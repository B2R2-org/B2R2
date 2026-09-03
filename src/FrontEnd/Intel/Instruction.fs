(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

namespace B2R2.FrontEnd.Intel

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents an instruction for Intel x86 and x86-64 architectures.
type Instruction internal(addr, packed: uint64, vex, oprs, lifter: ILiftable) =

  let hasConcJmpTarget () =
    match oprs with
    | OneOperand(OprDirAddr _) -> true
    | _ -> false

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = uint32 (packed &&& 0xFUL)

  /// Prefixes.
  member _.Prefixes with get(): Prefix =
    LanguagePrimitives.EnumOfValue(int ((packed >>> 16) &&& 0xFFFUL))

  /// REX Prefix.
  member _.REXPrefix with get(): REXPrefix =
    LanguagePrimitives.EnumOfValue(int ((packed >>> 28) &&& 0x7FUL))

  /// VEX information.
  member _.VEXInfo with get(): VEXInfo option = vex

  /// Opcode.
  member _.Opcode with get(): Opcode =
    LanguagePrimitives.EnumOfValue(int ((packed >>> 4) &&& 0xFFFUL))

  /// Operands.
  member _.Operands with get(): Operands = oprs

  /// Size of the main operation performed by the instruction. This field is
  /// mainly used by our lifter, and we suggest not to use this field for
  /// analyzing binaries because there is some ambiguity in deciding the
  /// operation size when the instruction semantics are complex. We use this
  /// only for the purpose of optimizing the lifting process.
  member _.MainOperationSize with get(): RegType =
    LanguagePrimitives.Int32WithMeasure(int ((packed >>> 35) &&& 0x3FFUL))

  /// Size of the memory pointer in the instruction, i.e., how many bytes are
  /// required to represent a memory address. This field may hold a dummy value
  /// if there's no memory operand. This is mainly used for the lifting purpose
  /// along with the MainOperationSize.
  member _.PointerSize with get(): RegType =
    LanguagePrimitives.Int32WithMeasure(int ((packed >>> 45) &&& 0xFFUL))

  member _.IsFar with get(): bool = (packed >>> 53) &&& 1UL = 1UL

  /// The word size of the mode the instruction was parsed in.
  member private _.WordSize with get(): WordSize =
    LanguagePrimitives.EnumOfValue(int ((packed >>> 54) &&& 0x1FFUL))

  /// The scalar fields packed into one word. An instruction is allocated for
  /// every one parsed, and as eight separate fields these cost three times the
  /// space and a third of the parsing time. Widths: the length in bits 3:0
  /// (at most 15), the opcode in 15:4, the prefixes in 27:16, REX in 34:28,
  /// the operation size in 44:35 (the widest operand, the x87 state, is 864
  /// bits), the pointer size in 52:45, the far flag in 53, and the word size
  /// in 62:54. Every property below unpacks its own.
  static member inline internal Pack(len: uint32,
                                     wordSz: WordSize,
                                     pref: Prefix,
                                     rex: REXPrefix,
                                     opcode: Opcode,
                                     opsz: RegType,
                                     psz: RegType,
                                     isFar: bool) =
    (uint64 len &&& 0xFUL)
    ||| ((uint64 (int opcode) &&& 0xFFFUL) <<< 4)
    ||| ((uint64 (int pref) &&& 0xFFFUL) <<< 16)
    ||| ((uint64 (int rex) &&& 0x7FUL) <<< 28)
    ||| ((uint64 (int opsz) &&& 0x3FFUL) <<< 35)
    ||| ((uint64 (int psz) &&& 0xFFUL) <<< 45)
    ||| ((if isFar then 1UL else 0UL) <<< 53)
    ||| ((uint64 (int wordSz) &&& 0x1FFUL) <<< 54)

  member private this.AddBranchTargetIfExist addrs =
    match (this :> IInstruction).DirectBranchTarget() with
    | false, _ -> addrs
    | true, target -> target :: addrs

  interface IInstruction with

    member _.Address with get() = addr

    member this.Length with get() = this.Length

    member this.IsBranch = Opcode.isBranch this.Opcode

    member _.IsModeChanging = false

    member this.IsDirectBranch =
      Opcode.isBranch this.Opcode && hasConcJmpTarget ()

    member this.IsIndirectBranch =
      Opcode.isBranch this.Opcode && (not <| hasConcJmpTarget ())

    member this.IsCondBranch =
      match this.Opcode with
      | Opcode.JA | Opcode.JB | Opcode.JBE | Opcode.JCXZ | Opcode.JECXZ
      | Opcode.JG | Opcode.JL | Opcode.JLE | Opcode.JNB | Opcode.JNL
      | Opcode.JNO | Opcode.JNP | Opcode.JNS | Opcode.JNZ | Opcode.JO
      | Opcode.JP | Opcode.JRCXZ | Opcode.JS | Opcode.JZ
      | Opcode.LOOP | Opcode.LOOPE | Opcode.LOOPNE -> true
      | _ -> false

    member this.IsCJmpOnTrue =
      match this.Opcode with
      | Opcode.JA | Opcode.JB | Opcode.JBE | Opcode.JCXZ | Opcode.JECXZ
      | Opcode.JG | Opcode.JL | Opcode.JLE | Opcode.JO | Opcode.JP
      | Opcode.JRCXZ | Opcode.JS | Opcode.JZ | Opcode.LOOP | Opcode.LOOPE ->
        true
      | _ ->
        false

    member this.IsCall =
      match this.Opcode with
      | Opcode.CALL -> true
      | _ -> false

    member this.IsRET =
      match this.Opcode with
      | Opcode.RET -> true
      | _ -> false

    member this.IsPush =
      match this.Opcode with
      | Opcode.PUSH
      | Opcode.PUSHA | Opcode.PUSHAD
      | Opcode.PUSHF | Opcode.PUSHFD | Opcode.PUSHFQ -> true
      | _ -> false

    member this.IsPop =
      match this.Opcode with
      | Opcode.POP
      | Opcode.POPA | Opcode.POPAD
      | Opcode.POPF | Opcode.POPFD | Opcode.POPFQ -> true
      | _ -> false

    member this.IsInterrupt =
      match this.Opcode with
      | Opcode.INT | Opcode.INT3 | Opcode.INTO
      | Opcode.SYSCALL | Opcode.SYSENTER
        -> true
      | _ -> false

    member this.IsExit =
      match this.Opcode with
      (* In kernel code, HLT is often preceded by CLI to shut down the machine.
         In user code, compilers insert HLT to raise a fault and exit. *)
      | Opcode.HLT
      | Opcode.UD2
      | Opcode.SYSEXIT | Opcode.SYSRET
      | Opcode.IRET | Opcode.IRETD | Opcode.IRETQ -> true
      | _ -> false

    member this.IsNop =
      match this.Opcode with
      | Opcode.NOP ->
        true
      | Opcode.LEA ->
        match oprs with
        | TwoOperands(OprReg dst, OprMem(Some src, None, Some 0L, _)) ->
          dst = src
        | _ ->
          false
      | Opcode.MOV ->
        match oprs with
        | TwoOperands(OprReg dst, OprReg src) -> dst = src
        | _ -> false
      | _ ->
        false

    member _.IsInlinedAssembly = false

    member this.IsTerminator _ =
      let ins = this :> IInstruction
      ins.IsBranch || ins.IsInterrupt || ins.IsExit

    member this.DirectBranchTarget(addr: byref<Addr>) =
      if (this :> IInstruction).IsBranch then
        match oprs with
        | OneOperand(OprDirAddr(Absolute(_))) ->
          Terminator.futureFeature ()
        | OneOperand(OprDirAddr(Relative offset)) ->
          addr <- (int64 this.Address + offset) |> uint64
          true
        | _ ->
          false
      else
        false

    member this.IndirectTrampolineAddr(addr: byref<Addr>) =
      if (this :> IInstruction).IsIndirectBranch then
        match oprs with
        | OneOperand(OprMem(None, None, Some disp, _)) ->
          addr <- uint64 disp; true
        | OneOperand(OprMem(Some Register.RIP, None, Some disp, _)) ->
          addr <- this.Address + uint64 this.Length + uint64 disp
          true
        | _ ->
          false
      else
        false

    member this.MemoryDereferences(addrs: byref<Addr[]>) =
      if this.Opcode = Opcode.LEA then
        false
      else
        match oprs with
        | OneOperand(OprMem(Some Register.RIP, None, Some disp, _)) ->
          addrs <- [| this.Address + uint64 this.Length + uint64 disp |]
          true
        | TwoOperands(OprMem(Some Register.RIP, None, Some disp, _), _)
        | TwoOperands(_, OprMem(Some Register.RIP, None, Some disp, _)) ->
          addrs <- [| this.Address + uint64 this.Length + uint64 disp |]
          true
        | _ ->
          false

    member _.Immediate(v: byref<int64>) =
      match oprs with
      | OneOperand(OprImm(c, _))
      | TwoOperands(OprImm(c, _), _)
      | TwoOperands(_, OprImm(c, _))
      | ThreeOperands(OprImm(c, _), _, _)
      | ThreeOperands(_, OprImm(c, _), _)
      | ThreeOperands(_, _, OprImm(c, _))
      | FourOperands(OprImm(c, _), _, _, _)
      | FourOperands(_, OprImm(c, _), _, _)
      | FourOperands(_, _, OprImm(c, _), _)
      | FourOperands(_, _, _, OprImm(c, _)) -> v <- c; true
      | _ -> false

    member this.GetNextInstrAddrs() =
      let acc = [ this.Address + uint64 this.Length ]
      let ins = this :> IInstruction
      let addrs =
        if ins.IsBranch then
          if ins.IsCondBranch then acc |> this.AddBranchTargetIfExist
          else this.AddBranchTargetIfExist []
        elif this.Opcode = Opcode.HLT || this.Opcode = Opcode.UD2 then
          []
        else
          acc
      addrs |> List.toArray

    member this.InterruptNum(num: byref<int64>) =
      if this.Opcode = Opcode.INT then
        match oprs with
        | OneOperand(OprImm(n, _)) ->
          num <- n
          true
        | _ ->
          false
      else
        false

    member this.Translate builder = lifter.Lift(this, builder).Stream.ToStmts()

    member this.TranslateToList builder = lifter.Lift(this, builder).Stream

    member this.Disasm builder = lifter.Disasm(this, builder).ToString()

    member this.Disasm() =
      let builder = StringDisasmBuilder(false, null, this.WordSize)
      lifter.Disasm(this, builder).ToString()

    member this.Decompose builder = lifter.Disasm(this, builder).ToAsmWords()

and internal ILiftable =
  abstract Lift: Instruction * ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction * IDisasmBuilder -> IDisasmBuilder
