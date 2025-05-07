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

/// Instruction for Intel x86 and x86-64.
type Instruction
  internal (addr, len, wordSz, pref, rex, vex, opcode, oprs, opsz, psz,
            lifter: ILiftable) =

  let hasConcJmpTarget () =
    match oprs with
    | OneOperand (OprDirAddr _) -> true
    | _ -> false

  /// Address of this instruction.
  member _.Address with get (): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get (): uint32 = len

  /// Prefixes.
  member _.Prefixes with get(): Prefix = pref

  /// REX Prefix.
  member _.REXPrefix with get(): REXPrefix = rex

  /// VEX information.
  member _.VEXInfo with get(): VEXInfo option = vex

  /// Opcode.
  member _.Opcode with get(): Opcode = opcode

  /// Operands.
  member _.Operands with get(): Operands = oprs

  /// Size of the main operation performed by the instruction. This field is
  /// mainly used by our lifter, and we suggest not to use this field for
  /// analyzing binaries because there is some ambiguity in deciding the
  /// operation size when the instruction semantics are complex. We use this
  /// only for the purpose of optimizing the lifting process.
  member _.MainOperationSize with get(): RegType = opsz

  /// Size of the memory pointer in the instruction, i.e., how many bytes are
  /// required to represent a memory address. This field may hold a dummy value
  /// if there's no memory operand. This is mainly used for the lifting purpose
  /// along with the MainOperationSize.
  member _.PointerSize with get(): RegType = psz

  member private this.AddBranchTargetIfExist addrs =
    match (this :> IInstruction).DirectBranchTarget () with
    | false, _ -> addrs
    | true, target -> target :: addrs

  interface IInstruction with

    member _.Address with get () = addr

    member _.Length with get () = len

    member _.IsBranch () = Opcode.isBranch opcode

    member _.IsModeChanging () = false

    member _.IsDirectBranch () =
      Opcode.isBranch opcode && hasConcJmpTarget ()

    member _.IsIndirectBranch () =
      Opcode.isBranch opcode && (not <| hasConcJmpTarget ())

    member _.IsCondBranch () =
      match opcode with
      | Opcode.JA | Opcode.JB | Opcode.JBE | Opcode.JCXZ | Opcode.JECXZ
      | Opcode.JG | Opcode.JL | Opcode.JLE | Opcode.JNB | Opcode.JNL
      | Opcode.JNO | Opcode.JNP | Opcode.JNS | Opcode.JNZ | Opcode.JO
      | Opcode.JP | Opcode.JRCXZ | Opcode.JS | Opcode.JZ
      | Opcode.LOOP | Opcode.LOOPE | Opcode.LOOPNE -> true
      | _ -> false

    member _.IsCJmpOnTrue () =
      match opcode with
      | Opcode.JA | Opcode.JB | Opcode.JBE | Opcode.JCXZ | Opcode.JECXZ
      | Opcode.JG | Opcode.JL | Opcode.JLE | Opcode.JO | Opcode.JP
      | Opcode.JRCXZ | Opcode.JS | Opcode.JZ | Opcode.LOOP | Opcode.LOOPE ->
        true
      | _ -> false

    member _.IsCall () =
      match opcode with
      | Opcode.CALLFar | Opcode.CALLNear -> true
      | _ -> false

    member _.IsRET () =
      match opcode with
      | Opcode.RETFar | Opcode.RETFarImm
      | Opcode.RETNear | Opcode.RETNearImm ->
        true
      | _ -> false

    member _.IsInterrupt () =
      match opcode with
      | Opcode.INT | Opcode.INT3 | Opcode.INTO
      | Opcode.SYSCALL | Opcode.SYSENTER
        -> true
      | _ -> false

    member _.IsExit () =
      match opcode with
      (* In kernel code, HLT is often preceded by CLI to shut down the machine.
         In user code, compilers insert HLT to raise a fault and exit. *)
      | Opcode.HLT
      | Opcode.UD2
      | Opcode.SYSEXIT | Opcode.SYSRET
      | Opcode.IRET | Opcode.IRETW | Opcode.IRETD | Opcode.IRETQ -> true
      | _ -> false

    member this.IsTerminator () =
      let ins = this :> IInstruction
      ins.IsBranch () || ins.IsInterrupt () || ins.IsExit ()

    member _.IsNop () =
      opcode = Opcode.NOP

    member _.IsInlinedAssembly () = false

    member this.DirectBranchTarget (addr: byref<Addr>) =
      if (this :> IInstruction).IsBranch () then
        match oprs with
        | OneOperand (OprDirAddr (Absolute (_))) -> Terminator.futureFeature ()
        | OneOperand (OprDirAddr (Relative offset)) ->
          addr <- (int64 this.Address + offset) |> uint64
          true
        | _ -> false
      else false

    member this.IndirectTrampolineAddr (addr: byref<Addr>) =
      if (this :> IInstruction).IsIndirectBranch () then
        match oprs with
        | OneOperand (OprMem (None, None, Some disp, _)) ->
          addr <- uint64 disp; true
        | OneOperand (OprMem (Some Register.RIP, None, Some disp, _)) ->
          addr <- this.Address + uint64 this.Length + uint64 disp
          true
        | _ -> false
      else false

    member _.Immediate (v: byref<int64>) =
      match oprs with
      | OneOperand (OprImm (c, _))
      | TwoOperands (OprImm (c, _), _)
      | TwoOperands (_, OprImm (c, _))
      | ThreeOperands (OprImm (c, _), _, _)
      | ThreeOperands (_, OprImm (c, _), _)
      | ThreeOperands (_, _, OprImm (c, _))
      | FourOperands (OprImm (c, _), _, _, _)
      | FourOperands (_, OprImm (c, _), _, _)
      | FourOperands (_, _, OprImm (c, _), _)
      | FourOperands (_, _, _, OprImm (c, _)) -> v <- c; true
      | _ -> false

    member this.GetNextInstrAddrs () =
      let acc = [ this.Address + uint64 this.Length ]
      let ins = this :> IInstruction
      if ins.IsBranch () then
        if ins.IsCondBranch () then acc |> this.AddBranchTargetIfExist
        else this.AddBranchTargetIfExist []
      elif opcode = Opcode.HLT || opcode = Opcode.UD2 then []
      else acc
      |> List.toArray

    member _.InterruptNum (num: byref<int64>) =
      if opcode = Opcode.INT then
        match oprs with
        | OneOperand (OprImm (n, _)) ->
          num <- n
          true
        | _ -> false
      else false

    member this.Translate builder =
      (lifter.Lift this builder).Stream.ToStmts ()

    member this.TranslateToList builder =
      (lifter.Lift this builder).Stream

    member this.Disasm builder =
      (lifter.Disasm this builder).ToString ()

    member this.Disasm () =
      let builder = StringDisasmBuilder (false, null, wordSz)
      (lifter.Disasm this builder).ToString ()

    member this.Decompose builder =
      (lifter.Disasm this builder).ToAsmWords ()

and internal ILiftable =
  abstract Lift: Instruction -> ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction -> IDisasmBuilder -> IDisasmBuilder
