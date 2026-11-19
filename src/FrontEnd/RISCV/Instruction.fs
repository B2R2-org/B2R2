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

namespace B2R2.FrontEnd.RISCV

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents an instruction for RISCV architectures.
type Instruction
  internal(addr, numBytes, op, opr, oprSize, wordSize, lifter: ILiftable) =

  let isJump () =
    match op with
    | Opcode.JAL | Opcode.JALR | Opcode.CdotJ | Opcode.CdotJAL
    | Opcode.CdotJR | Opcode.CdotJALR -> true
    | _ -> false

  let isCondBranch () =
    match op with
    | Opcode.BEQ | Opcode.BNE | Opcode.BLT | Opcode.BGE | Opcode.BLTU
    | Opcode.BGEU | Opcode.CdotBEQZ | Opcode.CdotBNEZ -> true
    | _ -> false

  let hasConcJmpTarget () =
    match opr with
    | TwoOperands(_, OpAddr(Relative _))
    | ThreeOperands(_, _, OpAddr(Relative _)) -> true
    | _ -> false

  (* The ISA takes x1 and x5 alone for links, the registers a call keeps the
     address after it in, and a processor predicts returns by them: code calls
     through x5 where x1 has to survive, as the functions that LLVM outlines
     do. A jump that keeps the address anywhere else, as the PLT does in t1,
     is a plain jump. *)
  let isLink reg = reg = Register.X1 || reg = Register.X5

  let links () =
    match opr with
    | TwoOperands(OpReg rd, OpAddr _) -> isLink rd
    | _ -> false

  let jumpsThroughLink () =
    match opr with
    | TwoOperands(_, OpAddr(RelativeBase(rs1, _))) -> isLink rs1
    | _ -> false

  (* NOP is ADDI x0, x0, 0, which pads code, as its compressed form does. *)
  let isNop () =
    match op, opr with
    | Opcode.CdotNOP, _ ->
      true
    | Opcode.ADDI, ThreeOperands(OpReg rd, OpReg rs1, OpImm 0UL) ->
      rd = Register.X0 && rs1 = Register.X0
    | _ ->
      false

  (* RV32 keeps an offset sign-extended to 32 bits, and a target wraps around
     the address space of the XLEN. *)
  let targetOf offset =
    let target = addr + uint64 offset
    if wordSize = WordSize.Bit32 then target &&& 0xFFFFFFFFUL else target

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = numBytes

  /// Opcode.
  member _.Opcode with get(): Opcode = op

  /// Operands.
  member _.Operands with get(): Operands = opr

  /// Operation Size.
  member _.OperationSize with get(): RegType = oprSize

  /// Word size of the architecture this instruction was read for.
  member _.WordSize with get(): WordSize = wordSize

  member private this.AddBranchTargetIfExist addrs =
    match (this :> IInstruction).DirectBranchTarget() with
    | false, _ -> addrs
    | true, target -> Array.append addrs [| target |]

  interface IInstruction with

    member _.Address with get() = addr

    member _.Length with get() = numBytes

    member _.Extent with get() = numBytes

    member _.IsBranch = isJump () || isCondBranch ()

    member _.IsModeChanging = false

    member this.IsDirectBranch =
      (this :> IInstruction).IsBranch && hasConcJmpTarget ()

    member this.IsIndirectBranch =
      (this :> IInstruction).IsBranch && not (hasConcJmpTarget ())

    member _.IsCondBranch = isCondBranch ()

    (* The low bit of funct3 negates the condition of a branch, as the low bit
       of a condition code does on Intel. *)
    member _.IsCJmpOnTrue =
      match op with
      | Opcode.BEQ | Opcode.BLT | Opcode.BLTU | Opcode.CdotBEQZ -> true
      | _ -> false

    member _.IsCall = isJump () && links ()

    (* A jump through a link that also links swaps one coroutine for another,
       which goes on to return here, so it calls rather than returns. *)
    member _.IsRET = isJump () && jumpsThroughLink () && not (links ())

    (* RISCV reaches its stack with plain loads and stores only. *)
    member _.IsPush = false

    member _.IsPop = false

    member _.IsInterrupt = op = Opcode.ECALL

    (* EBREAK and the illegal halfword return, if at all, to the instruction
       itself: GCC puts an EBREAK where __builtin_trap is, and compilers pad
       with the other where control never comes, so the next instruction is
       not where control goes on. *)
    member _.IsExit =
      match op with
      | Opcode.EBREAK | Opcode.CdotEBREAK | Opcode.CdotUNIMP -> true
      | _ -> false

    member _.IsNop = isNop ()

    member _.IsInlinedAssembly = false

    member this.IsTerminator _ =
      let ins = this :> IInstruction
      ins.IsBranch || ins.IsInterrupt || ins.IsExit

    member this.DirectBranchTarget(target: byref<Addr>) =
      if (this :> IInstruction).IsBranch then
        match opr with
        | TwoOperands(_, OpAddr(Relative offset))
        | ThreeOperands(_, _, OpAddr(Relative offset)) ->
          target <- targetOf offset
          true
        | _ ->
          false
      else
        false

    (* No jump reads its target from memory. *)
    member _.IndirectTrampolineAddr(_addr: byref<Addr>) = false

    member _.MemoryDereferences(_: byref<Addr[]>) = Terminator.futureFeature ()

    member _.Immediate(v: byref<int64>) =
      match opr with
      | TwoOperands(_, OpImm c)
      | ThreeOperands(_, _, OpImm c) ->
        v <- int64 c
        true
      | _ ->
        false

    member this.GetNextInstrAddrs() =
      let ins = this :> IInstruction
      let fallThrough = [| addr + uint64 numBytes |]
      if ins.IsCall || ins.IsCondBranch then
        this.AddBranchTargetIfExist fallThrough
      elif ins.IsBranch || ins.IsExit then
        this.AddBranchTargetIfExist [||]
      else
        fallThrough

    member _.InterruptNum(_num: byref<int64>) = Terminator.futureFeature ()

    member this.Translate builder = lifter.Lift(this, builder).Stream.ToStmts()

    member this.TranslateToList builder = lifter.Lift(this, builder).Stream

    member this.Disasm builder = lifter.Disasm(this, builder).ToString()

    member this.Disasm() =
      let builder = StringDisasmBuilder(false, null, wordSize)
      lifter.Disasm(this, builder).ToString()

    member this.Decompose builder = lifter.Disasm(this, builder).ToAsmWords()

and internal ILiftable =
  abstract Lift: Instruction * ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction * IDisasmBuilder -> IDisasmBuilder
