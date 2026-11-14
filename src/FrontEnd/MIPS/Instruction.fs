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

namespace B2R2.FrontEnd.MIPS

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents an instruction for MIPS.
type Instruction
  internal(addr,
           numBytes,
           condition,
           fmt,
           op,
           opr,
           oprSize,
           wordSize,
           isaMode,
           lifter: ILiftable) =

  let mutable delaySlot: Instruction option = None

  let hasConcJmpTarget () =
    match opr with
    | OneOperand(OpAddr _)
    | TwoOperands(_, OpAddr _)
    | ThreeOperands(_, _, OpAddr _)
    | OneOperand(OpImm _) -> true
    | _ -> false

  (* Every branch of the base architecture before Release 6 has one, and so
     do the jumps through a register and the calls of the compressed
     encodings; a MIPS16e branch, the compact branches of Release 6 and the
     branches on coprocessors this processor lacks do not. *)
  let hasDelaySlot () =
    match op with
    | Opcode.B -> isaMode <> MIPSISAMode.MIPS16
    | Opcode.BAL | Opcode.NAL | Opcode.BEQ | Opcode.BNE | Opcode.BLEZ
    | Opcode.BLTZ | Opcode.BGEZ | Opcode.BGTZ | Opcode.BLTZAL | Opcode.BGEZAL
    | Opcode.BEQL | Opcode.BNEL | Opcode.BLEZL | Opcode.BLTZL | Opcode.BGEZL
    | Opcode.BGTZL | Opcode.BLTZALL | Opcode.BGEZALL | Opcode.BC1F
    | Opcode.BC1T | Opcode.BC1FL | Opcode.BC1TL | Opcode.BC1EQZ
    | Opcode.BC1NEZ | Opcode.J | Opcode.JAL | Opcode.JALX | Opcode.JR
    | Opcode.JRHB | Opcode.JALR | Opcode.JALRHB | Opcode.JALS | Opcode.JALRS
    | Opcode.JALRSHB | Opcode.BLTZALS | Opcode.BGEZALS -> true
    | _ -> false

  let alwaysTraps () =
    match op, opr with
    | Opcode.TEQ, TwoOperands(OpReg r1, OpReg r2) -> r1 = r2
    | _ -> false

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = numBytes

  /// Condition.
  member _.Condition with get(): Condition option = condition

  /// Floating Point Format.
  member _.Fmt with get(): Fmt option = fmt

  /// Opcode.
  member _.Opcode with get(): Opcode = op

  /// Operands.
  member _.Operands with get(): Operands = opr

  /// Operation Size.
  member _.OperationSize with get(): RegType = oprSize

  /// Word Size.
  member _.WordSize with get() = wordSize

  /// <summary>
  /// Which encoding this instruction was read from.
  ///
  /// They all stand for the same instruction set, so this says nothing about
  /// what the instruction does -- except for JALX, whose whole effect is to
  /// cross from one to another, and which therefore has to know which side it
  /// is starting on.
  /// </summary>
  member _.ISAMode with get(): MIPSISAMode = isaMode

  /// Whether this instruction was read from the microMIPS encoding.
  member _.IsMicroMIPS with get(): bool = isaMode = MIPSISAMode.MicroMIPS

  /// <summary>
  /// Whether it was read from one of the COMPRESSED encodings, which is what
  /// JALX asks: the crossing is between the 32-bit encoding and whichever of
  /// the two a processor has, and no processor has both.
  /// </summary>
  member _.IsCompressed with get(): bool = isaMode <> MIPSISAMode.MIPS

  /// Whether this is a branch that runs the instruction after it, in its
  /// delay slot, before it transfers control.
  member _.HasDelaySlot with get(): bool = hasDelaySlot ()

  /// Checks if this instruction always traps, as a TEQ of a register with
  /// itself does: GCC traps with teq zero, zero where it proves a path wrong.
  member _.AlwaysTraps with get(): bool = alwaysTraps ()

  /// <summary>
  /// The instruction in the delay slot of this branch, which the branch runs
  /// after reading what decides the transfer and before making it, and so
  /// lifts as part of itself. None where the branch has no delay slot, or
  /// where the bytes after it were not given or hold no instruction; a branch
  /// left without its slot that way still disassembles, but is not lifted
  /// (see MissingDelaySlotException). Only the parser sets it, on the
  /// instruction it has just read.
  /// </summary>
  member _.DelaySlot
    with get(): Instruction option = delaySlot
     and internal set v = delaySlot <- v

  /// The address control goes on to unless this instruction sends it
  /// elsewhere: right after it, or past its delay slot, which runs either
  /// way, where it has one.
  member _.FallThroughAddress with get(): Addr =
    match delaySlot with
    | Some slot -> addr + uint64 numBytes + uint64 slot.Length
    | None -> addr + uint64 numBytes

  /// Lifts this instruction into the statements the builder holds.
  member internal this.LiftInto(builder: LowUIRBuilder) =
    lifter.Lift(this, builder) |> ignore

  member private this.AddBranchTargetIfExist addrs =
    match (this :> IInstruction).DirectBranchTarget() with
    | false, _ -> addrs
    | true, target -> Array.append addrs [| target |]

  interface IInstruction with

    member _.Address with get() = addr

    member _.Length with get() = numBytes

    (* NAL has a delay slot, but goes nowhere the next instruction does not. *)
    member _.IsBranch =
      match op with
      | Opcode.B -> true
      | Opcode.NAL -> false
      | _ -> hasDelaySlot ()

    member _.IsModeChanging = false

    member this.IsDirectBranch =
      (this :> IInstruction).IsBranch && hasConcJmpTarget ()

    member this.IsIndirectBranch =
      (this :> IInstruction).IsBranch && (not <| hasConcJmpTarget ())

    member _.IsCondBranch =
      match op with
      | Opcode.BEQ | Opcode.BNE | Opcode.BLTZ | Opcode.BLEZ | Opcode.BGTZ
      | Opcode.BGEZ | Opcode.BLTZAL | Opcode.BGEZAL | Opcode.BEQL | Opcode.BNEL
      | Opcode.BLTZL | Opcode.BLEZL | Opcode.BGTZL | Opcode.BGEZL
      | Opcode.BLTZALL | Opcode.BGEZALL | Opcode.BLTZALS | Opcode.BGEZALS
      | Opcode.BC1F | Opcode.BC1T | Opcode.BC1FL | Opcode.BC1TL
      | Opcode.BC1EQZ | Opcode.BC1NEZ -> true
      | _ -> false

    member _.IsCJmpOnTrue =
      match op with
      | Opcode.BEQ | Opcode.BLTZ | Opcode.BLEZ | Opcode.BGTZ | Opcode.BGEZ
      | Opcode.BGEZAL | Opcode.BC1T -> true
      | _ -> false

    member _.IsCall =
      match op with
      | Opcode.BAL | Opcode.BLTZAL | Opcode.BGEZAL | Opcode.BLTZALL
      | Opcode.BGEZALL | Opcode.BLTZALS | Opcode.BGEZALS | Opcode.JAL
      | Opcode.JALX | Opcode.JALS | Opcode.JALR | Opcode.JALRHB | Opcode.JALRS
      | Opcode.JALRSHB -> true
      | _ -> false

    member _.IsRET =
      match op with
      | Opcode.JR ->
        match opr with
        | OneOperand(OpReg Register.R31) -> true
        | _ -> false
      | _ ->
        false

    member _.IsPush = Terminator.futureFeature ()

    member _.IsPop = Terminator.futureFeature ()

    member _.IsInterrupt =
      match op with
      | Opcode.SYSCALL | Opcode.WAIT -> true
      | _ -> false

    member _.IsExit =
      match op with
      | Opcode.DERET | Opcode.ERET | Opcode.ERETNC -> true
      (* A trap that always takes place returns, if at all, to itself. *)
      | Opcode.TEQ -> alwaysTraps ()
      | _ -> false

    member _.IsNop = op = Opcode.NOP

    member _.IsInlinedAssembly = false

    (* A branch carries its delay slot, so it ends the block itself, and the
       instruction after it ends nothing. *)
    member this.IsTerminator _ =
      let ins = this :> IInstruction
      hasDelaySlot () || ins.IsBranch || ins.IsInterrupt || ins.IsExit

    member this.DirectBranchTarget(addr: byref<Addr>) =
      if (this :> IInstruction).IsBranch then
        match opr with
        | OneOperand(OpAddr(Relative offset)) ->
          addr <- (int64 this.Address + offset) |> uint64
          true
        | TwoOperands(_, OpAddr(Relative offset)) ->
          addr <- (int64 this.Address + offset) |> uint64
          true
        | ThreeOperands(_, _, OpAddr(Relative offset)) ->
          addr <- (int64 this.Address + offset) |> uint64
          true
        | OneOperand(OpAddr(Region index)) ->
          addr <- JumpTarget.regionTarget this.Address wordSize index
          true
        | OneOperand(OpImm(imm)) ->
          addr <- imm
          true
        | _ ->
          false
      else
        false

    member this.IndirectTrampolineAddr(_addr: byref<Addr>) =
      if (this :> IInstruction).IsIndirectBranch then
        Terminator.futureFeature ()
      else
        false

    member _.MemoryDereferences(_: byref<Addr[]>) = Terminator.futureFeature ()

    member _.Immediate(v: byref<int64>) =
      match opr with
      | OneOperand(OpImm(c))
      | TwoOperands(OpImm(c), _)
      | TwoOperands(_, OpImm(c))
      | ThreeOperands(OpImm(c), _, _)
      | ThreeOperands(_, OpImm(c), _)
      | ThreeOperands(_, _, OpImm(c))
      | FourOperands(OpImm(c), _, _, _)
      | FourOperands(_, OpImm(c), _, _)
      | FourOperands(_, _, OpImm(c), _)
      | FourOperands(_, _, _, OpImm(c)) -> v <- int64 c; true
      | _ -> false

    member this.GetNextInstrAddrs() =
      let ins = this :> IInstruction
      let fallThrough = [| this.FallThroughAddress |]
      if ins.IsCall || ins.IsCondBranch then
        this.AddBranchTargetIfExist fallThrough
      elif ins.IsBranch || ins.IsExit then
        this.AddBranchTargetIfExist [||]
      else
        fallThrough

    member _.InterruptNum(_num: byref<int64>) = Terminator.futureFeature ()

    member this.Translate builder =
      let builder = builder :?> LowUIRBuilder
      lifter.Lift(this, builder).Stream.ToStmts()

    member this.TranslateToList builder =
      let builder = builder :?> LowUIRBuilder
      lifter.Lift(this, builder).Stream

    member this.Disasm builder = lifter.Disasm(this, builder).ToString()

    member this.Disasm() =
      let builder = StringDisasmBuilder(false, null, wordSize)
      lifter.Disasm(this, builder).ToString()

    member this.Decompose builder = lifter.Disasm(this, builder).ToAsmWords()

and internal ILiftable =
  abstract Lift: Instruction * LowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction * IDisasmBuilder -> IDisasmBuilder
