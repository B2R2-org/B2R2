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

namespace B2R2.FrontEnd.SH4

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents an instruction for SH4.
type Instruction internal(addr, numBytes, op, opr, lifter: ILiftable) =

  let mutable delaySlot: Instruction option = None

  (* The delayed branches, which run the instruction after them before they
     transfer control. *)
  let isDelayedBranch () =
    match op with
    | Opcode.BFS | Opcode.BTS | Opcode.BRA | Opcode.BRAF | Opcode.BSR
    | Opcode.BSRF | Opcode.JMP | Opcode.JSR | Opcode.RTS | Opcode.RTE -> true
    | _ -> false

  (* Whether this writes SR, as LDC Rm, SR and LDC.L @Rm+, SR do. *)
  let writesSR () =
    match opr with
    | TwoOperands(_, OpReg(Regdir Register.SR)) -> true
    | _ -> false

  (* Whether this reads memory at an address taken from the PC. *)
  let readsPCRelative () =
    match opr with
    | TwoOperands(OpReg(PCRelDisp _), _) -> true
    | _ -> false

  (* The instructions that may not sit in a delay slot, which the processor
     meets with a slot illegal instruction exception: those that change the
     PC, and the PC-relative MOV and MOVA. *)
  let isSlotIllegal () =
    match op with
    | Opcode.BF | Opcode.BT | Opcode.TRAPA | Opcode.MOVA -> true
    | Opcode.LDC | Opcode.LDCL -> writesSR ()
    | Opcode.MOVW | Opcode.MOVL -> readsPCRelative ()
    | _ -> isDelayedBranch ()

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = numBytes

  //// Opcode.
  member _.Opcode with get(): Opcode = op

  //// Operands.
  member _.Operands with get(): Operands = opr

  /// Whether this is a delayed branch, which runs the instruction after it,
  /// in its delay slot, before it transfers control.
  member _.HasDelaySlot with get(): bool = isDelayedBranch ()

  /// Whether this may not sit in a delay slot: the processor raises a slot
  /// illegal instruction exception where it does.
  member _.IsSlotIllegal with get(): bool = isSlotIllegal ()

  /// <summary>
  /// The instruction in the delay slot of this branch, which the branch runs
  /// after reading what decides it and before making it, and so lifts as
  /// part of itself. None where the branch has no delay slot, or where the
  /// bytes after it were not given or hold no instruction; a branch left
  /// without its slot that way still disassembles, but is not lifted (see
  /// MissingDelaySlotException). Only the parser sets it, on the instruction
  /// it has just read.
  /// </summary>
  member _.DelaySlot
    with get(): Instruction option = delaySlot
     and internal set v = delaySlot <- v

  /// Lifts this instruction into the statements the builder holds.
  member internal this.LiftInto(builder: LowUIRBuilder) =
    lifter.Lift(this, builder) |> ignore

  interface IInstruction with
    member _.Address with get() = addr
    member _.Length with get() = numBytes

    member _.Extent with get() =
      match delaySlot with
      | Some slot -> numBytes + slot.Length
      | None -> numBytes

    member _.IsBranch = Terminator.futureFeature ()
    member _.IsModeChanging = false
    member _.IsDirectBranch = Terminator.futureFeature ()
    member _.IsIndirectBranch = Terminator.futureFeature ()
    member _.IsCondBranch = Terminator.futureFeature ()
    member _.IsCJmpOnTrue = Terminator.futureFeature ()
    member _.IsCall = Terminator.futureFeature ()
    member _.IsRET = Terminator.futureFeature ()
    member _.IsPush = Terminator.futureFeature ()
    member _.IsPop = Terminator.futureFeature ()
    member _.IsInterrupt = Terminator.futureFeature ()
    member _.IsExit = Terminator.futureFeature ()
    member _.IsNop = Terminator.futureFeature ()
    member _.IsInlinedAssembly = false
    (* A delayed branch carries its delay slot, so it ends the block itself,
       and the instruction after it ends nothing. *)
    member _.IsTerminator _ =
      match op with
      | Opcode.BF | Opcode.BT | Opcode.TRAPA -> true
      | _ -> isDelayedBranch ()

    member _.DirectBranchTarget _ = Terminator.futureFeature ()
    member _.IndirectTrampolineAddr _ = Terminator.futureFeature ()
    member _.MemoryDereferences _ = Terminator.futureFeature ()
    member _.Immediate _ = Terminator.futureFeature ()
    member _.GetNextInstrAddrs() = Terminator.futureFeature ()
    member _.InterruptNum _ = Terminator.futureFeature ()

    member this.Translate builder = lifter.Lift(this, builder).Stream.ToStmts()

    member this.TranslateToList builder = lifter.Lift(this, builder).Stream

    member this.Disasm builder = lifter.Disasm(this, builder).ToString()

    member this.Disasm() =
      let builder = StringDisasmBuilder(false, null, WordSize.Bit32)
      lifter.Disasm(this, builder).ToString()

    member this.Decompose builder = lifter.Disasm(this, builder).ToAsmWords()

and internal ILiftable =
  abstract Lift: Instruction * ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction * IDisasmBuilder -> IDisasmBuilder
