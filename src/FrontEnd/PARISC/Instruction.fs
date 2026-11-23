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

namespace B2R2.FrontEnd.PARISC

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents an instruction for PARISC.
type Instruction
  internal(addr,
           numBytes,
           completer,
           cond,
           id,
           op,
           opr,
           oprSize,
           wordSize,
           lifter: ILiftable) =
  let mutable delaySlot: Instruction option = None

  let isTransfer () =
    match op with
    | Opcode.B | Opcode.BLR | Opcode.BV | Opcode.BE | Opcode.BVE
    | Opcode.ADDB | Opcode.ADDIB | Opcode.BB | Opcode.CMPB | Opcode.CMPIB
    | Opcode.MOVB | Opcode.MOVIB -> true
    | _ -> false

  let isUnconditional () =
    match op with
    | Opcode.B | Opcode.BLR | Opcode.BV | Opcode.BE | Opcode.BVE -> true
    | _ -> false

  /// An unconditional transfer that nullifies never runs the instruction
  /// after it, so that instruction is none of its business: a jump table or
  /// a literal pool sits there as often as not.
  let hasDelaySlot () =
    isTransfer () && not (isUnconditional () && cond = Some Completer.N)

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = numBytes

  /// Completer.
  member _.Completer with get(): Completer array option = completer

  /// Completer condition or fmt.
  member _.Condition with get(): Completer option = cond

  /// Completer swap and uid.
  member _.ID with get(): uint64[] option = id

  /// Opcode.
  member _.Opcode with get(): Opcode = op

  /// Operands.
  member _.Operands with get(): Operands = opr

  /// Operation Size.
  member _.OperationSize with get(): RegType = oprSize

  /// Word size.
  member _.WordSize with get(): WordSize = wordSize

  /// Whether this instruction transfers control, which every one does after
  /// the instruction that follows it, its delay slot.
  member _.IsTransfer with get(): bool = isTransfer ()

  /// Whether this instruction is a transfer whose delay slot may run, and so
  /// must be lifted with it.
  member _.HasDelaySlot with get(): bool = hasDelaySlot ()

  /// The instruction in this transfer's delay slot, which the transfer lifts
  /// itself, or None where the instruction is no such transfer or the bytes
  /// ended before its slot (see MissingDelaySlotException). Only the parser
  /// sets it.
  member _.DelaySlot
    with get(): Instruction option = delaySlot
     and internal set v = delaySlot <- v

  /// Lifts this instruction into the given builder, as a transfer does the
  /// instruction in its delay slot.
  member internal this.LiftInto(builder: LowUIRBuilder) =
    lifter.Lift(this, builder) |> ignore

  interface IInstruction with

    member this.Address with get() = this.Address

    member this.Length with get() = this.Length

    member _.Extent with get() =
      match delaySlot with
      | Some slot -> numBytes + slot.Length
      | None -> numBytes

    member _.IsBranch =
      match op with
      | _ -> false

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

    member _.IsTerminator _ = isTransfer ()

    member _.DirectBranchTarget(_addr: byref<Addr>) =
      Terminator.futureFeature ()

    member _.IndirectTrampolineAddr(_addr: byref<Addr>) =
      Terminator.futureFeature ()

    member _.MemoryDereferences(_: byref<Addr[]>) = Terminator.futureFeature ()

    member _.Immediate(_v: byref<int64>) = Terminator.futureFeature ()

    member _.GetNextInstrAddrs() = Terminator.futureFeature ()

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
