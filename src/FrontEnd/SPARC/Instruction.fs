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

namespace B2R2.FrontEnd.SPARC

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents an instruction for SPARC.
type Instruction internal(addr, numBytes, op, opr, lifter: ILiftable) =

  let mutable delaySlot: Instruction option = None

  (* The delayed control transfers: every branch, CALL, JMPL and RETURN. *)
  let isTransfer () =
    match op with
    | Opcode.BA | Opcode.BN | Opcode.BNE | Opcode.BE | Opcode.BG | Opcode.BLE
    | Opcode.BGE | Opcode.BL | Opcode.BGU | Opcode.BLEU | Opcode.BCC
    | Opcode.BCS | Opcode.BPOS | Opcode.BNEG | Opcode.BVC | Opcode.BVS
    | Opcode.BPA | Opcode.BPN | Opcode.BPNE | Opcode.BPE | Opcode.BPG
    | Opcode.BPLE | Opcode.BPGE | Opcode.BPL | Opcode.BPGU | Opcode.BPLEU
    | Opcode.BPCC | Opcode.BPCS | Opcode.BPPOS | Opcode.BPNEG | Opcode.BPVC
    | Opcode.BPVS | Opcode.BRZ | Opcode.BRLEZ | Opcode.BRLZ | Opcode.BRNZ
    | Opcode.BRGZ | Opcode.BRGEZ | Opcode.FBA | Opcode.FBN | Opcode.FBU
    | Opcode.FBG | Opcode.FBUG | Opcode.FBL | Opcode.FBUL | Opcode.FBLG
    | Opcode.FBNE | Opcode.FBE | Opcode.FBUE | Opcode.FBGE | Opcode.FBUGE
    | Opcode.FBLE | Opcode.FBULE | Opcode.FBO | Opcode.FBPA | Opcode.FBPN
    | Opcode.FBPU | Opcode.FBPG | Opcode.FBPUG | Opcode.FBPL | Opcode.FBPUL
    | Opcode.FBPLG | Opcode.FBPNE | Opcode.FBPE | Opcode.FBPUE | Opcode.FBPGE
    | Opcode.FBPUGE | Opcode.FBPLE | Opcode.FBPULE | Opcode.FBPO
    | Opcode.CALL | Opcode.JMPL | Opcode.RETURN -> true
    | _ -> false

  (* The annul bit of a branch, which the parser puts first in the operands of
     the branches on icc and fcc and third in those of the others. *)
  let isAnnulling () =
    match opr with
    | TwoOperands(OprImm a, _)
    | FourOperands(_, _, OprImm a, _) -> a = 1
    | _ -> false

  (* A branch that always or never goes to its target annuls its delay slot
     whatever happens when its annul bit is set, so it never runs it. *)
  let annulsSlot () =
    match op with
    | Opcode.BA | Opcode.BN | Opcode.BPA | Opcode.BPN | Opcode.FBA
    | Opcode.FBN | Opcode.FBPA | Opcode.FBPN -> isAnnulling ()
    | _ -> false

  let hasDelaySlot () = isTransfer () && not (annulsSlot ())

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = numBytes

  /// Opcode.
  member _.Opcode with get(): Opcode = op

  /// Operands
  member _.Operands with get(): Operands = opr

  /// Whether this is a control transfer that runs the instruction after it,
  /// in its delay slot, before it transfers control. BA,a and BN,a and their
  /// kin do not: they annul their slot whatever happens.
  member _.HasDelaySlot with get(): bool = hasDelaySlot ()

  /// <summary>
  /// The instruction in the delay slot of this transfer, which the transfer
  /// runs after reading what decides it and before making it, and so lifts
  /// as part of itself. None where the transfer has no delay slot, or where
  /// the bytes after it were not given or hold no instruction; a transfer
  /// left without its slot that way still disassembles, but is not lifted
  /// (see MissingDelaySlotException). Only the parser sets it, on the
  /// instruction it has just read.
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

    (* A transfer carries its delay slot, so it ends the block itself, and
       the instruction after it ends nothing. *)
    member _.IsTerminator _ =
      isTransfer () || op = Opcode.DONE || op = Opcode.RETRY

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
      let builder = StringDisasmBuilder(false, null, WordSize.Bit32)
      lifter.Disasm(this, builder).ToString()

    member this.Decompose builder = lifter.Disasm(this, builder).ToAsmWords()

and internal ILiftable =
  abstract Lift: Instruction * ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction * IDisasmBuilder -> IDisasmBuilder
