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

  let isBranchNever () =
    match op with
    | Opcode.BN | Opcode.BPN | Opcode.FBN | Opcode.FBPN -> true
    | _ -> false

  let isBranch () = isTransfer () && not (isBranchNever ())

  let tryGetTarget () =
    if isBranch () then
      match opr with
      | OneOperand(OprAddr disp)
      | TwoOperands(_, OprAddr disp)
      | FourOperands(_, OprAddr disp, _, _) ->
        ValueSome(addr + uint64 (int64 disp))
      | _ ->
        ValueNone
    else
      ValueNone

  let isBranchAlways () =
    match op with
    | Opcode.BA | Opcode.BPA | Opcode.FBA | Opcode.FBPA -> true
    | _ -> false

  let isCondBranch () =
    match op with
    | Opcode.CALL | Opcode.JMPL | Opcode.RETURN -> false
    | _ -> isTransfer () && not (isBranchNever () || isBranchAlways ())

  (* JMPL links the register its last operand names, which %g0 discards. *)
  let linksO7 () =
    match op, opr with
    | Opcode.CALL, _ -> true
    | Opcode.JMPL, ThreeOperands(_, _, OprReg Register.O7) -> true
    | _ -> false

  (* MOV, an OR with %g0, of a saved address into %o7, which a leaf makes in
     the delay slot of a call: the slot runs after the call has linked, so the
     callee returns where the move says. *)
  let movesIntoO7 (slot: Instruction) =
    match slot.Opcode, slot.Operands with
    | Opcode.OR, ThreeOperands(OprReg Register.G0, OprReg _, OprReg dst) ->
      dst = Register.O7
    | _ ->
      false

  (* MOV, an OR with %g0, of %o7 into another register, which a leaf makes
     right before a call that calls a function as its tail, so that the call
     moves the copy back into %o7 in its delay slot. *)
  let copiesO7 () =
    match op, opr with
    | Opcode.OR, ThreeOperands(OprReg a, OprReg b, OprReg dst) ->
      dst <> Register.O7
      && ((a = Register.O7 && b = Register.G0)
          || (a = Register.G0 && b = Register.O7))
    | _ ->
      false

  (* RESTORE in the delay slot of a transfer turns the window back to the
     caller, whose %o7 holds the address the caller returns to, and a leaf
     moves that address back into %o7 in the slot of a call, over the link of
     the call: either way the code that the transfer goes to returns where the
     caller would have, so the transfer is the last thing the caller does. A
     branch may move into %o7 for any end, as %o7 links nothing it makes. *)
  let passesReturnAddress () =
    match delaySlot with
    | Some slot ->
      slot.Opcode = Opcode.RESTORE || (linksO7 () && movesIntoO7 slot)
    | None ->
      false

  let isCall () = linksO7 () && not (passesReturnAddress ())

  (* A function returns 8 past the CALL that called it, past the CALL and
     its delay slot: JMPL from the %i7 of its own window or the %o7 of a
     leaf, and RETURN from the %i7 of the window it restores. *)
  let isRet () =
    match op, opr with
    | Opcode.JMPL, ThreeOperands(OprReg r, OprImm 8, OprReg Register.G0) ->
      r = Register.I7 || r = Register.O7
    | Opcode.RETURN, TwoOperands(OprReg Register.I7, OprImm 8) ->
      true
    | _ ->
      false

  (* GCC plants ta 5 where __builtin_trap is, a software trap that Linux
     reserves, so the program gets a signal rather than going on. ILLTRAP
     raises an illegal instruction trap whatever its operand says, and DONE
     and RETRY return from a trap handler. *)
  let isExit () =
    match op, opr with
    | Opcode.TA, TwoOperands(_, OprImm 5) -> true
    | (Opcode.ILLTRAP | Opcode.DONE | Opcode.RETRY), _ -> true
    | _ -> false

  let isInterrupt () = op = Opcode.TA && not (isExit ())

  let operands () =
    match opr with
    | NoOperand -> []
    | OneOperand o1 -> [ o1 ]
    | TwoOperands(o1, o2) -> [ o1; o2 ]
    | ThreeOperands(o1, o2, o3) -> [ o1; o2; o3 ]
    | FourOperands(o1, o2, o3, o4) -> [ o1; o2; o3; o4 ]
    | FiveOperands(o1, o2, o3, o4, o5) -> [ o1; o2; o3; o4; o5 ]

  let tryImmediate () =
    operands ()
    |> List.tryPick (function
      | OprImm c -> Some(int64 c)
      | _ -> None)

  (* A transfer goes on past its delay slot, which it runs on that way unless
     it annuls it, and so does a branch that never branches. *)
  let fallThrough () =
    if isTransfer () then addr + 8UL else addr + uint64 numBytes

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

  /// Whether this transfer hands the code it goes to the return address of
  /// the caller, which it does by restoring the window in its delay slot, or
  /// as a call, by moving an address into %o7 there: the code then returns
  /// where the caller would have.
  member _.PassesReturnAddress with get(): bool =
    isTransfer () && passesReturnAddress ()

  /// Whether this instruction copies the return address in %o7 into another
  /// register, as a leaf does right before a call that calls a function as
  /// its tail, which moves the copy back into %o7 in its delay slot.
  member _.CopiesReturnAddress with get(): bool = copiesO7 ()

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

    member _.Extent with get() =
      match delaySlot with
      | Some slot -> numBytes + slot.Length
      | None -> numBytes

    (* A branch that never branches goes on past its delay slot, as any other
       instruction goes on to the next. *)
    member _.IsBranch = isBranch ()

    member _.IsModeChanging = false

    member _.IsDirectBranch = tryGetTarget () |> ValueOption.isSome

    member _.IsIndirectBranch =
      isBranch () && (tryGetTarget () |> ValueOption.isNone)

    member _.IsCondBranch = isCondBranch ()

    (* The lifter puts the target of every conditional branch on the side
       that its condition holds. *)
    member _.IsCJmpOnTrue = isCondBranch ()

    (* A call whose delay slot passes on the return address of the caller
       never comes back, and is a jump to its callee. *)
    member _.IsCall = isCall ()

    member _.IsRET = isRet ()

    member _.IsPush = false

    member _.IsPop = false

    member _.IsInterrupt = isInterrupt ()

    member _.IsExit = isExit ()

    member _.IsNop = op = Opcode.NOP

    member _.IsInlinedAssembly = false

    (* A transfer carries its delay slot, so it ends the block itself, and
       the instruction after it ends nothing. *)
    member _.IsTerminator _ = isTransfer () || isInterrupt () || isExit ()

    member _.DirectBranchTarget(target: byref<Addr>) =
      match tryGetTarget () with
      | ValueSome t ->
        target <- t
        true
      | ValueNone ->
        false

    (* JMPL and RETURN go where registers say, never through memory. *)
    member _.IndirectTrampolineAddr(_addr: byref<Addr>) = false

    member _.MemoryDereferences(_: byref<Addr[]>) = Terminator.futureFeature ()

    (* The immediate of an instruction, which no transfer has: a branch holds
       an offset and its annul bit, and a return pops nothing off the stack. *)
    member _.Immediate(v: byref<int64>) =
      let imm = if isTransfer () then None else tryImmediate ()
      match imm with
      | Some c ->
        v <- c
        true
      | None ->
        false

    member this.GetNextInstrAddrs() =
      let fallThrough = [| fallThrough () |]
      if isCall () || isCondBranch () then
        this.AddBranchTargetIfExist fallThrough
      elif isBranch () || isExit () then
        this.AddBranchTargetIfExist [||]
      else
        fallThrough

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
