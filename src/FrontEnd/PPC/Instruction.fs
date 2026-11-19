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

namespace B2R2.FrontEnd.PPC

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents an instruction for PPC.
type Instruction
  internal(addr, numBytes, op, opr, oprSize, ea, lifter: ILiftable) =

  (* The branches of the base encoding and of VLE, and rfebb, which goes back
     to where an event-based branch came from. *)
  let isBranch () =
    match op with
    | Opcode.B | Opcode.BA | Opcode.BL | Opcode.BLA | Opcode.BC | Opcode.BCA
    | Opcode.BCL | Opcode.BCLA | Opcode.BCLR | Opcode.BCLRL | Opcode.BCCTR
    | Opcode.BCCTRL | Opcode.BCTAR | Opcode.BCTARL | Opcode.RFEBB
    | Opcode.E_B | Opcode.E_BL | Opcode.E_BC | Opcode.E_BCL | Opcode.SE_B
    | Opcode.SE_BL | Opcode.SE_BC | Opcode.SE_BLR | Opcode.SE_BLRL
    | Opcode.SE_BCTR | Opcode.SE_BCTRL -> true
    | _ -> false

  let isDirect () =
    match op with
    | Opcode.B | Opcode.BA | Opcode.BL | Opcode.BLA | Opcode.BC | Opcode.BCA
    | Opcode.BCL | Opcode.BCLA | Opcode.E_B | Opcode.E_BL | Opcode.E_BC
    | Opcode.E_BCL | Opcode.SE_B | Opcode.SE_BL | Opcode.SE_BC -> true
    | _ -> false

  (* The BO field, which a branch of the base encoding names first: BO_0
     (0x10) skips the test of the CR bit, BO_1 (0x8) is the value of the bit
     that takes the branch, BO_2 (0x4) skips the decrement and the test of CTR,
     and BO_3 (0x2) takes the branch when CTR reaches zero rather than when it
     does not. An I-form branch has none, as it always goes. *)
  let boField () =
    match opr with
    | TwoOperands(OprImm bo, _)
    | ThreeOperands(OprImm bo, _, _) -> bo
    | _ -> 0x14UL

  (* A branch that skips both tests goes whatever CTR and the CR bit hold. The
     conditional branches of VLE always test one of them. *)
  let isCondBranch () =
    match op with
    | Opcode.BC | Opcode.BCA | Opcode.BCL | Opcode.BCLA | Opcode.BCLR
    | Opcode.BCLRL | Opcode.BCCTR | Opcode.BCCTRL | Opcode.BCTAR
    | Opcode.BCTARL -> (boField () &&& 0x14UL) <> 0x14UL
    | Opcode.E_BC | Opcode.E_BCL | Opcode.SE_BC -> true
    | _ -> false

  (* The base encoding takes a branch with BO_1 set when the CR bit is set,
     and one that tests CTR alone with BO_3 set when CTR reaches zero. The BO
     of VLE says the same in its low bit. *)
  let isCJmpOnTrue () =
    match op, opr with
    | (Opcode.E_BC | Opcode.E_BCL | Opcode.SE_BC),
      ThreeOperands(OprImm bo, _, _) ->
      (bo &&& 0x1UL) <> 0UL
    | _ when isCondBranch () ->
      let bo = boField ()
      if (bo &&& 0x10UL) = 0UL then (bo &&& 0x8UL) <> 0UL
      else (bo &&& 0x2UL) <> 0UL
    | _ ->
      false

  let links () =
    match op with
    | Opcode.BL | Opcode.BLA | Opcode.BCL | Opcode.BCLA | Opcode.BCLRL
    | Opcode.BCCTRL | Opcode.BCTARL | Opcode.E_BL | Opcode.E_BCL
    | Opcode.SE_BL | Opcode.SE_BLRL | Opcode.SE_BCTRL -> true
    | _ -> false

  (* A target wraps around the address space at the width of a register. *)
  let wrap (target: Addr) =
    target &&& (UInt64.MaxValue >>> (64 - RegType.toBitWidth oprSize))

  (* An I-form branch holds its target, which the parser has resolved, and an
     absolute B-form branch holds it as its displacement. *)
  let tryGetTarget () =
    match op, opr with
    | (Opcode.B | Opcode.BA | Opcode.BL | Opcode.BLA), OneOperand(OprImm t)
    | (Opcode.BCA | Opcode.BCLA), ThreeOperands(_, _, OprAddr t) ->
      ValueSome(wrap t)
    | _, OneOperand(OprAddr disp)
    | _, ThreeOperands(_, _, OprAddr disp) when isDirect () ->
      ValueSome(wrap (addr + disp))
    | _ ->
      ValueNone

  (* bcl 20,31,$+4 links only to read where the code is, which the ISA keeps
     off the link stack: control goes on to the next instruction, and no
     function returns there. *)
  let readsPC () =
    op = Opcode.BCL
    && not (isCondBranch ())
    && tryGetTarget () = ValueSome(addr + uint64 numBytes)

  let isInterrupt () =
    match op with
    | Opcode.SC | Opcode.SCV | Opcode.E_SC | Opcode.SE_SC -> true
    | _ -> false

  (* A trap whose TO takes in less-than, greater-than and equal, in either
     signedness, traps whatever it compares. *)
  let trapsAlways (tO: uint64) =
    (tO &&& 0x1CUL) = 0x1CUL || (tO &&& 0x7UL) = 0x7UL

  (* GCC puts a trap where __builtin_trap is, and the program interrupt it
     raises returns, if at all, to the trap itself. An illegal instruction
     does the same, and rfi leaves for the code that the interrupt came
     from. *)
  let isExit () =
    match op, opr with
    | (Opcode.TRAP | Opcode.SE_ILLEGAL | Opcode.RFI), _ ->
      true
    | (Opcode.TW | Opcode.TD | Opcode.TWI | Opcode.TDI),
      ThreeOperands(OprImm tO, _, _) ->
      trapsAlways tO
    | _ ->
      false

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

  /// Effective address.
  member _.EffectiveAddress with get(): Addr = ea

  member private this.AddBranchTargetIfExist addrs =
    match (this :> IInstruction).DirectBranchTarget() with
    | false, _ -> addrs
    | true, target -> Array.append addrs [| target |]

  interface IInstruction with

    member this.Address with get() = this.Address

    member this.Length with get() = this.Length

    member this.Extent with get() = this.Length

    member _.IsBranch = isBranch ()

    member _.IsModeChanging = false

    member _.IsDirectBranch = isDirect ()

    member _.IsIndirectBranch = isBranch () && not (isDirect ())

    member _.IsCondBranch = isCondBranch ()

    member _.IsCJmpOnTrue = isCJmpOnTrue ()

    member _.IsCall = links () && not (readsPC ())

    member _.IsRET =
      match op with
      | Opcode.BCLR | Opcode.SE_BLR | Opcode.RFEBB -> true
      | _ -> false

    member _.IsPush = false

    member _.IsPop = false

    member _.IsInterrupt = isInterrupt ()

    member _.IsExit = isExit ()

    member _.IsNop = op = Opcode.NOP || op = Opcode.XNOP

    member _.IsInlinedAssembly = false

    member _.IsTerminator _ = isBranch () || isInterrupt () || isExit ()

    member _.DirectBranchTarget(target: byref<Addr>) =
      match tryGetTarget () with
      | ValueSome t ->
        target <- t
        true
      | ValueNone ->
        false

    (* No branch reads its target from memory. *)
    member _.IndirectTrampolineAddr(_addr: byref<Addr>) = false

    member _.MemoryDereferences(_: byref<Addr[]>) = Terminator.futureFeature ()

    (* BO and BI only pick the condition of a branch, and a return pops
       nothing off the stack, which an immediate of a return would tell. *)
    member _.Immediate(v: byref<int64>) =
      match opr with
      | TwoOperands(_, OprImm c)
      | ThreeOperands(_, _, OprImm c) when not (isBranch ()) ->
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
      let builder = StringDisasmBuilder(false, null, WordSize.Bit32)
      lifter.Disasm(this, builder).ToString()

    member this.Decompose builder = lifter.Disasm(this, builder).ToAsmWords()

and internal ILiftable =
  abstract Lift: Instruction * ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction * IDisasmBuilder -> IDisasmBuilder
