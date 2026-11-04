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

/// The BO field of a conditional branch, as the Power ISA lays it out: bit 4
/// (0x10) skips the CR test, bit 3 (0x8) names the CR value that takes the
/// branch, bit 2 (0x4) skips the CTR decrement and bit 1 (0x2) takes the
/// branch when CTR reaches zero. 0b1z1zz is "branch always".
module private BO =
  let [<Literal>] NoCRTest = 0x10UL

  let [<Literal>] CRTrue = 0x8UL

  let [<Literal>] NoCTRDec = 0x4UL

  let [<Literal>] CTRZero = 0x2UL

  let [<Literal>] Always = NoCRTest ||| NoCTRDec

  let isAlways bo = (bo &&& Always) = Always

  /// Whether the branch is taken when its predicate holds: the CR bit where
  /// it is tested, and CTR <> 0 where only the counter is.
  let isOnTrue bo =
    if (bo &&& NoCRTest) = 0UL then (bo &&& CRTrue) <> 0UL
    else (bo &&& CTRZero) = 0UL

/// Represents an instruction for PPC.
type Instruction
  internal(addr, numBytes, op, opr, oprSize, ea, lifter: ILiftable) =

  /// The BO field, which every B-form and XL-form branch carries first; the
  /// I-form branches have none and always go.
  let bo () =
    match opr with
    | TwoOperands(OprImm bo, _) | ThreeOperands(OprImm bo, _, _) -> bo
    | _ -> BO.Always

  /// Wraps a relative target at the address width of the processor.
  let wrap target =
    target &&& (UInt64.MaxValue >>> (64 - RegType.toBitWidth oprSize))

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

  interface IInstruction with

    member this.Address with get() = this.Address

    member this.Length with get() = this.Length

    member _.IsBranch =
      match op with
      | Opcode.B | Opcode.BA | Opcode.BL | Opcode.BLA
      | Opcode.BC | Opcode.BCA | Opcode.BCL | Opcode.BCLA
      | Opcode.BCLR | Opcode.BCLRL | Opcode.BCCTR | Opcode.BCCTRL
      | Opcode.BCTAR | Opcode.BCTARL -> true
      | _ -> false

    member _.IsModeChanging = false

    member _.IsDirectBranch =
      match op with
      | Opcode.B | Opcode.BA | Opcode.BL | Opcode.BLA
      | Opcode.BC | Opcode.BCA | Opcode.BCL | Opcode.BCLA -> true
      | _ -> false

    member _.IsIndirectBranch =
      match op with
      | Opcode.BCLR | Opcode.BCLRL | Opcode.BCCTR | Opcode.BCCTRL
      | Opcode.BCTAR | Opcode.BCTARL -> true
      | _ -> false

    member this.IsCondBranch =
      (this :> IInstruction).IsBranch && not (BO.isAlways (bo ()))

    member this.IsCJmpOnTrue =
      (this :> IInstruction).IsCondBranch && BO.isOnTrue (bo ())

    member _.IsCall =
      match op with
      | Opcode.BL | Opcode.BLA | Opcode.BCL | Opcode.BCLA
      | Opcode.BCLRL | Opcode.BCCTRL | Opcode.BCTARL -> true
      | _ -> false

    member _.IsRET = op = Opcode.BCLR

    member _.IsPush = false

    member _.IsPop = false

    member _.IsInterrupt =
      match op with
      | Opcode.SC | Opcode.SCV -> true
      | _ -> false

    member _.IsExit =
      match op with
      | Opcode.RFI | Opcode.TRAP -> true
      | _ -> false

    member _.IsNop = op = Opcode.NOP

    member _.IsInlinedAssembly = false

    member this.IsTerminator _ =
      let ins = this :> IInstruction
      ins.IsBranch || ins.IsInterrupt || ins.IsExit

    member _.DirectBranchTarget(target: byref<Addr>) =
      match op, opr with
      (* The parser resolves an I-form target, relative or absolute. *)
      | (Opcode.B | Opcode.BA | Opcode.BL | Opcode.BLA), OneOperand(OprImm a) ->
        target <- a
        true
      | (Opcode.BC | Opcode.BCL), ThreeOperands(_, _, OprAddr disp) ->
        target <- wrap (addr + disp)
        true
      | (Opcode.BCA | Opcode.BCLA), ThreeOperands(_, _, OprAddr a) ->
        target <- a
        true
      | _ ->
        false

    member _.IndirectTrampolineAddr(_addr: byref<Addr>) = false

    member _.MemoryDereferences(_: byref<Addr[]>) = false

    member _.Immediate(v: byref<int64>) =
      match opr with
      | OneOperand(OprImm c)
      | TwoOperands(OprImm c, _)
      | TwoOperands(_, OprImm c)
      | ThreeOperands(OprImm c, _, _)
      | ThreeOperands(_, OprImm c, _)
      | ThreeOperands(_, _, OprImm c) ->
        v <- int64 c
        true
      | _ ->
        false

    member this.GetNextInstrAddrs() =
      let ins = this :> IInstruction
      let fallThrough = addr + uint64 numBytes
      let mutable target = 0UL
      if ins.IsExit then
        [||]
      elif not ins.IsBranch then
        [| fallThrough |]
      elif ins.DirectBranchTarget &target then
        if ins.IsCondBranch then [| target; fallThrough |] else [| target |]
      elif ins.IsCondBranch then
        [| fallThrough |]
      else
        [||]

    member _.InterruptNum(num: byref<int64>) =
      match op, opr with
      | Opcode.SC, _ ->
        num <- 0L
        true
      | Opcode.SCV, OneOperand(OprImm lev) ->
        num <- int64 lev
        true
      | _ ->
        false

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
