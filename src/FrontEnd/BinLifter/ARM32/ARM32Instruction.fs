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

namespace B2R2.FrontEnd.BinLifter.ARM32

open B2R2
open B2R2.FrontEnd.BinLifter

/// The internal representation for an ARM32 instruction used by our
/// disassembler and lifter.
type ARM32Instruction (addr, nb, cond, op, opr, its, wb, q, s, m, cf) =
  inherit ARM32InternalInstruction (addr, nb, cond, op, opr,
                                    its, wb, q, s, m, cf)

  let dummyHelper = DisasmHelper ()

  override __.IsBranch () =
    match op with
    | Op.B | Op.BL | Op.BLX | Op.BX | Op.BXJ
    | Op.CBNZ | Op.CBZ
    | Op.TBB | Op.TBH -> true
    | Op.LDR ->
      match opr with
      | TwoOperands (OprReg R.PC, _) -> true
      | _ -> false
    | Op.POP ->
      match opr with
      | OneOperand (OprRegList regs) -> List.contains R.PC regs
      | _ -> false
    | _ -> false

  override __.IsModeChanging () =
    match op with
    | Op.BLX -> true
    | _ -> false

  member __.HasConcJmpTarget () =
    match opr with
    | OneOperand (OprMemory (LiteralMode _)) -> true
    | _ -> false

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () =
    match op, cond with
    | Op.B, Condition.AL -> false
    | Op.B, Condition.NV -> false
    | Op.B, Condition.UN -> false
    | Op.B, _ -> true
    | Op.BX, Condition.AL -> false
    | Op.BX, Condition.NV -> false
    | Op.BX, Condition.UN -> false
    | Op.BX, _ -> true
    | _ -> false

  override __.IsCJmpOnTrue () =
    match op, cond with
    | Op.B, Condition.CS | Op.B, Condition.CC
    | Op.B, Condition.MI | Op.B, Condition.PL
    | Op.B, Condition.VS | Op.B, Condition.VC
    | Op.B, Condition.HI | Op.B, Condition.LS
    | Op.B, Condition.GE | Op.B, Condition.LT
    | Op.B, Condition.GT | Op.B, Condition.LE
    | Op.B, Condition.EQ -> true
    | _ -> false

  override __.IsCall () =
    match op with
    | Opcode.BL | Opcode.BLX -> true
    | _ -> false

  override __.IsRET () =
    match op, opr with
    | Op.LDR, TwoOperands (OprReg R.PC, _) -> true
    | Op.POP, OneOperand (OprRegList regs) when List.contains R.PC regs -> true
    | _ -> false

  override __.IsInterrupt () =
    match op with
    | Op.SVC | Op.HVC | Op.SMC -> true
    | _ -> false

  override __.IsExit () =
    Utils.futureFeature ()

  override __.IsBBLEnd () =
    __.IsDirectBranch () ||
    __.IsIndirectBranch () ||
    __.IsInterrupt ()

  override __.DirectBranchTarget (addr: byref<Addr>) =
    if __.IsBranch () then
      match opr with
      | OneOperand (OprMemory (LiteralMode target)) ->
        (* The PC value of an instruction is its address plus 4 for a Thumb
           instruction, or plus 8 for an ARM instruction. *)
        let offset = if m = ArchOperationMode.ARMMode then 8L else 4L
        let pc = (int64 __.Address + offset) / 4L * 4L (* Align by 4 *)
        addr <- ((pc + target) &&& 0xFFFFFFFFL) |> uint64
        true
      | _ -> false
    else false

  override __.IndirectTrampolineAddr (_: byref<Addr>) =
    false

  override __.Immediate (v: byref<int64>) =
    match opr with
    | OneOperand (OprImm c)
    | TwoOperands (OprImm c, _)
    | TwoOperands (_, OprImm c)
    | ThreeOperands (OprImm c, _, _)
    | ThreeOperands (_, OprImm c, _)
    | ThreeOperands (_, _, OprImm c)
    | FourOperands (OprImm c, _, _, _)
    | FourOperands (_, OprImm c, _, _)
    | FourOperands (_, _, OprImm c, _)
    | FourOperands (_, _, _, OprImm c)
    | FiveOperands (OprImm c, _, _, _, _)
    | FiveOperands (_, OprImm c, _, _, _)
    | FiveOperands (_, _, OprImm c, _, _)
    | FiveOperands (_, _, _, OprImm c, _)
    | FiveOperands (_, _, _, _, OprImm c)
    | SixOperands (OprImm c, _, _, _, _, _)
    | SixOperands (_, OprImm c, _, _, _, _)
    | SixOperands (_, _, OprImm c, _, _, _)
    | SixOperands (_, _, _, OprImm c, _, _)
    | SixOperands (_, _, _, _, OprImm c, _)
    | SixOperands (_, _, _, _, _, OprImm c) -> v <- c; true
    | _ -> false

  member private __.GetNextMode () =
    match op with
    | Opcode.BLX
    | Opcode.BX ->
      if m = ArchOperationMode.ARMMode then
        ArchOperationMode.ThumbMode
      else ArchOperationMode.ARMMode
    | _ -> m

  member private __.AddBranchTargetIfExist addrs =
    match __.DirectBranchTarget () |> Utils.tupleToOpt with
    | None -> addrs
    | Some target ->
      Seq.singleton (target, __.GetNextMode ()) |> Seq.append addrs

  override __.GetNextInstrAddrs () =
    let acc = Seq.singleton (__.Address + uint64 __.Length, m)
    if __.IsCall () then acc |> __.AddBranchTargetIfExist
    elif __.IsBranch () then
      if __.IsCondBranch () then acc |> __.AddBranchTargetIfExist
      else __.AddBranchTargetIfExist Seq.empty
    elif op = Opcode.HLT then Seq.empty
    else acc

  override __.InterruptNum (_num: byref<int64>) = Utils.futureFeature ()

  override __.IsNop () =
    op = Op.NOP

  override __.Translate ctxt =
    (Lifter.translate __ ctxt).ToStmts ()

  override __.TranslateToList ctxt =
    Lifter.translate __ ctxt

  override __.Disasm (showAddr, resolveSym, disasmHelper) =
    let builder =
      DisasmStringBuilder (showAddr, resolveSym, WordSize.Bit32, addr, nb)
    Disasm.disasm disasmHelper __ builder
    builder.Finalize ()

  override __.Disasm () =
    let builder =
      DisasmStringBuilder (false, false, WordSize.Bit32, addr, nb)
    Disasm.disasm dummyHelper __ builder
    builder.Finalize ()

  override __.Decompose (showAddr) =
    let builder =
      DisasmWordBuilder (showAddr, false, WordSize.Bit32, addr, nb, 8)
    Disasm.disasm dummyHelper __ builder
    builder.Finalize ()

  override __.IsInlinedAssembly () = false

  override __.Equals (_) = Utils.futureFeature ()
  override __.GetHashCode () = Utils.futureFeature ()

// vim: set tw=80 sts=2 sw=2:
