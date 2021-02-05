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
type ARM32Instruction (addr, numBytes, insInfo, ctxt, auxctxt) =
  inherit Instruction (addr, numBytes, WordSize.Bit32)

  let dummyHelper = DisasmHelper ()

  member val Info: InsInfo = insInfo

  override __.NextParsingContext = ctxt

  override __.AuxParsingContext = auxctxt

  override __.IsBranch () =
    match __.Info.Opcode with
    | Op.B | Op.BL | Op.BLX | Op.BX | Op.BXJ
    | Op.CBNZ | Op.CBZ
    | Op.TBB | Op.TBH -> true
    | Op.LDR ->
      match __.Info.Operands with
      | TwoOperands (OprReg R.PC, _) -> true
      | _ -> false
    | Op.POP ->
      match __.Info.Operands with
      | OneOperand (OprRegList regs) -> List.contains R.PC regs
      | _ -> false
    | _ -> false

  member __.HasConcJmpTarget () =
    match __.Info.Operands with
    | OneOperand (OprMemory (LiteralMode _)) -> true
    | _ -> false

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () =
    match __.Info.Opcode, __.Info.Condition with
    | Op.B, Some Condition.AL -> false
    | Op.B, Some Condition.NV -> false
    | Op.B, Some Condition.UN -> false
    | Op.B, Some _ -> true
    | Op.BX, Some Condition.AL -> false
    | Op.BX, Some Condition.NV -> false
    | Op.BX, Some Condition.UN -> false
    | Op.BX, Some _ -> true
    | _ -> false

  override __.IsCJmpOnTrue () =
    match __.Info.Opcode, __.Info.Condition with
    | Op.B, Some Condition.CS | Op.B, Some Condition.CC
    | Op.B, Some Condition.MI | Op.B, Some Condition.PL
    | Op.B, Some Condition.VS | Op.B, Some Condition.VC
    | Op.B, Some Condition.HI | Op.B, Some Condition.LS
    | Op.B, Some Condition.GE | Op.B, Some Condition.LT
    | Op.B, Some Condition.GT | Op.B, Some Condition.LE
    | Op.B, Some Condition.EQ -> true
    | _ -> false

  override __.IsCall () =
    match __.Info.Opcode with
    | Opcode.BL | Opcode.BLX -> true
    | _ -> false

  override __.IsRET () =
    Utils.futureFeature ()

  override __.IsInterrupt () =
    __.Info.Opcode = Op.SVC

  override __.IsExit () =
    Utils.futureFeature ()

  override __.IsBBLEnd () =
    __.IsDirectBranch () ||
    __.IsIndirectBranch () ||
    __.Info.Opcode = Op.SVC

  override __.DirectBranchTarget (addr: byref<Addr>) =
    if __.IsBranch () then
      match __.Info.Operands with
      | OneOperand (OprMemory (LiteralMode target)) ->
        (* The PC value of an instruction is its address plus 4 for a Thumb
           instruction, or plus 8 for an ARM instruction. *)
        let offset = if __.Info.Mode = ArchOperationMode.ARMMode then 8L else 4L
        let pc = (int64 __.Address + offset) / 4L * 4L (* Align by 4 *)
        addr <- ((pc + target) &&& 0xFFFFFFFFL) |> uint64
        true
      | _ -> false
    else false

  override __.IndirectTrampolineAddr (_: byref<Addr>) =
    false

  member private __.GetNextMode () =
    match __.Info.Opcode with
    | Opcode.BLX
    | Opcode.BX ->
      if __.Info.Mode = ArchOperationMode.ARMMode then
        ArchOperationMode.ThumbMode
      else ArchOperationMode.ARMMode
    | _ -> __.Info.Mode

  member private __.AddBranchTargetIfExist addrs =
    match __.DirectBranchTarget () |> Utils.tupleToOpt with
    | None -> addrs
    | Some target ->
      Seq.singleton (target, __.GetNextMode ()) |> Seq.append addrs

  override __.GetNextInstrAddrs () =
    let acc = Seq.singleton (__.Address + uint64 __.Length, __.Info.Mode)
    if __.IsCall () then acc |> __.AddBranchTargetIfExist
    elif __.IsBranch () then
      if __.IsCondBranch () then acc |> __.AddBranchTargetIfExist
      else __.AddBranchTargetIfExist Seq.empty
    elif __.Info.Opcode = Opcode.HLT then Seq.empty
    else acc

  override __.InterruptNum (_num: byref<int64>) = Utils.futureFeature ()

  override __.IsNop () =
    __.Info.Opcode = Op.NOP

  override __.Translate ctxt =
    Lifter.translate __.Info ctxt

  override __.Disasm (showAddr, resolveSym, disasmHelper) =
    let builder =
      DisasmStringBuilder (showAddr, resolveSym, WordSize.Bit32, addr, numBytes)
    Disasm.disasm disasmHelper __.Info builder
    builder.Finalize ()

  override __.Disasm () =
    let builder =
      DisasmStringBuilder (false, false, WordSize.Bit32, addr, numBytes)
    Disasm.disasm dummyHelper __.Info builder
    builder.Finalize ()

  override __.Decompose (showAddr) =
    let builder =
      DisasmWordBuilder (showAddr, false, WordSize.Bit32, addr, numBytes, 8)
    Disasm.disasm dummyHelper __.Info builder
    builder.Finalize ()

// vim: set tw=80 sts=2 sw=2:
