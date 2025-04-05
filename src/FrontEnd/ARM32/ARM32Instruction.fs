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

namespace B2R2.FrontEnd.ARM32

open B2R2
open B2R2.FrontEnd.BinLifter

/// The internal representation for an ARM32 instruction used by our
/// disassembler and lifter.
type ARM32Instruction (addr, nb, cond, op, opr, its, wb, q, s, m, cf, oSz, a) =
  inherit ARM32InternalInstruction (addr, nb, cond, op, opr,
                                    its, wb, q, s, m, cf, oSz, a)

  override _.IsBranch () =
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

  override _.IsModeChanging () =
    match op with
    | Op.BLX -> true
    | _ -> false

  member _.HasConcJmpTarget () =
    match opr with
    | OneOperand (OprMemory (LiteralMode _)) -> true
    | _ -> false

  override this.IsDirectBranch () =
    this.IsBranch () && this.HasConcJmpTarget ()

  override this.IsIndirectBranch () =
    this.IsBranch () && (not <| this.HasConcJmpTarget ())

  override _.IsCondBranch () =
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

  override _.IsCJmpOnTrue () =
    match op, cond with
    | Op.B, Condition.CS | Op.B, Condition.CC
    | Op.B, Condition.MI | Op.B, Condition.PL
    | Op.B, Condition.VS | Op.B, Condition.VC
    | Op.B, Condition.HI | Op.B, Condition.LS
    | Op.B, Condition.GE | Op.B, Condition.LT
    | Op.B, Condition.GT | Op.B, Condition.LE
    | Op.B, Condition.EQ -> true
    | _ -> false

  override _.IsCall () =
    match op with
    | Opcode.BL | Opcode.BLX -> true
    | _ -> false

  override _.IsRET () =
    match op, opr with
    | Op.LDR, TwoOperands (OprReg R.PC, _) -> true
    | Op.POP, OneOperand (OprRegList regs) when List.contains R.PC regs -> true
    | _ -> false

  override _.IsInterrupt () =
    match op with
    | Op.SVC | Op.HVC | Op.SMC -> true
    | _ -> false

  override _.IsExit () =
    match op with
    | Opcode.HLT
    | Opcode.UDF
    | Opcode.ERET -> true
    | _ -> false

  override this.IsTerminator () =
       this.IsBranch ()
    || this.IsInterrupt ()
    || this.IsExit ()

  override this.DirectBranchTarget (addr: byref<Addr>) =
    if this.IsBranch () then
      match opr with
      | OneOperand (OprMemory (LiteralMode target)) ->
        (* The PC value of an instruction is its address plus 4 for a Thumb
           instruction, or plus 8 for an ARM instruction. *)
        let offset = if m = ArchOperationMode.ARMMode then 8L else 4L
        let pc = (int64 this.Address + offset) / 4L * 4L (* Align by 4 *)
        addr <- ((pc + target) &&& 0xFFFFFFFFL) |> uint64
        true
      | _ -> false
    else false

  override _.IndirectTrampolineAddr (_: byref<Addr>) =
    false

  override _.Immediate (v: byref<int64>) =
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

  member private _.GetNextMode () =
    match op with
    | Opcode.BLX
    | Opcode.BX ->
      if m = ArchOperationMode.ARMMode then
        ArchOperationMode.ThumbMode
      else ArchOperationMode.ARMMode
    | _ -> m

  member private this.AddBranchTargetIfExist addrs =
    match this.DirectBranchTarget () with
    | false, _ -> addrs
    | true, target ->
      [| (target, this.GetNextMode ()) |] |> Array.append addrs

  override this.GetNextInstrAddrs () =
    let acc = [| (this.Address + uint64 this.Length, m) |]
    if this.IsCall () then acc |> this.AddBranchTargetIfExist
    elif this.IsBranch () then
      if this.IsCondBranch () then acc |> this.AddBranchTargetIfExist
      else this.AddBranchTargetIfExist [||]
    elif op = Opcode.HLT then [||]
    else acc

  override _.InterruptNum (_num: byref<int64>) = Terminator.futureFeature ()

  override _.IsNop () =
    op = Op.NOP

  override this.Translate ctxt =
    (Lifter.translate this nb ctxt).ToStmts ()

  override this.TranslateToList ctxt =
    Lifter.translate this nb ctxt

  override this.Disasm (showAddr, nameReader) =
    let resolveSymb = not (isNull nameReader)
    let builder =
      DisasmStringBuilder (showAddr, resolveSymb, WordSize.Bit32, addr, nb)
    Disasm.disasm nameReader this builder
    builder.ToString ()

  override this.Disasm () =
    let builder =
      DisasmStringBuilder (false, false, WordSize.Bit32, addr, nb)
    Disasm.disasm null this builder
    builder.ToString ()

  override this.Decompose (showAddr) =
    let builder =
      DisasmWordBuilder (showAddr, false, WordSize.Bit32, addr, nb, 8)
    Disasm.disasm null this builder
    builder.ToArray ()

  override _.IsInlinedAssembly () = false

  override _.Equals (_) = Terminator.futureFeature ()

  override _.GetHashCode () = Terminator.futureFeature ()

// vim: set tw=80 sts=2 sw=2:
