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

namespace B2R2.FrontEnd.BinLifter.ARM64

open B2R2
open B2R2.FrontEnd.BinLifter

/// The internal representation for an ARM64 instruction used by our
/// disassembler and lifter.
type ARM64Instruction (addr, numBytes, insInfo, wordSize) =
  inherit Instruction (addr, numBytes, wordSize)

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override __.IsBranch () =
    match __.Info.Opcode with
    (* Conditional branch *)
    | Opcode.BEQ | Opcode.BCS | Opcode.BMI | Opcode.BVS | Opcode.BHI
    | Opcode.BGE | Opcode.BGT | Opcode.BNE | Opcode.BCC | Opcode.BPL
    | Opcode.BVC | Opcode.BLS | Opcode.BLT | Opcode.BLE
    | Opcode.CBNZ | Opcode.CBZ | Opcode.TBNZ | Opcode.TBZ
    (* Unconditional branch (immediate) *)
    | Opcode.B | Opcode.BL
    (* Unconditional branch (register) *)
    | Opcode.BLR | Opcode.BR | Opcode.RET
      -> true
    | _ -> false

  override __.IsModeChanging () = false

  member __.HasConcJmpTarget () =
    match __.Info.Operands with
    (* All other instructions *)
    | OneOperand (OprMemory (LiteralMode _)) -> true
    (* CBNZ and CBZ *)
    | TwoOperands (_, OprMemory (LiteralMode _)) -> true
    (* TBNZ and TBZ *)
    | ThreeOperands (_, _, OprMemory (LiteralMode _)) -> true
    | _ -> false

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () =
    match __.Info.Opcode with
    | Opcode.BEQ | Opcode.BCS | Opcode.BMI | Opcode.BVS | Opcode.BHI
    | Opcode.BGE | Opcode.BGT | Opcode.BNE | Opcode.BCC | Opcode.BPL
    | Opcode.BVC | Opcode.BLS | Opcode.BLT | Opcode.BLE
    | Opcode.CBNZ | Opcode.CBZ | Opcode.TBNZ | Opcode.TBZ -> true
    | _ -> false

  override __.IsCJmpOnTrue () =
    match __.Info.Opcode with
    | Opcode.BEQ | Opcode.BCS | Opcode.BMI | Opcode.BVS | Opcode.BHI
    | Opcode.BGE | Opcode.BGT | Opcode.BCC | Opcode.BPL | Opcode.BVC
    | Opcode.BLS | Opcode.BLT | Opcode.BLE | Opcode.CBZ | Opcode.TBZ -> true
    | _ -> false

  override __.IsCall () =
    match __.Info.Opcode with
    | Opcode.BL | Opcode.BLR -> true
    | _ -> false

  override __.IsRET () =
    __.Info.Opcode = Opcode.RET

  override __.IsInterrupt () =
    match __.Info.Opcode with
    | Opcode.SVC | Opcode.HVC | Opcode.SMC -> true
    | _ -> false

  override __.IsExit () =
    match __.Info.Opcode with
    | Opcode.HLT
    | Opcode.ERET -> true
    | _ -> false

  override __.IsBBLEnd () =
       __.IsBranch ()
    || __.IsInterrupt ()
    || __.IsExit ()

  override __.DirectBranchTarget (addr: byref<Addr>) =
    if __.IsBranch () then
      match __.Info.Operands with
      | OneOperand (OprMemory (LiteralMode (ImmOffset (Lbl offset)))) ->
        addr <- (__.Address + uint64 offset)
        true
      | TwoOperands (_, OprMemory (LiteralMode (ImmOffset (Lbl offset)))) ->
        addr <- (__.Address + uint64 offset)
        true
      | ThreeOperands (_, _, OprMemory (LiteralMode (ImmOffset (Lbl offs)))) ->
        addr <- (__.Address + uint64 offs)
        true
      | _ -> false
    else false

  override __.IndirectTrampolineAddr (_addr: byref<Addr>) =
    if __.IsIndirectBranch () then Utils.futureFeature ()
    else false

  override __.Immediate (v: byref<int64>) =
    match __.Info.Operands with
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
    | FiveOperands (_, _, _, _, OprImm c) -> v <- c; true
    | _ -> false

  override __.GetNextInstrAddrs () = Utils.futureFeature ()

  override __.InterruptNum (_num: byref<int64>) = Utils.futureFeature ()

  override __.IsNop () =
    __.Info.Opcode = Opcode.NOP

  override __.Translate ctxt =
    (Lifter.translate __.Info numBytes ctxt).ToStmts ()

  override __.TranslateToList ctxt =
    Lifter.translate __.Info numBytes ctxt

  override __.Disasm (showAddr, _resolveSymbol, _fileInfo) =
    let builder =
      DisasmStringBuilder (showAddr, false, WordSize.Bit64, addr, numBytes)
    Disasm.disasm __.Info builder
    builder.Finalize ()

  override __.Disasm () =
    let builder =
      DisasmStringBuilder (false, false, WordSize.Bit64, addr, numBytes)
    Disasm.disasm __.Info builder
    builder.Finalize ()

  override __.Decompose (showAddr) =
    let builder =
      DisasmWordBuilder (showAddr, false, WordSize.Bit64, addr, numBytes, 8)
    Disasm.disasm __.Info builder
    builder.Finalize ()

  override __.IsInlinedAssembly () = false

  override __.Equals (_) = Utils.futureFeature ()
  override __.GetHashCode () = Utils.futureFeature ()

// vim: set tw=80 sts=2 sw=2:
