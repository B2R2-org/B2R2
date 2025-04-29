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

namespace B2R2.FrontEnd.ARM64

open B2R2
open B2R2.FrontEnd.BinLifter

/// The internal representation for an ARM64 instruction used by our
/// disassembler and lifter.
type ARM64Instruction (addr, numBytes, insInfo, wordSize) =
  inherit Instruction (addr, numBytes, wordSize)

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override this.IsBranch () =
    match this.Info.Opcode with
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

  override _.IsModeChanging () = false

  member this.HasConcJmpTarget () =
    match this.Info.Operands with
    (* All other instructions *)
    | OneOperand (OprMemory (LiteralMode _)) -> true
    (* CBNZ and CBZ *)
    | TwoOperands (_, OprMemory (LiteralMode _)) -> true
    (* TBNZ and TBZ *)
    | ThreeOperands (_, _, OprMemory (LiteralMode _)) -> true
    | _ -> false

  override this.IsDirectBranch () =
    this.IsBranch () && this.HasConcJmpTarget ()

  override this.IsIndirectBranch () =
    this.IsBranch () && (not <| this.HasConcJmpTarget ())

  override this.IsCondBranch () =
    match this.Info.Opcode with
    | Opcode.BEQ | Opcode.BCS | Opcode.BMI | Opcode.BVS | Opcode.BHI
    | Opcode.BGE | Opcode.BGT | Opcode.BNE | Opcode.BCC | Opcode.BPL
    | Opcode.BVC | Opcode.BLS | Opcode.BLT | Opcode.BLE
    | Opcode.CBNZ | Opcode.CBZ | Opcode.TBNZ | Opcode.TBZ -> true
    | _ -> false

  override this.IsCJmpOnTrue () =
    match this.Info.Opcode with
    | Opcode.BEQ | Opcode.BCS | Opcode.BMI | Opcode.BVS | Opcode.BHI
    | Opcode.BGE | Opcode.BGT | Opcode.BCC | Opcode.BPL | Opcode.BVC
    | Opcode.BLS | Opcode.BLT | Opcode.BLE | Opcode.CBZ | Opcode.TBZ -> true
    | _ -> false

  override this.IsCall () =
    match this.Info.Opcode with
    | Opcode.BL | Opcode.BLR -> true
    | _ -> false

  override this.IsRET () =
    this.Info.Opcode = Opcode.RET

  override this.IsInterrupt () =
    match this.Info.Opcode with
    | Opcode.SVC | Opcode.HVC | Opcode.SMC -> true
    | _ -> false

  override this.IsExit () =
    match this.Info.Opcode with
    | Opcode.HLT
    | Opcode.ERET -> true
    | _ -> false

  override this.IsTerminator () =
       this.IsBranch ()
    || this.IsInterrupt ()
    || this.IsExit ()

  override this.DirectBranchTarget (addr: byref<Addr>) =
    if this.IsBranch () then
      match this.Info.Operands with
      | OneOperand (OprMemory (LiteralMode (ImmOffset (Lbl offset)))) ->
        addr <- (this.Address + uint64 offset)
        true
      | TwoOperands (_, OprMemory (LiteralMode (ImmOffset (Lbl offset)))) ->
        addr <- (this.Address + uint64 offset)
        true
      | ThreeOperands (_, _, OprMemory (LiteralMode (ImmOffset (Lbl offs)))) ->
        addr <- (this.Address + uint64 offs)
        true
      | _ -> false
    else false

  override this.IndirectTrampolineAddr (_addr: byref<Addr>) =
    if this.IsIndirectBranch () then Terminator.futureFeature ()
    else false

  override this.Immediate (v: byref<int64>) =
    match this.Info.Operands with
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

  override _.GetNextInstrAddrs () = Terminator.futureFeature ()

  override _.InterruptNum (_num: byref<int64>) = Terminator.futureFeature ()

  override this.IsNop () =
    this.Info.Opcode = Opcode.NOP

  override this.Translate builder =
    (Lifter.translate this.Info numBytes builder).Stream.ToStmts ()

  override this.TranslateToList builder =
    (Lifter.translate this.Info numBytes builder).Stream

  override this.Disasm (showAddr, _) =
    let builder =
      DisasmStringBuilder (showAddr, false, WordSize.Bit64, addr, numBytes)
    Disasm.disasm this.Info builder
    builder.ToString ()

  override this.Disasm () =
    let builder =
      DisasmStringBuilder (false, false, WordSize.Bit64, addr, numBytes)
    Disasm.disasm this.Info builder
    builder.ToString ()

  override this.Decompose (showAddr) =
    let builder =
      DisasmWordBuilder (showAddr, false, WordSize.Bit64, addr, numBytes, 8)
    Disasm.disasm this.Info builder
    builder.ToArray ()

  override _.IsInlinedAssembly () = false

  override _.Equals (_) = Terminator.futureFeature ()

  override _.GetHashCode () = Terminator.futureFeature ()

// vim: set tw=80 sts=2 sw=2:
