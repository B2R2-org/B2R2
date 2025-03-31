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

namespace B2R2.FrontEnd.BinLifter.MIPS

open B2R2
open B2R2.FrontEnd.Register
open B2R2.FrontEnd.BinLifter

/// The internal representation for a MIPS instruction used by our
/// disassembler and lifter.
type MIPSInstruction (addr, numBytes, insInfo, wordSize) =
  inherit Instruction (addr, numBytes, wordSize)

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override __.IsBranch () =
    match __.Info.Opcode with
    | Opcode.B | Opcode.BAL | Opcode.BEQ | Opcode.BGEZ | Opcode.BGEZAL
    | Opcode.BGTZ | Opcode.BLEZ | Opcode.BLTZ | Opcode.BNE
    | Opcode.JALR | Opcode.JALRHB | Opcode.JR | Opcode.JRHB
    | Opcode.J | Opcode.JAL | Opcode.BC1F | Opcode.BC1T -> true
    | _ -> false

  override __.IsModeChanging () = false

  member __.HasConcJmpTarget () =
    match __.Info.Operands with
    | OneOperand (OpAddr _)
    | TwoOperands (_, OpAddr _)
    | ThreeOperands (_, _, OpAddr _)
    | OneOperand (OpImm _) -> true
    | _ -> false

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () =
    match __.Info.Opcode with
    | Opcode.BEQ | Opcode.BLTZ | Opcode.BLEZ | Opcode.BGTZ | Opcode.BGEZ
    | Opcode.BGEZAL | Opcode.BNE | Opcode.BC1F | Opcode.BC1T -> true
    | _ -> false

  override __.IsCJmpOnTrue () =
    match __.Info.Opcode with
    | Opcode.BEQ | Opcode.BLTZ | Opcode.BLEZ | Opcode.BGTZ | Opcode.BGEZ
    | Opcode.BGEZAL | Opcode.BC1F | Opcode.BC1T -> true
    | _ -> false

  override __.IsCall () =
    match __.Info.Opcode with
    | Opcode.BAL | Opcode.BGEZAL | Opcode.JALR | Opcode.JALRHB | Opcode.JAL ->
      true
    | _ -> false

  override __.IsRET () =
    match __.Info.Opcode with
    | Opcode.JR ->
      match __.Info.Operands with
      | OneOperand (OpReg (MIPS.R31)) -> true
      | _ -> false
    | _ -> false

  override __.IsInterrupt () =
    match __.Info.Opcode with
    | Opcode.SYSCALL | Opcode.WAIT -> true
    | _ -> false

  override __.IsExit () =
    match __.Info.Opcode with
    | Opcode.DERET | Opcode.ERET | Opcode.ERETNC -> true
    | _ -> false

  override __.IsTerminator () =
       __.IsBranch ()
    || __.IsInterrupt ()
    || __.IsExit ()

  override __.DirectBranchTarget (addr: byref<Addr>) =
    if __.IsBranch () then
      match __.Info.Operands with
      | OneOperand (OpAddr (Relative offset)) ->
        addr <- (int64 __.Address + offset) |> uint64
        true
      | TwoOperands (_, OpAddr (Relative offset)) ->
        addr <- (int64 __.Address + offset) |> uint64
        true
      | ThreeOperands (_, _,OpAddr (Relative offset)) ->
        addr <- (int64 __.Address + offset) |> uint64
        true
      | OneOperand (OpImm (imm)) ->
        addr <- imm
        true
      | _ -> false
    else false

  override __.IndirectTrampolineAddr (_addr: byref<Addr>) =
    if __.IsIndirectBranch () then Utils.futureFeature ()
    else false

  override __.Immediate (v: byref<int64>) =
    match __.Info.Operands with
    | OneOperand (OpImm (c))
    | TwoOperands (OpImm (c), _)
    | TwoOperands (_, OpImm (c))
    | ThreeOperands (OpImm (c), _, _)
    | ThreeOperands (_, OpImm (c), _)
    | ThreeOperands (_, _, OpImm (c))
    | FourOperands (OpImm (c), _, _, _)
    | FourOperands (_, OpImm (c), _, _)
    | FourOperands (_, _, OpImm (c), _)
    | FourOperands (_, _, _, OpImm (c)) -> v <- int64 c; true
    | _ -> false

  override __.GetNextInstrAddrs () = Utils.futureFeature ()

  override __.InterruptNum (_num: byref<int64>) = Utils.futureFeature ()

  override __.IsNop () =
    __.Info.Opcode = Opcode.NOP

  override __.Translate ctxt =
    (Lifter.translate __.Info numBytes ctxt).ToStmts ()

  override __.TranslateToList ctxt =
    Lifter.translate __.Info numBytes ctxt

  override __.Disasm (showAddr, _) =
    let builder =
      DisasmStringBuilder (showAddr, false, wordSize, addr, numBytes)
    Disasm.disasm wordSize __.Info builder
    builder.ToString ()

  override __.Disasm () =
    let builder =
      DisasmStringBuilder (false, false, wordSize, addr, numBytes)
    Disasm.disasm wordSize __.Info builder
    builder.ToString ()

  override __.Decompose (showAddr) =
    let builder =
      DisasmWordBuilder (showAddr, false, wordSize, addr, numBytes, 8)
    Disasm.disasm wordSize __.Info builder
    builder.ToArray ()

  override __.IsInlinedAssembly () = false

  override __.Equals (_) = Utils.futureFeature ()
  override __.GetHashCode () = Utils.futureFeature ()

// vim: set tw=80 sts=2 sw=2:
