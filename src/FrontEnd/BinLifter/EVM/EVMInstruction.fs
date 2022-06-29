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

namespace B2R2.FrontEnd.BinLifter.EVM

open B2R2
open B2R2.FrontEnd.BinLifter

/// The internal representation for a EVM instruction used by our
/// disassembler and lifter.
type EVMInstruction (addr, numBytes, insInfo, wordSize) =
  inherit Instruction (addr, numBytes, wordSize)

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override __.IsBranch () =
    match __.Info.Opcode with
    | Opcode.JUMP
    | Opcode.JUMPI -> true
    | _ -> false

  override __.IsModeChanging () = false

  member __.HasConcJmpTarget () = false

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () =
    match __.Info.Opcode with
    | Opcode.JUMPI -> true
    | _ -> false

  override __.IsCJmpOnTrue () =
    match __.Info.Opcode with
    | Opcode.JUMPI -> true
    | _ -> false

  override __.IsCall () = false

  override __.IsRET () =
    match __.Info.Opcode with
    | Opcode.REVERT
    | Opcode.RETURN -> true
    | _ -> false

  override __.IsInterrupt () = Utils.futureFeature ()

  override __.IsExit () =
    __.Info.Opcode = Opcode.REVERT
    || __.Info.Opcode = Opcode.RETURN
    || __.Info.Opcode = Opcode.SELFDESTRUCT
    || __.Info.Opcode = Opcode.INVALID
    || __.Info.Opcode = Opcode.STOP

  override __.IsBBLEnd () =
    __.IsDirectBranch ()
    || __.IsIndirectBranch ()
    || __.Info.Opcode = Opcode.REVERT
    || __.Info.Opcode = Opcode.RETURN
    || __.Info.Opcode = Opcode.SELFDESTRUCT
    || __.Info.Opcode = Opcode.INVALID
    || __.Info.Opcode = Opcode.STOP

  override __.DirectBranchTarget (_addr: byref<Addr>) = false

  override __.IndirectTrampolineAddr (_addr: byref<Addr>) =
    // FIXME
    false

  override __.Immediate (_) = false

  override __.GetNextInstrAddrs () =
    let fallthrough = __.Address + uint64 __.Length
    let acc = Seq.singleton (fallthrough, ArchOperationMode.NoMode)
    if __.IsExit () then Seq.empty
    else acc

  override __.InterruptNum (_num: byref<int64>) = Utils.futureFeature ()

  override __.IsNop () = false

  override __.Translate ctxt =
    (Lifter.translate __.Info ctxt).ToStmts ()

  override __.TranslateToList ctxt =
    Lifter.translate __.Info ctxt

  override __.Disasm (showAddr, _resolveSymbol, _fileInfo) =
    let builder =
      DisasmStringBuilder (showAddr, false, WordSize.Bit256, addr, numBytes)
    Disasm.disasm __.Info builder
    builder.Finalize ()

  override __.Disasm () =
    let builder =
      DisasmStringBuilder (false, false, WordSize.Bit256, addr, numBytes)
    Disasm.disasm __.Info builder
    builder.Finalize ()

  override __.Decompose (showAddr) =
    let builder =
      DisasmWordBuilder (showAddr, false, WordSize.Bit256, addr, numBytes, 8)
    Disasm.disasm __.Info builder
    builder.Finalize ()

  override __.IsInlinedAssembly () = false

  override __.Equals (_) = Utils.futureFeature ()
  override __.GetHashCode () = Utils.futureFeature ()

// vim: set tw=80 sts=2 sw=2:
