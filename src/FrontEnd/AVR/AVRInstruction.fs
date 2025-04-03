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

namespace B2R2.FrontEnd.AVR

open B2R2
open B2R2.FrontEnd.BinLifter

/// The internal representation for a AVR instruction used by our disassembler
/// and lifter.
type AVRInstruction (addr, numBytes, insInfo) =
  inherit Instruction (addr, numBytes, WordSize.Bit8)

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override __.IsBranch () =
    match __.Info.Opcode with
    | _ -> false

  override __.IsModeChanging () = false

  member __.HasConcJmpTarget () = Terminator.futureFeature ()

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () = Terminator.futureFeature ()

  override __.IsCJmpOnTrue () = Terminator.futureFeature ()

  override __.IsCall () = Terminator.futureFeature ()

  override __.IsRET () = Terminator.futureFeature ()

  override __.IsInterrupt () = Terminator.futureFeature ()

  override __.IsExit () = Terminator.futureFeature ()

  override __.IsTerminator () =
    __.IsDirectBranch () ||
    __.IsIndirectBranch ()

  override __.DirectBranchTarget (_addr: byref<Addr>) =
    Terminator.futureFeature ()

  override __.IndirectTrampolineAddr (_addr: byref<Addr>) =
    Terminator.futureFeature ()

  override __.Immediate (_v: byref<int64>) = Terminator.futureFeature ()

  override __.GetNextInstrAddrs () = Terminator.futureFeature ()

  override __.InterruptNum (_num: byref<int64>) = Terminator.futureFeature ()

  override __.IsNop () = Terminator.futureFeature ()

  override __.Translate ctxt =
    (Lifter.translate __.Info numBytes ctxt).ToStmts ()

  override __.TranslateToList ctxt =
    Lifter.translate __.Info numBytes ctxt

  override __.Disasm (showAddr, _) =
    let builder =
      DisasmStringBuilder (showAddr, false, WordSize.Bit32, addr, numBytes)
    Disasm.disasm __.Info builder
    builder.ToString ()

  override __.Disasm () =
    let builder =
      DisasmStringBuilder (false, false, WordSize.Bit32, addr, numBytes)
    Disasm.disasm __.Info builder
    builder.ToString ()

  override __.Decompose (showAddr) =
    let builder =
      DisasmWordBuilder (showAddr, false, WordSize.Bit32, addr, numBytes, 8)
    Disasm.disasm __.Info builder
    builder.ToArray ()

  override __.IsInlinedAssembly () = false

  override __.Equals (_) = Terminator.futureFeature ()
  override __.GetHashCode () = Terminator.futureFeature ()

// vim: set tw=80 sts=2 sw=2:
