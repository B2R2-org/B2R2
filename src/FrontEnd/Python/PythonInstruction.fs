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

namespace B2R2.FrontEnd.Python

open B2R2
open B2R2.FrontEnd.BinLifter

/// The internal representation for a Python instruction used by our
/// disassembler and lifter.
type PythonInstruction (addr, numBytes, insInfo) =
  inherit Instruction (addr, numBytes, WordSize.Bit32)

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override this.IsBranch () =
    match this.Info.Opcode with
    | _ -> false

  override _.IsModeChanging () = false

  member _.HasConcJmpTarget () = Terminator.futureFeature ()

  override this.IsDirectBranch () =
    this.IsBranch () && this.HasConcJmpTarget ()

  override this.IsIndirectBranch () =
    this.IsBranch () && (not <| this.HasConcJmpTarget ())

  override _.IsCondBranch () = Terminator.futureFeature ()

  override _.IsCJmpOnTrue () = Terminator.futureFeature ()

  override _.IsCall () = Terminator.futureFeature ()

  override _.IsRET () = Terminator.futureFeature ()

  override _.IsInterrupt () = Terminator.futureFeature ()

  override _.IsExit () = Terminator.futureFeature ()

  override this.IsTerminator () =
    this.IsDirectBranch () ||
    this.IsIndirectBranch ()

  override _.DirectBranchTarget (_addr: byref<Addr>) =
    Terminator.futureFeature ()

  override _.IndirectTrampolineAddr (_addr: byref<Addr>) =
    Terminator.futureFeature ()

  override _.Immediate (_v: byref<int64>) = Terminator.futureFeature ()

  override _.GetNextInstrAddrs () = Terminator.futureFeature ()

  override _.InterruptNum (_num: byref<int64>) = Terminator.futureFeature ()

  override _.IsNop () = Terminator.futureFeature ()

  override _.Translate ctxt =
    Terminator.futureFeature ()

  override _.TranslateToList ctxt =
    Terminator.futureFeature ()

  override _.Disasm (showAddr, _) =
    Terminator.futureFeature ()

  override _.Disasm () =
    Terminator.futureFeature ()

  override _.Decompose (showAddr) =
    Terminator.futureFeature ()

  override _.IsInlinedAssembly () = false

  override _.Equals (_) = Terminator.futureFeature ()

  override _.GetHashCode () = Terminator.futureFeature ()

// vim: set tw=80 sts=2 sw=2:
