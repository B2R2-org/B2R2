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

namespace B2R2.FrontEnd.SH4

open B2R2
open B2R2.FrontEnd.BinLifter

/// The internal representation for a SH4 instruction used by our disassembler
/// and lifter.
type SH4Instruction (addr, numBytes, insInfo) =
  inherit Instruction (addr, numBytes, WordSize())

  member val Info: InsInfo = insInfo

  override _.IsBranch () = Terminator.futureFeature ()
  override _.IsModeChanging () = false
  override _.IsDirectBranch () = Terminator.futureFeature ()
  override _.IsIndirectBranch () = Terminator.futureFeature ()
  override _.IsCondBranch () = Terminator.futureFeature ()
  override _.IsCJmpOnTrue () = Terminator.futureFeature ()
  override _.IsCall () = Terminator.futureFeature ()
  override _.IsRET () = Terminator.futureFeature ()
  override _.IsInterrupt () = Terminator.futureFeature ()
  override _.IsExit () = Terminator.futureFeature ()
  override _.IsTerminator () = Terminator.futureFeature ()
  override _.DirectBranchTarget (_) = Terminator.futureFeature ()
  override _.IndirectTrampolineAddr (_) = Terminator.futureFeature ()
  override _.Immediate (_) = Terminator.futureFeature ()
  override _.GetNextInstrAddrs () = Terminator.futureFeature ()
  override _.InterruptNum (_) = Terminator.futureFeature ()
  override _.IsNop () = Terminator.futureFeature ()

  override this.Translate builder =
    (Lifter.translate this.Info numBytes builder).Stream.ToStmts ()

  override this.TranslateToList builder =
    (Lifter.translate this.Info numBytes builder).Stream

  override this.Disasm (showAddr, _) =
    let builder =
      DisasmStringBuilder (showAddr, false, WordSize.Bit32, addr, numBytes)
    Disasm.disas this.Info builder
    builder.ToString ()

  override this.Disasm () =
    let builder =
      DisasmStringBuilder (false, false, WordSize.Bit32, addr, numBytes)
    Disasm.disas this.Info builder
    builder.ToString ()

  override this.Decompose (showAddr) =
    let builder =
      DisasmWordBuilder (showAddr, false, WordSize.Bit32, addr, numBytes, 8)
    Disasm.disas this.Info builder
    builder.ToArray ()

  override _.IsInlinedAssembly () = false

  override _.Equals (_) = Terminator.futureFeature ()

  override _.GetHashCode () = Terminator.futureFeature ()
