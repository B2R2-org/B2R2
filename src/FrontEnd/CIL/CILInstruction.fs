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

namespace B2R2.FrontEnd.CIL

open B2R2
open B2R2.FrontEnd.BinLifter

/// The internal representation for a CIL instruction used by our disassembler
/// and lifter.
type CILInstruction (addr, numBytes, wordSize) =
  inherit Instruction (addr, numBytes, wordSize)

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
  override _.Translate _ = Terminator.futureFeature ()
  override _.TranslateToList _ = Terminator.futureFeature ()
  override _.Disasm (_, _) = Terminator.futureFeature ()
  override _.Disasm () = Terminator.futureFeature ()
  override _.Decompose (_) = Terminator.futureFeature ()
  override _.IsInlinedAssembly () = false

  override _.Equals (_) = Terminator.futureFeature ()
  override _.GetHashCode () = Terminator.futureFeature ()
