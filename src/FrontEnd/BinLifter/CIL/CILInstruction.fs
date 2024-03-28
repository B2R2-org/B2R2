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

namespace B2R2.FrontEnd.BinLifter.CIL

open B2R2
open B2R2.FrontEnd.BinLifter

/// The internal representation for a CIL instruction used by our disassembler
/// and lifter.
type CILInstruction (addr, numBytes, wordSize) =
  inherit Instruction (addr, numBytes, wordSize)

  override __.IsBranch () = Utils.futureFeature ()
  override __.IsModeChanging () = false
  override __.IsDirectBranch () = Utils.futureFeature ()
  override __.IsIndirectBranch () = Utils.futureFeature ()
  override __.IsCondBranch () = Utils.futureFeature ()
  override __.IsCJmpOnTrue () = Utils.futureFeature ()
  override __.IsCall () = Utils.futureFeature ()
  override __.IsRET () = Utils.futureFeature ()
  override __.IsInterrupt () = Utils.futureFeature ()
  override __.IsExit () = Utils.futureFeature ()
  override __.IsBBLEnd () = Utils.futureFeature ()
  override __.DirectBranchTarget (_) = Utils.futureFeature ()
  override __.IndirectTrampolineAddr (_) = Utils.futureFeature ()
  override __.Immediate (_) = Utils.futureFeature ()
  override __.GetNextInstrAddrs () = Utils.futureFeature ()
  override __.InterruptNum (_) = Utils.futureFeature ()
  override __.IsNop () = Utils.futureFeature ()
  override __.Translate (_) = Utils.futureFeature ()
  override __.TranslateToList (_) = Utils.futureFeature ()
  override __.Disasm (_, _) = Utils.futureFeature ()
  override __.Disasm () = Utils.futureFeature ()
  override __.Decompose (_) = Utils.futureFeature ()
  override __.IsInlinedAssembly () = false

  override __.Equals (_) = Utils.futureFeature ()
  override __.GetHashCode () = Utils.futureFeature ()
