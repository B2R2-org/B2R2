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

/// Represents a CIL instruction.
type Instruction internal(addr, numBytes) =
  interface IInstruction with
    member _.Address with get() = addr
    member _.Length with get() = numBytes
    member _.IsBranch = Terminator.futureFeature ()
    member _.IsModeChanging = false
    member _.IsDirectBranch = Terminator.futureFeature ()
    member _.IsIndirectBranch = Terminator.futureFeature ()
    member _.IsCondBranch = Terminator.futureFeature ()
    member _.IsCJmpOnTrue = Terminator.futureFeature ()
    member _.IsCall = Terminator.futureFeature ()
    member _.IsRET = Terminator.futureFeature ()
    member _.IsPush = Terminator.futureFeature ()
    member _.IsPop = Terminator.futureFeature ()
    member _.IsInterrupt = Terminator.futureFeature ()
    member _.IsExit = Terminator.futureFeature ()
    member _.IsNop = Terminator.futureFeature ()
    member _.IsInlinedAssembly = false
    member _.IsTerminator _ = Terminator.futureFeature ()
    member _.DirectBranchTarget _ = Terminator.futureFeature ()
    member _.IndirectTrampolineAddr _ = Terminator.futureFeature ()
    member _.MemoryDereferences _ = Terminator.futureFeature ()
    member _.Immediate _ = Terminator.futureFeature ()
    member _.GetNextInstrAddrs() = Terminator.futureFeature ()
    member _.InterruptNum _ = Terminator.futureFeature ()
    member _.Translate _ = Terminator.futureFeature ()
    member _.TranslateToList _ = Terminator.futureFeature ()
    member _.Disasm _ = Terminator.futureFeature ()
    member _.Disasm() = Terminator.futureFeature ()
    member _.Decompose _ = Terminator.futureFeature ()
