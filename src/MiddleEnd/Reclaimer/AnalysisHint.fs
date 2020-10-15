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

namespace B2R2.MiddleEnd.Reclaimer

open B2R2

/// AnalysisHint stores inter-analysis information that survive through
/// analyses. It can potentially improve the speed and quality of the analyses.
type AnalysisHint = {
  /// Addresses of functions where no-return analysis has been performed.
  NoReturnPerformed: Set<Addr>
  /// Addresses of functions where branch recovery has been performed.
  BranchRecoveryPerformed: Set<Addr>
  /// Pairs of an indirect jump instruction addr and its jump table address.
  /// This involves all observed jump-table-based indirect jumps  before
  /// connecting indirect edges. These branches are currently unreachable, and
  /// will be deleted from the set when they become reachable.
  PotentialTableIndBranches: Set<Addr * Addr>
}
with
  /// Empty hint.
  [<CompiledName("Empty")>]
  static member empty () =
    { NoReturnPerformed = Set.empty
      BranchRecoveryPerformed = Set.empty
      PotentialTableIndBranches = Set.empty }

  static member markNoReturn entry hint =
    { hint with NoReturnPerformed = Set.add entry hint.NoReturnPerformed }

  static member unmarkNoReturn entry hint =
    { hint with NoReturnPerformed = Set.remove entry hint.NoReturnPerformed }

  static member markBranchRecovery entry hint =
    { hint with
        BranchRecoveryPerformed = Set.add entry hint.BranchRecoveryPerformed }
