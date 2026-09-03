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

namespace B2R2.MiddleEnd.SymbEval.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.MiddleEnd.SymbEval

[<TestClass>]
type SymbPruneReasonTests() =
  [<TestMethod>]
  member _.``A loop bound leaves the query's answer inconclusive``() =
    let reason = SymbPruneReason.LoopBoundReached(0x1000UL, 1)
    Assert.AreEqual<bool>(true, reason.IsInconclusive)

  [<TestMethod>]
  member _.``A failed solver check leaves the answer inconclusive``() =
    let error = UnsupportedOperation "no solver"
    let reason = SymbPruneReason.SolverPruningFailed(0x1000UL, error)
    Assert.AreEqual<bool>(true, reason.IsInconclusive)

  [<TestMethod>]
  member _.``A path the user asked to avoid settles the answer``() =
    let byAddress = SymbPruneReason.AvoidedAddress 0x1000UL
    let byPredicate = SymbPruneReason.AvoidedState 0x1000UL
    Assert.AreEqual<bool>(false, byAddress.IsInconclusive)
    Assert.AreEqual<bool>(false, byPredicate.IsInconclusive)

  [<TestMethod>]
  member _.``A path the solver proved dead settles the answer``() =
    let reason = SymbPruneReason.InfeasiblePath 0x1000UL
    Assert.AreEqual<bool>(false, reason.IsInconclusive)
