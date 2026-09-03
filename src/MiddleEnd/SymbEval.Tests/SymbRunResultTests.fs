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

open System
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.MiddleEnd.SymbEval

[<TestClass>]
type SymbRunResultTests() =
  let satAnswerAt addr =
    { Target = addr; State = SymbState(); Values = [] }

  let reachAnswerAt addr = { Target = addr; State = SymbState() }

  let resultOf answer =
    { Answer = answer
      StopReasons = []
      PruneReasons = []
      StateCount = 0
      Timeout = None }

  [<TestMethod>]
  member _.``A timed-out run still hands back its answer``() =
    let answer = SymbAnswer.Satisfiable [ satAnswerAt 0x1000UL ]
    let result = { resultOf answer with Timeout = Some 30000 }
    Assert.AreEqual<bool>(true, result.IsSatisfiable)
    Assert.AreEqual<bool>(true, result.IsTimedOut)
    Assert.AreEqual<Addr>(0x1000UL,
                          result.GetSatisfiabilityAnswer().Target)

  [<TestMethod>]
  member _.``An unsettled run reports the first reason it could not tell``() =
    let reason = SymbStopReason.DepthLimitReached(0x1000UL, 500)
    let failure = SymbRunFailure.Stopped(SymbState(), reason)
    let result = resultOf (SymbAnswer.Unknown [ failure ])
    Assert.AreEqual<bool>(true, result.IsFailed)
    Assert.AreEqual<SymbRunFailure option>(Some failure,
                                           result.TryGetFailure())

  [<TestMethod>]
  member _.``A settled run reports no failure``() =
    let result = resultOf SymbAnswer.Unsatisfiable
    Assert.AreEqual<bool>(false, result.IsFailed)
    Assert.AreEqual<SymbRunFailure option>(None, result.TryGetFailure())

  [<TestMethod>]
  member _.``An answer of the other kind reads as no answer``() =
    let result = resultOf (SymbAnswer.Reachable [ reachAnswerAt 0x1000UL ])
    Assert.AreEqual<bool>(true, result.IsReachable)
    Assert.AreEqual<bool>(false, result.IsSatisfiable)
    Assert.AreEqual<int>(1, List.length result.ReachabilityAnswers)
    Assert.AreEqual<int>(0, List.length result.SatisfiabilityAnswers)
    let noAnswer = result.TryGetSatisfiabilityAnswer()
    Assert.AreEqual<SymbSatisfiabilityAnswer option>(None, noAnswer)

  [<TestMethod>]
  member _.``Demanding an answer that is not there raises``() =
    let result = resultOf SymbAnswer.Unsatisfiable
    Assert.ThrowsExactly<InvalidOperationException>(fun () ->
      result.GetSatisfiabilityAnswer() |> ignore)
    |> ignore
