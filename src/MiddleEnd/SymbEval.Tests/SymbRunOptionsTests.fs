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
open B2R2
open B2R2.MiddleEnd.Executor
open B2R2.MiddleEnd.SymbEval

[<TestClass>]
type SymbRunOptionsTests() =
  let defaultOptions = SymbRunOptions.Default(ReachAddress 0x1000UL)

  let pointAt addr =
    { Address = addr
      InstructionCount = 0
      Instruction = None
      State = SymbState() }

  [<TestMethod>]
  member _.``A state predicate becomes the avoid condition``() =
    let predicate = StopPredicate(fun point -> point.Address = 0x1UL)
    match defaultOptions.AddAvoidState(predicate).Avoid with
    | AvoidState pred ->
      Assert.AreEqual<bool>(true, pred.Invoke(pointAt 0x1UL))
      Assert.AreEqual<bool>(false, pred.Invoke(pointAt 0x2UL))
    | avoid ->
      Assert.Fail $"Unexpected avoid condition: {avoid}"

  [<TestMethod>]
  member _.``Two state predicates combine disjunctively``() =
    let opts =
      defaultOptions
        .AddAvoidState(StopPredicate(fun point -> point.Address = 0x1UL))
        .AddAvoidState(StopPredicate(fun point -> point.Address = 0x2UL))
    match opts.Avoid with
    | AvoidState pred ->
      Assert.AreEqual<bool>(true, pred.Invoke(pointAt 0x1UL))
      Assert.AreEqual<bool>(true, pred.Invoke(pointAt 0x2UL))
      Assert.AreEqual<bool>(false, pred.Invoke(pointAt 0x3UL))
    | avoid ->
      Assert.Fail $"Unexpected avoid condition: {avoid}"
