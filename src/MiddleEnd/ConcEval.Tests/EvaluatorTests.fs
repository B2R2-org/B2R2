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

namespace B2R2.MiddleEnd.ConcEval.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.ConcEval

[<TestClass>]
type EvaluatorTests() =
  let newState () =
    let st = EvalState()
    st.CurrentInsLen <- 2u
    st

  let assertTerminatedWithIEMark (st: EvalState) =
    Assert.AreEqual<bool>(true, st.IsInstrTerminated)
    Assert.AreEqual<bool>(true, st.NeedToEvaluateIEMark)

  [<TestMethod>]
  member _.``Safe side effect terminates the instruction by default``() =
    let st = newState ()
    match SafeEvaluator.evalStmt st (AST.sideEffect SysCall) with
    | Ok() -> assertTerminatedWithIEMark st
    | Error e -> Assert.Fail $"Failed to evaluate a side effect: {e}"

  [<TestMethod>]
  member _.``Unsafe side effect terminates the instruction by default``() =
    let st = newState ()
    Evaluator.evalStmt st (AST.sideEffect SysCall)
    assertTerminatedWithIEMark st

  [<TestMethod>]
  member _.``Side effect handler keeps its own termination``() =
    let st = newState ()
    st.SideEffectEventHandler <- (fun _ state -> state.AbortInstr())
    match SafeEvaluator.evalStmt st (AST.sideEffect SysCall) with
    | Ok() ->
      Assert.AreEqual<bool>(true, st.IsInstrTerminated)
      Assert.AreEqual<bool>(false, st.NeedToEvaluateIEMark)
    | Error e ->
      Assert.Fail $"Failed to evaluate a side effect: {e}"
