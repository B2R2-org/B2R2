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
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.SymbEval

[<TestClass>]
type SymbStmtEvaluatorTests() =
  let condReg = RegisterID.create 1

  let cond = AST.var 1<rt> condReg "cond"

  (* One instruction that jumps to 0x10 or 0x20 on a one-bit condition. *)
  let branch =
    [| AST.ismark 4u
       AST.intercjmp cond (AST.num (BitVector(0x10UL, 64<rt>)))
                          (AST.num (BitVector(0x20UL, 64<rt>))) |]

  let stateWith value =
    let st = SymbState()
    st.SetReg(condReg, value)
    st

  [<TestMethod>]
  member _.``A symbolic condition leaves a successor on each side``() =
    let st = stateWith (SymbExpr.Var("cond", 1<rt>))
    match SymbStmtEvaluator.evalInstr st branch with
    | [ SymbEvalSuccessor.Continue taken
        SymbEvalSuccessor.Continue notTaken ] ->
      Assert.AreEqual<Addr>(0x10UL, taken.PC)
      Assert.AreEqual<Addr>(0x20UL, notTaken.PC)
      Assert.AreEqual<int>(1, List.length taken.PathCondition)
      Assert.AreEqual<int>(1, List.length notTaken.PathCondition)
    | successors ->
      Assert.Fail $"Unexpected successors: {successors}"

  [<TestMethod>]
  member _.``A concrete condition leaves the one successor it takes``() =
    let st = stateWith (SymbExpr.Const(BitVector.One 1<rt>))
    match SymbStmtEvaluator.evalInstr st branch with
    | [ SymbEvalSuccessor.Continue taken ] ->
      Assert.AreEqual<Addr>(0x10UL, taken.PC)
      Assert.AreEqual<int>(0, List.length taken.PathCondition)
    | successors ->
      Assert.Fail $"Unexpected successors: {successors}"

  [<TestMethod>]
  member _.``A side effect stops the instruction where it stands``() =
    let stmts = [| AST.ismark 4u; AST.sideEffect Terminate; AST.iemark 4u |]
    match SymbStmtEvaluator.evalInstr (SymbState()) stmts with
    | [ SymbEvalSuccessor.StoppedAtSideEffect(_, effect) ] ->
      Assert.AreEqual<SideEffect>(Terminate, effect)
    | successors ->
      Assert.Fail $"Unexpected successors: {successors}"
