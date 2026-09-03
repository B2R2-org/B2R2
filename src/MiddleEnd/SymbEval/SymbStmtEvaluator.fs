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

/// Evaluates LowUIR statements in the symbolic domain.
module B2R2.MiddleEnd.SymbEval.SymbStmtEvaluator

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

let private unsupportedStmt stmt =
  Stmt.toString stmt |> UnsupportedStatement |> Error

let private unsupportedOp op = UnsupportedOperation op |> Error

let private unsupportedSymbolicAddress expr =
  UnsupportedSymbolicAddress expr |> Error

let private conditionTypeError (expr: SymbExpr) =
  $"Invalid branch condition type: {RegType.toString expr.Type}"
  |> unsupportedOp

let private falseCond cond = SymbExpr.relop RelOpType.EQ cond SymbExpr.falseExpr

let private addTrueCond (st: SymbState) cond =
  if cond <> SymbExpr.trueExpr then st.AddPathCondition cond else ()

let private addFalseCond (st: SymbState) cond =
  if cond <> SymbExpr.falseExpr then st.AddPathCondition(falseCond cond) else ()

let private updatePC (st: SymbState) target =
  match target with
  | Const bv -> st.PC <- bv.ToUInt64(); Ok()
  | target -> unsupportedSymbolicAddress target

let private evalPCUpdate (st: SymbState) target =
  SymbExprEvaluator.eval st target |> Result.bind (updatePC st)

let private evalPut (st: SymbState) lhs rhs =
  match SymbExprEvaluator.eval st rhs with
  | Ok value ->
    match lhs with
    | Var(_, rid, _, _) -> st.SetReg(rid, value); Ok()
    | TempVar(_, idx, _) -> st.SetTmp(idx, value); Ok()
    | PCVar _ -> updatePC st value
    | _ -> UnsupportedExpression(Expr.toString lhs) |> Error
  | Error e ->
    Error e

let private evalStore (st: SymbState) endian addr value =
  match SymbExprEvaluator.eval st addr,
        SymbExprEvaluator.eval st value with
  | Ok(Const addr), Ok value ->
    SymbMemoryOperation.store (addr.ToUInt64()) value endian st.Memory
    Ok()
  | Ok addr, Ok _ ->
    unsupportedSymbolicAddress addr
  | Error e, _ | _, Error e ->
    Error e

let private evalJmp (st: SymbState) = function
  | JmpDest(lbl, _) -> st.GoToLabel lbl; Ok()
  | target -> UnsupportedExpression(Expr.toString target) |> Error

let private evalConcreteCJmp (st: SymbState) cond trueTarget falseTarget =
  if cond then evalJmp st trueTarget else evalJmp st falseTarget

let private evalSymbolicCJmp (st: SymbState) cond trueTarget falseTarget =
  if SymbExpr.isCondition cond then
    let trueState = st
    let falseState = st.Clone()
    addTrueCond trueState cond
    addFalseCond falseState cond
    match evalJmp trueState trueTarget, evalJmp falseState falseTarget with
    | Ok(), Ok() -> Ok(SymbEvalSuccessor.Fork(trueState, falseState))
    | Error e, _ | _, Error e -> Error e
  else
    conditionTypeError cond

let private evalCJmp (st: SymbState) cond trueTarget falseTarget =
  match SymbExprEvaluator.eval st cond with
  | Ok(Const cond) ->
    evalConcreteCJmp st cond.IsTrue trueTarget falseTarget
    |> Result.map (fun () -> SymbEvalSuccessor.Continue st)
  | Ok cond ->
    evalSymbolicCJmp st cond trueTarget falseTarget
  | Error e ->
    Error e

let private evalConcreteIntCJmp (st: SymbState) cond trueTarget falseTarget =
  if cond then evalPCUpdate st trueTarget else evalPCUpdate st falseTarget

let private evalSymbolicIntCJmp (st: SymbState) cond trueTarget falseTarget =
  if SymbExpr.isCondition cond then
    let trueState = st
    let falseState = st.Clone()
    addTrueCond trueState cond
    addFalseCond falseState cond
    let trueResult = evalPCUpdate trueState trueTarget
    let falseResult = evalPCUpdate falseState falseTarget
    match trueResult, falseResult with
    | Ok(), Ok() ->
      trueState.AbortInstr()
      falseState.AbortInstr()
      Ok(SymbEvalSuccessor.Fork(trueState, falseState))
    | Error e, _ | _, Error e ->
      Error e
  else
    conditionTypeError cond

let private evalIntCJmp (st: SymbState) cond trueTarget falseTarget =
  match SymbExprEvaluator.eval st cond with
  | Ok(Const cond) ->
    evalConcreteIntCJmp st cond.IsTrue trueTarget falseTarget
    |> Result.map (fun () ->
      st.AbortInstr()
      SymbEvalSuccessor.Continue st)
  | Ok cond ->
    evalSymbolicIntCJmp st cond trueTarget falseTarget
  | Error e ->
    Error e

/// Evaluates one LowUIR statement.
let evalStmt (st: SymbState) stmt =
  let result =
    match stmt with
    | ISMark(len, _) ->
      st.CurrentInsLen <- len
      st.NextStmt()
      Ok(SymbEvalSuccessor.Continue st)
    | IEMark(len, _) ->
      st.AdvancePC len
      st.AbortInstr()
      Ok(SymbEvalSuccessor.Continue st)
    | LMark _ ->
      st.NextStmt()
      Ok(SymbEvalSuccessor.Continue st)
    | Put(lhs, rhs, _) ->
      evalPut st lhs rhs |> Result.map (fun () ->
        st.NextStmt()
        SymbEvalSuccessor.Continue st)
    | Store(endian, addr, value, _) ->
      evalStore st endian addr value |> Result.map (fun () ->
        st.NextStmt()
        SymbEvalSuccessor.Continue st)
    | Jmp(target, _) ->
      evalJmp st target |> Result.map (fun () -> SymbEvalSuccessor.Continue st)
    | CJmp(cond, trueTarget, falseTarget, _) ->
      evalCJmp st cond trueTarget falseTarget
    | InterJmp(target, _, _) ->
      evalPCUpdate st target |> Result.map (fun () ->
        st.AbortInstr()
        SymbEvalSuccessor.Continue st)
    | InterCJmp(cond, trueTarget, falseTarget, _) ->
      evalIntCJmp st cond trueTarget falseTarget
    | ExternalCall _ ->
      unsupportedStmt stmt
    | SideEffect(effect, _) ->
      Ok(SymbEvalSuccessor.StoppedAtSideEffect(st, effect))
  match result with
  | Ok result -> result
  | Error e -> SymbEvalSuccessor.EvalError e
