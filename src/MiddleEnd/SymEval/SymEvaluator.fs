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

/// Represents a symbolic evaluation module for LowUIR.
module B2R2.MiddleEnd.SymEval.SymEvaluator

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

/// Represents a symbolic evaluation stop reason.
type SymEvalStopReason =
  /// Evaluation reached a LowUIR statement with architectural side effects.
  | SideEffectStop of SideEffect

/// Represents the successor relation produced by symbolic evaluation.
type SymEvalSuccessor =
  /// Evaluation can continue from the given state.
  | Continue of SymState
  /// Evaluation forked on a symbolic condition.
  | Fork of trueState: SymState * falseState: SymState
  /// Evaluation stopped before completing the current run.
  | Stopped of SymState * SymEvalStopReason
  /// Evaluation failed.
  | EvalError of SymEvalError

let private unsupportedStmt stmt =
  Stmt.ToString stmt |> UnsupportedStatement |> Error

let private unsupportedOp op = UnsupportedOperation op |> Error

let private unsupportedSymbolicAddress expr =
  UnsupportedSymbolicAddress expr |> Error

let private conditionTypeError (expr: SymExpr) =
  $"Invalid branch condition type: {RegType.toString expr.Type}"
  |> unsupportedOp

let private falseCond cond =
  SymExpr.relop RelOpType.EQ cond SymExpr.falseExpr

let private addTrueCond (st: SymState) cond =
  if cond <> SymExpr.trueExpr then st.AddPathCondition cond

let private addFalseCond (st: SymState) cond =
  if cond <> SymExpr.falseExpr then st.AddPathCondition(falseCond cond)

let private updatePC (st: SymState) target =
  match target with
  | Const bv -> st.PC <- BitVector.ToUInt64 bv; Ok()
  | target -> unsupportedSymbolicAddress target

let private evalPCUpdate (st: SymState) target =
  SymExprTranslator.translate st target |> Result.bind (updatePC st)

let private evalPut (st: SymState) lhs rhs =
  match SymExprTranslator.translate st rhs with
  | Ok value ->
    match lhs with
    | Var(_, rid, _, _) -> st.SetReg(rid, value); Ok()
    | TempVar(_, idx, _) -> st.SetTmp(idx, value); Ok()
    | PCVar _ -> updatePC st value
    | _ -> UnsupportedExpression(Expr.ToString lhs) |> Error
  | Error e -> Error e

let private evalStore (st: SymState) endian addr value =
  match SymExprTranslator.translate st addr,
        SymExprTranslator.translate st value with
  | Ok(Const addr), Ok value ->
    st.Memory.Store(BitVector.ToUInt64 addr, value, endian)
    Ok()
  | Ok addr, Ok _ -> unsupportedSymbolicAddress addr
  | Error e, _ | _, Error e -> Error e

let private evalJmp (st: SymState) = function
  | JmpDest(lbl, _) -> st.GoToLabel lbl; Ok()
  | target -> UnsupportedExpression(Expr.ToString target) |> Error

let private evalConcreteCJmp (st: SymState) cond trueTarget falseTarget =
  if cond then evalJmp st trueTarget else evalJmp st falseTarget

let private evalSymbolicCJmp (st: SymState) cond trueTarget falseTarget =
  if SymExpr.isCondition cond then
    let trueState = st
    let falseState = st.Clone()
    addTrueCond trueState cond
    addFalseCond falseState cond
    match evalJmp trueState trueTarget, evalJmp falseState falseTarget with
    | Ok(), Ok() -> Ok(Fork(trueState, falseState))
    | Error e, _ | _, Error e -> Error e
  else conditionTypeError cond

let private evalCJmp (st: SymState) cond trueTarget falseTarget =
  match SymExprTranslator.translate st cond with
  | Ok(Const cond) ->
    evalConcreteCJmp st cond.IsTrue trueTarget falseTarget
    |> Result.map (fun () -> Continue st)
  | Ok cond -> evalSymbolicCJmp st cond trueTarget falseTarget
  | Error e -> Error e

let private evalConcreteIntCJmp (st: SymState) cond trueTarget falseTarget =
  if cond then evalPCUpdate st trueTarget else evalPCUpdate st falseTarget

let private evalSymbolicIntCJmp (st: SymState) cond trueTarget falseTarget =
  if SymExpr.isCondition cond then
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
      Ok(Fork(trueState, falseState))
    | Error e, _ | _, Error e -> Error e
  else conditionTypeError cond

let private evalIntCJmp (st: SymState) cond trueTarget falseTarget =
  match SymExprTranslator.translate st cond with
  | Ok(Const cond) ->
    evalConcreteIntCJmp st cond.IsTrue trueTarget falseTarget
    |> Result.map (fun () ->
      st.AbortInstr()
      Continue st)
  | Ok cond -> evalSymbolicIntCJmp st cond trueTarget falseTarget
  | Error e -> Error e

/// Evaluates one LowUIR statement.
let evalStmt (st: SymState) stmt =
  let result =
    match stmt with
    | ISMark(len, _) ->
      st.CurrentInsLen <- len
      st.NextStmt()
      Ok(Continue st)
    | IEMark(len, _) ->
      st.AdvancePC len
      st.AbortInstr()
      Ok(Continue st)
    | LMark _ ->
      st.NextStmt()
      Ok(Continue st)
    | Put(lhs, rhs, _) ->
      evalPut st lhs rhs |> Result.map (fun () ->
        st.NextStmt()
        Continue st)
    | Store(endian, addr, value, _) ->
      evalStore st endian addr value |> Result.map (fun () ->
        st.NextStmt()
        Continue st)
    | Jmp(target, _) ->
      evalJmp st target |> Result.map (fun () -> Continue st)
    | CJmp(cond, trueTarget, falseTarget, _) ->
      evalCJmp st cond trueTarget falseTarget
    | InterJmp(target, _, _) ->
      evalPCUpdate st target |> Result.map (fun () ->
        st.AbortInstr()
        Continue st)
    | InterCJmp(cond, trueTarget, falseTarget, _) ->
      evalIntCJmp st cond trueTarget falseTarget
    | ExternalCall _ -> unsupportedStmt stmt
    | SideEffect(effect, _) ->
      Ok(Stopped(st, SideEffectStop effect))
  match result with
  | Ok result -> result
  | Error e -> EvalError e
