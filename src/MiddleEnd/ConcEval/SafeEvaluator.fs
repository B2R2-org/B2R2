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

/// Represents a concrete evaluation module for LowUIR that reports failure in
/// its return value instead of raising. Its value domain is ConcEvalValue, so
/// an uninitialized register or an Undefined node evaluates to Undef where
/// Evaluator raises; that difference, not the error channel alone, is what
/// separates the two. It costs roughly 2.5x what Evaluator does on a path with
/// no undefined value, and its operator tables are a deliberate duplicate of
/// Evaluator's, so a new operator has to be added to both.
module B2R2.MiddleEnd.ConcEval.SafeEvaluator

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.ConcEval.EvalUtils

let private map1 fn p1 = function
  | Ok(Def bv) -> Def(fn (bv, p1)) |> Ok
  | _ -> Error ErrorCase.InvalidExprEvaluation

let private map2 fn p1 p2 = function
  | Ok(Def bv) -> Def(fn (bv, p1, p2)) |> Ok
  | _ -> Error ErrorCase.InvalidExprEvaluation

let private unwrap = function
  | Ok(Def bv) -> Ok bv
  | _ -> Error ErrorCase.InvalidExprEvaluation

/// Evaluates a given expression in the context of the provided evaluation
/// state.
let rec evalExpr (st: EvalState) e =
  match e with
  | Num(n, _) -> Def n |> Ok
  | Var(_, n, _, _) -> st.TryGetReg n |> Ok
  | PCVar(t, _, _) -> BitVector(st.PC, t) |> Def |> Ok
  | TempVar(_, n, _) -> st.TryGetTmp n |> Ok
  | UnOp(t, e, _) -> evalUnOp st e t
  | BinOp(t, _, e1, e2, _) -> evalBinOp st e1 e2 t
  | RelOp(t, e1, e2, _) -> evalRelOp st e1 e2 t
  | Load(endian, t, addr, _) -> evalLoad st endian t addr
  | Ite(cond, e1, e2, _) -> evalIte st cond e1 e2
  | Cast(kind, t, e, _) -> evalCast st t e kind
  | Extract(e, t, p, _) -> evalExpr st e |> map2 BitVector.Extract t p
  | Undefined _ -> Ok Undef
  | _ -> Error ErrorCase.InvalidExprEvaluation

and private evalLoad st endian t addr =
  match evalExpr st addr |> unwrap |> Result.map (fun bv -> bv.ToUInt64()) with
  | Ok addr ->
    match Memory.read addr endian t st.Memory with
    | Ok v ->
      Ok(Def v)
    | Error e ->
      st.OnLoadFailure(st.PC, addr, t, e)
      |> Result.map Def
  | Error e ->
    Error e

and private evalIte st cond e1 e2 =
  match evalExpr st cond |> unwrap with
  | Ok cond -> if cond = tr then evalExpr st e1 else evalExpr st e2
  | Error e -> Error e

and private evalBinOpConc st e1 e2 fn =
  let e1 = evalExpr st e1 |> unwrap
  let e2 = evalExpr st e2 |> unwrap
  match e1, e2 with
  | Ok e1, Ok e2 -> fn (e1, e2) |> Def |> Ok
  | Error e, _ | _, Error e -> Error e

and private evalUnOpConc st e fn =
  evalExpr st e |> unwrap |> Result.map (fn >> Def)

and private evalCast st t e = function
  | CastKind.SignExt -> evalExpr st e |> map1 BitVector.SExt t
  | CastKind.ZeroExt -> evalExpr st e |> map1 BitVector.ZExt t
  | CastKind.FloatCast -> evalExpr st e |> map1 BitVector.FCast t
  | CastKind.SIntToFloat -> evalExpr st e |> map2 BitVector.Itof t true
  | CastKind.UIntToFloat -> evalExpr st e |> map2 BitVector.Itof t false
  | CastKind.FtoICeil -> evalExpr st e |> map1 BitVector.FtoiCeil t
  | CastKind.FtoIFloor -> evalExpr st e |> map1 BitVector.FtoiFloor t
  | CastKind.FtoIRound -> evalExpr st e |> map1 BitVector.FtoiRound t
  | CastKind.FtoITrunc -> evalExpr st e |> map1 BitVector.FtoiTrunc t
  | _ -> Error ErrorCase.InvalidExprEvaluation

and private evalUnOp st e = function
  | UnOpType.NEG -> evalUnOpConc st e BitVector.Neg
  | UnOpType.NOT -> evalUnOpConc st e BitVector.Not
  | UnOpType.FSQRT -> evalUnOpConc st e BitVector.FSqrt
  | UnOpType.FCOS -> evalUnOpConc st e BitVector.FCos
  | UnOpType.FSIN -> evalUnOpConc st e BitVector.FSin
  | UnOpType.FTAN -> evalUnOpConc st e BitVector.FTan
  | UnOpType.FATAN -> evalUnOpConc st e BitVector.FAtan
  | _ -> Error ErrorCase.InvalidExprEvaluation

and private evalBinOp st e1 e2 = function
  | BinOpType.ADD -> evalBinOpConc st e1 e2 BitVector.Add
  | BinOpType.SUB -> evalBinOpConc st e1 e2 BitVector.Sub
  | BinOpType.MUL -> evalBinOpConc st e1 e2 BitVector.Mul
  | BinOpType.DIV -> evalBinOpConc st e1 e2 BitVector.Div
  | BinOpType.SDIV -> evalBinOpConc st e1 e2 BitVector.SDiv
  | BinOpType.MOD -> evalBinOpConc st e1 e2 BitVector.Modulo
  | BinOpType.SMOD -> evalBinOpConc st e1 e2 BitVector.SModulo
  | BinOpType.SHL -> evalBinOpConc st e1 e2 BitVector.Shl
  | BinOpType.SAR -> evalBinOpConc st e1 e2 BitVector.Sar
  | BinOpType.SHR -> evalBinOpConc st e1 e2 BitVector.Shr
  | BinOpType.AND -> evalBinOpConc st e1 e2 BitVector.And
  | BinOpType.OR -> evalBinOpConc st e1 e2 BitVector.Or
  | BinOpType.XOR -> evalBinOpConc st e1 e2 BitVector.Xor
  | BinOpType.CONCAT -> evalBinOpConc st e1 e2 BitVector.Concat
  | BinOpType.FADD -> evalBinOpConc st e1 e2 BitVector.FAdd
  | BinOpType.FSUB -> evalBinOpConc st e1 e2 BitVector.FSub
  | BinOpType.FMUL -> evalBinOpConc st e1 e2 BitVector.FMul
  | BinOpType.FDIV -> evalBinOpConc st e1 e2 BitVector.FDiv
  | BinOpType.FPOW -> evalBinOpConc st e1 e2 BitVector.FPow
  | BinOpType.FLOG -> evalBinOpConc st e1 e2 BitVector.FLog
  | _ -> Error ErrorCase.InvalidExprEvaluation

and private evalRelOp st e1 e2 = function
  | RelOpType.EQ -> evalBinOpConc st e1 e2 BitVector.Eq
  | RelOpType.NEQ -> evalBinOpConc st e1 e2 BitVector.Neq
  | RelOpType.GT -> evalBinOpConc st e1 e2 BitVector.Gt
  | RelOpType.GE -> evalBinOpConc st e1 e2 BitVector.Ge
  | RelOpType.SGT -> evalBinOpConc st e1 e2 BitVector.SGt
  | RelOpType.SGE -> evalBinOpConc st e1 e2 BitVector.SGe
  | RelOpType.LT -> evalBinOpConc st e1 e2 BitVector.Lt
  | RelOpType.LE -> evalBinOpConc st e1 e2 BitVector.Le
  | RelOpType.SLT -> evalBinOpConc st e1 e2 BitVector.SLt
  | RelOpType.SLE -> evalBinOpConc st e1 e2 BitVector.SLe
  | RelOpType.FLT -> evalBinOpConc st e1 e2 BitVector.FLt
  | RelOpType.FLE -> evalBinOpConc st e1 e2 BitVector.FLe
  | RelOpType.FGT -> evalBinOpConc st e1 e2 BitVector.FGt
  | RelOpType.FGE -> evalBinOpConc st e1 e2 BitVector.FGe
  | _ -> Error ErrorCase.InvalidExprEvaluation

let private evalPCUpdate st rhs =
  match evalExpr st rhs with
  | Ok(Def v) ->
    st.PC <- v.ToUInt64()
    Ok()
  | _ ->
    Error ErrorCase.InvalidExprEvaluation

let private evalPut st lhs rhs =
  match evalExpr st rhs with
  | Ok(Def v) ->
    match lhs with
    | Var(_, n, _, _) -> st.SetReg(n, v) |> Ok
    | TempVar(_, n, _) -> st.SetTmp(n, v) |> Ok
    | PCVar _ -> st.PC <- v.ToUInt64(); Ok()
    | _ -> Error ErrorCase.InvalidExprEvaluation
  | _ ->
    markUndefAfterFailure st lhs
    Error ErrorCase.InvalidExprEvaluation

let private evalStore st endian addr v =
  let addr = evalExpr st addr |> unwrap |> Result.map (fun bv -> bv.ToUInt64())
  let v = evalExpr st v |> unwrap
  match addr, v with
  | Ok addr, Ok v ->
    Memory.write addr v endian st.Memory
    Ok()
  | Error e, _ | _, Error e ->
    Error e

let private evalJmp (st: EvalState) target =
  match target with
  | JmpDest(n, _) -> st.TryGoToLabel n
  | _ -> Error ErrorCase.InvalidExprEvaluation

let private evalCJmp st cond t f =
  match evalExpr st cond |> unwrap with
  | Ok cond -> if cond = tr then evalJmp st t else evalJmp st f
  | Error e -> Error e

let private evalIntCJmp st cond t f =
  match evalExpr st cond |> unwrap with
  | Ok cond -> evalPCUpdate st (if cond = tr then t else f)
  | Error e -> Error e

let rec private concretizeArgs st acc = function
  | arg :: tl ->
    match evalExpr st arg with
    | Ok(Def v) -> concretizeArgs st (v :: acc) tl
    | _ -> Error ErrorCase.InvalidExprEvaluation
  | [] ->
    Ok acc

let private evalArgs st args =
  match args with
  | BinOp(BinOpType.APP, _, _, ExprList(args, _), _) ->
    args |> concretizeArgs st []
  | _ ->
    Error ErrorCase.InvalidExprEvaluation

/// Evaluates an IR statement. This does not consult IgnoreUndef; a lone
/// statement has nothing to skip.
let evalStmt (st: EvalState) stmt =
  match stmt with
  | ISMark(len, _) ->
    st.CurrentInsLen <- len; st.NextStmt() |> Ok
  | IEMark(len, _) ->
    st.AdvancePC len; st.AbortInstr() |> Ok
  | LMark _ ->
    st.NextStmt() |> Ok
  | Put(lhs, rhs, _) ->
    evalPut st lhs rhs |> Result.map st.NextStmt
  | Store(e, addr, v, _) ->
    evalStore st e addr v |> Result.map st.NextStmt
  | Jmp(target, _) ->
    evalJmp st target
  | CJmp(cond, t, f, _) ->
    evalCJmp st cond t f
  | InterJmp(target, _, _) ->
    evalPCUpdate st target |> Result.map st.AbortInstr
  | InterCJmp(c, t, f, _) ->
    evalIntCJmp st c t f |> Result.map st.AbortInstr
  | ExternalCall(args, _) ->
    evalArgs st args
    |> Result.map (fun args -> st.OnExternalCall(args, st) |> st.NextStmt)
  | SideEffect(eff, _) ->
    st.OnSideEffect(eff, st)
    if st.IsInstrTerminated then () else st.AbortInstr true
    Ok()

let private evalStmtOrSkip (st: EvalState) stmt =
  match evalStmt st stmt with
  | Ok() ->
    Ok()
  | Error e ->
    if st.IgnoreUndef then
      st.NextStmt()
      Ok()
    else
      Error e

/// Evaluates the statements lifted from a single machine instruction, driving
/// the statement loop so that a caller does not have to. When the state has
/// IgnoreUndef set, a statement that fails to evaluate is skipped and
/// evaluation carries on.
let evalInstr (st: EvalState) stmts =
  st.PrepareInstrEval stmts
  tryEvalStmtsWith evalStmtOrSkip st stmts
