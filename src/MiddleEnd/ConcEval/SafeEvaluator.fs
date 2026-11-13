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
open B2R2.MiddleEnd.Executor

let private map2 fn p1 p2 = function
  | Ok(Def bv) -> Def(fn (bv, p1, p2)) |> Ok
  | _ -> Error ErrorCase.InvalidExprEvaluation

let private unwrap = function
  | Ok(Def bv) -> Ok bv
  | _ -> Error ErrorCase.InvalidExprEvaluation

/// Evaluates a given expression in the context of the provided evaluation
/// state.
let rec private evalExprIn ((st: ConcState), mode) e =
  match e with
  | Num(Value = n) ->
    Def n |> Ok
  | Var(RegisterID = n) ->
    st.TryGetReg n |> Ok
  | PCVar(Type = t) ->
    BitVector(st.PC, t) |> Def |> Ok
  | TempVar(Index = n) ->
    st.TryGetTmp n |> Ok
  | UnOp(Op = t; Operand = e) ->
    evalUnOp (st, mode) e t
  | BinOp(Op = t; Left = e1; Right = e2) ->
    evalBinOp (st, mode) e1 e2 t
  | RelOp(Op = t; Left = e1; Right = e2) ->
    evalRelOp (st, mode) e1 e2 t
  | Load(Endian = endian; Type = t; Addr = addr) ->
    evalLoad (st, mode) endian t addr
  | Ite(Cond = cond; TrueExpr = e1; FalseExpr = e2) ->
    evalIte (st, mode) cond e1 e2
  | Cast(Kind = kind; Type = t; Operand = e) ->
    evalCast (st, mode) t e kind
  | RoundCtrl(Mode = direction; Body = body) ->
    match evalExprIn (st, mode) direction |> unwrap with
    | Ok m -> evalExprIn (st, enum<RoundingMode> (int (m.ToUInt64()))) body
    | Error e -> Error e
  | Extract(Operand = e; Type = t; StartPos = p) ->
    evalExprIn (st, mode) e |> map2 BitVector.Extract t p
  | Undefined _ ->
    Ok Undef
  | _ ->
    Error ErrorCase.InvalidExprEvaluation

and private evalLoad ((st: ConcState), mode) endian t addr =
  let addr = evalExprIn (st, mode) addr |> unwrap
  match addr |> Result.map (fun bv -> bv.ToUInt64()) with
  | Ok addr ->
    match Memory.read addr endian t st.Memory with
    | Ok v ->
      Ok(Def v)
    | Error e ->
      st.OnLoadFailure(st.PC, addr, t, e)
      |> Result.map Def
  | Error e ->
    Error e

and private evalIte (st, mode) cond e1 e2 =
  match evalExprIn (st, mode) cond |> unwrap with
  | Ok cond ->
    if cond = tr then evalExprIn (st, mode) e1
    else evalExprIn (st, mode) e2
  | Error e ->
    Error e

and private evalBinOpConc (st, mode) e1 e2 fn =
  let e1 = evalExprIn (st, mode) e1 |> unwrap
  let e2 = evalExprIn (st, mode) e2 |> unwrap
  match e1, e2 with
  | Ok e1, Ok e2 -> fn (e1, e2) |> Def |> Ok
  | Error e, _ | _, Error e -> Error e

and private evalUnOpConc (st, mode) e fn =
  evalExprIn (st, mode) e |> unwrap |> Result.map (fn >> Def)

and private evalCast (st, mode) t e kind =
  match kind with
  | CastKind.SignExt | CastKind.ZeroExt | CastKind.FloatCast
  | CastKind.SIntToFloat | CastKind.UIntToFloat | CastKind.FloatToSInt
  | CastKind.RoundToIntegral ->
    evalUnOpConc (st, mode) e (FloatingPoint.convert mode kind t)
  | _ ->
    Error ErrorCase.InvalidExprEvaluation

and private evalUnOp (st, mode) e typ =
  let eval = evalUnOpConc (st, mode) e
  match typ with
  | UnOpType.NEG -> eval BitVector.Neg
  | UnOpType.NOT -> eval BitVector.Not
  | UnOpType.FSQRT -> eval (FloatingPoint.sqrt mode)
  | UnOpType.FCOS -> eval (FloatingPoint.unary typ)
  | UnOpType.FSIN -> eval (FloatingPoint.unary typ)
  | UnOpType.FTAN -> eval (FloatingPoint.unary typ)
  | UnOpType.FATAN -> eval (FloatingPoint.unary typ)
  | UnOpType.FASIN -> eval (FloatingPoint.unary typ)
  | UnOpType.FACOS -> eval (FloatingPoint.unary typ)
  | UnOpType.FSINH -> eval (FloatingPoint.unary typ)
  | UnOpType.FCOSH -> eval (FloatingPoint.unary typ)
  | UnOpType.FTANH -> eval (FloatingPoint.unary typ)
  | UnOpType.FATANH -> eval (FloatingPoint.unary typ)
  | _ -> Error ErrorCase.InvalidExprEvaluation

and private evalBinOp (st, mode) e1 e2 typ =
  let eval = evalBinOpConc (st, mode) e1 e2
  match typ with
  | BinOpType.ADD -> eval BitVector.Add
  | BinOpType.SUB -> eval BitVector.Sub
  | BinOpType.MUL -> eval BitVector.Mul
  | BinOpType.DIV -> eval BitVector.Div
  | BinOpType.SDIV -> eval BitVector.SDiv
  | BinOpType.MOD -> eval BitVector.Modulo
  | BinOpType.SMOD -> eval BitVector.SModulo
  | BinOpType.SHL -> eval BitVector.Shl
  | BinOpType.SAR -> eval BitVector.Sar
  | BinOpType.SHR -> eval BitVector.Shr
  | BinOpType.AND -> eval BitVector.And
  | BinOpType.OR -> eval BitVector.Or
  | BinOpType.XOR -> eval BitVector.Xor
  | BinOpType.CONCAT -> eval BitVector.Concat
  | BinOpType.FADD -> eval (FloatingPoint.binary mode BinOpType.FADD)
  | BinOpType.FSUB -> eval (FloatingPoint.binary mode BinOpType.FSUB)
  | BinOpType.FMUL -> eval (FloatingPoint.binary mode BinOpType.FMUL)
  | BinOpType.FDIV -> eval (FloatingPoint.binary mode BinOpType.FDIV)
  | BinOpType.FPOW -> eval (FloatingPoint.binary mode BinOpType.FPOW)
  | BinOpType.FLOG -> eval (FloatingPoint.binary mode BinOpType.FLOG)
  | _ -> Error ErrorCase.InvalidExprEvaluation

and private evalRelOp (st, mode) e1 e2 typ =
  let eval = evalBinOpConc (st, mode) e1 e2
  match typ with
  | RelOpType.EQ -> eval BitVector.Eq
  | RelOpType.NEQ -> eval BitVector.Neq
  | RelOpType.GT -> eval BitVector.Gt
  | RelOpType.GE -> eval BitVector.Ge
  | RelOpType.SGT -> eval BitVector.SGt
  | RelOpType.SGE -> eval BitVector.SGe
  | RelOpType.LT -> eval BitVector.Lt
  | RelOpType.LE -> eval BitVector.Le
  | RelOpType.SLT -> eval BitVector.SLt
  | RelOpType.SLE -> eval BitVector.SLe
  | RelOpType.FNEQ -> eval (FloatingPoint.relation typ)
  | RelOpType.FEQ -> eval (FloatingPoint.relation typ)
  | RelOpType.FLT -> eval (FloatingPoint.relation typ)
  | RelOpType.FLE -> eval (FloatingPoint.relation typ)
  | RelOpType.FGT -> eval (FloatingPoint.relation typ)
  | RelOpType.FGE -> eval (FloatingPoint.relation typ)
  | _ -> Error ErrorCase.InvalidExprEvaluation

/// Evaluates an expression, using round-to-nearest outside RoundCtrl.
let evalExpr st e = evalExprIn (st, RoundingMode.ToNearestEven) e

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
    | Var(RegisterID = n) -> st.SetReg(n, v) |> Ok
    | TempVar(Index = n) -> st.SetTmp(n, v) |> Ok
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

let private evalJmp (st: ConcState) target =
  match target with
  | JmpDest(Target = n) -> st.TryGoToLabel n
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

/// The name of the function an external call calls, and its arguments,
/// evaluated.
let private evalCall st call =
  match call with
  | BinOp(Op = BinOpType.APP
          Left = FuncName(Name = name)
          Right = ExprList(Elements = args)) ->
    concretizeArgs st [] args |> Result.map (fun args -> struct (name, args))
  | _ ->
    Error ErrorCase.InvalidExprEvaluation

/// Evaluates an IR statement. This does not consult IgnoreUndef; a lone
/// statement has nothing to skip.
let evalStmt (st: ConcState) stmt =
  match stmt with
  | ISMark(Length = len) ->
    st.CurrentInsLen <- len; st.NextStmt() |> Ok
  | IEMark(Length = len) ->
    st.AdvancePC len; st.AbortInstr() |> Ok
  | LMark _ ->
    st.NextStmt() |> Ok
  | Put(Dst = lhs; Src = rhs) ->
    evalPut st lhs rhs |> Result.map st.NextStmt
  | Store(Endian = e; Addr = addr; Value = v) ->
    evalStore st e addr v |> Result.map st.NextStmt
  | Jmp(Target = target) ->
    evalJmp st target
  | CJmp(Cond = cond; TrueTarget = t; FalseTarget = f) ->
    evalCJmp st cond t f
  | InterJmp(Target = target) ->
    evalPCUpdate st target |> Result.map st.AbortInstr
  | InterCJmp(Cond = c; TrueTarget = t; FalseTarget = f) ->
    evalIntCJmp st c t f |> Result.map st.AbortInstr
  | ExternalCall(Call = call) ->
    evalCall st call
    |> Result.map (fun struct (name, args) ->
      st.OnExternalCall(name, args, st) |> st.NextStmt)
  | SideEffect(Effect = eff) ->
    evalSideEffect st eff |> Ok

let private evalStmtOrSkip (st: ConcState) stmt =
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
let evalInstr (st: ConcState) stmts =
  st.PrepareInstrEval stmts
  match StmtLoop.run evalStmtOrSkip StmtLoop.whileOk st stmts with
  | Completed _ -> Ok()
  | Interrupted error -> error
