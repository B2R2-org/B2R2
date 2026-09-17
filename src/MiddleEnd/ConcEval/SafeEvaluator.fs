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
let rec evalExpr (st: ConcState) e =
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
    evalUnOp st e t
  | BinOp(Op = t; Left = e1; Right = e2) ->
    evalBinOp st e1 e2 t
  | RelOp(Op = t; Left = e1; Right = e2) ->
    evalRelOp st e1 e2 t
  | Load(Endian = endian; Type = t; Addr = addr) ->
    evalLoad st endian t addr
  | Ite(Cond = cond; TrueExpr = e1; FalseExpr = e2) ->
    evalIte st cond e1 e2
  | Cast(Kind = kind; Type = t; Operand = e) ->
    evalCast st t e kind
  | RoundCtrl(Mode = mode; Body = body) ->
    evalRoundCtrl st mode body
  | Extract(Operand = e; Type = t; StartPos = p) ->
    evalExpr st e |> map2 BitVector.Extract t p
  | Undefined _ ->
    Ok Undef
  | _ ->
    Error ErrorCase.InvalidExprEvaluation

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
  (* No direction is in force here, this evaluator having no notion of one, so
     the conversion rounds to nearest as everything else does. A direction the
     expression names outright is honoured by evalFtoI instead. *)
  | CastKind.FloatToSInt -> evalExpr st e |> map1 BitVector.FtoiRound t
  | _ -> Error ErrorCase.InvalidExprEvaluation

/// <summary>
/// Evaluates a body in a direction it names. A float-to-integer conversion is
/// the one rounding this evaluator can follow -- BitVector has a conversion
/// for each of the four directions, where its arithmetic is the host's and
/// takes none -- so every other body is evaluated as though the mode said
/// round-to-nearest, which is what this evaluator did before a direction could
/// be expressed at all.
/// </summary>
and private evalRoundCtrl st mode body =
  match mode, body with
  | Num(Value = m), Cast(Kind = CastKind.FloatToSInt; Type = t; Operand = e) ->
    evalFtoI st (enum<RoundingMode> (int (m.ToUInt64()))) t e
  | _ ->
    evalExpr st body

/// Converts a float to an integer in a direction the expression named.
and private evalFtoI st mode t e =
  match mode with
  | RoundingMode.TowardPositive -> evalExpr st e |> map1 BitVector.FtoiCeil t
  | RoundingMode.TowardNegative -> evalExpr st e |> map1 BitVector.FtoiFloor t
  | RoundingMode.TowardZero -> evalExpr st e |> map1 BitVector.FtoiTrunc t
  | _ -> evalExpr st e |> map1 BitVector.FtoiRound t

and private evalUnOp st e = function
  | UnOpType.NEG -> evalUnOpConc st e BitVector.Neg
  | UnOpType.NOT -> evalUnOpConc st e BitVector.Not
  | UnOpType.FSQRT -> evalUnOpConc st e BitVector.FSqrt
  | UnOpType.FCOS -> evalUnOpConc st e BitVector.FCos
  | UnOpType.FSIN -> evalUnOpConc st e BitVector.FSin
  | UnOpType.FTAN -> evalUnOpConc st e BitVector.FTan
  | UnOpType.FATAN -> evalUnOpConc st e BitVector.FAtan
  | UnOpType.FASIN -> evalUnOpConc st e BitVector.FAsin
  | UnOpType.FACOS -> evalUnOpConc st e BitVector.FAcos
  | UnOpType.FSINH -> evalUnOpConc st e BitVector.FSinh
  | UnOpType.FCOSH -> evalUnOpConc st e BitVector.FCosh
  | UnOpType.FTANH -> evalUnOpConc st e BitVector.FTanh
  | UnOpType.FATANH -> evalUnOpConc st e BitVector.FAtanh
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

let private evalArgs st args =
  match args with
  | BinOp(Op = BinOpType.APP; Right = ExprList(Elements = args)) ->
    args |> concretizeArgs st []
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
  | ExternalCall(Call = args) ->
    evalArgs st args
    |> Result.map (fun args -> st.OnExternalCall(args, st) |> st.NextStmt)
  | SideEffect(Effect = eff) ->
    st.OnSideEffect(eff, st)
    if st.IsInstrTerminated then () else st.AbortInstr true
    Ok()

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
