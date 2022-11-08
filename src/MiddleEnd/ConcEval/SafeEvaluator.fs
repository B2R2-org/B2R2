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

/// ConcEval.SafeEvaluator is a safe concrete evaluation module for LowUIR.
/// Unlike ConcEval.Evaluator, it does not raise exceptions, but it is slower
/// than ConcEval.Evaluator.
module B2R2.MiddleEnd.ConcEval.SafeEvaluator

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.ConcEval.EvalUtils

let private map1 fn p1 = function
  | Ok (Def bv) -> Def (fn (bv, p1)) |> Ok
  | _ -> Error ErrorCase.InvalidExprEvaluation

let private map2 fn p1 p2 = function
  | Ok (Def bv) -> Def (fn (bv, p1, p2)) |> Ok
  | _ -> Error ErrorCase.InvalidExprEvaluation

let private unwrap = function
  | Ok (Def bv) -> Ok bv
  | _ -> Error ErrorCase.InvalidExprEvaluation

let rec evalConcrete (st: EvalState) e =
  match e.E with
  | Num n -> Def n |> Ok
  | Var (_, n, _, _) -> st.TryGetReg n |> Ok
  | PCVar (t, _) -> BitVector.OfUInt64 st.PC t |> Def |> Ok
  | TempVar (_, n) -> st.TryGetTmp n |> Ok
  | UnOp (t, e, _) -> evalUnOp st e t
  | BinOp (t, _, e1, e2, _) -> evalBinOp st e1 e2 t
  | RelOp (t, e1, e2, _) -> evalRelOp st e1 e2 t
  | Load (endian, t, addr, _) -> evalLoad st endian t addr
  | Ite (cond, e1, e2, _) -> evalIte st cond e1 e2
  | Cast (kind, t, e, _) -> evalCast st t e kind
  | Extract (e, t, p, _) -> evalConcrete st e |> map2 BitVector.Extract t p
  | Undefined (_) -> Ok Undef
  | _ -> Error ErrorCase.InvalidExprEvaluation

and private evalLoad st endian t addr =
  match evalConcrete st addr |> unwrap |> Result.map BitVector.ToUInt64 with
  | Ok addr ->
    match st.Memory.Read addr endian t with
    | Ok v -> Ok (Def v)
    | Error e ->
      st.OnLoadFailure st.PC addr t e
      |> Result.map Def
  | Error e -> Error e

and private evalIte st cond e1 e2 =
  match evalConcrete st cond |> unwrap with
  | Ok cond ->
    if cond = tr then evalConcrete st e1 else evalConcrete st e2
  | Error e -> Error e

and private evalBinOpConc st e1 e2 fn =
  let e1 = evalConcrete st e1 |> unwrap
  let e2 = evalConcrete st e2 |> unwrap
  match e1, e2 with
  | Ok e1, Ok e2 -> fn (e1, e2) |> Def |> Ok
  | Error e, _ | _, Error e -> Error e

and private evalUnOpConc st e fn =
  evalConcrete st e |> unwrap |> Result.map (fn >> Def)

and private evalCast st t e = function
  | CastKind.SignExt -> evalConcrete st e |> map1 BitVector.SExt t
  | CastKind.ZeroExt -> evalConcrete st e |> map1 BitVector.ZExt t
  | CastKind.FloatCast -> evalConcrete st e |> map1 BitVector.FCast t
  | CastKind.IntToFloat -> evalConcrete st e |> map1 BitVector.Itof t
  | CastKind.FtoICeil -> evalConcrete st e |> map1 BitVector.FtoiCeil t
  | CastKind.FtoIFloor -> evalConcrete st e |> map1 BitVector.FtoiFloor t
  | CastKind.FtoIRound -> evalConcrete st e |> map1 BitVector.FtoiRound t
  | CastKind.FtoITrunc -> evalConcrete st e |> map1 BitVector.FtoiTrunc t
  | _ -> raise IllegalASTTypeException

and private evalUnOp st e = function
  | UnOpType.NEG -> evalUnOpConc st e BitVector.Neg
  | UnOpType.NOT -> evalUnOpConc st e BitVector.BNot
  | UnOpType.FSQRT -> evalUnOpConc st e BitVector.FSqrt
  | UnOpType.FCOS -> evalUnOpConc st e BitVector.FCos
  | UnOpType.FSIN -> evalUnOpConc st e BitVector.FSin
  | UnOpType.FTAN -> evalUnOpConc st e BitVector.FTan
  | UnOpType.FATAN -> evalUnOpConc st e BitVector.FAtan
  | _ -> raise IllegalASTTypeException

and private evalBinOp st e1 e2 = function
  | BinOpType.ADD -> evalBinOpConc st e1 e2 BitVector.Add
  | BinOpType.SUB -> evalBinOpConc st e1 e2 BitVector.Sub
  | BinOpType.MUL  -> evalBinOpConc st e1 e2 BitVector.Mul
  | BinOpType.DIV -> evalBinOpConc st e1 e2 BitVector.Div
  | BinOpType.SDIV -> evalBinOpConc st e1 e2 BitVector.SDiv
  | BinOpType.MOD -> evalBinOpConc st e1 e2 BitVector.Modulo
  | BinOpType.SMOD -> evalBinOpConc st e1 e2 BitVector.SModulo
  | BinOpType.SHL -> evalBinOpConc st e1 e2 BitVector.Shl
  | BinOpType.SAR -> evalBinOpConc st e1 e2 BitVector.Sar
  | BinOpType.SHR -> evalBinOpConc st e1 e2 BitVector.Shr
  | BinOpType.AND -> evalBinOpConc st e1 e2 BitVector.BAnd
  | BinOpType.OR -> evalBinOpConc st e1 e2 BitVector.BOr
  | BinOpType.XOR -> evalBinOpConc st e1 e2 BitVector.BXor
  | BinOpType.CONCAT -> evalBinOpConc st e1 e2 BitVector.Concat
  | BinOpType.FADD -> evalBinOpConc st e1 e2 BitVector.FAdd
  | BinOpType.FSUB -> evalBinOpConc st e1 e2 BitVector.FSub
  | BinOpType.FMUL -> evalBinOpConc st e1 e2 BitVector.FMul
  | BinOpType.FDIV -> evalBinOpConc st e1 e2 BitVector.FDiv
  | BinOpType.FPOW -> evalBinOpConc st e1 e2 BitVector.FPow
  | BinOpType.FLOG -> evalBinOpConc st e1 e2 BitVector.FLog
  | _ -> raise IllegalASTTypeException

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
  | _ -> raise IllegalASTTypeException

let private markUndefAfterFailure (st: EvalState) lhs =
  match lhs with
  | Var (_, n, _, _) -> st.UnsetReg n
  | TempVar (_, n) -> st.UnsetTmp n
  | _ -> ()

let private evalPCUpdate st rhs =
  match evalConcrete st rhs with
  | (Ok (Def v)) ->
    st.PC <- BitVector.ToUInt64 v
    Ok ()
  | _ -> Error ErrorCase.InvalidExprEvaluation

let private evalPut st lhs rhs =
  match evalConcrete st rhs with
  | Ok (Def v) ->
    match lhs.E with
    | Var (_, n, _, _) -> st.SetReg n v |> Ok
    | TempVar (_, n) -> st.SetTmp n v |> Ok
    | PCVar (_) -> st.PC <- BitVector.ToUInt64 v; Ok ()
    | _ -> Error ErrorCase.InvalidExprEvaluation
  | _ ->
    markUndefAfterFailure st lhs.E
    Error ErrorCase.InvalidExprEvaluation

let private evalStore st endian addr v =
  let addr = evalConcrete st addr |> unwrap |> Result.map BitVector.ToUInt64
  let v = evalConcrete st v |> unwrap
  match addr, v with
  | Ok addr, Ok v ->
    st.Memory.Write addr v endian
    Ok ()
  | Error e, _ | _, Error e -> Error e

let private evalJmp (st: EvalState) target =
  match target.E with
  | Name n -> st.GoToLabel n |> Ok
  | _ -> Error ErrorCase.InvalidExprEvaluation

let private evalCJmp st cond t f =
  match evalConcrete st cond |> unwrap with
  | Ok cond ->
    if cond = tr then evalJmp st t else evalJmp st f
  | Error e -> Error e

let private evalIntCJmp st cond t f =
  match evalConcrete st cond |> unwrap with
  | Ok cond -> evalPCUpdate st (if cond = tr then t else f)
  | Error e -> Error e

let rec concretizeArgs st acc = function
  | arg :: tl ->
    match evalConcrete st arg with
    | Ok (Def v) -> concretizeArgs st (v :: acc) tl
    | _ -> Error ErrorCase.InvalidExprEvaluation
  | [] -> Ok acc

let private evalArgs st args =
  match args with
  | { E = BinOp (BinOpType.APP, _, _, args, _) } ->
    uncurryArgs [] args |> concretizeArgs st []
  | _ -> Utils.impossible ()

/// Evaluate an IR statement.
let evalStmt (st: EvalState) = function
  | ISMark (len) -> st.CurrentInsLen <- len; st.NextStmt () |> Ok
  | IEMark (len) -> st.AdvancePC len; st.AbortInstr () |> Ok
  | LMark _ -> st.NextStmt () |> Ok
  | Put (lhs, rhs) -> evalPut st lhs rhs |> Result.map st.NextStmt
  | Store (e, addr, v) -> evalStore st e addr v |> Result.map st.NextStmt
  | Jmp target -> evalJmp st target
  | CJmp (cond, t, f) -> evalCJmp st cond t f
  | InterJmp (target, _) -> evalPCUpdate st target |> Result.map st.AbortInstr
  | InterCJmp (c, t, f) -> evalIntCJmp st c t f |> Result.map st.AbortInstr
  | ExternalCall (args) ->
    evalArgs st args |> Result.map (fun args -> st.OnExternalCall args st)
  | SideEffect eff -> st.OnSideEffect eff st |> ignore |> Ok

let internal tryEvaluate stmt st =
  match evalStmt st stmt.S with
  | Ok () -> Ok st
  | Error e ->
    if st.IgnoreUndef then st.NextStmt (); Ok st
    else Error e

/// Evaluate a sequence of statements, which is lifted from a single
/// instruction.
let rec internal evalStmts stmts result =
  match result with
  | Ok (st: EvalState) ->
    let idx = st.StmtIdx
    let numStmts = Array.length stmts
    if numStmts > idx then
      if st.IsInstrTerminated then
        if st.NeedToEvaluateIEMark then tryEvaluate stmts[numStmts - 1] st
        else Ok st
      else
        let stmt = stmts[idx]
        evalStmts stmts (tryEvaluate stmt st)
    else Ok st
  | Error _ -> result

let rec private evalBlockLoop idx (blk: Stmt[][]) result =
  match result with
  | Ok (st: EvalState) ->
    if idx < blk.Length then
      let stmts = blk[idx]
      st.PrepareInstrEval stmts
      evalStmts stmts (Ok st)
      |> evalBlockLoop (idx + 1) blk
    else result
  | Error e -> Error e

/// Evaluate a series of statement arrays, assuming that each array is obtained
/// from a single machine instruction.
let evalBlock (st: EvalState) pc blk =
  st.PC <- pc
  evalBlockLoop 0 blk (Ok st)
  |> function
    | Ok st -> Ok st
    | Error e -> Error e
