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

/// ConcEval.Evaluator is a concrete evaluation module for LowUIR.
module B2R2.MiddleEnd.ConcEval.Evaluator

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.ConcEval.EvalUtils

let rec evalConcrete (st: EvalState) e =
  match e.E with
  | Num n -> n
  | Var (_, n, _, _) -> st.GetReg n
  | PCVar (t, _) -> BitVector.OfUInt64 st.PC t
  | TempVar (_, n) -> st.GetTmp n
  | UnOp (t, e, _) -> evalUnOp st e t
  | BinOp (t, _, e1, e2, _) -> evalBinOp st e1 e2 t
  | RelOp (t, e1, e2, _) -> evalRelOp st e1 e2 t
  | Load (endian, t, addr, _) -> evalLoad st endian t addr
  | Ite (cond, e1, e2, _) ->
    let cond = evalConcrete st cond
    if cond = tr then evalConcrete st e1 else evalConcrete st e2
  | Cast (kind, t, e, _) -> evalCast st t e kind
  | Extract (e, t, p, _) -> BitVector.Extract (evalConcrete st e, t, p)
  | Undefined (_) -> raise UndefExpException
  | _ -> raise InvalidExprException

and private evalLoad st endian t addr =
  let addr = evalConcrete st addr |> BitVector.ToUInt64
  match st.Memory.Read addr endian t with
  | Ok v ->
    st.OnLoad st.PC addr v
    v
  | Error e ->
    match st.OnLoadFailure st.PC addr t e with
    | Ok v -> v
    | Error _ ->  raise (InvalidMemException addr)

and private evalCast st t e = function
  | CastKind.SignExt -> BitVector.SExt (evalConcrete st e, t)
  | CastKind.ZeroExt -> BitVector.ZExt (evalConcrete st e, t)
  | CastKind.FloatCast -> BitVector.FCast (evalConcrete st e, t)
  | CastKind.IntToFloat -> BitVector.Itof (evalConcrete st e, t)
  | CastKind.FtoICeil -> BitVector.FtoiCeil (evalConcrete st e, t)
  | CastKind.FtoIFloor -> BitVector.FtoiFloor (evalConcrete st e, t)
  | CastKind.FtoIRound -> BitVector.FtoiRound (evalConcrete st e, t)
  | CastKind.FtoITrunc -> BitVector.FtoiTrunc (evalConcrete st e, t)
  | _ -> raise IllegalASTTypeException

and private evalUnOp st e typ =
  let v = evalConcrete st e
  match typ with
  | UnOpType.NEG -> BitVector.Neg v
  | UnOpType.NOT -> BitVector.BNot v
  | UnOpType.FSQRT -> BitVector.FSqrt v
  | UnOpType.FCOS -> BitVector.FCos v
  | UnOpType.FSIN -> BitVector.FSin v
  | UnOpType.FTAN -> BitVector.FTan v
  | UnOpType.FATAN -> BitVector.FAtan v
  | _ -> raise IllegalASTTypeException

and private evalBinOp st e1 e2 typ =
  let e1 = evalConcrete st e1
  let e2 = evalConcrete st e2
  match typ with
  | BinOpType.ADD -> BitVector.Add (e1, e2)
  | BinOpType.SUB -> BitVector.Sub (e1, e2)
  | BinOpType.MUL  -> BitVector.Mul (e1, e2)
  | BinOpType.DIV -> BitVector.Div (e1, e2)
  | BinOpType.SDIV -> BitVector.SDiv (e1, e2)
  | BinOpType.MOD -> BitVector.Modulo (e1, e2)
  | BinOpType.SMOD -> BitVector.SModulo (e1, e2)
  | BinOpType.SHL -> BitVector.Shl (e1, e2)
  | BinOpType.SAR -> BitVector.Sar (e1, e2)
  | BinOpType.SHR -> BitVector.Shr (e1, e2)
  | BinOpType.AND -> BitVector.BAnd (e1, e2)
  | BinOpType.OR -> BitVector.BOr (e1, e2)
  | BinOpType.XOR -> BitVector.BXor (e1, e2)
  | BinOpType.CONCAT -> BitVector.Concat (e1, e2)
  | BinOpType.FADD -> BitVector.FAdd (e1, e2)
  | BinOpType.FSUB -> BitVector.FSub (e1, e2)
  | BinOpType.FMUL -> BitVector.FMul (e1, e2)
  | BinOpType.FDIV -> BitVector.FDiv (e1, e2)
  | BinOpType.FPOW -> BitVector.FPow (e1, e2)
  | BinOpType.FLOG -> BitVector.FLog (e1, e2)
  | _ -> raise IllegalASTTypeException

and private evalRelOp st e1 e2 typ =
  let e1 = evalConcrete st e1
  let e2 = evalConcrete st e2
  match typ with
  | RelOpType.EQ -> BitVector.Eq (e1, e2)
  | RelOpType.NEQ -> BitVector.Neq (e1, e2)
  | RelOpType.GT -> BitVector.Gt (e1, e2)
  | RelOpType.GE -> BitVector.Ge (e1, e2)
  | RelOpType.SGT -> BitVector.SGt (e1, e2)
  | RelOpType.SGE -> BitVector.SGe (e1, e2)
  | RelOpType.LT -> BitVector.Lt (e1, e2)
  | RelOpType.LE -> BitVector.Le (e1, e2)
  | RelOpType.SLT -> BitVector.SLt (e1, e2)
  | RelOpType.SLE -> BitVector.SLe (e1, e2)
  | RelOpType.FLT -> BitVector.FLt (e1, e2)
  | RelOpType.FLE -> BitVector.FLe (e1, e2)
  | RelOpType.FGT -> BitVector.FGt (e1, e2)
  | RelOpType.FGE -> BitVector.FGe (e1, e2)
  | _ -> raise IllegalASTTypeException

let private evalPCUpdate st rhs =
  let v = evalConcrete st rhs
  st.OnPut st.PC v
  st.PC <- BitVector.ToUInt64 v

let evalUndef (st: EvalState) lhs =
  match lhs.E with
  | Var (_, n, _, _) -> st.UnsetReg n
  | TempVar (_, n) -> st.UnsetTmp n
  | _ -> raise InvalidExprException

let private evalPut st lhs rhs =
  try
    let v = evalConcrete st rhs
    st.OnPut st.PC v
    match lhs.E with
    | Var (_, n, _, _) -> st.SetReg n v
    | TempVar (_, n) -> st.SetTmp n v
    | PCVar (_) -> st.PC <- BitVector.ToUInt64 v
    | _ -> raise InvalidExprException
  with
    | UndefExpException
    | :? System.Collections.Generic.KeyNotFoundException ->
#if EMULATION
      ()
#else
      evalUndef st lhs
#endif

let private evalStore st endian addr v =
  let addr = evalConcrete st addr |> BitVector.ToUInt64
  let v = evalConcrete st v
  st.OnStore st.PC addr v
  st.Memory.Write addr v endian

let private evalJmp (st: EvalState) target =
  match target.E with
  | Name n -> st.GoToLabel n
  | _ -> raise InvalidExprException

let private evalCJmp st cond t f =
  let cond = evalConcrete st cond
  if cond = tr then evalJmp st t else evalJmp st f

let private evalIntCJmp st cond t f =
  let cond = evalConcrete st cond
  evalPCUpdate st (if cond = tr then t else f)

let rec concretizeArgs st acc = function
  | arg :: tl ->
    let v = evalConcrete st arg
    concretizeArgs st (v :: acc) tl
  | [] -> acc

let private evalArgs st args =
  match args with
  | { E = BinOp (BinOpType.APP, _, _, args, _) } ->
    uncurryArgs [] args |> concretizeArgs st []
  | _ -> Utils.impossible ()

let evalStmt (st: EvalState) s =
  match s.S with
  | ISMark (len) -> st.CurrentInsLen <- len; st.NextStmt ()
  | IEMark (len) -> st.AdvancePC len; st.AbortInstr ()
  | LMark _ -> st.NextStmt ()
  | Put (lhs, { E = Undefined (_) }) -> evalUndef st lhs |> st.NextStmt
  | Put (lhs, rhs) -> evalPut st lhs rhs |> st.NextStmt
  | Store (e, addr, v) -> evalStore st e addr v |> st.NextStmt
  | Jmp target -> evalJmp st target
  | CJmp (cond, t, f) -> evalCJmp st cond t f
  | InterJmp (target, _) -> evalPCUpdate st target |> st.AbortInstr
  | InterCJmp (c, t, f) -> evalIntCJmp st c t f |> st.AbortInstr
  | ExternalCall (args) -> st.OnExternalCall (evalArgs st args) st
  | SideEffect eff -> st.OnSideEffect eff st

let internal tryEvaluate stmt st =
  try evalStmt st stmt with
  | UndefExpException
  | InvalidMemException _ ->
    if st.IgnoreUndef then st.NextStmt ()
    else raise UndefExpException

/// Evaluate a sequence of statements, assuming that the statements are lifted
/// from a single instruction.
let rec evalStmts stmts (st: EvalState) =
  let idx = st.StmtIdx
  let numStmts = Array.length stmts
  let st = if idx = 0 then st.OnInstr st else st
  if numStmts > idx then
    if st.IsInstrTerminated then
      if st.NeedToEvaluateIEMark then
        let stmt = stmts[numStmts - 1]
        st.OnStmtEval stmt
        tryEvaluate stmt st
      else ()
    else
      let stmt = stmts[idx]
      st.OnStmtEval stmt
      tryEvaluate stmt st
      evalStmts stmts st
  else ()
