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
  | PCVar (t, _) -> BitVector.ofUInt64 st.PC t
  | TempVar (_, n) -> st.GetTmp n
  | UnOp (t, e, _) -> evalUnOp st e t
  | BinOp (t, _, e1, e2, _) -> evalBinOp st e1 e2 t
  | RelOp (t, e1, e2, _) -> evalRelOp st e1 e2 t
  | Load (endian, t, addr, _) -> evalLoad st endian t addr
  | Ite (cond, e1, e2, _) ->
    let cond = evalConcrete st cond
    if cond = tr then evalConcrete st e1 else evalConcrete st e2
  | Cast (kind, t, e, _) -> evalCast st t e kind
  | Extract (e, t, p, _) -> BitVector.extract (evalConcrete st e) t p
  | Undefined (_) -> raise UndefExpException
  | _ -> raise InvalidExprException

and private evalLoad st endian t addr =
  let addr = evalConcrete st addr |> BitVector.toUInt64
  match st.Memory.Read addr endian t with
  | Ok v ->
    st.Callbacks.OnLoad st.PC addr v
    v
  | Error e ->
    match st.Callbacks.OnLoadFailure st.PC addr t e with
    | Ok v -> v
    | Error _ ->  raise InvalidMemException

and private evalCast st t e = function
  | CastKind.SignExt -> BitVector.sext (evalConcrete st e) t
  | CastKind.ZeroExt -> BitVector.zext (evalConcrete st e) t
  | CastKind.FloatCast -> BitVector.fcast (evalConcrete st e) t
  | CastKind.IntToFloat -> BitVector.itof (evalConcrete st e) t
  | CastKind.FtoICeil -> BitVector.ftoiceil (evalConcrete st e) t
  | CastKind.FtoIFloor -> BitVector.ftoifloor (evalConcrete st e) t
  | CastKind.FtoIRound -> BitVector.ftoiround (evalConcrete st e) t
  | CastKind.FtoITrunc -> BitVector.ftoitrunc (evalConcrete st e) t
  | _ -> raise IllegalASTTypeException

and private evalUnOp st e typ =
  let v = evalConcrete st e
  match typ with
  | UnOpType.NEG -> BitVector.neg v
  | UnOpType.NOT -> BitVector.bnot v
  | UnOpType.FSQRT -> BitVector.fsqrt v
  | UnOpType.FCOS -> BitVector.fcos v
  | UnOpType.FSIN -> BitVector.fsin v
  | UnOpType.FTAN -> BitVector.ftan v
  | UnOpType.FATAN -> BitVector.fatan v
  | _ -> raise IllegalASTTypeException

and private evalBinOp st e1 e2 typ =
  let e1 = evalConcrete st e1
  let e2 = evalConcrete st e2
  match typ with
  | BinOpType.ADD -> BitVector.add e1 e2
  | BinOpType.SUB -> BitVector.sub e1 e2
  | BinOpType.MUL  -> BitVector.mul e1 e2
  | BinOpType.DIV -> BitVector.div e1 e2
  | BinOpType.SDIV -> BitVector.sdiv e1 e2
  | BinOpType.MOD -> BitVector.modulo e1 e2
  | BinOpType.SMOD -> BitVector.smodulo e1 e2
  | BinOpType.SHL -> BitVector.shl e1 e2
  | BinOpType.SAR -> BitVector.sar e1 e2
  | BinOpType.SHR -> BitVector.shr e1 e2
  | BinOpType.AND -> BitVector.band e1 e2
  | BinOpType.OR -> BitVector.bor e1 e2
  | BinOpType.XOR -> BitVector.bxor e1 e2
  | BinOpType.CONCAT -> BitVector.concat e1 e2
  | BinOpType.FADD -> BitVector.fadd e1 e2
  | BinOpType.FSUB -> BitVector.fsub e1 e2
  | BinOpType.FMUL -> BitVector.fmul e1 e2
  | BinOpType.FDIV -> BitVector.fdiv e1 e2
  | BinOpType.FPOW -> BitVector.fpow e1 e2
  | BinOpType.FLOG -> BitVector.flog e1 e2
  | _ -> raise IllegalASTTypeException

and private evalRelOp st e1 e2 typ =
  let e1 = evalConcrete st e1
  let e2 = evalConcrete st e2
  match typ with
  | RelOpType.EQ -> BitVector.eq e1 e2
  | RelOpType.NEQ -> BitVector.neq e1 e2
  | RelOpType.GT -> BitVector.gt e1 e2
  | RelOpType.GE -> BitVector.ge e1 e2
  | RelOpType.SGT -> BitVector.sgt e1 e2
  | RelOpType.SGE -> BitVector.sge e1 e2
  | RelOpType.LT -> BitVector.lt e1 e2
  | RelOpType.LE -> BitVector.le e1 e2
  | RelOpType.SLT -> BitVector.slt e1 e2
  | RelOpType.SLE -> BitVector.sle e1 e2
  | RelOpType.FLT -> BitVector.flt e1 e2
  | RelOpType.FLE -> BitVector.fle e1 e2
  | RelOpType.FGT -> BitVector.fgt e1 e2
  | RelOpType.FGE -> BitVector.fge e1 e2
  | _ -> raise IllegalASTTypeException

let private evalPCUpdate st rhs =
  let v = evalConcrete st rhs
  st.Callbacks.OnPut st.PC v
  BitVector.toUInt64 v |> st.SetPC

let evalUndef (st: EvalState) lhs =
  match lhs.E with
  | Var (_, n, _, _) -> st.UnsetReg n
  | TempVar (_, n) -> st.UnsetTmp n
  | _ -> raise InvalidExprException

let private evalPut st lhs rhs =
  try
    let v = evalConcrete st rhs
    st.Callbacks.OnPut st.PC v
    match lhs.E with
    | Var (_, n, _, _) -> st.SetReg n v
    | TempVar (_, n) -> st.SetTmp n v
    | PCVar (_) -> BitVector.toUInt64 v |> st.SetPC
    | _ -> raise InvalidExprException
  with
    | UndefExpException
    | :? System.Collections.Generic.KeyNotFoundException -> ()

let private evalStore st endian addr v =
  let addr = evalConcrete st addr |> BitVector.toUInt64
  let v = evalConcrete st v
  st.Callbacks.OnStore st.PC addr v
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

let evalStmt (st: EvalState) s =
  match s.S with
  | ISMark (_) -> st.NextStmt ()
  | IEMark (len) -> st.IncPC len; st.AbortInstr ()
  | LMark _ -> st.NextStmt ()
  | Put (lhs, { E = Undefined (_) }) -> evalUndef st lhs |> st.NextStmt
  | Put (lhs, rhs) -> evalPut st lhs rhs |> st.NextStmt
  | Store (e, addr, v) -> evalStore st e addr v |> st.NextStmt
  | Jmp target -> evalJmp st target
  | CJmp (cond, t, f) -> evalCJmp st cond t f
  | InterJmp (target, _) -> evalPCUpdate st target |> st.AbortInstr
  | InterCJmp (c, t, f) -> evalIntCJmp st c t f |> st.AbortInstr
  | SideEffect eff -> st.Callbacks.OnSideEffect eff st |> ignore

let internal tryEvaluate stmt st =
  try evalStmt st stmt with
  | UndefExpException
  | InvalidMemException ->
    if st.IgnoreUndef then st.NextStmt ()
    else raise UndefExpException

/// Evaluate a sequence of statements, which is lifted from a single
/// instruction.
let rec internal evalStmts stmts (st: EvalState) =
  let ctxt = st.GetCurrentContext ()
  let idx = ctxt.StmtIdx
  let st = if idx = 0 then st.Callbacks.OnInstr st else st
  if not st.IsInstrTerminated && Array.length stmts > idx
    && not st.InPrematureState then
    let stmt = stmts[idx]
    st.Callbacks.OnStmtEval stmt
    tryEvaluate stmt st
    evalStmts stmts st
  else ()

let rec evalBlockLoop idx (blk: Stmt [][]) (st: EvalState) =
  if idx < blk.Length && not st.InPrematureState then
    let stmts = blk[idx]
    st.PrepareInstrEval stmts
    evalStmts stmts st
    evalBlockLoop (idx + 1) blk st
  else ()

/// Evaluate a block of statements. The block represents a series of lifted IR
/// statements from one or more machine instructions.
let evalBlock (st: EvalState) pc tid blk =
  st.SetPC pc
  if st.ThreadId <> tid then st.ContextSwitch tid else ()
  evalBlockLoop 0 blk st
  st.CleanUp ()
