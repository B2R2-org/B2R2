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
  | Ok (Def bv) -> Def (fn bv p1) |> Ok
  | _ -> Error ErrorCase.InvalidExprEvaluation

let private map2 fn p1 p2 = function
  | Ok (Def bv) -> Def (fn bv p1 p2) |> Ok
  | _ -> Error ErrorCase.InvalidExprEvaluation

let private unwrap = function
  | Ok (Def bv) -> Ok bv
  | _ -> Error ErrorCase.InvalidExprEvaluation

let rec evalConcrete (st: EvalState) e =
  match e.E with
  | Num n -> Def n |> Ok
  | Var (_, n, _, _) -> st.TryGetReg n |> Ok
  | PCVar (t, _) -> BitVector.ofUInt64 st.PC t |> Def |> Ok
  | TempVar (_, n) -> st.TryGetTmp n |> Ok
  | UnOp (t, e, _) -> evalUnOp st e t
  | BinOp (t, _, e1, e2, _) -> evalBinOp st e1 e2 t
  | RelOp (t, e1, e2, _) -> evalRelOp st e1 e2 t
  | Load (endian, t, addr, _) -> evalLoad st endian t addr
  | Ite (cond, e1, e2, _) -> evalIte st cond e1 e2
  | Cast (kind, t, e, _) -> evalCast st t e kind
  | Extract (e, t, p, _) -> evalConcrete st e |> map2 BitVector.extract t p
  | Undefined (_) -> Ok Undef
  | _ -> Error ErrorCase.InvalidExprEvaluation

and private evalLoad st endian t addr =
  let pc = st.PC
  match evalConcrete st addr |> unwrap |> Result.map BitVector.toUInt64 with
  | Ok addr ->
    match st.Memory.Read pc addr endian t with
    | Ok v ->
      st.Callbacks.OnLoad pc addr v
      Ok (Def v)
    | Error e -> Error e
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
  | Ok e1, Ok e2 -> fn e1 e2 |> Def |> Ok
  | Error e, _ | _, Error e -> Error e

and private evalUnOpConc st e fn =
  evalConcrete st e |> unwrap |> Result.map (fn >> Def)

and private evalCast st t e = function
  | CastKind.SignExt -> evalConcrete st e |> map1 BitVector.sext t
  | CastKind.ZeroExt -> evalConcrete st e |> map1 BitVector.zext t
  | CastKind.FloatCast -> evalConcrete st e |> map1 BitVector.fcast t
  | CastKind.IntToFloat -> evalConcrete st e |> map1 BitVector.itof t
  | CastKind.FtoICeil -> evalConcrete st e |> map1 BitVector.ftoiceil t
  | CastKind.FtoIFloor -> evalConcrete st e |> map1 BitVector.ftoifloor t
  | CastKind.FtoIRound -> evalConcrete st e |> map1 BitVector.ftoiround t
  | CastKind.FtoITrunc -> evalConcrete st e |> map1 BitVector.ftoitrunc t
  | _ -> raise IllegalASTTypeException

and private evalUnOp st e = function
  | UnOpType.NEG -> evalUnOpConc st e BitVector.neg
  | UnOpType.NOT -> evalUnOpConc st e BitVector.bnot
  | UnOpType.FSQRT -> evalUnOpConc st e BitVector.fsqrt
  | UnOpType.FCOS -> evalUnOpConc st e BitVector.fcos
  | UnOpType.FSIN -> evalUnOpConc st e BitVector.fsin
  | UnOpType.FTAN -> evalUnOpConc st e BitVector.ftan
  | UnOpType.FATAN -> evalUnOpConc st e BitVector.fatan
  | _ -> raise IllegalASTTypeException

and private evalBinOp st e1 e2 = function
  | BinOpType.ADD -> evalBinOpConc st e1 e2 BitVector.add
  | BinOpType.SUB -> evalBinOpConc st e1 e2 BitVector.sub
  | BinOpType.MUL  -> evalBinOpConc st e1 e2 BitVector.mul
  | BinOpType.DIV -> evalBinOpConc st e1 e2 BitVector.div
  | BinOpType.SDIV -> evalBinOpConc st e1 e2 BitVector.sdiv
  | BinOpType.MOD -> evalBinOpConc st e1 e2 BitVector.modulo
  | BinOpType.SMOD -> evalBinOpConc st e1 e2 BitVector.smodulo
  | BinOpType.SHL -> evalBinOpConc st e1 e2 BitVector.shl
  | BinOpType.SAR -> evalBinOpConc st e1 e2 BitVector.sar
  | BinOpType.SHR -> evalBinOpConc st e1 e2 BitVector.shr
  | BinOpType.AND -> evalBinOpConc st e1 e2 BitVector.band
  | BinOpType.OR -> evalBinOpConc st e1 e2 BitVector.bor
  | BinOpType.XOR -> evalBinOpConc st e1 e2 BitVector.bxor
  | BinOpType.CONCAT -> evalBinOpConc st e1 e2 BitVector.concat
  | BinOpType.FADD -> evalBinOpConc st e1 e2 BitVector.fadd
  | BinOpType.FSUB -> evalBinOpConc st e1 e2 BitVector.fsub
  | BinOpType.FMUL -> evalBinOpConc st e1 e2 BitVector.fmul
  | BinOpType.FDIV -> evalBinOpConc st e1 e2 BitVector.fdiv
  | BinOpType.FPOW -> evalBinOpConc st e1 e2 BitVector.fpow
  | BinOpType.FLOG -> evalBinOpConc st e1 e2 BitVector.flog
  | _ -> raise IllegalASTTypeException

and private evalRelOp st e1 e2 = function
  | RelOpType.EQ -> evalBinOpConc st e1 e2 BitVector.eq
  | RelOpType.NEQ -> evalBinOpConc st e1 e2 BitVector.neq
  | RelOpType.GT -> evalBinOpConc st e1 e2 BitVector.gt
  | RelOpType.GE -> evalBinOpConc st e1 e2 BitVector.ge
  | RelOpType.SGT -> evalBinOpConc st e1 e2 BitVector.sgt
  | RelOpType.SGE -> evalBinOpConc st e1 e2 BitVector.sge
  | RelOpType.LT -> evalBinOpConc st e1 e2 BitVector.lt
  | RelOpType.LE -> evalBinOpConc st e1 e2 BitVector.le
  | RelOpType.SLT -> evalBinOpConc st e1 e2 BitVector.slt
  | RelOpType.SLE -> evalBinOpConc st e1 e2 BitVector.sle
  | RelOpType.FLT -> evalBinOpConc st e1 e2 BitVector.flt
  | RelOpType.FLE -> evalBinOpConc st e1 e2 BitVector.fle
  | RelOpType.FGT -> evalBinOpConc st e1 e2 BitVector.fgt
  | RelOpType.FGE -> evalBinOpConc st e1 e2 BitVector.fge
  | _ -> raise IllegalASTTypeException

let private markUndefAfterFailure (st: EvalState) lhs =
  match lhs with
  | Var (_, n, _, _) -> st.UnsetReg n
  | _ -> ()

let private evalPCUpdate st rhs =
  match evalConcrete st rhs with
  | (Ok (Def v)) as res ->
    st.Callbacks.OnPut st.PC v
    unwrap res
    |> Result.map BitVector.toUInt64
    |> Result.map st.SetPC
  | _ -> Error ErrorCase.InvalidExprEvaluation

let private evalPut st lhs rhs =
  match evalConcrete st rhs with
  | (Ok (Def v)) ->
    st.Callbacks.OnPut st.PC v
    match lhs.E with
    | Var (_, n, _, _) -> st.SetReg n v |> Ok
    | TempVar (_, n) -> st.SetTmp n v |> Ok
    | PCVar (_) -> BitVector.toUInt64 v |> st.SetPC |> Ok
    | _ -> Error ErrorCase.InvalidExprEvaluation
  | _ ->
    markUndefAfterFailure st lhs.E
    Error ErrorCase.InvalidExprEvaluation

let private evalStore st endian addr v =
  let addr = evalConcrete st addr |> unwrap |> Result.map BitVector.toUInt64
  let v = evalConcrete st v |> unwrap
  match addr, v with
  | Ok addr, Ok v ->
    st.Callbacks.OnStore st.PC addr v
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

let evalStmt (st: EvalState) = function
  | ISMark (_) -> st.StartInstr (); st.NextStmt () |> Ok
  | IEMark (len) -> st.IncPC len; st.AbortInstr () |> Ok
  | LMark _ -> st.NextStmt () |> Ok
  | Put (lhs, rhs) -> evalPut st lhs rhs |> Result.map st.NextStmt
  | Store (e, addr, v) -> evalStore st e addr v |> Result.map st.NextStmt
  | Jmp target -> evalJmp st target
  | CJmp (cond, t, f) -> evalCJmp st cond t f
  | InterJmp (target, _) -> evalPCUpdate st target |> Result.map st.AbortInstr
  | InterCJmp (c, t, f) -> evalIntCJmp st c t f |> Result.map st.AbortInstr
  | SideEffect eff -> st.Callbacks.OnSideEffect eff st |> ignore |> Ok

let internal tryEvaluate stmt st =
  match evalStmt st stmt.S with
  | Ok () -> Ok ()
  | Error e ->
    if st.IgnoreUndef then st.NextStmt () |> Ok
    else Error e

let go stmts st = function
  | Ok () -> gotoNextInstr stmts st |> Ok
  | Error e -> Error e

let rec internal evalLoop stmts result =
  match result with
  | Ok (st: EvalState) ->
    let ctxt = st.GetCurrentContext ()
    let idx = ctxt.StmtIdx
    let st = if idx = 0 then st.Callbacks.OnInstr st else st
    if Array.length stmts > idx && idx >= 0 then
      let stmt = stmts.[idx]
      st.Callbacks.OnStmtEval stmt
      evalLoop stmts (tryEvaluate stmt st |> go stmts st)
    else Ok st
  | Error _ -> result

/// Evaluate a block of statements. The block may represent a machine
/// instruction, or a basic block.
let evalBlock (st: EvalState) pc tid stmts =
  st.SetPC pc
  if st.ThreadId <> tid then st.ContextSwitch tid else ()
  st.PrepareBlockEval stmts
  evalLoop stmts (Ok st)
  |> function
    | Ok st -> st.CleanUp (); Ok st
    | Error e -> Error e
