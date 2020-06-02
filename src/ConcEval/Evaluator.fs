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

/// ConcEval is a concrete evaluation module for LowUIR.
module B2R2.ConcEval.Evaluator

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

let private tr = BitVector.one 1<rt>

let private map1 fn p1 = function
  | Undef -> raise UndefExpException
  | Def bv -> Def (fn bv p1)

let private map2 fn p1 p2 = function
  | Undef -> raise UndefExpException
  | Def bv -> Def (fn bv p1 p2)

let private unwrap = function
  | Undef -> raise UndefExpException
  | Def bv -> bv

let rec evalConcrete st e =
  match e with
  | Num n -> Def n
  | Var (_, n, _, _) -> EvalState.GetReg st n
  | PCVar (t, _) -> BitVector.ofUInt64 st.PC t |> Def
  | TempVar (_, n) -> EvalState.GetTmp st n
  | UnOp (t, e, _, _) -> evalUnOp st e t |> Def
  | BinOp (t, _, e1, e2, _, _) -> evalBinOp st e1 e2 t |> Def
  | RelOp (t, e1, e2, _, _) -> evalRelOp st e1 e2 t |> Def
  | Load (endian, t, addr, _, _) -> evalLoad st endian t addr |> Def
  | Ite (cond, e1, e2, _, _) -> evalIte st cond e1 e2
  | Cast (kind, t, e, _, _) -> evalCast st t e kind
  | Extract (e, t, p, _, _) -> evalConcrete st e |> map2 BitVector.extract t p
  | Undefined (_) -> Undef
  | _ -> raise InvalidExprException

and private evalLoad st endian t addr =
  let pc = st.PC
  let addr = evalConcrete st addr |> unwrap |> BitVector.toUInt64
  let v = st.Memory.Read pc addr endian t
  st.Callbacks.OnLoad pc addr v
  v

and private evalIte st cond e1 e2 =
  let cond = evalConcrete st cond |> unwrap
  if cond = tr then evalConcrete st e1 else evalConcrete st e2

and private evalBinOpConc st e1 e2 fn =
  let e1 = evalConcrete st e1 |> unwrap
  let e2 = evalConcrete st e2 |> unwrap
  fn e1 e2

and private evalUnOpConc st e fn = evalConcrete st e |> unwrap |> fn

and private evalCast st t e = function
| CastKind.SignExt -> evalConcrete st e |> map1 BitVector.sext t
| CastKind.ZeroExt -> evalConcrete st e |> map1 BitVector.zext t
| CastKind.FloatExt -> evalConcrete st e |> map1 BitVector.fext t
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

let private evalPut st lhs rhs =
  try
    let v = evalConcrete st rhs
    st.Callbacks.OnPut st.PC v
    match lhs with
    | Var (_, n, _, _) -> EvalState.SetReg st n v
    | PCVar (_) -> unwrap v |> BitVector.toUInt64 |> EvalState.SetPC st
    | TempVar (_, n) -> EvalState.SetTmp st n v
    | _ -> raise InvalidExprException
  with UndefExpException ->
    st (* Do not store undefined value *)

let private evalStore st endian addr v =
  let addr = evalConcrete st addr |> unwrap |> BitVector.toUInt64
  let v = evalConcrete st v |> unwrap
  st.Callbacks.OnStore st.PC addr v
  st.Memory.Write addr v endian
  st

let private evalJmp st target =
  match target with
  | Name n -> EvalState.GoToLabel st n
  | _ -> raise InvalidExprException

let private evalCJmp st cond t f =
  let cond = evalConcrete st cond |> unwrap
  if cond = tr then evalJmp st t else evalJmp st f

let private evalIntCJmp st cond pc t f =
  let cond = evalConcrete st cond |> unwrap
  evalPut st pc (if cond = tr then t else f)

let evalStmt st = function
  | ISMark (pc, _) -> EvalState.StartInstr st pc |> EvalState.NextStmt
  | IEMark (addr) -> EvalState.SetPC st addr |> EvalState.AbortInstr
  | LMark _ -> EvalState.NextStmt st
  | Put (lhs, rhs) -> evalPut st lhs rhs |> EvalState.NextStmt
  | Store (e, addr, v) -> evalStore st e addr v |> EvalState.NextStmt
  | Jmp target -> evalJmp st target
  | CJmp (cond, t, f) -> evalCJmp st cond t f
  | InterJmp (pc, target, _) -> evalPut st pc target |> EvalState.AbortInstr
  | InterCJmp (c, pc, t, f) -> evalIntCJmp st c pc t f |> EvalState.AbortInstr
  | SideEffect eff -> st.Callbacks.OnSideEffect eff st

let rec internal gotoNextInstr stmts st =
  let ctxt = EvalState.GetCurrentContext st
  let idx = ctxt.StmtIdx
  if EvalState.IsInstrTerminated st && Array.length stmts > idx && idx >= 0 then
    match stmts.[idx] with
    | ISMark (pc, _) -> EvalState.StartInstr st pc
    | _ -> gotoNextInstr stmts (EvalState.NextStmt st)
  else st

let internal tryEvaluate stmt st =
  try evalStmt st stmt with
  | UndefExpException
  | InvalidMemException ->
    if st.IgnoreUndef then EvalState.NextStmt st
    else raise UndefExpException

let rec internal evalLoop stmts st =
  let ctxt = EvalState.GetCurrentContext st
  let idx = ctxt.StmtIdx
  let st = if idx = 0 then st.Callbacks.OnInstr st else st
  if Array.length stmts > idx && idx >= 0 then
    let stmt = stmts.[idx]
    st.Callbacks.OnStmtEval stmt
    evalLoop stmts (tryEvaluate stmt st |> gotoNextInstr stmts)
  else st

/// Evaluate a block of statements. The block may represent a machine
/// instruction, or a basic block.
let evalBlock (st: EvalState) tid stmts =
  if st.ThreadId <> tid then EvalState.ContextSwitch tid st else st
  |> EvalState.PrepareBlockEval stmts
  |> evalLoop stmts
  |> EvalState.CleanUp
