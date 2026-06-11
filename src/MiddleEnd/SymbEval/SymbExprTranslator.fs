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

namespace B2R2.MiddleEnd.SymbEval

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

/// Translates LowUIR expressions into symbolic expressions.
[<RequireQualifiedAccess>]
module SymbExprTranslator =
  let private unsupportedExpr expr =
    Expr.toString expr |> UnsupportedExpression |> Error

  let private unsupportedOp op = UnsupportedOperation op |> Error

  let private evalUnOp = function
    | UnOpType.NEG -> Some BitVector.Neg
    | UnOpType.NOT -> Some BitVector.Not
    | _ -> None

  let private evalBinOp = function
    | BinOpType.ADD -> Some(fun lhs rhs -> BitVector.Add(lhs, rhs))
    | BinOpType.SUB -> Some(fun lhs rhs -> BitVector.Sub(lhs, rhs))
    | BinOpType.MUL -> Some(fun lhs rhs -> BitVector.Mul(lhs, rhs))
    | BinOpType.DIV -> Some(fun lhs rhs -> BitVector.Div(lhs, rhs))
    | BinOpType.SDIV -> Some(fun lhs rhs -> BitVector.SDiv(lhs, rhs))
    | BinOpType.MOD -> Some(fun lhs rhs -> BitVector.Modulo(lhs, rhs))
    | BinOpType.SMOD -> Some(fun lhs rhs -> BitVector.SModulo(lhs, rhs))
    | BinOpType.SHL -> Some(fun lhs rhs -> BitVector.Shl(lhs, rhs))
    | BinOpType.SAR -> Some(fun lhs rhs -> BitVector.Sar(lhs, rhs))
    | BinOpType.SHR -> Some(fun lhs rhs -> BitVector.Shr(lhs, rhs))
    | BinOpType.AND -> Some(fun lhs rhs -> BitVector.And(lhs, rhs))
    | BinOpType.OR -> Some(fun lhs rhs -> BitVector.Or(lhs, rhs))
    | BinOpType.XOR -> Some(fun lhs rhs -> BitVector.Xor(lhs, rhs))
    | BinOpType.CONCAT -> Some(fun lhs rhs -> BitVector.Concat(lhs, rhs))
    | _ -> None

  let private evalRelOp = function
    | RelOpType.EQ -> Some(fun lhs rhs -> BitVector.Eq(lhs, rhs))
    | RelOpType.NEQ -> Some(fun lhs rhs -> BitVector.Neq(lhs, rhs))
    | RelOpType.GT -> Some(fun lhs rhs -> BitVector.Gt(lhs, rhs))
    | RelOpType.GE -> Some(fun lhs rhs -> BitVector.Ge(lhs, rhs))
    | RelOpType.SGT -> Some(fun lhs rhs -> BitVector.SGt(lhs, rhs))
    | RelOpType.SGE -> Some(fun lhs rhs -> BitVector.SGe(lhs, rhs))
    | RelOpType.LT -> Some(fun lhs rhs -> BitVector.Lt(lhs, rhs))
    | RelOpType.LE -> Some(fun lhs rhs -> BitVector.Le(lhs, rhs))
    | RelOpType.SLT -> Some(fun lhs rhs -> BitVector.SLt(lhs, rhs))
    | RelOpType.SLE -> Some(fun lhs rhs -> BitVector.SLe(lhs, rhs))
    | _ -> None

  let private evalCast typ kind value =
    match kind with
    | CastKind.SignExt -> Some(BitVector.SExt(value, typ))
    | CastKind.ZeroExt -> Some(BitVector.ZExt(value, typ))
    | _ -> None

  let private bitMask typ =
    (1I <<< int typ) - 1I

  let private valueMask (bv: BitVector) =
    bv.ToBigInt() &&& bitMask bv.Length

  let private constZero typ = Const(BitVector.Zero typ)

  let rec private getMayOneBits expr =
    match expr with
    | SymbExpr.Const bv -> valueMask bv
    | SymbExpr.Var(_, typ)
    | SymbExpr.Load(_, typ, _)
    | SymbExpr.FuncApp(_, typ, _)
    | SymbExpr.Undef(typ, _) -> bitMask typ
    | SymbExpr.UnOp(UnOpType.NOT, expr) -> bitMask expr.Type
    | SymbExpr.UnOp(_, expr) -> bitMask expr.Type
    | SymbExpr.BinOp(BinOpType.AND, typ, lhs, rhs) ->
        getMayOneBits lhs &&& getMayOneBits rhs &&& bitMask typ
    | SymbExpr.BinOp(BinOpType.OR, typ, lhs, rhs)
    | SymbExpr.BinOp(BinOpType.XOR, typ, lhs, rhs) ->
        getMayOneBits lhs ||| getMayOneBits rhs &&& bitMask typ
    | SymbExpr.BinOp(BinOpType.SHL, typ, lhs, SymbExpr.Const rhs) ->
      let shift = rhs.ToUInt64()
      if shift >= uint64 (int typ) then 0I
      else getMayOneBits lhs <<< int shift &&& bitMask typ
    | SymbExpr.BinOp(BinOpType.SHR, typ, lhs, SymbExpr.Const rhs) ->
      let shift = rhs.ToUInt64()
      if shift >= uint64 (int typ) then 0I
      else getMayOneBits lhs >>> int shift &&& bitMask typ
    | SymbExpr.BinOp(_, typ, _, _) -> bitMask typ
    | SymbExpr.RelOp _ -> bitMask 1<rt>
    | SymbExpr.Ite(_, thenExpr, elseExpr) ->
      getMayOneBits thenExpr ||| getMayOneBits elseExpr
      &&& bitMask thenExpr.Type
    | SymbExpr.Cast(CastKind.ZeroExt, typ, expr) ->
      getMayOneBits expr &&& bitMask typ
    | SymbExpr.Cast(_, typ, _) -> bitMask typ
    | SymbExpr.Extract(expr, typ, pos) ->
      getMayOneBits expr >>> pos &&& bitMask typ

  let private tryFoldMaskedAndToZero typ lhs rhs =
    match lhs, rhs with
    | expr, Const mask
    | Const mask, expr ->
      let mask = valueMask mask
      if getMayOneBits expr &&& mask = 0I then Some(constZero typ)
      else None
    | _ -> None

  let private foldUnOp op expr =
    match evalUnOp op with
    | Some fn ->
      match expr with
      | Const bv -> SymbExpr.Const(fn bv) |> Ok
      | _ -> SymbExpr.unop op expr |> Ok
    | None -> UnOpType.toString op |> unsupportedOp

  let private foldBinOp op typ lhs rhs =
    match evalBinOp op with
    | Some fn ->
      match lhs, rhs with
      | Const lhs, Const rhs -> SymbExpr.Const(fn lhs rhs) |> Ok
      | _ when op = BinOpType.AND ->
        match tryFoldMaskedAndToZero typ lhs rhs with
        | Some expr -> Ok expr
        | None -> SymbExpr.binop op typ lhs rhs |> Ok
      | _ -> SymbExpr.binop op typ lhs rhs |> Ok
    | None -> BinOpType.toString op |> unsupportedOp

  let private foldRelOp op lhs rhs =
    match evalRelOp op with
    | Some fn ->
      match lhs, rhs with
      | Const lhs, Const rhs -> SymbExpr.Const(fn lhs rhs) |> Ok
      | _ -> SymbExpr.relop op lhs rhs |> Ok
    | None -> RelOpType.toString op |> unsupportedOp

  let private foldCast kind typ expr =
    match expr with
    | Const bv ->
      match evalCast typ kind bv with
      | Some bv -> SymbExpr.Const bv |> Ok
      | None -> CastKind.toString kind |> unsupportedOp
    | _ ->
      match kind with
      | CastKind.SignExt
      | CastKind.ZeroExt -> SymbExpr.cast kind typ expr |> Ok
      | _ -> CastKind.toString kind |> unsupportedOp

  let private foldExtract typ pos = function
    | Const bv -> SymbExpr.Const(BitVector.Extract(bv, typ, pos)) |> Ok
    | expr -> SymbExpr.extract expr typ pos |> Ok

  let private bind2 fn lhs rhs =
    match lhs, rhs with
    | Ok lhs, Ok rhs -> fn lhs rhs
    | Error e, _ | _, Error e -> Error e

  let private evalRegister (state: SymbState) rid =
    match state.TryGetReg rid with
    | Ok value -> Ok value
    | Error _ -> Error(UninitializedRegister rid)

  let private evalTemporary (state: SymbState) idx =
    match state.TryGetTmp idx with
    | Ok value -> Ok value
    | Error _ -> Error(UninitializedTemporary idx)

  /// Translates a LowUIR expression in the context of the provided symbolic
  /// state.
  let rec translate (state: SymbState) (expr: Expr) =
    match expr with
    | Num(n, _) -> SymbExpr.Const n |> Ok
    | Var(_, rid, _, _) -> evalRegister state rid
    | PCVar(typ, _, _) -> SymbExpr.Const(BitVector(state.PC, typ)) |> Ok
    | TempVar(_, idx, _) -> evalTemporary state idx
    | UnOp(op, expr, _) ->
      translate state expr |> Result.bind (foldUnOp op)
    | BinOp(op, typ, lhs, rhs, _) ->
      bind2 (foldBinOp op typ) (translate state lhs) (translate state rhs)
    | RelOp(op, lhs, rhs, _) ->
      bind2 (foldRelOp op) (translate state lhs) (translate state rhs)
    | Load(endian, typ, addr, _) ->
      match translate state addr with
      | Ok(Const bv) -> state.Memory.Load(bv.ToUInt64(), endian, typ)
      | Ok addr -> Error(UnsupportedSymbolicAddress addr)
      | Error e -> Error e
    | Ite(cond, thenExpr, elseExpr, _) ->
      match translate state cond with
      | Ok(Const bv) when bv.IsTrue -> translate state thenExpr
      | Ok(Const bv) when bv.IsFalse -> translate state elseExpr
      | Ok cond when SymbExpr.isCondition cond ->
        match translate state thenExpr, translate state elseExpr with
        | Ok thenExpr, Ok elseExpr -> SymbExpr.ite cond thenExpr elseExpr |> Ok
        | Error e, _ | _, Error e -> Error e
      | Ok cond ->
        $"Invalid Ite condition type: {RegType.toString cond.Type}"
        |> unsupportedOp
      | Error e -> Error e
    | Cast(kind, typ, expr, _) ->
      translate state expr |> Result.bind (foldCast kind typ)
    | Extract(expr, typ, pos, _) ->
      translate state expr |> Result.bind (foldExtract typ pos)
    | Undefined(typ, reason, _) -> SymbExpr.undef typ reason |> Ok
    | _ -> unsupportedExpr expr
