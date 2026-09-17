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

/// <summary>
/// Provides functions for type checking LowUIR.
/// </summary>
[<RequireQualifiedAccess>]
module B2R2.BinIR.LowUIR.TypeCheck

open B2R2
open B2R2.BinIR

#if DEBUG
let internal bool e =
  let t = Expr.typeOf e
  if t <> 1<rt> then
    raise <| TypeCheckException(Expr.toString e + "must be boolean.")
  else
    ()
#endif

#if DEBUG
let internal roundingMode e =
  let t = Expr.typeOf e
  if t <> RoundingMode.modeType then
    raise <| TypeCheckException(Expr.toString e + "must be a rounding mode.")
  else
    ()
#endif

let inline internal checkEquivalence t1 t2 =
  if t1 = t2 then () else raise <| TypeCheckException "Inconsistent types."

let internal concat e1 e2 = Expr.typeOf e1 + Expr.typeOf e2

let internal binop e1 e2 =
  let t1 = Expr.typeOf e1
  let t2 = Expr.typeOf e2
  checkEquivalence t1 t2
  t1

let private castErr (newType: RegType) (oldType: RegType) =
  let errMsg =
    "Cannot cast from " + oldType.ToString() + " to " + newType.ToString()
  raise <| TypeCheckException errMsg

let private isValidFloatType = function
  | 32<rt> | 64<rt> | 80<rt> -> true
  | _ -> false

let internal canCast kind newType e =
  let oldType = Expr.typeOf e
  match kind with
  | CastKind.SignExt
  | CastKind.ZeroExt ->
    if oldType < newType then true
    else if oldType = newType then false
    else castErr newType oldType
  | CastKind.SIntToFloat
  | CastKind.UIntToFloat ->
    if isValidFloatType newType then true else raise InvalidFloatTypeException
  | CastKind.FloatCast ->
    if isValidFloatType oldType && isValidFloatType newType then true
    else raise InvalidFloatTypeException
  | _ ->
    true

let internal extract (t: RegType) pos (t2: RegType) =
  if (RegType.toBitWidth t + pos) <= RegType.toBitWidth t2 && pos >= 0 then ()
  else raise <| TypeCheckException "Inconsistent types."

/// Type-checks a LowUIR expression.
let rec expr e =
  match e with
  | UnOp(Operand = e) ->
    expr e
  | BinOp(Op = BinOpType.CONCAT; Type = t; Left = e1; Right = e2) ->
    expr e1 && expr e2 && concat e1 e2 = t
  | BinOp(Type = t; Left = e1; Right = e2) ->
    expr e1 && expr e2 && binop e1 e2 = t
  | RelOp(Left = e1; Right = e2) ->
    expr e1 && expr e2 && Expr.typeOf e1 = Expr.typeOf e2
  | Load(Addr = addr) ->
    expr addr
  | Ite(Cond = cond; TrueExpr = e1; FalseExpr = e2) ->
    Expr.typeOf cond = 1<rt> && expr e1 && expr e2
    && Expr.typeOf e1 = Expr.typeOf e2
  | Cast(Kind = CastKind.SignExt; Type = t; Operand = e)
  | Cast(Kind = CastKind.ZeroExt; Type = t; Operand = e) ->
    expr e && t >= Expr.typeOf e
  | RoundCtrl(Mode = mode; Body = body) ->
    expr mode && expr body && Expr.typeOf mode = RoundingMode.modeType
  | Extract(Operand = e; Type = t; StartPos = p) ->
    expr e && ((t + LanguagePrimitives.Int32WithMeasure p) <= Expr.typeOf e)
  | _ ->
    true

/// Type-checks a LowUIR statement.
let stmt s =
  match s with
  | Put(Dst = v; Src = e) ->
    (Expr.typeOf v) = (Expr.typeOf e)
  | Store(Addr = a; Value = v) ->
    expr a && expr v
  | Jmp(Target = a) ->
    expr a
  | CJmp(Cond = cond; TrueTarget = e1; FalseTarget = e2) ->
    expr cond && expr e1 && expr e2
  | InterJmp(Target = addr) ->
    expr addr
  | InterCJmp(Cond = cond; TrueTarget = a1; FalseTarget = a2) ->
    expr cond && expr a1 && expr a2
  | _ ->
    true
