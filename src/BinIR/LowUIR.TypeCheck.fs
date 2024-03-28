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

[<RequireQualifiedAccess>]
module B2R2.BinIR.LowUIR.TypeCheck

open B2R2
open B2R2.BinIR

/// Get the type of an expression.
let rec typeOf e =
  match e.E with
  | Num n -> n.Length
  | Var (t, _, _)
  | PCVar (t, _)
  | TempVar (t, _) -> t
  | UnOp (_, e) -> typeOf e
  | BinOp (_, t, _, _) -> t
  | RelOp (_) -> 1<rt>
  | Load (_, t, _) -> t
  | Ite (_, e1, _) -> typeOf e1
  | Cast (_, t, _) -> t
  | Extract (_, t, _) -> t
  | Undefined (t, _) -> t
  | FuncName (_) | Name (_) | Nil -> raise InvalidExprException

#if DEBUG
let internal bool e =
  let t = typeOf e
  if t <> 1<rt> then
    raise <| TypeCheckException (Pp.expToString e + "must be boolean.")
  else ()
#endif

let inline internal checkEquivalence t1 t2 =
  if t1 = t2 then ()
  else raise <| TypeCheckException "Inconsistent types."

let internal concat e1 e2 = typeOf e1 + typeOf e2

let internal binop e1 e2 =
  let t1 = typeOf e1
  let t2 = typeOf e2
  checkEquivalence t1 t2
  t1

let private castErr (newType: RegType) (oldType: RegType) =
  let errMsg =
    "Cannot cast from " + oldType.ToString () + " to " + newType.ToString ()
  raise <| TypeCheckException errMsg

let private isValidFloatType = function
  | 32<rt> | 64<rt> | 80<rt> -> true
  | _ -> false

let internal canCast kind newType e =
  let oldType = typeOf e
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
  | _ -> true

let internal extract (t: RegType) pos (t2: RegType) =
  if (RegType.toBitWidth t + pos) <= RegType.toBitWidth t2 && pos >= 0 then ()
  else raise <| TypeCheckException "Inconsistent types."

let rec expr e =
  match e.E with
  | UnOp (_, e) -> expr e
  | BinOp (BinOpType.CONCAT, t, e1, e2) ->
    expr e1 && expr e2 && concat e1 e2 = t
  | BinOp (_, t, e1, e2) -> expr e1 && expr e2 && binop e1 e2 = t
  | RelOp (_, e1, e2) -> expr e1 && expr e2 && typeOf e1 = typeOf e2
  | Load (_, _, addr) -> expr addr
  | Ite (cond, e1, e2) ->
    typeOf cond = 1<rt> && expr e1 && expr e2 && typeOf e1 = typeOf e2
  | Cast (CastKind.SignExt, t, e)
  | Cast (CastKind.ZeroExt, t, e) -> expr e && t >= typeOf e
  | Extract (e, t, p) ->
    expr e && ((t + LanguagePrimitives.Int32WithMeasure p) <= typeOf e)
  | _ -> true

let stmt s =
  match s.S with
  | Put (v, e) -> (typeOf v) = (typeOf e)
  | Store (_, a, v) -> expr a && expr v
  | Jmp (a) -> expr a
  | CJmp (cond, e1, e2) -> expr cond && expr e1 && expr e2
  | InterJmp (addr, _) -> expr addr
  | InterCJmp (cond, a1, a2) -> expr cond && expr a1 && expr a2
  | _ -> true
