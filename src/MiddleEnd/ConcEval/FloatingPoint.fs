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

module internal B2R2.MiddleEnd.ConcEval.FloatingPoint

open System.Numerics
open B2R2
open B2R2.BinIR

type private Format =
  { Precision: int
    FractionBits: int
    Bias: int
    MaxExponent: int }

type private Value =
  | Finite of bool * bigint * int
  | Infinity of bool
  | NaN

let private format = function
  | 32<rt> ->
    { Precision = 24; FractionBits = 23; Bias = 127; MaxExponent = 255 }
  | 64<rt> ->
    { Precision = 53; FractionBits = 52; Bias = 1023; MaxExponent = 2047 }
  | 80<rt> ->
    { Precision = 64; FractionBits = 64; Bias = 16383; MaxExponent = 32767 }
  | _ ->
    raise InvalidRegTypeException

let private decode (v: BitVector) =
  let f = format v.Length
  let bits = v.ToBigInt()
  let negative = v.IsNegative
  let exponent = int (bits >>> f.FractionBits) &&& f.MaxExponent
  let fraction = bits &&& ((1I <<< f.FractionBits) - 1I)
  let hidden = 1I <<< (f.Precision - 1)
  let significand =
    if exponent = 0 || v.Length = 80<rt> then fraction
    else fraction + hidden
  if exponent = f.MaxExponent then
    if fraction = 0I || (v.Length = 80<rt> && fraction = hidden) then
      Infinity negative
    else
      NaN
  else
    Finite(negative, significand, max 1 exponent - f.Bias - f.Precision + 1)

let private pack t negative exponent significand =
  let f = format t
  let sign = if negative then 1I <<< (int t - 1) else 0I
  let fraction = significand &&& ((1I <<< f.FractionBits) - 1I)
  let exponent = bigint (exponent: int) <<< f.FractionBits
  BitVector(sign ||| exponent ||| fraction, t)

let private infinity t negative =
  let f = format t
  let significand = if t = 80<rt> then 1I <<< 63 else 0I
  pack t negative f.MaxExponent significand

let private nan t =
  let f = format t
  let significand =
    if t = 80<rt> then (1I <<< 63) ||| (1I <<< 62)
    else 1I <<< (f.Precision - 2)
  pack t false f.MaxExponent significand

(* The comparison is against the midpoint, before rounding. Keeping the
   remainder exact avoids double rounding and loss of extended precision. *)
let private increment mode negative odd comparison inexact =
  match mode with
  | RoundingMode.TowardPositive -> inexact && not negative
  | RoundingMode.TowardNegative -> inexact && negative
  | RoundingMode.TowardZero -> false
  | RoundingMode.ToNearestAway -> comparison >= 0 && inexact
  | _ -> comparison > 0 || (comparison = 0 && odd)

let private quotient mode negative (n: bigint) (d: bigint) =
  let q, r = BigInteger.DivRem(n, d)
  if increment mode negative (not q.IsEven) (compare (r * 2I) d) (r <> 0I)
  then q + 1I
  else q

let private scale (n: bigint) d exponent =
  if exponent >= 0 then n <<< exponent, d
  else n, d <<< -exponent

let private binaryExponent (n: bigint) (d: bigint) =
  let estimate = int (n.GetBitLength() - d.GetBitLength())
  let a, b = scale n d -estimate
  if a < b then estimate - 1 else estimate

let private overflow mode t negative =
  let f = format t
  let finite =
    match mode with
    | RoundingMode.TowardZero -> true
    | RoundingMode.TowardPositive -> negative
    | RoundingMode.TowardNegative -> not negative
    | _ -> false
  if finite then
    pack t negative (f.MaxExponent - 1) ((1I <<< f.Precision) - 1I)
  else
    infinity t negative

let private finish mode t negative exponent q =
  let f = format t
  let carry = q >= (1I <<< f.Precision)
  let exponent = if carry then exponent + 1 else exponent
  let q = if carry then q >>> 1 else q
  if exponent > f.Bias then
    overflow mode t negative
  else
    let field = if q < (1I <<< (f.Precision - 1)) then 0 else exponent + f.Bias
    pack t negative field q

let private encode mode t negative (n, d, power) =
  let f = format t
  if n = 0I then
    pack t negative 0 0I
  else
    let exponent = max (1 - f.Bias) (binaryExponent n d + power)
    let a, b = scale n d (power - exponent + f.Precision - 1)
    finish mode t negative exponent (quotient mode negative a b)

/// Converts formats without passing through the host's floating point format.
let cast mode t v =
  match decode v with
  | Finite(sign, n, e) -> encode mode t sign (n, 1I, e)
  | Infinity sign -> infinity t sign
  | NaN -> if v.Length = t then v else nan t

/// Converts the integer's full precision, rounding once in the result format.
let ofInteger mode t signed (v: BitVector) =
  let n = v.ToBigInt()
  let n = if signed && v.IsNegative then n - (1I <<< int v.Length) else n
  encode mode t (n.Sign < 0) (BigInteger.Abs n, 1I, 0)

let private integral mode negative n exponent =
  let a, b = scale n 1I exponent
  quotient mode negative a b

/// Rounds a float to an integer, preserving the signed integer-indefinite rule.
let toInteger mode t v =
  let limit = 1I <<< (int t - 1)
  let result =
    match decode v with
    | Finite(sign, n, e) ->
      let q = integral mode sign n e
      let q = if sign then -q else q
      if q < -limit || q >= limit then limit else q
    | _ ->
      limit
  BitVector(result &&& ((1I <<< int t) - 1I), t)

/// Rounds in the original format, including its signed zero and exponent range.
let roundToIntegral mode t v =
  match decode v with
  | Finite(sign, n, e) ->
    encode mode t sign (integral mode sign n e, 1I, 0)
  | _ ->
    cast mode t v

/// Evaluates a cast in the rounding direction of the enclosing expression.
let convert mode kind t v =
  match kind with
  | CastKind.SignExt -> BitVector.SExt(v, t)
  | CastKind.ZeroExt -> BitVector.ZExt(v, t)
  | CastKind.FloatCast -> cast mode t v
  | CastKind.SIntToFloat -> ofInteger mode t true v
  | CastKind.UIntToFloat -> ofInteger mode t false v
  | CastKind.FloatToSInt -> toInteger mode t v
  | CastKind.RoundToIntegral -> roundToIntegral mode t v
  | _ -> raise IllegalASTTypeException

let private signed negative n = if negative then -n else n

let private addFinite mode t (sa, a, ea) (sb, b, eb) =
  let e = min ea eb
  let n = (signed sa a <<< (ea - e)) + (signed sb b <<< (eb - e))
  let sign =
    if n = 0I then
      if a = 0I && b = 0I && sa = sb then sa
      else mode = RoundingMode.TowardNegative
    else
      n.Sign < 0
  encode mode t sign (BigInteger.Abs n, 1I, e)

let private add mode t a b =
  match a, b with
  | NaN, _ | _, NaN ->
    nan t
  | Infinity sa, Infinity sb ->
    if sa = sb then infinity t sa else nan t
  | Infinity sign, _ | _, Infinity sign ->
    infinity t sign
  | Finite(sa, a, ea), Finite(sb, b, eb) ->
    addFinite mode t (sa, a, ea) (sb, b, eb)

let private negate = function
  | Finite(s, n, e) -> Finite(not s, n, e)
  | Infinity s -> Infinity(not s)
  | NaN -> NaN

let private multiply mode t a b =
  match a, b with
  | NaN, _ | _, NaN ->
    nan t
  | Infinity _, Finite(_, n, _) | Finite(_, n, _), Infinity _ when n = 0I ->
    nan t
  | Infinity sa, Infinity sb
  | Infinity sa, Finite(sb, _, _)
  | Finite(sa, _, _), Infinity sb ->
    infinity t (sa <> sb)
  | Finite(sa, a, ea), Finite(sb, b, eb) ->
    encode mode t (sa <> sb) (a * b, 1I, ea + eb)

let private divide mode t a b =
  match a, b with
  | NaN, _ | _, NaN | Infinity _, Infinity _ ->
    nan t
  | Infinity sa, Finite(sb, _, _) ->
    infinity t (sa <> sb)
  | Finite(sa, _, _), Infinity sb ->
    pack t (sa <> sb) 0 0I
  | Finite(sa, a, ea), Finite(sb, b, eb) ->
    if b = 0I then
      if a = 0I then nan t else infinity t (sa <> sb)
    else
      encode mode t (sa <> sb) (a, b, ea - eb)

/// Performs the basic arithmetic with an exact intermediate rational value.
let binary mode op (a: BitVector, b: BitVector) =
  if a.Length <> b.Length then raise RegTypeMismatchException else ()
  let t = a.Length
  match op with
  | BinOpType.FADD ->
    add mode t (decode a) (decode b)
  | BinOpType.FSUB ->
    add mode t (decode a) (negate (decode b))
  | BinOpType.FMUL ->
    multiply mode t (decode a) (decode b)
  | BinOpType.FDIV ->
    divide mode t (decode a) (decode b)
  | _ ->
    raise IllegalASTTypeException

let private integerSqrt (n: bigint) =
  if n = 0I then
    0I
  else
    let rec improve x =
      let next = (x + n / x) >>> 1
      if next >= x then x else improve next
    improve (1I <<< ((int (n.GetBitLength()) + 1) / 2))

let private sqrtFinite mode t n power =
  let f = format t
  let exponent = max (1 - f.Bias) ((binaryExponent n 1I + power) >>> 1)
  let a, b = scale n 1I (power - 2 * (exponent - f.Precision + 1))
  let q = integerSqrt (a / b)
  let midpoint = compare (4I * a) (b * (2I * q + 1I) * (2I * q + 1I))
  let inexact = a <> b * q * q
  let q =
    if increment mode false (not q.IsEven) midpoint inexact then q + 1I
    else q
  finish mode t false exponent q

/// Computes a square root with an exact test against the rounding midpoint.
let sqrt mode (v: BitVector) =
  match decode v with
  | Finite(sign, n, _) when n = 0I -> pack v.Length sign 0 0I
  | Finite(false, n, e) -> sqrtFinite mode v.Length n e
  | Infinity false -> v
  | _ -> nan v.Length

/// Floating inequality is the complement of floating equality, including NaNs.
let notEqual (a, b) = BitVector.Not(BitVector.FEq(a, b))
