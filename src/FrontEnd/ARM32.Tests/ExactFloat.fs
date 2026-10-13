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

namespace B2R2.FrontEnd.ARM32.Tests

open System.Numerics
open B2R2
open B2R2.BinIR

/// <summary>
/// The arithmetic of singles and doubles done exactly and rounded once, for
/// IRRunner to answer what the host's own arithmetic cannot: a rounding in a
/// direction other than to nearest, and the exceptions an operation raised.
/// A finite value is held as a sign and a magnitude times a power of two, so
/// a sum, a product and a fused multiply-add are exact; a quotient and a
/// square root are held to more bits than any rounding reads, with one more
/// bit that says whether anything was left over.
/// </summary>
module internal ExactFloat =
  /// A binary format: the bits of its significand, counting the hidden one,
  /// and the exponent of its greatest finite numbers.
  type private Format =
    { Precision: int
      EMax: int }

  /// What a single or a double encodes.
  type private Datum =
    | NaN of isSignalling: bool
    | Infinity of isNegative: bool
    | Finite of isNegative: bool * magnitude: BigInteger * exp: int

  let private formatOf (rt: RegType) =
    if rt = 32<rt> then { Precision = 24; EMax = 127 }
    elif rt = 64<rt> then { Precision = 53; EMax = 1023 }
    else failwith $"ExactFloat: no {rt}-bit format"

  /// The least exponent of a normal number.
  let private eMin fmt = 1 - fmt.EMax

  let private decode (x: BitVector) =
    let fmt = formatOf x.Length
    let fracBits = fmt.Precision - 1
    let v = x.ToUInt64()
    let frac = v &&& ((1UL <<< fracBits) - 1UL)
    let allOnes = 2 * fmt.EMax + 1
    let biased = int ((v >>> fracBits) &&& uint64 allOnes)
    let isNeg = (v >>> (int x.Length - 1)) = 1UL
    if biased = allOnes && frac = 0UL then
      Infinity isNeg
    elif biased = allOnes then
      NaN((frac >>> (fracBits - 1)) = 0UL)
    elif biased = 0 then
      Finite(isNeg, BigInteger frac, eMin fmt - fracBits)
    else
      let mag = BigInteger(frac ||| (1UL <<< fracBits))
      Finite(isNeg, mag, biased - fmt.EMax - fracBits)

  let private encode rt isNeg (biased: int) (frac: BigInteger) =
    let fmt = formatOf rt
    let sign = if isNeg then 1UL <<< (int rt - 1) else 0UL
    let e = uint64 biased <<< (fmt.Precision - 1)
    BitVector(sign ||| e ||| uint64 frac, rt)

  /// The flags of FPSCR's order, Invalid lowest.
  let private invalid = 0x1u

  let private divideByZero = 0x2u

  let private overflow = 0x4u

  let private underflow = 0x8u

  let private inexact = 0x10u

  /// Whether a rounding of a magnitude goes away from zero.
  let private roundsUp mode isNeg (q: BigInteger) (rem: BigInteger) half =
    match mode with
    | RoundingMode.ToNearestEven ->
      rem > half || (rem = half && not rem.IsZero && not q.IsEven)
    | RoundingMode.TowardPositive ->
      not rem.IsZero && not isNeg
    | RoundingMode.TowardNegative ->
      not rem.IsZero && isNeg
    | RoundingMode.TowardZero ->
      false
    | m ->
      failwith $"ExactFloat: no {m}"

  /// What an overflow gives: an infinity, or the greatest finite number where
  /// the direction rounds toward zero.
  let private overflowed rt mode isNeg =
    let fmt = formatOf rt
    let toInfinity =
      match mode with
      | RoundingMode.ToNearestEven -> true
      | RoundingMode.TowardPositive -> not isNeg
      | RoundingMode.TowardNegative -> isNeg
      | _ -> false
    if toInfinity then
      encode rt isNeg (2 * fmt.EMax + 1) BigInteger.Zero
    else
      let frac = (BigInteger.One <<< (fmt.Precision - 1)) - BigInteger.One
      encode rt isNeg (2 * fmt.EMax) frac

  /// The significand a nonzero magnitude rounds to, the exponent of its last
  /// bit, and whether anything was rounded away.
  let private significand fmt mode isNeg (mag: BigInteger) exp =
    let p = fmt.Precision
    let top = exp + int (mag.GetBitLength()) - 1
    let lsb = max (top - (p - 1)) (eMin fmt - (p - 1))
    let shift = lsb - exp
    let q, rem, half =
      if shift <= 0 then
        mag <<< -shift, BigInteger.Zero, BigInteger.Zero
      else
        let q = mag >>> shift
        q, mag - (q <<< shift), BigInteger.One <<< (shift - 1)
    let q = if roundsUp mode isNeg q rem half then q + BigInteger.One else q
    if q = (BigInteger.One <<< p) then q >>> 1, lsb + 1, not rem.IsZero
    else q, lsb, not rem.IsZero

  /// <summary>
  /// A nonzero exact value rounded to a format in a direction, and the flags
  /// the rounding raised. Tininess is decided before rounding, as FPRound
  /// decides it, and a tiny result raises Underflow only where it is inexact.
  /// </summary>
  let private round rt mode isNeg (mag: BigInteger) exp =
    let fmt = formatOf rt
    let p = fmt.Precision
    let tiny = exp + int (mag.GetBitLength()) - 1 < eMin fmt
    let q, lsb, isInexact = significand fmt mode isNeg mag exp
    let biased =
      if q < (BigInteger.One <<< (p - 1)) then 0 else lsb + p - 1 + fmt.EMax
    let frac = q &&& ((BigInteger.One <<< (p - 1)) - BigInteger.One)
    if biased > 2 * fmt.EMax then
      overflowed rt mode isNeg, overflow ||| inexact
    elif isInexact && tiny then
      encode rt isNeg biased frac, underflow ||| inexact
    elif isInexact then
      encode rt isNeg biased frac, inexact
    else
      encode rt isNeg biased frac, 0u

  /// A signed exact value as a sign and a magnitude.
  let private signed isNeg (mag: BigInteger) = if isNeg then -mag else mag

  /// An exact sum, its sign where it is zero being the one the direction
  /// gives a sum of two numbers of opposite sign.
  let private sum mode (n1, m1, e1) (n2, m2, e2) =
    let e = min e1 e2
    let v = (signed n1 m1 <<< (e1 - e)) + (signed n2 m2 <<< (e2 - e))
    if not v.IsZero then v.Sign < 0, BigInteger.Abs v, e
    elif n1 = n2 then n1, BigInteger.Zero, e
    else mode = RoundingMode.TowardNegative, BigInteger.Zero, e

  let private product (n1, m1: BigInteger, e1) (n2, m2, e2) =
    n1 <> n2, m1 * m2, e1 + e2

  /// A magnitude to more bits than a rounding reads, a last one set where
  /// the exact value lay beyond it.
  let private sticky (q: BigInteger) (rem: BigInteger) =
    (q <<< 1) + (if rem.IsZero then BigInteger.Zero else BigInteger.One)

  let private quotient fmt (n1, m1: BigInteger, e1) (n2, m2: BigInteger, e2) =
    let k = fmt.Precision + 3 + int (m2.GetBitLength())
    let q = BigInteger.Divide(m1 <<< k, m2)
    let rem = (m1 <<< k) - q * m2
    n1 <> n2, sticky q rem, e1 - e2 - k - 1

  let rec private isqrt (n: BigInteger) (x: BigInteger) =
    let y = (x + n / x) >>> 1
    if y >= x then x else isqrt n y

  let private root fmt (isNeg, m: BigInteger, e) =
    let s0 = 2 * (fmt.Precision + 3)
    let s = if (e - s0) % 2 = 0 then s0 else s0 + 1
    let n = m <<< s
    let r = isqrt n (BigInteger.One <<< (int (n.GetBitLength()) / 2 + 1))
    isNeg, sticky r (n - r * r), (e - s) / 2 - 1

  /// An exact result, a zero keeping its sign, rounded with its flags.
  let private finish rt mode (isNeg, mag: BigInteger, exp) =
    if mag.IsZero then encode rt isNeg 0 BigInteger.Zero, 0u
    else round rt mode isNeg mag exp

  let private negate = function
    | Finite(n, m, e) -> Finite(not n, m, e)
    | Infinity n -> Infinity(not n)
    | d -> d

  let private isZero = function
    | Finite(_, m, _) -> m.IsZero
    | _ -> false

  let private isInfinite = function
    | Infinity _ -> true
    | _ -> false

  let private isSignalling = function
    | NaN true -> true
    | _ -> false

  let private isNaN = function
    | NaN _ -> true
    | _ -> false

  let private isNegative = function
    | Finite(n, _, _) | Infinity n -> n
    | NaN _ -> false

  let private triple = function
    | Finite(n, m, e) -> n, m, e
    | d -> failwith $"ExactFloat: {d} is not finite"

  /// What an addition of a and b raised, b already negated for a
  /// subtraction, where neither is a NaN.
  let private sumRaised rt mode a b =
    match a, b with
    | Infinity n1, Infinity n2 -> if n1 = n2 then 0u else invalid
    | Infinity _, _ | _, Infinity _ -> 0u
    | _ -> sum mode (triple a) (triple b) |> finish rt mode |> snd

  let private productRaised rt mode a b =
    if (isInfinite a && isZero b) || (isZero a && isInfinite b) then invalid
    elif isInfinite a || isInfinite b then 0u
    else product (triple a) (triple b) |> finish rt mode |> snd

  let private quotientRaised rt mode a b =
    let fmt = formatOf rt
    if (isInfinite a && isInfinite b) || (isZero a && isZero b) then invalid
    elif isInfinite a || isInfinite b then 0u
    elif isZero b then divideByZero
    elif isZero a then 0u
    else quotient fmt (triple a) (triple b) |> finish rt mode |> snd

  let private rootRaised rt mode a =
    match a with
    | Infinity true -> invalid
    | Infinity false -> 0u
    | Finite(true, m, _) when not m.IsZero -> invalid
    | Finite(_, m, _) when m.IsZero -> 0u
    | _ -> root (formatOf rt) (triple a) |> finish rt mode |> snd

  /// <summary>
  /// The flags FPSCR's order gives the exceptions an operation raised, for
  /// the exception query: code 0 to 4 is an addition, a subtraction, a
  /// multiplication, a division and a square root, of a and b.
  /// </summary>
  let raised mode code (a: BitVector) (b: BitVector) =
    let rt = a.Length
    let da, db = decode a, decode b
    if isSignalling da || isSignalling db then
      invalid
    elif isNaN da || isNaN db then
      0u
    else
      match code with
      | 0 -> sumRaised rt mode da db
      | 1 -> sumRaised rt mode da (negate db)
      | 2 -> productRaised rt mode da db
      | 3 -> quotientRaised rt mode da db
      | 4 -> rootRaised rt mode da
      | c -> failwith $"ExactFloat: no operation {c}"

  /// What a fused multiply-add with an infinite operand and no NaN raised:
  /// Invalid only where an infinite product meets an infinite addend of the
  /// other sign.
  let private infiniteFusedRaised dx dy dz =
    let productIsNeg = isNegative dx <> isNegative dy
    let productIsInfinite = isInfinite dx || isInfinite dy
    match dz with
    | Infinity n when productIsInfinite && n <> productIsNeg -> invalid
    | _ -> 0u

  /// The flags a fused multiply-add, x times y plus z rounded once, raised.
  let fusedRaised mode (x: BitVector) (y: BitVector) (z: BitVector) =
    let rt = x.Length
    let dx, dy, dz = decode x, decode y, decode z
    let badProduct =
      (isInfinite dx && isZero dy) || (isZero dx && isInfinite dy)
    let signalling = isSignalling dx || isSignalling dy || isSignalling dz
    if signalling || badProduct then
      invalid
    elif isNaN dx || isNaN dy || isNaN dz then
      0u
    elif isInfinite dx || isInfinite dy || isInfinite dz then
      infiniteFusedRaised dx dy dz
    else
      let p = product (triple dx) (triple dy)
      sum mode p (triple dz) |> finish rt mode |> snd

  /// <summary>
  /// An addition, a subtraction, a multiplication or a division of two
  /// finite numbers rounded in a direction; None where an operand is not
  /// finite or the divisor is zero, whose answer no rounding decides.
  /// </summary>
  let arith mode (op: BinOpType) (a: BitVector) (b: BitVector) =
    let rt = a.Length
    match decode a, decode b with
    | Finite(n1, m1, e1), Finite(n2, m2, e2) ->
      let x, y = (n1, m1, e1), (n2, m2, e2)
      match op with
      | BinOpType.FADD ->
        sum mode x y |> finish rt mode |> fst |> Some
      | BinOpType.FSUB ->
        sum mode x (not n2, m2, e2) |> finish rt mode |> fst |> Some
      | BinOpType.FMUL ->
        product x y |> finish rt mode |> fst |> Some
      | BinOpType.FDIV when not m2.IsZero ->
        quotient (formatOf rt) x y |> finish rt mode |> fst |> Some
      | _ ->
        None
    | _ ->
      None

  /// A square root of a number greater than zero, rounded in a direction;
  /// None for any other, whose answer no rounding decides.
  let sqrt mode (a: BitVector) =
    match decode a with
    | Finite(false, m, e) when not m.IsZero ->
      root (formatOf a.Length) (false, m, e)
      |> finish a.Length mode
      |> fst
      |> Some
    | _ ->
      None
