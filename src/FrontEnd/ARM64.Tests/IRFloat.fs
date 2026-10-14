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

namespace B2R2.FrontEnd.ARM64.Tests

open System
open System.Numerics
open B2R2
open B2R2.BinIR

/// The arithmetic IRFloat computes, and the exception query asks about.
type internal FloatOp =
  | Add
  | Sub
  | Mul
  | Div
  | Sqrt

/// <summary>
/// The floating-point LowUIR IRRunner evaluates, on singles and doubles held
/// as their bits. Each value rounded to nearest is the host's, which IEEE 754
/// fixes for an addition, a subtraction, a multiplication, a division, a
/// square root, a fused multiply-add and a conversion; another direction is
/// that value moved one step where the sign of the exact error says the
/// exact answer lies on the other side, the error being worked out over
/// BigInteger. The exceptions an operation raises come from the same exact
/// comparison, rounded to nearest only.
///
/// <para>A NaN an operation makes is one no processor would choose (payload
/// 0xdead), so that a lifter that does not put the architecture's NaN in its
/// place is caught. Anything else -- a width other than 32 or 64 bits, a
/// direction an operation does not take, narrowing a NaN -- fails.</para>
/// </summary>
module internal IRFloat =
  /// The NaN no processor chooses.
  let private madeNaN t =
    if t = 32<rt> then 0x7fc0deadUL else 0x7ff800000000deadUL

  let private check t =
    if t <> 32<rt> && t <> 64<rt> then failwith $"IRFloat: no {t}" else ()

  /// The value a single or a double holds, which a double holds exactly.
  let toFloat t (v: uint64) =
    check t
    if t = 32<rt> then float (BitConverter.UInt32BitsToSingle(uint32 v))
    else BitConverter.UInt64BitsToDouble v

  /// The bits of a value that the format holds exactly.
  let private ofFloat t (d: float) =
    if t = 32<rt> then uint64 (BitConverter.SingleToUInt32Bits(float32 d))
    else BitConverter.DoubleToUInt64Bits d

  let private isNaN t v = Double.IsNaN(toFloat t v)

  /// Whether a NaN is a signalling one: its top fraction bit clear.
  let private isSNaN t (v: uint64) =
    let quiet = if t = 32<rt> then 1UL <<< 22 else 1UL <<< 51
    isNaN t v && v &&& quiet = 0UL

  /// A finite double as m * 2^e, exactly.
  let private dyadic (d: float) =
    let bits = BitConverter.DoubleToInt64Bits d
    let biased = int ((bits >>> 52) &&& 0x7ffL)
    let frac = bits &&& 0xfffffffffffffL
    let m = if biased = 0 then frac else frac ||| (1L <<< 52)
    let e = if biased = 0 then -1074 else biased - 1075
    (if bits < 0L then BigInteger(-m) else BigInteger m), e

  /// The sign of x - y, for two exact values.
  let private compare (mx: BigInteger, ex) (my: BigInteger, ey) =
    let e = min ex ey
    BigInteger.Compare(mx <<< (ex - e), my <<< (ey - e)) |> sign

  let private add (ma: BigInteger, ea) (mb: BigInteger, eb) =
    let e = min ea eb
    (ma <<< (ea - e)) + (mb <<< (eb - e)), e

  let private mul (ma: BigInteger, ea) (mb: BigInteger, eb) =
    ma * mb, ea + eb

  let private neg (m: BigInteger, e) = -m, e

  let private magnitude (m: BigInteger, e) = BigInteger.Abs m, e

  /// The answer rounded to nearest, in the format.
  let private nearest t op (a: float) (b: float) =
    match t, op with
    | 64<rt>, Add -> a + b
    | 64<rt>, Sub -> a - b
    | 64<rt>, Mul -> a * b
    | 64<rt>, Div -> a / b
    | 64<rt>, Sqrt -> Math.Sqrt a
    | _, Add -> float (float32 a + float32 b)
    | _, Sub -> float (float32 a - float32 b)
    | _, Mul -> float (float32 a * float32 b)
    | _, Div -> float (float32 a / float32 b)
    | _, Sqrt -> float (MathF.Sqrt(float32 a))

  /// The sign of the exact answer minus a finite one rounded to nearest.
  let private finiteError op a b r =
    let da, db, dr = dyadic a, dyadic b, dyadic r
    match op with
    | Add -> compare (add da db) dr
    | Sub -> compare (add da (neg db)) dr
    | Mul -> compare (mul da db) dr
    | Div -> compare da (mul dr db) * sign b
    | Sqrt -> compare da (mul dr dr)

  /// The sign of the exact answer of finite operands minus the one rounded
  /// to nearest, which may be the infinity it overflowed to.
  let private errorSign op a b (r: float) =
    if Double.IsInfinity r then -(sign r) else finiteError op a b r

  /// The next value of the format up or down.
  let private step t up (r: float) =
    match t, up with
    | 64<rt>, true -> Math.BitIncrement r
    | 64<rt>, false -> Math.BitDecrement r
    | _, true -> float (MathF.BitIncrement(float32 r))
    | _, false -> float (MathF.BitDecrement(float32 r))

  /// A value rounded to nearest, moved to the side a direction asks for
  /// where the exact answer lies on the other side of it.
  let private directed t (mode: RoundingMode) err (r: float) =
    match mode with
    | RoundingMode.ToNearestEven -> r
    | RoundingMode.TowardPositive -> if err > 0 then step t true r else r
    | RoundingMode.TowardNegative -> if err < 0 then step t false r else r
    | RoundingMode.TowardZero when err > 0 && r < 0.0 -> step t true r
    | RoundingMode.TowardZero when err < 0 && r > 0.0 -> step t false r
    | RoundingMode.TowardZero -> r
    | m -> failwith $"IRFloat: no {m}"

  /// An exact zero sum of two values that are not both zeros of one sign
  /// is minus zero rounded toward minus infinity, and plus zero otherwise.
  let private zeroSum (mode: RoundingMode) a b (r: float) =
    let sameZero =
      a = 0.0 && b = 0.0 && Double.IsNegative a = Double.IsNegative b
    if mode = RoundingMode.TowardNegative && not sameZero then -0.0 else r

  /// A finite answer of finite operands, in the direction.
  let private finiteAnswer t mode op a b r =
    let err = errorSign op a b r
    match op with
    | Add when err = 0 && r = 0.0 -> zeroSum mode a b r
    | Sub when err = 0 && r = 0.0 -> zeroSum mode a (-b) r
    | _ -> directed t mode err r

  /// One of the five operations on operands that are not NaNs: an answer
  /// that is exact, an infinity included, is the one the host gave.
  let private compute t mode op a b =
    let r = nearest t op a b
    if Double.IsNaN r then
      madeNaN t
    elif not (Double.IsFinite a && Double.IsFinite b) then
      ofFloat t r
    elif op = Div && b = 0.0 then
      ofFloat t r
    else
      ofFloat t (finiteAnswer t mode op a b r)

  /// The arithmetic of the BinOpType it is named by, or the square root.
  let arith t mode op (a: uint64) (b: uint64) =
    check t
    if isNaN t a || (op <> Sqrt && isNaN t b) then madeNaN t
    else compute t mode op (toFloat t a) (toFloat t b)

  /// The operands of a fused multiply-add, the negations bit 0 and bit 1 of
  /// the flags ask for applied.
  let private fmaOperands t (flags: uint64) x y z =
    let a = toFloat t x
    let c = toFloat t z
    let a = if flags &&& 1UL = 0UL then a else -a
    let c = if flags &&& 2UL = 0UL then c else -c
    a, toFloat t y, c

  /// x times y plus z rounded to nearest once.
  let private nearestFma t a b c =
    if t = 64<rt> then Math.FusedMultiplyAdd(a, b, c)
    else float (MathF.FusedMultiplyAdd(float32 a, float32 b, float32 c))

  let private exactFma a b c = add (mul (dyadic a) (dyadic b)) (dyadic c)

  /// A fused answer of finite operands, in the direction.
  let private fmaAnswer t mode a b c (r: float) =
    let err =
      if Double.IsInfinity r then -(sign r)
      else compare (exactFma a b c) (dyadic r)
    if err = 0 && r = 0.0 then zeroSum mode (a * b) c r
    else directed t mode err r

  let private allFinite a b c =
    Double.IsFinite a && Double.IsFinite b && Double.IsFinite c

  /// x times y plus z rounded once (FMA32, FMA64).
  let fma t mode flags x y z =
    check t
    let a, b, c = fmaOperands t flags x y z
    let r = nearestFma t a b c
    if Double.IsNaN r then madeNaN t
    elif not (allFinite a b c) then ofFloat t r
    else ofFloat t (fmaAnswer t mode a b c r)

  /// The five exceptions in the order FPSR keeps them, Invalid lowest.
  let private flags invalid divZero overflow underflow inexact =
    let bit c n = if c then 1UL <<< n else 0UL
    bit invalid 0 ||| bit divZero 1 ||| bit overflow 2 ||| bit underflow 3
    ||| bit inexact 4

  let private invalidOnly = flags true false false false false

  /// Whether the query asks what AArch64 does: FPSR's order and tininess
  /// before rounding, in the top bits of its code, rounded to nearest.
  let private checkQuery (code: uint64) (mode: RoundingMode) =
    if code &&& 0xc0UL <> 0xc0UL || mode <> RoundingMode.ToNearestEven then
      failwith $"IRFloat: no exception query {code} in {mode}"
    else
      ()

  let private opOf code =
    match code &&& 0xfUL with
    | 0UL -> Add
    | 1UL -> Sub
    | 2UL -> Mul
    | 3UL -> Div
    | 4UL -> Sqrt
    | c -> failwith $"IRFloat: no exception query {c}"

  let private isZeroTimesInf (a: float) (b: float) =
    (a = 0.0 && Double.IsInfinity b) || (b = 0.0 && Double.IsInfinity a)

  let private isInvalid op (a: float) (b: float) =
    let infs = Double.IsInfinity a && Double.IsInfinity b
    match op with
    | Add -> infs && a <> b
    | Sub -> infs && a = b
    | Mul -> isZeroTimesInf a b
    | Div -> (a = 0.0 && b = 0.0) || infs
    | Sqrt -> a < 0.0

  /// The smallest normal value of the format, exactly.
  let private minNormal t =
    BigInteger.One, (if t = 32<rt> then -126 else -1022)

  /// Whether an exact value is non-zero and below the smallest normal.
  let private tinyValue t (m: BigInteger, e) =
    not m.IsZero && compare (magnitude (m, e)) (minNormal t) < 0

  /// Whether the exact answer is non-zero and below the smallest normal.
  let private isTiny t op a b =
    let below = mul (minNormal t) (magnitude (dyadic b))
    match op with
    | Add -> tinyValue t (add (dyadic a) (dyadic b))
    | Sub -> tinyValue t (add (dyadic a) (neg (dyadic b)))
    | Mul -> tinyValue t (mul (dyadic a) (dyadic b))
    | Div -> a <> 0.0 && compare (magnitude (dyadic a)) below < 0
    | Sqrt -> false

  /// What rounding a finite answer of finite operands raises.
  let private rounded t op a b =
    let r = nearest t op a b
    let inexact = errorSign op a b r <> 0
    let tiny = not (Double.IsInfinity r) && isTiny t op a b
    flags false false (Double.IsInfinity r) (inexact && tiny) inexact

  let private raisedBy t op a b =
    if isInvalid op a b then
      invalidOnly
    elif op = Div && b = 0.0 && Double.IsFinite a then
      flags false true false false false
    elif not (Double.IsFinite a && Double.IsFinite b) then
      0UL
    else
      rounded t op a b

  /// The exception query of one operation (FEXC32, FEXC64): the IEEE
  /// exceptions it raises.
  let exceptions t mode (code: uint64) a b =
    check t
    checkQuery code mode
    let op = opOf code
    let unary = op = Sqrt
    if isSNaN t a || (not unary && isSNaN t b) then invalidOnly
    elif isNaN t a || (not unary && isNaN t b) then 0UL
    else raisedBy t op (toFloat t a) (toFloat t b)

  /// What rounding a fused multiply-add of finite operands raises.
  let private fusedRounded t a b c =
    let r = nearestFma t a b c
    let exact = exactFma a b c
    let inexact = Double.IsInfinity r || compare exact (dyadic r) <> 0
    let tiny = not (Double.IsInfinity r) && tinyValue t exact
    flags false false (Double.IsInfinity r) (inexact && tiny) inexact

  /// Whether the product of a fused multiply-add is an infinity and the
  /// addend one of the other sign.
  let private cancelsInfinity (a: float) b (c: float) =
    Double.IsInfinity(a * b) && Double.IsInfinity c && a * b <> c

  /// What a fused multiply-add raised, as FPMulAdd raises it: Invalid for a
  /// zero times an infinity whatever is added, even a quiet NaN.
  let fusedExceptions t mode (fl: uint64) x y z =
    check t
    checkQuery fl mode
    let a, b, c = fmaOperands t fl x y z
    let anySNaN = isSNaN t x || isSNaN t y || isSNaN t z
    if anySNaN || isZeroTimesInf a b then invalidOnly
    elif isNaN t x || isNaN t y || isNaN t z then 0UL
    elif cancelsInfinity a b c then invalidOnly
    elif not (allFinite a b c) then 0UL
    else fusedRounded t a b c

  /// The comparison of the RelOpType it is named by; one with a NaN is
  /// unordered, true only for FNEQ.
  let relation (op: RelOpType) t a b =
    let a, b = toFloat t a, toFloat t b
    match op with
    | RelOpType.FEQ -> a = b
    | RelOpType.FNEQ -> a <> b
    | RelOpType.FGT -> a > b
    | RelOpType.FGE -> a >= b
    | RelOpType.FLT -> a < b
    | RelOpType.FLE -> a <= b
    | _ -> failwith $"IRFloat: no {op}"

  /// A number rounded to an integral one in a direction.
  let private integral (mode: RoundingMode) (d: float) =
    match mode with
    | RoundingMode.ToNearestEven -> Math.Round(d, MidpointRounding.ToEven)
    | RoundingMode.ToNearestAway -> Math.Round(d, MidpointRounding.AwayFromZero)
    | RoundingMode.TowardNegative -> Math.Floor d
    | RoundingMode.TowardPositive -> Math.Ceiling d
    | RoundingMode.TowardZero -> Math.Truncate d
    | m -> failwith $"IRFloat: no {m}"

  /// A value rounded to an integral one of its format.
  let roundToIntegral t mode v =
    let d = toFloat t v
    if Double.IsNaN d then madeNaN t else ofFloat t (integral mode d)

  /// <summary>
  /// A conversion to an integer of the given width, rounded in the
  /// direction: MIN_INT where the value has none the width holds, a NaN
  /// included, as CastKind.FloatToSInt says.
  /// </summary>
  let toSInt t (dst: RegType) mode v =
    let d = toFloat t v
    let bits = int dst
    let limit = Math.ScaleB(1.0, bits - 1)
    let i = if Double.IsNaN d then nan else integral mode d
    if Double.IsNaN i || i >= limit || i < -limit then 1UL <<< (bits - 1)
    elif bits = 64 then uint64 (int64 i)
    else uint64 (int64 i) &&& ((1UL <<< bits) - 1UL)

  /// An integer, exact as a BigInteger, rounded into the format: to nearest
  /// by the host's conversion, which rounds once, and then moved.
  let private ofInteger t mode (exact: BigInteger) (r: float) =
    let err = compare (exact, 0) (dyadic r)
    directed t mode err r |> ofFloat t

  /// A signed integer of the given width converted to the format.
  let ofSInt (src: RegType) t mode (v: uint64) =
    check t
    let x = int64 (v <<< (64 - int src)) >>> (64 - int src)
    let r = if t = 32<rt> then float (float32 x) else float x
    ofInteger t mode (BigInteger x) r

  /// An unsigned integer past 2^63 rounded to nearest: halved, its low bit
  /// kept as a sticky one, which a signed conversion then rounds as the
  /// whole value would be, the format being narrower than 62 bits.
  let private ofLargeUInt t (x: uint64) =
    let half = int64 ((x >>> 1) ||| (x &&& 1UL))
    if t = 32<rt> then float (float32 half * 2.0f) else float half * 2.0

  /// An unsigned integer of the given width converted to the format.
  let ofUInt (src: RegType) t mode (v: uint64) =
    check t
    let x = if int src = 64 then v else v &&& ((1UL <<< int src) - 1UL)
    let r =
      if x >= (1UL <<< 63) then ofLargeUInt t x
      elif t = 32<rt> then float (float32 (int64 x))
      else float (int64 x)
    ofInteger t mode (BigInteger x) r

  /// A double narrowed to a single in the direction.
  let private narrow mode (d: float) =
    let r = float (float32 d)
    let err =
      if Double.IsInfinity r && Double.IsFinite d then -(sign r)
      elif Double.IsInfinity r then 0
      else compare (dyadic d) (dyadic r)
    directed 32<rt> mode err r |> ofFloat 32<rt>

  /// A single NaN widened to a double, its payload kept and made quiet.
  let private widenNaN (v: uint64) =
    ((v &&& 0x80000000UL) <<< 32) ||| 0x7ff8000000000000UL
    ||| ((v &&& 0x3fffffUL) <<< 29)

  /// <summary>
  /// A value converted to another format: a widening is exact, and widens a
  /// NaN's payload and makes it quiet, as IEEE 754 asks; a narrowing rounds
  /// in the direction, and fails on a NaN, which a lifter narrows itself.
  /// </summary>
  let cast src dst mode (v: uint64) =
    let d = toFloat src v
    match src, dst with
    | 32<rt>, 64<rt> when Double.IsNaN d -> widenNaN v
    | 32<rt>, 64<rt> -> ofFloat 64<rt> d
    | 64<rt>, 32<rt> when Double.IsNaN d -> failwith "IRFloat: no NaN narrowed"
    | 64<rt>, 32<rt> -> narrow mode d
    | _ -> failwith $"IRFloat: no cast from {src} to {dst}"
