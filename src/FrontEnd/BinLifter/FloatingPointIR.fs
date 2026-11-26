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

/// Builds ordinary LowUIR for floating-point operations and their exceptions.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinLifter.FloatingPointIR

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter.LiftingUtils

/// Maps an ISA's rounding field to LowUIR's rounding mode encoding.
let rounding field modes =
  let rt = Expr.typeOf field
  let nearest = AST.roundingMode RoundingMode.ToNearestEven
  let pick (n, mode) next =
    AST.ite (field == numI32 n rt) (AST.roundingMode mode) next
  List.foldBack pick modes nearest

/// Rounding fields ordered as nearest, zero, plus infinity, minus infinity.
let ieeeRounding field =
  rounding field
    [ 1, RoundingMode.TowardZero
      2, RoundingMode.TowardPositive
      3, RoundingMode.TowardNegative ]

let private format = function
  | 16<rt> -> struct (10, 15)
  | 32<rt> -> struct (23, 127)
  | 64<rt> -> struct (52, 1023)
  | _ -> raise InvalidRegTypeException

let private signMask sz = numU64 (1UL <<< (int sz - 1)) sz

let private magnitude sz x =
  x .& numU64 ((1UL <<< (int sz - 1)) - 1UL) sz

let private powerOfTwo sz n =
  let struct (fraction, bias) = format sz
  numU64 (uint64 (n + bias) <<< fraction) sz

let private infinity sz =
  let struct (_, bias) = format sz
  powerOfTwo sz (bias + 1)

let private isNaN sz x = magnitude sz x .> infinity sz

/// Whether the input is an IEEE 754 signalling NaN.
let isSignalling sz x =
  let struct (fraction, _) = format sz
  let quiet = numU64 (1UL <<< (fraction - 1)) sz
  isNaN sz x .& ((x .& quiet) == AST.num0 sz)

let private isInfinity sz x = magnitude sz x == infinity sz

let private isZero sz x = magnitude sz x == AST.num0 sz

/// IEEE exceptions in the order Invalid, Divide-by-zero, Overflow, Underflow,
/// Inexact, from the highest to the lowest bit.
let private exceptions invalid divZero overflow underflow inexact =
  [ invalid; divZero; overflow; underflow; inexact ]
  |> List.reduce AST.concat
  |> AST.zext 32<rt>

/// The same exceptions with the two IEEE tininess-detection policies.
type Exceptions =
  { BeforeRounding: Expr
    AfterRounding: Expr }

let private withTininess invalid divZero overflow inexact before after =
  let flags tiny =
    let underflow = inexact .& AST.not overflow .& tiny
    exceptions invalid divZero overflow underflow inexact
  { BeforeRounding = flags before; AfterRounding = flags after }

/// The arithmetic operations that use binary floating-point exception flags.
[<RequireQualifiedAccess>]
type Arithmetic =
  | Add
  | Sub
  | Mul
  | Div
  | Sqrt

let private arithmetic op a b =
  match op with
  | Arithmetic.Add -> AST.fadd a b
  | Arithmetic.Sub -> AST.fsub a b
  | Arithmetic.Mul -> AST.fmul a b
  | Arithmetic.Div -> AST.fdiv a b
  | Arithmetic.Sqrt -> AST.fsqrt a

let private directed mode x = AST.roundCtrl (AST.roundingMode mode) x

let private beyondRange sz op a b =
  let half x = AST.fmul x (powerOfTwo sz -1)
  let scaled =
    match op with
    | Arithmetic.Add | Arithmetic.Sub -> arithmetic op (half a) (half b)
    | Arithmetic.Mul | Arithmetic.Div -> arithmetic op (half a) b
    | Arithmetic.Sqrt -> AST.num0 sz
  let struct (_, bias) = format sz
  magnitude sz (directed RoundingMode.TowardZero scaled)
  .>= powerOfTwo sz bias

/// Re-evaluates the operation in directed modes to observe rounding loss and
/// tininess, as in the static AArch64 lifter.
let arithmeticExceptions bld mode op (a, b) =
  let sz = Expr.typeOf a
  let struct (answer, towardZero) = tmpVars2 bld sz
  let struct (invalid, divZero, normal) = tmpVars3 bld 1<rt>
  let struct (overflow, inexact) = tmpVars2 bld 1<rt>
  let nanIn = isNaN sz a .| isNaN sz b
  let infiniteIn = isInfinity sz a .| isInfinity sz b
  let arith = arithmetic op a b
  let up = directed RoundingMode.TowardPositive arith
  let down = directed RoundingMode.TowardNegative arith
  let zeroDivisor = if op = Arithmetic.Div then isZero sz b else AST.b0
  let struct (_, bias) = format sz
  let tiny value = magnitude sz value .< powerOfTwo sz (1 - bias)
  append bld {
    answer := AST.roundCtrl mode arith
    towardZero := directed RoundingMode.TowardZero arith
    invalid :=
      isSignalling sz a .| isSignalling sz b
      .| (isNaN sz answer .& AST.not nanIn)
    divZero := zeroDivisor .& AST.not (infiniteIn .| invalid .| nanIn)
    normal := AST.not (invalid .| divZero .| infiniteIn .| nanIn)
    overflow :=
      normal .& (isInfinity sz answer .| beyondRange sz op a b)
    inexact := normal .& (overflow .| AST.not (AST.feq up down))
  }
  withTininess invalid divZero overflow inexact (tiny towardZero) (tiny answer)

/// Invalid and Inexact for a conversion to a signed or unsigned integer.
let integerExceptions mode unsigned width value =
  let sz = Expr.typeOf value
  let upper = powerOfTwo sz (if unsigned then width else width - 1)
  let lower = if unsigned then AST.num0 sz else upper <+> signMask sz
  let rounded = AST.roundCtrl mode (AST.cast CastKind.RoundToIntegral sz value)
  let valid = AST.fge rounded lower .& AST.flt rounded upper
  let inexact = valid .& AST.not (AST.feq rounded value)
  exceptions (AST.not valid) AST.b0 AST.b0 AST.b0 inexact

/// The fused result, its truncation, and the exceptions its rounding raised.
type FusedResult =
  { Value: Expr
    Truncated: Expr
    Raised: Exceptions }

let private special mode sz dst (negProduct, negAddend) (x, y, z) =
  let neg flag v = if flag then v <+> signMask sz else v
  let badProduct =
    (isInfinity sz x .& isZero sz y) .| (isZero sz x .& isInfinity sz y)
  let opposite = AST.xthi 1<rt> (neg negProduct x <+> y <+> neg negAddend z)
  let cancels =
    (isInfinity sz x .| isInfinity sz y) .& isInfinity sz z .& opposite
  let anyNaN = isNaN sz x .| isNaN sz y .| isNaN sz z
  let invalid =
    isSignalling sz x .| isSignalling sz y .| isSignalling sz z
    .| badProduct .| (cancels .& AST.not anyNaN)
  let finite t = AST.not (isInfinity sz t .| isNaN sz t)
  let addend = neg negAddend z
  let onlyAddendInfinite = isInfinity sz z .& finite x .& finite y
  let sum = AST.fadd (AST.fmul (neg negProduct x) y) addend
  let struct (fraction, _) = format sz
  let quiet = numU64 (1UL <<< (fraction - 1)) sz
  let defaultNaN = signMask sz .| infinity sz .| quiet
  let nan =
    List.foldBack (fun t rest -> AST.ite (isNaN sz t) (t .| quiet) rest)
                  [ x; y; z ] defaultNaN
  let value mode =
    let number = AST.ite onlyAddendInfinite addend (AST.roundCtrl mode sum)
    AST.ite (invalid .| anyNaN) nan number
  let zeroProduct = isZero sz x .| isZero sz y
  let exact = if sz = dst then zeroProduct else zeroProduct .& isZero sz z
  let skip = anyNaN .| isInfinity sz x .| isInfinity sz y .| isInfinity sz z
             .| exact
  let truncated = value (AST.roundingMode RoundingMode.TowardZero)
  struct (skip, value mode, truncated, invalid)

/// Scales a subnormal exactly before unpacking so nonzero significands share
/// the same leading bit. The exponent measures the significand's low bit.
let private unpack bld sz v =
  let struct (fraction, bias) = format sz
  let wide = sz * 2
  let unit = numU64 (1UL <<< fraction) sz
  let shift = if sz = 16<rt> then 11 else 64
  let sub = tmpVar bld 1<rt>
  let n = tmpVar bld sz
  let e = tmpVar bld 64<rt>
  let mag = magnitude sz v
  let scaled = AST.fmul mag (powerOfTwo sz shift)
  append bld {
    sub := mag .< unit
    n := AST.ite sub scaled mag
    e := AST.zext 64<rt> (n >> numI32 fraction sz)
  }
  let significand = AST.zext wide ((n .& (unit .- AST.num1 sz)) .| unit)
  let exponent = e .- numI32 (bias + fraction) 64<rt>
  let correction = AST.ite sub (numI32 shift 64<rt>) (AST.num0 64<rt>)
  let sigValue = AST.ite (mag == AST.num0 sz) (AST.num0 wide) significand
  struct (sigValue, exponent .- correction)

/// Shift a term right, preserving discarded bits in a sticky low bit.
let private shiftDown rt value count =
  let width = numI32 (int rt) 64<rt>
  let bounded = AST.ite (count ?> width) width count
  let clamped = AST.ite (count ?< AST.num0 64<rt>) (AST.num0 64<rt>) bounded
  let n = AST.zext rt clamped
  let lost = value .& ((AST.num1 rt << n) .- AST.num1 rt)
  (value >> n) .| AST.zext rt (lost != AST.num0 rt)

/// Align the exact product and the addend, reserving room for the carry and
/// for the sign of a difference. A zero term has no exponent to align.
let private align bld sz (struct (p, ep)) (struct (z, ez)) =
  let struct (fraction, _) = format sz
  let rt = sz * 2
  let f = fraction + 1
  let struct (gap, top) = tmpVars2 bld 64<rt>
  let productTop = ep .+ numI32 (2 * f) 64<rt>
  let addendTop = ez .+ numI32 f 64<rt>
  let topP = AST.ite (p == AST.num0 rt) addendTop productTop
  let topZ = AST.ite (z == AST.num0 rt) topP addendTop
  let placedP = p << numI32 (int rt - 2 - 2 * f) rt
  let placedZ = z << numI32 (int rt - 2 - f) rt
  append bld {
    gap := topP .- topZ
    top := AST.ite (gap ?< AST.num0 64<rt>) topZ topP .+ numI32 2 64<rt>
  }
  let product = shiftDown rt placedP (AST.num0 64<rt> .- gap)
  let addend = shiftDown rt placedZ gap
  struct (product, addend, top)

let private sum bld (p, z) (signP, signZ) =
  let rt = Expr.typeOf p
  let struct (s, mask) = tmpVars2 bld rt
  let sign = tmpVar bld 1<rt>
  let negate = AST.sext rt (signP <+> signZ)
  append bld {
    s := p .+ ((z <+> negate) .- negate)
    sign := signP <+> AST.xthi 1<rt> s
    mask := AST.sext rt (AST.xthi 1<rt> s)
    s := (s <+> mask) .- mask
  }
  struct (s, sign)

let private normalize bld s =
  let rt = Expr.typeOf s
  let struct (count, by) = tmpVars2 bld 64<rt>
  let step n =
    let empty = (s >> numI32 (int rt - n) rt) == AST.num0 rt
    append bld {
      by := AST.ite empty (numI32 n 64<rt>) (AST.num0 64<rt>)
      count := count .+ by
      s := s << AST.zext rt by
    }
  append bld { count := AST.num0 64<rt> }
  List.unfold (fun n -> if n = 0 then None else Some(n, n / 2)) (int rt / 2)
  |> List.iter step
  count

let private discardCount sz rt lead =
  let struct (fraction, bias) = format sz
  let below = numI32 (1 - bias) 64<rt> .- lead
  let past = numI32 (int rt + 1) 64<rt>
  let more = AST.ite (below ?> AST.num0 64<rt>) below (AST.num0 64<rt>)
  let count = numI32 (int rt - fraction - 1) 64<rt> .+ more
  AST.zext rt (AST.ite (count ?> past) past count)

let private roundsUp mode sign cut (kept, lost) =
  let rt = Expr.typeOf kept
  let down = mode == AST.roundingMode RoundingMode.TowardNegative
  let up = mode == AST.roundingMode RoundingMode.TowardPositive
  let truncate = mode == AST.roundingMode RoundingMode.TowardZero
  let tiesAway = mode == AST.roundingMode RoundingMode.ToNearestAway
  let guard = AST.num1 rt << (cut .- AST.num1 rt)
  let odd = AST.xtlo 1<rt> kept
  let nearest = (cut .<= numI32 (int rt) rt)
                .& ((lost .> guard) .| ((lost == guard) .& (odd .| tiesAway)))
  let directional = (down .& sign) .| (up .& AST.not sign)
  let directedMode = down .| up .| truncate
  (lost != AST.num0 rt) .& AST.ite directedMode directional nearest

let private pack sz lead rounded =
  let struct (fraction, bias) = format sz
  let e = lead .- numI32 (1 - bias) 64<rt>
  let field = AST.ite (e ?< AST.num0 64<rt>) (AST.num0 64<rt>) e
  (AST.xtlo sz field << numI32 fraction sz) .+ rounded

let private round bld mode sz (s, sign, top) =
  let struct (_, bias) = format sz
  let rt = Expr.typeOf s
  let struct (lead, cut) = struct (tmpVar bld 64<rt>, tmpVar bld rt)
  let shift = normalize bld s
  let struct (kept, lost) = tmpVars2 bld rt
  let struct (bits, truncated) = tmpVars2 bld sz
  let struct (zero, over, inexact) = tmpVars3 bld 1<rt>
  let inf = infinity sz
  let largest = inf .- AST.num1 sz
  let signed = AST.ite sign (signMask sz) (AST.num0 sz)
  let down = mode == AST.roundingMode RoundingMode.TowardNegative
  let up = mode == AST.roundingMode RoundingMode.TowardPositive
  let truncate = mode == AST.roundingMode RoundingMode.TowardZero
  let toInf = AST.not (down .| up .| truncate)
              .| (down .& sign) .| (up .& AST.not sign)
  let pastRange = lead ?> numI32 bias 64<rt>
  let increment = roundsUp mode sign cut (kept, lost)
  let rounded = AST.xtlo sz kept .+ AST.zext sz increment
  append bld {
    lead := top .- AST.num1 64<rt> .- shift
    cut := discardCount sz rt lead
    kept := s >> cut
    lost := s .& ((AST.num1 rt << cut) .- AST.num1 rt)
    zero := s == AST.num0 rt
    bits := pack sz lead rounded
    truncated := AST.ite pastRange largest (pack sz lead (AST.xtlo sz kept))
    over := AST.not zero .& (pastRange .| (bits .>= inf))
    inexact := over .| (lost != AST.num0 rt)
    bits := AST.ite over (AST.ite toInf inf largest) bits
    bits :=
      AST.ite zero (AST.ite down (signMask sz) (AST.num0 sz)) (signed .| bits)
    truncated := AST.ite zero (AST.num0 sz) (signed .| truncated)
  }
  let before = lead ?< numI32 (1 - bias) 64<rt>
  let after = magnitude sz bits .< powerOfTwo sz (1 - bias)
  struct (bits, truncated, withTininess AST.b0 AST.b0 over inexact before after)

/// Emits an exact significand multiply-add and rounds it to the given format.
/// The booleans negate the product and the addend, preserving NaN signs.
let fusedTo bld mode dst (negProduct, negAddend) (x, y, z) =
  let sz = Expr.typeOf x
  let rounding = tmpVar bld RoundingMode.modeType
  let struct (a, b, c) = tmpVars3 bld sz
  append bld {
    rounding := mode
    a := x
    b := y
    c := z
  }
  let struct (skip, specialValue, specialTrunc, invalid) =
    special rounding sz dst (negProduct, negAddend) (a, b, c)
  let struct (sigX, expX) = unpack bld sz a
  let struct (sigY, expY) = unpack bld sz b
  let product = struct (sigX .* sigY, expX .+ expY)
  let struct (p, q, top) = align bld sz product (unpack bld sz c)
  let sign flag v = AST.xthi 1<rt> v <+> (if flag then AST.b1 else AST.b0)
  let signP = sign negProduct a <+> AST.xthi 1<rt> b
  let struct (s, negative) = sum bld (p, q) (signP, sign negAddend c)
  let terms = s, negative, top
  let struct (value, truncated, raised) = round bld rounding dst terms
  let struct (isSpecial, invalidOp) = tmpVars2 bld 1<rt>
  let result = tmpVar bld dst
  let convert v = if dst = sz then v else AST.cast CastKind.FloatCast dst v
  append bld {
    isSpecial := skip
    invalidOp := invalid
    result := AST.ite isSpecial (convert specialValue) value
  }
  let specialFlags = exceptions invalidOp AST.b0 AST.b0 AST.b0 AST.b0
  let flags e = AST.ite isSpecial specialFlags e
  { Value = result
    Truncated = AST.ite isSpecial (convert specialTrunc) truncated
    Raised =
      { BeforeRounding = flags raised.BeforeRounding
        AfterRounding = flags raised.AfterRounding } }

/// Emits a fused multiply-add with a result in the operands' format.
let fused bld mode signs ((x, _, _) as operands) =
  fusedTo bld mode (Expr.typeOf x) signs operands
