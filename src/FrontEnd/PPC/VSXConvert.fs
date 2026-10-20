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
/// Lifts the VSX conversions ISA 2.07 to 3.1 added: between the vector
/// single and double formats, from either to the integers and back, and to
/// and from half precision and bfloat16.
///
/// A conversion that can round is the IR's own cast, which the evaluator
/// rounds in the direction FPSCR[RN] names, except where the target is half
/// precision or bfloat16, which the IR has no type for: those go out as the
/// named calls FCVTHALF and FCVTBF16 (specified in lanes/X.md), the
/// direction passed with them. A conversion that cannot round -- from half
/// precision or bfloat16, which every wider format holds exactly -- is spelt
/// out in the IR.
/// </summary>
module internal B2R2.FrontEnd.PPC.VSXConvert

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.VSXLifter
open B2R2.FrontEnd.PPC.VSXFloat

/// The rounding direction FPSCR[RN] names, as the eight-bit argument the
/// named conversions take: 0 to nearest, 1 toward zero, 2 toward +Inf, 3
/// toward -Inf.
let private roundingArg bld =
  AST.zext 8<rt> (AST.extract (regVar bld Register.FPSCR) 2<rt> 0)

/// Two to the -24, the weight of a half-precision denormal's last bit, in
/// a lane.
let private halfUlp lane =
  if lane.Width = 32<rt> then numU64 0x33800000UL lane.Width
  else numU64 0x3e70000000000000UL lane.Width

/// <summary>
/// A half-precision value widened exactly into a lane. A normal value, an
/// infinity and a NaN move their fields, a signalling NaN coming back quiet;
/// a denormal one is its fraction times two to the -24, which the IR's own
/// conversion and multiply compute exactly, and so is a zero.
/// </summary>
let widenHalf lane (h: Expr) =
  let rt = lane.Width
  let exp = AST.extract h 5<rt> 10
  let frac = AST.zext rt (AST.extract h 10<rt> 0)
  let sign = AST.zext rt (AST.extract h 1<rt> 15) << numI32 (int rt - 1) rt
  let moved = frac << numI32 (lane.FracBits - 10) rt
  let ones = (AST.num1 rt << numI32 lane.ExpBits rt) .- AST.num1 rt
  let top = ones << numI32 lane.FracBits rt
  let quiet = AST.num1 rt << numI32 (lane.FracBits - 1) rt
  let rebias = numI32 ((1 <<< (lane.ExpBits - 1)) - 16) rt
  let normal = ((AST.zext rt exp .+ rebias) << numI32 lane.FracBits rt) .| moved
  let isInf = frac == AST.num0 rt
  let special = AST.ite isInf (top .| moved) (top .| moved .| quiet)
  let small = AST.fmul (AST.cast CastKind.UIntToFloat rt frac) (halfUlp lane)
  let finite = AST.ite (exp == AST.num0 5<rt>) small normal
  sign .| AST.ite (exp == numI32 31 5<rt>) special finite

/// A double of the same class as a half, for FPRF: its exact widening, but
/// for a half denormal, which widens to a normal double, a double denormal
/// of its sign.
let private classOfHalf (h: Expr) =
  let tiny =
    (AST.extract h 5<rt> 10 == AST.num0 5<rt>)
    .& (AST.extract h 10<rt> 0 != AST.num0 10<rt>)
  let sign = AST.zext 64<rt> (AST.extract h 1<rt> 15) << numI32 63 64<rt>
  AST.ite tiny (sign .| AST.num1 64<rt>) (widenHalf double h)

/// A float narrowed to half precision in the direction FPSCR[RN] names.
let private toHalf bld (x: Expr) =
  AST.app "FCVTHALF" [ x; roundingArg bld ] 16<rt>

/// <summary>
/// xscvhpdp and xscvdphp: the half in halfword 3 of xB widened to a double
/// in doubleword 0 of xT, or the double in doubleword 0 narrowed to a half
/// there, zero-extended; doubleword 1 is cleared and FPRF set to the
/// result's class as represented in its own format.
/// </summary>
let scalarHalf ins (bld: ILowUIRBuilder) toDouble =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (bh, _) = vsrOf bld o2
    let half = tmpVar bld 16<rt>
    if toDouble then
      dh := widenHalf double (AST.xtlo 16<rt> bh)
      dl := AST.num0 64<rt>
      setFPRF bld dh
    else
      half := toHalf bld bh
      dh := AST.zext 64<rt> half
      dl := AST.num0 64<rt>
      setFPRF bld (classOfHalf half)
  }

/// xvcvhpsp: the half in the low halfword of each word, widened.
let halfToSingle (_: Lane) xs = widenHalf single (AST.xtlo 16<rt> (one xs))

/// xvcvsphp: each single narrowed to a half in its word's low halfword.
let singleToHalf bld (_: Lane) xs = AST.zext 32<rt> (toHalf bld (one xs))

/// xvcvbf16spn: the bfloat16 in the low halfword of each word moved to the
/// high one, which is the single it stands for, NaNs and all.
let bfloat16ToSingle (_: Lane) xs =
  AST.concat (AST.xtlo 16<rt> (one xs)) (AST.num0 16<rt>)

/// xvcvspbf16: each single narrowed to bfloat16 in the direction FPSCR[RN]
/// names, into its word's low halfword.
let singleToBfloat16 bld (_: Lane) xs =
  let bf = AST.app "FCVTBF16" [ one xs; roundingArg bld ] 16<rt>
  AST.zext 32<rt> bf

/// A double rounded to a single, a NaN by its own bits -- quieted, keeping
/// its sign and the leading 22 bits of its payload -- as the cast of a NaN is
/// left to the host.
let private narrowDouble (x: Expr) =
  let sign = AST.extract x 1<rt> 63
  let payload = AST.extract x 22<rt> 29
  let top = AST.concat sign (numU32 0xffu 8<rt>)
  let nan = AST.concat top (AST.concat (AST.num1 1<rt>) payload)
  AST.ite (isNaNOf double x) nan (AST.cast CastKind.FloatCast 32<rt> x)

/// xvcvdpsp: each double rounded to a single, in both words of its
/// doubleword.
let doubleToSingle (_: Lane) xs =
  let s = narrowDouble (one xs)
  AST.concat s s

/// xvcvspdp: the single in the high word of each doubleword, widened.
let singleToDouble (_: Lane) xs =
  AST.cast CastKind.FloatCast 64<rt> (AST.xthi 32<rt> (one xs))

/// <summary>
/// Where a conversion to an integer saturates: the doubles beyond which it
/// does and the integers it answers there, one row of the ISA's tables. A
/// NaN answers with the low end, the smallest signed value or zero.
/// </summary>
let private limits isWord isSigned =
  match isWord, isSigned with
  | true, true ->
    let lo, hi = 0xc1e0000000000000UL, 0x41dfffffffc00000UL
    struct (lo, hi, 0xffffffff80000000UL, 0x000000007fffffffUL)
  | true, false ->
    struct (0UL, 0x41efffffffe00000UL, 0UL, 0x00000000ffffffffUL)
  | false, true ->
    let lo, hi = 0xc3e0000000000000UL, 0x43e0000000000000UL
    struct (lo, hi, 0x8000000000000000UL, 0x7fffffffffffffffUL)
  | false, false ->
    struct (0UL, 0x43f0000000000000UL, 0UL, 0xffffffffffffffffUL)

/// The conversion itself, before the limits: truncation toward zero, an
/// unsigned value at or above 2^63 folded down and biased back.
let private truncated isSigned src =
  let toInt e = AST.floatToSInt RoundingMode.TowardZero 64<rt> e
  let twoPow63 = numU64 0x43e0000000000000UL 64<rt>
  let bias = numU64 0x8000000000000000UL 64<rt>
  let folded = toInt (AST.fsub src twoPow63) .+ bias
  if isSigned then toInt src
  else AST.ite (AST.fge src twoPow63) folded (toInt src)

/// <summary>
/// A double converted to a 64-bit or a 32-bit integer (the word in the low
/// half), truncated toward zero and saturated at the ends of the range, a
/// NaN answering with the low end, as the ISA's convert-to-integer tables
/// say.
/// </summary>
let toInteger isWord isSigned src =
  let struct (lo, hi, loValue, hiValue) = limits isWord isSigned
  let n v = numU64 v 64<rt>
  let cut = truncated isSigned src
  let inRange = AST.ite (AST.fle src (n lo)) (n loValue) cut
  let ranged = AST.ite (AST.fge src (n hi)) (n hiValue) inRange
  AST.ite (isNaNOf double src) (n loValue) ranged

/// xvcvdp[su]xds: each double to a doubleword integer.
let doubleToLong isSigned (_: Lane) xs = toInteger false isSigned (one xs)

/// xvcvdp[su]xws: each double to a word integer, in both words of its
/// doubleword.
let doubleToInt isSigned (_: Lane) xs =
  let w = AST.xtlo 32<rt> (toInteger true isSigned (one xs))
  AST.concat w w

/// xvcvsp[su]xds: the single in the high word of each doubleword to a
/// doubleword integer, through its exact double.
let singleToLong isSigned (_: Lane) xs =
  toInteger false isSigned (singleToDouble single xs)

/// xvcvsp[su]xws: each single to a word integer.
let singleToInt isSigned (_: Lane) xs =
  let d = AST.cast CastKind.FloatCast 64<rt> (one xs)
  AST.xtlo 32<rt> (toInteger true isSigned d)

/// The cast from an integer, signed or unsigned.
let private fromInt isSigned rt x =
  let kind = if isSigned then CastKind.SIntToFloat else CastKind.UIntToFloat
  AST.cast kind rt x

/// xvcv[su]xddp and xvcv[su]xwsp: each element converted to the float of its
/// own width, rounded in the direction FPSCR[RN] names.
let intToFloat isSigned (lane: Lane) xs = fromInt isSigned lane.Width (one xs)

/// xvcv[su]xdsp: each doubleword integer rounded to a single, in both words.
let longToSingle isSigned (_: Lane) xs =
  let s = fromInt isSigned 32<rt> (one xs)
  AST.concat s s

/// xvcvuxwdp: the unsigned word in the high half of each doubleword,
/// converted exactly to a double.
let uintToDouble (_: Lane) xs =
  fromInt false 64<rt> (AST.zext 64<rt> (AST.xthi 32<rt> (one xs)))
