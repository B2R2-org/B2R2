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
/// The floating-point instructions Armv8 added to AArch32: VRINTA, VRINTN,
/// VRINTP, VRINTM, VRINTZ, VRINTR and VRINTX; VCVTA, VCVTN, VCVTP and VCVTM;
/// VMAXNM and VMINNM; the four VSELs; and VJCVT. Each has a VFP form over one
/// register and, but for VSEL, VRINTR and VJCVT, an Advanced SIMD form over
/// lanes, which reads the standard FPSCR value rather than FPSCR.
/// </summary>
module internal B2R2.FrontEnd.ARM32.FPv8Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.LiftingUtils
open B2R2.FrontEnd.ARM32.GeneralLifter
open B2R2.FrontEnd.ARM32.FloatingPoint
open B2R2.FrontEnd.ARM32.FPConversion
open B2R2.FrontEnd.ARM32.FPLifter

/// How an instruction rounds: in a direction it names, to the nearest with a
/// tie away from zero, or as the controls say.
type Rounding =
  | Directed of RoundingMode
  | TiesAway
  | Current

/// The four directions an instruction can name.
let toNearest = Directed RoundingMode.ToNearestEven

let towardPlus = Directed RoundingMode.TowardPositive

let towardMinus = Directed RoundingMode.TowardNegative

let towardZero = Directed RoundingMode.TowardZero

/// The type of the floating-point value an instruction reads.
let private sourceType (ins: Instruction) =
  match ins.SIMDTyp with
  | Some(OneDT t) | Some(TwoDT(_, t)) -> t
  | _ -> raise InvalidOperandException

/// The width of that value.
let private sourceSize ins =
  match sourceType ins with
  | SIMDTypF64 -> 64<rt>
  | SIMDTypF32 -> 32<rt>
  | _ -> raise <| NotImplementedIRException "half-precision lanes"

/// Whether an instruction is the Advanced SIMD form: a quadword, or a
/// doubleword of singles. The VFP form names a single, or a double.
let private isVector (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(d, _) | ThreeOperands(d, _, _) ->
    isQuad d || (not (isSingle d) && sourceType ins <> SIMDTypF64)
  | _ ->
    false

/// One half in the format given.
let private oneHalf sz =
  if sz = 64<rt> then numU64 0x3FE0000000000000UL 64<rt>
  else numU32 0x3F000000u 32<rt>

/// <summary>
/// The integral value nearest e with a tie going away from zero. It is
/// chosen between the neighbours above and below on the fraction left by
/// truncating, rather than named as a direction, because an evaluator with
/// no notion of that direction rounds it to even.
/// </summary>
let private tieAway bld sz e =
  let trunc = AST.roundToIntegral RoundingMode.TowardZero sz e
  let frac = tmpVar bld sz
  append bld { frac := AST.fsub e trunc }
  let up = AST.roundToIntegral RoundingMode.TowardPositive sz e
  let down = AST.roundToIntegral RoundingMode.TowardNegative sz e
  let half = oneHalf sz
  let positive = AST.ite (AST.fge frac half) up down
  let negative = AST.ite (AST.fle frac (half .| signOf sz)) down up
  AST.ite (AST.xthi 1<rt> e) negative positive

/// The integral value of e, rounded as an instruction rounds it.
let private integral bld ctl rounding sz e =
  match rounding with
  | Directed mode -> AST.roundToIntegral mode sz e
  | TiesAway -> tieAway bld sz e
  | Current -> inForce ctl (AST.cast CastKind.RoundToIntegral sz e)

/// <summary>
/// FPRoundInt: a NaN processed, and anything else rounded to an integral
/// value of its own format -- an infinity and a zero come back as they went
/// in, and a value that rounds to zero keeps its sign. A signalling NaN
/// raises Invalid, and only the exact form, VRINTX, raises Inexact.
/// </summary>
let private roundInt bld ctl rounding exact sz e =
  let e = fpFlushIn bld ctl sz e
  let rounded = integral bld ctl rounding sz e
  let res = tmpVar bld sz
  let nan = isNaN sz e
  append bld {
    res := rounded
    res := AST.ite nan (fpProcessNaN bld ctl sz e) res
  }
  let inexact = if exact then AST.not nan .& (res != e) else fpNone
  fpRecord bld (fpBits (isSNaN sz e) fpNone fpNone fpNone inexact)
  res

/// Every lane of an Advanced SIMD operation of one operand, of the width the
/// data type names.
let private lanes1 (ins: Instruction) bld lane =
  let struct (dst, src) = getTwoOprs ins
  let sz = sourceSize ins
  readLanes bld (int sz) src |> Array.map (lane sz) |> writeLanes bld dst

/// Every lane of an Advanced SIMD operation of two operands.
let private lanes2 (ins: Instruction) bld lane =
  let struct (dst, src1, src2) = getThreeOprs ins
  let sz = sourceSize ins
  let a = readLanes bld (int sz) src1
  let b = readLanes bld (int sz) src2
  Array.map2 (lane sz) a b |> writeLanes bld dst

/// A VFP operation of one operand.
let private scalar1 (ins: Instruction) bld op =
  let struct (dst, src) = transTwoOprs ins bld
  let r = op (sourceSize ins) src
  append bld { dst := r }

/// A VFP operation of two operands.
let private scalar2 (ins: Instruction) bld op =
  let struct (dst, a, b) = transThreeOprs ins bld
  let r = op (sourceSize ins) a b
  append bld { dst := r }

/// <summary>
/// VRINTA, VRINTN, VRINTP, VRINTM and VRINTZ round in the direction each
/// names, VRINTR and VRINTX as FPSCR.RMode says -- and in an Advanced SIMD
/// VRINTX, to nearest, as the standard value says. Only VRINTX is exact
/// (DDI0487F.c F6.1.199-F6.1.211).
/// </summary>
let vrint ins bld rounding exact =
  conditional ins bld (fun () ->
    if isVector ins then
      lanes1 ins bld (roundInt bld StandardValue rounding exact)
    else
      scalar1 ins bld (roundInt bld FPSCRValue rounding exact))

/// <summary>
/// VCVTA, VCVTN, VCVTP and VCVTM: FPToFixed with no fraction bits, rounding
/// in the direction each names, signed or unsigned as the data type says
/// (F6.1.65, F6.1.66 and F6.1.69-F6.1.74).
/// </summary>
let vcvtRounding (ins: Instruction) bld rounding =
  let unsigned =
    match ins.SIMDTyp with
    | Some(TwoDT(SIMDTypU32, _)) -> true
    | _ -> false
  let toInt ctl sz e =
    let round sz e = integral bld ctl rounding sz e
    fpToFixedBy bld ctl sz 32 0 unsigned round e
  conditional ins bld (fun () ->
    if isVector ins then lanes1 ins bld (toInt StandardValue)
    else scalar1 ins bld (toInt FPSCRValue))

/// <summary>
/// FPMaxNum and FPMinNum: a quiet NaN against a number counts as the
/// infinity that loses, so the number wins; anything else is FPMax's or
/// FPMin's answer.
/// </summary>
let private maxMinNum bld ctl isMax sz a b =
  let losing = fpInfinity sz (if isMax then AST.b1 else AST.b0)
  let qa = isQNaN sz a
  let qb = isQNaN sz b
  let a' = AST.ite (qa .& AST.not qb) losing a
  let b' = AST.ite (qb .& AST.not qa) losing b
  fpMaxMin bld ctl sz isMax a' b'

/// VMAXNM and VMINNM (F6.1.117 and F6.1.120).
let vmaxminnm ins bld isMax =
  conditional ins bld (fun () ->
    if isVector ins then lanes2 ins bld (maxMinNum bld StandardValue isMax)
    else scalar2 ins bld (maxMinNum bld FPSCRValue isMax))

/// <summary>
/// VSELEQ, VSELGE, VSELGT and VSELVS: the first source where the condition
/// holds on the flags and the second where it does not, moved as bits. A
/// half is moved into the bottom of the single and the top cleared
/// (F6.1.223).
/// </summary>
let vsel (ins: Instruction) bld cond =
  lift bld ins {
    let struct (d, n, m) = transThreeOprs ins bld
    let chosen = AST.ite (conditionPassed bld cond) n m
    match ins.SIMDTyp with
    | Some(OneDT SIMDTypF16) -> d := AST.zext 32<rt> (AST.xtlo 16<rt> chosen)
    | _ -> d := chosen
  }

/// <summary>
/// The integer part of a double, as a magnitude, with everything that has no
/// integer part answering zero. The significand moves by the exponent: below
/// two to the zero nothing is kept, up to 2^52 it moves right and above that
/// left; past 2^84 every bit that would reach the low word is a zero the
/// shift brought in, so the answer is zero, and the counts are clamped for
/// the same reason.
/// </summary>
let private jsIntegerPart bld s =
  let e = (s >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>
  let full = tmpVar bld 64<rt>
  let mant = s .& numU64 0xfffffffffffffUL 64<rt>
  append bld { full := numU64 0x10000000000000UL 64<rt> .| mant }
  let unbiased = e .- numI32 1023 64<rt>
  let capped n = AST.ite (n .> numI32 63 64<rt>) (numI32 63 64<rt>) n
  let rightBy = capped (numI32 52 64<rt> .- unbiased)
  let leftBy = capped (unbiased .- numI32 52 64<rt>)
  let small = unbiased ?< numI32 52 64<rt>
  let shifted = AST.ite small (full >> rightBy) (full << leftBy)
  let tiny = unbiased ?< AST.num0 64<rt>
  let huge = unbiased ?>= numI32 84 64<rt>
  let gone = tiny .| huge .| (e == numI32 0x7ff 64<rt>)
  let magnitude = tmpVar bld 64<rt>
  append bld { magnitude := AST.ite gone (AST.num0 64<rt>) shifted }
  let kept = (full >> rightBy) << rightBy
  let dropped = AST.ite small (full .- kept) (AST.num0 64<rt>)
  struct (magnitude, dropped, gone)

/// <summary>
/// VJCVT: JavaScript's ToInt32 of a double, which truncates and wraps modulo
/// two to the thirty-second rather than saturating (F6.1.99). FPSCR's N, C
/// and V are cleared and Z says the conversion was exact: an integer that
/// fitted, and not a minus zero. Invalid is raised for a NaN, an infinity or
/// an integer that does not fit, and otherwise Inexact for a fraction
/// dropped.
/// </summary>
let vjcvt (ins: Instruction) bld =
  conditional ins bld (fun () ->
    let struct (d, given) = transTwoOprs ins bld
    let s = fpFlushIn bld FPSCRValue 64<rt> given
    let struct (magnitude, dropped, gone) = jsIntegerPart bld s
    let negative = AST.xthi 1<rt> s
    let signed = AST.ite negative (AST.neg magnitude) magnitude
    let isZero = (s .& magnitudeOf 64<rt>) == AST.num0 64<rt>
    let bound = numU64 0x80000000UL 64<rt>
    let inRange = AST.ite negative (magnitude .<= bound) (magnitude .< bound)
    let biased = (s >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>
    let noInteger = (biased .>= numI32 (1023 + 64) 64<rt>) .| AST.not inRange
    let fitted = (dropped == AST.num0 64<rt>) .& AST.not (noInteger .| gone)
    let wasZero = (given .& magnitudeOf 64<rt>) == AST.num0 64<rt>
    let exact = AST.ite isZero (AST.not negative .& wasZero) fitted
    let invalid = noInteger .| isNaN 64<rt> s .| isInfinity 64<rt> s
    let inexact = AST.not invalid .& AST.not exact .& AST.not isZero
    fpRecord bld (fpBits invalid fpNone fpNone fpNone inexact)
    let fpscr = regVar bld R.FPSCR
    let z = AST.zext 32<rt> exact << numI32 30 32<rt>
    append bld { fpscr := (fpscr .& numU32 0x0fffffffu 32<rt>) .| z }
    append bld { d := AST.xtlo 32<rt> signed })
