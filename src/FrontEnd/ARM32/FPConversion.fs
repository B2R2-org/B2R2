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
/// The floating-point conversions of DDI0406C A2.7: between halves and
/// singles, FPHalfToSingle and FPSingleToHalf, under FPSCR.AHP as well; between
/// singles and doubles, FPSingleToDouble and FPDoubleToSingle; and between
/// floats and integers or fixed-point numbers, FPToFixed and FixedToFP. And
/// the arithmetic on halves, which is done on doubles and narrowed back.
///
/// <para>Narrowing to a half is FPRound done on the bits, since the IR has no
/// half-precision type to round into; everything else is the host's
/// conversion, with the NaN and what the conversion raised put right around
/// it.</para>
/// </summary>
module internal B2R2.FrontEnd.ARM32.FPConversion

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32.FloatingPoint

/// The position of the leading one of a half's subnormal fraction, zero to
/// nine.
let private leadingOne wSz m =
  [ 1 .. 9 ]
  |> List.fold (fun acc i ->
    AST.ite ((m >> numI32 i wSz) != AST.num0 wSz) (numI32 i wSz) acc)
    (AST.num0 wSz)

/// <summary>
/// One half widened to a single or a double, exactly: the exponent rebiased
/// and the fraction moved up, a subnormal half written as the normal number
/// it is in the wider format, and an infinity or a NaN carried across with
/// its payload. A conversion makes the NaN quiet; an operation carried out
/// in the wider format must not, or a signalling operand raises nothing.
/// </summary>
let private halfToWide quieting wSz bld h =
  let mBits, bias = if wSz = 32<rt> then 23, 127 else 52, 1023
  let sign = AST.zext wSz (h >> numI32 15 16<rt>) << numI32 (int wSz - 1) wSz
  let e = AST.zext wSz ((h >> numI32 10 16<rt>) .& numU32 0x1fu 16<rt>)
  let m = tmpVar bld wSz
  append bld { m := AST.zext wSz (h .& numU32 0x3ffu 16<rt>) }
  let up = m << numI32 (mBits - 10) wSz
  let normal = ((e .+ numI32 (bias - 15) wSz) << numI32 mBits wSz) .| up
  let infOrNaN = (numI32 (2 * bias + 1) wSz << numI32 mBits wSz) .| up
  let nan = if quieting then infOrNaN .| quietBit wSz else infOrNaN
  let special = AST.ite (m == AST.num0 wSz) infOrNaN nan
  (* the leading one of a subnormal's fraction sets the exponent: its position
     less the twenty-four the half's smallest step is *)
  let k = leadingOne wSz m
  let denExp = (k .+ numI32 (bias - 24) wSz) << numI32 mBits wSz
  let fraction = (AST.num1 wSz << numI32 mBits wSz) .- AST.num1 wSz
  let denMant = (m << (numI32 mBits wSz .- k)) .& fraction
  let subnormal =
    AST.ite (m == AST.num0 wSz) (AST.num0 wSz) (denExp .| denMant)
  let ordinary = AST.ite (e == AST.num0 wSz) subnormal normal
  sign .| AST.ite (e == numI32 31 wSz) special ordinary

/// A half with its top exponent read as the alternative format reads it -- an
/// ordinary number, (1 + m/1024) * 2^16 -- in a wider format.
let private altTopHalfToWide wSz h =
  let mBits, bias = if wSz = 32<rt> then 23, 127 else 52, 1023
  let sign = AST.zext wSz (h >> numI32 15 16<rt>) << numI32 (int wSz - 1) wSz
  let m = AST.zext wSz (h .& numU32 0x3ffu 16<rt>)
  sign .| (numI32 (16 + bias) wSz << numI32 mBits wSz)
  .| (m << numI32 (mBits - 10) wSz)

/// <summary>
/// FPHalfToSingle (A2.7), and its Armv8 widening to a double: exact, with a
/// NaN made quiet or replaced by the default one under FPSCR.DN, and Invalid
/// for a signalling one. Under FPSCR.AHP the half is the alternative format,
/// whose top exponent is an ordinary number rather than an infinity or a
/// NaN. A half is never flushed: FZ is a single's and a double's.
/// </summary>
let fpHalfToWide bld ctl wSz h =
  let ahp = altHalfPrecision bld
  let topExp = (h .& numU32 0x7c00u 16<rt>) == numU32 0x7c00u 16<rt>
  let ieee = halfToWide true wSz bld h
  let nan = AST.not ahp .& isNaN 16<rt> h
  let w = tmpVar bld wSz
  append bld {
    w := AST.ite (ahp .& topExp) (altTopHalfToWide wSz h) ieee
    w := AST.ite (nan .& defaultNaNMode bld ctl) (fpDefaultNaN wSz) w
  }
  fpInvalidOnly bld (AST.not ahp .& isSNaN 16<rt> h)
  w

/// <summary>
/// The fields of a single or a double as the narrowing reads them: its sign,
/// its biased exponent and fraction, and the significand with its leading
/// one together with the exponent it is scaled by.
/// </summary>
let private wideFields bld wSz s =
  let rt = 64<rt>
  let mBits, bias = if wSz = 32<rt> then 23, 127 else 52, 1023
  let x = tmpVar bld rt
  append bld { x := if wSz = rt then s else AST.zext rt s }
  let e = (x >> numI32 mBits rt) .& numI32 (2 * bias + 1) rt
  let m = x .& ((AST.num1 rt << numI32 mBits rt) .- AST.num1 rt)
  let struct (full, ue) = tmpVars2 bld rt
  let isSub = e == AST.num0 rt
  append bld {
    full := AST.ite isSub m ((AST.num1 rt << numI32 mBits rt) .| m)
    ue := AST.ite isSub (numI32 (1 - bias) rt) (e .- numI32 bias rt)
  }
  struct (AST.extract x 1<rt> (int wSz - 1), e, m, full, ue)

/// <summary>
/// Where a significand shifted down to a half's last place is cut, and what
/// fell off: the count, further for a value in the half's subnormal range and
/// held at sixty-two, past every bit a wider significand has; and the part
/// kept and the part lost.
/// </summary>
let private halfCut bld mBits full ue =
  let rt = 64<rt>
  let struct (drop, kept, lost) = tmpVars3 bld rt
  let below = numI32 -14 rt .- ue
  let extra = AST.ite (below ?> AST.num0 rt) below (AST.num0 rt)
  append bld {
    drop := numI32 (mBits - 10) rt .+ extra
    drop := AST.ite (drop ?> numI32 62 rt) (numI32 62 rt) drop
    kept := full >> drop
    lost := full .& ((AST.num1 rt << drop) .- AST.num1 rt)
  }
  struct (drop, kept, lost)

/// <summary>
/// Whether a cut significand goes up by one in the direction the two-bit mode
/// names: to nearest on a guard bit with anything below it or an odd last
/// place, which sends a tie to even; toward plus or minus infinity whenever
/// anything fell off and the sign points that way; toward zero never.
/// </summary>
let private halfRoundsUp bld mode sign drop kept lost =
  let rt = 64<rt>
  let halfway = AST.num1 rt << (drop .- AST.num1 rt)
  let anyLost = lost != AST.num0 rt
  let guard = (lost .& halfway) != AST.num0 rt
  let sticky = (lost .& (halfway .- AST.num1 rt)) != AST.num0 rt
  let odd = AST.xtlo 1<rt> kept
  let up = tmpVar bld 1<rt>
  append bld {
    up :=
      ((mode == numI32 0 2<rt>) .& guard .& (sticky .| odd))
      .| ((mode == numI32 1 2<rt>) .& anyLost .& AST.not sign)
      .| ((mode == numI32 2 2<rt>) .& anyLost .& sign)
  }
  up

/// <summary>
/// A finite value's bits as a half, rounded, with whether anything was lost
/// and whether it was tiny before the rounding. A normal half is its exponent
/// field plus the rounded significand with its leading one still in bit ten,
/// which is why one comes off the exponent, and a carry out of the kept part
/// walks into the exponent by itself.
/// </summary>
let private halfFinite bld mode mBits sign full ue =
  let rt = 64<rt>
  let bits = tmpVar bld rt
  let struct (drop, kept, lost) = halfCut bld mBits full ue
  let up = halfRoundsUp bld mode sign drop kept lost
  let rounded = kept .+ AST.zext rt up
  let tinyIn = (numI32 -14 rt .- ue) ?> AST.num0 rt
  let normalBits = ((ue .+ numI32 14 rt) << numI32 10 rt) .+ rounded
  append bld { bits := AST.ite tinyIn rounded normalBits }
  struct (bits, lost != AST.num0 rt, tinyIn)

/// Whether an overflow gives an infinity in the direction the mode names --
/// to nearest always, the two directed modes on their own side of zero --
/// rather than the largest finite number.
let private overflowsToInfinity mode sign =
  (mode == numI32 0 2<rt>)
  .| ((mode == numI32 1 2<rt>) .& AST.not sign)
  .| ((mode == numI32 2 2<rt>) .& sign)

/// <summary>
/// A single or a double narrowed to an IEEE half, FPRound done on the bits,
/// with what the rounding raised: Inexact, Overflow, and tininess before
/// rounding for the caller to make an underflow of where something was lost.
/// A NaN comes back quiet with the top of its payload; which NaN it is the
/// caller settles first.
/// </summary>
let private narrowToHalf bld mode wSz s =
  let rt = 64<rt>
  let mBits, bias = if wSz = 32<rt> then 23, 127 else 52, 1023
  let struct (sign, e, m, full, ue) = wideFields bld wSz s
  let struct (bits, lost, tinyIn) = halfFinite bld mode mBits sign full ue
  let over = bits .>= numI32 0x7c00 rt
  let toInf = overflowsToInfinity mode sign
  let largest = AST.ite toInf (numI32 0x7c00 rt) (numI32 0x7bff rt)
  let finite = AST.ite over largest bits
  let special = e == numI32 (2 * bias + 1) rt
  let isZ = (e == AST.num0 rt) .& (m == AST.num0 rt)
  let payload = (m >> numI32 (mBits - 10) rt) .& numI32 0x3ff rt
  let nanBits = numI32 0x7e00 rt .| payload
  let specialBits = AST.ite (m == AST.num0 rt) (numI32 0x7c00 rt) nanBits
  let magnitude =
    AST.ite special specialBits (AST.ite isZ (AST.num0 rt) finite)
  let h = tmpVar bld 16<rt>
  let struct (inexact, overflow, tiny) = tmpVars3 bld 1<rt>
  let ordinary = AST.not special .& AST.not isZ
  append bld {
    h := AST.xtlo 16<rt> ((AST.zext rt sign << numI32 15 rt) .| magnitude)
    overflow := ordinary .& over
    inexact := ordinary .& (lost .| over)
    tiny := ordinary .& tinyIn
  }
  struct (h, inexact, overflow, tiny)

/// <summary>
/// A single or a double narrowed to the ALTERNATIVE half format FPSCR.AHP
/// selects, which has no infinity and no NaN: a NaN becomes a zero of its own
/// sign and an infinity the largest magnitude, each raising Invalid, and so
/// does a number past the largest magnitude, without Inexact. Anything else
/// rounds as it does into the IEEE format. What it raised comes back as
/// FPSCR's flags.
/// </summary>
let private narrowToAltHalf bld mode wSz s =
  let rt = 64<rt>
  let mBits, bias = if wSz = 32<rt> then 23, 127 else 52, 1023
  let struct (sign, e, m, full, ue) = wideFields bld wSz s
  let struct (bits, lost, tinyIn) = halfFinite bld mode mBits sign full ue
  let special = e == numI32 (2 * bias + 1) rt
  let nan = special .& (m != AST.num0 rt)
  let isZ = (e == AST.num0 rt) .& (m == AST.num0 rt)
  let ordinary = AST.not special .& AST.not isZ
  let over = ordinary .& (bits .>= numI32 0x8000 rt)
  let largest = numI32 0x7fff rt
  let finite = AST.ite over largest (AST.ite isZ (AST.num0 rt) bits)
  let magnitude = AST.ite nan (AST.num0 rt) (AST.ite special largest finite)
  let h = tmpVar bld 16<rt>
  let struct (invalid, inexact) = tmpVars2 bld 1<rt>
  append bld {
    h := AST.xtlo 16<rt> ((AST.zext rt sign << numI32 15 rt) .| magnitude)
    invalid := special .| over
    inexact := ordinary .& AST.not over .& lost
  }
  let underflow = ordinary .& tinyIn .& inexact
  struct (h, fpBits invalid fpNone fpNone underflow inexact)

/// <summary>
/// FPSingleToHalf (A2.7), and its Armv8 narrowing from a double. The operand
/// is unpacked first, a denormal flushed under FZ; the NaN is processed, and
/// the value rounded in the direction the controls name into the format
/// FPSCR.AHP picks. FZ does not flush a half result (FPRound). What the
/// conversion raised is recorded.
/// </summary>
let fpWideToHalf bld ctl wSz src =
  let src = fpFlushIn bld ctl wSz src
  let mode = roundingMode bld ctl
  let v = tmpVar bld wSz
  let processed = fpProcessNaN bld ctl wSz src
  append bld { v := AST.ite (isNaN wSz src) processed src }
  let struct (h, inexact, overflow, tiny) = narrowToHalf bld mode wSz v
  let raised = fpBits (isSNaN wSz src) fpNone overflow (tiny .& inexact) inexact
  let struct (alt, altRaised) = narrowToAltHalf bld mode wSz src
  let ahp = altHalfPrecision bld
  fpRecord bld (AST.ite ahp altRaised raised)
  AST.ite ahp alt h

/// <summary>
/// FPSingleToDouble: exact, after the operand is unpacked and a denormal
/// flushed under FZ. A NaN keeps its payload and comes back quiet, or as the
/// default NaN under FPSCR.DN, and a signalling one raises Invalid.
/// </summary>
let fpSingleToDouble bld ctl s =
  let s = fpFlushIn bld ctl 32<rt> s
  let x = AST.zext 64<rt> s
  let sign = (x .& numU64 0x80000000UL 64<rt>) << numI32 32 64<rt>
  let payload = (x .& numU64 0x3fffffUL 64<rt>) << numI32 29 64<rt>
  let quiet = sign .| numU64 0x7ff8000000000000UL 64<rt> .| payload
  let nan = AST.ite (defaultNaNMode bld ctl) (fpDefaultNaN 64<rt>) quiet
  let w = tmpVar bld 64<rt>
  append bld {
    w := AST.ite (isNaN 32<rt> s) nan (AST.cast CastKind.FloatCast 64<rt> s)
  }
  fpInvalidOnly bld (isSNaN 32<rt> s)
  w

/// <summary>
/// What narrowing a double to a single raised. The answer widened back is
/// exact, so it is inexact where that does not give the operand. Overflow
/// and tininess are asked of the operand, which is the exact value: out of
/// range from two to the 128th whichever way the rounding went, or wherever
/// the rounding made an infinity of it; tiny below two to the -126th.
/// </summary>
let private narrowRaised bld src result =
  let struct (overflow, underflow, inexact) = tmpVars3 bld 1<rt>
  let rt = 64<rt>
  let finiteIn = AST.not (isNaN rt src .| isInfinity rt src)
  let magnitude = src .& magnitudeOf rt
  let beyond = magnitude .>= numU64 0x47f0000000000000UL rt
  let tiny = magnitude .< numU64 0x3810000000000000UL rt
  let back = AST.cast CastKind.FloatCast rt result
  append bld {
    overflow := finiteIn .& (beyond .| isInfinity 32<rt> result)
    inexact := finiteIn .& (overflow .| (back != src))
    underflow := inexact .& AST.not overflow .& tiny
  }
  fpBits (isSNaN rt src) fpNone overflow underflow inexact

/// <summary>
/// FPDoubleToSingle: the operand unpacked, a denormal flushed under FZ, and
/// rounded in the direction the controls name, a result tiny before rounding
/// flushed under FZ as well, raising Underflow alone. A NaN keeps the top of
/// its payload and comes back quiet, or as the default NaN under FPSCR.DN.
/// </summary>
let fpDoubleToSingle bld ctl d =
  let rt = 64<rt>
  let d = fpFlushIn bld ctl rt d
  let v = tmpVar bld rt
  let r = tmpVar bld 32<rt>
  let nan = isNaN rt d
  let sign = (v >> numI32 32 rt) .& numU64 0x80000000UL rt
  let payload = (v >> numI32 29 rt) .& numU64 0x7fffffUL rt
  let narrowNaN = AST.xtlo 32<rt> (sign .| numU64 0x7f800000UL rt .| payload)
  let rounded = inForce ctl (AST.cast CastKind.FloatCast 32<rt> v)
  append bld {
    v := AST.ite nan (fpProcessNaN bld ctl rt d) d
    r := AST.ite nan narrowNaN rounded
  }
  fpRecord bld (fpFlushOut bld ctl 32<rt> r (narrowRaised bld d r))
  r

/// Two to the power of k as a float of the given width, built from its
/// exponent field.
let private powerOfTwo sz k =
  if sz = 64<rt> then numU64 (uint64 (1023 + k) <<< 52) 64<rt>
  else numU64 (uint64 (127 + k) <<< 23) 32<rt>

/// The integral value in the direction a conversion rounds: toward zero where
/// it says so, and otherwise in the direction the controls name.
let private roundedToIntegral ctl towardZero sz e =
  if towardZero then AST.roundToIntegral RoundingMode.TowardZero sz e
  else inForce ctl (AST.cast CastKind.RoundToIntegral sz e)

/// <summary>
/// FPToFixed (A2.7) with the rounding given as a function from a width and
/// a value to its integral value: the operand, unpacked and scaled by two to
/// the number of fraction bits, rounded and saturated to a 16- or 32-bit
/// result, sign- or zero-extended to a word. A NaN gives zero; a NaN and a
/// value that does not fit raise Invalid, and anything else that lost a
/// fraction Inexact.
/// </summary>
let fpToFixedBy bld ctl srcSz size fbits unsigned round src =
  let src = fpFlushIn bld ctl srcSz src
  let struct (scaled, rounded) = tmpVars2 bld srcSz
  append bld { scaled := inForce ctl (AST.fmul src (powerOfTwo srcSz fbits)) }
  let r = round srcSz scaled
  append bld { rounded := r }
  let hi = powerOfTwo srcSz (if unsigned then size else size - 1)
  let lo =
    if unsigned then AST.num0 srcSz
    else signOf srcSz .| powerOfTwo srcSz (size - 1)
  let top = if unsigned then (1UL <<< size) - 1UL else (1UL <<< size - 1) - 1UL
  let bottom = if unsigned then 0UL else ~~~((1UL <<< size - 1) - 1UL)
  let nan = isNaN srcSz src
  let struct (tooHigh, tooLow) = tmpVars2 bld 1<rt>
  let value = AST.floatToSInt RoundingMode.TowardZero 64<rt> rounded
  let res = tmpVar bld 32<rt>
  append bld {
    tooHigh := AST.fge rounded hi
    tooLow := AST.flt rounded lo
    res := AST.xtlo 32<rt> value
    res := AST.ite tooLow (numU64 bottom 32<rt>) res
    res := AST.ite tooHigh (numU64 top 32<rt>) res
    res := AST.ite nan (AST.num0 32<rt>) res
  }
  let invalid = nan .| tooHigh .| tooLow
  let inexact = AST.not invalid .& AST.not (AST.feq rounded scaled)
  fpRecord bld (fpBits invalid fpNone fpNone fpNone inexact)
  res

/// FPToFixed rounding toward zero where the instruction says so, and
/// otherwise in the direction the controls name.
let fpToFixed bld ctl srcSz size fbits unsigned towardZero src =
  let round sz e = roundedToIntegral ctl towardZero sz e
  fpToFixedBy bld ctl srcSz size fbits unsigned round src

/// Whether an expression loses nothing to rounding: rounded up and down it
/// gives the same number exactly where it is representable.
let private isExact e =
  let up = AST.roundCtrl (AST.roundingMode RoundingMode.TowardPositive) e
  let down = AST.roundCtrl (AST.roundingMode RoundingMode.TowardNegative) e
  AST.feq up down

/// <summary>
/// FixedToFP (A2.7): the low <c>size</c> bits of the operand as a signed or
/// an unsigned integer, divided by two to the number of fraction bits, and
/// rounded once into a single or a double -- to nearest where the
/// instruction says so, and otherwise in the direction the controls name.
/// The division is exact, so the one rounding is the conversion's, and
/// Inexact, all it can raise, is asked of the conversion.
/// </summary>
let fixedToFP bld ctl dstSz size fbits unsigned nearest src =
  let operand = AST.xtlo (RegType.fromBitWidth size) src
  let ext = if unsigned then AST.zext else AST.sext
  let integer = AST.cast CastKind.SIntToFloat dstSz (ext 64<rt> operand)
  let scaled = AST.fdiv integer (powerOfTwo dstSz fbits)
  let r = tmpVar bld dstSz
  let ctl = if nearest then StandardValue else ctl
  append bld { r := inForce ctl scaled }
  fpRecord bld (fpBits fpNone fpNone fpNone fpNone (AST.not (isExact integer)))
  r

/// <summary>
/// A half unpacked into a double, exactly: flushed to a zero of its sign
/// under FPSCR.FZ16 where it is denormal, raising nothing, and a signalling
/// NaN left signalling, since the operation it is unpacked for decides what
/// a NaN raises.
/// </summary>
let halfToDouble bld h =
  let fz16 = AST.extract (regVar bld R.FPSCR) 1<rt> 19
  let w = tmpVar bld 64<rt>
  let flushed = AST.ite (fz16 .& isDenormal 16<rt> h) (fpZero 16<rt> h) h
  append bld { w := halfToWide false 64<rt> bld flushed }
  w

/// <summary>
/// A half unpacked into a single the same way, for FPMulAddH, which takes
/// halves into an operation on singles.
/// </summary>
let halfToSingle bld h =
  let fz16 = AST.extract (regVar bld R.FPSCR) 1<rt> 19
  let w = tmpVar bld 32<rt>
  let flushed = AST.ite (fz16 .& isDenormal 16<rt> h) (fpZero 16<rt> h) h
  append bld { w := halfToWide false 32<rt> bld flushed }
  w

/// <summary>
/// A double rounded once to a half in the direction the controls name, with
/// what the operation that made it raised: Invalid and Divide-by-zero are the
/// operation's, Inexact the operation's or the narrowing's, and Overflow and
/// Underflow the narrowing's. A result tiny before rounding is flushed under
/// FPSCR.FZ16, raising Underflow alone.
/// </summary>
let doubleToHalf bld ctl r (opRaised: Expr) =
  let fz16 = AST.extract (regVar bld R.FPSCR) 1<rt> 19
  let raised = tmpVar bld 32<rt>
  append bld { raised := opRaised }
  let mode = roundingMode bld ctl
  let struct (h, inexact, overflow, tiny) = narrowToHalf bld mode 64<rt> r
  let ixc = AST.extract raised 1<rt> 4 .| inexact
  let invalid, divZero = AST.extract raised 1<rt> 0, AST.extract raised 1<rt> 1
  let narrowed = fpBits invalid divZero overflow (tiny .& ixc) ixc
  let flush = tmpVar bld 1<rt>
  append bld {
    flush := fz16 .& tiny
    h := AST.ite flush (fpZero 16<rt> h) h
  }
  fpRecord bld (AST.ite flush (numU32 0x8u 32<rt>) narrowed)
  h

/// <summary>
/// A half-precision operation (Armv8.2) carried out on doubles and rounded
/// back once, under the controls given: a VFP one reads FPSCR's direction and
/// DN, and an Advanced SIMD one the standard value's, round to nearest and
/// the default NaN; FPSCR.FZ16 flushes either way, a denormal operand to a
/// zero of its sign, raising nothing, and a result tiny before rounding the
/// same way, raising Underflow alone. A double holds every half exactly, and
/// the operation hands back its double and what it raised.
/// </summary>
let viaDoubleIn bld ctl (op: Expr[] -> struct (Expr * Expr)) halves =
  let struct (r, opRaised) = op (Array.map (halfToDouble bld) halves)
  doubleToHalf bld ctl r opRaised

/// A half-precision Advanced SIMD operation, on the standard value.
let viaDouble bld (op: Expr[] -> struct (Expr * Expr)) (halves: Expr[]) =
  viaDoubleIn bld StandardValue op halves
