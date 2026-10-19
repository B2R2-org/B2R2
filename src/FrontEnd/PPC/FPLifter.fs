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

/// The binary floating-point instructions of primary opcodes 59 and 63 that
/// the Floating-Point Facility added after the first PowerPC, and the
/// floating-point register pair accesses.
module internal B2R2.FrontEnd.PPC.FPLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils

/// fcpsgn. frD, frA, frB: frB with the sign of frA, and CR1 recorded.
let fcpsgnDot ins bld =
  lift bld ins {
    let struct (frd, fra, frb) = transThreeOprs ins bld
    frd := VectorLifter.copySign fra frb
    setCR1Reg bld
  }

/// fmrgew and fmrgow: word element 0 (even) or 1 (odd) of frA, then the same
/// word of frB. Word element 0 is the high word of the doubleword.
let fmrg ins even bld =
  lift bld ins {
    let struct (frd, fra, frb) = transThreeOprs ins bld
    let word x = if even then AST.xthi 32<rt> x else AST.xtlo 32<rt> x
    frd := AST.concat (word fra) (word frb)
  }

/// The double-precision 1.0 the reciprocal estimates divide.
let private fpOne = numU64 0x3ff0000000000000UL 64<rt>

/// fre, the double-precision reciprocal estimate, taken as the reciprocal
/// itself: the architecture lets the estimate stray from 1/frB by a part in
/// 256, which no analysis can usefully model.
let fre ins updateCond bld =
  lift bld ins {
    let struct (frd, frb) = transTwoOprs ins bld
    frd := AST.fdiv fpOne frb
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

/// frsqrtes, the reciprocal square root estimate rounded to single precision,
/// taken exactly for the same reason as fre.
let frsqrtes ins updateCond bld =
  lift bld ins {
    let struct (frd, frb) = transTwoOprs ins bld
    let single = tmpVar bld 32<rt>
    let estimate = AST.fdiv fpOne (AST.fsqrt frb)
    single := AST.cast CastKind.FloatCast 32<rt> estimate
    frd := AST.cast CastKind.FloatCast 64<rt> single
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

/// The unbiased exponent of a double, as a signed doubleword: the biased one
/// less 1023, so -1023 for a zero or a denormal.
let private unbiasedExponent x =
  ((x >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>) .- numI32 1023 64<rt>

/// Whether a double is a zero of either sign.
let private isZero x = (x << AST.num1 64<rt>) == AST.num0 64<rt>

/// Whether a double is a NaN or an infinity: its exponent all ones.
let private isNaNOrInf x =
  (x .& numU64 0x7ff0000000000000UL 64<rt>)
  == numU64 0x7ff0000000000000UL 64<rt>

/// Writes the CR field BF as fl_flag || fg_flag || fe_flag || 0b0, where the
/// implementation guarantees the estimates' relative error: the estimates here
/// are the exact reciprocals rounded once, so fl_flag is 1.
let private setTestField bld (cr0, cr1, cr2, cr3) fg fe =
  append bld {
    cr0 := AST.b1
    cr1 := fg
    cr2 := fe
    cr3 := AST.b0
  }

/// ftdiv BF, frA, frB, the operand test of a software divide: fe_flag says
/// that the divide needs the special-case path, fg_flag that frB is a zero,
/// an infinity or a denormal, or frA an infinity.
let ftdiv ins bld =
  lift bld ins {
    let struct (crf, fra, frb) = transCmpOprs ins bld
    let struct (ea, eb) = tmpVars2 bld 64<rt>
    let struct (fe, fg) = tmpVars2 bld 1<rt>
    let nonZeroA = AST.not (isZero fra)
    let diff = ea .- eb
    ea := unbiasedExponent fra
    eb := unbiasedExponent frb
    fe := isNaNOrInf fra .| isNaNOrInf frb .| isZero frb
          .| (eb ?<= numI32 -1022 64<rt>) .| (eb ?>= numI32 1021 64<rt>)
          .| (nonZeroA .& (diff ?>= numI32 1023 64<rt>))
          .| (nonZeroA .& (diff ?<= numI32 -1021 64<rt>))
          .| (nonZeroA .& (ea ?<= numI32 -970 64<rt>))
    fg := IEEE754Double.isInfinity fra .| IEEE754Double.isInfinity frb
          .| isZero frb .| isDenormalized frb
    setTestField bld crf fg fe
  }

/// ftsqrt BF, frB, the operand test of a software square root.
let ftsqrt ins bld =
  lift bld ins {
    let struct (bf, frb) = getTwoOprs ins
    let crf =
      match bf with
      | OprReg r -> transCRxToExpr bld r
      | _ -> raise InvalidOperandException
    let frb = transOpr bld frb
    let eb = tmpVar bld 64<rt>
    let struct (fe, fg) = tmpVars2 bld 1<rt>
    eb := unbiasedExponent frb
    fe := isZero frb .| isNaNOrInf frb .| AST.xthi 1<rt> frb
          .| (eb ?<= numI32 -970 64<rt>)
    fg := isZero frb .| IEEE754Double.isInfinity frb .| isDenormalized frb
    setTestField bld crf fg fe
  }

/// The odd register of the even-odd pair an operand names by its even one.
let private oddOfPair (bld: ILowUIRBuilder) = function
  | OprReg r ->
    let odd: Register = LanguagePrimitives.EnumOfValue(int r + 1)
    regVar bld odd
  | _ ->
    raise InvalidOperandException

/// lfdp and lfdpx: the doubleword at EA into the even register of the pair and
/// the one at EA + 8 into the odd one, each in the byte order the processor
/// runs in.
let private loadPair ins frp ea (bld: ILowUIRBuilder) =
  lift bld ins {
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    transOpr bld frp := loadNative bld 64<rt> tmpEA
    oddOfPair bld frp := loadNative bld 64<rt> (tmpEA .+ numI32 8 bld.RegType)
  }

let lfdp ins bld =
  let struct (frp, mem) = getTwoOprs ins
  loadPair ins frp (transEAWithOffset mem bld) bld

let lfdpx ins bld =
  let struct (frp, ra, rb) = getThreeOprs ins
  loadPair ins frp (transEAWithIndexReg ra rb bld) bld

/// stfdp and stfdpx: the even register of the pair to EA and the odd one to
/// EA + 8.
let private storePair ins frp ea (bld: ILowUIRBuilder) =
  lift bld ins {
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 64<rt> tmpEA := transOpr bld frp
    loadNative bld 64<rt> (tmpEA .+ numI32 8 bld.RegType) := oddOfPair bld frp
  }

let stfdp ins bld =
  let struct (frp, mem) = getTwoOprs ins
  storePair ins frp (transEAWithOffset mem bld) bld

let stfdpx ins bld =
  let struct (frp, ra, rb) = getThreeOprs ins
  storePair ins frp (transEAWithIndexReg ra rb bld) bld
