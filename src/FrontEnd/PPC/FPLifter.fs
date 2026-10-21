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

/// The 64-bit FPSCR, its high word (FPSCRH, which holds DRN) over the low
/// one (FPSCR).
let private wholeFPSCR bld =
  AST.concat (regVar bld Register.FPSCRH) (regVar bld Register.FPSCR)

/// The control bits of the FPSCR as mffscrn, mffscdrn and their immediate
/// forms read them: DRN (bits 29:31) and VE, OE, UE, ZE, XE, NI, RN (bits
/// 56:63), every other bit zero.
let private controlBits bld =
  let high = regVar bld Register.FPSCRH .& numU32 0x7u 32<rt>
  let low = regVar bld Register.FPSCR .& numU32 0xffu 32<rt>
  AST.concat high low

/// The FPSCR exception bits, numbered from the least significant as FPSCR
/// holds them: OX, UX, ZX, XX, the VX causes VXSNAN to VXVC, and VXSOFT,
/// VXSQRT and VXCVI. FX is not one: it is the summary of their setting.
let private exceptionBits = [ 28; 27; 26; 25; 24; 23; 22; 21; 20; 19; 10; 9; 8 ]

/// The causes VX summarizes: VXSNAN to VXVC, and VXSOFT, VXSQRT, VXCVI.
let private invalidBits = [ 24; 23; 22; 21; 20; 19; 10; 9; 8 ]

/// Recomputes FEX and VX, which are never set or cleared but follow the bits
/// they summarize: VX is the OR of the invalid-operation causes, and FEX the
/// OR of every exception bit ANDed with its enable (VX with VE).
let updateSummaries bld =
  let fpscr = regVar bld Register.FPSCR
  let bit pos = AST.extract fpscr 1<rt> pos
  let vx = tmpVar bld 1<rt>
  let enabled (e, en) = bit e .& bit en
  let others = List.map enabled [ 28, 6; 27, 5; 26, 4; 25, 3 ]
  append bld {
    vx := List.reduce (.|) (List.map bit invalidBits)
    AST.extract fpscr 1<rt> 29 := vx
    AST.extract fpscr 1<rt> 30 := List.reduce (.|) ((vx .& bit 7) :: others)
  }

/// mffs and mffs.: the whole 64-bit FPSCR into frD.
let mffs ins updateCond bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    dst := wholeFPSCR bld
    if updateCond then setCR1Reg bld else ()
  }

/// mffsce: the whole FPSCR into frD, and then the enables VE, OE, UE, ZE and
/// XE cleared, which clears FEX with them.
let mffsce ins bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    let fpscr = regVar bld Register.FPSCR
    dst := wholeFPSCR bld
    fpscr := fpscr .& numU32 0xffffff07u 32<rt>
    updateSummaries bld
  }

/// mffsl: the control bits and the non-sticky status bits (FR, FI and FPRF,
/// bits 45:51) of the FPSCR into frD, every other bit zero.
let mffsl ins bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    let status = regVar bld Register.FPSCR .& numU32 0x7f000u 32<rt>
    dst := controlBits bld .| AST.zext 64<rt> status
  }

/// mffscrn, mffscrni, mffscdrn and mffscdrni: the control bits into frD,
/// then a new rounding mode in force -- RN from bits 62:63 of frB or a
/// two-bit immediate, DRN from bits 29:31 of frB or a three-bit immediate.
/// The new mode is read before frD is written, which frB may be.
let private mffsControl ins bld setMode =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let dst = transOpr bld o1
    let mode = tmpVar bld 64<rt>
    mode := AST.zext 64<rt> (transOpr bld o2)
    dst := controlBits bld
    setMode mode
  }

/// A new RN, the low two bits of the mode mffscrn or mffscrni names.
let mffscrn ins bld =
  let fpscr = regVar bld Register.FPSCR
  mffsControl ins bld (fun mode ->
    let rn = AST.xtlo 32<rt> mode .& numU32 3u 32<rt>
    append bld {
      fpscr := (fpscr .& numU32 0xfffffffcu 32<rt>) .| rn
    })

/// A new DRN, bits 29:31 of frB (the low three bits of its high word).
let mffscdrn ins bld =
  let fpscrh = regVar bld Register.FPSCRH
  mffsControl ins bld (fun mode ->
    let drn = AST.xthi 32<rt> mode .& numU32 7u 32<rt>
    append bld {
      fpscrh := (fpscrh .& numU32 0xfffffff8u 32<rt>) .| drn
    })

/// A new DRN, the three-bit immediate.
let mffscdrni ins bld =
  let fpscrh = regVar bld Register.FPSCRH
  mffsControl ins bld (fun mode ->
    let drn = AST.xtlo 32<rt> mode .& numU32 7u 32<rt>
    append bld {
      fpscrh := (fpscrh .& numU32 0xfffffff8u 32<rt>) .| drn
    })

/// The bits of the four-bit fields a field mask (mtfsf's FLM, mfocrf's FXM)
/// names: bit i of the mask, from the least significant, names the field
/// whose bits are 4i to 4i + 3 from the least significant.
let private fieldMask (mask: uint32) =
  [ 0 .. 7 ]
  |> List.filter (fun i -> (mask >>> i) &&& 1u = 1u)
  |> List.fold (fun m i -> m ||| (0xfu <<< (4 * i))) 0u

/// FPSCR bit 52 (bit 11 here), which is reserved and reads as zero.
let private reservedLow = numU32 0xfffff7ffu 32<rt>

/// The operands of mtfsf: FLM, frB, L and W, the last two zero where the
/// extended form leaves them out.
let private mtfsfOperands (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(fm, frb) ->
    struct (getImmValue fm, transOpr bld frb, 0u, 0u)
  | FourOperands(fm, frb, l, w) ->
    struct (getImmValue fm, transOpr bld frb, getImmValue l, getImmValue w)
  | _ ->
    raise InvalidOperandException

/// The fields mtfsf writes: with L = 1 the whole FPSCR, of whose high word
/// only DRN is defined; with L = 0 the fields FLM names, of the low word
/// (W = 0) or of the high word (W = 1).
let private writeFields bld frb flm l w =
  let fpscr = regVar bld Register.FPSCR
  let fpscrh = regVar bld Register.FPSCRH
  let merge reg value (mask: uint32) =
    (value .& numU32 mask 32<rt>) .| (reg .& numU32 ~~~mask 32<rt>)
  if l = 1u then
    append bld {
      fpscr := AST.xtlo 32<rt> frb .& reservedLow
      fpscrh := AST.xthi 32<rt> frb .& numU32 7u 32<rt>
    }
  elif w = 0u then
    append bld {
      fpscr := merge fpscr (AST.xtlo 32<rt> frb) (fieldMask flm) .& reservedLow
    }
  else
    append bld {
      fpscrh := merge fpscrh (AST.xthi 32<rt> frb) (fieldMask flm &&& 7u)
    }

/// mtfsf FLM, frB[, L, W]: the FPSCR fields from frB. FX and OX are written
/// as given, never set implicitly; FEX and VX follow the bits they summarize.
let mtfsf ins updateCond bld =
  lift bld ins {
    let struct (flm, frb, l, w) = mtfsfOperands ins bld
    writeFields bld frb flm l w
    updateSummaries bld
    if updateCond then setCR1Reg bld else ()
  }

/// The operands of mtfsfi: BF, U and W, which the extended form leaves out.
let private mtfsfiOperands (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(bf, u) ->
    struct (getImmValue bf, getImmValue u, 0u)
  | ThreeOperands(bf, u, w) ->
    struct (getImmValue bf, getImmValue u, getImmValue w)
  | _ ->
    raise InvalidOperandException

/// mtfsfi BF, U[, W]: U into FPSCR field BF + 8 * (1 - W), of the low word
/// (W = 0) or of the high word (W = 1, where field 7 holds DRN under a
/// reserved bit). FX is written only by field 0 of the low word, as given;
/// FEX and VX follow the bits they summarize, and CR1 records the result.
let mtfsfi ins updateCond bld =
  lift bld ins {
    let struct (bf, u, w) = mtfsfiOperands ins
    let shift = 4 * (7 - int bf)
    let field = 0xfu <<< shift
    let value = u <<< shift
    let reg = if w = 1u then Register.FPSCRH else Register.FPSCR
    let defined = if w = 1u then 7u else 0xfffff7ffu
    let fpscr = regVar bld reg
    fpscr := (fpscr .& numU32 ~~~(field &&& defined) 32<rt>)
             .| numU32 (value &&& defined) 32<rt>
    updateSummaries bld
    if updateCond then setCR1Reg bld else ()
  }

/// FX, set where an instruction other than mtfsfi and mtfsf turns an
/// exception bit from 0 to 1.
let private setFX bld turnedOn =
  let fx = AST.extract (regVar bld Register.FPSCR) 1<rt> 31
  append bld {
    fx := fx .| turnedOn
  }

/// mtfsb0 and mtfsb1: FPSCR bit BT + 32 cleared or set, and CR1 recorded.
/// FEX and VX (BT 1 and 2) cannot be set or cleared; they follow the bits
/// they summarize. Setting an exception bit that was 0 sets FX.
let mtfsb ins set updateCond bld =
  lift bld ins {
    let pos = 31 - (getOneOpr ins |> getImmValue |> int)
    let bit = AST.extract (regVar bld Register.FPSCR) 1<rt> pos
    let isException = List.contains pos exceptionBits
    if pos = 30 || pos = 29 then ()
    elif set && isException then setFX bld (AST.not bit)
    else ()
    if pos = 30 || pos = 29 then ()
    else bit := (if set then AST.b1 else AST.b0)
    updateSummaries bld
    if updateCond then setCR1Reg bld else ()
  }

/// mfocrf rD, FXM: the CR field FXM names into its place in rD. The manual
/// leaves the other bits undefined; they are zero here, as QEMU makes them.
let mfocrf ins bld =
  lift bld ins {
    let struct (rd, fxm) = getTwoOprs ins
    let rd = transOpr bld rd
    let mask = numU32 (fieldMask (getImmValue fxm)) 32<rt>
    let cr = tmpVar bld 32<rt>
    getCRRegValue bld cr
    rd := AST.zext bld.RegType (cr .& mask)
  }

/// The bits of the doubles the arithmetic below compares against.
module private FPConst =
  /// The sign bit.
  let sign = numU64 0x8000000000000000UL 64<rt>

  /// Everything below the sign bit.
  let magnitude = numU64 0x7fffffffffffffffUL 64<rt>

  /// The quiet bit of a NaN, the leading fraction bit.
  let quiet = numU64 0x0008000000000000UL 64<rt>

  /// The QNaN an invalid operation generates.
  let defaultNaN = numU64 0x7ff8000000000000UL 64<rt>

  /// What a NaN narrowed to single precision keeps: the sign, the exponent
  /// and the leading 23 fraction bits.
  let singleNaN = numU64 0xffffffffe0000000UL 64<rt>

  /// The largest single.
  let maxSingle = numU64 0x47efffffe0000000UL 64<rt>

  /// 2^128, the magnitude no single reaches.
  let pastSingle = numU64 0x47f0000000000000UL 64<rt>

  /// 2^-126, the smallest normal single.
  let minNormalSingle = numU64 0x3810000000000000UL 64<rt>

  /// 1.0, which the reciprocal estimates divide.
  let one = numU64 0x3ff0000000000000UL 64<rt>

/// A double's magnitude: its bits with the sign cleared.
let private absOf x = x .& FPConst.magnitude

/// Whether a double is a signalling NaN: a NaN with its quiet bit clear.
let private isSNaN x =
  IEEE754Double.isNaN x .& ((x .& FPConst.quiet) == AST.num0 64<rt>)

/// Whether any of a list of doubles is what a test says.
let private anyOf test operands = List.map test operands |> List.reduce (.|)

/// The NaN an operation delivers where one of its operands is a NaN or it
/// made one: the first NaN of the operands in the order the manual takes
/// them (frA, frB, frC), quieted, or else the default QNaN.
let private settledNaN operands =
  let pick x rest = AST.ite (IEEE754Double.isNaN x) (x .| FPConst.quiet) rest
  List.foldBack pick operands FPConst.defaultNaN

/// FPRF (C, FL, FG, FE, FU) of a result, in the five low bits of a word: a
/// single-precision instruction classes its result as a single, whose
/// denormals are denormal at that precision whatever the double's exponent.
let private fprfOf single r =
  let nan = IEEE754Double.isNaN r
  let zero = isZero r
  let neg = AST.xthi 1<rt> r
  let denormal =
    if single then AST.not zero .& AST.flt (absOf r) FPConst.minNormalSingle
    else isDenormalized r
  let positioned b n = AST.zext 32<rt> b << numI32 n 32<rt>
  positioned (nan .| denormal .| (zero .& neg)) 4
  .| positioned (AST.not nan .& neg .& AST.not zero) 3
  .| positioned (AST.not nan .& AST.not neg .& AST.not zero) 2
  .| positioned zero 1
  .| positioned (nan .| IEEE754Double.isInfinity r) 0

/// The exception query: the IEEE exceptions an operation raised, in the
/// order the evaluator answers them (Invalid 16, Divide by Zero 8, Overflow
/// 4, Underflow 2, Inexact 1), tininess decided before rounding (0x40) as
/// the Power ISA decides it, in the direction FPSCR[RN] names. Operation
/// codes: add 0, subtract 1, multiply 2, divide 3, square root 4 (whose one
/// operand goes twice).
let private query code a b =
  let code = numU64 (code ||| 0x40UL) 8<rt>
  AST.app "FEXC64" [ code; a; b ] 32<rt>

/// The fused multiply-add's query (code 8), frA x frC + frB, bit 1 of the
/// flags negating the addend; the modifier rides with the flags.
let private fusedQuery fra frc frb (flags: uint64) =
  let code = numU64 8UL 8<rt>
  let flags = numU64 (flags ||| 0x40UL) 8<rt>
  AST.app "FEXC64" [ code; fra; frc; frb; flags ] 32<rt>

/// What an arithmetic instruction computes, for fpArith.
type private Arith =
  { /// The instruction's operands, in the order the manual takes a NaN from
    /// them.
    Operands: Expr list
    /// The operation, rounded in whichever direction encloses it.
    Compute: Expr
    /// The exception query of the operation.
    Query: Expr
    /// The invalid-operation causes besides VXSNAN, as (FPSCR bit,
    /// condition) pairs, given whether the query raised Invalid and whether
    /// an operand is a signalling NaN.
    Invalid: Expr -> Expr -> (int * Expr) list
    /// Whether the rounded result is negated (fnmadd, fnmsub).
    Negate: bool }

/// The rounding of an arithmetic result, before NaNs and exceptions.
type private Rounding =
  { Result: Expr
    Overflow: Expr
    Underflow: Expr
    Inexact: Expr
    /// Whether rounding moved the result away from zero (FR).
    Rounded: Expr }

/// A double-precision result in the direction FPSCR[RN] names, with what
/// the query says its rounding raised; FR asks whether that moved it away
/// from zero, which is where it differs from the result truncated.
let private roundDouble bld (a: Arith) raised =
  let struct (r, rz) = tmpVars2 bld 64<rt>
  let toZero = AST.roundingMode RoundingMode.TowardZero
  let inexact = AST.extract raised 1<rt> 0
  append bld {
    r := a.Compute
    rz := AST.roundCtrl toZero a.Compute
  }
  { Result = r
    Overflow = AST.extract raised 1<rt> 2
    Underflow = AST.extract raised 1<rt> 1
    Inexact = inexact
    Rounded = inexact .& (r != rz) }

/// <summary>
/// A single-precision result rounded ONCE from the exact one: the operation
/// truncated to a double, its last bit set where that lost anything (round
/// to odd), rounds to single precision as the exact value does, a double's
/// 53 bits being more than 24 + 2. The status is that rounding's: inexact
/// where the single differs from it, overflowing where the single went past
/// the largest one (or stopped there short of the 2^128 the exact value
/// reached), tiny below 2^-126.
///
/// The manual leaves the result undefined for an operand a single cannot
/// hold; rounding the exact result once is what QEMU and the processors do.
/// </summary>
let private roundSingle bld (a: Arith) raised =
  let struct (t, r) = tmpVars2 bld 64<rt>
  let inexact = tmpVar bld 1<rt>
  let toZero = AST.roundingMode RoundingMode.TowardZero
  let sticky = AST.zext 64<rt> (AST.extract raised 1<rt> 0)
  let finite = AST.ite (IEEE754Double.isNaN t) (AST.num0 64<rt>) t
  let single = AST.cast CastKind.FloatCast 32<rt> finite
  let atMax = absOf r == FPConst.maxSingle
  append bld {
    t := AST.roundCtrl toZero a.Compute .| sticky
    t := AST.ite (absOf t == AST.num0 64<rt>) a.Compute t
    r := AST.cast CastKind.FloatCast 64<rt> single
    inexact := r != t
  }
  { Result = r
    Overflow =
      (IEEE754Double.isInfinity r .& AST.not (IEEE754Double.isInfinity t))
      .| (atMax .& AST.fge (absOf t) FPConst.pastSingle)
    Underflow =
      AST.fgt (absOf t) (AST.num0 64<rt>)
      .& AST.flt (absOf t) FPConst.minNormalSingle .& inexact
    Inexact = inexact
    Rounded = inexact .& AST.fgt (absOf r) (absOf t) }

/// What an arithmetic instruction delivers and records, for fpArith.
type private Outcome =
  { Result: Expr
    /// The exception bits raised, as FPSCR keeps them (XX with them).
    Raised: Expr
    FR: Expr
    FI: Expr
    /// Whether an enabled exception keeps the target and FPRF as they were.
    Suppressed: Expr }

/// The bits of FPSCR a list of (bit, condition) pairs names.
let private bitsOf pairs =
  pairs
  |> List.map (fun (n, c) -> AST.zext 32<rt> c << numI32 n 32<rt>)
  |> List.reduce (.|)

/// <summary>
/// The result and the exceptions of an arithmetic instruction (Section 4.4).
/// A NaN result -- an operand was one, or the operation was invalid -- is
/// the first NaN operand quieted or the default QNaN, narrowed by truncation
/// for a single-precision instruction. An invalid operation or a zero divide
/// raises no overflow, underflow or inexact and sets FR and FI to 0; with VE
/// (or ZE) set it leaves frD and FPRF unchanged.
/// </summary>
let private settle bld single (a: Arith) raised (rnd: Rounding) =
  let fpscr = regVar bld Register.FPSCR
  let res = tmpVar bld 64<rt>
  let struct (nan, snan, special, suppressed) = tmpVars4 bld 1<rt>
  let nv = AST.extract raised 1<rt> 4
  let dz = AST.extract raised 1<rt> 3
  let nanResult = settledNaN a.Operands
  let nanResult = if single then nanResult .& FPConst.singleNaN else nanResult
  let invalid = (24, snan) :: a.Invalid nv snan
  let anyInvalid = List.map snd invalid |> List.reduce (.|)
  let ve = AST.extract fpscr 1<rt> 7
  let ze = AST.extract fpscr 1<rt> 4
  let negated = AST.ite (IEEE754Double.isNaN res) res (res <+> FPConst.sign)
  let normal c = c .& AST.not special
  append bld {
    nan := anyOf IEEE754Double.isNaN a.Operands .| nv
    snan := anyOf isSNaN a.Operands
    special := nan .| dz
    res := AST.ite nan nanResult rnd.Result
    if a.Negate then res := negated else ()
    suppressed := (ve .& anyInvalid) .| (ze .& dz)
  }
  { Result = res
    Raised =
      bitsOf ((28, normal rnd.Overflow) :: (27, normal rnd.Underflow)
              :: (26, dz) :: (25, normal rnd.Inexact) :: invalid)
    FR = normal rnd.Rounded
    FI = normal rnd.Inexact
    Suppressed = suppressed }

/// The FPSCR after an arithmetic instruction: the exception bits it raised
/// OR-ed in, FR, FI and FPRF replaced (FPRF kept where the result was
/// suppressed), FX set where an exception bit turned on, FEX and VX
/// recomputed.
let private recordStatus bld (o: Outcome) fprf =
  let fpscr = regVar bld Register.FPSCR
  let struct (old, raised) = tmpVars2 bld 32<rt>
  let kept = old .& numU32 0x1f000u 32<rt>
  let positioned b n = AST.zext 32<rt> b << numI32 n 32<rt>
  let turnedOn = (raised .& AST.not old) != AST.num0 32<rt>
  append bld {
    old := fpscr
    raised := o.Raised
    fpscr :=
      ((old .| raised) .& numU32 0xfff80fffu 32<rt>)
      .| positioned o.FR 18 .| positioned o.FI 17
      .| AST.ite o.Suppressed kept (fprf << numI32 12 32<rt>)
      .| positioned turnedOn 31
  }
  updateSummaries bld

/// The register an arithmetic instruction writes, its first operand.
let private destination (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(d, _) | ThreeOperands(d, _, _) | FourOperands(d, _, _, _) ->
    transOpr bld d
  | _ ->
    raise InvalidOperandException

/// <summary>
/// An arithmetic instruction: the result and the FPSCR status the manual
/// defines, the result from the host's arithmetic and its exceptions from
/// the evaluator's query, as the other front ends lift floating point. The
/// adjusted results of an enabled overflow or underflow (OE, UE) are not
/// modelled: the result is the disabled one.
/// </summary>
let private fpArith ins updateCond isDouble (a: Arith) bld =
  lift bld ins {
    let frd = destination ins bld
    let raised = tmpVar bld 32<rt>
    raised := a.Query
    let rnd =
      if isDouble then roundDouble bld a raised else roundSingle bld a raised
    let o = settle bld (not isDouble) a raised rnd
    frd := AST.ite o.Suppressed frd o.Result
    recordStatus bld o (fprfOf (not isDouble) o.Result)
    if updateCond then setCR1Reg bld else ()
  }

/// The causes of magnitude-subtracted infinities (VXISI).
let private infMinusInf nv snan = [ 23, nv .& AST.not snan ]

/// The causes of an infinity times a zero (VXIMZ).
let private infTimesZero nv snan = [ 20, nv .& AST.not snan ]

/// The causes of a divide: infinity by infinity (VXIDI), zero by zero
/// (VXZDZ), told apart by the dividend.
let private divideCauses fra nv snan =
  let cause = nv .& AST.not snan
  [ 22, cause .& IEEE754Double.isInfinity fra; 21, cause .& isZero fra ]

/// The causes of a square root of a negative number (VXSQRT).
let private negativeRoot nv snan = [ 9, nv .& AST.not snan ]

/// A two-operand operation: fadd, fsub, fmul, fdiv and their single forms.
let private binary ins updateCond isDouble op code causes bld =
  let struct (_, fra, frb) = transThreeOprs ins bld
  { Operands = [ fra; frb ]
    Compute = op fra frb
    Query = query code fra frb
    Invalid = causes fra
    Negate = false }
  |> fun a -> fpArith ins updateCond isDouble a bld

let fadd ins updateCond isDouble bld =
  binary ins updateCond isDouble AST.fadd 0UL (fun _ -> infMinusInf) bld

let fsub ins updateCond isDouble bld =
  binary ins updateCond isDouble AST.fsub 1UL (fun _ -> infMinusInf) bld

let fmul ins updateCond isDouble bld =
  binary ins updateCond isDouble AST.fmul 2UL (fun _ -> infTimesZero) bld

let fdiv ins updateCond isDouble bld =
  binary ins updateCond isDouble AST.fdiv 3UL divideCauses bld

/// fsqrt and fsqrts.
let fsqrt ins updateCond isDouble bld =
  let struct (_, frb) = transTwoOprs ins bld
  { Operands = [ frb ]
    Compute = AST.fsqrt frb
    Query = query 4UL frb frb
    Invalid = negativeRoot
    Negate = false }
  |> fun a -> fpArith ins updateCond isDouble a bld

/// <summary>
/// The multiply-adds, frA x frC + frB with one rounding, as the FMA call
/// (bit 1 of its flag negating the addend for the subtracting forms). The
/// negated forms negate the rounded result, as the manual says, so a NaN
/// passes through as it is. An infinity times a zero is invalid (VXIMZ)
/// whatever the addend, an SNaN addend included; magnitude-subtracted
/// infinities otherwise (VXISI).
/// </summary>
let private fusedMulAdd ins updateCond isDouble subtract negate bld =
  let struct (_, fra, frc, frb) = transFourOprs ins bld
  let flags = if subtract then 2UL else 0UL
  let zeroTimesInf =
    (isZero fra .& IEEE754Double.isInfinity frc)
    .| (IEEE754Double.isInfinity fra .& isZero frc)
  let causes nv snan =
    [ 20, zeroTimesInf; 23, nv .& AST.not snan .& AST.not zeroTimesInf ]
  { Operands = [ fra; frb; frc ]
    Compute = AST.app "FMA64" [ fra; frc; frb; numU64 flags 8<rt> ] 64<rt>
    Query = fusedQuery fra frc frb flags
    Invalid = causes
    Negate = negate }
  |> fun a -> fpArith ins updateCond isDouble a bld

let fmadd ins updateCond isDouble bld =
  fusedMulAdd ins updateCond isDouble false false bld

let fmsub ins updateCond isDouble bld =
  fusedMulAdd ins updateCond isDouble true false bld

let fnmadd ins updateCond isDouble bld =
  fusedMulAdd ins updateCond isDouble false true bld

let fnmsub ins updateCond isDouble bld =
  fusedMulAdd ins updateCond isDouble true true bld

/// <summary>
/// fre and fres: the reciprocal estimate, taken as the reciprocal itself
/// rounded once -- the manual lets it stray from 1/frB by a part in 256,
/// which no analysis can usefully model. A zero divides by zero (ZX): the
/// result is the infinity the manual's table gives, where QEMU answers 1/2.
/// FR, FI and XX are undefined for an estimate.
/// </summary>
let private reciprocal ins updateCond isDouble bld =
  let struct (_, frb) = transTwoOprs ins bld
  { Operands = [ frb ]
    Compute = AST.fdiv FPConst.one frb
    Query = query 3UL FPConst.one frb
    Invalid = fun _ _ -> []
    Negate = false }
  |> fun a -> fpArith ins updateCond isDouble a bld

let fre ins updateCond bld = reciprocal ins updateCond true bld

let fres ins updateCond bld = reciprocal ins updateCond false bld

/// <summary>
/// frsqrte and frsqrtes: the reciprocal square root estimate, taken as
/// 1/sqrt(frB). A negative operand is invalid (VXSQRT) and a zero divides
/// by zero (ZX), which the root's own query does not say, so the query is
/// the root's Invalid, a zero's Divide by Zero and the division's rounding.
/// </summary>
let private reciprocalRoot ins updateCond isDouble bld =
  let struct (_, frb) = transTwoOprs ins bld
  let root = AST.fsqrt frb
  let invalid = query 4UL frb frb .& numU32 0x10u 32<rt>
  let divZero = AST.zext 32<rt> (isZero frb) << numI32 3 32<rt>
  let rounding = query 3UL FPConst.one root .& numU32 0x7u 32<rt>
  { Operands = [ frb ]
    Compute = AST.fdiv FPConst.one root
    Query = invalid .| divZero .| rounding
    Invalid = negativeRoot
    Negate = false }
  |> fun a -> fpArith ins updateCond isDouble a bld

let frsqrte ins updateCond bld = reciprocalRoot ins updateCond true bld

let frsqrtes ins updateCond bld = reciprocalRoot ins updateCond false bld

/// frsp: frB rounded to single precision, the one rounding from an exact
/// operand, which needs no query: frB itself is the exact value.
let frsp ins updateCond bld =
  let struct (_, frb) = transTwoOprs ins bld
  { Operands = [ frb ]
    Compute = frb
    Query = AST.num0 32<rt>
    Invalid = fun _ _ -> []
    Negate = false }
  |> fun a -> fpArith ins updateCond false a bld

/// A conversion in a direction the instruction names, or in the one
/// FPSCR[RN] names where it names none.
let private inDirection mode e =
  match mode with
  | Some m -> AST.roundCtrl (AST.roundingMode m) e
  | None -> e

/// <summary>
/// fcfid, fcfidu, fcfids and fcfidus: the integer in frB converted to a
/// double, or rounded ONCE straight to a single by the "s" forms -- not to a
/// double and then again to a single. FI (and XX with it) says the
/// conversion lost anything, which is where rounding it up and down differ;
/// FR that it moved the result away from zero; FPRF is the result's class.
/// </summary>
let fcfid ins updateCond bld signed single =
  lift bld ins {
    let struct (frd, frb) = transTwoOprs ins bld
    let kind = if signed then CastKind.SIntToFloat else CastKind.UIntToFloat
    let width = if single then 32<rt> else 64<rt>
    let convert mode =
      let c = inDirection mode (AST.cast kind width frb)
      if single then AST.cast CastKind.FloatCast 64<rt> c else c
    let struct (r, up, down, toZero) = tmpVars4 bld 64<rt>
    r := convert None
    up := convert (Some RoundingMode.TowardPositive)
    down := convert (Some RoundingMode.TowardNegative)
    toZero := convert (Some RoundingMode.TowardZero)
    let fi = up != down
    frd := r
    { Result = r
      Raised = bitsOf [ 25, fi ]
      FR = fi .& (r != toZero)
      FI = fi
      Suppressed = AST.b0 }
    |> fun o -> recordStatus bld o (fprfOf single r)
    if updateCond then setCR1Reg bld else ()
  }

/// The doubles bounding what a conversion to an integer can hold: the
/// least value it holds and the least it does not.
let private intRange width signed =
  let dbl (v: float) = numU64 (System.BitConverter.DoubleToUInt64Bits v) 64<rt>
  let span = 2.0 ** float (int width)
  if signed then struct (dbl (-span / 2.0), dbl (span / 2.0))
  else struct (dbl 0.0, dbl span)

/// <summary>
/// What a conversion to an integer records (Section 4.4.1, 4.3.6): VXSNAN
/// for an SNaN, VXCVI for a NaN, an infinity or a value whose integer the
/// width cannot hold, and otherwise FI where frB had a fraction to lose and
/// FR where the integer is farther from zero than frB. FPRF is undefined
/// and left as it was. An invalid conversion clears FR and FI; with VE set
/// it leaves frD as it was, which the caller is given back to keep.
/// </summary>
let private convertStatus bld frd old frb rounded width signed =
  let struct (low, past) = intRange width signed
  let struct (invalid, inexact) = tmpVars2 bld 1<rt>
  let ve = AST.extract (regVar bld Register.FPSCR) 1<rt> 7
  append bld {
    invalid :=
      IEEE754Double.isNaN frb .| AST.flt rounded low .| AST.fge rounded past
    inexact := AST.not invalid .& (rounded != frb)
    frd := AST.ite (ve .& invalid) old frd
  }
  { Result = frd
    Raised = bitsOf [ 25, inexact; 24, isSNaN frb; 8, invalid ]
    FR = inexact .& AST.fgt (absOf rounded) (absOf frb)
    FI = inexact
    Suppressed = AST.b1 }
  |> fun o -> recordStatus bld o (AST.num0 32<rt>)

/// Clamps a word conversion: NaN and anything below the most negative word
/// give 0x80000000, anything above the largest word gives 0x7fffffff.
let private saturateWord bld frd frb =
  append bld {
    let intMaxInFloat = numU64 0x41dfffffffc00000uL 64<rt>
    let intMinInFloat = numU64 0xc1e0000000000000uL 64<rt>
    let intMax = numU64 0x7fffffffUL 64<rt>
    let intMin = numU64 0x80000000UL 64<rt>
    frd := AST.ite (IEEE754Double.isNaN frb) intMin frd
    frd := AST.ite (AST.fle frb intMinInFloat) intMin frd
    frd := AST.ite (AST.fge frb intMaxInFloat) intMax frd
  }

/// fctiw and fctiwz: frB converted to a signed word, rounded in the
/// direction FPSCR[RN] names or toward zero.
let private fctiwIn ins updateCond bld mode =
  lift bld ins {
    let struct (frd, frb) = transTwoOprs ins bld
    let struct (src, old) = tmpVars2 bld 64<rt>
    let rounded = tmpVar bld 64<rt>
    src := frb
    old := frd
    rounded := inDirection mode (AST.cast CastKind.RoundToIntegral 64<rt> src)
    frd := inDirection mode (AST.cast CastKind.FloatToSInt 64<rt> src)
    saturateWord bld frd src
    convertStatus bld frd old src rounded 32<rt> true
    if updateCond then setCR1Reg bld else ()
  }

let fctiw ins updateCond bld = fctiwIn ins updateCond bld None

let fctiwz ins updateCond bld =
  fctiwIn ins updateCond bld (Some RoundingMode.TowardZero)

/// A double at or above 2^63 converted to an unsigned doubleword, by way of
/// the signed conversion of it less 2^63.
let private toUInt64 bld dst src mode =
  let big = tmpVar bld 1<rt>
  let adjusted = tmpVar bld 64<rt>
  let half = numU64 0x43e0000000000000UL 64<rt>
  append bld {
    big := AST.fge src half
    adjusted := AST.ite big (AST.fsub src half) src
    dst := inDirection mode (AST.cast CastKind.FloatToSInt 64<rt> adjusted)
    dst := AST.ite big (dst .+ numU64 0x8000000000000000UL 64<rt>) dst
  }

/// Clamps a conversion to `width` bits: a signed one gives the most negative
/// integer for NaN and anything below range and the largest for anything
/// above; an unsigned one gives zero for NaN and for a value whose rounded
/// integer is negative (a source in (-1, 0) rounds to -1 under
/// round-toward-minus-infinity) and all ones above the range.
let private saturateInt bld frd src rounded width signed =
  let bits = int width
  let dbl (v: float) = numU64 (System.BitConverter.DoubleToUInt64Bits v) 64<rt>
  let all = if bits = 64 then System.UInt64.MaxValue else (1UL <<< bits) - 1UL
  let ones = numU64 all 64<rt>
  append bld {
    if signed then
      let top = numU64 ((1UL <<< (bits - 1)) - 1UL) 64<rt>
      let bottom = numU64 (1UL <<< (bits - 1)) 64<rt>
      frd := AST.ite (AST.fge src (dbl (2.0 ** float (bits - 1)))) top frd
      frd := AST.ite (AST.fle src (dbl (-(2.0 ** float (bits - 1))))) bottom frd
      frd := AST.ite (IEEE754Double.isNaN src) bottom frd
    else
      let negative = AST.flt src (dbl 0.0) .& (rounded ?< AST.num0 64<rt>)
      frd := AST.ite (AST.fge src (dbl (2.0 ** float bits))) ones frd
      frd := AST.ite negative (AST.num0 64<rt>) frd
      frd := AST.ite (IEEE754Double.isNaN src) (AST.num0 64<rt>) frd
  }

/// fctid/fctidz/fctidu/fctiduz and fctiwu/fctiwuz: a conversion from a double
/// to an integer of `width` bits, left in the target's low bits. A "z" form
/// always truncates; the others follow FPSCR[RN].
let fcti ins updateCond bld width signed truncate =
  lift bld ins {
    let struct (frd, frb) = transTwoOprs ins bld
    let struct (src, old, converted, rounded) = tmpVars4 bld 64<rt>
    let mode = if truncate then Some RoundingMode.TowardZero else None
    src := frb
    old := frd
    rounded := inDirection mode (AST.cast CastKind.RoundToIntegral 64<rt> src)
    if not signed && width = 64<rt> then
      toUInt64 bld converted src mode
    else
      converted := inDirection mode (AST.cast CastKind.FloatToSInt 64<rt> src)
    frd := AST.zext 64<rt> (AST.xtlo width converted)
    saturateInt bld frd src converted width signed
    convertStatus bld frd old src rounded width signed
    if updateCond then setCR1Reg bld else ()
  }

/// <summary>
/// frin/friz/frip/frim, which round a double to an integral value in place:
/// to nearest with a tie going AWAY from zero -- not the even one IEEE
/// rounds to -- and then toward zero, up, and down. They set FR and FI to 0
/// and FPRF to the result's class; an SNaN raises VXSNAN and becomes its
/// QNaN, and with VE set leaves frD and FPRF as they were.
/// </summary>
let frnd ins updateCond bld mode =
  lift bld ins {
    let struct (frd, frb) = transTwoOprs ins bld
    let r = tmpVar bld 64<rt>
    let snan = tmpVar bld 1<rt>
    let ve = AST.extract (regVar bld Register.FPSCR) 1<rt> 7
    let quieted = frb .| FPConst.quiet
    let integral = AST.roundToIntegral mode 64<rt> frb
    snan := isSNaN frb
    r := AST.ite (IEEE754Double.isNaN frb) quieted integral
    frd := AST.ite (ve .& snan) frd r
    { Result = r
      Raised = bitsOf [ 24, snan ]
      FR = AST.b0
      FI = AST.b0
      Suppressed = ve .& snan }
    |> fun o -> recordStatus bld o (fprfOf false r)
    if updateCond then setCR1Reg bld else ()
  }

/// <summary>
/// fcmpu and fcmpo: CR field BF and FPSCR[FPCC] from the comparison, FL, FG,
/// FE or FU. An SNaN raises VXSNAN; fcmpo also raises VXVC for any NaN, but
/// for an SNaN only with VE clear. FX is set where either turned on, and VX
/// and FEX follow.
/// </summary>
let fcmp ins bld isOrdered =
  lift bld ins {
    let struct ((crf0, crf1, crf2, crf3), fra, frb) = transCmpOprs ins bld
    let fpscr = regVar bld Register.FPSCR
    let struct (lt, gt, eq, un) = tmpVars4 bld 1<rt>
    let old = tmpVar bld 32<rt>
    let ve = AST.extract fpscr 1<rt> 7
    let snan = isSNaN fra .| isSNaN frb
    let vxvc = if isOrdered then AST.ite snan (AST.not ve) un else AST.b0
    let raised = bitsOf [ 24, snan; 19, vxvc ]
    let fpcc = bitsOf [ 15, lt; 14, gt; 13, eq; 12, un ]
    old := fpscr
    un := IEEE754Double.isNaN fra .| IEEE754Double.isNaN frb
    lt := AST.flt fra frb
    gt := AST.fgt fra frb
    eq := AST.not (lt .| gt .| un)
    crf0 := lt
    crf1 := gt
    crf2 := eq
    crf3 := un
    fpscr := ((old .| raised) .& numU32 0xffff0fffu 32<rt>) .| fpcc
    setFX bld ((raised .& AST.not old) != AST.num0 32<rt>)
    updateSummaries bld
  }

let fcmpo ins bld = fcmp ins bld true

let fcmpu ins bld = fcmp ins bld false
