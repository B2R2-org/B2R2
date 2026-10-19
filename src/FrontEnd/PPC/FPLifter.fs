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
let private updateSummaries bld =
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
