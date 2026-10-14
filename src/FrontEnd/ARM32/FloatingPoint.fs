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
/// The floating-point model of DDI0406C A2.7, which the VFP and the Advanced
/// SIMD lifters share: where an operation reads its controls, how an operand
/// is classified, the NaN an operation answers with, the flush of a denormal
/// operand or a tiny result to zero, and the cumulative exception flags.
///
/// <para>A VFP instruction reads FPSCR. An Advanced SIMD one reads
/// StandardFPSCRValue instead -- round to nearest, flush to zero, the default
/// NaN, and FPSCR.AHP -- and still sets the cumulative flags in FPSCR, since
/// FPProcessException writes them whatever value it is handed and that value
/// enables no trap.</para>
///
/// <para>FPSCR.RMode is the direction an expression no RoundCtrl encloses
/// rounds in, so a VFP operation is left bare and an Advanced SIMD one is
/// enclosed in a RoundCtrl that names round to nearest, together with the
/// query for what it raised, which answers in the direction it stands
/// in.</para>
/// </summary>
module internal B2R2.FrontEnd.ARM32.FloatingPoint

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.LiftingUtils

/// Where an operation reads its floating-point controls.
type FPControl =
  /// FPSCR, as a VFP instruction reads it.
  | FPSCRValue
  /// StandardFPSCRValue, as an Advanced SIMD instruction reads it.
  | StandardValue

let private fpscrField bld rt pos = AST.extract (regVar bld R.FPSCR) rt pos

/// FPSCR.DN, the default NaN in place of a propagated one, which the standard
/// value sets.
let defaultNaNMode bld ctl =
  match ctl with
  | FPSCRValue -> fpscrField bld 1<rt> 25
  | StandardValue -> AST.b1

/// FPSCR.FZ, a denormal operand or a tiny result taken as a zero, which the
/// standard value sets.
let flushToZero bld ctl =
  match ctl with
  | FPSCRValue -> fpscrField bld 1<rt> 24
  | StandardValue -> AST.b1

/// FPSCR.AHP, the alternative half-precision format, which the standard value
/// carries over.
let altHalfPrecision bld = fpscrField bld 1<rt> 26

/// FPSCR.RMode in Arm's order -- to nearest, toward plus infinity, toward
/// minus infinity, toward zero -- where the standard value names nearest.
let roundingMode bld ctl =
  match ctl with
  | FPSCRValue -> fpscrField bld 2<rt> 22
  | StandardValue -> AST.num0 2<rt>

/// An expression evaluated in the direction the controls name: a bare one
/// rounds as FPSCR.RMode says, and the standard value names round to nearest.
let inForce ctl e =
  let nearest = AST.roundingMode RoundingMode.ToNearestEven
  match ctl with
  | FPSCRValue -> e
  | StandardValue -> AST.roundCtrl nearest e

let private fractionBits sz =
  match sz with
  | 64<rt> -> 52
  | 32<rt> -> 23
  | _ -> 10

/// The sign bit of a format.
let signOf sz = numU64 (1UL <<< (int sz - 1)) sz

/// Everything but the sign bit.
let magnitudeOf sz = numU64 ((1UL <<< (int sz - 1)) - 1UL) sz

/// The fraction's top bit, which makes a NaN quiet.
let quietBit sz = numU64 (1UL <<< (fractionBits sz - 1)) sz

/// A half without its sign, which is all its classification needs.
let private halfMagnitude e = e .& numU32 0x7fffu 16<rt>

/// Whether a value is a NaN: every exponent bit set and a fraction.
let isNaN sz e =
  match sz with
  | 64<rt> -> IEEE754Double.isNaN e
  | 32<rt> -> IEEE754Single.isNaN e
  | _ -> halfMagnitude e .> numU32 0x7c00u 16<rt>

/// Whether a value is a signalling NaN, its fraction's top bit clear.
let isSNaN sz e = isNaN sz e .& ((e .& quietBit sz) == AST.num0 sz)

/// Whether a value is a quiet NaN.
let isQNaN sz e = isNaN sz e .& ((e .& quietBit sz) != AST.num0 sz)

/// Whether a value is an infinity: every exponent bit set and no fraction.
let isInfinity sz e =
  match sz with
  | 64<rt> -> IEEE754Double.isInfinity e
  | 32<rt> -> IEEE754Single.isInfinity e
  | _ -> halfMagnitude e == numU32 0x7c00u 16<rt>

/// Whether a value is a zero of either sign.
let isZero sz e = (e .& magnitudeOf sz) == AST.num0 sz

/// Whether a value is subnormal: a magnitude above zero and below the
/// smallest normal's.
let isDenormal sz e =
  let magnitude = e .& magnitudeOf sz
  let smallestNormal = numU64 (1UL <<< fractionBits sz) sz
  (magnitude != AST.num0 sz) .& (magnitude .< smallestNormal)

/// FPZero, with the sign of the value given.
let fpZero sz e = e .& signOf sz

/// Every exponent bit set, which is an infinity's magnitude.
let private exponentMask sz =
  let fraction = (1UL <<< fractionBits sz) - 1UL
  numU64 (((1UL <<< (int sz - 1)) - 1UL) &&& ~~~fraction) sz

/// FPInfinity, with the sign given as a bit.
let fpInfinity sz sign =
  AST.ite sign (signOf sz) (AST.num0 sz) .| exponentMask sz

/// FPDefaultNaN, which is positive.
let fpDefaultNaN sz = exponentMask sz .| quietBit sz

/// FPProcessNaN: the NaN made quiet, or the default NaN where FPSCR.DN says
/// so.
let fpProcessNaN bld ctl sz e =
  AST.ite (defaultNaNMode bld ctl) (fpDefaultNaN sz) (e .| quietBit sz)

/// <summary>
/// FPProcessNaNs and FPProcessNaNs3: the first signalling NaN in the order
/// the operands are written, then the first quiet one, made quiet; and the
/// default NaN under FPSCR.DN, or for a NaN no operand brought in, which is an
/// invalid operation's. An answer that is not a NaN never reaches this: it is
/// a chain of selects behind one.
/// </summary>
let fpNaNResult bld ctl sz operands =
  let anyNaN = operands |> List.map (isNaN sz) |> List.reduce (.|)
  let candidates =
    List.map (fun e -> isSNaN sz e, e) operands
    @ List.map (fun e -> isNaN sz e, e) operands
  let pick = List.foldBack (fun (c, v) acc -> AST.ite c v acc) candidates
  let chosen = pick (AST.num0 sz) .| quietBit sz
  AST.ite (defaultNaNMode bld ctl .| AST.not anyNaN) (fpDefaultNaN sz) chosen

/// The five exceptions as FPSCR keeps them, Invalid lowest and Inexact
/// highest, from one-bit conditions.
let fpBits invalid divZero overflow underflow inexact =
  AST.zext 32<rt> invalid
  .| (AST.zext 32<rt> divZero << numI32 1 32<rt>)
  .| (AST.zext 32<rt> overflow << numI32 2 32<rt>)
  .| (AST.zext 32<rt> underflow << numI32 3 32<rt>)
  .| (AST.zext 32<rt> inexact << numI32 4 32<rt>)

/// Nothing raised, for an exception an operation cannot have.
let fpNone = AST.b0

/// <summary>
/// Sets FPSCR's cumulative flags for what an operation raised. They are
/// sticky: an operation sets the ones it raised and clears none. The trap
/// enables are not read, since nothing here traps -- the implementation
/// without trapped exceptions -- and the standard value enables none.
/// </summary>
let fpRecord bld raised =
  let fpscr = regVar bld R.FPSCR
  append bld { fpscr := fpscr .| raised }

/// Records Invalid alone, for an operation whose only exception it is.
let fpInvalidOnly bld invalid =
  fpRecord bld (fpBits invalid fpNone fpNone fpNone fpNone)

/// <summary>
/// FPUnpack's flush of a denormal single or double to a zero of its own sign
/// under FPSCR.FZ (A2.7), which raises Input Denormal, FPSCR.IDC, where it
/// takes the operand. What comes back is the operand as a temporary.
/// </summary>
let fpFlushIn bld ctl sz e =
  let flush = tmpVar bld 1<rt>
  let flushed = tmpVar bld sz
  append bld {
    flush := flushToZero bld ctl .& isDenormal sz e
    flushed := AST.ite flush (fpZero sz e) e
  }
  fpRecord bld (AST.zext 32<rt> flush << numI32 7 32<rt>)
  flushed

/// <summary>
/// FPRound's flush of a result that was tiny before rounding to a zero of its
/// own sign under FPSCR.FZ, and what the result raises with it: Underflow and
/// nothing else. An exact subnormal result is told by its bits, and an
/// inexact one by the Underflow the query raised, which it asks for with
/// tininess before rounding.
/// </summary>
let fpFlushOut bld ctl sz res (raised: Expr) =
  let flush = tmpVar bld 1<rt>
  let r = tmpVar bld 32<rt>
  let underflow = AST.extract r 1<rt> 3
  append bld {
    r := raised
    flush := flushToZero bld ctl .& (isDenormal sz res .| underflow)
    res := AST.ite flush (fpZero sz res) res
  }
  AST.ite flush (numU32 0x8u 32<rt>) r

/// The arithmetic an exception can be raised by.
type FPArith =
  | FPAdd
  | FPSub
  | FPMul
  | FPDiv
  | FPSqrt

/// What the exception query is asked beyond the operation: tininess decided
/// BEFORE rounding (0x40), as FPRound decides it, and the flags in FPSCR's
/// order (0x80), Invalid lowest.
let private fpExcArm = 0xC0UL

/// The operation codes of the query, which are the evaluator's contract.
let private fpExcCode = function
  | FPAdd -> 0UL
  | FPSub -> 1UL
  | FPMul -> 2UL
  | FPDiv -> 3UL
  | FPSqrt -> 4UL

let private fpExcName sz = if sz = 32<rt> then "FEXC32" else "FEXC64"

/// <summary>
/// The exceptions an arithmetic operation raised, as FPSCR's five flags.
/// Three of them are about the rounding, which an answer does not show, so
/// the question goes to the evaluator as a named call that works the
/// operation out again with its exact error in hand, in the direction the
/// controls name. The square root reads one operand; its caller passes it
/// twice.
/// </summary>
let fpRaised ctl sz op a b =
  let code = numU64 (fpExcCode op ||| fpExcArm) 8<rt>
  inForce ctl (AST.app (fpExcName sz) [ code; a; b ] 32<rt>)

/// What a fused multiply-add raised: x times y plus z, rounded once.
let fpFusedRaised ctl sz x y z =
  let args = [ numU64 8UL 8<rt>; x; y; z; numU64 fpExcArm 8<rt> ]
  inForce ctl (AST.app (fpExcName sz) args 32<rt>)

let private arithOf op a b =
  match op with
  | FPAdd -> AST.fadd a b
  | FPSub -> AST.fsub a b
  | FPMul -> AST.fmul a b
  | FPDiv -> AST.fdiv a b
  | FPSqrt -> AST.fsqrt a

/// <summary>
/// FPAdd, FPSub, FPMul, FPDiv and FPSqrt (A2.7), and what the operation
/// raised, for the caller to record. The operands are unpacked and the
/// operation done by the host in the direction the controls name, which
/// already answers the infinities and the zeros as the pseudocode's case
/// analysis does; the NaN, which IEEE leaves open, is put right after it.
/// FZ flushes the operands and a tiny result where the operation is the
/// instruction's own, and not where it is the double a half-precision one is
/// carried out on. The square root has one operand and the others two.
/// </summary>
let fpArithRaised bld ctl sz flushes op operands =
  let operands =
    if flushes then List.map (fpFlushIn bld ctl sz) operands else operands
  let a, b = List.head operands, List.last operands
  let res = tmpVar bld sz
  append bld {
    res := inForce ctl (arithOf op a b)
    res := AST.ite (isNaN sz res) (fpNaNResult bld ctl sz operands) res
  }
  let raised = fpRaised ctl sz op a b
  struct (res, if flushes then fpFlushOut bld ctl sz res raised else raised)

/// FPAdd, FPSub, FPMul, FPDiv and FPSqrt, with what they raised recorded.
let fpArith bld ctl sz op operands =
  let struct (res, raised) = fpArithRaised bld ctl sz true op operands
  fpRecord bld raised
  res

/// <summary>
/// FPMulAdd, the addend plus the product rounded once by the evaluator's own
/// fused operation, and what it raised, flushing as fpArithRaised does. A
/// quiet NaN addend does not win over an invalid product -- zero times
/// infinity answers the default NaN however the addend read -- while a
/// signalling one still comes back as itself, quieted.
/// </summary>
let fpMulAddRaised bld ctl sz flushes addend a b =
  let flushIn e = if flushes then fpFlushIn bld ctl sz e else e
  let addend = flushIn addend
  let a = flushIn a
  let b = flushIn b
  let res = tmpVar bld sz
  let badProduct =
    (isInfinity sz a .& isZero sz b) .| (isZero sz a .& isInfinity sz b)
  let processed = fpNaNResult bld ctl sz [ addend; a; b ]
  let nan = AST.ite (isQNaN sz addend .& badProduct) (fpDefaultNaN sz) processed
  append bld {
    res := inForce ctl (fma sz false false a b addend)
    res := AST.ite (isNaN sz res) nan res
  }
  let raised = fpFusedRaised ctl sz a b addend
  struct (res, if flushes then fpFlushOut bld ctl sz res raised else raised)

/// FPMulAdd, with what it raised recorded.
let fpMulAdd bld ctl sz addend a b =
  let struct (res, raised) = fpMulAddRaised bld ctl sz true addend a b
  fpRecord bld raised
  res

/// <summary>
/// FPCompare: NZCV for two operands -- 0011 unordered, 0110 equal, 1000 less
/// and 0010 greater -- raising Invalid for a signalling NaN, or for any NaN
/// where the compare signals on a quiet one as well, which VCMPE does.
/// </summary>
let fpCompare bld ctl sz signalsOnQuiet a b =
  let a = fpFlushIn bld ctl sz a
  let b = fpFlushIn bld ctl sz b
  let nzcv = tmpVar bld 4<rt>
  let unordered = isNaN sz a .| isNaN sz b
  let less = AST.ite (AST.flt a b) (numI32 0b1000 4<rt>) (numI32 0b0010 4<rt>)
  let ordered = AST.ite (AST.feq a b) (numI32 0b0110 4<rt>) less
  append bld { nzcv := AST.ite unordered (numI32 0b0011 4<rt>) ordered }
  let signals = if signalsOnQuiet then unordered else AST.b0
  fpInvalidOnly bld (signals .| isSNaN sz a .| isSNaN sz b)
  nzcv

/// The comparisons Advanced SIMD names.
type FPPredicate =
  | FPEqual
  | FPGreaterOrEqual
  | FPGreater

/// <summary>
/// FPCompareEQ, FPCompareGE and FPCompareGT: whether the relation holds,
/// which it never does with a NaN. Equality raises Invalid for a signalling
/// NaN only; the two orderings for any NaN.
/// </summary>
let fpComparePredicate bld ctl sz pred a b =
  let a = fpFlushIn bld ctl sz a
  let b = fpFlushIn bld ctl sz b
  let unordered = isNaN sz a .| isNaN sz b
  let holds, invalid =
    match pred with
    | FPEqual -> AST.feq a b, isSNaN sz a .| isSNaN sz b
    | FPGreaterOrEqual -> AST.fge a b, unordered
    | FPGreater -> AST.fgt a b, unordered
  fpInvalidOnly bld invalid
  AST.not unordered .& holds

/// <summary>
/// FPMax and FPMin. A NaN operand is propagated as FPProcessNaNs has it,
/// which a select on the comparison would lose, and a zero answer is signed
/// by both operands -- AND for the maximum, OR for the minimum -- so that plus
/// and minus zero give the same answer whichever way round they come.
/// </summary>
let fpMaxMin bld ctl sz isMax a b =
  let a = fpFlushIn bld ctl sz a
  let b = fpFlushIn bld ctl sz b
  let res = tmpVar bld sz
  let anyNaN = isNaN sz a .| isNaN sz b
  let wins = if isMax then AST.fgt a b else AST.flt a b
  let zeroSign =
    if isMax then fpZero sz a .& fpZero sz b else fpZero sz a .| fpZero sz b
  append bld {
    res := AST.ite wins a b
    res := AST.ite (isZero sz res) zeroSign res
    res := AST.ite anyNaN (fpNaNResult bld ctl sz [ a; b ]) res
  }
  fpInvalidOnly bld (isSNaN sz a .| isSNaN sz b)
  res
