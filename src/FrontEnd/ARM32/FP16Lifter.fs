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
/// The half-precision forms Armv8.2 (FEAT_FP16) gave the AArch32 VFP and
/// Advanced SIMD instructions. A VFP one names a single, reads its bottom
/// half and writes the result there with the top cleared, under FPSCR's
/// controls; an Advanced SIMD one reads lanes of halves under the standard
/// value. Either computes in doubles, which hold every half exactly, and
/// rounds back once, FPSCR.FZ16 flushing a half where FZ flushes a single.
/// </summary>
module internal B2R2.FrontEnd.ARM32.FP16Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.LiftingUtils
open B2R2.FrontEnd.ARM32.FloatingPoint
open B2R2.FrontEnd.ARM32.FPConversion
open B2R2.FrontEnd.ARM32.NEONLifter
open B2R2.FrontEnd.ARM32.FPLifter

let private isIntType = function
  | SIMDTypS16 | SIMDTypU16 | SIMDTypS32 | SIMDTypU32 -> true
  | _ -> false

/// Whether an instruction computes on halves: its data type is F16, or it
/// converts between halves and integers.
let private onHalves (ins: Instruction) =
  match ins.SIMDTyp with
  | Some(OneDT SIMDTypF16) -> true
  | Some(TwoDT(SIMDTypF16, t)) | Some(TwoDT(t, SIMDTypF16)) -> isIntType t
  | _ -> false

/// Whether an opcode's half-precision forms are lifted here.
let private isLifted = function
  | Op.VADD | Op.VSUB | Op.VMUL | Op.VDIV | Op.VSQRT | Op.VNMUL | Op.VFMA
  | Op.VFMS | Op.VFNMA | Op.VFNMS | Op.VMLA | Op.VMLS | Op.VNMLA | Op.VNMLS
  | Op.VABS | Op.VNEG | Op.VCMP | Op.VCMPE | Op.VMAXNM | Op.VMINNM | Op.VMAX
  | Op.VMIN | Op.VPADD | Op.VPMAX | Op.VPMIN | Op.VABD | Op.VRINTA
  | Op.VRINTN | Op.VRINTP | Op.VRINTM | Op.VRINTZ | Op.VRINTR | Op.VRINTX
  | Op.VCVT | Op.VCVTR | Op.VCVTA | Op.VCVTN | Op.VCVTP | Op.VCVTM | Op.VINS
  | Op.VMOVX | Op.VCEQ | Op.VCGE | Op.VCGT | Op.VCLE | Op.VCLT | Op.VACGE
  | Op.VACGT | Op.VACLE | Op.VACLT | Op.VRECPE | Op.VRSQRTE | Op.VRECPS
  | Op.VRSQRTS | Op.VFMAL | Op.VFMSL -> true
  | _ -> false

/// Whether this module lifts an instruction.
let handles (ins: Instruction) =
  onHalves ins && isLifted ins.Opcode

/// The controls an instruction reads: FPSCR for the VFP form, which names a
/// single, and the standard value for the Advanced SIMD one.
let private ctlOf opr = if isSingle opr then FPSCRValue else StandardValue

/// The halves of an operand: a single's bottom half, or every lane of a
/// doubleword or a quadword, read into temporaries.
let private halvesOf bld opr =
  if isSingle opr then
    let t = tmpVar bld 16<rt>
    append bld { t := AST.xtlo 16<rt> (regVar bld (regOf opr)) }
    [| t |]
  else
    readLanes bld 16 opr

/// The second operand's halves: its own, the one lane a scalar names in
/// every lane, or zeros for #0.
let private secondHalves bld count opr =
  match opr with
  | OprSIMD(SFReg(Scalar(r, Some idx))) ->
    let t = tmpVar bld 16<rt>
    append bld { t := AST.extract (regVar bld r) 16<rt> (int idx * 16) }
    Array.create count t
  | OprImm _ ->
    Array.create count (AST.num0 16<rt>)
  | _ ->
    halvesOf bld opr

/// Writes halves over a destination: a single's bottom half with the top
/// cleared, or every lane.
let private putHalves bld opr (hs: Expr[]) =
  if isSingle opr then
    let s = regVar bld (regOf opr)
    append bld { s := AST.zext 32<rt> hs[0] }
  else
    writeLanes bld opr hs

/// FPNeg of a half: its sign flipped, a NaN's too.
let private neg16 h = h <+> numU32 0x8000u 16<rt>

/// FPAbs of a half: its sign cleared.
let private abs16 h = h .& numU32 0x7fffu 16<rt>

/// An arithmetic operation on halves, carried out on doubles.
let private arith16 bld ctl op (hs: Expr[]) =
  let run (w: Expr[]) = fpArithRaised bld ctl 64<rt> false op (List.ofArray w)
  viaDoubleIn bld ctl run hs

/// FPMulAdd on halves: the addend plus the product, rounded once.
let private fused16 bld ctl addend a b =
  let run (w: Expr[]) = fpMulAddRaised bld ctl 64<rt> false w[0] w[1] w[2]
  viaDoubleIn bld ctl run [| addend; a; b |]

/// A selection among halves, which raises nothing a rounding could add: the
/// operation records what it raises itself.
let private chosen16 bld ctl (pick: Expr[] -> Expr) hs =
  viaDoubleIn bld ctl (fun w -> struct (pick w, AST.num0 32<rt>)) hs

/// Every half of an operation of one operand.
let private unary (ins: Instruction) bld f =
  let struct (dst, src) = getTwoOprs ins
  let ctl = ctlOf dst
  halvesOf bld src |> Array.map (f ctl) |> putHalves bld dst

/// Every half of an operation of two operands.
let private binary (ins: Instruction) bld f =
  let struct (dst, src1, src2) = getThreeOprs ins
  let ctl = ctlOf dst
  let a = halvesOf bld src1
  let b = secondHalves bld a.Length src2
  Array.map2 (f ctl) a b |> putHalves bld dst

/// Every half of an operation that accumulates into its destination.
let private accumulate (ins: Instruction) bld f =
  let struct (dst, src1, src2) = getThreeOprs ins
  let ctl = ctlOf dst
  let d = halvesOf bld dst
  let a = halvesOf bld src1
  let b = secondHalves bld a.Length src2
  Array.init a.Length (fun i -> f ctl d[i] a[i] b[i]) |> putHalves bld dst

/// The pairwise operations of doublewords: the adjacent pairs of Dn, then of
/// Dm, each to one lane.
let private pairwise (ins: Instruction) bld f =
  let struct (dst, src1, src2) = getThreeOprs ins
  let all = Array.append (halvesOf bld src1) (halvesOf bld src2)
  Array.init (all.Length / 2) (fun i ->
    f StandardValue all[2 * i] all[2 * i + 1])
  |> putHalves bld dst

/// The fused multiply-adds: FPNeg of the first source for VFMS and VFNMA, of
/// the accumulator for VFNMA and VFNMS, as the manual applies it to the
/// operand, so that a NaN comes out with its sign turned over.
let private fusedAcc ins bld negN negD =
  accumulate ins bld (fun ctl d a b ->
    let d = if negD then neg16 d else d
    let a = if negN then neg16 a else a
    fused16 bld ctl d a b)

/// The unfused multiply-accumulates: FPMul rounded, then FPAdd to the
/// accumulator, each with its own rounding and exceptions; negP flips the
/// product, for VMLS and VNMLA, and negD the accumulator, for VNMLA and VNMLS.
let private unfusedAcc ins bld negP negD =
  accumulate ins bld (fun ctl d a b ->
    let p = arith16 bld ctl FPMul [| a; b |]
    let p = if negP then neg16 p else p
    let d = if negD then neg16 d else d
    arith16 bld ctl FPAdd [| d; p |])

/// VCMP and VCMPE: FPCompare's NZCV in FPSCR, against a register or #0.
let private compare (ins: Instruction) bld signalsOnQuiet =
  let struct (o1, o2) = getTwoOprs ins
  let x = (halvesOf bld o1)[0]
  let y = (secondHalves bld 1 o2)[0]
  let a = halfToDouble bld x
  let b = halfToDouble bld y
  let nzcv = fpCompare bld FPSCRValue 64<rt> signalsOnQuiet a b
  let fpsr = regVar bld R.FPSR
  let flags = AST.zext 32<rt> nzcv << numI32 28 32<rt>
  append bld { fpsr := (fpsr .& numU32 0x0fffffffu 32<rt>) .| flags }

/// The Advanced SIMD compares: all ones in a lane where the relation holds.
let private neonCompare ins bld pred swapped absolute =
  binary ins bld (fun ctl x y ->
    let x, y = if swapped then y, x else x, y
    let mag e = if absolute then abs16 e else e
    let a = halfToDouble bld (mag x)
    let b = halfToDouble bld (mag y)
    let holds = fpComparePredicate bld ctl 64<rt> pred a b
    AST.ite holds (numU32 0xffffu 16<rt>) (AST.num0 16<rt>))

/// The rounding a conversion to an integer names: toward zero for VCVT, as
/// FPSCR says for VCVTR, and in its own direction for VCVTA, VCVTN, VCVTP and
/// VCVTM.
let private intRounding (ins: Instruction) =
  match ins.Opcode with
  | Op.VCVTR -> FPv8Lifter.Current
  | Op.VCVTA -> FPv8Lifter.TiesAway
  | Op.VCVTN -> FPv8Lifter.toNearest
  | Op.VCVTP -> FPv8Lifter.towardPlus
  | Op.VCVTM -> FPv8Lifter.towardMinus
  | _ -> FPv8Lifter.towardZero

/// The fraction bits a fixed-point conversion names, zero for an integer one.
let private fractionBits (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm f) -> int f
  | _ -> 0

/// The width of an integer data type, and whether it is unsigned.
let private intOf = function
  | SIMDTypS16 -> 16, false
  | SIMDTypU16 -> 16, true
  | SIMDTypS32 -> 32, false
  | SIMDTypU32 -> 32, true
  | _ -> raise InvalidOperandException

/// <summary>
/// A half to a signed or an unsigned integer or fixed-point number: unpacked
/// into a double, which holds it exactly, and converted there by FPToFixed,
/// saturating, rounding as the instruction names.
/// </summary>
let private toFixed bld ctl rounding size unsigned fbits h =
  let w = halfToDouble bld h
  let round sz e = FPv8Lifter.integral bld ctl rounding sz e
  fpToFixedBy bld ctl 64<rt> size fbits unsigned round w

/// <summary>
/// A signed or an unsigned integer or fixed-point number to a half: exact in
/// a double, divided there by two to the fraction bits, which is exact too,
/// and rounded once to a half -- to nearest for an Advanced SIMD or a
/// fixed-point conversion, and as FPSCR says for a VFP integer one.
/// </summary>
let private fromFixed bld ctl size unsigned fbits (e: Expr) =
  let ext = if unsigned then AST.zext else AST.sext
  let n = ext 64<rt> (AST.xtlo (RegType.fromBitWidth size) e)
  let scale = numU64 (uint64 (1023 - fbits) <<< 52) 64<rt>
  let d = tmpVar bld 64<rt>
  append bld { d := AST.fmul (AST.cast CastKind.SIntToFloat 64<rt> n) scale }
  let ctl = if fbits = 0 then ctl else StandardValue
  doubleToHalf bld ctl d (AST.num0 32<rt>)

/// The conversions between halves and integers or fixed-point numbers.
let private convert (ins: Instruction) bld =
  let struct (dst, src) =
    match ins.Operands with
    | ThreeOperands(d, s, _) -> struct (d, s)
    | _ -> getTwoOprs ins
  let ctl = ctlOf dst
  let fbits = fractionBits ins
  match ins.SIMDTyp with
  | Some(TwoDT(SIMDTypF16, t)) ->
    let size, unsigned = intOf t
    let ints =
      if isSingle src then [| regVar bld (regOf src) |]
      else readLanes bld size src
    let ctl = if isSingle src then ctl else StandardValue
    Array.map (fromFixed bld ctl size unsigned fbits) ints
    |> putHalves bld dst
  | Some(TwoDT(t, SIMDTypF16)) ->
    let size, unsigned = intOf t
    let rounding = intRounding ins
    let lane h = toFixed bld ctl rounding size unsigned fbits h
    let results = halvesOf bld src |> Array.map lane
    if isSingle dst then
      let s = regVar bld (regOf dst)
      append bld { s := results[0] }
    else
      results |> Array.map (AST.xtlo 16<rt>) |> writeLanes bld dst
  | _ ->
    raise InvalidOperandException

/// VINS: Sm's bottom half into Sd's top half, the bottom kept.
let private vins (ins: Instruction) bld =
  let struct (d, m) = transTwoOprs ins bld
  let top = AST.zext 32<rt> (AST.xtlo 16<rt> m) << numI32 16 32<rt>
  append bld { d := top .| (d .& numU32 0xffffu 32<rt>) }

/// VMOVX: Sm's top half into Sd's bottom half, the top cleared.
let private vmovx (ins: Instruction) bld =
  let struct (d, m) = transTwoOprs ins bld
  append bld { d := AST.zext 32<rt> (AST.xthi 16<rt> m) }

/// An instruction's rounding to an integral value, and whether it is exact.
let private rintOf (ins: Instruction) =
  match ins.Opcode with
  | Op.VRINTA -> FPv8Lifter.TiesAway, false
  | Op.VRINTN -> FPv8Lifter.toNearest, false
  | Op.VRINTP -> FPv8Lifter.towardPlus, false
  | Op.VRINTM -> FPv8Lifter.towardMinus, false
  | Op.VRINTZ -> FPv8Lifter.towardZero, false
  | Op.VRINTR -> FPv8Lifter.Current, false
  | _ -> FPv8Lifter.Current, true

/// VRINTA, VRINTN, VRINTP, VRINTM, VRINTZ, VRINTR and VRINTX.
let private vrint (ins: Instruction) bld =
  let rounding, exact = rintOf ins
  unary ins bld (fun ctl h ->
    chosen16 bld ctl (fun w ->
      FPv8Lifter.roundInt bld ctl rounding exact 64<rt> w[0]) [| h |])

/// FPMax and FPMin of halves.
let private maxMin bld ctl isMax a b =
  chosen16 bld ctl (fun w -> fpMaxMin bld ctl 64<rt> isMax w[0] w[1]) [| a; b |]

/// FPMaxNum and FPMinNum of halves.
let private maxMinNum bld ctl isMax a b =
  let pick (w: Expr[]) = FPv8Lifter.maxMinNum bld ctl isMax 64<rt> w[0] w[1]
  chosen16 bld ctl pick [| a; b |]

/// FPUnpack's flush of a half under FPSCR.FZ16: a denormal to a zero of its
/// sign, raising nothing.
let private flush16 bld h =
  let fz16 = AST.extract (regVar bld R.FPSCR) 1<rt> 19
  let t = tmpVar bld 16<rt>
  append bld { t := AST.ite (fz16 .& isDenormal 16<rt> h) (fpZero 16<rt> h) h }
  t

/// <summary>
/// The fraction of a nonzero half moved to the top of a 52-bit field, its
/// first set bit at bit 51 and dropped, and the exponent that goes with it: a
/// normal's own, and a denormal's lowered by how far its fraction had to
/// move -- the manual's loop, done as one shift by where the leading one is.
/// </summary>
let private normalised bld (x: Expr) =
  let rt = 64<rt>
  let exp = (x >> numI32 10 rt) .& numI32 0x1f rt
  let frac = (x .& numI32 0x3ff rt) << numI32 42 rt
  let lead =
    List.fold (fun acc k ->
      AST.ite (AST.extract x 1<rt> k) (numI32 (9 - k) rt) acc)
      (numI32 9 rt) [ 0 .. 9 ]
  let struct (f, e) = tmpVars2 bld rt
  let mask = (AST.num1 rt << numI32 52 rt) .- AST.num1 rt
  let isDen = exp == AST.num0 rt
  append bld {
    f := AST.ite isDen ((frac << (lead .+ AST.num1 rt)) .& mask) frac
    e := AST.ite isDen (AST.neg lead) exp
  }
  struct (f, e, isDen)

/// <summary>
/// FPRecipEstimate on a half: the fraction's top eight bits looked up and the
/// exponent reflected, on the standard value. A NaN gives the default NaN, an
/// infinity a zero and a zero an infinity, raising Divide-by-zero; a value
/// under 2^-16 overflows to an infinity, raising Overflow and Inexact, and
/// under FZ16 one of 2^14 or more is a zero, raising Underflow. A denormal's
/// fraction moves up by one place, or by two where its top bit is clear,
/// which lowers the exponent to -1.
/// </summary>
let private recipEstimate16 bld h =
  let rt = 64<rt>
  let h = flush16 bld h
  let x = AST.zext rt h
  let rawExp = (x >> numI32 10 rt) .& numI32 0x1f rt
  let isDen = rawExp == AST.num0 rt
  let frac0 = (x .& numI32 0x3ff rt) << numI32 42 rt
  let top = AST.extract frac0 1<rt> 51
  let mask = (AST.num1 rt << numI32 52 rt) .- AST.num1 rt
  let denFrac = AST.ite top (frac0 << AST.num1 rt) (frac0 << numI32 2 rt)
  let frac = AST.ite isDen (denFrac .& mask) frac0
  let exp = AST.ite isDen (AST.ite top (AST.num0 rt) (numI32 -1 rt)) rawExp
  let scaled = numI32 0x100 rt .| ((frac >> numI32 44 rt) .& numI32 0xff rt)
  let resExp = tmpVar bld rt
  append bld { resExp := numI32 29 rt .- exp }
  let fracE = (recipEstimate9 scaled .& numI32 0xff rt) << numI32 44 rt
  let atZero = (AST.num1 rt << numI32 51 rt) .| (fracE >> AST.num1 rt)
  let atMinusOne = (AST.num1 rt << numI32 50 rt) .| (fracE >> numI32 2 rt)
  let minusOne = resExp == numI32 -1 rt
  let fracF =
    AST.ite (resExp == AST.num0 rt) atZero (AST.ite minusOne atMinusOne fracE)
  let outExp = AST.ite minusOne (AST.num0 rt) resExp
  let body =
    (x .& numI32 0x8000 rt)
    .| ((outExp .& numI32 0x1f rt) << numI32 10 rt)
    .| ((fracF >> numI32 42 rt) .& numI32 0x3ff rt)
  let sign = AST.extract h 1<rt> 15
  let nan = isNaN 16<rt> h
  let zero = isZero 16<rt> h
  let tiny = isDen .& AST.not zero .& ((x .& numI32 0x300 rt) == AST.num0 rt)
  let fz16 = AST.extract (regVar bld R.FPSCR) 1<rt> 19
  let huge = fz16 .& (rawExp .>= numI32 29 rt) .& (rawExp .< numI32 31 rt)
  let res = tmpVar bld 16<rt>
  append bld {
    res := AST.xtlo 16<rt> body
    res := AST.ite (isInfinity 16<rt> h .| huge) (fpZero 16<rt> h) res
    res := AST.ite (zero .| tiny) (fpInfinity 16<rt> sign) res
    res := AST.ite nan (fpDefaultNaN 16<rt>) res
  }
  fpRecord bld (fpBits (isSNaN 16<rt> h) zero tiny huge tiny)
  res

/// <summary>
/// FPRSqrtEstimate on a half: scaled into [0.25, 1) with its exponent's
/// parity kept, its top bits looked up and the exponent halved, on the
/// standard value. A NaN gives the default NaN, a zero an infinity, raising
/// Divide-by-zero, a negative number the default NaN, raising Invalid, and
/// plus infinity a zero.
/// </summary>
let private rsqrtEstimate16 bld h =
  let rt = 64<rt>
  let h = flush16 bld h
  let struct (frac, exp, _) = normalised bld (AST.zext rt h)
  let odd = AST.extract exp 1<rt> 0
  let atEven = numI32 0x100 rt .| ((frac >> numI32 44 rt) .& numI32 0xff rt)
  let atOdd = numI32 0x80 rt .| ((frac >> numI32 45 rt) .& numI32 0x7f rt)
  let est = recipSqrtEstimate9 bld (AST.ite odd atOdd atEven)
  let resExp = (numI32 44 rt .- exp) ?>> AST.num1 rt
  let body =
    ((resExp .& numI32 0x1f rt) << numI32 10 rt)
    .| ((est .& numI32 0xff rt) << numI32 2 rt)
  let nan = isNaN 16<rt> h
  let zero = isZero 16<rt> h
  let negative = AST.extract h 1<rt> 15 .& AST.not nan .& AST.not zero
  let res = tmpVar bld 16<rt>
  append bld {
    res := AST.xtlo 16<rt> body
    res := AST.ite (isInfinity 16<rt> h) (AST.num0 16<rt>) res
    res := AST.ite (negative .| nan) (fpDefaultNaN 16<rt>) res
    res := AST.ite zero (fpInfinity 16<rt> (AST.extract h 1<rt> 15)) res
  }
  let invalid = isSNaN 16<rt> h .| negative
  fpRecord bld (fpBits invalid zero fpNone fpNone fpNone)
  res

/// <summary>
/// FPRecipStep and FPRSqrtStep on halves, which are not fused: the product
/// rounded first, then two less it, or three less it halved with one
/// rounding. An infinity and a zero make the product a zero, and a NaN gives
/// the default NaN, the standard value's.
/// </summary>
let private recipStep16 bld isSqrt a b =
  let a = flush16 bld a
  let b = flush16 bld b
  let anyNaN = isNaN 16<rt> a .| isNaN 16<rt> b
  let degenerate =
    (isInfinity 16<rt> a .& isZero 16<rt> b)
    .| (isZero 16<rt> a .& isInfinity 16<rt> b)
  let struct (x, y) = tmpVars2 bld 16<rt>
  append bld {
    x := AST.ite (anyNaN .| degenerate) (AST.num0 16<rt>) a
    y := AST.ite (anyNaN .| degenerate) (AST.num0 16<rt>) b
  }
  let p = arith16 bld StandardValue FPMul [| x; y |]
  let r =
    if isSqrt then
      let halved (w: Expr[]) =
        let half = numU64 0x3fe0000000000000UL 64<rt>
        struct (AST.fmul (AST.fsub w[0] w[1]) half, AST.num0 32<rt>)
      viaDoubleIn bld StandardValue halved [| numU32 0x4200u 16<rt>; p |]
    else
      arith16 bld StandardValue FPSub [| numU32 0x4000u 16<rt>; p |]
  fpInvalidOnly bld (isSNaN 16<rt> a .| isSNaN 16<rt> b)
  AST.ite anyNaN (fpDefaultNaN 16<rt>) r

/// Every half of a register: a single's two, or a doubleword's four.
let private allHalves bld opr =
  if isSingle opr then
    let s = regVar bld (regOf opr)
    let struct (lo, hi) = tmpVars2 bld 16<rt>
    append bld { lo := AST.xtlo 16<rt> s }
    append bld { hi := AST.xthi 16<rt> s }
    [| lo; hi |]
  else
    readLanes bld 16 opr

/// <summary>
/// VFMAL and VFMSL, by vector and by scalar (DDI0487F.c F6.1.89, F6.1.90,
/// F6.1.92 and F6.1.93): every word of Dd or Qd accumulates the product of
/// the halves of Sn and Sm, or Dn and Dm, in the same place, by FPMulAddH on
/// the standard value -- the halves widened exactly, the product exact in a
/// single and the sum rounded once -- VFMSL negating the first half before
/// anything else. By scalar, every word takes the one half the index names.
/// </summary>
let private vfmal (ins: Instruction) bld isSub =
  let struct (dst, src1, src2) = getThreeOprs ins
  let acc = readLanes bld 32 dst
  let a = allHalves bld src1
  let b =
    match src2 with
    | OprSIMD(SFReg(Scalar(r, Some idx))) ->
      let t = tmpVar bld 16<rt>
      append bld { t := AST.extract (regVar bld r) 16<rt> (int idx * 16) }
      Array.create acc.Length t
    | _ ->
      allHalves bld src2
  Array.init acc.Length (fun e ->
    let x = halfToSingle bld (if isSub then neg16 a[e] else a[e])
    let y = halfToSingle bld b[e]
    fpMulAdd bld StandardValue 32<rt> acc[e] x y)
  |> writeLanes bld dst

let private body (ins: Instruction) bld =
  match ins.Opcode with
  | Op.VADD ->
    binary ins bld (fun ctl a b -> arith16 bld ctl FPAdd [| a; b |])
  | Op.VSUB ->
    binary ins bld (fun ctl a b -> arith16 bld ctl FPSub [| a; b |])
  | Op.VMUL ->
    binary ins bld (fun ctl a b -> arith16 bld ctl FPMul [| a; b |])
  | Op.VDIV ->
    binary ins bld (fun ctl a b -> arith16 bld ctl FPDiv [| a; b |])
  | Op.VSQRT ->
    unary ins bld (fun ctl a -> arith16 bld ctl FPSqrt [| a |])
  | Op.VNMUL ->
    binary ins bld (fun ctl a b -> neg16 (arith16 bld ctl FPMul [| a; b |]))
  | Op.VABD ->
    binary ins bld (fun ctl a b -> abs16 (arith16 bld ctl FPSub [| a; b |]))
  | Op.VFMA ->
    fusedAcc ins bld false false
  | Op.VFMS ->
    fusedAcc ins bld true false
  | Op.VFNMA ->
    fusedAcc ins bld true true
  | Op.VFNMS ->
    fusedAcc ins bld false true
  | Op.VMLA ->
    unfusedAcc ins bld false false
  | Op.VMLS ->
    unfusedAcc ins bld true false
  | Op.VNMLA ->
    unfusedAcc ins bld true true
  | Op.VNMLS ->
    unfusedAcc ins bld false true
  | Op.VABS ->
    unary ins bld (fun _ h -> abs16 h)
  | Op.VNEG ->
    unary ins bld (fun _ h -> neg16 h)
  | Op.VCMP ->
    compare ins bld false
  | Op.VCMPE ->
    compare ins bld true
  | Op.VMAX ->
    binary ins bld (fun ctl a b -> maxMin bld ctl true a b)
  | Op.VMIN ->
    binary ins bld (fun ctl a b -> maxMin bld ctl false a b)
  | Op.VMAXNM ->
    binary ins bld (fun ctl a b -> maxMinNum bld ctl true a b)
  | Op.VMINNM ->
    binary ins bld (fun ctl a b -> maxMinNum bld ctl false a b)
  | Op.VPADD ->
    pairwise ins bld (fun ctl a b -> arith16 bld ctl FPAdd [| a; b |])
  | Op.VPMAX ->
    pairwise ins bld (fun ctl a b -> maxMin bld ctl true a b)
  | Op.VPMIN ->
    pairwise ins bld (fun ctl a b -> maxMin bld ctl false a b)
  | Op.VCEQ ->
    neonCompare ins bld FPEqual false false
  | Op.VCGE ->
    neonCompare ins bld FPGreaterOrEqual false false
  | Op.VCGT ->
    neonCompare ins bld FPGreater false false
  | Op.VCLE ->
    neonCompare ins bld FPGreaterOrEqual true false
  | Op.VCLT ->
    neonCompare ins bld FPGreater true false
  | Op.VACGE ->
    neonCompare ins bld FPGreaterOrEqual false true
  | Op.VACGT ->
    neonCompare ins bld FPGreater false true
  | Op.VACLE ->
    neonCompare ins bld FPGreaterOrEqual true true
  | Op.VACLT ->
    neonCompare ins bld FPGreater true true
  | Op.VRECPE ->
    unary ins bld (fun _ h -> recipEstimate16 bld h)
  | Op.VRSQRTE ->
    unary ins bld (fun _ h -> rsqrtEstimate16 bld h)
  | Op.VRECPS ->
    binary ins bld (fun _ a b -> recipStep16 bld false a b)
  | Op.VRSQRTS ->
    binary ins bld (fun _ a b -> recipStep16 bld true a b)
  | Op.VFMAL ->
    vfmal ins bld false
  | Op.VFMSL ->
    vfmal ins bld true
  | Op.VINS ->
    vins ins bld
  | Op.VMOVX ->
    vmovx ins bld
  | Op.VCVT | Op.VCVTR | Op.VCVTA | Op.VCVTN | Op.VCVTP | Op.VCVTM ->
    convert ins bld
  | _ ->
    vrint ins bld

/// Lifts a half-precision form, under its condition.
let translate (ins: Instruction) bld =
  conditional ins bld (fun () -> body ins bld)
