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
/// The floating-point instructions on singles and doubles, VFP and Advanced
/// SIMD alike, lifted on the model in FloatingPoint and FPConversion.
///
/// <para>A VFP instruction works on one S or D register and reads FPSCR. An
/// Advanced SIMD one works on every single-precision lane of a D or a Q
/// register and reads the standard value; it is told apart by its operands,
/// lanes of singles in a register that is not an S register. Every lane of a
/// source is read before any lane of the destination is written, since the
/// two can be the same register.</para>
/// </summary>
module internal B2R2.FrontEnd.ARM32.FPLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.LiftingUtils
open B2R2.FrontEnd.ARM32.GeneralLifter
open B2R2.FrontEnd.ARM32.NEONLifter
open B2R2.FrontEnd.ARM32.FloatingPoint
open B2R2.FrontEnd.ARM32.FPConversion

/// Lifts an instruction's body under its condition.
let private conditional (ins: Instruction) bld body =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    body ()
    putEndLabel bld lblIgnore
  }

/// The register an operand names.
let private regOf = function
  | OprSIMD(SFReg(Vector r)) -> r
  | OprSIMD(SFReg(Scalar(r, _))) -> r
  | _ -> raise InvalidOperandException

/// Whether an operand is a single-precision register, which only a VFP
/// instruction names.
let private isSingle opr =
  let r = regOf opr
  r >= R.S0 && r <= R.S31

/// Whether an operand is a quadword register.
let private isQuad opr =
  let r = regOf opr
  r >= R.Q0 && r <= R.Q15

/// Whether an instruction is the Advanced SIMD form: lanes of singles in a
/// doubleword or a quadword. A VFP one names an S register, or a D register
/// holding a double.
let private isAdvSIMD (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o, _)
  | ThreeOperands(o, _, _) ->
    not (isSingle o) && ins.SIMDTyp = Some(OneDT SIMDTypF32)
  | _ ->
    false

/// FPNeg, which flips the sign bit of whatever it is given, a NaN included.
let private fpNeg sz e = e <+> signOf sz

/// The doublewords of an Advanced SIMD operand, lowest first.
let private doublewords bld opr =
  let r = regOf opr
  if isQuad opr then
    let struct (hi, lo) = pseudoRegVar128 bld r
    [| lo; hi |]
  else
    [| regVar bld r |]

/// <summary>
/// The lanes of an Advanced SIMD operand, lowest first, read into
/// temporaries, so that a destination that is a source as well is read whole
/// before anything is written to it.
/// </summary>
let private readLanes bld esize opr =
  let rt = RegType.fromBitWidth esize
  doublewords bld opr
  |> Array.collect (fun dw ->
    Array.init (64 / esize) (fun i ->
      let t = tmpVar bld rt
      append bld { t := AST.extract dw rt (i * esize) }
      t))

/// Writes lanes, lowest first, over an Advanced SIMD destination.
let private writeLanes bld opr (lanes: Expr[]) =
  let dws = doublewords bld opr
  let per = lanes.Length / dws.Length
  dws
  |> Array.iteri (fun k dw ->
    append bld { dw := AST.revConcatRange lanes (k * per) per })

/// The second operand's lanes: the vector's own, or, by scalar, the one
/// element it names in every lane.
let private secondLanes bld count opr =
  match opr with
  | OprSIMD(SFReg(Scalar(r, Some idx))) ->
    let t = tmpVar bld 32<rt>
    append bld { t := AST.extract (regVar bld r) 32<rt> (int idx * 32) }
    Array.create count t
  | _ ->
    readLanes bld 32 opr

/// Every lane of an Advanced SIMD operation of one operand.
let private neonUnary (ins: Instruction) bld lane =
  let struct (dst, src) = getTwoOprs ins
  readLanes bld 32 src |> Array.map lane |> writeLanes bld dst

/// Every lane of an Advanced SIMD operation of two operands.
let private neonBinary (ins: Instruction) bld lane =
  let struct (dst, src1, src2) = getThreeOprs ins
  let a = readLanes bld 32 src1
  let b = secondLanes bld a.Length src2
  Array.map2 lane a b |> writeLanes bld dst

/// Every lane of an Advanced SIMD operation that accumulates into its
/// destination.
let private neonAccumulate (ins: Instruction) bld lane =
  let struct (dst, src1, src2) = getThreeOprs ins
  let d = readLanes bld 32 dst
  let a = readLanes bld 32 src1
  let b = secondLanes bld a.Length src2
  Array.init a.Length (fun i -> lane d[i] a[i] b[i]) |> writeLanes bld dst

/// The registers a VFP instruction names, the destination first; an
/// immediate is not one.
let private vfpRegs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(d, OprImm _) -> [| regOf d |]
  | TwoOperands(d, m) -> [| regOf d; regOf m |]
  | ThreeOperands(d, n, m) -> [| regOf d; regOf n; regOf m |]
  | _ -> raise InvalidOperandException

/// The number of a VFP register in its file: S0 to S31, or D0 to D31.
let private fileIndex (r: Register) =
  if r <= R.S31 then int r - int R.S0 else int r - int R.D0

/// Whether a register is in a first bank -- S0-S7, D0-D3 or D16-D19 --
/// which keeps a VFP instruction scalar whatever FPSCR.Len says.
let private isScalarBank (r: Register) =
  let i = fileIndex r
  if r <= R.S31 then i &&& 0x18 = 0 else i &&& 0xc = 0

/// A register some places further along its bank -- of eight singles or of
/// four doubles -- wrapping round inside it.
let private along (r: Register) places =
  let first, mask = if r <= R.S31 then int R.S0, 7 else int R.D0, 3
  let i = fileIndex r
  enum<Register> (first + (((i + places) &&& mask) ||| (i &&& ~~~mask)))

/// How many steps after the first a short vector of a stride takes at most: a
/// vector of singles a step apart runs to eight registers, one of doubles to
/// four, and each to half as many two apart (DDI0406C Table D11-1). A longer
/// one would name a register twice, which is UNPREDICTABLE, and stops there.
let private vectorSteps (r: Register) stride =
  let bank = if r <= R.S31 then 8 else 4
  bank / stride - 1

/// <summary>
/// A VFP instruction under FPSCR.Len and FPSCR.Stride (DDI0406C Appendix
/// D11). With its destination outside the first bank it repeats over a short
/// vector of Len + 1 steps, every register the stride further along its bank
/// each step and wrapping round inside it: the destination and the first
/// source always, and the last source unless it is in the first bank, where
/// it is a scalar to every step. A step reads what the one before wrote.
/// The stride is two where the field's top bit is set: 0b11, the only other
/// value the appendix permits, and the two UNPREDICTABLE ones taken as that
/// bit says.
/// </summary>
let private vfpVector bld (regs: Register[]) step =
  step regs
  if isScalarBank regs[0] then
    ()
  else
    let fpscr = regVar bld R.FPSCR
    let len = AST.extract fpscr 3<rt> 16
    let last = regs.Length - 1
    let moves k = k = 0 || k < last || not (isScalarBank regs[k])
    let at places =
      regs |> Array.mapi (fun k r -> if moves k then along r places else r)
    let lblOne = label bld "StrideOne"
    let lblTwo = label bld "StrideTwo"
    let lblEnd = label bld "VectorEnd"
    let wide = AST.extract fpscr 1<rt> 21
    append bld { AST.cjmp wide (AST.jmpDest lblTwo) (AST.jmpDest lblOne) }
    for stride, lbl in [ 1, lblOne; 2, lblTwo ] do
      append bld { AST.lmark lbl }
      for i in 1 .. vectorSteps regs[0] stride do
        let lblStep = label bld "VectorStep"
        let short = len .< numI32 i 3<rt>
        append bld {
          AST.cjmp short (AST.jmpDest lblEnd) (AST.jmpDest lblStep)
          AST.lmark lblStep
        }
        step (at (i * stride))
      append bld { AST.jmp (AST.jmpDest lblEnd) }
    append bld { AST.lmark lblEnd }

/// A VFP operation of one operand, over a short vector where FPSCR says so.
let private vfpUnary (ins: Instruction) bld op =
  vfpVector bld (vfpRegs ins) (fun regs ->
    let d = regVar bld regs[0]
    let r = op (Expr.typeOf d) (regVar bld regs[1])
    append bld { d := r })

/// A VFP operation of two operands, over a short vector where FPSCR says
/// so.
let private vfpBinary (ins: Instruction) bld op =
  vfpVector bld (vfpRegs ins) (fun regs ->
    let d = regVar bld regs[0]
    let r = op (Expr.typeOf d) (regVar bld regs[1]) (regVar bld regs[2])
    append bld { d := r })

/// A VFP operation that accumulates into its destination, over a short
/// vector where FPSCR says so.
let private vfpAccumulate (ins: Instruction) bld op =
  vfpVector bld (vfpRegs ins) (fun regs ->
    let d = regVar bld regs[0]
    let r = op (Expr.typeOf d) d (regVar bld regs[1]) (regVar bld regs[2])
    append bld { d := r })

/// A VFP operation that Appendix D11 leaves out of the short vectors: one of
/// two operands, or, accumulating, of three.
let private vfpScalar (ins: Instruction) bld op =
  match ins.Operands with
  | TwoOperands _ ->
    let struct (dst, src) = transTwoOprs ins bld
    let r = op (Expr.typeOf dst) dst src src
    append bld { dst := r }
  | _ ->
    let struct (dst, a, b) = transThreeOprs ins bld
    let r = op (Expr.typeOf dst) dst a b
    append bld { dst := r }

let private arith ins bld op =
  if isAdvSIMD ins then
    neonBinary ins bld (fun a b ->
      fpArith bld StandardValue 32<rt> op [ a; b ])
  else
    vfpBinary ins bld (fun sz a b -> fpArith bld FPSCRValue sz op [ a; b ])

/// VADD (floating-point): FPAdd.
let vadd ins bld = conditional ins bld (fun () -> arith ins bld FPAdd)

/// VSUB (floating-point): FPSub.
let vsub ins bld = conditional ins bld (fun () -> arith ins bld FPSub)

/// VMUL (floating-point), by vector or by scalar: FPMul.
let vmul ins bld = conditional ins bld (fun () -> arith ins bld FPMul)

/// VDIV: FPDiv.
let vdiv ins bld = conditional ins bld (fun () -> arith ins bld FPDiv)

/// VSQRT: FPSqrt.
let vsqrt ins bld =
  conditional ins bld (fun () ->
    vfpUnary ins bld (fun sz e -> fpArith bld FPSCRValue sz FPSqrt [ e ]))

/// VNMUL: FPNeg(FPMul(n, m)), the product's sign flipped, a NaN's too.
let vnmul ins bld =
  conditional ins bld (fun () ->
    vfpBinary ins bld (fun sz a b ->
      fpNeg sz (fpArith bld FPSCRValue sz FPMul [ a; b ])))

/// <summary>
/// The unfused multiply-accumulates: FPMul, then FPAdd of the product to the
/// accumulator, each rounding and raising on its own. negProduct and negAcc
/// say which of the two FPNeg flips first: the product for VMLS and VNMLA,
/// the accumulator for VNMLA and VNMLS.
/// </summary>
let private mulAcc bld ctl negProduct negAcc sz d a b =
  let p = fpArith bld ctl sz FPMul [ a; b ]
  let p = if negProduct then fpNeg sz p else p
  let d = if negAcc then fpNeg sz d else d
  fpArith bld ctl sz FPAdd [ d; p ]

let private accumulate ins bld negProduct negAcc =
  if isAdvSIMD ins then
    neonAccumulate ins bld (mulAcc bld StandardValue negProduct negAcc 32<rt>)
  else
    vfpAccumulate ins bld (mulAcc bld FPSCRValue negProduct negAcc)

/// VMLA (floating-point), by vector or by scalar.
let vmla ins bld =
  conditional ins bld (fun () -> accumulate ins bld false false)

/// VMLS (floating-point), by vector or by scalar.
let vmls ins bld =
  conditional ins bld (fun () -> accumulate ins bld true false)

/// VNMLA: FPAdd(FPNeg(d), FPNeg(product)).
let vnmla ins bld =
  conditional ins bld (fun () -> accumulate ins bld true true)

/// VNMLS: FPAdd(FPNeg(d), product).
let vnmls ins bld =
  conditional ins bld (fun () -> accumulate ins bld false true)

/// <summary>
/// The fused multiply-accumulates, FPMulAdd: negN flips the first operand
/// for VFMS and VFNMA, and negD the accumulator for VFNMA and VFNMS, before
/// the one rounding.
/// </summary>
let private fused bld ctl negN negD sz d a b =
  let a = if negN then fpNeg sz a else a
  let d = if negD then fpNeg sz d else d
  fpMulAdd bld ctl sz d a b

let private fusedAccumulate ins bld negN negD =
  if isAdvSIMD ins then
    neonAccumulate ins bld (fused bld StandardValue negN negD 32<rt>)
  else
    vfpScalar ins bld (fused bld FPSCRValue negN negD)

/// VFMA.
let vfma ins bld =
  conditional ins bld (fun () -> fusedAccumulate ins bld false false)

/// VFMS.
let vfms ins bld =
  conditional ins bld (fun () -> fusedAccumulate ins bld true false)

/// VFNMA.
let vfnma ins bld =
  conditional ins bld (fun () -> fusedAccumulate ins bld true true)

/// VFNMS.
let vfnms ins bld =
  conditional ins bld (fun () -> fusedAccumulate ins bld false true)

/// VABS (floating-point): the sign bit cleared, raising nothing.
let vabs ins bld =
  conditional ins bld (fun () ->
    if isAdvSIMD ins then neonUnary ins bld (fun e -> e .& magnitudeOf 32<rt>)
    else vfpUnary ins bld (fun sz e -> e .& magnitudeOf sz))

/// VNEG (floating-point): the sign bit flipped, raising nothing.
let vneg ins bld =
  conditional ins bld (fun () ->
    if isAdvSIMD ins then neonUnary ins bld (fpNeg 32<rt>)
    else vfpUnary ins bld fpNeg)

/// Whether a VMOV is the VFP one, between registers or of an immediate into
/// one.
let isVFPMove (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(OprSIMD _, (OprSIMD _ | OprImm _)) -> not (isSIMDF32Imm ins)
  | _ -> false

/// <summary>
/// VMOV between VFP registers, or of an immediate into one, over a short
/// vector where FPSCR says so. The immediate is the float's own bits.
/// </summary>
let vmov (ins: Instruction) bld =
  conditional ins bld (fun () ->
    match ins.Operands with
    | TwoOperands(_, OprImm imm) ->
      vfpVector bld (vfpRegs ins) (fun regs ->
        let d = regVar bld regs[0]
        let sz = Expr.typeOf d
        append bld { d := numU64 (uint64 imm) sz })
    | _ ->
      vfpUnary ins bld (fun _ e -> e))

/// VABD (floating-point): FPAbs(FPSub(n, m)).
let vabd ins bld =
  conditional ins bld (fun () ->
    neonBinary ins bld (fun a b ->
      fpArith bld StandardValue 32<rt> FPSub [ a; b ] .& magnitudeOf 32<rt>))

/// VMAX and VMIN (floating-point): FPMax and FPMin.
let vmaxmin ins bld isMax =
  conditional ins bld (fun () ->
    neonBinary ins bld (fpMaxMin bld StandardValue 32<rt> isMax))

let private pairwise (ins: Instruction) bld op =
  let struct (dst, src1, src2) = getThreeOprs ins
  let n = readLanes bld 32 src1
  let m = readLanes bld 32 src2
  writeLanes bld dst [| op n[0] n[1]; op m[0] m[1] |]

/// VPADD (floating-point): FPAdd of adjacent pairs, the first operand's in
/// the low lane.
let vpadd ins bld =
  conditional ins bld (fun () ->
    pairwise ins bld (fun a b ->
      fpArith bld StandardValue 32<rt> FPAdd [ a; b ]))

/// VPMAX and VPMIN (floating-point).
let vpmaxmin ins bld isMax =
  conditional ins bld (fun () ->
    pairwise ins bld (fpMaxMin bld StandardValue 32<rt> isMax))

/// <summary>
/// VCMP and VCMPE: FPCompare's NZCV, written to FPSCR's top four bits. The
/// second operand is a register or #0.0; VCMPE raises Invalid for a quiet
/// NaN as well as a signalling one.
/// </summary>
let vcmp (ins: Instruction) bld signalsOnQuiet =
  conditional ins bld (fun () ->
    let struct (o1, o2) = getTwoOprs ins
    let a = transOpr ins bld o1
    let sz = Expr.typeOf a
    let b =
      match o2 with
      | OprImm _ -> AST.num0 sz
      | _ -> transOpr ins bld o2
    let nzcv = fpCompare bld FPSCRValue sz signalsOnQuiet a b
    let fpscr = regVar bld R.FPSCR
    let flags = AST.zext 32<rt> nzcv << numI32 28 32<rt>
    append bld { fpscr := (fpscr .& numU32 0x0fffffffu 32<rt>) .| flags })

/// <summary>
/// The Advanced SIMD compares: all ones in a lane where the relation holds
/// and zero elsewhere. The second operand is a register or #0; swapped puts
/// it first, which is how the LE and LT forms are the GE and GT ones, and
/// absolute compares magnitudes, which is VACGE and VACGT.
/// </summary>
let private neonCompare (ins: Instruction) bld pred swapped absolute =
  let struct (dst, src1, src2) = getThreeOprs ins
  let a = readLanes bld 32 src1
  let b =
    match src2 with
    | OprImm _ -> Array.create a.Length (AST.num0 32<rt>)
    | _ -> readLanes bld 32 src2
  let lane x y =
    let x, y = if swapped then y, x else x, y
    let mag e = if absolute then e .& magnitudeOf 32<rt> else e
    let holds = fpComparePredicate bld StandardValue 32<rt> pred (mag x) (mag y)
    AST.ite holds (numU32 0xffffffffu 32<rt>) (AST.num0 32<rt>)
  Array.map2 lane a b |> writeLanes bld dst

/// VCEQ, VCGE, VCGT, VCLE and VCLT (floating-point), and VACGE, VACGT,
/// VACLE and VACLT.
let vcompare ins bld pred swapped absolute =
  conditional ins bld (fun () -> neonCompare ins bld pred swapped absolute)

/// <summary>
/// FPRecipStep and FPRSqrtStep (A2.7), which are not fused: two minus the
/// product, or three minus it halved, the product rounded first. One operand
/// an infinity and the other a zero gives the constant itself, 2.0 or 1.5,
/// with nothing raised, and a NaN the NaN FPProcessNaNs picks; neither
/// computes the product, so those lanes compute it on zeros instead.
/// </summary>
let private recipStep bld isSqrt a b =
  let rt = 32<rt>
  let ctl = StandardValue
  let a = fpFlushIn bld ctl rt a
  let b = fpFlushIn bld ctl rt b
  let anyNaN = isNaN rt a .| isNaN rt b
  let degenerate =
    (isInfinity rt a .& isZero rt b) .| (isZero rt a .& isInfinity rt b)
  let struct (x, y) = tmpVars2 bld rt
  append bld {
    x := AST.ite (anyNaN .| degenerate) (AST.num0 rt) a
    y := AST.ite (anyNaN .| degenerate) (AST.num0 rt) b
  }
  let p = fpArith bld ctl rt FPMul [ x; y ]
  let constant = numU32 (if isSqrt then 0x40400000u else 0x40000000u) rt
  let diff = fpArith bld ctl rt FPSub [ constant; p ]
  let half = numU32 0x3f000000u rt
  let r = if isSqrt then fpArith bld ctl rt FPMul [ diff; half ] else diff
  fpInvalidOnly bld (isSNaN rt a .| isSNaN rt b)
  AST.ite anyNaN (fpNaNResult bld ctl rt [ a; b ]) r

/// VRECPS and VRSQRTS.
let vrecpstep ins bld isSqrt =
  conditional ins bld (fun () -> neonBinary ins bld (recipStep bld isSqrt))

/// The widths a conversion's data types name.
let private dtWidth = function
  | SIMDTypF64 -> 64
  | SIMDTypF16 | SIMDTypS16 | SIMDTypU16 -> 16
  | _ -> 32

let private isUnsignedDt = function
  | SIMDTypU16 | SIMDTypU32 -> true
  | _ -> false

let private isFloatDt = function
  | SIMDTypF16 | SIMDTypF32 | SIMDTypF64 -> true
  | _ -> false

/// <summary>
/// VCVT and VCVTR between a VFP register's float and a 32-bit integer in an
/// S register. To an integer, VCVT rounds toward zero and VCVTR in the
/// direction FPSCR names; from one, both round as FPSCR names.
/// </summary>
let private vfpIntConvert (ins: Instruction) bld towardZero dst src =
  let struct (d, s) = transTwoOprs ins bld
  let ctl = FPSCRValue
  let r =
    if isFloatDt dst then
      fixedToFP bld ctl (Expr.typeOf d) 32 0 (isUnsignedDt src) false s
    else
      let unsigned = isUnsignedDt dst
      fpToFixed bld ctl (Expr.typeOf s) 32 0 unsigned towardZero s
  append bld { d := r }

/// <summary>
/// VCVT between a VFP register's float and a fixed-point number of 16 or 32
/// bits in the same register: to fixed point toward zero, the result
/// extended to the register's width, and from it to nearest.
/// </summary>
let private vfpFixedConvert (ins: Instruction) bld dst src fbits =
  let struct (o, _, _) = getThreeOprs ins
  let reg = transOpr ins bld o
  let sz = Expr.typeOf reg
  let r =
    if isFloatDt dst then
      let unsigned = isUnsignedDt src
      fixedToFP bld FPSCRValue sz (dtWidth src) fbits unsigned true reg
    else
      let unsigned = isUnsignedDt dst
      let word =
        fpToFixed bld FPSCRValue sz (dtWidth dst) fbits unsigned true reg
      if sz = 32<rt> then word
      elif unsigned then AST.zext sz word
      else AST.sext sz word
  append bld { reg := r }

let private fbitsOf (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm fbits) -> int fbits
  | _ -> 0

/// Whether a conversion is the Advanced SIMD one: lanes of singles and
/// 32-bit integers in a register that is not an S register.
let private isAdvSIMDConvert (ins: Instruction) dst src =
  match ins.Operands with
  | TwoOperands(o, _)
  | ThreeOperands(o, _, _) ->
    not (isSingle o) && dst <> SIMDTypF64 && src <> SIMDTypF64
  | _ ->
    false

let private convert (ins: Instruction) bld towardZero dst src =
  match dst, src with
  | SIMDTypF64, SIMDTypF32 ->
    vfpScalar ins bld (fun _ _ e _ -> fpSingleToDouble bld FPSCRValue e)
  | SIMDTypF32, SIMDTypF64 ->
    vfpScalar ins bld (fun _ _ e _ -> fpDoubleToSingle bld FPSCRValue e)
  | _ ->
    match ins.Operands with
    | ThreeOperands _ -> vfpFixedConvert ins bld dst src (fbitsOf ins)
    | _ -> vfpIntConvert ins bld towardZero dst src

let private isConvertible = function
  | SIMDTypF32 | SIMDTypF64 | SIMDTypS32 | SIMDTypU32 | SIMDTypS16
  | SIMDTypU16 -> true
  | _ -> false

/// Whether a conversion is one this lifts: the VFP ones, between singles or
/// doubles and integers or fixed-point numbers, and between singles and
/// doubles. The Advanced SIMD ones are not, nor the Armv8 half-precision
/// conversions to and from integers.
let private isLifted (ins: Instruction) dst src =
  isConvertible dst && isConvertible src
  && not (isAdvSIMDConvert ins dst src)

/// <summary>
/// VCVT and VCVTR. A conversion to an integer rounds toward zero for VCVT and
/// in the direction FPSCR names for VCVTR.
/// </summary>
let vcvt (ins: Instruction) bld towardZero =
  match ins.SIMDTyp with
  | Some(TwoDT(dst, src)) when isLifted ins dst src ->
    conditional ins bld (fun () -> convert ins bld towardZero dst src)
  | _ ->
    unsupported ins bld

/// <summary>
/// VCVTB and VCVTT between a single or a double and the half in the bottom
/// or the top of an S register. Widening reads that half; narrowing writes it
/// and leaves the other half of the register as it was.
/// </summary>
let private convertHalf (ins: Instruction) bld isTop dst =
  let struct (d, s) = transTwoOprs ins bld
  if dst = SIMDTypF16 then
    let h = fpWideToHalf bld FPSCRValue (Expr.typeOf s) s
    let mask = numU32 (if isTop then 0xffffu else 0xffff0000u) 32<rt>
    let shift = numI32 (if isTop then 16 else 0) 32<rt>
    append bld { d := (d .& mask) .| (AST.zext 32<rt> h << shift) }
  else
    let h = if isTop then AST.xthi 16<rt> s else AST.xtlo 16<rt> s
    let w = fpHalfToWide bld FPSCRValue (Expr.typeOf d) h
    append bld { d := w }

let private isIEEEFloat = function
  | SIMDTypF16 | SIMDTypF32 | SIMDTypF64 -> true
  | _ -> false

/// VCVTB and VCVTT; the Armv8.6 bfloat16 forms are not lifted.
let vcvtHalf (ins: Instruction) bld isTop =
  match ins.SIMDTyp with
  | Some(TwoDT(dst, src)) when isIEEEFloat dst && isIEEEFloat src ->
    conditional ins bld (fun () -> convertHalf ins bld isTop dst)
  | _ ->
    unsupported ins bld
