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
/// Encodes the Vector-Scalar Extension forms ISA 3.0 and 3.1 added, which the
/// decoder reads in ParsingVSX: the VSX loads and stores, the vector-scalar
/// arithmetic, the quad-precision forms and the matrix accumulators. A
/// vector-scalar register number is six bits, and where its sixth bit lies
/// depends on the form.
/// </summary>
module internal B2R2.Assembly.PPC.AsmVSX

open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField

/// The field of five bits a vector-scalar register number leaves once its
/// sixth bit is taken out, and that bit.
let private split n = struct (n &&& 0x1Fu, n >>> 5)

/// An X-form VSX access "xT, rA, rB" of primary opcode 31, and the moves of
/// the same shape with no rB, the register number's sixth bit last.
let private xIndexed xo ins =
  match ins.Operands with
  | [ Rg x; Rg a; Rg b ] ->
    let struct (t, tx) = split (vsr x)
    word 31u t (gpr a) (gpr b) ((xo <<< 1) ||| tx)
  | [ Rg x; Rg a ] ->
    let struct (t, tx) = split (vsr x)
    word 31u t (gpr a) 0u ((xo <<< 1) ||| tx)
  | _ ->
    wrongOperands ins

/// The field naming a register pair: four bits counting pairs, then the bit
/// saying which half of the vector-scalar registers the pair lies in. Only an
/// even register begins a pair.
let private pairField reg =
  let n = vsr reg
  if n &&& 1u = 0u then (n &&& 0x1Eu) ||| (n >>> 5)
  else fail $"{reg} does not begin a register pair"

/// lxvpx and stxvpx, "xTp, rA, rB".
let private pairIndexed xo ins =
  match ins.Operands with
  | [ Rg x; Rg a; Rg b ] -> word 31u (pairField x) (gpr a) (gpr b) (xo <<< 1)
  | _ -> wrongOperands ins

/// The sixteen bits a DQ-form holds, which leave out the four low bits of the
/// distance because what it reaches is a whole quadword away.
let private quadDisplacement (disp: int32) =
  if disp % 16 = 0 then signed 16 (int64 disp)
  else fail "this access cannot reach a place that is not a quadword away"

/// lxssp and stxssp, "vRT, DS(rA)", whose two low bits are 11.
let private singleDS po ins =
  match ins.Operands with
  | [ Rg v; Mem(disp, b) ] ->
    dForm po (vr v) (gpr b) ((wordDisplacement disp) ||| 3u)
  | _ ->
    wrongOperands ins

/// lxv and stxv, "xT, DQ(rA)": the sixth bit of the register number sits
/// above the three bits that say which of the two this is.
let private vectorDQ low ins =
  match ins.Operands with
  | [ Rg x; Mem(disp, b) ] ->
    let struct (t, tx) = split (vsr x)
    dForm 61u t (gpr b) ((quadDisplacement disp) ||| (tx <<< 3) ||| low)
  | _ ->
    wrongOperands ins

/// lxvp and stxvp, "xTp, DQ(rA)", told apart by their four low bits.
let private pairDQ low ins =
  match ins.Operands with
  | [ Rg x; Mem(disp, b) ] ->
    dForm 6u (pairField x) (gpr b) ((quadDisplacement disp) ||| low)
  | _ ->
    wrongOperands ins

/// lxvkq, "xT, UIM", which keeps five ones where xxspltib keeps the top of
/// its byte.
let private loadConstant ins =
  match ins.Operands with
  | [ Rg x; Im u ] ->
    let struct (t, tx) = split (vsr x)
    word 60u t 31u (unsigned 5 u) ((360u <<< 1) ||| tx)
  | _ ->
    wrongOperands ins

/// One word of primary opcode 60, given what fills the bits below the
/// registers and the three six-bit register numbers, each register's sixth
/// bit at the end: xA's in bit 2, xB's in bit 1, xT's in bit 0.
let private vsxWord rest t a b =
  let tail = rest ||| ((a >>> 5) <<< 2) ||| ((b >>> 5) <<< 1) ||| (t >>> 5)
  word 60u (t &&& 0x1Fu) (a &&& 0x1Fu) (b &&& 0x1Fu) tail

/// An XX2-form "xT, xB" whose A field is part of the opcode.
let private xx2 xo a ins =
  match ins.Operands with
  | [ Rg t; Rg b ] -> vsxWord (xo <<< 2) (vsr t) a (vsr b)
  | _ -> wrongOperands ins

/// The loads and stores of the vector-scalar registers, and the moves beside
/// them.
let private memoryEncoders () =
  [ Op.LXSIBZX, xIndexed 781u
    Op.LXSIHZX, xIndexed 813u
    Op.LXSIWAX, xIndexed 76u
    Op.LXSIWZX, xIndexed 12u
    Op.LXSSPX, xIndexed 524u
    Op.LXVB16X, xIndexed 876u
    Op.LXVH8X, xIndexed 812u
    Op.LXVL, xIndexed 269u
    Op.LXVLL, xIndexed 301u
    Op.LXVRBX, xIndexed 13u
    Op.LXVRDX, xIndexed 109u
    Op.LXVRHX, xIndexed 45u
    Op.LXVRWX, xIndexed 77u
    Op.LXVWSX, xIndexed 364u
    Op.LXVX, xIndexed 268u
    Op.MTVSRWS, xIndexed 403u
    Op.STXSIBX, xIndexed 909u
    Op.STXSIHX, xIndexed 941u
    Op.STXSIWX, xIndexed 140u
    Op.STXSSPX, xIndexed 652u
    Op.STXVB16X, xIndexed 1004u
    Op.STXVH8X, xIndexed 940u
    Op.STXVL, xIndexed 397u
    Op.STXVLL, xIndexed 429u
    Op.STXVRBX, xIndexed 141u
    Op.STXVRDX, xIndexed 237u
    Op.STXVRHX, xIndexed 173u
    Op.STXVRWX, xIndexed 205u
    Op.STXVX, xIndexed 396u
    Op.LXVPX, pairIndexed 333u
    Op.STXVPX, pairIndexed 461u
    Op.LXSSP, singleDS 57u
    Op.STXSSP, singleDS 61u
    Op.LXV, vectorDQ 1u
    Op.STXV, vectorDQ 5u
    Op.LXVP, pairDQ 0u
    Op.STXVP, pairDQ 1u
    Op.LXVKQ, loadConstant ]

/// An XX3-form "xT, xA, xB".
let private xx3 xo ins =
  match ins.Operands with
  | [ Rg t; Rg a; Rg b ] -> vsxWord (xo <<< 3) (vsr t) (vsr a) (vsr b)
  | _ -> wrongOperands ins

/// An XX2-form "xT, xB, UIM", the immediate in the A field.
let private xx2Uim xo ins =
  match ins.Operands with
  | [ Rg t; Rg b; Im u ] -> vsxWord (xo <<< 2) (vsr t) (unsigned 4 u) (vsr b)
  | _ -> wrongOperands ins

/// An XX2-form reporting in a condition-register field: "BF, xB".
let private xx2CR xo a ins =
  match ins.Operands with
  | [ Rg f; Rg b ] -> vsxWord (xo <<< 2) ((crf f) <<< 2) a (vsr b)
  | _ -> wrongOperands ins

/// The xxgenpcv forms, "xT, vRB, IMM", an X-form whose B field is a vector
/// register.
let private genPCV xo ins =
  match ins.Operands with
  | [ Rg x; Rg v; Im imm ] ->
    let struct (t, tx) = split (vsr x)
    word 60u t (unsigned 2 imm) (vr v) ((xo <<< 1) ||| tx)
  | _ ->
    wrongOperands ins

/// The permutes and the byte reversals, and the test on each byte's lowest
/// bit.
let private permuteEncoders () =
  [ Op.XXBRH, xx2 475u 7u
    Op.XXBRW, xx2 475u 15u
    Op.XXBRD, xx2 475u 23u
    Op.XXBRQ, xx2 475u 31u
    Op.XXEXTRACTUW, xx2Uim 165u
    Op.XXINSERTW, xx2Uim 181u
    Op.XXPERM, xx3 26u
    Op.XXPERMR, xx3 58u
    Op.XXGENPCVBM, genPCV 916u
    Op.XXGENPCVHM, genPCV 917u
    Op.XXGENPCVWM, genPCV 948u
    Op.XXGENPCVDM, genPCV 949u
    Op.XVTLSBB, xx2CR 475u 2u ]

/// The vector and scalar floating-point arithmetic ISA 2.07 to 3.1 added.
let private arithmeticEncoders () =
  [ Op.XVADDSP, xx3 64u
    Op.XVMADDASP, xx3 65u
    Op.XVSUBSP, xx3 72u
    Op.XVMADDMSP, xx3 73u
    Op.XVMULSP, xx3 80u
    Op.XVMSUBASP, xx3 81u
    Op.XVDIVSP, xx3 88u
    Op.XVMSUBMSP, xx3 89u
    Op.XVMADDADP, xx3 97u
    Op.XVMADDMDP, xx3 105u
    Op.XVMSUBADP, xx3 113u
    Op.XVMSUBMDP, xx3 121u
    Op.XSMAXCDP, xx3 128u
    Op.XSMINCDP, xx3 136u
    Op.XSMAXJDP, xx3 144u
    Op.XSMINJDP, xx3 152u
    Op.XVMAXSP, xx3 192u
    Op.XVNMADDASP, xx3 193u
    Op.XVMINSP, xx3 200u
    Op.XVNMADDMSP, xx3 201u
    Op.XVCPSGNSP, xx3 208u
    Op.XVNMSUBASP, xx3 209u
    Op.XVNMSUBMSP, xx3 217u
    Op.XVMAXDP, xx3 224u
    Op.XVNMADDADP, xx3 225u
    Op.XVMINDP, xx3 232u
    Op.XVNMADDMDP, xx3 233u
    Op.XVCPSGNDP, xx3 240u
    Op.XVNMSUBADP, xx3 241u
    Op.XVNMSUBMDP, xx3 249u
    Op.XSRSQRTEDP, xx2 74u 0u
    Op.XSREDP, xx2 90u 0u
    Op.XSRDPIC, xx2 107u 0u
    Op.XVRSPI, xx2 137u 0u
    Op.XVRSQRTESP, xx2 138u 0u
    Op.XVSQRTSP, xx2 139u 0u
    Op.XVRSPIZ, xx2 153u 0u
    Op.XVRESP, xx2 154u 0u
    Op.XVRSPIP, xx2 169u 0u
    Op.XVRSPIC, xx2 171u 0u
    Op.XVRSPIM, xx2 185u 0u
    Op.XVRDPI, xx2 201u 0u
    Op.XVRSQRTEDP, xx2 202u 0u
    Op.XVSQRTDP, xx2 203u 0u
    Op.XVRDPIZ, xx2 217u 0u
    Op.XVREDP, xx2 218u 0u
    Op.XVRDPIP, xx2 233u 0u
    Op.XVRDPIC, xx2 235u 0u
    Op.XVRDPIM, xx2 249u 0u
    Op.XVABSSP, xx2 409u 0u
    Op.XVNABSSP, xx2 425u 0u
    Op.XVNEGSP, xx2 441u 0u
    Op.XVABSDP, xx2 473u 0u
    Op.XVNABSDP, xx2 489u 0u ]

/// An XX3-form reporting in a condition-register field: "BF, xA, xB".
let private xx3CR xo ins =
  match ins.Operands with
  | [ Rg f; Rg a; Rg b ] -> vsxWord (xo <<< 3) ((crf f) <<< 2) (vsr a) (vsr b)
  | _ -> wrongOperands ins

/// xststdcdp and xststdcsp, "BF, xB, DCMX": the mask's top two bits sit
/// below the field, the other five in the A field.
let private scalarDCMX xo ins =
  match ins.Operands with
  | [ Rg f; Rg b; Im d ] ->
    let dcmx = unsigned 7 d
    let t = ((crf f) <<< 2) ||| (dcmx >>> 5)
    vsxWord (xo <<< 2) t (dcmx &&& 0x1Fu) (vsr b)
  | _ ->
    wrongOperands ins

/// xvtstdcdp and xvtstdcsp, "xT, xB, DCMX": dc in bit 6, dm in bit 2 and
/// dx in the A field.
let private vectorDCMX xo ins =
  match ins.Operands with
  | [ Rg t; Rg b; Im d ] ->
    let dcmx = unsigned 7 d
    let dc = (dcmx >>> 6) <<< 6
    let dm = ((dcmx >>> 5) &&& 1u) <<< 2
    vsxWord ((xo <<< 3) ||| dc ||| dm) (vsr t) (dcmx &&& 0x1Fu) (vsr b)
  | _ ->
    wrongOperands ins

/// xsxexpdp and xsxsigdp, "rT, xB".
let private toGPR a ins =
  match ins.Operands with
  | [ Rg r; Rg b ] -> vsxWord (347u <<< 2) (gpr r) a (vsr b)
  | _ -> wrongOperands ins

/// xsiexpdp, "xT, rA, rB".
let private insertExponent ins =
  match ins.Operands with
  | [ Rg x; Rg a; Rg b ] ->
    let struct (t, tx) = split (vsr x)
    word 60u t (gpr a) (gpr b) ((918u <<< 1) ||| tx)
  | _ ->
    wrongOperands ins

/// The compares, the tests for a software divide or square root, the
/// data-class tests and the exponent and significand forms.
let private testEncoders () =
  [ Op.XSCMPEQDP, xx3 3u
    Op.XSCMPGTDP, xx3 11u
    Op.XSCMPGEDP, xx3 19u
    Op.XVCMPEQSP, xx3 67u
    Op.XVCMPEQSPdot, xx3 195u
    Op.XVCMPGTSP, xx3 75u
    Op.XVCMPGTSPdot, xx3 203u
    Op.XVCMPGESP, xx3 83u
    Op.XVCMPGESPdot, xx3 211u
    Op.XVCMPEQDP, xx3 99u
    Op.XVCMPEQDPdot, xx3 227u
    Op.XVIEXPSP, xx3 216u
    Op.XVIEXPDP, xx3 248u
    Op.XSCMPODP, xx3CR 43u
    Op.XSCMPEXPDP, xx3CR 59u
    Op.XSTDIVDP, xx3CR 61u
    Op.XVTDIVSP, xx3CR 93u
    Op.XVTDIVDP, xx3CR 125u
    Op.XSTSQRTDP, xx2CR 106u 0u
    Op.XVTSQRTSP, xx2CR 170u 0u
    Op.XVTSQRTDP, xx2CR 234u 0u
    Op.XSTSTDCSP, scalarDCMX 298u
    Op.XSTSTDCDP, scalarDCMX 362u
    Op.XVTSTDCSP, vectorDCMX 213u
    Op.XVTSTDCDP, vectorDCMX 245u
    Op.XSXEXPDP, toGPR 0u
    Op.XSXSIGDP, toGPR 1u
    Op.XSIEXPDP, insertExponent
    Op.XVXEXPDP, xx2 475u 0u
    Op.XVXSIGDP, xx2 475u 1u
    Op.XVXEXPSP, xx2 475u 8u
    Op.XVXSIGSP, xx2 475u 9u ]

/// The conversions between the floating-point formats and to and from the
/// integers.
let private conversionEncoders () =
  [ Op.XVCVSPUXWS, xx2 136u 0u
    Op.XVCVSPSXWS, xx2 152u 0u
    Op.XVCVUXWSP, xx2 168u 0u
    Op.XVCVSXWSP, xx2 184u 0u
    Op.XVCVDPUXWS, xx2 200u 0u
    Op.XVCVDPSXWS, xx2 216u 0u
    Op.XVCVUXWDP, xx2 232u 0u
    Op.XVCVSPUXDS, xx2 392u 0u
    Op.XVCVDPSP, xx2 393u 0u
    Op.XVCVSPSXDS, xx2 408u 0u
    Op.XVCVUXDSP, xx2 424u 0u
    Op.XVCVSXDSP, xx2 440u 0u
    Op.XVCVDPUXDS, xx2 456u 0u
    Op.XVCVSPDP, xx2 457u 0u
    Op.XVCVDPSXDS, xx2 472u 0u
    Op.XVCVUXDDP, xx2 488u 0u
    Op.XVCVSXDDP, xx2 504u 0u
    Op.XSCVHPDP, xx2 347u 16u
    Op.XSCVDPHP, xx2 347u 17u
    Op.XVCVBF16SPN, xx2 475u 16u
    Op.XVCVSPBF16, xx2 475u 17u
    Op.XVCVHPSP, xx2 475u 24u
    Op.XVCVSPHP, xx2 475u 25u ]

/// A quad X-form "vRT, vRA, vRB" of primary opcode 63, ro its last bit.
let private quad3 xo ro ins =
  match ins.Operands with
  | [ Rg t; Rg a; Rg b ] -> word 63u (vr t) (vr a) (vr b) ((xo <<< 1) ||| ro)
  | _ -> wrongOperands ins

/// A quad compare: "BF, vRA, vRB".
let private quadCR xo ins =
  match ins.Operands with
  | [ Rg f; Rg a; Rg b ] -> word 63u ((crf f) <<< 2) (vr a) (vr b) (xo <<< 1)
  | _ -> wrongOperands ins

/// A quad X-form "vRT, vRB" whose A field is part of the opcode.
let private quad2 xo a ro ins =
  match ins.Operands with
  | [ Rg t; Rg b ] -> word 63u (vr t) a (vr b) ((xo <<< 1) ||| ro)
  | _ -> wrongOperands ins

/// xststdcqp, "BF, vRB, DCMX".
let private quadDCMX ins =
  match ins.Operands with
  | [ Rg f; Rg b; Im d ] ->
    let dcmx = unsigned 7 d
    let t = ((crf f) <<< 2) ||| (dcmx >>> 5)
    word 63u t (dcmx &&& 0x1Fu) (vr b) (708u <<< 1)
  | _ ->
    wrongOperands ins

/// A Z23-form "R, vRT, vRB, RMC": R at the bottom of the A field, RMC
/// above the eight-bit extended opcode.
let private z23 xo ex ins =
  match ins.Operands with
  | [ Im r; Rg t; Rg b; Im rmc ] ->
    let rest = ((unsigned 2 rmc) <<< 9) ||| (xo <<< 1) ||| ex
    word 63u (vr t) (unsigned 1 r) (vr b) rest
  | _ ->
    wrongOperands ins

/// The quad-precision forms.
let private quadEncoders () =
  [ Op.XSADDQP, quad3 4u 0u
    Op.XSADDQPO, quad3 4u 1u
    Op.XSMULQP, quad3 36u 0u
    Op.XSMULQPO, quad3 36u 1u
    Op.XSCMPEQQP, quad3 68u 0u
    Op.XSCPSGNQP, quad3 100u 0u
    Op.XSCMPOQP, quadCR 132u
    Op.XSCMPEXPQP, quadCR 164u
    Op.XSCMPGEQP, quad3 196u 0u
    Op.XSCMPGTQP, quad3 228u 0u
    Op.XSMADDQP, quad3 388u 0u
    Op.XSMADDQPO, quad3 388u 1u
    Op.XSMSUBQP, quad3 420u 0u
    Op.XSMSUBQPO, quad3 420u 1u
    Op.XSNMADDQP, quad3 452u 0u
    Op.XSNMADDQPO, quad3 452u 1u
    Op.XSNMSUBQP, quad3 484u 0u
    Op.XSNMSUBQPO, quad3 484u 1u
    Op.XSSUBQP, quad3 516u 0u
    Op.XSSUBQPO, quad3 516u 1u
    Op.XSDIVQP, quad3 548u 0u
    Op.XSDIVQPO, quad3 548u 1u
    Op.XSCMPUQP, quadCR 644u
    Op.XSMAXCQP, quad3 676u 0u
    Op.XSTSTDCQP, quadDCMX
    Op.XSMINCQP, quad3 740u 0u
    Op.XSABSQP, quad2 804u 0u 0u
    Op.XSXEXPQP, quad2 804u 2u 0u
    Op.XSNABSQP, quad2 804u 8u 0u
    Op.XSNEGQP, quad2 804u 16u 0u
    Op.XSXSIGQP, quad2 804u 18u 0u
    Op.XSSQRTQP, quad2 804u 27u 0u
    Op.XSSQRTQPO, quad2 804u 27u 1u
    Op.XSCVQPUQZ, quad2 836u 0u 0u
    Op.XSCVQPUWZ, quad2 836u 1u 0u
    Op.XSCVUDQP, quad2 836u 2u 0u
    Op.XSCVUQQP, quad2 836u 3u 0u
    Op.XSCVQPSQZ, quad2 836u 8u 0u
    Op.XSCVQPSWZ, quad2 836u 9u 0u
    Op.XSCVSDQP, quad2 836u 10u 0u
    Op.XSCVSQQP, quad2 836u 11u 0u
    Op.XSCVQPUDZ, quad2 836u 17u 0u
    Op.XSCVQPDP, quad2 836u 20u 0u
    Op.XSCVQPDPO, quad2 836u 20u 1u
    Op.XSCVDPQP, quad2 836u 22u 0u
    Op.XSCVQPSDZ, quad2 836u 25u 0u
    Op.XSIEXPQP, quad3 868u 0u
    Op.XSRQPI, z23 5u 0u
    Op.XSRQPIX, z23 5u 1u
    Op.XSRQPXP, z23 37u 0u ]

/// The single-precision estimates ISA 2.07 added.
let private estimateEncoders () =
  [ Op.XSRESP, xx2 26u 0u
    Op.XSRSQRTESP, xx2 10u 0u ]

/// Every instruction this module encodes.
let vsxEncoders () =
  List.concat
    [ memoryEncoders ()
      estimateEncoders ()
      permuteEncoders ()
      arithmeticEncoders ()
      testEncoders ()
      conversionEncoders ()
      quadEncoders () ]
