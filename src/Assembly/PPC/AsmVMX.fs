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
/// Encodes the rest of the vector facility's instructions in primary opcode
/// 4: the forms the processors after the first vector units added, and the
/// ones the older encoders here had left out.
/// </summary>
module internal B2R2.Assembly.PPC.AsmVMX

open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField
open B2R2.Assembly.PPC.AsmVector

/// The packs and unpacks beside the modulo ones the older encoders have --
/// the saturating packs, the doubleword packs and the pixel forms -- and the
/// multiply-sums and multiply-adds.
let private packAndSumEncoders () =
  [ Op.VPKUHUS, vx 142u
    Op.VPKUWUS, vx 206u
    Op.VPKSHSS, vx 398u
    Op.VPKSWSS, vx 462u
    Op.VPKSHUS, vx 270u
    Op.VPKSWUS, vx 334u
    Op.VPKPX, vx 782u
    Op.VUPKHPX, vx2 846u
    Op.VUPKLPX, vx2 974u
    Op.VPKUDUM, vx 1102u
    Op.VPKSDSS, vx 1486u
    Op.VPKSDUS, vx 1358u
    Op.VPKUDUS, vx 1230u
    Op.VMSUMCUD, va 23u
    Op.VMHADDSHS, va 32u
    Op.VMHRADDSHS, va 33u
    Op.VMLADDUHM, va 34u
    Op.VMSUMUDM, va 35u
    Op.VMSUMUBM, va 36u
    Op.VMSUMMBM, va 37u
    Op.VMSUMUHM, va 38u
    Op.VMSUMUHS, va 39u
    Op.VMSUMSHM, va 40u
    Op.VMSUMSHS, va 41u ]

/// The even and odd multiplies, whose products are twice as wide as the
/// elements multiplied.
let private multiplyEncoders () =
  [ Op.VMULEUB, vx 520u
    Op.VMULOUB, vx 8u
    Op.VMULESB, vx 776u
    Op.VMULOSB, vx 264u
    Op.VMULEUH, vx 584u
    Op.VMULOUH, vx 72u
    Op.VMULESH, vx 840u
    Op.VMULOSH, vx 328u
    Op.VMULEUW, vx 648u
    Op.VMULOUW, vx 136u
    Op.VMULEUD, vx 712u
    Op.VMULOUD, vx 200u
    Op.VMULESD, vx 968u
    Op.VMULOSD, vx 456u ]

/// The quadword adds and subtracts, with their carries.
let private quadwordEncoders () =
  [ Op.VADDUQM, vx 256u
    Op.VADDCUQ, vx 320u
    Op.VSUBUQM, vx 1280u
    Op.VSUBCUQ, vx 1344u
    Op.VADDEUQM, va 60u
    Op.VADDECUQ, va 61u
    Op.VSUBEUQM, va 62u
    Op.VSUBECUQ, va 63u ]

/// A VX-form "vD, vA" whose vB field no register fills (vsbox).
let private vxA xo ins =
  match ins.Operands with
  | [ Rg d; Rg a ] -> word 4u (vr d) (vr a) 0u xo
  | _ -> wrongOperands ins

/// vshasigmaw/vshasigmad, whose ST bit and four-bit SIX fill the vB field.
let private vxSigma xo ins =
  match ins.Operands with
  | [ Rg d; Rg a; Im st; Im six ] ->
    word 4u (vr d) (vr a) (((unsigned 1 st) <<< 4) ||| unsigned 4 six) xo
  | _ ->
    wrongOperands ins

/// The cryptography support: the AES rounds, the SHA-2 sigma functions, the
/// carry-less multiply-sums and the permute-and-XOR.
let private cryptoEncoders () =
  [ Op.VCIPHER, vx 1288u
    Op.VCIPHERLAST, vx 1289u
    Op.VNCIPHER, vx 1352u
    Op.VNCIPHERLAST, vx 1353u
    Op.VSBOX, vxA 1480u
    Op.VSHASIGMAW, vxSigma 1666u
    Op.VSHASIGMAD, vxSigma 1730u
    Op.VPMSUMB, vx 1032u
    Op.VPMSUMH, vx 1096u
    Op.VPMSUMW, vx 1160u
    Op.VPMSUMD, vx 1224u
    Op.VPERMXOR, va 45u ]

/// A decimal add or subtract, whose preferred-sign bit sits above its
/// nine-bit extended opcode.
let private vxDecimal xo ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg b; Im ps ] ->
    word 4u (vr d) (vr a) (vr b) (((unsigned 1 ps) <<< 9) ||| xo)
  | _ ->
    wrongOperands ins

/// The decimal integer arithmetic.
let private decimalEncoders () =
  [ Op.BCDADDdot, vxDecimal 1025u
    Op.BCDSUBdot, vxDecimal 1089u ]

/// The saturating adds and subtracts, the carries, the averages and the
/// absolute differences.
let private saturatingEncoders () =
  [ Op.VADDSBS, vx 768u
    Op.VADDSHS, vx 832u
    Op.VADDSWS, vx 896u
    Op.VADDUHS, vx 576u
    Op.VADDUWS, vx 640u
    Op.VSUBSBS, vx 1792u
    Op.VSUBSHS, vx 1856u
    Op.VSUBSWS, vx 1920u
    Op.VSUBUHS, vx 1600u
    Op.VSUBUWS, vx 1664u
    Op.VADDCUW, vx 384u
    Op.VSUBCUW, vx 1408u
    Op.VAVGSB, vx 1282u
    Op.VAVGSH, vx 1346u
    Op.VAVGSW, vx 1410u
    Op.VAVGUB, vx 1026u
    Op.VAVGUH, vx 1090u
    Op.VAVGUW, vx 1154u
    Op.VABSDUB, vx 1027u
    Op.VABSDUH, vx 1091u
    Op.VABSDUW, vx 1155u ]

/// vcmpsq/vcmpuq, which compare into a field of the condition register named
/// in the three bits where a target register would begin.
let private vxCompareToCR xo ins =
  match ins.Operands with
  | [ Rg f; Rg a; Rg b ] -> word 4u ((crf f) <<< 2) (vr a) (vr b) xo
  | _ -> wrongOperands ins

/// The compares added after the first vector units: quadword equality and
/// order, and inequality with or without a zero element counting as one.
let private compareEncoders () =
  List.concat
    [ recording vc 455u Op.VCMPEQUQ Op.VCMPEQUQdot
      recording vc 647u Op.VCMPGTUQ Op.VCMPGTUQdot
      recording vc 903u Op.VCMPGTSQ Op.VCMPGTSQdot
      recording vc 7u Op.VCMPNEB Op.VCMPNEBdot
      recording vc 71u Op.VCMPNEH Op.VCMPNEHdot
      recording vc 135u Op.VCMPNEW Op.VCMPNEWdot
      recording vc 263u Op.VCMPNEZB Op.VCMPNEZBdot
      recording vc 327u Op.VCMPNEZH Op.VCMPNEZHdot
      recording vc 391u Op.VCMPNEZW Op.VCMPNEZWdot
      [ Op.VCMPSQ, vxCompareToCR 321u; Op.VCMPUQ, vxCompareToCR 257u ] ]

/// maddhd/maddhdu/maddld, the VA form that names general registers.
let private vaGpr xo ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg b; Rg c ] ->
    word 4u (gpr d) (gpr a) (gpr b) (((gpr c) <<< 6) ||| xo)
  | _ ->
    wrongOperands ins

/// The multiplies that keep the high half of each product, the doubleword
/// multiply that keeps the low one, and the multiply-adds of doubleword
/// general registers.
let private multiplyHighEncoders () =
  [ Op.VMULHSW, vx 905u
    Op.VMULHUW, vx 649u
    Op.VMULHSD, vx 969u
    Op.VMULHUD, vx 713u
    Op.VMULLD, vx 457u
    Op.MADDHD, vaGpr 48u
    Op.MADDHDU, vaGpr 49u
    Op.MADDLD, vaGpr 51u ]

/// The divides, the extended divides and the remainders.
let private divideEncoders () =
  [ Op.VDIVSW, vx 395u
    Op.VDIVUW, vx 139u
    Op.VDIVSD, vx 459u
    Op.VDIVUD, vx 203u
    Op.VDIVSQ, vx 267u
    Op.VDIVUQ, vx 11u
    Op.VDIVESW, vx 907u
    Op.VDIVEUW, vx 651u
    Op.VDIVESD, vx 971u
    Op.VDIVEUD, vx 715u
    Op.VDIVESQ, vx 779u
    Op.VDIVEUQ, vx 523u
    Op.VMODSW, vx 1931u
    Op.VMODUW, vx 1675u
    Op.VMODSD, vx 1995u
    Op.VMODUD, vx 1739u
    Op.VMODSQ, vx 1803u
    Op.VMODUQ, vx 1547u ]

/// The sums across a vector, within words or across the whole of it.
let private sumEncoders () =
  [ Op.VSUM4UBS, vx 1544u
    Op.VSUM4SBS, vx 1800u
    Op.VSUM4SHS, vx 1608u
    Op.VSUM2SWS, vx 1672u
    Op.VSUMSWS, vx 1928u ]

/// A VX-form "vD, vB" whose vA field holds a further extended opcode.
let private vxSub sub xo ins =
  match ins.Operands with
  | [ Rg d; Rg b ] -> word 4u (vr d) sub (vr b) xo
  | _ -> wrongOperands ins

/// A VX-form "rD, vB" whose vA field holds a further extended opcode.
let private vxGprSub sub xo ins =
  match ins.Operands with
  | [ Rg d; Rg b ] -> word 4u (gpr d) sub (vr b) xo
  | _ -> wrongOperands ins

/// The counts, negations, parities and sign extensions of extended opcode
/// 1538, told apart by their vA field.
let private countEncoders () =
  [ Op.VCLZLSBB, vxGprSub 0u 1538u
    Op.VCTZLSBB, vxGprSub 1u 1538u
    Op.VNEGW, vxSub 6u 1538u
    Op.VNEGD, vxSub 7u 1538u
    Op.VPRTYBW, vxSub 8u 1538u
    Op.VPRTYBD, vxSub 9u 1538u
    Op.VPRTYBQ, vxSub 10u 1538u
    Op.VEXTSB2W, vxSub 16u 1538u
    Op.VEXTSH2W, vxSub 17u 1538u
    Op.VEXTSB2D, vxSub 24u 1538u
    Op.VEXTSH2D, vxSub 25u 1538u
    Op.VEXTSW2D, vxSub 26u 1538u
    Op.VEXTSD2Q, vxSub 27u 1538u
    Op.VCTZB, vxSub 28u 1538u
    Op.VCTZH, vxSub 29u 1538u
    Op.VCTZW, vxSub 30u 1538u
    Op.VCTZD, vxSub 31u 1538u ]

/// vsldbi/vsrdbi, the VN form whose bit 9 tells left from right and whose
/// three-bit shift sits below it.
let private vn right ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg b; Im sh ] ->
    let rest = (right <<< 9) ||| ((unsigned 3 sh) <<< 6) ||| 22u
    word 4u (vr d) (vr a) (vr b) rest
  | _ ->
    wrongOperands ins

/// The rotate-and-mask forms, the quadword shifts and rotate, the variable
/// byte shifts and the shifts of a register pair by bits.
let private shiftEncoders () =
  [ Op.VRLWMI, vx 133u
    Op.VRLDMI, vx 197u
    Op.VRLQMI, vx 69u
    Op.VRLWNM, vx 389u
    Op.VRLDNM, vx 453u
    Op.VRLQNM, vx 325u
    Op.VRLQ, vx 5u
    Op.VSLQ, vx 261u
    Op.VSRQ, vx 517u
    Op.VSRAQ, vx 773u
    Op.VSLV, vx 1860u
    Op.VSRV, vx 1796u
    Op.VSLDBI, vn 0u
    Op.VSRDBI, vn 1u ]

/// A VX-form "vD, rB" whose vA field holds a further extended opcode.
let private vxVecGprSub sub xo ins =
  match ins.Operands with
  | [ Rg d; Rg b ] -> word 4u (vr d) sub (gpr b) xo
  | _ -> wrongOperands ins

/// vcntmb* "rD, vB, MP", MP being the lowest bit of the vA field.
let private vxCountMask sub xo ins =
  match ins.Operands with
  | [ Rg d; Rg b; Im mp ] -> word 4u (gpr d) (sub ||| unsigned 1 mp) (vr b) xo
  | _ -> wrongOperands ins

/// mtvsrbmi "vD, bm", whose sixteen-bit bm is split in three fields.
let private dxMask ins =
  match ins.Operands with
  | [ Rg d; Im bm ] ->
    let bm = unsigned 16 bm
    let rest = ((bm >>> 6) <<< 6) ||| (10u <<< 1) ||| (bm &&& 1u)
    word 4u (vr d) ((bm >>> 1) &&& 0x1Fu) 0u rest
  | _ ->
    wrongOperands ins

/// The expands, extracts and moves of a mask, and the counts of its bits.
let private maskEncoders () =
  [ Op.VEXPANDBM, vxSub 0u 1602u
    Op.VEXPANDHM, vxSub 1u 1602u
    Op.VEXPANDWM, vxSub 2u 1602u
    Op.VEXPANDDM, vxSub 3u 1602u
    Op.VEXPANDQM, vxSub 4u 1602u
    Op.VEXTRACTBM, vxGprSub 8u 1602u
    Op.VEXTRACTHM, vxGprSub 9u 1602u
    Op.VEXTRACTWM, vxGprSub 10u 1602u
    Op.VEXTRACTDM, vxGprSub 11u 1602u
    Op.VEXTRACTQM, vxGprSub 12u 1602u
    Op.MTVSRBM, vxVecGprSub 16u 1602u
    Op.MTVSRHM, vxVecGprSub 17u 1602u
    Op.MTVSRWM, vxVecGprSub 18u 1602u
    Op.MTVSRDM, vxVecGprSub 19u 1602u
    Op.MTVSRQM, vxVecGprSub 20u 1602u
    Op.VCNTMBB, vxCountMask 24u 1602u
    Op.VCNTMBH, vxCountMask 26u 1602u
    Op.VCNTMBW, vxCountMask 28u 1602u
    Op.VCNTMBD, vxCountMask 30u 1602u
    Op.MTVSRBMI, dxMask ]

/// The string isolates, whose record bit sits above their extended opcode and
/// whose vA field picks the element and the end they start from; and vpermr.
let private stringEncoders () =
  [ Op.VSTRIBL, vxSub 0u 13u
    Op.VSTRIBLdot, vxSub 0u 1037u
    Op.VSTRIBR, vxSub 1u 13u
    Op.VSTRIBRdot, vxSub 1u 1037u
    Op.VSTRIHL, vxSub 2u 13u
    Op.VSTRIHLdot, vxSub 2u 1037u
    Op.VSTRIHR, vxSub 3u 13u
    Op.VSTRIHRdot, vxSub 3u 1037u
    Op.VPERMR, va 59u ]

/// vgnb "rD, vB, N", the stride in the low three bits of the vA field.
let private vxGather ins =
  match ins.Operands with
  | [ Rg t; Rg b; Im n ] -> word 4u (gpr t) (unsigned 3 n) (vr b) 1228u
  | _ -> wrongOperands ins

/// The gathers, scatters and counts of bits under a mask.
let private bitEncoders () =
  [ Op.VGNB, vxGather
    Op.VBPERMD, vx 1484u
    Op.VCFUGED, vx 1357u
    Op.VPDEPD, vx 1485u
    Op.VPEXTD, vx 1421u
    Op.VCLZDM, vx 1924u
    Op.VCTZDM, vx 1988u ]

/// vmaddfp/vnmsubfp "vD, vA, vC, vB", whose vC is written before vB.
let private vaFloat xo ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg c; Rg b ] ->
    word 4u (vr d) (vr a) (vr b) (((vr c) <<< 6) ||| xo)
  | _ ->
    wrongOperands ins

/// The floating-point arithmetic, estimates, roundings, conversions and
/// compares on four singles.
let private floatEncoders () =
  List.concat
    [ [ Op.VADDFP, vx 10u
        Op.VSUBFP, vx 74u
        Op.VMAXFP, vx 1034u
        Op.VMINFP, vx 1098u
        Op.VREFP, vx2 266u
        Op.VRSQRTEFP, vx2 330u
        Op.VEXPTEFP, vx2 394u
        Op.VLOGEFP, vx2 458u
        Op.VRFIN, vx2 522u
        Op.VRFIZ, vx2 586u
        Op.VRFIP, vx2 650u
        Op.VRFIM, vx2 714u
        Op.VCFUX, vxSplat 778u
        Op.VCFSX, vxSplat 842u
        Op.VCTUXS, vxSplat 906u
        Op.VCTSXS, vxSplat 970u
        Op.VMADDFP, vaFloat 46u
        Op.VNMSUBFP, vaFloat 47u ]
      recording vc 198u Op.VCMPEQFP Op.VCMPEQFPdot
      recording vc 454u Op.VCMPGEFP Op.VCMPGEFPdot
      recording vc 710u Op.VCMPGTFP Op.VCMPGTFPdot
      recording vc 966u Op.VCMPBFP Op.VCMPBFPdot ]

/// The decimal conversions and bcdsetsgn., extended opcode 1409 with the
/// conversion in the vA field and PS above the opcode where there is one.
let private vxDecimalSub sub ins =
  match ins.Operands with
  | [ Rg d; Rg b; Im ps ] ->
    word 4u (vr d) sub (vr b) (((unsigned 1 ps) <<< 9) ||| 1409u)
  | [ Rg d; Rg b ] ->
    word 4u (vr d) sub (vr b) 1409u
  | _ ->
    wrongOperands ins

/// The rest of the decimal integer instructions -- conversions, sign
/// changes, shifts and truncations -- and the multiplies by ten.
let private decimalMoreEncoders () =
  [ Op.BCDCTSQdot, vxDecimalSub 0u
    Op.BCDCFSQdot, vxDecimalSub 2u
    Op.BCDCTZdot, vxDecimalSub 4u
    Op.BCDCTNdot, vxDecimalSub 5u
    Op.BCDCFZdot, vxDecimalSub 6u
    Op.BCDCFNdot, vxDecimalSub 7u
    Op.BCDSETSGNdot, vxDecimalSub 31u
    Op.BCDCPSGNdot, vx 833u
    Op.BCDSdot, vxDecimal 1217u
    Op.BCDUSdot, vx 1153u
    Op.BCDSRdot, vxDecimal 1473u
    Op.BCDTRUNCdot, vxDecimal 1281u
    Op.BCDUTRUNCdot, vx 1345u
    Op.VMUL10UQ, vxA 513u
    Op.VMUL10CUQ, vxA 1u
    Op.VMUL10EUQ, vx 577u
    Op.VMUL10ECUQ, vx 65u ]

/// Every instruction of primary opcode 4 the older encoders leave out.
let vmxEncoders () =
  List.concat
    [ packAndSumEncoders ()
      multiplyEncoders ()
      quadwordEncoders ()
      cryptoEncoders ()
      decimalEncoders ()
      saturatingEncoders ()
      compareEncoders ()
      multiplyHighEncoders ()
      divideEncoders ()
      sumEncoders ()
      countEncoders ()
      shiftEncoders ()
      maskEncoders ()
      stringEncoders ()
      bitEncoders ()
      floatEncoders ()
      decimalMoreEncoders () ]
