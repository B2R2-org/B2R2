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

/// Every instruction of primary opcode 4 the older encoders leave out.
let vmxEncoders () =
  List.concat
    [ packAndSumEncoders ()
      multiplyEncoders ()
      quadwordEncoders ()
      cryptoEncoders ()
      decimalEncoders ()
      saturatingEncoders () ]
