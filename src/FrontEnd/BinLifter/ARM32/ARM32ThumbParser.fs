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

module internal B2R2.FrontEnd.BinLifter.ARM32.ThumbParser

open B2R2
open B2R2.FrontEnd.BinLifter.ARM32.ParseUtils
open B2R2.FrontEnd.BinLifter.ARM32.OperandHelper
open B2R2.FrontEnd.BinLifter.ARM32.ARMParser

let getCFThumb (b1, b2) =
  let imm1 = pickBit b1 10
  let imm3 = extract b2 14 12
  let imm8 = extract b2 7 0
  let imm12 = concat (concat imm1 imm3 3) imm8 8
  let chk1 = extract imm12 11 10
  let chk2 = extract imm12 9 8
  match (chk1, chk2) with
  | (0b00u, 0b00u) | (0b00u, 0b01u) | (0b00u, 0b10u) | (0b00u, 0b11u) -> None
  | _ ->
    let imm7 = extract imm12 6 0
    let unRotated = imm7 ||| 0b10000000u
    let amount = extract imm12 11 7
    let m = amount % 32u |> int32
    let result = (unRotated <<< (32 - m)) ||| (unRotated >>> m)
    (pickBit result 31 = 1u) |> Some

let getVMOVVORR bin =
  let n = pickBit bin 7
  let m = pickBit bin 5
  let vn = extract bin 19 16
  let vm = extract bin 3 0
  if n = m && vn = vm then Op.VMOV, p2Oprs bin chkUndefH (getRegX, getRegZ)
  else Op.VORR, p3Oprs bin chkUndefD (getRegX, getRegY, getRegZ)

let getXYZRegOprs bin chkUndef = p3Oprs bin chkUndef (getRegX, getRegY, getRegZ)

let getXZYRegOprs bin chkUndef = p3Oprs bin chkUndef (getRegX, getRegZ, getRegY)

let get3RegBitwise bin k =
  match concat k (extract bin 21 20) 2 with
  | 0b000u -> Op.VAND, getXYZRegOprs bin chkUndefD
  | 0b001u -> Op.VBIC, getXYZRegOprs bin chkUndefD
  | 0b010u -> getVMOVVORR bin
  | 0b011u -> Op.VORN, getXYZRegOprs bin chkUndefD
  | 0b100u -> Op.VEOR, getXYZRegOprs bin chkUndefD
  | 0b101u -> Op.VBSL, getXYZRegOprs bin chkUndefD
  | 0b110u -> Op.VBIT, getXYZRegOprs bin chkUndefD
  | 0b111u -> Op.VBIF, getXYZRegOprs bin chkUndefD
  | _ -> failwith "Wrong 3 register bitwise."

let get3RegFloat bin k =
  match pickBit bin 4, k, pickBit bin 21 with
  | 0u, 0u, 0u -> Op.VADD, getXYZRegOprs bin chkUndefL
  | 0u, 0u, 1u -> Op.VSUB, getXYZRegOprs bin chkUndefL
  | 0u, 1u, 0u -> Op.VPADD, getXYZRegOprs bin chkUndefM
  | 0u, 1u, 1u -> Op.VABD, getXYZRegOprs bin chkUndefL
  | 1u, 0u, 0u -> Op.VMLA, getXYZRegOprs bin chkUndefL
  | 1u, 0u, 1u -> Op.VMLS, getXYZRegOprs bin chkUndefL
  | 1u, 1u, 0u -> Op.VMUL, getXYZRegOprs bin chkUndefL
  | _ -> failwith "Wrong 3 register floating point."

let get3RegCompare bin k =
  match pickBit bin 4, k, pickBit bin 21 with
  | 0u, 0u, 0u -> Op.VCEQ
  | 0u, 1u, 0u -> Op.VCGE
  | 0u, 1u, 1u -> Op.VCGT
  | 1u, 1u, 0u -> Op.VACGE
  | 1u, 1u, 1u -> Op.VACGT
  | _ -> failwith "Wrong 3 register compare."
  , None, getOneDtG bin, getXYZRegOprs bin chkUndefL

let get3RegMaxMinNReciprocal bin k =
  match pickBit bin 4, k, pickBit bin 21 with
  | 0u, 0u, 0u -> Op.VMAX, None, getOneDtG bin, getXYZRegOprs bin chkUndefL
  | 0u, 0u, 1u -> Op.VMIN, None, getOneDtG bin, getXYZRegOprs bin chkUndefL
  | 0u, 1u, 0u -> Op.VPMAX, None, getOneDtG bin, getXYZRegOprs bin chkUndefM
  | 0u, 1u, 1u -> Op.VPMIN, None, getOneDtG bin, getXYZRegOprs bin chkUndefM
  | 1u, 0u, 0u -> Op.VRECPS, None, getOneDtG bin, getXYZRegOprs bin chkUndefL
  | 1u, 0u, 1u -> Op.VRSQRTS, None, getOneDtG bin, getXYZRegOprs bin chkUndefL
  | _ -> failwith "Wrong 3 register max/min & reciprocal."

/// Three registers of the same length, page A7-262
let parse3Reg bin k =
  let chkU = k = 0b0u
  match concat (extract bin 11 8) (pickBit bin 4) 1 with
  | 0b00000u -> Op.VHADD, None, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b00001u -> Op.VQADD, None, getOneDtD k bin, getXYZRegOprs bin chkUndefD
  | 0b00010u -> Op.VRHADD, None, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b00011u ->
    let opcode, oprs = get3RegBitwise bin k in opcode, None, None, oprs
  | 0b00100u -> Op.VHSUB, None, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b00101u -> Op.VQSUB, None, getOneDtD k bin, getXYZRegOprs bin chkUndefD
  | 0b00110u -> Op.VCGT, None, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b00111u -> Op.VCGE, None, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b01000u -> Op.VSHL, None, getOneDtD k bin, getXZYRegOprs bin chkUndefD
  | 0b01001u -> Op.VQSHL, None, getOneDtD k bin, getXZYRegOprs bin chkUndefD
  | 0b01010u -> Op.VRSHL, None, getOneDtD k bin, getXZYRegOprs bin chkUndefD
  | 0b01011u -> Op.VQRSHL, None, getOneDtD k bin, getXZYRegOprs bin chkUndefD
  | 0b01100u -> Op.VMAX, None, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b01101u -> Op.VMIN, None, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b01110u -> Op.VABD, None, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b01111u -> Op.VABA, None, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b10000u when chkU ->
    Op.VADD, None, getOneDtF bin, getXYZRegOprs bin chkUndefD
  | 0b10000u -> Op.VSUB, None, getOneDtF bin, getXYZRegOprs bin chkUndefD
  | 0b10001u when chkU ->
    Op.VTST, None, getOneDtF bin, getXYZRegOprs bin chkUndefD
  | 0b10001u -> Op.VCEQ, None, getOneDtF bin, getXYZRegOprs bin chkUndefD
  | 0b10010u when chkU ->
    Op.VMLA, None, getOneDtF bin, getXYZRegOprs bin chkUndefD
  | 0b10010u -> Op.VMLS, None, getOneDtF bin, getXYZRegOprs bin chkUndefD
  | 0b10011u -> Op.VMUL, None, getOneDtF bin, getXYZRegOprs bin chkUndefD
  | 0b10100u -> Op.VPMAX, None, getOneDtD k bin, getXYZRegOprs bin chkUndefJ
  | 0b10101u -> Op.VPMIN, None, getOneDtD k bin, getXYZRegOprs bin chkUndefJ
  | 0b10110u when chkU ->
    Op.VQDMULH, None, getOneDtF bin, getXYZRegOprs bin chkUndefK
  | 0b10110u -> Op.VQRDMULH, None, getOneDtF bin, getXYZRegOprs bin chkUndefK
  | 0b10111u -> Op.VPADD, None, getOneDtF bin, getXYZRegOprs bin chkUndefD
  | op when op &&& 0b11110u = 0b11010u ->
    let opcode, oprs = get3RegFloat bin k in opcode, None, getOneDtG bin, oprs
  | op when op &&& 0b11110u = 0b11100u -> get3RegCompare bin k
  | op when op &&& 0b11110u = 0b11110u -> get3RegMaxMinNReciprocal bin k
  | _ -> failwith "Wrong 3 register."

/// One register and a modified immediate value, page A7-269
let parse1Reg bin k =
  let opcode =
    match concat (pickBit bin 5) (extract bin 11 8) 4 with
    | op when op &&& 0b11001u = 0b00000u -> Op.VMOV
    | op when op &&& 0b11001u = 0b00001u -> Op.VORR
    | op when op &&& 0b11101u = 0b01000u -> Op.VMOV
    | op when op &&& 0b11101u = 0b01001u -> Op.VORR
    | op when op &&& 0b11100u = 0b01100u -> Op.VMOV
    | op when op &&& 0b11001u = 0b10000u -> Op.VMVN
    | op when op &&& 0b11001u = 0b10001u -> Op.VBIC
    | op when op &&& 0b11101u = 0b11000u -> Op.VMVN
    | op when op &&& 0b11101u = 0b11001u -> Op.VBIC
    | op when op &&& 0b11110u = 0b11100u -> Op.VMVN
    | 0b11110u -> Op.VMOV
    | 0b11111u -> raise UndefinedException
    | _ -> failwith "Wrong 1 register."
  opcode, None, getOneDtH bin, p2Oprs bin chkUndefN (getRxIa opcode k)

/// Two registers and a shift amount, page A7-266
let parse2Reg bin k =
  let chk = extract bin 18 16 = 0u
  match concat (extract bin 11 6) k 1 with
  | op when op &&& 0b1111000u = 0b0000000u ->
    Op.VSHR, None, getOneDtJ k bin,
    p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111000u = 0b0001000u ->
    Op.VSRA, None, getOneDtJ k bin,
    p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111000u = 0b0010000u ->
    Op.VRSHR, None, getOneDtJ k bin,
    p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111000u = 0b0011000u ->
    Op.VRSRA, None, getOneDtJ k bin,
    p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111001u = 0b0100001u ->
    Op.VSRI, None, getOneDtK bin,
    p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111001u = 0b0101000u ->
    Op.VSHL, None, getOneDtL bin,
    p3Oprs bin chkUndefH (getRegX, getRegZ, getImmC)
  | op when op &&& 0b1111001u = 0b0101001u ->
    Op.VSLI, None, getOneDtK bin,
    p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111000u = 0b0110000u ->
    Op.VQSHLU, None, getOneDtJ k bin,
    p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111000u = 0b0111000u ->
    Op.VQSHL, None, getOneDtJ k bin,
    p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | 0b1000000u ->
    Op.VSHRN, None, getOneDtM bin,
    p3Oprs bin chkUndefO (getRegAC, getRegAD, getImmD)
  | 0b1000010u ->
    Op.VRSHRN, None, getOneDtM bin,
    p3Oprs bin chkUndefO (getRegAC, getRegAD, getImmD)
  | 0b1000001u ->
    Op.VQSHRUN, None, getOneDtN bin,
    p3Oprs bin chkUndefO (getRegAC, getRegAD, getImmD)
  | 0b1000011u ->
    Op.VQRSHRUN, None, getOneDtN bin,
    p3Oprs bin chkUndefO (getRegAC, getRegAD, getImmD)
  | op when op &&& 0b1111010u = 0b1001000u ->
    Op.VQSHRN, None, getOneDtO k bin,
    p3Oprs bin chkUndefO (getRegAC, getRegAD, getImmE)
  | op when op &&& 0b1111010u = 0b1001010u ->
    Op.VQRSHRN, None, getOneDtO k bin,
    p3Oprs bin chkUndefO (getRegAC, getRegAD, getImmE)
  | op when op &&& 0b1111010u = 0b1010000u && chk ->
    Op.VMOVL, None, getOneDtP k bin,
    p3Oprs bin chkUndefO (getRegAE, getRegAF, getImmF)
  | op when op &&& 0b1111010u = 0b1010000u ->
    Op.VSHLL, None, getOneDtP k bin,
    p3Oprs bin chkUndefO (getRegAE, getRegAF, getImmF)
  | op when op &&& 0b1110000u = 0b1110000u ->
    Op.VCVT, None, getTwoDtA k bin,
    p3Oprs bin chkUndefP (getRegX, getRegZ, getImmG)
  | _ -> failwith "Wrong 2 register."

/// Three registers of different lengths, page A7-264
let parse3RegDiffLen bin k =
  match concat (extract bin 11 8) k 1 with
  | op when op &&& 0b11110u = 0b00000u ->
    Op.VADDL, None, getOneDtD k bin,
    p3Oprs bin chkUndefQ (getRegAE, getRegAG, getRegAF)
  | op when op &&& 0b11110u = 0b00010u ->
    Op.VADDW, None, getOneDtD k bin,
    p3Oprs bin chkUndefQ (getRegAE, getRegAG, getRegAF)
  | op when op &&& 0b11110u = 0b00100u ->
    Op.VSUBL, None, getOneDtD k bin,
    p3Oprs bin chkUndefQ (getRegAE, getRegAG, getRegAF)
  | op when op &&& 0b11110u = 0b00110u ->
    Op.VSUBW, None, getOneDtD k bin,
    p3Oprs bin chkUndefQ (getRegAE, getRegAG, getRegAF)
  | 0b01000u ->
    Op.VADDHN, None, getOneDtQ bin,
    p3Oprs bin chkUndefR (getRegAC, getRegU, getRegAD)
  | 0b01001u ->
    Op.VRADDHN, None, getOneDtQ bin,
    p3Oprs bin chkUndefR (getRegAC, getRegU, getRegAD)
  | op when op &&& 0b11110u = 0b01010u ->
    Op.VABAL, None, getOneDtD k bin,
    p3Oprs bin chkUndefS (getRegAE, getRegV, getRegAF)
  | 0b01100u ->
    Op.VSUBHN, None, getOneDtQ bin,
    p3Oprs bin chkUndefR (getRegAC, getRegU, getRegAD)
  | 0b01101u ->
    Op.VRSUBHN, None, getOneDtQ bin,
    p3Oprs bin chkUndefR (getRegAC, getRegU, getRegAD)
  | op when op &&& 0b11110u = 0b01110u ->
    Op.VABDL, None, getOneDtD k bin,
    p3Oprs bin chkUndefS (getRegAE, getRegV, getRegAF)
  | op when op &&& 0b11110u = 0b10000u ->
    Op.VMLAL, None, getOneDtD k bin,
    p3Oprs bin chkUndefS (getRegAE, getRegV, getRegAF)
  | op when op &&& 0b11110u = 0b10100u ->
    Op.VMLSL, None, getOneDtD k bin,
    p3Oprs bin chkUndefS (getRegAE, getRegV, getRegAF)
  | op when op &&& 0b11110u = 0b10010u ->
    Op.VQDMLAL, None, getOneDtA bin,
    p3Oprs bin chkUndefT (getRegAE, getRegU, getRegAD)
  | op when op &&& 0b11110u = 0b10110u ->
    Op.VQDMLSL, None, getOneDtA bin,
    p3Oprs bin chkUndefT (getRegAE, getRegU, getRegAD)
  | op when op &&& 0b11110u = 0b11000u ->
    Op.VMULL, None, getOneDtR k bin,
    p3Oprs bin chkUndefS (getRegAE, getRegV, getRegAF)
  | 0b11010u ->
    Op.VQDMULL, None, getOneDtA bin,
    p3Oprs bin chkUndefT (getRegAE, getRegU, getRegAD)
  | op when op &&& 0b11110u = 0b11100u ->
    Op.VMULL, None, getOneDtR k bin,
    p3Oprs bin chkUndefS (getRegAE, getRegV, getRegAF)
  | _ -> failwith "Wrong 3 register different lengths."

/// Two registers and a scalar, page A7-265
let parse2RegScalar bin k =
  match concat (extract bin 11 8) k 1 with
  | op when op &&& 0b11100u = 0b00000u ->
    Op.VMLA, None, getOneDtB bin, p3Oprs bin (chkUndefB k) (getRrRsSCa k)
  | op when op &&& 0b11100u = 0b01000u ->
    Op.VMLS, None, getOneDtB bin, p3Oprs bin (chkUndefB k) (getRrRsSCa k)
  | op when op &&& 0b11110u = 0b00100u ->
    Op.VMLAL, None, getOneDtD k bin,
    p3Oprs bin chkUndefC (getRegAE, getRegV, getScalarA)
  | op when op &&& 0b11110u = 0b01100u ->
    Op.VMLSL, None, getOneDtD k bin,
    p3Oprs bin chkUndefC (getRegAE, getRegV, getScalarA)
  | 0b00110u ->
    Op.VQDMLAL, None, getOneDtA bin,
    p3Oprs bin chkUndefC (getRegAE, getRegV, getScalarA)
  | 0b01110u ->
    Op.VQDMLSL, None, getOneDtA bin,
    p3Oprs bin chkUndefC (getRegAE, getRegV, getScalarA)
  | op when op &&& 0b11100u = 0b10000u ->
    Op.VMUL, None, getOneDtB bin, p3Oprs bin (chkUndefB k) (getRrRsSCa k)
  | op when op &&& 0b11110u = 0b10100u ->
    Op.VMULL, None, getOneDtD k bin,
    p3Oprs bin chkUndefC (getRegAE, getRegV, getScalarA)
  | 0b10110u ->
    Op.VQDMULL, None, getOneDtA bin,
    p3Oprs bin chkUndefC (getRegAE, getRegV, getScalarA)
  | op when op &&& 0b11110u = 0b11000u ->
    Op.VQDMULH, None, getOneDtA bin, p3Oprs bin (chkUndefA k) (getRrRsSCa k)
  | op when op &&& 0b11110u = 0b11010u ->
    Op.VQRDMULH, None, getOneDtA bin, p3Oprs bin (chkUndefA k) (getRrRsSCa k)
  | _ -> failwith "Wrong 2 register scalar."

/// Two registers, miscellaneous, page A7-267
let parse2RegMis b =
  let isBit6 () = pickBit b 6 = 0b0u
  match concat (extract b 17 16) (extract b 10 7) 4 with
  | 0b000000u ->
    Op.VREV64, None, getOneDtS b, p2Oprs b chkUndefU (getRegX, getRegZ)
  | 0b000001u ->
    Op.VREV32, None, getOneDtS b, p2Oprs b chkUndefU (getRegX, getRegZ)
  | 0b000010u ->
    Op.VREV16, None, getOneDtS b, p2Oprs b chkUndefU (getRegX, getRegZ)
  | o when o &&& 0b111110u = 0b000100u ->
    Op.VPADDL, None, getOneDtC b, p2Oprs b chkUndefV (getRegX, getRegZ)
  | 0b001000u ->
    Op.VCLS, None, getOneDtT b, p2Oprs b chkUndefX (getRegX, getRegZ)
  | 0b001001u ->
    Op.VCLZ, None, getOneDtU b, p2Oprs b chkUndefX (getRegX, getRegZ)
  | 0b001010u ->
    Op.VCNT, None, getOneDtE (), p2Oprs b chkUndefY (getRegX, getRegZ)
  | 0b001011u -> Op.VMVN, None, None, p2Oprs b chkUndefY (getRegX, getRegZ)
  | o when o &&& 0b111110u = 0b001100u ->
    Op.VPADAL, None, getOneDtC b, p2Oprs b chkUndefV (getRegX, getRegZ)
  | 0b001110u ->
    Op.VQABS, None, getOneDtT b, p2Oprs b chkUndefX (getRegX, getRegZ)
  | 0b001111u ->
    Op.VQNEG, None, getOneDtT b, p2Oprs b chkUndefX (getRegX, getRegZ)
  | o when o &&& 0b110111u = 0b010000u ->
    Op.VCGT, None, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | o when o &&& 0b110111u = 0b010001u ->
    Op.VCGE, None, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | o when o &&& 0b110111u = 0b010010u ->
    Op.VCEQ, None, getOneDtW b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | o when o &&& 0b110111u = 0b010011u ->
    Op.VCLE, None, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | o when o &&& 0b110111u = 0b010100u ->
    Op.VCLT, None, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | o when o &&& 0b110111u = 0b010110u ->
    Op.VABS, None, getOneDtV b, p2Oprs b chkUndefAC (getRegX, getRegZ)
  | o when o &&& 0b110111u = 0b010111u ->
    Op.VNEG, None, getOneDtV b, p2Oprs b chkUndefAC (getRegX, getRegZ)
  | 0b100000u -> Op.VSWP, None, None, p2Oprs b chkUndefZ (getRegX, getRegZ)
  | 0b100001u ->
    Op.VTRN, None, getOneDtS b, p2Oprs b chkUndefAA (getRegX, getRegZ)
  | 0b100010u ->
    Op.VUZP, None, getOneDtS b, p2Oprs b chkUndefAB (getRegX, getRegZ)
  | 0b100011u ->
    Op.VZIP, None, getOneDtS b, p2Oprs b chkUndefAB (getRegX, getRegZ)
  | 0b100100u when isBit6 () ->
    Op.VMOVN, None, getOneDtX b, p2Oprs b chkUndefAD (getRegAC, getRegAD)
  | 0b100100u ->
    Op.VQMOVUN, None, getOneDtY b, p2Oprs b chkUndefAD (getRegAC, getRegAD)
  | 0b100101u when isBit6 () ->
    Op.VQMOVN, None, getOneDtY b, p2Oprs b chkUndefAD (getRegAC, getRegAD)
  | 0b100101u ->
    Op.VQMOVN, None, getOneDtY b, p2Oprs b chkUndefAD (getRegAC, getRegAD)
  | 0b100110u when isBit6 () ->
    Op.VSHLL, None, getOneDtU b, p2Oprs b chkUndefAD (getRegAC, getRegAD)
  | o when o &&& 0b111101u = 0b101100u && isBit6 () ->
    Op.VCVT, None, getTwoDtC b, p2Oprs b chkUndefAE (getRegX, getRegZ)
  | o when o &&& 0b111101u = 0b111000u ->
    Op.VRECPE, None, getOneDtZ b, p2Oprs b chkUndefAF (getRegX, getRegZ)
  | o when o &&& 0b111101u = 0b111001u ->
    Op.VRSQRTE, None, getOneDtZ b, p2Oprs b chkUndefAF (getRegX, getRegZ)
  | o when o &&& 0b111100u = 0b111100u ->
    Op.VCVT, None, getTwoDtB b, p2Oprs b chkUndefW (getRegX, getRegZ)
  | _ -> failwith "Wrong 2 register miscellaneous."

/// Advanced SIMD data-processing instructions, page A7-261
let parseAdvSIMDDataProc b mode =
  let ext f t v = extract b f t = v
  let pick u v = pickBit b u = v
  let k = if mode = ArchOperationMode.ARMMode then pickBit b 24
          else pickBit b 28
  match concat (extract b 23 19) (extract b 7 4) 4 with
  | op when op &&& 0b100000000u = 0b000000000u -> parse3Reg b k
  | op when op &&& 0b101111001u = 0b100000001u -> parse1Reg b k
  | op when op &&& 0b101111001u = 0b100010001u -> parse2Reg b k
  | op when op &&& 0b101101001u = 0b100100001u -> parse2Reg b k
  | op when op &&& 0b101001001u = 0b101000001u -> parse2Reg b k
  | op when op &&& 0b100001001u = 0b100001001u -> parse2Reg b k
  | op when op &&& 0b101000101u = 0b100000000u -> parse3RegDiffLen b k
  | op when op &&& 0b101100101u = 0b101000000u -> parse3RegDiffLen b k
  | op when op &&& 0b101000101u = 0b100000100u -> parse2RegScalar b k
  | op when op &&& 0b101100101u = 0b101000100u -> parse2RegScalar b k
  | op when op &&& 0b101100001u = 0b101100000u && k = 0b0u ->
    Op.VEXT, None, getOneDtE (),
    p4Oprs b chkUndefG (getRegX, getRegY, getRegZ, getImm4C)
  | op when op &&& 0b101100001u = 0b101100000u && pick 11 0b0u ->
    parse2RegMis b
  | op when op &&& 0b101100101u = 0b101100000u && ext 11 10 0b10u ->
    Op.VTBL, None, getOneDtE (),
    p3Oprs b dummyChk (getRegAC, getRegListA, getRegAF)
  | op when op &&& 0b101100101u = 0b101100100u && ext 11 10 0b10u ->
    Op.VTBX, None, getOneDtE (),
    p3Oprs b dummyChk (getRegAC, getRegListA, getRegAF)
  | op when op &&& 0b101101001u = 0b101100000u && ext 11 8 0b1100u ->
    Op.VDUP, None, getOneDtAB b, p2Oprs b chkUndefAG (getRegX, getScalarB)
  | _ -> failwith "Wrong Advanced SIMD data-processing instrs encoding."

/// Advanced SIMD element or structure load/store instructions, page A7-275
let getAdvSIMDOrStrct bin =
  let op = concat (pickBit bin 23) (extract bin 11 8) 4
  let wback = extract bin 3 0 <> 15u |> Some
  match concat op (pickBit bin 21) 1 (* A B L *) with
  | 0b000100u | 0b001100u ->
    Op.VST1, wback, getOneDtAC bin, p2Oprs bin chkUndefAH (getRegListB, getMemS)
  | 0b001110u | 0b010100u ->
    Op.VST1, wback, getOneDtAC bin, p2Oprs bin chkUndefAH (getRegListB, getMemS)
  | 0b000110u | 0b010000u | 0b010010u ->
    Op.VST2, wback, getOneDtAC bin, p2Oprs bin chkUndefAI (getRegListB, getMemS)
  | 0b001000u | 0b001010u ->
    Op.VST3, wback, getOneDtAC bin, p2Oprs bin chkUndefAJ (getRegListB, getMemS)
  | 0b000000u | 0b000010u ->
    Op.VST4, wback, getOneDtAC bin, p2Oprs bin chkUndefAK (getRegListB, getMemS)
  | 0b100000u | 0b101000u | 0b110000u ->
    Op.VST1, wback, getOneDtAD bin, p2Oprs bin chkUndefAL (getRegListC, getMemT)
  | 0b100010u | 0b101010u | 0b110010u ->
    Op.VST2, wback, getOneDtAD bin, p2Oprs bin chkUndefAM (getRegListD, getMemU)
  | 0b100100u | 0b101100u | 0b110100u ->
    Op.VST3, wback, getOneDtAD bin, p2Oprs bin chkUndefAN (getRegListE, getMemV)
  | 0b100110u | 0b101110u | 0b110110u ->
    Op.VST4, wback, getOneDtAD bin, p2Oprs bin chkUndefAO (getRegListF, getMemW)
  | 0b000101u | 0b001101u ->
    Op.VLD1, wback, getOneDtAC bin, p2Oprs bin chkUndefAH (getRegListB, getMemS)
  | 0b001111u | 0b010101u ->
    Op.VLD1, wback, getOneDtAC bin, p2Oprs bin chkUndefAH (getRegListB, getMemS)
  | 0b000111u | 0b010001u | 0b010011u ->
    Op.VLD2, wback, getOneDtAC bin, p2Oprs bin chkUndefAI (getRegListB, getMemS)
  | 0b001001u | 0b001011u ->
    Op.VLD3, wback, getOneDtAC bin, p2Oprs bin chkUndefAJ (getRegListB, getMemS)
  | 0b000001u | 0b000011u ->
    Op.VLD4, wback, getOneDtAC bin, p2Oprs bin chkUndefAK (getRegListB, getMemS)
  | 0b100001u | 0b101001u | 0b110001u ->
    Op.VLD1, wback, getOneDtAD bin, p2Oprs bin chkUndefAL (getRegListC, getMemT)
  | 0b100011u | 0b101011u | 0b110011u ->
    Op.VLD2, wback, getOneDtAD bin, p2Oprs bin chkUndefAM (getRegListD, getMemU)
  | 0b100101u | 0b101101u | 0b110101u ->
    Op.VLD3, wback, getOneDtAD bin, p2Oprs bin chkUndefAN (getRegListE, getMemV)
  | 0b100111u | 0b101111u | 0b110111u ->
    Op.VLD4, wback, getOneDtAD bin, p2Oprs bin chkUndefAO (getRegListF, getMemW)
  | 0b111001u ->
    Op.VLD1, wback, getOneDtAC bin, p2Oprs bin chkUndefAP (getRegListG, getMemX)
  | 0b111011u ->
    Op.VLD2, wback, getOneDtAC bin, p2Oprs bin chkUndefAQ (getRegListH, getMemY)
  | 0b111101u ->
    Op.VLD3, wback, getOneDtAC bin, p2Oprs bin chkUndefAR (getRegListI, getMemZ)
  | 0b111111u -> Op.VLD4, wback, getOneDtAE bin,
                 p2Oprs bin chkUndefAS (getRegListJ, getMemAA)
  | _ -> failwith "Wrong advanced SIMD or struct."

/// 64-bit transfers between ARM core and extension registers, page A7-279
let parse64BitTransfer b =
  let op () = pickBit b 20 = 0b0u
  match extract b 8 4 &&& 0b11101u with
  | 0b00001u when op () ->
    Op.VMOV, None, p4Oprs b chkUnpreAW (getRegAI, getRegAJ, getRegD, getRegC)
  | 0b00001u ->
    Op.VMOV, None, p4Oprs b chkUnpreAX (getRegD, getRegC, getRegAI, getRegAJ)
  | 0b10001u when op () ->
    Op.VMOV, None, p3Oprs b chkUnpreP (getRegAF, getRegD, getRegC)
  | 0b10001u -> Op.VMOV, None, p3Oprs b chkUnpreAY (getRegD, getRegC, getRegAF)
  | _ -> failwith "Wrong 64-bit transfers."

/// Extension register load/store instructions, page A7-274
let parseExtRegLoadStore bin =
  let chkRn = extract bin 19 16 = 0b1101u
  let chk8 = pickBit bin 8 = 0b0u
  let wback = pickBit bin 21 = 0b1u |> Some
  match extract bin 24 20 with
  | op when op &&& 0b11110u = 0b00100u -> parse64BitTransfer bin
  | op when op &&& 0b11011u = 0b01000u && chk8 ->
    Op.VSTMIA, wback, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | op when op &&& 0b11011u = 0b01000u ->
    Op.VSTMIA, wback, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | op when op &&& 0b11011u = 0b01010u && chk8 ->
    Op.VSTMIA, wback, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | op when op &&& 0b11011u = 0b01010u ->
    Op.VSTMIA, wback, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | op when op &&& 0b10011u = 0b10000u ->
    Op.VSTR, None, p2Oprs bin dummyChk (getRegAL, getMemAR)
  | op when op &&& 0b11011u = 0b10010u && chkRn && chk8 ->
    Op.VPUSH, None, p1Opr bin chkUnpreBA getRegListM
  | op when op &&& 0b11011u = 0b10010u && chkRn ->
    Op.VPUSH, None, p1Opr bin chkUnpreAZ getRegListL
  | op when op &&& 0b11011u = 0b10010u && chk8 ->
    Op.VSTMDB, wback, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | op when op &&& 0b11011u = 0b10010u ->
    Op.VSTMDB, wback, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | op when op &&& 0b11011u = 0b01001u && chk8 ->
    Op.VLDMIA, wback, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | op when op &&& 0b11011u = 0b01001u ->
    Op.VLDMIA, wback, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | op when op &&& 0b11011u = 0b01011u && chkRn && chk8 ->
    Op.VPOP, None, p1Opr bin chkUnpreBA getRegListM
  | op when op &&& 0b11011u = 0b01011u && chkRn ->
    Op.VPOP, None, p1Opr bin chkUnpreAZ getRegListL
  | op when op &&& 0b11011u = 0b01011u && chk8 ->
    Op.VLDMIA, wback, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | op when op &&& 0b11011u = 0b01011u ->
    Op.VLDMIA, wback, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | op when op &&& 0b10011u = 0b10001u ->
    Op.VLDR, None, p2Oprs bin dummyChk (getRegAL, getMemAR)
  | op when op &&& 0b11011u = 0b10011u && chk8 ->
    Op.VLDMDB, wback, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | op when op &&& 0b11011u = 0b10011u ->
    Op.VLDMDB, wback, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | _ -> failwith "Wrong supervisor call, and coprocessor instrs."

/// Other VFP data-processing instructions, page A7-272
let parseOtherVFP bin =
  match concat (extract bin 19 16) (extract bin 7 6) 2 with
  | op when op &&& 0b000001u = 0b000000u ->
    Op.VMOV, None, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getImmH)
  | 0b000001u ->
    Op.VMOV, None, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getRegAN)
  | 0b000011u ->
    Op.VABS, None, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getRegAN)
  | 0b000101u ->
    Op.VNEG, None, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getRegAN)
  | 0b000111u ->
    Op.VSQRT, None, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getRegAN)
  | op when op &&& 0b111011u = 0b001001u ->
    Op.VCVTB, None, getTwoDtE bin, p2Oprs bin dummyChk (getRegAO, getRegAJ)
  | op when op &&& 0b111011u = 0b001011u ->
    Op.VCVTT, None, getTwoDtE bin, p2Oprs bin dummyChk (getRegAO, getRegAJ)
  | 0b010001u ->
    Op.VCMP, None, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getRegAN)
  | 0b010011u ->
    Op.VCMPE, None, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getRegAN)
  | 0b010101u ->
    Op.VCMP, None, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getImm0)
  | 0b010111u ->
    Op.VCMPE, None, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getImm0)
  | 0b011111u ->
    Op.VCVT, None, getTwoDtD bin, p2Oprs bin dummyChk (getRegAL', getRegAN)
  | op when op &&& 0b111101u = 0b100001u ->
    Op.VCVT, None, getTwoDtF bin, p2Oprs bin dummyChk (getRegAP, getRegAQ)
  | op when op &&& 0b111001u = 0b101001u ->
    Op.VCVT, None, getTwoDtH bin,
    p3Oprs bin dummyChk (getRegAT, getRegAT, getImmI)
  | op when op &&& 0b111011u = 0b110001u ->
    Op.VCVT, None, getTwoDtF bin, p2Oprs bin dummyChk (getRegAP, getRegAQ)
  | op when op &&& 0b111011u = 0b110011u ->
    Op.VCVTR, None, getTwoDtG bin, p2Oprs bin dummyChk (getRegAR, getRegAS)
  | op when op &&& 0b111001u = 0b111001u ->
    Op.VCVT, None, getTwoDtH bin,
    p3Oprs bin dummyChk (getRegAT, getRegAT, getImmI)
  | _ -> failwith "Wrong Other VFP."

/// Floating-point data-processing instructions, page A7-272
let parseVFP bin =
  let SIMDTyp = getOneDtAF bin
  match concat (extract bin 23 20) (extract bin 7 6) 2 with
  | op when op &&& 0b101101u = 0b000000u ->
    Op.VMLA, None, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b000001u ->
    Op.VMLS, None, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b000100u ->
    Op.VNMLS, None, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b000101u ->
    Op.VNMLA, None, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b001001u ->
    Op.VNMUL, None, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b001000u ->
    Op.VMUL, None, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b001100u ->
    Op.VADD, None, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b001101u ->
    Op.VSUB, None, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b100000u ->
    Op.VDIV, None, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b100100u ->
    Op.VFNMS, None, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b100101u ->
    Op.VFNMA, None, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b101000u ->
    Op.VFMA, None, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b101001u ->
    Op.VFMS, None, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101100u = 0b101100u -> parseOtherVFP bin
  | _ -> failwith "Wrong VFP."

/// 8,16,and 32-bit transfer between ARM core and extension registers, A7-278
let parse81632BTransfer mode b =
  let chkB () = pickBit b 6 = 0b0u
  let chkOp () = pickBit b 20 = 0b0u
  match concat (extract b 23 20) (pickBit b 8) 1 with
  | 0b00000u when chkOp () ->
    Op.VMOV, None, None, p2Oprs b chkUnpreF (getRegAU, getRegD)
  | 0b00000u ->
    Op.VMOV, None, None, p2Oprs b chkUnpreG (getRegD, getRegAU)
  | 0b00010u when chkOp () ->
    Op.VMOV, None, None, p2Oprs b chkUnpreF (getRegAU, getRegD)
  | 0b00010u ->
    Op.VMOV, None, None, p2Oprs b chkUnpreG (getRegD, getRegAU)
  | 0b11100u ->
    Op.VMSR, None, None, p2Oprs b chkUnpreF (getRegFPSCR, getRegD)
  | 0b11110u ->
    Op.VMRS, None, None, p2Oprs b (chkUnpreDL mode) (getRegAZ, getRegFPSCR)
  | o when o &&& 0b10011u = 0b00001u ->
    Op.VMOV, None, getOneDtAG b, p2Oprs b dummyChk (getScalarC, getRegD)
  | o when o &&& 0b10011u = 0b10001u && chkB () ->
    Op.VDUP, None, getOneDtI b, p2Oprs b chkUnpreAO (getRegAB, getRegD)
  | o when o &&& 0b00011u = 0b00011u ->
    Op.VMOV, None, getOneDtAH b, p2Oprs b dummyChk (getRegD, getScalarD)
  | _ -> failwith "Wrong Core and Register."


/// Shift (immediate), add, subtract, move, and compare, page A6-224
let group0LSLInITBlock bin =
  match extract bin 10 6 with
  | 0b0u -> Op.MOV, p2Oprs bin dummyChk (getRegI, getRegH)
  | _ -> Op.LSL, p3Oprs bin dummyChk (getRegI, getRegH, getImm5D)

/// Shift (immediate), add, subtract, move, and compare, page A6-224
let parseGroup0InITBlock cond bin =
  let opcode, operands =
    match extract bin 13 9 with
    | op when op &&& 0b11100u = 0b00000u -> group0LSLInITBlock bin
    | op when op &&& 0b11100u = 0b00100u ->
      Op.LSR, p3Oprs bin dummyChk (getRegI, getRegH, getImm5E)
    | op when op &&& 0b11100u = 0b01000u ->
      Op.ASR, p3Oprs bin dummyChk (getRegI, getRegH, getImm5E)
    | 0b01100u -> Op.ADD, p3Oprs bin dummyChk (getRegI, getRegH, getRegG)
    | 0b01101u -> Op.SUB, p3Oprs bin dummyChk (getRegI, getRegH, getRegG)
    | 0b01110u -> Op.ADD, p3Oprs bin dummyChk (getRegI, getRegH, getImm3A)
    | 0b01111u -> Op.SUB, p3Oprs bin dummyChk (getRegI, getRegH, getImm3A)
    | op when op &&& 0b11100u = 0b10000u ->
      Op.MOV, p2Oprs bin dummyChk (getRegJ, getImm8A)
    | op when op &&& 0b11100u = 0b11000u ->
      Op.ADD, p2Oprs bin dummyChk (getRegJ, getImm8A)
    | op when op &&& 0b11100u = 0b11100u ->
      Op.SUB, p2Oprs bin dummyChk (getRegJ, getImm8A)
    | _ -> failwith "Wrong opcode in parseGroup0."
  opcode, cond, 0uy, None, None, operands

/// Shift (immediate), add, subtract, move, and compare, page A6-224
let group0LSLOutITBlock bin =
  match extract bin 10 6 with
  | 0b0u -> Op.MOVS, p2Oprs bin dummyChk (getRegI, getRegH)
  | _ -> Op.LSLS, p3Oprs bin dummyChk (getRegI, getRegH, getImm5D)

/// Shift (immediate), add, subtract, move, and compare, page A6-224
let parseGroup0OutITBlock bin =
  let opcode, operands =
    match extract bin 13 9 with
    | op when op &&& 0b11100u = 0b00000u -> group0LSLOutITBlock bin
    | op when op &&& 0b11100u = 0b00100u ->
      Op.LSRS, p3Oprs bin dummyChk (getRegI, getRegH, getImm5E)
    | op when op &&& 0b11100u = 0b01000u ->
      Op.ASRS, p3Oprs bin dummyChk (getRegI, getRegH, getImm5E)
    | 0b01100u -> Op.ADDS, p3Oprs bin dummyChk (getRegI, getRegH, getRegG)
    | 0b01101u -> Op.SUBS, p3Oprs bin dummyChk (getRegI, getRegH, getRegG)
    | 0b01110u -> Op.ADDS, p3Oprs bin dummyChk (getRegI, getRegH, getImm3A)
    | 0b01111u -> Op.SUBS, p3Oprs bin dummyChk (getRegI, getRegH, getImm3A)
    | op when op &&& 0b11100u = 0b10000u ->
      Op.MOVS, p2Oprs bin dummyChk (getRegJ, getImm8A)
    | op when op &&& 0b11100u = 0b11000u ->
      Op.ADDS, p2Oprs bin dummyChk (getRegJ, getImm8A)
    | op when op &&& 0b11100u = 0b11100u ->
      Op.SUBS, p2Oprs bin dummyChk (getRegJ, getImm8A)
    | _ -> failwith "Wrong opcode in parseGroup0."
  opcode, None, 0uy, None, None, operands

/// Shift (immediate), add, subtract, move, and compare, page A6-224
let parseGroup0 itstate cond bin =
  if extract bin 13 9 &&& 0b11100u = 0b10100u then
    Op.CMP, cond, 0uy, None, None, p2Oprs bin dummyChk (getRegJ, getImm8A)
  else
    match inITBlock itstate with
    | true -> parseGroup0InITBlock cond bin
    | false -> parseGroup0OutITBlock bin

let parseGroup1InITBlock bin =
  match extract bin 9 6 with
  | 0b0000u -> Op.AND, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0001u -> Op.EOR, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0010u -> Op.LSL, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0011u -> Op.LSR, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0100u -> Op.ASR, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0101u -> Op.ADC, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0110u -> Op.SBC, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0111u -> Op.ROR, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b1001u -> Op.RSB, p3Oprs bin dummyChk (getRegI, getRegH, getImm0)
  | 0b1100u -> Op.ORR, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b1101u -> Op.MUL, p3Oprs bin dummyChk (getRegI, getRegH, getRegI)
  | 0b1110u -> Op.BIC, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b1111u -> Op.MVN, p2Oprs bin dummyChk (getRegI, getRegH)
  | _ -> failwith "Wrong opcode in parseGroup1."

let parseGroup1OutITBlock bin =
  match extract bin 9 6 with
  | 0b0000u -> Op.ANDS, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0001u -> Op.EORS, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0010u -> Op.LSLS, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0011u -> Op.LSRS, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0100u -> Op.ASRS, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0101u -> Op.ADCS, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0110u -> Op.SBCS, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b0111u -> Op.RORS, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b1001u -> Op.RSBS, p3Oprs bin dummyChk (getRegI, getRegH, getImm0)
  | 0b1100u -> Op.ORRS, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b1101u -> Op.MULS, p3Oprs bin dummyChk (getRegI, getRegH, getRegI)
  | 0b1110u -> Op.BICS, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b1111u -> Op.MVNS, p2Oprs bin dummyChk (getRegI, getRegH)
  | _ -> failwith "Wrong opcode in parseGroup1."

/// Data-processing, page A6-225
let parseGroup1 itstate cond bin =
  let parseWithITSTATE () = // XXX FIXME
    if inITBlock itstate then
      let op, oprs = parseGroup1InITBlock bin
      op, cond, 0uy, None, None, oprs
    else
      let op, oprs = parseGroup1OutITBlock bin
      op, None, 0uy, None, None, oprs
  match extract bin 9 6 with
  | 0b1000u ->
    Op.TST, cond, 0uy, None, None, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b1010u ->
    Op.CMP, cond, 0uy, None, None, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b1011u ->
    Op.CMN, cond, 0uy, None, None, p2Oprs bin dummyChk (getRegI, getRegH)
  | _ -> parseWithITSTATE ()

let parseGroup2ADD itstate bin =
  match concat (pickBit bin 7) (extract bin 2 0) 3, extract bin 6 3 with
  | 0b1101u, _ -> Op.ADD, p2Oprs bin dummyChk (getRegO, getRegP)
  | _ , 0b1101u ->
    Op.ADD, p3Oprs bin (chkUnpreDF itstate) (getRegO, getRegP, getRegO)
  | _ -> Op.ADD, p2Oprs bin (chkUnpreR itstate) (getRegO, getRegP)

/// Special data instructions and branch and exchange, page A6-226
let parseGroup2 itstate cond bin =
  let opcode, operands =
    match extract bin 9 7 with
    | 0b000u | 0b001u -> parseGroup2ADD itstate bin
    | 0b010u | 0b011u -> Op.CMP, p2Oprs bin chkUnpreS (getRegO, getRegP)
    | 0b100u | 0b101u ->
      Op.MOV, p2Oprs bin (chkUnpreDF itstate) (getRegO, getRegP)
    | 0b110u -> Op.BX, p1Opr bin (chkUnpreDG itstate) getRegP
    | 0b111u -> Op.BLX, p1Opr bin (chkUnpreDH itstate) getRegP
    | _ -> failwith "Wrong opcode in parseGroup2."
  opcode, cond, 0uy, None, None, operands

let parseGroup3Sub cond bin =
  match extract bin 15 11 with
  | 0b01100u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemE)
    Op.STR, cond, 0uy, Some false, None, oprs
  | 0b01101u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemE)
    Op.LDR, cond, 0uy, Some false, None, oprs
  | 0b01110u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemF)
    Op.STRB, cond, 0uy, Some false, None, oprs
  | 0b01111u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemF)
    Op.LDRB, cond, 0uy, Some false, None, oprs
  | 0b10000u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemG)
    Op.STRH, cond, 0uy, Some false, None, oprs
  | 0b10001u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemG)
    Op.LDRH, cond, 0uy, Some false, None, oprs
  | 0b10010u ->
    let oprs = p2Oprs bin dummyChk (getRegJ, getMemC)
    Op.STR, cond, 0uy, Some false, None, oprs
  | 0b10011u ->
    let oprs = p2Oprs bin dummyChk (getRegJ, getMemC)
    Op.LDR, cond, 0uy, Some false, None, oprs
  | _ -> failwith "Wrong opcode in parseGroup3."

/// Load/store single data item, page A6-227
let parseGroup3 cond bin =
  match concat (extract bin 15 12) (extract bin 11 9) 3 with
  | 0b0101000u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemD)
    Op.STR, cond, 0uy, Some false, None, oprs
  | 0b0101001u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemD)
    Op.STRH, cond, 0uy, Some false, None, oprs
  | 0b0101010u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemD)
    Op.STRB, cond, 0uy, Some false, None, oprs
  | 0b0101011u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemD)
    Op.LDRSB, cond, 0uy, Some false, None, oprs
  | 0b0101100u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemD)
    Op.LDR, cond, 0uy, None, None, oprs
  | 0b0101101u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemD)
    Op.LDRH, cond, 0uy, Some false, None, oprs
  | 0b0101110u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemD)
    Op.LDRB, cond, 0uy, Some false, None, oprs
  | 0b0101111u ->
    let oprs = p2Oprs bin dummyChk (getRegI, getMemD)
    Op.LDRSH, cond, 0uy, Some false, None, oprs
  | _ -> parseGroup3Sub cond bin

let inverseCond cond =
  (cond &&& 0xeuy) ||| ((~~~ cond) &&& 0b1uy)

let getITOpcodeWithX cond x =
  let invCond = inverseCond cond
  if x then Op.ITT, [ cond; cond ] else Op.ITE, [ cond; invCond ]

let getITOpcodeWithXY cond x y =
  let invCond = inverseCond cond
  match x, y with
  | true, true -> Op.ITTT, [ cond; cond; cond ]
  | true, false -> Op.ITTE, [ cond; cond; invCond ]
  | false, true -> Op.ITET, [ cond; invCond; cond ]
  | false, false -> Op.ITEE, [ cond; invCond; invCond ]

let getITOpcodeWithXYZ cond x y z =
  let invCond = inverseCond cond
  match x, y, z with
  | true, true, true -> Op.ITTTT, [ cond; cond; cond; cond ]
  | true, true, false -> Op.ITTTE, [ cond; cond; cond; invCond ]
  | true, false, true -> Op.ITTET, [ cond; cond; invCond; cond ]
  | true, false, false -> Op.ITTEE, [ cond; cond; invCond; invCond ]
  | false, true, true -> Op.ITETT, [ cond; invCond; cond; cond ]
  | false, true, false -> Op.ITETE, [ cond; invCond; cond; invCond ]
  | false, false, true -> Op.ITEET, [ cond; invCond; invCond; cond ]
  | false, false, false -> Op.ITEEE, [ cond; invCond; invCond; invCond ]

let getIT fstCond cond mask =
  let mask0 = pickBit mask 0
  let mask1 = pickBit mask 1
  let mask2 = pickBit mask 2
  let mask3 = pickBit mask 3
  let x = fstCond = pickBit mask 3
  let y = fstCond = pickBit mask 2
  let z = fstCond = pickBit mask 1
  let opcode, itState =
    match mask3, mask2, mask1, mask0 with
    | 0b1u, 0b0u, 0b0u, 0b0u -> Op.IT, [ cond ]
    | _, 0b1u, 0b0u, 0b0u -> getITOpcodeWithX cond x
    | _, _, 0b1u, 0b0u -> getITOpcodeWithXY cond x y
    | _, _, _, 0b1u -> getITOpcodeWithXYZ cond x y z
    | _ -> failwith "Wrong opcode in IT instruction"
  opcode, itState

/// If-Then, and hints, page A6-229
let getIfThenNHints cond (itstate: byref<byte list>) bin =
  match extract bin 7 4, extract bin 3 0 with
  | o1, o2 when o2 <> 0b0000u ->
    let opcode, itstate' = getIT (pickBit o1 0) (byte o1) o2
    let operand = p1Opr bin (chkUnpreBD opcode itstate) getFirstCond
    itstate <- itstate'
    opcode, None, (byte bin), None, None, operand
  | 0b0000u, _ -> Op.NOP, cond, 0uy, None, None, NoOperand
  | 0b0001u, _ -> Op.YIELD, cond, 0uy, None, None, NoOperand
  | 0b0010u, _ -> Op.WFE, cond, 0uy, None, None, NoOperand
  | 0b0011u, _ -> Op.WFI, cond, 0uy, None, None, NoOperand
  | 0b0100u, _ -> Op.SEV, cond, 0uy, None, None, NoOperand
  | _ -> failwith "Wrong if-then & hints."

/// Miscellaneous 16-bit instructions, page A6-228
let parseGroup4 (itstate: byref<byte list>) cond bin =
  match extract bin 11 5 with
  | op when op &&& 0b1111100u = 0b0000000u ->
    Op.ADD, cond, 0uy, None, None,
    p3Oprs bin dummyChk (getRegSP, getRegSP, getImm7A)
  | op when op &&& 0b1111100u = 0b0000100u ->
    Op.SUB, cond, 0uy, None, None,
    p3Oprs bin dummyChk (getRegSP, getRegSP, getImm7A)
  | op when op &&& 0b1111000u = 0b0001000u ->
    Op.CBZ, None, 0uy, None, None,
    p2Oprs bin (chkUnpreDE itstate) (getRegI, getLbl7A)
  | op when op &&& 0b1111110u = 0b0010000u ->
    Op.SXTH, cond, 0uy, None, None,
    p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111110u = 0b0010010u ->
    Op.SXTB, cond, 0uy, None, None,
    p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111110u = 0b0010100u ->
    Op.UXTH, cond, 0uy, None, None,
    p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111110u = 0b0010110u ->
    Op.UXTB, cond, 0uy, None, None,
    p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111000u = 0b0011000u ->
    Op.CBZ, None, 0uy, None, None,
    p2Oprs bin (chkUnpreDE itstate) (getRegI, getLbl7A)
  | op when op &&& 0b1110000u = 0b0100000u ->
    Op.PUSH, cond, 0uy, None, None, p1Opr bin chkUnpreBC getRegListN
  | 0b0110010u ->
    Op.SETEND, None, 0uy, None, None,
    p1Opr bin (chkUnpreDE itstate) getEndianB
  | 0b0110011u when pickBit bin 4 = 0b0u ->
    Op.CPSIE, None, 0uy, None, None,
    p1Opr bin (chkUnpreDE itstate) getFlagB
  | 0b0110011u ->
    Op.CPSID, None, 0uy, None, None,
    p1Opr bin (chkUnpreDE itstate) getFlagB
  | op when op &&& 0b1111000u = 0b1001000u ->
    Op.CBNZ, None, 0uy, None, None,
    p2Oprs bin (chkUnpreDE itstate) (getRegI, getLbl7A)
  | op when op &&& 0b1111110u = 0b1010000u ->
    Op.REV, cond, 0uy, None, None,
    p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111110u = 0b1010010u ->
    Op.REV16, cond, 0uy, None, None,
    p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111110u = 0b1010110u ->
    Op.REVSH, cond, 0uy, None, None,
    p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111000u = 0b1011000u ->
    Op.CBNZ, None, 0uy, None, None,
    p2Oprs bin (chkUnpreDE itstate) (getRegI, getLbl7A)
  | op when op &&& 0b1110000u = 0b1100000u ->
    Op.POP, cond, 0uy, None, None, p1Opr bin chkUnpreBC getRegListO
  | op when op &&& 0b1111000u = 0b1110000u ->
    Op.BKPT, None, 0uy, None, None, p1Opr bin dummyChk getImm8A
  | op when op &&& 0b1111000u = 0b1111000u -> getIfThenNHints cond &itstate bin
  | _ -> failwith "Wrong opcode in parseGroup4."

/// Conditional branch, and Supervisor Call, page A6-229
let parseGroup5 itstate cond bin =
  let bCond c = c |> byte |> parseCond |> Some
  match extract bin 11 8 with
  | 0b1110u -> Op.UDF, cond, 0uy, None, None, p1Opr bin dummyChk getImm8A
  | 0b1111u -> Op.SVC, cond, 0uy, None, None, p1Opr bin dummyChk getImm8A
  | c ->
    Op.B, bCond c, 0uy, None, getQfN (),
    p1Opr bin (chkUnpreBE itstate) getLbl9A

/// Load/store multiple. page A6-237
let parseGroup6 itstate bin =
  let struct (b1, b2) = halve bin
  let b = concat b1 b2 16
  let chkWRn = concat (pickBit b1 5) (extract b1 3 0) 4 = 0b11101u
  let wback = pickBit b1 5 = 0b1u |> Some
  match concat (extract b1 8 7) (pickBit b1 4) 1 with
  | 0b000u -> Op.SRSDB, wback, None, None, p2Oprs b dummyChk (getRegM, getImm5B)
  | 0b001u -> Op.RFEDB, wback, None, None, p1Opr b (chkUnpreDI itstate) getRegAA
  | 0b010u -> Op.STM, wback, getQfW (), None,
              p2Oprs (b1, b2) chkUnpreBF (getRegisterWB, getRegListP)
  | 0b011u when chkWRn ->
    Op.POP, None, getQfW (), None, p1Opr (b1, b2) (chkUnpreBG itstate) getRegListQ
  | 0b011u -> Op.LDM, wback, getQfW (), None,
              p2Oprs (b1, b2) (chkUnpreBH itstate) (getRegisterWB, getRegListQ)
  | 0b100u when chkWRn ->
    Op.PUSH, None, getQfW (), None, p1Opr (b1, b2) chkUnpreBI getRegListP
  | 0b100u -> Op.STMDB, wback, None, None,
              p2Oprs (b1, b2) chkUnpreBF (getRegisterWB, getRegListP)
  | 0b101u -> Op.LDMDB, wback, None, None,
              p2Oprs (b1, b2) (chkUnpreBH itstate) (getRegisterWB, getRegListQ)
  | 0b110u -> Op.SRSIA, wback, None, None, p2Oprs b dummyChk (getRegM, getImm5B)
  | 0b111u -> Op.RFEIA, wback, None, None, p1Opr b (chkUnpreDI itstate) getRegAA
  | _ -> failwith "Wrong opcode in parseGroup6."

/// Load/store dual, load/store exclusive, table branch, page A6-238
let parseGroup7Not010 b1 b2 =
  let op12 = concat (extract b1 8 7) (extract b1 5 4) 2
  let isRn1111 = extract b1 3 0 = 0b1111u
  let wback () = pickBit b1 5 = 0b1u |> Some
  match op12 with
  | o when o &&& 0b1111u = 0b0000u ->
    Op.STREX, None, p3Oprs (b1, b2) chkUnpreBJ (getRegAV, getRegAW, getMemAF)
  | o when o &&& 0b1111u = 0b0001u ->
    Op.LDREX, None, p2Oprs (b1, b2) chkUnpreBK (getRegAW, getMemAF)
  | o when o &&& 0b1011u = 0b0010u ->
    Op.STRD, wback (), p3Oprs (b1, b2) chkUnpreBM (getRegAW, getRegAV, getMemAH)
  | o when o &&& 0b1001u = 0b1000u ->
    Op.STRD, wback (), p3Oprs (b1, b2) chkUnpreBM (getRegAW, getRegAV, getMemAH)
  | o when o &&& 0b1011u = 0b0011u && not isRn1111 ->
    Op.LDRD, wback (), p3Oprs (b1, b2) chkUnpreBN (getRegAW, getRegAV, getMemAH)
  | o when o &&& 0b1001u = 0b1001u && not isRn1111 ->
    Op.LDRD, wback (), p3Oprs (b1, b2) chkUnpreBN (getRegAW, getRegAV, getMemAH)
  | o when o &&& 0b1011u = 0b0011u && isRn1111 ->
    Op.LDRD, wback (), p3Oprs (b1, b2) chkUnpreBO (getRegAW, getRegAV, getMemAI)
  | o when o &&& 0b1001u = 0b1001u && isRn1111 ->
    Op.LDRD, wback (), p3Oprs (b1, b2) chkUnpreBO (getRegAW, getRegAV, getMemAI)
  | _ -> failwith "Wrong opcode in parseGroup7."

/// Load/store dual, load/store exclusive, table branch, page A6-238
let parseGroup7With010 itstate b1 b2 =
  match concat (pickBit b1 4) (extract b2 6 4) 3 with
  | 0b0100u ->
    Op.STREXB, None, p3Oprs (b1, b2) chkUnpreBJ (getRegAX, getRegAW, getMemAJ)
  | 0b0101u ->
    Op.STREXH, None, p3Oprs (b1, b2) chkUnpreBJ (getRegAX, getRegAW, getMemAJ)
  | 0b0111u ->
    Op.STREXD, None,
    p4Oprs (b1, b2) chkUnpreBQ (getRegAX, getRegAW, getRegAV, getMemAJ)
  | 0b1000u -> Op.TBB, None, p1Opr (b1, b2) (chkUnpreBR itstate) getMemAK
  | 0b1001u -> Op.TBH, None, p1Opr (b1, b2) (chkUnpreBR itstate) getMemAL
  | 0b1100u -> Op.LDREXB, None, p2Oprs (b1, b2) chkUnpreBS (getRegAW, getMemAJ)
  | 0b1101u -> Op.LDREXH, None, p2Oprs (b1, b2) chkUnpreBS (getRegAW, getMemAJ)
  | 0b1111u ->
    Op.LDREXD, None, p3Oprs (b1, b2) chkUnpreBP (getRegAW, getRegAV, getMemAJ)
  | _ -> failwith "Wrong opcode in parseGroup7."

/// Load/store dual, load/store exclusive, table branch, page A6-238
let parseGroup7 itstate bin =
  let struct (b1, b2) = halve bin
  let opcode, wback, operands =
    match extract b1 8 7, pickBit b1 5 with
    | 0b01u, 0b0u -> parseGroup7With010 itstate b1 b2
    | _ -> parseGroup7Not010 b1 b2
  opcode, wback, None, None, operands

/// Move register and immediate shifts, page A6-244
let parseMOVRegImmShift b1 b2 =
  let imm = concat (extract b2 14 12) (extract b2 7 6) 2
  let oprs2 () = p2Oprs (b1, b2)
  let oprs3 () = p3Oprs (b1, b2)
  match extract b2 5 4, imm, pickBit b1 4 with
  | 0b00u, 0u, 0u -> Op.MOV, getQfW (), oprs2 () chkUnpreBT (getRegAV, getRegAX)
  | 0b00u, 0u, 1u ->
    Op.MOVS, getQfW (), oprs2 () chkUnpreBU (getRegAV, getRegAX)
  | 0b00u, _, 0u ->
    Op.LSL, getQfW (), oprs3 () chkUnpreBV (getRegAV, getRegAX, getImm5G)
  | 0b00u, _, 1u ->
    Op.LSLS, getQfW (), oprs3 () chkUnpreBV (getRegAV, getRegAX, getImm5G)
  | 0b01u, _, 0u ->
    Op.LSR, getQfW (), oprs3 () chkUnpreBV (getRegAV, getRegAX, getImm5G)
  | 0b01u, _, 1u ->
    Op.LSRS, getQfW (), oprs3 () chkUnpreBV (getRegAV, getRegAX, getImm5G)
  | 0b10u, _, 0u ->
    Op.ASR, getQfW (), oprs3 () chkUnpreBV (getRegAV, getRegAX, getImm5G)
  | 0b10u, _, 1u ->
    Op.ASRS, getQfW (), oprs3 () chkUnpreBV (getRegAV, getRegAX, getImm5G)
  | 0b11u, 0u, 0u -> Op.RRX, None, oprs2 () chkUnpreBU (getRegAV, getRegAX)
  | 0b11u, 0u, 1u -> Op.RRXS, None, oprs2 () chkUnpreBU (getRegAV, getRegAX)
  | 0b11u, _, 0u ->
    Op.ROR, getQfW (), oprs3 () chkUnpreBV (getRegAV, getRegAX, getImm5G)
  | 0b11u, _, 1u ->
    Op.RORS, getQfW (), oprs3 () chkUnpreBV (getRegAV, getRegAX, getImm5G)
  | _ -> failwith "Wrong opcode in parseMOVRegImmShift."

/// Data-processing (shifted register), page A6-243
let parseGroup8WithRdSub b1 b2 =
  let operands = (getRegAV, getRegAY, getRegAX, getShiftF)
  match extract b1 8 4 with
  | 0b00000u -> Op.AND, getQfW (), p4Oprs (b1, b2) chkUnpreBX operands
  | 0b00001u -> Op.ANDS, getQfW (), p4Oprs (b1, b2) chkUnpreBY operands
  | 0b01000u -> Op.EOR, getQfW (), p4Oprs (b1, b2) chkUnpreBX operands
  | 0b01001u -> Op.EORS, getQfW (), p4Oprs (b1, b2) chkUnpreBY operands
  | 0b10000u -> Op.ADD, getQfW (), p4Oprs (b1, b2) chkUnpreCA operands
  | 0b10001u -> Op.ADDS, getQfW (), p4Oprs (b1, b2) chkUnpreCB operands
  | 0b11010u -> Op.SUB, getQfW (), p4Oprs (b1, b2) chkUnpreCA operands
  | 0b11011u -> Op.SUBS, getQfW (), p4Oprs (b1, b2) chkUnpreCB operands
  | _ -> failwith "Wrong opcode in parseGroup8."

/// Data-processing (shifted register), page A6-243
let parseGroup8WithRd b1 b2 =
  let isNotRdS11111 = concat (extract b2 11 8) (pickBit b1 4) 1 <> 0b11111u
  let getOpr chk =
    p3Oprs (b1, b2) chk (getRegAY, getRegAX, getShiftF)
  if isNotRdS11111 then parseGroup8WithRdSub b1 b2
  else match extract b1 8 5 with
       | 0b0000u -> Op.TST, getQfW (), getOpr chkUnpreBV
       | 0b0100u -> Op.TEQ, getQfW (), getOpr chkUnpreBV
       | 0b1000u -> Op.CMN, getQfW (), getOpr chkUnpreBW
       | 0b1101u -> Op.CMP, getQfW (), getOpr chkUnpreBW
       | _ -> failwith "Wrong opcode in parseGroup8."

/// Data-processing (shifted register), page A6-243
let parseGroup8WithRnSub b1 b2 =
  match extract b1 6 5, pickBit b1 4 with
  | 0b10u, 0u -> Op.ORR
  | 0b10u, 1u -> Op.ORRS
  | 0b11u, 0u -> Op.ORN
  | 0b11u, 1u -> Op.ORNS
  | _ -> failwith "Wrong opcode in parseGroup8."
  , getQfW (),
  p4Oprs (b1, b2) chkUnpreBZ (getRegAV, getRegAY, getRegAX, getShiftF)

/// Data-processing (shifted register), page A6-243
let parseGroup8WithRn b1 b2 =
  if extract b1 3 0 <> 0b1111u then parseGroup8WithRnSub b1 b2
  else
    match extract b1 6 4 with
    | 0b100u | 0b101u  -> parseMOVRegImmShift b1 b2
    | 0b110u -> Op.MVN, getQfW (), p3Oprs (b1, b2) chkUnpreBV
                                  (getRegAV, getRegAX, getShiftF)
    | 0b111u -> Op.MVNS, getQfW (), p3Oprs (b1, b2) chkUnpreBV
                                   (getRegAV, getRegAX, getShiftF)
    | _ -> failwith "Wrong opcode in parseGroup8."

/// Data-processing (shifted register), page A6-243
let parseGroup8PKH b1 b2 =
  (if pickBit b2 5 = 1u then Op.PKHTB else Op.PKHBT), None,
  p4Oprs (b1, b2) chkBothB (getRegAV, getRegAY, getRegAX, getShiftF)

/// Data-processing (shifted register), page A6-243
let parseGroup8WithS b1 b2 =
  match extract b1 8 4 with
  | 0b00010u -> Op.BIC
  | 0b00011u -> Op.BICS
  | 0b10100u -> Op.ADC
  | 0b10101u -> Op.ADCS
  | 0b10110u -> Op.SBC
  | 0b10111u -> Op.SBCS
  | 0b11100u -> Op.RSB
  | 0b11101u -> Op.RSBS
  | _ -> failwith "Wrong opcode in parseGroup8."
  , getQfW (),
  p4Oprs (b1, b2) chkUnpreBX (getRegAV, getRegAY, getRegAX, getShiftF)

/// Data-processing (shifted register), page A6-243
let parseGroup8 bin =
  let struct (b1, b2) = halve bin
  let opcode, q, operands =
    match extract b1 8 5 with
    | 0b0000u -> parseGroup8WithRd b1 b2
    | 0b0001u -> parseGroup8WithS b1 b2
    | 0b0010u | 0b0011u -> parseGroup8WithRn b1 b2
    | 0b0100u -> parseGroup8WithRd b1 b2
    | 0b0110u -> parseGroup8PKH b1 b2
    | 0b1000u -> parseGroup8WithRd b1 b2
    | 0b1010u | 0b1011u -> parseGroup8WithS b1 b2
    | 0b1101u -> parseGroup8WithRd b1 b2
    | 0b1110u -> parseGroup8WithS b1 b2
    | _ -> failwith "Wrong opcode in parseGroup8."
  opcode, None, q, None, operands

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9MCRR b =
  if pickBit b 28 = 0b0u then
    Op.MCRR, None,
    p5Oprs b chkUnpreAU (getPRegA, getImm4D, getRegD, getRegC, getCRegB)
  else
    Op.MCRR2, None,
    p5Oprs b chkUnpreAU (getPRegA, getImm4D, getRegD, getRegC, getCRegB)

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9MRRC b =
  if pickBit b 28 = 0b0u then
    Op.MRRC, None,
    p5Oprs b chkUnpreAV (getPRegA, getImm4D, getRegD, getRegC, getCRegB)
  else
    Op.MRRC2, None,
    p5Oprs b chkUnpreAV (getPRegA, getImm4D, getRegD, getRegC, getCRegB)

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9STC b =
  let wback = pickBit b 21 = 0b1u |> Some
  let opcode =
    match pickBit b 28, pickBit b 22 with
    | 0u, 0u -> Op.STC
    | 0u, 1u -> Op.STCL
    | 1u, 0u -> Op.STC2
    | 1u, 1u -> Op.STC2L
    | _ -> failwith "Wrong opcode in parseGroup9."
  opcode, wback, p3Oprs b dummyChk (getPRegA, getCRegA, getMemAE)

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9LDC b =
  //,Some (pickBit b 21 = 0b1u),
  let opcode =
    match pickBit b 28, pickBit b 22 with
    | 0u, 0u -> Op.LDC
    | 0u, 1u -> Op.LDCL
    | 1u, 0u -> Op.LDC2
    | 1u, 1u -> Op.LDC2L
    | _ -> failwith "Wrong opcode in parseGroup9."
  let wback, oprs =
    if extract b 19 16 = 0b1111u then
      None, p3Oprs b dummyChk (getPRegA, getCRegA, getMemAD)
    else Some (pickBit b 21 = 0b1u),
         p3Oprs b dummyChk (getPRegA, getCRegA, getMemAE)
  opcode, wback, oprs

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9CDPMRC b =
  match pickBit b 28, pickBit b 20, pickBit b 4 with
  | 0u, _, 0u ->
    Op.CDP, None, p6Oprs b dummyChk
                  (getPRegA, getImm4E, getCRegA, getCRegC, getCRegB, getImm3B)
  | 1u, _, 0u ->
    Op.CDP2, None, p6Oprs b dummyChk
                   (getPRegA, getImm4E, getCRegA, getCRegC, getCRegB, getImm3B)
  | 0u, 0u, 1u ->
    Op.MCR, None, p6Oprs b chkUnpreBB
                  (getPRegA, getImm3C, getRegD, getCRegC, getCRegB, getImm3B)
  | 1u, 0u, 1u ->
    Op.MCR2, None, p6Oprs b chkUnpreBB
                   (getPRegA, getImm3C, getRegD, getCRegC, getCRegB, getImm3B)
  | 0u, 1u, 1u ->
    Op.MRC, None, p6Oprs b dummyChk
                  (getPRegA, getImm3C, getRegD, getCRegC, getCRegB, getImm3B)
  | 1u, 1u, 1u ->
    Op.MRC2, None, p6Oprs b dummyChk
                   (getPRegA, getImm3C, getRegD, getCRegC, getCRegB, getImm3B)
  | _ -> failwith "Wrong opcode in parseGroup9."

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9Sub2 b1 b2 =
  let b = concat b1 b2 16
  let opcode, wback, operands =
    match extract b1 9 4 with
    | 0b000100u -> parseGroup9MCRR b
    | 0b000101u -> parseGroup9MRRC b
    | op when op &&& 0b100001u = 0b000000u -> parseGroup9STC b
    | op when op &&& 0b100001u = 0b000001u -> parseGroup9LDC b
    | op when op &&& 0b110000u = 0b100000u -> parseGroup9CDPMRC b
    | _ -> failwith "Wrong opcode in parseGroup9."
  opcode, wback, None, operands

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9Sub b1 b2 =
  let b = concat b1 b2 16
  match pickBit b1 9 with
  | 0u -> raise UndefinedException
  | 1u -> parseAdvSIMDDataProc b ArchOperationMode.ThumbMode
  | _ -> failwith "Wrong opcode in parseGroup9."

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9Sub3 b1 b2 =
  let op = concat (extract b1 9 4) (pickBit b2 4) 1
  let b = concat b1 b2 16
  let chk () = op &&& 0b1110100u <> 0b0000000u
  checkUndef (pickBit b1 12 = 0b1u)
  match op with
  | o when o &&& 0b1000000u = 0b0000000u && chk () ->
    let opcode, wback, operands = parseExtRegLoadStore b
    opcode, wback, None, operands
  | o when o &&& 0b1111100u = 0b0001000u ->
    let opcode, wback, operands = parse64BitTransfer b
    opcode, wback, None, operands
  | o when o &&& 0b1000001u = 0b1000000u -> parseVFP b
  | o when o &&& 0b1000001u = 0b1000001u ->
    parse81632BTransfer ArchOperationMode.ThumbMode b
  | _ -> failwith "Wrong opcode in parseGroup9."

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9 bin =
  let struct (b1, b2) = halve bin
  let op1 = extract b1 9 4
  let chkCoproc = extract b2 11 8 &&& 0b1110u <> 0b1010u
  let chkSub = op1 = 0u || op1 = 1u || op1 &&& 0b110000u = 0b110000u
  let opcode, wback, dt, operands =
    if chkSub then parseGroup9Sub b1 b2
    elif chkCoproc then parseGroup9Sub2 b1 b2
    else parseGroup9Sub3 b1 b2
  opcode, wback, None, dt, operands

/// Data-processing (modified immediate), page A6-231
let parseGroup10WithRdSub b1 b2 =
  match extract b1 8 4 with
  | 0b00000u ->
    Op.AND, None, p3Oprs (b1, b2) chkUnpreBV (getRegAV, getRegAY, getImmJ), None
  | 0b00001u ->
    Op.ANDS, None, p3Oprs (b1, b2) chkUnpreCD (getRegAV, getRegAY, getImmJ),
    getCFThumb (b1, b2)
  | 0b01000u ->
    Op.EOR, None, p3Oprs (b1, b2) chkUnpreBV (getRegAV, getRegAY, getImmJ), None
  | 0b01001u ->
    Op.EORS, None, p3Oprs (b1, b2) chkUnpreCD (getRegAV, getRegAY, getImmJ),
    getCFThumb (b1, b2)
  | 0b10000u ->
    Op.ADD,
    getQfW (), p3Oprs (b1, b2) chkUnpreCF (getRegAV, getRegAY, getImmJ), None
  | 0b10001u ->
    Op.ADDS,
    getQfW (), p3Oprs (b1, b2) chkUnpreCG (getRegAV, getRegAY, getImmJ), None
  | 0b11010u ->
    Op.SUB,
    getQfW (), p3Oprs (b1, b2) chkUnpreCF (getRegAV, getRegAY, getImmJ), None
  | 0b11011u ->
    Op.SUBS, getQfW (),
    p3Oprs (b1, b2) chkUnpreCG (getRegAV, getRegAY, getImmJ), None
  | _ -> failwith "Wrong opcode in parseGroup10."

/// Data-processing (modified immediate), page A6-231
let parseGroup10WithRd b1 b2 =
  let isRdS11111 = concat (extract b2 11 8) (pickBit b1 4) 1 = 0b11111u
  if not isRdS11111 then parseGroup10WithRdSub b1 b2
  else
    match extract b1 8 5 with
    | 0b0000u -> Op.TST, None, p2Oprs (b1, b2) chkUnpreBL (getRegAY, getImmJ),
                 getCFThumb (b1, b2)
    | 0b0100u -> Op.TEQ, None, p2Oprs (b1, b2) chkUnpreBL (getRegAY, getImmJ),
                 getCFThumb (b1, b2)
    | 0b1000u -> Op.CMN, None, p2Oprs (b1, b2) chkUnpreCC (getRegAY, getImmJ),
                 None
    | 0b1101u ->
      Op.CMP, getQfW (), p2Oprs (b1, b2) chkUnpreCC (getRegAY, getImmJ), None
    | _ -> failwith "Wrong opcode in parseGroup10."

/// Data-processing (modified immediate), page A6-231
let parseGroup10WithRnSub b1 b2 =
  let opcode, cflag =
    match extract b1 6 4 with
    | 0b100u -> Op.ORR, None
    | 0b101u -> Op.ORRS, getCFThumb (b1, b2)
    | 0b110u -> Op.ORN, None
    | 0b111u -> Op.ORNS, getCFThumb (b1, b2)
    | _ -> failwith "Wrong opcode in parseGroup10."
  opcode, None, p3Oprs (b1, b2) chkUnpreCE (getRegAV, getRegAY, getImmJ), cflag

/// Data-processing (modified immediate), page A6-231
let parseGroup10WithRn b1 b2 =
  if extract b1 3 0 <> 0b1111u then parseGroup10WithRnSub b1 b2
  else
    match extract b1 6 4 with
    | 0b100u ->
      Op.MOV, getQfW (), p2Oprs (b1, b2) chkUnpreBL (getRegAV, getImmJ), None
    | 0b101u ->
      Op.MOVS, getQfW (), p2Oprs (b1, b2) chkUnpreBL (getRegAV, getImmJ),
      getCFThumb (b1, b2)
    | 0b110u ->
      Op.MVN, None, p2Oprs (b1, b2) chkUnpreBL (getRegAV, getImmJ), None
    | 0b111u ->
      Op.MVNS, None, p2Oprs (b1, b2) chkUnpreBL (getRegAV, getImmJ),
      getCFThumb (b1, b2)
    | _ -> failwith "Wrong opcode in parseGroup10."

/// Data-processing (modified immediate), page A6-231
let parseGroup10WithS b1 b2 =
  let opcode, aux, cflag =
    match extract b1 8 4 with
    | 0b00010u -> Op.BIC, None, None
    | 0b00011u -> Op.BICS, None, getCFThumb (b1, b2)
    | 0b10100u -> Op.ADC, None, None
    | 0b10101u -> Op.ADCS, None, None
    | 0b10110u -> Op.SBC, None, None
    | 0b10111u -> Op.SBCS, None, None
    | 0b11100u -> Op.RSB, getQfW (), None
    | 0b11101u -> Op.RSBS, getQfW (), None
    | _ -> failwith "Wrong opcode in parseGroup10."
  opcode, aux, p3Oprs (b1, b2) chkUnpreBV (getRegAV, getRegAY, getImmJ), cflag

/// Data-processing (modified immediate), page A6-231
let parseGroup10 cond bin =
  let struct (b1, b2) = halve bin
  let opcode, q, operands, cflag =
    match extract b1 8 5 with
    | 0b0000u -> parseGroup10WithRd b1 b2
    | 0b0001u -> parseGroup10WithS b1 b2
    | 0b0010u | 0b0011u -> parseGroup10WithRn b1 b2
    | 0b0100u | 0b1000u -> parseGroup10WithRd b1 b2
    | 0b1010u | 0b1011u -> parseGroup10WithS b1 b2
    | 0b1101u -> parseGroup10WithRd b1 b2
    | 0b1110u -> parseGroup10WithS b1 b2
    | _ -> failwith "Wrong opcode in parseGroup10."
  opcode, cond, q, operands, cflag

/// Data-processing (plain binary immediate), page A6-234
let parseGroup11 cond bin =
  let struct (b1, b2) = halve bin
  let chkRn = extract b1 3 0 <> 0b1111u
  let chkA = concat (extract b2 14 12) (extract b2 7 6) 2 <> 0b00000u
  let opcode, operands =
    match extract b1 8 4 with
    | 0b00000u when not chkRn ->
      Op.ADDW, p3Oprs (b1, b2) chkUnpreDM (getRegAV, getRegAY, getImm12F)
    | 0b00000u ->
      Op.ADDW, p3Oprs (b1, b2) chkUnpreCH (getRegAV, getRegAY, getImm12F)
    | 0b00100u ->
      Op.MOVW, p2Oprs (b1, b2) chkUnpreBL (getRegAV, getImm16A)
    | 0b01010u when not chkRn ->
      Op.SUBW, p3Oprs (b1, b2) chkUnpreDM (getRegAV, getRegAY, getImm12F)
    | 0b01010u ->
      Op.SUBW, p3Oprs (b1, b2) chkUnpreCH (getRegAV, getRegAY, getImm12F)
    | 0b01100u ->
      Op.MOVT, p2Oprs (b1, b2) chkUnpreBL (getRegAV, getImm16A)
    | 0b10000u ->
      Op.SSAT,
      p4Oprs (b1, b2) chkUnpreCI (getRegAV, getImm4F, getRegAY, getShiftI)
    | 0b10010u when chkA ->
      Op.SSAT,
      p4Oprs (b1, b2) chkUnpreCI (getRegAV, getImm4F, getRegAY, getShiftI)
    | 0b10010u ->
      Op.SSAT16, p3Oprs (b1, b2) chkUnpreCJ (getRegAV, getImm4F, getRegAY)
    | 0b10100u ->
      Op.SBFX,
      p4Oprs (b1, b2) chkUnpreCK (getRegAV, getRegAY, getImm5G, getImm4F)
    | 0b10110u when chkRn ->
      Op.BFI, p4Oprs (b1, b2) chkUnpreCL (getRegAV, getRegAY, getImm5G, getImmK)
    | 0b10110u ->
      Op.BFC, p3Oprs (b1, b2) chkUnpreCM (getRegAV, getImm5G, getImmK)
    | 0b11000u ->
      Op.USAT,
      p4Oprs (b1, b2) chkUnpreCI (getRegAV, getImm4F, getRegAY, getShiftI)
    | 0b11010u when chkA ->
      Op.USAT,
      p4Oprs (b1, b2) chkUnpreCI (getRegAV, getImm4F, getRegAY, getShiftI)
    | 0b11010u ->
      Op.USAT16, p3Oprs (b1, b2) chkUnpreCJ (getRegAV, getImm4F, getRegAY)
    | 0b11100u ->
      Op.UBFX,
      p4Oprs (b1, b2) chkUnpreCK (getRegAV, getRegAY, getImm5G, getImm4F)
    | _ -> failwith "Wrong opcode in parseGroup11."
  opcode, cond, None, operands

let parseChangeProcStateHintsCPS itstate b1 b2 =
  let opcode, operands =
    match extract b2 10 8 with
    | 0b100u -> Op.CPSIE, p1Opr (b1, b2) (chkUnpreCS itstate) getFlagC
    | 0b101u -> Op.CPSIE, p2Oprs (b1, b2) (chkUnpreCS itstate) (getFlagC, getImm5H)
    | 0b110u -> Op.CPSID, p1Opr (b1, b2) (chkUnpreCS itstate) getFlagC
    | 0b111u -> Op.CPSID, p2Oprs (b1, b2) (chkUnpreCS itstate) (getFlagC, getImm5H)
    | _ -> failwith "Wrong opcode in change processor state and hints."
  opcode, None, getQfW (), operands

/// Change Processor State, and hints, page A6-236
let parseChangeProcStateHints itstate cond b1 b2 =
  match extract b2 10 8, extract b2 7 0 with
  | 0b000u, 0b00000000u -> Op.NOP, cond, Some W, NoOperand
  | 0b000u, 0b00000001u -> Op.YIELD, cond, Some W, NoOperand
  | 0b000u, 0b00000010u -> Op.WFE, cond, Some W, NoOperand
  | 0b000u, 0b00000011u -> Op.WFI, cond, Some W, NoOperand
  | 0b000u, 0b00000100u -> Op.SEV, cond, Some W, NoOperand
  | 0b000u, o2 when o2 &&& 0b11110000u = 0b11110000u ->
    Op.DBG, cond, None, p1Opr b2 dummyChk getImm4A
  | 0b001u, _ -> Op.CPS, None, None, p1Opr (b1, b2) (chkUnpreCS itstate) getImm5H
  | 0b010u, _ -> raise UnpredictableException
  | 0b011u, _ -> raise UnpredictableException
  | _ -> parseChangeProcStateHintsCPS itstate b1 b2

/// Miscellaneous control instructions, page A6-237
let parseMiscellaneousInstrs cond b2 =
  let opcode, cond, operands =
    match extract b2 7 4 with
    | 0b0000u -> Op.LEAVEX, None, NoOperand  // Exit ThumbEE State or Nop
    | 0b0001u -> Op.ENTERX, None, NoOperand  // Enter ThumbEE State
    | 0b0010u -> Op.CLREX, cond, NoOperand
    | 0b0100u -> Op.DSB, cond, p1Opr b2 dummyChk getOptA
    | 0b0101u -> Op.DMB, cond, p1Opr b2 dummyChk getOptA
    | 0b0110u -> Op.ISB, cond, p1Opr b2 dummyChk getOptA
    | _ -> failwith "Wrong miscellaneous control instructions."
  opcode, cond, None, operands

/// Branches and miscellaneous control, page A6-235
let parseGroup12Sub itstate cond bin =
  let struct (b1, b2) = halve bin
  let chkBit5 = pickBit b2 5 = 0b1u
  let chkOp2 = extract b2 9 8 = 0b00u
  let chkI8 = extract b2 7 0 = 0b00000000u
  let opcode, cond, qualifiers, operands =
    match extract b1 10 4 with
    | op when op &&& 0b0111000u <> 0b0111000u ->
      Op.B, extract b1 9 6 |> byte |> parseCond |> Some, getQfW (),
      p1Opr (b1, b2) (chkUnpreDE itstate) getLbl21A
    | op when op &&& 0b1111110u = 0b0111000u && chkBit5 ->
      Op.MSR, cond, None, p2Oprs (b1, b2) chkUnpreCN (getBankedRegB, getRegAY)
    | 0b0111000u when not chkBit5 && chkOp2 ->
      Op.MSR, cond, None, p2Oprs (b1, b2) chkUnpreCO (getAPSRxC, getRegAY)
    | 0b0111000u when not chkBit5 ->
      Op.MSR, cond, None, p2Oprs (b1, b2) chkUnpreCP (getxPSRxA, getRegAY)
    | 0b0111010u -> parseChangeProcStateHints itstate cond b1 b2
    | 0b0111011u -> parseMiscellaneousInstrs cond b2
    | 0b0111100u -> Op.BXJ, cond, None, p1Opr (b1, b2) chkUnpreCQ getRegAY
    | 0b0111101u when chkI8 -> Op.ERET, cond, None, NoOperand
    | 0b0111101u ->
      Op.SUBS, cond, None, p3Oprs b2 dummyChk (getRegPC, getRegLR, getImm8A)
    | op when op &&& 0b1111110u = 0b0111110u && chkBit5 ->
      Op.MRS, cond, None, p2Oprs (b1, b2) chkUnpreCN (getBankedRegC, getRegAV)
    | op when op &&& 0b1111110u = 0b0111110u ->
      Op.MRS, cond, None, p2Oprs (b1, b2) chkUnpreBL (getRegAV, getxPSRxB)
    | _ -> failwith "Wrong opcode in parseGroup12."
  opcode, cond, qualifiers, operands

/// Branches and miscellaneous control, page A6-235
let parseGroup12 itstate cond bin =
  let struct (b1, b2) = halve bin
  let chkA = extract b1 10 4 = 0b1111110u
  let chkB = extract b1 10 4 = 0b1111111u
  match extract b2 14 12 with
  | 0b000u when chkA ->
    Op.HVC, None, None, p1Opr (b1, b2) dummyChk getImm16B
  | 0b000u when chkB -> Op.SMC, cond, None, p1Opr bin dummyChk getImm4A
  | 0b010u when chkB -> Op.UDF, cond, None, p1Opr (b1, b2) dummyChk getImm16B
  | op when op &&& 0b101u = 0b000u -> parseGroup12Sub itstate cond bin
  | op when op &&& 0b101u = 0b001u ->
    Op.B, cond, getQfW (), p1Opr (b1, b2) (chkUnpreDG itstate) getLbl25A
  | op when op &&& 0b101u = 0b100u ->
    Op.BLX, cond, None, p1Opr (b1, b2) chkUnpreCR getLbl25B
  | op when op &&& 0b101u = 0b101u ->
    Op.BL, cond, None, p1Opr (b1, b2) dummyChk getLbl25C
  | _ -> failwith "Wrong opcode in parseGroup12."

/// Store single data item, page A6-242
let parseGroup13Sub b1 b2 =
  let cRn = extract b1 3 0 = 0b1101u
  let cPush = extract b2 5 0 = 0b000100u
  let wback = pickBit b2 8 = 0b1u |> Some
  if extract b1 3 0 = 0b1111u then raise UndefinedException
  else
    match extract b2 11 6 with
    | 0b000000u ->
      Op.STR, Some false, getQfW (), None,
      p2Oprs (b1, b2) chkBothH (getRegAW, getMemAO)
    | 0b110100u when cRn && cPush ->
      Op.PUSH, None, getQfW (), None, p1Opr (b1, b2) chkUnpreCQ getRegAW
    | o2 when o2 &&& 0b100100u = 0b100100u ->
      Op.STR, wback, None, None, p2Oprs (b1, b2) chkBothD (getRegAW, getMemAM)
    | o2 when o2 &&& 0b111100u = 0b110000u ->
      Op.STR, wback, None, None, p2Oprs (b1, b2) chkBothD (getRegAW, getMemAM)
    | o2 when o2 &&& 0b111100u = 0b111000u ->
      Op.STRT, None, None, None, p2Oprs (b1, b2) chkBothA (getRegAW, getMemAG)
    | _ -> failwith "Wrong opcode in parseGroup13."

/// Store single data item, page A6-242
let parseGroup13 bin =
  let struct (b1, b2) = halve bin
  let wback () = pickBit b2 8 = 0b1u |> Some
  match concat (extract b1 7 5) (extract b2 11 6) 6 with
  | op when op &&& 0b111100100u = 0b000100100u ->
    Op.STRB, wback (), None, None, p2Oprs (b1, b2) chkBothC (getRegAW, getMemAM)
  | op when op &&& 0b111111100u = 0b000110000u ->
    Op.STRB, wback (), None, None, p2Oprs (b1, b2) chkBothC (getRegAW, getMemAM)
  | op when op &&& 0b111000000u = 0b100000000u ->
    Op.STRB, Some false, getQfW (), None,
    p2Oprs (b1, b2) chkBothE (getRegAW, getMemAN)
  | 0b000000000u ->
    Op.STRB, Some false, getQfW (), None,
    p2Oprs (b1, b2) chkBothG (getRegAW, getMemAO)
  | op when op &&& 0b111111100u = 0b000111000u ->
    Op.STRBT, None, None, None, p2Oprs (b1, b2) chkBothA (getRegAW, getMemAG)
  | op when op &&& 0b111100100u = 0b001100100u ->
    Op.STRH, wback (), None, None, p2Oprs (b1, b2) chkBothC (getRegAW, getMemAM)
  | op when op &&& 0b111111100u = 0b001110000u ->
    Op.STRH, wback (), None, None, p2Oprs (b1, b2) chkBothC (getRegAW, getMemAM)
  | op when op &&& 0b111000000u = 0b101000000u ->
    Op.STRH, Some false, getQfW (), None,
    p2Oprs (b1, b2) chkBothE (getRegAW, getMemAN)
  | 0b001000000u ->
    Op.STRH, Some false, getQfW (), None,
    p2Oprs (b1, b2) chkBothG (getRegAW, getMemAO)
  | op when op &&& 0b111111100u = 0b001111000u ->
    Op.STRHT, None, None, None, p2Oprs (b1, b2) chkBothA (getRegAW, getMemAG)
  | op when op &&& 0b111000000u = 0b110000000u ->
    Op.STR, Some false, getQfW (), None,
    p2Oprs (b1, b2) chkBothF (getRegAW, getMemAN)
  | op when op &&& 0b111000000u = 0b010000000u -> parseGroup13Sub b1 b2
  | _ -> failwith "Wrong opcode in parseGroup13."

/// Load byte, memory hints, page A6-241
let parseGroup14 bin =
  let struct (b1, b2) = halve bin
  let chkRn = extract b1 3 0 <> 0b1111u
  let chkRt = extract b2 15 12 <> 0b1111u
  let wback = pickBit b2 8 = 0b1u |> Some
  let opcode, wback, q, operands =
    match concat (extract b1 8 7) (extract b2 11 6) 6 with
    | 0b00000000u when chkRn && chkRt ->
      Op.LDRB, Some false, getQfW (),
      p2Oprs (b1, b2) chkUnpreCW (getRegAW, getMemAO)
    | 0b00000000u when chkRn ->
      Op.PLD, None, None, p1Opr (b1, b2) chkUnpreAK getMemP
    | op when op &&& 0b11100100u = 0b00100100u && chkRn ->
      Op.LDRB, wback, None, p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11111100u = 0b00110000u && chkRn && chkRt ->
      Op.LDRB, wback, None, p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11111100u = 0b00110000u && chkRn ->
      Op.PLD, None, None, p1Opr (b1, b2) dummyChk getMemAP
    | op when op &&& 0b11111100u = 0b00111000u && chkRn ->
      Op.LDRBT, None, None, p2Oprs (b1, b2) chkUnpreBL (getRegAW, getMemAG)
    | op when op &&& 0b11000000u = 0b01000000u && chkRn && chkRt ->
      Op.LDRB, Some false, getQfW (),
      p2Oprs (b1, b2) chkUnpreCV (getRegAW, getMemAN)
    | op when op &&& 0b11000000u = 0b01000000u && chkRn ->
      Op.PLD, None, None, p1Opr (b1, b2) dummyChk getMemAN
    | op when op &&& 0b10000000u = 0b00000000u && chkRt ->
      Op.LDRB, None, getQfW (), p2Oprs (b1, b2) dummyChk (getRegAW, getMemAQ)
    | op when op &&& 0b10000000u = 0b00000000u ->
      Op.PLD, None, None, p1Opr (b1, b2) dummyChk getMemAQ
    | 0b10000000u when chkRn && chkRt ->
      Op.LDRSB, Some false, getQfW (),
      p2Oprs (b1, b2) chkUnpreCW (getRegAW, getMemAO)
    | 0b10000000u when chkRn ->
      Op.PLI, None, None, p1Opr (b1, b2) chkUnpreAK getMemP
    | op when op &&& 0b11100100u = 0b10100100u && chkRn ->
      Op.LDRSB, wback, None, p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11111100u = 0b10110000u && chkRn && chkRt ->
      Op.LDRSB, wback, None, p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11111100u = 0b10110000u && chkRn ->
      Op.PLI, None, None, p1Opr (b1, b2) dummyChk getMemAP
    | op when op &&& 0b11111100u = 0b10111000u && chkRn ->
      Op.LDRSBT, None, None, p2Oprs (b1, b2) chkUnpreBL (getRegAW, getMemAG)
    | op when op &&& 0b11000000u = 0b11000000u && chkRn && chkRt ->
      Op.LDRSB, Some false, None,
      p2Oprs (b1, b2) chkUnpreCV (getRegAW, getMemAN)
    | op when op &&& 0b11000000u = 0b11000000u && chkRn ->
      Op.PLI, None, None, p1Opr (b1, b2) dummyChk getMemAN
    | op when op &&& 0b10000000u = 0b10000000u && chkRt ->
      Op.LDRSB, None, None, p2Oprs (b1, b2) dummyChk (getRegAW, getMemAQ)
    | op when op &&& 0b10000000u = 0b10000000u ->
      Op.PLI, None, None, p1Opr (b1, b2) dummyChk getMemAQ
    | _ -> failwith "Wrong opcode in parseGroup14."
  opcode, wback, q, None, operands

/// Load halfword, memory hints, page A6-240
let parseGroup15WithRn b1 b2 =
  let chkRt = extract b2 15 12 <> 0b1111u
  match extract b1 8 7 with
  | op when op &&& 0b10u = 0b00u && chkRt ->
    Op.LDRH, None, None, None, p2Oprs (b1, b2) chkUnpreCV (getRegAW, getMemAQ)
  | op when op &&& 0b10u = 0b00u ->
    Op.PLD, None, None, None, p1Opr (b1, b2) dummyChk getMemAQ
  | op when op &&& 0b10u = 0b10u && chkRt ->
    Op.LDRSH, None, None, None, p2Oprs (b1, b2) chkUnpreCV (getRegAW, getMemAQ)
  | op when op &&& 0b10u = 0b10u -> Op.NOP, None, None, None, NoOperand
  | _ -> failwith "Wrong opcode in parseGroup15."

/// Load halfword, memory hints, page A6-240
let parseGroup15 bin =
  let struct (b1, b2) = halve bin

  let chkRt = extract b2 15 12 <> 0b1111u
  let wback = pickBit b2 8 = 0b1u |> Some
  if extract b1 3 0 = 0b1111u then parseGroup15WithRn b1 b2
  else
    match concat (extract b1 8 7) (extract b2 11 6) 6 with
    | op when op &&& 0b11100100u = 0b00100100u ->
      Op.LDRH, wback, None, None,
      p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11111100u = 0b00110000u && chkRt ->
      Op.LDRH, wback, None, None,
      p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11000000u = 0b01000000u && chkRt ->
      Op.LDRH, Some false, getQfW (), None,
      p2Oprs (b1, b2) chkUnpreCV (getRegAW, getMemAN)
    | 0b00000000u when chkRt ->
      Op.LDRH, Some false, getQfW (), None,
      p2Oprs (b1, b2) chkUnpreCW (getRegAW, getMemAO)
    | op when op &&& 0b11111100u = 0b00111000u ->
      Op.LDRHT, None, None, None,
      p2Oprs (b1, b2) chkUnpreBL (getRegAW, getMemAG)
    | 0b00000000u ->
      Op.PLDW, None, None, None, p1Opr (b1, b2) chkUnpreAK getMemP
    | op when op &&& 0b11111100u = 0b00110000u ->
      Op.PLDW, None, None, None, p1Opr (b1, b2) dummyChk getMemAP
    | op when op &&& 0b11000000u = 0b01000000u ->
      Op.PLDW, None, None, None, p1Opr (b1, b2) dummyChk getMemAN
    | op when op &&& 0b11100100u = 0b10100100u ->
      Op.LDRSH, wback, None, None,
      p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11110000u = 0b10110000u && chkRt ->
      Op.LDRSH, wback, None, None,
      p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11000000u = 0b11000000u && chkRt ->
      Op.LDRSH, Some false, None, None,
      p2Oprs (b1, b2) chkUnpreCV (getRegAW, getMemAN)
    | 0b10000000u when chkRt ->
      Op.LDRSH, Some false, getQfW (), None,
      p2Oprs (b1, b2) chkUnpreCW (getRegAW, getMemAO)
    | op when op &&& 0b11111100u = 0b10111000u ->
      Op.LDRSHT, None, None, None,
      p2Oprs (b1, b2) chkUnpreBL (getRegAW, getMemAG)
    | 0b10000000u -> Op.NOP, None, None, None, NoOperand
    | op when op &&& 0b11111100u = 0b10110000u -> Op.NOP, None, None, None, NoOperand
    | op when op &&& 0b11000000u = 0b11000000u -> Op.NOP, None, None, None, NoOperand
    | _ -> failwith "Wrong opcode in parseGroup15."

/// Load word, page A6-239
let parseGroup16 itstate bin =
  let struct (b1, b2) = halve bin
  let chkRn = extract b1 3 0 = 0b1111u
  let chkRn2 = extract b1 3 0 = 0b1101u
  let chkPop = extract b2 5 0 = 0b000100u
  let wback = pickBit b2 8 = 0b1u |> Some
  match concat (extract b1 8 7) (extract b2 11 6) 6 with
  | op when op &&& 0b10000000u = 0b0u && chkRn ->
    Op.LDR, Some false, getQfW (), None,
    p2Oprs (b1, b2) (chkUnpreDK itstate) (getRegAW, getMemAQ)
  | 0b00000000u ->
    Op.LDR, None, getQfW (), None,
    p2Oprs (b1, b2) (chkUnpreCX itstate) (getRegAW, getMemAO)
  | 0b00101100u when chkRn2 && chkPop ->
    Op.POP, None, getQfW (), None, p1Opr (b1, b2) (chkUnpreDJ itstate) getRegAW
  | op when op &&& 0b11100100u = 0b00100100u ->
    Op.LDR, wback, None, None,
    p2Oprs (b1, b2) (chkUnpreCU itstate) (getRegAW, getMemAM)
  | op when op &&& 0b11111100u = 0b00110000u ->
    Op.LDR, wback, None, None,
    p2Oprs (b1, b2) (chkUnpreCU itstate) (getRegAW, getMemAM)
  | op when op &&& 0b11000000u = 0b01000000u ->
    Op.LDR, Some false, getQfW (), None,
    p2Oprs (b1, b2) (chkUnpreDK itstate) (getRegAW, getMemAN)
  | op when op &&& 0b11111100u = 0b00111000u ->
    Op.LDRT, None, None, None, p2Oprs (b1, b2) chkUnpreBL (getRegAW, getMemAG)
  | _ -> failwith "Wrong opcode in parseGroup16."

/// Advanced SIMD element or structure load/store instructions, page A7-275
let parseGroup17 bin =
  let struct (b1, b2) = halve bin
  let opcode, wback, dt, operands = concat b1 b2 16 |> getAdvSIMDOrStrct
  opcode, wback, None, dt, operands

/// Parallel addition and subtraction, signed, page A6-246
let parseParallelAddSubSigned b1 b2 =
  match concat (extract b1 6 4) (extract b2 5 4) 2 with
  | 0b00100u -> Op.SADD16
  | 0b01000u -> Op.SASX
  | 0b11000u -> Op.SSAX
  | 0b10100u -> Op.SSUB16
  | 0b00000u -> Op.SADD8
  | 0b10000u -> Op.SSUB8
  | 0b00101u -> Op.QADD16
  | 0b01001u -> Op.QASX
  | 0b11001u -> Op.QSAX
  | 0b10101u -> Op.QSUB16
  | 0b00001u -> Op.QADD8
  | 0b10001u -> Op.QSUB8
  | 0b00110u -> Op.SHADD16
  | 0b01010u -> Op.SHASX
  | 0b11010u -> Op.SHSAX
  | 0b10110u -> Op.SHSUB16
  | 0b00010u -> Op.SHADD8
  | 0b10010u -> Op.SHSUB8
  | _ -> failwith "Wrong opcode in Parallel addition and subtraction, signed."

/// Parallel addition and subtraction, unsigned, page A6-247
let parseParallelAddSubUnsigned b1 b2 =
  match concat (extract b1 6 4) (extract b2 5 4) 2 with
  | 0b00100u -> Op.UADD16
  | 0b01000u -> Op.UASX
  | 0b11000u -> Op.USAX
  | 0b10100u -> Op.USUB16
  | 0b00000u -> Op.UADD8
  | 0b10000u -> Op.USUB8
  | 0b00101u -> Op.UQADD16
  | 0b01001u -> Op.UQASX
  | 0b11001u -> Op.UQSAX
  | 0b10101u -> Op.UQSUB16
  | 0b00001u -> Op.UQADD8
  | 0b10001u -> Op.UQSUB8
  | 0b00110u -> Op.UHADD16
  | 0b01010u -> Op.UHASX
  | 0b11010u -> Op.UHSAX
  | 0b10110u -> Op.UHSUB16
  | 0b00010u -> Op.UHADD8
  | 0b10010u -> Op.UHSUB8
  | _ -> failwith "Wrong opcode in Parallel addition and subtraction, unsigned."

/// Miscellaneous operations, page A6-248
let parseParallelAddSub b1 b2 =
  if pickBit b2 6 = 0u then parseParallelAddSubSigned b1 b2
  else parseParallelAddSubUnsigned b1 b2
  , None, None, None, p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAY, getRegAX)

/// Miscellaneous operations, page A6-248
let parseMiscellaneousOperations b1 b2 =
  match concat (extract b1 5 4) (extract b2 5 4) 2 with
  | 0b0000u ->
    Op.QADD, None, None, None,
    p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAX, getRegAY)
  | 0b0001u ->
    Op.QDADD, None, None, None,
    p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAX, getRegAY)
  | 0b0010u ->
    Op.QSUB, None, None, None,
    p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAX, getRegAY)
  | 0b0011u ->
    Op.QDSUB, None, None, None,
    p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAX, getRegAY)
  | 0b0100u ->
    Op.REV, None, getQfW (), None,
    p2Oprs (b1, b2) chkUnpreCZ (getRegAV, getRegAX)
  | 0b0101u ->
    Op.REV16, None, getQfW (), None,
    p2Oprs (b1, b2) chkUnpreCZ (getRegAV, getRegAX)
  | 0b0110u ->
    Op.RBIT, None, None, None, p2Oprs (b1, b2) chkUnpreCZ (getRegAV, getRegAX)
  | 0b0111u ->
    Op.REVSH, None, getQfW (), None,
    p2Oprs (b1, b2) chkUnpreCZ (getRegAV, getRegAX)
  | 0b1000u ->
    Op.SEL, None, None, None,
    p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAY, getRegAX)
  | 0b1100u ->
    Op.CLZ, None, None, None, p2Oprs (b1, b2) chkUnpreCZ (getRegAV, getRegAX)
  | _ -> failwith "Wrong opcode in Miscellaneous operations."

/// Data-processing (register), page A6-245
let parseGroup18Sub b1 b2 =
  match extract b1 6 4 with
  | 0b000u -> Op.LSL
  | 0b001u -> Op.LSLS
  | 0b010u -> Op.LSR
  | 0b011u -> Op.LSRS
  | 0b100u -> Op.ASR
  | 0b101u -> Op.ASRS
  | 0b110u -> Op.ROR
  | 0b111u -> Op.RORS
  | _ -> failwith "Wrong opcode in parseGroup18."
  , None, getQfW (), None,
  p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAY, getRegAX)

/// Data-processing (register), page A6-245
let parseGroup18WithRn b1 b2 =
  let opcode, q =
    match extract b1 6 4 with
    | 0b000u -> Op.SXTH, getQfW ()
    | 0b001u -> Op.UXTH, getQfW ()
    | 0b010u -> Op.SXTB16, None
    | 0b011u -> Op.UXTB16, None
    | 0b100u -> Op.SXTB, getQfW ()
    | 0b101u -> Op.UXTB, getQfW ()
    | _ -> failwith "Wrong opcode in parseGroup18."
  opcode, None, q, None,
  p3Oprs (b1, b2) chkUnpreBV (getRegAV, getRegAX, getShiftJ)

let parseGroup18WithOutRn b1 b2 =
  match extract b1 6 4 with
  | 0b000u -> Op.SXTAH
  | 0b001u -> Op.UXTAH
  | 0b010u -> Op.SXTAB16
  | 0b011u -> Op.UXTAB16
  | 0b100u -> Op.SXTAB
  | 0b101u -> Op.UXTAB
  | _ -> failwith "Wrong opcode in parseGroup18."
  , None, None, None,
  p4Oprs (b1, b2) chkUnpreBZ (getRegAV, getRegAY, getRegAX, getShiftJ)

/// Data-processing (register), page A6-245
let parseGroup18ByRn b1 b2 =
  if extract b1 3 0 = 0b1111u then parseGroup18WithRn b1 b2
  else parseGroup18WithOutRn b1 b2

/// Data-processing (register), page A6-245
let parseGroup18 bin =
  let struct (b1, b2) = halve bin
  match concat (pickBit b1 7) (extract b2 7 4) 4 with
  | 0b00000u -> parseGroup18Sub b1 b2
  | op when op &&& 0b11000u = 0b01000u -> parseGroup18ByRn b1 b2
  | op when op &&& 0b11000u = 0b10000u -> parseParallelAddSub b1 b2
  | op when op &&& 0b11100u = 0b11000u -> parseMiscellaneousOperations b1 b2
  | _ -> failwith "Wrong opcode in parseGroup18."

/// Multiply, multiply accumulate, and absolute difference, page A6-249
let parseGroup19Sub b1 b2 =
  match concat (extract b1 6 4) (pickBit b2 4) 1 with
  | 0b0001u -> Op.MLS
  | 0b1100u -> Op.SMMLS
  | 0b1101u -> Op.SMMLSR
  | _ -> failwith "Wrong opcode in parseGroup19."
  , None, None, None,
  p4Oprs (b1, b2) chkUnpreDB (getRegAV, getRegAY, getRegAX, getRegAW)

/// Multiply, multiply accumulate, and absolute difference, page A6-249
let parseGroup19WithOutRa b1 b2 =
  match concat (extract b1 6 4) (extract b2 5 4) 2 with
  | 0b00000u -> Op.MLA
  | 0b00100u -> Op.SMLABB
  | 0b00101u -> Op.SMLABT
  | 0b00110u -> Op.SMLATB
  | 0b00111u -> Op.SMLATT
  | 0b01000u -> Op.SMLAD
  | 0b01001u -> Op.SMLADX
  | 0b01100u -> Op.SMLAWB
  | 0b01101u -> Op.SMLAWT
  | 0b10000u -> Op.SMLSD
  | 0b10001u -> Op.SMLSDX
  | 0b10100u -> Op.SMMLA
  | 0b10101u -> Op.SMMLAR
  | 0b11100u -> Op.USADA8
  | _ -> failwith "Wrong opcode in parseGroup19."
  , None, None, None,
  p4Oprs (b1, b2) chkUnpreDA (getRegAV, getRegAY, getRegAX, getRegAW)

/// Multiply, multiply accumulate, and absolute difference, page A6-249
let parseGroup19WithRa b1 b2 =
  match concat (extract b1 6 4) (extract b2 5 4) 2 with
  | 0b00000u -> Op.MUL
  | 0b00100u -> Op.SMULBB
  | 0b00101u -> Op.SMULBT
  | 0b00110u -> Op.SMULTB
  | 0b00111u -> Op.SMULTT
  | 0b01000u -> Op.SMUAD
  | 0b01001u -> Op.SMUADX
  | 0b01100u -> Op.SMULWB
  | 0b01101u -> Op.SMULWT
  | 0b10000u -> Op.SMUSD
  | 0b10001u -> Op.SMUSDX
  | 0b10100u -> Op.SMMUL
  | 0b10101u -> Op.SMMULR
  | 0b11100u -> Op.USAD8
  | _ -> failwith "Wrong opcode in parseGroup19."
  , None, None, None,
  p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAY, getRegAX)

/// Multiply, multiply accumulate, and absolute difference, page A6-249
let parseGroup19 bin =
  let struct (b1, b2) = halve bin
  let op = concat (extract b1 6 4) (extract b2 5 4) 2
  if op = 1u || op = 0b11000u || op = 0b11001u then parseGroup19Sub b1 b2
  elif extract b2 15 12 = 0b1111u then parseGroup19WithRa b1 b2
  else parseGroup19WithOutRa b1 b2

/// Long multiply, long multiply accumulate, and divide, page A6-250
let parseGroup20 bin =
  let struct (b1, b2) = halve bin
  let getFourOprs () =
    p4Oprs (b1, b2) chkUnpreDC (getRegAW, getRegAV, getRegAY, getRegAX)
  let getThreeOprs () =
    p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAY, getRegAX)
  match concat (extract b1 6 4) (extract b2 7 4) 4 with
  | 0b0000000u -> Op.SMULL, None, None, None, getFourOprs ()
  | 0b0011111u -> Op.SDIV, None, None, None, getThreeOprs ()
  | 0b0100000u -> Op.UMULL, None, None, None, getFourOprs ()
  | 0b0111111u -> Op.UDIV, None, None, None, getThreeOprs ()
  | 0b1000000u -> Op.SMLAL, None, None, None, getFourOprs ()
  | 0b1001000u -> Op.SMLALBB, None, None, None, getFourOprs ()
  | 0b1001001u -> Op.SMLALBT, None, None, None, getFourOprs ()
  | 0b1001010u -> Op.SMLALTB, None, None, None, getFourOprs ()
  | 0b1001011u -> Op.SMLALTT, None, None, None, getFourOprs ()
  | 0b1001100u -> Op.SMLALD, None, None, None, getFourOprs ()
  | 0b1001101u -> Op.SMLALDX, None, None, None, getFourOprs ()
  | 0b1011100u -> Op.SMLSLD, None, None, None, getFourOprs ()
  | 0b1011101u -> Op.SMLSLDX, None, None, None, getFourOprs ()
  | 0b1100000u -> Op.UMLAL, None, None, None, getFourOprs ()
  | 0b1100110u -> Op.UMAAL, None, None, None, getFourOprs ()
  | _ -> failwith "Wrong opcode in parseGroup20."

let parseV7Thumb32Group01 itstate cond bin =
  let opcode, wback, q, dt, operands =
    match extract bin 10 9 with
    | 0b00u when pickBit bin 6 = 0u -> parseGroup6 itstate bin
    | 0b00u -> parseGroup7 itstate bin
    | 0b01u -> parseGroup8 bin
    | 0b10u | 0b11u -> parseGroup9 bin
    | _ -> failwith "Wrong thumb group specified."
  opcode, cond, 0uy, wback, q, dt, operands, None

let parseV7Thumb32Group10 itstate cond bin =
  let opcode, cond, q, operands, cflag =
    match pickBit bin 9, pickBit bin 31 with
    | 0b0u, 0b0u -> parseGroup10 cond bin
    | 0b1u, 0b0u ->
      let opc, c, qual, opr = parseGroup11 cond bin
      opc, c, qual, opr, None
    | _, 0b1u ->
      let opc, c, qual, opr = parseGroup12 itstate cond bin
      opc, c, qual, opr, None
    | _ -> failwith "Wrong thumb group specified."
  opcode, cond, 0uy, None, q, None, operands, cflag

let parseV7Thumb32Group11 itstate cond bin =
  let opcode, wback, q, dt, operands =
    match extract bin 10 4 with
    | op when op &&& 0b1110001u = 0b0000000u -> parseGroup13 bin
    | op when op &&& 0b1100111u = 0b0000001u -> parseGroup14 bin
    | op when op &&& 0b1100111u = 0b0000011u -> parseGroup15 bin
    | op when op &&& 0b1100111u = 0b0000101u -> parseGroup16 itstate bin
    | op when op &&& 0b1100111u = 0b0000111u -> raise UndefinedException
    | op when op &&& 0b1110001u = 0b0010000u -> parseGroup17 bin
    | op when op &&& 0b1110000u = 0b0100000u -> parseGroup18 bin
    | op when op &&& 0b1111000u = 0b0110000u -> parseGroup19 bin
    | op when op &&& 0b1111000u = 0b0111000u -> parseGroup20 bin
    | op when op &&& 0b1000000u = 0b1000000u -> parseGroup9 bin
    | _ -> failwith "Wrong thumb group specified."
  opcode, cond, 0uy, wback, q, dt, operands, None

let inline updateITSTATE (itstate: byref<byte list>) =
  itstate <- List.tail itstate

let getCondWithITSTATE itstate =
  match List.tryHead itstate with
  | Some st -> st |> parseCond |> Some
  | None -> Condition.AL |> Some

/// ARM Architecture Reference Manual ARMv7-A and ARMv7-R edition, DDI0406C.b
let parseThumb32 (itstate: byref<byte list>) bin =
  let isInITBlock = not itstate.IsEmpty
  let cond = getCondWithITSTATE itstate
  let opcode, cond, itState, wback, qualifier, simdt, oprs, cflag =
    match extract bin 12 11 with
    | 0b01u -> parseV7Thumb32Group01 itstate cond bin
    | 0b10u -> parseV7Thumb32Group10 itstate cond bin
    | 0b11u -> parseV7Thumb32Group11 itstate cond bin
    | _ -> failwith "Wrong thumb group specified."
  if isInITBlock then updateITSTATE &itstate else ()
  opcode, cond, itState, wback, qualifier, simdt, oprs, cflag

/// ARM Architecture Reference Manual ARMv7-A and ARMv7-R edition, DDI0406C.b
let parseThumb16 (itstate: byref<byte list>) bin =
  let isInITBlock = not itstate.IsEmpty
  let cond = getCondWithITSTATE itstate
  let opcode, cond, itState, wback, qualifier, operands =
    match extract bin 15 11 with
    | op when op &&& 0b11000u = 0b00000u -> parseGroup0 itstate cond bin
    | 0b01000u when pickBit bin 10 = 0b0u -> parseGroup1 itstate cond bin
    | 0b01000u -> parseGroup2 itstate cond bin
    | 0b01001u ->
      let oprs = p2Oprs bin dummyChk (getRegJ, getLbl8A)
      Op.LDR, cond, 0uy, None, None, oprs
    | op when op &&& 0b11110u = 0b01010u -> parseGroup3 cond bin
    | op when op &&& 0b11100u = 0b01100u -> parseGroup3 cond bin
    | op when op &&& 0b11100u = 0b10000u -> parseGroup3 cond bin
    | 0b10100u ->
      Op.ADR, cond, 0uy, None, None, p2Oprs bin dummyChk (getRegJ, getLbl8A)
    | 0b10101u ->
      Op.ADD, cond, 0uy, None, None,
      p3Oprs bin dummyChk (getRegJ, getRegSP, getImm8B)
    | op when op &&& 0b11110u = 0b10110u -> parseGroup4 &itstate cond bin
    | 0b11000u ->
      Op.STM, cond, 0uy, Some true, None,
      p2Oprs bin chkUnpreDD (getRegisterWC, getRegListR)
    | 0b11001u ->
      let registers = concat 0b00000000u (extract bin 7 0) 8
      let n = extract bin 10 8 |> int
      let wback = pickBit registers n = 0u |> Some
      Op.LDM, cond, 0uy, wback, None,
      p2Oprs bin chkUnpreDD (getRegisterWD, getRegListR)
    | op when op &&& 0b11110u = 0b11010u -> parseGroup5 itstate cond bin
    | 0b11100u ->
      Op.B, cond, 0uy, None, getQfN (), p1Opr bin dummyChk getLbl12A
    | _ -> failwith "Wrong thumb group specified."
  if isInITBlock then updateITSTATE &itstate else ()
  opcode, cond, itState, wback, qualifier, None, operands, None

let render mode it addr bin len cond opcode dt fnOperand =
  let struct (oprs, wback, qualifier, cflag) = fnOperand bin
  let cond =
    match cond with
    | Some cond -> cond
    | None -> Condition.UN // FIXME
  newInsInfo mode addr len cond opcode oprs it wback qualifier dt cflag

(* <label> *)
let oprLabel bin =
  let label = extract bin 11 0 <<< 1 |> signExtend
  struct (OneOperand label, false, Qualifier.N, None)

/// ARM Architecture Reference Manual ARMv8-A, ARM DDI 0487F.c ID072120
/// T32 instruction set encoding on page F3-4148.
let parse mode (itstate: byref<byte list>) addr bin len =
  let isInITBlock = not itstate.IsEmpty
  let cond = getCondWithITSTATE itstate
  match extract bin 15 11 (* op0:op1 *) with
  | 0b11100u -> Utils.futureFeature ()
    //render mode 0uy addr bin len cond Op.B None oprLabel
  | 0b11101u | 0b11110u | 0b11111u (* 111 != 00 *) -> Utils.futureFeature ()
  | _ (* != 111 xx *) -> Utils.futureFeature ()

// vim: set tw=80 sts=2 sw=2:
