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
let parseParallelAddSubOld b1 b2 =
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
  | op when op &&& 0b11000u = 0b10000u -> parseParallelAddSubOld b1 b2
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

////////////////////////////////////////////////////////////////////////////////

/// aarch32/functions/common/T32ExpandImm_C on page J1-7767.
// T32ExpandImm_C()
// ================
/// Modified immediate constants in A32 instructions on page F2-4135.
let t32ExpandImm imm12 = (* _carryIn = *)
  if extract imm12 11 10 = 0b00u then
    let imm8 = extract imm12 7 0 (* imm12<7:0> *)
    let imm32 =
      match extract imm12 9 8 with
      | 0b00u -> imm8
      | 0b01u -> (imm8 <<< 16) + imm8
      | 0b10u -> (imm8 <<< 24) + (imm8 <<< 8)
      | _ (* 11 *) -> (imm8<<< 24) + (imm8 <<< 16) + (imm8 <<< 8) + imm8
    (* struct (imm32, carryIn) *) /// FIMXE: carry = PSTATE.C
    imm32
  else
    let value = (1u <<< 7) + (extract imm12 6 0)
    let rotation = (extract imm12 11 7) % 32u |> int
    let imm32 =
      if rotation = 0 then value
      else (value >>> rotation) ||| (value <<< (32 - rotation))
    let _carryOut = pickBit imm32 (32 - 1)
    (* struct (imm32, carryOut) *) /// FIMXE: carry = PSTATE.C
    imm32

(* W == '1' *)
let wbackW8 bin = pickBit bin 8 = 0b1u

(* if n == 15 || BitCount(registers) < 2 then UNPREDICTABLE
  if wback && registers<n> == '1' then UNPREDICTABLE
  if registers<13> == '1' then UNPREDICTABLE
  if registers<15> == '1' then UNPREDICTABLE *)
let chkPCRnRegsWBRegs bin =
  let n = extract bin 19 16 |> int
  ((n = 15 || (bitCount (extract bin 15 0) 15 < 2)) ||
   (wbackW bin && (pickBit bin n = 1u)) || (pickBit bin 13 = 1u) ||
   (pickBit bin 15 = 1u)) |> checkUnpred

(* if n < 8 && m < 8 then UNPREDICTABLE
   if n == 15 || m == 15 then UNPREDICTABLE *)
let chkNMPCRnRm bin =
  let n = concat (pickBit bin 7) (extract bin 2 0) 3 (* N:Rn *)
  let m = extract bin 6 3 (* Rm *)
  ((n < 8u && m < 8u) || (n = 15u || m = 15u)) |> checkUnpred

(* if n == 15 || BitCount(registers) < 2 || (P == '1' && M == '1') then
     UNPREDICTABLE
   if wback && registers<n> == '1' then UNPREDICTABLE
   if registers<13> == '1' then UNPREDICTABLE
   if registers<15> == '1' && InITBlock() && !LastInITBlock() then UNPREDICTABLE
*)
let chkPCRnRegsPMWback bin itstate =
  let n = extract bin 19 16 |> int
  ((n = 15 || bitCount (extract bin 15 0) 15 < 2 ||
    (pickBit bin 15 = 1u && pickBit bin 14 = 1u)) ||
    (wbackW bin && pickBit bin n = 1u) || (pickBit bin 13 = 1u) ||
    (pickBit bin 15 = 1u && inITBlock itstate && lastInITBlock itstate |> not))
    |> checkUnpred

(* if n == 15 then UNPREDICTABLE
   if InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRnIT bin itstate =
  (extract bin 19 16 = 15u ||
   (inITBlock itstate && lastInITBlock itstate |> not))
   |> checkUnpred

(* if firstcond == '1111' || (firstcond == '1110' && BitCount(mask) != 1)
     then UNPREDICTABLE
   if InITBlock() then UNPREDICTABLE *)
let chkFstCondIT bin itstate =
  ((extract bin 7 4 (* firstcond *) = 0b1111u ||
    (extract bin 7 4 = 0b1110u && bitCount (extract bin 3 0 (* mask *)) 3 <> 1))
    || (inITBlock itstate)) |> checkUnpred

(* if A:I:F == '000' then UNPREDICTABLE
   if InITBlock() then UNPREDICTABLE *)
let chkAIFIT bin itstate =
  (extract bin 2 0 = 0b000u && inITBlock itstate) |> checkUnpred

(* if InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkInITLastIT itstate =
  (inITBlock itstate && lastInITBlock itstate |> not) |> checkUnpred

(* if m == 15 then UNPREDICTABLE
   if InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRmIT16 bin itstate =
  ((extract bin 6 3 = 15u) ||
   (inITBlock itstate && lastInITBlock itstate |> not)) |> checkUnpred

(* if m == 15 then UNPREDICTABLE
   if InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRmIT32 bin itstate =
  ((extract bin 3 0 = 15u) ||
   (inITBlock itstate && lastInITBlock itstate |> not)) |> checkUnpred

(* if n != 14 then UNPREDICTABLE
   if InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkRnIT bin itstate =
  ((extract bin 19 16 <> 14u) ||
   (inITBlock itstate && lastInITBlock itstate |> not)) |> checkUnpred

(* if H = '1' then UNPREDICTABLE
   if InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkHInLastIT bin itstate =
  ((pickBit bin 0 = 1u) ||
   (inITBlock itstate && lastInITBlock itstate |> not)) |> checkUnpred

(* if d == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRdIT bin itstate =
  let d = concat (pickBit bin 7) (extract bin 2 0) 3 (* DM:Rdm *)
  (d = 15u && inITBlock itstate && lastInITBlock itstate |> not)
  |> checkUnpred

(* if d == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCDRdIT bin itstate =
  let d = concat (pickBit bin 7) (extract bin 2 0) 3 (* D:Rd *)
  (d = 15u && inITBlock itstate && lastInITBlock itstate |> not) |> checkUnpred

(* if n == 15 && m == 15 then UNPREDICTABLE
   if d == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRnRmRdIT bin itstate =
  let d = concat (pickBit bin 7) (extract bin 2 0) 3 (* DN:Rdn *)
  ((d (* n = d *) = 15u && extract bin 6 3 = 15u) ||
   (d = 15u && inITBlock itstate && lastInITBlock itstate |> not))
   |> checkUnpred

(* if BitCount(registers) < 1 then UNPREDICTABLE;
   if registers<15> == '1' && InITBlock() && !LastInITBlock() then UNPREDICTABLE
*)
let chkRegsIT bin itstate =
  ((concat (pickBit bin 8 <<< 7) (extract bin 7 0) 8 (* registers *) = 0u) ||
   (pickBit bin 8 = 1u && inITBlock itstate && lastInITBlock itstate |> not))
   |> checkUnpred

(* if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
   if sz == '1' && InITBlock() then UNPREDICTABLE *)
let chkQVdVnVmSzIT bin itstate =
  ((pickBit bin 6 = 1u) &&
   (pickBit bin 12 = 1u  || pickBit bin 16 = 1u || pickBit bin 0 = 1u))
   |> checkUndef
  (pickBit bin 20 = 1u && inITBlock itstate) |> checkUnpred

(* if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
   if size == '11' then UNDEFINED *)
let chkQVdVnVmSz bin =
  (((pickBit bin 6 = 1u) &&
    (pickBit bin 12 = 1u || pickBit bin 16 = 1u || pickBit bin 0 = 1u)) ||
    (extract bin 21 20 = 0b11u)) |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1' then UNDEFINED *)
let chkITVdVnVm bin itstate =
  inITBlock itstate |> checkUnpred
  (pickBit bin 12 = 1u || pickBit bin 16 = 1u || pickBit bin 0 = 1u)
  |> checkUndef

(* if sz == '1' && InITBlock() then UNPREDICTABLE *)
let chkSzIT bin itstate =
  (pickBit bin 20 = 1u && inITBlock itstate) |> checkUnpred

(* if size == '01' && InITBlock() then UNPREDICTABLE *)
let chkSz01IT bin itstate =
  (extract bin 9 8 = 0b01u && inITBlock itstate) |> checkUnpred

(* if sz == '1' && InITBlock() then UNPREDICTABLE
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
*)
let chkSzITQVdVnVm bin itstate =
  (pickBit bin 20 = 1u && inITBlock itstate) |> checkUnpred
  ((pickBit bin 6 = 1u) &&
   (pickBit bin 12 = 1u || pickBit bin 16 = 1u || pickBit bin 0 = 1u))
   |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
*)
let chkITQVdVnVm bin itstate =
  inITBlock itstate |> checkUnpred
  ((pickBit bin 6 = 1u) &&
   ((pickBit bin 12 = 1u) || (pickBit bin 16 = 1u) || (pickBit bin 0 = 1u)))
   |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED
*)
let chkITQVdVn bin itstate =
  inITBlock itstate |> checkUnpred
  ((pickBit bin 6 = 1u) && (pickBit bin 12 = 1u || pickBit bin 16 = 1u))
  |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Q == '1' && Vd<0> == '1' then UNDEFINED *)
let chkITQVd bin itstate =
  inITBlock itstate |> checkUnpred
  (pickBit bin 6 = 1u && pickBit bin 12 = 1u) |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Vd<0> == '1' || Vn<0> == '1' then UNDEFINED *)
let chkITVdVn bin itstate =
  inITBlock itstate |> checkUnpred
  checkUndef (pickBit bin 12 = 1u || pickBit bin 16 = 1u)

(* if op == '1' && size != '00' then UNDEFINED
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
*)
let chkQVdVnVmxx bin =
  ((pickBit bin 28 = 1u && extract bin 21 20 <> 0b00u) ||
   ((pickBit bin 6 = 1u) &&
    (pickBit bin 12 = 1u || pickBit bin 16 = 1u || pickBit bin 0 = 1u)))
    |> checkUndef

(* if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
   if Q == '0' && imm4<3> == '1' then UNDEFINED *)
let chkQVdVnVmImm4 bin =
  (((pickBit bin 6 = 1u) &&
    (pickBit bin 12 = 1u || pickBit bin 16 = 1u || pickBit bin 0 = 1u)) ||
   ((pickBit bin 6 = 0u) && (pickBit bin 11 = 1u))) |> checkUndef

(* if n+length > 32 then UNPREDICTABLE *)
let chkNLen bin =
  let n = concat (pickBit bin 7) (extract bin 19 16) 4
  (n + ((extract bin 9 8) + 1u (* length *)) > 32u) |> checkUnpred

(* half_to_single = (op == '1')
   if half_to_single && Vd<0> == '1' then UNDEFINED
   if !half_to_single && Vm<0> == '1' then UNDEFINED *)
let chkOpVdVm bin =
  ((pickBit bin 8 = 1u && pickBit bin 12 = 1u) ||
   (pickBit bin 8 <> 1u && pickBit bin 0 = 1u)) |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Vd<0> == '1' || Vm<0> == '1' then UNDEFINED *)
let chkITVdVm bin itstate =
  inITBlock itstate |> checkUnpred
  (pickBit bin 12 = 1u || pickBit bin 0 = 1u) |> checkUndef

(* if InITBlock() then UNPREDICTABLE
   if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED *)
let chkITQVdVm bin itstate =
  inITBlock itstate |> checkUnpred
  ((pickBit bin 6 = 1u) && (pickBit bin 12 = 1u || pickBit bin 0 = 1u))
  |> checkUndef

(* if F == '1' && size == '01' && InITBlock() then UNPREDICTABLE
   if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED *)
let chkFSzITQVdVm bin itstate =
  (pickBit bin 10 = 1u && extract bin 19 18 = 0b01u && inITBlock itstate)
  |> checkUnpred
  ((pickBit bin 6 = 1u) && (pickBit bin 12 = 1u || pickBit bin 0 = 1u))
  |> checkUndef

(* if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED
   if size == '01' && InITBlock() then UNPREDICTABLE *)
let chkQVdVmSzIT bin itstate =
  ((pickBit bin 6 = 1u) && (pickBit bin 12 = 1u || pickBit bin 0 = 1u))
  |> checkUndef
  (extract bin 19 18 = 0b01u && inITBlock itstate) |> checkUnpred

(* polynomial = (op == '1');
   if polynomial then
     if size == '10' then // .p64
       if InITBlock() then UNPREDICTABLE;
   if Vd<0> == '1' then UNDEFINED *)
let chkPolySzITVd bin itstate =
  (pickBit bin 9 = 1u && extract bin 21 20 = 0b10u && inITBlock itstate)
  |> checkUnpred
  (pickBit bin 16 = 1u) |> checkUndef

(* if size == '00' then UNDEFINED
   if F == '1' && size == '01' && InITBlock() then UNPREDICTABLE
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED *)
let chkSzFSzITQVdVn bin itstate =
  ((extract bin 21 20 = 0b00u) ||
   ((pickBit bin 24 = 1u) && (pickBit bin 12 = 1u || pickBit bin 16 = 1u)))
   |> checkUndef
  (pickBit bin 8 = 1u && extract bin 21 20 = 0b01u && inITBlock itstate)
  |> checkUnpred

(* if t == 15 || t2 == 15 || t == t2 then UNPREDICTABLE
   if W == '1' then UNPREDICTABLE *)
let chkPCRtRt2EqW bin =
  let t = extract bin 15 12
  let t2 = extract bin 11 8
  checkUnpred ((t = 15u || t2 = 15u || t = t2) || (pickBit bin 21 = 1u))

(* if d == 15 || t == 15 || n == 15 then UNPREDICTABLE
   if d == n || d == t then UNPREDICTABLE *)
let chkPCRd11RtRn bin =
  let d = extract bin 11 8
  let n = extract bin 19 16
  let t = extract bin 15 12
  checkUnpred ((d = 15u || t = 15u || n = 15u) || (d = n || d = t))

(* if d == 15 || t == 15 || n == 15 then UNPREDICTABLE
   if d == n || d == t then UNPREDICTABLE *)
let chkPCRd3RtRn bin =
  let d = extract bin 3 0
  let n = extract bin 19 16
  let t = extract bin 15 12
  checkUnpred ((d = 15u || t = 15u || n = 15u) || (d = n || d = t))

(* if d == 15 || t == 15 || t2 == 15 || n == 15 then UNPREDICTABLE
   if d == n || d == t || d == t2 then UNPREDICTABLE *)
let chkPCRdRtRt2Rn bin =
  let d = extract bin 3 0
  let t = extract bin 15 12
  let t2 = extract bin 11 8
  let n = extract bin 19 16
  ((d = 15u || t = 15u || t2 = 15u || n = 15u) || (d = n || d = t || d = t2))
  |> checkUnpred

(* if t == 15 || t2 == 15 || t == t2 || n == 15 then UNPREDICTABLE *)
let chkPCRtRt2Rn bin =
  let t = extract bin 15 12
  let t2 = extract bin 11 8
  (t = 15u || t2 = 15u || t = t2 || (extract bin 19 16 = 15u)) |> checkUnpred

(* if wback && (n == t || n == t2) then UNPREDICTABLE
   if n == 15 || t == 15 || t2 == 15 then UNPREDICTABLE *)
let chkPCRnRtRt2 bin =
  let n = extract bin 19 16
  let t = extract bin 15 12
  let t2 = extract bin 11 8
  ((wbackW bin && (n = t || n = t2)) || (n = 15u || t = 15u || t2 = 15u))
  |> checkUnpred

(* if wback && (n == t || n == t2) then UNPREDICTABLE
   if t == 15 || t2 == 15 || t == t2 then UNPREDICTABLE *)
let chkPCRtRt2Eq bin =
  let n = extract bin 19 16
  let t = extract bin 15 12
  let t2 = extract bin 11 8
  ((wbackW bin && (n = t || n = t2)) || (t = 15u || t2 = 15u || t = t2))
  |> checkUnpred

(* setflags = (S == '1')
   if (d == 15 && !setflags) || n == 15 || m == 15 then UNPREDICTABLE *)
let chkPCRdSRnRm bin =
  ((extract bin 11 8 = 15u && pickBit bin 20 <> 1u) ||
   (extract bin 19 16 = 15u) || (extract bin 3 0 = 15u)) |> checkUnpred

(* setflags = (S == '1')
   if (d == 15 && !setflags) || m == 15 then UNPREDICTABLE *)
let chkPCRdSRm bin =
  ((extract bin 11 8 = 15u && pickBit bin 20 <> 1u) || (extract bin 3 0 = 15u))
  |> checkUnpred

(* setflags = (S == '1')
   if (d == 15 && !setflags) || n == 15 then UNPREDICTABLE *)
let chkPCRdSRn bin =
  ((extract bin 11 8 = 15u && pickBit bin 20 <> 1u) || (extract bin 19 16 = 15u))
  |> checkUnpred

(* setflags = (S == '1')
   if d == 15 && !setflags then UNPREDICTABLE *)
let chkPCRdS bin =
  (extract bin 11 8 = 15u && pickBit bin 20 <> 1u) |> checkUnpred

(* if d == 15 then UNPREDICTABLE *)
let chkPCRd bin = checkUnpred (extract bin 11 8 = 15u)

(* if d == 15 || m == 15 then UNPREDICTABLE *)
let chkPCRdRm bin =
  checkUnpred ((extract bin 11 8 = 15u) || (extract bin 3 0 = 15u))

(* if n == 15 || m == 15 then UNPREDICTABLE *)
let chkPCRnRm bin =
  checkUnpred (extract bin 19 16 = 15u || extract bin 3 0 = 15u)

(* if d == 15 || n == 15 then UNPREDICTABLE *)
let chkPCRdRn bin =
  checkUnpred (extract bin 11 8 = 15u || extract bin 19 16 = 15u)

(* if mask == '0000' then UNPREDICTABLE
   if n == 15 then UNPREDICTABLE *)
let chkMaskPCRn bin =
  checkUnpred ((extract bin 11 8 = 0b0000u) || (extract bin 19 16 = 15u))

(* if mode != '00000' && M == '0' then UNPREDICTABLE
   if (imod<1> == '1' && A:I:F == '000') || (imod<1> == '0' && A:I:F != '000')
   then UNPREDICTABLE
   if imod == '01' || InITBlock() then UNPREDICTABLE *)
let chkModeImodAIFIT bin itstate =
  let imod1 = pickBit bin 10 (* imod<1> *)
  let aif = extract bin 7 5 (* A:I:F *)
  (((extract bin 4 0 (* mode *) <> 0u) && (pickBit bin 8 = 0u (* M *))) ||
   ((imod1 = 1u && aif = 0u) || (imod1 = 0u && aif <> 0u)) ||
   (extract bin 10 9 = 0b01u || inITBlock itstate)) |> checkUndef

(* if t == 15 || m == 15 then UNPREDICTABLE *)
let chkPCRtRm bin =
  ((extract bin 15 12 (* Rt *) = 15u) || (extract bin 3 0 (* Rm *) = 15u))
  |> checkUnpred

(* if m == 15 then UNPREDICTABLE
   if t == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRmRtIT bin itstate =
  ((extract bin 3 0 = 15u) ||
   (extract bin 19 16 = 15u &&
    inITBlock itstate && (lastInITBlock itstate |> not)))
    |> checkUnpred

(* if t == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE *)
let chkPCRtIT bin itstate =
  (extract bin 19 16 = 15u && inITBlock itstate && lastInITBlock itstate |> not)
  |> checkUnpred

(* if Rn == '1111' || (P == '0' && W == '0') then UNDEFINED
   if t == 15 || (wback && n == t) then UNPREDICTABLE *)
let chkRnPWPCRtWBRn bin =
  let n = extract bin 19 16
  let t = extract bin 15 12
  ((n = 0b1111u) || (pickBit bin 10 = 0u && pickBit bin 8 = 0u)) |> checkUndef
  (t = 15u || (wbackW8 bin && n = t)) |> checkUnpred

(* if P == '0' && W == '0' then UNDEFINED
   if (t == 15 && W == '1') || (wback && n == t) then UNPREDICTABLE *)
let chkPWPCRtWBRn bin =
  let w = pickBit bin 8
  let t = extract bin 15 12
  (pickBit bin 10 (* P *) = 0u && w = 0u) |> checkUndef
  ((t = 15u && w = 1u) || (wbackW8 bin && extract bin 19 16 (* Rn *) = t))
  |> checkUnpred

(* if P == '0' && W == '0' then UNDEFINED
   if (wback && n == t) || (t == 15 && InITBlock() && !LastInITBlock())
   then UNPREDICTABLE *)
let chkPWWBRnPCRtIT bin itstate =
  let t = extract bin 15 12
  (pickBit bin 10 (* P *) = 0u && pickBit bin 8 (* W *) = 0u) |> checkUndef
  ((wbackW8 bin && extract bin 19 16 (* Rn *) = t) ||
   (t = 15u && inITBlock itstate && (lastInITBlock itstate |> not)))
   |> checkUnpred

(* if Rn == '1111' then UNDEFINED
   if t == 15 then UNPREDICTABLE *)
let chkRnPCRt bin =
  extract bin 19 16 (* Rn *) = 0b1111u |> checkUndef
  extract bin 15 12 (* Rt *) = 15u |> checkUnpred

(* if d == 15 || m == 15 || s == 15 then UNPREDICTABLE *)
let chkPCRdRmRs bin =
  ((extract bin 11 8 = 15u) || (extract bin 19 16 = 15u) ||
   (extract bin 3 0 = 15u)) |> checkUnpred

(* if d == 15 || n == 15 || m == 15 then UNPREDICTABLE *)
let chkPCRdRnRm bin =
  ((extract bin 11 8 = 15u) || (extract bin 19 16 = 15u) ||
   (extract bin 3 0 = 15u)) |> checkUnpred

(* if InITBlock() then UNPREDICTABLE
   if d == 15 || n == 15 || m == 15 then UNPREDICTABLE *)
let chkITPCRdRnRm bin itstate =
  (inITBlock itstate || extract bin 11 8 = 15u || extract bin 19 16 = 15u ||
   extract bin 3 0 = 15u) |> checkUnpred

(* if m != n || d == 15 || m == 15 then UNPREDICTABLE *)
let chkRmRnPCRdRm bin =
  let rm = extract bin 3 0
  ((rm <> extract bin 19 16) || (extract bin 11 8 = 15u) || (rm = 15u))
  |> checkUnpred

(* if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE *)
let chkPCRdRnRmRa bin =
  (extract bin 11 8 = 15u || extract bin 19 16 = 15u || extract bin 3 0 = 15u ||
   extract bin 15 12 = 15u) |> checkUnpred

(* if d == 15 || n == 15 || m == 15 || a != 15 then UNPREDICTABLE *)
let chkPCRdRnRmRaNot bin =
  (extract bin 11 8 = 15u || extract bin 19 16 = 15u || extract bin 3 0 = 15u ||
   extract bin 15 12 <> 15u) |> checkUnpred

(* if dLo == 15 || dHi == 15 || n == 15 || m == 15 then UNPREDICTABLE
   if dHi == dLo then UNPREDICTABLE *)
let chkPCRdlRdhRnRm bin =
  let dLo = extract bin 15 12
  let dHi = extract bin 11 8
  ((dLo = 15u || dHi = 15u || extract bin 19 16 = 15u || extract bin 3 0 = 15u)
  || (dHi = dLo)) |> checkUnpred

(* S8  when U = 0, size = 00
   S16 when U = 0, size = 01
   S32 when U = 0, size = 10
   U8  when U = 1, size = 00
   U16 when U = 1, size = 01
   U32 when U = 1, size = 10 *)
let getDT bin = (* FIXME: Integration with ARM32 *)
  match concat (pickBit bin 28) (extract bin 21 20) 2 (* U:size *) with
  | 0b000u -> SIMDTypS8
  | 0b001u -> SIMDTypS16
  | 0b010u -> SIMDTypS32
  | 0b100u -> SIMDTypU8
  | 0b101u -> SIMDTypU16
  | 0b110u -> SIMDTypU32
  | _ -> Utils.impossible ()

(* U16 when size = 01
   U32 when size = 10 *)
let getDTUSign = function (* [21:20] *)
  | 0b01u -> SIMDTypU16
  | 0b10u -> SIMDTypU32
  | _ -> raise UndefinedException

(* 8 when  L = 0, imm6<5:3> = 001
   16 when L = 0, imm6<5:3> = 01x
   32 when L = 0, imm6<5:3> = 1xx
   64 when L = 1, imm6<5:3> = xxx *)
let getDTLImm bin = (* FIXME: Integration with ARM32 *)
  let isSign = pickBit bin 28 (* U *) = 0u
  match concat (pickBit bin 7) (extract bin 21 19) 3 (* L:imm6<5:3> *) with
  | 0b0000u -> Utils.impossible ()
  | 0b0001u -> if isSign then SIMDTypS8 else SIMDTypU16
  | 0b0010u | 0b0011u -> if isSign then SIMDTypS16 else SIMDTypU16
  | 0b0100u | 0b0101u | 0b0110u | 0b0111u ->
    if isSign then SIMDTypS32 else SIMDTypU32
  | _ (* 1xxx *) -> if isSign then SIMDTypS64 else SIMDTypU64
  |> oneDt

(* S8 when  U = 0, imm3H = 001
   S16 when U = 0, imm3H = 010
   S32 when U = 0, imm3H = 100
   U8 when  U = 1, imm3H = 001
   U16 when U = 1, imm3H = 010
   U32 when U = 1, imm3H = 100 *)
let getDTUImm3H bin = (* FIXME: Integration with ARM32 *)
  match concat (pickBit bin 28) (extract bin 21 19) 3 (* U:imm3H *) with
  | 0b0001u -> SIMDTypS8
  | 0b0010u -> SIMDTypS16
  | 0b0100u -> SIMDTypS32
  | 0b1001u -> SIMDTypU8
  | 0b1010u -> SIMDTypU16
  | 0b1100u -> SIMDTypU32
  | _ -> Utils.impossible ()
  |> oneDt

(* S when U = 0
   U when U = 1
   16 when imm6<5:3> = 001
   32 when imm6<5:3> = 01x
   64 when imm6<5:3> = 1xx *)
let getDTImm6Word bin = (* FIXME: Integration with ARM32 *)
  let isSign = pickBit bin 28 (* U *) = 0u
  match extract bin 21 19 (* imm6<5:3> *) with
  | 0b000u -> Utils.impossible ()
  | 0b001u -> if isSign then SIMDTypS16 else SIMDTypU16
  | 0b010u | 0b011u (* 01x *) -> if isSign then SIMDTypS32 else SIMDTypU32
  | _ (* 1xx *) -> if isSign then SIMDTypS64 else SIMDTypU64
  |> oneDt

let getDTImm6Byte bin = (* FIXME: Integration with ARM32 *)
  let isSign = pickBit bin 28 (* U *) = 0u
  match extract bin 21 19 (* imm6<5:3> *) with
  | 0b000u -> Utils.impossible ()
  | 0b001u -> if isSign then SIMDTypS8 else SIMDTypU8
  | 0b010u | 0b011u (* 01x *) -> if isSign then SIMDTypS16 else SIMDTypU16
  | _ (* 1xx *) -> if isSign then SIMDTypS32 else SIMDTypU32
  |> oneDt

let getDTPoly b =
  (* op:U:size *)
  match (pickBit b 9 <<< 3) + (pickBit b 28 <<< 2) + (extract b 21 20) with
  | 0b0000u -> SIMDTypS8
  | 0b0001u -> SIMDTypS16
  | 0b0010u -> SIMDTypS32
  | 0b0100u -> SIMDTypU8
  | 0b0101u -> SIMDTypU16
  | 0b0110u -> SIMDTypU32
  | 0b1000u -> SIMDTypP8
  | 0b1010u -> SIMDTypP64
  | _ -> raise UndefinedException

let getDTFP bin =
  match extract bin 9 8 (* size *) with
  | 0b00u -> raise UndefinedException
  | 0b01u -> SIMDTypF16
  | 0b10u -> SIMDTypF32
  | _ (* 11 *) -> SIMDTypF64
  |> oneDt

/// Data types: FP, sign, unsign
let getDTFSU bin =
  match extract bin 9 7 (* size:op *) with
  | 0b000u | 0b001u -> raise UndefinedException
  | 0b010u -> SIMDTypF16, SIMDTypU32
  | 0b011u -> SIMDTypF16, SIMDTypS32
  | 0b100u -> SIMDTypF32, SIMDTypU32
  | 0b101u -> SIMDTypF32, SIMDTypS32
  | 0b110u -> SIMDTypF64, SIMDTypU32
  | _ (* 111 *) -> SIMDTypF64, SIMDTypS32
  |> twoDt

let getDTOpU bin =
  let opU = concat (extract bin 9 8) (pickBit bin 28) 1 (* op:U *)
  let dt1 =
    match opU with
    | 0b000u | 0b001u (* 00x *) -> SIMDTypF16
    | 0b010u -> SIMDTypS16
    | 0b011u -> SIMDTypU16
    | 0b100u | 0b101u (* 10x *) -> SIMDTypF32
    | 0b110u -> SIMDTypS32
    | _ (* 111 *) -> SIMDTypU32
  let dt2 =
    match opU with
    | 0b000u -> SIMDTypS16
    | 0b001u -> SIMDTypU16
    | 0b010u | 0b011u (* 01x *) -> SIMDTypF16
    | 0b100u -> SIMDTypS32
    | 0b101u -> SIMDTypU32
    | _ (* 11x *) -> SIMDTypF32
  twoDt (dt1, dt2)

(* <label> *)
let oprLabel bin =
  let label = (extract bin 10 0 <<< 1) |> signExtend 12
  struct (OneOperand label, false, None)

(* <label> *)
let oprLabel8 bin =
  let label = extract bin 7 0 <<< 1 |> signExtend 9
  struct (OneOperand label, false, None)

(* <label> // Preferred syntax
   [PC, #{+/-}<imm>] // Alternative syntax *)
let oprLabel12 bin =
  let imm12 = extract bin 11 0 |> int64
  struct (OneOperand (memLabel imm12), false, None)

(* <label> *)
let oprLabelT3 bin =
  let imm32 (* S:J2:J1:imm6:imm11:'0' *) =
    ((pickBit bin 26 <<< 19) + (pickBit bin 11 <<< 18) + (pickBit bin 13 <<< 17)
    + (extract bin 21 16 <<< 11) + (extract bin 10 0)) <<< 1 |> signExtend 21
  struct (OneOperand imm32, false, None)

(* <label> *)
let oprLabelT4 bin = (* or BL T1 *)
  let i1 = if (pickBit bin 13 ^^^ pickBit bin 26) = 0u then 1u else 0u
  let i2 = if (pickBit bin 11 ^^^ pickBit bin 26) = 0u then 1u else 0u
  let imm32 (* S:I1:I2:imm10:imm11:'0' *) =
    ((pickBit bin 26 <<< 23) + (i1 <<< 22) + (i2 <<< 21) +
     (extract bin 25 16 <<< 11) + (extract bin 10 0)) <<< 1 |> signExtend 25
  struct (OneOperand imm32, false, None)

(* <label> *)
let oprLabelT2 bin =
  let i1 = if (pickBit bin 13 ^^^ pickBit bin 26) = 0u then 1u else 0u
  let i2 = if (pickBit bin 11 ^^^ pickBit bin 26) = 0u then 1u else 0u
  let imm32 (* S:I1:I2:imm10H:imm10L:'00' *) =
    ((pickBit bin 26 <<< 22) + (i1 <<< 21) + (i2 <<< 20) +
     (extract bin 25 16 <<< 10) + (extract bin 10 1)) <<< 2 |> signExtend 25
  struct (OneOperand imm32, false, None)

(* <Rm> *)
let oprRm16 bin =
  let rm = extract bin 6 3 |> getRegister |> OprReg
  struct (OneOperand rm, false, None)

(* <Rm> *)
let oprRm32 bin =
  let rm = extract bin 6 3 |> getRegister |> OprReg
  struct (OneOperand rm, false, None)

(* #<imm> *)
let oprImm bin =
  struct (OneOperand (OprImm (pickBit bin 3 (* imm1 *) |> int64)), false, None)

(* {#}<imm> *)
let oprImm6 bin =
  let imm = OprImm (extract bin 5 0 (* imm6 *) |> int64)
  struct (OneOperand imm, false, None)

(* {#}<imm> *)
let oprImm8 bin =
  let imm = OprImm (extract bin 7 0 (* imm8 *) |> int64)
  struct (OneOperand imm, false, None)

(* {#}<imm> *)
let oprImm16 bin =
  let imm (* imm4:imm12 *) =
    concat (extract bin 19 16) (extract bin 11 0) 12 |> int64 |> OprImm
  struct (OneOperand imm, false, None)

(* {#}<imm4> *)
let oprImm4 bin =
  struct (extract bin 19 16 |> int64 |> OprImm |> OneOperand, false, None)

(* <cond> *)
let oprCond bin =
  let cond = extract bin 7 4 |> byte |> parseCond |> OprCond
  struct (OneOperand cond, false, None)

(* <endian_specifier> *)
let oprEndian bin =
  let endian = pickBit bin 3 |> byte |> getEndian |> OprEndian
  struct (OneOperand endian, false, None)

(* <iflags> *)
let oprIflags bin =
  struct (OneOperand (OprIflag (getIflag (extract bin 7 5))), false, None)

(* <iflags> , #<mode> *)
let oprIflagsMode bin =
  let iflags = OprIflag (getIflag (extract bin 7 5))
  let mode = extract bin 4 0 |> int64 |> OprImm
  struct (TwoOperands (iflags, mode), false, None)

(* <registers> *)
let oprRegsM bin =
  let regs = (* '0':M:'000000':register_list *)
    concat (pickBit bin 8 <<< 6) (extract bin 7 0) 8 |> getRegList |> OprRegList
  struct (OneOperand regs, false, None)

(* <registers> *)
let oprRegsP bin =
  let regs = (* P:'0000000':register_list *)
    concat (pickBit bin 8 <<< 7) (extract bin 7 0) 8 |> getRegList |> OprRegList
  struct (OneOperand regs, false, None)

(* [<Rn> {, #-<imm>}] *)
let oprMemImm8M bin =
  let rn = extract bin 19 16 |> getRegister
  let imm = extract bin 7 0 (* imm8 *) |> int64
  struct (OneOperand (memOffsetImm (rn, Some Minus, Some imm)), false, None)

(* [<Rn> {, #{+}<imm>}] *)
let oprMemImm12 bin =
  let rn = extract bin 19 16 |> getRegister
  let imm = extract bin 11 0 (* imm12 *) |> int64
  struct (OneOperand (memOffsetImm (rn, Some Plus, Some imm)), false, None)

(* [<Rn>, <Rm>] *)
let oprMemReg bin =
  let rn = getRegister (extract bin 19 16)
  let rm = getRegister (extract bin 3 0)
  struct (OneOperand (memOffsetReg (rn, None, rm, None)), false, None)

(* [<Rn>, <Rm>, LSL #1] *)
let oprMemRegLSL1 bin =
  let rn = getRegister (extract bin 19 16)
  let rm = getRegister (extract bin 3 0)
  let shf = Some (SRTypeLSL, Imm 1u)
  struct (OneOperand (memOffsetReg (rn, None, rm, shf)), false, None)

(* [<Rn>, {+}<Rm> {, LSL #<amount>}] *)
let oprMemRegLSL bin =
  let rn = getRegister (extract bin 19 16)
  let rm = getRegister (extract bin 3 0)
  let shf = Some (SRTypeLSL, Imm (extract bin 5 4 (* imm2 *)))
  struct (OneOperand (memOffsetReg (rn, None, rm, shf)), false, None)

(* <Rt>, <label> *)
let oprRtLabel bin =
  let rt = extract bin 10 8 |> getRegister |> OprReg
  let label = extract bin 7 0 <<< 2 |> int64 |> memLabel
  struct (TwoOperands (rt, label), false, None)

(* <Rn>, <label> *)
let oprRnLabel bin =
  let rn = extract bin 2 0 |> getRegister |> OprReg
  let label = (* i:imm5:'0' *)
    (concat (pickBit bin 9) (extract bin 7 3) 5) <<< 1 |> int64 |> memLabel
  struct (TwoOperands (rn, label), false, None)

(* <Rt>, <label> // Preferred syntax
   <Rt>, [PC, #{+/-}<imm>] // Alternative syntax *)
let oprRtLabel12 bin =
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let label = extract bin 11 0 |> int64 |> memLabel
  struct (TwoOperands (rt, label), false, None)

(* <Rd>, #<imm8> *)
let oprRdImm8 bin =
  let rd = extract bin 10 8 |> getRegister |> OprReg
  let imm8 = extract bin 7 0 |> int64 |> OprImm
  struct (TwoOperands (rd, imm8), false, None) /// FIXME: carry = PSTATE.C

(* <Rdn>, #<imm8> *)
let oprRdnImm8 bin =
  let rdn = extract bin 10 8 |> getRegister |> OprReg
  let imm8 = extract bin 7 0 |> int64 |> OprImm
  struct (TwoOperands (rdn, imm8), false, None)

(* <Dd>, #<imm> *)
let oprDdImm bin =
  let dd = (* D:Vd *)
    concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
  let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64 |> OprImm
  struct (TwoOperands (dd, imm), false, None)

(* <Qd>, #<imm> *)
let oprQdImm bin =
  let qd = (* D:Vd *)
    concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
  let imm = advSIMDExpandImm bin (pickBit bin 28) |> int64 |> OprImm
  struct (TwoOperands (qd, imm), false, None)

(* <Rd>, <Rm> *)
let oprRdRmT16 bin =
  let rd = extract bin 2 0 |> getRegister |> OprReg
  let rm = extract bin 5 3 |> getRegister |> OprReg
  struct (TwoOperands (rd, rm), false, None)

(* <Rd>, <Rm> *)
let oprRdRmT32 bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let rm = extract bin 3 0 |> getRegister |> OprReg
  struct (TwoOperands (rd, rm), false, None)

(* <Rd>, <Rm> *)
let oprRdRmExt bin =
  let rd = (* D:Rd *)
    concat (pickBit bin 7) (extract bin 2 0) 3 |> getRegister |> OprReg
  let rm = extract bin 6 3 |> getRegister |> OprReg
  struct (TwoOperands (rd, rm), false, None)

(* <Rn>, <Rm> *)
let oprRnRm bin =
  let rn = extract bin 2 0 |> getRegister |> OprReg
  let rm = extract bin 5 3 |> getRegister |> OprReg
  struct (TwoOperands (rn, rm), false, None)

(* <Rn>, <Rm> *)
let oprRnRmExt bin =
  let rn = (* N:Rn *)
    concat (pickBit bin 7) (extract bin 2 0) 3 |> getRegister |> OprReg
  let rm = extract bin 6 3 |> getRegister |> OprReg
  struct (TwoOperands (rn, rm), false, None)

(* <Rdn>, <Rm> *)
let oprRdnRm bin =
  let rdn = (* DN:Rdn *)
    concat (pickBit bin 7) (extract bin 2 0) 3 |> getRegister |> OprReg
  let rm = extract bin 6 3 |> getRegister |> OprReg
  struct (TwoOperands (rdn, rm), false, None)

(* <Rn>, #<const> *)
let oprRnConst bin =
  let rn = extract bin 19 16 |> getRegister |> OprReg
  let imm12 (* i:imm3:imm8 *) =
    (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
  let cons = t32ExpandImm imm12 |> int64 |> OprImm
  struct (TwoOperands (rn, cons), false, None)

(* <Rd>, #<const> *)
let oprRdConst bin =
  let rn = extract bin 11 8 |> getRegister |> OprReg
  let imm12 (* i:imm3:imm8 *) =
    (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
  let cons = t32ExpandImm imm12 |> int64 |> OprImm
  struct (TwoOperands (rn, cons), false, None)

(* <Rn>!, <registers> *)
let oprRnRegs bin =
  let rn = extract bin 10 8 |> getRegister |> OprReg
  let regs = extract bin 7 0 (* register_list *) |> getRegList |> OprRegList
  struct (TwoOperands (rn, regs), true, None)

(* <Rn>!, <registers> *)
let oprRnRegsW bin =
  let rn = extract bin 10 8
  let regs = extract bin 7 0 (* register_list *)
  let wback = pickBit regs (int rn) = 0u
  let regs = regs |> getRegList |> OprRegList
  struct (TwoOperands (rn |> getRegister |> OprReg, regs), wback, None)

(* <spec_reg>, <Rn> *)
let oprSregRn bin =
  let struct (sreg, flag) = (* FIXME: F5-4583 *)
    if pickBit bin 20 = 1u (* R *) then getSPSR (extract bin 19 16)
    else getAPSR (extract bin 11 10 (* mask<3:2> *)) (* or CPSR *)
  let rn = extract bin 19 16 |> getRegister |> OprReg
  struct (TwoOperands (OprSpecReg (sreg, flag), rn), false, None)

(* <Rd>, <spec_reg> *)
let oprRdSreg bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let sreg =
    if pickBit bin 20 = 1u then R.SPSR else R.APSR (* or CPSR *)
    |> uint |> getRegister |> OprReg
  struct (TwoOperands (rd, sreg), false, None)

(* <banked_reg>, <Rn> *)
let oprBankregRn bin =
  let breg =
    concat (pickBit bin 4) (extract bin 11 8) 4 (* M:M1 *)
    |> getBankedReg (pickBit bin 20) (* R *) |> OprReg
  let rn = extract bin 19 16 |> getRegister |> OprReg
  struct (TwoOperands (breg, rn), false, None)

(* <Rd>, <banked_reg> *)
let oprRdBankreg bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let breg =
    concat (pickBit bin 4) (extract bin 19 16) 4 (* M:M1 *)
    |> getBankedReg (pickBit bin 20) (* R *) |> OprReg
  struct (TwoOperands (rd, breg), false, None)

(* {<Dd>,} <Dm>, #0 *)
let oprDdDm0 bin =
  let dd = (* D:Vd *)
    concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecDReg |> toSVReg
  let dm = (* M:Vm *)
    concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecDReg |> toSVReg
  struct (ThreeOperands (dd, dm, OprImm 0L), false, None)

(* {<Qd>,} <Qm>, #0 *)
let oprQdQm0 bin =
  let qd = (* D:Vd *)
    concat (pickBit bin 22) (extract bin 15 12) 4 |> getVecQReg |> toSVReg
  let qm = (* M:Vm *)
    concat (pickBit bin 5) (extract bin 3 0) 4 |> getVecQReg |> toSVReg
  struct (ThreeOperands (qd, qm, OprImm 0L), false, None)

(* <Rt>, [<Rn>, {+}<Rm>] *)
let oprRtMemReg16 bin =
  let rt = extract bin 2 0 |> getRegister |> OprReg
  let mem =
    let rn = extract bin 5 3 |> getRegister
    let rm = extract bin 8 6 |> getRegister
    memOffsetReg (rn, Some Plus, rm, None)
  struct (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn>, {+}<Rm>] *)
let oprRtMemReg32 bin =
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let mem =
    let rn = extract bin 19 16 |> getRegister
    let rm = extract bin 3 0 |> getRegister
    memOffsetReg (rn, Some Plus, rm, None)
  struct (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn>, {+}<Rm>{, LSL #<imm>}] *)
let oprRtMemRegLSL bin =
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let mem =
    let rn = extract bin 19 16 |> getRegister
    let rm = extract bin 3 0 |> getRegister
    let amount = Imm (extract bin 5 4 (* imm2 *))
    memOffsetReg (rn, Some Plus, rm, Some (SRTypeLSL, amount))
  struct (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #{+}<imm>}] *)
let oprRtMemImm bin shfAmt = /// imm5
  let rt = extract bin 2 0 |> getRegister |> OprReg
  let mem =
    let rn = extract bin 5 3 |> getRegister
    let imm = extract bin 10 6 (* imm5 *) <<< shfAmt |> int64
    memOffsetImm (rn, Some Plus, Some imm)
  struct (TwoOperands (rt, mem), false, None)

let oprRtMemImm0 bin = oprRtMemImm bin 0 (* ZeroExtend(imm5, 32) *)
let oprRtMemImm1 bin = oprRtMemImm bin 1 (* ZeroExtend(imm5:'0', 32) *)
let oprRtMemImm2 bin = oprRtMemImm bin 2 (* ZeroExtend(imm5:'00', 32) *)

(* <Rt>, [<Rn> {, #<imm>}] *)
let oprRtMemImm8 bin =
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let mem =
    let rn = extract bin 19 16 |> getRegister
    let imm = extract bin 7 0 <<< 2 (* imm8:'00' *) |> int64
    memOffsetImm (rn, None, Some imm)
  struct (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #{+}<imm>}] *)
let oprRtMemImm8P bin = /// imm8 & Plus
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let mem =
    let rn = extract bin 19 16 |> getRegister
    let imm = extract bin 7 0 (* imm8 *) |> int64
    memOffsetImm (rn, Some Plus, Some imm)
  struct (TwoOperands (rt, mem), false, None)

(* <Rt>, [<Rn> {, #-<imm>}] *)
let oprRtMemImm8M bin = /// imm8 & Minus
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let mem =
    let rn = extract bin 19 16 |> getRegister
    let imm = extract bin 7 0 (* imm8 *) |> int64
    memOffsetImm (rn, Some Minus, Some imm)
  struct (TwoOperands (rt, mem), wbackW8 bin, None)

(* <Rt>, [<Rn>], #{+/-}<imm> *)
let oprRtMemImmPs bin = /// Post-indexed
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let mem =
    let rn = extract bin 19 16 |> getRegister
    let imm = extract bin 7 0 (* imm8 *) |> int64
    let sign = pickBit bin 9 |> getSign |> Some
    memPostIdxImm (rn, sign, Some imm)
  struct (TwoOperands (rt, mem), wbackW8 bin, None)

(* <Rt>, [<Rn>, #{+/-}<imm>]! *)
let oprRtMemImmPr bin = /// Pre-indexed
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let mem =
    let rn = extract bin 19 16 |> getRegister
    let imm = extract bin 7 0 (* imm8 *) |> int64
    let sign = pickBit bin 9 |> getSign |> Some
    memPreIdxImm (rn, sign, Some imm)
  struct (TwoOperands (rt, mem), wbackW8 bin, None)

(* <Rt>, [<Rn> {, #{+}<imm>}] *)
let oprRtMemImm12 bin =
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let mem =
    let imm12 = extract bin 11 0 |> int64
    let rn = extract bin 19 16 |> getRegister
    memOffsetImm (rn, Some Plus, Some imm12)
  struct (TwoOperands (rt, mem), false, None)

(* <Rt>, [SP{, #{+}<imm>}] *)
let oprRtMemSP bin =
  let rt = extract bin 10 8 |> getRegister |> OprReg
  let mem =
    let imm = extract bin 7 0 (* imm8 *) <<< 2 |> int64
    memOffsetImm (R.SP, Some Plus, Some imm)
  struct (TwoOperands (rt, mem), false, None)

(* <Rd>, <label> *)
let oprRdLabel bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let imm32 (* i:imm3:imm8 *) =
    (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
    |> int64 |> memLabel
  struct (TwoOperands (rd, imm32), false, None)

(* <Rt>, <Rt2>, <label> *)
let oprRtRt2Label bin =
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let rt2 = extract bin 11 8 |> getRegister |> OprReg
  let label = extract bin 7 0 <<< 2 (* imm8:'00' *) |> int64 |> memLabel
  struct (ThreeOperands (rt, rt2, label), false, None)

(* <Rd>, <Rn>, <Rm> *)
(* {<Rd>,} <Rn>, <Rm> *)
let oprRdRnRmT16 bin =
  let rd = extract bin 2 0 |> getRegister |> OprReg
  let rn = extract bin 5 3 |> getRegister |> OprReg
  let rm = extract bin 8 6 |> getRegister |> OprReg
  struct (ThreeOperands (rd, rn, rm), false, None)

(* {<Rd>,} <Rn>, <Rm> *)
let oprRdRnRmT32 bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let rn = extract bin 19 16 |> getRegister |> OprReg
  let rm = extract bin 3 0 |> getRegister |> OprReg
  struct (ThreeOperands (rd, rn, rm), false, None)

(* {<Rd>,} <Rm>, <Rn> *)
let oprRdRmRn bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let rm = extract bin 3 0 |> getRegister |> OprReg
  let rn = extract bin 19 16 |> getRegister |> OprReg
  struct (ThreeOperands (rd, rm, rn), false, None)

(* {<Rd>,} <Rm>, #<imm> *)
let oprRdRmImm bin =
  let rd = extract bin 2 0 |> getRegister |> OprReg
  let rm = extract bin 5 3 |> getRegister |> OprReg
  let imm = extract bin 10 6 |> int64 |> OprImm
  struct (ThreeOperands (rd, rm, imm), false, None)

(* <Rd>, <Rn>, #<imm3> *)
let oprRdRnImm3 bin =
  let rd = extract bin 2 0 |> getRegister |> OprReg
  let rn = extract bin 5 3 |> getRegister |> OprReg
  let imm3 = extract bin 8 6 (* imm3 *) |> int64 |> OprImm
  struct (ThreeOperands (rd, rn, imm3), false, None)

(* <Rd>, SP, #<imm8> *)
let oprRdSPImm8 bin =
  let rd = extract bin 10 8 |> getRegister |> OprReg
  let imm8 = extract bin 7 0 (* imm8 *) <<< 2 |> int64 |> OprImm
  struct (ThreeOperands (rd, OprReg R.SP, imm8), false, None)

(* {<Rd>,} <Rn>, #<imm12> *)
let oprRdRnImm12 bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let rn = extract bin 19 16 |> getRegister |> OprReg
  let imm12 (* i:imm3:imm8 *) =
    (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
    |> int64
  struct (ThreeOperands (rd, rn, OprImm imm12), false, None)

(* <Rd>, #<imm16> *)
let oprRdImm16 bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let imm16 = (* imm4:i:imm3:imm8 *)
    (extract bin 19 16 <<< 12) + (pickBit bin 26 <<< 11) +
    (extract bin 14 12 <<< 8) + (extract bin 7 0) |> int64 |> OprImm
  struct (TwoOperands (rd, imm16), false, None)

(* {<Rd>,} SP, #<imm12> *)
let oprRdSPImm12 bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let imm12 (* i:imm3:imm8 *) =
    (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
    |> int64
  struct (ThreeOperands (rd, OprReg R.SP, OprImm imm12), false, None)

(* PC, LR, #<imm8> *)
let oprPCLRImm8 bin =
  let imm8 = extract bin 7 0 (* imm8 *) |> int64 |> OprImm
  struct (ThreeOperands (OprReg R.PC, OprReg R.LR, imm8), false, None)

(* {SP,} SP, #<imm7> *)
let oprSPSPImm7 bin =
  let imm = extract bin 6 0 (* imm7 *) <<< 2 |> int64 |> OprImm
  struct (ThreeOperands (OprReg R.SP, OprReg R.SP, imm), false, None)

(* <Rd>, <Rm> {, <shift> #<amount>} *)
let oprRdRmShfT16 bin =
  let rd = extract bin 2 0 |> getRegister |> OprReg
  let rm = extract bin 5 3 |> getRegister |> OprReg
  let struct (shift, amount) =
    decodeImmShift (extract bin 12 11) (extract bin 10 6) (* stype, imm5 *)
  struct (ThreeOperands (rd, rm, OprShift (shift, Imm amount)), false, None)

(* <Rd>, <Rm> {, <shift> #<amount>} *)
let oprRdRmShfT32 b =
  let rd = extract b 11 8 |> getRegister |> OprReg
  let rm = extract b 3 0 |> getRegister |> OprReg
  let struct (shift, amount) = (* stype, imm3:imm2 *)
    decodeImmShift (extract b 5 4) (concat (extract b 14 12) (extract b 7 6) 2)
  struct (ThreeOperands (rd, rm, OprShift (shift, Imm amount)), false, None)

(* {<Rd>, }<Rn>, #0 *)
let oprRdRn0 bin =
  let rd = extract bin 2 0 |> getRegister |> OprReg
  let rn = extract bin 5 3 |> getRegister |> OprReg
  struct (ThreeOperands (rd, rn, OprImm 0L), false, None)

(* {<Rd>, }<Rn>, #0 *)
let oprRdRn0T32 bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let rn = extract bin 19 16 |> getRegister |> OprReg
  struct (ThreeOperands (rd, rn, OprImm 0L), false, None)

(* {<Rdn>,} <Rdn>, <Rm> *)
let oprRdnRdnRm bin =
  let rdn = extract bin 2 0 |> getRegister |> OprReg
  let rm = extract bin 5 3 |> getRegister |> OprReg
  struct (ThreeOperands (rdn, rdn, rm), false, None)

(* <Rdm>, <Rn>{, <Rdm>} *)
let oprRdmRnRdm bin =
  let rdm = extract bin 2 0 |> getRegister |> OprReg
  let rn = extract bin 5 3 |> getRegister |> OprReg
  struct (ThreeOperands (rdm, rn, rdm), false, None)

(* {<Rdm>,} SP, <Rdm> *)
let oprRdmSPRdm bin =
  let rdm = (* DM:Rdm *)
    concat (pickBit bin 7) (extract bin 2 0) 3 |> getRegister |> OprReg
  struct (ThreeOperands (rdm, OprReg R.SP, rdm), false, None)

(* {SP,} SP, <Rm> *)
let oprSPSPRm bin =
  let rm = extract bin 6 3 |> getRegister |> OprReg
  struct (ThreeOperands (OprReg R.SP, OprReg R.SP, rm), false, None)

(* <Rd>, <Rt>, [<Rn>] *)
let oprRdRtMem bin =
  let rd = extract bin 3 0 |> getRegister |> OprReg
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
  struct (ThreeOperands (rd, rt, mem), false, None)

(* <Rt>, <Rt2>, [<Rn>] *)
let oprRtRt2Mem bin =
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let rt2 = extract bin 11 8 |> getRegister |> OprReg
  let mem =
    memOffsetImm (extract bin 19 16 (* Rn *) |> getRegister, None, None)
  struct (ThreeOperands (rt, rt2, mem), false, None)

(* <Rt>, <Rt2>, [<Rn> {, #{+/-}<imm>}]
   <Rt>, <Rt2>, [<Rn>], #{+/-}<imm>
   <Rt>, <Rt2>, [<Rn>, #{+/-}<imm>]! *)
let oprRtRt2MemImm bin =
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let rt2 = extract bin 11 8 |> getRegister |> OprReg
  let mem =
    let rn = extract bin 19 16 |> getRegister
    let imm = extract bin 7 0 <<< 2 |> int64
    let sign = pickBit bin 23 |> getSign |> Some
    match concat (pickBit bin 24) (pickBit bin 21) 1 with
    | 0b10u -> memOffsetImm (rn, sign, Some imm)
    | 0b01u -> memPostIdxImm (rn, sign, Some imm)
    | 0b11u -> memPreIdxImm (rn, sign, Some imm)
    | _ (* 00 *) -> raise UnpredictableException
  struct (ThreeOperands (rt, rt2, mem), wbackW bin, None)

(* <Rd>, <Rt>, [<Rn> {, #<imm>}] *)
let oprRdRtMemImm bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let mem =
    let imm = extract bin 7 0 <<< 2 (* imm8:'00' *) |> int64
    memOffsetImm (extract bin 19 16 |> getRegister, None, Some imm)
  struct (ThreeOperands (rd, rt, mem), false, None)

(* <Rn>, <Rm>, RRX *)
(* <Rn>, <Rm> {, <shift> #<amount>} *)
let oprRnRmShf b =
  let rn = extract b 19 16 |> getRegister |> OprReg
  let rm = extract b 3 0 |> getRegister |> OprReg
  let struct (shift, amount) = (* stype, imm3:imm2 *)
    decodeImmShift (extract b 5 4) (concat (extract b 14 12) (extract b 7 6) 2)
  struct (ThreeOperands (rn, rm, OprShift (shift, Imm amount)), false, None)

(* <Rdm>, <Rdm>, Shift <Rs> *)
let oprRdmRdmShfRs bin shift =
  let rdm = extract bin 2 0 |> getRegister |> OprReg
  let shift = OprRegShift (shift, extract bin 5 3 |> getRegister (* Rs *))
  struct (ThreeOperands (rdm, rdm, shift), false, None)

(* <Rd>, <Rm>, <shift> <Rs> *)
let oprRdRmShfRs bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let rm = extract bin 19 16 |> getRegister |> OprReg
  let shift =
    let rs = extract bin 3 0 |> getRegister
    OprRegShift (decodeRegShift (extract bin 22 21 (* stype *)), rs)
  struct (ThreeOperands (rd, rm, shift), false, None)

(* {<Rd>,} <Rm> {, ROR #<amount>} *)
let oprRdRmROR bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let rm = extract bin 3 0 |> getRegister |> OprReg
  let shift = OprShift (SRType.SRTypeROR, extract bin 5 4 <<< 3 |> Imm)
  struct (ThreeOperands (rd, rm, shift), false, None)

(* {<Rd>,} <Rn>, #<const> *)
let oprRdRnConst bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let rn = extract bin 19 16 |> getRegister |> OprReg
  let imm12 (* i:imm3:imm8 *) =
    (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
  let cons = t32ExpandImm imm12 |> int64 |> OprImm
  struct (ThreeOperands (rd, rn, cons), false, None)

(* {<Rd>,} SP, #<const> *)
let oprRdSPConst bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let imm12 (* i:imm3:imm8 *) =
    (pickBit bin 26 <<< 11) + (extract bin 14 12 <<< 8) + (extract bin 7 0)
  let cons = t32ExpandImm imm12 |> int64 |> OprImm
  struct (ThreeOperands (rd, OprReg R.SP, cons), false, None)

(* <Rd>, #<imm>, <Rn> *)
let oprRdImmRn bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let imm = extract bin 3 0 (* sat_imm *) + 1u |> int64 |> OprImm
  let rn = extract bin 19 16 |> getRegister |> OprReg
  struct (ThreeOperands (rd, imm, rn), false, None)

(* <Rd>, #<imm>, <Rn> *)
let oprRdImmRnU bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let imm = extract bin 3 0 (* sat_imm *) |> int64 |> OprImm
  let rn = extract bin 19 16 |> getRegister |> OprReg
  struct (ThreeOperands (rd, imm, rn), false, None)

(* <Rd>, #<lsb>, #<width> *)
let oprRdLsbWidth bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let lsb = concat (extract bin 14 12) (extract bin 7 6) 2
  let width = (* msb - lsb + 1 *)
    (extract bin 4 0) - lsb + 1u |> int64 |> OprImm
  struct (ThreeOperands (rd, OprImm (int64 lsb), width), false, None)

(* {<Rd>,} <Rn>, <Rm>, RRX *)
(* {<Rd>,} <Rn>, <Rm> {, <shift> #<amount>} *)
let oprRdRnRmShf b =
  let rd = extract b 11 8 |> getRegister |> OprReg
  let rn = extract b 19 16 |> getRegister |> OprReg
  let rm = extract b 3 0 |> getRegister |> OprReg
  let struct (shift, amount) = (* stype, imm3:imm2 *)
    decodeImmShift (extract b 5 4) (concat (extract b 14 12) (extract b 7 6) 2)
  struct (FourOperands (rd, rn, rm, OprShift (shift, Imm amount)), false, None)

(* {<Rd>,} SP, <Rm>, RRX *)
(* {<Rd>,} SP, <Rm> {, <shift> #<amount>} *)
let oprRdSPRmShf b =
  let rd = extract b 11 8 |> getRegister |> OprReg
  let rm = extract b 3 0 |> getRegister |> OprReg
  let struct (shift, amount) = (* stype, imm3:imm2 *)
    decodeImmShift (extract b 5 4) (concat (extract b 14 12) (extract b 7 6) 2)
  let shf = OprShift (shift, Imm amount)
  struct (FourOperands (rd, OprReg R.SP, rm, shf), false, None)

(* <Rdm>, <Rdm>, LSL <Rs> *)
let oprRdmRdmLSLRs bin = oprRdmRdmShfRs bin SRTypeLSL

(* <Rdm>, <Rdm>, LSR <Rs> *)
let oprRdmRdmLSRRs bin = oprRdmRdmShfRs bin SRTypeLSR

(* <Rdm>, <Rdm>, ASR <Rs> *)
let oprRdmRdmASRRs bin = oprRdmRdmShfRs bin SRTypeASR

(* <Rdm>, <Rdm>, ROR <Rs> *)
let oprRdmRdmRORRs bin = oprRdmRdmShfRs bin SRTypeROR

(* {<Rd>,} <Rn>, <Rm> {, ROR #<amount>} *)
let oprRdRnRmROR bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let rn = extract bin 19 16 |> getRegister |> OprReg
  let rm = extract bin 3 0 |> getRegister |> OprReg
  let shift = OprShift (SRType.SRTypeROR, extract bin 5 4 <<< 3 |> Imm)
  struct (FourOperands (rd, rn, rm, shift), false, None)

(* <Rd>, <Rn>, <Rm>, <Ra> *)
let oprRdRnRmRa bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let rn = extract bin 19 16 |> getRegister |> OprReg
  let rm = extract bin 3 0 |> getRegister |> OprReg
  let ra = extract bin 15 12 |> getRegister |> OprReg
  struct (FourOperands (rd, rn, rm, ra), false, None)

(* <RdLo>, <RdHi>, <Rn>, <Rm> *)
let oprRdlRdhRnRm bin =
  let rdLo = extract bin 15 12 |> getRegister |> OprReg
  let rdHi = extract bin 11 8 |> getRegister |> OprReg
  let rn = extract bin 19 16 |> getRegister |> OprReg
  let rm = extract bin 3 0 |> getRegister |> OprReg
  struct (FourOperands (rdLo, rdHi, rn, rm), false, None)

(* <Rd>, <Rt>, <Rt2>, [<Rn>] *)
let oprRdRtRt2Mem bin =
  let rd = extract bin 3 0 |> getRegister |> OprReg
  let rt = extract bin 15 12 |> getRegister |> OprReg
  let rt2 = extract bin 11 8 |> getRegister |> OprReg
  let mem = memOffsetImm (extract bin 19 16 |> getRegister, None, None)
  struct (FourOperands (rd, rt, rt2, mem), false, None)

(* <Rd>, #<imm>, <Rn>, ASR #<amount> *)
(* <Rd>, #<imm>, <Rn>, LSL #<amount> *)
let oprRdImmRnShf bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let imm = extract bin 4 0 (* sat_imm *) + 1u |> int64 |> OprImm
  let rn = extract bin 19 16 |> getRegister |> OprReg
  let imm5 (* imm3:imm2 *) = concat (extract bin 14 12) (extract bin 7 6) 2
  let struct (sTyp, amount) (* sh:'0' *) =
    decodeImmShift (extract bin 21 20) imm5
  struct (FourOperands (rd, imm, rn, OprShift (sTyp, Imm amount)), false, None)

(* <Rd>, #<imm>, <Rn>, ASR #<amount> *)
(* <Rd>, #<imm>, <Rn>, LSL #<amount> *)
let oprRdImmRnShfU bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let imm = extract bin 4 0 (* sat_imm *) |> int64 |> OprImm
  let rn = extract bin 19 16 |> getRegister |> OprReg
  let imm5 (* imm3:imm2 *) = concat (extract bin 14 12) (extract bin 7 6) 2
  let struct (sTyp, amount) (* sh:'0' *) =
    decodeImmShift (extract bin 21 20) imm5
  struct (FourOperands (rd, imm, rn, OprShift (sTyp, Imm amount)), false, None)

(* <Rd>, <Rn>, #<lsb>, #<width> *)
let oprRdRnLsbWidth bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let rn = extract bin 19 16 |> getRegister |> OprReg
  let lsb (* imm3:imm2 *) =
    concat (extract bin 14 12) (extract bin 7 6) 2
  let width = (* msb - lsb + 1 *)
    (extract bin 4 0) - lsb + 1u |> int64 |> OprImm
  struct (FourOperands (rd, rn, OprImm (int64 lsb), width), false, None)

(* <Rd>, <Rn>, #<lsb>, #<width> *)
let oprRdRnLsbWidthM1 bin =
  let rd = extract bin 11 8 |> getRegister |> OprReg
  let rn = extract bin 19 16 |> getRegister |> OprReg
  let lsb (* imm3:imm2 *) =
    concat (extract bin 14 12) (extract bin 7 6) 2 |> int64 |> OprImm
  let width (* widthm1 + 1 *) =
    (extract bin 4 0 (* widthm1 *)) + 1u |> int64 |> OprImm
  struct (FourOperands (rd, rn, lsb, width), false, None)

type bl = byte list

let render (itstate: byref<bl>) it isInIT mode addr bin len cond op dt q fnOpr =
  let struct (oprs, wback, cflag) = fnOpr bin
  let cond =
    match cond with
    | Some cond -> cond
    | None -> Condition.UN // FIXME
  if isInIT then updateITSTATE &itstate else ()
  newInsInfo mode addr len cond op oprs (byte it) wback q dt cflag

/// Add, subtract (three low registers) on page F3-4153.
let parseAddSubThreeLowReg (itstate: byref<bl>) isInIT mode addr bin len cond =
  match pickBit bin 9 (* S *) with
  | 0b0u ->
    let opcode = if inITBlock itstate then Op.ADD else Op.ADDS
    render &itstate 0 isInIT mode addr bin len cond opcode None N oprRdRnRmT16
  | _ (* 1 *) ->
    let opcode = if inITBlock itstate then Op.SUB else Op.SUBS
    render &itstate 0 isInIT mode addr bin len cond opcode None N oprRdRnRmT16

/// Add, subtract (two low registers and immediate) on page F3-4153.
let parseAddSubTwoLRegsImm (itstate: byref<bl>) isInIT mode addr bin len cond =
  match pickBit bin 9 (* S *) with
  | 0b0u ->
    let opcode = if inITBlock itstate then Op.ADD else Op.ADDS
    render &itstate 0 isInIT mode addr bin len cond opcode None N oprRdRnImm3
  | _ (* 1 *) ->
    let opcode = if inITBlock itstate then Op.SUB else Op.SUBS
    render &itstate 0 isInIT mode addr bin len cond opcode None N oprRdRnImm3

/// Add, subtract, compare, move (one low register and imm) on page F3-4153.
let parseAddSubCmpMov (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 12 11 (* op *) with
  | 0b00u ->
    let opcode = if inITBlock itstate then Op.MOV else Op.MOVS
    render &itstate 0 isInIT mode addr bin len cond opcode None N oprRdImm8
  | 0b01u ->
    render &itstate 0 isInIT mode addr bin len cond Op.CMP None N oprRdImm8
  | 0b10u ->
    let opcode = if inITBlock itstate then Op.ADD else Op.ADDS
    render &itstate 0 isInIT mode addr bin len cond opcode None N oprRdnImm8
  | _ (* 11 *) ->
    let opcode = if inITBlock itstate then Op.SUB else Op.SUBS
    render &itstate 0 isInIT mode addr bin len cond opcode None N oprRdnImm8

/// Shift (immediate), add, subtract, move, and compare on page F3-4152.
let parseShfImmAddSubMovCmp (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 13 10 (* op0:op1:op2 *) with
  | 0b0110u (* 0110 *) ->
    parseAddSubThreeLowReg &itstate isInIT mode addr bin len cond
  | 0b0111u (* 0111 *) ->
    parseAddSubTwoLRegsImm &itstate isInIT mode addr bin len cond
  | 0b0000u | 0b0001u | 0b0010u | 0b0011u | 0b0100u | 0b0101u (* 0 !=11 x *) ->
    let op = extract bin 12 11
    let imm5 = extract bin 10 6
    let inITBlock = inITBlock itstate
    checkUnpred (op = 0b00u && imm5 = 0u && inITBlock)
    /// Alias conditions on page F5-4557.
    let struct (opcode, operands) =
      if op = 0b10u && not inITBlock then struct (Op.ASRS, oprRdRmImm)
      elif op = 0b10u && inITBlock then struct (Op.ASR, oprRdRmImm)
      elif op = 0b00u && imm5 <> 0u && not inITBlock then (Op.LSLS, oprRdRmImm)
      elif op = 0b00u && imm5 <> 0u && inITBlock then (Op.LSL, oprRdRmImm)
      elif op = 0b01u && not inITBlock then (Op.LSRS, oprRdRmImm)
      elif op = 0b01u && inITBlock then (Op.LSR, oprRdRmImm)
      else if inITBlock then struct (Op.MOV, oprRdRmShfT16)
           else struct (Op.MOVS, oprRdRmShfT16)
    render &itstate 0 isInIT mode addr bin len cond opcode None N operands
  | _ (* 1xxx *) -> parseAddSubCmpMov &itstate isInIT mode addr bin len cond

/// Data-processing (two low registers) on page F3-4149.
let parseDataProc (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 9 6 (* op *) with
  | 0b0000u ->
    let op = if inITBlock itstate then Op.AND else Op.ANDS
    render &itstate 0 isInIT mode addr bin len cond op None N oprRdnRdnRm
  | 0b0001u ->
    let op = if inITBlock itstate then Op.EOR else Op.EORS
    render &itstate 0 isInIT mode addr bin len cond op None N oprRdnRdnRm
  | 0b0010u ->
    let op = if inITBlock itstate then Op.MOV else Op.MOVS
    render &itstate 0 isInIT mode addr bin len cond op None N oprRdmRdmLSLRs
  | 0b0011u ->
    let op = if inITBlock itstate then Op.MOV else Op.MOVS
    render &itstate 0 isInIT mode addr bin len cond op None N oprRdmRdmLSRRs
  | 0b0100u ->
    let op = if inITBlock itstate then Op.MOV else Op.MOVS
    render &itstate 0 isInIT mode addr bin len cond op None N oprRdmRdmASRRs
  | 0b0101u ->
    let op = if inITBlock itstate then Op.ADC else Op.ADCS
    render &itstate 0 isInIT mode addr bin len cond op None N oprRdnRdnRm
  | 0b0110u ->
    let op = if inITBlock itstate then Op.SBC else Op.SBCS
    render &itstate 0 isInIT mode addr bin len cond op None N oprRdnRdnRm
  | 0b0111u ->
    let op = if inITBlock itstate then Op.MOV else Op.MOVS
    render &itstate 0 isInIT mode addr bin len cond op None N oprRdmRdmRORRs
  | 0b1000u ->
    render &itstate 0 isInIT mode addr bin len cond Op.TST None N oprRnRm
  | 0b1001u ->
    let op = if inITBlock itstate then Op.RSB else Op.RSBS
    render &itstate 0 isInIT mode addr bin len cond op None N oprRdRn0
  | 0b1010u ->
    render &itstate 0 isInIT mode addr bin len cond Op.CMP None N oprRnRm
  | 0b1011u ->
    render &itstate 0 isInIT mode addr bin len cond Op.CMN None N oprRnRm
  | 0b1100u ->
    let op = if inITBlock itstate then Op.ORR else Op.ORRS
    render &itstate 0 isInIT mode addr bin len cond op None N oprRdnRdnRm
  | 0b1101u ->
    let op = if inITBlock itstate then Op.MUL else Op.MULS
    render &itstate 0 isInIT mode addr bin len cond op None N oprRdmRnRdm
  | 0b1110u ->
    let op = if inITBlock itstate then Op.BIC else Op.BICS
    render &itstate 0 isInIT mode addr bin len cond op None N oprRdnRdnRm
  | _ (* 1111 *) ->
    let op = if inITBlock itstate then Op.MVN else Op.MVNS
    render &itstate 0 isInIT mode addr bin len cond op None N oprRdRmT16

/// Branch and exchange on page F3-4154.
let parseBranchAndExchange (itstate: byref<bl>) isInIT mode addr bin len cond =
  match pickBit bin 7 (* L *) with
  | 0b0u ->
    chkInITLastIT itstate
    render &itstate 0 isInIT mode addr bin len cond Op.BX None N oprRm16
  | _ (* 1 *) ->
    chkPCRmIT16 bin itstate
    render &itstate 0 isInIT mode addr bin len cond Op.BLX None N oprRm16

/// Add, subtract, compare, move (two high registers) on page F3-4154.
let parseAddSubCmpMovTwoHRegs (itstate: byref<bl>) isInIT mode addr bin len c =
  let isDRd1101 = concat (pickBit bin 7) (extract bin 2 0) 3 = 0b1101u
  let isRs1101 = extract bin 6 3 = 0b1101u
  match extract bin 9 8 (* op *) with
  | 0b00u when not isDRd1101 && not isRs1101 ->
    chkPCRnRmRdIT bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.ADD None N oprRdnRm
  | 0b00u when isRs1101 ->
    chkPCRdIT bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.ADD None N oprRdmSPRdm
  | 0b00u when isDRd1101 && not isRs1101 ->
    render &itstate 0 isInIT mode addr bin len c Op.ADD None N oprSPSPRm
  | 0b01u ->
    chkNMPCRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.CMP None N oprRnRmExt
  | 0b10u ->
    chkPCDRdIT bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.MOV None N oprRdRmExt
  | _ -> Utils.impossible ()

/// Special data instructions and branch and exchange on page F3-4154.
let parseSpecDataInsBrXchg (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 9 8 (* op0 *) with
  | 0b11u -> parseBranchAndExchange &itstate isInIT mode addr bin len cond
  | _ (* != 11 *) ->
    parseAddSubCmpMovTwoHRegs &itstate isInIT mode addr bin len cond

/// Load/store (register offset) on page F3-4150.
let parseLoadStoreRegOffset (itstate: byref<bl>) isInIT mode addr bin len c =
  match extract bin 11 9 (* L:B:H *) with
  | 0b000u ->
    render &itstate 0 isInIT mode addr bin len c Op.STR None N oprRtMemReg16
  | 0b001u ->
    render &itstate 0 isInIT mode addr bin len c Op.STRH None N oprRtMemReg16
  | 0b010u ->
    render &itstate 0 isInIT mode addr bin len c Op.STRB None N oprRtMemReg16
  | 0b011u ->
    render &itstate 0 isInIT mode addr bin len c Op.LDRSB None N oprRtMemReg16
  | 0b100u ->
    render &itstate 0 isInIT mode addr bin len c Op.LDR None N oprRtMemReg16
  | 0b101u ->
    render &itstate 0 isInIT mode addr bin len c Op.LDRH None N oprRtMemReg16
  | 0b110u ->
    render &itstate 0 isInIT mode addr bin len c Op.LDRB None N oprRtMemReg16
  | _ (* 111 *) ->
    render &itstate 0 isInIT mode addr bin len c Op.LDRSH None N oprRtMemReg16

/// Load/store word/byte (immediate offset) on page F3-4150.
let parseLdStWordByteImmOff (itstate: byref<bl>) isInIT mode addr bin len c =
  match extract bin 12 11 (* B:L *) with
  | 0b00u ->
    render &itstate 0 isInIT mode addr bin len c Op.STR None N oprRtMemImm2
  | 0b01u ->
    render &itstate 0 isInIT mode addr bin len c Op.LDR None N oprRtMemImm2
  | 0b10u ->
    render &itstate 0 isInIT mode addr bin len c Op.STRB None N oprRtMemImm0
  | _ (* 11 *) ->
    render &itstate 0 isInIT mode addr bin len c Op.LDRB None N oprRtMemImm0

/// Load/store halfword (immediate offset) on page F3-4151.
let parseLdStHalfwordImmOff (itstate: byref<bl>) isInIT mode addr bin len c =
  match pickBit bin 11 (* L *) with
  | 0b0u ->
    render &itstate 0 isInIT mode addr bin len c Op.STRH None N oprRtMemImm1
  | _ (* 1 *) ->
    render &itstate 0 isInIT mode addr bin len c Op.LDRH None N oprRtMemImm1

/// Load/store (SP-relative) on page F3-4151.
let parseLdStSPRelative (itstate: byref<bl>) isInIT mode addr bin len cond =
  match pickBit bin 11 (* L *) with
  | 0b0u ->
    render &itstate 0 isInIT mode addr bin len cond Op.STR None N oprRtMemSP
  | _ (* 1 *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.LDR None N oprRtMemSP

/// Add PC/SP (immediate) on page F3-4151.
let parseAddPCSPImm (itstate: byref<bl>) isInIT mode addr bin len cond =
  match pickBit bin 11 (* SP *) with
  | 0b0u ->
    render &itstate 0 isInIT mode addr bin len cond Op.ADR None N oprRtLabel
  | _ (* 1 *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.ADD None N oprRdSPImm8

/// Adjust SP (immediate) on page F3-4156.
let parseAdjustSPImm (itstate: byref<bl>) isInIT mode addr bin len cond =
  match pickBit bin 7 (* S *) with
  | 0b0u ->
    render &itstate 0 isInIT mode addr bin len cond Op.ADD None N oprSPSPImm7
  | _ (* 1 *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.SUB None N oprSPSPImm7

/// Extend on page F3-4156.
let parseExtend (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 7 6 (* U:B *) with
  | 0b00u ->
    render &itstate 0 isInIT mode addr bin len cond Op.SXTH None N oprRdRmT16
  | 0b01u ->
    render &itstate 0 isInIT mode addr bin len cond Op.SXTB None N oprRdRmT16
  | 0b10u ->
    render &itstate 0 isInIT mode addr bin len cond Op.UXTH None N oprRdRmT16
  | _ (* 11 *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.UXTB None N oprRdRmT16

/// Change Processor State on page F3-4156.
let parseChgProcessorState (itstate: byref<bl>) isInIT mode addr bin len cond =
  match pickBit bin 5 (* op *) with
  | 0b0u ->
    inITBlock itstate |> checkUnpred
    render &itstate 0 isInIT mode addr bin len cond Op.SETEND None N oprEndian
  | _ (* 1 *) ->
    chkAIFIT bin itstate
    let opcode = if pickBit bin 4 = 1u then Op.CPSID else Op.CPSIE
    render &itstate 0 isInIT mode addr bin len cond opcode None N oprIflags

/// Miscellaneous 16-bit instructions on page F3-4155.
let parseMisc16BitInstr0110 (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 7 5 (* op1:op2 *) with
  | 0b000u -> (* Armv8.1 *)
    inITBlock itstate |> checkUnpred
    render &itstate 0 isInIT mode addr bin len cond Op.SETPAN None N oprImm
  | 0b001u -> raise UnallocatedException
  | 0b010u | 0b011u ->
    parseChgProcessorState &itstate isInIT mode addr bin len cond
  | _ (* 1xx *) -> raise UnallocatedException

/// Reverse bytes on page F3-4157.
let parseReverseBytes (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 7 6 (* op *) with
  | 0b00u ->
    render &itstate 0 isInIT mode addr bin len cond Op.REV None N oprRdRmT16
  | 0b01u ->
    render &itstate 0 isInIT mode addr bin len cond Op.REV16 None N oprRdRmT16
  | 0b11u ->
    render &itstate 0 isInIT mode addr bin len cond Op.REVSH None N oprRdRmT16
  | _ (* 10 *) -> Utils.impossible ()

/// Hints on page F3-4157.
let parseHints16 (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 7 4 (* hint *) with
  | 0b0000u ->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None N oprNo
  | 0b0001u ->
    render &itstate 0 isInIT mode addr bin len cond Op.YIELD None N oprNo
  | 0b0010u ->
    render &itstate 0 isInIT mode addr bin len cond Op.WFE None N oprNo
  | 0b0011u ->
    render &itstate 0 isInIT mode addr bin len cond Op.WFI None N oprNo
  | 0b0100u ->
    render &itstate 0 isInIT mode addr bin len cond Op.SEV None N oprNo
  | 0b0101u ->
    render &itstate 0 isInIT mode addr bin len cond Op.SEVL None N oprNo
  | _ (* 011x | 1xxx *) -> (* Reserved hint, behaves as NOP *)
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None N oprNo

/// Push and Pop on page F3-4158.
let parsePushAndPop (itstate: byref<bl>) isInIT mode addr bin len cond =
  match pickBit bin 11 (* L *) with
  | 0b0u ->
    concat (pickBit bin 8 <<< 6) (extract bin 7 0) 8 (* registers *) = 0u
    |> checkUnpred
    render &itstate 0 isInIT mode addr bin len cond Op.PUSH None N oprRegsM
  | _ (* 1 *) ->
    chkRegsIT bin itstate
    render &itstate 0 isInIT mode addr bin len cond Op.POP None N oprRegsP

/// Miscellaneous 16-bit instructions on page F3-4155.
let parseMisc16BitInstr (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 11 8 (* op0 *) with
  | 0b0000u -> parseAdjustSPImm &itstate isInIT mode addr bin len cond
  | 0b0010u -> parseExtend &itstate isInIT mode addr bin len cond
  | 0b0110u -> parseMisc16BitInstr0110 &itstate isInIT mode addr bin len cond
  | 0b0111u -> raise UnallocatedException
  | 0b1000u -> raise UnallocatedException
  | 0b1010u when extract bin 7 6 = 0b10u ->
    render &itstate 0 isInIT mode addr bin len cond Op.HLT None N oprImm6
  | 0b1010u (* != 10 *) ->
    parseReverseBytes &itstate isInIT mode addr bin len cond
  | 0b1110u ->
    render &itstate 0 isInIT mode addr bin len cond Op.BKPT None N oprImm8
  | 0b1111u when extract bin 3 0 = 0b0000u ->
    parseHints16 &itstate isInIT mode addr bin len cond
  | 0b1111u (* != 0000 *) ->
    chkFstCondIT bin itstate
    let struct (fstCond, mask) = struct (extract bin 7 4, extract bin 3 0)
    let op, itstate' = getIT (pickBit fstCond 0) (byte fstCond) mask
    itstate <- itstate'
    render &itstate (int bin) isInIT mode addr bin len cond op None N oprCond
  | 0b1001u | 0b1011u ->
    inITBlock itstate |> checkUnpred
    render &itstate 0 isInIT mode addr bin len None Op.CBNZ None N oprRnLabel
  | 0b0001u | 0b0011u ->
    inITBlock itstate |> checkUnpred
    render &itstate 0 isInIT mode addr bin len None Op.CBZ None N oprRnLabel
  | _ (* x10x *) -> parsePushAndPop &itstate isInIT mode addr bin len cond

/// Load/store multiple on page F3-4152.
let parseLoadStoreMul (itstate: byref<bl>) isInIT mode addr bin len cond =
  match pickBit bin 11 (* L *) with
  | 0b0u ->
    extract bin 7 0 (* register_list *) = 0u |> checkUnpred
    render &itstate 0 isInIT mode addr bin len cond Op.STMIA None N oprRnRegs
  | _ (* 1 *) ->
    extract bin 7 0 (* register_list *) = 0u |> checkUnpred
    render &itstate 0 isInIT mode addr bin len cond Op.LDMIA None N oprRnRegsW

/// Exception generation on page F3-4158.
let parseExceptionGen (itstate: byref<bl>) isInIT mode addr bin len cond =
  match pickBit bin 8 (* S *) with
  | 0b0u ->
    render &itstate 0 isInIT mode addr bin len cond Op.UDF None N oprImm8
  | _ (* 1 *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.SVC None N oprImm8

/// Conditional branch, and Supervisor Call on page F3-4158.
let parseCondBrSVCall (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 11 8 (* op0 *) with
  | 0b1110u | 0b1111u ->
    parseExceptionGen &itstate isInIT mode addr bin len cond
  | _ (* != 111x *) ->
    inITBlock itstate |> checkUnpred
    let cond = extract bin 11 8 |> byte |> parseCond |> Some
    render &itstate 0 isInIT mode addr bin len cond Op.B None N oprLabel8

/// 16-bit on page F3-4148.
let parse16Bit (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 15 10 (* op0 *) with
  | b when b &&& 0b110000u = 0b000000u (* 00xxxx *) ->
    parseShfImmAddSubMovCmp &itstate isInIT mode addr bin len cond
  | 0b010000u -> parseDataProc &itstate isInIT mode addr bin len cond
  | 0b010001u ->
    parseSpecDataInsBrXchg &itstate isInIT mode addr bin len cond
  | 0b010010u | 0b010011u (* 01001x *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.LDR None N oprRtLabel
  | 0b010100u | 0b010101u | 0b010110u | 0b010111u (* 0101xx *) ->
    parseLoadStoreRegOffset &itstate isInIT mode addr bin len cond
  | b when b &&& 0b111000u = 0b011000u (* 011xxx *) ->
    parseLdStWordByteImmOff &itstate isInIT mode addr bin len cond
  | 0b100000u| 0b100001u | 0b100010u | 0b100011u (* 1000xx *) ->
    parseLdStHalfwordImmOff &itstate isInIT mode addr bin len cond
  | 0b100100u| 0b100101u | 0b100110u | 0b100111u (* 1001xx *) ->
    parseLdStSPRelative &itstate isInIT mode addr bin len cond
  | 0b101000u| 0b101001u | 0b101010u | 0b101011u (* 1010xx *) ->
    parseAddPCSPImm &itstate isInIT mode addr bin len cond
  | 0b101100u| 0b101101u | 0b101110u | 0b101111u (* 1011xx *) ->
    parseMisc16BitInstr &itstate isInIT mode addr bin len cond
  | 0b110000u| 0b110001u | 0b110010u | 0b110011u (* 1100xx *) ->
    parseLoadStoreMul &itstate isInIT mode addr bin len cond
  | 0b110100u| 0b110101u | 0b110110u | 0b110111u (* 1101xx *) ->
    parseCondBrSVCall &itstate isInIT mode addr bin len cond
  | _ -> Utils.impossible ()

/// Advanced SIMD three registers of the same length on page F3-4165.
let parseAdvSIMDThreeRegsOfSameLen (itstate: byref<bl>) isIn m a b l c =
  let decodeFields (* U:size:opc:Q:o1 *) =
    (pickBit b 28 <<< 8) + (extract b 21 20 <<< 6) + (extract b 11 8 <<< 2) +
    (pickBit b 6 <<< 1) + pickBit b 4
  match decodeFields with
  (* VFMA 00x1100x1 *)
  | 0b000110001u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VFMA (oneDt SIMDTypF32) N oprDdDnDm
  | 0b000110011u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VFMA (oneDt SIMDTypF32) N oprQdQnQm
  | 0b001110001u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VFMA (oneDt SIMDTypF16) N oprDdDnDm
  | 0b001110011u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VFMA (oneDt SIMDTypF16) N oprQdQnQm
  (* VADD 00x1101x0 *)
  | 0b000110100u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VADD (oneDt SIMDTypF32) N oprDdDnDm
  | 0b000110110u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VADD (oneDt SIMDTypF32) N oprQdQnQm
  | 0b001110100u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VADD (oneDt SIMDTypF16) N oprDdDnDm
  | 0b001110110u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VADD (oneDt SIMDTypF16) N oprQdQnQm
  (* VMLA 00x1101x1 *)
  | 0b000110101u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMLA (oneDt SIMDTypF32) N oprDdDnDm
  | 0b000110111u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMLA (oneDt SIMDTypF32) N oprQdQnQm
  | 0b001110101u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMLA (oneDt SIMDTypF16) N oprDdDnDm
  | 0b001110111u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMLA (oneDt SIMDTypF16) N oprQdQnQm
  (* VCEQ 00x1110x0 *)
  | 0b000111000u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VCEQ (oneDt SIMDTypF32) N oprDdDnDm
  | 0b000111010u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VCEQ (oneDt SIMDTypF32) N oprQdQnQm
  | 0b001111000u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VCEQ (oneDt SIMDTypF16) N oprDdDnDm
  | 0b001111010u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VCEQ (oneDt SIMDTypF16) N oprQdQnQm
  (* VMAX 00x1111x0 *)
  | 0b000111100u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypF32) N oprDdDnDm
  | 0b000111110u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypF32) N oprQdQnQm
  | 0b001111100u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypF16) N oprDdDnDm
  | 0b001111110u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypF16) N oprQdQnQm
  (* VRECPS 00x1111x1 *)
  | 0b000111101u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VRECPS (oneDt SIMDTypF32) N oprDdDnDm
  | 0b000111111u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VRECPS (oneDt SIMDTypF32) N oprQdQnQm
  | 0b001111101u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VRECPS (oneDt SIMDTypF16) N oprDdDnDm
  | 0b001111111u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VRECPS (oneDt SIMDTypF16) N oprQdQnQm
  (* VHADD xxx0000x0 *)
  | 0b011000000u | 0b011000010u | 0b111000000u | 0b111000010u (* x110000x0 *) ->
    raise UndefinedException
  | 0b000000000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHADD (oneDt SIMDTypS8) N oprDdDnDm
  | 0b001000000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHADD (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010000000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHADD (oneDt SIMDTypS32) N oprDdDnDm
  | 0b100000000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHADD (oneDt SIMDTypU8) N oprDdDnDm
  | 0b101000000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHADD (oneDt SIMDTypU16) N oprDdDnDm
  | 0b110000000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHADD (oneDt SIMDTypU32) N oprDdDnDm
  | 0b000000010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHADD (oneDt SIMDTypS8) N oprQdQnQm
  | 0b001000010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHADD (oneDt SIMDTypS16) N oprQdQnQm
  | 0b010000010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHADD (oneDt SIMDTypS32) N oprQdQnQm
  | 0b100000010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHADD (oneDt SIMDTypU8) N oprQdQnQm
  | 0b101000010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHADD (oneDt SIMDTypU16) N oprQdQnQm
  | 0b110000010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHADD (oneDt SIMDTypU32) N oprQdQnQm
  (* VAND 0000001x1 *)
  | 0b000000101u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VAND None N oprDdDnDm
  | 0b000000111u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VAND None N oprQdQnQm
  (* VQADD xxx0000x1 *)
  | 0b000000001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypS8 ) N oprDdDnDm
  | 0b001000001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010000001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypS32) N oprDdDnDm
  | 0b011000001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypS64) N oprDdDnDm
  | 0b100000001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypU8 ) N oprDdDnDm
  | 0b101000001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypU16) N oprDdDnDm
  | 0b110000001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypU32) N oprDdDnDm
  | 0b111000001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypU64) N oprDdDnDm
  | 0b000000011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypS8 ) N oprQdQnQm
  | 0b001000011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypS16) N oprQdQnQm
  | 0b010000011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypS32) N oprQdQnQm
  | 0b011000011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypS64) N oprQdQnQm
  | 0b100000011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypU8 ) N oprQdQnQm
  | 0b101000011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypU16) N oprQdQnQm
  | 0b110000011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypU32) N oprQdQnQm
  | 0b111000011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQADD (oneDt SIMDTypU64) N oprQdQnQm
  (* VRHADD xxx0001x0 *)
  | 0b011000100u | 0b011000110u | 0b111000100u | 0b111000110u (* x110001x *) ->
    raise UndefinedException
  | 0b000000100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRHADD (oneDt SIMDTypS8) N oprDdDnDm
  | 0b001000100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRHADD (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010000100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRHADD (oneDt SIMDTypS32) N oprDdDnDm
  | 0b100000100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRHADD (oneDt SIMDTypU8) N oprDdDnDm
  | 0b101000100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRHADD (oneDt SIMDTypU16) N oprDdDnDm
  | 0b110000100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRHADD (oneDt SIMDTypU32) N oprDdDnDm
  | 0b000000110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRHADD (oneDt SIMDTypS8) N oprQdQnQm
  | 0b001000110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRHADD (oneDt SIMDTypS16) N oprQdQnQm
  | 0b010000110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRHADD (oneDt SIMDTypS32) N oprQdQnQm
  | 0b100000110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRHADD (oneDt SIMDTypU8) N oprQdQnQm
  | 0b101000110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRHADD (oneDt SIMDTypU16) N oprQdQnQm
  | 0b110000110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRHADD (oneDt SIMDTypU32) N oprQdQnQm
  (* SHA1C 0001100x0 *)
  | 0b000110000u (* Q != 1 *) -> raise UndefinedException
  | 0b000110010u ->
    chkITVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.SHA1C (oneDt SIMDTyp32) N oprQdQnQm
  (* VHSUB xxx0010x0 *)
  | 0b011001000u | 0b011001010u | 0b111001000u | 0b111001010u (* x110010x0 *) ->
    raise UndefinedException
  | 0b000001000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHSUB (oneDt SIMDTypS8) N oprDdDnDm
  | 0b001001000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHSUB (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010001000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHSUB (oneDt SIMDTypS32) N oprDdDnDm
  | 0b100001000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHSUB (oneDt SIMDTypU8) N oprDdDnDm
  | 0b101001000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHSUB (oneDt SIMDTypU16) N oprDdDnDm
  | 0b110001000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHSUB (oneDt SIMDTypU32) N oprDdDnDm
  | 0b000001010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHSUB (oneDt SIMDTypS8) N oprQdQnQm
  | 0b001001010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHSUB (oneDt SIMDTypS16) N oprQdQnQm
  | 0b010001010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHSUB (oneDt SIMDTypS32) N oprQdQnQm
  | 0b100001010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHSUB (oneDt SIMDTypU8) N oprQdQnQm
  | 0b101001010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHSUB (oneDt SIMDTypU16) N oprQdQnQm
  | 0b110001010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VHSUB (oneDt SIMDTypU32) N oprQdQnQm
  (* VBIC 0010001x1 *)
  | 0b001000101u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VBIC None N oprDdDnDm
  | 0b001000111u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VBIC None N oprQdQnQm
  (* VQSUB xxx0010x1 *)
  | 0b000001001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypS8) N oprDdDnDm
  | 0b001001001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010001001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypS32) N oprDdDnDm
  | 0b011001001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypS64) N oprDdDnDm
  | 0b100001001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypU8) N oprDdDnDm
  | 0b101001001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypU16) N oprDdDnDm
  | 0b110001001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypU32) N oprDdDnDm
  | 0b111001001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypU64) N oprDdDnDm
  | 0b000001011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypS8) N oprQdQnQm
  | 0b001001011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypS16) N oprQdQnQm
  | 0b010001011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypS32) N oprQdQnQm
  | 0b011001011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypS64) N oprQdQnQm
  | 0b100001011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypU8) N oprQdQnQm
  | 0b101001011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypU16) N oprQdQnQm
  | 0b110001011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypU32) N oprQdQnQm
  | 0b111001011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSUB (oneDt SIMDTypU64) N oprQdQnQm
  (* VCGT xxx0011x0 *)
  | 0b011001100u | 0b011001110u | 0b111001100u | 0b111001110u (* x110011x0 *) ->
    raise UndefinedException
  | 0b000001100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypS8) N oprDdDnDm
  | 0b001001100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010001100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypS32) N oprDdDnDm
  | 0b100001100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypU8) N oprDdDnDm
  | 0b101001100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypU16) N oprDdDnDm
  | 0b110001100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypU32) N oprDdDnDm
  | 0b000001110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypS8) N oprQdQnQm
  | 0b001001110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypS16) N oprQdQnQm
  | 0b010001110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypS32) N oprQdQnQm
  | 0b100001110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypU8) N oprQdQnQm
  | 0b101001110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypU16) N oprQdQnQm
  | 0b110001110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypU32) N oprQdQnQm
  (* VCGE xxx0011x1 *)
  | 0b011001101u | 0b011001111u | 0b111001101u | 0b111001111u (* xxx0011x1 *) ->
    raise UndefinedException
  | 0b000001101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypS8) N oprDdDnDm
  | 0b001001101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010001101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypS32) N oprDdDnDm
  | 0b100001101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypU8) N oprDdDnDm
  | 0b101001101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypU16) N oprDdDnDm
  | 0b110001101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypU32) N oprDdDnDm
  | 0b000001111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypS8) N oprQdQnQm
  | 0b001001111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypS16) N oprQdQnQm
  | 0b010001111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypS32) N oprQdQnQm
  | 0b100001111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypU8) N oprQdQnQm
  | 0b101001111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypU16) N oprQdQnQm
  | 0b110001111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypU32) N oprQdQnQm
  (* SHA1P 0011100x0 *)
  | 0b001110000u (* Q != 1 *) -> raise UndefinedException
  | 0b001110010u ->
    chkITVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.SHA1P (oneDt SIMDTyp32) N oprQdQnQm
  (* VFMS 01x1100x1 *)
  | 0b010110001u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VFMS (oneDt SIMDTypF32) N oprDdDnDm
  | 0b010110011u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VFMS (oneDt SIMDTypF32) N oprQdQnQm
  | 0b011110001u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VFMS (oneDt SIMDTypF16) N oprDdDnDm
  | 0b011110011u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VFMS (oneDt SIMDTypF16) N oprQdQnQm
  (* VSUB 01x1101x0 *)
  | 0b010110100u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VSUB (oneDt SIMDTypF32) N oprDdDnDm
  | 0b010110110u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VSUB (oneDt SIMDTypF32) N oprQdQnQm
  | 0b011110100u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VSUB (oneDt SIMDTypF16) N oprDdDnDm
  | 0b011110110u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VSUB (oneDt SIMDTypF16) N oprQdQnQm
  (* VMLS 01x1101x1 *)
  | 0b010110101u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMLS (oneDt SIMDTypF32) N oprDdDnDm
  | 0b010110111u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMLS (oneDt SIMDTypF32) N oprDdDnDm
  | 0b011110101u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMLS (oneDt SIMDTypF16) N oprQdQnQm
  | 0b011110111u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMLS (oneDt SIMDTypF16) N oprQdQnQm
  | b when b &&& 0b110111101u = 0b010111000u (* 0b01x1110x0u *) ->
    raise UnallocatedException
  (* VMIN 01x1111x0 *)
  | 0b010111100u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypF32) N oprDdDnDm
  | 0b010111110u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypF32) N oprDdDnDm
  | 0b011111100u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypF16) N oprQdQnQm
  | 0b011111110u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypF16) N oprQdQnQm
  (* VRSQRTS 01x1111x1 *)
  | 0b010111101u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VRSQRTS (oneDt SIMDTypF32) N oprDdDnDm
  | 0b010111111u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VRSQRTS (oneDt SIMDTypF32) N oprDdDnDm
  | 0b011111101u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VRSQRTS (oneDt SIMDTypF32) N oprDdDnDm
  | 0b011111111u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VRSQRTS (oneDt SIMDTypF32) N oprDdDnDm
  (* VSHL xxx0100x0 *)
  | 0b000010000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypS8) N oprDdDmDn
  | 0b001010000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypS16) N oprDdDmDn
  | 0b010010000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypS32) N oprDdDmDn
  | 0b011010000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypS64) N oprDdDmDn
  | 0b100010000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypU8) N oprDdDmDn
  | 0b101010000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypU16) N oprDdDmDn
  | 0b110010000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypU32) N oprDdDmDn
  | 0b111010000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypU64) N oprDdDmDn
  | 0b000010010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypS8) N oprQdQmQn
  | 0b001010010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypS16) N oprQdQmQn
  | 0b010010010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypS32) N oprQdQmQn
  | 0b011010010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypS64) N oprQdQmQn
  | 0b100010010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypU8) N oprQdQmQn
  | 0b101010010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypU16) N oprQdQmQn
  | 0b110010010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypU32) N oprQdQmQn
  | 0b111010010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSHL (oneDt SIMDTypU64) N oprQdQmQn
  (* VADD 0xx1000x0 *)
  | 0b000100000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VADD (oneDt SIMDTypI8)  N oprDdDnDm
  | 0b001100000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VADD (oneDt SIMDTypI16) N oprDdDnDm
  | 0b010100000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VADD (oneDt SIMDTypI32) N oprDdDnDm
  | 0b011100000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VADD (oneDt SIMDTypI64) N oprDdDnDm
  | 0b000100010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VADD (oneDt SIMDTypI8)  N oprQdQnQm
  | 0b001100010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VADD (oneDt SIMDTypI16) N oprQdQnQm
  | 0b010100010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VADD (oneDt SIMDTypI32) N oprQdQnQm
  | 0b011100010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VADD (oneDt SIMDTypI64) N oprQdQnQm
  (* VORR 0100001x1 *)
  | 0b010000101u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VORR None N oprDdDnDm
  | 0b010000111u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VORR None N oprQdQnQm
  (* VTST 0xx1000x1 *)
  | 0b011100001u | 0b011100011u (* 0111000x1 *) -> raise UndefinedException
  | 0b000100001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VTST (oneDt SIMDTyp8) N oprDdDnDm
  | 0b001100001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VTST (oneDt SIMDTyp16) N oprDdDnDm
  | 0b010100001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VTST (oneDt SIMDTyp32) N oprDdDnDm
  | 0b000100011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VTST (oneDt SIMDTyp8) N oprQdQnQm
  | 0b001100011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VTST (oneDt SIMDTyp16) N oprQdQnQm
  | 0b010100011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VTST (oneDt SIMDTyp32) N oprQdQnQm
  (* VQSHL xxx0100x1 *)
  | 0b000010001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypS8) N oprDdDmDn
  | 0b001010001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypS16) N oprDdDmDn
  | 0b010010001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypS32) N oprDdDmDn
  | 0b011010001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypS64) N oprDdDmDn
  | 0b100010001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypU8) N oprDdDmDn
  | 0b101010001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypU16) N oprDdDmDn
  | 0b110010001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypU32) N oprDdDmDn
  | 0b111010001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypU64) N oprDdDmDn
  | 0b000010011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypS8) N oprQdQmQn
  | 0b001010011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypS16) N oprQdQmQn
  | 0b010010011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypS32) N oprQdQmQn
  | 0b011010011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypS64) N oprQdQmQn
  | 0b100010011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypU8) N oprQdQmQn
  | 0b101010011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypU16) N oprQdQmQn
  | 0b110010011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypU32) N oprQdQmQn
  | 0b111010011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQSHL (oneDt SIMDTypU64) N oprQdQmQn
  (* VMLA 0xx1001x0 *)
  | 0b011100100u | 0b011100110u (* 0111001x0 *)-> raise UndefinedException
  | 0b000100100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMLA (oneDt SIMDTypI8) N oprDdDnDm
  | 0b001100100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMLA (oneDt SIMDTypI16) N oprDdDnDm
  | 0b010100100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMLA (oneDt SIMDTypI32) N oprDdDnDm
  | 0b000100110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMLA (oneDt SIMDTypI8) N oprQdQnQm
  | 0b001100110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMLA (oneDt SIMDTypI16) N oprQdQnQm
  | 0b010100110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMLA (oneDt SIMDTypI32) N oprQdQnQm
  (* VRSHL xxx0101x0 *)
  | 0b000010100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypS8) N oprDdDmDn
  | 0b001010100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypS16) N oprDdDmDn
  | 0b010010100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypS32) N oprDdDmDn
  | 0b011010100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypS64) N oprDdDmDn
  | 0b100010100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypU8) N oprDdDmDn
  | 0b101010100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypU16) N oprDdDmDn
  | 0b110010100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypU32) N oprDdDmDn
  | 0b111010100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypU64) N oprDdDmDn
  | 0b000010110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypS8) N oprQdQmQn
  | 0b001010110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypS16) N oprQdQmQn
  | 0b010010110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypS32) N oprQdQmQn
  | 0b011010110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypS64) N oprQdQmQn
  | 0b100010110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypU8) N oprQdQmQn
  | 0b101010110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypU16) N oprQdQmQn
  | 0b110010110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypU32) N oprQdQmQn
  | 0b111010110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VRSHL (oneDt SIMDTypU64) N oprQdQmQn
  (* VQRSHL xxx0101x1 *)
  | 0b000010101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypS8) N oprDdDmDn
  | 0b001010101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypS16) N oprDdDmDn
  | 0b010010101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypS32) N oprDdDmDn
  | 0b011010101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypS64) N oprDdDmDn
  | 0b100010101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypU8) N oprDdDmDn
  | 0b101010101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypU16) N oprDdDmDn
  | 0b110010101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypU32) N oprDdDmDn
  | 0b111010101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypU64) N oprDdDmDn
  | 0b000010111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypS8) N oprQdQmQn
  | 0b001010111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypS16) N oprQdQmQn
  | 0b010010111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypS32) N oprQdQmQn
  | 0b011010111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypS64) N oprQdQmQn
  | 0b100010111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypU8) N oprQdQmQn
  | 0b101010111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypU16) N oprQdQmQn
  | 0b110010111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypU32) N oprQdQmQn
  | 0b111010111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRSHL (oneDt SIMDTypU64) N oprQdQmQn
  (* VQDMULH 0xx1011x0 *)
  | 0b000101100u | 0b000101110u | 0b011101100u | 0b011101110u ->
    raise UndefinedException (* size == '00' || size == '11' *)
  | 0b001101100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQDMULH (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010101100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQDMULH (oneDt SIMDTypS32) N oprDdDnDm
  | 0b001101110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQDMULH (oneDt SIMDTypS16) N oprQdQnQm
  | 0b010101110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQDMULH (oneDt SIMDTypS32) N oprQdQnQm
  (* SHA1M 0101100x0 *)
  | 0b010110000u (* Q != 1 *) -> raise UndefinedException
  | 0b010110010u ->
    chkITVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.SHA1M (oneDt SIMDTyp32) N oprQdQnQm
  (* VPADD 0xx1011x1 *)
  | 0b011101101u | 0b011101111u | 0b000101111u | 0b001101111u | 0b010101111u ->
    raise UndefinedException (* size == '11' || Q == '1' *)
  | 0b000101101u ->
    render &itstate 0 isIn m a b l c Op.VPADD (oneDt SIMDTypI8) N oprDdDnDm
  | 0b001101101u ->
    render &itstate 0 isIn m a b l c Op.VPADD (oneDt SIMDTypI16) N oprDdDnDm
  | 0b010101101u ->
    render &itstate 0 isIn m a b l c Op.VPADD (oneDt SIMDTypI32) N oprDdDnDm
  (* VMAX xxx0110x0 *)
  | 0b011011000u | 0b011011010u | 0b111011000u | 0b111011010u (* x110110x0 *) ->
    raise UndefinedException (* size == '11' *)
  | 0b000011000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypS8) N oprDdDnDm
  | 0b001011000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010011000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypS32) N oprDdDnDm
  | 0b100011000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypU8) N oprDdDnDm
  | 0b101011000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypU16) N oprDdDnDm
  | 0b110011000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypU32) N oprDdDnDm
  | 0b000011010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypS8) N oprQdQnQm
  | 0b001011010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypS16) N oprQdQnQm
  | 0b010011010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypS32) N oprQdQnQm
  | 0b100011010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypU8) N oprQdQnQm
  | 0b101011010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypU16) N oprQdQnQm
  | 0b110011010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMAX (oneDt SIMDTypU32) N oprQdQnQm
  (* VORN 0110001x1 *)
  | 0b011000101u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VORN None N oprDdDnDm
  | 0b011000111u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VORN None N oprQdQnQm
  (* VMIN xxx0110x1 *)
  | 0b011011001u | 0b011011011u | 0b111011001u | 0b111011011u (* x110110x1 *) ->
    raise UndefinedException (* size == '11' *)
  | 0b000011001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypS8) N oprDdDnDm
  | 0b001011001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010011001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypS32) N oprDdDnDm
  | 0b100011001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypU8) N oprDdDnDm
  | 0b101011001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypU16) N oprDdDnDm
  | 0b110011001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypU32) N oprDdDnDm
  | 0b000011011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypS8) N oprQdQnQm
  | 0b001011011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypS16) N oprQdQnQm
  | 0b010011011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypS32) N oprQdQnQm
  | 0b100011011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypU8) N oprQdQnQm
  | 0b101011011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypU16) N oprQdQnQm
  | 0b110011011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMIN (oneDt SIMDTypU32) N oprQdQnQm
  (* VABD xxx0111x0 *)
  | 0b011011100u | 0b011011110u | 0b111011100u | 0b111011110u (* x110111x0 *) ->
    raise UndefinedException (* size == '11' *)
  | 0b000011100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypS8) N oprDdDnDm
  | 0b001011100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010011100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypS32) N oprDdDnDm
  | 0b100011100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypU8) N oprDdDnDm
  | 0b101011100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypU16) N oprDdDnDm
  | 0b110011100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypU32) N oprDdDnDm
  | 0b000011110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypS8) N oprQdQnQm
  | 0b001011110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypS16) N oprQdQnQm
  | 0b010011110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypS32) N oprQdQnQm
  | 0b100011110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypU8) N oprQdQnQm
  | 0b101011110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypU16) N oprQdQnQm
  | 0b110011110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypU32) N oprQdQnQm
  (* VABA xxx0111x1 *)
  | 0b011011101u | 0b011011111u | 0b111011101u | 0b111011111u (* x110111x1 *) ->
    raise UndefinedException (* size == '11' *)
  | 0b000011101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABA (oneDt SIMDTypS8) N oprDdDnDm
  | 0b001011101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABA (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010011101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABA (oneDt SIMDTypS32) N oprDdDnDm
  | 0b100011101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABA (oneDt SIMDTypU8) N oprDdDnDm
  | 0b101011101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABA (oneDt SIMDTypU16) N oprDdDnDm
  | 0b110011101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABA (oneDt SIMDTypU32) N oprDdDnDm
  | 0b000011111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABA (oneDt SIMDTypS8) N oprQdQnQm
  | 0b001011111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABA (oneDt SIMDTypS16) N oprQdQnQm
  | 0b010011111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABA (oneDt SIMDTypS32) N oprQdQnQm
  | 0b100011111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABA (oneDt SIMDTypU8) N oprQdQnQm
  | 0b101011111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABA (oneDt SIMDTypU16) N oprQdQnQm
  | 0b110011111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VABA (oneDt SIMDTypU32) N oprQdQnQm
  (* SHA1SU0 0111100x0 *)
  | 0b011110000u (* Q != '1' *) -> raise UndefinedException
  | 0b011110010u ->
    chkVdVnVm b
    render &itstate 0 isIn m a b l c Op.SHA1SU0 (oneDt SIMDTyp32) N oprQdQnQm
  (* VPADD 10x1101x0 *)
  | 0b100110110u | 0b101110110u (* Q == '1' *) -> raise UndefinedException
  | 0b100110100u ->
    chkSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VPADD (oneDt SIMDTypF32) N oprDdDnDm
  | 0b101110110u ->
    chkSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VPADD (oneDt SIMDTypF16) N oprDdDnDm
  (* VMUL 10x1101x1 *)
  | 0b100110101u ->
    chkSzITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VMUL (oneDt SIMDTypF32) N oprDdDnDm
  | 0b100110111u ->
    chkSzITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VMUL (oneDt SIMDTypF32) N oprQdQnQm
  | 0b101110101u ->
    chkSzITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VMUL (oneDt SIMDTypF16) N oprDdDnDm
  | 0b101110111u ->
    chkSzITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VMUL (oneDt SIMDTypF16) N oprQdQnQm
  (* VCGE 10x1110x0 *)
  | 0b100111000u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypF32) N oprDdDnDm
  | 0b100111010u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypF32) N oprQdQnQm
  | 0b101111000u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypF16) N oprDdDnDm
  | 0b101111010u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VCGE (oneDt SIMDTypF16) N oprQdQnQm
  (* VACGE 10x1110x1 *)
  | 0b100111001u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VACGE (oneDt SIMDTypF32) N oprDdDnDm
  | 0b100111011u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VACGE (oneDt SIMDTypF32) N oprQdQnQm
  | 0b101111001u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VACGE (oneDt SIMDTypF16) N oprDdDnDm
  | 0b101111011u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VACGE (oneDt SIMDTypF16) N oprQdQnQm
  (* VPMAX 10x111100 *)
  | 0b100111100u ->
    chkSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VPMAX (oneDt SIMDTypF32) N oprDdDnDm
  | 0b101111100u ->
    chkSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VPMAX (oneDt SIMDTypF16) N oprDdDnDm
  (* VMAXNM 10x1111x1 *)
  | 0b100111101u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VMAXNM (oneDt SIMDTypF32) N oprDdDnDm
  | 0b100111111u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VMAXNM (oneDt SIMDTypF32) N oprQdQnQm
  | 0b101111101u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VMAXNM (oneDt SIMDTypF16) N oprDdDnDm
  | 0b101111111u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VMAXNM (oneDt SIMDTypF16) N oprQdQnQm
  (* VEOR 1000001x1 *)
  | 0b100000101u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VEOR None N oprDdDnDm
  | 0b100000111u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VEOR None N oprQdQnQm
  (* VMUL xxx1001x1 *)
  | 0b011100101u | 0b011100111u | 0b111100101u | 0b111100111u (* size == '11' *)
  | 0b101100101u | 0b101100111u | 0b110100101u | 0b110100111u ->
    raise UndefinedException (* op == '1' && size != '00' *)
  | 0b000100101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMUL (oneDt SIMDTypI8) N oprDdDnDm
  | 0b001100101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMUL (oneDt SIMDTypI16) N oprDdDnDm
  | 0b010100101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMUL (oneDt SIMDTypI32) N oprDdDnDm
  | 0b100100101u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMUL (oneDt SIMDTypP8) N oprDdDnDm
  | 0b000100111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMUL (oneDt SIMDTypI8) N oprQdQnQm
  | 0b001100111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMUL (oneDt SIMDTypI16) N oprQdQnQm
  | 0b010100111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMUL (oneDt SIMDTypI32) N oprQdQnQm
  | 0b100100111u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMUL (oneDt SIMDTypP8) N oprQdQnQm
  (* SHA256H 1001100x0 *)
  | 0b100110000u (* Q != '1' *) -> raise UndefinedException
  | 0b100110010u ->
    chkITVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.SHA256H (oneDt SIMDTyp32) N oprQdQnQm
  (* VPMAX xxx101000 *)
  | 0b011101000u | 0b111101000u (* size == '11' *) -> raise UndefinedException
  | 0b000101000u ->
    render &itstate 0 isIn m a b l c Op.VPMAX (oneDt SIMDTypS8) N oprDdDnDm
  | 0b001101000u ->
    render &itstate 0 isIn m a b l c Op.VPMAX (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010101000u ->
    render &itstate 0 isIn m a b l c Op.VPMAX (oneDt SIMDTypS32) N oprDdDnDm
  | 0b100101000u ->
    render &itstate 0 isIn m a b l c Op.VPMAX (oneDt SIMDTypU8) N oprDdDnDm
  | 0b101101000u ->
    render &itstate 0 isIn m a b l c Op.VPMAX (oneDt SIMDTypU16) N oprDdDnDm
  | 0b110101000u ->
    render &itstate 0 isIn m a b l c Op.VPMAX (oneDt SIMDTypU32) N oprDdDnDm
  (* VBSL 1010001x1 *)
  | 0b101000101u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VBSL None N oprDdDnDm
  | 0b101000111u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VBSL None N oprQdQnQm
  (* VPMIN xxx101001 *)
  | 0b011101001u | 0b111101001u  (* size == '11' *) -> raise UndefinedException
  | 0b000101001u ->
    render &itstate 0 isIn m a b l c Op.VPMIN (oneDt SIMDTypS8) N oprDdDnDm
  | 0b001101001u ->
    render &itstate 0 isIn m a b l c Op.VPMIN (oneDt SIMDTypS16) N oprDdDnDm
  | 0b010101001u ->
    render &itstate 0 isIn m a b l c Op.VPMIN (oneDt SIMDTypS32) N oprDdDnDm
  | 0b100101001u ->
    render &itstate 0 isIn m a b l c Op.VPMIN (oneDt SIMDTypU8) N oprDdDnDm
  | 0b101101001u ->
    render &itstate 0 isIn m a b l c Op.VPMIN (oneDt SIMDTypU16) N oprDdDnDm
  | 0b110101001u ->
    render &itstate 0 isIn m a b l c Op.VPMIN (oneDt SIMDTypU32) N oprDdDnDm
  | b when b &&& 0b000111110u = 0b000101010u (* 0bxxx10101xu *) ->
    raise UnallocatedException
  (* SHA256H2 1011100x0 *)
  | 0b101110000u (* Q != '1' *) -> raise UndefinedException
  | 0b101110010u ->
    chkVdVnVm b
    render &itstate 0 isIn m a b l c Op.SHA256H2 (oneDt SIMDTyp32) N oprQdQnQm
  (* VABD 11x1101x0 *)
  | 0b110110100u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypF32) N oprDdDnDm
  | 0b110110110u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypF32) N oprQdQnQm
  | 0b111110100u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypF16) N oprDdDnDm
  | 0b111110110u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VABD (oneDt SIMDTypF16) N oprQdQnQm
  (* VCGT 11x1110x0 *)
  | 0b110111000u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypF32) N oprDdDnDm
  | 0b110111010u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypF32) N oprQdQnQm
  | 0b111111000u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypF16) N oprDdDnDm
  | 0b111111010u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VCGT (oneDt SIMDTypF16) N oprQdQnQm
  (* VACGT 11x1110x1 *)
  | 0b110111001u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VACGT (oneDt SIMDTypF32) N oprDdDnDm
  | 0b110111011u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VACGT (oneDt SIMDTypF32) N oprQdQnQm
  | 0b111111001u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VACGT (oneDt SIMDTypF16) N oprDdDnDm
  | 0b111111011u ->
    chkQVdVnVmSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VACGT (oneDt SIMDTypF16) N oprQdQnQm
  (* VPMIN 11x111100 *)
  | 0b110111100u ->
    chkSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VPMIN (oneDt SIMDTypF32) N oprDdDnDm
  | 0b111111100u ->
    chkSzIT b itstate
    render &itstate 0 isIn m a b l c Op.VPMIN (oneDt SIMDTypF16) N oprDdDnDm
  (* VMINNM 11x1111x1 *)
  | 0b110111101u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VMINNM (oneDt SIMDTypF32) N oprDdDnDm
  | 0b110111111u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VMINNM (oneDt SIMDTypF32) N oprQdQnQm
  | 0b111111101u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VMINNM (oneDt SIMDTypF32) N oprDdDnDm
  | 0b111111111u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VMINNM (oneDt SIMDTypF32) N oprQdQnQm
  (* VSUB 1xx1000x0 *)
  | 0b100100000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSUB (oneDt SIMDTypI8) N oprDdDnDm
  | 0b101100000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSUB (oneDt SIMDTypI16) N oprDdDnDm
  | 0b110100000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSUB (oneDt SIMDTypI32) N oprDdDnDm
  | 0b111100000u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSUB (oneDt SIMDTypI64) N oprDdDnDm
  | 0b100100010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSUB (oneDt SIMDTypI8) N oprQdQnQm
  | 0b101100010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSUB (oneDt SIMDTypI16) N oprQdQnQm
  | 0b110100010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSUB (oneDt SIMDTypI32) N oprQdQnQm
  | 0b111100010u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VSUB (oneDt SIMDTypI64) N oprQdQnQm
  (* VBIT 1100001x1 *)
  | 0b110000101u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VBIT None N oprDdDnDm
  | 0b110000111u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VBIT None N oprQdQnQm
  (* VCEQ 1xx1000x1 *)
  | 0b111100001u | 0b111100011u (* size == '11' *) -> raise UndefinedException
  | 0b100100001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCEQ (oneDt SIMDTypI8) N oprDdDnDm
  | 0b101100001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCEQ (oneDt SIMDTypI16) N oprDdDnDm
  | 0b110100001u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCEQ (oneDt SIMDTypI32) N oprDdDnDm
  | 0b100100011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCEQ (oneDt SIMDTypI8) N oprQdQnQm
  | 0b101100011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCEQ (oneDt SIMDTypI16) N oprQdQnQm
  | 0b110100011u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VCEQ (oneDt SIMDTypI32) N oprQdQnQm
  (* VMLS 1xx1001x0 *)
  | 00111100100u | 00111100110u (* size == '11' *) -> raise UndefinedException
  | 0b100100100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMLS (oneDt SIMDTypI8) N oprDdDnDm
  | 0b101100100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMLS (oneDt SIMDTypI16) N oprDdDnDm
  | 0b110100100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMLS (oneDt SIMDTypI32) N oprDdDnDm
  | 0b100100110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMLS (oneDt SIMDTypI8) N oprQdQnQm
  | 0b101100110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMLS (oneDt SIMDTypI16) N oprQdQnQm
  | 0b110100110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VMLS (oneDt SIMDTypI32) N oprQdQnQm
  (* VQRDMULH 1xx1011x0 *)
  | 0b100101100u | 0b100101110u | 0b111101100u | 0b111101110u ->
    raise UndefinedException (* size == '00' || size == '11' *)
  | 0b101101100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRDMULH (oneDt SIMDTypS16) N oprDdDnDm
  | 0b101101110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRDMULH (oneDt SIMDTypS16) N oprQdQnQm
  | 0b110101100u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRDMULH (oneDt SIMDTypS32) N oprDdDnDm
  | 0b110101110u ->
    chkQVdVnVm b
    render &itstate 0 isIn m a b l c Op.VQRDMULH (oneDt SIMDTypS32) N oprQdQnQm
  (* SHA256SU1 1101100x0 *)
  | 0b110110000u (* Q != '1' *) -> raise UndefinedException
  | 0b110110010u ->
    chkITVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.SHA256SU1 (oneDt SIMDTyp32) N oprQdQnQm
  (* VQRDMLAH 1xx1011x1 Armv8.1 *)
  | 0b100101101u | 0b100101111u | 0b111101101u | 0b111101111u ->
    raise UndefinedException (* size == '00' || size == '11' *)
  | 0b101101101u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VQRDMLAH (oneDt SIMDTypS16) N oprDdDnDm
  | 0b101101111u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VQRDMLAH (oneDt SIMDTypS16) N oprQdQnQm
  | 0b110101101u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VQRDMLAH (oneDt SIMDTypS32) N oprDdDnDm
  | 0b110101111u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VQRDMLAH (oneDt SIMDTypS32) N oprQdQnQm
  (* VBIF 1110001x1 *)
  | 0b111000101u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VBIF None N oprDdDnDm
  | 0b111000111u ->
    chkQVdVnVm b; render &itstate 0 isIn m a b l c Op.VBIF None N oprQdQnQm
  (* VQRDMLSH 1xx1100x1 Armv8.1 *)
  | 0b100110001u | 0b100110011u | 0b111110001u | 0b111110011u ->
    raise UndefinedException (* size == '00' || size == '11' *)
  | 0b101110001u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VQRDMLSH (oneDt SIMDTypS16) N oprDdDnDm
  | 0b101110011u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VQRDMLSH (oneDt SIMDTypS16) N oprQdQnQm
  | 0b110110001u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VQRDMLSH (oneDt SIMDTypS32) N oprDdDnDm
  | 0b110110011u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isIn m a b l c Op.VQRDMLSH (oneDt SIMDTypS32) N oprQdQnQm
  | b when b &&& 0b100111111u = 0b100111110u (* 0b1xx111110u *) ->
    raise UnallocatedException
  | _ -> Utils.impossible ()

/// Advanced SIMD two registers misc on page F3-4168.
let parseAdvSIMDTwoRegsMisc (itstate: byref<bl>) isInIT m a b l c =
  let decodeFields (* size:opc1:opc2:Q *) =
    concat (extract b 19 16) (extract b 10 6) 5
  match decodeFields with
  (* VREV64 xx000000x *)
  | 0b110000000u | 0b110000001u (* size = 11 *) -> raise UndefinedException
  | 0b000000000u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VREV64 (oneDt SIMDTyp8) N oprDdDm
  | 0b010000000u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VREV64 (oneDt SIMDTyp16) N oprDdDm
  | 0b100000000u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VREV64 (oneDt SIMDTyp32) N oprDdDm
  | 0b000000001u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VREV64 (oneDt SIMDTyp8) N oprQdQm
  | 0b010000001u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VREV64 (oneDt SIMDTyp16) N oprQdQm
  | 0b100000001u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VREV64 (oneDt SIMDTyp32) N oprQdQm
  (* VREV32 xx000001x *)
  | 0b100000010u | 0b100000011u (* size = 10 *)
  | 0b110000010u | 0b110000011u (* size = 11 *) -> raise UndefinedException
  | 0b000000010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VREV32 (oneDt SIMDTyp8) N oprDdDm
  | 0b010000010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VREV32 (oneDt SIMDTyp16) N oprDdDm
  | 0b000000011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VREV32 (oneDt SIMDTyp8) N oprQdQm
  | 0b010000011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VREV32 (oneDt SIMDTyp16) N oprQdQm
  (* VREV16 xx000010x *)
  | 0b010000100u | 0b010000101u (* size = 01 *)
  | 0b100000100u | 0b100000101u | 0b110000100u | 0b110000101u (* size = 1x *) ->
    raise UndefinedException
  | 0b000000100u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VREV16 (oneDt SIMDTyp8) N oprDdDm
  | 0b000000101u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VREV16 (oneDt SIMDTyp8) N oprQdQm
  | b when b &&& 0b001111110u = 0b000000110u (* xx000011x *) ->
    raise UnallocatedException
  (* VPADDL xx00010xx *)
  | 0b110001000u | 0b110001001u | 0b110001010u | 0b110001011u (* size = 11 *) ->
    raise UndefinedException
  | 0b000001000u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADDL (oneDt SIMDTypS8)  N oprDdDm
  | 0b010001000u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADDL (oneDt SIMDTypS16) N oprDdDm
  | 0b100001000u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADDL (oneDt SIMDTypS32) N oprDdDm
  | 0b000001010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADDL (oneDt SIMDTypU8)  N oprDdDm
  | 0b010001010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADDL (oneDt SIMDTypU16) N oprDdDm
  | 0b100001010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADDL (oneDt SIMDTypU32) N oprDdDm
  | 0b000001001u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADDL (oneDt SIMDTypS8)  N oprQdQm
  | 0b010001001u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADDL (oneDt SIMDTypS16) N oprQdQm
  | 0b100001001u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADDL (oneDt SIMDTypS32) N oprQdQm
  | 0b000001011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADDL (oneDt SIMDTypU8)  N oprQdQm
  | 0b010001011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADDL (oneDt SIMDTypU16) N oprQdQm
  | 0b100001011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADDL (oneDt SIMDTypU32) N oprQdQm
  (* AESE xx0001100 *)
  | 0b010001100u | 0b100001100u | 0b110001100u (* size != 00 *) ->
    raise UndefinedException
  | 0b000001100u ->
    chkITVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.AESE (oneDt SIMDTyp8) N oprQdQm
  (* AESD xx0001101 *)
  | 0b010001101u | 0b100001101u | 0b110001101u (* size != 00 *) ->
    raise UndefinedException
  | 0b000001101u ->
    chkITVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.AESD (oneDt SIMDTyp8) N oprQdQm
  (* AESMC xx0001110 *)
  | 0b010001110u | 0b100001110u | 0b110001110u (* size != 00 *) ->
    raise UndefinedException
  | 0b000001110u ->
    chkITVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.AESMC (oneDt SIMDTyp8) N oprQdQm
  (* AESIMC xx0001111 *)
  | 0b010001111u | 0b100001111u | 0b110001111u (* size != 00 *) ->
    raise UndefinedException
  | 0b000001111u ->
    chkITVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.AESIMC (oneDt SIMDTyp8) N oprQdQm
  (* VCLS xx001000x *)
  | 0b110010000u | 0b110010001u (* size = 11 *) -> raise UndefinedException
  | 0b000010000u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCLS (oneDt SIMDTypS8) N oprDdDm
  | 0b010010000u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCLS (oneDt SIMDTypS16) N oprDdDm
  | 0b100010000u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCLS (oneDt SIMDTypS32) N oprDdDm
  | 0b000010001u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCLS (oneDt SIMDTypS8) N oprQdQm
  | 0b010010001u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCLS (oneDt SIMDTypS16) N oprQdQm
  | 0b100010001u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCLS (oneDt SIMDTypS32) N oprQdQm
  (* VSWP 00100000x *)
  | 0b001000000u ->
    chkQVdVm b; render &itstate 0 isInIT m a b l c Op.VSWP None N oprDdDm
  | 0b001000001u ->
    chkQVdVm b; render &itstate 0 isInIT m a b l c Op.VSWP None N oprQdQm
  (* VCLZ xx001001x *)
  | 0b110010010u | 0b110010011u (* size = 11 *) -> raise UndefinedException
  | 0b000010010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCLZ (oneDt SIMDTypI8)  N oprDdDm
  | 0b010010010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCLZ (oneDt SIMDTypI16) N oprDdDm
  | 0b100010010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCLZ (oneDt SIMDTypI32) N oprDdDm
  | 0b000010011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCLZ (oneDt SIMDTypI8)  N oprQdQm
  | 0b010010011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCLZ (oneDt SIMDTypI16) N oprQdQm
  | 0b100010011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCLZ (oneDt SIMDTypI32) N oprQdQm
  (* VCNT xx001010x *)
  | 0b010010100u | 0b100010100u | 0b110010100u | 0b010010101u | 0b100010101u
  | 0b110010101u (* size != 00 *) -> raise UndefinedException
  | 0b000010100u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCNT (oneDt SIMDTyp8) N oprDdDm
  | 0b000010101u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VCNT (oneDt SIMDTyp8) N oprQdQm
  (* VMVN xx001011x *)
  | 0b010010110u | 0b010010111u | 0b100010110u | 0b100010111u | 0b110010110u
  | 0b110010111u (* size != 00 *) -> raise UndefinedException
  | 0b000010110u ->
    chkQVdVm b; render &itstate 0 isInIT m a b l c Op.VMVN None N oprDdDm
  | 0b000010111u ->
    chkQVdVm b; render &itstate 0 isInIT m a b l c Op.VMVN None N oprQdQm
  | 0b001011001u -> raise UnallocatedException
  (* VPADAL xx00110xx *)
  | 0b110011000u | 0b110011001u | 0b110011010u | 0b110011011u (* size = 11 *) ->
    raise UndefinedException
  | 0b000011000u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADAL (oneDt SIMDTypS8) N oprDdDm
  | 0b010011000u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADAL (oneDt SIMDTypS16) N oprDdDm
  | 0b100011000u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADAL (oneDt SIMDTypS32) N oprDdDm
  | 0b000011010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADAL (oneDt SIMDTypU8) N oprDdDm
  | 0b010011010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADAL (oneDt SIMDTypU16) N oprDdDm
  | 0b100011010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADAL (oneDt SIMDTypU32) N oprDdDm
  | 0b000011001u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADAL (oneDt SIMDTypS8) N oprQdQm
  | 0b010011001u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADAL (oneDt SIMDTypS16) N oprQdQm
  | 0b100011001u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADAL (oneDt SIMDTypS32) N oprQdQm
  | 0b000011011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADAL (oneDt SIMDTypU8) N oprQdQm
  | 0b010011011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADAL (oneDt SIMDTypU16) N oprQdQm
  | 0b100011011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VPADAL (oneDt SIMDTypU32) N oprQdQm
  (* VQABS xx001110x *)
  | 0b110011100u | 0b110011101u (* size = 11 *) -> raise UndefinedException
  | 0b000011100u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VQABS (oneDt SIMDTypS8) N oprDdDm
  | 0b010011100u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VQABS (oneDt SIMDTypS16) N oprDdDm
  | 0b100011100u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VQABS (oneDt SIMDTypS32) N oprDdDm
  | 0b000011101u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VQABS (oneDt SIMDTypS8) N oprQdQm
  | 0b010011101u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VQABS (oneDt SIMDTypS16) N oprQdQm
  | 0b100011101u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VQABS (oneDt SIMDTypS32) N oprQdQm
  (* VQNEG xx001111x *)
  | 0b110011110u | 0b110011111u (* size = 11 *) -> raise UndefinedException
  | 0b000011110u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VQNEG (oneDt SIMDTypS8) N oprDdDm
  | 0b010011110u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VQNEG (oneDt SIMDTypS16) N oprDdDm
  | 0b100011110u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VQNEG (oneDt SIMDTypS32) N oprDdDm
  | 0b000011111u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VQNEG (oneDt SIMDTypS8) N oprQdQm
  | 0b010011111u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VQNEG (oneDt SIMDTypS16) N oprQdQm
  | 0b100011111u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VQNEG (oneDt SIMDTypS32) N oprQdQm
  (* VCGT xx01x000x *)
  | 0b110100000u | 0b110100001u | 0b110110000u | 0b110110001u (* size = 11 *)
  | 0b000110000u | 0b000110001u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000100000u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGT (oneDt SIMDTypS8) N oprDdDm0
  | 0b010100000u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGT (oneDt SIMDTypS16) N oprDdDm0
  | 0b100100000u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGT (oneDt SIMDTypS32) N oprDdDm0
  | 0b010110000u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGT (oneDt SIMDTypF16) N oprDdDm0
  | 0b100110000u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGT (oneDt SIMDTypF32) N oprDdDm0
  | 0b000100001u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGT (oneDt SIMDTypS8) N oprQdQm0
  | 0b010100001u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGT (oneDt SIMDTypS16) N oprQdQm0
  | 0b100100001u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGT (oneDt SIMDTypS32) N oprQdQm0
  | 0b010110001u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGT (oneDt SIMDTypF16) N oprQdQm0
  | 0b100110001u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGT (oneDt SIMDTypF32) N oprQdQm0
  (* VCGE xx01x001x *)
  | 0b110100010u | 0b110100011u | 0b110110010u | 0b110110011u (* size = 11 *)
  | 0b000110010u | 0b000110011u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000100010u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGE (oneDt SIMDTypS8) N oprDdDm0
  | 0b010100010u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGE (oneDt SIMDTypS16) N oprDdDm0
  | 0b100100010u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGE (oneDt SIMDTypS32) N oprDdDm0
  | 0b010110010u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGE (oneDt SIMDTypF16) N oprDdDm0
  | 0b100110010u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGE (oneDt SIMDTypF32) N oprDdDm0
  | 0b000100011u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGE (oneDt SIMDTypS8) N oprQdQm0
  | 0b010100011u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGE (oneDt SIMDTypS16) N oprQdQm0
  | 0b100100011u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGE (oneDt SIMDTypS32) N oprQdQm0
  | 0b010110011u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGE (oneDt SIMDTypF16) N oprQdQm0
  | 0b100110011u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCGE (oneDt SIMDTypF32) N oprQdQm0
  (* VCEQ xx01x010x *)
  | 0b110100100u | 0b110100101u | 0b110110100u | 0b110110101u (* size = 11 *)
  | 0b000110100u | 0b000110101u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000100100u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCEQ (oneDt SIMDTypS8) N oprDdDm0
  | 0b010100100u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCEQ (oneDt SIMDTypS16) N oprDdDm0
  | 0b100100100u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCEQ (oneDt SIMDTypS32) N oprDdDm0
  | 0b010110100u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCEQ (oneDt SIMDTypF16) N oprDdDm0
  | 0b100110100u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCEQ (oneDt SIMDTypF32) N oprDdDm0
  | 0b000100101u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCEQ (oneDt SIMDTypS8) N oprQdQm0
  | 0b010100101u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCEQ (oneDt SIMDTypS16) N oprQdQm0
  | 0b100100101u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCEQ (oneDt SIMDTypS32) N oprQdQm0
  | 0b010110101u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCEQ (oneDt SIMDTypF16) N oprQdQm0
  | 0b100110101u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCEQ (oneDt SIMDTypF32) N oprQdQm0
  (* VCLE xx01x011x *)
  | 0b110100110u | 0b110100111u | 0b110110110u | 0b110110111u (* size = 11 *)
  | 0b000110110u | 0b000110111u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000100110u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLE (oneDt SIMDTypS8) N oprDdDm0
  | 0b010100110u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLE (oneDt SIMDTypS16) N oprDdDm0
  | 0b100100110u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLE (oneDt SIMDTypS32) N oprDdDm0
  | 0b010110110u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLE (oneDt SIMDTypF16) N oprDdDm0
  | 0b100110110u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLE (oneDt SIMDTypF32) N oprDdDm0
  | 0b000100111u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLE (oneDt SIMDTypS8) N oprQdQm0
  | 0b010100111u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLE (oneDt SIMDTypS16) N oprQdQm0
  | 0b100100111u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLE (oneDt SIMDTypS32) N oprQdQm0
  | 0b010110111u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLE (oneDt SIMDTypF16) N oprQdQm0
  | 0b100110111u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLE (oneDt SIMDTypF32) N oprQdQm0
  (* VCLT xx01x100x *)
  | 0b110101000u | 0b110101001u | 0b110111000u | 0b110111001u (* size = 11 *)
  | 0b000111000u | 0b000111001u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000101000u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLT (oneDt SIMDTypS8) N oprDdDm0
  | 0b010101000u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLT (oneDt SIMDTypS16) N oprDdDm0
  | 0b100101000u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLT (oneDt SIMDTypS32) N oprDdDm0
  | 0b010111000u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLT (oneDt SIMDTypF16) N oprDdDm0
  | 0b100111000u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLT (oneDt SIMDTypF32) N oprDdDm0
  | 0b000101001u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLT (oneDt SIMDTypS8) N oprQdQm0
  | 0b010101001u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLT (oneDt SIMDTypS16) N oprQdQm0
  | 0b100101001u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLT (oneDt SIMDTypS32) N oprQdQm0
  | 0b010111001u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLT (oneDt SIMDTypF16) N oprQdQm0
  | 0b100111001u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VCLT (oneDt SIMDTypF32) N oprQdQm0
  (* VABS xx01x110x *)
  | 0b110101100u | 0b110101101u | 0b110111100u | 0b110111101u (* size = 11 *)
  | 0b000111100u | 0b000111101u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000101100u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VABS (oneDt SIMDTypS8) N oprDdDm
  | 0b010101100u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VABS (oneDt SIMDTypS16) N oprDdDm
  | 0b100101100u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VABS (oneDt SIMDTypS32) N oprDdDm
  | 0b010111100u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VABS (oneDt SIMDTypF16) N oprDdDm
  | 0b100111100u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VABS (oneDt SIMDTypF32) N oprDdDm
  | 0b000101101u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VABS (oneDt SIMDTypS8) N oprDdDm
  | 0b010101101u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VABS (oneDt SIMDTypS16) N oprDdDm
  | 0b100101101u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VABS (oneDt SIMDTypS32) N oprDdDm
  | 0b010111101u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VABS (oneDt SIMDTypF16) N oprDdDm
  | 0b100111101u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VABS (oneDt SIMDTypF32) N oprDdDm
  (* VNEG xx01x111x *)
  | 0b110101110u | 0b110101111u | 0b110111110u | 0b110111111u (* size = 11 *)
  | 0b000111110u | 0b000111111u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000101110u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VNEG (oneDt SIMDTypS8) N oprDdDm
  | 0b010101110u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VNEG (oneDt SIMDTypS16) N oprDdDm
  | 0b100101110u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VNEG (oneDt SIMDTypS32) N oprDdDm
  | 0b010111110u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VNEG (oneDt SIMDTypF16) N oprDdDm
  | 0b100111110u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VNEG (oneDt SIMDTypF32) N oprDdDm
  | 0b000101111u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VNEG (oneDt SIMDTypS8) N oprQdQm
  | 0b010101111u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VNEG (oneDt SIMDTypS16) N oprQdQm
  | 0b100101111u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VNEG (oneDt SIMDTypS32) N oprQdQm
  | 0b010111111u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VNEG (oneDt SIMDTypF16) N oprQdQm
  | 0b100111111u ->
    chkFSzITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VNEG (oneDt SIMDTypF32) N oprQdQm
  (* SHA1H xx0101011 *)
  | 0b000101011u | 0b010101011u | 0b110101011u (* size != 10 *) ->
    raise UndefinedException
  | 0b100101011u ->
    chkITVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.SHA1H (oneDt SIMDTyp32) N oprQdQm
  (* VCVT 011011001 Armv8.6 *)
  | 0b011011001u ->
    pickBit b 0 = 1u (* Vm<0> = 1 *) |> checkUndef
    let dt = twoDt (BF16, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprDdQm
  (* VTRN xx100001x *)
  | 0b111000010u | 0b111000011u (* size = 11 *) -> raise UndefinedException
  | 0b001000010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VTRN (oneDt SIMDTyp8) N oprDdDm
  | 0b011000010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VTRN (oneDt SIMDTyp16) N oprDdDm
  | 0b101000010u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VTRN (oneDt SIMDTyp32) N oprDdDm
  | 0b001000011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VTRN (oneDt SIMDTyp8) N oprQdQm
  | 0b011000011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VTRN (oneDt SIMDTyp16) N oprQdQm
  | 0b101000011u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VTRN (oneDt SIMDTyp32) N oprQdQm
  (* VUZP xx100010x *)
  | 0b111000100u | 0b111000101u (* size = 11 *)
  | 0b101000100u (* Q = 0 && size = 10 *) -> raise UndefinedException
  | 0b001000100u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VUZP (oneDt SIMDTyp8) N oprDdDm
  | 0b011000100u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VUZP (oneDt SIMDTyp16) N oprDdDm
  | 0b001000101u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VUZP (oneDt SIMDTyp8) N oprQdQm
  | 0b011000101u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VUZP (oneDt SIMDTyp16) N oprQdQm
  | 0b101000101u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VUZP (oneDt SIMDTyp32) N oprQdQm
  (* VZIP xx100011x *)
  | 0b111000110u | 0b111000111u (* size = 11 *)
  | 0b101000110u (* Q = 0 && size = 10 *) -> raise UndefinedException
  | 0b001000110u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VZIP (oneDt SIMDTyp8) N oprDdDm
  | 0b011000110u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VZIP (oneDt SIMDTyp16) N oprDdDm
  | 0b001000111u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VZIP (oneDt SIMDTyp8) N oprQdQm
  | 0b011000111u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VZIP (oneDt SIMDTyp16) N oprQdQm
  | 0b101000111u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VZIP (oneDt SIMDTyp32) N oprQdQm
  (* VMOVN xx1001000 *)
  | 0b111001000u (* size = 11 *) -> raise UndefinedException
  | 0b001001000u ->
    chkVm b
    render &itstate 0 isInIT m a b l c Op.VMOVN (oneDt SIMDTypI16) N oprDdQm
  | 0b011001000u ->
    chkVm b
    render &itstate 0 isInIT m a b l c Op.VMOVN (oneDt SIMDTypI32) N oprDdQm
  | 0b101001000u ->
    chkVm b
    render &itstate 0 isInIT m a b l c Op.VMOVN (oneDt SIMDTypI64) N oprDdQm
  (* VQMOVUN xx1001001 *)
  | 00111001001u (* size = 11 *) -> raise UndefinedException
  | 0b001001001u ->
    chkVm b
    render &itstate 0 isInIT m a b l c Op.VQMOVUN (oneDt SIMDTypS16) N oprDdQm
  | 0b011001001u ->
    chkVm b
    render &itstate 0 isInIT m a b l c Op.VQMOVUN (oneDt SIMDTypS32) N oprDdQm
  | 0b101001001u ->
    chkVm b
    render &itstate 0 isInIT m a b l c Op.VQMOVUN (oneDt SIMDTypS64) N oprDdQm
  (* VQMOVN xx100101x *)
  | 0b001001010u ->
    chkVm b
    render &itstate 0 isInIT m a b l c Op.VQMOVN (oneDt SIMDTypS16) N oprDdQm
  | 0b011001010u ->
    chkVm b
    render &itstate 0 isInIT m a b l c Op.VQMOVN (oneDt SIMDTypS32) N oprDdQm
  | 0b101001010u ->
    chkVm b
    render &itstate 0 isInIT m a b l c Op.VQMOVN (oneDt SIMDTypS64) N oprDdQm
  | 0b001001011u ->
    chkVm b
    render &itstate 0 isInIT m a b l c Op.VQMOVN (oneDt SIMDTypU16) N oprDdQm
  | 0b011001011u ->
    chkVm b
    render &itstate 0 isInIT m a b l c Op.VQMOVN (oneDt SIMDTypU32) N oprDdQm
  | 0b101001011u ->
    chkVm b
    render &itstate 0 isInIT m a b l c Op.VQMOVN (oneDt SIMDTypU64) N oprDdQm
  (* VSHLL xx1001100 *)
  | 0b111001100u (* size = 11 *) -> raise UndefinedException
  | 0b001001100u ->
    chkVm b
    render &itstate 0 isInIT m a b l c Op.VSHLL (oneDt SIMDTypI8) N oprQdDmImm8
  | 0b011001100u ->
    chkVm b
    let dt = oneDt SIMDTypI16
    render &itstate 0 isInIT m a b l c Op.VSHLL dt N oprQdDmImm16
  | 0b101001100u ->
    chkVm b
    let dt = oneDt SIMDTypI32
    render &itstate 0 isInIT m a b l c Op.VSHLL dt N oprQdDmImm32
  (* SHA1SU1 xx1001110 *)
  | 0b001001110u | 0b011001110u | 0b111001110u (* size != 10 *) ->
    raise UndefinedException
  | 0b101001110u ->
    chkITVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.SHA1SU1 (oneDt SIMDTyp32) N oprQdQm
  (* SHA256SU0 xx1001111 *)
  | 0b001001111u | 0b011001111u | 0b111001111u (* size != 10 *) ->
    raise UndefinedException
  | 0b101001111u ->
    chkITVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.SHA256SU0 (oneDt SIMDTyp32) N oprQdQm
  (* VRINTN xx101000x *)
  | 0b001010000u | 0b001010001u (* size = 00 *)
  | 0b111010000u | 0b111010001u (* size = 11 *) -> raise UndefinedException
  | 0b011010000u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTN (oneDt SIMDTypF16) N oprDdDm
  | 0b011010001u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTN (oneDt SIMDTypF16) N oprQdQm
  | 0b101010000u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTN (oneDt SIMDTypF32) N oprDdDm
  | 0b101010001u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTN (oneDt SIMDTypF32) N oprQdQm
  (* VRINTX xx101001x *)
  | 0b001010010u | 0b001010011u (* size = 00 *)
  | 0b111010010u | 0b111010011u (* size = 11 *) -> raise UndefinedException
  | 0b011010010u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTX (oneDt SIMDTypF16) N oprDdDm
  | 0b011010011u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTX (oneDt SIMDTypF16) N oprQdQm
  | 0b101010010u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTX (oneDt SIMDTypF32) N oprDdDm
  | 0b101010011u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTX (oneDt SIMDTypF32) N oprQdQm
  (* VRINTA xx101010x *)
  | 0b001010100u | 0b001010101u (* size = 00 *)
  | 0b111010100u | 0b111010101u (* size = 11 *) -> raise UndefinedException
  | 0b011010100u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTA (oneDt SIMDTypF16) N oprDdDm
  | 0b011010101u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTA (oneDt SIMDTypF16) N oprQdQm
  | 0b101010100u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTA (oneDt SIMDTypF32) N oprDdDm
  | 0b101010101u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTA (oneDt SIMDTypF32) N oprQdQm
  (* VRINTZ xx101011x *)
  | 0b001010110u | 0b001010111u (* size = 00 *)
  | 0b111010110u | 0b111010111u (* size = 11 *) -> raise UndefinedException
  | 0b011010110u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTZ (oneDt SIMDTypF16) N oprDdDm
  | 0b011010111u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTZ (oneDt SIMDTypF16) N oprQdQm
  | 0b101010110u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTZ (oneDt SIMDTypF32) N oprDdDm
  | 0b101010111u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTZ (oneDt SIMDTypF32) N oprQdQm
  | 0b101011001u -> raise UnallocatedException
  (* VCVT xx1011000 *)
  | 0b001011000u | 0b101011000u | 0b111011000u (* size != 01 *) ->
    raise UndefinedException
  | 0b011011000u ->
    chkOpVdVm b
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprDdQm
  (* VRINTM xx101101x *)
  | 0b001011010u | 0b001011011u (* size = 00 *)
  | 0b111011010u | 0b111011011u (* size = 11 *) -> raise UndefinedException
  | 0b011011010u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTM (oneDt SIMDTypF16) N oprDdDm
  | 0b011011011u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTM (oneDt SIMDTypF16) N oprQdQm
  | 0b101011010u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTM (oneDt SIMDTypF32) N oprDdDm
  | 0b101011011u ->
    chkITQVdVm b itstate
    render &itstate 0 isInIT m a b l c Op.VRINTM (oneDt SIMDTypF32) N oprQdQm
  (* VCVT xx1011100 *)
  | 0b001011100u | 0b101011100u | 0b111011100u (* size =! 01 *) ->
    raise UndefinedException
  | 0b011011100u ->
    chkOpVdVm b
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprQdDm
  | 0b001011101u | 0b011011101u | 0b101011101u | 0b111011101u (* xx1011101 *) ->
    raise UnallocatedException
  (* VRINTP xx101111x *)
  | 0b001011110u | 0b001011111u (* size = 00 *)
  | 0b111011110u | 0b111011111u (* size = 11 *) -> raise UndefinedException
  | 0b011011110u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VRINTP (oneDt SIMDTypF16) N oprDdDm
  | 0b011011111u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VRINTP (oneDt SIMDTypF16) N oprQdQm
  | 0b101011110u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VRINTP (oneDt SIMDTypF32) N oprDdDm
  | 0b101011111u ->
    chkQVdVm b
    render &itstate 0 isInIT m a b l c Op.VRINTP (oneDt SIMDTypF32) N oprQdQm
  (* VCVTA xx11000xx *)
  | 0b001100000u | 0b001100001u | 0b001100010u | 0b001100011u (* size = 00 *)
  | 0b111100000u | 0b111100001u | 0b111100010u | 0b111100011u (* size = 11 *) ->
    raise UndefinedException
  | 0b011100000u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTA dt N oprDdDm
  | 0b101100000u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTA dt N oprDdDm
  | 0b011100010u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTA dt N oprDdDm
  | 0b101100010u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTA dt N oprDdDm
  | 0b011100001u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTA dt N oprQdQm
  | 0b101100001u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTA dt N oprQdQm
  | 0b011100011u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTA dt N oprQdQm
  | 0b101100011u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTA dt N oprQdQm
  (* VCVTN xx11001xx *)
  | 0b001100100u | 0b001100101u | 0b001100110u | 0b001100111u (* size = 00 *)
  | 0b111100100u | 0b111100101u | 0b111100110u | 0b111100111u (* size = 11 *) ->
    raise UndefinedException
  | 0b011100100u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTN dt N oprDdDm
  | 0b101100100u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTN dt N oprDdDm
  | 0b011100110u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTN dt N oprDdDm
  | 0b101100110u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTN dt N oprDdDm
  | 0b011100101u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTN dt N oprQdQm
  | 0b101100101u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTN dt N oprQdQm
  | 0b011100111u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTN dt N oprQdQm
  | 0b101100111u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTN dt N oprQdQm
  (* VCVTP xx11010xx *)
  | 0b001101000u | 0b001101001u | 0b001101010u | 0b001101011u (* size = 00 *)
  | 0b111101000u | 0b111101001u | 0b111101010u | 0b111101011u (* size = 11 *) ->
    raise UndefinedException
  | 0b011101000u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTP dt N oprDdDm
  | 0b101101000u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTP dt N oprDdDm
  | 0b011101010u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTP dt N oprDdDm
  | 0b101101010u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTP dt N oprDdDm
  | 0b011101001u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTP dt N oprQdQm
  | 0b101101001u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTP dt N oprQdQm
  | 0b011101011u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTP dt N oprQdQm
  | 0b101101011u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTP dt N oprQdQm
  (* VCVTM xx11011xx *)
  | 0b001101100u | 0b001101101u | 0b001101110u | 0b001101111u (* size = 00 *)
  | 0b111101100u | 0b111101101u | 0b111101110u | 0b111101111u (* size = 11 *) ->
    raise UndefinedException
  | 0b011101100u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTM dt N oprDdDm
  | 0b101101100u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTM dt N oprDdDm
  | 0b011101110u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTM dt N oprDdDm
  | 0b101101110u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTM dt N oprDdDm
  | 0b011101101u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTM dt N oprQdQm
  | 0b101101101u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTM dt N oprQdQm
  | 0b011101111u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVTM dt N oprQdQm
  | 0b101101111u ->
    chkITQVdVm b itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVTM dt N oprQdQm
  (* VRECPE xx1110x0x *)
  | 0b001110000u | 0b001110001u | 0b001110100u | 0b001110101u (* size = 00 *)
  | 0b111110000u | 0b111110001u | 0b111110100u | 0b111110101u (* size = 11 *) ->
    raise UndefinedException
  | 0b101110000u ->
    chkQVdVmSzIT b itstate
    render &itstate 0 isInIT m a b l c Op.VRECPE (oneDt SIMDTypU32) N oprDdDm
  | 0b011110100u ->
    chkQVdVmSzIT b itstate
    render &itstate 0 isInIT m a b l c Op.VRECPE (oneDt SIMDTypF16) N oprDdDm
  | 0b101110100u ->
    chkQVdVmSzIT b itstate
    render &itstate 0 isInIT m a b l c Op.VRECPE (oneDt SIMDTypF32) N oprDdDm
  | 0b101110001u ->
    chkQVdVmSzIT b itstate
    render &itstate 0 isInIT m a b l c Op.VRECPE (oneDt SIMDTypU32) N oprQdQm
  | 0b011110101u ->
    chkQVdVmSzIT b itstate
    render &itstate 0 isInIT m a b l c Op.VRECPE (oneDt SIMDTypF16) N oprQdQm
  | 0b101110101u ->
    chkQVdVmSzIT b itstate
    render &itstate 0 isInIT m a b l c Op.VRECPE (oneDt SIMDTypF32) N oprQdQm
  (* VRSQRTE xx1110x1x *)
  | 0b001110010u | 0b001110011u | 0b001110110u | 0b001110111u (* size = 00 *)
  | 0b111110010u | 0b111110011u | 0b111110110u | 0b111110111u (* size = 11 *) ->
    raise UndefinedException
  | 0b101110010u ->
    chkQVdVmSzIT b itstate
    render &itstate 0 isInIT m a b l c Op.VRSQRTE (oneDt SIMDTypU32) N oprDdDm
  | 0b011110110u ->
    chkQVdVmSzIT b itstate
    render &itstate 0 isInIT m a b l c Op.VRSQRTE (oneDt SIMDTypF16) N oprDdDm
  | 0b101110110u ->
    chkQVdVmSzIT b itstate
    render &itstate 0 isInIT m a b l c Op.VRSQRTE (oneDt SIMDTypF32) N oprDdDm
  | 0b101110011u ->
    chkQVdVmSzIT b itstate
    render &itstate 0 isInIT m a b l c Op.VRSQRTE (oneDt SIMDTypU32) N oprQdQm
  | 0b011110111u ->
    chkQVdVmSzIT b itstate
    render &itstate 0 isInIT m a b l c Op.VRSQRTE (oneDt SIMDTypF16) N oprQdQm
  | 0b101110111u ->
    chkQVdVmSzIT b itstate
    render &itstate 0 isInIT m a b l c Op.VRSQRTE (oneDt SIMDTypF32) N oprQdQm
  | 0b111011001u -> raise UnallocatedException
  (* VCVT xx1111xxx *)
  | b when extract b 8 7 = 0b00u (* size = 00 *) -> raise UndefinedException
  | b when extract b 8 7 = 0b11u (* size = 11 *) -> raise UndefinedException
  | 0b011111000u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypF16, SIMDTypS16)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprDdDm
  | 0b011111010u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypF16, SIMDTypU16)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprDdDm
  | 0b011111100u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprDdDm
  | 0b011111110u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprDdDm
  | 0b101111000u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprDdDm
  | 0b101111010u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprDdDm
  | 0b101111100u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprDdDm
  | 0b101111110u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprDdDm
  | 0b011111001u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypF16, SIMDTypS16)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprQdQm
  | 0b011111011u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypF16, SIMDTypU16)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprQdQm
  | 0b011111101u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprQdQm
  | 0b011111111u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprQdQm
  | 0b101111001u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprQdQm
  | 0b101111011u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprQdQm
  | 0b101111101u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprQdQm
  | 0b101111111u ->
    chkQVdVmSzIT b itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render &itstate 0 isInIT m a b l c Op.VCVT dt N oprQdQm
  | _ -> Utils.impossible ()

/// Advanced SIMD duplicate (scalar) on page F3-4170.
let parseAdvSIMDDupScalar (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 9 7 with
  | 0b000u ->
    chkQVd bin
    let dt = getDTImm4 (extract bin 19 16) |> oneDt
    render &itstate 0 isInIT mode addr bin len cond Op.VDUP dt N oprDdDmx
  | _ (* 001 | 01x | 1xx *) -> raise UnallocatedException

/// Advanced SIMD three registers of different lengths on page F3-4171.
let parseAdvSIMDThreeRegsDiffLen (itstate: byref<bl>) isInIT mode addr bin l c =
  match concat (pickBit bin 28) (extract bin 11 8) 4 (* U:opc *) with
  | 0b00000u | 0b10000u (* x0000 *) ->
    chkVdOpVn bin
    let dt = getDT bin |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VADDL dt N oprQdDnDm
  | 0b00001u | 0b10001u (* x0001 *) ->
    chkVdOpVn bin
    let dt = getDT bin |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VADDW dt N oprQdQnDm
  | 0b00010u | 0b10010u (* x0010 *) ->
    chkVdOpVn bin
    let dt = getDT bin |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VSUBL dt N oprQdDnDm
  | 0b00100u ->
    chkVnVm bin
    let dt = getDTInt (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VADDHN dt N oprDdQnQm
  | 0b00011u | 0b10011u (* x0011 *) ->
    chkVdOpVn bin
    let dt = getDT bin |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VSUBW dt N oprQdQnDm
  | 0b00110u ->
    chkVnVm bin
    let dt = getDTInt (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VSUBHN dt N oprDdQnQm
  | 0b01001u ->
    chkSzVd bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQDMLAL dt N oprQdDnDm
  | 0b00101u | 0b10101u (* x0101 *) ->
    chkVd bin
    let dt = getDT bin |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VABAL dt N oprQdDnDm
  | 0b01011u ->
    chkSzVd bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQDMLSL dt N oprQdDnDm
  | 0b01101u ->
    chkSzVd bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQDMULL dt N oprQdDnDm
  | 0b00111u | 0b10111u (* x0111 *) ->
    chkVd bin
    let dt = getDT bin |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VABDL dt N oprQdDnDm
  | 0b01000u | 0b11000u (* x1000 *) ->
    chkVd bin
    let dt = getDT bin |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLAL dt N oprQdDnDm
  | 0b01010u | 0b11010u (* x1010 *) ->
    chkVd bin
    let dt = getDT bin |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLSL dt N oprQdDnDm
  | 0b10100u ->
    chkVnVm bin
    let dt = getDTInt (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VRADDHN dt N oprDdQnQm
  | 0b10110u ->
    chkVnVm bin
    let dt = getDTInt (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VRSUBHN dt N oprDdQnQm
  | 0b01100u | 0b01110u | 0b11100u | 0b11110u (* x11x0 *) ->
    chkPolySzITVd bin itstate
    let dt = getDTPoly bin |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMULL dt N oprQdDnDm
  | 0b11001u -> raise UnallocatedException
  | 0b11011u -> raise UnallocatedException
  | 0b11101u -> raise UnallocatedException
  | 0b01111u | 0b11111u (* x1111 *) -> raise UnallocatedException
  | _ -> Utils.impossible ()

/// Advanced SIMD two registers and a scalar on page F3-4172.
let parseAdvSIMDTwoRegsAndScalar (itstate: byref<bl>) isInIT mode addr bin l c =
  match concat (pickBit bin 28) (extract bin 11 8) 4 (* Q:opc *) with
  (* VMLA x000x *)
  | 0b00000u ->
    chkSzFSzITQVdVn bin itstate
    let dt = getDTF0 (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLA dt N oprDdDnDmx
  | 0b00001u ->
    chkSzFSzITQVdVn bin itstate
    let dt = getDTF1 (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLA dt N oprDdDnDmx
  | 0b10000u ->
    chkSzFSzITQVdVn bin itstate
    let dt = getDTF0 (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLA dt N oprQdQnDmx
  | 0b10001u ->
    chkSzFSzITQVdVn bin itstate
    let dt = getDTF1 (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLA dt N oprQdQnDmx
  (* VQDMLAL *)
  | 0b00011u ->
    chkSzVd bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQDMLAL dt N oprQdDnDmx
  (* VMLAL x0010 *)
  | 0b00010u ->
    chkSzVd bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLAL dt N oprQdDnDmx
  | 0b10010u ->
    chkSzVd bin
    let dt = getDTUSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLAL dt N oprQdDnDmx
  (* VQDMLSL *)
  | 0b00111u ->
    chkSzVd bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQDMLSL dt N oprQdDnDmx
  (* VMLS x010x *)
  | 0b00100u ->
    chkSzFSzITQVdVn bin itstate
    let dt = getDTF0 (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLS dt N oprDdDnDmx
  | 0b00101u ->
    chkSzFSzITQVdVn bin itstate
    let dt = getDTF1 (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLS dt N oprDdDnDmx
  | 0b10100u ->
    chkSzFSzITQVdVn bin itstate
    let dt = getDTF0 (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLS dt N oprQdQnDmx
  | 0b10101u ->
    chkSzFSzITQVdVn bin itstate
    let dt = getDTF1 (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLS dt N oprQdQnDmx
  (* VQDMULL *)
  | 0b01011u ->
    chkSzVd bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQDMULL dt N oprQdDnDmx
  (* VMLSL x0110 *)
  | 0b00110u ->
    chkSzVd bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLSL dt N oprQdDnDmx
  | 0b10110u ->
    chkSzVd bin
    let dt = getDTUSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMLSL dt N oprQdDnDmx
  (* VMUL x100x *)
  | 0b01000u ->
    chkQVdVn bin
    let dt = getDTF0 (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMUL dt N oprDdDnDmx
  | 0b01001u ->
    chkQVdVn bin
    let dt = getDTF1 (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMUL dt N oprDdDnDmx
  | 0b11000u ->
    chkQVdVn bin
    let dt = getDTF0 (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMUL dt N oprQdQnDmx
  | 0b11001u ->
    chkQVdVn bin
    let dt = getDTF1 (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMUL dt N oprQdQnDmx
  | 0b10011u -> raise UnallocatedException
  (* VMULL x1010 *)
  | 0b01010u ->
    chkSzVd bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMULL dt N oprQdDnDmx
  | 0b11010u ->
    chkSzVd bin
    let dt = getDTUSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VMULL dt N oprQdDnDmx
  | 0b10111u -> raise UnallocatedException
  (* VQDMULH x1100 *)
  | 0b01100u ->
    chkSzQVdVn bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQDMULH dt N oprDdDnDmx
  | 0b11100u ->
    chkSzQVdVn bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQDMULH dt N oprQdQnDmx
  (* VQRDMULH x1101 *)
  | 0b01101u ->
    chkSzQVdVn bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQRDMULH dt N oprDdDnDmx
  | 0b11101u ->
    chkSzQVdVn bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQRDMULH dt N oprQdQnDmx
  | 0b11011u -> raise UnallocatedException
  (* VQRDMLAH x1110 Armv8.1 *)
  | 0b01110u ->
    chkSzQVdVn bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQRDMLAH dt N oprDdDnDmx
  | 0b11110u ->
    chkSzQVdVn bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQRDMLAH dt N oprQdQnDmx
  (* VQRDMLSH x1111 Armv8.1 *)
  | 0b01111u ->
    chkSzQVdVn bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQRDMLSH dt N oprDdDnDmx
  | _ (* 11111 *) ->
    chkSzQVdVn bin
    let dt = getDTSign (extract bin 21 20) |> oneDt
    render &itstate 0 isInIT mode addr bin l c Op.VQRDMLSH dt N oprQdQnDmx

/// Advanced SIMD two registers, or three registers of different lengths
/// on page F3-4168.
let parseAdvSIMDTwoOrThreeRegsDiffLen (itstate: byref<bl>) isInIT m a b l c =
  let decodeFields (* op0:op1:op2:op3 *) =
    (pickBit b 28 <<< 5) + (extract b 21 20 <<< 3) + (extract b 11 10 <<< 1) +
    (pickBit b 6)
  match decodeFields with
  (* VEXT 011xxx *)
  | 0b011000u | 0b011010u | 0b011100u | 0b011110u (* 011xx0 *) ->
    chkQVdVnVmImm4 b
    render &itstate 0 isInIT m a b l c Op.VEXT (oneDt SIMDTyp8) N oprDdDnDmImm
  | 0b011001u | 0b011011u | 0b011101u | 0b011111u (* 011xx1 *) ->
    render &itstate 0 isInIT m a b l c Op.VEXT (oneDt SIMDTyp8) N oprQdQnQmImm
  | 0b111000u | 0b111001u | 0b111010u | 0b111011u (* 1110xx *) ->
    parseAdvSIMDTwoRegsMisc &itstate isInIT m a b l c
  (* VTBL, VTBX 11110x *)
  | 0b111100u ->
    chkNLen b
    render &itstate 0 isInIT m a b l c Op.VTBL (oneDt SIMDTyp8) N oprDdListDm
  | 0b111101u ->
    chkNLen b
    render &itstate 0 isInIT m a b l c Op.VTBX (oneDt SIMDTyp8) N oprDdListDm
  | 0b111110u | 0b111111u (* 11111x *) ->
    parseAdvSIMDDupScalar &itstate isInIT m a b l c
  | _ when pickBit b 6 = 0u (* x != 11 xx 0 *) ->
    parseAdvSIMDThreeRegsDiffLen &itstate isInIT m a b l c
  | _ (* x != 11 xx 1 *) ->
    parseAdvSIMDTwoRegsAndScalar &itstate isInIT m a b l c

/// Advanced SIMD one register and modified immediate on page F3-4173.
let parseAdvSIMDOneRegAndModImm (itstate: byref<bl>) isInIT mode addr bin l c =
  match concat (extract bin 11 8) (pickBit bin 5) 1 (* cmode:op *) with
  | 0b00000u | 0b00100u | 0b01000u | 0b01100u (* 0xx00 *) ->
    chkQVd bin
    let oprs = if pickBit bin 6 = 0u then oprDdImm else oprQdImm
    render &itstate 0 isInIT mode addr bin l c Op.VMOV (oneDt SIMDTypI32) N oprs
  | 0b00001u | 0b00101u | 0b01001u | 0b01101u (* 0xx01 *) ->
    chkQVd bin
    let oprs = if pickBit bin 6 = 0u then oprDdImm else oprQdImm
    render &itstate 0 isInIT mode addr bin l c Op.VMVN (oneDt SIMDTypI32) N oprs
  | 0b00010u | 0b00110u | 0b01010u | 0b01110u (* 0xx10 *) ->
    chkQVd bin
    let oprs = if pickBit bin 6 = 0u then oprDdImm else oprQdImm
    render &itstate 0 isInIT mode addr bin l c Op.VORR (oneDt SIMDTypI32) N oprs
  | 0b00011u | 0b00111u | 0b01011u | 0b01111u (* 0xx11 *) ->
    chkQVd bin
    let oprs = if pickBit bin 6 = 0u then oprDdImm else oprQdImm
    render &itstate 0 isInIT mode addr bin l c Op.VBIC (oneDt SIMDTypI32) N oprs
  | 0b10000u | 0b10100u (* 10x00 *) ->
    chkQVd bin
    let oprs = if pickBit bin 6 = 0u then oprDdImm else oprQdImm
    render &itstate 0 isInIT mode addr bin l c Op.VMOV (oneDt SIMDTypI16) N oprs
  | 0b10001u | 0b10101u (* 10x01 *) ->
    chkQVd bin
    let oprs = if pickBit bin 6 = 0u then oprDdImm else oprQdImm
    render &itstate 0 isInIT mode addr bin l c Op.VMVN (oneDt SIMDTypI16) N oprs
  | 0b10010u | 0b10110u (* 10x10 *) ->
    chkQVd bin
    let oprs = if pickBit bin 6 = 0u then oprDdImm else oprQdImm
    render &itstate 0 isInIT mode addr bin l c Op.VORR (oneDt SIMDTypI16) N oprs
  | 0b10011u | 0b10111u (* 10x11 *) ->
    chkQVd bin
    let oprs = if pickBit bin 6 = 0u then oprDdImm else oprQdImm
    render &itstate 0 isInIT mode addr bin l c Op.VBIC (oneDt SIMDTypI16) N oprs
  (* VMOV 11xx0 *)
  | 0b11000u | 0b11010u ->
    chkQVd bin
    let oprs = if pickBit bin 6 = 0u then oprDdImm else oprQdImm
    render &itstate 0 isInIT mode addr bin l c Op.VMOV (oneDt SIMDTypI32) N oprs
  | 0b11100u ->
    chkQVd bin
    let oprs = if pickBit bin 6 = 0u then oprDdImm else oprQdImm
    render &itstate 0 isInIT mode addr bin l c Op.VMOV (oneDt SIMDTypI8) N oprs
  | 0b11110u ->
    chkQVd bin
    let oprs = if pickBit bin 6 = 0u then oprDdImm else oprQdImm
    render &itstate 0 isInIT mode addr bin l c Op.VMOV (oneDt SIMDTypF32) N oprs
  | 0b11001u | 0b11011u (* 110x1 *) ->
    chkQVd bin
    let oprs = if pickBit bin 6 = 0u then oprDdImm else oprQdImm
    render &itstate 0 isInIT mode addr bin l c Op.VMVN (oneDt SIMDTypI32) N oprs
  | 0b11101u ->
    chkQVd bin
    let oprs = if pickBit bin 6 = 0u then oprDdImm else oprQdImm
    render &itstate 0 isInIT mode addr bin l c Op.VMOV (oneDt SIMDTypI64) N oprs
  | _ (* 11111 *) -> raise UnallocatedException

/// Advanced SIMD two registers and shift amount on page F3-4174.
let parseAdvSIMDTwoRegsAndShfAmt (itstate: byref<bl>) isInIT mode addr bin l c =
  let decodeFields (* U:opc:Q *) =
    (pickBit bin 28 <<< 5) + (extract bin 11 8 <<< 1) + pickBit bin 6
  match decodeFields with
  | _ when concat (extract bin 21 19) (pickBit bin 7) 1 (* imm3H:L *) = 0u ->
    Utils.impossible ()
  (* VSHR x0000x *)
  | 0b000000u | 0b100000u ->
    chkQVdVm bin
    let dt = getDTLImm bin
    render &itstate 0 isInIT mode addr bin l c Op.VSHR dt N oprDdDmImm
  | 0b000001u | 0b100001u ->
    chkQVdVm bin
    let dt = getDTLImm bin
    render &itstate 0 isInIT mode addr bin l c Op.VSHR dt N oprQdQmImm
  (* VSRA x0001x *)
  | 0b000010u | 0b100010u ->
    chkQVdVm bin
    let dt = getDTLImm bin
    render &itstate 0 isInIT mode addr bin l c Op.VSRA dt N oprDdDmImm
  | 0b000011u | 0b100011u ->
    chkQVdVm bin
    let dt = getDTLImm bin
    render &itstate 0 isInIT mode addr bin l c Op.VSRA dt N oprQdQmImm
  (* VMOVL x10100 *)
  | 0b010100u | 0b110100u when extract bin 18 6 (* imm3L *) = 0u ->
    chkVd bin
    let dt = getDTUImm3H bin
    render &itstate 0 isInIT mode addr bin l c Op.VMOVL dt N oprQdDm
  (* VRSHR x0010x *)
  | 0b000100u | 0b100100u ->
    chkQVdVm bin
    let dt = getDTLImm bin
    render &itstate 0 isInIT mode addr bin l c Op.VRSHR dt N oprDdDmImm
  | 0b000101u | 0b100101u ->
    chkQVdVm bin
    let dt = getDTLImm bin
    render &itstate 0 isInIT mode addr bin l c Op.VRSHR dt N oprQdQmImm
  (* VRSRA x0011x *)
  | 0b000110u | 0b100110u ->
    chkQVdVm bin
    let dt = getDTLImm bin
    render &itstate 0 isInIT mode addr bin l c Op.VRSRA dt N oprDdDmImm
  | 0b000111u | 0b100111u ->
    chkQVdVm bin
    let dt = getDTLImm bin
    render &itstate 0 isInIT mode addr bin l c Op.VRSRA dt N oprQdQmImm
  (* VQSHL x0111x *)
  | 0b001110u | 0b101110u ->
    chkQVdVm bin
    let dt = getDTLImm bin
    render &itstate 0 isInIT mode addr bin l c Op.VQSHL dt N oprDdDmImmLeft
  | 0b001111u | 0b101111u ->
    chkQVdVm bin
    let dt = getDTLImm bin
    render &itstate 0 isInIT mode addr bin l c Op.VQSHL dt N oprQdQmImmLeft
  (* VQSHRN x10010 *)
  | 0b010010u | 0b110010u ->
    chkVm bin
    let dt = getDTImm6Word bin
    render &itstate 0 isInIT mode addr bin l c Op.VQSHRN dt N oprDdQmImm
  (* VQRSHRN x10011 *)
  | 0b010011u | 0b110011u ->
    chkVm bin
    let dt = getDTImm6Word bin
    render &itstate 0 isInIT mode addr bin l c Op.VQRSHRN dt N oprDdQmImm
  (* VSHLL x10100 *)
  | 0b010100u | 0b110100u ->
    chkVd bin
    let dt = getDTImm6Byte bin
    render &itstate 0 isInIT mode addr bin l c Op.VSHLL dt N oprQdDmImm
  (* VCVT x11xxx *)
  | b when b &&& 0b011001u = 0b011000u ->
    chkOpImm6QVdVm bin
    let dt = getDTOpU bin
    render &itstate 0 isInIT mode addr bin l c Op.VCVT dt N oprDdDmFbits
  | b when b &&& 0b011001u = 0b011001u ->
    chkOpImm6QVdVm bin
    let dt = getDTOpU bin
    render &itstate 0 isInIT mode addr bin l c Op.VCVT dt N oprQdQmFbits
  (* VSHL 00101x *)
  | 0b001010u ->
    chkQVdVm bin
    let dt = getDTImm6 bin
    render &itstate 0 isInIT mode addr bin l c Op.VSHL dt N oprDdDmImm
  | 0b001011u ->
    chkQVdVm bin
    let dt = getDTImm6 bin
    render &itstate 0 isInIT mode addr bin l c Op.VSHL dt N oprQdQmImm
  (* VSHRN 010000 *)
  | 0b010000u ->
    chkVm bin
    let dt = getDTImm6Int bin
    render &itstate 0 isInIT mode addr bin l c Op.VSHRN dt N oprDdQmImm
  (* VRSHRN 010001 *)
  | 0b010001u ->
    chkVm bin
    let dt = getDTImm6Int bin
    render &itstate 0 isInIT mode addr bin l c Op.VRSHRN dt N oprDdQmImm
  (* VSRI 10100x *)
  | 0b101000u ->
    chkQVdVm bin
    let dt = getDTImm6 bin
    render &itstate 0 isInIT mode addr bin l c Op.VSRI dt N oprDdDmImm
  | 0b101001u ->
    chkQVdVm bin
    let dt = getDTImm6 bin
    render &itstate 0 isInIT mode addr bin l c Op.VSRI dt N oprQdQmImm
  (* VSLI 10101x *)
  | 0b101010u ->
    chkQVdVm bin
    let dt = getDTImm6 bin
    render &itstate 0 isInIT mode addr bin l c Op.VSLI dt N oprDdDmImmLeft
  | 0b101011u ->
    chkQVdVm bin
    let dt = getDTImm6 bin
    render &itstate 0 isInIT mode addr bin l c Op.VSLI dt N oprQdQmImmLeft
  (* VQSHLU 10110x *)
  | 0b101100u ->
    chkUOpQVdVm bin
    let dt = getDTLImm bin
    render &itstate 0 isInIT mode addr bin l c Op.VQSHLU dt N oprDdDmImmLeft
  | 0b101101u ->
    chkUOpQVdVm bin
    let dt = getDTLImm bin
    render &itstate 0 isInIT mode addr bin l c Op.VQSHLU dt N oprQdQmImmLeft
  (* VQSHRUN 110000 *)
  | 0b110000u ->
    chkVm bin
    let dt = getDTImm6Word bin
    render &itstate 0 isInIT mode addr bin l c Op.VQSHRUN dt N oprDdQmImm
  (* VQRSHRUN 110001 *)
  | 0b110001u ->
    chkVm bin
    let dt = getDTImm6Word bin
    render &itstate 0 isInIT mode addr bin l c Op.VQRSHRUN dt N oprDdQmImm
  | _ -> Utils.futureFeature ()

/// Advanced SIMD shifts and immediate generation on page F3-4173.
let parseAdvSIMDShfsAndImmGen (itstate: byref<bl>) isInIT mode addr bin len c =
  if concat (extract bin 21 19) (pickBit bin 7) 1 = 0b0000u then
    parseAdvSIMDOneRegAndModImm &itstate isInIT mode addr bin len c
  else parseAdvSIMDTwoRegsAndShfAmt &itstate isInIT mode addr bin len c

/// Advanced SIMD data-processing on page F3-4165.
let parseAdvSIMDDataProcess (itstate: byref<bl>) isInIT mode addr bin len cond =
  match concat (pickBit bin 23) (pickBit bin 4) 1 (* op0:op1 *) with
  | 0b00u | 0b01u ->
    parseAdvSIMDThreeRegsOfSameLen &itstate isInIT mode addr bin len cond
  | 0b10u ->
    parseAdvSIMDTwoOrThreeRegsDiffLen &itstate isInIT mode addr bin len cond
  | _ (* 11 *) ->
    parseAdvSIMDShfsAndImmGen &itstate isInIT mode addr bin len cond

/// Advanced SIMD and floating-point 64-bit move on page F3-4175.
let parseAdvSIMDAndFP64BitMove (itstate: byref<bl>) isInIT mode addr bin len c =
  let decodeFields (* D:op:size:opc2:o3 *) =
    (pickBit bin 22 <<< 6) + (pickBit bin 20 <<< 5) + (extract bin 9 6 <<< 1) +
    (pickBit bin 4)
  match decodeFields with
  | b when b &&& 0b1000000u = 0b0000000u (* 0xxxxxx *) ->
    raise UnallocatedException
  | b when b &&& 0b1000001u = 0b1000000u (* 1xxxxx0 *) ->
    raise UnallocatedException
  | b when b &&& 0b1010111u = 0b1000001u (* 1x0x001 *) ->
    raise UnallocatedException
  | b when b &&& 0b1000110u = 0b1000010u (* 1xxx01x *) ->
    raise UnallocatedException
  | 0b1010001u (* 1010001 *) ->
    chkPCRtRt2VmArmEq bin
    render &itstate 0 isInIT mode addr bin len c Op.VMOV None N oprSmSm1RtRt2
  | 0b1011001u (* 1011001 *) ->
    chkPCRtRt2ArmEq bin
    render &itstate 0 isInIT mode addr bin len c Op.VMOV None N oprDmRtRt2
  | b when b &&& 0b1000100u = 0b1000100u (* 1xxx1xx *) ->
    raise UnallocatedException
  | 0b1110001u (* 1110001 *) ->
    chkPCRtRt2VmArmEq bin
    render &itstate 0 isInIT mode addr bin len c Op.VMOV None N oprRtRt2SmSm1
  | _ (* 1111001 *) ->
    chkPCRtRt2ArmEq bin
    render &itstate 0 isInIT mode addr bin len c Op.VMOV None N oprRtRt2Dm

/// System register 64-bit move on page F3-4176.
let parseSystemReg64BitMove (itstate: byref<bl>) isInIT mode addr bin l c =
  match concat (pickBit bin 22) (pickBit bin 20) 1 (* D:L *) with
  | 0b00u | 0b01u -> raise UnallocatedException
  | 0b10u ->
    chkPCRtRt2 bin
    render &itstate 0 isInIT mode addr bin l c Op.MCRR None N oprCpOpc1RtRt2CRm
  | _ (* 10 *) ->
    chkPCRtRt2Eq bin
    render &itstate 0 isInIT mode addr bin l c Op.MRRC None N oprCpOpc1RtRt2CRm

/// Advanced SIMD and floating-point load/store on page F3-4176.
let parseAdvSIMDAndFPLdSt (itstate: byref<bl>) isInIT mode addr bin len c =
  let isNot1111 = extract bin 19 16 (* Rn *) <> 0b1111u
  let isxxxxxxx0 = pickBit bin 0 (* imm8<0> *) = 0u
  let decodeFields (* P:U:W:L:size *) =
    (extract bin 24 23 <<< 4) + (extract bin 21 20 <<< 2) + (extract bin 9 8)
  match decodeFields with
  | b when b &&& 0b111000u = 0b001000u (* 001xxx *) ->
    raise UnallocatedException
  | b when b &&& 0b110010u = 0b010000u (* 01xx0x *) ->
    raise UnallocatedException
  | 0b010010u | 0b011010u (* 01x010 *) ->
    chkPCRnDRegs bin
    render &itstate 0 isInIT mode addr bin len c Op.VSTMIA None N oprRnSreglist
  | 0b010011u | 0b011011u (* 01x011 *) when isxxxxxxx0 ->
    chkPCRnRegsImm bin
    render &itstate 0 isInIT mode addr bin len c Op.VSTMIA None N oprRnDreglist
  | 0b010011u | 0b011011u (* 01x011 *) ->
    chkPCRnRegsImm bin
    render &itstate 0 isInIT mode addr bin len c Op.FSTMIAX None N oprRnDreglist
  | 0b010110u | 0b011110u (* 01x110 *) ->
    chkPCRnDRegs bin
    render &itstate 0 isInIT mode addr bin len c Op.VLDMIA None N oprRnSreglist
  | 0b010111u | 0b011111u (* 01x111 *) when isxxxxxxx0 ->
    chkPCRnRegsImm bin
    render &itstate 0 isInIT mode addr bin len c Op.VLDMIA None N oprRnDreglist
  | 0b010111u | 0b011111u (* 01x111 *) ->
    chkPCRnRegsImm bin
    render &itstate 0 isInIT mode addr bin len c Op.FLDMIAX None N oprRnDreglist
  (* VSTR 1x00xx *)
  | 0b100000u | 0b110000u (* size = 00 *) -> raise UndefinedException
  | 0b100001u | 0b110001u ->
    chkSzIT bin itstate
    let dt = oneDt SIMDTyp16
    render &itstate 0 isInIT mode addr bin len c Op.VSTR dt N oprSdMem
  | 0b100010u | 0b110010u ->
    chkSz01IT bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.VSTR None N oprSdMem
  | 0b100011u | 0b110011u ->
    chkSz01IT bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.VSTR None N oprDdMem
  (* VLDR 1x01xx *)
  | 0b100100u | 0b110100u when isNot1111 -> raise UndefinedException
  | 0b100101u | 0b110101u when isNot1111 ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTyp16
    render &itstate 0 isInIT mode addr bin len c Op.VLDR dt N oprSdMem
  | 0b100110u | 0b110110u when isNot1111 ->
    chkSz01IT bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.VLDR None N oprSdMem
  | 0b100111u | 0b110111u when isNot1111 ->
    chkSz01IT bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.VLDR None N oprDdMem
  | 0b101000u | 0b101001u | 0b101100u | 0b101101u (* 101x0x *) ->
    raise UnallocatedException
  | 0b101010u ->
    chkPCRnDRegs bin
    render &itstate 0 isInIT mode addr bin len c Op.VSTMDB None N oprRnSreglist
  | 0b101011u when isxxxxxxx0 ->
    chkPCRnRegsImm bin
    render &itstate 0 isInIT mode addr bin len c Op.VSTMDB None N oprRnDreglist
  | 0b101011u ->
    chkPCRnRegsImm bin
    render &itstate 0 isInIT mode addr bin len c Op.FSTMDBX None N oprRnDreglist
  | 0b101110u ->
    chkPCRnDRegs bin
    render &itstate 0 isInIT mode addr bin len c Op.VLDMDB None N oprRnSreglist
  | 0b101111u when isxxxxxxx0 ->
    chkPCRnRegsImm bin
    render &itstate 0 isInIT mode addr bin len c Op.VLDMDB None N oprRnDreglist
  | 0b101111u ->
    chkPCRnRegsImm bin
    render &itstate 0 isInIT mode addr bin len c Op.FLDMDBX None N oprRnDreglist
  (* VLDR 1x01xx *)
  | 0b100100u | 0b110100u (* size = 00 *) -> raise UndefinedException
  | 0b100101u | 0b110101u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTyp16
    render &itstate 0 isInIT mode addr bin len c Op.VLDR dt N oprSdMem
  | 0b100110u | 0b110110u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTyp32
    render &itstate 0 isInIT mode addr bin len c Op.VLDR dt N oprSdMem
  | 0b100111u | 0b110111u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTyp64
    render &itstate 0 isInIT mode addr bin len c Op.VLDR dt N oprDdMem
  | b when b &&& 0b111000u = 0b111000u (* 111xxx *) ->
    raise UnallocatedException
  | _ -> Utils.impossible ()

/// System register Load/Store on page F3-4177.
let parseSystemRegLdSt (itstate: byref<bl>) isInIT mode addr bin len c =
  let puw = concat (extract bin 24 23) (pickBit bin 21) 1 (* P:U:W *)
  let rn = extract bin 19 16 (* Rn *)
  let crd = extract bin 15 12 (* CRd *)
  let decodeField1 = (* D:L:cp15 *)
    (pickBit bin 22 <<< 2) + (pickBit bin 20 <<< 1) + (pickBit bin 8)
  let decodeField2 = (* P:U:W:D:L:CRd:cp15 *)
    (puw <<< 7) + (pickBit bin 22 <<< 6) + (pickBit bin 20 <<< 5) + (crd <<< 1)
    + (pickBit bin 8)
  match decodeField1 (* D:L:cp15 *) with
  | 0b000u | 0b010u | 0b100u | 0b110u (* xx0 *)
    when puw <> 0b000u && crd <> 0b0101u -> raise UnallocatedException
  | 0b010u when puw <> 0b000u && rn = 0b1111u && crd = 0b0101u ->
    (* if W == '1' then UNPREDICTABLE *)
    pickBit bin 21 = 1u |> checkUnpred
    render &itstate 0 isInIT mode addr bin len c Op.LDC None N oprP14C5Label
  | 0b001u | 0b001u | 0b011u | 0b111u (* xx1 *) when puw <> 0b000u ->
    raise UnallocatedException
  | 0b100u | 0b110u (* 1x0 *) when puw <> 0b000u && crd = 0b0101u ->
    raise UnallocatedException
  | _ ->
    match decodeField2 (* P:U:W:D:L:CRd:cp15 *) with
    | 0b0010001010u | 0b0110001010u (* 0x10001010 *) ->
      chkPCRnWback bin
      render &itstate 0 isInIT mode addr bin len c Op.STC None N oprP14C5Mem
    | 0b0010101010u | 0b0110101010u (* 0x10101010 *) when rn <> 0b1111u ->
      render &itstate 0 isInIT mode addr bin len c Op.LDC None N oprP14C5Mem
    | 0b0100001010u ->
      chkPCRnWback bin
      render &itstate 0 isInIT mode addr bin len c Op.STC None N oprP14C5Option
    | 0b0100101010u when rn <> 0b1111u ->
      render &itstate 0 isInIT mode addr bin len c Op.LDC None N oprP14C5Option
    | 0b1000001010u | 0b1100001010u (* 1x00001010 *) ->
      chkPCRnWback bin
      render &itstate 0 isInIT mode addr bin len c Op.STC None N oprP14C5Mem
    | 0b1000101010u | 0b1100101010u (* 1x00101010 *) when rn <> 0b1111u ->
      render &itstate 0 isInIT mode addr bin len c Op.LDC None N oprP14C5Mem
    | 0b1010001010u | 0b1110001010u (* 1x10001010 *) ->
      chkPCRnWback bin
      render &itstate 0 isInIT mode addr bin len c Op.STC None N oprP14C5Mem
    | 0b1010101010u | 0b1110101010u (* 1x10101010 *) when rn <> 0b1111u ->
      render &itstate 0 isInIT mode addr bin len c Op.LDC None N oprP14C5Mem
    | _ -> Utils.impossible ()

/// Advanced SIMD and System register load/store and 64-bit move
/// on page F3-4174.
let parseAdvSIMDAndSysRegLdStAnd64BitMov (itstate: byref<bl>) isInIT m a b l c =
  let is00x0 = extract b 24 21 &&& 0b1101u = 0b0000u (* op0 *)
  match extract b 10 9 (* op1 *) with
  | 0b00u | 0b01u (* 0x *) when is00x0 ->
    parseAdvSIMDAndFP64BitMove &itstate isInIT m a b l c
  | 0b11u when is00x0 -> parseSystemReg64BitMove &itstate isInIT m a b l c
  | 0b00u | 0b01u (* 0x *) -> parseAdvSIMDAndFPLdSt &itstate isInIT m a b l c
  | 0b11u -> parseSystemRegLdSt &itstate isInIT m a b l c
  | _ (* 10 *) -> raise UnallocatedException

/// Floating-point data-processing (two registers) on page F3-4178.
let parseFPDataProcTwoRegs (itstate: byref<bl>) isInIT mode addr bin len cond =
  match (extract bin 19 16 <<< 3) + (extract bin 9 7) (* o1:opc2:size:o3 *) with
  | b when b &&& 0b0000110u = 0u (* xxxx00x *) -> raise UnallocatedException
  | 0b0000010u -> raise UnallocatedException
  (* VABS 0000xx1 *)
  | 0b0000001u (* size = 00 *) -> raise UndefinedException
  | 0b0000011u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VABS dt N oprSdSm
  | 0b0000101u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VABS dt N oprSdSm
  | 0b0000111u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VABS dt N oprDdDm
  (* VMOV *)
  | 0b0000100u ->
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VMOV dt N oprSdSm
  | 0b0000110u ->
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VMOV dt N oprDdDm
  (* VNEG 0001xx0 *)
  | 0b0001000u (* size = 00 *) -> raise UndefinedException
  | 0b0001010u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VNEG dt N oprSdSm
  | 0b0001100u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VNEG dt N oprSdSm
  | 0b0001110u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VNEG dt N oprDdDm
  (* VSQRT 0001xx1 *)
  | 0b0001001u (* size = 00 *) -> raise UndefinedException
  | 0b0001011u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VSQRT dt N oprSdSm
  | 0b0001101u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VSQRT dt N oprSdSm
  | 0b0001111u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VSQRT dt N oprDdDm
  (* VCVTB 0010xx0 *)
  | 0b0010100u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTB dt N oprSdSm
  | 0b0010110u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTB dt N oprDdSm
  | 0b0010010u | 0b0010011u (* 001001x *) -> raise UnallocatedException
  (* VCVTT 0010xx1 *)
  | 0b0010101u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTT dt N oprSdSm
  | 0b0010111u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTT dt N oprDdSm
  | 0b0011010u -> (* Armv8.6 *)
    let dt = twoDt (BF16, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTB dt N oprSdSm
  | 0b0011011u -> (* Armv8.6 *)
    let dt = twoDt (BF16, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTT dt N oprSdSm
  | 0b0011100u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTB dt N oprSdSm
  | 0b0011101u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTT dt N oprSdSm
  | 0b0011110u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF64)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTB dt N oprSdDm
  | 0b0011111u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF64)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTT dt N oprSdDm
  (* VCMP 0100xx0 *)
  | 0b0100000u (* size = 00 *) -> raise UndefinedException
  | 0b0100010u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VCMP dt N oprSdSm
  | 0b0100100u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VCMP dt N oprSdSm
  | 0b0100110u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VCMP dt N oprDdDm
  (* 0100xx1 VCMPE *)
  | 0b0100001u (* size = 00 *) -> raise UndefinedException
  | 0b0100011u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VCMPE dt N oprSdSm
  | 0b0100101u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VCMPE dt N oprSdSm
  | 0b0100111u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VCMPE dt N oprDdDm
  (* 0101xx0 VCMP *)
  | 0b0101000u (* size = 00 *) -> raise UndefinedException
  | 0b0101010u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VCMP dt N oprSdImm0
  | 0b0101100u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VCMP dt N oprSdImm0
  | 0b0101110u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VCMP dt N oprDdImm0
  (* 0101xx1 VCMPE *)
  | 0b0101001u (* size = 00 *) -> raise UndefinedException
  | 0b0101011u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VCMPE dt N oprSdImm0
  | 0b0101101u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VCMPE dt N oprSdImm0
  | 0b0101111u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VCMPE dt N oprDdImm0
  (* 0110xx0 VRINTR ARMv8 *)
  | 0b0110010u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VRINTR dt N oprSdSm
  | 0b0110100u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VRINTR dt N oprSdSm
  | 0b0110110u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VRINTR dt N oprDdDm
  (* 0110xx1 VRINTZ ARMv8 *)
  | 0b0110001u (* size = 00 *) -> raise UndefinedException
  | 0b0110011u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VRINTZ dt N oprSdSm
  | 0b0110101u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VRINTZ dt N oprSdSm
  | 0b0110111u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VRINTZ dt N oprDdDm
  (* 0111xx0 VRINTX ARMv8 *)
  | 0b0111000u (* size = 00 *) -> raise UndefinedException
  | 0b0111010u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VRINTX dt N oprSdSm
  | 0b0111100u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VRINTX dt N oprSdSm
  | 0b0111110u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VRINTX dt N oprDdDm
  | 0b0111011u -> raise UnallocatedException
  | 0b0111101u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprDdSm
  | 0b0111111u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF64)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdDm
  (* 1000xxx VCVT *)
  | 0b1000000u | 0b1000001u (* size = 00 *) -> raise UndefinedException
  | 0b1000010u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF16, SIMDTypU32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdSm
  | 0b1000011u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF16, SIMDTypS32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdSm
  | 0b1000100u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdSm
  | 0b1000101u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdSm
  | 0b1000110u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF64, SIMDTypU32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprDdSm
  | 0b1000111u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF64, SIMDTypS32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprDdSm
  | 0b1001010u | 0b1001011u (* 100101x *) -> raise UnallocatedException
  | 0b1001100u | 0b1001101u (* 100110x *) -> raise UnallocatedException
  | 0b1001110u -> raise UnallocatedException
  | 0b1001111u -> (* Armv8.3 *)
    inITBlock itstate |> checkUnpred
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render &itstate 0 isInIT mode addr bin len cond Op.VJCVT dt N oprSdDm
  (* 101xxxx Op.VCVT *)
  | 0b1010000u | 0b1010001u | 0b1011000u | 0b1011001u (* sf = 00 *) ->
    raise UndefinedException
  | 0b1010010u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF16, SIMDTypS16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1010011u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF16, SIMDTypS32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1011010u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF16, SIMDTypU16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1011011u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF16, SIMDTypU32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1010100u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF32, SIMDTypS16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1010101u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1011100u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF32, SIMDTypU16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1011101u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1010110u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF64, SIMDTypS16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprDdmDdmFbits
  | 0b1010111u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF64, SIMDTypS32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprDdmDdmFbits
  | 0b1011110u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF64, SIMDTypU16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprDdmDdmFbits
  | 0b1011111u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypF64, SIMDTypU32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprDdmDdmFbits
  (* 1100xx0 VCVTR *)
  | 0b1100000u (* size = 00 *) -> raise UndefinedException
  | 0b1100010u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTR dt N oprSdSm
  | 0b1100100u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTR dt N oprSdSm
  | 0b1100110u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTR dt N oprSdDm
  (* 1100xx1 VCVT *)
  | 0b1100001u (* size = 00 *) -> raise UndefinedException
  | 0b1100011u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdSm
  | 0b1100101u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdSm
  | 0b1100111u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdDm
  (* 1101xx0 VCVTR *)
  | 0b1101000u (* size = 00 *) -> raise UndefinedException
  | 0b1101010u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTR dt N oprSdSm
  | 0b1101100u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTR dt N oprSdSm
  | 0b1101110u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTR dt N oprSdDm
  (* 1101xx1u VCVT *)
  | 0b1101001u (* size = 00 *) -> raise UndefinedException
  | 0b1101011u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdSm
  | 0b1101101u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdSm
  | 0b1101111u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdDm
  (* 111xxxx VCVT *)
  | 0b1110000u | 0b1110001u | 0b1111000u | 0b1111001u (* size = 00 *) ->
    raise UndefinedException
  | 0b1110010u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1110011u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1111010u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1111011u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1110100u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypS16, SIMDTypF32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1110101u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1111100u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypU16, SIMDTypF32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1111101u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprSdmSdmFbits
  | 0b1110110u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypS16, SIMDTypF64)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprDdmDdmFbits
  | 0b1110111u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprDdmDdmFbits
  | 0b1111110u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypU16, SIMDTypF64)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprDdmDdmFbits
  | 0b1111111u ->
    chkSz01IT bin itstate
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render &itstate 0 isInIT mode addr bin len cond Op.VCVT dt N oprDdmDdmFbits
  | _ -> Utils.impossible ()

/// Floating-point move immediate on page F3-4180.
let parseFPMoveImm (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 9 8 (* size *) with
  | 0b00u -> raise UnallocatedException
  | 0b01u -> (* Armv8.2 *)
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VMOV dt N oprSdVImm
  | 0b10u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VMOV dt N oprSdVImm
  | _ (* 11 *) ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VMOV dt N oprDdVImm

/// Floating-point data-processing (three registers) on page F3-4180.
let parseFPDataProcThreeRegs (itstate: byref<bl>) isInIT mode addr bin len c =
  let decodeFields (* o0:o1:size:o2 *) =
    (pickBit bin 23 <<< 5) + (extract bin 21 20 <<< 3) + (extract bin 9 8 <<< 1)
    + (pickBit bin 6)
  match decodeFields with
  | b when (b >>> 3 <> 0b111u) && (b &&& 0b000110u = 0b000u) (* != 111 00x *) ->
    raise UnallocatedException
  (* 000xx0 VMLA *)
  | 0b000000u (* size = 00 *) -> raise UndefinedException
  | 0b000010u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len c Op.VMLA dt N oprSdSnSm
  | 0b000100u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len c Op.VMLA dt N oprSdSnSm
  | 0b000110u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len c Op.VMLA dt N oprDdDnDm
  (* 000xx1 VMLS *)
  | 0b000001u (* size = 00 *) -> raise UndefinedException
  | 0b000011u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len c Op.VMLS dt N oprSdSnSm
  | 0b000101u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len c Op.VMLS dt N oprSdSnSm
  | 0b000111u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len c Op.VMLS dt N oprDdDnDm
  (* 001xx0 VNMLS *)
  | 0b001000u (* size = 00 *) -> raise UndefinedException
  | 0b001010u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len c Op.VNMLS dt N oprSdSnSm
  | 0b001100u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len c Op.VNMLS dt N oprSdSnSm
  | 0b001110u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len c Op.VNMLS dt N oprDdDnDm
  (* 001xx1 VNMLA *)
  | 0b001001u (* size = 00 *) -> raise UndefinedException
  | 0b001011u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len c Op.VNMLA dt N oprSdSnSm
  | 0b001101u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len c Op.VNMLA dt N oprSdSnSm
  | 0b001111u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len c Op.VNMLA dt N oprDdDnDm
  (* 010xx0 VMUL *)
  | 0b010000u (* size = 00 *) -> raise UndefinedException
  | 0b010010u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len c Op.VMUL dt N oprSdSnSm
  | 0b010100u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len c Op.VMUL dt N oprSdSnSm
  | 0b010110u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len c Op.VMUL dt N oprDdDnDm
  (* 010xx1 VNMUL *)
  | 0b010001u (* size = 00 *) -> raise UndefinedException
  | 0b010011u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len c Op.VNMUL dt N oprSdSnSm
  | 0b010101u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len c Op.VNMUL dt N oprSdSnSm
  | 0b010111u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len c Op.VNMUL dt N oprDdDnDm
  (* 011xx0 VADD *)
  | 0b011000u (* size = 00 *) -> raise UndefinedException
  | 0b011010u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len c Op.VADD dt N oprSdSnSm
  | 0b011100u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len c Op.VADD dt N oprSdSnSm
  | 0b011110u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len c Op.VADD dt N oprDdDnDm
  (* 011xx1 VSUB *)
  | 0b011001u (* size = 00 *) -> raise UndefinedException
  | 0b011011u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len c Op.VSUB dt N oprSdSnSm
  | 0b011101u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len c Op.VSUB dt N oprSdSnSm
  | 0b011111u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len c Op.VSUB dt N oprDdDnDm
  (* 100xx0 VDIV *)
  | 0b100000u (* size = 00 *) -> raise UndefinedException
  | 0b100010u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len c Op.VDIV dt N oprSdSnSm
  | 0b100100u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len c Op.VDIV dt N oprSdSnSm
  | 0b100110u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len c Op.VDIV dt N oprDdDnDm
  (* 101xx0 VFNMS *)
  | 0b101000u (* size = 00 *) -> raise UndefinedException
  | 0b101010u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len c Op.VFNMS dt N oprSdSnSm
  | 0b101100u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len c Op.VFNMS dt N oprSdSnSm
  | 0b101110u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len c Op.VFNMS dt N oprDdDnDm
  (* 101xx1 VFNMA *)
  | 0b101001u (* size = 00 *) -> raise UndefinedException
  | 0b101011u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len c Op.VFNMA dt N oprSdSnSm
  | 0b101101u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len c Op.VFNMA dt N oprSdSnSm
  | 0b101111u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len c Op.VFNMA dt N oprDdDnDm
  (* 110xx0 VFMA *)
  | 0b110000u (* size = 00 *) -> raise UndefinedException
  | 0b110010u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len c Op.VFMA dt N oprSdSnSm
  | 0b110100u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len c Op.VFMA dt N oprSdSnSm
  | 0b110110u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len c Op.VFMA dt N oprDdDnDm
  (* 110xx1 VFMS *)
  | 0b110001u (* size = 00 *) -> raise UndefinedException
  | 0b110011u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len c Op.VFMS dt N oprSdSnSm
  | 0b110101u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len c Op.VFMS dt N oprSdSnSm
  | 0b110111u ->
    chkSz01IT bin itstate
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len c Op.VFMS dt N oprDdDnDm
  | _ -> Utils.impossible ()

/// Floating-point data-processing on page F3-4178.
let parseFPDataProcessing (itstate: byref<bl>) isInIT mode addr bin len cond =
  match concat (extract bin 23 20) (pickBit bin 6) 1 (* op0:op1 *) with
  | 0b10111u | 0b11111u (* 1x111 *) ->
    parseFPDataProcTwoRegs &itstate isInIT mode addr bin len cond
  | 0b10110u | 0b11110u (* 1x110 *) ->
    parseFPMoveImm &itstate isInIT mode addr bin len cond
  | _ (* != 1x11 x *) ->
    parseFPDataProcThreeRegs &itstate isInIT mode addr bin len cond

/// Floating-point move special register on page F3-4182.
let parseFPMoveSpecialReg (itstate: byref<bl>) isInIT mode addr bin len cond =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
    chkPCRt bin
    render &itstate 0 isInIT mode addr bin len cond Op.VMSR None N oprSregRt
  | _ (* 0b1u *) ->
    chkPCRt bin
    render &itstate 0 isInIT mode addr bin len cond Op.VMRS None N oprRtSreg

/// Advanced SIMD 8/16/32-bit element move/duplicate on page F3-4182.
let parseAdvSIMD8n16n32BitElemMoveDup (itstate: byref<bl>) isInIT m a b l c =
  match concat (extract b 23 20) (extract b 6 5) 2 (* opc1:L:opc2 *) with
  (* 0xx0xx VMOV (general-purpose register to scalar) *)
  | 0b010000u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp8) N oprDd0Rt
  | 0b010001u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp8) N oprDd1Rt
  | 0b010010u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp8) N oprDd2Rt
  | 0b010011u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp8) N oprDd3Rt
  | 0b011000u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp8) N oprDd4Rt
  | 0b011001u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp8) N oprDd5Rt
  | 0b011010u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp8) N oprDd6Rt
  | 0b011011u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp8) N oprDd7Rt
  | 0b000001u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp16) N oprDd0Rt
  | 0b000011u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp16) N oprDd1Rt
  | 0b001001u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp16) N oprDd2Rt
  | 0b001011u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp16) N oprDd3Rt
  | 0b000000u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp32) N oprDd0Rt
  | 0b001000u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp32) N oprDd1Rt
  | 0b000010u | 0b001010u -> raise UndefinedException
  (* xxx1xx VMOV (scalar to general-purpose register) *)
  | 0b010100u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypS8) N oprRtDn0
  | 0b010101u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypS8) N oprRtDn1
  | 0b010110u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypS8) N oprRtDn2
  | 0b010111u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypS8) N oprRtDn3
  | 0b011100u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypS8) N oprRtDn4
  | 0b011101u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypS8) N oprRtDn5
  | 0b011110u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypS8) N oprRtDn6
  | 0b011111u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypS8) N oprRtDn7
  | 0b110100u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypU8) N oprRtDn0
  | 0b110101u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypU8) N oprRtDn1
  | 0b110110u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypU8) N oprRtDn2
  | 0b110111u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypU8) N oprRtDn3
  | 0b111100u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypU8) N oprRtDn4
  | 0b111101u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypU8) N oprRtDn5
  | 0b111110u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypU8) N oprRtDn6
  | 0b111111u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypU8) N oprRtDn7
  | 0b000101u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypS16) N oprRtDn0
  | 0b000111u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypS16) N oprRtDn1
  | 0b001101u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypS16) N oprRtDn2
  | 0b001111u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypS16) N oprRtDn3
  | 0b100101u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypU16) N oprRtDn0
  | 0b100111u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypU16) N oprRtDn1
  | 0b101101u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypU16) N oprRtDn2
  | 0b101111u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTypU16) N oprRtDn3
  | 0b000100u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp32) N oprRtDn0
  | 0b001100u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VMOV (oneDt SIMDTyp32) N oprRtDn1
  | 0b100100u | 0b101100u (* 10x100 *)
  | 0b000110u | 0b001110u | 0b100110u | 0b101110u (* x0x110 *) ->
    raise UndefinedException
  (* 1xx00x VDUP (general-purpose register) *)
  | 0b110000u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VDUP (oneDt SIMDTyp8) N oprDdRt
  | 0b100001u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VDUP (oneDt SIMDTyp16) N oprDdRt
  | 0b100000u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VDUP (oneDt SIMDTyp32) N oprDdRt
  | 0b111000u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VDUP (oneDt SIMDTyp8) N oprQdRt
  | 0b101001u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VDUP (oneDt SIMDTyp16) N oprQdRt
  | 0b101000u ->
    chkPCRt b
    render &itstate 0 isInIT m a b l c Op.VDUP (oneDt SIMDTyp32) N oprQdRt
  | 0b111001u | 0b110001u -> raise UndefinedException
  | _ (* 1xx01x *) -> raise UnallocatedException

/// System register 32-bit move on page F3-4183.
let parseSystemReg32BitMove (itstate: byref<bl>) isInIT m addr bin l c =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
    chkPCRt bin
    render &itstate 0 isInIT m addr bin l c Op.MCR None N oprCpOpc1RtCRnCRmOpc2
  | _ (* 1 *) ->
    render &itstate 0 isInIT m addr bin l c Op.MRC None N oprCpOpc1RtCRnCRmOpc2

/// Advanced SIMD and System register 32-bit move on page F3-4181.
let parseAdvSIMDAndSysReg32BitMov (itstate: byref<bl>) isInIT m addr bin len c =
  match concat (extract bin 23 21) (extract bin 10 8) 3 (* op0:op1 *) with
  | 0b000000u -> raise UnallocatedException
  | 0b000001u -> (* Armv8.2 *)
    inITBlock itstate |> checkUnpred
    let oprs = if pickBit bin 20 = 0u then oprSnRt else oprRtSn
    render &itstate 0 isInIT m addr bin len c Op.VMOV (oneDt SIMDTypF16) N oprs
  | 0b000010u ->
    chkPCRt bin
    let oprs = if pickBit bin 20 = 0u then oprSnRt else oprRtSn
    render &itstate 0 isInIT m addr bin len c Op.VMOV None N oprs
  | 0b001010u -> raise UnallocatedException
  | 0b010010u | 0b011010u (* 01x010 *) -> raise UnallocatedException
  | 0b100010u | 0b101010u (* 10x010 *) -> raise UnallocatedException
  | 0b110010u -> raise UnallocatedException
  | 0b111010u -> parseFPMoveSpecialReg &itstate isInIT m addr bin len c
  | b when b &&& 0b000111u = 0b000011u (* xxx011 *) ->
    parseAdvSIMD8n16n32BitElemMoveDup &itstate isInIT m addr bin len c
  | b when b &&& 0b000110u = 0b000100u (* xxx10x *) ->
    raise UnallocatedException
  | b when b &&& 0b000110u = 0b000110u (* xxx11x *) ->
    parseSystemReg32BitMove &itstate isInIT m addr bin len c
  | _ -> Utils.impossible ()

/// Advanced SIMD three registers of the same length extension on page F3-4184.
let parseAdvSIMDThreeRegSameLenExt (itstate: byref<bl>) isInIT m a b l c =
  let decodeFields (* op1:op2:op3:op4:Q:U *) =
    (extract b 24 23 <<< 6) + (extract b 21 20 <<< 4) + (pickBit b 10 <<< 3) +
    (pickBit b 8 <<< 2) + (pickBit b 6 <<< 1) + (pickBit b 4)
  match decodeFields with
  (* VCADD 64-bit x10x0000 Armv8.3 *)
  | 0b01000000u | 0b11000000u (* x1000000 *) ->
    chkITQVdVnVm b itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT m a b l c Op.VCADD dt N oprDdDnDmRotate
  | 0b01010000u | 0b11010000u (* x1010000 *) ->
    chkITQVdVnVm b itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT m a b l c Op.VCADD dt N oprDdDnDmRotate
  | 0b01000001u | 0b01010001u | 0b11000001u | 0b11010001u (* x10x0001 *) ->
    raise UnallocatedException
  (* VCADD 128-bit x10x0010 Armv8.3 *)
  | 0b01000010u | 0b11000010u (* x1000010 *) ->
    chkITQVdVnVm b itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT m a b l c Op.VCADD dt N oprQdQnQmRotate
  | 0b01010010u | 0b11010010u (* x1010010 *) ->
    chkITQVdVnVm b itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT m a b l c Op.VCADD dt N oprQdQnQmRotate
  | b when b &&& 0b01101111u = 0b01000011u (* x10x0011 *) ->
    raise UnallocatedException
  | b when b &&& 0b11101100u = 0b00000000u (* 000x00xx *) ->
    raise UnallocatedException
  | b when b &&& 0b11101100u = 0b00000100u (* 000x01xx *) ->
    raise UnallocatedException
  | 0b00001000u -> raise UnallocatedException
  | 0b00001001u -> raise UnallocatedException
  (* VMMLA Armv8.6 *)
  | 0b00001010u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VMMLA (oneDt BF16) N oprQdQnQm
  | 0b00001011u -> raise UnallocatedException
  (* VDOT 64-bit Armv8.6 *)
  | 0b00001100u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VDOT (oneDt BF16) N oprDdDnDm
  | 0b00001101u -> raise UnallocatedException
  (* VDOT 128-bit Armv8.6 *)
  | 0b00001110u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VDOT (oneDt BF16) N oprQdQnQm
  | 0b00001111u -> raise UnallocatedException
  | 0b00011000u | 0b00011001u | 0b00011010u | 0b00011011u (* 000110xx *) ->
    raise UnallocatedException
  | 0b00011100u | 0b00011101u | 0b00011110u | 0b00011111u (* 000111xx *) ->
    raise UnallocatedException
  (* VFMAL Armv8.2 *)
  | 0b00100001u ->
    chkITQVd b itstate
    render &itstate 0 isInIT m a b l c Op.VFMAL (oneDt SIMDTypF16) N oprDdSnSm
  | 0b00100011u ->
    chkITQVd b itstate
    render &itstate 0 isInIT m a b l c Op.VFMAL (oneDt SIMDTypF16) N oprQdDnDm
  | 0b00100100u | 0b00100101u | 0b00100110u | 0b00100111u (* 001001xx *) ->
    raise UnallocatedException
  | 0b00101000u | 0b00101001u (* 0010100xu *) -> raise UnallocatedException
  (* VSMMLA Armv8.6 *)
  | 0b00101010u ->
    chkITVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VSMMLA (oneDt SIMDTypS8) N oprQdQnQm
  (* VUMMLA Armv8.6 *)
  | 0b00101011u ->
    chkITVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VUMMLA (oneDt SIMDTypU8) N oprQdQnQm
  (* VSDOT 64-bit Armv8.2 *)
  | 0b00101100u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VSDOT (oneDt SIMDTypS8) N oprDdDnDm
   (* VUDOT 64-bit Armv8.2 *)
  | 0b00101101u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VUDOT (oneDt SIMDTypU8) N oprDdDnDm
  (* VSDOT 128-bit Armv8.2 *)
  | 0b00101110u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VSDOT (oneDt SIMDTypS8) N oprQdQnQm
  (* VUDOT 128-bit Armv8.2 *)
  | 0b00101111u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VUDOT (oneDt SIMDTypU8) N oprQdQnQm
  (* VFMAB Armv8.6 *)
  | 0b00110001u ->
    chkITVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VFMAB (oneDt BF16) N oprQdQnQm
  (* VFMAT Armv8.6 *)
  | 0b00110011u ->
    chkITVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VFMAT (oneDt BF16) N oprQdQnQm
  | 0b00110100u | 0b00110101u | 0b00110110u | 0b00110111u (* 0b001101xxu *) ->
    raise UnallocatedException
  | 0b00111000u | 0b00111001u | 0b00111010u | 0b00111011u (* 0b001110xxu *) ->
    raise UnallocatedException
  | 0b00111100u | 0b00111101u | 0b00111110u | 0b00111111u (* 0b001111xxu *) ->
    raise UnallocatedException
  | 0b01100001u -> (* Armv8.2 *)
    chkQVd b
    render &itstate 0 isInIT m a b l c Op.VFMSL (oneDt SIMDTypF16) N oprDdSnSm
  | 0b01100011u -> (* Armv8.2 *)
    chkQVd b
    render &itstate 0 isInIT m a b l c Op.VFMSL (oneDt SIMDTypF16) N oprQdDnDm
  | 0b01100100u | 0b01100101u | 0b01100110u | 0b01100111u (* 011001xx *) ->
    raise UnallocatedException
  | 0b01101000u | 0b01101001u (* 0110100x *) -> raise UnallocatedException
  (* VUSMMLA Armv8.6 *)
  | 0b01101010u ->
    chkITVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VUSMMLA (oneDt SIMDTypS8) N oprQdQnQm
  | 0b01101011u -> raise UnallocatedException
  (* VUSDOT 64-bit Armv8.6 *)
  | 0b01101100u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VUSDOT (oneDt SIMDTypS8) N oprDdDnDm
  | 0b01101101u | 0b01101111u (* 011011x1 *) -> raise UnallocatedException
  (* VUSDOT 128-bit Armv8.6 *)
  | 0b01101110u ->
    chkITQVdVnVm b itstate
    render &itstate 0 isInIT m a b l c Op.VUSDOT (oneDt SIMDTypS8) N oprQdQnQm
  | 0b01110100u | 0b01110101u | 0b01110110u | 0b01110111u (* 011101xx *) ->
    raise UnallocatedException
  | 0b01111000u | 0b01111001u | 0b01111010u | 0b01111011u (* 011110xx *) ->
    raise UnallocatedException
  | 0b01111100u | 0b01111101u | 0b01111110u | 0b01111111u (* 011111xx *) ->
    raise UnallocatedException
  (* VCMLA Armv8.3 *)
  | 0b00100000u ->
    chkITQVdVnVm b itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT m a b l c Op.VCMLA dt N oprDdDnDmRotate
  | 0b00100010u ->
    chkITQVdVnVm b itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT m a b l c Op.VCMLA dt N oprQdQnQmRotate
  | 0b00110000u ->
    chkITQVdVnVm b itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT m a b l c Op.VCMLA dt N oprDdDnDmRotate
  | 0b00110010u ->
    chkITQVdVnVm b itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT m a b l c Op.VCMLA dt N oprQdQnQmRotate
  | 0b10110100u | 0b10110101u | 0b10110110u | 0b10110111u (* 101101xx *) ->
    raise UnallocatedException
  | 0b10111000u | 0b10111001u | 0b10111010u | 0b10111011u (* 101110xx *) ->
    raise UnallocatedException
  | 0b10111100u | 0b10111101u | 0b10111110u | 0b10111111u (* 101111xx *) ->
    raise UnallocatedException
  | 0b11110100u | 0b11110101u | 0b11110110u | 0b11110111u (* 111101xx *) ->
    raise UnallocatedException
  | 0b11111000u | 0b11111001u | 0b11111010u | 0b11111011u (* 111110xx *) ->
    raise UnallocatedException
  | 0b11111100u | 0b11111101u | 0b11111110u | 0b11111111u (* 111111xx *) ->
    raise UnallocatedException
  | _ -> Utils.impossible ()

/// VSELEQ, VSELGE, VSELGT, VSELVS on page F6-5579.
let parseVectorSelect (itstate: byref<bl>) isInIT mode addr bin len cond =
  match concat (extract bin 21 20) (extract bin 9 8) 2 (* cc:size *) with
  | 0b0011u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VSELEQ dt N oprDdDnDm
  | 0b0001u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VSELEQ dt N oprSdSnSm
  | 0b0010u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VSELEQ dt N oprSdSnSm
  | 0b1011u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VSELGE dt N oprDdDnDm
  | 0b1001u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VSELGE dt N oprSdSnSm
  | 0b1010u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VSELGE dt N oprSdSnSm
  | 0b1111u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VSELGT dt N oprDdDnDm
  | 0b1101u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VSELGT dt N oprSdSnSm
  | 0b1110u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VSELGT dt N oprSdSnSm
  | 0b0111u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF64
    render &itstate 0 isInIT mode addr bin len cond Op.VSELVS dt N oprDdDnDm
  | 0b0101u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT mode addr bin len cond Op.VSELVS dt N oprSdSnSm
  | 0b0110u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT mode addr bin len cond Op.VSELVS dt N oprSdSnSm
  | _ (* xx00 *) -> raise UndefinedException

/// Floating-point minNum/maxNum on page F3-4185.
let parseFPMinMaxNum (itstate: byref<bl>) isInIT mode addr bin len cond =
  match pickBit bin 6 (* op *) with
  | 0b0u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFP bin
    let oprs = if extract bin 9 8 = 0b11u then oprDdDnDm else oprSdSnSm
    render &itstate 0 isInIT mode addr bin len cond Op.VMAXNM dt N oprs
  | _ (* 1 *) ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFP bin
    let oprs = if extract bin 9 8 = 0b11u then oprDdDnDm else oprSdSnSm
    render &itstate 0 isInIT mode addr bin len cond Op.VMINNM dt N oprDdDnDm

/// Floating-point extraction and insertion on page F3-4186.
let parseFPExtractionAndInsertion (itstate: byref<bl>) isInIT m a b l c =
  match concat (extract b 9 8) (pickBit b 7) 1 (* size:op *) with
  | 0b010u | 0b011u (* 01x *) -> raise UnallocatedException
  | 0b100u -> (* Armv8.2 *)
    render &itstate 0 isInIT m a b l c Op.VMOVX (oneDt SIMDTypF16) N oprSdSm
  | 0b101u -> (* Armv8.2 *)
    render &itstate 0 isInIT m a b l c Op.VINS (oneDt SIMDTypF16) N oprSdSm
  | 0b110u | 0b111u (* 11x *) -> raise UnallocatedException
  | _ -> Utils.impossible ()

/// Floating-point directed convert to integer on page F3-4186.
let parseFPDirConvToInt (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 18 16 (* o1:RM *) with
  | 0b000u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFP bin
    let oprs = if extract bin 9 8 (* size *) = 0b11u then oprDdDm else oprSdSm
    render &itstate 0 isInIT mode addr bin len cond Op.VRINTA dt N oprs
  | 0b001u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFP bin
    let oprs = if extract bin 9 8 (* size *) = 0b11u then oprDdDm else oprSdSm
    render &itstate 0 isInIT mode addr bin len cond Op.VRINTN dt N oprs
  | 0b010u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFP bin
    let oprs = if extract bin 9 8 (* size *) = 0b11u then oprDdDm else oprSdSm
    render &itstate 0 isInIT mode addr bin len cond Op.VRINTP dt N oprs
  | 0b011u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFP bin
    let oprs = if extract bin 9 8 (* size *) = 0b11u then oprDdDm else oprSdSm
    render &itstate 0 isInIT mode addr bin len cond Op.VRINTM dt N oprs
  | 0b100u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFSU bin
    let oprs = if extract bin 9 8 (* size *) = 0b11u then oprSdDm else oprSdSm
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTA dt N oprs
  | 0b101u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFSU bin
    let oprs = if extract bin 9 8 (* size *) = 0b11u then oprSdDm else oprSdSm
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTN dt N oprs
  | 0b110u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFSU bin
    let oprs = if extract bin 9 8 (* size *) = 0b11u then oprSdDm else oprSdSm
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTP dt N oprs
  | _ (* 111 *) ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFSU bin
    let oprs = if extract bin 9 8 (* size *) = 0b11u then oprSdDm else oprSdSm
    render &itstate 0 isInIT mode addr bin len cond Op.VCVTM dt N oprs

/// Advanced SIMD and floating-point multiply with accumulate on page F3-4187.
let parseAdvSIMDAndFPMulWithAcc (itstate: byref<bl>) isInIT m a b l c =
  let decodeFields = (* op1:op2:Q:U *)
    (pickBit b 23 <<< 4) + (extract b 21 20 <<< 2) + (pickBit b 6 <<< 1) +
    (pickBit b 4)
  match decodeFields with
  (* VCMLA 0xxx0 Armv8.3 *)
  | 0b00000u | 0b00100u | 0b01000u | 0b01100u (* 0xx00 *) ->
    chkITQVdVn b itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT m a b l c Op.VCMLA dt N oprDdDnDmidxRotate
  | 0b00010u | 0b00110u | 0b01010u | 0b01110u (* 0xx10 *) ->
    chkITQVdVn b itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT m a b l c Op.VCMLA dt N oprQdQnDmidxRotate
  (* VFMAL 000x1 Armv8.2 *)
  | 0b00001u ->
    chkITQVd b itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT m a b l c Op.VFMAL dt N oprDdSnSmidx
  | 0b00011u ->
    chkITQVd b itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT m a b l c Op.VFMAL dt N oprQdDnDmidx
  (* VFMSL 001x1 Armv8.2 *)
  | 0b00101u ->
    chkITQVd b itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT m a b l c Op.VFMSL dt N oprDdSnSmidx
  | 0b00111u ->
    chkITQVd b itstate
    let dt = oneDt SIMDTypF16
    render &itstate 0 isInIT m a b l c Op.VFMSL dt N oprQdDnDmidx
  | 0b01001u | 0b01011u (* 010x1 *) -> raise UnallocatedException
  (* VFMAB Armv8.6 *)
  | 0b01101u ->
    chkITVdVn b itstate
    let dt = oneDt BF16
    render &itstate 0 isInIT m a b l c Op.VFMAB dt N oprQdQnDmidxm
  (* VFMAT Armv8.6 *)
  | 0b01111u ->
    chkITVdVn b itstate
    let dt = oneDt BF16
    render &itstate 0 isInIT m a b l c Op.VFMAT dt N oprQdQnDmidxm
  (* VCMLA 1xx00 Armv8.3 *)
  | 0b10000u | 0b10100u | 0b11000u | 0b11100u (* 1xx00 *) ->
    chkITQVdVn b itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT m a b l c Op.VCMLA dt N oprDdDnDm0Rotate
  | 0b10001u | 0b10011u | 0b10101u | 0b10111u | 0b11001u | 0b11011u | 0b11101u
  | 0b11111u (* 1xxx1 *) -> raise UnallocatedException
  (* VCMLA Armv8.3 *)
  | _ (* 1xx10 *) ->
    chkITQVdVn b itstate
    let dt = oneDt SIMDTypF32
    render &itstate 0 isInIT m a b l c Op.VCMLA dt N oprQdQnDm0Rotate

/// Advanced SIMD and floating-point dot product on page F3-4187.
let parseAdvSIMDAndFPDotProduct (itstate: byref<bl>) isInIT m a b l c =
  let decodeFields (* op1:op2:op4:Q:U *) =
    (pickBit b 23 <<< 5) + (extract b 21 20 <<< 3) + (pickBit b 8 <<< 2) +
    (pickBit b 6 <<< 1) + (pickBit b 4)
  match decodeFields with
  | 0b000000u | 0b000001u | 0b000010u | 0b000011u (* 0000xx *) ->
    raise UnallocatedException
  (* VDOT 64-bit Armv8.6 *)
  | 0b000100u ->
    chkITQVdVn b itstate
    render &itstate 0 isInIT m a b l c Op.VDOT (oneDt BF16) N oprDdDnDmidx
  | 0b000101u | 0b000111u (* 0001x1 *) -> raise UnallocatedException
  (* VDOT 128-bit Armv8.6 *)
  | 0b000110u ->
    chkITQVdVn b itstate
    render &itstate 0 isInIT m a b l c Op.VDOT (oneDt BF16) N oprQdQnDmidx
  | 0b001000u | 0b001001u | 0b001010u | 0b001011u (* 0010xx *) ->
    raise UnallocatedException
  | 0b010000u | 0b010001u | 0b010010u | 0b010011u (* 0100xx *) ->
    raise UnallocatedException
  (* VSDOT 64-bit Armv8.2 *)
  | 0b010100u ->
    chkITQVdVn b itstate
    render &itstate 0 isInIT m a b l c Op.VSDOT (oneDt SIMDTypS8) N oprDdDnDmidx
  (* VUDOT 64-bit Armv8.2 *)
  | 0b010101u ->
    chkITQVdVn b itstate
    render &itstate 0 isInIT m a b l c Op.VUDOT (oneDt SIMDTypU8) N oprDdDnDmidx
  (* VSDOT 128-bit Armv8.2 *)
  | 0b010110u ->
    chkITQVdVn b itstate
    render &itstate 0 isInIT m a b l c Op.VSDOT (oneDt SIMDTypS8) N oprQdQnDmidx
  (* VUDOT 128-bit Armv8.2 *)
  | 0b010111u ->
    chkITQVdVn b itstate
    render &itstate 0 isInIT m a b l c Op.VUDOT (oneDt SIMDTypU8) N oprQdQnDmidx
  | b when b &&& 0b111000u = 0b011000u (* 011xxx *) ->
    raise UnallocatedException
  | b when b &&& 0b100100u = 0b100000u (* 1xx0xx *) ->
    raise UnallocatedException
  (* VUSDOT 64-bit Armv8.6 *)
  | 0b100100u ->
    chkQVdVn b
    let dt = oneDt SIMDTypS8
    render &itstate 0 isInIT m a b l c Op.VUSDOT dt N oprDdDnDmidx
  (* VSUDOT 64-bit Armv8.6 *)
  | 0b100101u ->
    chkQVdVn b
    let dt = oneDt SIMDTypU8
    render &itstate 0 isInIT m a b l c Op.VSUDOT dt N oprDdDnDmidx
  (* VUSDOT 128-bit Armv8.6 *)
  | 0b100110u ->
    chkQVdVn b
    let dt = oneDt SIMDTypS8
    render &itstate 0 isInIT m a b l c Op.VUSDOT dt N oprQdQnDmidx
  (* VSUDOT 128-bit Armv8.6 *)
  | 0b100111u ->
    chkQVdVn b
    let dt = oneDt SIMDTypU8
    render &itstate 0 isInIT m a b l c Op.VSUDOT dt N oprQdQnDmidx
  | 0b101100u | 0b101101u | 0b101110u | 0b101111u (* 1011xx *) ->
    raise UnallocatedException
  | b when b &&& 0b110100u = 0b110100u (* 11x1xx *) ->
    raise UnallocatedException
  | _ -> Utils.impossible ()

/// Additional Advanced SIMD and floating-point instructions on page F3-4183.
let parseAddAdvSIMDAndFPInstrs (itstate: byref<bl>) isInIT mode addr bin len c =
  let op1 = extract bin 21 16 (* op1 *)
  let op3 = extract bin 9 8 (* op3 *)
  let decodeFields (* op0:op2:op4:op5 *) =
    (extract bin 25 23 <<< 3) + (pickBit bin 10 <<< 2) + (pickBit bin 6 <<< 1) +
    (pickBit bin 4)
  match decodeFields with
  | b when b &&& 0b100000u = 0b000000u (* 0xxxxx *) && pickBit op3 1 = 0u ->
    parseAdvSIMDThreeRegSameLenExt &itstate isInIT mode addr bin len c
  | 0b100000u (* 100000 *) when op3 <> 0b00u ->
    parseVectorSelect &itstate isInIT mode addr bin len c
  | 0b101000u | 0b101010u (* 1010x0 *) when extract op1 5 4 = 0u && op3 <> 0u ->
    parseFPMinMaxNum &itstate isInIT mode addr bin len c
  | 0b101010u (* 101010 *) when op1 = 0b110000u && op3 <> 0b00u ->
    parseFPExtractionAndInsertion &itstate isInIT mode addr bin len c
  | 0b101010u (* 101010 *) when extract op1 5 3 = 0b111u && op3 <> 0b00u ->
    parseFPDirConvToInt &itstate isInIT mode addr bin len c
  | b when b &&& 0b110100u = 0b100000u (* 10x0xx *) && op3 = 0b00u ->
    parseAdvSIMDAndFPMulWithAcc &itstate isInIT mode addr bin len c
  | b when b &&& 0b110100u = 0b100100u (* 10x1xx *) && pickBit op3 1 = 0u ->
    parseAdvSIMDAndFPDotProduct &itstate isInIT mode addr bin len c
  | _ -> Utils.impossible ()

/// System register access, Advanced SIMD, and floating-point on page F3-4164.
let parseSystemRegAccessAdvSIMDAndFP (itstate: byref<bl>) isInIT m a bin l c =
  let decodeFields (* op0:op1:op2:op3 *) =
    (pickBit bin 28 <<< 4) + (extract bin 25 24 <<< 2) + (pickBit bin 11 <<< 1)
    + (pickBit bin 4)
  match decodeFields with
  | b when b &&& 0b01010u = 0b00000u (* x0x0x *) -> raise UnallocatedException
  | b when b &&& 0b01110u = 0b01000u (* x100x *) -> raise UnallocatedException
  | b when b &&& 0b01100u = 0b01100u (* x11xx *) ->
    parseAdvSIMDDataProcess &itstate isInIT m a bin l c
  | b when b &&& 0b11010u = 0b00010u (* 00x1x *) ->
    parseAdvSIMDAndSysRegLdStAnd64BitMov &itstate isInIT m a bin l c
  | 0b01010u -> parseFPDataProcessing &itstate isInIT m a bin l c
  | 0b01011u -> parseAdvSIMDAndSysReg32BitMov &itstate isInIT m a bin l c
  | _ (* 1 != 11 1 x *) ->
    parseAddAdvSIMDAndFPInstrs &itstate isInIT m a bin l c

/// Load/store multiple on page F3-4160.
let parseLdStMul (itstate: byref<bl>) isInIT mode addr bin len cond =
  match concat (extract bin 24 23) (pickBit bin 20) 1 (* opc:L *) with
  | 0b000u ->
    render &itstate 0 isInIT mode addr bin len cond Op.SRSDB None N oprSPMode
  | 0b001u ->
    render &itstate 0 isInIT mode addr bin len cond Op.RFEDB None N oprRn
  | 0b010u ->
    chkPCRnRegsWBRegs bin
    render &itstate 0 isInIT mode addr bin len cond Op.STM None W oprRnRegs
  | 0b011u ->
    chkPCRnRegsPMWback bin itstate
    render &itstate 0 isInIT mode addr bin len cond Op.LDM None W oprRnRegs
  | 0b100u ->
    chkPCRnRegsWBRegs bin
    render &itstate 0 isInIT mode addr bin len cond Op.STMDB None N oprRnRegs
  | 0b101u ->
    chkPCRnRegsPMWback bin itstate
    render &itstate 0 isInIT mode addr bin len cond Op.LDMDB None N oprRnRegs
  | 0b110u ->
    render &itstate 0 isInIT mode addr bin len cond Op.SRSIA None N oprSPMode
  | _ (* 111 *) ->
    chkPCRnIT bin itstate
    render &itstate 0 isInIT mode addr bin len cond Op.RFEIA None N oprRn

/// Load/store exclusive on page F3-4189.
let parseLdStExclusive (itstate: byref<bl>) isInIT mode addr bin len c =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
    chkPCRd11RtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.STREX None N oprRdRtMemImm
  | _ (* 1 *) ->
    chkPCRtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDREX None N oprRtMemImm8

/// Load/store exclusive byte/half/dual on page F3-4189.
let parseLdStEexclusiveByteHalfDual (itstate: byref<bl>) isInIT m a b l c =
  match concat (pickBit b 20) (extract b 5 4) 2 (* L:sz *) with
  | 0b000u ->
    chkPCRd3RtRn b
    render &itstate 0 isInIT m a b l c Op.STREXB None N oprRdRtMem
  | 0b001u ->
    chkPCRd3RtRn b
    render &itstate 0 isInIT m a b l c Op.STREXH None N oprRdRtMem
  | 0b010u -> raise UnallocatedException
  | 0b011u ->
    chkPCRdRtRt2Rn b
    render &itstate 0 isInIT m a b l c Op.STREXD None N oprRdRtRt2Mem
  | 0b100u ->
    chkPCRtRn b; render &itstate 0 isInIT m a b l c Op.LDREXB None N oprRt15Mem
  | 0b101u ->
    chkPCRtRn b; render &itstate 0 isInIT m a b l c Op.LDREXH None N oprRt15Mem
  | 0b110u -> raise UnallocatedException
  | _ (* 111 *) ->
    chkPCRtRt2Rn b
    render &itstate 0 isInIT m a b l c Op.LDREXD None N oprRtRt2Mem

/// Load-acquire / Store-release on page F3-4190.
let parseLdAcqStRel (itstate: byref<bl>) isInIT mode addr bin len c =
  match concat (pickBit bin 20) (extract bin 6 4) 3 (* L:op:sz *) with
  | 0b0000u ->
    chkPCRtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.STLB None N oprRt15Mem
  | 0b0001u ->
    chkPCRtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.STLH None N oprRt15Mem
  | 0b0010u ->
    chkPCRtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.STL None N oprRt15Mem
  | 0b0011u -> raise UnallocatedException
  | 0b0100u ->
    chkPCRd3RtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.STLEXB None N oprRdRtMem
  | 0b0101u ->
    chkPCRd3RtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.STLEXH None N oprRdRtMem
  | 0b0110u ->
    chkPCRd3RtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.STLEX None N oprRdRtMem
  | 0b0111u ->
    chkPCRdRtRt2Rn bin
    render &itstate 0 isInIT mode addr bin len c Op.STLEXD None N oprRdRtRt2Mem
  | 0b1000u ->
    chkPCRtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDAB None N oprRt15Mem
  | 0b1001u ->
    chkPCRtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDAH None N oprRt15Mem
  | 0b1010u ->
    chkPCRtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDA None N oprRt15Mem
  | 0b1011u -> raise UnallocatedException
  | 0b1100u ->
    chkPCRtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDAEXB None N oprRt15Mem
  | 0b1101u ->
    chkPCRtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDAEXH None N oprRt15Mem
  | 0b1110u ->
    chkPCRtRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDAEX None N oprRt15Mem
  | _ (* 1111 *) ->
    chkPCRtRt2Rn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDAEXD None N oprRtRt2Mem

/// Load/store dual (immediate, post-indexed) on page F3-4191.
let parseLdStDualImmePostIndexed (itstate: byref<bl>) isInIT m a b l c =
  match pickBit b 20 (* L *) with
  | 0b0u ->
    chkPCRnRtRt2 b
    render &itstate 0 isInIT m a b l c Op.STRD None N oprRtRt2MemImm
  | _ (* 1 *) ->
    chkPCRtRt2Eq b
    render &itstate 0 isInIT m a b l c Op.LDRD None N oprRtRt2MemImm

/// Load/store dual (immediate) on page F3-4191.
let parseLdStDualImm (itstate: byref<bl>) isInIT mode addr bin len c =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
    chkPCRnRtRt2 bin
    render &itstate 0 isInIT mode addr bin len c Op.STRD None N oprRtRt2MemImm
  | _ (* 1 *) ->
    chkPCRtRt2Eq bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRD None N oprRtRt2MemImm

/// Load/store dual (immediate, pre-indexed) on page F3-4191.
let parseLdStDualImmPreIndexed (itstate: byref<bl>) isInIT mode addr bin len c =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
    chkPCRnRtRt2 bin
    render &itstate 0 isInIT mode addr bin len c Op.STRD None N oprRtRt2MemImm
  | _ (* 1 *) ->
    chkPCRtRt2Eq bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRD None N oprRtRt2MemImm

/// Load/store dual, load/store exclusive, load-acquire/store-release, and table
/// branch on page F3-4188.
let parseLdStDualExclusiveAndTblBranch (itstate: byref<bl>) isInIT m a bin l c =
  let op0 = extract bin 24 21 (* op0 *)
  let op2 = extract bin 19 16 (* op2 *)
  match concat (extract bin 24 20) (extract bin 7 5) 3 (* op0:op1:op3 *) with
  | b when extract b 7 4 = 0b0010u (* 0010xxxx *) ->
    parseLdStExclusive &itstate isInIT m a bin l c
  | 0b01100000u -> raise UnallocatedException
  | 0b01101000u ->
    chkPCRmIT32 bin itstate
    let struct (op, oprs) =
      if pickBit bin 4 (* H *) = 0u then struct (Op.TBB, oprMemReg)
      else struct (Op.TBH, oprMemRegLSL1)
    render &itstate 0 isInIT m a bin l c op None N oprs
  | 0b01100010u | 0b01100011u | 0b01101010u | 0b01101011u (* 0110x01x *) ->
    parseLdStEexclusiveByteHalfDual &itstate isInIT m a bin l c
  | b when b &&& 0b11110100u = 0b01100100u (* 0110x1xx *) ->
    parseLdAcqStRel &itstate isInIT m a bin l c
  | b when b &&& 0b10110000u = 0b00110000u (* 0x11xxxx *) && op2 <> 0b1111u ->
    parseLdStDualImmePostIndexed &itstate isInIT m a bin l c
  | b when b &&& 0b10110000u = 0b10100000u (* 1x10xxxx *) && op2 <> 0b1111u ->
    parseLdStDualImm &itstate isInIT m a bin l c
  | b when b &&& 0b10110000u = 0b10110000u (* 1x11xxxx *) && op2 <> 0b1111u ->
    parseLdStDualImmPreIndexed &itstate isInIT m a bin l c
  | _ when (op0 &&& 0b1001u <> 0b0000u) && (op2 = 0b1111u) ->
    chkPCRtRt2EqW bin
    render &itstate 0 isInIT m a bin l c Op.LDRD None N oprRtRt2Label
  | _ -> Utils.impossible ()

/// Data-processing (shifted register) on page F3-4160.
let parseDataProcessingShiftReg (itstate: byref<bl>) isInIT mode addr bin l c =
  let rn = extract bin 19 16
  let i3i2st (* imm3:imm2:stype *) =
    concat (extract bin 14 12) (extract bin 7 4) 4
  let rd = extract bin 11 8
  match extract bin 24 20 (* op1:S *) with
  | 0b00000u ->
    chkPCRdSRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.AND None q oprs
  | 0b00001u when i3i2st <> 0b11u && rd <> 0b1111u ->
    chkPCRdSRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.ANDS None q oprs
  | 0b00001u when i3i2st <> 0b11u && rd = 0b1111u ->
    chkPCRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.TST None W oprRnRmShf
  | 0b00001u when i3i2st = 0b11u && rd <> 0b1111u ->
    chkPCRdSRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.ANDS None N oprRdRnRmShf
  | 0b00001u when i3i2st = 0b11u && rd = 0b1111u ->
    chkPCRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.TST None N oprRnRmShf
  | 0b00010u when i3i2st = 0b11u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.BIC None N oprRdRnRmShf
  | 0b00010u ->
    chkPCRdRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.BIC None q oprs
  | 0b00011u when i3i2st = 0b11u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.BICS None N oprRdRnRmShf
  | 0b00011u ->
    chkPCRdRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.BICS None q oprs
  | 0b00100u when rn <> 0b1111u && i3i2st = 0b11u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin l c Op.ORR None N oprRdRnRmShf
  | 0b00100u when rn <> 0b1111u ->
    chkPCRdRm bin
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.ORR None q oprs
  | 0b00100u when rn = 0b1111u && i3i2st = 0b11u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin l c Op.MOV None N oprRdRmShfT16
  | 0b00100u when rn = 0b1111u -> (* FIXME: Alias conditions on page F5-4557 *)
    chkPCRdRm bin
    let q = if inITBlock itstate then W else N
    render &itstate 0 isInIT mode addr bin l c Op.MOV None q oprRdRmShfT32
  | 0b00101u when rn <> 0b1111u && i3i2st = 0b11u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin l c Op.ORRS None N oprRdRnRmShf
  | 0b00101u when rn <> 0b1111u ->
    chkPCRdRm bin
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.ORRS None q oprs
  | 0b00101u when rn = 0b1111u && i3i2st = 0b11u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin l c Op.MOVS None N oprRdRmShfT32
  | 0b00101u when rn = 0b1111u ->
    chkPCRdRm bin
    let q = if inITBlock itstate |> not then W else N
    render &itstate 0 isInIT mode addr bin l c Op.MOVS None q oprRdRmShfT32
  | 0b00110u when rn <> 0b1111u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin l c Op.ORN None N oprRdRnRmShf
  | 0b00110u when rn = 0b1111u && i3i2st = 0b11u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin l c Op.MVN None N oprRdRmShfT32
  | 0b00110u when rn = 0b1111u ->
    chkPCRdRm bin
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, oprRdRmT32)
      else struct (N, oprRdRmShfT32)
    render &itstate 0 isInIT mode addr bin l c Op.MVN None q oprs
  | 0b00111u when rn <> 0b1111u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin l c Op.ORNS None N oprRdRnRmShf
  | 0b00111u when rn = 0b1111u && i3i2st = 0b11u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin l c Op.MVNS None N oprRdRmShfT32
  | 0b00111u when rn = 0b1111u ->
    chkPCRdRm bin
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, oprRdRmT32)
      else struct (N, oprRdRmShfT32)
    render &itstate 0 isInIT mode addr bin l c Op.MVNS None q oprs
  | 0b01000u when i3i2st = 0b11u ->
    chkPCRdSRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.EOR None N oprRdRnRmShf
  | 0b01000u ->
    chkPCRdSRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.EOR None q oprs
  | 0b01001u when i3i2st <> 0b11u && rd <> 0b1111u ->
    chkPCRdSRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.EORS None q oprs
  | 0b01001u when i3i2st <> 0b11u && rd = 0b1111u ->
    chkPCRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.TEQ None N oprRnRmShf
  | 0b01001u when i3i2st = 0b11u && rd <> 0b1111u ->
    chkPCRdSRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.EORS None N oprRdRnRmShf
  | 0b01001u when i3i2st = 0b11u && rd = 0b1111u ->
    chkPCRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.TEQ None N oprRnRmShf
  | 0b01010u | 0b01011u (* 0101x *) -> raise UnallocatedException
  | 0b01100u when i3i2st &&& 0b11u = 0b00u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.PKHBT None N oprRdRnRmShf
  | 0b01100u when i3i2st &&& 0b11u = 0b01u -> raise UnallocatedException
  | 0b01100u when i3i2st &&& 0b11u = 0b10u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.PKHTB None N oprRdRnRmShf
  | 0b01100u when i3i2st &&& 0b11u = 0b11u -> raise UnallocatedException
  | 0b01110u | 0b01111u (* 0111x *) -> raise UnallocatedException
  | 0b10000u when rn <> 0b1101u && i3i2st = 0b11u ->
    chkPCRdSRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.ADD None N oprRdRnRmShf
  | 0b10000u when rn <> 0b1101u ->
    chkPCRdSRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.ADD None q oprs
  | 0b10000u when rn = 0b1101u ->
    chkPCRdSRm bin
    render &itstate 0 isInIT mode addr bin l c Op.ADD None N oprRdSPRmShf
  | 0b10001u when rn <> 0b1101u && rd <> 0b1111u && i3i2st = 0b11u ->
    chkPCRdSRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.ADDS None N oprRdRnRmShf
  | 0b10001u when rn <> 0b1101u && rd <> 0b1111u ->
    chkPCRdSRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.ADDS None q oprs
  | 0b10001u when rn = 0b1101u && rd <> 0b1111u ->
    chkPCRdSRm bin
    render &itstate 0 isInIT mode addr bin l c Op.ADDS None N oprRdSPRmShf
  | 0b10001u when rd = 0b1111u ->
    chkPCRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.CMN None N oprRnRmShf
  | 0b10010u | 0b10011u (* 1001x *) -> raise UnallocatedException
  | 0b10100u when i3i2st = 0b11u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.ADC None N oprRdRnRmShf
  | 0b10100u ->
    chkPCRdRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.ADC None q oprs
  | 0b10101u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.ADCS None N oprRdRnRmShf
  | 0b10101u ->
    chkPCRdRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.ADCS None q oprs
  | 0b10110u when i3i2st = 0b11u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.SBC None N oprRdRnRmShf
  | 0b10110u ->
    chkPCRdRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.SBC None q oprs
  | 0b10111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.SBCS None N oprRdRnRmShf
  | 0b10111u ->
    chkPCRdRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.SBCS None q oprs
  | 0b11000u | 0b11001u (* 1100x *) -> raise UnallocatedException
  | 0b11010u when rn <> 0b1101u && i3i2st = 0b11u ->
    chkPCRdSRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.SUB None N oprRdRnRmShf
  | 0b11010u when rn <> 0b1101u ->
    chkPCRdSRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.SUB None q oprs
  | 0b11010u when rn = 0b1101u && i3i2st = 0b11u ->
    chkPCRdSRm bin
    render &itstate 0 isInIT mode addr bin l c Op.SUB None N oprRdSPRmShf
  | 0b11010u when rn = 0b1101u ->
    chkPCRdSRm bin
    render &itstate 0 isInIT mode addr bin l c Op.SUB None N oprRdSPRmShf
  | 0b11011u when rn <> 0b1101u && rd <> 0b1111u && i3i2st = 0b11u ->
    chkPCRdSRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.SUBS None N oprRdRnRmShf
  | 0b11011u when rn <> 0b1101u && rd <> 0b1111u ->
    chkPCRdSRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.SUBS None q oprs
  | 0b11011u when rn = 0b1101u && rd <> 0b1111u && i3i2st = 0b11u ->
    chkPCRdSRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.SUBS None N oprRdRnRmShf
  | 0b11011u when rn = 0b1101u && rd <> 0b1111u ->
    chkPCRdSRnRm bin
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, oprRdRnRmT32)
      else struct (N, oprRdRnRmShf)
    render &itstate 0 isInIT mode addr bin l c Op.SUBS None q oprs
  | 0b11011u when rd = 0b1111u ->
    chkPCRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.CMP None N oprRnRmShf
  | 0b11100u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.RSB None N oprRdRnRmShf
  | 0b11101u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.RSBS None N oprRdRnRmShf
  | 0b11110u | 0b11111u (* 1111x *) -> raise UnallocatedException
  | _ -> Utils.impossible ()

/// Hints on page F3-4193.
let parseHints32 (itstate: byref<bl>) isInIT mode addr bin len cond =
  match extract bin 7 0 (* hint:option *) with
  | 0b00000000u ->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None W oprNo
  | 0b00000001u ->
    render &itstate 0 isInIT mode addr bin len cond Op.YIELD None W oprNo
  | 0b00000010u ->
    render &itstate 0 isInIT mode addr bin len cond Op.WFE None W oprNo
  | 0b00000011u ->
    render &itstate 0 isInIT mode addr bin len cond Op.WFI None W oprNo
  | 0b00000100u ->
    render &itstate 0 isInIT mode addr bin len cond Op.SEV None W oprNo
  | 0b00000101u ->
    render &itstate 0 isInIT mode addr bin len cond Op.SEVL None W oprNo
  | 0b00000110u | 0b00000111u ->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None W oprNo
  | b when b &&& 0b11111000u = 0b00001000u ->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None W oprNo
  | 0b00010000u -> (* Armv8.2 *)
    inITBlock itstate |> checkUndef
    render &itstate 0 isInIT mode addr bin len cond Op.ESB None W oprNo
  | 0b00010001u ->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None W oprNo
  | 0b00010010u -> (* TSB CSYNC Armv8.4 *)
    inITBlock itstate |> checkUndef
    render &itstate 0 isInIT mode addr bin len cond Op.TSB None N oprNo
  | 0b00010011u ->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None W oprNo
  | 0b00010100u ->
    inITBlock itstate |> checkUndef
    render &itstate 0 isInIT mode addr bin len cond Op.CSDB None W oprNo
  | 0b00010101u ->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None W oprNo
  | 0b00010110u | 0b00010111u (* 0001011x *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None W oprNo
  | b when b &&& 0b11111000u = 0b00011000u (* 00011xxx *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None W oprNo
  | b when b &&& 0b11100000u = 0b00100000u (* 001xxxxx *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None W oprNo
  | b when b &&& 0b11000000u = 0b01000000u (* 01xxxxxx *)->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None W oprNo
  | b when b &&& 0b11000000u = 0b10000000u (* 10xxxxxx *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None W oprNo
  | b when b &&& 0b11100000u = 0b11000000u (* 110xxxxx *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None W oprNo
  | b when b &&& 0b11110000u = 0b11100000u (* 1110xxxx *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.NOP None W oprNo
  | b when b &&& 0b11110000u = 0b11110000u ->
    render &itstate 0 isInIT mode addr bin len cond Op.DBG None N oprOption
  | _ -> Utils.impossible ()

/// Change processor state on page F3-4194.
let parseChangeProcessorState (itstate: byref<bl>) isInIT mode addr bin len c =
  match extract bin 10 8 (* imod:M *) with
  | 0b001u ->
    chkModeImodAIFIT bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.CPS None N oprMode
  | 0b010u | 0b011u (* 01x *) -> raise UnallocatedException
  (* CPSIE 10x *)
  | 0b100u ->
    chkModeImodAIFIT bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.CPSIE None W oprIflags
  | 0b101u ->
    chkModeImodAIFIT bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.CPSIE None N oprIflagsMode
  (* CPSID 11x *)
  | 0b110u ->
    chkModeImodAIFIT bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.CPSID None W oprIflags
  | 0b111u ->
    chkModeImodAIFIT bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.CPSID None N oprIflagsMode
  | _ -> Utils.impossible ()

/// Miscellaneous system on page F3-4194.
let parseMiscSystem (itstate: byref<bl>) isInIT mode addr bin len cond =
  let option = extract bin 3 0
  match extract bin 7 4 (* opc *) with
  | 0b0000u | 0b0001u (* 000x *) -> raise UnallocatedException
  | 0b0010u ->
    render &itstate 0 isInIT mode addr bin len cond Op.CLREX None N oprNo
  | 0b0011u -> raise UnallocatedException
  | 0b0100u when option <> 0b0000u || option <> 0b0100u (* != 0x00 *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.DSB None N oprOption
  | 0b0100u when option = 0b0000u ->
    inITBlock itstate |> checkUndef
    render &itstate 0 isInIT mode addr bin len cond Op.SSBB None N oprNo
  | 0b0100u when option = 0b0100u ->
    inITBlock itstate |> checkUndef
    render &itstate 0 isInIT mode addr bin len cond Op.PSSBB None N oprNo
  | 0b0101u ->
    render &itstate 0 isInIT mode addr bin len cond Op.DMB None N oprOption
  | 0b0110u ->
    render &itstate 0 isInIT mode addr bin len cond Op.ISB None N oprOption
  | 0b0111u ->
    inITBlock itstate |> checkUndef
    render &itstate 0 isInIT mode addr bin len cond Op.SB None N oprNo
  | _ (* 1xxx *) -> raise UnallocatedException

/// Exception return on page F3-4195.
let parseExceptionReturn (itstate: byref<bl>) isInIT mode addr bin len cond =
  match concat (extract bin 19 16) (extract bin 7 0) 8 (* Rn:imm8 *) with
  | 0b111000000000u ->
    chkInITLastIT itstate
    render &itstate 0 isInIT mode addr bin len cond Op.ERET None N oprNo
  | _ (* xxxx != 00000000 *) ->
    chkRnIT bin itstate
    render &itstate 0 isInIT mode addr bin len cond Op.SUBS None N oprPCLRImm8

/// DCPS on page F3-4195.
let parseDCPS (itstate: byref<bl>) isInIT mode addr bin len cond =
  if extract bin 19 16 (* imm4 *) <> 0b1111u then raise UndefinedException
  elif extract bin 11 2 (* imm10 *) <> 0b0u then raise UndefinedException
  else
    match extract bin 1 0 (* opt *) with
    | 0b00u -> raise UnallocatedException
    | 0b01u ->
      render &itstate 0 isInIT mode addr bin len cond Op.DCPS1 None N oprNo
    | 0b10u ->
      render &itstate 0 isInIT mode addr bin len cond Op.DCPS2 None N oprNo
    | _ (* 11 *) ->
      render &itstate 0 isInIT mode addr bin len cond Op.DCPS3 None N oprNo

/// Exception generation on page F3-4195.
let parseExcepGeneration (itstate: byref<bl>) isInIT mode addr bin len cond =
  match concat (pickBit bin 20) (pickBit bin 13) 1 (* o1:o2 *) with
  | 0b00u ->
    inITBlock itstate |> checkUnpred
    render &itstate 0 isInIT mode addr bin len cond Op.HVC None N oprImm16
  | 0b01u -> raise UnallocatedException
  | 0b10u ->
    chkInITLastIT itstate
    render &itstate 0 isInIT mode addr bin len cond Op.SMC None N oprImm4
  | _ (* 11 *) ->
    render &itstate 0 isInIT mode addr bin len cond Op.UDF None W oprImm16

/// Branches and miscellaneous control on page F3-4192.
let parseBranchAndMiscCtrl (itstate: byref<bl>) isInIT mode addr bin len cond =
  let op1 = extract bin 25 23 (* op1<3:1> *)
  let op3 = extract bin 14 12 (* op3 *)
  let decodeFields (* op0:op1:op2:op3:op5 *) =
    (extract bin 26 20 <<< 4) + (extract bin 14 12 <<< 1) + (pickBit bin 5)
  match decodeFields with
  | b when b &&& 0b11111101011u = 0b01110000000u (* 011100x0x00 *) ->
    chkMaskPCRn bin
    render &itstate 0 isInIT mode addr bin len cond Op.MSR None N oprSregRn
  | b when b &&& 0b11111101011u = 0b01110000001u (* 011100x0x01 *) ->
    chkPCRn bin
    render &itstate 0 isInIT mode addr bin len cond Op.MSR None N oprBankregRn
  | 0b01110100000u | 0b01110100001u | 0b01110100100u | 0b01110100101u
    when extract bin 10 8 (* op4 *) = 0b000u ->
    parseHints32 &itstate isInIT mode addr bin len cond
  | 0b01110100000u | 0b01110100001u | 0b01110100100u | 0b01110100101u ->
    parseChangeProcessorState &itstate isInIT mode addr bin len cond
  | b when b &&& 0b11111111010u = 0b01110110000u (* 01110110x0x *) ->
    parseMiscSystem &itstate isInIT mode addr bin len cond
  | b when b &&& 0b11111111010u = 0b01111000000u (* 01111000x0x *) ->
    chkPCRmIT32 bin itstate
    render &itstate 0 isInIT mode addr bin len cond Op.BXJ None N oprRm32
  | b when b &&& 0b11111111010u = 0b01111010000u (* 01111010x0x *) ->
    parseExceptionReturn &itstate isInIT mode addr bin len cond
  | b when b &&& 0b11111101011u = 0b01111100000u (* 011111x0x00 *) ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len cond Op.MRS None N oprRdSreg
  | b when b &&& 0b11111101011u = 0b01111100001u (* 011111x0x01 *) ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len cond Op.MRS None N oprRdBankreg
  | 0b11110000000u | 0b11110000001u (* 1111000000x *) ->
    parseDCPS &itstate isInIT mode addr bin len cond
  | 0b11110000100u | 0b11110000101u (* 1111000010x *) ->
    raise UnallocatedException
  | b when b &&& 0b11111111010u = 0b11110010000u (* 11110010x0x *) ->
    raise UnallocatedException
  | b when b &&& 0b11111101010u = 0b11110100000u (* 111101x0x0x *) ->
    raise UnallocatedException
  | b when b &&& 0b11111101010u = 0b11111000000u (* 111110x0x0x *) ->
    raise UnallocatedException
  | b when b &&& 0b11111101010u = 0b11111100000u (* 111111x0x0x *) ->
    parseExcepGeneration &itstate isInIT mode addr bin len cond
  | _ when (op1 <> 0b111u) (* op1 != 111x *) && (op3 &&& 0b101u = 0b0u) ->
    inITBlock itstate |> checkUnpred
    let cond = extract bin 25 22 |> byte |> parseCond |> Some
    render &itstate 0 isInIT mode addr bin len cond Op.B None W oprLabelT3
  | _ when op3 &&& 0b101u = 0b001u (* 0x1 *) ->
    chkInITLastIT itstate
    render &itstate 0 isInIT mode addr bin len cond Op.B None W oprLabelT4
  | _ when op3 &&& 0b101u = 0b100u (* 1x0 *) ->
    chkHInLastIT bin itstate
    render &itstate 0 isInIT mode addr bin len cond Op.BLX None N oprLabelT2
  | _ when op3 &&& 0b101u = 0b101u (* 1x1 *) ->
    chkInITLastIT itstate
    render &itstate 0 isInIT mode addr bin len cond Op.BL None N oprLabelT4
  | _ -> Utils.impossible ()

/// Data-processing (modified immediate) on page F3-4162.
let parseDataProcessingModImm (itstate: byref<bl>) isInIT mode addr bin len c =
  let rn = extract bin 19 16
  let rd = extract bin 11 8
  match extract bin 24 20 (* op1:S *) with
  | 0b00000u ->
    chkPCRdSRn bin
    render &itstate 0 isInIT mode addr bin len c Op.AND None N oprRdRnConst
  | 0b00001u when rd <> 0b1111u ->
    chkPCRdSRn bin
    render &itstate 0 isInIT mode addr bin len c Op.ANDS None N oprRdRnConst
  | 0b00001u when rd = 0b1111u ->
    chkPCRn bin
    render &itstate 0 isInIT mode addr bin len c Op.TST None N oprRnConst
  | 0b00010u ->
    chkPCRdRn bin
    render &itstate 0 isInIT mode addr bin len c Op.BIC None N oprRdRnConst
  | 0b00011u ->
    chkPCRdRn bin
    render &itstate 0 isInIT mode addr bin len c Op.BICS None N oprRdRnConst
  | 0b00100u when rn <> 0b1111u ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len c Op.ORR None N oprRdRnConst
  | 0b00100u when rn = 0b1111u ->
    chkPCRd bin
    let q = if inITBlock itstate then W else N
    render &itstate 0 isInIT mode addr bin len c Op.MOV None q oprRdConst
  | 0b00101u when rn <> 0b1111u ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len c Op.ORRS None N oprRdRnConst
  | 0b00101u when rn = 0b1111u ->
    chkPCRd bin
    let q = if inITBlock itstate then W else N
    render &itstate 0 isInIT mode addr bin len c Op.MOVS None q oprRdConst
  | 0b00110u when rn <> 0b1111u ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len c Op.ORN None N oprRdRnConst
  | 0b00110u when rn = 0b1111u ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len c Op.MVN None N oprRdConst
  | 0b00111u when rn <> 0b1111u ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len c Op.ORNS None N oprRdRnConst
  | 0b00111u when rn = 0b1111u ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len c Op.MVNS None N oprRdConst
  | 0b01000u ->
    chkPCRdSRn bin
    render &itstate 0 isInIT mode addr bin len c Op.EOR None N oprRdRnConst
  | 0b01001u when rd <> 0b1111u ->
    chkPCRdSRn bin
    render &itstate 0 isInIT mode addr bin len c Op.EORS None N oprRdRnConst
  | 0b01001u when rd = 0b1111u ->
    chkPCRn bin
    render &itstate 0 isInIT mode addr bin len c Op.TEQ None N oprRnConst
  | 0b01010u | 0b01011u (* 0101x *) -> raise UnallocatedException
  | 0b01100u | 0b01101u | 0b01110u | 0b01111u (* 011xx *) ->
    raise UnallocatedException
  | 0b10000u when rn <> 0b1101u ->
    chkPCRdSRn bin
    let q = if inITBlock itstate then W else N
    render &itstate 0 isInIT mode addr bin len c Op.ADD None q oprRdRnConst
  | 0b10000u when rn = 0b1101u ->
    chkPCRdS bin
    render &itstate 0 isInIT mode addr bin len c Op.ADD None W oprRdSPConst
  | 0b10001u when rn <> 0b1101u && rd <> 0b1111u ->
    chkPCRdSRn bin
    let q = if inITBlock itstate |> not then W else N
    render &itstate 0 isInIT mode addr bin len c Op.ADDS None q oprRdRnConst
  | 0b10001u when rn = 0b1101u && rd <> 0b1111u ->
    chkPCRdS bin
    render &itstate 0 isInIT mode addr bin len c Op.ADDS None N oprRdSPConst
  | 0b10001u when rd = 0b1111u ->
    chkPCRn bin
    render &itstate 0 isInIT mode addr bin len c Op.CMN None N oprRnConst
  | 0b10010u | 0b10011u (* 1001x *) -> raise UnallocatedException
  | 0b10100u ->
    render &itstate 0 isInIT mode addr bin len c Op.ADC None N oprRdRnConst
  | 0b10101u ->
    render &itstate 0 isInIT mode addr bin len c Op.ADCS None N oprRdRnConst
  | 0b10110u ->
    chkPCRdRn bin
    render &itstate 0 isInIT mode addr bin len c Op.SBC None N oprRdRnConst
  | 0b10111u ->
    chkPCRdRn bin
    render &itstate 0 isInIT mode addr bin len c Op.SBCS None N oprRdRnConst
  | 0b11000u | 0b11001u (* 1100x *) -> raise UnallocatedException
  | 0b11010u when rn <> 0b1101u ->
    chkPCRdSRn bin
    let q = if inITBlock itstate then W else N
    render &itstate 0 isInIT mode addr bin len c Op.SUB None q oprRdRnConst
  | 0b11010u when rn = 0b1101u ->
    chkPCRdS bin
    render &itstate 0 isInIT mode addr bin len c Op.SUB None N oprRdSPConst
  | 0b11011u when rn <> 0b1101u && rd <> 0b1111u ->
    chkPCRdSRn bin
    let q = if inITBlock itstate |> not then W else N
    render &itstate 0 isInIT mode addr bin len c Op.SUBS None q oprRdRnConst
  | 0b11011u when rn = 0b1101u && rd <> 0b1111u ->
    chkPCRdS bin
    render &itstate 0 isInIT mode addr bin len c Op.SUBS None N oprRdSPConst
  | 0b11011u when rd = 0b1111u ->
    chkPCRn bin
    render &itstate 0 isInIT mode addr bin len c Op.CMP None W oprRnConst
  | 0b11100u ->
    chkPCRdRn bin
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, oprRdRn0T32)
      else struct (N, oprRdRnConst)
    render &itstate 0 isInIT mode addr bin len c Op.RSB None q oprs
  | 0b11101u ->
    chkPCRdRn bin
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, oprRdRn0T32)
      else struct (N, oprRdRnConst)
    render &itstate 0 isInIT mode addr bin len c Op.RSBS None q oprs
  | _ (* 1111x *) -> raise UnallocatedException

/// Data-processing (simple immediate) on page F3-4196.
let parseDataProcSimImm (itstate: byref<bl>) isInIT mode addr bin len cond =
  let rn = extract bin 19 16
  match concat (pickBit bin 23) (pickBit bin 21) 1 (* o1:o2 *) with
  | 0b00u when rn = 0b1101u ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len cond Op.ADDW None N oprRdSPImm12
  | 0b00u when rn = 0b1111u ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len cond Op.ADR None W oprRdLabel
  | 0b00u (* rn != 11x1 *) ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len cond Op.ADDW None N oprRdRnImm12
  | 0b01u -> raise UnallocatedException
  | 0b10u -> raise UnallocatedException
  | 0b11u when rn = 0b1101u ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len cond Op.SUBW None N oprRdSPImm12
  | 0b11u when rn = 0b1111u ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len cond Op.ADR None N oprRdLabel
  | _ (* 11 && rn != 11x1 *) ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len cond Op.SUBW None N oprRdRnImm12

/// Move Wide (16-bit immediate) on page F3-4197.
let parseMoveWide16BitImm (itstate: byref<bl>) isInIT mode addr bin len cond =
  match pickBit bin 7 with
  | 0b0u ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len cond Op.MOVW None N oprRdImm16
  | _ (* 1 *) ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin len cond Op.MOVT None N oprRdImm16

/// Saturate, Bitfield on page F3-4197.
let parseSaturateBitfield (itstate: byref<bl>) isInIT mode addr bin l c =
  let rn = extract bin 19 16
  let i3i2 (* imm3:imm2 *) = concat (extract bin 14 12) (extract bin 7 6) 2
  match extract bin 23 21 (* op1 *) with
  | 0b000u ->
    chkPCRdRn bin
    render &itstate 0 isInIT mode addr bin l c Op.SSAT None N oprRdImmRnShf
  | 0b001u when i3i2 <> 0b00000u ->
    chkPCRdRn bin
    render &itstate 0 isInIT mode addr bin l c Op.SSAT None N oprRdImmRnShf
  | 0b001u ->
    chkPCRdRn bin
    render &itstate 0 isInIT mode addr bin l c Op.SSAT16 None N oprRdImmRn
  | 0b010u ->
    chkPCRdRn bin
    render &itstate 0 isInIT mode addr bin l c Op.SBFX None N oprRdRnLsbWidthM1
  | 0b011u when rn <> 0b1111u ->
    chkPCRn bin
    render &itstate 0 isInIT mode addr bin l c Op.BFI None N oprRdRnLsbWidth
  | 0b011u ->
    chkPCRd bin
    render &itstate 0 isInIT mode addr bin l c Op.BFC None N oprRdLsbWidth
  | 0b100u ->
    chkPCRdRn bin
    render &itstate 0 isInIT mode addr bin l c Op.USAT None N oprRdImmRnShfU
  | 0b101u when i3i2 <> 0b00000u ->
    chkPCRdRn bin
    render &itstate 0 isInIT mode addr bin l c Op.USAT None N oprRdImmRnShfU
  | 0b101u ->
    chkPCRdRn bin
    render &itstate 0 isInIT mode addr bin l c Op.USAT16 None N oprRdImmRnU
  | 0b110u ->
    chkPCRdRn bin
    render &itstate 0 isInIT mode addr bin l c Op.UBFX None N oprRdRnLsbWidthM1
  | _ (* 111 *) -> raise UnallocatedException

/// Data-processing (plain binary immediate) on page F3-4196.
let parseDataProcessingPlainBinImm (itstate: byref<bl>) isInIT mode addr b l c =
  match concat (pickBit b 24) (extract b 22 21) 2 (* op0:op1 *) with
  | 0b000u | 0b001u (* 00x *) ->
    parseDataProcSimImm &itstate isInIT mode addr b l c
  | 0b010u -> parseMoveWide16BitImm &itstate isInIT mode addr b l c
  | 0b011u -> raise UnallocatedException
  | _ (* 1xx *) -> parseSaturateBitfield &itstate isInIT mode addr b l c

/// Advanced SIMD load/store multiple structures on page F3-4199.
let parseAdvSIMDLdStMulStruct (itstate: byref<bl>) isInIT mode addr bin len c =
  match concat (pickBit bin 21) (extract bin 11 8) 4 (* L:itype *) with
  | 0b00000u | 0b00001u (* 0000x *) ->
    chkSzPCRnD4 bin
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VST4 dt N oprListMem
  | 0b00010u ->
    chkPCRnDregs bin
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VST1 dt N oprListMem
  | 0b00011u ->
    chkPCRnD2regs bin
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VST2 dt N oprListMem
  | 0b00100u | 0b00101u (* 0010x *) ->
    chkPCRnD3 bin
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VST3 dt N oprListMem
  | 0b00110u ->
    chkAlign1PCRnDregs bin 3u
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VST1 dt N oprListMem
  | 0b00111u ->
    chkAlign1PCRnDregs bin 1u
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VST1 dt N oprListMem
  | 0b01000u | 0b01001u (* 0100x *) ->
    chkAlignPCRnD2regs bin
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VST2 dt N oprListMem
  | 0b01010u ->
    chkAlignPCRnDregs bin
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VST1 dt N oprListMem
  | 0b10000u | 0b10001u (* 1000x *) ->
    chkSzPCRnD4 bin
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VLD4 dt N oprListMem
  | 0b10010u ->
    chkPCRnDregs bin
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VLD1 dt N oprListMem
  | 0b10011u ->
    chkPCRnD2regs bin
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VLD2 dt N oprListMem
  | 0b10100u | 0b10101u (* 1010x *) ->
    chkPCRnD3 bin
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VLD3 dt N oprListMem
  | 0b01011u | 0b11011u (* x1011 *) -> raise UnallocatedException
  | 0b10110u ->
    chkAlign1PCRnDregs bin 3u
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VLD1 dt N oprListMem
  | 0b10111u ->
    chkAlign1PCRnDregs bin 1u
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VLD1 dt N oprListMem
  | 0b01100u | 0b01101u | 0b01110u | 0b01111u | 0b11100u | 0b11101u | 0b11110u
  | 0b11111u (* x11xx *) -> raise UnallocatedException
  | 0b11000u | 0b11001u (* 1100x *) ->
    chkAlignPCRnD2regs bin
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VLD2 dt N oprListMem
  | 0b11010u ->
    chkAlignPCRnDregs bin
    let dt = getDT64 (extract bin 7 6) |> oneDt
    render &itstate 0 isInIT mode addr bin len c Op.VLD1 dt N oprListMem
  | _ -> Utils.impossible ()

/// Advanced SIMD load single structure to all lanes on page F3-4199.
let parseAdvSIMDLdSingStruAllLanes (itstate: byref<bl>) isInIT mode addr b l c =
  let decodeFields (* L:N:a *) =
    concat (concat (pickBit b 21) (extract b 9 8) 2) (pickBit b 4) 1
  match decodeFields with
  | b when b &&& 0b1000u = 0b0000u (* 0xxx *) -> raise UnallocatedException
  | 0b1000u | 0b1001u (* 100x *) ->
    chkSzAPCRnDregs b
    let dt = getDT64 (extract b 7 6) |> oneDt
    render &itstate 0 isInIT  mode addr b l c Op.VLD1 dt N oprListMem1
  | 0b1010u | 0b1011u (* 101x *) ->
    chkSzPCRnD2 b
    let dt = getDT64 (extract b 7 6) |> oneDt
    render &itstate 0 isInIT  mode addr b l c Op.VLD2 dt N oprListMem2
  | 0b1100u ->
    chkSzAPCRnD3 b
    let dt = getDT64 (extract b 7 6) |> oneDt
    render &itstate 0 isInIT  mode addr b l c Op.VLD3 dt N oprListMem3
  | 0b1101u -> raise UnallocatedException
  | _ (* 111x *) ->
    chkSzAPCRnD4 b
    let dt = getDT32 (extract b 7 6) |> oneDt
    render &itstate 0 isInIT  mode addr b l c Op.VLD4 dt N oprListMem4

/// Advanced SIMD load/store single structure to one lane on page F3-4200.
let parseAdvSIMDLdStSingStruOneLane (itstate: byref<bl>) isInIT mode a b l c =
  match concat (pickBit b 21) (extract b 11 8) 4 (* L:size:N *) with
  | 0b00000u ->
    chkSzIdx0PCRn b
    render &itstate 0 isInIT mode a b l c Op.VST1 (oneDt SIMDTyp8) N oprListMemA
  | 0b00001u ->
    chkPCRnD2 b
    render &itstate 0 isInIT mode a b l c Op.VST2 (oneDt SIMDTyp8) N oprListMemB
  | 0b00010u ->
    chkIdx0PCRnD3 b
    render &itstate 0 isInIT mode a b l c Op.VST3 (oneDt SIMDTyp8) N oprListMemC
  | 0b00011u ->
    chkPCRnD4 b
    render &itstate 0 isInIT mode a b l c Op.VST4 (oneDt SIMDTyp8) N oprListMemD
  | 0b00100u ->
    chkSzIdx1PCRn b
    let dt = oneDt SIMDTyp16
    render &itstate 0 isInIT mode a b l c Op.VST1 dt N oprListMemA
  | 0b00101u ->
    chkPCRnD2 b
    let dt = oneDt SIMDTyp16
    render &itstate 0 isInIT mode a b l c Op.VST2 dt N oprListMemB
  | 0b00110u ->
    chkIdx0PCRnD3 b
    let dt = oneDt SIMDTyp16
    render &itstate 0 isInIT mode a b l c Op.VST3 dt N oprListMemC
  | 0b00111u ->
    chkPCRnD4 b
    let dt = oneDt SIMDTyp16
    render &itstate 0 isInIT mode a b l c Op.VST4 dt N oprListMemD
  | 0b01000u ->
    chkSzIdx2PCRn b
    let dt = oneDt SIMDTyp32
    render &itstate 0 isInIT mode a b l c Op.VST1 dt N oprListMemA
  | 0b01001u ->
    chkIdxPCRnD2 b
    let dt = oneDt SIMDTyp32
    render &itstate 0 isInIT mode a b l c Op.VST2 dt N oprListMemB
  | 0b01010u ->
    chkIdx10PCRnD3 b
    let dt = oneDt SIMDTyp32
    render &itstate 0 isInIT mode a b l c Op.VST3 dt N oprListMemC
  | 0b01011u ->
    chkIdxPCRnD4 b
    let dt = oneDt SIMDTyp32
    render &itstate 0 isInIT mode a b l c Op.VST4 dt N oprListMemD
  | 0b10000u ->
    chkSzIdx0PCRn b
    render &itstate 0 isInIT mode a b l c Op.VLD1 (oneDt SIMDTyp8) N oprListMemA
  | 0b10001u ->
    chkPCRnD2 b
    render &itstate 0 isInIT mode a b l c Op.VLD2 (oneDt SIMDTyp8) N oprListMemB
  | 0b10010u ->
    chkIdx0PCRnD3 b
    render &itstate 0 isInIT mode a b l c Op.VLD3 (oneDt SIMDTyp8) N oprListMemC
  | 0b10011u ->
    chkPCRnD4 b
    render &itstate 0 isInIT mode a b l c Op.VLD4 (oneDt SIMDTyp8) N oprListMemD
  | 0b10100u ->
    chkSzIdx1PCRn b
    let dt = oneDt SIMDTyp16
    render &itstate 0 isInIT mode a b l c Op.VLD1 dt N oprListMemA
  | 0b10101u ->
    chkPCRnD2 b
    let dt = oneDt SIMDTyp16
    render &itstate 0 isInIT mode a b l c Op.VLD2 dt N oprListMemB
  | 0b10110u ->
    chkIdx0PCRnD3 b
    let dt = oneDt SIMDTyp16
    render &itstate 0 isInIT mode a b l c Op.VLD3 dt N oprListMemC
  | 0b10111u ->
    chkPCRnD4 b
    let dt = oneDt SIMDTyp16
    render &itstate 0 isInIT mode a b l c Op.VLD4 dt N oprListMemD
  | 0b11000u ->
    chkSzIdx2PCRn b
    let dt = oneDt SIMDTyp32
    render &itstate 0 isInIT mode a b l c Op.VLD1 dt N oprListMemA
  | 0b11001u ->
    chkIdxPCRnD2 b
    let dt = oneDt SIMDTyp32
    render &itstate 0 isInIT mode a b l c Op.VLD2 dt N oprListMemB
  | 0b11010u ->
    chkIdx10PCRnD3 b
    let dt = oneDt SIMDTyp32
    render &itstate 0 isInIT mode a b l c Op.VLD3 dt N oprListMemC
  | 0b11011u ->
    chkIdxPCRnD4 b
    let dt = oneDt SIMDTyp32
    render &itstate 0 isInIT mode a b l c Op.VLD4 dt N oprListMemD
  | _ -> Utils.impossible ()

/// Advanced SIMD element or structure load/store on page F3-4198.
let parseAdvSIMDElemOrStructLdSt (itstate: byref<bl>) isInIT mode addr bin l c =
  match pickBit bin 23 (* op0 *) with
  | 0b0u -> parseAdvSIMDLdStMulStruct &itstate isInIT mode addr bin l c
  | 0b1u when extract bin 11 10 = 0b11u ->
    parseAdvSIMDLdSingStruAllLanes &itstate isInIT mode addr bin l c
  | _ (* 1 *) ->
    parseAdvSIMDLdStSingStruOneLane &itstate isInIT mode addr bin l c

/// Load/store, unsigned (register offset) on page F3-4202.
let parseLdStUnsignedRegOffset (itstate: byref<bl>) isInIT mode addr bin len c =
  let rt = extract bin 15 12
  match extract bin 22 20 (* size:L *) with
  | 0b000u ->
    chkPCRtRm bin
    let struct (q, oprs) =
      if extract bin 5 4 = 0b00u then struct (W, oprRtMemReg32)
      else struct (N, oprRtMemRegLSL)
    render &itstate 0 isInIT mode addr bin len c Op.STRB None q oprs
  | 0b001u when rt <> 0b1111u ->
    chkPCRm bin
    let struct (q, oprs) =
      if extract bin 5 4 = 0b00u then struct (W, oprRtMemReg32)
      else struct (N, oprRtMemRegLSL)
    render &itstate 0 isInIT mode addr bin len c Op.LDRB None q oprs
  | 0b001u ->
    chkPCRm bin
    render &itstate 0 isInIT mode addr bin len c Op.PLD None N oprMemRegLSL
  | 0b010u ->
    chkPCRtRm bin
    let struct (q, oprs) =
      if extract bin 5 4 = 0b00u then struct (W, oprRtMemReg32)
      else struct (N, oprRtMemRegLSL)
    render &itstate 0 isInIT mode addr bin len c Op.STRH None q oprs
  | 0b011u when rt <> 0b1111u ->
    chkPCRm bin
    let struct (q, oprs) =
      if extract bin 5 4 = 0b00u then struct (W, oprRtMemReg32)
      else struct (N, oprRtMemRegLSL)
    render &itstate 0 isInIT mode addr bin len c Op.LDRH None q oprs
  | 0b011u ->
    chkPCRm bin
    render &itstate 0 isInIT mode addr bin len c Op.PLDW None N oprMemRegLSL
  | 0b100u ->
    chkPCRtRm bin
    let struct (q, oprs) =
      if extract bin 5 4 = 0b00u then struct (W, oprRtMemReg32)
      else struct (N, oprRtMemRegLSL)
    render &itstate 0 isInIT mode addr bin len c Op.STR None q oprs
  | 0b101u ->
    chkPCRmRtIT bin itstate
    let struct (q, oprs) =
      if extract bin 5 4 = 0b00u then struct (W, oprRtMemReg32)
      else struct (N, oprRtMemRegLSL)
    render &itstate 0 isInIT mode addr bin len c Op.LDR None q oprs
  | _ (* 11x *) -> raise UnallocatedException

/// Load/store, unsigned (immediate, post-indexed) on page F3-4203.
let parseLdStUnsignedImmPostIdx (itstate: byref<bl>) isInIT mode addr bin l c =
  match extract bin 6 4 (* size:L *) with
  | 0b000u ->
    chkRnPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin l c Op.STRB None N oprRtMemImmPs
  | 0b001u ->
    chkPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin l c Op.LDRB None N oprRtMemImmPs
  | 0b010u ->
    chkRnPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin l c Op.STRH None N oprRtMemImmPs
  | 0b011u ->
    chkPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin l c Op.LDRH None N oprRtMemImmPs
  | 0b100u ->
    chkRnPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin l c Op.STR None N oprRtMemImmPs
  | 0b101u ->
    chkPWWBRnPCRtIT bin itstate
    render &itstate 0 isInIT mode addr bin l c Op.LDR None N oprRtMemImmPs
  | _ (* 11x *) -> raise UnallocatedException

/// Load/store, unsigned (negative immediate) on page F3-4203.
let parseLdStUnsignedNegImm (itstate: byref<bl>) isInIT mode addr bin len cond =
  let rt = extract bin 15 12
  match extract bin 22 20 (* size:L *) with
  | 0b000u ->
    chkRnPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len cond Op.STRB None N oprRtMemImm8M
  | 0b001u when rt <> 0b1111u ->
    chkPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len cond Op.LDRB None N oprRtMemImm8M
  | 0b001u ->
    render &itstate 0 isInIT mode addr bin len cond Op.PLD None N oprMemImm8M
  | 0b010u ->
    chkRnPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len cond Op.STRH None N oprRtMemImm8M
  | 0b011u when rt <> 0b1111u ->
    chkPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len cond Op.LDRH None N oprRtMemImm8M
  | 0b011u ->
    chkPCRm bin
    render &itstate 0 isInIT mode addr bin len cond Op.PLDW None N oprMemImm8M
  | 0b100u ->
    chkRnPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len cond Op.STR None N oprRtMemImm8M
  | 0b101u ->
    chkPWWBRnPCRtIT bin itstate
    render &itstate 0 isInIT mode addr bin len cond Op.LDR None N oprRtMemImm8M
  | _ (* 11x *) -> raise UnallocatedException

/// Load/store, unsigned (unprivileged) on page F3-4204.
let parseLdStUnsignedUnpriv (itstate: byref<bl>) isInIT mode addr bin len c =
  match extract bin 22 20 (* size:L *) with
  | 0b000u ->
    chkRnPCRt bin
    render &itstate 0 isInIT mode addr bin len c Op.STRBT None N oprRtMemImm8P
  | 0b001u ->
    chkPCRt bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRBT None N oprRtMemImm8P
  | 0b010u ->
    chkRnPCRt bin
    render &itstate 0 isInIT mode addr bin len c Op.STRHT None N oprRtMemImm8P
  | 0b011u ->
    chkPCRt bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRHT None N oprRtMemImm8P
  | 0b100u ->
    chkRnPCRt bin
    render &itstate 0 isInIT mode addr bin len c Op.STRT None N oprRtMemImm8P
  | 0b101u ->
    chkPCRt bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRT None N oprRtMemImm8P
  | _ (* 11x *) -> raise UnallocatedException

/// Load/store, unsigned (immediate, pre-indexed) on page F3-4204.
let parseLdStUnsignedImmPreIdx (itstate: byref<bl>) isInIT mode addr bin len c =
  match extract bin 22 20 (* size:L *) with
  | 0b000u ->
    chkRnPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len c Op.STRB None N oprRtMemImmPr
  | 0b001u ->
    chkPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRB None N oprRtMemImmPr
  | 0b010u ->
    chkRnPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len c Op.STRH None N oprRtMemImmPr
  | 0b011u ->
    chkPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRH None N oprRtMemImmPr
  | 0b100u ->
    chkRnPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len c Op.STR None N oprRtMemImmPr
  | 0b101u ->
    chkPWWBRnPCRtIT bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.LDR None N oprRtMemImmPr
  | _ (* 11x *) -> raise UnallocatedException

/// Load/store, unsigned (positive immediate) on page F3-4205.
let parseLdStUnsignedPosImm (itstate: byref<bl>) isInIT mode addr bin len cond =
  let rt = extract bin 15 12
  match extract bin 22 20 (* size:L *) with
  | 0b000u ->
    chkRnPCRt bin
    render &itstate 0 isInIT mode addr bin len cond Op.STRB None W oprRtMemImm12
  | 0b001u when rt <> 0b1111u ->
    render &itstate 0 isInIT mode addr bin len cond Op.LDRB None W oprRtMemImm12
  | 0b001u ->
    render &itstate 0 isInIT mode addr bin len cond Op.PLD None N oprMemImm12
  | 0b010u ->
    chkRnPCRt bin
    render &itstate 0 isInIT mode addr bin len cond Op.STRH None W oprRtMemImm12
  | 0b011u when rt <> 0b1111u ->
    render &itstate 0 isInIT mode addr bin len cond Op.LDRH None W oprRtMemImm12
  | 0b011u ->
    render &itstate 0 isInIT mode addr bin len cond Op.PLDW None N oprMemImm12
  | 0b100u ->
    chkRnPCRt bin
    render &itstate 0 isInIT mode addr bin len cond Op.STR None W oprRtMemImm12
  | 0b101u ->
    chkPCRtIT bin itstate
    render &itstate 0 isInIT mode addr bin len cond Op.LDR None W oprRtMemImm12
  | _ (* 11x *) -> raise UnallocatedException

/// Load, unsigned (literal) on page F3-4205.
let parseLdUnsignedLiteral (itstate: byref<bl>) isInIT mode addr bin len cond =
  let rt = extract bin 15 12
  match extract bin 22 20 (* size:L *) with
  | 0b001u | 0b011u when rt = 0b1111u ->
    render &itstate 0 isInIT mode addr bin len cond Op.PLD None N oprLabel12
  | 0b001u ->
    render &itstate 0 isInIT mode addr bin len cond Op.LDRB None N oprRtLabel12
  | 0b011u ->
    render &itstate 0 isInIT mode addr bin len cond Op.LDRH None N oprRtLabel12
  | 0b101u ->
    chkPCRtIT bin itstate
    render &itstate 0 isInIT mode addr bin len cond Op.LDR None W oprRtLabel12
  | 0b110u | 0b111u -> raise UnallocatedException
  | _ -> Utils.impossible ()

/// Load/store, signed (register offset) on page F3-4206.
let parseLdStSignedRegOffset (itstate: byref<bl>) isInIT mode addr bin len c =
  let rt = extract bin 15 12
  match extract bin 22 21 with
  | 0b00u when rt <> 0b1111u ->
    chkPCRm bin
    let struct (q, oprs) =
      if extract bin 5 4 (* imm2 *) = 0b00u then struct (W, oprRtMemReg32)
      else struct (N, oprRtMemRegLSL)
    render &itstate 0 isInIT mode addr bin len c Op.LDRSB None q oprs
  | 0b00u ->
    chkPCRm bin
    render &itstate 0 isInIT mode addr bin len c Op.PLI None N oprMemReg
  | 0b01u when rt <> 0b1111u ->
    chkPCRm bin
    let struct (q, oprs) =
      if extract bin 5 4 (* imm2 *) = 0b00u then struct (W, oprRtMemReg32)
      else struct (N, oprRtMemRegLSL)
    render &itstate 0 isInIT mode addr bin len c Op.LDRSH None q oprs
  | 0b01u ->
    render &itstate 0 isInIT mode addr bin len c Op.NOP None N oprNo
  | _ (* 1x *) -> raise UnallocatedException

/// Load/store, signed (immediate, post-indexed) on page F3-4206.
let parseLdStoreSignedImmPostIdx (itstate: byref<bl>) isInIT mode addr bin l c =
  match extract bin 22 21 (* size *) with
  | 0b00u ->
    chkPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin l c Op.LDRSB None N oprRtMemImmPs
  | 0b01u ->
    chkPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin l c Op.LDRSH None N oprRtMemImmPs
  | _ (* 1x *) -> raise UnallocatedException

/// Load/store, signed (negative immediate) on page F3-4207.
let parseLdStSignedNegImm (itstate: byref<bl>) isInIT mode addr bin len c =
  let rt = extract bin 15 12
  match extract bin 22 21 (* size *) with
  | 0b00u when rt <> 0b1111u ->
    chkPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRSB None N oprRtMemImm8M
  | 0b00u ->
    render &itstate 0 isInIT mode addr bin len c Op.PLI None N oprMemImm8M
  | 0b01u when rt <> 0b1111u ->
    chkPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRSH None N oprRtMemImm8M
  | 0b01u -> render &itstate 0 isInIT mode addr bin len c Op.NOP None N oprNo
  | _ (* 1x *) -> raise UnallocatedException

/// Load/store, signed (unprivileged) on page F3-4207.
let parseLdStSignedUnpriv (itstate: byref<bl>) isInIT mode addr bin len c =
  match extract bin 22 21 (* size *) with
  | 0b00u ->
    chkPCRt bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRSBT None N oprRtMemImm8P
  | 0b01u ->
    chkPCRt bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRSHT None N oprRtMemImm8P
  | _ (* 1x *) -> raise UnallocatedException

/// Load/store, signed (immediate, pre-indexed) on page F3-4208.
let parseLdStSignedImmPreIdx (itstate: byref<bl>) isInIT mode addr bin len c =
  match extract bin 22 21 (* size *) with
  | 0b00u ->
    chkPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRSB None N oprRtMemImmPr
  | 0b01u ->
    chkPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRSH None N oprRtMemImmPr
  | _ (* 1x *) -> raise UnallocatedException

/// Load/store, signed (positive immediate) on page F3-4208.
let parseLdStSignedPosImm (itstate: byref<bl>) isInIT mode addr bin len c =
  let rt = extract bin 15 12
  match extract bin 22 21 (* size *) with
  | 0b00u when rt <> 0b1111u ->
    render &itstate 0 isInIT mode addr bin len c Op.LDRSB None N oprRtMemImm12
  | 0b00u ->
    render &itstate 0 isInIT mode addr bin len c Op.PLI None N oprMemImm12
  | 0b01u when rt <> 0b1111u ->
    chkPWPCRtWBRn bin
    render &itstate 0 isInIT mode addr bin len c Op.LDRSH None N oprRtMemImm12
  | 0b01u -> render &itstate 0 isInIT mode addr bin len c Op.NOP None N oprNo
  | _ (* 1x *) -> Utils.impossible ()

/// Load, signed (literal) on page F3-4209.
let parseLoadSignedLiteral (itstate: byref<bl>) isInIT mode addr bin len c =
  let rt = extract bin 15 12
  match extract bin 22 21 (* size *) with
  | 0b00u when rt <> 0b1111u ->
    render &itstate 0 isInIT mode addr bin len c Op.LDRSB None N oprRtLabel12
  | 0b00u ->
    render &itstate 0 isInIT mode addr bin len c Op.PLI None N oprMemImm12
  | 0b01u when rt <> 0b1111u ->
    render &itstate 0 isInIT mode addr bin len c Op.LDRSH None N oprRtLabel12
  | 0b01u -> render &itstate 0 isInIT mode addr bin len c Op.NOP None N oprNo
  | _ (* 1x *) -> raise UnallocatedException

/// Load/store single on page F3-4201.
let parseLdStSingle (itstate: byref<bl>) isInIT mode addr bin len cond =
  let o2 = extract bin 19 16 (* op2 *)
  let decodeFields (* op0:op1:op3 *) =
    (extract bin 24 23 <<< 7) + (pickBit bin 20 <<< 6) + (extract bin 11 6)
  match decodeFields (* op0:op1:op3 *) with
  | 0b000000000u | 0b001000000u (* 00x000000 *) when o2 <> 0b1111u ->
    parseLdStUnsignedRegOffset &itstate isInIT mode addr bin len cond
  | 0b000000001u | 0b001000001u (* 00x000001 *) when o2 <> 0b1111u ->
    raise UnallocatedException
  | b when b &&& 0b110111110u = 0b000000010u (* 00x00001x *) && o2 <> 0b1111u ->
    raise UnallocatedException
  | b when b &&& 0b110111100u = 0b000000100u (* 00x0001xx *) && o2 <> 0b1111u ->
    raise UnallocatedException
  | b when b &&& 0b110111000u = 0b000001000u (* 00x001xxx *) && o2 <> 0b1111u ->
    raise UnallocatedException
  | b when b &&& 0b110110000u = 0b000010000u (* 00x01xxxx *) && o2 <> 0b1111u ->
    raise UnallocatedException
  | b when b &&& 0b110110100u = 0b000100000u (* 00x10x0xx *) && o2 <> 0b1111u ->
    raise UnallocatedException
  | b when b &&& 0b110110100u = 0b000100100u (* 00x10x1xx *) && o2 <> 0b1111u ->
    parseLdStUnsignedImmPostIdx &itstate isInIT mode addr bin len cond
  | b when b &&& 0b110111100u = 0b000110000u (* 00x1100xx *) && o2 <> 0b1111u ->
    parseLdStUnsignedNegImm &itstate isInIT mode addr bin len cond
  | b when b &&& 0b110111100u = 0b000111000u (* 00x1110xx *) && o2 <> 0b1111u ->
    parseLdStUnsignedUnpriv &itstate isInIT mode addr bin len cond
  | b when b &&& 0b110110100u = 0b000110100u (* 00x11x1xx *) && o2 <> 0b1111u ->
    parseLdStUnsignedImmPreIdx &itstate isInIT mode addr bin len cond
  | b when b &&& 0b110000000u = 0b010000000u (* 01xxxxxxx *) && o2 <> 0b1111u ->
    parseLdStUnsignedPosImm &itstate isInIT mode addr bin len cond
  | b when b &&& 0b100000000u = 0b000000000u (* 0xxxxxxxx *) && o2 = 0b1111u ->
    parseLdUnsignedLiteral &itstate isInIT mode addr bin len cond
  | 0b101000000u when o2 <> 0b1111u ->
    parseLdStSignedRegOffset &itstate isInIT mode addr bin len cond
  | 0b101000001u when o2 <> 0b1111u -> raise UnallocatedException
  | b when b &&& 0b111111110u = 0b101000010u (* 10100001x *) && o2 <> 0b1111u ->
    raise UnallocatedException
  | b when b &&& 0b111111100u = 0b101000100u (* 1010001xx *) && o2 <> 0b1111u ->
    raise UnallocatedException
  | b when b &&& 0b111111000u = 0b101001000u (* 101001xxx *) && o2 <> 0b1111u ->
    raise UnallocatedException
  | b when b &&& 0b111110000u = 0b101010000u (* 10101xxxx *) && o2 <> 0b1111u ->
    raise UnallocatedException
  | b when b &&& 0b111110100u = 0b101100000u (* 10110x0xx *) && o2 <> 0b1111u ->
    raise UnallocatedException
  | b when b &&& 0b111110100u = 0b101100100u (* 10110x1xx *) && o2 <> 0b1111u ->
    parseLdStoreSignedImmPostIdx &itstate isInIT mode addr bin len cond
  | b when b &&& 0b111111100u = 0b101110000u (* 1011100xx *) && o2 <> 0b1111u ->
    parseLdStSignedNegImm &itstate isInIT mode addr bin len cond
  | b when b &&& 0b111111100u = 0b101111000u (* 1011110xx *) && o2 <> 0b1111u ->
    parseLdStSignedUnpriv &itstate isInIT mode addr bin len cond
  | b when b &&& 0b111110100u = 0b101110100u (* 10111x1xx *) && o2 <> 0b1111u ->
    parseLdStSignedImmPreIdx &itstate isInIT mode addr bin len cond
  | b when b &&& 0b111000000u = 0b111000000u (* 111xxxxxx *) && o2 <> 0b1111u ->
    parseLdStSignedPosImm &itstate isInIT mode addr bin len cond
  | b when b &&& 0b101000000u = 0b101000000u (* 1x1xxxxxx *) && o2 = 0b1111u ->
    parseLoadSignedLiteral &itstate isInIT mode addr bin len cond
  | _ -> Utils.impossible ()

/// Register extends on page F3-4210.
let parseRegExtends (itstate: byref<bl>) isInIT mode addr bin len c =
  let rn = extract bin 19 16
  match extract bin 22 20 (* op1:U *) with
  | 0b000u when rn <> 0b1111u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SXTAH None N oprRdRnRmROR
  | 0b000u ->
    chkPCRdRm bin
    let struct (q, oprs) =
      if extract bin 5 4 (* rotate *) = 0b00u then struct (W, oprRdRmT32)
      else struct (N, oprRdRmROR)
    render &itstate 0 isInIT mode addr bin len c Op.SXTH None q oprs
  | 0b001u when rn <> 0b1111u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UXTAH None N oprRdRnRmROR
  | 0b001u ->
    chkPCRdRm bin
    let struct (q, oprs) =
      if extract bin 5 4 (* rotate *) = 0b00u then struct (W, oprRdRmT32)
      else struct (N, oprRdRmROR)
    render &itstate 0 isInIT mode addr bin len c Op.UXTH None q oprs
  | 0b010u when rn <> 0b1111u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SXTAB16 None N oprRdRnRmROR
  | 0b010u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SXTB16 None N oprRdRmROR
  | 0b011u when rn <> 0b1111u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UXTAB16 None N oprRdRnRmROR
  | 0b011u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UXTB16 None N oprRdRmROR
  | 0b100u when rn <> 0b1111u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SXTAB None N oprRdRnRmROR
  | 0b100u ->
    chkPCRdRm bin
    let struct (q, oprs) =
      if extract bin 5 4 (* rotate *) = 0b00u then struct (W, oprRdRmT32)
      else struct (N, oprRdRmROR)
    render &itstate 0 isInIT mode addr bin len c Op.SXTB None q oprs
  | 0b101u when rn <> 0b1111u ->
    chkPCRdRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UXTAB None N oprRdRnRmROR
  | 0b101u ->
    chkPCRdRm bin
    let struct (q, oprs) =
      if extract bin 5 4 (* rotate *) = 0b00u then struct (W, oprRdRmT32)
      else struct (N, oprRdRmROR)
    render &itstate 0 isInIT mode addr bin len c Op.UXTB None q oprs
  | _ (* 11x *) -> raise UnallocatedException

/// Parallel add-subtract on page F3-4210.
let parseParallelAddSub (itstate: byref<bl>) isInIT mode addr bin len c =
  match concat (extract bin 22 20) (extract bin 6 4) 3 (* op1:U:H:S *) with
  | 0b000000u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SADD8 None N oprRdRnRmT32
  | 0b000001u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.QADD8 None N oprRdRnRmT32
  | 0b000010u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SHADD8 None N oprRdRnRmT32
  | 0b000011u -> raise UnallocatedException
  | 0b000100u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UADD8 None N oprRdRnRmT32
  | 0b000101u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UQADD8 None N oprRdRnRmT32
  | 0b000110u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UHADD8 None N oprRdRnRmT32
  | 0b000111u -> raise UnallocatedException
  | 0b001000u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SADD16 None N oprRdRnRmT32
  | 0b001001u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.QADD16 None N oprRdRnRmT32
  | 0b001010u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SHADD16 None N oprRdRnRmT32
  | 0b001011u -> raise UnallocatedException
  | 0b001100u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UADD16 None N oprRdRnRmT32
  | 0b001101u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UQADD16 None N oprRdRnRmT32
  | 0b001110u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UHADD16 None N oprRdRnRmT32
  | 0b001111u -> raise UnallocatedException
  | 0b010000u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SASX None N oprRdRnRmT32
  | 0b010001u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.QASX None N oprRdRnRmT32
  | 0b010010u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SHASX None N oprRdRnRmT32
  | 0b010011u -> raise UnallocatedException
  | 0b010100u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UASX None N oprRdRnRmT32
  | 0b010101u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UQASX None N oprRdRnRmT32
  | 0b010110u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UHASX None N oprRdRnRmT32
  | 0b010111u -> raise UnallocatedException
  | 0b100000u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SSUB8 None N oprRdRnRmT32
  | 0b100001u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.QSUB8 None N oprRdRnRmT32
  | 0b100010u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SHSUB8 None N oprRdRnRmT32
  | 0b100011u -> raise UnallocatedException
  | 0b100100u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.USUB8 None N oprRdRnRmT32
  | 0b100101u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UQSUB8 None N oprRdRnRmT32
  | 0b100110u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UHSUB8 None N oprRdRnRmT32
  | 0b100111u -> raise UnallocatedException
  | 0b101000u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SSUB16 None N oprRdRnRmT32
  | 0b101001u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.QSUB16 None N oprRdRnRmT32
  | 0b101010u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SHSUB16 None N oprRdRnRmT32
  | 0b101011u -> raise UnallocatedException
  | 0b101100u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.USUB16 None N oprRdRnRmT32
  | 0b101101u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UQSUB16 None N oprRdRnRmT32
  | 0b101110u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UHSUB16 None N oprRdRnRmT32
  | 0b101111u -> raise UnallocatedException
  | 0b110000u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SSAX None N oprRdRnRmT32
  | 0b110001u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.QSAX None N oprRdRnRmT32
  | 0b110010u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SHSAX None N oprRdRnRmT32
  | 0b110011u -> raise UnallocatedException
  | 0b110100u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.USAX None N oprRdRnRmT32
  | 0b110101u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UQSAX None N oprRdRnRmT32
  | 0b110110u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.UHSAX None N oprRdRnRmT32
  | 0b110111u -> raise UnallocatedException
  | _ (* 111xxx *) -> raise UnallocatedException

/// Data-processing (two source registers) on page F3-4212.
let parseDataProcTwoSrcRegs (itstate: byref<bl>) isInIT mode addr bin len c =
  match concat (extract bin 22 20) (extract bin 5 4) 2 (* op1:op2 *) with
  | 0b00000u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.QADD None N oprRdRmRn
  | 0b00001u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.QDADD None N oprRdRmRn
  | 0b00010u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.QSUB None N oprRdRmRn
  | 0b00011u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.QDSUB None N oprRdRmRn
  | 0b00100u ->
    chkRmRnPCRdRm bin
    render &itstate 0 isInIT mode addr bin len c Op.REV None W oprRdRmT32
  | 0b00101u ->
    chkRmRnPCRdRm bin
    render &itstate 0 isInIT mode addr bin len c Op.REV16 None W oprRdRmT32
  | 0b00110u ->
    chkRmRnPCRdRm bin
    render &itstate 0 isInIT mode addr bin len c Op.RBIT None N oprRdRmT32
  | 0b00111u ->
    chkRmRnPCRdRm bin
    render &itstate 0 isInIT mode addr bin len c Op.REVSH None W oprRdRmT32
  | 0b01000u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SEL None N oprRdRnRmT32
  | 0b01001u -> raise UnallocatedException
  | 0b01010u | 0b01011u (* 0101x *) -> raise UnallocatedException
  | 0b01100u ->
    chkRmRnPCRdRm bin
    render &itstate 0 isInIT mode addr bin len c Op.CLZ None N oprRdRmT32
  | 0b01101u -> raise UnallocatedException
  | 0b01110u | 0b01111u (* 0111x *) -> raise UnallocatedException
  | 0b10000u ->
    chkITPCRdRnRm bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.CRC32B None N oprRdRnRmT32
  | 0b10001u ->
    chkITPCRdRnRm bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.CRC32H None N oprRdRnRmT32
  | 0b10010u ->
    chkITPCRdRnRm bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.CRC32W None N oprRdRnRmT32
  | 0b10011u -> raise UnpredictableException
  | 0b10100u ->
    chkITPCRdRnRm bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.CRC32CB None N oprRdRnRmT32
  | 0b10101u ->
    chkITPCRdRnRm bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.CRC32CH None N oprRdRnRmT32
  | 0b10110u ->
    chkITPCRdRnRm bin itstate
    render &itstate 0 isInIT mode addr bin len c Op.CRC32CW None N oprRdRnRmT32
  | 0b10111u -> raise UnpredictableException
  | _ (* 11xxx *) -> raise UnallocatedException

/// Data-processing (register) on page F3-4209.
let parseDataProcessingReg (itstate: byref<bl>) isInIT mode addr bin len cond =
  let decodeFields (* op0:op1:op2 *) =
    (pickBit bin 23 <<< 8) + (extract bin 15 12 <<< 4) + (extract bin 7 4)
  match decodeFields with
  | 0b011110000u -> (* FIXME: Alias conditions on page F5-4562 *)
    chkPCRdRmRs bin
    let struct (op, q) =
      if pickBit bin 20 (* S *) = 1u then
        if inITBlock itstate |> not then struct (Op.MOVS, W)
        else struct (Op.MOVS, N)
      else if inITBlock itstate then struct (Op.MOV, W) else struct (Op.MOV, N)
    render &itstate 0 isInIT mode addr bin len cond op None q oprRdRmShfRs
  | 0b011110001u -> raise UnallocatedException
  | 0b011110010u | 0b011110011u (* 01111001x *) -> raise UnallocatedException
  | b when b &&& 0b111111100u = 0b011110100u (* 0111101xx *) ->
    raise UnallocatedException
  | b when b &&& 0b111111000u = 0b011111000u (* 011111xxx *) ->
    parseRegExtends &itstate isInIT mode addr bin len cond
  | b when b &&& 0b111111000u = 0b111110000u (* 111110xxx *) ->
    parseParallelAddSub &itstate isInIT mode addr bin len cond
  | b when b &&& 0b111111100u = 0b111111000u (* 1111110xx *) ->
    parseDataProcTwoSrcRegs &itstate isInIT mode addr bin len cond
  | b when b &&& 0b111111100u = 0b111111100u (* 1111111xx *) ->
    raise UnallocatedException
  | _ (* x != 1111 xxxx *) -> raise UnallocatedException

/// Multiply and absolute difference on page F3-4213.
let parseMulAndAbsDiff (itstate: byref<bl>) isInIT mode addr bin len c =
  let ra = extract bin 15 12
  match concat (extract bin 22 20) (extract bin 5 4) 2 (* op1:op2 *) with
  | 0b00000u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.MLA None N oprRdRnRmRa
  | 0b00001u ->
    chkPCRdRnRmRa bin
    render &itstate 0 isInIT mode addr bin len c Op.MLS None N oprRdRnRmRa
  | 0b00010u | 0b00011u (* 0001x *) -> raise UnallocatedException
  | 0b00000u ->
    chkPCRdRnRm bin
    let q = if inITBlock itstate then W else N
    render &itstate 0 isInIT mode addr bin len c Op.MUL None q oprRdRnRmT32
  | 0b00100u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMLABB None N oprRdRnRmRa
  | 0b00101u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMLABT None N oprRdRnRmRa
  | 0b00110u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMLATB None N oprRdRnRmRa
  | 0b00111u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMLATT None N oprRdRnRmRa
  | 0b00100u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMULBB None N oprRdRnRmT32
  | 0b00101u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMULBT None N oprRdRnRmT32
  | 0b00110u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMULTB None N oprRdRnRmT32
  | 0b00111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMULTT None N oprRdRnRmT32
  | 0b01000u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMLAD None N oprRdRnRmRa
  | 0b01001u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMLADX None N oprRdRnRmRa
  | 0b01010u | 0b01011u (* 0101x *) -> raise UnallocatedException
  | 0b01000u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMUAD None N oprRdRnRmT32
  | 0b01001u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMUADX None N oprRdRnRmT32
  | 0b01100u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMLAWB None N oprRdRnRmRa
  | 0b01101u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMLAWT None N oprRdRnRmRa
  | 0b01110u | 0b01111u (* 0111x *) -> raise UnallocatedException
  | 0b01100u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMULWB None N oprRdRnRmT32
  | 0b01101u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMULWT None N oprRdRnRmT32
  | 0b10000u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMLSD None N oprRdRnRmRa
  | 0b10001u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMLSDX None N oprRdRnRmRa
  | 0b10010u | 0b10011u (* 1001x *) -> raise UnallocatedException
  | 0b10000u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMUSD None N oprRdRnRmT32
  | 0b10001u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMUSDX None N oprRdRnRmT32
  | 0b10100u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMMLA None N oprRdRnRmRa
  | 0b10101u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMMLAR None N oprRdRnRmRa
  | 0b10110u | 0b10111u (* 1011x *) -> raise UnallocatedException
  | 0b10100u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMMUL None N oprRdRnRmT32
  | 0b10101u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMMULR None N oprRdRnRmT32
  | 0b11000u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMMLS None N oprRdRnRmRa
  | 0b11001u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.SMMLSR None N oprRdRnRmRa
  | 0b11010u | 0b11011u (* 1101x *) -> raise UnallocatedException
  | 0b11100u when ra <> 0b1111u ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.USADA8 None N oprRdRnRmRa
  | 0b11101u -> raise UnallocatedException
  | 0b11110u | 0b11111u (* 1111x *) -> raise UnallocatedException
  | _ (* 11100 *) ->
    chkPCRdRnRm bin
    render &itstate 0 isInIT mode addr bin len c Op.USAD8 None N oprRdRnRmT32

/// Multiply, multiply accumulate, and absolute difference on page F3-4213.
let parseMulAccumlateAndAbsDiff (itstate: byref<bl>) isInIT mode addr bin l c =
  match extract bin 7 6 (* op0 *) with
  | 0b00u -> parseMulAndAbsDiff &itstate isInIT mode addr bin l c
  | 0b01u -> raise UnallocatedException
  | _ (* 11 *) -> raise UnallocatedException

/// Long multiply and divide on page F3-4163.
let parseLongMulAndDiv (itstate: byref<bl>) isInIT mode addr bin l c =
  let op2 = extract bin 7 4
  match extract bin 22 20 (* op1 *) with
  | 0b000u when op2 <> 0b0000u -> raise UnallocatedException
  | 0b000u ->
    chkPCRdlRdhRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.SMULL None N oprRdlRdhRnRm
  | 0b001u when op2 <> 0b1111u -> raise UnallocatedException
  | 0b001u ->
    chkPCRdRnRmRaNot bin
    render &itstate 0 isInIT mode addr bin l c Op.SDIV None N oprRdRnRmT32
  | 0b010u when op2 <> 0b0000u -> raise UnallocatedException
  | 0b010u ->
    chkPCRdlRdhRnRm bin
    render &itstate 0 isInIT mode addr bin l c Op.UMULL None N oprRdlRdhRnRm
  | 0b011u when op2 <> 0b1111u -> raise UnallocatedException
  | 0b011u ->
    chkPCRdRnRmRaNot bin
    render &itstate 0 isInIT mode addr bin l c Op.UDIV None N oprRdRnRmT32
  | _ ->
    match concat (extract bin 22 20) (extract bin 7 4) 4 (* op1:op2 *) with
    | 0b1000000u ->
      chkPCRdlRdhRnRm bin
      render &itstate 0 isInIT mode addr bin l c Op.SMLAL None N oprRdlRdhRnRm
    | 0b1000001u -> raise UnallocatedException
    | 0b1000010u | 0b1000011u (* 100001x *) -> raise UnallocatedException
    | 0b1000100u | 0b1000101u | 0b1000110u | 0b1000111u (* 10001xx *) ->
      raise UnallocatedException
    | 0b1001000u ->
      chkPCRdlRdhRnRm bin
      render &itstate 0 isInIT mode addr bin l c Op.SMLALBB None N oprRdlRdhRnRm
    | 0b1001001u ->
      chkPCRdlRdhRnRm bin
      render &itstate 0 isInIT mode addr bin l c Op.SMLALBT None N oprRdlRdhRnRm
    | 0b1001010u ->
      chkPCRdlRdhRnRm bin
      render &itstate 0 isInIT mode addr bin l c Op.SMLALTB None N oprRdlRdhRnRm
    | 0b1001011u ->
      chkPCRdlRdhRnRm bin
      render &itstate 0 isInIT mode addr bin l c Op.SMLALTT None N oprRdlRdhRnRm
    | 0b1001100u ->
      chkPCRdlRdhRnRm bin
      render &itstate 0 isInIT mode addr bin l c Op.SMLALD None N oprRdlRdhRnRm
    | 0b1001101u ->
      chkPCRdlRdhRnRm bin
      render &itstate 0 isInIT mode addr bin l c Op.SMLALDX None N oprRdlRdhRnRm
    | 0b1001110u | 0b1001111u (* 100111x *) -> raise UnallocatedException
    | b when b &&& 0b1111000u = 0b1010000u (* 1010xxx *) ->
      raise UnallocatedException
    | 0b1011000u | 0b1011001u | 0b1011010u | 0b1011011u (* 10110xx *) ->
      raise UnallocatedException
    | 0b1011100u ->
      chkPCRdlRdhRnRm bin
      render &itstate 0 isInIT mode addr bin l c Op.SMLSLD None N oprRdlRdhRnRm
    | 0b1011101u ->
      chkPCRdlRdhRnRm bin
      render &itstate 0 isInIT mode addr bin l c Op.SMLSLDX None N oprRdlRdhRnRm
    | 0b1011110u | 0b1011111u (* 101111x *) -> raise UnallocatedException
    | 0b1100000u ->
      chkPCRdlRdhRnRm bin
      render &itstate 0 isInIT mode addr bin l c Op.UMLAL None N oprRdlRdhRnRm
    | 0b1100001u -> raise UnallocatedException
    | 0b1100010u | 0b1100011u (* 110001x *) -> raise UnallocatedException
    | 0b1100100u | 0b1100101u (* 110010x *) -> raise UnallocatedException
    | 0b1100110u ->
      chkPCRdlRdhRnRm bin
      render &itstate 0 isInIT mode addr bin l c Op.UMAAL None N oprRdlRdhRnRm
    | 0b1100111u -> raise UnallocatedException
    | b when b &&& 0b1111000u = 0b1101000u (* 1101xxx *) ->
      raise UnallocatedException
    | _ (* 111xxxx *) -> raise UnallocatedException

/// 32-bit on page F3-4159.
let parse32Bit (itstate: byref<bl>) isInIT mode addr bin len cond =
  match concat (extract bin 28 25) (pickBit bin 15) 1 (* op0:op3 *) with
  | b when b &&& 0b01100u = 0b01100u (* x11x xxxxx x *) ->
    parseSystemRegAccessAdvSIMDAndFP &itstate isInIT mode addr bin len cond
  | 0b01000u | 0b01001u when pickBit bin 22 = 0u (* 0100 xx0xx x *) ->
    parseLdStMul &itstate isInIT mode addr bin len cond
  | 0b01000u | 0b01001u when pickBit bin 22 = 1u (* 0100 xx1xx x *) ->
    parseLdStDualExclusiveAndTblBranch &itstate isInIT mode addr bin len cond
  | 0b01010u | 0b01011u (* 0101 xxxxx x *) ->
    parseDataProcessingShiftReg &itstate isInIT mode addr bin len cond
  | 0b10001u | 0b10011u | 0b10101u | 0b10111u (* 10xx xxxxx 1 *) ->
    parseBranchAndMiscCtrl &itstate isInIT mode addr bin len cond
  | 0b10000u | 0b10100u (* 10x0 xxxxx 0 *) ->
    parseDataProcessingModImm &itstate isInIT mode addr bin len cond
  | 0b10010u | 0b10110u when pickBit bin 20 = 0u (* 10x1 xxxx0 0 *) ->
    parseDataProcessingPlainBinImm &itstate isInIT mode addr bin len cond
  | 0b10010u | 0b10110u when pickBit bin 20 = 1u (* 10x1 xxxx1 0 *) ->
    raise UnallocatedException
  | 0b11000u | 0b11001u
    when extract bin 24 20 &&& 0b10001u = 0b10000u (* 1100 1xxx0 x *) ->
    parseAdvSIMDElemOrStructLdSt &itstate isInIT mode addr bin len cond
  | 0b11000u | 0b11001u (* 1100 != 1xxx0 x *) ->
    parseLdStSingle &itstate isInIT mode addr bin len cond
  | 0b11010u | 0b11011u when pickBit bin 24 = 0u (* 1101 0xxxx x *) ->
    parseDataProcessingReg &itstate isInIT mode addr bin len cond
  | 0b11010u | 0b11011u when extract bin 24 23 = 0b10u (* 1101 10xxx x *) ->
    parseMulAccumlateAndAbsDiff &itstate isInIT mode addr bin len cond
  | 0b11010u | 0b11011u when extract bin 24 23 = 0b11u (* 1101 11xxx x *) ->
    parseLongMulAndDiv &itstate isInIT mode addr bin len cond
  | _ -> Utils.impossible ()

/// ARM Architecture Reference Manual ARMv8-A, ARM DDI 0487F.c ID072120
/// T32 instruction set encoding on page F3-4148.
let parse (reader: BinReader) mode (itstate: byref<bl>) addr pos =
  let isInIT = not itstate.IsEmpty
  let cond = getCondWithITSTATE itstate
  let struct (bin, nextPos) = reader.ReadUInt16 pos
  let bin = uint32 bin
  match extract bin 15 11 (* op0:op1 *) with
  | 0b11100u ->
    chkInITLastIT itstate
    let len = nextPos - pos |> uint32
    render &itstate 0 isInIT mode addr bin len cond Op.B None N oprLabel
  | 0b11101u | 0b11110u | 0b11111u (* 111 != 00 *) ->
    let struct (bin2, nextPos) = reader.ReadUInt16 nextPos
    let len = nextPos - pos |> uint32
    parse32Bit &itstate isInIT mode addr ((bin <<< 16) + (uint32 bin2)) len cond
  | _ (* != 111 xx *) ->
    parse16Bit &itstate isInIT mode addr bin (nextPos - pos |> uint32) cond

// vim: set tw=80 sts=2 sw=2:
