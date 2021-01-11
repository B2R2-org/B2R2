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

module internal B2R2.FrontEnd.BinLifter.ARM32.Parserv8

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ARM32.ParseUtils
open B2R2.FrontEnd.BinLifter.ARM32.OperandHelper

let getRegDCAOprsWithUnpreA bin =
  p3Oprs bin chkUnpreA (getRegD, getRegC, getRegA)

/// Parallel Arithmetic, page F4-2522
let parsePhrallelArithmetic bin =
  let op = concat (extract bin 22u 20u) (extract bin 6u 5u) 2
  match concat op (pickBit bin 7u) 1 with
  | b when b &&& 0b111000u = 0b000000u -> raise UnallocatedException
  | 0b001000u -> Op.SADD16, getRegDCAOprsWithUnpreA bin
  | 0b001001u -> Op.SADD8, getRegDCAOprsWithUnpreA bin
  | 0b001010u -> Op.SASX, getRegDCAOprsWithUnpreA bin
  | 0b001011u -> raise UnallocatedException
  | 0b001100u -> Op.SSAX, getRegDCAOprsWithUnpreA bin
  | 0b001101u -> raise UnallocatedException
  | 0b001110u -> Op.SSUB16, getRegDCAOprsWithUnpreA bin
  | 0b001111u -> Op.SSUB8, getRegDCAOprsWithUnpreA bin
  | 0b010000u -> Op.QADD16, getRegDCAOprsWithUnpreA bin
  | 0b010001u -> Op.QADD8, getRegDCAOprsWithUnpreA bin
  | 0b010010u -> Op.QASX, getRegDCAOprsWithUnpreA bin
  | 0b010011u -> raise UnallocatedException
  | 0b010100u -> Op.QSAX, getRegDCAOprsWithUnpreA bin
  | 0b010101u -> raise UnallocatedException
  | 0b010110u -> Op.QSUB16, getRegDCAOprsWithUnpreA bin
  | 0b010111u -> Op.QSUB8, getRegDCAOprsWithUnpreA bin
  | 0b011000u -> Op.SHADD16, getRegDCAOprsWithUnpreA bin
  | 0b011001u -> Op.SHADD8, getRegDCAOprsWithUnpreA bin
  | 0b011010u -> Op.SHASX, getRegDCAOprsWithUnpreA bin
  | 0b011011u -> raise UnallocatedException
  | 0b011100u -> Op.SHSAX, getRegDCAOprsWithUnpreA bin
  | 0b011101u -> raise UnallocatedException
  | 0b011110u -> Op.SHSUB16, getRegDCAOprsWithUnpreA bin
  | 0b011111u -> Op.SHSUB8, getRegDCAOprsWithUnpreA bin
  | b when b &&& 0b111000u = 0b100000u -> raise UnallocatedException
  | 0b101000u -> Op.UADD16, getRegDCAOprsWithUnpreA bin
  | 0b101001u -> Op.UADD8, getRegDCAOprsWithUnpreA bin
  | 0b101010u -> Op.UASX, getRegDCAOprsWithUnpreA bin
  | 0b101011u -> raise UnallocatedException
  | 0b101100u -> Op.USAX, getRegDCAOprsWithUnpreA bin
  | 0b101101u -> raise UnallocatedException
  | 0b101110u -> Op.USUB16, getRegDCAOprsWithUnpreA bin
  | 0b101111u -> Op.USUB8, getRegDCAOprsWithUnpreA bin
  | 0b110000u -> Op.UQADD16, getRegDCAOprsWithUnpreA bin
  | 0b110001u -> Op.UQADD8, getRegDCAOprsWithUnpreA bin
  | 0b110010u -> Op.UQASX, getRegDCAOprsWithUnpreA bin
  | 0b110011u -> raise UnallocatedException
  | 0b110100u -> Op.UQSAX, getRegDCAOprsWithUnpreA bin
  | 0b110101u -> raise UnallocatedException
  | 0b110110u -> Op.UQSUB16, getRegDCAOprsWithUnpreA bin
  | 0b110111u -> Op.UQSUB8, getRegDCAOprsWithUnpreA bin
  | 0b111000u -> Op.UHADD16, getRegDCAOprsWithUnpreA bin
  | 0b111001u -> Op.UHADD8, getRegDCAOprsWithUnpreA bin
  | 0b111010u -> Op.UHASX, getRegDCAOprsWithUnpreA bin
  | 0b111011u -> raise UnallocatedException
  | 0b111100u -> Op.UHSAX, getRegDCAOprsWithUnpreA bin
  | 0b111101u -> raise UnallocatedException
  | 0b111110u -> Op.UHSUB16, getRegDCAOprsWithUnpreA bin
  | 0b111111u -> Op.UHSUB8, getRegDCAOprsWithUnpreA bin
  | _ -> failwith "Wrong phrallel arithmetic."

/// Saturate 16-bit, page F4-2524
let parseSaturate16Bit bin =
  let oprs = p3Oprs bin chkUnpreM (getRegA, getImm4B, getRegA)
  if pickBit bin 22u = 0b0u then Op.SSAT16 else Op.USAT16
  , oprs

/// Reverse Bit/Byte, page F4-2524
let pReverseBitByte bin =
  match concat (pickBit bin 22u) (pickBit bin 7u) 1 with
  | 0b00u -> Op.REV, p2Oprs bin chkUnpreE (getRegD, getRegA)
  | 0b01u -> Op.REV16, p2Oprs bin chkUnpreE (getRegD, getRegA)
  | 0b10u -> Op.RBIT, p2Oprs bin chkUnpreE (getRegD, getRegA)
  | 0b11u -> Op.REVSH, p2Oprs bin chkUnpreE (getRegD, getRegA)
  | _ -> failwith "Wrong reverse bit/byte."

/// Saturate 32-bit, page F4-2524
let parseSaturate32Bit bin =
  let opcode = if pickBit bin 22u = 0b0u then Op.SSAT else Op.USAT
  opcode, p4Oprs bin chkUnpreO (getRegD, getImm5C, getRegA, getShiftD)

/// Extend and Add, page F4-2525
let pExtendAndAdd bin =
  let opU = concat (extract bin 21u 20u) (pickBit bin 22u) 1
  let getThreeOprs () = p3Oprs bin chkUnpreP (getRegD, getRegA, getShiftC)
  let getFourOprs () =
    p4Oprs bin chkUnpreO (getRegD, getRegC, getRegA, getShiftC)
  match opU, extract bin 19u 16u with
  | 0b000u, 0b1111u -> Op.SXTB16, getThreeOprs ()
  | 0b000u, _ -> Op.SXTAB16, getFourOprs ()
  | 0b001u, 0b1111u -> Op.UXTB16, getThreeOprs ()
  | 0b001u, _ -> Op.UXTAB16, getFourOprs ()
  | 0b100u, 0b1111u -> Op.SXTB, getThreeOprs ()
  | 0b100u, _ -> Op.SXTAB, getFourOprs ()
  | 0b101u, 0b1111u -> Op.UXTB, getThreeOprs ()
  | 0b101u, _ -> Op.UXTAB, getFourOprs ()
  | 0b110u, 0b1111u -> Op.SXTH, getThreeOprs ()
  | 0b110u, _ -> Op.SXTAH, getFourOprs ()
  | 0b111u, 0b1111u -> Op.UXTH, getThreeOprs ()
  | 0b111u, _ -> Op.UXTAH, getFourOprs ()
  | _ -> failwith "Wrong extend and add."

/// Signed multiply, Divide, page F4-2525
let parseSignedMultiplyDivide bin =
  let op2 = extract bin 7u 5u
  let op = concat (extract bin 22u 20u) op2 3
  let ra = extract bin 15u 12u
  let chkOp2 () = op2 <> 0b000u
  let chkRa () = ra <> 0b1111u
  match op with
  | 0b000000u when chkRa () ->
    Op.SMLAD, p4Oprs bin chkUnpreC (getRegC, getRegA, getRegB, getRegD)
  | 0b000000u -> Op.SMUAD, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b000001u when chkRa () ->
    Op.SMLADX, p4Oprs bin chkUnpreC (getRegC, getRegA, getRegB, getRegD)
  | 0b000001u -> Op.SMUADX, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b000010u when chkRa () ->
    Op.SMLSD, p4Oprs bin chkUnpreC (getRegC, getRegA, getRegB, getRegD)
  | 0b000010u -> Op.SMUSD, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b000011u when chkRa () ->
    Op.SMLSDX, p4Oprs bin chkUnpreC (getRegC, getRegA, getRegB, getRegD)
  | 0b000011u -> Op.SMUSDX, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | op when op &&& 0b111100u = 0b000100u -> raise UnallocatedException
  | op when op &&& 0b111000u = 0b001000u && chkOp2 () ->
    raise UnallocatedException
  | 0b001000u -> Op.SDIV, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | op when op &&& 0b111000u = 0b010000u -> raise UnallocatedException
  | op when op &&& 0b111000u = 0b011000u && chkOp2 () ->
    raise UnallocatedException
  | 0b011000u -> Op.UDIV, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b100000u ->
    Op.SMLALD, p4Oprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b100001u ->
    Op.SMLALDX, p4Oprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b100010u ->
    Op.SMLSLD, p4Oprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b100011u ->
    Op.SMLSLDX, p4Oprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | op when op &&& 0b111100u = 0b100100u -> raise UnallocatedException
  | 0b101000u when chkRa () ->
    Op.SMMLA, p4Oprs bin chkUnpreC (getRegC, getRegA, getRegB, getRegD)
  | 0b101000u -> Op.SMMUL, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b101001u when chkRa () ->
    Op.SMMLAR, p4Oprs bin chkUnpreC (getRegC, getRegA, getRegB, getRegD)
  | 0b101001u -> Op.SMMULR, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | op when op &&& 0b111110u = 0b101010u -> raise UnallocatedException
  | op when op &&& 0b111110u = 0b101100u -> raise UnallocatedException
  | 0b101110u ->
    Op.SMMLS, p4Oprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
  | 0b101111u ->
    Op.SMMLSR, p4Oprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
  | op when op &&& 0b110000u = 0b110000u -> raise UnallocatedException
  | _ -> failwith "Wrong signed multiplies."

/// Unsigned Sum of Absolute Differences, page F4-2527
let unsignedSumAbsoluteDiff bin =
  if extract bin 15u 12u <> 0b1111u
    then Op.USAD8, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  else Op.USADA8, p4Oprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)

/// Bitfield Insert, page F4-2527
let pBitfieldInsert bin =
  if extract bin 3u 0u <> 0b1111u then
    Op.BFI, p4Oprs bin chkUnpreAQ (getRegD, getRegA, getImm5A, getImm5F)
  else Op.BFC, p3Oprs bin chkUnpreAP (getRegD, getImm5A, getImm5F)

/// Permanently UNDEFINED, page F4-2527
let parsePermanentlyUndefined cond bin =
  if cond = Condition.AL then Op.UDF, p1Opr bin dummyChk getImm12D
  else raise UnallocatedException

/// Bitfield Extract, page F4-2528
let pBitfieldExtract bin =
  let opcode = if pickBit bin 22u = 0b0u then Op.SBFX else Op.UBFX
  opcode, p4Oprs bin chkUnpreQ (getRegD, getRegA, getImm5A, getImm5C)

/// Advanced SIMD and floating-point 64-bit move, page F4-2532
let getAdvSIMDNFloat64Bit bin =
  let opOpc2 = concat (pickBit bin 20u) (extract bin 7u 6u) 2
  let o3D = concat (pickBit bin 4u) (pickBit bin 22u) 1
  let op = concat opOpc2 o3D 2
  let chkSz = pickBit bin 8u = 0b0u
  let chkOp = pickBit bin 20u = 0b0u
  match op with
  | op when op &&& 0b00001u = 0b00000u -> raise UnallocatedException
  | 0b00011u when chkSz && chkOp ->
    Op.VMOV, p4Oprs bin chkUnpreAW (getRegAI, getRegAJ, getRegD, getRegC)
  | 0b00011u when chkSz ->
    Op.VMOV, p4Oprs bin chkUnpreAX (getRegD, getRegC, getRegAI, getRegAJ)
  | 0b00011u when chkOp ->
    Op.VMOV, p3Oprs bin chkUnpreP (getRegAF, getRegD, getRegC)
  | 0b00011u -> Op.VMOV, p3Oprs bin chkUnpreAY (getRegD, getRegC, getRegAF)
  | op when op &&& 0b00011u = 0b00001u -> raise UnallocatedException
  | op when op &&& 0b01101u = 0b00101u -> raise UnallocatedException
  | op when op &&& 0b01001u = 0b01001u -> raise UnallocatedException
  | 0b10011u when chkSz && chkOp ->
    Op.VMOV, p4Oprs bin chkUnpreAW (getRegAI, getRegAJ, getRegD, getRegC)
  | 0b10011u when chkSz ->
    Op.VMOV, p4Oprs bin chkUnpreAX (getRegD, getRegC, getRegAI, getRegAJ)
  | 0b10011u when chkSz && chkOp ->
    Op.VMOV, p3Oprs bin chkUnpreP (getRegAF, getRegD, getRegC)
  | 0b10011u when chkSz ->
    Op.VMOV, p3Oprs bin chkUnpreAY (getRegD, getRegC, getRegAF)
  | _ -> failwith "Wrong 64-bit transfers."

/// Advanced SIMD and floating-point Load/Store, page F4-2532
let getAdvSIMDNFloatLoadStore bin =
  let pul = concat (extract bin 24u 23u) (pickBit bin 20u) 1
  let op = concat pul (pickBit bin 8u) 1
  let chkW = pickBit bin 21u = 0b1u
  let chkImm8 = pickBit bin 0u = 0b0u
  let chkRn = extract bin 19u 16u <> 0b1111u
  let chkPushPop = extract bin 19u 16u = 0b1101u
  let chk8 = pickBit bin 8u = 0b0u
  match op with
  | op when op &&& 0b1100u = 0b0000u && chkW -> raise UnallocatedException
  | op when op &&& 0b1100u = 0b0100u && chkW && chkPushPop && chk8 ->
    Op.VPOP, p1Opr bin chkUnpreBA getRegListM
  | op when op &&& 0b1100u = 0b0100u && chkW && chkPushPop ->
    Op.VPOP, p1Opr bin chkUnpreAZ getRegListL
  | 0b0100u when chk8 ->
    Op.VSTMIA, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | 0b0100u -> Op.VSTMIA, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | 0b0101u when chkImm8 && chk8 ->
    Op.VSTMIA, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | 0b0101u when chkImm8 ->
    Op.VSTMIA, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | 0b0101u when chk8 ->
    Op.FSTMIAX, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | 0b0101u -> Op.FSTMIAX, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | 0b0110u when chk8 ->
    Op.VLDMIA, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | 0b0110u -> Op.VLDMIA, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | 0b0111u when chkImm8 && chk8 ->
    Op.VLDMIA, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | 0b0111u when chkImm8 ->
    Op.VLDMIA, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | 0b0111u when chk8 ->
    Op.FSTMIAX, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | 0b0111u -> Op.FSTMIAX, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | op when op &&& 0b1010u = 0b1000u && chkW ->
    Op.VSTR, p2Oprs bin dummyChk (getRegAL, getMemAR)
  | op when op &&& 0b1100u = 0b1000u && chkW && chkPushPop && chk8 ->
    Op.VPUSH, p1Opr bin chkUnpreBA getRegListM
  | op when op &&& 0b1100u = 0b1000u && chkW && chkPushPop ->
    Op.VPUSH, p1Opr bin chkUnpreAZ getRegListL
  | 0b1000u when not chkW && chk8 ->
    Op.VSTMDB, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | 0b1000u when not chkW ->
    Op.VSTMDB, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | 0b1001u when chkImm8 && not chkW && chk8 ->
    Op.VSTMDB, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | 0b1001u when chkImm8 && not chkW ->
    Op.VSTMDB, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | 0b1001u when not chkImm8 && not chkW && chk8 ->
    Op.FSTMDBX, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | 0b1001u when not chkImm8 && not chkW ->
    Op.FSTMDBX, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | 0b1010u when not chkW && chk8 ->
    Op.VLDMDB, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | 0b1010u when not chkW ->
    Op.VLDMDB, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | 0b1011u when chkImm8 && not chkW && chk8 ->
    Op.VLDMDB, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | 0b1011u when chkImm8 && not chkW ->
    Op.VLDMDB, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | 0b1011u when not chkImm8 && not chkW && chk8 ->
    Op.VLDMDB, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | 0b1011u when not chkImm8 && not chkW ->
    Op.VLDMDB, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | op when op &&& 0b1010u = 0b1010u && chkW && chkRn ->
    Op.VLDR, p2Oprs bin dummyChk (getRegAL, getMemAR)
  | op when op &&& 0b1100u = 0b1100u && not chkW -> raise UnallocatedException
  | _ -> failwith "Wrong supervisor call, and coprocessor instrs."

/// System register 64-bit move, page F4-2538
let getSystemRegister64Bit bin =
  let dl = concat (pickBit bin 22u) (pickBit bin 20u) 1
  let getOprs chk =
    p5Oprs bin chk (getPRegA, getImm4D, getRegD, getRegC, getCRegB)
  match dl with
  | 0b00u -> raise UnallocatedException
  | 0b01u -> raise UnallocatedException
  | 0b10u -> Op.MCRR, getOprs chkUnpreAU
  | 0b11u -> Op.MRRC, getOprs chkUnpreAV
  | _ -> failwith "Wrong system register 64-bit."

/// System register Load/Store, page F4-2539
let getSystemRegLoadStore bin =
  let puw = concat (extract bin 24u 23u) (pickBit bin 21u) 1
  let chkCRd = extract bin 15u 12u = 0b0101u
  let chkL = pickBit bin 20u = 0b1u
  let chkRn = extract bin 19u 16u = 0b1111u
  match puw with
  | 0b000u -> raise UnallocatedException
  | _ when not chkCRd -> raise UnallocatedException
  | _ when chkCRd && not chkL ->
    Op.STC, p3Oprs bin dummyChk (getPRegA, getCRegA, getMemAE)
  | _ when chkCRd && chkL && not chkRn ->
    Op.LDC, p3Oprs bin dummyChk (getPRegA, getCRegA, getMemAE)
  | _ when chkCRd && chkL && chkRn ->
    Op.LDC, p3Oprs bin dummyChk (getPRegA, getCRegA, getMemAD)
  | _ -> raise UnallocatedException

/// Load/Store Dual, Half, Signed byte (register) on page F4-2503
/// This section is decoded from Extra Load/Store on page F4-2502.
let parseLdStReg b =
  let getThreeOprs chk = p3Oprs b chk (getRegD, getRegL, getMemN)
  match pickBit b 20u, extract b 6u 5u, pickBit b 24u, pickBit b 21u with
  | 0u, 1u, 0u, 0u -> Op.STRH, p2Oprs b chkUnpreAD (getRegD, getMemN)
  | 0u, 1u, 0u, 1u -> Op.STRHT, p2Oprs b chkUnpreW (getRegD, getMemJ)
  | 0u, 1u, 1u, _ -> Op.STRH, p2Oprs b chkUnpreAD (getRegD, getMemN)
  | 0u, 2u, 0u, 0u -> Op.LDRD, getThreeOprs chkUnpreAE
  | 0u, 2u, 0u, 1u -> raise UnallocatedException
  | 0u, 2u, 1u, _ -> Op.LDRD, getThreeOprs chkUnpreAE
  | 0u, 3u, 0u, 0u -> Op.STRD, getThreeOprs chkUnpreAF
  | 0u, 3u, 1u, 1u -> raise UnallocatedException
  | 0u, 3u, 1u, _ -> Op.STRD, getThreeOprs chkUnpreAF
  | 1u, 1u, 0u, 0u -> Op.LDRH, p2Oprs b chkUnpreAD (getRegD, getMemN)
  | 1u, 1u, 0u, 1u -> Op.LDRHT, p2Oprs b chkUnpreW (getRegD, getMemJ)
  | 1u, 1u, 1u, _ -> Op.LDRH, p2Oprs b chkUnpreAD (getRegD, getMemN)
  | 1u, 2u, 0u, 0u -> Op.LDRSB, p2Oprs b chkUnpreAD (getRegD, getMemN)
  | 1u, 2u, 0u, 1u -> Op.LDRSBT, p2Oprs b chkUnpreW (getRegD, getMemJ)
  | 1u, 2u, 1u, _ -> Op.LDRSB, p2Oprs b chkUnpreAD (getRegD, getMemN)
  | 1u, 3u, 0u, 0u -> Op.LDRSH, p2Oprs b chkUnpreAD (getRegD, getMemN)
  | 1u, 3u, 1u, 1u -> Op.LDRSHT, p2Oprs b chkUnpreW (getRegD, getMemJ)
  | 1u, 3u, 1u, _ -> Op.LDRSH, p2Oprs b chkUnpreAD (getRegD, getMemN)
  | _ -> failwith "Wrong Load/Store (register) instructions."

/// Load/Store Dual, Half, Signed byte (immediate, literal) on page F4-2504
/// This section is decoded from Extra Load/Store on page F4-2502.
let parseLdStImm b =
  let pw = concat (pickBit b 24u) (pickBit b 21u) 1
  match pickBit b 20u, extract b 6u 5u, pw, extract b 19u 16u with
  | 0u, 1u, 1u, _ -> Op.STRHT, p2Oprs b chkUnpreW (getRegD, getMemJ)
  | 0u, 1u, _, _ -> Op.STRH, p2Oprs b chkUnpreAG (getRegD, getMemO)
  | 0u, 2u, _, 15u -> Op.LDRD, p3Oprs b chkUnpreU (getRegD, getRegL, getMemH)
  | 0u, 2u, 0u, rn when rn <> 15u ->
    Op.LDRD, p3Oprs b chkUnpreAI (getRegD, getRegL, getMemO)
  | 0u, 2u, 1u, rn when rn <> 15u -> raise UnallocatedException
  | 0u, 2u, _, rn when rn <> 15u ->
    Op.LDRD, p3Oprs b chkUnpreAI (getRegD, getRegL, getMemO)
  | 0u, 3u, 1u, _ -> raise UnallocatedException
  | 0u, 3u, _, _ -> Op.STRD, p3Oprs b chkUnpreAJ (getRegD, getRegL, getMemO)
  | 1u, 1u, pw, 15u when pw <> 1u ->
    Op.LDRH, p2Oprs b chkUnpreG (getRegD, getMemH)
  | 1u, 1u, 0u, rn when rn <> 15u ->
    Op.LDRH, p2Oprs b chkUnpreT (getRegD, getMemH)
  | 1u, 1u, 1u, _ -> Op.LDRHT, p2Oprs b chkUnpreW (getRegD, getMemJ)
  | 1u, 1u, 2u, rn when rn <> 15u ->
    Op.LDRH, p2Oprs b chkUnpreAH (getRegD, getMemO)
  | 1u, 1u, 3u, rn when rn <> 15u ->
    Op.LDRH, p2Oprs b chkUnpreAH (getRegD, getMemO)
  | 1u, 2u, pw, 15u when pw <> 1u ->
    Op.LDRSB, p2Oprs b chkUnpreT (getRegD, getMemH)
  | 1u, 2u, 1u, _ -> Op.LDRSBT, p2Oprs b chkUnpreW (getRegD, getMemJ)
  | 1u, 2u, _, rn when rn <> 15u ->
    Op.LDRSB, p2Oprs b chkUnpreAH (getRegD, getMemO)
  | 1u, 3u, pw, 15u when pw <> 1u ->
    Op.LDRSH, p2Oprs b chkUnpreT (getRegD, getMemH)
  | 1u, 3u, 0u, rn when rn <> 15u ->
    Op.LDRSH, p2Oprs b chkUnpreAH (getRegD, getMemO)
  | _ -> failwith "Wrong Load/Store (immediate, literal) instructions."

/// Extra Load/Store on F4-2502
let parseExtLoadStore bin =
  match pickBit bin 22u with
  | 0u -> parseLdStReg bin
  | 1u -> parseLdStImm bin
  | _ -> failwith "Invalid bit in Extra Load/Store"

/// Synchronization primitives and Load-Acquire/Store-Release on page F4-2506
/// Data-processing and miscellaneous instructions on page F4-2502.
let parseSynPrimitives bin =
  let op0 = pickBit bin 23u
  let typ = extract bin 22u 21u
  let l = pickBit bin 20u
  let ex = pickBit bin 9u
  let ord = pickBit bin 8u
  match op0, typ, l, ex, ord with
  | 0u, _, _, _, _ -> raise UnallocatedException
  | 1u, 0u, 0u, 0u, 0u -> Op.STL, p2Oprs bin chkUnpreK (getRegC, getMemA)
  | 1u, 0u, 0u, 0u, 1u -> raise UnallocatedException
  | 1u, 0u, 0u, 1u, 0u ->
    Op.STLEX, p3Oprs bin checkStoreEx1 (getRegD, getRegA, getMemA)
  | 1u, 0u, 0u, 1u, 1u ->
    Op.STREX, p3Oprs bin checkStoreEx1 (getRegD, getRegA, getMemA)
  | 1u, 0u, 1u, 0u, 0u -> Op.LDA, p2Oprs bin chkUnpreK (getRegD, getMemA)
  | 1u, 0u, 1u, 0u, 1u -> raise UnallocatedException
  | 1u, 0u, 1u, 1u, 0u -> Op.LDAEX, p2Oprs bin chkUnpreK (getRegD, getMemA)
  | 1u, 0u, 1u, 1u, 1u -> Op.LDREX, p2Oprs bin chkUnpreK (getRegD, getMemA)
  | 1u, 1u, 0u, 0u, _ -> raise UnallocatedException
  | 1u, 1u, 0u, 1u, 0u ->
    Op.STLEXD, p4Oprs bin checkStoreEx2 (getRegD, getRegA, getRegF, getMemA)
  | 1u, 1u, 0u, 1u, 1u ->
    Op.STREXD, p4Oprs bin checkStoreEx2 (getRegD, getRegA, getRegF, getMemA)
  | 1u, 1u, 1u, 0u, _ -> raise UnallocatedException
  | 1u, 1u, 1u, 1u, 0u ->
    Op.LDAEXD, p3Oprs bin chkUnpreL (getRegD, getRegL, getMemA)
  | 1u, 1u, 1u, 1u, 1u ->
    Op.LDREXD, p3Oprs bin chkUnpreL (getRegD, getRegL, getMemA)
  | 1u, 2u, 0u, 0u, 0u -> Op.STLB, p2Oprs bin chkUnpreK (getRegC, getMemA)
  | 1u, 2u, 0u, 0u, 1u -> raise UnallocatedException
  | 1u, 2u, 0u, 1u, 0u ->
    Op.STLEXB, p3Oprs bin checkStoreEx1 (getRegD, getRegA, getMemA)
  | 1u, 2u, 0u, 1u, 1u ->
    Op.STREXB, p3Oprs bin checkStoreEx1 (getRegD, getRegA, getMemA)
  | 1u, 2u, 1u, 0u, 0u -> Op.LDAB, p2Oprs bin chkUnpreK (getRegD, getMemA)
  | 1u, 2u, 1u, 0u, 1u -> raise UnallocatedException
  | 1u, 2u, 1u, 1u, 0u -> Op.LDAEXB, p2Oprs bin chkUnpreK (getRegD, getMemA)
  | 1u, 2u, 1u, 1u, 1u -> Op.LDREXB, p2Oprs bin chkUnpreK (getRegD, getMemA)
  | 1u, 3u, 0u, 0u, 0u -> Op.STLH, p2Oprs bin chkUnpreK (getRegC, getMemA)
  | 1u, 3u, 0u, 0u, 1u -> raise UnallocatedException
  | 1u, 3u, 0u, 1u, 0u ->
    Op.STLEXH, p3Oprs bin checkStoreEx1 (getRegD, getRegA, getMemA)
  | 1u, 3u, 0u, 1u, 1u ->
    Op.STREXH, p3Oprs bin checkStoreEx1 (getRegD, getRegA, getMemA)
  | 1u, 3u, 1u, 0u, 0u -> Op.LDAH, p2Oprs bin chkUnpreK (getRegD, getMemA)
  | 1u, 3u, 1u, 0u, 1u -> raise UnallocatedException
  | 1u, 3u, 1u, 1u, 0u -> Op.LDAEXH, p2Oprs bin chkUnpreK (getRegD, getMemA)
  | 1u, 3u, 1u, 1u, 1u -> Op.LDREXH, p2Oprs bin chkUnpreK (getRegD, getMemA)
  | _ -> failwith "Invalid bit in Synchronization primitives"

/// Exception Generation on page F4-2508
/// Miscellaneous on page F4-2507
let parseExcepGenInstrs cond bin =
  match extract bin 22u 21u with
  | 0u when cond = Condition.AL -> Op.HLT, p1Opr bin dummyChk getImm12D
  | 1u when cond = Condition.AL -> Op.BKPT, p1Opr bin dummyChk getImm12D
  | 2u when cond = Condition.AL -> Op.HVC, p1Opr bin dummyChk getImm12D
  | 3u when cond = Condition.AL -> Op.SMC, p1Opr bin dummyChk getImm4A
  | _ -> failwith "Invalid bit in Exception Generation instrs"

/// Move special register (register) on page F4-2509
/// Miscellaneous on page F4-2507
let parseMoveSpecRegInstr bin =
  match pickBit bin 21u, pickBit bin 9u with
  | 0u, 0u -> Op.MRS, p2Oprs bin dummyChk (getRegD, getRegE)
  | 0u, 1u -> Op.MRS, p2Oprs bin chkUnpreG (getRegD, getBankedRegA)
  | 1u, 0u -> Op.MSR, p2Oprs bin chkUnpreH (getRegK, getRegA)
  | 1u, 1u -> Op.MSR, p2Oprs bin chkUnpreF (getBankedRegA, getRegA)
  | _ -> failwith "Invalid bit in Move special register (register) instrs"

/// Cyclic Redundancy Check on page F4-2509
/// Miscellaneous on page F4-2507
let parseCyclRedundanyCheckInstrs cond bin =
  checkUnpred (cond <> Condition.AL)
  checkSize ((extract bin 22u 21u) <<< 8 |> int) 64
  match extract bin 22u 21u, pickBit bin 9u with
  | 0u, 0u -> Op.CRC32B, getRegDCAOprsWithUnpreA bin
  | 0u, 1u -> Op.CRC32CB, getRegDCAOprsWithUnpreA bin
  | 1u, 0u -> Op.CRC32H, getRegDCAOprsWithUnpreA bin
  | 1u, 1u -> Op.CRC32CH, getRegDCAOprsWithUnpreA bin
  | 2u, 0u -> Op.CRC32W, getRegDCAOprsWithUnpreA bin
  | 2u, 1u -> Op.CRC32CW, getRegDCAOprsWithUnpreA bin
  | 3u, _ -> raise UnallocatedException
  | _ -> failwith "Invalid bit in Cyclic Redundancy Check instrs"

/// Integer Saturating Arithmetic on page F4-2510
/// Miscellaneous on page F4-2507
let parseIntArithmeticInstrs bin =
  match extract bin 22u 21u with
  | 0u -> Op.QADD, getRegDCAOprsWithUnpreA bin
  | 1u -> Op.QSUB, getRegDCAOprsWithUnpreA bin
  | 2u -> Op.QDADD, getRegDCAOprsWithUnpreA bin
  | 3u -> Op.QDSUB, getRegDCAOprsWithUnpreA bin
  | _ -> failwith "Invalid bit in Integer Saturating Arithmetic instrs"

/// Miscellaneous on page F4-2507
/// Data-processing and miscellaneous instructions on page F4-2502
let parseMiscelInstrs cond bin =
  match extract bin 22u 21u, extract bin 6u 4u with
  | _, 0u -> parseMoveSpecRegInstr bin
  | _, 4u -> parseCyclRedundanyCheckInstrs cond bin
  | _, 5u -> parseIntArithmeticInstrs bin
  | _, 7u -> parseExcepGenInstrs cond bin
  | 0u, _ -> raise UnallocatedException
  | 1u, 1u -> Op.BX, p1Opr bin dummyChk getRegA
  | 1u, 2u -> Op.BXJ, p1Opr bin chkUnpreD getRegA
  | 1u, 3u -> Op.BLX, p1Opr bin chkUnpreD getRegA
  | 1u, 6u -> raise UnallocatedException
  | 2u, _ -> raise UnallocatedException
  | 3u, 1u -> Op.CLZ, p2Oprs bin chkUnpreE (getRegD, getRegA)
  | 3u, 2u -> raise UnallocatedException
  | 3u, 3u -> raise UnallocatedException
  | 3u, 6u -> Op.ERET, NoOperand
  | _ -> failwith "Invalid bit in Miscellaneous"

/// Logical Arithmetic (three register, immediate shift) on page F4-2512
/// Data-processing register (immediate shift) on page F4-2512
let logicArithImmShift bin =
  match extract bin 22u 20u with
  | 0u -> Op.ORR, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 1u -> Op.ORRS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 2u -> Op.MOV, p3Oprs bin dummyChk (getRegD, getRegA, getShiftB)
  | 3u -> Op.MOVS, p3Oprs bin dummyChk (getRegD, getRegA, getShiftB)
  | 4u -> Op.BIC, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 5u -> Op.BICS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 6u -> Op.MVN, p3Oprs bin dummyChk (getRegD, getRegA, getShiftB)
  | 7u -> Op.MVNS, p3Oprs bin dummyChk (getRegD, getRegA, getShiftB)
  | _ -> failwith "Invalid bit in Logical Arithmetic"

/// Integer Data Processing (three register, immediate shift) on page F4-2511
/// Integer Data Processing (three register, register shift) on page F4-2513
/// Data-processing register (immediate shift) on page F4-2511
let intDataProc bin =
  match extract bin 23u 20u with
  | 0b0000u -> Op.AND
  | 0b0001u -> Op.ANDS
  | 0b0010u -> Op.EOR
  | 0b0011u -> Op.EORS
  | 0b0100u -> Op.SUB
  | 0b0101u -> Op.SUBS
  | 0b0110u -> Op.RSB
  | 0b0111u -> Op.RSBS
  | 0b1000u -> Op.ADD
  | 0b1001u -> Op.ADDS
  | 0b1010u -> Op.ADC
  | 0b1011u -> Op.ADCS
  | 0b1100u -> Op.SBC
  | 0b1101u -> Op.SBCS
  | 0b1110u -> Op.RSC
  | 0b1111u -> Op.RSCS
  | _ -> failwith "Invalid bit in Integer Data Processing"

/// Integer Test & Compare (two register, immediate shift) on page F4-2512
/// Integer Test & Compare (two register, register shift) on page F4-2514
/// Data-processing register (immediate shift) on page F4-2512
let intTestComp bin =
  match extract bin 22u 21u with
  | 0u -> Op.TST
  | 1u -> Op.TEQ
  | 2u -> Op.CMP
  | 3u -> Op.CMN
  | _ -> failwith "Invalid bit in Integer Test & Compare"

/// Logical Arithmetic (three register, register shift) on page F4-2514
/// Data-processing register (register shift) on page F4-2512
let logicArithRegShift bin =
  match extract bin 22u 20u with
  | 0u -> Op.ORR, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 1u -> Op.ORRS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 2u -> Op.MOV, p3Oprs bin dummyChk (getRegD, getRegA, getShiftA)
  | 3u -> Op.MOVS, p3Oprs bin dummyChk (getRegD, getRegA, getShiftA)
  | 4u -> Op.BIC, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 5u -> Op.BICS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 6u -> Op.MVN, p3Oprs bin dummyChk (getRegD, getRegA, getShiftB)
  | 7u -> Op.MVNS, p3Oprs bin dummyChk (getRegD, getRegA, getShiftA)
  | _ -> failwith "Invalid bit in Logical Arithmetic"

/// Data-processing register (immediate shift) on page F4-2511
/// Data-processing and miscellaneous instructions on page F4-2502
let parseDataProcImmSReg bin =
  match extract bin 24u 23u with
  | 0u | 1u ->
    intDataProc bin, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 2u when pickBit bin 20u = 1u ->
    intTestComp bin, p3Oprs bin dummyChk (getRegC, getRegA, getShiftB)
  | 3u -> logicArithImmShift bin
  | _ -> failwith "Invalid bit in Data-processing register"

/// Data-processing register (register shift) on page F4-2513
/// Data-processing and miscellaneous instructions on page F4-2502
let parseDataProcRegSReg bin =
  match extract bin 24u 23u, pickBit bin 20u with
  | 0u, _ | 1u, _ ->
    intDataProc bin, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 2u, 1u -> intTestComp bin, p3Oprs bin dummyChk (getRegC, getRegA, getShiftA)
  | 3u, _ -> logicArithRegShift bin
  | _ -> failwith "Invalid bit in Data-processing register"

/// Change Process State on page F4-2541
/// Unconditional instructions on page F4-2540.
let parseUnCondMiscellaneous bin =
  match pickBit bin 16u, pickBit bin 4u with
  | 0u, _ -> getCPS bin
  | 1u, 0u -> Op.SETEND, p1Opr bin dummyChk getEndianA
  | _ -> failwith "Invalid bit in Change Process State"

/// Data-processing and miscellaneous instructions, page F4-2502
/// Unconditional instructions on page F4-2540
let parseGroup000v8 cond bin =
  let o1 = extract bin 24u 20u
  let o2 = pickBit bin 7u
  let o3 = extract bin 6u 5u
  let o4 = pickBit bin 4u
  let o5 = pickBit bin 5u
  let opcode, operands =
    match o1, o2, o3, o4 with
    | 0b10000u, _, _, _ when cond = Condition.UN && o5 = 0u ->
      parseUnCondMiscellaneous bin
    | _, 1u, b, 1u when b <> 0u -> parseExtLoadStore bin
//    | b, 1u, 0u, 1u when b &&& 0b10000u = 0u -> parseMulNMulAcc bin
    | b, 1u, 0u, 1u when b &&& 0b10000u = 0b10000u -> parseSynPrimitives bin
    | b, 0u, _, _ when b &&& 0b11001u = 0b10000u -> parseMiscelInstrs cond bin
//    | b, 1u, _, 0u when b &&& 0b11001u = 0b10000u -> parseHalfMulNMulAcc bin
    | b, _, _, 0u when b &&& 0b11001u <> 0b10000u -> parseDataProcImmSReg bin
    | b, 0u, _, 1u when b &&& 0b11001u <> 0b10000u -> parseDataProcRegSReg bin
    | _ -> failwith "Wrong opcode in group000."
  opcode, None, operands

/// Integer Data Processing (two register and immediate)
/// Data-processing immediate on page F4-2515
/// ADR is integrated into ADD or SUB respectively
let parseIntDataProcImm bin =
  intDataProc bin, None, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)

/// Move Halfword (immediate) on page F4-2516
/// Data-processing immediate on page F4-2515
let parseMovHalfwordImm bin =
  match pickBit bin 22u, pickBit bin 20u with
  | 0u, 0u -> Op.MOV, None, p2Oprs bin dummyChk (getRegD, getImm12A)
  | 0u, 1u -> Op.MOVS, None, p2Oprs bin dummyChk (getRegD, getImm12A)
  | 1u, _ -> Op.MOVT, None, p2Oprs bin dummyChk (getRegD, getImm12B)
  | _ -> failwith "Invalid bit in Move Halfword (immediate)"

/// Move Special Register & Hints (immediate) on page F4-2516
/// Data-processing and miscellaneous instructions, page F4-2502
let parseMovSpecRegImm bin =
  match extract bin 7u 0u with
  | 0u -> Op.NOP, None, NoOperand
  | 1u -> Op.YIELD, None, NoOperand
  | 2u -> Op.WFE, None, NoOperand
  | 3u -> Op.WFI, None, NoOperand
  | 4u -> Op.SEV, None, NoOperand
  | 5u -> Op.SEVL, None, NoOperand
  | 6u | 7u -> Op.NOP, None, NoOperand
  | op when op &&& 0b11111000u = 0b00001000u -> Op.NOP, None, NoOperand
  | op when op &&& 0b11110000u = 0b00010000u -> Op.NOP, None, NoOperand
  | op when op &&& 0b11100000u = 0b00100000u -> Op.NOP, None, NoOperand
  | op when op &&& 0b11000000u = 0b01000000u -> Op.NOP, None, NoOperand
  | op when op &&& 0b11000000u = 0b10000000u -> Op.NOP, None, NoOperand
  | op when op &&& 0b11100000u = 0b11000000u -> Op.NOP, None, NoOperand
  | op when op &&& 0b11110000u = 0b11100000u -> Op.NOP, None, NoOperand
  | op when op &&& 0b11110000u = 0b11110000u -> Op.DBG, None, NoOperand
  | _ -> failwith "Invalid bit in Move Special Register & Hints"

/// Integer Test & Compare (one register and immediate) on page F4-2517
/// Data-processing and miscellaneous instructions, page F4-2502
let parseIntTestCompImm bin =
  match extract bin 22u 21u with
  | 0u -> Op.TST, None, p2Oprs bin dummyChk (getRegC, getImm12A)
  | 1u -> Op.TEQ, None, p2Oprs bin dummyChk (getRegC, getImm12A)
  | 2u -> Op.CMP, None, p2Oprs bin dummyChk (getRegC, getImm12A)
  | 3u -> Op.CMN, None, p2Oprs bin dummyChk (getRegC, getImm12A)
  | _ -> failwith "Invalid bit in Integer Test & Compare"

/// Logical Arithmetic (two register and immediate) on page F4-2518
/// Data-processing and miscellaneous instructions, page F4-2502
let parselogicArithImm bin =
  match extract bin 22u 20u with
  | 0u -> Op.ORR, None, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 1u -> Op.ORRS, None, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 2u -> Op.MOV, None, p2Oprs bin dummyChk (getRegD, getImm12A)
  | 3u -> Op.MOVS, None, p2Oprs bin dummyChk (getRegD, getImm12A)
  | 4u -> Op.BIC, None, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 5u -> Op.BICS, None, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 6u -> Op.MVN, None, p2Oprs bin dummyChk (getRegD, getImm12A)
  | 7u -> Op.MVNS, None, p2Oprs bin dummyChk (getRegD, getImm12A)
  | _ -> failwith "Invalid bit in Logical Arithmetic"

/// Advanced SIMD two registers misc on page F4-2542
/// Advanced SIMD data-processing on page F4-2541
let parseAdvSIMDMisc bin =
  let size = extract bin 19u 18u
  match extract bin 17u 16u, extract bin 10u 7u, pickBit bin 6u with
  | 0u, 0u, _ -> Op.VREV64, getOneDtS bin,
                 p2Oprs bin chkUndefU (getRegX, getRegZ)
  | 0u, 1u, _ -> Op.VREV32, getOneDtS bin,
                 p2Oprs bin chkUndefU (getRegX, getRegZ)
  | 0u, 2u, _ -> Op.VREV16, getOneDtS bin,
                 p2Oprs bin chkUndefU (getRegX, getRegZ)
  | 0u, 3u, _ -> raise UnallocatedException
  | 0u, 4u, _ | 0u, 5u, _ ->
    Op.VPADDL, getOneDtC bin, p2Oprs bin chkUndefV (getRegX, getRegZ)
  | 0u, 6u, 0u -> Op.AESE, getOneDtE (),
                  p2Oprs bin chkUndefAT (getRegAC, getRegAD)
  | 0u, 6u, 1u -> Op.AESD, getOneDtE (),
                  p2Oprs bin chkUndefAT (getRegAC, getRegAD)
  | 0u, 7u, 0u ->
    Op.AESMC, getOneDtE (), p2Oprs bin chkUndefAT (getRegAC, getRegAD)
  | 0u, 7u, 1u ->
    Op.AESIMC, getOneDtE (), p2Oprs bin chkUndefAT (getRegAC, getRegAD)
  | 0u, 8u, _ -> Op.VCLS, getOneDtT bin, p2Oprs bin chkUndefX (getRegX, getRegZ)
  | 0u, 9u, _ -> Op.VCLZ, getOneDtU bin, p2Oprs bin chkUndefX (getRegX, getRegZ)
  | 0u, 10u, _ -> Op.VCNT, getOneDtE (), p2Oprs bin chkUndefY (getRegX, getRegZ)
  | 0u, 11u, _ -> Op.VMVN, None, p2Oprs bin chkUndefY (getRegX, getRegZ)
  | 0u, 12u, _ | 0u, 13u, _ ->
    Op.VPADAL, getOneDtC bin, p2Oprs bin chkUndefV (getRegX, getRegZ)
  | 0u, 14u, _ ->
    Op.VQABS, getOneDtT bin, p2Oprs bin chkUndefX (getRegX, getRegZ)
  | 0u, 15u, _ ->
    Op.VQNEG, getOneDtT bin, p2Oprs bin chkUndefX (getRegX, getRegZ)
  | 1u, b, _ when b &&& 7u = 0u ->
    Op.VCGT, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | 1u, b, _ when b &&& 7u = 1u ->
    Op.VCGE, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | 1u, b, _ when b &&& 7u = 2u ->
    Op.VCEQ, getOneDtW b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | 1u, b, _ when b &&& 7u = 3u ->
    Op.VCLE, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | 1u, b, _ when b &&& 7u = 4u ->
    Op.VCLT, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | 1u, b, _ when b &&& 7u = 6u ->
    Op.VABS, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | 1u, b, _ when b &&& 7u = 7u ->
    Op.VNEG, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | 1u, 5u, 1u ->
    Op.SHA1H, getOneDtAI (), p2Oprs bin chkUndefAU (getRegAC, getRegAD)
  | 2u, 0u, _ when size = 0u ->
    Op.VSWP, None, p2Oprs bin chkUndefZ (getRegX, getRegZ)
  | 2u, 1u, _ ->
    Op.VTRN, getOneDtS bin, p2Oprs bin chkUndefAA (getRegX, getRegZ)
  | 2u, 2u, _ ->
    Op.VUZP, getOneDtS bin, p2Oprs bin chkUndefAB (getRegX, getRegZ)
  | 2u, 3u, _ ->
    Op.VZIP, getOneDtS bin, p2Oprs bin chkUndefAB (getRegX, getRegZ)
  | 2u, 4u, 0u ->
    Op.VMOVN, getOneDtX bin, p2Oprs bin chkUndefAD (getRegAC, getRegAD)
  | 2u, 4u, 1u | 2u, 5u, _ ->
    Op.VQMOVN, getOneDtY bin, p2Oprs bin chkUndefAD (getRegAC, getRegAD)
  | 2u, 5u, _ ->
    Op.VQMOVN, getOneDtY bin, p2Oprs bin chkUndefAD (getRegAC, getRegAD)
  | 2u, 6u, 0u ->
    Op.VSHLL, getOneDtU bin, p2Oprs bin chkUndefAD (getRegAC, getRegAD)
  | 2u, 7u, 0u ->
    Op.SHA1SU1, getOneDtAI (), p2Oprs bin chkUndefAU (getRegAC, getRegAD)
  | 2u, 7u, 1u ->
    Op.SHA256SU0, getOneDtAI (), p2Oprs bin chkUndefAU (getRegAC, getRegAD)
  | 2u, 8u, _ ->
    Op.VRINTN, getOneDtAA (), p2Oprs bin chkUndefAF (getRegX, getRegZ)
  | 2u, 9u, _ ->
    Op.VRINTX, getOneDtAA (), p2Oprs bin chkUndefAF (getRegX, getRegZ)
  | 2u, 10u, _ ->
    Op.VRINTA, getOneDtAA (), p2Oprs bin chkUndefAF (getRegX, getRegZ)
  | 2u, 11u, _ ->
    Op.VRINTZ, getOneDtAA (), p2Oprs bin chkUndefAF (getRegX, getRegZ)
  | 2u, 12u, 0u | 2u, 14u, 0u ->
    Op.VCVT, getTwoDtC bin, p2Oprs bin chkUndefAE (getRegX, getRegZ)
  | 2u, 12u, _ -> raise UnallocatedException
  | 2u, 13u, _ ->
    Op.VRINTM, getOneDtAA (), p2Oprs bin chkUndefAF (getRegX, getRegZ)
  | 2u, 14u, 1u -> raise UnallocatedException
  | 2u, 15u, _ ->
    Op.VRINTP, getOneDtAA (), p2Oprs bin chkUndefAF (getRegX, getRegZ)
  | 2u, 15u, _ ->
    Op.VRINTP, getOneDtAA (), p2Oprs bin chkUndefAF (getRegX, getRegZ)
  | 3u, b, _ when b &&& 14u = 0u ->
    Op.VCVTA, getTwoDtB bin, p2Oprs bin chkUndefAF (getRegAI, getRegAH)
  | 3u, b, _ when b &&& 14u = 2u ->
    Op.VCVTN, getTwoDtB bin, p2Oprs bin chkUndefAF (getRegAI, getRegAH)
  | 3u, b, _ when b &&& 14u = 4u ->
    Op.VCVTP, getTwoDtB bin, p2Oprs bin chkUndefAF (getRegAI, getRegAH)
  | 3u, b, _ when b &&& 14u = 5u ->
    Op.VCVTM, getTwoDtB bin, p2Oprs bin chkUndefAF (getRegAI, getRegAH)
  | 3u, b, _ when b &&& 13u = 8u ->
    Op.VRECPE, getOneDtZ b, p2Oprs b chkUndefAF (getRegX, getRegZ)
  | 3u, b, _ when b &&& 13u = 9u ->
    Op.VRSQRTE, getOneDtZ b, p2Oprs b chkUndefAF (getRegX, getRegZ)
  | 3u, b, _ when b &&& 12u = 12u ->
    Op.VCVT, getTwoDtB bin, p2Oprs bin chkUndefW (getRegX, getRegZ)
  | _ -> failwith "Invalid bit in Advanced SIMD two registers misc"

let parseAdbSIMDDupl _ =
  failwith "TODO"

let parseAdvSIMDSame _ =
  failwith "TODO"

let parseAdvSIMDModI _ =
  failwith "TODO"

let parseAdvSIMDDiff _ =
  failwith "TODO"

let parseAdvSIMDScal _ =
  failwith "TODO"

let parseAdvSIMDShift _ =
  failwith "TODO"

/// Advanced SIMD data-processing on page F4-2541
/// Unconditional instructions on page F4-2540
let parseAdvSIMDDataProcV8 bin =
  let pick b = pickBit bin b
  let isVEXT b = b &&& 0b110000000000000u = 0b110000000000000u
  let isMisc b = b &&& 0b110000000010000u = 0b110000000000000u
  let isVTB b = b &&& 0b110000000011000u = 0b110000000010000u
  let isDupl b = b &&& 0b110000000011000u = 0b110000000011000u
  let isDiff b = b &&& 0b110000000000000u <> 0b110000000000000u
  let isModI b = b &&& 0b111000000000001u = 0u
  let chkOp b = b &&& 1u = 1u
  match extract bin 24u 23u, extract bin 21u 7u, pick 6u, pick 4u with
  | 1u, b, _, 0u when isVEXT b ->
    Op.VEXT, getOneDtE (),
    p4Oprs bin chkUndefG (getRegX, getRegY, getRegZ, getImm4C)
  | 3u, b, _, 0u when isMisc b -> parseAdvSIMDMisc bin
  | 3u, b, 0u, 0u when isVTB b ->
    Op.VTBL, getOneDtE (), p3Oprs b dummyChk (getRegAC, getRegListA, getRegAF)
  | 3u, b, 1u, 0u when isVTB b ->
    Op.VTBX, getOneDtE (), p3Oprs b dummyChk (getRegAC, getRegListA, getRegAF)
  | 3u, b, _, 0u when isDupl b -> parseAdbSIMDDupl bin
  | b, _, _, _ when b &&& 1u = 0u -> parseAdvSIMDSame bin
  | b, b2, _, 1u when chkOp b && isModI b2 -> parseAdvSIMDModI bin
  | b, b2, 0u, 0u when chkOp b && isDiff b2 -> parseAdvSIMDDiff bin
  | b, b2, 1u, 0u when chkOp b && isDiff b2 -> parseAdvSIMDScal bin
  | b, b2, _, 1u when chkOp b && not (isModI b2) -> parseAdvSIMDShift bin
  | _ -> failwith "Invalid bit in Advanced SIMD data-processing"

/// Data-processing immediate on page F4-2515
/// Data-processing and miscellaneous instructions, page F4-2502
/// Unconditional instructions on page F4-2540
let parseGroup001v8 cond bin =
  match extract bin 24u 23u, extract bin 21u 20u with
  | _ when cond = Condition.UN -> parseAdvSIMDDataProcV8 bin
  | 1u, _ | 0u, _ -> parseIntDataProcImm bin
  | 2u, 0u -> parseMovHalfwordImm bin
  | 2u, 2u when pickBit bin 22u = 0u -> parseMovSpecRegImm bin
  | 2u, 2u -> Op.MSR, None, p2Oprs bin dummyChk (getAPSRxB, getImm12C)
  | 2u, 1u | 2u, 3u -> parseIntTestCompImm bin
  | 3u, _ -> parselogicArithImm bin
  | _ -> failwith "Wrong opcode in group001."

let parseGroup010v8 cond bin =
  let op = concat (pickBit bin 20u) (pickBit bin 22u) 1
  let pw = concat (pickBit bin 24u) (pickBit bin 21u) 1
  let chkRn () = extract bin 19u 16u = 0b1111u
  let chkPW () = pw = 0b01u
  let isPushPop () = extract bin 19u 16u = 0b1101u
  let opcode, operands =
    match op with
    | _ when cond = Condition.UN -> raise UnallocatedException
    | 0b00u when chkPW () -> Op.STRT, p2Oprs bin chkUnpreZ (getRegD, getMemK)
    | 0b00u when isPushPop () -> Op.PUSH, p1Opr bin chkUnpreY getRegD
    | 0b00u -> Op.STR, p2Oprs bin chkUnpreAA (getRegD, getMemL)
    | 0b01u when chkPW () -> Op.STRBT, p2Oprs bin chkUnpreW (getRegD, getMemK)
    | 0b01u -> Op.STRB, p2Oprs bin chkUnpreAC (getRegD, getMemL)
    | 0b10u when not (chkPW ()) && chkRn () ->
      Op.LDR, p2Oprs bin dummyChk (getRegD, getMemM)
    | 0b10u when chkPW () -> Op.LDRT, p2Oprs bin chkUnpreW (getRegD, getMemK)
    | 0b10u when isPushPop () -> Op.POP, p1Opr bin chkUnpreY getRegD
    | 0b10u when not (chkRn ()) ->
      Op.LDR, p2Oprs bin chkUnpreAA (getRegD, getMemL)
    | 0b11u when not (chkPW ()) && chkRn () ->
      Op.LDRB, p2Oprs bin chkUnpreG (getRegD, getMemM)
    | 0b11u when chkPW () -> Op.LDRBT, p2Oprs bin chkUnpreW (getRegD, getMemK)
    | 0b11u when not (chkRn ()) ->
      Op.LDRB, p2Oprs bin chkUnpreAB (getRegD, getMemL)
    | _ -> failwith "Wrong opcode in group010."
  opcode, None, operands

/// Load/Store Word, Unsigned byte (Register), F4-2520
let parseGroup0110v8 cond bin =
  let op = concat (pickBit bin 20u) (pickBit bin 22u) 1
  let pw = concat (pickBit bin 24u) (pickBit bin 21u) 1
  let chkPW () = pw = 0b01u
  let opcode, operands =
    match op with
    | _ when cond = Condition.UN -> raise UnallocatedException
    | 0b00u when chkPW () -> Op.STRT, p2Oprs bin chkUnpreAL (getRegD, getMemQ)
    | 0b00u -> Op.STR, p2Oprs bin chkUnpreAM (getRegD, getMemR)
    | 0b01u when chkPW () -> Op.STRBT, p2Oprs bin chkUnpreV (getRegD, getMemQ)
    | 0b01u -> Op.STRB, p2Oprs bin chkUnpreAN (getRegD, getMemR)
    | 0b10u when chkPW () -> Op.LDRT, p2Oprs bin chkUnpreV (getRegD, getMemQ)
    | 0b10u -> Op.LDR, p2Oprs bin chkUnpreAM (getRegD, getMemR)
    | 0b11u when chkPW () -> Op.LDRBT, p2Oprs bin chkUnpreV (getRegD, getMemQ)
    | 0b11u -> Op.LDRB, p2Oprs bin chkUnpreAN (getRegD, getMemR)
    | _ -> failwith "Wrong opcode in group0110."
  opcode, None, operands

/// Media instructions, page F4-2521
let parseGroup0111v8 cond bin =
  let op = concat (extract bin 24u 20u) (extract bin 7u 5u) 3
  let opcode, operands =
    match op with
    | op when op &&& 0b11000000u = 0b00000000u -> parsePhrallelArithmetic bin
    | 0b01000101u -> Op.SEL, getRegDCAOprsWithUnpreA bin
    | 0b01000001u -> raise UnallocatedException
    | op when op &&& 0b11111011u = 0b01000000u ->
      Op.PKHBT, p4Oprs bin chkUnpreC (getRegD, getRegC, getRegA, getShiftD)
    | op when op &&& 0b11111011u = 0b01000010u ->
      Op.PKHTB, p4Oprs bin chkUnpreC (getRegD, getRegC, getRegA, getShiftD)
    | op when op &&& 0b11111011u = 0b01001001u -> raise UnallocatedException
    | op when op &&& 0b11111001u = 0b01001000u -> raise UnallocatedException
    | op when op &&& 0b11110011u = 0b01100001u -> raise UnallocatedException
    | op when op &&& 0b11110001u = 0b01100000u -> raise UnallocatedException
    | op when op &&& 0b11011111u = 0b01010001u -> parseSaturate16Bit bin
    | op when op &&& 0b11011111u = 0b01010101u -> raise UnallocatedException
    | op when op &&& 0b11011011u = 0b01011001u -> pReverseBitByte bin
    | op when op &&& 0b11010001u = 0b01010000u -> parseSaturate32Bit bin
    | op when op &&& 0b11000111u = 0b01000111u -> raise UnallocatedException
    | op when op &&& 0b11000111u = 0b01000011u -> pExtendAndAdd bin
    | op when op &&& 0b11000000u = 0b10000000u -> parseSignedMultiplyDivide bin
    | 0b11000000u -> unsignedSumAbsoluteDiff bin
    | 0b11000100u -> raise UnallocatedException
    | op when op &&& 0b11111011u = 0b11001000u -> raise UnallocatedException
    | op when op &&& 0b11110011u = 0b11010000u -> raise UnallocatedException
    | op when op &&& 0b11100111u = 0b11000111u -> raise UnallocatedException
    | op when op &&& 0b11110111u = 0b11100111u -> raise UnallocatedException
    | op when op &&& 0b11110011u = 0b11100000u -> pBitfieldInsert bin
    | 0b11110111u -> raise UnallocatedException
    | 0b11111111u -> parsePermanentlyUndefined cond bin
    | op when op &&& 0b11110011u = 0b11110000u -> raise UnallocatedException
    | op when op &&& 0b11010011u = 0b11000010u -> raise UnallocatedException
    | op when op &&& 0b11010011u = 0b11010010u -> pBitfieldExtract bin
    | op when op &&& 0b11000111u = 0b11000011u -> raise UnallocatedException
    | op when op &&& 0b11000011u = 0b11000001u -> raise UnallocatedException
    | _ -> failwith "Wrong opcode in group0111."
  opcode, None, operands

/// Branch, branch with link, and block data transfer, page F4-2529
let parseGroup100v8 cond bin =
  let opP = concat (pickBit bin 22u) (pickBit bin 24u) 1
  let uL = concat (pickBit bin 23u) (pickBit bin 20u) 1
  let op = concat opP uL 2
  let chkRL () = pickBit bin 15u = 0b0u
  let isPushPop () = extract bin 19u 16u = 0b1101u
  let opcode, operands =
    match op with
    | _ when cond = Condition.UN -> raise UnallocatedException
    | 0b0000u -> Op.STMDA, p2Oprs bin chkUnpreAR (getRegisterWA, getRegListK)
    | 0b0001u -> Op.LDMDA, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
    | 0b0010u -> Op.STM, p2Oprs bin chkUnpreAR (getRegisterWA, getRegListK)
    | 0b0011u when isPushPop () -> Op.POP, p1Opr bin chkUnpreAT getRegListK
    | 0b0011u -> Op.LDM, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
    | 0b0100u when isPushPop () -> Op.PUSH, p1Opr bin dummyChk getRegListK
    | 0b0100u -> Op.STMDB, p2Oprs bin chkUnpreAR (getRegisterWA, getRegListK)
    | 0b0101u -> Op.LDMDB, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
    | 0b0110u -> Op.STMIB, p2Oprs bin chkUnpreAR (getRegisterWA, getRegListK)
    | 0b0111u -> Op.LDMIB, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
    | 0b1000u -> Op.STMDA, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
    | 0b1100u -> Op.STMDB, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
    | 0b1010u -> Op.STMIA, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
    | 0b1110u -> Op.STMIB, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
    | 0b1001u when chkRL () ->
      Op.LDMDA, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
    | 0b1001u -> Op.LDMDA, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
    | 0b1101u when chkRL () ->
      Op.LDMDB, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
    | 0b1101u -> Op.LDMDB, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
    | 0b1011u when chkRL () ->
      Op.LDMIA, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
    | 0b1011u -> Op.LDMIA, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
    | 0b1111u when chkRL () ->
      Op.LDMIA, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
    | 0b1111u -> Op.LDMIA, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
    | _ -> failwith "Wrong opcode in group100."
  opcode, None, operands

/// System register access, Advanced SIMD, floating-point, and Supervisor Call,
/// page F4-2531
let parseGroup110v8 cond bin =
  let op = extract bin 24u 21u
  let chkFloat = extract bin 11u 9u = 0b101u
  let chkSys = extract bin 11u 9u = 0b111u
  let opcode, operands =
    match op with
    | _ when cond = Condition.UN -> raise UnallocatedException
    | op when op &&& 0b1101u = 0b0000u && chkFloat -> getAdvSIMDNFloat64Bit bin
    | op when op &&& 0b1101u <> 0b0000u && chkFloat ->
      getAdvSIMDNFloatLoadStore bin
    | op when op &&& 0b1101u = 0b0000u && chkSys -> getSystemRegister64Bit bin
    | op when op &&& 0b1101u <> 0b0000u && chkSys -> getSystemRegLoadStore bin
    | _ -> failwith "Wrong opcode in group110."
  opcode, None, operands

/// Decoding function
let d bin = extract bin 15u 12u
let m bin = extract bin 3u 0u
let n bin = extract bin 19u 16u
let s bin = extract bin 11u 8u
let t bin = extract bin 15u 12u
let t2 bin = t bin + 1u

module DGrB = (* DecodeGroupB *)
  let a bin = extract bin 15u 12u
  let d bin = extract bin 19u 16u
  let dHi bin = extract bin 19u 16u
  let dLo bin = extract bin 15u 12u
  let m bin = extract bin 11u 8u
  let n bin = extract bin 3u 0u

module DGrC = (* DecodeGroupC *)
  let d bin = extract bin 15u 12u
  let n bin = extract bin 19u 16u
  let t bin = extract bin 3u 0u

module DGrD = (* DecodeGroupD *)
  let d bin = extract bin 15u 12u
  let n bin = extract bin 3u 0u

module DGrE = (* DecodeGroupE *)
  let coproc bin = extract bin 11u 8u
  let crm bin = extract bin 3u 0u
  let dm bin = concat (pickBit bin 5u) (extract bin 3u 0u) 4 (* M:Vm *)
  let opc1 bin = extract bin 7u 4u
  let sm bin = concat (extract bin 3u 0u) (pickBit bin 5u) 1 (* Vm:M *)
  let t bin = extract bin 15u 12u
  let t2 bin = extract bin 19u 16u

module DGrF = (* DecodeGroupF *)
  let n bin = extract bin 19u 16u
  /// A1
  let regs1 bin = (extract bin 7u 0u) / 2u
  let d1 bin = concat (pickBit bin 22u) (extract bin 15u 12u) 4 (* D:Vd *)
  /// A2
  let regs2 bin = extract bin 7u 0u
  let d2 bin = concat (extract bin 15u 12u) (pickBit bin 22u) 1 (* Vd:D *)

module DGrG = (* DecodeGroupG *)
  let coproc bin = extract bin 11u 8u
  let crm bin = extract bin 3u 0u
  let crn bin = extract bin 19u 16u
  let opc1 bin = extract bin 23u 21u
  let opc2 bin = extract bin 7u 5u
  let t bin = extract bin 15u 12u

/// shared/functions/common/Replicate on page J1-7848.
// Replicate()
// ===========
let replicate value bits oprSize =
  let rec loop acc shift =
    if shift >= RegType.toBitWidth oprSize then acc
    else loop (acc ||| (value <<< shift)) (shift + bits)
  loop value bits

/// shared/functions/vector/AdvSIMDExpandImm on page J1-7926.
// AdvSIMDExpandImm()
// ==================
let advSIMDExpandImm bin =
  let cmode = extract bin 11u 8u
  let cmode0 = pickBit cmode 0u (* cmode<0> *)
  let op = pickBit bin 5u
  let imm8 = concat (concat (pickBit bin 24u) (extract bin 18u 16u) 3)
                    (extract bin 3u 0u) 4
  match extract cmode 3u 1u (* cmode<3:1> *) with
  | 0b000u -> replicate (imm8 |> int64) (* Zeros(24):imm8 *) 32 64<rt>
  | 0b001u ->
    replicate (imm8 <<< 8 |> int64) 32 64<rt> (* Zeros(16):imm8:Zeros(8) *)
  | 0b010u ->
    replicate (imm8 <<< 16 |> int64) 32 64<rt> (* Zeros(8):imm8:Zeros(16) *)
  | 0b011u -> replicate (imm8 <<< 24 |> int64) 32 64<rt> (* imm8:Zeros(24) *)
  | 0b100u -> replicate (imm8 |> int64) 16 64<rt> (* Zeros(8):imm8 *)
  | 0b101u -> replicate (imm8 <<< 8 |> int64) 16 64<rt> (* imm8:Zeros(8) *)
  | 0b110u ->
    let imm = if cmode0 = 0u && op = 0u then
                (imm8 <<< 8 |> int64) ||| 0xFL (* Zeros(16):imm8:Ones(8) *)
              else (imm8 <<< 16 |> int64) ||| 0xFFL (* Zeros(8):imm8:Ones(16) *)
    replicate (imm |> int64) 32 64<rt>
  | 0b111u ->
    if cmode0 = 0u && op = 0u then replicate (imm8 |> int64) 8 64<rt>
    elif cmode0 = 0u && op = 1u then
      (* imm8a = Replicate(imm8<7>, 8); imm8b = Replicate(imm8<6>, 8)
         imm8c = Replicate(imm8<5>, 8); imm8d = Replicate(imm8<4>, 8)
         imm8e = Replicate(imm8<3>, 8); imm8f = Replicate(imm8<2>, 8)
         imm8g = Replicate(imm8<1>, 8); imm8h = Replicate(imm8<0>, 8)
         imm64 = imm8a:imm8b:imm8c:imm8d:imm8e:imm8f:imm8g:imm8h *)
      (replicate (pickBit imm8 7u |> int64) 1 8<rt>) <<< 56 |||
      (replicate (pickBit imm8 6u |> int64) 1 8<rt>) <<< 48 |||
      (replicate (pickBit imm8 5u |> int64) 1 8<rt>) <<< 40 |||
      (replicate (pickBit imm8 4u |> int64) 1 8<rt>) <<< 32 |||
      (replicate (pickBit imm8 3u |> int64) 1 8<rt>) <<< 24 |||
      (replicate (pickBit imm8 2u |> int64) 1 8<rt>) <<< 16 |||
      (replicate (pickBit imm8 1u |> int64) 1 8<rt>) <<< 8 |||
      (replicate (pickBit imm8 0u |> int64) 1 8<rt>)
    elif cmode0 = 1u && op = 0u then
      (* imm32 = imm8<7>:NOT(imm8<6>):Replicate(imm8<6>,5):imm8<5:0>:Zeros(19)
         imm64 = Replicate(imm32, 2) *)
      let imm32 =
        ((pickBit imm8 7u |> int64) <<< 12 |||
         (~~~ (pickBit imm8 6u) |> int64) <<< 11 |||
         (replicate (pickBit imm8 6u |> int64) 1 5<rt>) <<< 6 |||
         (extract imm8 5u 0u |> int64)) <<< 19
      replicate imm32 32 64<rt>
    else (* cmode0 = 1u && op = 1u *)
      (((pickBit imm8 7u |> int64) <<< 15) |||
       ((~~~ (pickBit imm8 6u) |> int64) <<< 14) |||
       ((replicate (pickBit imm8 6u |> int64) 1 8<rt>) <<< 6) |||
       (extract imm8 5u 0u |> int64)) <<< 48
  | _ -> Utils.impossible ()

module DGrH = (* DecodeGroupH *)
  let d bin = concat (pickBit bin 22u) (extract bin 15u 12u) 4 (* D:Vd *)
  let imm64 bin = advSIMDExpandImm bin

/// shared/functions/float/vfpexpandimm/VFPExpandImm one page J1-7900.
// VFPExpandImm()
// ==============
let vfpExpandImm bin imm8 =
  let size = extract bin 9u 8u (* size *)
  let E =
    match size with
    | 0b01u -> 5
    | 0b10u -> 8
    | 0b11u -> 11
    | _ (* 00 *) -> raise UndefinedException
  let F = int size - E - 1
  let sign = pickBit imm8 8u
  let exp =
    concat (concat (~~~ (pickBit imm8 6u))
      (replicate (pickBit imm8 6u |> int64) (E - 3) 1<rt> |> uint32) (E - 3))
      (extract imm8 5u 4u) 2
  let frac = extract imm8 3u 0u <<< (F - 4)
  concat (concat sign exp (1 + (E - 3) + 2)) frac 4

/// Operand function
let getRegister n: Register = n |> LanguagePrimitives.EnumOfValue
//let parseCond n: Condition = n |> LanguagePrimitives.EnumOfValue
let getVecSReg n: Register = n + 0x100 |> LanguagePrimitives.EnumOfValue
let getVecDReg n: Register = n + 0x200 |> LanguagePrimitives.EnumOfValue
let getVecQReg n: Register = (n >>> 1) + 0x300 |> LanguagePrimitives.EnumOfValue
let getCoprocCReg n: Register = n + 0x400 |> LanguagePrimitives.EnumOfValue
let getCoprocDReg n: Register = n + 0x500 |> LanguagePrimitives.EnumOfValue
let getOption n: Option = n |> LanguagePrimitives.EnumOfValue

(* fReg: First Register, rNum: Number of registers *)
let getDRegList fReg rNum =
  List.map (fun r -> int r |> getVecDReg) [ fReg .. fReg + rNum - 1u ]
  |> OprRegList

let getSRegList fReg rNum =
  List.map (fun r -> int r |> getVecSReg) [ fReg .. fReg + rNum - 1u ]
  |> OprRegList

let rd bin = d bin |> int |> getRegister |> OprReg
let rt bin = t bin |> int |> getRegister |> OprReg
let rt2 bin = t2 bin |> int |> getRegister |> OprReg
let rn bin = n bin |> int |> getRegister |> OprReg
let rm bin = m bin |> int |> getRegister |> OprReg
let rs bin = s bin |> int |> getRegister |> OprReg
let sReg bin = extract bin 15u 12u |> int |> getRegister |> OprReg

module OFnB =
  let rd bin = DGrB.d bin |> int |> getRegister |> OprReg
  let rn bin = DGrB.n bin |> int |> getRegister |> OprReg
  let rm bin = DGrB.m bin |> int |> getRegister |> OprReg
  let ra bin = DGrB.a bin |> int |> getRegister |> OprReg
  let rdl bin = DGrB.dLo bin |> int |> getRegister |> OprReg
  let rdh bin = DGrB.dHi bin |> int |> getRegister |> OprReg

module OFnC =
  let rd bin = DGrC.d bin |> int |> getRegister |> OprReg
  let rt bin = DGrC.t bin |> int |> getRegister |> OprReg
  let rt2 bin = DGrC.t bin + 1u |> int |> getRegister |> OprReg
  let rn bin = DGrC.n bin |> int |> getRegister |> OprReg

module OFnD =
  let rd bin = DGrD.d bin |> int |> getRegister |> OprReg
  let rn bin = DGrD.n bin |> int |> getRegister |> OprReg

module OFnE =
  let coproc bin = DGrE.coproc bin |> int |> getCoprocDReg |> OprReg
  let crm bin = DGrE.crm bin |> int |> getCoprocCReg |> OprReg
  let dm bin = DGrE.dm bin |> int |> getVecDReg |> sVReg
  let opc1 bin = DGrE.opc1 bin |> int64 |> OprImm
  let rt bin = DGrE.t bin |> int |> getRegister |> OprReg
  let rt2 bin = DGrE.t2 bin |> int |> getRegister |> OprReg
  let sm bin = DGrE.sm bin |> int |> getVecSReg |> sVReg
  let sm1 bin = DGrE.sm bin + 1u |> int |> getVecSReg |> sVReg

module OFnF =
  let rn bin = DGrF.n bin |> int |> getRegister |> OprReg
  let dreglist bin = getDRegList (DGrF.d1 bin) (DGrF.regs1 bin)
  let sreglist bin = getSRegList (DGrF.d2 bin) (DGrF.regs2 bin)
  let sd bin = DGrF.d2 bin |> int |> getVecSReg |> sVReg
  let dd bin = DGrF.d1 bin |> int |> getVecDReg |> sVReg
  let label bin = extract bin 7u 0u |> int64 |> memLabel

module OFnG =
  let coproc bin = DGrG.coproc bin |> int |> getCoprocDReg |> OprReg
  let crm bin = DGrG.crm bin |> int |> getCoprocCReg |> OprReg
  let crn bin = DGrG.crn bin |> int |> getCoprocCReg |> OprReg
  let opc1 bin = DGrG.opc1 bin |> int64 |> OprImm
  let opc2 bin = DGrG.opc2 bin |> int64 |> OprImm
  let rt bin = DGrG.t bin |> int |> getRegister |> OprReg

module OFnH =
  let dd bin = DGrH.d bin |> int |> getVecDReg |> sVReg
  let qd bin = DGrH.d bin |> int |> getVecQReg |> sVReg
  let imm bin = DGrH.imm64 bin |> int64 |> OprImm

/// m [5], vm [3:0], d [22], vd [15:12], n [7], vn [19:16]
module DGrI =
  let m bin = pickBit bin 5u (* M *)
  let vm bin = extract bin 3u 0u (* Vm *)
  let d bin = pickBit bin 22u (* D *)
  let vd bin = extract bin 15u 12u (* Vd *)
  let n bin = pickBit bin 7u (* N *)
  let vn bin = extract bin 19u 16u (* Vn *)
  let d1 bin = concat (vd bin) (d bin) 1 (* Vd:D *)
  let m1 bin = concat (vm bin) (m bin) 1 (* Vm:M *)
  let d2 bin = concat (d bin) (vd bin) 4 (* D:Vd *)
  let m2 bin = concat (m bin) (vm bin) 4 (* M:Vm *)
  let n1 bin = concat (vn bin) (n bin) 1 (* Vn:N *)
  let n2 bin = concat (n bin) (vn bin) 4 (* N:Vn *)

  let sd bin = d1 bin |> int |> getVecSReg |> sVReg
  let sm bin = m1 bin |> int |> getVecSReg |> sVReg
  let dd bin = d2 bin |> int |> getVecDReg |> sVReg
  let dm bin = m2 bin |> int |> getVecDReg |> sVReg
  let sn bin = n1 bin |> int |> getVecSReg |> sVReg
  let dn bin = n2 bin |> int |> getVecDReg |> sVReg

/// vd [19:16], D [7], t [15:12]
module DGrJ =
  let t bin = extract bin 15u 12u (* Rt *)
  let vd bin = extract bin 19u 16u (* Vd *)
  let D bin = pickBit bin 7u (* D *)
  let d bin = concat (D bin) (vd bin) 4 (* D:Vd *)
  let vn bin = extract bin 19u 16u (* Vn *)
  let N bin = pickBit bin 7u (* N *)
  let n bin = concat (N bin) (vn bin) 4 (* N:Vn *)

  let rt bin = t bin |> int |> getRegister |> OprReg
  let dd0 bin = sSReg (d bin |> int |> getVecDReg, Some 0uy)
  let dd1 bin = sSReg (d bin |> int |> getVecDReg, Some 1uy)
  let dd2 bin = sSReg (d bin |> int |> getVecDReg, Some 2uy)
  let dd3 bin = sSReg (d bin |> int |> getVecDReg, Some 3uy)
  let dd4 bin = sSReg (d bin |> int |> getVecDReg, Some 4uy)
  let dd5 bin = sSReg (d bin |> int |> getVecDReg, Some 5uy)
  let dd6 bin = sSReg (d bin |> int |> getVecDReg, Some 6uy)
  let dd7 bin = sSReg (d bin |> int |> getVecDReg, Some 7uy)
  let dn0 bin = sSReg (n bin |> int |> getVecDReg, Some 0uy)
  let dn1 bin = sSReg (n bin |> int |> getVecDReg, Some 1uy)
  let dn2 bin = sSReg (n bin |> int |> getVecDReg, Some 2uy)
  let dn3 bin = sSReg (n bin |> int |> getVecDReg, Some 3uy)
  let dn4 bin = sSReg (n bin |> int |> getVecDReg, Some 4uy)
  let dn5 bin = sSReg (n bin |> int |> getVecDReg, Some 5uy)
  let dn6 bin = sSReg (n bin |> int |> getVecDReg, Some 6uy)
  let dn7 bin = sSReg (n bin |> int |> getVecDReg, Some 7uy)
  let dd bin = d bin |> int |> getVecDReg |> sVReg
  let qd bin = d bin |> int |> getVecQReg |> sVReg

/// vd [15:12], D [22], rn [19:16], rm [3:0]
module DGrK =
  let vd bin = extract bin 15u 12u (* Vd *)
  let D bin = pickBit bin 22u (* D *)
  let d bin = concat (D bin) (vd bin) 4 (* D:Vd *)
  let itype bin = extract bin 11u 8u (* itype *)
  let n bin = extract bin 19u 16u (* Rn *)
  let m bin = extract bin 3u 0u (* Rm *)
  let size bin = extract bin 7u 6u (* size *)

  let inc bin =
    match itype bin with
    | 0b0000u | 0b0100u -> 1u
    | _ -> 2u
  let d2 bin = d bin + inc bin
  let d3 bin = d2 bin + inc bin
  let d4 bin = d3 bin + inc bin

/// Vd [15:12], Vn [19:16], Vm [3:0], D [22], N [7], M [5], imm4 [11:8]
module DGrL =
  let vd bin = extract bin 15u 12u (* Vd *)
  let vn bin = extract bin 19u 16u (* Vn *)
  let vm bin = extract bin 3u 0u (* Vm *)
  let D bin = pickBit bin 22u (* D *)
  let N bin = pickBit bin 7u (* N *)
  let M bin = pickBit bin 5u (* M *)
  let Q bin = pickBit bin 6u (* Q *)
  let imm4 bin = extract bin 11u 8u (* imm4 *)
  let len bin = extract bin 9u 8u (* len *)
  let d bin = concat (D bin) (vd bin) 4 (* D:Vd *)
  let n bin = concat (N bin) (vn bin) 4 (* N:Vn *)
  let m bin = concat (M bin) (vm bin) 4 (* M:Vm *)

  let dd bin = d bin |> int |> getVecDReg |> sVReg
  let dn bin = n bin |> int |> getVecDReg |> sVReg
  let dm bin = m bin |> int |> getVecDReg |> sVReg
  let qd bin = d bin |> int |> getVecQReg |> sVReg
  let qn bin = n bin |> int |> getVecQReg |> sVReg
  let qm bin = m bin |> int |> getVecQReg |> sVReg
  let imm bin = imm4 bin |> int64 |> OprImm
  let list bin =
    let d = DGrH.d bin |> int
    match extract bin 9u 8u (* len *) with
    | 0b00u -> [ d ]
    | 0b01u -> [ d; d + 1 ]
    | 0b10u -> [ d; d + 1; d + 2 ]
    | _ (* 11u *) -> [ d; d + 1; d + 2; d + 3 ]
    |> List.map getVecDReg |> getSIMDVector
  let dmx bin =
    let idx =
      match extract bin 19u 16u (* imm4 *) with
      | b when b &&& 0b0001u = 0b0001u (* xxx1 *) -> extract b 3u 1u
      | b when b &&& 0b0011u = 0b0010u (* xx10 *) -> extract b 3u 2u
      | b when b &&& 0b0111u = 0b0100u (* x100 *) -> pickBit b 3u
      | _ (* x000 *) -> raise UndefinedException
      |> uint8
    sSReg (m bin |> int |> getVecDReg, Some idx)

/// Vd [15:12], Vn [19:16], Vm [3:0], D [22], N [7], M [5]
module DGrM =
  let vd bin = extract bin 15u 12u (* Vd *)
  let vn bin = extract bin 19u 16u (* Vn *)
  let vm bin = extract bin 3u 0u (* Vm *)
  let D bin = pickBit bin 22u (* D *)
  let N bin = pickBit bin 7u (* N *)
  let M bin = pickBit bin 5u (* M *)
  let d bin = concat (D bin) (vd bin) 4 (* D:Vd *)
  let n bin = concat (N bin) (vn bin) 4 (* N:Vn *)
  let m bin = concat (M bin) (vm bin) 4 (* M:Vm *)

  let dd bin = d bin |> int |> getVecDReg |> sVReg
  let dn bin = n bin |> int |> getVecDReg |> sVReg
  let dm bin = m bin |> int |> getVecDReg |> sVReg
  let qd bin = d bin |> int |> getVecQReg |> sVReg
  let qn bin = n bin |> int |> getVecQReg |> sVReg
  let qm bin = m bin |> int |> getVecQReg |> sVReg

/// Q [24], D [22], size [21:20], vn [19:16], vd [15:12], N [7], M [5], vm [3:0]
module DGrN =
  let Q bin = pickBit bin 24u (* Q *)
  let D bin = pickBit bin 22u (* D *)
  let size bin = extract bin 21u 20u (* size *)
  let vn bin = extract bin 19u 16u (* Vn *)
  let vd bin = extract bin 15u 12u (* Vd *)
  let N bin = pickBit bin 7u (* N *)
  let M bin = pickBit bin 5u (* M *)
  let vm bin = extract bin 3u 0u (* Vm *)
  let d bin = concat (D bin) (vd bin) 4 (* D:Vd *)
  let n bin = concat (N bin) (vn bin) 4 (* N:Vn *)
  let m bin =
    match size bin with
    | 0b01u -> extract (vm bin) 2u 0u (* Vm<2:0> *)
    | 0b10u -> vm bin (* Vm *)
    | _ -> raise UndefinedException
  let index bin =
    match size bin with
    | 0b01u -> concat (M bin) (pickBit (vm bin) 3u) 1 (* M:Vm<3> *)
    | 0b10u -> M bin (* Vm *)
    | _ -> raise UndefinedException

  let dd bin = d bin |> int |> getVecDReg |> sVReg
  let dn bin = n bin |> int |> getVecDReg |> sVReg
  let dmx bin = sSReg (m bin |> int |> getVecDReg, Some (index bin |> uint8))
  let qd bin = d bin |> int |> getVecQReg |> sVReg
  let qn bin = n bin |> int |> getVecQReg |> sVReg

/// D [22], Rn [19:16], Vd [15:12], size [7:6], a [4], Rm [3:0]
module DGrO =
  let D bin = pickBit bin 22u (* D *)
  let rn bin = extract bin 19u 16u (* Rn *)
  let vd bin = extract bin 15u 12u (* Vd *)
  let size bin = extract bin 7u 6u (* size *)
  let T bin = pickBit bin 5u
  let a bin = pickBit bin 4u (* a *)
  let rm bin = extract bin 3u 0u (* Rm *)
  let d bin = concat (D bin) (vd bin) 4 (* D:Vd *)
  let regs bin = if T bin = 0u then 1u else 2u
  let inc bin = if T bin = 0u then 1u else 2u
  let d2 bin = d bin + inc bin
  let d3 bin = d2 bin + inc bin
  let d4 bin = d3 bin + inc bin

  let list1 bin =
    let d = d bin |> int
    if T bin = 0u then [ d ] else [ d; d + 1 ]
    |> List.map getVecDReg |> getSIMDScalar None

  let list2 bin =
    let d = d bin |> int
    if T bin = 0u then [ d; d + 1 ] else [ d; d + 2 ]
    |> List.map getVecDReg |> getSIMDScalar None

  let list3 bin =
    let d = d bin |> int
    if T bin = 0u then [ d; d + 1; d + 2 ] else [ d; d + 2; d + 4 ]
    |> List.map getVecDReg |> getSIMDScalar None

  let list4 bin =
    let d = d bin |> int
    if T bin = 0u then [ d; d + 1; d + 2; d + 3 ]
    else [ d; d + 2; d + 4; d + 6 ]
    |> List.map getVecDReg |> getSIMDScalar None

  let memRnAlign1 bin =
    let rn = rn bin |> int |> getRegister
    let rm = rm bin |> int |> getRegister
    let align =
      match concat (size bin) (a bin) 1 with
      | 0b011u -> Some 16L
      | 0b101u -> Some 32L
      | _ -> None
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)

  let memRnAlign2 bin =
    let rn = rn bin |> int |> getRegister
    let rm = rm bin |> int |> getRegister
    let align =
      match concat (size bin) (a bin) 1 with
      | 0b001u -> Some 16L
      | 0b011u -> Some 32L
      | 0b101u -> Some 64L
      | _ -> None
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)

  let memRnAlign3 bin =
    let rn = rn bin |> int |> getRegister
    let rm = rm bin |> int |> getRegister
    let align =
      match concat (size bin) (a bin) 1 with
      | 0b001u -> Some 32L
      | 0b011u -> Some 64L
      | 0b101u -> Some 64L
      | 0b111u -> Some 128L
      | _ -> None
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)

  let memRn bin =
    let rn = rn bin |> int |> getRegister
    let rm = rm bin |> int |> getRegister
    match rm with
    | R.PC -> memOffsetImm (rn, None, None)
    | R.SP -> memPreIdxImm (rn, None, None)
    | _ -> memPostIdxReg (rn, None, rm, None)

/// D [22], Rn [19:16], Vd [15:12], index_align [7:4], Rm [3:0]
module DGrP =
  let D bin = pickBit bin 22u (* D *)
  let rn bin = extract bin 19u 16u (* Rn *)
  let vd bin = extract bin 15u 12u (* Vd *)
  let size bin = extract bin 11u 10u (* size *)
  let idxAlign bin = extract bin 7u 4u (* index_align *)
  let rm bin = extract bin 3u 0u (* Rm *)
  let d bin = concat (D bin) (vd bin) 4 (* D:Vd *)
  let inc bin =
    match size bin with
    | 0b00u -> 1u
    | 0b01u -> if pickBit (idxAlign bin) 1u = 0u then 1u else 2u
    | 0b10u -> if pickBit (idxAlign bin) 2u = 0u then 1u else 2u
    | _ -> raise UndefinedException
  let d2 bin = d bin + inc bin
  let d3 bin = d2 bin + inc bin
  let d4 bin = d3 bin + inc bin

  let idx bin =
    match size bin with
    | 0b00u -> extract (idxAlign bin) 3u 1u
    | 0b01u -> extract (idxAlign bin) 3u 2u
    | 0b10u -> pickBit (idxAlign bin) 3u
    | _ (* 11 *) -> raise UndefinedException
    |> uint8 |> Some

  let list1 bin = getSIMDScalar (idx bin) [ getVecDReg (d bin |> int) ]
  let list2 bin =
    let d = d bin |> int
    match size bin with
    | 0b00u -> [ d; d + 1 ]
    | 0b01u ->
      if pickBit (idxAlign bin) 1u = 0u then [ d; d + 1 ] else [ d; d + 2 ]
    | 0b10u ->
      if pickBit (idxAlign bin) 2u = 0u then [ d; d + 1 ] else [ d; d + 2 ]
    | _ -> raise UndefinedException
    |> List.map getVecDReg |> getSIMDScalar (idx bin)
  let list3 bin =
    let d = d bin |> int
    match size bin with
    | 0b00u -> [ d; d + 1; d + 2 ]
    | 0b01u -> if pickBit (idxAlign bin) 1u = 0u then [ d; d + 1; d + 2 ]
               else [ d; d + 2; d + 4 ]
    | 0b10u -> if pickBit (idxAlign bin) 2u = 0u then [ d; d + 1; d + 2 ]
               else [ d; d + 2; d + 4 ]
    | _ -> raise UndefinedException
    |> List.map getVecDReg |> getSIMDScalar (idx bin)
  let list4 bin =
    let d = d bin |> int
    match size bin with
    | 0b00u -> [ d; d + 1; d + 2; d + 3 ]
    | 0b01u -> if pickBit (idxAlign bin) 1u = 0u then [ d; d + 1; d + 2; d + 3 ]
               else [ d; d + 2; d + 4; d + 6 ]
    | 0b10u -> if pickBit (idxAlign bin) 2u = 0u then [ d; d + 1; d + 2; d + 3 ]
               else [ d; d + 2; d + 4; d + 6 ]
    | _ -> raise UndefinedException
    |> List.map getVecDReg |> getSIMDScalar (idx bin)

  let memRnAlign1 bin =
    let rn = rn bin |> int |> getRegister
    let rm = rm bin |> int |> getRegister
    let align =
      match size bin with
      (* index_align<1:0> *)
      | 0b01u when extract (idxAlign bin) 1u 0u = 0b01u -> Some 16L
      (* index_align<2:0> *)
      | 0b10u when extract (idxAlign bin) 2u 0u = 0b011u -> Some 32L
      | _ -> None
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)

  let memRnAlign2 bin =
    let rn = rn bin |> int |> getRegister
    let rm = rm bin |> int |> getRegister
    let align =
      match size bin with
      (* index_align<0> *)
      | 0b00u when pickBit (idxAlign bin) 0u = 1u -> Some 16L
      | 0b01u when pickBit (idxAlign bin) 0u = 1u -> Some 32L
      (* index_align<1:0> *)
      | 0b10u when extract (idxAlign bin) 1u 0u = 0b01u -> Some 64L
      | _ -> None
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)

  let memRnAlign3 bin =
    let rn = rn bin |> int |> getRegister
    let rm = rm bin |> int |> getRegister
    let align =
      match size bin with
      (* index_align<0> *)
      | 0b00u when pickBit (idxAlign bin) 0u = 1u -> Some 32L
      | 0b01u when pickBit (idxAlign bin) 0u = 1u -> Some 64L
      (* index_align<1:0> *)
      | 0b10u when extract (idxAlign bin) 1u 0u = 0b01u -> Some 64L
      | 0b10u when extract (idxAlign bin) 1u 0u = 0b10u -> Some 128L
      | _ -> None
    match rm with
    | R.PC -> memOffsetAlign (rn, align, None)
    | R.SP -> memPreIdxAlign (rn, align, None)
    | _ -> memPostIdxAlign (rn, align, Some rm)

  let memRn bin =
    let rn = rn bin |> int |> getRegister
    let rm = rm bin |> int |> getRegister
    match rm with
    | R.PC -> memOffsetImm (rn, None, None)
    | R.SP -> memPreIdxImm (rn, None, None)
    | _ -> memPostIdxReg (rn, None, rm, None)

/// Parse according to itype
let list bin =
  let d = DGrH.d bin |> int
  match extract bin 11u 8u (* itype *) with
  | 0b0000u -> [ d; d + 1; d + 2; d + 3 ]
  | 0b0001u -> [ d; d + 2; d + 4; d + 6 ]
  | 0b0111u -> [ d ]
  | 0b1010u -> [ d; d + 1 ]
  | 0b0110u -> [ d; d + 1; d + 2 ]
  | 0b0010u -> [ d; d + 1; d + 2; d + 3 ]
  | _ -> Utils.futureFeature ()
  |> List.map getVecDReg |> getSIMDVector

let rnMemAlign bin =
  let rn = extract bin 19u 16u |> int |> getRegister
  let rm = extract bin 3u 0u |> int |> getRegister
  let align =
    match extract bin 5u 4u (* align *) with
    | 0b01u -> Some 64L
    | 0b10u -> Some 128L
    | 0b11u -> Some 256L
    | _ -> None
  match rm with
  | R.PC -> memOffsetAlign (rn, align, None)
  | R.SP -> memPreIdxAlign (rn, align, None)
  | _ -> memPostIdxAlign (rn, align, Some rm)

let vfpImm bin =
  let imm8 = concat (extract bin 19u 16u) (extract bin 3u 0u) 4
  vfpExpandImm bin imm8 |> int64 |> OprImm


/// Data Type parsing
(* S8  when U = 0, size = 00
   S16 when U = 0, size = 01
   S32 when U = 0, size = 10
   U8  when U = 1, size = 00
   U16 when U = 1, size = 01
   U32 when U = 1, size = 10 *)
let getDataType bin =
  match concat (pickBit bin 24u) (extract bin 21u 20u) 2 (* U:size *) with
  | 0b000u -> SIMDTypS8
  | 0b001u -> SIMDTypS16
  | 0b010u -> SIMDTypS32
  | 0b100u -> SIMDTypU8
  | 0b101u -> SIMDTypU16
  | 0b110u -> SIMDTypU32
  | _ -> Utils.impossible ()

(* S16 when size = 01
   S32 when size = 10 *)
let getSignDT = function (* [21:20] *)
  | 0b001u -> SIMDTypS16
  | 0b010u -> SIMDTypS32
  | _ -> raise UndefinedException

let getIntSize = function (* [21:20] *)
  | 0b00u -> SIMDTypI16
  | 0b01u -> SIMDTypI32
  | 0b10u -> SIMDTypI64
  | _ -> Utils.impossible ()

let getSize = function (* [7:6] *)
  | 0b00u -> SIMDTyp8
  | 0b01u -> SIMDTyp16
  | 0b10u -> SIMDTyp32
  | _ (* 11 *) -> SIMDTyp64 (* or reserved *)

let getSizeS = function (* [7:6] *)  // FIXME: function name
  | 0b00u -> SIMDTyp8
  | 0b01u -> SIMDTyp16
  | _ (* 10 or 11 *) -> SIMDTyp32

(* I16 when F = 0, size = 01
   I32 when F = 0, size = 10 *)
let getSizeF0 = function (* [21:20] *)
  | 0b01u -> SIMDTypI16
  | 0b10u -> SIMDTypI32
  | _ (* 00 or 11 *) -> raise UndefinedException

(* F16 when F = 1, size = 01
   F32 when F = 1, size = 10 *)
let getSizeF1 = function (* [21:20] *)
  | 0b01u -> SIMDTypF16
  | 0b10u -> SIMDTypF32
  | _ (* 00 or 11 *) -> raise UndefinedException

let getSizeByImm4 = function (* [19:16] *)
  | 0b0001u | 0b0011u | 0b0101u | 0b0111u | 0b1001u | 0b1011u | 0b1101u
  | 0b1111u (* xxx1 *) -> SIMDTyp8
  | 0b0010u | 0b0110u | 0b1010u | 0b1110u (* xx10 *) -> SIMDTyp16
  | 0b0100u | 0b1100u (* x100 *) -> SIMDTyp32
  | _ (* x000 *) -> raise UndefinedException

/// Unpredicted Exception
(* (P == '0') || (W == '1') *)
let wback bin = (pickBit bin 24u = 0b0u || pickBit bin 21u = 0b1u)
(* (W == '1') *)
let wbackW bin = pickBit bin 21u = 0b1u
(* (m != 15) *)
let wbackM bin = extract bin 3u 0u <> 15u

(* Modified immediate constants in A32 instructions on page F2-4136.
   aarch32/functions/common/A32ExpandImm_C on page J1-7766. *)
let expandImmediate bin =
  let rotation = (extract bin 11u 8u |> int32) * 2
  let value = extract bin 7u 0u
  if rotation = 0 then value
  else (value <<< (32 - rotation)) ||| (value >>> rotation)

(* shared/functions/common/SignExtend *)
let signExtend bits =
  bits |> uint64 |> signExtend 26 32 |> System.Convert.ToInt64 |> memLabel

/// Unpredictable function
(* if n == 15 then UNPREDICTABLE *)
let chkPCRn bin = checkUnpred (n bin = 15u)

(* if n == 15 then UNPREDICTABLE *)
let chkPCRnB bin = checkUnpred (DGrB.n bin = 15u)

(* if wback && (n == 15 || n == t) then UNPREDICTABLE *)
let chkPCRnWithWB bin = checkUnpred (wback bin && (n bin = 15u || n bin = t bin))

(* if t == 15 then UNPREDICTABLE
   if wback && (n == 15 || n == t) then UNPREDICTABLE *)
let chkPCRnRtWithWB bin =
  checkUnpred ((t bin = 15u) || ((wback bin) && (n bin = 15u || n bin = t bin)))

(* if t == 15 || wback then UNPREDICTABLE *)
let chkPCRtWithWB bin = checkUnpred ((t bin = 15u) || wback bin)

(* if t == 15 || (wback && n == t) then UNPREDICTABLE *)
let chkPCRtRnWithWB bin =
  checkUnpred (t bin = 15u || (wback bin && (n bin = t bin)))

(* if n == 15 || n == t then UNPREDICTABLE *)
let chkPCRnRt bin = checkUnpred ((n bin = 15u) || (n bin = t bin))

(* if t == 15 || n == 15 || n == t then UNPREDICTABLE *)
let chkPCRtRnEq bin =
  checkUnpred ((t bin = 15u) || (n bin = 15u) || (n bin = t bin))

(* if t == 15 || n == 15 then UNPREDICTABLE *)
let chkPCRtRn bin = checkUnpred ((t bin = 15u) || (n bin = 15u))

(* if d == 15 || Rt<0> == '1' || t2 == 15 || n == 15 then UNPREDICTABLE
   if d == n || d == t || d == t2 then UNPREDICTABLE *)
let chkPCRdRt2Rn bin =
  let d = DGrC.d bin
  let t = DGrC.t bin
  let n = DGrC.n bin
  checkUnpred (((d = 15u) || (pickBit t 0u = 1u) || (t + 1u = 15u) || (n = 15u))
              || ((d = n) || (d = t) || (d = t + 1u)))

(* if Rt<0> == '1' || t2 == 15 || n == 15 then UNPREDICTABLE *)
let chkPCRt2Rn bin =
  let t = DGrC.t bin
  checkUnpred (((pickBit t 0u = 1u) || (t + 1u = 15u) || (DGrC.n bin = 15u)))

(* if d == 15 || t == 15 || n == 15 then UNPREDICTABLE
   if d == n || d == t then UNPREDICTABLE *)
let chkPCRdRtRn bin =
  checkUnpred (((DGrC.d bin = 15u) || (DGrC.t bin = 15u) || (DGrC.n bin = 15u))
              || ((DGrC.d bin = DGrC.n bin) || (DGrC.d bin = DGrC.t bin)))

(* if m == 15 then UNPREDICTABLE
   if wback && (n == 15 || n == t) then UNPREDICTABLE *)
let chkPCRmRn bin =
  checkUnpred ((m bin = 15u) || ((wback bin) && (n bin = 15u || n bin = t bin)))

(* if n == 15 || n == t || m == 15 then UNPREDICTABLE *)
let chkPCRnRm bin =
  checkUnpred ((n bin = 15u) || (n bin = t bin) || (m bin = 15u))

(* if d == 15 || n == 15 || m == 15 then UNPREDICTABLE *)
let chkPCRdRnRm bin =
  checkUnpred ((DGrB.d bin = 15u) || (DGrB.n bin = 15u) || (DGrB.m bin = 15u))

(* if d == 15 || n == 15 || m == 15 then UNPREDICTABLE *)
let chkPCRdOptRnRm bin =
  checkUnpred ((d bin = 15u) || (n bin = 15u) || (m bin = 15u))

(* if d == 15 || n == 15 then UNPREDICTABLE *)
let chkPCRdRn bin = checkUnpred ((DGrD.d bin = 15u) || (DGrD.n bin = 15u))

(* if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE *)
let chkPCRdRnRmRa bin =
  checkUnpred ((DGrB.d bin = 15u) || (DGrB.n bin = 15u) || (DGrB.m bin = 15u) ||
              (DGrB.a bin = 15u))

(* if d == 15 || n == 15 || m == 15 || a != 15 then UNPREDICTABLE *)
let chkPCRdRnRmRaNot bin =
  checkUnpred ((DGrB.d bin = 15u) || (DGrB.n bin = 15u) || (DGrB.m bin = 15u) ||
              (DGrB.a bin <> 15u))

(* if dLo == 15 || dHi == 15 || n == 15 || m == 15 then UNPREDICTABLE
   if dHi == dLo then UNPREDICTABLE *)
let chkPCRdlRdhRnRm bin =
  checkUnpred (((DGrB.dLo bin = 15u) || (DGrB.dHi bin = 15u) ||
                (DGrB.n bin = 15u) || (DGrB.m bin = 15u)) ||
              (DGrB.dHi bin = DGrB.dLo bin))

(* if t == 15 || n == 15 || n == t || m == 15 then UNPREDICTABLE *)
let chkPCRtRnRm b =
  checkUnpred ((t b = 15u) || (n b = 15u) || (n b = t b) || (m b = 15u))

(* if t == 15 || m == 15 then UNPREDICTABLE
   if wback && (n == 15 || n == t) then UNPREDICTABLE *)
let chkPCRtRm b = checkUnpred ((t b = 15u) || (m b = 15u) ||
                              (wback b && ((n b = 15u) || (n b = t b))))

(* if Rt<0> == '1' then UNPREDICTABLE
   if t2 == 15 then UNPREDICTABLE *)
let chkPCRt2 bin = checkUnpred ((pickBit (t bin) 0u = 1u) || (t2 bin = 15u))

(* if P == '0' && W == '1' then UNPREDICTABLE // Already checked.
   if t2 == 15 || m == 15 || m == t || m == t2 then UNPREDICTABLE
   if wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE *)
let chkPCRt2RmRnEq bin =
  (((t2 bin = 15u) || (m bin = 15u) || (m bin = t bin) || (m bin = t2 bin)) ||
   ((wback bin) && (n bin = 15u || n bin = t bin || n bin = t2 bin)))
   |> checkUnpred

(* if P == '0' && W == '1' then UNPREDICTABLE // Already checked.
   if t2 == 15 || m == 15 then UNPREDICTABLE
   if wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE *)
let chkPCRt2RmRn bin =
  (((t2 bin = 15u) || (m bin = 15u)) ||
   ((wback bin) && (n bin = 15u || n bin = t bin || n bin = t2 bin)))
   |> checkUnpred

(* if mask == '0000' then UNPREDICTABLE *)
let chkMask bin = checkUnpred (extract bin 19u 16u = 0b0000u)

(* if wback && n == t then UNPREDICTABLE *)
let chkRnRt bin = checkUnpred ((wback bin) && (n bin = t bin))

(* if wback then UNPREDICTABLE *)
let chkWback bin = checkUnpred (wback bin)

(* if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE *)
let chkPCRnRegs bin = checkUnpred (n bin = 15u || (extract bin 15u 0u = 0u))

(* if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE
   if wback && registers<n> == '1' then UNPREDICTABLE *)
let chkWBRegs bin = checkUnpred ((n bin = 15u || (extract bin 15u 0u = 0u)) ||
                                (wbackW bin && (pickBit bin (n bin) = 1u)))

(* if Rt<0> == '1' then UNPREDICTABLE
   if P == '0' && W == '1' then UNPREDICTABLE // Already checked.
   if wback && (n == t || n == t2) then UNPREDICTABLE
   if t2 == 15 then UNPREDICTABLE *)
let chkRnRtPCRt2 bin =
  checkUnpred ((pickBit (t bin) 0u = 1u) ||
              (wback bin && ((n bin = t bin) || (n bin = t2 bin))) ||
              (t2 bin = 15u))

(* if Rt<0> == '1' then UNPREDICTABLE
   if P == '0' && W == '1' then UNPREDICTABLE // Already checked.
   if wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE
   if t2 == 15 then UNPREDICTABLE *)
let chkPCRnRt2 bin =
  let struct (n, t2) = struct (n bin, t2 bin)
  checkUnpred ((pickBit (t bin) 0u = 1u) ||
              (wback bin && ((n = 15u) || (n = t bin) || (n = t2))) ||
              (t2 = 15u))

(* if d == 15 || m == 15 then UNPREDICTABLE *)
let chkPCRdRm bin = checkUnpred ((d bin = 15u) || (m bin = 15u))

(* if m == 15 then UNPREDICTABLE *)
let chkPCRm bin = checkUnpred (m bin = 15u)

(* if d == 15 then UNPREDICTABLE *)
let chkPCRd bin = checkUnpred (d bin = 15u)

(* if mask == '0000' then UNPREDICTABLE
   if n == 15 then UNPREDICTABLE *)
let chkMaskPCRn bin =
  checkUnpred ((extract bin 19u 16u = 0b0000u) || (DGrB.n bin = 15u))

(* if d == 15 || n == 15 || m == 15 || s == 15 then UNPREDICTABLE *)
let chkPCRdRnRmRs bin =
  checkUnpred ((d bin = 15u) || (n bin = 15u) || (m bin = 15u) || (s bin = 15u))

(* if d == 15 || m == 15 || s == 15 then UNPREDICTABLE *)
let chkPCRdRmRs bin =
  checkUnpred ((d bin = 15u) || (m bin = 15u) || (s bin = 15u))

(* if n == 15 || m == 15 || s == 15 then UNPREDICTABLE *)
let chkPCRnRmRs bin =
  checkUnpred ((n bin = 15u) || (m bin = 15u) || (s bin = 15u))

(* if d == 15 || n == 15 || m == 15 then UNPREDICTABLE
   if size == 64 then UNPREDICTABLE // Already checked.
   if cond != '1110' then UNPREDICTABLE *)
let chkPCRdRnRmSz bin cond =
  checkUnpred ((d bin = 15u || n bin = 15u || m bin = 15u) ||
              (cond <> Condition.AL))

(* if EDSCR.HDE == '0' || !HaltingAllowed() then UNDEFINED // ignore.
   if cond != '1110' then UNPREDICTABLE *)
let chkCondAL cond = checkUnpred (cond <> Condition.AL)

(* if t == 15 || t2 == 15 || m == 31 then UNPREDICTABLE
   if to_arm_registers && t == t2 then UNPREDICTABLE *)
let chkPCRtRt2VmEq bin =
  (((DGrE.t bin = 15u) || (DGrE.t2 bin = 15u) || (DGrE.sm bin = 31u))
  || ((pickBit bin 20u = 1u) && (DGrE.t bin = DGrE.t2 bin))) |> checkUnpred

(* // Armv8-A removes UNPREDICTABLE for R13
   if t == 15 || t2 == 15 then UNPREDICTABLE
   if to_arm_registers && t == t2 then UNPREDICTABLE *)
let chkPCRtRt2ArmEq bin =
  checkUnpred (((DGrE.t bin = 15u) || (DGrE.t2 bin = 15u)) ||
              ((pickBit bin 20u = 1u) && (DGrE.t bin = DGrE.t2 bin)))

(* // Armv8-A removes UNPREDICTABLE for R13
   if t == 15 || t2 == 15 || t == t2 then UNPREDICTABLE *)
let chkPCRtRt2Eq bin =
  checkUnpred ((DGrE.t bin = 15u) || (DGrE.t2 bin = 15u) ||
              (DGrE.t bin = DGrE.t2 bin))

(* // Armv8-A removes UNPREDICTABLE for R13
   if t == 15 || t2 == 15 then UNPREDICTABLE *)
let chkPCRtRt2 bin = checkUnpred ((DGrE.t bin = 15u) || (DGrE.t2 bin = 15u))

(* if n == 15 && (wback || CurrentInstrSet() != InstrSet_A32) then UNPREDICTABLE
   if regs == 0 || (d+regs) > 32 then UNPREDICTABLE *)
let chkPCRnDRegs bin =
  (((DGrF.n bin = 15u) && (wbackW bin)) ||
   ((DGrF.regs2 bin = 0u) || (((DGrF.d2 bin) + (DGrF.regs2 bin)) > 32u)))
   |> checkUnpred

(* if P == U && W == '1' then UNDEFINED // Already checked.
   if n == 15 && (wback || CurrentInstrSet() != InstrSet_A32) then UNPREDICTABLE
   if regs == 0 || regs > 16 || (d+regs) > 32 then UNPREDICTABLE
   if imm8<0> == '1' && (d+regs) > 16 then UNPREDICTABLE *)
let chkPCRnRegsImm bin =
  (((DGrF.n bin = 15u) && (wbackW bin)) ||
   ((DGrF.regs1 bin = 0u) || (DGrF.regs1 bin > 16u) ||
    (((DGrF.d1 bin) + (DGrF.regs1 bin)) > 32u)) ||
   ((pickBit bin 0u = 1u) && (((DGrF.d1 bin) + (DGrF.regs1 bin)) > 16u)))
   |> checkUnpred

(* if size == '00' || (size == '01' && !HaveFP16Ext()) then UNDEFINED // Checked
   if size == '01' && cond != '1110' then UNPREDICTABLE
   if n == 15 && CurrentInstrSet() != InstrSet_A32 then UNPREDICTABLE *)
let chkSzCondPCRn bin cond =
  (((extract bin 9u 8u = 0b01u) && (cond <> Condition.AL)) ||
   (DGrF.n bin = 15u (* && != InstrSet_A32 *))) |> checkUnpred

(* if size == '00' || (size == '01' && !HaveFP16Ext()) then UNDEFINED // Checked
   if size == '01' && cond != '1110' then UNPREDICTABLE *)
let chkSzCond bin cond =
  checkUnpred ((extract bin 9u 8u = 0b01u) && (cond <> Condition.AL))

(* if P == '0' && U == '0' && W == '0' then UNDEFINED // Checked.
   if n == 15 && (wback || CurrentInstrSet() != InstrSet_A32) then UNPREDICTABLE
*)
let chkPCRnWback bin = checkUnpred ((DGrF.n bin = 15u) && (wbackW bin))

(* if t == 15 then UNPREDICTABLE *)
let chkPCRt bin = checkUnpred (t bin = 15u)

(* if P == '0' && U == '0' && W == '0' then UNDEFINED // Checked.
   if W == '1' || (P == '0' && CurrentInstrSet() != InstrSet_A32)
   then UNPREDICTABLE *)
let chkWP bin =
  checkUnpred ((pickBit bin 21u = 0b1u) || (pickBit bin 24u = 0b0u))

(* is_pldw = (R == '0') *)
(* if m == 15 || (n == 15 && is_pldw) then UNPREDICTABLE *)
let chkPCRmRnPldw bin =
  checkUnpred ((m bin = 15u) || ((n bin = 15u) && (pickBit bin 22u = 0u)))

(* if Q == '1' && Vd<0> == '1' then UNDEFINED *)
let chkQVd bin =
  checkUndef ((pickBit bin 6u = 0b1u) && (pickBit bin 12u = 0b1u))

(* if size == '11' then UNDEFINED
   if n == 15 || d4 > 31 then UNPREDICTABLE *)
let chkSzPCRnD4 bin =
  checkUndef (DGrK.size bin = 0b11u)
  checkUnpred ((DGrK.n bin = 15u) || (DGrK.d4 bin > 31u))

(* if n == 15 || d+regs > 32 then UNPREDICTABLE *)
let chkPCRnDregs bin =
  checkUnpred ((DGrK.n bin = 15u) || ((DGrK.d bin) + 4u > 32u))

(* if size == '11' then UNDEFINED
   if n == 15 || d2+regs > 32 then UNPREDICTABLE *)
let chkPCRnD2regs bin =
  checkUndef (DGrK.size bin = 0b11u)
  checkUnpred ((DGrK.n bin = 15u) || ((DGrK.d2 bin) + 2u > 32u))

(* if size == '11' || align<1> == '1' then UNDEFINED
   if n == 15 || d3 > 31 then UNPREDICTABLE *)
let chkPCRnD3 bin =
  checkUndef ((DGrK.size bin = 0b11u) || (pickBit bin 5u = 1u))
  checkUnpred ((DGrK.n bin = 15u) || ((DGrK.d3 bin) > 31u))

(* if align<1> == '1' then UNDEFINED
   if n == 15 || d+regs > 32 then UNPREDICTABLE *)
let chkAlign1PCRnDregs bin regs =
  checkUndef (pickBit bin 5u = 1u)
  checkUnpred ((DGrK.n bin = 15u) || ((DGrK.d bin) + regs > 32u))

(* if align == '11' then UNDEFINED
   if n == 15 || d+regs > 32 then UNPREDICTABLE *)
let chkAlignPCRnDregs bin =
  checkUndef (extract bin 5u 4u = 0b11u)
  checkUnpred ((DGrK.n bin = 15u) || ((DGrK.d bin) + 2u > 32u))

(* if align == '11' then UNDEFINED
   if size == '11' then UNDEFINED
   if n == 15 || d2+regs > 32 then UNPREDICTABLE *)
let chkAlignPCRnD2regs bin =
  checkUndef ((extract bin 5u 4u = 0b11u) || (DGrK.size bin = 0b11u))
  checkUnpred ((DGrK.n bin = 15u) || ((DGrK.d2 bin) + 1u > 32u))

(* if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
   if Q == '0' && imm4<3> == '1' then UNDEFINED *)
let chkQVdImm bin =
  let isVd1 bin = pickBit (DGrL.vd bin) 0u = 1u
  let isVn1 bin = pickBit (DGrL.vn bin) 0u = 1u
  let isVm1 bin = pickBit (DGrL.vm bin) 0u = 1u
  checkUndef (((DGrL.Q bin = 1u) && ((isVd1 bin) || (isVn1 bin) || (isVm1 bin)))
             || ((DGrL.Q bin = 0u) && (pickBit (DGrL.imm4 bin) 3u = 1u)))

(* if n+length > 32 then UNPREDICTABLE *)
let chkPCRnLen bin = checkUnpred (DGrL.n bin + (DGrL.len bin + 1u) > 32u)

(* if Vd<0> == '1' || (op == '1' && Vn<0> == '1') then UNDEFINED *)
let chkVdOp bin =
  checkUndef ((pickBit (DGrM.vd bin) 0u = 1u) ||
             ((pickBit bin 8u = 1u) && (pickBit (DGrM.vn bin) 0u = 1u)) )

(* if Vn<0> == '1' || Vm<0> == '1' then UNDEFINED *)
let chkVnVm bin =
  checkUndef (pickBit (DGrM.vn bin) 0u = 1u || pickBit (DGrM.vn bin) 0u = 1u)

(* if size == '00' || Vd<0> == '1' then UNDEFINED *)
let chkSzVd bin =
  checkUndef ((extract bin 21u 20u = 0b00u) || (pickBit (DGrM.vd bin) 0u = 1u))

(* if Vn<0> == '1' then UNDEFINED *)
let chkVd0 bin = checkUndef (pickBit (DGrM.vd bin) 0u = 1u)

(* if size == '00' ||
   (F == '1' && size == '01' && !HaveFP16Ext()) then UNDEFINED
   if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED *)
let chkSzQVdVn bin =
  checkUndef ((DGrN.size bin = 0b00u) ||
             (((DGrN.Q bin) = 1u) && ((pickBit (DGrN.vd bin) 0u = 1u) ||
                                       pickBit (DGrN.vn bin) 0u = 1u)))

(* if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED
   if size == '00' || size == '11' then UNDEFINED *)
let chkQVdVnVmSz bin =
  let isLsb1 bin = pickBit bin 0u = 1u
  ((((DGrN.Q bin) = 1u) &&
    (isLsb1 (DGrN.vd bin) || isLsb1 (DGrN.vn bin) || isLsb1 (DGrN.vm bin)))
  || (DGrN.size bin = 0b00u || DGrN.size bin = 0b11u)) |> checkUndef

(* if size == '11' || (size == '00' && a == '1') then UNDEFINED
   if n == 15 || d+regs > 32 then UNPREDICTABLE *)
let chkSzAPCRnDregs bin =
  checkUndef ((DGrO.size bin = 0b11u)
             || ((DGrO.size bin = 0b00u) && (DGrO.a bin = 1u)))
  checkUnpred ((DGrO.rn bin = 15u) || ((DGrO.d bin + DGrO.regs bin) > 32u))

(* if size == '11' then UNDEFINED
   if n == 15 || d2 > 31 then UNPREDICTABLE *)
let chkSzPCRnD2 bin =
  checkUndef (DGrO.size bin = 0b11u)
  checkUnpred ((DGrO.rn bin = 15u) || (DGrO.d2 bin > 31u))

(* if size == '11' || a == '1' then UNDEFINED
   if n == 15 || d3 > 31 then UNPREDICTABLE *)
let chkSzAPCRnD3 bin =
  checkUndef (DGrO.size bin = 0b11u || DGrO.a bin = 1u)
  checkUnpred (DGrO.rn bin = 15u || DGrO.d3 bin > 31u)

(* if size == '11' && a == '0' then UNDEFINED
   if n == 15 || d4 > 31 then UNPREDICTABLE *)
let chkSzAPCRnD4 bin =
  checkUndef (DGrO.size bin = 0b11u && DGrO.a bin = 0u)
  checkUnpred (DGrO.rn bin = 15u || DGrO.d4 bin > 31u)

(* if size == '11' then UNDEFINED
   if index_align<0> != '0' then UNDEFINED
   if n == 15 then UNPREDICTABLE *)
let chkSzIdx0PCRn bin =
  checkUndef ((DGrP.size bin = 0b11u) || (pickBit (DGrP.idxAlign bin) 0u <> 0u))
  checkUnpred (DGrP.rn bin = 15u)

(* if size == '11' then UNDEFINED
   if index_align<1> != '0' then UNDEFINED
   if n == 15 then UNPREDICTABLE *)
let chkSzIdx1PCRn bin =
  checkUndef ((DGrP.size bin = 0b11u) || (pickBit (DGrP.idxAlign bin) 1u <> 0u))
  checkUnpred (DGrP.rn bin = 15u)

(* if size == '11' then UNDEFINED
   if index_align<2> != '0' then UNDEFINED
   if index_align<1:0> != '00' && index_align<1:0> != '11' then UNDEFINED
   if n == 15 then UNPREDICTABLE *)
let chkSzIdx2PCRn bin =
  let idxAl = DGrP.idxAlign bin
  checkUndef ((DGrP.size bin = 0b11u) || (pickBit idxAl 2u <> 0u) ||
             (extract idxAl 1u 0u <> 0b00u && extract idxAl 1u 0u <> 0b11u))
  checkUnpred (DGrP.rn bin = 15u)

(* if size == '11' then UNDEFINED // Already checked
   if n == 15 || d2 > 31 then UNPREDICTABLE *)
let chkPCRnD2 bin = checkUnpred ((DGrP.rn bin = 15u) || ((DGrP.d2 bin) > 31u))

(* if size == '11' then UNDEFINED // Already checked.
   if index_align<0> != '0' then UNDEFINED
   if n == 15 || d3 > 31 then UNPREDICTABLE *)
let chkIdx0PCRnD3 bin =
  checkUndef (pickBit (DGrP.idxAlign bin) 0u <> 0u)
  checkUnpred ((DGrP.rn bin = 15u) || (DGrP.d3 bin > 31u))

(* if size == '11' then UNDEFINED // Already checked.
   if index_align<1> != '0' then UNDEFINED
   if n == 15 || d2 > 31 then UNPREDICTABLE *)
let chkIdxPCRnD2 bin =
  checkUndef (pickBit (DGrP.idxAlign bin) 1u <> 0u)
  checkUnpred ((DGrP.rn bin = 15u) || (DGrP.d2 bin > 31u))

(* if size == '11' then UNDEFINED // Already checked.
   if index_align<1:0> != '00' then UNDEFINED
   if n == 15 || d3 > 31 then UNPREDICTABLE *)
let chkIdx10PCRnD3 bin =
  checkUndef (extract (DGrP.idxAlign bin) 1u 0u <> 0b00u)
  checkUnpred ((DGrP.rn bin = 15u) || (DGrP.d3 bin > 31u))

(* if size == '11' then UNDEFINED // Already checked.
   if n == 15 || d4 > 31 then UNPREDICTABLE *)
let chkPCRnD4 bin = checkUnpred ((DGrP.rn bin = 15u) || (DGrP.d4 bin > 31u))

(* if size == '11' then UNDEFINED // Already checked.
   if index_align<1:0> == '11' then UNDEFINED
   if n == 15 || d4 > 31 then UNPREDICTABLE *)
let chkIdxPCRnD4 bin =
  checkUndef (extract (DGrP.idxAlign bin) 1u 0u = 0b11u)
  checkUnpred ((DGrP.rn bin = 15u) || (DGrP.d4 bin > 31u))


let getBankedReg r sysM =
  match concat r sysM 5 with
  | 0b000000u -> R.R8usr
  | 0b000001u -> R.R9usr
  | 0b000010u -> R.R10usr
  | 0b000011u -> R.R11usr
  | 0b000100u -> R.R12usr
  | 0b000101u -> R.SPusr
  | 0b000110u -> R.LRusr
  | 0b001000u -> R.R8fiq
  | 0b001001u -> R.R9fiq
  | 0b001010u -> R.R10fiq
  | 0b001011u -> R.R11fiq
  | 0b001100u -> R.R12fiq
  | 0b001101u -> R.SPfiq
  | 0b001110u -> R.LRfiq
  | 0b010000u -> R.LRirq
  | 0b010001u -> R.SPirq
  | 0b010010u -> R.LRsvc
  | 0b010011u -> R.SPsvc
  | 0b010100u -> R.LRabt
  | 0b010101u -> R.SPabt
  | 0b010110u -> R.LRund
  | 0b010111u -> R.SPund
  | 0b011100u -> R.LRmon
  | 0b011101u -> R.SPmon
  | 0b011110u -> R.ELRhyp
  | 0b011111u -> R.SPhyp
  | 0b101110u -> R.SPSRfiq
  | 0b110000u -> R.SPSRirq
  | 0b110010u -> R.SPSRsvc
  | 0b110100u -> R.SPSRabt
  | 0b110110u -> R.SPSRund
  | 0b111100u -> R.SPSRmon
  | 0b111110u -> R.SPSRhyp
  | _ -> raise UnpredictableException

let sreg bin =
  let sreg = if pickBit bin 22u = 1u then R.SPSR else R.APSR (* or CPSR *)
  sreg |> int |> getRegister |> OprReg

let breg bin =
  let sysm = concat (pickBit bin 8u) (extract bin 19u 16u) 4
  getBankedReg (pickBit bin 22u) sysm |> OprReg

let expandImm bin = expandImmediate bin |> int64 |> OprImm

let expandImmCF bin =
  let imm32 = expandImmediate bin
  if extract bin 11u 8u = 0u then struct (imm32 |> int64 |> OprImm, None)
  else struct (imm32 |> int64 |> OprImm, Some (pickBit imm32 31u = 1u))

let imm0 () = OprImm 0L

let imm16 bin =
  concat (extract bin 19u 16u) (extract bin 11u 0u) 12 |> int64 |> OprImm

let imm12n4 bin =
  concat (extract bin 19u 8u) (extract bin 3u 0u) 4 |> int64 |> OprImm

let imm4 bin = extract bin 3u 0u |> int64 |> OprImm

let imm5 bin = extract bin 11u 7u |> int64 |> OprImm

let imm8 bin = extract bin 7u 0u |> int64 |> OprImm

let imm12 bin = extract bin 11u 0u |> int64 |> memLabel

let imm24LShf2 bin = extract bin 23u 0u <<< 2 |> signExtend

let imm24 bin = extract bin 23u 0u |> int64 |> OprImm

let imm24H bin =
  (concat (extract bin 23u 0u) (pickBit bin 24u) 1) <<< 1 |> signExtend

let imm4HL bin = concat (extract bin 11u 8u) (extract bin 3u 0u) 4 |> int64

let satImm bin = extract bin 19u 16u + 1u |> int64 |> OprImm

let lsb bin = extract bin 11u 7u |> int64 |> OprImm

let width bin =
  (extract bin 20u 16u) - (extract bin 11u 7u) + 1u |> int64 |> OprImm

let widthM1 bin = (extract bin 20u 16u) + 1u |> int64 |> OprImm

let label4HL bin = imm4HL bin |> memLabel

let specReg bin =
  let mask = extract bin 19u 16u
  if pickBit bin 22u = 0b0u then getCPSR (mask |> byte) |> OprSpecReg
  else getSPSR (mask |> byte) |> OprSpecReg

let label bin = /// FIXME: Label Operand? (memLabel)
  expandImmediate bin |> int64 |> memLabel

let mode bin = extract bin 5u 0u |> int64 |> OprImm

(* [<Rn>] *)
let rnMem bin = memOffsetImm (getReg bin 19u 16u, None, None)

let rnMemImm8 bin =
  let imm32 =
    match extract bin 9u 8u (* size *) with
    | 0b01u -> (extract bin 7u 0u (* imm8 *)) * 2u |> int64
    | _ -> (extract bin 7u 0u (* imm8 *)) * 4u |> int64
  let rn = getReg bin 19u 16u (* Rn *)
  let sign = pickBit bin 23u (* U *) |> getSign |> Some
  match concat (pickBit bin 24u) (pickBit bin 21u) 1 (* P:W *) with
  | 0b10u -> memOffsetImm (rn, sign, Some imm32)
  | 0b01u -> memPostIdxImm (rn, sign, Some imm32)
  | 0b11u -> memPreIdxImm (rn, sign, Some imm32)
  | _ -> Utils.impossible ()

let rnMemUnidx bin =
  let rn = getReg bin 19u 16u (* Rn *)
  memUnIdxImm (rn, extract bin 7u 0u (* imm8 *) |> int64)

let rnMemImm12 bin =
  let imm12 = extract bin 11u 0u |> int64
  let rn = getReg bin 19u 16u
  let sign = pickBit bin 23u |> getSign |> Some
  match concat (pickBit bin 24u) (pickBit bin 21u) 1 with
  | 0b10u -> memOffsetImm (rn, sign, Some imm12)
  | 0b11u -> memPreIdxImm  (rn, sign, Some imm12)
  | _ (* 0b0xu *) -> memPostIdxImm (rn, sign, Some imm12)

let rnMemImmHL bin =
  let rn = getReg bin 19u 16u
  let imm4H = extract bin 11u 8u
  let imm4L = extract bin 3u 0u
  let imm = concat imm4H imm4L 4 |> int64
  let sign = pickBit bin 23u |> getSign |> Some
  match concat (pickBit bin 24u) (pickBit bin 21u) 1 with
  | 0b10u -> memOffsetImm (rn, sign, if imm = 0L then None else Some imm)
  | 0b11u -> memPreIdxImm  (rn, sign, Some imm)
  | _ (* 0b0xu *) -> memPostIdxImm (rn, sign, Some imm)

let rnMemImm0 bin =
  memOffsetImm (getReg bin 19u 16u, None, None (* imm32 = 0 *))

let rnMemImmPIdx bin =
  let rn = getReg bin 19u 16u
  let imm4H = extract bin 11u 8u
  let imm4L = extract bin 3u 0u
  let imm = concat imm4H imm4L 4 |> int64 |> Some
  let sign = pickBit bin 23u |> getSign |> Some
  memPostIdxImm (rn, sign, imm)

let rnRmMem bin =
  let rn = getReg bin 19u 16u
  let rm = getReg bin 3u 0u
  let sign = pickBit bin 23u |> getSign |> Some
  match concat (pickBit bin 24u) (pickBit bin 21u) 1 with
  | 0b10u -> memOffsetReg (rn, sign, rm, None)
  | 0b00u -> memPostIdxReg (rn, sign, rm, None)
  | _ (* 0b11u | 0b01u *) -> memPreIdxReg (rn, sign, rm, None)

let rnRmMemPIdx bin =
  let rn = getReg bin 19u 16u
  let rm = getReg bin 3u 0u
  let sign = pickBit bin 23u |> getSign |> Some
  memPostIdxReg (rn, sign, rm, None)

let rnRmMemShf bin =
  let rn = getReg bin 19u 16u
  let rm = getReg bin 3u 0u
  let struct (shift, imm) =
    decodeImmShift (extract bin 6u 5u) (extract bin 11u 7u)
  let shiftOffset = Some (shift, Imm imm)
  let sign = pickBit bin 23u |> getSign |> Some
  match concat (pickBit bin 24u) (pickBit bin 21u) 1 with
  | 0b10u -> memOffsetReg (rn, sign, rm, shiftOffset)
  | 0b11u -> memPreIdxReg (rn, sign, rm, shiftOffset)
  | _ (* 0b0xu *) -> memPostIdxReg (rn, sign, rm, shiftOffset)

let rnRmMemShfOffset bin =
  let rn = getReg bin 19u 16u
  let rm = getReg bin 3u 0u
  let struct (shift, imm) =
    decodeImmShift (extract bin 6u 5u) (extract bin 11u 7u)
  let shiftOffset = Some (shift, Imm imm)
  let sign = pickBit bin 23u |> getSign |> Some
  memOffsetReg (rn, sign, rm, shiftOffset)

let regs bin = extract bin 15u 0u |> getRegList |> OprRegList

let option bin = getOption (extract bin 3u 0u |> int) |> OprOption

let fbits bin =
  let imm4i = concat (extract bin 3u 0u) (pickBit bin 5u) 1
  if pickBit bin 7u = 0u then 16u - imm4i else 32u - imm4i
  |> int64 |> OprImm

let endian bin = pickBit bin 9u |> byte |> getEndian |> OprEndian


/// Operands function (Operands, wback, cflag)
let oprNo _ = struct (NoOperand, false, None)

(* <Rt>, [<Rn>] *)
let oprRtAMem bin = struct (TwoOperands (rt bin, rnMem bin), false, None)

(* <Rd>, <Rt>, [<Rn>] *)
let oprRdRtMem bin =
  struct (ThreeOperands (OFnC.rd bin, OFnC.rt bin, rnMem bin), false, None)

(* <Rt>, [<Rn> {, {#}<imm>}] *)
let oprRtMemImm0 bin =
  struct (TwoOperands (rt bin, rnMemImm0 bin), false, None)

(* <Rd>, <Rt>, [<Rn> {, {#}<imm>}] *)
let oprRdRtMemImm bin =
  struct (ThreeOperands (OFnC.rd bin, OFnC.rt bin, rnMemImm0 bin), false, None)

(* {<Rd>,} <Rn>, #<const> *)
let oprRdRnConst bin =
  struct (ThreeOperands (rd bin, rn bin, expandImm bin), false, None)

(* {<Rd>,} <Rn>, #<const> with carry *)
let oprRdRnConstCF bin =
  let struct (imm32, carryOut) = expandImmCF bin
  struct (ThreeOperands (rd bin, rn bin, imm32), false, carryOut)

let oprRdSPConst bin =
  struct (ThreeOperands (rd bin, OprReg R.SP, expandImm bin), false, None)

let oprRdConst bin =
  struct (TwoOperands (rd bin, expandImm bin), false, None)

let oprRdConstCF bin =
  let struct (imm32, carryOut) = expandImmCF bin
  struct (TwoOperands (rd bin, imm32), false, carryOut)

let oprRnConst bin =
  struct (TwoOperands (rn bin, expandImm bin), false, None)

let oprRnConstCF bin =
  let struct (imm32, carryOut) = expandImmCF bin
  struct (TwoOperands (rn bin, imm32), false, carryOut)

let oprRdImm16 bin = struct (TwoOperands (rd bin, imm16 bin), false, None)

let oprSregImm bin = struct (TwoOperands (sReg bin, expandImm bin), false, None)

let oprRdLabel bin = struct (TwoOperands (rd bin, label bin), false, None)

let oprRtLabel bin = struct (TwoOperands (rt bin, imm12 bin), wback bin, None)

let oprRtLabelHL bin =
  struct (TwoOperands (rt bin, label4HL bin), wback bin, None)

(* <Rd>, <Rn>, <Rm> *)
(* {<Rd>,} <Rn>, <Rm> : SADD16? *)
let oprRdRnRm bin = struct (ThreeOperands (rd bin, rn bin, rm bin), false, None)

(* <Rd>, <Rn>{, <Rm>} *)
(* {<Rd>,} <Rn>, <Rm> *)
let oprRdRnRmOpt bin =
  struct (ThreeOperands (OFnB.rd bin, OFnB.rn bin, OFnB.rm bin), false, None)

(* {<Rd>,} <Rn>, <Rm>, RRX *)
(* {<Rd>,} <Rn>, <Rm> {, <shift> #<amount>} *)
let oprRdRnRmShf bin =
  let struct (shift, amount) =
    decodeImmShift (extract bin 6u 5u) (extract bin 11u 7u)
  let shift = OprShift (shift, Imm amount)
  struct (FourOperands (rd bin, rn bin, rm bin, shift), false, None)

(* {<Rd>,} <Rm>, #<imm> : MOV alias *)
let oprRdRmImm bin =
  struct (ThreeOperands (rd bin, rm bin, imm5 bin), false, None)

(* <Rn>, <Rm>, RRX *)
(* <Rn>, <Rm> {, <shift> #<amount>} *)
let oprRnRmShf bin =
  let struct (shift, amount) =
    decodeImmShift (extract bin 6u 5u) (extract bin 11u 7u)
  let shift = OprShift (shift, Imm amount)
  struct (ThreeOperands (rn bin, rm bin, shift), false, None)

(* <Rd>, <Rm>, RRX *)
(* <Rd>, <Rm> {, <shift> #<amount>} *)
let oprRdRmShf bin =
  let struct (shift, amount) =
    decodeImmShift (extract bin 6u 5u) (extract bin 11u 7u)
  let shift = OprShift (shift, Imm amount)
  struct (ThreeOperands (rd bin, rm bin, shift), false, None)

(* {<Rd>,} <Rn>, <Rm>, <shift> <Rs> *)
let oprRdRnRmShfRs bin =
  let rs = s bin |> int |> getRegister
  let shift = OprRegShift (decodeRegShift (extract bin 6u 5u), rs)
  struct (FourOperands (rd bin, rn bin, rm bin, shift), false, None)

(* <Rn>, <Rm>, <type> <Rs> *)
let oprRnRmShfRs bin =
  let rs = s bin |> int |> getRegister
  let shift = OprRegShift (decodeRegShift (extract bin 6u 5u), rs)
  struct (ThreeOperands (rn bin, rm bin, shift), false, None)

(* <Rd>, <Rm>, <shift> <Rs> *)
let oprRdRmShfRs bin =
  let rs = s bin |> int |> getRegister
  let shift = OprRegShift (decodeRegShift (extract bin 6u 5u), rs)
  struct (ThreeOperands (rd bin, rm bin, shift), false, None)

(* {<Rd>,} <Rm>, <Rs> *)
let oprRdRmRs bin = struct (ThreeOperands (rd bin, rm bin, rs bin), false, None)

(* <Rd>, #<imm>, <Rn> *)
let oprRdImmRn bin =
  struct (ThreeOperands (OFnD.rd bin, satImm bin, OFnD.rn bin), false, None)

(* <Rd>, #<imm>, <Rn>, ASR #<amount> *)
(* <Rd>, #<imm>, <Rn>, LSL #<amount> *)
let oprRdImmRnShf bin =
  let struct (sTyp, amount) =
    decodeImmShift (extract bin 6u 5u (* sh:'0' *)) (extract bin 11u 7u)
  let oprs = (OFnD.rd bin, satImm bin, OFnD.rn bin, OprShift (sTyp, Imm amount))
  struct (FourOperands oprs, false, None)

(* {<Rd>,} <Rn>, <Rm> {, ROR #<amount>} *)
let oprRdRnRmROR bin =
  let shift = OprShift (SRType.SRTypeROR, extract bin 11u 10u <<< 3 |> Imm)
  struct (FourOperands (rd bin, rn bin, rm bin, shift), false, None)

(* {<Rd>,} <Rm> {, ROR #<amount>} *)
let oprRdRmROR bin =
  let shift = OprShift (SRType.SRTypeROR, extract bin 11u 10u <<< 3 |> Imm)
  struct (ThreeOperands (rd bin, rm bin, shift), false, None)

(* {<Rd>,} <Rm>, <Rn> *)
let oprRdRmRn bin = struct (ThreeOperands (rd bin, rm bin, rn bin), false, None)

(* <Rd>, <Rn>, <Rm>, <Ra> *)
let oprRdRnRmRa bin =
  let oprs = FourOperands (OFnB.rd bin, OFnB.rn bin, OFnB.rm bin, OFnB.ra bin)
  struct (oprs, false, None)

(* <RdLo>, <RdHi>, <Rn>, <Rm> *)
let oprRdlRdhRnRm bin =
  let oprs = FourOperands (OFnB.rdl bin, OFnB.rdh bin, OFnB.rn bin, OFnB.rm bin)
  struct (oprs, false, None)

(* <Rt>, [<Rn>] *)
let oprRtMem bin = struct (TwoOperands (OFnC.rt bin, rnMem bin), false, None)

(* <Rd>, <Rt>, <Rt2>, [<Rn>] *)
let oprRdRtRt2Mem bin =
  let oprs = FourOperands (OFnC.rd bin, OFnC.rt bin, OFnC.rt2 bin, rnMem bin)
  struct (oprs, false, None)

(* <Rt>, <Rt2>, [<Rn>] *)
let oprRtRt2Mem bin =
  let oprs = ThreeOperands (OFnC.rt bin, OFnC.rt2 bin, rnMem bin)
  struct (oprs, false, None)

let oprRtMemImm12 bin =
  struct (TwoOperands (rt bin, rnMemImm12 bin), wback bin, None)

(* <Rt>, [<Rn>, {+/-}<Rm>{, <shift>}]
   <Rt>, [<Rn>], {+/-}<Rm>{, <shift>}
   <Rt>, [<Rn>, {+/-}<Rm>{, <shift>}]! *)
let oprRtMemShfWithWB bin =
  struct (TwoOperands (rt bin, rnRmMemShf bin), wback bin, None)

(* <Rt>, [<Rn>], {+/-}<Rm>{, <shift>} *)
let oprRtMemShf bin = struct (TwoOperands (rt bin, rnRmMemShf bin), false, None)

(* <Rt>, [<Rn>, {+/-}<Rm>]
   <Rt>, [<Rn>], {+/-}<Rm>
   <Rt>, [<Rn>, {+/-}<Rm>]! *)
let oprRtMemReg bin =
 struct (TwoOperands (rt bin, rnRmMem bin), wback bin, None)

(* <Rt>, [<Rn>], {+/-}<Rm> *)
let oprRtMemRegPIdx bin =
  struct (TwoOperands (rt bin, rnRmMemPIdx bin), false, None)

(* <Rt>, <Rt2>, [<Rn>, {+/-}<Rm>]
   <Rt>, <Rt2>, [<Rn>], {+/-}<Rm>
   <Rt>, <Rt2>, [<Rn>, {+/-}<Rm>]! *)
let oprRtRt2MemReg bin =
  struct (ThreeOperands (rt bin, rt2 bin, rnRmMem bin), wback bin, None)

(* <Rt>, [<Rn>] {, #{+/-}<imm>} *)
let oprRtMemImmPIdx bin =
  struct (TwoOperands (rt bin, rnMemImmHL bin), false, None)

(* <Rt>, [<Rn> {, #{+/-}<imm>}]
   <Rt>, [<Rn>], #{+/-}<imm>
   <Rt>, [<Rn>, #{+/-}<imm>]! *)
let oprRtMemImm bin =
  struct (TwoOperands (rt bin, rnMemImmHL bin), wback bin, None)

(* <Rt>, <Rt2>, [<Rn> {, #{+/-}<imm>}]
   <Rt>, <Rt2>, [<Rn>], #{+/-}<imm>
   <Rt>, <Rt2>, [<Rn>, #{+/-}<imm>]! *)
let oprRtRt2MemImm bin =
  struct (ThreeOperands (rt bin, rt2 bin, rnMemImmHL bin), wback bin, None)

(* <Rt>, <Rt2>, <label> *)
let oprRtRt2Label bin =
  struct (ThreeOperands (rt bin, rt2 bin, label4HL bin), false, None)

(* <Rn>{!} *)
let oprRn bin = struct (OneOperand (rn bin), wbackW bin, None)

(* SP{!}, #<mode> *)
let oprSPMode bin =
  struct (TwoOperands (OprReg R.SP, mode bin), wbackW bin, None)

(* <Rn>{!}, <registers> *)
let oprRnRegs bin = struct (TwoOperands (rn bin, regs bin), wbackW bin, None)

(* <registers> *)
let oprRegs bin = struct (OneOperand (regs bin), true, None)

(* <Rn>, <registers>^ *) /// FIXME: '^' not apply
let oprRnRegsCaret bin = struct (TwoOperands (rn bin, regs bin), false, None)

(* <label> *)
let oprLabel bin = struct (OneOperand (imm24LShf2 bin), false, None)

(* <label> *)
let oprLabelH bin = struct (OneOperand (imm24H bin), false, None)

(* [<Rn> {, #{+/-}<imm>}] *)
(* <label> // Normal form *)
(* [PC, #{+/-}<imm>] // Alternative form *)
let oprLabel12 bin = struct (OneOperand (imm12 bin), false, None)

(* <Rm> *)
let oprRm bin = struct (OneOperand (rm bin), false, None)

(* <Rd>, <spec_reg> *)
let oprRdSreg bin = struct (TwoOperands (rd bin, sreg bin), false, None)

(* <spec_reg>, <Rn> *)
let oprSregRn bin =
  struct (TwoOperands (sreg bin, OFnB.rn bin), false, None)

(* <Rd>, <banked_reg> *)
let oprRdBankreg bin = struct (TwoOperands (rd bin, breg bin), false, None)

(* <banked_reg>, <Rn> *)
let oprBankregRn bin = struct (TwoOperands (breg bin, OFnB.rn bin), false, None)

(* <Rd>, <Rm> *)
let oprRdRm bin = struct (TwoOperands (rd bin, rm bin), false, None)

(* {#}<imm> *)
let oprImm16 bin = struct (OneOperand (imm12n4 bin), false, None)

(* {#}<imm4> *)
let oprImm4 bin = struct (OneOperand (imm4 bin), false, None)

(* {#}<imm> *)
let oprImm24 bin = struct (OneOperand (imm24 bin), false, None)

(* <Rd>, #<lsb>, #<width> *)
let oprRdLsbWidth bin =
  struct (ThreeOperands (OFnD.rd bin, lsb bin, width bin), false, None)

(* <Rd>, <Rn>, #<lsb>, #<width> *)
let oprRdRnLsbWidth bin =
  let oprs = FourOperands (OFnD.rd bin, OFnD.rn bin, lsb bin, width bin)
  struct (oprs, false, None)

(* <Rd>, <Rn>, #<lsb>, #<width> *)
let oprRdRnLsbWidthM1 bin =
  let oprs = FourOperands (OFnD.rd bin, OFnD.rn bin, lsb bin, widthM1 bin)
  struct (oprs, false, None)

(* <Sm>, <Sm1>, <Rt>, <Rt2> *)
let oprSmSm1RtRt2 bin =
  let oprs = FourOperands (OFnE.sm bin, OFnE.sm1 bin, OFnE.rt bin, OFnE.rt2 bin)
  struct (oprs, false, None)

(* <Rt>, <Rt2>, <Sm>, <Sm1> *)
let oprRtRt2SmSm1 bin =
  let oprs = FourOperands (OFnE.rt bin, OFnE.rt2 bin, OFnE.sm bin, OFnE.sm1 bin)
  struct (oprs, false, None)

(* <Dm>, <Rt>, <Rt2> *)
let oprDmRtRt2 bin =
  let oprs = ThreeOperands (OFnE.dm bin, OFnE.rt bin, OFnE.rt2 bin)
  struct (oprs, false, None)

(* <Rt>, <Rt2>, <Dm> *)
let oprRtRt2Dm bin =
  let oprs = ThreeOperands (OFnE.rt bin, OFnE.rt2 bin, OFnE.dm bin)
  struct (oprs, false, None)

(* <coproc>, {#}<opc1>, <Rt>, <Rt2>, <CRm> *)
let oprCpOpc1RtRt2CRm b =
  let oprs = OFnE.coproc b, OFnE.opc1 b, OFnE.rt b, OFnE.rt2 b, OFnE.crm b
  struct (FiveOperands oprs, false, None)

(* <Rn>{!}, <dreglist> *)
let oprRnDreglist bin =
  struct (TwoOperands (OFnF.rn bin, OFnF.dreglist bin), wbackW bin, None)

(* <Rn>{!}, <sreglist> *)
let oprRnSreglist bin =
  struct (TwoOperands (OFnF.rn bin, OFnF.sreglist bin), wbackW bin, None)

(* <Sd>, <label> *)
let oprSdLabel bin =
  struct (TwoOperands (OFnF.sd bin, OFnF.label bin), false, None)

(* <Dd>, <label> *)
let oprDdLabel bin =
  struct (TwoOperands (OFnF.dd bin, OFnF.label bin), false, None)

(* <Sd>, [<Rn>{, #{+/-}<imm>}] *)
let oprSdMem bin =
  struct (TwoOperands (OFnF.sd bin, rnMemImm8 bin), false, None)

(* <Dd>, [<Rn>{, #{+/-}<imm>}] *)
let oprDdMem bin =
  struct (TwoOperands (OFnF.dd bin, rnMemImm8 bin), false, None)

(* p14, c5, [<Rn>], #{+/-}<imm> *)
let oprP14C5Mem bin =
  let oprs = ThreeOperands (OprReg R.P14, OprReg R.C5, rnMemImm8 bin)
  struct (oprs, wbackW bin, None)

(* p14, c5, [<Rn>], <option> *)
let oprP14C5Option bin =
  let oprs = ThreeOperands (OprReg R.P14, OprReg R.C5, rnMemUnidx bin)
  struct (oprs, wbackW bin, None)

(* p14, c5, <label> *)
let oprP14C5Label bin =
  let oprs = ThreeOperands (OprReg R.P14, OprReg R.C5, OFnF.label bin)
  struct (oprs, wbackW bin, None)

(* <coproc>, {#}<opc1>, <Rt>, <CRn>, <CRm>{, {#}<opc2>} *)
let oprCpOpc1RtCRnCRmOpc2 bin =
  let oprs = SixOperands (OFnG.coproc bin, OFnG.opc1 bin, OFnG.rt bin,
                         OFnG.crn bin, OFnG.crm bin, OFnG.opc2 bin)
  struct (oprs, false, None)

(* {<option>} *)
let oprOption bin = struct (OneOperand (option bin), false, None)

(* [<Rn>, {+/-}<Rm> , RRX] *)
(* [<Rn>, {+/-}<Rm> {, <shift> #<amount>}] *)
let oprMemReg bin = struct (OneOperand (rnRmMemShfOffset bin), false, None)

(* [<Rn> {, #{+/-}<imm>}] *)
let oprMemImm bin = struct (OneOperand (rnMemImm12 bin), false, None)

(* <Dd>, #<imm> *)
let oprDdImm bin = struct (TwoOperands (OFnH.dd bin, OFnH.imm bin), false, None)

(* <Qd>, #<imm> *)
let oprQdImm bin = struct (TwoOperands (OFnH.qd bin, OFnH.imm bin), false, None)

(* <list>, [<Rn>{:<align>}] *)
(* <list>, [<Rn>{:<align>}]! *)
(* <list>, [<Rn>{:<align>}], <Rm> *)
/// itype
let oprListMem bin =
  struct (TwoOperands (list bin, rnMemAlign bin), wbackM bin, None)

(* <list>, [<Rn>{:<align>}] *)
(* <list>, [<Rn>{:<align>}]! *)
(* <list>, [<Rn>{:<align>}], <Rm> *)
/// VLD1 (single element to all lanes)
let oprListMem1 bin =
  struct (TwoOperands (DGrO.list1 bin, DGrO.memRnAlign1 bin), wbackM bin, None)

/// VLD2 (single 2-element structure to all lanes)
let oprListMem2 bin =
  struct (TwoOperands (DGrO.list2 bin, DGrO.memRnAlign2 bin), wbackM bin, None)

/// VLD4 (single 4-element structure to all lanes)
let oprListMem4 bin =
  struct (TwoOperands (DGrO.list4 bin, DGrO.memRnAlign3 bin), wbackM bin, None)

(* <list>, [<Rn>] *)
(* <list>, [<Rn>]! *)
(* <list>, [<Rn>], <Rm> *)
/// VLD3 (single 3-element structure to all lanes)
let oprListMem3 bin =
  struct (TwoOperands (DGrO.list3 bin, DGrO.memRn bin), wbackM bin, None)

(* <list>, [<Rn>{:<align>}] *)
(* <list>, [<Rn>{:<align>}]! *)
(* <list>, [<Rn>{:<align>}], <Rm> *)
/// VST1: index_align
let oprListMemA bin =
  struct (TwoOperands (DGrP.list1 bin, DGrP.memRnAlign1 bin), wbackM bin, None)

/// VST2: index_align
let oprListMemB bin =
  struct (TwoOperands (DGrP.list2 bin, DGrP.memRnAlign2 bin), wbackM bin, None)

/// VST4: index_align
let oprListMemD bin =
  struct (TwoOperands (DGrP.list4 bin, DGrP.memRnAlign3 bin), wbackM bin, None)

(* <list>, [<Rn>] *)
(* <list>, [<Rn>]! *)
(* <list>, [<Rn>], <Rm> *)
/// VST3: index_align
let oprListMemC bin =
  struct (TwoOperands (DGrP.list3 bin, DGrP.memRn bin), wbackM bin, None)

(* <Sd>, <Sm> *)
let oprSdSm bin = struct (TwoOperands (DGrI.sd bin, DGrI.sm bin), false, None)

(* <Dd>, <Dm> *)
let oprDdDm bin = struct (TwoOperands (DGrI.dd bin, DGrI.dm bin), false, None)

(* <Dd>, <Sm> *)
let oprDdSm bin = struct (TwoOperands (DGrI.dd bin, DGrI.sm bin), false, None)

(* <Sd>, <Dm> *)
let oprSdDm bin = struct (TwoOperands (DGrI.sd bin, DGrI.dm bin), false, None)

(* <Sd>, #0.0 *)
let oprSdImm0 bin = struct (TwoOperands (DGrI.sd bin, imm0 ()), false, None)

(* <Dd>, #0.0 *)
let oprDdImm0 bin = struct (TwoOperands (DGrI.dd bin, imm0 ()), false, None)

(* <Sdm>, <Sdm>, #<fbits> *)
let oprSdmSdmFbits bin =
  struct (ThreeOperands (DGrI.sd bin, DGrI.sd bin, fbits bin), false, None)

(* <Ddm>, <Ddm>, #<fbits> *)
let oprDdmDdmFbits bin =
  struct (ThreeOperands (DGrI.dd bin, DGrI.dd bin, fbits bin), false, None)

(* <Sd>, #<imm> *)
let oprSdVImm bin = struct (TwoOperands (DGrI.sd bin, vfpImm bin), false, None)

(* <Dd>, #<imm> *)
let oprDdVImm bin = struct (TwoOperands (DGrI.dd bin, vfpImm bin), false, None)

(* <Sd>, <Sn>, <Sm> *)
let oprSdSnSm bin =
  struct (ThreeOperands (DGrI.sd bin, DGrI.sn bin, DGrI.sm bin), false, None)

(* <Dd>, <Dn>, <Dm> *)
let oprDdDnDm bin =
  struct (ThreeOperands (DGrI.dd bin, DGrI.dn bin, DGrI.dm bin), false, None)

(* <Sn>, <Rt> *)
let oprSnRt bin = struct (TwoOperands (DGrI.sn bin, rt bin), false, None)

(* <Rt>, <Sn> *)
let oprRtSn bin = struct (TwoOperands (rt bin, DGrI.sn bin), false, None)

(* <spec_reg>, <Rt> *)
let oprSregRt bin =
  struct (TwoOperands (OprReg R.FPSCR, rt bin), false, None) /// FIXME: spec_reg

(* <Rt>, <spec_reg> *)
let oprRtSreg bin =
  struct (TwoOperands (rt bin, OprReg R.FPSCR), false, None) /// FIXME: spec_reg

(* <Dd[x]>, <Rt> *)
let oprDd0Rt bin = struct (TwoOperands (DGrJ.dd0 bin, DGrJ.rt bin), false, None)
let oprDd1Rt bin = struct (TwoOperands (DGrJ.dd1 bin, DGrJ.rt bin), false, None)
let oprDd2Rt bin = struct (TwoOperands (DGrJ.dd2 bin, DGrJ.rt bin), false, None)
let oprDd3Rt bin = struct (TwoOperands (DGrJ.dd3 bin, DGrJ.rt bin), false, None)
let oprDd4Rt bin = struct (TwoOperands (DGrJ.dd4 bin, DGrJ.rt bin), false, None)
let oprDd5Rt bin = struct (TwoOperands (DGrJ.dd5 bin, DGrJ.rt bin), false, None)
let oprDd6Rt bin = struct (TwoOperands (DGrJ.dd6 bin, DGrJ.rt bin), false, None)
let oprDd7Rt bin = struct (TwoOperands (DGrJ.dd7 bin, DGrJ.rt bin), false, None)

(* <Rt>, <Dn[x]> *)
let oprRtDn0 bin = struct (TwoOperands (DGrJ.rt bin, DGrJ.dn0 bin), false, None)
let oprRtDn1 bin = struct (TwoOperands (DGrJ.rt bin, DGrJ.dn1 bin), false, None)
let oprRtDn2 bin = struct (TwoOperands (DGrJ.rt bin, DGrJ.dn2 bin), false, None)
let oprRtDn3 bin = struct (TwoOperands (DGrJ.rt bin, DGrJ.dn3 bin), false, None)
let oprRtDn4 bin = struct (TwoOperands (DGrJ.rt bin, DGrJ.dn4 bin), false, None)
let oprRtDn5 bin = struct (TwoOperands (DGrJ.rt bin, DGrJ.dn5 bin), false, None)
let oprRtDn6 bin = struct (TwoOperands (DGrJ.rt bin, DGrJ.dn6 bin), false, None)
let oprRtDn7 bin = struct (TwoOperands (DGrJ.rt bin, DGrJ.dn7 bin), false, None)

(* <Qd>, <Rt> *)
let oprQdRt bin = struct (TwoOperands (DGrJ.qd bin, DGrJ.rt bin), false, None)

(* <Dd>, <Rt> *)
let oprDdRt bin = struct (TwoOperands (DGrJ.dd bin, DGrJ.rt bin), false, None)

(* <endian_specifier> *)
let oprEndian bin = struct (OneOperand (endian bin), false, None)

(* {<Dd>,} <Dn>, <Dm>, #<imm> *)
let oprDdDnDmImm bin =
  let oprs = FourOperands (DGrL.dd bin, DGrL.dn bin, DGrL.dm bin, DGrL.imm bin)
  struct (oprs, false, None)

(* {<Qd>,} <Qn>, <Qm>, #<imm> *)
let oprQdQnQmImm bin =
  let oprs = FourOperands (DGrL.qd bin, DGrL.qn bin, DGrL.qm bin, DGrL.imm bin)
  struct (oprs, false, None)

(* <Dd>, <list>, <Dm> *)
let oprDdListDm bin =
  struct (ThreeOperands (DGrL.dd bin, DGrL.list bin, DGrL.dm bin), false, None)

(* <Dd>, <Dm[x]> *)
let oprDdDmx bin = struct (TwoOperands (DGrL.dd bin, DGrL.dmx bin), false, None)

(* <Qd>, <Dm[x]> *)
let oprQdDmx bin = struct (TwoOperands (DGrL.qd bin, DGrL.dmx bin), false, None)

(* <Qd>, <Dn>, <Dm> *)
let oprQdDnDm bin =
  struct (ThreeOperands (DGrM.qd bin, DGrM.dn bin, DGrM.dm bin), false, None)

(* {<Qd>,} <Qn>, <Dm> *)
let oprQdQnDm bin =
  struct (ThreeOperands (DGrM.qd bin, DGrM.qn bin, DGrM.dm bin), false, None)

(* <Dd>, <Qn>, <Qm> *)
let oprDdQnQm bin =
  struct (ThreeOperands (DGrM.dd bin, DGrM.qn bin, DGrM.qm bin), false, None)

(* <Dd>, <Dn>, <Dm[x]> *)
let oprDdDnDmx bin =
  struct (ThreeOperands (DGrN.dd bin, DGrN.dn bin, DGrN.dmx bin), false, None)

(* <Qd>, <Qn>, <Dm[x]> *)
let oprQdQnDmx bin =
  struct (ThreeOperands (DGrN.qd bin, DGrN.qn bin, DGrN.dmx bin), false, None)

(* <Qd>, <Dn>, <Dm>[<index>] *)
let oprQdDnDmx bin =
  struct (ThreeOperands (DGrN.qd bin, DGrN.dn bin, DGrN.dmx bin), false, None)


/// Parsing
let newInsInfo mode addr len cond opcode oprs itState wback q simdt cflag =
  let insInfo =
    { Address = addr
      NumBytes = len
      Condition = Some cond
      Opcode = opcode
      Operands = oprs
      ITState = itState
      WriteBack = wback
      Qualifier = q
      SIMDTyp = simdt
      Mode = mode
      Cflag = cflag }
  ARM32Instruction (addr, len, insInfo)

let render mode addr bin len cond opcode dt fnOperand =
  let struct (oprs, wback, cflag) = fnOperand bin
  newInsInfo mode addr len cond opcode oprs 0uy wback Qualifier.N dt cflag

let parseLoadStoreReg mode addr bin len cond =
  let pwo1op2 = concat (concat (pickBit bin 24u) (extract bin 21u 20u) 2)
                       (extract bin 6u 5u) 2
  match pwo1op2 with
  | 0b00001u ->
    chkPCRtRm bin; render mode addr bin len cond Op.STRH None oprRtMemReg
  | 0b00010u -> chkPCRt2RmRnEq bin
                render mode addr bin len cond Op.LDRD None oprRtRt2MemReg
  | 0b00011u ->
    chkPCRt2RmRn bin; render mode addr bin len cond Op.STRD None oprRtRt2MemReg
  | 0b00101u ->
    chkPCRtRm bin; render mode addr bin len cond Op.LDRH None oprRtMemReg
  | 0b00110u ->
    chkPCRtRm bin; render mode addr bin len cond Op.LDRSB None oprRtMemReg
  | 0b00111u ->
    chkPCRtRm bin; render mode addr bin len cond Op.LDRSH None oprRtMemReg
  | 0b01001u ->
    chkPCRtRnRm bin; render mode addr bin len cond Op.STRHT None oprRtMemRegPIdx
  | 0b01010u | 0b01011u -> raise UnallocatedException
  | 0b01101u ->
    chkPCRtRnRm bin; render mode addr bin len cond Op.LDRHT None oprRtMemRegPIdx
  | 0b01110u -> chkPCRtRnRm bin
                render mode addr bin len cond Op.LDRSBT None oprRtMemRegPIdx
  | 0b01111u -> chkPCRtRnRm bin
                render mode addr bin len cond Op.LDRSHT None oprRtMemRegPIdx
  | 0b10001u | 0b11001u ->
    chkPCRtRm bin; render mode addr bin len cond Op.STRH None oprRtMemReg
  | 0b10010u | 0b11010u ->
    chkPCRt2RmRn bin; render mode addr bin len cond Op.LDRD None oprRtRt2MemReg
  | 0b10011u | 0b11011u ->
    chkPCRt2RmRn bin; render mode addr bin len cond Op.STRD None oprRtRt2MemReg
  | 0b10101u | 0b11101u ->
    chkPCRtRm bin; render mode addr bin len cond Op.LDRH None oprRtMemReg
  | 0b10110u | 0b11110u ->
    chkPCRtRm bin; render mode addr bin len cond Op.LDRSB None oprRtMemReg
  | 0b10111u | 0b11111u ->
    chkPCRtRm bin; render mode addr bin len cond Op.LDRSH None oprRtMemReg
  | _ -> Utils.impossible ()

let parseLoadStoreImm mode addr bin len cond =
  let pwo1op2 = concat (concat (pickBit bin 24u) (extract bin 21u 20u) 2)
                       (extract bin 6u 5u) 2
  let isNotRn1111 bin = n bin <> 0b1111u
  match pwo1op2 with
  | 0b00010u when isNotRn1111 bin ->
    chkRnRtPCRt2 bin; render mode addr bin len cond Op.LDRD None oprRtRt2MemImm
  | 0b00010u ->
    chkPCRt2 bin; render mode addr bin len cond Op.LDRD None oprRtRt2Label
  | 0b00001u ->
    chkPCRnRtWithWB bin; render mode addr bin len cond Op.STRH None oprRtMemImm
  | 0b00011u ->
    chkPCRnRt2 bin; render mode addr bin len cond Op.STRD None oprRtRt2MemImm
  | 0b00101u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render mode addr bin len cond Op.LDRH None oprRtMemImm
  | 0b00101u ->
    chkPCRtWithWB bin; render mode addr bin len cond Op.LDRH None oprRtLabelHL
  | 0b00110u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render mode addr bin len cond Op.LDRSB None oprRtMemImm
  | 0b00110u ->
    chkPCRtWithWB bin; render mode addr bin len cond Op.LDRSB None oprRtLabelHL
  | 0b00111u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render mode addr bin len cond Op.LDRSH None oprRtMemImm
  | 0b00111u ->
    chkPCRtWithWB bin; render mode addr bin len cond Op.LDRSH None oprRtLabelHL
  | 0b01010u when isNotRn1111 bin -> raise UnallocatedException
  | 0b01010u ->
    chkPCRt2 bin; render mode addr bin len cond Op.LDRD None oprRtRt2Label
  | 0b01001u ->
    chkPCRtRnEq bin; render mode addr bin len cond Op.STRHT None oprRtMemImmPIdx
  | 0b01011u -> raise UnallocatedException
  | 0b01101u ->
    chkPCRtRnEq bin; render mode addr bin len cond Op.LDRHT None oprRtMemImmPIdx
  | 0b01110u -> chkPCRtRnEq bin
                render mode addr bin len cond Op.LDRSBT None oprRtMemImmPIdx
  | 0b01111u -> chkPCRtRnEq bin
                render mode addr bin len cond Op.LDRSHT None oprRtMemImmPIdx
  | 0b10010u when isNotRn1111 bin ->
    chkRnRtPCRt2 bin; render mode addr bin len cond Op.LDRD None oprRtRt2MemImm
  | 0b10010u ->
    chkPCRt2 bin; render mode addr bin len cond Op.LDRD None oprRtRt2Label
  | 0b10001u ->
    chkPCRnRtWithWB bin; render mode addr bin len cond Op.STRH None oprRtMemImm
  | 0b10011u ->
    chkPCRnRt2 bin; render mode addr bin len cond Op.STRD None oprRtRt2MemImm
  | 0b10101u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render mode addr bin len cond Op.LDRH None oprRtMemImm
  | 0b10101u ->
    chkPCRtWithWB bin; render mode addr bin len cond Op.LDRH None oprRtLabelHL
  | 0b10110u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render mode addr bin len cond Op.LDRSB None oprRtMemImm
  | 0b10110u ->
    chkPCRtWithWB bin; render mode addr bin len cond Op.LDRSB None oprRtLabelHL
  | 0b10111u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render mode addr bin len cond Op.LDRSH None oprRtMemImm
  | 0b10111u ->
    chkPCRtWithWB bin; render mode addr bin len cond Op.LDRSH None oprRtLabelHL
  | 0b11010u when isNotRn1111 bin ->
    chkRnRtPCRt2 bin; render mode addr bin len cond Op.LDRD None oprRtRt2MemImm
  | 0b11010u ->
    chkPCRt2 bin; render mode addr bin len cond Op.LDRD None oprRtRt2Label
  | 0b11001u ->
    chkPCRnRtWithWB bin; render mode addr bin len cond Op.STRH None oprRtMemImm
  | 0b11011u->
    chkPCRnRt2 bin; render mode addr bin len cond Op.STRD None oprRtRt2MemImm
  | 0b11101u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render mode addr bin len cond Op.LDRH None oprRtMemImm
  | 0b11101u ->
    chkPCRtWithWB bin; render mode addr bin len cond Op.LDRH None oprRtLabelHL
  | 0b11110u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render mode addr bin len cond Op.LDRSB None oprRtMemImm
  | 0b11110u ->
    chkPCRtWithWB bin; render mode addr bin len cond Op.LDRSB None oprRtLabelHL
  | 0b11111u when isNotRn1111 bin ->
    chkPCRtRnWithWB bin; render mode addr bin len cond Op.LDRSH None oprRtMemImm
  | 0b11111u ->
    chkPCRtWithWB bin; render mode addr bin len cond Op.LDRSH None oprRtLabelHL
  | _ -> Utils.impossible ()

/// Extra load/store on page F4-4220.
let parseExtraLoadStore mode addr bin len cond =
  match pickBit bin 22u (* op0 *) with
  | 0b0u -> parseLoadStoreReg mode addr bin len cond
  | _ (* 0b1u *) -> parseLoadStoreImm mode addr bin len cond

/// Multiply and Accumulate on page F4-4129.
let parseMultiplyAndAccumlate mode addr bin len cond =
  match extract bin 23u 20u (* opc:S *) with
  | 0b0000u ->
    chkPCRdRnRm bin; render mode addr bin len cond Op.MUL None oprRdRnRmOpt
  | 0b0001u ->
    chkPCRdRnRm bin; render mode addr bin len cond Op.MULS None oprRdRnRmOpt
  | 0b0010u ->
    chkPCRdRnRmRa bin; render mode addr bin len cond Op.MLA None oprRdRnRmRa
  | 0b0011u ->
    chkPCRdRnRmRa bin; render mode addr bin len cond Op.MLAS None oprRdRnRmRa
  | 0b0100u -> chkPCRdlRdhRnRm bin
               render mode addr bin len cond Op.UMAAL None oprRdlRdhRnRm
  | 0b0101u -> raise UnallocatedException
  | 0b0110u ->
    chkPCRdRnRmRa bin; render mode addr bin len cond Op.MLS None oprRdRnRmRa
  | 0b0111u -> raise UnallocatedException
  | 0b1000u -> chkPCRdlRdhRnRm bin
               render mode addr bin len cond Op.UMULL None oprRdlRdhRnRm
  | 0b1001u -> chkPCRdlRdhRnRm bin
               render mode addr bin len cond Op.UMULLS None oprRdlRdhRnRm
  | 0b1010u -> chkPCRdlRdhRnRm bin
               render mode addr bin len cond Op.UMLAL None oprRdlRdhRnRm
  | 0b1011u -> chkPCRdlRdhRnRm bin
               render mode addr bin len cond Op.UMLALS None oprRdlRdhRnRm
  | 0b1100u -> chkPCRdlRdhRnRm bin
               render mode addr bin len cond Op.SMULL None oprRdlRdhRnRm
  | 0b1101u -> chkPCRdlRdhRnRm bin
               render mode addr bin len cond Op.SMULLS None oprRdlRdhRnRm
  | 0b1110u -> chkPCRdlRdhRnRm bin
               render mode addr bin len cond Op.SMLAL None oprRdlRdhRnRm
  | _ (* 0b1111u *) ->
    chkPCRdlRdhRnRm bin
    render mode addr bin len cond Op.SMLALS None oprRdlRdhRnRm

/// Load/Store Exclusive and Load-Acquire/Store-Release on page F4-4223
/// ARMv8
let parseLdStExclAndLdAcqStRel mode addr bin len cond =
  (* size:L:ex:ord *)
  match concat (extract bin 22u 20u) (extract bin 9u 8u) 2 with
  | 0b00000u ->
    chkPCRtRn bin; render mode addr bin len cond Op.STL None oprRtMem
  | 0b00001u -> raise UnallocatedException
  | 0b00010u ->
    chkPCRdRtRn bin; render mode addr bin len cond Op.STLEX None oprRdRtMem
  | 0b00011u ->
    chkPCRdRtRn bin; render mode addr bin len cond Op.STREX None oprRdRtMem
  | 0b00100u ->
    chkPCRtRn bin; render mode addr bin len cond Op.LDA None oprRtAMem
  | 0b00101u -> raise UnallocatedException
  | 0b00110u ->
    chkPCRtRn bin; render mode addr bin len cond Op.LDAEX None oprRtAMem
  | 0b00111u ->
    chkPCRtRn bin; render mode addr bin len cond Op.LDREX None oprRtMemImm0
  | 0b01000u | 0b01001u -> raise UnallocatedException
  | 0b01010u ->
    chkPCRdRt2Rn bin; render mode addr bin len cond Op.STLEXD None oprRdRtRt2Mem
  | 0b01011u ->
    chkPCRdRt2Rn bin; render mode addr bin len cond Op.STREXD None oprRdRtRt2Mem
  | 0b01100u | 0b01101u -> raise UnallocatedException
  | 0b01110u ->
    chkPCRt2Rn bin; render mode addr bin len cond Op.LDAEXD None oprRtRt2Mem
  | 0b01111u ->
    chkPCRt2Rn bin; render mode addr bin len cond Op.LDREXD None oprRtRt2Mem
  | 0b10000u ->
    chkPCRtRn bin; render mode addr bin len cond Op.STLB None oprRtMem
  | 0b10001u -> raise UnallocatedException
  | 0b10010u ->
    chkPCRdRtRn bin; render mode addr bin len cond Op.STLEXB None oprRdRtMem
  | 0b10011u ->
    chkPCRdRtRn bin; render mode addr bin len cond Op.STREXB None oprRdRtMem
  | 0b10100u ->
    chkPCRtRn bin; render mode addr bin len cond Op.LDAB None oprRtMem
  | 0b10101u -> raise UnallocatedException
  | 0b10110u ->
    chkPCRtRn bin; render mode addr bin len cond Op.LDAEXB None oprRtMem
  | 0b10111u ->
    chkPCRtRn bin; render mode addr bin len cond Op.LDREXB None oprRtMem
  | 0b11000u ->
    chkPCRtRn bin; render mode addr bin len cond Op.STLH None oprRtMem
  | 0b11001u -> raise UnallocatedException
  | 0b11010u ->
    chkPCRdRtRn bin; render mode addr bin len cond Op.STLEXH None oprRdRtMem
  | 0b11011u ->
    chkPCRdRtRn bin; render mode addr bin len cond Op.STREXH None oprRdRtMem
  | 0b11100u ->
    chkPCRtRn bin; render mode addr bin len cond Op.LDAH None oprRtMem
  | 0b11101u -> raise UnallocatedException
  | 0b11110u ->
    chkPCRtRn bin; render mode addr bin len cond Op.LDAEXH None oprRtMem
  | _ (* 0b11111u *) ->
    chkPCRtRn bin; render mode addr bin len cond Op.LDREXH None oprRtMem

/// Synchronization primitives and Load-Acquire/Store-Release on page F4-4223.
let parseSyncAndLoadAcqStoreRel mode addr bin len cond =
  match pickBit bin 23u (* op0 *) with
  | 0b0u -> raise UnallocatedException
  | _ (* 0b01u *) -> parseLdStExclAndLdAcqStRel mode addr bin len cond

/// Move special register (register) on page F4-4225.
let parseMoveSpecialReg mode addr bin len cond =
  match concat (extract bin 22u 21u) (pickBit bin 9u) 1 (* opc:B *) with
  | 0b000u | 0b100u ->
    chkPCRd bin; render mode addr bin len cond Op.MRS None oprRdSreg
  | 0b001u | 0b101u ->
    chkPCRd bin; render mode addr bin len cond Op.MRS None oprRdBankreg
  | 0b010u | 0b110u ->
    chkMaskPCRn bin; render mode addr bin len cond Op.MSR None oprSregRn
  | _ (* 0bx11u *) ->
    chkPCRnB bin; render mode addr bin len cond Op.MSR None oprBankregRn

/// Cyclic Redundancy Check on page F4-4226.
/// ARMv8-A
let parseCyclicRedundancyCheck mode addr bin len cond =
  match concat (extract bin 22u 21u) (pickBit bin 9u) 1 (* sz:C *) with
  | 0b000u -> chkPCRdRnRmSz bin cond
              render mode addr bin len cond Op.CRC32B None oprRdRnRm
  | 0b001u -> chkPCRdRnRmSz bin cond
              render mode addr bin len cond Op.CRC32CB None oprRdRnRm
  | 0b010u -> chkPCRdRnRmSz bin cond
              render mode addr bin len cond Op.CRC32H None oprRdRnRm
  | 0b011u -> chkPCRdRnRmSz bin cond
              render mode addr bin len cond Op.CRC32CH None oprRdRnRm
  | 0b100u -> chkPCRdRnRmSz bin cond
              render mode addr bin len cond Op.CRC32W None oprRdRnRm
  | 0b101u -> chkPCRdRnRmSz bin cond
              render mode addr bin len cond Op.CRC32CW None oprRdRnRm
  | _  (* 0b11xu *) -> raise UnpredictableException

/// Integer Saturating Arithmetic on page F4-4226.
let parseIntegerSaturatingArithmetic mode addr bin len cond =
  match extract bin 22u 21u (* opc *) with
  | 0b00u ->
    chkPCRdOptRnRm bin; render mode addr bin len cond Op.QADD None oprRdRmRn
  | 0b01u -> render mode addr bin len cond Op.QSUB None oprRdRmRn
  | 0b10u -> render mode addr bin len cond Op.QDADD None oprRdRmRn
  | _ (* 0b11u *) -> render mode addr bin len cond Op.QDSUB None oprRdRmRn

/// Miscellaneous on page F4-4224.
let parseMiscellaneous mode addr bin len cond =
  match concat (extract bin 22u 21u) (extract bin 6u 4u) 3 (* op0:op1 *) with
  | 0b00001u | 0b00010u | 0b00011u | 0b00110u -> raise UnallocatedException
  | 0b01001u -> render mode addr bin len cond Op.BX None oprRm
  | 0b01010u -> chkPCRm bin; render mode addr bin len cond Op.BXJ None oprRm
  | 0b01011u -> chkPCRm bin; render mode addr bin len cond Op.BLX None oprRm
  | 0b01110u | 0b10001u | 0b10010u | 0b10011u | 0b10110u ->
    raise UnallocatedException
  | 0b11001u -> chkPCRdRm bin; render mode addr bin len cond Op.CLZ None oprRdRm
  | 0b11010u | 0b11011u -> raise UnallocatedException
  | 0b11110u -> render mode addr bin len cond Op.ERET None oprNo
  (* Exception Generation on page F4-4225. *)
  | 0b00111u ->
    chkCondAL cond; render mode addr bin len cond Op.HLT None oprImm16
  | 0b01111u ->
    chkCondAL cond; render mode addr bin len cond Op.BKPT None oprImm16
  | 0b10111u ->
    chkCondAL cond; render mode addr bin len cond Op.HVC None oprImm16
  | 0b11111u -> render mode addr bin len cond Op.SMC None oprImm4
  | 0b00000u | 0b01000u | 0b10000u | 0b11000u ->
    parseMoveSpecialReg mode addr bin len cond
  | 0b00100u | 0b01100u | 0b10100u | 0b11100u ->
    parseCyclicRedundancyCheck mode addr bin len cond
  | _ (* 0bxx101 *) -> parseIntegerSaturatingArithmetic mode addr bin len cond

/// Halfword Multiply and Accumulate on page F4-4220.
let parseHalfMulAndAccumulate mode addr bin len cond =
  match concat (extract bin 22u 21u) (extract bin 6u 5u) 2 (* opc:M:N *) with
  | 0b0000u ->
    chkPCRdRnRmRa bin; render mode addr bin len cond Op.SMLABB None oprRdRnRmRa
  | 0b0001u ->
    chkPCRdRnRmRa bin; render mode addr bin len cond Op.SMLATB None oprRdRnRmRa
  | 0b0010u ->
    chkPCRdRnRmRa bin; render mode addr bin len cond Op.SMLABT None oprRdRnRmRa
  | 0b0011u ->
    chkPCRdRnRmRa bin; render mode addr bin len cond Op.SMLATT None oprRdRnRmRa
  | 0b0100u ->
    chkPCRdRnRmRa bin; render mode addr bin len cond Op.SMLAWB None oprRdRnRmRa
  | 0b0101u ->
    chkPCRdRnRm bin; render mode addr bin len cond Op.SMULWB None oprRdRnRmOpt
  | 0b0110u ->
    chkPCRdRnRmRa bin; render mode addr bin len cond Op.SMLAWT None oprRdRnRmRa
  | 0b0111u ->
    chkPCRdRnRm bin; render mode addr bin len cond Op.SMULWT None oprRdRnRmOpt
  | 0b1000u -> chkPCRdlRdhRnRm bin
               render mode addr bin len cond Op.SMLALBB None oprRdlRdhRnRm
  | 0b1001u -> chkPCRdlRdhRnRm bin
               render mode addr bin len cond Op.SMLALTB None oprRdlRdhRnRm
  | 0b1010u -> chkPCRdlRdhRnRm bin
               render mode addr bin len cond Op.SMLALBT None oprRdlRdhRnRm
  | 0b1011u -> chkPCRdlRdhRnRm bin
               render mode addr bin len cond Op.SMLALTT None oprRdlRdhRnRm
  | 0b1100u ->
    chkPCRdRnRm bin; render mode addr bin len cond Op.SMULBB None oprRdRnRmOpt
  | 0b1101u ->
    chkPCRdRnRm bin; render mode addr bin len cond Op.SMULTB None oprRdRnRmOpt
  | 0b1110u ->
    chkPCRdRnRm bin; render mode addr bin len cond Op.SMULBT None oprRdRnRmOpt
  | _ (* 0b1111u *) ->
    chkPCRdRnRm bin; render mode addr bin len cond Op.SMULTT None oprRdRnRmOpt

/// Integer Data Processing (three register, immediate shift) on page F4-4227.
let parseIntegerDataProcThreeRegImm mode addr bin len cond =
  let isNotRn1101 bin = n bin <> 0b1101u
  match concat (extract bin 23u 21u) (pickBit bin 20u) 1 (* opc:S *) with
  | 0b0000u -> render mode addr bin len cond Op.AND None oprRdRnRmShf
  | 0b0001u -> render mode addr bin len cond Op.ANDS None oprRdRnRmShf
  | 0b0010u -> render mode addr bin len cond Op.EOR None oprRdRnRmShf
  | 0b0011u -> render mode addr bin len cond Op.EORS None oprRdRnRmShf
  (* | 0b0100u when isNotRn1101 bin ->
    render mode addr bin len cond Op.SUB None oprRdRnRmShf *)
  | 0b0100u -> render mode addr bin len cond Op.SUB None oprRdRnRmShf
  (* | 0b0101u when isNotRn1101 bin ->
    render mode addr bin len cond Op.SUBS None oprRdRnRmShf *)
  | 0b0101u -> render mode addr bin len cond Op.SUBS None oprRdRnRmShf
  | 0b0110u -> render mode addr bin len cond Op.RSB None oprRdRnRmShf
  | 0b0111u -> render mode addr bin len cond Op.RSBS None oprRdRnRmShf
  (* | 0b1000u when isNotRn1101 bin ->
    render mode addr bin len cond Op.ADD None oprRdRnRmShf *)
  | 0b1000u -> render mode addr bin len cond Op.ADD None oprRdRnRmShf
  (* | 0b1001u when isNotRn1101 bin ->
    render mode addr bin len cond Op.ADDS None oprRdRnRmShf *)
  | 0b1001u -> render mode addr bin len cond Op.ADDS None oprRdRnRmShf
  | 0b1010u -> render mode addr bin len cond Op.ADC None oprRdRnRmShf
  | 0b1011u -> render mode addr bin len cond Op.ADCS None oprRdRnRmShf
  | 0b1100u -> render mode addr bin len cond Op.SBC None oprRdRnRmShf
  | 0b1101u -> render mode addr bin len cond Op.SBCS None oprRdRnRmShf
  | 0b1110u -> render mode addr bin len cond Op.RSC None oprRdRnRmShf
  | _ (* 0b1111u *) -> render mode addr bin len cond Op.RSCS None oprRdRnRmShf

/// Integer Test and Compare (two register, immediate shift) on page F4-4228.
let parseIntegerTestAndCompareTwoRegImm mode addr bin len cond =
  match extract bin 22u 21u (* opc *) with
  | 0b00u -> render mode addr bin len cond Op.TST None oprRnRmShf
  | 0b01u -> render mode addr bin len cond Op.TEQ None oprRnRmShf
  | 0b10u -> render mode addr bin len cond Op.CMP None oprRnRmShf
  | _ (* 0b11u *) -> render mode addr bin len cond Op.CMN None oprRnRmShf

/// Alias conditions on page F5-4557.
let changeToAliasOfMOV bin =
  let stype = extract bin 6u 5u
  let imm5 = extract bin 11u 7u
  if stype = 0b10u then struct (Op.ASR, oprRdRmImm)
  elif imm5 <> 0b00000u && stype = 0b00u then struct (Op.LSL, oprRdRmImm)
  elif stype = 0b01u then struct (Op.LSR, oprRdRmImm)
  elif imm5 <> 0b00000u && stype = 0b11u then struct (Op.ROR, oprRdRmImm)
  elif imm5 = 0b00000u && stype = 0b11u then struct (Op.RRX, oprRdRm)
  /// FIXME: AArch32(F5-4555) vs ARMv7(A8-489)
  elif imm5 = 0b00000u then struct (Op.MOV, oprRdRm)
  else struct (Op.MOV, oprRdRmShf)

/// Alias conditions on page F5-4557.
let changeToAliasOfMOVS bin =
  let stype = extract bin 6u 5u
  let imm5 = extract bin 11u 7u
  if stype = 0b10u then struct (Op.ASRS, oprRdRmImm)
  elif imm5 <> 0b00000u && stype = 0b00u then struct (Op.LSLS, oprRdRmImm)
  elif stype = 0b01u then struct (Op.LSRS, oprRdRmImm)
  elif imm5 <> 0b00000u && stype = 0b11u then struct (Op.RORS, oprRdRmImm)
  elif imm5 = 0b00000u && stype = 0b11u then struct (Op.RRXS, oprRdRmImm)
  else struct (Op.MOVS, oprRdRmShf)

/// Logical Arithmetic (three register, immediate shift) on page F4-4229.
let parseLogicalArithThreeRegImm mode addr bin len cond =
  match extract bin 22u 20u (* opc:S *) with
  | 0b000u -> render mode addr bin len cond Op.ORR None oprRdRnRmShf
  | 0b001u -> render mode addr bin len cond Op.ORRS None oprRdRnRmShf
  | 0b010u ->
    let struct (opcode, oprFunc) = changeToAliasOfMOV bin
    render mode addr bin len cond opcode None oprFunc
  | 0b011u ->
    let struct (opcode, oprFunc) = changeToAliasOfMOVS bin
    render mode addr bin len cond opcode None oprFunc
  | 0b100u -> render mode addr bin len cond Op.BIC None oprRdRnRmShf
  | 0b101u -> render mode addr bin len cond Op.BICS None oprRdRnRmShf
  | 0b110u -> render mode addr bin len cond Op.MVN None oprRdRmShf
  | _ (* 0b111u *) -> render mode addr bin len cond Op.MVNS None oprRdRmShf

/// Data-processing register (immediate shift) on page F4-4227.
let parseDataProcRegisterImmShf mode addr bin len cond =
  match concat (extract bin 24u 23u) (pickBit bin 20u) 1 (* op0:op1 *) with
  | 0b000u | 0b001u | 0b010u | 0b011u ->
    parseIntegerDataProcThreeRegImm mode addr bin len cond
  | 0b101u -> parseIntegerTestAndCompareTwoRegImm mode addr bin len cond
  | 0b110u | 0b111u -> parseLogicalArithThreeRegImm mode addr bin len cond
  | _ (* 0b100u *) -> Utils.impossible ()

/// Integer Data Processing (three register, register shift) on page F4-4229.
let parseIntegerDataProcThreeRegRegShf mode addr bin len cond =
  match extract bin 23u 20u (* opc:S *) with
  | 0b0000u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.AND None oprRdRnRmShfRs
  | 0b0001u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.ANDS None oprRdRnRmShfRs
  | 0b0010u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.EOR None oprRdRnRmShfRs
  | 0b0011u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.EORS None oprRdRnRmShfRs
  | 0b0100u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.SUB None oprRdRnRmShfRs
  | 0b0101u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.SUBS None oprRdRnRmShfRs
  | 0b0110u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.RSB None oprRdRnRmShfRs
  | 0b0111u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.RSBS None oprRdRnRmShfRs
  | 0b1000u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.ADD None oprRdRnRmShfRs
  | 0b1001u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.ADDS None oprRdRnRmShfRs
  | 0b1010u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.ADC None oprRdRnRmShfRs
  | 0b1011u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.ADCS None oprRdRnRmShfRs
  | 0b1100u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.SBC None oprRdRnRmShfRs
  | 0b1101u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.SBCS None oprRdRnRmShfRs
  | 0b1110u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.RSC None oprRdRnRmShfRs
  | _ (* 0b1111u *) ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.RSCS None oprRdRnRmShfRs

/// Integer Test and Compare (two register, register shift) on page F4-4230.
let parseIntegerTestAndCompareTwoRegRegShf mode addr bin len cond =
  match extract bin 22u 21u (* opc *) with
  | 0b00u ->
    chkPCRnRmRs bin; render mode addr bin len cond Op.TST None oprRnRmShfRs
  | 0b01u ->
    chkPCRnRmRs bin; render mode addr bin len cond Op.TEQ None oprRnRmShfRs
  | 0b10u ->
    chkPCRnRmRs bin; render mode addr bin len cond Op.CMP None oprRnRmShfRs
  | _ (* 0b11u *) ->
    chkPCRnRmRs bin; render mode addr bin len cond Op.CMN None oprRnRmShfRs

/// Alias conditions on page F5-4562.
let changeToAliasOfMOVRegShf bin =
  let s = pickBit bin 20u (* S *)
  let stype = extract bin 6u 5u (* stype *)
  match concat s stype 2 (* S:stype *) with
  | 0b010u -> struct (Op.ASR, oprRdRmRs)
  | 0b000u -> struct (Op.LSL, oprRdRmRs)
  | 0b001u -> struct (Op.LSR, oprRdRmRs)
  | 0b011u -> struct (Op.ROR, oprRdRmRs)
  | _ -> struct (Op.MOV, oprRdRmShfRs)

/// Alias conditions on page F5-4562.
let changeToAliasOfMOVSRegShf bin =
  let s = pickBit bin 20u (* S *)
  let stype = extract bin 6u 5u (* stype *)
  match concat s stype 2 (* S:stype *) with
  | 0b110u -> struct (Op.ASRS, oprRdRmRs)
  | 0b100u -> struct (Op.LSLS, oprRdRmRs)
  | 0b101u -> struct (Op.LSRS, oprRdRmRs)
  | 0b111u -> struct (Op.RORS, oprRdRmRs)
  | _ -> struct (Op.MOVS, oprRdRmShfRs)

/// Logical Arithmetic (three register, register shift) on page F4-4230.
let parseLogicalArithThreeRegRegShf mode addr bin len cond =
  match extract bin 22u 20u (* opc:S *) with
  | 0b000u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.ORR None oprRdRnRmShfRs
  | 0b001u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.ORRS None oprRdRnRmShfRs
  | 0b010u ->
    chkPCRdRmRs bin
    let struct (opcode, oprFn) = changeToAliasOfMOVRegShf bin
    render mode addr bin len cond opcode None oprFn
  | 0b011u ->
    chkPCRdRmRs bin
    let struct (opcode, oprFn) = changeToAliasOfMOVSRegShf bin
    render mode addr bin len cond opcode None oprFn
  | 0b100u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.BIC None oprRdRnRmShfRs
  | 0b101u ->
    chkPCRdRnRmRs bin; render mode addr bin len cond Op.BICS None oprRdRnRmShfRs
  | 0b110u ->
    chkPCRdRmRs bin; render mode addr bin len cond Op.MVN None oprRdRmShfRs
  | _ (* 0b111u *) ->
    chkPCRdRmRs bin; render mode addr bin len cond  Op.MVNS None oprRdRmShfRs

/// Data-processing register (register shift) on page F4-4229.
let parseDataProcRegisterRegShf mode addr bin len cond =
  match concat (extract bin 24u 23u) (pickBit bin 20u) 1 (* op0:op1 *) with
  | 0b000u | 0b001u | 0b010u | 0b011u ->
    parseIntegerDataProcThreeRegRegShf mode addr bin len cond
  | 0b101u -> parseIntegerTestAndCompareTwoRegRegShf mode addr bin len cond
  | 0b110u | 0b111u -> parseLogicalArithThreeRegRegShf mode addr bin len cond
  | _ (* 0b100u *) -> Utils.impossible ()

let is0xxxx bin = bin &&& 0b10000u = 0b00000u
let is10xx0 bin = bin &&& 0b11001u = 0b10000u

let parseCase000 mode addr bin len cond =
  let op1 = extract bin 24u 20u
  match extract bin 7u 4u (* op2:op3:op4 *) with
  | 0b1011u | 0b1101u | 0b1111u -> parseExtraLoadStore mode addr bin len cond
  | 0b1001u when is0xxxx op1 -> parseMultiplyAndAccumlate mode addr bin len cond
  | 0b1001u (* op1 = 0b1xxxxu *) ->
    parseSyncAndLoadAcqStoreRel mode addr bin len cond
  | 0b0000u | 0b0010u | 0b0100u | 0b0110u | 0b0001u | 0b0011u | 0b0101u
  | 0b0111u when is10xx0 op1 -> parseMiscellaneous mode addr bin len cond
  | 0b1000u | 0b1010u | 0b1100u | 0b1110u when is10xx0 op1 ->
    parseHalfMulAndAccumulate mode addr bin len cond
  | 0b0000u | 0b0010u | 0b0100u | 0b0110u | 0b1000u | 0b1010u | 0b1100u
  | 0b1110u -> parseDataProcRegisterImmShf mode addr bin len cond
  | _ (* 0b0xx1u *) -> parseDataProcRegisterRegShf mode addr bin len cond

let parseIntDataProc0100 mode addr bin len cond =
  match extract bin 19u 16u with
  | 0b1101u -> render mode addr bin len cond Op.SUB None oprRdSPConst
  //| 0b1111u -> (* FIXME: Alias conditions on page F5-4310 *)
  //  render mode addr bin len cond Op.ADR None oprRdLabel
  | _ (* != 0b11x1u *) -> render mode addr bin len cond Op.SUB None oprRdRnConst

let parseIntDataProc0101 mode addr bin len cond =
  match extract bin 19u 16u with
  | 0b1101u -> render mode addr bin len cond Op.SUBS None oprRdSPConst
  | _ (* != 0b1101u *) ->
    render mode addr bin len cond Op.SUBS None oprRdRnConst

let parseIntDataProc1000 mode addr bin len cond =
  match extract bin 19u 16u with
  | 0b1101u -> render mode addr bin len cond Op.ADD None oprRdSPConst
  //| 0b1111u -> (* FIXME: Alias conditions on page F5-4310 *)
  //  render mode addr bin len cond Op.ADR None oprRdLabel
  | _ (* != 0b11x1u *) -> render mode addr bin len cond Op.ADD None oprRdRnConst

let parseIntDataProc1001 mode addr bin len cond =
  match extract bin 19u 16u with
  | 0b1101u -> render mode addr bin len cond Op.ADDS None oprRdSPConst
  | _ (* != 0b1101u *) ->
    render mode addr bin len cond Op.ADDS None oprRdRnConst

/// Integer Data Processing (two register and immediate) on page F4-4231.
let parseIntegerDataProcessing mode addr bin len cond =
  match extract bin 23u 20u (* opc:S *) with
  | 0b0000u -> render mode addr bin len cond Op.AND None oprRdRnConst
  | 0b0001u -> render mode addr bin len cond Op.ANDS None oprRdRnConstCF
  | 0b0010u -> render mode addr bin len cond Op.EOR None oprRdRnConst
  | 0b0011u -> render mode addr bin len cond Op.EORS None oprRdRnConstCF
  | 0b0100u -> parseIntDataProc0100 mode addr bin len cond
  | 0b0101u -> parseIntDataProc0101 mode addr bin len cond
  | 0b0110u -> render mode addr bin len cond Op.RSB None oprRdRnConst
  | 0b0111u -> render mode addr bin len cond Op.RSBS None oprRdRnConst
  | 0b1000u -> parseIntDataProc1000 mode addr bin len cond
  | 0b1001u -> parseIntDataProc1001 mode addr bin len cond
  | 0b1010u -> render mode addr bin len cond Op.ADC None oprRdRnConst
  | 0b1011u -> render mode addr bin len cond Op.ADCS None oprRdRnConst
  | 0b1100u -> render mode addr bin len cond Op.SBC None oprRdRnConst
  | 0b1101u -> render mode addr bin len cond Op.SBCS None oprRdRnConst
  | 0b1110u -> render mode addr bin len cond Op.RSC None oprRdRnConst
  | 0b1111u -> render mode addr bin len cond Op.RSCS None oprRdRnConst
  | _ (* 0b1111u *) -> render mode addr bin len cond Op.RSCS None oprRdRnConst

/// Move Halfword (immediate) on page F4-4232.
let parseMoveHalfword mode addr bin len cond =
  match pickBit bin 22u (* H *) with
  | 0b0u -> render mode addr bin len cond Op.MOVW None oprRdImm16
  | _ (* 0b1u *) -> render mode addr bin len cond Op.MOVT None oprRdImm16

let parseMovSpecReg00 mode addr bin len cond =
  match extract bin 5u 0u with
  | 0b000000u -> render mode addr bin len cond Op.NOP None oprNo
  | 0b000001u -> render mode addr bin len cond Op.YIELD None oprNo
  | 0b000010u -> render mode addr bin len cond Op.WFE None oprNo
  | 0b000011u -> render mode addr bin len cond Op.WFI None oprNo
  | 0b000100u -> render mode addr bin len cond Op.SEV None oprNo
  | 0b000101u -> render mode addr bin len cond Op.SEVL None oprNo (* AArch32 *)
  | 0b000110u | 0b000111u -> render mode addr bin len cond Op.NOP None oprNo
  | imm when imm &&& 0b111000u = 0b001000u (* 0b001xxx *) ->
    render mode addr bin len cond Op.NOP None oprNo
  | 0b010000u -> Utils.futureFeature ()
    /// render mode addr bin len cond Op.ESB None oprNo (* Armv8.2 *)
  | 0b010001u -> render mode addr bin len cond Op.NOP None oprNo
  | 0b010010u -> Utils.futureFeature ()
    /// render mode addr bin len cond Op.TSB None oprNo (* Armv8.4 *)
  | 0b010011u -> render mode addr bin len cond Op.NOP None oprNo
  | 0b010100u -> Utils.futureFeature ()
    /// render mode addr bin len cond Op.CSDB None oprNo (* AArch32 *)
  | 0b010101u -> render mode addr bin len cond Op.NOP None oprNo
  | imm when imm &&& 0b111000u = 0b011000u (* 0b011xxx *) ->
    render mode addr bin len cond Op.NOP None oprNo
  | imm when imm &&& 0b111110u = 0b011110u (* 0b01111x *) ->
    render mode addr bin len cond Op.NOP None oprNo
  | imm when imm &&& 0b100000u = 0b100000u (* 0b1xxxxx *) ->
    render mode addr bin len cond Op.NOP None oprNo
  | _ -> Utils.impossible ()

let parseMovSpecReg11 mode addr bin len cond =
  match extract bin 5u 4u with
  | 0b10u -> render mode addr bin len cond Op.NOP None oprNo
  | 0b11u -> render mode addr bin len cond Op.DBG None oprNo
  | _ (* 0b0xu *) -> render mode addr bin len cond Op.NOP None oprNo

/// Move Special Register and Hints (immediate) on page F4-4233.
let parseMoveSpecialRegisterAndHints mode addr bin len cond =
  let rimm4 = concat (pickBit bin 22u) (extract bin 19u 16u) 4
  match extract bin 7u 6u (* imm12<7:6> *) with
  | _ when rimm4 <> 0b00000u ->
    render mode addr bin len cond Op.MSR None oprSregImm
  | 0b00u -> parseMovSpecReg00 mode addr bin len cond
  | 0b01u -> render mode addr bin len cond Op.NOP None oprNo
  | 0b10u -> render mode addr bin len cond Op.NOP None oprNo
  | _ (* 0b11u *) -> parseMovSpecReg11 mode addr bin len cond

/// Integer Test and Compare (one register and immediate) on page F4-4233.
let parseIntegerTestAndCompareOneReg mode addr bin len cond =
  match extract bin 22u 21u (* opc *) with
  | 0b00u -> render mode addr bin len cond Op.TST None oprRnConstCF
  | 0b01u -> render mode addr bin len cond Op.TEQ None oprRnConstCF
  | 0b10u -> render mode addr bin len cond Op.CMP None oprRnConst
  | _ (* 0b11u *) -> render mode addr bin len cond Op.CMN None oprRnConst

let parseCase00110 mode addr bin len cond =
  match extract bin 21u 20u with
  | 0b00u -> parseMoveHalfword mode addr bin len cond
  | 0b10u -> parseMoveSpecialRegisterAndHints mode addr bin len cond
  | _ (* 0bx1u *) -> parseIntegerTestAndCompareOneReg mode addr bin len cond

/// Logical Arithmetic (two register and immediate) on page F4-4234.
let parseLogicalArithmetic mode addr bin len cond =
  match (extract bin 22u 20u) (* opc:S *) with
  | 0b000u -> render mode addr bin len cond Op.ORR None oprRdRnConst
  | 0b001u -> render mode addr bin len cond Op.ORRS None oprRdRnConstCF
  | 0b010u -> render mode addr bin len cond Op.MOV None oprRdConst
  | 0b011u -> render mode addr bin len cond Op.MOVS None oprRdConstCF
  | 0b100u -> render mode addr bin len cond Op.BIC None oprRdRnConst
  | 0b101u -> render mode addr bin len cond Op.BICS None oprRdRnConstCF
  | 0b110u -> render mode addr bin len cond Op.MVN None oprRdConst
  | _ (* 0b111u *) -> render mode addr bin len cond Op.MVNS None oprRdConstCF

/// Data-processing immediate on page F4-4231.
let parseCase001 mode addr bin len cond =
  match extract bin 24u 23u (* op0 *) with
  | 0b00u | 0b01u -> parseIntegerDataProcessing mode addr bin len cond
  | 0b10u -> parseCase00110 mode addr bin len cond
  | _ (* 0b11u *) -> parseLogicalArithmetic mode addr bin len cond

/// Data-processing and miscellaneous instructions on page F4-4218.
let parseCase00 mode addr bin len cond =
  match pickBit bin 25u (* op0 *) with
  | 0b0u -> parseCase000 mode addr bin len cond
  | _ (* 0b1u *) -> parseCase001 mode addr bin len cond

/// Load/Store Word, Unsigned Byte (immediate, literal) on page F4-4234.
let parseCase010 mode addr bin len cond =
  let pw = concat (pickBit bin 24u) (pickBit bin 21u) 1
  let o2o1 = concat (pickBit bin 22u) (pickBit bin 20u) 1
  let rn = extract bin 19u 16u
  match concat pw o2o1 2 with
  | 0b0000u ->
    chkPCRnRt bin; render mode addr bin len cond Op.STR None oprRtMemImm12
  | 0b0001u when rn = 0b1111u ->
    chkWback bin; render mode addr bin len cond Op.LDR None oprRtLabel
  | 0b0001u (* rn != 1111 *) ->
    chkRnRt bin; render mode addr bin len cond Op.LDR None oprRtMemImm12
  | 0b0010u -> chkPCRnRtWithWB bin
               render mode addr bin len cond Op.STRB None oprRtMemImm12
  | 0b0011u when rn = 0b1111u ->
    chkPCRtWithWB bin; render mode addr bin len cond Op.LDRB None oprRtLabel
  | 0b0011u (* rn != 1111 *) ->
    chkPCRtRnWithWB bin
    render mode addr bin len cond Op.LDRB None oprRtMemImm12
  | 0b0100u ->
    chkPCRnRt bin; render mode addr bin len cond Op.STRT None oprRtMemImm12
  | 0b0101u ->
    chkPCRtRnEq bin; render mode addr bin len cond Op.LDRT None oprRtMemImm12
  | 0b0110u ->
    chkPCRtRnEq bin; render mode addr bin len cond Op.STRBT None oprRtMemImm12
  | 0b0111u ->
    chkPCRtRnEq bin; render mode addr bin len cond Op.LDRBT None oprRtMemImm12
  | 0b1000u ->
    chkPCRnWithWB bin; render mode addr bin len cond Op.STR None oprRtMemImm12
  | 0b1001u when rn = 0b1111u ->
    chkWback bin; render mode addr bin len cond Op.LDR None oprRtLabel
  | 0b1001u (* rn != 1111 *) ->
    chkRnRt bin; render mode addr bin len cond Op.LDR None oprRtMemImm12
  | 0b1010u -> chkPCRnRtWithWB bin
               render mode addr bin len cond Op.STRB None oprRtMemImm12
  | 0b1011u when rn = 0b1111u ->
    chkPCRtWithWB bin; render mode addr bin len cond Op.LDRB None oprRtLabel
  | 0b1011u (* rn != 1111 *) ->
    chkPCRtRnWithWB bin
    render mode addr bin len cond Op.LDRB None oprRtMemImm12
  | 0b1100u ->
    chkPCRnRt bin; render mode addr bin len cond Op.STR None oprRtMemImm12
  | 0b1101u when rn = 0b1111u ->
    chkWback bin; render mode addr bin len cond Op.LDR None oprRtLabel
  | 0b1101u (* rn != 1111 *) ->
    chkRnRt bin; render mode addr bin len cond Op.LDR None oprRtMemImm12
  | 0b1110u -> chkPCRnRtWithWB bin
               render mode addr bin len cond Op.STRB None oprRtMemImm12
  | 0b1111u when rn = 0b1111u ->
    chkPCRtWithWB bin; render mode addr bin len cond Op.LDRB None oprRtLabel
  | _ (* 0b1111u  & rn != 1111 *) ->
    chkPCRtRnWithWB bin
    render mode addr bin len cond Op.LDRB None oprRtMemImm12

let parseCase0110 mode addr bin len cond =
  match concat (pickBit bin 22u) (extract bin 22u 20u) 3 (* P:o2:W:o1 *) with
  | 0b0000u ->
    chkPCRmRn bin; render mode addr bin len cond Op.STR None oprRtMemShfWithWB
  | 0b0001u ->
    chkPCRmRn bin; render mode addr bin len cond Op.LDR None oprRtMemShfWithWB
  | 0b0010u ->
    chkPCRnRm bin; render mode addr bin len cond Op.STRT None oprRtMemShf
  | 0b0011u ->
    chkPCRtRnRm bin; render mode addr bin len cond Op.LDRT None oprRtMemShf
  | 0b0100u ->
    chkPCRtRm bin; render mode addr bin len cond Op.STRB None oprRtMemShfWithWB
  | 0b0101u ->
    chkPCRtRm bin; render mode addr bin len cond Op.LDRB None oprRtMemShfWithWB
  | 0b0110u ->
    chkPCRtRnRm bin; render mode addr bin len cond Op.STRBT None oprRtMemShf
  | 0b0111u ->
    chkPCRtRnRm bin; render mode addr bin len cond Op.LDRBT None oprRtMemShf
  | 0b1000u | 0b1010u ->
    chkPCRmRn bin; render mode addr bin len cond Op.STR None oprRtMemShfWithWB
  | 0b1001u | 0b1011u ->
    chkPCRmRn bin; render mode addr bin len cond Op.LDR None oprRtMemShfWithWB
  | 0b1100u | 0b1110u ->
    chkPCRtRm bin; render mode addr bin len cond Op.STRB None oprRtMemShfWithWB
  | _ (*  0b11x1u *) ->
    chkPCRtRm bin; render mode addr bin len cond Op.LDRB None oprRtMemShfWithWB

/// Parallel Arithmetic on page F4-4237.
let parseParallelArith ctxt addr bin len cond =
  match concat (extract bin 22u 20u) (extract bin 7u 5u) 3 (* op1:B:op2 *) with
  | 0b000000u | 0b000001u | 0b000010u | 0b000111u | 0b000100u | 0b000101u
  | 0b000110u | 0b000111u (* 000xxx *) -> raise UnallocatedException
  | 0b001000u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.SADD16 None oprRdRnRm
  | 0b001001u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.SASX None oprRdRnRm
  | 0b001010u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.SSAX None oprRdRnRm
  | 0b001011u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.SSUB16 None oprRdRnRm
  | 0b001100u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.SADD8 None oprRdRnRm
  | 0b001101u -> raise UnallocatedException
  | 0b001110u -> raise UnallocatedException
  | 0b001111u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.SSUB8 None oprRdRnRm
  | 0b010000u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.QADD16 None oprRdRnRm
  | 0b010001u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.QASX None oprRdRnRm
  | 0b010010u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.QSAX None oprRdRnRm
  | 0b010011u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.QSUB16 None oprRdRnRm
  | 0b010100u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.QADD8 None oprRdRnRm
  | 0b010101u -> raise UnallocatedException
  | 0b010110u -> raise UnallocatedException
  | 0b010111u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.QSUB8 None oprRdRnRm
  | 0b011000u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.SHADD16 None oprRdRnRm
  | 0b011001u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.SHASX None oprRdRnRm
  | 0b011010u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.SHSAX None oprRdRnRm
  | 0b011011u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.SHSUB16 None oprRdRnRm
  | 0b011100u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.SHADD8 None oprRdRnRm
  | 0b011101u -> raise UnallocatedException
  | 0b011110u -> raise UnallocatedException
  | 0b011111u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.SHSUB8 None oprRdRnRm
  | 0b100000u | 0b100001u | 0b100010u | 0b100111u | 0b100100u | 0b100101u
  | 0b100110u | 0b100111u (* 100xxx *) -> raise UnallocatedException
  | 0b101000u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UADD16 None oprRdRnRm
  | 0b101001u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UASX None oprRdRnRm
  | 0b101010u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.USAX None oprRdRnRm
  | 0b101011u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.USUB16 None oprRdRnRm
  | 0b101100u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UADD8 None oprRdRnRm
  | 0b101101u -> raise UnallocatedException
  | 0b101110u -> raise UnallocatedException
  | 0b101111u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.USUB8 None oprRdRnRm
  | 0b110000u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UQADD16 None oprRdRnRm
  | 0b110001u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UQASX None oprRdRnRm
  | 0b110010u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UQSAX None oprRdRnRm
  | 0b110011u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UQSUB16 None oprRdRnRm
  | 0b110100u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UQADD8 None oprRdRnRm
  | 0b110101u -> raise UnallocatedException
  | 0b110110u -> raise UnallocatedException
  | 0b110111u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UQSUB8 None oprRdRnRm
  | 0b111000u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UHADD16 None oprRdRnRm
  | 0b111001u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UHASX None oprRdRnRm
  | 0b111010u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UHSAX None oprRdRnRm
  | 0b111011u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UHSUB16 None oprRdRnRm
  | 0b111100u ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UHADD8 None oprRdRnRm
  | 0b111101u -> raise UnallocatedException
  | 0b111110u -> raise UnallocatedException
  | _ (* 0b111111u *) ->
    chkPCRdOptRnRm bin; render ctxt addr bin len cond Op.UHSUB8 None oprRdRnRm

/// Saturate 16-bit on page F4-4239.
let parseSaturate16bit ctxt addr bin len cond =
  match pickBit bin 22u (* U *) with
  | 0b0u ->
    chkPCRdRn bin; render ctxt addr bin len cond Op.SSAT16 None oprRdImmRn
  | _ (* 0b1u *) ->
    chkPCRdRn bin; render ctxt addr bin len cond Op.USAT16 None oprRdImmRn

/// Reverse Bit/Byte on page F4-4240.
let parseReverseBitByte ctxt addr bin len cond =
  match concat (pickBit bin 22u) (pickBit bin 7u) 1 (* o1:o2 *) with
  | 0b00u -> chkPCRdRm bin; render ctxt addr bin len cond Op.REV None oprRdRm
  | 0b01u -> chkPCRdRm bin; render ctxt addr bin len cond Op.REV16 None oprRdRm
  | 0b10u -> chkPCRdRm bin; render ctxt addr bin len cond Op.RBIT None oprRdRm
  | _ (* 0b11u *) ->
    chkPCRdRm bin; render ctxt addr bin len cond Op.REVSH None oprRdRm

/// Saturate 32-bit on page F4-4240.
let parseSaturate32bit ctxt addr bin len cond =
  match pickBit bin 22u (* U *) with
  | 0b0u ->
    chkPCRdRn bin; render ctxt addr bin len cond Op.SSAT None oprRdImmRnShf
  | _ (* 0b1u *) ->
    chkPCRdRn bin; render ctxt addr bin len cond Op.USAT None oprRdImmRnShf

/// Extend and Add on page F4-4241.
let parseExtendAndAdd ctxt addr bin len cond =
  let isNotRn1111 bin = n bin <> 0b1111u (* Rn != 1111 *)
  match extract bin 22u 20u (* U:op *) with
  | 0b000u when isNotRn1111 bin ->
    chkPCRdRm bin; render ctxt addr bin len cond Op.SXTAB16 None oprRdRnRmROR
  | 0b000u ->
    chkPCRdRm bin; render ctxt addr bin len cond Op.SXTB16 None oprRdRmROR
  | 0b010u when isNotRn1111 bin ->
    chkPCRdRm bin; render ctxt addr bin len cond Op.SXTAB None oprRdRnRmROR
  | 0b010u ->
    chkPCRdRm bin; render ctxt addr bin len cond Op.SXTB None oprRdRmROR
  | 0b011u when isNotRn1111 bin ->
    chkPCRdRm bin; render ctxt addr bin len cond Op.SXTAH None oprRdRnRmROR
  | 0b011u ->
    chkPCRdRm bin; render ctxt addr bin len cond  Op.SXTH None oprRdRmROR
  | 0b100u when isNotRn1111 bin ->
    chkPCRdRm bin; render ctxt addr bin len cond Op.UXTAB16 None oprRdRnRmROR
  | 0b100u ->
    chkPCRdRm bin; render ctxt addr bin len cond Op.UXTB16 None oprRdRmROR
  | 0b110u when isNotRn1111 bin ->
    chkPCRdRm bin; render ctxt addr bin len cond Op.UXTAB None oprRdRnRmROR
  | 0b110u ->
    chkPCRdRm bin; render ctxt addr bin len cond Op.UXTB None oprRdRmROR
  | 0b111u when isNotRn1111 bin ->
    chkPCRdRm bin; render ctxt addr bin len cond Op.UXTAH None oprRdRnRmROR
  | _ (* 0b111u *) ->
    chkPCRdRm bin; render ctxt addr bin len cond Op.UXTH None oprRdRmROR

/// Signed multiply, Divide on page F4-4241.
let parseSignedMulDiv ctxt addr bin len cond =
  let isNotRa1111 bin = DGrB.a bin <> 0b1111u (* Ra != 1111 *)
  match concat (extract bin 22u 20u) (extract bin 7u 5u) 3 (* op1:op2 *) with
  | 0b000000u when isNotRa1111 bin ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.SMLAD None oprRdRnRmRa
  | 0b000001u when isNotRa1111 bin ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.SMLADX None oprRdRnRmRa
  | 0b000010u when isNotRa1111 bin ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.SMLSD None oprRdRnRmRa
  | 0b000011u when isNotRa1111 bin ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.SMLSDX None oprRdRnRmRa
  | 0b000100u | 0b000101u | 0b000110u | 0b000111u (* 0001xx *) ->
    raise UnallocatedException
  | 0b000000u ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.SMUAD None oprRdRnRmOpt
  | 0b000001u ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.SMUADX None oprRdRnRmOpt
  | 0b000010u ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.SMUSD None oprRdRnRmOpt
  | 0b000011u ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.SMUSDX None oprRdRnRmOpt
  | 0b001000u -> chkPCRdRnRmRaNot bin
                 render ctxt addr bin len cond Op.SDIV None oprRdRnRmOpt
  | 0b001001u | 0b001010u | 0b001011u | 0b001100u | 0b001101u | 0b001110u
  | 0b001111u (* 001 - != 000 *) -> raise UnallocatedException
  | 0b010000u | 0b010001u | 0b010010u | 0b010011u | 0b010100u | 0b010101u
  | 0b010110u | 0b010111u (* 010 - - *) -> raise UnallocatedException
  | 0b011000u -> chkPCRdRnRmRaNot bin
                 render ctxt addr bin len cond Op.UDIV None oprRdRnRmOpt
  | 0b011001u | 0b011010u | 0b011011u | 0b011100u | 0b011101u | 0b011110u
  | 0b011111u (* 001 - != 000 *) -> raise UnallocatedException
  | 0b100000u -> chkPCRdlRdhRnRm bin
                 render ctxt addr bin len cond Op.SMLALD None oprRdlRdhRnRm
  | 0b100001u -> chkPCRdlRdhRnRm bin
                 render ctxt addr bin len cond Op.SMLALDX None oprRdlRdhRnRm
  | 0b100010u -> chkPCRdlRdhRnRm bin
                 render ctxt addr bin len cond Op.SMLSLD None oprRdlRdhRnRm
  | 0b100011u -> chkPCRdlRdhRnRm bin
                 render ctxt addr bin len cond Op.SMLSLDX None oprRdlRdhRnRm
  | 0b100100u | 0b100101u | 0b100110u | 0b100111u (* 100 - 1xx *) ->
    raise UnallocatedException
  | 0b101000u when isNotRa1111 bin ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.SMMLA None oprRdRnRmRa
  | 0b101001u when isNotRa1111 bin ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.SMMLAR None oprRdRnRmRa
  | 0b101010u | 0b101011u (* 101 - 01x *) -> raise UnallocatedException
  | 0b101100u | 0b101101u (* 101 - 10x *) -> raise UnallocatedException
  | 0b101110u ->
    chkPCRdRnRmRa bin; render ctxt addr bin len cond Op.SMMLS None oprRdRnRmRa
  | 0b101111u ->
    chkPCRdRnRmRa bin; render ctxt addr bin len cond Op.SMMLSR None oprRdRnRmRa
  | 0b101000u ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.SMMUL None oprRdRnRmOpt
  | 0b101001u ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.SMMULR None oprRdRnRmOpt
  | _ (* 11x - - *) -> raise UnallocatedException

/// Unsigned Sum of Absolute Differences on page F4-4242.
let parseUnsignedSumOfAbsoluteDiff ctxt addr bin len cond =
  match extract bin 15u 12u (* Ra *) with
  | 0b1111u ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.USAD8 None oprRdRnRmOpt
  | _ (* != 1111 *) ->
    chkPCRdRnRm bin; render ctxt addr bin len cond Op.USADA8 None oprRdRnRmRa

/// Bitfield Insert on page F4-4243.
let parseBitfieldInsert ctxt addr bin len cond =
  match extract bin 3u 0u (* Rn *) with
  | 0b1111u ->
    chkPCRd bin; render ctxt addr bin len cond Op.BFC None oprRdLsbWidth
  | _ (* != 1111 *) ->
    chkPCRd bin; render ctxt addr bin len cond Op.BFI None oprRdRnLsbWidth

/// Permanently UNDEFINED on page F4-4243.
let parsePermanentlyUndef ctxt addr bin len cond =
  if cond <> Condition.AL then raise UnallocatedException
  else render ctxt addr bin len cond Op.UDF None oprImm16

/// Bitfield Extract on page F4-4244.
let parseBitfieldExtract ctxt addr bin len cond =
  match pickBit bin 22u (* U *) with
  | 0b0u ->
    chkPCRdRn bin; render ctxt addr bin len cond Op.SBFX None oprRdRnLsbWidthM1
  | _ (* 0b1u *) ->
    chkPCRdRn bin; render ctxt addr bin len cond Op.UBFX None oprRdRnLsbWidthM1

/// Media instructions on page F4-4236.
let parseCase0111 mode addr bin len cond =
  match concat (extract bin 24u 20u) (extract bin 7u 5u) 3 (* op0:op1 *) with
  | b when b &&& 0b11000000u = 0b00000000u (* 0b00xxxxxx *) ->
    parseParallelArith mode addr bin len cond
  | 0b01000101u ->
    chkPCRdOptRnRm bin; render mode addr bin len cond Op.SEL None oprRdRnRm
  | 0b01000001u -> raise UnallocatedException
  | 0b01000000u | 0b01000100u (* 01000x00 *) ->
    chkPCRdOptRnRm bin; render mode addr bin len cond Op.PKHBT None oprRdRnRm
  | 0b01000010u | 0b01000110u (* 01000x10 *) ->
    chkPCRdOptRnRm bin; render mode addr bin len cond Op.PKHTB None oprRdRnRm
  | 0b01001001u | 0b01001101u (* 01001x01 *) -> raise UnallocatedException
  | 0b01001000u | 0b01001010u | 0b01001100u | 0b01001110u (* 01001xx0 *) ->
    raise UnallocatedException
  | 0b01100001u | 0b01100101u | 0b01101001u | 0b01101101u (* 0110xx01 *) ->
    raise UnallocatedException
  | 0b01100000u | 0b01100010u | 0b01100100u | 0b01100110u | 0b01101000u
  | 0b01101010u | 0b01101100u | 0b01101110u (* 0110xxx0 *) ->
    raise UnallocatedException
  | 0b01010001u | 0b01110001u (* 01x10001 *) ->
    parseSaturate16bit mode addr bin len cond
  | 0b01010101u | 0b01110101u (* 01x10101 *) -> raise UnallocatedException
  | 0b01011001u | 0b01011101u | 0b01111001u | 0b01111101u (* 01x11x01 *) ->
    parseReverseBitByte mode addr bin len cond
  | 0b01010000u | 0b01010010u | 0b01010100u | 0b01010110u | 0b01011000u
  | 0b01011010u | 0b01011100u | 0b01011110u | 0b01110000u | 0b01110010u
  | 0b01110100u | 0b01110110u | 0b01111000u | 0b01111010u | 0b01111100u
  | 0b01111110u (* 01x1xxx0 *) -> parseSaturate32bit mode addr bin len cond
  | 0b01000111u | 0b01001111u | 0b01010111u | 0b01011111u | 0b01100111u
  | 0b01101111u | 0b01110111u | 0b01111111u (* 01xxx111 *) ->
    raise UnallocatedException
  | 0b01000011u | 0b01001011u | 0b01010011u | 0b01011011u | 0b01100011u
  | 0b01101011u | 0b01110011u | 0b01111011u (* 01xxx011 *) ->
    parseExtendAndAdd mode addr bin len cond
  | b when b &&& 0b11000000u = 0b10000000u (* 10xxxxxx *) ->
    parseSignedMulDiv mode addr bin len cond
  | 0b11000000u -> parseUnsignedSumOfAbsoluteDiff mode addr bin len cond
  | 0b11000100u -> raise UnallocatedException
  | 0b11001000u | 0b11001100u (* 11001x00 *) -> raise UnallocatedException
  | 0b11010000u | 0b11010100u | 0b11011000u | 0b11011100u (* 1101xx00 *) ->
    raise UnallocatedException
  | 0b11000111u | 0b11001111u | 0b11010111u | 0b11011111u (* 110xx111 *) ->
    raise UnallocatedException
  | 0b11100111u | 0b11101111u (* 1110x111 *) -> raise UnallocatedException
  | 0b11100000u | 0b11100100u | 0b11101000u | 0b11101100u (* 1110xx00 *) ->
    parseBitfieldInsert mode addr bin len cond
  | 0b11110111u -> raise UnallocatedException
  | 0b11111111u -> parsePermanentlyUndef mode addr bin len cond
  | 0b11110000u | 0b11110100u | 0b11111000u | 0b11111100u (* 1111xx00 *) ->
    raise UnallocatedException
  | 0b11000010u | 0b11000110u | 0b11001010u | 0b11001110u | 0b11100010u
  | 0b11100110u | 0b11101010u | 0b11101110u (* 11x0xx10 *) ->
    raise UnallocatedException
  | 0b11010010u | 0b11010110u | 0b11011010u | 0b11011110u | 0b11110010u
  | 0b11110110u | 0b11111010u | 0b11111110u (* 11x1xx10 *) ->
    parseBitfieldExtract mode addr bin len cond
  | 0b11000011u | 0b11001011u | 0b11010011u | 0b11011011u | 0b11100011u
  | 0b11101011u | 0b11110011u | 0b11111011u (* 11xxx011 *) ->
    raise UnallocatedException
  | b when b &&& 0b11000011u = 0b11000001u (* 11xxxx01 *) ->
    raise UnallocatedException
  | _ -> Utils.impossible ()

let parseCase011 mode addr bin len cond =
  match pickBit bin 4u with
  | 0b0u -> parseCase0110 mode addr bin len cond
  | _ (* 0b1u *) -> parseCase0111 mode addr bin len cond

let parseCase01 mode addr bin len cond =
  match pickBit bin 25u with
  | 0b0u -> parseCase010 mode addr bin len cond
  | _ (* 0b1u *) -> parseCase011 mode addr bin len cond

/// Exception Save/Restore on page F4-4244.
let parseExceptionSaveStore mode addr bin len cond =
  match concat (extract bin 24u 22u) (pickBit bin 20u) 1 (* P:U:S:L *) with
  | 0b0001u -> chkPCRn bin; render mode addr bin len cond Op.RFEDA None oprRn
  | 0b0010u -> render mode addr bin len cond Op.SRSDA None oprSPMode
  | 0b0101u -> chkPCRn bin; render mode addr bin len cond Op.RFEIA None oprRn
  | 0b0110u -> render mode addr bin len cond Op.SRSIA None oprSPMode
  | 0b1001u -> chkPCRn bin; render mode addr bin len cond Op.RFEDB None oprRn
  | 0b1010u -> render mode addr bin len cond Op.SRSDB None oprSPMode
  | 0b1101u -> chkPCRn bin; render mode addr bin len cond Op.RFEIB None oprRn
  | 0b1110u -> render mode addr bin len cond Op.SRSIB None oprSPMode
  | _ (* 0b--00u or 0b--11u *) -> raise UnallocatedException

/// shared/functions/common/BitCount on page J1-7845.
let bitCount bin =
  let regList = extract bin 15u 0u
  let rec loop cnt idx =
    if idx > 15 then cnt
    elif ((regList >>> idx) &&& 0b1u) = 1u then loop (cnt + 1) (idx + 1)
    else loop cnt (idx + 1)
  loop 0 0

/// Alias conditions on page F5-4438.
let changeToAliasOfLDM bin =
  if (wbackW bin) && (n bin = 0b1101u) && (bitCount bin > 1) then
    struct (Op.POP, oprRegs)
  else struct (Op.LDM, oprRnRegs)

/// Load/Store Multiple on page F4-4245.
let parseLoadStoreMultiple mode addr bin len cond =
  match concat (extract bin 24u 22u) (pickBit bin 20u) 1 (* P:U:op:L *) with
  | 0b0000u ->
    chkPCRnRegs bin; render mode addr bin len cond Op.STMDA None oprRnRegs
  | 0b0001u ->
    chkWBRegs bin; render mode addr bin len cond Op.LDMDA None oprRnRegs
  | 0b0100u ->
    chkPCRnRegs bin; render mode addr bin len cond Op.STM None oprRnRegs
  | 0b0101u ->
    chkWBRegs bin
    let struct (opcode, oprFn) = changeToAliasOfLDM bin
    render mode addr bin len cond opcode None oprFn
  | 0b0010u ->
    chkPCRnRegs bin; render mode addr bin len cond Op.STMDA None oprRnRegsCaret
  | 0b0110u ->
    chkPCRnRegs bin; render mode addr bin len cond Op.STMIA None oprRnRegsCaret
  | 0b1010u ->
    chkPCRnRegs bin; render mode addr bin len cond Op.STMDB None oprRnRegsCaret
  | 0b1110u ->
    chkPCRnRegs bin; render mode addr bin len cond Op.STMIB None oprRnRegsCaret
  | 0b1000u ->
    chkPCRnRegs bin; render mode addr bin len cond Op.STMDB None oprRnRegs
  | 0b1001u ->
    chkWBRegs bin; render mode addr bin len cond Op.LDMDB None oprRnRegs
  | 0b0011u ->
    (* 0xxxxxxxxxxxxxxx LDM (User registers) *)
    if pickBit bin 15u = 0u then
      chkPCRnRegs bin
      render mode addr bin len cond Op.LDMDA None oprRnRegsCaret
    else (* 1xxxxxxxxxxxxxxx LDM (exception return) *)
      chkWBRegs bin; render mode addr bin len cond Op.LDMDA None oprRnRegsCaret
  | 0b0111u ->
    if pickBit bin 15u = 0u then
      chkPCRnRegs bin; render mode addr bin len cond Op.LDM None oprRnRegsCaret
    else chkWBRegs bin; render mode addr bin len cond Op.LDM None oprRnRegsCaret
  | 0b1011u ->
    if pickBit bin 15u = 0u then
      chkPCRnRegs bin
      render mode addr bin len cond Op.LDMDB None oprRnRegsCaret
    else
      chkWBRegs bin; render mode addr bin len cond Op.LDMDB None oprRnRegsCaret
  | 0b1111u ->
    if pickBit bin 15u = 0u then
      chkPCRnRegs bin
      render mode addr bin len cond Op.LDMIB None oprRnRegsCaret
    else
      chkWBRegs bin; render mode addr bin len cond Op.LDMIB None oprRnRegsCaret
  | 0b1100u ->
    chkPCRnRegs bin; render mode addr bin len cond Op.STMIB None oprRnRegs
  | _ (* 0b1101u *) ->
    chkWBRegs bin; render mode addr bin len cond Op.LDMIB None oprRnRegs

let parseCase100 mode addr bin len cond =
  match cond with
  | Condition.UN (* 0b1111u *) -> parseExceptionSaveStore mode addr bin len cond
  | _ (* != 0b1111u *) -> parseLoadStoreMultiple mode addr bin len cond

/// Branch (immediate) on page F4-4246.
let parseCase101 mode addr bin len cond =
  match cond with
  | Condition.UN (* 0b1111u *) ->
    render mode addr bin len cond Op.BLX None oprLabelH
  | _ (* != 0b1111u *) ->
    if pickBit bin 24u (* H *) = 0u then
      render mode addr bin len cond Op.B None oprLabel
    else render mode addr bin len cond Op.BL None oprLabel

/// Branch, branch with link, and block data transfer on page F4-4244.
let parseCase10 mode addr bin len cond =
  match pickBit bin 25u (* op0 *) with
  | 0b0u -> parseCase100 mode addr bin len cond
  | _ (* 0b1u *) -> parseCase101 mode addr bin len cond

/// Supervisor call on page F4-4247.
let parseSupervisorCall mode addr bin len cond =
  if cond = Condition.UN then raise UnallocatedException
  else render mode addr bin len cond Op.SVC None oprImm24

/// Advanced SIMD three registers of the same length extension on page F4-4248.
let parseAdvSIMDThreeRegSameLenExt mode addr bin len cond =
  Utils.futureFeature () // ARMv8
  (*
  let op1 = extract bin 24u 23u
  let op2 = extract bin 21u 20u
  let op3 = pickBit bin 10u
  let op4 = pickBit bin 8u
  let q = pickBit bin 6u
  let u = pickBit bin 4u
  let op1op2opo3op4QU =
    concat (concat (concat (concat (concat (extract bin 24u 23u)
      (extract bin 21u 20u) 2) (pickBit bin 10u) 1) (pickBit bin 8u) 1)
        (pickBit bin 6u) 1) (pickBit bin 4u) 1
  match op1op2opo3op4QU (* op1:op2:op3:op4:Q:U *) with
  | 0b01000000u | 0b01010000u | 0b11000000u | 0b11010000u ->
    Op.VCADD - 64-bit SIMD vector variant (* Armv8.3 *)
  | 0bx10x0001u -> raise UnallocatedException
  | 0bx10x0010u -> VCADD - 128-bit SIMD vector variant Armv8.3
  | 0bx10x0011u -> raise UnallocatedException
  | 0b000x00xxu -> raise UnallocatedException
  | 0b000x01xxu -> raise UnallocatedException
  | 0b00001000u -> raise UnallocatedException
  | 0b00001001u -> raise UnallocatedException
  | 0b00001010u -> VMMLA Armv8.6
  | 0b00001011u -> raise UnallocatedException
  | 0b00001100u -> VDOT (vector) - 64-bit SIMD vector variant Armv8.6
  | 0b00001101u -> raise UnallocatedException
  | 0b00001110u -> VDOT (vector) - 128-bit SIMD vector variant Armv8.6
  | 0b00001111u -> raise UnallocatedException
  | 0b000110xxu -> raise UnallocatedException
  | 0b000111xxu -> raise UnallocatedException
  | 0b001000x1u -> VFMAL (vector) Armv8.2
  | 0b001001xxu -> raise UnallocatedException
  | 0b0010100xu -> raise UnallocatedException
  | 0b00101010u -> VSMMLA Armv8.6
  | 0b00101011u -> VUMMLA Armv8.6
  | 0b00101100u -> VSDOT (vector) - 64-bit SIMD vector variant Armv8.2
  | 0b00101101u -> VUDOT (vector) - 64-bit SIMD vector variant Armv8.2
  | 0b00101110u -> VSDOT (vector) - 128-bit SIMD vector variant Armv8.2
  | 0b00101111u -> VUDOT (vector) - 128-bit SIMD vector variant Armv8.2
  | 0b001100x1u -> VFMAB, VFMAT (BFloat16, vector) Armv8.6
  | 0b001101xxu -> raise UnallocatedException
  | 0b001110xxu -> raise UnallocatedException
  | 0b001111xxu -> raise UnallocatedException
  | 0b011000x1u -> VFMSL (vector) Armv8.2
  | 0b011001xxu -> raise UnallocatedException
  | 0b0110100xu -> raise UnallocatedException
  | 0b01101010u -> VUSMMLA Armv8.6
  | 0b01101011u -> raise UnallocatedException
  | 0b01101100u -> VUSDOT (vector) - 64-bit SIMD vector variant Armv8.6
  | 0b011011x1u -> raise UnallocatedException
  | 0b01101110u -> VUSDOT (vector) - 128-bit SIMD vector variant Armv8.6
  | 0b011101xxu -> raise UnallocatedException
  | 0b011110xxu -> raise UnallocatedException
  | 0b011111xxu -> raise UnallocatedException
  | 0bxx1x00x0u -> VCMLA Armv8.3
  | 0b101101xxu -> raise UnallocatedException
  | 0b101110xxu -> raise UnallocatedException
  | 0b101111xxu -> raise UnallocatedException
  | 0b111101xxu -> raise UnallocatedException
  | 0b111110xxu -> raise UnallocatedException
  | 0b111111xxu -> raise UnallocatedException
  *)

/// Floating-point minNum/maxNum on page F4-4250.
let parseFloatingPointMinMaxNum mode addr bin len cond =
  match pickBit bin 6u (* op *) with
  | 0b0u -> Utils.futureFeature () // ARMv8
  | _ (* 0b1u *) -> Utils.futureFeature () // ARMv8

/// Floating-point extraction and insertion on page F4-4250.
let parseFloatingPointExtractionAndInsertion mode addr bin len cond =
  Utils.futureFeature () // ARMv8.2

/// Floating-point directed convert to integer on page F4-4250.
let parseFloatingPointDirectedConvertToInteger mode addr bin len cond =
  Utils.futureFeature () // ARMv8
  (*
  match extract bin 18u 16u (* o1:RM *) with
  | 0b000u -> Op.VRINTA
  | 0b001u -> Op.VRINTN
  | 0b010u -> Op.VRINTP
  | 0b011u -> Op.VRINTM
  | 0b100u -> Op.VCVTA
  | 0b101u -> Op.VCVTN
  | 0b110u -> Op.VCVTP
  | _ (* 111 *) -> Op.VCVTM
  *)

/// Advanced SIMD and floating-point multiply with accumulate on page F4-4251.
let parseAdvSIMDAndFPMulWithAccumulate mode addr bin len cond =
  Utils.futureFeature () // ARMv8.2, ARMv8.3, ARMv8.6

/// Advanced SIMD and floating-point dot product on page F4-4252.
let parseAdvSIMDAndFPDotProduct mode addr bin len cond =
  Utils.futureFeature () // ARMv8.2, ARMv8.6

/// Unconditional Advanced SIMD and floating-point instructions on page F4-4247.
let parseUncondAdvSIMDAndFPInstr mode addr bin len cond =
  let op0op2op3op4op5 = (* op0:op2:op3:op4:op5 *)
    concat (concat (concat (extract bin 25u 23u) (extract bin 10u 8u) 3)
           (pickBit bin 6u) 1) (pickBit bin 4u) 1
  let is00xxxx bin = (extract bin 21u 16u) &&& 0b110000u = 0b000000u
  let is110000 bin = extract bin 21u 16u = 0b110000u
  let is111xxx bin = (extract bin 21u 16u) &&& 0b111000u = 0b111000u
  match op0op2op3op4op5 with
  | b when b &&& 0b10001000u = 0b00000000u ->
    parseAdvSIMDThreeRegSameLenExt mode addr bin len cond
  //| 0b10000100u | 0b10001000u | 0b10001100u ->
  //  Op.VSELEQ, Op.VSELGE, Op.VSELGT, Op.VSELVS
  | 0b10100100u | 0b10101000u | 0b10101100u | 0b10100110u | 0b10101010u
  | 0b10101110u when is00xxxx bin ->
    parseFloatingPointMinMaxNum mode addr bin len cond
  | 0b10100110u | 0b10101010u | 0b10101110u when is110000 bin ->
    parseFloatingPointExtractionAndInsertion mode addr bin len cond
  | 0b10100110u | 0b10101010u | 0b10101110u when is111xxx bin ->
    parseFloatingPointDirectedConvertToInteger mode addr bin len cond
  | 0b10000000u | 0b10000001u | 0b10000010u | 0b10000011u | 0b10100000u
  | 0b10100001u | 0b10100010u | 0b10100011u ->
    parseAdvSIMDAndFPMulWithAccumulate mode addr bin len cond
  | b when b &&& 0b11011000u = 0b10010000u ->
    parseAdvSIMDAndFPDotProduct mode addr bin len cond
  | _ -> Utils.impossible ()

/// Advanced SIMD and floating-point 64-bit move on page F4-4253.
let parseAdvancedSIMDandFP64bitMove mode addr bin len cond =
  let decodeFields (* D:op:size:opc2:o3 *) =
    concat (concat (concat (pickBit bin 22u) (pickBit bin 20u) 1)
      (extract bin 9u 6u) 4) (pickBit bin 4u) 1
  match decodeFields (* D:op:size:opc2:o3 *) with
  | 0b1010001u ->
    chkPCRtRt2VmEq bin; render mode addr bin len cond Op.VMOV None oprSmSm1RtRt2
  | 0b1011001u ->
    chkPCRtRt2ArmEq bin; render mode addr bin len cond Op.VMOV None oprDmRtRt2
  | 0b1110001u ->
    chkPCRtRt2VmEq bin; render mode addr bin len cond Op.VMOV None oprRtRt2SmSm1
  | 0b1111001u ->
    chkPCRtRt2ArmEq bin; render mode addr bin len cond Op.VMOV None oprRtRt2Dm
  | _ (* 0xxxxxx 1xxxxx0  1x0x001 1xxx01x 1xxx1xx *) ->
    raise UnallocatedException

/// System register 64-bit move on page F4-4254.
let parseSystemReg64bitMove mode addr bin len cond =
  match concat (pickBit bin 22u) (pickBit bin 20u) 1 (* D:L *) with
  | 0b00u | 0b01u -> raise UnallocatedException
  | 0b10u ->
    chkPCRtRt2 bin; render mode addr bin len cond Op.MCRR None oprCpOpc1RtRt2CRm
  | _ (* 0b11u *) ->
    chkPCRtRt2Eq bin
    render mode addr bin len cond Op.MRRC None oprCpOpc1RtRt2CRm

/// Advanced SIMD and floating-point load/store on page F4-4254.
let parseAdvSIMDAndFPLdSt mode addr bin len cond =
  let decodeFields = concat (concat (extract bin 24u 23u)
                      (extract bin 21u 20u) 2) (extract bin 9u 8u) 2
  let isxxxxxxx0 bin = pickBit bin 0u = 0u
  //let isxxxxxxx1 bin = pickBit bin 1u = 1u
  let isRn1111 bin = extract bin 19u 16u = 0b1111u
  match decodeFields (* P:U:W:L:size *) with
  | 0b001000u | 0b001001u | 0b001010u | 0b001011u | 0b001100u | 0b001101u
  | 0b001110u | 0b001111u (* 001xxx *) -> raise UnallocatedException
  | 0b010000u | 0b010001u | 0b010100u | 0b011000u | 0b011000u | 0b011001u
  | 0b011100u | 0b011101u (* 01xx0x *) -> raise UnallocatedException
  | 0b010010u | 0b011010u ->
    chkPCRnDRegs bin; render mode addr bin len cond Op.VSTMIA None oprRnSreglist
  | 0b010011u | 0b011011u when isxxxxxxx0 bin ->
    chkPCRnRegsImm bin
    render mode addr bin len cond Op.VSTMIA None oprRnDreglist
  //| 0b010011u | 0b011011u (* 01x011 *) when isxxxxxxx1 bin -> Op.FSTMIAX
  | 0b010110u | 0b011110u ->
    chkPCRnDRegs bin
    render mode addr bin len cond Op.VLDMIA None oprRnSreglist
  | 0b010111u | 0b011111u when isxxxxxxx0 bin ->
    chkPCRnRegsImm bin
    render mode addr bin len cond Op.VLDMIA None oprRnDreglist
  //| 0b010111u | 0b011111u (* 01x111 *) when isxxxxxxx1 bin -> Op.FLDIAX
  | 0b100000u | 0b110000u -> raise UndefinedException
  | 0b100001u | 0b110001u | 0b100010u | 0b110010u ->
    chkSzCondPCRn bin cond; render mode addr bin len cond Op.VSTR None oprSdMem
  | 0b100011u | 0b110011u ->
    chkSzCondPCRn bin cond; render mode addr bin len cond Op.VSTR None oprDdMem
  | 0b100100u | 0b110100u when cond <> Condition.UN -> raise UndefinedException
  | 0b100101u | 0b110101u | 0b100110u | 0b110110u when cond <> Condition.UN ->
    chkSzCond bin cond; render mode addr bin len cond Op.VLDR None oprSdMem
  | 0b100111u | 0b110111u when cond <> Condition.UN ->
    chkSzCond bin cond; render mode addr bin len cond Op.VLDR None oprDdMem
  | 0b101000u | 0b101001u | 0b101100u | 0b101101u ->
    raise UnallocatedException
  | 0b101010u ->
    chkPCRnDRegs bin; render mode addr bin len cond Op.VSTMDB None oprRnSreglist
  | 0b101011u when isxxxxxxx0 bin ->
    chkPCRnRegsImm bin
    render mode addr bin len cond Op.VSTMDB None oprRnDreglist
  //| 0b101011u xxxxxxx1 FSTMDBX - Decrement Before variant on page F6-5006
  | 0b101110u ->
    chkPCRnDRegs bin; render mode addr bin len cond Op.VLDMDB None oprRnSreglist
  | 0b101111u when isxxxxxxx0 bin ->
    chkPCRnRegsImm bin
    render mode addr bin len cond Op.VLDMDB None oprRnDreglist
  //| 0b101111u xxxxxxx1 FLDMDBX - Decrement Before variant on page F6-5003
  | 0b100100u | 0b110100u when isRn1111 bin -> raise UndefinedException
  | 0b100101u | 0b110101u | 0b100110u | 0b110110u when isRn1111 bin ->
    chkSzCond bin cond; render mode addr bin len cond Op.VLDR None oprSdLabel
  | 0b100111u | 0b110111u when isRn1111 bin ->
    chkSzCond bin cond; render mode addr bin len cond Op.VLDR None oprDdLabel
  | 0b111000u | 0b111001u | 0b111010u | 0b111011u | 0b111100u | 0b111101u
  | 0b111110u | 0b111111u -> raise UnallocatedException
  | _ -> Utils.impossible ()

/// System register load/store on page F4-4255.
let parseSysRegisterLdSt mode addr bin len cond =
  let isNotRn1111 bin = extract bin 19u 16u <> 0b1111u
  let isCRd0101 bin = (extract bin 15u 12u) = 0b0101u
  let puw = concat (extract bin 24u 23u) (pickBit bin 21u) 1 (* P:U:W *)
  let dL = concat (pickBit bin 22u) (pickBit bin 20u) 1 (* D:L *)
  let cRdCp15 = concat (extract bin 15u 12u) (pickBit bin 8u) 1 (* CRd:cp15 *)
  match concat dL (pickBit bin 8u) 1 (* D:L:cp15 *) with
  | 0b000u | 0b001u | 0b010u | 0b011u (* 0b0xxu *)
    when puw <> 0b000u && not (isCRd0101 bin) -> raise UnallocatedException
  | 0b010u when puw <> 0b000u && isNotRn1111 bin |> not && isCRd0101 bin ->
    chkWP bin; render mode addr bin len cond Op.LDC None oprP14C5Label
  | 0b001u | 0b011u | 0b101u | 0b111u (* 0bxx1u *) when puw <> 0b000u ->
    raise UnallocatedException
  | 0b100u | 0b110u (* 0b1x0u *) when puw <> 0b000u && isCRd0101 bin ->
    raise UnallocatedException
  | _ ->
    match concat (concat puw dL 2) cRdCp15 5 (* P:U:W:D:L:CRd:cp15 *) with
    | 0b0010001010u | 0b0110001010u ->
      chkPCRnWback bin; render mode addr bin len cond Op.STC None oprP14C5Mem
    | 0b0010101010u | 0b0110101010u when isNotRn1111 bin ->
      render mode addr bin len cond Op.LDC None oprP14C5Mem
    | 0b0100001010u ->
      chkPCRnWback bin; render mode addr bin len cond Op.STC None oprP14C5Option
    | 0b0100101010u when isNotRn1111 bin ->
      render mode addr bin len cond Op.LDC None oprP14C5Option
    | 0b1000001010u | 0b1100001010u ->
      chkPCRnWback bin; render mode addr bin len cond Op.STC None oprP14C5Mem
    | 0b1000101010u | 0b1100101010u when isNotRn1111 bin ->
      render mode addr bin len cond Op.LDC None oprP14C5Mem
    | 0b1010001010u | 0b1110001010u ->
      chkPCRnWback bin; render mode addr bin len cond Op.STC None oprP14C5Mem
    | 0b1010101010u | 0b1110101010u when isNotRn1111 bin ->
      render mode addr bin len cond Op.LDC None oprP14C5Mem
    | _ -> Utils.impossible ()

/// Advanced SIMD and System register load/store and 64-bit move
/// on page F4-4252.
let parseAdvSIMDAndSysRegLdStAnd64bitMove mode addr bin len cond =
  let is00x0 bin = (extract bin 24u 21u (* op0 *)) &&& 0b1101u = 0b0000u
  match extract bin 10u 9u (* op1 *) with
  | 0b00u | 0b01u when is00x0 bin ->
    parseAdvancedSIMDandFP64bitMove mode addr bin len cond
  | 0b11u when is00x0 bin -> parseSystemReg64bitMove mode addr bin len cond
  | 0b00u | 0b01u -> parseAdvSIMDAndFPLdSt mode addr bin len cond
  | 0b11u -> parseSysRegisterLdSt mode addr bin len cond
  | _ (* 10 *) -> raise UnallocatedException

/// Floating-point data-processing (two registers) on page F4-4256.
let parseFPDataProcTwoRegs mode addr bin len cond =
  let decodeFields =
    concat (extract bin 19u 16u) (extract bin 9u 7u) 3 (* o1:opc2:size:o3 *)
  match decodeFields (* o1:opc2:size:o3 *) with
  | b when b &&& 0b0000110u = 0b0000000u (* xxxx00x *) ->
    raise UnallocatedException
  | 0b0000010u -> raise UnallocatedException
  (* 0000xx1 VABS *)
  | 0b0000001u -> raise UndefinedException
  | 0b0000011u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VABS (oneDt SIMDTypF16) oprSdSm
  | 0b0000101u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VABS (oneDt SIMDTypF32) oprSdSm
  | 0b0000111u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VABS (oneDt SIMDTypF64) oprDdDm
  (* 00001x0 VMOV *)
  | 0b0000100u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypF32) oprSdSm
  | 0b0000110u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypF64) oprDdDm
  (* 0001xx0 VNEG *)
  | 0b0001000u -> raise UndefinedException
  | 0b0001010u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VNEG (oneDt SIMDTypF16) oprSdSm
  | 0b0001100u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VNEG (oneDt SIMDTypF32) oprSdSm
  | 0b0001110u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VNEG (oneDt SIMDTypF64) oprDdDm
  (* 0001xx1 VSQRT *)
  | 0b0001001u -> raise UndefinedException
  | 0b0001011u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VSQRT (oneDt SIMDTypF16) oprSdSm
  | 0b0001101u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VSQRT (oneDt SIMDTypF32) oprSdSm
  | 0b0001111u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VSQRT (oneDt SIMDTypF64) oprDdDm
  (* 0010xx0 VCVTB *)
  //| 0b0010000u -> Op.VCVTB
  | 0b0010100u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render mode addr bin len cond Op.VCVTB dt oprSdSm
  | 0b0010110u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF16)
    render mode addr bin len cond Op.VCVTB dt oprDdSm
  | 0b0010010u | 0b0010011u (* 001001x *) -> raise UnallocatedException
  (* 0010xx1 VCVTT *)
  | 0b0010101u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render mode addr bin len cond Op.VCVTT dt oprSdSm
  | 0b0010111u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF16)
    render mode addr bin len cond Op.VCVTT dt oprDdSm
  //| 0b0011010u -> VCVTB    Armv8.6
  //| 0b0011011u -> VCVTT    Armv8.6
  | 0b0011100u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render mode addr bin len cond Op.VCVTB dt oprSdSm
  | 0b0011101u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render mode addr bin len cond Op.VCVTT dt oprSdSm
  | 0b0011110u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF64)
    render mode addr bin len cond Op.VCVTB dt oprSdDm
  | 0b0011111u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF64)
    render mode addr bin len cond Op.VCVTT dt oprSdDm
  (* 0100xx0 VCMP *)
  | 0b0100000u -> raise UndefinedException
  | 0b0100010u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VCMP (oneDt SIMDTypF16) oprSdSm
  | 0b0100100u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VCMP (oneDt SIMDTypF32) oprSdSm
  | 0b0100110u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VCMP (oneDt SIMDTypF64) oprDdDm
  (* 0100xx1 VCMPE *)
  | 0b0100001u -> raise UndefinedException
  | 0b0100011u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VCMPE (oneDt SIMDTypF16) oprSdSm
  | 0b0100101u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VCMPE (oneDt SIMDTypF32) oprSdSm
  | 0b0100111u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VCMPE (oneDt SIMDTypF64) oprDdDm
  (* 0101xx0 VCMP *)
  | 0b0101000u -> raise UndefinedException
  | 0b0101010u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VCMP (oneDt SIMDTypF16) oprSdImm0
  | 0b0101100u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VCMP (oneDt SIMDTypF32) oprSdImm0
  | 0b0101110u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VCMP (oneDt SIMDTypF64) oprDdImm0
  (* 0101xx1 VCMPE *)
  | 0b0101001u -> raise UndefinedException
  | 0b0101011u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VCMPE (oneDt SIMDTypF16) oprSdImm0
  | 0b0101101u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VCMPE (oneDt SIMDTypF32) oprSdImm0
  | 0b0101111u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VCMPE (oneDt SIMDTypF64) oprDdImm0
  //| 0b0110xx0u -> Op.VRINTR    ARMv8
  (* 0110xx1 VRINTZ ARMv8 *)
  | 0b0110001u -> raise UndefinedException
  | 0b0110011u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VRINTZ (oneDt SIMDTypF16) oprSdSm
  | 0b0110101u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VRINTZ (oneDt SIMDTypF32) oprSdSm
  | 0b0110111u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VRINTZ (oneDt SIMDTypF64) oprDdDm
  (* 0111xx0 VRINTX ARMv8 *)
  | 0b0111000u -> raise UndefinedException
  | 0b0111010u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VRINTX (oneDt SIMDTypF16) oprSdSm
  | 0b0111100u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VRINTX (oneDt SIMDTypF32) oprSdSm
  | 0b0111110u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VRINTX (oneDt SIMDTypF64) oprDdDm
  | 0b0111011u -> raise UnallocatedException
  | 0b0111101u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF32)
    render mode addr bin len cond Op.VCVT dt oprDdSm
  | 0b0111111u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF64)
    render mode addr bin len cond Op.VCVT dt oprSdDm
  (* 1000xxx VCVT *)
  | 0b1000000u | 0b1000001u -> raise UndefinedException
  | 0b1000010u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF16, SIMDTypU32)
    render mode addr bin len cond Op.VCVT dt oprSdSm
  | 0b1000011u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF16, SIMDTypS32)
    render mode addr bin len cond Op.VCVT dt oprSdSm
  | 0b1000100u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render mode addr bin len cond Op.VCVT dt oprSdSm
  | 0b1000101u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render mode addr bin len cond Op.VCVT dt oprSdSm
  | 0b1000110u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF64, SIMDTypU32)
    render mode addr bin len cond Op.VCVT dt oprDdSm
  | 0b1000111u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF64, SIMDTypS32)
    render mode addr bin len cond Op.VCVT dt oprDdSm
  | 0b1001010u | 0b1001011u (* 100101x *) -> raise UnallocatedException
  | 0b1001100u | 0b1001101u (* 100110x *) -> raise UnallocatedException
  | 0b1001110u -> raise UnallocatedException
  //| 0b1001111u -> VJCVT    Armv8.3
  (* 101xxxx Op.VCVT *)
  | 0b1010000u | 0b1010001u | 0b1011000u | 0b1011001u ->
    raise UndefinedException
  | 0b1010010u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF16, SIMDTypS16)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1010011u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF16, SIMDTypS32)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1011010u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF16, SIMDTypU16)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1011011u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF16, SIMDTypU32)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1010100u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF32, SIMDTypS16)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1010101u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1011100u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF32, SIMDTypU16)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1011101u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1010110u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF64, SIMDTypS16)
    render mode addr bin len cond Op.VCVT dt oprDdmDdmFbits
  | 0b1010111u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF64, SIMDTypS32)
    render mode addr bin len cond Op.VCVT dt oprDdmDdmFbits
  | 0b1011110u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF64, SIMDTypU16)
    render mode addr bin len cond Op.VCVT dt oprDdmDdmFbits
  | 0b1011111u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypF64, SIMDTypU32)
    render mode addr bin len cond Op.VCVT dt oprDdmDdmFbits
  (* 1100xx0 VCVTR *)
  | 0b1100000u -> raise UndefinedException
  | 0b1100010u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render mode addr bin len cond Op.VCVTR dt oprSdSm
  | 0b1100100u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render mode addr bin len cond Op.VCVTR dt oprSdSm
  | 0b1100110u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render mode addr bin len cond Op.VCVTR dt oprSdDm
  (* 1100xx1 VCVT *)
  | 0b1100001u -> raise UndefinedException
  | 0b1100011u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render mode addr bin len cond Op.VCVT dt oprSdSm
  | 0b1100101u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render mode addr bin len cond Op.VCVT dt oprSdSm
  | 0b1100111u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render mode addr bin len cond Op.VCVT dt oprSdDm
  (* 1101xx0 VCVTR *)
  | 0b1101000u -> raise UndefinedException
  | 0b1101010u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render mode addr bin len cond Op.VCVTR dt oprSdSm
  | 0b1101100u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render mode addr bin len cond Op.VCVTR dt oprSdSm
  | 0b1101110u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render mode addr bin len cond Op.VCVTR dt oprSdDm
  (* 1101xx1u VCVT *)
  | 0b1101001u -> raise UndefinedException
  | 0b1101011u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render mode addr bin len cond Op.VCVT dt oprSdSm
  | 0b1101101u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render mode addr bin len cond Op.VCVT dt oprSdSm
  | 0b1101111u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render mode addr bin len cond Op.VCVT dt oprSdDm
  (* 111xxxx VCVT *)
  | 0b1110000u | 0b1110001u | 0b1111000u | 0b1111001u ->
    raise UndefinedException
  | 0b1110010u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1110011u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1111010u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1111011u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1110100u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypS16, SIMDTypF32)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1110101u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1111100u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypU16, SIMDTypF32)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1111101u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render mode addr bin len cond Op.VCVT dt oprSdmSdmFbits
  | 0b1110110u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypS16, SIMDTypF64)
    render mode addr bin len cond Op.VCVT dt oprDdmDdmFbits
  | 0b1110111u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render mode addr bin len cond Op.VCVT dt oprDdmDdmFbits
  | 0b1111110u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypU16, SIMDTypF64)
    render mode addr bin len cond Op.VCVT dt oprDdmDdmFbits
  | 0b1111111u ->
    chkSzCond bin cond
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render mode addr bin len cond Op.VCVT dt oprDdmDdmFbits
  | _ -> Utils.impossible ()

/// Floating-point move immediate on page F4-4258.
let parseFPMoveImm mode addr bin len cond =
  match extract bin 9u 8u (* size *) with
  | 0b00u -> raise UnallocatedException
  //| 0b01u  Armv8.2
  | 0b10u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypF32) oprSdVImm
  | _ (* 11 *) ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypF64) oprDdVImm

/// Floating-point data-processing (three registers) on page F4-4258.
let parseFPDataProcThreeRegs mode addr bin len cond =
  let decodeField = (* o0:o1:size:o2 *)
    concat (concat (concat (pickBit bin 23u) (extract bin 21u 20u) 2)
      (extract bin 9u 8u) 2) (pickBit bin 6u) 1
  match decodeField with
  | b when (b >>> 3 <> 0b111u) && (b &&& 0b000110u = 0b000u) (* != 111 00x *)
    -> raise UnallocatedException
  (* 000xx0 VMLA *)
  | 0b000000u -> raise UndefinedException
  | 0b000010u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VMLA (oneDt SIMDTypF16) oprSdSnSm
  | 0b000100u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VMLA (oneDt SIMDTypF32) oprSdSnSm
  | 0b000110u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VMLA (oneDt SIMDTypF64) oprDdDnDm
  (* 000xx1 VMLS *)
  | 0b000001u -> raise UndefinedException
  | 0b000011u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VMLS (oneDt SIMDTypF16) oprSdSnSm
  | 0b000101u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VMLS (oneDt SIMDTypF32) oprSdSnSm
  | 0b000111u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VMLS (oneDt SIMDTypF64) oprDdDnDm
  (* 001xx0 VNMLS *)
  | 0b001000u -> raise UndefinedException
  | 0b001010u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VNMLS (oneDt SIMDTypF16) oprSdSnSm
  | 0b001100u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VNMLS (oneDt SIMDTypF32) oprSdSnSm
  | 0b001110u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VNMLS (oneDt SIMDTypF64) oprDdDnDm
  (* 001xx1 VNMLA *)
  | 0b001001u -> raise UndefinedException
  | 0b001011u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VNMLA (oneDt SIMDTypF16) oprSdSnSm
  | 0b001101u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VNMLA (oneDt SIMDTypF32) oprSdSnSm
  | 0b001111u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VNMLA (oneDt SIMDTypF64) oprDdDnDm
  (* 010xx0 VMUL *)
  | 0b010000u ->raise UndefinedException
  | 0b010010u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VMUL (oneDt SIMDTypF16) oprSdSnSm
  | 0b010100u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VMUL (oneDt SIMDTypF32) oprSdSnSm
  | 0b010110u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VMUL (oneDt SIMDTypF64) oprDdDnDm
  (* 010xx1 VNMUL *)
  | 0b010001u -> raise UndefinedException
  | 0b010011u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VNMUL (oneDt SIMDTypF16) oprSdSnSm
  | 0b010101u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VNMUL (oneDt SIMDTypF32) oprSdSnSm
  | 0b010111u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VNMUL (oneDt SIMDTypF64) oprDdDnDm
  (* 011xx0 VADD *)
  | 0b011000u ->raise UndefinedException
  | 0b011010u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VADD (oneDt SIMDTypF16) oprSdSnSm
  | 0b011100u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VADD (oneDt SIMDTypF32) oprSdSnSm
  | 0b011110u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VADD (oneDt SIMDTypF64) oprDdDnDm
  (* 011xx1 VSUB *)
  | 0b011001u ->raise UndefinedException
  | 0b011011u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VSUB (oneDt SIMDTypF16) oprSdSnSm
  | 0b011101u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VSUB (oneDt SIMDTypF32) oprSdSnSm
  | 0b011111u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VSUB (oneDt SIMDTypF64) oprDdDnDm
  (* 100xx0 VDIV *)
  | 0b100000u ->raise UndefinedException
  | 0b100010u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VDIV (oneDt SIMDTypF16) oprSdSnSm
  | 0b100100u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VDIV (oneDt SIMDTypF32) oprSdSnSm
  | 0b100110u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VDIV (oneDt SIMDTypF64) oprDdDnDm
  (* 101xx0 VFNMS *)
  | 0b101000u -> raise UndefinedException
  | 0b101010u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VFNMS (oneDt SIMDTypF16) oprSdSnSm
  | 0b101100u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VFNMS (oneDt SIMDTypF32) oprSdSnSm
  | 0b101110u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VFNMS (oneDt SIMDTypF64) oprDdDnDm
  (* 101xx1 VFNMA *)
  | 0b101001u -> raise UndefinedException
  | 0b101011u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VFNMA (oneDt SIMDTypF16) oprSdSnSm
  | 0b101101u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VFNMA (oneDt SIMDTypF32) oprSdSnSm
  | 0b101111u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VFNMA (oneDt SIMDTypF64) oprDdDnDm
  (* 110xx0 VFMA *)
  | 0b110000u ->raise UndefinedException
  | 0b110010u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VFMA (oneDt SIMDTypF16) oprSdSnSm
  | 0b110100u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VFMA (oneDt SIMDTypF32) oprSdSnSm
  | 0b110110u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VFMA (oneDt SIMDTypF64) oprDdDnDm
  (* 110xx1 VFMS *)
  | 0b110001u ->raise UndefinedException
  | 0b110011u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VFMS (oneDt SIMDTypF16) oprSdSnSm
  | 0b110101u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VFMS (oneDt SIMDTypF32) oprSdSnSm
  | 0b110111u ->
    chkSzCond bin cond
    render mode addr bin len cond Op.VFMS (oneDt SIMDTypF64) oprDdDnDm
  | _ -> Utils.impossible ()

/// Floating-point data-processing on page F4-4256.
let parseFloatingPointDataProcessing mode addr bin len cond =
  match concat (extract bin 23u 20u) (pickBit bin 6u) 1 (* op0:op1 *) with
  | 0b10111u | 0b11111u -> parseFPDataProcTwoRegs mode addr bin len cond
  | 0b10110u | 0b11110u -> parseFPMoveImm mode addr bin len cond
  | _ (* != 1x11 && 0bxu *) -> parseFPDataProcThreeRegs mode addr bin len cond

/// Floating-point move special register on page F4-4259.
let parseFPMoveSpecialReg mode addr bin len cond =
  match pickBit bin 20u (* L *) with
  | 0b0u -> chkPCRt bin; render mode addr bin len cond Op.VMSR None oprSregRt
  | _ (* 0b1u *) ->
     chkPCRt bin; render mode addr bin len cond Op.VMRS None oprRtSreg

/// Advanced SIMD 8/16/32-bit element move/duplicate on page F4-4260.
let parseAdvSIMD8n16n32bitElemMoveDup mode addr bin len cond =
  chkPCRt bin
  let decodeField = concat (extract bin 23u 20u) (extract bin 6u 5u) 2
  match decodeField (* opc1:L:opc2 *) with
  (* 0xx0xx VMOV (general-purpose register to scalar) *)
  | 0b010000u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp8) oprDd0Rt
  | 0b010001u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp8) oprDd1Rt
  | 0b010010u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp8) oprDd2Rt
  | 0b010011u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp8) oprDd3Rt
  | 0b011000u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp8) oprDd4Rt
  | 0b011001u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp8) oprDd5Rt
  | 0b011010u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp8) oprDd6Rt
  | 0b011011u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp8) oprDd7Rt
  | 0b000001u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTyp16) oprDd0Rt
  | 0b000011u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTyp16) oprDd1Rt
  | 0b001001u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTyp16) oprDd2Rt
  | 0b001011u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTyp16) oprDd3Rt
  | 0b000000u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTyp32) oprDd0Rt
  | 0b001000u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTyp32) oprDd1Rt
  | 0b000010u | 0b001010u -> raise UndefinedException
  (* xxx1xx VMOV (scalar to general-purpose register) *)
  | 0b010100u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypS8) oprRtDn0
  | 0b010101u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypS8) oprRtDn1
  | 0b010110u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypS8) oprRtDn2
  | 0b010111u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypS8) oprRtDn3
  | 0b011100u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypS8) oprRtDn4
  | 0b011101u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypS8) oprRtDn5
  | 0b011110u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypS8) oprRtDn6
  | 0b011111u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypS8) oprRtDn7
  | 0b110100u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypU8) oprRtDn0
  | 0b110101u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypU8) oprRtDn1
  | 0b110110u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypU8) oprRtDn2
  | 0b110111u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypU8) oprRtDn3
  | 0b111100u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypU8) oprRtDn4
  | 0b111101u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypU8) oprRtDn5
  | 0b111110u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypU8) oprRtDn6
  | 0b111111u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypU8) oprRtDn7
  | 0b000101u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypS16) oprRtDn0
  | 0b000111u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypS16) oprRtDn1
  | 0b001101u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypS16) oprRtDn2
  | 0b001111u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypS16) oprRtDn3
  | 0b100101u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypU16) oprRtDn0
  | 0b100111u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypU16) oprRtDn1
  | 0b101101u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypU16) oprRtDn2
  | 0b101111u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTypU16) oprRtDn3
  | 0b000100u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTyp32) oprRtDn0
  | 0b001100u ->
    render mode addr bin len cond Op.VMOV (oneDt SIMDTyp32) oprRtDn1
  | 0b100100u | 0b101100u | 0b000110u | 0b001110u | 0b100110u | 0b101110u ->
    raise UndefinedException (* 10x100 or x0x110 *)
  (* 1xx00x VDUP (general-purpose register) *)
  | 0b110000u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp8) oprDdRt
  | 0b100001u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp16) oprDdRt
  | 0b100000u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp32) oprDdRt
  | 0b111000u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp8) oprQdRt
  | 0b101001u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp16) oprQdRt
  | 0b101000u -> render mode addr bin len cond Op.VMOV (oneDt SIMDTyp32) oprQdRt
  | 0b111001u | 0b110001u -> raise UndefinedException
  | b when b &&& 0b100110u = 0b100010u (* 1xx01x *) ->
    raise UnallocatedException
  | _ -> Utils.impossible ()

/// System register 32-bit move on page F4-4260.
let parseSystemReg32bitMove mode addr bin len cond =
  match pickBit bin 20u (* L *) with
  | 0b0u ->
    chkPCRt bin; render mode addr bin len cond Op.MCR None oprCpOpc1RtCRnCRmOpc2
  | _ (* 0b1u *) ->
    render mode addr bin len cond Op.MRC None oprCpOpc1RtCRnCRmOpc2

/// Advanced SIMD and System register 32-bit move on page F4-4259.
let parseAdvSIMDAndSysReg32bitMove mode addr bin len cond =
  match concat (extract bin 23u 21u) (extract bin 10u 8u) 3 (* op0:op1 *) with
  | 0b000000u -> raise UnallocatedException
  //| 0b000001u -> VMOV  Armv8.2
  | 0b000010u ->
    chkPCRt bin
    let oprFn = if pickBit bin 20u = 0u then oprSnRt else oprRtSn
    render mode addr bin len cond Op.VMOV None oprFn
  | 0b001010u -> raise UnallocatedException
  | 0b010010u | 0b011010u -> raise UnallocatedException
  | 0b100010u | 0b101010u -> raise UnallocatedException
  | 0b110010u -> raise UnallocatedException
  | 0b111010u -> parseFPMoveSpecialReg mode addr bin len cond
  | _ ->
    match extract bin 10u 8u (* op1 *) with
    | 0b011u -> parseAdvSIMD8n16n32bitElemMoveDup mode addr bin len cond
    | 0b100u | 0b101u -> raise UnallocatedException
    | 0b110u | 0b111u -> parseSystemReg32bitMove mode addr bin len cond
    | _ -> Utils.impossible ()

/// System register access, Advanced SIMD, floating-point, and Supervisor call
/// on page F4-4246.
let parseCase11 mode addr bin len cond =
  let op0op1op2 =
    concat (concat (extract bin 25u 24u) (pickBit bin 11u) 1) (pickBit bin 4u) 1
  match op0op1op2 (* op0:op1:op2 *) with
  | 0b0000u | 0b0001u | 0b0100u | 0b0101u -> raise UnallocatedException
  | 0b1000u | 0b1001u -> raise UnallocatedException
  | 0b1100u | 0b1101u | 0b1110u | 0b1111u ->
    parseSupervisorCall mode addr bin len cond
  | 0b0010u | 0b0011u | 0b0110u | 0b0111u | 0b1010u | 0b1011u
    when cond = Condition.UN ->
    parseUncondAdvSIMDAndFPInstr mode addr bin len cond
  | 0b0010u | 0b0011u | 0b0110u | 0b0111u ->
    parseAdvSIMDAndSysRegLdStAnd64bitMove mode addr bin len cond
  | 0b1010u -> parseFloatingPointDataProcessing mode addr bin len cond
  | _ (* 0b1011u *) -> parseAdvSIMDAndSysReg32bitMove mode addr bin len cond

/// Change Process State on page F4-4262.
let parseChangeProcessState mode addr bin len cond =
  match concat (pickBit bin 16u) (pickBit bin 4u) 1 (* op:mode<4> *) with
  | 0b10u -> render mode addr bin len cond Op.SETEND None oprEndian
  //| 0b00u | 0b01u -> CPS, CPSID, CPSIE // ARMv8
  | _ (* 11 *) -> raise UnallocatedException

/// Miscellaneous on page F4-4261.
let parseUncondMiscellaneous mode addr bin len cond =
  match concat (extract bin 24u 20u) (extract bin 7u 4u) 4 (* op0:op1 *) with
  | 0b100000000u | 0b100000001u | 0b100000100u | 0b100000101u | 0b100001000u
  | 0b100001001u | 0b100001100u | 0b100001101u (* 10000xx0x *) ->
    parseChangeProcessState mode addr bin len cond
  //| 0b100010000u -> Op.SETPAN // Armv8.1
  | 0b100100111u -> raise UnpredictableException
  | _ -> raise UnallocatedException

/// Advanced SIMD three registers of the same length on page F4-4263.
let parseAdvSIMDThreeRegsSameLen mode addr bin len cond = Utils.futureFeature ()

/// Advanced SIMD two registers misc on page F4-4266.
let parseAdvaSIMDTwoRegsMisc mode addr bin len cond = Utils.futureFeature ()

/// Advanced SIMD duplicate (scalar) on page F4-4268.
let parseAdvSIMDDupScalar mode addr bin len cond =
  match extract bin 9u 7u (* opc *) with
  | 0b000u ->
    let dt = getSizeByImm4 (extract bin 19u 16u) |> oneDt
    chkQVd bin; render mode addr bin len cond Op.VDUP dt oprDdDmx
  | _ (* 001 or 01x or 1xx *) -> raise UnallocatedException

/// Advanced SIMD three registers of different lengths on page F4-4268.
let parseAdvSIMDThreeRegsDiffLen mode addr bin len cond =
  match concat (pickBit bin 24u) (extract bin 11u 8u) 4 (* U:opc *) with
  | 0b00000u | 0b10000u (* x0000 *) ->
    let dt = getDataType bin |> oneDt
    chkVdOp bin; render mode addr bin len cond Op.VADDL dt oprQdDnDm
  | 0b00001u | 0b10001u (* x0001 *) ->
    let dt = getDataType bin |> oneDt
    chkVdOp bin; render mode addr bin len cond Op.VADDW dt oprQdQnDm
  | 0b00010u | 0b10010u (* x0010 *) ->
    let dt = getDataType bin |> oneDt
    chkVdOp bin; render mode addr bin len cond Op.VSUBL dt oprQdDnDm
  | 0b00100u ->
    let dt = getIntSize (extract bin 21u 20u) |> oneDt
    chkVnVm bin; render mode addr bin len cond Op.VADDHN dt oprDdQnQm
  | 0b00011u | 0b10011u (* x0011 *) ->
    let dt = getDataType bin |> oneDt
    chkVdOp bin; render mode addr bin len cond Op.VSUBW dt oprQdQnDm
  | 0b00110u ->
    let dt = getIntSize (extract bin 21u 20u) |> oneDt
    chkVnVm bin; render mode addr bin len cond Op.VSUBHN dt oprDdQnQm
  | 0b01001u ->
    let dt = getDataType bin |> oneDt
    chkSzVd bin; render mode addr bin len cond Op.VQDMLAL dt oprQdDnDm
  | 0b00101u | 0b10101u (* x0101 *) ->
    let dt = getDataType bin |> oneDt
    chkVd0 bin; render mode addr bin len cond Op.VABAL dt oprQdDnDm
  | 0b01011u ->
    let dt = getDataType bin |> oneDt
    chkSzVd bin; render mode addr bin len cond Op.VQDMLSL dt oprQdDnDm
  | 0b01101u ->
    let dt = getDataType bin |> oneDt
    chkSzVd bin; render mode addr bin len cond Op.VQDMULL dt oprQdDnDm
  | 0b00111u | 0b10111u (* x0111 *) ->
    let dt = getDataType bin |> oneDt
    chkVd0 bin; render mode addr bin len cond Op.VABDL dt oprQdDnDm
  | 0b01000u | 0b11000u (* x1000 *) ->
    let dt = getDataType bin |> oneDt
    chkVd0 bin; render mode addr bin len cond Op.VMLAL dt oprQdDnDm
  | 0b01010u | 0b11010u (* x1010 *) ->
    let dt = getDataType bin |> oneDt
    chkVd0 bin; render mode addr bin len cond Op.VMLSL dt oprQdDnDm
  | 0b10100u ->
    let dt = getIntSize (extract bin 21u 20u) |> oneDt
    chkVnVm bin; render mode addr bin len cond Op.VRADDHN dt oprDdQnQm
  | 0b10110u ->
    let dt = getIntSize (extract bin 21u 20u) |> oneDt
    chkVnVm bin; render mode addr bin len cond Op.VRSUBHN dt oprDdQnQm
  | 0b01100u | 0b01110u | 0b11100u | 0b11110u (* x11x0 *) ->
    let dt = getDataType bin |> oneDt
    chkVd0 bin; render mode addr bin len cond Op.VMULL dt oprQdDnDm
  | 0b11001u -> raise UnallocatedException
  | 0b11011u -> raise UnallocatedException
  | 0b11101u -> raise UnallocatedException
  | _ (* x1111 *) -> raise UnallocatedException

/// Advanced SIMD two registers and a scalar on page F4-4269.
let parseAdvSIMDTRegsAndScalar mode addr bin len cond =
  match concat (pickBit bin 24u) (extract bin 11u 8u) 4 (* Q:opc *) with
  | 0b00000u ->
    let dt = getSizeF0 (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VMLA dt oprDdDnDmx
  | 0b00001u ->
    let dt = getSizeF1 (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VMLA dt oprDdDnDmx
  | 0b10000u ->
    let dt = getSizeF0 (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VMLA dt oprQdQnDmx
  | 0b10001u ->
    let dt = getSizeF1 (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VMLA dt oprQdQnDmx
  | 0b00011u ->
    let dt = getDataType bin |> oneDt
    chkSzVd bin; render mode addr bin len cond Op.VQDMLAL dt oprQdDnDmx
  | 0b00010u | 0b10010u (* x0010 *) ->
    let dt = getDataType bin |> oneDt
    chkSzVd bin; render mode addr bin len cond Op.VMLAL dt oprQdDnDmx
  | 0b00111u ->
    let dt = getDataType bin |> oneDt
    chkSzVd bin; render mode addr bin len cond Op.VQDMLSL dt oprQdDnDmx
  | 0b00100u ->
    let dt = getSizeF0 (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VMLS dt oprDdDnDmx
  | 0b00101u ->
    let dt = getSizeF1 (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VMLS dt oprDdDnDmx
  | 0b10100u ->
    let dt = getSizeF0 (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VMLS dt oprQdQnDmx
  | 0b10101u ->
    let dt = getSizeF1 (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VMLS dt oprQdQnDmx
  | 0b01011u ->
    let dt = getDataType bin |> oneDt
    chkSzVd bin; render mode addr bin len cond Op.VQDMULL dt oprQdDnDmx
  | 0b00110u | 0b10110u (* x0110 *) ->
    let dt = getDataType bin |> oneDt
    chkSzVd bin; render mode addr bin len cond Op.VMLSL dt oprQdDnDmx
  | 0b01000u ->
    let dt = getSizeF0 (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VMUL dt oprDdDnDmx
  | 0b01001u ->
    let dt = getSizeF1 (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VMUL dt oprDdDnDmx
  | 0b11000u ->
    let dt = getSizeF0 (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VMUL dt oprQdQnDmx
  | 0b11001u ->
    let dt = getSizeF1 (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VMUL dt oprQdQnDmx
  | 0b10011u -> raise UnallocatedException
  | 0b01010u | 0b11010u (* x1010 *) ->
    let dt = getDataType bin |> oneDt
    chkSzVd bin; render mode addr bin len cond Op.VMULL dt oprQdDnDmx
  | 0b10111u -> raise UnallocatedException
  | 0b01100u ->
    let dt = getSignDT (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VQDMULH dt oprDdDnDmx
  | 0b11100u ->
    let dt = getSignDT (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VQDMULH dt oprQdQnDmx
  | 0b01101u ->
    let dt = getSignDT (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VQRDMULH dt oprDdDnDmx
  | 0b11101u ->
    let dt = getSignDT (extract bin 21u 20u) |> oneDt
    chkSzQVdVn bin; render mode addr bin len cond Op.VQRDMULH dt oprQdQnDmx
  | 0b11011u -> raise UnallocatedException
  //| 0bx1110u -> chk bin; render mode addr bin len cond Op.VQRDMLAH // Armv8.1
  //| 0bx1111u -> chk bin; render mode addr bin len cond Op.VQRDMLSH // Armv8.1
  | _ -> Utils.impossible ()

/// Advanced SIMD two registers, or three registers of different lengths
/// on page F4-4265.
let parseAdvSIMDTwoThreeRegsDiffLen mode addr bin len cond =
  let decodeField = (* op0:op1:op2:op3 *)
    concat (concat (concat (pickBit bin 23u) (extract bin 21u 20u) 2)
           (extract bin 11u 10u) 2) (pickBit bin 6u) 1
  match decodeField (* op0:op1:op2:op3 *) with
  | 0b011000u | 0b011001u | 0b011010u | 0b011011u | 0b011100u | 0b011101u
  | 0b011110u ->
    chkQVdImm bin
    render mode addr bin len cond Op.VEXT (oneDt SIMDTyp8) oprDdDnDmImm
  | 0b011111u ->
    chkQVdImm bin
    render mode addr bin len cond Op.VEXT (oneDt SIMDTyp8) oprQdQnQmImm
  | 0b111000u | 0b111001u | 0b111010u | 0b111011u (* 1110xx *) ->
    parseAdvSIMDThreeRegsSameLen mode addr bin len cond
  | 0b111100u ->
    chkPCRnLen bin
    render mode addr bin len cond Op.VTBL (oneDt SIMDTyp8) oprDdListDm
  | 0b111101u ->
    chkPCRnLen bin
    render mode addr bin len cond Op.VTBX (oneDt SIMDTyp8) oprDdListDm
  | 0b111110u | 0b111111u (* 11111x *) ->
    parseAdvSIMDDupScalar mode addr bin len cond
  | b when (b &&& 0b000001u = 0b000000u) && (extract bin 21u 20u <> 0b11u) ->
    (* x != 11 xx0 *) parseAdvSIMDThreeRegsDiffLen mode addr bin len cond
  | _ (* x != 11 xx1 *) -> parseAdvSIMDTRegsAndScalar mode addr bin len cond

/// Advanced SIMD one register and modified immediate on page F4-4271.
let parseAdvSIMDOneRegAndModImm mode addr bin len cond =
  match concat (extract bin 11u 8u) (pickBit bin 5u) 1 (* cmode:op *) with
  | 0b00000u | 0b00100u | 0b01000u | 0b01100u (* 0xx00 *) ->
    let oprFn = if pickBit bin 6u = 0u then oprDdImm else oprQdImm
    chkQVd bin; render mode addr bin len cond Op.VMOV None oprFn
  | 0b00001u | 0b00101u | 0b01001u | 0b01101u (* 0xx01 *) ->
    let oprFn = if pickBit bin 6u = 0u then oprDdImm else oprQdImm
    chkQVd bin; render mode addr bin len cond Op.VMVN None oprFn
  | 0b00010u | 0b00110u | 0b01010u | 0b01110u (* 0xx10 *) ->
    let oprFn = if pickBit bin 6u = 0u then oprDdImm else oprQdImm
    chkQVd bin; render mode addr bin len cond Op.VORR None oprFn
  | 0b00011u | 0b00111u | 0b01011u | 0b01111u (* 0xx11 *) ->
    let oprFn = if pickBit bin 6u = 0u then oprDdImm else oprQdImm
    chkQVd bin; render mode addr bin len cond Op.VBIC None oprFn
  | 0b10000u | 0b10100u (* 10x00 *) ->
    let oprFn = if pickBit bin 6u = 0u then oprDdImm else oprQdImm
    chkQVd bin; render mode addr bin len cond Op.VMOV None oprFn
  | 0b10001u | 0b10101u (* 10x01 *) ->
    let oprFn = if pickBit bin 6u = 0u then oprDdImm else oprQdImm
    chkQVd bin; render mode addr bin len cond Op.VMVN None oprFn
  | 0b10010u | 0b10110u (* 10x10 *) ->
    let oprFn = if pickBit bin 6u = 0u then oprDdImm else oprQdImm
    chkQVd bin; render mode addr bin len cond Op.VORR None oprFn
  | 0b10011u | 0b10111u (* 10x11 *) ->
    let oprFn = if pickBit bin 6u = 0u then oprDdImm else oprQdImm
    chkQVd bin; render mode addr bin len cond Op.VBIC None oprFn
  | 0b11000u | 0b11010u | 0b11100u | 0b11110u (* 11xx0 *) ->
    let oprFn = if pickBit bin 6u = 0u then oprDdImm else oprQdImm
    chkQVd bin; render mode addr bin len cond Op.VMOV None oprFn
  | 0b11001u | 0b11011u (* 110x1 *) ->
    let oprFn = if pickBit bin 6u = 0u then oprDdImm else oprQdImm
    chkQVd bin; render mode addr bin len cond Op.VMVN None oprFn
  | 0b11101u ->
    let oprFn = if pickBit bin 6u = 0u then oprDdImm else oprQdImm
    chkQVd bin; render mode addr bin len cond Op.VMOV None oprFn
  | _ (* 11111 *) -> raise UnallocatedException

/// Advanced SIMD two registers and shift amount on page F4-4271.
let parseAdvSIMDTwoRegsAndShfAmt mode addr bin len cond = Utils.futureFeature ()

/// Advanced SIMD shifts and immediate generation on page F4-4270.
let parseAdvSIMDShfAndImmGen mode addr bin len cond =
  if extract bin 21u 7u &&& 0b111000000000001u = 0b0u (* 000xxxxxxxxxxx0 *) then
    parseAdvSIMDOneRegAndModImm mode addr bin len cond
  else (* != 000xxxxxxxxxxx0 *)
    parseAdvSIMDTwoRegsAndShfAmt mode addr bin len cond

/// Advanced SIMD data-processing on page F4-4262.
let parseAdvSIMDDataProc mode addr bin len cond =
  match concat (pickBit bin 23u) (pickBit bin 4u) 1 (* op0:op1 *) with
  | 0b00u | 0b01u -> parseAdvSIMDThreeRegsSameLen mode addr bin len cond
  | 0b10u -> parseAdvSIMDTwoThreeRegsDiffLen mode addr bin len cond
  | _ (* 11 *) -> parseAdvSIMDShfAndImmGen mode addr bin len cond

/// Barriers on page F4-4273.
let parseBarriers mode addr bin len cond =
  let option = extract bin 3u 0u
  match extract bin 7u 4u (* opcode *) with
  | 0b0000u -> raise UnpredictableException
  | 0b0001u -> render mode addr bin len cond Op.CLREX None oprNo
  | 0b0010u | 0b0011u -> raise UnpredictableException
  | 0b0100u when (option <> 0b0000u) || (option <> 0b0100u) ->
    render mode addr bin len cond Op.DSB None oprOption
  //| 0b0100u when option = 0b0000u -> Op.SSBB
  //| 0b0100u when option = 0b0100u -> Op.PSSBB
  | 0b0101u -> render mode addr bin len cond Op.DMB None oprOption
  | 0b0110u -> render mode addr bin len cond Op.ISB None oprOption
  //| 0b0111u -> Op.SB
  | _ (* 1xxx *) -> raise UnpredictableException

/// Preload (immediate) on page F4-4273.
let parsePreloadImm mode addr bin len cond =
  let isRn1111 bin = extract bin 19u 16u = 0b1111u
  match concat (pickBit bin 24u) (pickBit bin 22u) 1 (* D:R *) with
  | 0b00u -> render mode addr bin len cond Op.NOP None oprNo
  | 0b01u -> render mode addr bin len cond Op.PLI None oprLabel12
  | 0b10u | 0b11u when isRn1111 bin ->
    render mode addr bin len cond Op.PLD None oprLabel12
  | 0b10u (* != 1111 *) -> render mode addr bin len cond Op.PLDW None oprMemImm
  | _ (* 0b11u != 1111 *) -> render mode addr bin len cond Op.PLD None oprMemImm

/// Preload (register) on page F4-4274.
let parsePreloadReg mode addr bin len cond =
  match concat (pickBit bin 24u) (pickBit bin 22u) 1 (* D:o2 *) with
  | 0b00u -> render mode addr bin len cond Op.NOP None oprNo
  | 0b01u -> chkPCRm bin; render mode addr bin len cond Op.PLI None oprMemReg
  | 0b10u ->
    chkPCRmRnPldw bin; render mode addr bin len cond Op.PLDW None oprMemReg
  | _ (* 11 *) ->
    chkPCRmRnPldw bin; render mode addr bin len cond Op.PLD None oprMemReg

/// Memory hints and barriers on page F4-4272.
let parseMemoryHintsAndBarriers mode addr bin len cond =
  match concat (extract bin 25u 21u) (pickBit bin 4u) 1 (* op0:op1 *) with
  | b when b &&& 0b110010u = 0b000010u (* 00xx1x *) ->
    raise UnpredictableException
  | 0b010010u | 0b010011u (* 01001x *) -> raise UnpredictableException
  | 0b010110u | 0b010111u (* 01011x *) -> parseBarriers mode addr bin len cond
  | 0b011010u | 0b011011u | 0b011110u | 0b011111u (* 011x1x *) ->
    raise UnpredictableException
  | b when b &&& 0b100010u = 0b000000u (* 0xxx0x *) ->
    parsePreloadImm mode addr bin len cond
  | b when b &&& 0b100011u = 0b100000u (* 1xxx00 *) ->
    parsePreloadReg mode addr bin len cond
  | b when b &&& 0b100011u = 0b100010u (* 1xxx10 *) ->
    raise UnpredictableException
  | _ (* 1xxxx1 *) -> raise UnallocatedException

/// Advanced SIMD load/store multiple structures on page F4-4275.
let parseAdvSIMDLdStMulStruct mode addr bin len cond =
  match concat (pickBit bin 21u) (extract bin 11u 8u) 4 (* L:itype *) with
  | 0b00000u | 0b00001u (* 0000x *) ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkSzPCRnD4 bin; render mode addr bin len cond Op.VST4 dt oprListMem
  | 0b00010u ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkPCRnDregs bin; render mode addr bin len cond Op.VST1 dt oprListMem
  | 0b00011u ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkPCRnD2regs bin; render mode addr bin len cond Op.VST2 dt oprListMem
  | 0b00100u | 0b00101u (* 0010x *) ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkPCRnD3 bin; render mode addr bin len cond Op.VST3 dt oprListMem
  | 0b00110u ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkAlign1PCRnDregs bin 3u
    render mode addr bin len cond Op.VST1 dt oprListMem
  | 0b00111u ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkAlign1PCRnDregs bin 1u
    render mode addr bin len cond Op.VST1 dt oprListMem
  | 0b01000u | 0b01001u (* 0100x *) ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkAlignPCRnD2regs bin; render mode addr bin len cond Op.VST2 dt oprListMem
  | 0b01010u ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkAlignPCRnDregs bin; render mode addr bin len cond Op.VST1 dt oprListMem
  | 0b10000u | 0b10001u (* 1000x *) ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkSzPCRnD4 bin; render mode addr bin len cond Op.VLD4 dt oprListMem
  | 0b10010u ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkPCRnDregs bin; render mode addr bin len cond Op.VLD1 dt oprListMem
  | 0b10011u ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkPCRnD2regs bin; render mode addr bin len cond Op.VLD2 dt oprListMem
  | 0b10100u | 0b10101u (* 1010x *) ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkPCRnD3 bin; render mode addr bin len cond Op.VLD3 dt oprListMem
  | 0b01011u | 0b11011u (* x1011 *) -> raise UnallocatedException
  | 0b10110u ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkAlign1PCRnDregs bin 3u
    render mode addr bin len cond Op.VLD1 dt oprListMem
  | 0b10111u ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkAlign1PCRnDregs bin 1u
    render mode addr bin len cond Op.VLD1 dt oprListMem
  | 0b01100u | 0b01101u | 0b01110u | 0b01111u | 0b11100u | 0b11101u | 0b11110u
  | 0b11111u (* x11xx *) -> raise UnallocatedException
  | 0b11000u | 0b11001u (* 1100x *) ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkAlignPCRnD2regs bin; render mode addr bin len cond Op.VLD2 dt oprListMem
  | 0b11010u ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkAlignPCRnDregs bin; render mode addr bin len cond Op.VLD1 dt oprListMem
  | _ -> Utils.impossible ()

/// Advanced SIMD load single structure to all lanes on page F4-4276.
let parseAdvSIMDLdSingleStructAllLanes mode addr bin len cond =
  let decodeField = (* L:N:a *)
    concat (concat (pickBit bin 21u) (extract bin 9u 8u) 2) (pickBit bin 4u) 1
  match decodeField with
  | b when b &&& 0b1000u = 0b0000u (* 0xxx *) -> raise UnallocatedException
  | 0b1000u | 0b1001u (* 100x *) ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkSzAPCRnDregs bin; render mode addr bin len cond Op.VLD1 dt oprListMem1
  | 0b1010u | 0b1011u (* 101x *) ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkSzPCRnD2 bin; render mode addr bin len cond Op.VLD2 dt oprListMem2
  | 0b1100u ->
    let dt = getSize (extract bin 7u 6u) |> oneDt
    chkSzAPCRnD3 bin; render mode addr bin len cond Op.VLD3 dt oprListMem3
  | 0b1101u -> raise UnallocatedException
  | _ (* 111x *) ->
    let dt = getSizeS (extract bin 7u 6u) |> oneDt
    chkSzAPCRnD4 bin; render mode addr bin len cond Op.VLD4 dt oprListMem4

/// Advanced SIMD load/store single structure to one lane on page F4-4276.
let parseAdvSIMDLdStSingleStructOneLane mode addr bin len cond =
  match concat (pickBit bin 21u) (extract bin 11u 8u) 4 (* L:size:N *) with
  | 0b00000u ->
    chkSzIdx0PCRn bin
    render mode addr bin len cond Op.VST1 (oneDt SIMDTyp8) oprListMemA
  | 0b00001u ->
    chkPCRnD2 bin
    render mode addr bin len cond Op.VST2 (oneDt SIMDTyp8) oprListMemB
  | 0b00010u ->
    chkIdx0PCRnD3 bin
    render mode addr bin len cond Op.VST3 (oneDt SIMDTyp8) oprListMemC
  | 0b00011u ->
    chkPCRnD4 bin
    render mode addr bin len cond Op.VST4 (oneDt SIMDTyp8) oprListMemD
  | 0b00100u ->
    chkSzIdx1PCRn bin
    render mode addr bin len cond Op.VST1 (oneDt SIMDTyp16) oprListMemA
  | 0b00101u ->
    chkPCRnD2 bin
    render mode addr bin len cond Op.VST2 (oneDt SIMDTyp16) oprListMemB
  | 0b00110u ->
    chkIdx0PCRnD3 bin
    render mode addr bin len cond Op.VST3 (oneDt SIMDTyp16) oprListMemC
  | 0b00111u ->
    chkPCRnD4 bin
    render mode addr bin len cond Op.VST4 (oneDt SIMDTyp16) oprListMemD
  | 0b01000u ->
    chkSzIdx2PCRn bin
    render mode addr bin len cond Op.VST1 (oneDt SIMDTyp32) oprListMemA
  | 0b01001u ->
    chkIdxPCRnD2 bin
    render mode addr bin len cond Op.VST2 (oneDt SIMDTyp32) oprListMemB
  | 0b01010u ->
    chkIdx10PCRnD3 bin
    render mode addr bin len cond Op.VST3 (oneDt SIMDTyp32) oprListMemC
  | 0b01011u ->
    chkIdxPCRnD4 bin
    render mode addr bin len cond Op.VST4 (oneDt SIMDTyp32) oprListMemD
  | 0b10000u ->
    chkSzIdx0PCRn bin
    render mode addr bin len cond Op.VLD1 (oneDt SIMDTyp8) oprListMemA
  | 0b10001u ->
    chkPCRnD2 bin
    render mode addr bin len cond Op.VLD2 (oneDt SIMDTyp8) oprListMemB
  | 0b10010u ->
    chkIdx0PCRnD3 bin
    render mode addr bin len cond Op.VLD3 (oneDt SIMDTyp8) oprListMemC
  | 0b10011u ->
    chkPCRnD4 bin
    render mode addr bin len cond Op.VLD4 (oneDt SIMDTyp8) oprListMemD
  | 0b10100u ->
    chkSzIdx1PCRn bin
    render mode addr bin len cond Op.VLD1 (oneDt SIMDTyp16) oprListMemA
  | 0b10101u ->
    chkPCRnD2 bin
    render mode addr bin len cond Op.VLD2 (oneDt SIMDTyp16) oprListMemB
  | 0b10110u ->
    chkIdx0PCRnD3 bin
    render mode addr bin len cond Op.VLD3 (oneDt SIMDTyp16) oprListMemC
  | 0b10111u ->
    chkPCRnD4 bin
    render mode addr bin len cond Op.VLD4 (oneDt SIMDTyp16) oprListMemD
  | 0b11000u ->
    chkSzIdx2PCRn bin
    render mode addr bin len cond Op.VLD1 (oneDt SIMDTyp32) oprListMemA
  | 0b11001u ->
    chkIdxPCRnD2 bin
    render mode addr bin len cond Op.VLD2 (oneDt SIMDTyp32) oprListMemB
  | 0b11010u ->
    chkIdx10PCRnD3 bin
    render mode addr bin len cond Op.VLD3 (oneDt SIMDTyp32) oprListMemC
  | 0b11011u ->
    chkIdxPCRnD4 bin
    render mode addr bin len cond Op.VLD4 (oneDt SIMDTyp32) oprListMemD
  | _ -> Utils.impossible ()

/// Advanced SIMD element or structure load/store on page F4-4274.
let parseAdvSIMDElemOrStructLdSt mode addr bin len cond =
  match concat (pickBit bin 23u) (extract bin 11u 10u) 2 (* op0:op1 *) with
  | 0b000u | 0b001u | 0b010u | 0b011u (* 0xx *) ->
    parseAdvSIMDLdStMulStruct mode addr bin len cond
  | 0b111u -> parseAdvSIMDLdSingleStructAllLanes mode addr bin len cond
  | _ (* 1 !=11 *) -> parseAdvSIMDLdStSingleStructOneLane mode addr bin len cond

/// Unconditional instructions on page F4-4261.
let parseUncondInstr mode addr bin len cond =
  match concat (extract bin 26u 25u) (pickBit bin 20u) 1 (* op0:op1 *) with
  | 0b000u | 0b001u -> parseUncondMiscellaneous mode addr bin len cond
  | 0b010u | 0b011u -> parseAdvSIMDDataProc mode addr bin len cond
  | 0b101u | 0b111u -> parseMemoryHintsAndBarriers mode addr bin len cond
  | 0b100u -> parseAdvSIMDElemOrStructLdSt mode addr bin len cond
  | _ (* 0b110u *) -> raise UnallocatedException

/// ARM Architecture Reference Manual ARMv8-A, ARM DDI 0487F.c ID072120
/// A32 instruction set encoding on page F4-4218.
let parseV8A32ARM mode addr bin len =
  let cond = extract bin 31u 28u |> byte |> parseCond
  match extract bin 27u 26u (* op1<2:1> *) with
  | 0b00u when cond <> Condition.UN -> parseCase00 mode addr bin len cond
  | 0b01u when cond <> Condition.UN -> parseCase01 mode addr bin len cond
  | 0b10u -> parseCase10 mode addr bin len cond
  | 0b11u -> parseCase11 mode addr bin len cond
  | _ (* 0b0xu *) -> parseUncondInstr mode addr bin len cond

// vim: set tw=80 sts=2 sw=2:
