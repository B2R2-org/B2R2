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
let parseReverseBitByte bin =
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
let parseExtendAndAdd bin =
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
let parseBitfieldInsert bin =
  if extract bin 3u 0u <> 0b1111u then
    Op.BFI, p4Oprs bin chkUnpreAQ (getRegD, getRegA, getImm5A, getImm5F)
  else Op.BFC, p3Oprs bin chkUnpreAP (getRegD, getImm5A, getImm5F)

/// Permanently UNDEFINED, page F4-2527
let parsePermanentlyUndefined cond bin =
  if cond = Condition.AL then Op.UDF, p1Opr bin dummyChk getImm12D
  else raise UnallocatedException

/// Bitfield Extract, page F4-2528
let parseBitfieldExtract bin =
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
let parseLoadStoreReg b =
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
let parseLoadStoreImm b =
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
let parseExtraLoadStore bin =
  match pickBit bin 22u with
  | 0u -> parseLoadStoreReg bin
  | 1u -> parseLoadStoreImm bin
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
    | _, 1u, b, 1u when b <> 0u -> parseExtraLoadStore bin
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
    | op when op &&& 0b11011011u = 0b01011001u -> parseReverseBitByte bin
    | op when op &&& 0b11010001u = 0b01010000u -> parseSaturate32Bit bin
    | op when op &&& 0b11000111u = 0b01000111u -> raise UnallocatedException
    | op when op &&& 0b11000111u = 0b01000011u -> parseExtendAndAdd bin
    | op when op &&& 0b11000000u = 0b10000000u -> parseSignedMultiplyDivide bin
    | 0b11000000u -> unsignedSumAbsoluteDiff bin
    | 0b11000100u -> raise UnallocatedException
    | op when op &&& 0b11111011u = 0b11001000u -> raise UnallocatedException
    | op when op &&& 0b11110011u = 0b11010000u -> raise UnallocatedException
    | op when op &&& 0b11100111u = 0b11000111u -> raise UnallocatedException
    | op when op &&& 0b11110111u = 0b11100111u -> raise UnallocatedException
    | op when op &&& 0b11110011u = 0b11100000u -> parseBitfieldInsert bin
    | 0b11110111u -> raise UnallocatedException
    | 0b11111111u -> parsePermanentlyUndefined cond bin
    | op when op &&& 0b11110011u = 0b11110000u -> raise UnallocatedException
    | op when op &&& 0b11010011u = 0b11000010u -> raise UnallocatedException
    | op when op &&& 0b11010011u = 0b11010010u -> parseBitfieldExtract bin
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

/// ARM Architecture Reference Manual ARMv8-A ARM DDI 0487A.k
let parseV8A32ARM bin =
  let op = concat (extract bin 27u 25u) (pickBit bin 4u) 1
  let cond = extract bin 31u 28u |> byte |> parseCond
  let opcode, SIMDTyp, operands =
    match op with
    //| op when op &&& 0b1110u = 0b0000u -> parseGroup000v8 cond bin
    | op when op &&& 0b1110u = 0b0010u -> parseGroup001v8 cond bin
    | op when op &&& 0b1110u = 0b0100u -> parseGroup010v8 cond bin
    | op when op &&& 0b1111u = 0b0110u -> parseGroup0110v8 cond bin
    | op when op &&& 0b1111u = 0b0111u -> parseGroup0111v8 cond bin
    | op when op &&& 0b1110u = 0b1000u -> parseGroup100v8 cond bin
    | op when op &&& 0b1110u = 0b1010u -> raise UnallocatedException
    | op when op &&& 0b1110u = 0b1100u -> parseGroup110v8 cond bin
    | op when op &&& 0b1110u = 0b1110u -> raise UnallocatedException
    | _ -> failwith "Wrong group specified."
  opcode, Some cond, 0uy, None, None, SIMDTyp, operands, None

// vim: set tw=80 sts=2 sw=2:
