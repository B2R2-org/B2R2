(*
  B2R2 - the Next-Generation Reversing Platform

  Author: DongYeop Oh <oh51dy@kaist.ac.kr>

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

module internal B2R2.FrontEnd.ARM32.Parserv7

open B2R2
open B2R2.FrontEnd.ARM32.ParseUtils
open B2R2.FrontEnd.ARM32.OperandHelper

let getCondWithITSTATE itState =
  if itState = 0uy then Some Condition.AL
  else itState >>> 4 |> parseCond |> Some

/// Data-processing (register), page A5-197
let parseDataProcReg bin op =
  let chkImm5 () = extract bin 11u 7u = 0b00000u
  match op with
  | 0b00000u ->
    Op.AND, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b00001u ->
    Op.ANDS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b00010u ->
    Op.EOR, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b00011u ->
    Op.EORS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b00100u ->
    Op.SUB, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b00101u ->
    Op.SUBS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b00110u ->
    Op.RSB, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b00111u ->
    Op.RSBS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b01000u ->
    Op.ADD, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b01001u ->
    Op.ADDS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b01010u ->
    Op.ADC, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b01011u ->
    Op.ADCS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b01100u ->
    Op.SBC, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b01101u ->
    Op.SBCS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b01110u ->
    Op.RSC, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b01111u ->
    Op.RSCS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b10001u -> Op.TST, p3Oprs bin dummyChk (getRegC, getRegA, getShiftB)
  | 0b10011u -> Op.TEQ, p3Oprs bin dummyChk (getRegC, getRegA, getShiftB)
  | 0b10101u -> Op.CMP, p3Oprs bin dummyChk (getRegC, getRegA, getShiftB)
  | 0b10111u -> Op.CMN, p3Oprs bin dummyChk (getRegC, getRegA, getShiftB)
  | 0b11000u ->
    Op.ORR, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b11001u ->
    Op.ORRS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b11010u when extract bin 6u 5u = 0b00u && chkImm5 () ->
    Op.MOV, p2Oprs bin dummyChk (getRegD, getRegA)
  | 0b11010u when extract bin 6u 5u = 0b00u && not (chkImm5 ()) ->
    Op.LSL, p3Oprs bin dummyChk (getRegD, getRegA, getImm5A)
  | 0b11011u when extract bin 6u 5u = 0b00u && chkImm5 () ->
    Op.MOVS, p2Oprs bin dummyChk (getRegD, getRegA)
  | 0b11011u when extract bin 6u 5u = 0b00u && not (chkImm5 ()) ->
    Op.LSLS, p3Oprs bin dummyChk (getRegD, getRegA, getImm5A)
  | 0b11010u when extract bin 6u 5u = 0b01u ->
    Op.LSR, p3Oprs bin dummyChk (getRegD, getRegA, getImm5A)
  | 0b11011u when extract bin 6u 5u = 0b01u ->
    Op.LSRS, p3Oprs bin dummyChk (getRegD, getRegA, getImm5A)
  | 0b11010u when extract bin 6u 5u = 0b10u ->
    Op.ASR, p3Oprs bin dummyChk (getRegD, getRegA, getImm5A)
  | 0b11011u when extract bin 6u 5u = 0b10u ->
    Op.ASRS, p3Oprs bin dummyChk (getRegD, getRegA, getImm5A)
  | 0b11010u when extract bin 6u 5u = 0b11u && chkImm5 () ->
    Op.RRX, p2Oprs bin dummyChk (getRegD, getRegA)
  | 0b11010u when extract bin 6u 5u = 0b11u && not (chkImm5 ()) ->
    Op.ROR, p3Oprs bin dummyChk (getRegD, getRegA, getImm5A)
  | 0b11011u when extract bin 6u 5u = 0b11u && chkImm5 () ->
    Op.RRXS, p2Oprs bin dummyChk (getRegD, getRegA)
  | 0b11011u when extract bin 6u 5u = 0b11u && not (chkImm5 ()) ->
    Op.RORS, p3Oprs bin dummyChk (getRegD, getRegA, getImm5A)
  | 0b11100u ->
    Op.BIC, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b11101u ->
    Op.BICS, p4Oprs bin dummyChk (getRegD, getRegC, getRegA, getShiftB)
  | 0b11110u -> Op.MVN, p3Oprs bin dummyChk (getRegD, getRegA, getShiftB)
  | 0b11111u -> Op.MVNS, p3Oprs bin dummyChk (getRegD, getRegA, getShiftB)
  | _ -> failwith "Wrong Data-proc (reg) encoding."

/// Data-processing (register-shifted register), page A5-198
let parseDataProcRegSReg b op =
  let chk () = extract b 6u 5u
  match op with
  | 0b00000u -> Op.AND, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b00001u ->
    Op.ANDS, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b00010u -> Op.EOR, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b00011u ->
    Op.EORS, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b00100u -> Op.SUB, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b00101u ->
    Op.SUBS, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b00110u -> Op.RSB, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b00111u ->
    Op.RSBS, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b01000u -> Op.ADD, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b01001u ->
    Op.ADDS, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b01010u -> Op.ADC, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b01011u ->
    Op.ADCS, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b01100u -> Op.SBC, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b01101u ->
    Op.SBCS, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b01110u -> Op.RSC, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b01111u ->
    Op.RSCS, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b10001u -> Op.TST, p3Oprs b dummyChk (getRegC, getRegA, getShiftA)
  | 0b10011u -> Op.TEQ, p3Oprs b dummyChk (getRegC, getRegA, getShiftA)
  | 0b10101u -> Op.CMP, p3Oprs b dummyChk (getRegC, getRegA, getShiftA)
  | 0b10111u -> Op.CMN, p3Oprs b dummyChk (getRegC, getRegA, getShiftA)
  | 0b11000u -> Op.ORR, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b11001u ->
    Op.ORRS, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b11010u when chk () = 0u ->
    Op.LSL, p3Oprs b dummyChk (getRegD, getRegA, getRegB)
  | 0b11011u when chk () = 0u ->
    Op.LSLS, p3Oprs b dummyChk (getRegD, getRegA, getRegB)
  | 0b11010u when chk () = 1u ->
    Op.LSR, p3Oprs b dummyChk (getRegD, getRegA, getRegB)
  | 0b11011u when chk () = 1u ->
    Op.LSRS, p3Oprs b dummyChk (getRegD, getRegA, getRegB)
  | 0b11010u when chk () = 2u ->
    Op.ASR, p3Oprs b dummyChk (getRegD, getRegA, getRegB)
  | 0b11011u when chk () = 2u ->
    Op.ASRS, p3Oprs b dummyChk (getRegD, getRegA, getRegB)
  | 0b11010u when chk () = 3u ->
    Op.ROR, p3Oprs b dummyChk (getRegD, getRegA, getRegB)
  | 0b11011u when chk () = 3u ->
    Op.RORS, p3Oprs b dummyChk (getRegD, getRegA, getRegB)
  | 0b11100u -> Op.BIC, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b11101u ->
    Op.BICS, p4Oprs b dummyChk (getRegD, getRegC, getRegA, getShiftA)
  | 0b11110u -> Op.MVN, p3Oprs b dummyChk (getRegD, getRegA, getShiftA)
  | 0b11111u -> Op.MVNS, p3Oprs b dummyChk (getRegD, getRegA, getShiftA)
  | _ -> failwith "Wrong Data-proc (reg-shifted reg) encoding."

/// Miscellaneous instructions, page A5-207
/// Saturating addition and subtraction, page A5-202
let parseMiscelInstrs cond bin =
  let chk () = pickBit bin 9u = 0b1u
  let pick u b = pickBit bin u = b && not (chk ())
  match concat (extract bin 6u 4u) (extract bin 22u 21u) 2 with
  | 0b00000u when chk () ->
    Op.MRS, p2Oprs bin chkUnpreG (getRegD, getBankedRegA)
  | 0b00010u when chk () ->
    Op.MRS, p2Oprs bin chkUnpreG (getRegD, getBankedRegA)
  | 0b00001u when chk () ->
    Op.MSR, p2Oprs bin chkUnpreF (getBankedRegA, getRegA)
  | 0b00011u when chk () ->
    Op.MSR, p2Oprs bin chkUnpreF (getBankedRegA, getRegA)
  (* new opcodes has to be built later on, B9-1990, 1992 *)
  | 0b00000u | 0b00010u -> Op.MRS, p2Oprs bin dummyChk (getRegD, getRegE)
  (* MRS for SYSTEM LEVEL has to be consideded and built later on, B9-1988 *)
  | 0b00001u when extract bin 17u 16u = 0u && not (chk ()) ->
    Op.MSR, p2Oprs bin chkUnpreF (getAPSRxA, getRegA)
  | 0b00001u when extract bin 17u 16u = 1u && not (chk ()) ->
    Op.MSR, p2Oprs bin chkUnpreH (getRegK, getRegA)
  | 0b00001u when pick 17u 0b1u ->
    Op.MSR, p2Oprs bin chkUnpreH (getRegK, getRegA)
  | 0b00011u -> Op.MSR, p2Oprs bin chkUnpreH (getRegK, getRegA)
  | 0b00101u -> Op.BX, p1Opr bin dummyChk getRegA
  | 0b00111u -> Op.CLZ, p2Oprs bin chkUnpreE (getRegD, getRegA)
  | 0b01001u -> Op.BXJ, p1Opr bin chkUnpreD getRegA
  | 0b01101u -> Op.BLX, p1Opr bin chkUnpreD getRegA
  | 0b10100u -> Op.QADD, p3Oprs bin chkUnpreA (getRegD, getRegC, getRegA)
  | 0b10101u -> Op.QSUB, p3Oprs bin chkUnpreA (getRegD, getRegC, getRegA)
  | 0b10110u -> Op.QDADD, p3Oprs bin chkUnpreA (getRegD, getRegC, getRegA)
  | 0b10111u -> Op.QDSUB, p3Oprs bin chkUnpreA (getRegD, getRegC, getRegA)
  | 0b11101u when cond = Condition.AL -> Op.BKPT, p1Opr bin dummyChk getImm12D
  | 0b11111u -> Op.SMC, p1Opr bin dummyChk getImm4A
  | _ -> failwith "Wrong Miscellaneous intstructions encoding."

/// Syncronization primitives, page A5-205
let parseSynPrimitives bin =
  match extract bin 23u 20u with
  | 0b0000u -> Op.SWP, p3Oprs bin chkUnpreJ (getRegD, getRegA, getMemA)
  | 0b0100u -> Op.SWPB, p3Oprs bin chkUnpreJ (getRegD, getRegA, getMemA)
  | 0b1000u -> Op.STREX, p3Oprs bin checkStoreEx1 (getRegD, getRegA, getMemA)
  | 0b1001u -> Op.LDREX, p2Oprs bin chkUnpreK (getRegD, getMemA)
  | 0b1010u ->
    Op.STREXD, p4Oprs bin checkStoreEx2 (getRegD, getRegA, getRegF, getMemA)
  | 0b1011u -> Op.LDREXD, p3Oprs bin chkUnpreL (getRegD, getRegL, getMemA)
  | 0b1100u -> Op.STREXB, p3Oprs bin checkStoreEx1 (getRegD, getRegA, getMemA)
  | 0b1101u -> Op.LDREXB, p2Oprs bin chkUnpreK (getRegD, getMemA)
  | 0b1110u -> Op.STREXH, p3Oprs bin checkStoreEx1 (getRegD, getRegA, getMemA)
  | 0b1111u -> Op.LDREXH, p2Oprs bin chkUnpreK (getRegD, getMemA)
  | _ -> failwith "Wrong Synchronization primitives encoding."

/// Extra load/store instructions, page A5-203
let parseExLoadStoreInstrs b =
  let rn () = extract b 19u 16u = 0b1111u
  let mask = 0b1100101u
  match concat (extract b 6u 5u) (extract b 24u 20u) 5 with
  | o when o &&& mask = 0b0100000u ->
    if pickBit b 24u = 0b0u && pickBit b 21u = 0b1u then
      Op.STRHT, p2Oprs b chkUnpreV (getRegD, getMemI)
    else Op.STRH, p2Oprs b chkUnpreAD (getRegD, getMemN)
  | o when o &&& mask = 0b0100001u ->
    if pickBit b 24u = 0b0u && pickBit b 21u = 0b1u then
      Op.LDRHT, p2Oprs b chkUnpreV (getRegD, getMemI)
    else Op.LDRH, p2Oprs b chkUnpreAD (getRegD, getMemN)
  | o when o &&& mask = 0b0100100u ->
    if pickBit b 24u = 0b0u && pickBit b 21u = 0b1u then
      Op.STRHT, p2Oprs b chkUnpreW (getRegD, getMemJ)
    else Op.STRH, p2Oprs b chkUnpreAD (getRegD, getMemO)
  | o when o &&& mask = 0b0100101u && rn () ->
    if pickBit b 24u = 0b0u && pickBit b 21u = 0b1u then
      Op.LDRHT, p2Oprs b chkUnpreW (getRegD, getMemJ)
    else Op.LDRH, p2Oprs b chkUnpreT (getRegD, getMemH)
  | o when o &&& mask = 0b0100101u ->
    if pickBit b 24u = 0b0u && pickBit b 21u = 0b1u then
      Op.LDRHT, p2Oprs b chkUnpreW (getRegD, getMemJ)
    else Op.LDRH, p2Oprs b chkUnpreAH (getRegD, getMemO)
  | o when o &&& mask = 0b1000000u ->
    Op.LDRD, p3Oprs b chkUnpreAE (getRegD, getRegL, getMemN)
  | o when o &&& mask = 0b1000001u ->
    if pickBit b 24u = 0b0u && pickBit b 21u = 0b1u then
      Op.LDRSBT, p2Oprs b chkUnpreV (getRegD, getMemI)
    else Op.LDRSB, p2Oprs b chkUnpreAD (getRegD, getMemN)
  | o when o &&& mask = 0b1000100u && rn () ->
    Op.LDRD, p3Oprs b chkUnpreU (getRegD, getRegL, getMemH)
  | o when o &&& mask = 0b1000100u ->
    Op.LDRD, p3Oprs b chkUnpreAI (getRegD, getRegL, getMemO)
  | o when o &&& mask = 0b1000101u && rn () ->
    Op.LDRSB, p2Oprs b chkUnpreG (getRegD, getMemH)
  | o when o &&& mask = 0b1000101u ->
    if pickBit b 24u = 0b0u && pickBit b 21u = 0b1u then
      Op.LDRSBT, p2Oprs b chkUnpreW (getRegD, getMemJ)
    else Op.LDRSB, p2Oprs b chkUnpreAH (getRegD, getMemO)
  | o when o &&& mask = 0b1100000u ->
    Op.STRD, p3Oprs b chkUnpreAF (getRegD, getRegL, getMemN)
  | o when o &&& mask = 0b1100001u ->
    if pickBit b 24u = 0b0u && pickBit b 21u = 0b1u then
      Op.LDRSHT, p2Oprs b chkUnpreV (getRegD, getMemI)
    else Op.LDRSH, p2Oprs b chkUnpreAD (getRegD, getMemN)
  | o when o &&& mask = 0b1100100u ->
    Op.STRD, p3Oprs b chkUnpreAJ (getRegD, getRegL, getMemO)
  | o when o &&& mask = 0b1100101u && rn () ->
    Op.LDRSH, p2Oprs b chkUnpreG (getRegD, getMemH)
  | o when o &&& mask = 0b1100101u ->
    if pickBit b 24u = 0b0u && pickBit b 21u = 0b1u then
      Op.LDRSHT, p2Oprs b chkUnpreW (getRegD, getMemJ)
    else Op.LDRSH, p2Oprs b chkUnpreAH (getRegD, getMemO)
  | _ -> failwith "Wrong Extra load/store instructions."

/// Extra load/store instructions (unprivileged), page A5-204
let parseExLoadStoreInstrsUnpriv b =
  let chk22 () = pickBit b 22u = 0b0u
  let chk12 () = pickBit b 12u = 0b0u
  match concat (extract b 6u 5u) (pickBit b 20u) 1 with
  | 0b010u when chk22 () -> Op.STRHT, p2Oprs b chkUnpreV (getRegD, getMemI)
  | 0b010u when not (chk22 ()) ->
    Op.STRHT, p2Oprs b chkUnpreW (getRegD, getMemJ)
  | 0b011u when chk22 () -> Op.LDRHT, p2Oprs b chkUnpreV (getRegD, getMemI)
  | 0b011u when not (chk22 ()) ->
    Op.LDRHT, p2Oprs b chkUnpreW (getRegD, getMemJ)
  | 0b100u when chk12 () -> raise UnpredictableException
  | 0b100u when not (chk12 ()) -> raise UndefinedException
  | 0b110u when chk12 () -> raise UnpredictableException
  | 0b110u when not (chk12 ()) -> raise UndefinedException
  | 0b101u when chk22 () -> Op.LDRSBT, p2Oprs b chkUnpreV (getRegD, getMemI)
  | 0b101u when not (chk22 ()) ->
    Op.LDRSBT, p2Oprs b chkUnpreW (getRegD, getMemJ)
  | 0b111u when chk22 () -> Op.LDRSHT, p2Oprs b chkUnpreV (getRegD, getMemI)
  | 0b111u when not (chk22 ()) ->
    Op.LDRSHT, p2Oprs b chkUnpreW (getRegD, getMemJ)
  | _ -> failwith "Wrong Extra load/store instructions (unprivilieged)."

/// Data-processing and miscellaneous instructions, page A5-196
/// Unconditional SETEND and CPS, page A5-217
let parseGroup000 cond bin =
  let o1 = extract bin 24u 20u
  let o2 = extract bin 7u 4u
  let isDataProc () = o1 &&& 0b11001u <> 0b10000u
  let isMiscel () = o1 &&& 0b11001u = 0b10000u && o2 &&& 0b1000u = 0u
  let isHalfword () = o1 &&& 0b11001u = 0b10000u && o2 &&& 0b1001u = 0b1000u
  let isExLoad () = o1 &&& 0b10010u <> 0b00010u
  let isExLoadUnpriv () = o1 &&& 0b10010u = 0b00010u
  let opcode, operands =
    match o1, o2 with
    | b1, 0b1001u when b1 &&& 0b10000u = 0u -> parseMulNMulAcc bin
    | b1, 0b1001u when b1 &&& 0b10000u = 0b10000u -> parseSynPrimitives bin
    | _, 0b1011u when isExLoad () -> parseExLoadStoreInstrs bin
    | _, 0b1101u when isExLoad () -> parseExLoadStoreInstrs bin
    | _, 0b1111u when isExLoad () -> parseExLoadStoreInstrs bin
    | _, 0b1011u when isExLoadUnpriv () -> parseExLoadStoreInstrsUnpriv bin
    | _, 0b1101u when isExLoadUnpriv () -> parseExLoadStoreInstrs bin
    | _, 0b1111u when isExLoadUnpriv () -> parseExLoadStoreInstrs bin
    | _, b when isDataProc () && b &&& 1u = 0u -> parseDataProcReg bin o1
    | _, b when isDataProc () && b &&& 0b1001u = 1u ->
      parseDataProcRegSReg bin o1
    | _, _ when isMiscel () -> parseMiscelInstrs cond bin
    | _, _ when isHalfword () -> parseHalfMulNMulAcc bin
    | _ -> failwith "Wrong opcode in group000."
  opcode, None, operands

/// MSR (immediate) and hints, page A5-206
let getMSRNHints bin =
  let op12 = concat (extract bin 19u 16u) (extract bin 7u 0u) 8
  let op = concat (pickBit bin 22u) op12 12
  match op with
  | 0b0000000000000u -> Op.NOP, NoOperand
  | 0b0000000000001u -> Op.YIELD, NoOperand
  | 0b0000000000010u -> Op.WFE, NoOperand
  | 0b0000000000011u -> Op.WFI, NoOperand
  | 0b0000000000100u -> Op.SEV, NoOperand
  | op when op &&& 0b1111111110000u = 0b0000011110000u ->
    Op.DBG, p1Opr bin dummyChk getImm4A
  | op when op &&& 0b1111100000000u = 0b0010000000000u ->
    Op.MSR, p2Oprs bin dummyChk (getAPSRxB, getImm12C)
  | op when op &&& 0b1101100000000u = 0b0100000000000u ->
    Op.MSR, p2Oprs bin dummyChk (getAPSRxB, getImm12C)
  | op when op &&& 0b1001100000000u = 0b0000100000000u ->
    Op.MSR, p2Oprs bin chkUnpreX (getRegQ, getImm12E)
  | op when op &&& 0b1001000000000u = 0b0001000000000u ->
    Op.MSR, p2Oprs bin chkUnpreX (getRegQ, getImm12E)
  | op when op &&& 0b1000000000000u = 0b1000000000000u ->
    Op.MSR, p2Oprs bin chkUnpreX (getRegQ, getImm12E)
  | _ -> failwith "Wrong MSR or Hints opcode."

/// Data-processing (immediate), page A5-199
/// ADR is integrated into ADD or SUB respectively
let dataProcImm op bin =
  match op with
  | 0b00000u -> Op.AND, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b00001u -> Op.ANDS, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b00010u -> Op.EOR, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b00011u -> Op.EORS, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b00100u -> Op.SUB, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b00101u -> Op.SUBS, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b00110u -> Op.RSB, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b00111u -> Op.RSBS, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b01000u -> Op.ADD, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b01001u -> Op.ADDS, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b01010u -> Op.ADC, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b01011u -> Op.ADCS, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b01100u -> Op.SBC, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b01101u -> Op.SBCS, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b01110u -> Op.RSC, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b01111u -> Op.RSCS, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b10001u -> Op.TST, p2Oprs bin dummyChk (getRegC, getImm12A)
  | 0b10011u -> Op.TEQ, p2Oprs bin dummyChk (getRegC, getImm12A)
  | 0b10101u -> Op.CMP, p2Oprs bin dummyChk (getRegC, getImm12A)
  | 0b10111u -> Op.CMN, p2Oprs bin dummyChk (getRegC, getImm12A)
  | 0b11000u -> Op.ORR, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b11001u -> Op.ORRS, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b11010u -> Op.MOV, p2Oprs bin dummyChk (getRegD, getImm12A)
  | 0b11011u -> Op.MOVS, p2Oprs bin dummyChk (getRegD, getImm12A)
  | 0b11100u -> Op.BIC, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b11101u -> Op.BICS, p3Oprs bin dummyChk (getRegD, getRegC, getImm12A)
  | 0b11110u -> Op.MVN, p2Oprs bin dummyChk (getRegD, getImm12A)
  | 0b11111u -> Op.MVNS, p2Oprs bin dummyChk (getRegD, getImm12A)
  | _ -> failwith "Wrong data-processing (Immediate)."

let getVMOVVORR bin =
  let n = pickBit bin 7u
  let m = pickBit bin 5u
  let vn = extract bin 19u 16u
  let vm = extract bin 3u 0u
  if n = m && vn = vm then Op.VMOV, p2Oprs bin chkUndefH (getRegX, getRegZ)
  else Op.VORR, p3Oprs bin chkUndefD (getRegX, getRegY, getRegZ)

let getXYZRegOprs bin chkUndef = p3Oprs bin chkUndef (getRegX, getRegY, getRegZ)

let getXZYRegOprs bin chkUndef = p3Oprs bin chkUndef (getRegX, getRegZ, getRegY)

let get3RegBitwise bin k =
  match concat k (extract bin 21u 20u) 2 with
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
  match pickBit bin 4u, k, pickBit bin 21u with
  | 0u, 0u, 0u -> Op.VADD, getXYZRegOprs bin chkUndefL
  | 0u, 0u, 1u -> Op.VSUB, getXYZRegOprs bin chkUndefL
  | 0u, 1u, 0u -> Op.VPADD, getXYZRegOprs bin chkUndefM
  | 0u, 1u, 1u -> Op.VABD, getXYZRegOprs bin chkUndefL
  | 1u, 0u, 0u -> Op.VMLA, getXYZRegOprs bin chkUndefL
  | 1u, 0u, 1u -> Op.VMLS, getXYZRegOprs bin chkUndefL
  | 1u, 1u, 0u -> Op.VMUL, getXYZRegOprs bin chkUndefL
  | _ -> failwith "Wrong 3 register floating point."

let get3RegCompare bin k =
  match pickBit bin 4u, k, pickBit bin 21u with
  | 0u, 0u, 0u -> Op.VCEQ
  | 0u, 1u, 0u -> Op.VCGE
  | 0u, 1u, 1u -> Op.VCGT
  | 1u, 1u, 0u -> Op.VACGE
  | 1u, 1u, 1u -> Op.VACGT
  | _ -> failwith "Wrong 3 register compare."
  , getOneDtG bin, getXYZRegOprs bin chkUndefL

let get3RegMaxMinNReciprocal bin k =
  match pickBit bin 4u, k, pickBit bin 21u with
  | 0u, 0u, 0u -> Op.VMAX, getOneDtG bin, getXYZRegOprs bin chkUndefL
  | 0u, 0u, 1u -> Op.VMIN, getOneDtG bin, getXYZRegOprs bin chkUndefL
  | 0u, 1u, 0u -> Op.VPMAX, getOneDtG bin, getXYZRegOprs bin chkUndefM
  | 0u, 1u, 1u -> Op.VPMIN, getOneDtG bin, getXYZRegOprs bin chkUndefM
  | 1u, 0u, 0u -> Op.VRECPS, getOneDtG bin, getXYZRegOprs bin chkUndefL
  | 1u, 0u, 1u -> Op.VRSQRTS, getOneDtG bin, getXYZRegOprs bin chkUndefL
  | _ -> failwith "Wrong 3 register max/min & reciprocal."

/// Three registers of the same length, page A7-262
let parse3Reg bin k =
  let chkU () = k = 0b0u
  match concat (extract bin 11u 8u) (pickBit bin 4u) 1 with
  | 0b00000u -> Op.VHADD, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b00001u -> Op.VQADD, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b00010u -> Op.VRHADD, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b00011u -> let opcode, oprs = get3RegBitwise bin k in opcode, None, oprs
  | 0b00100u -> Op.VHSUB, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b00101u -> Op.VQSUB, getOneDtD k bin, getXYZRegOprs bin chkUndefD
  | 0b00110u -> Op.VCGT, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b00111u -> Op.VCGE, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b01000u -> Op.VSHL, getOneDtD k bin, getXZYRegOprs bin chkUndefF
  | 0b01001u -> Op.VQSHL, getOneDtD k bin, getXZYRegOprs bin chkUndefF
  | 0b01010u -> Op.VRSHL, getOneDtD k bin, getXZYRegOprs bin chkUndefF
  | 0b01011u -> Op.VQRSHL, getOneDtD k bin, getXZYRegOprs bin chkUndefF
  | 0b01100u -> Op.VMAX, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b01101u -> Op.VMIN, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b01110u -> Op.VABD, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b01111u -> Op.VABA, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b10000u when chkU () -> Op.VADD, getOneDtF bin, getXYZRegOprs bin chkUndefJ
  | 0b10000u -> Op.VSUB, getOneDtF bin, getXYZRegOprs bin chkUndefJ
  | 0b10001u when chkU () -> Op.VTST, getOneDtF bin, getXYZRegOprs bin chkUndefD
  | 0b10001u ->Op.VCEQ, getOneDtF bin, getXYZRegOprs bin chkUndefD
  | 0b10010u when chkU () -> Op.VMLA, getOneDtF bin, getXYZRegOprs bin chkUndefD
  | 0b10010u -> Op.VMLS, getOneDtF bin, getXYZRegOprs bin chkUndefD
  | 0b10011u -> Op.VMUL, getOneDtF bin, getXYZRegOprs bin chkUndefD
  | 0b10100u -> Op.VPMAX, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b10101u -> Op.VPMIN, getOneDtD k bin, getXYZRegOprs bin chkUndefF
  | 0b10110u when chkU () ->
    Op.VQDMULH, getOneDtF bin, getXYZRegOprs bin chkUndefK
  | 0b10110u -> Op.VQRDMULH, getOneDtF bin,  getXYZRegOprs bin chkUndefK
  | 0b10111u -> Op.VPADD, getOneDtF bin,  getXYZRegOprs bin chkUndefD
  | op when op &&& 0b11110u = 0b11010u ->
    let opcode, oprs = get3RegFloat bin k in opcode, getOneDtG bin, oprs
  | op when op &&& 0b11110u = 0b11100u -> get3RegCompare bin k
  | op when op &&& 0b11110u = 0b11110u -> get3RegMaxMinNReciprocal bin k
  | _ -> failwith "Wrong 3 register."

/// One register and a modified immediate value, page A7-269
let parse1Reg bin k =
  let opcode =
    match concat (pickBit bin 5u) (extract bin 11u 8u) 4 with
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
  opcode, getOneDtH bin, p2Oprs bin chkUndefN (getRxIa opcode k)

/// Two registers and a shift amount, page A7-266
let parse2Reg bin k =
  let chk () = extract bin 18u 16u = 0u
  match concat (extract bin 11u 6u) k 1 with
  | op when op &&& 0b1111000u = 0b0000000u ->
    Op.VSHR, getOneDtJ k bin, p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111000u = 0b0001000u ->
    Op.VSRA, getOneDtJ k bin, p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111000u = 0b0010000u ->
    Op.VRSHR, getOneDtJ k bin, p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111000u = 0b0011000u ->
    Op.VRSRA, getOneDtJ k bin, p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111001u = 0b0100001u ->
    Op.VSRI, getOneDtK bin, p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111001u = 0b0101000u ->
    Op.VSHL, getOneDtL bin, p3Oprs bin chkUndefH (getRegX, getRegZ, getImmC)
  | op when op &&& 0b1111001u = 0b0101001u ->
    Op.VSLI, getOneDtK bin, p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111000u = 0b0110000u ->
    Op.VQSHLU, getOneDtJ k bin, p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | op when op &&& 0b1111000u = 0b0111000u ->
    Op.VQSHL, getOneDtJ k bin, p3Oprs bin chkUndefH (getRegX, getRegZ, getImmB)
  | 0b1000000u ->
    Op.VSHRN, getOneDtM bin, p3Oprs bin chkUndefO (getRegAC, getRegAD, getImmD)
  | 0b1000010u ->
    Op.VRSHRN, getOneDtM bin, p3Oprs bin chkUndefO (getRegAC, getRegAD, getImmD)
  | 0b1000001u ->
    Op.VQSHRUN, getOneDtN bin,
    p3Oprs bin chkUndefO (getRegAC, getRegAD, getImmD)
  | 0b1000011u ->
    Op.VQRSHRUN, getOneDtN bin,
    p3Oprs bin chkUndefO (getRegAC, getRegAD, getImmD)
  | op when op &&& 0b1111010u = 0b1001000u ->
    Op.VQSHRN, getOneDtO k bin,
    p3Oprs bin chkUndefO (getRegAC, getRegAD, getImmE)
  | op when op &&& 0b1111010u = 0b1001010u ->
    Op.VQRSHRN, getOneDtO k bin,
    p3Oprs bin chkUndefO (getRegAC, getRegAD, getImmE)
  | op when op &&& 0b1111010u = 0b1010000u && chk () ->
    Op.VMOVL, getOneDtP k bin,
    p3Oprs bin chkUndefO (getRegAE, getRegAF, getImmF)
  | op when op &&& 0b1111010u = 0b1010000u ->
    Op.VSHLL, getOneDtP k bin,
    p3Oprs bin chkUndefO (getRegAE, getRegAF, getImmF)
  | op when op &&& 0b1110000u = 0b1110000u ->
    Op.VCVT, getTwoDtA k bin, p3Oprs bin chkUndefP (getRegX, getRegZ, getImmG)
  | _ -> failwith "Wrong 2 register."

/// Three registers of different lengths, page A7-264
let parse3RegDiffLen bin k =
  match concat (extract bin 11u 8u) k 1 with
  | op when op &&& 0b11110u = 0b00000u ->
    Op.VADDL, getOneDtD k bin,
    p3Oprs bin chkUndefQ (getRegAE, getRegAG, getRegAF)
  | op when op &&& 0b11110u = 0b00010u ->
    Op.VADDW, getOneDtD k bin,
    p3Oprs bin chkUndefQ (getRegAE, getRegAG, getRegAF)
  | op when op &&& 0b11110u = 0b00100u ->
    Op.VSUBL, getOneDtD k bin,
    p3Oprs bin chkUndefQ (getRegAE, getRegAG, getRegAF)
  | op when op &&& 0b11110u = 0b00110u ->
    Op.VSUBW, getOneDtD k bin,
    p3Oprs bin chkUndefQ (getRegAE, getRegAG, getRegAF)
  | 0b01000u ->
    Op.VADDHN, getOneDtQ bin, p3Oprs bin chkUndefR (getRegAC, getRegU, getRegAD)
  | 0b01001u ->
    Op.VRADDHN, getOneDtQ bin,
    p3Oprs bin chkUndefR (getRegAC, getRegU, getRegAD)
  | op when op &&& 0b11110u = 0b01010u ->
    Op.VABAL, getOneDtD k bin,
    p3Oprs bin chkUndefS (getRegAE, getRegV, getRegAF)
  | 0b01100u ->
    Op.VSUBHN, getOneDtQ bin, p3Oprs bin chkUndefR (getRegAC, getRegU, getRegAD)
  | 0b01101u ->
    Op.VRSUBHN, getOneDtQ bin,
    p3Oprs bin chkUndefR (getRegAC, getRegU, getRegAD)
  | op when op &&& 0b11110u = 0b01110u ->
    Op.VABDL, getOneDtD k bin,
    p3Oprs bin chkUndefS (getRegAE, getRegV, getRegAF)
  | op when op &&& 0b11110u = 0b10000u ->
    Op.VMLAL, getOneDtD k bin,
    p3Oprs bin chkUndefS (getRegAE, getRegV, getRegAF)
  | op when op &&& 0b11110u = 0b10100u ->
    Op.VMLSL, getOneDtD k bin,
    p3Oprs bin chkUndefS (getRegAE, getRegV, getRegAF)
  | op when op &&& 0b11110u = 0b10010u ->
    Op.VQDMLAL, getOneDtA bin,
    p3Oprs bin chkUndefT (getRegAE, getRegU, getRegAD)
  | op when op &&& 0b11110u = 0b10110u ->
    Op.VQDMLSL, getOneDtA bin,
    p3Oprs bin chkUndefT (getRegAE, getRegU, getRegAD)
  | op when op &&& 0b11110u = 0b11000u ->
    Op.VMULL, getOneDtR k bin,
    p3Oprs bin chkUndefS (getRegAE, getRegV, getRegAF)
  | 0b11010u ->
    Op.VQDMULL, getOneDtA bin,
    p3Oprs bin chkUndefT (getRegAE, getRegU, getRegAD)
  | op when op &&& 0b11110u = 0b11100u ->
    Op.VMULL, getOneDtR k bin,
    p3Oprs bin chkUndefS (getRegAE, getRegV, getRegAF)
  | _ -> failwith "Wrong 3 register different lengths."

/// Two registers and a scalar, page A7-265
let parse2RegScalar bin k =
  match concat (extract bin 11u 8u) k 1 with
  | op when op &&& 0b11100u = 0b00000u ->
    Op.VMLA, getOneDtB bin, p3Oprs bin (chkUndefB k) (getRrRsSCa k)
  | op when op &&& 0b11100u = 0b01000u ->
    Op.VMLS, getOneDtB bin, p3Oprs bin (chkUndefB k) (getRrRsSCa k)
  | op when op &&& 0b11110u = 0b00100u ->
    Op.VMLAL, getOneDtD k bin,
    p3Oprs bin chkUndefC (getRegAE, getRegV, getScalarA)
  | op when op &&& 0b11110u = 0b01100u ->
    Op.VMLSL, getOneDtD k bin,
    p3Oprs bin chkUndefC (getRegAE, getRegV, getScalarA)
  | 0b00110u ->
    Op.VQDMLAL, getOneDtA bin,
    p3Oprs bin chkUndefC (getRegAE, getRegV, getScalarA)
  | 0b01110u ->
    Op.VQDMLSL, getOneDtA bin,
    p3Oprs bin chkUndefC (getRegAE, getRegV, getScalarA)
  | op when op &&& 0b11100u = 0b10000u ->
    Op.VMUL, getOneDtB bin, p3Oprs bin (chkUndefB k) (getRrRsSCa k)
  | op when op &&& 0b11110u = 0b10100u ->
    Op.VMULL, getOneDtD k bin,
    p3Oprs bin chkUndefC (getRegAE, getRegV, getScalarA)
  | 0b10110u ->
    Op.VQDMULL, getOneDtA bin,
    p3Oprs bin chkUndefC (getRegAE, getRegV, getScalarA)
  | op when op &&& 0b11110u = 0b11000u ->
    Op.VQDMULH, getOneDtA bin, p3Oprs bin (chkUndefA k) (getRrRsSCa k)
  | op when op &&& 0b11110u = 0b11010u ->
    Op.VQRDMULH, getOneDtA bin, p3Oprs bin (chkUndefA k) (getRrRsSCa k)
  | _ -> failwith "Wrong 2 register scalar."

/// Two registers, miscellaneous, page A7-267
let parse2RegMis b =
  let isBit6 () = pickBit b 6u = 0b0u
  match concat (extract b 17u 16u) (extract b 10u 7u) 4 with
  | 0b000000u -> Op.VREV64, getOneDtS b, p2Oprs b chkUndefU (getRegX, getRegZ)
  | 0b000001u -> Op.VREV32, getOneDtS b, p2Oprs b chkUndefU (getRegX, getRegZ)
  | 0b000010u -> Op.VREV16, getOneDtS b, p2Oprs b chkUndefU (getRegX, getRegZ)
  | o when o &&& 0b111110u = 0b000100u ->
    Op.VPADDL, getOneDtC b, p2Oprs b chkUndefV (getRegX, getRegZ)
  | 0b001000u -> Op.VCLS, getOneDtT b, p2Oprs b chkUndefX (getRegX, getRegZ)
  | 0b001001u -> Op.VCLZ, getOneDtU b, p2Oprs b chkUndefX (getRegX, getRegZ)
  | 0b001010u -> Op.VCNT, getOneDtE (), p2Oprs b chkUndefY (getRegX, getRegZ)
  | 0b001011u -> Op.VMVN, None, p2Oprs b chkUndefY (getRegX, getRegZ)
  | o when o &&& 0b111110u = 0b001100u ->
    Op.VPADAL, getOneDtC b, p2Oprs b chkUndefV (getRegX, getRegZ)
  | 0b001110u -> Op.VQABS, getOneDtT b, p2Oprs b chkUndefX (getRegX, getRegZ)
  | 0b001111u -> Op.VQNEG, getOneDtT b, p2Oprs b chkUndefX (getRegX, getRegZ)
  | o when o &&& 0b110111u = 0b010000u ->
    Op.VCGT, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | o when o &&& 0b110111u = 0b010001u ->
    Op.VCGE, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | o when o &&& 0b110111u = 0b010010u ->
    Op.VCEQ, getOneDtW b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | o when o &&& 0b110111u = 0b010011u ->
    Op.VCLE, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | o when o &&& 0b110111u = 0b010100u ->
    Op.VCLT, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | o when o &&& 0b110111u = 0b010110u ->
    Op.VABS, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | o when o &&& 0b110111u = 0b010111u ->
    Op.VNEG, getOneDtV b, p3Oprs b chkUndefAC (getRegX, getRegZ, getImm0)
  | 0b100000u -> Op.VSWP, None, p2Oprs b chkUndefZ (getRegX, getRegZ)
  | 0b100001u -> Op.VTRN, getOneDtS b, p2Oprs b chkUndefAA (getRegX, getRegZ)
  | 0b100010u -> Op.VUZP, getOneDtS b, p2Oprs b chkUndefAB (getRegX, getRegZ)
  | 0b100011u -> Op.VZIP, getOneDtS b, p2Oprs b chkUndefAB (getRegX, getRegZ)
  | 0b100100u when isBit6 () ->
    Op.VMOVN, getOneDtX b, p2Oprs b chkUndefAD (getRegAC, getRegAD)
  | 0b100100u ->
    Op.VQMOVUN, getOneDtY b, p2Oprs b chkUndefAD (getRegAC, getRegAD)
  | 0b100101u when isBit6 () ->
    Op.VQMOVN, getOneDtY b, p2Oprs b chkUndefAD (getRegAC, getRegAD)
  | 0b100101u ->
    Op.VQMOVN, getOneDtY b, p2Oprs b chkUndefAD (getRegAC, getRegAD)
  | 0b100110u when isBit6 () ->
    Op.VSHLL, getOneDtU b, p2Oprs b chkUndefAD (getRegAC, getRegAD)
  | o when o &&& 0b111101u = 0b101100u && isBit6 () ->
    Op.VCVT, getTwoDtC b, p2Oprs b chkUndefAE (getRegX, getRegZ)
  | o when o &&& 0b111101u = 0b111000u ->
    Op.VRECPE, getOneDtZ b, p2Oprs b chkUndefAF (getRegX, getRegZ)
  | o when o &&& 0b111101u = 0b111001u ->
    Op.VRSQRTE, getOneDtZ b, p2Oprs b chkUndefAF (getRegX, getRegZ)
  | o when o &&& 0b111100u = 0b111100u ->
    Op.VCVT, getTwoDtB b, p2Oprs b chkUndefW (getRegX, getRegZ)
  | _ -> failwith "Wrong 2 register miscellaneous."

/// Advanced SIMD data-processing instructions, page A7-261
let parseAdvSIMDDataProc b mode =
  let ext f t v = extract b f t = v
  let pick u v = pickBit b u = v
  let k = if mode = ArchOperationMode.ARMMode then pickBit b 24u else pickBit b 28u
  let cU () = k = 0b0u
  match concat (extract b 23u 19u) (extract b 7u 4u) 4 with
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
  | op when op &&& 0b101100001u = 0b101100000u && cU () ->
    Op.VEXT, getOneDtE (),
    p4Oprs b chkUndefG (getRegX, getRegY, getRegZ, getImm4C)
  | op when op &&& 0b101100001u = 0b101100000u && pick 11u 0b0u ->
    parse2RegMis b
  | op when op &&& 0b101100101u = 0b101100000u && ext 11u 10u 0b10u ->
    Op.VTBL, getOneDtE (), p3Oprs b dummyChk (getRegAC, getRegListA, getRegAF)
  | op when op &&& 0b101100101u = 0b101100100u && ext 11u 10u 0b10u ->
    Op.VTBX, getOneDtE (), p3Oprs b dummyChk (getRegAC, getRegListA, getRegAF)
  | op when op &&& 0b101101001u = 0b101100000u && ext 11u 8u 0b1100u ->
    Op.VDUP, getOneDtAB b, p2Oprs b chkUndefAG (getRegX, getScalarB)
  | _ -> failwith "Wrong Advanced SIMD data-processing instrs encoding."

/// Data-processing and miscellaneous instructions, page A5-196
let parseGroup001 bin =
  let op = extract bin 24u 20u
  let opcode, operands =
    match op with
    | op when op &&& 0b11001u <> 0b10000u -> dataProcImm op bin
    | 0b10000u -> Op.MOVW, p2Oprs bin dummyChk (getRegD, getImm12B)
    | 0b10100u -> Op.MOVT, p2Oprs bin dummyChk (getRegD, getImm12B)
    | op when op &&& 0b11011u = 0b10010u -> getMSRNHints bin
    | _ -> failwith "Wrong opcode in group001."
  opcode, None, operands

/// Advanced SIMD element or structure load/store instructions, page A7-275
let getAdvSIMDOrStrct bin =
  let op = concat (pickBit bin 23u) (extract bin 11u 8u) 4
  match concat op (pickBit bin 21u) 1 (* A B L *) with
  | 0b000100u | 0b001100u ->
    Op.VST1, getOneDtAC bin, p2Oprs bin chkUndefAH (getRegListB, getMemS)
  | 0b001110u | 0b010100u ->
    Op.VST1, getOneDtAC bin, p2Oprs bin chkUndefAH (getRegListB, getMemS)
  | 0b000110u | 0b010000u | 0b010010u ->
    Op.VST2, getOneDtAC bin, p2Oprs bin chkUndefAI (getRegListB, getMemS)
  | 0b001000u | 0b001010u ->
    Op.VST3, getOneDtAC bin, p2Oprs bin chkUndefAJ (getRegListB, getMemS)
  | 0b000000u | 0b000010u ->
    Op.VST4, getOneDtAC bin, p2Oprs bin chkUndefAK (getRegListB, getMemS)
  | 0b100000u | 0b101000u | 0b110000u ->
    Op.VST1, getOneDtAD bin, p2Oprs bin chkUndefAL (getRegListC, getMemT)
  | 0b100010u | 0b101010u | 0b110010u ->
    Op.VST2, getOneDtAD bin, p2Oprs bin chkUndefAM (getRegListD, getMemU)
  | 0b100100u | 0b101100u | 0b110100u ->
    Op.VST3, getOneDtAD bin, p2Oprs bin chkUndefAN (getRegListE, getMemV)
  | 0b100110u | 0b101110u | 0b110110u ->
    Op.VST4, getOneDtAD bin, p2Oprs bin chkUndefAO (getRegListF, getMemW)
  | 0b000101u | 0b001101u ->
    Op.VLD1, getOneDtAC bin, p2Oprs bin chkUndefAH (getRegListB, getMemS)
  | 0b001111u | 0b010101u ->
    Op.VLD1, getOneDtAC bin, p2Oprs bin chkUndefAH (getRegListB, getMemS)
  | 0b000111u | 0b010001u | 0b010011u ->
    Op.VLD2, getOneDtAC bin, p2Oprs bin chkUndefAI (getRegListB, getMemS)
  | 0b001001u | 0b001011u ->
    Op.VLD3, getOneDtAC bin, p2Oprs bin chkUndefAJ (getRegListB, getMemS)
  | 0b000001u | 0b000011u ->
    Op.VLD4, getOneDtAC bin, p2Oprs bin chkUndefAK (getRegListB, getMemS)
  | 0b100001u | 0b101001u | 0b110001u ->
    Op.VLD1, getOneDtAD bin, p2Oprs bin chkUndefAL (getRegListC, getMemT)
  | 0b100011u | 0b101011u | 0b110011u ->
    Op.VLD2, getOneDtAD bin, p2Oprs bin chkUndefAM (getRegListD, getMemU)
  | 0b100101u | 0b101101u | 0b110101u ->
    Op.VLD3, getOneDtAD bin, p2Oprs bin chkUndefAN (getRegListE, getMemV)
  | 0b100111u | 0b101111u | 0b110111u ->
    Op.VLD4, getOneDtAD bin, p2Oprs bin chkUndefAO (getRegListF, getMemW)
  | 0b111001u ->
    Op.VLD1, getOneDtAC bin, p2Oprs bin chkUndefAP (getRegListG, getMemX)
  | 0b111011u ->
    Op.VLD2, getOneDtAC bin, p2Oprs bin chkUndefAQ (getRegListH, getMemY)
  | 0b111101u ->
    Op.VLD3, getOneDtAC bin, p2Oprs bin chkUndefAR (getRegListI, getMemZ)
  | 0b111111u ->
    Op.VLD4, getOneDtAE bin, p2Oprs bin chkUndefAS (getRegListJ, getMemAA)
  | _ -> failwith "Wrong advanced SIMD or struct."

/// Memory hints, Advanced SIMD instructions, and miscellaneous instructions,
/// page A5-217
let uncond010 bin =
  let op = extract bin 24u 20u
  let chkRn () = extract bin 19u 16u = 0b1111u
  let chk1 op = op &&& 0b10001u
  let chk2 op = op &&& 0b10111u
  match op with
  | op when chk1 op = 0b00000u -> getAdvSIMDOrStrct bin
  | op when chk2 op = 0b00001u -> Op.NOP, None, NoOperand
  | op when chk2 op = 0b00101u -> Op.PLI, None, p1Opr bin dummyChk getMemAB
  | op when op &&& 0b10011u = 0b00011u -> raise UnpredictableException
  | op when chk2 op = 0b10001u && chkRn () -> raise UnpredictableException
  | op when chk2 op = 0b10001u -> Op.PLDW, None, p1Opr bin dummyChk getMemAB
  | op when chk2 op = 0b10101u && chkRn () ->
    Op.PLD, None, p1Opr bin dummyChk getMemM
  | op when chk2 op = 0b10101u -> Op.PLD, None, p1Opr bin dummyChk getMemAB
  | 0b10011u -> raise UnpredictableException
  | 0b10111u when extract bin 7u 4u = 0b0001u -> Op.CLREX, None, NoOperand
  | 0b10111u when extract bin 7u 4u = 0b0100u ->
    Op.DSB, None, p1Opr bin dummyChk getOptA
  | 0b10111u when extract bin 7u 4u = 0b0101u ->
    Op.DMB, None, p1Opr bin dummyChk getOptA
  | 0b10111u when extract bin 7u 4u = 0b0110u ->
    Op.ISB, None, p1Opr bin dummyChk getOptA
  | 0b10111u -> raise UnpredictableException // a rest of cases
  | op when op &&& 0b11011u = 0b11011u -> raise UnpredictableException
  | _ -> failwith "Wrong uncond opcode in Group010."

/// Load/store word and unsigned byte, page A5-208
let parseGroup010 b =
  let isPushPop () = extract b 19u 16u = 0b1101u
  let chkRn () = extract b 19u 16u = 0b1111u
  let opcode, operands =
    match extract b 24u 20u with
    | 0b01001u when isPushPop () -> Op.POP, p1Opr b chkUnpreY getRegD
    | 0b10010u when isPushPop () -> Op.PUSH, p1Opr b chkUnpreY getRegD
    | op when op &&& 0b10111u = 0b00010u ->
      Op.STRT, p2Oprs b chkUnpreZ (getRegD, getMemK)
    | op when op &&& 0b00101u = 0b00000u ->
      Op.STR, p2Oprs b chkUnpreAA (getRegD, getMemL)
    | op when op &&& 0b10111u = 0b00011u ->
      Op.LDRT, p2Oprs b chkUnpreW (getRegD, getMemK)
    | op when op &&& 0b00101u = 0b00001u && chkRn () ->
      Op.LDR, p2Oprs b dummyChk (getRegD, getMemM)
    | op when op &&& 0b00101u = 0b00001u ->
      Op.LDR, p2Oprs b chkUnpreAA (getRegD, getMemL)
    | op when op &&& 0b10111u = 0b00110u ->
      Op.STRBT, p2Oprs b chkUnpreW (getRegD, getMemK)
    | op when op &&& 0b00101u = 0b00100u ->
      Op.STRB, p2Oprs b chkUnpreAC (getRegD, getMemL)
    | op when op &&& 0b10111u = 0b00111u ->
      Op.LDRBT, p2Oprs b chkUnpreW (getRegD, getMemK)
    | op when op &&& 0b00101u = 0b00101u && chkRn () ->
      Op.LDRB, p2Oprs b chkUnpreG (getRegD, getMemM)
    | op when op &&& 0b00101u = 0b00101u ->
      Op.LDRB, p2Oprs b chkUnpreAB (getRegD, getMemL)
    | _ -> failwith "Wrong opcode in group010."
  opcode, None, operands

/// Memory hints, Adv SIND instructions, miscellaneous instructions, page A5-217
let uncond0110 bin =
  let opcode, operands =
    match extract bin 24u 20u with
    | op when op &&& 0b10111u = 0b00001u -> Op.NOP, NoOperand
    | op when op &&& 0b10111u = 0b00101u -> Op.PLI, p1Opr bin chkUnpreD getMemAC
    | op when op &&& 0b10111u = 0b10001u ->
      Op.PLDW, p1Opr bin chkUnpreD getMemAC
    | op when op &&& 0b10111u = 0b10101u -> Op.PLD, p1Opr bin chkUnpreD getMemAC
    | op when op &&& 0b00011u = 0b00011u -> raise UnpredictableException
    | _ -> failwith "Wrong uncond opcode in Group0110."
  opcode, None, operands

/// Load/store word and unsigned byte, page A5-208
let parseGroup0110 bin =
  let opcode, operands =
    match extract bin 24u 20u with
    | o when o &&& 0b10111u = 0b00010u ->
      Op.STRT, p2Oprs bin chkUnpreAL (getRegD, getMemQ)
    | o when o &&& 0b00101u = 0b00000u ->
      Op.STR, p2Oprs bin chkUnpreAM (getRegD, getMemR)
    | o when o &&& 0b10111u = 0b00011u ->
      Op.LDRT, p2Oprs bin chkUnpreV (getRegD, getMemQ)
    | o when o &&& 0b00101u = 0b00001u ->
      Op.LDR, p2Oprs bin chkUnpreAM (getRegD, getMemR)
    | o when o &&& 0b10111u = 0b00110u ->
      Op.STRBT, p2Oprs bin chkUnpreV (getRegD, getMemQ)
    | o when o &&& 0b00101u = 0b00100u ->
      Op.STRB, p2Oprs bin chkUnpreAN (getRegD, getMemR)
    | o when o &&& 0b10111u = 0b00111u ->
      Op.LDRBT, p2Oprs bin chkUnpreV (getRegD, getMemQ)
    | o when o &&& 0b00101u = 0b00101u ->
      Op.LDRB, p2Oprs bin chkUnpreAN (getRegD, getMemR)
    | _ -> failwith "Wrong opcode in Group0110."
  opcode, None, operands

/// Parallel addition and subtraction, signed, page A5-210
let parsePhrallelAddNSubSigned bin =
  match concat (extract bin 21u 20u) (extract bin 7u 5u) 3 with
  | 0b01000u -> Op.SADD16
  | 0b01001u -> Op.SASX
  | 0b01010u -> Op.SSAX
  | 0b01011u -> Op.SSUB16
  | 0b01100u -> Op.SADD8
  | 0b01111u -> Op.SSUB8
  | 0b10000u -> Op.QADD16
  | 0b10001u -> Op.QASX
  | 0b10010u -> Op.QSAX
  | 0b10011u -> Op.QSUB16
  | 0b10100u -> Op.QADD8
  | 0b10111u -> Op.QSUB8
  | 0b11000u -> Op.SHADD16
  | 0b11001u -> Op.SHASX
  | 0b11010u -> Op.SHSAX
  | 0b11011u -> Op.SHSUB16
  | 0b11100u -> Op.SHADD8
  | 0b11111u -> Op.SHSUB8
  | _ -> failwith "Wrong phrallel add and sub, signed."
  , p3Oprs bin chkUnpreA (getRegD, getRegC, getRegA)

/// Parallel addition and subtraction, unsigned, page A5-211
let parsePhrallelAddNSubUnsigned bin =
  match concat (extract bin 21u 20u) (extract bin 7u 5u) 3 with
  | 0b01000u -> Op.UADD16
  | 0b01001u -> Op.UASX
  | 0b01010u -> Op.USAX
  | 0b01011u -> Op.USUB16
  | 0b01100u -> Op.UADD8
  | 0b01111u -> Op.USUB8
  | 0b10000u -> Op.UQADD16
  | 0b10001u -> Op.UQASX
  | 0b10010u -> Op.UQSAX
  | 0b10011u -> Op.UQSUB16
  | 0b10100u -> Op.UQADD8
  | 0b10111u -> Op.UQSUB8
  | 0b11000u -> Op.UHADD16
  | 0b11001u -> Op.UHASX
  | 0b11010u -> Op.UHSAX
  | 0b11011u -> Op.UHSUB16
  | 0b11100u -> Op.UHADD8
  | 0b11111u -> Op.UHSUB8
  | _ -> failwith "Wrong phrallel add and sub, unsigned."
  , p3Oprs bin chkUnpreA (getRegD, getRegC, getRegA)

/// Packing, unpacking, saturation, and reversal, page A5-212
let parsePackingSaturationReversal bin =
  let chk = extract bin 19u 16u
  match concat (extract bin 22u 20u) (extract bin 7u 5u) 3, chk with
  | op, _ when op &&& 0b111011u = 0b000000u ->
    Op.PKHBT, p4Oprs bin chkUnpreC (getRegD, getRegC, getRegA, getShiftD)
  | op, _ when op &&& 0b111011u = 0b000010u ->
    Op.PKHTB, p4Oprs bin chkUnpreC (getRegD, getRegC, getRegA, getShiftD)
  | op, _ when op &&& 0b110001u = 0b010000u ->
    Op.SSAT, p4Oprs bin chkUnpreO (getRegD, getImm5C, getRegA, getShiftD)
  | op, _ when op &&& 0b110001u = 0b110000u ->
    Op.USAT, p4Oprs bin chkUnpreO (getRegD, getImm5C, getRegA, getShiftD)
  | 0b000011u, 0b1111u ->
    Op.SXTB16, p3Oprs bin chkUnpreP (getRegD, getRegA, getShiftC)
  | 0b000011u, _ ->
    Op.SXTAB16, p4Oprs bin chkUnpreO (getRegD, getRegC, getRegA, getShiftC)
  | 0b000101u, _ ->
    Op.SEL, p3Oprs bin chkUnpreA (getRegD, getRegC, getRegA)
  | 0b010001u, _ ->
    Op.SSAT16, p3Oprs bin chkUnpreM (getRegA, getImm4B, getRegA)
  | 0b010011u, 0b1111u ->
    Op.SXTB, p3Oprs bin chkUnpreP (getRegD, getRegA, getShiftC)
  | 0b010011u, _ ->
    Op.SXTAB, p4Oprs bin chkUnpreO (getRegD, getRegC, getRegA, getShiftC)
  | 0b011001u, _ -> Op.REV, p2Oprs bin chkUnpreE (getRegD, getRegA)
  | 0b011011u, 0b1111u ->
    Op.SXTH, p3Oprs bin chkUnpreP (getRegD, getRegA, getShiftC)
  | 0b011011u, _ ->
    Op.SXTAH, p4Oprs bin chkUnpreO (getRegD, getRegC, getRegA, getShiftC)
  | 0b011101u, _ -> Op.REV16, p2Oprs bin chkUnpreE (getRegD, getRegA)
  | 0b100011u, 0b1111u ->
    Op.UXTB16, p3Oprs bin chkUnpreP (getRegD, getRegA, getShiftC)
  | 0b100011u, _ ->
    Op.UXTAB16, p4Oprs bin chkUnpreO (getRegD, getRegC, getRegA, getShiftC)
  | 0b110001u, _ ->
    Op.USAT16, p3Oprs bin chkUnpreM (getRegA, getImm4B, getRegA)
  | 0b110011u, 0b1111u ->
    Op.UXTB, p3Oprs bin chkUnpreP (getRegD, getRegA, getShiftC)
  | 0b110011u, _ ->
    Op.UXTAB, p4Oprs bin chkUnpreO (getRegD, getRegC, getRegA, getShiftC)
  | 0b111001u, _ -> Op.RBIT, p2Oprs bin chkUnpreE (getRegD, getRegA)
  | 0b111011u, 0b1111u ->
    Op.UXTH, p3Oprs bin chkUnpreP (getRegD, getRegA, getShiftC)
  | 0b111011u, _ ->
    Op.UXTAH, p4Oprs bin chkUnpreO (getRegD, getRegC, getRegA, getShiftC)
  | 0b111101u, _ -> Op.REVSH, p2Oprs bin chkUnpreE (getRegD, getRegA)
  | _ -> failwith "Wrong packing, unpacking, saturation, and reversal."

/// Signed multiplies, page A5-213
let parseSignedMultiplies bin =
  let a () = extract bin 15u 12u = 0b1111u
  match concat (extract bin 22u 20u) (extract bin 7u 5u) 3 with
  | 0b000000u when a () ->
    Op.SMUAD, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b000000u ->
    Op.SMLAD, p4Oprs bin chkUnpreC (getRegC, getRegA, getRegB, getRegD)
  | 0b000001u when a () ->
    Op.SMUADX, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b000001u ->
    Op.SMLADX, p4Oprs bin chkUnpreC (getRegC, getRegA, getRegB, getRegD)
  | 0b000010u when a () ->
    Op.SMUSD, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b000010u ->
    Op.SMLSD, p4Oprs bin chkUnpreC (getRegC, getRegA, getRegB, getRegD)
  | 0b000011u when a () ->
    Op.SMUSDX, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b000011u ->
    Op.SMLSDX, p4Oprs bin chkUnpreC (getRegC, getRegA, getRegB, getRegD)
  | 0b100000u ->
    Op.SMLALD, p4Oprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b100001u ->
    Op.SMLALDX, p4Oprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b100010u ->
    Op.SMLSLD, p4Oprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b100011u ->
    Op.SMLSLDX, p4Oprs bin chkUnpreI (getRegD, getRegC, getRegA, getRegB)
  | 0b101000u when a () ->
    Op.SMMUL, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b101000u ->
    Op.SMMLA, p4Oprs bin chkUnpreC (getRegC, getRegA, getRegB, getRegD)
  | 0b101001u when a () ->
    Op.SMMULR, p3Oprs bin chkUnpreA (getRegC, getRegA, getRegB)
  | 0b101001u ->
    Op.SMMLAR, p4Oprs bin chkUnpreC (getRegC, getRegA, getRegB, getRegD)
  | 0b101110u ->
    Op.SMMLS, p4Oprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
  | 0b101111u ->
    Op.SMMLSR, p4Oprs bin chkUnpreB (getRegC, getRegA, getRegB, getRegD)
  | _ -> failwith "Wrong signed multiplies."

/// Media instructions, page A5-209
let parseGroup0111 cond b =
  let chkRd () = extract b 15u 12u = 0b1111u
  let chkRn () = extract b 3u 0u = 0b1111u
  let isBitField op = op &&& 0b11110011u = 0b11100000u
  let opcode, operands =
    match concat (extract b 24u 20u) (extract b 7u 5u) 3 with
    | o when o &&& 0b11100000u = 0b00000000u -> parsePhrallelAddNSubSigned b
    | o when o &&& 0b11100000u = 0b00100000u -> parsePhrallelAddNSubUnsigned b
    | o when o &&& 0b11000000u = 0b01000000u -> parsePackingSaturationReversal b
    | o when o &&& 0b11000000u = 0b10000000u -> parseSignedMultiplies b
    | 0b11000000u when chkRd () ->
      Op.USAD8, p3Oprs b chkUnpreA (getRegC, getRegA, getRegB)
    | 0b11000000u ->
      Op.USADA8, p4Oprs b chkUnpreB (getRegC, getRegA, getRegB, getRegD)
    | o when o &&& 0b11110011u = 0b11010010u ->
      Op.SBFX, p4Oprs b chkUnpreQ (getRegD, getRegA, getImm5A, getImm5C)
    | o when isBitField o && chkRn () ->
      Op.BFC, p3Oprs b chkUnpreAP (getRegD, getImm5A, getImm5F)
    | o when isBitField o ->
      Op.BFI, p4Oprs b chkUnpreAQ (getRegD, getRegA, getImm5A, getImm5F)
    | o when o &&& 0b11110011u = 0b11110010u ->
      Op.UBFX, p4Oprs b chkUnpreQ (getRegD, getRegA, getImm5A, getImm5C)
    | 0b11111111u when cond = Condition.AL -> Op.UDF, p1Opr b dummyChk getImm12D
    | 0b11111111u -> raise UndefinedException
    | _ -> failwith "Wrong opcode in group0111."
  opcode, None, operands

let getSTM bin =
  match extract bin 24u 23u with
  | 0b00u -> Op.STMDA, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
  | 0b01u -> Op.STMIA, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
  | 0b10u -> Op.STMDB, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
  | 0b11u -> Op.STMIB, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
  | _ -> failwith "Wrong STM."

let getLDMUser bin =
  match extract bin 24u 23u with
  | 0b00u -> Op.LDMDA, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
  | 0b01u -> Op.LDMIA, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
  | 0b10u -> Op.LDMDB, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
  | 0b11u -> Op.LDMIB, p2Oprs bin chkUnpreAR (getRegC, getRegListK)
  | _ -> failwith "Wrong LDM user regs."

let getLDMException bin =
  match extract bin 24u 23u with
  | 0b00u -> Op.LDMDA, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
  | 0b01u -> Op.LDMIA, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
  | 0b10u -> Op.LDMDB, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
  | 0b11u -> Op.LDMIA, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
  | _ -> failwith "Wrong LDM user regs."

/// Unconditional instructions, A5-216
let uncond100 bin =
  let opcode, operands =
    match extract bin 24u 20u with
    | op when op &&& 0b11101u = 0b00100u ->
      Op.SRSDA, p2Oprs bin dummyChk (getRegM, getImm5B)
    | op when op &&& 0b11101u = 0b01100u ->
      Op.SRSIA, p2Oprs bin dummyChk (getRegM, getImm5B)
    | op when op &&& 0b11101u = 0b10100u ->
      Op.SRSDB, p2Oprs bin dummyChk (getRegM, getImm5B)
    | op when op &&& 0b11101u = 0b11100u ->
      Op.SRSIB, p2Oprs bin dummyChk (getRegM, getImm5B)
    | op when op &&& 0b11101u = 0b00001u ->
      Op.RFEDA, p1Opr bin chkUnpreN getRegN
    | op when op &&& 0b11101u = 0b01001u ->
      Op.RFEIA, p1Opr bin chkUnpreN getRegN
    | op when op &&& 0b11101u = 0b10001u ->
      Op.RFEDB, p1Opr bin chkUnpreN getRegN
    | op when op &&& 0b11101u = 0b11001u ->
      Op.RFEIB, p1Opr bin chkUnpreN getRegN
    | _ -> failwith "Wrong uncond opcode in group100."
  opcode, None, operands

/// Branch, branch with link, and block data transfer, page A5-214
let parseGroup100 bin =
  let isPushPop () = extract bin 19u 16u = 0b1101u &&
                     (extract bin 15u 0u |> getRegList).Length >= 2
  let chkR () = pickBit bin 15u = 0b0u
  let opcode, operands =
    match extract bin 24u 20u with
    | op when op &&& 0b11101u = 0b00000u ->
      Op.STMDA, p2Oprs bin chkUnpreAR (getRegisterWA, getRegListK)
    | op when op &&& 0b11101u = 0b00001u ->
      Op.LDMDA, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
    | op when op &&& 0b11101u = 0b01000u ->
      Op.STM, p2Oprs bin chkUnpreAR (getRegisterWA, getRegListK)
    | 0b01001u -> Op.LDM, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
    | 0b01011u when isPushPop () -> Op.POP, p1Opr bin chkUnpreAT getRegListK
    | 0b01011u -> Op.LDM, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
    | 0b10000u -> Op.STMDB, p2Oprs bin chkUnpreAR (getRegisterWA, getRegListK)
    | 0b10010u when isPushPop () -> Op.PUSH, p1Opr bin dummyChk getRegListK
    | 0b10010u -> Op.STMDB, p2Oprs bin chkUnpreAR (getRegisterWA, getRegListK)
    | op when op &&& 0b11101u = 0b10001u ->
      Op.LDMDB, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
    | op when op &&& 0b11101u = 0b11000u ->
      Op.STMIB, p2Oprs bin chkUnpreAR (getRegisterWA, getRegListK)
    | op when op &&& 0b11101u = 0b11001u ->
      Op.LDMIB, p2Oprs bin chkUnpreAS (getRegisterWA, getRegListK)
    | op when op &&& 0b00101u = 0b00100u -> getSTM bin
    | op when op &&& 0b00101u = 0b00101u && chkR () -> getLDMUser bin
    | op when op &&& 0b00101u = 0b00101u -> getLDMException bin
    | _ -> failwith "Wrong opcode in group100."
  opcode, None, operands

/// B, BL, page A5-214
/// Unconditional instructions, A5-216
let parseGroup101 bin =
  match pickBit bin 24u with
  | 0u -> Op.B, None, p1Opr bin dummyChk getLblA
  | 1u -> Op.BL, None, p1Opr bin dummyChk getLbl24B
  | _ -> failwith "Wrong opcode in group7."

/// Unconditional instructions, A5-216
let uncond110 bin =
  let op = extract bin 24u 20u
  let checkRn () = extract bin 19u 16u = 0b1111u
  let chkLDC op = op &&& 0b00101u = 0b00001u
  let chkLDCL op = op &&& 0b00101u = 0b00101u
  let opcode, operands =
    match op with
    | op when chkLDC op && checkRn () ->
      Op.LDC2, p3Oprs bin dummyChk (getPRegA, getCRegA, getMemAD)
    | op when chkLDC op ->
      Op.LDC2, p3Oprs bin dummyChk (getPRegA, getCRegA, getMemAE)
    | op when chkLDCL op && checkRn () ->
      Op.LDC2L, p3Oprs bin dummyChk (getPRegA, getCRegA, getMemAD)
    | op when chkLDCL op ->
      Op.LDC2L, p3Oprs bin dummyChk (getPRegA, getCRegA, getMemAE)
    | op when op &&& 0b11101u = 0b01000u ->
      Op.STC2, p3Oprs bin dummyChk (getPRegA, getCRegA, getMemAE)
    | op when op &&& 0b11101u = 0b01100u ->
      Op.STC2L, p3Oprs bin dummyChk (getPRegA, getCRegA, getMemAE)
    | op when op &&& 0b10101u = 0b10000u ->
      Op.STC2, p3Oprs bin dummyChk (getPRegA, getCRegA, getMemAE)
    | op when op &&& 0b10101u = 0b10100u ->
      Op.STC2L, p3Oprs bin dummyChk (getPRegA, getCRegA, getMemAE)
    | 0b00010u -> Op.STC2, p3Oprs bin dummyChk (getPRegA, getCRegA, getMemAE)
    | 0b00110u -> Op.STC2L, p3Oprs bin dummyChk (getPRegA, getCRegA, getMemAE)
    | 0b00100u -> Op.MCRR2, p5Oprs bin chkUnpreAU
                            (getPRegA, getImm4D, getRegD, getRegC, getCRegB)
    | 0b00101u -> Op.MRRC2, p5Oprs bin chkUnpreAV
                            (getPRegA, getImm4D, getRegD, getRegC, getCRegB)
    | _ -> failwith "Wrong opcode in Unconditional Instr."
  opcode, None, operands

/// 64-bit transfers between ARM core and extension registers, page A7-279
let parse64BitTransfer b =
  let op () = pickBit b 20u = 0b0u
  match extract b 8u 4u &&& 0b11101u with
  | 0b00001u when op () ->
    Op.VMOV, p4Oprs b chkUnpreAW (getRegAI, getRegAJ, getRegD, getRegC)
  | 0b00001u ->
    Op.VMOV, p4Oprs b chkUnpreAX (getRegD, getRegC, getRegAI, getRegAJ)
  | 0b10001u when op () ->
    Op.VMOV, p3Oprs b chkUnpreP (getRegAF, getRegD, getRegC)
  | 0b10001u -> Op.VMOV, p3Oprs b chkUnpreAY (getRegD, getRegC, getRegAF)
  | _ -> failwith "Wrong 64-bit transfers."

/// Extension register load/store instructions, page A7-274
let parseExtRegLoadStore bin =
  let chkRn () = extract bin 19u 16u = 0b1101u
  let chk8 () = pickBit bin 8u = 0b0u
  match extract bin 24u 20u with
  | op when op &&& 0b11110u = 0b00100u -> parse64BitTransfer bin
  | op when op &&& 0b11011u = 0b01000u && chk8 () ->
    Op.VSTMIA, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | op when op &&& 0b11011u = 0b01000u ->
    Op.VSTMIA, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | op when op &&& 0b11011u = 0b01010u && chk8 () ->
    Op.VSTMIA, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | op when op &&& 0b11011u = 0b01010u ->
    Op.VSTMIA, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | op when op &&& 0b10011u = 0b10000u ->
    Op.VSTR, p2Oprs bin dummyChk (getRegAL, getMemAR)
  | op when op &&& 0b11011u = 0b10010u && chkRn () && chk8 () ->
    Op.VPUSH, p1Opr bin chkUnpreBA getRegListM
  | op when op &&& 0b11011u = 0b10010u && chkRn () ->
    Op.VPUSH, p1Opr bin chkUnpreAZ getRegListL
  | op when op &&& 0b11011u = 0b10010u && chk8 () ->
    Op.VSTMDB, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | op when op &&& 0b11011u = 0b10010u ->
    Op.VSTMDB, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | op when op &&& 0b11011u = 0b01001u && chk8 () ->
    Op.VLDMIA, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | op when op &&& 0b11011u = 0b01001u ->
    Op.VLDMIA, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | op when op &&& 0b11011u = 0b01011u && chkRn () && chk8 () ->
    Op.VPOP, p1Opr bin chkUnpreBA getRegListM
  | op when op &&& 0b11011u = 0b01011u && chkRn () ->
    Op.VPOP, p1Opr bin chkUnpreAZ getRegListL
  | op when op &&& 0b11011u = 0b01011u && chk8 () ->
    Op.VLDMIA, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | op when op &&& 0b11011u = 0b01011u ->
    Op.VLDMIA, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | op when op &&& 0b10011u = 0b10001u ->
    Op.VLDR, p2Oprs bin dummyChk (getRegAL, getMemAR)
  | op when op &&& 0b11011u = 0b10011u && chk8 () ->
    Op.VLDMDB, p2Oprs bin chkUnpreBA (getRegisterWA, getRegListM)
  | op when op &&& 0b11011u = 0b10011u ->
    Op.VLDMDB, p2Oprs bin chkUnpreAZ (getRegisterWA, getRegListL)
  | _ -> failwith "Wrong supervisor call, and coprocessor instrs."

/// Supervisor Call, and coprocessor instructions, page A5-215
let parseGroup110 b =
  let chkRn () = extract b 19u 16u <> 0b1111u
  let chkCop () = extract b 11u 9u <> 0b101u
  let chkLDC op = op &&& 0b00101u = 0b00001u
  let chkLDCL op = op &&& 0b00101u = 0b00101u
  let opcode, operands =
    match extract b 24u 20u with
    | op when op &&& 0b11110u = 0b00000u -> raise UndefinedException
    | 0b00100u when chkCop () ->
      Op.MCRR,
      p5Oprs b chkUnpreAU (getPRegA, getImm4D, getRegD, getRegC, getCRegB)
    | 0b00101u when chkCop () ->
      Op.MRRC,
      p5Oprs b chkUnpreAV (getPRegA, getImm4D, getRegD, getRegC, getCRegB)
    | op when op &&& 0b00101u = 0u && chkCop () ->
      Op.STC, p3Oprs b dummyChk (getPRegA, getCRegA, getMemAE)
    | op when op &&& 0b00101u = 4u && chkCop () ->
      Op.STCL, p3Oprs b dummyChk (getPRegA, getCRegA, getMemAE)
    | op when chkLDC op && chkCop () && chkRn () ->
      Op.LDC, p3Oprs b dummyChk (getPRegA, getCRegA, getMemAE)
    | op when chkLDC op && chkCop () ->
      Op.LDC, p3Oprs b dummyChk (getPRegA, getCRegA, getMemAD)
    | op when chkLDCL op && chkCop () && chkRn () ->
      Op.LDCL, p3Oprs b dummyChk (getPRegA, getCRegA, getMemAE)
    | op when chkLDCL op && chkCop () ->
      Op.LDCL, p3Oprs b dummyChk (getPRegA, getCRegA, getMemAD)
    | op when op &&& 0b100000u = 0b000000u -> parseExtRegLoadStore b
    | _ -> failwith "Wrong opcode in group110."
  opcode, None, operands

/// Other VFP data-processing instructions, page A7-272
let parseOtherVFP bin =
  match concat (extract bin 19u 16u) (extract bin 7u 6u) 2 with
  | op when op &&& 0b000001u = 0b000000u ->
    Op.VMOV, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getImmH)
  | 0b000001u ->
    Op.VMOV, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getRegAN)
  | 0b000011u ->
    Op.VABS, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getRegAN)
  | 0b000101u ->
    Op.VNEG, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getRegAN)
  | 0b000111u ->
    Op.VSQRT, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getRegAN)
  | op when op &&& 0b111011u = 0b001001u ->
    Op.VCVTB, getTwoDtE bin, p2Oprs bin dummyChk (getRegAO, getRegAJ)
  | op when op &&& 0b111011u = 0b001011u ->
    Op.VCVTT, getTwoDtE bin, p2Oprs bin dummyChk (getRegAO, getRegAJ)
  | 0b010001u ->
    Op.VCMP, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getRegAN)
  | 0b010011u ->
    Op.VCMPE, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getRegAN)
  | 0b010101u ->
    Op.VCMP, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getImm0)
  | 0b010111u ->
    Op.VCMPE, getOneDtAF bin, p2Oprs bin dummyChk (getRegAL, getImm0)
  | 0b011111u ->
    Op.VCVT, getTwoDtD bin, p2Oprs bin dummyChk (getRegAL, getRegAN)
  | 0b100001u ->
    Op.VCVT, getTwoDtF bin, p2Oprs bin dummyChk (getRegAP, getRegAQ)
  | 0b100011u ->
    Op.VCVTR, getTwoDtG bin, p2Oprs bin dummyChk (getRegAR, getRegAS)
  | op when op &&& 0b111001u = 0b101001u ->
    Op.VCVT, getTwoDtH bin, p3Oprs bin dummyChk (getRegAT, getRegAT, getImmI)
  | op when op &&& 0b111011u = 0b110001u ->
    Op.VCVT, getTwoDtF bin, p2Oprs bin dummyChk (getRegAP, getRegAQ)
  | op when op &&& 0b111011u = 0b110011u ->
    Op.VCVTR, getTwoDtG bin, p2Oprs bin dummyChk (getRegAR, getRegAS)
  | op when op &&& 0b111001u = 0b111001u ->
    Op.VCVT, getTwoDtH bin, p3Oprs bin dummyChk (getRegAT, getRegAT, getImmI)
  | _ -> failwith "Wrong Other VFP."

/// Floating-point data-processing instructions, page A7-272
let parseVFP bin =
  let SIMDTyp = getOneDtAF bin
  match concat (extract bin 23u 20u) (extract bin 7u 6u) 2 with
  | op when op &&& 0b101101u = 0b000000u ->
    Op.VMLA, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b000001u ->
    Op.VMLS, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b000100u ->
    Op.VNMLS, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b000101u ->
    Op.VNMLA, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b001001u ->
    Op.VNMUL, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b001000u ->
    Op.VMUL, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b001100u ->
    Op.VADD, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b001101u ->
    Op.VSUB, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b100000u ->
    Op.VDIV, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b100100u ->
    Op.VFNMS, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b100101u ->
    Op.VFNMA, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b101000u ->
    Op.VFMA, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101101u = 0b101001u ->
    Op.VFMS, SIMDTyp, p3Oprs bin dummyChk (getRegAL, getRegAM, getRegAN)
  | op when op &&& 0b101100u = 0b101100u -> parseOtherVFP bin
  | _ -> failwith "Wrong VFP."

/// 8,16,and 32-bit transfer between ARM core and extension registers, A7-278
let parse81632BTransfer mode b =
  let chkB () = pickBit b 6u = 0b0u
  let chkOp () = pickBit b 20u = 0b0u
  match concat (extract b 23u 20u) (pickBit b 8u) 1 with
  | 0b00000u when chkOp () ->
    Op.VMOV, None, p2Oprs b chkUnpreF (getRegAU, getRegD)
  | 0b00000u ->
    Op.VMOV, None, p2Oprs b chkUnpreG (getRegD, getRegAU)
  | 0b00010u when chkOp () ->
    Op.VMOV, None, p2Oprs b chkUnpreF (getRegAU, getRegD)
  | 0b00010u ->
    Op.VMOV, None, p2Oprs b chkUnpreG (getRegD, getRegAU)
  | 0b11100u ->
    Op.VMSR, None, p2Oprs b chkUnpreF (getRegFPSCR, getRegD)
  | 0b11110u ->
    Op.VMRS, None, p2Oprs b (chkUnpreDL mode) (getRegAZ, getRegFPSCR)
  | o when o &&& 0b10011u = 0b00001u ->
    Op.VMOV, getOneDtAG b, p2Oprs b dummyChk (getScalarC, getRegD)
  | o when o &&& 0b10011u = 0b10001u && chkB () ->
    Op.VDUP, getOneDtI b, p2Oprs b chkUnpreAO (getRegAB, getRegD)
  | o when o &&& 0b00011u = 0b00011u ->
    Op.VMOV, getOneDtAH b, p2Oprs b dummyChk (getRegD, getScalarD)
  | _ -> failwith "Wrong Core and Register."

/// Unconditional instructions, A5-216
let uncond111 bin =
  let opcode, operands =
    match concat (extract bin 24u 20u) (pickBit bin 4u) 1 with
    | op when op &&& 0b100001u = 0u ->
      Op.CDP2, p6Oprs bin dummyChk
               (getPRegA, getImm4E, getCRegA, getCRegC, getCRegB, getImm3B)
    | op when op &&& 0b100011u = 0b000001u ->
      Op.MCR2, p6Oprs bin chkUnpreBB
               (getPRegA, getImm3C, getRegD, getCRegC, getCRegB, getImm3B)
    | op when op &&& 0b100011u = 0b000011u ->
      Op.MRC2, p6Oprs bin dummyChk
               (getPRegA, getImm3C, getRegD, getCRegC, getCRegB, getImm3B)
    | _ -> failwith "Wrong uncond opcode in group111."
  opcode, None, operands

/// Supervisor Call, and coprocessor instructions, page A5-215
let parseGroup111 bin =
  let chkCoprc () = extract bin 11u 9u <> 0b101u
  let opcode, SIMDTyp, operands =
    match concat (extract bin 24u 20u) (pickBit bin 4u) 1 with
    | op when op &&& 0b100000u = 0b100000u ->
      Op.SVC, None, p1Opr bin dummyChk getImm24A
    | op when op &&& 0b100001u = 0b000000u && chkCoprc () ->
      Op.CDP, None, p6Oprs bin dummyChk
                    (getPRegA, getImm4E, getCRegA, getCRegC, getCRegB, getImm3B)
    | op when op &&& 0b100011u = 0b000001u && chkCoprc () ->
      Op.MCR, None, p6Oprs bin chkUnpreBB
                    (getPRegA, getImm3C, getRegD, getCRegC, getCRegB, getImm3B)
    | op when op &&& 0b100011u = 0b000011u && chkCoprc () ->
      Op.MRC, None, p6Oprs bin dummyChk
                    (getPRegA, getImm3C, getRegD, getCRegC, getCRegB, getImm3B)
    | op when op &&& 0b100001u = 0b000000u -> parseVFP bin
    | op when op &&& 0b100001u = 0b000001u ->
      parse81632BTransfer ArchOperationMode.ARMMode bin
    | _ -> failwith "Wrong opcode in group111."
  opcode, SIMDTyp, operands

let uncond000 bin =
  let chkRn () = pickBit bin 16u = 1u
  let opcode, operands =
    match extract bin 7u 4u with
    | op when op &&& 0b0010u = 0b0000u && not (chkRn ()) -> getCPS bin
    | 0b0000u when chkRn ()-> Op.SETEND, p1Opr bin dummyChk getEndianA
    | _ -> failwith "Wrong opcode in group000."
  opcode, None, operands

/// ARM Architecture Reference Manual ARMv7-A and ARMv7-R edition, DDI0406C.b
let parseV7ARMUncond bin =
  let opcode, q, operands =
    match extract bin 27u 25u with
    | op when op &&& 0b111u = 0b000u -> uncond000 bin
    | op when op &&& 0b111u = 0b001u ->
      parseAdvSIMDDataProc bin ArchOperationMode.ARMMode
    | op when op &&& 0b111u = 0b010u -> uncond010 bin
    | op when op &&& 0b111u = 0b011u -> uncond0110 bin
    | op when op &&& 0b111u = 0b100u -> uncond100 bin
    | op when op &&& 0b111u = 0b101u ->
      Op.BLX, None, p1Opr bin dummyChk getLbl26A
    | op when op &&& 0b111u = 0b110u -> uncond110 bin
    | op when op &&& 0b111u = 0b111u -> uncond111 bin
    | _ -> failwith "Wrong group specified."
  opcode, None, None, q, operands

/// ARM Architecture Reference Manual ARMv7-A and ARMv7-R edition, DDI0406C.b
let parseV7ARM bin =
  let op = concat (extract bin 27u 25u) (pickBit bin 4u) 1
  let cond = extract bin 31u 28u |> byte |> parseCond
  if cond = Condition.UN then parseV7ARMUncond bin
  else
    let opcode, SIMDTyp, operands =
      match op with
      | op when op &&& 0b1110u = 0b0000u -> parseGroup000 cond bin
      | op when op &&& 0b1110u = 0b0010u -> parseGroup001 bin
      | op when op &&& 0b1110u = 0b0100u -> parseGroup010 bin
      | op when op &&& 0b1111u = 0b0110u -> parseGroup0110 bin
      | op when op &&& 0b1111u = 0b0111u -> parseGroup0111 cond bin
      | op when op &&& 0b1110u = 0b1000u -> parseGroup100 bin
      | op when op &&& 0b1110u = 0b1010u -> parseGroup101 bin
      | op when op &&& 0b1110u = 0b1100u -> parseGroup110 bin
      | op when op &&& 0b1110u = 0b1110u -> parseGroup111 bin
      | _ -> failwith "Wrong group specified."
    opcode, Some cond, None, SIMDTyp, operands

/// Shift (immediate), add, subtract, move, and compare, page A6-224
let group0LSLInITBlock bin =
  match extract bin 10u 6u with
  | 0b0u -> Op.MOV, p2Oprs bin dummyChk (getRegI, getRegH)
  | _ -> Op.LSL, p3Oprs bin dummyChk (getRegI, getRegH, getImm5D)

/// Shift (immediate), add, subtract, move, and compare, page A6-224
let parseGroup0InITBlock cond bin =
  let opcode, operands =
    match extract bin 13u 9u with
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
  opcode, cond, None, operands

/// Shift (immediate), add, subtract, move, and compare, page A6-224
let group0LSLOutITBlock bin =
  match extract bin 10u 6u with
  | 0b0u -> Op.MOVS, p2Oprs bin dummyChk (getRegI, getRegH)
  | _ -> Op.LSLS, p3Oprs bin dummyChk (getRegI, getRegH, getImm5D)

/// Shift (immediate), add, subtract, move, and compare, page A6-224
let parseGroup0OutITBlock bin =
  let opcode, operands =
    match extract bin 13u 9u with
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
  opcode, None, None, operands

/// Shift (immediate), add, subtract, move, and compare, page A6-224
let parseGroup0 itState bin =
  if extract bin 13u 9u &&& 0b11100u = 0b10100u then
    Op.CMP, getCondWithITSTATE itState, None,
    p2Oprs bin dummyChk (getRegJ, getImm8A)
  else match inITBlock itState with
        | true -> parseGroup0InITBlock (getCondWithITSTATE itState) bin
        | false -> parseGroup0OutITBlock bin

let parseGroup1InITBlock bin =
  match extract bin 9u 6u with
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
  match extract bin 9u 6u with
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
let parseGroup1 itState bin =
  let cond () = getCondWithITSTATE itState
  let parseWithITSTATE () =
    if inITBlock itState then
      let op, opers = parseGroup1InITBlock bin in op, cond (), None, opers
    else let op, opers = parseGroup1OutITBlock bin in op, None, None, opers
  match extract bin 9u 6u with
  | 0b1000u -> Op.TST, cond (), None, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b1010u -> Op.CMP, cond (), None, p2Oprs bin dummyChk (getRegI, getRegH)
  | 0b1011u -> Op.CMN, cond (), None, p2Oprs bin dummyChk (getRegI, getRegH)
  | _ -> parseWithITSTATE ()

let parseGroup2ADD itState bin =
  match concat (pickBit bin 7u) (extract bin 2u 0u) 3, extract bin 6u 3u with
  | 0b1101u, _ -> Op.ADD, p2Oprs bin dummyChk (getRegO, getRegP)
  | _ , 0b1101u ->
    Op.ADD, p3Oprs bin (chkUnpreDF itState) (getRegO, getRegP, getRegO)
  | _ -> Op.ADD, p2Oprs bin (chkUnpreR itState) (getRegO, getRegP)

/// Special data instructions and branch and exchange, page A6-226
let parseGroup2 itState bin =
  let cond = getCondWithITSTATE itState
  let opcode, operands =
    match extract bin 9u 7u with
    | 0b000u | 0b001u -> parseGroup2ADD itState bin
    | 0b010u | 0b011u -> Op.CMP, p2Oprs bin chkUnpreS (getRegO, getRegP)
    | 0b100u | 0b101u ->
      Op.MOV, p2Oprs bin (chkUnpreDF itState) (getRegO, getRegP)
    | 0b110u -> Op.BX, p1Opr bin (chkUnpreDG itState) getRegP
    | 0b111u -> Op.BLX, p1Opr bin (chkUnpreDH itState) getRegP
    | _ -> failwith "Wrong opcode in parseGroup2."
  opcode, cond, None, operands

let parseGroup3Sub cond bin =
  match extract bin 15u 11u with
  | 0b01100u -> Op.STR, cond, None, p2Oprs bin dummyChk (getRegI, getMemE)
  | 0b01101u -> Op.LDR, cond, None, p2Oprs bin dummyChk (getRegI, getMemE)
  | 0b01110u -> Op.STRB, cond, None, p2Oprs bin dummyChk (getRegI, getMemF)
  | 0b01111u -> Op.LDRB, cond, None, p2Oprs bin dummyChk (getRegI, getMemF)
  | 0b10000u -> Op.STRH, cond, None, p2Oprs bin dummyChk (getRegI, getMemG)
  | 0b10001u -> Op.LDRH, cond, None, p2Oprs bin dummyChk (getRegI, getMemG)
  | 0b10010u -> Op.STR, cond, None, p2Oprs bin dummyChk (getRegJ, getMemC)
  | 0b10011u -> Op.LDR, cond, None, p2Oprs bin dummyChk (getRegJ, getMemC)
  | _ -> failwith "Wrong opcode in parseGroup3."

/// Load/store single data item, page A6-227
let parseGroup3 itState bin =
  let cond = getCondWithITSTATE itState
  match concat (extract bin 15u 12u) (extract bin 11u 9u) 3 with
  | 0b0101000u -> Op.STR, cond, None, p2Oprs bin dummyChk (getRegI, getMemD)
  | 0b0101001u -> Op.STRH, cond, None, p2Oprs bin dummyChk (getRegI, getMemD)
  | 0b0101010u -> Op.STRB, cond, None, p2Oprs bin dummyChk (getRegI, getMemD)
  | 0b0101011u -> Op.LDRSB, cond, None, p2Oprs bin dummyChk (getRegI, getMemD)
  | 0b0101100u -> Op.LDR, cond, None, p2Oprs bin dummyChk (getRegI, getMemD)
  | 0b0101101u -> Op.LDRH, cond, None, p2Oprs bin dummyChk (getRegI, getMemD)
  | 0b0101110u -> Op.LDRB, cond, None, p2Oprs bin dummyChk (getRegI, getMemD)
  | 0b0101111u -> Op.LDRSH, cond, None, p2Oprs bin dummyChk (getRegI, getMemD)
  | _ -> parseGroup3Sub cond bin

let getIT fstCond mask =
  let mask0 = pickBit mask 0u
  let mask1 = pickBit mask 1u
  let mask2 = pickBit mask 2u
  let mask3 = pickBit mask 3u
  let checkX () = fstCond = pickBit mask 3u
  let checkY () = fstCond = pickBit mask 2u
  let checkZ () = fstCond = pickBit mask 1u
  let getITOpcodeWithX () = if checkX () then Op.ITT else Op.ITE
  let getITOpcodeWithXY () =
    match checkX (), checkY () with
    | true, true -> Op.ITTT
    | true, false -> Op.ITTE
    | false, true -> Op.ITET
    | false, false -> Op.ITEE
  let getITOpcodeWithXYZ () =
    match checkX (), checkY (), checkZ () with
    | true, true, true -> Op.ITTTT
    | true, true, false -> Op.ITTTE
    | true, false, true -> Op.ITTET
    | true, false, false -> Op.ITTEE
    | false, true, true -> Op.ITETT
    | false, true, false -> Op.ITETE
    | false, false, true -> Op.ITEET
    | false, false, false -> Op.ITEEE
  let opcode =
    match mask3, mask2, mask1, mask0 with
    | 0b1u, 0b0u, 0b0u, 0b0u -> Op.IT
    | _, 0b1u, 0b0u, 0b0u -> getITOpcodeWithX ()
    | _, _, 0b1u, 0b0u -> getITOpcodeWithXY ()
    | _, _, _, 0b1u -> getITOpcodeWithXYZ ()
    | _ -> failwith "Wrong opcode in IT instruction"
  opcode

/// If-Then, and hints, page A6-229
let getIfThenNHints cond itState bin =
  match extract bin 7u 4u, extract bin 3u 0u with
  | o1, o2 when o2 <> 0b0000u ->
    let opcode = getIT (pickBit o1 0u) o2
    let operand = p1Opr bin (chkUnpreBD opcode itState) getFirstCond
    opcode, None, None, operand
  | 0b0000u, _ -> Op.NOP, cond (), None, NoOperand
  | 0b0001u, _ -> Op.YIELD, cond (), None, NoOperand
  | 0b0010u, _ -> Op.WFE, cond (), None, NoOperand
  | 0b0011u, _ -> Op.WFI, cond (), None, NoOperand
  | 0b0100u, _ -> Op.SEV, cond (), None, NoOperand
  | _ -> failwith "Wrong if-then & hints."

/// Miscellaneous 16-bit instructions, page A6-228
let parseGroup4 it bin =
  let cond () = getCondWithITSTATE it
  let chkImod () = pickBit bin 4u = 0b0u
  match extract bin 11u 5u with
  | op when op &&& 0b1111100u = 0b0000000u ->
    Op.ADD, cond (), None, p3Oprs bin dummyChk (getRegSP, getRegSP, getImm7A)
  | op when op &&& 0b1111100u = 0b0000100u ->
    Op.SUB, cond (), None, p3Oprs bin dummyChk (getRegSP, getRegSP, getImm7A)
  | op when op &&& 0b1111000u = 0b0001000u ->
    Op.CBZ, None, None, p2Oprs bin (chkUnpreDE it) (getRegI, getLbl7A)
  | op when op &&& 0b1111110u = 0b0010000u ->
    Op.SXTH, cond (), None, p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111110u = 0b0010010u ->
    Op.SXTB, cond (), None, p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111110u = 0b0010100u ->
    Op.UXTH, cond (), None, p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111110u = 0b0010110u ->
    Op.UXTB, cond (), None, p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111000u = 0b0011000u ->
    Op.CBZ, None, None, p2Oprs bin (chkUnpreDE it) (getRegI, getLbl7A)
  | op when op &&& 0b1110000u = 0b0100000u ->
    Op.PUSH, cond (), None, p1Opr bin chkUnpreBC getRegListN
  | 0b0110010u -> Op.SETEND, None, None, p1Opr bin (chkUnpreDE it) getEndianB
  | 0b0110011u when chkImod () ->
    Op.CPSIE, None, None, p1Opr bin (chkUnpreDE it) getFlagB
  | 0b0110011u -> Op.CPSID, None, None, p1Opr bin (chkUnpreDE it) getFlagB
  | op when op &&& 0b1111000u = 0b1001000u ->
    Op.CBNZ, None, None, p2Oprs bin (chkUnpreDE it) (getRegI, getLbl7A)
  | op when op &&& 0b1111110u = 0b1010000u ->
    Op.REV, cond (), None, p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111110u = 0b1010010u ->
    Op.REV16, cond (), None, p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111110u = 0b1010110u ->
    Op.REVSH, cond (), None, p2Oprs bin dummyChk (getRegI, getRegH)
  | op when op &&& 0b1111000u = 0b1011000u ->
    Op.CBNZ, None, None, p2Oprs bin (chkUnpreDE it) (getRegI, getLbl7A)
  | op when op &&& 0b1110000u = 0b1100000u ->
    Op.POP, cond (), None, p1Opr bin chkUnpreBC getRegListO
  | op when op &&& 0b1111000u = 0b1110000u ->
    Op.BKPT, None, None, p1Opr bin dummyChk getImm8A
  | op when op &&& 0b1111000u = 0b1111000u -> getIfThenNHints cond it bin
  | _ -> failwith "Wrong opcode in parseGroup4."

/// Conditional branch, and Supervisor Call, page A6-229
let parseGroup5 it bin =
  let cond () = getCondWithITSTATE it
  let bCond c = c |> byte |> parseCond |> Some
  match extract bin 11u 8u with
  | 0b1110u -> Op.UDF, cond (), None, p1Opr bin dummyChk getImm8A
  | 0b1111u -> Op.SVC, cond (), None, p1Opr bin dummyChk getImm8A
  | c -> Op.B, bCond c, getQfN (), p1Opr bin (chkUnpreBE it) getLbl9A

/// Load/store multiple. page A6-237
let parseGroup6 it bin =
  let b1, b2 = halve bin
  let b = concat b1 b2 16
  let chkWRn () = concat (pickBit b1 5u) (extract b1 3u 0u) 4 = 0b11101u
  match concat (extract b1 8u 7u) (pickBit b1 4u) 1 with
  | 0b000u -> Op.SRSDB, None, None, p2Oprs b dummyChk (getRegM, getImm5B)
  | 0b001u -> Op.RFEDB, None, None, p1Opr b (chkUnpreDI it) getRegAA
  | 0b010u -> Op.STM, getQfW (), None,
              p2Oprs (b1, b2) chkUnpreBF (getRegisterWB, getRegListP)
  | 0b011u when chkWRn () ->
    Op.POP, getQfW (), None, p1Opr (b1, b2) (chkUnpreBG it) getRegListQ
  | 0b011u -> Op.LDM, getQfW (), None,
              p2Oprs (b1, b2) (chkUnpreBH it) (getRegisterWB, getRegListQ)
  | 0b100u when chkWRn () ->
    Op.PUSH, getQfW (), None, p1Opr (b1, b2) chkUnpreBI getRegListP
  | 0b100u -> Op.STMDB, None, None,
              p2Oprs (b1, b2) chkUnpreBF (getRegisterWB, getRegListP)
  | 0b101u -> Op.LDMDB, None, None,
              p2Oprs (b1, b2) (chkUnpreBH it) (getRegisterWB, getRegListQ)
  | 0b110u -> Op.SRSIA, None, None, p2Oprs b dummyChk (getRegM, getImm5B)
  | 0b111u -> Op.RFEIA, None, None, p1Opr b (chkUnpreDI it) getRegAA
  | _ -> failwith "Wrong opcode in parseGroup6."

/// Load/store dual, load/store exclusive, table branch, page A6-238
let parseGroup7Not010 b1 b2 =
  let op12 = concat (extract b1 8u 7u) (extract b1 5u 4u) 2
  let isRn1111 = extract b1 3u 0u = 0b1111u
  match op12 with
  | o when o &&& 0b1111u = 0b0000u ->
    Op.STREX, p3Oprs (b1, b2) chkUnpreBJ (getRegAV, getRegAW, getMemAF)
  | o when o &&& 0b1111u = 0b0001u ->
    Op.LDREX, p2Oprs (b1, b2) chkUnpreBK (getRegAW, getMemAF)
  | o when o &&& 0b1011u = 0b0010u ->
    Op.STRD, p3Oprs (b1, b2) chkUnpreBM (getRegAW, getRegAV, getMemAH)
  | o when o &&& 0b1001u = 0b1000u ->
    Op.STRD, p3Oprs (b1, b2) chkUnpreBM (getRegAW, getRegAV, getMemAH)
  | o when o &&& 0b1011u = 0b0011u && not isRn1111 ->
    Op.LDRD, p3Oprs (b1, b2) chkUnpreBN (getRegAW, getRegAV, getMemAH)
  | o when o &&& 0b1001u = 0b1001u && not isRn1111 ->
    Op.LDRD, p3Oprs (b1, b2) chkUnpreBN (getRegAW, getRegAV, getMemAH)
  | o when o &&& 0b1011u = 0b0011u && isRn1111 ->
    Op.LDRD, p3Oprs (b1, b2) chkUnpreBO (getRegAW, getRegAV, getMemAI)
  | o when o &&& 0b1001u = 0b1001u && isRn1111 ->
    Op.LDRD, p3Oprs (b1, b2) chkUnpreBO (getRegAW, getRegAV, getMemAI)
  | _ -> failwith "Wrong opcode in parseGroup7."

/// Load/store dual, load/store exclusive, table branch, page A6-238
let parseGroup7With010 it b1 b2 =
  match concat (pickBit b1 4u) (extract b2 6u 4u) 3 with
  | 0b0100u -> Op.STREXB,
               p3Oprs (b1, b2) chkUnpreBJ (getRegAX, getRegAW, getMemAJ)
  | 0b0101u -> Op.STREXH,
               p3Oprs (b1, b2) chkUnpreBJ (getRegAX, getRegAW, getMemAJ)
  | 0b0111u -> Op.STREXD, p4Oprs (b1, b2) chkUnpreBQ
                          (getRegAX, getRegAW, getRegAV, getMemAJ)
  | 0b1000u -> Op.TBB, p1Opr (b1, b2) (chkUnpreBR it) getMemAK
  | 0b1001u -> Op.TBH, p1Opr (b1, b2) (chkUnpreBR it) getMemAL
  | 0b1100u -> Op.LDREXB, p2Oprs (b1, b2) chkUnpreBS (getRegAW, getMemAJ)
  | 0b1101u -> Op.LDREXH, p2Oprs (b1, b2) chkUnpreBS (getRegAW, getMemAJ)
  | 0b1111u -> Op.LDREXD, p3Oprs (b1, b2) chkUnpreBP (getRegAW, getRegAV, getMemAJ)
  | _ -> failwith "Wrong opcode in parseGroup7."

/// Load/store dual, load/store exclusive, table branch, page A6-238
let parseGroup7 itState bin =
  let b1, b2 = halve bin
  let opcode, operands =
    match extract b1 8u 7u, pickBit b1 5u with
    | 0b01u, 0b0u -> parseGroup7With010 itState b1 b2
    | _ -> parseGroup7Not010 b1 b2
  opcode, None, None, operands

/// Move register and immediate shifts, page A6-244
let parseMOVRegImmShift b1 b2 =
  let imm = concat (extract b2 14u 12u) (extract b2 7u 6u) 2
  let oprs2 () = p2Oprs (b1, b2)
  let oprs3 () = p3Oprs (b1, b2)
  match extract b2 5u 4u, imm, pickBit b1 4u with
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
  match extract b1 8u 4u with
  | 0b00000u -> Op.AND, getQfW (), p4Oprs (b1, b2) chkUnpreCA operands
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
  let isNotRdS11111 = concat (extract b2 11u 8u) (pickBit b1 4u) 1 <> 0b11111u
  let getOpr chk =
    p3Oprs (b1, b2) chk (getRegAY, getRegAX, getShiftF)
  if isNotRdS11111 then parseGroup8WithRdSub b1 b2
  else match extract b1 8u 5u with
       | 0b0000u -> Op.TST, getQfW (), getOpr chkUnpreBV
       | 0b0100u -> Op.TEQ, getQfW (), getOpr chkUnpreBV
       | 0b1000u -> Op.CMN, getQfW (), getOpr chkUnpreBW
       | 0b1101u -> Op.CMP, getQfW (), getOpr chkUnpreBW
       | _ -> failwith "Wrong opcode in parseGroup8."

/// Data-processing (shifted register), page A6-243
let parseGroup8WithRnSub b1 b2 =
  match extract b1 6u 5u, pickBit b1 4u with
  | 0b10u, 0u -> Op.ORR
  | 0b10u, 1u -> Op.ORRS
  | 0b11u, 0u -> Op.ORN
  | 0b11u, 1u -> Op.ORNS
  | _ -> failwith "Wrong opcode in parseGroup8."
  , getQfW (),
  p4Oprs (b1, b2) chkUnpreBZ (getRegAV, getRegAY, getRegAX, getShiftF)

/// Data-processing (shifted register), page A6-243
let parseGroup8WithRn b1 b2 =
  if extract b1 3u 0u <> 0b1111u then parseGroup8WithRnSub b1 b2
  else
    match extract b1 6u 4u with
    | 0b100u | 0b101u  -> parseMOVRegImmShift b1 b2
    | 0b110u -> Op.MVN, getQfW (), p3Oprs (b1, b2) chkUnpreBV
                                  (getRegAV, getRegAX, getShiftF)
    | 0b111u -> Op.MVNS, getQfW (), p3Oprs (b1, b2) chkUnpreBV
                                   (getRegAV, getRegAX, getShiftF)
    | _ -> failwith "Wrong opcode in parseGroup8."

/// Data-processing (shifted register), page A6-243
let parseGroup8PKH b1 b2 =
  (if pickBit b2 5u = 1u then Op.PKHTB else Op.PKHBT), None,
  p4Oprs (b1, b2) chkBothB (getRegAV, getRegAY, getRegAX, getShiftF)

/// Data-processing (shifted register), page A6-243
let parseGroup8WithS b1 b2 =
  match extract b1 8u 4u with
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
  let b1, b2 = halve bin
  let opcode, q, operands =
    match extract b1 8u 5u with
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
  opcode, q, None, operands

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9MCRR b =
  if pickBit b 28u = 0b0u then
    Op.MCRR, p5Oprs b chkUnpreAU
           (getPRegA, getImm4D, getRegD, getRegC, getCRegB)
  else Op.MCRR2, p5Oprs b chkUnpreAU
               (getPRegA, getImm4D, getRegD, getRegC, getCRegB)

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9MRRC b =
  if pickBit b 28u = 0b0u then
    Op.MRRC, p5Oprs b chkUnpreAV
           (getPRegA, getImm4D, getRegD, getRegC, getCRegB)
  else Op.MRRC2, p5Oprs b chkUnpreAV
               (getPRegA, getImm4D, getRegD, getRegC, getCRegB)

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9STC b =
  let opcode =
    match pickBit b 28u, pickBit b 22u with
    | 0u, 0u -> Op.STC
    | 0u, 1u -> Op.STCL
    | 1u, 0u -> Op.STC2
    | 1u, 1u -> Op.STC2L
    | _ -> failwith "Wrong opcode in parseGroup9."
  opcode, p3Oprs b dummyChk (getPRegA, getCRegA, getMemAE)

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9LDC b =
  match pickBit b 28u, pickBit b 22u with
  | 0u, 0u -> Op.LDC
  | 0u, 1u -> Op.LDCL
  | 1u, 0u -> Op.LDC2
  | 1u, 1u -> Op.LDC2L
  | _ -> failwith "Wrong opcode in parseGroup9."
  , if extract b 19u 16u = 0b1111u then
      p3Oprs b dummyChk (getPRegA, getCRegA, getMemAD)
    else p3Oprs b dummyChk (getPRegA, getCRegA, getMemAE)

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9CDPMRC b =
  match pickBit b 28u, pickBit b 20u, pickBit b 4u with
  | 0u, _, 0u ->
    Op.CDP, p6Oprs b dummyChk
           (getPRegA, getImm4E, getCRegA, getCRegC, getCRegB, getImm3B)
  | 1u, _, 0u ->
    Op.CDP2, p6Oprs b dummyChk
            (getPRegA, getImm4E, getCRegA, getCRegC, getCRegB, getImm3B)
  | 0u, 0u, 1u ->
    Op.MCR, p6Oprs b chkUnpreBB
           (getPRegA, getImm3C, getRegD, getCRegC, getCRegB, getImm3B)
  | 1u, 0u, 1u ->
    Op.MCR2, p6Oprs b chkUnpreBB
            (getPRegA, getImm3C, getRegD, getCRegC, getCRegB, getImm3B)
  | 0u, 1u, 1u ->
    Op.MRC, p6Oprs b dummyChk
           (getPRegA, getImm3C, getRegD, getCRegC, getCRegB, getImm3B)
  | 1u, 1u, 1u ->
    Op.MRC2, p6Oprs b dummyChk
            (getPRegA, getImm3C, getRegD, getCRegC, getCRegB, getImm3B)
  | _ -> failwith "Wrong opcode in parseGroup9."

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9Sub2 b1 b2 =
  let b = concat b1 b2 16
  let opcode, operands =
    match extract b1 9u 4u with
    | 0b000100u -> parseGroup9MCRR b
    | 0b000101u -> parseGroup9MRRC b
    | op when op &&& 0b100001u = 0b000000u -> parseGroup9STC b
    | op when op &&& 0b100001u = 0b000001u -> parseGroup9LDC b
    | op when op &&& 0b110000u = 0b100000u -> parseGroup9CDPMRC b
    | _ -> failwith "Wrong opcode in parseGroup9."
  opcode, None, operands

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9Sub b1 b2 =
  let b = concat b1 b2 16
  match pickBit b1 9u with
  | 0u -> raise UndefinedException
  | 1u -> parseAdvSIMDDataProc b ArchOperationMode.ThumbMode
  | _ -> failwith "Wrong opcode in parseGroup9."

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9Sub3 b1 b2 =
  let op = concat (extract b1 9u 4u) (pickBit b2 4u) 1
  let b = concat b1 b2 16
  let chk () = op &&& 0b1110100u <> 0b0000000u
  isUndefined (pickBit b1 12u = 0b1u)
  match op with
  | o when o &&& 0b1000000u = 0b0000000u && chk () ->
    let opcode, operands = parseExtRegLoadStore b
    opcode, None, operands
  | o when o &&& 0b1111100u = 0b0001000u ->
    let opcode, operands = parse64BitTransfer b
    opcode, None, operands
  | o when o &&& 0b1000001u = 0b1000000u -> parseVFP b
  | o when o &&& 0b1000001u = 0b1000001u ->
    parse81632BTransfer ArchOperationMode.ThumbMode b
  | _ -> failwith "Wrong opcode in parseGroup9."

/// Co-processor, Advanced SIMD, and Floating-point instructions, page A6-251
let parseGroup9 bin =
  let b1, b2 = halve bin
  let op1 = extract b1 9u 4u
  let chkCoproc = extract b2 11u 8u &&& 0b1110u <> 0b1010u
  let chkSub = op1 = 0u || op1 = 1u || op1 &&& 0b110000u = 0b110000u
  let opcode, dt, operands =
    if chkSub then parseGroup9Sub b1 b2
    elif chkCoproc then parseGroup9Sub2 b1 b2
    else parseGroup9Sub3 b1 b2
  opcode, None, dt, operands

/// Data-processing (modified immediate), page A6-231
let parseGroup10WithRdSub b1 b2 =
  match extract b1 8u 4u with
  | 0b00000u ->
    Op.AND, None, p3Oprs (b1, b2) chkUnpreBV (getRegAV, getRegAY, getImmJ)
  | 0b00001u ->
    Op.ANDS, None, p3Oprs (b1, b2) chkUnpreCD (getRegAV, getRegAY, getImmJ)
  | 0b01000u ->
    Op.EOR, None, p3Oprs (b1, b2) chkUnpreBV (getRegAV, getRegAY, getImmJ)
  | 0b01001u ->
    Op.EORS, None, p3Oprs (b1, b2) chkUnpreCD (getRegAV, getRegAY, getImmJ)
  | 0b10000u ->
    Op.ADD, getQfW (), p3Oprs (b1, b2) chkUnpreCF (getRegAV, getRegAY, getImmJ)
  | 0b10001u ->
    Op.ADDS, getQfW (), p3Oprs (b1, b2) chkUnpreCG (getRegAV, getRegAY, getImmJ)
  | 0b11010u ->
    Op.SUB, getQfW (), p3Oprs (b1, b2) chkUnpreCF (getRegAV, getRegAY, getImmJ)
  | 0b11011u ->
    Op.SUBS, getQfW (), p3Oprs (b1, b2) chkUnpreCG (getRegAV, getRegAY, getImmJ)
  | _ -> failwith "Wrong opcode in parseGroup10."

/// Data-processing (modified immediate), page A6-231
let parseGroup10WithRd b1 b2 =
  let isRdS11111 = concat (extract b2 11u 8u) (pickBit b1 4u) 1 = 0b11111u
  if not isRdS11111 then parseGroup10WithRdSub b1 b2
  else
    match extract b1 8u 5u with
    | 0b0000u -> Op.TST, None, p2Oprs (b1, b2) chkUnpreBL (getRegAY, getImmJ)
    | 0b0100u -> Op.TEQ, None, p2Oprs (b1, b2) chkUnpreBL (getRegAY, getImmJ)
    | 0b1000u -> Op.CMN, None, p2Oprs (b1, b2) chkUnpreCC (getRegAY, getImmJ)
    | 0b1101u ->
      Op.CMP, getQfW (), p2Oprs (b1, b2) chkUnpreCC (getRegAY, getImmJ)
    | _ -> failwith "Wrong opcode in parseGroup10."

/// Data-processing (modified immediate), page A6-231
let parseGroup10WithRnSub b1 b2 =
  let opcode =
    match extract b1 6u 4u with
    | 0b100u -> Op.ORR
    | 0b101u -> Op.ORRS
    | 0b110u -> Op.ORN
    | 0b111u -> Op.ORNS
    | _ -> failwith "Wrong opcode in parseGroup10."
  opcode, None, p3Oprs (b1, b2) chkUnpreCE (getRegAV, getRegAY, getImmJ)

/// Data-processing (modified immediate), page A6-231
let parseGroup10WithRn b1 b2 =
  if extract b1 3u 0u <> 0b1111u then parseGroup10WithRnSub b1 b2
  else
    match extract b1 6u 4u with
    | 0b100u -> Op.MOV, getQfW (), p2Oprs (b1, b2) chkUnpreBL (getRegAV, getImmJ)
    | 0b101u -> Op.MOVS, getQfW (), p2Oprs (b1, b2) chkUnpreBL (getRegAV, getImmJ)
    | 0b110u -> Op.MVN, None, p2Oprs (b1, b2) chkUnpreBL (getRegAV, getImmJ)
    | 0b111u -> Op.MVNS, None, p2Oprs (b1, b2) chkUnpreBL (getRegAV, getImmJ)
    | _ -> failwith "Wrong opcode in parseGroup10."

/// Data-processing (modified immediate), page A6-231
let parseGroup10WithS b1 b2 =
  let opcode, aux =
    match extract b1 8u 4u with
    | 0b00010u -> Op.BIC, None
    | 0b00011u -> Op.BICS, None
    | 0b10100u -> Op.ADC, None
    | 0b10101u -> Op.ADCS, None
    | 0b10110u -> Op.SBC, None
    | 0b10111u -> Op.SBCS, None
    | 0b11100u -> Op.RSB, getQfW ()
    | 0b11101u -> Op.RSBS, getQfW ()
    | _ -> failwith "Wrong opcode in parseGroup10."
  opcode, aux, p3Oprs (b1, b2) chkUnpreBV (getRegAV, getRegAY, getImmJ)

/// Data-processing (modified immediate), page A6-231
let parseGroup10 it bin =
  let b1, b2 = halve bin
  let opcode, q, operands =
    match extract b1 8u 5u with
    | 0b0000u -> parseGroup10WithRd b1 b2
    | 0b0001u -> parseGroup10WithS b1 b2
    | 0b0010u | 0b0011u -> parseGroup10WithRn b1 b2
    | 0b0100u | 0b1000u -> parseGroup10WithRd b1 b2
    | 0b1010u | 0b1011u -> parseGroup10WithS b1 b2
    | 0b1101u -> parseGroup10WithRd b1 b2
    | 0b1110u -> parseGroup10WithS b1 b2
    | _ -> failwith "Wrong opcode in parseGroup10."
  opcode, getCondWithITSTATE it, q, operands

/// Data-processing (plain binary immediate), page A6-234
let parseGroup11 it bin =
  let b1, b2 = halve bin
  let chkRn () = extract b1 3u 0u <> 0b1111u
  let chkA () = concat (extract b2 14u 12u) (extract b2 7u 6u) 2 <> 0b00000u
  let opcode, operands =
    match extract b1 8u 4u with
    | 0b00000u ->
      Op.ADDW, p3Oprs (b1, b2) chkUnpreCH (getRegAV, getRegAY, getImm12F)
    | 0b00100u ->
      Op.MOVW, p2Oprs (b1, b2) chkUnpreBL (getRegAV, getImm16A)
    | 0b01010u ->
      Op.SUBW, p3Oprs (b1, b2) chkUnpreCH (getRegAV, getRegAY, getImm12F)
    | 0b01100u ->
      Op.MOVT, p2Oprs (b1, b2) chkUnpreBL (getRegAV, getImm16A)
    | 0b10000u ->
      Op.SSAT,
      p4Oprs (b1, b2) chkUnpreCI (getRegAV, getImm4F, getRegAY, getShiftI)
    | 0b10010u when chkA () ->
      Op.SSAT,
      p4Oprs (b1, b2) chkUnpreCI (getRegAV, getImm4F, getRegAY, getShiftI)
    | 0b10010u ->
      Op.SSAT16, p3Oprs (b1, b2) chkUnpreCJ (getRegAV, getImm4F, getRegAY)
    | 0b10100u ->
      Op.SBFX,
      p4Oprs (b1, b2) chkUnpreCK (getRegAV, getRegAY, getImm5G, getImm4F)
    | 0b10110u when chkRn () ->
      Op.BFI, p4Oprs (b1, b2) chkUnpreCL (getRegAV, getRegAY, getImm5G, getImmK)
    | 0b10110u ->
      Op.BFC, p3Oprs (b1, b2) chkUnpreCM (getRegAV, getImm5G, getImmK)
    | 0b11000u ->
      Op.USAT,
      p4Oprs (b1, b2) chkUnpreCI (getRegAV, getImm4F, getRegAY, getShiftI)
    | 0b11010u when chkA () ->
      Op.USAT,
      p4Oprs (b1, b2) chkUnpreCI (getRegAV, getImm4F, getRegAY, getShiftI)
    | 0b11010u ->
      Op.USAT16, p3Oprs (b1, b2) chkUnpreCJ (getRegAV, getImm4F, getRegAY)
    | 0b11100u ->
      Op.UBFX,
      p4Oprs (b1, b2) chkUnpreCK (getRegAV, getRegAY, getImm5G, getImm4F)
    | _ -> failwith "Wrong opcode in parseGroup11."
  opcode, getCondWithITSTATE it, None, operands

let parseChangeProcStateHintsCPS it b1 b2 =
  let opcode, operands =
    match extract b2 10u 8u with
    | 0b100u -> Op.CPSIE, p1Opr (b1, b2) (chkUnpreCS it) getFlagC
    | 0b101u -> Op.CPSIE, p2Oprs (b1, b2) (chkUnpreCS it) (getFlagC, getImm5H)
    | 0b110u -> Op.CPSID, p1Opr (b1, b2) (chkUnpreCS it) getFlagC
    | 0b111u -> Op.CPSID, p2Oprs (b1, b2) (chkUnpreCS it) (getFlagC, getImm5H)
    | _ -> failwith "Wrong opcode in change processor state and hints."
  opcode, None, getQfW (), operands

/// Change Processor State, and hints, page A6-236
let parseChangeProcStateHints it cond b1 b2 =
  match extract b2 10u 8u, extract b2 7u 0u with
  | 0b000u, 0b00000000u -> Op.NOP, cond, Some W, NoOperand
  | 0b000u, 0b00000001u -> Op.YIELD, cond, Some W, NoOperand
  | 0b000u, 0b00000010u -> Op.WFE, cond, Some W, NoOperand
  | 0b000u, 0b00000011u -> Op.WFI, cond, Some W, NoOperand
  | 0b000u, 0b00000100u -> Op.SEV, cond, Some W, NoOperand
  | 0b000u, o2 when o2 &&& 0b11110000u = 0b11110000u ->
    Op.DBG, cond, None, p1Opr b2 dummyChk getImm4A
  | 0b001u, _ -> Op.CPS, None, None, p1Opr (b1, b2) (chkUnpreCS it) getImm5H
  | 0b010u, _ -> raise UnpredictableException
  | 0b011u, _ -> raise UnpredictableException
  | _ -> parseChangeProcStateHintsCPS it b1 b2

/// Miscellaneous control instructions, page A6-237
let parseMiscellaneousInstrs cond b2 =
  let opcode, cond, operands =
    match extract b2 7u 4u with
    | 0b0000u -> Op.LEAVEX, None, NoOperand  // Exit ThumbEE State or Nop
    | 0b0001u -> Op.ENTERX, None, NoOperand  // Enter ThumbEE State
    | 0b0010u -> Op.CLREX, cond, NoOperand
    | 0b0100u -> Op.DSB, cond, p1Opr b2 dummyChk getOptA
    | 0b0101u -> Op.DMB, cond, p1Opr b2 dummyChk getOptA
    | 0b0110u -> Op.ISB, cond, p1Opr b2 dummyChk getOptA
    | _ -> failwith "Wrong miscellaneous control instructions."
  opcode, cond, None, operands

/// Branches and miscellaneous control, page A6-235
let parseGroup12Sub it cond bin =
  let b1, b2 = halve bin
  let chkBit5 () = pickBit b2 5u = 0b1u
  let chkOp2 () = extract b2 9u 8u = 0b00u
  let chkI8 () = extract b2 7u 0u = 0b00000000u
  let opcode, cond, qualifiers, operands =
    match extract b1 10u 4u with
    | op when op &&& 0b0111000u <> 0b0111000u ->
      Op.B, extract b1 9u 6u |> byte |> parseCond |> Some, getQfW (),
      p1Opr (b1, b2) (chkUnpreDE it) getLbl21A
    | op when op &&& 0b1111110u = 0b0111000u && chkBit5 () ->
      Op.MSR, cond, None, p2Oprs (b1, b2) chkUnpreCN (getBankedRegB, getRegAY)
    | 0b0111000u when not (chkBit5 ()) && chkOp2 () ->
      Op.MSR, cond, None, p2Oprs (b1, b2) chkUnpreCO (getAPSRxC, getRegAY)
    | 0b0111000u when not (chkBit5 ()) ->
      Op.MSR, cond, None, p2Oprs (b1, b2) chkUnpreCP (getxPSRxA, getRegAY)
    | 0b0111010u -> parseChangeProcStateHints it cond b1 b2
    | 0b0111011u -> parseMiscellaneousInstrs cond b2
    | 0b0111100u -> Op.BXJ, cond, None, p1Opr (b1, b2) chkUnpreCQ getRegAY
    | 0b0111101u when chkI8 () -> Op.ERET, cond, None, NoOperand
    | 0b0111101u ->
      Op.SUBS, cond, None, p3Oprs b2 dummyChk (getRegPC, getRegLR, getImm8A)
    | op when op &&& 0b1111110u = 0b0111110u && chkBit5 () ->
      Op.MRS, cond, None, p2Oprs (b1, b2) chkUnpreCN (getBankedRegC, getRegAV)
    | op when op &&& 0b1111110u = 0b0111110u ->
      Op.MRS, cond, None, p2Oprs (b1, b2) chkUnpreBL (getRegAV, getxPSRxB)
    | _ -> failwith "Wrong opcode in parseGroup12."
  opcode, cond, qualifiers, operands

/// Branches and miscellaneous control, page A6-235
let parseGroup12 it bin =
  let b1, b2 = halve bin
  let cond = getCondWithITSTATE it
  let chkA () = extract b1 10u 4u = 0b1111110u
  let chkB () = extract b1 10u 4u = 0b1111111u
  match extract b2 14u 12u with
  | 0b000u when chkA () ->
    Op.HVC, None, None, p1Opr (b1, b2) dummyChk getImm16B
  | 0b000u when chkB () -> Op.SMC, cond, None, p1Opr bin dummyChk getImm4A
  | 0b010u when chkB () -> Op.UDF, cond, None, p1Opr (b1, b2) dummyChk getImm16B
  | op when op &&& 0b101u = 0b000u -> parseGroup12Sub it cond bin
  | op when op &&& 0b101u = 0b001u ->
    Op.B, cond, getQfW (), p1Opr (b1, b2) (chkUnpreDG it) getLbl25A
  | op when op &&& 0b101u = 0b100u ->
    Op.BLX, cond, None, p1Opr (b1, b2) chkUnpreCR getLbl25B
  | op when op &&& 0b101u = 0b101u ->
    Op.BL, cond, None, p1Opr (b1, b2) dummyChk getLbl25C
  | _ -> failwith "Wrong opcode in parseGroup12."

/// Store single data item, page A6-242
let parseGroup13Sub b1 b2 =
  let cRn () = extract b1 3u 0u = 0b1101u
  let cPush () = extract b2 5u 0u = 0b000100u
  if extract b1 3u 0u = 0b1111u then raise UndefinedException
  else match extract b2 11u 6u with
       | 0b000000u ->
         Op.STR, getQfW (), None, p2Oprs (b1, b2) chkBothH (getRegAW, getMemAO)
       | 0b110100u when cRn () && cPush () ->
         Op.PUSH, getQfW (), None, p1Opr (b1, b2) chkUnpreCQ getRegAW
       | o2 when o2 &&& 0b100100u = 0b100100u ->
         Op.STR, None, None, p2Oprs (b1, b2) chkBothD (getRegAW, getMemAM)
       | o2 when o2 &&& 0b111100u = 0b110000u ->
         Op.STR, None, None, p2Oprs (b1, b2) chkBothD (getRegAW, getMemAM)
       | o2 when o2 &&& 0b111100u = 0b111000u ->
         Op.STRT, None, None, p2Oprs (b1, b2) chkBothA (getRegAW, getMemAG)
       | _ -> failwith "Wrong opcode in parseGroup13."

/// Store single data item, page A6-242
let parseGroup13 bin =
  let b1, b2 = halve bin
  match concat (extract b1 7u 5u) (extract b2 11u 6u) 6 with
  | op when op &&& 0b111100100u = 0b000100100u ->
    Op.STRB, None, None, p2Oprs (b1, b2) chkBothC (getRegAW, getMemAM)
  | op when op &&& 0b111111100u = 0b000110000u ->
    Op.STRB, None, None, p2Oprs (b1, b2) chkBothC (getRegAW, getMemAM)
  | op when op &&& 0b111000000u = 0b100000000u ->
    Op.STRB, getQfW (), None, p2Oprs (b1, b2) chkBothE (getRegAW, getMemAN)
  | 0b000000000u ->
    Op.STRB, getQfW (), None, p2Oprs (b1, b2) chkBothG (getRegAW, getMemAO)
  | op when op &&& 0b111111100u = 0b000111000u ->
    Op.STRBT, None, None, p2Oprs (b1, b2) chkBothA (getRegAW, getMemAG)
  | op when op &&& 0b111100100u = 0b001100100u ->
    Op.STRH, None, None, p2Oprs (b1, b2) chkBothC (getRegAW, getMemAM)
  | op when op &&& 0b111111100u = 0b001110000u ->
    Op.STRH, None, None, p2Oprs (b1, b2) chkBothC (getRegAW, getMemAM)
  | op when op &&& 0b111000000u = 0b101000000u ->
    Op.STRH, getQfW (), None, p2Oprs (b1, b2) chkBothE (getRegAW, getMemAN)
  | 0b001000000u ->
    Op.STRH, getQfW (), None, p2Oprs (b1, b2) chkBothG (getRegAW, getMemAO)
  | op when op &&& 0b111111100u = 0b001111000u ->
    Op.STRHT, None, None, p2Oprs (b1, b2) chkBothA (getRegAW, getMemAG)
  | op when op &&& 0b111000000u = 0b110000000u ->
    Op.STR, getQfW (), None, p2Oprs (b1, b2) chkBothF (getRegAW, getMemAN)
  | op when op &&& 0b111000000u = 0b010000000u -> parseGroup13Sub b1 b2
  | _ -> failwith "Wrong opcode in parseGroup13."

/// Load byte, memory hints, page A6-241
let parseGroup14 bin =
  let b1, b2 = halve bin
  let chkRn () = extract b1 3u 0u <> 0b1111u
  let chkRt () = extract b2 15u 12u <> 0b1111u
  let opcode, q, operands =
    match concat (extract b1 8u 7u) (extract b2 11u 6u) 6 with
    | 0b00000000u when chkRn () && chkRt () ->
      Op.LDRB, getQfW (), p2Oprs (b1, b2) chkUnpreCW (getRegAW, getMemAO)
    | 0b00000000u when chkRn () ->
      Op.PLD, None, p1Opr (b1, b2) chkUnpreAK getMemP
    | op when op &&& 0b11100100u = 0b00100100u && chkRn () ->
      Op.LDRB, None, p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11111100u = 0b00110000u && chkRn () && chkRt () ->
      Op.LDRB, None, p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11111100u = 0b00110000u && chkRn () ->
      Op.PLD, None, p1Opr (b1, b2) dummyChk getMemAP
    | op when op &&& 0b11111100u = 0b00111000u && chkRn () ->
      Op.LDRBT, None, p2Oprs (b1, b2) chkUnpreBL (getRegAW, getMemAG)
    | op when op &&& 0b11000000u = 0b01000000u && chkRn () && chkRt () ->
      Op.LDRB, getQfW (), p2Oprs (b1, b2) chkUnpreCV (getRegAW, getMemAN)
    | op when op &&& 0b11000000u = 0b01000000u && chkRn () ->
      Op.PLD, None, p1Opr (b1, b2) dummyChk getMemAN
    | op when op &&& 0b10000000u = 0b00000000u && chkRt () ->
      Op.LDRB, getQfW (), p2Oprs (b1, b2) dummyChk (getRegAW, getMemAQ)
    | op when op &&& 0b10000000u = 0b00000000u ->
      Op.PLD, None, p1Opr (b1, b2) dummyChk getMemAQ
    | 0b10000000u when chkRn () && chkRt () ->
      Op.LDRSB, getQfW (), p2Oprs (b1, b2) chkUnpreCW (getRegAW, getMemAO)
    | 0b10000000u when chkRn () ->
      Op.PLI, None, p1Opr (b1, b2) chkUnpreAK getMemP
    | op when op &&& 0b11100100u = 0b10100100u && chkRn () ->
      Op.LDRSB, None, p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11111100u = 0b10110000u && chkRn () && chkRt () ->
      Op.LDRSB, None, p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11111100u = 0b10110000u && chkRn () ->
      Op.PLI, None, p1Opr (b1, b2) dummyChk getMemAP
    | op when op &&& 0b11111100u = 0b10111000u && chkRn () ->
      Op.LDRSBT, None, p2Oprs (b1, b2) chkUnpreBL (getRegAW, getMemAG)
    | op when op &&& 0b11000000u = 0b11000000u && chkRn () && chkRt () ->
      Op.LDRSB, None, p2Oprs (b1, b2) chkUnpreCV (getRegAW, getMemAN)
    | op when op &&& 0b11000000u = 0b11000000u && chkRn () ->
      Op.PLI, None, p1Opr (b1, b2) dummyChk getMemAN
    | op when op &&& 0b10000000u = 0b10000000u && chkRt () ->
      Op.LDRSB, None, p2Oprs (b1, b2) dummyChk (getRegAW, getMemAQ)
    | op when op &&& 0b10000000u = 0b10000000u ->
      Op.PLI, None, p1Opr (b1, b2) dummyChk getMemAQ
    | _ -> failwith "Wrong opcode in parseGroup14."
  opcode, q, None, operands

/// Load halfword, memory hints, page A6-240
let parseGroup15WithRn b1 b2 =
  let chkRt () = extract b2 15u 12u <> 0b1111u
  match extract b1 8u 7u with
  | op when op &&& 0b10u = 0b00u && chkRt () ->
    Op.LDRH, None, None, p2Oprs (b1, b2) chkUnpreCV (getRegAW, getMemAQ)
  | op when op &&& 0b10u = 0b00u ->
    Op.PLD, None, None, p1Opr (b1, b2) dummyChk getMemAQ
  | op when op &&& 0b10u = 0b10u && chkRt () ->
    Op.LDRSH, None, None, p2Oprs (b1, b2) chkUnpreCV (getRegAW, getMemAQ)
  | op when op &&& 0b10u = 0b10u -> Op.NOP, None, None, NoOperand
  | _ -> failwith "Wrong opcode in parseGroup15."

/// Load halfword, memory hints, page A6-240
let parseGroup15 bin =
  let b1, b2 = halve bin
  let chkRt () = extract b2 15u 12u <> 0b1111u
  if extract b1 3u 0u = 0b1111u then parseGroup15WithRn b1 b2
  else
    match concat (extract b1 8u 7u) (extract b2 11u 6u) 6 with
    | op when op &&& 0b11100100u = 0b00100100u ->
      Op.LDRH, None, None, p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11111100u = 0b00110000u && chkRt () ->
      Op.LDRH, None, None, p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11000000u = 0b01000000u && chkRt () ->
      Op.LDRH, getQfW (), None, p2Oprs (b1, b2) chkUnpreCV (getRegAW, getMemAN)
    | 0b00000000u when chkRt () ->
      Op.LDRH, getQfW (), None, p2Oprs (b1, b2) chkUnpreCW (getRegAW, getMemAO)
    | op when op &&& 0b11111100u = 0b00111000u ->
      Op.LDRHT, None, None, p2Oprs (b1, b2) chkUnpreBL (getRegAW, getMemAG)
    | 0b00000000u -> Op.PLDW, None, None, p1Opr (b1, b2) chkUnpreAK getMemP
    | op when op &&& 0b11111100u = 0b00110000u ->
      Op.PLDW, None, None, p1Opr (b1, b2) dummyChk getMemAP
    | op when op &&& 0b11000000u = 0b01000000u ->
      Op.PLDW, None, None, p1Opr (b1, b2) dummyChk getMemAN
    | op when op &&& 0b11100100u = 0b10100100u ->
      Op.LDRSH, None, None, p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11110000u = 0b10110000u && chkRt () ->
      Op.LDRSH, None, None, p2Oprs (b1, b2) chkUnpreCT (getRegAW, getMemAM)
    | op when op &&& 0b11000000u = 0b11000000u && chkRt () ->
      Op.LDRSH, None, None, p2Oprs (b1, b2) chkUnpreCV (getRegAW, getMemAN)
    | 0b10000000u when chkRt () ->
      Op.LDRSH, getQfW (), None, p2Oprs (b1, b2) chkUnpreCW (getRegAW, getMemAO)
    | op when op &&& 0b11111100u = 0b10111000u ->
      Op.LDRSHT, None, None, p2Oprs (b1, b2) chkUnpreBL (getRegAW, getMemAG)
    | 0b10000000u -> Op.NOP, None, None, NoOperand
    | op when op &&& 0b11111100u = 0b10110000u -> Op.NOP, None, None, NoOperand
    | op when op &&& 0b11000000u = 0b11000000u -> Op.NOP, None, None, NoOperand
    | _ -> failwith "Wrong opcode in parseGroup15."

/// Load word, page A6-239
let parseGroup16 it bin =
  let b1, b2 = halve bin
  let chkRn () = extract b1 3u 0u = 0b1111u
  let chkRn2 () = extract b1 3u 0u = 0b1101u
  let chkPop () = extract b2 5u 0u = 0b000100u
  match concat (extract b1 8u 7u) (extract b2 11u 6u) 6 with
  | op when op &&& 0b10000000u = 0b0u && chkRn () ->
    Op.LDR, getQfW (), None, p2Oprs (b1, b2) (chkUnpreDK it) (getRegAW, getMemAQ)
  | 0b00000000u ->
    Op.LDR, getQfW (), None, p2Oprs (b1, b2) (chkUnpreCX it) (getRegAW, getMemAO)
  | 0b00101100u when chkRn2 () && chkPop () ->
    Op.POP, getQfW (), None, p1Opr (b1, b2) (chkUnpreDJ it) getRegAW
  | op when op &&& 0b11100100u = 0b00100100u ->
    Op.LDR, None, None, p2Oprs (b1, b2) (chkUnpreCU it) (getRegAW, getMemAM)
  | op when op &&& 0b11111100u = 0b00110000u ->
    Op.LDR, None, None, p2Oprs (b1, b2) (chkUnpreCU it) (getRegAW, getMemAM)
  | op when op &&& 0b11000000u = 0b01000000u ->
    Op.LDR, getQfW (), None, p2Oprs (b1, b2) (chkUnpreDK it) (getRegAW, getMemAN)
  | op when op &&& 0b11111100u = 0b00111000u ->
    Op.LDRT, None, None, p2Oprs (b1, b2) chkUnpreBL (getRegAW, getMemAG)
  | _ -> failwith "Wrong opcode in parseGroup16."

/// Advanced SIMD element or structure load/store instructions, page A7-275
let parseGroup17 bin =
  let b1, b2 = halve bin
  let opcode, dt, operands = concat b1 b2 16 |> getAdvSIMDOrStrct
  opcode, None, dt, operands

/// Parallel addition and subtraction, signed, page A6-246
let parseParallelAddSubSigned b1 b2 =
  match concat (extract b1 6u 4u) (extract b2 5u 4u) 2 with
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
  match concat (extract b1 6u 4u) (extract b2 5u 4u) 2 with
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
  if pickBit b2 6u = 0u then parseParallelAddSubSigned b1 b2
  else parseParallelAddSubUnsigned b1 b2
  ,None, None, p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAY, getRegAX)

/// Miscellaneous operations, page A6-248
let parseMiscellaneousOperations b1 b2 =
  match concat (extract b1 5u 4u) (extract b2 5u 4u) 2 with
  | 0b0000u ->
    Op.QADD, None, None,
    p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAX, getRegAY)
  | 0b0001u ->
    Op.QDADD, None, None,
    p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAX, getRegAY)
  | 0b0010u ->
    Op.QSUB, None, None,
    p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAX, getRegAY)
  | 0b0011u ->
    Op.QDSUB, None, None,
    p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAX, getRegAY)
  | 0b0100u ->
    Op.REV, getQfW (), None, p2Oprs (b1, b2) chkUnpreCZ (getRegAV, getRegAX)
  | 0b0101u ->
    Op.REV16, getQfW (), None, p2Oprs (b1, b2) chkUnpreCZ (getRegAV, getRegAX)
  | 0b0110u ->
    Op.RBIT, None, None, p2Oprs (b1, b2) chkUnpreCZ (getRegAV, getRegAX)
  | 0b0111u ->
    Op.REVSH, getQfW (), None, p2Oprs (b1, b2) chkUnpreCZ (getRegAV, getRegAX)
  | 0b1000u ->
    Op.SEL, None, None,
    p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAY, getRegAX)
  | 0b1100u ->
    Op.CLZ, None, None, p2Oprs (b1, b2) chkUnpreCZ (getRegAV, getRegAX)
  | _ -> failwith "Wrong opcode in Miscellaneous operations."

/// Data-processing (register), page A6-245
let parseGroup18Sub b1 b2 =
  match extract b1 6u 4u with
  | 0b000u -> Op.LSL
  | 0b001u -> Op.LSLS
  | 0b010u -> Op.LSR
  | 0b011u -> Op.LSRS
  | 0b100u -> Op.ASR
  | 0b101u -> Op.ASRS
  | 0b110u -> Op.ROR
  | 0b111u -> Op.RORS
  | _ -> failwith "Wrong opcode in parseGroup18."
  , getQfW (), None, p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAY, getRegAX)

/// Data-processing (register), page A6-245
let parseGroup18WithRn b1 b2 =
  let opcode, q =
    match extract b1 6u 4u with
    | 0b000u -> Op.SXTH, getQfW ()
    | 0b001u -> Op.UXTH, getQfW ()
    | 0b010u -> Op.SXTB16, None
    | 0b011u -> Op.UXTB16, None
    | 0b100u -> Op.SXTB, getQfW ()
    | 0b101u -> Op.UXTB, getQfW ()
    | _ -> failwith "Wrong opcode in parseGroup18."
  opcode, q, None, p3Oprs (b1, b2) chkUnpreBV (getRegAV, getRegAX, getShiftJ)

let parseGroup18WithOutRn b1 b2 =
  match extract b1 6u 4u with
  | 0b000u -> Op.SXTAH
  | 0b001u -> Op.UXTAH
  | 0b010u -> Op.SXTAB16
  | 0b011u -> Op.UXTAB16
  | 0b100u -> Op.SXTAB
  | 0b101u -> Op.UXTAB
  | _ -> failwith "Wrong opcode in parseGroup18."
  , None, None,
  p4Oprs (b1, b2) chkUnpreBZ (getRegAV, getRegAY, getRegAX, getShiftJ)

/// Data-processing (register), page A6-245
let parseGroup18ByRn b1 b2 =
  if extract b1 3u 0u = 0b1111u then parseGroup18WithRn b1 b2
  else parseGroup18WithOutRn b1 b2

/// Data-processing (register), page A6-245
let parseGroup18 bin =
  let b1, b2 = halve bin
  match concat (pickBit b1 7u) (extract b2 7u 4u) 4 with
  | 0b00000u -> parseGroup18Sub b1 b2
  | op when op &&& 0b11000u = 0b01000u -> parseGroup18ByRn b1 b2
  | op when op &&& 0b11000u = 0b10000u -> parseParallelAddSub b1 b2
  | op when op &&& 0b11100u = 0b11000u -> parseMiscellaneousOperations b1 b2
  | _ -> failwith "Wrong opcode in parseGroup18."

/// Multiply, multiply accumulate, and absolute difference, page A6-249
let parseGroup19Sub b1 b2 =
  match concat (extract b1 6u 4u) (pickBit b2 4u) 1 with
  | 0b0001u -> Op.MLS
  | 0b1100u -> Op.SMMLS
  | 0b1101u -> Op.SMMLSR
  | _ -> failwith "Wrong opcode in parseGroup19."
  , None, None,
  p4Oprs (b1, b2) chkUnpreDB (getRegAV, getRegAY, getRegAX, getRegAW)

/// Multiply, multiply accumulate, and absolute difference, page A6-249
let parseGroup19WithOutRa b1 b2 =
  match concat (extract b1 6u 4u) (extract b2 5u 4u) 2 with
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
  , None, None,
  p4Oprs (b1, b2) chkUnpreDA (getRegAV, getRegAY, getRegAX, getRegAW)

/// Multiply, multiply accumulate, and absolute difference, page A6-249
let parseGroup19WithRa b1 b2 =
  match concat (extract b1 6u 4u) (extract b2 5u 4u) 2 with
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
  , None, None,
  p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAY, getRegAX)

/// Multiply, multiply accumulate, and absolute difference, page A6-249
let parseGroup19 bin =
  let b1, b2 = halve bin
  let op = concat (extract b1 6u 4u) (extract b2 5u 4u) 2
  if op = 1u || op = 0b11000u || op = 0b11001u then parseGroup19Sub b1 b2
  elif extract b2 15u 12u = 0b1111u then parseGroup19WithRa b1 b2
  else parseGroup19WithOutRa b1 b2

/// Long multiply, long multiply accumulate, and divide, page A6-250
let parseGroup20 bin =
  let b1, b2 = halve bin
  let getFourOprs () =
    p4Oprs (b1, b2) chkUnpreDC (getRegAW, getRegAV, getRegAY, getRegAX)
  let getThreeOprs () =
    p3Oprs (b1, b2) chkUnpreCY (getRegAV, getRegAY, getRegAX)
  match concat (extract b1 6u 4u) (extract b2 7u 4u) 4 with
  | 0b0000000u -> Op.SMULL, None, None, getFourOprs ()
  | 0b0011111u -> Op.SDIV, None, None, getThreeOprs ()
  | 0b0100000u -> Op.UMULL, None, None, getFourOprs ()
  | 0b0111111u -> Op.UDIV, None, None, getThreeOprs ()
  | 0b1000000u -> Op.SMLAL, None, None, getFourOprs ()
  | 0b1001000u -> Op.SMLALBB, None, None, getFourOprs ()
  | 0b1001001u -> Op.SMLALBT, None, None, getFourOprs ()
  | 0b1001010u -> Op.SMLALTB, None, None, getFourOprs ()
  | 0b1001011u -> Op.SMLALTT, None, None, getFourOprs ()
  | 0b1001100u -> Op.SMLALD, None, None, getFourOprs ()
  | 0b1001101u -> Op.SMLALDX, None, None, getFourOprs ()
  | 0b1011100u -> Op.SMLSLD, None, None, getFourOprs ()
  | 0b1011101u -> Op.SMLSLDX, None, None, getFourOprs ()
  | 0b1100000u -> Op.UMLAL, None, None, getFourOprs ()
  | 0b1100110u -> Op.UMAAL, None, None, getFourOprs ()
  | _ -> failwith "Wrong opcode in parseGroup20."

let parseV7Thumb32Group01 it bin =
  let opcode, q, dt, operands =
    match extract bin 10u 9u with
    | 0b00u when pickBit bin 6u = 0u -> parseGroup6 it bin
    | 0b00u -> parseGroup7 it bin
    | 0b01u -> parseGroup8 bin
    | 0b10u | 0b11u -> parseGroup9 bin
    | _ -> failwith "Wrong thumb group specified."
  opcode, getCondWithITSTATE it, q, dt, operands

let parseV7Thumb32Group10 itState bin =
  let opcode, cond, q, operands =
    match pickBit bin 9u, pickBit bin 31u with
    | 0b0u, 0b0u -> parseGroup10 itState bin
    | 0b1u, 0b0u -> parseGroup11 itState bin
    | _, 0b1u -> parseGroup12 itState bin
    | _ -> failwith "Wrong thumb group specified."
  opcode, cond, q, None, operands


let parseV7Thumb32Group11 itState bin =
  let opcode, q, dt, operands =
    match extract bin 10u 4u with
    | op when op &&& 0b1110001u = 0b0000000u -> parseGroup13 bin
    | op when op &&& 0b1100111u = 0b0000001u -> parseGroup14 bin
    | op when op &&& 0b1100111u = 0b0000011u -> parseGroup15 bin
    | op when op &&& 0b1100111u = 0b0000101u -> parseGroup16 itState bin
    | op when op &&& 0b1100111u = 0b0000111u -> raise UndefinedException
    | op when op &&& 0b1110001u = 0b0010000u -> parseGroup17 bin
    | op when op &&& 0b1110000u = 0b0100000u -> parseGroup18 bin
    | op when op &&& 0b1111000u = 0b0110000u -> parseGroup19 bin
    | op when op &&& 0b1111000u = 0b0111000u -> parseGroup20 bin
    | op when op &&& 0b1000000u = 0b1000000u -> parseGroup9 bin
    | _ -> failwith "Wrong thumb group specified."
  opcode, getCondWithITSTATE itState, q, dt, operands

/// ARM Architecture Reference Manual ARMv7-A and ARMv7-R edition, DDI0406C.b
let parseV7Thumb32 it bin =
  match extract bin 12u 11u with
  | 0b01u -> parseV7Thumb32Group01 it bin
  | 0b10u -> parseV7Thumb32Group10 it bin
  | 0b11u -> parseV7Thumb32Group11 it bin
  | _ -> failwith "Wrong thumb group specified."

/// ARM Architecture Reference Manual ARMv7-A and ARMv7-R edition, DDI0406C.b
let parseV7Thumb16 it bin =
  let cond () = getCondWithITSTATE it
  let opcode, cond, qualifier, operands =
    match extract bin 15u 11u with
    | op when op &&& 0b11000u = 0b00000u -> parseGroup0 it bin
    | 0b01000u when pickBit bin 10u = 0b0u -> parseGroup1 it bin
    | 0b01000u -> parseGroup2 it bin
    | 0b01001u -> Op.LDR, cond (), None, p2Oprs bin dummyChk (getRegJ, getLbl8A)
    | op when op &&& 0b11110u = 0b01010u -> parseGroup3 it bin
    | op when op &&& 0b11100u = 0b01100u -> parseGroup3 it bin
    | op when op &&& 0b11100u = 0b10000u -> parseGroup3 it bin
    | 0b10100u -> Op.ADR, cond (), None, p2Oprs bin dummyChk (getRegJ, getLbl8A)
    | 0b10101u ->
      Op.ADD, cond (), None, p3Oprs bin dummyChk (getRegJ, getRegSP, getImm8B)
    | op when op &&& 0b11110u = 0b10110u -> parseGroup4 it bin
    | 0b11000u ->
      Op.STM, cond (), None, p2Oprs bin chkUnpreDD (getRegisterWC, getRegListR)
    | 0b11001u ->
      Op.LDM, cond (), None, p2Oprs bin chkUnpreDD (getRegisterWD, getRegListR)
    | op when op &&& 0b11110u = 0b11010u -> parseGroup5 it bin
    | 0b11100u -> Op.B, cond (), getQfN (), p1Opr bin dummyChk getLbl12A
    | _ -> failwith "Wrong thumb group specified."
  opcode, cond, qualifier, None, operands
