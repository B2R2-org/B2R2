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

module internal B2R2.FrontEnd.ARM32.ARMParser

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.ParseUtils
open B2R2.FrontEnd.ARM32.OperandHelper
open B2R2.FrontEnd.ARM32.OperandParsingHelper
#if !EMULATION
open B2R2.FrontEnd.ARM32.ARMValidator
#endif

let render (phlp: ParsingHelper) bin opcode dt oidx =
  let struct (oprs, wback, cflags, oSz) = phlp.OprParsers.[int oidx].Render bin
  Instruction (phlp.InsAddr, phlp.Len, phlp.Cond, opcode, oprs, 0uy, wback, N,
               dt, phlp.IsThumb, cflags, oSz, phlp.IsAdd, phlp.Lifter)

/// Load/Store Dual, Half, Signed Byte (register) on page F4-4221.
let parseLoadStoreReg (phlp: ParsingHelper) bin =
  let decodeField = (* P:W:o1:o2 *)
    (pickBit bin 24 <<< 4) + (pickTwo bin 20 <<< 2) + (pickTwo bin 5)
  match decodeField with
  | 0b00001u ->
#if !EMULATION
    chkPCRtRm bin
#endif
    render phlp bin Op.STRH None OD.OprRtMemReg
  | 0b00010u ->
#if !EMULATION
    chkPCRt2RmRnEq bin
#endif
    render phlp bin Op.LDRD None OD.OprRtRt2MemReg
  | 0b00011u ->
#if !EMULATION
    chkPCRt2RmRn bin
#endif
    render phlp bin Op.STRD None OD.OprRtRt2MemReg
  | 0b00101u ->
#if !EMULATION
    chkPCRtRm bin
#endif
    render phlp bin Op.LDRH None OD.OprRtMemReg
  | 0b00110u ->
#if !EMULATION
    chkPCRtRm bin
#endif
    render phlp bin Op.LDRSB None OD.OprRtMemReg
  | 0b00111u ->
#if !EMULATION
    chkPCRtRm bin
#endif
    render phlp bin Op.LDRSH None OD.OprRtMemReg
  | 0b01001u ->
#if !EMULATION
    chkPCRtRnRm bin
#endif
    render phlp bin Op.STRHT None OD.OprRtMemRegP
  | 0b01010u | 0b01011u -> raise ParsingFailureException
  | 0b01101u ->
#if !EMULATION
    chkPCRtRnRm bin
#endif
    render phlp bin Op.LDRHT None OD.OprRtMemRegP
  | 0b01110u ->
#if !EMULATION
    chkPCRtRnRm bin
#endif
    render phlp bin Op.LDRSBT None OD.OprRtMemRegP
  | 0b01111u ->
#if !EMULATION
    chkPCRtRnRm bin
#endif
    render phlp bin Op.LDRSHT None OD.OprRtMemRegP
  | 0b10001u | 0b11001u ->
#if !EMULATION
    chkPCRtRm bin
#endif
    render phlp bin Op.STRH None OD.OprRtMemReg
  | 0b10010u | 0b11010u ->
#if !EMULATION
    chkPCRt2RmRnEq bin
#endif
    render phlp bin Op.LDRD None OD.OprRtRt2MemReg
  | 0b10011u | 0b11011u ->
#if !EMULATION
    chkPCRt2RmRn bin
#endif
    render phlp bin Op.STRD None OD.OprRtRt2MemReg
  | 0b10101u | 0b11101u ->
#if !EMULATION
    chkPCRtRm bin
#endif
    render phlp bin Op.LDRH None OD.OprRtMemReg
  | 0b10110u | 0b11110u ->
#if !EMULATION
    chkPCRtRm bin
#endif
    render phlp bin Op.LDRSB None OD.OprRtMemReg
  | 0b10111u | 0b11111u ->
#if !EMULATION
    chkPCRtRm bin
#endif
    render phlp bin Op.LDRSH None OD.OprRtMemReg
  | _ -> raise ParsingFailureException

/// Load/Store Dual, Half, Signed Byte (immediate, literal) on page F4-4221.
let parseLoadStoreImm (phlp: ParsingHelper) bin =
  let decodeField = (* P:W:o1:op2 *)
    ((bin >>> 20) &&& 0b10000u) (* 24th bit *)
    ||| ((bin >>> 18) &&& 0b01100u) (* 21, 20th bit *)
    ||| ((bin >>> 5) &&& 0b00011u) (* 6, 5th bit *)
  let isNotRn1111 bin = pickFour bin 16 <> 0b1111u
  match decodeField (* P:W:o1:op2 *) with
  | 0b00010u when isNotRn1111 bin -> (* LDRD (immediate) *)
#if !EMULATION
    chkRnRtPCRt2 bin
#endif
    render phlp bin Op.LDRD None OD.OprRtRt2MemImmA
  | 0b00010u -> (* LDRD (literal) *)
#if !EMULATION
    chkRtPCRt2 bin
#endif
    render phlp bin Op.LDRD None OD.OprRtRt2LabelA
  | 0b00001u ->
#if !EMULATION
    chkPCRnRtWithWB bin
#endif
    render phlp bin Op.STRH None OD.OprRtMemImm
  | 0b00011u ->
#if !EMULATION
    chkPCRnRt2 bin
#endif
    render phlp bin Op.STRD None OD.OprRtRt2MemImmA
  | 0b00101u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRtRnWithWB bin
#endif
    render phlp bin Op.LDRH None OD.OprRtMemImm
  | 0b00101u -> (* LDRH (literal) *)
#if !EMULATION
    chkPCRtWithWB bin
#endif
    render phlp bin Op.LDRH None OD.OprRtLabelHL
  | 0b00110u when isNotRn1111 bin -> (* LDRH (immediate) *)
#if !EMULATION
    chkPCRtRnWithWB bin
#endif
    render phlp bin Op.LDRSB None OD.OprRtMemImm
  | 0b00110u ->
#if !EMULATION
    chkPCRtWithWB bin
#endif
    render phlp bin Op.LDRSB None OD.OprRtLabelHL
  | 0b00111u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRtRnWithWB bin
#endif
    render phlp bin Op.LDRSH None OD.OprRtMemImm
  | 0b00111u ->
#if !EMULATION
    chkPCRtWithWB bin
#endif
    render phlp bin Op.LDRSH None OD.OprRtLabelHL
  | 0b01010u when isNotRn1111 bin -> raise ParsingFailureException
  | 0b01010u ->
#if !EMULATION
    chkRtPCRt2 bin
#endif
    render phlp bin Op.LDRD None OD.OprRtRt2LabelA
  | 0b01001u ->
#if !EMULATION
    chkPCRtRnEq bin
#endif
    render phlp bin Op.STRHT None OD.OprRtMemImmP
  | 0b01011u -> raise ParsingFailureException
  | 0b01101u ->
#if !EMULATION
    chkPCRtRnEq bin
#endif
    render phlp bin Op.LDRHT None OD.OprRtMemImmP
  | 0b01110u ->
#if !EMULATION
    chkPCRtRnEq bin
#endif
    render phlp bin Op.LDRSBT None OD.OprRtMemImmP
  | 0b01111u ->
#if !EMULATION
    chkPCRtRnEq bin
#endif
    render phlp bin Op.LDRSHT None OD.OprRtMemImmP
  | 0b10010u when isNotRn1111 bin ->
#if !EMULATION
    chkRnRtPCRt2 bin
#endif
    render phlp bin Op.LDRD None OD.OprRtRt2MemImmA
  | 0b10010u ->
#if !EMULATION
    chkRtPCRt2 bin
#endif
    render phlp bin Op.LDRD None OD.OprRtRt2LabelA
  | 0b10001u ->
#if !EMULATION
    chkPCRnRtWithWB bin
#endif
    render phlp bin Op.STRH None OD.OprRtMemImm
  | 0b10011u ->
#if !EMULATION
    chkPCRnRt2 bin
#endif
    render phlp bin Op.STRD None OD.OprRtRt2MemImmA
  | 0b10101u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRtRnWithWB bin
#endif
    render phlp bin Op.LDRH None OD.OprRtMemImm
  | 0b10101u ->
#if !EMULATION
    chkPCRtWithWB bin
#endif
    render phlp bin Op.LDRH None OD.OprRtLabelHL
  | 0b10110u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRtRnWithWB bin
#endif
    render phlp bin Op.LDRSB None OD.OprRtMemImm
  | 0b10110u ->
#if !EMULATION
    chkPCRtWithWB bin
#endif
    render phlp bin Op.LDRSB None OD.OprRtLabelHL
  | 0b10111u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRtRnWithWB bin
#endif
    render phlp bin Op.LDRSH None OD.OprRtMemImm
  | 0b10111u ->
#if !EMULATION
    chkPCRtWithWB bin
#endif
    render phlp bin Op.LDRSH None OD.OprRtLabelHL
  | 0b11010u when isNotRn1111 bin ->
#if !EMULATION
    chkRnRtPCRt2 bin
#endif
    render phlp bin Op.LDRD None OD.OprRtRt2MemImmA
  | 0b11010u ->
#if !EMULATION
    chkRtPCRt2 bin
#endif
    render phlp bin Op.LDRD None OD.OprRtRt2LabelA
  | 0b11001u ->
#if !EMULATION
    chkPCRnRtWithWB bin
#endif
    render phlp bin Op.STRH None OD.OprRtMemImm
  | 0b11011u ->
#if !EMULATION
    chkPCRnRt2 bin
#endif
    render phlp bin Op.STRD None OD.OprRtRt2MemImmA
  | 0b11101u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRtRnWithWB bin
#endif
    render phlp bin Op.LDRH None OD.OprRtMemImm
  | 0b11101u ->
#if !EMULATION
    chkPCRtWithWB bin
#endif
    render phlp bin Op.LDRH None OD.OprRtLabelHL
  | 0b11110u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRtRnWithWB bin
#endif
    render phlp bin Op.LDRSB None OD.OprRtMemImm
  | 0b11110u ->
#if !EMULATION
    chkPCRtWithWB bin
#endif
    render phlp bin Op.LDRSB None OD.OprRtLabelHL
  | 0b11111u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRtRnWithWB bin
#endif
    render phlp bin Op.LDRSH None OD.OprRtMemImm
  | 0b11111u ->
#if !EMULATION
    chkPCRtWithWB bin
#endif
    render phlp bin Op.LDRSH None OD.OprRtLabelHL
  | _ -> raise ParsingFailureException

/// Extra load/store on page F4-4220.
let parseExtraLoadStore (phlp: ParsingHelper) bin =
  match pickBit bin 22 (* op0 *) with
  | 0b0u -> parseLoadStoreReg phlp bin
  | _ (* 0b1u *) -> parseLoadStoreImm phlp bin

/// Multiply and Accumulate on page F4-4129.
let parseMultiplyAndAccumlate (phlp: ParsingHelper) bin =
  match pickFour bin 20 (* opc:S *) with
  | 0b0000u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.MUL None OD.OprRdRnRmOpt
  | 0b0001u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.MULS None OD.OprRdRnRmOpt
  | 0b0010u ->
#if !EMULATION
    chkPCRdRnRmRa bin
#endif
    render phlp bin Op.MLA None OD.OprRdRnRmRaA
  | 0b0011u ->
#if !EMULATION
    chkPCRdRnRmRa bin
#endif
    render phlp bin Op.MLAS None OD.OprRdRnRmRaA
  | 0b0100u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.UMAAL None OD.OprRdlRdhRnRmA
  | 0b0101u -> raise ParsingFailureException
  | 0b0110u ->
#if !EMULATION
    chkPCRdRnRmRa bin
#endif
    render phlp bin Op.MLS None OD.OprRdRnRmRaA
  | 0b0111u -> raise ParsingFailureException
  | 0b1000u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.UMULL None OD.OprRdlRdhRnRmA
  | 0b1001u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.UMULLS None OD.OprRdlRdhRnRmA
  | 0b1010u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.UMLAL None OD.OprRdlRdhRnRmA
  | 0b1011u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.UMLALS None OD.OprRdlRdhRnRmA
  | 0b1100u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.SMULL None OD.OprRdlRdhRnRmA
  | 0b1101u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.SMULLS None OD.OprRdlRdhRnRmA
  | 0b1110u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.SMLAL None OD.OprRdlRdhRnRmA
  | _ (* 0b1111u *) ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.SMLALS None OD.OprRdlRdhRnRmA

/// Load/Store Exclusive and Load-Acquire/Store-Release on page F4-4223
/// ARMv8
let parseLdStExclAndLdAcqStRel (phlp: ParsingHelper) bin =
  match concat (pickThree bin 20) (pickTwo bin 8) 2 (* size:L:ex:ord *) with
  | 0b00000u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp bin Op.STL None OD.OprRtMem
  | 0b00001u -> raise ParsingFailureException
  | 0b00010u ->
#if !EMULATION
    chkPCRdRtRn bin
#endif
    render phlp bin Op.STLEX None OD.OprRdRtMemA
  | 0b00011u ->
#if !EMULATION
    chkPCRdRtRn bin
#endif
    render phlp bin Op.STREX None OD.OprRdRtMemA
  | 0b00100u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp bin Op.LDA None OD.OprRt15Mem
  | 0b00101u -> raise ParsingFailureException
  | 0b00110u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp bin Op.LDAEX None OD.OprRt15Mem
  | 0b00111u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp bin Op.LDREX None OD.OprRtMemImm0A
  | 0b01000u | 0b01001u -> raise ParsingFailureException
  | 0b01010u ->
#if !EMULATION
    chkPCRdRt2Rn bin
#endif
    render phlp bin Op.STLEXD None OD.OprRdRtRt2MemA
  | 0b01011u ->
#if !EMULATION
    chkPCRdRt2Rn bin
#endif
    render phlp bin Op.STREXD None OD.OprRdRtRt2MemA
  | 0b01100u | 0b01101u -> raise ParsingFailureException
  | 0b01110u ->
#if !EMULATION
    chkPCRt2Rn bin
#endif
    render phlp bin Op.LDAEXD None OD.OprRtRt2MemA
  | 0b01111u ->
#if !EMULATION
    chkPCRt2Rn bin
#endif
    render phlp bin Op.LDREXD None OD.OprRtRt2MemA
  | 0b10000u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp bin Op.STLB None OD.OprRtMem
  | 0b10001u -> raise ParsingFailureException
  | 0b10010u ->
#if !EMULATION
    chkPCRdRtRn bin
#endif
    render phlp bin Op.STLEXB None OD.OprRdRtMemA
  | 0b10011u ->
#if !EMULATION
    chkPCRdRtRn bin
#endif
    render phlp bin Op.STREXB None OD.OprRdRtMemA
  | 0b10100u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp bin Op.LDAB None OD.OprRtMem
  | 0b10101u -> raise ParsingFailureException
  | 0b10110u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp bin Op.LDAEXB None OD.OprRtMem
  | 0b10111u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp bin Op.LDREXB None OD.OprRtMem
  | 0b11000u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp bin Op.STLH None OD.OprRtMem
  | 0b11001u -> raise ParsingFailureException
  | 0b11010u ->
#if !EMULATION
    chkPCRdRtRn bin
#endif
    render phlp bin Op.STLEXH None OD.OprRdRtMemA
  | 0b11011u ->
#if !EMULATION
    chkPCRdRtRn bin
#endif
    render phlp bin Op.STREXH None OD.OprRdRtMemA
  | 0b11100u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp bin Op.LDAH None OD.OprRtMem
  | 0b11101u -> raise ParsingFailureException
  | 0b11110u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp bin Op.LDAEXH None OD.OprRtMem
  | _ (* 0b11111u *) ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp bin Op.LDREXH None OD.OprRtMem

/// Synchronization primitives and Load-Acquire/Store-Release on page F4-4223.
let parseSyncAndLoadAcqStoreRel (phlp: ParsingHelper) bin =
  match pickBit bin 23 (* op0 *) with
  | 0b0u when phlp.IsARMv7 -> (* ARMv7 A8-723 *)
#if !EMULATION
    chkPCRtRt2Rn bin
#endif
    let op = if pickBit bin 22 = 1u (* B *) then Op.SWPB else Op.SWP
    render phlp bin op None OD.OprRtRt2Mem2
  | 0b0u -> raise ParsingFailureException
  | _ (* 0b01u *) -> parseLdStExclAndLdAcqStRel phlp bin

/// Move special register (register) on page F4-4225.
let parseMoveSpecialReg (phlp: ParsingHelper) bin =
  match concat (pickTwo bin 21) (pickBit bin 9) 1 (* opc:B *) with
  | 0b000u | 0b100u ->
#if !EMULATION
    chkPCRd bin
#endif
    render phlp bin Op.MRS None OD.OprRdSregA
  | 0b001u | 0b101u ->
#if !EMULATION
    chkPCRd bin
#endif
    render phlp bin Op.MRS None OD.OprRdBankregA
  | 0b010u | 0b110u ->
#if !EMULATION
    chkMaskPCRn bin
#endif
    render phlp bin Op.MSR None OD.OprSregRnA
  | _ (* 0bx11u *) ->
#if !EMULATION
    chkPCRnB bin
#endif
    render phlp bin Op.MSR None OD.OprBankregRnA

/// Cyclic Redundancy Check on page F4-4226.
/// ARMv8-A
let parseCyclicRedundancyCheck (phlp: ParsingHelper) bin =
  match concat (pickTwo bin 21) (pickBit bin 9) 1 (* sz:C *) with
  | 0b000u ->
#if !EMULATION
    chkPCRdRnRmSz bin phlp.Cond
#endif
    render phlp bin Op.CRC32B None OD.OprRdRnRm
  | 0b001u ->
#if !EMULATION
    chkPCRdRnRmSz bin phlp.Cond
#endif
    render phlp bin Op.CRC32CB None OD.OprRdRnRm
  | 0b010u ->
#if !EMULATION
    chkPCRdRnRmSz bin phlp.Cond
#endif
    render phlp bin Op.CRC32H None OD.OprRdRnRm
  | 0b011u ->
#if !EMULATION
    chkPCRdRnRmSz bin phlp.Cond
#endif
    render phlp bin Op.CRC32CH None OD.OprRdRnRm
  | 0b100u ->
#if !EMULATION
    chkPCRdRnRmSz bin phlp.Cond
#endif
    render phlp bin Op.CRC32W None OD.OprRdRnRm
  | 0b101u ->
#if !EMULATION
    chkPCRdRnRmSz bin phlp.Cond
#endif
    render phlp bin Op.CRC32CW None OD.OprRdRnRm
  | _ (* 0b11xu *) -> raise UnpredictableException

/// Integer Saturating Arithmetic on page F4-4226.
let parseIntegerSaturatingArithmetic (phlp: ParsingHelper) bin =
  match pickTwo bin 21 (* opc *) with
  | 0b00u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.QADD None OD.OprRdRmRnA
  | 0b01u -> render phlp bin Op.QSUB None OD.OprRdRmRnA
  | 0b10u -> render phlp bin Op.QDADD None OD.OprRdRmRnA
  | _ (* 0b11u *) -> render phlp bin Op.QDSUB None OD.OprRdRmRnA

/// Miscellaneous on page F4-4224.
let parseMiscellaneous (phlp: ParsingHelper) bin =
  match concat (pickTwo bin 21) (pickThree bin 4) 3 (* op0:op1 *) with
  | 0b00001u | 0b00010u | 0b00011u | 0b00110u -> raise ParsingFailureException
  | 0b01001u -> render phlp bin Op.BX None OD.OprRm
  | 0b01010u ->
#if !EMULATION
    chkPCRm bin
#endif
    render phlp bin Op.BXJ None OD.OprRm
  | 0b01011u ->
#if !EMULATION
    chkPCRm bin
#endif
    render phlp bin Op.BLX None OD.OprRm
  | 0b01110u | 0b10001u | 0b10010u | 0b10011u | 0b10110u ->
    raise ParsingFailureException
  | 0b11001u ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.CLZ None OD.OprRdRm
  | 0b11010u | 0b11011u -> raise ParsingFailureException
  | 0b11110u -> render phlp bin Op.ERET None OD.OprNo
  (* Exception Generation on page F4-4225. *)
  | 0b00111u ->
#if !EMULATION
    chkCondAL phlp.Cond
#endif
    render phlp bin Op.HLT None OD.OprImm16A
  | 0b01111u ->
#if !EMULATION
    chkCondAL phlp.Cond
#endif
    phlp.Cond <- Condition.UN
    render phlp bin Op.BKPT None OD.OprImm16A
  | 0b10111u ->
#if !EMULATION
    chkCondAL phlp.Cond
#endif
    render phlp bin Op.HVC None OD.OprImm16A
  | 0b11111u -> render phlp bin Op.SMC None OD.OprImm4A
  | 0b00000u | 0b01000u | 0b10000u | 0b11000u ->
    parseMoveSpecialReg phlp bin
  | 0b00100u | 0b01100u | 0b10100u | 0b11100u ->
    parseCyclicRedundancyCheck phlp bin
  | _ (* 0bxx101 *) -> parseIntegerSaturatingArithmetic phlp bin

/// Halfword Multiply and Accumulate on page F4-4220.
let parseHalfMulAndAccumulate (phlp: ParsingHelper) bin =
  match concat (pickTwo bin 21) (pickTwo bin 5) 2 (* opc:M:N *) with
  | 0b0000u ->
#if !EMULATION
    chkPCRdRnRmRa bin
#endif
    render phlp bin Op.SMLABB None OD.OprRdRnRmRaA
  | 0b0001u ->
#if !EMULATION
    chkPCRdRnRmRa bin
#endif
    render phlp bin Op.SMLATB None OD.OprRdRnRmRaA
  | 0b0010u ->
#if !EMULATION
    chkPCRdRnRmRa bin
#endif
    render phlp bin Op.SMLABT None OD.OprRdRnRmRaA
  | 0b0011u ->
#if !EMULATION
    chkPCRdRnRmRa bin
#endif
    render phlp bin Op.SMLATT None OD.OprRdRnRmRaA
  | 0b0100u ->
#if !EMULATION
    chkPCRdRnRmRa bin
#endif
    render phlp bin Op.SMLAWB None OD.OprRdRnRmRaA
  | 0b0101u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMULWB None OD.OprRdRnRmOpt
  | 0b0110u ->
#if !EMULATION
    chkPCRdRnRmRa bin
#endif
    render phlp bin Op.SMLAWT None OD.OprRdRnRmRaA
  | 0b0111u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMULWT None OD.OprRdRnRmOpt
  | 0b1000u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.SMLALBB None OD.OprRdlRdhRnRmA
  | 0b1001u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.SMLALTB None OD.OprRdlRdhRnRmA
  | 0b1010u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.SMLALBT None OD.OprRdlRdhRnRmA
  | 0b1011u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.SMLALTT None OD.OprRdlRdhRnRmA
  | 0b1100u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMULBB None OD.OprRdRnRmOpt
  | 0b1101u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMULTB None OD.OprRdRnRmOpt
  | 0b1110u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMULBT None OD.OprRdRnRmOpt
  | _ (* 0b1111u *) ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMULTT None OD.OprRdRnRmOpt

/// Integer Data Processing (three register, immediate shift) on page F4-4227.
let parseIntegerDataProcThreeRegImm (phlp: ParsingHelper) bin =
  match pickFour bin 20 (* opc:S *) with
  | 0b0000u -> render phlp bin Op.AND None OD.OprRdRnRmShfA
  | 0b0001u -> render phlp bin Op.ANDS None OD.OprRdRnRmShfA
  | 0b0010u -> render phlp bin Op.EOR None OD.OprRdRnRmShfA
  | 0b0011u -> render phlp bin Op.EORS None OD.OprRdRnRmShfA
  | 0b0100u -> render phlp bin Op.SUB None OD.OprRdRnRmShfA
  | 0b0101u -> render phlp bin Op.SUBS None OD.OprRdRnRmShfA
  | 0b0110u -> render phlp bin Op.RSB None OD.OprRdRnRmShfA
  | 0b0111u -> render phlp bin Op.RSBS None OD.OprRdRnRmShfA
  | 0b1000u -> render phlp bin Op.ADD None OD.OprRdRnRmShfA
  | 0b1001u -> render phlp bin Op.ADDS None OD.OprRdRnRmShfA
  | 0b1010u -> render phlp bin Op.ADC None OD.OprRdRnRmShfA
  | 0b1011u -> render phlp bin Op.ADCS None OD.OprRdRnRmShfA
  | 0b1100u -> render phlp bin Op.SBC None OD.OprRdRnRmShfA
  | 0b1101u -> render phlp bin Op.SBCS None OD.OprRdRnRmShfA
  | 0b1110u -> render phlp bin Op.RSC None OD.OprRdRnRmShfA
  | _ (* 0b1111u *) -> render phlp bin Op.RSCS None OD.OprRdRnRmShfA

/// Integer Test and Compare (two register, immediate shift) on page F4-4228.
let parseIntegerTestAndCompareTwoRegImm (phlp: ParsingHelper) bin =
  match pickTwo bin 21 (* opc *) with
  | 0b00u -> render phlp bin Op.TST None OD.OprRnRmShfA
  | 0b01u -> render phlp bin Op.TEQ None OD.OprRnRmShfA
  | 0b10u -> render phlp bin Op.CMP None OD.OprRnRmShfA
  | _ (* 0b11u *) -> render phlp bin Op.CMN None OD.OprRnRmShfA

/// Alias conditions on page F5-4557.
let changeToAliasOfMOV bin =
  let stype = pickTwo bin 5
  let imm5 = pickFive bin 7
  if stype = 0b10u then struct (Op.ASR, OD.OprRdRmImmA)
  elif imm5 <> 0b00000u && stype = 0b00u then struct (Op.LSL, OD.OprRdRmImmA)
  elif stype = 0b01u then struct (Op.LSR, OD.OprRdRmImmA)
  elif imm5 <> 0b00000u && stype = 0b11u then struct (Op.ROR, OD.OprRdRmImmA)
  elif imm5 = 0b00000u && stype = 0b11u then struct (Op.RRX, OD.OprRdRm)
  elif imm5 = 0b00000u then struct (Op.MOV, OD.OprRdRm)
  else struct (Op.MOV, OD.OprRdRmShf)

/// Alias conditions on page F5-4557.
let changeToAliasOfMOVS bin =
  let stype = pickTwo bin 5
  let imm5 = pickFive bin 7
  if stype = 0b10u then struct (Op.ASRS, OD.OprRdRmImmA)
  elif imm5 <> 0b00000u && stype = 0b00u then struct (Op.LSLS, OD.OprRdRmImmA)
  elif stype = 0b01u then struct (Op.LSRS, OD.OprRdRmImmA)
  elif imm5 <> 0b00000u && stype = 0b11u then struct (Op.RORS, OD.OprRdRmImmA)
  elif imm5 = 0b00000u && stype = 0b11u then struct (Op.RRXS, OD.OprRdRm)
  elif imm5 = 0b00000u then struct (Op.MOVS, OD.OprRdRm)
  else struct (Op.MOVS, OD.OprRdRmShf)

/// Logical Arithmetic (three register, immediate shift) on page F4-4229.
let parseLogicalArithThreeRegImm (phlp: ParsingHelper) bin =
  match pickThree bin 20 (* opc:S *) with
  | 0b000u -> render phlp bin Op.ORR None OD.OprRdRnRmShfA
  | 0b001u -> render phlp bin Op.ORRS None OD.OprRdRnRmShfA
  | 0b010u ->
    let struct (opcode, oprFn) = changeToAliasOfMOV bin
    render phlp bin opcode None oprFn
  | 0b011u ->
    let struct (opcode, oprFn) = changeToAliasOfMOVS bin
    render phlp bin opcode None oprFn
  | 0b100u -> render phlp bin Op.BIC None OD.OprRdRnRmShfA
  | 0b101u -> render phlp bin Op.BICS None OD.OprRdRnRmShfA
  | 0b110u -> render phlp bin Op.MVN None OD.OprRdRmShf
  | _ (* 0b111u *) -> render phlp bin Op.MVNS None OD.OprRdRmShf

/// Data-processing register (immediate shift) on page F4-4227.
let parseDataProcRegisterImmShf (phlp: ParsingHelper) bin =
  match concat (pickTwo bin 23) (pickBit bin 20) 1 (* op0:op1 *) with
  | 0b000u | 0b001u | 0b010u | 0b011u ->
    parseIntegerDataProcThreeRegImm phlp bin
  | 0b101u -> parseIntegerTestAndCompareTwoRegImm phlp bin
  | 0b110u | 0b111u -> parseLogicalArithThreeRegImm phlp bin
  | _ (* 0b100u *) -> raise ParsingFailureException

/// Integer Data Processing (three register, register shift) on page F4-4229.
let parseIntegerDataProcThreeRegRegShf (phlp: ParsingHelper) bin =
  match pickFour bin 20 (* opc:S *) with
  | 0b0000u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.AND None OD.OprRdRnRmShfRs
  | 0b0001u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.ANDS None OD.OprRdRnRmShfRs
  | 0b0010u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.EOR None OD.OprRdRnRmShfRs
  | 0b0011u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.EORS None OD.OprRdRnRmShfRs
  | 0b0100u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.SUB None OD.OprRdRnRmShfRs
  | 0b0101u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.SUBS None OD.OprRdRnRmShfRs
  | 0b0110u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.RSB None OD.OprRdRnRmShfRs
  | 0b0111u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.RSBS None OD.OprRdRnRmShfRs
  | 0b1000u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.ADD None OD.OprRdRnRmShfRs
  | 0b1001u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.ADDS None OD.OprRdRnRmShfRs
  | 0b1010u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.ADC None OD.OprRdRnRmShfRs
  | 0b1011u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.ADCS None OD.OprRdRnRmShfRs
  | 0b1100u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.SBC None OD.OprRdRnRmShfRs
  | 0b1101u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.SBCS None OD.OprRdRnRmShfRs
  | 0b1110u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.RSC None OD.OprRdRnRmShfRs
  | _ (* 0b1111u *) ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.RSCS None OD.OprRdRnRmShfRs

/// Integer Test and Compare (two register, register shift) on page F4-4230.
let parseIntegerTestAndCompareTwoRegRegShf (phlp: ParsingHelper) bin =
  match pickTwo bin 21 (* opc *) with
  | 0b00u ->
#if !EMULATION
    chkPCRnRmRs bin
#endif
    render phlp bin Op.TST None OD.OprRnRmShfRs
  | 0b01u ->
#if !EMULATION
    chkPCRnRmRs bin
#endif
    render phlp bin Op.TEQ None OD.OprRnRmShfRs
  | 0b10u ->
#if !EMULATION
    chkPCRnRmRs bin
#endif
    render phlp bin Op.CMP None OD.OprRnRmShfRs
  | _ (* 0b11u *) ->
#if !EMULATION
    chkPCRnRmRs bin
#endif
    render phlp bin Op.CMN None OD.OprRnRmShfRs

/// Alias conditions on page F5-4562.
let changeToAliasOfMOVRegShf bin =
  let s = pickBit bin 20 (* S *)
  let stype = pickTwo bin 5 (* stype *)
  match concat s stype 2 (* S:stype *) with
  | 0b010u -> struct (Op.ASR, OD.OprRdRmRsA)
  | 0b000u -> struct (Op.LSL, OD.OprRdRmRsA)
  | 0b001u -> struct (Op.LSR, OD.OprRdRmRsA)
  | 0b011u -> struct (Op.ROR, OD.OprRdRmRsA)
  | _ -> struct (Op.MOV, OD.OprRdRmShfRsA)

/// Alias conditions on page F5-4562.
let changeToAliasOfMOVSRegShf bin =
  let s = pickBit bin 20 (* S *)
  let stype = pickTwo bin 5 (* stype *)
  match concat s stype 2 (* S:stype *) with
  | 0b110u -> struct (Op.ASRS, OD.OprRdRmRsA)
  | 0b100u -> struct (Op.LSLS, OD.OprRdRmRsA)
  | 0b101u -> struct (Op.LSRS, OD.OprRdRmRsA)
  | 0b111u -> struct (Op.RORS, OD.OprRdRmRsA)
  | _ -> struct (Op.MOVS, OD.OprRdRmShfRsA)

/// Logical Arithmetic (three register, register shift) on page F4-4230.
let parseLogicalArithThreeRegRegShf (phlp: ParsingHelper) bin =
  match pickThree bin 20 (* opc:S *) with
  | 0b000u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.ORR None OD.OprRdRnRmShfRs
  | 0b001u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.ORRS None OD.OprRdRnRmShfRs
  | 0b010u ->
#if !EMULATION
    chkPCRdRmRs bin
#endif
    let struct (opcode, oprFn) = changeToAliasOfMOVRegShf bin
    render phlp bin opcode None oprFn
  | 0b011u ->
#if !EMULATION
    chkPCRdRmRs bin
#endif
    let struct (opcode, oprFn) = changeToAliasOfMOVSRegShf bin
    render phlp bin opcode None oprFn
  | 0b100u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.BIC None OD.OprRdRnRmShfRs
  | 0b101u ->
#if !EMULATION
    chkPCRdRnRmRs bin
#endif
    render phlp bin Op.BICS None OD.OprRdRnRmShfRs
  | 0b110u ->
#if !EMULATION
    chkPCRdRmRs bin
#endif
    render phlp bin Op.MVN None OD.OprRdRmShfRsA
  | _ (* 0b111u *) ->
#if !EMULATION
    chkPCRdRmRs bin
#endif
    render phlp bin Op.MVNS None OD.OprRdRmShfRsA

/// Data-processing register (register shift) on page F4-4229.
let parseDataProcRegisterRegShf (phlp: ParsingHelper) bin =
  match concat (pickTwo bin 23) (pickBit bin 20) 1 (* op0:op1 *) with
  | 0b000u | 0b001u | 0b010u | 0b011u ->
    parseIntegerDataProcThreeRegRegShf phlp bin
  | 0b101u -> parseIntegerTestAndCompareTwoRegRegShf phlp bin
  | 0b110u | 0b111u -> parseLogicalArithThreeRegRegShf phlp bin
  | _ (* 0b100u *) -> raise ParsingFailureException

/// Data-processing and miscellaneous instructions on page F4-4218.
let parseCase000 (phlp: ParsingHelper) bin =
  let op1 = pickFive bin 20
  let is0xxxx bin = bin &&& 0b10000u = 0b00000u
  let is10xx0 bin = bin &&& 0b11001u = 0b10000u
  match pickFour bin 4 (* op2:op3:op4 *) with
  | 0b1011u | 0b1101u | 0b1111u -> parseExtraLoadStore phlp bin
  | 0b1001u when is0xxxx op1 -> parseMultiplyAndAccumlate phlp bin
  | 0b1001u (* op1 = 0b1xxxxu *) -> parseSyncAndLoadAcqStoreRel phlp bin
  | 0b0000u | 0b0010u | 0b0100u | 0b0110u | 0b0001u | 0b0011u | 0b0101u
  | 0b0111u when is10xx0 op1 -> parseMiscellaneous phlp bin
  | 0b1000u | 0b1010u | 0b1100u | 0b1110u when is10xx0 op1 ->
    parseHalfMulAndAccumulate phlp bin
  | 0b0000u | 0b0010u | 0b0100u | 0b0110u | 0b1000u | 0b1010u | 0b1100u
  | 0b1110u -> parseDataProcRegisterImmShf phlp bin
  | _ (* 0b0xx1u *) -> parseDataProcRegisterRegShf phlp bin

/// Integer Data Processing (two register and immediate) on page F4-4231.
let parseIntDataProc0100 (phlp: ParsingHelper) bin =
  match pickFour bin 16 (* Rn *) with
  | 0b1101u -> render phlp bin Op.SUB None OD.OprRdSPConstA
  | _ (* != 0b11x1u *) -> render phlp bin Op.SUB None OD.OprRdRnConstA

/// Integer Data Processing (two register and immediate) on page F4-4231.
let parseIntDataProc0101 (phlp: ParsingHelper) bin =
  match pickFour bin 16 (* Rn *) with
  | 0b1101u -> render phlp bin Op.SUBS None OD.OprRdSPConstA
  | _ (* != 0b1101u *) ->
    render phlp bin Op.SUBS None OD.OprRdRnConstA

/// Integer Data Processing (two register and immediate) on page F4-4231.
let parseIntDataProc1000 (phlp: ParsingHelper) bin =
  match pickFour bin 16 (* Rn *) with
  | 0b1101u -> render phlp bin Op.ADD None OD.OprRdSPConstA
  | _ (* != 0b11x1u *) -> render phlp bin Op.ADD None OD.OprRdRnConstA

/// Integer Data Processing (two register and immediate) on page F4-4231.
let parseIntDataProc1001 (phlp: ParsingHelper) bin =
  match pickFour bin 16 (* Rn *) with
  | 0b1101u -> render phlp bin Op.ADDS None OD.OprRdSPConstA
  | _ (* != 0b1101u *) -> render phlp bin Op.ADDS None OD.OprRdRnConstA

/// Integer Data Processing (two register and immediate) on page F4-4231.
let parseIntegerDataProcessing (phlp: ParsingHelper) bin =
  match pickFour bin 20 (* opc:S *) with
  | 0b0000u -> render phlp bin Op.AND None OD.OprRdRnConstA
  | 0b0001u -> render phlp bin Op.ANDS None OD.OprRdRnConstCF
  | 0b0010u -> render phlp bin Op.EOR None OD.OprRdRnConstA
  | 0b0011u -> render phlp bin Op.EORS None OD.OprRdRnConstCF
  | 0b0100u -> parseIntDataProc0100 phlp bin
  | 0b0101u -> parseIntDataProc0101 phlp bin
  | 0b0110u -> render phlp bin Op.RSB None OD.OprRdRnConstA
  | 0b0111u -> render phlp bin Op.RSBS None OD.OprRdRnConstA
  | 0b1000u -> parseIntDataProc1000 phlp bin
  | 0b1001u -> parseIntDataProc1001 phlp bin
  | 0b1010u -> render phlp bin Op.ADC None OD.OprRdRnConstA
  | 0b1011u -> render phlp bin Op.ADCS None OD.OprRdRnConstA
  | 0b1100u -> render phlp bin Op.SBC None OD.OprRdRnConstA
  | 0b1101u -> render phlp bin Op.SBCS None OD.OprRdRnConstA
  | 0b1110u -> render phlp bin Op.RSC None OD.OprRdRnConstA
  | 0b1111u -> render phlp bin Op.RSCS None OD.OprRdRnConstA
  | _ (* 0b1111u *) -> render phlp bin Op.RSCS None OD.OprRdRnConstA

/// Move Halfword (immediate) on page F4-4232.
let parseMoveHalfword (phlp: ParsingHelper) bin =
  match pickBit bin 22 (* H *) with
  | 0b0u -> render phlp bin Op.MOVW None OD.OprRdImm16A
  | _ (* 0b1u *) -> render phlp bin Op.MOVT None OD.OprRdImm16A

/// Move Special Register and Hints (immediate) on page F4-4233.
let parseMovSpecReg00 (phlp: ParsingHelper) bin =
  match extract bin 5 0 (* imm12<5:0> *) with
  | 0b000000u -> render phlp bin Op.NOP None OD.OprNo
  | 0b000001u -> render phlp bin Op.YIELD None OD.OprNo
  | 0b000010u -> render phlp bin Op.WFE None OD.OprNo
  | 0b000011u -> render phlp bin Op.WFI None OD.OprNo
  | 0b000100u -> render phlp bin Op.SEV None OD.OprNo
  | 0b000101u -> render phlp bin Op.SEVL None OD.OprNo (* AArch32 *)
  | 0b000110u | 0b000111u -> render phlp bin Op.NOP None OD.OprNo
  | imm when imm &&& 0b111000u = 0b001000u (* 0b001xxx *) ->
    render phlp bin Op.NOP None OD.OprNo
  | 0b010000u ->
    phlp.Cond <> Condition.AL |> checkUnpred
    render phlp bin Op.ESB None OD.OprNo (* Armv8.2 *)
  | 0b010001u -> render phlp bin Op.NOP None OD.OprNo
  | 0b010010u -> (* TSB CSYNC *)
    phlp.Cond <> Condition.AL |> checkUnpred
    render phlp bin Op.TSB None OD.OprNo (* Armv8.4 *)
  | 0b010011u -> render phlp bin Op.NOP None OD.OprNo
  | 0b010100u ->
    phlp.Cond <> Condition.AL |> checkUnpred
    render phlp bin Op.CSDB None OD.OprNo
  | 0b010101u -> render phlp bin Op.NOP None OD.OprNo
  | imm when imm &&& 0b111000u = 0b011000u (* 0b011xxx *) ->
    render phlp bin Op.NOP None OD.OprNo
  | imm when imm &&& 0b111110u = 0b011110u (* 0b01111x *) ->
    render phlp bin Op.NOP None OD.OprNo
  | imm when imm &&& 0b100000u = 0b100000u (* 0b1xxxxx *) ->
    render phlp bin Op.NOP None OD.OprNo
  | _ -> raise ParsingFailureException

let parseMovSpecReg11 (phlp: ParsingHelper) bin =
  match pickTwo bin 4 with
  | 0b10u -> render phlp bin Op.NOP None OD.OprNo
  | 0b11u -> render phlp bin Op.DBG None OD.OprNo
  | _ (* 0b0xu *) -> render phlp bin Op.NOP None OD.OprNo

/// Move Special Register and Hints (immediate) on page F4-4233.
let parseMoveSpecialRegisterAndHints (phlp: ParsingHelper) bin =
  let rimm4 = concat (pickBit bin 22) (pickFour bin 16) 4
  checkUndef (pickFour bin 12 <> 0b1111u)
  match pickTwo bin 6 (* imm12<7:6> *) with
  | _ when rimm4 <> 0b00000u ->
    render phlp bin Op.MSR None OD.OprSregImm
  | 0b00u -> parseMovSpecReg00 phlp bin
  | 0b01u -> render phlp bin Op.NOP None OD.OprNo
  | 0b10u -> render phlp bin Op.NOP None OD.OprNo
  | _ (* 0b11u *) -> parseMovSpecReg11 phlp bin

/// Integer Test and Compare (one register and immediate) on page F4-4233.
let parseIntegerTestAndCompareOneReg (phlp: ParsingHelper) bin =
  match pickTwo bin 21 (* opc *) with
  | 0b00u -> render phlp bin Op.TST None OD.OprRnConstCF
  | 0b01u -> render phlp bin Op.TEQ None OD.OprRnConstCF
  | 0b10u -> render phlp bin Op.CMP None OD.OprRnConstA
  | _ (* 0b11u *) -> render phlp bin Op.CMN None OD.OprRnConstA

let parseCase00110 (phlp: ParsingHelper) bin =
  match pickTwo bin 20 with
  | 0b00u -> parseMoveHalfword phlp bin
  | 0b10u -> parseMoveSpecialRegisterAndHints phlp bin
  | _ (* 0bx1u *) -> parseIntegerTestAndCompareOneReg phlp bin

/// Logical Arithmetic (two register and immediate) on page F4-4234.
let parseLogicalArithmetic (phlp: ParsingHelper) bin =
  match (pickThree bin 20) (* opc:S *) with
  | 0b000u -> render phlp bin Op.ORR None OD.OprRdRnConstA
  | 0b001u -> render phlp bin Op.ORRS None OD.OprRdRnConstCF
  | 0b010u -> render phlp bin Op.MOV None OD.OprRdConstA
  | 0b011u -> render phlp bin Op.MOVS None OD.OprRdConstCF
  | 0b100u -> render phlp bin Op.BIC None OD.OprRdRnConstA
  | 0b101u -> render phlp bin Op.BICS None OD.OprRdRnConstCF
  | 0b110u -> render phlp bin Op.MVN None OD.OprRdConstA
  | _ (* 0b111u *) -> render phlp bin Op.MVNS None OD.OprRdConstCF

/// Data-processing immediate on page F4-4231.
let parseCase001 (phlp: ParsingHelper) bin =
  match pickTwo bin 23 (* op0 *) with
  | 0b00u | 0b01u -> parseIntegerDataProcessing phlp bin
  | 0b10u -> parseCase00110 phlp bin
  | _ (* 0b11u *) -> parseLogicalArithmetic phlp bin

/// Data-processing and miscellaneous instructions on page F4-4218.
let parseCase00 (phlp: ParsingHelper) bin =
  match pickBit bin 25 (* op0 *) with
  | 0b0u -> parseCase000 phlp bin
  | _ (* 0b1u *) -> parseCase001 phlp bin

/// Alias conditions on page F5-4453.
let changeToAliasOfLDR bin =
  (* U == '1' && Rn == '1101' && imm12 == '000000000100' *)
  let isRn1101 = pickFour bin 16 = 0b1101u
  if (pickBit bin 23 = 1u) && isRn1101 && (extract bin 11 0 = 0b100u) then
    struct (Op.POP, OD.OprSingleRegsA)
  else struct (Op.LDR, OD.OprRtMemImm12A)

/// Alias conditions on page F5-4819.
let changeToAliasOfSTR bin =
  (* U == '0' && Rn == '1101' && imm12 == '000000000100' *)
  let isRn1101 = pickFour bin 16 = 0b1101u
  if (pickBit bin 23 = 0u) && isRn1101 && (extract bin 11 0 = 0b100u) then
    struct (Op.PUSH, OD.OprSingleRegsA)
  else struct (Op.STR, OD.OprRtMemImm12A)

/// Load/Store Word, Unsigned Byte (immediate, literal) on page F4-4234.
let parseCase010 (phlp: ParsingHelper) bin =
  let rn = pickFour bin 16
  match pickFourBitsApart bin 24 21 22 20 (* P:W:o2:o1 *) with
  (* LDR (literal) *)
  | 0b0001u when rn = 0b1111u ->
#if !EMULATION
    chkWback bin
#endif
    render phlp bin Op.LDR None OD.OprRtLabelA
  | 0b1001u when rn = 0b1111u ->
#if !EMULATION
    chkWback bin
#endif
    render phlp bin Op.LDR None OD.OprRtLabelA
  | 0b1101u when rn = 0b1111u ->
#if !EMULATION
    chkWback bin
#endif
    render phlp bin Op.LDR None OD.OprRtLabelA
  (* LDRB (literal) *)
  | 0b0011u when rn = 0b1111u ->
#if !EMULATION
    chkPCRtWithWB bin
#endif
    render phlp bin Op.LDRB None OD.OprRtLabelA
  | 0b1011u when rn = 0b1111u ->
#if !EMULATION
    chkPCRtWithWB bin
#endif
    render phlp bin Op.LDRB None OD.OprRtLabelA
  | 0b1111u when rn = 0b1111u ->
#if !EMULATION
    chkPCRtWithWB bin
#endif
    render phlp bin Op.LDRB None OD.OprRtLabelA
  | 0b0000u -> (* STR (immediate) - Post-indexed variant *)
#if !EMULATION
    chkPCRnRt bin
#endif
    render phlp bin Op.STR None OD.OprRtMemImm12A
  | 0b0001u (* rn != 1111 *) -> (* LDR (immediate) - Post-indexed variant *)
#if !EMULATION
    chkRnRt bin
#endif
    let struct (opcode, oprFn) = changeToAliasOfLDR bin
    render phlp bin opcode None oprFn
  | 0b0010u -> (* STRB (immediate) - Post-indexed variant *)
#if !EMULATION
    chkPCRnRtWithWB bin
#endif
    render phlp bin Op.STRB None OD.OprRtMemImm12A
  | 0b0011u (* rn != 1111 *) -> (* LDRB (immediate) - Post-indexed variant *)
#if !EMULATION
    chkPCRtRnWithWB bin
#endif
    render phlp bin Op.LDRB None OD.OprRtMemImm12A
  | 0b0100u ->
#if !EMULATION
    chkPCRnRt bin
#endif
    render phlp bin Op.STRT None OD.OprRtMemImm12P
  | 0b0101u ->
#if !EMULATION
    chkPCRtRnEq bin
#endif
    render phlp bin Op.LDRT None OD.OprRtMemImm12P
  | 0b0110u ->
#if !EMULATION
    chkPCRtRnEq bin
#endif
    render phlp bin Op.STRBT None OD.OprRtMemImm12P
  | 0b0111u ->
#if !EMULATION
    chkPCRtRnEq bin
#endif
    render phlp bin Op.LDRBT None OD.OprRtMemImm12P
  | 0b1000u ->
#if !EMULATION
    chkPCRnWithWB bin
#endif
    render phlp bin Op.STR None OD.OprRtMemImm12A
  | 0b1001u (* rn != 1111 *) ->
#if !EMULATION
    chkRnRt bin
#endif
    render phlp bin Op.LDR None OD.OprRtMemImm12A
  | 0b1010u ->
#if !EMULATION
    chkPCRnRtWithWB bin
#endif
    render phlp bin Op.STRB None OD.OprRtMemImm12A
  | 0b1011u (* rn != 1111 *) ->
#if !EMULATION
    chkPCRtRnWithWB bin
#endif
    render phlp bin Op.LDRB None OD.OprRtMemImm12A
  | 0b1100u ->
#if !EMULATION
    chkPCRnRt bin
#endif
    let struct (opcode, oprFn) = changeToAliasOfSTR bin
    render phlp bin opcode None oprFn
  | 0b1101u (* rn != 1111 *) ->
#if !EMULATION
    chkRnRt bin
#endif
    render phlp bin Op.LDR None OD.OprRtMemImm12A
  | 0b1110u ->
#if !EMULATION
    chkPCRnRtWithWB bin
#endif
    render phlp bin Op.STRB None OD.OprRtMemImm12A
  | _ (* 0b1111u & rn != 1111 *) ->
#if !EMULATION
    chkPCRtRnWithWB bin
#endif
    render phlp bin Op.LDRB None OD.OprRtMemImm12A

/// Load/Store Word, Unsigned Byte (register) on page F4-4235.
let parseCase0110 (phlp: ParsingHelper) bin =
  match ((bin >>> 21) &&& 0b1000u) ||| (pickThree bin 20) (* P:o2:W:o1 *) with
  | 0b0000u ->
#if !EMULATION
    chkPCRmRn bin
#endif
    render phlp bin Op.STR None OD.OprRtMemShf
  | 0b0001u ->
#if !EMULATION
    chkPCRmRn bin
#endif
    render phlp bin Op.LDR None OD.OprRtMemShf
  | 0b0010u ->
#if !EMULATION
    chkPCRnRm bin
#endif
    render phlp bin Op.STRT None OD.OprRtMemShfP
  | 0b0011u ->
#if !EMULATION
    chkPCRtRnRm bin
#endif
    render phlp bin Op.LDRT None OD.OprRtMemShfP
  | 0b0100u ->
#if !EMULATION
    chkPCRtRm bin
#endif
    render phlp bin Op.STRB None OD.OprRtMemShf
  | 0b0101u ->
#if !EMULATION
    chkPCRtRm bin
#endif
    render phlp bin Op.LDRB None OD.OprRtMemShf
  | 0b0110u ->
#if !EMULATION
    chkPCRtRnRm bin
#endif
    render phlp bin Op.STRBT None OD.OprRtMemShfP
  | 0b0111u ->
#if !EMULATION
    chkPCRtRnRm bin
#endif
    render phlp bin Op.LDRBT None OD.OprRtMemShfP
  | 0b1000u | 0b1010u ->
#if !EMULATION
    chkPCRmRn bin
#endif
    render phlp bin Op.STR None OD.OprRtMemShf
  | 0b1001u | 0b1011u ->
#if !EMULATION
    chkPCRmRn bin
#endif
    render phlp bin Op.LDR None OD.OprRtMemShf
  | 0b1100u | 0b1110u ->
#if !EMULATION
    chkPCRtRm bin
#endif
    render phlp bin Op.STRB None OD.OprRtMemShf
  | _ (*  0b11x1u *) ->
#if !EMULATION
    chkPCRtRm bin
#endif
    render phlp bin Op.LDRB None OD.OprRtMemShf

/// Parallel Arithmetic on page F4-4237.
let parseParallelArith (phlp: ParsingHelper) bin =
  match concat (pickThree bin 20) (pickThree bin 5) 3 (* op1:B:op2 *) with
  | 0b000000u | 0b000001u | 0b000010u | 0b000111u | 0b000100u | 0b000101u
  | 0b000110u | 0b000111u (* 000xxx *) -> raise ParsingFailureException
  | 0b001000u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.SADD16 None OD.OprRdRnRm
  | 0b001001u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.SASX None OD.OprRdRnRm
  | 0b001010u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.SSAX None OD.OprRdRnRm
  | 0b001011u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.SSUB16 None OD.OprRdRnRm
  | 0b001100u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.SADD8 None OD.OprRdRnRm
  | 0b001101u -> raise ParsingFailureException
  | 0b001110u -> raise ParsingFailureException
  | 0b001111u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.SSUB8 None OD.OprRdRnRm
  | 0b010000u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.QADD16 None OD.OprRdRnRm
  | 0b010001u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.QASX None OD.OprRdRnRm
  | 0b010010u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.QSAX None OD.OprRdRnRm
  | 0b010011u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.QSUB16 None OD.OprRdRnRm
  | 0b010100u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.QADD8 None OD.OprRdRnRm
  | 0b010101u -> raise ParsingFailureException
  | 0b010110u -> raise ParsingFailureException
  | 0b010111u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.QSUB8 None OD.OprRdRnRm
  | 0b011000u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.SHADD16 None OD.OprRdRnRm
  | 0b011001u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.SHASX None OD.OprRdRnRm
  | 0b011010u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.SHSAX None OD.OprRdRnRm
  | 0b011011u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.SHSUB16 None OD.OprRdRnRm
  | 0b011100u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.SHADD8 None OD.OprRdRnRm
  | 0b011101u -> raise ParsingFailureException
  | 0b011110u -> raise ParsingFailureException
  | 0b011111u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.SHSUB8 None OD.OprRdRnRm
  | 0b100000u | 0b100001u | 0b100010u | 0b100111u | 0b100100u | 0b100101u
  | 0b100110u | 0b100111u (* 100xxx *) -> raise ParsingFailureException
  | 0b101000u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UADD16 None OD.OprRdRnRm
  | 0b101001u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UASX None OD.OprRdRnRm
  | 0b101010u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.USAX None OD.OprRdRnRm
  | 0b101011u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.USUB16 None OD.OprRdRnRm
  | 0b101100u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UADD8 None OD.OprRdRnRm
  | 0b101101u -> raise ParsingFailureException
  | 0b101110u -> raise ParsingFailureException
  | 0b101111u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.USUB8 None OD.OprRdRnRm
  | 0b110000u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UQADD16 None OD.OprRdRnRm
  | 0b110001u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UQASX None OD.OprRdRnRm
  | 0b110010u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UQSAX None OD.OprRdRnRm
  | 0b110011u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UQSUB16 None OD.OprRdRnRm
  | 0b110100u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UQADD8 None OD.OprRdRnRm
  | 0b110101u -> raise ParsingFailureException
  | 0b110110u -> raise ParsingFailureException
  | 0b110111u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UQSUB8 None OD.OprRdRnRm
  | 0b111000u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UHADD16 None OD.OprRdRnRm
  | 0b111001u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UHASX None OD.OprRdRnRm
  | 0b111010u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UHSAX None OD.OprRdRnRm
  | 0b111011u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UHSUB16 None OD.OprRdRnRm
  | 0b111100u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UHADD8 None OD.OprRdRnRm
  | 0b111101u -> raise ParsingFailureException
  | 0b111110u -> raise ParsingFailureException
  | _ (* 0b111111u *) ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.UHSUB8 None OD.OprRdRnRm

/// Saturate 16-bit on page F4-4239.
let parseSaturate16bit (phlp: ParsingHelper) bin =
  match pickBit bin 22 (* U *) with
  | 0b0u ->
#if !EMULATION
    chkPCRdRn bin
#endif
    render phlp bin Op.SSAT16 None OD.OprRdImmRnA
  | _ (* 0b1u *) ->
#if !EMULATION
    chkPCRdRn bin
#endif
    render phlp bin Op.USAT16 None OD.OprRdImmRnA

/// Reverse Bit/Byte on page F4-4240.
let parseReverseBitByte (phlp: ParsingHelper) bin =
  match pickTwoBitsApart bin 22 7 (* o1:o2 *) with
  | 0b00u ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.REV None OD.OprRdRm
  | 0b01u ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.REV16 None OD.OprRdRm
  | 0b10u ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.RBIT None OD.OprRdRm
  | _ (* 0b11u *) ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.REVSH None OD.OprRdRm

/// Saturate 32-bit on page F4-4240.
let parseSaturate32bit (phlp: ParsingHelper) bin =
  match pickBit bin 22 (* U *) with
  | 0b0u ->
#if !EMULATION
    chkPCRdRn bin
#endif
    render phlp bin Op.SSAT None OD.OprRdImmRnShfA
  | _ (* 0b1u *) ->
#if !EMULATION
    chkPCRdRn bin
#endif
    render phlp bin Op.USAT None OD.OprRdImmRnShfUA

/// Extend and Add on page F4-4241.
let parseExtendAndAdd (phlp: ParsingHelper) bin =
  let isNotRn1111 bin = pickFour bin 16 <> 0b1111u (* Rn != 1111 *)
  match pickThree bin 20 (* U:op *) with
  | 0b000u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.SXTAB16 None OD.OprRdRnRmRorA
  | 0b000u ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.SXTB16 None OD.OprRdRmRorA
  | 0b010u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.SXTAB None OD.OprRdRnRmRorA
  | 0b010u ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.SXTB None OD.OprRdRmRorA
  | 0b011u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.SXTAH None OD.OprRdRnRmRorA
  | 0b011u ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.SXTH None OD.OprRdRmRorA
  | 0b100u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.UXTAB16 None OD.OprRdRnRmRorA
  | 0b100u ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.UXTB16 None OD.OprRdRmRorA
  | 0b110u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.UXTAB None OD.OprRdRnRmRorA
  | 0b110u ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.UXTB None OD.OprRdRmRorA
  | 0b111u when isNotRn1111 bin ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.UXTAH None OD.OprRdRnRmRorA
  | _ (* 0b111u *) ->
#if !EMULATION
    chkPCRdRm bin
#endif
    render phlp bin Op.UXTH None OD.OprRdRmRorA

/// Signed multiply, Divide on page F4-4241.
let parseSignedMulDiv (phlp: ParsingHelper) bin =
  (* a <> Ra != 1111 *)
  let isNotRa1111 bin = pickFour bin 12 <> 0b1111u
  match concat (pickThree bin 20) (pickThree bin 5) 3 (* op1:op2 *) with
  | 0b000000u when isNotRa1111 bin ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMLAD None OD.OprRdRnRmRaA
  | 0b000001u when isNotRa1111 bin ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMLADX None OD.OprRdRnRmRaA
  | 0b000010u when isNotRa1111 bin ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMLSD None OD.OprRdRnRmRaA
  | 0b000011u when isNotRa1111 bin ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMLSDX None OD.OprRdRnRmRaA
  | 0b000100u | 0b000101u | 0b000110u | 0b000111u (* 0001xx *) ->
    raise ParsingFailureException
  | 0b000000u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMUAD None OD.OprRdRnRmOpt
  | 0b000001u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMUADX None OD.OprRdRnRmOpt
  | 0b000010u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMUSD None OD.OprRdRnRmOpt
  | 0b000011u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMUSDX None OD.OprRdRnRmOpt
  | 0b001000u ->
#if !EMULATION
    chkPCRdRnRmRaNot bin
#endif
    render phlp bin Op.SDIV None OD.OprRdRnRmOpt
  | 0b001001u | 0b001010u | 0b001011u | 0b001100u | 0b001101u | 0b001110u
  | 0b001111u (* 001 - != 000 *) -> raise ParsingFailureException
  | 0b010000u | 0b010001u | 0b010010u | 0b010011u | 0b010100u | 0b010101u
  | 0b010110u | 0b010111u (* 010 - - *) -> raise ParsingFailureException
  | 0b011000u ->
#if !EMULATION
    chkPCRdRnRmRaNot bin
#endif
    render phlp bin Op.UDIV None OD.OprRdRnRmOpt
  | 0b011001u | 0b011010u | 0b011011u | 0b011100u | 0b011101u | 0b011110u
  | 0b011111u (* 001 - != 000 *) -> raise ParsingFailureException
  | 0b100000u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.SMLALD None OD.OprRdlRdhRnRmA
  | 0b100001u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.SMLALDX None OD.OprRdlRdhRnRmA
  | 0b100010u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.SMLSLD None OD.OprRdlRdhRnRmA
  | 0b100011u ->
#if !EMULATION
    chkPCRdlRdhRnRm bin
#endif
    render phlp bin Op.SMLSLDX None OD.OprRdlRdhRnRmA
  | 0b100100u | 0b100101u | 0b100110u | 0b100111u (* 100 - 1xx *) ->
    raise ParsingFailureException
  | 0b101000u when isNotRa1111 bin ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMMLA None OD.OprRdRnRmRaA
  | 0b101001u when isNotRa1111 bin ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMMLAR None OD.OprRdRnRmRaA
  | 0b101010u | 0b101011u (* 101 - 01x *) -> raise ParsingFailureException
  | 0b101100u | 0b101101u (* 101 - 10x *) -> raise ParsingFailureException
  | 0b101110u ->
#if !EMULATION
    chkPCRdRnRmRa bin
#endif
    render phlp bin Op.SMMLS None OD.OprRdRnRmRaA
  | 0b101111u ->
#if !EMULATION
    chkPCRdRnRmRa bin
#endif
    render phlp bin Op.SMMLSR None OD.OprRdRnRmRaA
  | 0b101000u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMMUL None OD.OprRdRnRmOpt
  | 0b101001u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.SMMULR None OD.OprRdRnRmOpt
  | _ (* 11x - - *) -> raise ParsingFailureException

/// Unsigned Sum of Absolute Differences on page F4-4242.
let parseUnsignedSumOfAbsoluteDiff (phlp: ParsingHelper) bin =
  match pickFour bin 12 (* Ra *) with
  | 0b1111u ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.USAD8 None OD.OprRdRnRmOpt
  | _ (* != 1111 *) ->
#if !EMULATION
    chkPCRdRnRm bin
#endif
    render phlp bin Op.USADA8 None OD.OprRdRnRmRaA

/// Bitfield Insert on page F4-4243.
let parseBitfieldInsert (phlp: ParsingHelper) bin =
  match pickFour bin 0 (* Rn *) with
  | 0b1111u ->
#if !EMULATION
    chkPCRd bin
#endif
    render phlp bin Op.BFC None OD.OprRdLsbWidthA
  | _ (* != 1111 *) ->
#if !EMULATION
    chkPCRd bin
#endif
    render phlp bin Op.BFI None OD.OprRdRnLsbWidthA

/// Permanently UNDEFINED on page F4-4243.
let parsePermanentlyUndef (phlp: ParsingHelper) bin =
  if phlp.Cond <> Condition.AL then raise ParsingFailureException
  else render phlp bin Op.UDF None OD.OprImm16A

/// Bitfield Extract on page F4-4244.
let parseBitfieldExtract (phlp: ParsingHelper) bin =
  match pickBit bin 22 (* U *) with
  | 0b0u ->
#if !EMULATION
    chkPCRdRn bin
#endif
    render phlp bin Op.SBFX None OD.OprRdRnLsbWidthM1A
  | _ (* 0b1u *) ->
#if !EMULATION
    chkPCRdRn bin
#endif
    render phlp bin Op.UBFX None OD.OprRdRnLsbWidthM1A

/// Media instructions on page F4-4236.
let parseCase0111 (phlp: ParsingHelper) bin =
  match concat (pickFive bin 20) (pickThree bin 5) 3 (* op0:op1 *) with
  | b when b &&& 0b11000000u = 0b00000000u (* 0b00xxxxxx *) ->
    parseParallelArith phlp bin
  | 0b01000101u ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.SEL None OD.OprRdRnRm
  | 0b01000001u -> raise ParsingFailureException
  | 0b01000000u | 0b01000100u (* 01000x00 *) ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.PKHBT None OD.OprRdRnRmShfA
  | 0b01000010u | 0b01000110u (* 01000x10 *) ->
#if !EMULATION
    chkPCRdOptRnRm bin
#endif
    render phlp bin Op.PKHTB None OD.OprRdRnRmShfA
  | 0b01001001u | 0b01001101u (* 01001x01 *) -> raise ParsingFailureException
  | 0b01001000u | 0b01001010u | 0b01001100u | 0b01001110u (* 01001xx0 *) ->
    raise ParsingFailureException
  | 0b01100001u | 0b01100101u | 0b01101001u | 0b01101101u (* 0110xx01 *) ->
    raise ParsingFailureException
  | 0b01100000u | 0b01100010u | 0b01100100u | 0b01100110u | 0b01101000u
  | 0b01101010u | 0b01101100u | 0b01101110u (* 0110xxx0 *) ->
    raise ParsingFailureException
  | 0b01010001u | 0b01110001u (* 01x10001 *) ->
    parseSaturate16bit phlp bin
  | 0b01010101u | 0b01110101u (* 01x10101 *) -> raise ParsingFailureException
  | 0b01011001u | 0b01011101u | 0b01111001u | 0b01111101u (* 01x11x01 *) ->
    parseReverseBitByte phlp bin
  | 0b01010000u | 0b01010010u | 0b01010100u | 0b01010110u | 0b01011000u
  | 0b01011010u | 0b01011100u | 0b01011110u | 0b01110000u | 0b01110010u
  | 0b01110100u | 0b01110110u | 0b01111000u | 0b01111010u | 0b01111100u
  | 0b01111110u (* 01x1xxx0 *) -> parseSaturate32bit phlp bin
  | 0b01000111u | 0b01001111u | 0b01010111u | 0b01011111u | 0b01100111u
  | 0b01101111u | 0b01110111u | 0b01111111u (* 01xxx111 *) ->
    raise ParsingFailureException
  | 0b01000011u | 0b01001011u | 0b01010011u | 0b01011011u | 0b01100011u
  | 0b01101011u | 0b01110011u | 0b01111011u (* 01xxx011 *) ->
    parseExtendAndAdd phlp bin
  | b when b &&& 0b11000000u = 0b10000000u (* 10xxxxxx *) ->
    parseSignedMulDiv phlp bin
  | 0b11000000u -> parseUnsignedSumOfAbsoluteDiff phlp bin
  | 0b11000100u -> raise ParsingFailureException
  | 0b11001000u | 0b11001100u (* 11001x00 *) -> raise ParsingFailureException
  | 0b11010000u | 0b11010100u | 0b11011000u | 0b11011100u (* 1101xx00 *) ->
    raise ParsingFailureException
  | 0b11000111u | 0b11001111u | 0b11010111u | 0b11011111u (* 110xx111 *) ->
    raise ParsingFailureException
  | 0b11100111u | 0b11101111u (* 1110x111 *) -> raise ParsingFailureException
  | 0b11100000u | 0b11100100u | 0b11101000u | 0b11101100u (* 1110xx00 *) ->
    parseBitfieldInsert phlp bin
  | 0b11110111u -> raise ParsingFailureException
  | 0b11111111u -> parsePermanentlyUndef phlp bin
  | 0b11110000u | 0b11110100u | 0b11111000u | 0b11111100u (* 1111xx00 *) ->
    raise ParsingFailureException
  | 0b11000010u | 0b11000110u | 0b11001010u | 0b11001110u | 0b11100010u
  | 0b11100110u | 0b11101010u | 0b11101110u (* 11x0xx10 *) ->
    raise ParsingFailureException
  | 0b11010010u | 0b11010110u | 0b11011010u | 0b11011110u | 0b11110010u
  | 0b11110110u | 0b11111010u | 0b11111110u (* 11x1xx10 *) ->
    parseBitfieldExtract phlp bin
  | 0b11000011u | 0b11001011u | 0b11010011u | 0b11011011u | 0b11100011u
  | 0b11101011u | 0b11110011u | 0b11111011u (* 11xxx011 *) ->
    raise ParsingFailureException
  | b when b &&& 0b11000011u = 0b11000001u (* 11xxxx01 *) ->
    raise ParsingFailureException
  | _ -> raise ParsingFailureException

let parseCase011 (phlp: ParsingHelper) bin =
  match pickBit bin 4 with
  | 0b0u -> parseCase0110 phlp bin
  | _ (* 0b1u *) -> parseCase0111 phlp bin

let parseCase01 (phlp: ParsingHelper) bin =
  match pickBit bin 25 with
  | 0b0u -> parseCase010 phlp bin
  | _ (* 0b1u *) -> parseCase011 phlp bin

/// Exception Save/Restore on page F4-4244.
let parseExceptionSaveStore (phlp: ParsingHelper) bin =
  match concat (pickThree bin 22) (pickBit bin 20) 1 (* P:U:S:L *) with
  | 0b0001u ->
#if !EMULATION
    chkPCRn bin
#endif
    render phlp bin Op.RFEDA None OD.OprRn
  | 0b0010u -> render phlp bin Op.SRSDA None OD.OprSPMode
  | 0b0101u ->
#if !EMULATION
    chkPCRn bin
#endif
    render phlp bin Op.RFEIA None OD.OprRn
  | 0b0110u -> render phlp bin Op.SRSIA None OD.OprSPMode
  | 0b1001u ->
#if !EMULATION
    chkPCRn bin
#endif
    render phlp bin Op.RFEDB None OD.OprRn
  | 0b1010u -> render phlp bin Op.SRSDB None OD.OprSPMode
  | 0b1101u ->
#if !EMULATION
    chkPCRn bin
#endif
    render phlp bin Op.RFEIB None OD.OprRn
  | 0b1110u -> render phlp bin Op.SRSIB None OD.OprSPMode
  | _ (* 0b--00u or 0b--11u *) -> raise ParsingFailureException

/// Alias conditions on page F5-4438.
let changeToAliasOfLDM bin =
  if (wbackW bin) && (pickFour bin 16 = 0b1101u) &&
     (bitCount (extract bin 15 0) 15 > 1)
  then struct (Op.POP, OD.OprRegs)
  else struct (Op.LDM, OD.OprRnRegsA)

/// Alias conditions on page F5-4813.
let changeToAliasOfSTMDB bin =
  if (pickBit bin 21 = 1u) && (pickFour bin 16 = 0b1101u) &&
     (bitCount (extract bin 15 0) 15 > 1)
  then struct (Op.PUSH, OD.OprRegs)
  else struct (Op.STMDB, OD.OprRnRegsA)

/// Load/Store Multiple on page F4-4245.
let parseLoadStoreMultiple (phlp: ParsingHelper) bin =
  match concat (pickThree bin 22) (pickBit bin 20) 1 (* P:U:op:L *) with
  | 0b0000u ->
#if !EMULATION
    chkPCRnRegs bin
#endif
    render phlp bin Op.STMDA None OD.OprRnRegsA
  | 0b0001u ->
#if !EMULATION
    chkWBRegs bin
#endif
    render phlp bin Op.LDMDA None OD.OprRnRegsA
  | 0b0100u ->
#if !EMULATION
    chkPCRnRegs bin
#endif
    render phlp bin Op.STM None OD.OprRnRegsA
  | 0b0101u ->
#if !EMULATION
    chkWBRegs bin
#endif
    let struct (opcode, oprFn) = changeToAliasOfLDM bin
    render phlp bin opcode None oprFn
  | 0b0010u ->
#if !EMULATION
    chkPCRnRegs bin
#endif
    render phlp bin Op.STMDA None OD.OprRnRegsCaret
  | 0b0110u ->
#if !EMULATION
    chkPCRnRegs bin
#endif
    render phlp bin Op.STMIA None OD.OprRnRegsCaret
  | 0b1010u ->
#if !EMULATION
    chkPCRnRegs bin
#endif
    render phlp bin Op.STMDB None OD.OprRnRegsCaret
  | 0b1110u ->
#if !EMULATION
    chkPCRnRegs bin
#endif
    render phlp bin Op.STMIB None OD.OprRnRegsCaret
  | 0b1000u ->
#if !EMULATION
    chkPCRnRegs bin
#endif
    let struct (opcode, oprFn) = changeToAliasOfSTMDB bin
    render phlp bin opcode None oprFn
  | 0b1001u ->
#if !EMULATION
    chkWBRegs bin
#endif
    render phlp bin Op.LDMDB None OD.OprRnRegsA
  | 0b0011u ->
    (* 0xxxxxxxxxxxxxxx LDM (User registers) *)
    if pickBit bin 15 = 0u then
#if !EMULATION
      chkPCRnRegs bin
#endif
      render phlp bin Op.LDMDA None OD.OprRnRegsCaret
    else (* 1xxxxxxxxxxxxxxx LDM (exception return) *)
#if !EMULATION
      chkWBRegs bin
#endif
      render phlp bin Op.LDMDA None OD.OprRnRegsCaret
  | 0b0111u ->
    if pickBit bin 15 = 0u then
#if !EMULATION
      chkPCRnRegs bin
#endif
      render phlp bin Op.LDM None OD.OprRnRegsCaret
    else
#if !EMULATION
      chkWBRegs bin
#endif
      render phlp bin Op.LDM None OD.OprRnRegsCaret
  | 0b1011u ->
    if pickBit bin 15 = 0u then
#if !EMULATION
      chkPCRnRegs bin
#endif
      render phlp bin Op.LDMDB None OD.OprRnRegsCaret
    else
#if !EMULATION
      chkWBRegs bin
#endif
      render phlp bin Op.LDMDB None OD.OprRnRegsCaret
  | 0b1111u ->
    if pickBit bin 15 = 0u then
#if !EMULATION
      chkPCRnRegs bin
#endif
      render phlp bin Op.LDMIB None OD.OprRnRegsCaret
    else
#if !EMULATION
      chkWBRegs bin
#endif
      render phlp bin Op.LDMIB None OD.OprRnRegsCaret
  | 0b1100u ->
#if !EMULATION
    chkPCRnRegs bin
#endif
    render phlp bin Op.STMIB None OD.OprRnRegsA
  | _ (* 0b1101u *) ->
#if !EMULATION
    chkWBRegs bin
#endif
    render phlp bin Op.LDMIB None OD.OprRnRegsA

let parseCase100 (phlp: ParsingHelper) bin =
  match phlp.Cond with
  | Condition.UN (* 0b1111u *) -> parseExceptionSaveStore phlp bin
  | _ (* != 0b1111u *) -> parseLoadStoreMultiple phlp bin

/// Branch (immediate) on page F4-4246.
let parseCase101 (phlp: ParsingHelper) bin =
  match phlp.Cond with
  | Condition.UN (* 0b1111u *) ->
    render phlp bin Op.BLX None OD.OprLabelH
  | _ (* != 0b1111u *) ->
    if pickBit bin 24 = 0u (* H *) then
      render phlp bin Op.B None OD.OprLabelA
    else render phlp bin Op.BL None OD.OprLabelA

/// Branch, branch with link, and block data transfer on page F4-4244.
let parseCase10 (phlp: ParsingHelper) bin =
  match pickBit bin 25 (* op0 *) with
  | 0b0u -> parseCase100 phlp bin
  | _ (* 0b1u *) -> parseCase101 phlp bin

/// Supervisor call on page F4-4247.
let parseSupervisorCall (phlp: ParsingHelper) bin =
  if phlp.Cond = Condition.UN then raise ParsingFailureException
  else render phlp bin Op.SVC None OD.OprImm24

/// Advanced SIMD three registers of the same length extension on page F4-4248.
let parseAdvSIMDThreeRegSameLenExt (phlp: ParsingHelper) bin =
  let decodeFields =
    (pickTwo bin 23 <<< 6) + (pickTwo bin 20 <<< 4) +
    (pickBit bin 10 <<< 3) + (pickBit bin 8 <<< 2) + (pickBit bin 6 <<< 1) +
    (pickBit bin 4)
  match decodeFields (* op1:op2:op3:op4:Q:U *) with
  | 0b01000000u | 0b11000000u (* x1000000 *) -> (* Armv8.3 *)
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCADD (oneDt SIMDTypF16) OD.OprDdDnDmRotate
  | 0b01010000u | 0b11010000u (* x1010000 *) -> (* Armv8.3 *)
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCADD (oneDt SIMDTypF32) OD.OprDdDnDmRotate
  | 0b01000001u | 0b01010001u | 0b11000001u | 0b11010001u (* x10x0001 *) ->
    raise ParsingFailureException
  | 0b01000010u | 0b11000010u (* x1000010 *) -> (* Armv8.3 *)
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCADD (oneDt SIMDTypF16) OD.OprQdQnQmRotate
  | 0b01010010u | 0b11010010u (* x1010010 *) -> (* Armv8.3 *)
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCADD (oneDt SIMDTypF32) OD.OprQdQnQmRotate
  | b when b &&& 0b01101111u = 0b01000011u (* x10x0011 *) ->
    raise ParsingFailureException
  | b when b &&& 0b11101100u = 0b00000000u (* 000x00xx *) ->
    raise ParsingFailureException
  | b when b &&& 0b11101100u = 0b00000100u (* 000x01xx *) ->
    raise ParsingFailureException
  | 0b00001000u -> raise ParsingFailureException
  | 0b00001001u -> raise ParsingFailureException
  | 0b00001010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMMLA (oneDt BF16) OD.OprQdQnQm (* Armv8.6 *)
  | 0b00001011u -> raise ParsingFailureException
  | 0b00001100u -> (* Armv8.6 *)
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VDOT (oneDt BF16) OD.OprDdDnDm
  | 0b00001101u -> raise ParsingFailureException
  | 0b00001110u -> (* Armv8.6 *)
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VDOT (oneDt BF16) OD.OprQdQnQm
  | 0b00001111u -> raise ParsingFailureException
  | 0b00011000u | 0b00011001u | 0b00011010u | 0b00011011u (* 000110xx *) ->
    raise ParsingFailureException
  | 0b00011100u | 0b00011101u | 0b00011110u | 0b00011111u (* 000111xx *) ->
    raise ParsingFailureException
  | 0b00100001u -> (* Armv8.2 *)
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VFMAL (oneDt SIMDTypF16) OD.OprDdSnSm
  | 0b00100011u -> (* Armv8.2 *)
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VFMAL (oneDt SIMDTypF16) OD.OprQdDnDm
  | 0b00100100u | 0b00100101u | 0b00100110u | 0b00100111u (* 001001xx *) ->
    raise ParsingFailureException
  | 0b00101000u | 0b00101001u (* 0010100xu *) -> raise ParsingFailureException
  | 0b00101010u -> (* Armv8.6 *)
#if !EMULATION
    chkVdVnVm bin
#endif
    render phlp bin Op.VSMMLA (oneDt SIMDTypS8) OD.OprQdQnQm
  | 0b00101011u -> (* Armv8.6 *)
#if !EMULATION
    chkVdVnVm bin
#endif
    render phlp bin Op.VUMMLA (oneDt SIMDTypU8) OD.OprQdQnQm
  | 0b00101100u -> (* Armv8.2 *)
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSDOT (oneDt SIMDTypS8) OD.OprDdDnDm
  | 0b00101101u -> (* Armv8.2 *)
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VUDOT (oneDt SIMDTypU8) OD.OprDdDnDm
  | 0b00101110u -> (* Armv8.2 *)
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSDOT (oneDt SIMDTypS8) OD.OprQdQnQm
  | 0b00101111u -> (* Armv8.2 *)
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VUDOT (oneDt SIMDTypU8) OD.OprQdQnQm
  | 0b00110001u -> (* Armv8.6 *)
#if !EMULATION
    chkVdVnVm bin
#endif
    render phlp bin Op.VFMAB (oneDt BF16) OD.OprQdQnQm
  | 0b00110011u -> (* Armv8.6 *)
#if !EMULATION
    chkVdVnVm bin
#endif
    render phlp bin Op.VFMAT (oneDt BF16) OD.OprQdQnQm
  | 0b00110100u | 0b00110101u | 0b00110110u | 0b00110111u (* 0b001101xxu *) ->
    raise ParsingFailureException
  | 0b00111000u | 0b00111001u | 0b00111010u | 0b00111011u (* 0b001110xxu *) ->
    raise ParsingFailureException
  | 0b00111100u | 0b00111101u | 0b00111110u | 0b00111111u (* 0b001111xxu *) ->
    raise ParsingFailureException
  | 0b01100001u -> (* Armv8.2 *)
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VFMSL (oneDt SIMDTypF16) OD.OprDdSnSm
  | 0b01100011u -> (* Armv8.2 *)
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VFMSL (oneDt SIMDTypF16) OD.OprQdDnDm
  | 0b01100100u | 0b01100101u | 0b01100110u | 0b01100111u (* 011001xx *) ->
    raise ParsingFailureException
  | 0b01101000u | 0b01101001u (* 0110100x *) -> raise ParsingFailureException
  | 0b01101010u -> (* Armv8.6 *)
#if !EMULATION
    chkVdVnVm bin
#endif
    render phlp bin Op.VUSMMLA (oneDt SIMDTypS8) OD.OprQdQnQm
  | 0b01101011u -> raise ParsingFailureException
  | 0b01101100u -> (* Armv8.6 *)
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VUSDOT (oneDt SIMDTypS8) OD.OprDdDnDm
  | 0b01101101u | 0b01101111u (* 011011x1 *) -> raise ParsingFailureException
  | 0b01101110u -> (* Armv8.6 *)
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VUSDOT (oneDt SIMDTypS8) OD.OprQdQnQm
  | 0b01110100u | 0b01110101u | 0b01110110u | 0b01110111u (* 011101xx *) ->
    raise ParsingFailureException
  | 0b01111000u | 0b01111001u | 0b01111010u | 0b01111011u (* 011110xx *) ->
    raise ParsingFailureException
  | 0b01111100u | 0b01111101u | 0b01111110u | 0b01111111u (* 011111xx *) ->
    raise ParsingFailureException
  (* VCMLA Armv8.3 *)
  | 0b00100000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCMLA (oneDt SIMDTypF16) OD.OprDdDnDmRotate
  | 0b00100010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCMLA (oneDt SIMDTypF16) OD.OprQdQnQmRotate
  | 0b00110000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCMLA (oneDt SIMDTypF32) OD.OprDdDnDmRotate
  | 0b00110010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCMLA (oneDt SIMDTypF32) OD.OprQdQnQmRotate
  | 0b10110100u | 0b10110101u | 0b10110110u | 0b10110111u (* 101101xx *) ->
    raise ParsingFailureException
  | 0b10111000u | 0b10111001u | 0b10111010u | 0b10111011u (* 101110xx *) ->
    raise ParsingFailureException
  | 0b10111100u | 0b10111101u | 0b10111110u | 0b10111111u (* 101111xx *) ->
    raise ParsingFailureException
  | 0b11110100u | 0b11110101u | 0b11110110u | 0b11110111u (* 111101xx *) ->
    raise ParsingFailureException
  | 0b11111000u | 0b11111001u | 0b11111010u | 0b11111011u (* 111110xx *) ->
    raise ParsingFailureException
  | 0b11111100u | 0b11111101u | 0b11111110u | 0b11111111u (* 111111xx *) ->
    raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// Floating-point minNum/maxNum on page F4-4250.
let parseFloatingPointMinMaxNum (phlp: ParsingHelper) bin =
  match concat (pickBit bin 6) (pickTwo bin 8) 2 (* op:size *) with
  | 0b000u | 0b100u -> raise UndefinedException
  | 0b001u ->
    render phlp bin Op.VMAXNM (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b010u ->
    render phlp bin Op.VMAXNM (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b011u ->
    render phlp bin Op.VMAXNM (oneDt SIMDTypF64) OD.OprDdDnDm
  | 0b101u ->
    render phlp bin Op.VMINNM (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b110u ->
    render phlp bin Op.VMINNM (oneDt SIMDTypF32) OD.OprSdSnSm
  | _ (* 111 *) ->
    render phlp bin Op.VMINNM (oneDt SIMDTypF64) OD.OprDdDnDm

/// Floating-point extraction and insertion on page F4-4250.
let parseFloatingPointExtractionAndInsertion (phlp: ParsingHelper) bin =
  match concat (pickTwo bin 8) (pickBit bin 7) 1 (* size:op *) with
  | 0b010u | 0b011u (* 01x *) -> raise ParsingFailureException
  | 0b100u -> (* Armv8.2 *)
    render phlp bin Op.VMOVX (oneDt SIMDTypF16) OD.OprSdSm
  | 0b101u -> (* Armv8.2 *)
    render phlp bin Op.VINS (oneDt SIMDTypF16) OD.OprSdSm
  | 0b110u | 0b111u (* 11x *) -> raise ParsingFailureException
  | _ (* 00x *) -> raise UndefinedException

/// Floating-point directed convert to integer on page F4-4250.
let parseFloatingPointDirectedConvertToInteger (phlp: ParsingHelper) bin =
  let struct (dt1, oprs1) =
    match pickTwo bin 8 (* size *) with
    | 0b00u -> raise UndefinedException
    | 0b01u -> struct (SIMDTypF16 |> oneDt, OD.OprSdSm)
    | 0b10u -> struct (SIMDTypF32 |> oneDt, OD.OprSdSm)
    | _ (* 11 *) -> struct (SIMDTypF64 |> oneDt, OD.OprDdDm)
  let struct (dt2, oprs2) =
    match pickThree bin 7 (* size:op *) with
    | 0b000u | 0b001u -> raise UndefinedException
    | 0b010u -> struct (twoDt (SIMDTypF16, SIMDTypU32), OD.OprSdSm)
    | 0b011u -> struct (twoDt (SIMDTypF16, SIMDTypS32), OD.OprSdSm)
    | 0b100u -> struct (twoDt (SIMDTypF32, SIMDTypU32), OD.OprSdSm)
    | 0b101u -> struct (twoDt (SIMDTypF32, SIMDTypS32), OD.OprSdSm)
    | 0b110u -> struct (twoDt (SIMDTypF64, SIMDTypU32), OD.OprSdDm)
    | _ (* 111 *) -> struct (twoDt (SIMDTypF64, SIMDTypS32), OD.OprSdDm)
  match pickThree bin 16 (* o1:RM *) with
  | 0b000u -> render phlp bin Op.VRINTA dt1 oprs1
  | 0b001u -> render phlp bin Op.VRINTN dt1 oprs1
  | 0b010u -> render phlp bin Op.VRINTP dt1 oprs1
  | 0b011u -> render phlp bin Op.VRINTM dt1 oprs1
  | 0b100u -> render phlp bin Op.VCVTA dt2 oprs2
  | 0b101u -> render phlp bin Op.VCVTN dt2 oprs2
  | 0b110u -> render phlp bin Op.VCVTP dt2 oprs2
  | _ (* 111 *) -> render phlp bin Op.VCVTM dt2 oprs2

/// Advanced SIMD and floating-point multiply with accumulate on page F4-4251.
let parseAdvSIMDAndFPMulWithAccumulate (phlp: ParsingHelper) bin =
  let decodeFields = (* op1:op2:Q:U *)
    (pickBit bin 23 <<< 4) + (pickTwo bin 20 <<< 2) + (pickBit bin 6 <<< 1) +
    (pickBit bin 4)
  match decodeFields with
  | 0b00000u | 0b00100u | 0b01000u | 0b01100u (* 0xx00 *) -> (* Armv8.3 *)
#if !EMULATION
    chkQVdVn bin
#endif
    render phlp bin Op.VCMLA (oneDt SIMDTypF16) OD.OprDdDnDmidxRotate
  | 0b00010u | 0b00110u | 0b01010u | 0b01110u (* 0xx10 *) -> (* Armv8.3 *)
    render phlp bin Op.VCMLA (oneDt SIMDTypF16) OD.OprQdQnDmidxRotate
  | 0b00001u -> (* Armv8.2 *)
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VFMAL (oneDt SIMDTypF16) OD.OprDdSnSmidx
  | 0b00011u -> (* Armv8.2 *)
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VFMAL (oneDt SIMDTypF16) OD.OprQdDnDmidx
  | 0b00101u -> (* Armv8.2 *)
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VFMSL (oneDt SIMDTypF16) OD.OprDdSnSmidx
  | 0b00111u -> (* Armv8.2 *)
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VFMSL (oneDt SIMDTypF16) OD.OprQdDnDmidx
  | 0b01001u | 0b01011u (* 010x1 *) -> raise ParsingFailureException
  | 0b01101u -> (* Armv8.6 *)
#if !EMULATION
    chkVdVn bin
#endif
    render phlp bin Op.VFMAB (oneDt BF16) OD.OprQdQnDmidxm
  | 0b01111u -> (* Armv8.6 *)
#if !EMULATION
    chkVdVn bin
#endif
    render phlp bin Op.VFMAT (oneDt BF16) OD.OprQdQnDmidxm
  | 0b10000u | 0b10100u | 0b11000u | 0b11100u (* 1xx00 *) -> (* Armv8.3 *)
#if !EMULATION
    chkQVdVn bin
#endif
    render phlp bin Op.VCMLA (oneDt SIMDTypF32) OD.OprDdDnDm0Rotate
  | 0b10001u | 0b10011u | 0b10101u | 0b10111u | 0b11001u | 0b11011u | 0b11101u
  | 0b11111u (* 1xxx1 *) -> raise ParsingFailureException
  | _ (* 1xx10 *) -> (* Armv8.3 *)
#if !EMULATION
    chkQVdVn bin
#endif
    render phlp bin Op.VCMLA (oneDt SIMDTypF32) OD.OprQdQnDm0Rotate

/// Advanced SIMD and floating-point dot product on page F4-4252.
let parseAdvSIMDAndFPDotProduct (phlp: ParsingHelper) bin =
  let decodeFields = (* op1:op2:op4:Q:U *)
    (pickBit bin 23 <<< 5) + (pickTwo bin 20 <<< 3) + (pickBit bin 8 <<< 2) +
    (pickBit bin 6 <<< 1) + (pickBit bin 4)
  match decodeFields (* op1:op2:op4:Q:U *) with
  | 0b000000u | 0b000001u | 0b000010u | 0b000011u (* 0000xx *) ->
    raise ParsingFailureException
  | 0b000100u -> (* Armv8.6 *)
#if !EMULATION
    chkQVdVn bin
#endif
    render phlp bin Op.VDOT (oneDt BF16) OD.OprDdDnDmidx
  | 0b000101u | 0b000111u (* 0001x1 *) -> raise ParsingFailureException
  | 0b000110u -> (* Armv8.6 *)
#if !EMULATION
    chkQVdVn bin
#endif
    render phlp bin Op.VDOT (oneDt BF16) OD.OprQdQnDmidx
  | 0b001000u | 0b001001u | 0b001010u | 0b001011u (* 0010xx *) ->
    raise ParsingFailureException
  | 0b010000u | 0b010001u | 0b010010u | 0b010011u (* 0100xx *) ->
    raise ParsingFailureException
  | 0b010100u -> (* Armv8.2 *)
#if !EMULATION
    chkQVdVn bin
#endif
    render phlp bin Op.VSDOT (oneDt SIMDTypS8) OD.OprDdDnDmidx
  | 0b010101u -> (* Armv8.2 *)
#if !EMULATION
    chkQVdVn bin
#endif
    render phlp bin Op.VUDOT (oneDt SIMDTypU8) OD.OprDdDnDmidx
  | 0b010110u -> (* Armv8.2 *)
#if !EMULATION
    chkQVdVn bin
#endif
    render phlp bin Op.VSDOT (oneDt SIMDTypS8) OD.OprQdQnDmidx
  | 0b010111u -> (* Armv8.2 *)
#if !EMULATION
    chkQVdVn bin
#endif
    render phlp bin Op.VUDOT (oneDt SIMDTypU8) OD.OprQdQnDmidx
  | b when b &&& 0b111000u = 0b011000u (* 011xxx *) ->
    raise ParsingFailureException
  | b when b &&& 0b100100u = 0b100000u (* 1xx0xx *) ->
    raise ParsingFailureException
  | 0b100100u -> (* Armv8.6 *)
#if !EMULATION
    chkQVdVn bin
#endif
    render phlp bin Op.VUSDOT (oneDt SIMDTypS8) OD.OprDdDnDmidx
  | 0b100101u -> (* Armv8.6 *)
#if !EMULATION
    chkQVdVn bin
#endif
    render phlp bin Op.VSUDOT (oneDt SIMDTypU8) OD.OprDdDnDmidx
  | 0b100110u -> (* Armv8.6 *)
#if !EMULATION
    chkQVdVn bin
#endif
    render phlp bin Op.VUSDOT (oneDt SIMDTypS8) OD.OprQdQnDmidx
  | 0b100111u -> (* Armv8.6 *)
#if !EMULATION
    chkQVdVn bin
#endif
    render phlp bin Op.VSUDOT (oneDt SIMDTypU8) OD.OprQdQnDmidx
  | 0b101100u | 0b101101u | 0b101110u | 0b101111u (* 1011xx *) ->
    raise ParsingFailureException
  | b when b &&& 0b110100u = 0b110100u (* 11x1xx *) ->
    raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// VSELEQ, VSELGE, VSELGT, VSELVS on page F6-5579.
let parseVectorSelect (phlp: ParsingHelper) bin =
  match concat (pickTwo bin 20) (pickTwo bin 8) 2 (* cc:size *) with
  | 0b0011u ->
    render phlp bin Op.VSELEQ (oneDt SIMDTypF64) OD.OprDdDnDm
  | 0b0001u ->
    render phlp bin Op.VSELEQ (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b0010u ->
    render phlp bin Op.VSELEQ (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b1011u ->
    render phlp bin Op.VSELGE (oneDt SIMDTypF64) OD.OprDdDnDm
  | 0b1001u ->
    render phlp bin Op.VSELGE (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b1010u ->
    render phlp bin Op.VSELGE (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b1111u ->
    render phlp bin Op.VSELGT (oneDt SIMDTypF64) OD.OprDdDnDm
  | 0b1101u ->
    render phlp bin Op.VSELGT (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b1110u ->
    render phlp bin Op.VSELGT (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b0111u ->
    render phlp bin Op.VSELVS (oneDt SIMDTypF64) OD.OprDdDnDm
  | 0b0101u ->
    render phlp bin Op.VSELVS (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b0110u ->
    render phlp bin Op.VSELVS (oneDt SIMDTypF32) OD.OprSdSnSm
  | _ (* xx00 *) -> raise UndefinedException

/// Unconditional Advanced SIMD and floating-point instructions on page F4-4247.
let parseUncondAdvSIMDAndFPInstr (phlp: ParsingHelper) bin =
  let op0op2op3op4op5 = (* op0:op2:op3:op4:op5 *)
    (pickThree bin 23 <<< 5) + (pickThree bin 8 <<< 2) +
    (pickBit bin 6 <<< 1) + (pickBit bin 4)
  let is00xxxx bin = (extract bin 21 16) &&& 0b110000u = 0b000000u
  let is110000 bin = extract bin 21 16 = 0b110000u
  let is111xxx bin = (extract bin 21 16) &&& 0b111000u = 0b111000u
  match op0op2op3op4op5 with
  | b when b &&& 0b10001000u = 0b00000000u ->
    parseAdvSIMDThreeRegSameLenExt phlp bin
  | 0b10000100u | 0b10001000u | 0b10001100u ->
    parseVectorSelect phlp bin
  | 0b10100100u | 0b10101000u | 0b10101100u | 0b10100110u | 0b10101010u
  | 0b10101110u when is00xxxx bin ->
    parseFloatingPointMinMaxNum phlp bin
  | 0b10100110u | 0b10101010u | 0b10101110u when is110000 bin ->
    parseFloatingPointExtractionAndInsertion phlp bin
  | 0b10100110u | 0b10101010u | 0b10101110u when is111xxx bin ->
    parseFloatingPointDirectedConvertToInteger phlp bin
  | 0b10000000u | 0b10000001u | 0b10000010u | 0b10000011u | 0b10100000u
  | 0b10100001u | 0b10100010u | 0b10100011u ->
    parseAdvSIMDAndFPMulWithAccumulate phlp bin
  | b when b &&& 0b11011000u = 0b10010000u ->
    parseAdvSIMDAndFPDotProduct phlp bin
  | _ -> raise ParsingFailureException

/// Advanced SIMD and floating-point 64-bit move on page F4-4253.
let parseAdvancedSIMDandFP64bitMove (phlp: ParsingHelper) bin =
  let decodeFields = (* D:op:size:opc2:o3 *)
    (pickBit bin 22 <<< 6) + (pickBit bin 20 <<< 5) + (pickFour bin 6 <<< 1) +
    (pickBit bin 4)
  match decodeFields (* D:op:size:opc2:o3 *) with
  | 0b1010001u ->
#if !EMULATION
    chkPCRtRt2VmRegsEq bin
#endif
    render phlp bin Op.VMOV None OD.OprSmSm1RtRt2
  | 0b1011001u ->
#if !EMULATION
    chkPCRtRt2ArmEq bin
#endif
    render phlp bin Op.VMOV None OD.OprDmRtRt2
  | 0b1110001u ->
#if !EMULATION
    chkPCRtRt2VmRegsEq bin
#endif
    render phlp bin Op.VMOV None OD.OprRtRt2SmSm1
  | 0b1111001u ->
#if !EMULATION
    chkPCRtRt2ArmEq bin
#endif
    render phlp bin Op.VMOV None OD.OprRtRt2Dm
  | _ (* 0xxxxxx 1xxxxx0 1x0x001 1xxx01x 1xxx1xx *) ->
    raise ParsingFailureException

/// System register 64-bit move on page F4-4254.
let parseSystemReg64bitMove (phlp: ParsingHelper) bin =
  match pickTwoBitsApart bin 22 20 (* D:L *) with
  | 0b00u | 0b01u -> raise ParsingFailureException
  | 0b10u ->
#if !EMULATION
    chkPCRtRt2 bin
#endif
    render phlp bin Op.MCRR None OD.OprCpOpc1RtRt2CRm
  | _ (* 0b11u *) ->
#if !EMULATION
    chkPCRtRt2Eq bin
#endif
    render phlp bin Op.MRRC None OD.OprCpOpc1RtRt2CRm

/// Advanced SIMD and floating-point load/store on page F4-4254.
let parseAdvSIMDAndFPLdSt (phlp: ParsingHelper) bin =
  let decodeFields = (* P:U:W:L:size *)
    (pickTwo bin 23 <<< 4) + (pickTwo bin 20 <<< 2) + (pickTwo bin 8)
  let isxxxxxxx0 bin = pickBit bin 0 = 0u
  let isxxxxxxx1 bin = pickBit bin 1 = 1u
  let isRn1111 bin = pickFour bin 16 = 0b1111u
  match decodeFields (* P:U:W:L:size *) with
  | 0b001000u | 0b001001u | 0b001010u | 0b001011u | 0b001100u | 0b001101u
  | 0b001110u | 0b001111u (* 001xxx *) -> raise ParsingFailureException
  | 0b010000u | 0b010001u | 0b010100u | 0b011000u | 0b011000u | 0b011001u
  | 0b011100u | 0b011101u (* 01xx0x *) -> raise ParsingFailureException
  | 0b010010u | 0b011010u (* 01x010 *) ->
#if !EMULATION
    chkPCRnDRegs bin
#endif
    render phlp bin Op.VSTMIA None OD.OprRnSreglist
  | 0b010011u | 0b011011u when isxxxxxxx0 bin ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp bin Op.VSTMIA None OD.OprRnDreglist
  | 0b010011u | 0b011011u (* 01x011 *) when isxxxxxxx1 bin ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp bin Op.FSTMIAX None OD.OprRnDreglist
  | 0b010110u | 0b011110u (* 01x110 *) ->
#if !EMULATION
    chkPCRnDRegs bin
#endif
    render phlp bin Op.VLDMIA None OD.OprRnSreglist
  | 0b010111u | 0b011111u (* 01x111 *) when isxxxxxxx0 bin ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp bin Op.VLDMIA None OD.OprRnDreglist
  | 0b010111u | 0b011111u (* 01x111 *) when isxxxxxxx1 bin ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp bin Op.FLDMIAX None OD.OprRnDreglist
  | 0b100000u | 0b110000u (* 1x0000 *) -> raise UndefinedException
  | 0b100001u | 0b110001u ->
#if !EMULATION
    chkSzCondPCRn bin phlp.Cond
#endif
    render phlp bin Op.VSTR (oneDt SIMDTyp16) OD.OprSdMem
  | 0b100010u | 0b110010u ->
#if !EMULATION
    chkSzCondPCRn bin phlp.Cond
#endif
    render phlp bin Op.VSTR (oneDt SIMDTyp32) OD.OprSdMem
  | 0b100011u | 0b110011u ->
#if !EMULATION
    chkSzCondPCRn bin phlp.Cond
#endif
    render phlp bin Op.VSTR (oneDt SIMDTyp64) OD.OprDdMem
  | 0b100100u | 0b110100u when phlp.Cond <> Condition.UN ->
    raise UndefinedException
  | 0b100101u | 0b110101u | 0b100110u | 0b110110u
    when phlp.Cond <> Condition.UN ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VLDR None OD.OprSdMem
  | 0b100111u | 0b110111u when phlp.Cond <> Condition.UN ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VLDR None OD.OprDdMem
  | 0b101000u | 0b101001u | 0b101100u | 0b101101u ->
    raise ParsingFailureException
  | 0b101010u ->
#if !EMULATION
    chkPCRnDRegs bin
#endif
    render phlp bin Op.VSTMDB None OD.OprRnSreglist
  | 0b101011u when isxxxxxxx0 bin ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp bin Op.VSTMDB None OD.OprRnDreglist
  | 0b101011u when isxxxxxxx1 bin ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp bin Op.FSTMDBX None OD.OprRnDreglist
  | 0b101110u ->
#if !EMULATION
    chkPCRnDRegs bin
#endif
    render phlp bin Op.VLDMDB None OD.OprRnSreglist
  | 0b101111u when isxxxxxxx0 bin ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp bin Op.VLDMDB None OD.OprRnDreglist
  | 0b101111u when isxxxxxxx1 bin ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp bin Op.FLDMDBX None OD.OprRnDreglist
  | 0b100100u | 0b110100u when isRn1111 bin -> raise UndefinedException
  | 0b100101u | 0b110101u | 0b100110u | 0b110110u when isRn1111 bin ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VLDR None OD.OprSdLabel
  | 0b100111u | 0b110111u when isRn1111 bin ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VLDR None OD.OprDdLabel
  | 0b111000u | 0b111001u | 0b111010u | 0b111011u | 0b111100u | 0b111101u
  | 0b111110u | 0b111111u -> raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// System register load/store on page F4-4255.
let parseSysRegisterLdSt (phlp: ParsingHelper) bin =
  let isNotRn1111 bin = pickFour bin 16 <> 0b1111u
  let isCRd0101 bin = (pickFour bin 12) = 0b0101u
  let puw = concat (pickTwo bin 23) (pickBit bin 21) 1 (* P:U:W *)
  let dL = pickTwoBitsApart bin 22 20 (* D:L *)
  let cRdCp15 = concat (pickFour bin 12) (pickBit bin 8) 1 (* CRd:cp15 *)
  match concat dL (pickBit bin 8) 1 (* D:L:cp15 *) with
  | 0b000u | 0b001u | 0b010u | 0b011u (* 0b0xxu *)
    when puw <> 0b000u && not (isCRd0101 bin) -> raise ParsingFailureException
  | 0b010u when puw <> 0b000u && isNotRn1111 bin |> not && isCRd0101 bin ->
    (* if W == '1' then UNPREDICTABLE *)
    pickBit bin 21 = 1u |> checkUnpred
    render phlp bin Op.LDC None OD.OprP14C5Label
  | 0b001u | 0b011u | 0b101u | 0b111u (* 0bxx1u *) when puw <> 0b000u ->
    raise ParsingFailureException
  | 0b100u | 0b110u (* 0b1x0u *) when puw <> 0b000u && isCRd0101 bin ->
    raise ParsingFailureException
  | _ ->
    match concat (concat puw dL 2) cRdCp15 5 (* P:U:W:D:L:CRd:cp15 *) with
    | 0b0010001010u | 0b0110001010u ->
#if !EMULATION
      chkPCRnWback bin
#endif
      render phlp bin Op.STC None OD.OprP14C5Mem
    | 0b0010101010u | 0b0110101010u when isNotRn1111 bin ->
      render phlp bin Op.LDC None OD.OprP14C5Mem
    | 0b0100001010u ->
#if !EMULATION
      chkPCRnWback bin
#endif
      render phlp bin Op.STC None OD.OprP14C5Option
    | 0b0100101010u when isNotRn1111 bin ->
      render phlp bin Op.LDC None OD.OprP14C5Option
    | 0b1000001010u | 0b1100001010u ->
#if !EMULATION
      chkPCRnWback bin
#endif
      render phlp bin Op.STC None OD.OprP14C5Mem
    | 0b1000101010u | 0b1100101010u when isNotRn1111 bin ->
      render phlp bin Op.LDC None OD.OprP14C5Mem
    | 0b1010001010u | 0b1110001010u ->
#if !EMULATION
      chkPCRnWback bin
#endif
      render phlp bin Op.STC None OD.OprP14C5Mem
    | 0b1010101010u | 0b1110101010u when isNotRn1111 bin ->
      render phlp bin Op.LDC None OD.OprP14C5Mem
    | _ -> raise ParsingFailureException

/// Advanced SIMD and System register load/store and 64-bit move
/// on page F4-4252.
let parseAdvSIMDAndSysRegLdStAnd64bitMove (phlp: ParsingHelper) bin =
  let is00x0 bin = (pickFour bin 21 (* op0 *)) &&& 0b1101u = 0b0000u
  match pickTwo bin 9 (* op1 *) with
  | 0b00u | 0b01u when is00x0 bin ->
    parseAdvancedSIMDandFP64bitMove phlp bin
  | 0b11u when is00x0 bin -> parseSystemReg64bitMove phlp bin
  | 0b00u | 0b01u -> parseAdvSIMDAndFPLdSt phlp bin
  | 0b11u -> parseSysRegisterLdSt phlp bin
  | _ (* 10 *) -> raise ParsingFailureException

/// Floating-point data-processing (two registers) on page F4-4256.
let parseFPDataProcTwoRegs (phlp: ParsingHelper) bin =
  let decodeFields =
    concat (pickFour bin 16) (pickThree bin 7) 3 (* o1:opc2:size:o3 *)
  match decodeFields (* o1:opc2:size:o3 *) with
  | b when b &&& 0b0000110u = 0b0000000u (* xxxx00x *) ->
    raise ParsingFailureException
  | 0b0000010u -> raise ParsingFailureException
  (* 0000xx1 VABS *)
  | 0b0000001u -> raise UndefinedException
  | 0b0000011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VABS (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0000101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VABS (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0000111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VABS (oneDt SIMDTypF64) OD.OprDdDm
  (* 00001x0 VMOV *)
  | 0b0000100u ->
    render phlp bin Op.VMOV (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0000110u ->
    render phlp bin Op.VMOV (oneDt SIMDTypF64) OD.OprDdDm
  (* 0001xx0 VNEG *)
  | 0b0001000u -> raise UndefinedException
  | 0b0001010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VNEG (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0001100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VNEG (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0001110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VNEG (oneDt SIMDTypF64) OD.OprDdDm
  (* 0001xx1 VSQRT *)
  | 0b0001001u -> raise UndefinedException
  | 0b0001011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VSQRT (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0001101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VSQRT (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0001111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VSQRT (oneDt SIMDTypF64) OD.OprDdDm
  (* 0010xx0 VCVTB *)
  | 0b0010100u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render phlp bin Op.VCVTB dt OD.OprSdSm
  | 0b0010110u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF16)
    render phlp bin Op.VCVTB dt OD.OprDdSm
  | 0b0010010u | 0b0010011u (* 001001x *) -> raise ParsingFailureException
  (* 0010xx1 VCVTT *)
  | 0b0010101u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render phlp bin Op.VCVTT dt OD.OprSdSm
  | 0b0010111u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF16)
    render phlp bin Op.VCVTT dt OD.OprDdSm
  | 0b0011010u -> (* Armv8.6 *)
    render phlp bin Op.VCVTB (twoDt (BF16, SIMDTypF16)) OD.OprSdSm
  | 0b0011011u -> (* Armv8.6 *)
    render phlp bin Op.VCVTT (twoDt (BF16, SIMDTypF16)) OD.OprSdSm
  | 0b0011100u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render phlp bin Op.VCVTB dt OD.OprSdSm
  | 0b0011101u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render phlp bin Op.VCVTT dt OD.OprSdSm
  | 0b0011110u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF64)
    render phlp bin Op.VCVTB dt OD.OprSdDm
  | 0b0011111u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF64)
    render phlp bin Op.VCVTT dt OD.OprSdDm
  (* 0100xx0 VCMP *)
  | 0b0100000u -> raise UndefinedException
  | 0b0100010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VCMP (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0100100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VCMP (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0100110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VCMP (oneDt SIMDTypF64) OD.OprDdDm
  (* 0100xx1 VCMPE *)
  | 0b0100001u -> raise UndefinedException
  | 0b0100011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VCMPE (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0100101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VCMPE (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0100111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VCMPE (oneDt SIMDTypF64) OD.OprDdDm
  (* 0101xx0 VCMP *)
  | 0b0101000u -> raise UndefinedException
  | 0b0101010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VCMP (oneDt SIMDTypF16) OD.OprSdImm0
  | 0b0101100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VCMP (oneDt SIMDTypF32) OD.OprSdImm0
  | 0b0101110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VCMP (oneDt SIMDTypF64) OD.OprDdImm0
  (* 0101xx1 VCMPE *)
  | 0b0101001u -> raise UndefinedException
  | 0b0101011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VCMPE (oneDt SIMDTypF16) OD.OprSdImm0
  | 0b0101101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VCMPE (oneDt SIMDTypF32) OD.OprSdImm0
  | 0b0101111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VCMPE (oneDt SIMDTypF64) OD.OprDdImm0
  (* 0110xx0 VRINTR ARMv8 *)
  | 0b0110000u -> raise UndefinedException
  | 0b0110010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VRINTR (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0110100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VRINTR (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0110110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VRINTR (oneDt SIMDTypF64) OD.OprDdDm
  (* 0110xx1 VRINTZ ARMv8 *)
  | 0b0110001u -> raise UndefinedException
  | 0b0110011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VRINTZ (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0110101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VRINTZ (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0110111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VRINTZ (oneDt SIMDTypF64) OD.OprDdDm
  (* 0111xx0 VRINTX ARMv8 *)
  | 0b0111000u -> raise UndefinedException
  | 0b0111010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VRINTX (oneDt SIMDTypF16) OD.OprSdSm
  | 0b0111100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VRINTX (oneDt SIMDTypF32) OD.OprSdSm
  | 0b0111110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VRINTX (oneDt SIMDTypF64) OD.OprDdDm
  | 0b0111011u -> raise ParsingFailureException
  | 0b0111101u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprDdSm
  | 0b0111111u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprSdDm
  (* 1000xxx VCVT *)
  | 0b1000000u | 0b1000001u -> raise UndefinedException
  | 0b1000010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1000011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1000100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1000101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1000110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF64, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprDdSm
  | 0b1000111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF64, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprDdSm
  | 0b1001010u | 0b1001011u (* 100101x *) -> raise ParsingFailureException
  | 0b1001100u | 0b1001101u (* 100110x *) -> raise ParsingFailureException
  | 0b1001110u -> raise ParsingFailureException
  | 0b1001111u -> (* Armv8.3 *)
    phlp.Cond <> Condition.AL |> checkUnpred
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render phlp bin Op.VJCVT dt OD.OprSdDm
  (* 101xxxx Op.VCVT *)
  | 0b1010000u | 0b1010001u | 0b1011000u | 0b1011001u ->
    raise UndefinedException
  | 0b1010010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypS16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1010011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1011010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypU16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1011011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1010100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypS16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1010101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1011100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypU16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1011101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1010110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF64, SIMDTypS16)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | 0b1010111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF64, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | 0b1011110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF64, SIMDTypU16)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | 0b1011111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypF64, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  (* 1100xx0 VCVTR *)
  | 0b1100000u -> raise UndefinedException
  | 0b1100010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render phlp bin Op.VCVTR dt OD.OprSdSm
  | 0b1100100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTR dt OD.OprSdSm
  | 0b1100110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render phlp bin Op.VCVTR dt OD.OprSdDm
  (* 1100xx1 VCVT *)
  | 0b1100001u -> raise UndefinedException
  | 0b1100011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1100101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1100111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprSdDm
  (* 1101xx0 VCVTR *)
  | 0b1101000u -> raise UndefinedException
  | 0b1101010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render phlp bin Op.VCVTR dt OD.OprSdSm
  | 0b1101100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTR dt OD.OprSdSm
  | 0b1101110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render phlp bin Op.VCVTR dt OD.OprSdDm
  (* 1101xx1u VCVT *)
  | 0b1101001u -> raise UndefinedException
  | 0b1101011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1101101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprSdSm
  | 0b1101111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprSdDm
  (* 111xxxx VCVT *)
  | 0b1110000u | 0b1110001u | 0b1111000u | 0b1111001u ->
    raise UndefinedException
  | 0b1110010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1110011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1111010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1111011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1110100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1110101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1111100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1111101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprSdmSdmFbits
  | 0b1110110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | 0b1110111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | 0b1111110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | 0b1111111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render phlp bin Op.VCVT dt OD.OprDdmDdmFbits
  | _ -> raise ParsingFailureException

/// Floating-point move immediate on page F4-4258.
let parseFPMoveImm (phlp: ParsingHelper) bin =
  match pickTwo bin 8 (* size *) with
  | 0b00u -> raise ParsingFailureException
  | 0b01u -> (* Armv8.2 *)
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VMOV (oneDt SIMDTypF16) OD.OprSdVImm
  | 0b10u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VMOV (oneDt SIMDTypF32) OD.OprSdVImm
  | _ (* 11 *) ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VMOV (oneDt SIMDTypF64) OD.OprDdVImm

/// Floating-point data-processing (three registers) on page F4-4258.
let parseFPDataProcThreeRegs (phlp: ParsingHelper) bin =
  let decodeFields = (* o0:o1:size:o2 *)
    (pickBit bin 23 <<< 5) + (pickTwo bin 20 <<< 3) + (pickTwo bin 8 <<< 1)
    + (pickBit bin 6)
  match decodeFields with
  | b when (b >>> 3 <> 0b111u) && (b &&& 0b000110u = 0b000u) (* != 111 00x *) ->
    raise ParsingFailureException
  (* 000xx0 VMLA *)
  | 0b000000u -> raise UndefinedException
  | 0b000010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VMLA (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b000100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VMLA (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b000110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VMLA (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 000xx1 VMLS *)
  | 0b000001u -> raise UndefinedException
  | 0b000011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VMLS (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b000101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VMLS (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b000111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VMLS (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 001xx0 VNMLS *)
  | 0b001000u -> raise UndefinedException
  | 0b001010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VNMLS (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b001100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VNMLS (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b001110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VNMLS (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 001xx1 VNMLA *)
  | 0b001001u -> raise UndefinedException
  | 0b001011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VNMLA (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b001101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VNMLA (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b001111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VNMLA (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 010xx0 VMUL *)
  | 0b010000u -> raise UndefinedException
  | 0b010010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b010100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b010110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 010xx1 VNMUL *)
  | 0b010001u -> raise UndefinedException
  | 0b010011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VNMUL (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b010101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VNMUL (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b010111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VNMUL (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 011xx0 VADD *)
  | 0b011000u -> raise UndefinedException
  | 0b011010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VADD (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b011100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VADD (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b011110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VADD (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 011xx1 VSUB *)
  | 0b011001u -> raise UndefinedException
  | 0b011011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b011101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b011111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 100xx0 VDIV *)
  | 0b100000u -> raise UndefinedException
  | 0b100010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VDIV (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b100100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VDIV (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b100110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VDIV (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 101xx0 VFNMS *)
  | 0b101000u -> raise UndefinedException
  | 0b101010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VFNMS (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b101100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VFNMS (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b101110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VFNMS (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 101xx1 VFNMA *)
  | 0b101001u -> raise UndefinedException
  | 0b101011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VFNMA (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b101101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VFNMA (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b101111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VFNMA (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 110xx0 VFMA *)
  | 0b110000u -> raise UndefinedException
  | 0b110010u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VFMA (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b110100u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VFMA (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b110110u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VFMA (oneDt SIMDTypF64) OD.OprDdDnDm
  (* 110xx1 VFMS *)
  | 0b110001u -> raise UndefinedException
  | 0b110011u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VFMS (oneDt SIMDTypF16) OD.OprSdSnSm
  | 0b110101u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VFMS (oneDt SIMDTypF32) OD.OprSdSnSm
  | 0b110111u ->
#if !EMULATION
    chkSzCond bin phlp.Cond
#endif
    render phlp bin Op.VFMS (oneDt SIMDTypF64) OD.OprDdDnDm
  | _ -> raise ParsingFailureException

/// Floating-point data-processing on page F4-4256.
let parseFloatingPointDataProcessing (phlp: ParsingHelper) bin =
  match concat (pickFour bin 20) (pickBit bin 6) 1 (* op0:op1 *) with
  | 0b10111u | 0b11111u -> parseFPDataProcTwoRegs phlp bin
  | 0b10110u | 0b11110u -> parseFPMoveImm phlp bin
  | _ (* != 1x11 && 0bxu *) -> parseFPDataProcThreeRegs phlp bin

/// Floating-point move special register on page F4-4259.
let parseFPMoveSpecialReg (phlp: ParsingHelper) bin =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp bin Op.VMSR None OD.OprSregRt
  | _ (* 0b1u *) ->
#if !EMULATION
    chkPCRtR1 bin
#endif
    render phlp bin Op.VMRS None OD.OprRtSreg

/// Advanced SIMD 8/16/32-bit element move/duplicate on page F4-4260.
let parseAdvSIMD8n16n32bitElemMoveDup (phlp: ParsingHelper) bin =
#if !EMULATION
  chkPCRt bin
#endif
  let decodeField = concat (pickFour bin 20) (pickTwo bin 5) 2
  match decodeField (* opc1:L:opc2 *) with
  (* 0xx0xx VMOV (general-purpose register to scalar) *)
  | 0b010000u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd0Rt
  | 0b010001u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd1Rt
  | 0b010010u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd2Rt
  | 0b010011u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd3Rt
  | 0b011000u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd4Rt
  | 0b011001u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd5Rt
  | 0b011010u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd6Rt
  | 0b011011u -> render phlp bin Op.VMOV (oneDt SIMDTyp8) OD.OprDd7Rt
  | 0b000001u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp16) OD.OprDd0Rt
  | 0b000011u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp16) OD.OprDd1Rt
  | 0b001001u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp16) OD.OprDd2Rt
  | 0b001011u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp16) OD.OprDd3Rt
  | 0b000000u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp32) OD.OprDd0Rt
  | 0b001000u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp32) OD.OprDd1Rt
  | 0b000010u | 0b001010u -> raise UndefinedException
  (* xxx1xx VMOV (scalar to general-purpose register) *)
  | 0b010100u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn0
  | 0b010101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn1
  | 0b010110u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn2
  | 0b010111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn3
  | 0b011100u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn4
  | 0b011101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn5
  | 0b011110u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn6
  | 0b011111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS8) OD.OprRtDn7
  | 0b110100u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn0
  | 0b110101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn1
  | 0b110110u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn2
  | 0b110111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn3
  | 0b111100u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn4
  | 0b111101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn5
  | 0b111110u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn6
  | 0b111111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU8) OD.OprRtDn7
  | 0b000101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS16) OD.OprRtDn0
  | 0b000111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS16) OD.OprRtDn1
  | 0b001101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS16) OD.OprRtDn2
  | 0b001111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypS16) OD.OprRtDn3
  | 0b100101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU16) OD.OprRtDn0
  | 0b100111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU16) OD.OprRtDn1
  | 0b101101u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU16) OD.OprRtDn2
  | 0b101111u ->
    render phlp bin Op.VMOV (oneDt SIMDTypU16) OD.OprRtDn3
  | 0b000100u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp32) OD.OprRtDn0
  | 0b001100u ->
    render phlp bin Op.VMOV (oneDt SIMDTyp32) OD.OprRtDn1
  | 0b100100u | 0b101100u | 0b000110u | 0b001110u | 0b100110u | 0b101110u ->
    raise UndefinedException (* 10x100 or x0x110 *)
  (* 1xx00x VDUP (general-purpose register) *)
  | 0b110000u -> render phlp bin Op.VDUP (oneDt SIMDTyp8) OD.OprDdRt
  | 0b100001u -> render phlp bin Op.VDUP (oneDt SIMDTyp16) OD.OprDdRt
  | 0b100000u -> render phlp bin Op.VDUP (oneDt SIMDTyp32) OD.OprDdRt
  | 0b111000u -> render phlp bin Op.VDUP (oneDt SIMDTyp8) OD.OprQdRt
  | 0b101001u -> render phlp bin Op.VDUP (oneDt SIMDTyp16) OD.OprQdRt
  | 0b101000u -> render phlp bin Op.VDUP (oneDt SIMDTyp32) OD.OprQdRt
  | 0b111001u | 0b110001u -> raise UndefinedException
  | b when b &&& 0b100110u = 0b100010u (* 1xx01x *) ->
    raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// System register 32-bit move on page F4-4260.
let parseSystemReg32bitMove (phlp: ParsingHelper) bin =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp bin Op.MCR None OD.OprCpOpc1RtCRnCRmOpc2
  | _ (* 0b1u *) ->
    render phlp bin Op.MRC None OD.OprCpOpc1RtCRnCRmOpc2

/// Advanced SIMD and System register 32-bit move on page F4-4259.
let parseAdvSIMDAndSysReg32bitMove (phlp: ParsingHelper) bin =
  match concat (pickThree bin 21) (pickThree bin 8) 3 (* op0:op1 *) with
  | 0b000000u -> raise ParsingFailureException
  | 0b000001u -> (* Armv8.2 *)
#if !EMULATION
    chkCondPCRt bin phlp.Cond
#endif
    let oprFn = if pickBit bin 20 = 0u (* op *) then OD.OprSnRt else OD.OprRtSn
    render phlp bin Op.VMOV (oneDt SIMDTypF16) oprFn
  | 0b000010u ->
#if !EMULATION
    chkPCRt bin
#endif
    let oprFn = if pickBit bin 20 = 0u (* op *) then OD.OprSnRt else OD.OprRtSn
    render phlp bin Op.VMOV None oprFn
  | 0b001010u -> raise ParsingFailureException
  | 0b010010u | 0b011010u -> raise ParsingFailureException
  | 0b100010u | 0b101010u -> raise ParsingFailureException
  | 0b110010u -> raise ParsingFailureException
  | 0b111010u -> parseFPMoveSpecialReg phlp bin
  | _ ->
    match pickThree bin 8 (* op1 *) with
    | 0b011u -> parseAdvSIMD8n16n32bitElemMoveDup phlp bin
    | 0b100u | 0b101u -> raise ParsingFailureException
    | 0b110u | 0b111u -> parseSystemReg32bitMove phlp bin
    | _ -> raise ParsingFailureException

/// System register access, Advanced SIMD, floating-point, and Supervisor call
/// on page F4-4246.
let parseCase11 (phlp: ParsingHelper) bin =
  let op0op1op2 =
    (pickTwo bin 24 <<< 2) + (pickBit bin 11 <<< 1) + (pickBit bin 4)
  match op0op1op2 (* op0:op1:op2 *) with
  | _ when phlp.IsARMv7 && phlp.Cond = Condition.UN &&
           (pickBit bin 25 = 0u) && (pickBit bin 20 = 0u) (* ARMv7 A8-663 *) ->
#if !EMULATION
    chkPUDWCopPCRn bin
#endif
    render phlp bin Op.STC2 None OD.OprCoprocCRdMem
  | 0b0000u | 0b0001u | 0b0100u | 0b0101u (* 0x0x *) ->
    raise ParsingFailureException
  | 0b1000u | 0b1001u (* 100x *) when phlp.IsARMv7 -> (* ARMv7 A8-356 *)
    render phlp bin Op.CDP None OD.OprCpOpc1CRdCRnCRmOpc2
  | 0b1000u | 0b1001u (* 100x *) -> raise ParsingFailureException
  | 0b1100u | 0b1101u | 0b1110u | 0b1111u (* 11xx *) ->
    parseSupervisorCall phlp bin
  | 0b0010u | 0b0011u | 0b0110u | 0b0111u | 0b1010u | 0b1011u (* != 11 1 x *)
    when phlp.Cond = Condition.UN ->
    parseUncondAdvSIMDAndFPInstr phlp bin
  | 0b0010u | 0b0011u | 0b0110u | 0b0111u ->
    parseAdvSIMDAndSysRegLdStAnd64bitMove phlp bin
  | 0b1010u -> parseFloatingPointDataProcessing phlp bin
  | _ (* 0b1011u *) -> parseAdvSIMDAndSysReg32bitMove phlp bin

/// CPS, CPSID, CPSIE on page F5-4372.
let parseCPS (phlp: ParsingHelper) bin =
  (* if mode != '00000' && M == '0' then UNPREDICTABLE
     if (imod<1> == '1' && A:I:F == '000') || (imod<1> == '0' && A:I:F != '000')
     then UNPREDICTABLE *)
  let imod1 = pickBit bin 19 (* imod<1> *)
  let aif = pickThree bin 6 (* A:I:F *)
  (((pickFive bin 0 <> 0u (* mode *)) && (pickBit bin 17 = 0u (* M *))) ||
   (((imod1 = 1u) && (aif = 0u)) || ((imod1 = 0u) && (aif <> 0u))))
   |> checkUnpred
  let struct (op, oprs) =
    match pickThree bin 17 (* imod:M *) with
    | 0b001u -> struct (Op.CPS, OD.OprMode)
    | 0b110u -> struct (Op.CPSID, OD.OprIflagsA)
    | 0b111u -> struct (Op.CPSID, OD.OprIflagsModeA)
    | 0b100u -> struct (Op.CPSIE, OD.OprIflagsA)
    | 0b101u -> struct (Op.CPSIE, OD.OprIflagsModeA)
    | _ (* 000 or 01x *) -> raise UnpredictableException
  render phlp bin op None oprs

/// Change Process State on page F4-4262.
let parseChangeProcessState (phlp: ParsingHelper) bin =
  match pickTwoBitsApart bin 16 4 (* op:mode<4> *) with
  | 0b10u -> render phlp bin Op.SETEND None OD.OprEndianA
  | 0b00u | 0b01u -> parseCPS phlp bin
  | _ (* 11 *) -> raise ParsingFailureException

/// Miscellaneous on page F4-4261.
let parseUncondMiscellaneous (phlp: ParsingHelper) bin =
  match concat (pickFive bin 20) (pickFour bin 4) 4 (* op0:op1 *) with
  | 0b100000000u | 0b100000001u | 0b100000100u | 0b100000101u | 0b100001000u
  | 0b100001001u | 0b100001100u | 0b100001101u (* 10000xx0x *) ->
    parseChangeProcessState phlp bin
  | 0b100010000u -> (* Armv8.1 *)
    render phlp bin Op.SETPAN None OD.OprImm1A
  | 0b100100111u -> raise UnpredictableException
  | _ -> raise ParsingFailureException

/// Advanced SIMD three registers of the same length on page F4-4263.
let parseAdvSIMDThreeRegsSameLen (phlp: ParsingHelper) bin =
  let decodeFields =
    (pickBit bin 24 <<< 8) + (pickTwo bin 20 <<< 6) +
    (pickFour bin 8 <<< 2) + (pickBit bin 6 <<< 1) + (pickBit bin 4)
  match decodeFields (* U:size:opc:Q:o1 *) with
  | 0b000110001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VFMA (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b000110011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VFMA (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b001110001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VFMA (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b001110011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VFMA (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b000110100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VADD (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b000110110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VADD (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b001110100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VADD (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b001110110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VADD (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b000110101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLA (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b000110111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLA (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b001110101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLA (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b001110111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLA (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b000111000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b000111010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b001111000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b001111010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b000111100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMAX (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b000111110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMAX (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b001111100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMAX (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b001111110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMAX (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b000111101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VRECPS (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b000111111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VRECPS (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b001111101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VRECPS (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b001111111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VRECPS (oneDt SIMDTypF16) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000000000u (* xxx000000 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VHADD (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000000010u (* xxx000010 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VHADD (getDTUSize bin) OD.OprQdQnQm
  | 0b000000101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VAND None OD.OprDdDnDm
  | 0b000000111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VAND None OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000000001u (* xxx000001 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQADD (getDTUSzQ bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000000011u (* xxx000011 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQADD (getDTUSzQ bin) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000000100u (* xxx000100 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VRHADD (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000000110u (* xxx000110 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VRHADD (getDTUSize bin) OD.OprQdQnQm
  | 0b000110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b000110010u -> (* ARMv8 *)
#if !EMULATION
    chkVdVnVm bin
#endif
    render phlp bin Op.SHA1C (oneDt SIMDTyp32) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000001000u (* xxx001000 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VHSUB (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000001010u (* xxx001010 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VHSUB (getDTUSize bin) OD.OprQdQnQm
  | 0b001000101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VBIC None OD.OprDdDnDm
  | 0b001000111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VBIC None OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000001001u (* xxx001001 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQSUB (getDTUSzQ bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000001011u (* xxx001011 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQSUB (getDTUSzQ bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000001100u (* xxx001100 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCGT (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000001110u (* xxx001110 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCGT (getDTUSize bin) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000001101u (* xxx0011x1 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCGE (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000001111u (* xxx0011x1 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCGE (getDTUSize bin) OD.OprQdQnQm
  | 0b001110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b001110010u -> (* ARMv8 *)
#if !EMULATION
    chkVdVnVm bin
#endif
    render phlp bin Op.SHA1P (oneDt SIMDTyp32) OD.OprQdQnQm
  | 0b010110001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VFMS (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b010110011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VFMS (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b011110001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VFMS (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b011110011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VFMS (oneDt SIMDTypF16) OD.OprQdQnQm
  (* 01x1101x0 VSUB (floating-point) *)
  | 0b010110100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b010110110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b011110100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b011110110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b010110101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLS (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b010110111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLS (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b011110101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLS (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b011110111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLS (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b010111000u | 0b010111010u | 0b011111000u | 0b011111010u (* 01x1110x0 *) ->
    raise ParsingFailureException
  | 0b010111100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMIN (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b010111110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMIN (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b011111100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMIN (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b011111110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMIN (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b010111101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VRSQRTS (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b010111111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VRSQRTS (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b011111101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VRSQRTS (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b011111111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VRSQRTS (oneDt SIMDTypF16) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000010000u (* xxx010000 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSHL (getDTUSzQ bin) OD.OprDdDmDn
  | b when b &&& 0b000111111u = 0b000010010u (* xxx010010 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSHL (getDTUSzQ bin) OD.OprQdQmQn
  | 0b000100000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VADD (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b001100000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VADD (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b010100000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VADD (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b011100000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VADD (oneDt SIMDTypI64) OD.OprDdDnDm
  | 0b000100010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VADD (oneDt SIMDTypI8) OD.OprQdQnQm
  | 0b001100010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VADD (oneDt SIMDTypI16) OD.OprQdQnQm
  | 0b010100010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VADD (oneDt SIMDTypI32) OD.OprQdQnQm
  | 0b011100010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VADD (oneDt SIMDTypI64) OD.OprQdQnQm
  | 0b010000101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VORR None OD.OprDdDnDm
  | 0b010000111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VORR None OD.OprQdQnQm
  | 0b000100001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VTST (oneDt SIMDTyp8) OD.OprDdDnDm
  | 0b001100001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VTST (oneDt SIMDTyp16) OD.OprDdDnDm
  | 0b010100001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VTST (oneDt SIMDTyp32) OD.OprDdDnDm
  | 0b000100011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VTST (oneDt SIMDTyp8) OD.OprQdQnQm
  | 0b001100011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VTST (oneDt SIMDTyp16) OD.OprQdQnQm
  | 0b010100011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VTST (oneDt SIMDTyp32) OD.OprQdQnQm
  | 0b011100001u | 0b011100011u (* 0111000x1 *) -> raise UndefinedException
  | b when b &&& 0b000111111u = 0b000010001u (* xxx010001 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQSHL (getDTUSzQ bin) OD.OprDdDmDn
  | b when b &&& 0b000111111u = 0b000010011u (* xxx010011 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQSHL (getDTUSzQ bin) OD.OprQdQmQn
  | 0b000100100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLA (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b001100100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLA (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b010100100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLA (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b000100110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLA (oneDt SIMDTypI8) OD.OprQdQnQm
  | 0b001100110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLA (oneDt SIMDTypI16) OD.OprQdQnQm
  | 0b010100110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLA (oneDt SIMDTypI32) OD.OprQdQnQm
  | 0b011100100u | 0b011100110u (* 0111001x0 *) -> raise UndefinedException
  | b when b &&& 0b000111111u = 0b000010100u (* xxx010100 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VRSHL (getDTUSzQ bin) OD.OprDdDmDn
  | b when b &&& 0b000111111u = 0b000010110u (* xxx010110 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VRSHL (getDTUSzQ bin) OD.OprQdQmQn
  | b when b &&& 0b000111111u = 0b000010101u (* xxx010101 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRSHL (getDTUSzQ bin) OD.OprDdDmDn
  | b when b &&& 0b000111111u = 0b000010111u (* xxx010111 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRSHL (getDTUSzQ bin) OD.OprQdQmQn
  | 0b001101100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQDMULH (oneDt SIMDTypS16) OD.OprDdDnDm
  | 0b010101100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQDMULH (oneDt SIMDTypS32) OD.OprDdDnDm
  | 0b001101110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQDMULH (oneDt SIMDTypS16) OD.OprQdQnQm
  | 0b010101110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQDMULH (oneDt SIMDTypS32) OD.OprQdQnQm
  | 0b000101100u | 0b000101110u (* 0001011x0 *)
  | 0b011101100u | 0b011101110u (* 0111011x0 *) -> raise UndefinedException
  | 0b010110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b010110010u -> (* ARMv8 *)
#if !EMULATION
    chkVdVnVm bin
#endif
    render phlp bin Op.SHA1M (oneDt SIMDTyp32) OD.OprQdQnQm
  | 0b000101101u (* 0xx101101 *) ->
    render phlp bin Op.VPADD (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b001101101u (* 0xx101101 *) ->
    render phlp bin Op.VPADD (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b010101101u (* 0xx101101 *) ->
    render phlp bin Op.VPADD (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b011101101u (* 0111011x1 *) -> raise UndefinedException
  | 0b000101111u | 0b001101111u | 0b010101111u | 0b011101111u (* 0xx101111 *) ->
    raise UndefinedException
  | b when b &&& 0b000111111u = 0b000011000u (* xxx011000 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMAX (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000011010u (* xxx011010 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMAX (getDTUSize bin) OD.OprQdQnQm
  | 0b011000101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VORN None OD.OprDdDnDm
  | 0b011000111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VORN None OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000011001u (* xxx011001 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMIN (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000011011u (* xxx011011 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMIN (getDTUSize bin) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000011100u (* xxx011100 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VABD (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000011110u (* xxx011110 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VABD (getDTUSize bin) OD.OprQdQnQm
  | b when b &&& 0b000111111u = 0b000011101u (* xxx011101 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VABA (getDTUSize bin) OD.OprDdDnDm
  | b when b &&& 0b000111111u = 0b000011111u (* xxx011111 *) ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VABA (getDTUSize bin) OD.OprQdQnQm
  | 0b011110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b011110010u -> (* ARMv8 *)
#if !EMULATION
    chkVdVnVm bin
#endif
    render phlp bin Op.SHA1SU0 (oneDt SIMDTyp32) OD.OprQdQnQm
  | 0b100110100u ->
    render phlp bin Op.VPADD (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b101110100u ->
    render phlp bin Op.VPADD (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b100110110u | 0b101110110u (* 10x110110 *) -> raise UndefinedException
  | 0b100110101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b100110111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b101110101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b101110111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b100111000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b100111010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b101111000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b101111010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b100111001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VACGE (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b100111011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VACGE (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b101111001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VACGE (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b101111011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VACGE (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b100111100u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b101111100u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypF16) OD.OprDdDnDm
  (* 10x1111x1 Op.VMAXNM ARMv8 *)
  | 0b100111101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMAXNM (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b100111111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMAXNM (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b101111101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMAXNM (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b101111111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMAXNM (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b100000101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VEOR None OD.OprDdDnDm
  | 0b100000111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VEOR None OD.OprQdQnQm
  | 0b000100101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b000100111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypI8) OD.OprQdQnQm
  | 0b001100101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b001100111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypI16) OD.OprQdQnQm
  | 0b010100101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b010100111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypI32) OD.OprQdQnQm
  | 0b100100101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypP8) OD.OprDdDnDm
  | 0b100100111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMUL (oneDt SIMDTypP8) OD.OprQdQnQm
  (* if size == '11' || (op == '1' && size != '00') then UNDEFINED *)
  | 0b011100101u | 0b011100111u | 0b111100101u | 0b111100111u | 0b101100101u
  | 0b101100111u | 0b110100101u | 0b110100111u -> raise UndefinedException
  | 0b100110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b100110010u -> (* ARMv8 *)
#if !EMULATION
    chkVdVnVm bin
#endif
    render phlp bin Op.SHA256H (oneDt SIMDTyp32) OD.OprQdQnQm
  | 0b000101000u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypS8) OD.OprDdDnDm
  | 0b001101000u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypS16) OD.OprDdDnDm
  | 0b010101000u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypS32) OD.OprDdDnDm
  | 0b100101000u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypU8) OD.OprDdDnDm
  | 0b101101000u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypU16) OD.OprDdDnDm
  | 0b110101000u ->
    render phlp bin Op.VPMAX (oneDt SIMDTypU32) OD.OprDdDnDm
  | 0b011101000u | 0b111101000u (* x11101000 *) -> raise UndefinedException
  | 0b101000101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VBSL None OD.OprDdDnDm
  | 0b101000111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VBSL None OD.OprQdQnQm
  | 0b000101001u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypS8) OD.OprDdDnDm
  | 0b001101001u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypS16) OD.OprDdDnDm
  | 0b010101001u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypS32) OD.OprDdDnDm
  | 0b100101001u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypU8) OD.OprDdDnDm
  | 0b101101001u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypU16) OD.OprDdDnDm
  | 0b110101001u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypU32) OD.OprDdDnDm
  | 0b011101001u | 0b111101001u (* x11101001 *) -> raise UndefinedException
  | b when b &&& 0b000111110u = 0b000101010u (* xxx10101x *) ->
    raise ParsingFailureException
  | 0b101110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b101110010u -> (* ARMv8 *)
#if !EMULATION
    chkVdVnVm bin
#endif
    render phlp bin Op.SHA256H2 (oneDt SIMDTyp32) OD.OprQdQnQm
  | 0b110110100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VABD (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b110110110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VABD (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b111110100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VABD (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b111110110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VABD (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b110111000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b110111010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b111111000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b111111010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b110111001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VACGT (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b110111011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VACGT (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b111111001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VACGT (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b111111011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VACGT (oneDt SIMDTypF16) OD.OprQdQnQm
  | 0b110111100u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b111111100u ->
    render phlp bin Op.VPMIN (oneDt SIMDTypF16) OD.OprDdDnDm
  (* 11x1111x1 Op.VMINNM ARMv8 *)
  | 0b110111101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMINNM (oneDt SIMDTypF32) OD.OprDdDnDm
  | 0b110111111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMINNM (oneDt SIMDTypF32) OD.OprQdQnQm
  | 0b111111101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMINNM (oneDt SIMDTypF16) OD.OprDdDnDm
  | 0b111111111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMINNM (oneDt SIMDTypF16) OD.OprQdQnQm
  (* 1xx1000x0 VSUB *)
  | 0b100100000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b101100000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b110100000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b111100000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypI64) OD.OprDdDnDm
  | 0b100100010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypI8) OD.OprQdQnQm
  | 0b101100010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypI16) OD.OprQdQnQm
  | 0b110100010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypI32) OD.OprQdQnQm
  | 0b111100010u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSUB (oneDt SIMDTypI64) OD.OprQdQnQm
  (* 1100001x1 VBIT *)
  | 0b110000101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VBIT None OD.OprDdDnDm
  | 0b110000111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VBIT None OD.OprQdQnQm
   (* 1xx1000x1 VCEQ *)
  | 0b100100001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b101100001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b110100001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b100100011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypI8) OD.OprQdQnQm
  | 0b101100011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypI16) OD.OprQdQnQm
  | 0b110100011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypI32) OD.OprQdQnQm
  | 0b111100001u | 0b111100011u (* 0b1111000x1u *) -> raise UndefinedException
  (* 1xx1001x0 VMLS *)
  | 0b100100100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLS (oneDt SIMDTypI8) OD.OprDdDnDm
  | 0b101100100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLS (oneDt SIMDTypI16) OD.OprDdDnDm
  | 0b110100100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLS (oneDt SIMDTypI32) OD.OprDdDnDm
  | 0b100100110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLS (oneDt SIMDTypI8) OD.OprQdQnQm
  | 0b101100110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLS (oneDt SIMDTypI16) OD.OprQdQnQm
  | 0b110100110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VMLS (oneDt SIMDTypI32) OD.OprQdQnQm
  | 0b111100100u | 0b111100110u (* 1111001x0 *) -> raise UndefinedException
  (* 1xx1011x0 VQRDMULH *)
  | 0b101101100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRDMULH (oneDt SIMDTypS16) OD.OprDdDnDm
  | 0b110101100u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRDMULH (oneDt SIMDTypS32) OD.OprDdDnDm
  | 0b101101110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRDMULH (oneDt SIMDTypS16) OD.OprQdQnQm
  | 0b110101110u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRDMULH (oneDt SIMDTypS32) OD.OprQdQnQm
  | 0b100101100u | 0b100101110u | 0b111101100u
  | 0b111101110u (* 1001011x0 or 1111011x0 *) -> raise UndefinedException
  | 0b110110000u -> raise UndefinedException (* if Q != '1' then UNDEFINED *)
  | 0b110110010u -> (* ARMv8 *)
#if !EMULATION
    chkVdVnVm bin
#endif
    render phlp bin Op.SHA256SU1 (oneDt SIMDTyp32) OD.OprQdQnQm
  (* 1xx1011x1 Op.VQRDMLAH Armv8.1 *)
  | 0b100101101u | 0b100101111u (* 1001011x1 *) -> raise UndefinedException
  | 0b111101101u | 0b111101111u (* 1111011x1 *) -> raise UndefinedException
  | 0b101101101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRDMLAH (oneDt SIMDTypS16) OD.OprDdDnDm
  | 0b101101111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRDMLAH (oneDt SIMDTypS16) OD.OprQdQnQm
  | 0b110101101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRDMLAH (oneDt SIMDTypS32) OD.OprDdDnDm
  | 0b110101111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRDMLAH (oneDt SIMDTypS32) OD.OprQdQnQm
  (* 1110001x1 VBIF *)
  | 0b111000101u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VBIF None OD.OprDdDnDm
  | 0b111000111u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VBIF None OD.OprQdQnQm
  (* 1xx1100x1 Op.VQRDMLSH Armv8.1 *)
  | 0b100110001u | 0b100110011u (* 1001100x1 *) -> raise UndefinedException
  | 0b111110001u | 0b111110011u (* 1111100x1 *) -> raise UndefinedException
  | 0b101110001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRDMLSH (oneDt SIMDTypS16) OD.OprDdDnDm
  | 0b101110011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRDMLSH (oneDt SIMDTypS16) OD.OprQdQnQm
  | 0b110110001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRDMLSH (oneDt SIMDTypS32) OD.OprDdDnDm
  | 0b110110011u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VQRDMLSH (oneDt SIMDTypS32) OD.OprQdQnQm
  | b when b &&& 0b100111111u = 0b100111110u (* 1xx111110 *) ->
    raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// Advanced SIMD two registers misc on page F4-4266.
let parseAdvaSIMDTwoRegsMisc (phlp: ParsingHelper) bin =
  (* size:opc1:opc2:Q *)
  match concat (pickFour bin 16) (pickFive bin 6) 5 with
  (* xx000000x VREV64 *)
  | 0b000000000u ->
#if !EMULATION
    chkOpSzQVdVm bin
#endif
    render phlp bin Op.VREV64 (oneDt SIMDTyp8) OD.OprDdDm
  | 0b010000000u ->
#if !EMULATION
    chkOpSzQVdVm bin
#endif
    render phlp bin Op.VREV64 (oneDt SIMDTyp16) OD.OprDdDm
  | 0b100000000u ->
#if !EMULATION
    chkOpSzQVdVm bin
#endif
    render phlp bin Op.VREV64 (oneDt SIMDTyp32) OD.OprDdDm
  | 0b000000001u ->
#if !EMULATION
    chkOpSzQVdVm bin
#endif
    render phlp bin Op.VREV64 (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010000001u ->
#if !EMULATION
    chkOpSzQVdVm bin
#endif
    render phlp bin Op.VREV64 (oneDt SIMDTyp16) OD.OprQdQm
  | 0b100000001u ->
#if !EMULATION
    chkOpSzQVdVm bin
#endif
    render phlp bin Op.VREV64 (oneDt SIMDTyp32) OD.OprQdQm
  | 0b110000000u | 0b110000001u (* 11000000x *) -> raise UndefinedException
  (* xx000001x VREV32 *)
  | 0b000000010u ->
#if !EMULATION
    chkOpSzQVdVm bin
#endif
    render phlp bin Op.VREV32 (oneDt SIMDTyp8) OD.OprDdDm
  | 0b010000010u ->
#if !EMULATION
    chkOpSzQVdVm bin
#endif
    render phlp bin Op.VREV32 (oneDt SIMDTyp16) OD.OprDdDm
  | 0b000000011u ->
#if !EMULATION
    chkOpSzQVdVm bin
#endif
    render phlp bin Op.VREV32 (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010000011u ->
#if !EMULATION
    chkOpSzQVdVm bin
#endif
    render phlp bin Op.VREV32 (oneDt SIMDTyp16) OD.OprQdQm
  | 0b100000010u | 0b100000011u | 0b110000010u | 0b110000011u (* 1x000001x *)
    -> raise UndefinedException (* reserved *)
  (* xx000010x VREV16 *)
  | 0b000000100u ->
#if !EMULATION
    chkOpSzQVdVm bin
#endif
    render phlp bin Op.VREV16 (oneDt SIMDTyp8) OD.OprDdDm
  | 0b000000101u ->
#if !EMULATION
    chkOpSzQVdVm bin
#endif
    render phlp bin Op.VREV16 (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010000100u | 0b010000101u (* 01000010x *)
  | 0b100000100u | 0b100000101u | 0b110000100u | 0b110000101u (* 1x000010x *) ->
    raise UndefinedException (* reserved *)
  | b when b &&& 0b001111110u = 0b000000110u (* xx000011x *) ->
    raise ParsingFailureException
  (* xx00010xx VPADDL *)
  | 0b000001000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADDL (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010001000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADDL (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100001000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADDL (oneDt SIMDTypS32) OD.OprDdDm
  | 0b000001010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADDL (oneDt SIMDTypU8) OD.OprDdDm
  | 0b010001010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADDL (oneDt SIMDTypU16) OD.OprDdDm
  | 0b100001010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADDL (oneDt SIMDTypU32) OD.OprDdDm
  | 0b000001001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADDL (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010001001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADDL (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100001001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADDL (oneDt SIMDTypS32) OD.OprQdQm
  | 0b000001011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADDL (oneDt SIMDTypU8) OD.OprQdQm
  | 0b010001011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADDL (oneDt SIMDTypU16) OD.OprQdQm
  | 0b100001011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADDL (oneDt SIMDTypU32) OD.OprQdQm
  | 0b110001000u | 0b110001001u | 0b110001010u | 0b110001011u (* 1100010xx *) ->
    raise UndefinedException (* size = 11 *)
  (* xx0001100 AESE *)
  | 0b000001100u ->
#if !EMULATION
    chkVdVm bin
#endif
    render phlp bin Op.AESE (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010001100u | 0b100001100u | 0b110001100u (* size = 10 or 1x *) ->
    raise UndefinedException
   (* xx0001101 AESD *)
  | 0b000001101u ->
#if !EMULATION
    chkVdVm bin
#endif
    render phlp bin Op.AESD (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010001101u | 0b100001101u | 0b110001101u (* size = 10 or 1x *) ->
    raise UndefinedException
  (* xx0001110 AESMC *)
  | 0b000001110u ->
#if !EMULATION
    chkVdVm bin
#endif
    render phlp bin Op.AESMC (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010001110u | 0b100001110u | 0b110001110u (* size = 10 or 1x *) ->
    raise UndefinedException
  (* xx0001111 AESIMC *)
  | 0b000001111u ->
#if !EMULATION
    chkVdVm bin
#endif
    render phlp bin Op.AESIMC (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010001111u | 0b100001111u | 0b110001111u (* size = 10 or 1x *) ->
    raise UndefinedException
  (* xx001000x VCLS *)
  | 0b000010000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLS (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010010000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLS (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100010000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLS (oneDt SIMDTypS32) OD.OprDdDm
  | 0b000010001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLS (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010010001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLS (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100010001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLS (oneDt SIMDTypS32) OD.OprQdQm
  | 0b110010000u| 0b110010001u (* 11001000x *) -> raise UndefinedException
  (* 00100000x VSWP *)
  | 0b001000000u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSWP None OD.OprDdDm
  | 0b001000001u ->
#if !EMULATION
    chkQVdVnVm bin
#endif
    render phlp bin Op.VSWP None OD.OprQdQm
  (* xx001001x VCLZ *)
  | 0b000010010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLZ (oneDt SIMDTypI8) OD.OprDdDm
  | 0b010010010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLZ (oneDt SIMDTypI16) OD.OprDdDm
  | 0b100010010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLZ (oneDt SIMDTypI32) OD.OprDdDm
  | 0b000010011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLZ (oneDt SIMDTypI8) OD.OprQdQm
  | 0b010010011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLZ (oneDt SIMDTypI16) OD.OprQdQm
  | 0b100010011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLZ (oneDt SIMDTypI32) OD.OprQdQm
  | 0b110010010u | 0b110010011u (* 11x001001x *) -> raise UndefinedException
  (* xx001010x *)
  | 0b000010100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCNT (oneDt SIMDTyp8) OD.OprDdDm
  | 0b000010101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCNT (oneDt SIMDTyp8) OD.OprQdQm
  | 0b010010100u | 0b100010100u | 0b110010100u | 0b010010101u | 0b100010101u
  | 0b110010101u (* size != 00 *) -> raise UndefinedException
  (* xx001011x VMVN *)
  | 0b000010110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VMVN None OD.OprDdDm
  | 0b000010111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VMVN None OD.OprQdQm
  | 0b010010110u | 0b100010110u | 0b110010110u | 0b010010111u | 0b100010111u
  | 0b110010111u (* size != 00 *) -> raise UndefinedException
  | 0b001011001u -> raise ParsingFailureException
  (* xx00110xx VPADAL *)
  | 0b000011000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADAL (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010011000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADAL (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100011000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADAL (oneDt SIMDTypS32) OD.OprDdDm
  | 0b000011010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADAL (oneDt SIMDTypU8) OD.OprDdDm
  | 0b010011010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADAL (oneDt SIMDTypU16) OD.OprDdDm
  | 0b100011010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADAL (oneDt SIMDTypU32) OD.OprDdDm
  | 0b000011001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADAL (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010011001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADAL (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100011001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADAL (oneDt SIMDTypS32) OD.OprQdQm
  | 0b000011011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADAL (oneDt SIMDTypU8) OD.OprQdQm
  | 0b010011011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADAL (oneDt SIMDTypU16) OD.OprQdQm
  | 0b100011011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VPADAL (oneDt SIMDTypU32) OD.OprQdQm
  | 0b110011000u | 0b110011001u | 0b110011010u | 0b110011011u (* 1100110xx *) ->
    raise UndefinedException
  (* xx001110x VQABS *)
  | 0b000011100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VQABS (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010011100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VQABS (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100011100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VQABS (oneDt SIMDTypS32) OD.OprDdDm
  | 0b000011101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VQABS (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010011101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VQABS (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100011101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VQABS (oneDt SIMDTypS32) OD.OprQdQm
  | 0b110011100u | 0b110011101u (* 11001110x *) -> raise UndefinedException
  (* xx001111x VQNEG *)
  | 0b000011110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VQNEG (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010011110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VQNEG (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100011110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VQNEG (oneDt SIMDTypS32) OD.OprDdDm
  | 0b000011111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VQNEG (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010011111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VQNEG (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100011111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VQNEG (oneDt SIMDTypS32) OD.OprQdQm
  | 0b110011110u | 0b110011111u (* 11001111x *) -> raise UndefinedException
  (* xx01x000x VCGT *)
  | 0b000100000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypS8) OD.OprDdDmImm0
  | 0b010100000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypS16) OD.OprDdDmImm0
  | 0b100100000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypS32) OD.OprDdDmImm0
  | 0b010110000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypF16) OD.OprDdDmImm0
  | 0b100110000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypF32) OD.OprDdDmImm0
  | 0b000100001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypS8) OD.OprQdQmImm0
  | 0b010100001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypS16) OD.OprQdQmImm0
  | 0b100100001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypS32) OD.OprQdQmImm0
  | 0b010110001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypF16) OD.OprQdQmImm0
  | 0b100110001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGT (oneDt SIMDTypF32) OD.OprQdQmImm0
  | 0b000110000u | 0b000110001u (* 00011000x *) -> raise UndefinedException
  | 0b110100000u | 0b110100001u | 0b110110000u | 0b110110001u (* 1101x000x *) ->
    raise UndefinedException
  (* xx01x001x VCGE *)
  | 0b000100010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypS8) OD.OprDdDmImm0
  | 0b010100010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypS16) OD.OprDdDmImm0
  | 0b100100010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypS32) OD.OprDdDmImm0
  | 0b010110010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypF16) OD.OprDdDmImm0
  | 0b100110010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypF32) OD.OprDdDmImm0
  | 0b000100011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypS8) OD.OprQdQmImm0
  | 0b010100011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypS16) OD.OprQdQmImm0
  | 0b100100011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypS32) OD.OprQdQmImm0
  | 0b010110011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypF16) OD.OprQdQmImm0
  | 0b100110011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCGE (oneDt SIMDTypF32) OD.OprQdQmImm0
  | 0b000110010u | 0b000110011u (* 00011001x *) -> raise UndefinedException
  | 0b110100010u | 0b110100011u | 0b110110010u | 0b110110011u (* 1101x001x *) ->
    raise UndefinedException
  (* xx01x010x VCEQ *)
  | 0b000100100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypI8) OD.OprDdDmImm0
  | 0b010100100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypI16) OD.OprDdDmImm0
  | 0b100100100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypI32) OD.OprDdDmImm0
  | 0b010110100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypF16) OD.OprDdDmImm0
  | 0b100110100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypF32) OD.OprDdDmImm0
  | 0b000100101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypI8) OD.OprQdQmImm0
  | 0b010100101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypI16) OD.OprQdQmImm0
  | 0b100100101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypI32) OD.OprQdQmImm0
  | 0b010110101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypF16) OD.OprQdQmImm0
  | 0b100110101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCEQ (oneDt SIMDTypF32) OD.OprQdQmImm0
  | 0b000110100u | 0b000110101u (* 00011010x *) -> raise UndefinedException
  | 0b110100100u | 0b110100101u | 0b110110100u | 0b110110101u (* 1101x010x *) ->
    raise UndefinedException
  (* xx01x011x VCLE *)
  | 0b000100110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLE (oneDt SIMDTypS8) OD.OprDdDmImm0
  | 0b010100110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLE (oneDt SIMDTypS16) OD.OprDdDmImm0
  | 0b100100110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLE (oneDt SIMDTypS32) OD.OprDdDmImm0
  | 0b010110110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLE (oneDt SIMDTypF16) OD.OprDdDmImm0
  | 0b100110110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLE (oneDt SIMDTypF32) OD.OprDdDmImm0
  | 0b000100111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLE (oneDt SIMDTypS8) OD.OprQdQmImm0
  | 0b010100111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLE (oneDt SIMDTypS16) OD.OprQdQmImm0
  | 0b100100111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLE (oneDt SIMDTypS32) OD.OprQdQmImm0
  | 0b010110111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLE (oneDt SIMDTypF16) OD.OprQdQmImm0
  | 0b100110111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLE (oneDt SIMDTypF32) OD.OprQdQmImm0
  | 0b000110110u| 0b000110111u (* 00011011x *) -> raise UndefinedException
  | 0b110100110u | 0b110100111u | 0b110110110u | 0b110110111u (* 1101x011x *) ->
    raise UndefinedException
  (* xx01x100x VCLT *)
  | 0b000101000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLT (oneDt SIMDTypS8) OD.OprDdDmImm0
  | 0b010101000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLT (oneDt SIMDTypS16) OD.OprDdDmImm0
  | 0b100101000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLT (oneDt SIMDTypS32) OD.OprDdDmImm0
  | 0b010111000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLT (oneDt SIMDTypF16) OD.OprDdDmImm0
  | 0b100111000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLT (oneDt SIMDTypF32) OD.OprDdDmImm0
  | 0b000101001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLT (oneDt SIMDTypS8) OD.OprQdQmImm0
  | 0b010101001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLT (oneDt SIMDTypS16) OD.OprQdQmImm0
  | 0b100101001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLT (oneDt SIMDTypS32) OD.OprQdQmImm0
  | 0b010111001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLT (oneDt SIMDTypF16) OD.OprQdQmImm0
  | 0b100111001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VCLT (oneDt SIMDTypF32) OD.OprQdQmImm0
  | 0b000111000u | 0b000111001u (* 00011100x *) -> raise UndefinedException
  | 0b110101000u | 0b110101001u | 0b110111000u | 0b110111001u (* 1101x100x *) ->
    raise UndefinedException
  (* xx01x110x VABS *)
  | 0b000101100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VABS (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010101100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VABS (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100101100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VABS (oneDt SIMDTypS32) OD.OprDdDm
  | 0b010111100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VABS (oneDt SIMDTypF16) OD.OprDdDm
  | 0b100111100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VABS (oneDt SIMDTypF32) OD.OprDdDm
  | 0b000101101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VABS (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010101101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VABS (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100101101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VABS (oneDt SIMDTypS32) OD.OprQdQm
  | 0b010111101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VABS (oneDt SIMDTypF16) OD.OprQdQm
  | 0b100111101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VABS (oneDt SIMDTypF32) OD.OprQdQm
  | 0b000111100u | 0b000111101u (* 00011110x *) -> raise UndefinedException
  | 0b110101100u | 0b110101101u | 0b110111100u | 0b110111101u (* 1101x110x *) ->
    raise UndefinedException
  (* xx01x111x VNEG *)
  | 0b000101110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VNEG (oneDt SIMDTypS8) OD.OprDdDm
  | 0b010101110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VNEG (oneDt SIMDTypS16) OD.OprDdDm
  | 0b100101110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VNEG (oneDt SIMDTypS32) OD.OprDdDm
  | 0b010111110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VNEG (oneDt SIMDTypF16) OD.OprDdDm
  | 0b100111110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VNEG (oneDt SIMDTypF32) OD.OprDdDm
  | 0b000101111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VNEG (oneDt SIMDTypS8) OD.OprQdQm
  | 0b010101111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VNEG (oneDt SIMDTypS16) OD.OprQdQm
  | 0b100101111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VNEG (oneDt SIMDTypS32) OD.OprQdQm
  | 0b010111111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VNEG (oneDt SIMDTypF16) OD.OprQdQm
  | 0b100111111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VNEG (oneDt SIMDTypF32) OD.OprQdQm
  | 0b000111110u | 0b000111111u (* 00011111x *) -> raise UndefinedException
  | 0b110101110u | 0b110101111u | 0b110111110u | 0b110111111u (* 1101x111x *) ->
    raise UndefinedException
  (* xx0101011 SHA1H *)
  | 0b100101011u ->
#if !EMULATION
    chkVdVm bin
#endif
    render phlp bin Op.SHA1H (oneDt SIMDTyp32) OD.OprQdQm
  | 0b000101011u | 0b010101011u | 0b110101011u (* size != 10 *) ->
    raise UndefinedException
  | 0b011011001u -> (* Armv8.6 *)
#if !EMULATION
    chkVm bin
#endif
    render phlp bin Op.VCVT (twoDt (BF16, SIMDTypF32)) OD.OprDdQm
  (* xx100001x VTRN *)
  | 0b001000010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VTRN (oneDt SIMDTyp8) OD.OprDdDm
  | 0b011000010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VTRN (oneDt SIMDTyp16) OD.OprDdDm
  | 0b101000010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VTRN (oneDt SIMDTyp32) OD.OprDdDm
  | 0b001000011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VTRN (oneDt SIMDTyp8) OD.OprQdQm
  | 0b011000011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VTRN (oneDt SIMDTyp16) OD.OprQdQm
  | 0b101000011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VTRN (oneDt SIMDTyp32) OD.OprQdQm
  | 0b111000010u | 0b111000011u (* 11100001x *) -> raise UndefinedException
  (* xx100010x VUZP *)
  | 0b001000100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VUZP (oneDt SIMDTyp8) OD.OprDdDm
  | 0b011000100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VUZP (oneDt SIMDTyp16) OD.OprDdDm
  | 0b001000101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VUZP (oneDt SIMDTyp8) OD.OprQdQm
  | 0b011000101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VUZP (oneDt SIMDTyp16) OD.OprQdQm
  | 0b101000101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VUZP (oneDt SIMDTyp32) OD.OprQdQm
  | 0b111000100u | 0b111000101u (* 11100010x *) -> raise UndefinedException
  | 0b101000100u -> raise UndefinedException (* Q == 0 && size == 10 *)
  (* xx100011x VZIP *)
  | 0b001000110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VZIP (oneDt SIMDTyp8) OD.OprDdDm
  | 0b011000110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VZIP (oneDt SIMDTyp16) OD.OprDdDm
  | 0b001000111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VZIP (oneDt SIMDTyp8) OD.OprQdQm
  | 0b011000111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VZIP (oneDt SIMDTyp16) OD.OprQdQm
  | 0b101000111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VZIP (oneDt SIMDTyp32) OD.OprQdQm
  | 0b111000110u | 0b111000111u (* 11100011x *) -> raise UndefinedException
  | 0b101000110u -> raise UndefinedException (* Q == 0 && size == 10 *)
  (* xx1001000 VMOVN *)
  | 0b001001000u ->
#if !EMULATION
    chkVm bin
#endif
    render phlp bin Op.VMOVN (oneDt SIMDTyp16) OD.OprDdQm
  | 0b011001000u ->
#if !EMULATION
    chkVm bin
#endif
    render phlp bin Op.VMOVN (oneDt SIMDTyp32) OD.OprDdQm
  | 0b101001000u ->
#if !EMULATION
    chkVm bin
#endif
    render phlp bin Op.VMOVN (oneDt SIMDTyp64) OD.OprDdQm
  | 0b111001000u (* size == 11 *) -> raise UndefinedException
  (* xx1001001 VQMOVUN *)
  | 0b001001001u ->
#if !EMULATION
    chkVm bin
#endif
    render phlp bin Op.VQMOVUN (oneDt SIMDTypS16) OD.OprDdQm
  | 0b011001001u ->
#if !EMULATION
    chkVm bin
#endif
    render phlp bin Op.VQMOVUN (oneDt SIMDTypS32) OD.OprDdQm
  | 0b101001001u ->
#if !EMULATION
    chkVm bin
#endif
    render phlp bin Op.VQMOVUN (oneDt SIMDTypS64) OD.OprDdQm
  | 0b111001001u (* size = 11 *) -> raise UndefinedException
  (* xx100101x VQMOVN *)
  | 0b001001010u ->
#if !EMULATION
    chkVm bin
#endif
    render phlp bin Op.VQMOVN (oneDt SIMDTypS16) OD.OprDdQm
  | 0b011001010u ->
#if !EMULATION
    chkVm bin
#endif
    render phlp bin Op.VQMOVN (oneDt SIMDTypS32) OD.OprDdQm
  | 0b101001010u ->
#if !EMULATION
    chkVm bin
#endif
    render phlp bin Op.VQMOVN (oneDt SIMDTypS64) OD.OprDdQm
  | 0b001001011u ->
#if !EMULATION
    chkVm bin
#endif
    render phlp bin Op.VQMOVN (oneDt SIMDTypU16) OD.OprDdQm
  | 0b011001011u ->
#if !EMULATION
    chkVm bin
#endif
    render phlp bin Op.VQMOVN (oneDt SIMDTypU32) OD.OprDdQm
  | 0b101001011u ->
#if !EMULATION
    chkVm bin
#endif
    render phlp bin Op.VQMOVN (oneDt SIMDTypU64) OD.OprDdQm
  | 0b111001010u | 0b111001011u (* size = 11 *) -> raise UndefinedException
  (* xx1001100 VSHLL *)
  | 0b001001100u ->
#if !EMULATION
    chkVd bin
#endif
    render phlp bin Op.VSHLL (oneDt SIMDTypI8) OD.OprQdDmImm8
  | 0b011001100u ->
#if !EMULATION
    chkVd bin
#endif
    render phlp bin Op.VSHLL (oneDt SIMDTypI16) OD.OprQdDmImm16
  | 0b101001100u ->
#if !EMULATION
    chkVd bin
#endif
    render phlp bin Op.VSHLL (oneDt SIMDTypI32) OD.OprQdDmImm32
  | 0b111001100u (* size = 11 *) -> raise UndefinedException
  (* xx1001110 SHA1SU1 *)
  | 0b101001110u ->
#if !EMULATION
    chkVdVm bin
#endif
    render phlp bin Op.SHA1SU1 (oneDt SIMDTyp32) OD.OprQdQm
  | 00001001110u | 0b011001110u | 0b111001110u (* size != 10 *) ->
    raise UndefinedException
  (* xx1001111 SHA256SU0 *)
  | 0b101001111u ->
#if !EMULATION
    chkVdVm bin
#endif
    render phlp bin Op.SHA256SU0 (oneDt SIMDTyp32) OD.OprQdQm
  | 0b001001111u| 0b011001111u| 0b111001111u (* size != 10 *) ->
    raise UndefinedException
  (* xx101000x VRINTN *)
  | 0b011010000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTN (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101010000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTN (oneDt SIMDTypF32) OD.OprDdDm
  | 0b011010001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTN (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101010001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTN (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001010000u | 0b001010001u | 0b111010000u
  | 0b111010001u (* size = 00 or 11 *) -> raise UndefinedException
  (* xx101001x VRINTX *)
  | 0b011010010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTX (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101010010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTX (oneDt SIMDTypF32) OD.OprDdDm
  | 0b011010011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTX (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101010011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTX (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001010010u | 0b001010011u | 0b111010010u
  | 0b111010011u (* size = 00 or 11 *) -> raise UndefinedException
  (* xx101010x VRINTA *)
  | 0b011010100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTA (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101010100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTA (oneDt SIMDTypF32) OD.OprDdDm
  | 0b011010101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTA (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101010101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTA (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001010100u | 0b001010101u | 0b111010100u
  | 0b111010101u (* size = 00 or 11 *) -> raise UndefinedException
  (* xx101011x VRINTZ *)
  | 0b011010110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTZ (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101010110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTZ (oneDt SIMDTypF32) OD.OprDdDm
  | 0b011010111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTZ (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101010111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTZ (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001010110u | 0b001010111u | 0b111010110u
  | 0b111010111u (* size = 00 or 1 1*) -> raise UndefinedException
  | 0b101011001u -> raise ParsingFailureException
  (* xx1011000 VCVT *)
  | 0b011011000u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprDdQm
  | 0b001011000u | 0b101011000u | 0b111011000u (* size != 01 *) ->
    raise UndefinedException
  (* xx101101x VRINTM *)
  | 0b011011010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTM (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101011010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTM (oneDt SIMDTypF32) OD.OprDdDm
  | 0b011011011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTM (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101011011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTM (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001011010u | 0b001011011u | 0b111011010u
  | 0b111011011u (* size = 00 or 11*) -> raise UndefinedException
  (* xx1011100 VCVT *)
  | 0b011011100u ->
#if !EMULATION
    chkVdVm bin
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprQdDm
  | 0b001011100u | 0b101011100u | 0b111011100u (* size != 01 *) ->
    raise UndefinedException
  | 0b001011101u | 0b011011101u | 0b101011101u | 0b111011101u (* xx1011101 *) ->
    raise ParsingFailureException
  (* xx101111x VRINTP *)
  | 0b011011110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTP (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101011110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTP (oneDt SIMDTypF32) OD.OprDdDm
  | 0b011011111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTP (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101011111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRINTP (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001011110u | 0b001011111u | 0b111011110u
  | 0b111011111u (* size = 00 or 11 *) -> raise UndefinedException
  (* xx11000xx VCVTA *)
  | 0b011100000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTA dt OD.OprDdDm
  | 0b101100000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTA dt OD.OprDdDm
  | 0b011100010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTA dt OD.OprDdDm
  | 0b101100010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTA dt OD.OprDdDm
  | 0b011100001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTA dt OD.OprQdQm
  | 0b101100001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTA dt OD.OprQdQm
  | 0b011100011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTA dt OD.OprQdQm
  | 0b101100011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTA dt OD.OprQdQm
  | 0b001100000u | 0b001100001u | 0b001100010u | 0b001100011u | 0b111100000u
  | 0b111100001u | 0b111100010u | 0b111100011u (* size = 00 or 11 *) ->
    raise UndefinedException
  (* xx11001xx VCVTN *)
  | 0b011100100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTN dt OD.OprDdDm
  | 0b101100100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTN dt OD.OprDdDm
  | 0b011100110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTN dt OD.OprDdDm
  | 0b101100110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTN dt OD.OprDdDm
  | 0b011100101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTN dt OD.OprQdQm
  | 0b101100101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTN dt OD.OprQdQm
  | 0b011100111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTN dt OD.OprQdQm
  | 0b101100111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTN dt OD.OprQdQm
  | 0b001100100u | 0b001100101u | 0b001100110u | 0b001100111u | 0b111100100u
  | 0b111100101u | 0b111100110u | 0b111100111u (* size = 00 or 11 *) ->
    raise UndefinedException
  (* xx11010xx VCVTP *)
  | 0b011101000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTP dt OD.OprDdDm
  | 0b101101000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTP dt OD.OprDdDm
  | 0b011101010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTP dt OD.OprDdDm
  | 0b101101010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTP dt OD.OprDdDm
  | 0b011101001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTP dt OD.OprQdQm
  | 0b101101001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTP dt OD.OprQdQm
  | 0b011101011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTP dt OD.OprQdQm
  | 0b101101011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTP dt OD.OprQdQm
  | 0b001101000u | 0b001101001u | 0b001101010u | 0b001101011u | 0b111101000u
  | 0b111101001u | 0b111101010u | 0b111101011u (* size = 00 or 11 *) ->
    raise UndefinedException
  (* xx11011xx VCVTM *)
  | 0b011101100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTM dt OD.OprDdDm
  | 0b101101100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTM dt OD.OprDdDm
  | 0b011101110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTM dt OD.OprDdDm
  | 0b101101110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTM dt OD.OprDdDm
  | 0b011101101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVTM dt OD.OprQdQm
  | 0b101101101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVTM dt OD.OprQdQm
  | 0b011101111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp bin Op.VCVTM dt OD.OprQdQm
  | 0b101101111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVTM dt OD.OprQdQm
  | 0b001101100u | 0b001101101u | 0b001101110u | 0b001101111u | 0b111101100u
  | 0b111101101u | 0b111101110u | 0b111101111u (* size = 00 or 11 *) ->
    raise UndefinedException
  (* xx1110x0x VRECPE *)
  | 0b101110000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRECPE (oneDt SIMDTypU32) OD.OprDdDm
  | 0b011110100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRECPE (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101110100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRECPE (oneDt SIMDTypF32) OD.OprDdDm
  | 0b101110001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRECPE (oneDt SIMDTypU32) OD.OprQdQm
  | 0b011110101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRECPE (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101110101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRECPE (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001110000u | 0b001110001u | 0b001110100u | 0b001110101u | 0b111110000u
  | 0b111110001u | 0b111110100u | 0b111110101u (* size = 00 or 11 *) ->
    raise UndefinedException
  (* xx1110x1x VRSQRTE *)
  | 0b101110010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRSQRTE (oneDt SIMDTypU32) OD.OprDdDm
  | 0b011110110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRSQRTE (oneDt SIMDTypF16) OD.OprDdDm
  | 0b101110110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRSQRTE (oneDt SIMDTypF32) OD.OprDdDm
  | 0b101110011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRSQRTE (oneDt SIMDTypU32) OD.OprQdQm
  | 0b011110111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRSQRTE (oneDt SIMDTypF16) OD.OprQdQm
  | 0b101110111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRSQRTE (oneDt SIMDTypF32) OD.OprQdQm
  | 0b001110010u | 0b001110011u | 0b001110110u | 0b001110111u | 0b111110010u
  | 0b111110011u | 0b111110110u | 0b111110111u (* size = 00 or 11 *) ->
    raise UndefinedException
  | 0b111011001u -> raise ParsingFailureException
  (* xx1111xxx VCVT *)
  | 0b011111000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypS16)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b011111010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypU16)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b011111100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b011111110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b101111000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b101111010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b101111100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b101111110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprDdDm
  | 0b011111001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypS16)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b011111011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypU16)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b011111101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b011111111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b101111001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b101111011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b101111101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b101111111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp bin Op.VCVT dt OD.OprQdQm
  | 0b001111000u | 0b001111001u | 0b001111010u | 0b001111011u | 0b001111100u
  | 0b001111101u | 0b001111110u | 0b001111111u (* size = 00 *) ->
    raise UndefinedException
  | 0b111111000u | 0b111111001u | 0b111111010u | 0b111111011u | 0b111111100u
  | 0b111111101u | 0b111111110u | 0b111111111u (* size = 11 *) ->
    raise UndefinedException
  | _ -> raise ParsingFailureException

/// Advanced SIMD duplicate (scalar) on page F4-4268.
let parseAdvSIMDDupScalar (phlp: ParsingHelper) bin =
  match pickThree bin 7 (* opc *) with
  | 0b000u ->
    let dt = getDTImm4 (pickFour bin 16) |> oneDt
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdDmx else OD.OprQdDmx
    render phlp bin Op.VDUP dt oprs
  | _ (* 001 or 01x or 1xx *) -> raise ParsingFailureException

/// Advanced SIMD three registers of different lengths on page F4-4268.
let parseAdvSIMDThreeRegsDiffLen (phlp: ParsingHelper) bin =
  match concat (pickBit bin 24) (pickFour bin 8) 4 (* U:opc *) with
  | 0b00000u | 0b10000u (* x0000 *) ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkVdOpVn bin
#endif
    render phlp bin Op.VADDL dt OD.OprQdDnDm
  | 0b00001u | 0b10001u (* x0001 *) ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkVdOpVn bin
#endif
    render phlp bin Op.VADDW dt OD.OprQdQnDm
  | 0b00010u | 0b10010u (* x0010 *) ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkVdOpVn bin
#endif
    render phlp bin Op.VSUBL dt OD.OprQdDnDm
  | 0b00100u ->
    let dt = getDTInt (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkVnVm bin
#endif
    render phlp bin Op.VADDHN dt OD.OprDdQnQm
  | 0b00011u | 0b10011u (* x0011 *) ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkVdOpVn bin
#endif
    render phlp bin Op.VSUBW dt OD.OprQdQnDm
  | 0b00110u ->
    let dt = getDTInt (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkVnVm bin
#endif
    render phlp bin Op.VSUBHN dt OD.OprDdQnQm
  | 0b01001u ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkSzVd bin
#endif
    render phlp bin Op.VQDMLAL dt OD.OprQdDnDm
  | 0b00101u | 0b10101u (* x0101 *) ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkVd0 bin
#endif
    render phlp bin Op.VABAL dt OD.OprQdDnDm
  | 0b01011u ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkSzVd bin
#endif
    render phlp bin Op.VQDMLSL dt OD.OprQdDnDm
  | 0b01101u ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkSzVd bin
#endif
    render phlp bin Op.VQDMULL dt OD.OprQdDnDm
  | 0b00111u | 0b10111u (* x0111 *) ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkVd0 bin
#endif
    render phlp bin Op.VABDL dt OD.OprQdDnDm
  | 0b01000u | 0b11000u (* x1000 *) ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkVd0 bin
#endif
    render phlp bin Op.VMLAL dt OD.OprQdDnDm
  | 0b01010u | 0b11010u (* x1010 *) ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkVd0 bin
#endif
    render phlp bin Op.VMLSL dt OD.OprQdDnDm
  | 0b10100u ->
    let dt = getDTInt (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkVnVm bin
#endif
    render phlp bin Op.VRADDHN dt OD.OprDdQnQm
  | 0b10110u ->
    let dt = getDTInt (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkVnVm bin
#endif
    render phlp bin Op.VRSUBHN dt OD.OprDdQnQm
  | 0b01100u | 0b01110u | 0b11100u | 0b11110u (* x11x0 *) ->
    let dt = getDTPolyA bin |> oneDt
#if !EMULATION
    chkVd0 bin
#endif
    render phlp bin Op.VMULL dt OD.OprQdDnDm
  | 0b11001u -> raise ParsingFailureException
  | 0b11011u -> raise ParsingFailureException
  | 0b11101u -> raise ParsingFailureException
  | _ (* x1111 *) -> raise ParsingFailureException

/// Advanced SIMD two registers and a scalar on page F4-4269.
let parseAdvSIMDTRegsAndScalar (phlp: ParsingHelper) bin =
  match concat (pickBit bin 24) (pickFour bin 8) 4 (* Q:opc *) with
  | 0b00000u ->
    let dt = getDTF0 (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VMLA dt OD.OprDdDnDmx
  | 0b00001u ->
    let dt = getDTF1 (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VMLA dt OD.OprDdDnDmx
  | 0b10000u ->
    let dt = getDTF0 (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VMLA dt OD.OprQdQnDmx
  | 0b10001u ->
    let dt = getDTF1 (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VMLA dt OD.OprQdQnDmx
  | 0b00011u ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkSzVd bin
#endif
    render phlp bin Op.VQDMLAL dt OD.OprQdDnDmx
  | 0b00010u | 0b10010u (* x0010 *) ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkSzVd bin
#endif
    render phlp bin Op.VMLAL dt OD.OprQdDnDmx
  | 0b00111u ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkSzVd bin
#endif
    render phlp bin Op.VQDMLSL dt OD.OprQdDnDmx
  | 0b00100u ->
    let dt = getDTF0 (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VMLS dt OD.OprDdDnDmx
  | 0b00101u ->
    let dt = getDTF1 (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VMLS dt OD.OprDdDnDmx
  | 0b10100u ->
    let dt = getDTF0 (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VMLS dt OD.OprQdQnDmx
  | 0b10101u ->
    let dt = getDTF1 (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VMLS dt OD.OprQdQnDmx
  | 0b01011u ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkSzVd bin
#endif
    render phlp bin Op.VQDMULL dt OD.OprQdDnDmx
  | 0b00110u | 0b10110u (* x0110 *) ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkSzVd bin
#endif
    render phlp bin Op.VMLSL dt OD.OprQdDnDmx
  | 0b01000u ->
    let dt = getDTF0 (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VMUL dt OD.OprDdDnDmx
  | 0b01001u ->
    let dt = getDTF1 (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VMUL dt OD.OprDdDnDmx
  | 0b11000u ->
    let dt = getDTF0 (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VMUL dt OD.OprQdQnDmx
  | 0b11001u ->
    let dt = getDTF1 (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VMUL dt OD.OprQdQnDmx
  | 0b10011u -> raise ParsingFailureException
  | 0b01010u | 0b11010u (* x1010 *) ->
    let dt = getDtA bin |> oneDt
#if !EMULATION
    chkSzVd bin
#endif
    render phlp bin Op.VMULL dt OD.OprQdDnDmx
  | 0b10111u -> raise ParsingFailureException
  | 0b01100u ->
    let dt = getDTSign (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VQDMULH dt OD.OprDdDnDmx
  | 0b11100u ->
    let dt = getDTSign (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VQDMULH dt OD.OprQdQnDmx
  | 0b01101u ->
    let dt = getDTSign (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VQRDMULH dt OD.OprDdDnDmx
  | 0b11101u ->
    let dt = getDTSign (pickTwo bin 20) |> oneDt
#if !EMULATION
    chkSzQVdVn bin
#endif
    render phlp bin Op.VQRDMULH dt OD.OprQdQnDmx
  | 0b11011u -> raise ParsingFailureException
  | 0b01110u -> (* Armv8.1 *)
#if !EMULATION
    chkQVdVnSz bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp bin Op.VQRDMLAH dt OD.OprDdDnDmx
  | 0b11110u -> (* Armv8.1 *)
#if !EMULATION
    chkQVdVnSz bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp bin Op.VQRDMLAH dt OD.OprQdQnDmx
  | 0b01111u -> (* Armv8.1 *)
#if !EMULATION
    chkQVdVnSz bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp bin Op.VQRDMLSH dt OD.OprDdDnDmx
  | 0b11111u -> (* Armv8.1 *)
#if !EMULATION
    chkQVdVnSz bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp bin Op.VQRDMLSH dt OD.OprQdQnDmx
  | _ -> raise ParsingFailureException

/// Advanced SIMD two registers, or three registers of different lengths
/// on page F4-4265.
let parseAdvSIMDTwoThreeRegsDiffLen (phlp: ParsingHelper) bin =
  let decodeField = (* op0:op1:op2:op3 *)
    (pickBit bin 24 <<< 5) + (pickTwo bin 20 <<< 3) +
    (pickTwo bin 10 <<< 1) + (pickBit bin 6)
  match decodeField (* op0:op1:op2:op3 *) with
  | 0b011000u | 0b011010u | 0b011100u | 0b011110u (* 011xx0 *) ->
#if !EMULATION
    chkQVdImm bin
#endif
    render phlp bin Op.VEXT (oneDt SIMDTyp8) OD.OprDdDnDmImm
  | 0b011001u | 0b011011u | 0b011101u | 0b011111u (* 011xx1 *) ->
#if !EMULATION
    chkQVdImm bin
#endif
    render phlp bin Op.VEXT (oneDt SIMDTyp8) OD.OprQdQnQmImm
  | 0b111000u | 0b111001u | 0b111010u | 0b111011u (* 1110xx *) ->
    parseAdvaSIMDTwoRegsMisc phlp bin
  | 0b111100u ->
#if !EMULATION
    chkPCRnLen bin
#endif
    render phlp bin Op.VTBL (oneDt SIMDTyp8) OD.OprDdListDm
  | 0b111101u ->
#if !EMULATION
    chkPCRnLen bin
#endif
    render phlp bin Op.VTBX (oneDt SIMDTyp8) OD.OprDdListDm
  | 0b111110u | 0b111111u (* 11111x *) ->
    parseAdvSIMDDupScalar phlp bin
  | b when (b &&& 0b000001u = 0b000000u) && (pickTwo bin 20 <> 0b11u) ->
    (* x != 11 xx0 *) parseAdvSIMDThreeRegsDiffLen phlp bin
  | _ (* x != 11 xx1 *) -> parseAdvSIMDTRegsAndScalar phlp bin

/// Advanced SIMD one register and modified immediate on page F4-4271.
let parseAdvSIMDOneRegAndModImm (phlp: ParsingHelper) bin =
  match concat (pickFour bin 8) (pickBit bin 5) 1 (* cmode:op *) with
  | 0b00000u | 0b00100u | 0b01000u | 0b01100u (* 0xx00 *) ->
    let dt = Some (OneDT SIMDTypI32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm32A else OD.OprQdImm32A
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VMOV dt oprFn
  | 0b00001u | 0b00101u | 0b01001u | 0b01101u (* 0xx01 *) ->
    let dt = Some (OneDT SIMDTypI32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm32A else OD.OprQdImm32A
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VMVN dt oprFn
  | 0b00010u | 0b00110u | 0b01010u | 0b01110u (* 0xx10 *) ->
    let dt = Some (OneDT SIMDTypI32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm32A else OD.OprQdImm32A
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VORR dt oprFn
  | 0b00011u | 0b00111u | 0b01011u | 0b01111u (* 0xx11 *) ->
    let dt = Some (OneDT SIMDTypI32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm32A else OD.OprQdImm32A
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VBIC dt oprFn
  | 0b10000u | 0b10100u (* 10x00 *) ->
    let dt = Some (OneDT SIMDTypI16)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm16A else OD.OprQdImm16A
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VMOV dt oprFn
  | 0b10001u | 0b10101u (* 10x01 *) ->
    let dt = Some (OneDT SIMDTypI16)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm16A else OD.OprQdImm16A
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VMVN dt oprFn
  | 0b10010u | 0b10110u (* 10x10 *) ->
    let dt = Some (OneDT SIMDTypI16)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm16A else OD.OprQdImm16A
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VORR dt oprFn
  | 0b10011u | 0b10111u (* 10x11 *) ->
    let dt = Some (OneDT SIMDTypI16)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm16A else OD.OprQdImm16A
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VBIC dt oprFn
  (* 11xx0 VMOV (immediate) - A4 *)
  | 0b11000u | 0b11010u ->
    let dt = Some (OneDT SIMDTypI32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm32A else OD.OprQdImm32A
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VMOV dt oprFn
  | 0b11100u ->
    let dt = Some (OneDT SIMDTypI8)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm8A else OD.OprQdImm8A
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VMOV dt oprFn
  | 0b11110u ->
    let dt = Some (OneDT SIMDTypF32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImmF32A else OD.OprQdImmF32A
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VMOV dt oprFn
  | 0b11001u | 0b11011u (* 110x1 *) ->
    let dt = Some (OneDT SIMDTypI32)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm32A else OD.OprQdImm32A
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VMVN dt oprFn
  | 0b11101u ->
    let dt = Some (OneDT SIMDTypI64)
    let oprFn = if pickBit bin 6 = 0u then OD.OprDdImm64A else OD.OprQdImm64A
#if !EMULATION
    chkQVd bin
#endif
    render phlp bin Op.VMOV dt oprFn
  | _ (* 11111 *) -> raise ParsingFailureException

/// Advanced SIMD two registers and shift amount on page F4-4271.
let parseAdvSIMDTwoRegsAndShfAmt (phlp: ParsingHelper) bin =
  (* imm3H:L *)
  if concat (pickThree bin 19) (pickBit bin 7) 1 <> 0b0000u then ()
  else raise ParsingFailureException
  let decodeField = (* U:opc:Q *)
    concat (concat (pickBit bin 24) (pickFour bin 8) 4) (pickBit bin 6) 1
  match decodeField (* U:opc:Q *) with
  | 0b000000u | 0b100000u (* x00000 *) ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VSHR (getDTLImmA bin) OD.OprDdDmImm
  | 0b000001u | 0b100001u (* x00001 *) ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VSHR (getDTLImmA bin) OD.OprQdQmImm
  | 0b000010u | 0b100010u (* x00010 *) ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VSRA (getDTLImmA bin) OD.OprDdDmImm
  | 0b000011u | 0b100011u (* x00011 *) ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VSRA (getDTLImmA bin) OD.OprQdQmImm
  | 0b010100u | 0b110100u (* x10100 *)
    when pickThree bin 16 = 0b000u (* imm3L *) ->
    (* if Vd<0> == '1' then UNDEFINED *)
    pickBit bin 12 = 1u |> checkUndef (* Vd<0> *)
    render phlp bin Op.VMOVL (getDTUImm3hA bin) OD.OprQdDm
  | 0b000100u | 0b100100u (* x00100 *) ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRSHR (getDTLImmA bin) OD.OprDdDmImm
  | 0b000101u | 0b100101u (* x00101 *) ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRSHR (getDTLImmA bin) OD.OprQdQmImm
  | 0b000110u | 0b100110u (* x00110 *) ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRSRA (getDTLImmA bin) OD.OprDdDmImm
  | 0b000111u | 0b100111u (* x00111 *) ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VRSRA (getDTLImmA bin) OD.OprQdQmImm
  | 0b001110u | 0b101110u (* x01110 *) ->
#if !EMULATION
    chkUOpQVdVm bin
#endif
    render phlp bin Op.VQSHL (getDTLImmA bin) OD.OprDdDmImmLeft
  | 0b001111u | 0b101111u (* x01111 *) ->
#if !EMULATION
    chkUOpQVdVm bin
#endif
    render phlp bin Op.VQSHL (getDTLImmA bin) OD.OprQdQmImmLeft
  | 0b010010u | 0b110010u (* x10010 *) ->
    (* if Vm<0> == '1' then UNDEFINED *)
    checkUndef (pickBit bin 0 = 1u)
    render phlp bin Op.VQSHRN (getDTImm6WordA bin) OD.OprDdQmImm
  | 0b010011u | 0b110011u (* x10011 *) ->
    (* if Vm<0> == '1' then UNDEFINED *)
    pickBit bin 0 = 1u |> checkUndef
    render phlp bin Op.VQRSHRN (getDTImm6WordA bin) OD.OprDdQmImm
  | 0b010100u | 0b110100u (* x10100 *) ->
    (* if Vd<0> == '1' then UNDEFINED *)
    pickBit bin 12 = 1u |> checkUndef
    render phlp bin Op.VSHLL (getDTImm6ByteA bin) OD.OprQdDmImm
  | b when b &&& 0b011000u = 0b011000u (* x11xxx *) ->
#if !EMULATION
    chkOpImm6QVdVm bin
#endif
    let dt1 =
      match concat (pickTwo bin 8) (pickBit bin 24) 1 (* op:U *) with
      | 0b000u | 0b001u (* 00x *) -> SIMDTypF16
      | 0b010u -> SIMDTypS16
      | 0b011u -> SIMDTypU16
      | 0b100u | 0b101u (* 10x *) -> SIMDTypF32
      | 0b110u -> SIMDTypS32
      | _ (* 111 *) -> SIMDTypU32
    let dt2 =
      match concat (pickTwo bin 8) (pickBit bin 24) 1 (* op:U *) with
      | 0b000u -> SIMDTypS16
      | 0b001u -> SIMDTypU16
      | 0b010u | 0b011u (* 01x *) -> SIMDTypF16
      | 0b100u -> SIMDTypS32
      | 0b101u -> SIMDTypU32
      | _ (* 11x *) -> SIMDTypF32
    let oprFn =
      if pickBit bin 6 = 0u (* Q *) then OD.OprDdDmFbits else OD.OprQdQmFbits
    render phlp bin Op.VCVT (twoDt (dt1, dt2)) oprFn
  | 0b001010u | 0b001011u (* 00101x *) ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = (* L:imm6<5:3> *)
      match concat (pickBit bin 7) (pickThree bin 19) 3 with
      | 0b0000u -> raise ParsingFailureException
      | 0b0001u -> SIMDTypI8
      | 0b0010u | 0b0011u (* 001x *) -> SIMDTypI16
      | 0b0100u | 0b0101u | 0b0110u | 0b0111u (* 01xx *) -> SIMDTypI32
      | _ (* 1xxx *) -> SIMDTypI64
      |> oneDt
    let oprFn =
      if pickBit bin 6 = 0u (* Q *) then OD.OprDdDmImmLeft
      else OD.OprQdQmImmLeft
    render phlp bin Op.VSHL dt oprFn
  | 0b010000u ->
    (* if Vm<0> == '1' then UNDEFINED *)
    pickBit bin 0 = 1u |> checkUndef (* Vm<0> *)
    render phlp bin Op.VSHRN (getDTImm6Int bin) OD.OprDdQmImm
  | 0b010001u ->
    (* if Vm<0> == '1' then UNDEFINED *)
    pickBit bin 0 = 1u |> checkUndef (* Vm<0> *)
    render phlp bin Op.VRSHRN (getDTImm6Int bin) OD.OprDdQmImm
  | 0b101000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VSRI (getDTImm6 bin) OD.OprDdDmImm
  | 0b101001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VSRI (getDTImm6 bin) OD.OprQdQmImm
  | 0b101010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VSLI (getDTImm6 bin) OD.OprDdDmImmLeft
  | 0b101011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    render phlp bin Op.VSLI (getDTImm6 bin) OD.OprQdQmImmLeft
  | 0b101100u ->
#if !EMULATION
    chkUOpQVdVm bin
#endif
    render phlp bin Op.VQSHLU (getDTLImmA bin) OD.OprDdDmImmLeft
  | 0b101101u ->
#if !EMULATION
    chkUOpQVdVm bin
#endif
    render phlp bin Op.VQSHLU (getDTLImmA bin) OD.OprQdQmImmLeft
  | 0b110000u ->
    (* if Vm<0> == '1' then UNDEFINED *)
    pickBit bin 0 = 1u |> checkUndef (* Vm<0> *)
    render phlp bin Op.VQSHRUN (getDTImm6Sign bin) OD.OprDdQmImm
  | 0b110001u ->
    (* if Vm<0> == '1' then UNDEFINED *)
    pickBit bin 0 = 1u |> checkUndef (* Vm<0> *)
    render phlp bin Op.VQRSHRUN (getDTImm6Sign bin) OD.OprDdQmImm
  | _ -> raise ParsingFailureException

/// Advanced SIMD shifts and immediate generation on page F4-4270.
let parseAdvSIMDShfAndImmGen (phlp: ParsingHelper) bin =
  if extract bin 21 7 &&& 0b111000000000001u = 0b0u (* 000xxxxxxxxxxx0 *) then
    parseAdvSIMDOneRegAndModImm phlp bin
  else (* != 000xxxxxxxxxxx0 *)
    parseAdvSIMDTwoRegsAndShfAmt phlp bin

/// Advanced SIMD data-processing on page F4-4262.
let parseAdvSIMDDataProc (phlp: ParsingHelper) bin =
  match pickTwoBitsApart bin 23 4 (* op0:op1 *) with
  | 0b00u | 0b01u (* 0x *) ->
    parseAdvSIMDThreeRegsSameLen phlp bin
  | 0b10u -> parseAdvSIMDTwoThreeRegsDiffLen phlp bin
  | _ (* 11 *) -> parseAdvSIMDShfAndImmGen phlp bin

/// Barriers on page F4-4273.
let parseBarriers (phlp: ParsingHelper) bin =
  let option = pickFour bin 0
  match pickFour bin 4 (* opcode *) with
  | 0b0000u -> raise UnpredictableException
  | 0b0001u -> render phlp bin Op.CLREX None OD.OprNo
  | 0b0010u | 0b0011u -> raise UnpredictableException
  | 0b0100u when (option <> 0b0000u) || (option <> 0b0100u) ->
    render phlp bin Op.DSB None OD.OprOpt
  | 0b0100u when option = 0b0000u ->
    render phlp bin Op.SSBB None OD.OprNo
  | 0b0100u when option = 0b0100u ->
    render phlp bin Op.PSSBB None OD.OprNo
  | 0b0101u -> render phlp bin Op.DMB None OD.OprOpt
  | 0b0110u -> render phlp bin Op.ISB None OD.OprOpt
  | 0b0111u -> render phlp bin Op.SB None OD.OprNo
  | _ (* 1xxx *) -> raise UnpredictableException

/// Preload (immediate) on page F4-4273.
let parsePreloadImm (phlp: ParsingHelper) bin =
  let isRn1111 bin = pickFour bin 16 = 0b1111u
  match pickTwoBitsApart bin 24 22 (* D:R *) with
  | 0b00u -> render phlp bin Op.NOP None OD.OprNo
  | 0b01u -> render phlp bin Op.PLI None OD.OprLabel12A
  | 0b10u | 0b11u when isRn1111 bin ->
    render phlp bin Op.PLD None OD.OprLabel12A
  | 0b10u (* != 1111 *) -> render phlp bin Op.PLDW None OD.OprMemImm
  | _ (* 0b11u != 1111 *) -> render phlp bin Op.PLD None OD.OprMemImm

/// Preload (register) on page F4-4274.
let parsePreloadReg (phlp: ParsingHelper) bin =
  match pickTwoBitsApart bin 24 22 (* D:o2 *) with
  | 0b00u -> render phlp bin Op.NOP None OD.OprNo
  | 0b01u ->
#if !EMULATION
    chkPCRm bin
#endif
    render phlp bin Op.PLI None OD.OprMemRegA
  | 0b10u ->
#if !EMULATION
    chkPCRmRnPldw bin
#endif
    render phlp bin Op.PLDW None OD.OprMemRegA
  | _ (* 11 *) ->
#if !EMULATION
    chkPCRmRnPldw bin
#endif
    render phlp bin Op.PLD None OD.OprMemRegA

/// Memory hints and barriers on page F4-4272.
let parseMemoryHintsAndBarriers (phlp: ParsingHelper) bin =
  match concat (pickFive bin 21) (pickBit bin 4) 1 (* op0:op1 *) with
  | b when b &&& 0b110010u = 0b000010u (* 00xx1x *) ->
    raise UnpredictableException
  | 0b010010u | 0b010011u (* 01001x *) -> raise UnpredictableException
  | 0b010110u | 0b010111u (* 01011x *) -> parseBarriers phlp bin
  | 0b011010u | 0b011011u | 0b011110u | 0b011111u (* 011x1x *) ->
    raise UnpredictableException
  | b when b &&& 0b100010u = 0b000000u (* 0xxx0x *) ->
    parsePreloadImm phlp bin
  | b when b &&& 0b100011u = 0b100000u (* 1xxx00 *) ->
    parsePreloadReg phlp bin
  | b when b &&& 0b100011u = 0b100010u (* 1xxx10 *) ->
    raise UnpredictableException
  | _ (* 1xxxx1 *) -> raise ParsingFailureException

/// Advanced SIMD load/store multiple structures on page F4-4275.
let parseAdvSIMDLdStMulStruct (phlp: ParsingHelper) bin =
  match concat (pickBit bin 21) (pickFour bin 8) 4 (* L:itype *) with
  | 0b00000u | 0b00001u (* 0000x *) ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkSzPCRnD4 bin
#endif
    render phlp bin Op.VST4 dt OD.OprListMem
  | 0b00010u ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkPCRnDregs bin
#endif
    render phlp bin Op.VST1 dt OD.OprListMem
  | 0b00011u ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkPCRnD2regs bin
#endif
    render phlp bin Op.VST2 dt OD.OprListMem
  | 0b00100u | 0b00101u (* 0010x *) ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkPCRnD3 bin
#endif
    render phlp bin Op.VST3 dt OD.OprListMem
  | 0b00110u ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkAlign1PCRnDregs bin 3u
#endif
    render phlp bin Op.VST1 dt OD.OprListMem
  | 0b00111u ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkAlign1PCRnDregs bin 1u
#endif
    render phlp bin Op.VST1 dt OD.OprListMem
  | 0b01000u | 0b01001u (* 0100x *) ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkAlignPCRnD2regs bin
#endif
    render phlp bin Op.VST2 dt OD.OprListMem
  | 0b01010u ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkAlignPCRnDregs bin
#endif
    render phlp bin Op.VST1 dt OD.OprListMem
  | 0b10000u | 0b10001u (* 1000x *) ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkSzPCRnD4 bin
#endif
    render phlp bin Op.VLD4 dt OD.OprListMem
  | 0b10010u ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkPCRnDregs bin
#endif
    render phlp bin Op.VLD1 dt OD.OprListMem
  | 0b10011u ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkPCRnD2regs bin
#endif
    render phlp bin Op.VLD2 dt OD.OprListMem
  | 0b10100u | 0b10101u (* 1010x *) ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkPCRnD3 bin
#endif
    render phlp bin Op.VLD3 dt OD.OprListMem
  | 0b01011u | 0b11011u (* x1011 *) -> raise ParsingFailureException
  | 0b10110u ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkAlign1PCRnDregs bin 3u
#endif
    render phlp bin Op.VLD1 dt OD.OprListMem
  | 0b10111u ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkAlign1PCRnDregs bin 1u
#endif
    render phlp bin Op.VLD1 dt OD.OprListMem
  | 0b01100u | 0b01101u | 0b01110u | 0b01111u | 0b11100u | 0b11101u | 0b11110u
  | 0b11111u (* x11xx *) -> raise ParsingFailureException
  | 0b11000u | 0b11001u (* 1100x *) ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkAlignPCRnD2regs bin
#endif
    render phlp bin Op.VLD2 dt OD.OprListMem
  | 0b11010u ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkAlignPCRnDregs bin
#endif
    render phlp bin Op.VLD1 dt OD.OprListMem
  | _ -> raise ParsingFailureException

/// Advanced SIMD load single structure to all lanes on page F4-4276.
let parseAdvSIMDLdSingleStructAllLanes (phlp: ParsingHelper) bin =
  let decodeField = (* L:N:a *)
    (pickBit bin 21 <<< 3) + (pickTwo bin 8 <<< 1) +
    (pickBit bin 4)
  match decodeField with
  | b when b &&& 0b1000u = 0b0000u (* 0xxx *) -> raise ParsingFailureException
  | 0b1000u | 0b1001u (* 100x *) ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkSzAPCRnDregs bin
#endif
    render phlp bin Op.VLD1 dt OD.OprListMem1
  | 0b1010u | 0b1011u (* 101x *) ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkSzPCRnD2 bin
#endif
    render phlp bin Op.VLD2 dt OD.OprListMem2
  | 0b1100u ->
    let dt = getDT64 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkSzAPCRnD3 bin
#endif
    render phlp bin Op.VLD3 dt OD.OprListMem3
  | 0b1101u -> raise ParsingFailureException
  | _ (* 111x *) ->
    let dt = getDT32 (pickTwo bin 6) |> oneDt
#if !EMULATION
    chkSzAPCRnD4 bin
#endif
    render phlp bin Op.VLD4 dt OD.OprListMem4

/// Advanced SIMD load/store single structure to one lane on page F4-4276.
let parseAdvSIMDLdStSingleStructOneLane (phlp: ParsingHelper) bin =
  match concat (pickBit bin 21) (pickFour bin 8) 4 (* L:size:N *) with
  | 0b00000u ->
#if !EMULATION
    chkSzIdx0PCRn bin
#endif
    render phlp bin Op.VST1 (oneDt SIMDTyp8) OD.OprListMemA
  | 0b00001u ->
#if !EMULATION
    chkPCRnD2 bin
#endif
    render phlp bin Op.VST2 (oneDt SIMDTyp8) OD.OprListMemB
  | 0b00010u ->
#if !EMULATION
    chkIdx0PCRnD3 bin
#endif
    render phlp bin Op.VST3 (oneDt SIMDTyp8) OD.OprListMemC
  | 0b00011u ->
#if !EMULATION
    chkPCRnD4 bin
#endif
    render phlp bin Op.VST4 (oneDt SIMDTyp8) OD.OprListMemD
  | 0b00100u ->
#if !EMULATION
    chkSzIdx1PCRn bin
#endif
    render phlp bin Op.VST1 (oneDt SIMDTyp16) OD.OprListMemA
  | 0b00101u ->
#if !EMULATION
    chkPCRnD2 bin
#endif
    render phlp bin Op.VST2 (oneDt SIMDTyp16) OD.OprListMemB
  | 0b00110u ->
#if !EMULATION
    chkIdx0PCRnD3 bin
#endif
    render phlp bin Op.VST3 (oneDt SIMDTyp16) OD.OprListMemC
  | 0b00111u ->
#if !EMULATION
    chkPCRnD4 bin
#endif
    render phlp bin Op.VST4 (oneDt SIMDTyp16) OD.OprListMemD
  | 0b01000u ->
#if !EMULATION
    chkSzIdx2PCRn bin
#endif
    render phlp bin Op.VST1 (oneDt SIMDTyp32) OD.OprListMemA
  | 0b01001u ->
#if !EMULATION
    chkIdxPCRnD2 bin
#endif
    render phlp bin Op.VST2 (oneDt SIMDTyp32) OD.OprListMemB
  | 0b01010u ->
#if !EMULATION
    chkIdx10PCRnD3 bin
#endif
    render phlp bin Op.VST3 (oneDt SIMDTyp32) OD.OprListMemC
  | 0b01011u ->
#if !EMULATION
    chkIdxPCRnD4 bin
#endif
    render phlp bin Op.VST4 (oneDt SIMDTyp32) OD.OprListMemD
  | 0b10000u ->
#if !EMULATION
    chkSzIdx0PCRn bin
#endif
    render phlp bin Op.VLD1 (oneDt SIMDTyp8) OD.OprListMemA
  | 0b10001u ->
#if !EMULATION
    chkPCRnD2 bin
#endif
    render phlp bin Op.VLD2 (oneDt SIMDTyp8) OD.OprListMemB
  | 0b10010u ->
#if !EMULATION
    chkIdx0PCRnD3 bin
#endif
    render phlp bin Op.VLD3 (oneDt SIMDTyp8) OD.OprListMemC
  | 0b10011u ->
#if !EMULATION
    chkPCRnD4 bin
#endif
    render phlp bin Op.VLD4 (oneDt SIMDTyp8) OD.OprListMemD
  | 0b10100u ->
#if !EMULATION
    chkSzIdx1PCRn bin
#endif
    render phlp bin Op.VLD1 (oneDt SIMDTyp16) OD.OprListMemA
  | 0b10101u ->
#if !EMULATION
    chkPCRnD2 bin
#endif
    render phlp bin Op.VLD2 (oneDt SIMDTyp16) OD.OprListMemB
  | 0b10110u ->
#if !EMULATION
    chkIdx0PCRnD3 bin
#endif
    render phlp bin Op.VLD3 (oneDt SIMDTyp16) OD.OprListMemC
  | 0b10111u ->
#if !EMULATION
    chkPCRnD4 bin
#endif
    render phlp bin Op.VLD4 (oneDt SIMDTyp16) OD.OprListMemD
  | 0b11000u ->
#if !EMULATION
    chkSzIdx2PCRn bin
#endif
    render phlp bin Op.VLD1 (oneDt SIMDTyp32) OD.OprListMemA
  | 0b11001u ->
#if !EMULATION
    chkIdxPCRnD2 bin
#endif
    render phlp bin Op.VLD2 (oneDt SIMDTyp32) OD.OprListMemB
  | 0b11010u ->
#if !EMULATION
    chkIdx10PCRnD3 bin
#endif
    render phlp bin Op.VLD3 (oneDt SIMDTyp32) OD.OprListMemC
  | 0b11011u ->
#if !EMULATION
    chkIdxPCRnD4 bin
#endif
    render phlp bin Op.VLD4 (oneDt SIMDTyp32) OD.OprListMemD
  | _ -> raise ParsingFailureException

/// Advanced SIMD element or structure load/store on page F4-4274.
let parseAdvSIMDElemOrStructLdSt (phlp: ParsingHelper) bin =
  match concat (pickBit bin 23) (pickTwo bin 10) 2 (* op0:op1 *) with
  | 0b000u | 0b001u | 0b010u | 0b011u (* 0xx *) ->
    parseAdvSIMDLdStMulStruct phlp bin
  | 0b111u -> parseAdvSIMDLdSingleStructAllLanes phlp bin
  | _ (* 1 !=11 *) -> parseAdvSIMDLdStSingleStructOneLane phlp bin

/// Unconditional instructions on page F4-4261.
let parseUncondInstr (phlp: ParsingHelper) bin =
  match concat (pickTwo bin 25) (pickBit bin 20) 1 (* op0:op1 *) with
  | 0b000u | 0b001u -> parseUncondMiscellaneous phlp bin
  | 0b010u | 0b011u -> parseAdvSIMDDataProc phlp bin
  | 0b101u | 0b111u -> parseMemoryHintsAndBarriers phlp bin
  | 0b100u -> parseAdvSIMDElemOrStructLdSt phlp bin
  | _ (* 0b110u *) -> raise ParsingFailureException

/// Parse ARMv8 (AARCH32) and ARMv7 ARM mode instructions. The code is based on
/// ARM Architecture Reference Manual ARMv8-A, ARM DDI 0487F.c ID072120 A32
/// instruction set encoding on page F4-4218.
let parse (phlp: ParsingHelper) bin =
  let cond = pickFour bin 28 |> byte |> parseCond
  phlp.Cond <- cond
  phlp.IsAdd <- true
  match pickTwo bin 26 (* op0<2:1> *) with
  | 0b00u when cond <> Condition.UN -> parseCase00 phlp bin
  | 0b01u when cond <> Condition.UN -> parseCase01 phlp bin
  | 0b10u -> parseCase10 phlp bin
  | 0b11u -> parseCase11 phlp bin
  | _ (* 0b0xu *) -> parseUncondInstr phlp bin

// vim: set tw=80 sts=2 sw=2:
