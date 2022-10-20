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

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ARM32.ParseUtils
open B2R2.FrontEnd.BinLifter.ARM32.OperandHelper
#if !EMULATION
open B2R2.FrontEnd.BinLifter.ARM32.ARMValidator
#endif
open OperandParsingHelper

type BL = byte list

let render (phlp: ParsingHelper) (itstate: byref<BL>) it isInIT bin op dt q o =
  let struct (oprs, wback, cflags, oSz) = phlp.OprParsers.[int o].Render bin
  if isInIT then updateITSTATE &itstate else ()
  ARM32Instruction (phlp.InsAddr, phlp.Len, phlp.Cond, op, oprs,
                    (byte it), wback, q, dt, phlp.Mode, cflags, oSz, phlp.IsAdd)

/// Add, subtract (three low registers) on page F3-4153.
let parseAddSubThreeLowReg (phlp: ParsingHelper) (itstate: byref<BL>) isInIT b =
  match pickBit b 9 (* S *) with
  | 0b0u ->
    let op =
      if inITBlock itstate then Op.ADD
      else phlp.Cond <- Condition.UN; Op.ADDS
    render phlp &itstate 0 isInIT b op None N OD.OprRdRnRmT16
  | _ (* 1 *) ->
    let op =
      if inITBlock itstate then Op.SUB
      else phlp.Cond <- Condition.UN; Op.SUBS
    render phlp &itstate 0 isInIT b op None N OD.OprRdRnRmT16

/// Add, subtract (two low registers and immediate) on page F3-4153.
let parseAddSubTwoLRegsImm (phlp: ParsingHelper) (itstate: byref<BL>) isInIT b =
  match pickBit b 9 (* S *) with
  | 0b0u ->
    let op =
      if inITBlock itstate then Op.ADD
      else phlp.Cond <- Condition.UN; Op.ADDS
    render phlp &itstate 0 isInIT b op None N OD.OprRdRnImm3
  | _ (* 1 *) ->
    let op =
      if inITBlock itstate then Op.SUB
      else phlp.Cond <- Condition.UN; Op.SUBS
    render phlp &itstate 0 isInIT b op None N OD.OprRdRnImm3

/// Add, subtract, compare, move (one low register and imm) on page F3-4153.
let parseAddSubCmpMov phlp (itstate: byref<BL>) isInIT bin =
  match pickTwo bin 11 (* op *) with
  | 0b00u ->
    let opcode = if inITBlock itstate then Op.MOV else Op.MOVS
    render phlp &itstate 0 isInIT bin opcode None N OD.OprRdImm8
  | 0b01u ->
    render phlp &itstate 0 isInIT bin Op.CMP None N OD.OprRdImm8
  | 0b10u ->
    let opcode = if inITBlock itstate then Op.ADD else Op.ADDS
    render phlp &itstate 0 isInIT bin opcode None N OD.OprRdnImm8
  | _ (* 11 *) ->
    let opcode = if inITBlock itstate then Op.SUB else Op.SUBS
    render phlp &itstate 0 isInIT bin opcode None N OD.OprRdnImm8

/// Shift (immediate), add, subtract, move, and compare on page F3-4152.
let parseShfImmAddSubMovCmp phlp (itstate: byref<BL>) isInIT bin =
  match pickFour bin 10 (* op0:op1:op2 *) with
  | 0b0110u (* 0110 *) ->
    parseAddSubThreeLowReg phlp &itstate isInIT bin
  | 0b0111u (* 0111 *) ->
    parseAddSubTwoLRegsImm phlp &itstate isInIT bin
  | 0b0000u | 0b0001u | 0b0010u | 0b0011u | 0b0100u | 0b0101u (* 0 !=11 x *) ->
    let op = pickTwo bin 11
    let imm5 = pickFive bin 6
    let inITBlock = inITBlock itstate
    checkUnpred (op = 0b00u && imm5 = 0u && inITBlock)
    /// Alias conditions on page F5-4557.
    let struct (opcode, operands) =
      if op = 0b10u && not inITBlock then struct (Op.ASRS, OD.OprRdRmImmT16)
      elif op = 0b10u && inITBlock then struct (Op.ASR, OD.OprRdRmImmT16)
      elif op = 0b00u && imm5 <> 0u && not inITBlock
        then struct (Op.LSLS, OD.OprRdRmImmT16)
      elif op = 0b00u && imm5 <> 0u && inITBlock
        then struct (Op.LSL, OD.OprRdRmImmT16)
      elif op = 0b01u && not inITBlock then struct (Op.LSRS, OD.OprRdRmImmT16)
      elif op = 0b01u && inITBlock then struct (Op.LSR, OD.OprRdRmImmT16)
      else if inITBlock then struct (Op.MOV, OD.OprRdRmShfT16)
           else phlp.Cond <- Condition.UN; struct (Op.MOVS, OD.OprRdRmShfT16)
    render phlp &itstate 0 isInIT bin opcode None N operands
  | _ (* 1xxx *) -> parseAddSubCmpMov phlp &itstate isInIT bin

/// Data-processing (two low registers) on page F3-4149.
let parseDataProc (phlp: ParsingHelper) (itstate: byref<BL>) isInIT bin =
  match pickFour bin 6 (* op *) with
  | 0b0000u ->
    let op =
      if inITBlock itstate then Op.AND
      else phlp.Cond <- Condition.UN; Op.ANDS
    render phlp &itstate 0 isInIT bin op None N OD.OprRdnRdnRm
  | 0b0001u ->
    let op =
      if inITBlock itstate then Op.EOR
      else phlp.Cond <- Condition.UN; Op.EORS
    render phlp &itstate 0 isInIT bin op None N OD.OprRdnRdnRm
  | 0b0010u ->
    let op =
      if inITBlock itstate then Op.MOV
      else phlp.Cond <- Condition.UN; Op.MOVS
    render phlp &itstate 0 isInIT bin op None N OD.OprRdmRdmLSLRs
  | 0b0011u ->
    let op =
      if inITBlock itstate then Op.MOV
      else phlp.Cond <- Condition.UN; Op.MOVS
    render phlp &itstate 0 isInIT bin op None N OD.OprRdmRdmLSRRs
  | 0b0100u ->
    let op =
      if inITBlock itstate then Op.MOV
      else phlp.Cond <- Condition.UN; Op.MOVS
    render phlp &itstate 0 isInIT bin op None N OD.OprRdmRdmASRRs
  | 0b0101u ->
    let op =
      if inITBlock itstate then Op.ADC
      else phlp.Cond <- Condition.UN; Op.ADCS
    render phlp &itstate 0 isInIT bin op None N OD.OprRdnRdnRm
  | 0b0110u ->
    let op =
      if inITBlock itstate then Op.SBC
      else phlp.Cond <- Condition.UN; Op.SBCS
    render phlp &itstate 0 isInIT bin op None N OD.OprRdnRdnRm
  | 0b0111u ->
    let op =
      if inITBlock itstate then Op.MOV
      else phlp.Cond <- Condition.UN; Op.MOVS
    render phlp &itstate 0 isInIT bin op None N OD.OprRdmRdmRORRs
  | 0b1000u ->
    render phlp &itstate 0 isInIT bin Op.TST None N OD.OprRnRm
  | 0b1001u ->
    let op =
      if inITBlock itstate then Op.RSB
      else phlp.Cond <- Condition.UN; Op.RSBS
    render phlp &itstate 0 isInIT bin op None N OD.OprRdRn0
  | 0b1010u ->
    render phlp &itstate 0 isInIT bin Op.CMP None N OD.OprRnRm
  | 0b1011u ->
    render phlp &itstate 0 isInIT bin Op.CMN None N OD.OprRnRm
  | 0b1100u ->
    let op =
      if inITBlock itstate then Op.ORR
      else phlp.Cond <- Condition.UN; Op.ORRS
    render phlp &itstate 0 isInIT bin op None N OD.OprRdnRdnRm
  | 0b1101u ->
    let op =
      if inITBlock itstate then Op.MUL
      else phlp.Cond <- Condition.UN; Op.MULS
    render phlp &itstate 0 isInIT bin op None N OD.OprRdmRnRdm
  | 0b1110u ->
    let op =
      if inITBlock itstate then Op.BIC
      else phlp.Cond <- Condition.UN; Op.BICS
    render phlp &itstate 0 isInIT bin op None N OD.OprRdnRdnRm
  | _ (* 1111 *) ->
    let op =
      if inITBlock itstate then Op.MVN
      else phlp.Cond <- Condition.UN; Op.MVNS
    render phlp &itstate 0 isInIT bin op None N OD.OprRdRmT16

/// Branch and exchange on page F3-4154.
let parseBranchAndExchange phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 7 (* L *) with
  | 0b0u ->
#if !EMULATION
    chkInITLastIT itstate
#endif
    render phlp &itstate 0 isInIT bin Op.BX None N OD.OprRmT16
  | _ (* 1 *) ->
#if !EMULATION
    chkPCRmIT16 bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.BLX None N OD.OprRmT16

/// Add, subtract, compare, move (two high registers) on page F3-4154.
let parseAddSubCmpMovTwoHRegs phlp (itstate: byref<BL>) isInIT bin =
  let isDRd1101 = concat (pickBit bin 7) (pickThree bin 0) 3 = 0b1101u
  let isRs1101 = pickFour bin 3 = 0b1101u
  match pickTwo bin 8 (* op *) with
  | 0b00u when not isDRd1101 && not isRs1101 ->
#if !EMULATION
    chkPCRnRmRdIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.ADD None N OD.OprRdnRm
  | 0b00u when isRs1101 ->
#if !EMULATION
    chkPCRdIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.ADD None N OD.OprRdmSPRdm
  | 0b00u when isDRd1101 && not isRs1101 ->
    render phlp &itstate 0 isInIT bin Op.ADD None N OD.OprSPSPRm
  | 0b01u ->
#if !EMULATION
    chkNMPCRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.CMP None N OD.OprRnRmExt
  | 0b10u ->
#if !EMULATION
    chkPCDRdIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.MOV None N OD.OprRdRmExt
  | _ -> raise ParsingFailureException

/// Special data instructions and branch and exchange on page F3-4154.
let parseSpecDataInsBrXchg phlp (itstate: byref<BL>) isInIT bin =
  match pickTwo bin 8 (* op0 *) with
  | 0b11u -> parseBranchAndExchange phlp &itstate isInIT bin
  | _ (* != 11 *) ->
    parseAddSubCmpMovTwoHRegs phlp &itstate isInIT bin

/// Load/store (register offset) on page F3-4150.
let parseLoadStoreRegOffset phlp (itstate: byref<BL>) isInIT bin =
  match pickThree bin 9 (* L:B:H *) with
  | 0b000u ->
    render phlp &itstate 0 isInIT bin Op.STR None N OD.OprRtMemReg16
  | 0b001u ->
    render phlp &itstate 0 isInIT bin Op.STRH None N OD.OprRtMemReg16
  | 0b010u ->
    render phlp &itstate 0 isInIT bin Op.STRB None N OD.OprRtMemReg16
  | 0b011u ->
    render phlp &itstate 0 isInIT bin Op.LDRSB None N OD.OprRtMemReg16
  | 0b100u ->
    render phlp &itstate 0 isInIT bin Op.LDR None N OD.OprRtMemReg16
  | 0b101u ->
    render phlp &itstate 0 isInIT bin Op.LDRH None N OD.OprRtMemReg16
  | 0b110u ->
    render phlp &itstate 0 isInIT bin Op.LDRB None N OD.OprRtMemReg16
  | _ (* 111 *) ->
    render phlp &itstate 0 isInIT bin Op.LDRSH None N OD.OprRtMemReg16

/// Load/store word/byte (immediate offset) on page F3-4150.
let parseLdStWordByteImmOff phlp (itstate: byref<BL>) isInIT bin =
  match pickTwo bin 11 (* B:L *) with
  | 0b00u ->
    render phlp &itstate 0 isInIT bin Op.STR None N OD.OprRtMemImm2
  | 0b01u ->
    render phlp &itstate 0 isInIT bin Op.LDR None N OD.OprRtMemImm2
  | 0b10u ->
    render phlp &itstate 0 isInIT bin Op.STRB None N OD.OprRtMemImm0T
  | _ (* 11 *) ->
    render phlp &itstate 0 isInIT bin Op.LDRB None N OD.OprRtMemImm0T

/// Load/store halfword (immediate offset) on page F3-4151.
let parseLdStHalfwordImmOff phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 11 (* L *) with
  | 0b0u ->
    render phlp &itstate 0 isInIT bin Op.STRH None N OD.OprRtMemImm1
  | _ (* 1 *) ->
    render phlp &itstate 0 isInIT bin Op.LDRH None N OD.OprRtMemImm1

/// Load/store (SP-relative) on page F3-4151.
let parseLdStSPRelative phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 11 (* L *) with
  | 0b0u ->
    render phlp &itstate 0 isInIT bin Op.STR None N OD.OprRtMemSP
  | _ (* 1 *) ->
    render phlp &itstate 0 isInIT bin Op.LDR None N OD.OprRtMemSP

/// Add PC/SP (immediate) on page F3-4151.
let parseAddPCSPImm (phlp: ParsingHelper) (itstate: byref<BL>) isInIT bin =
  match pickBit bin 11 (* SP *) with
  | 0b0u ->
    phlp.IsAdd <- true
    render phlp &itstate 0 isInIT bin Op.ADR None N OD.OprRtLabelT
  | _ (* 1 *) ->
    render phlp &itstate 0 isInIT bin Op.ADD None N OD.OprRdSPImm8

/// Adjust SP (immediate) on page F3-4156.
let parseAdjustSPImm phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 7 (* S *) with
  | 0b0u ->
    render phlp &itstate 0 isInIT bin Op.ADD None N OD.OprSPSPImm7
  | _ (* 1 *) ->
    render phlp &itstate 0 isInIT bin Op.SUB None N OD.OprSPSPImm7

/// Extend on page F3-4156.
let parseExtend phlp (itstate: byref<BL>) isInIT bin =
  match pickTwo bin 6 (* U:B *) with
  | 0b00u ->
    render phlp &itstate 0 isInIT bin Op.SXTH None N OD.OprRdRmT16
  | 0b01u ->
    render phlp &itstate 0 isInIT bin Op.SXTB None N OD.OprRdRmT16
  | 0b10u ->
    render phlp &itstate 0 isInIT bin Op.UXTH None N OD.OprRdRmT16
  | _ (* 11 *) ->
    render phlp &itstate 0 isInIT bin Op.UXTB None N OD.OprRdRmT16

/// Change Processor State on page F3-4156.
let parseChgProcStateT16 (phlp: ParsingHelper) (itstate: byref<BL>) isInIT bin =
  phlp.Cond <- Condition.UN
  match pickBit bin 5 (* op *) with
  | 0b0u ->
    inITBlock itstate |> checkUnpred
    render phlp &itstate 0 isInIT bin Op.SETEND None N OD.OprEndianT
  | _ (* 1 *) ->
#if !EMULATION
    chkAIFIT bin itstate
#endif
    let opcode = if pickBit bin 4 = 1u then Op.CPSID else Op.CPSIE
    render phlp &itstate 0 isInIT bin opcode None N OD.OprIflagsT16

/// Miscellaneous 16-bit instructions on page F3-4155.
let parseMisc16BitInstr0110 phlp (itstate: byref<BL>) isInIT bin =
  match pickThree bin 5 (* op1:op2 *) with
  | 0b000u -> (* Armv8.1 *)
    inITBlock itstate |> checkUnpred
    render phlp &itstate 0 isInIT bin Op.SETPAN None N OD.OprImm1T
  | 0b001u -> raise ParsingFailureException
  | 0b010u | 0b011u ->
    parseChgProcStateT16 phlp &itstate isInIT bin
  | _ (* 1xx *) -> raise ParsingFailureException

/// Reverse bytes on page F3-4157.
let parseReverseBytes phlp (itstate: byref<BL>) isInIT bin =
  match pickTwo bin 6 (* op *) with
  | 0b00u ->
    render phlp &itstate 0 isInIT bin Op.REV None N OD.OprRdRmT16
  | 0b01u ->
    render phlp &itstate 0 isInIT bin Op.REV16 None N OD.OprRdRmT16
  | 0b11u ->
    render phlp &itstate 0 isInIT bin Op.REVSH None N OD.OprRdRmT16
  | _ (* 10 *) -> raise ParsingFailureException

/// Hints on page F3-4157.
let parseHints16 phlp (itstate: byref<BL>) isInIT bin =
  match pickFour bin 4 (* hint *) with
  | 0b0000u ->
    render phlp &itstate 0 isInIT bin Op.NOP None N OD.OprNo
  | 0b0001u ->
    render phlp &itstate 0 isInIT bin Op.YIELD None N OD.OprNo
  | 0b0010u ->
    render phlp &itstate 0 isInIT bin Op.WFE None N OD.OprNo
  | 0b0011u ->
    render phlp &itstate 0 isInIT bin Op.WFI None N OD.OprNo
  | 0b0100u ->
    render phlp &itstate 0 isInIT bin Op.SEV None N OD.OprNo
  | 0b0101u ->
    render phlp &itstate 0 isInIT bin Op.SEVL None N OD.OprNo
  | _ (* 011x | 1xxx *) -> (* Reserved hint, behaves as NOP *)
    render phlp &itstate 0 isInIT bin Op.NOP None N OD.OprNo

/// Push and Pop on page F3-4158.
let parsePushAndPop phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 11 (* L *) with
  | 0b0u ->
    concat (pickBit bin 8 <<< 6) (extract bin 7 0) 8 (* registers *) = 0u
    |> checkUnpred
    render phlp &itstate 0 isInIT bin Op.PUSH None N OD.OprRegsM
  | _ (* 1 *) ->
#if !EMULATION
    chkRegsIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.POP None N OD.OprRegsP

/// Miscellaneous 16-bit instructions on page F3-4155.
let parseMisc16BitInstr phlp (itstate: byref<BL>) isInIT bin =
  match pickFour bin 8 (* op0 *) with
  | 0b0000u -> parseAdjustSPImm phlp &itstate isInIT bin
  | 0b0010u -> parseExtend phlp &itstate isInIT bin
  | 0b0110u -> parseMisc16BitInstr0110 phlp &itstate isInIT bin
  | 0b0111u -> raise ParsingFailureException
  | 0b1000u -> raise ParsingFailureException
  | 0b1010u when pickTwo bin 6 = 0b10u ->
    render phlp &itstate 0 isInIT bin Op.HLT None N OD.OprImm6
  | 0b1010u (* != 10 *) -> parseReverseBytes phlp &itstate isInIT bin
  | 0b1110u ->
    phlp.Cond <- Condition.UN
    render phlp &itstate 0 isInIT bin Op.BKPT None N OD.OprImm8
  | 0b1111u when pickFour bin 0 = 0b0000u ->
    parseHints16 phlp &itstate isInIT bin
  | 0b1111u (* != 0000 *) ->
#if !EMULATION
    chkFstCondIT bin itstate
#endif
    let fstCond = pickFour bin 4
    phlp.Cond <- Condition.UN
    let op, itstate' =
      getIT (pickBit fstCond 0) (byte fstCond) (pickFour bin 0 (* mask *))
    itstate <- itstate'
    render phlp &itstate (int bin) isInIT bin op None N OD.OprCondition
  | 0b1001u | 0b1011u ->
    inITBlock itstate |> checkUnpred
    phlp.Cond <- Condition.UN
    render phlp &itstate 0 isInIT bin Op.CBNZ None N OD.OprRnLabel
  | 0b0001u | 0b0011u ->
    inITBlock itstate |> checkUnpred
    phlp.Cond <- Condition.UN
    render phlp &itstate 0 isInIT bin Op.CBZ None N OD.OprRnLabel
  | _ (* x10x *) -> parsePushAndPop phlp &itstate isInIT bin

/// Load/store multiple on page F3-4152.
let parseLoadStoreMul phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 11 (* L *) with
  | 0b0u ->
    extract bin 7 0 (* register_list *) = 0u |> checkUnpred
    render phlp &itstate 0 isInIT bin Op.STM (* {IA} *) None N OD.OprRnRegsT16
  | _ (* 1 *) ->
    extract bin 7 0 (* register_list *) = 0u |> checkUnpred
    render phlp &itstate 0 isInIT bin Op.LDM (* {IA} *) None N OD.OprRnRegsW

/// Exception generation on page F3-4158.
let parseExceptionGen phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 8 (* S *) with
  | 0b0u ->
    render phlp &itstate 0 isInIT bin Op.UDF None N OD.OprImm8
  | _ (* 1 *) ->
    render phlp &itstate 0 isInIT bin Op.SVC None N OD.OprImm8

/// Conditional branch, and Supervisor Call on page F3-4158.
let parseCondBrSVCall phlp (itstate: byref<BL>) isInIT bin =
  match pickFour bin 8 (* op0 *) with
  | 0b1110u | 0b1111u -> parseExceptionGen phlp &itstate isInIT bin
  | _ (* != 111x *) ->
    inITBlock itstate |> checkUnpred
    phlp.Cond <- pickFour bin 8 |> byte |> parseCond
    render phlp &itstate 0 isInIT bin Op.B None N OD.OprLabel8

/// 16-bit on page F3-4148.
let parse16Bit phlp (itstate: byref<BL>) isInIT bin =
  match extract bin 15 10 (* op0 *) with
  | b when b &&& 0b110000u = 0b000000u (* 00xxxx *) ->
    parseShfImmAddSubMovCmp phlp &itstate isInIT bin
  | 0b010000u -> parseDataProc phlp &itstate isInIT bin
  | 0b010001u ->
    parseSpecDataInsBrXchg phlp &itstate isInIT bin
  | 0b010010u | 0b010011u (* 01001x *) ->
    render phlp &itstate 0 isInIT bin Op.LDR None N OD.OprRtLabelT
  | 0b010100u | 0b010101u | 0b010110u | 0b010111u (* 0101xx *) ->
    parseLoadStoreRegOffset phlp &itstate isInIT bin
  | b when b &&& 0b111000u = 0b011000u (* 011xxx *) ->
    parseLdStWordByteImmOff phlp &itstate isInIT bin
  | 0b100000u| 0b100001u | 0b100010u | 0b100011u (* 1000xx *) ->
    parseLdStHalfwordImmOff phlp &itstate isInIT bin
  | 0b100100u| 0b100101u | 0b100110u | 0b100111u (* 1001xx *) ->
    parseLdStSPRelative phlp &itstate isInIT bin
  | 0b101000u| 0b101001u | 0b101010u | 0b101011u (* 1010xx *) ->
    parseAddPCSPImm phlp &itstate isInIT bin
  | 0b101100u| 0b101101u | 0b101110u | 0b101111u (* 1011xx *) ->
    parseMisc16BitInstr phlp &itstate isInIT bin
  | 0b110000u| 0b110001u | 0b110010u | 0b110011u (* 1100xx *) ->
    parseLoadStoreMul phlp &itstate isInIT bin
  | 0b110100u| 0b110101u | 0b110110u | 0b110111u (* 1101xx *) ->
    parseCondBrSVCall phlp &itstate isInIT bin
  | _ -> raise ParsingFailureException

/// Advanced SIMD three registers of the same length on page F3-4165.
let parseAdvSIMDThreeRegsOfSameLen phlp (itstate: byref<BL>) isInIT b =
  let decodeFields (* U:size:opc:Q:o1 *) =
    (pickBit b 28 <<< 8) + (pickTwo b 20 <<< 6) + (pickFour b 8 <<< 2) +
    (pickBit b 6 <<< 1) + pickBit b 4
  match decodeFields with
  (* VFMA 00x1100x1 *)
  | 0b000110001u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VFMA (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b000110011u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VFMA (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b001110001u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VFMA (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b001110011u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VFMA (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VADD 00x1101x0 *)
  | 0b000110100u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VADD (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b000110110u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VADD (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b001110100u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VADD (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b001110110u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VADD (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VMLA 00x1101x1 *)
  | 0b000110101u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMLA (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b000110111u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMLA (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b001110101u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMLA (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b001110111u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMLA (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VCEQ 00x1110x0 *)
  | 0b000111000u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b000111010u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b001111000u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b001111010u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VMAX 00x1111x0 *)
  | 0b000111100u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b000111110u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b001111100u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b001111110u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VRECPS 00x1111x1 *)
  | 0b000111101u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRECPS (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b000111111u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRECPS (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b001111101u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRECPS (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b001111111u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRECPS (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VHADD xxx0000x0 *)
  | 0b011000000u | 0b011000010u | 0b111000000u | 0b111000010u (* x110000x0 *) ->
    raise UndefinedException
  | 0b000000000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHADD (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b001000000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHADD (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010000000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHADD (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b100000000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHADD (oneDt SIMDTypU8) N OD.OprDdDnDm
  | 0b101000000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHADD (oneDt SIMDTypU16) N OD.OprDdDnDm
  | 0b110000000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHADD (oneDt SIMDTypU32) N OD.OprDdDnDm
  | 0b000000010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHADD (oneDt SIMDTypS8) N OD.OprQdQnQm
  | 0b001000010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHADD (oneDt SIMDTypS16) N OD.OprQdQnQm
  | 0b010000010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHADD (oneDt SIMDTypS32) N OD.OprQdQnQm
  | 0b100000010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHADD (oneDt SIMDTypU8) N OD.OprQdQnQm
  | 0b101000010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHADD (oneDt SIMDTypU16) N OD.OprQdQnQm
  | 0b110000010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHADD (oneDt SIMDTypU32) N OD.OprQdQnQm
  (* VAND 0000001x1 *)
  | 0b000000101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VAND None N OD.OprDdDnDm
  | 0b000000111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VAND None N OD.OprQdQnQm
  (* VQADD xxx0000x1 *)
  | 0b000000001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b001000001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010000001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b011000001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypS64) N OD.OprDdDnDm
  | 0b100000001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypU8) N OD.OprDdDnDm
  | 0b101000001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypU16) N OD.OprDdDnDm
  | 0b110000001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypU32) N OD.OprDdDnDm
  | 0b111000001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypU64) N OD.OprDdDnDm
  | 0b000000011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypS8) N OD.OprQdQnQm
  | 0b001000011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypS16) N OD.OprQdQnQm
  | 0b010000011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypS32) N OD.OprQdQnQm
  | 0b011000011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypS64) N OD.OprQdQnQm
  | 0b100000011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypU8) N OD.OprQdQnQm
  | 0b101000011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypU16) N OD.OprQdQnQm
  | 0b110000011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypU32) N OD.OprQdQnQm
  | 0b111000011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQADD (oneDt SIMDTypU64) N OD.OprQdQnQm
  (* VRHADD xxx0001x0 *)
  | 0b011000100u | 0b011000110u | 0b111000100u | 0b111000110u (* x110001x *) ->
    raise UndefinedException
  | 0b000000100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRHADD (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b001000100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRHADD (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010000100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRHADD (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b100000100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRHADD (oneDt SIMDTypU8) N OD.OprDdDnDm
  | 0b101000100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRHADD (oneDt SIMDTypU16) N OD.OprDdDnDm
  | 0b110000100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRHADD (oneDt SIMDTypU32) N OD.OprDdDnDm
  | 0b000000110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRHADD (oneDt SIMDTypS8) N OD.OprQdQnQm
  | 0b001000110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRHADD (oneDt SIMDTypS16) N OD.OprQdQnQm
  | 0b010000110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRHADD (oneDt SIMDTypS32) N OD.OprQdQnQm
  | 0b100000110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRHADD (oneDt SIMDTypU8) N OD.OprQdQnQm
  | 0b101000110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRHADD (oneDt SIMDTypU16) N OD.OprQdQnQm
  | 0b110000110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRHADD (oneDt SIMDTypU32) N OD.OprQdQnQm
  (* SHA1C 0001100x0 *)
  | 0b000110000u (* Q != 1 *) -> raise UndefinedException
  | 0b000110010u ->
#if !EMULATION
    chkITVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.SHA1C (oneDt SIMDTyp32) N OD.OprQdQnQm
  (* VHSUB xxx0010x0 *)
  | 0b011001000u | 0b011001010u | 0b111001000u | 0b111001010u (* x110010x0 *) ->
    raise UndefinedException
  | 0b000001000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHSUB (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b001001000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHSUB (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010001000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHSUB (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b100001000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHSUB (oneDt SIMDTypU8) N OD.OprDdDnDm
  | 0b101001000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHSUB (oneDt SIMDTypU16) N OD.OprDdDnDm
  | 0b110001000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHSUB (oneDt SIMDTypU32) N OD.OprDdDnDm
  | 0b000001010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHSUB (oneDt SIMDTypS8) N OD.OprQdQnQm
  | 0b001001010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHSUB (oneDt SIMDTypS16) N OD.OprQdQnQm
  | 0b010001010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHSUB (oneDt SIMDTypS32) N OD.OprQdQnQm
  | 0b100001010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHSUB (oneDt SIMDTypU8) N OD.OprQdQnQm
  | 0b101001010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHSUB (oneDt SIMDTypU16) N OD.OprQdQnQm
  | 0b110001010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VHSUB (oneDt SIMDTypU32) N OD.OprQdQnQm
  (* VBIC 0010001x1 *)
  | 0b001000101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VBIC None N OD.OprDdDnDm
  | 0b001000111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VBIC None N OD.OprQdQnQm
  (* VQSUB xxx0010x1 *)
  | 0b000001001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b001001001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010001001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b011001001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypS64) N OD.OprDdDnDm
  | 0b100001001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypU8) N OD.OprDdDnDm
  | 0b101001001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypU16) N OD.OprDdDnDm
  | 0b110001001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypU32) N OD.OprDdDnDm
  | 0b111001001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypU64) N OD.OprDdDnDm
  | 0b000001011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypS8) N OD.OprQdQnQm
  | 0b001001011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypS16) N OD.OprQdQnQm
  | 0b010001011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypS32) N OD.OprQdQnQm
  | 0b011001011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypS64) N OD.OprQdQnQm
  | 0b100001011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypU8) N OD.OprQdQnQm
  | 0b101001011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypU16) N OD.OprQdQnQm
  | 0b110001011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypU32) N OD.OprQdQnQm
  | 0b111001011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSUB (oneDt SIMDTypU64) N OD.OprQdQnQm
  (* VCGT xxx0011x0 *)
  | 0b011001100u | 0b011001110u | 0b111001100u | 0b111001110u (* x110011x0 *) ->
    raise UndefinedException
  | 0b000001100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b001001100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010001100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b100001100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypU8) N OD.OprDdDnDm
  | 0b101001100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypU16) N OD.OprDdDnDm
  | 0b110001100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypU32) N OD.OprDdDnDm
  | 0b000001110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypS8) N OD.OprQdQnQm
  | 0b001001110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypS16) N OD.OprQdQnQm
  | 0b010001110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypS32) N OD.OprQdQnQm
  | 0b100001110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypU8) N OD.OprQdQnQm
  | 0b101001110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypU16) N OD.OprQdQnQm
  | 0b110001110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypU32) N OD.OprQdQnQm
  (* VCGE xxx0011x1 *)
  | 0b011001101u | 0b011001111u | 0b111001101u | 0b111001111u (* xxx0011x1 *) ->
    raise UndefinedException
  | 0b000001101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b001001101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010001101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b100001101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypU8) N OD.OprDdDnDm
  | 0b101001101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypU16) N OD.OprDdDnDm
  | 0b110001101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypU32) N OD.OprDdDnDm
  | 0b000001111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypS8) N OD.OprQdQnQm
  | 0b001001111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypS16) N OD.OprQdQnQm
  | 0b010001111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypS32) N OD.OprQdQnQm
  | 0b100001111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypU8) N OD.OprQdQnQm
  | 0b101001111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypU16) N OD.OprQdQnQm
  | 0b110001111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypU32) N OD.OprQdQnQm
  (* SHA1P 0011100x0 *)
  | 0b001110000u (* Q != 1 *) -> raise UndefinedException
  | 0b001110010u ->
#if !EMULATION
    chkITVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.SHA1P (oneDt SIMDTyp32) N OD.OprQdQnQm
  (* VFMS 01x1100x1 *)
  | 0b010110001u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VFMS (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b010110011u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VFMS (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b011110001u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VFMS (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b011110011u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VFMS (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VSUB 01x1101x0 *)
  | 0b010110100u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VSUB (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b010110110u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VSUB (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b011110100u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VSUB (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b011110110u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VSUB (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VMLS 01x1101x1 *)
  | 0b010110101u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMLS (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b010110111u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMLS (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b011110101u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMLS (oneDt SIMDTypF16) N OD.OprQdQnQm
  | 0b011110111u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMLS (oneDt SIMDTypF16) N OD.OprQdQnQm
  | b when b &&& 0b110111101u = 0b010111000u (* 0b01x1110x0u *) ->
    raise ParsingFailureException
  (* VMIN 01x1111x0 *)
  | 0b010111100u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b010111110u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b011111100u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypF16) N OD.OprQdQnQm
  | 0b011111110u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VRSQRTS 01x1111x1 *)
  | 0b010111101u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRSQRTS (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b010111111u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRSQRTS (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b011111101u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRSQRTS (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b011111111u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRSQRTS (oneDt SIMDTypF32) N OD.OprDdDnDm
  (* VSHL xxx0100x0 *)
  | 0b000010000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypS8) N OD.OprDdDmDn
  | 0b001010000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypS16) N OD.OprDdDmDn
  | 0b010010000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypS32) N OD.OprDdDmDn
  | 0b011010000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypS64) N OD.OprDdDmDn
  | 0b100010000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypU8) N OD.OprDdDmDn
  | 0b101010000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypU16) N OD.OprDdDmDn
  | 0b110010000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypU32) N OD.OprDdDmDn
  | 0b111010000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypU64) N OD.OprDdDmDn
  | 0b000010010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypS8) N OD.OprQdQmQn
  | 0b001010010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypS16) N OD.OprQdQmQn
  | 0b010010010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypS32) N OD.OprQdQmQn
  | 0b011010010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypS64) N OD.OprQdQmQn
  | 0b100010010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypU8) N OD.OprQdQmQn
  | 0b101010010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypU16) N OD.OprQdQmQn
  | 0b110010010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypU32) N OD.OprQdQmQn
  | 0b111010010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHL (oneDt SIMDTypU64) N OD.OprQdQmQn
  (* VADD 0xx1000x0 *)
  | 0b000100000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VADD (oneDt SIMDTypI8)  N OD.OprDdDnDm
  | 0b001100000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VADD (oneDt SIMDTypI16) N OD.OprDdDnDm
  | 0b010100000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VADD (oneDt SIMDTypI32) N OD.OprDdDnDm
  | 0b011100000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VADD (oneDt SIMDTypI64) N OD.OprDdDnDm
  | 0b000100010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VADD (oneDt SIMDTypI8)  N OD.OprQdQnQm
  | 0b001100010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VADD (oneDt SIMDTypI16) N OD.OprQdQnQm
  | 0b010100010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VADD (oneDt SIMDTypI32) N OD.OprQdQnQm
  | 0b011100010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VADD (oneDt SIMDTypI64) N OD.OprQdQnQm
  (* VORR 0100001x1 *)
  | 0b010000101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VORR None N OD.OprDdDnDm
  | 0b010000111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VORR None N OD.OprQdQnQm
  (* VTST 0xx1000x1 *)
  | 0b011100001u | 0b011100011u (* 0111000x1 *) -> raise UndefinedException
  | 0b000100001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VTST (oneDt SIMDTyp8) N OD.OprDdDnDm
  | 0b001100001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VTST (oneDt SIMDTyp16) N OD.OprDdDnDm
  | 0b010100001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VTST (oneDt SIMDTyp32) N OD.OprDdDnDm
  | 0b000100011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VTST (oneDt SIMDTyp8) N OD.OprQdQnQm
  | 0b001100011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VTST (oneDt SIMDTyp16) N OD.OprQdQnQm
  | 0b010100011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VTST (oneDt SIMDTyp32) N OD.OprQdQnQm
  (* VQSHL xxx0100x1 *)
  | 0b000010001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypS8) N OD.OprDdDmDn
  | 0b001010001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypS16) N OD.OprDdDmDn
  | 0b010010001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypS32) N OD.OprDdDmDn
  | 0b011010001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypS64) N OD.OprDdDmDn
  | 0b100010001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypU8) N OD.OprDdDmDn
  | 0b101010001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypU16) N OD.OprDdDmDn
  | 0b110010001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypU32) N OD.OprDdDmDn
  | 0b111010001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypU64) N OD.OprDdDmDn
  | 0b000010011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypS8) N OD.OprQdQmQn
  | 0b001010011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypS16) N OD.OprQdQmQn
  | 0b010010011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypS32) N OD.OprQdQmQn
  | 0b011010011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypS64) N OD.OprQdQmQn
  | 0b100010011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypU8) N OD.OprQdQmQn
  | 0b101010011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypU16) N OD.OprQdQmQn
  | 0b110010011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypU32) N OD.OprQdQmQn
  | 0b111010011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQSHL (oneDt SIMDTypU64) N OD.OprQdQmQn
  (* VMLA 0xx1001x0 *)
  | 0b011100100u | 0b011100110u (* 0111001x0 *)-> raise UndefinedException
  | 0b000100100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMLA (oneDt SIMDTypI8) N OD.OprDdDnDm
  | 0b001100100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMLA (oneDt SIMDTypI16) N OD.OprDdDnDm
  | 0b010100100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMLA (oneDt SIMDTypI32) N OD.OprDdDnDm
  | 0b000100110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMLA (oneDt SIMDTypI8) N OD.OprQdQnQm
  | 0b001100110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMLA (oneDt SIMDTypI16) N OD.OprQdQnQm
  | 0b010100110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMLA (oneDt SIMDTypI32) N OD.OprQdQnQm
  (* VRSHL xxx0101x0 *)
  | 0b000010100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypS8) N OD.OprDdDmDn
  | 0b001010100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypS16) N OD.OprDdDmDn
  | 0b010010100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypS32) N OD.OprDdDmDn
  | 0b011010100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypS64) N OD.OprDdDmDn
  | 0b100010100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypU8) N OD.OprDdDmDn
  | 0b101010100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypU16) N OD.OprDdDmDn
  | 0b110010100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypU32) N OD.OprDdDmDn
  | 0b111010100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypU64) N OD.OprDdDmDn
  | 0b000010110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypS8) N OD.OprQdQmQn
  | 0b001010110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypS16) N OD.OprQdQmQn
  | 0b010010110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypS32) N OD.OprQdQmQn
  | 0b011010110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypS64) N OD.OprQdQmQn
  | 0b100010110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypU8) N OD.OprQdQmQn
  | 0b101010110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypU16) N OD.OprQdQmQn
  | 0b110010110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypU32) N OD.OprQdQmQn
  | 0b111010110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRSHL (oneDt SIMDTypU64) N OD.OprQdQmQn
  (* VQRSHL xxx0101x1 *)
  | 0b000010101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypS8) N OD.OprDdDmDn
  | 0b001010101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypS16) N OD.OprDdDmDn
  | 0b010010101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypS32) N OD.OprDdDmDn
  | 0b011010101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypS64) N OD.OprDdDmDn
  | 0b100010101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypU8) N OD.OprDdDmDn
  | 0b101010101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypU16) N OD.OprDdDmDn
  | 0b110010101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypU32) N OD.OprDdDmDn
  | 0b111010101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypU64) N OD.OprDdDmDn
  | 0b000010111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypS8) N OD.OprQdQmQn
  | 0b001010111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypS16) N OD.OprQdQmQn
  | 0b010010111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypS32) N OD.OprQdQmQn
  | 0b011010111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypS64) N OD.OprQdQmQn
  | 0b100010111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypU8) N OD.OprQdQmQn
  | 0b101010111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypU16) N OD.OprQdQmQn
  | 0b110010111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypU32) N OD.OprQdQmQn
  | 0b111010111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQRSHL (oneDt SIMDTypU64) N OD.OprQdQmQn
  (* VQDMULH 0xx1011x0 *)
  | 0b000101100u | 0b000101110u | 0b011101100u | 0b011101110u ->
    raise UndefinedException (* size == '00' || size == '11' *)
  | 0b001101100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQDMULH (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010101100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQDMULH (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b001101110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQDMULH (oneDt SIMDTypS16) N OD.OprQdQnQm
  | 0b010101110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQDMULH (oneDt SIMDTypS32) N OD.OprQdQnQm
  (* SHA1M 0101100x0 *)
  | 0b010110000u (* Q != 1 *) -> raise UndefinedException
  | 0b010110010u ->
#if !EMULATION
    chkITVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.SHA1M (oneDt SIMDTyp32) N OD.OprQdQnQm
  (* VPADD 0xx1011x1 *)
  | 0b011101101u | 0b011101111u | 0b000101111u | 0b001101111u | 0b010101111u ->
    raise UndefinedException (* size == '11' || Q == '1' *)
  | 0b000101101u ->
    render phlp &itstate 0 isInIT b Op.VPADD (oneDt SIMDTypI8) N OD.OprDdDnDm
  | 0b001101101u ->
    render phlp &itstate 0 isInIT b Op.VPADD (oneDt SIMDTypI16) N OD.OprDdDnDm
  | 0b010101101u ->
    render phlp &itstate 0 isInIT b Op.VPADD (oneDt SIMDTypI32) N OD.OprDdDnDm
  (* VMAX xxx0110x0 *)
  | 0b011011000u | 0b011011010u | 0b111011000u | 0b111011010u (* x110110x0 *) ->
    raise UndefinedException (* size == '11' *)
  | 0b000011000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b001011000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010011000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b100011000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypU8) N OD.OprDdDnDm
  | 0b101011000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypU16) N OD.OprDdDnDm
  | 0b110011000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypU32) N OD.OprDdDnDm
  | 0b000011010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypS8) N OD.OprQdQnQm
  | 0b001011010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypS16) N OD.OprQdQnQm
  | 0b010011010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypS32) N OD.OprQdQnQm
  | 0b100011010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypU8) N OD.OprQdQnQm
  | 0b101011010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypU16) N OD.OprQdQnQm
  | 0b110011010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMAX (oneDt SIMDTypU32) N OD.OprQdQnQm
  (* VORN 0110001x1 *)
  | 0b011000101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VORN None N OD.OprDdDnDm
  | 0b011000111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VORN None N OD.OprQdQnQm
  (* VMIN xxx0110x1 *)
  | 0b011011001u | 0b011011011u | 0b111011001u | 0b111011011u (* x110110x1 *) ->
    raise UndefinedException (* size == '11' *)
  | 0b000011001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b001011001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010011001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b100011001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypU8) N OD.OprDdDnDm
  | 0b101011001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypU16) N OD.OprDdDnDm
  | 0b110011001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypU32) N OD.OprDdDnDm
  | 0b000011011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypS8) N OD.OprQdQnQm
  | 0b001011011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypS16) N OD.OprQdQnQm
  | 0b010011011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypS32) N OD.OprQdQnQm
  | 0b100011011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypU8) N OD.OprQdQnQm
  | 0b101011011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypU16) N OD.OprQdQnQm
  | 0b110011011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMIN (oneDt SIMDTypU32) N OD.OprQdQnQm
  (* VABD xxx0111x0 *)
  | 0b011011100u | 0b011011110u | 0b111011100u | 0b111011110u (* x110111x0 *) ->
    raise UndefinedException (* size == '11' *)
  | 0b000011100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b001011100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010011100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b100011100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypU8) N OD.OprDdDnDm
  | 0b101011100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypU16) N OD.OprDdDnDm
  | 0b110011100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypU32) N OD.OprDdDnDm
  | 0b000011110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypS8) N OD.OprQdQnQm
  | 0b001011110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypS16) N OD.OprQdQnQm
  | 0b010011110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypS32) N OD.OprQdQnQm
  | 0b100011110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypU8) N OD.OprQdQnQm
  | 0b101011110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypU16) N OD.OprQdQnQm
  | 0b110011110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypU32) N OD.OprQdQnQm
  (* VABA xxx0111x1 *)
  | 0b011011101u | 0b011011111u | 0b111011101u | 0b111011111u (* x110111x1 *) ->
    raise UndefinedException (* size == '11' *)
  | 0b000011101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABA (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b001011101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABA (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010011101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABA (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b100011101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABA (oneDt SIMDTypU8) N OD.OprDdDnDm
  | 0b101011101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABA (oneDt SIMDTypU16) N OD.OprDdDnDm
  | 0b110011101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABA (oneDt SIMDTypU32) N OD.OprDdDnDm
  | 0b000011111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABA (oneDt SIMDTypS8) N OD.OprQdQnQm
  | 0b001011111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABA (oneDt SIMDTypS16) N OD.OprQdQnQm
  | 0b010011111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABA (oneDt SIMDTypS32) N OD.OprQdQnQm
  | 0b100011111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABA (oneDt SIMDTypU8) N OD.OprQdQnQm
  | 0b101011111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABA (oneDt SIMDTypU16) N OD.OprQdQnQm
  | 0b110011111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VABA (oneDt SIMDTypU32) N OD.OprQdQnQm
  (* SHA1SU0 0111100x0 *)
  | 0b011110000u (* Q != '1' *) -> raise UndefinedException
  | 0b011110010u ->
#if !EMULATION
    chkVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.SHA1SU0 (oneDt SIMDTyp32) N OD.OprQdQnQm
  (* VPADD 10x1101x0 *)
  | 0b100110110u | 0b101110110u (* Q == '1' *) -> raise UndefinedException
  | 0b100110100u ->
#if !EMULATION
    chkSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VPADD (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b101110100u ->
#if !EMULATION
    chkSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VPADD (oneDt SIMDTypF16) N OD.OprDdDnDm
  (* VMUL 10x1101x1 *)
  | 0b100110101u ->
#if !EMULATION
    chkSzITQVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMUL (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b100110111u ->
#if !EMULATION
    chkSzITQVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMUL (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b101110101u ->
#if !EMULATION
    chkSzITQVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMUL (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b101110111u ->
#if !EMULATION
    chkSzITQVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMUL (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VCGE 10x1110x0 *)
  | 0b100111000u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b100111010u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b101111000u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b101111010u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VACGE 10x1110x1 *)
  | 0b100111001u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VACGE (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b100111011u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VACGE (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b101111001u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VACGE (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b101111011u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VACGE (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VPMAX 10x111100 *)
  | 0b100111100u ->
#if !EMULATION
    chkSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VPMAX (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b101111100u ->
#if !EMULATION
    chkSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VPMAX (oneDt SIMDTypF16) N OD.OprDdDnDm
  (* VMAXNM 10x1111x1 *)
  | 0b100111101u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMAXNM (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b100111111u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMAXNM (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b101111101u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMAXNM (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b101111111u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMAXNM (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VEOR 1000001x1 *)
  | 0b100000101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VEOR None N OD.OprDdDnDm
  | 0b100000111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VEOR None N OD.OprQdQnQm
  (* VMUL xxx1001x1 *)
  | 0b011100101u | 0b011100111u | 0b111100101u | 0b111100111u (* size == '11' *)
  | 0b101100101u | 0b101100111u | 0b110100101u | 0b110100111u ->
    raise UndefinedException (* op == '1' && size != '00' *)
  | 0b000100101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMUL (oneDt SIMDTypI8) N OD.OprDdDnDm
  | 0b001100101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMUL (oneDt SIMDTypI16) N OD.OprDdDnDm
  | 0b010100101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMUL (oneDt SIMDTypI32) N OD.OprDdDnDm
  | 0b100100101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMUL (oneDt SIMDTypP8) N OD.OprDdDnDm
  | 0b000100111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMUL (oneDt SIMDTypI8) N OD.OprQdQnQm
  | 0b001100111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMUL (oneDt SIMDTypI16) N OD.OprQdQnQm
  | 0b010100111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMUL (oneDt SIMDTypI32) N OD.OprQdQnQm
  | 0b100100111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMUL (oneDt SIMDTypP8) N OD.OprQdQnQm
  (* SHA256H 1001100x0 *)
  | 0b100110000u (* Q != '1' *) -> raise UndefinedException
  | 0b100110010u ->
#if !EMULATION
    chkITVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.SHA256H (oneDt SIMDTyp32) N OD.OprQdQnQm
  (* VPMAX xxx101000 *)
  | 0b011101000u | 0b111101000u (* size == '11' *) -> raise UndefinedException
  | 0b000101000u ->
    render phlp &itstate 0 isInIT b Op.VPMAX (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b001101000u ->
    render phlp &itstate 0 isInIT b Op.VPMAX (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010101000u ->
    render phlp &itstate 0 isInIT b Op.VPMAX (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b100101000u ->
    render phlp &itstate 0 isInIT b Op.VPMAX (oneDt SIMDTypU8) N OD.OprDdDnDm
  | 0b101101000u ->
    render phlp &itstate 0 isInIT b Op.VPMAX (oneDt SIMDTypU16) N OD.OprDdDnDm
  | 0b110101000u ->
    render phlp &itstate 0 isInIT b Op.VPMAX (oneDt SIMDTypU32) N OD.OprDdDnDm
  (* VBSL 1010001x1 *)
  | 0b101000101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VBSL None N OD.OprDdDnDm
  | 0b101000111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VBSL None N OD.OprQdQnQm
  (* VPMIN xxx101001 *)
  | 0b011101001u | 0b111101001u  (* size == '11' *) -> raise UndefinedException
  | 0b000101001u ->
    render phlp &itstate 0 isInIT b Op.VPMIN (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b001101001u ->
    render phlp &itstate 0 isInIT b Op.VPMIN (oneDt SIMDTypS16) N OD.OprDdDnDm
  | 0b010101001u ->
    render phlp &itstate 0 isInIT b Op.VPMIN (oneDt SIMDTypS32) N OD.OprDdDnDm
  | 0b100101001u ->
    render phlp &itstate 0 isInIT b Op.VPMIN (oneDt SIMDTypU8) N OD.OprDdDnDm
  | 0b101101001u ->
    render phlp &itstate 0 isInIT b Op.VPMIN (oneDt SIMDTypU16) N OD.OprDdDnDm
  | 0b110101001u ->
    render phlp &itstate 0 isInIT b Op.VPMIN (oneDt SIMDTypU32) N OD.OprDdDnDm
  | b when b &&& 0b000111110u = 0b000101010u (* 0bxxx10101xu *) ->
    raise ParsingFailureException
  (* SHA256H2 1011100x0 *)
  | 0b101110000u (* Q != '1' *) -> raise UndefinedException
  | 0b101110010u ->
#if !EMULATION
    chkVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.SHA256H2 (oneDt SIMDTyp32) N OD.OprQdQnQm
  (* VABD 11x1101x0 *)
  | 0b110110100u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b110110110u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b111110100u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b111110110u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABD (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VCGT 11x1110x0 *)
  | 0b110111000u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b110111010u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b111111000u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b111111010u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VACGT 11x1110x1 *)
  | 0b110111001u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VACGT (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b110111011u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VACGT (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b111111001u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VACGT (oneDt SIMDTypF16) N OD.OprDdDnDm
  | 0b111111011u ->
#if !EMULATION
    chkQVdVnVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VACGT (oneDt SIMDTypF16) N OD.OprQdQnQm
  (* VPMIN 11x111100 *)
  | 0b110111100u ->
#if !EMULATION
    chkSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VPMIN (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b111111100u ->
#if !EMULATION
    chkSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VPMIN (oneDt SIMDTypF16) N OD.OprDdDnDm
  (* VMINNM 11x1111x1 *)
  | 0b110111101u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMINNM (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b110111111u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMINNM (oneDt SIMDTypF32) N OD.OprQdQnQm
  | 0b111111101u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMINNM (oneDt SIMDTypF32) N OD.OprDdDnDm
  | 0b111111111u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VMINNM (oneDt SIMDTypF32) N OD.OprQdQnQm
  (* VSUB 1xx1000x0 *)
  | 0b100100000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSUB (oneDt SIMDTypI8) N OD.OprDdDnDm
  | 0b101100000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSUB (oneDt SIMDTypI16) N OD.OprDdDnDm
  | 0b110100000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSUB (oneDt SIMDTypI32) N OD.OprDdDnDm
  | 0b111100000u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSUB (oneDt SIMDTypI64) N OD.OprDdDnDm
  | 0b100100010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSUB (oneDt SIMDTypI8) N OD.OprQdQnQm
  | 0b101100010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSUB (oneDt SIMDTypI16) N OD.OprQdQnQm
  | 0b110100010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSUB (oneDt SIMDTypI32) N OD.OprQdQnQm
  | 0b111100010u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSUB (oneDt SIMDTypI64) N OD.OprQdQnQm
  (* VBIT 1100001x1 *)
  | 0b110000101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VBIT None N OD.OprDdDnDm
  | 0b110000111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VBIT None N OD.OprQdQnQm
  (* VCEQ 1xx1000x1 *)
  | 0b111100001u | 0b111100011u (* size == '11' *) -> raise UndefinedException
  | 0b100100001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypI8) N OD.OprDdDnDm
  | 0b101100001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypI16) N OD.OprDdDnDm
  | 0b110100001u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypI32) N OD.OprDdDnDm
  | 0b100100011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypI8) N OD.OprQdQnQm
  | 0b101100011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypI16) N OD.OprQdQnQm
  | 0b110100011u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypI32) N OD.OprQdQnQm
  (* VMLS 1xx1001x0 *)
  | 00111100100u | 00111100110u (* size == '11' *) -> raise UndefinedException
  | 0b100100100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMLS (oneDt SIMDTypI8) N OD.OprDdDnDm
  | 0b101100100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMLS (oneDt SIMDTypI16) N OD.OprDdDnDm
  | 0b110100100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMLS (oneDt SIMDTypI32) N OD.OprDdDnDm
  | 0b100100110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMLS (oneDt SIMDTypI8) N OD.OprQdQnQm
  | 0b101100110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMLS (oneDt SIMDTypI16) N OD.OprQdQnQm
  | 0b110100110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMLS (oneDt SIMDTypI32) N OD.OprQdQnQm
  (* VQRDMULH 1xx1011x0 *)
  | 0b100101100u | 0b100101110u | 0b111101100u | 0b111101110u ->
    raise UndefinedException (* size == '00' || size == '11' *)
  | 0b101101100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    let dt = oneDt SIMDTypS16
    render phlp &itstate 0 isInIT b Op.VQRDMULH dt N OD.OprDdDnDm
  | 0b101101110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    let dt = oneDt SIMDTypS16
    render phlp &itstate 0 isInIT b Op.VQRDMULH dt N OD.OprQdQnQm
  | 0b110101100u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    let dt = oneDt SIMDTypS32
    render phlp &itstate 0 isInIT b Op.VQRDMULH dt N OD.OprDdDnDm
  | 0b110101110u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    let dt = oneDt SIMDTypS32
    render phlp &itstate 0 isInIT b Op.VQRDMULH dt N OD.OprQdQnQm
  (* SHA256SU1 1101100x0 *)
  | 0b110110000u (* Q != '1' *) -> raise UndefinedException
  | 0b110110010u ->
#if !EMULATION
    chkITVdVnVm b itstate
#endif
    let dt = oneDt SIMDTyp32
    render phlp &itstate 0 isInIT b Op.SHA256SU1 dt N OD.OprQdQnQm
  (* VQRDMLAH 1xx1011x1 Armv8.1 *)
  | 0b100101101u | 0b100101111u | 0b111101101u | 0b111101111u ->
    raise UndefinedException (* size == '00' || size == '11' *)
  | 0b101101101u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    let dt = oneDt SIMDTypS16
    render phlp &itstate 0 isInIT b Op.VQRDMLAH dt N OD.OprDdDnDm
  | 0b101101111u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    let dt = oneDt SIMDTypS16
    render phlp &itstate 0 isInIT b Op.VQRDMLAH dt N OD.OprQdQnQm
  | 0b110101101u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    let dt = oneDt SIMDTypS32
    render phlp &itstate 0 isInIT b Op.VQRDMLAH dt N OD.OprDdDnDm
  | 0b110101111u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    let dt = oneDt SIMDTypS32
    render phlp &itstate 0 isInIT b Op.VQRDMLAH dt N OD.OprQdQnQm
  (* VBIF 1110001x1 *)
  | 0b111000101u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VBIF None N OD.OprDdDnDm
  | 0b111000111u ->
#if !EMULATION
    chkQVdVnVm b
#endif
    render phlp &itstate 0 isInIT b Op.VBIF None N OD.OprQdQnQm
  (* VQRDMLSH 1xx1100x1 Armv8.1 *)
  | 0b100110001u | 0b100110011u | 0b111110001u | 0b111110011u ->
    raise UndefinedException (* size == '00' || size == '11' *)
  | 0b101110001u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    let dt = oneDt SIMDTypS16
    render phlp &itstate 0 isInIT b Op.VQRDMLSH dt N OD.OprDdDnDm
  | 0b101110011u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    let dt = oneDt SIMDTypS16
    render phlp &itstate 0 isInIT b Op.VQRDMLSH dt N OD.OprQdQnQm
  | 0b110110001u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    let dt = oneDt SIMDTypS32
    render phlp &itstate 0 isInIT b Op.VQRDMLSH dt N OD.OprDdDnDm
  | 0b110110011u ->
#if !EMULATION
    chkITQVdVnVm b itstate
#endif
    let dt = oneDt SIMDTypS32
    render phlp &itstate 0 isInIT b Op.VQRDMLSH dt N OD.OprQdQnQm
  | b when b &&& 0b100111111u = 0b100111110u (* 0b1xx111110u *) ->
    raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// Advanced SIMD two registers misc on page F3-4168.
let parseAdvSIMDTwoRegsMisc phlp (itstate: byref<BL>) isInIT b =
  let decodeFields (* size:opc1:opc2:Q *) =
    concat (pickFour b 16) (pickFive b 6) 5
  match decodeFields with
  (* VREV64 xx000000x *)
  | 0b110000000u | 0b110000001u (* size = 11 *) -> raise UndefinedException
  | 0b000000000u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VREV64 (oneDt SIMDTyp8) N OD.OprDdDm
  | 0b010000000u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VREV64 (oneDt SIMDTyp16) N OD.OprDdDm
  | 0b100000000u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VREV64 (oneDt SIMDTyp32) N OD.OprDdDm
  | 0b000000001u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VREV64 (oneDt SIMDTyp8) N OD.OprQdQm
  | 0b010000001u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VREV64 (oneDt SIMDTyp16) N OD.OprQdQm
  | 0b100000001u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VREV64 (oneDt SIMDTyp32) N OD.OprQdQm
  (* VREV32 xx000001x *)
  | 0b100000010u | 0b100000011u (* size = 10 *)
  | 0b110000010u | 0b110000011u (* size = 11 *) -> raise UndefinedException
  | 0b000000010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VREV32 (oneDt SIMDTyp8) N OD.OprDdDm
  | 0b010000010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VREV32 (oneDt SIMDTyp16) N OD.OprDdDm
  | 0b000000011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VREV32 (oneDt SIMDTyp8) N OD.OprQdQm
  | 0b010000011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VREV32 (oneDt SIMDTyp16) N OD.OprQdQm
  (* VREV16 xx000010x *)
  | 0b010000100u | 0b010000101u (* size = 01 *)
  | 0b100000100u | 0b100000101u | 0b110000100u | 0b110000101u (* size = 1x *) ->
    raise UndefinedException
  | 0b000000100u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VREV16 (oneDt SIMDTyp8) N OD.OprDdDm
  | 0b000000101u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VREV16 (oneDt SIMDTyp8) N OD.OprQdQm
  | b when b &&& 0b001111110u = 0b000000110u (* xx000011x *) ->
    raise ParsingFailureException
  (* VPADDL xx00010xx *)
  | 0b110001000u | 0b110001001u | 0b110001010u | 0b110001011u (* size = 11 *) ->
    raise UndefinedException
  | 0b000001000u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADDL (oneDt SIMDTypS8)  N OD.OprDdDm
  | 0b010001000u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADDL (oneDt SIMDTypS16) N OD.OprDdDm
  | 0b100001000u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADDL (oneDt SIMDTypS32) N OD.OprDdDm
  | 0b000001010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADDL (oneDt SIMDTypU8)  N OD.OprDdDm
  | 0b010001010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADDL (oneDt SIMDTypU16) N OD.OprDdDm
  | 0b100001010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADDL (oneDt SIMDTypU32) N OD.OprDdDm
  | 0b000001001u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADDL (oneDt SIMDTypS8)  N OD.OprQdQm
  | 0b010001001u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADDL (oneDt SIMDTypS16) N OD.OprQdQm
  | 0b100001001u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADDL (oneDt SIMDTypS32) N OD.OprQdQm
  | 0b000001011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADDL (oneDt SIMDTypU8)  N OD.OprQdQm
  | 0b010001011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADDL (oneDt SIMDTypU16) N OD.OprQdQm
  | 0b100001011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADDL (oneDt SIMDTypU32) N OD.OprQdQm
  (* AESE xx0001100 *)
  | 0b010001100u | 0b100001100u | 0b110001100u (* size != 00 *) ->
    raise UndefinedException
  | 0b000001100u ->
#if !EMULATION
    chkITVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.AESE (oneDt SIMDTyp8) N OD.OprQdQm
  (* AESD xx0001101 *)
  | 0b010001101u | 0b100001101u | 0b110001101u (* size != 00 *) ->
    raise UndefinedException
  | 0b000001101u ->
#if !EMULATION
    chkITVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.AESD (oneDt SIMDTyp8) N OD.OprQdQm
  (* AESMC xx0001110 *)
  | 0b010001110u | 0b100001110u | 0b110001110u (* size != 00 *) ->
    raise UndefinedException
  | 0b000001110u ->
#if !EMULATION
    chkITVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.AESMC (oneDt SIMDTyp8) N OD.OprQdQm
  (* AESIMC xx0001111 *)
  | 0b010001111u | 0b100001111u | 0b110001111u (* size != 00 *) ->
    raise UndefinedException
  | 0b000001111u ->
#if !EMULATION
    chkITVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.AESIMC (oneDt SIMDTyp8) N OD.OprQdQm
  (* VCLS xx001000x *)
  | 0b110010000u | 0b110010001u (* size = 11 *) -> raise UndefinedException
  | 0b000010000u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCLS (oneDt SIMDTypS8) N OD.OprDdDm
  | 0b010010000u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCLS (oneDt SIMDTypS16) N OD.OprDdDm
  | 0b100010000u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCLS (oneDt SIMDTypS32) N OD.OprDdDm
  | 0b000010001u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCLS (oneDt SIMDTypS8) N OD.OprQdQm
  | 0b010010001u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCLS (oneDt SIMDTypS16) N OD.OprQdQm
  | 0b100010001u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCLS (oneDt SIMDTypS32) N OD.OprQdQm
  (* VSWP 00100000x *)
  | 0b001000000u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSWP None N OD.OprDdDm
  | 0b001000001u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSWP None N OD.OprQdQm
  (* VCLZ xx001001x *)
  | 0b110010010u | 0b110010011u (* size = 11 *) -> raise UndefinedException
  | 0b000010010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCLZ (oneDt SIMDTypI8)  N OD.OprDdDm
  | 0b010010010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCLZ (oneDt SIMDTypI16) N OD.OprDdDm
  | 0b100010010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCLZ (oneDt SIMDTypI32) N OD.OprDdDm
  | 0b000010011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCLZ (oneDt SIMDTypI8)  N OD.OprQdQm
  | 0b010010011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCLZ (oneDt SIMDTypI16) N OD.OprQdQm
  | 0b100010011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCLZ (oneDt SIMDTypI32) N OD.OprQdQm
  (* VCNT xx001010x *)
  | 0b010010100u | 0b100010100u | 0b110010100u | 0b010010101u | 0b100010101u
  | 0b110010101u (* size != 00 *) -> raise UndefinedException
  | 0b000010100u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCNT (oneDt SIMDTyp8) N OD.OprDdDm
  | 0b000010101u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VCNT (oneDt SIMDTyp8) N OD.OprQdQm
  (* VMVN xx001011x *)
  | 0b010010110u | 0b010010111u | 0b100010110u | 0b100010111u | 0b110010110u
  | 0b110010111u (* size != 00 *) -> raise UndefinedException
  | 0b000010110u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMVN None N OD.OprDdDm
  | 0b000010111u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMVN None N OD.OprQdQm
  | 0b001011001u -> raise ParsingFailureException
  (* VPADAL xx00110xx *)
  | 0b110011000u | 0b110011001u | 0b110011010u | 0b110011011u (* size = 11 *) ->
    raise UndefinedException
  | 0b000011000u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADAL (oneDt SIMDTypS8) N OD.OprDdDm
  | 0b010011000u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADAL (oneDt SIMDTypS16) N OD.OprDdDm
  | 0b100011000u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADAL (oneDt SIMDTypS32) N OD.OprDdDm
  | 0b000011010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADAL (oneDt SIMDTypU8) N OD.OprDdDm
  | 0b010011010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADAL (oneDt SIMDTypU16) N OD.OprDdDm
  | 0b100011010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADAL (oneDt SIMDTypU32) N OD.OprDdDm
  | 0b000011001u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADAL (oneDt SIMDTypS8) N OD.OprQdQm
  | 0b010011001u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADAL (oneDt SIMDTypS16) N OD.OprQdQm
  | 0b100011001u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADAL (oneDt SIMDTypS32) N OD.OprQdQm
  | 0b000011011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADAL (oneDt SIMDTypU8) N OD.OprQdQm
  | 0b010011011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADAL (oneDt SIMDTypU16) N OD.OprQdQm
  | 0b100011011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VPADAL (oneDt SIMDTypU32) N OD.OprQdQm
  (* VQABS xx001110x *)
  | 0b110011100u | 0b110011101u (* size = 11 *) -> raise UndefinedException
  | 0b000011100u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQABS (oneDt SIMDTypS8) N OD.OprDdDm
  | 0b010011100u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQABS (oneDt SIMDTypS16) N OD.OprDdDm
  | 0b100011100u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQABS (oneDt SIMDTypS32) N OD.OprDdDm
  | 0b000011101u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQABS (oneDt SIMDTypS8) N OD.OprQdQm
  | 0b010011101u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQABS (oneDt SIMDTypS16) N OD.OprQdQm
  | 0b100011101u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQABS (oneDt SIMDTypS32) N OD.OprQdQm
  (* VQNEG xx001111x *)
  | 0b110011110u | 0b110011111u (* size = 11 *) -> raise UndefinedException
  | 0b000011110u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQNEG (oneDt SIMDTypS8) N OD.OprDdDm
  | 0b010011110u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQNEG (oneDt SIMDTypS16) N OD.OprDdDm
  | 0b100011110u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQNEG (oneDt SIMDTypS32) N OD.OprDdDm
  | 0b000011111u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQNEG (oneDt SIMDTypS8) N OD.OprQdQm
  | 0b010011111u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQNEG (oneDt SIMDTypS16) N OD.OprQdQm
  | 0b100011111u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQNEG (oneDt SIMDTypS32) N OD.OprQdQm
  (* VCGT xx01x000x *)
  | 0b110100000u | 0b110100001u | 0b110110000u | 0b110110001u (* size = 11 *)
  | 0b000110000u | 0b000110001u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000100000u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypS8) N OD.OprDdDm0
  | 0b010100000u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypS16) N OD.OprDdDm0
  | 0b100100000u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypS32) N OD.OprDdDm0
  | 0b010110000u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypF16) N OD.OprDdDm0
  | 0b100110000u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypF32) N OD.OprDdDm0
  | 0b000100001u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypS8) N OD.OprQdQm0
  | 0b010100001u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypS16) N OD.OprQdQm0
  | 0b100100001u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypS32) N OD.OprQdQm0
  | 0b010110001u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypF16) N OD.OprQdQm0
  | 0b100110001u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGT (oneDt SIMDTypF32) N OD.OprQdQm0
  (* VCGE xx01x001x *)
  | 0b110100010u | 0b110100011u | 0b110110010u | 0b110110011u (* size = 11 *)
  | 0b000110010u | 0b000110011u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000100010u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypS8) N OD.OprDdDm0
  | 0b010100010u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypS16) N OD.OprDdDm0
  | 0b100100010u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypS32) N OD.OprDdDm0
  | 0b010110010u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypF16) N OD.OprDdDm0
  | 0b100110010u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypF32) N OD.OprDdDm0
  | 0b000100011u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypS8) N OD.OprQdQm0
  | 0b010100011u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypS16) N OD.OprQdQm0
  | 0b100100011u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypS32) N OD.OprQdQm0
  | 0b010110011u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypF16) N OD.OprQdQm0
  | 0b100110011u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCGE (oneDt SIMDTypF32) N OD.OprQdQm0
  (* VCEQ xx01x010x *)
  | 0b110100100u | 0b110100101u | 0b110110100u | 0b110110101u (* size = 11 *)
  | 0b000110100u | 0b000110101u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000100100u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypS8) N OD.OprDdDm0
  | 0b010100100u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypS16) N OD.OprDdDm0
  | 0b100100100u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypS32) N OD.OprDdDm0
  | 0b010110100u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypF16) N OD.OprDdDm0
  | 0b100110100u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypF32) N OD.OprDdDm0
  | 0b000100101u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypS8) N OD.OprQdQm0
  | 0b010100101u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypS16) N OD.OprQdQm0
  | 0b100100101u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypS32) N OD.OprQdQm0
  | 0b010110101u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypF16) N OD.OprQdQm0
  | 0b100110101u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCEQ (oneDt SIMDTypF32) N OD.OprQdQm0
  (* VCLE xx01x011x *)
  | 0b110100110u | 0b110100111u | 0b110110110u | 0b110110111u (* size = 11 *)
  | 0b000110110u | 0b000110111u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000100110u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLE (oneDt SIMDTypS8) N OD.OprDdDm0
  | 0b010100110u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLE (oneDt SIMDTypS16) N OD.OprDdDm0
  | 0b100100110u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLE (oneDt SIMDTypS32) N OD.OprDdDm0
  | 0b010110110u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLE (oneDt SIMDTypF16) N OD.OprDdDm0
  | 0b100110110u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLE (oneDt SIMDTypF32) N OD.OprDdDm0
  | 0b000100111u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLE (oneDt SIMDTypS8) N OD.OprQdQm0
  | 0b010100111u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLE (oneDt SIMDTypS16) N OD.OprQdQm0
  | 0b100100111u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLE (oneDt SIMDTypS32) N OD.OprQdQm0
  | 0b010110111u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLE (oneDt SIMDTypF16) N OD.OprQdQm0
  | 0b100110111u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLE (oneDt SIMDTypF32) N OD.OprQdQm0
  (* VCLT xx01x100x *)
  | 0b110101000u | 0b110101001u | 0b110111000u | 0b110111001u (* size = 11 *)
  | 0b000111000u | 0b000111001u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000101000u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLT (oneDt SIMDTypS8) N OD.OprDdDm0
  | 0b010101000u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLT (oneDt SIMDTypS16) N OD.OprDdDm0
  | 0b100101000u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLT (oneDt SIMDTypS32) N OD.OprDdDm0
  | 0b010111000u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLT (oneDt SIMDTypF16) N OD.OprDdDm0
  | 0b100111000u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLT (oneDt SIMDTypF32) N OD.OprDdDm0
  | 0b000101001u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLT (oneDt SIMDTypS8) N OD.OprQdQm0
  | 0b010101001u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLT (oneDt SIMDTypS16) N OD.OprQdQm0
  | 0b100101001u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLT (oneDt SIMDTypS32) N OD.OprQdQm0
  | 0b010111001u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLT (oneDt SIMDTypF16) N OD.OprQdQm0
  | 0b100111001u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VCLT (oneDt SIMDTypF32) N OD.OprQdQm0
  (* VABS xx01x110x *)
  | 0b110101100u | 0b110101101u | 0b110111100u | 0b110111101u (* size = 11 *)
  | 0b000111100u | 0b000111101u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000101100u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABS (oneDt SIMDTypS8) N OD.OprDdDm
  | 0b010101100u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABS (oneDt SIMDTypS16) N OD.OprDdDm
  | 0b100101100u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABS (oneDt SIMDTypS32) N OD.OprDdDm
  | 0b010111100u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABS (oneDt SIMDTypF16) N OD.OprDdDm
  | 0b100111100u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABS (oneDt SIMDTypF32) N OD.OprDdDm
  | 0b000101101u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABS (oneDt SIMDTypS8) N OD.OprDdDm
  | 0b010101101u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABS (oneDt SIMDTypS16) N OD.OprDdDm
  | 0b100101101u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABS (oneDt SIMDTypS32) N OD.OprDdDm
  | 0b010111101u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABS (oneDt SIMDTypF16) N OD.OprDdDm
  | 0b100111101u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VABS (oneDt SIMDTypF32) N OD.OprDdDm
  (* VNEG xx01x111x *)
  | 0b110101110u | 0b110101111u | 0b110111110u | 0b110111111u (* size = 11 *)
  | 0b000111110u | 0b000111111u (* F = 1 && size = 00 *) ->
    raise UndefinedException
  | 0b000101110u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VNEG (oneDt SIMDTypS8) N OD.OprDdDm
  | 0b010101110u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VNEG (oneDt SIMDTypS16) N OD.OprDdDm
  | 0b100101110u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VNEG (oneDt SIMDTypS32) N OD.OprDdDm
  | 0b010111110u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VNEG (oneDt SIMDTypF16) N OD.OprDdDm
  | 0b100111110u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VNEG (oneDt SIMDTypF32) N OD.OprDdDm
  | 0b000101111u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VNEG (oneDt SIMDTypS8) N OD.OprQdQm
  | 0b010101111u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VNEG (oneDt SIMDTypS16) N OD.OprQdQm
  | 0b100101111u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VNEG (oneDt SIMDTypS32) N OD.OprQdQm
  | 0b010111111u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VNEG (oneDt SIMDTypF16) N OD.OprQdQm
  | 0b100111111u ->
#if !EMULATION
    chkFSzITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VNEG (oneDt SIMDTypF32) N OD.OprQdQm
  (* SHA1H xx0101011 *)
  | 0b000101011u | 0b010101011u | 0b110101011u (* size != 10 *) ->
    raise UndefinedException
  | 0b100101011u ->
#if !EMULATION
    chkITVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.SHA1H (oneDt SIMDTyp32) N OD.OprQdQm
  (* VCVT 011011001 Armv8.6 *)
  | 0b011011001u ->
    pickBit b 0 = 1u (* Vm<0> = 1 *) |> checkUndef
    let dt = twoDt (BF16, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprDdQm
  (* VTRN xx100001x *)
  | 0b111000010u | 0b111000011u (* size = 11 *) -> raise UndefinedException
  | 0b001000010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VTRN (oneDt SIMDTyp8) N OD.OprDdDm
  | 0b011000010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VTRN (oneDt SIMDTyp16) N OD.OprDdDm
  | 0b101000010u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VTRN (oneDt SIMDTyp32) N OD.OprDdDm
  | 0b001000011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VTRN (oneDt SIMDTyp8) N OD.OprQdQm
  | 0b011000011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VTRN (oneDt SIMDTyp16) N OD.OprQdQm
  | 0b101000011u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VTRN (oneDt SIMDTyp32) N OD.OprQdQm
  (* VUZP xx100010x *)
  | 0b111000100u | 0b111000101u (* size = 11 *)
  | 0b101000100u (* Q = 0 && size = 10 *) -> raise UndefinedException
  | 0b001000100u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VUZP (oneDt SIMDTyp8) N OD.OprDdDm
  | 0b011000100u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VUZP (oneDt SIMDTyp16) N OD.OprDdDm
  | 0b001000101u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VUZP (oneDt SIMDTyp8) N OD.OprQdQm
  | 0b011000101u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VUZP (oneDt SIMDTyp16) N OD.OprQdQm
  | 0b101000101u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VUZP (oneDt SIMDTyp32) N OD.OprQdQm
  (* VZIP xx100011x *)
  | 0b111000110u | 0b111000111u (* size = 11 *)
  | 0b101000110u (* Q = 0 && size = 10 *) -> raise UndefinedException
  | 0b001000110u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VZIP (oneDt SIMDTyp8) N OD.OprDdDm
  | 0b011000110u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VZIP (oneDt SIMDTyp16) N OD.OprDdDm
  | 0b001000111u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VZIP (oneDt SIMDTyp8) N OD.OprQdQm
  | 0b011000111u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VZIP (oneDt SIMDTyp16) N OD.OprQdQm
  | 0b101000111u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VZIP (oneDt SIMDTyp32) N OD.OprQdQm
  (* VMOVN xx1001000 *)
  | 0b111001000u (* size = 11 *) -> raise UndefinedException
  | 0b001001000u ->
#if !EMULATION
    chkVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMOVN (oneDt SIMDTypI16) N OD.OprDdQm
  | 0b011001000u ->
#if !EMULATION
    chkVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMOVN (oneDt SIMDTypI32) N OD.OprDdQm
  | 0b101001000u ->
#if !EMULATION
    chkVm b
#endif
    render phlp &itstate 0 isInIT b Op.VMOVN (oneDt SIMDTypI64) N OD.OprDdQm
  (* VQMOVUN xx1001001 *)
  | 00111001001u (* size = 11 *) -> raise UndefinedException
  | 0b001001001u ->
#if !EMULATION
    chkVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQMOVUN (oneDt SIMDTypS16) N OD.OprDdQm
  | 0b011001001u ->
#if !EMULATION
    chkVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQMOVUN (oneDt SIMDTypS32) N OD.OprDdQm
  | 0b101001001u ->
#if !EMULATION
    chkVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQMOVUN (oneDt SIMDTypS64) N OD.OprDdQm
  (* VQMOVN xx100101x *)
  | 0b001001010u ->
#if !EMULATION
    chkVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQMOVN (oneDt SIMDTypS16) N OD.OprDdQm
  | 0b011001010u ->
#if !EMULATION
    chkVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQMOVN (oneDt SIMDTypS32) N OD.OprDdQm
  | 0b101001010u ->
#if !EMULATION
    chkVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQMOVN (oneDt SIMDTypS64) N OD.OprDdQm
  | 0b001001011u ->
#if !EMULATION
    chkVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQMOVN (oneDt SIMDTypU16) N OD.OprDdQm
  | 0b011001011u ->
#if !EMULATION
    chkVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQMOVN (oneDt SIMDTypU32) N OD.OprDdQm
  | 0b101001011u ->
#if !EMULATION
    chkVm b
#endif
    render phlp &itstate 0 isInIT b Op.VQMOVN (oneDt SIMDTypU64) N OD.OprDdQm
  (* VSHLL xx1001100 *)
  | 0b111001100u (* size = 11 *) -> raise UndefinedException
  | 0b001001100u ->
#if !EMULATION
    chkVm b
#endif
    render phlp &itstate 0 isInIT b Op.VSHLL (oneDt SIMDTypI8) N OD.OprQdDmImm8
  | 0b011001100u ->
#if !EMULATION
    chkVm b
#endif
    let dt = oneDt SIMDTypI16
    render phlp &itstate 0 isInIT b Op.VSHLL dt N OD.OprQdDmImm16
  | 0b101001100u ->
#if !EMULATION
    chkVm b
#endif
    let dt = oneDt SIMDTypI32
    render phlp &itstate 0 isInIT b Op.VSHLL dt N OD.OprQdDmImm32
  (* SHA1SU1 xx1001110 *)
  | 0b001001110u | 0b011001110u | 0b111001110u (* size != 10 *) ->
    raise UndefinedException
  | 0b101001110u ->
#if !EMULATION
    chkITVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.SHA1SU1 (oneDt SIMDTyp32) N OD.OprQdQm
  (* SHA256SU0 xx1001111 *)
  | 0b001001111u | 0b011001111u | 0b111001111u (* size != 10 *) ->
    raise UndefinedException
  | 0b101001111u ->
#if !EMULATION
    chkITVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.SHA256SU0 (oneDt SIMDTyp32) N OD.OprQdQm
  (* VRINTN xx101000x *)
  | 0b001010000u | 0b001010001u (* size = 00 *)
  | 0b111010000u | 0b111010001u (* size = 11 *) -> raise UndefinedException
  | 0b011010000u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTN (oneDt SIMDTypF16) N OD.OprDdDm
  | 0b011010001u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTN (oneDt SIMDTypF16) N OD.OprQdQm
  | 0b101010000u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTN (oneDt SIMDTypF32) N OD.OprDdDm
  | 0b101010001u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTN (oneDt SIMDTypF32) N OD.OprQdQm
  (* VRINTX xx101001x *)
  | 0b001010010u | 0b001010011u (* size = 00 *)
  | 0b111010010u | 0b111010011u (* size = 11 *) -> raise UndefinedException
  | 0b011010010u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTX (oneDt SIMDTypF16) N OD.OprDdDm
  | 0b011010011u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTX (oneDt SIMDTypF16) N OD.OprQdQm
  | 0b101010010u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTX (oneDt SIMDTypF32) N OD.OprDdDm
  | 0b101010011u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTX (oneDt SIMDTypF32) N OD.OprQdQm
  (* VRINTA xx101010x *)
  | 0b001010100u | 0b001010101u (* size = 00 *)
  | 0b111010100u | 0b111010101u (* size = 11 *) -> raise UndefinedException
  | 0b011010100u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTA (oneDt SIMDTypF16) N OD.OprDdDm
  | 0b011010101u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTA (oneDt SIMDTypF16) N OD.OprQdQm
  | 0b101010100u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTA (oneDt SIMDTypF32) N OD.OprDdDm
  | 0b101010101u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTA (oneDt SIMDTypF32) N OD.OprQdQm
  (* VRINTZ xx101011x *)
  | 0b001010110u | 0b001010111u (* size = 00 *)
  | 0b111010110u | 0b111010111u (* size = 11 *) -> raise UndefinedException
  | 0b011010110u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTZ (oneDt SIMDTypF16) N OD.OprDdDm
  | 0b011010111u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTZ (oneDt SIMDTypF16) N OD.OprQdQm
  | 0b101010110u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTZ (oneDt SIMDTypF32) N OD.OprDdDm
  | 0b101010111u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTZ (oneDt SIMDTypF32) N OD.OprQdQm
  | 0b101011001u -> raise ParsingFailureException
  (* VCVT xx1011000 *)
  | 0b001011000u | 0b101011000u | 0b111011000u (* size != 01 *) ->
    raise UndefinedException
  | 0b011011000u ->
#if !EMULATION
    chkOpVdVm b
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprDdQm
  (* VRINTM xx101101x *)
  | 0b001011010u | 0b001011011u (* size = 00 *)
  | 0b111011010u | 0b111011011u (* size = 11 *) -> raise UndefinedException
  | 0b011011010u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTM (oneDt SIMDTypF16) N OD.OprDdDm
  | 0b011011011u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTM (oneDt SIMDTypF16) N OD.OprQdQm
  | 0b101011010u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTM (oneDt SIMDTypF32) N OD.OprDdDm
  | 0b101011011u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRINTM (oneDt SIMDTypF32) N OD.OprQdQm
  (* VCVT xx1011100 *)
  | 0b001011100u | 0b101011100u | 0b111011100u (* size =! 01 *) ->
    raise UndefinedException
  | 0b011011100u ->
#if !EMULATION
    chkOpVdVm b
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprQdDm
  | 0b001011101u | 0b011011101u | 0b101011101u | 0b111011101u (* xx1011101 *) ->
    raise ParsingFailureException
  (* VRINTP xx101111x *)
  | 0b001011110u | 0b001011111u (* size = 00 *)
  | 0b111011110u | 0b111011111u (* size = 11 *) -> raise UndefinedException
  | 0b011011110u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRINTP (oneDt SIMDTypF16) N OD.OprDdDm
  | 0b011011111u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRINTP (oneDt SIMDTypF16) N OD.OprQdQm
  | 0b101011110u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRINTP (oneDt SIMDTypF32) N OD.OprDdDm
  | 0b101011111u ->
#if !EMULATION
    chkQVdVm b
#endif
    render phlp &itstate 0 isInIT b Op.VRINTP (oneDt SIMDTypF32) N OD.OprQdQm
  (* VCVTA xx11000xx *)
  | 0b001100000u | 0b001100001u | 0b001100010u | 0b001100011u (* size = 00 *)
  | 0b111100000u | 0b111100001u | 0b111100010u | 0b111100011u (* size = 11 *) ->
    raise UndefinedException
  | 0b011100000u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTA dt N OD.OprDdDm
  | 0b101100000u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTA dt N OD.OprDdDm
  | 0b011100010u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTA dt N OD.OprDdDm
  | 0b101100010u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTA dt N OD.OprDdDm
  | 0b011100001u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTA dt N OD.OprQdQm
  | 0b101100001u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTA dt N OD.OprQdQm
  | 0b011100011u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTA dt N OD.OprQdQm
  | 0b101100011u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTA dt N OD.OprQdQm
  (* VCVTN xx11001xx *)
  | 0b001100100u | 0b001100101u | 0b001100110u | 0b001100111u (* size = 00 *)
  | 0b111100100u | 0b111100101u | 0b111100110u | 0b111100111u (* size = 11 *) ->
    raise UndefinedException
  | 0b011100100u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTN dt N OD.OprDdDm
  | 0b101100100u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTN dt N OD.OprDdDm
  | 0b011100110u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTN dt N OD.OprDdDm
  | 0b101100110u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTN dt N OD.OprDdDm
  | 0b011100101u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTN dt N OD.OprQdQm
  | 0b101100101u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTN dt N OD.OprQdQm
  | 0b011100111u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTN dt N OD.OprQdQm
  | 0b101100111u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTN dt N OD.OprQdQm
  (* VCVTP xx11010xx *)
  | 0b001101000u | 0b001101001u | 0b001101010u | 0b001101011u (* size = 00 *)
  | 0b111101000u | 0b111101001u | 0b111101010u | 0b111101011u (* size = 11 *) ->
    raise UndefinedException
  | 0b011101000u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTP dt N OD.OprDdDm
  | 0b101101000u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTP dt N OD.OprDdDm
  | 0b011101010u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTP dt N OD.OprDdDm
  | 0b101101010u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTP dt N OD.OprDdDm
  | 0b011101001u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTP dt N OD.OprQdQm
  | 0b101101001u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTP dt N OD.OprQdQm
  | 0b011101011u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTP dt N OD.OprQdQm
  | 0b101101011u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTP dt N OD.OprQdQm
  (* VCVTM xx11011xx *)
  | 0b001101100u | 0b001101101u | 0b001101110u | 0b001101111u (* size = 00 *)
  | 0b111101100u | 0b111101101u | 0b111101110u | 0b111101111u (* size = 11 *) ->
    raise UndefinedException
  | 0b011101100u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTM dt N OD.OprDdDm
  | 0b101101100u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTM dt N OD.OprDdDm
  | 0b011101110u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTM dt N OD.OprDdDm
  | 0b101101110u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTM dt N OD.OprDdDm
  | 0b011101101u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTM dt N OD.OprQdQm
  | 0b101101101u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTM dt N OD.OprQdQm
  | 0b011101111u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVTM dt N OD.OprQdQm
  | 0b101101111u ->
#if !EMULATION
    chkITQVdVm b itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVTM dt N OD.OprQdQm
  (* VRECPE xx1110x0x *)
  | 0b001110000u | 0b001110001u | 0b001110100u | 0b001110101u (* size = 00 *)
  | 0b111110000u | 0b111110001u | 0b111110100u | 0b111110101u (* size = 11 *) ->
    raise UndefinedException
  | 0b101110000u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRECPE (oneDt SIMDTypU32) N OD.OprDdDm
  | 0b011110100u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRECPE (oneDt SIMDTypF16) N OD.OprDdDm
  | 0b101110100u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRECPE (oneDt SIMDTypF32) N OD.OprDdDm
  | 0b101110001u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRECPE (oneDt SIMDTypU32) N OD.OprQdQm
  | 0b011110101u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRECPE (oneDt SIMDTypF16) N OD.OprQdQm
  | 0b101110101u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRECPE (oneDt SIMDTypF32) N OD.OprQdQm
  (* VRSQRTE xx1110x1x *)
  | 0b001110010u | 0b001110011u | 0b001110110u | 0b001110111u (* size = 00 *)
  | 0b111110010u | 0b111110011u | 0b111110110u | 0b111110111u (* size = 11 *) ->
    raise UndefinedException
  | 0b101110010u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRSQRTE (oneDt SIMDTypU32) N OD.OprDdDm
  | 0b011110110u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRSQRTE (oneDt SIMDTypF16) N OD.OprDdDm
  | 0b101110110u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRSQRTE (oneDt SIMDTypF32) N OD.OprDdDm
  | 0b101110011u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRSQRTE (oneDt SIMDTypU32) N OD.OprQdQm
  | 0b011110111u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRSQRTE (oneDt SIMDTypF16) N OD.OprQdQm
  | 0b101110111u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VRSQRTE (oneDt SIMDTypF32) N OD.OprQdQm
  | 0b111011001u -> raise ParsingFailureException
  (* VCVT xx1111xxx *)
  | b when pickTwo b 7 = 0b00u (* size = 00 *) -> raise UndefinedException
  | b when pickTwo b 7 = 0b11u (* size = 11 *) -> raise UndefinedException
  | 0b011111000u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypS16)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprDdDm
  | 0b011111010u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypU16)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprDdDm
  | 0b011111100u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprDdDm
  | 0b011111110u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprDdDm
  | 0b101111000u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprDdDm
  | 0b101111010u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprDdDm
  | 0b101111100u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprDdDm
  | 0b101111110u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprDdDm
  | 0b011111001u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypS16)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprQdQm
  | 0b011111011u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypU16)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprQdQm
  | 0b011111101u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprQdQm
  | 0b011111111u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprQdQm
  | 0b101111001u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprQdQm
  | 0b101111011u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprQdQm
  | 0b101111101u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprQdQm
  | 0b101111111u ->
#if !EMULATION
    chkQVdVmSzIT b itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp &itstate 0 isInIT b Op.VCVT dt N OD.OprQdQm
  | _ -> raise ParsingFailureException

/// Advanced SIMD duplicate (scalar) on page F3-4170.
let parseAdvSIMDDupScalar phlp (itstate: byref<BL>) isInIT bin =
  match pickThree bin 7 with
  | 0b000u ->
#if !EMULATION
    chkQVd bin
#endif
    let dt = getDTImm4 (pickFour bin 16) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VDUP dt N OD.OprDdDmx
  | _ (* 001 | 01x | 1xx *) -> raise ParsingFailureException

/// Advanced SIMD three registers of different lengths on page F3-4171.
let parseAdvSIMDThreeRegsDiffLen phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickBit bin 28) (pickFour bin 8) 4 (* U:opc *) with
  | 0b00000u | 0b10000u (* x0000 *) ->
#if !EMULATION
    chkVdOpVn bin
#endif
    let dt = getDtT bin |> oneDt
    render phlp &itstate 0 isInIT bin Op.VADDL dt N OD.OprQdDnDm
  | 0b00001u | 0b10001u (* x0001 *) ->
#if !EMULATION
    chkVdOpVn bin
#endif
    let dt = getDtT bin |> oneDt
    render phlp &itstate 0 isInIT bin Op.VADDW dt N OD.OprQdQnDm
  | 0b00010u | 0b10010u (* x0010 *) ->
#if !EMULATION
    chkVdOpVn bin
#endif
    let dt = getDtT bin |> oneDt
    render phlp &itstate 0 isInIT bin Op.VSUBL dt N OD.OprQdDnDm
  | 0b00100u ->
#if !EMULATION
    chkVnVm bin
#endif
    let dt = getDTInt (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VADDHN dt N OD.OprDdQnQm
  | 0b00011u | 0b10011u (* x0011 *) ->
#if !EMULATION
    chkVdOpVn bin
#endif
    let dt = getDtT bin |> oneDt
    render phlp &itstate 0 isInIT bin Op.VSUBW dt N OD.OprQdQnDm
  | 0b00110u ->
#if !EMULATION
    chkVnVm bin
#endif
    let dt = getDTInt (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VSUBHN dt N OD.OprDdQnQm
  | 0b01001u ->
#if !EMULATION
    chkSzVd bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQDMLAL dt N OD.OprQdDnDm
  | 0b00101u | 0b10101u (* x0101 *) ->
#if !EMULATION
    chkVd bin
#endif
    let dt = getDtT bin |> oneDt
    render phlp &itstate 0 isInIT bin Op.VABAL dt N OD.OprQdDnDm
  | 0b01011u ->
#if !EMULATION
    chkSzVd bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQDMLSL dt N OD.OprQdDnDm
  | 0b01101u ->
#if !EMULATION
    chkSzVd bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQDMULL dt N OD.OprQdDnDm
  | 0b00111u | 0b10111u (* x0111 *) ->
#if !EMULATION
    chkVd bin
#endif
    let dt = getDtT bin |> oneDt
    render phlp &itstate 0 isInIT bin Op.VABDL dt N OD.OprQdDnDm
  | 0b01000u | 0b11000u (* x1000 *) ->
#if !EMULATION
    chkVd bin
#endif
    let dt = getDtT bin |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLAL dt N OD.OprQdDnDm
  | 0b01010u | 0b11010u (* x1010 *) ->
#if !EMULATION
    chkVd bin
#endif
    let dt = getDtT bin |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLSL dt N OD.OprQdDnDm
  | 0b10100u ->
#if !EMULATION
    chkVnVm bin
#endif
    let dt = getDTInt (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VRADDHN dt N OD.OprDdQnQm
  | 0b10110u ->
#if !EMULATION
    chkVnVm bin
#endif
    let dt = getDTInt (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VRSUBHN dt N OD.OprDdQnQm
  | 0b01100u | 0b01110u | 0b11100u | 0b11110u (* x11x0 *) ->
#if !EMULATION
    chkPolySzITVd bin itstate
#endif
    let dt = getDTPoly bin |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMULL dt N OD.OprQdDnDm
  | 0b11001u -> raise ParsingFailureException
  | 0b11011u -> raise ParsingFailureException
  | 0b11101u -> raise ParsingFailureException
  | 0b01111u | 0b11111u (* x1111 *) -> raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// Advanced SIMD two registers and a scalar on page F3-4172.
let parseAdvSIMDTwoRegsAndScalar phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickBit bin 28) (pickFour bin 8) 4 (* Q:opc *) with
  (* VMLA x000x *)
  | 0b00000u ->
#if !EMULATION
    chkSzFSzITQVdVn bin itstate
#endif
    let dt = getDTF0 (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLA dt N OD.OprDdDnDmx
  | 0b00001u ->
#if !EMULATION
    chkSzFSzITQVdVn bin itstate
#endif
    let dt = getDTF1 (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLA dt N OD.OprDdDnDmx
  | 0b10000u ->
#if !EMULATION
    chkSzFSzITQVdVn bin itstate
#endif
    let dt = getDTF0 (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLA dt N OD.OprQdQnDmx
  | 0b10001u ->
#if !EMULATION
    chkSzFSzITQVdVn bin itstate
#endif
    let dt = getDTF1 (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLA dt N OD.OprQdQnDmx
  (* VQDMLAL *)
  | 0b00011u ->
#if !EMULATION
    chkSzVd bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQDMLAL dt N OD.OprQdDnDmx
  (* VMLAL x0010 *)
  | 0b00010u ->
#if !EMULATION
    chkSzVd bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLAL dt N OD.OprQdDnDmx
  | 0b10010u ->
#if !EMULATION
    chkSzVd bin
#endif
    let dt = getDTUSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLAL dt N OD.OprQdDnDmx
  (* VQDMLSL *)
  | 0b00111u ->
#if !EMULATION
    chkSzVd bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQDMLSL dt N OD.OprQdDnDmx
  (* VMLS x010x *)
  | 0b00100u ->
#if !EMULATION
    chkSzFSzITQVdVn bin itstate
#endif
    let dt = getDTF0 (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLS dt N OD.OprDdDnDmx
  | 0b00101u ->
#if !EMULATION
    chkSzFSzITQVdVn bin itstate
#endif
    let dt = getDTF1 (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLS dt N OD.OprDdDnDmx
  | 0b10100u ->
#if !EMULATION
    chkSzFSzITQVdVn bin itstate
#endif
    let dt = getDTF0 (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLS dt N OD.OprQdQnDmx
  | 0b10101u ->
#if !EMULATION
    chkSzFSzITQVdVn bin itstate
#endif
    let dt = getDTF1 (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLS dt N OD.OprQdQnDmx
  (* VQDMULL *)
  | 0b01011u ->
#if !EMULATION
    chkSzVd bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQDMULL dt N OD.OprQdDnDmx
  (* VMLSL x0110 *)
  | 0b00110u ->
#if !EMULATION
    chkSzVd bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLSL dt N OD.OprQdDnDmx
  | 0b10110u ->
#if !EMULATION
    chkSzVd bin
#endif
    let dt = getDTUSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMLSL dt N OD.OprQdDnDmx
  (* VMUL x100x *)
  | 0b01000u ->
#if !EMULATION
    chkQVdVn bin
#endif
    let dt = getDTF0 (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMUL dt N OD.OprDdDnDmx
  | 0b01001u ->
#if !EMULATION
    chkQVdVn bin
#endif
    let dt = getDTF1 (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMUL dt N OD.OprDdDnDmx
  | 0b11000u ->
#if !EMULATION
    chkQVdVn bin
#endif
    let dt = getDTF0 (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMUL dt N OD.OprQdQnDmx
  | 0b11001u ->
#if !EMULATION
    chkQVdVn bin
#endif
    let dt = getDTF1 (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMUL dt N OD.OprQdQnDmx
  | 0b10011u -> raise ParsingFailureException
  (* VMULL x1010 *)
  | 0b01010u ->
#if !EMULATION
    chkSzVd bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMULL dt N OD.OprQdDnDmx
  | 0b11010u ->
#if !EMULATION
    chkSzVd bin
#endif
    let dt = getDTUSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VMULL dt N OD.OprQdDnDmx
  | 0b10111u -> raise ParsingFailureException
  (* VQDMULH x1100 *)
  | 0b01100u ->
#if !EMULATION
    chkSzQVdVn bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQDMULH dt N OD.OprDdDnDmx
  | 0b11100u ->
#if !EMULATION
    chkSzQVdVn bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQDMULH dt N OD.OprQdQnDmx
  (* VQRDMULH x1101 *)
  | 0b01101u ->
#if !EMULATION
    chkSzQVdVn bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQRDMULH dt N OD.OprDdDnDmx
  | 0b11101u ->
#if !EMULATION
    chkSzQVdVn bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQRDMULH dt N OD.OprQdQnDmx
  | 0b11011u -> raise ParsingFailureException
  (* VQRDMLAH x1110 Armv8.1 *)
  | 0b01110u ->
#if !EMULATION
    chkSzQVdVn bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQRDMLAH dt N OD.OprDdDnDmx
  | 0b11110u ->
#if !EMULATION
    chkSzQVdVn bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQRDMLAH dt N OD.OprQdQnDmx
  (* VQRDMLSH x1111 Armv8.1 *)
  | 0b01111u ->
#if !EMULATION
    chkSzQVdVn bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQRDMLSH dt N OD.OprDdDnDmx
  | _ (* 11111 *) ->
#if !EMULATION
    chkSzQVdVn bin
#endif
    let dt = getDTSign (pickTwo bin 20) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VQRDMLSH dt N OD.OprQdQnDmx

/// Advanced SIMD two registers, or three registers of different lengths
/// on page F3-4168.
let parseAdvSIMDTwoOrThreeRegsDiffLen phlp (itstate: byref<BL>) isInIT b =
  let decodeFields (* op0:op1:op2:op3 *) =
    (pickBit b 28 <<< 5) + (pickTwo b 20 <<< 3) + (pickTwo b 10 <<< 1) +
    (pickBit b 6)
  match decodeFields with
  (* VEXT 011xxx *)
  | 0b011000u | 0b011010u | 0b011100u | 0b011110u (* 011xx0 *) ->
#if !EMULATION
    chkQVdVnVmImm4 b
#endif
    render phlp &itstate 0 isInIT b Op.VEXT (oneDt SIMDTyp8) N OD.OprDdDnDmImm
  | 0b011001u | 0b011011u | 0b011101u | 0b011111u (* 011xx1 *) ->
    render phlp &itstate 0 isInIT b Op.VEXT (oneDt SIMDTyp8) N OD.OprQdQnQmImm
  | 0b111000u | 0b111001u | 0b111010u | 0b111011u (* 1110xx *) ->
    parseAdvSIMDTwoRegsMisc phlp &itstate isInIT b
  (* VTBL, VTBX 11110x *)
  | 0b111100u ->
#if !EMULATION
    chkNLen b
#endif
    render phlp &itstate 0 isInIT b Op.VTBL (oneDt SIMDTyp8) N OD.OprDdListDm
  | 0b111101u ->
#if !EMULATION
    chkNLen b
#endif
    render phlp &itstate 0 isInIT b Op.VTBX (oneDt SIMDTyp8) N OD.OprDdListDm
  | 0b111110u | 0b111111u (* 11111x *) ->
    parseAdvSIMDDupScalar phlp &itstate isInIT b
  | _ when pickBit b 6 = 0u (* x != 11 xx 0 *) ->
    parseAdvSIMDThreeRegsDiffLen phlp &itstate isInIT b
  | _ (* x != 11 xx 1 *) ->
    parseAdvSIMDTwoRegsAndScalar phlp &itstate isInIT b

/// Advanced SIMD one register and modified immediate on page F3-4173.
let parseAdvSIMDOneRegAndModImm phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickFour bin 8) (pickBit bin 5) 1 (* cmode:op *) with
  | 0b00000u | 0b00100u | 0b01000u | 0b01100u (* 0xx00 *) ->
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdImm32T else OD.OprQdImm32T
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypI32) N oprs
  | 0b00001u | 0b00101u | 0b01001u | 0b01101u (* 0xx01 *) ->
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdImm32T else OD.OprQdImm32T
    render phlp &itstate 0 isInIT bin Op.VMVN (oneDt SIMDTypI32) N oprs
  | 0b00010u | 0b00110u | 0b01010u | 0b01110u (* 0xx10 *) ->
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdImm32T else OD.OprQdImm32T
    render phlp &itstate 0 isInIT bin Op.VORR (oneDt SIMDTypI32) N oprs
  | 0b00011u | 0b00111u | 0b01011u | 0b01111u (* 0xx11 *) ->
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdImm32T else OD.OprQdImm32T
    render phlp &itstate 0 isInIT bin Op.VBIC (oneDt SIMDTypI32) N oprs
  | 0b10000u | 0b10100u (* 10x00 *) ->
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdImm16T else OD.OprQdImm16T
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypI16) N oprs
  | 0b10001u | 0b10101u (* 10x01 *) ->
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdImm16T else OD.OprQdImm16T
    render phlp &itstate 0 isInIT bin Op.VMVN (oneDt SIMDTypI16) N oprs
  | 0b10010u | 0b10110u (* 10x10 *) ->
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdImm16T else OD.OprQdImm16T
    render phlp &itstate 0 isInIT bin Op.VORR (oneDt SIMDTypI16) N oprs
  | 0b10011u | 0b10111u (* 10x11 *) ->
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdImm16T else OD.OprQdImm16T
    render phlp &itstate 0 isInIT bin Op.VBIC (oneDt SIMDTypI16) N oprs
  (* VMOV 11xx0 *)
  | 0b11000u | 0b11010u ->
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdImm32T else OD.OprQdImm32T
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypI32) N oprs
  | 0b11100u ->
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdImm8T else OD.OprQdImm8T
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypI8) N oprs
  | 0b11110u ->
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdImmF32T else OD.OprQdImmF32T
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypF32) N oprs
  | 0b11001u | 0b11011u (* 110x1 *) ->
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdImm32T else OD.OprQdImm32T
    render phlp &itstate 0 isInIT bin Op.VMVN (oneDt SIMDTypI32) N oprs
  | 0b11101u ->
#if !EMULATION
    chkQVd bin
#endif
    let oprs = if pickBit bin 6 = 0u then OD.OprDdImm64T else OD.OprQdImm64T
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypI64) N oprs
  | _ (* 11111 *) -> raise ParsingFailureException

/// Advanced SIMD two registers and shift amount on page F3-4174.
let parseAdvSIMDTwoRegsAndShfAmt phlp (itstate: byref<BL>) isInIT bin =
  let decodeFields (* U:opc:Q *) =
    (pickBit bin 28 <<< 5) + (pickFour bin 8 <<< 1) + pickBit bin 6
  match decodeFields with
  | _ when concat (pickThree bin 19) (pickBit bin 7) 1 (* imm3H:L *) = 0u ->
    raise ParsingFailureException
  (* VSHR x0000x *)
  | 0b000000u | 0b100000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTLImmT bin
    render phlp &itstate 0 isInIT bin Op.VSHR dt N OD.OprDdDmImm
  | 0b000001u | 0b100001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTLImmT bin
    render phlp &itstate 0 isInIT bin Op.VSHR dt N OD.OprQdQmImm
  (* VSRA x0001x *)
  | 0b000010u | 0b100010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTLImmT bin
    render phlp &itstate 0 isInIT bin Op.VSRA dt N OD.OprDdDmImm
  | 0b000011u | 0b100011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTLImmT bin
    render phlp &itstate 0 isInIT bin Op.VSRA dt N OD.OprQdQmImm
  (* VMOVL x10100 *)
  | 0b010100u | 0b110100u when extract bin 18 6 (* imm3L *) = 0u ->
#if !EMULATION
    chkVd bin
#endif
    let dt = getDTUImm3hT bin
    render phlp &itstate 0 isInIT bin Op.VMOVL dt N OD.OprQdDm
  (* VRSHR x0010x *)
  | 0b000100u | 0b100100u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTLImmT bin
    render phlp &itstate 0 isInIT bin Op.VRSHR dt N OD.OprDdDmImm
  | 0b000101u | 0b100101u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTLImmT bin
    render phlp &itstate 0 isInIT bin Op.VRSHR dt N OD.OprQdQmImm
  (* VRSRA x0011x *)
  | 0b000110u | 0b100110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTLImmT bin
    render phlp &itstate 0 isInIT bin Op.VRSRA dt N OD.OprDdDmImm
  | 0b000111u | 0b100111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTLImmT bin
    render phlp &itstate 0 isInIT bin Op.VRSRA dt N OD.OprQdQmImm
  (* VQSHL x0111x *)
  | 0b001110u | 0b101110u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTLImmT bin
    render phlp &itstate 0 isInIT bin Op.VQSHL dt N OD.OprDdDmImmLeft
  | 0b001111u | 0b101111u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTLImmT bin
    render phlp &itstate 0 isInIT bin Op.VQSHL dt N OD.OprQdQmImmLeft
  (* VQSHRN x10010 *)
  | 0b010010u | 0b110010u ->
#if !EMULATION
    chkVm bin
#endif
    let dt = getDTImm6WordT bin
    render phlp &itstate 0 isInIT bin Op.VQSHRN dt N OD.OprDdQmImm
  (* VQRSHRN x10011 *)
  | 0b010011u | 0b110011u ->
#if !EMULATION
    chkVm bin
#endif
    let dt = getDTImm6WordT bin
    render phlp &itstate 0 isInIT bin Op.VQRSHRN dt N OD.OprDdQmImm
  (* VSHLL x10100 *)
  | 0b010100u | 0b110100u ->
#if !EMULATION
    chkVd bin
#endif
    let dt = getDTImm6ByteT bin
    render phlp &itstate 0 isInIT bin Op.VSHLL dt N OD.OprQdDmImm
  (* VCVT x11xxx *)
  | b when b &&& 0b011001u = 0b011000u ->
#if !EMULATION
    chkOpImm6QVdVm bin
#endif
    let dt = getDTOpU bin
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprDdDmFbits
  | b when b &&& 0b011001u = 0b011001u ->
#if !EMULATION
    chkOpImm6QVdVm bin
#endif
    let dt = getDTOpU bin
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprQdQmFbits
  (* VSHL 00101x *)
  | 0b001010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTImm6 bin
    render phlp &itstate 0 isInIT bin Op.VSHL dt N OD.OprDdDmImm
  | 0b001011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTImm6 bin
    render phlp &itstate 0 isInIT bin Op.VSHL dt N OD.OprQdQmImm
  (* VSHRN 010000 *)
  | 0b010000u ->
#if !EMULATION
    chkVm bin
#endif
    let dt = getDTImm6Int bin
    render phlp &itstate 0 isInIT bin Op.VSHRN dt N OD.OprDdQmImm
  (* VRSHRN 010001 *)
  | 0b010001u ->
#if !EMULATION
    chkVm bin
#endif
    let dt = getDTImm6Int bin
    render phlp &itstate 0 isInIT bin Op.VRSHRN dt N OD.OprDdQmImm
  (* VSRI 10100x *)
  | 0b101000u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTImm6 bin
    render phlp &itstate 0 isInIT bin Op.VSRI dt N OD.OprDdDmImm
  | 0b101001u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTImm6 bin
    render phlp &itstate 0 isInIT bin Op.VSRI dt N OD.OprQdQmImm
  (* VSLI 10101x *)
  | 0b101010u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTImm6 bin
    render phlp &itstate 0 isInIT bin Op.VSLI dt N OD.OprDdDmImmLeft
  | 0b101011u ->
#if !EMULATION
    chkQVdVm bin
#endif
    let dt = getDTImm6 bin
    render phlp &itstate 0 isInIT bin Op.VSLI dt N OD.OprQdQmImmLeft
  (* VQSHLU 10110x *)
  | 0b101100u ->
#if !EMULATION
    chkUOpQVdVm bin
#endif
    let dt = getDTLImmT bin
    render phlp &itstate 0 isInIT bin Op.VQSHLU dt N OD.OprDdDmImmLeft
  | 0b101101u ->
#if !EMULATION
    chkUOpQVdVm bin
#endif
    let dt = getDTLImmT bin
    render phlp &itstate 0 isInIT bin Op.VQSHLU dt N OD.OprQdQmImmLeft
  (* VQSHRUN 110000 *)
  | 0b110000u ->
#if !EMULATION
    chkVm bin
#endif
    let dt = getDTImm6WordT bin
    render phlp &itstate 0 isInIT bin Op.VQSHRUN dt N OD.OprDdQmImm
  (* VQRSHRUN 110001 *)
  | 0b110001u ->
#if !EMULATION
    chkVm bin
#endif
    let dt = getDTImm6WordT bin
    render phlp &itstate 0 isInIT bin Op.VQRSHRUN dt N OD.OprDdQmImm
  | _ -> B2R2.Utils.futureFeature ()

/// Advanced SIMD shifts and immediate generation on page F3-4173.
let parseAdvSIMDShfsAndImmGen phlp (itstate: byref<BL>) isInIT bin =
  if concat (pickThree bin 19) (pickBit bin 7) 1 = 0b0000u then
    parseAdvSIMDOneRegAndModImm phlp &itstate isInIT bin
  else parseAdvSIMDTwoRegsAndShfAmt phlp &itstate isInIT bin

/// Advanced SIMD data-processing on page F3-4165.
let parseAdvSIMDDataProcess phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickBit bin 23) (pickBit bin 4) 1 (* op0:op1 *) with
  | 0b00u | 0b01u ->
    parseAdvSIMDThreeRegsOfSameLen phlp &itstate isInIT bin
  | 0b10u ->
    parseAdvSIMDTwoOrThreeRegsDiffLen phlp &itstate isInIT bin
  | _ (* 11 *) ->
    parseAdvSIMDShfsAndImmGen phlp &itstate isInIT bin

/// Advanced SIMD and floating-point 64-bit move on page F3-4175.
let parseAdvSIMDAndFP64BitMove phlp (itstate: byref<BL>) isInIT bin =
  let decodeFields (* D:op:size:opc2:o3 *) =
    (pickBit bin 22 <<< 6) + (pickBit bin 20 <<< 5) + (pickFour bin 6 <<< 1) +
    (pickBit bin 4)
  match decodeFields with
  | b when b &&& 0b1000000u = 0b0000000u (* 0xxxxxx *) ->
    raise ParsingFailureException
  | b when b &&& 0b1000001u = 0b1000000u (* 1xxxxx0 *) ->
    raise ParsingFailureException
  | b when b &&& 0b1010111u = 0b1000001u (* 1x0x001 *) ->
    raise ParsingFailureException
  | b when b &&& 0b1000110u = 0b1000010u (* 1xxx01x *) ->
    raise ParsingFailureException
  | 0b1010001u (* 1010001 *) ->
#if !EMULATION
    chkPCRtRt2VmRegsEq bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV None N OD.OprSmSm1RtRt2
  | 0b1011001u (* 1011001 *) ->
#if !EMULATION
    chkPCRtRt2ArmEq bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV None N OD.OprDmRtRt2
  | b when b &&& 0b1000100u = 0b1000100u (* 1xxx1xx *) ->
    raise ParsingFailureException
  | 0b1110001u (* 1110001 *) ->
#if !EMULATION
    chkPCRtRt2VmRegsEq bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV None N OD.OprRtRt2SmSm1
  | _ (* 1111001 *) ->
#if !EMULATION
    chkPCRtRt2ArmEq bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV None N OD.OprRtRt2Dm

/// System register 64-bit move on page F3-4176.
let parseSystemReg64BitMove phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickBit bin 22) (pickBit bin 20) 1 (* D:L *) with
  | 0b00u | 0b01u -> raise ParsingFailureException
  | 0b10u ->
#if !EMULATION
    chkPCRtRt2 bin
#endif
    render phlp &itstate 0 isInIT bin Op.MCRR None N OD.OprCpOpc1RtRt2CRm
  | _ (* 10 *) ->
#if !EMULATION
    chkThumbPCRtRt2Eq bin
#endif
    render phlp &itstate 0 isInIT bin Op.MRRC None N OD.OprCpOpc1RtRt2CRm

/// Advanced SIMD and floating-point load/store on page F3-4176.
let parseAdvSIMDAndFPLdSt phlp (itstate: byref<BL>) isInIT bin =
  let isNot1111 = pickFour bin 16 (* Rn *) <> 0b1111u
  let isxxxxxxx0 = pickBit bin 0 (* imm8<0> *) = 0u
  let decodeFields (* P:U:W:L:size *) =
    (pickTwo bin 23 <<< 4) + (pickTwo bin 20 <<< 2) + (pickTwo bin 8)
  match decodeFields with
  | b when b &&& 0b111000u = 0b001000u (* 001xxx *) ->
    raise ParsingFailureException
  | b when b &&& 0b110010u = 0b010000u (* 01xx0x *) ->
    raise ParsingFailureException
  | 0b010010u | 0b011010u (* 01x010 *) ->
#if !EMULATION
    chkPCRnDRegs bin
#endif
    render phlp &itstate 0 isInIT bin Op.VSTMIA None N OD.OprRnSreglist
  | 0b010011u | 0b011011u (* 01x011 *) when isxxxxxxx0 ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp &itstate 0 isInIT bin Op.VSTMIA None N OD.OprRnDreglist
  | 0b010011u | 0b011011u (* 01x011 *) ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp &itstate 0 isInIT bin Op.FSTMIAX None N OD.OprRnDreglist
  | 0b010110u | 0b011110u (* 01x110 *) ->
#if !EMULATION
    chkPCRnDRegs bin
#endif
    render phlp &itstate 0 isInIT bin Op.VLDMIA None N OD.OprRnSreglist
  | 0b010111u | 0b011111u (* 01x111 *) when isxxxxxxx0 ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp &itstate 0 isInIT bin Op.VLDMIA None N OD.OprRnDreglist
  | 0b010111u | 0b011111u (* 01x111 *) ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp &itstate 0 isInIT bin Op.FLDMIAX None N OD.OprRnDreglist
  (* VSTR 1x00xx *)
  | 0b100000u | 0b110000u (* size = 00 *) -> raise UndefinedException
  | 0b100001u | 0b110001u ->
#if !EMULATION
    chkSzIT bin itstate
#endif
    let dt = oneDt SIMDTyp16
    render phlp &itstate 0 isInIT bin Op.VSTR dt N OD.OprSdMem
  | 0b100010u | 0b110010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VSTR None N OD.OprSdMem
  | 0b100011u | 0b110011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VSTR None N OD.OprDdMem
  (* VLDR 1x01xx *)
  | 0b100100u | 0b110100u when isNot1111 -> raise UndefinedException
  | 0b100101u | 0b110101u when isNot1111 ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTyp16
    render phlp &itstate 0 isInIT bin Op.VLDR dt N OD.OprSdMem
  | 0b100110u | 0b110110u when isNot1111 ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VLDR None N OD.OprSdMem
  | 0b100111u | 0b110111u when isNot1111 ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VLDR None N OD.OprDdMem
  | 0b101000u | 0b101001u | 0b101100u | 0b101101u (* 101x0x *) ->
    raise ParsingFailureException
  | 0b101010u ->
#if !EMULATION
    chkPCRnDRegs bin
#endif
    render phlp &itstate 0 isInIT bin Op.VSTMDB None N OD.OprRnSreglist
  | 0b101011u when isxxxxxxx0 ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp &itstate 0 isInIT bin Op.VSTMDB None N OD.OprRnDreglist
  | 0b101011u ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp &itstate 0 isInIT bin Op.FSTMDBX None N OD.OprRnDreglist
  | 0b101110u ->
#if !EMULATION
    chkPCRnDRegs bin
#endif
    render phlp &itstate 0 isInIT bin Op.VLDMDB None N OD.OprRnSreglist
  | 0b101111u when isxxxxxxx0 ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp &itstate 0 isInIT bin Op.VLDMDB None N OD.OprRnDreglist
  | 0b101111u ->
#if !EMULATION
    chkPCRnRegsImm bin
#endif
    render phlp &itstate 0 isInIT bin Op.FLDMDBX None N OD.OprRnDreglist
  (* VLDR 1x01xx *)
  | 0b100100u | 0b110100u (* size = 00 *) -> raise UndefinedException
  | 0b100101u | 0b110101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTyp16
    render phlp &itstate 0 isInIT bin Op.VLDR dt N OD.OprSdMem
  | 0b100110u | 0b110110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTyp32
    render phlp &itstate 0 isInIT bin Op.VLDR dt N OD.OprSdMem
  | 0b100111u | 0b110111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTyp64
    render phlp &itstate 0 isInIT bin Op.VLDR dt N OD.OprDdMem
  | b when b &&& 0b111000u = 0b111000u (* 111xxx *) ->
    raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// System register Load/Store on page F3-4177.
let parseSystemRegLdSt phlp (itstate: byref<BL>) isInIT bin =
  let puw = concat (pickTwo bin 23) (pickBit bin 21) 1 (* P:U:W *)
  let rn = pickFour bin 16 (* Rn *)
  let crd = pickFour bin 12 (* CRd *)
  let decodeField1 = (* D:L:cp15 *)
    (pickBit bin 22 <<< 2) + (pickBit bin 20 <<< 1) + (pickBit bin 8)
  let decodeField2 = (* P:U:W:D:L:CRd:cp15 *)
    (puw <<< 7) + (pickBit bin 22 <<< 6) + (pickBit bin 20 <<< 5) + (crd <<< 1)
    + (pickBit bin 8)
  match decodeField1 (* D:L:cp15 *) with
  | 0b000u | 0b010u | 0b100u | 0b110u (* xx0 *)
    when puw <> 0b000u && crd <> 0b0101u -> raise ParsingFailureException
  | 0b010u when puw <> 0b000u && rn = 0b1111u && crd = 0b0101u ->
    (* if W == '1' then UNPREDICTABLE *)
    pickBit bin 21 = 1u |> checkUnpred
    render phlp &itstate 0 isInIT bin Op.LDC None N OD.OprP14C5Label
  | 0b001u | 0b001u | 0b011u | 0b111u (* xx1 *) when puw <> 0b000u ->
    raise ParsingFailureException
  | 0b100u | 0b110u (* 1x0 *) when puw <> 0b000u && crd = 0b0101u ->
    raise ParsingFailureException
  | _ ->
    match decodeField2 (* P:U:W:D:L:CRd:cp15 *) with
    | 0b0010001010u | 0b0110001010u (* 0x10001010 *) ->
#if !EMULATION
      chkPCRnWback bin
#endif
      render phlp &itstate 0 isInIT bin Op.STC None N OD.OprP14C5Mem
    | 0b0010101010u | 0b0110101010u (* 0x10101010 *) when rn <> 0b1111u ->
      render phlp &itstate 0 isInIT bin Op.LDC None N OD.OprP14C5Mem
    | 0b0100001010u ->
#if !EMULATION
      chkPCRnWback bin
#endif
      render phlp &itstate 0 isInIT bin Op.STC None N OD.OprP14C5Option
    | 0b0100101010u when rn <> 0b1111u ->
      render phlp &itstate 0 isInIT bin Op.LDC None N OD.OprP14C5Option
    | 0b1000001010u | 0b1100001010u (* 1x00001010 *) ->
#if !EMULATION
      chkPCRnWback bin
#endif
      render phlp &itstate 0 isInIT bin Op.STC None N OD.OprP14C5Mem
    | 0b1000101010u | 0b1100101010u (* 1x00101010 *) when rn <> 0b1111u ->
      render phlp &itstate 0 isInIT bin Op.LDC None N OD.OprP14C5Mem
    | 0b1010001010u | 0b1110001010u (* 1x10001010 *) ->
#if !EMULATION
      chkPCRnWback bin
#endif
      render phlp &itstate 0 isInIT bin Op.STC None N OD.OprP14C5Mem
    | 0b1010101010u | 0b1110101010u (* 1x10101010 *) when rn <> 0b1111u ->
      render phlp &itstate 0 isInIT bin Op.LDC None N OD.OprP14C5Mem
    | _ -> raise ParsingFailureException

/// Advanced SIMD and System register load/store and 64-bit move
/// on page F3-4174.
let parseAdvSIMDAndSysRegLdStAnd64BitMov phlp (itstate: byref<BL>) isInIT bin =
  let is00x0 = pickFour bin 21 &&& 0b1101u = 0b0000u (* op0 *)
  match pickTwo bin 9 (* op1 *) with
  | 0b00u | 0b01u (* 0x *) when is00x0 ->
    parseAdvSIMDAndFP64BitMove phlp &itstate isInIT bin
  | 0b11u when is00x0 -> parseSystemReg64BitMove phlp &itstate isInIT bin
  | 0b00u | 0b01u (* 0x *) -> parseAdvSIMDAndFPLdSt phlp &itstate isInIT bin
  | 0b11u -> parseSystemRegLdSt phlp &itstate isInIT bin
  | _ (* 10 *) -> raise ParsingFailureException

/// Floating-point data-processing (two registers) on page F3-4178.
let parseFPDataProcTwoRegs phlp (itstate: byref<BL>) isInIT bin =
  match (pickFour bin 16 <<< 3) + (pickThree bin 7) (* o1:opc2:size:o3 *) with
  | b when b &&& 0b0000110u = 0u (* xxxx00x *) -> raise ParsingFailureException
  | 0b0000010u -> raise ParsingFailureException
  (* VABS 0000xx1 *)
  | 0b0000001u (* size = 00 *) -> raise UndefinedException
  | 0b0000011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VABS dt N OD.OprSdSm
  | 0b0000101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VABS dt N OD.OprSdSm
  | 0b0000111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VABS dt N OD.OprDdDm
  (* VMOV *)
  | 0b0000100u ->
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VMOV dt N OD.OprSdSm
  | 0b0000110u ->
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VMOV dt N OD.OprDdDm
  (* VNEG 0001xx0 *)
  | 0b0001000u (* size = 00 *) -> raise UndefinedException
  | 0b0001010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VNEG dt N OD.OprSdSm
  | 0b0001100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VNEG dt N OD.OprSdSm
  | 0b0001110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VNEG dt N OD.OprDdDm
  (* VSQRT 0001xx1 *)
  | 0b0001001u (* size = 00 *) -> raise UndefinedException
  | 0b0001011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VSQRT dt N OD.OprSdSm
  | 0b0001101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VSQRT dt N OD.OprSdSm
  | 0b0001111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VSQRT dt N OD.OprDdDm
  (* VCVTB 0010xx0 *)
  | 0b0010100u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVTB dt N OD.OprSdSm
  | 0b0010110u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVTB dt N OD.OprDdSm
  | 0b0010010u | 0b0010011u (* 001001x *) -> raise ParsingFailureException
  (* VCVTT 0010xx1 *)
  | 0b0010101u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVTT dt N OD.OprSdSm
  | 0b0010111u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVTT dt N OD.OprDdSm
  | 0b0011010u -> (* Armv8.6 *)
    let dt = twoDt (BF16, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVTB dt N OD.OprSdSm
  | 0b0011011u -> (* Armv8.6 *)
    let dt = twoDt (BF16, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVTT dt N OD.OprSdSm
  | 0b0011100u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render phlp &itstate 0 isInIT bin Op.VCVTB dt N OD.OprSdSm
  | 0b0011101u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF32)
    render phlp &itstate 0 isInIT bin Op.VCVTT dt N OD.OprSdSm
  | 0b0011110u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF64)
    render phlp &itstate 0 isInIT bin Op.VCVTB dt N OD.OprSdDm
  | 0b0011111u ->
    let dt = twoDt (SIMDTypF16, SIMDTypF64)
    render phlp &itstate 0 isInIT bin Op.VCVTT dt N OD.OprSdDm
  (* VCMP 0100xx0 *)
  | 0b0100000u (* size = 00 *) -> raise UndefinedException
  | 0b0100010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VCMP dt N OD.OprSdSm
  | 0b0100100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VCMP dt N OD.OprSdSm
  | 0b0100110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VCMP dt N OD.OprDdDm
  (* 0100xx1 VCMPE *)
  | 0b0100001u (* size = 00 *) -> raise UndefinedException
  | 0b0100011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VCMPE dt N OD.OprSdSm
  | 0b0100101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VCMPE dt N OD.OprSdSm
  | 0b0100111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VCMPE dt N OD.OprDdDm
  (* 0101xx0 VCMP *)
  | 0b0101000u (* size = 00 *) -> raise UndefinedException
  | 0b0101010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VCMP dt N OD.OprSdImm0
  | 0b0101100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VCMP dt N OD.OprSdImm0
  | 0b0101110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VCMP dt N OD.OprDdImm0
  (* 0101xx1 VCMPE *)
  | 0b0101001u (* size = 00 *) -> raise UndefinedException
  | 0b0101011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VCMPE dt N OD.OprSdImm0
  | 0b0101101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VCMPE dt N OD.OprSdImm0
  | 0b0101111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VCMPE dt N OD.OprDdImm0
  (* 0110xx0 VRINTR ARMv8 *)
  | 0b0110010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VRINTR dt N OD.OprSdSm
  | 0b0110100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VRINTR dt N OD.OprSdSm
  | 0b0110110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VRINTR dt N OD.OprDdDm
  (* 0110xx1 VRINTZ ARMv8 *)
  | 0b0110001u (* size = 00 *) -> raise UndefinedException
  | 0b0110011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VRINTZ dt N OD.OprSdSm
  | 0b0110101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VRINTZ dt N OD.OprSdSm
  | 0b0110111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VRINTZ dt N OD.OprDdDm
  (* 0111xx0 VRINTX ARMv8 *)
  | 0b0111000u (* size = 00 *) -> raise UndefinedException
  | 0b0111010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VRINTX dt N OD.OprSdSm
  | 0b0111100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VRINTX dt N OD.OprSdSm
  | 0b0111110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VRINTX dt N OD.OprDdDm
  | 0b0111011u -> raise ParsingFailureException
  | 0b0111101u ->
    let dt = twoDt (SIMDTypF64, SIMDTypF32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprDdSm
  | 0b0111111u ->
    let dt = twoDt (SIMDTypF32, SIMDTypF64)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdDm
  (* 1000xxx VCVT *)
  | 0b1000000u | 0b1000001u (* size = 00 *) -> raise UndefinedException
  | 0b1000010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypU32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdSm
  | 0b1000011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypS32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdSm
  | 0b1000100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdSm
  | 0b1000101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdSm
  | 0b1000110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF64, SIMDTypU32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprDdSm
  | 0b1000111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF64, SIMDTypS32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprDdSm
  | 0b1001010u | 0b1001011u (* 100101x *) -> raise ParsingFailureException
  | 0b1001100u | 0b1001101u (* 100110x *) -> raise ParsingFailureException
  | 0b1001110u -> raise ParsingFailureException
  | 0b1001111u -> (* Armv8.3 *)
    inITBlock itstate |> checkUnpred
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render phlp &itstate 0 isInIT bin Op.VJCVT dt N OD.OprSdDm
  (* 101xxxx Op.VCVT *)
  | 0b1010000u | 0b1010001u | 0b1011000u | 0b1011001u (* sf = 00 *) ->
    raise UndefinedException
  | 0b1010010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypS16)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1010011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypS32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1011010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypU16)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1011011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF16, SIMDTypU32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1010100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypS16)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1010101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypS32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1011100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypU16)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1011101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF32, SIMDTypU32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1010110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF64, SIMDTypS16)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprDdmDdmFbits
  | 0b1010111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF64, SIMDTypS32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprDdmDdmFbits
  | 0b1011110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF64, SIMDTypU16)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprDdmDdmFbits
  | 0b1011111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypF64, SIMDTypU32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprDdmDdmFbits
  (* 1100xx0 VCVTR *)
  | 0b1100000u (* size = 00 *) -> raise UndefinedException
  | 0b1100010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVTR dt N OD.OprSdSm
  | 0b1100100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp &itstate 0 isInIT bin Op.VCVTR dt N OD.OprSdSm
  | 0b1100110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render phlp &itstate 0 isInIT bin Op.VCVTR dt N OD.OprSdDm
  (* 1100xx1 VCVT *)
  | 0b1100001u (* size = 00 *) -> raise UndefinedException
  | 0b1100011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdSm
  | 0b1100101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdSm
  | 0b1100111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdDm
  (* 1101xx0 VCVTR *)
  | 0b1101000u (* size = 00 *) -> raise UndefinedException
  | 0b1101010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVTR dt N OD.OprSdSm
  | 0b1101100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp &itstate 0 isInIT bin Op.VCVTR dt N OD.OprSdSm
  | 0b1101110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render phlp &itstate 0 isInIT bin Op.VCVTR dt N OD.OprSdDm
  (* 1101xx1u VCVT *)
  | 0b1101001u (* size = 00 *) -> raise UndefinedException
  | 0b1101011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdSm
  | 0b1101101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdSm
  | 0b1101111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdDm
  (* 111xxxx VCVT *)
  | 0b1110000u | 0b1110001u | 0b1111000u | 0b1111001u (* size = 00 *) ->
    raise UndefinedException
  | 0b1110010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1110011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1111010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1111011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF16)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1110100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1110101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1111100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1111101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF32)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprSdmSdmFbits
  | 0b1110110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypS16, SIMDTypF64)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprDdmDdmFbits
  | 0b1110111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypS32, SIMDTypF64)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprDdmDdmFbits
  | 0b1111110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypU16, SIMDTypF64)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprDdmDdmFbits
  | 0b1111111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = twoDt (SIMDTypU32, SIMDTypF64)
    render phlp &itstate 0 isInIT bin Op.VCVT dt N OD.OprDdmDdmFbits
  | _ -> raise ParsingFailureException

/// Floating-point move immediate on page F3-4180.
let parseFPMoveImm phlp (itstate: byref<BL>) isInIT bin =
  match pickTwo bin 8 (* size *) with
  | 0b00u -> raise ParsingFailureException
  | 0b01u -> (* Armv8.2 *)
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VMOV dt N OD.OprSdVImm
  | 0b10u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VMOV dt N OD.OprSdVImm
  | _ (* 11 *) ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VMOV dt N OD.OprDdVImm

/// Floating-point data-processing (three registers) on page F3-4180.
let parseFPDataProcThreeRegs phlp (itstate: byref<BL>) isInIT bin =
  let decodeFields (* o0:o1:size:o2 *) =
    (pickBit bin 23 <<< 5) + (pickTwo bin 20 <<< 3) + (pickTwo bin 8 <<< 1)
    + (pickBit bin 6)
  match decodeFields with
  | b when (b >>> 3 <> 0b111u) && (b &&& 0b000110u = 0b000u) (* != 111 00x *) ->
    raise ParsingFailureException
  (* 000xx0 VMLA *)
  | 0b000000u (* size = 00 *) -> raise UndefinedException
  | 0b000010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VMLA dt N OD.OprSdSnSm
  | 0b000100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VMLA dt N OD.OprSdSnSm
  | 0b000110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VMLA dt N OD.OprDdDnDm
  (* 000xx1 VMLS *)
  | 0b000001u (* size = 00 *) -> raise UndefinedException
  | 0b000011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VMLS dt N OD.OprSdSnSm
  | 0b000101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VMLS dt N OD.OprSdSnSm
  | 0b000111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VMLS dt N OD.OprDdDnDm
  (* 001xx0 VNMLS *)
  | 0b001000u (* size = 00 *) -> raise UndefinedException
  | 0b001010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VNMLS dt N OD.OprSdSnSm
  | 0b001100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VNMLS dt N OD.OprSdSnSm
  | 0b001110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VNMLS dt N OD.OprDdDnDm
  (* 001xx1 VNMLA *)
  | 0b001001u (* size = 00 *) -> raise UndefinedException
  | 0b001011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VNMLA dt N OD.OprSdSnSm
  | 0b001101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VNMLA dt N OD.OprSdSnSm
  | 0b001111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VNMLA dt N OD.OprDdDnDm
  (* 010xx0 VMUL *)
  | 0b010000u (* size = 00 *) -> raise UndefinedException
  | 0b010010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VMUL dt N OD.OprSdSnSm
  | 0b010100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VMUL dt N OD.OprSdSnSm
  | 0b010110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VMUL dt N OD.OprDdDnDm
  (* 010xx1 VNMUL *)
  | 0b010001u (* size = 00 *) -> raise UndefinedException
  | 0b010011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VNMUL dt N OD.OprSdSnSm
  | 0b010101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VNMUL dt N OD.OprSdSnSm
  | 0b010111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VNMUL dt N OD.OprDdDnDm
  (* 011xx0 VADD *)
  | 0b011000u (* size = 00 *) -> raise UndefinedException
  | 0b011010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VADD dt N OD.OprSdSnSm
  | 0b011100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VADD dt N OD.OprSdSnSm
  | 0b011110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VADD dt N OD.OprDdDnDm
  (* 011xx1 VSUB *)
  | 0b011001u (* size = 00 *) -> raise UndefinedException
  | 0b011011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VSUB dt N OD.OprSdSnSm
  | 0b011101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VSUB dt N OD.OprSdSnSm
  | 0b011111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VSUB dt N OD.OprDdDnDm
  (* 100xx0 VDIV *)
  | 0b100000u (* size = 00 *) -> raise UndefinedException
  | 0b100010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VDIV dt N OD.OprSdSnSm
  | 0b100100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VDIV dt N OD.OprSdSnSm
  | 0b100110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VDIV dt N OD.OprDdDnDm
  (* 101xx0 VFNMS *)
  | 0b101000u (* size = 00 *) -> raise UndefinedException
  | 0b101010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VFNMS dt N OD.OprSdSnSm
  | 0b101100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VFNMS dt N OD.OprSdSnSm
  | 0b101110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VFNMS dt N OD.OprDdDnDm
  (* 101xx1 VFNMA *)
  | 0b101001u (* size = 00 *) -> raise UndefinedException
  | 0b101011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VFNMA dt N OD.OprSdSnSm
  | 0b101101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VFNMA dt N OD.OprSdSnSm
  | 0b101111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VFNMA dt N OD.OprDdDnDm
  (* 110xx0 VFMA *)
  | 0b110000u (* size = 00 *) -> raise UndefinedException
  | 0b110010u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VFMA dt N OD.OprSdSnSm
  | 0b110100u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VFMA dt N OD.OprSdSnSm
  | 0b110110u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VFMA dt N OD.OprDdDnDm
  (* 110xx1 VFMS *)
  | 0b110001u (* size = 00 *) -> raise UndefinedException
  | 0b110011u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VFMS dt N OD.OprSdSnSm
  | 0b110101u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VFMS dt N OD.OprSdSnSm
  | 0b110111u ->
#if !EMULATION
    chkSz01IT bin itstate
#endif
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VFMS dt N OD.OprDdDnDm
  | _ -> raise ParsingFailureException

/// Floating-point data-processing on page F3-4178.
let parseFPDataProcessing phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickFour bin 20) (pickBit bin 6) 1 (* op0:op1 *) with
  | 0b10111u | 0b11111u (* 1x111 *) ->
    parseFPDataProcTwoRegs phlp &itstate isInIT bin
  | 0b10110u | 0b11110u (* 1x110 *) ->
    parseFPMoveImm phlp &itstate isInIT bin
  | _ (* != 1x11 x *) ->
    parseFPDataProcThreeRegs phlp &itstate isInIT bin

/// Floating-point move special register on page F3-4182.
let parseFPMoveSpecialReg phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMSR None N OD.OprSregRt
  | _ (* 0b1u *) ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMRS None N OD.OprRtSreg

/// Advanced SIMD 8/16/32-bit element move/duplicate on page F3-4182.
let parseAdvSIMD8n16n32BitElemMoveDup phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickFour bin 20) (pickTwo bin 5) 2 (* opc1:L:opc2 *) with
  (* 0xx0xx VMOV (general-purpose register to scalar) *)
  | 0b010000u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp8) N OD.OprDd0Rt
  | 0b010001u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp8) N OD.OprDd1Rt
  | 0b010010u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp8) N OD.OprDd2Rt
  | 0b010011u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp8) N OD.OprDd3Rt
  | 0b011000u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp8) N OD.OprDd4Rt
  | 0b011001u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp8) N OD.OprDd5Rt
  | 0b011010u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp8) N OD.OprDd6Rt
  | 0b011011u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp8) N OD.OprDd7Rt
  | 0b000001u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp16) N OD.OprDd0Rt
  | 0b000011u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp16) N OD.OprDd1Rt
  | 0b001001u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp16) N OD.OprDd2Rt
  | 0b001011u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp16) N OD.OprDd3Rt
  | 0b000000u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp32) N OD.OprDd0Rt
  | 0b001000u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp32) N OD.OprDd1Rt
  | 0b000010u | 0b001010u -> raise UndefinedException
  (* xxx1xx VMOV (scalar to general-purpose register) *)
  | 0b010100u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypS8) N OD.OprRtDn0
  | 0b010101u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypS8) N OD.OprRtDn1
  | 0b010110u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypS8) N OD.OprRtDn2
  | 0b010111u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypS8) N OD.OprRtDn3
  | 0b011100u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypS8) N OD.OprRtDn4
  | 0b011101u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypS8) N OD.OprRtDn5
  | 0b011110u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypS8) N OD.OprRtDn6
  | 0b011111u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypS8) N OD.OprRtDn7
  | 0b110100u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypU8) N OD.OprRtDn0
  | 0b110101u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypU8) N OD.OprRtDn1
  | 0b110110u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypU8) N OD.OprRtDn2
  | 0b110111u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypU8) N OD.OprRtDn3
  | 0b111100u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypU8) N OD.OprRtDn4
  | 0b111101u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypU8) N OD.OprRtDn5
  | 0b111110u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypU8) N OD.OprRtDn6
  | 0b111111u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypU8) N OD.OprRtDn7
  | 0b000101u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypS16) N OD.OprRtDn0
  | 0b000111u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypS16) N OD.OprRtDn1
  | 0b001101u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypS16) N OD.OprRtDn2
  | 0b001111u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypS16) N OD.OprRtDn3
  | 0b100101u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypU16) N OD.OprRtDn0
  | 0b100111u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypU16) N OD.OprRtDn1
  | 0b101101u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypU16) N OD.OprRtDn2
  | 0b101111u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypU16) N OD.OprRtDn3
  | 0b000100u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp32) N OD.OprRtDn0
  | 0b001100u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTyp32) N OD.OprRtDn1
  | 0b100100u | 0b101100u (* 10x100 *)
  | 0b000110u | 0b001110u | 0b100110u | 0b101110u (* x0x110 *) ->
    raise UndefinedException
  (* 1xx00x VDUP (general-purpose register) *)
  | 0b110000u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VDUP (oneDt SIMDTyp8) N OD.OprDdRt
  | 0b100001u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VDUP (oneDt SIMDTyp16) N OD.OprDdRt
  | 0b100000u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VDUP (oneDt SIMDTyp32) N OD.OprDdRt
  | 0b111000u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VDUP (oneDt SIMDTyp8) N OD.OprQdRt
  | 0b101001u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VDUP (oneDt SIMDTyp16) N OD.OprQdRt
  | 0b101000u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.VDUP (oneDt SIMDTyp32) N OD.OprQdRt
  | 0b111001u | 0b110001u -> raise UndefinedException
  | _ (* 1xx01x *) -> raise ParsingFailureException

/// System register 32-bit move on page F3-4183.
let parseSystemReg32BitMove phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.MCR None N OD.OprCpOpc1RtCRnCRmOpc2
  | _ (* 1 *) ->
    render phlp &itstate 0 isInIT bin Op.MRC None N OD.OprCpOpc1RtCRnCRmOpc2

/// Advanced SIMD and System register 32-bit move on page F3-4181.
let parseAdvSIMDAndSysReg32BitMov phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickThree bin 21) (pickThree bin 8) 3 (* op0:op1 *) with
  | 0b000000u -> raise ParsingFailureException
  | 0b000001u -> (* Armv8.2 *)
    inITBlock itstate |> checkUnpred
    let oprs = if pickBit bin 20 = 0u then OD.OprSnRt  else OD.OprRtSn
    render phlp &itstate 0 isInIT bin Op.VMOV (oneDt SIMDTypF16) N oprs
  | 0b000010u ->
#if !EMULATION
    chkPCRt bin
#endif
    let oprs = if pickBit bin 20 = 0u then OD.OprSnRt  else OD.OprRtSn
    render phlp &itstate 0 isInIT bin Op.VMOV None N oprs
  | 0b001010u -> raise ParsingFailureException
  | 0b010010u | 0b011010u (* 01x010 *) -> raise ParsingFailureException
  | 0b100010u | 0b101010u (* 10x010 *) -> raise ParsingFailureException
  | 0b110010u -> raise ParsingFailureException
  | 0b111010u -> parseFPMoveSpecialReg phlp &itstate isInIT bin
  | b when b &&& 0b000111u = 0b000011u (* xxx011 *) ->
    parseAdvSIMD8n16n32BitElemMoveDup phlp &itstate isInIT bin
  | b when b &&& 0b000110u = 0b000100u (* xxx10x *) ->
    raise ParsingFailureException
  | b when b &&& 0b000110u = 0b000110u (* xxx11x *) ->
    parseSystemReg32BitMove phlp &itstate isInIT bin
  | _ -> raise ParsingFailureException

/// Advanced SIMD three registers of the same length extension on page F3-4184.
let parseAdvSIMDThreeRegSameLenExt phlp (itstate: byref<BL>) isInIT bin =
  let decodeFields (* op1:op2:op3:op4:Q:U *) =
    (pickTwo bin 23 <<< 6) + (pickTwo bin 20 <<< 4) +
    (pickBit bin 10 <<< 3) + (pickBit bin 8 <<< 2) + (pickBit bin 6 <<< 1) +
    (pickBit bin 4)
  match decodeFields with
  (* VCADD 64-bit x10x0000 Armv8.3 *)
  | 0b01000000u | 0b11000000u (* x1000000 *) ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VCADD dt N OD.OprDdDnDmRotate
  | 0b01010000u | 0b11010000u (* x1010000 *) ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VCADD dt N OD.OprDdDnDmRotate
  | 0b01000001u | 0b01010001u | 0b11000001u | 0b11010001u (* x10x0001 *) ->
    raise ParsingFailureException
  (* VCADD 128-bit x10x0010 Armv8.3 *)
  | 0b01000010u | 0b11000010u (* x1000010 *) ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VCADD dt N OD.OprQdQnQmRotate
  | 0b01010010u | 0b11010010u (* x1010010 *) ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VCADD dt N OD.OprQdQnQmRotate
  | bin when bin &&& 0b01101111u = 0b01000011u (* x10x0011 *) ->
    raise ParsingFailureException
  | bin when bin &&& 0b11101100u = 0b00000000u (* 000x00xx *) ->
    raise ParsingFailureException
  | bin when bin &&& 0b11101100u = 0b00000100u (* 000x01xx *) ->
    raise ParsingFailureException
  | 0b00001000u -> raise ParsingFailureException
  | 0b00001001u -> raise ParsingFailureException
  (* VMMLA Armv8.6 *)
  | 0b00001010u ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VMMLA (oneDt BF16) N OD.OprQdQnQm
  | 0b00001011u -> raise ParsingFailureException
  (* VDOT 64-bit Armv8.6 *)
  | 0b00001100u ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VDOT (oneDt BF16) N OD.OprDdDnDm
  | 0b00001101u -> raise ParsingFailureException
  (* VDOT 128-bit Armv8.6 *)
  | 0b00001110u ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VDOT (oneDt BF16) N OD.OprQdQnQm
  | 0b00001111u -> raise ParsingFailureException
  | 0b00011000u | 0b00011001u | 0b00011010u | 0b00011011u (* 000110xx *) ->
    raise ParsingFailureException
  | 0b00011100u | 0b00011101u | 0b00011110u | 0b00011111u (* 000111xx *) ->
    raise ParsingFailureException
  (* VFMAL Armv8.2 *)
  | 0b00100001u ->
#if !EMULATION
    chkITQVd bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VFMAL (oneDt SIMDTypF16) N OD.OprDdSnSm
  | 0b00100011u ->
#if !EMULATION
    chkITQVd bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VFMAL (oneDt SIMDTypF16) N OD.OprQdDnDm
  | 0b00100100u | 0b00100101u | 0b00100110u | 0b00100111u (* 001001xx *) ->
    raise ParsingFailureException
  | 0b00101000u | 0b00101001u (* 0010100xu *) -> raise ParsingFailureException
  (* VSMMLA Armv8.6 *)
  | 0b00101010u ->
#if !EMULATION
    chkITVdVnVm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VSMMLA (oneDt SIMDTypS8) N OD.OprQdQnQm
  (* VUMMLA Armv8.6 *)
  | 0b00101011u ->
#if !EMULATION
    chkITVdVnVm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VUMMLA (oneDt SIMDTypU8) N OD.OprQdQnQm
  (* VSDOT 64-bit Armv8.2 *)
  | 0b00101100u ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VSDOT (oneDt SIMDTypS8) N OD.OprDdDnDm
   (* VUDOT 64-bit Armv8.2 *)
  | 0b00101101u ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VUDOT (oneDt SIMDTypU8) N OD.OprDdDnDm
  (* VSDOT 128-bit Armv8.2 *)
  | 0b00101110u ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VSDOT (oneDt SIMDTypS8) N OD.OprQdQnQm
  (* VUDOT 128-bit Armv8.2 *)
  | 0b00101111u ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VUDOT (oneDt SIMDTypU8) N OD.OprQdQnQm
  (* VFMAB Armv8.6 *)
  | 0b00110001u ->
#if !EMULATION
    chkITVdVnVm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VFMAB (oneDt BF16) N OD.OprQdQnQm
  (* VFMAT Armv8.6 *)
  | 0b00110011u ->
#if !EMULATION
    chkITVdVnVm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VFMAT (oneDt BF16) N OD.OprQdQnQm
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
    render phlp &itstate 0 isInIT bin Op.VFMSL (oneDt SIMDTypF16) N OD.OprDdSnSm
  | 0b01100011u -> (* Armv8.2 *)
#if !EMULATION
    chkQVd bin
#endif
    render phlp &itstate 0 isInIT bin Op.VFMSL (oneDt SIMDTypF16) N OD.OprQdDnDm
  | 0b01100100u | 0b01100101u | 0b01100110u | 0b01100111u (* 011001xx *) ->
    raise ParsingFailureException
  | 0b01101000u | 0b01101001u (* 0110100x *) -> raise ParsingFailureException
  (* VUSMMLA Armv8.6 *)
  | 0b01101010u ->
#if !EMULATION
    chkITVdVnVm bin itstate
#endif
    let dt = oneDt SIMDTypS8
    render phlp &itstate 0 isInIT bin Op.VUSMMLA dt N OD.OprQdQnQm
  | 0b01101011u -> raise ParsingFailureException
  (* VUSDOT 64-bit Armv8.6 *)
  | 0b01101100u ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VUSDOT (oneDt SIMDTypS8) N OD.OprDdDnDm
  | 0b01101101u | 0b01101111u (* 011011x1 *) -> raise ParsingFailureException
  (* VUSDOT 128-bit Armv8.6 *)
  | 0b01101110u ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.VUSDOT (oneDt SIMDTypS8) N OD.OprQdQnQm
  | 0b01110100u | 0b01110101u | 0b01110110u | 0b01110111u (* 011101xx *) ->
    raise ParsingFailureException
  | 0b01111000u | 0b01111001u | 0b01111010u | 0b01111011u (* 011110xx *) ->
    raise ParsingFailureException
  | 0b01111100u | 0b01111101u | 0b01111110u | 0b01111111u (* 011111xx *) ->
    raise ParsingFailureException
  (* VCMLA Armv8.3 *)
  | 0b00100000u ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VCMLA dt N OD.OprDdDnDmRotate
  | 0b00100010u ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VCMLA dt N OD.OprQdQnQmRotate
  | 0b00110000u ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VCMLA dt N OD.OprDdDnDmRotate
  | 0b00110010u ->
#if !EMULATION
    chkITQVdVnVm bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VCMLA dt N OD.OprQdQnQmRotate
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

/// VSELEQ, VSELGE, VSELGT, VSELVS on page F6-5579.
let parseVectorSelect phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickTwo bin 20) (pickTwo bin 8) 2 (* cc:size *) with
  | 0b0011u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VSELEQ dt N OD.OprDdDnDm
  | 0b0001u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VSELEQ dt N OD.OprSdSnSm
  | 0b0010u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VSELEQ dt N OD.OprSdSnSm
  | 0b1011u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VSELGE dt N OD.OprDdDnDm
  | 0b1001u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VSELGE dt N OD.OprSdSnSm
  | 0b1010u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VSELGE dt N OD.OprSdSnSm
  | 0b1111u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VSELGT dt N OD.OprDdDnDm
  | 0b1101u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VSELGT dt N OD.OprSdSnSm
  | 0b1110u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VSELGT dt N OD.OprSdSnSm
  | 0b0111u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF64
    render phlp &itstate 0 isInIT bin Op.VSELVS dt N OD.OprDdDnDm
  | 0b0101u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VSELVS dt N OD.OprSdSnSm
  | 0b0110u ->
    inITBlock itstate |> checkUnpred
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VSELVS dt N OD.OprSdSnSm
  | _ (* xx00 *) -> raise UndefinedException

/// Floating-point minNum/maxNum on page F3-4185.
let parseFPMinMaxNum phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 6 (* op *) with
  | 0b0u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFP bin
    let oprs = if pickTwo bin 8 = 0b11u then OD.OprDdDnDm  else OD.OprSdSnSm
    render phlp &itstate 0 isInIT bin Op.VMAXNM dt N oprs
  | _ (* 1 *) ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFP bin
    let oprs = if pickTwo bin 8 = 0b11u then OD.OprDdDnDm  else OD.OprSdSnSm
    render phlp &itstate 0 isInIT bin Op.VMINNM dt N OD.OprDdDnDm

/// Floating-point extraction and insertion on page F3-4186.
let parseFPExtractionAndInsertion phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickTwo bin 8) (pickBit bin 7) 1 (* size:op *) with
  | 0b010u | 0b011u (* 01x *) -> raise ParsingFailureException
  | 0b100u -> (* Armv8.2 *)
    render phlp &itstate 0 isInIT bin Op.VMOVX (oneDt SIMDTypF16) N OD.OprSdSm
  | 0b101u -> (* Armv8.2 *)
    render phlp &itstate 0 isInIT bin Op.VINS (oneDt SIMDTypF16) N OD.OprSdSm
  | 0b110u | 0b111u (* 11x *) -> raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// Floating-point directed convert to integer on page F3-4186.
let parseFPDirConvToInt phlp (itstate: byref<BL>) isInIT bin =
  match pickThree bin 16 (* o1:RM *) with
  | 0b000u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFP bin
    let oprs =
      if pickTwo bin 8 (* size *) = 0b11u then OD.OprDdDm  else OD.OprSdSm
    render phlp &itstate 0 isInIT bin Op.VRINTA dt N oprs
  | 0b001u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFP bin
    let oprs =
      if pickTwo bin 8 (* size *) = 0b11u then OD.OprDdDm  else OD.OprSdSm
    render phlp &itstate 0 isInIT bin Op.VRINTN dt N oprs
  | 0b010u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFP bin
    let oprs =
      if pickTwo bin 8 (* size *) = 0b11u then OD.OprDdDm  else OD.OprSdSm
    render phlp &itstate 0 isInIT bin Op.VRINTP dt N oprs
  | 0b011u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFP bin
    let oprs =
      if pickTwo bin 8 (* size *) = 0b11u then OD.OprDdDm  else OD.OprSdSm
    render phlp &itstate 0 isInIT bin Op.VRINTM dt N oprs
  | 0b100u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFSU bin
    let oprs =
      if pickTwo bin 8 (* size *) = 0b11u then OD.OprSdDm  else OD.OprSdSm
    render phlp &itstate 0 isInIT bin Op.VCVTA dt N oprs
  | 0b101u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFSU bin
    let oprs =
      if pickTwo bin 8 (* size *) = 0b11u then OD.OprSdDm  else OD.OprSdSm
    render phlp &itstate 0 isInIT bin Op.VCVTN dt N oprs
  | 0b110u ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFSU bin
    let oprs =
      if pickTwo bin 8 (* size *) = 0b11u then OD.OprSdDm  else OD.OprSdSm
    render phlp &itstate 0 isInIT bin Op.VCVTP dt N oprs
  | _ (* 111 *) ->
    inITBlock itstate |> checkUnpred
    let dt = getDTFSU bin
    let oprs =
      if pickTwo bin 8 (* size *) = 0b11u then OD.OprSdDm  else OD.OprSdSm
    render phlp &itstate 0 isInIT bin Op.VCVTM dt N oprs

/// Advanced SIMD and floating-point multiply with accumulate on page F3-4187.
let parseAdvSIMDAndFPMulWithAcc phlp (itstate: byref<BL>) isInIT bin =
  let decodeFields = (* op1:op2:Q:U *)
    (pickBit bin 23 <<< 4) + (pickTwo bin 20 <<< 2) + (pickBit bin 6 <<< 1) +
    (pickBit bin 4)
  match decodeFields with
  (* VCMLA 0xxx0 Armv8.3 *)
  | 0b00000u | 0b00100u | 0b01000u | 0b01100u (* 0xx00 *) ->
#if !EMULATION
    chkITQVdVn bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VCMLA dt N OD.OprDdDnDmidxRotate
  | 0b00010u | 0b00110u | 0b01010u | 0b01110u (* 0xx10 *) ->
#if !EMULATION
    chkITQVdVn bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VCMLA dt N OD.OprQdQnDmidxRotate
  (* VFMAL 000x1 Armv8.2 *)
  | 0b00001u ->
#if !EMULATION
    chkITQVd bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VFMAL dt N OD.OprDdSnSmidx
  | 0b00011u ->
#if !EMULATION
    chkITQVd bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VFMAL dt N OD.OprQdDnDmidx
  (* VFMSL 001x1 Armv8.2 *)
  | 0b00101u ->
#if !EMULATION
    chkITQVd bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VFMSL dt N OD.OprDdSnSmidx
  | 0b00111u ->
#if !EMULATION
    chkITQVd bin itstate
#endif
    let dt = oneDt SIMDTypF16
    render phlp &itstate 0 isInIT bin Op.VFMSL dt N OD.OprQdDnDmidx
  | 0b01001u | 0b01011u (* 010x1 *) -> raise ParsingFailureException
  (* VFMAB Armv8.6 *)
  | 0b01101u ->
#if !EMULATION
    chkITVdVn bin itstate
#endif
    let dt = oneDt BF16
    render phlp &itstate 0 isInIT bin Op.VFMAB dt N OD.OprQdQnDmidxm
  (* VFMAT Armv8.6 *)
  | 0b01111u ->
#if !EMULATION
    chkITVdVn bin itstate
#endif
    let dt = oneDt BF16
    render phlp &itstate 0 isInIT bin Op.VFMAT dt N OD.OprQdQnDmidxm
  (* VCMLA 1xx00 Armv8.3 *)
  | 0b10000u | 0b10100u | 0b11000u | 0b11100u (* 1xx00 *) ->
#if !EMULATION
    chkITQVdVn bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VCMLA dt N OD.OprDdDnDm0Rotate
  | 0b10001u | 0b10011u | 0b10101u | 0b10111u | 0b11001u | 0b11011u | 0b11101u
  | 0b11111u (* 1xxx1 *) -> raise ParsingFailureException
  (* VCMLA Armv8.3 *)
  | _ (* 1xx10 *) ->
#if !EMULATION
    chkITQVdVn bin itstate
#endif
    let dt = oneDt SIMDTypF32
    render phlp &itstate 0 isInIT bin Op.VCMLA dt N OD.OprQdQnDm0Rotate

/// Advanced SIMD and floating-point dot product on page F3-4187.
let parseAdvSIMDAndFPDotProduct phlp (itstate: byref<BL>) isInIT b =
  let decodeFields (* op1:op2:op4:Q:U *) =
    (pickBit b 23 <<< 5) + (pickTwo b 20 <<< 3) + (pickBit b 8 <<< 2) +
    (pickBit b 6 <<< 1) + (pickBit b 4)
  match decodeFields with
  | 0b000000u | 0b000001u | 0b000010u | 0b000011u (* 0000xx *) ->
    raise ParsingFailureException
  (* VDOT 64-bit Armv8.6 *)
  | 0b000100u ->
#if !EMULATION
    chkITQVdVn b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VDOT (oneDt BF16) N OD.OprDdDnDmidx
  | 0b000101u | 0b000111u (* 0001x1 *) -> raise ParsingFailureException
  (* VDOT 128-bit Armv8.6 *)
  | 0b000110u ->
#if !EMULATION
    chkITQVdVn b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VDOT (oneDt BF16) N OD.OprQdQnDmidx
  | 0b001000u | 0b001001u | 0b001010u | 0b001011u (* 0010xx *) ->
    raise ParsingFailureException
  | 0b010000u | 0b010001u | 0b010010u | 0b010011u (* 0100xx *) ->
    raise ParsingFailureException
  (* VSDOT 64-bit Armv8.2 *)
  | 0b010100u ->
#if !EMULATION
    chkITQVdVn b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VSDOT (oneDt SIMDTypS8) N OD.OprDdDnDmidx
  (* VUDOT 64-bit Armv8.2 *)
  | 0b010101u ->
#if !EMULATION
    chkITQVdVn b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VUDOT (oneDt SIMDTypU8) N OD.OprDdDnDmidx
  (* VSDOT 128-bit Armv8.2 *)
  | 0b010110u ->
#if !EMULATION
    chkITQVdVn b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VSDOT (oneDt SIMDTypS8) N OD.OprQdQnDmidx
  (* VUDOT 128-bit Armv8.2 *)
  | 0b010111u ->
#if !EMULATION
    chkITQVdVn b itstate
#endif
    render phlp &itstate 0 isInIT b Op.VUDOT (oneDt SIMDTypU8) N OD.OprQdQnDmidx
  | b when b &&& 0b111000u = 0b011000u (* 011xxx *) ->
    raise ParsingFailureException
  | b when b &&& 0b100100u = 0b100000u (* 1xx0xx *) ->
    raise ParsingFailureException
  (* VUSDOT 64-bit Armv8.6 *)
  | 0b100100u ->
#if !EMULATION
    chkQVdVn b
#endif
    let dt = oneDt SIMDTypS8
    render phlp &itstate 0 isInIT b Op.VUSDOT dt N OD.OprDdDnDmidx
  (* VSUDOT 64-bit Armv8.6 *)
  | 0b100101u ->
#if !EMULATION
    chkQVdVn b
#endif
    let dt = oneDt SIMDTypU8
    render phlp &itstate 0 isInIT b Op.VSUDOT dt N OD.OprDdDnDmidx
  (* VUSDOT 128-bit Armv8.6 *)
  | 0b100110u ->
#if !EMULATION
    chkQVdVn b
#endif
    let dt = oneDt SIMDTypS8
    render phlp &itstate 0 isInIT b Op.VUSDOT dt N OD.OprQdQnDmidx
  (* VSUDOT 128-bit Armv8.6 *)
  | 0b100111u ->
#if !EMULATION
    chkQVdVn b
#endif
    let dt = oneDt SIMDTypU8
    render phlp &itstate 0 isInIT b Op.VSUDOT dt N OD.OprQdQnDmidx
  | 0b101100u | 0b101101u | 0b101110u | 0b101111u (* 1011xx *) ->
    raise ParsingFailureException
  | b when b &&& 0b110100u = 0b110100u (* 11x1xx *) ->
    raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// Additional Advanced SIMD and floating-point instructions on page F3-4183.
let parseAddAdvSIMDAndFPInstrs phlp (itstate: byref<BL>) isInIT bin =
  let op1 = extract bin 21 16 (* op1 *)
  let op3 = pickTwo bin 8 (* op3 *)
  let decodeFields (* op0:op2:op4:op5 *) =
    (pickThree bin 23 <<< 3) + (pickBit bin 10 <<< 2) + (pickBit bin 6 <<< 1) +
    (pickBit bin 4)
  match decodeFields with
  | b when b &&& 0b100000u = 0b000000u (* 0xxxxx *) && pickBit op3 1 = 0u ->
    parseAdvSIMDThreeRegSameLenExt phlp &itstate isInIT bin
  | 0b100000u (* 100000 *) when op3 <> 0b00u ->
    parseVectorSelect phlp &itstate isInIT bin
  | 0b101000u | 0b101010u (* 1010x0 *) when pickTwo op1 4 = 0u && op3 <> 0u ->
    parseFPMinMaxNum phlp &itstate isInIT bin
  | 0b101010u (* 101010 *) when op1 = 0b110000u && op3 <> 0b00u ->
    parseFPExtractionAndInsertion phlp &itstate isInIT bin
  | 0b101010u (* 101010 *) when pickThree op1 3 = 0b111u && op3 <> 0b00u ->
    parseFPDirConvToInt phlp &itstate isInIT bin
  | b when b &&& 0b110100u = 0b100000u (* 10x0xx *) && op3 = 0b00u ->
    parseAdvSIMDAndFPMulWithAcc phlp &itstate isInIT bin
  | b when b &&& 0b110100u = 0b100100u (* 10x1xx *) && pickBit op3 1 = 0u ->
    parseAdvSIMDAndFPDotProduct phlp &itstate isInIT bin
  | _ -> raise ParsingFailureException

/// System register access, Advanced SIMD, and floating-point on page F3-4164.
let parseSystemRegAccessAdvSIMDAndFP phlp (itstate: byref<BL>) isInIT bin =
  let decodeFields (* op0:op1:op2:op3 *) =
    (pickBit bin 28 <<< 4) + (pickTwo bin 24 <<< 2) + (pickBit bin 11 <<< 1)
    + (pickBit bin 4)
  match decodeFields with
  | b when b &&& 0b01010u = 0b00000u (* x0x0x *) ->
    raise ParsingFailureException
  | b when b &&& 0b01110u = 0b01000u (* x100x *) ->
    raise ParsingFailureException
  | b when b &&& 0b01100u = 0b01100u (* x11xx *) ->
    parseAdvSIMDDataProcess phlp &itstate isInIT bin
  | b when b &&& 0b11010u = 0b00010u (* 00x1x *) ->
    parseAdvSIMDAndSysRegLdStAnd64BitMov phlp &itstate isInIT bin
  | 0b01010u -> parseFPDataProcessing phlp &itstate isInIT bin
  | 0b01011u -> parseAdvSIMDAndSysReg32BitMov phlp &itstate isInIT bin
  | _ (* 1 != 11 1 x *) ->
    parseAddAdvSIMDAndFPInstrs phlp &itstate isInIT bin

/// Load/store multiple on page F3-4160.
let parseLdStMul phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickTwo bin 23) (pickBit bin 20) 1 (* opc:L *) with
  | 0b000u ->
    render phlp &itstate 0 isInIT bin Op.SRSDB None N OD.OprSPMode
  | 0b001u ->
    render phlp &itstate 0 isInIT bin Op.RFEDB None N OD.OprRn
  | 0b010u ->
#if !EMULATION
    chkPCRnRegsWBRegs bin
#endif
    render phlp &itstate 0 isInIT bin Op.STM None W OD.OprRnRegsT32
  | 0b011u ->
#if !EMULATION
    chkPCRnRegsPMWback bin itstate
#endif
    let struct (op, oprs) = (* Alias conditions F5-4438 *)
      if (wbackW bin) && (pickFour bin 16 = 0b1101u) &&
         (bitCount (extract bin 15 0) 15 > 1)
      then struct (Op.POP, OD.OprRegs)
      else struct (Op.LDM, OD.OprRnRegsT32)
    render phlp &itstate 0 isInIT bin op None W oprs
  | 0b100u ->
#if !EMULATION
    chkPCRnRegsWBRegs bin
#endif
    let struct (op, oprs, q) = (* Alias conditions on page F5-4813 *)
      if (wbackW bin) && (pickFour bin 16 = 0b1101u) &&
         (bitCount (extract bin 14 0) 14 > 1)
      then struct (Op.PUSH, OD.OprRegs, W)
      else struct (Op.STMDB, OD.OprRnRegsT32, N)
    render phlp &itstate 0 isInIT bin op None q oprs
  | 0b101u ->
#if !EMULATION
    chkPCRnRegsPMWback bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.LDMDB None N OD.OprRnRegsT32
  | 0b110u ->
    render phlp &itstate 0 isInIT bin Op.SRSIA None N OD.OprSPMode
  | _ (* 111 *) ->
#if !EMULATION
    chkPCRnIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.RFEIA None N OD.OprRn

/// Load/store exclusive on page F3-4189.
let parseLdStExclusive phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
#if !EMULATION
    chkPCRd11RtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STREX None N OD.OprRdRtMemImmT
  | _ (* 1 *) ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDREX None N OD.OprRtMemImm8

/// Load/store exclusive byte/half/dual on page F3-4189.
let parseLdStEexclusiveByteHalfDual phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickBit bin 20) (pickTwo bin 4) 2 (* L:sz *) with
  | 0b000u ->
#if !EMULATION
    chkPCRd3RtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STREXB None N OD.OprRdRtMemT
  | 0b001u ->
#if !EMULATION
    chkPCRd3RtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STREXH None N OD.OprRdRtMemT
  | 0b010u -> raise ParsingFailureException
  | 0b011u ->
#if !EMULATION
    chkPCRdRtRt2Rn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STREXD None N OD.OprRdRtRt2MemT
  | 0b100u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDREXB None N OD.OprRt15Mem
  | 0b101u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDREXH None N OD.OprRt15Mem
  | 0b110u -> raise ParsingFailureException
  | _ (* 111 *) ->
#if !EMULATION
    chkThumbPCRtRt2Rn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDREXD None N OD.OprRtRt2MemT

/// Load-acquire / Store-release on page F3-4190.
let parseLdAcqStRel phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickBit bin 20) (pickThree bin 4) 3 (* L:op:sz *) with
  | 0b0000u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STLB None N OD.OprRt15Mem
  | 0b0001u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STLH None N OD.OprRt15Mem
  | 0b0010u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STL None N OD.OprRt15Mem
  | 0b0011u -> raise ParsingFailureException
  | 0b0100u ->
#if !EMULATION
    chkPCRd3RtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STLEXB None N OD.OprRdRtMemT
  | 0b0101u ->
#if !EMULATION
    chkPCRd3RtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STLEXH None N OD.OprRdRtMemT
  | 0b0110u ->
#if !EMULATION
    chkPCRd3RtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STLEX None N OD.OprRdRtMemT
  | 0b0111u ->
#if !EMULATION
    chkPCRdRtRt2Rn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STLEXD None N OD.OprRdRtRt2MemT
  | 0b1000u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDAB None N OD.OprRt15Mem
  | 0b1001u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDAH None N OD.OprRt15Mem
  | 0b1010u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDA None N OD.OprRt15Mem
  | 0b1011u -> raise ParsingFailureException
  | 0b1100u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDAEXB None N OD.OprRt15Mem
  | 0b1101u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDAEXH None N OD.OprRt15Mem
  | 0b1110u ->
#if !EMULATION
    chkPCRtRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDAEX None N OD.OprRt15Mem
  | _ (* 1111 *) ->
#if !EMULATION
    chkThumbPCRtRt2Rn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDAEXD None N OD.OprRtRt2MemT

/// Load/store dual (immediate, post-indexed) on page F3-4191.
let parseLdStDualImmePostIndexed phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
#if !EMULATION
    chkPCRnRtRt2 bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRD None N OD.OprRtRt2MemImmT
  | _ (* 1 *) ->
#if !EMULATION
    chkThumbPCRtRt2Eq bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRD None N OD.OprRtRt2MemImmT

/// Load/store dual (immediate) on page F3-4191.
let parseLdStDualImm phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
#if !EMULATION
    chkPCRnRtRt2 bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRD None N OD.OprRtRt2MemImmT
  | _ (* 1 *) ->
#if !EMULATION
    chkThumbPCRtRt2Eq bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRD None N OD.OprRtRt2MemImmT

/// Load/store dual (immediate, pre-indexed) on page F3-4191.
let parseLdStDualImmPreIndexed phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 20 (* L *) with
  | 0b0u ->
#if !EMULATION
    chkPCRnRtRt2 bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRD None N OD.OprRtRt2MemImmT
  | _ (* 1 *) ->
#if !EMULATION
    chkThumbPCRtRt2Eq bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRD None N OD.OprRtRt2MemImmT

/// Load/store dual, load/store exclusive, load-acquire/store-release, and table
/// branch on page F3-4188.
let parseLdStDualExclusiveAndTblBranch phlp (itstate: byref<BL>) isInIT bin =
  let op0 = pickFour bin 21 (* op0 *)
  let op2 = pickFour bin 16 (* op2 *)
  match concat (pickFive bin 20) (pickThree bin 5) 3 (* op0:op1:op3 *) with
  | b when pickFour b 4 = 0b0010u (* 0010xxxx *) ->
    parseLdStExclusive phlp &itstate isInIT bin
  | 0b01100000u -> raise ParsingFailureException
  | 0b01101000u ->
#if !EMULATION
    chkPCRmIT32 bin itstate
#endif
    let struct (op, oprs) =
      if pickBit bin 4 (* H *) = 0u then struct (Op.TBB, OD.OprMemRegT)
      else struct (Op.TBH, OD.OprMemRegLSL1)
    render phlp &itstate 0 isInIT bin op None N oprs
  | 0b01100010u | 0b01100011u | 0b01101010u | 0b01101011u (* 0110x01x *) ->
    parseLdStEexclusiveByteHalfDual phlp &itstate isInIT bin
  | b when b &&& 0b11110100u = 0b01100100u (* 0110x1xx *) ->
    parseLdAcqStRel phlp &itstate isInIT bin
  | b when b &&& 0b10110000u = 0b00110000u (* 0x11xxxx *) && op2 <> 0b1111u ->
    parseLdStDualImmePostIndexed phlp &itstate isInIT bin
  | b when b &&& 0b10110000u = 0b10100000u (* 1x10xxxx *) && op2 <> 0b1111u ->
    parseLdStDualImm phlp &itstate isInIT bin
  | b when b &&& 0b10110000u = 0b10110000u (* 1x11xxxx *) && op2 <> 0b1111u ->
    parseLdStDualImmPreIndexed phlp &itstate isInIT bin
  | _ when (op0 &&& 0b1001u <> 0b0000u) && (op2 = 0b1111u) ->
#if !EMULATION
    chkPCRtRt2EqW bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRD None N OD.OprRtRt2LabelT
  | _ -> raise ParsingFailureException

/// Alias conditions on page F5-4557.
let changeToAliasOfMOVS bin =
  let stype = pickTwo bin 4
  let imm5 = concat (pickThree bin 12) (pickTwo bin 6) 2
  if stype = 0b10u then struct (Op.ASRS, OD.OprRdRmImmT32)
  elif imm5 <> 0b00000u && stype = 0b00u then struct (Op.LSLS, OD.OprRdRmImmT32)
  elif stype = 0b01u then struct (Op.LSRS, OD.OprRdRmImmT32)
  elif imm5 <> 0b00000u && stype = 0b11u then struct (Op.RORS, OD.OprRdRmImmT32)
  elif imm5 = 0b00000u && stype = 0b11u then struct (Op.RRXS, OD.OprRdRm)
  elif imm5 = 0b00000u then struct (Op.MOVS, OD.OprRdRm)
  else struct (Op.MOVS, OD.OprRdRmShf)

/// Data-processing (shifted register) on page F3-4160.
let parseDataProcessingShiftReg phlp (itstate: byref<BL>) isInIT bin =
  let rn = pickFour bin 16
  let i3i2st (* imm3:imm2:stype *) =
    concat (pickThree bin 12) (pickFour bin 4) 4
  let rd = pickFour bin 8
  match pickFive bin 20 (* op1:S *) with
  | 0b00000u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.AND None q oprs
  | 0b00001u when i3i2st <> 0b11u && rd <> 0b1111u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.ANDS None q oprs
  | 0b00001u when i3i2st <> 0b11u && rd = 0b1111u ->
#if !EMULATION
    chkThumbPCRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.TST None N OD.OprRnRmShfT
  | 0b00001u when i3i2st = 0b11u && rd <> 0b1111u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.ANDS None N OD.OprRdRnRmShfT
  | 0b00001u when i3i2st = 0b11u && rd = 0b1111u ->
#if !EMULATION
    chkThumbPCRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.TST None N OD.OprRnRmShfT
  (* BIC, BICS (register) *)
  | 0b00010u when i3i2st = 0b11u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.BIC None N OD.OprRdRnRmShfT
  | 0b00010u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.BIC None q oprs
  | 0b00011u when i3i2st = 0b11u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.BICS None N OD.OprRdRnRmShfT
  | 0b00011u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.BICS None q oprs
  (* ORR (register) *)
  | 0b00100u when rn <> 0b1111u && i3i2st = 0b11u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.ORR None N OD.OprRdRnRmShfT
  | 0b00100u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.ORR None q oprs
  (* MOV (register) *)
  | 0b00100u when rn = 0b1111u && i3i2st = 0b11u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.MOV None N OD.OprRdRmShfT32
  | 0b00100u when rn = 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    let q = if inITBlock itstate then W else N
    render phlp &itstate 0 isInIT bin Op.MOV None q OD.OprRdRmShfT32
  (* ORRS (register) *)
  | 0b00101u when rn <> 0b1111u && i3i2st = 0b11u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.ORRS None N OD.OprRdRnRmShfT
  | 0b00101u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.ORRS None q oprs
  (* MOVS (register) *)
  | 0b00101u when rn = 0b1111u && i3i2st = 0b11u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    let struct (opcode, oprs) = changeToAliasOfMOVS bin
    render phlp &itstate 0 isInIT bin opcode None N oprs
  | 0b00101u when rn = 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    let struct (opcode, oprs) = changeToAliasOfMOVS bin
    let q = if inITBlock itstate |> not then W else N
    render phlp &itstate 0 isInIT bin opcode None q oprs
  (* ORN (register) *)
  | 0b00110u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.ORN None N OD.OprRdRnRmShfT
  (* MVNS (register) *)
  | 0b00110u when rn = 0b1111u && i3i2st = 0b11u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.MVN None N OD.OprRdRmShfT32
  | 0b00110u when rn = 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, OD.OprRdRmT32)
      else struct (N, OD.OprRdRmShfT32)
    render phlp &itstate 0 isInIT bin Op.MVN None q oprs
  (* ORNS (register) *)
  | 0b00111u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.ORNS None N OD.OprRdRnRmShfT
  (* MVNS (register) *)
  | 0b00111u when rn = 0b1111u && i3i2st = 0b11u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.MVNS None N OD.OprRdRmShfT32
  | 0b00111u when rn = 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, OD.OprRdRmT32)
      else struct (N, OD.OprRdRmShfT32)
    render phlp &itstate 0 isInIT bin Op.MVNS None q oprs
  (* EOR (register) *)
  | 0b01000u when i3i2st = 0b11u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.EOR None N OD.OprRdRnRmShfT
  | 0b01000u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.EOR None q oprs
  (* EORS (register) *)
  | 0b01001u when i3i2st <> 0b11u && rd <> 0b1111u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.EORS None q oprs
  | 0b01001u when i3i2st <> 0b11u && rd = 0b1111u ->
#if !EMULATION
    chkThumbPCRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.TEQ None N OD.OprRnRmShfT
  | 0b01001u when i3i2st = 0b11u && rd <> 0b1111u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.EORS None N OD.OprRdRnRmShfT
  | 0b01001u when i3i2st = 0b11u && rd = 0b1111u ->
#if !EMULATION
    chkThumbPCRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.TEQ None N OD.OprRnRmShfT
  | 0b01010u | 0b01011u (* 0101x *) -> raise ParsingFailureException
  | 0b01100u when i3i2st &&& 0b11u = 0b00u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.PKHBT None N OD.OprRdRnRmShfT
  | 0b01100u when i3i2st &&& 0b11u = 0b01u -> raise ParsingFailureException
  | 0b01100u when i3i2st &&& 0b11u = 0b10u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.PKHTB None N OD.OprRdRnRmShfT
  | 0b01100u when i3i2st &&& 0b11u = 0b11u -> raise ParsingFailureException
  | 0b01110u | 0b01111u (* 0111x *) -> raise ParsingFailureException
  | 0b10000u when rn <> 0b1101u && i3i2st = 0b11u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.ADD None N OD.OprRdRnRmShfT
  | 0b10000u when rn <> 0b1101u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.ADD None q oprs
  | 0b10000u when rn = 0b1101u ->
#if !EMULATION
    chkPCRdSRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.ADD None N OD.OprRdSPRmShf
  | 0b10001u when rn <> 0b1101u && rd <> 0b1111u && i3i2st = 0b11u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.ADDS None N OD.OprRdRnRmShfT
  | 0b10001u when rn <> 0b1101u && rd <> 0b1111u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.ADDS None q oprs
  | 0b10001u when rn = 0b1101u && rd <> 0b1111u ->
#if !EMULATION
    chkPCRdSRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.ADDS None N OD.OprRdSPRmShf
  | 0b10001u when rd = 0b1111u ->
#if !EMULATION
    chkThumbPCRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.CMN None N OD.OprRnRmShfT
  | 0b10010u | 0b10011u (* 1001x *) -> raise ParsingFailureException
  | 0b10100u when i3i2st = 0b11u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.ADC None N OD.OprRdRnRmShfT
  | 0b10100u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.ADC None q oprs
  | 0b10101u when i3i2st = 0b11u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.ADCS None N OD.OprRdRnRmShfT
  | 0b10101u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.ADCS None q oprs
  | 0b10110u when i3i2st = 0b11u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SBC None N OD.OprRdRnRmShfT
  | 0b10110u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.SBC None q oprs
  | 0b10111u when i3i2st = 0b11u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SBCS None N OD.OprRdRnRmShfT
  | 0b10111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.SBCS None q oprs
  | 0b11000u | 0b11001u (* 1100x *) -> raise ParsingFailureException
  | 0b11010u when rn <> 0b1101u && i3i2st = 0b11u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SUB None N OD.OprRdRnRmShfT
  | 0b11010u when rn <> 0b1101u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.SUB None q oprs
  | 0b11010u when rn = 0b1101u && i3i2st = 0b11u ->
#if !EMULATION
    chkPCRdSRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SUB None N OD.OprRdSPRmShf
  | 0b11010u when rn = 0b1101u ->
#if !EMULATION
    chkPCRdSRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SUB None N OD.OprRdSPRmShf
  | 0b11011u when rn <> 0b1101u && rd <> 0b1111u && i3i2st = 0b11u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SUBS None N OD.OprRdRnRmShfT
  | 0b11011u when rn <> 0b1101u && rd <> 0b1111u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.SUBS None q oprs
  | 0b11011u when rn = 0b1101u && rd <> 0b1111u && i3i2st = 0b11u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SUBS None N OD.OprRdRnRmShfT
  | 0b11011u when rn = 0b1101u && rd <> 0b1111u ->
#if !EMULATION
    chkPCRdSRnRm bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate |> not then struct (W, OD.OprRdRnRmT32)
      else struct (N, OD.OprRdRnRmShfT)
    render phlp &itstate 0 isInIT bin Op.SUBS None q oprs
  | 0b11011u when rd = 0b1111u ->
#if !EMULATION
    chkThumbPCRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.CMP None N OD.OprRnRmShfT
  | 0b11100u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.RSB None N OD.OprRdRnRmShfT
  | 0b11101u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.RSBS None N OD.OprRdRnRmShfT
  | 0b11110u | 0b11111u (* 1111x *) -> raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// Hints on page F3-4193.
let parseHints32 phlp (itstate: byref<BL>) isInIT bin =
  match extract bin 7 0 (* hint:option *) with
  | 0b00000000u ->
    render phlp &itstate 0 isInIT bin Op.NOP None W OD.OprNo
  | 0b00000001u ->
    render phlp &itstate 0 isInIT bin Op.YIELD None W OD.OprNo
  | 0b00000010u ->
    render phlp &itstate 0 isInIT bin Op.WFE None W OD.OprNo
  | 0b00000011u ->
    render phlp &itstate 0 isInIT bin Op.WFI None W OD.OprNo
  | 0b00000100u ->
    render phlp &itstate 0 isInIT bin Op.SEV None W OD.OprNo
  | 0b00000101u ->
    render phlp &itstate 0 isInIT bin Op.SEVL None W OD.OprNo
  | 0b00000110u | 0b00000111u ->
    render phlp &itstate 0 isInIT bin Op.NOP None W OD.OprNo
  | b when b &&& 0b11111000u = 0b00001000u ->
    render phlp &itstate 0 isInIT bin Op.NOP None W OD.OprNo
  | 0b00010000u -> (* Armv8.2 *)
    inITBlock itstate |> checkUndef
    render phlp &itstate 0 isInIT bin Op.ESB None W OD.OprNo
  | 0b00010001u ->
    render phlp &itstate 0 isInIT bin Op.NOP None W OD.OprNo
  | 0b00010010u -> (* TSB CSYNC Armv8.4 *)
    inITBlock itstate |> checkUndef
    render phlp &itstate 0 isInIT bin Op.TSB None N OD.OprNo
  | 0b00010011u ->
    render phlp &itstate 0 isInIT bin Op.NOP None W OD.OprNo
  | 0b00010100u ->
    inITBlock itstate |> checkUndef
    render phlp &itstate 0 isInIT bin Op.CSDB None W OD.OprNo
  | 0b00010101u ->
    render phlp &itstate 0 isInIT bin Op.NOP None W OD.OprNo
  | 0b00010110u | 0b00010111u (* 0001011x *) ->
    render phlp &itstate 0 isInIT bin Op.NOP None W OD.OprNo
  | b when b &&& 0b11111000u = 0b00011000u (* 00011xxx *) ->
    render phlp &itstate 0 isInIT bin Op.NOP None W OD.OprNo
  | b when b &&& 0b11100000u = 0b00100000u (* 001xxxxx *) ->
    render phlp &itstate 0 isInIT bin Op.NOP None W OD.OprNo
  | b when b &&& 0b11000000u = 0b01000000u (* 01xxxxxx *)->
    render phlp &itstate 0 isInIT bin Op.NOP None W OD.OprNo
  | b when b &&& 0b11000000u = 0b10000000u (* 10xxxxxx *) ->
    render phlp &itstate 0 isInIT bin Op.NOP None W OD.OprNo
  | b when b &&& 0b11100000u = 0b11000000u (* 110xxxxx *) ->
    render phlp &itstate 0 isInIT bin Op.NOP None W OD.OprNo
  | b when b &&& 0b11110000u = 0b11100000u (* 1110xxxx *) ->
    render phlp &itstate 0 isInIT bin Op.NOP None W OD.OprNo
  | b when b &&& 0b11110000u = 0b11110000u ->
    render phlp &itstate 0 isInIT bin Op.DBG None N OD.OprOptImm
  | _ -> raise ParsingFailureException

/// Change processor state on page F3-4194.
let parseChgProcStateT32 (phlp: ParsingHelper) (itstate: byref<BL>) isInIT bin =
  phlp.Cond <- Condition.UN
  match pickThree bin 8 (* imod:M *) with
  | 0b001u ->
#if !EMULATION
    chkModeImodAIFIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.CPS None N OD.OprMode
  | 0b010u | 0b011u (* 01x *) -> raise ParsingFailureException
  (* CPSIE 10x *)
  | 0b100u ->
#if !EMULATION
    chkModeImodAIFIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.CPSIE None W OD.OprIflagsT32
  | 0b101u ->
#if !EMULATION
    chkModeImodAIFIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.CPSIE None N OD.OprIflagsModeT
  (* CPSID 11x *)
  | 0b110u ->
#if !EMULATION
    chkModeImodAIFIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.CPSID None W OD.OprIflagsT32
  | 0b111u ->
#if !EMULATION
    chkModeImodAIFIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.CPSID None N OD.OprIflagsModeT
  | _ -> raise ParsingFailureException

/// Miscellaneous system on page F3-4194.
let parseMiscSystem phlp (itstate: byref<BL>) isInIT bin =
  let option = pickFour bin 0
  match pickFour bin 4 (* opc *) with
  | 0b0000u | 0b0001u (* 000x *) -> raise ParsingFailureException
  | 0b0010u ->
    render phlp &itstate 0 isInIT bin Op.CLREX None N OD.OprNo
  | 0b0011u -> raise ParsingFailureException
  | 0b0100u when option <> 0b0000u || option <> 0b0100u (* != 0x00 *) ->
    render phlp &itstate 0 isInIT bin Op.DSB None N OD.OprOpt
  | 0b0100u when option = 0b0000u ->
    inITBlock itstate |> checkUndef
    render phlp &itstate 0 isInIT bin Op.SSBB None N OD.OprNo
  | 0b0100u when option = 0b0100u ->
    inITBlock itstate |> checkUndef
    render phlp &itstate 0 isInIT bin Op.PSSBB None N OD.OprNo
  | 0b0101u ->
    render phlp &itstate 0 isInIT bin Op.DMB None N OD.OprOpt
  | 0b0110u ->
    render phlp &itstate 0 isInIT bin Op.ISB None N OD.OprOpt
  | 0b0111u ->
    inITBlock itstate |> checkUndef
    render phlp &itstate 0 isInIT bin Op.SB None N OD.OprNo
  | _ (* 1xxx *) -> raise ParsingFailureException

/// Exception return on page F3-4195.
let parseExceptionReturn phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickFour bin 16) (extract bin 7 0) 8 (* Rn:imm8 *) with
  | 0b111000000000u ->
#if !EMULATION
    chkInITLastIT itstate
#endif
    render phlp &itstate 0 isInIT bin Op.ERET None N OD.OprNo
  | _ (* xxxx != 00000000 *) ->
#if !EMULATION
    chkRnIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.SUBS None N OD.OprPCLRImm8

/// DCPS on page F3-4195.
let parseDCPS phlp (itstate: byref<BL>) isInIT bin =
  if pickFour bin 16 (* imm4 *) <> 0b1111u then raise UndefinedException
  elif extract bin 11 2 (* imm10 *) <> 0b0u then raise UndefinedException
  else
    match pickTwo bin 0 (* opt *) with
    | 0b00u -> raise ParsingFailureException
    | 0b01u ->
      render phlp &itstate 0 isInIT bin Op.DCPS1 None N OD.OprNo
    | 0b10u ->
      render phlp &itstate 0 isInIT bin Op.DCPS2 None N OD.OprNo
    | _ (* 11 *) ->
      render phlp &itstate 0 isInIT bin Op.DCPS3 None N OD.OprNo

/// Exception generation on page F3-4195.
let parseExcepGeneration (phlp: ParsingHelper) (itstate: byref<BL>) isInIT bin =
  match concat (pickBit bin 20) (pickBit bin 13) 1 (* o1:o2 *) with
  | 0b00u ->
    inITBlock itstate |> checkUnpred
    phlp.Cond <- Condition.UN
    render phlp &itstate 0 isInIT bin Op.HVC None N OD.OprImm16T
  | 0b01u -> raise ParsingFailureException
  | 0b10u ->
#if !EMULATION
    chkInITLastIT itstate
#endif
    render phlp &itstate 0 isInIT bin Op.SMC None N OD.OprImm4T
  | _ (* 11 *) ->
    render phlp &itstate 0 isInIT bin Op.UDF None W OD.OprImm16T

/// Branches and miscellaneous control on page F3-4192.
let parseBranchAndMiscCtrl phlp (itstate: byref<BL>) isInIT bin =
  let op1 = pickThree bin 23 (* op1<3:1> *)
  let op3 = pickThree bin 12 (* op3 *)
  let decodeFields (* op0:op1:op2:op3:op5 *) =
    (extract bin 26 20 <<< 4) + (pickThree bin 12 <<< 1) + (pickBit bin 5)
  match decodeFields with
  | b when b &&& 0b11111101011u = 0b01110000000u (* 011100x0x00 *) ->
#if !EMULATION
    chkThumbMaskPCRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.MSR None N OD.OprSregRnT
  | b when b &&& 0b11111101011u = 0b01110000001u (* 011100x0x01 *) ->
#if !EMULATION
    chkPCRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.MSR None N OD.OprBankregRnT
  | 0b01110100000u | 0b01110100001u | 0b01110100100u | 0b01110100101u
    when pickThree bin 8 (* op4 *) = 0b000u ->
    parseHints32 phlp &itstate isInIT bin
  | 0b01110100000u | 0b01110100001u | 0b01110100100u | 0b01110100101u ->
    parseChgProcStateT32 phlp &itstate isInIT bin
  | b when b &&& 0b11111111010u = 0b01110110000u (* 01110110x0x *) ->
    parseMiscSystem phlp &itstate isInIT bin
  | b when b &&& 0b11111111010u = 0b01111000000u (* 01111000x0x *) ->
#if !EMULATION
    chkPCRmIT32 bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.BXJ None N OD.OprRmT32
  | b when b &&& 0b11111111010u = 0b01111010000u (* 01111010x0x *) ->
    parseExceptionReturn phlp &itstate isInIT bin
  | b when b &&& 0b11111101011u = 0b01111100000u (* 011111x0x00 *) ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.MRS None N OD.OprRdSregT
  | b when b &&& 0b11111101011u = 0b01111100001u (* 011111x0x01 *) ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.MRS None N OD.OprRdBankregT
  | 0b11110000000u | 0b11110000001u (* 1111000000x *) ->
    parseDCPS phlp &itstate isInIT bin
  | 0b11110000100u | 0b11110000101u (* 1111000010x *) ->
    raise ParsingFailureException
  | b when b &&& 0b11111111010u = 0b11110010000u (* 11110010x0x *) ->
    raise ParsingFailureException
  | b when b &&& 0b11111101010u = 0b11110100000u (* 111101x0x0x *) ->
    raise ParsingFailureException
  | b when b &&& 0b11111101010u = 0b11111000000u (* 111110x0x0x *) ->
    raise ParsingFailureException
  | b when b &&& 0b11111101010u = 0b11111100000u (* 111111x0x0x *) ->
    parseExcepGeneration phlp &itstate isInIT bin
  | _ when (op1 <> 0b111u) (* op1 != 111x *) && (op3 &&& 0b101u = 0b0u) ->
    inITBlock itstate |> checkUnpred
    phlp.Cond <- pickFour bin 22 |> byte |> parseCond
    render phlp &itstate 0 isInIT bin Op.B None W OD.OprLabelT3
  | _ when op3 &&& 0b101u = 0b001u (* 0x1 *) ->
#if !EMULATION
    chkInITLastIT itstate
#endif
    render phlp &itstate 0 isInIT bin Op.B None W OD.OprLabelT4
  | _ when op3 &&& 0b101u = 0b100u (* 1x0 *) ->
#if !EMULATION
    chkHInLastIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.BLX None N OD.OprLabelT2
  | _ when op3 &&& 0b101u = 0b101u (* 1x1 *) ->
#if !EMULATION
    chkInITLastIT itstate
#endif
    render phlp &itstate 0 isInIT bin Op.BL None N OD.OprLabelT4
  | _ -> raise ParsingFailureException

/// Data-processing (modified immediate) on page F3-4162.
let parseDataProcessingModImm phlp (itstate: byref<BL>) isInIT bin =
  let rn = pickFour bin 16
  let rd = pickFour bin 8
  match pickFive bin 20 (* op1:S *) with
  | 0b00000u ->
#if !EMULATION
    chkPCRdSRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.AND None N OD.OprRdRnConstT
  | 0b00001u when rd <> 0b1111u ->
#if !EMULATION
    chkPCRdSRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.ANDS None N OD.OprRdRnConstT
  | 0b00001u when rd = 0b1111u ->
#if !EMULATION
    chkPCRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.TST None N OD.OprRnConstT
  | 0b00010u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.BIC None N OD.OprRdRnConstT
  | 0b00011u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.BICS None N OD.OprRdRnConstT
  | 0b00100u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.ORR None N OD.OprRdRnConstT
  | 0b00100u when rn = 0b1111u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    let q = if inITBlock itstate then W else N
    render phlp &itstate 0 isInIT bin Op.MOV None q OD.OprRdConstT
  | 0b00101u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.ORRS None N OD.OprRdRnConstT
  | 0b00101u when rn = 0b1111u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    let q = if inITBlock itstate then W else N
    render phlp &itstate 0 isInIT bin Op.MOVS None q OD.OprRdConstT
  | 0b00110u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.ORN None N OD.OprRdRnConstT
  | 0b00110u when rn = 0b1111u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.MVN None N OD.OprRdConstT
  | 0b00111u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.ORNS None N OD.OprRdRnConstT
  | 0b00111u when rn = 0b1111u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.MVNS None N OD.OprRdConstT
  | 0b01000u ->
#if !EMULATION
    chkPCRdSRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.EOR None N OD.OprRdRnConstT
  | 0b01001u when rd <> 0b1111u ->
#if !EMULATION
    chkPCRdSRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.EORS None N OD.OprRdRnConstT
  | 0b01001u when rd = 0b1111u ->
#if !EMULATION
    chkPCRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.TEQ None N OD.OprRnConstT
  | 0b01010u | 0b01011u (* 0101x *) -> raise ParsingFailureException
  | 0b01100u | 0b01101u | 0b01110u | 0b01111u (* 011xx *) ->
    raise ParsingFailureException
  | 0b10000u when rn <> 0b1101u ->
#if !EMULATION
    chkPCRdSRn bin
#endif
    let q = if inITBlock itstate then W else N
    render phlp &itstate 0 isInIT bin Op.ADD None q OD.OprRdRnConstT
  | 0b10000u when rn = 0b1101u ->
#if !EMULATION
    chkPCRdS bin
#endif
    render phlp &itstate 0 isInIT bin Op.ADD None W OD.OprRdSPConstT
  | 0b10001u when rn <> 0b1101u && rd <> 0b1111u ->
#if !EMULATION
    chkPCRdSRn bin
#endif
    let q = if inITBlock itstate |> not then W else N
    render phlp &itstate 0 isInIT bin Op.ADDS None q OD.OprRdRnConstT
  | 0b10001u when rn = 0b1101u && rd <> 0b1111u ->
#if !EMULATION
    chkPCRdS bin
#endif
    render phlp &itstate 0 isInIT bin Op.ADDS None N OD.OprRdSPConstT
  | 0b10001u when rd = 0b1111u ->
#if !EMULATION
    chkPCRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.CMN None N OD.OprRnConstT
  | 0b10010u | 0b10011u (* 1001x *) -> raise ParsingFailureException
  | 0b10100u ->
    render phlp &itstate 0 isInIT bin Op.ADC None N OD.OprRdRnConstT
  | 0b10101u ->
    render phlp &itstate 0 isInIT bin Op.ADCS None N OD.OprRdRnConstT
  | 0b10110u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.SBC None N OD.OprRdRnConstT
  | 0b10111u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.SBCS None N OD.OprRdRnConstT
  | 0b11000u | 0b11001u (* 1100x *) -> raise ParsingFailureException
  | 0b11010u when rn <> 0b1101u ->
#if !EMULATION
    chkPCRdSRn bin
#endif
    let q = if inITBlock itstate then W else N
    render phlp &itstate 0 isInIT bin Op.SUB None q OD.OprRdRnConstT
  | 0b11010u when rn = 0b1101u ->
#if !EMULATION
    chkPCRdS bin
#endif
    render phlp &itstate 0 isInIT bin Op.SUB None N OD.OprRdSPConstT
  | 0b11011u when rn <> 0b1101u && rd <> 0b1111u ->
#if !EMULATION
    chkPCRdSRn bin
#endif
    let q = if inITBlock itstate |> not then W else N
    render phlp &itstate 0 isInIT bin Op.SUBS None q OD.OprRdRnConstT
  | 0b11011u when rn = 0b1101u && rd <> 0b1111u ->
#if !EMULATION
    chkPCRdS bin
#endif
    render phlp &itstate 0 isInIT bin Op.SUBS None N OD.OprRdSPConstT
  | 0b11011u when rd = 0b1111u ->
#if !EMULATION
    chkPCRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.CMP None W OD.OprRnConstT
  | 0b11100u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, OD.OprRdRn0T32)
      else struct (N, OD.OprRdRnConstT)
    render phlp &itstate 0 isInIT bin Op.RSB None q oprs
  | 0b11101u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    let struct (q, oprs) =
      if inITBlock itstate then struct (W, OD.OprRdRn0T32)
      else struct (N, OD.OprRdRnConstT)
    render phlp &itstate 0 isInIT bin Op.RSBS None q oprs
  | _ (* 1111x *) -> raise ParsingFailureException

/// Data-processing (simple immediate) on page F3-4196.
let parseDataProcSimImm phlp (itstate: byref<BL>) isInIT bin =
  let rn = pickFour bin 16
  match concat (pickBit bin 23) (pickBit bin 21) 1 (* o1:o2 *) with
  | 0b00u when rn = 0b1101u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.ADDW None N OD.OprRdSPImm12
  | 0b00u when rn = 0b1111u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    phlp.IsAdd <- true
    render phlp &itstate 0 isInIT bin Op.ADR None W OD.OprRdLabelT
  | 0b00u (* rn != 11x1 *) ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.ADDW None N OD.OprRdRnImm12
  | 0b01u -> raise ParsingFailureException
  | 0b10u -> raise ParsingFailureException
  | 0b11u when rn = 0b1101u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.SUBW None N OD.OprRdSPImm12
  | 0b11u when rn = 0b1111u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    phlp.IsAdd <- false
    render phlp &itstate 0 isInIT bin Op.ADR None N OD.OprRdLabelT
  | _ (* 11 && rn != 11x1 *) ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.SUBW None N OD.OprRdRnImm12

/// Move Wide (16-bit immediate) on page F3-4197.
let parseMoveWide16BitImm phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 23 with
  | 0b0u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.MOVW None N OD.OprRdImm16T
  | _ (* 1 *) ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.MOVT None N OD.OprRdImm16T

/// Saturate, Bitfield on page F3-4197.
let parseSaturateBitfield phlp (itstate: byref<BL>) isInIT bin =
  let rn = pickFour bin 16
  let i3i2 (* imm3:imm2 *) = concat (pickThree bin 12) (pickTwo bin 6) 2
  match pickThree bin 21 (* op1 *) with
  | 0b000u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.SSAT None N OD.OprRdImmRnShfT
  | 0b001u when i3i2 <> 0b00000u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.SSAT None N OD.OprRdImmRnShfT
  | 0b001u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.SSAT16 None N OD.OprRdImmRnT
  | 0b010u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.SBFX None N OD.OprRdRnLsbWidthM1T
  | 0b011u when rn <> 0b1111u ->
#if !EMULATION
    chkPCRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.BFI None N OD.OprRdRnLsbWidthT
  | 0b011u ->
#if !EMULATION
    chkThumbPCRd bin
#endif
    render phlp &itstate 0 isInIT bin Op.BFC None N OD.OprRdLsbWidthT
  | 0b100u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.USAT None N OD.OprRdImmRnShfUT
  | 0b101u when i3i2 <> 0b00000u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.USAT None N OD.OprRdImmRnShfUT
  | 0b101u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.USAT16 None N OD.OprRdImmRnU
  | 0b110u ->
#if !EMULATION
    chkThumbPCRdRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.UBFX None N OD.OprRdRnLsbWidthM1T
  | _ (* 111 *) -> raise ParsingFailureException

/// Data-processing (plain binary immediate) on page F3-4196.
let parseDataProcessingPlainBinImm phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickBit bin 24) (pickTwo bin 21) 2 (* op0:op1 *) with
  | 0b000u | 0b001u (* 00x *) ->
    parseDataProcSimImm phlp &itstate isInIT bin
  | 0b010u -> parseMoveWide16BitImm phlp &itstate isInIT bin
  | 0b011u -> raise ParsingFailureException
  | _ (* 1xx *) -> parseSaturateBitfield phlp &itstate isInIT bin

/// Advanced SIMD load/store multiple structures on page F3-4199.
let parseAdvSIMDLdStMulStruct phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickBit bin 21) (pickFour bin 8) 4 (* L:itype *) with
  | 0b00000u | 0b00001u (* 0000x *) ->
#if !EMULATION
    chkSzPCRnD4 bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VST4 dt N OD.OprListMem
  | 0b00010u ->
#if !EMULATION
    chkPCRnDregs bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VST1 dt N OD.OprListMem
  | 0b00011u ->
#if !EMULATION
    chkPCRnD2regs bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VST2 dt N OD.OprListMem
  | 0b00100u | 0b00101u (* 0010x *) ->
#if !EMULATION
    chkPCRnD3 bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VST3 dt N OD.OprListMem
  | 0b00110u ->
#if !EMULATION
    chkAlign1PCRnDregs bin 3u
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VST1 dt N OD.OprListMem
  | 0b00111u ->
#if !EMULATION
    chkAlign1PCRnDregs bin 1u
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VST1 dt N OD.OprListMem
  | 0b01000u | 0b01001u (* 0100x *) ->
#if !EMULATION
    chkAlignPCRnD2regs bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VST2 dt N OD.OprListMem
  | 0b01010u ->
#if !EMULATION
    chkAlignPCRnDregs bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VST1 dt N OD.OprListMem
  | 0b10000u | 0b10001u (* 1000x *) ->
#if !EMULATION
    chkSzPCRnD4 bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VLD4 dt N OD.OprListMem
  | 0b10010u ->
#if !EMULATION
    chkPCRnDregs bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VLD1 dt N OD.OprListMem
  | 0b10011u ->
#if !EMULATION
    chkPCRnD2regs bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VLD2 dt N OD.OprListMem
  | 0b10100u | 0b10101u (* 1010x *) ->
#if !EMULATION
    chkPCRnD3 bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VLD3 dt N OD.OprListMem
  | 0b01011u | 0b11011u (* x1011 *) -> raise ParsingFailureException
  | 0b10110u ->
#if !EMULATION
    chkAlign1PCRnDregs bin 3u
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VLD1 dt N OD.OprListMem
  | 0b10111u ->
#if !EMULATION
    chkAlign1PCRnDregs bin 1u
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VLD1 dt N OD.OprListMem
  | 0b01100u | 0b01101u | 0b01110u | 0b01111u | 0b11100u | 0b11101u | 0b11110u
  | 0b11111u (* x11xx *) -> raise ParsingFailureException
  | 0b11000u | 0b11001u (* 1100x *) ->
#if !EMULATION
    chkAlignPCRnD2regs bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VLD2 dt N OD.OprListMem
  | 0b11010u ->
#if !EMULATION
    chkAlignPCRnDregs bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VLD1 dt N OD.OprListMem
  | _ -> raise ParsingFailureException

/// Advanced SIMD load single structure to all lanes on page F3-4199.
let parseAdvSIMDLdSingStruAllLanes phlp (itstate: byref<BL>) isInIT bin =
  let decodeFields (* L:N:a *) =
    concat (concat (pickBit bin 21) (pickTwo bin 8) 2) (pickBit bin 4) 1
  match decodeFields with
  | b when b &&& 0b1000u = 0b0000u (* 0xxx *) -> raise ParsingFailureException
  | 0b1000u | 0b1001u (* 100x *) ->
#if !EMULATION
    chkSzAPCRnDregs bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VLD1 dt N OD.OprListMem1
  | 0b1010u | 0b1011u (* 101x *) ->
#if !EMULATION
    chkSzPCRnD2 bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VLD2 dt N OD.OprListMem2
  | 0b1100u ->
#if !EMULATION
    chkSzAPCRnD3 bin
#endif
    let dt = getDT64 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VLD3 dt N OD.OprListMem3
  | 0b1101u -> raise ParsingFailureException
  | _ (* 111x *) ->
#if !EMULATION
    chkSzAPCRnD4 bin
#endif
    let dt = getDT32 (pickTwo bin 6) |> oneDt
    render phlp &itstate 0 isInIT bin Op.VLD4 dt N OD.OprListMem4

/// Advanced SIMD load/store single structure to one lane on page F3-4200.
let parseAdvSIMDLdStSingStruOneLane phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickBit bin 21) (pickFour bin 8) 4 (* L:size:N *) with
  | 0b00000u ->
#if !EMULATION
    chkSzIdx0PCRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.VST1 (oneDt SIMDTyp8) N OD.OprListMemA
  | 0b00001u ->
#if !EMULATION
    chkPCRnD2 bin
#endif
    render phlp &itstate 0 isInIT bin Op.VST2 (oneDt SIMDTyp8) N OD.OprListMemB
  | 0b00010u ->
#if !EMULATION
    chkIdx0PCRnD3 bin
#endif
    render phlp &itstate 0 isInIT bin Op.VST3 (oneDt SIMDTyp8) N OD.OprListMemC
  | 0b00011u ->
#if !EMULATION
    chkPCRnD4 bin
#endif
    render phlp &itstate 0 isInIT bin Op.VST4 (oneDt SIMDTyp8) N OD.OprListMemD
  | 0b00100u ->
#if !EMULATION
    chkSzIdx1PCRn bin
#endif
    let dt = oneDt SIMDTyp16
    render phlp &itstate 0 isInIT bin Op.VST1 dt N OD.OprListMemA
  | 0b00101u ->
#if !EMULATION
    chkPCRnD2 bin
#endif
    let dt = oneDt SIMDTyp16
    render phlp &itstate 0 isInIT bin Op.VST2 dt N OD.OprListMemB
  | 0b00110u ->
#if !EMULATION
    chkIdx0PCRnD3 bin
#endif
    let dt = oneDt SIMDTyp16
    render phlp &itstate 0 isInIT bin Op.VST3 dt N OD.OprListMemC
  | 0b00111u ->
#if !EMULATION
    chkPCRnD4 bin
#endif
    let dt = oneDt SIMDTyp16
    render phlp &itstate 0 isInIT bin Op.VST4 dt N OD.OprListMemD
  | 0b01000u ->
#if !EMULATION
    chkSzIdx2PCRn bin
#endif
    let dt = oneDt SIMDTyp32
    render phlp &itstate 0 isInIT bin Op.VST1 dt N OD.OprListMemA
  | 0b01001u ->
#if !EMULATION
    chkIdxPCRnD2 bin
#endif
    let dt = oneDt SIMDTyp32
    render phlp &itstate 0 isInIT bin Op.VST2 dt N OD.OprListMemB
  | 0b01010u ->
#if !EMULATION
    chkIdx10PCRnD3 bin
#endif
    let dt = oneDt SIMDTyp32
    render phlp &itstate 0 isInIT bin Op.VST3 dt N OD.OprListMemC
  | 0b01011u ->
#if !EMULATION
    chkIdxPCRnD4 bin
#endif
    let dt = oneDt SIMDTyp32
    render phlp &itstate 0 isInIT bin Op.VST4 dt N OD.OprListMemD
  | 0b10000u ->
#if !EMULATION
    chkSzIdx0PCRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.VLD1 (oneDt SIMDTyp8) N OD.OprListMemA
  | 0b10001u ->
#if !EMULATION
    chkPCRnD2 bin
#endif
    render phlp &itstate 0 isInIT bin Op.VLD2 (oneDt SIMDTyp8) N OD.OprListMemB
  | 0b10010u ->
#if !EMULATION
    chkIdx0PCRnD3 bin
#endif
    render phlp &itstate 0 isInIT bin Op.VLD3 (oneDt SIMDTyp8) N OD.OprListMemC
  | 0b10011u ->
#if !EMULATION
    chkPCRnD4 bin
#endif
    render phlp &itstate 0 isInIT bin Op.VLD4 (oneDt SIMDTyp8) N OD.OprListMemD
  | 0b10100u ->
#if !EMULATION
    chkSzIdx1PCRn bin
#endif
    let dt = oneDt SIMDTyp16
    render phlp &itstate 0 isInIT bin Op.VLD1 dt N OD.OprListMemA
  | 0b10101u ->
#if !EMULATION
    chkPCRnD2 bin
#endif
    let dt = oneDt SIMDTyp16
    render phlp &itstate 0 isInIT bin Op.VLD2 dt N OD.OprListMemB
  | 0b10110u ->
#if !EMULATION
    chkIdx0PCRnD3 bin
#endif
    let dt = oneDt SIMDTyp16
    render phlp &itstate 0 isInIT bin Op.VLD3 dt N OD.OprListMemC
  | 0b10111u ->
#if !EMULATION
    chkPCRnD4 bin
#endif
    let dt = oneDt SIMDTyp16
    render phlp &itstate 0 isInIT bin Op.VLD4 dt N OD.OprListMemD
  | 0b11000u ->
#if !EMULATION
    chkSzIdx2PCRn bin
#endif
    let dt = oneDt SIMDTyp32
    render phlp &itstate 0 isInIT bin Op.VLD1 dt N OD.OprListMemA
  | 0b11001u ->
#if !EMULATION
    chkIdxPCRnD2 bin
#endif
    let dt = oneDt SIMDTyp32
    render phlp &itstate 0 isInIT bin Op.VLD2 dt N OD.OprListMemB
  | 0b11010u ->
#if !EMULATION
    chkIdx10PCRnD3 bin
#endif
    let dt = oneDt SIMDTyp32
    render phlp &itstate 0 isInIT bin Op.VLD3 dt N OD.OprListMemC
  | 0b11011u ->
#if !EMULATION
    chkIdxPCRnD4 bin
#endif
    let dt = oneDt SIMDTyp32
    render phlp &itstate 0 isInIT bin Op.VLD4 dt N OD.OprListMemD
  | _ -> raise ParsingFailureException

/// Advanced SIMD element or structure load/store on page F3-4198.
let parseAdvSIMDElemOrStructLdSt phlp (itstate: byref<BL>) isInIT bin =
  match pickBit bin 23 (* op0 *) with
  | 0b0u -> parseAdvSIMDLdStMulStruct phlp &itstate isInIT bin
  | 0b1u when pickTwo bin 10 = 0b11u ->
    parseAdvSIMDLdSingStruAllLanes phlp &itstate isInIT bin
  | _ (* 1 *) ->
    parseAdvSIMDLdStSingStruOneLane phlp &itstate isInIT bin

/// Load/store, unsigned (register offset) on page F3-4202.
let parseLdStUnsignedRegOffset phlp (itstate: byref<BL>) isInIT bin =
  let rt = pickFour bin 12
  match pickThree bin 20 (* size:L *) with
  | 0b000u ->
#if !EMULATION
    chkThumbPCRtRm bin
#endif
    let struct (q, oprs) =
      if pickTwo bin 4 = 0b00u then struct (W, OD.OprRtMemReg32)
      else struct (N, OD.OprRtMemRegLSL)
    render phlp &itstate 0 isInIT bin Op.STRB None q oprs
  | 0b001u when rt <> 0b1111u ->
#if !EMULATION
    chkPCRm bin
#endif
    let struct (q, oprs) =
      if pickTwo bin 4 = 0b00u then struct (W, OD.OprRtMemReg32)
      else struct (N, OD.OprRtMemRegLSL)
    render phlp &itstate 0 isInIT bin Op.LDRB None q oprs
  | 0b001u ->
#if !EMULATION
    chkPCRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.PLD None N OD.OprMemRegLSL
  | 0b010u ->
#if !EMULATION
    chkThumbPCRtRm bin
#endif
    let struct (q, oprs) =
      if pickTwo bin 4 = 0b00u then struct (W, OD.OprRtMemReg32)
      else struct (N, OD.OprRtMemRegLSL)
    render phlp &itstate 0 isInIT bin Op.STRH None q oprs
  | 0b011u when rt <> 0b1111u ->
#if !EMULATION
    chkPCRm bin
#endif
    let struct (q, oprs) =
      if pickTwo bin 4 = 0b00u then struct (W, OD.OprRtMemReg32)
      else struct (N, OD.OprRtMemRegLSL)
    render phlp &itstate 0 isInIT bin Op.LDRH None q oprs
  | 0b011u ->
#if !EMULATION
    chkPCRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.PLDW None N OD.OprMemRegLSL
  | 0b100u ->
#if !EMULATION
    chkThumbPCRtRm bin
#endif
    let struct (q, oprs) =
      if pickTwo bin 4 = 0b00u then struct (W, OD.OprRtMemReg32)
      else struct (N, OD.OprRtMemRegLSL)
    render phlp &itstate 0 isInIT bin Op.STR None q oprs
  | 0b101u ->
#if !EMULATION
    chkPCRmRtIT bin itstate
#endif
    let struct (q, oprs) =
      if pickTwo bin 4 = 0b00u then struct (W, OD.OprRtMemReg32)
      else struct (N, OD.OprRtMemRegLSL)
    render phlp &itstate 0 isInIT bin Op.LDR None q oprs
  | _ (* 11x *) -> raise ParsingFailureException

/// Load/store, unsigned (immediate, post-indexed) on page F3-4203.
let parseLdStUnsignedImmPostIdx phlp (itstate: byref<BL>) isInIT bin =
  match pickThree bin 20 (* size:L *) with
  | 0b000u ->
#if !EMULATION
    chkRnPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRB None N OD.OprRtMemImmPs
  | 0b001u ->
#if !EMULATION
    chkPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRB None N OD.OprRtMemImmPs
  | 0b010u ->
#if !EMULATION
    chkRnPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRH None N OD.OprRtMemImmPs
  | 0b011u ->
#if !EMULATION
    chkPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRH None N OD.OprRtMemImmPs
  | 0b100u ->
#if !EMULATION
    chkRnPWPCRtWBRn bin
#endif
    /// Alias conditions on page F5-4819.
    let struct (op, oprs, q) =
      if pickFour bin 16 = 0b1101u && extract bin 10 0 = 0b10100000100u
      then struct (Op.PUSH, OD.OprSingleRegsT, W)
      else struct (Op.STR, OD.OprRtMemImmPs, N)
    render phlp &itstate 0 isInIT bin op None q oprs
  | 0b101u ->
#if !EMULATION
    chkPWWBRnPCRtIT bin itstate
#endif
    /// Alias conditions on page F5-4453.
    let struct (op, oprs, q) =
      if pickFour bin 16 = 0b1101u && extract bin 10 0 = 0b01100000100u
      then struct (Op.POP, OD.OprSingleRegsT, W)
      else struct (Op.LDR, OD.OprRtMemImmPs, N)
    render phlp &itstate 0 isInIT bin op None q oprs
  | _ (* 11x *) -> raise ParsingFailureException

/// Load/store, unsigned (negative immediate) on page F3-4203.
let parseLdStUnsignedNegImm phlp (itstate: byref<BL>) isInIT bin =
  let rt = pickFour bin 12
  match pickThree bin 20 (* size:L *) with
  | 0b000u ->
#if !EMULATION
    chkRnPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRB None N OD.OprRtMemImm8M
  | 0b001u when rt <> 0b1111u ->
#if !EMULATION
    chkPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRB None N OD.OprRtMemImm8M
  | 0b001u ->
    render phlp &itstate 0 isInIT bin Op.PLD None N OD.OprMemImm8M
  | 0b010u ->
#if !EMULATION
    chkRnPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRH None N OD.OprRtMemImm8M
  | 0b011u when rt <> 0b1111u ->
#if !EMULATION
    chkPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRH None N OD.OprRtMemImm8M
  | 0b011u ->
#if !EMULATION
    chkPCRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.PLDW None N OD.OprMemImm8M
  | 0b100u ->
#if !EMULATION
    chkRnPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STR None N OD.OprRtMemImm8M
  | 0b101u ->
#if !EMULATION
    chkPWWBRnPCRtIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.LDR None N OD.OprRtMemImm8M
  | _ (* 11x *) -> raise ParsingFailureException

/// Load/store, unsigned (unprivileged) on page F3-4204.
let parseLdStUnsignedUnpriv phlp (itstate: byref<BL>) isInIT bin =
  match pickThree bin 20 (* size:L *) with
  | 0b000u ->
#if !EMULATION
    chkRnPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRBT None N OD.OprRtMemImm8P
  | 0b001u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRBT None N OD.OprRtMemImm8P
  | 0b010u ->
#if !EMULATION
    chkRnPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRHT None N OD.OprRtMemImm8P
  | 0b011u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRHT None N OD.OprRtMemImm8P
  | 0b100u ->
#if !EMULATION
    chkRnPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRT None N OD.OprRtMemImm8P
  | 0b101u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRT None N OD.OprRtMemImm8P
  | _ (* 11x *) -> raise ParsingFailureException

/// Load/store, unsigned (immediate, pre-indexed) on page F3-4204.
let parseLdStUnsignedImmPreIdx phlp (itstate: byref<BL>) isInIT bin =
  match pickThree bin 20 (* size:L *) with
  | 0b000u ->
#if !EMULATION
    chkRnPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRB None N OD.OprRtMemImmPr
  | 0b001u ->
#if !EMULATION
    chkPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRB None N OD.OprRtMemImmPr
  | 0b010u ->
#if !EMULATION
    chkRnPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRH None N OD.OprRtMemImmPr
  | 0b011u ->
#if !EMULATION
    chkPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRH None N OD.OprRtMemImmPr
  | 0b100u ->
#if !EMULATION
    chkRnPWPCRtWBRn bin
#endif
    /// Alias conditions on page F5-4819.
    let struct (op, oprs, q) =
      if pickFour bin 16 = 0b1101u && extract bin 10 0 = 0b10100000100u
      then struct (Op.PUSH, OD.OprSingleRegsT, W)
      else struct (Op.STR, OD.OprRtMemImmPr, N)
    render phlp &itstate 0 isInIT bin op None q oprs
  | 0b101u ->
#if !EMULATION
    chkPWWBRnPCRtIT bin itstate
#endif
    /// Alias conditions on page F5-4453.
    let struct (op, oprs, q) =
      if pickFour bin 16 = 0b1101u && extract bin 10 0 = 0b01100000100u
      then struct (Op.POP, OD.OprSingleRegsT, W)
      else struct (Op.LDR, OD.OprRtMemImmPr, N)
    render phlp &itstate 0 isInIT bin op None q oprs
  | _ (* 11x *) -> raise ParsingFailureException

/// Load/store, unsigned (positive immediate) on page F3-4205.
let parseLdStUnsignedPosImm phlp (itstate: byref<BL>) isInIT bin =
  let rt = pickFour bin 12
  match pickThree bin 20 (* size:L *) with
  | 0b000u ->
#if !EMULATION
    chkRnPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRB None W OD.OprRtMemImm12T
  | 0b001u when rt <> 0b1111u ->
    render phlp &itstate 0 isInIT bin Op.LDRB None W OD.OprRtMemImm12T
  | 0b001u ->
    render phlp &itstate 0 isInIT bin Op.PLD None N OD.OprMemImm12
  | 0b010u ->
#if !EMULATION
    chkRnPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.STRH None W OD.OprRtMemImm12T
  | 0b011u when rt <> 0b1111u ->
    render phlp &itstate 0 isInIT bin Op.LDRH None W OD.OprRtMemImm12T
  | 0b011u ->
    render phlp &itstate 0 isInIT bin Op.PLDW None N OD.OprMemImm12
  | 0b100u ->
#if !EMULATION
    chkRnPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.STR None W OD.OprRtMemImm12T
  | 0b101u ->
#if !EMULATION
    chkPCRtIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.LDR None W OD.OprRtMemImm12T
  | _ (* 11x *) -> raise ParsingFailureException

/// Load, unsigned (literal) on page F3-4205.
let parseLdUnsignedLiteral phlp (itstate: byref<BL>) isInIT bin =
  let rt = pickFour bin 12
  match pickThree bin 20 (* size:L *) with
  | 0b001u | 0b011u when rt = 0b1111u ->
    render phlp &itstate 0 isInIT bin Op.PLD None N OD.OprLabel12T
  | 0b001u ->
    render phlp &itstate 0 isInIT bin Op.LDRB None N OD.OprRtLabel12
  | 0b011u ->
    render phlp &itstate 0 isInIT bin Op.LDRH None N OD.OprRtLabel12
  | 0b101u ->
#if !EMULATION
    chkPCRtIT bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.LDR None W OD.OprRtLabel12
  | 0b110u | 0b111u -> raise ParsingFailureException
  | _ -> raise ParsingFailureException

/// Load/store, signed (register offset) on page F3-4206.
let parseLdStSignedRegOffset phlp (itstate: byref<BL>) isInIT bin =
  let rt = pickFour bin 12
  match pickTwo bin 21 with
  | 0b00u when rt <> 0b1111u ->
#if !EMULATION
    chkPCRm bin
#endif
    let struct (q, oprs) =
      if pickTwo bin 4 (* imm2 *) = 0b00u then struct (W, OD.OprRtMemReg32)
      else struct (N, OD.OprRtMemRegLSL)
    render phlp &itstate 0 isInIT bin Op.LDRSB None q oprs
  | 0b00u ->
#if !EMULATION
    chkPCRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.PLI None N OD.OprMemRegT
  | 0b01u when rt <> 0b1111u ->
#if !EMULATION
    chkPCRm bin
#endif
    let struct (q, oprs) =
      if pickTwo bin 4 (* imm2 *) = 0b00u then struct (W, OD.OprRtMemReg32)
      else struct (N, OD.OprRtMemRegLSL)
    render phlp &itstate 0 isInIT bin Op.LDRSH None q oprs
  | 0b01u ->
    render phlp &itstate 0 isInIT bin Op.NOP None N OD.OprNo
  | _ (* 1x *) -> raise ParsingFailureException

/// Load/store, signed (immediate, post-indexed) on page F3-4206.
let parseLdStoreSignedImmPostIdx phlp (itstate: byref<BL>) isInIT bin =
  match pickTwo bin 21 (* size *) with
  | 0b00u ->
#if !EMULATION
    chkPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRSB None N OD.OprRtMemImmPs
  | 0b01u ->
#if !EMULATION
    chkPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRSH None N OD.OprRtMemImmPs
  | _ (* 1x *) -> raise ParsingFailureException

/// Load/store, signed (negative immediate) on page F3-4207.
let parseLdStSignedNegImm phlp (itstate: byref<BL>) isInIT bin =
  let rt = pickFour bin 12
  match pickTwo bin 21 (* size *) with
  | 0b00u when rt <> 0b1111u ->
#if !EMULATION
    chkPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRSB None N OD.OprRtMemImm8M
  | 0b00u ->
    render phlp &itstate 0 isInIT bin Op.PLI None N OD.OprMemImm8M
  | 0b01u when rt <> 0b1111u ->
#if !EMULATION
    chkPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRSH None N OD.OprRtMemImm8M
  | 0b01u -> render phlp &itstate 0 isInIT bin Op.NOP None N OD.OprNo
  | _ (* 1x *) -> raise ParsingFailureException

/// Load/store, signed (unprivileged) on page F3-4207.
let parseLdStSignedUnpriv phlp (itstate: byref<BL>) isInIT bin =
  match pickTwo bin 21 (* size *) with
  | 0b00u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRSBT None N OD.OprRtMemImm8P
  | 0b01u ->
#if !EMULATION
    chkPCRt bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRSHT None N OD.OprRtMemImm8P
  | _ (* 1x *) -> raise ParsingFailureException

/// Load/store, signed (immediate, pre-indexed) on page F3-4208.
let parseLdStSignedImmPreIdx phlp (itstate: byref<BL>) isInIT bin =
  match pickTwo bin 21 (* size *) with
  | 0b00u ->
#if !EMULATION
    chkPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRSB None N OD.OprRtMemImmPr
  | 0b01u ->
#if !EMULATION
    chkPWPCRtWBRn bin
#endif
    render phlp &itstate 0 isInIT bin Op.LDRSH None N OD.OprRtMemImmPr
  | _ (* 1x *) -> raise ParsingFailureException

/// Load/store, signed (positive immediate) on page F3-4208.
let parseLdStSignedPosImm phlp (itstate: byref<BL>) isInIT bin =
  let rt = pickFour bin 12
  match pickTwo bin 21 (* size *) with
  | 0b00u when rt <> 0b1111u ->
    render phlp &itstate 0 isInIT bin Op.LDRSB None N OD.OprRtMemImm12T
  | 0b00u ->
    render phlp &itstate 0 isInIT bin Op.PLI None N OD.OprMemImm12
  | 0b01u when rt <> 0b1111u ->
    render phlp &itstate 0 isInIT bin Op.LDRSH None N OD.OprRtMemImm12T
  | 0b01u -> render phlp &itstate 0 isInIT bin Op.NOP None N OD.OprNo
  | _ (* 1x *) -> raise ParsingFailureException

/// Load, signed (literal) on page F3-4209.
let parseLoadSignedLiteral phlp (itstate: byref<BL>) isInIT bin =
  let rt = pickFour bin 12
  match pickTwo bin 21 (* size *) with
  | 0b00u when rt <> 0b1111u ->
    render phlp &itstate 0 isInIT bin Op.LDRSB None N OD.OprRtLabel12
  | 0b00u ->
    render phlp &itstate 0 isInIT bin Op.PLI None N OD.OprMemImm12
  | 0b01u when rt <> 0b1111u ->
    render phlp &itstate 0 isInIT bin Op.LDRSH None N OD.OprRtLabel12
  | 0b01u -> render phlp &itstate 0 isInIT bin Op.NOP None N OD.OprNo
  | _ (* 1x *) -> raise ParsingFailureException

/// Load/store single on page F3-4201.
let parseLdStSingle phlp (itstate: byref<BL>) isInIT bin =
  let o2 = pickFour bin 16 (* op2 *)
  let decodeFields (* op0:op1:op3 *) =
    (pickTwo bin 23 <<< 7) + (pickBit bin 20 <<< 6) + (extract bin 11 6)
  match decodeFields (* op0:op1:op3 *) with
  | 0b000000000u | 0b001000000u (* 00x000000 *) when o2 <> 0b1111u ->
    parseLdStUnsignedRegOffset phlp &itstate isInIT bin
  | 0b000000001u | 0b001000001u (* 00x000001 *) when o2 <> 0b1111u ->
    raise ParsingFailureException
  | b when b &&& 0b110111110u = 0b000000010u (* 00x00001x *) && o2 <> 0b1111u ->
    raise ParsingFailureException
  | b when b &&& 0b110111100u = 0b000000100u (* 00x0001xx *) && o2 <> 0b1111u ->
    raise ParsingFailureException
  | b when b &&& 0b110111000u = 0b000001000u (* 00x001xxx *) && o2 <> 0b1111u ->
    raise ParsingFailureException
  | b when b &&& 0b110110000u = 0b000010000u (* 00x01xxxx *) && o2 <> 0b1111u ->
    raise ParsingFailureException
  | b when b &&& 0b110110100u = 0b000100000u (* 00x10x0xx *) && o2 <> 0b1111u ->
    raise ParsingFailureException
  | b when b &&& 0b110110100u = 0b000100100u (* 00x10x1xx *) && o2 <> 0b1111u ->
    parseLdStUnsignedImmPostIdx phlp &itstate isInIT bin
  | b when b &&& 0b110111100u = 0b000110000u (* 00x1100xx *) && o2 <> 0b1111u ->
    parseLdStUnsignedNegImm phlp &itstate isInIT bin
  | b when b &&& 0b110111100u = 0b000111000u (* 00x1110xx *) && o2 <> 0b1111u ->
    parseLdStUnsignedUnpriv phlp &itstate isInIT bin
  | b when b &&& 0b110110100u = 0b000110100u (* 00x11x1xx *) && o2 <> 0b1111u ->
    parseLdStUnsignedImmPreIdx phlp &itstate isInIT bin
  | b when b &&& 0b110000000u = 0b010000000u (* 01xxxxxxx *) && o2 <> 0b1111u ->
    parseLdStUnsignedPosImm phlp &itstate isInIT bin
  | b when b &&& 0b100000000u = 0b000000000u (* 0xxxxxxxx *) && o2 = 0b1111u ->
    parseLdUnsignedLiteral phlp &itstate isInIT bin
  | 0b101000000u when o2 <> 0b1111u ->
    parseLdStSignedRegOffset phlp &itstate isInIT bin
  | 0b101000001u when o2 <> 0b1111u -> raise ParsingFailureException
  | b when b &&& 0b111111110u = 0b101000010u (* 10100001x *) && o2 <> 0b1111u ->
    raise ParsingFailureException
  | b when b &&& 0b111111100u = 0b101000100u (* 1010001xx *) && o2 <> 0b1111u ->
    raise ParsingFailureException
  | b when b &&& 0b111111000u = 0b101001000u (* 101001xxx *) && o2 <> 0b1111u ->
    raise ParsingFailureException
  | b when b &&& 0b111110000u = 0b101010000u (* 10101xxxx *) && o2 <> 0b1111u ->
    raise ParsingFailureException
  | b when b &&& 0b111110100u = 0b101100000u (* 10110x0xx *) && o2 <> 0b1111u ->
    raise ParsingFailureException
  | b when b &&& 0b111110100u = 0b101100100u (* 10110x1xx *) && o2 <> 0b1111u ->
    parseLdStoreSignedImmPostIdx phlp &itstate isInIT bin
  | b when b &&& 0b111111100u = 0b101110000u (* 1011100xx *) && o2 <> 0b1111u ->
    parseLdStSignedNegImm phlp &itstate isInIT bin
  | b when b &&& 0b111111100u = 0b101111000u (* 1011110xx *) && o2 <> 0b1111u ->
    parseLdStSignedUnpriv phlp &itstate isInIT bin
  | b when b &&& 0b111110100u = 0b101110100u (* 10111x1xx *) && o2 <> 0b1111u ->
    parseLdStSignedImmPreIdx phlp &itstate isInIT bin
  | b when b &&& 0b111000000u = 0b111000000u (* 111xxxxxx *) && o2 <> 0b1111u ->
    parseLdStSignedPosImm phlp &itstate isInIT bin
  | b when b &&& 0b101000000u = 0b101000000u (* 1x1xxxxxx *) && o2 = 0b1111u ->
    parseLoadSignedLiteral phlp &itstate isInIT bin
  | _ -> raise ParsingFailureException

/// Register extends on page F3-4210.
let parseRegExtends phlp (itstate: byref<BL>) isInIT bin =
  let rn = pickFour bin 16
  match pickThree bin 20 (* op1:U *) with
  | 0b000u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SXTAH None N OD.OprRdRnRmRorT
  | 0b000u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    let struct (q, oprs) =
      if pickTwo bin 4 (* rotate *) = 0b00u then struct (W, OD.OprRdRmT32)
      else struct (N, OD.OprRdRmRorT)
    render phlp &itstate 0 isInIT bin Op.SXTH None q oprs
  | 0b001u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UXTAH None N OD.OprRdRnRmRorT
  | 0b001u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    let struct (q, oprs) =
      if pickTwo bin 4 (* rotate *) = 0b00u then struct (W, OD.OprRdRmT32)
      else struct (N, OD.OprRdRmRorT)
    render phlp &itstate 0 isInIT bin Op.UXTH None q oprs
  | 0b010u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SXTAB16 None N OD.OprRdRnRmRorT
  | 0b010u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SXTB16 None N OD.OprRdRmRorT
  | 0b011u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UXTAB16 None N OD.OprRdRnRmRorT
  | 0b011u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UXTB16 None N OD.OprRdRmRorT
  | 0b100u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SXTAB None N OD.OprRdRnRmRorT
  | 0b100u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    let struct (q, oprs) =
      if pickTwo bin 4 (* rotate *) = 0b00u then struct (W, OD.OprRdRmT32)
      else struct (N, OD.OprRdRmRorT)
    render phlp &itstate 0 isInIT bin Op.SXTB None q oprs
  | 0b101u when rn <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UXTAB None N OD.OprRdRnRmRorT
  | 0b101u ->
#if !EMULATION
    chkThumbPCRdRm bin
#endif
    let struct (q, oprs) =
      if pickTwo bin 4 (* rotate *) = 0b00u then struct (W, OD.OprRdRmT32)
      else struct (N, OD.OprRdRmRorT)
    render phlp &itstate 0 isInIT bin Op.UXTB None q oprs
  | _ (* 11x *) -> raise ParsingFailureException

/// Parallel add-subtract on page F3-4210.
let parseParallelAddSub phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickThree bin 20) (pickThree bin 4) 3 (* op1:U:H:S *) with
  | 0b000000u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SADD8 None N OD.OprRdRnRmT32
  | 0b000001u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.QADD8 None N OD.OprRdRnRmT32
  | 0b000010u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SHADD8 None N OD.OprRdRnRmT32
  | 0b000011u -> raise ParsingFailureException
  | 0b000100u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UADD8 None N OD.OprRdRnRmT32
  | 0b000101u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UQADD8 None N OD.OprRdRnRmT32
  | 0b000110u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UHADD8 None N OD.OprRdRnRmT32
  | 0b000111u -> raise ParsingFailureException
  | 0b001000u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SADD16 None N OD.OprRdRnRmT32
  | 0b001001u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.QADD16 None N OD.OprRdRnRmT32
  | 0b001010u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SHADD16 None N OD.OprRdRnRmT32
  | 0b001011u -> raise ParsingFailureException
  | 0b001100u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UADD16 None N OD.OprRdRnRmT32
  | 0b001101u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UQADD16 None N OD.OprRdRnRmT32
  | 0b001110u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UHADD16 None N OD.OprRdRnRmT32
  | 0b001111u -> raise ParsingFailureException
  | 0b010000u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SASX None N OD.OprRdRnRmT32
  | 0b010001u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.QASX None N OD.OprRdRnRmT32
  | 0b010010u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SHASX None N OD.OprRdRnRmT32
  | 0b010011u -> raise ParsingFailureException
  | 0b010100u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UASX None N OD.OprRdRnRmT32
  | 0b010101u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UQASX None N OD.OprRdRnRmT32
  | 0b010110u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UHASX None N OD.OprRdRnRmT32
  | 0b010111u -> raise ParsingFailureException
  | 0b100000u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SSUB8 None N OD.OprRdRnRmT32
  | 0b100001u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.QSUB8 None N OD.OprRdRnRmT32
  | 0b100010u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SHSUB8 None N OD.OprRdRnRmT32
  | 0b100011u -> raise ParsingFailureException
  | 0b100100u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.USUB8 None N OD.OprRdRnRmT32
  | 0b100101u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UQSUB8 None N OD.OprRdRnRmT32
  | 0b100110u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UHSUB8 None N OD.OprRdRnRmT32
  | 0b100111u -> raise ParsingFailureException
  | 0b101000u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SSUB16 None N OD.OprRdRnRmT32
  | 0b101001u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.QSUB16 None N OD.OprRdRnRmT32
  | 0b101010u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SHSUB16 None N OD.OprRdRnRmT32
  | 0b101011u -> raise ParsingFailureException
  | 0b101100u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.USUB16 None N OD.OprRdRnRmT32
  | 0b101101u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UQSUB16 None N OD.OprRdRnRmT32
  | 0b101110u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UHSUB16 None N OD.OprRdRnRmT32
  | 0b101111u -> raise ParsingFailureException
  | 0b110000u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SSAX None N OD.OprRdRnRmT32
  | 0b110001u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.QSAX None N OD.OprRdRnRmT32
  | 0b110010u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SHSAX None N OD.OprRdRnRmT32
  | 0b110011u -> raise ParsingFailureException
  | 0b110100u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.USAX None N OD.OprRdRnRmT32
  | 0b110101u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UQSAX None N OD.OprRdRnRmT32
  | 0b110110u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UHSAX None N OD.OprRdRnRmT32
  | 0b110111u -> raise ParsingFailureException
  | _ (* 111xxx *) -> raise ParsingFailureException

/// Data-processing (two source registers) on page F3-4212.
let parseDataProcTwoSrcRegs phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickThree bin 20) (pickTwo bin 4) 2 (* op1:op2 *) with
  | 0b00000u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.QADD None N OD.OprRdRmRnT
  | 0b00001u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.QDADD None N OD.OprRdRmRnT
  | 0b00010u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.QSUB None N OD.OprRdRmRnT
  | 0b00011u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.QDSUB None N OD.OprRdRmRnT
  | 0b00100u ->
#if !EMULATION
    chkRmRnPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.REV None W OD.OprRdRmT32
  | 0b00101u ->
#if !EMULATION
    chkRmRnPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.REV16 None W OD.OprRdRmT32
  | 0b00110u ->
#if !EMULATION
    chkRmRnPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.RBIT None N OD.OprRdRmT32
  | 0b00111u ->
#if !EMULATION
    chkRmRnPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.REVSH None W OD.OprRdRmT32
  | 0b01000u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SEL None N OD.OprRdRnRmT32
  | 0b01001u -> raise ParsingFailureException
  | 0b01010u | 0b01011u (* 0101x *) -> raise ParsingFailureException
  | 0b01100u ->
#if !EMULATION
    chkRmRnPCRdRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.CLZ None N OD.OprRdRmT32
  | 0b01101u -> raise ParsingFailureException
  | 0b01110u | 0b01111u (* 0111x *) -> raise ParsingFailureException
  | 0b10000u ->
#if !EMULATION
    chkITPCRdRnRm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.CRC32B None N OD.OprRdRnRmT32
  | 0b10001u ->
#if !EMULATION
    chkITPCRdRnRm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.CRC32H None N OD.OprRdRnRmT32
  | 0b10010u ->
#if !EMULATION
    chkITPCRdRnRm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.CRC32W None N OD.OprRdRnRmT32
  | 0b10011u -> raise UnpredictableException
  | 0b10100u ->
#if !EMULATION
    chkITPCRdRnRm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.CRC32CB None N OD.OprRdRnRmT32
  | 0b10101u ->
#if !EMULATION
    chkITPCRdRnRm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.CRC32CH None N OD.OprRdRnRmT32
  | 0b10110u ->
#if !EMULATION
    chkITPCRdRnRm bin itstate
#endif
    render phlp &itstate 0 isInIT bin Op.CRC32CW None N OD.OprRdRnRmT32
  | 0b10111u -> raise UnpredictableException
  | _ (* 11xxx *) -> raise ParsingFailureException

/// Data-processing (register) on page F3-4209.
let parseDataProcessingReg phlp (itstate: byref<BL>) isInIT bin =
  let decodeFields (* op0:op1:op2 *) =
    (pickBit bin 23 <<< 8) + (pickFour bin 12 <<< 4) + (pickFour bin 4)
  match decodeFields with
  | 0b011110000u ->
#if !EMULATION
    chkThumbPCRdRmRs bin
#endif
    let struct (op, q) =
      if pickBit bin 20 (* S *) = 1u then
        let q = if inITBlock itstate |> not then W else N
        let opcode =
          (* Alias conditions on page F5-4562 *)
          match pickTwo bin 21 (* stype *) with
          | 0b10u -> Op.ASRS
          | 0b00u -> Op.LSLS
          | 0b01u -> Op.LSRS
          | _ (* 11 *) -> Op.RORS
        struct (opcode, q)
      else
        let q = if inITBlock itstate then W else N
        let opcode =
          (* Alias conditions on page F5-4562 *)
          match pickTwo bin 21 (* stype *) with
          | 0b10u -> Op.ASR
          | 0b00u -> Op.LSL
          | 0b01u -> Op.LSR
          | _ (* 11 *) -> Op.ROR
        struct (opcode, q)
    render phlp &itstate 0 isInIT bin op None q OD.OprRdRmRsT
  | 0b011110001u -> raise ParsingFailureException
  | 0b011110010u | 0b011110011u (* 01111001x *) -> raise ParsingFailureException
  | b when b &&& 0b111111100u = 0b011110100u (* 0111101xx *) ->
    raise ParsingFailureException
  | b when b &&& 0b111111000u = 0b011111000u (* 011111xxx *) ->
    parseRegExtends phlp &itstate isInIT bin
  | b when b &&& 0b111111000u = 0b111110000u (* 111110xxx *) ->
    parseParallelAddSub phlp &itstate isInIT bin
  | b when b &&& 0b111111100u = 0b111111000u (* 1111110xx *) ->
    parseDataProcTwoSrcRegs phlp &itstate isInIT bin
  | b when b &&& 0b111111100u = 0b111111100u (* 1111111xx *) ->
    raise ParsingFailureException
  | _ (* x != 1111 xxxx *) -> raise ParsingFailureException

/// Multiply and absolute difference on page F3-4213.
let parseMulAndAbsDiff phlp (itstate: byref<BL>) isInIT bin =
  let ra = pickFour bin 12
  match concat (pickThree bin 20) (pickTwo bin 4) 2 (* op1:op2 *) with
  | 0b00000u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.MLA None N OD.OprRdRnRmRaT
  | 0b00001u ->
#if !EMULATION
    chkThumbPCRdRnRmRa bin
#endif
    render phlp &itstate 0 isInIT bin Op.MLS None N OD.OprRdRnRmRaT
  | 0b00010u | 0b00011u (* 0001x *) -> raise ParsingFailureException
  | 0b00000u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    let q = if inITBlock itstate then W else N
    render phlp &itstate 0 isInIT bin Op.MUL None q OD.OprRdRnRmT32
  | 0b00100u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMLABB None N OD.OprRdRnRmRaT
  | 0b00101u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMLABT None N OD.OprRdRnRmRaT
  | 0b00110u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMLATB None N OD.OprRdRnRmRaT
  | 0b00111u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMLATT None N OD.OprRdRnRmRaT
  | 0b00100u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMULBB None N OD.OprRdRnRmT32
  | 0b00101u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMULBT None N OD.OprRdRnRmT32
  | 0b00110u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMULTB None N OD.OprRdRnRmT32
  | 0b00111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMULTT None N OD.OprRdRnRmT32
  | 0b01000u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMLAD None N OD.OprRdRnRmRaT
  | 0b01001u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMLADX None N OD.OprRdRnRmRaT
  | 0b01010u | 0b01011u (* 0101x *) -> raise ParsingFailureException
  | 0b01000u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMUAD None N OD.OprRdRnRmT32
  | 0b01001u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMUADX None N OD.OprRdRnRmT32
  | 0b01100u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMLAWB None N OD.OprRdRnRmRaT
  | 0b01101u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMLAWT None N OD.OprRdRnRmRaT
  | 0b01110u | 0b01111u (* 0111x *) -> raise ParsingFailureException
  | 0b01100u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMULWB None N OD.OprRdRnRmT32
  | 0b01101u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMULWT None N OD.OprRdRnRmT32
  | 0b10000u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMLSD None N OD.OprRdRnRmRaT
  | 0b10001u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMLSDX None N OD.OprRdRnRmRaT
  | 0b10010u | 0b10011u (* 1001x *) -> raise ParsingFailureException
  | 0b10000u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMUSD None N OD.OprRdRnRmT32
  | 0b10001u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMUSDX None N OD.OprRdRnRmT32
  | 0b10100u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMMLA None N OD.OprRdRnRmRaT
  | 0b10101u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMMLAR None N OD.OprRdRnRmRaT
  | 0b10110u | 0b10111u (* 1011x *) -> raise ParsingFailureException
  | 0b10100u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMMUL None N OD.OprRdRnRmT32
  | 0b10101u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMMULR None N OD.OprRdRnRmT32
  | 0b11000u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMMLS None N OD.OprRdRnRmRaT
  | 0b11001u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMMLSR None N OD.OprRdRnRmRaT
  | 0b11010u | 0b11011u (* 1101x *) -> raise ParsingFailureException
  | 0b11100u when ra <> 0b1111u ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.USADA8 None N OD.OprRdRnRmRaT
  | 0b11101u -> raise ParsingFailureException
  | 0b11110u | 0b11111u (* 1111x *) -> raise ParsingFailureException
  | _ (* 11100 *) ->
#if !EMULATION
    chkThumbPCRdRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.USAD8 None N OD.OprRdRnRmT32

/// Multiply, multiply accumulate, and absolute difference on page F3-4213.
let parseMulAccumlateAndAbsDiff phlp (itstate: byref<BL>) isInIT bin =
  match pickTwo bin 6 (* op0 *) with
  | 0b00u -> parseMulAndAbsDiff phlp &itstate isInIT bin
  | 0b01u -> raise ParsingFailureException
  | _ (* 11 *) -> raise ParsingFailureException

/// Long multiply and divide on page F3-4163.
let parseLongMulAndDiv phlp (itstate: byref<BL>) isInIT bin =
  let op2 = pickFour bin 4
  match pickThree bin 20 (* op1 *) with
  | 0b000u when op2 <> 0b0000u -> raise ParsingFailureException
  | 0b000u ->
#if !EMULATION
    chkThumbPCRdlRdhRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.SMULL None N OD.OprRdlRdhRnRmT
  | 0b001u when op2 <> 0b1111u -> raise ParsingFailureException
  | 0b001u ->
#if !EMULATION
    chkThumbPCRdRnRmRaNot bin
#endif
    render phlp &itstate 0 isInIT bin Op.SDIV None N OD.OprRdRnRmT32
  | 0b010u when op2 <> 0b0000u -> raise ParsingFailureException
  | 0b010u ->
#if !EMULATION
    chkThumbPCRdlRdhRnRm bin
#endif
    render phlp &itstate 0 isInIT bin Op.UMULL None N OD.OprRdlRdhRnRmT
  | 0b011u when op2 <> 0b1111u -> raise ParsingFailureException
  | 0b011u ->
#if !EMULATION
    chkThumbPCRdRnRmRaNot bin
#endif
    render phlp &itstate 0 isInIT bin Op.UDIV None N OD.OprRdRnRmT32
  | _ ->
    match concat (pickThree bin 20) (pickFour bin 4) 4 (* op1:op2 *) with
    | 0b1000000u ->
#if !EMULATION
      chkThumbPCRdlRdhRnRm bin
#endif
      render phlp &itstate 0 isInIT bin Op.SMLAL None N OD.OprRdlRdhRnRmT
    | 0b1000001u -> raise ParsingFailureException
    | 0b1000010u | 0b1000011u (* 100001x *) -> raise ParsingFailureException
    | 0b1000100u | 0b1000101u | 0b1000110u | 0b1000111u (* 10001xx *) ->
      raise ParsingFailureException
    | 0b1001000u ->
#if !EMULATION
      chkThumbPCRdlRdhRnRm bin
#endif
      render phlp &itstate 0 isInIT bin Op.SMLALBB None N OD.OprRdlRdhRnRmT
    | 0b1001001u ->
#if !EMULATION
      chkThumbPCRdlRdhRnRm bin
#endif
      render phlp &itstate 0 isInIT bin Op.SMLALBT None N OD.OprRdlRdhRnRmT
    | 0b1001010u ->
#if !EMULATION
      chkThumbPCRdlRdhRnRm bin
#endif
      render phlp &itstate 0 isInIT bin Op.SMLALTB None N OD.OprRdlRdhRnRmT
    | 0b1001011u ->
#if !EMULATION
      chkThumbPCRdlRdhRnRm bin
#endif
      render phlp &itstate 0 isInIT bin Op.SMLALTT None N OD.OprRdlRdhRnRmT
    | 0b1001100u ->
#if !EMULATION
      chkThumbPCRdlRdhRnRm bin
#endif
      render phlp &itstate 0 isInIT bin Op.SMLALD None N OD.OprRdlRdhRnRmT
    | 0b1001101u ->
#if !EMULATION
      chkThumbPCRdlRdhRnRm bin
#endif
      render phlp &itstate 0 isInIT bin Op.SMLALDX None N OD.OprRdlRdhRnRmT
    | 0b1001110u | 0b1001111u (* 100111x *) -> raise ParsingFailureException
    | b when b &&& 0b1111000u = 0b1010000u (* 1010xxx *) ->
      raise ParsingFailureException
    | 0b1011000u | 0b1011001u | 0b1011010u | 0b1011011u (* 10110xx *) ->
      raise ParsingFailureException
    | 0b1011100u ->
#if !EMULATION
      chkThumbPCRdlRdhRnRm bin
#endif
      render phlp &itstate 0 isInIT bin Op.SMLSLD None N OD.OprRdlRdhRnRmT
    | 0b1011101u ->
#if !EMULATION
      chkThumbPCRdlRdhRnRm bin
#endif
      render phlp &itstate 0 isInIT bin Op.SMLSLDX None N OD.OprRdlRdhRnRmT
    | 0b1011110u | 0b1011111u (* 101111x *) -> raise ParsingFailureException
    | 0b1100000u ->
#if !EMULATION
      chkThumbPCRdlRdhRnRm bin
#endif
      render phlp &itstate 0 isInIT bin Op.UMLAL None N OD.OprRdlRdhRnRmT
    | 0b1100001u -> raise ParsingFailureException
    | 0b1100010u | 0b1100011u (* 110001x *) -> raise ParsingFailureException
    | 0b1100100u | 0b1100101u (* 110010x *) -> raise ParsingFailureException
    | 0b1100110u ->
#if !EMULATION
      chkThumbPCRdlRdhRnRm bin
#endif
      render phlp &itstate 0 isInIT bin Op.UMAAL None N OD.OprRdlRdhRnRmT
    | 0b1100111u -> raise ParsingFailureException
    | b when b &&& 0b1111000u = 0b1101000u (* 1101xxx *) ->
      raise ParsingFailureException
    | _ (* 111xxxx *) -> raise ParsingFailureException

/// 32-bit on page F3-4159.
let parse32Bit phlp (itstate: byref<BL>) isInIT bin =
  match concat (pickFour bin 25) (pickBit bin 15) 1 (* op0:op3 *) with
  | b when b &&& 0b01100u = 0b01100u (* x11x xxxxx x *) ->
    parseSystemRegAccessAdvSIMDAndFP phlp &itstate isInIT bin
  | 0b01000u | 0b01001u when pickBit bin 22 = 0u (* 0100 xx0xx x *) ->
    parseLdStMul phlp &itstate isInIT bin
  | 0b01000u | 0b01001u when pickBit bin 22 = 1u (* 0100 xx1xx x *) ->
    parseLdStDualExclusiveAndTblBranch phlp &itstate isInIT bin
  | 0b01010u | 0b01011u (* 0101 xxxxx x *) ->
    parseDataProcessingShiftReg phlp &itstate isInIT bin
  | 0b10001u | 0b10011u | 0b10101u | 0b10111u (* 10xx xxxxx 1 *) ->
    parseBranchAndMiscCtrl phlp &itstate isInIT bin
  | 0b10000u | 0b10100u (* 10x0 xxxxx 0 *) ->
    parseDataProcessingModImm phlp &itstate isInIT bin
  | 0b10010u | 0b10110u when pickBit bin 20 = 0u (* 10x1 xxxx0 0 *) ->
    parseDataProcessingPlainBinImm phlp &itstate isInIT bin
  | 0b10010u | 0b10110u when pickBit bin 20 = 1u (* 10x1 xxxx1 0 *) ->
    raise ParsingFailureException
  | 0b11000u | 0b11001u
    when pickFive bin 20 &&& 0b10001u = 0b10000u (* 1100 1xxx0 x *) ->
    parseAdvSIMDElemOrStructLdSt phlp &itstate isInIT bin
  | 0b11000u | 0b11001u (* 1100 != 1xxx0 x *) ->
    parseLdStSingle phlp &itstate isInIT bin
  | 0b11010u | 0b11011u when pickBit bin 24 = 0u (* 1101 0xxxx x *) ->
    parseDataProcessingReg phlp &itstate isInIT bin
  | 0b11010u | 0b11011u when pickTwo bin 23 = 0b10u (* 1101 10xxx x *) ->
    parseMulAccumlateAndAbsDiff phlp &itstate isInIT bin
  | 0b11010u | 0b11011u when pickTwo bin 23 = 0b11u (* 1101 11xxx x *) ->
    parseLongMulAndDiv phlp &itstate isInIT bin
  | _ -> raise ParsingFailureException

/// ARM Architecture Reference Manual ARMv8-A, ARM DDI 0487F.c ID072120
/// T32 instruction set encoding on page F3-4148.
let parse (span: B2R2.ByteSpan) (phlp: ParsingHelper) (itstate: byref<BL>) =
  let isInIT = not itstate.IsEmpty
  phlp.Cond <- getCondWithITSTATE itstate
  phlp.IsAdd <- true
  let bin = phlp.BinReader.ReadUInt16 (span, 0) |> uint32
  match pickFive bin 11 (* op0:op1 *) with
  | 0b11100u ->
#if !EMULATION
    chkInITLastIT itstate
#endif
    phlp.Len <- 2u
    render phlp &itstate 0 isInIT bin Op.B None N OD.OprLabelT
  | 0b11101u | 0b11110u | 0b11111u (* 111 != 00 *) ->
    let bin2 = phlp.BinReader.ReadUInt16 (span, 2) |> uint32
    phlp.Len <- 4u
    parse32Bit phlp &itstate isInIT ((bin <<< 16) + (uint32 bin2))
  | _ (* != 111 xx *) ->
    phlp.Len <- 2u
    parse16Bit phlp &itstate isInIT bin

// vim: set tw=80 sts=2 sw=2:
