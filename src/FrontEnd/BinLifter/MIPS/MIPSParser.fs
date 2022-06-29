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

module B2R2.FrontEnd.BinLifter.MIPS.Parser

open System
open B2R2
open B2R2.FrontEnd.BinLifter.MIPS.Helper
open B2R2.FrontEnd.BinLifter.MIPS.Utils

/// Check encoded field value
let nd binary target = pickBit binary 17u = target
let tf binary target = pickBit binary 16u = target
let ztf binary target = extract binary 17u 16u (* 0:tf *) = target
let cc binary target = extract binary 10u 8u = target
let chk10to0 binary target = extract binary 10u 0u = target
let chk10to6 binary target = extract binary 10u 6u = target
let chk15to6 binary target = extract binary 15u 6u = target
let chk15to11 binary target = extract binary 15u 11u = target
let chk20to6 binary target = extract binary 20u 6u = target
let chk20to16 binary target = extract binary 20u 16u = target
let chk25to11 binary target = extract binary 25u 11u = target
let chk25to21 binary target = extract binary 25u 21u = target

let parseNOP binary =
  match extract binary 10u 6u with
  | 0u -> Op.NOP, None, None, NoOperand
  | 1u -> Op.SSNOP, None, None, NoOperand
  | 3u -> Op.EHB, None, None, NoOperand
  | 5u -> Op.PAUSE, None, None, NoOperand
  | _ -> failwith "Not Implemented."

let parseSLL binary =
  match extract binary 25u 11u with
  | 0u -> parseNOP binary
  | _ when extract binary 25u 21u = 0u -> Op.SLL, None, None, getRdRtSa binary
  | _ -> failwith "Not Implemented."

let parseJALR binary =
  match extract binary 15u 11u, pickBit binary 10u with
  | 0u, 0u -> Op.JR, None, None, getRs binary
  | 31u, 0u -> Op.JALR, None, None, getRs binary
  | 31u, 1u -> Op.JALRHB, None, None, getRs binary
  | _, 0u -> Op.JALR, None, None, getRdRs binary
  | _, 1u -> Op.JALRHB, None, None, getRdRs binary
  | _ -> failwith "Not Implemented."

let parseJR binary =
  match pickBit binary 10u with
  | 0u -> Op.JR, None, None, getRs binary
  | _ -> Op.JRHB, None, None, getRs binary

let parseDIVU arch binary =
  match extract binary 15u 11u, extract binary 10u 6u with
  | 0u, 0u -> Op.DIVU, None, None, getRsRt binary
  | _, 0b00010u when isMIPS32R6 arch -> Op.DIVU, None, None, getRdRsRt binary
  | _ -> failwith "Not Implemented."

let parseR2CLZ binary =
  match extract binary 10u 6u with
  | 0u -> Op.CLZ, None, None, getRdRs binary
  | _ -> failwith "Not Implemented."

let parseR6CLZ binary =
  match extract binary 20u 16u with
  | 0u -> Op.CLZ, None, None, getRdRs binary
  | _ -> failwith "Not Implemented."

let parseMFHI arch binary =
  match isRel2 arch, extract binary 25u 16u, extract binary 10u 6u with
  | true, 0u, 0u -> Op.MFHI, None, None, getRd binary
  | false, _, 1u -> parseR6CLZ binary
  | _ -> failwith "Not Implemented."

let parseR2DCLZ binary =
  match extract binary 10u 6u with
  | 0u -> Op.DCLZ, None, None, getRdRs binary
  | _ -> failwith "Not Implemented."

let parseR6DCLZ binary =
  match extract binary 20u 16u with
  | 0u -> Op.DCLZ, None, None, getRdRs binary
  | _ -> failwith "Not Implemented."

let parseMFLO arch binary =
  match isRel2 arch, extract binary 25u 16u, extract binary 10u 6u with
  | true, 0u, 0u -> Op.MFLO, None, None, getRd binary
  | false, _, 1u -> parseR6DCLZ binary
  | _ -> failwith "Not Implemented."

/// Table A.3 MIPS64 SEPCIAL Opcode Encoding of Function Field
let parseSPECIAL arch bin =
  match extract bin 5u 0u with
  | 0b000000u -> parseSLL bin
  | 0b000001u when chk10to6 bin 0u && ztf bin 0b00u && isRel2 arch ->
    Op.MOVF, None, None, getRdRsCc bin
  | 0b000001u when chk10to6 bin 0u && ztf bin 0b01u && isRel2 arch ->
    Op.MOVT, None, None, getRdRsCc bin
  | 0b000010u when chk25to21 bin 0u -> Op.SRL, None, None, getRdRtSa bin
  | 0b000010u when chk25to21 bin 1u -> Op.ROTR, None, None, getRdRtSa bin
  | 0b000011u when chk25to21 bin 0u -> Op.SRA, None, None, getRdRtSa bin
  | 0b000100u when chk10to6 bin 0u -> Op.SLLV, None, None, getRdRtRs bin
  | 0b000101u -> failwith "LSA"
  | 0b000110u when chk10to6 bin 0u -> Op.SRLV, None, None, getRdRtRs bin
  | 0b000110u when chk10to6 bin 1u && isRel2 arch ->
    Op.ROTRV, None, None, getRdRtRs bin
  | 0b000111u when chk10to6 bin 0u -> Op.SRAV, None, None, getRdRtRs bin
  | 0b001000u -> parseJR bin
  | 0b001001u -> parseJALR bin
  | 0b001010u when chk10to6 bin 0u -> Op.MOVZ, None, None, getRdRsRt bin
  | 0b001011u when chk10to6 bin 0u -> Op.MOVN, None, None, getRdRsRt bin
  | 0b001101u -> Op.BREAK, None, None, NoOperand
  | 0b001111u when chk25to11 bin 0u -> Op.SYNC, None, None, getStype bin
  | 0b010000u -> parseMFHI arch bin
  | 0b010001u when isRel2 arch && chk20to6 bin 0u ->
    Op.MTHI, None, None, getRs bin
  | 0b010010u -> parseMFLO arch bin
  | 0b010011u when isRel2 arch && chk20to6 bin 0u ->
    Op.MTLO, None, None, getRs bin
  | 0b010100u when chk10to6 bin 0u && isMIPS64 arch ->
    Op.DSLLV, None, None, getRdRtRs bin
  | 0b010110u when chk10to6 bin 0u && isMIPS64 arch ->
    Op.DSRLV, None, None, getRdRtRs bin
  | 0b010110u when chk10to6 bin 1u && isMIPS64R2 arch ->
    Op.DROTRV, None, None, getRdRtRs bin
  | 0b010111u when chk10to6 bin 0u && isMIPS64 arch ->
    Op.DSRAV, None, None, getRdRtRs bin
  | 0b011000u when chk15to6 bin 0u && isRel2 arch ->
    Op.MULT, None, None, getRsRt bin
  | 0b011001u when chk15to6 bin 0u -> Op.MULTU, None, None, getRsRt bin
  | 0b011010u when chk15to6 bin 0u -> Op.DIV, None, None, getRsRt bin
  | 0b011011u -> parseDIVU arch bin
  | 0b011100u when chk15to6 bin 0u && isMIPS64R2 arch ->
    Op.DMULT, None, None, getRsRt bin
  | 0b011101u when chk15to6 bin 0u && isMIPS64R2 arch ->
    Op.DMULTU, None, None, getRsRt bin
  | 0b011110u when chk15to6 bin 0u && isMIPS64R2 arch ->
    Op.DDIV, None, None, getRsRt bin
  | 0b011111u when chk15to6 bin 0u && isMIPS64R2 arch ->
    Op.DDIVU, None, None, getRsRt bin
  | 0b100000u when chk10to6 bin 0u -> Op.ADD, None, None, getRdRsRt bin
  | 0b100001u when chk10to6 bin 0u -> Op.ADDU, None, None, getRdRsRt bin
  | 0b100011u when chk10to6 bin 0u -> Op.SUBU, None, None, getRdRsRt bin
  | 0b100100u when chk10to6 bin 0u -> Op.AND, None, None, getRdRsRt bin
  | 0b100101u when chk10to6 bin 0u -> Op.OR, None, None, getRdRsRt bin
  | 0b100110u when chk10to6 bin 0u -> Op.XOR, None, None, getRdRsRt bin
  | 0b100111u when chk10to6 bin 0u -> Op.NOR, None, None, getRdRsRt bin
  | 0b101010u when chk10to6 bin 0u -> Op.SLT, None, None, getRdRsRt bin
  | 0b101011u when chk10to6 bin 0u -> Op.SLTU, None, None, getRdRsRt bin
  | 0b101101u when chk10to6 bin 0u && isMIPS64 arch ->
    Op.DADDU, None, None, getRdRsRt bin
  | 0b101111u when chk10to6 bin 0u && isMIPS64 arch ->
    Op.DSUBU, None, None, getRdRsRt bin
  | 0b110100u -> Op.TEQ, None, None, getRsRt bin
  | 0b111000u when chk25to21 bin 0u && isMIPS64 arch ->
    Op.DSLL, None, None, getRdRtSa bin
  | 0b111010u when chk25to21 bin 0u && isMIPS64 arch ->
    Op.DSRL, None, None, getRdRtSa bin
  | 0b111010u when chk25to21 bin 1u && isMIPS64R2 arch ->
    Op.DROTR, None, None, getRdRtSa bin
  | 0b111011u when chk25to21 bin 0u && isMIPS64 arch ->
    Op.DSRA, None, None, getRdRtSa bin
  | 0b111100u when chk25to21 bin 0u && isMIPS64 arch ->
    Op.DSLL32, None, None, getRdRtSa bin
  | 0b111110u when chk25to21 bin 0u && isMIPS64 arch ->
    Op.DSRL32, None, None, getRdRtSa bin
  | 0b111110u when chk25to21 bin 1u && isMIPS64R2 arch ->
    Op.DROTR32, None, None, getRdRtSa bin
  | 0b111111u when chk25to21 bin 0u && isMIPS64 arch ->
    Op.DSRA32, None, None, getRdRtSa bin
  | _ -> failwith "Not Implemented."

let parseBAL arch binary =
  match extract binary 25u 21u with
  | 0u -> Op.BAL, None, None, getRel16 binary
  | _ when isMIPS32R2 arch -> Op.BGEZAL, None, None, getRsRel16 binary
  | _ -> failwith "Not Implemented."

/// Table A.4 MIPS64 REGIMM Encoding of rt Field
let parseREGIMM arch binary =
  match extract binary 20u 16u with
  | 0b00000u -> Op.BLTZ, None, None, getRsRel16 binary
  | 0b00001u -> Op.BGEZ, None, None, getRsRel16 binary
  | 0b10001u -> parseBAL arch binary
  | _ -> failwith "Not Implemented."

/// Table A.5 MIPS64 SEPCIAL2 Encoding of Function Field
let parseSPECIAL2 arch bin =
  match extract bin 5u 0u with
  | 0b000000u when isRel2 arch && chk15to6 bin 0u ->
    Op.MADD, None, None, getRsRt bin
  | 0b000001u when isRel2 arch && chk15to6 bin 0u ->
    Op.MADDU, None, None, getRsRt bin
  | 0b000010u when isRel2 arch && chk10to6 bin 0u ->
    Op.MUL, None, None, getRdRsRt bin
  | 0b000100u when isRel2 arch && chk15to6 bin 0u ->
    Op.MSUB, None, None, getRsRt bin
  | 0b000101u when isRel2 arch && chk15to6 bin 0u ->
    Op.MSUBU, None, None, getRsRt bin
  | 0b100000u -> parseR2CLZ bin
  | 0b100100u when isMIPS64 arch -> parseR2DCLZ bin
  | _ -> failwith "Not Implemented."

let parseSignExt arch binary =
  match extract binary 25u 21u, extract binary 10u 8u, extract binary 7u 6u with
  | 0u, 0u, 0u when isMIPS32R6 arch -> Op.BITSWAP, None, None, getRdRt binary
  | 0u, 0u, 0u when isMIPS64R6 arch -> Op.DBITSWAP, None, None, getRdRt binary
  | _, 0b10u, _ when isMIPS32R6 arch -> Op.ALIGN, None, None, getRdRsRtBp binary
  | _, 0b10u, _ when isMIPS64R6 arch ->
    Op.DALIGN, None, None, getRdRsRtBp binary
  | 0u, 0b100u, 0u -> Op.SEB, None, None, getRdRt binary
  | 0u, 0b110u, 0u -> Op.SEH, None, None, getRdRt binary
  | 0u, 0u, 0b10u when isRel2 arch ->
    Op.WSBH, None, None, getRdRt binary
  | _ -> failwith "Not Implemented."

/// Table A.6 MIPS64 SEPCIAL3 Encoding of Function Field for Release of the
/// Architecture
let parseSPECIAL3 arch binary =
  match extract binary 5u 0u with
  | 0b000000u -> Op.EXT, None, None, getRtRsPosSize2 binary
  | 0b000001u when isMIPS64R2 arch ->
    Op.DEXTM, None, None, getRtRsPosSize5 binary
  | 0b000010u when isMIPS64R2 arch ->
    Op.DEXTU, None, None, getRtRsPosSize6 binary
  | 0b000011u when isMIPS64R2 arch ->
    Op.DEXT, None, None, getRtRsPosSize2 binary
  | 0b000100u -> Op.INS, None, None, getRtRsPosSize binary
  | 0b000101u when isMIPS64R2 arch ->
    Op.DINSM, None, None, getRtRsPosSize3 binary
  | 0b000110u when isMIPS64R2 arch ->
    Op.DINSU, None, None, getRtRsPosSize4 binary
  | 0b000111u when isMIPS64R2 arch ->
    Op.DINS, None, None, getRtRsPosSize binary
  | 0b100000u -> parseSignExt arch binary
  | 0b100100u when chk25to21 binary 0u && isMIPS64R2 arch (* DBSHFL *) ->
    match extract binary 10u 6u with
    | 0b00010u -> Op.DSBH, None, None, getRdRt binary
    | 0b00101u -> Op.DSHD, None, None, getRdRt binary
    | _ -> failwith "Not Implemented."
  | 0b100110u when pickBit binary 6u = 0u && isRel6 arch ->
    Op.SC, None, None, getRtMemBaseOff9 binary 32<rt>
  | 0b100111u when pickBit binary 6u = 0u && isRel6 arch ->
    Op.SCD, None, None, getRtMemBaseOff9 binary 64<rt>
  | 0b110101u when pickBit binary 6u = 0u && isRel6 arch ->
    Op.PREF, None, None, getHintMemBaseOff9 binary 32<rt>
  | 0b110110u when pickBit binary 6u = 0u && isRel6 arch ->
    Op.LL, None, None, getRtMemBaseOff9 binary 32<rt>
  | 0b110111u when pickBit binary 6u = 0u && isMIPS64R6 arch ->
    Op.LL, None, None, getRtMemBaseOff9 binary 64<rt>
  | 0b111011u when extract binary 10u 9u = 0u ->
    Op.RDHWR, None, None, getRtRdSel binary
  | _ -> failwith "Not Implemented."

/// The MIPS64 Instruction Set Reference Manual, Revision 6.06
/// on page 70, 93
let parseBEQ binary =
  match extract binary 25u 16u with
  | 0u -> Op.B, None, None, getRel16 binary
  | _ -> Op.BEQ, None, None, getRsRtRel16 binary

/// The MIPS64 Instruction Set Reference Manual, Revision 6.06
/// on page 58, 295
let parseLUIAUI arch binary =
  match extract binary 25u 21u with
  | 0u when isRel6 arch -> Op.AUI, None, None, getRtImm16 binary
  | 0u -> Op.LUI, None, None, getRtImm16 binary
  | _ -> Op.AUI, None, None, getRtRsImm16s binary

/// The MIPS64 Instruction Set Reference Manual, Revision 6.06
/// on page 89, 94, 105
let parsePOP06 binary =
  match extract binary 20u 16u with
  | 0u -> Op.BLEZ, None, None, getRsRel16 binary
  | _ -> failwith "Not Implemented."

/// The MIPS64 Instruction Set Reference Manual, Revision 6.06
/// on page 89, 94, 105
let parsePOP07 binary =
  match extract binary 20u 16u with
  | 0u -> Op.BGTZ, None, None, getRsRel16 binary
  | _ -> failwith "Not Implemented."

/// Table A.18 MIPS64 COP1 Encoding of Function Field When rs=S, Revision 6.06
let parseCOP1WhenRsS arch binary =
  match extract binary 5u 0u with
  | 0b000000u -> Op.ADD, None, Some Fmt.S, getFdFsFt binary
  | 0b000001u -> Op.SUB, None, Some Fmt.S, getFdFsFt binary
  | 0b000010u -> Op.MUL, None, Some Fmt.S, getFdFsFt binary
  | 0b000011u -> Op.DIV, None, Some Fmt.S, getFdFsFt binary
  | 0b000100u -> Op.SQRT, None, Some Fmt.S, getFdFs binary
  | 0b000101u -> Op.ABS, None, Some Fmt.S, getFdFs binary
  | 0b000110u when chk20to16 binary 0u ->
    Op.MOV, None, Some Fmt.S, getFdFs binary
  | 0b000111u when chk20to16 binary 0u ->
    Op.NEG, None, Some Fmt.S, getFdFs binary
  | 0b001001u when chk20to16 binary 0u ->
    Op.TRUNCL, None, Some Fmt.S, getFdFs binary
  | 0b001101u when chk20to16 binary 0u ->
    Op.TRUNCW, None, Some Fmt.S, getFdFs binary
  | 0b010001u when ztf binary 0b00u && isRel2 arch ->
    Op.MOVF, None, Some Fmt.S, getFdFsCc binary
  | 0b010001u when ztf binary 0b01u && isRel2 arch ->
    Op.MOVT, None, Some Fmt.S, getFdFsCc binary
  | 0b010010u when isRel2 arch -> Op.MOVZ, None, Some Fmt.S, getFdFsRt binary
  | 0b010011u when isRel2 arch -> Op.MOVN, None, Some Fmt.S, getFdFsRt binary
  | 0b010101u -> Op.RECIP, None, Some Fmt.S, getFdFs binary
  | 0b010110u -> Op.RSQRT, None, Some Fmt.S, getFdFs binary
  | 0b100001u when chk20to16 binary 0u ->
    Op.CVTD, None, Some Fmt.S, getFdFs binary
  | b when b &&& 0b110000u = 0b110000u && isRel2 arch ->
    let oprFn = if cc binary 0u then getFsFt else getCcFsFt
    let cond = getCondition (extract binary 3u 0u) |> Some
    Op.C, cond, Some Fmt.S, oprFn binary
  | _ -> failwith "Not Implemented."

/// Table A.19 MIPS64 COP1 Encoding of Function Field When rs=D, Revision 6.06
let parseCOP1WhenRsD arch binary =
  match extract binary 5u 0u with
  | 0b000000u -> Op.ADD, None, Some Fmt.D, getFdFsFt binary
  | 0b000001u -> Op.SUB, None, Some Fmt.D, getFdFsFt binary
  | 0b000010u -> Op.MUL, None, Some Fmt.D, getFdFsFt binary
  | 0b000011u -> Op.DIV, None, Some Fmt.D, getFdFsFt binary
  | 0b000100u -> Op.SQRT, None, Some Fmt.D, getFdFs binary
  | 0b000101u -> Op.ABS, None, Some Fmt.D, getFdFs binary
  | 0b000110u when chk20to16 binary 0u ->
    Op.MOV, None, Some Fmt.D, getFdFs binary
  | 0b000111u when chk20to16 binary 0u ->
    Op.NEG, None, Some Fmt.D, getFdFs binary
  | 0b001001u when chk20to16 binary 0u ->
    Op.TRUNCL, None, Some Fmt.D, getFdFs binary
  | 0b001101u when chk20to16 binary 0u ->
    Op.TRUNCW, None, Some Fmt.D, getFdFs binary
  | 0b010001u when ztf binary 0b00u && isRel2 arch ->
    Op.MOVF, None, Some Fmt.D, getFdFsCc binary
  | 0b010001u when ztf binary 0b01u && isRel2 arch ->
    Op.MOVT, None, Some Fmt.D, getFdFsCc binary
  | 0b010010u when isRel2 arch -> Op.MOVZ, None, Some Fmt.D, getFdFsRt binary
  | 0b010011u when isRel2 arch -> Op.MOVN, None, Some Fmt.D, getFdFsRt binary
  | 0b010101u -> Op.RECIP, None, Some Fmt.D, getFdFs binary
  | 0b010110u -> Op.RSQRT, None, Some Fmt.D, getFdFs binary
  | 0b100000u when chk20to16 binary 0u ->
    Op.CVTS, None, Some Fmt.D, getFdFs binary
  | b when b &&& 0b110000u = 0b110000u && isRel2 arch ->
    let oprFn = if cc binary 0u then getFsFt else getCcFsFt
    let cond = getCondition (extract binary 3u 0u) |> Some
    Op.C, cond, Some Fmt.D, oprFn binary
  | _ -> failwith "Not Implemented."

/// Table A.20 MIPS64 COP1 Encoding of Function Field When rs=W or L,
/// Revision 6.06
let parseCOP1WhenRsW _arch binary =
  match extract binary 5u 0u with
  | 0b100000u when chk20to16 binary 0u ->
    Op.CVTS, None, Some Fmt.W, getFdFs binary
  | 0b100001u when chk20to16 binary 0u ->
    Op.CVTD, None, Some Fmt.W, getFdFs binary
  | _ -> failwith "Not Implemented."

/// Table A.20 MIPS64 COP1 Encoding of Function Field When rs=W or L,
/// Revision 6.06
let parseCOP1WhenRsL _arch binary =
  match extract binary 5u 0u with
  | 0b100000u when chk20to16 binary 0u ->
    Op.CVTS, None, Some Fmt.L, getFdFs binary
  | 0b100001u when chk20to16 binary 0u ->
    Op.CVTD, None, Some Fmt.L, getFdFs binary
  | _ -> failwith "Not Implemented."

let parseCOP1 arch binary =
  match extract binary 25u 21u with
  | 0b00000u when chk10to0 binary 0u -> Op.MFC1, None, None, getRtFs binary
  | 0b00001u when chk10to0 binary 0u && isMIPS64 arch ->
    Op.DMFC1, None, None, getRtFs binary
  | 0b00010u when chk10to0 binary 0u -> Op.CFC1, None, None, getRtFs binary
  | 0b00011u when chk10to0 binary 0u && isRel2 arch ->
    Op.MFHC1, None, None, getRtFs binary
  | 0b00100u when chk10to0 binary 0u -> Op.MTC1, None, None, getRtFs binary
  | 0b00101u when chk10to0 binary 0u -> Op.DMTC1, None, None, getRtFs binary
  | 0b00110u when chk10to0 binary 0u -> Op.CTC1, None, None, getRtFs binary
  | 0b00111u when chk10to0 binary 0u && isRel2 arch ->
    Op.MTHC1, None, None, getRtFs binary
  | 0b01000u when nd binary 0u && tf binary 0u ->
    Op.BC1F, None, None, getCcOff binary
  | 0b01000u when nd binary 0u && tf binary 1u ->
    Op.BC1T, None, None, getCcOff binary
  | 0b10000u -> parseCOP1WhenRsS arch binary
  | 0b10001u -> parseCOP1WhenRsD arch binary
  | 0b10100u -> parseCOP1WhenRsW arch binary
  | 0b10101u -> parseCOP1WhenRsL arch binary
  | _ -> failwith "Not Implemented."

/// Table A.24 MIPS64 COP1X6R1 Encoding of Function Field on page 588,
/// Revision 6.06.
let parseCOP1X arch binary =
  match extract binary 5u 0u with
  | 0b000000u when chk15to11 binary 0u && isRel2 arch ->
    Op.LWXC1, None, None, getFdMemBaseIdx binary 32<rt>
  | 0b000001u when chk15to11 binary 0u && isRel2 arch ->
    Op.LDXC1, None, None, getFdMemBaseIdx binary 64<rt>
  | 0b001000u when chk10to6 binary 0u && isRel2 arch ->
    Op.SWXC1, None, None, getFsMemBaseIdx binary 32<rt>
  | 0b001001u when chk10to6 binary 0u && isRel2 arch ->
    Op.SDXC1, None, None, getFsMemBaseIdx binary 64<rt>
  | 0b001111u when chk10to6 binary 0u && isRel2 arch ->
    Op.PREFX, None, None, getHintMemBaseIdx binary 32<rt>
  | 0b100000u when isRel2 arch -> Op.MADD, None, Some Fmt.S, getFdFrFsFt binary
  | 0b100001u when isRel2 arch -> Op.MADD, None, Some Fmt.D, getFdFrFsFt binary
  | 0b100110u when isRel2 arch ->
    Op.MADD, None, Some Fmt.PS, getFdFrFsFt binary
  | 0b101000u when isRel2 arch -> Op.MSUB, None, Some Fmt.S, getFdFrFsFt binary
  | 0b101001u when isRel2 arch -> Op.MSUB, None, Some Fmt.D, getFdFrFsFt binary
  | 0b101110u when isRel2 arch ->
    Op.MSUB, None, Some Fmt.PS, getFdFrFsFt binary
  | 0b110000u when isRel2 arch -> Op.NMADD, None, Some Fmt.S, getFdFrFsFt binary
  | 0b110001u when isRel2 arch -> Op.NMADD, None, Some Fmt.D, getFdFrFsFt binary
  | 0b110110u when isRel2 arch ->
    Op.NMADD, None, Some Fmt.PS, getFdFrFsFt binary
  | _ -> failwith "Not Implemented."

/// The MIPS64 Instrecutin Set Reference Manual, MD00087, Revision 6.06
/// Table A.2 MIPS64 Encoding of the Opcode Field
let parseOpcodeField arch binary =
  match extract binary 31u 26u with
  | 0b000000u -> parseSPECIAL arch binary
  | 0b000001u -> parseREGIMM arch binary
  | 0b000010u -> Op.J, None, None, getTarget binary
  | 0b000011u -> Op.JAL, None, None, getTarget binary
  | 0b000100u -> parseBEQ binary
  | 0b000101u -> Op.BNE, None, None, getRsRtRel16 binary
  | 0b000110u -> parsePOP06 binary
  | 0b000111u -> parsePOP07 binary
  | 0b001000u -> failwith "ADDI/POP10"
  | 0b001001u -> Op.ADDIU, None, None, getRtRsImm16s binary
  | 0b001010u -> Op.SLTI, None, None, getRtRsImm16s binary
  | 0b001011u -> Op.SLTIU, None, None, getRtRsImm16s binary
  | 0b001100u -> Op.ANDI, None, None, getRtRsImm16 binary
  | 0b001101u -> Op.ORI, None, None, getRtRsImm16 binary
  | 0b001110u -> Op.XORI, None, None, getRtRsImm16 binary
  | 0b001111u -> parseLUIAUI arch binary
  | 0b010000u -> failwith "COP0"
  | 0b010001u -> parseCOP1 arch binary
  | 0b010010u -> failwith "COP2"
  | 0b010011u -> parseCOP1X arch binary
  | 0b010100u -> failwith "BEQL"
  | 0b010101u -> failwith "BNEL"
  | 0b010110u -> failwith "BLEZL/POP26"
  | 0b010111u -> failwith "BGTZL/POP27"
  | 0b011000u -> failwith "DADDI/POP30"
  | 0b011001u when isMIPS64 arch -> Op.DADDIU, None, None, getRtRsImm16s binary
  | 0b011010u when isMIPS64R2 arch ->
    Op.LDL, None, None, getRtMemBaseOff binary 64<rt>
  | 0b011011u when isMIPS64R2 arch ->
    Op.LDR, None, None, getRtMemBaseOff binary 64<rt>
  | 0b011100u -> parseSPECIAL2 arch binary
  | 0b011101u -> failwith "JALX/DAUI"
  | 0b011110u -> failwith "MSA"
  | 0b011111u -> parseSPECIAL3 arch binary
  | 0b100000u -> Op.LB, None, None, getRtMemBaseOff binary 8<rt>
  | 0b100001u -> Op.LH, None, None, getRtMemBaseOff binary 16<rt>
  | 0b100010u when isRel2 arch ->
    Op.LWL, None, None, getRtMemBaseOff binary 32<rt>
  | 0b100011u -> Op.LW, None, None, getRtMemBaseOff binary 32<rt>
  | 0b100100u -> Op.LBU, None, None, getRtMemBaseOff binary 8<rt>
  | 0b100101u -> Op.LHU, None, None, getRtMemBaseOff binary 16<rt>
  | 0b100110u when isRel2 arch ->
    Op.LWR, None, None, getRtMemBaseOff binary 32<rt>
  | 0b100111u when isMIPS64 arch ->
    Op.LWU, None, None, getRtMemBaseOff binary 32<rt>
  | 0b101000u -> Op.SB, None, None, getRtMemBaseOff binary 8<rt>
  | 0b101001u -> Op.SH, None, None, getRtMemBaseOff binary 16<rt>
  | 0b101010u when isRel2 arch ->
    Op.SWL, None, None, getRtMemBaseOff binary 32<rt>
  | 0b101011u -> Op.SW, None, None, getRtMemBaseOff binary 32<rt>
  | 0b101100u when isMIPS64R2 arch ->
    Op.SDL, None, None, getRtMemBaseOff binary 64<rt>
  | 0b101101u when isMIPS64R2 arch ->
    Op.SDR, None, None, getRtMemBaseOff binary 64<rt>
  | 0b101110u when isRel2 arch ->
    Op.SWR, None, None, getRtMemBaseOff binary 32<rt>
  | 0b101111u -> failwith "CACHE"
  | 0b110000u when isRel2 arch (* pre-Release 6 *) ->
    Op.LL, None, None, getRtMemBaseOff binary 32<rt>
  | 0b110001u -> Op.LWC1, None, None, getFtMemBaseOff binary 32<rt>
  | 0b110010u -> failwith "LWC2"
  | 0b110011u when isRel2 arch (* pre-Release 6 *) ->
    Op.PREF, None, None, getHintMemBaseOff binary 32<rt>
  | 0b110100u when isMIPS64R2 arch (* MIPS64 pre-Release 6 *) ->
    Op.LLD, None, None, getRtMemBaseOff binary 64<rt>
  | 0b110101u -> Op.LDC1, None, None, getFtMemBaseOff binary 64<rt>
  | 0b110110u -> failwith "LDC2/BEQZC/JIC/POP66"
  | 0b110111u when isMIPS64 arch ->
    Op.LD, None, None, getRtMemBaseOff binary 64<rt>
  | 0b111000u when isRel2 arch (* pre-Release 6 *) ->
    Op.SC, None, None, getRtMemBaseOff binary 32<rt>
  | 0b111001u -> Op.SWC1, None, None, getFtMemBaseOff binary 32<rt>
  | 0b111010u -> failwith "SWC2/BALC"
  | 0b111011u -> failwith "PCREL"
  | 0b111100u when isRel2 arch (* pre-Release 6 *) ->
    Op.SCD, None, None, getRtMemBaseOff binary 64<rt>
  | 0b111101u -> Op.SDC1, None, None, getFtMemBaseOff binary 64<rt>
  | 0b111110u -> failwith "SDC2/BNEZC/JIALC/POP76"
  | 0b111111u when isMIPS64 arch ->
    Op.SD, None, None, getRtMemBaseOff binary 64<rt>
  | _ -> failwith "Not Implemented."

let getOperationSize opcode wordSz =
  match opcode with
  | Op.SB -> 8<rt>
  | Op.SH -> 16<rt>
  | Op.SW -> 32<rt>
  | Op.SD -> 64<rt>
  | _ -> WordSize.toRegType wordSz

let parse (span: ReadOnlySpan<byte>) (reader: IBinReader) arch wordSize addr =
  let bin = reader.ReadUInt32 (span, 0)
  let opcode, cond, fmt, operands = parseOpcodeField arch bin
  let insInfo =
    { Address = addr
      NumBytes = 4u
      Condition = cond
      Fmt = fmt
      Opcode = opcode
      Operands = operands
      OperationSize = getOperationSize opcode wordSize
      Arch = arch }
  MIPSInstruction (addr, 4u, insInfo, wordSize)

// vim: set tw=80 sts=2 sw=2:
