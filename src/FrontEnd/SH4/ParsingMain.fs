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

module internal B2R2.FrontEnd.SH4.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SH4.OperandHelper

let getState = function
 | _ -> Terminator.futureFeature ()

/// 0000 0000 ---- ---- with no operands
let noOpParse0000 b16 =
  match getBits b16 8 1 with
  | 0b00011001us -> Opcode.DIV0U, NoOperand
  | 0b00001011us -> Opcode.RTS, NoOperand
  | 0b00101000us -> Opcode.CLRMAC, NoOperand
  | 0b01001000us -> Opcode.CLRS, NoOperand
  | 0b00001000us -> Opcode.CLRT, NoOperand
  | 0b00111000us -> Opcode.LDTLB, NoOperand
  | 0b00001001us -> Opcode.NOP, NoOperand
  | 0b00101011us -> Opcode.RTE, NoOperand
  | 0b01011000us -> Opcode.SETS, NoOperand
  | 0b00011000us -> Opcode.SETT, NoOperand
  | 0b00011011us -> Opcode.SLEEP, NoOperand
  | _ -> Opcode.InvalidOp, NoOperand

/// 1111 ---- 1111 1101 with no operands.
let noOpParse1111 b16 =
  match getBits b16 12 9 with
  | 0b1011us -> Opcode.FRCHG, NoOperand
  | 0b0011us -> Opcode.FSCHG, NoOperand
  | _ -> Opcode.InvalidOp, NoOperand

/// 0100 ---- ---- ---- with destination operand only.
let oneOpParse0100 b16 =
  match getBits b16 8 5 with
  | 0b0010us ->
    match getBits b16 4 1 with
    | 0b1001us -> Opcode.MOVT, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0100us -> Opcode.ROTCL, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0101us -> Opcode.ROTCR, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0000us -> Opcode.SHAL, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0001us -> Opcode.SHAR, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b1000us -> Opcode.SHLL16, OneOperand(OpReg(Regdir(getReg1d b16)))
    | _ -> Opcode.InvalidOp, NoOperand
  | 0b0001us ->
    match getBits b16 4 1 with
    | 0b0001us -> Opcode.CMPPZ, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0101us -> Opcode.CMPPL, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0000us -> Opcode.DT, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b1000us -> Opcode.SHLL8, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b1001us -> Opcode.SHLR8, OneOperand(OpReg(Regdir(getReg1d b16)))
    | _ -> Opcode.InvalidOp, NoOperand
  | 0b0000us ->
    match getBits b16 4 1 with
    | 0b0100us -> Opcode.ROTL, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0101us -> Opcode.ROTR, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0000us -> Opcode.SHLL, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0001us -> Opcode.SHLR, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b1000us -> Opcode.SHLL2, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b1001us -> Opcode.SHLR2, OneOperand(OpReg(Regdir(getReg1d b16)))
    | _ -> Opcode.InvalidOp, NoOperand
  | _ -> Opcode.InvalidOp, NoOperand

/// 1111 ---- ---- 1101 with destination operand only.
let oneOpParse1111 b16 =
  match getBits b16 8 5 with
  | 0b0101us ->
    if get1Bit b16 9 then
      Opcode.FABS, OneOperand(OpReg(Regdir(getReg1dFR b16)))
    elif getState ()
      then Opcode.FABS, OneOperand(OpReg(Regdir(getReg1dDR b16)))
    else
      Opcode.FABS, OneOperand(OpReg(Regdir(getReg1dFR b16)))
  | 0b0100us ->
    if get1Bit b16 9 then
      Opcode.FNEG, OneOperand(OpReg(Regdir(getReg1dFR b16)))
    elif getState () then
      Opcode.FNEG, OneOperand(OpReg(Regdir(getReg1dDR b16)))
    else
      Opcode.FNEG, OneOperand(OpReg(Regdir(getReg1dFR b16)))
  | 0b0110us ->
    if get1Bit b16 9 then
      Opcode.FSQRT, OneOperand(OpReg(Regdir(getReg1dFR b16)))
    elif getState () then
      Opcode.FSQRT, OneOperand(OpReg(Regdir(getReg1dDR b16)))
    else
      Opcode.FSQRT, OneOperand(OpReg(Regdir(getReg1dFR b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// 0011 ---- ---- ---- with source and destination operands.
let twoOpParse0011 b16 =
  match getBits b16 4 1 with
  | 0b1100us ->
    Opcode.ADD,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1110us ->
    Opcode.ADDC,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1111us ->
    Opcode.ADDV,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0000us ->
    Opcode.CMPEQ,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0010us ->
    Opcode.CMPHS,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0011us ->
    Opcode.CMPGE,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0110us ->
    Opcode.CMPHI,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0111us ->
    Opcode.CMPGT,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0100us ->
    Opcode.DIV1,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1101us ->
    Opcode.DMULSL,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0101us ->
    Opcode.DMULUL,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1000us ->
    Opcode.SUB,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1010us ->
    Opcode.SUBC,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1011us ->
    Opcode.SUBV,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// 0110 ---- ---- ---- with source and destination operands.
let twoOpParse0110 b16 =
  match getBits b16 4 1 with
  | 0b0011us ->
    Opcode.MOV,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1000us ->
    Opcode.SWAPB,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1001us ->
    Opcode.SWAPW,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1110us ->
    Opcode.EXTSB,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1111us ->
    Opcode.EXTSW,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1100us ->
    Opcode.EXTUB,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1101us ->
    Opcode.EXTUW,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1011us ->
    Opcode.NEG,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1010us ->
    Opcode.NEGC,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0111us ->
    Opcode.NOT,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// 0010 ---- ---- ---- with source and destination operands.
let twoOpParse0010 b16 =
  match getBits b16 4 1 with
  | 0b1101us ->
    Opcode.XTRCT,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1100us ->
    Opcode.CMPSTR,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0111us ->
    Opcode.DIV0S,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1111us ->
    Opcode.MULSW,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1110us ->
    Opcode.MULUW,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1001us ->
    Opcode.AND,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1011us ->
    Opcode.OR,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1000us ->
    Opcode.TST,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1010us ->
    Opcode.XOR,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// 0100 ---- ---- ---- with source and destination operands.
let twoOpParse0100 b16 =
  match getBits b16 4 1 with
  | 0b1100us ->
    Opcode.SHAD,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1101us ->
    Opcode.SHLD,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b1110us ->
    match getBits b16 8 5 with
    | 0b0000us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.SR)))
    | 0b0001us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.GBR)))
    | 0b0010us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.VBR)))
    | 0b0011us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.SSR)))
    | 0b0100us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.SPC)))
    | 0b1000us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)),
        OpReg(Regdir(getReg1dBank b16)))
    | 0b1001us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)),
        OpReg(Regdir(getReg1dBank b16)))
    | 0b1010us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)),
        OpReg(Regdir(getReg1dBank b16)))
    | 0b1011us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)),
        OpReg(Regdir(getReg1dBank b16)))
    | 0b1100us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)),
        OpReg(Regdir(getReg1dBank b16)))
    | 0b1101us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)),
        OpReg(Regdir(getReg1dBank b16)))
    | 0b1110us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)),
        OpReg(Regdir(getReg1dBank b16)))
    | 0b1111us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)),
        OpReg(Regdir(getReg1dBank b16)))
    | _ -> Opcode.InvalidOp, NoOperand
  | 0b1010us ->
    match getBits b16 8 5 with
    | 0b1111us ->
      Opcode.LDC,
      TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.DBR)))
    | 0b0000us ->
      Opcode.LDS,
      TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.MACH)))
    | 0b0001us ->
      Opcode.LDS,
      TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.MACL)))
    | 0b0010us ->
      Opcode.LDS,
      TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.PR)))
    | 0b0110us ->
      Opcode.LDS,
      TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.FPSCR)))
    | 0b0101us ->
      Opcode.LDS,
      TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.FPUL)))
    | _ -> Opcode.InvalidOp, NoOperand
  | _ -> Opcode.InvalidOp, NoOperand

/// 0000 ---- ---- ---- with source and destination operand.
let twoOpParse0000 b16 =
  match getBits b16 4 1 with
  | 0b0111us ->
    Opcode.MULL,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0010us ->
    match getBits b16 8 5 with
    | 0b0000us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(R.SR)), OpReg(Regdir(getReg1d b16)))
    | 0b0001us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(R.GBR)), OpReg(Regdir(getReg1d b16)))
    | 0b0010us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(R.VBR)), OpReg(Regdir(getReg1d b16)))
    | 0b0011us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(R.SSR)), OpReg(Regdir(getReg1d b16)))
    | 0b0100us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(R.SPC)), OpReg(Regdir(getReg1d b16)))
    | 0b1000us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(getReg1dBank b16)),
        OpReg(Regdir(getReg1d b16)))
    | 0b1001us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(getReg1dBank b16)),
        OpReg(Regdir(getReg1d b16)))
    | 0b1010us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(getReg1dBank b16)),
        OpReg(Regdir(getReg1d b16)))
    | 0b1011us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(getReg1dBank b16)),
        OpReg(Regdir(getReg1d b16)))
    | 0b1100us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(getReg1dBank b16)),
        OpReg(Regdir(getReg1d b16)))
    | 0b1101us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(getReg1dBank b16)),
        OpReg(Regdir(getReg1d b16)))
    | 0b1110us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(getReg1dBank b16)),
        OpReg(Regdir(getReg1d b16)))
    | 0b1111us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(getReg1dBank b16)),
        OpReg(Regdir(getReg1d b16)))
    | _ -> Opcode.InvalidOp, NoOperand
  | 0b1010us ->
    match getBits b16 8 5 with
    | 0b0011us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(R.SGR)), OpReg(Regdir(getReg1d b16)))
    | 0b1111us ->
      Opcode.STC,
      TwoOperands(OpReg(Regdir(R.DBR)), OpReg(Regdir(getReg1d b16)))
    | 0b0000us ->
      Opcode.STS,
      TwoOperands(OpReg(Regdir(R.MACH)), OpReg(Regdir(getReg1d b16)))
    | 0b0001us ->
      Opcode.STS,
      TwoOperands(OpReg(Regdir(R.MACL)), OpReg(Regdir(getReg1d b16)))
    | 0b0010us ->
      Opcode.STS,
      TwoOperands(OpReg(Regdir(R.PR)), OpReg(Regdir(getReg1d b16)))
    | 0b0110us ->
      Opcode.STS,
      TwoOperands(OpReg(Regdir(R.FPSCR)), OpReg(Regdir(getReg1d b16)))
    | 0b0101us ->
      Opcode.STS,
      TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(Regdir(getReg1d b16)))
    | _ -> Opcode.InvalidOp, NoOperand
  | _ -> Opcode.InvalidOp, NoOperand

/// 1111 ---- ---- ---- with source and destination operands.
let twoOpParse1111 b16 =
  match getBits b16 4 1 with
  | 0b1110us ->
    Opcode.FMAC,
    ThreeOperands(OpReg(Regdir(R.FR0)), OpReg(Regdir(getReg1sFR b16)),
      OpReg(Regdir(getReg1dFR b16)))
  | 0b0000us ->
    if get1Bit b16 5 then
      Opcode.FADD,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
    elif getState () then
      Opcode.FADD,
      TwoOperands(OpReg(Regdir(getReg1sDR b16)),
        OpReg(Regdir(getReg1dDR b16)))
    else
      Opcode.FADD,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
  | 0b0100us ->
    if get1Bit b16 5 then
      Opcode.FCMPEQ,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
    elif getState () then
      Opcode.FCMPEQ,
      TwoOperands(OpReg(Regdir(getReg1sDR b16)),
        OpReg(Regdir(getReg1dDR b16)))
    else
      Opcode.FCMPEQ,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
  | 0b0101us ->
    if get1Bit b16 5 then
      Opcode.FCMPGT,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
    elif getState () then
      Opcode.FCMPGT,
      TwoOperands(OpReg(Regdir(getReg1sDR b16)),
        OpReg(Regdir(getReg1dDR b16)))
    else
      Opcode.FCMPGT,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
  | 0b0011us ->
    if get1Bit b16 5 then
      Opcode.FDIV,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
    elif getState () then
      Opcode.FDIV,
      TwoOperands(OpReg(Regdir(getReg1sDR b16)),
        OpReg(Regdir(getReg1dDR b16)))
    else
      Opcode.FDIV,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
  | 0b0010us ->
    if get1Bit b16 5 then
      Opcode.FMUL,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
    elif getState () then
      Opcode.FMUL,
      TwoOperands(OpReg(Regdir(getReg1sDR b16)),
        OpReg(Regdir(getReg1dDR b16)))
    else
      Opcode.FMUL,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
  | 0b0001us ->
    if get1Bit b16 5 then
      Opcode.FSUB,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
    elif getState () then
      Opcode.FSUB,
      TwoOperands(OpReg(Regdir(getReg1sDR b16)),
        OpReg(Regdir(getReg1dDR b16)))
    else
      Opcode.FSUB,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
  | 0b1100us ->
    if (get1Bit b16 5 && get1Bit b16 9) then
      if getState () then
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sXD b16)),
        OpReg(Regdir(getReg1dXD b16)))
      else
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
    elif ((get1Bit b16 9) && not (get1Bit b16 5)) then
      if getState () then
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sDR b16)),
        OpReg(Regdir(getReg1dXD b16)))
      else
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
    elif ((get1Bit b16 5) && not (get1Bit b16 9)) then
      if getState () then
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sXD b16)),
        OpReg(Regdir(getReg1dDR b16)))
      else
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
    else
      if getState () then
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sDR b16)),
        OpReg(Regdir(getReg1dDR b16)))
      else
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(Regdir(getReg1dFR b16)))
  | 0b1101us ->
    match getBits b16 8 5 with
    | 0b1110us ->
      Opcode.FIPR,
      TwoOperands(OpReg(Regdir(getReg1sFV b16)),
        OpReg(Regdir(getReg1dFV b16)))
    | 0b1111us ->
      Opcode.FTRV,
      TwoOperands(OpReg(Regdir(R.XMTRX)), OpReg(Regdir(getReg1dFV b16)))
    | 0b0001us ->
      Opcode.FLDS,
      TwoOperands(OpReg(Regdir(getReg1dFR b16)), OpReg(Regdir(R.FPUL)))
    | 0b1011us ->
      Opcode.FCNVDS,
      TwoOperands(OpReg(Regdir(getReg1dDR b16)), OpReg(Regdir(R.FPUL)))
    | 0b0011us ->
      if get1Bit b16 9 then
        Opcode.FTRC,
        TwoOperands(OpReg(Regdir(getReg1dFR b16)), OpReg(Regdir(R.FPUL)))
      elif getState () then
        Opcode.FTRC,
        TwoOperands(OpReg(Regdir(getReg1dDR b16)), OpReg(Regdir(R.FPUL)))
      else
        Opcode.FTRC,
        TwoOperands(OpReg(Regdir(getReg1dFR b16)), OpReg(Regdir(R.FPUL)))
    | 0b0000us ->
      Opcode.FSTS,
      TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(Regdir(getReg1dFR b16)))
    | 0b1010us ->
      Opcode.FCNVSD,
      TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(Regdir(getReg1dDR b16)))
    | 0b0010us ->
      if get1Bit b16 9 then
        Opcode.FLOAT,
        TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(Regdir(getReg1dFR b16)))
      elif getState () then
        Opcode.FLOAT,
        TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(Regdir(getReg1dFR b16)))
      else
        Opcode.FLOAT,
        TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(Regdir(getReg1dFR b16)))
    | _ -> Opcode.InvalidOp, NoOperand
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect 0100 ---- ---- ---- with destination operand only.
let parseRegInd0100 b16 =
  match getBits b16 8 5 with
  | 0b0001us -> Opcode.TASB, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | 0b0010us -> Opcode.JMP, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | 0b0000us -> Opcode.JSR, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect 0000 ---- ---- ---- with destination operand only.
let parseRegInd0000 b16 =
  match getBits b16 8 5 with
  | 0b1001us -> Opcode.OCBI, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | 0b1010us -> Opcode.OCBP, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | 0b1011us -> Opcode.OCBWB, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | 0b1000us -> Opcode.PREF, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | 0b1100us ->
    Opcode.MOVCAL,
    TwoOperands(OpReg(Regdir(R.R0)), OpReg(RegIndir(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect 0010 ---- ---- ---- with source and destination operands.
let parseRegInd0010 b16 =
  match getBits b16 4 1 with
  | 0b0000us ->
    Opcode.MOVB,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(RegIndir(getReg1d b16)))
  | 0b0001us ->
    Opcode.MOVW,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(RegIndir(getReg1d b16)))
  | 0b0010us ->
    Opcode.MOVL,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(RegIndir(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect 0110 ---- ---- ---- with source and destination operands.
let parseRegInd0110 b16 =
  match getBits b16 4 1 with
  | 0b0000us ->
    Opcode.MOVB,
    TwoOperands(OpReg(RegIndir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0001us ->
    Opcode.MOVW,
    TwoOperands(OpReg(RegIndir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0010us ->
    Opcode.MOVL,
    TwoOperands(OpReg(RegIndir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect 1111 ---- ---- ---- with source and destination operands.
let parseRegInd1111 b16 =
  match getBits b16 4 1 with
  | 0b1000us ->
    if getState () then
      if get1Bit b16 9 then
        Opcode.FMOV,
        TwoOperands(OpReg(RegIndir(getReg1s b16)),
        OpReg(Regdir(getReg1dXD b16)))
      else
        Opcode.FMOV,
        TwoOperands(OpReg(RegIndir(getReg1s b16)),
        OpReg(Regdir(getReg1dDR b16)))
    else
      Opcode.FMOVS,
      TwoOperands(OpReg(RegIndir(getReg1s b16)),
      OpReg(Regdir(getReg1sFR b16)))
  | 0b1010us ->
    if getState () then
      if get1Bit b16 5 then
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sXD b16)),
        OpReg(RegIndir(getReg1d b16)))
      else
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sDR b16)),
        OpReg(RegIndir(getReg1d b16)))
    else
      Opcode.FMOVS,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
      OpReg(RegIndir(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect (Post-Increment)
/// 0000 ---- ---- ---- with source and destination operands.
let parsePostInc0000 b16 =
  match getBits b16 4 1 with
  | 0b1111us ->
    Opcode.MACL,
    TwoOperands(OpReg(PostInc(getReg1s b16)), OpReg(PostInc(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect (Post-Increment)
/// 0100 ---- ---- ---- with source and destination operands.
let parsePostInc0100 b16 =
  match getBits b16 4 1 with
  | 0b1111us ->
    Opcode.MACW,
    TwoOperands(OpReg(PostInc(getReg1s b16)), OpReg(PostInc(getReg1d b16)))
  | 0b0111us ->
    match getBits b16 8 5 with
    | 0b0000us ->
      Opcode.LDCL,
      TwoOperands(OpReg(PostInc(getReg1d b16)), OpReg(Regdir(R.SR)))
    | 0b0001us ->
      Opcode.LDCL,
      TwoOperands(OpReg(PostInc(getReg1d b16)), OpReg(Regdir(R.GBR)))
    | 0b0010us ->
      Opcode.LDCL,
      TwoOperands(OpReg(PostInc(getReg1d b16)), OpReg(Regdir(R.VBR)))
    | 0b0011us ->
      Opcode.LDCL,
      TwoOperands(OpReg(PostInc(getReg1d b16)), OpReg(Regdir(R.SSR)))
    | 0b0100us ->
      Opcode.LDCL,
      TwoOperands(OpReg(PostInc(getReg1d b16)), OpReg(Regdir(R.SPC)))
    | _ ->
      Opcode.LDCL,
      TwoOperands(OpReg(PostInc(getReg1d b16)),
      OpReg(Regdir(getReg1dBank b16)))
  | 0b0110us ->
    match getBits b16 8 5 with
    | 0b1111us ->
      Opcode.LDCL,
      TwoOperands(OpReg(PostInc(getReg1d b16)), OpReg(Regdir(R.DBR)))
    | 0b0000us ->
      Opcode.LDSL,
      TwoOperands(OpReg(PostInc(getReg1d b16)), OpReg(Regdir(R.MACH)))
    | 0b0001us ->
      Opcode.LDSL,
      TwoOperands(OpReg(PostInc(getReg1d b16)), OpReg(Regdir(R.MACL)))
    | 0b0010us ->
      Opcode.LDSL,
      TwoOperands(OpReg(PostInc(getReg1d b16)), OpReg(Regdir(R.PR)))
    | 0b0110us ->
      Opcode.LDSL,
      TwoOperands(OpReg(PostInc(getReg1d b16)), OpReg(Regdir(R.FPSCR)))
    | 0b0101us ->
      Opcode.LDSL,
      TwoOperands(OpReg(PostInc(getReg1d b16)), OpReg(Regdir(R.FPUL)))
    | _ -> Opcode.InvalidOp, NoOperand
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect (Post-Increment)
/// 0110 ---- ---- ---- with source and destination operands.
let parsePostInc0110 b16 =
  match getBits b16 4 1 with
  | 0b0100us ->
    Opcode.MOVB,
    TwoOperands(OpReg(PostInc(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0101us ->
    Opcode.MOVW,
    TwoOperands(OpReg(PostInc(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | 0b0110us ->
    Opcode.MOVL,
    TwoOperands(OpReg(PostInc(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect (Post-Increment)
/// 1111 ---- ---- ---- with source and destination operands.
let parsePostInc1111 b16 =
  match getBits b16 4 1 with
  | 0b1001us ->
    if getState () then
      if get1Bit b16 9 then
        Opcode.FMOV,
        TwoOperands(OpReg(PostInc(getReg1s b16)),
        OpReg(Regdir(getReg1dXD b16)))
      else
        Opcode.FMOV,
        TwoOperands(OpReg(PostInc(getReg1s b16)),
        OpReg(Regdir(getReg1dDR b16)))
    else
      Opcode.FMOVS,
      TwoOperands(OpReg(PostInc(getReg1s b16)),
        OpReg(Regdir(getReg1dFR b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect (Pre-Decrement)
/// 0000 ---- ---- ---- with source and destination operands.
let parsePreDec0010 b16 =
  match getBits b16 4 1 with
  | 0b0100us ->
    Opcode.MOVB,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(PreDec(getReg1d b16)))
  | 0b0101us ->
    Opcode.MOVW,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(PreDec(getReg1d b16)))
  | 0b0110us ->
    Opcode.MOVL,
    TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(PreDec(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect (Pre-Decrement)
/// 1111 ---- ---- ---- with source and destination operands.
let parsePreDec1111 b16 =
  match getBits b16 4 1 with
  | 0b1011us ->
    if getState () (*SZ*) then
      if get1Bit b16 5 then
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sDR b16)),
          OpReg(PreDec(getReg1d b16)))
      else
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sXD b16)),
          OpReg(PreDec(getReg1d b16)))
    else
      Opcode.FMOVS,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(PreDec(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect (Pre-Decrement)
/// 0100 ---- ---- ---- with source and destination operands.
let parsePreDec0100 b16 =
  match getBits b16 4 1 with
  | 0b0011us ->
    match getBits b16 8 5 with
    | 0b0000us ->
      Opcode.STCL,
      TwoOperands(OpReg(Regdir(R.SR)), OpReg(PreDec(getReg1d b16)))
    | 0b0001us ->
      Opcode.STCL,
      TwoOperands(OpReg(Regdir(R.GBR)), OpReg(PreDec(getReg1d b16)))
    | 0b0010us ->
      Opcode.STCL,
      TwoOperands(OpReg(Regdir(R.VBR)), OpReg(PreDec(getReg1d b16)))
    | 0b0011us ->
      Opcode.STCL,
      TwoOperands(OpReg(Regdir(R.SSR)), OpReg(PreDec(getReg1d b16)))
    | 0b0100us ->
      Opcode.STCL,
      TwoOperands(OpReg(Regdir(R.SPC)), OpReg(PreDec(getReg1d b16)))
    | _  ->
      Opcode.STCL,
      TwoOperands(OpReg(Regdir(getReg1dBank b16)),
        OpReg(PreDec(getReg1d b16)))
  | 0b0010us ->
    match getBits b16 8 5 with
    | 0b0011us ->
      Opcode.STCL,
      TwoOperands(OpReg(Regdir(R.SGR)), OpReg(PreDec(getReg1d b16)))
    | 0b1111us ->
      Opcode.STCL,
      TwoOperands(OpReg(Regdir(R.DBR)), OpReg(PreDec(getReg1d b16)))
    | 0b0000us ->
      Opcode.STSL,
      TwoOperands(OpReg(Regdir(R.MACH)), OpReg(PreDec(getReg1d b16)))
    | 0b0001us ->
      Opcode.STSL,
      TwoOperands(OpReg(Regdir(R.MACL)), OpReg(PreDec(getReg1d b16)))
    | 0b0010us ->
      Opcode.STSL,
      TwoOperands(OpReg(Regdir(R.PR)), OpReg(PreDec(getReg1d b16)))
    | 0b0110us ->
      Opcode.STSL,
      TwoOperands(OpReg(Regdir(R.FPSCR)), OpReg(PreDec(getReg1d b16)))
    | 0b0101us ->
      Opcode.STSL,
      TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(PreDec(getReg1d b16)))
    | _ -> Opcode.InvalidOp, NoOperand
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect with Displacement
/// 1000 ---- ---- ---- with source and destination operands.
let parseIndDisp1000 b16 =
  match getBits b16 12 9 with
  | 0b0000us ->
    Opcode.MOVB,
    TwoOperands(OpReg(Regdir(R.R0)),
    OpReg(RegDisp(getDisp4b b16, getReg1s b16)))
  | 0b0001us ->
    Opcode.MOVW,
    TwoOperands(OpReg(Regdir(R.R0)),
    OpReg(RegDisp(getDisp4b b16, getReg1s b16)))
  | 0b0100us ->
    Opcode.MOVB,
    TwoOperands(OpReg(RegDisp(getDisp4b b16, getReg1s b16)),
    OpReg(Regdir(R.R0)))
  | 0b0101us ->
    Opcode.MOVW,
    TwoOperands(OpReg(RegDisp(getDisp4b b16, getReg1s b16)),
    OpReg(Regdir(R.R0)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Register Indirect with Displacement
/// 0001 ---- ---- ---- with source and destination operands.
let parseIndDisp0001 b16 =
  Opcode.MOVL,
  TwoOperands(OpReg(Regdir(getReg1s b16)),
  OpReg(RegDisp(getDisp4b b16, getReg1d b16)))

/// Register Indirect with Displacement
/// 0101 ---- ---- ---- with source and destination operands.
let parseIndDisp0101 b16 =
  Opcode.MOVL,
  TwoOperands(OpReg(RegDisp(getDisp4b b16, getReg1s b16)),
  OpReg(Regdir(getReg1d b16)))

/// Indexed Register Indirect
/// 0000 ---- ---- ---- with source and destination operands.
let parseIdxInd0000 b16 =
  match getBits b16 4 1 with
  | 0b0100us ->
    Opcode.MOVB,
    TwoOperands(OpReg(Regdir(getReg1s b16)),
    OpReg(IdxIndir(R.R0, getReg1d b16)))
  | 0b0101us ->
    Opcode.MOVW,
    TwoOperands(OpReg(Regdir(getReg1s b16)),
    OpReg(IdxIndir(R.R0, getReg1d b16)))
  | 0b0110us ->
    Opcode.MOVL,
    TwoOperands(OpReg(Regdir(getReg1s b16)),
    OpReg(IdxIndir(R.R0, getReg1d b16)))
  | 0b1100us ->
    Opcode.MOVB,
    TwoOperands(OpReg(IdxIndir(R.R0, getReg1s b16)),
    OpReg(Regdir(getReg1d b16)))
  | 0b1101us ->
    Opcode.MOVW,
    TwoOperands(OpReg(IdxIndir(R.R0, getReg1s b16)),
    OpReg(Regdir(getReg1d b16)))
  | 0b1110us ->
    Opcode.MOVL,
    TwoOperands(OpReg(IdxIndir(R.R0, getReg1s b16)),
    OpReg(Regdir(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Indexed Register Indirect
/// 1111 ---- ---- ---- with source and destination operands.
let parseIdxInd1111 b16 =
  match getBits b16 4 1 with
  | 0b0110us ->
    if getState ()(*SZ*) then
      Opcode.FMOV,
      TwoOperands(OpReg(IdxIndir(R.R0, getReg1s b16)),
      OpReg(Regdir(getReg1dDR b16)))
    else
      Opcode.FMOVS,
      TwoOperands(OpReg(IdxIndir(R.R0, getReg1s b16)),
      OpReg(Regdir(getReg1dFR b16)))
  | 0b0111us ->
    if getState ()(*SZ*) then
      if get1Bit b16 5 then
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sXD b16)),
        OpReg(IdxIndir(R.R0, getReg1d b16)))
      else
        Opcode.FMOV,
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
        OpReg(IdxIndir(R.R0, getReg1d b16)))
    else
      Opcode.FMOVS,
      TwoOperands(OpReg(Regdir(getReg1sFR b16)),
      OpReg(IdxIndir(R.R0, getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// GBR Indirect with Displacement
/// 1100 ---- ---- ---- with source and destination operands.
let parseGBRIndDisp1100 b16 =
  match getBits b16 12 9 with
  | 0b0000us ->
    Opcode.MOVB,
    TwoOperands(OpReg(Regdir(R.R0)), OpReg(GbrDisp(getDisp8b b16, R.GBR)))
  | 0b0001us ->
    Opcode.MOVW,
    TwoOperands(OpReg(Regdir(R.R0)), OpReg(GbrDisp(getDisp8b b16, R.GBR)))
  | 0b0010us ->
    Opcode.MOVL,
    TwoOperands(OpReg(Regdir(R.R0)), OpReg(GbrDisp(getDisp8b b16, R.GBR)))
  | 0b0100us ->
    Opcode.MOVB,
    TwoOperands(OpReg(GbrDisp(getDisp8b b16, R.GBR)), OpReg(Regdir(R.R0)))
  | 0b0101us ->
    Opcode.MOVW,
    TwoOperands(OpReg(GbrDisp(getDisp8b b16, R.GBR)), OpReg(Regdir(R.R0)))
  | 0b0110us ->
    Opcode.MOVL,
    TwoOperands(OpReg(GbrDisp(getDisp8b b16, R.GBR)), OpReg(Regdir(R.R0)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Indexed GBR Indirect
/// 1100 ---- ---- ---- with source and destination operands.
let parseIdxGBRInd1100 b16 =
  match getBits b16 12 9 with
  | 0b1101us ->
    Opcode.ANDB,
    TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(IdxGbr(R.R0, R.GBR)))
  | 0b1111us ->
    Opcode.ORB,
    TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(IdxGbr(R.R0, R.GBR)))
  | 0b1100us ->
    Opcode.TSTB,
    TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(IdxGbr(R.R0, R.GBR)))
  | 0b1110us ->
    Opcode.XORB,
    TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(IdxGbr(R.R0, R.GBR)))
  | _ -> Opcode.InvalidOp, NoOperand

/// PC Relative with Displacement
/// 1001 ---- ---- ---- with source and destination operands.
let parsePCDisp1001 b16 =
  Opcode.MOVW,
  TwoOperands(OpReg(PCrDisp(getDisp8b b16, R.PC)),
    OpReg(Regdir(getReg1d b16)))

/// PC Relative with Displacement
/// 1101 ---- ---- ---- with source and destination operands.
let parsePCDisp1101 b16 =
  Opcode.MOVL,
  TwoOperands(OpReg(PCrDisp(getDisp8b b16, R.PC)),
    OpReg(Regdir(getReg1d b16)))

/// PC Relative with Displacement
/// 1100 ---- ---- ---- with source and destination operands.
let parsePCDisp1100 b16 =
  Opcode.MOVA,
  TwoOperands(OpReg(PCrDisp(getDisp8b b16, R.PC)), OpReg(Regdir(R.R0)))

/// PC Relative using Rn
/// 0000 ---- ---- ---- destination operand only.
let parsePCReg0000 b16 =
  match getBits b16 8 5 with
  | 0b0010us -> Opcode.BRAF, OneOperand(OpReg(Regdir(getReg1d b16)))
  | 0b0000us -> Opcode.BSRF, OneOperand(OpReg(Regdir(getReg1d b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// PC Relative 1000 ---- ---- ---- destination operand only.
let parsePC1000 b16 =
  match getBits b16 8 5 with
  | 0b1011us -> Opcode.BF, OneOperand(OpReg(PCr(getDisp8b b16)))
  | 0b1111us -> Opcode.BFS, OneOperand(OpReg(PCr(getDisp8b b16)))
  | 0b1001us -> Opcode.BT, OneOperand(OpReg(PCr(getDisp8b b16)))
  | 0b1101us -> Opcode.BTS, OneOperand(OpReg(PCr(getDisp8b b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// PC Relative 1010 ---- ---- ---- destination operand only.
let parsePC1010 b16 =
  Opcode.BRA, OneOperand(OpReg(PCr(getDisp12b b16)))

/// PC Relative 1011 ---- ---- ---- destination operand only.
let parsePC1011 b16 =
  Opcode.BSR, OneOperand(OpReg(PCr(getDisp12b b16)))

/// Immediate
let parseImm1111 b16 =
  match getBits b16 8 5 with
  | 0b1000us -> Opcode.FLDI0, OneOperand(OpReg(Regdir(getReg1dFR b16)))
  | 0b1001us -> Opcode.FLDI1, OneOperand(OpReg(Regdir(getReg1dFR b16)))
  | _ -> Opcode.InvalidOp, NoOperand

/// Immediate
let parseImm1110 b16 =
  Opcode.MOV,
  TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(Regdir(getReg1d b16)))

/// Immediate
let parseImm0111 b16 =
  Opcode.ADD,
  TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(Regdir(getReg1d b16)))

/// Immediate
let parseImm1000 b16 =
  Opcode.CMPEQ,
  TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(Regdir(R.R0)))

/// Immmediate
let parseImm1100 b16 =
  match getBits b16 8 5 with
  | 0b1001us ->
    Opcode.AND, TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(Regdir(R.R0)))
  | 0b1011us ->
    Opcode.OR, TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(Regdir(R.R0)))
  | 0b1000us ->
    Opcode.TST, TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(Regdir(R.R0)))
  | 0b1010us ->
    Opcode.XOR, TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(Regdir(R.R0)))
  | 0b0011us ->
    Opcode.TRAPA, OneOperand(OpReg(Imm(getDisp8b b16)))
  | _ -> Opcode.InvalidOp, NoOperand

let parseNow b16 =
  match getBits b16 16 13 with
  | 0b0000us ->
    match getBits b16 4 1 with
    | 0b0111us | 0b0010us | 0b1010us -> twoOpParse0000 b16
    | 0b0011us ->
      match getBits b16 8 5 with
      | 0b0010us | 0b0000us -> parsePCReg0000 b16
      | _ -> parseRegInd0000 b16
    | 0b0100us | 0b0101us | 0b0110us | 0b1100us
    | 0b1101us | 0b1110us -> parseIdxInd0000 b16
    | 0b1111us -> parsePostInc0000 b16
    | _ -> noOpParse0000 b16
  | 0b0100us ->
    match getBits b16 4 1 with
    | 0b1100us | 0b1110us | 0b1101us | 0b1010us -> twoOpParse0100 b16
    | 0b1011us -> parseRegInd0100 b16
    | 0b1111us | 0b0111us | 0b0110us -> parsePostInc0100 b16
    | 0b0011us | 0b0010us -> parsePreDec0100 b16
    | _ -> oneOpParse0100 b16
  | 0b0010us ->
    match getBits b16 4 1 with
    | 0b0000us | 0b0001us | 0b0010us -> parseRegInd0010 b16
    | 0b0100us | 0b0101us | 0b0110us -> parsePreDec0010 b16
    | _ -> twoOpParse0010 b16
  | 0b0110us ->
    match getBits b16 4 1 with
    | 0b0000us | 0b0001us | 0b0010us -> parseRegInd0010 b16
    | 0b0100us | 0b0101us | 0b0110us -> parsePostInc0110 b16
    | _ -> twoOpParse0110 b16
  | 0b0011us -> twoOpParse0011 b16
  | 0b1000us ->
    match getBits b16 8 5 with
    | 0b1011us | 0b1111us | 0b1001us | 0b1101us -> parsePC1000 b16
    | 0b1000us -> parseImm1000 b16
    | _ -> parseIndDisp1000 b16
  | 0b1001us -> parsePCDisp1001 b16
  | 0b1010us -> parsePC1010 b16
  | 0b1011us -> parsePC1011 b16
  | 0b1101us -> parsePCDisp1101 b16
  | 0b1110us -> parseImm1110 b16
  | 0b0111us -> parseImm0111 b16
  | 0b1100us ->
    if get1Bit b16 12 then
      match getBits b16 12 9 with
      | 0b1001us | 0b1011us | 0b1000us | 0b1010us -> parseImm1100 b16
      | _ -> parseIdxGBRInd1100 b16
    else
      if getBits b16 8 5 = 0b0111us then parsePCDisp1100 b16
      elif getBits b16 8 5 = 0b0011us then parseImm1100 b16
      else parseGBRIndDisp1100 b16
  | 0b0001us -> parseIndDisp0001 b16
  | 0b0101us -> parseIndDisp0101 b16
  | 0b1111us ->
    if ((getBits b16 4 1 = 0b1101us) && (getBits b16 8 5 = 0b1111us)) then
      match getBits b16 12 9 with
      | 0b1011us | 0b0011us -> noOpParse1111 b16
      | _ -> twoOpParse1111 b16
    else
      match getBits b16 4 1 with
      | 0b1000us | 0b1010us -> parseRegInd1111 b16
      | 0b0110us | 0b0111us -> parseIdxInd1111 b16
      | 0b1001us -> parsePostInc1111 b16
      | 0b1011us -> parsePreDec1111 b16
      | 0b1101us -> parseImm1111 b16
      | _ ->
        match getBits b16 8 5 with
        | 0b0101us | 0b0100us | 0b0110us -> oneOpParse1111 b16
        | _ -> twoOpParse1111 b16
  | _ -> Terminator.futureFeature ()

let parse lifter (span: ByteSpan) (reader: IBinReader) addr =
  let bin = reader.ReadUInt16(span, 0)
  let op, operands = parseNow bin
  Instruction(addr, 2u, op, operands, lifter)
