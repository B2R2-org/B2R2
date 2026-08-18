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

/// Whether the FPU mode bit an encoding selects on is set: FPSCR.SZ for a
/// transfer, FPSCR.PR for an arithmetic operation. A parser cannot know, as the
/// bit lives in a register the program writes at run time while the two
/// encodings it chooses between are identical. This answers for the cleared
/// state -- single precision, thirty-two-bit transfers -- which is what a Linux
/// userland runs in until it sets the bit itself; decoding the set state would
/// mean deferring the choice into the lifter, and fschg and frchg stay unlifted
/// so that a program which does set one stops here rather than running as if it
/// had not.
let getState _ = false

/// 0000 0000 ---- ---- with no operands
let noOpParse0000 b16 =
  (* Every one of these is spelt out to the last bit, so the field that names a
     register elsewhere in this family has to be zero here. Reading only the low
     byte let a word carrying anything in that field pass as the instruction
     below it, and a linear sweep then saw eleven spurious instructions at every
     one of the fifteen nonzero values it can hold. *)
  if getBits b16 12 9 <> 0b0000us then raise ParsingFailureException else ()
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
  | _ -> raise ParsingFailureException

/// 1111 ---- 1111 1101 with no operands.
let noOpParse1111 b16 =
  match getBits b16 12 9 with
  | 0b1011us -> Opcode.FRCHG, NoOperand
  | 0b0011us -> Opcode.FSCHG, NoOperand
  | _ -> raise ParsingFailureException

/// 0000 ---- ---- 1001 with destination operand only. Only movt names a
/// register here; nop and div0u share the low nibble but not the field above
/// it, so they fall through to the no-operand table.
let oneOpParse0000 b16 =
  match getBits b16 8 5 with
  | 0b0010us -> Opcode.MOVT, OneOperand(OpReg(Regdir(getReg1d b16)))
  | _ -> noOpParse0000 b16

/// 0100 ---- ---- ---- with destination operand only.
let oneOpParse0100 b16 =
  match getBits b16 8 5 with
  | 0b0010us ->
    match getBits b16 4 1 with
    | 0b1001us -> Opcode.SHLR16, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0100us -> Opcode.ROTCL, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0101us -> Opcode.ROTCR, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0000us -> Opcode.SHAL, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0001us -> Opcode.SHAR, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b1000us -> Opcode.SHLL16, OneOperand(OpReg(Regdir(getReg1d b16)))
    | _ -> raise ParsingFailureException
  | 0b0001us ->
    match getBits b16 4 1 with
    | 0b0001us -> Opcode.CMPPZ, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0101us -> Opcode.CMPPL, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0000us -> Opcode.DT, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b1000us -> Opcode.SHLL8, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b1001us -> Opcode.SHLR8, OneOperand(OpReg(Regdir(getReg1d b16)))
    | _ -> raise ParsingFailureException
  | 0b0000us ->
    match getBits b16 4 1 with
    | 0b0100us -> Opcode.ROTL, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0101us -> Opcode.ROTR, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0000us -> Opcode.SHLL, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b0001us -> Opcode.SHLR, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b1000us -> Opcode.SHLL2, OneOperand(OpReg(Regdir(getReg1d b16)))
    | 0b1001us -> Opcode.SHLR2, OneOperand(OpReg(Regdir(getReg1d b16)))
    | _ -> raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// 1111 ---- ---- 1101 with destination operand only.
let oneOpParse1111 b16 =
  match getBits b16 8 5 with
  | 0b0101us ->
    if get1Bit b16 9 then Opcode.FABS, OneOperand(OpReg(Regdir(getReg1dFR b16)))
    elif getState ()
      then Opcode.FABS, OneOperand(OpReg(Regdir(getReg1dDR b16)))
    else Opcode.FABS, OneOperand(OpReg(Regdir(getReg1dFR b16)))
  | 0b0100us ->
    if get1Bit b16 9 then Opcode.FNEG, OneOperand(OpReg(Regdir(getReg1dFR b16)))
    elif getState () then Opcode.FNEG, OneOperand(OpReg(Regdir(getReg1dDR b16)))
    else Opcode.FNEG, OneOperand(OpReg(Regdir(getReg1dFR b16)))
  | 0b0110us ->
    if get1Bit b16 9 then
      Opcode.FSQRT, OneOperand(OpReg(Regdir(getReg1dFR b16)))
    elif getState () then
      Opcode.FSQRT, OneOperand(OpReg(Regdir(getReg1dDR b16)))
    else
      Opcode.FSQRT, OneOperand(OpReg(Regdir(getReg1dFR b16)))
  | _ ->
    raise ParsingFailureException

/// 0011 ---- ---- ---- with source and destination operands.
let twoOpParse0011 b16 =
  match getBits b16 4 1 with
  | 0b1100us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.ADD, opr
  | 0b1110us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.ADDC, opr
  | 0b1111us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.ADDV, opr
  | 0b0000us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.CMPEQ, opr
  | 0b0010us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.CMPHS, opr
  | 0b0011us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.CMPGE, opr
  | 0b0110us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.CMPHI, opr
  | 0b0111us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.CMPGT, opr
  | 0b0100us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.DIV1, opr
  | 0b1101us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.DMULSL, opr
  | 0b0101us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.DMULUL, opr
  | 0b1000us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.SUB, opr
  | 0b1010us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.SUBC, opr
  | 0b1011us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.SUBV, opr
  | _ ->
    raise ParsingFailureException

/// 0110 ---- ---- ---- with source and destination operands.
let twoOpParse0110 b16 =
  match getBits b16 4 1 with
  | 0b0011us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.MOV, opr
  | 0b1000us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.SWAPB, opr
  | 0b1001us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.SWAPW, opr
  | 0b1110us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.EXTSB, opr
  | 0b1111us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.EXTSW, opr
  | 0b1100us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.EXTUB, opr
  | 0b1101us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.EXTUW, opr
  | 0b1011us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.NEG, opr
  | 0b1010us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.NEGC, opr
  | 0b0111us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.NOT, opr
  | _ ->
    raise ParsingFailureException

/// 0010 ---- ---- ---- with source and destination operands.
let twoOpParse0010 b16 =
  match getBits b16 4 1 with
  | 0b1101us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.XTRCT, opr
  | 0b1100us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.CMPSTR, opr
  | 0b0111us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.DIV0S, opr
  | 0b1111us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.MULSW, opr
  | 0b1110us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.MULUW, opr
  | 0b1001us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.AND, opr
  | 0b1011us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.OR, opr
  | 0b1000us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.TST, opr
  | 0b1010us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.XOR, opr
  | _ ->
    raise ParsingFailureException

/// 0100 ---- ---- ---- with source and destination operands.
let twoOpParse0100 b16 =
  match getBits b16 4 1 with
  | 0b1100us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.SHAD, opr
  | 0b1101us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.SHLD, opr
  | 0b1110us ->
    match getBits b16 8 5 with
    | 0b0000us ->
      Opcode.LDC, TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.SR)))
    | 0b0001us ->
      Opcode.LDC, TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.GBR)))
    | 0b0010us ->
      Opcode.LDC, TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.VBR)))
    | 0b0011us ->
      Opcode.LDC, TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.SSR)))
    | 0b0100us ->
      Opcode.LDC, TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.SPC)))
    | 0b1000us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1d b16)),
                    OpReg(Regdir(getReg1dBank b16)))
      Opcode.LDC, opr
    | 0b1001us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1d b16)),
                    OpReg(Regdir(getReg1dBank b16)))
      Opcode.LDC, opr
    | 0b1010us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1d b16)),
                    OpReg(Regdir(getReg1dBank b16)))
      Opcode.LDC, opr
    | 0b1011us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1d b16)),
                    OpReg(Regdir(getReg1dBank b16)))
      Opcode.LDC, opr
    | 0b1100us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1d b16)),
                    OpReg(Regdir(getReg1dBank b16)))
      Opcode.LDC, opr
    | 0b1101us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1d b16)),
                    OpReg(Regdir(getReg1dBank b16)))
      Opcode.LDC, opr
    | 0b1110us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1d b16)),
                    OpReg(Regdir(getReg1dBank b16)))
      Opcode.LDC, opr
    | 0b1111us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1d b16)),
                    OpReg(Regdir(getReg1dBank b16)))
      Opcode.LDC, opr
    | _ ->
      raise ParsingFailureException
  | 0b1010us ->
    match getBits b16 8 5 with
    | 0b1111us ->
      Opcode.LDC, TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.DBR)))
    | 0b0000us ->
      let opr = TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.MACH)))
      Opcode.LDS, opr
    | 0b0001us ->
      let opr = TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.MACL)))
      Opcode.LDS, opr
    | 0b0010us ->
      Opcode.LDS, TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.PR)))
    | 0b0110us ->
      let opr = TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.FPSCR)))
      Opcode.LDS, opr
    | 0b0101us ->
      let opr = TwoOperands(OpReg(Regdir(getReg1d b16)), OpReg(Regdir(R.FPUL)))
      Opcode.LDS, opr
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// 0000 ---- ---- ---- with source and destination operand.
let twoOpParse0000 b16 =
  match getBits b16 4 1 with
  | 0b0111us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.MULL, opr
  | 0b0010us ->
    match getBits b16 8 5 with
    | 0b0000us ->
      Opcode.STC, TwoOperands(OpReg(Regdir(R.SR)), OpReg(Regdir(getReg1d b16)))
    | 0b0001us ->
      Opcode.STC, TwoOperands(OpReg(Regdir(R.GBR)), OpReg(Regdir(getReg1d b16)))
    | 0b0010us ->
      Opcode.STC, TwoOperands(OpReg(Regdir(R.VBR)), OpReg(Regdir(getReg1d b16)))
    | 0b0011us ->
      Opcode.STC, TwoOperands(OpReg(Regdir(R.SSR)), OpReg(Regdir(getReg1d b16)))
    | 0b0100us ->
      Opcode.STC, TwoOperands(OpReg(Regdir(R.SPC)), OpReg(Regdir(getReg1d b16)))
    | 0b1000us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1dBank b16)),
                    OpReg(Regdir(getReg1d b16)))
      Opcode.STC, opr
    | 0b1001us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1dBank b16)),
                    OpReg(Regdir(getReg1d b16)))
      Opcode.STC, opr
    | 0b1010us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1dBank b16)),
                    OpReg(Regdir(getReg1d b16)))
      Opcode.STC, opr
    | 0b1011us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1dBank b16)),
                    OpReg(Regdir(getReg1d b16)))
      Opcode.STC, opr
    | 0b1100us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1dBank b16)),
                    OpReg(Regdir(getReg1d b16)))
      Opcode.STC, opr
    | 0b1101us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1dBank b16)),
                    OpReg(Regdir(getReg1d b16)))
      Opcode.STC, opr
    | 0b1110us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1dBank b16)),
                    OpReg(Regdir(getReg1d b16)))
      Opcode.STC, opr
    | 0b1111us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1dBank b16)),
                    OpReg(Regdir(getReg1d b16)))
      Opcode.STC, opr
    | _ ->
      raise ParsingFailureException
  | 0b1010us ->
    match getBits b16 8 5 with
    | 0b0011us ->
      Opcode.STC, TwoOperands(OpReg(Regdir(R.SGR)), OpReg(Regdir(getReg1d b16)))
    | 0b1111us ->
      Opcode.STC, TwoOperands(OpReg(Regdir(R.DBR)), OpReg(Regdir(getReg1d b16)))
    | 0b0000us ->
      let opr = TwoOperands(OpReg(Regdir(R.MACH)), OpReg(Regdir(getReg1d b16)))
      Opcode.STS, opr
    | 0b0001us ->
      let opr = TwoOperands(OpReg(Regdir(R.MACL)), OpReg(Regdir(getReg1d b16)))
      Opcode.STS, opr
    | 0b0010us ->
      Opcode.STS, TwoOperands(OpReg(Regdir(R.PR)), OpReg(Regdir(getReg1d b16)))
    | 0b0110us ->
      let opr = TwoOperands(OpReg(Regdir(R.FPSCR)), OpReg(Regdir(getReg1d b16)))
      Opcode.STS, opr
    | 0b0101us ->
      let opr = TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(Regdir(getReg1d b16)))
      Opcode.STS, opr
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// 1111 ---- ---- ---- with source and destination operands.
let twoOpParse1111 b16 =
  match getBits b16 4 1 with
  | 0b1110us ->
    let oprs =
      ThreeOperands(OpReg(Regdir(R.FR0)),
                    OpReg(Regdir(getReg1sFR b16)),
                    OpReg(Regdir(getReg1dFR b16)))
    Opcode.FMAC, oprs
  | 0b0000us ->
    if get1Bit b16 5 then
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FADD, opr
    elif getState () then
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sDR b16)),
                    OpReg(Regdir(getReg1dDR b16)))
      Opcode.FADD, opr
    else
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FADD, opr
  | 0b0100us ->
    if get1Bit b16 5 then
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FCMPEQ, opr
    elif getState () then
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sDR b16)),
                    OpReg(Regdir(getReg1dDR b16)))
      Opcode.FCMPEQ, opr
    else
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FCMPEQ, opr
  | 0b0101us ->
    if get1Bit b16 5 then
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FCMPGT, opr
    elif getState () then
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sDR b16)),
                    OpReg(Regdir(getReg1dDR b16)))
      Opcode.FCMPGT, opr
    else
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FCMPGT, opr
  | 0b0011us ->
    if get1Bit b16 5 then
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FDIV, opr
    elif getState () then
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sDR b16)),
                    OpReg(Regdir(getReg1dDR b16)))
      Opcode.FDIV, opr
    else
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FDIV, opr
  | 0b0010us ->
    if get1Bit b16 5 then
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FMUL, opr
    elif getState () then
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sDR b16)),
                    OpReg(Regdir(getReg1dDR b16)))
      Opcode.FMUL, opr
    else
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FMUL, opr
  | 0b0001us ->
    if get1Bit b16 5 then
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FSUB, opr
    elif getState () then
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sDR b16)),
                    OpReg(Regdir(getReg1dDR b16)))
      Opcode.FSUB, opr
    else
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FSUB, opr
  | 0b1100us ->
    if (get1Bit b16 5 && get1Bit b16 9) then
      if getState () then
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sXD b16)),
                      OpReg(Regdir(getReg1dXD b16)))
        Opcode.FMOV, oprs
      else
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                      OpReg(Regdir(getReg1dFR b16)))
        Opcode.FMOV, oprs
    elif ((get1Bit b16 9) && not (get1Bit b16 5)) then
      if getState () then
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sDR b16)),
                      OpReg(Regdir(getReg1dXD b16)))
        Opcode.FMOV, oprs
      else
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                      OpReg(Regdir(getReg1dFR b16)))
        Opcode.FMOV, oprs
    elif ((get1Bit b16 5) && not (get1Bit b16 9)) then
      if getState () then
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sXD b16)),
                      OpReg(Regdir(getReg1dDR b16)))
        Opcode.FMOV, oprs
      else
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                      OpReg(Regdir(getReg1dFR b16)))
        Opcode.FMOV, oprs
    else
      if getState () then
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sDR b16)),
                      OpReg(Regdir(getReg1dDR b16)))
        Opcode.FMOV, oprs
      else
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                      OpReg(Regdir(getReg1dFR b16)))
        Opcode.FMOV, oprs
  | 0b1101us ->
    match getBits b16 8 5 with
    | 0b1110us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFV b16)),
                    OpReg(Regdir(getReg1dFV b16)))
      Opcode.FIPR, opr
    (* A vector is named by the two uppermost bits of the field, and the two
       below them are spelt out. A pair is named by the three uppermost and the
       one below them is spelt out likewise. Reading only the bits that name the
       register let every value of the ones that do not pass as well, so each of
       these decoded at three or seven words it does not belong to. *)
    | 0b1111us when getBits b16 10 9 = 0b01us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.XMTRX)), OpReg(Regdir(getReg1dFV b16)))
      Opcode.FTRV, opr
    | 0b0001us ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1dFR b16)), OpReg(Regdir(R.FPUL)))
      Opcode.FLDS, opr
    | 0b1011us when not (get1Bit b16 9) ->
      let opr =
        TwoOperands(OpReg(Regdir(getReg1dDR b16)), OpReg(Regdir(R.FPUL)))
      Opcode.FCNVDS, opr
    | 0b0011us ->
      if get1Bit b16 9 then
        let opr =
          TwoOperands(OpReg(Regdir(getReg1dFR b16)), OpReg(Regdir(R.FPUL)))
        Opcode.FTRC, opr
      elif getState () then
        let opr =
          TwoOperands(OpReg(Regdir(getReg1dDR b16)), OpReg(Regdir(R.FPUL)))
        Opcode.FTRC, opr
      else
        let opr =
          TwoOperands(OpReg(Regdir(getReg1dFR b16)), OpReg(Regdir(R.FPUL)))
        Opcode.FTRC, opr
    | 0b0000us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(Regdir(getReg1dFR b16)))
      Opcode.FSTS, opr
    | 0b1010us when not (get1Bit b16 9) ->
      let opr =
        TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(Regdir(getReg1dDR b16)))
      Opcode.FCNVSD, opr
    | 0b0010us ->
      if get1Bit b16 9 then
        let opr =
          TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(Regdir(getReg1dFR b16)))
        Opcode.FLOAT, opr
      elif getState () then
        let opr =
          TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(Regdir(getReg1dFR b16)))
        Opcode.FLOAT, opr
      else
        let opr =
          TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(Regdir(getReg1dFR b16)))
        Opcode.FLOAT, opr
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// Register Indirect 0100 ---- ---- ---- with destination operand only.
let parseRegInd0100 b16 =
  match getBits b16 8 5 with
  | 0b0001us -> Opcode.TASB, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | 0b0010us -> Opcode.JMP, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | 0b0000us -> Opcode.JSR, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | _ -> raise ParsingFailureException

/// Register Indirect 0000 ---- ---- ---- with destination operand only.
let parseRegInd0000 b16 =
  match getBits b16 8 5 with
  | 0b1001us ->
    Opcode.OCBI, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | 0b1010us ->
    Opcode.OCBP, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | 0b1011us ->
    Opcode.OCBWB, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | 0b1000us ->
    Opcode.PREF, OneOperand(OpReg(RegIndir(getReg1d b16)))
  | 0b1100us ->
    let opr = TwoOperands(OpReg(Regdir(R.R0)), OpReg(RegIndir(getReg1d b16)))
    Opcode.MOVCAL, opr
  | _ ->
    raise ParsingFailureException

/// Register Indirect 0010 ---- ---- ---- with source and destination operands.
let parseRegInd0010 b16 =
  match getBits b16 4 1 with
  | 0b0000us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(RegIndir(getReg1d b16)))
    Opcode.MOVB, opr
  | 0b0001us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(RegIndir(getReg1d b16)))
    Opcode.MOVW, opr
  | 0b0010us ->
    let opr =
      TwoOperands(OpReg(Regdir(getReg1s b16)), OpReg(RegIndir(getReg1d b16)))
    Opcode.MOVL, opr
  | _ ->
    raise ParsingFailureException

/// Register Indirect 0110 ---- ---- ---- with source and destination operands.
let parseRegInd0110 b16 =
  match getBits b16 4 1 with
  | 0b0000us ->
    let opr =
      TwoOperands(OpReg(RegIndir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.MOVB, opr
  | 0b0001us ->
    let opr =
      TwoOperands(OpReg(RegIndir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.MOVW, opr
  | 0b0010us ->
    let opr =
      TwoOperands(OpReg(RegIndir(getReg1s b16)), OpReg(Regdir(getReg1d b16)))
    Opcode.MOVL, opr
  | _ ->
    raise ParsingFailureException

/// Register Indirect 1111 ---- ---- ---- with source and destination operands.
let parseRegInd1111 b16 =
  match getBits b16 4 1 with
  | 0b1000us ->
    if getState () then
      if get1Bit b16 9 then
        let oprs =
          TwoOperands(OpReg(RegIndir(getReg1s b16)),
                      OpReg(Regdir(getReg1dXD b16)))
        Opcode.FMOV, oprs
      else
        let oprs =
          TwoOperands(OpReg(RegIndir(getReg1s b16)),
                      OpReg(Regdir(getReg1dDR b16)))
        Opcode.FMOV, oprs
    else
      let opr =
        TwoOperands(OpReg(RegIndir(getReg1s b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FMOVS, opr
  | 0b1010us ->
    if getState () then
      if get1Bit b16 5 then
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sXD b16)),
                      OpReg(RegIndir(getReg1d b16)))
        Opcode.FMOV, oprs
      else
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sDR b16)),
                      OpReg(RegIndir(getReg1d b16)))
        Opcode.FMOV, oprs
    else
      let opr =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(RegIndir(getReg1d b16)))
      Opcode.FMOVS, opr
  | _ ->
    raise ParsingFailureException

/// Register Indirect (Post-Increment)
/// 0000 ---- ---- ---- with source and destination operands.
let parsePostInc0000 b16 =
  match getBits b16 4 1 with
  | 0b1111us ->
    let oprs =
      TwoOperands(OpReg(RegIndirPostInc(getReg1s b16)),
                  OpReg(RegIndirPostInc(getReg1d b16)))
    Opcode.MACL, oprs
  | _ ->
    raise ParsingFailureException

/// Register Indirect (Post-Increment)
/// 0100 ---- ---- ---- with source and destination operands.
let parsePostInc0100 b16 =
  match getBits b16 4 1 with
  | 0b1111us ->
    let oprs =
      TwoOperands(OpReg(RegIndirPostInc(getReg1s b16)),
                  OpReg(RegIndirPostInc(getReg1d b16)))
    Opcode.MACW, oprs
  | 0b0111us ->
    match getBits b16 8 5 with
    | 0b0000us ->
      let opr =
        TwoOperands(OpReg(RegIndirPostInc(getReg1d b16)), OpReg(Regdir(R.SR)))
      Opcode.LDCL, opr
    | 0b0001us ->
      let opr =
        TwoOperands(OpReg(RegIndirPostInc(getReg1d b16)), OpReg(Regdir(R.GBR)))
      Opcode.LDCL, opr
    | 0b0010us ->
      let opr =
        TwoOperands(OpReg(RegIndirPostInc(getReg1d b16)), OpReg(Regdir(R.VBR)))
      Opcode.LDCL, opr
    | 0b0011us ->
      let opr =
        TwoOperands(OpReg(RegIndirPostInc(getReg1d b16)), OpReg(Regdir(R.SSR)))
      Opcode.LDCL, opr
    | 0b0100us ->
      let opr =
        TwoOperands(OpReg(RegIndirPostInc(getReg1d b16)), OpReg(Regdir(R.SPC)))
      Opcode.LDCL, opr
    (* A banked register is named by the three bits below the one saying that
       this is a bank at all, so the values with that bit clear name nothing.
       Falling through to the bank case on any value read the bit as part of the
       number and gave three registers that cannot be loaded this way. *)
    | field when field >= 0b1000us ->
      let oprs =
        TwoOperands(OpReg(RegIndirPostInc(getReg1d b16)),
                    OpReg(Regdir(getReg1dBank b16)))
      Opcode.LDCL, oprs
    | _ ->
      raise ParsingFailureException
  | 0b0110us ->
    match getBits b16 8 5 with
    | 0b1111us ->
      let opr =
        TwoOperands(OpReg(RegIndirPostInc(getReg1d b16)), OpReg(Regdir(R.DBR)))
      Opcode.LDCL, opr
    | 0b0000us ->
      let opr =
        TwoOperands(OpReg(RegIndirPostInc(getReg1d b16)), OpReg(Regdir(R.MACH)))
      Opcode.LDSL, opr
    | 0b0001us ->
      let opr =
        TwoOperands(OpReg(RegIndirPostInc(getReg1d b16)), OpReg(Regdir(R.MACL)))
      Opcode.LDSL, opr
    | 0b0010us ->
      let opr =
        TwoOperands(OpReg(RegIndirPostInc(getReg1d b16)), OpReg(Regdir(R.PR)))
      Opcode.LDSL, opr
    | 0b0110us ->
      let opr =
        TwoOperands(OpReg(RegIndirPostInc(getReg1d b16)),
                    OpReg(Regdir(R.FPSCR)))
      Opcode.LDSL, opr
    | 0b0101us ->
      let opr =
        TwoOperands(OpReg(RegIndirPostInc(getReg1d b16)), OpReg(Regdir(R.FPUL)))
      Opcode.LDSL, opr
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// Register Indirect (Post-Increment)
/// 0110 ---- ---- ---- with source and destination operands.
let parsePostInc0110 b16 =
  match getBits b16 4 1 with
  | 0b0100us ->
    let oprs =
      TwoOperands(OpReg(RegIndirPostInc(getReg1s b16)),
                  OpReg(Regdir(getReg1d b16)))
    Opcode.MOVB, oprs
  | 0b0101us ->
    let oprs =
      TwoOperands(OpReg(RegIndirPostInc(getReg1s b16)),
                  OpReg(Regdir(getReg1d b16)))
    Opcode.MOVW, oprs
  | 0b0110us ->
    let oprs =
      TwoOperands(OpReg(RegIndirPostInc(getReg1s b16)),
                  OpReg(Regdir(getReg1d b16)))
    Opcode.MOVL, oprs
  | _ ->
    raise ParsingFailureException

/// Register Indirect (Post-Increment)
/// 1111 ---- ---- ---- with source and destination operands.
let parsePostInc1111 b16 =
  match getBits b16 4 1 with
  | 0b1001us ->
    if getState () then
      if get1Bit b16 9 then
        let oprs =
          TwoOperands(OpReg(RegIndirPostInc(getReg1s b16)),
                      OpReg(Regdir(getReg1dXD b16)))
        Opcode.FMOV, oprs
      else
        let oprs =
          TwoOperands(OpReg(RegIndirPostInc(getReg1s b16)),
                      OpReg(Regdir(getReg1dDR b16)))
        Opcode.FMOV, oprs
    else
      let oprs =
        TwoOperands(OpReg(RegIndirPostInc(getReg1s b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FMOVS, oprs
  | _ ->
    raise ParsingFailureException

/// Register Indirect (Pre-Decrement)
/// 0000 ---- ---- ---- with source and destination operands.
let parsePreDec0010 b16 =
  match getBits b16 4 1 with
  | 0b0100us ->
    let oprs =
      TwoOperands(OpReg(Regdir(getReg1s b16)),
                  OpReg(RegIndirPreDec(getReg1d b16)))
    Opcode.MOVB, oprs
  | 0b0101us ->
    let oprs =
      TwoOperands(OpReg(Regdir(getReg1s b16)),
                  OpReg(RegIndirPreDec(getReg1d b16)))
    Opcode.MOVW, oprs
  | 0b0110us ->
    let oprs =
      TwoOperands(OpReg(Regdir(getReg1s b16)),
                  OpReg(RegIndirPreDec(getReg1d b16)))
    Opcode.MOVL, oprs
  | _ ->
    raise ParsingFailureException

/// Register Indirect (Pre-Decrement)
/// 1111 ---- ---- ---- with source and destination operands.
let parsePreDec1111 b16 =
  match getBits b16 4 1 with
  | 0b1011us ->
    if getState () (*SZ*) then
      if get1Bit b16 5 then
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sDR b16)),
                      OpReg(RegIndirPreDec(getReg1d b16)))
        Opcode.FMOV, oprs
      else
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sXD b16)),
                      OpReg(RegIndirPreDec(getReg1d b16)))
        Opcode.FMOV, oprs
    else
      let oprs =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.FMOVS, oprs
  | _ ->
    raise ParsingFailureException

/// Register Indirect (Pre-Decrement)
/// 0100 ---- ---- ---- with source and destination operands.
let parsePreDec0100 b16 =
  match getBits b16 4 1 with
  | 0b0011us ->
    match getBits b16 8 5 with
    | 0b0000us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.SR)), OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.STCL, opr
    | 0b0001us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.GBR)), OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.STCL, opr
    | 0b0010us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.VBR)), OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.STCL, opr
    | 0b0011us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.SSR)), OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.STCL, opr
    | 0b0100us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.SPC)), OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.STCL, opr
    (* The same bit says whether a bank is named here, and the same three
       registers appeared out of nowhere while it was read as a number. *)
    | field when field >= 0b1000us ->
      let oprs =
        TwoOperands(OpReg(Regdir(getReg1dBank b16)),
                    OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.STCL, oprs
    | _ ->
      raise ParsingFailureException
  | 0b0010us ->
    match getBits b16 8 5 with
    | 0b0011us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.SGR)), OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.STCL, opr
    | 0b1111us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.DBR)), OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.STCL, opr
    | 0b0000us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.MACH)), OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.STSL, opr
    | 0b0001us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.MACL)), OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.STSL, opr
    | 0b0010us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.PR)), OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.STSL, opr
    | 0b0110us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.FPSCR)), OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.STSL, opr
    | 0b0101us ->
      let opr =
        TwoOperands(OpReg(Regdir(R.FPUL)), OpReg(RegIndirPreDec(getReg1d b16)))
      Opcode.STSL, opr
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// Register Indirect with Displacement
/// 1000 ---- ---- ---- with source and destination operands.
let parseIndDisp1000 b16 =
  match getBits b16 12 9 with
  | 0b0000us ->
    let oprs =
      TwoOperands(OpReg(Regdir(R.R0)),
                  OpReg(RegIndirDisp(getDisp4b b16, getReg1s b16)))
    Opcode.MOVB, oprs
  | 0b0001us ->
    let oprs =
      TwoOperands(OpReg(Regdir(R.R0)),
                  OpReg(RegIndirDisp(getDisp4b b16, getReg1s b16)))
    Opcode.MOVW, oprs
  | 0b0100us ->
    let oprs =
      TwoOperands(OpReg(RegIndirDisp(getDisp4b b16, getReg1s b16)),
                  OpReg(Regdir(R.R0)))
    Opcode.MOVB, oprs
  | 0b0101us ->
    let oprs =
      TwoOperands(OpReg(RegIndirDisp(getDisp4b b16, getReg1s b16)),
                  OpReg(Regdir(R.R0)))
    Opcode.MOVW, oprs
  | _ ->
    raise ParsingFailureException

/// Register Indirect with Displacement
/// 0001 ---- ---- ---- with source and destination operands.
let parseIndDisp0001 b16 =
  let oprs =
    TwoOperands(OpReg(Regdir(getReg1s b16)),
                OpReg(RegIndirDisp(getDisp4b b16, getReg1d b16)))
  Opcode.MOVL, oprs

/// Register Indirect with Displacement
/// 0101 ---- ---- ---- with source and destination operands.
let parseIndDisp0101 b16 =
  let oprs =
    TwoOperands(OpReg(RegIndirDisp(getDisp4b b16, getReg1s b16)),
                OpReg(Regdir(getReg1d b16)))
  Opcode.MOVL, oprs

/// Indexed Register Indirect
/// 0000 ---- ---- ---- with source and destination operands.
let parseIdxInd0000 b16 =
  match getBits b16 4 1 with
  | 0b0100us ->
    let oprs =
      TwoOperands(OpReg(Regdir(getReg1s b16)),
                  OpReg(IdxRegIndir(R.R0, getReg1d b16)))
    Opcode.MOVB, oprs
  | 0b0101us ->
    let oprs =
      TwoOperands(OpReg(Regdir(getReg1s b16)),
                  OpReg(IdxRegIndir(R.R0, getReg1d b16)))
    Opcode.MOVW, oprs
  | 0b0110us ->
    let oprs =
      TwoOperands(OpReg(Regdir(getReg1s b16)),
                  OpReg(IdxRegIndir(R.R0, getReg1d b16)))
    Opcode.MOVL, oprs
  | 0b1100us ->
    let oprs =
      TwoOperands(OpReg(IdxRegIndir(R.R0, getReg1s b16)),
                  OpReg(Regdir(getReg1d b16)))
    Opcode.MOVB, oprs
  | 0b1101us ->
    let oprs =
      TwoOperands(OpReg(IdxRegIndir(R.R0, getReg1s b16)),
                  OpReg(Regdir(getReg1d b16)))
    Opcode.MOVW, oprs
  | 0b1110us ->
    let oprs =
      TwoOperands(OpReg(IdxRegIndir(R.R0, getReg1s b16)),
                  OpReg(Regdir(getReg1d b16)))
    Opcode.MOVL, oprs
  | _ ->
    raise ParsingFailureException

/// Indexed Register Indirect
/// 1111 ---- ---- ---- with source and destination operands.
let parseIdxInd1111 b16 =
  match getBits b16 4 1 with
  | 0b0110us ->
    if getState ()(*SZ*) then
      let oprs =
        TwoOperands(OpReg(IdxRegIndir(R.R0, getReg1s b16)),
                    OpReg(Regdir(getReg1dDR b16)))
      Opcode.FMOV, oprs
    else
      let oprs =
        TwoOperands(OpReg(IdxRegIndir(R.R0, getReg1s b16)),
                    OpReg(Regdir(getReg1dFR b16)))
      Opcode.FMOVS, oprs
  | 0b0111us ->
    if getState ()(*SZ*) then
      if get1Bit b16 5 then
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sXD b16)),
                      OpReg(IdxRegIndir(R.R0, getReg1d b16)))
        Opcode.FMOV, oprs
      else
        let oprs =
          TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                      OpReg(IdxRegIndir(R.R0, getReg1d b16)))
        Opcode.FMOV, oprs
    else
      let oprs =
        TwoOperands(OpReg(Regdir(getReg1sFR b16)),
                    OpReg(IdxRegIndir(R.R0, getReg1d b16)))
      Opcode.FMOVS, oprs
  | _ ->
    raise ParsingFailureException

/// GBR Indirect with Displacement
/// 1100 ---- ---- ---- with source and destination operands.
let parseGBRIndDisp1100 b16 =
  match getBits b16 12 9 with
  | 0b0000us ->
    let opr =
      TwoOperands(OpReg(Regdir(R.R0)),
                  OpReg(GBRIndirDisp(getDisp8b b16, R.GBR)))
    Opcode.MOVB, opr
  | 0b0001us ->
    let opr =
      TwoOperands(OpReg(Regdir(R.R0)),
                  OpReg(GBRIndirDisp(getDisp8b b16, R.GBR)))
    Opcode.MOVW, opr
  | 0b0010us ->
    let opr =
      TwoOperands(OpReg(Regdir(R.R0)),
                  OpReg(GBRIndirDisp(getDisp8b b16, R.GBR)))
    Opcode.MOVL, opr
  | 0b0100us ->
    let opr =
      TwoOperands(OpReg(GBRIndirDisp(getDisp8b b16, R.GBR)),
                  OpReg(Regdir(R.R0)))
    Opcode.MOVB, opr
  | 0b0101us ->
    let opr =
      TwoOperands(OpReg(GBRIndirDisp(getDisp8b b16, R.GBR)),
                  OpReg(Regdir(R.R0)))
    Opcode.MOVW, opr
  | 0b0110us ->
    let opr =
      TwoOperands(OpReg(GBRIndirDisp(getDisp8b b16, R.GBR)),
                  OpReg(Regdir(R.R0)))
    Opcode.MOVL, opr
  | _ ->
    raise ParsingFailureException

/// Indexed GBR Indirect
/// 1100 ---- ---- ---- with source and destination operands.
let parseIdxGBRInd1100 b16 =
  match getBits b16 12 9 with
  | 0b1101us ->
    let opr =
      TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(IdxGBRIndir(R.R0, R.GBR)))
    Opcode.ANDB, opr
  | 0b1111us ->
    let opr =
      TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(IdxGBRIndir(R.R0, R.GBR)))
    Opcode.ORB, opr
  | 0b1100us ->
    let opr =
      TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(IdxGBRIndir(R.R0, R.GBR)))
    Opcode.TSTB, opr
  | 0b1110us ->
    let opr =
      TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(IdxGBRIndir(R.R0, R.GBR)))
    Opcode.XORB, opr
  | _ ->
    raise ParsingFailureException

/// PC Relative with Displacement
/// 1001 ---- ---- ---- with source and destination operands.
let parsePCDisp1001 b16 =
  let oprs =
    TwoOperands(OpReg(PCRelDisp(getDisp8b b16, R.PC)),
                OpReg(Regdir(getReg1d b16)))
  Opcode.MOVW, oprs

/// PC Relative with Displacement
/// 1101 ---- ---- ---- with source and destination operands.
let parsePCDisp1101 b16 =
  let oprs =
    TwoOperands(OpReg(PCRelDisp(getDisp8b b16, R.PC)),
                OpReg(Regdir(getReg1d b16)))
  Opcode.MOVL, oprs

/// PC Relative with Displacement
/// 1100 ---- ---- ---- with source and destination operands.
let parsePCDisp1100 b16 =
  let oprs =
    TwoOperands(OpReg(PCRelDisp(getDisp8b b16, R.PC)), OpReg(Regdir(R.R0)))
  Opcode.MOVA, oprs

/// PC Relative using Rn
/// 0000 ---- ---- ---- destination operand only.
let parsePCReg0000 b16 =
  match getBits b16 8 5 with
  | 0b0010us -> Opcode.BRAF, OneOperand(OpReg(Regdir(getReg1d b16)))
  | 0b0000us -> Opcode.BSRF, OneOperand(OpReg(Regdir(getReg1d b16)))
  | _ -> raise ParsingFailureException

/// PC Relative 1000 ---- ---- ---- destination operand only.
let parsePC1000 b16 =
  match getBits b16 12 9 with
  | 0b1011us -> Opcode.BF, OneOperand(OpReg(PCRelative(getDisp8b b16)))
  | 0b1111us -> Opcode.BFS, OneOperand(OpReg(PCRelative(getDisp8b b16)))
  | 0b1001us -> Opcode.BT, OneOperand(OpReg(PCRelative(getDisp8b b16)))
  | 0b1101us -> Opcode.BTS, OneOperand(OpReg(PCRelative(getDisp8b b16)))
  | _ -> raise ParsingFailureException

/// PC Relative 1010 ---- ---- ---- destination operand only.
let parsePC1010 b16 = Opcode.BRA, OneOperand(OpReg(PCRelative(getDisp12b b16)))

/// PC Relative 1011 ---- ---- ---- destination operand only.
let parsePC1011 b16 = Opcode.BSR, OneOperand(OpReg(PCRelative(getDisp12b b16)))

/// Immediate
let parseImm1111 b16 =
  match getBits b16 8 5 with
  | 0b1000us -> Opcode.FLDI0, OneOperand(OpReg(Regdir(getReg1dFR b16)))
  | 0b1001us -> Opcode.FLDI1, OneOperand(OpReg(Regdir(getReg1dFR b16)))
  | _ -> raise ParsingFailureException

/// Immediate
let parseImm1110 b16 =
  let oprs = TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(Regdir(getReg1d b16)))
  Opcode.MOV, oprs

/// Immediate
let parseImm0111 b16 =
  let oprs = TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(Regdir(getReg1d b16)))
  Opcode.ADD, oprs

/// Immediate
let parseImm1000 b16 =
  Opcode.CMPEQ, TwoOperands(OpReg(Imm(getDisp8b b16)), OpReg(Regdir(R.R0)))

/// Immmediate
let parseImm1100 b16 =
  match getBits b16 12 9 with
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
  | _ ->
    raise ParsingFailureException

let parseNow b16 =
  match getBits b16 16 13 with
  | 0b0000us ->
    match getBits b16 4 1 with
    | 0b0111us | 0b0010us | 0b1010us ->
      twoOpParse0000 b16
    | 0b0011us ->
      match getBits b16 8 5 with
      | 0b0010us | 0b0000us -> parsePCReg0000 b16
      | _ -> parseRegInd0000 b16
    | 0b0100us | 0b0101us | 0b0110us | 0b1100us
    | 0b1101us | 0b1110us ->
      parseIdxInd0000 b16
    | 0b1111us ->
      parsePostInc0000 b16
    | 0b1001us ->
      oneOpParse0000 b16
    | _ ->
      noOpParse0000 b16
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
    | 0b0000us | 0b0001us | 0b0010us -> parseRegInd0110 b16
    | 0b0100us | 0b0101us | 0b0110us -> parsePostInc0110 b16
    | _ -> twoOpParse0110 b16
  | 0b0011us ->
    twoOpParse0011 b16
  | 0b1000us ->
    match getBits b16 12 9 with
    | 0b1011us | 0b1111us | 0b1001us | 0b1101us -> parsePC1000 b16
    | 0b1000us -> parseImm1000 b16
    | _ -> parseIndDisp1000 b16
  | 0b1001us ->
    parsePCDisp1001 b16
  | 0b1010us ->
    parsePC1010 b16
  | 0b1011us ->
    parsePC1011 b16
  | 0b1101us ->
    parsePCDisp1101 b16
  | 0b1110us ->
    parseImm1110 b16
  | 0b0111us ->
    parseImm0111 b16
  | 0b1100us ->
    if get1Bit b16 12 then
      match getBits b16 12 9 with
      | 0b1001us | 0b1011us | 0b1000us | 0b1010us -> parseImm1100 b16
      | _ -> parseIdxGBRInd1100 b16
    else
      if getBits b16 12 9 = 0b0111us then parsePCDisp1100 b16
      elif getBits b16 12 9 = 0b0011us then parseImm1100 b16
      else parseGBRIndDisp1100 b16
  | 0b0001us ->
    parseIndDisp0001 b16
  | 0b0101us ->
    parseIndDisp0101 b16
  | 0b1111us ->
    match getBits b16 4 1 with
    | 0b1000us | 0b1010us ->
      parseRegInd1111 b16
    | 0b0110us | 0b0111us ->
      parseIdxInd1111 b16
    | 0b1001us ->
      parsePostInc1111 b16
    | 0b1011us ->
      parsePreDec1111 b16
    | 0b1101us ->
      (* A low nibble of 1101 heads a whole family -- the conversions, the
         one-operand arithmetic, the immediate loads, and the vector
         instructions -- which the field above it tells apart. Reading that
         field only for the vector case left every other member of the family
         undecodable, and sent the two-register arithmetic whose source
         register happened to look like fabs's field to fabs. *)
      match getBits b16 8 5 with
      | 0b0100us | 0b0101us | 0b0110us ->
        oneOpParse1111 b16
      | 0b1000us | 0b1001us ->
        parseImm1111 b16
      | 0b1111us ->
        match getBits b16 12 9 with
        | 0b1011us | 0b0011us -> noOpParse1111 b16
        | _ -> twoOpParse1111 b16
      | _ ->
        twoOpParse1111 b16
    | _ ->
      twoOpParse1111 b16
  | _ ->
    Terminator.futureFeature ()

let parse lifter (span: ByteSpan) (reader: IBinReader) addr =
  let bin = reader.ReadUInt16(span, 0)
  let op, operands = parseNow bin
  Instruction(addr, 2u, op, operands, lifter)
