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

module internal B2R2.FrontEnd.PPC.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils

let getRegister (n: uint32) =
  match n with
  | 0u -> Register.R0
  | 1u -> Register.R1
  | 2u -> Register.R2
  | 3u -> Register.R3
  | 4u -> Register.R4
  | 5u -> Register.R5
  | 6u -> Register.R6
  | 7u -> Register.R7
  | 8u -> Register.R8
  | 9u -> Register.R9
  | 10u -> Register.R10
  | 11u -> Register.R11
  | 12u -> Register.R12
  | 13u -> Register.R13
  | 14u -> Register.R14
  | 15u -> Register.R15
  | 16u -> Register.R16
  | 17u -> Register.R17
  | 18u -> Register.R18
  | 19u -> Register.R19
  | 20u -> Register.R20
  | 21u -> Register.R21
  | 22u -> Register.R22
  | 23u -> Register.R23
  | 24u -> Register.R24
  | 25u -> Register.R25
  | 26u -> Register.R26
  | 27u -> Register.R27
  | 28u -> Register.R28
  | 29u -> Register.R29
  | 30u -> Register.R30
  | 31u -> Register.R31
  | _ -> Terminator.futureFeature ()

let extractAndErase (bin: uint32) ofs1 ofs2 =
  let v = Bits.extract bin ofs1 ofs2
  bin ^^^ (v <<< (min ofs1 ofs2 |> int)), v

let extractField (bin: uint32) (field: Field) =
  match field with
  | Fi.PO -> extractAndErase bin 31u 26u
  | Fi.RA -> extractAndErase bin 20u 16u
  | Fi.RB -> extractAndErase bin 15u 11u
  | Fi.RT -> extractAndErase bin 25u 21u
  | Fi.SI_D -> extractAndErase bin 15u 0u
  | Fi.DSPLIT ->
    let bin0, d0 = extractAndErase bin 15u 6u
    let bin1, d1 = extractAndErase bin0 20u 16u
    let bin2, d2 = extractAndErase bin1 0u 0u
    bin2, Bits.concat d0 (Bits.concat d1 d2 1) 6
  | Fi.CY -> extractAndErase bin 10u 9u
  | Fi.L_X_14_15 -> extractAndErase bin 17u 16u
  | Fi.XO_X_21_30 -> extractAndErase bin 10u 1u
  | Fi.XO_XO -> extractAndErase bin 9u 1u
  | Fi.XO_DX -> extractAndErase bin 5u 1u
  | Fi.XO_Z23 -> extractAndErase bin 8u 1u
  | Fi.XO_XL -> extractAndErase bin 10u 1u
  | Fi.OE -> extractAndErase bin 10u 10u
  | Fi.Rc_XO -> extractAndErase bin 0u 0u
  | Fi.LI -> extractAndErase bin 25u 2u
  | Fi.AA -> extractAndErase bin 1u 1u
  | Fi.LK -> extractAndErase bin 0u 0u
  | Fi.BO -> extractAndErase bin 25u 21u
  | Fi.BI -> extractAndErase bin 20u 16u
  | Fi.BD -> extractAndErase bin 15u 2u
  | Fi.BH -> extractAndErase bin 12u 11u
  | _ -> Terminator.futureFeature ()

let extractTwoFields (bin: uint32) f1 f2 =
  let bin0, _ = extractField bin Fi.PO
  let bin1, v1 = extractField bin0 f1
  let bin2, v2 = extractField bin1 f2
  if bin2 <> 0u then
    raise ParsingFailureException
  v1, v2

let extractThreeFields (bin: uint32) f1 f2 f3 =
  let bin0, _ = extractField bin Fi.PO
  let bin1, v1 = extractField bin0 f1
  let bin2, v2 = extractField bin1 f2
  let bin3, v3 = extractField bin2 f3
  if bin3 <> 0u then
    raise ParsingFailureException
  v1, v2, v3

let extractFourFields (bin: uint32) f1 f2 f3 f4 =
  let bin0, _ = extractField bin Fi.PO
  let bin1, v1 = extractField bin0 f1
  let bin2, v2 = extractField bin1 f2
  let bin3, v3 = extractField bin2 f3
  let bin4, v4 = extractField bin3 f4
  if bin4 <> 0u then
    raise ParsingFailureException
  v1, v2, v3, v4

let extractFiveFields (bin: uint32) f1 f2 f3 f4 f5 =
  let bin0, _ = extractField bin Fi.PO
  let bin1, v1 = extractField bin0 f1
  let bin2, v2 = extractField bin1 f2
  let bin3, v3 = extractField bin2 f3
  let bin4, v4 = extractField bin3 f4
  let bin5, v5 = extractField bin4 f5
  if bin5 <> 0u then
    raise ParsingFailureException
  v1, v2, v3, v4, v5

let extractSixFields (bin: uint32) f1 f2 f3 f4 f5 f6 =
  let bin0, _ = extractField bin Fi.PO
  let bin1, v1 = extractField bin0 f1
  let bin2, v2 = extractField bin1 f2
  let bin3, v3 = extractField bin2 f3
  let bin4, v4 = extractField bin3 f4
  let bin5, v5 = extractField bin4 f5
  let bin6, v6 = extractField bin5 f6
  if bin6 <> 0u then
    raise ParsingFailureException
  v1, v2, v3, v4, v5, v6

let getOprReg (fieldValue: uint32) =
  fieldValue |> getRegister |> OprReg

let getOprImm (fieldValue: uint32) =
  fieldValue |> uint64 |> OprImm

let getOprCY (fieldValue: uint32) =
  fieldValue |> uint8 |> OprCY

let getOprL (fieldValue: uint32) =
  fieldValue |> uint8 |> OprL

let getOprAddr (targetAddr: uint64) =
  targetAddr |> OprAddr

let getOprBO (fieldValue: uint32) =
  fieldValue |> uint8 |> OprBO

let getOprBI (fieldValue: uint32) =
  fieldValue |> uint8 |> OprBI

let getOprBH (fieldValue: uint32) =
  fieldValue |> uint8 |> OprBH

let getOpcodeExt19 (bin: uint32) =
  match Bits.extract bin 5u 1u with
  | 0b00010u -> Op.ADDPCIS
  | 0b10000u ->
    match Bits.extract bin 10u 6u with
    | 0b00000u ->
      if Bits.pick bin 0u = 0u then Op.BCLR else Op.BCLRL
    | 0b10000u ->
      if Bits.pick bin 0u = 0u then Op.BCCTR else Op.BCCTRL
    | 0b10001u ->
      if Bits.pick bin 0u = 0u then Op.BCTAR else Op.BCTARL
    | _ -> Terminator.futureFeature ()
  | _ -> Terminator.futureFeature ()

let getOpcodeExt31 (bin: uint32) =
  match Bits.extract bin 10u 1u with
  | 0b0100001010u ->
    if Bits.pick bin 0u = 0u then Op.ADD else Op.ADD_DOT
  | 0b1100001010u ->
    if Bits.pick bin 0u = 0u then Op.ADDO else Op.ADDO_DOT
  | 0b0000101000u ->
    if Bits.pick bin 0u = 0u then Op.SUBF else Op.SUBF_DOT
  | 0b1000101000u ->
    if Bits.pick bin 0u = 0u then Op.SUBFO else Op.SUBFO_DOT
  | 0b0000001010u ->
    if Bits.pick bin 0u = 0u then Op.ADDC else Op.ADDC_DOT
  | 0b1000001010u ->
    if Bits.pick bin 0u = 0u then Op.ADDCO else Op.ADDCO_DOT
  | 0b0000001000u ->
    if Bits.pick bin 0u = 0u then Op.SUBFC else Op.SUBFC_DOT
  | 0b1000001000u ->
    if Bits.pick bin 0u = 0u then Op.SUBFCO else Op.SUBFCO_DOT
  | 0b0010001010u ->
    if Bits.pick bin 0u = 0u then Op.ADDE else Op.ADDE_DOT
  | 0b1010001010u ->
    if Bits.pick bin 0u = 0u then Op.ADDEO else Op.ADDEO_DOT
  | 0b0010001000u ->
    if Bits.pick bin 0u = 0u then Op.SUBFE else Op.SUBFE_DOT
  | 0b1010001000u ->
    if Bits.pick bin 0u = 0u then Op.SUBFEO else Op.SUBFEO_DOT
  | 0b0011101010u ->
    if Bits.pick bin 0u = 0u then Op.ADDME else Op.ADDME_DOT
  | 0b1011101010u ->
    if Bits.pick bin 0u = 0u then Op.ADDMEO else Op.ADDMEO_DOT
  | 0b0011101000u ->
    if Bits.pick bin 0u = 0u then Op.SUBFME else Op.SUBFME_DOT
  | 0b1011101000u ->
    if Bits.pick bin 0u = 0u then Op.SUBFMEO else Op.SUBFMEO_DOT
  | 0b0010101010u -> Op.ADDEX
  | 0b0110101010u -> Op.ADDEX
  | 0b1010101010u -> Op.ADDEX
  | 0b1110101010u -> Op.ADDEX
  | 0b0011001000u ->
    if Bits.pick bin 0u = 0u then Op.SUBFZE else Op.SUBFZE_DOT
  | 0b1011001000u ->
    if Bits.pick bin 0u = 0u then Op.SUBFZEO else Op.SUBFZEO_DOT
  | 0b0011001010u ->
    if Bits.pick bin 0u = 0u then Op.ADDZE else Op.ADDZE_DOT
  | 0b1011001010u ->
    if Bits.pick bin 0u = 0u then Op.ADDZEO else Op.ADDZEO_DOT
  | 0b0001101000u ->
    if Bits.pick bin 0u = 0u then Op.NEG else Op.NEG_DOT
  | 0b1001101000u ->
    if Bits.pick bin 0u = 0u then Op.NEGO else Op.NEGO_DOT
  | 0b0001001011u ->
    if Bits.pick bin 0u = 0u then Op.MULHW else Op.MULHW_DOT
  | 0b1001001011u ->
    if Bits.pick bin 0u = 0u then Op.MULHW else Op.MULHW_DOT
  | 0b0011101011u ->
    if Bits.pick bin 0u = 0u then Op.MULLW else Op.MULLW_DOT
  | 0b1011101011u ->
    if Bits.pick bin 0u = 0u then Op.MULLWO else Op.MULLWO_DOT
  | 0b0000001011u ->
    if Bits.pick bin 0u = 0u then Op.MULHWU else Op.MULHWU_DOT
  | 0b1000001011u ->
    if Bits.pick bin 0u = 0u then Op.MULHWU else Op.MULHWU_DOT
  | 0b0111101011u ->
    if Bits.pick bin 0u = 0u then Op.DIVW else Op.DIVW_DOT
  | 0b1111101011u ->
    if Bits.pick bin 0u = 0u then Op.DIVWO else Op.DIVWO_DOT
  | 0b0111001011u ->
    if Bits.pick bin 0u = 0u then Op.DIVWU else Op.DIVWU_DOT
  | 0b1111001011u ->
    if Bits.pick bin 0u = 0u then Op.DIVWUO else Op.DIVWUO_DOT
  | 0b0110101011u ->
    if Bits.pick bin 0u = 0u then Op.DIVWE else Op.DIVWE_DOT
  | 0b1110101011u ->
    if Bits.pick bin 0u = 0u then Op.DIVWEO else Op.DIVWEO_DOT
  | 0b0110001011u ->
    if Bits.pick bin 0u = 0u then Op.DIVWEU else Op.DIVWEU_DOT
  | 0b1110001011u ->
    if Bits.pick bin 0u = 0u then Op.DIVWEUO else Op.DIVWEUO_DOT
  | 0b1100001011u -> Op.MODSW
  | 0b100001011u -> Op.MODUW
  | 0b1011110011u -> Op.DARN
  | _ -> Terminator.futureFeature ()

let getOpcode (bin: uint32) =
  match Bits.extract bin 31u 26u with
  | 0b000111u -> Op.MULLI
  | 0b001000u -> Op.SUBFIC
  | 0b001100u -> Op.ADDIC
  | 0b001101u -> Op.ADDIC_DOT
  | 0b001110u -> Op.ADDI
  | 0b001111u -> Op.ADDIS
  | 0b010000u ->
    match Bits.pick bin 1u, Bits.pick bin 0u with
    | 0u, 0u -> Op.BC
    | 1u, 0u -> Op.BCA
    | 0u, 1u -> Op.BCL
    | 1u, 1u -> Op.BCLA
    | _ ->  raise ParsingFailureException
  | 0b010010u ->
    match Bits.pick bin 1u, Bits.pick bin 0u with
    | 0u, 0u -> Op.B
    | 1u, 0u -> Op.BA
    | 0u, 1u -> Op.BL
    | 1u, 1u -> Op.BLA
    | _ ->  raise ParsingFailureException
  | 0b010011u -> getOpcodeExt19 bin
  | 0b011111u -> getOpcodeExt31 bin
  | _ -> Terminator.futureFeature ()

let getOperands (opcode: Opcode) (bin: uint32) (addr: Addr) =
  match opcode with
  | Op.ADDI
  | Op.ADDIS
  | Op.ADDIC | Op.ADDIC_DOT ->
    let rt, ra, si =
      extractThreeFields bin Fi.RT Fi.RA Fi.SI_D
    ThreeOperands(getOprReg rt, getOprReg ra, getOprImm si)
  | Op.SUBFIC ->
    let rt, ra, si =
      extractThreeFields bin Fi.RT Fi.RA Fi.SI_D
    ThreeOperands(getOprReg rt, getOprReg ra, getOprImm si)
  | Op.ADDPCIS ->
    let rt, d, _ =
      extractThreeFields bin Fi.RT Fi.DSPLIT Fi.XO_DX
    TwoOperands(getOprReg rt, getOprImm d)
  | Op.ADD | Op.ADD_DOT | Op.ADDO | Op.ADDO_DOT
  | Op.ADDC | Op.ADDC_DOT | Op.ADDCO | Op.ADDCO_DOT
  | Op.ADDE | Op.ADDE_DOT | Op.ADDEO | Op.ADDEO_DOT ->
    let rt, ra, rb, _, _, _ =
      extractSixFields bin Fi.RT Fi.RA Fi.RB Fi.OE Fi.XO_XO Fi.Rc_XO
    ThreeOperands(getOprReg rt, getOprReg ra, getOprReg rb)
  | Op.SUBF | Op.SUBF_DOT | Op.SUBFO | Op.SUBFO_DOT
  | Op.SUBFC | Op.SUBFC_DOT | Op.SUBFCO | Op.SUBFCO_DOT
  | Op.SUBFE | Op.SUBFE_DOT | Op.SUBFEO | Op.SUBFEO_DOT ->
    let rt, ra, rb, _, _, _ =
      extractSixFields bin Fi.RT Fi.RA Fi.RB Fi.OE Fi.XO_XO Fi.Rc_XO
    ThreeOperands(getOprReg rt, getOprReg ra, getOprReg rb)
  | Op.ADDME | Op.ADDME_DOT | Op.ADDMEO | Op.ADDMEO_DOT ->
    let rt, ra, _, _, _ =
      extractFiveFields bin Fi.RT Fi.RA Fi.OE Fi.XO_XO Fi.Rc_XO
    TwoOperands(getOprReg rt, getOprReg ra)
  | Op.SUBFME | Op.SUBFME_DOT | Op.SUBFMEO | Op.SUBFMEO_DOT ->
    let rt, ra, _, _, _ =
      extractFiveFields bin Fi.RT Fi.RA Fi.OE Fi.XO_XO Fi.Rc_XO
    TwoOperands(getOprReg rt, getOprReg ra)
  | Op.ADDEX ->
    let rt, ra, rb, cy, _ =
      extractFiveFields bin Fi.RT Fi.RA Fi.RB Fi.CY Fi.XO_Z23
    FourOperands(getOprReg rt, getOprReg ra, getOprReg rb, getOprCY cy)
  | Op.ADDZE | Op.ADDZE_DOT | Op.ADDZEO | Op.ADDZEO_DOT ->
    let rt, ra, _, _, _ =
      extractFiveFields bin Fi.RT Fi.RA Fi.OE Fi.XO_XO Fi.Rc_XO
    TwoOperands(getOprReg rt, getOprReg ra)
  | Op.SUBFZE | Op.SUBFZE_DOT | Op.SUBFZEO | Op.SUBFZEO_DOT ->
    let rt, ra, _, _, _ =
      extractFiveFields bin Fi.RT Fi.RA Fi.OE Fi.XO_XO Fi.Rc_XO
    TwoOperands(getOprReg rt, getOprReg ra)
  | Op.NEG | Op.NEG_DOT | Op.NEGO | Op.NEGO_DOT ->
    let rt, ra, _, _, _ =
      extractFiveFields bin Fi.RT Fi.RA Fi.OE Fi.XO_XO Fi.Rc_XO
    TwoOperands(getOprReg rt, getOprReg ra)
  | Op.MULLI ->
    let rt, ra, si =
      extractThreeFields bin Fi.RT Fi.RA Fi.SI_D
    ThreeOperands(getOprReg rt, getOprReg ra, getOprImm si)
  | Op.MULHW | Op.MULHW_DOT
  | Op.MULHWU | Op.MULHWU_DOT ->
    let rt, ra, rb, _, _ =
      extractFiveFields bin Fi.RT Fi.RA Fi.RB Fi.XO_XO Fi.Rc_XO
    ThreeOperands(getOprReg rt, getOprReg ra, getOprReg rb)
  | Op.MULLW | Op.MULLW_DOT | Op.MULLWO | Op.MULLWO_DOT ->
    let rt, ra, rb, _, _, _ =
      extractSixFields bin Fi.RT Fi.RA Fi.RB Fi.OE Fi.XO_XO Fi.Rc_XO
    ThreeOperands(getOprReg rt, getOprReg ra, getOprReg rb)
  | Op.DIVW | Op.DIVW_DOT | Op.DIVWO | Op.DIVWO_DOT
  | Op.DIVWU | Op.DIVWU_DOT | Op.DIVWUO | Op.DIVWUO_DOT
  | Op.DIVWE | Op.DIVWE_DOT | Op.DIVWEO | Op.DIVWEO_DOT
  | Op.DIVWEU | Op.DIVWEU_DOT | Op.DIVWEUO | Op.DIVWEUO_DOT ->
    let rt, ra, rb, _, _, _ =
      extractSixFields bin Fi.RT Fi.RA Fi.RB Fi.OE Fi.XO_XO Fi.Rc_XO
    ThreeOperands(getOprReg rt, getOprReg ra, getOprReg rb)
  | Op.MODSW
  | Op.MODUW ->
    let rt, ra, rb, _ =
      extractFourFields bin Fi.RT Fi.RA Fi.RB Fi.XO_X_21_30
    ThreeOperands(getOprReg rt, getOprReg ra, getOprReg rb)
  | Op.DARN ->
    let rt, l, _ =
      extractThreeFields bin Fi.RT Fi.L_X_14_15 Fi.XO_X_21_30
    TwoOperands(getOprReg rt, getOprL l)
  | Op.B | Op.BL ->
    let li, _, _ =
      extractThreeFields bin Fi.LI Fi.AA Fi.LK
    let targetAddr = addr + Bits.signExtend 26 64 (li |> uint64 <<< 2)
    OneOperand(getOprAddr targetAddr)
  | Op.BA | Op.BLA ->
    let li, _, _ =
      extractThreeFields bin Fi.LI Fi.AA Fi.LK
    let targetAddr = Bits.signExtend 26 64 (li |> uint64 <<< 2)
    OneOperand(getOprAddr targetAddr)
  | Op.BC | Op.BCL ->
    let bo, bi, bd, _, _ =
      extractFiveFields bin Fi.BO Fi.BI Fi.BD Fi.AA Fi.LK
    let targetAddr = addr + Bits.signExtend 16 64 (bd |> uint64 <<< 2)
    ThreeOperands(getOprBO bo, getOprBI bi, getOprAddr targetAddr)
  | Op.BCA | Op.BCLA ->
    let bo, bi, bd, _, _ =
      extractFiveFields bin Fi.BO Fi.BI Fi.BD Fi.AA Fi.LK
    let targetAddr = Bits.signExtend 16 64 (bd |> uint64 <<< 2)
    ThreeOperands(getOprBO bo, getOprBI bi, getOprAddr targetAddr)
  | Op.BCLR | Op.BCLRL
  | Op.BCCTR | Op.BCCTRL
  | Op.BCTAR | Op.BCTARL ->
    let bo, bi, bh, _, _ =
      extractFiveFields bin Fi.BO Fi.BI Fi.BH Fi.XO_XL Fi.LK
    ThreeOperands(getOprBO bo, getOprBI bi, getOprBH bh)
  | _ -> Terminator.futureFeature ()

let parseInstruction (bin: uint32) (addr: Addr) =
  let opcode = getOpcode bin
  let operands = getOperands opcode bin addr
  struct (opcode, operands)

let parse lifter (span: ByteSpan) (reader: IBinReader) (addr: Addr) =
  let bin = reader.ReadUInt32(span, 0)
  let struct (opcode, operands) = parseInstruction bin addr
  Instruction(addr, 4u, opcode, operands, 64<rt>, 0UL, lifter)
