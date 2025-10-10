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
  n |> int |> LanguagePrimitives.EnumOfValue

let getOprReg (reg: uint32) =
  reg |> getRegister |> OprReg

let getOprImm (imm: uint32) =
  imm |> uint64 |> OprImm

let getOprCY (cy: uint32) =
  cy |> uint8 |> OprCY

let getOprL (l: uint32) =
  l |> uint8 |> OprL

let getOprAddr (targetAddr: uint64) =
  targetAddr |> OprAddr

let getOprBO (bo: uint32) =
  bo |> uint8 |> OprBO

let getOprBI (bi: uint32) =
  bi |> uint8 |> OprBI

let getOprBH (bh: uint32) =
  bh |> uint8 |> OprBH

let getOprMem (disp: uint64) (reg: uint32) =
  OprMem(disp |> int64, reg |> getRegister)

let checkIfZero (fieldValue: uint32) =
  if fieldValue <> 0u then raise ParsingFailureException

let extractExtendedField (bin: uint32) ofs1 ofs2 shift =
  let v = Bits.extract bin ofs1 ofs2
  let sz = (max ofs1 ofs2 - min ofs1 ofs2 + 1u |> int) + shift
  Bits.signExtend sz 64 (v |> uint64 <<< shift)

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
  | 0b0100001011u -> Op.MODUW
  | 0b1011110011u -> Op.DARN
  | 0b0001010111u -> Op.LBZX
  | 0b0001110111u -> Op.LBZUX
  | 0b0100010111u -> Op.LHZX
  | 0b0100110111u -> Op.LHZUX
  | 0b0101010111u -> Op.LHAX
  | 0b0101110111u -> Op.LHAUX
  | 0b0000010111u -> Op.LWZX
  | 0b0000110111u -> Op.LWZUX
  | 0b0101010101u -> Op.LWAX
  | 0b0101110101u -> Op.LWAUX
  | 0b0000010101u -> Op.LDX
  | 0b0000110101u -> Op.LDUX
  | 0b0011010111u -> Op.STBX
  | 0b0011110111u -> Op.STBUX
  | 0b0110010111u -> Op.STHX
  | 0b0110110111u -> Op.STHUX
  | 0b0010010111u -> Op.STWX
  | 0b0010110111u -> Op.STWUX
  | 0b0010010101u -> Op.STDX
  | 0b0010110101u -> Op.STDUX
  | 0b1100010110u -> Op.LHBRX
  | 0b1110010110u -> Op.STHBRX
  | 0b1000010110u -> Op.LWBRX
  | 0b1010010110u -> Op.STWBRX
  | 0b1000010100u -> Op.LDBRX
  | 0b1010010100u -> Op.STDBRX
  | 0b1001010101u -> Op.LSWI
  | 0b1000010101u -> Op.LSWX
  | 0b1011010101u -> Op.STSWI
  | 0b1010010101u -> Op.STSWX
  | _ -> Terminator.futureFeature ()

let getOpcodeExt58 (bin: uint32) =
  match Bits.extract bin 1u 0u with
  | 0b00u -> Op.LD
  | 0b01u -> Op.LDU
  | 0b10u -> Op.LWA
  | _ -> Terminator.futureFeature ()

let getOpcodeExt62 (bin: uint32) =
  match Bits.extract bin 1u 0u with
  | 0b00u -> Op.STD
  | 0b01u -> Op.STDU
  | 0b10u -> Op.STQ
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
  | 0b100010u -> Op.LBZ
  | 0b100011u -> Op.LBZU
  | 0b101000u -> Op.LHZ
  | 0b101001u -> Op.LHZU
  | 0b101010u -> Op.LHA
  | 0b101011u -> Op.LHAU
  | 0b100000u -> Op.LWZ
  | 0b100001u -> Op.LWZU
  | 0b111010u -> getOpcodeExt58 bin
  | 0b100110u -> Op.STB
  | 0b100111u -> Op.STBU
  | 0b101100u -> Op.STH
  | 0b101101u -> Op.STHU
  | 0b100100u -> Op.STW
  | 0b100101u -> Op.STWU
  | 0b111110u -> getOpcodeExt62 bin
  | 0b111000u -> Op.LQ
  | 0b101110u -> Op.LMW
  | 0b101111u -> Op.STMW
  | _ -> Terminator.futureFeature ()

let getOperands (opcode: Opcode) (bin: uint32) (addr: Addr) =
  match opcode with
  | Op.ADDI
  | Op.ADDIS
  | Op.ADDIC | Op.ADDIC_DOT ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let si = Bits.extract bin 15u 0u |> getOprImm
    ThreeOperands(rt, ra, si)
  | Op.SUBFIC ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let si = Bits.extract bin 15u 0u |> getOprImm
    ThreeOperands(rt, ra, si)
  | Op.ADDPCIS ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let d0 = Bits.extract bin 15u 6u
    let d1 = Bits.extract bin 20u 16u
    let d2 = Bits.pick bin 0u
    let d = Bits.concat d0 (Bits.concat d1 d2 1) 6 |> getOprImm
    TwoOperands(rt, d)
  | Op.ADD | Op.ADD_DOT | Op.ADDO | Op.ADDO_DOT
  | Op.ADDC | Op.ADDC_DOT | Op.ADDCO | Op.ADDCO_DOT
  | Op.ADDE | Op.ADDE_DOT | Op.ADDEO | Op.ADDEO_DOT ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    ThreeOperands(rt, ra, rb)
  | Op.SUBF | Op.SUBF_DOT | Op.SUBFO | Op.SUBFO_DOT
  | Op.SUBFC | Op.SUBFC_DOT | Op.SUBFCO | Op.SUBFCO_DOT
  | Op.SUBFE | Op.SUBFE_DOT | Op.SUBFEO | Op.SUBFEO_DOT ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    ThreeOperands(rt, ra, rb)
  | Op.ADDME | Op.ADDME_DOT | Op.ADDMEO | Op.ADDMEO_DOT ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    Bits.extract bin 15u 11u |> checkIfZero
    TwoOperands(rt, ra)
  | Op.SUBFME | Op.SUBFME_DOT | Op.SUBFMEO | Op.SUBFMEO_DOT ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    Bits.extract bin 15u 11u |> checkIfZero
    TwoOperands(rt, ra)
  | Op.ADDEX ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    let cy = Bits.extract bin 10u 9u |> getOprCY
    Bits.pick bin 0u |> checkIfZero
    FourOperands(rt, ra, rb, cy)
  | Op.ADDZE | Op.ADDZE_DOT | Op.ADDZEO | Op.ADDZEO_DOT ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    Bits.extract bin 15u 11u |> checkIfZero
    TwoOperands(rt, ra)
  | Op.SUBFZE | Op.SUBFZE_DOT | Op.SUBFZEO | Op.SUBFZEO_DOT ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    Bits.extract bin 15u 11u |> checkIfZero
    TwoOperands(rt, ra)
  | Op.NEG | Op.NEG_DOT | Op.NEGO | Op.NEGO_DOT ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    Bits.extract bin 15u 11u |> checkIfZero
    TwoOperands(rt, ra)
  | Op.MULLI ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let si = Bits.extract bin 15u 0u |> getOprImm
    ThreeOperands(rt, ra, si)
  | Op.MULHW | Op.MULHW_DOT
  | Op.MULHWU | Op.MULHWU_DOT ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    Bits.extract bin 10u 10u |> checkIfZero
    ThreeOperands(rt, ra, rb)
  | Op.MULLW | Op.MULLW_DOT | Op.MULLWO | Op.MULLWO_DOT ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    ThreeOperands(rt, ra, rb)
  | Op.DIVW | Op.DIVW_DOT | Op.DIVWO | Op.DIVWO_DOT
  | Op.DIVWU | Op.DIVWU_DOT | Op.DIVWUO | Op.DIVWUO_DOT
  | Op.DIVWE | Op.DIVWE_DOT | Op.DIVWEO | Op.DIVWEO_DOT
  | Op.DIVWEU | Op.DIVWEU_DOT | Op.DIVWEUO | Op.DIVWEUO_DOT ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    ThreeOperands(rt, ra, rb)
  | Op.MODSW
  | Op.MODUW ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    Bits.pick bin 0u |> checkIfZero
    ThreeOperands(rt, ra, rb)
  | Op.DARN ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    Bits.extract bin 20u 18u |> checkIfZero
    let l = Bits.extract bin 17u 16u |> getOprL
    Bits.extract bin 15u 11u |> checkIfZero
    Bits.pick bin 0u |> checkIfZero
    TwoOperands(rt, l)
  | Op.B | Op.BL ->
    let targetAddr = addr + extractExtendedField bin 25u 2u 2 |> getOprAddr
    OneOperand(targetAddr)
  | Op.BA | Op.BLA ->
    let targetAddr = extractExtendedField bin 25u 2u 2 |> getOprAddr
    OneOperand(targetAddr)
  | Op.BC | Op.BCL ->
    let bo = Bits.extract bin 25u 21u |> getOprBO
    let bi = Bits.extract bin 20u 16u |> getOprBI
    let targetAddr = addr + extractExtendedField bin 15u 2u 2 |> getOprAddr
    ThreeOperands(bo, bi, targetAddr)
  | Op.BCA | Op.BCLA ->
    let bo = Bits.extract bin 25u 21u |> getOprBO
    let bi = Bits.extract bin 20u 16u |> getOprBI
    let targetAddr = extractExtendedField bin 15u 2u 2 |> getOprAddr
    ThreeOperands(bo, bi, targetAddr)
  | Op.BCLR | Op.BCLRL
  | Op.BCCTR | Op.BCCTRL
  | Op.BCTAR | Op.BCTARL ->
    let bo = Bits.extract bin 25u 21u |> getOprBO
    let bi = Bits.extract bin 20u 16u |> getOprBI
    Bits.extract bin 15u 13u |> checkIfZero
    let bh = Bits.extract bin 12u 11u |> getOprBH
    ThreeOperands(bo, bi, bh)
  | Op.LBZ | Op.LBZU
  | Op.LHZ | Op.LHZU
  | Op.LHA | Op.LHAU
  | Op.LWZ | Op.LWZU ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    TwoOperands(rt, getOprMem d ra)
  | Op.LBZX | Op.LBZUX
  | Op.LHZX | Op.LHZUX
  | Op.LHAX | Op.LHAUX
  | Op.LWZX | Op.LWZUX
  | Op.LWAX | Op.LWAUX
  | Op.LDX | Op.LDUX ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    Bits.pick bin 0u |> checkIfZero
    ThreeOperands(rt, ra, rb)
  | Op.LWA
  | Op.LD | Op.LDU ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    TwoOperands(rt, getOprMem ds ra)
  | Op.STB | Op.STBU
  | Op.STH | Op.STHU
  | Op.STW | Op.STWU ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    TwoOperands(rt, getOprMem d ra)
  | Op.STBX | Op.STBUX
  | Op.STHX | Op.STHUX
  | Op.STWX | Op.STWUX
  | Op.STDX | Op.STDUX ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    Bits.pick bin 0u |> checkIfZero
    ThreeOperands(rt, ra, rb)
  | Op.STD | Op.STDU ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    TwoOperands(rt, getOprMem ds ra)
  | Op.LQ ->
    let rtp = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let dq = extractExtendedField bin 15u 4u 4
    Bits.extract bin 3u 0u |> checkIfZero
    TwoOperands(rtp, getOprMem dq ra)
  | Op.STQ ->
    let rsp = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    TwoOperands(rsp, getOprMem ds ra)
  | Op.LHBRX | Op.LWBRX | Op.LDBRX
  | Op.STHBRX | Op.STWBRX | Op.STDBRX ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    Bits.pick bin 0u |> checkIfZero
    ThreeOperands(rt, ra, rb)
  | Op.LMW
  | Op.STMW ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    TwoOperands(rt, getOprMem d ra)
  | Op.LSWI
  | Op.STSWI ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let nb = Bits.extract bin 15u 11u |> getOprReg
    Bits.pick bin 0u |> checkIfZero
    ThreeOperands(rt, ra, nb)
  | Op.LSWX
  | Op.STSWX ->
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    Bits.pick bin 0u |> checkIfZero
    ThreeOperands(rt, ra, rb)
  | _ -> Terminator.futureFeature ()

let parseInstruction (bin: uint32) (addr: Addr) =
  let opcode = getOpcode bin
  let operands = getOperands opcode bin addr
  struct (opcode, operands)

let parse lifter (span: ByteSpan) (reader: IBinReader) (addr: Addr) =
  let bin = reader.ReadUInt32(span, 0)
  let struct (opcode, operands) = parseInstruction bin addr
  Instruction(addr, 4u, opcode, operands, 64<rt>, 0UL, lifter)
