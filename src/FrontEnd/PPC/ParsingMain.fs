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

let getFPRegister (n: uint32) =
  0x20u + n |> int |> LanguagePrimitives.EnumOfValue

let getVRegister (n: uint32) =
  0x40u + n |> int |> LanguagePrimitives.EnumOfValue

let getVSRegister (n: uint32) =
  0x60u + n |> int |> LanguagePrimitives.EnumOfValue

let getCondRegister (n: uint32) =
  0xA0u + n |> int |> LanguagePrimitives.EnumOfValue

let getCondBitRegister (n: uint32) =
  0xA8u + n |> int |> LanguagePrimitives.EnumOfValue

let getFPSCondRegister (n: uint32) =
  0xC8u + n |> int |> LanguagePrimitives.EnumOfValue

let getFPSCondBitRegister (n: uint32) =
  0xD0u + n |> int |> LanguagePrimitives.EnumOfValue

let getSPRegister (n: uint32) =
  match n with
  | 0b0000000001u -> Register.XER
  | 0b0000000011u -> Register.DSCR
  | 0b0000001000u -> Register.LR
  | 0b0000001001u -> Register.CTR
  | 0b0000001101u -> Register.AMR
  | 0b0000010001u -> Register.DSCR
  | 0b0000010010u -> Register.DSISR
  | 0b0000010011u -> Register.DAR
  | 0b0000010110u -> Register.DEC
  | 0b0000011010u -> Register.SRR0
  | 0b0000011011u -> Register.SRR1
  | 0b0000011100u -> Register.CFAR
  | 0b0000011101u -> Register.AMR
  | 0b0000110000u -> Register.PIDR
  | 0b0000111101u -> Register.IAMR
  | 0b0010000000u -> Register.TFHAR
  | 0b0010000001u -> Register.TFIAR
  | 0b0010000010u -> Register.TEXASR
  | 0b0010000011u -> Register.TEXASRU
  | 0b0010001000u -> Register.CTRL
  | 0b0010010000u -> Register.TIDR
  | 0b0010011000u -> Register.CTRL
  | 0b0010011001u -> Register.FSCR
  | 0b0010011101u -> Register.UAMOR
  | 0b0010011110u -> Register.NA
  | 0b0010011111u -> Register.PSPB
  | 0b0010110000u -> Register.DPDES
  | 0b0010110100u -> Register.DAWR0
  | 0b0010111010u -> Register.RPR
  | 0b0010111011u -> Register.CIABR
  | 0b0010111100u -> Register.DAWRX0
  | 0b0010111110u -> Register.HFSCR
  | 0b0100000000u -> Register.VRSAVE
  | 0b0100000011u -> Register.SPRG3
  | 0b0100001100u -> Register.TB
  | 0b0100001101u -> Register.TBU
  | 0b0100010000u -> Register.SPRG0
  | 0b0100010001u -> Register.SPRG1
  | 0b0100010010u -> Register.SPRG2
  | 0b0100010011u -> Register.SPRG3
  | 0b0100011011u -> Register.CIR
  | 0b0100011100u -> Register.TBL
  | 0b0100011101u -> Register.TBU
  | 0b0100011110u -> Register.TBU40
  | 0b0100011111u -> Register.PVR
  | 0b0100110000u -> Register.HSPRG0
  | 0b0100110001u -> Register.HSPRG1
  | 0b0100110010u -> Register.HDSISR
  | 0b0100110011u -> Register.HDAR
  | 0b0100110100u -> Register.SPURR
  | 0b0100110101u -> Register.PURR
  | 0b0100110110u -> Register.HDEC
  | 0b0100111001u -> Register.HRMOR
  | 0b0100111010u -> Register.HSRR0
  | 0b0100111011u -> Register.HSRR1
  | 0b0100111110u -> Register.LPCR
  | 0b0100111111u -> Register.LPIDR
  | 0b0101010000u -> Register.HMER
  | 0b0101010001u -> Register.HMEER
  | 0b0101010010u -> Register.PCR
  | 0b0101010011u -> Register.HEIR
  | 0b0101011101u -> Register.AMOR
  | 0b0110111110u -> Register.TIR
  | 0b0111010000u -> Register.PTCR
  | 0b0111110000u -> Register.USPRG0
  | 0b0111110001u -> Register.USPRG1
  | 0b0111111001u -> Register.URMOR
  | 0b0111111010u -> Register.USRR0
  | 0b0111111011u -> Register.USRR1
  | 0b0111111111u -> Register.SMFCTRL
  | 0b1100000000u -> Register.SIER
  | 0b1100000001u -> Register.MMCR2
  | 0b1100000010u -> Register.MMCRA
  | 0b1100000011u -> Register.PMC1
  | 0b1100000100u -> Register.PMC2
  | 0b1100000101u -> Register.PMC3
  | 0b1100000110u -> Register.PMC4
  | 0b1100000111u -> Register.PMC5
  | 0b1100001000u -> Register.PMC6
  | 0b1100001011u -> Register.MMCR0
  | 0b1100001100u -> Register.SIAR
  | 0b1100001101u -> Register.SDAR
  | 0b1100001110u -> Register.MMCR1
  | 0b1100010000u -> Register.SIER
  | 0b1100010001u -> Register.MMCR2
  | 0b1100010010u -> Register.MMCRA
  | 0b1100010011u -> Register.PMC1
  | 0b1100010100u -> Register.PMC2
  | 0b1100010101u -> Register.PMC3
  | 0b1100010110u -> Register.PMC4
  | 0b1100010111u -> Register.PMC5
  | 0b1100011000u -> Register.PMC6
  | 0b1100011011u -> Register.MMCR0
  | 0b1100011100u -> Register.SIAR
  | 0b1100011101u -> Register.SDAR
  | 0b1100011110u -> Register.MMCR1
  | 0b1100100000u -> Register.BESCRS
  | 0b1100100001u -> Register.BESCRSU
  | 0b1100100010u -> Register.BESCRR
  | 0b1100100011u -> Register.BESCRRU
  | 0b1100100100u -> Register.EBBHR
  | 0b1100100101u -> Register.EBBRR
  | 0b1100100110u -> Register.BESCR
  | 0b1100101000u -> Register.ReservedSPR
  | 0b1100101001u -> Register.ReservedSPR
  | 0b1100101010u -> Register.ReservedSPR
  | 0b1100101011u -> Register.ReservedSPR
  | 0b1100101110u -> Register.TAR
  | 0b1100110000u -> Register.ASDR
  | 0b1100110111u -> Register.PSSCR
  | 0b1101010000u -> Register.IC
  | 0b1101010001u -> Register.VTB
  | 0b1101010111u -> Register.PSSCR
  | 0b1110000000u -> Register.PPR
  | 0b1110000010u -> Register.PPR32
  | 0b1111111111u -> Register.PIR
  | _ -> Register.ReservedSPR

let getOprReg (reg: uint32) =
  reg |> getRegister |> OprReg

let getOprFPReg (reg: uint32) =
  reg |> getFPRegister |> OprReg

let getOprVReg (reg: uint32) =
  reg |> getVRegister |> OprReg

let getOprVSReg (reg: uint32) =
  reg |> getVSRegister |> OprReg

let getOprCondReg (reg: uint32) =
  reg |> getCondRegister |> OprReg

let getOprCondBitReg (reg: uint32) =
  reg |> getCondBitRegister |> OprReg

let getOprFPSCondReg (reg: uint32) =
  reg |> getFPSCondRegister |> OprReg

let getOprFPSCondBitReg (reg: uint32) =
  reg |> getFPSCondBitRegister |> OprReg

let getOprSPReg (reg: uint32) =
  reg |> getSPRegister |> OprReg

let getOprImm (imm: uint32) =
  imm |> uint64 |> OprImm

let getOprImm64 (imm: uint64) =
  imm |> OprImm

let getOprCY (cy: uint32) =
  cy |> uint8 |> OprCY

let getOprL (l: uint32) =
  l |> uint8 |> OprL

let getOprAddr (targetAddr: uint64) =
  targetAddr |> OprAddr

let getOprBO (bo: uint32) =
  bo |> uint8 |> OprBO

let getOprBH (bh: uint32) =
  bh |> uint8 |> OprBH

let getOprTO (toValue: uint32) =
  toValue |> uint8 |> OprTO

let getOprCRMask (mask: uint32) =
  mask |> uint8 |> OprCRMask

let getOprFPSCRMask (mask: uint32) =
  mask |> uint8 |> OprFPSCRMask

let getOprW (w: uint32) =
  w |> uint8 |> OprW

let getOprDCM (dcm: uint32) =
  dcm |> uint8 |> OprDCM

let getOprDGM (dgm: uint32) =
  dgm |> uint8 |> OprDGM

let getOprMem (disp: uint64) (reg: uint32) =
  OprMem(disp |> int64, reg |> getRegister)

let extractExtendedField (bin: uint32) ofs1 ofs2 shift =
  let v = Bits.extract bin ofs1 ofs2
  let sz = (max ofs1 ofs2 - min ofs1 ofs2 + 1u |> int) + shift
  Bits.signExtend sz 64 (v |> uint64 <<< shift)

let parseInstruction (bin: uint32) (addr: Addr) =
  match bin with
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1001000000000000000000000000000u ->
    let opcode = Opcode.B
    let targetaddrOpr = extractExtendedField bin 25u 2u 2 |> getOprAddr
    struct (opcode, OneOperand(targetaddrOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1001000000000000000000000000010u ->
    let opcode = Opcode.BA
    let targetaddrOpr = extractExtendedField bin 25u 2u 2 |> getOprAddr
    struct (opcode, OneOperand(targetaddrOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1001000000000000000000000000001u ->
    let opcode = Opcode.BL
    let targetaddrOpr = extractExtendedField bin 25u 2u 2 |> getOprAddr
    struct (opcode, OneOperand(targetaddrOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1001000000000000000000000000011u ->
    let opcode = Opcode.BLA
    let targetaddrOpr = extractExtendedField bin 25u 2u 2 |> getOprAddr
    struct (opcode, OneOperand(targetaddrOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1000000000000000000000000000000u ->
    let opcode = Opcode.BC
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let targetaddrOpr = extractExtendedField bin 15u 2u 2 |> getOprAddr
    struct (opcode, ThreeOperands(boOpr, biOpr, targetaddrOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1000000000000000000000000000010u ->
    let opcode = Opcode.BCA
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let targetaddrOpr = extractExtendedField bin 15u 2u 2 |> getOprAddr
    struct (opcode, ThreeOperands(boOpr, biOpr, targetaddrOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1000000000000000000000000000001u ->
    let opcode = Opcode.BCL
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let targetaddrOpr = extractExtendedField bin 15u 2u 2 |> getOprAddr
    struct (opcode, ThreeOperands(boOpr, biOpr, targetaddrOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1000000000000000000000000000011u ->
    let opcode = Opcode.BCLA
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let targetaddrOpr = extractExtendedField bin 15u 2u 2 |> getOprAddr
    struct (opcode, ThreeOperands(boOpr, biOpr, targetaddrOpr))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000000000100000u ->
    let opcode = Opcode.BCLR
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bhOpr = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(boOpr, biOpr, bhOpr))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000000000100001u ->
    let opcode = Opcode.BCLRL
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bhOpr = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(boOpr, biOpr, bhOpr))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000010000100000u ->
    let opcode = Opcode.BCCTR
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bhOpr = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(boOpr, biOpr, bhOpr))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000010000100001u ->
    let opcode = Opcode.BCCTRL
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bhOpr = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(boOpr, biOpr, bhOpr))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000010001100000u ->
    let opcode = Opcode.BCTAR
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bhOpr = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(boOpr, biOpr, bhOpr))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000010001100001u ->
    let opcode = Opcode.BCTARL
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bhOpr = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(boOpr, biOpr, bhOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1001100000000000000001000000010u ->
    let opcode = Opcode.CRAND
    let btOpr = Bits.extract bin 25u 21u |> getOprCondBitReg
    let baOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bbOpr = Bits.extract bin 15u 11u |> getOprCondBitReg
    struct (opcode, ThreeOperands(btOpr, baOpr, bbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1001100000000000000001110000010u ->
    let opcode = Opcode.CROR
    let btOpr = Bits.extract bin 25u 21u |> getOprCondBitReg
    let baOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bbOpr = Bits.extract bin 15u 11u |> getOprCondBitReg
    struct (opcode, ThreeOperands(btOpr, baOpr, bbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1001100000000000000000111000010u ->
    let opcode = Opcode.CRNAND
    let btOpr = Bits.extract bin 25u 21u |> getOprCondBitReg
    let baOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bbOpr = Bits.extract bin 15u 11u |> getOprCondBitReg
    struct (opcode, ThreeOperands(btOpr, baOpr, bbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1001100000000000000000110000010u ->
    let opcode = Opcode.CRXOR
    let btOpr = Bits.extract bin 25u 21u |> getOprCondBitReg
    let baOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bbOpr = Bits.extract bin 15u 11u |> getOprCondBitReg
    struct (opcode, ThreeOperands(btOpr, baOpr, bbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1001100000000000000000001000010u ->
    let opcode = Opcode.CRNOR
    let btOpr = Bits.extract bin 25u 21u |> getOprCondBitReg
    let baOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bbOpr = Bits.extract bin 15u 11u |> getOprCondBitReg
    struct (opcode, ThreeOperands(btOpr, baOpr, bbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1001100000000000000000100000010u ->
    let opcode = Opcode.CRANDC
    let btOpr = Bits.extract bin 25u 21u |> getOprCondBitReg
    let baOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bbOpr = Bits.extract bin 15u 11u |> getOprCondBitReg
    struct (opcode, ThreeOperands(btOpr, baOpr, bbOpr))
  | b when b &&&
    0b11111100011000111111111111111111u = 0b1001100000000000000000000000000u ->
    let opcode = Opcode.MCRF
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let bfaOpr = Bits.extract bin 20u 18u |> getOprCondReg
    struct (opcode, TwoOperands(bfOpr, bfaOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1001100000000000000001001000010u ->
    let opcode = Opcode.CREQV
    let btOpr = Bits.extract bin 25u 21u |> getOprCondBitReg
    let baOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bbOpr = Bits.extract bin 15u 11u |> getOprCondBitReg
    struct (opcode, ThreeOperands(btOpr, baOpr, bbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1001100000000000000001101000010u ->
    let opcode = Opcode.CRORC
    let btOpr = Bits.extract bin 25u 21u |> getOprCondBitReg
    let baOpr = Bits.extract bin 20u 16u |> getOprCondBitReg
    let bbOpr = Bits.extract bin 15u 11u |> getOprCondBitReg
    struct (opcode, ThreeOperands(btOpr, baOpr, bbOpr))
  | b when b &&&
    0b11111111111111111111000000011111u = 0b1000100000000000000000000000010u ->
    let opcode = Opcode.SC
    let levOpr = Bits.extract bin 11u 5u |> getOprImm
    struct (opcode, OneOperand(levOpr))
  | b when b &&&
    0b11111111111111111111000000011111u = 0b1000100000000000000000000000001u ->
    let opcode = Opcode.SCV
    let levOpr = Bits.extract bin 11u 5u |> getOprImm
    struct (opcode, OneOperand(levOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10001000000000000000000000000000u ->
    let opcode = Opcode.LBZ
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rtOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10001100000000000000000000000000u ->
    let opcode = Opcode.LBZU
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rtOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000010101110u ->
    let opcode = Opcode.LBZX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000011101110u ->
    let opcode = Opcode.LBZUX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10100000000000000000000000000000u ->
    let opcode = Opcode.LHZ
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rtOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10100100000000000000000000000000u ->
    let opcode = Opcode.LHZU
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rtOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001000101110u ->
    let opcode = Opcode.LHZX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001001101110u ->
    let opcode = Opcode.LHZUX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10101000000000000000000000000000u ->
    let opcode = Opcode.LHA
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rtOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10101100000000000000000000000000u ->
    let opcode = Opcode.LHAU
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rtOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001010101110u ->
    let opcode = Opcode.LHAX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001011101110u ->
    let opcode = Opcode.LHAUX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10000000000000000000000000000000u ->
    let opcode = Opcode.LWZ
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rtOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10000100000000000000000000000000u ->
    let opcode = Opcode.LWZU
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rtOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000101110u ->
    let opcode = Opcode.LWZX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000001101110u ->
    let opcode = Opcode.LWZUX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11101000000000000000000000000010u ->
    let opcode = Opcode.LWA
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2raOpr = getOprMem ds ra
    struct (opcode, TwoOperands(rtOpr, ds2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001010101010u ->
    let opcode = Opcode.LWAX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001011101010u ->
    let opcode = Opcode.LWAUX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11101000000000000000000000000000u ->
    let opcode = Opcode.LD
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2raOpr = getOprMem ds ra
    struct (opcode, TwoOperands(rtOpr, ds2raOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11101000000000000000000000000001u ->
    let opcode = Opcode.LDU
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2raOpr = getOprMem ds ra
    struct (opcode, TwoOperands(rtOpr, ds2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000101010u ->
    let opcode = Opcode.LDX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000001101010u ->
    let opcode = Opcode.LDUX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10011000000000000000000000000000u ->
    let opcode = Opcode.STB
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rsOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10011100000000000000000000000000u ->
    let opcode = Opcode.STBU
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rsOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000110101110u ->
    let opcode = Opcode.STBX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000111101110u ->
    let opcode = Opcode.STBUX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10110000000000000000000000000000u ->
    let opcode = Opcode.STH
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rsOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10110100000000000000000000000000u ->
    let opcode = Opcode.STHU
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rsOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001100101110u ->
    let opcode = Opcode.STHX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001101101110u ->
    let opcode = Opcode.STHUX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10010000000000000000000000000000u ->
    let opcode = Opcode.STW
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rsOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10010100000000000000000000000000u ->
    let opcode = Opcode.STWU
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rsOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100101110u ->
    let opcode = Opcode.STWX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000101101110u ->
    let opcode = Opcode.STWUX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11111000000000000000000000000000u ->
    let opcode = Opcode.STD
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2raOpr = getOprMem ds ra
    struct (opcode, TwoOperands(rsOpr, ds2raOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11111000000000000000000000000001u ->
    let opcode = Opcode.STDU
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2raOpr = getOprMem ds ra
    struct (opcode, TwoOperands(rsOpr, ds2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100101010u ->
    let opcode = Opcode.STDX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000101101010u ->
    let opcode = Opcode.STDUX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000001111u = 0b11100000000000000000000000000000u ->
    let opcode = Opcode.LQ
    let rtpOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let dq = extractExtendedField bin 15u 4u 4
    let dq2raOpr = getOprMem dq ra
    struct (opcode, TwoOperands(rtpOpr, dq2raOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11111000000000000000000000000010u ->
    let opcode = Opcode.STQ
    let rspOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2raOpr = getOprMem ds ra
    struct (opcode, TwoOperands(rspOpr, ds2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000101100u ->
    let opcode = Opcode.LHBRX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000101100u ->
    let opcode = Opcode.LWBRX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011100101100u ->
    let opcode = Opcode.STHBRX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100101100u ->
    let opcode = Opcode.STWBRX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000101000u ->
    let opcode = Opcode.LDBRX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100101000u ->
    let opcode = Opcode.STDBRX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10111000000000000000000000000000u ->
    let opcode = Opcode.LMW
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rtOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10111100000000000000000000000000u ->
    let opcode = Opcode.STMW
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(rsOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010010101010u ->
    let opcode = Opcode.LSWI
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let nbOpr = Bits.extract bin 15u 11u |> getOprImm
    struct (opcode, ThreeOperands(rtOpr, raOpr, nbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000101010u ->
    let opcode = Opcode.LSWX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010110101010u ->
    let opcode = Opcode.STSWI
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let nbOpr = Bits.extract bin 15u 11u |> getOprImm
    struct (opcode, ThreeOperands(rsOpr, raOpr, nbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100101010u ->
    let opcode = Opcode.STSWX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b111000000000000000000000000000u ->
    let opcode = Opcode.ADDI
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = extractExtendedField bin 15u 0u 0 |> getOprImm64
    struct (opcode, ThreeOperands(rtOpr, raOpr, siOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b111100000000000000000000000000u ->
    let opcode = Opcode.ADDIS
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = extractExtendedField bin 15u 0u 0 |> getOprImm64
    struct (opcode, ThreeOperands(rtOpr, raOpr, siOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001000010100u ->
    let opcode = Opcode.ADD
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001000010101u ->
    let opcode = Opcode.ADD_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000010100u ->
    let opcode = Opcode.ADDO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000010101u ->
    let opcode = Opcode.ADDO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b110000000000000000000000000000u ->
    let opcode = Opcode.ADDIC
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = extractExtendedField bin 15u 0u 0 |> getOprImm64
    struct (opcode, ThreeOperands(rtOpr, raOpr, siOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000001010000u ->
    let opcode = Opcode.SUBF
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000001010001u ->
    let opcode = Opcode.SUBF_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010001010000u ->
    let opcode = Opcode.SUBFO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010001010001u ->
    let opcode = Opcode.SUBFO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b110100000000000000000000000000u ->
    let opcode = Opcode.ADDIC_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = extractExtendedField bin 15u 0u 0 |> getOprImm64
    struct (opcode, ThreeOperands(rtOpr, raOpr, siOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b100000000000000000000000000000u ->
    let opcode = Opcode.SUBFIC
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = extractExtendedField bin 15u 0u 0 |> getOprImm64
    struct (opcode, ThreeOperands(rtOpr, raOpr, siOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010100u ->
    let opcode = Opcode.ADDC
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010101u ->
    let opcode = Opcode.ADDC_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000010100u ->
    let opcode = Opcode.ADDCO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000010101u ->
    let opcode = Opcode.ADDCO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010000u ->
    let opcode = Opcode.SUBFC
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010001u ->
    let opcode = Opcode.SUBFC_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000010000u ->
    let opcode = Opcode.SUBFCO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000010001u ->
    let opcode = Opcode.SUBFCO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100010100u ->
    let opcode = Opcode.ADDE
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100010101u ->
    let opcode = Opcode.ADDE_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100010100u ->
    let opcode = Opcode.ADDEO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100010101u ->
    let opcode = Opcode.ADDEO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000111010100u ->
    let opcode = Opcode.ADDME
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000111010101u ->
    let opcode = Opcode.ADDME_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010111010100u ->
    let opcode = Opcode.ADDMEO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010111010101u ->
    let opcode = Opcode.ADDMEO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100010000u ->
    let opcode = Opcode.SUBFE
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100010001u ->
    let opcode = Opcode.SUBFE_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100010000u ->
    let opcode = Opcode.SUBFEO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100010001u ->
    let opcode = Opcode.SUBFEO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000111010000u ->
    let opcode = Opcode.SUBFME
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000111010001u ->
    let opcode = Opcode.SUBFME_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010111010000u ->
    let opcode = Opcode.SUBFMEO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010111010001u ->
    let opcode = Opcode.SUBFMEO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b1111100000000000000000101010100u ->
    let opcode = Opcode.ADDEX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let cyOpr = Bits.extract bin 10u 9u |> getOprCY
    struct (opcode, FourOperands(rtOpr, raOpr, rbOpr, cyOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000110010100u ->
    let opcode = Opcode.ADDZE
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000110010101u ->
    let opcode = Opcode.ADDZE_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010110010100u ->
    let opcode = Opcode.ADDZEO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010110010101u ->
    let opcode = Opcode.ADDZEO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000110010000u ->
    let opcode = Opcode.SUBFZE
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000110010001u ->
    let opcode = Opcode.SUBFZE_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010110010000u ->
    let opcode = Opcode.SUBFZEO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010110010001u ->
    let opcode = Opcode.SUBFZEO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000011010000u ->
    let opcode = Opcode.NEG
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000011010001u ->
    let opcode = Opcode.NEG_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010011010000u ->
    let opcode = Opcode.NEGO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010011010001u ->
    let opcode = Opcode.NEGO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, raOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b011100000000000000000000000000u ->
    let opcode = Opcode.MULLI
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = extractExtendedField bin 15u 0u 0 |> getOprImm64
    struct (opcode, ThreeOperands(rtOpr, raOpr, siOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000111010110u ->
    let opcode = Opcode.MULLW
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000111010111u ->
    let opcode = Opcode.MULLW_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010111010110u ->
    let opcode = Opcode.MULLWO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010111010111u ->
    let opcode = Opcode.MULLWO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000010010110u ->
    let opcode = Opcode.MULHW
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000010010111u ->
    let opcode = Opcode.MULHW_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010110u ->
    let opcode = Opcode.MULHWU
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010111u ->
    let opcode = Opcode.MULHWU_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001111010110u ->
    let opcode = Opcode.DIVW
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001111010111u ->
    let opcode = Opcode.DIVW_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011111010110u ->
    let opcode = Opcode.DIVWO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011111010111u ->
    let opcode = Opcode.DIVWO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001110010110u ->
    let opcode = Opcode.DIVWU
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001110010111u ->
    let opcode = Opcode.DIVWU_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011110010110u ->
    let opcode = Opcode.DIVWUO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011110010111u ->
    let opcode = Opcode.DIVWUO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001101010110u ->
    let opcode = Opcode.DIVWE
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001101010111u ->
    let opcode = Opcode.DIVWE_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011101010110u ->
    let opcode = Opcode.DIVWEO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011101010111u ->
    let opcode = Opcode.DIVWEO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001100010110u ->
    let opcode = Opcode.DIVWEU
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001100010111u ->
    let opcode = Opcode.DIVWEU_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011100010110u ->
    let opcode = Opcode.DIVWEUO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011100010111u ->
    let opcode = Opcode.DIVWEUO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000010110u ->
    let opcode = Opcode.MODSW
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001000010110u ->
    let opcode = Opcode.MODUW
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000111010010u ->
    let opcode = Opcode.MULLD
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000111010011u ->
    let opcode = Opcode.MULLD_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010111010010u ->
    let opcode = Opcode.MULLDO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010111010011u ->
    let opcode = Opcode.MULLDO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000010010010u ->
    let opcode = Opcode.MULHD
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000010010011u ->
    let opcode = Opcode.MULHD_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010010u ->
    let opcode = Opcode.MULHDU
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010011u ->
    let opcode = Opcode.MULHDU_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001111010010u ->
    let opcode = Opcode.DIVD
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001111010011u ->
    let opcode = Opcode.DIVD_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011111010010u ->
    let opcode = Opcode.DIVDO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011111010011u ->
    let opcode = Opcode.DIVDO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001110010010u ->
    let opcode = Opcode.DIVDU
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001110010011u ->
    let opcode = Opcode.DIVDU_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011110010010u ->
    let opcode = Opcode.DIVDUO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011110010011u ->
    let opcode = Opcode.DIVDUO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001101010010u ->
    let opcode = Opcode.DIVDE
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001101010011u ->
    let opcode = Opcode.DIVDE_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011101010010u ->
    let opcode = Opcode.DIVDEO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011101010011u ->
    let opcode = Opcode.DIVDEO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001100010010u ->
    let opcode = Opcode.DIVDEU
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001100010011u ->
    let opcode = Opcode.DIVDEU_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011100010010u ->
    let opcode = Opcode.DIVDEUO
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011100010011u ->
    let opcode = Opcode.DIVDEUO_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000010010u ->
    let opcode = Opcode.MODSD
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001000010010u ->
    let opcode = Opcode.MODUD
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100010000000000000000000000u = 0b101100000000000000000000000000u ->
    let opcode = Opcode.CMPI
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let lOpr = Bits.pick bin 21u |> getOprL
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = extractExtendedField bin 15u 0u 0 |> getOprImm64
    struct (opcode, FourOperands(bfOpr, lOpr, raOpr, siOpr))
  | b when b &&&
    0b11111100010000000000011111111111u = 0b1111100000000000000000000000000u ->
    let opcode = Opcode.CMP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let lOpr = Bits.pick bin 21u |> getOprL
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, FourOperands(bfOpr, lOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100010000000000000000000000u = 0b101000000000000000000000000000u ->
    let opcode = Opcode.CMPLI
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let lOpr = Bits.pick bin 21u |> getOprL
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let uiOpr = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, FourOperands(bfOpr, lOpr, raOpr, uiOpr))
  | b when b &&&
    0b11111100010000000000011111111111u = 0b1111100000000000000000001000000u ->
    let opcode = Opcode.CMPL
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let lOpr = Bits.pick bin 21u |> getOprL
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, FourOperands(bfOpr, lOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100010000000000011111111111u = 0b1111100000000000000000110000000u ->
    let opcode = Opcode.CMPRB
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let lOpr = Bits.pick bin 21u |> getOprL
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, FourOperands(bfOpr, lOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100011000000000011111111111u = 0b1111100000000000000000111000000u ->
    let opcode = Opcode.CMPEQB
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(bfOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b001100000000000000000000000000u ->
    let opcode = Opcode.TWI
    let toOpr = Bits.extract bin 25u 21u |> getOprTO
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = extractExtendedField bin 15u 0u 0 |> getOprImm64
    struct (opcode, ThreeOperands(toOpr, raOpr, siOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000001000u ->
    let opcode = Opcode.TW
    let toOpr = Bits.extract bin 25u 21u |> getOprTO
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(toOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b001000000000000000000000000000u ->
    let opcode = Opcode.TDI
    let toOpr = Bits.extract bin 25u 21u |> getOprTO
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = extractExtendedField bin 15u 0u 0 |> getOprImm64
    struct (opcode, ThreeOperands(toOpr, raOpr, siOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b1111100000000000000000000011110u ->
    let opcode = Opcode.ISEL
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let bcOpr = Bits.extract bin 10u 6u |> getOprCondBitReg
    struct (opcode, FourOperands(rtOpr, raOpr, rbOpr, bcOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000010001000u ->
    let opcode = Opcode.TD
    let toOpr = Bits.extract bin 25u 21u |> getOprTO
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(toOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b1110000000000000000000000000000u ->
    let opcode = Opcode.ANDI_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let uiOpr = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rsOpr, uiOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b1110100000000000000000000000000u ->
    let opcode = Opcode.ANDIS_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let uiOpr = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rsOpr, uiOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b1100000000000000000000000000000u ->
    let opcode = Opcode.ORI
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let uiOpr = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rsOpr, uiOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b1100100000000000000000000000000u ->
    let opcode = Opcode.ORIS
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let uiOpr = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rsOpr, uiOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b1101000000000000000000000000000u ->
    let opcode = Opcode.XORI
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let uiOpr = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rsOpr, uiOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b1101100000000000000000000000000u ->
    let opcode = Opcode.XORIS
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let uiOpr = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rsOpr, uiOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000111000u ->
    let opcode = Opcode.AND
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000111001u ->
    let opcode = Opcode.AND_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001001111000u ->
    let opcode = Opcode.XOR
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001001111001u ->
    let opcode = Opcode.XOR_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001110111000u ->
    let opcode = Opcode.NAND
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001110111001u ->
    let opcode = Opcode.NAND_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001101111000u ->
    let opcode = Opcode.OR
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001101111001u ->
    let opcode = Opcode.OR_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000011111000u ->
    let opcode = Opcode.NOR
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000011111001u ->
    let opcode = Opcode.NOR_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000001111000u ->
    let opcode = Opcode.ANDC
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000001111001u ->
    let opcode = Opcode.ANDC_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001000111000u ->
    let opcode = Opcode.EQV
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001000111001u ->
    let opcode = Opcode.EQV_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001100111000u ->
    let opcode = Opcode.ORC
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001100111001u ->
    let opcode = Opcode.ORC_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000011101110100u ->
    let opcode = Opcode.EXTSB
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000011101110101u ->
    let opcode = Opcode.EXTSB_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000000110100u ->
    let opcode = Opcode.CNTLZW
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000000110101u ->
    let opcode = Opcode.CNTLZW_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000011100110100u ->
    let opcode = Opcode.EXTSH
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000011100110101u ->
    let opcode = Opcode.EXTSH_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010000110100u ->
    let opcode = Opcode.CNTTZW
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010000110101u ->
    let opcode = Opcode.CNTTZW_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001111111000u ->
    let opcode = Opcode.CMPB
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000011110100u ->
    let opcode = Opcode.POPCNTB
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000001011110100u ->
    let opcode = Opcode.POPCNTW
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000101110100u ->
    let opcode = Opcode.PRTYD
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000100110100u ->
    let opcode = Opcode.PRTYW
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000011110110100u ->
    let opcode = Opcode.EXTSW
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000011110110101u ->
    let opcode = Opcode.EXTSW_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000001110100u ->
    let opcode = Opcode.CNTLZD
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000001110101u ->
    let opcode = Opcode.CNTLZD_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000001111110100u ->
    let opcode = Opcode.POPCNTD
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010001110100u ->
    let opcode = Opcode.CNTTZD
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010001110101u ->
    let opcode = Opcode.CNTTZD_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000000000000000000001u = 0b1010100000000000000000000000000u ->
    let opcode = Opcode.RLWINM
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let shOpr = Bits.extract bin 15u 11u |> getOprImm
    let mbOpr = Bits.extract bin 10u 6u |> getOprImm
    let meOpr = Bits.extract bin 5u 1u |> getOprImm
    struct (opcode, FiveOperands(raOpr, rsOpr, shOpr, mbOpr, meOpr))
  | b when b &&&
    0b11111100000000000000000000000001u = 0b1010100000000000000000000000001u ->
    let opcode = Opcode.RLWINM_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let shOpr = Bits.extract bin 15u 11u |> getOprImm
    let mbOpr = Bits.extract bin 10u 6u |> getOprImm
    let meOpr = Bits.extract bin 5u 1u |> getOprImm
    struct (opcode, FiveOperands(raOpr, rsOpr, shOpr, mbOpr, meOpr))
  | b when b &&&
    0b11111100000000000000000000000001u = 0b1011100000000000000000000000000u ->
    let opcode = Opcode.RLWNM
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let mbOpr = Bits.extract bin 10u 6u |> getOprImm
    let meOpr = Bits.extract bin 5u 1u |> getOprImm
    struct (opcode, FiveOperands(raOpr, rsOpr, rbOpr, mbOpr, meOpr))
  | b when b &&&
    0b11111100000000000000000000000001u = 0b1011100000000000000000000000001u ->
    let opcode = Opcode.RLWNM_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let mbOpr = Bits.extract bin 10u 6u |> getOprImm
    let meOpr = Bits.extract bin 5u 1u |> getOprImm
    struct (opcode, FiveOperands(raOpr, rsOpr, rbOpr, mbOpr, meOpr))
  | b when b &&&
    0b11111100000000000000000000000001u = 0b1010000000000000000000000000000u ->
    let opcode = Opcode.RLWIMI
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let shOpr = Bits.extract bin 15u 11u |> getOprImm
    let mbOpr = Bits.extract bin 10u 6u |> getOprImm
    let meOpr = Bits.extract bin 5u 1u |> getOprImm
    struct (opcode, FiveOperands(raOpr, rsOpr, shOpr, mbOpr, meOpr))
  | b when b &&&
    0b11111100000000000000000000000001u = 0b1010000000000000000000000000001u ->
    let opcode = Opcode.RLWIMI_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let shOpr = Bits.extract bin 15u 11u |> getOprImm
    let mbOpr = Bits.extract bin 10u 6u |> getOprImm
    let meOpr = Bits.extract bin 5u 1u |> getOprImm
    struct (opcode, FiveOperands(raOpr, rsOpr, shOpr, mbOpr, meOpr))
  | b when b &&&
    0b11111100000000000000000000011101u = 0b1111000000000000000000000000000u ->
    let opcode = Opcode.RLDICL
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let sh0 = Bits.extract bin 15u 11u
    let sh1 = Bits.pick bin 1u
    let shOpr = Bits.concat sh1 sh0 5 |> getOprImm
    let mb0 = Bits.extract bin 10u 6u
    let mb1 = Bits.pick bin 5u
    let mbOpr = Bits.concat mb1 mb0 5 |> getOprImm
    struct (opcode, FourOperands(raOpr, rsOpr, shOpr, mbOpr))
  | b when b &&&
    0b11111100000000000000000000011101u = 0b1111000000000000000000000000001u ->
    let opcode = Opcode.RLDICL_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let sh0 = Bits.extract bin 15u 11u
    let sh1 = Bits.pick bin 1u
    let shOpr = Bits.concat sh1 sh0 5 |> getOprImm
    let mb0 = Bits.extract bin 10u 6u
    let mb1 = Bits.pick bin 5u
    let mbOpr = Bits.concat mb1 mb0 5 |> getOprImm
    struct (opcode, FourOperands(raOpr, rsOpr, shOpr, mbOpr))
  | b when b &&&
    0b11111100000000000000000000011101u = 0b1111000000000000000000000000100u ->
    let opcode = Opcode.RLDICR
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let sh0 = Bits.extract bin 15u 11u
    let sh1 = Bits.pick bin 1u
    let shOpr = Bits.concat sh1 sh0 5 |> getOprImm
    let me0 = Bits.extract bin 10u 6u
    let me1 = Bits.pick bin 5u
    let meOpr = Bits.concat me1 me0 5 |> getOprImm
    struct (opcode, FourOperands(raOpr, rsOpr, shOpr, meOpr))
  | b when b &&&
    0b11111100000000000000000000011101u = 0b1111000000000000000000000000101u ->
    let opcode = Opcode.RLDICR_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let sh0 = Bits.extract bin 15u 11u
    let sh1 = Bits.pick bin 1u
    let shOpr = Bits.concat sh1 sh0 5 |> getOprImm
    let me0 = Bits.extract bin 10u 6u
    let me1 = Bits.pick bin 5u
    let meOpr = Bits.concat me1 me0 5 |> getOprImm
    struct (opcode, FourOperands(raOpr, rsOpr, shOpr, meOpr))
  | b when b &&&
    0b11111100000000000000000000011101u = 0b1111000000000000000000000001000u ->
    let opcode = Opcode.RLDIC
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let sh0 = Bits.extract bin 15u 11u
    let sh1 = Bits.pick bin 1u
    let shOpr = Bits.concat sh1 sh0 5 |> getOprImm
    let mb0 = Bits.extract bin 10u 6u
    let mb1 = Bits.pick bin 5u
    let mbOpr = Bits.concat mb1 mb0 5 |> getOprImm
    struct (opcode, FourOperands(raOpr, rsOpr, shOpr, mbOpr))
  | b when b &&&
    0b11111100000000000000000000011101u = 0b1111000000000000000000000001001u ->
    let opcode = Opcode.RLDIC_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let sh0 = Bits.extract bin 15u 11u
    let sh1 = Bits.pick bin 1u
    let shOpr = Bits.concat sh1 sh0 5 |> getOprImm
    let mb0 = Bits.extract bin 10u 6u
    let mb1 = Bits.pick bin 5u
    let mbOpr = Bits.concat mb1 mb0 5 |> getOprImm
    struct (opcode, FourOperands(raOpr, rsOpr, shOpr, mbOpr))
  | b when b &&&
    0b11111100000000000000000000011111u = 0b1111000000000000000000000010000u ->
    let opcode = Opcode.RLDCL
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let mb0 = Bits.extract bin 10u 6u
    let mb1 = Bits.pick bin 5u
    let mbOpr = Bits.concat mb1 mb0 5 |> getOprImm
    struct (opcode, FourOperands(raOpr, rsOpr, rbOpr, mbOpr))
  | b when b &&&
    0b11111100000000000000000000011111u = 0b1111000000000000000000000010001u ->
    let opcode = Opcode.RLDCL_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let mb0 = Bits.extract bin 10u 6u
    let mb1 = Bits.pick bin 5u
    let mbOpr = Bits.concat mb1 mb0 5 |> getOprImm
    struct (opcode, FourOperands(raOpr, rsOpr, rbOpr, mbOpr))
  | b when b &&&
    0b11111100000000000000000000011111u = 0b1111000000000000000000000010010u ->
    let opcode = Opcode.RLDCR
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let me0 = Bits.extract bin 10u 6u
    let me1 = Bits.pick bin 5u
    let meOpr = Bits.concat me1 me0 5 |> getOprImm
    struct (opcode, FourOperands(raOpr, rsOpr, rbOpr, meOpr))
  | b when b &&&
    0b11111100000000000000000000011111u = 0b1111000000000000000000000010011u ->
    let opcode = Opcode.RLDCR_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let me0 = Bits.extract bin 10u 6u
    let me1 = Bits.pick bin 5u
    let meOpr = Bits.concat me1 me0 5 |> getOprImm
    struct (opcode, FourOperands(raOpr, rsOpr, rbOpr, meOpr))
  | b when b &&&
    0b11111100000000000000000000011101u = 0b1111000000000000000000000001100u ->
    let opcode = Opcode.RLDIMI
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let sh0 = Bits.extract bin 15u 11u
    let sh1 = Bits.pick bin 1u
    let shOpr = Bits.concat sh1 sh0 5 |> getOprImm
    let mb0 = Bits.extract bin 10u 6u
    let mb1 = Bits.pick bin 5u
    let mbOpr = Bits.concat mb1 mb0 5 |> getOprImm
    struct (opcode, FourOperands(raOpr, rsOpr, shOpr, mbOpr))
  | b when b &&&
    0b11111100000000000000000000011101u = 0b1111000000000000000000000001101u ->
    let opcode = Opcode.RLDIMI_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let sh0 = Bits.extract bin 15u 11u
    let sh1 = Bits.pick bin 1u
    let shOpr = Bits.concat sh1 sh0 5 |> getOprImm
    let mb0 = Bits.extract bin 10u 6u
    let mb1 = Bits.pick bin 5u
    let mbOpr = Bits.concat mb1 mb0 5 |> getOprImm
    struct (opcode, FourOperands(raOpr, rsOpr, shOpr, mbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000110000u ->
    let opcode = Opcode.SLW
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000110001u ->
    let opcode = Opcode.SLW_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000110000u ->
    let opcode = Opcode.SRW
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000110001u ->
    let opcode = Opcode.SRW_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011001110000u ->
    let opcode = Opcode.SRAWI
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let shOpr = Bits.extract bin 15u 11u |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rsOpr, shOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011001110001u ->
    let opcode = Opcode.SRAWI_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let shOpr = Bits.extract bin 15u 11u |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rsOpr, shOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000110000u ->
    let opcode = Opcode.SRAW
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000110001u ->
    let opcode = Opcode.SRAW_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000110110u ->
    let opcode = Opcode.SLD
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000110111u ->
    let opcode = Opcode.SLD_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000110110u ->
    let opcode = Opcode.SRD
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000110111u ->
    let opcode = Opcode.SRD_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111101u = 0b1111100000000000000011001110100u ->
    let opcode = Opcode.SRADI
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let sh0 = Bits.extract bin 15u 11u
    let sh1 = Bits.pick bin 1u
    let shOpr = Bits.concat sh1 sh0 5 |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rsOpr, shOpr))
  | b when b &&&
    0b11111100000000000000011111111101u = 0b1111100000000000000011001110101u ->
    let opcode = Opcode.SRADI_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let sh0 = Bits.extract bin 15u 11u
    let sh1 = Bits.pick bin 1u
    let shOpr = Bits.concat sh1 sh0 5 |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rsOpr, shOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000110100u ->
    let opcode = Opcode.SRAD
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000110101u ->
    let opcode = Opcode.SRAD_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111101u = 0b1111100000000000000011011110100u ->
    let opcode = Opcode.EXTSWSLI
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let sh0 = Bits.extract bin 15u 11u
    let sh1 = Bits.pick bin 1u
    let shOpr = Bits.concat sh1 sh0 5 |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rsOpr, shOpr))
  | b when b &&&
    0b11111100000000000000011111111101u = 0b1111100000000000000011011110101u ->
    let opcode = Opcode.EXTSWSLI_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let sh0 = Bits.extract bin 15u 11u
    let sh1 = Bits.pick bin 1u
    let shOpr = Bits.concat sh1 sh0 5 |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rsOpr, shOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000010010100u ->
    let opcode = Opcode.ADDG6S
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000001111111111111110u = 0b1111100000000000000000001100110u ->
    let opcode = Opcode.MFVSRD
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    struct (opcode, TwoOperands(raOpr, xsOpr))
  | b when b &&&
    0b11111100000000001111111111111110u = 0b1111100000000000000001001100110u ->
    let opcode = Opcode.MFVSRLD
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    struct (opcode, TwoOperands(raOpr, xsOpr))
  | b when b &&&
    0b11111100000000001111111111111110u = 0b1111100000000000000000011100110u ->
    let opcode = Opcode.MFVSRWZ
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    struct (opcode, TwoOperands(raOpr, xsOpr))
  | b when b &&&
    0b11111100000000001111111111111110u = 0b1111100000000000000000101100110u ->
    let opcode = Opcode.MTVSRD
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(xtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111110u = 0b1111100000000000000000110100110u ->
    let opcode = Opcode.MTVSRWA
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(xtOpr, raOpr))
  | b when b &&&
    0b11111100000000001111111111111110u = 0b1111100000000000000000111100110u ->
    let opcode = Opcode.MTVSRWZ
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(xtOpr, raOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000001101100110u ->
    let opcode = Opcode.MTVSRDD
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000001111111111111110u = 0b1111100000000000000001100100110u ->
    let opcode = Opcode.MTVSRWS
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(xtOpr, raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001110100110u ->
    let opcode = Opcode.MTSPR
    let spr0 = Bits.extract bin 20u 16u
    let spr1 = Bits.extract bin 15u 11u
    let sprOpr = Bits.concat spr1 spr0 5 |> getOprSPReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(sprOpr, rsOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001010100110u ->
    let opcode = Opcode.MFSPR
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let spr0 = Bits.extract bin 20u 16u
    let spr1 = Bits.extract bin 15u 11u
    let sprOpr = Bits.concat spr1 spr0 5 |> getOprSPReg
    struct (opcode, TwoOperands(rtOpr, sprOpr))
  | b when b &&&
    0b11111100011111111111111111111111u = 0b1111100000000000000010010000000u ->
    let opcode = Opcode.MCRXRX
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    struct (opcode, OneOperand(bfOpr))
  | b when b &&&
    0b11111100000100000000111111111111u = 0b1111100000100000000000100100000u ->
    let opcode = Opcode.MTOCRF
    let fxmOpr = Bits.extract bin 19u 12u |> getOprCRMask
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(fxmOpr, rsOpr))
  | b when b &&&
    0b11111100000100000000111111111111u = 0b1111100000000000000000100100000u ->
    let opcode = Opcode.MTCRF
    let fxmOpr = Bits.extract bin 19u 12u |> getOprCRMask
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(fxmOpr, rsOpr))
  | b when b &&&
    0b11111100000100000000111111111111u = 0b1111100000100000000000000100110u ->
    let opcode = Opcode.MFOCRF
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let fxmOpr = Bits.extract bin 19u 12u |> getOprCRMask
    struct (opcode, TwoOperands(rtOpr, fxmOpr))
  | b when b &&&
    0b11111100000111111111111111111111u = 0b1111100000000000000000000100110u ->
    let opcode = Opcode.MFCR
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, OneOperand(rtOpr))
  | b when b &&&
    0b11111100000000111111111111111111u = 0b1111100000000000000000100000000u ->
    let opcode = Opcode.SETB
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let bfaOpr = Bits.extract bin 20u 18u |> getOprCondReg
    struct (opcode, TwoOperands(rtOpr, bfaOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b11000000000000000000000000000000u ->
    let opcode = Opcode.LFS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(frtOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000101110u ->
    let opcode = Opcode.LFSX
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(frtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b11000100000000000000000000000000u ->
    let opcode = Opcode.LFSU
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(frtOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010001101110u ->
    let opcode = Opcode.LFSUX
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(frtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b11001000000000000000000000000000u ->
    let opcode = Opcode.LFD
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(frtOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010010101110u ->
    let opcode = Opcode.LFDX
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(frtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b11001100000000000000000000000000u ->
    let opcode = Opcode.LFDU
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(frtOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010011101110u ->
    let opcode = Opcode.LFDUX
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(frtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011010101110u ->
    let opcode = Opcode.LFIWAX
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(frtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011011101110u ->
    let opcode = Opcode.LFIWZX
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(frtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b11010000000000000000000000000000u ->
    let opcode = Opcode.STFS
    let frsOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(frsOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b11010100000000000000000000000000u ->
    let opcode = Opcode.STFSU
    let frsOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(frsOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100101110u ->
    let opcode = Opcode.STFSX
    let frsOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(frsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010101101110u ->
    let opcode = Opcode.STFSUX
    let frsOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(frsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b11011000000000000000000000000000u ->
    let opcode = Opcode.STFD
    let frsOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(frsOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b11011100000000000000000000000000u ->
    let opcode = Opcode.STFDU
    let frsOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2raOpr = getOprMem d ra
    struct (opcode, TwoOperands(frsOpr, d2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010110101110u ->
    let opcode = Opcode.STFDX
    let frsOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(frsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010111101110u ->
    let opcode = Opcode.STFDUX
    let frsOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(frsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011110101110u ->
    let opcode = Opcode.STFIWX
    let frsOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(frsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11100100000000000000000000000000u ->
    let opcode = Opcode.LFDP
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2raOpr = getOprMem ds ra
    struct (opcode, TwoOperands(frtpOpr, ds2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000101110u ->
    let opcode = Opcode.LFDPX
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(frtpOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11110100000000000000000000000000u ->
    let opcode = Opcode.STFDP
    let frspOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2raOpr = getOprMem ds ra
    struct (opcode, TwoOperands(frspOpr, ds2raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011100101110u ->
    let opcode = Opcode.STFDPX
    let frspOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(frspOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000010010000u ->
    let opcode = Opcode.FMR
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000010010001u ->
    let opcode = Opcode.FMR_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001000010000u ->
    let opcode = Opcode.FABS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001000010001u ->
    let opcode = Opcode.FABS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000100010000u ->
    let opcode = Opcode.FNABS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000100010001u ->
    let opcode = Opcode.FNABS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000001010000u ->
    let opcode = Opcode.FNEG
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000001010001u ->
    let opcode = Opcode.FNEG_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000000010000u ->
    let opcode = Opcode.FCPSGN
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000000010001u ->
    let opcode = Opcode.FCPSGN_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000011110001100u ->
    let opcode = Opcode.FMRGEW
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000011010001100u ->
    let opcode = Opcode.FMRGOW
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000000101010u ->
    let opcode = Opcode.FADD
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000000101011u ->
    let opcode = Opcode.FADD_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000000000101010u ->
    let opcode = Opcode.FADDS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000000000101011u ->
    let opcode = Opcode.FADDS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000000101000u ->
    let opcode = Opcode.FSUB
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000000101001u ->
    let opcode = Opcode.FSUB_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000000000101000u ->
    let opcode = Opcode.FSUBS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000000000101001u ->
    let opcode = Opcode.FSUBS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000001111100000111111u = 0b11111100000000000000000000110010u ->
    let opcode = Opcode.FMUL
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frcOpr))
  | b when b &&&
    0b11111100000000001111100000111111u = 0b11111100000000000000000000110011u ->
    let opcode = Opcode.FMUL_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frcOpr))
  | b when b &&&
    0b11111100000000001111100000111111u = 0b11101100000000000000000000110010u ->
    let opcode = Opcode.FMULS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frcOpr))
  | b when b &&&
    0b11111100000000001111100000111111u = 0b11101100000000000000000000110011u ->
    let opcode = Opcode.FMULS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frcOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000000100100u ->
    let opcode = Opcode.FDIV
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000000100101u ->
    let opcode = Opcode.FDIV_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000000000100100u ->
    let opcode = Opcode.FDIVS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000000000100101u ->
    let opcode = Opcode.FDIVS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000000101100u ->
    let opcode = Opcode.FSQRT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000000101101u ->
    let opcode = Opcode.FSQRT_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000000000101100u ->
    let opcode = Opcode.FSQRTS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000000000101101u ->
    let opcode = Opcode.FSQRTS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000000110000u ->
    let opcode = Opcode.FRE
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000000110001u ->
    let opcode = Opcode.FRE_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000000000110000u ->
    let opcode = Opcode.FRES
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000000000110001u ->
    let opcode = Opcode.FRES_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000000110100u ->
    let opcode = Opcode.FRSQRTE
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000000110101u ->
    let opcode = Opcode.FRSQRTE_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000000000110100u ->
    let opcode = Opcode.FRSQRTES
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000000000110101u ->
    let opcode = Opcode.FRSQRTES_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100011000000000011111111111u = 0b11111100000000000000000100000000u ->
    let opcode = Opcode.FTDIV
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(bfOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100011111110000011111111111u = 0b11111100000000000000000101000000u ->
    let opcode = Opcode.FTSQRT
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(bfOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11111100000000000000000000111010u ->
    let opcode = Opcode.FMADD
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11111100000000000000000000111011u ->
    let opcode = Opcode.FMADD_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11101100000000000000000000111010u ->
    let opcode = Opcode.FMADDS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11101100000000000000000000111011u ->
    let opcode = Opcode.FMADDS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11111100000000000000000000111000u ->
    let opcode = Opcode.FMSUB
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11111100000000000000000000111001u ->
    let opcode = Opcode.FMSUB_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11101100000000000000000000111000u ->
    let opcode = Opcode.FMSUBS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11101100000000000000000000111001u ->
    let opcode = Opcode.FMSUBS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11111100000000000000000000111110u ->
    let opcode = Opcode.FNMADD
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11111100000000000000000000111111u ->
    let opcode = Opcode.FNMADD_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11101100000000000000000000111110u ->
    let opcode = Opcode.FNMADDS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11101100000000000000000000111111u ->
    let opcode = Opcode.FNMADDS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11111100000000000000000000111100u ->
    let opcode = Opcode.FNMSUB
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11111100000000000000000000111101u ->
    let opcode = Opcode.FNMSUB_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11101100000000000000000000111100u ->
    let opcode = Opcode.FNMSUBS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11101100000000000000000000111101u ->
    let opcode = Opcode.FNMSUBS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000000011000u ->
    let opcode = Opcode.FRSP
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000000011001u ->
    let opcode = Opcode.FRSP_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011001011100u ->
    let opcode = Opcode.FCTID
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011001011101u ->
    let opcode = Opcode.FCTID_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011001011110u ->
    let opcode = Opcode.FCTIDZ
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011001011111u ->
    let opcode = Opcode.FCTIDZ_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011101011100u ->
    let opcode = Opcode.FCTIDU
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011101011101u ->
    let opcode = Opcode.FCTIDU_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011101011110u ->
    let opcode = Opcode.FCTIDUZ
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011101011111u ->
    let opcode = Opcode.FCTIDUZ_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000000011100u ->
    let opcode = Opcode.FCTIW
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000000011101u ->
    let opcode = Opcode.FCTIW_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000000011110u ->
    let opcode = Opcode.FCTIWZ
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000000011111u ->
    let opcode = Opcode.FCTIWZ_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000100011100u ->
    let opcode = Opcode.FCTIWU
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000100011101u ->
    let opcode = Opcode.FCTIWU_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000100011110u ->
    let opcode = Opcode.FCTIWUZ
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000000100011111u ->
    let opcode = Opcode.FCTIWUZ_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011010011100u ->
    let opcode = Opcode.FCFID
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011010011101u ->
    let opcode = Opcode.FCFID_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011110011100u ->
    let opcode = Opcode.FCFIDU
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011110011101u ->
    let opcode = Opcode.FCFIDU_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011010011100u ->
    let opcode = Opcode.FCFIDS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011010011101u ->
    let opcode = Opcode.FCFIDS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000011110011100u ->
    let opcode = Opcode.FCFIDUS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000011110011101u ->
    let opcode = Opcode.FCFIDUS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001100010000u ->
    let opcode = Opcode.FRIN
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001100010001u ->
    let opcode = Opcode.FRIN_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001101010000u ->
    let opcode = Opcode.FRIZ
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001101010001u ->
    let opcode = Opcode.FRIZ_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001110010000u ->
    let opcode = Opcode.FRIP
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001110010001u ->
    let opcode = Opcode.FRIP_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001111010000u ->
    let opcode = Opcode.FRIM
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001111010001u ->
    let opcode = Opcode.FRIM_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100011000000000011111111111u = 0b11111100000000000000000000000000u ->
    let opcode = Opcode.FCMPU
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(bfOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100011000000000011111111111u = 0b11111100000000000000000001000000u ->
    let opcode = Opcode.FCMPO
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(bfOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11111100000000000000000000101110u ->
    let opcode = Opcode.FSEL
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b11111100000000000000000000101111u ->
    let opcode = Opcode.FSEL_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frcOpr = Bits.extract bin 10u 6u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, FourOperands(frtOpr, fraOpr, frcOpr, frbOpr))
  | b when b &&&
    0b11111100000111111111111111111111u = 0b11111100000000000000010010001110u ->
    let opcode = Opcode.MFFS
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    struct (opcode, OneOperand(frtOpr))
  | b when b &&&
    0b11111100000111111111111111111111u = 0b11111100000000000000010010001111u ->
    let opcode = Opcode.MFFS_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    struct (opcode, OneOperand(frtOpr))
  | b when b &&&
    0b11111100000111111111111111111111u = 0b11111100000000010000010010001110u ->
    let opcode = Opcode.MFFSCE
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    struct (opcode, OneOperand(frtOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000101000000010010001110u ->
    let opcode = Opcode.MFFSCDRN
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111111100011111111111u = 0b11111100000101010000010010001110u ->
    let opcode = Opcode.MFFSCDRNI
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let drmOpr = Bits.extract bin 13u 11u |> getOprImm
    struct (opcode, TwoOperands(frtOpr, drmOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000101100000010010001110u ->
    let opcode = Opcode.MFFSCRN
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111111110011111111111u = 0b11111100000101110000010010001110u ->
    let opcode = Opcode.MFFSCRNI
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let rmOpr = Bits.extract bin 12u 11u |> getOprImm
    struct (opcode, TwoOperands(frtOpr, rmOpr))
  | b when b &&&
    0b11111100000111111111111111111111u = 0b11111100000110000000010010001110u ->
    let opcode = Opcode.MFFSL
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    struct (opcode, OneOperand(frtOpr))
  | b when b &&&
    0b11111100011000111111111111111111u = 0b11111100000000000000000010000000u ->
    let opcode = Opcode.MCRFS
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let bfaOpr = Bits.extract bin 20u 18u |> getOprFPSCondReg
    struct (opcode, TwoOperands(bfOpr, bfaOpr))
  | b when b &&&
    0b11111100011111100000111111111111u = 0b11111100000000000000000100001100u ->
    let opcode = Opcode.MTFSFI
    let bfOpr = Bits.extract bin 25u 23u |> getOprFPSCondReg
    let uOpr = Bits.extract bin 15u 12u |> getOprImm
    let wOpr = Bits.pick bin 16u |> getOprW
    struct (opcode, ThreeOperands(bfOpr, uOpr, wOpr))
  | b when b &&&
    0b11111100011111100000111111111111u = 0b11111100000000000000000100001101u ->
    let opcode = Opcode.MTFSFI_DOT
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let uOpr = Bits.extract bin 15u 12u |> getOprImm
    let wOpr = Bits.pick bin 16u |> getOprW
    struct (opcode, ThreeOperands(bfOpr, uOpr, wOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000010110001110u ->
    let opcode = Opcode.MTFSF
    let flmOpr = Bits.extract bin 24u 17u |> getOprFPSCRMask
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let lOpr = Bits.pick bin 25u |> getOprL
    let wOpr = Bits.pick bin 16u |> getOprW
    struct (opcode, FourOperands(flmOpr, frbOpr, lOpr, wOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000010110001111u ->
    let opcode = Opcode.MTFSF_DOT
    let flmOpr = Bits.extract bin 24u 17u |> getOprFPSCRMask
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let lOpr = Bits.pick bin 25u |> getOprL
    let wOpr = Bits.pick bin 16u |> getOprW
    struct (opcode, FourOperands(flmOpr, frbOpr, lOpr, wOpr))
  | b when b &&&
    0b11111100000111111111111111111111u = 0b11111100000000000000000010001100u ->
    let opcode = Opcode.MTFSB0
    let btOpr = Bits.extract bin 25u 21u |> getOprFPSCondBitReg
    struct (opcode, OneOperand(btOpr))
  | b when b &&&
    0b11111100000111111111111111111111u = 0b11111100000000000000000010001101u ->
    let opcode = Opcode.MTFSB0_DOT
    let btOpr = Bits.extract bin 25u 21u |> getOprCondBitReg
    struct (opcode, OneOperand(btOpr))
  | b when b &&&
    0b11111100000111111111111111111111u = 0b11111100000000000000000001001100u ->
    let opcode = Opcode.MTFSB1
    let btOpr = Bits.extract bin 25u 21u |> getOprFPSCondBitReg
    struct (opcode, OneOperand(btOpr))
  | b when b &&&
    0b11111100000111111111111111111111u = 0b11111100000000000000000001001101u ->
    let opcode = Opcode.MTFSB1_DOT
    let btOpr = Bits.extract bin 25u 21u |> getOprCondBitReg
    struct (opcode, OneOperand(btOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000000000000100u ->
    let opcode = Opcode.DADD
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000000000000101u ->
    let opcode = Opcode.DADD_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000000000100u ->
    let opcode = Opcode.DADDQ
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtpOpr, frapOpr, frbpOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000000000101u ->
    let opcode = Opcode.DADDQ_DOT
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtpOpr, frapOpr, frbpOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000010000000100u ->
    let opcode = Opcode.DSUB
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000010000000101u ->
    let opcode = Opcode.DSUB_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000010000000100u ->
    let opcode = Opcode.DSUBQ
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtpOpr, frapOpr, frbpOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000010000000101u ->
    let opcode = Opcode.DSUBQ_DOT
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtpOpr, frapOpr, frbpOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000000001000100u ->
    let opcode = Opcode.DMUL
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000000001000101u ->
    let opcode = Opcode.DMUL_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000001000100u ->
    let opcode = Opcode.DMULQ
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtpOpr, frapOpr, frbpOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000001000101u ->
    let opcode = Opcode.DMULQ_DOT
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtpOpr, frapOpr, frbpOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000010001000100u ->
    let opcode = Opcode.DDIV
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000010001000101u ->
    let opcode = Opcode.DDIV_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000010001000100u ->
    let opcode = Opcode.DDIVQ
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtpOpr, frapOpr, frbpOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000010001000101u ->
    let opcode = Opcode.DDIVQ_DOT
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtpOpr, frapOpr, frbpOpr))
  | b when b &&&
    0b11111100011000000000011111111111u = 0b11101100000000000000010100000100u ->
    let opcode = Opcode.DCMPU
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(bfOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100011000000000011111111111u = 0b11111100000000000000010100000100u ->
    let opcode = Opcode.DCMPUQ
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(bfOpr, frapOpr, frbpOpr))
  | b when b &&&
    0b11111100011000000000011111111111u = 0b11101100000000000000000100000100u ->
    let opcode = Opcode.DCMPO
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(bfOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100011000000000011111111111u = 0b11111100000000000000000100000100u ->
    let opcode = Opcode.DCMPOQ
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(bfOpr, frapOpr, frbpOpr))
  | b when b &&&
    0b11111100011000000000001111111111u = 0b11101100000000000000000110000100u ->
    let opcode = Opcode.DTSTDC
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let dcmOpr = Bits.extract bin 15u 10u |> getOprDCM
    struct (opcode, ThreeOperands(bfOpr, fraOpr, dcmOpr))
  | b when b &&&
    0b11111100011000000000001111111111u = 0b11111100000000000000000110000100u ->
    let opcode = Opcode.DTSTDCQ
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let dcmOpr = Bits.extract bin 15u 10u |> getOprDCM
    struct (opcode, ThreeOperands(bfOpr, frapOpr, dcmOpr))
  | b when b &&&
    0b11111100011000000000001111111111u = 0b11101100000000000000000111000100u ->
    let opcode = Opcode.DTSTDG
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let dgmOpr = Bits.extract bin 15u 10u |> getOprDGM
    struct (opcode, ThreeOperands(bfOpr, fraOpr, dgmOpr))
  | b when b &&&
    0b11111100011000000000001111111111u = 0b11111100000000000000000111000100u ->
    let opcode = Opcode.DTSTDGQ
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let dgmOpr = Bits.extract bin 15u 10u |> getOprDGM
    struct (opcode, ThreeOperands(bfOpr, frapOpr, dgmOpr))
  | b when b &&&
    0b11111100011000000000011111111111u = 0b11101100000000000000000101000100u ->
    let opcode = Opcode.DTSTEX
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(bfOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100011000000000011111111111u = 0b11111100000000000000000101000100u ->
    let opcode = Opcode.DTSTEXQ
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(bfOpr, frapOpr, frbpOpr))
  | b when b &&&
    0b11111100010000000000011111111111u = 0b11101100000000000000010101000100u ->
    let opcode = Opcode.DTSTSF
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let fraOpr = Bits.extract bin 21u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(bfOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100010000000000011111111111u = 0b11111100000000000000010101000100u ->
    let opcode = Opcode.DTSTSFQ
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let fraOpr = Bits.extract bin 21u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(bfOpr, fraOpr, frbpOpr))
  | b when b &&&
    0b11111100010000000000011111111111u = 0b11101100000000000000010101000110u ->
    let opcode = Opcode.DTSTSFI
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let uimOpr = Bits.extract bin 21u 16u |> getOprImm
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(bfOpr, uimOpr, frbOpr))
  | b when b &&&
    0b11111100010000000000011111111111u = 0b11111100000000000000010101000110u ->
    let opcode = Opcode.DTSTSFIQ
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let uimOpr = Bits.extract bin 21u 16u |> getOprImm
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(bfOpr, uimOpr, frbpOpr))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b11101100000000000000000010000110u ->
    let opcode = Opcode.DQUAI
    let teOpr = Bits.extract bin 20u 16u |> getOprImm
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(teOpr, frtOpr, frbOpr, rmcOpr))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b11101100000000000000000010000111u ->
    let opcode = Opcode.DQUAI_DOT
    let teOpr = Bits.extract bin 20u 16u |> getOprImm
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(teOpr, frtOpr, frbOpr, rmcOpr))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b11111100000000000000000010000110u ->
    let opcode = Opcode.DQUAIQ
    let teOpr = Bits.extract bin 20u 16u |> getOprImm
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(teOpr, frtpOpr, frbpOpr, rmcOpr))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b11111100000000000000000010000111u ->
    let opcode = Opcode.DQUAIQ_DOT
    let teOpr = Bits.extract bin 20u 16u |> getOprImm
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(teOpr, frtpOpr, frbpOpr, rmcOpr))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b11101100000000000000000000000110u ->
    let opcode = Opcode.DQUA
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(frtOpr, fraOpr, frbOpr, rmcOpr))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b11101100000000000000000000000111u ->
    let opcode = Opcode.DQUA_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(frtOpr, fraOpr, frbOpr, rmcOpr))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b11111100000000000000000000000110u ->
    let opcode = Opcode.DQUAQ
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(frtpOpr, frapOpr, frbpOpr, rmcOpr))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b11111100000000000000000000000111u ->
    let opcode = Opcode.DQUAQ_DOT
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(frtpOpr, frapOpr, frbpOpr, rmcOpr))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b11101100000000000000000001000111u ->
    let opcode = Opcode.DRRND_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(frtOpr, fraOpr, frbOpr, rmcOpr))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b11111100000000000000000001000110u ->
    let opcode = Opcode.DRRNDQ
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(frtpOpr, fraOpr, frbpOpr, rmcOpr))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b11111100000000000000000001000111u ->
    let opcode = Opcode.DRRNDQ_DOT
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(frtpOpr, fraOpr, frbpOpr, rmcOpr))
  | b when b &&&
    0b11111100000111100000000111111111u = 0b11101100000000000000000011000110u ->
    let opcode = Opcode.DRINTX
    let rOpr = Bits.pick bin 16u |> getOprImm
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(rOpr, frtOpr, frbOpr, rmcOpr))
  | b when b &&&
    0b11111100000111100000000111111111u = 0b11101100000000000000000011000111u ->
    let opcode = Opcode.DRINTX_DOT
    let rOpr = Bits.pick bin 16u |> getOprImm
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(rOpr, frtOpr, frbOpr, rmcOpr))
  | b when b &&&
    0b11111100000111100000000111111111u = 0b11111100000000000000000011000110u ->
    let opcode = Opcode.DRINTXQ
    let rOpr = Bits.pick bin 16u |> getOprImm
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(rOpr, frtpOpr, frbpOpr, rmcOpr))
  | b when b &&&
    0b11111100000111100000000111111111u = 0b11111100000000000000000011000111u ->
    let opcode = Opcode.DRINTXQ_DOT
    let rOpr = Bits.pick bin 16u |> getOprImm
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(rOpr, frtpOpr, frbpOpr, rmcOpr))
  | b when b &&&
    0b11111100000111100000000111111111u = 0b11101100000000000000000111000110u ->
    let opcode = Opcode.DRINTN
    let rOpr = Bits.pick bin 16u |> getOprImm
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(rOpr, frtOpr, frbOpr, rmcOpr))
  | b when b &&&
    0b11111100000111100000000111111111u = 0b11101100000000000000000111000111u ->
    let opcode = Opcode.DRINTN_DOT
    let rOpr = Bits.pick bin 16u |> getOprImm
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(rOpr, frtOpr, frbOpr, rmcOpr))
  | b when b &&&
    0b11111100000111100000000111111111u = 0b11111100000000000000000111000110u ->
    let opcode = Opcode.DRINTNQ
    let rOpr = Bits.pick bin 16u |> getOprImm
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(rOpr, frtpOpr, frbpOpr, rmcOpr))
  | b when b &&&
    0b11111100000111100000000111111111u = 0b11111100000000000000000111000111u ->
    let opcode = Opcode.DRINTNQ_DOT
    let rOpr = Bits.pick bin 16u |> getOprImm
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(rOpr, frtpOpr, frbpOpr, rmcOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000001000000100u ->
    let opcode = Opcode.DCTDP
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000001000000101u ->
    let opcode = Opcode.DCTDP_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001000000100u ->
    let opcode = Opcode.DCTQPQ
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtpOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001000000101u ->
    let opcode = Opcode.DCTQPQ_DOT
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtpOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000011000000100u ->
    let opcode = Opcode.DRSP
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000011000000101u ->
    let opcode = Opcode.DRSP_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011000000100u ->
    let opcode = Opcode.DRDPQ
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtpOpr, frbpOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011000000101u ->
    let opcode = Opcode.DRDPQ_DOT
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtpOpr, frbpOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000011001000100u ->
    let opcode = Opcode.DCFFIX
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000011001000101u ->
    let opcode = Opcode.DCFFIX_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011001000100u ->
    let opcode = Opcode.DCFFIXQ
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtpOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011001000101u ->
    let opcode = Opcode.DCFFIXQ_DOT
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtpOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000001001000100u ->
    let opcode = Opcode.DCTFIX
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000001001000101u ->
    let opcode = Opcode.DCTFIX_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001001000100u ->
    let opcode = Opcode.DCTFIXQ
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbpOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001001000101u ->
    let opcode = Opcode.DCTFIXQ_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbpOpr))
  | b when b &&&
    0b11111100000001110000011111111111u = 0b11101100000000000000001010000100u ->
    let opcode = Opcode.DDEDPD
    let spOpr = Bits.extract bin 20u 19u |> getOprImm
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(spOpr, frtOpr, frbOpr))
  | b when b &&&
    0b11111100000001110000011111111111u = 0b11101100000000000000001010000101u ->
    let opcode = Opcode.DDEDPD_DOT
    let spOpr = Bits.extract bin 20u 19u |> getOprImm
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(spOpr, frtOpr, frbOpr))
  | b when b &&&
    0b11111100000001110000011111111111u = 0b11111100000000000000001010000100u ->
    let opcode = Opcode.DDEDPDQ
    let spOpr = Bits.extract bin 20u 19u |> getOprImm
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(spOpr, frtpOpr, frbpOpr))
  | b when b &&&
    0b11111100000001110000011111111111u = 0b11111100000000000000001010000101u ->
    let opcode = Opcode.DDEDPDQ_DOT
    let spOpr = Bits.extract bin 20u 19u |> getOprImm
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(spOpr, frtpOpr, frbpOpr))
  | b when b &&&
    0b11111100000011110000011111111111u = 0b11101100000000000000011010000100u ->
    let opcode = Opcode.DENBCD
    let sOpr = Bits.pick bin 20u |> getOprImm
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(sOpr, frtOpr, frbOpr))
  | b when b &&&
    0b11111100000011110000011111111111u = 0b11101100000000000000011010000101u ->
    let opcode = Opcode.DENBCD_DOT
    let sOpr = Bits.pick bin 20u |> getOprImm
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(sOpr, frtOpr, frbOpr))
  | b when b &&&
    0b11111100000011110000011111111111u = 0b11111100000000000000011010000100u ->
    let opcode = Opcode.DENBCDQ
    let sOpr = Bits.pick bin 20u |> getOprImm
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(sOpr, frtpOpr, frbpOpr))
  | b when b &&&
    0b11111100000011110000011111111111u = 0b11111100000000000000011010000101u ->
    let opcode = Opcode.DENBCDQ_DOT
    let sOpr = Bits.pick bin 20u |> getOprImm
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(sOpr, frtpOpr, frbpOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000001011000100u ->
    let opcode = Opcode.DXEX
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11101100000000000000001011000101u ->
    let opcode = Opcode.DXEX_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001011000100u ->
    let opcode = Opcode.DXEXQ
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbpOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000001011000101u ->
    let opcode = Opcode.DXEXQ_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, TwoOperands(frtOpr, frbpOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000011011000100u ->
    let opcode = Opcode.DIEX
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11101100000000000000011011000101u ->
    let opcode = Opcode.DIEX_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtOpr, fraOpr, frbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000011011000100u ->
    let opcode = Opcode.DIEXQ
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtpOpr, fraOpr, frbpOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000011011000101u ->
    let opcode = Opcode.DIEXQ_DOT
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbpOpr = Bits.extract bin 15u 11u |> getOprFPReg
    struct (opcode, ThreeOperands(frtpOpr, fraOpr, frbpOpr))
  | b when b &&&
    0b11111100000000000000001111111111u = 0b11101100000000000000000010000100u ->
    let opcode = Opcode.DSCLI
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let shOpr = Bits.extract bin 15u 10u |> getOprImm
    struct (opcode, ThreeOperands(frtOpr, fraOpr, shOpr))
  | b when b &&&
    0b11111100000000000000001111111111u = 0b11101100000000000000000010000101u ->
    let opcode = Opcode.DSCLI_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let shOpr = Bits.extract bin 15u 10u |> getOprImm
    struct (opcode, ThreeOperands(frtOpr, fraOpr, shOpr))
  | b when b &&&
    0b11111100000000000000001111111111u = 0b11111100000000000000000010000100u ->
    let opcode = Opcode.DSCLIQ
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let shOpr = Bits.extract bin 15u 10u |> getOprImm
    struct (opcode, ThreeOperands(frtpOpr, frapOpr, shOpr))
  | b when b &&&
    0b11111100000000000000001111111111u = 0b11111100000000000000000010000101u ->
    let opcode = Opcode.DSCLIQ_DOT
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let shOpr = Bits.extract bin 15u 10u |> getOprImm
    struct (opcode, ThreeOperands(frtpOpr, frapOpr, shOpr))
  | b when b &&&
    0b11111100000000000000001111111111u = 0b11101100000000000000000011000100u ->
    let opcode = Opcode.DSCRI
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let shOpr = Bits.extract bin 15u 10u |> getOprImm
    struct (opcode, ThreeOperands(frtOpr, fraOpr, shOpr))
  | b when b &&&
    0b11111100000000000000001111111111u = 0b11101100000000000000000011000101u ->
    let opcode = Opcode.DSCRI_DOT
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let shOpr = Bits.extract bin 15u 10u |> getOprImm
    struct (opcode, ThreeOperands(frtOpr, fraOpr, shOpr))
  | b when b &&&
    0b11111100000000000000001111111111u = 0b11111100000000000000000011000100u ->
    let opcode = Opcode.DSCRIQ
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let shOpr = Bits.extract bin 15u 10u |> getOprImm
    struct (opcode, ThreeOperands(frtpOpr, frapOpr, shOpr))
  | b when b &&&
    0b11111100000000000000001111111111u = 0b11111100000000000000000011000101u ->
    let opcode = Opcode.DSCRIQ_DOT
    let frtpOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let frapOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let shOpr = Bits.extract bin 15u 10u |> getOprImm
    struct (opcode, ThreeOperands(frtpOpr, frapOpr, shOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000001110u ->
    let opcode = Opcode.LVEBX
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(vrtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000001001110u ->
    let opcode = Opcode.LVEHX
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(vrtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000010001110u ->
    let opcode = Opcode.LVEWX
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(vrtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000011001110u ->
    let opcode = Opcode.LVX
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(vrtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001011001110u ->
    let opcode = Opcode.LVXL
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(vrtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100001110u ->
    let opcode = Opcode.STVEBX
    let vrsOpr = Bits.extract bin 25u 21u |> getOprVReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(vrsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000101001110u ->
    let opcode = Opcode.STVEHX
    let vrsOpr = Bits.extract bin 25u 21u |> getOprVReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(vrsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000110001110u ->
    let opcode = Opcode.STVEWX
    let vrsOpr = Bits.extract bin 25u 21u |> getOprVReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(vrsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000111001110u ->
    let opcode = Opcode.STVX
    let vrsOpr = Bits.extract bin 25u 21u |> getOprVReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(vrsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001111001110u ->
    let opcode = Opcode.STVXL
    let vrsOpr = Bits.extract bin 25u 21u |> getOprVReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(vrsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000001100u ->
    let opcode = Opcode.LVSL
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(vrtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000001001100u ->
    let opcode = Opcode.LVSR
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(vrtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001100001110u ->
    let opcode = Opcode.VPKPX
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010111001110u ->
    let opcode = Opcode.VPKSDSS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010101001110u ->
    let opcode = Opcode.VPKSDUS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000110001110u ->
    let opcode = Opcode.VPKSHSS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000100001110u ->
    let opcode = Opcode.VPKSHUS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000111001110u ->
    let opcode = Opcode.VPKSWSS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000101001110u ->
    let opcode = Opcode.VPKSWUS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010001001110u ->
    let opcode = Opcode.VPKUDUM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010011001110u ->
    let opcode = Opcode.VPKUDUS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000000001110u ->
    let opcode = Opcode.VPKUHUM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000010001110u ->
    let opcode = Opcode.VPKUHUS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000001001110u ->
    let opcode = Opcode.VPKUWUM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000011001110u ->
    let opcode = Opcode.VPKUWUS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000001101001110u ->
    let opcode = Opcode.VUPKHPX
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000001111001110u ->
    let opcode = Opcode.VUPKLPX
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000001000001110u ->
    let opcode = Opcode.VUPKHSB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000001001001110u ->
    let opcode = Opcode.VUPKHSH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000011001001110u ->
    let opcode = Opcode.VUPKHSW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000001010001110u ->
    let opcode = Opcode.VUPKLSB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000001011001110u ->
    let opcode = Opcode.VUPKLSH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000011011001110u ->
    let opcode = Opcode.VUPKLSW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000000001100u ->
    let opcode = Opcode.VMRGHB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000001001100u ->
    let opcode = Opcode.VMRGHH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000100001100u ->
    let opcode = Opcode.VMRGLB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000101001100u ->
    let opcode = Opcode.VMRGLH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000010001100u ->
    let opcode = Opcode.VMRGHW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000110001100u ->
    let opcode = Opcode.VMRGLW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011110001100u ->
    let opcode = Opcode.VMRGEW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011010001100u ->
    let opcode = Opcode.VMRGOW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000100000000011111111111u = 0b010000000000000000001000001100u ->
    let opcode = Opcode.VSPLTB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 19u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000110000000011111111111u = 0b010000000000000000001001001100u ->
    let opcode = Opcode.VSPLTH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 18u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000111000000011111111111u = 0b010000000000000000001010001100u ->
    let opcode = Opcode.VSPLTW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 17u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b010000000000000000001100001100u ->
    let opcode = Opcode.VSPLTISB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let simOpr = extractExtendedField bin 20u 16u 0 |> getOprImm64
    struct (opcode, TwoOperands(vrtOpr, simOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b010000000000000000001101001100u ->
    let opcode = Opcode.VSPLTISH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let simOpr = extractExtendedField bin 20u 16u 0 |> getOprImm64
    struct (opcode, TwoOperands(vrtOpr, simOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b010000000000000000001110001100u ->
    let opcode = Opcode.VSPLTISW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let simOpr = extractExtendedField bin 20u 16u 0 |> getOprImm64
    struct (opcode, TwoOperands(vrtOpr, simOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000101011u ->
    let opcode = Opcode.VPERM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000111011u ->
    let opcode = Opcode.VPERMR
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000101010u ->
    let opcode = Opcode.VSEL
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000010000111111u = 0b010000000000000000000000101100u ->
    let opcode = Opcode.VSLDOI
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let shbOpr = Bits.extract bin 9u 6u |> getOprImm
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, shbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000111000100u ->
    let opcode = Opcode.VSL
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010000001100u ->
    let opcode = Opcode.VSLO
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001011000100u ->
    let opcode = Opcode.VSR
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010001001100u ->
    let opcode = Opcode.VSRO
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011101000100u ->
    let opcode = Opcode.VSLV
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011100000100u ->
    let opcode = Opcode.VSRV
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000100000000011111111111u = 0b010000000000000000001000001101u ->
    let opcode = Opcode.VEXTRACTUB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 19u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000100000000011111111111u = 0b010000000000000000001010001101u ->
    let opcode = Opcode.VEXTRACTUW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 19u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000100000000011111111111u = 0b010000000000000000001001001101u ->
    let opcode = Opcode.VEXTRACTUH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 19u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000100000000011111111111u = 0b010000000000000000001011001101u ->
    let opcode = Opcode.VEXTRACTD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 19u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000100000000011111111111u = 0b010000000000000000001100001101u ->
    let opcode = Opcode.VINSERTB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 19u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000100000000011111111111u = 0b010000000000000000001110001101u ->
    let opcode = Opcode.VINSERTW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 19u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000100000000011111111111u = 0b010000000000000000001101001101u ->
    let opcode = Opcode.VINSERTH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 19u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000100000000011111111111u = 0b010000000000000000001111001101u ->
    let opcode = Opcode.VINSERTD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 19u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000110000000u ->
    let opcode = Opcode.VADDCUW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001100000000u ->
    let opcode = Opcode.VADDSBS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001101000000u ->
    let opcode = Opcode.VADDSHS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001110000000u ->
    let opcode = Opcode.VADDSWS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000000000000u ->
    let opcode = Opcode.VADDUBM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000011000000u ->
    let opcode = Opcode.VADDUDM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000001000000u ->
    let opcode = Opcode.VADDUHM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000010000000u ->
    let opcode = Opcode.VADDUWM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001000000000u ->
    let opcode = Opcode.VADDUBS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001001000000u ->
    let opcode = Opcode.VADDUHS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001010000000u ->
    let opcode = Opcode.VADDUWS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000100000000u ->
    let opcode = Opcode.VADDUQM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000111100u ->
    let opcode = Opcode.VADDEUQM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000101000000u ->
    let opcode = Opcode.VADDCUQ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000111101u ->
    let opcode = Opcode.VADDECUQ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010110000000u ->
    let opcode = Opcode.VSUBCUW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011100000000u ->
    let opcode = Opcode.VSUBSBS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011101000000u ->
    let opcode = Opcode.VSUBSHS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011110000000u ->
    let opcode = Opcode.VSUBSWS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010000000000u ->
    let opcode = Opcode.VSUBUBM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010011000000u ->
    let opcode = Opcode.VSUBUDM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010001000000u ->
    let opcode = Opcode.VSUBUHM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010010000000u ->
    let opcode = Opcode.VSUBUWM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011000000000u ->
    let opcode = Opcode.VSUBUBS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011001000000u ->
    let opcode = Opcode.VSUBUHS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011010000000u ->
    let opcode = Opcode.VSUBUWS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010100000000u ->
    let opcode = Opcode.VSUBUQM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000111110u ->
    let opcode = Opcode.VSUBEUQM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010101000000u ->
    let opcode = Opcode.VSUBCUQ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000111111u ->
    let opcode = Opcode.VSUBECUQ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001100001000u ->
    let opcode = Opcode.VMULESB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001000001000u ->
    let opcode = Opcode.VMULEUB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000100001000u ->
    let opcode = Opcode.VMULOSB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000000001000u ->
    let opcode = Opcode.VMULOUB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001101001000u ->
    let opcode = Opcode.VMULESH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001001001000u ->
    let opcode = Opcode.VMULEUH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000101001000u ->
    let opcode = Opcode.VMULOSH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000001001000u ->
    let opcode = Opcode.VMULOUH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001110001000u ->
    let opcode = Opcode.VMULESW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001010001000u ->
    let opcode = Opcode.VMULEUW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000110001000u ->
    let opcode = Opcode.VMULOSW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000010001000u ->
    let opcode = Opcode.VMULOUW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000010001001u ->
    let opcode = Opcode.VMULUWM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000100000u ->
    let opcode = Opcode.VMHADDSHS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000100001u ->
    let opcode = Opcode.VMHRADDSHS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000100010u ->
    let opcode = Opcode.VMLADDUHM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000100100u ->
    let opcode = Opcode.VMSUMUBM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000100101u ->
    let opcode = Opcode.VMSUMMBM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000101000u ->
    let opcode = Opcode.VMSUMSHM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000101001u ->
    let opcode = Opcode.VMSUMSHS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000100110u ->
    let opcode = Opcode.VMSUMUHM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000100111u ->
    let opcode = Opcode.VMSUMUHS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000100011u ->
    let opcode = Opcode.VMSUMUDM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011110001000u ->
    let opcode = Opcode.VSUMSWS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011010001000u ->
    let opcode = Opcode.VSUM2SWS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011100001000u ->
    let opcode = Opcode.VSUM4SBS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011001001000u ->
    let opcode = Opcode.VSUM4SHS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011000001000u ->
    let opcode = Opcode.VSUM4UBS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000001100000011000000010u ->
    let opcode = Opcode.VNEGW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000001110000011000000010u ->
    let opcode = Opcode.VNEGD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000100000000011000000010u ->
    let opcode = Opcode.VEXTSB2W
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000100010000011000000010u ->
    let opcode = Opcode.VEXTSH2W
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000110000000011000000010u ->
    let opcode = Opcode.VEXTSB2D
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000110010000011000000010u ->
    let opcode = Opcode.VEXTSH2D
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000110100000011000000010u ->
    let opcode = Opcode.VEXTSW2D
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010100000010u ->
    let opcode = Opcode.VAVGSB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010101000010u ->
    let opcode = Opcode.VAVGSH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010110000010u ->
    let opcode = Opcode.VAVGSW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010000000010u ->
    let opcode = Opcode.VAVGUB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010010000010u ->
    let opcode = Opcode.VAVGUW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010001000010u ->
    let opcode = Opcode.VAVGUH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010000000011u ->
    let opcode = Opcode.VABSDUB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010001000011u ->
    let opcode = Opcode.VABSDUH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010010000011u ->
    let opcode = Opcode.VABSDUW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000100000010u ->
    let opcode = Opcode.VMAXSB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000111000010u ->
    let opcode = Opcode.VMAXSD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000000000010u ->
    let opcode = Opcode.VMAXUB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000011000010u ->
    let opcode = Opcode.VMAXUD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000101000010u ->
    let opcode = Opcode.VMAXSH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000110000010u ->
    let opcode = Opcode.VMAXSW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000001000010u ->
    let opcode = Opcode.VMAXUH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000010000010u ->
    let opcode = Opcode.VMAXUW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001100000010u ->
    let opcode = Opcode.VMINSB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001111000010u ->
    let opcode = Opcode.VMINSD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001000000010u ->
    let opcode = Opcode.VMINUB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001011000010u ->
    let opcode = Opcode.VMINUD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001101000010u ->
    let opcode = Opcode.VMINSH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001110000010u ->
    let opcode = Opcode.VMINSW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001001000010u ->
    let opcode = Opcode.VMINUH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001010000010u ->
    let opcode = Opcode.VMINUW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000000000110u ->
    let opcode = Opcode.VCMPEQUB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010000000110u ->
    let opcode = Opcode.VCMPEQUB_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000001000110u ->
    let opcode = Opcode.VCMPEQUH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010001000110u ->
    let opcode = Opcode.VCMPEQUH_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000010000110u ->
    let opcode = Opcode.VCMPEQUW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010010000110u ->
    let opcode = Opcode.VCMPEQUW_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000011000111u ->
    let opcode = Opcode.VCMPEQUD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010011000111u ->
    let opcode = Opcode.VCMPEQUD_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001100000110u ->
    let opcode = Opcode.VCMPGTSB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011100000110u ->
    let opcode = Opcode.VCMPGTSB_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001111000111u ->
    let opcode = Opcode.VCMPGTSD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011111000111u ->
    let opcode = Opcode.VCMPGTSD_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001101000110u ->
    let opcode = Opcode.VCMPGTSH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011101000110u ->
    let opcode = Opcode.VCMPGTSH_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001110000110u ->
    let opcode = Opcode.VCMPGTSW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011110000110u ->
    let opcode = Opcode.VCMPGTSW_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001000000110u ->
    let opcode = Opcode.VCMPGTUB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011000000110u ->
    let opcode = Opcode.VCMPGTUB_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001011000111u ->
    let opcode = Opcode.VCMPGTUD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011011000111u ->
    let opcode = Opcode.VCMPGTUD_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001001000110u ->
    let opcode = Opcode.VCMPGTUH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011001000110u ->
    let opcode = Opcode.VCMPGTUH_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001010000110u ->
    let opcode = Opcode.VCMPGTUW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011010000110u ->
    let opcode = Opcode.VCMPGTUW_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010000000100u ->
    let opcode = Opcode.VAND
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010001000100u ->
    let opcode = Opcode.VANDC
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011010000100u ->
    let opcode = Opcode.VEQV
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010110000100u ->
    let opcode = Opcode.VNAND
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010101000100u ->
    let opcode = Opcode.VORC
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010100000100u ->
    let opcode = Opcode.VNOR
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010010000100u ->
    let opcode = Opcode.VOR
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010011000100u ->
    let opcode = Opcode.VXOR
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000010000000011000000010u ->
    let opcode = Opcode.VPRTYBW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000010010000011000000010u ->
    let opcode = Opcode.VPRTYBD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000010100000011000000010u ->
    let opcode = Opcode.VPRTYBQ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000000000100u ->
    let opcode = Opcode.VRLB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000001000100u ->
    let opcode = Opcode.VRLH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000010000100u ->
    let opcode = Opcode.VRLW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000011000100u ->
    let opcode = Opcode.VRLD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000100000100u ->
    let opcode = Opcode.VSLB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000101000100u ->
    let opcode = Opcode.VSLH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000110000100u ->
    let opcode = Opcode.VSLW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010111000100u ->
    let opcode = Opcode.VSLD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001000000100u ->
    let opcode = Opcode.VSRB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001001000100u ->
    let opcode = Opcode.VSRH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001010000100u ->
    let opcode = Opcode.VSRW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011011000100u ->
    let opcode = Opcode.VSRD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001100000100u ->
    let opcode = Opcode.VSRAB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001101000100u ->
    let opcode = Opcode.VSRAH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001110000100u ->
    let opcode = Opcode.VSRAW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001111000100u ->
    let opcode = Opcode.VSRAD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000110000101u ->
    let opcode = Opcode.VRLWNM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000010000101u ->
    let opcode = Opcode.VRLWMI
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000111000101u ->
    let opcode = Opcode.VRLDNM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000011000101u ->
    let opcode = Opcode.VRLDMI
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000000001010u ->
    let opcode = Opcode.VADDFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000001001010u ->
    let opcode = Opcode.VSUBFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000101110u ->
    let opcode = Opcode.VMADDFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrcOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000101111u ->
    let opcode = Opcode.VNMSUBFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrcOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010000001010u ->
    let opcode = Opcode.VMAXFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010001001010u ->
    let opcode = Opcode.VMINFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001111001010u ->
    let opcode = Opcode.VCTSXS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 20u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001110001010u ->
    let opcode = Opcode.VCTUXS
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 20u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001101001010u ->
    let opcode = Opcode.VCFSX
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 20u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001100001010u ->
    let opcode = Opcode.VCFUX
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let uimOpr = Bits.extract bin 20u 16u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, uimOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000001011001010u ->
    let opcode = Opcode.VRFIM
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000001000001010u ->
    let opcode = Opcode.VRFIN
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000001010001010u ->
    let opcode = Opcode.VRFIP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000001001001010u ->
    let opcode = Opcode.VRFIZ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001111000110u ->
    let opcode = Opcode.VCMPBFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011111000110u ->
    let opcode = Opcode.VCMPBFP_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000011000110u ->
    let opcode = Opcode.VCMPEQFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010011000110u ->
    let opcode = Opcode.VCMPEQFP_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000111000110u ->
    let opcode = Opcode.VCMPGEFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010111000110u ->
    let opcode = Opcode.VCMPGEFP_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001011000110u ->
    let opcode = Opcode.VCMPGTFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011011000110u ->
    let opcode = Opcode.VCMPGTFP_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000000110001010u ->
    let opcode = Opcode.VEXPTEFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000000111001010u ->
    let opcode = Opcode.VLOGEFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000000100001010u ->
    let opcode = Opcode.VREFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000000101001010u ->
    let opcode = Opcode.VRSQRTEFP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010100001000u ->
    let opcode = Opcode.VCIPHER
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010100001001u ->
    let opcode = Opcode.VCIPHERLAST
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010101001000u ->
    let opcode = Opcode.VNCIPHER
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010101001001u ->
    let opcode = Opcode.VNCIPHERLAST
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b010000000000000000010111001000u ->
    let opcode = Opcode.VSBOX
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vraOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011011000010u ->
    let opcode = Opcode.VSHASIGMAD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let stOpr = Bits.pick bin 15u |> getOprImm
    let sixOpr = Bits.extract bin 14u 11u |> getOprImm
    struct (opcode, FourOperands(vrtOpr, vraOpr, stOpr, sixOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011010000010u ->
    let opcode = Opcode.VSHASIGMAW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let stOpr = Bits.pick bin 15u |> getOprImm
    let sixOpr = Bits.extract bin 14u 11u |> getOprImm
    struct (opcode, FourOperands(vrtOpr, vraOpr, stOpr, sixOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010000001000u ->
    let opcode = Opcode.VPMSUMB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010011001000u ->
    let opcode = Opcode.VPMSUMD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010001001000u ->
    let opcode = Opcode.VPMSUMH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010010001000u ->
    let opcode = Opcode.VPMSUMW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000101101u ->
    let opcode = Opcode.VPERMXOR
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let vrcOpr = Bits.extract bin 10u 6u |> getOprVReg
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, vrcOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000010100001100u ->
    let opcode = Opcode.VGBBD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000011100000010u ->
    let opcode = Opcode.VCLZB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000011101000010u ->
    let opcode = Opcode.VCLZH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000011110000010u ->
    let opcode = Opcode.VCLZW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000011111000010u ->
    let opcode = Opcode.VCLZD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000111000000011000000010u ->
    let opcode = Opcode.VCTZB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000111010000011000000010u ->
    let opcode = Opcode.VCTZH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000111100000011000000010u ->
    let opcode = Opcode.VCTZW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000111110000011000000010u ->
    let opcode = Opcode.VCTZD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000011000000010u ->
    let opcode = Opcode.VCLZLSBB
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(rtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000010000011000000010u ->
    let opcode = Opcode.VCTZLSBB
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(rtOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011000001101u ->
    let opcode = Opcode.VEXTUBLX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011001001101u ->
    let opcode = Opcode.VEXTUHLX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011100001101u ->
    let opcode = Opcode.VEXTUBRX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011101001101u ->
    let opcode = Opcode.VEXTUHRX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011010001101u ->
    let opcode = Opcode.VEXTUWLX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000011110001101u ->
    let opcode = Opcode.VEXTUWRX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000011100000011u ->
    let opcode = Opcode.VPOPCNTB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000011111000011u ->
    let opcode = Opcode.VPOPCNTD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000011101000011u ->
    let opcode = Opcode.VPOPCNTH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000011110000011u ->
    let opcode = Opcode.VPOPCNTW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010111001100u ->
    let opcode = Opcode.VBPERMD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010101001100u ->
    let opcode = Opcode.VBPERMQ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000010111111111u = 0b010000000000000000010000000001u ->
    let opcode = Opcode.BCDADD_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let psOpr = Bits.pick bin 9u |> getOprImm
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, psOpr))
  | b when b &&&
    0b11111100000000000000010111111111u = 0b010000000000000000010001000001u ->
    let opcode = Opcode.BCDSUB_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let psOpr = Bits.pick bin 9u |> getOprImm
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, psOpr))
  | b when b &&&
    0b11111100000111110000010111111111u = 0b010000000001110000010110000001u ->
    let opcode = Opcode.BCDCFN_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let psOpr = Bits.pick bin 9u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, psOpr))
  | b when b &&&
    0b11111100000111110000010111111111u = 0b010000000001100000010110000001u ->
    let opcode = Opcode.BCDCFZ_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let psOpr = Bits.pick bin 9u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, psOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000001010000010110000001u ->
    let opcode = Opcode.BCDCTN_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000010111111111u = 0b010000000001000000010110000001u ->
    let opcode = Opcode.BCDCTZ_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let psOpr = Bits.pick bin 9u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, psOpr))
  | b when b &&&
    0b11111100000111110000010111111111u = 0b010000000000100000010110000001u ->
    let opcode = Opcode.BCDCFSQ_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let psOpr = Bits.pick bin 9u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, psOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b010000000000000000010110000001u ->
    let opcode = Opcode.BCDCTSQ_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b010000000000000000001000000001u ->
    let opcode = Opcode.VMUL10UQ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vraOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b010000000000000000000000000001u ->
    let opcode = Opcode.VMUL10CUQ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vraOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001001000001u ->
    let opcode = Opcode.VMUL10EUQ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000001000001u ->
    let opcode = Opcode.VMUL10ECUQ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000001101000001u ->
    let opcode = Opcode.BCDCPSGN_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000010111111111u = 0b010000000111110000010110000001u ->
    let opcode = Opcode.BCDSETSGN_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let psOpr = Bits.pick bin 9u |> getOprImm
    struct (opcode, ThreeOperands(vrtOpr, vrbOpr, psOpr))
  | b when b &&&
    0b11111100000000000000010111111111u = 0b010000000000000000010011000001u ->
    let opcode = Opcode.BCDS_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let psOpr = Bits.pick bin 9u |> getOprImm
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, psOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010010000001u ->
    let opcode = Opcode.BCDUS_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000010111111111u = 0b010000000000000000010111000001u ->
    let opcode = Opcode.BCDSR_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let psOpr = Bits.pick bin 9u |> getOprImm
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, psOpr))
  | b when b &&&
    0b11111100000000000000010111111111u = 0b010000000000000000010100000001u ->
    let opcode = Opcode.BCDTRUNC_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let psOpr = Bits.pick bin 9u |> getOprImm
    struct (opcode, FourOperands(vrtOpr, vraOpr, vrbOpr, psOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010101000001u ->
    let opcode = Opcode.BCDUTRUNC_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111111111111110000011111111111u = 0b010000000000000000011001000100u ->
    let opcode = Opcode.MTVSCR
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, OneOperand(vrbOpr))
  | b when b &&&
    0b11111100000111111111111111111111u = 0b010000000000000000011000000100u ->
    let opcode = Opcode.MFVSCR
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    struct (opcode, OneOperand(vrtOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11100100000000000000000000000010u ->
    let opcode = Opcode.LXSD
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2raOpr = getOprMem ds ra
    struct (opcode, TwoOperands(vrtOpr, ds2raOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000010010011000u ->
    let opcode = Opcode.LXSDX
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000011000011010u ->
    let opcode = Opcode.LXSIBZX
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000011001011010u ->
    let opcode = Opcode.LXSIHZX
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000000010011000u ->
    let opcode = Opcode.LXSIWAX
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000000000011000u ->
    let opcode = Opcode.LXSIWZX
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11100100000000000000000000000011u ->
    let opcode = Opcode.LXSSP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2raOpr = getOprMem ds ra
    struct (opcode, TwoOperands(vrtOpr, ds2raOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000010000011000u ->
    let opcode = Opcode.LXSSPX
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000011011011000u ->
    let opcode = Opcode.LXVB16X
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000011010011000u ->
    let opcode = Opcode.LXVD2X
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000001000011010u ->
    let opcode = Opcode.LXVL
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000001001011010u ->
    let opcode = Opcode.LXVLL
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000111u = 0b11110100000000000000000000000001u ->
    let opcode = Opcode.LXV
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 3u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let ra = Bits.extract bin 20u 16u
    let dq = extractExtendedField bin 15u 4u 4
    let dq2raOpr = getOprMem dq ra
    struct (opcode, TwoOperands(xtOpr, dq2raOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000001000011000u ->
    let opcode = Opcode.LXVX
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000001010011000u ->
    let opcode = Opcode.LXVDSX
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000011001011000u ->
    let opcode = Opcode.LXVH8X
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000011000011000u ->
    let opcode = Opcode.LXVW4X
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000001011011000u ->
    let opcode = Opcode.LXVWSX
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11110100000000000000000000000010u ->
    let opcode = Opcode.STXSD
    let vrsOpr = Bits.extract bin 25u 21u |> getOprVReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2raOpr = getOprMem ds ra
    struct (opcode, TwoOperands(vrsOpr, ds2raOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000010110011000u ->
    let opcode = Opcode.STXSDX
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000011100011010u ->
    let opcode = Opcode.STXSIBX
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000011101011010u ->
    let opcode = Opcode.STXSIHX
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000000100011000u ->
    let opcode = Opcode.STXSIWX
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11110100000000000000000000000011u ->
    let opcode = Opcode.STXSSP
    let vrsOpr = Bits.extract bin 25u 21u |> getOprVReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2raOpr = getOprMem ds ra
    struct (opcode, TwoOperands(vrsOpr, ds2raOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000010100011000u ->
    let opcode = Opcode.STXSSPX
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000011111011000u ->
    let opcode = Opcode.STXVB16X
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000011110011000u ->
    let opcode = Opcode.STXVD2X
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000011101011000u ->
    let opcode = Opcode.STXVH8X
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000011100011000u ->
    let opcode = Opcode.STXVW4X
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000111u = 0b11110100000000000000000000000101u ->
    let opcode = Opcode.STXV
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 3u
    let xsOpr = 32u * sx + s |> getOprVSReg
    let ra = Bits.extract bin 20u 16u
    let dq = extractExtendedField bin 15u 4u 4
    let dq2raOpr = getOprMem dq ra
    struct (opcode, TwoOperands(xsOpr, dq2raOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000001100011010u ->
    let opcode = Opcode.STXVL
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000001101011010u ->
    let opcode = Opcode.STXVLL
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000001100011000u ->
    let opcode = Opcode.STXVX
    let s = Bits.extract bin 25u 21u
    let sx = Bits.pick bin 0u
    let xsOpr = 32u * sx + s |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010101100100u ->
    let opcode = Opcode.XSABSDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000000000011001001000u ->
    let opcode = Opcode.XSABSQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000100000000u ->
    let opcode = Opcode.XSADDDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000000000000u ->
    let opcode = Opcode.XSADDSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000000001000u ->
    let opcode = Opcode.XSADDQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000000001001u ->
    let opcode = Opcode.XSADDQPO
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100011000000000011111111001u = 0b11110000000000000000000111011000u ->
    let opcode = Opcode.XSCMPEXPDP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(bfOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100011000000000011111111111u = 0b11111100000000000000000101001000u ->
    let opcode = Opcode.XSCMPEXPQP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(bfOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000000011000u ->
    let opcode = Opcode.XSCMPEQDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000010011000u ->
    let opcode = Opcode.XSCMPGEDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000001011000u ->
    let opcode = Opcode.XSCMPGTDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100011000000000011111111001u = 0b11110000000000000000000101011000u ->
    let opcode = Opcode.XSCMPODP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(bfOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100011000000000011111111111u = 0b11111100000000000000000100001000u ->
    let opcode = Opcode.XSCMPOQP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(bfOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100011000000000011111111001u = 0b11110000000000000000000100011000u ->
    let opcode = Opcode.XSCMPUDP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(bfOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100011000000000011111111111u = 0b11111100000000000000010100001000u ->
    let opcode = Opcode.XSCMPUQP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(bfOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010110000000u ->
    let opcode = Opcode.XSCPSGNDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000011001000u ->
    let opcode = Opcode.XSCPSGNQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000100010000010101101100u ->
    let opcode = Opcode.XSCVDPHP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000101100000011010001000u ->
    let opcode = Opcode.XSCVDPQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010000100100u ->
    let opcode = Opcode.XSCVDPSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010000101100u ->
    let opcode = Opcode.XSCVDPSPN
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010101100000u ->
    let opcode = Opcode.XSCVDPSXDS
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000000101100000u ->
    let opcode = Opcode.XSCVDPSXWS
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010100100000u ->
    let opcode = Opcode.XSCVDPUXDS
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000000100100000u ->
    let opcode = Opcode.XSCVDPUXWS
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000100000000010101101100u ->
    let opcode = Opcode.XSCVHPDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000101000000011010001000u ->
    let opcode = Opcode.XSCVQPDP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000101000000011010001001u ->
    let opcode = Opcode.XSCVQPDPO
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000110010000011010001000u ->
    let opcode = Opcode.XSCVQPSDZ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000010010000011010001000u ->
    let opcode = Opcode.XSCVQPSWZ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000100010000011010001000u ->
    let opcode = Opcode.XSCVQPUDZ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000010000011010001000u ->
    let opcode = Opcode.XSCVQPUWZ
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000010100000011010001000u ->
    let opcode = Opcode.XSCVSDQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010100100100u ->
    let opcode = Opcode.XSCVSPDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010100101100u ->
    let opcode = Opcode.XSCVSPDPN
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010111100000u ->
    let opcode = Opcode.XSCVSXDDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010011100000u ->
    let opcode = Opcode.XSCVSXDSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000100000011010001000u ->
    let opcode = Opcode.XSCVUDQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010110100000u ->
    let opcode = Opcode.XSCVUXDDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010010100000u ->
    let opcode = Opcode.XSCVUXDSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000111000000u ->
    let opcode = Opcode.XSDIVDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000010001001000u ->
    let opcode = Opcode.XSDIVQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000010001001001u ->
    let opcode = Opcode.XSDIVQPO
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000011000000u ->
    let opcode = Opcode.XSDIVSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b11110000000000000000011100101100u ->
    let opcode = Opcode.XSIEXPDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(xtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000011011001000u ->
    let opcode = Opcode.XSIEXPQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000100001000u ->
    let opcode = Opcode.XSMADDADP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000101001000u ->
    let opcode = Opcode.XSMADDMDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000000001000u ->
    let opcode = Opcode.XSMADDASP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000001001000u ->
    let opcode = Opcode.XSMADDMSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000001100001000u ->
    let opcode = Opcode.XSMADDQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000001100001001u ->
    let opcode = Opcode.XSMADDQPO
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010100000000u ->
    let opcode = Opcode.XSMAXDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010000000000u ->
    let opcode = Opcode.XSMAXCDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010010000000u ->
    let opcode = Opcode.XSMAXJDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010101000000u ->
    let opcode = Opcode.XSMINDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010001000000u ->
    let opcode = Opcode.XSMINCDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010011000000u ->
    let opcode = Opcode.XSMINJDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000110001000u ->
    let opcode = Opcode.XSMSUBADP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000111001000u ->
    let opcode = Opcode.XSMSUBMDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000010001000u ->
    let opcode = Opcode.XSMSUBASP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000011001000u ->
    let opcode = Opcode.XSMSUBMSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000001101001000u ->
    let opcode = Opcode.XSMSUBQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000001101001001u ->
    let opcode = Opcode.XSMSUBQPO
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000110000000u ->
    let opcode = Opcode.XSMULDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000001001000u ->
    let opcode = Opcode.XSMULQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000000001001001u ->
    let opcode = Opcode.XSMULQPO
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000010000000u ->
    let opcode = Opcode.XSMULSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010110100100u ->
    let opcode = Opcode.XSNABSDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000010000000011001001000u ->
    let opcode = Opcode.XSNABSQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010111100100u ->
    let opcode = Opcode.XSNEGDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000100000000011001001000u ->
    let opcode = Opcode.XSNEGQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010100001000u ->
    let opcode = Opcode.XSNMADDADP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010101001000u ->
    let opcode = Opcode.XSNMADDMDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010000001000u ->
    let opcode = Opcode.XSNMADDASP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010001001000u ->
    let opcode = Opcode.XSNMADDMSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000001110001000u ->
    let opcode = Opcode.XSNMADDQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000001110001001u ->
    let opcode = Opcode.XSNMADDQPO
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010110001000u ->
    let opcode = Opcode.XSNMSUBADP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010111001000u ->
    let opcode = Opcode.XSNMSUBMDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010010001000u ->
    let opcode = Opcode.XSNMSUBASP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010011001000u ->
    let opcode = Opcode.XSNMSUBMSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000001111001000u ->
    let opcode = Opcode.XSNMSUBQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000001111001001u ->
    let opcode = Opcode.XSNMSUBQPO
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000000100100100u ->
    let opcode = Opcode.XSRDPI
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000000110101100u ->
    let opcode = Opcode.XSRDPIC
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000000111100100u ->
    let opcode = Opcode.XSRDPIM
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000000110100100u ->
    let opcode = Opcode.XSRDPIP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000000101100100u ->
    let opcode = Opcode.XSRDPIZ
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000000101101000u ->
    let opcode = Opcode.XSREDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000000001101000u ->
    let opcode = Opcode.XSRESP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111100000000111111111u = 0b11111100000000000000000000001010u ->
    let opcode = Opcode.XSRQPI
    let rOpr = Bits.pick bin 16u |> getOprImm
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(rOpr, vrtOpr, vrbOpr, rmcOpr))
  | b when b &&&
    0b11111100000111100000000111111111u = 0b11111100000000000000000000001011u ->
    let opcode = Opcode.XSRQPIX
    let rOpr = Bits.pick bin 16u |> getOprImm
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(rOpr, vrtOpr, vrbOpr, rmcOpr))
  | b when b &&&
    0b11111100000111100000000111111111u = 0b11111100000000000000000001001010u ->
    let opcode = Opcode.XSRQPXP
    let rOpr = Bits.pick bin 16u |> getOprImm
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(rOpr, vrtOpr, vrbOpr, rmcOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000010001100100u ->
    let opcode = Opcode.XSRSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000000100101000u ->
    let opcode = Opcode.XSRSQRTEDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000000000101000u ->
    let opcode = Opcode.XSRSQRTESP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000000100101100u ->
    let opcode = Opcode.XSSQRTDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000110110000011001001000u ->
    let opcode = Opcode.XSSQRTQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000110110000011001001001u ->
    let opcode = Opcode.XSSQRTQPO
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000000000101100u ->
    let opcode = Opcode.XSSQRTSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000101000000u ->
    let opcode = Opcode.XSSUBDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000010000001000u ->
    let opcode = Opcode.XSSUBQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000010000001001u ->
    let opcode = Opcode.XSSUBQPO
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100011000000000011111111001u = 0b11110000000000000000000111101000u ->
    let opcode = Opcode.XSTDIVDP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(bfOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100011111110000011111111101u = 0b11110000000000000000000110101000u ->
    let opcode = Opcode.XSTSQRTDP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(bfOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111101u = 0b11110000000000000000010110101000u ->
    let opcode = Opcode.XSTSTDCDP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    let dcmxOpr = Bits.extract bin 22u 16u |> getOprDCM
    struct (opcode, ThreeOperands(bfOpr, xbOpr, dcmxOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b11111100000000000000010110001000u ->
    let opcode = Opcode.XSTSTDCQP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    let dcmxOpr = Bits.extract bin 22u 16u |> getOprDCM
    struct (opcode, ThreeOperands(bfOpr, vrbOpr, dcmxOpr))
  | b when b &&&
    0b11111100000000000000011111111101u = 0b11110000000000000000010010101000u ->
    let opcode = Opcode.XSTSTDCSP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    let dcmxOpr = Bits.extract bin 22u 16u |> getOprDCM
    struct (opcode, ThreeOperands(bfOpr, xbOpr, dcmxOpr))
  | b when b &&&
    0b11111100000111110000011111111101u = 0b11110000000000000000010101101100u ->
    let opcode = Opcode.XSXEXPDP
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(rtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000000100000011001001000u ->
    let opcode = Opcode.XSXEXPQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111101u = 0b11110000000000010000010101101100u ->
    let opcode = Opcode.XSXSIGDP
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(rtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b11111100000100100000011001001000u ->
    let opcode = Opcode.XSXSIGQP
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, TwoOperands(vrtOpr, vrbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011101100100u ->
    let opcode = Opcode.XVABSDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011001100100u ->
    let opcode = Opcode.XVABSSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001100000000u ->
    let opcode = Opcode.XVADDDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001000000000u ->
    let opcode = Opcode.XVADDSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001100011000u ->
    let opcode = Opcode.XVCMPEQDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011100011000u ->
    let opcode = Opcode.XVCMPEQDP_DOT
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001000011000u ->
    let opcode = Opcode.XVCMPEQSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011000011000u ->
    let opcode = Opcode.XVCMPEQSP_DOT
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001110011000u ->
    let opcode = Opcode.XVCMPGEDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011110011000u ->
    let opcode = Opcode.XVCMPGEDP_DOT
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001010011000u ->
    let opcode = Opcode.XVCMPGESP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011010011000u ->
    let opcode = Opcode.XVCMPGESP_DOT
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001101011000u ->
    let opcode = Opcode.XVCMPGTDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011101011000u ->
    let opcode = Opcode.XVCMPGTDP_DOT
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001001011000u ->
    let opcode = Opcode.XVCMPGTSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011001011000u ->
    let opcode = Opcode.XVCMPGTSP_DOT
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011110000000u ->
    let opcode = Opcode.XVCPSGNDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011010000000u ->
    let opcode = Opcode.XVCPSGNSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011000100100u ->
    let opcode = Opcode.XVCVDPSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011101100000u ->
    let opcode = Opcode.XVCVDPSXDS
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001101100000u ->
    let opcode = Opcode.XVCVDPSXWS
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011100100000u ->
    let opcode = Opcode.XVCVDPUXDS
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001100100000u ->
    let opcode = Opcode.XVCVDPUXWS
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000110000000011101101100u ->
    let opcode = Opcode.XVCVHPSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011100100100u ->
    let opcode = Opcode.XVCVSPDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000110010000011101101100u ->
    let opcode = Opcode.XVCVSPHP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011001100000u ->
    let opcode = Opcode.XVCVSPSXDS
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001001100000u ->
    let opcode = Opcode.XVCVSPSXWS
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011000100000u ->
    let opcode = Opcode.XVCVSPUXDS
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001000100000u ->
    let opcode = Opcode.XVCVSPUXWS
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011111100000u ->
    let opcode = Opcode.XVCVSXDDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011011100000u ->
    let opcode = Opcode.XVCVSXDSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001111100000u ->
    let opcode = Opcode.XVCVSXWDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001011100000u ->
    let opcode = Opcode.XVCVSXWSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011110100000u ->
    let opcode = Opcode.XVCVUXDDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011010100000u ->
    let opcode = Opcode.XVCVUXDSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001110100000u ->
    let opcode = Opcode.XVCVUXWDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001010100000u ->
    let opcode = Opcode.XVCVUXWSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001111000000u ->
    let opcode = Opcode.XVDIVDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001011000000u ->
    let opcode = Opcode.XVDIVSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011111000000u ->
    let opcode = Opcode.XVIEXPDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011011000000u ->
    let opcode = Opcode.XVIEXPSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001100001000u ->
    let opcode = Opcode.XVMADDADP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001101001000u ->
    let opcode = Opcode.XVMADDMDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001000001000u ->
    let opcode = Opcode.XVMADDASP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001001001000u ->
    let opcode = Opcode.XVMADDMSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011100000000u ->
    let opcode = Opcode.XVMAXDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011000000000u ->
    let opcode = Opcode.XVMAXSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011101000000u ->
    let opcode = Opcode.XVMINDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011001000000u ->
    let opcode = Opcode.XVMINSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001110001000u ->
    let opcode = Opcode.XVMSUBADP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001111001000u ->
    let opcode = Opcode.XVMSUBMDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001010001000u ->
    let opcode = Opcode.XVMSUBASP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001011001000u ->
    let opcode = Opcode.XVMSUBMSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001110000000u ->
    let opcode = Opcode.XVMULDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001010000000u ->
    let opcode = Opcode.XVMULSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011110100100u ->
    let opcode = Opcode.XVNABSDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011010100100u ->
    let opcode = Opcode.XVNABSSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011111100100u ->
    let opcode = Opcode.XVNEGDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011011100100u ->
    let opcode = Opcode.XVNEGSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011100001000u ->
    let opcode = Opcode.XVNMADDADP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011101001000u ->
    let opcode = Opcode.XVNMADDMDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011000001000u ->
    let opcode = Opcode.XVNMADDASP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011001001000u ->
    let opcode = Opcode.XVNMADDMSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011110001000u ->
    let opcode = Opcode.XVNMSUBADP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011111001000u ->
    let opcode = Opcode.XVNMSUBMDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011010001000u ->
    let opcode = Opcode.XVNMSUBASP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000011011001000u ->
    let opcode = Opcode.XVNMSUBMSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001100100100u ->
    let opcode = Opcode.XVRDPI
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001110101100u ->
    let opcode = Opcode.XVRDPIC
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001111100100u ->
    let opcode = Opcode.XVRDPIM
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001110100100u ->
    let opcode = Opcode.XVRDPIP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001101100100u ->
    let opcode = Opcode.XVRDPIZ
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001101101000u ->
    let opcode = Opcode.XVREDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001001101000u ->
    let opcode = Opcode.XVRESP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001000100100u ->
    let opcode = Opcode.XVRSPI
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001010101100u ->
    let opcode = Opcode.XVRSPIC
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001011100100u ->
    let opcode = Opcode.XVRSPIM
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001010100100u ->
    let opcode = Opcode.XVRSPIP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001001100100u ->
    let opcode = Opcode.XVRSPIZ
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001100101000u ->
    let opcode = Opcode.XVRSQRTEDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001000101000u ->
    let opcode = Opcode.XVRSQRTESP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001100101100u ->
    let opcode = Opcode.XVSQRTDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000001000101100u ->
    let opcode = Opcode.XVSQRTSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001101000000u ->
    let opcode = Opcode.XVSUBDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000001001000000u ->
    let opcode = Opcode.XVSUBSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100011000000000011111111001u = 0b11110000000000000000001111101000u ->
    let opcode = Opcode.XVTDIVDP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(bfOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100011000000000011111111001u = 0b11110000000000000000001011101000u ->
    let opcode = Opcode.XVTDIVSP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(bfOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100011111110000011111111101u = 0b11110000000000000000001110101000u ->
    let opcode = Opcode.XVTSQRTDP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(bfOpr, xbOpr))
  | b when b &&&
    0b11111100011111110000011111111101u = 0b11110000000000000000001010101000u ->
    let opcode = Opcode.XVTSQRTSP
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(bfOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000000000011101101100u ->
    let opcode = Opcode.XVXEXPDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000010000000011101101100u ->
    let opcode = Opcode.XVXEXPSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000000010000011101101100u ->
    let opcode = Opcode.XVXSIGDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000010010000011101101100u ->
    let opcode = Opcode.XVXSIGSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000101110000011101101100u ->
    let opcode = Opcode.XXBRD
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000001110000011101101100u ->
    let opcode = Opcode.XXBRH
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000111110000011101101100u ->
    let opcode = Opcode.XXBRQ
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000111110000011111111100u = 0b11110000000011110000011101101100u ->
    let opcode = Opcode.XXBRW
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, TwoOperands(xtOpr, xbOpr))
  | b when b &&&
    0b11111100000100000000011111111100u = 0b11110000000000000000001010010100u ->
    let opcode = Opcode.XXEXTRACTUW
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    let uimOpr = Bits.extract bin 19u 16u |> getOprImm
    struct (opcode, ThreeOperands(xtOpr, xbOpr, uimOpr))
  | b when b &&&
    0b11111100000100000000011111111100u = 0b11110000000000000000001011010100u ->
    let opcode = Opcode.XXINSERTW
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    let uimOpr = Bits.extract bin 19u 16u |> getOprImm
    struct (opcode, ThreeOperands(xtOpr, xbOpr, uimOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010000010000u ->
    let opcode = Opcode.XXLAND
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010001010000u ->
    let opcode = Opcode.XXLANDC
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010111010000u ->
    let opcode = Opcode.XXLEQV
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010110010000u ->
    let opcode = Opcode.XXLNAND
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010101010000u ->
    let opcode = Opcode.XXLORC
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010100010000u ->
    let opcode = Opcode.XXLNOR
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010010010000u ->
    let opcode = Opcode.XXLOR
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000010011010000u ->
    let opcode = Opcode.XXLXOR
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000010010000u ->
    let opcode = Opcode.XXMRGHW
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000110010000u ->
    let opcode = Opcode.XXMRGLW
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000010011111000u = 0b11110000000000000000000001010000u ->
    let opcode = Opcode.XXPERMDI
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    let dmOpr = Bits.extract bin 9u 8u |> getOprImm
    struct (opcode, FourOperands(xtOpr, xaOpr, xbOpr, dmOpr))
  | b when b &&&
    0b11111100000000000000000000110000u = 0b11110000000000000000000000110000u ->
    let opcode = Opcode.XXSEL
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    let c = Bits.extract bin 10u 6u
    let cx = Bits.pick bin 3u
    let xcOpr = 32u * cx + c |> getOprVSReg
    struct (opcode, FourOperands(xtOpr, xaOpr, xbOpr, xcOpr))
  | b when b &&&
    0b11111100000000000000010011111000u = 0b11110000000000000000000000010000u ->
    let opcode = Opcode.XXSLDWI
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    let shwOpr = Bits.extract bin 9u 8u |> getOprImm
    struct (opcode, FourOperands(xtOpr, xaOpr, xbOpr, shwOpr))
  | b when b &&&
    0b11111100000110000000011111111110u = 0b11110000000000000000001011010000u ->
    let opcode = Opcode.XXSPLTIB
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let imm8Opr = Bits.extract bin 18u 11u |> getOprImm
    struct (opcode, TwoOperands(xtOpr, imm8Opr))
  | b when b &&&
    0b11111100000111000000011111111100u = 0b11110000000000000000001010010000u ->
    let opcode = Opcode.XXSPLTW
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    let uimOpr = Bits.extract bin 17u 16u |> getOprImm
    struct (opcode, ThreeOperands(xtOpr, xbOpr, uimOpr))
  | b when b &&&
    0b11111111111000000000011111111111u = 0b1111100000000000000011110101100u ->
    let opcode = Opcode.ICBI
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rbOpr))
  | b when b &&&
    0b11111110000000000000011111111111u = 0b1111100000000000000000000101100u ->
    let opcode = Opcode.ICBT
    let ctOpr = Bits.extract bin 24u 21u |> getOprImm
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(ctOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001000101100u ->
    let opcode = Opcode.DCBT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let thOpr = Bits.extract bin 25u 21u |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rbOpr, thOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000111101100u ->
    let opcode = Opcode.DCBTST
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let thOpr = Bits.extract bin 25u 21u |> getOprImm
    struct (opcode, ThreeOperands(raOpr, rbOpr, thOpr))
  | b when b &&&
    0b11111111111000000000011111111111u = 0b1111100000000000000011111101100u ->
    let opcode = Opcode.DCBZ
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rbOpr))
  | b when b &&&
    0b11111111111000000000011111111111u = 0b1111100000000000000000001101100u ->
    let opcode = Opcode.DCBST
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rbOpr))
  | b when b &&&
    0b11111111100000000000011111111111u = 0b1111100000000000000000010101100u ->
    let opcode = Opcode.DCBF
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let lOpr = Bits.extract bin 22u 21u |> getOprL
    struct (opcode, ThreeOperands(raOpr, rbOpr, lOpr))
  | b when b &&&
    0b11111111111111111111111111111111u = 0b1111100000000000000011010001100u ->
    let opcode = Opcode.CPABORT
    struct (opcode, NoOperand)
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010010001100u ->
    let opcode = Opcode.LWAT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let fcOpr = Bits.extract bin 15u 11u |> getOprImm
    struct (opcode, ThreeOperands(rtOpr, raOpr, fcOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010011001100u ->
    let opcode = Opcode.LDAT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let fcOpr = Bits.extract bin 15u 11u |> getOprImm
    struct (opcode, ThreeOperands(rtOpr, raOpr, fcOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010110001100u ->
    let opcode = Opcode.STWAT
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let fcOpr = Bits.extract bin 15u 11u |> getOprImm
    struct (opcode, ThreeOperands(rsOpr, raOpr, fcOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010111001100u ->
    let opcode = Opcode.STDAT
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let fcOpr = Bits.extract bin 15u 11u |> getOprImm
    struct (opcode, ThreeOperands(rsOpr, raOpr, fcOpr))
  | b when b &&&
    0b11111111111111111111111111111111u = 0b1001100000000000000000100101100u ->
    let opcode = Opcode.ISYNC
    struct (opcode, NoOperand)
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000000001101000u ->
    let opcode = Opcode.LBARX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let ehOpr = Bits.pick bin 0u |> getOprImm
    struct (opcode, FourOperands(rtOpr, raOpr, rbOpr, ehOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000000011101000u ->
    let opcode = Opcode.LHARX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let ehOpr = Bits.pick bin 0u |> getOprImm
    struct (opcode, FourOperands(rtOpr, raOpr, rbOpr, ehOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000000000101000u ->
    let opcode = Opcode.LWARX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let ehOpr = Bits.pick bin 0u |> getOprImm
    struct (opcode, FourOperands(rtOpr, raOpr, rbOpr, ehOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010101101101u ->
    let opcode = Opcode.STBCX_DOT
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010110101101u ->
    let opcode = Opcode.STHCX_DOT
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100101101u ->
    let opcode = Opcode.STWCX_DOT
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000000010101000u ->
    let opcode = Opcode.LDARX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let ehOpr = Bits.pick bin 0u |> getOprImm
    struct (opcode, FourOperands(rtOpr, raOpr, rbOpr, ehOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000110101101u ->
    let opcode = Opcode.STDCX_DOT
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111110u = 0b1111100000000000000001000101000u ->
    let opcode = Opcode.LQARX
    let rtpOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let ehOpr = Bits.pick bin 0u |> getOprImm
    struct (opcode, FourOperands(rtpOpr, raOpr, rbOpr, ehOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000101101101u ->
    let opcode = Opcode.STQCX_DOT
    let rspOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rspOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111111100111111111111111111111u = 0b1111100000000000000010010101100u ->
    let opcode = Opcode.SYNC
    let lOpr = Bits.extract bin 22u 21u |> getOprL
    struct (opcode, OneOperand(lOpr))
  | b when b &&&
    0b11111111111111111111111111111111u = 0b1111100000000000000011010101100u ->
    let opcode = Opcode.EIEIO
    struct (opcode, NoOperand)
  | b when b &&&
    0b11111111100111111111111111111111u = 0b1111100000000000000000000111100u ->
    let opcode = Opcode.WAIT
    let wcOpr = Bits.extract bin 22u 21u |> getOprImm
    struct (opcode, OneOperand(wcOpr))
  | b when b &&&
    0b11111101110111111111111111111111u = 0b1111100000000000000010100011101u ->
    let opcode = Opcode.TBEGIN_DOT
    let rOpr = Bits.pick bin 21u |> getOprImm
    struct (opcode, OneOperand(rOpr))
  | b when b &&&
    0b11111101111111111111111111111111u = 0b1111100000000000000010101011101u ->
    let opcode = Opcode.TEND_DOT
    let aOpr = Bits.pick bin 25u |> getOprImm
    struct (opcode, OneOperand(aOpr))
  | b when b &&&
    0b11111111111000001111111111111111u = 0b1111100000000000000011100011101u ->
    let opcode = Opcode.TABORT_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, OneOperand(raOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000011101u ->
    let opcode = Opcode.TABORTWC_DOT
    let toOpr = Bits.extract bin 25u 21u |> getOprTO
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(toOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011010011101u ->
    let opcode = Opcode.TABORTWCI_DOT
    let toOpr = Bits.extract bin 25u 21u |> getOprTO
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = extractExtendedField bin 15u 11u 0 |> getOprImm64
    struct (opcode, ThreeOperands(toOpr, raOpr, siOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011001011101u ->
    let opcode = Opcode.TABORTDC_DOT
    let toOpr = Bits.extract bin 25u 21u |> getOprTO
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(toOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011011011101u ->
    let opcode = Opcode.TABORTDCI_DOT
    let toOpr = Bits.extract bin 25u 21u |> getOprTO
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = extractExtendedField bin 15u 11u 0 |> getOprImm64
    struct (opcode, ThreeOperands(toOpr, raOpr, siOpr))
  | b when b &&&
    0b11111111110111111111111111111111u = 0b1111100000000000000010111011101u ->
    let opcode = Opcode.TSR_DOT
    let lOpr = Bits.pick bin 21u |> getOprL
    struct (opcode, OneOperand(lOpr))
  | b when b &&&
    0b11111100011111111111111111111111u = 0b1111100000000000000010110011100u ->
    let opcode = Opcode.TCHECK
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    struct (opcode, OneOperand(bfOpr))
  | b when b &&&
    0b11111111111111111111011111111111u = 0b1001100000000000000000100100100u ->
    let opcode = Opcode.RFEBB
    let sOpr = Bits.pick bin 11u |> getOprImm
    struct (opcode, OneOperand(sOpr))
  | b when b &&&
    0b11111111111111111111111111111111u = 0b1111100000000000000001101011100u ->
    let opcode = Opcode.CLRBHRB
    struct (opcode, NoOperand)
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001001011100u ->
    let opcode = Opcode.MFBHRBE
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let bhrbeOpr = Bits.extract bin 20u 11u |> getOprImm
    struct (opcode, TwoOperands(rtOpr, bhrbeOpr))
  | b when b &&&
    0b11111111111111111111111111111111u = 0b1001100000000000000000010100100u ->
    let opcode = Opcode.RFSCV
    struct (opcode, NoOperand)
  | b when b &&&
    0b11111111111111111111111111111111u = 0b1001100000000000000000000100100u ->
    let opcode = Opcode.RFID
    struct (opcode, NoOperand)
  | b when b &&&
    0b11111111111111111111111111111111u = 0b1001100000000000000001000100100u ->
    let opcode = Opcode.HRFID
    struct (opcode, NoOperand)
  | b when b &&&
    0b11111111111111111111111111111111u = 0b1001100000000000000001001100100u ->
    let opcode = Opcode.URFID
    struct (opcode, NoOperand)
  | b when b &&&
    0b11111111111111111111111111111111u = 0b1001100000000000000001011100100u ->
    let opcode = Opcode.STOP
    struct (opcode, NoOperand)
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011010101010u ->
    let opcode = Opcode.LBZCIX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000101010u ->
    let opcode = Opcode.LWZCIX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011001101010u ->
    let opcode = Opcode.LHZCIX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011011101010u ->
    let opcode = Opcode.LDCIX
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011110101010u ->
    let opcode = Opcode.STBCIX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011100101010u ->
    let opcode = Opcode.STWCIX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011101101010u ->
    let opcode = Opcode.STHCIX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011111101010u ->
    let opcode = Opcode.STDCIX
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rsOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111111111000001111111111111111u = 0b1111100000000000000011101011101u ->
    let opcode = Opcode.TRECLAIM_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, OneOperand(raOpr))
  | b when b &&&
    0b11111111111111111111111111111111u = 0b1111100000000000000011111011101u ->
    let opcode = Opcode.TRECHKPT_DOT
    struct (opcode, NoOperand)
  | b when b &&&
    0b11111100000111101111111111111111u = 0b1111100000000000000000100100100u ->
    let opcode = Opcode.MTMSR
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let lOpr = Bits.pick bin 16u |> getOprL
    struct (opcode, TwoOperands(rsOpr, lOpr))
  | b when b &&&
    0b11111100000111101111111111111111u = 0b1111100000000000000000101100100u ->
    let opcode = Opcode.MTMSRD
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let lOpr = Bits.pick bin 16u |> getOprL
    struct (opcode, TwoOperands(rsOpr, lOpr))
  | b when b &&&
    0b11111100000111111111111111111111u = 0b1111100000000000000000010100110u ->
    let opcode = Opcode.MFMSR
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, OneOperand(rtOpr))
  | b when b &&&
    0b11111111111111110000011111111111u = 0b1111100000000000000001101100100u ->
    let opcode = Opcode.SLBIE
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, OneOperand(rbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b1111100000000000000001110100100u ->
    let opcode = Opcode.SLBIEG
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, TwoOperands(rsOpr, rbOpr))
  | b when b &&&
    0b11111111000111111111111111111111u = 0b1111100000000000000001111100100u ->
    let opcode = Opcode.SLBIA
    let ihOpr = Bits.extract bin 23u 21u |> getOprImm
    struct (opcode, OneOperand(ihOpr))
  | b when b &&&
    0b11111100000111111111111111111111u = 0b1111100000000000000011010100100u ->
    let opcode = Opcode.SLBIAG
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, OneOperand(rsOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b1111100000000000000001100100100u ->
    let opcode = Opcode.SLBMTE
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, TwoOperands(rsOpr, rbOpr))
  | b when b &&&
    0b11111100000111100000011111111111u = 0b1111100000000000000011010100110u ->
    let opcode = Opcode.SLBMFEV
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, rbOpr))
  | b when b &&&
    0b11111100000111100000011111111111u = 0b1111100000000000000011100100110u ->
    let opcode = Opcode.SLBMFEE
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, rbOpr))
  | b when b &&&
    0b11111100000111110000011111111111u = 0b1111100000000000000011110100111u ->
    let opcode = Opcode.SLBFEE_DOT
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, TwoOperands(rtOpr, rbOpr))
  | b when b &&&
    0b11111111111111111111111111111111u = 0b1111100000000000000001010100100u ->
    let opcode = Opcode.SLBSYNC
    struct (opcode, NoOperand)
  | b when b &&&
    0b11111100000100000000011111111111u = 0b1111100000000000000001001100100u ->
    let opcode = Opcode.TLBIE
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let ricOpr = Bits.extract bin 19u 18u |> getOprImm
    let prsOpr = Bits.pick bin 17u |> getOprImm
    let rOpr = Bits.pick bin 16u |> getOprImm
    struct (opcode, FiveOperands(rbOpr, rsOpr, ricOpr, prsOpr, rOpr))
  | b when b &&&
    0b11111111111111111111111111111111u = 0b1111100000000000000010001101100u ->
    let opcode = Opcode.TLBSYNC
    struct (opcode, NoOperand)
  | b when b &&&
    0b11111111111111110000011111111111u = 0b1111100000000000000000010011100u ->
    let opcode = Opcode.MSGSNDU
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, OneOperand(rbOpr))
  | b when b &&&
    0b11111111111111110000011111111111u = 0b1111100000000000000000011011100u ->
    let opcode = Opcode.MSGCLRU
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, OneOperand(rbOpr))
  | b when b &&&
    0b11111111111111110000011111111111u = 0b1111100000000000000000110011100u ->
    let opcode = Opcode.MSGSND
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, OneOperand(rbOpr))
  | b when b &&&
    0b11111111111111110000011111111111u = 0b1111100000000000000000111011100u ->
    let opcode = Opcode.MSGCLR
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, OneOperand(rbOpr))
  | b when b &&&
    0b11111111111111110000011111111111u = 0b1111100000000000000000100011100u ->
    let opcode = Opcode.MSGSNDP
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, OneOperand(rbOpr))
  | b when b &&&
    0b11111111111111110000011111111111u = 0b1111100000000000000000101011100u ->
    let opcode = Opcode.MSGCLRP
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, OneOperand(rbOpr))
  | b when b &&&
    0b11111111111111111111111111111111u = 0b1111100000000000000011011101100u ->
    let opcode = Opcode.MSGSYNC
    struct (opcode, NoOperand)
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000110000u ->
    let opcode = Opcode.MADDHD
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let rcOpr = Bits.extract bin 10u 6u |> getOprReg
    struct (opcode, FourOperands(rtOpr, raOpr, rbOpr, rcOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000110001u ->
    let opcode = Opcode.MADDHDU
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let rcOpr = Bits.extract bin 10u 6u |> getOprReg
    struct (opcode, FourOperands(rtOpr, raOpr, rbOpr, rcOpr))
  | b when b &&&
    0b11111100000000000000000000111111u = 0b010000000000000000000000110011u ->
    let opcode = Opcode.MADDLD
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let rcOpr = Bits.extract bin 10u 6u |> getOprReg
    struct (opcode, FourOperands(rtOpr, raOpr, rbOpr, rcOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000111111000u ->
    let opcode = Opcode.BPERMD
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000011110111000u = 0b11110000000000000000011110101000u ->
    let opcode = Opcode.XVTSTDCDP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    let dc = Bits.pick bin 6u
    let dm = Bits.pick bin 2u
    let dx = Bits.extract bin 20u 16u
    let dcmxOpr = Bits.concat dc (Bits.concat dm dx 5) 6 |> getOprDCM
    struct (opcode, ThreeOperands(xtOpr, xbOpr, dcmxOpr))
  | b when b &&&
    0b11111100000000000000011110111000u = 0b11110000000000000000011010101000u ->
    let opcode = Opcode.XVTSTDCSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    let dc = Bits.pick bin 6u
    let dm = Bits.pick bin 2u
    let dx = Bits.extract bin 20u 16u
    let dcmxOpr = Bits.concat dc (Bits.concat dm dx 5) 6 |> getOprDCM
    struct (opcode, ThreeOperands(xtOpr, xbOpr, dcmxOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000011010000u ->
    let opcode = Opcode.XXPERM
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000111010000u ->
    let opcode = Opcode.XXPERMR
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000001000110100u ->
    let opcode = Opcode.CDTBCD
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000001001110100u ->
    let opcode = Opcode.CBCDTD
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rsOpr))
  | b when b &&&
    0b11111100000100000000011111111111u = 0b1111100000000000000001000100100u ->
    let opcode = Opcode.TLBIEL
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let ricOpr = Bits.extract bin 19u 18u |> getOprImm
    let prsOpr = Bits.pick bin 17u |> getOprImm
    let rOpr = Bits.pick bin 16u |> getOprImm
    struct (opcode, FiveOperands(rbOpr, rsOpr, ricOpr, prsOpr, rOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001011100110u ->
    let opcode = Opcode.MFTB
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let tbrOpr = Bits.extract bin 20u 11u |> getOprImm
    struct (opcode, TwoOperands(rtOpr, tbrOpr))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b11101100000000000000000001000110u ->
    let opcode = Opcode.DRRND
    let frtOpr = Bits.extract bin 25u 21u |> getOprFPReg
    let fraOpr = Bits.extract bin 20u 16u |> getOprFPReg
    let frbOpr = Bits.extract bin 15u 11u |> getOprFPReg
    let rmcOpr = Bits.extract bin 10u 9u |> getOprImm
    struct (opcode, FourOperands(frtOpr, fraOpr, frbOpr, rmcOpr))
  | b when b &&&
    0b11111100000000000000000000111110u = 0b1001100000000000000000000000100u ->
    let opcode = Opcode.ADDPCIS
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let d0 = Bits.extract bin 15u 6u
    let d1 = Bits.extract bin 20u 16u
    let d2 = Bits.pick bin 0u
    let d = Bits.concat d0 (Bits.concat d1 d2 1) 6 |> uint64
    let dOpr = Bits.signExtend 16 64 d |> getOprImm64
    struct (opcode, TwoOperands(rtOpr, dOpr))
  | b when b &&&
    0b11111100000000000000011111111000u = 0b11110000000000000000000001000000u ->
    let opcode = Opcode.XSSUBSP
    let t = Bits.extract bin 25u 21u
    let tx = Bits.pick bin 0u
    let xtOpr = 32u * tx + t |> getOprVSReg
    let a = Bits.extract bin 20u 16u
    let ax = Bits.pick bin 2u
    let xaOpr = 32u * ax + a |> getOprVSReg
    let b = Bits.extract bin 15u 11u
    let bx = Bits.pick bin 1u
    let xbOpr = 32u * bx + b |> getOprVSReg
    struct (opcode, ThreeOperands(xtOpr, xaOpr, xbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000000000111u ->
    let opcode = Opcode.VCMPNEB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010000000111u ->
    let opcode = Opcode.VCMPNEB_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000100000111u ->
    let opcode = Opcode.VCMPNEZB
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010100000111u ->
    let opcode = Opcode.VCMPNEZB_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000001000111u ->
    let opcode = Opcode.VCMPNEH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010001000111u ->
    let opcode = Opcode.VCMPNEH_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000101000111u ->
    let opcode = Opcode.VCMPNEZH
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010101000111u ->
    let opcode = Opcode.VCMPNEZH_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000010000111u ->
    let opcode = Opcode.VCMPNEW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010010000111u ->
    let opcode = Opcode.VCMPNEW_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000000110000111u ->
    let opcode = Opcode.VCMPNEZW
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b010000000000000000010110000111u ->
    let opcode = Opcode.VCMPNEZW_DOT
    let vrtOpr = Bits.extract bin 25u 21u |> getOprVReg
    let vraOpr = Bits.extract bin 20u 16u |> getOprVReg
    let vrbOpr = Bits.extract bin 15u 11u |> getOprVReg
    struct (opcode, ThreeOperands(vrtOpr, vraOpr, vrbOpr))
  | b when b &&&
    0b11111111111000000000011111111111u = 0b1111100001000000000011000001100u ->
    let opcode = Opcode.COPY
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rbOpr))
  | b when b &&&
    0b11111111111000000000011111111111u = 0b1111100001000000000011100001101u ->
    let opcode = Opcode.PASTE_DOT
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, TwoOperands(raOpr, rbOpr))
  | b when b &&&
    0b11111100000111001111111111111111u = 0b1111100000000000000010111100110u ->
    let opcode = Opcode.DARN
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let lOpr = Bits.extract bin 17u 16u |> getOprL
    struct (opcode, TwoOperands(rtOpr, lOpr))
  | _ -> raise ParsingFailureException

let parse lifter (span: ByteSpan) (reader: IBinReader) (addr: Addr) =
  let bin = reader.ReadUInt32(span, 0)
  let struct (opcode, operands) = parseInstruction bin addr
  Instruction(addr, 4u, opcode, operands, 64<rt>, 0UL, lifter)
