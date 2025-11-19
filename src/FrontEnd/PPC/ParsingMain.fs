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
  | 0b0010000000u -> Register.TFHAR
  | 0b0010000001u -> Register.TFIAR
  | 0b0010000010u -> Register.TEXASR
  | 0b0010000011u -> Register.TEXASRU
  | 0b0010001000u -> Register.CTRL
  | 0b0100000000u -> Register.VRSAVE
  | 0b0100000011u -> Register.SPRG3
  | 0b0100001100u -> Register.TB
  | 0b0100001101u -> Register.TBU
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
  | 0b1100101111u -> Register.TAR
  | 0b1110000000u -> Register.PPR
  | 0b1110000010u -> Register.PPR32
  | _ -> Terminator.futureFeature ()

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
    0b11111100000000000000011111111111u = 0b1111100000000000000000010010100u ->
    let opcode = Opcode.ADDG6S
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rtOpr, raOpr, rbOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1001000000000000000000000000000u ->
    let opcode = Opcode.B
    let targetaddrOpr = addr + extractExtendedField bin 25u 2u 2 |> getOprAddr
    struct (opcode, OneOperand(targetaddrOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1001000000000000000000000000010u ->
    let opcode = Opcode.BA
    let targetaddrOpr = extractExtendedField bin 25u 2u 2 |> getOprAddr
    struct (opcode, OneOperand(targetaddrOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1001000000000000000000000000001u ->
    let opcode = Opcode.BL
    let targetaddrOpr = addr + extractExtendedField bin 25u 2u 2 |> getOprAddr
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
    let biOpr = Bits.extract bin 20u 16u |> getOprBI
    let targetaddrOpr = addr + extractExtendedField bin 15u 2u 2 |> getOprAddr
    struct (opcode, ThreeOperands(boOpr, biOpr, targetaddrOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1000000000000000000000000000010u ->
    let opcode = Opcode.BCA
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprBI
    let targetaddrOpr = extractExtendedField bin 15u 2u 2 |> getOprAddr
    struct (opcode, ThreeOperands(boOpr, biOpr, targetaddrOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1000000000000000000000000000001u ->
    let opcode = Opcode.BCL
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprBI
    let targetaddrOpr = addr + extractExtendedField bin 15u 2u 2 |> getOprAddr
    struct (opcode, ThreeOperands(boOpr, biOpr, targetaddrOpr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1000000000000000000000000000011u ->
    let opcode = Opcode.BCLA
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprBI
    let targetaddrOpr = extractExtendedField bin 15u 2u 2 |> getOprAddr
    struct (opcode, ThreeOperands(boOpr, biOpr, targetaddrOpr))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000000000100000u ->
    let opcode = Opcode.BCLR
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprBI
    let bhOpr = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(boOpr, biOpr, bhOpr))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000000000100001u ->
    let opcode = Opcode.BCLRL
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprBI
    let bhOpr = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(boOpr, biOpr, bhOpr))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000010000100000u ->
    let opcode = Opcode.BCCTR
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprBI
    let bhOpr = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(boOpr, biOpr, bhOpr))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000010000100001u ->
    let opcode = Opcode.BCCTRL
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprBI
    let bhOpr = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(boOpr, biOpr, bhOpr))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000010001100000u ->
    let opcode = Opcode.BCTAR
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprBI
    let bhOpr = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(boOpr, biOpr, bhOpr))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000010001100001u ->
    let opcode = Opcode.BCTARL
    let boOpr = Bits.extract bin 25u 21u |> getOprBO
    let biOpr = Bits.extract bin 20u 16u |> getOprBI
    let bhOpr = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(boOpr, biOpr, bhOpr))
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
    0b11111100000000000000000000000000u = 0b111000000000000000000000000000u ->
    let opcode = Opcode.ADDI
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(rtOpr, raOpr, siOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b111100000000000000000000000000u ->
    let opcode = Opcode.ADDIS
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(rtOpr, raOpr, siOpr))
  | b when b &&&
    0b11111100000000000000000000111110u = 0b1001100000000000000000000000100u ->
    let opcode = Opcode.ADDPCIS
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let d0 = Bits.extract bin 15u 6u
    let d1 = Bits.extract bin 20u 16u
    let d2 = Bits.pick bin 0u
    let dOpr = Bits.concat d0 (Bits.concat d1 d2 1) 6 |> getOprImm
    struct (opcode, TwoOperands(rtOpr, dOpr))
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
    let siOpr = Bits.extract bin 15u 0u |> getOprImm
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
    let siOpr = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(rtOpr, raOpr, siOpr))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b100000000000000000000000000000u ->
    let opcode = Opcode.SUBFIC
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = Bits.extract bin 15u 0u |> getOprImm
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
    let siOpr = Bits.extract bin 15u 0u |> getOprImm
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
    0b11111100000111001111111111111111u = 0b1111100000000000000010111100110u ->
    let opcode = Opcode.DARN
    let rtOpr = Bits.extract bin 25u 21u |> getOprReg
    let lOpr = Bits.extract bin 17u 16u |> getOprL
    struct (opcode, TwoOperands(rtOpr, lOpr))
  | b when b &&&
    0b11111100010000000000000000000000u = 0b101100000000000000000000000000u ->
    let opcode = Opcode.CMPI
    let bfOpr = Bits.extract bin 25u 23u |> getOprCondReg
    let lOpr = Bits.pick bin 21u |> getOprL
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = Bits.extract bin 15u 0u |> getOprImm
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
    0b11111100000000000000011111111111u = 0b1111100000000000000000111111000u ->
    let opcode = Opcode.BPERMD
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let rsOpr = Bits.extract bin 25u 21u |> getOprReg
    let rbOpr = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(raOpr, rsOpr, rbOpr))
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
    0b11111100000000000000000000000000u = 0b001100000000000000000000000000u ->
    let opcode = Opcode.TWI
    let toOpr = Bits.extract bin 25u 21u |> getOprTO
    let raOpr = Bits.extract bin 20u 16u |> getOprReg
    let siOpr = Bits.extract bin 15u 0u |> getOprImm
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
    let siOpr = Bits.extract bin 15u 0u |> getOprImm
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
  | _ -> Terminator.futureFeature ()

let parse lifter (span: ByteSpan) (reader: IBinReader) (addr: Addr) =
  let bin = reader.ReadUInt32(span, 0)
  let struct (opcode, operands) = parseInstruction bin addr
  Instruction(addr, 4u, opcode, operands, 64<rt>, 0UL, lifter)
