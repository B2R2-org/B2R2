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

let extractExtendedField (bin: uint32) ofs1 ofs2 shift =
  let v = Bits.extract bin ofs1 ofs2
  let sz = (max ofs1 ofs2 - min ofs1 ofs2 + 1u |> int) + shift
  Bits.signExtend sz 64 (v |> uint64 <<< shift)

let parseInstruction (bin: uint32) (addr: Addr) =
  match bin with
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1001000000000000000000000000000u ->
    let opcode = Opcode.B
    let targetaddr = addr + extractExtendedField bin 25u 2u 2 |> getOprAddr
    struct (opcode, OneOperand(targetaddr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1001000000000000000000000000010u ->
    let opcode = Opcode.BA
    let targetaddr = extractExtendedField bin 25u 2u 2 |> getOprAddr
    struct (opcode, OneOperand(targetaddr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1001000000000000000000000000001u ->
    let opcode = Opcode.BL
    let targetaddr = addr + extractExtendedField bin 25u 2u 2 |> getOprAddr
    struct (opcode, OneOperand(targetaddr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1001000000000000000000000000011u ->
    let opcode = Opcode.BLA
    let targetaddr = extractExtendedField bin 25u 2u 2 |> getOprAddr
    struct (opcode, OneOperand(targetaddr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1000000000000000000000000000000u ->
    let opcode = Opcode.BC
    let bo = Bits.extract bin 25u 21u |> getOprBO
    let bi = Bits.extract bin 20u 16u |> getOprBI
    let targetaddr = addr + extractExtendedField bin 15u 2u 2 |> getOprAddr
    struct (opcode, ThreeOperands(bo, bi, targetaddr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1000000000000000000000000000010u ->
    let opcode = Opcode.BCA
    let bo = Bits.extract bin 25u 21u |> getOprBO
    let bi = Bits.extract bin 20u 16u |> getOprBI
    let targetaddr = extractExtendedField bin 15u 2u 2 |> getOprAddr
    struct (opcode, ThreeOperands(bo, bi, targetaddr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1000000000000000000000000000001u ->
    let opcode = Opcode.BCL
    let bo = Bits.extract bin 25u 21u |> getOprBO
    let bi = Bits.extract bin 20u 16u |> getOprBI
    let targetaddr = addr + extractExtendedField bin 15u 2u 2 |> getOprAddr
    struct (opcode, ThreeOperands(bo, bi, targetaddr))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b1000000000000000000000000000011u ->
    let opcode = Opcode.BCLA
    let bo = Bits.extract bin 25u 21u |> getOprBO
    let bi = Bits.extract bin 20u 16u |> getOprBI
    let targetaddr = extractExtendedField bin 15u 2u 2 |> getOprAddr
    struct (opcode, ThreeOperands(bo, bi, targetaddr))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000000000100000u ->
    let opcode = Opcode.BCLR
    let bo = Bits.extract bin 25u 21u |> getOprBO
    let bi = Bits.extract bin 20u 16u |> getOprBI
    let bh = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(bo, bi, bh))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000000000100001u ->
    let opcode = Opcode.BCLRL
    let bo = Bits.extract bin 25u 21u |> getOprBO
    let bi = Bits.extract bin 20u 16u |> getOprBI
    let bh = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(bo, bi, bh))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000010000100000u ->
    let opcode = Opcode.BCCTR
    let bo = Bits.extract bin 25u 21u |> getOprBO
    let bi = Bits.extract bin 20u 16u |> getOprBI
    let bh = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(bo, bi, bh))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000010000100001u ->
    let opcode = Opcode.BCCTRL
    let bo = Bits.extract bin 25u 21u |> getOprBO
    let bi = Bits.extract bin 20u 16u |> getOprBI
    let bh = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(bo, bi, bh))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000010001100000u ->
    let opcode = Opcode.BCTAR
    let bo = Bits.extract bin 25u 21u |> getOprBO
    let bi = Bits.extract bin 20u 16u |> getOprBI
    let bh = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(bo, bi, bh))
  | b when b &&&
    0b11111100000000001110011111111111u = 0b1001100000000000000010001100001u ->
    let opcode = Opcode.BCTARL
    let bo = Bits.extract bin 25u 21u |> getOprBO
    let bi = Bits.extract bin 20u 16u |> getOprBI
    let bh = Bits.extract bin 12u 11u |> getOprBH
    struct (opcode, ThreeOperands(bo, bi, bh))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b111000000000000000000000000000u ->
    let opcode = Opcode.ADDI
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let si = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(rt, ra, si))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b111100000000000000000000000000u ->
    let opcode = Opcode.ADDIS
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let si = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(rt, ra, si))
  | b when b &&&
    0b11111100000000000000000000111110u = 0b1001100000000000000000000000100u ->
    let opcode = Opcode.ADDPCIS
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let d0 = Bits.extract bin 15u 6u
    let d1 = Bits.extract bin 20u 16u
    let d2 = Bits.pick bin 0u
    let d = Bits.concat d0 (Bits.concat d1 d2 1) 6 |> getOprImm
    struct (opcode, TwoOperands(rt, d))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001000010100u ->
    let opcode = Opcode.ADD
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001000010101u ->
    let opcode = Opcode.ADD_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000010100u ->
    let opcode = Opcode.ADDO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000010101u ->
    let opcode = Opcode.ADDO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b110000000000000000000000000000u ->
    let opcode = Opcode.ADDIC
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let si = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(rt, ra, si))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000001010000u ->
    let opcode = Opcode.SUBF
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000001010001u ->
    let opcode = Opcode.SUBF_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010001010000u ->
    let opcode = Opcode.SUBFO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010001010001u ->
    let opcode = Opcode.SUBFO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b110100000000000000000000000000u ->
    let opcode = Opcode.ADDIC_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let si = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(rt, ra, si))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b100000000000000000000000000000u ->
    let opcode = Opcode.SUBFIC
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let si = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(rt, ra, si))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010100u ->
    let opcode = Opcode.ADDC
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010101u ->
    let opcode = Opcode.ADDC_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000010100u ->
    let opcode = Opcode.ADDCO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000010101u ->
    let opcode = Opcode.ADDCO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010000u ->
    let opcode = Opcode.SUBFC
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010001u ->
    let opcode = Opcode.SUBFC_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000010000u ->
    let opcode = Opcode.SUBFCO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000010001u ->
    let opcode = Opcode.SUBFCO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100010100u ->
    let opcode = Opcode.ADDE
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100010101u ->
    let opcode = Opcode.ADDE_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100010100u ->
    let opcode = Opcode.ADDEO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100010101u ->
    let opcode = Opcode.ADDEO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000111010100u ->
    let opcode = Opcode.ADDME
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000111010101u ->
    let opcode = Opcode.ADDME_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010111010100u ->
    let opcode = Opcode.ADDMEO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010111010101u ->
    let opcode = Opcode.ADDMEO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100010000u ->
    let opcode = Opcode.SUBFE
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100010001u ->
    let opcode = Opcode.SUBFE_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100010000u ->
    let opcode = Opcode.SUBFEO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100010001u ->
    let opcode = Opcode.SUBFEO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000111010000u ->
    let opcode = Opcode.SUBFME
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000111010001u ->
    let opcode = Opcode.SUBFME_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010111010000u ->
    let opcode = Opcode.SUBFMEO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010111010001u ->
    let opcode = Opcode.SUBFMEO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000000000000111111111u = 0b1111100000000000000000101010100u ->
    let opcode = Opcode.ADDEX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    let cy = Bits.extract bin 10u 9u |> getOprCY
    struct (opcode, FourOperands(rt, ra, rb, cy))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000110010100u ->
    let opcode = Opcode.ADDZE
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000110010101u ->
    let opcode = Opcode.ADDZE_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010110010100u ->
    let opcode = Opcode.ADDZEO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010110010101u ->
    let opcode = Opcode.ADDZEO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000110010000u ->
    let opcode = Opcode.SUBFZE
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000110010001u ->
    let opcode = Opcode.SUBFZE_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010110010000u ->
    let opcode = Opcode.SUBFZEO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010110010001u ->
    let opcode = Opcode.SUBFZEO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000011010000u ->
    let opcode = Opcode.NEG
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000000011010001u ->
    let opcode = Opcode.NEG_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010011010000u ->
    let opcode = Opcode.NEGO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000001111111111111111u = 0b1111100000000000000010011010001u ->
    let opcode = Opcode.NEGO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    struct (opcode, TwoOperands(rt, ra))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b011100000000000000000000000000u ->
    let opcode = Opcode.MULLI
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let si = Bits.extract bin 15u 0u |> getOprImm
    struct (opcode, ThreeOperands(rt, ra, si))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000111010110u ->
    let opcode = Opcode.MULLW
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000111010111u ->
    let opcode = Opcode.MULLW_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010111010110u ->
    let opcode = Opcode.MULLWO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010111010111u ->
    let opcode = Opcode.MULLWO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000010010110u ->
    let opcode = Opcode.MULHW
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000010010111u ->
    let opcode = Opcode.MULHW_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010110u ->
    let opcode = Opcode.MULHWU
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000010111u ->
    let opcode = Opcode.MULHWU_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001111010110u ->
    let opcode = Opcode.DIVW
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001111010111u ->
    let opcode = Opcode.DIVW_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011111010110u ->
    let opcode = Opcode.DIVWO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011111010111u ->
    let opcode = Opcode.DIVWO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001110010110u ->
    let opcode = Opcode.DIVWU
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001110010111u ->
    let opcode = Opcode.DIVWU_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011110010110u ->
    let opcode = Opcode.DIVWUO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011110010111u ->
    let opcode = Opcode.DIVWUO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001101010110u ->
    let opcode = Opcode.DIVWE
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001101010111u ->
    let opcode = Opcode.DIVWE_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011101010110u ->
    let opcode = Opcode.DIVWEO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011101010111u ->
    let opcode = Opcode.DIVWEO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001100010110u ->
    let opcode = Opcode.DIVWEU
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001100010111u ->
    let opcode = Opcode.DIVWEU_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011100010110u ->
    let opcode = Opcode.DIVWEUO
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011100010111u ->
    let opcode = Opcode.DIVWEUO_DOT
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000010110u ->
    let opcode = Opcode.MODSW
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001000010110u ->
    let opcode = Opcode.MODUW
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000111001111111111111111u = 0b1111100000000000000010111100110u ->
    let opcode = Opcode.DARN
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let l = Bits.extract bin 17u 16u |> getOprL
    struct (opcode, TwoOperands(rt, l))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10001000000000000000000000000000u ->
    let opcode = Opcode.LBZ
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rt, d2ra))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10001100000000000000000000000000u ->
    let opcode = Opcode.LBZU
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rt, d2ra))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000010101110u ->
    let opcode = Opcode.LBZX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000011101110u ->
    let opcode = Opcode.LBZUX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10100000000000000000000000000000u ->
    let opcode = Opcode.LHZ
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rt, d2ra))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10100100000000000000000000000000u ->
    let opcode = Opcode.LHZU
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rt, d2ra))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001000101110u ->
    let opcode = Opcode.LHZX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001001101110u ->
    let opcode = Opcode.LHZUX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10101000000000000000000000000000u ->
    let opcode = Opcode.LHA
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rt, d2ra))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10101100000000000000000000000000u ->
    let opcode = Opcode.LHAU
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rt, d2ra))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001010101110u ->
    let opcode = Opcode.LHAX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001011101110u ->
    let opcode = Opcode.LHAUX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10000000000000000000000000000000u ->
    let opcode = Opcode.LWZ
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rt, d2ra))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10000100000000000000000000000000u ->
    let opcode = Opcode.LWZU
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rt, d2ra))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000101110u ->
    let opcode = Opcode.LWZX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000001101110u ->
    let opcode = Opcode.LWZUX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11101000000000000000000000000010u ->
    let opcode = Opcode.LWA
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2ra = getOprMem ds ra
    struct (opcode, TwoOperands(rt, ds2ra))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001010101010u ->
    let opcode = Opcode.LWAX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001011101010u ->
    let opcode = Opcode.LWAUX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11101000000000000000000000000000u ->
    let opcode = Opcode.LD
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2ra = getOprMem ds ra
    struct (opcode, TwoOperands(rt, ds2ra))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11101000000000000000000000000001u ->
    let opcode = Opcode.LDU
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2ra = getOprMem ds ra
    struct (opcode, TwoOperands(rt, ds2ra))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000000101010u ->
    let opcode = Opcode.LDX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000001101010u ->
    let opcode = Opcode.LDUX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10011000000000000000000000000000u ->
    let opcode = Opcode.STB
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rs, d2ra))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10011100000000000000000000000000u ->
    let opcode = Opcode.STBU
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rs, d2ra))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000110101110u ->
    let opcode = Opcode.STBX
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rs, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000111101110u ->
    let opcode = Opcode.STBUX
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rs, ra, rb))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10110000000000000000000000000000u ->
    let opcode = Opcode.STH
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rs, d2ra))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10110100000000000000000000000000u ->
    let opcode = Opcode.STHU
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rs, d2ra))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001100101110u ->
    let opcode = Opcode.STHX
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rs, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000001101101110u ->
    let opcode = Opcode.STHUX
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rs, ra, rb))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10010000000000000000000000000000u ->
    let opcode = Opcode.STW
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rs, d2ra))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10010100000000000000000000000000u ->
    let opcode = Opcode.STWU
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rs, d2ra))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100101110u ->
    let opcode = Opcode.STWX
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rs, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000101101110u ->
    let opcode = Opcode.STWUX
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rs, ra, rb))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11111000000000000000000000000000u ->
    let opcode = Opcode.STD
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2ra = getOprMem ds ra
    struct (opcode, TwoOperands(rs, ds2ra))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11111000000000000000000000000001u ->
    let opcode = Opcode.STDU
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2ra = getOprMem ds ra
    struct (opcode, TwoOperands(rs, ds2ra))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000100101010u ->
    let opcode = Opcode.STDX
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rs, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000000101101010u ->
    let opcode = Opcode.STDUX
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rs, ra, rb))
  | b when b &&&
    0b11111100000000000000000000001111u = 0b11100000000000000000000000000000u ->
    let opcode = Opcode.LQ
    let rtp = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let dq = extractExtendedField bin 15u 4u 4
    let dq2ra = getOprMem dq ra
    struct (opcode, TwoOperands(rtp, dq2ra))
  | b when b &&&
    0b11111100000000000000000000000011u = 0b11111000000000000000000000000010u ->
    let opcode = Opcode.STQ
    let rsp = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let ds = extractExtendedField bin 15u 2u 2
    let ds2ra = getOprMem ds ra
    struct (opcode, TwoOperands(rsp, ds2ra))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011000101100u ->
    let opcode = Opcode.LHBRX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000101100u ->
    let opcode = Opcode.LWBRX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000011100101100u ->
    let opcode = Opcode.STHBRX
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rs, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100101100u ->
    let opcode = Opcode.STWBRX
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rs, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000101000u ->
    let opcode = Opcode.LDBRX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100101000u ->
    let opcode = Opcode.STDBRX
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rs, ra, rb))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10111000000000000000000000000000u ->
    let opcode = Opcode.LMW
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rt, d2ra))
  | b when b &&&
    0b11111100000000000000000000000000u = 0b10111100000000000000000000000000u ->
    let opcode = Opcode.STMW
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u
    let d = extractExtendedField bin 15u 0u 0
    let d2ra = getOprMem d ra
    struct (opcode, TwoOperands(rs, d2ra))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010010101010u ->
    let opcode = Opcode.LSWI
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let nb = Bits.extract bin 15u 11u |> getOprImm
    struct (opcode, ThreeOperands(rt, ra, nb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010000101010u ->
    let opcode = Opcode.LSWX
    let rt = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rt, ra, rb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010110101010u ->
    let opcode = Opcode.STSWI
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let nb = Bits.extract bin 15u 11u |> getOprImm
    struct (opcode, ThreeOperands(rs, ra, nb))
  | b when b &&&
    0b11111100000000000000011111111111u = 0b1111100000000000000010100101010u ->
    let opcode = Opcode.STSWX
    let rs = Bits.extract bin 25u 21u |> getOprReg
    let ra = Bits.extract bin 20u 16u |> getOprReg
    let rb = Bits.extract bin 15u 11u |> getOprReg
    struct (opcode, ThreeOperands(rs, ra, rb))
  | _ -> Terminator.futureFeature ()

let parse lifter (span: ByteSpan) (reader: IBinReader) (addr: Addr) =
  let bin = reader.ReadUInt32(span, 0)
  let struct (opcode, operands) = parseInstruction bin addr
  Instruction(addr, 4u, opcode, operands, 64<rt>, 0UL, lifter)
