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

module B2R2.FrontEnd.BinLifter.SPARC.Parser

open B2R2.FrontEnd.BinLifter.SPARC

open B2R2
open B2R2.FrontEnd.BinLifter

let getRegister = function
  | 0x0uy -> R.G0
  | 0x1uy -> R.G1
  | 0x2uy -> R.G2
  | 0x3uy -> R.G3
  | 0x4uy -> R.G4
  | 0x5uy -> R.G5
  | 0x6uy -> R.G6
  | 0x7uy -> R.G7
  | 0x8uy -> R.O0
  | 0x9uy -> R.O1
  | 0xAuy -> R.O2
  | 0xBuy -> R.O3
  | 0xCuy -> R.O4
  | 0xDuy -> R.O5
  | 0xEuy -> R.O6
  | 0xFuy -> R.O7
  | 0x10uy -> R.L0
  | 0x11uy -> R.L1
  | 0x12uy -> R.L2
  | 0x13uy -> R.L3
  | 0x14uy -> R.L4
  | 0x15uy -> R.L5
  | 0x16uy -> R.L6
  | 0x17uy -> R.L7
  | 0x18uy -> R.I0
  | 0x19uy -> R.I1
  | 0x1Auy -> R.I2
  | 0x1Buy -> R.I3
  | 0x1Cuy -> R.I4
  | 0x1Duy -> R.I5
  | 0x1Euy -> R.I6
  | 0x1Fuy -> R.I7
  | _ -> raise InvalidRegisterException

let getFloatRegister = function
  | 0x0uy -> R.F0
  | 0x1uy -> R.F1
  | 0x2uy -> R.F2
  | 0x3uy -> R.F3
  | 0x4uy -> R.F4
  | 0x5uy -> R.F5
  | 0x6uy -> R.F6
  | 0x7uy -> R.F7
  | 0x8uy -> R.F8
  | 0x9uy -> R.F9
  | 0xauy -> R.F10
  | 0xbuy -> R.F11
  | 0xcuy -> R.F12
  | 0xduy -> R.F13
  | 0xeuy -> R.F14
  | 0xfuy -> R.F15
  | 0x10uy -> R.F16
  | 0x11uy -> R.F17
  | 0x12uy -> R.F18
  | 0x13uy -> R.F19
  | 0x14uy -> R.F20
  | 0x15uy -> R.F21
  | 0x16uy -> R.F22
  | 0x17uy -> R.F23
  | 0x18uy -> R.F24
  | 0x19uy -> R.F25
  | 0x1auy -> R.F26
  | 0x1buy -> R.F27
  | 0x1cuy -> R.F28
  | 0x1duy -> R.F29
  | 0x1euy -> R.F30
  | 0x1fuy -> R.F31
  | _ -> raise InvalidRegisterException

let getDPFloatRegister = function
  | 0x0uy -> R.F0
  | 0x1uy -> R.F32
  | 0x2uy -> R.F2
  | 0x3uy -> R.F34
  | 0x4uy -> R.F4
  | 0x5uy -> R.F36
  | 0x6uy -> R.F6
  | 0x7uy -> R.F38
  | 0x8uy -> R.F8
  | 0x9uy -> R.F40
  | 0xauy -> R.F10
  | 0xbuy -> R.F42
  | 0xcuy -> R.F12
  | 0xduy -> R.F44
  | 0xeuy -> R.F14
  | 0xfuy -> R.F46
  | 0x10uy -> R.F16
  | 0x11uy -> R.F48
  | 0x12uy -> R.F18
  | 0x13uy -> R.F50
  | 0x14uy -> R.F20
  | 0x15uy -> R.F52
  | 0x16uy -> R.F22
  | 0x17uy -> R.F54
  | 0x18uy -> R.F24
  | 0x19uy -> R.F56
  | 0x1auy -> R.F26
  | 0x1buy -> R.F58
  | 0x1cuy -> R.F28
  | 0x1duy -> R.F60
  | 0x1euy -> R.F30
  | 0x1fuy -> R.F62
  | _ -> raise InvalidRegisterException

let getQPFloatRegister = function
  | 0x0uy -> R.F0
  | 0x01uy -> R.F32
  | 0x4uy -> R.F4
  | 0x05uy -> R.F36
  | 0x8uy -> R.F8
  | 0x9uy -> R.F40
  | 0xcuy -> R.F12
  | 0xduy -> R.F44
  | 0x10uy -> R.F16
  | 0x11uy -> R.F48
  | 0x14uy -> R.F20
  | 0x15uy -> R.F52
  | 0x18uy -> R.F24
  | 0x19uy -> R.F56
  | 0x1cuy -> R.F28
  | 0x1duy -> R.F60
  | _ -> raise InvalidRegisterException

let pickBit binary (pos: uint32) = binary >>> int pos &&& 0b1u

let concat (n1: uint32) (n2: uint32) shift = (n1 <<< shift) + n2

let parseOneOpr b op1 = OneOperand (op1 b)

let parseTwoOpr b op1 op2 = TwoOperands (op1 b, op2 b)

let parseThrOpr b op1 op2 op3 = ThreeOperands (op1 b, op2 b, op3 b)

let parseFourOpr b op1 op2 op3 op4 =
  FourOperands (op1 b, op2 b, op3 b, op4 b)

let parseOneCC cc1 = OneOperand (cc1)

let parseOneCCOneOpr b cc1 op1 = TwoOperands (cc1, op1 b)

let parseOneCCTwoOpr b cc1 op1 op2 = ThreeOperands (cc1, op1 b, op2 b)

let parseOneOprOneCC b op1 cc1 = TwoOperands (op1 b, cc1)

let parseOneRegOneOpr b reg op1 = TwoOperands (reg, op1 b)

let parseTwoOprOneReg b op1 op2 reg = ThreeOperands (op1 b, op2 b, reg)

let parseOneRegTwoOpr b reg op1 op2 = ThreeOperands (reg, op1 b, op2 b)

let parseThrOprOneReg b op1 op2 reg op3 =
  FourOperands (op1 b, op2 b, reg, op3 b)

let parseSTXA b op1 op2 op3 reg =
  FourOperands (op1 b, op2 b, op3 b, reg)

let extract binary n1 n2 =
  let m, n = if max n1 n2 = n1 then n1, n2 else n2, n1
  let range = m - n + 1u
  if range > 31u then failwith "invalid range" else ()
  let mask = pown 2 (int range) - 1 |> uint32
  binary >>> int n &&& mask

let getReg b s e = getRegister (extract b s e |> byte)

let getRegRd b = getReg b 29u 25u |> OprReg

let getRegRs1 b = getReg b 18u 14u |> OprReg

let getRegRs2 b = getReg b 4u 0u |> OprReg

let getFloatReg b s e = getFloatRegister (extract b s e |> byte)

let getFloatRegRd b = getFloatReg b 29u 25u |> OprReg

let getFloatRegRs1 b = getFloatReg b 18u 14u |> OprReg

let getFloatRegRs2 b = getFloatReg b 4u 0u |> OprReg

let getDPFloatReg b s e = getDPFloatRegister (extract b s e |> byte)

let getDPFloatRegRd b = getDPFloatReg b 29u 25u |> OprReg

let getDPFloatRegRs1 b = getDPFloatReg b 18u 14u |> OprReg

let getDPFloatRegRs2 b = getDPFloatReg b 4u 0u |> OprReg

let getQPFloatReg b s e = getQPFloatRegister (extract b s e |> byte)

let getQPFloatRegRd b = getQPFloatReg b 29u 25u |> OprReg

let getQPFloatRegRs1 b = getQPFloatReg b 18u 14u |> OprReg

let getQPFloatRegRs2 b = getQPFloatReg b 4u 0u |> OprReg

let getRegAsi b = getReg b 7u 0u |> OprReg

let getConst22 b = extract b 21u 0u |> int32 |> OprImm

let getimm22 b =
  extract b 21u 0u <<< 10 |> int32 |> OprImm

let getSimm13 b =
  (extract b 12u 0u) <<< 19 |> int32 >>> 19 |> OprImm

let getSimm13Zero b =
  let checkSimm13 = (extract b 12u 0u) <<< 19 |> int32 >>> 19
  if checkSimm13 = 0 then getReg b 12u 0u |> OprReg
  else checkSimm13 |> OprImm

let getSimm11 b = extract b 10u 0u |> int32 |> OprImm

let getSimm10 b = extract b 9u 0u |> int32 |> OprImm

let getAbit b = pickBit b 29u |> int32 |> OprImm

let getPbit b = pickBit b 19u |> int32 |> OprImm

let getd16hi b = extract b 21u 20u

let getd16lo b = extract b 13u 0u

let getdisp30 b =
  let disp30 = extract b 29u 0u <<< 2 |> int32 >>> 2
  4 * disp30 |> int32 |> OprAddr

let getdisp22 b =
  let disp22 = extract b 21u 0u <<< 10 |> int32 >>> 10
  4 * disp22 |> OprImm

let getdisp19 b =
  let disp19 = extract b 18u 0u <<< 13 |> int32 >>> 13
  4 * disp19 |> OprImm

let get26cc1 b = pickBit b 26u

let get25cc0 b = pickBit b 25u

let get21cc1 b = pickBit b 21u

let get20cc0 b = pickBit b 20u

let get18cc2 b = pickBit b 18u

let get13cc2 b = pickBit b 13u

let get12cc1 b = pickBit b 12u

let get11cc0 b = pickBit b 11u

let getImmAsi b = extract b 12u 5u |> int32 |> OprImm

let getImplDep b =
  concat (extract b 29u 25u) (extract b 18u 0u) 19 |> int32 |> OprImm

let getcmask b = extract b 6u 4u |> int32 |> OprImm

let getmmask b = extract b 3u 0u |> int32 |> OprImm

let getMembarMask b =
  let cmask = extract b 6u 4u
  let mmask = extract b 3u 0u
  cmask ||| mmask |> int32 |> OprImm

let getOpFCC b = extract b 13u 11u |> int32 |> OprImm

let getshcnt32 b = extract b 4u 0u |> int32 |> OprImm

let getshcnt64 b = extract b 5u 0u |> int32 |> OprImm

let getfcn b = extract b 29u 25u |> int32 |> OprImm

let getAddrRs1 b = getReg b 18u 14u |> OprReg

let getAddrRs2 b = getReg b 4u 0u |> OprReg

let getAddrSimm13 b =
  (extract b 12u 0u) <<< 19 |> int32 >>> 19 |> OprImm

let setPriReg r = r |> OprReg

let getThrCC (cc2: uint32) (cc1: uint32) (cc0: uint32) =
  match cc2, cc1, cc0 with
  | 0b0u, 0b0u, 0b0u -> ConditionCode.Fcc0 |> OprCC
  | 0b0u, 0b0u, 0b1u -> ConditionCode.Fcc1 |> OprCC
  | 0b0u, 0b1u, 0b0u -> ConditionCode.Fcc2 |> OprCC
  | 0b0u, 0b1u, 0b1u -> ConditionCode.Fcc3 |> OprCC
  | 0b1u, 0b0u, 0b0u -> ConditionCode.Icc |> OprCC
  | 0b1u, 0b1u, 0b0u -> ConditionCode.Xcc |> OprCC
  | _ -> raise InvalidOperandException

let getTwoCCix (cc1: uint32) (cc0: uint32) =
  match cc1, cc0 with
  | 0b0u, 0b0u -> ConditionCode.Icc |> OprCC
  | 0b1u, 0b0u -> ConditionCode.Xcc |> OprCC
  | _ -> raise InvalidOperandException

let getTwoCCFcc (cc1: uint32) (cc0: uint32) =
  match cc1, cc0 with
  | 0b0u, 0b0u -> ConditionCode.Fcc0 |> OprCC
  | 0b0u, 0b1u -> ConditionCode.Fcc1 |> OprCC
  | 0b1u, 0b0u -> ConditionCode.Fcc2 |> OprCC
  | 0b1u, 0b1u -> ConditionCode.Fcc3 |> OprCC
  | _ -> raise InvalidOperandException

let getTwod16 (hi: uint32) (lo: uint32) =
  (hi <<< 14 ||| lo) * 4u |> int32 |> OprImm

let getPriReg b =
  match b >>> 14 with
  | 0u -> Register.TPC |> OprPriReg
  | 1u -> Register.TNPC |> OprPriReg
  | 2u -> Register.TSTATE |> OprPriReg
  | 3u -> Register.TT |> OprPriReg
  | 4u -> Register.TICK |> OprPriReg
  | 5u -> Register.TBA |> OprPriReg
  | 6u -> Register.PSTATE |> OprPriReg
  | 7u -> Register.TL |> OprPriReg
  | 8u -> Register.PIL |> OprPriReg
  | 9u -> Register.CWP |> OprPriReg
  | 10u -> Register.CANSAVE |> OprPriReg
  | 11u -> Register.CANRESTORE |> OprPriReg
  | 12u -> Register.CLEANWIN |> OprPriReg
  | 13u -> Register.OTHERWIN |> OprPriReg
  | 14u -> Register.WSTATE |> OprPriReg
  | 15u -> Register.FQ |> OprPriReg
  | 31u -> Register.VER |> OprPriReg
  | _ -> raise InvalidRegisterException

(*
  00r_ __d1 1010 0---
  --o_ __p_ __f- ----
*)
let parseFP b32 =
  match extract b32 13u 5u with
  | 0b001000001u ->
    struct (
      Opcode.FADDs,
      parseThrOpr b32 getFloatRegRs1 getFloatRegRs2 getFloatRegRd
    )
  | 0b001000010u ->
    struct (
      Opcode.FADDd,
      parseThrOpr b32 getDPFloatRegRs1 getDPFloatRegRs2 getDPFloatRegRd
    )
  | 0b001000011u ->
    struct (
      Opcode.FADDq,
      parseThrOpr b32 getQPFloatRegRs1 getQPFloatRegRs2 getQPFloatRegRd
    )
  | 0b001000101u ->
    struct (
      Opcode.FSUBs,
      parseThrOpr b32 getFloatRegRs1 getFloatRegRs2 getFloatRegRd
    )
  | 0b001000110u ->
    struct (
      Opcode.FSUBd,
      parseThrOpr b32 getDPFloatRegRs1 getDPFloatRegRs2 getDPFloatRegRd
    )
  | 0b001000111u ->
    struct (
      Opcode.FSUBq,
      parseThrOpr b32 getQPFloatRegRs1 getQPFloatRegRs2 getQPFloatRegRd
    )
  | 0b010000001u ->
    struct (
      Opcode.FsTOx,
      parseTwoOpr b32 getFloatRegRs2 getDPFloatRegRd
    )
  | 0b010000010u ->
    struct (
      Opcode.FdTOx,
      parseTwoOpr b32 getDPFloatRegRs2 getDPFloatRegRd
    )
  | 0b010000011u ->
    struct (
      Opcode.FqTOx,
      parseTwoOpr b32 getQPFloatRegRs2 getDPFloatRegRd
    )
  | 0b011010001u ->
    struct (
      Opcode.FsTOi,
      parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    )
  | 0b011010010u ->
    struct (
      Opcode.FdTOi,
      parseTwoOpr b32 getDPFloatRegRs2 getFloatRegRd
    )
  | 0b011010011u ->
    struct (
      Opcode.FqTOi,
      parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    )
  | 0b011001001u ->
    struct (
      Opcode.FsTOd,
      parseTwoOpr b32 getFloatRegRs2 getDPFloatRegRd
    )
  | 0b011001101u ->
    struct (
      Opcode.FsTOq,
      parseTwoOpr b32 getFloatRegRs2 getQPFloatRegRd
    )
  | 0b011000110u ->
    struct (
      Opcode.FdTOs,
      parseTwoOpr b32 getDPFloatRegRs2 getFloatRegRd
    )
  | 0b011001110u ->
    struct (
      Opcode.FdTOq,
      parseTwoOpr b32 getDPFloatRegRs2 getQPFloatRegRd
    )
  | 0b011000111u ->
    struct (
      Opcode.FqTOs,
      parseTwoOpr b32 getQPFloatRegRs2 getFloatRegRd
    )
  | 0b011001011u ->
    struct (
      Opcode.FqTOd,
      parseTwoOpr b32 getQPFloatRegRs2 getDPFloatRegRd
    )
  | 0b010000100u ->
    struct (
      Opcode.FxTOs,
      parseTwoOpr b32 getDPFloatRegRs2 getFloatRegRd
    )
  | 0b010001000u ->
    struct (
      Opcode.FxTOd,
      parseTwoOpr b32 getDPFloatRegRs2 getDPFloatRegRd
    )
  | 0b010001100u ->
    struct (
      Opcode.FxTOq,
      parseTwoOpr b32 getDPFloatRegRs2 getQPFloatRegRd
    )
  | 0b011000100u ->
    struct (
      Opcode.FiTOs,
      parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    )
  | 0b011001000u ->
    struct (
      Opcode.FiTOd,
      parseTwoOpr b32 getFloatRegRs2 getDPFloatRegRd
    )
  | 0b011001100u ->
    struct (
      Opcode.FiTOq,
      parseTwoOpr b32 getFloatRegRs2 getQPFloatRegRd
    )
  | 0b000000001u ->
    struct (
      Opcode.FMOVs,
      parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    )
  | 0b000000010u ->
    struct (
      Opcode.FMOVd,
      parseTwoOpr b32 getDPFloatRegRs2 getDPFloatRegRd
    )
  | 0b000000011u ->
    struct (
      Opcode.FMOVq,
      parseTwoOpr b32 getQPFloatRegRs2 getQPFloatRegRd
    )
  | 0b000000101u ->
    struct (
      Opcode.FNEGs,
      parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    )
  | 0b000000110u ->
    struct (
      Opcode.FNEGd,
      parseTwoOpr b32 getDPFloatRegRs2 getDPFloatRegRd
    )
  | 0b000000111u ->
    struct (
      Opcode.FNEGq,
      parseTwoOpr b32 getQPFloatRegRs2 getQPFloatRegRd
    )
  | 0b000001001u ->
    struct (
      Opcode.FABSs,
      parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    )
  | 0b000001010u ->
    struct (
      Opcode.FABSd,
      parseTwoOpr b32 getDPFloatRegRs2 getDPFloatRegRd
    )
  | 0b000001011u ->
    struct (
      Opcode.FABSq,
      parseTwoOpr b32 getQPFloatRegRs2 getQPFloatRegRd
    )
  | 0b001001001u ->
    struct (
      Opcode.FMULs,
      parseThrOpr b32 getFloatRegRs1 getFloatRegRs2 getFloatRegRd
    )
  | 0b001001010u ->
    struct (
      Opcode.FMULd,
      parseThrOpr b32 getDPFloatRegRs1 getDPFloatRegRs2 getDPFloatRegRd
    )
  | 0b001001011u ->
    struct (
      Opcode.FMULq,
      parseThrOpr b32 getQPFloatRegRs1 getQPFloatRegRs2 getQPFloatRegRd
    )
  | 0b001101001u ->
    struct (
      Opcode.FsMULd,
      parseThrOpr b32 getFloatRegRs1 getFloatRegRs2 getDPFloatRegRd
    )
  | 0b001101110u ->
    struct (
      Opcode.FdMULq,
      parseThrOpr b32 getDPFloatRegRs1 getDPFloatRegRs2 getQPFloatRegRd
    )
  | 0b001001101u ->
    struct (
      Opcode.FDIVs,
      parseThrOpr b32 getFloatRegRs1 getFloatRegRs2 getFloatRegRd
    )
  | 0b001001110u ->
    struct (
      Opcode.FDIVd,
      parseThrOpr b32 getDPFloatRegRs1 getDPFloatRegRs2 getDPFloatRegRd
    )
  | 0b001001111u ->
    struct (
      Opcode.FDIVq,
      parseThrOpr b32 getQPFloatRegRs1 getQPFloatRegRs2 getQPFloatRegRd
    )
  | 0b000101001u ->
    struct (
      Opcode.FSQRTs,
      parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    )
  | 0b000101010u ->
    struct (
      Opcode.FSQRTd,
      parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    )
  | 0b000101011u ->
    struct (
      Opcode.FSQRTq,
      parseTwoOpr b32 getQPFloatRegRs2 getQPFloatRegRd
    )
  | _ -> struct (Opcode.InvalidOp, NoOperand)


let parse110101fmovr b32 =
  match extract b32 12u 10u with
  | 0b001u ->
    match extract b32 9u 5u with
    | 0b00101u ->
      struct (
        Opcode.FMOVRsZ,
        parseThrOpr b32 getRegRs1 getFloatRegRs2 getFloatRegRd
      )
    | 0b00110u ->
      struct (
        Opcode.FMOVRdZ,
        parseThrOpr b32 getRegRs1 getDPFloatRegRs2 getDPFloatRegRd
      )
    | 0b00111u ->
      struct (
        Opcode.FMOVRqZ,
        parseThrOpr b32 getRegRs1 getQPFloatRegRs2 getQPFloatRegRd
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b010u ->
    match extract b32 9u 5u with
    | 0b00101u ->
      struct (
        Opcode.FMOVRsLEZ,
        parseThrOpr b32 getRegRs1 getFloatRegRs2 getFloatRegRd
      )
    | 0b00110u ->
      struct (Opcode.FMOVRdLEZ,
      parseThrOpr b32 getRegRs1 getDPFloatRegRs2 getDPFloatRegRd
      )
    | 0b00111u ->
      struct (
        Opcode.FMOVRqLEZ,
        parseThrOpr b32 getRegRs1 getQPFloatRegRs2 getQPFloatRegRd
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b011u ->
    match extract b32 9u 5u with
    | 0b00101u ->
      struct (
        Opcode.FMOVRsLZ,
        parseThrOpr b32 getRegRs1 getFloatRegRs2 getFloatRegRd
      )
    | 0b00110u ->
      struct (
        Opcode.FMOVRdLZ,
        parseThrOpr b32 getRegRs1 getDPFloatRegRs2 getDPFloatRegRd
      )
    | 0b00111u ->
      struct (
        Opcode.FMOVRqLZ,
        parseThrOpr b32 getRegRs1 getQPFloatRegRs2 getQPFloatRegRd
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b101u ->
    match extract b32 9u 5u with
    | 0b00101u ->
      struct (
        Opcode.FMOVRsNZ,
        parseThrOpr b32 getRegRs1 getFloatRegRs2 getFloatRegRd
      )
    | 0b00110u ->
      struct (
        Opcode.FMOVRdNZ,
        parseThrOpr b32 getRegRs1 getDPFloatRegRs2 getDPFloatRegRd
      )
    | 0b00111u ->
      struct (
        Opcode.FMOVRqNZ,
        parseThrOpr b32 getRegRs1 getQPFloatRegRs2 getQPFloatRegRd
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b110u ->
    match extract b32 9u 5u with
    | 0b00101u ->
      struct (
        Opcode.FMOVRsGZ,
        parseThrOpr b32 getRegRs1 getFloatRegRs2 getFloatRegRd
      )
    | 0b00110u ->
      struct (
        Opcode.FMOVRdGZ,
        parseThrOpr b32 getRegRs1 getDPFloatRegRs2 getDPFloatRegRd
      )
    | 0b00111u ->
      struct (
        Opcode.FMOVRqGZ,
        parseThrOpr b32 getRegRs1 getQPFloatRegRs2 getQPFloatRegRd
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b111u ->
    match extract b32 9u 5u with
    | 0b00101u ->
      struct (
        Opcode.FMOVRsGEZ,
        parseThrOpr b32 getRegRs1 getFloatRegRs2 getFloatRegRd
      )
    | 0b00110u ->
      struct (
        Opcode.FMOVRdGEZ,
        parseThrOpr b32 getRegRs1 getDPFloatRegRs2 getDPFloatRegRd
      )
    | 0b00111u ->
      struct (
        Opcode.FMOVRqGEZ,
        parseThrOpr b32 getRegRs1 getQPFloatRegRs2 getQPFloatRegRd
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | _ -> struct (Opcode.InvalidOp, NoOperand)

(*
  10r_ __d1 1010 10--
  ---- ---- ---- ----
*)
let parse110101 b32 =
  match extract b32 13u 11u with
  | 0b100u | 0b110u ->
    match extract b32 17u 14u with
    | 0b1000u ->
      // struct (Opcode.FMOVA, parseThrOpr b32 getOpFCC getFloatRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsA,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdA,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqA,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0000u ->
      // struct (Opcode.FMOVN, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsN,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdN,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqN,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1001u ->
      // struct (Opcode.FMOVNE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsNE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdNE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqNE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0001u ->
      // struct (Opcode.FMOVE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1010u ->
      // struct (Opcode.FMOVG, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0010u ->
      // struct (Opcode.FMOVLE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsLE,
          parseOneCCTwoOpr b32
           (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
              getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdLE,
          parseOneCCTwoOpr b32
              (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
              getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqLE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1011u ->
      // struct (Opcode.FMOVGE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsGE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdGE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqGE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0011u ->
      // struct (Opcode.FMOVL, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsL,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdL,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqL,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1100u ->
      // struct (Opcode.FMOVGU, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsGU,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdGU,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqGU,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0100u ->
      // struct (Opcode.FMOVLEU, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsLEU,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdLEU,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqLEU,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1101u ->
      // struct (Opcode.FMOVCC, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsCC,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdCC,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqCC,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0101u ->
      // struct (Opcode.FMOVCS, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsCS,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdCS,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqCS,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1110u ->
      // struct (Opcode.FMOVPOS, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsPOS,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdPOS,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqPOS,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0110u ->
      // struct (Opcode.FMOVNEG, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsNEG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdNEG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqNEG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1111u ->
      // struct (Opcode.FMOVVC, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsVC,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdVC,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqVC,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0111u ->
      // struct (Opcode.FMOVVS, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVsVS,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVdVS,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVqVS,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | _ -> parse110101fmovr b32

  | 0b000u | 0b001u | 0b010u | 0b011u ->
    match extract b32 17u 14u with
    | 0b1000u ->
      // struct (Opcode.FMOVA, parseThrOpr b32 getOpFCC getFloatRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsA,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdA,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqA,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0000u ->
      // struct (Opcode.FMOVN, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsN,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdN,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqN,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0111u ->
      // struct (Opcode.FMOVNE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsU,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdU,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqU,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b110u ->
      // struct (Opcode.FMOVE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0101u ->
      // struct (Opcode.FMOVG, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsUG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdUG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqUG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0100u ->
      // struct (Opcode.FMOVLE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsL,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdL,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqL,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0011u ->
      // struct (Opcode.FMOVGE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsUL,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdUL,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqUL,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0010u ->
      // struct (Opcode.FMOVL, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsLG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdLG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqLG,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b0001u ->
      // struct (Opcode.FMOVGU, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsNE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdNE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqNE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1001u ->
      // struct (Opcode.FMOVLEU, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1010u ->
      // struct (Opcode.FMOVCC, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsUE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdUE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqUE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1011u ->
      // struct (Opcode.FMOVCS, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsGE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdGE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqGE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1100u ->
      // struct (Opcode.FMOVPOS, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsUGE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdUGE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqUGE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1101u ->
      // struct (Opcode.FMOVNEG, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsLE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdLE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqLE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1110u ->
      // struct (Opcode.FMOVVC, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsULE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdULE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqULE,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | 0b1111u ->
      // struct (Opcode.FMOVVS, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        struct (
          Opcode.FMOVFsO,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2 getFloatRegRd
        )
      | 0b000010u ->
        struct (
          Opcode.FMOVFdO,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2 getDPFloatRegRd
        )
      | 0b000011u ->
        struct (
          Opcode.FMOVFqO,
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2 getQPFloatRegRd
        )
      | _ -> parse110101fmovr b32
    | _ -> struct (Opcode.InvalidOp, NoOperand)

  | _ -> parse110101fmovr b32


(*
  10r_ __d1 0100 0---
  ---- ---- ---- ----
*)
let parse101000 b32 =
  match extract b32 18u 14u with
  | 0u -> struct (Opcode.RDY, parseOneRegOneOpr b32 (setPriReg R.Y) getRegRd)
  | 2u ->
    struct (Opcode.RDCCR, parseOneRegOneOpr b32 (setPriReg R.CCR) getRegRd)
  | 3u ->
    struct (Opcode.RDASI, parseOneRegOneOpr b32 (setPriReg R.ASI) getRegRd)
  | 4u ->
    struct (Opcode.RDTICK, parseOneRegOneOpr b32 (setPriReg R.TICK) getRegRd)
  | 5u -> struct (Opcode.RDPC, parseOneRegOneOpr b32 (setPriReg R.PC) getRegRd)
  | 6u ->
    struct (Opcode.RDFPRS, parseOneRegOneOpr b32 (setPriReg R.FPRS) getRegRd)
  | 7u
  | 8u
  | 9u
  | 10u
  | 12u
  | 13u
  | 14u -> struct (Opcode.RDASR, parseTwoOpr b32 getRegRs1 getRegRd)
  | 16u
  | 17u
  | 18u
  | 19u
  | 20u
  | 21u
  | 22u
  | 23u
  | 24u
  | 25u
  | 26u
  | 27u
  | 28u
  | 29u
  | 30u
  | 31u -> struct (Opcode.RDASR, parseTwoOpr b32 getRegRs1 getRegRd)
  | _ -> struct (Opcode.InvalidOp, NoOperand)

(*
  10r_ __d1 1000 0---
  ---- ---- ---- ----
*)
let parse110000 b32 =
  match pickBit b32 13u with
  | 0b0u ->
    match extract b32 29u 25u with
    | 0u -> struct (Opcode.WRY, parseTwoOpr b32 getRegRs1 getRegRs2)
    | 2u -> struct (Opcode.WRCCR, parseTwoOpr b32 getRegRs1 getRegRs2)
    | 3u -> struct (Opcode.WRASI, parseTwoOpr b32 getRegRs1 getRegRs2)
    | 4u
    | 5u
    | 7u
    | 8u
    | 9u
    | 10u
    | 12u
    | 13u
    | 14u -> struct (Opcode.WRASR, parseTwoOpr b32 getRegRs1 getRegRs2)
    | 6u -> struct (Opcode.WRFPRS, parseTwoOpr b32 getRegRs1 getRegRs2)
    | 15u -> struct (Opcode.SIR, NoOperand)
    | 16u
    | 17u
    | 18u
    | 19u
    | 20u
    | 21u
    | 22u
    | 23u
    | 24u
    | 25u
    | 26u
    | 27u
    | 28u
    | 29u
    | 30u
    | 31u -> struct (Opcode.WRASR, parseTwoOpr b32 getRegRs1 getRegRs2)
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b1u ->
    match extract b32 29u 25u with
    | 0u ->
      struct (Opcode.WRY,
              parseTwoOprOneReg b32 getRegRs1 getSimm13 (setPriReg R.Y))
    | 2u ->
      struct (Opcode.WRCCR,
              parseTwoOprOneReg b32 getRegRs1 getSimm13 (setPriReg R.CCR))
    | 3u ->
      struct (Opcode.WRASI,
              parseTwoOprOneReg b32 getRegRs1 getSimm13 (setPriReg R.ASI))
    | 4u
    | 5u
    | 7u
    | 8u
    | 9u
    | 10u
    | 12u
    | 13u
    | 14u -> struct (Opcode.WRASR, parseTwoOpr b32 getRegRs1 getSimm13)
    | 6u ->
      struct (
        Opcode.WRFPRS,
        parseTwoOprOneReg b32 getRegRs1 getSimm13 (setPriReg R.FPRS)
      )
    | 15u -> struct (Opcode.SIR, parseOneOpr b32 getSimm13)
    | 16u
    | 17u
    | 18u
    | 19u
    | 20u
    | 21u
    | 22u
    | 23u
    | 24u
    | 25u
    | 26u
    | 27u
    | 28u
    | 29u
    | 30u
    | 31u ->
      struct (Opcode.WRASR, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | _ -> struct (Opcode.InvalidOp, NoOperand)

(*
  10r_ __d1 0110 0---
  ---- ---- ---- ----
*)
let parse101100 b32 =
  match pickBit b32 13u with
  | 0b0u ->
    match extract b32 17u 14u with
    | 0b1000u ->
      struct (
        Opcode.MOVA,
        parseOneCCTwoOpr b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2 getRegRd
        )
    | 0b0000u ->
      struct (
        Opcode.MOVN,
        parseOneCCTwoOpr b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2 getRegRd
      )
    | 0b1001u ->
      struct (
        Opcode.MOVNE,
        parseOneCCTwoOpr
          b32 (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b0001u ->
      struct (
        Opcode.MOVE,
        parseOneCCTwoOpr b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b1010u ->
      struct (
        Opcode.MOVG,
        parseOneCCTwoOpr
          b32 (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b0010u ->
      struct (
        Opcode.MOVLE,
        parseOneCCTwoOpr
          b32 (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2 getRegRd
      )
    | 0b1011u ->
      struct (
        Opcode.MOVGE,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2 getRegRd
      )
    | 0b0011u ->
      struct (
        Opcode.MOVL,
        parseOneCCTwoOpr b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
           getRegRs2 getRegRd
      )
    | 0b1100u ->
      struct (
        Opcode.MOVGU,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b0100u ->
      struct (
        Opcode.MOVLEU,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b1101u ->
      struct (
        Opcode.MOVCC,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b0101u ->
      struct (
        Opcode.MOVCS,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b1110u ->
      struct (
        Opcode.MOVPOS,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b0110u ->
      struct (
        Opcode.MOVNEG,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b1111u ->
      struct (
        Opcode.MOVVC,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd)
    | 0b0111u ->
      struct (
        Opcode.MOVVS,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b1u ->
    match extract b32 17u 14u with
    | 0b1000u ->
      struct (
        Opcode.MOVA,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b0000u ->
      struct (
        Opcode.MOVN,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b1001u ->
      struct (
        Opcode.MOVNE,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b0001u ->
      struct (
        Opcode.MOVE,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b1010u ->
      struct (
        Opcode.MOVG,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b0010u ->
      struct (
        Opcode.MOVLE,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b1011u ->
      struct (
        Opcode.MOVGE,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b0011u ->
      struct (
        Opcode.MOVL,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b1100u ->
      struct (
        Opcode.MOVGU,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b0100u ->
      struct (
        Opcode.MOVLEU,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b1101u ->
      struct (
        Opcode.MOVCC,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b0101u ->
      struct (
        Opcode.MOVCS,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b1110u ->
      struct (
        Opcode.MOVPOS,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b0110u ->
      struct (
        Opcode.MOVNEG,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b1111u ->
      struct (
        Opcode.MOVVC,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
      )
    | 0b0111u ->
      struct (
        Opcode.MOVVS,
        parseOneCCTwoOpr
          b32
          (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
          getRegRs2
          getRegRd
          )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | _ -> struct (Opcode.InvalidOp, NoOperand)

(*
  10r_ __d1 0111 1---
  ---- ---- ---- ----
*)
let parse101111 b32 =
  match pickBit b32 13u with
  | 0b0u ->
    match extract b32 12u 10u with
    | 0b001u ->
      struct (Opcode.MOVRZ, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b010u ->
      struct (Opcode.MOVRLEZ, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b011u ->
      struct (Opcode.MOVRLZ, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b101u ->
      struct (Opcode.MOVRNZ, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b110u ->
      struct (Opcode.MOVRGZ, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b111u ->
      struct (Opcode.MOVRGEZ, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b1u ->
    match extract b32 12u 10u with
    | 0b001u ->
      struct (Opcode.MOVRZ, parseThrOpr b32 getRegRs1 getSimm10 getRegRd)
    | 0b010u ->
      struct (Opcode.MOVRLEZ, parseThrOpr b32 getRegRs1 getSimm10 getRegRd)
    | 0b011u ->
      struct (Opcode.MOVRLZ, parseThrOpr b32 getRegRs1 getSimm10 getRegRd)
    | 0b101u ->
      struct (Opcode.MOVRNZ, parseThrOpr b32 getRegRs1 getSimm10 getRegRd)
    | 0b110u ->
      struct (Opcode.MOVRGZ, parseThrOpr b32 getRegRs1 getSimm10 getRegRd)
    | 0b111u ->
      struct (Opcode.MOVRGEZ, parseThrOpr b32 getRegRs1 getSimm10 getRegRd)
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | _ -> struct (Opcode.InvalidOp, NoOperand)

(*
  10r_ __do ___p 3---
  ---- ---- ---- ----
*)
let parse10rd b32 =
  match pickBit b32 13u with
  | 0b0u ->
    match extract b32 24u 19u with
    (* ADD *)
    | 0b000000u ->
      struct (Opcode.ADD, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b010000u ->
      struct (Opcode.ADDcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b001000u ->
      struct (Opcode.ADDC, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b011000u ->
      struct (Opcode.ADDCcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Divide *)
    | 0b001110u ->
      struct (Opcode.UDIV, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b001111u ->
      struct (Opcode.SDIV, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b011110u ->
      struct (Opcode.UDIVcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b011111u ->
      struct (Opcode.SDIVcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Jump and Link *)
    | 0b111000u ->
      struct (Opcode.JMPL, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Logical Operations *)
    | 0b000001u ->
      struct (Opcode.AND, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b010001u ->
      struct (Opcode.ANDcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b000101u ->
      struct (Opcode.ANDN, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b010101u ->
      struct (Opcode.ANDNcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b000010u ->
      struct (Opcode.OR, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b010010u ->
      struct (Opcode.ORcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b000110u ->
      struct (Opcode.ORN, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b010110u ->
      struct (Opcode.ORNcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b000011u ->
      struct (Opcode.XOR, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b010011u ->
      struct (Opcode.XORcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b000111u ->
      struct (Opcode.XNOR, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b010111u ->
      struct (Opcode.XNORcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Multiply and Divide (64-bit) *)
    | 0b001001u ->
      struct (Opcode.MULX, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b101101u ->
      struct (Opcode.SDIVX, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b001101u ->
      struct (Opcode.UDIVX, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Multiply (32-bit) *)
    | 0b001010u ->
      struct (Opcode.UMUL, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b001011u ->
      struct (Opcode.SMUL, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b011010u ->
      struct (Opcode.UMULcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b011011u ->
      struct (Opcode.SMULcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Multiply Step *)
    | 0b100100u ->
      struct (Opcode.MULScc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Population Count*)
    | 0b101110u -> struct (Opcode.POPC, parseTwoOpr b32 getRegRs2 getRegRd)
    (* SAVE and RESTORE *)
    | 0b111100u ->
      struct (Opcode.SAVE, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b111101u ->
      struct (Opcode.RESTORE, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Shift *)
    | 0b100101u ->
      struct (Opcode.SLL, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b100110u ->
      struct (Opcode.SRL, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b100111u ->
      struct (Opcode.SRA, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Subtract *)
    | 0b000100u ->
      struct (Opcode.SUB, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b010100u ->
      struct (Opcode.SUBcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b001100u ->
      struct (Opcode.SUBC, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b011100u ->
      struct (Opcode.SUBCcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Tagged Add *)
    | 0b100000u ->
      struct (Opcode.TADDcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b100010u ->
      struct (Opcode.TADDccTV, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Tagged Subtract *)
    | 0b100001u ->
      struct (Opcode.TSUBcc, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b100011u ->
      struct (Opcode.TSUBccTV, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Write Privileged Register *)
    | 0b110010u ->
      struct (Opcode.WRPR, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Move Floating-Point Register on Condition (FMOVcc) *)
    | 0b110101u -> parse110101 b32
    (* Floating-Point *)
    | 0b110100u -> parseFP b32
    (* Read State Register *)
    | 0b101000u -> parse101000 b32
    (* Write State Register *)
    | 0b110000u -> parse110000 b32
    (* Move Integer Register on Condition *)
    | 0b101100u -> parse101100 b32
    (* Move Integer Register on Register Condition *)
    | 0b101111u -> parse101111 b32
    | _ -> Opcode.InvalidOp, NoOperand
  | 0b01u ->
    match extract b32 24u 19u with
    (* ADD *)
    | 0b000000u ->
      struct (Opcode.ADD, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b010000u ->
      struct (Opcode.ADDcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b001000u ->
      struct (Opcode.ADDC, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b011000u ->
      struct (Opcode.ADDCcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    (* Divide *)
    | 0b001110u ->
      struct (Opcode.UDIV, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b001111u ->
      struct (Opcode.SDIV, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b011110u ->
      struct (Opcode.UDIVcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b011111u ->
      struct (Opcode.SDIVcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    (* Jump and Link *)
    | 0b111000u ->
      struct (Opcode.JMPL, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    (* Logical Operations *)
    | 0b000001u ->
      struct (Opcode.AND, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b010001u ->
      struct (Opcode.ANDcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b000101u ->
      struct (Opcode.ANDN, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b010101u ->
      struct (Opcode.ANDNcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b000010u ->
      struct (Opcode.OR, parseThrOpr b32 getRegRs1 getSimm13Zero getRegRd)
    | 0b010010u ->
      struct (Opcode.ORcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b000110u ->
      struct (Opcode.ORN, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b010110u ->
      struct (Opcode.ORNcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b000011u ->
      struct (Opcode.XOR, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b010011u ->
      struct (Opcode.XORcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b000111u ->
      struct (Opcode.XNOR, parseThrOpr b32 getRegRs1 getSimm13Zero getRegRd)
    | 0b010111u ->
      struct (Opcode.XNORcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    (* Multiply and Divide (64-bit) *)
    | 0b001001u ->
      struct (Opcode.MULX, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b101101u ->
      struct (Opcode.SDIVX, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b001101u ->
      struct (Opcode.UDIVX, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    (* Multiply (32-bit) *)
    | 0b001010u ->
      struct (Opcode.UMUL, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b001011u ->
      struct (Opcode.SMUL, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b011010u ->
      struct (Opcode.UMULcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b011011u ->
      struct (Opcode.SMULcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    (* Multiply Step *)
    | 0b100100u ->
      struct (Opcode.MULScc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    (* Population Count *)
    | 0b101110u -> struct (Opcode.POPC, parseTwoOpr b32 getSimm13 getRegRd)
    (* SAVE and RESTORE *)
    | 0b111100u ->
      struct (Opcode.SAVE, parseThrOpr b32 getRegRs1 getSimm13Zero getRegRd)
    | 0b111101u ->
      struct (Opcode.RESTORE, parseThrOpr b32 getRegRs1 getSimm13Zero getRegRd)
    (* Shift *)
    | 0b100101u ->
      match pickBit b32 12u with
      | 0b0u ->
        struct (Opcode.SLL, parseThrOpr b32 getRegRs1 getshcnt32 getRegRd)
      | 0b1u ->
        struct (Opcode.SLLX, parseThrOpr b32 getRegRs1 getshcnt64 getRegRd)
      | _ -> struct (Opcode.InvalidOp, NoOperand)
    | 0b100110u ->
      match pickBit b32 12u with
      | 0b0u ->
        struct (Opcode.SRL, parseThrOpr b32 getRegRs1 getshcnt32 getRegRd)
      | 0b1u ->
        struct (Opcode.SRLX, parseThrOpr b32 getRegRs1 getshcnt64 getRegRd)
      | _ -> struct (Opcode.InvalidOp, NoOperand)
    | 0b100111u ->
      match pickBit b32 12u with
      | 0b0u ->
        struct (Opcode.SRA, parseThrOpr b32 getRegRs1 getshcnt32 getRegRd)
      | 0b1u ->
        struct (Opcode.SRAX, parseThrOpr b32 getRegRs1 getshcnt64 getRegRd)
      | _ -> struct (Opcode.InvalidOp, NoOperand)
    (* Subtract *)
    | 0b000100u ->
      struct (Opcode.SUB, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b010100u ->
      struct (Opcode.SUBcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b001100u ->
      struct (Opcode.SUBC, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b011100u ->
      struct (Opcode.SUBCcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    (* Tagged Add *)
    | 0b100000u ->
      struct (Opcode.TADDcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b100010u ->
      struct (Opcode.TADDccTV, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    (* Tagged Subtract *)
    | 0b100001u ->
      struct (Opcode.TSUBcc, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b100011u ->
      struct (Opcode.TSUBccTV, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    (* Write Privileged Register *)
    | 0b110010u ->
      struct (Opcode.WRPR, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    (* Read Privileged Register *)
    | 0b101010u -> struct (Opcode.RDPR, parseTwoOpr b32 getPriReg getRegRd)
    (* Write State Register *)
    | 0b110000u -> parse110000 b32
    (* Move Integer Register on Condition *)
    | 0b101100u -> parse101100 b32
    (* Move Integer Register on Register Condition *)
    | 0b101111u -> parse101111 b32
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | _ -> struct (Opcode.InvalidOp, NoOperand)

(*
  11r_ __d- ---- ----
  ---- ---- ---- ----
*)
let parse11rd b32 =
  match pickBit b32 13u with
  | 0b0u ->
    match extract b32 24u 19u with
    | 0b011111u -> struct (Opcode.SWAPA, parseTwoOpr b32 getImmAsi getRegRd)
    | 0b001111u -> struct (Opcode.SWAP, parseTwoOpr b32 getAddrRs1 getRegRd)
    | 0b010101u ->
      struct (
        Opcode.STBA,
        parseFourOpr b32 getRegRd getAddrRs1 getAddrRs2 getImmAsi
      )
    | 0b010110u ->
      struct (
        Opcode.STHA,
        parseFourOpr b32 getRegRd getAddrRs1 getAddrRs2 getImmAsi
      )
    | 0b010100u ->
      struct (
        Opcode.STWA,
        parseFourOpr b32 getRegRd getAddrRs1 getAddrRs2 getImmAsi
      )
    | 0b011110u ->
      struct (
        Opcode.STXA,
        parseFourOpr b32 getRegRd getAddrRs1 getAddrRs2 getImmAsi
      )
    | 0b010111u ->
      struct (
        Opcode.STDA,
        parseFourOpr b32 getRegRd getAddrRs1 getAddrRs2 getImmAsi
      )
    | 0b000101u ->
      struct (Opcode.STB, parseThrOpr b32 getRegRd getAddrRs1 getAddrRs2)
    | 0b000110u ->
      struct (Opcode.STH, parseThrOpr b32 getRegRd getAddrRs1 getAddrRs2)
    | 0b000100u ->
      struct (Opcode.STW, parseThrOpr b32 getRegRd getAddrRs1 getAddrRs2)
    | 0b001110u ->
      struct (Opcode.STX, parseThrOpr b32 getRegRd getAddrRs1 getAddrRs2)
    | 0b000111u ->
      struct (Opcode.STD, parseThrOpr b32 getRegRd getAddrRs1 getAddrRs2)
    | 0b110100u ->
      struct (
        Opcode.STFA,
        parseFourOpr b32 getFloatRegRd getAddrRs1 getAddrRs2 getImmAsi
      )
    | 0b110111u ->
      struct (
        Opcode.STDFA,
        parseFourOpr b32 getDPFloatRegRd getAddrRs1 getAddrRs2 getImmAsi
      )
    | 0b110110u ->
      struct (
        Opcode.STQFA,
        parseFourOpr b32 getQPFloatRegRd getAddrRs1 getAddrRs2 getImmAsi
      )
    | 0b100100u ->
      struct (
        Opcode.STF,
        parseThrOpr b32 getFloatRegRd getAddrRs1 getAddrRs2
      )
    | 0b100111u ->
      struct (
        Opcode.STDF,
        parseThrOpr b32 getDPFloatRegRd getAddrRs1 getAddrRs2
      )
    | 0b100110u ->
      struct (
        Opcode.STQF,
        parseThrOpr b32 getQPFloatRegRd getAddrRs1 getAddrRs2
      )
    | 0b100101u ->
      match extract b32 29u 25u with
      | 0b00000u ->
        struct (
          Opcode.STFSR,
          parseOneRegTwoOpr b32 (setPriReg R.FSR) getAddrRs1 getAddrRs2
        )
      | 0b00001u ->
        struct (
          Opcode.STXFSR,
          parseOneRegTwoOpr b32 (setPriReg R.FSR) getAddrRs1 getAddrRs2
        )
      | _ -> struct (Opcode.InvalidOp, NoOperand)
    | 0b111100u ->
      struct (
        Opcode.CASA,
        parseFourOpr b32 getRegRs1 getRegAsi getRegRs2 getRegRd
      )
    | 0b111110u ->
      struct (
        Opcode.CASXA,
        parseFourOpr b32 getRegRs1 getRegAsi getRegRs2 getRegRd
      )
    | 0b100000u ->
      struct (
        Opcode.LDF,
        parseThrOpr b32 getAddrRs1 getAddrRs2 getFloatRegRd
      )
    | 0b100011u ->
      struct (
        Opcode.LDDF,
        parseThrOpr b32 getAddrRs1 getAddrRs2 getDPFloatRegRd
      )
    | 0b100010u ->
      struct (
        Opcode.LDQF,
        parseThrOpr b32 getAddrRs1 getAddrRs2 getQPFloatRegRd
      )
    | 0b100001u ->
      match extract b32 29u 25u with
      | 0b00000u ->
        struct (
          Opcode.LDFSR,
          parseTwoOprOneReg b32 getAddrRs1 getAddrRs2 (setPriReg R.FSR)
        )
      | 0b00001u ->
        struct (
          Opcode.LDXFSR,
          parseTwoOprOneReg b32 getAddrRs1 getAddrRs2 (setPriReg R.FSR)
        )
      | _ -> struct (Opcode.InvalidOp, NoOperand)
    | 0b110000u ->
      struct (
        Opcode.LDFA,
        parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getFloatRegRd
      )
    | 0b110011u ->
      struct (
        Opcode.LDDFA,
        parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getDPFloatRegRd
      )
    | 0b110010u ->
      struct (
        Opcode.LDQFA,
        parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getQPFloatRegRd
      )
    | 0b001001u ->
      struct (Opcode.LDSB, parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd)
    | 0b001010u ->
      struct (Opcode.LDSH, parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd)
    | 0b001000u ->
      struct (Opcode.LDSW, parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd)
    | 0b000001u ->
      struct (Opcode.LDUB, parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd)
    | 0b000010u ->
      struct (Opcode.LDUH, parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd)
    | 0b000000u ->
      struct (Opcode.LDUW, parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd)
    | 0b001011u ->
      struct (Opcode.LDX, parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd)
    | 0b000011u ->
      struct (Opcode.LDD, parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd)
    | 0b011001u ->
      struct (
        Opcode.LDSBA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13 getImmAsi getRegRd
      )
    | 0b011010u ->
      struct (
        Opcode.LDSHA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13 getImmAsi getRegRd
      )
    | 0b011000u ->
      struct (
        Opcode.LDSWA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13 getImmAsi getRegRd
      )
    | 0b010001u ->
      struct (
        Opcode.LDUBA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13 getImmAsi getRegRd
      )
    | 0b010010u ->
      struct (
        Opcode.LDUHA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13 getImmAsi getRegRd
      )
    | 0b011011u ->
      struct (
        Opcode.LDXA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13 getImmAsi getRegRd
      )
    | 0b010011u ->
      struct (
        Opcode.LDDA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13 getImmAsi getRegRd
      )
    | 0b001101u ->
      struct (Opcode.LDSTUB, parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd)
    | 0b011101u ->
      struct (
        Opcode.LDSTUBA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13 getImmAsi getRegRd
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b1u ->
    match extract b32 24u 19u with
    | 0b011111u -> struct (Opcode.SWAPA, parseTwoOpr b32 getRegAsi getRegRd)
    | 0b001111u -> struct (Opcode.SWAP, parseTwoOpr b32 getAddrRs1 getRegRd)
    | 0b010101u ->
      struct (
        Opcode.STBA,
        parseThrOprOneReg b32 getRegRd getAddrRs1 (setPriReg R.ASI)
          getAddrSimm13
      )
    | 0b010110u ->
      struct (
        Opcode.STHA,
        parseThrOprOneReg b32 getRegRd getAddrRs1 (setPriReg R.ASI)
          getAddrSimm13
      )
    | 0b010100u ->
      struct (
        Opcode.STWA,
        parseThrOprOneReg b32 getRegRd getAddrRs1 (setPriReg R.ASI)
          getAddrSimm13
      )
    | 0b011110u ->
      struct (
        Opcode.STXA,
        parseThrOprOneReg b32 getRegRd getAddrRs1 (setPriReg R.ASI)
          getAddrSimm13
      )
    | 0b010111u ->
      struct (
        Opcode.STDA,
        parseThrOprOneReg b32 getRegRd getAddrRs1 (setPriReg R.ASI)
          getAddrSimm13
      )
    | 0b000101u ->
      struct (Opcode.STB, parseThrOpr b32 getRegRd getAddrRs1 getAddrSimm13)
    | 0b000110u ->
      struct (Opcode.STH, parseThrOpr b32 getRegRd getAddrRs1 getAddrSimm13)
    | 0b000100u ->
      struct (Opcode.STW, parseThrOpr b32 getRegRd getAddrRs1 getAddrSimm13)
    | 0b001110u ->
      struct (Opcode.STX, parseThrOpr b32 getRegRd getAddrRs1 getAddrSimm13)
    | 0b000111u ->
      struct (Opcode.STD, parseThrOpr b32 getRegRd getAddrRs1 getAddrSimm13)
    | 0b110100u ->
      struct (
        Opcode.STFA,
        parseSTXA b32 getFloatRegRd getAddrRs1 getAddrSimm13 (setPriReg R.ASI)
      )
    | 0b110111u ->
      struct (
        Opcode.STDFA,
        parseSTXA b32 getDPFloatRegRd getAddrRs1 getAddrSimm13 (setPriReg R.ASI)
      )
    | 0b110110u ->
      struct (
        Opcode.STQFA,
        parseSTXA b32 getQPFloatRegRd getAddrRs1 getAddrSimm13 (setPriReg R.ASI)
      )
    | 0b100100u ->
      struct (
        Opcode.STF,
        parseThrOpr b32 getFloatRegRd getAddrRs1 getAddrSimm13
      )
    | 0b100111u ->
      struct (
        Opcode.STDF,
        parseThrOpr b32 getDPFloatRegRd getAddrRs1 getAddrSimm13
      )
    | 0b100110u ->
      struct (
        Opcode.STQF,
        parseThrOpr b32 getQPFloatRegRd getAddrRs1 getAddrSimm13
      )
    | 0b100101u ->
      match extract b32 29u 25u with
      | 0b00000u ->
        struct (
          Opcode.STFSR,
          parseOneRegTwoOpr b32 (setPriReg R.FSR) getAddrRs1 getAddrSimm13
        )
      | 0b00001u ->
        struct (
          Opcode.STXFSR,
          parseOneRegTwoOpr b32 (setPriReg R.FSR) getAddrRs1 getAddrSimm13
        )
      | _ -> struct (Opcode.InvalidOp, NoOperand)
    | 0b111100u ->
      struct (
        Opcode.CASA,
        parseFourOpr b32 getRegRs1 getRegAsi getRegRs2 getRegRd
      )
    | 0b111110u ->
      struct (
        Opcode.CASXA,
        parseFourOpr b32 getRegRs1 getRegAsi getRegRs2 getRegRd
      )
    | 0b100000u ->
      struct (
        Opcode.LDF,
        parseThrOpr b32 getAddrRs1 getAddrSimm13 getFloatRegRd
      )
    | 0b100011u ->
      struct (
        Opcode.LDDF,
        parseThrOpr b32 getAddrRs1 getAddrSimm13 getDPFloatRegRd
      )
    | 0b100010u ->
      struct (
        Opcode.LDQF,
        parseThrOpr b32 getAddrRs1 getAddrSimm13 getQPFloatRegRd
      )
    | 0b100001u ->
      match extract b32 29u 25u with
      | 0b00000u ->
        struct (
          Opcode.LDFSR,
          parseTwoOprOneReg b32 getAddrRs1 getAddrSimm13
            (setPriReg R.FSR)
        )
      | 0b00001u ->
        struct (
          Opcode.LDXFSR,
          parseTwoOprOneReg b32 getAddrRs1 getAddrSimm13
            (setPriReg R.FSR)
        )
      | _ -> struct (Opcode.InvalidOp, NoOperand)
    | 0b110000u ->
      struct (
        Opcode.LDFA,
        parseThrOprOneReg b32 getAddrRs1 getAddrSimm13
          (setPriReg R.ASI) getFloatRegRd
      )
    | 0b110011u ->
      struct (
        Opcode.LDDFA,
        parseThrOprOneReg b32 getAddrRs1 getAddrSimm13
          (setPriReg R.ASI) getDPFloatRegRd)
    | 0b110010u ->
      struct (
        Opcode.LDQFA,
        parseThrOprOneReg b32 getAddrRs1 getAddrSimm13
          (setPriReg R.ASI) getQPFloatRegRd
      )

    | 0b001001u ->
      struct (Opcode.LDSB, parseThrOpr b32 getAddrRs1 getAddrSimm13 getRegRd)
    | 0b001010u ->
      struct (Opcode.LDSH, parseThrOpr b32 getAddrRs1 getAddrSimm13 getRegRd)
    | 0b001000u ->
      struct (Opcode.LDSW, parseThrOpr b32 getAddrRs1 getAddrSimm13 getRegRd)
    | 0b000001u ->
      struct (Opcode.LDUB, parseThrOpr b32 getAddrRs1 getAddrSimm13 getRegRd)
    | 0b000010u ->
      struct (Opcode.LDUH, parseThrOpr b32 getAddrRs1 getAddrSimm13 getRegRd)
    | 0b000000u ->
      struct (Opcode.LDUW, parseThrOpr b32 getAddrRs1 getAddrSimm13 getRegRd)
    | 0b001011u ->
      struct (Opcode.LDX, parseThrOpr b32 getAddrRs1 getAddrSimm13 getRegRd)
    | 0b000011u ->
      struct (Opcode.LDD, parseThrOpr b32 getAddrRs1 getAddrSimm13 getRegRd)
    | 0b011001u ->
      struct (
        Opcode.LDSBA,
        parseThrOprOneReg b32 getAddrRs1 getAddrRs2
          (setPriReg R.ASI) getRegRd
      )
    | 0b011010u ->
      struct (
        Opcode.LDSHA,
        parseThrOprOneReg b32 getAddrRs1 getAddrRs2
          (setPriReg R.ASI) getRegRd
      )
    | 0b011000u ->
      struct (
        Opcode.LDSWA,
        parseThrOprOneReg b32 getAddrRs1 getAddrRs2
          (setPriReg R.ASI) getRegRd
      )
    | 0b010001u ->
      struct (
        Opcode.LDUBA,
        parseThrOprOneReg b32 getAddrRs1 getAddrRs2
          (setPriReg R.ASI) getRegRd
      )
    | 0b010010u ->
      struct (
        Opcode.LDUHA,
        parseThrOprOneReg b32 getAddrRs1 getAddrRs2
          (setPriReg R.ASI) getRegRd
      )
    | 0b011011u ->
      struct (
        Opcode.LDXA,
        parseThrOprOneReg b32 getAddrRs1 getAddrRs2
          (setPriReg R.ASI) getRegRd
      )
    | 0b010011u ->
      struct (
        Opcode.LDDA,
        parseThrOprOneReg b32 getAddrRs1 getAddrRs2
          (setPriReg R.ASI) getRegRd
      )
    | 0b001101u ->
      struct (Opcode.LDSTUB, parseThrOpr b32 getAddrRs1 getAddrSimm13 getRegRd)
    | 0b011101u ->
      struct (
        Opcode.LDSTUBA,
        parseThrOprOneReg b32 getAddrRs1 getAddrRs2
          (setPriReg R.ASI) getRegRd
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | _ -> struct (Opcode.InvalidOp, NoOperand)

(*
  00-- ---- ---- ----
  ---- ---- ---- ----
*)
let parse00 b32 =
  match extract b32 24u 22u with
  | 0b000u -> struct (Opcode.ILLTRAP, parseOneOpr b32 getConst22)
  | 0b100u ->
    match extract b32 29u 25u with
    | 0b00000u -> struct (Opcode.NOP, NoOperand)
    | _ -> struct (Opcode.SETHI, parseTwoOpr b32 getimm22 getRegRd)
  | 0b110u ->
    match extract b32 28u 25u with
    | 0b1000u -> struct (Opcode.FBA, parseOneOpr b32 getdisp22)
    | 0b0000u -> struct (Opcode.FBN, parseTwoOpr b32 getAbit getdisp22)
    | 0b0111u -> struct (Opcode.FBU, parseTwoOpr b32 getAbit getdisp22)
    | 0b0110u -> struct (Opcode.FBG, parseTwoOpr b32 getAbit getdisp22)
    | 0b0101u -> struct (Opcode.FBUG, parseTwoOpr b32 getAbit getdisp22)
    | 0b0100u -> struct (Opcode.FBL, parseTwoOpr b32 getAbit getdisp22)
    | 0b0011u -> struct (Opcode.FBUL, parseTwoOpr b32 getAbit getdisp22)
    | 0b0010u -> struct (Opcode.FBLG, parseTwoOpr b32 getAbit getdisp22)
    | 0b0001u -> struct (Opcode.FBNE, parseTwoOpr b32 getAbit getdisp22)
    | 0b1001u -> struct (Opcode.FBE, parseTwoOpr b32 getAbit getdisp22)
    | 0b1010u -> struct (Opcode.FBUE, parseTwoOpr b32 getAbit getdisp22)
    | 0b1011u -> struct (Opcode.FBGE, parseTwoOpr b32 getAbit getdisp22)
    | 0b1100u -> struct (Opcode.FBUGE, parseTwoOpr b32 getAbit getdisp22)
    | 0b1101u -> struct (Opcode.FBLE, parseTwoOpr b32 getAbit getdisp22)
    | 0b1110u -> struct (Opcode.FBULE, parseTwoOpr b32 getAbit getdisp22)
    | 0b1111u -> struct (Opcode.FBO, parseTwoOpr b32 getAbit getdisp22)
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b101u ->
    match extract b32 28u 25u with
    | 0b1000u ->
      struct (
        Opcode.FBPA,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0000u ->
      struct (
        Opcode.FBPN,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0111u ->
      struct (
        Opcode.FBPU,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0110u ->
      struct (
        Opcode.FBPG,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0101u ->
      struct (
        Opcode.FBPUG,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0100u ->
      struct (
        Opcode.FBPL,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0011u ->
      struct (
        Opcode.FBPUL,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          )
    | 0b0010u ->
      struct (
        Opcode.FBPLG,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          )
    | 0b0001u ->
      struct (
        Opcode.FBPNE,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1001u ->
      struct (
        Opcode.FBPE,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1010u ->
      struct (
        Opcode.FBPUE,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1011u ->
      struct (
        Opcode.FBPGE,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1100u ->
      struct (
        Opcode.FBPUGE,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1101u ->
      struct (
        Opcode.FBPLE,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1110u ->
      struct (
        Opcode.FBPULE,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1111u ->
      struct (
        Opcode.FBPO,
        parseOneCCOneOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b010u ->
    match extract b32 28u 25u with
    | 0b1000u -> struct (Opcode.BA, parseTwoOpr b32 getAbit getdisp22)
    | 0b0000u -> struct (Opcode.BN, parseTwoOpr b32 getAbit getdisp22)
    | 0b1001u -> struct (Opcode.BNE, parseTwoOpr b32 getAbit getdisp22)
    | 0b0001u -> struct (Opcode.BE, parseTwoOpr b32 getAbit getdisp22)
    | 0b1010u -> struct (Opcode.BG, parseTwoOpr b32 getAbit getdisp22)
    | 0b0010u -> struct (Opcode.BLE, parseTwoOpr b32 getAbit getdisp22)
    | 0b1011u -> struct (Opcode.BGE, parseTwoOpr b32 getAbit getdisp22)
    | 0b0011u -> struct (Opcode.BL, parseTwoOpr b32 getAbit getdisp22)
    | 0b1100u -> struct (Opcode.BGU, parseTwoOpr b32 getAbit getdisp22)
    | 0b0100u -> struct (Opcode.BLEU, parseTwoOpr b32 getAbit getdisp22)
    | 0b1101u -> struct (Opcode.BCC, parseTwoOpr b32 getAbit getdisp22)
    | 0b0101u -> struct (Opcode.BCS, parseTwoOpr b32 getAbit getdisp22)
    | 0b1110u -> struct (Opcode.BPOS, parseTwoOpr b32 getAbit getdisp22)
    | 0b0110u -> struct (Opcode.BNEG, parseTwoOpr b32 getAbit getdisp22)
    | 0b1111u -> struct (Opcode.BVC, parseTwoOpr b32 getAbit getdisp22)
    | 0b0111u -> struct (Opcode.BVS, parseTwoOpr b32 getAbit getdisp22)
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b001u ->
    match extract b32 28u 25u with
    | 0b1000u ->
      struct (
        Opcode.BPA,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0000u ->
      struct (
        Opcode.BPN,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1001u ->
      struct (
        Opcode.BPNE,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0001u ->
      struct (
        Opcode.BPE,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1010u ->
      struct (
        Opcode.BPG,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0010u ->
      struct (
        Opcode.BPLE,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1011u ->
      struct (
        Opcode.BPGE,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0011u ->
      struct (
        Opcode.BPL,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1100u ->
      struct (
        Opcode.BPGU,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0100u ->
      struct (
        Opcode.BPLEU,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1101u ->
      struct (
        Opcode.BPCC,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0101u ->
      struct (
        Opcode.BPCS,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1110u ->
      struct (
        Opcode.BPPOS,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0110u ->
      struct (
        Opcode.BPNEG,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b1111u ->
      struct (
        Opcode.BPVC,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | 0b0111u ->
      struct (
        Opcode.BPVS,
        parseOneCCOneOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b011u ->
    match extract b32 27u 25u with
    | 0b001u ->
      struct (
        Opcode.BRZ,
        parseOneOprOneCC
          b32
          getRegRs1
          (getTwod16 (getd16hi b32) (getd16lo b32))
      )
    | 0b010u ->
      struct (
        Opcode.BRLEZ,
        parseOneOprOneCC
          b32
          getRegRs1
          (getTwod16 (getd16hi b32) (getd16lo b32))
      )
    | 0b011u ->
      struct (
        Opcode.BRLZ,
        parseOneOprOneCC
          b32
          getRegRs1
          (getTwod16 (getd16hi b32) (getd16lo b32))
      )
    | 0b101u ->
      struct (
        Opcode.BRNZ,
        parseOneOprOneCC
          b32
          getRegRs1
          (getTwod16 (getd16hi b32) (getd16lo b32))
      )
    | 0b110u ->
      struct (
        Opcode.BRGZ,
        parseOneOprOneCC
          b32
          getRegRs1
          (getTwod16 (getd16hi b32) (getd16lo b32))
      )
    | 0b111u ->
      struct (
        Opcode.BRGEZ,
        parseOneOprOneCC
          b32
          getRegRs1
          (getTwod16 (getd16hi b32) (getd16lo b32))
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | _ -> struct (Opcode.InvalidOp, NoOperand)

(*
  10-- ---- ---- ----
  ---- ---- ---- ----
*)
let parse10 b32 =
  match extract b32 24u 19u with
  | 0b111010u ->
    match pickBit b32 13u with
    | 0b0u ->
      match extract b32 28u 25u with
      | 0b1000u ->
        struct (
          Opcode.TA,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          )
      | 0b0000u ->
        struct (
          Opcode.TN,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b1001u ->
        struct (
          Opcode.TNE,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0001u ->
        struct (
          Opcode.TE,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b1010u ->
        struct (
          Opcode.TG,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0010u ->
        struct (
          Opcode.TLE,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b1011u ->
        struct (
          Opcode.TGE,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0011u ->
        struct (
          Opcode.TL,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b1100u ->
        struct (
          Opcode.TGU,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0100u ->
        struct (
          Opcode.TLEU,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b1101u ->
        struct (
          Opcode.TCC,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0101u ->
        struct (
          Opcode.TCS,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b1110u ->
        struct (
          Opcode.TPOS,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0110u ->
        struct (
          Opcode.TNEG,
                parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32)))
      | 0b1111u ->
        struct (
          Opcode.TVC,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0111u ->
        struct (
          Opcode.TVS,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | _ -> struct (Opcode.InvalidOp, NoOperand)
    | 0b1u ->
      match extract b32 28u 25u with
      | 0b1000u ->
        struct (
          Opcode.TA,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0000u ->
        struct (
          Opcode.TN,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b1001u ->
        struct (
          Opcode.TNE,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0001u ->
        struct (
          Opcode.TE,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b1010u ->
        struct (
          Opcode.TG,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0010u ->
        struct (
          Opcode.TLE,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b1011u ->
        struct (
          Opcode.TGE,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0011u ->
        struct (
          Opcode.TL,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b1100u ->
        struct (
          Opcode.TGU,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0100u ->
        struct (
          Opcode.TLEU,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b1101u ->
        struct (
          Opcode.TCC,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0101u ->
        struct (
          Opcode.TCS,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b1110u ->
        struct (Opcode.TPOS,
                parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32)))
      | 0b0110u ->
        struct (
          Opcode.TNEG,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b1111u ->
        struct (
          Opcode.TVC,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | 0b0111u ->
        struct (
          Opcode.TVS,
          parseOneCC (getTwoCCix (get21cc1 b32) (get20cc0 b32))
        )
      | _ -> struct (Opcode.InvalidOp, NoOperand)
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b101000u ->
    match pickBit b32 25u with
    | 0u ->
      match pickBit b32 13u with
      | 0b0u -> struct (Opcode.STBAR, NoOperand)
      | 0b1u -> struct (Opcode.MEMBAR, parseOneOpr b32 getMembarMask)
      | _ -> struct (Opcode.InvalidOp, NoOperand)
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b110000u -> struct (Opcode.SIR, parseOneOpr b32 getSimm13)
  | 0b110001u ->
    match pickBit b32 25u with
    | 0u -> struct (Opcode.SAVED, NoOperand)
    | 1u -> struct (Opcode.RESTORED, NoOperand)
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b111001u ->
    match pickBit b32 13u with
    | 0b0u -> struct (Opcode.RETURN, parseTwoOpr b32 getRegRs1 getRegRs2)
    | 0b1u -> struct (Opcode.RETURN, parseTwoOpr b32 getRegRs1 getSimm13)
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b111110u ->
    match pickBit b32 25u with
    | 0u -> struct (Opcode.DONE, NoOperand)
    | 1u -> struct (Opcode.RETRY, NoOperand)
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b110101u ->
    match extract b32 13u 5u with
    | 0b001010001u ->
      struct (
        Opcode.FCMPs,
        parseOneCCTwoOpr b32 (getTwoCCFcc (get26cc1 b32) (get25cc0 b32))
          getFloatRegRs1
          getFloatRegRs2
      )
    | 0b001010010u ->
      struct (Opcode.FCMPd,
              parseOneCCTwoOpr
                b32
                (getTwoCCFcc (get26cc1 b32) (get25cc0 b32))
                getDPFloatRegRs1
                getDPFloatRegRs2)
    | 0b001010011u ->
      struct (
        Opcode.FCMPq,
        parseOneCCTwoOpr b32 (getTwoCCFcc (get26cc1 b32) (get25cc0 b32))
          getQPFloatRegRs1
          getQPFloatRegRs2
      )
    | 0b001010101u ->
      struct (
        Opcode.FCMPEs,
        parseOneCCTwoOpr b32 (getTwoCCFcc (get26cc1 b32) (get25cc0 b32))
          getFloatRegRs1
          getFloatRegRs2
      )
    | 0b001010110u ->
      struct (
        Opcode.FCMPEd,
        parseOneCCTwoOpr b32 (getTwoCCFcc (get26cc1 b32) (get25cc0 b32))
          getDPFloatRegRs1 getDPFloatRegRs2
      )
    | 0b001010111u ->
      struct (
        Opcode.FCMPEq,
        parseOneCCTwoOpr b32 (getTwoCCFcc (get26cc1 b32) (get25cc0 b32))
          getQPFloatRegRs1
          getQPFloatRegRs2
      )
    | _ -> parse110101 b32
  | 0b111011u ->
    match pickBit b32 13u with
    | 0b0u -> struct (Opcode.FLUSH, parseTwoOpr b32 getRegRs1 getRegRs2)
    | 0b1u -> struct (Opcode.FLUSH, parseTwoOpr b32 getRegRs1 getSimm13)
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b101011u -> struct (Opcode.FLUSHW, NoOperand)
  | 0b110110u -> struct (Opcode.IMPDEP1, parseOneOpr b32 getImplDep)
  | 0b110111u -> struct (Opcode.IMPDEP2, parseOneOpr b32 getImplDep)
  | _ -> parse10rd b32

(*
  11-- ---- ---- ----
  ---- ---- ---- ----
*)
let parse11 b32 =
  match pickBit b32 13u with
  | 0b0u ->
    match extract b32 24u 19u with
    | 0b101101u ->
      struct (Opcode.PREFETCH, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b111101u ->
      struct (
        Opcode.PREFETCHA,
        parseFourOpr b32 getRegRs1 getRegRs2 getImmAsi getRegRd
      )
    | _ -> parse11rd b32
  | 0b1u ->
    match extract b32 24u 19u with
    | 0b101101u ->
      struct (Opcode.PREFETCH, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b111101u ->
      struct (
        Opcode.PREFETCHA,
        parseThrOprOneReg b32 getRegRs1 getSimm13 (setPriReg R.ASI)
          getRegRd
      )
    | _ -> parse11rd b32
  | _ -> parse11rd b32

let parseTwoBits bin =
  match extract bin 31u 30u with
  | 0b00u -> parse00 bin
  | 0b01u -> struct (Opcode.CALL, parseOneOpr bin getdisp30)
  | 0b10u -> parse10 bin
  | 0b11u -> parse11 bin
  | _ -> struct (Opcode.InvalidOp, NoOperand)

let parse (span: ByteSpan) (reader: IBinReader) addr =
  let bin = reader.ReadInt32 (span, 0)
  let struct (op, operands) = uint32 bin |> parseTwoBits

  let insInfo =
    { Address = addr
      NumBytes = 4u
      Opcode = op
      Operands = operands }

  SPARCInstruction (addr, 4u, insInfo)

// vim: set tw=80 sts=2 sw=2:
