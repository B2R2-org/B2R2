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

module internal B2R2.FrontEnd.SPARC.ParsingMain

open B2R2.FrontEnd.BinLifter
open type Register

let getRegister = function
  | 0x0uy -> G0
  | 0x1uy -> G1
  | 0x2uy -> G2
  | 0x3uy -> G3
  | 0x4uy -> G4
  | 0x5uy -> G5
  | 0x6uy -> G6
  | 0x7uy -> G7
  | 0x8uy -> O0
  | 0x9uy -> O1
  | 0xAuy -> O2
  | 0xBuy -> O3
  | 0xCuy -> O4
  | 0xDuy -> O5
  | 0xEuy -> O6
  | 0xFuy -> O7
  | 0x10uy -> L0
  | 0x11uy -> L1
  | 0x12uy -> L2
  | 0x13uy -> L3
  | 0x14uy -> L4
  | 0x15uy -> L5
  | 0x16uy -> L6
  | 0x17uy -> L7
  | 0x18uy -> I0
  | 0x19uy -> I1
  | 0x1Auy -> I2
  | 0x1Buy -> I3
  | 0x1Cuy -> I4
  | 0x1Duy -> I5
  | 0x1Euy -> I6
  | 0x1Fuy -> I7
  | _ -> raise InvalidRegisterException

let getFloatRegister = function
  | 0x0uy -> F0
  | 0x1uy -> F1
  | 0x2uy -> F2
  | 0x3uy -> F3
  | 0x4uy -> F4
  | 0x5uy -> F5
  | 0x6uy -> F6
  | 0x7uy -> F7
  | 0x8uy -> F8
  | 0x9uy -> F9
  | 0xauy -> F10
  | 0xbuy -> F11
  | 0xcuy -> F12
  | 0xduy -> F13
  | 0xeuy -> F14
  | 0xfuy -> F15
  | 0x10uy -> F16
  | 0x11uy -> F17
  | 0x12uy -> F18
  | 0x13uy -> F19
  | 0x14uy -> F20
  | 0x15uy -> F21
  | 0x16uy -> F22
  | 0x17uy -> F23
  | 0x18uy -> F24
  | 0x19uy -> F25
  | 0x1auy -> F26
  | 0x1buy -> F27
  | 0x1cuy -> F28
  | 0x1duy -> F29
  | 0x1euy -> F30
  | 0x1fuy -> F31
  | _ -> raise InvalidRegisterException

let getDPFloatRegister = function
  | 0x0uy -> F0
  | 0x1uy -> F32
  | 0x2uy -> F2
  | 0x3uy -> F34
  | 0x4uy -> F4
  | 0x5uy -> F36
  | 0x6uy -> F6
  | 0x7uy -> F38
  | 0x8uy -> F8
  | 0x9uy -> F40
  | 0xauy -> F10
  | 0xbuy -> F42
  | 0xcuy -> F12
  | 0xduy -> F44
  | 0xeuy -> F14
  | 0xfuy -> F46
  | 0x10uy -> F16
  | 0x11uy -> F48
  | 0x12uy -> F18
  | 0x13uy -> F50
  | 0x14uy -> F20
  | 0x15uy -> F52
  | 0x16uy -> F22
  | 0x17uy -> F54
  | 0x18uy -> F24
  | 0x19uy -> F56
  | 0x1auy -> F26
  | 0x1buy -> F58
  | 0x1cuy -> F28
  | 0x1duy -> F60
  | 0x1euy -> F30
  | 0x1fuy -> F62
  | _ -> raise InvalidRegisterException

let getQPFloatRegister = function
  | 0x0uy -> F0
  | 0x01uy -> F32
  | 0x4uy -> F4
  | 0x05uy -> F36
  | 0x8uy -> F8
  | 0x9uy -> F40
  | 0xcuy -> F12
  | 0xduy -> F44
  | 0x10uy -> F16
  | 0x11uy -> F48
  | 0x14uy -> F20
  | 0x15uy -> F52
  | 0x18uy -> F24
  | 0x19uy -> F56
  | 0x1cuy -> F28
  | 0x1duy -> F60
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

let parseOneCCThrOpr b cc1 op1 op2 op3 = FourOperands (cc1, op1 b, op2 b, op3 b)

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

let getRegAsi b = ASI |> OprReg

let getRegFsr b = FSR |> OprReg

let getConst22 b = extract b 21u 0u |> int32 |> OprImm

let getimm22 b =
  extract b 21u 0u <<< 10 |> int32 |> OprImm

let getSimm13 b =
  (extract b 12u 0u) <<< 19 |> int32 >>> 19 |> OprImm

let getSimm13Zero b =
  let checkSimm13 = (extract b 12u 0u) <<< 19 |> int32 >>> 19
  if checkSimm13 = 0 then getReg b 12u 0u |> OprReg
  else checkSimm13 |> OprImm

let getSimm11 b =
  (extract b 10u 0u) <<< 21 |> int32 >>> 21 |> OprImm

let getSimm10 b =
  (extract b 9u 0u) <<< 22 |> int32 >>> 22 |> OprImm


let getAbit b = pickBit b 29u |> int32 |> OprImm

let getPbit b = pickBit b 19u |> int32 |> OprImm

let getd16hi b = extract b 21u 20u |> uint32

let getd16lo b = extract b 13u 0u |> uint32

let getdisp30 b =
  let disp30 = extract b 29u 0u <<< 2 |> int32 >>> 2
  4 * disp30 |> int32 |> OprAddr

let getdisp22 b =
  let disp22 = extract b 21u 0u <<< 10 |> int32 >>> 10
  4 * disp22 |> OprAddr

let getdisp19 b =
  let disp19 = extract b 18u 0u <<< 13 |> int32 >>> 13
  4 * disp19 |> OprAddr

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

let getd16 b =
  let hi = extract b 21u 20u
  let lo = extract b 13u 0u
  (hi <<< 14 ||| lo) * 4u |> int32 |> OprAddr

let getPriReg b32 s e =
  match (extract b32 s e) |> byte with
  | 0uy -> TPC |> OprPriReg
  | 1uy -> TNPC |> OprPriReg
  | 2uy -> TSTATE |> OprPriReg
  | 3uy -> TT |> OprPriReg
  | 4uy -> TICK |> OprPriReg
  | 5uy -> TBA |> OprPriReg
  | 6uy -> PSTATE |> OprPriReg
  | 7uy -> TL |> OprPriReg
  | 8uy -> PIL |> OprPriReg
  | 9uy -> CWP |> OprPriReg
  | 10uy -> CANSAVE |> OprPriReg
  | 11uy -> CANRESTORE |> OprPriReg
  | 12uy -> CLEANWIN |> OprPriReg
  | 13uy -> OTHERWIN |> OprPriReg
  | 14uy -> WSTATE |> OprPriReg
  | 15uy -> FQ |> OprPriReg
  | 31uy -> VER |> OprPriReg
  | _ -> raise InvalidRegisterException

let priregRDPR b32 = getPriReg b32 18u 14u

let priregWRPR b32 = getPriReg b32 29u 25u

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
  | 0u -> struct (Opcode.RDY, parseOneRegOneOpr b32 (setPriReg Y) getRegRd)
  | 2u ->
    struct (Opcode.RDCCR, parseOneRegOneOpr b32 (setPriReg CCR) getRegRd)
  | 3u ->
    struct (Opcode.RDASI, parseOneRegOneOpr b32 (setPriReg ASI) getRegRd)
  | 4u ->
    struct (Opcode.RDTICK, parseOneRegOneOpr b32 (setPriReg TICK) getRegRd)
  | 5u -> struct (Opcode.RDPC, parseOneRegOneOpr b32 (setPriReg PC) getRegRd)
  | 6u ->
    struct (Opcode.RDFPRS, parseOneRegOneOpr b32 (setPriReg FPRS) getRegRd)
  | 7u
  | 8u
  | 9u
  | 10u
  | 12u
  | 13u
  | 14u -> struct (Opcode.RDASR, parseTwoOpr b32 getRegRs1 getRegRd)
  | 15u ->
    match pickBit b32 13u with
    | 0b0u -> struct (Opcode.STBAR, NoOperand)
    | _ -> struct (Opcode.MEMBAR, parseOneOpr b32 getMembarMask)
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
    | 0u -> struct (Opcode.WRY,
              parseTwoOprOneReg b32 getRegRs1 getRegRs2 (setPriReg Y))
    | 2u -> struct (Opcode.WRCCR,
              parseTwoOprOneReg b32 getRegRs1 getRegRs2 (setPriReg CCR))
    | 3u -> struct (Opcode.WRASI,
              parseTwoOprOneReg b32 getRegRs1 getRegRs2 (setPriReg ASI))
    | 4u
    | 5u
    | 7u
    | 8u
    | 9u
    | 10u
    | 12u
    | 13u
    | 14u -> struct (Opcode.WRASR, parseTwoOpr b32 getRegRs1 getRegRs2)
    | 6u -> struct (Opcode.WRFPRS,
                  parseTwoOprOneReg b32 getRegRs1 getRegRs2 (setPriReg FPRS))
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
              parseTwoOprOneReg b32 getRegRs1 getSimm13 (setPriReg Y))
    | 2u ->
      struct (Opcode.WRCCR,
              parseTwoOprOneReg b32 getRegRs1 getSimm13 (setPriReg CCR))
    | 3u ->
      struct (Opcode.WRASI,
              parseTwoOprOneReg b32 getRegRs1 getSimm13 (setPriReg ASI))
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
        parseTwoOprOneReg b32 getRegRs1 getSimm13 (setPriReg FPRS)
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
  match (get18cc2 b32), (get12cc1 b32), (get11cc0 b32) with
  | 0b0u, 0b0u, 0b0u
  | 0b0u, 0b0u, 0b1u
  | 0b0u, 0b1u, 0b0u
  | 0b0u, 0b1u, 0b1u ->
    match pickBit b32 13u with
    | 0b0u ->
      match extract b32 17u 14u with
      | 0b1000u ->
        struct (
          Opcode.MOVFA,
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2 getRegRd
          )
      | 0b0000u ->
        struct (
          Opcode.MOVFN,
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2 getRegRd
        )
      | 0b0111u ->
        struct (
          Opcode.MOVFU,
          parseOneCCTwoOpr
            b32 (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        )
      | 0b0110u ->
        struct (
          Opcode.MOVFG,
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        )
      | 0b0101u ->
        struct (
          Opcode.MOVFUG,
          parseOneCCTwoOpr
            b32 (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        )
      | 0b0100u ->
        struct (
          Opcode.MOVFL,
          parseOneCCTwoOpr
            b32 (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2 getRegRd
        )
      | 0b0011u ->
        struct (
          Opcode.MOVFUL,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2 getRegRd
        )
      | 0b0010u ->
        struct (
          Opcode.MOVFLG,
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2 getRegRd
        )
      | 0b0001u ->
        struct (
          Opcode.MOVFNE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        )
      | 0b1001u ->
        struct (
          Opcode.MOVFE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        )
      | 0b1010u ->
        struct (
          Opcode.MOVFUE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        )
      | 0b1011u ->
        struct (
          Opcode.MOVFGE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        )
      | 0b1100u ->
        struct (
          Opcode.MOVFUGE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        )
      | 0b1101u ->
        struct (
          Opcode.MOVFLE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        )
      | 0b1110u ->
        struct (
          Opcode.MOVFULE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd)
      | 0b1111u ->
        struct (
          Opcode.MOVFO,
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
          Opcode.MOVFA,
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11 getRegRd
          )
      | 0b0000u ->
        struct (
          Opcode.MOVFN,
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11 getRegRd
        )
      | 0b0111u ->
        struct (
          Opcode.MOVFU,
          parseOneCCTwoOpr
            b32 (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b0110u ->
        struct (
          Opcode.MOVFG,
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b0101u ->
        struct (
          Opcode.MOVFUG,
          parseOneCCTwoOpr
            b32 (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b0100u ->
        struct (
          Opcode.MOVFL,
          parseOneCCTwoOpr
            b32 (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11 getRegRd
        )
      | 0b0011u ->
        struct (
          Opcode.MOVFUL,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11 getRegRd
        )
      | 0b0010u ->
        struct (
          Opcode.MOVFLG,
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11 getRegRd
        )
      | 0b0001u ->
        struct (
          Opcode.MOVFNE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b1001u ->
        struct (
          Opcode.MOVFE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b1010u ->
        struct (
          Opcode.MOVFUE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b1011u ->
        struct (
          Opcode.MOVFGE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b1100u ->
        struct (
          Opcode.MOVFUGE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b1101u ->
        struct (
          Opcode.MOVFLE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b1110u ->
        struct (
          Opcode.MOVFULE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd)
      | 0b1111u ->
        struct (
          Opcode.MOVFO,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | _ -> struct (Opcode.InvalidOp, NoOperand)
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b1u, 0b0u, 0b0u
  | 0b1u, 0b1u, 0b0u ->
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
            getSimm11
            getRegRd
        )
      | 0b0000u ->
        struct (
          Opcode.MOVN,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b1001u ->
        struct (
          Opcode.MOVNE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b0001u ->
        struct (
          Opcode.MOVE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b1010u ->
        struct (
          Opcode.MOVG,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b0010u ->
        struct (
          Opcode.MOVLE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b1011u ->
        struct (
          Opcode.MOVGE,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b0011u ->
        struct (
          Opcode.MOVL,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b1100u ->
        struct (
          Opcode.MOVGU,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b0100u ->
        struct (
          Opcode.MOVLEU,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b1101u ->
        struct (
          Opcode.MOVCC,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b0101u ->
        struct (
          Opcode.MOVCS,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b1110u ->
        struct (
          Opcode.MOVPOS,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b0110u ->
        struct (
          Opcode.MOVNEG,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b1111u ->
        struct (
          Opcode.MOVVC,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        )
      | 0b0111u ->
        struct (
          Opcode.MOVVS,
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
            )
      | _ -> struct (Opcode.InvalidOp, NoOperand)
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
      struct (Opcode.WRPR, parseThrOpr b32 getRegRs1 getRegRs2 priregWRPR)
    (* Move Floating-Point Register on Condition (FMOVcc) *)
    | 0b110101u -> parse110101 b32
    (* Floating-Point *)
    | 0b110100u -> parseFP b32
    (* Read State Register *)
    | 0b101000u -> parse101000 b32
    (* Read Privileged State Register *)
    | 0b101010u -> struct (Opcode.RDPR, parseTwoOpr b32 priregRDPR getRegRd)
    (* Write State Register *)
    | 0b110000u -> parse110000 b32
    (* Move Integer Register on Condition *)
    | 0b101100u -> parse101100 b32
    (* Move Integer Register on Register Condition *)
    | 0b101111u -> parse101111 b32
    | _ -> Opcode.InvalidOp, NoOperand
  | 0b1u ->
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
      struct (Opcode.WRPR, parseThrOpr b32 getRegRs1 getSimm13 priregWRPR)
    (* Read Privileged Register *)
    | 0b101010u -> struct (Opcode.RDPR, parseTwoOpr b32 priregRDPR getRegRd)
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
    | 0b011111u -> struct (Opcode.SWAPA, parseFourOpr b32 getAddrRs1
        getAddrRs2 getImmAsi getRegRd)
    | 0b001111u -> struct (
        Opcode.SWAP,
        parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd
      )
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
          parseOneRegTwoOpr b32 (setPriReg FSR) getAddrRs1 getAddrRs2
        )
      | 0b00001u ->
        struct (
          Opcode.STXFSR,
          parseOneRegTwoOpr b32 (setPriReg FSR) getAddrRs1 getAddrRs2
        )
      | _ -> struct (Opcode.InvalidOp, NoOperand)
    | 0b111100u ->
      struct (
        Opcode.CASA,
        parseFourOpr b32 getRegRs1 getImmAsi getRegRs2 getRegRd
      )
    | 0b111110u ->
      struct (
        Opcode.CASXA,
        parseFourOpr b32 getRegRs1 getImmAsi getRegRs2 getRegRd
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
          parseTwoOprOneReg b32 getAddrRs1 getAddrRs2 (setPriReg FSR)
        )
      | 0b00001u ->
        struct (
          Opcode.LDXFSR,
          parseTwoOprOneReg b32 getAddrRs1 getAddrRs2 (setPriReg FSR)
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
        parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      )
    | 0b011010u ->
      struct (
        Opcode.LDSHA,
        parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      )
    | 0b011000u ->
      struct (
        Opcode.LDSWA,
        parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      )
    | 0b010001u ->
      struct (
        Opcode.LDUBA,
        parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      )
    | 0b010010u ->
      struct (
        Opcode.LDUHA,
        parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      )
    | 0b010000u ->
      struct (
        Opcode.LDUWA,
        parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      )
    | 0b011011u ->
      struct (
        Opcode.LDXA,
        parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      )
    | 0b010011u ->
      struct (
        Opcode.LDDA,
        parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      )
    | 0b001101u ->
      struct (Opcode.LDSTUB, parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd)
    | 0b011101u ->
      struct (
        Opcode.LDSTUBA,
        parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b1u ->
    match extract b32 24u 19u with
    | 0b011111u -> struct (Opcode.SWAPA, parseFourOpr b32 getRegRs1
        getSimm13 getRegAsi getRegRd)
    | 0b001111u -> struct (
        Opcode.SWAP,
        parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd
      )
    | 0b010101u ->
      struct (
        Opcode.STBA,
        parseFourOpr b32 getRegRd getAddrRs1
          getAddrSimm13 getRegAsi
      )
    | 0b010110u ->
      struct (
        Opcode.STHA,
        parseFourOpr b32 getRegRd getAddrRs1
          getAddrSimm13 getRegAsi
      )
    | 0b010100u ->
      struct (
        Opcode.STWA,
        parseFourOpr b32 getRegRd getAddrRs1
          getAddrSimm13 getRegAsi
      )
    | 0b011110u ->
      struct (
        Opcode.STXA,
        parseFourOpr b32 getRegRd getAddrRs1
          getAddrSimm13 getRegAsi
      )
    | 0b010111u ->
      struct (
        Opcode.STDA,
        parseFourOpr b32 getRegRd getAddrRs1
          getAddrSimm13 getRegAsi
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
        parseSTXA b32 getFloatRegRd getAddrRs1 getAddrSimm13 (setPriReg ASI)
      )
    | 0b110111u ->
      struct (
        Opcode.STDFA,
        parseSTXA b32 getDPFloatRegRd getAddrRs1 getAddrSimm13 (setPriReg ASI)
      )
    | 0b110110u ->
      struct (
        Opcode.STQFA,
        parseSTXA b32 getQPFloatRegRd getAddrRs1 getAddrSimm13 (setPriReg ASI)
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
          parseOneRegTwoOpr b32 (setPriReg FSR) getAddrRs1 getAddrSimm13
        )
      | 0b00001u ->
        struct (
          Opcode.STXFSR,
          parseOneRegTwoOpr b32 (setPriReg FSR) getAddrRs1 getAddrSimm13
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
            (setPriReg FSR)
        )
      | 0b00001u ->
        struct (
          Opcode.LDXFSR,
          parseTwoOprOneReg b32 getAddrRs1 getAddrSimm13
            (setPriReg FSR)
        )
      | _ -> struct (Opcode.InvalidOp, NoOperand)
    | 0b110000u ->
      struct (
        Opcode.LDFA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13
          getRegAsi getFloatRegRd
      )
    | 0b110011u ->
      struct (
        Opcode.LDDFA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13
          getRegAsi getDPFloatRegRd)
    | 0b110010u ->
      struct (
        Opcode.LDQFA,
        parseThrOprOneReg b32 getAddrRs1 getAddrSimm13
          (setPriReg ASI) getQPFloatRegRd
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
        parseFourOpr b32 getAddrRs1 getAddrSimm13
          getRegAsi getRegRd
      )
    | 0b011010u ->
      struct (
        Opcode.LDSHA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13
          getRegAsi getRegRd
      )
    | 0b011000u ->
      struct (
        Opcode.LDSWA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13
          getRegAsi getRegRd
      )
    | 0b010001u ->
      struct (
        Opcode.LDUBA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13
          getRegAsi getRegRd
      )
    | 0b010010u ->
      struct (
        Opcode.LDUHA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13
          getRegAsi getRegRd
      )
    | 0b010000u ->
      struct (
        Opcode.LDUWA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13
          getRegAsi getRegRd
      )
    | 0b011011u ->
      struct (
        Opcode.LDXA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13
          getRegAsi getRegRd
      )
    | 0b010011u ->
      struct (
        Opcode.LDDA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13
          getRegAsi getRegRd
      )
    | 0b001101u ->
      struct (Opcode.LDSTUB, parseThrOpr b32 getAddrRs1 getAddrSimm13 getRegRd)
    | 0b011101u ->
      struct (
        Opcode.LDSTUBA,
        parseFourOpr b32 getAddrRs1 getAddrSimm13
          getRegAsi getRegRd
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
    | 0b1000u -> struct (Opcode.FBA, parseTwoOpr b32 getAbit getdisp22)
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
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0000u ->
      struct (
        Opcode.FBPN,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0111u ->
      struct (
        Opcode.FBPU,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0110u ->
      struct (
        Opcode.FBPG,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0101u ->
      struct (
        Opcode.FBPUG,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0100u ->
      struct (
        Opcode.FBPL,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0011u ->
      struct (
        Opcode.FBPUL,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
          )
    | 0b0010u ->
      struct (
        Opcode.FBPLG,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
          )
    | 0b0001u ->
      struct (
        Opcode.FBPNE,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1001u ->
      struct (
        Opcode.FBPE,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1010u ->
      struct (
        Opcode.FBPUE,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1011u ->
      struct (
        Opcode.FBPGE,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1100u ->
      struct (
        Opcode.FBPUGE,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1101u ->
      struct (
        Opcode.FBPLE,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1110u ->
      struct (
        Opcode.FBPULE,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1111u ->
      struct (
        Opcode.FBPO,
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
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
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0000u ->
      struct (
        Opcode.BPN,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1001u ->
      struct (
        Opcode.BPNE,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0001u ->
      struct (
        Opcode.BPE,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1010u ->
      struct (
        Opcode.BPG,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0010u ->
      struct (
        Opcode.BPLE,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1011u ->
      struct (
        Opcode.BPGE,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0011u ->
      struct (
        Opcode.BPL,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1100u ->
      struct (
        Opcode.BPGU,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0100u ->
      struct (
        Opcode.BPLEU,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1101u ->
      struct (
        Opcode.BPCC,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0101u ->
      struct (
        Opcode.BPCS,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1110u ->
      struct (
        Opcode.BPPOS,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0110u ->
      struct (
        Opcode.BPNEG,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b1111u ->
      struct (
        Opcode.BPVC,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | 0b0111u ->
      struct (
        Opcode.BPVS,
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      )
    | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b011u ->
    match extract b32 27u 25u with
    | 0b001u ->
      struct (
        Opcode.BRZ,
        parseFourOpr
          b32
          getRegRs1
          getd16
          getAbit
          getPbit
      )
    | 0b010u ->
      struct (
        Opcode.BRLEZ,
        parseFourOpr
          b32
          getRegRs1
          getd16
          getAbit
          getPbit
      )
    | 0b011u ->
      struct (
        Opcode.BRLZ,
        parseFourOpr
          b32
          getRegRs1
          getd16
          getAbit
          getPbit
      )
    | 0b101u ->
      struct (
        Opcode.BRNZ,
        parseFourOpr
          b32
          getRegRs1
          getd16
          getAbit
          getPbit
      )
    | 0b110u ->
      struct (
        Opcode.BRGZ,
        parseFourOpr
          b32
          getRegRs1
          getd16
          getAbit
          getPbit
      )
    | 0b111u ->
      struct (
        Opcode.BRGEZ,
        parseFourOpr
          b32
          getRegRs1
          getd16
          getAbit
          getPbit
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
    match pickBit b32 13u with
    | 0b0u -> parse101000  b32
    | _ ->
      match pickBit b32 25u with
      | 0u ->
        match pickBit b32 13u with
        | 0b0u -> struct (Opcode.STBAR, NoOperand)
        | 0b1u -> struct (Opcode.MEMBAR, parseOneOpr b32 getMembarMask)
        | _ -> struct (Opcode.InvalidOp, NoOperand)
      | _ -> struct (Opcode.InvalidOp, NoOperand)
  | 0b110000u -> parse110000 b32
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
        parseThrOprOneReg b32 getRegRs1 getSimm13 (setPriReg ASI)
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
