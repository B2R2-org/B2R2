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
open B2R2.FrontEnd.BinLifter.ParsingUtils
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

let parseOneOpr b op1 = OneOperand(op1 b)

let parseTwoOpr b op1 op2 = TwoOperands(op1 b, op2 b)

let parseThrOpr b op1 op2 op3 = ThreeOperands(op1 b, op2 b, op3 b)

let parseFourOpr b op1 op2 op3 op4 = FourOperands(op1 b, op2 b, op3 b, op4 b)

let parseOneCC cc1 = OneOperand(cc1)

let parseOneCCOneOpr b cc1 op1 = TwoOperands(cc1, op1 b)

let parseOneCCTwoOpr b cc1 op1 op2 = ThreeOperands(cc1, op1 b, op2 b)

let parseOneCCThrOpr b cc1 op1 op2 op3 = FourOperands(cc1, op1 b, op2 b, op3 b)

let parseOneOprOneCC b op1 cc1 = TwoOperands(op1 b, cc1)

let parseOneRegOneOpr b reg op1 = TwoOperands(reg, op1 b)

let parseTwoOprOneReg b op1 op2 reg = ThreeOperands(op1 b, op2 b, reg)

let parseOneRegTwoOpr b reg op1 op2 = ThreeOperands(reg, op1 b, op2 b)

let parseThrOprOneReg b op1 op2 reg op3 = FourOperands(op1 b, op2 b, reg, op3 b)

let parseSTXA b op1 op2 op3 reg = FourOperands(op1 b, op2 b, op3 b, reg)

(* The shared extractor, aliased so that the hundred call sites below read as
   they did. This file used to carry its own copy, differing only in rejecting a
   bad offset range with a bare exception instead of naming the mistake. *)
let extract = Bits.extract

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

let getimm22 b = extract b 21u 0u <<< 10 |> int32 |> OprImm

let getSimm13 b = (extract b 12u 0u) <<< 19 |> int32 >>> 19 |> OprImm

let getSimm13Zero b =
  let checkSimm13 = (extract b 12u 0u) <<< 19 |> int32 >>> 19
  if checkSimm13 = 0 then getReg b 12u 0u |> OprReg else checkSimm13 |> OprImm

let getSimm11 b = (extract b 10u 0u) <<< 21 |> int32 >>> 21 |> OprImm

let getSimm10 b = (extract b 9u 0u) <<< 22 |> int32 >>> 22 |> OprImm

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

let getAddrSimm13 b = (extract b 12u 0u) <<< 19 |> int32 >>> 19 |> OprImm

let setPriReg r = r |> OprReg

let getThrCC (cc2: uint32) (cc1: uint32) (cc0: uint32) =
  match cc2, cc1, cc0 with
  | 0b0u, 0b0u, 0b0u -> ConditionCode.Fcc0 |> OprCC
  | 0b0u, 0b0u, 0b1u -> ConditionCode.Fcc1 |> OprCC
  | 0b0u, 0b1u, 0b0u -> ConditionCode.Fcc2 |> OprCC
  | 0b0u, 0b1u, 0b1u -> ConditionCode.Fcc3 |> OprCC
  | 0b1u, 0b0u, 0b0u -> ConditionCode.Icc |> OprCC
  | 0b1u, 0b1u, 0b0u -> ConditionCode.Xcc |> OprCC
  | _ -> raise ParsingFailureException

let getTwoCCix (cc1: uint32) (cc0: uint32) =
  match cc1, cc0 with
  | 0b0u, 0b0u -> ConditionCode.Icc |> OprCC
  | 0b1u, 0b0u -> ConditionCode.Xcc |> OprCC
  | _ -> raise ParsingFailureException

let getTwoCCFcc (cc1: uint32) (cc0: uint32) =
  match cc1, cc0 with
  | 0b0u, 0b0u -> ConditionCode.Fcc0 |> OprCC
  | 0b0u, 0b1u -> ConditionCode.Fcc1 |> OprCC
  | 0b1u, 0b0u -> ConditionCode.Fcc2 |> OprCC
  | 0b1u, 0b1u -> ConditionCode.Fcc3 |> OprCC
  | _ -> raise ParsingFailureException

let getSwTrapNum b = extract b 7u 0u |> int32 |> OprImm

/// Parses a Tcc (trap on condition) instruction's operands. Its cc field lives
/// at bits [12:11] (unlike the branch instructions' [21:20]); the trap target
/// is rs1 + rs2 for the register form (i=0) or rs1 + a software trap number for
/// the immediate form (i=1). We surface the cc and the trap target so the
/// lifter can recognize the Linux syscall gate (a TA to the well-known number).
let parseTcc b =
  let cc = getTwoCCix (get12cc1 b) (get11cc0 b)
  match pickBit b 13u with
  | 0b0u -> TwoOperands(cc, getAddrRs2 b)
  | _ -> TwoOperands(cc, getSwTrapNum b)

let getTwod16 (hi: uint32) (lo: uint32) =
  let d16 = (hi <<< 14 ||| lo) <<< 16 |> int32 >>> 16
  4 * d16 |> OprImm

let getd16 b =
  let hi = extract b 21u 20u
  let lo = extract b 13u 0u
  let d16 = (hi <<< 14 ||| lo) <<< 16 |> int32 >>> 16
  4 * d16 |> OprAddr

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
    let opr = parseThrOpr b32 getFloatRegRs1 getFloatRegRs2 getFloatRegRd
    struct (Opcode.FADDs, opr)
  | 0b001000010u ->
    let opr = parseThrOpr b32 getDPFloatRegRs1 getDPFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FADDd, opr)
  | 0b001000011u ->
    let opr = parseThrOpr b32 getQPFloatRegRs1 getQPFloatRegRs2 getQPFloatRegRd
    struct (Opcode.FADDq, opr)
  | 0b001000101u ->
    let opr = parseThrOpr b32 getFloatRegRs1 getFloatRegRs2 getFloatRegRd
    struct (Opcode.FSUBs, opr)
  | 0b001000110u ->
    let opr = parseThrOpr b32 getDPFloatRegRs1 getDPFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FSUBd, opr)
  | 0b001000111u ->
    let opr = parseThrOpr b32 getQPFloatRegRs1 getQPFloatRegRs2 getQPFloatRegRd
    struct (Opcode.FSUBq, opr)
  | 0b010000001u ->
    let opr = parseTwoOpr b32 getFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FsTOx, opr)
  | 0b010000010u ->
    let opr = parseTwoOpr b32 getDPFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FdTOx, opr)
  | 0b010000011u ->
    let opr = parseTwoOpr b32 getQPFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FqTOx, opr)
  | 0b011010001u ->
    let opr = parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    struct (Opcode.FsTOi, opr)
  | 0b011010010u ->
    let opr = parseTwoOpr b32 getDPFloatRegRs2 getFloatRegRd
    struct (Opcode.FdTOi, opr)
  | 0b011010011u ->
    let opr = parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    struct (Opcode.FqTOi, opr)
  | 0b011001001u ->
    let opr = parseTwoOpr b32 getFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FsTOd, opr)
  | 0b011001101u ->
    let opr = parseTwoOpr b32 getFloatRegRs2 getQPFloatRegRd
    struct (Opcode.FsTOq, opr)
  | 0b011000110u ->
    let opr = parseTwoOpr b32 getDPFloatRegRs2 getFloatRegRd
    struct (Opcode.FdTOs, opr)
  | 0b011001110u ->
    let opr = parseTwoOpr b32 getDPFloatRegRs2 getQPFloatRegRd
    struct (Opcode.FdTOq, opr)
  | 0b011000111u ->
    let opr = parseTwoOpr b32 getQPFloatRegRs2 getFloatRegRd
    struct (Opcode.FqTOs, opr)
  | 0b011001011u ->
    let opr = parseTwoOpr b32 getQPFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FqTOd, opr)
  | 0b010000100u ->
    let opr = parseTwoOpr b32 getDPFloatRegRs2 getFloatRegRd
    struct (Opcode.FxTOs, opr)
  | 0b010001000u ->
    let opr = parseTwoOpr b32 getDPFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FxTOd, opr)
  | 0b010001100u ->
    let opr = parseTwoOpr b32 getDPFloatRegRs2 getQPFloatRegRd
    struct (Opcode.FxTOq, opr)
  | 0b011000100u ->
    let opr = parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    struct (Opcode.FiTOs, opr)
  | 0b011001000u ->
    let opr = parseTwoOpr b32 getFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FiTOd, opr)
  | 0b011001100u ->
    let opr = parseTwoOpr b32 getFloatRegRs2 getQPFloatRegRd
    struct (Opcode.FiTOq, opr)
  | 0b000000001u ->
    let opr = parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    struct (Opcode.FMOVs, opr)
  | 0b000000010u ->
    let opr = parseTwoOpr b32 getDPFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FMOVd, opr)
  | 0b000000011u ->
    let opr = parseTwoOpr b32 getQPFloatRegRs2 getQPFloatRegRd
    struct (Opcode.FMOVq, opr)
  | 0b000000101u ->
    let opr = parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    struct (Opcode.FNEGs, opr)
  | 0b000000110u ->
    let opr = parseTwoOpr b32 getDPFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FNEGd, opr)
  | 0b000000111u ->
    let opr = parseTwoOpr b32 getQPFloatRegRs2 getQPFloatRegRd
    struct (Opcode.FNEGq, opr)
  | 0b000001001u ->
    let opr = parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    struct (Opcode.FABSs, opr)
  | 0b000001010u ->
    let opr = parseTwoOpr b32 getDPFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FABSd, opr)
  | 0b000001011u ->
    let opr = parseTwoOpr b32 getQPFloatRegRs2 getQPFloatRegRd
    struct (Opcode.FABSq, opr)
  | 0b001001001u ->
    let opr = parseThrOpr b32 getFloatRegRs1 getFloatRegRs2 getFloatRegRd
    struct (Opcode.FMULs, opr)
  | 0b001001010u ->
    let opr = parseThrOpr b32 getDPFloatRegRs1 getDPFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FMULd, opr)
  | 0b001001011u ->
    let opr = parseThrOpr b32 getQPFloatRegRs1 getQPFloatRegRs2 getQPFloatRegRd
    struct (Opcode.FMULq, opr)
  | 0b001101001u ->
    let opr = parseThrOpr b32 getFloatRegRs1 getFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FsMULd, opr)
  | 0b001101110u ->
    let opr = parseThrOpr b32 getDPFloatRegRs1 getDPFloatRegRs2 getQPFloatRegRd
    struct (Opcode.FdMULq, opr)
  | 0b001001101u ->
    let opr = parseThrOpr b32 getFloatRegRs1 getFloatRegRs2 getFloatRegRd
    struct (Opcode.FDIVs, opr)
  | 0b001001110u ->
    let opr = parseThrOpr b32 getDPFloatRegRs1 getDPFloatRegRs2 getDPFloatRegRd
    struct (Opcode.FDIVd, opr)
  | 0b001001111u ->
    let opr = parseThrOpr b32 getQPFloatRegRs1 getQPFloatRegRs2 getQPFloatRegRd
    struct (Opcode.FDIVq, opr)
  | 0b000101001u ->
    let opr = parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    struct (Opcode.FSQRTs, opr)
  | 0b000101010u ->
    let opr = parseTwoOpr b32 getFloatRegRs2 getFloatRegRd
    struct (Opcode.FSQRTd, opr)
  | 0b000101011u ->
    let opr = parseTwoOpr b32 getQPFloatRegRs2 getQPFloatRegRd
    struct (Opcode.FSQRTq, opr)
  | _ ->
    raise ParsingFailureException

let parse110101fmovr b32 =
  match extract b32 12u 10u with
  | 0b001u ->
    match extract b32 9u 5u with
    | 0b00101u ->
      let opr = parseThrOpr b32 getRegRs1 getFloatRegRs2 getFloatRegRd
      struct (Opcode.FMOVRsZ, opr)
    | 0b00110u ->
      let opr = parseThrOpr b32 getRegRs1 getDPFloatRegRs2 getDPFloatRegRd
      struct (Opcode.FMOVRdZ, opr)
    | 0b00111u ->
      let opr = parseThrOpr b32 getRegRs1 getQPFloatRegRs2 getQPFloatRegRd
      struct (Opcode.FMOVRqZ, opr)
    | _ ->
      raise ParsingFailureException
  | 0b010u ->
    match extract b32 9u 5u with
    | 0b00101u ->
      let opr = parseThrOpr b32 getRegRs1 getFloatRegRs2 getFloatRegRd
      struct (Opcode.FMOVRsLEZ, opr)
    | 0b00110u ->
      let parseThrOpr =
        parseThrOpr b32 getRegRs1 getDPFloatRegRs2 getDPFloatRegRd
      struct (Opcode.FMOVRdLEZ, parseThrOpr)
    | 0b00111u ->
      let opr = parseThrOpr b32 getRegRs1 getQPFloatRegRs2 getQPFloatRegRd
      struct (Opcode.FMOVRqLEZ, opr)
    | _ ->
      raise ParsingFailureException
  | 0b011u ->
    match extract b32 9u 5u with
    | 0b00101u ->
      let opr = parseThrOpr b32 getRegRs1 getFloatRegRs2 getFloatRegRd
      struct (Opcode.FMOVRsLZ, opr)
    | 0b00110u ->
      let opr = parseThrOpr b32 getRegRs1 getDPFloatRegRs2 getDPFloatRegRd
      struct (Opcode.FMOVRdLZ, opr)
    | 0b00111u ->
      let opr = parseThrOpr b32 getRegRs1 getQPFloatRegRs2 getQPFloatRegRd
      struct (Opcode.FMOVRqLZ, opr)
    | _ ->
      raise ParsingFailureException
  | 0b101u ->
    match extract b32 9u 5u with
    | 0b00101u ->
      let opr = parseThrOpr b32 getRegRs1 getFloatRegRs2 getFloatRegRd
      struct (Opcode.FMOVRsNZ, opr)
    | 0b00110u ->
      let opr = parseThrOpr b32 getRegRs1 getDPFloatRegRs2 getDPFloatRegRd
      struct (Opcode.FMOVRdNZ, opr)
    | 0b00111u ->
      let opr = parseThrOpr b32 getRegRs1 getQPFloatRegRs2 getQPFloatRegRd
      struct (Opcode.FMOVRqNZ, opr)
    | _ ->
      raise ParsingFailureException
  | 0b110u ->
    match extract b32 9u 5u with
    | 0b00101u ->
      let opr = parseThrOpr b32 getRegRs1 getFloatRegRs2 getFloatRegRd
      struct (Opcode.FMOVRsGZ, opr)
    | 0b00110u ->
      let opr = parseThrOpr b32 getRegRs1 getDPFloatRegRs2 getDPFloatRegRd
      struct (Opcode.FMOVRdGZ, opr)
    | 0b00111u ->
      let opr = parseThrOpr b32 getRegRs1 getQPFloatRegRs2 getQPFloatRegRd
      struct (Opcode.FMOVRqGZ, opr)
    | _ ->
      raise ParsingFailureException
  | 0b111u ->
    match extract b32 9u 5u with
    | 0b00101u ->
      let opr = parseThrOpr b32 getRegRs1 getFloatRegRs2 getFloatRegRd
      struct (Opcode.FMOVRsGEZ, opr)
    | 0b00110u ->
      let opr = parseThrOpr b32 getRegRs1 getDPFloatRegRs2 getDPFloatRegRd
      struct (Opcode.FMOVRdGEZ, opr)
    | 0b00111u ->
      let opr = parseThrOpr b32 getRegRs1 getQPFloatRegRs2 getQPFloatRegRd
      struct (Opcode.FMOVRqGEZ, opr)
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

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
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsA, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdA, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqA, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0000u ->
      // struct (Opcode.FMOVN, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsN, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdN, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqN, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1001u ->
      // struct (Opcode.FMOVNE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsNE, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdNE, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqNE, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0001u ->
      // struct (Opcode.FMOVE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsE, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdE, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqE, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1010u ->
      // struct (Opcode.FMOVG, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsG, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdG, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqG, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0010u ->
      // struct (Opcode.FMOVLE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsLE, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdLE, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqLE, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1011u ->
      // struct (Opcode.FMOVGE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsGE, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdGE, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqGE, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0011u ->
      // struct (Opcode.FMOVL, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsL, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdL, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqL, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1100u ->
      // struct (Opcode.FMOVGU, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsGU, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdGU, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqGU, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0100u ->
      // struct (Opcode.FMOVLEU, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsLEU, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdLEU, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqLEU, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1101u ->
      // struct (Opcode.FMOVCC, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsCC, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdCC, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqCC, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0101u ->
      // struct (Opcode.FMOVCS, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsCS, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdCS, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqCS, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1110u ->
      // struct (Opcode.FMOVPOS, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsPOS, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdPOS, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqPOS, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0110u ->
      // struct (Opcode.FMOVNEG, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsNEG, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdNEG, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqNEG, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1111u ->
      // struct (Opcode.FMOVVC, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsVC, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdVC, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqVC, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0111u ->
      // struct (Opcode.FMOVVS, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVsVS, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVdVS, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVqVS, opr)
      | _ ->
        parse110101fmovr b32
    | _ ->
      parse110101fmovr b32
  | 0b000u | 0b001u | 0b010u | 0b011u ->
    match extract b32 17u 14u with
    | 0b1000u ->
      // struct (Opcode.FMOVA, parseThrOpr b32 getOpFCC getFloatRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsA, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdA, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqA, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0000u ->
      // struct (Opcode.FMOVN, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsN, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdN, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqN, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0111u ->
      // struct (Opcode.FMOVNE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsU, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdU, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqU, opr)
      | _ ->
        parse110101fmovr b32
    | 0b110u ->
      // struct (Opcode.FMOVE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsG, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdG, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqG, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0101u ->
      // struct (Opcode.FMOVG, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsUG, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdUG, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqUG, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0100u ->
      // struct (Opcode.FMOVLE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsL, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdL, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqL, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0011u ->
      // struct (Opcode.FMOVGE, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsUL, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdUL, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqUL, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0010u ->
      // struct (Opcode.FMOVL, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsLG, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdLG, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqLG, opr)
      | _ ->
        parse110101fmovr b32
    | 0b0001u ->
      // struct (Opcode.FMOVGU, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsNE, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdNE, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqNE, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1001u ->
      // struct (Opcode.FMOVLEU, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsE, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdE, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqE, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1010u ->
      // struct (Opcode.FMOVCC, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsUE, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdUE, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqUE, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1011u ->
      // struct (Opcode.FMOVCS, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsGE, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdGE, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqGE, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1100u ->
      // struct (Opcode.FMOVPOS, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsUGE, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdUGE, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqUGE, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1101u ->
      // struct (Opcode.FMOVNEG, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsLE, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdLE, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqLE, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1110u ->
      // struct (Opcode.FMOVVC, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsULE, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdULE, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqULE, opr)
      | _ ->
        parse110101fmovr b32
    | 0b1111u ->
      // struct (Opcode.FMOVVS, parseThrOpr b32 getOpFCC getRegRs2 getRegRd)
      match extract b32 10u 5u with
      | 0b000001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getFloatRegRs2
            getFloatRegRd
        struct (Opcode.FMOVFsO, opr)
      | 0b000010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getDPFloatRegRs2
            getDPFloatRegRd
        struct (Opcode.FMOVFdO, opr)
      | 0b000011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get13cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getQPFloatRegRs2
            getQPFloatRegRd
        struct (Opcode.FMOVFqO, opr)
      | _ ->
        parse110101fmovr b32
    | _ ->
      raise ParsingFailureException
  | _ ->
    parse110101fmovr b32

(*
  10r_ __d1 0100 0---
  ---- ---- ---- ----
*)
let parse101000 b32 =
  match extract b32 18u 14u with
  | 0u ->
    struct (Opcode.RDY, parseOneRegOneOpr b32 (setPriReg Y) getRegRd)
  | 2u ->
    struct (Opcode.RDCCR, parseOneRegOneOpr b32 (setPriReg CCR) getRegRd)
  | 3u ->
    struct (Opcode.RDASI, parseOneRegOneOpr b32 (setPriReg ASI) getRegRd)
  | 4u ->
    struct (Opcode.RDTICK, parseOneRegOneOpr b32 (setPriReg TICK) getRegRd)
  | 5u ->
    struct (Opcode.RDPC, parseOneRegOneOpr b32 (setPriReg PC) getRegRd)
  | 6u ->
    struct (Opcode.RDFPRS, parseOneRegOneOpr b32 (setPriReg FPRS) getRegRd)
  | 7u
  | 8u
  | 9u
  | 10u
  | 12u
  | 13u
  | 14u ->
    struct (Opcode.RDASR, parseTwoOpr b32 getRegRs1 getRegRd)
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
  | 31u ->
    struct (Opcode.RDASR, parseTwoOpr b32 getRegRs1 getRegRd)
  | _ ->
    raise ParsingFailureException

(*
  10r_ __d1 1000 0---
  ---- ---- ---- ----
*)
let parse110000 b32 =
  match pickBit b32 13u with
  | 0b0u ->
    match extract b32 29u 25u with
    | 0u ->
      let parseTwoOprOneReg =
        parseTwoOprOneReg b32 getRegRs1 getRegRs2 (setPriReg Y)
      struct (Opcode.WRY, parseTwoOprOneReg)
    | 2u ->
      let parseTwoOprOneReg =
        parseTwoOprOneReg b32 getRegRs1 getRegRs2 (setPriReg CCR)
      struct (Opcode.WRCCR, parseTwoOprOneReg)
    | 3u ->
      let parseTwoOprOneReg =
        parseTwoOprOneReg b32 getRegRs1 getRegRs2 (setPriReg ASI)
      struct (Opcode.WRASI, parseTwoOprOneReg)
    | 4u
    | 5u
    | 7u
    | 8u
    | 9u
    | 10u
    | 12u
    | 13u
    | 14u ->
      struct (Opcode.WRASR, parseTwoOpr b32 getRegRs1 getRegRs2)
    | 6u ->
      let parseTwoOprOneReg =
        parseTwoOprOneReg b32 getRegRs1 getRegRs2 (setPriReg FPRS)
      struct (Opcode.WRFPRS, parseTwoOprOneReg)
    | 15u ->
      struct (Opcode.SIR, NoOperand)
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
      struct (Opcode.WRASR, parseTwoOpr b32 getRegRs1 getRegRs2)
    | _ ->
      raise ParsingFailureException
  | 0b1u ->
    match extract b32 29u 25u with
    | 0u ->
      let parseTwoOprOneReg =
        parseTwoOprOneReg b32 getRegRs1 getSimm13 (setPriReg Y)
      struct (Opcode.WRY, parseTwoOprOneReg)
    | 2u ->
      let parseTwoOprOneReg =
        parseTwoOprOneReg b32 getRegRs1 getSimm13 (setPriReg CCR)
      struct (Opcode.WRCCR, parseTwoOprOneReg)
    | 3u ->
      let parseTwoOprOneReg =
        parseTwoOprOneReg b32 getRegRs1 getSimm13 (setPriReg ASI)
      struct (Opcode.WRASI, parseTwoOprOneReg)
    | 4u
    | 5u
    | 7u
    | 8u
    | 9u
    | 10u
    | 12u
    | 13u
    | 14u ->
      struct (Opcode.WRASR, parseTwoOpr b32 getRegRs1 getSimm13)
    | 6u ->
      let opr = parseTwoOprOneReg b32 getRegRs1 getSimm13 (setPriReg FPRS)
      struct (Opcode.WRFPRS, opr)
    | 15u ->
      struct (Opcode.SIR, parseOneOpr b32 getSimm13)
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
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

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
        let parseOneCCTwoOpr =
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFA, parseOneCCTwoOpr)
      | 0b0000u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFN, opr)
      | 0b0111u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFU, opr)
      | 0b0110u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFG, opr)
      | 0b0101u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFUG, opr)
      | 0b0100u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFL, opr)
      | 0b0011u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFUL, opr)
      | 0b0010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFLG, opr)
      | 0b0001u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFNE, opr)
      | 0b1001u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFE, opr)
      | 0b1010u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFUE, opr)
      | 0b1011u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFGE, opr)
      | 0b1100u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFUGE, opr)
      | 0b1101u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFLE, opr)
      | 0b1110u ->
        let parseOneCCTwoOpr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFULE, parseOneCCTwoOpr)
      | 0b1111u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVFO, opr)
      | _ ->
        raise ParsingFailureException
    | 0b1u ->
      match extract b32 17u 14u with
      | 0b1000u ->
        let parseOneCCTwoOpr =
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFA, parseOneCCTwoOpr)
      | 0b0000u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFN, opr)
      | 0b0111u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFU, opr)
      | 0b0110u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFG, opr)
      | 0b0101u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFUG, opr)
      | 0b0100u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFL, opr)
      | 0b0011u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFUL, opr)
      | 0b0010u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFLG, opr)
      | 0b0001u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFNE, opr)
      | 0b1001u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFE, opr)
      | 0b1010u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFUE, opr)
      | 0b1011u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFGE, opr)
      | 0b1100u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFUGE, opr)
      | 0b1101u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFLE, opr)
      | 0b1110u ->
        let parseOneCCTwoOpr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFULE, parseOneCCTwoOpr)
      | 0b1111u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVFO, opr)
      | _ ->
        raise ParsingFailureException
    | _ ->
      raise ParsingFailureException
  | 0b1u, 0b0u, 0b0u
  | 0b1u, 0b1u, 0b0u ->
    match pickBit b32 13u with
    | 0b0u ->
      match extract b32 17u 14u with
      | 0b1000u ->
        let parseOneCCTwoOpr =
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVA, parseOneCCTwoOpr)
      | 0b0000u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVN, opr)
      | 0b1001u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVNE, opr)
      | 0b0001u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVE, opr)
      | 0b1010u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVG, opr)
      | 0b0010u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVLE, opr)
      | 0b1011u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVGE, opr)
      | 0b0011u ->
        let opr =
          parseOneCCTwoOpr b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVL, opr)
      | 0b1100u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVGU, opr)
      | 0b0100u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVLEU, opr)
      | 0b1101u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVCC, opr)
      | 0b0101u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVCS, opr)
      | 0b1110u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVPOS, opr)
      | 0b0110u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVNEG, opr)
      | 0b1111u ->
        let parseOneCCTwoOpr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVVC, parseOneCCTwoOpr)
      | 0b0111u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getRegRs2
            getRegRd
        struct (Opcode.MOVVS, opr)
      | _ ->
        raise ParsingFailureException
    | 0b1u ->
      match extract b32 17u 14u with
      | 0b1000u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVA, opr)
      | 0b0000u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVN, opr)
      | 0b1001u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVNE, opr)
      | 0b0001u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVE, opr)
      | 0b1010u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVG, opr)
      | 0b0010u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVLE, opr)
      | 0b1011u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVGE, opr)
      | 0b0011u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVL, opr)
      | 0b1100u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVGU, opr)
      | 0b0100u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVLEU, opr)
      | 0b1101u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVCC, opr)
      | 0b0101u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVCS, opr)
      | 0b1110u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVPOS, opr)
      | 0b0110u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVNEG, opr)
      | 0b1111u ->
        let opr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVVC, opr)
      | 0b0111u ->
        let parseOneCCTwoOpr =
          parseOneCCTwoOpr
            b32
            (getThrCC (get18cc2 b32) (get12cc1 b32) (get11cc0 b32))
            getSimm11
            getRegRd
        struct (Opcode.MOVVS, parseOneCCTwoOpr)
      | _ ->
        raise ParsingFailureException
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

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
    | _ ->
      raise ParsingFailureException
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
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

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
    | 0b101110u ->
      struct (Opcode.POPC, parseTwoOpr b32 getRegRs2 getRegRd)
    (* SAVE and RESTORE *)
    | 0b111100u ->
      struct (Opcode.SAVE, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b111101u ->
      struct (Opcode.RESTORE, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    (* Shift *)
    | 0b100101u ->
      match pickBit b32 12u with
      | 0b0u ->
        struct (Opcode.SLL, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
      | _ ->
        struct (Opcode.SLLX, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b100110u ->
      match pickBit b32 12u with
      | 0b0u ->
        struct (Opcode.SRL, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
      | _ ->
        struct (Opcode.SRLX, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
    | 0b100111u ->
      match pickBit b32 12u with
      | 0b0u ->
        struct (Opcode.SRA, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
      | _ ->
        struct (Opcode.SRAX, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
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
    | 0b110101u ->
      parse110101 b32
    (* Floating-Point *)
    | 0b110100u ->
      parseFP b32
    (* Read State Register *)
    | 0b101000u ->
      parse101000 b32
    (* Read Privileged State Register *)
    | 0b101010u ->
      struct (Opcode.RDPR, parseTwoOpr b32 priregRDPR getRegRd)
    (* Write State Register *)
    | 0b110000u ->
      parse110000 b32
    (* Move Integer Register on Condition *)
    | 0b101100u ->
      parse101100 b32
    (* Move Integer Register on Register Condition *)
    | 0b101111u ->
      parse101111 b32
    | _ ->
      raise ParsingFailureException
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
    | 0b101110u ->
      struct (Opcode.POPC, parseTwoOpr b32 getSimm13 getRegRd)
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
      | _ ->
        raise ParsingFailureException
    | 0b100110u ->
      match pickBit b32 12u with
      | 0b0u ->
        struct (Opcode.SRL, parseThrOpr b32 getRegRs1 getshcnt32 getRegRd)
      | 0b1u ->
        struct (Opcode.SRLX, parseThrOpr b32 getRegRs1 getshcnt64 getRegRd)
      | _ ->
        raise ParsingFailureException
    | 0b100111u ->
      match pickBit b32 12u with
      | 0b0u ->
        struct (Opcode.SRA, parseThrOpr b32 getRegRs1 getshcnt32 getRegRd)
      | 0b1u ->
        struct (Opcode.SRAX, parseThrOpr b32 getRegRs1 getshcnt64 getRegRd)
      | _ ->
        raise ParsingFailureException
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
    | 0b101010u ->
      struct (Opcode.RDPR, parseTwoOpr b32 priregRDPR getRegRd)
    (* Write State Register *)
    | 0b110000u ->
      parse110000 b32
    (* Move Integer Register on Condition *)
    | 0b101100u ->
      parse101100 b32
    (* Move Integer Register on Register Condition *)
    | 0b101111u ->
      parse101111 b32
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

(*
  11r_ __d- ---- ----
  ---- ---- ---- ----
*)
let parse11rd b32 =
  match pickBit b32 13u with
  | 0b0u ->
    match extract b32 24u 19u with
    | 0b011111u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      struct (Opcode.SWAPA, opr)
    | 0b001111u ->
      let opr = parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd
      struct (Opcode.SWAP, opr)
    | 0b010101u ->
      let opr = parseFourOpr b32 getRegRd getAddrRs1 getAddrRs2 getImmAsi
      struct (Opcode.STBA, opr)
    | 0b010110u ->
      let opr = parseFourOpr b32 getRegRd getAddrRs1 getAddrRs2 getImmAsi
      struct (Opcode.STHA, opr)
    | 0b010100u ->
      let opr = parseFourOpr b32 getRegRd getAddrRs1 getAddrRs2 getImmAsi
      struct (Opcode.STWA, opr)
    | 0b011110u ->
      let opr = parseFourOpr b32 getRegRd getAddrRs1 getAddrRs2 getImmAsi
      struct (Opcode.STXA, opr)
    | 0b010111u ->
      let opr = parseFourOpr b32 getRegRd getAddrRs1 getAddrRs2 getImmAsi
      struct (Opcode.STDA, opr)
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
      let opr = parseFourOpr b32 getFloatRegRd getAddrRs1 getAddrRs2 getImmAsi
      struct (Opcode.STFA, opr)
    | 0b110111u ->
      let opr = parseFourOpr b32 getDPFloatRegRd getAddrRs1 getAddrRs2 getImmAsi
      struct (Opcode.STDFA, opr)
    | 0b110110u ->
      let opr = parseFourOpr b32 getQPFloatRegRd getAddrRs1 getAddrRs2 getImmAsi
      struct (Opcode.STQFA, opr)
    | 0b100100u ->
      let opr = parseThrOpr b32 getFloatRegRd getAddrRs1 getAddrRs2
      struct (Opcode.STF, opr)
    | 0b100111u ->
      let opr = parseThrOpr b32 getDPFloatRegRd getAddrRs1 getAddrRs2
      struct (Opcode.STDF, opr)
    | 0b100110u ->
      let opr = parseThrOpr b32 getQPFloatRegRd getAddrRs1 getAddrRs2
      struct (Opcode.STQF, opr)
    | 0b100101u ->
      match extract b32 29u 25u with
      | 0b00000u ->
        let opr = parseOneRegTwoOpr b32 (setPriReg FSR) getAddrRs1 getAddrRs2
        struct (Opcode.STFSR, opr)
      | 0b00001u ->
        let opr = parseOneRegTwoOpr b32 (setPriReg FSR) getAddrRs1 getAddrRs2
        struct (Opcode.STXFSR, opr)
      | _ ->
        raise ParsingFailureException
    | 0b111100u ->
      let opr = parseFourOpr b32 getRegRs1 getImmAsi getRegRs2 getRegRd
      struct (Opcode.CASA, opr)
    | 0b111110u ->
      let opr = parseFourOpr b32 getRegRs1 getImmAsi getRegRs2 getRegRd
      struct (Opcode.CASXA, opr)
    | 0b100000u ->
      let opr = parseThrOpr b32 getAddrRs1 getAddrRs2 getFloatRegRd
      struct (Opcode.LDF, opr)
    | 0b100011u ->
      let opr = parseThrOpr b32 getAddrRs1 getAddrRs2 getDPFloatRegRd
      struct (Opcode.LDDF, opr)
    | 0b100010u ->
      let opr = parseThrOpr b32 getAddrRs1 getAddrRs2 getQPFloatRegRd
      struct (Opcode.LDQF, opr)
    | 0b100001u ->
      match extract b32 29u 25u with
      | 0b00000u ->
        let opr = parseTwoOprOneReg b32 getAddrRs1 getAddrRs2 (setPriReg FSR)
        struct (Opcode.LDFSR, opr)
      | 0b00001u ->
        let opr = parseTwoOprOneReg b32 getAddrRs1 getAddrRs2 (setPriReg FSR)
        struct (Opcode.LDXFSR, opr)
      | _ ->
        raise ParsingFailureException
    | 0b110000u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getFloatRegRd
      struct (Opcode.LDFA, opr)
    | 0b110011u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getDPFloatRegRd
      struct (Opcode.LDDFA, opr)
    | 0b110010u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getQPFloatRegRd
      struct (Opcode.LDQFA, opr)
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
      let opr = parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      struct (Opcode.LDSBA, opr)
    | 0b011010u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      struct (Opcode.LDSHA, opr)
    | 0b011000u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      struct (Opcode.LDSWA, opr)
    | 0b010001u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      struct (Opcode.LDUBA, opr)
    | 0b010010u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      struct (Opcode.LDUHA, opr)
    | 0b010000u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      struct (Opcode.LDUWA, opr)
    | 0b011011u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      struct (Opcode.LDXA, opr)
    | 0b010011u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      struct (Opcode.LDDA, opr)
    | 0b001101u ->
      struct (Opcode.LDSTUB, parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd)
    | 0b011101u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrRs2 getImmAsi getRegRd
      struct (Opcode.LDSTUBA, opr)
    | _ ->
      raise ParsingFailureException
  | 0b1u ->
    match extract b32 24u 19u with
    | 0b011111u ->
      let opr = parseFourOpr b32 getRegRs1 getSimm13 getRegAsi getRegRd
      struct (Opcode.SWAPA, opr)
    | 0b001111u ->
      let opr = parseThrOpr b32 getAddrRs1 getAddrRs2 getRegRd
      struct (Opcode.SWAP, opr)
    | 0b010101u ->
      let opr = parseFourOpr b32 getRegRd getAddrRs1 getAddrSimm13 getRegAsi
      struct (Opcode.STBA, opr)
    | 0b010110u ->
      let opr = parseFourOpr b32 getRegRd getAddrRs1 getAddrSimm13 getRegAsi
      struct (Opcode.STHA, opr)
    | 0b010100u ->
      let opr = parseFourOpr b32 getRegRd getAddrRs1 getAddrSimm13 getRegAsi
      struct (Opcode.STWA, opr)
    | 0b011110u ->
      let opr = parseFourOpr b32 getRegRd getAddrRs1 getAddrSimm13 getRegAsi
      struct (Opcode.STXA, opr)
    | 0b010111u ->
      let opr = parseFourOpr b32 getRegRd getAddrRs1 getAddrSimm13 getRegAsi
      struct (Opcode.STDA, opr)
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
      let opr =
        parseSTXA b32 getFloatRegRd getAddrRs1 getAddrSimm13 (setPriReg ASI)
      struct (Opcode.STFA, opr)
    | 0b110111u ->
      let opr =
        parseSTXA b32 getDPFloatRegRd getAddrRs1 getAddrSimm13 (setPriReg ASI)
      struct (Opcode.STDFA, opr)
    | 0b110110u ->
      let opr =
        parseSTXA b32 getQPFloatRegRd getAddrRs1 getAddrSimm13 (setPriReg ASI)
      struct (Opcode.STQFA, opr)
    | 0b100100u ->
      let opr = parseThrOpr b32 getFloatRegRd getAddrRs1 getAddrSimm13
      struct (Opcode.STF, opr)
    | 0b100111u ->
      let opr = parseThrOpr b32 getDPFloatRegRd getAddrRs1 getAddrSimm13
      struct (Opcode.STDF, opr)
    | 0b100110u ->
      let opr = parseThrOpr b32 getQPFloatRegRd getAddrRs1 getAddrSimm13
      struct (Opcode.STQF, opr)
    | 0b100101u ->
      match extract b32 29u 25u with
      | 0b00000u ->
        let opr = parseOneRegTwoOpr b32 (setPriReg FSR) getAddrRs1 getAddrSimm13
        struct (Opcode.STFSR, opr)
      | 0b00001u ->
        let opr = parseOneRegTwoOpr b32 (setPriReg FSR) getAddrRs1 getAddrSimm13
        struct (Opcode.STXFSR, opr)
      | _ ->
        raise ParsingFailureException
    | 0b111100u ->
      let opr = parseFourOpr b32 getRegRs1 getRegAsi getRegRs2 getRegRd
      struct (Opcode.CASA, opr)
    | 0b111110u ->
      let opr = parseFourOpr b32 getRegRs1 getRegAsi getRegRs2 getRegRd
      struct (Opcode.CASXA, opr)
    | 0b100000u ->
      let opr = parseThrOpr b32 getAddrRs1 getAddrSimm13 getFloatRegRd
      struct (Opcode.LDF, opr)
    | 0b100011u ->
      let opr = parseThrOpr b32 getAddrRs1 getAddrSimm13 getDPFloatRegRd
      struct (Opcode.LDDF, opr)
    | 0b100010u ->
      let opr = parseThrOpr b32 getAddrRs1 getAddrSimm13 getQPFloatRegRd
      struct (Opcode.LDQF, opr)
    | 0b100001u ->
      match extract b32 29u 25u with
      | 0b00000u ->
        let opr = parseTwoOprOneReg b32 getAddrRs1 getAddrSimm13 (setPriReg FSR)
        struct (Opcode.LDFSR, opr)
      | 0b00001u ->
        let opr = parseTwoOprOneReg b32 getAddrRs1 getAddrSimm13 (setPriReg FSR)
        struct (Opcode.LDXFSR, opr)
      | _ ->
        raise ParsingFailureException
    | 0b110000u ->
      let opr =
        parseFourOpr b32 getAddrRs1 getAddrSimm13 getRegAsi getFloatRegRd
      struct (Opcode.LDFA, opr)
    | 0b110011u ->
      let parseFourOpr =
        parseFourOpr b32 getAddrRs1 getAddrSimm13 getRegAsi getDPFloatRegRd
      struct (Opcode.LDDFA, parseFourOpr)
    | 0b110010u ->
      let opr =
        parseThrOprOneReg b32
                          getAddrRs1
                          getAddrSimm13
                          (setPriReg ASI)
                          getQPFloatRegRd
      struct (Opcode.LDQFA, opr)
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
      let opr = parseFourOpr b32 getAddrRs1 getAddrSimm13 getRegAsi getRegRd
      struct (Opcode.LDSBA, opr)
    | 0b011010u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrSimm13 getRegAsi getRegRd
      struct (Opcode.LDSHA, opr)
    | 0b011000u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrSimm13 getRegAsi getRegRd
      struct (Opcode.LDSWA, opr)
    | 0b010001u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrSimm13 getRegAsi getRegRd
      struct (Opcode.LDUBA, opr)
    | 0b010010u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrSimm13 getRegAsi getRegRd
      struct (Opcode.LDUHA, opr)
    | 0b010000u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrSimm13 getRegAsi getRegRd
      struct (Opcode.LDUWA, opr)
    | 0b011011u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrSimm13 getRegAsi getRegRd
      struct (Opcode.LDXA, opr)
    | 0b010011u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrSimm13 getRegAsi getRegRd
      struct (Opcode.LDDA, opr)
    | 0b001101u ->
      struct (Opcode.LDSTUB, parseThrOpr b32 getAddrRs1 getAddrSimm13 getRegRd)
    | 0b011101u ->
      let opr = parseFourOpr b32 getAddrRs1 getAddrSimm13 getRegAsi getRegRd
      struct (Opcode.LDSTUBA, opr)
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

(*
  00-- ---- ---- ----
  ---- ---- ---- ----
*)
let parse00 b32 =
  match extract b32 24u 22u with
  | 0b000u ->
    struct (Opcode.ILLTRAP, parseOneOpr b32 getConst22)
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
    | _ -> raise ParsingFailureException
  | 0b101u ->
    match extract b32 28u 25u with
    | 0b1000u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPA, opr)
    | 0b0000u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPN, opr)
    | 0b0111u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPU, opr)
    | 0b0110u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPG, opr)
    | 0b0101u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPUG, opr)
    | 0b0100u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPL, opr)
    | 0b0011u ->
      let parseOneCCThrOpr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPUL, parseOneCCThrOpr)
    | 0b0010u ->
      let parseOneCCThrOpr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPLG, parseOneCCThrOpr)
    | 0b0001u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPNE, opr)
    | 0b1001u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPE, opr)
    | 0b1010u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPUE, opr)
    | 0b1011u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPGE, opr)
    | 0b1100u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPUGE, opr)
    | 0b1101u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPLE, opr)
    | 0b1110u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPULE, opr)
    | 0b1111u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCFcc (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.FBPO, opr)
    | _ ->
      raise ParsingFailureException
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
    | _ -> raise ParsingFailureException
  | 0b001u ->
    match extract b32 28u 25u with
    | 0b1000u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPA, opr)
    | 0b0000u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPN, opr)
    | 0b1001u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPNE, opr)
    | 0b0001u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPE, opr)
    | 0b1010u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPG, opr)
    | 0b0010u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPLE, opr)
    | 0b1011u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPGE, opr)
    | 0b0011u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPL, opr)
    | 0b1100u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPGU, opr)
    | 0b0100u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPLEU, opr)
    | 0b1101u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPCC, opr)
    | 0b0101u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPCS, opr)
    | 0b1110u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPPOS, opr)
    | 0b0110u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPNEG, opr)
    | 0b1111u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPVC, opr)
    | 0b0111u ->
      let opr =
        parseOneCCThrOpr
          b32
          (getTwoCCix (get21cc1 b32) (get20cc0 b32))
          getdisp19
          getAbit
          getPbit
      struct (Opcode.BPVS, opr)
    | _ ->
      raise ParsingFailureException
  | 0b011u ->
    match extract b32 27u 25u with
    | 0b001u ->
      let opr = parseFourOpr b32 getRegRs1 getd16 getAbit getPbit
      struct (Opcode.BRZ, opr)
    | 0b010u ->
      let opr = parseFourOpr b32 getRegRs1 getd16 getAbit getPbit
      struct (Opcode.BRLEZ, opr)
    | 0b011u ->
      let opr = parseFourOpr b32 getRegRs1 getd16 getAbit getPbit
      struct (Opcode.BRLZ, opr)
    | 0b101u ->
      let opr = parseFourOpr b32 getRegRs1 getd16 getAbit getPbit
      struct (Opcode.BRNZ, opr)
    | 0b110u ->
      let opr = parseFourOpr b32 getRegRs1 getd16 getAbit getPbit
      struct (Opcode.BRGZ, opr)
    | 0b111u ->
      let opr = parseFourOpr b32 getRegRs1 getd16 getAbit getPbit
      struct (Opcode.BRGEZ, opr)
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// IMPDEP1 (op=10, op3=0x36) is the VIS opcode space, sub-selected by the 9-bit
/// opf field (bits 13:5). Decode the 64-bit logical/select VIS ops (fzerod,
/// fsrc*d, for*d, ...) here; anything else stays a raw IMPDEP1.
let private parseVISimpdep1 b32 =
  let vis op = struct (op, parseThrOpr b32
                                       getDPFloatRegRs1
                                       getDPFloatRegRs2
                                       getDPFloatRegRd)
  match extract b32 13u 5u with
  | 0b001100000u ->
    vis Opcode.FZEROd
  | 0b001111110u ->
    vis Opcode.FONEd
  | 0b001110100u ->
    vis Opcode.FSRC1d
  | 0b001111000u ->
    vis Opcode.FSRC2d
  | 0b001101010u ->
    vis Opcode.FNOT1d
  | 0b001100110u ->
    vis Opcode.FNOT2d
  | 0b001111100u ->
    vis Opcode.FORd
  | 0b001100010u ->
    vis Opcode.FNORd
  | 0b001110000u ->
    vis Opcode.FANDd
  | 0b001101110u ->
    vis Opcode.FNANDd
  | 0b001101100u ->
    vis Opcode.FXORd
  | 0b001110010u ->
    vis Opcode.FXNORd
  | 0b001111010u ->
    vis Opcode.FORNOT1d
  | 0b001110110u ->
    vis Opcode.FORNOT2d
  | 0b001101000u ->
    vis Opcode.FANDNOT1d
  | 0b001100100u ->
    vis Opcode.FANDNOT2d
  | 0b001001000u ->
    vis Opcode.FALIGNDATAd
  | 0b000011000u ->
    struct (Opcode.ALIGNADDR, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
  | 0b000011010u ->
    struct (Opcode.ALIGNADDRL, parseThrOpr b32 getRegRs1 getRegRs2 getRegRd)
  | _ ->
    struct (Opcode.IMPDEP1, parseOneOpr b32 getImplDep)

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
        let opr = parseTcc b32
        struct (Opcode.TA, opr)
      | 0b0000u ->
        let opr = parseTcc b32
        struct (Opcode.TN, opr)
      | 0b1001u ->
        let opr = parseTcc b32
        struct (Opcode.TNE, opr)
      | 0b0001u ->
        let opr = parseTcc b32
        struct (Opcode.TE, opr)
      | 0b1010u ->
        let opr = parseTcc b32
        struct (Opcode.TG, opr)
      | 0b0010u ->
        let opr = parseTcc b32
        struct (Opcode.TLE, opr)
      | 0b1011u ->
        let opr = parseTcc b32
        struct (Opcode.TGE, opr)
      | 0b0011u ->
        let opr = parseTcc b32
        struct (Opcode.TL, opr)
      | 0b1100u ->
        let opr = parseTcc b32
        struct (Opcode.TGU, opr)
      | 0b0100u ->
        let opr = parseTcc b32
        struct (Opcode.TLEU, opr)
      | 0b1101u ->
        let opr = parseTcc b32
        struct (Opcode.TCC, opr)
      | 0b0101u ->
        let opr = parseTcc b32
        struct (Opcode.TCS, opr)
      | 0b1110u ->
        let opr = parseTcc b32
        struct (Opcode.TPOS, opr)
      | 0b0110u ->
        let opr = parseTcc b32
        struct (Opcode.TNEG, opr)
      | 0b1111u ->
        let opr = parseTcc b32
        struct (Opcode.TVC, opr)
      | 0b0111u ->
        let opr = parseTcc b32
        struct (Opcode.TVS, opr)
      | _ ->
        raise ParsingFailureException
    | 0b1u ->
      match extract b32 28u 25u with
      | 0b1000u ->
        let opr = parseTcc b32
        struct (Opcode.TA, opr)
      | 0b0000u ->
        let opr = parseTcc b32
        struct (Opcode.TN, opr)
      | 0b1001u ->
        let opr = parseTcc b32
        struct (Opcode.TNE, opr)
      | 0b0001u ->
        let opr = parseTcc b32
        struct (Opcode.TE, opr)
      | 0b1010u ->
        let opr = parseTcc b32
        struct (Opcode.TG, opr)
      | 0b0010u ->
        let opr = parseTcc b32
        struct (Opcode.TLE, opr)
      | 0b1011u ->
        let opr = parseTcc b32
        struct (Opcode.TGE, opr)
      | 0b0011u ->
        let opr = parseTcc b32
        struct (Opcode.TL, opr)
      | 0b1100u ->
        let opr = parseTcc b32
        struct (Opcode.TGU, opr)
      | 0b0100u ->
        let opr = parseTcc b32
        struct (Opcode.TLEU, opr)
      | 0b1101u ->
        let opr = parseTcc b32
        struct (Opcode.TCC, opr)
      | 0b0101u ->
        let opr = parseTcc b32
        struct (Opcode.TCS, opr)
      | 0b1110u ->
        let opr = parseTcc b32
        struct (Opcode.TPOS, opr)
      | 0b0110u ->
        let opr = parseTcc b32
        struct (Opcode.TNEG, opr)
      | 0b1111u ->
        let opr = parseTcc b32
        struct (Opcode.TVC, opr)
      | 0b0111u ->
        let opr = parseTcc b32
        struct (Opcode.TVS, opr)
      | _ ->
        raise ParsingFailureException
    | _ ->
      raise ParsingFailureException
  | 0b101000u ->
    match pickBit b32 13u with
    | 0b0u ->
      parse101000 b32
    | _ ->
      match pickBit b32 25u with
      | 0u ->
        match pickBit b32 13u with
        | 0b0u -> struct (Opcode.STBAR, NoOperand)
        | 0b1u -> struct (Opcode.MEMBAR, parseOneOpr b32 getMembarMask)
        | _ -> raise ParsingFailureException
      | _ ->
        raise ParsingFailureException
  | 0b110000u ->
    parse110000 b32
  | 0b110001u ->
    match pickBit b32 25u with
    | 0u -> struct (Opcode.SAVED, NoOperand)
    | 1u -> struct (Opcode.RESTORED, NoOperand)
    | _ -> raise ParsingFailureException
  | 0b111001u ->
    match pickBit b32 13u with
    | 0b0u -> struct (Opcode.RETURN, parseTwoOpr b32 getRegRs1 getRegRs2)
    | 0b1u -> struct (Opcode.RETURN, parseTwoOpr b32 getRegRs1 getSimm13)
    | _ -> raise ParsingFailureException
  | 0b111110u ->
    match pickBit b32 25u with
    | 0u -> struct (Opcode.DONE, NoOperand)
    | 1u -> struct (Opcode.RETRY, NoOperand)
    | _ -> raise ParsingFailureException
  | 0b110101u ->
    match extract b32 13u 5u with
    | 0b001010001u ->
      let opr =
        parseOneCCTwoOpr b32
          (getTwoCCFcc (get26cc1 b32) (get25cc0 b32))
          getFloatRegRs1
          getFloatRegRs2
      struct (Opcode.FCMPs, opr)
    | 0b001010010u ->
      let parseOneCCTwoOpr =
        parseOneCCTwoOpr b32
                         (getTwoCCFcc (get26cc1 b32) (get25cc0 b32))
                         getDPFloatRegRs1
                         getDPFloatRegRs2
      struct (Opcode.FCMPd, parseOneCCTwoOpr)
    | 0b001010011u ->
      let opr =
        parseOneCCTwoOpr b32
          (getTwoCCFcc (get26cc1 b32) (get25cc0 b32))
          getQPFloatRegRs1
          getQPFloatRegRs2
      struct (Opcode.FCMPq, opr)
    | 0b001010101u ->
      let opr =
        parseOneCCTwoOpr b32
          (getTwoCCFcc (get26cc1 b32) (get25cc0 b32))
          getFloatRegRs1
          getFloatRegRs2
      struct (Opcode.FCMPEs, opr)
    | 0b001010110u ->
      let opr =
        parseOneCCTwoOpr b32
          (getTwoCCFcc (get26cc1 b32) (get25cc0 b32))
          getDPFloatRegRs1
          getDPFloatRegRs2
      struct (Opcode.FCMPEd, opr)
    | 0b001010111u ->
      let opr =
        parseOneCCTwoOpr b32
          (getTwoCCFcc (get26cc1 b32) (get25cc0 b32))
          getQPFloatRegRs1
          getQPFloatRegRs2
      struct (Opcode.FCMPEq, opr)
    | _ ->
      parse110101 b32
  | 0b111011u ->
    match pickBit b32 13u with
    | 0b0u -> struct (Opcode.FLUSH, parseTwoOpr b32 getRegRs1 getRegRs2)
    | 0b1u -> struct (Opcode.FLUSH, parseTwoOpr b32 getRegRs1 getSimm13)
    | _ -> raise ParsingFailureException
  | 0b101011u ->
    struct (Opcode.FLUSHW, NoOperand)
  | 0b110110u ->
    parseVISimpdep1 b32
  | 0b110111u ->
    struct (Opcode.IMPDEP2, parseOneOpr b32 getImplDep)
  | _ ->
    parse10rd b32

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
      let opr = parseFourOpr b32 getRegRs1 getRegRs2 getImmAsi getRegRd
      struct (Opcode.PREFETCHA, opr)
    | _ ->
      parse11rd b32
  | 0b1u ->
    match extract b32 24u 19u with
    | 0b101101u ->
      struct (Opcode.PREFETCH, parseThrOpr b32 getRegRs1 getSimm13 getRegRd)
    | 0b111101u ->
      let opr =
        parseThrOprOneReg b32 getRegRs1 getSimm13 (setPriReg ASI) getRegRd
      struct (Opcode.PREFETCHA, opr)
    | _ ->
      parse11rd b32
  | _ ->
    parse11rd b32

let parseTwoBits bin =
  match extract bin 31u 30u with
  | 0b00u -> parse00 bin
  | 0b01u -> struct (Opcode.CALL, parseOneOpr bin getdisp30)
  | 0b10u -> parse10 bin
  | 0b11u -> parse11 bin
  | _ -> raise ParsingFailureException

let parse lifter (span: ByteSpan) (reader: IBinReader) addr =
  let bin = reader.ReadInt32(span, 0)
  let struct (op, operands) = uint32 bin |> parseTwoBits
  Instruction(addr, 4u, op, operands, lifter)

// vim: set tw=80 sts=2 sw=2:
