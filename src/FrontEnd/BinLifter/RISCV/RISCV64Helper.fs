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

module B2R2.FrontEnd.BinLifter.RISCV.Helper

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.BitData

let getRm = function
  | 0u -> RoundMode.RNE
  | 1u -> RoundMode.RTZ
  | 2u -> RoundMode.RDN
  | 3u -> RoundMode.RUP
  | 4u -> RoundMode.RMM
  | 7u -> RoundMode.DYN
  | _ -> raise ParsingFailureException

let getRegister = function
  | 0x0uy -> R.X0
  | 0x1uy -> R.X1
  | 0x2uy -> R.X2
  | 0x3uy -> R.X3
  | 0x4uy -> R.X4
  | 0x5uy -> R.X5
  | 0x6uy -> R.X6
  | 0x7uy -> R.X7
  | 0x8uy -> R.X8
  | 0x9uy -> R.X9
  | 0xAuy -> R.X10
  | 0xBuy -> R.X11
  | 0xCuy -> R.X12
  | 0xDuy -> R.X13
  | 0xEuy -> R.X14
  | 0xFuy -> R.X15
  | 0x10uy -> R.X16
  | 0x11uy -> R.X17
  | 0x12uy -> R.X18
  | 0x13uy -> R.X19
  | 0x14uy -> R.X20
  | 0x15uy -> R.X21
  | 0x16uy -> R.X22
  | 0x17uy -> R.X23
  | 0x18uy -> R.X24
  | 0x19uy -> R.X25
  | 0x1Auy -> R.X26
  | 0x1Buy -> R.X27
  | 0x1Cuy -> R.X28
  | 0x1Duy -> R.X29
  | 0x1Euy -> R.X30
  | 0x1Fuy -> R.X31
  | _ -> raise InvalidRegisterException

let getFRegister = function
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
  | 0xAuy -> R.F10
  | 0xBuy -> R.F11
  | 0xCuy -> R.F12
  | 0xDuy -> R.F13
  | 0xEuy -> R.F14
  | 0xFuy -> R.F15
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
  | 0x1Auy -> R.F26
  | 0x1Buy -> R.F27
  | 0x1Cuy -> R.F28
  | 0x1Duy -> R.F29
  | 0x1Euy -> R.F30
  | 0x1Fuy -> R.F31
  | _ -> raise InvalidRegisterException

let getCompRegister = function
  | 0x0uy -> R.X8
  | 0x1uy -> R.X9
  | 0x2uy -> R.X10
  | 0x3uy -> R.X11
  | 0x4uy -> R.X12
  | 0x5uy -> R.X13
  | 0x6uy -> R.X14
  | 0x7uy -> R.X15
  | _ -> Utils.impossible ()

let getFCompRegister = function
  | 0x0uy -> R.F8
  | 0x1uy -> R.F9
  | 0x2uy -> R.F10
  | 0x3uy -> R.F11
  | 0x4uy -> R.F12
  | 0x5uy -> R.F13
  | 0x6uy -> R.F14
  | 0x7uy -> R.F15
  | _ -> Utils.impossible ()

let getRegFrom117 b = getRegister (extract b 11u 7u |> byte)
let getFRegFrom117 b = getFRegister (extract b 11u 7u |> byte)
let getRegFrom1915 b = getRegister (extract b 19u 15u |> byte)
let getFRegFrom1915 b = getFRegister (extract b 19u 15u |> byte)
let getRegFrom2420 b = getRegister (extract b 24u 20u |> byte)
let getFRegFrom2420 b = getFRegister (extract b 24u 20u |> byte)
let getRegFrom3127 b = getRegister (extract b 31u 27u |> byte)
let getFRegFrom3127 b = getFRegister (extract b 31u 27u |> byte)
let getRegFrom62 b = getRegister (extract b 6u 2u |> byte)
let getFRegFrom62 b = getFRegister (extract b 6u 2u |> byte)
let getCompRegFrom42 b = getCompRegister (extract b 4u 2u |> byte)
let getFCompRegFrom42 b = getFCompRegister (extract b 4u 2u |> byte)
let getCompRegFrom97 b = getCompRegister (extract b 9u 7u |> byte)

let getUImm b = (b &&& 0xfffff000u)

let getBImm b =
  let from4to1 = (extract b 11u 8u) <<< 1
  let from10to5 = (extract b 30u 25u) <<< 5
  let from11to11 = (pickBit b 7u) <<< 11
  let from31to12 = (pickBit b 31u) <<< 12
  let imm = from31to12 ||| from11to11 ||| from10to5 ||| from4to1 |> uint64
  signExtend 12 32 imm |> int32

let getIImm b =
  let imm = extract b 31u 20u |> uint64
  signExtend 11 32 imm

let getSImm b =
  let from4to0 = extract b 11u 7u
  let from11to5 = extract b 31u 25u <<< 5
  let imm = from11to5 ||| from4to0 |> uint64
  signExtend 11 32 imm

let getJImm bin =
  let from10to1 = (extract bin 30u 21u) <<< 1
  let from11to11 = (pickBit bin 20u) <<< 11
  let from19to12 = (extract bin 19u 12u) <<< 12
  let from20to20 = (pickBit bin 31u) <<< 20
  let imm = from10to1 ||| from11to11 ||| from19to12 ||| from20to20 |> uint64
  signExtend 20 32 imm |> int32

let rd b = getRegFrom117 b |> OpReg
let frd b = getFRegFrom117 b |> OpReg
let rs1 b = getRegFrom1915 b |> OpReg
let frs1 b = getFRegFrom1915 b |> OpReg
let rs2 b = getRegFrom2420 b |> OpReg
let frs2 b = getFRegFrom2420 b |> OpReg
let rs3 b = getRegFrom3127 b |> OpReg
let frs3 b = getFRegFrom3127 b |> OpReg
let rm b = getRm (extract b 14u 12u) |> OpRoundMode
let csr b = extract b 31u 20u |> uint16 |> OpCSR
let uimm b = extract b 19u 15u |> uint32 |> OpImm
let shamt b = (extract b 25u 20u) |> uint32 |> OpShiftAmount
let crd b = getRegFrom117 b |> OpReg
let cfrd b = getFRegFrom117 b |> OpReg
let crs2 b = getRegFrom62 b |> OpReg
let crs2Comp b = getCompRegFrom42 b |> OpReg
let cfrs2 b = getRegFrom62 b |> OpReg
let cfrs2Comp b = getFCompRegFrom42 b |> OpReg
let crdComp b = getCompRegFrom42 b |> OpReg
let cfrdComp b = getFCompRegFrom42 b |> OpReg
let crs1Comp b = getCompRegFrom97 b |> OpReg

let getPred bin = extract bin 27u 24u |> uint8
let getSucc bin = extract bin 23u 20u |> uint8
let getAqRl bin = OpAtomMemOper(pickBit bin 26u > 0u, pickBit bin 25u > 0u)
let getRdImm20 b = TwoOperands (rd b, getUImm b |> OpImm)
let getPCRdImm20 b = TwoOperands (rd b, getUImm b |> OpImm)
let getRs1Rs2BImm b = ThreeOperands (rs1 b, rs2 b, getBImm b |> int64 |> Relative |> OpAddr)
let getRdRs1IImmAcc b acc =
  let mem = (getRegFrom1915 b, getIImm b |> uint32 |> Imm |> Some, acc)
  TwoOperands (rd b, mem |> OpMem)
let getRdRs1IImm b = ThreeOperands (rd b, rs1 b, getIImm b |> uint32 |> OpImm)
let getFRdRs1Addr b acc =
  TwoOperands(frd b, OpMem (getRegFrom1915 b, getIImm b |> uint32 |> Imm |> Some, acc))
let getRs2Rs1SImm b acc =
  let mem = (getRegFrom1915 b, getSImm b |> uint32 |> Imm |> Some, acc)
  TwoOperands (rs2 b, mem |> OpMem)
let getFRs2Rs1Addr b acc =
  TwoOperands (frs2 b, OpMem (getRegFrom1915 b, getSImm b |> uint32 |> Imm |> Some, acc))
let getRdRs1Shamt b = ThreeOperands(rd b, rs1 b, shamt b)
let getRdRs1Rs2 b = ThreeOperands(rd b, rs1 b, rs2 b)
let getFRdRs1Rs2 b = ThreeOperands(frd b, frs1 b, frs2 b)
let getFNRdRs1Rs2 b = ThreeOperands(rd b, frs1 b, frs2 b)
let getPredSucc b = OneOperand ((getPred b, getSucc b) |> OpFenceMask)
let getFunc3 b = extract b 14u 12u
let getFunc7 b = extract b 31u 25u
let getRs2 b = extract b 24u 20u
let getRdRs1AqRlAcc b acc =
  ThreeOperands (rd b, OpMem (getRegFrom1915 b, None, acc), getAqRl b)
let getRdRs1Rs2AqRlAcc b acc =
  let mem = OpMem (getRegFrom1915 b, None, acc)
  FourOperands (rd b, mem, rs2 b, getAqRl b)
let getRdJImm b = TwoOperands (rd b, getJImm b |> int64 |> Relative |> OpAddr)
let getRdRs1JImm b =
  let off = RelativeBase (getRegFrom1915 b, getIImm b |> uint32)
  TwoOperands (rd b, off |> OpAddr)
let getFRdRs1Rs2Rs3Rm b = FiveOperands (frd b, frs1 b, frs2 b, frs3 b, rm b)
let getRdRs1Rs2Rm b = FourOperands (rd b, rs1 b, rs2 b, rm b)
let getFRdRs1Rs2Rm b = FourOperands (frd b, frs1 b, frs2 b, rm b)
let getRdRs1Rm b = ThreeOperands (rd b, rs1 b, rm b)
let getFRdRs1Rm b = ThreeOperands (frd b, frs1 b, rm b)
let getRdRs1 b = TwoOperands (rd b, rs1 b)
let getRdFRs1 b = TwoOperands (rd b, frs1 b)
let getFRdFRs1 b = TwoOperands (frd b, frs1 b)
let getFRdRs1 b = TwoOperands (frd b, rs1 b)
let getRdCSRRs1 b = ThreeOperands (rd b, csr b, rs1 b)
let getRdCSRUImm b = ThreeOperands (rd b, csr b, uimm b)
