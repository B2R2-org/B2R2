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

module B2R2.FrontEnd.RISCV64.Helper

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
  | 0x0uy -> Register.X0
  | 0x1uy -> Register.X1
  | 0x2uy -> Register.X2
  | 0x3uy -> Register.X3
  | 0x4uy -> Register.X4
  | 0x5uy -> Register.X5
  | 0x6uy -> Register.X6
  | 0x7uy -> Register.X7
  | 0x8uy -> Register.X8
  | 0x9uy -> Register.X9
  | 0xAuy -> Register.X10
  | 0xBuy -> Register.X11
  | 0xCuy -> Register.X12
  | 0xDuy -> Register.X13
  | 0xEuy -> Register.X14
  | 0xFuy -> Register.X15
  | 0x10uy -> Register.X16
  | 0x11uy -> Register.X17
  | 0x12uy -> Register.X18
  | 0x13uy -> Register.X19
  | 0x14uy -> Register.X20
  | 0x15uy -> Register.X21
  | 0x16uy -> Register.X22
  | 0x17uy -> Register.X23
  | 0x18uy -> Register.X24
  | 0x19uy -> Register.X25
  | 0x1Auy -> Register.X26
  | 0x1Buy -> Register.X27
  | 0x1Cuy -> Register.X28
  | 0x1Duy -> Register.X29
  | 0x1Euy -> Register.X30
  | 0x1Fuy -> Register.X31
  | _ -> raise InvalidRegisterException

let getFRegister = function
  | 0x0uy -> Register.F0
  | 0x1uy -> Register.F1
  | 0x2uy -> Register.F2
  | 0x3uy -> Register.F3
  | 0x4uy -> Register.F4
  | 0x5uy -> Register.F5
  | 0x6uy -> Register.F6
  | 0x7uy -> Register.F7
  | 0x8uy -> Register.F8
  | 0x9uy -> Register.F9
  | 0xAuy -> Register.F10
  | 0xBuy -> Register.F11
  | 0xCuy -> Register.F12
  | 0xDuy -> Register.F13
  | 0xEuy -> Register.F14
  | 0xFuy -> Register.F15
  | 0x10uy -> Register.F16
  | 0x11uy -> Register.F17
  | 0x12uy -> Register.F18
  | 0x13uy -> Register.F19
  | 0x14uy -> Register.F20
  | 0x15uy -> Register.F21
  | 0x16uy -> Register.F22
  | 0x17uy -> Register.F23
  | 0x18uy -> Register.F24
  | 0x19uy -> Register.F25
  | 0x1Auy -> Register.F26
  | 0x1Buy -> Register.F27
  | 0x1Cuy -> Register.F28
  | 0x1Duy -> Register.F29
  | 0x1Euy -> Register.F30
  | 0x1Fuy -> Register.F31
  | _ -> raise InvalidRegisterException

let getCompRegister = function
  | 0x0uy -> Register.X8
  | 0x1uy -> Register.X9
  | 0x2uy -> Register.X10
  | 0x3uy -> Register.X11
  | 0x4uy -> Register.X12
  | 0x5uy -> Register.X13
  | 0x6uy -> Register.X14
  | 0x7uy -> Register.X15
  | _ -> Terminator.impossible ()

let getFCompRegister = function
  | 0x0uy -> Register.F8
  | 0x1uy -> Register.F9
  | 0x2uy -> Register.F10
  | 0x3uy -> Register.F11
  | 0x4uy -> Register.F12
  | 0x5uy -> Register.F13
  | 0x6uy -> Register.F14
  | 0x7uy -> Register.F15
  | _ -> Terminator.impossible ()

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

let getUImm b wordSize =
  let imm = extract b 31u 12u |> uint64
  signExtend 20 wordSize imm

let getBImm b wordSize =
  let from4to1 = (extract b 11u 8u) <<< 1
  let from10to5 = (extract b 30u 25u) <<< 5
  let from11to11 = (pickBit b 7u) <<< 11
  let from12to12 = (pickBit b 31u) <<< 12
  let imm = from12to12 ||| from11to11 ||| from10to5 ||| from4to1 ||| 0b0u
            |> uint64
  signExtend 13 wordSize imm

let getIImm b wordSize =
  let imm = extract b 31u 20u |> uint64
  signExtend 12 wordSize imm

let getSImm b wordSize =
  let from4to0 = extract b 11u 7u
  let from11to5 = extract b 31u 25u <<< 5
  let imm = from11to5 ||| from4to0 |> uint64
  signExtend 12 wordSize imm

let getJImm bin wordSize =
  let from10to1 = (extract bin 30u 21u) <<< 1
  let from11to11 = (pickBit bin 20u) <<< 11
  let from19to12 = (extract bin 19u 12u) <<< 12
  let from20to20 = (pickBit bin 31u) <<< 20
  let imm = 0b0u ||| from10to1 ||| from11to11 ||| from19to12 ||| from20to20
            |> uint64
  signExtend 21 wordSize imm |> int64

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
let uimm b = extract b 19u 15u |> uint64 |> OpImm
let shamt b = extract b 25u 20u |> uint64 |> OpShiftAmount
let crd b = getRegFrom117 b |> OpReg
let cfrd b = getFRegFrom117 b |> OpReg
let crs2 b = getRegFrom62 b |> OpReg
let crs2Comp b = getCompRegFrom42 b |> OpReg
let cfrs2 b = getFRegFrom62 b |> OpReg
let cfrs2Comp b = getFCompRegFrom42 b |> OpReg
let crdComp b = getCompRegFrom42 b |> OpReg
let cfrdComp b = getFCompRegFrom42 b |> OpReg
let crs1Comp b = getCompRegFrom97 b |> OpReg

let getPred bin = extract bin 27u 24u |> uint8
let getSucc bin = extract bin 23u 20u |> uint8
let getAqRl bin = OpAtomMemOper(pickBit bin 26u > 0u, pickBit bin 25u > 0u)
let getRdImm20 b wordSz = TwoOperands (rd b, getUImm b wordSz |> OpImm)
let getPCRdImm20 b wordSz = TwoOperands (rd b, getUImm b wordSz |> OpImm)
let getRs1Rs2BImm b wordSz =
  ThreeOperands (rs1 b, rs2 b, getBImm b wordSz |> int64 |> Relative |> OpAddr)
let getRdRs1IImmAcc b acc wordSize =
  let mem = (getRegFrom1915 b, getIImm b wordSize |> int64 |> Imm |> Some, acc)
  TwoOperands (rd b, mem |> OpMem)
let getRdRs1IImm b wordSize =
  ThreeOperands (rd b, rs1 b, getIImm b wordSize |> uint64 |> OpImm)
let getFRdRs1Addr b acc wordSize =
  let imm = getIImm b wordSize |> int64 |> Imm |> Some
  TwoOperands(frd b, OpMem (getRegFrom1915 b, imm, acc))
let getRs2Rs1SImm b acc wordSize =
  let mem = (getRegFrom1915 b, getSImm b wordSize |> int64 |> Imm |> Some, acc)
  TwoOperands (rs2 b, mem |> OpMem)
let getFRs2Rs1Addr b acc wordSize =
  let imm = getSImm b wordSize |> int64 |> Imm |> Some
  TwoOperands (frs2 b, OpMem (getRegFrom1915 b, imm, acc))
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
let getRdRs2Rs1AqRlAcc b acc =
  let mem = OpMem (getRegFrom1915 b, None, acc)
  FourOperands (rd b, rs2 b, mem, getAqRl b)
let getRdJImm b wordSize =
  TwoOperands (rd b, getJImm b wordSize |> int64 |> Relative |> OpAddr)
let getRdRs1JImm b wordSize =
  let off = RelativeBase (getRegFrom1915 b, getIImm b wordSize |> uint64)
  TwoOperands (rd b, off |> OpAddr)
let getFRdRs1Rs2Rs3Rm b = FiveOperands (frd b, frs1 b, frs2 b, frs3 b, rm b)
let getRdRs1Rs2Rm b = FourOperands (rd b, rs1 b, rs2 b, rm b)
let getFRdRs1Rs2Rm b = FourOperands (frd b, frs1 b, frs2 b, rm b)
let getRdRs1Rm b = ThreeOperands (rd b, rs1 b, rm b)
let getFRdRs1Rm b = ThreeOperands (frd b, rs1 b, rm b)
let getFRdFRs1Rm b = ThreeOperands (frd b, frs1 b, rm b)
let getRdFRs1Rm b = ThreeOperands (rd b, frs1 b, rm b)
let getRdRs1 b = TwoOperands (rd b, rs1 b)
let getRdFRs1 b = TwoOperands (rd b, frs1 b)
let getFRdFRs1 b = TwoOperands (frd b, frs1 b)
let getFRdRs1 b = TwoOperands (frd b, rs1 b)
let getRdCSRRs1 b = ThreeOperands (rd b, csr b, rs1 b)
let getRdCSRUImm b = ThreeOperands (rd b, csr b, uimm b)
