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
open B2R2.FrontEnd.BinLifter.RISCV.Utils

let getRm = function
  | 0u -> RoundMode.RNE
  | 1u -> RoundMode.RTZ
  | 2u -> RoundMode.RDN
  | 3u -> RoundMode.RUP
  | 4u -> RoundMode.RMM
  | 7u -> RoundMode.DYN
  | _ -> failwith "invalid rounding mode"


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

let getRegFrom117 b = getRegister (extract b 11u 7u |> byte)
let getRegFrom1915 b = getRegister (extract b 19u 15u |> byte)
let getRegFrom2420 b = getRegister (extract b 24u 20u |> byte)
let getRegFrom3127 b = getRegister (extract b 31u 27u |> byte)

let getUImm b = (b &&& 0xfffff000u) |> uint64 |> OpImm

let getBImm b =
  let from4to1 = (extract b 11u 8u) <<< 1
  let from10to5 = (extract b 30u 25u) <<< 5
  let from7to7 = (pickBit b 7u) <<< 7
  let from31to12 = (pickBit b 31u) <<< 12
  let imm = from31to12 ||| from7to7 ||| from10to5 ||| from4to1 |> uint64
  signExtend 12 32 imm |> OpImm

let getIImm b =
  let imm = extract b 31u 20u |> uint64
  signExtend 11 32 imm |> OpImm

let getSImm b =
  let from4to0 = extract b 11u 7u
  let from11to5 = extract b 31u 25u <<< 5
  let imm = from11to5 ||| from4to0 |> uint64
  signExtend 11 32 imm |> OpImm

let getJImm bin =
  let from10to1 = (extract bin 30u 21u) <<< 1
  let from11to11 = (pickBit bin 20u) <<< 11
  let from19to12 = (extract bin 19u 12u) <<< 12
  let from20to20 = (pickBit bin 31u) <<< 20
  let imm = from10to1 ||| from11to11 ||| from19to12 ||| from20to20 |> uint64
  signExtend 20 32 imm |> int64 |> Relative |> OpAddr

let rd b = getRegFrom117 b |> OpReg
let rs1 b = getRegFrom1915 b |> OpReg
let rs2 b = getRegFrom2420 b |> OpReg
let rs3 b = getRegFrom3127 b |> OpReg
let rm b = getRm (extract b 14u 12u) |> OpRoundMode
let csr b = extract b 31u 20u |> uint16 |> OpCSR
let uimm b = extract b 19u 15u |> uint64 |> OpImm
let shamt b = (extract b 24u 20u) |> uint64 |> OpShiftAmount

let getPred bin = extract bin 27u 24u |> uint8
let getSucc bin = extract bin 23u 20u |> uint8
let getAqRl bin = OpAtomMemOper(pickBit bin 26u > 0u, pickBit bin 25u > 0u)
let getRdImm20 b = TwoOperands (rd b, getUImm b)
let getPCRdImm20 b = ThreeOperands (R.PC |> OpReg, rd b, getUImm b)
let getPCBImm b = TwoOperands (R.PC |> OpReg, getBImm b)
let getRdRs1IImm b = ThreeOperands (rd b, rs1 b, getIImm b)
let getRs2Rs1SImm b = ThreeOperands (rs2 b, rs1 b, getSImm b)
let getRdRs1Shamt b = ThreeOperands(rd b, rs1 b, shamt b)
let getRdRs1Rs2 b = ThreeOperands(rd b, rs1 b, rs2 b)
let getPredSucc b = (getPred b, getSucc b) |> OpFenceMask |> OneOperand
let getFunc3 b = extract b 14u 12u
let getFunc7 b = extract b 31u 25u
let getRs2 b = extract b 24u 20u
let getRdRs1AqRlAcc b acc =
  ThreeOperands (rd b, OpMem (getRegFrom1915 b, 0L |> Imm, acc), getAqRl b)
let getRdRs1Rs2AqRlAcc b acc =
  let mem = OpMem (getRegFrom1915 b, 0L |> Imm, acc)
  FourOperands (rd b, mem, rs2 b,  getAqRl b)
let getRdJImm b = TwoOperands (rd b, getJImm b)
let getRdRs1JImm b = ThreeOperands (rd b, rs1 b, getIImm b)
let getRdRs1Rs2Rs3 b = FourOperands (rd b, rs1 b, rs2 b, rs3 b)
let getRdRs1Rs2Rm b = FourOperands (rd b, rs1 b, rs2 b, rm b)
let getRdRs1Rm b = ThreeOperands (rd b, rs1 b, rm b)
let getRdRs1 b = TwoOperands (rd b, rs1 b)
let getRdRs1CSR b = ThreeOperands (rd b, rs1 b, csr b)
let getRdUImmCSR b = ThreeOperands (rd b, uimm b, csr b)