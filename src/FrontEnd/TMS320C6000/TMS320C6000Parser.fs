(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Seung Il Jung <sijung@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

module B2R2.FrontEnd.TMS320C6000.Parser

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BitData

let getRegisterA = function
  | 0b00000u -> R.A0
  | 0b00001u -> R.A1
  | 0b00010u -> R.A2
  | 0b00011u -> R.A3
  | 0b00100u -> R.A4
  | 0b00101u -> R.A5
  | 0b00110u -> R.A6
  | 0b00111u -> R.A7
  | 0b01000u -> R.A8
  | 0b01001u -> R.A9
  | 0b01010u -> R.A10
  | 0b01011u -> R.A11
  | 0b01100u -> R.A12
  | 0b01101u -> R.A13
  | 0b01110u -> R.A14
  | 0b01111u -> R.A15
  | 0b10000u -> R.A16
  | 0b10001u -> R.A17
  | 0b10010u -> R.A18
  | 0b10011u -> R.A19
  | 0b10100u -> R.A20
  | 0b10101u -> R.A21
  | 0b10110u -> R.A22
  | 0b10111u -> R.A23
  | 0b11000u -> R.A24
  | 0b11001u -> R.A25
  | 0b11010u -> R.A26
  | 0b11011u -> R.A27
  | 0b11100u -> R.A28
  | 0b11101u -> R.A29
  | 0b11110u -> R.A30
  | 0b11111u -> R.A31
  | _ -> failwith "Invalid Register"

let getRegisterB = function
  | 0b00000u -> R.B0
  | 0b00001u -> R.B1
  | 0b00010u -> R.B2
  | 0b00011u -> R.B3
  | 0b00100u -> R.B4
  | 0b00101u -> R.B5
  | 0b00110u -> R.B6
  | 0b00111u -> R.B7
  | 0b01000u -> R.B8
  | 0b01001u -> R.B9
  | 0b01010u -> R.B10
  | 0b01011u -> R.B11
  | 0b01100u -> R.B12
  | 0b01101u -> R.B13
  | 0b01110u -> R.B14
  | 0b01111u -> R.B15
  | 0b10000u -> R.B16
  | 0b10001u -> R.B17
  | 0b10010u -> R.B18
  | 0b10011u -> R.B19
  | 0b10100u -> R.B20
  | 0b10101u -> R.B21
  | 0b10110u -> R.B22
  | 0b10111u -> R.B23
  | 0b11000u -> R.B24
  | 0b11001u -> R.B25
  | 0b11010u -> R.B26
  | 0b11011u -> R.B27
  | 0b11100u -> R.B28
  | 0b11101u -> R.B29
  | 0b11110u -> R.B30
  | 0b11111u -> R.B31
  | _ -> failwith "Invalid Register"

let parseRegister bin = function
  | L1 | S1 | M1 | D1 -> getRegisterA bin
  | L2 | S2 | M2 | D2 -> getRegisterB bin
  | L1X | S1X | M1X -> getRegisterA bin
  | L2X | S2X | M2X -> getRegisterB bin
  | _ -> failwith "Invalid Register"

let parseRegisterX bin = function
  | L1 | S1 | M1 | D1 -> getRegisterA bin
  | L2 | S2 | M2 | D2 -> getRegisterB bin
  | L1X | S1X | M1X -> getRegisterB bin
  | L2X | S2X | M2X -> getRegisterA bin
  | _ -> failwith "Invalid Register"

let src1Bits bin = extract bin 17u 13u
let src2Bits bin = extract bin 22u 18u
let dstBits bin = extract bin 27u 23u
let xBit bin = pickBit bin 12u
let sBit bin = pickBit bin 1u

let opFld11to5 bin = extract bin 11u 5u
let opFld11to6 bin = extract bin 11u 6u
let opFld12to7 bin = extract bin 12u 7u

let getLUnit s x =
  match s, x with
  | 0b0u, 0b0u -> L1
  | 0b0u, 0b1u -> L1X
  | 0b1u, 0b0u -> L2
  | _ -> L2X

let getSUnit s x =
  match s, x with
  | 0b0u, 0b0u -> S1
  | 0b0u, 0b1u -> S1X
  | 0b1u, 0b0u -> S2
  | _ -> S2X

let getDUnit s = if s = 0b0u then D1 else D2

let Si bin unit = parseRegister bin unit |> Register
let XSi bin unit = parseRegisterX bin unit |> Register
let Sl bin unit =
  (parseRegisterX (bin + 0b1u) unit, parseRegister bin unit) |> RegisterPair

let toImm imm = imm |> uint64 |> Immediate
let Sc5 bin = toImm bin
let Uc5 bin = toImm bin

/// sint, xsint, sint
let parseSiXSiSi bin u =
  ThreeOperands (Si (src1Bits bin) u, XSi (src2Bits bin) u, Si (dstBits bin) u)
/// sint, xsint, slong
let parseSiXSiSl bin u =
  ThreeOperands (Si (src1Bits bin) u, XSi (src2Bits bin) u, Sl (dstBits bin) u)
/// xsint, slong, slong
let parseXSiSlSl bin u =
  ThreeOperands (XSi (src1Bits bin) u, Sl (src2Bits bin) u, Sl (dstBits bin) u)
/// scst5, xsing, slong
let parseSc5XSiSi bin u =
  ThreeOperands (Sc5 (src1Bits bin), XSi (src2Bits bin) u, Si (dstBits bin) u)
/// scst5, slong, slong
let parseSc5SlSl bin u =
  ThreeOperands (Sc5 (src1Bits bin), Sl (src2Bits bin) u, Sl (dstBits bin) u)
/// sint, sint, sint
let parseSiSiSi bin u =
  ThreeOperands (Si (src2Bits bin) u, Si (src1Bits bin) u, Si (dstBits bin) u)
/// sint, ucst5, sint
let parseSiUc5Si bin u =
  ThreeOperands (Si (src2Bits bin) u, Uc5 (src1Bits bin), Si (dstBits bin) u)

/// Appendix C-5. Fig. C-1
let parseDUnitSrcs bin =
  let unit = getDUnit (sBit bin)
  match opFld12to7 bin with
  | 0b010000u -> Op.ADD, unit, parseSiSiSi bin unit
  | 0b010010u -> Op.ADD, unit, parseSiUc5Si bin unit
  | _ -> raise InvalidOpcodeException

let parseDUnitSrcsExt bin = Op.InvalOP, NoUnit, NoOperand
let parseDUnitLSBasic bin = Op.InvalOP, NoUnit, NoOperand
let parseDUnitLSLongImm bin = Op.InvalOP, NoUnit, NoOperand

let parseLUnitSrcs bin =
  let x, s = xBit bin, sBit bin
  let unit = getLUnit s x
  match opFld11to5 bin with
  | 0b0000011u -> Op.ADD, unit, parseSiXSiSi bin unit
  | 0b0100011u -> Op.ADD, unit, parseSiXSiSl bin unit
  | 0b0100001u -> Op.ADD, unit, parseXSiSlSl bin unit
  | 0b0000010u -> Op.ADD, unit, parseSc5XSiSi bin unit
  | 0b0100000u -> Op.ADD, unit, parseSc5SlSl bin unit
  | _ -> raise InvalidOpcodeException

let parseLUnitNonCond bin = Op.InvalOP, NoUnit, NoOperand
let parseLUnitUnary bin = Op.InvalOP, NoUnit, NoOperand

let parseMUnitCompound bin = Op.InvalOP, NoUnit, NoOperand
let parseMUnitNonCond bin = Op.InvalOP, NoUnit, NoOperand
let parseMUnitUnaryExt bin = Op.InvalOP, NoUnit, NoOperand

let parseSUnitSrcs bin =
  let x, s = xBit bin, sBit bin
  let unit = getSUnit s x
  match opFld11to6 bin with
  | 0b000111u -> Op.ADD, unit, parseSiXSiSi bin unit
  | 0b000110u -> Op.ADD, unit, parseSc5XSiSi bin unit
  | _ -> raise InvalidOpcodeException

let parseSUnitSrcsExt bin = Op.InvalOP, NoUnit, NoOperand
let parseSUnitNonCond bin = Op.InvalOP, NoUnit, NoOperand
let parseSUnitUnary bin = Op.InvalOP, NoUnit, NoOperand
let parseSUnitBrImm bin = Op.InvalOP, NoUnit, NoOperand
let parseSUnitUncondImm bin = Op.InvalOP, NoUnit, NoOperand
let parseSUnitBrNOPConst bin = Op.InvalOP, NoUnit, NoOperand
let parseSUnitBrNOPReg bin = Op.InvalOP, NoUnit, NoOperand
let parseSUnitBr bin = Op.InvalOP, NoUnit, NoOperand
let parseSUnitMVK bin = Op.InvalOP, NoUnit, NoOperand
let parseSUnitFieldOps bin = Op.InvalOP, NoUnit, NoOperand

let parseNoUnitLoop bin = Op.InvalOP, NoUnit, NoOperand
let parseNoUnitNOPIdle bin = Op.InvalOP, NoUnit, NoOperand
let parseNoUnitEmuControl bin = Op.InvalOP, NoUnit, NoOperand

let parseCase1111 bin =
  match extract bin 31u 29u with
  | 0b0000u -> parseSUnitNonCond bin
  | _ -> parseSUnitSrcsExt bin

let parseMUnit bin =
  match extract bin 10u 6u with
  | 0b00011u -> parseMUnitUnaryExt bin
  | _ ->
    match extract bin 31u 28u with
    | 0b0001u -> parseMUnitNonCond bin
    | _ -> parseMUnitCompound bin

let parseNoUnit bin =
  match extract bin 31u 28u, pickBit bin 17u with
  | 0b0001u, _ -> parseNoUnitNOPIdle bin
  | _, 0b1u -> parseNoUnitLoop bin
  | _, _ (* 0b0u *) -> parseNoUnitEmuControl bin

let parseCase0000 bin =
  match pickBit bin 6u with
  | 0b0u -> parseNoUnit bin
  | _ -> parseDUnitSrcs bin

let parseCase0100 bin =
  match extract bin 31u 29u with
  | 0b000u -> parseSUnitUncondImm bin
  | _ -> parseSUnitBrImm bin

let parseCase1000 bin =
  match extract bin 27u 23u, extract bin 11u 6u with
  | 0b00000u, 0b001101u -> parseSUnitBr bin
  | 0b00001u, 0b001101u -> parseSUnitBrNOPReg bin
  | _, 0b000100u -> parseSUnitBrNOPConst bin
  | _, 0b111100u -> parseSUnitUnary bin
  | _, _ -> parseSUnitSrcs bin

let parseCase00 bin =
  match extract bin 11u 10u, extract bin 5u 4u with
  | 0b10u, 0b11u -> parseDUnitSrcsExt bin
  | 0b11u, 0b11u -> parseCase1111 bin
  | _, 0b11u -> parseMUnit bin
  | _, 0b00u -> parseCase0000 bin
  | _, 0b01u -> parseCase0100 bin
  | _, _ (* 0b10u *) -> parseCase1000 bin

let parseLUnit bin =
  match extract bin 31u 28u, extract bin 11u 5u with
  | 0b0001u, _ -> parseLUnitNonCond bin
  | _, 0b0011010u -> parseLUnitUnary bin
  | _ -> parseLUnitSrcs bin

let parseCase10 bin =
  match extract bin 5u 4u with
  | 0b10u -> parseSUnitMVK bin
  | 0b11u | 0b01u -> parseLUnit bin
  | _ (* 0b00u *) -> parseSUnitFieldOps bin

let parseInstruction bin =
  match extract bin 3u 2u with
  | 0b00u -> parseCase00 bin
  | 0b01u -> parseDUnitLSBasic bin
  | 0b10u -> parseCase10 bin
  | _ (* 11u *) -> parseDUnitLSLongImm bin

let parse (reader: BinReader) addr pos =
  let struct (bin, nextPos) = reader.ReadUInt32 pos
  let instrLen = nextPos - pos |> uint32
  let opcode, unit, operands = parseInstruction bin
  let insInfo =
    { Address = addr
      NumBytes = instrLen
      Opcode = opcode
      Operands = operands
      Unit = unit
      OperationSize = 32<rt> // FIXME
      PacketIndex = 0 // FIXME
      EffectiveAddress = 0UL }
  printfn "%A" insInfo
  TMS320C6000Instruction (addr, instrLen, insInfo, WordSize.Bit32)

// vim: set tw=80 sts=2 sw=2:
