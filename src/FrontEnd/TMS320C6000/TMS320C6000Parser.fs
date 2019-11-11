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

/// Table 3-1. Instruction Operation and Execution Notations.
type OperandType =
  /// Double-precision floating-point register value.
  | DP
  /// Signed 32-bit integer value.
  | SInt
  /// Signed 40-bit integer value.
  | SLong
  /// Single-precision floating-point register value that can optionally use
  /// cross path.
  | SP
  /// Double-precision floating-point register value that can optionally use
  /// cross path.
  | XDP
  /// Single-precision floating-point register value that can optionally use
  /// cross path.
  | XSP
  /// 32-bit integer value that can optionally use cross path.
  | XSInt
  /// n-bit signed constant field.
  | SConst
  /// n-bit unsigned constant field (for example, ucst5).
  | UConst

[<Struct>]
type OperandInfo =
  struct
    val OperandValue: uint32
    val OperandType: OperandType
    new (v, t) = { OperandValue = v; OperandType = t }
  end

let private getRegisterA = function
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
  | _ -> Utils.impossible ()

let private getRegisterB = function
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
  | _ -> Utils.impossible ()

let private parseRegister bin isCrossPath = function
  | L1 | S1 | M1 | D1 -> getRegisterA bin
  | L2 | S2 | M2 | D2 -> getRegisterB bin
  | L1X | S1X | M1X ->
    if isCrossPath then getRegisterB bin else getRegisterA bin
  | L2X | S2X | M2X ->
    if isCrossPath then getRegisterA bin else getRegisterB bin
  | _ -> Utils.impossible ()

let private translateOperand unit (oprInfo: OperandInfo) =
  let v = oprInfo.OperandValue
  match oprInfo.OperandType with
  | DP -> (parseRegister (v + 0b1u) false unit, parseRegister v false unit)
          |> RegisterPair
  | SInt -> parseRegister v false unit |> Register
  | SLong ->
    (parseRegister (v + 0b1u) false unit, parseRegister v false unit)
    |> RegisterPair
  | SP -> (parseRegister (v + 0b1u) false unit, parseRegister v false unit)
          |> RegisterPair
  | XDP -> (parseRegister (v + 0b1u) true unit, parseRegister v true unit)
           |> RegisterPair
  | XSInt -> parseRegister v true unit |> Register
  | XSP -> (parseRegister (v + 0b1u) true unit, parseRegister v true unit)
           |> RegisterPair
  | SConst -> uint64 v |> Immediate
  | UConst -> uint64 v |> Immediate

let private parseTwoOprs unit o1 o2 =
  TwoOperands (translateOperand unit o1, translateOperand unit o2)

let private parseThreeOprs unit o1 o2 o3 =
  ThreeOperands (translateOperand unit o1,
                 translateOperand unit o2,
                 translateOperand unit o3)

let private xBit bin = pickBit bin 12u
let private sBit bin = pickBit bin 1u
let private pBit bin = pickBit bin 0u

/// xsint, sint
let parseXSiSi bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, XSInt)
  let o2 = OperandInfo (extract bin 27u 23u, SInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// slong, slong
let parseSlSl bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, SLong)
  let o2 = OperandInfo (extract bin 27u 23u, SLong)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// sint, xsint, sint
let private parseSiXSiSi bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, SInt)
  let o2 = OperandInfo (extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sint, xsint, slong
let private parseSiXSiSl bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, SInt)
  let o2 = OperandInfo (extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (extract bin 27u 23u, SLong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xsint, slong, slong
let private parseXSiSlSl bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, XSInt)
  let o2 = OperandInfo (extract bin 22u 18u, SLong)
  let o3 = OperandInfo (extract bin 27u 23u, SLong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// scst5, xsint, sint
let private parseSc5XSiSi bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, SConst)
  let o2 = OperandInfo (extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// scst5, slong, slong
let private parseSc5SlSl bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, SConst)
  let o2 = OperandInfo (extract bin 22u 18u, SLong)
  let o3 = OperandInfo (extract bin 27u 23u, SLong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sint, sint, sint
let private parseSiSiSi bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, SInt)
  let o2 = OperandInfo (extract bin 17u 13u, SInt)
  let o3 = OperandInfo (extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sint, ucst5, sint
let private parseSiUc5Si bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, SInt)
  let o2 = OperandInfo (extract bin 17u 13u, UConst)
  let o3 = OperandInfo (extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sp, xsp, sp
let parseSpXSpSp bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, SP)
  let o2 = OperandInfo (extract bin 22u 18u, XSP)
  let o3 = OperandInfo (extract bin 27u 23u, SP)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// dp, xdp, dp
let parseDpXDpDp bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, DP)
  let o2 = OperandInfo (extract bin 22u 18u, XDP)
  let o3 = OperandInfo (extract bin 27u 23u, DP)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

let private getDUnit s = if s = 0b0u then D1 else D2

let exchangeToSUnit = function
  | L1 -> S1
  | L2 -> S2
  | L1X -> S1X
  | L2X -> S2X
  | _ -> failwith "Invalid exchange unit"

/// Appendix C-5. Fig. C-1
let private parseDUnitSrcs bin =
  let unit = getDUnit (sBit bin)
  match extract bin 12u 7u with
  | 0b010000u -> parseSiSiSi bin Op.ADD unit
  | 0b010010u -> parseSiUc5Si bin Op.ADD unit
  | _ -> raise InvalidOpcodeException

let private parseDUnitSrcsExt bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseDUnitLSBasic bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseDUnitLSLongImm bin = struct (Op.InvalOP, NoUnit, NoOperand)

let private getLUnit s x =
  match s, x with
  | 0b0u, 0b0u -> L1
  | 0b0u, 0b1u -> L1X
  | 0b1u, 0b0u -> L2
  | _ -> L2X

let private parseLUnitSrcs bin =
  let x, s = xBit bin, sBit bin
  let unit = getLUnit s x
  match extract bin 11u 5u with
  | 0b0000011u -> parseSiXSiSi bin Op.ADD unit
  | 0b0010000u -> parseSpXSpSp bin Op.ADDSP unit
  | 0b0011000u -> parseDpXDpDp bin Op.ADDDP unit
  | 0b0011010u -> parseXSiSi bin Op.ABS unit (* [17:13] - 00000 *)
  | 0b0111000u -> parseSlSl bin Op.ABS unit
  | 0b0100011u -> parseSiXSiSl bin Op.ADD unit
  | 0b0100001u -> parseXSiSlSl bin Op.ADD unit
  | 0b0000010u -> parseSc5XSiSi bin Op.ADD unit
  | 0b0100000u -> parseSc5SlSl bin Op.ADD unit
  | 0b1110000u -> parseSpXSpSp bin Op.ADDSP (exchangeToSUnit unit)
  | 0b1110010u -> parseDpXDpDp bin Op.ADDDP (exchangeToSUnit unit)
  | _ -> raise InvalidOpcodeException

let private parseLUnitNonCond bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseLUnitUnary bin = struct (Op.InvalOP, NoUnit, NoOperand)

let private parseMUnitCompound bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseMUnitNonCond bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseMUnitUnaryExt bin = struct (Op.InvalOP, NoUnit, NoOperand)

let private getSUnit = function
  | 0b0u, 0b0u -> S1
  | 0b0u, 0b1u -> S1X
  | 0b1u, 0b0u -> S2
  | _ (* 0b1u, 0b1u *) -> S2X

let private parseSUnitSrcs bin =
  let unit = (xBit bin, sBit bin) |> getSUnit
  match extract bin 11u 6u with
  | 0b000111u -> parseSiXSiSi bin Op.ADD unit
  | 0b000110u -> parseSc5XSiSi bin Op.ADD unit
  | _ -> raise InvalidOpcodeException

let private parseSUnitSrcsExt bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseSUnitNonCond bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseSUnitUnary bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseSUnitBrImm bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseSUnitUncondImm bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseSUnitBrNOPConst bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseSUnitBrNOPReg bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseSUnitBr bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseSUnitMVK bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseSUnitFieldOps bin = struct (Op.InvalOP, NoUnit, NoOperand)

let private parseNoUnitLoop bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseNoUnitNOPIdle bin = struct (Op.InvalOP, NoUnit, NoOperand)
let private parseNoUnitEmuControl bin = struct (Op.InvalOP, NoUnit, NoOperand)

let private parseCase1111 bin =
  match extract bin 31u 29u with
  | 0b0000u -> parseSUnitNonCond bin
  | _ -> parseSUnitSrcsExt bin

let private parseMUnit bin =
  match extract bin 10u 6u with
  | 0b00011u -> parseMUnitUnaryExt bin
  | _ ->
    match extract bin 31u 28u with
    | 0b0001u -> parseMUnitNonCond bin
    | _ -> parseMUnitCompound bin

let private parseNoUnit bin =
  match extract bin 31u 28u, pickBit bin 17u with
  | 0b0001u, _ -> parseNoUnitNOPIdle bin
  | _, 0b1u -> parseNoUnitLoop bin
  | _, _ (* 0b0u *) -> parseNoUnitEmuControl bin

let private parseCase0000 bin =
  match pickBit bin 6u with
  | 0b0u -> parseNoUnit bin
  | _ -> parseDUnitSrcs bin

let private parseCase0100 bin =
  match extract bin 31u 29u with
  | 0b000u -> parseSUnitUncondImm bin
  | _ -> parseSUnitBrImm bin

let private parseCase1000 bin =
  match extract bin 27u 23u, extract bin 11u 6u with
  | 0b00000u, 0b001101u -> parseSUnitBr bin
  | 0b00001u, 0b001101u -> parseSUnitBrNOPReg bin
  | _, 0b000100u -> parseSUnitBrNOPConst bin
  | _, 0b111100u -> parseSUnitUnary bin
  | _, _ -> parseSUnitSrcs bin

let private parseCase00 bin =
  match extract bin 11u 10u, extract bin 5u 4u with
  | 0b10u, 0b11u -> parseDUnitSrcsExt bin
  | 0b11u, 0b11u -> parseCase1111 bin
  | _, 0b11u -> parseMUnit bin
  | _, 0b00u -> parseCase0000 bin
  | _, 0b01u -> parseCase0100 bin
  | _, _ (* 0b10u *) -> parseCase1000 bin

let private parseLUnit bin =
  match extract bin 31u 28u, extract bin 11u 5u with
  | 0b0001u, _ -> parseLUnitNonCond bin
  | _, 0b0011010u -> parseLUnitUnary bin
  | _ -> parseLUnitSrcs bin

let private parseCase10 bin =
  match extract bin 5u 4u with
  | 0b10u -> parseSUnitMVK bin
  | 0b11u | 0b01u -> parseLUnit bin
  | _ (* 0b00u *) -> parseSUnitFieldOps bin

let private parseInstruction bin =
  match extract bin 3u 2u with
  | 0b00u -> parseCase00 bin
  | 0b01u -> parseDUnitLSBasic bin
  | 0b10u -> parseCase10 bin
  | _ (* 11u *) -> parseDUnitLSLongImm bin

let parse (reader: BinReader) addr pos =
  let struct (bin, nextPos) = reader.ReadUInt32 pos
  let instrLen = nextPos - pos |> uint32
  let struct (opcode, unit, operands) = parseInstruction bin
  let insInfo =
    { Address = addr
      NumBytes = instrLen
      Opcode = opcode
      Operands = operands
      FunctionalUnit = unit
      OperationSize = 32<rt> // FIXME
      IsParallel = pBit bin <> 0u
      EffectiveAddress = 0UL }
  printfn "%A" insInfo
  TMS320C6000Instruction (addr, instrLen, insInfo)

// vim: set tw=80 sts=2 sw=2:
