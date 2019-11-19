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
  /// 32-bit integer value that can optionally use cross path.
  | XSInt
  /// Single-precision floating-point register value that can optionally use
  /// cross path.
  | XSP
  /// Unsigned 32-bit integer value that can optionally use cross path.
  | XUInt
  /// n-bit signed constant field.
  | SConst
  /// n-bit unsigned constant field (for example, ucst5).
  | UConst
  /// Unsigned 32-bit integer value.
  | UInt
  /// Unsigned 40-bit integer value.
  | ULong

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

let private parseReg bin isCrossPath = function
  | L1 | S1 | M1 | D1 -> getRegisterA bin
  | L2 | S2 | M2 | D2 -> getRegisterB bin
  | L1X | S1X | M1X ->
    if isCrossPath then getRegisterB bin else getRegisterA bin
  | L2X | S2X | M2X ->
    if isCrossPath then getRegisterA bin else getRegisterB bin
  | _ -> Utils.impossible ()

let private parseRegBySide bin = function
  | SideA -> getRegisterA bin
  | SideB -> getRegisterB bin

let private parseAddrMode unit offset mode baseR =
  match mode with
  | 0b0000u -> baseR, NegativeOffset, uint64 offset |> UCst5
  | 0b0001u -> baseR, PositiveOffset, uint64 offset |> UCst5
  | 0b0100u -> baseR, NegativeOffset, parseReg offset false unit |> OffsetR
  | 0b0101u -> baseR, PositiveOffset, parseReg offset false unit |> OffsetR
  | 0b1000u -> baseR, PreDecrement, uint64 offset |> UCst5
  | 0b1001u -> baseR, PreIncrement, uint64 offset |> UCst5
  | 0b1010u -> baseR, PostDecrement, uint64 offset |> UCst5
  | 0b1011u -> baseR, PostIncrement, uint64 offset |> UCst5
  | 0b1100u -> baseR, PreDecrement, parseReg offset false unit |> OffsetR
  | 0b1101u -> baseR, PreIncrement, parseReg offset false unit |> OffsetR
  | 0b1110u -> baseR, PostDecrement, parseReg offset false unit |> OffsetR
  | 0b1111u -> baseR, PostIncrement, parseReg offset false unit |> OffsetR
  | _ -> Utils.impossible ()

let private parseMem oprVal unit =
  parseReg (extract oprVal 13u 9u) false unit (* Base register *)
  |> parseAddrMode unit (extract oprVal 8u 4u) (extract oprVal 3u 0u)
  |> OprMem

let private assertEvenNumber v =
#if DEBUG
  if v &&& 1u <> 0u then raise InvalidOperandException else ()
#endif
  ()

let getSide sBit = if sBit = 0b0u then SideA else SideB

let private xBit bin = pickBit bin 12u
let private yBit bin = pickBit bin 8u
let private sBit bin = pickBit bin 1u
let private pBit bin = pickBit bin 0u

let private parseRegPair v unit isCPath =
  let high, low = if v &&& 0b1u = 0b0u then v + 1u, v else v, v - 1u
  (parseReg high isCPath unit, parseReg low isCPath unit) |> RegisterPair

let private translateOperand unit (oprInfo: OperandInfo) =
  let v = oprInfo.OperandValue
  match oprInfo.OperandType with
  | DP -> parseRegPair v unit false
  | SInt -> parseReg v false unit |> Register
  | SLong -> parseRegPair v unit false
  | SP -> parseReg v false unit |> Register
  | XDP -> parseRegPair v unit true
  | XSInt -> parseReg v true unit |> Register
  | XSP -> parseReg v true unit |> Register
  | XUInt -> parseReg v true unit |> Register
  | SConst -> uint64 v |> Immediate
  | UConst -> uint64 v |> Immediate
  | UInt -> parseReg v false unit |> Register
  | ULong -> parseRegPair v unit false

let private parseOneOpr unit o = OneOperand (translateOperand unit o)

let private parseTwoOprs unit o1 o2 =
  TwoOperands (translateOperand unit o1, translateOperand unit o2)

let private parseThreeOprs unit o1 o2 o3 =
  ThreeOperands (translateOperand unit o1,
                 translateOperand unit o2,
                 translateOperand unit o3)

let private parseFourOprs unit o1 o2 o3 o4 =
  FourOperands (translateOperand unit o1,
                translateOperand unit o2,
                translateOperand unit o3,
                translateOperand unit o4)

/// scst21
let private parseSc21 bin opcode unit =
  let o = OperandInfo (extract bin 27u 7u, SConst)
  struct (opcode, unit, parseOneOpr unit o)

/// xuint
let private parseXUi bin opcode unit =
  let o = OperandInfo (extract bin 22u 18u, XUInt)
  struct (opcode, unit, parseOneOpr unit o)

/// xsint, sint
let private parseXSiSi bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, XSInt)
  let o2 = OperandInfo (extract bin 27u 23u, SInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// slong, slong
let private parseSlSl bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, SLong)
  let o2 = OperandInfo (extract bin 27u 23u, SLong)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// dp, dp
let private parseDpDp bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, DP)
  let o2 = OperandInfo (extract bin 27u 23u, DP)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xsp, sp
let private parseXSpSp bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, XSP)
  let o2 = OperandInfo (extract bin 27u 23u, SP)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// scst16, uint
let private parseSc16Ui bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 7u, SConst)
  let o2 = OperandInfo (extract bin 27u 23u, UInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// dp, sint
let private parseDpSi bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, DP)
  let o2 = OperandInfo (extract bin 27u 23u, SInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// dp, sp
let private parseDpSp bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, DP)
  let o2 = OperandInfo (extract bin 27u 23u, SP)
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

/// uint, xuint, ulong
let parseUiXUiUl bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, UInt)
  let o2 = OperandInfo (extract bin 22u 18u, XUInt)
  let o3 = OperandInfo (extract bin 27u 23u, ULong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xuint, ulong, ulong
let parseXUiUlUl bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, XUInt)
  let o2 = OperandInfo (extract bin 22u 18u, ULong)
  let o3 = OperandInfo (extract bin 27u 23u, ULong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// uint, xuint, uint
let parseUiXUiUi bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, UInt)
  let o2 = OperandInfo (extract bin 22u 18u, XUInt)
  let o3 = OperandInfo (extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// scst5, xuint, uint
let parseSc5XUiUi bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, SConst)
  let o2 = OperandInfo (extract bin 22u 18u, XUInt)
  let o3 = OperandInfo (extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xuint, uint, uint
let parseXUiUiUi bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, XUInt)
  let o2 = OperandInfo (extract bin 17u 13u, UInt)
  let o3 = OperandInfo (extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sint, xsint, uint
let parseSiXSiUi bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, SInt)
  let o2 = OperandInfo (extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// scst5, xsint, uint
let parseSc5XSiUi bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, SConst)
  let o2 = OperandInfo (extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xsint, slong, uint
let parseXSiSlUi bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, XSInt)
  let o2 = OperandInfo (extract bin 22u 18u, SLong)
  let o3 = OperandInfo (extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// scst5, slong, uint
let parseSc5SlUi bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, SConst)
  let o2 = OperandInfo (extract bin 22u 18u, SLong)
  let o3 = OperandInfo (extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// dp, xdp, sint
let parseDpXDpSi bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, DP)
  let o2 = OperandInfo (extract bin 22u 18u, XDP)
  let o3 = OperandInfo (extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sp, xsp, sint
let parseSpXSpSi bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, SP)
  let o2 = OperandInfo (extract bin 22u 18u, XSP)
  let o3 = OperandInfo (extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// ucst4, xuint, uint
let parseUc4XUiUi bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, UConst)
  let o2 = OperandInfo (extract bin 22u 18u, XUInt)
  let o3 = OperandInfo (extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xuint, ulong, uint
let parseXUiUlUi bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, XUInt)
  let o2 = OperandInfo (extract bin 22u 18u, ULong)
  let o3 = OperandInfo (extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// ucst4, ulong, uint
let parseUc4UlUi bin opcode unit =
  let o1 = OperandInfo (extract bin 17u 13u, UConst)
  let o2 = OperandInfo (extract bin 22u 18u, ULong)
  let o3 = OperandInfo (extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xsint, uint, sint
let parseXSiUiSi bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, XSInt)
  let o2 = OperandInfo (extract bin 17u 13u, UInt)
  let o3 = OperandInfo (extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// unit, ucst5, ucst5, uint
let parseUiUc5Uc5Ui bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, UInt)
  let o2 = OperandInfo (extract bin 17u 13u, UConst)
  let o3 = OperandInfo (extract bin 12u 8u, UConst)
  let o4 = OperandInfo (extract bin 27u 23u, UInt)
  struct (opcode, unit, parseFourOprs unit o1 o2 o3 o4)

/// snit, ucst5, ucst5, sint
let parseSiUc5Uc5Si bin opcode unit =
  let o1 = OperandInfo (extract bin 22u 18u, SInt)
  let o2 = OperandInfo (extract bin 17u 13u, UConst)
  let o3 = OperandInfo (extract bin 12u 8u, UConst)
  let o4 = OperandInfo (extract bin 27u 23u, SInt)
  struct (opcode, unit, parseFourOprs unit o1 o2 o3 o4)

/// mem, reg
let parseMemReg bin opcode unit =
  let mem = parseMem (extract bin 22u 9u) unit
  let reg =
    parseRegBySide (extract bin 27u 23u) (getSide (sBit bin)) |> Register
  struct (opcode, unit, TwoOperands (mem, reg))

/// mem, regPair
let parseMemRegPair bin opcode unit =
  let mem = parseMem (extract bin 22u 9u) unit
  let v = extract bin 27u 23u
  let regPair =
    assertEvenNumber v
    let side = getSide (sBit bin)
    (parseRegBySide (v + 0b1u) side, parseRegBySide v side) |> RegisterPair
  struct (opcode, unit, TwoOperands (mem, regPair))

let private getDUnit bit = if bit = 0b0u then D1 else D2

/// Appendix C-5. Fig. C-1
let private parseDUnitSrcs bin =
  let unit = getDUnit (sBit bin)
  match extract bin 12u 7u with
  | 0b010000u -> parseSiSiSi bin Op.ADD unit
  | 0b010010u -> parseSiUc5Si bin Op.ADD unit
  | 0b110000u -> parseSiSiSi bin Op.ADDAB unit
  | 0b110010u -> parseSiUc5Si bin Op.ADDAB unit
  | 0b110100u -> parseSiSiSi bin Op.ADDAH unit
  | 0b110110u -> parseSiUc5Si bin Op.ADDAH unit
  | 0b111000u -> parseSiSiSi bin Op.ADDAW unit
  | 0b111010u -> parseSiUc5Si bin Op.ADDAW unit
  | 0b111100u -> parseSiSiSi bin Op.ADDAD unit
  | 0b111101u -> parseSiUc5Si bin Op.ADDAD unit
  | _ -> raise InvalidOpcodeException

/// Appendix C-5. Fig. C-2
let private parseDUnitSrcsExt bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix C-5. Fig. C-3
let private parseDUnitLSBasic bin =
  let unit = getDUnit (yBit bin)
  match pickBit bin 8u, extract bin 6u 4u with
  | 0b0u, 0b001u -> parseMemReg bin Op.LDBU unit
  | 0b0u, 0b010u -> parseMemReg bin Op.LDB unit
  | 0b0u, 0b110u -> parseMemReg bin Op.LDW unit
  | 0b1u, 0b110u -> parseMemRegPair bin Op.LDDW unit
  | _ -> raise InvalidOpcodeException

/// Appendix C-5. Fig. C-4
let private parseDUnitLSLongImm bin = struct (Op.InvalOP, NoUnit, NoOperand)

let private getLUnit s x =
  match s, x with
  | 0b0u, 0b0u -> L1
  | 0b0u, 0b1u -> L1X
  | 0b1u, 0b0u -> L2
  | _ -> L2X

let private getSUnit s x =
  match s, x with
  | 0b0u, 0b0u -> S1
  | 0b0u, 0b1u -> S1X
  | 0b1u, 0b0u -> S2
  | _ (* 0b1u, 0b1u *) -> S2X

/// Appendix D-4. Fig. D-1
let private parseLUnitSrcs bin =
  let x, s = xBit bin, sBit bin
  match extract bin 11u 5u with
  | 0b0000001u -> parseDpSi bin Op.DPTRUNC (getLUnit s x)
  | 0b0000011u -> parseSiXSiSi bin Op.ADD (getLUnit s x)
  | 0b0000010u -> parseSc5XSiSi bin Op.ADD (getLUnit s x)
  | 0b0001000u -> parseDpSi bin Op.DPINT (getLUnit s x)
  | 0b0001001u -> parseDpSp bin Op.DPSP (getLUnit s x)
  | 0b0010000u -> parseSpXSpSp bin Op.ADDSP (getLUnit s x)
  | 0b0011000u -> parseDpXDpDp bin Op.ADDDP (getLUnit s x)
  | 0b0011010u -> parseXSiSi bin Op.ABS (getLUnit s x)
  | 0b0100000u -> parseSc5SlSl bin Op.ADD (getLUnit s x)
  | 0b0100001u -> parseXSiSlSl bin Op.ADD (getLUnit s x)
  | 0b0100011u -> parseSiXSiSl bin Op.ADD (getLUnit s x)
  | 0b0101001u -> parseXUiUlUl bin Op.ADDU (getLUnit s x)
  | 0b0101011u -> parseUiXUiUl bin Op.ADDU (getLUnit s x)
  | 0b0111000u -> parseSlSl bin Op.ABS (getLUnit s x)
  | 0b1000100u -> parseSc5SlUi bin Op.CMPGT (getLUnit s x)
  | 0b1000101u -> parseXSiSlUi bin Op.CMPGT (getLUnit s x)
  | 0b1000110u -> parseSc5XSiUi bin Op.CMPGT (getLUnit s x)
  | 0b1000111u -> parseSiXSiUi bin Op.CMPGT (getLUnit s x)
  | 0b1001100u -> parseUc4UlUi bin Op.CMPGTU (getLUnit s x)
  | 0b1001101u -> parseXUiUlUi bin Op.CMPGTU (getLUnit s x)
  | 0b1001110u -> parseUc4XUiUi bin Op.CMPGTU (getLUnit s x)
  | 0b1001111u -> parseUiXUiUi bin Op.CMPGTU (getLUnit s x)
  | 0b1010000u -> parseSc5SlUi bin Op.CMPEQ (getLUnit s x)
  | 0b1010001u -> parseXSiSlUi bin Op.CMPEQ (getLUnit s x)
  | 0b1010010u -> parseSc5XSiUi bin Op.CMPEQ (getLUnit s x)
  | 0b1010011u -> parseSiXSiUi bin Op.CMPEQ (getLUnit s x)
  | 0b1010100u -> parseSc5SlUi bin Op.CMPLT (getLUnit s x)
  | 0b1010101u -> parseXSiSlUi bin Op.CMPLT (getLUnit s x)
  | 0b1010110u -> parseSc5XSiUi bin Op.CMPLT (getLUnit s x)
  | 0b1010111u -> parseSiXSiUi bin Op.CMPLT (getLUnit s x)
  | 0b1011100u -> parseUc4UlUi bin Op.CMPGTU (getLUnit s x)
  | 0b1011101u -> parseXUiUlUi bin Op.CMPGTU (getLUnit s x)
  | 0b1011110u -> parseUc4XUiUi bin Op.CMPGTU (getLUnit s x)
  | 0b1011111u -> parseUiXUiUi bin Op.CMPGTU (getLUnit s x)
  | 0b1110000u -> parseSpXSpSp bin Op.ADDSP (getSUnit s x)
  | 0b1110010u -> parseDpXDpDp bin Op.ADDDP (getSUnit s x)
  | 0b1111010u -> parseSc5XUiUi bin Op.AND (getLUnit s x)
  | 0b1111011u -> parseUiXUiUi bin Op.AND (getLUnit s x)
  | _ -> raise InvalidOpcodeException

/// Appendix D-4. Fig. D-2
let private parseLUnitNonCond bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix D-4. Fig. D-3
let private parseLUnitUnary bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix E-4. Fig. E-1
let private parseMUnitCompound bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix E-4. Fig. E-2
let private parseMUnitNonCond bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix E-4. Fig. E-3
let private parseMUnitUnaryExt bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix F-4. Fig. F-1
let private parseSUnitSrcs bin =
  let unit = getSUnit (sBit bin) (xBit bin)
  match extract bin 11u 6u with
  | 0b000001u -> parseSiXSiSi bin Op.ADD2 unit
  | 0b000111u -> parseSiXSiSi bin Op.ADD unit
  | 0b000110u -> parseSc5XSiSi bin Op.ADD unit
  | 0b101000u -> parseDpXDpSi bin Op.CMPEQDP unit
  | 0b101001u -> parseDpXDpSi bin Op.CMPGTDP unit
  | 0b101010u -> parseDpXDpSi bin Op.CMPLTDP unit
  | 0b101011u -> parseXUiUiUi bin Op.EXTU unit
  | 0b101100u -> parseDpDp bin Op.ABSDP unit
  | 0b101111u -> parseXSiUiSi bin Op.EXT unit
  | 0b111000u -> parseSpXSpSi bin Op.CMPEQSP unit
  | 0b111001u -> parseSpXSpSi bin Op.CMPGTSP unit
  | 0b111010u -> parseSpXSpSi bin Op.CMPLTSP unit
  | 0b111111u -> parseXUiUiUi bin Op.CLR unit // FIXME: Manual(111011)
  | _ -> raise InvalidOpcodeException

/// Appendix F-4. Fig. F-2
let private parseSUnitSrcsExt bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix F-4. Fig. F-3
let private parseSUnitNonCond bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix F-4. Fig. F-4
let private parseSUnitUnary bin =
  let unit = getSUnit (sBit bin) (xBit bin)
  match extract bin 17u 13u with
  | 0b00000u -> parseXSpSp bin Op.ABSSP unit
  | _ -> raise InvalidOpcodeException

/// Appendix F-4. Fig. F-5
let private parseSUnitBrImm bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix F-5. Fig. F-6
let private parseSUnitUncondImm bin =
  parseSc21 bin Op.B (getSUnit (sBit bin) 0u) // FIXME: label

/// Appendix F-5. Fig. F-7
let private parseSUnitBrNOPConst bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix F-5. Fig. F-8
let private parseSUnitBrNOPReg bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix F-5. Fig. F-9
let private parseSUnitBr bin =
  parseXUi bin Op.B (getSUnit (sBit bin) (xBit bin))

/// Appendix F-5. Fig. F-10
let private parseSUnitMVK bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix F-5. Fig. F-11
let private parseSUnitFieldOps bin =
  match extract bin 7u 6u with
  | 0b00u -> parseUiUc5Uc5Ui bin Op.EXTU (getSUnit (sBit bin) 0u)
  | 0b01u -> parseSiUc5Uc5Si bin Op.EXT (getSUnit (sBit bin) 0u)
  | 0b10u -> parseUiUc5Uc5Ui bin Op.CLR (getSUnit (sBit bin) 0u)
  | _ -> raise InvalidOpcodeException

let private parseSUnitADDK bin = (* Additional format *)
  parseSc16Ui bin Op.ADDK (getSUnit (sBit bin) 0u)

/// Appendix G-3. Fig. G-1
let private parseNoUnitLoop bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix G-3. Fig. G-2
let private parseNoUnitNOPIdle bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix G-3. Fig. G-3
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
  match extract bin 31u 29u, pickBit bin 6u with
  | 0b000u, 0u -> parseSUnitUncondImm bin
  | _, 0u -> parseSUnitBrImm bin
  | _, _ (* 0b1u *) -> parseSUnitADDK bin

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

let parse (reader: BinReader) (ctxt: ParsingContext) addr pos =
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
      IsParallel = ctxt.InParallel
      EffectiveAddress = 0UL }
  ctxt.InParallel <- pBit bin <> 0u (* Update the parallel exec information *)
  printfn "%A" insInfo
  TMS320C6000Instruction (addr, instrLen, insInfo)

// vim: set tw=80 sts=2 sw=2:
