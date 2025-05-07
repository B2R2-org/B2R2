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

module internal B2R2.FrontEnd.TMS320C6000.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils

/// Table 3-1. Instruction Operation and Execution Notations.
type OperandType =
  /// Register B14 or B15.
  | B14B15
  /// Bit vector of two flags for s2 or u2 data type.
  | BVec2
  /// Bit vector of four flags for s4 or u4 data type.
  | BVec4
  /// n-bit constant field (for example, cst5).
  | Const
  /// 64-bit integer value (two registers).
  | DInt
  /// Double-precision floating-point register value.
  | DP
  /// Two packed signed 16-bit integers in a single 64-bit register pair.
  | DS2
  /// Unsigned 64-bit integer value (two registers).
  | DUInt
  /// Four packed signed 16-bit integers in a 64-bit register pair.
  | DWS4
  /// Four packed unsigned 16-bit integers in a 64-bit register pair.
  | DWU4
  /// Two packed 16-bit integers in a single 32-bit register.
  | I2
  /// Four packed 8-bit integers in a single 32-bit register.
  | I4
  /// 32-bit integer value.
  | Int
  /// Two packed signed 16-bit integers in a single 32-bit register.
  | S2
  /// Four packed signed 8-bit integers in a single 32-bit register.
  | S4
  /// n-bit signed constant field.
  | SConst
  /// Signed 64-bit integer value (two registers).
  | SDInt
  /// Signed 32-bit integer value.
  | SInt
  /// Signed 64-bit integer value.
  | SLLong
  /// Signed 40-bit integer value.
  | SLong
  /// Signed 16-bit integer value in lower half of 32-bit register.
  | SLsb16
  /// Signed 16-bit integer value in upper half of 32-bit register.
  | SMsb16
  /// Single-precision floating-point register value that can optionally use
  /// cross path.
  | SP
  /// Two packed unsigned 16-bit integers in a single 32-bit register.
  | U2
  /// Four packed unsigned 8-bit integers in a single 32-bit register.
  | U4
  /// n-bit unsigned constant field (for example, ucst5).
  | UConst
  /// Unsigned 32-bit integer value.
  | UInt
  /// Unsigned 64-bit integer value.
  | ULLong
  /// Unsigned 40-bit integer value.
  | ULong
  /// Unsigned 16-bit integer value in lower half of 32-bit register.
  | ULsb16
  /// Unsigned 16-bit integer value in upper half of 32-bit register.
  | UMsb16
  /// Double-precision floating-point register value that can optionally use
  /// cross path.
  | XDP
  /// Two packed 16-bit integers in a single 32-bit register that can optionally
  /// use cross path.
  | XI2
  /// Four packed 8-bit integers in a single 32-bit register that can optionally
  /// use cross path.
  | XI4
  /// 32-bit integer value that can optionally use cross path.
  | XInt
  /// Two packed signed 16-bit integers in a single 32-bit register that can
  /// optionally use cross path.
  | XS2
  /// Four packed signed 8-bit integers in a single 32-bit register that can
  /// optionally use cross path.
  | XS4
  /// Signed 32-bit integer value that can optionally use cross path.
  | XSInt
  /// Signed 16 LSB of register that can optionally use cross path.
  | XSLsb16
  /// Signed 16 MSB of register that can optionally use cross path.
  | XSMsb16
  /// Single-precision floating-point register value that can optionally use
  /// cross path.
  | XSP
  /// Two packed unsigned 16-bit integers in a single 32-bit register that can
  /// optionally use cross path.
  | XU2
  /// Four packed unsigned 8-bit integers in a single 32-bit register that can
  /// optionally use cross path.
  | XU4
  /// Unsigned 32-bit integer value that can optionally use cross path.
  | XUInt
  /// Unsigned 16 LSB of register that can optionally use cross path.
  | XULsb16
  /// Unsigned 16 MSB of register that can optionally use cross path.
  | XUMsb16

type MemoryOpOrder =
  | RegMem
  | MemReg

let buildMemOperand reg mem = function
  | RegMem -> TwoOperands (reg, mem)
  | MemReg -> TwoOperands (mem, reg)

[<Struct>]
type OperandInfo =
  struct
    val OperandValue: uint32
    val OperandType: OperandType
    new (v, t) = { OperandValue = v; OperandType = t }
  end

let private getRegisterA = function
  | 0b00000u -> Register.A0
  | 0b00001u -> Register.A1
  | 0b00010u -> Register.A2
  | 0b00011u -> Register.A3
  | 0b00100u -> Register.A4
  | 0b00101u -> Register.A5
  | 0b00110u -> Register.A6
  | 0b00111u -> Register.A7
  | 0b01000u -> Register.A8
  | 0b01001u -> Register.A9
  | 0b01010u -> Register.A10
  | 0b01011u -> Register.A11
  | 0b01100u -> Register.A12
  | 0b01101u -> Register.A13
  | 0b01110u -> Register.A14
  | 0b01111u -> Register.A15
  | 0b10000u -> Register.A16
  | 0b10001u -> Register.A17
  | 0b10010u -> Register.A18
  | 0b10011u -> Register.A19
  | 0b10100u -> Register.A20
  | 0b10101u -> Register.A21
  | 0b10110u -> Register.A22
  | 0b10111u -> Register.A23
  | 0b11000u -> Register.A24
  | 0b11001u -> Register.A25
  | 0b11010u -> Register.A26
  | 0b11011u -> Register.A27
  | 0b11100u -> Register.A28
  | 0b11101u -> Register.A29
  | 0b11110u -> Register.A30
  | 0b11111u -> Register.A31
  | _ -> Terminator.impossible ()

let private getRegisterB = function
  | 0b00000u -> Register.B0
  | 0b00001u -> Register.B1
  | 0b00010u -> Register.B2
  | 0b00011u -> Register.B3
  | 0b00100u -> Register.B4
  | 0b00101u -> Register.B5
  | 0b00110u -> Register.B6
  | 0b00111u -> Register.B7
  | 0b01000u -> Register.B8
  | 0b01001u -> Register.B9
  | 0b01010u -> Register.B10
  | 0b01011u -> Register.B11
  | 0b01100u -> Register.B12
  | 0b01101u -> Register.B13
  | 0b01110u -> Register.B14
  | 0b01111u -> Register.B15
  | 0b10000u -> Register.B16
  | 0b10001u -> Register.B17
  | 0b10010u -> Register.B18
  | 0b10011u -> Register.B19
  | 0b10100u -> Register.B20
  | 0b10101u -> Register.B21
  | 0b10110u -> Register.B22
  | 0b10111u -> Register.B23
  | 0b11000u -> Register.B24
  | 0b11001u -> Register.B25
  | 0b11010u -> Register.B26
  | 0b11011u -> Register.B27
  | 0b11100u -> Register.B28
  | 0b11101u -> Register.B29
  | 0b11110u -> Register.B30
  | 0b11111u -> Register.B31
  | _ -> Terminator.impossible ()

let private parseReg bin isCrossPath = function
  | L1Unit | S1Unit | M1Unit | D1Unit -> getRegisterA bin
  | L2Unit | S2Unit | M2Unit | D2Unit -> getRegisterB bin
  | L1XUnit | S1XUnit | M1XUnit | D1XUnit ->
    if isCrossPath then getRegisterB bin else getRegisterA bin
  | L2XUnit | S2XUnit | M2XUnit | D2XUnit ->
    if isCrossPath then getRegisterA bin else getRegisterB bin
  | _ -> Terminator.impossible ()

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
  | _ -> Terminator.impossible ()

let private parseMem oprVal unit =
  parseReg (Bits.extract oprVal 13u 9u) false unit (* Base register *)
  |> parseAddrMode unit (Bits.extract oprVal 8u 4u) (Bits.extract oprVal 3u 0u)
  |> OprMem

let private assertEvenNumber v =
#if DEBUG
  if v &&& 1u <> 0u then raise InvalidOperandException else ()
#endif
  ()

let getSide sBit = if sBit = 0b0u then SideA else SideB

let private xBit bin = Bits.pick bin 12u
let private yBit bin = Bits.pick bin 7u
let private sBit bin = Bits.pick bin 1u
let private pBit bin = Bits.pick bin 0u

let private isSrc1Zero bin = Bits.extract bin 17u 13u = 0u
let private isSrc111111 bin = Bits.extract bin 17u 13u = 0b11111u
let private isSrc100010 bin = Bits.extract bin 17u 13u = 0b000010u
let private isEqualSrc1Src2 bin =
  xBit bin = 0u && Bits.extract bin 22u 18u = Bits.extract bin 17u 13u

let private parseRegPair v unit isCPath =
  let high, low = if v &&& 0b1u = 0b0u then v + 1u, v else v, v - 1u
  (parseReg high isCPath unit, parseReg low isCPath unit) |> RegisterPair

let getB14orB15 value =
  if value = 0b0u then Register.B14 else Register.B15

let private translateOperand unit (oprInfo: OperandInfo) =
  let v = oprInfo.OperandValue
  match oprInfo.OperandType with
  | B14B15 -> getB14orB15 v |> OpReg
  | BVec2 | BVec4 | I2 | I4 | Int | S2 | S4 | SInt | SLsb16 | SMsb16 | SP | U2
  | U4 | UInt | ULsb16 | UMsb16 -> parseReg v false unit |> OpReg
  | Const | SConst | UConst -> uint64 v |> Immediate
  | DInt | DP | DS2 | DUInt | DWS4 | DWU4 | SDInt | SLLong | SLong | ULLong
  | ULong -> parseRegPair v unit false
  | XDP -> parseRegPair v unit true
  | XI2 | XI4 | XInt | XS2 | XS4 | XSInt | XSLsb16 | XSMsb16 | XSP | XU2 | XU4
  | XUInt | XULsb16 | XUMsb16 -> parseReg v true unit |> OpReg

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
  let o = OperandInfo (Bits.extract bin 27u 7u, SConst)
  struct (opcode, unit, parseOneOpr unit o)

/// xuint
let private parseXUi bin opcode unit =
  let o = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  struct (opcode, unit, parseOneOpr unit o)

/// ucst4 (NOP)
let private parseUc4 bin opcode unit =
  let o = OperandInfo (Bits.extract bin 16u 13u + 1u, UConst)
  struct (opcode, unit, parseOneOpr unit o)

/// slong
let private parseSl bin opcode unit =
  let o = OperandInfo (Bits.extract bin 27u 23u, SLong)
  struct (opcode, unit, parseOneOpr unit o)

/// sint
let private parseSi bin opcode unit =
  let o = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseOneOpr unit o)

/// xsint, sint
let private parseXSiSi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// slong, slong
let private parseSlSl bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, SLong)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SLong)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// dp, dp
let private parseXDpDp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XDP)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, DP)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xsp, sp
let private parseXSpSp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XSP)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SP)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// scst16, uint
let private parseSc16Ui bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 7u, SConst)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// dp, sint
let private parseDpSi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, DP)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// dp, sp
let private parseDpSp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, DP)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SP)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xsint, dp
let private parseXSiDp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, DP)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xuint, dp
let private parseXUiDp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, DP)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xsint, sp
let private parseXSiSp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SP)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xuint, sp
let private parseXUiSp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SP)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xs2, s2
let private parseXs2S2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XS2)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, S2)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// scst10, int
let private parseSc10Int bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 13u, SConst)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, Int)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xu4, u4
let private parseXU4U4 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XU4)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, U4)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xuint, uint
let private parseXUiUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// scst12, ucst3
let private parseSc12Uc3 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 27u 16u, SConst)
  let o2 = OperandInfo (Bits.extract bin 15u 13u, UConst)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xuint, ucst3
let private parseXUiUc3 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o2 = OperandInfo (Bits.extract bin 15u 13u, UConst)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// sint, sint
let private parseSiSi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, SInt)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xint, int
let private parseXiInt bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XInt)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, Int)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// scst16, sint
let private parseSc16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 7u, SConst)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// scst5 (22-18), sint
let private parseSc5Si1 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, SConst)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// scst5 (17-13), sint
let private parseSc5Si2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SConst)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xsint, uint
let private parseXSiUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// slong, uint
let private parseSlUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, SLong)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// dp, dp
let private parseDpDp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, DP)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, DP)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// slong, sint
let private parseSlSi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, SLong)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xsp, dp
let private parseXSpDp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XSP)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, DP)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xsp, sint
let private parseXSpSi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XSP)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// xu4, u2
let private parseXU4U2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XU4)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, U2)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// s2, s2
let private parseS2S2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, S2)
  let o2 = OperandInfo (Bits.extract bin 27u 23u, S2)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// uscst16, sint
let private parseUSc16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 7u, UConst) // FIXME
  let o2 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseTwoOprs unit o1 o2)

/// sint, xsint, sint
let private parseSiXSiSi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sint, xsint, slong
let private parseSiXSiSl bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SLong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xsint, slong, slong
let private parseXSiSlSl bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, XSInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, SLong)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SLong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// scst5, xsint, sint
let private parseSc5XSiSi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SConst)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// scst5, slong, slong
let private parseSc5SlSl bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SConst)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, SLong)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SLong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sint, sint, sint
let private parseSiSiSi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, SInt)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, SInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sint, ucst5, sint
let private parseSiUc5Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, SInt)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UConst)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sp, xsp, sp
let parseSpXSpSp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SP)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSP)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SP)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// dp, xdp, dp
let parseDpXDpDp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, DP)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XDP)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DP)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// uint, xuint, ulong
let parseUiXUiUl bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, UInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, ULong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xuint, ulong, ulong
let parseXUiUlUl bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, XUInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, ULong)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, ULong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// uint, xuint, uint
let parseUiXUiUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, UInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// scst5, xuint, uint
let parseSc5XUiUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SConst)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xuint, uint, uint
let parseXUiUiUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sint, xsint, uint
let parseSiXSiUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// scst5, xsint, uint
let parseSc5XSiUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SConst)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xsint, slong, uint
let parseXSiSlUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, XSInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, SLong)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// scst5, slong, uint
let parseSc5SlUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SConst)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, SLong)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// dp, xdp, sint
let parseDpXDpSi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, DP)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XDP)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sp, xsp, sint
let parseSpXSpSi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SP)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSP)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// ucst4, xuint, uint
let parseUc4XUiUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, UConst)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xuint, ulong, uint
let parseXUiUlUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, XUInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, ULong)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// ucst4, ulong, uint
let parseUc4UlUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, UConst)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, ULong)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xsint, uint, sint
let parseXSiUiSi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// cst5, xuint, uint
let parseC5XUiUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, Const)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// slsb16, xslsb16, sint
let parseSlsb16XSlsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SLsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSLsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// scst5, xslsb16, sint
let parseSc5XSlsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SConst)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSLsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// scst7, ucst3, uint
let parseSc7Uc3Ui bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 16u, SConst)
  let o2 = OperandInfo (Bits.extract bin 15u 13u, UConst)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sint, xsint, dint
let parseSiXSiDi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// i4, xi4, i4
let parseI4Xi4I4 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, I4)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XI4)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, I4)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// B14/B15, ucst15, sint
let parseB14B15Uc15Si bin opcode unit =
  let o1 = OperandInfo (Bits.pick bin 7u, B14B15)
  let o2 = OperandInfo (Bits.extract bin 22u 8u, UConst)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// i2, xi2, i2
let parseI2Xi2I2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, I2)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XI2)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, I2)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// s2, xs2, s2
let parseS2XS2S2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, S2)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XS2)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, S2)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// u4, xu4, u4
let parseU4XU4U4 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, U4)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XU4)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, U4)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// s2, xs2, bv2
let parseS2XS2Bv2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, S2)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XS2)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, BVec2)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// s4, xs4, bv4
let parseS4XS4Bv4 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, S4)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XS4)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, BVec4)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// u4, xu4, bv4
let parseU4XU4Bv4 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, U4)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XU4)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, BVec4)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// s2, xs2, dint
let parseS2XS2Di bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, S2)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XS2)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// s2, xs4, dint
let parseS2XS4Di bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, S2)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XS4)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// ds2, xs2, dint
let parseDS2XS2Di bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, DS2)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XS2)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// ds2, xs2, s2
let parseDS2XS2S2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, DS2)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XS2)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, S2)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// s2, xs2, int
let parseS2XS2Int bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, S2)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XS2)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, Int)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// s2, xs2, sllong
let parseS2XS2Sll bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, S2)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XS2)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SLLong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// s2, xu2, int
let parseS2XU2Int bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, S2)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XU2)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, Int)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// s4, xu4, int
let parseS4XU4Int bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, S4)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XU4)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, Int)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// u4, xu4, uint
let parseU4XU4Ui bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, U4)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XU4)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// uint, uint, uint
let parseUiUiUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, UInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, UInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// smsb16, xsmsb16, sint
let parseSmsb16XSmsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SMsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSMsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// int, xint, sllong
let parseIntXiSll bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, Int)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SLLong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// int, xint, int
let parseIntXiInt bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, Int)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, Int)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// smsb16, xslsb16, sint
let parseSmsb16XSlsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SMsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSLsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// umsb16, xulsb16, uint
let parseUmsb16XUlsb16Ui bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, UMsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XULsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// smsb16, xulsb16, sint
let parseSmsb16XUlsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SMsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XULsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// smsb16, xumsb16, sint
let parseSmsb16XUmsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SMsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XUMsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// umsb16, xumsb16, uint
let parseUmsb16XUmsb16Ui bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, UMsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XUMsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// umsb16, xslsb16, sint
let parseUmsb16XSlsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, UMsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSLsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// umsb16, xsmsb16, sint
let parseUmsb16XSmsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, UMsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSMsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// cst5, xsint, sint
let parseC5XSiSi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, Const)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sint, xsint, sdint
let parseSiXSiSDi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SDInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// cst5, xsint, sdint
let parseC5XSiSDi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, Const)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SDInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// slsb16, xsmsb16, sint
let parseSlsb16XSmsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SLsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSMsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// ulsb16, xumsb16, uint
let parseUlsb16XUmsb16Ui bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, ULsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XUMsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// slsb16, xumsb16, sint
let parseSlsb16XUmsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SLsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XUMsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// ulsb16, xsmsb16, sint
let parseUlsb16XSmsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, ULsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSMsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sp, xdp, dp
let parseSpXDpDp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SP)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XDP)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DP)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sp, xsp, dp
let parseSpXSpDp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SP)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSP)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DP)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// slsb16, xulsb16, sint
let parseSlsb16XUlsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SLsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XULsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// scst5, xulsb16, sint
let parseSc5XUlsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SConst)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XULsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// s4, xu4, dws4
let parseS4XU4DWS4 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, S4)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XU4)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DWS4)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// ulsb16, xulsb16, uint
let parseUlsb16XUlsb16Ui bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, ULsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XULsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// u4, xu4, dwu4
let parseU4XU4DWU4 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, U4)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XU4)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DWU4)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// ulsb16, xslsb16, sint
let parseUlsb16XSlsb16Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, ULsb16)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSLsb16)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// s2, xs2, ullong
let parseS2XS2Ull bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, S2)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XS2)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, ULLong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// int, xint, dint
let parseIntXiDi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, Int)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// int, xuint, dint
let parseIntXUiDi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, Int)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// uint, xuint, duint
let parseUiXUiDUi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, UInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DUInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// uint, xint, dint
let parseUiXiDi bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, UInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xuint, ucst5, uint
let parseXUiUc5Ui bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UConst)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// sint, xsint, s2
let parseSiXSiS2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, SInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, S2)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// u2, xs2, u2
let parseU2XS2U2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, U2)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XS2)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, U2)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// slong, uint, slong
let parseSlUiSl bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, SLong)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SLong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xuint, uint, ulong
let parseXUiUiUl1 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, XUInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, UInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, ULong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xuint, uint, ulong
let parseXUiUiUl2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, ULong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xsint, ucst5, sint
let parseXSiUc5Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UConst)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// slong, ucst5, slong
let parseSlUc5Sl bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, SLong)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UConst)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SLong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xuint, ucst5, ulong
let parseXUiUc5Ul bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XUInt)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UConst)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, ULong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xs2, uint, s2
let parseXS2UiS2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XS2)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, S2)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xs2, ucst5, s2
let parseXS2Uc5S2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XS2)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UConst)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, S2)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// ulong, uint, ulong
let parseUlUiUl bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, ULong)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, ULong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// ulong, ucst5, ulong
let parseUlUc5Ul bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, ULong)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UConst)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, ULong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xu2, uint, u2
let parseXU2UiU2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XU2)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, U2)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xu2, ucst5, u2
let parseXU2Uc5U2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XU2)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UConst)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, U2)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// int, xint, s2
let parseIntXiS2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, Int)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, S2)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// s2, xs2, u4
let parseS2XS2U4 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, S2)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, XS2)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, U4)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xsint, sint, sint
let parseXSiSiSi1 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, XSInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, SInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xsint, sint, sint
let parseXSiSiSi2 bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XSInt)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, SInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xint, int, int
let parseXiIntInt bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, XInt)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, Int)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, Int)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xsint, sint, slong
let parseXSiSiSl bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, XSInt)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, SInt)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SLong)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xdp, dp, dp
let parseXDpDpDp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, XDP)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, DP)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, DP)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// xsp, sp, sp
let parseXSpSpSp bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 17u 13u, XSP)
  let o2 = OperandInfo (Bits.extract bin 22u 18u, SP)
  let o3 = OperandInfo (Bits.extract bin 27u 23u, SP)
  struct (opcode, unit, parseThreeOprs unit o1 o2 o3)

/// unit, ucst5, ucst5, uint
let parseUiUc5Uc5Ui bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, UInt)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UConst)
  let o3 = OperandInfo (Bits.extract bin 12u 8u, UConst)
  let o4 = OperandInfo (Bits.extract bin 27u 23u, UInt)
  struct (opcode, unit, parseFourOprs unit o1 o2 o3 o4)

/// snit, ucst5, ucst5, sint
let parseSiUc5Uc5Si bin opcode unit =
  let o1 = OperandInfo (Bits.extract bin 22u 18u, SInt)
  let o2 = OperandInfo (Bits.extract bin 17u 13u, UConst)
  let o3 = OperandInfo (Bits.extract bin 12u 8u, UConst)
  let o4 = OperandInfo (Bits.extract bin 27u 23u, SInt)
  struct (opcode, unit, parseFourOprs unit o1 o2 o3 o4)

/// mem [offsetR/ucst5]
let parseDUnitLSBasicOperands bin opcode unit order =
  let mem = parseMem (Bits.extract bin 22u 9u) unit
  let reg =
    parseRegBySide (Bits.extract bin 27u 23u) (getSide (sBit bin)) |> OpReg
  struct (opcode, unit, buildMemOperand reg mem order)

/// mem [ucst15]
let parseDUnitLSLongImmOperands bin opcode unit order =
  let baseReg = getB14orB15 (yBit bin)
  let mem =
    OprMem (baseReg, PositiveOffset, UCst15 (uint64 (Bits.extract bin 22u 8u)))
  let reg =
    parseRegBySide (Bits.extract bin 27u 23u) (getSide (sBit bin)) |> OpReg
  struct (opcode, unit, buildMemOperand reg mem order)

/// mem, regPair
let parseDUnitDWordOperands bin opcode unit order =
  let mem = parseMem (Bits.extract bin 22u 9u) unit
  let v = Bits.extract bin 27u 23u
  let regPair =
    let high, low = if v &&& 0b1u = 0b0u then v + 1u, v else v, v - 1u
    let side = getSide (sBit bin)
    (parseRegBySide high side, parseRegBySide low side) |> RegisterPair
  struct (opcode, unit, buildMemOperand regPair mem order)

let is0xxxx address = address &&& 0b10000u = 0b00000u

let getCtrlReg crHi crLo =
  match crHi, crLo with
  | _, 0b00000u when is0xxxx crHi -> Register.AMR
  | _, 0b00001u when is0xxxx crHi -> Register.CSR
  | 0b00000u, 0b11001u -> Register.DIER
  | 0b00000u, 0b10001u -> Register.DNUM
  | 0b00000u, 0b11101u -> Register.ECR
  (* | 0b00000u, 0b11101u -> Register.EFR *) // XXX: depending on the MVC
  | 0b00000u, 0b10010u -> Register.FADCR
  | 0b00000u, 0b10011u -> Register.FAUCR
  | 0b00000u, 0b10100u -> Register.FMCR
  | 0b00000u, 0b11000u -> Register.GFPGFR
  | 0b00000u, 0b10110u -> Register.GPLYA
  | 0b00000u, 0b10111u -> Register.GPLYB
  | _, 0b00011u when is0xxxx crHi -> Register.ICR
  | _, 0b00100u when is0xxxx crHi -> Register.IER
  | 0b00000u, 0b11111u -> Register.IERR
  | 0b00000u, 0b00010u -> Register.IFR
  | 0b00010u, 0b00010u -> Register.IFR
  | 0b00000u, 0b01101u -> Register.ILC
  | _, 0b00110u when is0xxxx crHi -> Register.IRP
  | _, 0b00010u when is0xxxx crHi -> Register.ISR
  | _, 0b00101u when is0xxxx crHi -> Register.ISTP
  | 0b00000u, 0b11011u -> Register.ITSR
  | _, 0b00111u when is0xxxx crHi -> Register.NRP
  | 0b00000u, 0b11100u -> Register.NTSR
  | 0b00000u, 0b10000u -> Register.PCE1
  | 0b10000u, 0b10000u -> Register.PCE1
  | 0b00000u, 0b01111u -> Register.REP
  | 0b00000u, 0b01110u -> Register.RILC
  | 0b00000u, 0b10101u -> Register.SSR
  | 0b00000u, 0b01011u -> Register.TSCH
  | 0b00000u, 0b01010u -> Register.TSCL
  | 0b00000u, 0b11010u -> Register.TSR
  | _ -> Terminator.impossible ()

/// Control Register to Register
let parseCtrlRegToReg bin opcode unit =
  let o1 =
    getCtrlReg (Bits.extract bin 17u 13u) (Bits.extract bin 22u 18u) |> OpReg
  let o2 = translateOperand unit (OperandInfo (Bits.extract bin 27u 23u, UInt))
  struct (opcode, unit, TwoOperands (o1, o2))

/// Register to Control Register
let parseRegToCtrlReg bin opcode unit =
  let o1 = translateOperand unit (OperandInfo (Bits.extract bin 22u 18u, XUInt))
  let o2 =
    getCtrlReg (Bits.extract bin 17u 13u) (Bits.extract bin 27u 23u) |> OpReg
  struct (opcode, unit, TwoOperands (o1, o2))

let private getDUnit s x =
  match s, x with
  | 0b0u, 0b0u -> D1Unit
  | 0b0u, 0b1u -> D1XUnit
  | 0b1u, 0b0u -> D2Unit
  | _ (* 0b1u, 0b1u *) -> D2XUnit

/// Appendix C. page 724. Fig. C-1
let private parseDUnitSrcs bin =
  let unit = getDUnit (sBit bin) 0u
  match Bits.extract bin 12u 7u with
  | 0b000000u -> parseSc5Si2 bin Op.MVK unit
  | 0b010000u -> parseSiSiSi bin Op.ADD unit
  | 0b010001u -> parseSiSiSi bin Op.SUB unit
  | 0b010010u when isSrc1Zero bin -> parseSiSi bin Op.MV unit
  | 0b010010u -> parseSiUc5Si bin Op.ADD unit
  | 0b010011u -> parseSiUc5Si bin Op.SUB unit
  | 0b110000u -> parseSiSiSi bin Op.ADDAB unit
  | 0b110001u -> parseSiSiSi bin Op.SUBAB unit
  | 0b110010u -> parseSiUc5Si bin Op.ADDAB unit
  | 0b110011u -> parseSiUc5Si bin Op.SUBAB unit
  | 0b110100u -> parseSiSiSi bin Op.ADDAH unit
  | 0b110101u -> parseSiSiSi bin Op.SUBAH unit
  | 0b110110u -> parseSiUc5Si bin Op.ADDAH unit
  | 0b110111u -> parseSiUc5Si bin Op.SUBAH unit
  | 0b111000u -> parseSiSiSi bin Op.ADDAW unit
  | 0b111001u -> parseSiSiSi bin Op.SUBAW unit
  | 0b111010u -> parseSiUc5Si bin Op.ADDAW unit
  | 0b111011u -> parseSiUc5Si bin Op.SUBAW unit
  | 0b111100u -> parseSiSiSi bin Op.ADDAD unit
  | 0b111101u -> parseSiUc5Si bin Op.ADDAD unit
  | _ -> Terminator.impossible ()

/// Appendix C. page 724. Fig. C-2
let private parseDUnitSrcsExt bin =
  let unit = getDUnit (sBit bin) (xBit bin)
  match Bits.extract bin 9u 6u with
  | 0b0000u -> parseUiXUiUi bin Op.ANDN unit
  | 0b0010u -> parseUiXUiUi bin Op.OR unit
  | 0b0011u when isSrc1Zero bin -> parseXUiUi bin Op.MV unit
  | 0b0011u -> parseSc5XUiUi bin Op.OR unit
  | 0b0100u -> parseI2Xi2I2 bin Op.ADD2 unit
  | 0b0101u -> parseI2Xi2I2 bin Op.SUB2 unit
  | 0b0110u -> parseUiXUiUi bin Op.AND unit
  | 0b0111u -> parseSc5XUiUi bin Op.AND unit
  | 0b1010u -> parseSiXSiSi bin Op.ADD unit
  | 0b1011u -> parseSc5XSiSi bin Op.ADD unit
  | 0b1100u -> parseSiXSiSi bin Op.SUB unit
  | 0b1110u -> parseUiXUiUi bin Op.XOR unit
  | 0b1111u when isSrc111111 bin -> parseXUiUi bin Op.NOT unit
  | 0b1111u -> parseSc5XUiUi bin Op.XOR unit
  | _ -> Terminator.impossible ()

/// Appendix C. page 724. Fig. C-3
let private parseDUnitADDLongImm bin =
  let unit = getDUnit (sBit bin) 0u
  match Bits.extract bin 6u 4u with
  | 0b011u -> parseB14B15Uc15Si bin Op.ADDAB unit
  | 0b101u -> parseB14B15Uc15Si bin Op.ADDAH unit
  | 0b111u -> parseB14B15Uc15Si bin Op.ADDAW unit
  | _ -> Terminator.impossible ()

/// Appendix C. page 724. Fig. C-4
let private parseDUnitLSBasic bin =
  let unit = getDUnit (yBit bin) 0u
  match Bits.extract bin 6u 4u with
  | 0b000u -> parseDUnitLSBasicOperands bin Op.LDHU unit MemReg
  | 0b001u -> parseDUnitLSBasicOperands bin Op.LDBU unit MemReg
  | 0b010u -> parseDUnitLSBasicOperands bin Op.LDB unit MemReg
  | 0b011u -> parseDUnitLSBasicOperands bin Op.STB unit RegMem
  | 0b100u -> parseDUnitLSBasicOperands bin Op.LDH unit MemReg
  | 0b101u -> parseDUnitLSBasicOperands bin Op.STH unit RegMem
  | 0b110u -> parseDUnitLSBasicOperands bin Op.LDW unit MemReg
  | 0b111u -> parseDUnitLSBasicOperands bin Op.STW unit RegMem
  | _ -> Terminator.impossible ()

/// Appendix C. page 724. Fig. C-5
let private parseDUnitLSLongImm bin =
  match Bits.extract bin 6u 4u with
  | 0b000u -> parseDUnitLSLongImmOperands bin Op.LDHU D2Unit MemReg
  | 0b001u -> parseDUnitLSLongImmOperands bin Op.LDBU D2Unit MemReg
  | 0b010u -> parseDUnitLSLongImmOperands bin Op.LDB D2Unit MemReg
  | 0b011u -> parseDUnitLSLongImmOperands bin Op.STB D2Unit RegMem
  | 0b100u -> parseDUnitLSLongImmOperands bin Op.LDH D2Unit MemReg
  | 0b101u -> parseDUnitLSLongImmOperands bin Op.STH D2Unit RegMem
  | 0b110u -> parseDUnitLSLongImmOperands bin Op.LDW D2Unit MemReg
  | 0b111u -> parseDUnitLSLongImmOperands bin Op.STW D2Unit RegMem
  | _ -> Terminator.impossible ()

/// Appendix C. page 724. Fig. C-6
let private parseDUnitLSDWord bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix C. page 724. Fig. C-7
let private parseDUnitLSNonalignDWord bin =
  struct (Op.InvalOP, NoUnit, NoOperand)

let private getLUnit s x =
  match s, x with
  | 0b0u, 0b0u -> L1Unit
  | 0b0u, 0b1u -> L1XUnit
  | 0b1u, 0b0u -> L2Unit
  | _ (* 0b1u, 0b1u *) -> L2XUnit

let private getSUnit s x =
  match s, x with
  | 0b0u, 0b0u -> S1Unit
  | 0b0u, 0b1u -> S1XUnit
  | 0b1u, 0b0u -> S2Unit
  | _ (* 0b1u, 0b1u *) -> S2XUnit

/// Appendix D. page 735. Fig. D-1
let private parseLUnitSrcs bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix D. page 735. Fig. D-2
let private parseLUnitUnary bin =
  let unit = getLUnit (sBit bin) (xBit bin)
  match Bits.extract bin 17u 13u with
  | 0b00000u -> parseXSiSi bin Op.ABS unit
  | 0b00001u -> parseXU4U4 bin Op.SWAP4 unit
  | 0b00010u -> parseXU4U2 bin Op.UNPKLU4 unit
  | 0b00011u -> parseXU4U2 bin Op.UNPKHU4 unit
  | 0b00100u -> parseXs2S2 bin Op.ABS2 unit
  | 0b00101u -> parseSc5Si1 bin Op.MVK unit
  | _ -> Terminator.impossible ()

/// Appendix D. page 735. Fig. D-3
let private parseLUnitNonCond bin = struct (Op.InvalOP, NoUnit, NoOperand)

let private getMUnit s x =
  match s, x with
  | 0b0u, 0b0u -> M1Unit
  | 0b0u, 0b1u -> M1XUnit
  | 0b1u, 0b0u -> M2Unit
  | _ (* 0b1u, 0b1u *) -> M2XUnit

/// Appendix E. page 743. Fig. E-1
let private parseMUnitCompound bin =
  let unit = getMUnit (sBit bin) (xBit bin)
  match Bits.extract bin 10u 6u with
  | 0b00000u -> parseS2XS2Ull bin Op.MPY2 unit
  | 0b00001u -> parseS2XS2Sll bin Op.SMPY2 unit
  | 0b00010u -> parseS4XU4Int bin Op.DOTPSU4 unit (* DOTPUS4 *)
  | 0b00100u -> parseU4XU4DWU4 bin Op.MPYU4 unit
  | 0b00101u -> parseS4XU4DWS4 bin Op.MPYSU4 unit (* MPYUS4 *)
  | 0b00110u -> parseU4XU4Ui bin Op.DOTPU4 unit
  | 0b00111u -> parseS2XU2Int bin Op.DOTPNRSU2 unit (* DOTPNRUS2 *)
  | 0b01001u -> parseS2XS2Int bin Op.DOTPN2 unit
  | 0b01101u -> parseS2XU2Int bin Op.DOTPRSU2 unit (* DOTPRUS2 *)
  | 0b01011u -> parseS2XS2Sll bin Op.DOTP2 unit
  | 0b01100u -> parseS2XS2Int bin Op.DOTP2 unit
  | 0b01110u -> parseIntXiInt bin Op.MPYLIR unit (* MPYILR *)
  | 0b10000u -> parseIntXiInt bin Op.MPYHIR unit (* MPYIHR *)
  | 0b10001u -> parseU4XU4U4 bin Op.GMPY4 unit
  | 0b10010u -> parseU4XU4U4 bin Op.AVGU4 unit
  | 0b10011u -> parseS2XS2S2 bin Op.AVG2 unit
  | 0b10100u -> parseIntXiSll bin Op.MPYHI unit (* MPYIH *)
  | 0b10101u -> parseIntXiSll bin Op.MPYLI unit (* MPYIL *)
  | 0b10110u -> parseSpXDpDp bin Op.MPYSPDP unit
  | 0b10111u -> parseSpXSpDp bin Op.MPYSP2DP unit
  | 0b11000u -> parseUiXUiDUi bin Op.MPY32U unit
  | 0b11001u -> parseUiXiDi bin Op.MPY32US unit
  | 0b11010u -> parseXiIntInt bin Op.SSHVR unit
  | 0b11100u -> parseXiIntInt bin Op.SSHVL unit
  | 0b11101u -> parseXUiUiUi bin Op.ROTL unit
  | 0b11110u -> parseXUiUc5Ui bin Op.ROTL unit
  | _ -> Terminator.impossible  ()

/// Appendix E. page 743. Fig. E-2
let private parseMUnitUnaryExt bin =
  let unit = getMUnit (sBit bin) (xBit bin)
  match Bits.extract bin 17u 13u with
  | 0b11010u -> parseXiInt bin Op.MVD unit
  | 0b11000u -> parseXUiUi bin Op.XPND4 unit
  | 0b11001u -> parseXUiUi bin Op.XPND2 unit
  | 0b11101u -> parseXUiUi bin Op.DEAL unit
  | 0b11100u -> parseXUiUi bin Op.SHFL unit
  | 0b11110u -> parseXU4U4 bin Op.BITC4 unit
  | 0b11111u -> parseXUiUi bin Op.BITR unit
  | _ -> Terminator.impossible ()

/// Appendix E. page 743. Fig. E-3
let private parseMUnitNonCond bin =
  let unit = getMUnit (sBit bin) (xBit bin)
  match Bits.extract bin 10u 6u with
  | 0b01010u -> parseS2XS2Di bin Op.CMPY unit
  | 0b01011u -> parseS2XS2S2 bin Op.CMPYR unit
  | 0b01100u -> parseS2XS2S2 bin Op.CMPYR1 unit
  | 0b01111u -> parseIntXiDi bin Op.MPY2IR unit (* E-1, Exceptional case. *)
  | 0b10100u -> parseDS2XS2S2 bin Op.DDOTPL2R unit
  | 0b10101u -> parseDS2XS2S2 bin Op.DDOTPH2R unit
  | 0b10110u -> parseDS2XS2Di bin Op.DDOTPL2 unit
  | 0b10111u -> parseDS2XS2Di bin Op.DDOTPH2 unit
  | 0b11000u -> parseS2XS4Di bin Op.DDOTP4 unit
  | 0b11001u -> parseIntXiInt bin Op.SMPY32 unit
  | 0b11011u -> parseUiXUiUi bin Op.XORMPY unit
  | 0b11111u -> parseUiUiUi bin Op.GMPY unit
  | _ -> Terminator.impossible ()

/// Appendix E. page 743. Fig. E-4
let private parseMUnitMPY bin =
  let unit = getMUnit (sBit bin) (xBit bin)
  match Bits.extract bin 11u 7u with
  | 0b00001u -> parseSmsb16XSmsb16Si bin Op.MPYH unit
  | 0b00010u -> parseSmsb16XSmsb16Si bin Op.SMPYH unit
  | 0b00011u -> parseSmsb16XUmsb16Si bin Op.MPYHSU unit
  | 0b00100u -> parseSiXSiSi bin Op.MPYI unit
  | 0b00101u -> parseUmsb16XSmsb16Si bin Op.MPYHUS unit
  | 0b00110u -> parseC5XSiSi bin Op.MPYI unit
  | 0b00111u -> parseUmsb16XUmsb16Ui bin Op.MPYHU unit
  | 0b01000u -> parseSiXSiSDi bin Op.MPYID unit
  | 0b01001u -> parseSmsb16XSlsb16Si bin Op.MPYHL unit
  | 0b01010u -> parseSmsb16XSlsb16Si bin Op.SMPYHL unit
  | 0b01011u -> parseSmsb16XUlsb16Si bin Op.MPYHSLU unit
  | 0b01100u -> parseC5XSiSDi bin Op.MPYID unit
  | 0b01101u -> parseUmsb16XSlsb16Si bin Op.MPYHULS unit
  | 0b01110u -> parseDpXDpDp bin Op.MPYDP unit
  | 0b01111u -> parseUmsb16XUlsb16Ui bin Op.MPYHLU unit
  | 0b10000u -> parseIntXiInt bin Op.MPY32 unit
  | 0b10001u -> parseSlsb16XSmsb16Si bin Op.MPYLH unit
  | 0b10010u -> parseSlsb16XSmsb16Si bin Op.SMPYLH unit
  | 0b10011u -> parseSlsb16XUmsb16Si bin Op.MPYLSHU unit
  | 0b10100u -> parseIntXiDi bin Op.MPY32 unit
  | 0b10101u -> parseUlsb16XSmsb16Si bin Op.MPYLUHS unit
  | 0b10110u -> parseIntXUiDi bin Op.MPY32SU unit
  | 0b10111u -> parseUlsb16XUmsb16Ui bin Op.MPYLHU unit
  | 0b11000u -> parseSc5XSlsb16Si bin Op.MPY unit
  | 0b11001u -> parseSlsb16XSlsb16Si bin Op.MPY unit
  | 0b11010u -> parseSlsb16XSlsb16Si bin Op.SMPY unit
  | 0b11011u -> parseSlsb16XUlsb16Si bin Op.MPYSU unit
  | 0b11100u -> parseSpXSpSp bin Op.MPYSP unit
  | 0b11101u -> parseUlsb16XSlsb16Si bin Op.MPYUS unit
  | 0b11110u -> parseSc5XUlsb16Si bin Op.MPYSU unit
  | 0b11111u -> parseUlsb16XUlsb16Ui bin Op.MPYU unit
  | _ -> Terminator.impossible ()

/// Appendix F. page 747. Fig. F-1
let private parseSUnitSrcs bin =
  let unit = getSUnit (sBit bin) (xBit bin)
  match Bits.extract bin 11u 6u with
  | 0b000001u -> parseI2Xi2I2 bin Op.ADD2 unit
  | 0b000010u -> parseXSpDp bin Op.SPDP unit
  | 0b000110u when isSrc1Zero bin -> parseXSiSi bin Op.MV unit
  | 0b000110u -> parseSc5XSiSi bin Op.ADD unit
  | 0b000111u -> parseSiXSiSi bin Op.ADD unit
  | 0b001000u -> parseI2Xi2I2 bin Op.PACKHL2 unit
  | 0b001001u -> parseI2Xi2I2 bin Op.PACKH2 unit
  | 0b001010u when isSrc111111 bin -> parseXUiUi bin Op.NOT unit
  | 0b001010u -> parseSc5XUiUi bin Op.XOR unit
  | 0b001011u -> parseUiXUiUi bin Op.XOR unit
  | 0b001110u -> parseRegToCtrlReg bin Op.MVC unit
  | 0b001111u -> parseCtrlRegToReg bin Op.MVC unit
  | 0b010000u when isSrc100010 bin -> parseS2S2 bin Op.SWAP2 unit // FIXME
  | 0b010000u -> parseI2Xi2I2 bin Op.PACKLH2 unit
  | 0b010001u -> parseI2Xi2I2 bin Op.SUB2 unit
  | 0b010010u -> parseXUiUc5Ul bin Op.SHL unit
  | 0b010011u -> parseXUiUiUl2 bin Op.SHL unit
  | 0b010100u -> parseS2XS2Bv2 bin Op.CMPGT2 unit (* CMPLT2 src2, src1, dst *)
  | 0b010101u -> parseU4XU4Bv4 bin Op.CMPGTU4 unit (* CMPLTU4 src2, src1, dst *)
  | 0b010110u when isSrc1Zero bin -> parseXSiSi bin Op.NEG unit
  | 0b010110u -> parseSc5XSiSi bin Op.SUB unit
  | 0b010111u -> parseSiXSiSi bin Op.SUB unit
  | 0b011000u -> parseXS2Uc5S2 bin Op.SHR2 unit
  | 0b011001u -> parseXU2Uc5U2 bin Op.SHRU2 unit
  | 0b011010u -> parseSc5XUiUi bin Op.OR unit
  | 0b011011u -> parseUiXUiUi bin Op.OR unit
  | 0b011100u -> parseS4XS4Bv4 bin Op.CMPEQ4 unit
  | 0b011101u -> parseS2XS2Bv2 bin Op.CMPEQ2 unit
  | 0b011110u -> parseSc5XUiUi bin Op.AND unit
  | 0b011111u -> parseUiXUiUi bin Op.AND unit
  | 0b100000u -> parseSiXSiSi bin Op.SADD unit
  | 0b100010u -> parseXSiUc5Si bin Op.SSHL unit
  | 0b100011u -> parseXSiUiSi bin Op.SSHL unit
  | 0b100100u -> parseUlUc5Ul bin Op.SHRU unit
  | 0b100101u -> parseUlUiUl bin Op.SHRU unit
  | 0b100110u -> parseXUiUc5Ui bin Op.SHRU unit
  | 0b100111u -> parseXUiUiUi bin Op.SHRU unit
  | 0b101000u -> parseDpXDpSi bin Op.CMPEQDP unit
  | 0b101001u -> parseDpXDpSi bin Op.CMPGTDP unit
  | 0b101010u -> parseDpXDpSi bin Op.CMPLTDP unit
  | 0b101011u -> parseXUiUiUi bin Op.EXTU unit
  | 0b101100u -> parseXDpDp bin Op.ABSDP unit
  | 0b101101u -> parseDpDp bin Op.RCPDP unit
  | 0b101110u -> parseDpDp bin Op.RSQRDP unit
  | 0b101111u -> parseXSiUiSi bin Op.EXT unit
  | 0b110000u -> parseSlUc5Sl bin Op.SHL unit
  | 0b110001u -> parseSlUiSl bin Op.SHL unit
  | 0b110010u -> parseXSiUc5Si bin Op.SHL unit
  | 0b110011u -> parseXSiUiSi bin Op.SHL unit
  | 0b110100u -> parseSlUc5Sl bin Op.SHR unit
  | 0b110101u -> parseSlUiSl bin Op.SHR unit
  | 0b110110u -> parseXSiUc5Si bin Op.SHR unit
  | 0b110111u -> parseXSiUiSi bin Op.SHR unit
  | 0b111000u -> parseSpXSpSi bin Op.CMPEQSP unit
  | 0b111001u -> parseSpXSpSi bin Op.CMPGTSP unit
  | 0b111010u -> parseSpXSpSi bin Op.CMPLTSP unit
  | 0b111011u -> parseXUiUiUi bin Op.SET unit
  | 0b111110u -> parseXSpSp bin Op.RSQRSP unit
  | 0b111111u -> parseXUiUiUi bin Op.CLR unit
  | _ -> Terminator.impossible ()

/// Appendix F. page 747. Fig. F-2
let private parseSUnitAddSubFloat bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix F. page 747. Fig. F-3
let private parseSUnitADDK bin =
  parseSc16Ui bin Op.ADDK (getSUnit (sBit bin) 0u)

/// Appendix F. page 748. Fig. F-4
let private parseSUnitADDKPC bin =
  parseSc7Uc3Ui bin Op.ADDKPC (getSUnit (sBit bin) 0u)

/// Appendix F. page 748. Fig. F-5
let private parseSUnitSrcsExt bin =
  let unit = getSUnit (sBit bin) (xBit bin)
  match Bits.extract bin 9u 6u with
  | 0b0000u -> parseS2XS2S2 bin Op.SADD2 unit
  | 0b0001u -> parseU2XS2U2 bin Op.SADDUS2 unit (* SADDSU2 *)
  | 0b0010u -> parseIntXiS2 bin Op.SPACK2 unit
  | 0b0011u -> parseU4XU4U4 bin Op.SADDU4 unit
  | 0b0100u -> parseS2XS2U4 bin Op.SPACKU4 unit
  | 0b0101u -> parseXSiSiSi2 bin Op.SUB unit
  | 0b0110u -> parseUiXUiUi bin Op.ANDN unit
  | 0b0111u -> parseXS2UiS2 bin Op.SHR2 unit
  | 0b1000u -> parseXU2UiU2 bin Op.SHRU2 unit
  | 0b1001u -> parseU4XU4U4 bin Op.SHLMB unit
  | 0b1010u -> parseU4XU4U4 bin Op.SHRMB unit
  | 0b1011u -> parseSiXSiDi bin Op.DMV unit
  | 0b1100u -> parseS2XS2S2 bin Op.MIN2 unit
  | 0b1101u -> parseS2XS2S2 bin Op.MAX2 unit
  | 0b1111u -> parseI2Xi2I2 bin Op.PACK2 unit
  | _ -> Terminator.impossible ()

/// Appendix F. page 748. Fig. F-6
let private parseSUnitBrDisp bin =
  parseSc21 bin Op.B (getSUnit (sBit bin) 0u) // FIXME: label

/// Appendix F. page 748. Fig. F-7
let private parseSUnitBrRegWithoutNOP bin =
  parseXUi bin Op.B (getSUnit (sBit bin) (xBit bin))

/// Appendix F. page 748. Fig. F-8
let private parseSUnitBrPointer bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix F. page 748. Fig. F-9
let private parseSUnitBdecBpos bin =
  let unit = getSUnit (sBit bin) 0u
  match Bits.pick bin 12u with
  | 0b1u -> parseSc10Int bin Op.BDEC unit
  | _ (* 0b0u *) -> parseSc10Int bin Op.BPOS unit

/// Appendix F. page 748. Fig. F-10
let private parseSUnitBrDispNOP bin =
  parseSc12Uc3 bin Op.BNOP (getSUnit (sBit bin) 0u)

/// Appendix F. page 748. Fig. F-11
let private parseSUnitBrRegNOP bin =
  parseXUiUc3 bin Op.BNOP (getSUnit (sBit bin) (xBit bin))

/// Appendix F. page 749. Fig. F-12
let private parseSUnitNonCondImm bin =
  parseSc21 bin Op.CALLP (getSUnit (sBit bin) 0u) // FIXME: label

/// Appendix F. page 749. Fig. F-13
let private parseSUnitMoveConst bin =
  match Bits.pick bin 6u with
  | 0b0u -> parseSc16Si bin Op.MVK (getSUnit (sBit bin) 0u)
  | _ (* 0b01 *) -> parseUSc16Si bin Op.MVKH (getSUnit (sBit bin) 0u) // FIXME

/// Appendix F. page 749. Fig. F-14
let private parseSUnitNonCond bin =
  let unit = getSUnit (sBit bin) (xBit bin)
  match Bits.extract bin 9u 6u with
  | 0b1011u -> parseSiXSiS2 bin Op.RPACK2 unit
  | _ -> Terminator.impossible ()

/// Appendix F. page 749. Fig. F-15
let private parseSUnitUnary bin =
  let unit = getSUnit (sBit bin) (xBit bin)
  match Bits.extract bin 17u 13u with
  | 0b00000u -> parseXSpSp bin Op.ABSSP unit
  | 0b00010u -> parseXU4U2 bin Op.UNPKLU4 unit
  | 0b00011u -> parseXU4U2 bin Op.UNPKHU4 unit
  | _ -> Terminator.impossible ()

/// Appendix F. page 749. Fig. F-16
let private parseSUnitFieldOps bin =
  match Bits.extract bin 7u 6u with
  | 0b00u -> parseUiUc5Uc5Ui bin Op.EXTU (getSUnit (sBit bin) 0u)
  | 0b01u -> parseSiUc5Uc5Si bin Op.EXT (getSUnit (sBit bin) 0u)
  | 0b10u -> parseUiUc5Uc5Ui bin Op.SET (getSUnit (sBit bin) 0u)
  | 0b11u -> parseUiUc5Uc5Ui bin Op.CLR (getSUnit (sBit bin) 0u)
  | _ -> Terminator.impossible ()

/// Appendix H. page 765. Fig. H-1
let private parseNoUnitDINT bin =
  match Bits.extract bin 16u 13u with
  | 0b0000u -> struct (Op.SWE, NoUnit, NoOperand)
  | 0b0001u -> struct (Op.SWENR, NoUnit, NoOperand)
  | 0b0010u -> struct (Op.DINT, NoUnit, NoOperand)
  | 0b0011u -> struct (Op.RINT, NoUnit, NoOperand)
  | _ -> Terminator.impossible ()

/// Appendix H. page 765. Fig. H-2
let private parseNoUnitIdleNop bin =
  match Bits.extract bin 16u 13u with
  | 0b1111u -> struct (Op.IDLE, NoUnit, NoOperand)
  | _ -> parseUc4 bin Op.NOP NoUnit

/// Appendix H. page 765. Fig. H-3
let private parseNoUnitLoopNonCond bin = struct (Op.InvalOP, NoUnit, NoOperand)

/// Appendix H. page 765. Fig. H-4
let private parseNoUnitLoop bin = struct (Op.InvalOP, NoUnit, NoOperand)

let private parseNoUnitCase0 bin =
  match Bits.extract bin 31u 28u with
  | 0b0000u -> parseNoUnitIdleNop bin
  | 0b0001u -> parseNoUnitDINT bin
  | _ -> Terminator.impossible ()

let private parseNoUnitCase1 bin =
  match Bits.extract bin 31u 28u with
  | 0b0000u -> parseNoUnitLoopNonCond bin
  | _ -> parseNoUnitLoop bin

let private parseNoUnit bin =
  match Bits.pick bin 17u with
  | 0b0u -> parseNoUnitCase0 bin
  | _ (* 0b1u *) -> parseNoUnitCase1 bin

let private parseCase00000 bin =
  match Bits.extract bin 12u 7u with
  | 0b000000u -> parseNoUnit bin
  | _ -> parseMUnitMPY bin

let private parseCase0000 bin =
  match Bits.pick bin 6u with
  | 0b1u -> parseDUnitSrcs bin
  | _ (* 0b0u *) -> parseCase00000 bin

let private parseCase00100 bin =
  match Bits.extract bin 31u 28u with
  | 0b0001u -> parseSUnitNonCondImm bin
  | _ -> parseSUnitBrDisp bin

let private parseCase0100 bin =
  match Bits.pick bin 6u with
  | 0b0u -> parseCase00100 bin
  | _ (* 0b1u *) -> parseSUnitADDK bin

let private parseSUnitBrReg bin =
  match Bits.pick bin 23u with
  | 0b0u -> parseSUnitBrRegWithoutNOP bin
  | _ (* 0b1u *) -> parseSUnitBrRegNOP bin

let private parseCase1000 bin =
  match Bits.extract bin 11u 6u with
  | 0b000000u -> parseSUnitBdecBpos bin
  | 0b000011u -> parseSUnitBrPointer bin
  | 0b000100u -> parseSUnitBrDispNOP bin
  | 0b000101u -> parseSUnitADDKPC bin
  | 0b111100u -> parseSUnitUnary bin
  | 0b001101u -> parseSUnitBrReg bin
  | _ -> parseSUnitSrcs bin

let parseMUnitSub bin =
  match Bits.extract bin 31u 28u with
  | 0b0001u -> parseMUnitNonCond bin
  | _ -> parseMUnitCompound bin

let private parseMUnit bin =
  match Bits.extract bin 10u 6u with
  | 0b00011u -> parseMUnitUnaryExt bin
  | _ -> parseMUnitSub bin

let parseCase111100 bin =
  match Bits.extract bin 31u 28u with
  | 0b0001u -> parseSUnitNonCond bin
  | _ -> parseSUnitSrcsExt bin

let private parseCase11100 bin =
  match Bits.pick bin 10u with
  | 0b0u -> parseDUnitSrcsExt bin
  | _ (* 0b1u *) -> parseCase111100 bin

let private parseCase1100 bin =
  match Bits.pick bin 11u with
  | 0b0u -> parseMUnit bin
  | _ (* 0b1u *) -> parseCase11100 bin

let private parseCase00 bin =
  match Bits.extract bin 5u 4u with
  | 0b00u -> parseCase0000 bin
  | 0b01u -> parseCase0100 bin
  | 0b10u -> parseCase1000 bin
  | _ (* 0b11 *) -> parseCase1100 bin

let private parseCase010 bin =
  match Bits.pick bin 5u with
  | 0b0u -> parseSUnitFieldOps bin
  | _ (* 0b1u *) -> parseSUnitMoveConst bin

let private parseCase110 bin =
  let x, s = xBit bin, sBit bin
  let creg = Bits.extract bin 31u 29u
  match Bits.extract bin 11u 5u with
  | 0b0011010u -> parseLUnitUnary bin
  (* parseLUnitNonCond, D-3 *)
  | 0b0001110u when creg = 0b0001u ->
    parseSiXSiDi bin Op.SADDSUB (getLUnit s x)
  | 0b0001111u when creg = 0b0001u ->
    parseSiXSiDi bin Op.SADDSUB2 (getLUnit s x)
  | 0b0110011u -> parseSiXSiDi bin Op.DPACKX2 (getLUnit s x)
  | 0b0110100u -> parseSiXSiDi bin Op.DPACK2 (getLUnit s x)
  | 0b0110110u -> parseSiXSiDi bin Op.SHFL3 (getLUnit s x)
  (* parseLUnitSrcs, D-1 *)
  | 0b0000000u -> parseI2Xi2I2 bin Op.PACK2 (getLUnit s x)
  | 0b0000001u -> parseDpSi bin Op.DPTRUNC (getLUnit s x)
  | 0b0000011u -> parseSiXSiSi bin Op.ADD (getLUnit s x)
  | 0b0000010u when isSrc1Zero bin -> parseXSiSi bin Op.MV (getLUnit s x)
  | 0b0000010u -> parseSc5XSiSi bin Op.ADD (getLUnit s x)
  | 0b0000100u -> parseI2Xi2I2 bin Op.SUB2 (getLUnit s x)
  | 0b0000101u -> parseI2Xi2I2 bin Op.ADD2 (getLUnit s x)
  | 0b0000110u when isSrc1Zero bin -> parseXSiSi bin Op.NEG (getLUnit s x)
  | 0b0000110u -> parseSc5XSiSi bin Op.SUB (getLUnit s x)
  | 0b0000111u when isEqualSrc1Src2 bin -> parseSi bin Op.ZERO (getLUnit s x)
  | 0b0000111u -> parseSiXSiSi bin Op.SUB (getLUnit s x)
  | 0b0001000u -> parseDpSi bin Op.DPINT (getLUnit s x)
  | 0b0001001u -> parseDpSp bin Op.DPSP (getLUnit s x)
  | 0b0001010u -> parseXSpSi bin Op.SPINT (getLUnit s x)
  | 0b0001011u -> parseXSpSi bin Op.SPTRUNC (getLUnit s x)
  | 0b0001100u -> parseSiXSiDi bin Op.ADDSUB (getLUnit s x)
  | 0b0001101u -> parseSiXSiDi bin Op.ADDSUB2 (getLUnit s x)
  | 0b0001110u -> parseSc5XSiSi bin Op.SSUB (getLUnit s x)
  | 0b0001111u -> parseSiXSiSi bin Op.SSUB (getLUnit s x)
  | 0b0010000u -> parseSpXSpSp bin Op.ADDSP (getLUnit s x)
  | 0b0010001u -> parseSpXSpSp bin Op.SUBSP (getLUnit s x)
  | 0b0010010u -> parseSc5XSiSi bin Op.SADD (getLUnit s x)
  | 0b0010011u -> parseSiXSiSi bin Op.SADD (getLUnit s x)
  | 0b0010101u -> parseXSpSpSp bin Op.SUBSP (getLUnit s x)
  | 0b0010111u -> parseXSiSiSi1 bin Op.SUB (getLUnit s x)
  | 0b0011000u -> parseDpXDpDp bin Op.ADDDP (getLUnit s x)
  | 0b0011001u -> parseDpXDpDp bin Op.SUBDP (getLUnit s x)
  | 0b0011011u when isSrc100010 bin -> parseS2S2 bin Op.SWAP2 (getLUnit s x)
  | 0b0011011u -> parseI2Xi2I2 bin Op.PACKLH2 (getLUnit s x)
  | 0b0011100u -> parseI2Xi2I2 bin Op.PACKHL2 (getLUnit s x)
  | 0b0011101u -> parseXDpDpDp bin Op.SUBDP (getLUnit s x)
  | 0b0011110u -> parseI2Xi2I2 bin Op.PACKH2 (getLUnit s x)
  | 0b0011111u -> parseXSiSiSi1 bin Op.SSUB (getLUnit s x)
  | 0b0100000u when isSrc1Zero bin -> parseSlSl bin Op.MV (getLUnit s 0u)
  | 0b0100000u -> parseSc5SlSl bin Op.ADD (getLUnit s x)
  | 0b0100001u -> parseXSiSlSl bin Op.ADD (getLUnit s x)
  | 0b0100011u -> parseSiXSiSl bin Op.ADD (getLUnit s x)
  | 0b0100100u when isSrc1Zero bin -> parseSlSl bin Op.NEG (getLUnit s x)
  | 0b0100100u -> parseSc5SlSl bin Op.SUB (getLUnit s x)
  | 0b0100111u when isEqualSrc1Src2 bin -> parseSl bin Op.ZERO (getLUnit s x)
  | 0b0100111u -> parseSiXSiSl bin Op.SUB (getLUnit s x)
  | 0b0101001u -> parseXUiUlUl bin Op.ADDU (getLUnit s x)
  | 0b0101011u -> parseUiXUiUl bin Op.ADDU (getLUnit s x)
  | 0b0101100u -> parseSc5SlSl bin Op.SSUB (getLUnit s x)
  | 0b0101111u -> parseUiXUiUl bin Op.SUBU (getLUnit s x)
  | 0b0110000u -> parseSc5SlSl bin Op.SADD (getLUnit s x)
  | 0b0110001u -> parseXSiSlSl bin Op.SADD (getLUnit s x)
  | 0b0110111u when isEqualSrc1Src2 bin -> parseSl bin Op.ZERO (getLUnit s x)
  | 0b0110111u -> parseXSiSiSl bin Op.SUB (getLUnit s x)
  | 0b0111000u -> parseSlSl bin Op.ABS (getLUnit s x)
  | 0b0111001u -> parseXSiDp bin Op.INTDP (getLUnit s x)
  | 0b0111011u -> parseXUiDp bin Op.INTDPU (getLUnit s x)
  | 0b0111111u -> parseXUiUiUl1 bin Op.SUBU (getLUnit s x)
  | 0b1000000u -> parseSlSi bin Op.SAT (getLUnit s x)
  | 0b1000001u -> parseS2XS2S2 bin Op.MIN2 (getLUnit s x)
  | 0b1000010u -> parseS2XS2S2 bin Op.MAX2 (getLUnit s x)
  | 0b1000011u -> parseU4XU4U4 bin Op.MAXU4 (getLUnit s x)
  | 0b1000100u -> parseSc5SlUi bin Op.CMPGT (getLUnit s x)
  | 0b1000101u -> parseXSiSlUi bin Op.CMPGT (getLUnit s x)
  | 0b1000110u -> parseSc5XSiUi bin Op.CMPGT (getLUnit s x)
  | 0b1000111u -> parseSiXSiUi bin Op.CMPGT (getLUnit s x)
  | 0b1001000u -> parseU4XU4U4 bin Op.MINU4 (getLUnit s x)
  | 0b1001001u -> parseXUiSp bin Op.INTSPU (getLUnit s x)
  | 0b1001010u -> parseXSiSp bin Op.INTSP (getLUnit s x)
  | 0b1001011u -> parseUiXUiUi bin Op.SUBC (getLUnit s x)
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
  | 0b1011010u -> parseU4XU4U4 bin Op.SUBABS4 (getLUnit s x)
  | 0b1011100u -> parseUc4UlUi bin Op.CMPGTU (getLUnit s x)
  | 0b1011101u -> parseXUiUlUi bin Op.CMPGTU (getLUnit s x)
  | 0b1011110u -> parseUc4XUiUi bin Op.CMPGTU (getLUnit s x)
  | 0b1011111u -> parseUiXUiUi bin Op.CMPGTU (getLUnit s x)
  | 0b1100000u -> parseSlUi bin Op.NORM (getLUnit s x)
  | 0b1100001u -> parseU4XU4U4 bin Op.SHLMB (getLUnit s x)
  | 0b1100010u -> parseU4XU4U4 bin Op.SHRMB (getLUnit s x)
  | 0b1100011u -> parseXSiUi bin Op.NORM (getLUnit s x)
  | 0b1100100u -> parseS2XS2S2 bin Op.SSUB2 (getLUnit s x)
  | 0b1100101u -> parseI4Xi4I4 bin Op.ADD4 (getLUnit s x)
  | 0b1100110u -> parseI4Xi4I4 bin Op.SUB4 (getLUnit s x)
  | 0b1101000u -> parseI4Xi4I4 bin Op.PACKL4 (getLUnit s x)
  | 0b1101001u -> parseI4Xi4I4 bin Op.PACKH4 (getLUnit s x)
  | 0b1101010u -> parseC5XUiUi bin Op.LMBD (getLUnit s x)
  | 0b1101011u -> parseUiXUiUi bin Op.LMBD (getLUnit s x)
  | 0b1101110u when isSrc111111 bin -> parseXUiUi bin Op.NOT (getLUnit s x)
  | 0b1101110u -> parseSc5XUiUi bin Op.XOR (getLUnit s x)
  | 0b1101111u -> parseUiXUiUi bin Op.XOR (getLUnit s x)
  | 0b1111010u -> parseSc5XUiUi bin Op.AND (getLUnit s x)
  | 0b1111011u -> parseUiXUiUi bin Op.AND (getLUnit s x)
  | 0b1111100u -> parseUiXUiUi bin Op.ANDN (getLUnit s x)
  | 0b1111110u when isSrc1Zero bin -> parseXUiUi bin Op.MV (getLUnit s x)
  | 0b1111110u -> parseSc5XUiUi bin Op.OR (getLUnit s x)
  | 0b1111111u -> parseUiXUiUi bin Op.OR (getLUnit s x)
  (* parseSUnitAddSubFloat, F-2 *)
  | 0b1110000u -> parseSpXSpSp bin Op.ADDSP (getSUnit s x)
  | 0b1110001u -> parseSpXSpSp bin Op.SUBSP (getSUnit s x)
  | 0b1110010u -> parseDpXDpDp bin Op.ADDDP (getSUnit s x)
  | 0b1110011u -> parseDpXDpDp bin Op.SUBDP (getSUnit s x)
  | 0b1110101u -> parseSpXSpSp bin Op.SUBSP (getSUnit s x) (* src2 - src1 *)
  | 0b1110111u -> parseDpXDpDp bin Op.SUBDP (getSUnit s x) (* src2 - src1 *)
  | _ -> Terminator.impossible ()

let private parseCase10 bin =
  match Bits.pick bin 4u with
  | 0b0u -> parseCase010 bin
  | _ (* 0b1u *) -> parseCase110 bin

let private parseDUnitDWord bin =
  let unit = getDUnit (yBit bin) 0u
  match Bits.extract bin 6u 4u with
  (* parseDUnitLSBasic, C-4. Exceptional case. *)
  | 0b011u -> parseDUnitLSBasicOperands bin Op.LDNW unit MemReg
  | 0b101u -> parseDUnitLSBasicOperands bin Op.STNW unit RegMem
  (* parseDUnitLSDWord, C-6 *)
  | 0b100u -> parseDUnitDWordOperands bin Op.STDW unit RegMem
  | 0b110u -> parseDUnitDWordOperands bin Op.LDDW unit MemReg
  (* parseDUnitLSNonalignDWord C-7 *)
  | 0b010u -> parseDUnitDWordOperands bin Op.LDNDW unit MemReg
  | 0b111u -> parseDUnitDWordOperands bin Op.STNDW unit RegMem
  | _ -> Terminator.impossible ()

let private parseDUnitLoadStore bin =
  match Bits.pick bin 8u with
  | 0b1u -> parseDUnitDWord bin
  | _ (* 0b0u *) -> parseDUnitLSBasic bin

let private parseDUnitLongImm bin =
  match Bits.extract bin 31u 28u with
  | 0b0001u -> parseDUnitADDLongImm bin
  | _ -> parseDUnitLSLongImm bin

let private parseInstruction bin =
  match Bits.extract bin 3u 2u with
  | 0b00u -> parseCase00 bin
  | 0b10u -> parseCase10 bin
  | 0b01u -> parseDUnitLoadStore bin
  | _ (* 0b11u *) -> parseDUnitLongImm bin

let parse lifter (span: ByteSpan) reader (inParallel: byref<bool>) addr =
  let bin = (reader: IBinReader).ReadUInt32 (span, 0)
  let struct (opcode, unit, operands) = parseInstruction bin
  inParallel <- pBit bin <> 0u
  Instruction (addr, 4u, opcode, operands, unit, 32<rt>, inParallel, lifter)

// vim: set tw=80 sts=2 sw=2:
