(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)

namespace B2R2.FrontEnd.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd

module MIPS32 =
  open B2R2.FrontEnd.BinLifter.MIPS

  let private test arch endian opcode cond fmt oprs (bytes: byte[]) =
    let reader = BinReader.Init endian
    let span = System.ReadOnlySpan bytes
    let ins = ParsingMain.parse span reader arch WordSize.Bit32 0UL
    let opcode' = ins.Info.Opcode
    let cond' = ins.Info.Condition
    let fmt' = ins.Info.Fmt
    let oprs' = ins.Info.Operands
    Assert.AreEqual (opcode', opcode)
    Assert.AreEqual (cond', cond)
    Assert.AreEqual (fmt', fmt)
    Assert.AreEqual (oprs', oprs)

  let private test32R2 = test Architecture.MIPS32 Endian.Big

  /// Arithmetic Operations
  [<TestClass>]
  type ArithmeticClass () =
    [<TestMethod>]
    member __.``[MIPS32] Arithmetic Operations Parse Test`` () =
      test32R2
        Op.ADDIU
        None
        None
        (ThreeOperands (OpReg R.R28, OpReg R.R28, OpImm 0xffffffffffff85bcUL))
        [| 0x27uy; 0x9cuy; 0x85uy; 0xbcuy |]

      test32R2
        Op.CLZ
        None
        None
        (TwoOperands (OpReg R.R2, OpReg R.R7))
        [| 0x70uy; 0xe2uy; 0x10uy; 0x20uy |]

      test32R2
        Op.LUI
        None
        None
        (TwoOperands (OpReg R.R28, OpImm 4UL))
        [| 0x3cuy; 0x1cuy; 0x00uy; 0x04uy |]

      test32R2
        Op.SEB
        None
        None
        (TwoOperands (OpReg R.R10, OpReg R.R10))
        [| 0x7cuy; 0x0auy; 0x54uy; 0x20uy |]

      test32R2
        Op.SUBU
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R16, OpReg R.R19))
        [| 0x02uy; 0x13uy; 0x10uy; 0x23uy |]

  /// Shift And Rotate Operations
  [<TestClass>]
  type ShiftAndRotateClass () =
    [<TestMethod>]
    member __.``[MIPS32] Shift And Rotate Operations Parse Test`` () =
      test32R2
        Op.ROTR
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R4, OpShiftAmount 3UL))
        [| 0x00uy; 0x24uy; 0x10uy; 0xc2uy |]

      test32R2
        Op.SLL
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R2, OpShiftAmount 2UL))
        [| 0x00uy; 0x02uy; 0x10uy; 0x80uy |]

      test32R2
        Op.SRA
        None
        None
        (ThreeOperands (OpReg R.R5, OpReg R.R5, OpShiftAmount 2UL))
        [| 0x00uy; 0x05uy; 0x28uy; 0x83uy |]

      test32R2
        Op.SRL
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R5, OpShiftAmount 31UL))
        [| 0x00uy; 0x05uy; 0x17uy; 0xc2uy |]

  /// Logical And Bit-Field Operations
  [<TestClass>]
  type LogicalAndBitFieldClass () =
    [<TestMethod>]
    member __.``[MIPS32] Logical And Bit-Field operations Parse Test`` () =
      test32R2
        Op.AND
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R19, OpReg R.R2))
        [| 0x02uy; 0x62uy; 0x10uy; 0x24uy |]

      test32R2
        Op.ANDI
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R2, OpImm 1UL))
        [| 0x30uy; 0x42uy; 0x00uy; 0x01uy |]

      test32R2
        Op.EXT
        None
        None
        (FourOperands (OpReg R.R2, OpReg R.R2, OpImm 6UL, OpImm 1UL))
        [| 0x7cuy; 0x42uy; 0x01uy; 0x80uy |]

      test32R2
        Op.INS
        None
        None
        (FourOperands (OpReg R.R3, OpReg R.R6, OpImm 6UL, OpImm 1UL))
        [| 0x7cuy; 0xc3uy; 0x31uy; 0x84uy |]

      test32R2
        Op.NOR
        None
        None
        (ThreeOperands (OpReg R.R6, OpReg R.R0, OpReg R.R6))
        [| 0x00uy; 0x06uy; 0x30uy; 0x27uy |]

      test32R2
        Op.OR
        None
        None
        (ThreeOperands (OpReg R.R19, OpReg R.R3, OpReg R.R0))
        [| 0x00uy; 0x60uy; 0x98uy; 0x25uy |]

      test32R2
        Op.ORI
        None
        None
        (ThreeOperands (OpReg R.R19, OpReg R.R19, OpImm 65535UL))
        [| 0x36uy; 0x73uy; 0xffuy; 0xffuy |]

      test32R2
        Op.XOR
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R2, OpReg R.R6))
        [| 0x00uy; 0x46uy; 0x10uy; 0x26uy |]

      test32R2
        Op.XORI
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R19, OpImm 6UL))
        [| 0x3auy; 0x62uy; 0x00uy; 0x06uy |]

  /// Condition Testing And Conditional Move Operations
  [<TestClass>]
  type CondTestAndCondMoveClass () =
    [<TestMethod>]
    member __.``[MIPS32] Condition Testing And .. Operations Parse Test`` () =
      test32R2
        Op.MOVN
        None
        None
        (ThreeOperands (OpReg R.R3, OpReg R.R4, OpReg R.R2))
        [| 0x00uy; 0x82uy; 0x18uy; 0x0buy |]

      test32R2
        Op.MOVZ
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R0, OpReg R.R5))
        [| 0x00uy; 0x05uy; 0x10uy; 0x0auy |]

      test32R2
        Op.SLT
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R19, OpReg R.R16))
        [| 0x02uy; 0x70uy; 0x10uy; 0x2auy |]

      test32R2
        Op.SLTI
        None
        None
        (ThreeOperands (OpReg R.R23, OpReg R.R2, OpImm 2UL))
        [| 0x28uy; 0x57uy; 0x00uy; 0x02uy |]

      test32R2
        Op.SLTIU
        None
        None
        (ThreeOperands (OpReg R.R3, OpReg R.R2, OpImm 275UL))
        [| 0x2cuy; 0x43uy; 0x01uy; 0x13uy |]

      test32R2
        Op.SLTU
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R0, OpReg R.R2))
        [| 0x00uy; 0x02uy; 0x10uy; 0x2buy |]

  /// Multiply and Divide operations
  [<TestClass>]
  type MultiplyAndDivideClass () =
    [<TestMethod>]
    member __.``[MIPS32] Multiply and Divide operations Parse Test`` () =
      test32R2
        Op.DIVU
        None
        None
        (TwoOperands (OpReg R.R3, OpReg R.R2))
        [| 0x00uy; 0x62uy; 0x00uy; 0x1buy |]

      test32R2
        Op.MUL
        None
        None
        (ThreeOperands (OpReg R.R3, OpReg R.R4, OpReg R.R8))
        [| 0x70uy; 0x88uy; 0x18uy; 0x02uy |]

      test32R2
        Op.MULTU
        None
        None
        (TwoOperands (OpReg R.R23, OpReg R.R5))
        [| 0x02uy; 0xe5uy; 0x00uy; 0x19uy |]

  /// Accumulator Access operations
  [<TestClass>]
  type AccumulatorAccessClass () =
    [<TestMethod>]
    member __.``[MIPS32] Accumulator Access operations Parse Test`` () =
      test32R2
        Op.MFHI
        None
        None
        (OneOperand (OpReg R.R2))
        [| 0x00uy; 0x00uy; 0x10uy; 0x10uy |]

      test32R2
        Op.MFLO
        None
        None
        (OneOperand (OpReg R.R3))
        [| 0x00uy; 0x00uy; 0x18uy; 0x12uy |]

  /// Jumps And Branches Operations
  [<TestClass>]
  type JumpAndBranchesClass () =
    [<TestMethod>]
    member __.``[MIPS32] Jump And Branches operations Parse Test`` () =
      test32R2
        Op.BNE
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R0, OpAddr (Relative 4100L)))
        [| 0x14uy; 0x40uy; 0x04uy; 0x00uy |]

      test32R2
        Op.BLEZ
        None
        None
        (TwoOperands (OpReg R.R23, OpAddr (Relative 4444L)))
        [| 0x1auy; 0xe0uy; 0x04uy; 0x56uy |]

      test32R2
        Op.BGTZ
        None
        None
        (TwoOperands (OpReg R.R2, OpAddr (Relative -48L)))
        [| 0x1cuy; 0x40uy; 0xffuy; 0xf3uy |]

      test32R2
        Op.JR
        None
        None
        (OneOperand (OpReg R.R31))
        [| 0x03uy; 0xe0uy; 0x00uy; 0x08uy |]

      test32R2
        Op.JALR
        None
        None
        (OneOperand (OpReg R.R25))
        [| 0x03uy; 0x20uy; 0xf8uy; 0x09uy |]

      test32R2
        Op.BAL
        None
        None
        (OneOperand (OpAddr (Relative 63608L)))
        [| 0x04uy; 0x11uy; 0x3euy; 0x1duy |]

      test32R2
        Op.BLTZ
        None
        None
        (TwoOperands (OpReg R.R2, OpAddr (Relative 424L)))
        [| 0x04uy; 0x40uy; 0x00uy; 0x69uy |]

      test32R2
        Op.BGEZ
        None
        None
        (TwoOperands (OpReg R.R22, OpAddr (Relative 1404L)))
        [| 0x06uy; 0xc1uy; 0x01uy; 0x5euy |]

  /// Load And Store operations
  [<TestClass>]
  type LoadAndStoreClass () =
    [<TestMethod>]
    member __.``[MIPS32] Load And Store operations Parse Test`` () =
      test32R2
        Op.LB
        None
        None
        (TwoOperands (OpReg R.R2, OpMem (R.R2, Imm 0L, 8<rt>)))
        [| 0x80uy; 0x42uy; 0x00uy; 0x00uy |]

      test32R2
        Op.LBU
        None
        None
        (TwoOperands (OpReg R.R2, OpMem (R.R19, Imm 17432L, 8<rt>)))
        [| 0x92uy; 0x62uy; 0x44uy; 0x18uy |]

      test32R2
        Op.LHU
        None
        None
        (TwoOperands (OpReg R.R2, OpMem (R.R29, Imm 170L, 16<rt>)))
        [| 0x97uy; 0xa2uy; 0x00uy; 0xaauy |]

      test32R2
        Op.LW
        None
        None
        (TwoOperands (OpReg R.R2, OpMem (R.R28, Imm -032060L, 32<rt>)))
        [| 0x8fuy; 0x82uy; 0x82uy; 0xc4uy |]

      test32R2
        Op.SB
        None
        None
        (TwoOperands (OpReg R.R4, OpMem (R.R22, Imm 17372L, 8<rt>)))
        [| 0xa2uy; 0xc4uy; 0x43uy; 0xdcuy |]

      test32R2
        Op.SH
        None
        None
        (TwoOperands (OpReg R.R2, OpMem (R.R29, Imm 184L, 16<rt>)))
        [| 0xa7uy; 0xa2uy; 0x00uy; 0xb8uy |]

      test32R2
        Op.SW
        None
        None
        (TwoOperands (OpReg R.R28, OpMem (R.R29, Imm 16L, 32<rt>)))
        [| 0xafuy; 0xbcuy; 0x00uy; 0x10uy |]

      test32R2
        Op.SWL
        None
        None
        (TwoOperands (OpReg R.R4, OpMem (R.R2, Imm 0L, 32<rt>)))
        [| 0xa8uy; 0x44uy; 0x00uy; 0x00uy |]

      test32R2
        Op.SWR
        None
        None
        (TwoOperands (OpReg R.R4, OpMem (R.R2, Imm 3L, 32<rt>)))
        [| 0xb8uy; 0x44uy; 0x00uy; 0x03uy |]

  /// Floating Point operations
  [<TestClass>]
  type FloatingPointClass () =
    [<TestMethod>]
    member __.``[MIPS32] Floating Point operations Parse Test`` () =
      test32R2
        Op.ADD
        None
        (Some Fmt.S)
        (ThreeOperands (OpReg R.F2, OpReg R.F4, OpReg R.F2))
        [| 0x46uy; 0x02uy; 0x20uy; 0x80uy |]

      test32R2
        Op.ADD
        None
        (Some Fmt.D)
        (ThreeOperands (OpReg R.F0, OpReg R.F0, OpReg R.F2))
        [| 0x46uy; 0x22uy; 0x00uy; 0x00uy |]

      test32R2
        Op.SUB
        None
        (Some Fmt.D)
        (ThreeOperands (OpReg R.F12, OpReg R.F12, OpReg R.F0))
        [| 0x46uy; 0x20uy; 0x63uy; 0x01uy |]

      test32R2
        Op.DIV
        None
        (Some Fmt.D)
        (ThreeOperands (OpReg R.F0, OpReg R.F0, OpReg R.F2))
        [| 0x46uy; 0x22uy; 0x00uy; 0x03uy |]

      test32R2
        Op.DIV
        None
        (Some Fmt.S)
        (ThreeOperands (OpReg R.F0, OpReg R.F0, OpReg R.F2))
        [| 0x46uy; 0x02uy; 0x00uy; 0x03uy |]

      test32R2
        Op.MOV
        None
        (Some Fmt.D)
        (TwoOperands (OpReg R.F20, OpReg R.F0))
        [| 0x46uy; 0x20uy; 0x05uy; 0x06uy |]

      test32R2
        Op.MFC1
        None
        None
        (TwoOperands (OpReg R.R20, OpReg R.F0))
        [| 0x44uy; 0x14uy; 0x00uy; 0x00uy |]

      test32R2
        Op.MTC1
        None
        None
        (TwoOperands (OpReg R.R0, OpReg R.F6))
        [| 0x44uy; 0x80uy; 0x30uy; 0x00uy |]

      test32R2
        Op.LDC1
        None
        None
        (TwoOperands (OpReg R.F4, OpMem (R.R2, Imm 2632L, 32<rt>)))
        [| 0xd4uy; 0x44uy; 0x0auy; 0x48uy |]

      test32R2
        Op.LWC1
        None
        None
        (TwoOperands (OpReg R.F0, OpMem (R.R3, Imm 8L, 32<rt>)))
        [| 0xc4uy; 0x60uy; 0x00uy; 0x08uy |]

      test32R2
        Op.SDC1
        None
        None
        (TwoOperands (OpReg R.F0, OpMem (R.R29, Imm 16L, 32<rt>)))
        [| 0xf7uy; 0xa0uy; 0x00uy; 0x10uy |]

      test32R2
        Op.SWC1
        None
        None
        (TwoOperands (OpReg R.F0, OpMem (R.R4, Imm 4L, 32<rt>)))
        [| 0xe4uy; 0x80uy; 0x00uy; 0x04uy |]

      test32R2
        Op.C
        (Some Condition.LT)
        (Some Fmt.S)
        (TwoOperands (OpReg R.F2, OpReg R.F0))
        [| 0x46uy; 0x00uy; 0x10uy; 0x3cuy |]

      test32R2
        Op.CVTD
        None
        (Some Fmt.W)
        (TwoOperands (OpReg R.F0, OpReg R.F0))
        [| 0x46uy; 0x80uy; 0x00uy; 0x21uy |]

      test32R2
        Op.CVTS
        None
        (Some Fmt.D)
        (TwoOperands (OpReg R.F0, OpReg R.F0))
        [| 0x46uy; 0x20uy; 0x00uy; 0x20uy |]

      test32R2
        Op.TRUNCW
        None
        (Some Fmt.D)
        (TwoOperands (OpReg R.F0, OpReg R.F0))
        [| 0x46uy; 0x20uy; 0x00uy; 0x0duy |]

      test32R2
        Op.TRUNCW
        None
        (Some Fmt.S)
        (TwoOperands (OpReg R.F0, OpReg R.F0))
        [| 0x46uy; 0x00uy; 0x00uy; 0x0duy |]

  /// ETC Operations
  [<TestClass>]
  type ETCClass () =
    [<TestMethod>]
    member __.``[MIPS32] ETC Operations Parse Test`` () =
      test32R2
        Op.TEQ
        None
        None
        (TwoOperands (OpReg R.R2, OpReg R.R0))
        [| 0x00uy; 0x40uy; 0x01uy; 0xf4uy |]

      test32R2
        Op.BC1T
        None
        None
        (TwoOperands (OpImm 6UL, OpAddr (Relative 20L)))
        [| 0x45uy; 0x19uy; 0x00uy; 0x04uy |]

      test32R2
        Op.BC1F
        None
        None
        (OneOperand (OpAddr (Relative 108L)))
        [| 0x45uy; 0x00uy; 0x00uy; 0x1auy |]
