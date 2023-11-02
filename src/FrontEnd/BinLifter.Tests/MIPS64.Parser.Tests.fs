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

module MIPS64 =
  open B2R2.FrontEnd.BinLifter.MIPS

  let private test arch endian opcode oprs (bytes: byte[]) =
    let reader = BinReader.Init endian
    let span = System.ReadOnlySpan bytes
    let ins = Parser.parse span reader arch WordSize.Bit64 0UL
    let opcode' = ins.Info.Opcode
    let oprs' = ins.Info.Operands
    Assert.AreEqual (opcode', opcode)
    Assert.AreEqual (oprs', oprs)

  let private test64R2 = test Architecture.MIPS64 Endian.Big

  /// Arithmetic operations
  [<TestClass>]
  type ArithmeticClass () =
    [<TestMethod>]
    member __.``[MIPS64] Arithmetic operations Parse Test`` () =
      test64R2
        Op.DADDU
        (ThreeOperands (OpReg R.R15, OpReg R.R21, OpReg R.R29))
        [| 0x02uy; 0xbduy; 0x78uy; 0x2duy |]

      test64R2
        Op.DADDIU
        (ThreeOperands (OpReg R.R13, OpReg R.R6, OpImm 0xffffffffffffccd5UL))
        [| 0x64uy; 0xcduy; 0xccuy; 0xd5uy |]

      test64R2
        Op.DSUBU
        (ThreeOperands (OpReg R.R26, OpReg R.R17, OpReg R.R9))
        [| 0x02uy; 0x29uy; 0xd0uy; 0x2fuy |]

  /// Shift And Rotate operations
  [<TestClass>]
  type ShiftAndRotateClass () =
    [<TestMethod>]
    member __.``[MIPS64] Shift And Rotate operations Parse Test`` () =
      test64R2
        Op.DROTR
        (ThreeOperands (OpReg R.R30, OpReg R.R13, OpShiftAmount 0x1aUL))
        [| 0x00uy; 0x2duy; 0xf6uy; 0xbauy |]

      test64R2
        Op.DSLL
        (ThreeOperands (OpReg R.R29, OpReg R.R14, OpShiftAmount 0x1bUL))
        [| 0x00uy; 0x0euy; 0xeeuy; 0xf8uy |]

      test64R2
        Op.DSLL32
        (ThreeOperands (OpReg R.R28, OpReg R.R17, OpShiftAmount 0x15UL))
        [| 0x00uy; 0x11uy; 0xe5uy; 0x7cuy |]

      test64R2
        Op.DSLLV
        (ThreeOperands (OpReg R.R30, OpReg R.R26, OpReg R.R21))
        [| 0x02uy; 0xbauy; 0xf0uy; 0x14uy |]

      test64R2
        Op.DSRA
        (ThreeOperands (OpReg R.R30, OpReg R.R14, OpShiftAmount 0x1fUL))
        [| 0x00uy; 0x0euy; 0xf7uy; 0xfbuy |]

      test64R2
        Op.DSRA32
        (ThreeOperands (OpReg R.R26, OpReg R.R15, OpShiftAmount 0x7UL))
        [| 0x00uy; 0x0fuy; 0xd1uy; 0xffuy |]

  /// Logical and Bit-Field Operations
  [<TestClass>]
  type LogicalAndBitFieldClass () =
    [<TestMethod>]
    member __.``[MIPS64] Logical and Bit-Field operations Parse Test`` () =
      test64R2
        Op.DEXT
        (FourOperands (OpReg R.R29, OpReg R.R10, OpImm 0x2UL, OpImm 0xeUL))
        [| 0x7duy; 0x5duy; 0x68uy; 0x83uy |]

      test64R2
        Op.DINS
        (FourOperands (OpReg R.R21, OpReg R.R15, OpImm 0x9UL, OpImm 0x11UL))
        [| 0x7duy; 0xf5uy; 0xcauy; 0x47uy |]

  /// Multiply and Divide operations
  [<TestClass>]
  type MultiplyAndDivideClass () =
    [<TestMethod>]
    member __.``[MIPS64] Multiply and Divide operations Parse Test`` () =
      test64R2
        Op.DDIVU
        (TwoOperands (OpReg R.R30, OpReg R.R3))
        [| 0x03uy; 0xc3uy; 0x00uy; 0x1fuy |]

      test64R2
        Op.DMULT
        (TwoOperands (OpReg R.R24, OpReg R.R14))
        [| 0x03uy; 0x0euy; 0x00uy; 0x1cuy |]

      test64R2
        Op.DMULTU
        (TwoOperands (OpReg R.R17, OpReg R.R18))
        [| 0x02uy; 0x32uy; 0x00uy; 0x1duy |]

  /// Load and Store operations
  [<TestClass>]
  type LoadAndStoreClass () =
    [<TestMethod>]
    member __.``[MIPS64] Load and Store operations Parse Test`` () =
      test64R2
        Op.LD
        (TwoOperands (OpReg R.R29, OpMem (R.R26, Imm 0x2afdL, 64<rt>)))
        [| 0xdfuy; 0x5duy; 0x2auy; 0xfduy |]

      test64R2
        Op.LWU
        (TwoOperands (OpReg R.R17, OpMem (R.R24, Imm -0x52ffL, 32<rt>)))
        [| 0x9fuy; 0x11uy; 0xaduy; 0x01uy |]

      test64R2
        Op.SD
        (TwoOperands (OpReg R.R5, OpMem (R.R17, Imm 0x380aL, 64<rt>)))
        [| 0xfeuy; 0x25uy; 0x38uy; 0x0auy |]

      test64R2
        Op.SDL
        (TwoOperands (OpReg R.R12, OpMem (R.R26, Imm 0x3f02L, 64<rt>)))
        [| 0xb3uy; 0x4cuy; 0x3fuy; 0x02uy |]

      test64R2
        Op.SDR
        (TwoOperands (OpReg R.R11, OpMem (R.R6, Imm -0x78ebL, 64<rt>)))
        [| 0xb4uy; 0xcbuy; 0x87uy; 0x15uy |]
