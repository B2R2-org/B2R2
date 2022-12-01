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

module B2R2.FrontEnd.Tests.TMS320

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter.TMS320C6000

let private test opcode unit oprs (bytes: byte[]) =
  let reader = BinReader.binReaderLE
  let span = System.ReadOnlySpan bytes
  let mutable inpar = false
  let ins = Parser.parse span reader &inpar 0UL
  Assert.AreEqual (ins.Info.Opcode, opcode)
  Assert.AreEqual (ins.Info.FunctionalUnit, unit)
  Assert.AreEqual (ins.Info.Operands, oprs)

/// .D Unit Instructions
[<TestClass>]
type DUnitTest () =
  [<TestMethod>]
  member __.``[TMS320] .D Unit Insturctions Parse Test`` () =
    test Opcode.ADD D1XUnit
         (ThreeOperands (OpReg R.A1, OpReg R.B12, OpReg R.A6))
         [| 0xB0uy; 0x3Auy; 0x30uy; 0x03uy |]

    test Opcode.LDB D1Unit // *-A5[4],A7
         (TwoOperands (OprMem (R.A5, NegativeOffset, UCst5 4UL),
                       OpReg R.A7))
         [| 0x24uy; 0x80uy; 0x94uy; 0x03uy |]

/// .L Unit Instructions
[<TestClass>]
type LUnitTest () =
  [<TestMethod>]
  member __.``[TMS320] .L Unit Insturctions Parse Test`` () =
    test Opcode.ABS2 L1Unit (TwoOperands (OpReg R.A0, OpReg R.A2))
         [| 0x58uy; 0x83uy; 0x00uy; 0x01uy |]

    test Opcode.SUBDP L1XUnit
         (ThreeOperands (RegisterPair (R.A1, R.A0),
                         RegisterPair (R.B3, R.B2),
                         RegisterPair (R.A5, R.A4)))
         [| 0x38uy; 0x13uy; 0x08uy; 0x02uy |]

/// .M Unit Instructions
[<TestClass>]
type MUnitTest () =
  [<TestMethod>]
  member __.``[TMS320] .M Unit Insturctions Parse Test`` () =
    test Opcode.AVG2 M1Unit
         (ThreeOperands (OpReg R.A0, OpReg R.A1, OpReg R.A2))
         [| 0xF0uy; 0x04uy; 0x04uy; 0x01uy |]

    test Opcode.MPY2IR M1XUnit
         (ThreeOperands (OpReg R.A2, OpReg R.B5,
                         RegisterPair (R.A9, R.A8)))
         [| 0xF0uy; 0x53uy; 0x14uy; 0x14uy |]

/// .S Unit Instructions
[<TestClass>]
type SUnitTest () =
  [<TestMethod>]
  member __.``[TMS320] .S Unit Insturctions Parse Test`` () =
    test Opcode.ABSDP S1Unit
         (TwoOperands (RegisterPair (R.A1, R.A0), RegisterPair (R.A3, R.A2)))
         [| 0x20uy; 0x0Buy; 0x04uy; 0x01uy |]

    test Opcode.SHRU S1Unit
         (ThreeOperands (RegisterPair (R.A5, R.A4), Immediate 0x0UL,
                         RegisterPair (R.A1, R.A0)))
         [| 0x20uy; 0x09uy; 0x10uy; 0x00uy |]

/// No Unit Instructions
[<TestClass>]
type NoUnitTest () =
  [<TestMethod>]
  member __.``[TMS320] No Unit Insturctions Parse Test`` () =
    test Opcode.IDLE NoUnit NoOperand
         [| 0x00uy; 0xE0uy; 0x01uy; 0x00uy |]

    test Opcode.NOP NoUnit (OneOperand (Immediate 5UL))
         [| 0x00uy; 0x80uy; 0x00uy; 0x00uy |]

