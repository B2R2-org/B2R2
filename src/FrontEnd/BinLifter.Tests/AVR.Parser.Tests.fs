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

module B2R2.FrontEnd.Tests.AVRParser

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter.AVR

let private test opcode oprs bytes =
  let reader = BinReader.Init (bytes, Endian.Little)
  let ins = Parser.parse reader 0UL 0
  Assert.AreEqual (ins.Info.Opcode, opcode)
  Assert.AreEqual (ins.Info.Operands, oprs)

[<TestClass>]
type AVRUnitTest () =
  [<TestMethod>]
  member __.``[AVR] No Operand Insturctions Parse Test`` () =
    test Opcode.RET
        (NoOperand)
        [| 0x08uy; 0x95uy |]

  [<TestMethod>]
  member __.``[AVR] One Operand Insturctions Parse Test`` () =
    test Opcode.BREQ
        (OneOperand (OprAddr 96))
        [| 0x81uy; 0xf1uy |]
    test Opcode.BRGE
        (OneOperand (OprAddr 44))
        [| 0xB4uy; 0xf4uy |]

  [<TestMethod>]
  member __.``[AVR] Two Register Operands Insturctions Parse Test`` () =
    test Opcode.ADD
        (TwoOperands (OprReg R.R12, OprReg R.R25))
        [| 0xC9uy; 0x0Euy |]
    test Opcode.MOV
        (TwoOperands (OprReg R.R14, OprReg R.R1))
        [| 0xE1uy; 0x2Cuy |]

  [<TestMethod>]
  member __.``[AVR] Memory Operands Insturctions Parse Test`` () =
    test Opcode.ST
        (TwoOperands (OprMemory (PostIdxMode (R.X)), OprReg R.R1))
        [| 0x1Duy; 0x92uy |]
    test Opcode.LDD
        (TwoOperands (OprReg R.R6, OprMemory (DispMode ((R.Y, 1)))))
        [| 0x69uy; 0x80uy |]

  [<TestMethod>]
  member __.``[AVR] Immediate Operand Insturction Parse Test`` () =
    test Opcode.LDI
        (TwoOperands (OprReg R.R24, OprImm 0xff))
        [| 0x8Fuy; 0xEFuy |]
    

