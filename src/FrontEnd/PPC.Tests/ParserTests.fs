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

namespace B2R2.FrontEnd.PPC.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.PPC
open type Opcode
open type Register

/// Shortcut for creating operands.
[<AutoOpen>]
module private Shortcut =
  type O =
    static member Reg(r) =
      OprReg r

    static member Imm(v) =
      OprImm v

  let test (isa: ISA) opcode (opr: Operands) bytes =
    let reader = BinReader.Init isa.Endian
    let parser = PPCParser(isa, reader) :> IInstructionParsable
    let span = System.ReadOnlySpan(bytes: byte[])
    let ins = parser.Parse(span, 0UL) :?> Instruction
    let opcode' = ins.Opcode
    let oprs' = ins.Operands
    Assert.AreEqual<Opcode>(opcode, opcode')
    Assert.AreEqual<Operands>(opr, oprs')

  let testPPC wordSz bytes (opcode, operands) =
    let isa = ISA(Architecture.PPC, Endian.Big, wordSz)
    test isa opcode operands bytes

  let operandsFromArray oprList =
    let oprArr = Array.ofList oprList
    match oprArr.Length with
    | 0 -> NoOperand
    | 2 -> TwoOperands(oprArr[0], oprArr[1])
    | 3 -> ThreeOperands(oprArr[0], oprArr[1], oprArr[2])
    | 4 -> FourOperands(oprArr[0], oprArr[1], oprArr[2], oprArr[3])
    | _ -> Terminator.futureFeature ()

  let ( ** ) opcode oprList = opcode, operandsFromArray oprList

  let ( ++ ) byteString pair = ByteArray.ofHexString byteString, pair

[<TestClass>]
type ArithmeticClass() =
  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (1)``() =
    "38622408"
    ++ (ADDI ** [ O.Reg R3; O.Reg R2; O.Imm 0x2408UL ])
    ||> testPPC WordSize.Bit64
