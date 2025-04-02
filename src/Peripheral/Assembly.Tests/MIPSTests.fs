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

namespace B2R2.Peripheral.Assembly.Tests

open B2R2
open B2R2.Peripheral.Assembly
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.FrontEnd.MIPS

[<TestClass>]
type MIPSTests () =
  let mips =
      { Arch = Architecture.MIPS32
        Endian = Endian.Big
        WordSize = WordSize.Bit32 }
  let assembler = MIPS.AsmParser (mips, 0UL)
  let newInfo = MIPS.ParserHelper.newInfo

  [<TestMethod>]
  member __.``[MipsAssembly] Test add with and three operands ``() =
    let result = assembler.Run "add $s0 $1 v0"
    let operands =
       ThreeOperands (OpReg Register.R16,
                      OpReg Register.R1,
                      OpReg Register.R2)
    let answer =
      [ newInfo mips 0UL Opcode.ADD None None operands ]
    Assert.AreEqual (answer, result)

  [<TestMethod>]
  member __.``[MipsAssembly] Test jmp with immediate address ``() =
    let result = assembler.Run " jalr 0"
    let operands = OneOperand (OpImm 0UL)
    let answer =
      [ newInfo mips 0UL Opcode.JALR None None operands ]
    Assert.AreEqual (answer, result)

  [<TestMethod>]
  member __.``[MipsAssembly] Test jmp with memmory access operand``() =
    let result = assembler.Run "jr ($s0)"
    let operands = OneOperand (OpMem (Register.R16, Imm 0L, 32<rt>))
    let answer =
      [ newInfo mips 0UL Opcode.JR None None operands ]
    Assert.AreEqual (answer, result)

  [<TestMethod>]
  member __.``[MipsAssembly] Test Label and Jump to Label Instruction``() =
    let result =
      assembler.Run "someLabel:
                     beq $4, r0, 0x1
                     jr someLabel"
    let operands1 =
      ThreeOperands (OpReg Register.R4,
                     OpReg Register.R0,
                     OpImm 1UL)
    let operands2 = OneOperand (OpAddr (Relative -8L))
    let answer =
      [ newInfo mips 0UL Opcode.BEQ None None operands1;
        newInfo mips 4UL Opcode.JR None None operands2 ]
    Assert.AreEqual (answer, result)

