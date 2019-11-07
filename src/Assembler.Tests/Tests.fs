namespace B2R2.Assembler.Tests

open B2R2
open B2R2.Assembler
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.FrontEnd.MIPS

[<TestClass>]
type TestClass () =
  let mips =
      { Arch = Arch.MIPS32; Endian = Endian.Big; WordSize = WordSize.Bit32 }
  let assembler = AsmInterface (mips, 0UL)
  let newInfo = MIPS.ParserHelper.newInfo
 
  [<TestMethod>]
  member __.``[MipsAssembly] Test add with and three operands ``() =
    let result = assembler.Run "add $s0 $1 v0"
    let operands =
       ThreeOperands (Operand.Register Register.R16,
                      Operand.Register Register.R1,
                      Operand.Register Register.R2)
    let answer =
      [ newInfo mips 0UL Opcode.ADD None None operands ]
    Assert.AreEqual (answer, result)

  [<TestMethod>]
  member __.``[MipsAssembly] Test jmp with immediate address ``() =
    let result = assembler.Run " jalr 0"
    let operands = OneOperand (Operand.Immediate 0UL)
    let answer =
      [ newInfo mips 0UL Opcode.JALR None None operands ]
    Assert.AreEqual (answer, result)

  [<TestMethod>]
  member __.``[MipsAssembly] Test jmp with memmory access operand``() =
    let result = assembler.Run "jr ($s0)"
    let operands = OneOperand (Operand.Memory (Register.R16, 0L, 32<rt>))
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
      ThreeOperands (Operand.Register Register.R4,
                     Operand.Register Register.R0,
                     Operand.Immediate 1UL)
    let operands2 = OneOperand (Operand.Address (Relative -8L))
    let answer =
      [ newInfo mips 0UL Opcode.BEQ None None operands1;
        newInfo mips 4UL Opcode.JR None None operands2 ]
    Assert.AreEqual (answer, result)