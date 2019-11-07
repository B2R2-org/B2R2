namespace B2R2.Assembler.Tests

open B2R2
open B2R2.Assembler
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type TestClass () =

  [<TestMethod>]
  member __.``[Assembler] Parse Test (MIPS)`` () =
    let mips =
      { Arch = Arch.MIPS32; Endian = Endian.Big; WordSize = WordSize.Bit32 }
    let assembler = AsmInterface (mips, 0UL)
    // Test register parse
    let result = assembler.Run "add $s0 $1 v0"
    printf "%A\n" result
    // Test imm parse
    let result = assembler.Run " jalr 0"
    printf "%A\n" result
    // Test addr parse
    let result = assembler.Run "jr ($s0)"
    printf "%A\n" result
    // Test label parse
    let result =
      assembler.Run
       "someLabel:
        beq $4, r0, 0xE5B0
        addiu a1, a2, 0x1
        sw v0, 4(v1)
        c.lt.s f2, f4, f6
        jr someLabel"
    printf "%A\n" result
