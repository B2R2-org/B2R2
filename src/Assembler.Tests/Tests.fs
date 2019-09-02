namespace B2R2.Assembler.Tests

open B2R2.Assembler.MIPS.Parser
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type TestClass () =

  [<TestMethod>]
  member __.``[Assembler] Parse Test (MIPS)`` () =
    // Test register parse
    let result = parse "add $s0 $1 v0"
    printf "%A\n" result
    // Test imm parse
    let result = parse "sub 1, 1+1, 1-1; jalr 0, -1, 0b1; jr 0x1, 0o7"
    printf "%A\n" result
    // Test addr parse
    let result = parse "jr ($s0), 1($s0), -1($s0)"
    printf "%A\n" result
    // Test label parse
    let result = parse "1:\n2: jr ($s0), 1($s0), -1($s0)"
    printf "%A\n" result
