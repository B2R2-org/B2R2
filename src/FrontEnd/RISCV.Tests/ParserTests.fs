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

namespace B2R2.FrontEnd.RISCV.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.RISCV
open type Opcode
open type Register

/// Shortcut for creating operands.
[<AutoOpen>]
module private Shortcut =
  type O =
    static member Reg(reg) = OpReg reg

    static member Imm(imm: uint64) = OpImm imm

    static member Shamt(imm: uint64) = OpShiftAmount imm

    static member Mem(b, offset, size) = OpMem(b, Some(Imm offset), size)

    static member Rel(offset) = OpAddr(Relative offset)

  let parserFor wordSize =
    let isa = ISA(Architecture.RISCV, Endian.Little, wordSize)
    RISCVParser(isa, BinReader.Init Endian.Little) :> IInstructionParsable

  let parse wordSize (bytes: byte[]) =
    (parserFor wordSize).Parse(System.ReadOnlySpan bytes, 0UL)

  /// Checks that the given word says the given instruction on the given width.
  let testRISCV wordSize bytes (opcode: Opcode, operands: Operands) =
    let ins = parse wordSize bytes :?> Instruction
    Assert.AreEqual<Opcode>(opcode, ins.Opcode)
    Assert.AreEqual<Operands>(operands, ins.Operands)

  /// Checks that the given word says nothing on the given width, the
  /// instruction it would name being one that width does not have.
  let testUnsupported wordSize (byteString: string) =
    let bytes = ByteArray.ofHexString byteString
    Assert.Throws<ParsingFailureException>(fun () ->
      parse wordSize bytes |> ignore)
    |> ignore

  let operandsFromArray oprList =
    let oprArr = Array.ofList oprList
    match oprArr.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprArr[0]
    | 2 -> TwoOperands(oprArr[0], oprArr[1])
    | 3 -> ThreeOperands(oprArr[0], oprArr[1], oprArr[2])
    | 4 -> FourOperands(oprArr[0], oprArr[1], oprArr[2], oprArr[3])
    | _ -> Terminator.futureFeature ()

  let ( ** ) opcode oprList = opcode, operandsFromArray oprList

  let ( ++ ) byteString pair = ByteArray.ofHexString byteString, pair

[<TestClass>]
type ParserTests() =
  [<TestMethod>]
  member _.``[RISCV32] ADDI (immediate)``() =
    "13851500"
    ++ (ADDI ** [ O.Reg X10; O.Reg X11; O.Imm 0x1UL ])
    ||> testRISCV WordSize.Bit32

  [<TestMethod>]
  member _.``[RISCV64] ADDI (immediate)``() =
    "13851500"
    ++ (ADDI ** [ O.Reg X10; O.Reg X11; O.Imm 0x1UL ])
    ||> testRISCV WordSize.Bit64

  [<TestMethod>]
  member _.``[RISCV32] ADDI reads a negative number to its own width``() =
    "1385f5ff"
    ++ (ADDI ** [ O.Reg X10; O.Reg X11; O.Imm 0xffffffffUL ])
    ||> testRISCV WordSize.Bit32

  [<TestMethod>]
  member _.``[RISCV64] ADDI reads a negative number to its own width``() =
    "1385f5ff"
    ++ (ADDI ** [ O.Reg X10; O.Reg X11; O.Imm 0xffffffffffffffffUL ])
    ||> testRISCV WordSize.Bit64

  [<TestMethod>]
  member _.``[RISCV32] ADD (register)``() =
    "3385c500"
    ++ (ADD ** [ O.Reg X10; O.Reg X11; O.Reg X12 ])
    ||> testRISCV WordSize.Bit32

  [<TestMethod>]
  member _.``[RISCV32] LW (load word)``() =
    "03a58500"
    ++ (LW ** [ O.Reg X10; O.Mem(X11, 8L, 32<rt>) ])
    ||> testRISCV WordSize.Bit32

  [<TestMethod>]
  member _.``[RISCV32] SLLI (shift by an immediate)``() =
    "1395f501"
    ++ (SLLI ** [ O.Reg X10; O.Reg X11; O.Shamt 0x1fUL ])
    ||> testRISCV WordSize.Bit32

  [<TestMethod>]
  member _.``[RISCV64] SLLI shifts across a whole doubleword``() =
    "13950502"
    ++ (SLLI ** [ O.Reg X10; O.Reg X11; O.Shamt 0x20UL ])
    ||> testRISCV WordSize.Bit64

  [<TestMethod>]
  member _.``[RISCV32] SLLI cannot shift past a word``() =
    testUnsupported WordSize.Bit32 "13950502"

  [<TestMethod>]
  member _.``[RISCV64] LD (load doubleword)``() =
    "03b58500"
    ++ (LD ** [ O.Reg X10; O.Mem(X11, 8L, 64<rt>) ])
    ||> testRISCV WordSize.Bit64

  [<TestMethod>]
  member _.``[RISCV32] LD is not a 32-bit form``() =
    testUnsupported WordSize.Bit32 "03b58500"

  [<TestMethod>]
  member _.``[RISCV64] SD (store doubleword)``() =
    "23b4a500"
    ++ (SD ** [ O.Reg X10; O.Mem(X11, 8L, 64<rt>) ])
    ||> testRISCV WordSize.Bit64

  [<TestMethod>]
  member _.``[RISCV32] SD is not a 32-bit form``() =
    testUnsupported WordSize.Bit32 "23b4a500"

  [<TestMethod>]
  member _.``[RISCV64] ADDIW (add a word immediate)``() =
    "1b851500"
    ++ (ADDIW ** [ O.Reg X10; O.Reg X11; O.Imm 0x1UL ])
    ||> testRISCV WordSize.Bit64

  [<TestMethod>]
  member _.``[RISCV32] ADDIW is not a 32-bit form``() =
    testUnsupported WordSize.Bit32 "1b851500"

  [<TestMethod>]
  member _.``[RISCV64] ADDW (add a word)``() =
    "3b85c500"
    ++ (ADDW ** [ O.Reg X10; O.Reg X11; O.Reg X12 ])
    ||> testRISCV WordSize.Bit64

  [<TestMethod>]
  member _.``[RISCV32] ADDW is not a 32-bit form``() =
    testUnsupported WordSize.Bit32 "3b85c500"

  /// <summary>
  /// The encoding RV64 gives to the addition on a word is the one RV32 gives
  /// to the compressed jump that keeps where it came from, so the same word
  /// says a different instruction on each.
  /// </summary>
  [<TestMethod>]
  member _.``[RISCV64] C.ADDIW is what RV32 reads as C.JAL``() =
    "0525"
    ++ (CdotADDIW ** [ O.Reg X10; O.Reg X10; O.Imm 0x1UL ])
    ||> testRISCV WordSize.Bit64

  [<TestMethod>]
  member _.``[RISCV32] C.JAL keeps where it came from``() =
    "0525"
    ++ (CdotJAL ** [ O.Reg X1; O.Rel 0x620L ])
    ||> testRISCV WordSize.Bit32

  [<TestMethod>]
  member _.``[RISCV64] C.LD is what RV32 reads as C.FLW``() =
    "4460"
    ++ (CdotLD ** [ O.Reg X9; O.Mem(X8, 128L, 64<rt>) ])
    ||> testRISCV WordSize.Bit64

  [<TestMethod>]
  member _.``[RISCV32] C.FLW loads a word of floating point``() =
    "4460"
    ++ (CdotFLW ** [ O.Reg F9; O.Mem(X8, 4L, 32<rt>) ])
    ||> testRISCV WordSize.Bit32

  [<TestMethod>]
  member _.``[RISCV32] C.FSW stores a word of floating point``() =
    "44e0"
    ++ (CdotFSW ** [ O.Reg F9; O.Mem(X8, 4L, 32<rt>) ])
    ||> testRISCV WordSize.Bit32

  [<TestMethod>]
  member _.``[RISCV32] C.FLWSP loads through the stack pointer``() =
    "1265"
    ++ (CdotFLWSP ** [ O.Reg F10; O.Mem(X2, 4L, 32<rt>) ])
    ||> testRISCV WordSize.Bit32

  [<TestMethod>]
  member _.``[RISCV32] C.FSWSP stores through the stack pointer``() =
    "2ae2"
    ++ (CdotFSWSP ** [ O.Reg F10; O.Mem(X2, 4L, 32<rt>) ])
    ||> testRISCV WordSize.Bit32

  [<TestMethod>]
  member _.``[RISCV64] C.SLLI shifts across a whole doubleword``() =
    "0215"
    ++ (CdotSLLI ** [ O.Reg X10; O.Reg X10; O.Shamt 0x20UL ])
    ||> testRISCV WordSize.Bit64

  [<TestMethod>]
  member _.``[RISCV32] C.SLLI cannot shift past a word``() =
    testUnsupported WordSize.Bit32 "0215"

// vim: set tw=80 sts=2 sw=2:
