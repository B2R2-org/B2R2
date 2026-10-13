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

namespace B2R2.FrontEnd.MIPS.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.MIPS

/// <summary>
/// One test for each instruction MD00077 describes, ADDIU to ZEW. Each reads
/// words of the instruction and checks the text, and each word is one binutils'
/// objdump reads as the same instruction with the same operands, so what is
/// asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualMIPS16x64ParserTests1() =
  let isa =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSISAMode.MIPS16)

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser = Parser(isa, BinReader.Init isa.Endian) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  [<TestMethod>]
  member _.``MD00077 ADDIU``() =
    testDisasm "00006500" "addiu s0, sp, 0x0"
    testDisasm "00016500" "addiu s0, sp, 0x4"
    testDisasm "00026500" "addiu s0, sp, 0x8"
    testDisasm "00036500" "addiu s0, sp, 0xc"

  [<TestMethod>]
  member _.``MD00077 ADDU``() =
    testDisasm "e0016500" "addu s0, s0, s0"
    testDisasm "e0056500" "addu s1, s0, s0"
    testDisasm "e0096500" "addu v0, s0, s0"
    testDisasm "e00d6500" "addu v1, s0, s0"

  [<TestMethod>]
  member _.``MD00077 AND``() =
    testDisasm "e80c6500" "and s0, s0, s0"
    testDisasm "e82c6500" "and s0, s0, s1"
    testDisasm "e84c6500" "and s0, s0, v0"
    testDisasm "e86c6500" "and s0, s0, v1"

  [<TestMethod>]
  member _.``MD00077 B``() =
    testDisasm "10006500" "b 0x2"
    testDisasm "10016500" "b 0x4"
    testDisasm "10026500" "b 0x6"
    testDisasm "10036500" "b 0x8"

  [<TestMethod>]
  member _.``MD00077 BEQZ``() =
    testDisasm "20006500" "beqz s0, 0x2"
    testDisasm "20016500" "beqz s0, 0x4"
    testDisasm "20026500" "beqz s0, 0x6"
    testDisasm "20036500" "beqz s0, 0x8"

  [<TestMethod>]
  member _.``MD00077 BNEZ``() =
    testDisasm "28006500" "bnez s0, 0x2"
    testDisasm "28016500" "bnez s0, 0x4"
    testDisasm "28026500" "bnez s0, 0x6"
    testDisasm "28036500" "bnez s0, 0x8"

  [<TestMethod>]
  member _.``MD00077 BREAK``() =
    testDisasm "e8056500" "break 0x0"
    testDisasm "e8256500" "break 0x1"
    testDisasm "e8456500" "break 0x2"
    testDisasm "e8656500" "break 0x3"

  [<TestMethod>]
  member _.``MD00077 BTEQZ``() =
    testDisasm "60006500" "bteqz 0x2"
    testDisasm "60016500" "bteqz 0x4"
    testDisasm "60026500" "bteqz 0x6"
    testDisasm "60036500" "bteqz 0x8"

  [<TestMethod>]
  member _.``MD00077 BTNEZ``() =
    testDisasm "61006500" "btnez 0x2"
    testDisasm "61016500" "btnez 0x4"
    testDisasm "61026500" "btnez 0x6"
    testDisasm "61036500" "btnez 0x8"

  [<TestMethod>]
  member _.``MD00077 CMP``() =
    testDisasm "e80a6500" "cmp s0, s0"
    testDisasm "e82a6500" "cmp s0, s1"
    testDisasm "e84a6500" "cmp s0, v0"
    testDisasm "e86a6500" "cmp s0, v1"

  [<TestMethod>]
  member _.``MD00077 CMPI``() =
    testDisasm "70006500" "cmpi s0, 0x0"
    testDisasm "70016500" "cmpi s0, 0x1"
    testDisasm "70026500" "cmpi s0, 0x2"
    testDisasm "70036500" "cmpi s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 DADDIU``() =
    testDisasm "40106500" "daddiu s0, s0, 0x0"
    testDisasm "40116500" "daddiu s0, s0, 0x1"
    testDisasm "40126500" "daddiu s0, s0, 0x2"
    testDisasm "40136500" "daddiu s0, s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 DADDU``() =
    testDisasm "e0006500" "daddu s0, s0, s0"
    testDisasm "e0046500" "daddu s1, s0, s0"
    testDisasm "e0086500" "daddu v0, s0, s0"
    testDisasm "e00c6500" "daddu v1, s0, s0"

  [<TestMethod>]
  member _.``MD00077 DDIV``() =
    testDisasm "e81e6500" "ddiv s0, s0"
    testDisasm "e83e6500" "ddiv s0, s1"
    testDisasm "e85e6500" "ddiv s0, v0"
    testDisasm "e87e6500" "ddiv s0, v1"

  [<TestMethod>]
  member _.``MD00077 DDIVU``() =
    testDisasm "e81f6500" "ddivu s0, s0"
    testDisasm "e83f6500" "ddivu s0, s1"
    testDisasm "e85f6500" "ddivu s0, v0"
    testDisasm "e87f6500" "ddivu s0, v1"

  [<TestMethod>]
  member _.``MD00077 DIV``() =
    testDisasm "e81a6500" "div s0, s0"
    testDisasm "e83a6500" "div s0, s1"
    testDisasm "e85a6500" "div s0, v0"
    testDisasm "e87a6500" "div s0, v1"

  [<TestMethod>]
  member _.``MD00077 DIVU``() =
    testDisasm "e81b6500" "divu s0, s0"
    testDisasm "e83b6500" "divu s0, s1"
    testDisasm "e85b6500" "divu s0, v0"
    testDisasm "e87b6500" "divu s0, v1"

  [<TestMethod>]
  member _.``MD00077 DMULT``() =
    testDisasm "e81c6500" "dmult s0, s0"
    testDisasm "e83c6500" "dmult s0, s1"
    testDisasm "e85c6500" "dmult s0, v0"
    testDisasm "e87c6500" "dmult s0, v1"

  [<TestMethod>]
  member _.``MD00077 DMULTU``() =
    testDisasm "e81d6500" "dmultu s0, s0"
    testDisasm "e83d6500" "dmultu s0, s1"
    testDisasm "e85d6500" "dmultu s0, v0"
    testDisasm "e87d6500" "dmultu s0, v1"

  [<TestMethod>]
  member _.``MD00077 DSLL``() =
    testDisasm "30016500" "dsll s0, s0, 0x8"
    testDisasm "30056500" "dsll s0, s0, 0x1"
    testDisasm "30096500" "dsll s0, s0, 0x2"
    testDisasm "300d6500" "dsll s0, s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 DSLLV``() =
    testDisasm "e8146500" "dsllv s0, s0, s0"
    testDisasm "e8346500" "dsllv s1, s1, s0"
    testDisasm "e8546500" "dsllv v0, v0, s0"
    testDisasm "e8746500" "dsllv v1, v1, s0"

  [<TestMethod>]
  member _.``MD00077 DSRA``() =
    testDisasm "e8136500" "dsra s0, s0, 0x8"
    testDisasm "e8336500" "dsra s1, s1, 0x8"
    testDisasm "e8536500" "dsra v0, v0, 0x8"
    testDisasm "e8736500" "dsra v1, v1, 0x8"

  [<TestMethod>]
  member _.``MD00077 DSRAV``() =
    testDisasm "e8176500" "dsrav s0, s0, s0"
    testDisasm "e8376500" "dsrav s1, s1, s0"
    testDisasm "e8576500" "dsrav v0, v0, s0"
    testDisasm "e8776500" "dsrav v1, v1, s0"

  [<TestMethod>]
  member _.``MD00077 DSRL``() =
    testDisasm "e8086500" "dsrl s0, s0, 0x8"
    testDisasm "e8286500" "dsrl s1, s1, 0x8"
    testDisasm "e8486500" "dsrl v0, v0, 0x8"
    testDisasm "e8686500" "dsrl v1, v1, 0x8"

  [<TestMethod>]
  member _.``MD00077 DSRLV``() =
    testDisasm "e8166500" "dsrlv s0, s0, s0"
    testDisasm "e8366500" "dsrlv s1, s1, s0"
    testDisasm "e8566500" "dsrlv v0, v0, s0"
    testDisasm "e8766500" "dsrlv v1, v1, s0"

  [<TestMethod>]
  member _.``MD00077 DSUBU``() =
    testDisasm "e0026500" "dsubu s0, s0, s0"
    testDisasm "e0066500" "dsubu s1, s0, s0"
    testDisasm "e00a6500" "dsubu v0, s0, s0"
    testDisasm "e00e6500" "dsubu v1, s0, s0"

  [<TestMethod>]
  member _.``MD00077 JAL``() =
    testDisasm "18006500" "jal 0x19400"
    testDisasm "18016500" "jal 0x819400"
    testDisasm "18026500" "jal 0x1019400"
    testDisasm "18036500" "jal 0x1819400"

  [<TestMethod>]
  member _.``MD00077 JALR``() =
    testDisasm "e8406500" "jalr ra, s0"
    testDisasm "e9406500" "jalr ra, s1"
    testDisasm "ea406500" "jalr ra, v0"
    testDisasm "eb406500" "jalr ra, v1"

  [<TestMethod>]
  member _.``MD00077 JALRC``() =
    testDisasm "e8c06500" "jalrc ra, s0"
    testDisasm "e9c06500" "jalrc ra, s1"
    testDisasm "eac06500" "jalrc ra, v0"
    testDisasm "ebc06500" "jalrc ra, v1"

  [<TestMethod>]
  member _.``MD00077 JALX``() =
    testDisasm "1c006500" "jalx 0x19400"
    testDisasm "1c016500" "jalx 0x819400"
    testDisasm "1c026500" "jalx 0x1019400"
    testDisasm "1c036500" "jalx 0x1819400"

  [<TestMethod>]
  member _.``MD00077 JR``() =
    testDisasm "e8006500" "jr s0"
    testDisasm "e8206500" "jr ra"
    testDisasm "e9006500" "jr s1"
    testDisasm "ea006500" "jr v0"

  [<TestMethod>]
  member _.``MD00077 JRC``() =
    testDisasm "e8806500" "jrc s0"
    testDisasm "e8a06500" "jrc ra"
    testDisasm "e9806500" "jrc s1"
    testDisasm "ea806500" "jrc v0"

  [<TestMethod>]
  member _.``MD00077 LB``() =
    testDisasm "80006500" "lb s0, 0(s0)"
    testDisasm "80016500" "lb s0, 1(s0)"
    testDisasm "80026500" "lb s0, 2(s0)"
    testDisasm "80036500" "lb s0, 3(s0)"

  [<TestMethod>]
  member _.``MD00077 LBU``() =
    testDisasm "a0006500" "lbu s0, 0(s0)"
    testDisasm "a0016500" "lbu s0, 1(s0)"
    testDisasm "a0026500" "lbu s0, 2(s0)"
    testDisasm "a0036500" "lbu s0, 3(s0)"

  [<TestMethod>]
  member _.``MD00077 LD``() =
    testDisasm "38006500" "ld s0, 0(s0)"
    testDisasm "38016500" "ld s0, 8(s0)"
    testDisasm "38026500" "ld s0, 16(s0)"
    testDisasm "38036500" "ld s0, 24(s0)"

  [<TestMethod>]
  member _.``MD00077 LH``() =
    testDisasm "88006500" "lh s0, 0(s0)"
    testDisasm "88016500" "lh s0, 2(s0)"
    testDisasm "88026500" "lh s0, 4(s0)"
    testDisasm "88036500" "lh s0, 6(s0)"

  [<TestMethod>]
  member _.``MD00077 LHU``() =
    testDisasm "a8006500" "lhu s0, 0(s0)"
    testDisasm "a8016500" "lhu s0, 2(s0)"
    testDisasm "a8026500" "lhu s0, 4(s0)"
    testDisasm "a8036500" "lhu s0, 6(s0)"

  [<TestMethod>]
  member _.``MD00077 LI``() =
    testDisasm "68006500" "li s0, 0x0"
    testDisasm "68016500" "li s0, 0x1"
    testDisasm "68026500" "li s0, 0x2"
    testDisasm "68036500" "li s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 LW``() =
    testDisasm "90006500" "lw s0, 0(sp)"
    testDisasm "90016500" "lw s0, 4(sp)"
    testDisasm "90026500" "lw s0, 8(sp)"
    testDisasm "90036500" "lw s0, 12(sp)"

  [<TestMethod>]
  member _.``MD00077 LWU``() =
    testDisasm "b8006500" "lwu s0, 0(s0)"
    testDisasm "b8016500" "lwu s0, 4(s0)"
    testDisasm "b8026500" "lwu s0, 8(s0)"
    testDisasm "b8036500" "lwu s0, 12(s0)"

  [<TestMethod>]
  member _.``MD00077 MFHI``() =
    testDisasm "e8106500" "mfhi s0"
    testDisasm "e9106500" "mfhi s1"
    testDisasm "ea106500" "mfhi v0"
    testDisasm "eb106500" "mfhi v1"

  [<TestMethod>]
  member _.``MD00077 MFLO``() =
    testDisasm "e8126500" "mflo s0"
    testDisasm "e9126500" "mflo s1"
    testDisasm "ea126500" "mflo v0"
    testDisasm "eb126500" "mflo v1"

  [<TestMethod>]
  member _.``MD00077 MOVE``() =
    testDisasm "65016500" "move r0, s1"
    testDisasm "65026500" "move r0, v0"
    testDisasm "65036500" "move r0, v1"
    testDisasm "65046500" "move r0, a0"

  [<TestMethod>]
  member _.``MD00077 MULT``() =
    testDisasm "e8186500" "mult s0, s0"
    testDisasm "e8386500" "mult s0, s1"
    testDisasm "e8586500" "mult s0, v0"
    testDisasm "e8786500" "mult s0, v1"

  [<TestMethod>]
  member _.``MD00077 MULTU``() =
    testDisasm "e8196500" "multu s0, s0"
    testDisasm "e8396500" "multu s0, s1"
    testDisasm "e8596500" "multu s0, v0"
    testDisasm "e8796500" "multu s0, v1"

  [<TestMethod>]
  member _.``MD00077 NEG``() =
    testDisasm "e80b6500" "neg s0, s0"
    testDisasm "e82b6500" "neg s0, s1"
    testDisasm "e84b6500" "neg s0, v0"
    testDisasm "e86b6500" "neg s0, v1"

  [<TestMethod>]
  member _.``MD00077 NOP``() =
    testDisasm "65006500" "nop"

  [<TestMethod>]
  member _.``MD00077 NOT``() =
    testDisasm "e80f6500" "not s0, s0"
    testDisasm "e82f6500" "not s0, s1"
    testDisasm "e84f6500" "not s0, v0"
    testDisasm "e86f6500" "not s0, v1"

  [<TestMethod>]
  member _.``MD00077 OR``() =
    testDisasm "e80d6500" "or s0, s0, s0"
    testDisasm "e82d6500" "or s0, s0, s1"
    testDisasm "e84d6500" "or s0, s0, v0"
    testDisasm "e86d6500" "or s0, s0, v1"

  [<TestMethod>]
  member _.``MD00077 RESTORE``() =
    testDisasm "64006500" "restore 0x80"
    testDisasm "64016500" "restore 0x8"
    testDisasm "64026500" "restore 0x10"
    testDisasm "64036500" "restore 0x18"

  [<TestMethod>]
  member _.``MD00077 SAVE``() =
    testDisasm "64806500" "save 0x80"
    testDisasm "64816500" "save 0x8"
    testDisasm "64826500" "save 0x10"
    testDisasm "64836500" "save 0x18"

  [<TestMethod>]
  member _.``MD00077 SB``() =
    testDisasm "c0006500" "sb s0, 0(s0)"
    testDisasm "c0016500" "sb s0, 1(s0)"
    testDisasm "c0026500" "sb s0, 2(s0)"
    testDisasm "c0036500" "sb s0, 3(s0)"

  [<TestMethod>]
  member _.``MD00077 SD``() =
    testDisasm "78006500" "sd s0, 0(s0)"
    testDisasm "78016500" "sd s0, 8(s0)"
    testDisasm "78026500" "sd s0, 16(s0)"
    testDisasm "78036500" "sd s0, 24(s0)"

  [<TestMethod>]
  member _.``MD00077 SDBBP``() =
    testDisasm "e8016500" "sdbbp 0x0"
    testDisasm "e8216500" "sdbbp 0x1"
    testDisasm "e8416500" "sdbbp 0x2"
    testDisasm "e8616500" "sdbbp 0x3"

  [<TestMethod>]
  member _.``MD00077 SEB``() =
    testDisasm "e8916500" "seb s0, s0"
    testDisasm "e9916500" "seb s1, s1"
    testDisasm "ea916500" "seb v0, v0"
    testDisasm "eb916500" "seb v1, v1"

  [<TestMethod>]
  member _.``MD00077 SEH``() =
    testDisasm "e8b16500" "seh s0, s0"
    testDisasm "e9b16500" "seh s1, s1"
    testDisasm "eab16500" "seh v0, v0"
    testDisasm "ebb16500" "seh v1, v1"

  [<TestMethod>]
  member _.``MD00077 SEW``() =
    testDisasm "e8d16500" "sew s0, s0"
    testDisasm "e9d16500" "sew s1, s1"
    testDisasm "ead16500" "sew v0, v0"
    testDisasm "ebd16500" "sew v1, v1"

  [<TestMethod>]
  member _.``MD00077 SH``() =
    testDisasm "c8006500" "sh s0, 0(s0)"
    testDisasm "c8016500" "sh s0, 2(s0)"
    testDisasm "c8026500" "sh s0, 4(s0)"
    testDisasm "c8036500" "sh s0, 6(s0)"

  [<TestMethod>]
  member _.``MD00077 SLL``() =
    testDisasm "30006500" "sll s0, s0, 0x8"
    testDisasm "30046500" "sll s0, s0, 0x1"
    testDisasm "30086500" "sll s0, s0, 0x2"
    testDisasm "300c6500" "sll s0, s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 SLLV``() =
    testDisasm "e8046500" "sllv s0, s0, s0"
    testDisasm "e8246500" "sllv s1, s1, s0"
    testDisasm "e8446500" "sllv v0, v0, s0"
    testDisasm "e8646500" "sllv v1, v1, s0"

  [<TestMethod>]
  member _.``MD00077 SLT``() =
    testDisasm "e8026500" "slt s0, s0"
    testDisasm "e8226500" "slt s0, s1"
    testDisasm "e8426500" "slt s0, v0"
    testDisasm "e8626500" "slt s0, v1"

  [<TestMethod>]
  member _.``MD00077 SLTI``() =
    testDisasm "50006500" "slti s0, 0x0"
    testDisasm "50016500" "slti s0, 0x1"
    testDisasm "50026500" "slti s0, 0x2"
    testDisasm "50036500" "slti s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 SLTIU``() =
    testDisasm "58006500" "sltiu s0, 0x0"
    testDisasm "58016500" "sltiu s0, 0x1"
    testDisasm "58026500" "sltiu s0, 0x2"
    testDisasm "58036500" "sltiu s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 SLTU``() =
    testDisasm "e8036500" "sltu s0, s0"
    testDisasm "e8236500" "sltu s0, s1"
    testDisasm "e8436500" "sltu s0, v0"
    testDisasm "e8636500" "sltu s0, v1"

  [<TestMethod>]
  member _.``MD00077 SRA``() =
    testDisasm "30036500" "sra s0, s0, 0x8"
    testDisasm "30076500" "sra s0, s0, 0x1"
    testDisasm "300b6500" "sra s0, s0, 0x2"
    testDisasm "300f6500" "sra s0, s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 SRAV``() =
    testDisasm "e8076500" "srav s0, s0, s0"
    testDisasm "e8276500" "srav s1, s1, s0"
    testDisasm "e8476500" "srav v0, v0, s0"
    testDisasm "e8676500" "srav v1, v1, s0"

  [<TestMethod>]
  member _.``MD00077 SRL``() =
    testDisasm "30026500" "srl s0, s0, 0x8"
    testDisasm "30066500" "srl s0, s0, 0x1"
    testDisasm "300a6500" "srl s0, s0, 0x2"
    testDisasm "300e6500" "srl s0, s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 SRLV``() =
    testDisasm "e8066500" "srlv s0, s0, s0"
    testDisasm "e8266500" "srlv s1, s1, s0"
    testDisasm "e8466500" "srlv v0, v0, s0"
    testDisasm "e8666500" "srlv v1, v1, s0"

  [<TestMethod>]
  member _.``MD00077 SUBU``() =
    testDisasm "e0036500" "subu s0, s0, s0"
    testDisasm "e0076500" "subu s1, s0, s0"
    testDisasm "e00b6500" "subu v0, s0, s0"
    testDisasm "e00f6500" "subu v1, s0, s0"

  [<TestMethod>]
  member _.``MD00077 SW``() =
    testDisasm "62006500" "sw ra, 0(sp)"
    testDisasm "62016500" "sw ra, 4(sp)"
    testDisasm "62026500" "sw ra, 8(sp)"
    testDisasm "62036500" "sw ra, 12(sp)"

  [<TestMethod>]
  member _.``MD00077 XOR``() =
    testDisasm "e80e6500" "xor s0, s0, s0"
    testDisasm "e82e6500" "xor s0, s0, s1"
    testDisasm "e84e6500" "xor s0, s0, v0"
    testDisasm "e86e6500" "xor s0, s0, v1"

  [<TestMethod>]
  member _.``MD00077 ZEB``() =
    testDisasm "e8116500" "zeb s0, s0"
    testDisasm "e9116500" "zeb s1, s1"
    testDisasm "ea116500" "zeb v0, v0"
    testDisasm "eb116500" "zeb v1, v1"

  [<TestMethod>]
  member _.``MD00077 ZEH``() =
    testDisasm "e8316500" "zeh s0, s0"
    testDisasm "e9316500" "zeh s1, s1"
    testDisasm "ea316500" "zeh v0, v0"
    testDisasm "eb316500" "zeh v1, v1"

  [<TestMethod>]
  member _.``MD00077 ZEW``() =
    testDisasm "e8516500" "zew s0, s0"
    testDisasm "e9516500" "zew s1, s1"
    testDisasm "ea516500" "zew v0, v0"
    testDisasm "eb516500" "zew v1, v1"
