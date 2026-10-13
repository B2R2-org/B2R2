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
/// One test for each instruction microMIPS64 5.04 describes, ABS.fmt to
/// JRADDIUSP. Each reads words of the instruction and checks the text, and each
/// word is one binutils' objdump reads as the same instruction with the same
/// operands, so what is asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualMicroMIPSParserTests1() =
  let isa =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSISAMode.MicroMIPS)

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser = Parser(isa, BinReader.Init isa.Endian) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  [<TestMethod>]
  member _.``microMIPS64 5.04 ABS.fmt``() =
    testDisasm "5400037b" "abs.s f0, f0"
    testDisasm "5400237b" "abs.d f0, f0"
    testDisasm "5400437b" "abs.ps f0, f0"
    testDisasm "5422037b" "abs.s f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADD``() =
    testDisasm "00000110" "add r0, r0, r0"
    testDisasm "00000910" "add at, r0, r0"
    testDisasm "00001110" "add v0, r0, r0"
    testDisasm "00001910" "add v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADD.fmt``() =
    testDisasm "54000030" "add.s f0, f0, f0"
    testDisasm "54000130" "add.d f0, f0, f0"
    testDisasm "54000230" "add.ps f0, f0, f0"
    testDisasm "54000830" "add.s f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDI``() =
    testDisasm "10030000" "addi r0, v1, 0x0"
    testDisasm "10600000" "addi v1, r0, 0x0"
    testDisasm "10030001" "addi r0, v1, 0x1"
    testDisasm "10600001" "addi v1, r0, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIU``() =
    testDisasm "4c000c00" "addiu r0, r0, 0x0"
    testDisasm "4c010c00" "addiu sp, sp, 0x400"
    testDisasm "4c020c00" "addiu r0, r0, 0x1"
    testDisasm "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUPC``() =
    testDisasm "78030000" "addiupc s0, 0xc0000"
    testDisasm "78030001" "addiupc s0, 0xc0004"
    testDisasm "78830000" "addiupc s1, 0xc0000"
    testDisasm "78830001" "addiupc s1, 0xc0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUR1SP``() =
    testDisasm "4c000c00" "addiu r0, r0, 0x0"
    testDisasm "4c010c00" "addiu sp, sp, 0x400"
    testDisasm "4c020c00" "addiu r0, r0, 0x1"
    testDisasm "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUR2``() =
    testDisasm "4c000c00" "addiu r0, r0, 0x0"
    testDisasm "4c010c00" "addiu sp, sp, 0x400"
    testDisasm "4c020c00" "addiu r0, r0, 0x1"
    testDisasm "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUS5``() =
    testDisasm "4c000c00" "addiu r0, r0, 0x0"
    testDisasm "4c010c00" "addiu sp, sp, 0x400"
    testDisasm "4c020c00" "addiu r0, r0, 0x1"
    testDisasm "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUSP``() =
    testDisasm "4c000c00" "addiu r0, r0, 0x0"
    testDisasm "4c010c00" "addiu sp, sp, 0x400"
    testDisasm "4c020c00" "addiu r0, r0, 0x1"
    testDisasm "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDU``() =
    testDisasm "04000c00" "addu s0, s0, s0"
    testDisasm "04020c00" "addu s0, s1, s0"
    testDisasm "04040c00" "addu s0, v0, s0"
    testDisasm "04060c00" "addu s0, v1, s0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDU16``() =
    testDisasm "04000c00" "addu s0, s0, s0"
    testDisasm "04020c00" "addu s0, s1, s0"
    testDisasm "04040c00" "addu s0, v0, s0"
    testDisasm "04060c00" "addu s0, v1, s0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ALNV.PS``() =
    testDisasm "54000019" "alnv.ps f0, f0, f0, r0"
    testDisasm "54000059" "alnv.ps f0, f0, f0, at"
    testDisasm "54000099" "alnv.ps f0, f0, f0, v0"
    testDisasm "540000d9" "alnv.ps f0, f0, f0, v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 AND``() =
    testDisasm "44800c00" "and s0, s0, s0"
    testDisasm "44810c00" "and s0, s0, s1"
    testDisasm "44820c00" "and s0, s0, v0"
    testDisasm "44830c00" "and s0, s0, v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 AND16``() =
    testDisasm "44800c00" "and s0, s0, s0"
    testDisasm "44810c00" "and s0, s0, s1"
    testDisasm "44820c00" "and s0, s0, v0"
    testDisasm "44830c00" "and s0, s0, v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ANDI``() =
    testDisasm "2c000c00" "andi s0, s0, 0x80"
    testDisasm "2c010c00" "andi s0, s0, 0x1"
    testDisasm "2c020c00" "andi s0, s0, 0x2"
    testDisasm "2c030c00" "andi s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ANDI16``() =
    testDisasm "2c000c00" "andi s0, s0, 0x80"
    testDisasm "2c010c00" "andi s0, s0, 0x1"
    testDisasm "2c020c00" "andi s0, s0, 0x2"
    testDisasm "2c030c00" "andi s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 B``() =
    testDisasm "cc000c00" "b 0x2"
    testDisasm "cc010c00" "b 0x4"
    testDisasm "cc020c00" "b 0x6"
    testDisasm "cc030c00" "b 0x8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 B16``() =
    testDisasm "cc000c00" "b 0x2"
    testDisasm "cc010c00" "b 0x4"
    testDisasm "cc020c00" "b 0x6"
    testDisasm "cc030c00" "b 0x8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BAL``() =
    testDisasm "40600000" "bgezal r0, 0x4"
    testDisasm "40600001" "bgezal r0, 0x6"
    testDisasm "40607fff" "bgezal r0, 0x10002"
    testDisasm "40608000" "bgezal r0, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BEQ``() =
    testDisasm "8d000c00" "beq v0, r0, 0x2"
    testDisasm "8c000c00" "beq s0, r0, 0x2"
    testDisasm "8c010c00" "beq s0, r0, 0x4"
    testDisasm "8c020c00" "beq s0, r0, 0x6"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BEQZ16``() =
    testDisasm "8d000c00" "beq v0, r0, 0x2"
    testDisasm "8c000c00" "beq s0, r0, 0x2"
    testDisasm "8c010c00" "beq s0, r0, 0x4"
    testDisasm "8c020c00" "beq s0, r0, 0x6"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BEQZC``() =
    testDisasm "40e30000" "beqzc v1, 0x4"
    testDisasm "40e30001" "beqzc v1, 0x6"
    testDisasm "40e37fff" "beqzc v1, 0x10002"
    testDisasm "40e38000" "beqzc v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BGEZ``() =
    testDisasm "40430000" "bgez v1, 0x4"
    testDisasm "40430001" "bgez v1, 0x6"
    testDisasm "40437fff" "bgez v1, 0x10002"
    testDisasm "40438000" "bgez v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BGEZAL``() =
    testDisasm "40600000" "bgezal r0, 0x4"
    testDisasm "40600001" "bgezal r0, 0x6"
    testDisasm "40607fff" "bgezal r0, 0x10002"
    testDisasm "40608000" "bgezal r0, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BGEZALS``() =
    testDisasm "42630000" "bgezals v1, 0x4"
    testDisasm "42630001" "bgezals v1, 0x6"
    testDisasm "42637fff" "bgezals v1, 0x10002"
    testDisasm "42638000" "bgezals v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BGTZ``() =
    testDisasm "40c30000" "bgtz v1, 0x4"
    testDisasm "40c30001" "bgtz v1, 0x6"
    testDisasm "40c37fff" "bgtz v1, 0x10002"
    testDisasm "40c38000" "bgtz v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BLEZ``() =
    testDisasm "40830000" "blez v1, 0x4"
    testDisasm "40830001" "blez v1, 0x6"
    testDisasm "40837fff" "blez v1, 0x10002"
    testDisasm "40838000" "blez v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BLTZ``() =
    testDisasm "40000000" "bltz r0, 0x4"
    testDisasm "40000001" "bltz r0, 0x6"
    testDisasm "40000002" "bltz r0, 0x8"
    testDisasm "40000003" "bltz r0, 0xa"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BLTZAL``() =
    testDisasm "40220000" "bltzal v0, 0x4"
    testDisasm "40220001" "bltzal v0, 0x6"
    testDisasm "40220002" "bltzal v0, 0x8"
    testDisasm "40220003" "bltzal v0, 0xa"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BLTZALS``() =
    testDisasm "42230000" "bltzals v1, 0x4"
    testDisasm "42230001" "bltzals v1, 0x6"
    testDisasm "42237fff" "bltzals v1, 0x10002"
    testDisasm "42238000" "bltzals v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BNE``() =
    testDisasm "ad000c00" "bne v0, r0, 0x2"
    testDisasm "ac000c00" "bne s0, r0, 0x2"
    testDisasm "ac010c00" "bne s0, r0, 0x4"
    testDisasm "ac020c00" "bne s0, r0, 0x6"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BNEZ16``() =
    testDisasm "ad000c00" "bne v0, r0, 0x2"
    testDisasm "ac000c00" "bne s0, r0, 0x2"
    testDisasm "ac010c00" "bne s0, r0, 0x4"
    testDisasm "ac020c00" "bne s0, r0, 0x6"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BNEZC``() =
    testDisasm "40a30000" "bnezc v1, 0x4"
    testDisasm "40a30001" "bnezc v1, 0x6"
    testDisasm "40a37fff" "bnezc v1, 0x10002"
    testDisasm "40a38000" "bnezc v1, 0xffffffffffff0004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BREAK``() =
    testDisasm "46800c00" "break 0x0"
    testDisasm "46810c00" "break 0x1"
    testDisasm "46820c00" "break 0x2"
    testDisasm "46830c00" "break 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 BREAK16``() =
    testDisasm "46800c00" "break 0x0"
    testDisasm "46810c00" "break 0x1"
    testDisasm "46820c00" "break 0x2"
    testDisasm "46830c00" "break 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 C.cond.fmt``() =
    testDisasm "5400203c" "c.f.s 0x1, f0, f0"
    testDisasm "5400207c" "c.un.s 0x1, f0, f0"
    testDisasm "540020bc" "c.eq.s 0x1, f0, f0"
    testDisasm "540020fc" "c.ueq.s 0x1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CACHE``() =
    testDisasm "20006000" "cache 0x0, 0(r0)"
    testDisasm "20006001" "cache 0x0, 1(r0)"
    testDisasm "20006002" "cache 0x0, 2(r0)"
    testDisasm "20006003" "cache 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CACHEE``() =
    testDisasm "6000a600" "cachee 0x0, 0(r0)"
    testDisasm "6000a601" "cachee 0x0, 1(r0)"
    testDisasm "6000a602" "cachee 0x0, 2(r0)"
    testDisasm "6000a603" "cachee 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CEIL.L.fmt``() =
    testDisasm "5400133b" "ceil.l.s f0, f0"
    testDisasm "5400533b" "ceil.l.d f0, f0"
    testDisasm "5422133b" "ceil.l.s f1, f2"
    testDisasm "5422533b" "ceil.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CEIL.W.fmt``() =
    testDisasm "54001b3b" "ceil.w.s f0, f0"
    testDisasm "54005b3b" "ceil.w.d f0, f0"
    testDisasm "54221b3b" "ceil.w.s f1, f2"
    testDisasm "54225b3b" "ceil.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CFC1``() =
    testDisasm "5400103b" "cfc1 r0, f0"
    testDisasm "5422103b" "cfc1 at, f2"
    testDisasm "57fe103b" "cfc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CFC2``() =
    testDisasm "0000cd3c" "cfc2 r0, 0x0"
    testDisasm "0022cd3c" "cfc2 at, 0x2"
    testDisasm "03fecd3c" "cfc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CLO``() =
    testDisasm "00004b3c" "clo r0, r0"
    testDisasm "00224b3c" "clo at, v0"
    testDisasm "03fe4b3c" "clo ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CLZ``() =
    testDisasm "00005b3c" "clz r0, r0"
    testDisasm "00225b3c" "clz at, v0"
    testDisasm "03fe5b3c" "clz ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 COP2``() =
    testDisasm "00000002" "cop2 0x0"
    testDisasm "0000000a" "cop2 0x1"
    testDisasm "00000012" "cop2 0x2"
    testDisasm "0000001a" "cop2 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CTC1``() =
    testDisasm "5400183b" "ctc1 r0, f0"
    testDisasm "5422183b" "ctc1 at, f2"
    testDisasm "57fe183b" "ctc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CTC2``() =
    testDisasm "0000dd3c" "ctc2 r0, 0x0"
    testDisasm "0022dd3c" "ctc2 at, 0x2"
    testDisasm "03fedd3c" "ctc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.D.fmt``() =
    testDisasm "5400137b" "cvt.d.s f0, f0"
    testDisasm "5400337b" "cvt.d.w f0, f0"
    testDisasm "5400537b" "cvt.d.l f0, f0"
    testDisasm "5422137b" "cvt.d.s f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.L.fmt``() =
    testDisasm "5400013b" "cvt.l.s f0, f0"
    testDisasm "5400413b" "cvt.l.d f0, f0"
    testDisasm "5422013b" "cvt.l.s f1, f2"
    testDisasm "5422413b" "cvt.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.PS.S``() =
    testDisasm "54000180" "cvt.ps.s f0, f0, f0"
    testDisasm "54000980" "cvt.ps.s f1, f0, f0"
    testDisasm "54001180" "cvt.ps.s f2, f0, f0"
    testDisasm "54001980" "cvt.ps.s f3, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.S.PL``() =
    testDisasm "5400213b" "cvt.s.pl f0, f0"
    testDisasm "5422213b" "cvt.s.pl f1, f2"
    testDisasm "57fe213b" "cvt.s.pl f31, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.S.PU``() =
    testDisasm "5400293b" "cvt.s.pu f0, f0"
    testDisasm "5422293b" "cvt.s.pu f1, f2"
    testDisasm "57fe293b" "cvt.s.pu f31, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.S.fmt``() =
    testDisasm "54001b7b" "cvt.s.d f0, f0"
    testDisasm "54003b7b" "cvt.s.w f0, f0"
    testDisasm "54005b7b" "cvt.s.l f0, f0"
    testDisasm "54221b7b" "cvt.s.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.W.fmt``() =
    testDisasm "5400093b" "cvt.w.s f0, f0"
    testDisasm "5400493b" "cvt.w.d f0, f0"
    testDisasm "5422093b" "cvt.w.s f1, f2"
    testDisasm "5422493b" "cvt.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DADD``() =
    testDisasm "58000110" "dadd r0, r0, r0"
    testDisasm "58000910" "dadd at, r0, r0"
    testDisasm "58001110" "dadd v0, r0, r0"
    testDisasm "58001910" "dadd v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DADDI``() =
    testDisasm "5800001c" "daddi r0, r0, 0x0"
    testDisasm "5800005c" "daddi r0, r0, 0x1"
    testDisasm "5800009c" "daddi r0, r0, 0x2"
    testDisasm "580000dc" "daddi r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DADDIU``() =
    testDisasm "5c030000" "daddiu r0, v1, 0x0"
    testDisasm "5c600000" "daddiu v1, r0, 0x0"
    testDisasm "5c030001" "daddiu r0, v1, 0x1"
    testDisasm "5c600001" "daddiu v1, r0, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DADDU``() =
    testDisasm "58220150" "daddu r0, v0, at"
    testDisasm "58220950" "daddu at, v0, at"
    testDisasm "58221150" "daddu v0, v0, at"
    testDisasm "58221950" "daddu v1, v0, at"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DCLO``() =
    testDisasm "58004b3c" "dclo r0, r0"
    testDisasm "58224b3c" "dclo at, v0"
    testDisasm "5bfe4b3c" "dclo ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DCLZ``() =
    testDisasm "58005b3c" "dclz r0, r0"
    testDisasm "58225b3c" "dclz at, v0"
    testDisasm "5bfe5b3c" "dclz ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DDIV``() =
    testDisasm "5800ab3c" "ddiv r0, r0"
    testDisasm "5822ab3c" "ddiv v0, at"
    testDisasm "5bfeab3c" "ddiv s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DDIVU``() =
    testDisasm "5800bb3c" "ddivu r0, r0"
    testDisasm "5822bb3c" "ddivu v0, at"
    testDisasm "5bfebb3c" "ddivu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DERET``() =
    testDisasm "0000e37c" "deret"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DEXT``() =
    testDisasm "5800002c" "dext r0, r0, 0x0, 0x1"
    testDisasm "5800006c" "dext r0, r0, 0x1, 0x1"
    testDisasm "580000ac" "dext r0, r0, 0x2, 0x1"
    testDisasm "580000ec" "dext r0, r0, 0x3, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DEXTM``() =
    testDisasm "58000024" "dextm r0, r0, 0x0, 0x21"
    testDisasm "58000064" "dextm r0, r0, 0x1, 0x21"
    testDisasm "580000a4" "dextm r0, r0, 0x2, 0x21"
    testDisasm "580000e4" "dextm r0, r0, 0x3, 0x21"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DEXTU``() =
    testDisasm "58000014" "dextu r0, r0, 0x20, 0x1"
    testDisasm "58000054" "dextu r0, r0, 0x21, 0x1"
    testDisasm "58000094" "dextu r0, r0, 0x22, 0x1"
    testDisasm "580000d4" "dextu r0, r0, 0x23, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DI``() =
    testDisasm "0000477c" "di r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DINS``() =
    testDisasm "5800000c" "dins r0, r0, 0x0, 0x1"
    testDisasm "5800080c" "dins r0, r0, 0x0, 0x2"
    testDisasm "5800084c" "dins r0, r0, 0x1, 0x1"
    testDisasm "5800100c" "dins r0, r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DINSM``() =
    testDisasm "58000004" "dinsm r0, r0, 0x0, 0x21"
    testDisasm "58000044" "dinsm r0, r0, 0x1, 0x20"
    testDisasm "58000084" "dinsm r0, r0, 0x2, 0x1f"
    testDisasm "580000c4" "dinsm r0, r0, 0x3, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DINSU``() =
    testDisasm "58000034" "dinsu r0, r0, 0x20, 0x1"
    testDisasm "58000834" "dinsu r0, r0, 0x20, 0x2"
    testDisasm "58000874" "dinsu r0, r0, 0x21, 0x1"
    testDisasm "58001034" "dinsu r0, r0, 0x20, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DIV``() =
    testDisasm "0000ab3c" "div r0, r0"
    testDisasm "0022ab3c" "div v0, at"
    testDisasm "03feab3c" "div s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DIV.fmt``() =
    testDisasm "540000f0" "div.s f0, f0, f0"
    testDisasm "540001f0" "div.d f0, f0, f0"
    testDisasm "540008f0" "div.s f1, f0, f0"
    testDisasm "540009f0" "div.d f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DIVU``() =
    testDisasm "0000bb3c" "divu r0, r0"
    testDisasm "0022bb3c" "divu v0, at"
    testDisasm "03febb3c" "divu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMFC0``() =
    testDisasm "580008fc" "dmfc0 r0, 0x0, 0x1"
    testDisasm "580010fc" "dmfc0 r0, 0x0, 0x2"
    testDisasm "580018fc" "dmfc0 r0, 0x0, 0x3"
    testDisasm "582208fc" "dmfc0 at, 0x2, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMFC1``() =
    testDisasm "5400243b" "dmfc1 r0, f0"
    testDisasm "5422243b" "dmfc1 at, f2"
    testDisasm "57fe243b" "dmfc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMFC2``() =
    testDisasm "00006d3c" "dmfc2 r0, 0x0"
    testDisasm "00226d3c" "dmfc2 at, 0x2"
    testDisasm "03fe6d3c" "dmfc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMTC0``() =
    testDisasm "58000afc" "dmtc0 r0, 0x0, 0x1"
    testDisasm "580012fc" "dmtc0 r0, 0x0, 0x2"
    testDisasm "58001afc" "dmtc0 r0, 0x0, 0x3"
    testDisasm "58220afc" "dmtc0 at, 0x2, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMTC1``() =
    testDisasm "54002c3b" "dmtc1 r0, f0"
    testDisasm "54222c3b" "dmtc1 at, f2"
    testDisasm "57fe2c3b" "dmtc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMTC2``() =
    testDisasm "00007d3c" "dmtc2 r0, 0x0"
    testDisasm "00227d3c" "dmtc2 at, 0x2"
    testDisasm "03fe7d3c" "dmtc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMULT``() =
    testDisasm "58008b3c" "dmult r0, r0"
    testDisasm "58228b3c" "dmult v0, at"
    testDisasm "5bfe8b3c" "dmult s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DMULTU``() =
    testDisasm "58009b3c" "dmultu r0, r0"
    testDisasm "58229b3c" "dmultu v0, at"
    testDisasm "5bfe9b3c" "dmultu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DROTR``() =
    testDisasm "580000c0" "drotr r0, r0, 0x0"
    testDisasm "580008c0" "drotr r0, r0, 0x1"
    testDisasm "580010c0" "drotr r0, r0, 0x2"
    testDisasm "580018c0" "drotr r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DROTR32``() =
    testDisasm "580000c8" "drotr32  r0, r0, 0x0"
    testDisasm "580008c8" "drotr32  r0, r0, 0x1"
    testDisasm "580010c8" "drotr32  r0, r0, 0x2"
    testDisasm "580018c8" "drotr32  r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DROTRV``() =
    testDisasm "580000d0" "drotrv r0, r0, r0"
    testDisasm "580008d0" "drotrv at, r0, r0"
    testDisasm "580010d0" "drotrv v0, r0, r0"
    testDisasm "580018d0" "drotrv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSBH``() =
    testDisasm "58007b3c" "dsbh r0, r0"
    testDisasm "58227b3c" "dsbh at, v0"
    testDisasm "5bfe7b3c" "dsbh ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSHD``() =
    testDisasm "5800fb3c" "dshd r0, r0"
    testDisasm "5822fb3c" "dshd at, v0"
    testDisasm "5bfefb3c" "dshd ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSLL``() =
    testDisasm "58000000" "dsll r0, r0, 0x0"
    testDisasm "58000800" "dsll r0, r0, 0x1"
    testDisasm "58001000" "dsll r0, r0, 0x2"
    testDisasm "58001800" "dsll r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSLL32``() =
    testDisasm "58000008" "dsll32 r0, r0, 0x0"
    testDisasm "58000808" "dsll32 r0, r0, 0x1"
    testDisasm "58001008" "dsll32 r0, r0, 0x2"
    testDisasm "58001808" "dsll32 r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSLLV``() =
    testDisasm "58000010" "dsllv r0, r0, r0"
    testDisasm "58000810" "dsllv at, r0, r0"
    testDisasm "58001010" "dsllv v0, r0, r0"
    testDisasm "58001810" "dsllv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRA``() =
    testDisasm "58000080" "dsra r0, r0, 0x0"
    testDisasm "58000880" "dsra r0, r0, 0x1"
    testDisasm "58001080" "dsra r0, r0, 0x2"
    testDisasm "58001880" "dsra r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRA32``() =
    testDisasm "58000088" "dsra32 r0, r0, 0x0"
    testDisasm "58000888" "dsra32 r0, r0, 0x1"
    testDisasm "58001088" "dsra32 r0, r0, 0x2"
    testDisasm "58001888" "dsra32 r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRAV``() =
    testDisasm "58000090" "dsrav r0, r0, r0"
    testDisasm "58000890" "dsrav at, r0, r0"
    testDisasm "58001090" "dsrav v0, r0, r0"
    testDisasm "58001890" "dsrav v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRL``() =
    testDisasm "58000040" "dsrl r0, r0, 0x0"
    testDisasm "58000840" "dsrl r0, r0, 0x1"
    testDisasm "58001040" "dsrl r0, r0, 0x2"
    testDisasm "58001840" "dsrl r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRL32``() =
    testDisasm "58000048" "dsrl32 r0, r0, 0x0"
    testDisasm "58000848" "dsrl32 r0, r0, 0x1"
    testDisasm "58001048" "dsrl32 r0, r0, 0x2"
    testDisasm "58001848" "dsrl32 r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRLV``() =
    testDisasm "58000050" "dsrlv r0, r0, r0"
    testDisasm "58000850" "dsrlv at, r0, r0"
    testDisasm "58001050" "dsrlv v0, r0, r0"
    testDisasm "58001850" "dsrlv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSUB``() =
    testDisasm "58220190" "dsub r0, v0, at"
    testDisasm "58220990" "dsub at, v0, at"
    testDisasm "58221190" "dsub v0, v0, at"
    testDisasm "58221990" "dsub v1, v0, at"

  [<TestMethod>]
  member _.``microMIPS64 5.04 DSUBU``() =
    testDisasm "582201d0" "dsubu r0, v0, at"
    testDisasm "582209d0" "dsubu at, v0, at"
    testDisasm "582211d0" "dsubu v0, v0, at"
    testDisasm "582219d0" "dsubu v1, v0, at"

  [<TestMethod>]
  member _.``microMIPS64 5.04 EHB``() =
    testDisasm "00001800" "ehb"

  [<TestMethod>]
  member _.``microMIPS64 5.04 EI``() =
    testDisasm "0000577c" "ei r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ERET``() =
    testDisasm "0000f37c" "eret"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ERETNC``() =
    testDisasm "0001f37c" "eretnc"

  [<TestMethod>]
  member _.``microMIPS64 5.04 EXT``() =
    testDisasm "0000002c" "ext r0, r0, 0x0, 0x1"
    testDisasm "0000006c" "ext r0, r0, 0x1, 0x1"
    testDisasm "000000ac" "ext r0, r0, 0x2, 0x1"
    testDisasm "000000ec" "ext r0, r0, 0x3, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 FLOOR.L.fmt``() =
    testDisasm "5400033b" "floor.l.s f0, f0"
    testDisasm "5400433b" "floor.l.d f0, f0"
    testDisasm "5422033b" "floor.l.s f1, f2"
    testDisasm "5422433b" "floor.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 FLOOR.W.fmt``() =
    testDisasm "54000b3b" "floor.w.s f0, f0"
    testDisasm "54004b3b" "floor.w.d f0, f0"
    testDisasm "54220b3b" "floor.w.s f1, f2"
    testDisasm "54224b3b" "floor.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 INS``() =
    testDisasm "0000000c" "ins r0, r0, 0x0, 0x1"
    testDisasm "0000080c" "ins r0, r0, 0x0, 0x2"
    testDisasm "0000084c" "ins r0, r0, 0x1, 0x1"
    testDisasm "0000100c" "ins r0, r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 J``() =
    testDisasm "d4030000" "j 0x60000"
    testDisasm "d4600000" "j 0xc00000"
    testDisasm "d4030001" "j 0x60002"
    testDisasm "d4600001" "j 0xc00002"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JAL``() =
    testDisasm "f4030000" "jal 0x60000"
    testDisasm "f4600000" "jal 0xc00000"
    testDisasm "f4030001" "jal 0x60002"
    testDisasm "f4600001" "jal 0xc00002"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALR``() =
    testDisasm "45c00c00" "jalr r0"
    testDisasm "45c10c00" "jalr at"
    testDisasm "45c20c00" "jalr v0"
    testDisasm "45c30c00" "jalr v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALR.HB``() =
    testDisasm "00051f3c" "jalr.hb r0, a1"
    testDisasm "00001f3c" "jalr.hb r0, r0"
    testDisasm "00221f3c" "jalr.hb at, v0"
    testDisasm "03fe1f3c" "jalr.hb ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALR16``() =
    testDisasm "45c00c00" "jalr r0"
    testDisasm "45c10c00" "jalr at"
    testDisasm "45c20c00" "jalr v0"
    testDisasm "45c30c00" "jalr v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALRS``() =
    testDisasm "45e00c00" "jalrs r0"
    testDisasm "45e10c00" "jalrs at"
    testDisasm "45e20c00" "jalrs v0"
    testDisasm "45e30c00" "jalrs v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALRS.HB``() =
    testDisasm "00225f3c" "jalrs.hb at, v0"
    testDisasm "03fe5f3c" "jalrs.hb ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALRS16``() =
    testDisasm "45e00c00" "jalrs r0"
    testDisasm "45e10c00" "jalrs at"
    testDisasm "45e20c00" "jalrs v0"
    testDisasm "45e30c00" "jalrs v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALS``() =
    testDisasm "74030000" "jals 0x60000"
    testDisasm "74600000" "jals 0xc00000"
    testDisasm "74030001" "jals 0x60002"
    testDisasm "74600001" "jals 0xc00002"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JALX``() =
    testDisasm "f0030000" "jalx 0xc0000"
    testDisasm "f0600000" "jalx 0x1800000"
    testDisasm "f0030001" "jalx 0xc0004"
    testDisasm "f0600001" "jalx 0x1800004"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JR``() =
    testDisasm "45800c00" "jr r0"
    testDisasm "45810c00" "jr at"
    testDisasm "45820c00" "jr v0"
    testDisasm "45830c00" "jr v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JR.HB``() =
    testDisasm "00051f3c" "jalr.hb r0, a1"
    testDisasm "00001f3c" "jalr.hb r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JR16``() =
    testDisasm "45800c00" "jr r0"
    testDisasm "45810c00" "jr at"
    testDisasm "45820c00" "jr v0"
    testDisasm "45830c00" "jr v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 JRADDIUSP``() =
    testDisasm "47000c00" "jraddiusp 0x0"
    testDisasm "47010c00" "jraddiusp 0x4"
    testDisasm "47020c00" "jraddiusp 0x8"
    testDisasm "47030c00" "jraddiusp 0xc"
