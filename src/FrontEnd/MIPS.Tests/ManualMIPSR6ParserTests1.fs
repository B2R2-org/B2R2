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
/// One test for each instruction MD00087 describes, ABS.fmt to DSRAV. Each
/// reads words of the instruction and checks the text, and each word is one
/// binutils' objdump reads as the same instruction with the same operands, so
/// what is asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualMIPSR6ParserTests1() =
  let isa =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSRelease.R6)

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser = Parser(isa, BinReader.Init isa.Endian) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  [<TestMethod>]
  member _.``MD00087 ABS.fmt``() =
    testDisasm "46000005" "abs.s f0, f0"
    testDisasm "46200005" "abs.d f0, f0"
    testDisasm "46001805" "abs.s f0, f3"
    testDisasm "46201805" "abs.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 ADD``() =
    testDisasm "00000020" "add r0, r0, r0"
    testDisasm "00200020" "add r0, at, r0"
    testDisasm "00010020" "add r0, r0, at"
    testDisasm "00000820" "add at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 ADD.fmt``() =
    testDisasm "46000000" "add.s f0, f0, f0"
    testDisasm "46200000" "add.d f0, f0, f0"
    testDisasm "46021900" "add.s f4, f3, f2"
    testDisasm "46221900" "add.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 ADDIU``() =
    testDisasm "24000000" "addiu r0, r0, 0x0"
    testDisasm "24200000" "addiu r0, at, 0x0"
    testDisasm "24010000" "addiu at, r0, 0x0"
    testDisasm "24400000" "addiu r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 ADDIUPC``() =
    testDisasm "ec000000" "addiupc r0, 0x0"
    testDisasm "ec200000" "addiupc at, 0x0"
    testDisasm "ec400000" "addiupc v0, 0x0"
    testDisasm "ec600000" "addiupc v1, 0x0"

  [<TestMethod>]
  member _.``MD00087 ADDU``() =
    testDisasm "00000021" "addu r0, r0, r0"
    testDisasm "00200021" "addu r0, at, r0"
    testDisasm "00010021" "addu r0, r0, at"
    testDisasm "00000821" "addu at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 ALIGN``() =
    testDisasm "7c000220" "align r0, r0, r0, 0x0"
    testDisasm "7c000260" "align r0, r0, r0, 0x1"
    testDisasm "7c0002a0" "align r0, r0, r0, 0x2"
    testDisasm "7c0002e0" "align r0, r0, r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 ALUIPC``() =
    testDisasm "ec1f0000" "aluipc r0, 0x0"
    testDisasm "ec1f0001" "aluipc r0, 0x1"
    testDisasm "ec1f0002" "aluipc r0, 0x2"
    testDisasm "ec1f0003" "aluipc r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 AND``() =
    testDisasm "00000024" "and r0, r0, r0"
    testDisasm "00200024" "and r0, at, r0"
    testDisasm "00010024" "and r0, r0, at"
    testDisasm "00000824" "and at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 ANDI``() =
    testDisasm "30000000" "andi r0, r0, 0x0"
    testDisasm "30200000" "andi r0, at, 0x0"
    testDisasm "30010000" "andi at, r0, 0x0"
    testDisasm "30400000" "andi r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 AUI``() =
    testDisasm "3c200000" "aui r0, at, 0x0"
    testDisasm "3c400000" "aui r0, v0, 0x0"
    testDisasm "3c600000" "aui r0, v1, 0x0"
    testDisasm "3c800000" "aui r0, a0, 0x0"

  [<TestMethod>]
  member _.``MD00087 AUIPC``() =
    testDisasm "ec1e0000" "auipc r0, 0x0"
    testDisasm "ec1e0001" "auipc r0, 0x1"
    testDisasm "ec1e0002" "auipc r0, 0x2"
    testDisasm "ec1e0003" "auipc r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 B``() =
    testDisasm "10000000" "b 0x4"

  [<TestMethod>]
  member _.``MD00087 BAL``() =
    testDisasm "04110000" "bal 0x4"
    testDisasm "04110001" "bal 0x8"
    testDisasm "04110002" "bal 0xc"
    testDisasm "04110003" "bal 0x10"

  [<TestMethod>]
  member _.``MD00087 BALC``() =
    testDisasm "e8000000" "balc 0x4"

  [<TestMethod>]
  member _.``MD00087 BC``() =
    testDisasm "c8000000" "bc 0x4"

  [<TestMethod>]
  member _.``MD00087 BC1EQZ``() =
    testDisasm "45200000" "bc1eqz f0, 0x4"
    testDisasm "45200001" "bc1eqz f0, 0x8"
    testDisasm "45200002" "bc1eqz f0, 0xc"
    testDisasm "45200003" "bc1eqz f0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BC1NEZ``() =
    testDisasm "45a00000" "bc1nez f0, 0x4"
    testDisasm "45a00001" "bc1nez f0, 0x8"
    testDisasm "45a00002" "bc1nez f0, 0xc"
    testDisasm "45a00003" "bc1nez f0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BC2EQZ``() =
    testDisasm "49200000" "bc2eqz 0x0, 0x4"
    testDisasm "49200001" "bc2eqz 0x0, 0x8"
    testDisasm "49200002" "bc2eqz 0x0, 0xc"
    testDisasm "49200003" "bc2eqz 0x0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BC2NEZ``() =
    testDisasm "49a00000" "bc2nez 0x0, 0x4"
    testDisasm "49a00001" "bc2nez 0x0, 0x8"
    testDisasm "49a00002" "bc2nez 0x0, 0xc"
    testDisasm "49a00003" "bc2nez 0x0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BEQ``() =
    testDisasm "10200000" "beq at, r0, 0x4"
    testDisasm "10010000" "beq r0, at, 0x4"
    testDisasm "10400000" "beq v0, r0, 0x4"
    testDisasm "10020000" "beq r0, v0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BEQC``() =
    testDisasm "20220100" "beqc at, v0, 0x404"
    testDisasm "20221800" "beqc at, v0, 0x6004"
    testDisasm "20221900" "beqc at, v0, 0x6404"
    testDisasm "20220900" "beqc at, v0, 0x2404"

  [<TestMethod>]
  member _.``MD00087 BEQZALC``() =
    testDisasm "20010000" "beqzalc at, 0x4"
    testDisasm "20020000" "beqzalc v0, 0x4"
    testDisasm "20030000" "beqzalc v1, 0x4"
    testDisasm "20040000" "beqzalc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BEQZC``() =
    testDisasm "d8200000" "beqzc at, 0x4"
    testDisasm "d8400000" "beqzc v0, 0x4"
    testDisasm "d8600000" "beqzc v1, 0x4"
    testDisasm "d8800000" "beqzc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BGEC``() =
    testDisasm "58220100" "bgec at, v0, 0x404"
    testDisasm "58221800" "bgec at, v0, 0x6004"
    testDisasm "58221900" "bgec at, v0, 0x6404"
    testDisasm "58220900" "bgec at, v0, 0x2404"

  [<TestMethod>]
  member _.``MD00087 BGEUC``() =
    testDisasm "18220100" "bgeuc at, v0, 0x404"
    testDisasm "18221800" "bgeuc at, v0, 0x6004"
    testDisasm "18221900" "bgeuc at, v0, 0x6404"
    testDisasm "18220900" "bgeuc at, v0, 0x2404"

  [<TestMethod>]
  member _.``MD00087 BGEZ``() =
    testDisasm "04010000" "bgez r0, 0x4"
    testDisasm "04010001" "bgez r0, 0x8"
    testDisasm "04010002" "bgez r0, 0xc"
    testDisasm "04010003" "bgez r0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BGEZALC``() =
    testDisasm "18211900" "bgezalc at, 0x6404"
    testDisasm "18421900" "bgezalc v0, 0x6404"
    testDisasm "18211901" "bgezalc at, 0x6408"
    testDisasm "18421901" "bgezalc v0, 0x6408"

  [<TestMethod>]
  member _.``MD00087 BGEZC``() =
    testDisasm "58211900" "bgezc at, 0x6404"
    testDisasm "58421900" "bgezc v0, 0x6404"
    testDisasm "58211901" "bgezc at, 0x6408"
    testDisasm "58421901" "bgezc v0, 0x6408"

  [<TestMethod>]
  member _.``MD00087 BGTZ``() =
    testDisasm "1c000000" "bgtz r0, 0x4"
    testDisasm "1c200000" "bgtz at, 0x4"
    testDisasm "1c400000" "bgtz v0, 0x4"
    testDisasm "1c600000" "bgtz v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BGTZALC``() =
    testDisasm "1c010000" "bgtzalc at, 0x4"
    testDisasm "1c020000" "bgtzalc v0, 0x4"
    testDisasm "1c030000" "bgtzalc v1, 0x4"
    testDisasm "1c040000" "bgtzalc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BGTZC``() =
    testDisasm "5c010000" "bgtzc at, 0x4"
    testDisasm "5c020000" "bgtzc v0, 0x4"
    testDisasm "5c030000" "bgtzc v1, 0x4"
    testDisasm "5c040000" "bgtzc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BITSWAP``() =
    testDisasm "7c000020" "bitswap r0, r0"
    testDisasm "7c010020" "bitswap r0, at"
    testDisasm "7c000820" "bitswap at, r0"
    testDisasm "7c020020" "bitswap r0, v0"

  [<TestMethod>]
  member _.``MD00087 BLEZ``() =
    testDisasm "18000000" "blez r0, 0x4"
    testDisasm "18200000" "blez at, 0x4"
    testDisasm "18400000" "blez v0, 0x4"
    testDisasm "18600000" "blez v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLEZALC``() =
    testDisasm "18010000" "blezalc at, 0x4"
    testDisasm "18020000" "blezalc v0, 0x4"
    testDisasm "18030000" "blezalc v1, 0x4"
    testDisasm "18040000" "blezalc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLEZC``() =
    testDisasm "58010000" "blezc at, 0x4"
    testDisasm "58020000" "blezc v0, 0x4"
    testDisasm "58030000" "blezc v1, 0x4"
    testDisasm "58040000" "blezc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLTC``() =
    testDisasm "5c220100" "bltc at, v0, 0x404"
    testDisasm "5c221800" "bltc at, v0, 0x6004"
    testDisasm "5c221900" "bltc at, v0, 0x6404"
    testDisasm "5c220900" "bltc at, v0, 0x2404"

  [<TestMethod>]
  member _.``MD00087 BLTUC``() =
    testDisasm "1c220100" "bltuc at, v0, 0x404"
    testDisasm "1c221800" "bltuc at, v0, 0x6004"
    testDisasm "1c221900" "bltuc at, v0, 0x6404"
    testDisasm "1c220900" "bltuc at, v0, 0x2404"

  [<TestMethod>]
  member _.``MD00087 BLTZ``() =
    testDisasm "04000000" "bltz r0, 0x4"
    testDisasm "04200000" "bltz at, 0x4"
    testDisasm "04400000" "bltz v0, 0x4"
    testDisasm "04600000" "bltz v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLTZALC``() =
    testDisasm "1c211900" "bltzalc at, 0x6404"
    testDisasm "1c421900" "bltzalc v0, 0x6404"
    testDisasm "1c211901" "bltzalc at, 0x6408"
    testDisasm "1c421901" "bltzalc v0, 0x6408"

  [<TestMethod>]
  member _.``MD00087 BLTZC``() =
    testDisasm "5c211900" "bltzc at, 0x6404"
    testDisasm "5c421900" "bltzc v0, 0x6404"
    testDisasm "5c211901" "bltzc at, 0x6408"
    testDisasm "5c421901" "bltzc v0, 0x6408"

  [<TestMethod>]
  member _.``MD00087 BNE``() =
    testDisasm "14000000" "bne r0, r0, 0x4"
    testDisasm "14200000" "bne at, r0, 0x4"
    testDisasm "14010000" "bne r0, at, 0x4"
    testDisasm "14400000" "bne v0, r0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BNEC``() =
    testDisasm "60220100" "bnec at, v0, 0x404"
    testDisasm "60221800" "bnec at, v0, 0x6004"
    testDisasm "60221900" "bnec at, v0, 0x6404"
    testDisasm "60220900" "bnec at, v0, 0x2404"

  [<TestMethod>]
  member _.``MD00087 BNEZALC``() =
    testDisasm "60010000" "bnezalc at, 0x4"
    testDisasm "60020000" "bnezalc v0, 0x4"
    testDisasm "60030000" "bnezalc v1, 0x4"
    testDisasm "60040000" "bnezalc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BNEZC``() =
    testDisasm "f8200000" "bnezc at, 0x4"
    testDisasm "f8400000" "bnezc v0, 0x4"
    testDisasm "f8600000" "bnezc v1, 0x4"
    testDisasm "f8800000" "bnezc a0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BNVC``() =
    testDisasm "60000000" "bnvc r0, r0, 0x4"
    testDisasm "60200000" "bnvc at, r0, 0x4"
    testDisasm "60400000" "bnvc v0, r0, 0x4"
    testDisasm "60600000" "bnvc v1, r0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BOVC``() =
    testDisasm "20000000" "bovc r0, r0, 0x4"
    testDisasm "20200000" "bovc at, r0, 0x4"
    testDisasm "20400000" "bovc v0, r0, 0x4"
    testDisasm "20600000" "bovc v1, r0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BREAK``() =
    testDisasm "0000000d" "break"

  [<TestMethod>]
  member _.``MD00087 CACHE``() =
    testDisasm "7c000025" "cache 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 CACHEE``() =
    testDisasm "7c00001b" "cachee 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 CEIL.L.fmt``() =
    testDisasm "4600000a" "ceil.l.s f0, f0"
    testDisasm "4620000a" "ceil.l.d f0, f0"
    testDisasm "4600180a" "ceil.l.s f0, f3"
    testDisasm "4620180a" "ceil.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CEIL.W.fmt``() =
    testDisasm "4600000e" "ceil.w.s f0, f0"
    testDisasm "4620000e" "ceil.w.d f0, f0"
    testDisasm "4600180e" "ceil.w.s f0, f3"
    testDisasm "4620180e" "ceil.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CFC1``() =
    testDisasm "44400000" "cfc1 r0, f0"
    testDisasm "44401800" "cfc1 r0, f3"
    testDisasm "44411800" "cfc1 at, f3"
    testDisasm "44421800" "cfc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 CFC2``() =
    testDisasm "48400000" "cfc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 CLASS.fmt``() =
    testDisasm "4600001b" "class.s f0, f0"
    testDisasm "4620001b" "class.d f0, f0"
    testDisasm "4600181b" "class.s f0, f3"
    testDisasm "4620181b" "class.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CLO``() =
    testDisasm "00000051" "clo r0, r0"

  [<TestMethod>]
  member _.``MD00087 CLZ``() =
    testDisasm "00000050" "clz r0, r0"

  [<TestMethod>]
  member _.``MD00087 CMP.condn.fmt``() =
    testDisasm "46800000" "cmp.af.s f0, f0, f0"
    testDisasm "46a00000" "cmp.af.d f0, f0, f0"
    testDisasm "46800001" "cmp.un.s f0, f0, f0"
    testDisasm "46a00001" "cmp.un.d f0, f0, f0"

  [<TestMethod>]
  member _.``MD00087 COP2``() =
    testDisasm "4a000000" "cop2 0x0"
    testDisasm "4a200000" "cop2 0x200000"
    testDisasm "4a400000" "cop2 0x400000"
    testDisasm "4a600000" "cop2 0x600000"

  [<TestMethod>]
  member _.``MD00087 CRC32B``() =
    testDisasm "7c00000f" "crc32b r0, r0, r0"
    testDisasm "7c20000f" "crc32b r0, at, r0"
    testDisasm "7c01000f" "crc32b at, r0, at"
    testDisasm "7c40000f" "crc32b r0, v0, r0"

  [<TestMethod>]
  member _.``MD00087 CRC32CB``() =
    testDisasm "7c00010f" "crc32cb r0, r0, r0"
    testDisasm "7c22010f" "crc32cb v0, at, v0"

  [<TestMethod>]
  member _.``MD00087 CRC32CD``() =
    testDisasm "7c0001cf" "crc32cd r0, r0, r0"

  [<TestMethod>]
  member _.``MD00087 CRC32CH``() =
    testDisasm "7c00014f" "crc32ch r0, r0, r0"

  [<TestMethod>]
  member _.``MD00087 CRC32CW``() =
    testDisasm "7c00018f" "crc32cw r0, r0, r0"

  [<TestMethod>]
  member _.``MD00087 CRC32D``() =
    testDisasm "7c0000cf" "crc32d r0, r0, r0"

  [<TestMethod>]
  member _.``MD00087 CRC32H``() =
    testDisasm "7c00004f" "crc32h r0, r0, r0"

  [<TestMethod>]
  member _.``MD00087 CRC32W``() =
    testDisasm "7c00008f" "crc32w r0, r0, r0"

  [<TestMethod>]
  member _.``MD00087 CTC1``() =
    testDisasm "44c00000" "ctc1 r0, f0"
    testDisasm "44c01800" "ctc1 r0, f3"
    testDisasm "44c11800" "ctc1 at, f3"
    testDisasm "44c21800" "ctc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 CTC2``() =
    testDisasm "48c00000" "ctc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 CVT.D.fmt``() =
    testDisasm "46000021" "cvt.d.s f0, f0"
    testDisasm "46800021" "cvt.d.w f0, f0"
    testDisasm "46a00021" "cvt.d.l f0, f0"
    testDisasm "46001821" "cvt.d.s f0, f3"

  [<TestMethod>]
  member _.``MD00087 CVT.L.fmt``() =
    testDisasm "46000025" "cvt.l.s f0, f0"
    testDisasm "46200025" "cvt.l.d f0, f0"
    testDisasm "46001825" "cvt.l.s f0, f3"
    testDisasm "46201825" "cvt.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CVT.S.fmt``() =
    testDisasm "46200020" "cvt.s.d f0, f0"
    testDisasm "46800020" "cvt.s.w f0, f0"
    testDisasm "46a00020" "cvt.s.l f0, f0"
    testDisasm "46201820" "cvt.s.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 CVT.W.fmt``() =
    testDisasm "46000024" "cvt.w.s f0, f0"
    testDisasm "46200024" "cvt.w.d f0, f0"
    testDisasm "46001824" "cvt.w.s f0, f3"
    testDisasm "46201824" "cvt.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 DADD``() =
    testDisasm "0000002c" "dadd r0, r0, r0"
    testDisasm "0020002c" "dadd r0, at, r0"
    testDisasm "0001002c" "dadd r0, r0, at"
    testDisasm "0000082c" "dadd at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 DADDIU``() =
    testDisasm "64000000" "daddiu r0, r0, 0x0"
    testDisasm "64200000" "daddiu r0, at, 0x0"
    testDisasm "64010000" "daddiu at, r0, 0x0"
    testDisasm "64400000" "daddiu r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DADDU``() =
    testDisasm "0001002d" "daddu r0, r0, at"
    testDisasm "0002002d" "daddu r0, r0, v0"
    testDisasm "0003002d" "daddu r0, r0, v1"
    testDisasm "0004002d" "daddu r0, r0, a0"

  [<TestMethod>]
  member _.``MD00087 DAHI``() =
    testDisasm "04060000" "dahi r0, 0x0"
    testDisasm "04060001" "dahi r0, 0x1"
    testDisasm "04060002" "dahi r0, 0x2"
    testDisasm "04060003" "dahi r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 DALIGN``() =
    testDisasm "7c000224" "dalign r0, r0, r0, 0x0"
    testDisasm "7c000264" "dalign r0, r0, r0, 0x1"
    testDisasm "7c0002a4" "dalign r0, r0, r0, 0x2"
    testDisasm "7c0002e4" "dalign r0, r0, r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 DATI``() =
    testDisasm "041e0000" "dati r0, 0x0"
    testDisasm "041e0001" "dati r0, 0x1"
    testDisasm "041e0002" "dati r0, 0x2"
    testDisasm "041e0003" "dati r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 DAUI``() =
    testDisasm "74200000" "daui r0, at, 0x0"
    testDisasm "74400000" "daui r0, v0, 0x0"
    testDisasm "74600000" "daui r0, v1, 0x0"
    testDisasm "74800000" "daui r0, a0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DBITSWAP``() =
    testDisasm "7c000024" "dbitswap r0, r0"
    testDisasm "7c010024" "dbitswap r0, at"
    testDisasm "7c000824" "dbitswap at, r0"
    testDisasm "7c020024" "dbitswap r0, v0"

  [<TestMethod>]
  member _.``MD00087 DCLO``() =
    testDisasm "00000053" "dclo r0, r0"

  [<TestMethod>]
  member _.``MD00087 DCLZ``() =
    testDisasm "00000052" "dclz r0, r0"

  [<TestMethod>]
  member _.``MD00087 DDIV``() =
    testDisasm "0000009e" "ddiv r0, r0, r0"
    testDisasm "0022189e" "ddiv v1, at, v0"
    testDisasm "03fee89e" "ddiv sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DDIVU``() =
    testDisasm "0000009f" "ddivu r0, r0, r0"
    testDisasm "0022189f" "ddivu v1, at, v0"
    testDisasm "03fee89f" "ddivu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DERET``() =
    testDisasm "4200001f" "deret"

  [<TestMethod>]
  member _.``MD00087 DEXT``() =
    testDisasm "7c000003" "dext r0, r0, 0x0, 0x1"
    testDisasm "7c200003" "dext r0, at, 0x0, 0x1"
    testDisasm "7c010003" "dext at, r0, 0x0, 0x1"
    testDisasm "7c400003" "dext r0, v0, 0x0, 0x1"

  [<TestMethod>]
  member _.``MD00087 DEXTM``() =
    testDisasm "7c000001" "dextm r0, r0, 0x0, 0x21"
    testDisasm "7c200001" "dextm r0, at, 0x0, 0x21"
    testDisasm "7c010001" "dextm at, r0, 0x0, 0x21"
    testDisasm "7c400001" "dextm r0, v0, 0x0, 0x21"

  [<TestMethod>]
  member _.``MD00087 DEXTU``() =
    testDisasm "7c000002" "dextu r0, r0, 0x20, 0x1"
    testDisasm "7c200002" "dextu r0, at, 0x20, 0x1"
    testDisasm "7c010002" "dextu at, r0, 0x20, 0x1"
    testDisasm "7c400002" "dextu r0, v0, 0x20, 0x1"

  [<TestMethod>]
  member _.``MD00087 DI``() =
    testDisasm "41626000" "di v0"

  [<TestMethod>]
  member _.``MD00087 DINS``() =
    testDisasm "7c000007" "dins r0, r0, 0x0, 0x1"
    testDisasm "7c200007" "dins r0, at, 0x0, 0x1"
    testDisasm "7c010007" "dins at, r0, 0x0, 0x1"
    testDisasm "7c400007" "dins r0, v0, 0x0, 0x1"

  [<TestMethod>]
  member _.``MD00087 DINSM``() =
    testDisasm "7c000005" "dinsm r0, r0, 0x0, 0x21"
    testDisasm "7c200005" "dinsm r0, at, 0x0, 0x21"
    testDisasm "7c010005" "dinsm at, r0, 0x0, 0x21"
    testDisasm "7c400005" "dinsm r0, v0, 0x0, 0x21"

  [<TestMethod>]
  member _.``MD00087 DINSU``() =
    testDisasm "7c000006" "dinsu r0, r0, 0x20, 0x1"
    testDisasm "7c200006" "dinsu r0, at, 0x20, 0x1"
    testDisasm "7c010006" "dinsu at, r0, 0x20, 0x1"
    testDisasm "7c400006" "dinsu r0, v0, 0x20, 0x1"

  [<TestMethod>]
  member _.``MD00087 DIV``() =
    testDisasm "0000009a" "div r0, r0, r0"
    testDisasm "0022189a" "div v1, at, v0"
    testDisasm "03fee89a" "div sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DIV.fmt``() =
    testDisasm "46000003" "div.s f0, f0, f0"
    testDisasm "46200003" "div.d f0, f0, f0"
    testDisasm "46021903" "div.s f4, f3, f2"
    testDisasm "46221903" "div.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 DIVU``() =
    testDisasm "0000009b" "divu r0, r0, r0"
    testDisasm "0022189b" "divu v1, at, v0"
    testDisasm "03fee89b" "divu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DLSA``() =
    testDisasm "00000015" "dlsa r0, r0, r0, 0x0"
    testDisasm "00200015" "dlsa r0, at, r0, 0x0"
    testDisasm "00010015" "dlsa r0, r0, at, 0x0"
    testDisasm "00000815" "dlsa at, r0, r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DMFC0``() =
    testDisasm "40200001" "dmfc0 r0, 0x0, 0x1"
    testDisasm "40200002" "dmfc0 r0, 0x0, 0x2"
    testDisasm "40200003" "dmfc0 r0, 0x0, 0x3"
    testDisasm "40221801" "dmfc0 v0, 0x3, 0x1"

  [<TestMethod>]
  member _.``MD00087 DMFC1``() =
    testDisasm "44200000" "dmfc1 r0, f0"
    testDisasm "44221800" "dmfc1 v0, f3"
    testDisasm "44201800" "dmfc1 r0, f3"
    testDisasm "44211800" "dmfc1 at, f3"

  [<TestMethod>]
  member _.``MD00087 DMFC2``() =
    testDisasm "48200000" "dmfc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DMOD``() =
    testDisasm "000000de" "dmod r0, r0, r0"
    testDisasm "002218de" "dmod v1, at, v0"
    testDisasm "03fee8de" "dmod sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DMODU``() =
    testDisasm "000000df" "dmodu r0, r0, r0"
    testDisasm "002218df" "dmodu v1, at, v0"
    testDisasm "03fee8df" "dmodu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DMTC0``() =
    testDisasm "40a00001" "dmtc0 r0, 0x0, 0x1"
    testDisasm "40a00002" "dmtc0 r0, 0x0, 0x2"
    testDisasm "40a00003" "dmtc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``MD00087 DMTC1``() =
    testDisasm "44a00000" "dmtc1 r0, f0"
    testDisasm "44a01800" "dmtc1 r0, f3"
    testDisasm "44a11800" "dmtc1 at, f3"
    testDisasm "44a21800" "dmtc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 DMTC2``() =
    testDisasm "48a00000" "dmtc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DMUH``() =
    testDisasm "000000dc" "dmuh r0, r0, r0"
    testDisasm "002218dc" "dmuh v1, at, v0"
    testDisasm "03fee8dc" "dmuh sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DMUHU``() =
    testDisasm "000000dd" "dmuhu r0, r0, r0"
    testDisasm "002218dd" "dmuhu v1, at, v0"
    testDisasm "03fee8dd" "dmuhu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DMUL``() =
    testDisasm "0000009c" "dmul r0, r0, r0"
    testDisasm "0022189c" "dmul v1, at, v0"
    testDisasm "03fee89c" "dmul sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DMULU``() =
    testDisasm "0000009d" "dmulu r0, r0, r0"
    testDisasm "0022189d" "dmulu v1, at, v0"
    testDisasm "03fee89d" "dmulu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 DROTR``() =
    testDisasm "0020003a" "drotr r0, r0, 0x0"
    testDisasm "0020193a" "drotr v1, r0, 0x4"
    testDisasm "0022013a" "drotr r0, v0, 0x4"
    testDisasm "0022183a" "drotr v1, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DROTR32``() =
    testDisasm "0020003e" "drotr32  r0, r0, 0x0"
    testDisasm "0020193e" "drotr32  v1, r0, 0x4"
    testDisasm "0022013e" "drotr32  r0, v0, 0x4"
    testDisasm "0022183e" "drotr32  v1, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DROTRV``() =
    testDisasm "00000056" "drotrv r0, r0, r0"
    testDisasm "00221856" "drotrv v1, v0, at"
    testDisasm "03fee856" "drotrv sp, s8, ra"

  [<TestMethod>]
  member _.``MD00087 DSBH``() =
    testDisasm "7c0000a4" "dsbh r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSHD``() =
    testDisasm "7c000164" "dshd r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSLL``() =
    testDisasm "00000038" "dsll r0, r0, 0x0"
    testDisasm "00010038" "dsll r0, at, 0x0"
    testDisasm "00000838" "dsll at, r0, 0x0"
    testDisasm "00020038" "dsll r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSLL32``() =
    testDisasm "0000003c" "dsll32 r0, r0, 0x0"
    testDisasm "0001003c" "dsll32 r0, at, 0x0"
    testDisasm "0000083c" "dsll32 at, r0, 0x0"
    testDisasm "0002003c" "dsll32 r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSLLV``() =
    testDisasm "00000014" "dsllv r0, r0, r0"
    testDisasm "00200014" "dsllv r0, r0, at"
    testDisasm "00010014" "dsllv r0, at, r0"
    testDisasm "00000814" "dsllv at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSRA``() =
    testDisasm "0000003b" "dsra r0, r0, 0x0"
    testDisasm "0001003b" "dsra r0, at, 0x0"
    testDisasm "0000083b" "dsra at, r0, 0x0"
    testDisasm "0002003b" "dsra r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSRA32``() =
    testDisasm "0000003f" "dsra32 r0, r0, 0x0"
    testDisasm "0001003f" "dsra32 r0, at, 0x0"
    testDisasm "0000083f" "dsra32 at, r0, 0x0"
    testDisasm "0002003f" "dsra32 r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSRAV``() =
    testDisasm "00000017" "dsrav r0, r0, r0"
    testDisasm "00200017" "dsrav r0, r0, at"
    testDisasm "00010017" "dsrav r0, at, r0"
    testDisasm "00000817" "dsrav at, r0, r0"
