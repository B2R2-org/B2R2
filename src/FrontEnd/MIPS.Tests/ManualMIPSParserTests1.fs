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
/// One test for each instruction MD00087 describes, ABS.fmt to LDL. Each reads
/// words of the instruction and checks the text, and each word is one binutils'
/// objdump reads as the same instruction with the same operands, so what is
/// asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualMIPSParserTests1() =
  let isa =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser = Parser(isa, BinReader.Init isa.Endian) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  [<TestMethod>]
  member _.``MD00087 ABS.fmt``() =
    testDisasm "46000005" "abs.s f0, f0"
    testDisasm "46200005" "abs.d f0, f0"
    testDisasm "46c00005" "abs.ps f0, f0"
    testDisasm "46001805" "abs.s f0, f3"

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
    testDisasm "46c00000" "add.ps f0, f0, f0"
    testDisasm "46021900" "add.s f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 ADDI``() =
    testDisasm "20000000" "addi r0, r0, 0x0"
    testDisasm "20200000" "addi r0, at, 0x0"
    testDisasm "20010000" "addi at, r0, 0x0"
    testDisasm "20400000" "addi r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 ADDIU``() =
    testDisasm "24000000" "addiu r0, r0, 0x0"
    testDisasm "24200000" "addiu r0, at, 0x0"
    testDisasm "24010000" "addiu at, r0, 0x0"
    testDisasm "24400000" "addiu r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 ADDU``() =
    testDisasm "00000021" "addu r0, r0, r0"
    testDisasm "00200021" "addu r0, at, r0"
    testDisasm "00010021" "addu r0, r0, at"
    testDisasm "00000821" "addu at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 ALNV.PS``() =
    testDisasm "4c00001e" "alnv.ps f0, f0, f0, r0"
    testDisasm "4c20001e" "alnv.ps f0, f0, f0, at"
    testDisasm "4c01001e" "alnv.ps f0, f0, f1, r0"
    testDisasm "4c00081e" "alnv.ps f0, f1, f0, r0"

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
  member _.``MD00087 B``() =
    testDisasm "10000000" "b 0x4"

  [<TestMethod>]
  member _.``MD00087 BAL``() =
    testDisasm "04110000" "bal 0x4"
    testDisasm "04110001" "bal 0x8"
    testDisasm "04110002" "bal 0xc"
    testDisasm "04110003" "bal 0x10"

  [<TestMethod>]
  member _.``MD00087 BC1F``() =
    testDisasm "45000000" "bc1f 0x4"
    testDisasm "45000001" "bc1f 0x8"
    testDisasm "45000002" "bc1f 0xc"
    testDisasm "45000003" "bc1f 0x10"

  [<TestMethod>]
  member _.``MD00087 BC1FL``() =
    testDisasm "45021900" "bc1fl 0x6404"
    testDisasm "45021901" "bc1fl 0x6408"
    testDisasm "45021902" "bc1fl 0x640c"
    testDisasm "45021903" "bc1fl 0x6410"

  [<TestMethod>]
  member _.``MD00087 BC1T``() =
    testDisasm "45011800" "bc1t 0x6004"
    testDisasm "45011801" "bc1t 0x6008"
    testDisasm "45011802" "bc1t 0x600c"
    testDisasm "45011803" "bc1t 0x6010"

  [<TestMethod>]
  member _.``MD00087 BC1TL``() =
    testDisasm "45031800" "bc1tl 0x6004"
    testDisasm "45031801" "bc1tl 0x6008"
    testDisasm "45031802" "bc1tl 0x600c"
    testDisasm "45031803" "bc1tl 0x6010"

  [<TestMethod>]
  member _.``MD00087 BC2F``() =
    testDisasm "49000000" "bc2f 0x4"
    testDisasm "49000001" "bc2f 0x8"
    testDisasm "49000002" "bc2f 0xc"
    testDisasm "49000003" "bc2f 0x10"

  [<TestMethod>]
  member _.``MD00087 BC2FL``() =
    testDisasm "49021900" "bc2fl 0x6404"
    testDisasm "49021901" "bc2fl 0x6408"
    testDisasm "49021902" "bc2fl 0x640c"
    testDisasm "49021903" "bc2fl 0x6410"

  [<TestMethod>]
  member _.``MD00087 BC2T``() =
    testDisasm "49010003" "bc2t 0x10"

  [<TestMethod>]
  member _.``MD00087 BC2TL``() =
    testDisasm "49030001" "bc2tl 0x8"

  [<TestMethod>]
  member _.``MD00087 BEQ``() =
    testDisasm "10200000" "beq at, r0, 0x4"
    testDisasm "10010000" "beq r0, at, 0x4"
    testDisasm "10400000" "beq v0, r0, 0x4"
    testDisasm "10020000" "beq r0, v0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BEQL``() =
    testDisasm "50000000" "beql r0, r0, 0x4"
    testDisasm "50200000" "beql at, r0, 0x4"
    testDisasm "50010000" "beql r0, at, 0x4"
    testDisasm "50400000" "beql v0, r0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BGEZ``() =
    testDisasm "04010000" "bgez r0, 0x4"
    testDisasm "04010001" "bgez r0, 0x8"
    testDisasm "04010002" "bgez r0, 0xc"
    testDisasm "04010003" "bgez r0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BGEZAL``() =
    testDisasm "04311900" "bgezal at, 0x6404"
    testDisasm "04311901" "bgezal at, 0x6408"
    testDisasm "04311902" "bgezal at, 0x640c"
    testDisasm "04311903" "bgezal at, 0x6410"

  [<TestMethod>]
  member _.``MD00087 BGEZALL``() =
    testDisasm "04130000" "bgezall r0, 0x4"
    testDisasm "04130001" "bgezall r0, 0x8"
    testDisasm "04130002" "bgezall r0, 0xc"
    testDisasm "04130003" "bgezall r0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BGEZL``() =
    testDisasm "04030000" "bgezl r0, 0x4"
    testDisasm "04030001" "bgezl r0, 0x8"
    testDisasm "04030002" "bgezl r0, 0xc"
    testDisasm "04030003" "bgezl r0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BGTZ``() =
    testDisasm "1c000000" "bgtz r0, 0x4"
    testDisasm "1c200000" "bgtz at, 0x4"
    testDisasm "1c400000" "bgtz v0, 0x4"
    testDisasm "1c600000" "bgtz v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BGTZL``() =
    testDisasm "5c000000" "bgtzl r0, 0x4"
    testDisasm "5c200000" "bgtzl at, 0x4"
    testDisasm "5c400000" "bgtzl v0, 0x4"
    testDisasm "5c600000" "bgtzl v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLEZ``() =
    testDisasm "18000000" "blez r0, 0x4"
    testDisasm "18200000" "blez at, 0x4"
    testDisasm "18400000" "blez v0, 0x4"
    testDisasm "18600000" "blez v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLEZL``() =
    testDisasm "58000000" "blezl r0, 0x4"
    testDisasm "58200000" "blezl at, 0x4"
    testDisasm "58400000" "blezl v0, 0x4"
    testDisasm "58600000" "blezl v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLTZ``() =
    testDisasm "04000000" "bltz r0, 0x4"
    testDisasm "04200000" "bltz at, 0x4"
    testDisasm "04400000" "bltz v0, 0x4"
    testDisasm "04600000" "bltz v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 BLTZAL``() =
    testDisasm "04301900" "bltzal at, 0x6404"
    testDisasm "04301901" "bltzal at, 0x6408"
    testDisasm "04301902" "bltzal at, 0x640c"
    testDisasm "04301903" "bltzal at, 0x6410"

  [<TestMethod>]
  member _.``MD00087 BLTZALL``() =
    testDisasm "04120000" "bltzall r0, 0x4"
    testDisasm "04120001" "bltzall r0, 0x8"
    testDisasm "04120002" "bltzall r0, 0xc"
    testDisasm "04120003" "bltzall r0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BLTZL``() =
    testDisasm "04020000" "bltzl r0, 0x4"
    testDisasm "04020001" "bltzl r0, 0x8"
    testDisasm "04020002" "bltzl r0, 0xc"
    testDisasm "04020003" "bltzl r0, 0x10"

  [<TestMethod>]
  member _.``MD00087 BNE``() =
    testDisasm "14000000" "bne r0, r0, 0x4"
    testDisasm "14200000" "bne at, r0, 0x4"
    testDisasm "14010000" "bne r0, at, 0x4"
    testDisasm "14400000" "bne v0, r0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BNEL``() =
    testDisasm "54000000" "bnel r0, r0, 0x4"
    testDisasm "54200000" "bnel at, r0, 0x4"
    testDisasm "54010000" "bnel r0, at, 0x4"
    testDisasm "54400000" "bnel v0, r0, 0x4"

  [<TestMethod>]
  member _.``MD00087 BREAK``() =
    testDisasm "0000000d" "break"

  [<TestMethod>]
  member _.``MD00087 C.cond.fmt``() =
    testDisasm "46000030" "c.f.s f0, f0"
    testDisasm "46200030" "c.f.d f0, f0"
    testDisasm "46c00030" "c.f.ps f0, f0"
    testDisasm "46000031" "c.un.s f0, f0"

  [<TestMethod>]
  member _.``MD00087 CACHE``() =
    testDisasm "bc000000" "cache 0x0, 0(r0)"

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
  member _.``MD00087 CLO``() =
    testDisasm "70000021" "clo r0, r0"
    testDisasm "70200021" "clo r0, at"
    testDisasm "70000821" "clo at, r0"
    testDisasm "70400021" "clo r0, v0"

  [<TestMethod>]
  member _.``MD00087 CLZ``() =
    testDisasm "70000020" "clz r0, r0"
    testDisasm "70200020" "clz r0, at"
    testDisasm "70000820" "clz at, r0"
    testDisasm "70400020" "clz r0, v0"

  [<TestMethod>]
  member _.``MD00087 COP2``() =
    testDisasm "4a000000" "cop2 0x0"
    testDisasm "4a200000" "cop2 0x200000"
    testDisasm "4a400000" "cop2 0x400000"
    testDisasm "4a600000" "cop2 0x600000"

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
  member _.``MD00087 CVT.PS.S``() =
    testDisasm "46000026" "cvt.ps.s f0, f0, f0"
    testDisasm "46021926" "cvt.ps.s f4, f3, f2"
    testDisasm "461eef26" "cvt.ps.s f28, f29, f30"
    testDisasm "46001826" "cvt.ps.s f0, f3, f0"

  [<TestMethod>]
  member _.``MD00087 CVT.S.PL``() =
    testDisasm "46c00028" "cvt.s.pl f0, f0"
    testDisasm "46c01828" "cvt.s.pl f0, f3"

  [<TestMethod>]
  member _.``MD00087 CVT.S.PU``() =
    testDisasm "46c00020" "cvt.s.pu f0, f0"
    testDisasm "46c01820" "cvt.s.pu f0, f3"

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
  member _.``MD00087 DADDI``() =
    testDisasm "60000000" "daddi r0, r0, 0x0"
    testDisasm "60200000" "daddi r0, at, 0x0"
    testDisasm "60010000" "daddi at, r0, 0x0"
    testDisasm "60400000" "daddi r0, v0, 0x0"

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
  member _.``MD00087 DCLO``() =
    testDisasm "70000025" "dclo r0, r0"
    testDisasm "70200025" "dclo r0, at"
    testDisasm "70000825" "dclo at, r0"
    testDisasm "70400025" "dclo r0, v0"

  [<TestMethod>]
  member _.``MD00087 DCLZ``() =
    testDisasm "70000024" "dclz r0, r0"
    testDisasm "70200024" "dclz r0, at"
    testDisasm "70000824" "dclz at, r0"
    testDisasm "70400024" "dclz r0, v0"

  [<TestMethod>]
  member _.``MD00087 DDIV``() =
    testDisasm "0000001e" "ddiv r0, r0"
    testDisasm "0020001e" "ddiv at, r0"
    testDisasm "0001001e" "ddiv r0, at"
    testDisasm "0040001e" "ddiv v0, r0"

  [<TestMethod>]
  member _.``MD00087 DDIVU``() =
    testDisasm "0000001f" "ddivu r0, r0"
    testDisasm "0020001f" "ddivu at, r0"
    testDisasm "0001001f" "ddivu r0, at"
    testDisasm "0040001f" "ddivu v0, r0"

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
    testDisasm "0000001a" "div r0, r0"
    testDisasm "0020001a" "div at, r0"
    testDisasm "0001001a" "div r0, at"
    testDisasm "0040001a" "div v0, r0"

  [<TestMethod>]
  member _.``MD00087 DIV.fmt``() =
    testDisasm "46000003" "div.s f0, f0, f0"
    testDisasm "46200003" "div.d f0, f0, f0"
    testDisasm "46021903" "div.s f4, f3, f2"
    testDisasm "46221903" "div.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 DIVU``() =
    testDisasm "0000001b" "divu r0, r0"
    testDisasm "0020001b" "divu at, r0"
    testDisasm "0001001b" "divu r0, at"
    testDisasm "0040001b" "divu v0, r0"

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
  member _.``MD00087 DMULT``() =
    testDisasm "0000001c" "dmult r0, r0"
    testDisasm "0020001c" "dmult at, r0"
    testDisasm "0001001c" "dmult r0, at"
    testDisasm "0040001c" "dmult v0, r0"

  [<TestMethod>]
  member _.``MD00087 DMULTU``() =
    testDisasm "0000001d" "dmultu r0, r0"
    testDisasm "0020001d" "dmultu at, r0"
    testDisasm "0001001d" "dmultu r0, at"
    testDisasm "0040001d" "dmultu v0, r0"

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

  [<TestMethod>]
  member _.``MD00087 DSRL``() =
    testDisasm "0000003a" "dsrl r0, r0, 0x0"
    testDisasm "0001003a" "dsrl r0, at, 0x0"
    testDisasm "0000083a" "dsrl at, r0, 0x0"
    testDisasm "0002003a" "dsrl r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSRL32``() =
    testDisasm "0000003e" "dsrl32 r0, r0, 0x0"
    testDisasm "0001003e" "dsrl32 r0, at, 0x0"
    testDisasm "0000083e" "dsrl32 at, r0, 0x0"
    testDisasm "0002003e" "dsrl32 r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 DSRLV``() =
    testDisasm "00000016" "dsrlv r0, r0, r0"
    testDisasm "00200016" "dsrlv r0, r0, at"
    testDisasm "00010016" "dsrlv r0, at, r0"
    testDisasm "00000816" "dsrlv at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 DSUB``() =
    testDisasm "0020002e" "dsub r0, at, r0"
    testDisasm "0040002e" "dsub r0, v0, r0"
    testDisasm "0060002e" "dsub r0, v1, r0"
    testDisasm "0080002e" "dsub r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 DSUBU``() =
    testDisasm "0020002f" "dsubu r0, at, r0"
    testDisasm "0040002f" "dsubu r0, v0, r0"
    testDisasm "0060002f" "dsubu r0, v1, r0"
    testDisasm "0080002f" "dsubu r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 EHB``() =
    testDisasm "000000c0" "ehb"

  [<TestMethod>]
  member _.``MD00087 EI``() =
    testDisasm "41636020" "ei v1"

  [<TestMethod>]
  member _.``MD00087 ERET``() =
    testDisasm "42000018" "eret"

  [<TestMethod>]
  member _.``MD00087 EXT``() =
    testDisasm "7c000000" "ext r0, r0, 0x0, 0x1"
    testDisasm "7c200000" "ext r0, at, 0x0, 0x1"
    testDisasm "7c010000" "ext at, r0, 0x0, 0x1"
    testDisasm "7c400000" "ext r0, v0, 0x0, 0x1"

  [<TestMethod>]
  member _.``MD00087 FLOOR.L.fmt``() =
    testDisasm "4600000b" "floor.l.s f0, f0"
    testDisasm "4620000b" "floor.l.d f0, f0"
    testDisasm "4600180b" "floor.l.s f0, f3"
    testDisasm "4620180b" "floor.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 FLOOR.W.fmt``() =
    testDisasm "4600000f" "floor.w.s f0, f0"
    testDisasm "4620000f" "floor.w.d f0, f0"
    testDisasm "4600180f" "floor.w.s f0, f3"
    testDisasm "4620180f" "floor.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 INS``() =
    testDisasm "7c000004" "ins r0, r0, 0x0, 0x1"
    testDisasm "7c200004" "ins r0, at, 0x0, 0x1"
    testDisasm "7c010004" "ins at, r0, 0x0, 0x1"
    testDisasm "7c400004" "ins r0, v0, 0x0, 0x1"

  [<TestMethod>]
  member _.``MD00087 J``() =
    testDisasm "08000000" "j 0x0"

  [<TestMethod>]
  member _.``MD00087 JAL``() =
    testDisasm "0c000000" "jal 0x0"

  [<TestMethod>]
  member _.``MD00087 JALR``() =
    testDisasm "00000809" "jalr at, r0"
    testDisasm "00001009" "jalr v0, r0"
    testDisasm "00001809" "jalr v1, r0"
    testDisasm "00002009" "jalr a0, r0"

  [<TestMethod>]
  member _.``MD00087 JALR.HB``() =
    testDisasm "00000409" "jalr.hb r0, r0"

  [<TestMethod>]
  member _.``MD00087 JALX``() =
    testDisasm "74000000" "jalx 0x0"

  [<TestMethod>]
  member _.``MD00087 JR``() =
    testDisasm "00000008" "jr r0"
    testDisasm "00200008" "jr at"
    testDisasm "00400008" "jr v0"
    testDisasm "00600008" "jr v1"

  [<TestMethod>]
  member _.``MD00087 JR.HB``() =
    testDisasm "00000408" "jr.hb r0"
    testDisasm "00000409" "jalr.hb r0, r0"

  [<TestMethod>]
  member _.``MD00087 LB``() =
    testDisasm "80000000" "lb r0, 0(r0)"
    testDisasm "80010000" "lb at, 0(r0)"
    testDisasm "80020000" "lb v0, 0(r0)"
    testDisasm "80030000" "lb v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LBE``() =
    testDisasm "7c00002c" "lbe r0, 0(r0)"
    testDisasm "7c01002c" "lbe at, 0(r0)"
    testDisasm "7c02002c" "lbe v0, 0(r0)"
    testDisasm "7c03002c" "lbe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LBU``() =
    testDisasm "90000000" "lbu r0, 0(r0)"
    testDisasm "90010000" "lbu at, 0(r0)"
    testDisasm "90020000" "lbu v0, 0(r0)"
    testDisasm "90030000" "lbu v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LBUE``() =
    testDisasm "7c000028" "lbue r0, 0(r0)"
    testDisasm "7c010028" "lbue at, 0(r0)"
    testDisasm "7c020028" "lbue v0, 0(r0)"
    testDisasm "7c030028" "lbue v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LD``() =
    testDisasm "dc000000" "ld r0, 0(r0)"
    testDisasm "dc010000" "ld at, 0(r0)"
    testDisasm "dc020000" "ld v0, 0(r0)"
    testDisasm "dc030000" "ld v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LDC1``() =
    testDisasm "d4000000" "ldc1 f0, 0(r0)"
    testDisasm "d4010000" "ldc1 f1, 0(r0)"
    testDisasm "d4020000" "ldc1 f2, 0(r0)"
    testDisasm "d4030000" "ldc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LDC2``() =
    testDisasm "d8000000" "ldc2 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LDL``() =
    testDisasm "68000000" "ldl r0, 0(r0)"
    testDisasm "68010000" "ldl at, 0(r0)"
    testDisasm "68020000" "ldl v0, 0(r0)"
    testDisasm "68030000" "ldl v1, 0(r0)"
