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
/// One test for each instruction MD00087 describes, DSRL to SLLV. Each reads
/// words of the instruction and checks the text, and each word is one binutils'
/// objdump reads as the same instruction with the same operands, so what is
/// asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualMIPSR6ParserTests2() =
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
  member _.``MD00087 DVP``() =
    testDisasm "41600024" "dvp r0"

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
  member _.``MD00087 ERETNC``() =
    testDisasm "42000058" "eretnc"

  [<TestMethod>]
  member _.``MD00087 EVP``() =
    testDisasm "41600004" "evp r0"

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
  member _.``MD00087 GINVI``() =
    testDisasm "7c00003d" "ginvi r0"
    testDisasm "7c20003d" "ginvi at"
    testDisasm "7c40003d" "ginvi v0"
    testDisasm "7c60003d" "ginvi v1"

  [<TestMethod>]
  member _.``MD00087 GINVT``() =
    testDisasm "7c0000bd" "ginvt r0, 0x0"
    testDisasm "7c0001bd" "ginvt r0, 0x1"
    testDisasm "7c0002bd" "ginvt r0, 0x2"
    testDisasm "7c0003bd" "ginvt r0, 0x3"

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
  member _.``MD00087 JIALC``() =
    testDisasm "f8010001" "jialc at, 0x1"
    testDisasm "f8020001" "jialc v0, 0x1"
    testDisasm "f8030001" "jialc v1, 0x1"
    testDisasm "f8040001" "jialc a0, 0x1"

  [<TestMethod>]
  member _.``MD00087 JIC``() =
    testDisasm "d8010001" "jic at, 0x1"
    testDisasm "d8020001" "jic v0, 0x1"
    testDisasm "d8030001" "jic v1, 0x1"
    testDisasm "d8040001" "jic a0, 0x1"

  [<TestMethod>]
  member _.``MD00087 JR``() =
    testDisasm "00200009" "jr at"
    testDisasm "00400009" "jr v0"
    testDisasm "00600009" "jr v1"
    testDisasm "00800009" "jr a0"

  [<TestMethod>]
  member _.``MD00087 JR.HB``() =
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
    testDisasm "49c00000" "ldc2 0x0, 0(r0)"
    testDisasm "49c00001" "ldc2 0x0, 1(r0)"
    testDisasm "49c00002" "ldc2 0x0, 2(r0)"
    testDisasm "49c00003" "ldc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``MD00087 LDPC``() =
    testDisasm "ec391900" "ldpc at, 0x8c800"
    testDisasm "ec3b1900" "ldpc at, 0xfffffffffff8c800"
    testDisasm "eff8ef00" "ldpc ra, 0x77800"
    testDisasm "eff9ef00" "ldpc ra, 0xf7800"

  [<TestMethod>]
  member _.``MD00087 LH``() =
    testDisasm "84000000" "lh r0, 0(r0)"
    testDisasm "84010000" "lh at, 0(r0)"
    testDisasm "84020000" "lh v0, 0(r0)"
    testDisasm "84030000" "lh v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LHE``() =
    testDisasm "7c00002d" "lhe r0, 0(r0)"
    testDisasm "7c01002d" "lhe at, 0(r0)"
    testDisasm "7c02002d" "lhe v0, 0(r0)"
    testDisasm "7c03002d" "lhe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LHU``() =
    testDisasm "94000000" "lhu r0, 0(r0)"
    testDisasm "94010000" "lhu at, 0(r0)"
    testDisasm "94020000" "lhu v0, 0(r0)"
    testDisasm "94030000" "lhu v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LHUE``() =
    testDisasm "7c000029" "lhue r0, 0(r0)"
    testDisasm "7c010029" "lhue at, 0(r0)"
    testDisasm "7c020029" "lhue v0, 0(r0)"
    testDisasm "7c030029" "lhue v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LL``() =
    testDisasm "7c000036" "ll r0, 0(r0)"
    testDisasm "7c010036" "ll at, 0(r0)"
    testDisasm "7c020036" "ll v0, 0(r0)"
    testDisasm "7c030036" "ll v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LLD``() =
    testDisasm "7c000037" "lld r0, 0(r0)"
    testDisasm "7c010037" "lld at, 0(r0)"
    testDisasm "7c020037" "lld v0, 0(r0)"
    testDisasm "7c030037" "lld v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LLDP``() =
    testDisasm "7c000077" "lldp r0, r0, 0(r0)"
    testDisasm "7c221877" "lldp v0, v1, 0(at)"
    testDisasm "7ffee877" "lldp s8, sp, 0(ra)"

  [<TestMethod>]
  member _.``MD00087 LLE``() =
    testDisasm "7c00002e" "lle r0, 0(r0)"
    testDisasm "7c01002e" "lle at, 0(r0)"
    testDisasm "7c02002e" "lle v0, 0(r0)"
    testDisasm "7c03002e" "lle v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LLWP``() =
    testDisasm "7c000076" "llwp r0, r0, 0(r0)"
    testDisasm "7c221876" "llwp v0, v1, 0(at)"
    testDisasm "7ffee876" "llwp s8, sp, 0(ra)"

  [<TestMethod>]
  member _.``MD00087 LLWPE``() =
    testDisasm "7c00006e" "llwpe r0, r0, 0(r0)"
    testDisasm "7c22186e" "llwpe v0, v1, 0(at)"
    testDisasm "7ffee86e" "llwpe s8, sp, 0(ra)"

  [<TestMethod>]
  member _.``MD00087 LSA``() =
    testDisasm "00000005" "lsa r0, r0, r0, 0x0"
    testDisasm "00200005" "lsa r0, at, r0, 0x0"
    testDisasm "00010005" "lsa r0, r0, at, 0x0"
    testDisasm "00000805" "lsa at, r0, r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 LUI``() =
    testDisasm "3c000000" "lui r0, 0x0"
    testDisasm "3c010000" "lui at, 0x0"
    testDisasm "3c020000" "lui v0, 0x0"
    testDisasm "3c030000" "lui v1, 0x0"

  [<TestMethod>]
  member _.``MD00087 LW``() =
    testDisasm "8c000000" "lw r0, 0(r0)"
    testDisasm "8c010000" "lw at, 0(r0)"
    testDisasm "8c020000" "lw v0, 0(r0)"
    testDisasm "8c030000" "lw v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWC1``() =
    testDisasm "c4000000" "lwc1 f0, 0(r0)"
    testDisasm "c4010000" "lwc1 f1, 0(r0)"
    testDisasm "c4020000" "lwc1 f2, 0(r0)"
    testDisasm "c4030000" "lwc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWC2``() =
    testDisasm "49400000" "lwc2 0x0, 0(r0)"
    testDisasm "49400001" "lwc2 0x0, 1(r0)"
    testDisasm "49400002" "lwc2 0x0, 2(r0)"
    testDisasm "49400003" "lwc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``MD00087 LWE``() =
    testDisasm "7c00002f" "lwe r0, 0(r0)"
    testDisasm "7c01002f" "lwe at, 0(r0)"
    testDisasm "7c02002f" "lwe v0, 0(r0)"
    testDisasm "7c03002f" "lwe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWPC``() =
    testDisasm "ec080000" "lwpc r0, 0x0"
    testDisasm "ec090000" "lwpc r0, 0x40000"
    testDisasm "ec0a0000" "lwpc r0, 0x80000"
    testDisasm "ec0b0000" "lwpc r0, 0xc0000"

  [<TestMethod>]
  member _.``MD00087 LWU``() =
    testDisasm "9c000000" "lwu r0, 0(r0)"
    testDisasm "9c010000" "lwu at, 0(r0)"
    testDisasm "9c020000" "lwu v0, 0(r0)"
    testDisasm "9c030000" "lwu v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWUPC``() =
    testDisasm "ec100000" "lwupc r0, 0x0"
    testDisasm "ec110000" "lwupc r0, 0x40000"
    testDisasm "ec120000" "lwupc r0, 0x80000"
    testDisasm "ec130000" "lwupc r0, 0xc0000"

  [<TestMethod>]
  member _.``MD00087 MADDF.fmt``() =
    testDisasm "46000018" "maddf.s f0, f0, f0"
    testDisasm "46200018" "maddf.d f0, f0, f0"
    testDisasm "46021918" "maddf.s f4, f3, f2"
    testDisasm "46221918" "maddf.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MAX.fmt``() =
    testDisasm "4600001e" "max.s f0, f0, f0"
    testDisasm "4620001e" "max.d f0, f0, f0"
    testDisasm "4602191e" "max.s f4, f3, f2"
    testDisasm "4622191e" "max.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MAXA.fmt``() =
    testDisasm "4600001f" "maxa.s f0, f0, f0"
    testDisasm "4620001f" "maxa.d f0, f0, f0"
    testDisasm "4602191f" "maxa.s f4, f3, f2"
    testDisasm "4622191f" "maxa.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MFC0``() =
    testDisasm "40000000" "mfc0 r0, 0x0, 0x0"
    testDisasm "40010000" "mfc0 at, 0x0, 0x0"
    testDisasm "40020000" "mfc0 v0, 0x0, 0x0"
    testDisasm "40030000" "mfc0 v1, 0x0, 0x0"

  [<TestMethod>]
  member _.``MD00087 MFC1``() =
    testDisasm "44000000" "mfc1 r0, f0"
    testDisasm "44010000" "mfc1 at, f0"
    testDisasm "44000800" "mfc1 r0, f1"
    testDisasm "44020000" "mfc1 v0, f0"

  [<TestMethod>]
  member _.``MD00087 MFC2``() =
    testDisasm "48000000" "mfc2 r0, 0x0"
    testDisasm "48010000" "mfc2 at, 0x0"
    testDisasm "48020000" "mfc2 v0, 0x0"
    testDisasm "48030000" "mfc2 v1, 0x0"

  [<TestMethod>]
  member _.``MD00087 MFHC0``() =
    testDisasm "40400000" "mfhc0 r0, 0x0, 0x0"
    testDisasm "40400001" "mfhc0 r0, 0x0, 0x1"
    testDisasm "40400002" "mfhc0 r0, 0x0, 0x2"
    testDisasm "40400003" "mfhc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``MD00087 MFHC1``() =
    testDisasm "44600000" "mfhc1 r0, f0"
    testDisasm "44601800" "mfhc1 r0, f3"
    testDisasm "44611800" "mfhc1 at, f3"
    testDisasm "44621800" "mfhc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 MFHC2``() =
    testDisasm "48600000" "mfhc2 r0, 0x0"
    testDisasm "48621900" "mfhc2 v0, 0x1900"
    testDisasm "48621901" "mfhc2 v0, 0x1901"
    testDisasm "48621902" "mfhc2 v0, 0x1902"

  [<TestMethod>]
  member _.``MD00087 MIN.fmt``() =
    testDisasm "4600001c" "min.s f0, f0, f0"
    testDisasm "4620001c" "min.d f0, f0, f0"
    testDisasm "4602191c" "min.s f4, f3, f2"
    testDisasm "4622191c" "min.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MINA.fmt``() =
    testDisasm "4600001d" "mina.s f0, f0, f0"
    testDisasm "4620001d" "mina.d f0, f0, f0"
    testDisasm "4602191d" "mina.s f4, f3, f2"
    testDisasm "4622191d" "mina.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MOD``() =
    testDisasm "000000da" "mod r0, r0, r0"
    testDisasm "002218da" "mod v1, at, v0"
    testDisasm "03fee8da" "mod sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 MODU``() =
    testDisasm "000000db" "modu r0, r0, r0"
    testDisasm "002218db" "modu v1, at, v0"
    testDisasm "03fee8db" "modu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 MOV.fmt``() =
    testDisasm "46000006" "mov.s f0, f0"
    testDisasm "46200006" "mov.d f0, f0"
    testDisasm "46001806" "mov.s f0, f3"
    testDisasm "46201806" "mov.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 MSUBF.fmt``() =
    testDisasm "46000019" "msubf.s f0, f0, f0"
    testDisasm "46200019" "msubf.d f0, f0, f0"
    testDisasm "46021919" "msubf.s f4, f3, f2"
    testDisasm "46221919" "msubf.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MTC0``() =
    testDisasm "40800000" "mtc0 r0, 0x0, 0x0"
    testDisasm "40800001" "mtc0 r0, 0x0, 0x1"
    testDisasm "40800002" "mtc0 r0, 0x0, 0x2"
    testDisasm "40800003" "mtc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``MD00087 MTC1``() =
    testDisasm "44800000" "mtc1 r0, f0"
    testDisasm "44801800" "mtc1 r0, f3"
    testDisasm "44811800" "mtc1 at, f3"
    testDisasm "44821800" "mtc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 MTC2``() =
    testDisasm "48800000" "mtc2 r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 MTHC0``() =
    testDisasm "40c00000" "mthc0 r0, 0x0, 0x0"
    testDisasm "40c00001" "mthc0 r0, 0x0, 0x1"
    testDisasm "40c00002" "mthc0 r0, 0x0, 0x2"
    testDisasm "40c00003" "mthc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``MD00087 MTHC1``() =
    testDisasm "44e00000" "mthc1 r0, f0"
    testDisasm "44e01800" "mthc1 r0, f3"
    testDisasm "44e11800" "mthc1 at, f3"
    testDisasm "44e21800" "mthc1 v0, f3"

  [<TestMethod>]
  member _.``MD00087 MTHC2``() =
    testDisasm "48e00000" "mthc2 r0, 0x0"
    testDisasm "48e21900" "mthc2 v0, 0x1900"
    testDisasm "48e21901" "mthc2 v0, 0x1901"
    testDisasm "48e21902" "mthc2 v0, 0x1902"

  [<TestMethod>]
  member _.``MD00087 MUH``() =
    testDisasm "000000d8" "muh r0, r0, r0"
    testDisasm "002218d8" "muh v1, at, v0"
    testDisasm "03fee8d8" "muh sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 MUHU``() =
    testDisasm "000000d9" "muhu r0, r0, r0"
    testDisasm "002218d9" "muhu v1, at, v0"
    testDisasm "03fee8d9" "muhu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 MUL``() =
    testDisasm "00000098" "mul r0, r0, r0"
    testDisasm "00221898" "mul v1, at, v0"
    testDisasm "03fee898" "mul sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 MUL.fmt``() =
    testDisasm "46000002" "mul.s f0, f0, f0"
    testDisasm "46200002" "mul.d f0, f0, f0"
    testDisasm "46021902" "mul.s f4, f3, f2"
    testDisasm "46221902" "mul.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MULU``() =
    testDisasm "00000099" "mulu r0, r0, r0"
    testDisasm "00221899" "mulu v1, at, v0"
    testDisasm "03fee899" "mulu sp, ra, s8"

  [<TestMethod>]
  member _.``MD00087 NAL``() =
    testDisasm "04100000" "nal 0x4"

  [<TestMethod>]
  member _.``MD00087 NEG.fmt``() =
    testDisasm "46000007" "neg.s f0, f0"
    testDisasm "46200007" "neg.d f0, f0"
    testDisasm "46001807" "neg.s f0, f3"
    testDisasm "46201807" "neg.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 NOP``() =
    testDisasm "00000000" "nop"

  [<TestMethod>]
  member _.``MD00087 NOR``() =
    testDisasm "00000027" "nor r0, r0, r0"
    testDisasm "00200027" "nor r0, at, r0"
    testDisasm "00010027" "nor r0, r0, at"
    testDisasm "00000827" "nor at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 OR``() =
    testDisasm "00000025" "or r0, r0, r0"
    testDisasm "00200025" "or r0, at, r0"
    testDisasm "00010025" "or r0, r0, at"
    testDisasm "00000825" "or at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 ORI``() =
    testDisasm "34200000" "ori r0, at, 0x0"
    testDisasm "34400000" "ori r0, v0, 0x0"
    testDisasm "34600000" "ori r0, v1, 0x0"
    testDisasm "34800000" "ori r0, a0, 0x0"

  [<TestMethod>]
  member _.``MD00087 PAUSE``() =
    testDisasm "00000140" "pause"

  [<TestMethod>]
  member _.``MD00087 PREF``() =
    testDisasm "7c000035" "pref 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 PREFE``() =
    testDisasm "7c000023" "prefe 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 RDHWR``() =
    testDisasm "7c02193b" "rdhwr v0, v1, 0x4"

  [<TestMethod>]
  member _.``MD00087 RDPGPR``() =
    testDisasm "41400000" "rdpgpr r0, r0"

  [<TestMethod>]
  member _.``MD00087 RECIP.fmt``() =
    testDisasm "46000015" "recip.s f0, f0"
    testDisasm "46200015" "recip.d f0, f0"
    testDisasm "46001815" "recip.s f0, f3"
    testDisasm "46201815" "recip.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 RINT.fmt``() =
    testDisasm "4600001a" "rint.s f0, f0"
    testDisasm "4620001a" "rint.d f0, f0"
    testDisasm "4600181a" "rint.s f0, f3"
    testDisasm "4620181a" "rint.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 ROTR``() =
    testDisasm "00200002" "rotr r0, r0, 0x0"
    testDisasm "00201902" "rotr v1, r0, 0x4"
    testDisasm "00220102" "rotr r0, v0, 0x4"
    testDisasm "00221802" "rotr v1, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 ROTRV``() =
    testDisasm "00000046" "rotrv r0, r0, r0"
    testDisasm "00221846" "rotrv v1, v0, at"
    testDisasm "03fee846" "rotrv sp, s8, ra"

  [<TestMethod>]
  member _.``MD00087 ROUND.L.fmt``() =
    testDisasm "46000008" "round.l.s f0, f0"
    testDisasm "46200008" "round.l.d f0, f0"
    testDisasm "46001808" "round.l.s f0, f3"
    testDisasm "46201808" "round.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 ROUND.W.fmt``() =
    testDisasm "4600000c" "round.w.s f0, f0"
    testDisasm "4620000c" "round.w.d f0, f0"
    testDisasm "4600180c" "round.w.s f0, f3"
    testDisasm "4620180c" "round.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 RSQRT.fmt``() =
    testDisasm "46000016" "rsqrt.s f0, f0"
    testDisasm "46200016" "rsqrt.d f0, f0"
    testDisasm "46001816" "rsqrt.s f0, f3"
    testDisasm "46201816" "rsqrt.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 SB``() =
    testDisasm "a0000000" "sb r0, 0(r0)"
    testDisasm "a0010000" "sb at, 0(r0)"
    testDisasm "a0020000" "sb v0, 0(r0)"
    testDisasm "a0030000" "sb v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SBE``() =
    testDisasm "7c00001c" "sbe r0, 0(r0)"
    testDisasm "7c01001c" "sbe at, 0(r0)"
    testDisasm "7c02001c" "sbe v0, 0(r0)"
    testDisasm "7c03001c" "sbe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SC``() =
    testDisasm "7c000026" "sc r0, 0(r0)"
    testDisasm "7c010026" "sc at, 0(r0)"
    testDisasm "7c020026" "sc v0, 0(r0)"
    testDisasm "7c030026" "sc v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SCD``() =
    testDisasm "7c000027" "scd r0, 0(r0)"
    testDisasm "7c010027" "scd at, 0(r0)"
    testDisasm "7c020027" "scd v0, 0(r0)"
    testDisasm "7c030027" "scd v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SCDP``() =
    testDisasm "7c000067" "scdp r0, r0, 0(r0)"
    testDisasm "7c221867" "scdp v0, v1, 0(at)"
    testDisasm "7ffee867" "scdp s8, sp, 0(ra)"

  [<TestMethod>]
  member _.``MD00087 SCE``() =
    testDisasm "7c00001e" "sce r0, 0(r0)"
    testDisasm "7c01001e" "sce at, 0(r0)"
    testDisasm "7c02001e" "sce v0, 0(r0)"
    testDisasm "7c03001e" "sce v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SCWP``() =
    testDisasm "7c000066" "scwp r0, r0, 0(r0)"
    testDisasm "7c221866" "scwp v0, v1, 0(at)"
    testDisasm "7ffee866" "scwp s8, sp, 0(ra)"

  [<TestMethod>]
  member _.``MD00087 SCWPE``() =
    testDisasm "7c00005e" "scwpe r0, r0, 0(r0)"
    testDisasm "7c22185e" "scwpe v0, v1, 0(at)"
    testDisasm "7ffee85e" "scwpe s8, sp, 0(ra)"

  [<TestMethod>]
  member _.``MD00087 SD``() =
    testDisasm "fc000000" "sd r0, 0(r0)"
    testDisasm "fc010000" "sd at, 0(r0)"
    testDisasm "fc020000" "sd v0, 0(r0)"
    testDisasm "fc030000" "sd v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDBBP``() =
    testDisasm "0000000e" "sdbbp 0x0"

  [<TestMethod>]
  member _.``MD00087 SDC1``() =
    testDisasm "f4000000" "sdc1 f0, 0(r0)"
    testDisasm "f4010000" "sdc1 f1, 0(r0)"
    testDisasm "f4020000" "sdc1 f2, 0(r0)"
    testDisasm "f4030000" "sdc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDC2``() =
    testDisasm "49e00000" "sdc2 0x0, 0(r0)"
    testDisasm "49e00001" "sdc2 0x0, 1(r0)"
    testDisasm "49e00002" "sdc2 0x0, 2(r0)"
    testDisasm "49e00003" "sdc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``MD00087 SEB``() =
    testDisasm "7c000420" "seb r0, r0"

  [<TestMethod>]
  member _.``MD00087 SEH``() =
    testDisasm "7c000620" "seh r0, r0"

  [<TestMethod>]
  member _.``MD00087 SEL.fmt``() =
    testDisasm "46000010" "sel.s f0, f0, f0"
    testDisasm "46200010" "sel.d f0, f0, f0"
    testDisasm "46021910" "sel.s f4, f3, f2"
    testDisasm "46221910" "sel.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 SELEQZ``() =
    testDisasm "00000035" "seleqz r0, r0, r0"
    testDisasm "00200035" "seleqz r0, at, r0"
    testDisasm "00010035" "seleqz r0, r0, at"
    testDisasm "00000835" "seleqz at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SELEQZ.fmt``() =
    testDisasm "46000014" "seleqz.s f0, f0, f0"
    testDisasm "46200014" "seleqz.d f0, f0, f0"
    testDisasm "46021914" "seleqz.s f4, f3, f2"
    testDisasm "46221914" "seleqz.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 SELNEQZ.fmt``() =
    testDisasm "46000017" "selneqz.s f0, f0, f0"
    testDisasm "46200017" "selneqz.d f0, f0, f0"
    testDisasm "46021917" "selneqz.s f4, f3, f2"
    testDisasm "46221917" "selneqz.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 SELNEZ``() =
    testDisasm "00000037" "selnez r0, r0, r0"
    testDisasm "00200037" "selnez r0, at, r0"
    testDisasm "00010037" "selnez r0, r0, at"
    testDisasm "00000837" "selnez at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SH``() =
    testDisasm "a4000000" "sh r0, 0(r0)"
    testDisasm "a4010000" "sh at, 0(r0)"
    testDisasm "a4020000" "sh v0, 0(r0)"
    testDisasm "a4030000" "sh v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SHE``() =
    testDisasm "7c00001d" "she r0, 0(r0)"
    testDisasm "7c01001d" "she at, 0(r0)"
    testDisasm "7c02001d" "she v0, 0(r0)"
    testDisasm "7c03001d" "she v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SIGRIE``() =
    testDisasm "04170000" "sigrie 0x0"
    testDisasm "04170001" "sigrie 0x1"
    testDisasm "04170002" "sigrie 0x2"
    testDisasm "04170003" "sigrie 0x3"

  [<TestMethod>]
  member _.``MD00087 SLL``() =
    testDisasm "00010000" "sll r0, at, 0x0"
    testDisasm "00000800" "sll at, r0, 0x0"
    testDisasm "00020000" "sll r0, v0, 0x0"
    testDisasm "00001000" "sll v0, r0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SLLV``() =
    testDisasm "00000004" "sllv r0, r0, r0"
    testDisasm "00200004" "sllv r0, r0, at"
    testDisasm "00010004" "sllv r0, at, r0"
    testDisasm "00000804" "sllv at, r0, r0"
