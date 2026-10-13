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
/// One test for each instruction MD00087 describes, LDR to SWXC1. Each reads
/// words of the instruction and checks the text, and each word is one binutils'
/// objdump reads as the same instruction with the same operands, so what is
/// asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualMIPSParserTests2() =
  let isa =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser = Parser(isa, BinReader.Init isa.Endian) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  [<TestMethod>]
  member _.``MD00087 LDR``() =
    testDisasm "6c000000" "ldr r0, 0(r0)"
    testDisasm "6c010000" "ldr at, 0(r0)"
    testDisasm "6c020000" "ldr v0, 0(r0)"
    testDisasm "6c030000" "ldr v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LDXC1``() =
    testDisasm "4c000001" "ldxc1 f0, r0(r0)"
    testDisasm "4c200001" "ldxc1 f0, r0(at)"
    testDisasm "4c010001" "ldxc1 f0, at(r0)"
    testDisasm "4c000041" "ldxc1 f1, r0(r0)"

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
    testDisasm "c0000000" "ll r0, 0(r0)"
    testDisasm "c0010000" "ll at, 0(r0)"
    testDisasm "c0020000" "ll v0, 0(r0)"
    testDisasm "c0030000" "ll v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LLD``() =
    testDisasm "d0000000" "lld r0, 0(r0)"
    testDisasm "d0010000" "lld at, 0(r0)"
    testDisasm "d0020000" "lld v0, 0(r0)"
    testDisasm "d0030000" "lld v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LLE``() =
    testDisasm "7c00002e" "lle r0, 0(r0)"
    testDisasm "7c01002e" "lle at, 0(r0)"
    testDisasm "7c02002e" "lle v0, 0(r0)"
    testDisasm "7c03002e" "lle v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LUI``() =
    testDisasm "3c000000" "lui r0, 0x0"
    testDisasm "3c010000" "lui at, 0x0"
    testDisasm "3c020000" "lui v0, 0x0"
    testDisasm "3c030000" "lui v1, 0x0"

  [<TestMethod>]
  member _.``MD00087 LUXC1``() =
    testDisasm "4c000005" "luxc1 f0, r0(r0)"
    testDisasm "4c200005" "luxc1 f0, r0(at)"
    testDisasm "4c010005" "luxc1 f0, at(r0)"
    testDisasm "4c000045" "luxc1 f1, r0(r0)"

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
    testDisasm "c8000000" "lwc2 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWE``() =
    testDisasm "7c00002f" "lwe r0, 0(r0)"
    testDisasm "7c01002f" "lwe at, 0(r0)"
    testDisasm "7c02002f" "lwe v0, 0(r0)"
    testDisasm "7c03002f" "lwe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWL``() =
    testDisasm "88000000" "lwl r0, 0(r0)"
    testDisasm "88010000" "lwl at, 0(r0)"
    testDisasm "88020000" "lwl v0, 0(r0)"
    testDisasm "88030000" "lwl v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWLE``() =
    testDisasm "7c000019" "lwle r0, 0(r0)"
    testDisasm "7c010019" "lwle at, 0(r0)"
    testDisasm "7c020019" "lwle v0, 0(r0)"
    testDisasm "7c030019" "lwle v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWR``() =
    testDisasm "98000000" "lwr r0, 0(r0)"
    testDisasm "98010000" "lwr at, 0(r0)"
    testDisasm "98020000" "lwr v0, 0(r0)"
    testDisasm "98030000" "lwr v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWRE``() =
    testDisasm "7c00001a" "lwre r0, 0(r0)"
    testDisasm "7c01001a" "lwre at, 0(r0)"
    testDisasm "7c02001a" "lwre v0, 0(r0)"
    testDisasm "7c03001a" "lwre v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWU``() =
    testDisasm "9c000000" "lwu r0, 0(r0)"
    testDisasm "9c010000" "lwu at, 0(r0)"
    testDisasm "9c020000" "lwu v0, 0(r0)"
    testDisasm "9c030000" "lwu v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 LWXC1``() =
    testDisasm "4c000000" "lwxc1 f0, r0(r0)"
    testDisasm "4c200000" "lwxc1 f0, r0(at)"
    testDisasm "4c010000" "lwxc1 f0, at(r0)"
    testDisasm "4c000040" "lwxc1 f1, r0(r0)"

  [<TestMethod>]
  member _.``MD00087 MADD``() =
    testDisasm "70000000" "madd r0, r0"
    testDisasm "70200000" "madd at, r0"
    testDisasm "70010000" "madd r0, at"
    testDisasm "70400000" "madd v0, r0"

  [<TestMethod>]
  member _.``MD00087 MADD.fmt``() =
    testDisasm "4c000020" "madd.s f0, f0, f0, f0"
    testDisasm "4c200020" "madd.s f0, f1, f0, f0"
    testDisasm "4c010020" "madd.s f0, f0, f0, f1"
    testDisasm "4c000820" "madd.s f0, f0, f1, f0"

  [<TestMethod>]
  member _.``MD00087 MADDU``() =
    testDisasm "70000001" "maddu r0, r0"
    testDisasm "70200001" "maddu at, r0"
    testDisasm "70010001" "maddu r0, at"
    testDisasm "70400001" "maddu v0, r0"

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
  member _.``MD00087 MFHI``() =
    testDisasm "00000010" "mfhi r0"
    testDisasm "00000810" "mfhi at"
    testDisasm "00001010" "mfhi v0"
    testDisasm "00001810" "mfhi v1"

  [<TestMethod>]
  member _.``MD00087 MFLO``() =
    testDisasm "00000012" "mflo r0"
    testDisasm "00000812" "mflo at"
    testDisasm "00001012" "mflo v0"
    testDisasm "00001812" "mflo v1"

  [<TestMethod>]
  member _.``MD00087 MOV.fmt``() =
    testDisasm "46000006" "mov.s f0, f0"
    testDisasm "46200006" "mov.d f0, f0"
    testDisasm "46c00006" "mov.ps f0, f0"
    testDisasm "46001806" "mov.s f0, f3"

  [<TestMethod>]
  member _.``MD00087 MOVF``() =
    testDisasm "00000001" "movf r0, r0, 0x0"
    testDisasm "00200001" "movf r0, at, 0x0"
    testDisasm "00000801" "movf at, r0, 0x0"
    testDisasm "00400001" "movf r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 MOVF.fmt``() =
    testDisasm "46000011" "movf.s f0, f0, 0x0"
    testDisasm "46200011" "movf.d f0, f0, 0x0"
    testDisasm "46c00011" "movf.ps f0, f0, 0x0"
    testDisasm "46001811" "movf.s f0, f3, 0x0"

  [<TestMethod>]
  member _.``MD00087 MOVN``() =
    testDisasm "0000000b" "movn r0, r0, r0"
    testDisasm "0020000b" "movn r0, at, r0"
    testDisasm "0001000b" "movn r0, r0, at"
    testDisasm "0000080b" "movn at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 MOVN.fmt``() =
    testDisasm "46000013" "movn.s f0, f0, r0"
    testDisasm "46200013" "movn.d f0, f0, r0"
    testDisasm "46c00013" "movn.ps f0, f0, r0"
    testDisasm "46021913" "movn.s f4, f3, v0"

  [<TestMethod>]
  member _.``MD00087 MOVT``() =
    testDisasm "00010001" "movt r0, r0, 0x0"
    testDisasm "00050001" "movt r0, r0, 0x1"
    testDisasm "00090001" "movt r0, r0, 0x2"
    testDisasm "000d0001" "movt r0, r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 MOVT.fmt``() =
    testDisasm "46011811" "movt.s f0, f3, 0x0"
    testDisasm "46051811" "movt.s f0, f3, 0x1"
    testDisasm "46091811" "movt.s f0, f3, 0x2"
    testDisasm "460d1811" "movt.s f0, f3, 0x3"

  [<TestMethod>]
  member _.``MD00087 MOVZ``() =
    testDisasm "0000000a" "movz r0, r0, r0"
    testDisasm "0020000a" "movz r0, at, r0"
    testDisasm "0001000a" "movz r0, r0, at"
    testDisasm "0000080a" "movz at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 MOVZ.fmt``() =
    testDisasm "46000012" "movz.s f0, f0, r0"
    testDisasm "46200012" "movz.d f0, f0, r0"
    testDisasm "46c00012" "movz.ps f0, f0, r0"
    testDisasm "46021912" "movz.s f4, f3, v0"

  [<TestMethod>]
  member _.``MD00087 MSUB``() =
    testDisasm "70000004" "msub r0, r0"
    testDisasm "70200004" "msub at, r0"
    testDisasm "70010004" "msub r0, at"
    testDisasm "70400004" "msub v0, r0"

  [<TestMethod>]
  member _.``MD00087 MSUB.fmt``() =
    testDisasm "4c000028" "msub.s f0, f0, f0, f0"
    testDisasm "4c200028" "msub.s f0, f1, f0, f0"
    testDisasm "4c010028" "msub.s f0, f0, f0, f1"
    testDisasm "4c000828" "msub.s f0, f0, f1, f0"

  [<TestMethod>]
  member _.``MD00087 MSUBU``() =
    testDisasm "70000005" "msubu r0, r0"
    testDisasm "70200005" "msubu at, r0"
    testDisasm "70010005" "msubu r0, at"
    testDisasm "70400005" "msubu v0, r0"

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
  member _.``MD00087 MTHI``() =
    testDisasm "00000011" "mthi r0"
    testDisasm "00200011" "mthi at"
    testDisasm "00400011" "mthi v0"
    testDisasm "00600011" "mthi v1"

  [<TestMethod>]
  member _.``MD00087 MTLO``() =
    testDisasm "00000013" "mtlo r0"
    testDisasm "00200013" "mtlo at"
    testDisasm "00400013" "mtlo v0"
    testDisasm "00600013" "mtlo v1"

  [<TestMethod>]
  member _.``MD00087 MUL``() =
    testDisasm "70000002" "mul r0, r0, r0"
    testDisasm "70200002" "mul r0, at, r0"
    testDisasm "70010002" "mul r0, r0, at"
    testDisasm "70000802" "mul at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 MUL.fmt``() =
    testDisasm "46000002" "mul.s f0, f0, f0"
    testDisasm "46200002" "mul.d f0, f0, f0"
    testDisasm "46c00002" "mul.ps f0, f0, f0"
    testDisasm "46021902" "mul.s f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 MULT``() =
    testDisasm "00000018" "mult r0, r0"
    testDisasm "00200018" "mult at, r0"
    testDisasm "00010018" "mult r0, at"
    testDisasm "00400018" "mult v0, r0"

  [<TestMethod>]
  member _.``MD00087 MULTU``() =
    testDisasm "00000019" "multu r0, r0"
    testDisasm "00200019" "multu at, r0"
    testDisasm "00010019" "multu r0, at"
    testDisasm "00400019" "multu v0, r0"

  [<TestMethod>]
  member _.``MD00087 NAL``() =
    testDisasm "04100000" "nal 0x4"
    testDisasm "04100001" "nal 0x8"
    testDisasm "04100002" "nal 0xc"
    testDisasm "04100003" "nal 0x10"

  [<TestMethod>]
  member _.``MD00087 NEG.fmt``() =
    testDisasm "46000007" "neg.s f0, f0"
    testDisasm "46200007" "neg.d f0, f0"
    testDisasm "46c00007" "neg.ps f0, f0"
    testDisasm "46001807" "neg.s f0, f3"

  [<TestMethod>]
  member _.``MD00087 NMADD.fmt``() =
    testDisasm "4c000030" "nmadd.s f0, f0, f0, f0"
    testDisasm "4c200030" "nmadd.s f0, f1, f0, f0"
    testDisasm "4c010030" "nmadd.s f0, f0, f0, f1"
    testDisasm "4c000830" "nmadd.s f0, f0, f1, f0"

  [<TestMethod>]
  member _.``MD00087 NMSUB.fmt``() =
    testDisasm "4c000038" "nmsub.s f0, f0, f0, f0"
    testDisasm "4c200038" "nmsub.s f0, f1, f0, f0"
    testDisasm "4c010038" "nmsub.s f0, f0, f0, f1"
    testDisasm "4c000838" "nmsub.s f0, f0, f1, f0"

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
  member _.``MD00087 PLL.PS``() =
    testDisasm "46c0002c" "pll.ps f0, f0, f0"
    testDisasm "46c2192c" "pll.ps f4, f3, f2"
    testDisasm "46deef2c" "pll.ps f28, f29, f30"
    testDisasm "46c0182c" "pll.ps f0, f3, f0"

  [<TestMethod>]
  member _.``MD00087 PLU.PS``() =
    testDisasm "46c0002d" "plu.ps f0, f0, f0"
    testDisasm "46c2192d" "plu.ps f4, f3, f2"
    testDisasm "46deef2d" "plu.ps f28, f29, f30"
    testDisasm "46c0182d" "plu.ps f0, f3, f0"

  [<TestMethod>]
  member _.``MD00087 PREF``() =
    testDisasm "cc000000" "pref 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 PREFE``() =
    testDisasm "7c000023" "prefe 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 PREFX``() =
    testDisasm "4c00000f" "prefx 0x0, r0(r0)"
    testDisasm "4c20000f" "prefx 0x0, r0(at)"
    testDisasm "4c40000f" "prefx 0x0, r0(v0)"
    testDisasm "4c60000f" "prefx 0x0, r0(v1)"

  [<TestMethod>]
  member _.``MD00087 PUL.PS``() =
    testDisasm "46c0002e" "pul.ps f0, f0, f0"
    testDisasm "46c2192e" "pul.ps f4, f3, f2"
    testDisasm "46deef2e" "pul.ps f28, f29, f30"
    testDisasm "46c0182e" "pul.ps f0, f3, f0"

  [<TestMethod>]
  member _.``MD00087 PUU.PS``() =
    testDisasm "46c0002f" "puu.ps f0, f0, f0"
    testDisasm "46c2192f" "puu.ps f4, f3, f2"
    testDisasm "46deef2f" "puu.ps f28, f29, f30"
    testDisasm "46c0182f" "puu.ps f0, f3, f0"

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
    testDisasm "e0000000" "sc r0, 0(r0)"
    testDisasm "e0010000" "sc at, 0(r0)"
    testDisasm "e0020000" "sc v0, 0(r0)"
    testDisasm "e0030000" "sc v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SCD``() =
    testDisasm "f0000000" "scd r0, 0(r0)"
    testDisasm "f0010000" "scd at, 0(r0)"
    testDisasm "f0020000" "scd v0, 0(r0)"
    testDisasm "f0030000" "scd v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SCE``() =
    testDisasm "7c00001e" "sce r0, 0(r0)"
    testDisasm "7c01001e" "sce at, 0(r0)"
    testDisasm "7c02001e" "sce v0, 0(r0)"
    testDisasm "7c03001e" "sce v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SD``() =
    testDisasm "fc000000" "sd r0, 0(r0)"
    testDisasm "fc010000" "sd at, 0(r0)"
    testDisasm "fc020000" "sd v0, 0(r0)"
    testDisasm "fc030000" "sd v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDBBP``() =
    testDisasm "7000003f" "sdbbp 0x0"

  [<TestMethod>]
  member _.``MD00087 SDC1``() =
    testDisasm "f4000000" "sdc1 f0, 0(r0)"
    testDisasm "f4010000" "sdc1 f1, 0(r0)"
    testDisasm "f4020000" "sdc1 f2, 0(r0)"
    testDisasm "f4030000" "sdc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDC2``() =
    testDisasm "f8000000" "sdc2 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDL``() =
    testDisasm "b0000000" "sdl r0, 0(r0)"
    testDisasm "b0010000" "sdl at, 0(r0)"
    testDisasm "b0020000" "sdl v0, 0(r0)"
    testDisasm "b0030000" "sdl v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDR``() =
    testDisasm "b4000000" "sdr r0, 0(r0)"
    testDisasm "b4010000" "sdr at, 0(r0)"
    testDisasm "b4020000" "sdr v0, 0(r0)"
    testDisasm "b4030000" "sdr v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SDXC1``() =
    testDisasm "4c000009" "sdxc1 f0, r0(r0)"
    testDisasm "4c200009" "sdxc1 f0, r0(at)"
    testDisasm "4c010009" "sdxc1 f0, at(r0)"
    testDisasm "4c000809" "sdxc1 f1, r0(r0)"

  [<TestMethod>]
  member _.``MD00087 SEB``() =
    testDisasm "7c000420" "seb r0, r0"

  [<TestMethod>]
  member _.``MD00087 SEH``() =
    testDisasm "7c000620" "seh r0, r0"

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

  [<TestMethod>]
  member _.``MD00087 SLT``() =
    testDisasm "0000002a" "slt r0, r0, r0"
    testDisasm "0020002a" "slt r0, at, r0"
    testDisasm "0001002a" "slt r0, r0, at"
    testDisasm "0000082a" "slt at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SLTI``() =
    testDisasm "28000000" "slti r0, r0, 0x0"
    testDisasm "28200000" "slti r0, at, 0x0"
    testDisasm "28010000" "slti at, r0, 0x0"
    testDisasm "28400000" "slti r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SLTIU``() =
    testDisasm "2c000000" "sltiu r0, r0, 0x0"
    testDisasm "2c200000" "sltiu r0, at, 0x0"
    testDisasm "2c010000" "sltiu at, r0, 0x0"
    testDisasm "2c400000" "sltiu r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SLTU``() =
    testDisasm "0000002b" "sltu r0, r0, r0"
    testDisasm "0020002b" "sltu r0, at, r0"
    testDisasm "0001002b" "sltu r0, r0, at"
    testDisasm "0000082b" "sltu at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SQRT.fmt``() =
    testDisasm "46000004" "sqrt.s f0, f0"
    testDisasm "46200004" "sqrt.d f0, f0"
    testDisasm "46001804" "sqrt.s f0, f3"
    testDisasm "46201804" "sqrt.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 SRA``() =
    testDisasm "00000003" "sra r0, r0, 0x0"
    testDisasm "00010003" "sra r0, at, 0x0"
    testDisasm "00000803" "sra at, r0, 0x0"
    testDisasm "00020003" "sra r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SRAV``() =
    testDisasm "00000007" "srav r0, r0, r0"
    testDisasm "00200007" "srav r0, r0, at"
    testDisasm "00010007" "srav r0, at, r0"
    testDisasm "00000807" "srav at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SRL``() =
    testDisasm "00000002" "srl r0, r0, 0x0"
    testDisasm "00010002" "srl r0, at, 0x0"
    testDisasm "00000802" "srl at, r0, 0x0"
    testDisasm "00020002" "srl r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SRLV``() =
    testDisasm "00000006" "srlv r0, r0, r0"
    testDisasm "00200006" "srlv r0, r0, at"
    testDisasm "00010006" "srlv r0, at, r0"
    testDisasm "00000806" "srlv at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SSNOP``() =
    testDisasm "00000040" "ssnop"

  [<TestMethod>]
  member _.``MD00087 SUB``() =
    testDisasm "00200022" "sub r0, at, r0"
    testDisasm "00400022" "sub r0, v0, r0"
    testDisasm "00600022" "sub r0, v1, r0"
    testDisasm "00800022" "sub r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 SUB.fmt``() =
    testDisasm "46000001" "sub.s f0, f0, f0"
    testDisasm "46200001" "sub.d f0, f0, f0"
    testDisasm "46c00001" "sub.ps f0, f0, f0"
    testDisasm "46021901" "sub.s f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 SUBU``() =
    testDisasm "00200023" "subu r0, at, r0"
    testDisasm "00400023" "subu r0, v0, r0"
    testDisasm "00600023" "subu r0, v1, r0"
    testDisasm "00800023" "subu r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 SUXC1``() =
    testDisasm "4c00000d" "suxc1 f0, r0(r0)"
    testDisasm "4c20000d" "suxc1 f0, r0(at)"
    testDisasm "4c01000d" "suxc1 f0, at(r0)"
    testDisasm "4c00080d" "suxc1 f1, r0(r0)"

  [<TestMethod>]
  member _.``MD00087 SW``() =
    testDisasm "ac000000" "sw r0, 0(r0)"
    testDisasm "ac010000" "sw at, 0(r0)"
    testDisasm "ac020000" "sw v0, 0(r0)"
    testDisasm "ac030000" "sw v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWC1``() =
    testDisasm "e4000000" "swc1 f0, 0(r0)"
    testDisasm "e4010000" "swc1 f1, 0(r0)"
    testDisasm "e4020000" "swc1 f2, 0(r0)"
    testDisasm "e4030000" "swc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWC2``() =
    testDisasm "e8000000" "swc2 0x0, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWE``() =
    testDisasm "7c00001f" "swe r0, 0(r0)"
    testDisasm "7c01001f" "swe at, 0(r0)"
    testDisasm "7c02001f" "swe v0, 0(r0)"
    testDisasm "7c03001f" "swe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWL``() =
    testDisasm "a8000000" "swl r0, 0(r0)"
    testDisasm "a8010000" "swl at, 0(r0)"
    testDisasm "a8020000" "swl v0, 0(r0)"
    testDisasm "a8030000" "swl v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWLE``() =
    testDisasm "7c000021" "swle r0, 0(r0)"
    testDisasm "7c010021" "swle at, 0(r0)"
    testDisasm "7c020021" "swle v0, 0(r0)"
    testDisasm "7c030021" "swle v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWR``() =
    testDisasm "b8000000" "swr r0, 0(r0)"
    testDisasm "b8010000" "swr at, 0(r0)"
    testDisasm "b8020000" "swr v0, 0(r0)"
    testDisasm "b8030000" "swr v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWRE``() =
    testDisasm "7c000022" "swre r0, 0(r0)"
    testDisasm "7c010022" "swre at, 0(r0)"
    testDisasm "7c020022" "swre v0, 0(r0)"
    testDisasm "7c030022" "swre v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWXC1``() =
    testDisasm "4c000008" "swxc1 f0, r0(r0)"
    testDisasm "4c200008" "swxc1 f0, r0(at)"
    testDisasm "4c010008" "swxc1 f0, at(r0)"
    testDisasm "4c000808" "swxc1 f1, r0(r0)"
