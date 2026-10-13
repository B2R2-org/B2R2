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
/// One test for each instruction microMIPS64 5.04 describes, JRC to SDP. Each
/// reads words of the instruction and checks the text, and each word is one
/// binutils' objdump reads as the same instruction with the same operands, so
/// what is asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualMicroMIPSParserTests2() =
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
  member _.``microMIPS64 5.04 JRC``() =
    testDisasm "45a00c00" "jrc r0"
    testDisasm "45a10c00" "jrc at"
    testDisasm "45a20c00" "jrc v0"
    testDisasm "45a30c00" "jrc v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LB``() =
    testDisasm "1c030000" "lb r0, 0(v1)"
    testDisasm "1c600000" "lb v1, 0(r0)"
    testDisasm "1c030001" "lb r0, 1(v1)"
    testDisasm "1c600001" "lb v1, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LBE``() =
    testDisasm "60006800" "lbe r0, 0(r0)"
    testDisasm "60006801" "lbe r0, 1(r0)"
    testDisasm "60006802" "lbe r0, 2(r0)"
    testDisasm "60006803" "lbe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LBU``() =
    testDisasm "08000c00" "lbu s0, 0(s0)"
    testDisasm "08010c00" "lbu s0, 1(s0)"
    testDisasm "08020c00" "lbu s0, 2(s0)"
    testDisasm "08030c00" "lbu s0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LBU16``() =
    testDisasm "08000c00" "lbu s0, 0(s0)"
    testDisasm "08010c00" "lbu s0, 1(s0)"
    testDisasm "08020c00" "lbu s0, 2(s0)"
    testDisasm "08030c00" "lbu s0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LBUE``() =
    testDisasm "60006000" "lbue r0, 0(r0)"
    testDisasm "60006001" "lbue r0, 1(r0)"
    testDisasm "60006002" "lbue r0, 2(r0)"
    testDisasm "60006003" "lbue r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LD``() =
    testDisasm "dc030000" "ld r0, 0(v1)"
    testDisasm "dc600000" "ld v1, 0(r0)"
    testDisasm "dc030001" "ld r0, 1(v1)"
    testDisasm "dc600001" "ld v1, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDC1``() =
    testDisasm "bc030000" "ldc1 f0, 0(v1)"
    testDisasm "bc600000" "ldc1 f3, 0(r0)"
    testDisasm "bc030001" "ldc1 f0, 1(v1)"
    testDisasm "bc600001" "ldc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDC2``() =
    testDisasm "20002000" "ldc2 0x0, 0(r0)"
    testDisasm "20002001" "ldc2 0x0, 1(r0)"
    testDisasm "20002002" "ldc2 0x0, 2(r0)"
    testDisasm "20002003" "ldc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDL``() =
    testDisasm "60004000" "ldl r0, 0(r0)"
    testDisasm "60004001" "ldl r0, 1(r0)"
    testDisasm "60004002" "ldl r0, 2(r0)"
    testDisasm "60004003" "ldl r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDM``() =
    testDisasm "20227000" "ldm s0, 0(v0)"
    testDisasm "20227001" "ldm s0, 1(v0)"
    testDisasm "20227002" "ldm s0, 2(v0)"
    testDisasm "20227003" "ldm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDP``() =
    testDisasm "20004000" "ldp r0, at, 0(r0)"
    testDisasm "20004001" "ldp r0, at, 1(r0)"
    testDisasm "20004002" "ldp r0, at, 2(r0)"
    testDisasm "20004003" "ldp r0, at, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDR``() =
    testDisasm "60005000" "ldr r0, 0(r0)"
    testDisasm "60005001" "ldr r0, 1(r0)"
    testDisasm "60005002" "ldr r0, 2(r0)"
    testDisasm "60005003" "ldr r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LDXC1``() =
    testDisasm "540000c8" "ldxc1 f0, r0(r0)"
    testDisasm "540008c8" "ldxc1 f1, r0(r0)"
    testDisasm "540010c8" "ldxc1 f2, r0(r0)"
    testDisasm "540018c8" "ldxc1 f3, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LH``() =
    testDisasm "3c030000" "lh r0, 0(v1)"
    testDisasm "3c600000" "lh v1, 0(r0)"
    testDisasm "3c030001" "lh r0, 1(v1)"
    testDisasm "3c600001" "lh v1, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LHE``() =
    testDisasm "60006a00" "lhe r0, 0(r0)"
    testDisasm "60006a01" "lhe r0, 1(r0)"
    testDisasm "60006a02" "lhe r0, 2(r0)"
    testDisasm "60006a03" "lhe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LHU``() =
    testDisasm "28000c00" "lhu s0, 0(s0)"
    testDisasm "28010c00" "lhu s0, 2(s0)"
    testDisasm "28020c00" "lhu s0, 4(s0)"
    testDisasm "28030c00" "lhu s0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LHU16``() =
    testDisasm "28000c00" "lhu s0, 0(s0)"
    testDisasm "28010c00" "lhu s0, 2(s0)"
    testDisasm "28020c00" "lhu s0, 4(s0)"
    testDisasm "28030c00" "lhu s0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LHUE``() =
    testDisasm "60006200" "lhue r0, 0(r0)"
    testDisasm "60006201" "lhue r0, 1(r0)"
    testDisasm "60006202" "lhue r0, 2(r0)"
    testDisasm "60006203" "lhue r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LI16``() =
    testDisasm "4c000c00" "addiu r0, r0, 0x0"
    testDisasm "4c010c00" "addiu sp, sp, 0x400"
    testDisasm "4c020c00" "addiu r0, r0, 0x1"
    testDisasm "4c030c00" "addiu sp, sp, 0x404"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LL``() =
    testDisasm "60003000" "ll r0, 0(r0)"
    testDisasm "60003001" "ll r0, 1(r0)"
    testDisasm "60003002" "ll r0, 2(r0)"
    testDisasm "60003003" "ll r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LLD``() =
    testDisasm "60007000" "lld r0, 0(r0)"
    testDisasm "60007001" "lld r0, 1(r0)"
    testDisasm "60007002" "lld r0, 2(r0)"
    testDisasm "60007003" "lld r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LLE``() =
    testDisasm "60006c00" "lle r0, 0(r0)"
    testDisasm "60006c01" "lle r0, 1(r0)"
    testDisasm "60006c02" "lle r0, 2(r0)"
    testDisasm "60006c03" "lle r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LUI``() =
    testDisasm "41a30000" "lui v1, 0x0"
    testDisasm "41a30001" "lui v1, 0x1"
    testDisasm "41a37fff" "lui v1, 0x7fff"
    testDisasm "41a38000" "lui v1, 0x8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LUXC1``() =
    testDisasm "54000148" "luxc1 f0, r0(r0)"
    testDisasm "54000948" "luxc1 f1, r0(r0)"
    testDisasm "54001148" "luxc1 f2, r0(r0)"
    testDisasm "54001948" "luxc1 f3, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LW``() =
    testDisasm "48000c00" "lw r0, 0(sp)"
    testDisasm "48010c00" "lw r0, 4(sp)"
    testDisasm "48020c00" "lw r0, 8(sp)"
    testDisasm "48030c00" "lw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LW16``() =
    testDisasm "48000c00" "lw r0, 0(sp)"
    testDisasm "48010c00" "lw r0, 4(sp)"
    testDisasm "48020c00" "lw r0, 8(sp)"
    testDisasm "48030c00" "lw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWC1``() =
    testDisasm "9c030000" "lwc1 f0, 0(v1)"
    testDisasm "9c600000" "lwc1 f3, 0(r0)"
    testDisasm "9c030001" "lwc1 f0, 1(v1)"
    testDisasm "9c600001" "lwc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWC2``() =
    testDisasm "20000000" "lwc2 0x0, 0(r0)"
    testDisasm "20000001" "lwc2 0x0, 1(r0)"
    testDisasm "20000002" "lwc2 0x0, 2(r0)"
    testDisasm "20000003" "lwc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWE``() =
    testDisasm "60006e00" "lwe r0, 0(r0)"
    testDisasm "60006e01" "lwe r0, 1(r0)"
    testDisasm "60006e02" "lwe r0, 2(r0)"
    testDisasm "60006e03" "lwe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWGP``() =
    testDisasm "48000c00" "lw r0, 0(sp)"
    testDisasm "48010c00" "lw r0, 4(sp)"
    testDisasm "48020c00" "lw r0, 8(sp)"
    testDisasm "48030c00" "lw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWL``() =
    testDisasm "60000000" "lwl r0, 0(r0)"
    testDisasm "60000001" "lwl r0, 1(r0)"
    testDisasm "60000002" "lwl r0, 2(r0)"
    testDisasm "60000003" "lwl r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWLE``() =
    testDisasm "60006400" "lwle r0, 0(r0)"
    testDisasm "60006401" "lwle r0, 1(r0)"
    testDisasm "60006402" "lwle r0, 2(r0)"
    testDisasm "60006403" "lwle r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWM16``() =
    testDisasm "45300c00" "lwm s0, s1, s2, s3, ra, 0(sp)"
    testDisasm "45000c00" "lwm s0, ra, 0(sp)"
    testDisasm "45010c00" "lwm s0, ra, 4(sp)"
    testDisasm "45020c00" "lwm s0, ra, 8(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWM32``() =
    testDisasm "20225000" "lwm s0, 0(v0)"
    testDisasm "20225001" "lwm s0, 1(v0)"
    testDisasm "20225002" "lwm s0, 2(v0)"
    testDisasm "20225003" "lwm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWP``() =
    testDisasm "20001000" "lwp r0, at, 0(r0)"
    testDisasm "20001001" "lwp r0, at, 1(r0)"
    testDisasm "20001002" "lwp r0, at, 2(r0)"
    testDisasm "20001003" "lwp r0, at, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWR``() =
    testDisasm "60001000" "lwr r0, 0(r0)"
    testDisasm "60001001" "lwr r0, 1(r0)"
    testDisasm "60001002" "lwr r0, 2(r0)"
    testDisasm "60001003" "lwr r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWRE``() =
    testDisasm "60006600" "lwre r0, 0(r0)"
    testDisasm "60006601" "lwre r0, 1(r0)"
    testDisasm "60006602" "lwre r0, 2(r0)"
    testDisasm "60006603" "lwre r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWSP``() =
    testDisasm "48000c00" "lw r0, 0(sp)"
    testDisasm "48010c00" "lw r0, 4(sp)"
    testDisasm "48020c00" "lw r0, 8(sp)"
    testDisasm "48030c00" "lw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWU``() =
    testDisasm "6000e000" "lwu r0, 0(r0)"
    testDisasm "6000e001" "lwu r0, 1(r0)"
    testDisasm "6000e002" "lwu r0, 2(r0)"
    testDisasm "6000e003" "lwu r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWXC1``() =
    testDisasm "54000048" "lwxc1 f0, r0(r0)"
    testDisasm "54000848" "lwxc1 f1, r0(r0)"
    testDisasm "54001048" "lwxc1 f2, r0(r0)"
    testDisasm "54001848" "lwxc1 f3, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 LWXS``() =
    testDisasm "00000118" "lwxs r0, r0(r0)"
    testDisasm "00000918" "lwxs at, r0(r0)"
    testDisasm "00001118" "lwxs v0, r0(r0)"
    testDisasm "00001918" "lwxs v1, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MADD``() =
    testDisasm "0000cb3c" "madd r0, r0"
    testDisasm "0022cb3c" "madd v0, at"
    testDisasm "03fecb3c" "madd s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MADD.fmt``() =
    testDisasm "54000001" "madd.s f0, f0, f0, f0"
    testDisasm "54000009" "madd.d f0, f0, f0, f0"
    testDisasm "54000011" "madd.ps f0, f0, f0, f0"
    testDisasm "54000041" "madd.s f0, f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MADDU``() =
    testDisasm "0000db3c" "maddu r0, r0"
    testDisasm "0022db3c" "maddu v0, at"
    testDisasm "03fedb3c" "maddu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFC0``() =
    testDisasm "000000fc" "mfc0 r0, 0x0, 0x0"
    testDisasm "000008fc" "mfc0 r0, 0x0, 0x1"
    testDisasm "000010fc" "mfc0 r0, 0x0, 0x2"
    testDisasm "000018fc" "mfc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFC1``() =
    testDisasm "5400203b" "mfc1 r0, f0"
    testDisasm "5422203b" "mfc1 at, f2"
    testDisasm "57fe203b" "mfc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFC2``() =
    testDisasm "00004d3c" "mfc2 r0, 0x0"
    testDisasm "00224d3c" "mfc2 at, 0x2"
    testDisasm "03fe4d3c" "mfc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHC0``() =
    testDisasm "000000f4" "mfhc0 r0, 0x0, 0x0"
    testDisasm "000008f4" "mfhc0 r0, 0x0, 0x1"
    testDisasm "000010f4" "mfhc0 r0, 0x0, 0x2"
    testDisasm "000018f4" "mfhc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHC1``() =
    testDisasm "5400303b" "mfhc1 r0, f0"
    testDisasm "5422303b" "mfhc1 at, f2"
    testDisasm "57fe303b" "mfhc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHC2``() =
    testDisasm "00008d3c" "mfhc2 r0, 0x0"
    testDisasm "00228d3c" "mfhc2 at, 0x2"
    testDisasm "03fe8d3c" "mfhc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHI``() =
    testDisasm "46000c00" "mfhi r0"
    testDisasm "46010c00" "mfhi at"
    testDisasm "46020c00" "mfhi v0"
    testDisasm "46030c00" "mfhi v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHI16``() =
    testDisasm "46000c00" "mfhi r0"
    testDisasm "46010c00" "mfhi at"
    testDisasm "46020c00" "mfhi v0"
    testDisasm "46030c00" "mfhi v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFLO``() =
    testDisasm "46400c00" "mflo r0"
    testDisasm "46410c00" "mflo at"
    testDisasm "46420c00" "mflo v0"
    testDisasm "46430c00" "mflo v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MFLO16``() =
    testDisasm "46400c00" "mflo r0"
    testDisasm "46410c00" "mflo at"
    testDisasm "46420c00" "mflo v0"
    testDisasm "46430c00" "mflo v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOV.fmt``() =
    testDisasm "5400007b" "mov.s f0, f0"
    testDisasm "5400207b" "mov.d f0, f0"
    testDisasm "5400407b" "mov.ps f0, f0"
    testDisasm "5422007b" "mov.s f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVE16``() =
    testDisasm "04000c00" "addu s0, s0, s0"
    testDisasm "04020c00" "addu s0, s1, s0"
    testDisasm "04040c00" "addu s0, v0, s0"
    testDisasm "04060c00" "addu s0, v1, s0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVEP``() =
    testDisasm "84000c00" "movep a1, a2, r0, r0"
    testDisasm "84020c00" "movep a1, a2, s1, r0"
    testDisasm "84040c00" "movep a1, a2, v0, r0"
    testDisasm "84060c00" "movep a1, a2, v1, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVF``() =
    testDisasm "5400017b" "movf r0, r0, 0x0"
    testDisasm "5400217b" "movf r0, r0, 0x1"
    testDisasm "5400417b" "movf r0, r0, 0x2"
    testDisasm "5400617b" "movf r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVF.fmt``() =
    testDisasm "54000020" "movf.s f0, f0, 0x0"
    testDisasm "54000220" "movf.d f0, f0, 0x0"
    testDisasm "54000420" "movf.ps f0, f0, 0x0"
    testDisasm "54220020" "movf.s f1, f2, 0x0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVN``() =
    testDisasm "00000018" "movn r0, r0, r0"
    testDisasm "00000818" "movn at, r0, r0"
    testDisasm "00001018" "movn v0, r0, r0"
    testDisasm "00001818" "movn v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVN.fmt``() =
    testDisasm "54000038" "movn.s f0, f0, r0"
    testDisasm "54000138" "movn.d f0, f0, r0"
    testDisasm "54000238" "movn.ps f0, f0, r0"
    testDisasm "54000838" "movn.s f1, f0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVT``() =
    testDisasm "5400097b" "movt r0, r0, 0x0"
    testDisasm "5400297b" "movt r0, r0, 0x1"
    testDisasm "5400497b" "movt r0, r0, 0x2"
    testDisasm "5400697b" "movt r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVT.fmt``() =
    testDisasm "54000060" "movt.s f0, f0, 0x0"
    testDisasm "54000260" "movt.d f0, f0, 0x0"
    testDisasm "54000460" "movt.ps f0, f0, 0x0"
    testDisasm "54220060" "movt.s f1, f2, 0x0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVZ``() =
    testDisasm "00000058" "movz r0, r0, r0"
    testDisasm "00000858" "movz at, r0, r0"
    testDisasm "00001058" "movz v0, r0, r0"
    testDisasm "00001858" "movz v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVZ.fmt``() =
    testDisasm "54000078" "movz.s f0, f0, r0"
    testDisasm "54000178" "movz.d f0, f0, r0"
    testDisasm "54000278" "movz.ps f0, f0, r0"
    testDisasm "54000878" "movz.s f1, f0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MSUB``() =
    testDisasm "0000eb3c" "msub r0, r0"
    testDisasm "0022eb3c" "msub v0, at"
    testDisasm "03feeb3c" "msub s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MSUB.fmt``() =
    testDisasm "54000021" "msub.s f0, f0, f0, f0"
    testDisasm "54000029" "msub.d f0, f0, f0, f0"
    testDisasm "54000031" "msub.ps f0, f0, f0, f0"
    testDisasm "54000061" "msub.s f0, f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MSUBU``() =
    testDisasm "0000fb3c" "msubu r0, r0"
    testDisasm "0022fb3c" "msubu v0, at"
    testDisasm "03fefb3c" "msubu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTC0``() =
    testDisasm "000002fc" "mtc0 r0, 0x0, 0x0"
    testDisasm "00000afc" "mtc0 r0, 0x0, 0x1"
    testDisasm "000012fc" "mtc0 r0, 0x0, 0x2"
    testDisasm "00001afc" "mtc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTC1``() =
    testDisasm "5400283b" "mtc1 r0, f0"
    testDisasm "5422283b" "mtc1 at, f2"
    testDisasm "57fe283b" "mtc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTC2``() =
    testDisasm "00005d3c" "mtc2 r0, 0x0"
    testDisasm "00225d3c" "mtc2 at, 0x2"
    testDisasm "03fe5d3c" "mtc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHC0``() =
    testDisasm "000002f4" "mthc0 r0, 0x0, 0x0"
    testDisasm "00000af4" "mthc0 r0, 0x0, 0x1"
    testDisasm "000012f4" "mthc0 r0, 0x0, 0x2"
    testDisasm "00001af4" "mthc0 r0, 0x0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHC1``() =
    testDisasm "5400383b" "mthc1 r0, f0"
    testDisasm "5422383b" "mthc1 at, f2"
    testDisasm "57fe383b" "mthc1 ra, f30"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHC2``() =
    testDisasm "00009d3c" "mthc2 r0, 0x0"
    testDisasm "00229d3c" "mthc2 at, 0x2"
    testDisasm "03fe9d3c" "mthc2 ra, 0x1e"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHI``() =
    testDisasm "00002d7c" "mthi r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MTLO``() =
    testDisasm "00003d7c" "mtlo r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MUL``() =
    testDisasm "00000210" "mul r0, r0, r0"
    testDisasm "00000a10" "mul at, r0, r0"
    testDisasm "00001210" "mul v0, r0, r0"
    testDisasm "00001a10" "mul v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MUL.fmt``() =
    testDisasm "540000b0" "mul.s f0, f0, f0"
    testDisasm "540001b0" "mul.d f0, f0, f0"
    testDisasm "540002b0" "mul.ps f0, f0, f0"
    testDisasm "540008b0" "mul.s f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MULT``() =
    testDisasm "00008b3c" "mult r0, r0"
    testDisasm "00228b3c" "mult v0, at"
    testDisasm "03fe8b3c" "mult s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 MULTU``() =
    testDisasm "00009b3c" "multu r0, r0"
    testDisasm "00229b3c" "multu v0, at"
    testDisasm "03fe9b3c" "multu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 NEG.fmt``() =
    testDisasm "54000b7b" "neg.s f0, f0"
    testDisasm "54002b7b" "neg.d f0, f0"
    testDisasm "54004b7b" "neg.ps f0, f0"
    testDisasm "54220b7b" "neg.s f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 NMADD.fmt``() =
    testDisasm "54000002" "nmadd.s f0, f0, f0, f0"
    testDisasm "5400000a" "nmadd.d f0, f0, f0, f0"
    testDisasm "54000012" "nmadd.ps f0, f0, f0, f0"
    testDisasm "54000042" "nmadd.s f0, f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 NMSUB.fmt``() =
    testDisasm "54000022" "nmsub.s f0, f0, f0, f0"
    testDisasm "5400002a" "nmsub.d f0, f0, f0, f0"
    testDisasm "54000032" "nmsub.ps f0, f0, f0, f0"
    testDisasm "54000062" "nmsub.s f0, f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 NOP``() =
    testDisasm "00000000" "nop"

  [<TestMethod>]
  member _.``microMIPS64 5.04 NOR``() =
    testDisasm "44130c00" "nor v0, v1, r0"
    testDisasm "44000c00" "nor s0, s0, r0"
    testDisasm "44010c00" "nor s0, s1, r0"
    testDisasm "44020c00" "nor s0, v0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 NOT16``() =
    testDisasm "44130c00" "nor v0, v1, r0"
    testDisasm "44000c00" "nor s0, s0, r0"
    testDisasm "44010c00" "nor s0, s1, r0"
    testDisasm "44020c00" "nor s0, v0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 OR``() =
    testDisasm "0c010c00" "or r0, at, r0"
    testDisasm "0c020c00" "or r0, v0, r0"
    testDisasm "0c030c00" "or r0, v1, r0"
    testDisasm "0c040c00" "or r0, a0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 OR16``() =
    testDisasm "0c010c00" "or r0, at, r0"
    testDisasm "0c020c00" "or r0, v0, r0"
    testDisasm "0c030c00" "or r0, v1, r0"
    testDisasm "0c040c00" "or r0, a0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ORI``() =
    testDisasm "50030000" "ori r0, v1, 0x0"
    testDisasm "50030001" "ori r0, v1, 0x1"
    testDisasm "50037fff" "ori r0, v1, 0x7fff"
    testDisasm "50038000" "ori r0, v1, 0x8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PAUSE``() =
    testDisasm "00002800" "pause"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PLL.PS``() =
    testDisasm "54000080" "pll.ps f0, f0, f0"
    testDisasm "54000880" "pll.ps f1, f0, f0"
    testDisasm "54001080" "pll.ps f2, f0, f0"
    testDisasm "54001880" "pll.ps f3, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PLU.PS``() =
    testDisasm "540000c0" "plu.ps f0, f0, f0"
    testDisasm "540008c0" "plu.ps f1, f0, f0"
    testDisasm "540010c0" "plu.ps f2, f0, f0"
    testDisasm "540018c0" "plu.ps f3, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PREF``() =
    testDisasm "60002000" "pref 0x0, 0(r0)"
    testDisasm "60002001" "pref 0x0, 1(r0)"
    testDisasm "60002002" "pref 0x0, 2(r0)"
    testDisasm "60002003" "pref 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PREFE``() =
    testDisasm "6000a400" "prefe 0x0, 0(r0)"
    testDisasm "6000a401" "prefe 0x0, 1(r0)"
    testDisasm "6000a402" "prefe 0x0, 2(r0)"
    testDisasm "6000a403" "prefe 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PREFX``() =
    testDisasm "540001a0" "prefx 0x0, r0(r0)"
    testDisasm "542201a0" "prefx 0x0, at(v0)"
    testDisasm "57fe01a0" "prefx 0x0, ra(s8)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PUL.PS``() =
    testDisasm "54000100" "pul.ps f0, f0, f0"
    testDisasm "54000900" "pul.ps f1, f0, f0"
    testDisasm "54001100" "pul.ps f2, f0, f0"
    testDisasm "54001900" "pul.ps f3, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 PUU.PS``() =
    testDisasm "54000140" "puu.ps f0, f0, f0"
    testDisasm "54000940" "puu.ps f1, f0, f0"
    testDisasm "54001140" "puu.ps f2, f0, f0"
    testDisasm "54001940" "puu.ps f3, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 RDHWR``() =
    testDisasm "00006b3c" "rdhwr r0, r0"
    testDisasm "00226b3c" "rdhwr at, v0"
    testDisasm "03fe6b3c" "rdhwr ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 RDPGPR``() =
    testDisasm "0000e17c" "rdpgpr r0, r0"
    testDisasm "0022e17c" "rdpgpr at, v0"
    testDisasm "03fee17c" "rdpgpr ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 RECIP.fmt``() =
    testDisasm "5400123b" "recip.s f0, f0"
    testDisasm "5400523b" "recip.d f0, f0"
    testDisasm "5422123b" "recip.s f1, f2"
    testDisasm "5422523b" "recip.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ROTR``() =
    testDisasm "000000c0" "rotr r0, r0, 0x0"
    testDisasm "000008c0" "rotr r0, r0, 0x1"
    testDisasm "000010c0" "rotr r0, r0, 0x2"
    testDisasm "000018c0" "rotr r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ROTRV``() =
    testDisasm "000000d0" "rotrv r0, r0, r0"
    testDisasm "000008d0" "rotrv at, r0, r0"
    testDisasm "000010d0" "rotrv v0, r0, r0"
    testDisasm "000018d0" "rotrv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ROUND.L.fmt``() =
    testDisasm "5400333b" "round.l.s f0, f0"
    testDisasm "5400733b" "round.l.d f0, f0"
    testDisasm "5422333b" "round.l.s f1, f2"
    testDisasm "5422733b" "round.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 ROUND.W.fmt``() =
    testDisasm "54003b3b" "round.w.s f0, f0"
    testDisasm "54007b3b" "round.w.d f0, f0"
    testDisasm "54223b3b" "round.w.s f1, f2"
    testDisasm "54227b3b" "round.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 RSQRT.fmt``() =
    testDisasm "5400023b" "rsqrt.s f0, f0"
    testDisasm "5400423b" "rsqrt.d f0, f0"
    testDisasm "5422023b" "rsqrt.s f1, f2"
    testDisasm "5422423b" "rsqrt.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SB``() =
    testDisasm "88000c00" "sb r0, 0(s0)"
    testDisasm "88010c00" "sb r0, 1(s0)"
    testDisasm "88020c00" "sb r0, 2(s0)"
    testDisasm "88030c00" "sb r0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SB16``() =
    testDisasm "88000c00" "sb r0, 0(s0)"
    testDisasm "88010c00" "sb r0, 1(s0)"
    testDisasm "88020c00" "sb r0, 2(s0)"
    testDisasm "88030c00" "sb r0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SBE``() =
    testDisasm "6000a800" "sbe r0, 0(r0)"
    testDisasm "6000a801" "sbe r0, 1(r0)"
    testDisasm "6000a802" "sbe r0, 2(r0)"
    testDisasm "6000a803" "sbe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SC``() =
    testDisasm "6000b000" "sc r0, 0(r0)"
    testDisasm "6000b001" "sc r0, 1(r0)"
    testDisasm "6000b002" "sc r0, 2(r0)"
    testDisasm "6000b003" "sc r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SCD``() =
    testDisasm "6000f000" "scd r0, 0(r0)"
    testDisasm "6000f001" "scd r0, 1(r0)"
    testDisasm "6000f002" "scd r0, 2(r0)"
    testDisasm "6000f003" "scd r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SCE``() =
    testDisasm "6000ac00" "sce r0, 0(r0)"
    testDisasm "6000ac01" "sce r0, 1(r0)"
    testDisasm "6000ac02" "sce r0, 2(r0)"
    testDisasm "6000ac03" "sce r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SD``() =
    testDisasm "d8030000" "sd r0, 0(v1)"
    testDisasm "d8600000" "sd v1, 0(r0)"
    testDisasm "d8030001" "sd r0, 1(v1)"
    testDisasm "d8600001" "sd v1, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDBBP``() =
    testDisasm "46c00c00" "sdbbp 0x0"
    testDisasm "46c10c00" "sdbbp 0x1"
    testDisasm "46c20c00" "sdbbp 0x2"
    testDisasm "46c30c00" "sdbbp 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDBBP16``() =
    testDisasm "46c00c00" "sdbbp 0x0"
    testDisasm "46c10c00" "sdbbp 0x1"
    testDisasm "46c20c00" "sdbbp 0x2"
    testDisasm "46c30c00" "sdbbp 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDC1``() =
    testDisasm "b8030000" "sdc1 f0, 0(v1)"
    testDisasm "b8600000" "sdc1 f3, 0(r0)"
    testDisasm "b8030001" "sdc1 f0, 1(v1)"
    testDisasm "b8600001" "sdc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDC2``() =
    testDisasm "2000a000" "sdc2 0x0, 0(r0)"
    testDisasm "2000a001" "sdc2 0x0, 1(r0)"
    testDisasm "2000a002" "sdc2 0x0, 2(r0)"
    testDisasm "2000a003" "sdc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDL``() =
    testDisasm "6000c000" "sdl r0, 0(r0)"
    testDisasm "6000c001" "sdl r0, 1(r0)"
    testDisasm "6000c002" "sdl r0, 2(r0)"
    testDisasm "6000c003" "sdl r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDM``() =
    testDisasm "2022f000" "sdm s0, 0(v0)"
    testDisasm "2022f001" "sdm s0, 1(v0)"
    testDisasm "2022f002" "sdm s0, 2(v0)"
    testDisasm "2022f003" "sdm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDP``() =
    testDisasm "2000c000" "sdp r0, at, 0(r0)"
    testDisasm "2000c001" "sdp r0, at, 1(r0)"
    testDisasm "2000c002" "sdp r0, at, 2(r0)"
    testDisasm "2000c003" "sdp r0, at, 3(r0)"
