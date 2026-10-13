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

namespace B2R2.FrontEnd.ARM32.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM32

/// <summary>
/// One test for each T32 instruction DDI0406C and DDI0487F.c's AArch32
/// chapters describe, ADC to TBB in the order of their sections. Each
/// reads T32 words of the instruction and checks the text, and each word's
/// text is one binutils' objdump reads the word as too, so what is asserted
/// is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualT32ParserTests1() =
  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let isa = ISA(Architecture.ARMv7, Endian.Big)
    let parser = Parser(isa, true, BinReader.Init Endian.Big)
    let ins = (parser :> IInstructionParsable).Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// A8.8.1 ADC (immediate)
  [<TestMethod>]
  member _.``A8.8.1 ADC``() =
    testDisasm "eb400002" "adc r0, r0, r2"
    testDisasm "eb510002" "adcs.w r0, r1, r2"
    testDisasm "eb410042" "adc r0, r1, r2, lsl #0x1"
    testDisasm "eb4100d2" "adc r0, r1, r2, lsr #0x3"

  /// A8.8.100 MCRR, MCRR2
  [<TestMethod>]
  member _.``A8.8.100 MCRR``() =
    testDisasm "ec410e34" "mcrr p14, #0x3, r0, r1, c4"
    testDisasm "ec419e34" "mcrr p14, #0x3, sb, r1, c4"
    testDisasm "ec41ae34" "mcrr p14, #0x3, sl, r1, c4"
    testDisasm "ec41be34" "mcrr p14, #0x3, fp, r1, c4"

  /// A8.8.101 MLA
  [<TestMethod>]
  member _.``A8.8.101 MLA``() =
    testDisasm "fb013002" "mla r0, r1, r2, r3"
    testDisasm "fb010900" "mla sb, r1, r0, r0"
    testDisasm "fb010a00" "mla sl, r1, r0, r0"
    testDisasm "fb010b00" "mla fp, r1, r0, r0"

  /// A8.8.102 MLS
  [<TestMethod>]
  member _.``A8.8.102 MLS``() =
    testDisasm "fb013012" "mls r0, r1, r2, r3"
    testDisasm "fb010910" "mls sb, r1, r0, r0"
    testDisasm "fb010a10" "mls sl, r1, r0, r0"
    testDisasm "fb010b10" "mls fp, r1, r0, r0"

  /// A8.8.103 MOV (immediate)
  [<TestMethod>]
  member _.``A8.8.103 MOV``() =
    testDisasm "f04f0003" "mov r0, #0x3"
    testDisasm "f05f407f" "movs r0, #0xff000000"
    testDisasm "4610bf00" "mov r0, r2"
    testDisasm "0010bf00" "movs r0, r2"

  /// A8.8.107 MOVT
  [<TestMethod>]
  member _.``A8.8.107 MOVT``() =
    testDisasm "f2c00007" "movt r0, #0x7"
    testDisasm "f2c10934" "movt sb, #0x1034"
    testDisasm "f2c10a34" "movt sl, #0x1034"
    testDisasm "f2c10b34" "movt fp, #0x1034"

  /// A8.8.108 MRC, MRC2
  [<TestMethod>]
  member _.``A8.8.108 MRC``() =
    testDisasm "ee110e34" "mrc p14, #0x0, r0, c1, c4, #0x1"
    testDisasm "ee119e34" "mrc p14, #0x0, sb, c1, c4, #0x1"
    testDisasm "ee11ae34" "mrc p14, #0x0, sl, c1, c4, #0x1"
    testDisasm "ee11be34" "mrc p14, #0x0, fp, c1, c4, #0x1"

  /// A8.8.109 MRRC, MRRC2
  [<TestMethod>]
  member _.``A8.8.109 MRRC``() =
    testDisasm "ec510e34" "mrrc p14, #0x3, r0, r1, c4"
    testDisasm "ec519e34" "mrrc p14, #0x3, sb, r1, c4"
    testDisasm "ec51ae34" "mrrc p14, #0x3, sl, r1, c4"
    testDisasm "ec51be34" "mrrc p14, #0x3, fp, r1, c4"

  /// A8.8.110 MRS
  [<TestMethod>]
  member _.``A8.8.110 MRS``() =
    testDisasm "f3e18034" "mrs r0, sp_irq"
    testDisasm "f3e1806f" "mrs r0, r9_usr"
    testDisasm "f3e18934" "mrs sb, sp_irq"
    testDisasm "f3e1896f" "mrs sb, r9_usr"

  /// A8.8.112 MSR (immediate)
  [<TestMethod>]
  member _.``A8.8.112 MSR``() =
    testDisasm "f3818034" "msr lr_irq, r1"
    testDisasm "f381806f" "msr r8_usr, r1"
    testDisasm "f3818134" "msr sp_irq, r1"
    testDisasm "f3818100" "msr cpsr_c, r1"

  /// A8.8.115 MUL
  [<TestMethod>]
  member _.``A8.8.115 MUL``() =
    testDisasm "fb01f002" "mul r0, r1, r2"
    testDisasm "4340bf00" "muls r0, r0, r0"
    testDisasm "fb01f900" "mul sb, r1, r0"
    testDisasm "fb01fa00" "mul sl, r1, r0"

  /// A8.8.116 MVN (immediate)
  [<TestMethod>]
  member _.``A8.8.116 MVN``() =
    testDisasm "f06f407f" "mvn r0, #0xff000000"
    testDisasm "f07f407f" "mvns r0, #0xff000000"
    testDisasm "ea6f0002" "mvn r0, r2"
    testDisasm "43d0bf00" "mvns r0, r2"

  /// A8.8.119 NEG
  [<TestMethod>]
  member _.``A8.8.119 NEG``() =
    testDisasm "f1c20000" "rsb r0, r2, #0x0"
    testDisasm "f1d10000" "rsbs r0, r1, #0x0"

  /// A8.8.12 ADR
  [<TestMethod>]
  member _.``A8.8.12 ADR``() =
    testDisasm "f20f0002" "adr.w r0, [0x6]"
    testDisasm "a000bf00" "adr r0, [0x4]"
    testDisasm "f20f0934" "adr.w sb, [0x38]"
    testDisasm "f2af0934" "adr sb, [0xffffffd0]"

  /// A8.8.120 NOP
  [<TestMethod>]
  member _.``A8.8.120 NOP``() =
    testDisasm "bf00bf00" "nop"
    testDisasm "f3af8000" "nop.w"

  /// A8.8.121 ORN (immediate)
  [<TestMethod>]
  member _.``A8.8.121 ORN``() =
    testDisasm "f0610001" "orn r0, r1, #0x1"
    testDisasm "f071407f" "orns r0, r1, #0xff000000"
    testDisasm "ea610002" "orn r0, r1, r2"
    testDisasm "ea710002" "orns r0, r1, r2"

  /// A8.8.123 ORR (immediate)
  [<TestMethod>]
  member _.``A8.8.123 ORR``() =
    testDisasm "f041407f" "orr r0, r1, #0xff000000"
    testDisasm "f051407f" "orrs r0, r1, #0xff000000"
    testDisasm "ea400002" "orr r0, r0, r2"
    testDisasm "ea510002" "orrs.w r0, r1, r2"

  /// A8.8.126 PKH
  [<TestMethod>]
  member _.``A8.8.126 PKH``() =
    testDisasm "eac11002" "pkhbt r0, r1, r2, lsl #0x4"
    testDisasm "eac11022" "pkhtb r0, r1, r2, asr #0x4"
    testDisasm "eac10000" "pkhbt r0, r1, r0"
    testDisasm "eac10900" "pkhbt sb, r1, r0"

  /// A8.8.127 PLD, PLDW (immediate)
  [<TestMethod>]
  member _.``A8.8.127 PLD``() =
    testDisasm "f891f007" "pld [r1, #0x7]"
    testDisasm "f89ff002" "pld [0x6]"
    testDisasm "f811f002" "pld [r1, r2]"
    testDisasm "f891f000" "pld [r1]"

  /// A8.8.127 PLD, PLDW (immediate)
  [<TestMethod>]
  member _.``A8.8.127 PLDW``() =
    testDisasm "f8b1f007" "pldw [r1, #0x7]"
    testDisasm "f831f002" "pldw [r1, r2]"
    testDisasm "f8b1f000" "pldw [r1]"
    testDisasm "f831f034" "pldw [r1, r4, lsl #0x3]"

  /// A8.8.13 AND (immediate)
  [<TestMethod>]
  member _.``A8.8.13 AND``() =
    testDisasm "f011407f" "ands r0, r1, #0xff000000"
    testDisasm "f001417f" "and r1, r1, #0xff000000"
    testDisasm "ea000002" "and r0, r0, r2"
    testDisasm "ea110002" "ands.w r0, r1, r2"

  /// A8.8.130 PLI (immediate, literal)
  [<TestMethod>]
  member _.``A8.8.130 PLI``() =
    testDisasm "f991f007" "pli [r1, #0x7]"
    testDisasm "f99ff002" "pli [pc, #0x2]"
    testDisasm "f99ff000" "pli [pc]"
    testDisasm "f911f002" "pli [r1, r2]"

  /// A8.8.132 POP (Thumb)
  [<TestMethod>]
  member _.``A8.8.132 POP``() =
    testDisasm "bc0cbf00" "pop {r2, r3}"
    testDisasm "bc01bf00" "pop {r0}"
    testDisasm "bc07bf00" "pop {r0, r1, r2}"
    testDisasm "bc0fbf00" "pop {r0, r1, r2, r3}"

  /// A8.8.134 PUSH
  [<TestMethod>]
  member _.``A8.8.134 PUSH``() =
    testDisasm "b40cbf00" "push {r2, r3}"
    testDisasm "b401bf00" "push {r0}"
    testDisasm "b407bf00" "push {r0, r1, r2}"
    testDisasm "b40fbf00" "push {r0, r1, r2, r3}"

  /// A8.8.135 QADD
  [<TestMethod>]
  member _.``A8.8.135 QADD``() =
    testDisasm "fa82f081" "qadd r0, r1, r2"

  /// A8.8.136 QADD16
  [<TestMethod>]
  member _.``A8.8.136 QADD16``() =
    testDisasm "fa91f012" "qadd16 r0, r1, r2"
    testDisasm "fa91f910" "qadd16 sb, r1, r0"
    testDisasm "fa91fa10" "qadd16 sl, r1, r0"
    testDisasm "fa91fb10" "qadd16 fp, r1, r0"

  /// A8.8.137 QADD8
  [<TestMethod>]
  member _.``A8.8.137 QADD8``() =
    testDisasm "fa81f012" "qadd8 r0, r1, r2"
    testDisasm "fa81f910" "qadd8 sb, r1, r0"
    testDisasm "fa81fa10" "qadd8 sl, r1, r0"
    testDisasm "fa81fb10" "qadd8 fp, r1, r0"

  /// A8.8.138 QASX
  [<TestMethod>]
  member _.``A8.8.138 QASX``() =
    testDisasm "faa1f012" "qasx r0, r1, r2"
    testDisasm "faa1f910" "qasx sb, r1, r0"
    testDisasm "faa1fa10" "qasx sl, r1, r0"
    testDisasm "faa1fb10" "qasx fp, r1, r0"

  /// A8.8.139 QDADD
  [<TestMethod>]
  member _.``A8.8.139 QDADD``() =
    testDisasm "fa82f091" "qdadd r0, r1, r2"

  /// A8.8.140 QDSUB
  [<TestMethod>]
  member _.``A8.8.140 QDSUB``() =
    testDisasm "fa82f0b1" "qdsub r0, r1, r2"

  /// A8.8.141 QSAX
  [<TestMethod>]
  member _.``A8.8.141 QSAX``() =
    testDisasm "fae1f012" "qsax r0, r1, r2"
    testDisasm "fae1f910" "qsax sb, r1, r0"
    testDisasm "fae1fa10" "qsax sl, r1, r0"
    testDisasm "fae1fb10" "qsax fp, r1, r0"

  /// A8.8.142 QSUB
  [<TestMethod>]
  member _.``A8.8.142 QSUB``() =
    testDisasm "fa82f0a1" "qsub r0, r1, r2"

  /// A8.8.143 QSUB16
  [<TestMethod>]
  member _.``A8.8.143 QSUB16``() =
    testDisasm "fad1f012" "qsub16 r0, r1, r2"
    testDisasm "fad1f910" "qsub16 sb, r1, r0"
    testDisasm "fad1fa10" "qsub16 sl, r1, r0"
    testDisasm "fad1fb10" "qsub16 fp, r1, r0"

  /// A8.8.144 QSUB8
  [<TestMethod>]
  member _.``A8.8.144 QSUB8``() =
    testDisasm "fac1f012" "qsub8 r0, r1, r2"
    testDisasm "fac1f910" "qsub8 sb, r1, r0"
    testDisasm "fac1fa10" "qsub8 sl, r1, r0"
    testDisasm "fac1fb10" "qsub8 fp, r1, r0"

  /// A8.8.145 RBIT
  [<TestMethod>]
  member _.``A8.8.145 RBIT``() =
    testDisasm "fa91f0a1" "rbit r0, r1"

  /// A8.8.146 REV
  [<TestMethod>]
  member _.``A8.8.146 REV``() =
    testDisasm "ba08bf00" "rev r0, r1"
    testDisasm "fa92f082" "rev.w r0, r2"

  /// A8.8.147 REV16
  [<TestMethod>]
  member _.``A8.8.147 REV16``() =
    testDisasm "ba48bf00" "rev16 r0, r1"
    testDisasm "fa92f092" "rev16.w r0, r2"

  /// A8.8.148 REVSH
  [<TestMethod>]
  member _.``A8.8.148 REVSH``() =
    testDisasm "bac8bf00" "revsh r0, r1"
    testDisasm "fa92f0b2" "revsh.w r0, r2"

  /// A8.8.149 RFE
  [<TestMethod>]
  member _.``A8.8.149 RFE``() =
    testDisasm "e991c000" "rfeia r1"
    testDisasm "e831c000" "rfedb r1!"

  /// A8.8.150 ROR (immediate)
  [<TestMethod>]
  member _.``A8.8.150 ROR``() =
    testDisasm "fa60f002" "ror r0, r0, r2"
    testDisasm "fa71f002" "rors.w r0, r1, r2"
    testDisasm "41d1bf00" "rors r1, r2"
    testDisasm "fa61f900" "ror sb, r1, r0"

  /// A8.8.152 RRX
  [<TestMethod>]
  member _.``A8.8.152 RRX``() =
    testDisasm "ea5f0032" "rrxs r0, r2"
    testDisasm "ea4f0032" "rrx r0, r2"
    testDisasm "ea4f0034" "rrx r0, r4"
    testDisasm "ea4f0031" "rrx r0, r1"

  /// A8.8.153 RSB (immediate)
  [<TestMethod>]
  member _.``A8.8.153 RSB``() =
    testDisasm "f1c1407f" "rsb r0, r1, #0xff000000"
    testDisasm "f1d1407f" "rsbs r0, r1, #0xff000000"
    testDisasm "ebc10002" "rsb r0, r1, r2"
    testDisasm "ebd10002" "rsbs r0, r1, r2"

  /// A8.8.159 SADD16
  [<TestMethod>]
  member _.``A8.8.159 SADD16``() =
    testDisasm "fa91f002" "sadd16 r0, r1, r2"
    testDisasm "fa91f900" "sadd16 sb, r1, r0"
    testDisasm "fa91fa00" "sadd16 sl, r1, r0"
    testDisasm "fa91fb00" "sadd16 fp, r1, r0"

  /// A8.8.16 ASR (immediate)
  [<TestMethod>]
  member _.``A8.8.16 ASR``() =
    testDisasm "1410bf00" "asrs r0, r2, #0x10"
    testDisasm "fa40f002" "asr r0, r0, r2"
    testDisasm "fa51f002" "asrs.w r0, r1, r2"
    testDisasm "4111bf00" "asrs r1, r2"

  /// A8.8.160 SADD8
  [<TestMethod>]
  member _.``A8.8.160 SADD8``() =
    testDisasm "fa81f002" "sadd8 r0, r1, r2"
    testDisasm "fa81f900" "sadd8 sb, r1, r0"
    testDisasm "fa81fa00" "sadd8 sl, r1, r0"
    testDisasm "fa81fb00" "sadd8 fp, r1, r0"

  /// A8.8.161 SASX
  [<TestMethod>]
  member _.``A8.8.161 SASX``() =
    testDisasm "faa1f002" "sasx r0, r1, r2"
    testDisasm "faa1f900" "sasx sb, r1, r0"
    testDisasm "faa1fa00" "sasx sl, r1, r0"
    testDisasm "faa1fb00" "sasx fp, r1, r0"

  /// A8.8.162 SBC (immediate)
  [<TestMethod>]
  member _.``A8.8.162 SBC``() =
    testDisasm "f161407f" "sbc r0, r1, #0xff000000"
    testDisasm "f171407f" "sbcs r0, r1, #0xff000000"
    testDisasm "eb600002" "sbc r0, r0, r2"
    testDisasm "eb710002" "sbcs.w r0, r1, r2"

  /// A8.8.165 SBFX
  [<TestMethod>]
  member _.``A8.8.165 SBFX``() =
    testDisasm "f34100c4" "sbfx r0, r1, #0x3, #0x5"
    testDisasm "f3410900" "sbfx sb, r1, #0x0, #0x1"
    testDisasm "f3410a00" "sbfx sl, r1, #0x0, #0x1"
    testDisasm "f3410b00" "sbfx fp, r1, #0x0, #0x1"

  /// A8.8.166 SDIV
  [<TestMethod>]
  member _.``A8.8.166 SDIV``() =
    testDisasm "fb91f0f2" "sdiv r0, r1, r2"
    testDisasm "fb91f9f1" "sdiv sb, r1, r1"
    testDisasm "fb91faf1" "sdiv sl, r1, r1"
    testDisasm "fb91fbf1" "sdiv fp, r1, r1"

  /// A8.8.167 SEL
  [<TestMethod>]
  member _.``A8.8.167 SEL``() =
    testDisasm "faa1f082" "sel r0, r1, r2"

  /// A8.8.168 SETEND
  [<TestMethod>]
  member _.``A8.8.168 SETEND``() =
    testDisasm "b658bf00" "setend be"

  /// A8.8.169 SEV
  [<TestMethod>]
  member _.``A8.8.169 SEV``() =
    testDisasm "bf40bf00" "sev"
    testDisasm "f3af8004" "sev.w"

  /// A8.8.170 SHADD16
  [<TestMethod>]
  member _.``A8.8.170 SHADD16``() =
    testDisasm "fa91f022" "shadd16 r0, r1, r2"

  /// A8.8.171 SHADD8
  [<TestMethod>]
  member _.``A8.8.171 SHADD8``() =
    testDisasm "fa81f022" "shadd8 r0, r1, r2"

  /// A8.8.172 SHASX
  [<TestMethod>]
  member _.``A8.8.172 SHASX``() =
    testDisasm "faa1f022" "shasx r0, r1, r2"

  /// A8.8.173 SHSAX
  [<TestMethod>]
  member _.``A8.8.173 SHSAX``() =
    testDisasm "fae1f022" "shsax r0, r1, r2"

  /// A8.8.174 SHSUB16
  [<TestMethod>]
  member _.``A8.8.174 SHSUB16``() =
    testDisasm "fad1f022" "shsub16 r0, r1, r2"

  /// A8.8.175 SHSUB8
  [<TestMethod>]
  member _.``A8.8.175 SHSUB8``() =
    testDisasm "fac1f022" "shsub8 r0, r1, r2"

  /// A8.8.176 SMC (previously SMI)
  [<TestMethod>]
  member _.``A8.8.176 SMC``() =
    testDisasm "f7f18000" "smc #0x1"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLABB``() =
    testDisasm "fb113002" "smlabb r0, r1, r2, r3"
    testDisasm "fb110900" "smlabb sb, r1, r0, r0"
    testDisasm "fb110a00" "smlabb sl, r1, r0, r0"
    testDisasm "fb110b00" "smlabb fp, r1, r0, r0"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLABT``() =
    testDisasm "fb113012" "smlabt r0, r1, r2, r3"
    testDisasm "fb110910" "smlabt sb, r1, r0, r0"
    testDisasm "fb110a10" "smlabt sl, r1, r0, r0"
    testDisasm "fb110b10" "smlabt fp, r1, r0, r0"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLATB``() =
    testDisasm "fb113022" "smlatb r0, r1, r2, r3"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLATT``() =
    testDisasm "fb113032" "smlatt r0, r1, r2, r3"
    testDisasm "fb110934" "smlatt sb, r1, r4, r0"
    testDisasm "fb110a34" "smlatt sl, r1, r4, r0"
    testDisasm "fb110b34" "smlatt fp, r1, r4, r0"

  /// A8.8.178 SMLAD
  [<TestMethod>]
  member _.``A8.8.178 SMLAD``() =
    testDisasm "fb213002" "smlad r0, r1, r2, r3"
    testDisasm "fb210900" "smlad sb, r1, r0, r0"
    testDisasm "fb210a00" "smlad sl, r1, r0, r0"
    testDisasm "fb210b00" "smlad fp, r1, r0, r0"

  /// A8.8.179 SMLAL
  [<TestMethod>]
  member _.``A8.8.179 SMLAL``() =
    testDisasm "fbc20103" "smlal r0, r1, r2, r3"
    testDisasm "fbc10900" "smlal r0, sb, r1, r0"
    testDisasm "fbc10a00" "smlal r0, sl, r1, r0"
    testDisasm "fbc10b00" "smlal r0, fp, r1, r0"

  /// A8.8.18 B
  [<TestMethod>]
  member _.``A8.8.18 B``() =
    testDisasm "e000bf00" "b 0x4 ; "
    testDisasm "f000b800" "b.w 0x4 ; "

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALBB``() =
    testDisasm "fbc20183" "smlalbb r0, r1, r2, r3"

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALBT``() =
    testDisasm "fbc20193" "smlalbt r0, r1, r2, r3"

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALTB``() =
    testDisasm "fbc201a3" "smlaltb r0, r1, r2, r3"

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALTT``() =
    testDisasm "fbc201b3" "smlaltt r0, r1, r2, r3"

  /// A8.8.181 SMLALD
  [<TestMethod>]
  member _.``A8.8.181 SMLALD``() =
    testDisasm "fbc201c3" "smlald r0, r1, r2, r3"
    testDisasm "fbc109c1" "smlald r0, sb, r1, r1"
    testDisasm "fbc10ac1" "smlald r0, sl, r1, r1"
    testDisasm "fbc10bc1" "smlald r0, fp, r1, r1"

  /// A8.8.182 SMLAWB, SMLAWT
  [<TestMethod>]
  member _.``A8.8.182 SMLAWB``() =
    testDisasm "fb313002" "smlawb r0, r1, r2, r3"
    testDisasm "fb310900" "smlawb sb, r1, r0, r0"
    testDisasm "fb310a00" "smlawb sl, r1, r0, r0"
    testDisasm "fb310b00" "smlawb fp, r1, r0, r0"

  /// A8.8.182 SMLAWB, SMLAWT
  [<TestMethod>]
  member _.``A8.8.182 SMLAWT``() =
    testDisasm "fb313012" "smlawt r0, r1, r2, r3"
    testDisasm "fb310910" "smlawt sb, r1, r0, r0"
    testDisasm "fb310a10" "smlawt sl, r1, r0, r0"
    testDisasm "fb310b10" "smlawt fp, r1, r0, r0"

  /// A8.8.183 SMLSD
  [<TestMethod>]
  member _.``A8.8.183 SMLSD``() =
    testDisasm "fb413002" "smlsd r0, r1, r2, r3"
    testDisasm "fb410900" "smlsd sb, r1, r0, r0"
    testDisasm "fb410a00" "smlsd sl, r1, r0, r0"
    testDisasm "fb410b00" "smlsd fp, r1, r0, r0"

  /// A8.8.184 SMLSLD
  [<TestMethod>]
  member _.``A8.8.184 SMLSLD``() =
    testDisasm "fbd201c3" "smlsld r0, r1, r2, r3"
    testDisasm "fbd109c1" "smlsld r0, sb, r1, r1"
    testDisasm "fbd10ac1" "smlsld r0, sl, r1, r1"
    testDisasm "fbd10bc1" "smlsld r0, fp, r1, r1"

  /// A8.8.185 SMMLA
  [<TestMethod>]
  member _.``A8.8.185 SMMLA``() =
    testDisasm "fb513002" "smmla r0, r1, r2, r3"
    testDisasm "fb510900" "smmla sb, r1, r0, r0"
    testDisasm "fb510a00" "smmla sl, r1, r0, r0"
    testDisasm "fb510b00" "smmla fp, r1, r0, r0"

  /// A8.8.186 SMMLS
  [<TestMethod>]
  member _.``A8.8.186 SMMLS``() =
    testDisasm "fb613002" "smmls r0, r1, r2, r3"
    testDisasm "fb610900" "smmls sb, r1, r0, r0"
    testDisasm "fb610a00" "smmls sl, r1, r0, r0"
    testDisasm "fb610b00" "smmls fp, r1, r0, r0"

  /// A8.8.187 SMMUL
  [<TestMethod>]
  member _.``A8.8.187 SMMUL``() =
    testDisasm "fb51f002" "smmul r0, r1, r2"
    testDisasm "fb51f900" "smmul sb, r1, r0"
    testDisasm "fb51fa00" "smmul sl, r1, r0"
    testDisasm "fb51fb00" "smmul fp, r1, r0"

  /// A8.8.188 SMUAD
  [<TestMethod>]
  member _.``A8.8.188 SMUAD``() =
    testDisasm "fb21f002" "smuad r0, r1, r2"
    testDisasm "fb21f900" "smuad sb, r1, r0"
    testDisasm "fb21fa00" "smuad sl, r1, r0"
    testDisasm "fb21fb00" "smuad fp, r1, r0"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULBB``() =
    testDisasm "fb11f002" "smulbb r0, r1, r2"
    testDisasm "fb11f900" "smulbb sb, r1, r0"
    testDisasm "fb11fa00" "smulbb sl, r1, r0"
    testDisasm "fb11fb00" "smulbb fp, r1, r0"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULBT``() =
    testDisasm "fb11f012" "smulbt r0, r1, r2"
    testDisasm "fb11f910" "smulbt sb, r1, r0"
    testDisasm "fb11fa10" "smulbt sl, r1, r0"
    testDisasm "fb11fb10" "smulbt fp, r1, r0"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULTB``() =
    testDisasm "fb11f022" "smultb r0, r1, r2"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULTT``() =
    testDisasm "fb11f032" "smultt r0, r1, r2"
    testDisasm "fb11f934" "smultt sb, r1, r4"
    testDisasm "fb11fa34" "smultt sl, r1, r4"
    testDisasm "fb11fb34" "smultt fp, r1, r4"

  /// A8.8.19 BFC
  [<TestMethod>]
  member _.``A8.8.19 BFC``() =
    testDisasm "f36f00c7" "bfc r0, #0x3, #0x5"
    testDisasm "f36f0900" "bfc sb, #0x0, #0x1"
    testDisasm "f36f0a00" "bfc sl, #0x0, #0x1"
    testDisasm "f36f0b00" "bfc fp, #0x0, #0x1"

  /// A8.8.190 SMULL
  [<TestMethod>]
  member _.``A8.8.190 SMULL``() =
    testDisasm "fb820103" "smull r0, r1, r2, r3"
    testDisasm "fb810900" "smull r0, sb, r1, r0"
    testDisasm "fb810a00" "smull r0, sl, r1, r0"
    testDisasm "fb810b00" "smull r0, fp, r1, r0"

  /// A8.8.191 SMULWB, SMULWT
  [<TestMethod>]
  member _.``A8.8.191 SMULWB``() =
    testDisasm "fb31f002" "smulwb r0, r1, r2"
    testDisasm "fb31f900" "smulwb sb, r1, r0"
    testDisasm "fb31fa00" "smulwb sl, r1, r0"
    testDisasm "fb31fb00" "smulwb fp, r1, r0"

  /// A8.8.191 SMULWB, SMULWT
  [<TestMethod>]
  member _.``A8.8.191 SMULWT``() =
    testDisasm "fb31f012" "smulwt r0, r1, r2"
    testDisasm "fb31f910" "smulwt sb, r1, r0"
    testDisasm "fb31fa10" "smulwt sl, r1, r0"
    testDisasm "fb31fb10" "smulwt fp, r1, r0"

  /// A8.8.192 SMUSD
  [<TestMethod>]
  member _.``A8.8.192 SMUSD``() =
    testDisasm "fb41f002" "smusd r0, r1, r2"
    testDisasm "fb41f900" "smusd sb, r1, r0"
    testDisasm "fb41fa00" "smusd sl, r1, r0"
    testDisasm "fb41fb00" "smusd fp, r1, r0"

  /// A8.8.193 SRS
  [<TestMethod>]
  member _.``A8.8.193 SRS``() =
    testDisasm "e9adc013" "srsia sp!, #0x13"
    testDisasm "e80dc013" "srsdb sp, #0x13"

  /// A8.8.194 SSAT
  [<TestMethod>]
  member _.``A8.8.194 SSAT``() =
    testDisasm "f3010007" "ssat r0, #0x8, r1"
    testDisasm "f301004f" "ssat r0, #0x10, r1, lsl #0x1"
    testDisasm "f321104f" "ssat r0, #0x10, r1, asr #0x5"
    testDisasm "f3010900" "ssat sb, #0x1, r1"

  /// A8.8.195 SSAT16
  [<TestMethod>]
  member _.``A8.8.195 SSAT16``() =
    testDisasm "f3210007" "ssat16 r0, #0x8, r1"
    testDisasm "f3210900" "ssat16 sb, #0x1, r1"
    testDisasm "f3210a00" "ssat16 sl, #0x1, r1"
    testDisasm "f3210b00" "ssat16 fp, #0x1, r1"

  /// A8.8.196 SSAX
  [<TestMethod>]
  member _.``A8.8.196 SSAX``() =
    testDisasm "fae1f002" "ssax r0, r1, r2"
    testDisasm "fae1f900" "ssax sb, r1, r0"
    testDisasm "fae1fa00" "ssax sl, r1, r0"
    testDisasm "fae1fb00" "ssax fp, r1, r0"

  /// A8.8.197 SSUB16
  [<TestMethod>]
  member _.``A8.8.197 SSUB16``() =
    testDisasm "fad1f002" "ssub16 r0, r1, r2"
    testDisasm "fad1f900" "ssub16 sb, r1, r0"
    testDisasm "fad1fa00" "ssub16 sl, r1, r0"
    testDisasm "fad1fb00" "ssub16 fp, r1, r0"

  /// A8.8.198 SSUB8
  [<TestMethod>]
  member _.``A8.8.198 SSUB8``() =
    testDisasm "fac1f002" "ssub8 r0, r1, r2"
    testDisasm "fac1f900" "ssub8 sb, r1, r0"
    testDisasm "fac1fa00" "ssub8 sl, r1, r0"
    testDisasm "fac1fb00" "ssub8 fp, r1, r0"

  /// A8.8.199 STC, STC2
  [<TestMethod>]
  member _.``A8.8.199 STC``() =
    testDisasm "ec215e34" "stc p14, c5, [r1], #-0xd0"
    testDisasm "ec295e34" "stc p14, c5, [sb], #-0xd0"
    testDisasm "ec2d5e34" "stc p14, c5, [sp], #-0xd0"
    testDisasm "ed015e34" "stc p14, c5, [r1, #-0xd0]"

  /// A8.8.20 BFI
  [<TestMethod>]
  member _.``A8.8.20 BFI``() =
    testDisasm "f36100c7" "bfi r0, r1, #0x3, #0x5"
    testDisasm "f3610900" "bfi sb, r1, #0x0, #0x1"
    testDisasm "f3610a00" "bfi sl, r1, #0x0, #0x1"
    testDisasm "f3610b00" "bfi fp, r1, #0x0, #0x1"

  /// A8.8.200 STM (STMIA, STMEA)
  [<TestMethod>]
  member _.``A8.8.200 STM``() =
    testDisasm "e881000c" "stm.w r1, {r2, r3}"
    testDisasm "c10cbf00" "stm r1!, {r2, r3}"
    testDisasm "c001bf00" "stm r0!, {r0}"
    testDisasm "c007bf00" "stm r0!, {r0, r1, r2}"

  /// A8.8.202 STMDB (STMFD)
  [<TestMethod>]
  member _.``A8.8.202 STMDB``() =
    testDisasm "e901000c" "stmdb r1, {r2, r3}"
    testDisasm "e921000c" "stmdb r1!, {r2, r3}"
    testDisasm "e9010034" "stmdb r1, {r2, r4, r5}"
    testDisasm "e901004f" "stmdb r1, {r0, r1, r2, r3, r6}"

  /// A8.8.204 STR (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.204 STR``() =
    testDisasm "6108bf00" "str r0, [r1, #0x10]"
    testDisasm "5088bf00" "str r0, [r1, r2]"
    testDisasm "f8410012" "str r0, [r1, r2, lsl #0x1]"
    testDisasm "6008bf00" "str r0, [r1]"

  /// A8.8.207 STRB (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.207 STRB``() =
    testDisasm "70c8bf00" "strb r0, [r1, #0x3]"
    testDisasm "5488bf00" "strb r0, [r1, r2]"
    testDisasm "f8010012" "strb r0, [r1, r2, lsl #0x1]"
    testDisasm "7008bf00" "strb r0, [r1]"

  /// A8.8.21 BIC (immediate)
  [<TestMethod>]
  member _.``A8.8.21 BIC``() =
    testDisasm "f021407f" "bic r0, r1, #0xff000000"
    testDisasm "f031407f" "bics r0, r1, #0xff000000"
    testDisasm "ea200002" "bic r0, r0, r2"
    testDisasm "ea310002" "bics r0, r1, r2"

  /// A8.8.210 STRBT
  [<TestMethod>]
  member _.``A8.8.210 STRBT``() =
    testDisasm "f8010e00" "strbt r0, [r1]"
    testDisasm "f8010e03" "strbt r0, [r1, #0x3]"
    testDisasm "f8019e34" "strbt sb, [r1, #0x34]"
    testDisasm "f8019e00" "strbt sb, [r1]"

  /// A8.8.211 STRD (immediate)
  [<TestMethod>]
  member _.``A8.8.211 STRD``() =
    testDisasm "e9c10100" "strd r0, r1, [r1]"
    testDisasm "e8610034" "strd r0, r0, [r1], #-0xd0"
    testDisasm "e8610934" "strd r0, sb, [r1], #-0xd0"
    testDisasm "e8610a34" "strd r0, sl, [r1], #-0xd0"

  /// A8.8.213 STREX
  [<TestMethod>]
  member _.``A8.8.213 STREX``() =
    testDisasm "e8412000" "strex r0, r2, [r1]"
    testDisasm "e8410234" "strex r2, r0, [r1, #0xd0]"
    testDisasm "e8410934" "strex sb, r0, [r1, #0xd0]"
    testDisasm "e8410900" "strex sb, r0, [r1]"

  /// A8.8.214 STREXB
  [<TestMethod>]
  member _.``A8.8.214 STREXB``() =
    testDisasm "e8c12f40" "strexb r0, r2, [r1]"

  /// A8.8.215 STREXD
  [<TestMethod>]
  member _.``A8.8.215 STREXD``() =
    testDisasm "e8c12370" "strexd r0, r2, r3, [r1]"
    testDisasm "e8c11970" "strexd r0, r1, sb, [r1]"
    testDisasm "e8c11a70" "strexd r0, r1, sl, [r1]"
    testDisasm "e8c11b70" "strexd r0, r1, fp, [r1]"

  /// A8.8.216 STREXH
  [<TestMethod>]
  member _.``A8.8.216 STREXH``() =
    testDisasm "e8c12f50" "strexh r0, r2, [r1]"

  /// A8.8.217 STRH (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.217 STRH``() =
    testDisasm "8208bf00" "strh r0, [r1, #0x10]"
    testDisasm "5288bf00" "strh r0, [r1, r2]"
    testDisasm "8008bf00" "strh r0, [r1]"
    testDisasm "f8a10000" "strh.w r0, [r1]"

  /// A8.8.220 STRHT
  [<TestMethod>]
  member _.``A8.8.220 STRHT``() =
    testDisasm "f8210e00" "strht r0, [r1]"
    testDisasm "f8210e03" "strht r0, [r1, #0x3]"
    testDisasm "f8219e34" "strht sb, [r1, #0x34]"
    testDisasm "f8219e00" "strht sb, [r1]"

  /// A8.8.221 STRT
  [<TestMethod>]
  member _.``A8.8.221 STRT``() =
    testDisasm "f8410e00" "strt r0, [r1]"
    testDisasm "f8410e03" "strt r0, [r1, #0x3]"
    testDisasm "f8419e34" "strt sb, [r1, #0x34]"
    testDisasm "f8419e00" "strt sb, [r1]"

  /// A8.8.222 SUB (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.222 SUB``() =
    testDisasm "b082bf00" "sub sp, sp, #0x8"
    testDisasm "f1a00003" "sub r0, r0, #0x3"
    testDisasm "f1b1417f" "subs.w r1, r1, #0xff000000"
    testDisasm "eba10002" "sub r0, r1, r2"

  /// A8.8.228 SUBS PC, LR and related instructions
  [<TestMethod>]
  member _.``A8.8.228 SUBS``() =
    testDisasm "f1b1417f" "subs.w r1, r1, #0xff000000"
    testDisasm "1a88bf00" "subs r0, r1, r2"
    testDisasm "ebb10002" "subs.w r0, r1, r2"
    testDisasm "1e00bf00" "subs r0, r0, #0x0"

  /// A8.8.229 SVC (previously SWI)
  [<TestMethod>]
  member _.``A8.8.229 SVC``() =
    testDisasm "df00bf00" "svc #0x0"

  /// A8.8.231 SXTAB
  [<TestMethod>]
  member _.``A8.8.231 SXTAB``() =
    testDisasm "fa41f082" "sxtab r0, r1, r2"

  /// A8.8.232 SXTAB16
  [<TestMethod>]
  member _.``A8.8.232 SXTAB16``() =
    testDisasm "fa21f082" "sxtab16 r0, r1, r2"

  /// A8.8.233 SXTAH
  [<TestMethod>]
  member _.``A8.8.233 SXTAH``() =
    testDisasm "fa01f082" "sxtah r0, r1, r2"

  /// A8.8.234 SXTB
  [<TestMethod>]
  member _.``A8.8.234 SXTB``() =
    testDisasm "b248bf00" "sxtb r0, r1"
    testDisasm "fa4ff082" "sxtb.w r0, r2"

  /// A8.8.235 SXTB16
  [<TestMethod>]
  member _.``A8.8.235 SXTB16``() =
    testDisasm "fa2ff081" "sxtb16 r0, r1"

  /// A8.8.236 SXTH
  [<TestMethod>]
  member _.``A8.8.236 SXTH``() =
    testDisasm "b208bf00" "sxth r0, r1"
    testDisasm "fa0ff082" "sxth.w r0, r2"

  /// A8.8.237 TBB, TBH
  [<TestMethod>]
  member _.``A8.8.237 TBB``() =
    testDisasm "e8d1f002" "tbb [r1, r2]"
    testDisasm "e8dff002" "tbb [pc, r2]"
