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
/// One test for each A32 instruction DDI0406C and DDI0487F.c's AArch32
/// chapters describe, ADC to SXTAB16 in the order of their sections. Each
/// reads A32 words of the instruction and checks the text, and each word's
/// text is one binutils' objdump reads the word as too, so what is asserted
/// is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualA32ParserTests1() =
  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let isa = ISA(Architecture.ARMv7, Endian.Big)
    let parser = Parser(isa, false, BinReader.Init Endian.Big)
    let ins = (parser :> IInstructionParsable).Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// A8.8.1 ADC (immediate)
  [<TestMethod>]
  member _.``A8.8.1 ADC``() =
    testDisasm "e0a00002" "adc r0, r0, r2"
    testDisasm "e0b10002" "adcs r0, r1, r2"
    testDisasm "e0a10082" "adc r0, r1, r2, lsl #0x1"
    testDisasm "e0a101a2" "adc r0, r1, r2, lsr #0x3"

  /// A8.8.100 MCRR, MCRR2
  [<TestMethod>]
  member _.``A8.8.100 MCRR``() =
    testDisasm "ec412e04" "mcrr p14, #0x0, r2, r1, c4"
    testDisasm "ec41de04" "mcrr p14, #0x0, sp, r1, c4"
    testDisasm "ec492e04" "mcrr p14, #0x0, r2, sb, c4"
    testDisasm "ec49de04" "mcrr p14, #0x0, sp, sb, c4"

  /// A8.8.100 MCRR, MCRR2
  [<TestMethod>]
  member _.``A8.8.100 MCRR2``() =
    testDisasm "fc432314" "mcrr2 p3, #0x1, r2, r3, c4"

  /// A8.8.101 MLA
  [<TestMethod>]
  member _.``A8.8.101 MLA``() =
    testDisasm "e0203291" "mla r0, r1, r2, r3"
    testDisasm "e0303291" "mlas r0, r1, r2, r3"
    testDisasm "e0212994" "mla r1, r4, sb, r2"
    testDisasm "e0212a94" "mla r1, r4, sl, r2"

  /// A8.8.102 MLS
  [<TestMethod>]
  member _.``A8.8.102 MLS``() =
    testDisasm "e0603291" "mls r0, r1, r2, r3"
    testDisasm "e0612994" "mls r1, r4, sb, r2"
    testDisasm "e0612a94" "mls r1, r4, sl, r2"
    testDisasm "e0612b94" "mls r1, r4, fp, r2"

  /// A8.8.103 MOV (immediate)
  [<TestMethod>]
  member _.``A8.8.103 MOV``() =
    testDisasm "e3a00003" "mov r0, #0x3"
    testDisasm "e1a00002" "mov r0, r2"
    testDisasm "e1b00002" "movs r0, r2"
    testDisasm "e1a0200f" "mov r2, pc"

  /// A8.8.107 MOVT
  [<TestMethod>]
  member _.``A8.8.107 MOVT``() =
    testDisasm "e3400007" "movt r0, #0x7"
    testDisasm "e341d004" "movt sp, #0x1004"
    testDisasm "e341f004" "movt pc, #0x1004"
    testDisasm "13412004" "movtne r2, #0x1004"

  /// A8.8.108 MRC, MRC2
  [<TestMethod>]
  member _.``A8.8.108 MRC``() =
    testDisasm "ee112e14" "mrc p14, #0x0, r2, c1, c4, #0x0"
    testDisasm "ee11de14" "mrc p14, #0x0, sp, c1, c4, #0x0"
    testDisasm "ee11fe14" "mrc p14, #0x0, apsr_nzcv, c1, c4, #0x0"
    testDisasm "1e112e14" "mrcne p14, #0x0, r2, c1, c4, #0x0"

  /// A8.8.108 MRC, MRC2
  [<TestMethod>]
  member _.``A8.8.108 MRC2``() =
    testDisasm "fe3323b4" "mrc2 p3, #0x1, r2, c3, c4, #0x5"

  /// A8.8.109 MRRC, MRRC2
  [<TestMethod>]
  member _.``A8.8.109 MRRC``() =
    testDisasm "ec512e04" "mrrc p14, #0x0, r2, r1, c4"
    testDisasm "ec51de04" "mrrc p14, #0x0, sp, r1, c4"
    testDisasm "ec592e04" "mrrc p14, #0x0, r2, sb, c4"
    testDisasm "ec59de04" "mrrc p14, #0x0, sp, sb, c4"

  /// A8.8.109 MRRC, MRRC2
  [<TestMethod>]
  member _.``A8.8.109 MRRC2``() =
    testDisasm "fc532314" "mrrc2 p3, #0x1, r2, r3, c4"

  /// A8.8.110 MRS
  [<TestMethod>]
  member _.``A8.8.110 MRS``() =
    testDisasm "e1012200" "mrs r2, r9_usr"
    testDisasm "e1012300" "mrs r2, sp_irq"
    testDisasm "e101d200" "mrs sp, r9_usr"
    testDisasm "e101d300" "mrs sp, sp_irq"

  /// A8.8.112 MSR (immediate)
  [<TestMethod>]
  member _.``A8.8.112 MSR``() =
    testDisasm "e321f004" "msr cpsr_c, #0x4"
    testDisasm "e329f004" "msr cpsr_fc, #0x4"
    testDisasm "e32df004" "msr cpsr_fsc, #0x4"
    testDisasm "e32ff004" "msr cpsr_fsxc, #0x4"

  /// A8.8.115 MUL
  [<TestMethod>]
  member _.``A8.8.115 MUL``() =
    testDisasm "e0100091" "muls r0, r1, r0"
    testDisasm "e0000291" "mul r0, r1, r2"
    testDisasm "e0012994" "mul r1, r4, sb"
    testDisasm "e0012a94" "mul r1, r4, sl"

  /// A8.8.116 MVN (immediate)
  [<TestMethod>]
  member _.``A8.8.116 MVN``() =
    testDisasm "e1e00002" "mvn r0, r2"
    testDisasm "e1f00002" "mvns r0, r2"
    testDisasm "e1e00082" "mvn r0, r2, lsl #0x1"
    testDisasm "e1e001a2" "mvn r0, r2, lsr #0x3"

  /// A8.8.119 NEG
  [<TestMethod>]
  member _.``A8.8.119 NEG``() =
    testDisasm "e2620000" "rsb r0, r2, #0x0"
    testDisasm "e2712000" "rsbs r2, r1, #0x0"
    testDisasm "12612000" "rsbne r2, r1, #0x0"
    testDisasm "12712000" "rsbsne r2, r1, #0x0"

  /// A8.8.120 NOP
  [<TestMethod>]
  member _.``A8.8.120 NOP``() =
    testDisasm "e320f000" "nop"

  /// A8.8.123 ORR (immediate)
  [<TestMethod>]
  member _.``A8.8.123 ORR``() =
    testDisasm "e1800002" "orr r0, r0, r2"
    testDisasm "e1910002" "orrs r0, r1, r2"
    testDisasm "e1810082" "orr r0, r1, r2, lsl #0x1"
    testDisasm "e18101a2" "orr r0, r1, r2, lsr #0x3"

  /// A8.8.126 PKH
  [<TestMethod>]
  member _.``A8.8.126 PKH``() =
    testDisasm "e6810212" "pkhbt r0, r1, r2, lsl #0x4"
    testDisasm "e6810252" "pkhtb r0, r1, r2, asr #0x4"
    testDisasm "e6810012" "pkhbt r0, r1, r2"
    testDisasm "e681d014" "pkhbt sp, r1, r4"

  /// A8.8.127 PLD, PLDW (immediate)
  [<TestMethod>]
  member _.``A8.8.127 PLD``() =
    testDisasm "f5d1f007" "pld [r1, #0x7]"
    testDisasm "f55ff004" "pld [0x4]"
    testDisasm "f7d1f002" "pld [r1, r2]"
    testDisasm "f5d1f000" "pld [r1]"

  /// A8.8.127 PLD, PLDW (immediate)
  [<TestMethod>]
  member _.``A8.8.127 PLDW``() =
    testDisasm "f591f007" "pldw [r1, #0x7]"
    testDisasm "f791f002" "pldw [r1, r2]"
    testDisasm "f591f000" "pldw [r1]"
    testDisasm "f519f000" "pldw [sb]"

  /// A8.8.13 AND (immediate)
  [<TestMethod>]
  member _.``A8.8.13 AND``() =
    testDisasm "e0000002" "and r0, r0, r2"
    testDisasm "e0110002" "ands r0, r1, r2"
    testDisasm "e0010082" "and r0, r1, r2, lsl #0x1"
    testDisasm "e00101a2" "and r0, r1, r2, lsr #0x3"

  /// A8.8.130 PLI (immediate, literal)
  [<TestMethod>]
  member _.``A8.8.130 PLI``() =
    testDisasm "f45ff004" "pli [0x4]"
    testDisasm "f6d1f002" "pli [r1, r2]"
    testDisasm "f651f004" "pli [r1, -r4]"
    testDisasm "f651f104" "pli [r1, -r4, lsl #0x2]"

  /// A8.8.132 POP (Thumb)
  [<TestMethod>]
  member _.``A8.8.132 POP``() =
    testDisasm "e8bd000c" "pop {r2, r3}"
    testDisasm "e49d2004" "pop {r2}"
    testDisasm "e49df004" "pop {pc}"
    testDisasm "e8bd000f" "pop {r0, r1, r2, r3}"

  /// A8.8.134 PUSH
  [<TestMethod>]
  member _.``A8.8.134 PUSH``() =
    testDisasm "e92d000c" "push {r2, r3}"
    testDisasm "e52d2004" "push {r2}"
    testDisasm "e52df004" "push {pc}"
    testDisasm "e92d2004" "push {r2, sp}"

  /// A8.8.135 QADD
  [<TestMethod>]
  member _.``A8.8.135 QADD``() =
    testDisasm "e1020051" "qadd r0, r1, r2"
    testDisasm "e101d054" "qadd sp, r4, r1"
    testDisasm "e1092054" "qadd r2, r4, sb"
    testDisasm "e109d054" "qadd sp, r4, sb"

  /// A8.8.136 QADD16
  [<TestMethod>]
  member _.``A8.8.136 QADD16``() =
    testDisasm "e6210f12" "qadd16 r0, r1, r2"

  /// A8.8.137 QADD8
  [<TestMethod>]
  member _.``A8.8.137 QADD8``() =
    testDisasm "e6210f92" "qadd8 r0, r1, r2"

  /// A8.8.138 QASX
  [<TestMethod>]
  member _.``A8.8.138 QASX``() =
    testDisasm "e6210f32" "qasx r0, r1, r2"

  /// A8.8.139 QDADD
  [<TestMethod>]
  member _.``A8.8.139 QDADD``() =
    testDisasm "e1420051" "qdadd r0, r1, r2"
    testDisasm "e141205f" "qdadd r2, pc, r1"
    testDisasm "e141d054" "qdadd sp, r4, r1"
    testDisasm "e141d05f" "qdadd sp, pc, r1"

  /// A8.8.140 QDSUB
  [<TestMethod>]
  member _.``A8.8.140 QDSUB``() =
    testDisasm "e1620051" "qdsub r0, r1, r2"
    testDisasm "e161205f" "qdsub r2, pc, r1"
    testDisasm "e161d054" "qdsub sp, r4, r1"
    testDisasm "e161d05f" "qdsub sp, pc, r1"

  /// A8.8.141 QSAX
  [<TestMethod>]
  member _.``A8.8.141 QSAX``() =
    testDisasm "e6210f52" "qsax r0, r1, r2"

  /// A8.8.142 QSUB
  [<TestMethod>]
  member _.``A8.8.142 QSUB``() =
    testDisasm "e1220051" "qsub r0, r1, r2"
    testDisasm "e121205f" "qsub r2, pc, r1"
    testDisasm "e121d054" "qsub sp, r4, r1"
    testDisasm "e121d05f" "qsub sp, pc, r1"

  /// A8.8.143 QSUB16
  [<TestMethod>]
  member _.``A8.8.143 QSUB16``() =
    testDisasm "e6210f72" "qsub16 r0, r1, r2"

  /// A8.8.144 QSUB8
  [<TestMethod>]
  member _.``A8.8.144 QSUB8``() =
    testDisasm "e6210ff2" "qsub8 r0, r1, r2"

  /// A8.8.145 RBIT
  [<TestMethod>]
  member _.``A8.8.145 RBIT``() =
    testDisasm "e6ff0f31" "rbit r0, r1"

  /// A8.8.146 REV
  [<TestMethod>]
  member _.``A8.8.146 REV``() =
    testDisasm "e6bf0f31" "rev r0, r1"

  /// A8.8.147 REV16
  [<TestMethod>]
  member _.``A8.8.147 REV16``() =
    testDisasm "e6bf0fb1" "rev16 r0, r1"

  /// A8.8.148 REVSH
  [<TestMethod>]
  member _.``A8.8.148 REVSH``() =
    testDisasm "e6ff0fb1" "revsh r0, r1"

  /// A8.8.149 RFE
  [<TestMethod>]
  member _.``A8.8.149 RFE``() =
    testDisasm "f8910a00" "rfeia r1"
    testDisasm "f8310a00" "rfeda r1!"
    testDisasm "f9110a00" "rfedb r1"
    testDisasm "f9b10a00" "rfeib r1!"

  /// A8.8.150 ROR (immediate)
  [<TestMethod>]
  member _.``A8.8.150 ROR``() =
    testDisasm "e1a00862" "ror r0, r2, #0x10"
    testDisasm "e1b00862" "rors r0, r2, #0x10"
    testDisasm "e1a00270" "ror r0, r0, r2"
    testDisasm "e1b00271" "rors r0, r1, r2"

  /// A8.8.152 RRX
  [<TestMethod>]
  member _.``A8.8.152 RRX``() =
    testDisasm "e1b00062" "rrxs r0, r2"
    testDisasm "e1a00062" "rrx r0, r2"
    testDisasm "e1a0206f" "rrx r2, pc"
    testDisasm "e1a0d064" "rrx sp, r4"

  /// A8.8.153 RSB (immediate)
  [<TestMethod>]
  member _.``A8.8.153 RSB``() =
    testDisasm "e0610002" "rsb r0, r1, r2"
    testDisasm "e0710002" "rsbs r0, r1, r2"
    testDisasm "e0610082" "rsb r0, r1, r2, lsl #0x1"
    testDisasm "e06101a2" "rsb r0, r1, r2, lsr #0x3"

  /// A8.8.156 RSC (immediate)
  [<TestMethod>]
  member _.``A8.8.156 RSC``() =
    testDisasm "e2e10000" "rsc r0, r1, #0x0"
    testDisasm "e0e10002" "rsc r0, r1, r2"
    testDisasm "e0f10002" "rscs r0, r1, r2"
    testDisasm "e0e10082" "rsc r0, r1, r2, lsl #0x1"

  /// A8.8.159 SADD16
  [<TestMethod>]
  member _.``A8.8.159 SADD16``() =
    testDisasm "e6110f12" "sadd16 r0, r1, r2"

  /// A8.8.16 ASR (immediate)
  [<TestMethod>]
  member _.``A8.8.16 ASR``() =
    testDisasm "e1a00842" "asr r0, r2, #0x10"
    testDisasm "e1b00842" "asrs r0, r2, #0x10"
    testDisasm "e1a00250" "asr r0, r0, r2"
    testDisasm "e1b00251" "asrs r0, r1, r2"

  /// A8.8.160 SADD8
  [<TestMethod>]
  member _.``A8.8.160 SADD8``() =
    testDisasm "e6110f92" "sadd8 r0, r1, r2"

  /// A8.8.161 SASX
  [<TestMethod>]
  member _.``A8.8.161 SASX``() =
    testDisasm "e6110f32" "sasx r0, r1, r2"

  /// A8.8.162 SBC (immediate)
  [<TestMethod>]
  member _.``A8.8.162 SBC``() =
    testDisasm "e0c00002" "sbc r0, r0, r2"
    testDisasm "e0d10002" "sbcs r0, r1, r2"
    testDisasm "e0c10082" "sbc r0, r1, r2, lsl #0x1"
    testDisasm "e0c101a2" "sbc r0, r1, r2, lsr #0x3"

  /// A8.8.165 SBFX
  [<TestMethod>]
  member _.``A8.8.165 SBFX``() =
    testDisasm "e7a401d1" "sbfx r0, r1, #0x3, #0x5"
    testDisasm "e7a1d054" "sbfx sp, r4, #0x0, #0x2"
    testDisasm "17a12054" "sbfxne r2, r4, #0x0, #0x2"
    testDisasm "17a1d054" "sbfxne sp, r4, #0x0, #0x2"

  /// A8.8.166 SDIV
  [<TestMethod>]
  member _.``A8.8.166 SDIV``() =
    testDisasm "e710f211" "sdiv r0, r1, r2"
    testDisasm "e711f914" "sdiv r1, r4, sb"
    testDisasm "e711fa14" "sdiv r1, r4, sl"
    testDisasm "e711fb14" "sdiv r1, r4, fp"

  /// A8.8.167 SEL
  [<TestMethod>]
  member _.``A8.8.167 SEL``() =
    testDisasm "e6810fb2" "sel r0, r1, r2"

  /// A8.8.168 SETEND
  [<TestMethod>]
  member _.``A8.8.168 SETEND``() =
    testDisasm "f1010200" "setend be"
    testDisasm "f1010000" "setend le"

  /// A8.8.169 SEV
  [<TestMethod>]
  member _.``A8.8.169 SEV``() =
    testDisasm "e320f004" "sev"
    testDisasm "1320f004" "sevne"

  /// A8.8.170 SHADD16
  [<TestMethod>]
  member _.``A8.8.170 SHADD16``() =
    testDisasm "e6310f12" "shadd16 r0, r1, r2"

  /// A8.8.171 SHADD8
  [<TestMethod>]
  member _.``A8.8.171 SHADD8``() =
    testDisasm "e6310f92" "shadd8 r0, r1, r2"

  /// A8.8.172 SHASX
  [<TestMethod>]
  member _.``A8.8.172 SHASX``() =
    testDisasm "e6310f32" "shasx r0, r1, r2"

  /// A8.8.173 SHSAX
  [<TestMethod>]
  member _.``A8.8.173 SHSAX``() =
    testDisasm "e6310f52" "shsax r0, r1, r2"

  /// A8.8.174 SHSUB16
  [<TestMethod>]
  member _.``A8.8.174 SHSUB16``() =
    testDisasm "e6310f72" "shsub16 r0, r1, r2"

  /// A8.8.175 SHSUB8
  [<TestMethod>]
  member _.``A8.8.175 SHSUB8``() =
    testDisasm "e6310ff2" "shsub8 r0, r1, r2"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLABB``() =
    testDisasm "e1003281" "smlabb r0, r1, r2, r3"
    testDisasm "e1012984" "smlabb r1, r4, sb, r2"
    testDisasm "e1012a84" "smlabb r1, r4, sl, r2"
    testDisasm "e1012b84" "smlabb r1, r4, fp, r2"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLABT``() =
    testDisasm "e10032c1" "smlabt r0, r1, r2, r3"
    testDisasm "e10129c4" "smlabt r1, r4, sb, r2"
    testDisasm "e1012ac4" "smlabt r1, r4, sl, r2"
    testDisasm "e1012bc4" "smlabt r1, r4, fp, r2"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLATB``() =
    testDisasm "e10032a1" "smlatb r0, r1, r2, r3"
    testDisasm "e10129a4" "smlatb r1, r4, sb, r2"
    testDisasm "e1012aa4" "smlatb r1, r4, sl, r2"
    testDisasm "e1012ba4" "smlatb r1, r4, fp, r2"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLATT``() =
    testDisasm "e10032e1" "smlatt r0, r1, r2, r3"
    testDisasm "e10129e4" "smlatt r1, r4, sb, r2"
    testDisasm "e1012ae4" "smlatt r1, r4, sl, r2"
    testDisasm "e1012be4" "smlatt r1, r4, fp, r2"

  /// A8.8.178 SMLAD
  [<TestMethod>]
  member _.``A8.8.178 SMLAD``() =
    testDisasm "e7003211" "smlad r0, r1, r2, r3"
    testDisasm "e7012914" "smlad r1, r4, sb, r2"
    testDisasm "e7012a14" "smlad r1, r4, sl, r2"
    testDisasm "e7012b14" "smlad r1, r4, fp, r2"

  /// A8.8.179 SMLAL
  [<TestMethod>]
  member _.``A8.8.179 SMLAL``() =
    testDisasm "e0e10392" "smlal r0, r1, r2, r3"
    testDisasm "e0f10291" "smlals r0, r1, r1, r2"
    testDisasm "e0e12994" "smlal r2, r1, r4, sb"
    testDisasm "e0e12a94" "smlal r2, r1, r4, sl"

  /// A8.8.18 B
  [<TestMethod>]
  member _.``A8.8.18 B``() =
    testDisasm "eaffffff" "b 0x4 ; "

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALBB``() =
    testDisasm "e1410382" "smlalbb r0, r1, r2, r3"
    testDisasm "e1412984" "smlalbb r2, r1, r4, sb"
    testDisasm "e1412a84" "smlalbb r2, r1, r4, sl"
    testDisasm "e1412b84" "smlalbb r2, r1, r4, fp"

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALBT``() =
    testDisasm "e14103c2" "smlalbt r0, r1, r2, r3"
    testDisasm "e14129c4" "smlalbt r2, r1, r4, sb"
    testDisasm "e1412ac4" "smlalbt r2, r1, r4, sl"
    testDisasm "e1412bc4" "smlalbt r2, r1, r4, fp"

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALTB``() =
    testDisasm "e14103a2" "smlaltb r0, r1, r2, r3"
    testDisasm "e14129a4" "smlaltb r2, r1, r4, sb"
    testDisasm "e1412aa4" "smlaltb r2, r1, r4, sl"
    testDisasm "e1412ba4" "smlaltb r2, r1, r4, fp"

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALTT``() =
    testDisasm "e14103e2" "smlaltt r0, r1, r2, r3"
    testDisasm "e14129e4" "smlaltt r2, r1, r4, sb"
    testDisasm "e1412ae4" "smlaltt r2, r1, r4, sl"
    testDisasm "e1412be4" "smlaltt r2, r1, r4, fp"

  /// A8.8.181 SMLALD
  [<TestMethod>]
  member _.``A8.8.181 SMLALD``() =
    testDisasm "e7410312" "smlald r0, r1, r2, r3"
    testDisasm "e7412914" "smlald r2, r1, r4, sb"
    testDisasm "e7412a14" "smlald r2, r1, r4, sl"
    testDisasm "e7412b14" "smlald r2, r1, r4, fp"

  /// A8.8.182 SMLAWB, SMLAWT
  [<TestMethod>]
  member _.``A8.8.182 SMLAWB``() =
    testDisasm "e1203281" "smlawb r0, r1, r2, r3"
    testDisasm "e1212984" "smlawb r1, r4, sb, r2"
    testDisasm "e1212a84" "smlawb r1, r4, sl, r2"
    testDisasm "e1212b84" "smlawb r1, r4, fp, r2"

  /// A8.8.182 SMLAWB, SMLAWT
  [<TestMethod>]
  member _.``A8.8.182 SMLAWT``() =
    testDisasm "e12032c1" "smlawt r0, r1, r2, r3"
    testDisasm "e12129c4" "smlawt r1, r4, sb, r2"
    testDisasm "e1212ac4" "smlawt r1, r4, sl, r2"
    testDisasm "e1212bc4" "smlawt r1, r4, fp, r2"

  /// A8.8.183 SMLSD
  [<TestMethod>]
  member _.``A8.8.183 SMLSD``() =
    testDisasm "e7003251" "smlsd r0, r1, r2, r3"
    testDisasm "e7012954" "smlsd r1, r4, sb, r2"
    testDisasm "e7012a54" "smlsd r1, r4, sl, r2"
    testDisasm "e7012b54" "smlsd r1, r4, fp, r2"

  /// A8.8.184 SMLSLD
  [<TestMethod>]
  member _.``A8.8.184 SMLSLD``() =
    testDisasm "e7410352" "smlsld r0, r1, r2, r3"
    testDisasm "e7412954" "smlsld r2, r1, r4, sb"
    testDisasm "e7412a54" "smlsld r2, r1, r4, sl"
    testDisasm "e7412b54" "smlsld r2, r1, r4, fp"

  /// A8.8.185 SMMLA
  [<TestMethod>]
  member _.``A8.8.185 SMMLA``() =
    testDisasm "e7503211" "smmla r0, r1, r2, r3"
    testDisasm "e7512914" "smmla r1, r4, sb, r2"
    testDisasm "e7512a14" "smmla r1, r4, sl, r2"
    testDisasm "e7512b14" "smmla r1, r4, fp, r2"

  /// A8.8.186 SMMLS
  [<TestMethod>]
  member _.``A8.8.186 SMMLS``() =
    testDisasm "e75032d1" "smmls r0, r1, r2, r3"
    testDisasm "e75129d4" "smmls r1, r4, sb, r2"
    testDisasm "e7512ad4" "smmls r1, r4, sl, r2"
    testDisasm "e7512bd4" "smmls r1, r4, fp, r2"

  /// A8.8.187 SMMUL
  [<TestMethod>]
  member _.``A8.8.187 SMMUL``() =
    testDisasm "e750f211" "smmul r0, r1, r2"
    testDisasm "e751f914" "smmul r1, r4, sb"
    testDisasm "e751fa14" "smmul r1, r4, sl"
    testDisasm "e751fb14" "smmul r1, r4, fp"

  /// A8.8.188 SMUAD
  [<TestMethod>]
  member _.``A8.8.188 SMUAD``() =
    testDisasm "e700f211" "smuad r0, r1, r2"
    testDisasm "e701f914" "smuad r1, r4, sb"
    testDisasm "e701fa14" "smuad r1, r4, sl"
    testDisasm "e701fb14" "smuad r1, r4, fp"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULBB``() =
    testDisasm "e1600281" "smulbb r0, r1, r2"
    testDisasm "e1610984" "smulbb r1, r4, sb"
    testDisasm "e1610a84" "smulbb r1, r4, sl"
    testDisasm "e1610b84" "smulbb r1, r4, fp"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULBT``() =
    testDisasm "e16002c1" "smulbt r0, r1, r2"
    testDisasm "e16109c4" "smulbt r1, r4, sb"
    testDisasm "e1610ac4" "smulbt r1, r4, sl"
    testDisasm "e1610bc4" "smulbt r1, r4, fp"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULTB``() =
    testDisasm "e16002a1" "smultb r0, r1, r2"
    testDisasm "e16109a4" "smultb r1, r4, sb"
    testDisasm "e1610aa4" "smultb r1, r4, sl"
    testDisasm "e1610ba4" "smultb r1, r4, fp"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULTT``() =
    testDisasm "e16002e1" "smultt r0, r1, r2"
    testDisasm "e16109e4" "smultt r1, r4, sb"
    testDisasm "e1610ae4" "smultt r1, r4, sl"
    testDisasm "e1610be4" "smultt r1, r4, fp"

  /// A8.8.19 BFC
  [<TestMethod>]
  member _.``A8.8.19 BFC``() =
    testDisasm "e7c7019f" "bfc r0, #0x3, #0x5"
    testDisasm "e7c1d01f" "bfc sp, #0x0, #0x2"
    testDisasm "17c1201f" "bfcne r2, #0x0, #0x2"
    testDisasm "17c1d01f" "bfcne sp, #0x0, #0x2"

  /// A8.8.190 SMULL
  [<TestMethod>]
  member _.``A8.8.190 SMULL``() =
    testDisasm "e0c10392" "smull r0, r1, r2, r3"
    testDisasm "e0d10291" "smulls r0, r1, r1, r2"
    testDisasm "e0c12994" "smull r2, r1, r4, sb"
    testDisasm "e0c12a94" "smull r2, r1, r4, sl"

  /// A8.8.191 SMULWB, SMULWT
  [<TestMethod>]
  member _.``A8.8.191 SMULWB``() =
    testDisasm "e12002a1" "smulwb r0, r1, r2"
    testDisasm "e12109a4" "smulwb r1, r4, sb"
    testDisasm "e1210aa4" "smulwb r1, r4, sl"
    testDisasm "e1210ba4" "smulwb r1, r4, fp"

  /// A8.8.191 SMULWB, SMULWT
  [<TestMethod>]
  member _.``A8.8.191 SMULWT``() =
    testDisasm "e12002e1" "smulwt r0, r1, r2"
    testDisasm "e12109e4" "smulwt r1, r4, sb"
    testDisasm "e1210ae4" "smulwt r1, r4, sl"
    testDisasm "e1210be4" "smulwt r1, r4, fp"

  /// A8.8.192 SMUSD
  [<TestMethod>]
  member _.``A8.8.192 SMUSD``() =
    testDisasm "e700f251" "smusd r0, r1, r2"
    testDisasm "e701f954" "smusd r1, r4, sb"
    testDisasm "e701fa54" "smusd r1, r4, sl"
    testDisasm "e701fb54" "smusd r1, r4, fp"

  /// A8.8.193 SRS
  [<TestMethod>]
  member _.``A8.8.193 SRS``() =
    testDisasm "f8cd0513" "srsia sp, #0x13"
    testDisasm "f8ed0513" "srsia sp!, #0x13"
    testDisasm "f84d0513" "srsda sp, #0x13"
    testDisasm "f96d0513" "srsdb sp!, #0x13"

  /// A8.8.194 SSAT
  [<TestMethod>]
  member _.``A8.8.194 SSAT``() =
    testDisasm "e6a70011" "ssat r0, #0x8, r1"
    testDisasm "e6af0091" "ssat r0, #0x10, r1, lsl #0x1"
    testDisasm "e6af02d1" "ssat r0, #0x10, r1, asr #0x5"
    testDisasm "e6a1d014" "ssat sp, #0x2, r4"

  /// A8.8.195 SSAT16
  [<TestMethod>]
  member _.``A8.8.195 SSAT16``() =
    testDisasm "e6a70f31" "ssat16 r0, #0x8, r1"

  /// A8.8.196 SSAX
  [<TestMethod>]
  member _.``A8.8.196 SSAX``() =
    testDisasm "e6110f52" "ssax r0, r1, r2"

  /// A8.8.197 SSUB16
  [<TestMethod>]
  member _.``A8.8.197 SSUB16``() =
    testDisasm "e6110f72" "ssub16 r0, r1, r2"

  /// A8.8.198 SSUB8
  [<TestMethod>]
  member _.``A8.8.198 SSUB8``() =
    testDisasm "e6110ff2" "ssub8 r0, r1, r2"

  /// A8.8.199 STC, STC2
  [<TestMethod>]
  member _.``A8.8.199 STC2``() =
    testDisasm "fd815302" "stc2 p3, c5, [r1, #0x8]"

  /// A8.8.20 BFI
  [<TestMethod>]
  member _.``A8.8.20 BFI``() =
    testDisasm "e7c70191" "bfi r0, r1, #0x3, #0x5"
    testDisasm "e7c1d014" "bfi sp, r4, #0x0, #0x2"
    testDisasm "17c12014" "bfine r2, r4, #0x0, #0x2"
    testDisasm "17c1d014" "bfine sp, r4, #0x0, #0x2"

  /// A8.8.200 STM (STMIA, STMEA)
  [<TestMethod>]
  member _.``A8.8.200 STM``() =
    testDisasm "e881000c" "stm r1, {r2, r3}"
    testDisasm "e8a1000c" "stm r1!, {r2, r3}"
    testDisasm "e8812004" "stm r1, {r2, sp}"
    testDisasm "e8812000" "stm r1, {sp}"

  /// A8.8.201 STMDA (STMED)
  [<TestMethod>]
  member _.``A8.8.201 STMDA``() =
    testDisasm "e801000c" "stmda r1, {r2, r3}"
    testDisasm "e8012004" "stmda r1, {r2, sp}"
    testDisasm "e8012000" "stmda r1, {sp}"
    testDisasm "e801200f" "stmda r1, {r0, r1, r2, r3, sp}"

  /// A8.8.202 STMDB (STMFD)
  [<TestMethod>]
  member _.``A8.8.202 STMDB``() =
    testDisasm "e901000c" "stmdb r1, {r2, r3}"
    testDisasm "e921000c" "stmdb r1!, {r2, r3}"
    testDisasm "e9012004" "stmdb r1, {r2, sp}"
    testDisasm "e9012000" "stmdb r1, {sp}"

  /// A8.8.203 STMIB (STMFA)
  [<TestMethod>]
  member _.``A8.8.203 STMIB``() =
    testDisasm "e981000c" "stmib r1, {r2, r3}"
    testDisasm "e9812004" "stmib r1, {r2, sp}"
    testDisasm "e9812000" "stmib r1, {sp}"
    testDisasm "e981200f" "stmib r1, {r0, r1, r2, r3, sp}"

  /// A8.8.204 STR (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.204 STR``() =
    testDisasm "e5810010" "str r0, [r1, #0x10]"
    testDisasm "e7810002" "str r0, [r1, r2]"
    testDisasm "e7810082" "str r0, [r1, r2, lsl #0x1]"
    testDisasm "e5810000" "str r0, [r1]"

  /// A8.8.207 STRB (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.207 STRB``() =
    testDisasm "e5c10003" "strb r0, [r1, #0x3]"
    testDisasm "e7c10002" "strb r0, [r1, r2]"
    testDisasm "e7c10082" "strb r0, [r1, r2, lsl #0x1]"
    testDisasm "e5c10000" "strb r0, [r1]"

  /// A8.8.21 BIC (immediate)
  [<TestMethod>]
  member _.``A8.8.21 BIC``() =
    testDisasm "e1c00002" "bic r0, r0, r2"
    testDisasm "e1d10002" "bics r0, r1, r2"
    testDisasm "e1c10082" "bic r0, r1, r2, lsl #0x1"
    testDisasm "e1c101a2" "bic r0, r1, r2, lsr #0x3"

  /// A8.8.210 STRBT
  [<TestMethod>]
  member _.``A8.8.210 STRBT``() =
    testDisasm "e4e10000" "strbt r0, [r1], #0x0"
    testDisasm "e461d004" "strbt sp, [r1], #-0x4"
    testDisasm "e4692004" "strbt r2, [sb], #-0x4"
    testDisasm "e469d004" "strbt sp, [sb], #-0x4"

  /// A8.8.211 STRD (immediate)
  [<TestMethod>]
  member _.``A8.8.211 STRD``() =
    testDisasm "e1c100f0" "strd r0, r1, [r1]"
    testDisasm "e00120f4" "strd r2, r3, [r1], -r4"
    testDisasm "e00920f4" "strd r2, r3, [sb], -r4"
    testDisasm "e00d20f4" "strd r2, r3, [sp], -r4"

  /// A8.8.213 STREX
  [<TestMethod>]
  member _.``A8.8.213 STREX``() =
    testDisasm "e1810f92" "strex r0, r2, [r1]"
    testDisasm "e181df94" "strex sp, r4, [r1]"
    testDisasm "e1892f94" "strex r2, r4, [sb]"
    testDisasm "e189df94" "strex sp, r4, [sb]"

  /// A8.8.214 STREXB
  [<TestMethod>]
  member _.``A8.8.214 STREXB``() =
    testDisasm "e1c10f92" "strexb r0, r2, [r1]"
    testDisasm "e1c1df94" "strexb sp, r4, [r1]"
    testDisasm "e1c92f94" "strexb r2, r4, [sb]"
    testDisasm "e1c9df94" "strexb sp, r4, [sb]"

  /// A8.8.215 STREXD
  [<TestMethod>]
  member _.``A8.8.215 STREXD``() =
    testDisasm "e1a10f92" "strexd r0, r2, r3, [r1]"

  /// A8.8.216 STREXH
  [<TestMethod>]
  member _.``A8.8.216 STREXH``() =
    testDisasm "e1e10f92" "strexh r0, r2, [r1]"
    testDisasm "e1e1df94" "strexh sp, r4, [r1]"
    testDisasm "e1e92f94" "strexh r2, r4, [sb]"
    testDisasm "e1e9df94" "strexh sp, r4, [sb]"

  /// A8.8.217 STRH (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.217 STRH``() =
    testDisasm "e1c101b0" "strh r0, [r1, #0x10]"
    testDisasm "e18100b2" "strh r0, [r1, r2]"
    testDisasm "e1c100b0" "strh r0, [r1]"
    testDisasm "e00120b4" "strh r2, [r1], -r4"

  /// A8.8.220 STRHT
  [<TestMethod>]
  member _.``A8.8.220 STRHT``() =
    testDisasm "e0e100b0" "strht r0, [r1], #0x0"
    testDisasm "e02120b4" "strht r2, [r1], -r4"
    testDisasm "e021d0b4" "strht sp, [r1], -r4"
    testDisasm "e02920b4" "strht r2, [sb], -r4"

  /// A8.8.221 STRT
  [<TestMethod>]
  member _.``A8.8.221 STRT``() =
    testDisasm "e4a10000" "strt r0, [r1], #0x0"
    testDisasm "e421d004" "strt sp, [r1], #-0x4"
    testDisasm "e421f004" "strt pc, [r1], #-0x4"
    testDisasm "e4292004" "strt r2, [sb], #-0x4"

  /// A8.8.222 SUB (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.222 SUB``() =
    testDisasm "e24dd008" "sub sp, sp, #0x8"
    testDisasm "e2400003" "sub r0, r0, #0x3"
    testDisasm "e0410002" "sub r0, r1, r2"
    testDisasm "e0510002" "subs r0, r1, r2"

  /// A8.8.228 SUBS PC, LR and related instructions
  [<TestMethod>]
  member _.``A8.8.228 SUBS``() =
    testDisasm "e0510002" "subs r0, r1, r2"
    testDisasm "e2510e3f" "subs r0, r1, #0x3f0"
    testDisasm "e0510312" "subs r0, r1, r2, lsl r3"
    testDisasm "e0510332" "subs r0, r1, r2, lsr r3"

  /// A8.8.229 SVC (previously SWI)
  [<TestMethod>]
  member _.``A8.8.229 SVC``() =
    testDisasm "ef012004" "svc #0x12004"
    testDisasm "1f012004" "svcne #0x12004"

  /// A8.8.230 SWP, SWPB
  [<TestMethod>]
  member _.``A8.8.230 SWP``() =
    testDisasm "e1020091" "swp r0, r1, [r2]"

  /// A8.8.230 SWP, SWPB
  [<TestMethod>]
  member _.``A8.8.230 SWPB``() =
    testDisasm "e1420091" "swpb r0, r1, [r2]"

  /// A8.8.231 SXTAB
  [<TestMethod>]
  member _.``A8.8.231 SXTAB``() =
    testDisasm "e6a10072" "sxtab r0, r1, r2"
    testDisasm "e6a12474" "sxtab r2, r1, r4, ror #0x8"
    testDisasm "e6a1d074" "sxtab sp, r1, r4"
    testDisasm "e6a1d474" "sxtab sp, r1, r4, ror #0x8"

  /// A8.8.232 SXTAB16
  [<TestMethod>]
  member _.``A8.8.232 SXTAB16``() =
    testDisasm "e6810072" "sxtab16 r0, r1, r2"
    testDisasm "e6812474" "sxtab16 r2, r1, r4, ror #0x8"
    testDisasm "e681d074" "sxtab16 sp, r1, r4"
    testDisasm "e681d474" "sxtab16 sp, r1, r4, ror #0x8"
