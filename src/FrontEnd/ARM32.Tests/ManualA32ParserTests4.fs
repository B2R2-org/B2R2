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
/// chapters describe, RFEIB to VJCVT in the order of their sections. Each
/// reads A32 words of the instruction and checks the text, and each word's
/// text is one binutils' objdump reads the word as too, so what is asserted
/// is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualA32ParserTests4() =
  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let isa = ISA(Architecture.ARMv7, Endian.Big)
    let parser = Parser(isa, false, BinReader.Init Endian.Big)
    let ins = (parser :> IInstructionParsable).Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// F5.1.159 RFE, RFEDA, RFEDB, RFEIA, RFEIB
  [<TestMethod>]
  member _.``F5.1.159 RFEIB``() =
    testDisasm "f9b10a00" "rfeib r1!"

  /// F5.1.16 ASRS (immediate)
  [<TestMethod>]
  member _.``F5.1.16 ASRS``() =
    testDisasm "e1b00842" "asrs r0, r2, #0x10"
    testDisasm "e1b00251" "asrs r0, r1, r2"
    testDisasm "e1b02954" "asrs r2, r4, sb"
    testDisasm "e1b02a54" "asrs r2, r4, sl"

  /// F5.1.162 RORS (immediate)
  [<TestMethod>]
  member _.``F5.1.162 RORS``() =
    testDisasm "e1b00862" "rors r0, r2, #0x10"
    testDisasm "e1b00271" "rors r0, r1, r2"
    testDisasm "e1b02974" "rors r2, r4, sb"
    testDisasm "e1b02a74" "rors r2, r4, sl"

  /// F5.1.165 RRXS
  [<TestMethod>]
  member _.``F5.1.165 RRXS``() =
    testDisasm "e1b00062" "rrxs r0, r2"
    testDisasm "e1b0206f" "rrxs r2, pc"
    testDisasm "e1b0d064" "rrxs sp, r4"
    testDisasm "e1b0d06f" "rrxs sp, pc"

  /// F5.1.166 RSB, RSBS (immediate)
  [<TestMethod>]
  member _.``F5.1.166 RSBS``() =
    testDisasm "e0710002" "rsbs r0, r1, r2"
    testDisasm "e0710312" "rsbs r0, r1, r2, lsl r3"
    testDisasm "e0710332" "rsbs r0, r1, r2, lsr r3"
    testDisasm "e0710352" "rsbs r0, r1, r2, asr r3"

  /// F5.1.169 RSC, RSCS (immediate)
  [<TestMethod>]
  member _.``F5.1.169 RSCS``() =
    testDisasm "e0f10002" "rscs r0, r1, r2"
    testDisasm "e0f10312" "rscs r0, r1, r2, lsl r3"
    testDisasm "e0f10332" "rscs r0, r1, r2, lsr r3"
    testDisasm "e0f10352" "rscs r0, r1, r2, asr r3"

  /// F5.1.175 SB
  [<TestMethod>]
  member _.``F5.1.175 SB``() =
    testDisasm "e0d10002" "sbcs r0, r1, r2"
    testDisasm "e0d10312" "sbcs r0, r1, r2, lsl r3"
    testDisasm "e0d10332" "sbcs r0, r1, r2, lsr r3"
    testDisasm "e0d10352" "sbcs r0, r1, r2, asr r3"

  /// F5.1.176 SBC, SBCS (immediate)
  [<TestMethod>]
  member _.``F5.1.176 SBCS``() =
    testDisasm "e0d10002" "sbcs r0, r1, r2"
    testDisasm "e0d10312" "sbcs r0, r1, r2, lsl r3"
    testDisasm "e0d10332" "sbcs r0, r1, r2, lsr r3"
    testDisasm "e0d10352" "sbcs r0, r1, r2, asr r3"

  /// F5.1.183 SETPAN
  [<TestMethod>]
  member _.``F5.1.183 SETPAN``() =
    testDisasm "f1100000" "setpan #0x0"

  /// F5.1.185 SEVL
  [<TestMethod>]
  member _.``F5.1.185 SEVL``() =
    testDisasm "e320f005" "sevl"

  /// F5.1.194 SMLAD, SMLADX
  [<TestMethod>]
  member _.``F5.1.194 SMLADX``() =
    testDisasm "e7003231" "smladx r0, r1, r2, r3"
    testDisasm "e7012934" "smladx r1, r4, sb, r2"
    testDisasm "e7012a34" "smladx r1, r4, sl, r2"
    testDisasm "e7012b34" "smladx r1, r4, fp, r2"

  /// F5.1.195 SMLAL, SMLALS
  [<TestMethod>]
  member _.``F5.1.195 SMLALS``() =
    testDisasm "e0f10291" "smlals r0, r1, r1, r2"
    testDisasm "e0f12994" "smlals r2, r1, r4, sb"
    testDisasm "e0f12a94" "smlals r2, r1, r4, sl"
    testDisasm "e0f12b94" "smlals r2, r1, r4, fp"

  /// F5.1.197 SMLALD, SMLALDX
  [<TestMethod>]
  member _.``F5.1.197 SMLALDX``() =
    testDisasm "e7410231" "smlaldx r0, r1, r1, r2"
    testDisasm "e7412934" "smlaldx r2, r1, r4, sb"
    testDisasm "e7412a34" "smlaldx r2, r1, r4, sl"
    testDisasm "e7412b34" "smlaldx r2, r1, r4, fp"

  /// F5.1.199 SMLSD, SMLSDX
  [<TestMethod>]
  member _.``F5.1.199 SMLSDX``() =
    testDisasm "e7003271" "smlsdx r0, r1, r2, r3"
    testDisasm "e7012974" "smlsdx r1, r4, sb, r2"
    testDisasm "e7012a74" "smlsdx r1, r4, sl, r2"
    testDisasm "e7012b74" "smlsdx r1, r4, fp, r2"

  /// F5.1.200 SMLSLD, SMLSLDX
  [<TestMethod>]
  member _.``F5.1.200 SMLSLDX``() =
    testDisasm "e7410271" "smlsldx r0, r1, r1, r2"
    testDisasm "e7412974" "smlsldx r2, r1, r4, sb"
    testDisasm "e7412a74" "smlsldx r2, r1, r4, sl"
    testDisasm "e7412b74" "smlsldx r2, r1, r4, fp"

  /// F5.1.201 SMMLA, SMMLAR
  [<TestMethod>]
  member _.``F5.1.201 SMMLAR``() =
    testDisasm "e7503231" "smmlar r0, r1, r2, r3"
    testDisasm "e7512934" "smmlar r1, r4, sb, r2"
    testDisasm "e7512a34" "smmlar r1, r4, sl, r2"
    testDisasm "e7512b34" "smmlar r1, r4, fp, r2"

  /// F5.1.202 SMMLS, SMMLSR
  [<TestMethod>]
  member _.``F5.1.202 SMMLSR``() =
    testDisasm "e75032f1" "smmlsr r0, r1, r2, r3"
    testDisasm "e75129f4" "smmlsr r1, r4, sb, r2"
    testDisasm "e7512af4" "smmlsr r1, r4, sl, r2"
    testDisasm "e7512bf4" "smmlsr r1, r4, fp, r2"

  /// F5.1.203 SMMUL, SMMULR
  [<TestMethod>]
  member _.``F5.1.203 SMMULR``() =
    testDisasm "e750f231" "smmulr r0, r1, r2"
    testDisasm "e751f934" "smmulr r1, r4, sb"
    testDisasm "e751fa34" "smmulr r1, r4, sl"
    testDisasm "e751fb34" "smmulr r1, r4, fp"

  /// F5.1.204 SMUAD, SMUADX
  [<TestMethod>]
  member _.``F5.1.204 SMUADX``() =
    testDisasm "e700f231" "smuadx r0, r1, r2"
    testDisasm "e701f934" "smuadx r1, r4, sb"
    testDisasm "e701fa34" "smuadx r1, r4, sl"
    testDisasm "e701fb34" "smuadx r1, r4, fp"

  /// F5.1.206 SMULL, SMULLS
  [<TestMethod>]
  member _.``F5.1.206 SMULLS``() =
    testDisasm "e0d10291" "smulls r0, r1, r1, r2"
    testDisasm "e0d12994" "smulls r2, r1, r4, sb"
    testDisasm "e0d12a94" "smulls r2, r1, r4, sl"
    testDisasm "e0d12b94" "smulls r2, r1, r4, fp"

  /// F5.1.208 SMUSD, SMUSDX
  [<TestMethod>]
  member _.``F5.1.208 SMUSDX``() =
    testDisasm "e700f271" "smusdx r0, r1, r2"
    testDisasm "e701f974" "smusdx r1, r4, sb"
    testDisasm "e701fa74" "smusdx r1, r4, sl"
    testDisasm "e701fb74" "smusdx r1, r4, fp"

  /// F5.1.209 SRS, SRSDA, SRSDB, SRSIA, SRSIB
  [<TestMethod>]
  member _.``F5.1.209 SRSDA``() =
    testDisasm "f84d0513" "srsda sp, #0x13"

  /// F5.1.209 SRS, SRSDA, SRSDB, SRSIA, SRSIB
  [<TestMethod>]
  member _.``F5.1.209 SRSDB``() =
    testDisasm "f96d0513" "srsdb sp!, #0x13"

  /// F5.1.209 SRS, SRSDA, SRSDB, SRSIA, SRSIB
  [<TestMethod>]
  member _.``F5.1.209 SRSIA``() =
    testDisasm "f8cd0513" "srsia sp, #0x13"
    testDisasm "f8ed0513" "srsia sp!, #0x13"

  /// F5.1.209 SRS, SRSDA, SRSDB, SRSIA, SRSIB
  [<TestMethod>]
  member _.``F5.1.209 SRSIB``() =
    testDisasm "f9cd0513" "srsib sp, #0x13"

  /// F5.1.21 BIC, BICS (immediate)
  [<TestMethod>]
  member _.``F5.1.21 BICS``() =
    testDisasm "e1d10002" "bics r0, r1, r2"
    testDisasm "e1d10312" "bics r0, r1, r2, lsl r3"
    testDisasm "e1d10332" "bics r0, r1, r2, lsr r3"
    testDisasm "e1d10352" "bics r0, r1, r2, asr r3"

  /// F5.1.213 SSBB
  [<TestMethod>]
  member _.``F5.1.213 SSBB``() =
    testDisasm "f57ff040" "ssbb"

  /// F5.1.217 STL
  [<TestMethod>]
  member _.``F5.1.217 STL``() =
    testDisasm "e181fc90" "stl r0, [r1]"

  /// F5.1.218 STLB
  [<TestMethod>]
  member _.``F5.1.218 STLB``() =
    testDisasm "e1c1fc90" "stlb r0, [r1]"

  /// F5.1.219 STLEX
  [<TestMethod>]
  member _.``F5.1.219 STLEX``() =
    testDisasm "e1810e92" "stlex r0, r2, [r1]"
    testDisasm "e181de94" "stlex sp, r4, [r1]"
    testDisasm "e1892e94" "stlex r2, r4, [sb]"
    testDisasm "e189de94" "stlex sp, r4, [sb]"

  /// F5.1.220 STLEXB
  [<TestMethod>]
  member _.``F5.1.220 STLEXB``() =
    testDisasm "e1c10e92" "stlexb r0, r2, [r1]"
    testDisasm "e1c1de94" "stlexb sp, r4, [r1]"
    testDisasm "e1c92e94" "stlexb r2, r4, [sb]"
    testDisasm "e1c9de94" "stlexb sp, r4, [sb]"

  /// F5.1.221 STLEXD
  [<TestMethod>]
  member _.``F5.1.221 STLEXD``() =
    testDisasm "e1a10e92" "stlexd r0, r2, r3, [r1]"
    testDisasm "e1a1de94" "stlexd sp, r4, r5, [r1]"
    testDisasm "e1a92e94" "stlexd r2, r4, r5, [sb]"
    testDisasm "e1a9de94" "stlexd sp, r4, r5, [sb]"

  /// F5.1.222 STLEXH
  [<TestMethod>]
  member _.``F5.1.222 STLEXH``() =
    testDisasm "e1e10e92" "stlexh r0, r2, [r1]"
    testDisasm "e1e1de94" "stlexh sp, r4, [r1]"
    testDisasm "e1e92e94" "stlexh r2, r4, [sb]"
    testDisasm "e1e9de94" "stlexh sp, r4, [sb]"

  /// F5.1.223 STLH
  [<TestMethod>]
  member _.``F5.1.223 STLH``() =
    testDisasm "e1e1fc90" "stlh r0, [r1]"

  /// F5.1.224 STM, STMIA, STMEA
  [<TestMethod>]
  member _.``F5.1.224 STMEA``() =
    testDisasm "e881000c" "stm r1, {r2, r3}"
    testDisasm "e8a1000c" "stm r1!, {r2, r3}"
    testDisasm "e8812004" "stm r1, {r2, sp}"
    testDisasm "e8812000" "stm r1, {sp}"

  /// F5.1.224 STM, STMIA, STMEA
  [<TestMethod>]
  member _.``F5.1.224 STMIA``() =
    testDisasm "e881000c" "stm r1, {r2, r3}"
    testDisasm "e8a1000c" "stm r1!, {r2, r3}"
    testDisasm "e8812004" "stm r1, {r2, sp}"
    testDisasm "e8812000" "stm r1, {sp}"

  /// F5.1.226 STMDA, STMED
  [<TestMethod>]
  member _.``F5.1.226 STMED``() =
    testDisasm "e801000c" "stmda r1, {r2, r3}"
    testDisasm "e8012004" "stmda r1, {r2, sp}"
    testDisasm "e8012000" "stmda r1, {sp}"
    testDisasm "e801200f" "stmda r1, {r0, r1, r2, r3, sp}"

  /// F5.1.227 STMDB, STMFD
  [<TestMethod>]
  member _.``F5.1.227 STMFD``() =
    testDisasm "e901000c" "stmdb r1, {r2, r3}"
    testDisasm "e92d000c" "push {r2, r3}"
    testDisasm "e921000c" "stmdb r1!, {r2, r3}"
    testDisasm "e52d2004" "push {r2}"

  /// F5.1.228 STMIB, STMFA
  [<TestMethod>]
  member _.``F5.1.228 STMFA``() =
    testDisasm "e981000c" "stmib r1, {r2, r3}"
    testDisasm "e9812004" "stmib r1, {r2, sp}"
    testDisasm "e9812000" "stmib r1, {sp}"
    testDisasm "e981200f" "stmib r1, {r0, r1, r2, r3, sp}"

  /// F5.1.278 UMLAL, UMLALS
  [<TestMethod>]
  member _.``F5.1.278 UMLALS``() =
    testDisasm "e0b10291" "umlals r0, r1, r1, r2"
    testDisasm "e0b12994" "umlals r2, r1, r4, sb"
    testDisasm "e0b12a94" "umlals r2, r1, r4, sl"
    testDisasm "e0b12b94" "umlals r2, r1, r4, fp"

  /// F5.1.279 UMULL, UMULLS
  [<TestMethod>]
  member _.``F5.1.279 UMULLS``() =
    testDisasm "e0910291" "umulls r0, r1, r1, r2"
    testDisasm "e0912994" "umulls r2, r1, r4, sb"
    testDisasm "e0912a94" "umulls r2, r1, r4, sl"
    testDisasm "e0912b94" "umulls r2, r1, r4, fp"

  /// F5.1.38 CPS, CPSID, CPSIE
  [<TestMethod>]
  member _.``F5.1.38 CPSID``() =
    testDisasm "f10e00d3" "cpsid if, #0x13"

  /// F5.1.38 CPS, CPSID, CPSIE
  [<TestMethod>]
  member _.``F5.1.38 CPSIE``() =
    testDisasm "f1080080" "cpsie i"

  /// F5.1.39 CRC32
  [<TestMethod>]
  member _.``F5.1.39 CRC32``() =
    testDisasm "e1020043" "crc32b r0, r2, r3"
    testDisasm "e1210042" "crc32h r0, r1, r2"
    testDisasm "e1410042" "crc32w r0, r1, r2"
    testDisasm "e101d044" "crc32b sp, r1, r4"

  /// F5.1.4 ADD, ADDS (immediate)
  [<TestMethod>]
  member _.``F5.1.4 ADDS``() =
    testDisasm "e0911002" "adds r1, r1, r2"
    testDisasm "e0910312" "adds r0, r1, r2, lsl r3"
    testDisasm "e0910332" "adds r0, r1, r2, lsr r3"
    testDisasm "e0910352" "adds r0, r1, r2, asr r3"

  /// F5.1.40 CRC32C
  [<TestMethod>]
  member _.``F5.1.40 CRC32C``() =
    testDisasm "e1420243" "crc32cw r0, r2, r3"
    testDisasm "e1010242" "crc32cb r0, r1, r2"
    testDisasm "e1210242" "crc32ch r0, r1, r2"
    testDisasm "e101d244" "crc32cb sp, r1, r4"

  /// F5.1.48 EOR, EORS (immediate)
  [<TestMethod>]
  member _.``F5.1.48 EORS``() =
    testDisasm "e0310002" "eors r0, r1, r2"
    testDisasm "e0310312" "eors r0, r1, r2, lsl r3"
    testDisasm "e0310332" "eors r0, r1, r2, lsr r3"
    testDisasm "e0310352" "eors r0, r1, r2, asr r3"

  /// F5.1.52 ESB
  [<TestMethod>]
  member _.``F5.1.52 ESB``() =
    testDisasm "e320f010" "esb"

  /// F5.1.53 HLT
  [<TestMethod>]
  member _.``F5.1.53 HLT``() =
    testDisasm "e1000070" "hlt #0x0"

  /// F5.1.57 LDA
  [<TestMethod>]
  member _.``F5.1.57 LDA``() =
    testDisasm "e1910c9f" "lda r0, [r1]"

  /// F5.1.58 LDAB
  [<TestMethod>]
  member _.``F5.1.58 LDAB``() =
    testDisasm "e1d10c9f" "ldab r0, [r1]"

  /// F5.1.59 LDAEX
  [<TestMethod>]
  member _.``F5.1.59 LDAEX``() =
    testDisasm "e1910e9f" "ldaex r0, [r1]"

  /// F5.1.60 LDAEXB
  [<TestMethod>]
  member _.``F5.1.60 LDAEXB``() =
    testDisasm "e1d10e9f" "ldaexb r0, [r1]"

  /// F5.1.61 LDAEXD
  [<TestMethod>]
  member _.``F5.1.61 LDAEXD``() =
    testDisasm "e1b12e9f" "ldaexd r2, r3, [r1]"

  /// F5.1.62 LDAEXH
  [<TestMethod>]
  member _.``F5.1.62 LDAEXH``() =
    testDisasm "e1f10e9f" "ldaexh r0, [r1]"

  /// F5.1.63 LDAH
  [<TestMethod>]
  member _.``F5.1.63 LDAH``() =
    testDisasm "e1f10c9f" "ldah r0, [r1]"

  /// F6.1.1 AESD
  [<TestMethod>]
  member _.``F6.1.1 AESD``() =
    testDisasm "f3b00342" "aesd.8 q0, q1"

  /// F6.1.10 SHA1P
  [<TestMethod>]
  member _.``F6.1.10 SHA1P``() =
    testDisasm "f2120c44" "sha1p.32 q0, q1, q2"

  /// F6.1.11 SHA1SU0
  [<TestMethod>]
  member _.``F6.1.11 SHA1SU0``() =
    testDisasm "f2320c44" "sha1su0.32 q0, q1, q2"

  /// F6.1.112 VLDM, VLDMDB, VLDMIA
  [<TestMethod>]
  member _.``F6.1.112 VLDMDB``() =
    testDisasm "ed312a04" "vldmdb r1!, {s4, s5, s6, s7}"
    testDisasm "ed312a01" "vldmdb r1!, {s4}"
    ("vldmdb r1!, {s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, "
     + "s16, s17, s18}")
    |> testDisasm "ed312a0f"
    testDisasm "ed312b04" "vldmdb r1!, {d2, d3}"

  /// F6.1.112 VLDM, VLDMDB, VLDMIA
  [<TestMethod>]
  member _.``F6.1.112 VLDMIA``() =
    testDisasm "ec910b04" "vldmia r1, {d0, d1}"
    testDisasm "ecbd0b04" "vldmia sp!, {d0, d1}"
    testDisasm "ecb10b08" "vldmia r1!, {d0, d1, d2, d3}"
    testDisasm "ec912a04" "vldmia r1, {s4, s5, s6, s7}"

  /// F6.1.117 VMAXNM
  [<TestMethod>]
  member _.``F6.1.117 VMAXNM``() =
    testDisasm "fe800981" "vmaxnm.f16 s0, s1, s2"
    testDisasm "f3120f54" "vmaxnm.f16 q0, q1, q2"
    testDisasm "f3012f14" "vmaxnm.f32 d2, d1, d4"

  /// F6.1.12 SHA1SU1
  [<TestMethod>]
  member _.``F6.1.12 SHA1SU1``() =
    testDisasm "f3ba0382" "sha1su1.32 q0, q1"

  /// F6.1.120 VMINNM
  [<TestMethod>]
  member _.``F6.1.120 VMINNM``() =
    testDisasm "fe8009c1" "vminnm.f16 s0, s1, s2"
    testDisasm "f3320f54" "vminnm.f16 q0, q1, q2"
    testDisasm "f3212f14" "vminnm.f32 d2, d1, d4"

  /// F6.1.13 SHA256H
  [<TestMethod>]
  member _.``F6.1.13 SHA256H``() =
    testDisasm "f3020c44" "sha256h.32 q0, q1, q2"

  /// F6.1.131 VMMLA
  [<TestMethod>]
  member _.``F6.1.131 VMMLA``() =
    testDisasm "fc002c44" "vmmla.bf16 q1, q0, q2"

  /// F6.1.14 SHA256H2
  [<TestMethod>]
  member _.``F6.1.14 SHA256H2``() =
    testDisasm "f3120c44" "sha256h2.32 q0, q1, q2"

  /// F6.1.143 VMOVX
  [<TestMethod>]
  member _.``F6.1.143 VMOVX``() =
    testDisasm "feb00a60" "vmovx.f16 s0, s1"

  /// F6.1.15 SHA256SU0
  [<TestMethod>]
  member _.``F6.1.15 SHA256SU0``() =
    testDisasm "f3ba03c2" "sha256su0.32 q0, q1"

  /// F6.1.16 SHA256SU1
  [<TestMethod>]
  member _.``F6.1.16 SHA256SU1``() =
    testDisasm "f3220c44" "sha256su1.32 q0, q1, q2"

  /// F6.1.179 VQRDMLAH
  [<TestMethod>]
  member _.``F6.1.179 VQRDMLAH``() =
    testDisasm "f3110b12" "vqrdmlah.s16 d0, d1, d2"
    testDisasm "f2912e44" "vqrdmlah.s16 d2, d1, d4[0]"
    testDisasm "f3102b54" "vqrdmlah.s16 q1, q0, q2"
    testDisasm "f3902e44" "vqrdmlah.s16 q1, q0, d4[0]"

  /// F6.1.180 VQRDMLSH
  [<TestMethod>]
  member _.``F6.1.180 VQRDMLSH``() =
    testDisasm "f3220c54" "vqrdmlsh.s32 q0, q1, q2"
    testDisasm "f2912f44" "vqrdmlsh.s16 d2, d1, d4[0]"
    testDisasm "f3112c14" "vqrdmlsh.s16 d2, d1, d4"
    testDisasm "f3902f44" "vqrdmlsh.s16 q1, q0, d4[0]"

  /// F6.1.199 VRINTA (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.199 VRINTA``() =
    testDisasm "feb80960" "vrinta.f16 s0, s1"
    testDisasm "f3b60542" "vrinta.f16 q0, q1"

  /// F6.1.2 AESE
  [<TestMethod>]
  member _.``F6.1.2 AESE``() =
    testDisasm "f3b00302" "aese.8 q0, q1"

  /// F6.1.201 VRINTM (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.201 VRINTM``() =
    testDisasm "febb0960" "vrintm.f16 s0, s1"
    testDisasm "f3b606c2" "vrintm.f16 q0, q1"
    testDisasm "febb0b41" "vrintm.f64 d0, d1"

  /// F6.1.203 VRINTN (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.203 VRINTN``() =
    testDisasm "feb90960" "vrintn.f16 s0, s1"
    testDisasm "f3b60442" "vrintn.f16 q0, q1"
    testDisasm "feb92b44" "vrintn.f64 d2, d4"

  /// F6.1.205 VRINTP (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.205 VRINTP``() =
    testDisasm "feba0960" "vrintp.f16 s0, s1"
    testDisasm "f3b607c2" "vrintp.f16 q0, q1"
    testDisasm "f3ba0781" "vrintp.f32 d0, d1"

  /// F6.1.207 VRINTR
  [<TestMethod>]
  member _.``F6.1.207 VRINTR``() =
    testDisasm "eeb60960" "vrintr.f16 s0, s1"

  /// F6.1.208 VRINTX (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.208 VRINTX``() =
    testDisasm "eeb70960" "vrintx.f16 s0, s1"
    testDisasm "f3b604c2" "vrintx.f16 q0, q1"
    testDisasm "eeb70b41" "vrintx.f64 d0, d1"

  /// F6.1.210 VRINTZ (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.210 VRINTZ``() =
    testDisasm "eeb609e0" "vrintz.f16 s0, s1"
    testDisasm "f3b605c2" "vrintz.f16 q0, q1"

  /// F6.1.221 VSDOT (by element)
  [<TestMethod>]
  member _.``F6.1.221 VSDOT``() =
    testDisasm "fc210d02" "vsdot.s8 d0, d1, d2"
    testDisasm "fc202d44" "vsdot.s8 q1, q0, q2"
    testDisasm "fe212d04" "vsdot.s8 d2, d1, d4[0]"
    testDisasm "fe202d44" "vsdot.s8 q1, q0, d4[0]"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELEQ``() =
    testDisasm "fe000981" "vseleq.f16 s0, s1, s2"
    testDisasm "fe012b04" "vseleq.f64 d2, d1, d4"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELGE``() =
    testDisasm "fe200981" "vselge.f16 s0, s1, s2"
    testDisasm "fe210b02" "vselge.f64 d0, d1, d2"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELGT``() =
    testDisasm "fe300981" "vselgt.f16 s0, s1, s2"
    testDisasm "fe312b04" "vselgt.f64 d2, d1, d4"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELVS``() =
    testDisasm "fe100981" "vselvs.f16 s0, s1, s2"
    testDisasm "fe110b02" "vselvs.f64 d0, d1, d2"

  /// F6.1.232 VSMMLA
  [<TestMethod>]
  member _.``F6.1.232 VSMMLA``() =
    testDisasm "fc202c44" "vsmmla.s8 q1, q0, q2"

  /// F6.1.244 VSTM, VSTMDB, VSTMIA
  [<TestMethod>]
  member _.``F6.1.244 VSTMDB``() =
    testDisasm "ed2d0b04" "vstmdb sp!, {d0, d1}"
    testDisasm "ed2d0a04" "vstmdb sp!, {s0, s1, s2, s3}"
    testDisasm "ed212a04" "vstmdb r1!, {s4, s5, s6, s7}"
    testDisasm "ed212a01" "vstmdb r1!, {s4}"

  /// F6.1.244 VSTM, VSTMDB, VSTMIA
  [<TestMethod>]
  member _.``F6.1.244 VSTMIA``() =
    testDisasm "ec810b04" "vstmia r1, {d0, d1}"
    testDisasm "ec810a04" "vstmia r1, {s0, s1, s2, s3}"
    testDisasm "ec812a01" "vstmia r1, {s4}"
    ("vstmia r1, {s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, "
     + "s16, s17, s18}")
    |> testDisasm "ec812a0f"

  /// F6.1.251 VSUDOT (by element)
  [<TestMethod>]
  member _.``F6.1.251 VSUDOT``() =
    testDisasm "fe812d14" "vsudot.u8 d2, d1, d4[0]"
    testDisasm "fe802d54" "vsudot.u8 q1, q0, d4[0]"

  /// F6.1.256 VUDOT (by element)
  [<TestMethod>]
  member _.``F6.1.256 VUDOT``() =
    testDisasm "fe220d74" "vudot.u8 q0, q1, d4[1]"
    testDisasm "fc212d14" "vudot.u8 d2, d1, d4"
    testDisasm "fc202d54" "vudot.u8 q1, q0, q2"
    testDisasm "fe212d14" "vudot.u8 d2, d1, d4[0]"

  /// F6.1.258 VUMMLA
  [<TestMethod>]
  member _.``F6.1.258 VUMMLA``() =
    testDisasm "fc202c54" "vummla.u8 q1, q0, q2"

  /// F6.1.259 VUSDOT (by element)
  [<TestMethod>]
  member _.``F6.1.259 VUSDOT``() =
    testDisasm "fca12d04" "vusdot.s8 d2, d1, d4"
    testDisasm "fca02d44" "vusdot.s8 q1, q0, q2"
    testDisasm "fe812d04" "vusdot.s8 d2, d1, d4[0]"
    testDisasm "fe802d44" "vusdot.s8 q1, q0, d4[0]"

  /// F6.1.261 VUSMMLA
  [<TestMethod>]
  member _.``F6.1.261 VUSMMLA``() =
    testDisasm "fca02c44" "vusmmla.s8 q1, q0, q2"

  /// F6.1.3 AESIMC
  [<TestMethod>]
  member _.``F6.1.3 AESIMC``() =
    testDisasm "f3b003c2" "aesimc.8 q0, q1"

  /// F6.1.39 VCADD
  [<TestMethod>]
  member _.``F6.1.39 VCADD``() =
    testDisasm "fc910802" "vcadd.f32 d0, d1, d2, #0x5a"
    testDisasm "fc802844" "vcadd.f16 q1, q0, q2, #0x5a"

  /// F6.1.4 AESMC
  [<TestMethod>]
  member _.``F6.1.4 AESMC``() =
    testDisasm "f3b00382" "aesmc.8 q0, q1"

  /// F6.1.52 VCMLA
  [<TestMethod>]
  member _.``F6.1.52 VCMLA``() =
    testDisasm "fc310802" "vcmla.f32 d0, d1, d2, #0x0"
    testDisasm "fc202844" "vcmla.f16 q1, q0, q2, #0x0"
    testDisasm "fe012804" "vcmla.f16 d2, d1, d4[0], #0x0"
    testDisasm "fe002844" "vcmla.f16 q1, q0, d4[0], #0x0"

  /// F6.1.6 FSTMDBX, FSTMIAX
  [<TestMethod>]
  member _.``F6.1.6 FSTMDBX``() =
    testDisasm "ed212b0f" "fstmdbx r1!, {d2, d3, d4, d5, d6, d7, d8}"
    testDisasm "ed292b0f" "fstmdbx sb!, {d2, d3, d4, d5, d6, d7, d8}"
    testDisasm "ed2d2b0f" "fstmdbx sp!, {d2, d3, d4, d5, d6, d7, d8}"
    testDisasm "ed212b11" "fstmdbx r1!, {d2, d3, d4, d5, d6, d7, d8, d9}"

  /// F6.1.6 FSTMDBX, FSTMIAX
  [<TestMethod>]
  member _.``F6.1.6 FSTMIAX``() =
    testDisasm "ec812b0f" "fstmiax r1, {d2, d3, d4, d5, d6, d7, d8}"
    testDisasm "ec892b0f" "fstmiax sb, {d2, d3, d4, d5, d6, d7, d8}"
    testDisasm "ec8d2b0f" "fstmiax sp, {d2, d3, d4, d5, d6, d7, d8}"
    testDisasm "ec8f2b0f" "fstmiax pc, {d2, d3, d4, d5, d6, d7, d8}"

  /// F6.1.65 VCVTA (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.65 VCVTA``() =
    testDisasm "febc09e0" "vcvta.s32.f16 s0, s1"
    testDisasm "f3b70042" "vcvta.s16.f16 q0, q1"

  /// F6.1.69 VCVTM (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.69 VCVTM``() =
    testDisasm "febf09e0" "vcvtm.s32.f16 s0, s1"
    testDisasm "f3b70342" "vcvtm.s16.f16 q0, q1"
    testDisasm "febf0b41" "vcvtm.u32.f64 s0, d1"
    testDisasm "febf2944" "vcvtm.u32.f16 s4, s8"

  /// F6.1.7 SHA1C
  [<TestMethod>]
  member _.``F6.1.7 SHA1C``() =
    testDisasm "f2020c44" "sha1c.32 q0, q1, q2"

  /// F6.1.71 VCVTN (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.71 VCVTN``() =
    testDisasm "febd09e0" "vcvtn.s32.f16 s0, s1"
    testDisasm "f3b70142" "vcvtn.s16.f16 q0, q1"
    testDisasm "f3bb0101" "vcvtn.s32.f32 d0, d1"
    testDisasm "febd2944" "vcvtn.u32.f16 s4, s8"

  /// F6.1.73 VCVTP (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.73 VCVTP``() =
    testDisasm "febe09e0" "vcvtp.s32.f16 s0, s1"
    testDisasm "f3b70242" "vcvtp.s16.f16 q0, q1"
    testDisasm "f3bb02c2" "vcvtp.u32.f32 q0, q1"

  /// F6.1.79 VDOT (vector)
  [<TestMethod>]
  member _.``F6.1.79 VDOT``() =
    testDisasm "fc012d04" "vdot.bf16 d2, d1, d4"
    testDisasm "fc002d44" "vdot.bf16 q1, q0, q2"
    testDisasm "fe012d04" "vdot.bf16 d2, d1, d4[0]"
    testDisasm "fe002d44" "vdot.bf16 q1, q0, d4[0]"

  /// F6.1.8 SHA1H
  [<TestMethod>]
  member _.``F6.1.8 SHA1H``() =
    testDisasm "f3b902c2" "sha1h.32 q0, q1"

  /// F6.1.87 VFMAB, VFMAT (BFloat16, vector)
  [<TestMethod>]
  member _.``F6.1.87 VFMAB``() =
    testDisasm "fc302814" "vfmab.bf16 q1, q0, q2"
    testDisasm "fe302814" "vfmab.bf16 q1, q0, d4[0]"

  /// F6.1.87 VFMAB, VFMAT (BFloat16, vector)
  [<TestMethod>]
  member _.``F6.1.87 VFMAT``() =
    testDisasm "fc302854" "vfmat.bf16 q1, q0, q2"
    testDisasm "fe302854" "vfmat.bf16 q1, q0, d4[0]"

  /// F6.1.89 VFMAL (vector)
  [<TestMethod>]
  member _.``F6.1.89 VFMAL``() =
    testDisasm "fc210831" "vfmal.f16 d0, s2, s3"
    testDisasm "fc212854" "vfmal.f16 q1, d1, d4"
    testDisasm "fe012814" "vfmal.f16 d2, s2, s8[0]"
    testDisasm "fe012854" "vfmal.f16 q1, d1, d4[0]"

  /// F6.1.9 SHA1M
  [<TestMethod>]
  member _.``F6.1.9 SHA1M``() =
    testDisasm "f2220c44" "sha1m.32 q0, q1, q2"

  /// F6.1.92 VFMSL (vector)
  [<TestMethod>]
  member _.``F6.1.92 VFMSL``() =
    testDisasm "fe12085b" "vfmsl.f16 q0, d2, d3[1]"
    testDisasm "fca12814" "vfmsl.f16 d2, s2, s8"
    testDisasm "fca12854" "vfmsl.f16 q1, d1, d4"
    testDisasm "fe112814" "vfmsl.f16 d2, s2, s8[0]"

  /// F6.1.98 VINS
  [<TestMethod>]
  member _.``F6.1.98 VINS``() =
    testDisasm "feb00ae0" "vins.f16 s0, s1"

  /// F6.1.99 VJCVT
  [<TestMethod>]
  member _.``F6.1.99 VJCVT``() =
    testDisasm "eeb90bc1" "vjcvt.s32.f64 s0, d1"
