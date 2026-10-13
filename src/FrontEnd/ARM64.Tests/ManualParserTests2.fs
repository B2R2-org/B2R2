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

namespace B2R2.FrontEnd.ARM64.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM64

/// <summary>
/// One test for each instruction DDI0487F.c describes, LDUMINAB to STCLRLB in
/// the order of its sections. Each reads words of the instruction and checks
/// the text, and each word's text is one binutils' objdump reads the word as
/// too, so what is asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualParserTests2() =
  let parser =
    Parser(BinReader.Init Endian.Big) :> IInstructionParsable

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINAB``() =
    testDisasm "38a27020" "lduminab w2, w0, [x1]"
    testDisasm "38bf73ff" "lduminab wzr, wzr, [sp]"
    testDisasm "38aa73e9" "lduminab w10, w9, [sp]"
    testDisasm "38bf73c0" "lduminab wzr, w0, [x30]"

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINALB``() =
    testDisasm "38e27020" "lduminalb w2, w0, [x1]"
    testDisasm "38ff73ff" "lduminalb wzr, wzr, [sp]"
    testDisasm "38ea73e9" "lduminalb w10, w9, [sp]"
    testDisasm "38ff73c0" "lduminalb wzr, w0, [x30]"

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINB``() =
    testDisasm "38227020" "lduminb w2, w0, [x1]"
    testDisasm "3822703f" "stuminb w2, [x1]"
    testDisasm "383f73ff" "stuminb wzr, [sp]"
    testDisasm "382a73e9" "lduminb w10, w9, [sp]"

  /// C6.2.164 LDUMINB, LDUMINAB, LDUMINALB, LDUMINLB
  [<TestMethod>]
  member _.``C6.2.164 LDUMINLB``() =
    testDisasm "38627020" "lduminlb w2, w0, [x1]"
    testDisasm "3862703f" "stuminlb w2, [x1]"
    testDisasm "387f73ff" "stuminlb wzr, [sp]"
    testDisasm "386a73e9" "lduminlb w10, w9, [sp]"

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINAH``() =
    testDisasm "78a27020" "lduminah w2, w0, [x1]"
    testDisasm "78bf73ff" "lduminah wzr, wzr, [sp]"
    testDisasm "78aa73e9" "lduminah w10, w9, [sp]"
    testDisasm "78bf73c0" "lduminah wzr, w0, [x30]"

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINALH``() =
    testDisasm "78e27020" "lduminalh w2, w0, [x1]"
    testDisasm "78ff73ff" "lduminalh wzr, wzr, [sp]"
    testDisasm "78ea73e9" "lduminalh w10, w9, [sp]"
    testDisasm "78ff73c0" "lduminalh wzr, w0, [x30]"

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINH``() =
    testDisasm "78227020" "lduminh w2, w0, [x1]"
    testDisasm "7822703f" "stuminh w2, [x1]"
    testDisasm "783f73ff" "stuminh wzr, [sp]"
    testDisasm "782a73e9" "lduminh w10, w9, [sp]"

  /// C6.2.165 LDUMINH, LDUMINAH, LDUMINALH, LDUMINLH
  [<TestMethod>]
  member _.``C6.2.165 LDUMINLH``() =
    testDisasm "78627020" "lduminlh w2, w0, [x1]"
    testDisasm "7862703f" "stuminlh w2, [x1]"
    testDisasm "787f73ff" "stuminlh wzr, [sp]"
    testDisasm "786a73e9" "lduminlh w10, w9, [sp]"

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMIN``() =
    testDisasm "f8227020" "ldumin x2, x0, [x1]"
    testDisasm "f822703f" "stumin x2, [x1]"
    testDisasm "b8227020" "ldumin w2, w0, [x1]"
    testDisasm "b822703f" "stumin w2, [x1]"

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMINA``() =
    testDisasm "b8a27020" "ldumina w2, w0, [x1]"
    testDisasm "b8bf73ff" "ldumina wzr, wzr, [sp]"
    testDisasm "b8aa73e9" "ldumina w10, w9, [sp]"
    testDisasm "b8bf73c0" "ldumina wzr, w0, [x30]"

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMINAL``() =
    testDisasm "b8e27020" "lduminal w2, w0, [x1]"
    testDisasm "b8ff73ff" "lduminal wzr, wzr, [sp]"
    testDisasm "b8ea73e9" "lduminal w10, w9, [sp]"
    testDisasm "b8ff73c0" "lduminal wzr, w0, [x30]"

  /// C6.2.166 LDUMIN, LDUMINA, LDUMINAL, LDUMINL
  [<TestMethod>]
  member _.``C6.2.166 LDUMINL``() =
    testDisasm "b8627020" "lduminl w2, w0, [x1]"
    testDisasm "b862703f" "stuminl w2, [x1]"
    testDisasm "b87f73ff" "stuminl wzr, [sp]"
    testDisasm "b86a73e9" "lduminl w10, w9, [sp]"

  /// C6.2.167 LDUR
  [<TestMethod>]
  member _.``C6.2.167 LDUR``() =
    testDisasm "b8410020" "ldur w0, [x1, #0x10]"
    testDisasm "f8400020" "ldur x0, [x1]"
    testDisasm "f8410020" "ldur x0, [x1, #0x10]"
    testDisasm "b8400020" "ldur w0, [x1]"

  /// C6.2.168 LDURB
  [<TestMethod>]
  member _.``C6.2.168 LDURB``() =
    testDisasm "38410020" "ldurb w0, [x1, #0x10]"
    testDisasm "38400020" "ldurb w0, [x1]"
    testDisasm "385f03ff" "ldurb wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "384a03e9" "ldurb w9, [sp, #0xa0]"

  /// C6.2.169 LDURH
  [<TestMethod>]
  member _.``C6.2.169 LDURH``() =
    testDisasm "78410020" "ldurh w0, [x1, #0x10]"
    testDisasm "78400020" "ldurh w0, [x1]"
    testDisasm "785f03ff" "ldurh wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "784a03e9" "ldurh w9, [sp, #0xa0]"

  /// C6.2.170 LDURSB
  [<TestMethod>]
  member _.``C6.2.170 LDURSB``() =
    testDisasm "38c10020" "ldursb w0, [x1, #0x10]"
    testDisasm "38800020" "ldursb x0, [x1]"
    testDisasm "38810020" "ldursb x0, [x1, #0x10]"
    testDisasm "38c00020" "ldursb w0, [x1]"

  /// C6.2.171 LDURSH
  [<TestMethod>]
  member _.``C6.2.171 LDURSH``() =
    testDisasm "78c10020" "ldursh w0, [x1, #0x10]"
    testDisasm "78800020" "ldursh x0, [x1]"
    testDisasm "78810020" "ldursh x0, [x1, #0x10]"
    testDisasm "78c00020" "ldursh w0, [x1]"

  /// C6.2.172 LDURSW
  [<TestMethod>]
  member _.``C6.2.172 LDURSW``() =
    testDisasm "b8810020" "ldursw x0, [x1, #0x10]"
    testDisasm "b8800020" "ldursw x0, [x1]"
    testDisasm "b89f03ff" "ldursw xzr, [sp, #0xfffffffffffffff0]"
    testDisasm "b88a03e9" "ldursw x9, [sp, #0xa0]"

  /// C6.2.173 LDXP
  [<TestMethod>]
  member _.``C6.2.173 LDXP``() =
    testDisasm "887f0022" "ldxp w2, w0, [x1]"
    testDisasm "887f03ff" "ldxp wzr, w0, [sp]"
    testDisasm "886a03e9" "ldxp w9, w0, [sp]"
    testDisasm "88617c43" "ldxp w3, wzr, [x2]"

  /// C6.2.174 LDXR
  [<TestMethod>]
  member _.``C6.2.174 LDXR``() =
    testDisasm "885f7c20" "ldxr w0, [x1]"
    testDisasm "885f03ff" "ldxr wzr, [sp]"
    testDisasm "884a03e9" "ldxr w9, [sp]"
    testDisasm "c8410043" "ldxr x3, [x2]"

  /// C6.2.175 LDXRB
  [<TestMethod>]
  member _.``C6.2.175 LDXRB``() =
    testDisasm "085f7c20" "ldxrb w0, [x1]"
    testDisasm "085f03ff" "ldxrb wzr, [sp]"
    testDisasm "084a03e9" "ldxrb w9, [sp]"
    testDisasm "0841005f" "ldxrb wzr, [x2]"

  /// C6.2.176 LDXRH
  [<TestMethod>]
  member _.``C6.2.176 LDXRH``() =
    testDisasm "485f7c20" "ldxrh w0, [x1]"
    testDisasm "485f03ff" "ldxrh wzr, [sp]"
    testDisasm "484a03e9" "ldxrh w9, [sp]"
    testDisasm "4841005f" "ldxrh wzr, [x2]"

  /// C6.2.177 LSL (register)
  [<TestMethod>]
  member _.``C6.2.177 LSL``() =
    testDisasm "1ac22020" "lsl w0, w1, w2"
    testDisasm "531f7820" "lsl w0, w1, #0x1"
    testDisasm "d37ff820" "lsl x0, x1, #0x1"
    testDisasm "9ac22020" "lsl x0, x1, x2"

  /// C6.2.179 LSLV
  [<TestMethod>]
  member _.``C6.2.179 LSLV``() =
    testDisasm "1ac22020" "lsl w0, w1, w2"
    testDisasm "9ac22020" "lsl x0, x1, x2"
    testDisasm "1adf23ff" "lsl wzr, wzr, wzr"
    testDisasm "1aca23e9" "lsl w9, wzr, w10"

  /// C6.2.18 ASRV
  [<TestMethod>]
  member _.``C6.2.18 ASRV``() =
    testDisasm "1ac22820" "asr w0, w1, w2"
    testDisasm "9ac22820" "asr x0, x1, x2"
    testDisasm "1adf2bff" "asr wzr, wzr, wzr"
    testDisasm "1aca2be9" "asr w9, wzr, w10"

  /// C6.2.180 LSR (register)
  [<TestMethod>]
  member _.``C6.2.180 LSR``() =
    testDisasm "1ac22420" "lsr w0, w1, w2"
    testDisasm "53017c20" "lsr w0, w1, #0x1"
    testDisasm "d341fc20" "lsr x0, x1, #0x1"
    testDisasm "9ac22420" "lsr x0, x1, x2"

  /// C6.2.182 LSRV
  [<TestMethod>]
  member _.``C6.2.182 LSRV``() =
    testDisasm "1ac22420" "lsr w0, w1, w2"
    testDisasm "9ac22420" "lsr x0, x1, x2"
    testDisasm "1adf27ff" "lsr wzr, wzr, wzr"
    testDisasm "1aca27e9" "lsr w9, wzr, w10"

  /// C6.2.183 MADD
  [<TestMethod>]
  member _.``C6.2.183 MADD``() =
    testDisasm "1b020c20" "madd w0, w1, w2, w3"
    testDisasm "1b027c20" "mul w0, w1, w2"
    testDisasm "9b020c20" "madd x0, x1, x2, x3"
    testDisasm "9b027c20" "mul x0, x1, x2"

  /// C6.2.184 MNEG
  [<TestMethod>]
  member _.``C6.2.184 MNEG``() =
    testDisasm "1b02fc20" "mneg w0, w1, w2"
    testDisasm "9b02fc20" "mneg x0, x1, x2"
    testDisasm "1b1fffff" "mneg wzr, wzr, wzr"
    testDisasm "1b0affe9" "mneg w9, wzr, w10"

  /// C6.2.185 MOV (to/from SP)
  [<TestMethod>]
  member _.``C6.2.185 MOV``() =
    testDisasm "2a0103e0" "mov w0, w1"
    testDisasm "52800200" "mov w0, #0x10"
    testDisasm "d2800200" "mov x0, #0x10"
    testDisasm "aa0203e0" "mov x0, x2"

  /// C6.2.19 AT
  [<TestMethod>]
  member _.``C6.2.19 AT``() =
    testDisasm "d5087800" "at s1e1r, x0"
    testDisasm "d508781f" "at s1e1r, xzr"
    testDisasm "d5087820" "at s1e1w, x0"
    testDisasm "d508783f" "at s1e1w, xzr"

  /// C6.2.190 MOVK
  [<TestMethod>]
  member _.``C6.2.190 MOVK``() =
    testDisasm "72800200" "movk w0, #0x10"
    testDisasm "f2800200" "movk x0, #0x10"
    testDisasm "729f03ff" "movk wzr, #0xf81f"
    testDisasm "72a10043" "movk w3, #0x802, lsl #0x10"

  /// C6.2.191 MOVN
  [<TestMethod>]
  member _.``C6.2.191 MOVN``() =
    testDisasm "12800200" "mov w0, #0xffffffef"
    testDisasm "92800200" "mov x0, #0xffffffffffffffef"
    testDisasm "129f03ff" "mov wzr, #0xffff07e0"
    testDisasm "129fffff" "movn wzr, #0xffff"

  /// C6.2.192 MOVZ
  [<TestMethod>]
  member _.``C6.2.192 MOVZ``() =
    testDisasm "52800200" "mov w0, #0x10"
    testDisasm "d2800200" "mov x0, #0x10"
    testDisasm "52a00000" "movz w0, #0x0, lsl #0x10"
    testDisasm "d2a00000" "movz x0, #0x0, lsl #0x10"

  /// C6.2.193 MRS
  [<TestMethod>]
  member _.``C6.2.193 MRS``() =
    testDisasm "d53402b6" "mrs x22, s2_4_c0_c2_5"
    testDisasm "d53f03ff" "mrs xzr, s3_7_c0_c3_7"
    testDisasm "d5380000" "mrs x0, midr_el1"
    testDisasm "d538001f" "mrs xzr, midr_el1"

  /// C6.2.194 MSR (immediate)
  [<TestMethod>]
  member _.``C6.2.194 MSR``() =
    testDisasm "d51402b6" "msr s2_4_c0_c2_5, x22"
    testDisasm "d51f03ff" "msr s3_7_c0_c3_7, xzr"
    testDisasm "d500407f" "msr uao, #0x0"
    testDisasm "d500409f" "msr pan, #0x0"

  /// C6.2.196 MSUB
  [<TestMethod>]
  member _.``C6.2.196 MSUB``() =
    testDisasm "1b02fc20" "mneg w0, w1, w2"
    testDisasm "1b028c20" "msub w0, w1, w2, w3"
    testDisasm "9b02fc20" "mneg x0, x1, x2"
    testDisasm "9b028c20" "msub x0, x1, x2, x3"

  /// C6.2.197 MUL
  [<TestMethod>]
  member _.``C6.2.197 MUL``() =
    testDisasm "1b027c20" "mul w0, w1, w2"
    testDisasm "0f528020" "mul v0.4h, v1.4h, v2.h[1]"
    testDisasm "0fa28020" "mul v0.2s, v1.2s, v2.s[1]"
    testDisasm "0e229c20" "mul v0.8b, v1.8b, v2.8b"

  /// C6.2.198 MVN
  [<TestMethod>]
  member _.``C6.2.198 MVN``() =
    testDisasm "6e205820" "mvn v0.16b, v1.16b"
    testDisasm "2a2203e0" "mvn w0, w2"
    testDisasm "aa2203e0" "mvn x0, x2"
    testDisasm "2a3f03ff" "mvn wzr, wzr"

  /// C6.2.199 NEG (shifted register)
  [<TestMethod>]
  member _.``C6.2.199 NEG``() =
    testDisasm "4b0203e0" "neg w0, w2"
    testDisasm "2e20b820" "neg v0.8b, v1.8b"
    testDisasm "2e60b820" "neg v0.4h, v1.4h"
    testDisasm "2ea0b820" "neg v0.2s, v1.2s"

  /// C6.2.2 ADCS
  [<TestMethod>]
  member _.``C6.2.2 ADCS``() =
    testDisasm "3a020020" "adcs w0, w1, w2"
    testDisasm "ba020020" "adcs x0, x1, x2"
    testDisasm "3a1f03ff" "adcs wzr, wzr, wzr"
    testDisasm "3a0a03e9" "adcs w9, wzr, w10"

  /// C6.2.20 AUTDA, AUTDZA
  [<TestMethod>]
  member _.``C6.2.20 AUTDA``() =
    testDisasm "dac11820" "autda x0, x1"

  /// C6.2.20 AUTDA, AUTDZA
  [<TestMethod>]
  member _.``C6.2.20 AUTDZA``() =
    testDisasm "dac13be0" "autdza x0"

  /// C6.2.200 NEGS
  [<TestMethod>]
  member _.``C6.2.200 NEGS``() =
    testDisasm "6b0203e0" "negs w0, w2"
    testDisasm "eb0203e0" "negs x0, x2"
    testDisasm "6b1f03e0" "negs w0, wzr"
    testDisasm "6b0a07e9" "negs w9, w10, lsl #0x1"

  /// C6.2.201 NGC
  [<TestMethod>]
  member _.``C6.2.201 NGC``() =
    testDisasm "5a0203e0" "ngc w0, w2"
    testDisasm "da0203e0" "ngc x0, x2"
    testDisasm "5a1f03ff" "ngc wzr, wzr"
    testDisasm "5a1f03e0" "ngc w0, wzr"

  /// C6.2.202 NGCS
  [<TestMethod>]
  member _.``C6.2.202 NGCS``() =
    testDisasm "7a0203e0" "ngcs w0, w2"
    testDisasm "fa0203e0" "ngcs x0, x2"
    testDisasm "7a1f03ff" "ngcs wzr, wzr"
    testDisasm "7a1f03e0" "ngcs w0, wzr"

  /// C6.2.203 NOP
  [<TestMethod>]
  member _.``C6.2.203 NOP``() =
    testDisasm "d503201f" "nop"

  /// C6.2.204 ORN (shifted register)
  [<TestMethod>]
  member _.``C6.2.204 ORN``() =
    testDisasm "2a2203e0" "mvn w0, w2"
    testDisasm "2a220020" "orn w0, w1, w2"
    testDisasm "0ee21c20" "orn v0.8b, v1.8b, v2.8b"
    testDisasm "aa2203e0" "mvn x0, x2"

  /// C6.2.205 ORR (immediate)
  [<TestMethod>]
  member _.``C6.2.205 ORR``() =
    testDisasm "b2410420" "orr x0, x1, #0x8000000000000001"
    testDisasm "2a0103e0" "mov w0, w1"
    testDisasm "aa0203e0" "mov x0, x2"
    testDisasm "321c0020" "orr w0, w1, #0x10"

  /// C6.2.207 PACDA, PACDZA
  [<TestMethod>]
  member _.``C6.2.207 PACDA``() =
    testDisasm "dac10820" "pacda x0, x1"

  /// C6.2.207 PACDA, PACDZA
  [<TestMethod>]
  member _.``C6.2.207 PACDZA``() =
    testDisasm "dac12be0" "pacdza x0"

  /// C6.2.208 PACDB, PACDZB
  [<TestMethod>]
  member _.``C6.2.208 PACDB``() =
    testDisasm "dac10c20" "pacdb x0, x1"

  /// C6.2.208 PACDB, PACDZB
  [<TestMethod>]
  member _.``C6.2.208 PACDZB``() =
    testDisasm "dac12fe0" "pacdzb x0"

  /// C6.2.209 PACGA
  [<TestMethod>]
  member _.``C6.2.209 PACGA``() =
    testDisasm "9ac23020" "pacga x0, x1, x2"
    testDisasm "9adf33ff" "pacga xzr, xzr, sp"
    testDisasm "9aca33e9" "pacga x9, xzr, x10"
    testDisasm "9adf33c0" "pacga x0, x30, sp"

  /// C6.2.21 AUTDB, AUTDZB
  [<TestMethod>]
  member _.``C6.2.21 AUTDB``() =
    testDisasm "dac11c20" "autdb x0, x1"

  /// C6.2.21 AUTDB, AUTDZB
  [<TestMethod>]
  member _.``C6.2.21 AUTDZB``() =
    testDisasm "dac13fe0" "autdzb x0"

  /// C6.2.210 PACIA, PACIA1716, PACIASP, PACIAZ, PACIZA
  [<TestMethod>]
  member _.``C6.2.210 PACIA``() =
    testDisasm "dac10020" "pacia x0, x1"
    testDisasm "dac103e3" "pacia x3, sp"
    testDisasm "dac1005f" "pacia xzr, x2"

  /// C6.2.210 PACIA, PACIA1716, PACIASP, PACIAZ, PACIZA
  [<TestMethod>]
  member _.``C6.2.210 PACIA1716``() =
    testDisasm "d503211f" "pacia1716"

  /// C6.2.210 PACIA, PACIA1716, PACIASP, PACIAZ, PACIZA
  [<TestMethod>]
  member _.``C6.2.210 PACIASP``() =
    testDisasm "d503233f" "paciasp"

  /// C6.2.210 PACIA, PACIA1716, PACIASP, PACIAZ, PACIZA
  [<TestMethod>]
  member _.``C6.2.210 PACIAZ``() =
    testDisasm "d503231f" "paciaz"

  /// C6.2.210 PACIA, PACIA1716, PACIASP, PACIAZ, PACIZA
  [<TestMethod>]
  member _.``C6.2.210 PACIZA``() =
    testDisasm "dac123e0" "paciza x0"

  /// C6.2.211 PACIB, PACIB1716, PACIBSP, PACIBZ, PACIZB
  [<TestMethod>]
  member _.``C6.2.211 PACIB``() =
    testDisasm "dac10420" "pacib x0, x1"

  /// C6.2.211 PACIB, PACIB1716, PACIBSP, PACIBZ, PACIZB
  [<TestMethod>]
  member _.``C6.2.211 PACIB1716``() =
    testDisasm "d503215f" "pacib1716"

  /// C6.2.211 PACIB, PACIB1716, PACIBSP, PACIBZ, PACIZB
  [<TestMethod>]
  member _.``C6.2.211 PACIBSP``() =
    testDisasm "d503237f" "pacibsp"

  /// C6.2.211 PACIB, PACIB1716, PACIBSP, PACIBZ, PACIZB
  [<TestMethod>]
  member _.``C6.2.211 PACIBZ``() =
    testDisasm "d503235f" "pacibz"

  /// C6.2.211 PACIB, PACIB1716, PACIBSP, PACIBZ, PACIZB
  [<TestMethod>]
  member _.``C6.2.211 PACIZB``() =
    testDisasm "dac127e0" "pacizb x0"

  /// C6.2.212 PRFM (immediate)
  [<TestMethod>]
  member _.``C6.2.212 PRFM``() =
    testDisasm "f9800020" "prfm pldl1keep, [x1]"
    testDisasm "d8010043" "prfm pldl2strm, 0x2008"
    testDisasm "d81f03ff" "prfm #0x1f, 0x3e07c"
    testDisasm "d80003c0" "prfm pldl1keep, 0x78"

  /// C6.2.215 PRFUM
  [<TestMethod>]
  member _.``C6.2.215 PRFUM``() =
    testDisasm "f8800020" "prfum pldl1keep, [x1]"
    testDisasm "f8810043" "prfum pldl2strm, [x2, #0x10]"
    testDisasm "f89f03ff" "prfum #0x1f, [sp, #0xfffffffffffffff0]"
    testDisasm "f88a03e9" "prfum plil1strm, [sp, #0xa0]"

  /// C6.2.216 PSB CSYNC
  [<TestMethod>]
  member _.``C6.2.216 PSB``() =
    testDisasm "d503223f" "psb csync"

  /// C6.2.217 PSSBB
  [<TestMethod>]
  member _.``C6.2.217 PSSBB``() =
    testDisasm "d503349f" "pssbb"

  /// C6.2.218 RBIT
  [<TestMethod>]
  member _.``C6.2.218 RBIT``() =
    testDisasm "5ac00020" "rbit w0, w1"
    testDisasm "2e605820" "rbit v0.8b, v1.8b"
    testDisasm "dac00020" "rbit x0, x1"

  /// C6.2.219 RET
  [<TestMethod>]
  member _.``C6.2.219 RET``() =
    testDisasm "d65f03c0" "ret"
    testDisasm "d65f03e0" "ret xzr"

  /// C6.2.22 AUTIA, AUTIA1716, AUTIASP, AUTIAZ, AUTIZA
  [<TestMethod>]
  member _.``C6.2.22 AUTIA``() =
    testDisasm "dac11020" "autia x0, x1"

  /// C6.2.22 AUTIA, AUTIA1716, AUTIASP, AUTIAZ, AUTIZA
  [<TestMethod>]
  member _.``C6.2.22 AUTIA1716``() =
    testDisasm "d503219f" "autia1716"

  /// C6.2.22 AUTIA, AUTIA1716, AUTIASP, AUTIAZ, AUTIZA
  [<TestMethod>]
  member _.``C6.2.22 AUTIASP``() =
    testDisasm "d50323bf" "autiasp"

  /// C6.2.22 AUTIA, AUTIA1716, AUTIASP, AUTIAZ, AUTIZA
  [<TestMethod>]
  member _.``C6.2.22 AUTIAZ``() =
    testDisasm "d503239f" "autiaz"

  /// C6.2.22 AUTIA, AUTIA1716, AUTIASP, AUTIAZ, AUTIZA
  [<TestMethod>]
  member _.``C6.2.22 AUTIZA``() =
    testDisasm "dac133e0" "autiza x0"

  /// C6.2.220 RETAA, RETAB
  [<TestMethod>]
  member _.``C6.2.220 RETAA``() =
    testDisasm "d65f0bff" "retaa"

  /// C6.2.220 RETAA, RETAB
  [<TestMethod>]
  member _.``C6.2.220 RETAB``() =
    testDisasm "d65f0fff" "retab"

  /// C6.2.221 REV
  [<TestMethod>]
  member _.``C6.2.221 REV``() =
    testDisasm "5ac00820" "rev w0, w1"
    testDisasm "dac00c20" "rev x0, x1"

  /// C6.2.222 REV16
  [<TestMethod>]
  member _.``C6.2.222 REV16``() =
    testDisasm "5ac00420" "rev16 w0, w1"
    testDisasm "0e201820" "rev16 v0.8b, v1.8b"
    testDisasm "dac00420" "rev16 x0, x1"

  /// C6.2.223 REV32
  [<TestMethod>]
  member _.``C6.2.223 REV32``() =
    testDisasm "2e200820" "rev32 v0.8b, v1.8b"
    testDisasm "2e600820" "rev32 v0.4h, v1.4h"
    testDisasm "dac00820" "rev32 x0, x1"

  /// C6.2.224 REV64
  [<TestMethod>]
  member _.``C6.2.224 REV64``() =
    testDisasm "0e200820" "rev64 v0.8b, v1.8b"
    testDisasm "0e600820" "rev64 v0.4h, v1.4h"
    testDisasm "0ea00820" "rev64 v0.2s, v1.2s"

  /// C6.2.225 RMIF
  [<TestMethod>]
  member _.``C6.2.225 RMIF``() =
    testDisasm "ba03840f" "rmif x0, #0x7, #0xf"
    testDisasm "ba0a07e9" "rmif xzr, #0x14, #0x9"

  /// C6.2.226 ROR (immediate)
  [<TestMethod>]
  member _.``C6.2.226 ROR``() =
    testDisasm "13820440" "ror w0, w2, #1"
    testDisasm "93c20440" "ror x0, x2, #1"
    testDisasm "1ac22c20" "rorv w0, w1, w2"
    testDisasm "9ac22c20" "rorv x0, x1, x2"

  /// C6.2.228 RORV
  [<TestMethod>]
  member _.``C6.2.228 RORV``() =
    testDisasm "1ac22c20" "rorv w0, w1, w2"
    testDisasm "9ac22c20" "rorv x0, x1, x2"
    testDisasm "1adf2fff" "rorv wzr, wzr, wzr"
    testDisasm "1aca2fe9" "rorv w9, wzr, w10"

  /// C6.2.229 SB
  [<TestMethod>]
  member _.``C6.2.229 SB``() =
    testDisasm "d50330ff" "sb"

  /// C6.2.23 AUTIB, AUTIB1716, AUTIBSP, AUTIBZ, AUTIZB
  [<TestMethod>]
  member _.``C6.2.23 AUTIB``() =
    testDisasm "dac11420" "autib x0, x1"

  /// C6.2.23 AUTIB, AUTIB1716, AUTIBSP, AUTIBZ, AUTIZB
  [<TestMethod>]
  member _.``C6.2.23 AUTIB1716``() =
    testDisasm "d50321df" "autib1716"

  /// C6.2.23 AUTIB, AUTIB1716, AUTIBSP, AUTIBZ, AUTIZB
  [<TestMethod>]
  member _.``C6.2.23 AUTIBSP``() =
    testDisasm "d50323ff" "autibsp"

  /// C6.2.23 AUTIB, AUTIB1716, AUTIBSP, AUTIBZ, AUTIZB
  [<TestMethod>]
  member _.``C6.2.23 AUTIBZ``() =
    testDisasm "d50323df" "autibz"

  /// C6.2.23 AUTIB, AUTIB1716, AUTIBSP, AUTIBZ, AUTIZB
  [<TestMethod>]
  member _.``C6.2.23 AUTIZB``() =
    testDisasm "dac137e0" "autizb x0"

  /// C6.2.230 SBC
  [<TestMethod>]
  member _.``C6.2.230 SBC``() =
    testDisasm "5a0203e0" "ngc w0, w2"
    testDisasm "5a020020" "sbc w0, w1, w2"
    testDisasm "da0203e0" "ngc x0, x2"
    testDisasm "da020020" "sbc x0, x1, x2"

  /// C6.2.231 SBCS
  [<TestMethod>]
  member _.``C6.2.231 SBCS``() =
    testDisasm "7a0203e0" "ngcs w0, w2"
    testDisasm "7a020020" "sbcs w0, w1, w2"
    testDisasm "fa0203e0" "ngcs x0, x2"
    testDisasm "fa020020" "sbcs x0, x1, x2"

  /// C6.2.232 SBFIZ
  [<TestMethod>]
  member _.``C6.2.232 SBFIZ``() =
    testDisasm "131d1020" "sbfiz w0, w1, #0x3, #0x5"
    testDisasm "937d1020" "sbfiz x0, x1, #0x3, #0x5"
    testDisasm "131f03ff" "sbfiz wzr, wzr, #0x1, #0x1"
    testDisasm "130a03e9" "sbfiz w9, wzr, #0x16, #0x1"

  /// C6.2.233 SBFM
  [<TestMethod>]
  member _.``C6.2.233 SBFM``() =
    testDisasm "13017c20" "asr w0, w1, #0x1"
    testDisasm "9341fc20" "asr x0, x1, #0x1"
    testDisasm "131d1020" "sbfiz w0, w1, #0x3, #0x5"
    testDisasm "937d1020" "sbfiz x0, x1, #0x3, #0x5"

  /// C6.2.234 SBFX
  [<TestMethod>]
  member _.``C6.2.234 SBFX``() =
    testDisasm "13031420" "sbfx w0, w1, #0x3, #0x3"
    testDisasm "93431420" "sbfx x0, x1, #0x3, #0x3"
    testDisasm "130a2be9" "sbfx w9, wzr, #0xa, #0x1"
    testDisasm "934a2be9" "sbfx x9, xzr, #0xa, #0x1"

  /// C6.2.235 SDIV
  [<TestMethod>]
  member _.``C6.2.235 SDIV``() =
    testDisasm "1ac20c20" "sdiv w0, w1, w2"
    testDisasm "9ac20c20" "sdiv x0, x1, x2"
    testDisasm "1adf0fff" "sdiv wzr, wzr, wzr"
    testDisasm "1aca0fe9" "sdiv w9, wzr, w10"

  /// C6.2.236 SETF8, SETF16
  [<TestMethod>]
  member _.``C6.2.236 SETF16``() =
    testDisasm "3a00480d" "setf16 w0"

  /// C6.2.236 SETF8, SETF16
  [<TestMethod>]
  member _.``C6.2.236 SETF8``() =
    testDisasm "3a00080d" "setf8 w0"

  /// C6.2.237 SEV
  [<TestMethod>]
  member _.``C6.2.237 SEV``() =
    testDisasm "d503209f" "sev"

  /// C6.2.238 SEVL
  [<TestMethod>]
  member _.``C6.2.238 SEVL``() =
    testDisasm "d50320bf" "sevl"

  /// C6.2.239 SMADDL
  [<TestMethod>]
  member _.``C6.2.239 SMADDL``() =
    testDisasm "9b220c20" "smaddl x0, w1, w2, x3"
    testDisasm "9b227c20" "smull x0, w1, w2"
    testDisasm "9b3f03ff" "smaddl xzr, wzr, wzr, x0"
    testDisasm "9b2a03e9" "smaddl x9, wzr, w10, x0"

  /// C6.2.24 AXFLAG
  [<TestMethod>]
  member _.``C6.2.24 AXFLAG``() =
    testDisasm "d500405f" "axflag"

  /// C6.2.240 SMC
  [<TestMethod>]
  member _.``C6.2.240 SMC``() =
    testDisasm "d4010043" "smc #0x802"

  /// C6.2.241 SMNEGL
  [<TestMethod>]
  member _.``C6.2.241 SMNEGL``() =
    testDisasm "9b22fc20" "smnegl x0, w1, w2"
    testDisasm "9b3fffff" "smnegl xzr, wzr, wzr"
    testDisasm "9b2affe9" "smnegl x9, wzr, w10"
    testDisasm "9b3fffc0" "smnegl x0, w30, wzr"

  /// C6.2.242 SMSUBL
  [<TestMethod>]
  member _.``C6.2.242 SMSUBL``() =
    testDisasm "9b22fc20" "smnegl x0, w1, w2"
    testDisasm "9b228c20" "smsubl x0, w1, w2, x3"
    testDisasm "9b3f83ff" "smsubl xzr, wzr, wzr, x0"
    testDisasm "9b2a83e9" "smsubl x9, wzr, w10, x0"

  /// C6.2.243 SMULH
  [<TestMethod>]
  member _.``C6.2.243 SMULH``() =
    testDisasm "9b427c20" "smulh x0, x1, x2"
    testDisasm "9b5f03ff" "smulh xzr, xzr, xzr"
    testDisasm "9b4a03e9" "smulh x9, xzr, x10"
    testDisasm "9b5f03c0" "smulh x0, x30, xzr"

  /// C6.2.244 SMULL
  [<TestMethod>]
  member _.``C6.2.244 SMULL``() =
    testDisasm "0f52a020" "smull v0.4s, v1.4h, v2.h[1]"
    testDisasm "0fa2a020" "smull v0.2d, v1.2s, v2.s[1]"
    testDisasm "0e22c020" "smull v0.8h, v1.8b, v2.8b"
    testDisasm "0e62c020" "smull v0.4s, v1.4h, v2.4h"

  /// C6.2.245 SSBB
  [<TestMethod>]
  member _.``C6.2.245 SSBB``() =
    testDisasm "d503309f" "ssbb"

  /// C6.2.246 ST2G
  [<TestMethod>]
  member _.``C6.2.246 ST2G``() =
    testDisasm "d9a00820" "st2g x0, [x1]"
    testDisasm "d9a01420" "st2g x0, [x1], #0x10"
    testDisasm "d9a01c20" "st2g x0, [x1, #0x10]!"
    testDisasm "d9a01820" "st2g x0, [x1, #0x10]"

  /// C6.2.247 STADDB, STADDLB
  [<TestMethod>]
  member _.``C6.2.247 STADDB``() =
    testDisasm "3822003f" "staddb w2, [x1]"
    testDisasm "383f03ff" "staddb wzr, [sp]"

  /// C6.2.247 STADDB, STADDLB
  [<TestMethod>]
  member _.``C6.2.247 STADDLB``() =
    testDisasm "3862003f" "staddlb w2, [x1]"
    testDisasm "387f03ff" "staddlb wzr, [sp]"

  /// C6.2.248 STADDH, STADDLH
  [<TestMethod>]
  member _.``C6.2.248 STADDH``() =
    testDisasm "7822003f" "staddh w2, [x1]"
    testDisasm "783f03ff" "staddh wzr, [sp]"

  /// C6.2.248 STADDH, STADDLH
  [<TestMethod>]
  member _.``C6.2.248 STADDLH``() =
    testDisasm "7862003f" "staddlh w2, [x1]"
    testDisasm "787f03ff" "staddlh wzr, [sp]"

  /// C6.2.249 STADD, STADDL
  [<TestMethod>]
  member _.``C6.2.249 STADD``() =
    testDisasm "f822003f" "stadd x2, [x1]"
    testDisasm "b822003f" "stadd w2, [x1]"
    testDisasm "b83f03ff" "stadd wzr, [sp]"
    testDisasm "f83f03ff" "stadd xzr, [sp]"

  /// C6.2.249 STADD, STADDL
  [<TestMethod>]
  member _.``C6.2.249 STADDL``() =
    testDisasm "b862003f" "staddl w2, [x1]"
    testDisasm "b87f03ff" "staddl wzr, [sp]"
    testDisasm "f87f03ff" "staddl xzr, [sp]"
    testDisasm "f861005f" "staddl x1, [x2]"

  /// C6.2.25 B.cond
  [<TestMethod>]
  member _.``C6.2.25 B.COND``() =
    testDisasm "54000040" "beq 0x8"
    testDisasm "54010043" "bcc 0x2008"
    testDisasm "540a03e9" "bls 0x1407c"
    testDisasm "5403010d" "ble 0x6020"

  /// C6.2.250 STCLRB, STCLRLB
  [<TestMethod>]
  member _.``C6.2.250 STCLRB``() =
    testDisasm "3822103f" "stclrb w2, [x1]"
    testDisasm "383f13ff" "stclrb wzr, [sp]"

  /// C6.2.250 STCLRB, STCLRLB
  [<TestMethod>]
  member _.``C6.2.250 STCLRLB``() =
    testDisasm "3862103f" "stclrlb w2, [x1]"
    testDisasm "387f13ff" "stclrlb wzr, [sp]"
