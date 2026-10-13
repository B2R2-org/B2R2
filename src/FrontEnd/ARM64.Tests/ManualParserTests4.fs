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
/// One test for each instruction DDI0487F.c describes, UMULH to FMLAL in
/// the order of its sections. Each reads words of the instruction and checks
/// the text, and each word's text is one binutils' objdump reads the word as
/// too, so what is asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualParserTests4() =
  let parser =
    Parser(BinReader.Init Endian.Big) :> IInstructionParsable

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// C6.2.340 UMULH
  [<TestMethod>]
  member _.``C6.2.340 UMULH``() =
    testDisasm "9bc27c20" "umulh x0, x1, x2"
    testDisasm "9bdf03ff" "umulh xzr, xzr, xzr"
    testDisasm "9bca03e9" "umulh x9, xzr, x10"
    testDisasm "9bdf03c0" "umulh x0, x30, xzr"

  /// C6.2.341 UMULL
  [<TestMethod>]
  member _.``C6.2.341 UMULL``() =
    testDisasm "2f52a020" "umull v0.4s, v1.4h, v2.h[1]"
    testDisasm "2fa2a020" "umull v0.2d, v1.2s, v2.s[1]"
    testDisasm "2e22c020" "umull v0.8h, v1.8b, v2.8b"
    testDisasm "2e62c020" "umull v0.4s, v1.4h, v2.4h"

  /// C6.2.342 UXTB
  [<TestMethod>]
  member _.``C6.2.342 UXTB``() =
    testDisasm "53001c20" "uxtb w0, w1"

  /// C6.2.343 UXTH
  [<TestMethod>]
  member _.``C6.2.343 UXTH``() =
    testDisasm "53003c20" "uxth w0, w1"

  /// C6.2.344 WFE
  [<TestMethod>]
  member _.``C6.2.344 WFE``() =
    testDisasm "d503205f" "wfe"

  /// C6.2.345 WFI
  [<TestMethod>]
  member _.``C6.2.345 WFI``() =
    testDisasm "d503207f" "wfi"

  /// C6.2.346 XAFLAG
  [<TestMethod>]
  member _.``C6.2.346 XAFLAG``() =
    testDisasm "d500403f" "xaflag"

  /// C6.2.347 XPACD, XPACI, XPACLRI
  [<TestMethod>]
  member _.``C6.2.347 XPACD``() =
    testDisasm "dac147e0" "xpacd x0"

  /// C6.2.347 XPACD, XPACI, XPACLRI
  [<TestMethod>]
  member _.``C6.2.347 XPACI``() =
    testDisasm "dac143e0" "xpaci x0"

  /// C6.2.347 XPACD, XPACI, XPACLRI
  [<TestMethod>]
  member _.``C6.2.347 XPACLRI``() =
    testDisasm "d50320ff" "xpaclri"

  /// C6.2.348 YIELD
  [<TestMethod>]
  member _.``C6.2.348 YIELD``() =
    testDisasm "d503203f" "yield"

  /// C6.2.35 BLRAA, BLRAAZ, BLRAB, BLRABZ
  [<TestMethod>]
  member _.``C6.2.35 BLRAA``() =
    testDisasm "d73f0bff" "blraa xzr, sp"
    testDisasm "d73f0bc0" "blraa x30, x0"
    testDisasm "d73f0be0" "blraa xzr, x0"

  /// C6.2.35 BLRAA, BLRAAZ, BLRAB, BLRABZ
  [<TestMethod>]
  member _.``C6.2.35 BLRAAZ``() =
    testDisasm "d63f0bff" "blraaz xzr"

  /// C6.2.35 BLRAA, BLRAAZ, BLRAB, BLRABZ
  [<TestMethod>]
  member _.``C6.2.35 BLRAB``() =
    testDisasm "d73f0fff" "blrab xzr, sp"
    testDisasm "d73f0fc0" "blrab x30, x0"
    testDisasm "d73f0fe0" "blrab xzr, x0"

  /// C6.2.35 BLRAA, BLRAAZ, BLRAB, BLRABZ
  [<TestMethod>]
  member _.``C6.2.35 BLRABZ``() =
    testDisasm "d63f0fff" "blrabz xzr"

  /// C6.2.36 BR
  [<TestMethod>]
  member _.``C6.2.36 BR``() =
    testDisasm "d61f03c0" "br x30"
    testDisasm "d61f03e0" "br xzr"

  /// C6.2.37 BRAA, BRAAZ, BRAB, BRABZ
  [<TestMethod>]
  member _.``C6.2.37 BRAA``() =
    testDisasm "d71f0bff" "braa xzr, sp"
    testDisasm "d71f0bc0" "braa x30, x0"
    testDisasm "d71f0be0" "braa xzr, x0"

  /// C6.2.37 BRAA, BRAAZ, BRAB, BRABZ
  [<TestMethod>]
  member _.``C6.2.37 BRAAZ``() =
    testDisasm "d61f0bff" "braaz xzr"

  /// C6.2.37 BRAA, BRAAZ, BRAB, BRABZ
  [<TestMethod>]
  member _.``C6.2.37 BRAB``() =
    testDisasm "d71f0fff" "brab xzr, sp"
    testDisasm "d71f0fc0" "brab x30, x0"
    testDisasm "d71f0fe0" "brab xzr, x0"

  /// C6.2.37 BRAA, BRAAZ, BRAB, BRABZ
  [<TestMethod>]
  member _.``C6.2.37 BRABZ``() =
    testDisasm "d61f0fff" "brabz xzr"

  /// C6.2.38 BRK
  [<TestMethod>]
  member _.``C6.2.38 BRK``() =
    testDisasm "d42003c0" "brk #0x1e"

  /// C6.2.39 BTI
  [<TestMethod>]
  member _.``C6.2.39 BTI``() =
    testDisasm "d503241f" "bti"
    testDisasm "d503245f" "bti c"
    testDisasm "d503249f" "bti j"
    testDisasm "d50324df" "bti jc"

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASAB``() =
    testDisasm "08e27c20" "casab w2, w0, [x1]"
    testDisasm "08ff7fff" "casab wzr, wzr, [sp]"
    testDisasm "08ea7fe9" "casab w10, w9, [sp]"
    testDisasm "08ff7fc0" "casab wzr, w0, [x30]"

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASALB``() =
    testDisasm "08e2fc20" "casalb w2, w0, [x1]"
    testDisasm "08ffffff" "casalb wzr, wzr, [sp]"
    testDisasm "08eaffe9" "casalb w10, w9, [sp]"
    testDisasm "08ffffc0" "casalb wzr, w0, [x30]"

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASB``() =
    testDisasm "08a27c20" "casb w2, w0, [x1]"
    testDisasm "08bf7fff" "casb wzr, wzr, [sp]"
    testDisasm "08aa7fe9" "casb w10, w9, [sp]"
    testDisasm "08bf7fc0" "casb wzr, w0, [x30]"

  /// C6.2.40 CASB, CASAB, CASALB, CASLB
  [<TestMethod>]
  member _.``C6.2.40 CASLB``() =
    testDisasm "08a2fc20" "caslb w2, w0, [x1]"
    testDisasm "08bfffff" "caslb wzr, wzr, [sp]"
    testDisasm "08aaffe9" "caslb w10, w9, [sp]"
    testDisasm "08bfffc0" "caslb wzr, w0, [x30]"

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASAH``() =
    testDisasm "48e27c20" "casah w2, w0, [x1]"
    testDisasm "48ff7fff" "casah wzr, wzr, [sp]"
    testDisasm "48ea7fe9" "casah w10, w9, [sp]"
    testDisasm "48ff7fc0" "casah wzr, w0, [x30]"

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASALH``() =
    testDisasm "48e2fc20" "casalh w2, w0, [x1]"
    testDisasm "48ffffff" "casalh wzr, wzr, [sp]"
    testDisasm "48eaffe9" "casalh w10, w9, [sp]"
    testDisasm "48ffffc0" "casalh wzr, w0, [x30]"

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASH``() =
    testDisasm "48a27c20" "cash w2, w0, [x1]"
    testDisasm "48bf7fff" "cash wzr, wzr, [sp]"
    testDisasm "48aa7fe9" "cash w10, w9, [sp]"
    testDisasm "48bf7fc0" "cash wzr, w0, [x30]"

  /// C6.2.41 CASH, CASAH, CASALH, CASLH
  [<TestMethod>]
  member _.``C6.2.41 CASLH``() =
    testDisasm "48a2fc20" "caslh w2, w0, [x1]"
    testDisasm "48bfffff" "caslh wzr, wzr, [sp]"
    testDisasm "48aaffe9" "caslh w10, w9, [sp]"
    testDisasm "48bfffc0" "caslh wzr, w0, [x30]"

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASP``() =
    testDisasm "48227c80" "casp x2, x3, x0, x1, [x4]"
    testDisasm "08347eb6" "casp w20, w21, w22, w23, [x21]"

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASPA``() =
    testDisasm "48627c80" "caspa x2, x3, x0, x1, [x4]"
    testDisasm "08747eb6" "caspa w20, w21, w22, w23, [x21]"

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASPAL``() =
    testDisasm "4862fc80" "caspal x2, x3, x0, x1, [x4]"
    testDisasm "0874feb6" "caspal w20, w21, w22, w23, [x21]"

  /// C6.2.42 CASP, CASPA, CASPAL, CASPL
  [<TestMethod>]
  member _.``C6.2.42 CASPL``() =
    testDisasm "4822fc80" "caspl x2, x3, x0, x1, [x4]"
    testDisasm "0834feb6" "caspl w20, w21, w22, w23, [x21]"

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CAS``() =
    testDisasm "c8a27c20" "cas x2, x0, [x1]"
    testDisasm "88a27c20" "cas w2, w0, [x1]"
    testDisasm "88bf7fff" "cas wzr, wzr, [sp]"
    testDisasm "88aa7fe9" "cas w10, w9, [sp]"

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CASA``() =
    testDisasm "88e27c20" "casa w2, w0, [x1]"
    testDisasm "88ff7fff" "casa wzr, wzr, [sp]"
    testDisasm "88ea7fe9" "casa w10, w9, [sp]"
    testDisasm "88ff7fc0" "casa wzr, w0, [x30]"

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CASAL``() =
    testDisasm "88e2fc20" "casal w2, w0, [x1]"
    testDisasm "88ffffff" "casal wzr, wzr, [sp]"
    testDisasm "88eaffe9" "casal w10, w9, [sp]"
    testDisasm "88ffffc0" "casal wzr, w0, [x30]"

  /// C6.2.43 CAS, CASA, CASAL, CASL
  [<TestMethod>]
  member _.``C6.2.43 CASL``() =
    testDisasm "88a2fc20" "casl w2, w0, [x1]"
    testDisasm "88bfffff" "casl wzr, wzr, [sp]"
    testDisasm "88aaffe9" "casl w10, w9, [sp]"
    testDisasm "88bfffc0" "casl wzr, w0, [x30]"

  /// C6.2.44 CBNZ
  [<TestMethod>]
  member _.``C6.2.44 CBNZ``() =
    testDisasm "35000020" "cbnz w0, 0x4"
    testDisasm "b5000020" "cbnz x0, 0x4"
    testDisasm "351f03ff" "cbnz wzr, 0x3e07c"
    testDisasm "b51f03ff" "cbnz xzr, 0x3e07c"

  /// C6.2.45 CBZ
  [<TestMethod>]
  member _.``C6.2.45 CBZ``() =
    testDisasm "34000020" "cbz w0, 0x4"
    testDisasm "b4000020" "cbz x0, 0x4"
    testDisasm "341f03ff" "cbz wzr, 0x3e07c"
    testDisasm "b41f03ff" "cbz xzr, 0x3e07c"

  /// C6.2.46 CCMN (immediate)
  [<TestMethod>]
  member _.``C6.2.46 CCMN``() =
    testDisasm "3a500829" "ccmn w1, #0x10, #0x9, eq"
    testDisasm "ba500829" "ccmn x1, #0x10, #0x9, eq"
    testDisasm "3a420029" "ccmn w1, w2, #0x9, eq"
    testDisasm "ba420029" "ccmn x1, x2, #0x9, eq"

  /// C6.2.48 CCMP (immediate)
  [<TestMethod>]
  member _.``C6.2.48 CCMP``() =
    testDisasm "7a500829" "ccmp w1, #0x10, #0x9, eq"
    testDisasm "fa500829" "ccmp x1, #0x10, #0x9, eq"
    testDisasm "7a420029" "ccmp w1, w2, #0x9, eq"
    testDisasm "fa420029" "ccmp x1, x2, #0x9, eq"

  /// C6.2.50 CFINV
  [<TestMethod>]
  member _.``C6.2.50 CFINV``() =
    testDisasm "d500401f" "cfinv"

  /// C6.2.51 CFP
  [<TestMethod>]
  member _.``C6.2.51 CFP``() =
    testDisasm "d50b7380" "cfp rctx, x0"
    testDisasm "d50b739f" "cfp rctx, xzr"

  /// C6.2.52 CINC
  [<TestMethod>]
  member _.``C6.2.52 CINC``() =
    testDisasm "1a811420" "cinc w0, w1, eq"
    testDisasm "9a811420" "cinc x0, x1, eq"
    testDisasm "1a800400" "cinc w0, w0, ne"
    testDisasm "1a802400" "cinc w0, w0, cc"

  /// C6.2.53 CINV
  [<TestMethod>]
  member _.``C6.2.53 CINV``() =
    testDisasm "5a811020" "cinv w0, w1, eq"
    testDisasm "da811020" "cinv x0, x1, eq"
    testDisasm "5a800000" "cinv w0, w0, ne"
    testDisasm "5a802000" "cinv w0, w0, cc"

  /// C6.2.54 CLREX
  [<TestMethod>]
  member _.``C6.2.54 CLREX``() =
    testDisasm "d503305f" "clrex #0x0"

  /// C6.2.55 CLS
  [<TestMethod>]
  member _.``C6.2.55 CLS``() =
    testDisasm "5ac01420" "cls w0, w1"
    testDisasm "0e204820" "cls v0.8b, v1.8b"
    testDisasm "0e604820" "cls v0.4h, v1.4h"
    testDisasm "0ea04820" "cls v0.2s, v1.2s"

  /// C6.2.56 CLZ
  [<TestMethod>]
  member _.``C6.2.56 CLZ``() =
    testDisasm "5ac01020" "clz w0, w1"
    testDisasm "2e204820" "clz v0.8b, v1.8b"
    testDisasm "2e604820" "clz v0.4h, v1.4h"
    testDisasm "2ea04820" "clz v0.2s, v1.2s"

  /// C6.2.57 CMN (extended register)
  [<TestMethod>]
  member _.``C6.2.57 CMN``() =
    testDisasm "2b02003f" "cmn w1, w2"
    testDisasm "3100403f" "cmn w1, #0x10"
    testDisasm "b100403f" "cmn x1, #0x10"
    testDisasm "ab02003f" "cmn x1, x2"

  /// C6.2.6 ADDG
  [<TestMethod>]
  member _.``C6.2.6 ADDG``() =
    testDisasm "91800020" "addg x0, x1, #0x0, #0x0"
    testDisasm "919f03ff" "addg sp, sp, #0x1f0, #0x0"
    testDisasm "918a03e9" "addg x9, sp, #0xa0, #0x0"
    testDisasm "9181005f" "addg sp, x2, #0x10, #0x0"

  /// C6.2.60 CMP (extended register)
  [<TestMethod>]
  member _.``C6.2.60 CMP``() =
    testDisasm "6b02003f" "cmp w1, w2"
    testDisasm "7100403f" "cmp w1, #0x10"
    testDisasm "f100403f" "cmp x1, #0x10"
    testDisasm "eb02003f" "cmp x1, x2"

  /// C6.2.63 CMPP
  [<TestMethod>]
  member _.``C6.2.63 CMPP``() =
    testDisasm "bac1001f" "cmpp x0, x1"
    testDisasm "badf03ff" "cmpp sp, sp"

  /// C6.2.64 CNEG
  [<TestMethod>]
  member _.``C6.2.64 CNEG``() =
    testDisasm "5a811420" "cneg w0, w1, eq"
    testDisasm "da811420" "cneg x0, x1, eq"
    testDisasm "5a9f07ff" "cneg wzr, wzr, ne"
    testDisasm "5a9f07e0" "cneg w0, wzr, ne"

  /// C6.2.65 CPP
  [<TestMethod>]
  member _.``C6.2.65 CPP``() =
    testDisasm "d50b73e0" "cpp rctx, x0"
    testDisasm "d50b73ff" "cpp rctx, xzr"

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32B``() =
    testDisasm "1ac24020" "crc32b w0, w1, w2"
    testDisasm "1adf43ff" "crc32b wzr, wzr, wzr"
    testDisasm "1aca43e9" "crc32b w9, wzr, w10"
    testDisasm "1adf43c0" "crc32b w0, w30, wzr"

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32H``() =
    testDisasm "1ac24420" "crc32h w0, w1, w2"
    testDisasm "1adf47ff" "crc32h wzr, wzr, wzr"
    testDisasm "1aca47e9" "crc32h w9, wzr, w10"
    testDisasm "1adf47c0" "crc32h w0, w30, wzr"

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32W``() =
    testDisasm "1ac24820" "crc32w w0, w1, w2"
    testDisasm "1adf4bff" "crc32w wzr, wzr, wzr"
    testDisasm "1aca4be9" "crc32w w9, wzr, w10"
    testDisasm "1adf4bc0" "crc32w w0, w30, wzr"

  /// C6.2.66 CRC32B, CRC32H, CRC32W, CRC32X
  [<TestMethod>]
  member _.``C6.2.66 CRC32X``() =
    testDisasm "9ac24c20" "crc32x w0, w1, x2"
    testDisasm "9adf4fff" "crc32x wzr, wzr, xzr"
    testDisasm "9aca4fe9" "crc32x w9, wzr, x10"
    testDisasm "9adf4fc0" "crc32x w0, w30, xzr"

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CB``() =
    testDisasm "1ac25020" "crc32cb w0, w1, w2"
    testDisasm "1adf53ff" "crc32cb wzr, wzr, wzr"
    testDisasm "1aca53e9" "crc32cb w9, wzr, w10"
    testDisasm "1adf53c0" "crc32cb w0, w30, wzr"

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CH``() =
    testDisasm "1ac25420" "crc32ch w0, w1, w2"
    testDisasm "1adf57ff" "crc32ch wzr, wzr, wzr"
    testDisasm "1aca57e9" "crc32ch w9, wzr, w10"
    testDisasm "1adf57c0" "crc32ch w0, w30, wzr"

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CW``() =
    testDisasm "1ac25820" "crc32cw w0, w1, w2"
    testDisasm "1adf5bff" "crc32cw wzr, wzr, wzr"
    testDisasm "1aca5be9" "crc32cw w9, wzr, w10"
    testDisasm "1adf5bc0" "crc32cw w0, w30, wzr"

  /// C6.2.67 CRC32CB, CRC32CH, CRC32CW, CRC32CX
  [<TestMethod>]
  member _.``C6.2.67 CRC32CX``() =
    testDisasm "9ac25c20" "crc32cx w0, w1, x2"
    testDisasm "9adf5fff" "crc32cx wzr, wzr, xzr"
    testDisasm "9aca5fe9" "crc32cx w9, wzr, x10"
    testDisasm "9adf5fc0" "crc32cx w0, w30, xzr"

  /// C6.2.68 CSDB
  [<TestMethod>]
  member _.``C6.2.68 CSDB``() =
    testDisasm "d503229f" "csdb"

  /// C6.2.69 CSEL
  [<TestMethod>]
  member _.``C6.2.69 CSEL``() =
    testDisasm "1a820020" "csel w0, w1, w2, eq"
    testDisasm "9a820020" "csel x0, x1, x2, eq"
    testDisasm "1a9f03ff" "csel wzr, wzr, wzr, eq"
    testDisasm "1a8a03e9" "csel w9, wzr, w10, eq"

  /// C6.2.7 ADDS (extended register)
  [<TestMethod>]
  member _.``C6.2.7 ADDS``() =
    testDisasm "2b020020" "adds w0, w1, w2"
    testDisasm "31004020" "adds w0, w1, #0x10"
    testDisasm "b1004020" "adds x0, x1, #0x10"
    testDisasm "ab020020" "adds x0, x1, x2"

  /// C6.2.70 CSET
  [<TestMethod>]
  member _.``C6.2.70 CSET``() =
    testDisasm "1a9f17e0" "cset w0, eq"
    testDisasm "9a9f17e0" "cset x0, eq"
    testDisasm "1a9f07ff" "cset wzr, ne"
    testDisasm "1a9f07e0" "cset w0, ne"

  /// C6.2.71 CSETM
  [<TestMethod>]
  member _.``C6.2.71 CSETM``() =
    testDisasm "5a9f13e0" "csetm w0, eq"
    testDisasm "da9f13e0" "csetm x0, eq"
    testDisasm "5a9f03ff" "csetm wzr, ne"
    testDisasm "5a9f03e0" "csetm w0, ne"

  /// C6.2.72 CSINC
  [<TestMethod>]
  member _.``C6.2.72 CSINC``() =
    testDisasm "1a811420" "cinc w0, w1, eq"
    testDisasm "1a9f17e0" "cset w0, eq"
    testDisasm "1a820420" "csinc w0, w1, w2, eq"
    testDisasm "9a811420" "cinc x0, x1, eq"

  /// C6.2.73 CSINV
  [<TestMethod>]
  member _.``C6.2.73 CSINV``() =
    testDisasm "5a811020" "cinv w0, w1, eq"
    testDisasm "5a9f13e0" "csetm w0, eq"
    testDisasm "5a820020" "csinv w0, w1, w2, eq"
    testDisasm "da811020" "cinv x0, x1, eq"

  /// C6.2.74 CSNEG
  [<TestMethod>]
  member _.``C6.2.74 CSNEG``() =
    testDisasm "5a811420" "cneg w0, w1, eq"
    testDisasm "5a820420" "csneg w0, w1, w2, eq"
    testDisasm "da811420" "cneg x0, x1, eq"
    testDisasm "da820420" "csneg x0, x1, x2, eq"

  /// C6.2.75 DC
  [<TestMethod>]
  member _.``C6.2.75 DC``() =
    testDisasm "d5087620" "dc ivac, x0"
    testDisasm "d508763f" "dc ivac, xzr"
    testDisasm "d5087640" "dc isw, x0"
    testDisasm "d508765f" "dc isw, xzr"

  /// C6.2.76 DCPS1
  [<TestMethod>]
  member _.``C6.2.76 DCPS1``() =
    testDisasm "d4a10041" "dcps1 #0x802"

  /// C6.2.77 DCPS2
  [<TestMethod>]
  member _.``C6.2.77 DCPS2``() =
    testDisasm "d4a10042" "dcps2 #0x802"

  /// C6.2.78 DCPS3
  [<TestMethod>]
  member _.``C6.2.78 DCPS3``() =
    testDisasm "d4a10043" "dcps3 #0x802"

  /// C6.2.79 DGH
  [<TestMethod>]
  member _.``C6.2.79 DGH``() =
    testDisasm "d50320df" "dgh"

  /// C6.2.80 DMB
  [<TestMethod>]
  member _.``C6.2.80 DMB``() =
    testDisasm "d50330bf" "dmb #0x0"
    testDisasm "d50331bf" "dmb oshld"
    testDisasm "d50332bf" "dmb oshst"
    testDisasm "d50333bf" "dmb osh"

  /// C6.2.81 DRPS
  [<TestMethod>]
  member _.``C6.2.81 DRPS``() =
    testDisasm "d6bf03e0" "drps"

  /// C6.2.82 DSB
  [<TestMethod>]
  member _.``C6.2.82 DSB``() =
    testDisasm "d503349f" "pssbb"
    testDisasm "d503309f" "ssbb"
    testDisasm "d503319f" "dsb oshld"
    testDisasm "d503329f" "dsb oshst"

  /// C6.2.83 DVP
  [<TestMethod>]
  member _.``C6.2.83 DVP``() =
    testDisasm "d50b73a0" "dvp rctx, x0"
    testDisasm "d50b73bf" "dvp rctx, xzr"

  /// C6.2.84 EON (shifted register)
  [<TestMethod>]
  member _.``C6.2.84 EON``() =
    testDisasm "4a220020" "eon w0, w1, w2"
    testDisasm "ca220020" "eon x0, x1, x2"
    testDisasm "4a3f03ff" "eon wzr, wzr, wzr"
    testDisasm "4a2a03e9" "eon w9, wzr, w10"

  /// C6.2.85 EOR (immediate)
  [<TestMethod>]
  member _.``C6.2.85 EOR``() =
    testDisasm "d200cc20" "eor x0, x1, #0xf0f0f0f0f0f0f0f"
    testDisasm "521c0020" "eor w0, w1, #0x10"
    testDisasm "4a020020" "eor w0, w1, w2"
    testDisasm "ca020020" "eor x0, x1, x2"

  /// C6.2.87 ERET
  [<TestMethod>]
  member _.``C6.2.87 ERET``() =
    testDisasm "d69f03e0" "eret"

  /// C6.2.88 ERETAA, ERETAB
  [<TestMethod>]
  member _.``C6.2.88 ERETAA``() =
    testDisasm "d69f0bff" "eretaa"

  /// C6.2.88 ERETAA, ERETAB
  [<TestMethod>]
  member _.``C6.2.88 ERETAB``() =
    testDisasm "d69f0fff" "eretab"

  /// C6.2.89 ESB
  [<TestMethod>]
  member _.``C6.2.89 ESB``() =
    testDisasm "d503221f" "esb"

  /// C6.2.90 EXTR
  [<TestMethod>]
  member _.``C6.2.90 EXTR``() =
    testDisasm "13820c20" "extr w0, w1, w2, #3"
    testDisasm "93c20c20" "extr x0, x1, x2, #3"
    testDisasm "13820440" "ror w0, w2, #1"
    testDisasm "93c20440" "ror x0, x2, #1"

  /// C6.2.91 GMI
  [<TestMethod>]
  member _.``C6.2.91 GMI``() =
    testDisasm "9ac21420" "gmi x0, x1, x2"
    testDisasm "9adf17ff" "gmi xzr, sp, xzr"
    testDisasm "9aca17e9" "gmi x9, sp, x10"
    testDisasm "9adf17c0" "gmi x0, x30, xzr"

  /// C6.2.92 HINT
  [<TestMethod>]
  member _.``C6.2.92 HINT``() =
    testDisasm "d503219f" "autia1716"
    testDisasm "d50323bf" "autiasp"
    testDisasm "d503239f" "autiaz"
    testDisasm "d50321df" "autib1716"

  /// C6.2.93 HLT
  [<TestMethod>]
  member _.``C6.2.93 HLT``() =
    testDisasm "d44003c0" "hlt #0x1e"

  /// C6.2.94 HVC
  [<TestMethod>]
  member _.``C6.2.94 HVC``() =
    testDisasm "d4010042" "hvc #0x802"

  /// C6.2.95 IC
  [<TestMethod>]
  member _.``C6.2.95 IC``() =
    testDisasm "d508711f" "ic ialluis"
    testDisasm "d508751f" "ic iallu"
    testDisasm "d50b7520" "ic ivau, x0"
    testDisasm "d50b753f" "ic ivau, xzr"

  /// C6.2.96 IRG
  [<TestMethod>]
  member _.``C6.2.96 IRG``() =
    testDisasm "9adf1020" "irg x0, x1"
    testDisasm "9ac21020" "irg x0, x1, x2"
    testDisasm "9adf13ff" "irg sp, sp"
    testDisasm "9aca13e9" "irg x9, sp, x10"

  /// C6.2.97 ISB
  [<TestMethod>]
  member _.``C6.2.97 ISB``() =
    testDisasm "d50330df" "isb #0x0"

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDAB``() =
    testDisasm "38a20020" "ldaddab w2, w0, [x1]"
    testDisasm "38bf03ff" "ldaddab wzr, wzr, [sp]"
    testDisasm "38aa03e9" "ldaddab w10, w9, [sp]"
    testDisasm "38bf03c0" "ldaddab wzr, w0, [x30]"

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDALB``() =
    testDisasm "38e20020" "ldaddalb w2, w0, [x1]"
    testDisasm "38ff03ff" "ldaddalb wzr, wzr, [sp]"
    testDisasm "38ea03e9" "ldaddalb w10, w9, [sp]"
    testDisasm "38ff03c0" "ldaddalb wzr, w0, [x30]"

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDB``() =
    testDisasm "38220020" "ldaddb w2, w0, [x1]"
    testDisasm "3822003f" "staddb w2, [x1]"
    testDisasm "383f03ff" "staddb wzr, [sp]"
    testDisasm "382a03e9" "ldaddb w10, w9, [sp]"

  /// C6.2.98 LDADDB, LDADDAB, LDADDALB, LDADDLB
  [<TestMethod>]
  member _.``C6.2.98 LDADDLB``() =
    testDisasm "38620020" "ldaddlb w2, w0, [x1]"
    testDisasm "3862003f" "staddlb w2, [x1]"
    testDisasm "387f03ff" "staddlb wzr, [sp]"
    testDisasm "386a03e9" "ldaddlb w10, w9, [sp]"

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDAH``() =
    testDisasm "78a20020" "ldaddah w2, w0, [x1]"
    testDisasm "78bf03ff" "ldaddah wzr, wzr, [sp]"
    testDisasm "78aa03e9" "ldaddah w10, w9, [sp]"
    testDisasm "78bf03c0" "ldaddah wzr, w0, [x30]"

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDALH``() =
    testDisasm "78e20020" "ldaddalh w2, w0, [x1]"
    testDisasm "78ff03ff" "ldaddalh wzr, wzr, [sp]"
    testDisasm "78ea03e9" "ldaddalh w10, w9, [sp]"
    testDisasm "78ff03c0" "ldaddalh wzr, w0, [x30]"

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDH``() =
    testDisasm "78220020" "ldaddh w2, w0, [x1]"
    testDisasm "7822003f" "staddh w2, [x1]"
    testDisasm "783f03ff" "staddh wzr, [sp]"
    testDisasm "782a03e9" "ldaddh w10, w9, [sp]"

  /// C6.2.99 LDADDH, LDADDAH, LDADDALH, LDADDLH
  [<TestMethod>]
  member _.``C6.2.99 LDADDLH``() =
    testDisasm "78620020" "ldaddlh w2, w0, [x1]"
    testDisasm "7862003f" "staddlh w2, [x1]"
    testDisasm "787f03ff" "staddlh wzr, [sp]"
    testDisasm "786a03e9" "ldaddlh w10, w9, [sp]"

  /// C7.2.1 ABS
  [<TestMethod>]
  member _.``C7.2.1 ABS``() =
    testDisasm "0e20b820" "abs v0.8b, v1.8b"
    testDisasm "0e60b820" "abs v0.4h, v1.4h"
    testDisasm "0ea0b820" "abs v0.2s, v1.2s"
    testDisasm "4ee0b820" "abs v0.2d, v1.2d"

  /// C7.2.10 AESMC
  [<TestMethod>]
  member _.``C7.2.10 AESMC``() =
    testDisasm "4e286820" "aesmc v0.16b, v1.16b"

  /// C7.2.100 FMADD
  [<TestMethod>]
  member _.``C7.2.100 FMADD``() =
    testDisasm "1fc20c20" "fmadd h0, h1, h2, h3"
    testDisasm "1f020c20" "fmadd s0, s1, s2, s3"
    testDisasm "1f420c20" "fmadd d0, d1, d2, d3"

  /// C7.2.101 FMAX (vector)
  [<TestMethod>]
  member _.``C7.2.101 FMAX``() =
    testDisasm "0e423420" "fmax v0.4h, v1.4h, v2.4h"
    testDisasm "0e22f420" "fmax v0.2s, v1.2s, v2.2s"
    testDisasm "4e62f420" "fmax v0.2d, v1.2d, v2.2d"
    testDisasm "1ee24820" "fmax h0, h1, h2"

  /// C7.2.103 FMAXNM (vector)
  [<TestMethod>]
  member _.``C7.2.103 FMAXNM``() =
    testDisasm "0e420420" "fmaxnm v0.4h, v1.4h, v2.4h"
    testDisasm "0e22c420" "fmaxnm v0.2s, v1.2s, v2.2s"
    testDisasm "4e62c420" "fmaxnm v0.2d, v1.2d, v2.2d"
    testDisasm "1ee26820" "fmaxnm h0, h1, h2"

  /// C7.2.105 FMAXNMP (scalar)
  [<TestMethod>]
  member _.``C7.2.105 FMAXNMP``() =
    testDisasm "2e420420" "fmaxnmp v0.4h, v1.4h, v2.4h"
    testDisasm "2e22c420" "fmaxnmp v0.2s, v1.2s, v2.2s"
    testDisasm "6e62c420" "fmaxnmp v0.2d, v1.2d, v2.2d"
    testDisasm "5e30c843" "fmaxnmp h3, v2.2h"

  /// C7.2.107 FMAXNMV
  [<TestMethod>]
  member _.``C7.2.107 FMAXNMV``() =
    testDisasm "6e30c820" "fmaxnmv s0, v1.4s"
    testDisasm "0e30c843" "fmaxnmv h3, v2.4h"

  /// C7.2.108 FMAXP (scalar)
  [<TestMethod>]
  member _.``C7.2.108 FMAXP``() =
    testDisasm "2e423420" "fmaxp v0.4h, v1.4h, v2.4h"
    testDisasm "2e22f420" "fmaxp v0.2s, v1.2s, v2.2s"
    testDisasm "6e62f420" "fmaxp v0.2d, v1.2d, v2.2d"
    testDisasm "5e30f843" "fmaxp h3, v2.2h"

  /// C7.2.110 FMAXV
  [<TestMethod>]
  member _.``C7.2.110 FMAXV``() =
    testDisasm "6e30f820" "fmaxv s0, v1.4s"
    testDisasm "0e30f843" "fmaxv h3, v2.4h"

  /// C7.2.111 FMIN (vector)
  [<TestMethod>]
  member _.``C7.2.111 FMIN``() =
    testDisasm "0ec23420" "fmin v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2f420" "fmin v0.2s, v1.2s, v2.2s"
    testDisasm "4ee2f420" "fmin v0.2d, v1.2d, v2.2d"
    testDisasm "1ee25820" "fmin h0, h1, h2"

  /// C7.2.113 FMINNM (vector)
  [<TestMethod>]
  member _.``C7.2.113 FMINNM``() =
    testDisasm "0ec20420" "fminnm v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2c420" "fminnm v0.2s, v1.2s, v2.2s"
    testDisasm "4ee2c420" "fminnm v0.2d, v1.2d, v2.2d"
    testDisasm "1ee27820" "fminnm h0, h1, h2"

  /// C7.2.115 FMINNMP (scalar)
  [<TestMethod>]
  member _.``C7.2.115 FMINNMP``() =
    testDisasm "2ec20420" "fminnmp v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2c420" "fminnmp v0.2s, v1.2s, v2.2s"
    testDisasm "6ee2c420" "fminnmp v0.2d, v1.2d, v2.2d"
    testDisasm "5eb0c843" "fminnmp h3, v2.2h"

  /// C7.2.117 FMINNMV
  [<TestMethod>]
  member _.``C7.2.117 FMINNMV``() =
    testDisasm "6eb0c820" "fminnmv s0, v1.4s"
    testDisasm "0eb0c843" "fminnmv h3, v2.4h"

  /// C7.2.118 FMINP (scalar)
  [<TestMethod>]
  member _.``C7.2.118 FMINP``() =
    testDisasm "2ec23420" "fminp v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2f420" "fminp v0.2s, v1.2s, v2.2s"
    testDisasm "6ee2f420" "fminp v0.2d, v1.2d, v2.2d"
    testDisasm "5eb0f843" "fminp h3, v2.2h"

  /// C7.2.12 BCAX
  [<TestMethod>]
  member _.``C7.2.12 BCAX``() =
    testDisasm "ce220c20" "bcax v0.16b, v1.16b, v2.16b, v3.16b"

  /// C7.2.120 FMINV
  [<TestMethod>]
  member _.``C7.2.120 FMINV``() =
    testDisasm "6eb0f820" "fminv s0, v1.4s"
    testDisasm "0eb0f843" "fminv h3, v2.4h"

  /// C7.2.121 FMLA (by element)
  [<TestMethod>]
  member _.``C7.2.121 FMLA``() =
    testDisasm "5f121020" "fmla h0, h1, v2.h[1]"
    testDisasm "0f121020" "fmla v0.4h, v1.4h, v2.h[1]"
    testDisasm "0fa21020" "fmla v0.2s, v1.2s, v2.s[1]"
    testDisasm "4fc21820" "fmla v0.2d, v1.2d, v2.d[1]"

  /// C7.2.123 FMLAL, FMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.123 FMLAL``() =
    testDisasm "0e22ec20" "fmlal v0.2s, v1.2h, v2.2h"
    testDisasm "4f920020" "fmlal v0.4s, v1.4h, v2.h[1]"
