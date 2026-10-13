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
/// One test for each instruction DDI0487F.c describes, FMLAL2 to SMLSL in
/// the order of its sections. Each reads words of the instruction and checks
/// the text, and each word's text is one binutils' objdump reads the word as
/// too, so what is asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualParserTests5() =
  let parser =
    Parser(BinReader.Init Endian.Big) :> IInstructionParsable

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// C7.2.123 FMLAL, FMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.123 FMLAL2``() =
    testDisasm "6e22cc20" "fmlal2 v0.4s, v1.4h, v2.4h"
    testDisasm "2f818043" "fmlal2 v3.2s, v2.2h, v1.h[0]"

  /// C7.2.125 FMLS (by element)
  [<TestMethod>]
  member _.``C7.2.125 FMLS``() =
    testDisasm "5f125020" "fmls h0, h1, v2.h[1]"
    testDisasm "0f125020" "fmls v0.4h, v1.4h, v2.h[1]"
    testDisasm "0fa25020" "fmls v0.2s, v1.2s, v2.s[1]"
    testDisasm "4fc25820" "fmls v0.2d, v1.2d, v2.d[1]"

  /// C7.2.127 FMLSL, FMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.127 FMLSL``() =
    testDisasm "0ea2ec20" "fmlsl v0.2s, v1.2h, v2.2h"
    testDisasm "4f924020" "fmlsl v0.4s, v1.4h, v2.h[1]"

  /// C7.2.127 FMLSL, FMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.127 FMLSL2``() =
    testDisasm "6ea2cc20" "fmlsl2 v0.4s, v1.4h, v2.4h"
    testDisasm "2f81c043" "fmlsl2 v3.2s, v2.2h, v1.h[0]"

  /// C7.2.129 FMOV (vector, immediate)
  [<TestMethod>]
  member _.``C7.2.129 FMOV``() =
    testDisasm "9e670020" "fmov d0, x1"
    testDisasm "0f01fe00" "fmov v0.4h, #16.00000000"
    testDisasm "0f01f600" "fmov v0.2s, #16.00000000"
    testDisasm "6f01f600" "fmov v0.2d, #16.00000000"

  /// C7.2.13 BFCVT
  [<TestMethod>]
  member _.``C7.2.13 BFCVT``() =
    testDisasm "1e634020" "bfcvt h0, s1"

  /// C7.2.133 FMSUB
  [<TestMethod>]
  member _.``C7.2.133 FMSUB``() =
    testDisasm "1fc28c20" "fmsub h0, h1, h2, h3"
    testDisasm "1f028c20" "fmsub s0, s1, s2, s3"
    testDisasm "1f428c20" "fmsub d0, d1, d2, d3"

  /// C7.2.134 FMUL (by element)
  [<TestMethod>]
  member _.``C7.2.134 FMUL``() =
    testDisasm "5f129020" "fmul h0, h1, v2.h[1]"
    testDisasm "0f129020" "fmul v0.4h, v1.4h, v2.h[1]"
    testDisasm "0fa29020" "fmul v0.2s, v1.2s, v2.s[1]"
    testDisasm "4fc29820" "fmul v0.2d, v1.2d, v2.d[1]"

  /// C7.2.137 FMULX (by element)
  [<TestMethod>]
  member _.``C7.2.137 FMULX``() =
    testDisasm "7f129020" "fmulx h0, h1, v2.h[1]"
    testDisasm "2f129020" "fmulx v0.4h, v1.4h, v2.h[1]"
    testDisasm "2fa29020" "fmulx v0.2s, v1.2s, v2.s[1]"
    testDisasm "6fc29820" "fmulx v0.2d, v1.2d, v2.d[1]"

  /// C7.2.139 FNEG (vector)
  [<TestMethod>]
  member _.``C7.2.139 FNEG``() =
    testDisasm "2ef8f820" "fneg v0.4h, v1.4h"
    testDisasm "2ea0f820" "fneg v0.2s, v1.2s"
    testDisasm "6ee0f820" "fneg v0.2d, v1.2d"
    testDisasm "1ee14020" "fneg h0, h1"

  /// C7.2.14 BFCVTN, BFCVTN2
  [<TestMethod>]
  member _.``C7.2.14 BFCVTN``() =
    testDisasm "0ea16820" "bfcvtn v0.4h, v1.4s"

  /// C7.2.14 BFCVTN, BFCVTN2
  [<TestMethod>]
  member _.``C7.2.14 BFCVTN2``() =
    testDisasm "4ea16820" "bfcvtn2 v0.8h, v1.4s"

  /// C7.2.141 FNMADD
  [<TestMethod>]
  member _.``C7.2.141 FNMADD``() =
    testDisasm "1fe20c20" "fnmadd h0, h1, h2, h3"
    testDisasm "1f620c20" "fnmadd d0, d1, d2, d3"
    testDisasm "1f220c20" "fnmadd s0, s1, s2, s3"

  /// C7.2.142 FNMSUB
  [<TestMethod>]
  member _.``C7.2.142 FNMSUB``() =
    testDisasm "1fe28c20" "fnmsub h0, h1, h2, h3"
    testDisasm "1f228c20" "fnmsub s0, s1, s2, s3"
    testDisasm "1f628c20" "fnmsub d0, d1, d2, d3"

  /// C7.2.143 FNMUL (scalar)
  [<TestMethod>]
  member _.``C7.2.143 FNMUL``() =
    testDisasm "1ee28820" "fnmul h0, h1, h2"
    testDisasm "1e228820" "fnmul s0, s1, s2"
    testDisasm "1e628820" "fnmul d0, d1, d2"

  /// C7.2.144 FRECPE
  [<TestMethod>]
  member _.``C7.2.144 FRECPE``() =
    testDisasm "5ef9d820" "frecpe h0, h1"
    testDisasm "0ef9d820" "frecpe v0.4h, v1.4h"
    testDisasm "0ea1d820" "frecpe v0.2s, v1.2s"
    testDisasm "4ee1d820" "frecpe v0.2d, v1.2d"

  /// C7.2.145 FRECPS
  [<TestMethod>]
  member _.``C7.2.145 FRECPS``() =
    testDisasm "5e423c20" "frecps h0, h1, h2"
    testDisasm "0e423c20" "frecps v0.4h, v1.4h, v2.4h"
    testDisasm "0e22fc20" "frecps v0.2s, v1.2s, v2.2s"
    testDisasm "4e62fc20" "frecps v0.2d, v1.2d, v2.2d"

  /// C7.2.146 FRECPX
  [<TestMethod>]
  member _.``C7.2.146 FRECPX``() =
    testDisasm "5ef9f820" "frecpx h0, h1"
    testDisasm "5ee1f820" "frecpx d0, d1"
    testDisasm "5ea1f843" "frecpx s3, s2"

  /// C7.2.147 FRINT32X (vector)
  [<TestMethod>]
  member _.``C7.2.147 FRINT32X``() =
    testDisasm "1e68c020" "frint32x d0, d1"
    testDisasm "2e21e820" "frint32x v0.2s, v1.2s"
    testDisasm "6e61e820" "frint32x v0.2d, v1.2d"
    testDisasm "1e28c020" "frint32x s0, s1"

  /// C7.2.149 FRINT32Z (vector)
  [<TestMethod>]
  member _.``C7.2.149 FRINT32Z``() =
    testDisasm "1e684020" "frint32z d0, d1"
    testDisasm "0e21e820" "frint32z v0.2s, v1.2s"
    testDisasm "4e61e820" "frint32z v0.2d, v1.2d"
    testDisasm "1e284020" "frint32z s0, s1"

  /// C7.2.15 BFDOT (by element)
  [<TestMethod>]
  member _.``C7.2.15 BFDOT``() =
    testDisasm "2e42fc20" "bfdot v0.2s, v1.4h, v2.4h"
    testDisasm "0f62f020" "bfdot v0.2s, v1.4h, v2.2h[1]"

  /// C7.2.151 FRINT64X (vector)
  [<TestMethod>]
  member _.``C7.2.151 FRINT64X``() =
    testDisasm "1e69c020" "frint64x d0, d1"
    testDisasm "2e21f820" "frint64x v0.2s, v1.2s"
    testDisasm "6e61f820" "frint64x v0.2d, v1.2d"
    testDisasm "1e29c020" "frint64x s0, s1"

  /// C7.2.153 FRINT64Z (vector)
  [<TestMethod>]
  member _.``C7.2.153 FRINT64Z``() =
    testDisasm "1e694020" "frint64z d0, d1"
    testDisasm "0e21f820" "frint64z v0.2s, v1.2s"
    testDisasm "4e61f820" "frint64z v0.2d, v1.2d"
    testDisasm "1e294020" "frint64z s0, s1"

  /// C7.2.155 FRINTA (vector)
  [<TestMethod>]
  member _.``C7.2.155 FRINTA``() =
    testDisasm "2e798820" "frinta v0.4h, v1.4h"
    testDisasm "2e218820" "frinta v0.2s, v1.2s"
    testDisasm "6e618820" "frinta v0.2d, v1.2d"
    testDisasm "1ee64020" "frinta h0, h1"

  /// C7.2.157 FRINTI (vector)
  [<TestMethod>]
  member _.``C7.2.157 FRINTI``() =
    testDisasm "2ef99820" "frinti v0.4h, v1.4h"
    testDisasm "2ea19820" "frinti v0.2s, v1.2s"
    testDisasm "6ee19820" "frinti v0.2d, v1.2d"
    testDisasm "1ee7c020" "frinti h0, h1"

  /// C7.2.159 FRINTM (vector)
  [<TestMethod>]
  member _.``C7.2.159 FRINTM``() =
    testDisasm "0e799820" "frintm v0.4h, v1.4h"
    testDisasm "0e219820" "frintm v0.2s, v1.2s"
    testDisasm "4e619820" "frintm v0.2d, v1.2d"
    testDisasm "1ee54020" "frintm h0, h1"

  /// C7.2.161 FRINTN (vector)
  [<TestMethod>]
  member _.``C7.2.161 FRINTN``() =
    testDisasm "0e798820" "frintn v0.4h, v1.4h"
    testDisasm "0e218820" "frintn v0.2s, v1.2s"
    testDisasm "4e618820" "frintn v0.2d, v1.2d"
    testDisasm "1ee44020" "frintn h0, h1"

  /// C7.2.163 FRINTP (vector)
  [<TestMethod>]
  member _.``C7.2.163 FRINTP``() =
    testDisasm "0ef98820" "frintp v0.4h, v1.4h"
    testDisasm "0ea18820" "frintp v0.2s, v1.2s"
    testDisasm "4ee18820" "frintp v0.2d, v1.2d"
    testDisasm "1ee4c020" "frintp h0, h1"

  /// C7.2.165 FRINTX (vector)
  [<TestMethod>]
  member _.``C7.2.165 FRINTX``() =
    testDisasm "2e799820" "frintx v0.4h, v1.4h"
    testDisasm "2e219820" "frintx v0.2s, v1.2s"
    testDisasm "6e619820" "frintx v0.2d, v1.2d"
    testDisasm "1ee74020" "frintx h0, h1"

  /// C7.2.167 FRINTZ (vector)
  [<TestMethod>]
  member _.``C7.2.167 FRINTZ``() =
    testDisasm "0ef99820" "frintz v0.4h, v1.4h"
    testDisasm "0ea19820" "frintz v0.2s, v1.2s"
    testDisasm "4ee19820" "frintz v0.2d, v1.2d"
    testDisasm "1ee5c020" "frintz h0, h1"

  /// C7.2.169 FRSQRTE
  [<TestMethod>]
  member _.``C7.2.169 FRSQRTE``() =
    testDisasm "7ef9d820" "frsqrte h0, h1"
    testDisasm "2ef9d820" "frsqrte v0.4h, v1.4h"
    testDisasm "2ea1d820" "frsqrte v0.2s, v1.2s"
    testDisasm "6ee1d820" "frsqrte v0.2d, v1.2d"

  /// C7.2.17 BFMLALB, BFMLALT (by element)
  [<TestMethod>]
  member _.``C7.2.17 BFMLALB``() =
    testDisasm "2ec2fc20" "bfmlalb v0.4s, v1.8h, v2.8h"
    testDisasm "0fc1f043" "bfmlalb v3.4s, v2.8h, v1.h[0]"

  /// C7.2.17 BFMLALB, BFMLALT (by element)
  [<TestMethod>]
  member _.``C7.2.17 BFMLALT``() =
    testDisasm "6ec2fc20" "bfmlalt v0.4s, v1.8h, v2.8h"
    testDisasm "4fc1f043" "bfmlalt v3.4s, v2.8h, v1.h[0]"

  /// C7.2.170 FRSQRTS
  [<TestMethod>]
  member _.``C7.2.170 FRSQRTS``() =
    testDisasm "5ec23c20" "frsqrts h0, h1, h2"
    testDisasm "0ec23c20" "frsqrts v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2fc20" "frsqrts v0.2s, v1.2s, v2.2s"
    testDisasm "4ee2fc20" "frsqrts v0.2d, v1.2d, v2.2d"

  /// C7.2.171 FSQRT (vector)
  [<TestMethod>]
  member _.``C7.2.171 FSQRT``() =
    testDisasm "2ef9f820" "fsqrt v0.4h, v1.4h"
    testDisasm "2ea1f820" "fsqrt v0.2s, v1.2s"
    testDisasm "6ee1f820" "fsqrt v0.2d, v1.2d"
    testDisasm "1ee1c020" "fsqrt h0, h1"

  /// C7.2.173 FSUB (vector)
  [<TestMethod>]
  member _.``C7.2.173 FSUB``() =
    testDisasm "0ec21420" "fsub v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2d420" "fsub v0.2s, v1.2s, v2.2s"
    testDisasm "4ee2d420" "fsub v0.2d, v1.2d, v2.2d"
    testDisasm "1ee23820" "fsub h0, h1, h2"

  /// C7.2.175 INS (element)
  [<TestMethod>]
  member _.``C7.2.175 INS``() =
    testDisasm "4e081c20" "ins v0.d[0], x1"
    testDisasm "4e011c43" "ins v3.b[0], w2"
    testDisasm "4e141eb6" "ins v22.s[2], w21"
    testDisasm "4e1f1fff" "ins v31.b[15], wzr"

  /// C7.2.177 LD1 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.177 LD1``() =
    testDisasm "4c407020" "ld1 { v0.16b }, [x1]"
    testDisasm "0c4023c0" "ld1 { v0.8b - v3.8b }, [x30]"
    testDisasm "0c4027c0" "ld1 { v0.4h - v3.4h }, [x30]"
    testDisasm "0c402bc0" "ld1 { v0.2s - v3.2s }, [x30]"

  /// C7.2.179 LD1R
  [<TestMethod>]
  member _.``C7.2.179 LD1R``() =
    testDisasm "4d40c020" "ld1r { v0.16b }, [x1]"
    testDisasm "0d40c7c0" "ld1r { v0.4h }, [x30]"
    testDisasm "0d40cbc0" "ld1r { v0.2s }, [x30]"
    testDisasm "0d40cfc0" "ld1r { v0.1d }, [x30]"

  /// C7.2.180 LD2 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.180 LD2``() =
    testDisasm "4c408020" "ld2 { v0.16b, v1.16b }, [x1]"
    testDisasm "0c4087c0" "ld2 { v0.4h, v1.4h }, [x30]"
    testDisasm "0c408bc0" "ld2 { v0.2s, v1.2s }, [x30]"
    testDisasm "0cc18043" "ld2 { v3.8b, v4.8b }, [x2], x1"

  /// C7.2.182 LD2R
  [<TestMethod>]
  member _.``C7.2.182 LD2R``() =
    testDisasm "4d60c020" "ld2r { v0.16b, v1.16b }, [x1]"
    testDisasm "0d60c7c0" "ld2r { v0.4h, v1.4h }, [x30]"
    testDisasm "0d60cbc0" "ld2r { v0.2s, v1.2s }, [x30]"
    testDisasm "0d60cfc0" "ld2r { v0.1d, v1.1d }, [x30]"

  /// C7.2.183 LD3 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.183 LD3``() =
    testDisasm "4c404020" "ld3 { v0.16b, v1.16b, v2.16b }, [x1]"
    testDisasm "0c4047c0" "ld3 { v0.4h, v1.4h, v2.4h }, [x30]"
    testDisasm "0c404bc0" "ld3 { v0.2s, v1.2s, v2.2s }, [x30]"
    testDisasm "0cc14043" "ld3 { v3.8b, v4.8b, v5.8b }, [x2], x1"

  /// C7.2.185 LD3R
  [<TestMethod>]
  member _.``C7.2.185 LD3R``() =
    testDisasm "4d40e020" "ld3r { v0.16b, v1.16b, v2.16b }, [x1]"
    testDisasm "0d40e7c0" "ld3r { v0.4h, v1.4h, v2.4h }, [x30]"
    testDisasm "0d40ebc0" "ld3r { v0.2s, v1.2s, v2.2s }, [x30]"
    testDisasm "0d40efc0" "ld3r { v0.1d, v1.1d, v2.1d }, [x30]"

  /// C7.2.186 LD4 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.186 LD4``() =
    testDisasm "4c400020" "ld4 { v0.16b - v3.16b }, [x1]"
    testDisasm "0c4007c0" "ld4 { v0.4h - v3.4h }, [x30]"
    testDisasm "0c400bc0" "ld4 { v0.2s - v3.2s }, [x30]"
    testDisasm "0cc10043" "ld4 { v3.8b - v6.8b }, [x2], x1"

  /// C7.2.188 LD4R
  [<TestMethod>]
  member _.``C7.2.188 LD4R``() =
    testDisasm "4d60e020" "ld4r { v0.16b - v3.16b }, [x1]"
    testDisasm "0d60e7c0" "ld4r { v0.4h - v3.4h }, [x30]"
    testDisasm "0d60ebc0" "ld4r { v0.2s - v3.2s }, [x30]"
    testDisasm "0d60efc0" "ld4r { v0.1d - v3.1d }, [x30]"

  /// C7.2.19 BFMMLA
  [<TestMethod>]
  member _.``C7.2.19 BFMMLA``() =
    testDisasm "6e42ec20" "bfmmla v0.4s, v1.8h, v2.8h"

  /// C7.2.195 MLA (by element)
  [<TestMethod>]
  member _.``C7.2.195 MLA``() =
    testDisasm "2f520020" "mla v0.4h, v1.4h, v2.h[1]"
    testDisasm "2fa20020" "mla v0.2s, v1.2s, v2.s[1]"
    testDisasm "0e229420" "mla v0.8b, v1.8b, v2.8b"
    testDisasm "0e629420" "mla v0.4h, v1.4h, v2.4h"

  /// C7.2.197 MLS (by element)
  [<TestMethod>]
  member _.``C7.2.197 MLS``() =
    testDisasm "2f524020" "mls v0.4h, v1.4h, v2.h[1]"
    testDisasm "2fa24020" "mls v0.2s, v1.2s, v2.s[1]"
    testDisasm "2e229420" "mls v0.8b, v1.8b, v2.8b"
    testDisasm "2e629420" "mls v0.4h, v1.4h, v2.4h"

  /// C7.2.204 MOVI
  [<TestMethod>]
  member _.``C7.2.204 MOVI``() =
    testDisasm "0f00e460" "movi v0.8b, #0x3"
    testDisasm "0f008460" "movi v0.4h, #0x3"
    testDisasm "0f000460" "movi v0.2s, #0x3"
    testDisasm "0f012443" "movi v3.2s, #0x22, lsl #0x8"

  /// C7.2.208 MVNI
  [<TestMethod>]
  member _.``C7.2.208 MVNI``() =
    testDisasm "2f008460" "mvni v0.4h, #0x3"
    testDisasm "2f000460" "mvni v0.2s, #0x3"
    testDisasm "2f012443" "mvni v3.2s, #0x22, lsl #0x8"
    testDisasm "2f01a443" "mvni v3.4h, #0x22, lsl #0x8"

  /// C7.2.210 NOT
  [<TestMethod>]
  member _.``C7.2.210 NOT``() =
    testDisasm "6e205820" "mvn v0.16b, v1.16b"

  /// C7.2.214 PMUL
  [<TestMethod>]
  member _.``C7.2.214 PMUL``() =
    testDisasm "2e229c20" "pmul v0.8b, v1.8b, v2.8b"

  /// C7.2.215 PMULL, PMULL2
  [<TestMethod>]
  member _.``C7.2.215 PMULL``() =
    testDisasm "0e22e020" "pmull v0.8h, v1.8b, v2.8b"
    testDisasm "0ee1e043" "pmull v3.1q, v2.1d, v1.1d"

  /// C7.2.215 PMULL, PMULL2
  [<TestMethod>]
  member _.``C7.2.215 PMULL2``() =
    testDisasm "4e22e020" "pmull2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ee1e043" "pmull2 v3.1q, v2.2d, v1.2d"

  /// C7.2.216 RADDHN, RADDHN2
  [<TestMethod>]
  member _.``C7.2.216 RADDHN``() =
    testDisasm "2e224020" "raddhn v0.8b, v1.8h, v2.8h"
    testDisasm "2ea24020" "raddhn v0.2s, v1.2d, v2.2d"
    testDisasm "2e624020" "raddhn v0.4h, v1.4s, v2.4s"

  /// C7.2.216 RADDHN, RADDHN2
  [<TestMethod>]
  member _.``C7.2.216 RADDHN2``() =
    testDisasm "6e624020" "raddhn2 v0.8h, v1.4s, v2.4s"
    testDisasm "6ea24020" "raddhn2 v0.4s, v1.2d, v2.2d"
    testDisasm "6e224020" "raddhn2 v0.16b, v1.8h, v2.8h"

  /// C7.2.217 RAX1
  [<TestMethod>]
  member _.``C7.2.217 RAX1``() =
    testDisasm "ce628c20" "rax1 v0.2d, v1.2d, v2.2d"

  /// C7.2.22 BIF
  [<TestMethod>]
  member _.``C7.2.22 BIF``() =
    testDisasm "6ee21c20" "bif v0.16b, v1.16b, v2.16b"

  /// C7.2.222 RSHRN, RSHRN2
  [<TestMethod>]
  member _.``C7.2.222 RSHRN``() =
    testDisasm "0f1f8c20" "rshrn v0.4h, v1.4s, #0x1"
    testDisasm "0f0f8c20" "rshrn v0.8b, v1.8h, #0x1"
    testDisasm "0f3f8c20" "rshrn v0.2s, v1.2d, #0x1"

  /// C7.2.222 RSHRN, RSHRN2
  [<TestMethod>]
  member _.``C7.2.222 RSHRN2``() =
    testDisasm "4f1f8c20" "rshrn2 v0.8h, v1.4s, #0x1"
    testDisasm "4f3f8c20" "rshrn2 v0.4s, v1.2d, #0x1"
    testDisasm "4f0f8c20" "rshrn2 v0.16b, v1.8h, #0x1"

  /// C7.2.223 RSUBHN, RSUBHN2
  [<TestMethod>]
  member _.``C7.2.223 RSUBHN``() =
    testDisasm "2e226020" "rsubhn v0.8b, v1.8h, v2.8h"
    testDisasm "2ea26020" "rsubhn v0.2s, v1.2d, v2.2d"
    testDisasm "2e626020" "rsubhn v0.4h, v1.4s, v2.4s"

  /// C7.2.223 RSUBHN, RSUBHN2
  [<TestMethod>]
  member _.``C7.2.223 RSUBHN2``() =
    testDisasm "6e626020" "rsubhn2 v0.8h, v1.4s, v2.4s"
    testDisasm "6ea26020" "rsubhn2 v0.4s, v1.2d, v2.2d"
    testDisasm "6e226020" "rsubhn2 v0.16b, v1.8h, v2.8h"

  /// C7.2.224 SABA
  [<TestMethod>]
  member _.``C7.2.224 SABA``() =
    testDisasm "0e227c20" "saba v0.8b, v1.8b, v2.8b"
    testDisasm "0e627c20" "saba v0.4h, v1.4h, v2.4h"
    testDisasm "0ea27c20" "saba v0.2s, v1.2s, v2.2s"

  /// C7.2.225 SABAL, SABAL2
  [<TestMethod>]
  member _.``C7.2.225 SABAL``() =
    testDisasm "0e625020" "sabal v0.4s, v1.4h, v2.4h"
    testDisasm "0e225020" "sabal v0.8h, v1.8b, v2.8b"
    testDisasm "0ea25020" "sabal v0.2d, v1.2s, v2.2s"

  /// C7.2.225 SABAL, SABAL2
  [<TestMethod>]
  member _.``C7.2.225 SABAL2``() =
    testDisasm "4e225020" "sabal2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ea25020" "sabal2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e625020" "sabal2 v0.4s, v1.8h, v2.8h"

  /// C7.2.226 SABD
  [<TestMethod>]
  member _.``C7.2.226 SABD``() =
    testDisasm "0e227420" "sabd v0.8b, v1.8b, v2.8b"
    testDisasm "0e627420" "sabd v0.4h, v1.4h, v2.4h"
    testDisasm "0ea27420" "sabd v0.2s, v1.2s, v2.2s"

  /// C7.2.227 SABDL, SABDL2
  [<TestMethod>]
  member _.``C7.2.227 SABDL``() =
    testDisasm "0e627020" "sabdl v0.4s, v1.4h, v2.4h"
    testDisasm "0e227020" "sabdl v0.8h, v1.8b, v2.8b"
    testDisasm "0ea27020" "sabdl v0.2d, v1.2s, v2.2s"

  /// C7.2.227 SABDL, SABDL2
  [<TestMethod>]
  member _.``C7.2.227 SABDL2``() =
    testDisasm "4e227020" "sabdl2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ea27020" "sabdl2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e627020" "sabdl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.228 SADALP
  [<TestMethod>]
  member _.``C7.2.228 SADALP``() =
    testDisasm "0e206820" "sadalp v0.4h, v1.8b"
    testDisasm "0e606820" "sadalp v0.2s, v1.4h"
    testDisasm "4ea06820" "sadalp v0.2d, v1.4s"

  /// C7.2.229 SADDL, SADDL2
  [<TestMethod>]
  member _.``C7.2.229 SADDL``() =
    testDisasm "0e620020" "saddl v0.4s, v1.4h, v2.4h"
    testDisasm "0e220020" "saddl v0.8h, v1.8b, v2.8b"
    testDisasm "0ea20020" "saddl v0.2d, v1.2s, v2.2s"

  /// C7.2.229 SADDL, SADDL2
  [<TestMethod>]
  member _.``C7.2.229 SADDL2``() =
    testDisasm "4e220020" "saddl2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ea20020" "saddl2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e620020" "saddl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.23 BIT
  [<TestMethod>]
  member _.``C7.2.23 BIT``() =
    testDisasm "6ea21c20" "bit v0.16b, v1.16b, v2.16b"

  /// C7.2.230 SADDLP
  [<TestMethod>]
  member _.``C7.2.230 SADDLP``() =
    testDisasm "0e202820" "saddlp v0.4h, v1.8b"
    testDisasm "0e602820" "saddlp v0.2s, v1.4h"
    testDisasm "4ea02820" "saddlp v0.2d, v1.4s"

  /// C7.2.231 SADDLV
  [<TestMethod>]
  member _.``C7.2.231 SADDLV``() =
    testDisasm "0e303820" "saddlv h0, v1.8b"
    testDisasm "0e703843" "saddlv s3, v2.4h"
    testDisasm "4eb03843" "saddlv d3, v2.4s"

  /// C7.2.232 SADDW, SADDW2
  [<TestMethod>]
  member _.``C7.2.232 SADDW``() =
    testDisasm "0e621020" "saddw v0.4s, v1.4s, v2.4h"
    testDisasm "0e221020" "saddw v0.8h, v1.8h, v2.8b"
    testDisasm "0ea21020" "saddw v0.2d, v1.2d, v2.2s"

  /// C7.2.232 SADDW, SADDW2
  [<TestMethod>]
  member _.``C7.2.232 SADDW2``() =
    testDisasm "4e221020" "saddw2 v0.8h, v1.8h, v2.16b"
    testDisasm "4ea21020" "saddw2 v0.2d, v1.2d, v2.4s"
    testDisasm "4e621020" "saddw2 v0.4s, v1.4s, v2.8h"

  /// C7.2.233 SCVTF (vector, fixed-point)
  [<TestMethod>]
  member _.``C7.2.233 SCVTF``() =
    testDisasm "0f1be420" "scvtf v0.4h, v1.4h, #5"
    testDisasm "0f3be420" "scvtf v0.2s, v1.2s, #5"
    testDisasm "4f7be420" "scvtf v0.2d, v1.2d, #5"
    testDisasm "5e79d820" "scvtf h0, h1"

  /// C7.2.237 SDOT (by element)
  [<TestMethod>]
  member _.``C7.2.237 SDOT``() =
    testDisasm "0e829420" "sdot v0.2s, v1.8b, v2.8b"
    testDisasm "0f81e043" "sdot v3.2s, v2.8b, v1.4b[0]"

  /// C7.2.239 SHA1C
  [<TestMethod>]
  member _.``C7.2.239 SHA1C``() =
    testDisasm "5e020020" "sha1c q0, s1, v2.4s"

  /// C7.2.24 BSL
  [<TestMethod>]
  member _.``C7.2.24 BSL``() =
    testDisasm "6e621c20" "bsl v0.16b, v1.16b, v2.16b"

  /// C7.2.240 SHA1H
  [<TestMethod>]
  member _.``C7.2.240 SHA1H``() =
    testDisasm "5e280820" "sha1h s0, s1"

  /// C7.2.241 SHA1M
  [<TestMethod>]
  member _.``C7.2.241 SHA1M``() =
    testDisasm "5e022020" "sha1m q0, s1, v2.4s"

  /// C7.2.242 SHA1P
  [<TestMethod>]
  member _.``C7.2.242 SHA1P``() =
    testDisasm "5e021020" "sha1p q0, s1, v2.4s"

  /// C7.2.243 SHA1SU0
  [<TestMethod>]
  member _.``C7.2.243 SHA1SU0``() =
    testDisasm "5e023020" "sha1su0 v0.4s, v1.4s, v2.4s"

  /// C7.2.244 SHA1SU1
  [<TestMethod>]
  member _.``C7.2.244 SHA1SU1``() =
    testDisasm "5e281820" "sha1su1 v0.4s, v1.4s"

  /// C7.2.245 SHA256H2
  [<TestMethod>]
  member _.``C7.2.245 SHA256H2``() =
    testDisasm "5e025020" "sha256h2 q0, q1, v2.4s"

  /// C7.2.246 SHA256H
  [<TestMethod>]
  member _.``C7.2.246 SHA256H``() =
    testDisasm "5e024020" "sha256h q0, q1, v2.4s"

  /// C7.2.247 SHA256SU0
  [<TestMethod>]
  member _.``C7.2.247 SHA256SU0``() =
    testDisasm "5e282820" "sha256su0 v0.4s, v1.4s"

  /// C7.2.248 SHA256SU1
  [<TestMethod>]
  member _.``C7.2.248 SHA256SU1``() =
    testDisasm "5e026020" "sha256su1 v0.4s, v1.4s, v2.4s"

  /// C7.2.249 SHA512H
  [<TestMethod>]
  member _.``C7.2.249 SHA512H``() =
    testDisasm "ce628020" "sha512h q0, q1, v2.2d"

  /// C7.2.250 SHA512H2
  [<TestMethod>]
  member _.``C7.2.250 SHA512H2``() =
    testDisasm "ce628420" "sha512h2 q0, q1, v2.2d"

  /// C7.2.251 SHA512SU0
  [<TestMethod>]
  member _.``C7.2.251 SHA512SU0``() =
    testDisasm "cec08020" "sha512su0 v0.2d, v1.2d"

  /// C7.2.252 SHA512SU1
  [<TestMethod>]
  member _.``C7.2.252 SHA512SU1``() =
    testDisasm "ce628820" "sha512su1 v0.2d, v1.2d, v2.2d"

  /// C7.2.253 SHADD
  [<TestMethod>]
  member _.``C7.2.253 SHADD``() =
    testDisasm "0e220420" "shadd v0.8b, v1.8b, v2.8b"
    testDisasm "0e620420" "shadd v0.4h, v1.4h, v2.4h"
    testDisasm "0ea20420" "shadd v0.2s, v1.2s, v2.2s"

  /// C7.2.254 SHL
  [<TestMethod>]
  member _.``C7.2.254 SHL``() =
    testDisasm "0f095420" "shl v0.8b, v1.8b, #0x1"
    testDisasm "0f115420" "shl v0.4h, v1.4h, #0x1"
    testDisasm "0f215420" "shl v0.2s, v1.2s, #0x1"
    testDisasm "4f415420" "shl v0.2d, v1.2d, #0x1"

  /// C7.2.255 SHLL, SHLL2
  [<TestMethod>]
  member _.``C7.2.255 SHLL``() =
    testDisasm "2e613820" "shll v0.4s, v1.4h, #0x10"
    testDisasm "2e213843" "shll v3.8h, v2.8b, #0x8"
    testDisasm "2ea13843" "shll v3.2d, v2.2s, #0x20"

  /// C7.2.255 SHLL, SHLL2
  [<TestMethod>]
  member _.``C7.2.255 SHLL2``() =
    testDisasm "6e213820" "shll2 v0.8h, v1.16b, #0x8"
    testDisasm "6e613843" "shll2 v3.4s, v2.8h, #0x10"
    testDisasm "6ea13843" "shll2 v3.2d, v2.4s, #0x20"

  /// C7.2.256 SHRN, SHRN2
  [<TestMethod>]
  member _.``C7.2.256 SHRN``() =
    testDisasm "0f1f8420" "shrn v0.4h, v1.4s, #0x1"
    testDisasm "0f0f8420" "shrn v0.8b, v1.8h, #0x1"
    testDisasm "0f3f8420" "shrn v0.2s, v1.2d, #0x1"

  /// C7.2.256 SHRN, SHRN2
  [<TestMethod>]
  member _.``C7.2.256 SHRN2``() =
    testDisasm "4f1f8420" "shrn2 v0.8h, v1.4s, #0x1"
    testDisasm "4f3f8420" "shrn2 v0.4s, v1.2d, #0x1"
    testDisasm "4f0f8420" "shrn2 v0.16b, v1.8h, #0x1"

  /// C7.2.257 SHSUB
  [<TestMethod>]
  member _.``C7.2.257 SHSUB``() =
    testDisasm "0e222420" "shsub v0.8b, v1.8b, v2.8b"
    testDisasm "0e622420" "shsub v0.4h, v1.4h, v2.4h"
    testDisasm "0ea22420" "shsub v0.2s, v1.2s, v2.2s"

  /// C7.2.258 SLI
  [<TestMethod>]
  member _.``C7.2.258 SLI``() =
    testDisasm "2f095420" "sli v0.8b, v1.8b, #0x1"
    testDisasm "2f115420" "sli v0.4h, v1.4h, #0x1"
    testDisasm "2f215420" "sli v0.2s, v1.2s, #0x1"
    testDisasm "6f415420" "sli v0.2d, v1.2d, #0x1"

  /// C7.2.259 SM3PARTW1
  [<TestMethod>]
  member _.``C7.2.259 SM3PARTW1``() =
    testDisasm "ce62c020" "sm3partw1 v0.4s, v1.4s, v2.4s"

  /// C7.2.260 SM3PARTW2
  [<TestMethod>]
  member _.``C7.2.260 SM3PARTW2``() =
    testDisasm "ce62c420" "sm3partw2 v0.4s, v1.4s, v2.4s"

  /// C7.2.261 SM3SS1
  [<TestMethod>]
  member _.``C7.2.261 SM3SS1``() =
    testDisasm "ce420c20" "sm3ss1 v0.4s, v1.4s, v2.4s, v3.4s"

  /// C7.2.262 SM3TT1A
  [<TestMethod>]
  member _.``C7.2.262 SM3TT1A``() =
    testDisasm "ce428020" "sm3tt1a v0.4s, v1.4s, v2.s[0]"

  /// C7.2.263 SM3TT1B
  [<TestMethod>]
  member _.``C7.2.263 SM3TT1B``() =
    testDisasm "ce428420" "sm3tt1b v0.4s, v1.4s, v2.s[0]"

  /// C7.2.264 SM3TT2A
  [<TestMethod>]
  member _.``C7.2.264 SM3TT2A``() =
    testDisasm "ce428820" "sm3tt2a v0.4s, v1.4s, v2.s[0]"

  /// C7.2.265 SM3TT2B
  [<TestMethod>]
  member _.``C7.2.265 SM3TT2B``() =
    testDisasm "ce428c20" "sm3tt2b v0.4s, v1.4s, v2.s[0]"

  /// C7.2.266 SM4E
  [<TestMethod>]
  member _.``C7.2.266 SM4E``() =
    testDisasm "cec08420" "sm4e v0.4s, v1.4s"

  /// C7.2.267 SM4EKEY
  [<TestMethod>]
  member _.``C7.2.267 SM4EKEY``() =
    testDisasm "ce62c820" "sm4ekey v0.4s, v1.4s, v2.4s"

  /// C7.2.268 SMAX
  [<TestMethod>]
  member _.``C7.2.268 SMAX``() =
    testDisasm "0e226420" "smax v0.8b, v1.8b, v2.8b"
    testDisasm "0e626420" "smax v0.4h, v1.4h, v2.4h"
    testDisasm "0ea26420" "smax v0.2s, v1.2s, v2.2s"

  /// C7.2.269 SMAXP
  [<TestMethod>]
  member _.``C7.2.269 SMAXP``() =
    testDisasm "0e22a420" "smaxp v0.8b, v1.8b, v2.8b"
    testDisasm "0e62a420" "smaxp v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2a420" "smaxp v0.2s, v1.2s, v2.2s"

  /// C7.2.27 CMEQ (register)
  [<TestMethod>]
  member _.``C7.2.27 CMEQ``() =
    testDisasm "2e228c20" "cmeq v0.8b, v1.8b, v2.8b"
    testDisasm "2e628c20" "cmeq v0.4h, v1.4h, v2.4h"
    testDisasm "2ea28c20" "cmeq v0.2s, v1.2s, v2.2s"
    testDisasm "6ee28c20" "cmeq v0.2d, v1.2d, v2.2d"

  /// C7.2.270 SMAXV
  [<TestMethod>]
  member _.``C7.2.270 SMAXV``() =
    testDisasm "4eb0a820" "smaxv s0, v1.4s"
    testDisasm "0e30a843" "smaxv b3, v2.8b"
    testDisasm "0e70a843" "smaxv h3, v2.4h"

  /// C7.2.271 SMIN
  [<TestMethod>]
  member _.``C7.2.271 SMIN``() =
    testDisasm "0e226c20" "smin v0.8b, v1.8b, v2.8b"
    testDisasm "0e626c20" "smin v0.4h, v1.4h, v2.4h"
    testDisasm "0ea26c20" "smin v0.2s, v1.2s, v2.2s"

  /// C7.2.272 SMINP
  [<TestMethod>]
  member _.``C7.2.272 SMINP``() =
    testDisasm "0e22ac20" "sminp v0.8b, v1.8b, v2.8b"
    testDisasm "0e62ac20" "sminp v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2ac20" "sminp v0.2s, v1.2s, v2.2s"

  /// C7.2.273 SMINV
  [<TestMethod>]
  member _.``C7.2.273 SMINV``() =
    testDisasm "4eb1a820" "sminv s0, v1.4s"
    testDisasm "0e31a843" "sminv b3, v2.8b"
    testDisasm "0e71a843" "sminv h3, v2.4h"

  /// C7.2.274 SMLAL, SMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.274 SMLAL``() =
    testDisasm "0e628020" "smlal v0.4s, v1.4h, v2.4h"
    testDisasm "0f522020" "smlal v0.4s, v1.4h, v2.h[1]"
    testDisasm "0fa22020" "smlal v0.2d, v1.2s, v2.s[1]"
    testDisasm "0e228020" "smlal v0.8h, v1.8b, v2.8b"

  /// C7.2.274 SMLAL, SMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.274 SMLAL2``() =
    testDisasm "4f522020" "smlal2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "4fa22020" "smlal2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "4e228020" "smlal2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ea28020" "smlal2 v0.2d, v1.4s, v2.4s"

  /// C7.2.276 SMLSL, SMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.276 SMLSL``() =
    testDisasm "0e62a020" "smlsl v0.4s, v1.4h, v2.4h"
    testDisasm "0f526020" "smlsl v0.4s, v1.4h, v2.h[1]"
    testDisasm "0fa26020" "smlsl v0.2d, v1.2s, v2.s[1]"
    testDisasm "0e22a020" "smlsl v0.8h, v1.8b, v2.8b"
