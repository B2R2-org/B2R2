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
/// One test for each instruction DDI0487F.c describes, SMLSL2 to USHL in
/// the order of its sections. Each reads words of the instruction and checks
/// the text, and each word's text is one binutils' objdump reads the word as
/// too, so what is asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualParserTests6() =
  let parser =
    Parser(BinReader.Init Endian.Big) :> IInstructionParsable

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// C7.2.276 SMLSL, SMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.276 SMLSL2``() =
    testDisasm "4f526020" "smlsl2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "4fa26020" "smlsl2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "4e22a020" "smlsl2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ea2a020" "smlsl2 v0.2d, v1.4s, v2.4s"

  /// C7.2.278 SMMLA (vector)
  [<TestMethod>]
  member _.``C7.2.278 SMMLA``() =
    testDisasm "4e82a420" "smmla v0.4s, v1.16b, v2.16b"

  /// C7.2.279 SMOV
  [<TestMethod>]
  member _.``C7.2.279 SMOV``() =
    testDisasm "0e032c20" "smov w0, v1.b[1]"
    testDisasm "0e062c20" "smov w0, v1.h[1]"
    testDisasm "4e032c20" "smov x0, v1.b[1]"
    testDisasm "4e062c20" "smov x0, v1.h[1]"

  /// C7.2.280 SMULL, SMULL2 (by element)
  [<TestMethod>]
  member _.``C7.2.280 SMULL2``() =
    testDisasm "4f52a020" "smull2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "4fa2a020" "smull2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "4e62c020" "smull2 v0.4s, v1.8h, v2.8h"
    testDisasm "4ea2c020" "smull2 v0.2d, v1.4s, v2.4s"

  /// C7.2.282 SQABS
  [<TestMethod>]
  member _.``C7.2.282 SQABS``() =
    testDisasm "0e207820" "sqabs v0.8b, v1.8b"
    testDisasm "0e607820" "sqabs v0.4h, v1.4h"
    testDisasm "0ea07820" "sqabs v0.2s, v1.2s"
    testDisasm "4ee07820" "sqabs v0.2d, v1.2d"

  /// C7.2.283 SQADD
  [<TestMethod>]
  member _.``C7.2.283 SQADD``() =
    testDisasm "0e220c20" "sqadd v0.8b, v1.8b, v2.8b"
    testDisasm "0e620c20" "sqadd v0.4h, v1.4h, v2.4h"
    testDisasm "0ea20c20" "sqadd v0.2s, v1.2s, v2.2s"
    testDisasm "4ee20c20" "sqadd v0.2d, v1.2d, v2.2d"

  /// C7.2.284 SQDMLAL, SQDMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.284 SQDMLAL``() =
    testDisasm "0f523020" "sqdmlal v0.4s, v1.4h, v2.h[1]"
    testDisasm "0fa23020" "sqdmlal v0.2d, v1.2s, v2.s[1]"
    testDisasm "0ea29020" "sqdmlal v0.2d, v1.2s, v2.2s"
    testDisasm "0e629020" "sqdmlal v0.4s, v1.4h, v2.4h"

  /// C7.2.284 SQDMLAL, SQDMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.284 SQDMLAL2``() =
    testDisasm "4f523020" "sqdmlal2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "4fa23020" "sqdmlal2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "4ea29020" "sqdmlal2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e629020" "sqdmlal2 v0.4s, v1.8h, v2.8h"

  /// C7.2.286 SQDMLSL, SQDMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.286 SQDMLSL``() =
    testDisasm "0f527020" "sqdmlsl v0.4s, v1.4h, v2.h[1]"
    testDisasm "0fa27020" "sqdmlsl v0.2d, v1.2s, v2.s[1]"
    testDisasm "0ea2b020" "sqdmlsl v0.2d, v1.2s, v2.2s"
    testDisasm "0e62b020" "sqdmlsl v0.4s, v1.4h, v2.4h"

  /// C7.2.286 SQDMLSL, SQDMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.286 SQDMLSL2``() =
    testDisasm "4f527020" "sqdmlsl2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "4fa27020" "sqdmlsl2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "4ea2b020" "sqdmlsl2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e62b020" "sqdmlsl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.288 SQDMULH (by element)
  [<TestMethod>]
  member _.``C7.2.288 SQDMULH``() =
    testDisasm "0f52c020" "sqdmulh v0.4h, v1.4h, v2.h[1]"
    testDisasm "0fa2c020" "sqdmulh v0.2s, v1.2s, v2.s[1]"
    testDisasm "0e62b420" "sqdmulh v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2b420" "sqdmulh v0.2s, v1.2s, v2.2s"

  /// C7.2.29 CMGE (register)
  [<TestMethod>]
  member _.``C7.2.29 CMGE``() =
    testDisasm "0e223c20" "cmge v0.8b, v1.8b, v2.8b"
    testDisasm "0e623c20" "cmge v0.4h, v1.4h, v2.4h"
    testDisasm "0ea23c20" "cmge v0.2s, v1.2s, v2.2s"
    testDisasm "4ee23c20" "cmge v0.2d, v1.2d, v2.2d"

  /// C7.2.290 SQDMULL, SQDMULL2 (by element)
  [<TestMethod>]
  member _.``C7.2.290 SQDMULL``() =
    testDisasm "0f52b020" "sqdmull v0.4s, v1.4h, v2.h[1]"
    testDisasm "0fa2b020" "sqdmull v0.2d, v1.2s, v2.s[1]"
    testDisasm "0ea2d020" "sqdmull v0.2d, v1.2s, v2.2s"
    testDisasm "0e62d020" "sqdmull v0.4s, v1.4h, v2.4h"

  /// C7.2.290 SQDMULL, SQDMULL2 (by element)
  [<TestMethod>]
  member _.``C7.2.290 SQDMULL2``() =
    testDisasm "4f52b020" "sqdmull2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "4fa2b020" "sqdmull2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "4ea2d020" "sqdmull2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e62d020" "sqdmull2 v0.4s, v1.8h, v2.8h"

  /// C7.2.292 SQNEG
  [<TestMethod>]
  member _.``C7.2.292 SQNEG``() =
    testDisasm "2e207820" "sqneg v0.8b, v1.8b"
    testDisasm "2e607820" "sqneg v0.4h, v1.4h"
    testDisasm "2ea07820" "sqneg v0.2s, v1.2s"
    testDisasm "6ee07820" "sqneg v0.2d, v1.2d"

  /// C7.2.293 SQRDMLAH (by element)
  [<TestMethod>]
  member _.``C7.2.293 SQRDMLAH``() =
    testDisasm "2f52d020" "sqrdmlah v0.4h, v1.4h, v2.h[1]"
    testDisasm "2fa2d020" "sqrdmlah v0.2s, v1.2s, v2.s[1]"
    testDisasm "2e428420" "sqrdmlah v0.4h, v1.4h, v2.4h"
    testDisasm "2e828420" "sqrdmlah v0.2s, v1.2s, v2.2s"

  /// C7.2.295 SQRDMLSH (by element)
  [<TestMethod>]
  member _.``C7.2.295 SQRDMLSH``() =
    testDisasm "2f52f020" "sqrdmlsh v0.4h, v1.4h, v2.h[1]"
    testDisasm "2fa2f020" "sqrdmlsh v0.2s, v1.2s, v2.s[1]"
    testDisasm "2e428c20" "sqrdmlsh v0.4h, v1.4h, v2.4h"
    testDisasm "2e828c20" "sqrdmlsh v0.2s, v1.2s, v2.2s"

  /// C7.2.297 SQRDMULH (by element)
  [<TestMethod>]
  member _.``C7.2.297 SQRDMULH``() =
    testDisasm "0f52d020" "sqrdmulh v0.4h, v1.4h, v2.h[1]"
    testDisasm "0fa2d020" "sqrdmulh v0.2s, v1.2s, v2.s[1]"
    testDisasm "2e62b420" "sqrdmulh v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2b420" "sqrdmulh v0.2s, v1.2s, v2.2s"

  /// C7.2.299 SQRSHL
  [<TestMethod>]
  member _.``C7.2.299 SQRSHL``() =
    testDisasm "0e225c20" "sqrshl v0.8b, v1.8b, v2.8b"
    testDisasm "0e625c20" "sqrshl v0.4h, v1.4h, v2.4h"
    testDisasm "0ea25c20" "sqrshl v0.2s, v1.2s, v2.2s"
    testDisasm "4ee25c20" "sqrshl v0.2d, v1.2d, v2.2d"

  /// C7.2.3 ADDHN, ADDHN2
  [<TestMethod>]
  member _.``C7.2.3 ADDHN``() =
    testDisasm "0e624020" "addhn v0.4h, v1.4s, v2.4s"
    testDisasm "0ea24020" "addhn v0.2s, v1.2d, v2.2d"
    testDisasm "0e224020" "addhn v0.8b, v1.8h, v2.8h"

  /// C7.2.3 ADDHN, ADDHN2
  [<TestMethod>]
  member _.``C7.2.3 ADDHN2``() =
    testDisasm "4e624020" "addhn2 v0.8h, v1.4s, v2.4s"
    testDisasm "4ea24020" "addhn2 v0.4s, v1.2d, v2.2d"
    testDisasm "4e224020" "addhn2 v0.16b, v1.8h, v2.8h"

  /// C7.2.300 SQRSHRN, SQRSHRN2
  [<TestMethod>]
  member _.``C7.2.300 SQRSHRN``() =
    testDisasm "0f1f9c20" "sqrshrn v0.4h, v1.4s, #0x1"
    testDisasm "0f3f9c20" "sqrshrn v0.2s, v1.2d, #0x1"
    testDisasm "0f0f9c20" "sqrshrn v0.8b, v1.8h, #0x1"
    testDisasm "5f149eb6" "sqrshrn h22, s21, #0xc"

  /// C7.2.300 SQRSHRN, SQRSHRN2
  [<TestMethod>]
  member _.``C7.2.300 SQRSHRN2``() =
    testDisasm "4f1f9c20" "sqrshrn2 v0.8h, v1.4s, #0x1"
    testDisasm "4f3f9c20" "sqrshrn2 v0.4s, v1.2d, #0x1"
    testDisasm "4f0f9c20" "sqrshrn2 v0.16b, v1.8h, #0x1"

  /// C7.2.301 SQRSHRUN, SQRSHRUN2
  [<TestMethod>]
  member _.``C7.2.301 SQRSHRUN``() =
    testDisasm "2f1f8c20" "sqrshrun v0.4h, v1.4s, #0x1"
    testDisasm "2f3f8c20" "sqrshrun v0.2s, v1.2d, #0x1"
    testDisasm "2f0f8c20" "sqrshrun v0.8b, v1.8h, #0x1"
    testDisasm "7f148eb6" "sqrshrun h22, s21, #0xc"

  /// C7.2.301 SQRSHRUN, SQRSHRUN2
  [<TestMethod>]
  member _.``C7.2.301 SQRSHRUN2``() =
    testDisasm "6f1f8c20" "sqrshrun2 v0.8h, v1.4s, #0x1"
    testDisasm "6f3f8c20" "sqrshrun2 v0.4s, v1.2d, #0x1"
    testDisasm "6f0f8c20" "sqrshrun2 v0.16b, v1.8h, #0x1"

  /// C7.2.302 SQSHL (immediate)
  [<TestMethod>]
  member _.``C7.2.302 SQSHL``() =
    testDisasm "0f097420" "sqshl v0.8b, v1.8b, #0x1"
    testDisasm "0f117420" "sqshl v0.4h, v1.4h, #0x1"
    testDisasm "0f217420" "sqshl v0.2s, v1.2s, #0x1"
    testDisasm "4f417420" "sqshl v0.2d, v1.2d, #0x1"

  /// C7.2.304 SQSHLU
  [<TestMethod>]
  member _.``C7.2.304 SQSHLU``() =
    testDisasm "2f096420" "sqshlu v0.8b, v1.8b, #0x1"
    testDisasm "2f116420" "sqshlu v0.4h, v1.4h, #0x1"
    testDisasm "2f216420" "sqshlu v0.2s, v1.2s, #0x1"
    testDisasm "6f416420" "sqshlu v0.2d, v1.2d, #0x1"

  /// C7.2.305 SQSHRN, SQSHRN2
  [<TestMethod>]
  member _.``C7.2.305 SQSHRN``() =
    testDisasm "0f0f9420" "sqshrn v0.8b, v1.8h, #0x1"
    testDisasm "0f1f9420" "sqshrn v0.4h, v1.4s, #0x1"
    testDisasm "0f3f9420" "sqshrn v0.2s, v1.2d, #0x1"
    testDisasm "5f1496b6" "sqshrn h22, s21, #0xc"

  /// C7.2.305 SQSHRN, SQSHRN2
  [<TestMethod>]
  member _.``C7.2.305 SQSHRN2``() =
    testDisasm "4f1f9420" "sqshrn2 v0.8h, v1.4s, #0x1"
    testDisasm "4f3f9420" "sqshrn2 v0.4s, v1.2d, #0x1"
    testDisasm "4f0f9420" "sqshrn2 v0.16b, v1.8h, #0x1"

  /// C7.2.306 SQSHRUN, SQSHRUN2
  [<TestMethod>]
  member _.``C7.2.306 SQSHRUN``() =
    testDisasm "2f1f8420" "sqshrun v0.4h, v1.4s, #0x1"
    testDisasm "2f3f8420" "sqshrun v0.2s, v1.2d, #0x1"
    testDisasm "2f0f8420" "sqshrun v0.8b, v1.8h, #0x1"
    testDisasm "7f1486b6" "sqshrun h22, s21, #0xc"

  /// C7.2.306 SQSHRUN, SQSHRUN2
  [<TestMethod>]
  member _.``C7.2.306 SQSHRUN2``() =
    testDisasm "6f1f8420" "sqshrun2 v0.8h, v1.4s, #0x1"
    testDisasm "6f3f8420" "sqshrun2 v0.4s, v1.2d, #0x1"
    testDisasm "6f0f8420" "sqshrun2 v0.16b, v1.8h, #0x1"

  /// C7.2.307 SQSUB
  [<TestMethod>]
  member _.``C7.2.307 SQSUB``() =
    testDisasm "0e222c20" "sqsub v0.8b, v1.8b, v2.8b"
    testDisasm "0e622c20" "sqsub v0.4h, v1.4h, v2.4h"
    testDisasm "0ea22c20" "sqsub v0.2s, v1.2s, v2.2s"
    testDisasm "4ee22c20" "sqsub v0.2d, v1.2d, v2.2d"

  /// C7.2.308 SQXTN, SQXTN2
  [<TestMethod>]
  member _.``C7.2.308 SQXTN``() =
    testDisasm "0e214820" "sqxtn v0.8b, v1.8h"
    testDisasm "0ea14820" "sqxtn v0.2s, v1.2d"
    testDisasm "0e614820" "sqxtn v0.4h, v1.4s"
    testDisasm "5e214843" "sqxtn b3, h2"

  /// C7.2.308 SQXTN, SQXTN2
  [<TestMethod>]
  member _.``C7.2.308 SQXTN2``() =
    testDisasm "4e614820" "sqxtn2 v0.8h, v1.4s"
    testDisasm "4ea14820" "sqxtn2 v0.4s, v1.2d"
    testDisasm "4e214820" "sqxtn2 v0.16b, v1.8h"

  /// C7.2.309 SQXTUN, SQXTUN2
  [<TestMethod>]
  member _.``C7.2.309 SQXTUN``() =
    testDisasm "2e212820" "sqxtun v0.8b, v1.8h"
    testDisasm "2ea12820" "sqxtun v0.2s, v1.2d"
    testDisasm "2e612820" "sqxtun v0.4h, v1.4s"
    testDisasm "7e212843" "sqxtun b3, h2"

  /// C7.2.309 SQXTUN, SQXTUN2
  [<TestMethod>]
  member _.``C7.2.309 SQXTUN2``() =
    testDisasm "6e612820" "sqxtun2 v0.8h, v1.4s"
    testDisasm "6ea12820" "sqxtun2 v0.4s, v1.2d"
    testDisasm "6e212820" "sqxtun2 v0.16b, v1.8h"

  /// C7.2.31 CMGT (register)
  [<TestMethod>]
  member _.``C7.2.31 CMGT``() =
    testDisasm "0e223420" "cmgt v0.8b, v1.8b, v2.8b"
    testDisasm "0e623420" "cmgt v0.4h, v1.4h, v2.4h"
    testDisasm "0ea23420" "cmgt v0.2s, v1.2s, v2.2s"
    testDisasm "4ee23420" "cmgt v0.2d, v1.2d, v2.2d"

  /// C7.2.310 SRHADD
  [<TestMethod>]
  member _.``C7.2.310 SRHADD``() =
    testDisasm "0e221420" "srhadd v0.8b, v1.8b, v2.8b"
    testDisasm "0e621420" "srhadd v0.4h, v1.4h, v2.4h"
    testDisasm "0ea21420" "srhadd v0.2s, v1.2s, v2.2s"

  /// C7.2.311 SRI
  [<TestMethod>]
  member _.``C7.2.311 SRI``() =
    testDisasm "2f0f4420" "sri v0.8b, v1.8b, #0x1"
    testDisasm "2f1f4420" "sri v0.4h, v1.4h, #0x1"
    testDisasm "2f3f4420" "sri v0.2s, v1.2s, #0x1"
    testDisasm "6f7f4420" "sri v0.2d, v1.2d, #0x1"

  /// C7.2.312 SRSHL
  [<TestMethod>]
  member _.``C7.2.312 SRSHL``() =
    testDisasm "0e225420" "srshl v0.8b, v1.8b, v2.8b"
    testDisasm "0e625420" "srshl v0.4h, v1.4h, v2.4h"
    testDisasm "0ea25420" "srshl v0.2s, v1.2s, v2.2s"
    testDisasm "4ee25420" "srshl v0.2d, v1.2d, v2.2d"

  /// C7.2.313 SRSHR
  [<TestMethod>]
  member _.``C7.2.313 SRSHR``() =
    testDisasm "0f0f2420" "srshr v0.8b, v1.8b, #0x1"
    testDisasm "0f1f2420" "srshr v0.4h, v1.4h, #0x1"
    testDisasm "0f3f2420" "srshr v0.2s, v1.2s, #0x1"
    testDisasm "4f7f2420" "srshr v0.2d, v1.2d, #0x1"

  /// C7.2.314 SRSRA
  [<TestMethod>]
  member _.``C7.2.314 SRSRA``() =
    testDisasm "0f0f3420" "srsra v0.8b, v1.8b, #0x1"
    testDisasm "0f1f3420" "srsra v0.4h, v1.4h, #0x1"
    testDisasm "0f3f3420" "srsra v0.2s, v1.2s, #0x1"
    testDisasm "4f7f3420" "srsra v0.2d, v1.2d, #0x1"

  /// C7.2.315 SSHL
  [<TestMethod>]
  member _.``C7.2.315 SSHL``() =
    testDisasm "0e224420" "sshl v0.8b, v1.8b, v2.8b"
    testDisasm "0e624420" "sshl v0.4h, v1.4h, v2.4h"
    testDisasm "0ea24420" "sshl v0.2s, v1.2s, v2.2s"
    testDisasm "4ee24420" "sshl v0.2d, v1.2d, v2.2d"

  /// C7.2.316 SSHLL, SSHLL2
  [<TestMethod>]
  member _.``C7.2.316 SSHLL``() =
    testDisasm "0f11a420" "sshll v0.4s, v1.4h, #0x1"
    testDisasm "0f09a420" "sshll v0.8h, v1.8b, #0x1"
    testDisasm "0f21a420" "sshll v0.2d, v1.2s, #0x1"

  /// C7.2.316 SSHLL, SSHLL2
  [<TestMethod>]
  member _.``C7.2.316 SSHLL2``() =
    testDisasm "4f09a420" "sshll2 v0.8h, v1.16b, #0x1"
    testDisasm "4f11a420" "sshll2 v0.4s, v1.8h, #0x1"
    testDisasm "4f21a420" "sshll2 v0.2d, v1.4s, #0x1"

  /// C7.2.317 SSHR
  [<TestMethod>]
  member _.``C7.2.317 SSHR``() =
    testDisasm "0f0f0420" "sshr v0.8b, v1.8b, #0x1"
    testDisasm "0f1f0420" "sshr v0.4h, v1.4h, #0x1"
    testDisasm "0f3f0420" "sshr v0.2s, v1.2s, #0x1"
    testDisasm "4f7f0420" "sshr v0.2d, v1.2d, #0x1"

  /// C7.2.318 SSRA
  [<TestMethod>]
  member _.``C7.2.318 SSRA``() =
    testDisasm "0f0f1420" "ssra v0.8b, v1.8b, #0x1"
    testDisasm "0f1f1420" "ssra v0.4h, v1.4h, #0x1"
    testDisasm "0f3f1420" "ssra v0.2s, v1.2s, #0x1"
    testDisasm "4f7f1420" "ssra v0.2d, v1.2d, #0x1"

  /// C7.2.319 SSUBL, SSUBL2
  [<TestMethod>]
  member _.``C7.2.319 SSUBL``() =
    testDisasm "0e622020" "ssubl v0.4s, v1.4h, v2.4h"
    testDisasm "0e222020" "ssubl v0.8h, v1.8b, v2.8b"
    testDisasm "0ea22020" "ssubl v0.2d, v1.2s, v2.2s"

  /// C7.2.319 SSUBL, SSUBL2
  [<TestMethod>]
  member _.``C7.2.319 SSUBL2``() =
    testDisasm "4e222020" "ssubl2 v0.8h, v1.16b, v2.16b"
    testDisasm "4ea22020" "ssubl2 v0.2d, v1.4s, v2.4s"
    testDisasm "4e622020" "ssubl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.320 SSUBW, SSUBW2
  [<TestMethod>]
  member _.``C7.2.320 SSUBW``() =
    testDisasm "0e623020" "ssubw v0.4s, v1.4s, v2.4h"
    testDisasm "0e223020" "ssubw v0.8h, v1.8h, v2.8b"
    testDisasm "0ea23020" "ssubw v0.2d, v1.2d, v2.2s"

  /// C7.2.320 SSUBW, SSUBW2
  [<TestMethod>]
  member _.``C7.2.320 SSUBW2``() =
    testDisasm "4e223020" "ssubw2 v0.8h, v1.8h, v2.16b"
    testDisasm "4ea23020" "ssubw2 v0.2d, v1.2d, v2.4s"
    testDisasm "4e623020" "ssubw2 v0.4s, v1.4s, v2.8h"

  /// C7.2.321 ST1 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.321 ST1``() =
    testDisasm "4c007020" "st1 { v0.16b }, [x1]"
    testDisasm "0c0023c0" "st1 { v0.8b - v3.8b }, [x30]"
    testDisasm "0c0027c0" "st1 { v0.4h - v3.4h }, [x30]"
    testDisasm "0c002bc0" "st1 { v0.2s - v3.2s }, [x30]"

  /// C7.2.323 ST2 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.323 ST2``() =
    testDisasm "4c008020" "st2 { v0.16b, v1.16b }, [x1]"
    testDisasm "0c0087c0" "st2 { v0.4h, v1.4h }, [x30]"
    testDisasm "0c008bc0" "st2 { v0.2s, v1.2s }, [x30]"
    testDisasm "0c818043" "st2 { v3.8b, v4.8b }, [x2], x1"

  /// C7.2.325 ST3 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.325 ST3``() =
    testDisasm "4c004020" "st3 { v0.16b, v1.16b, v2.16b }, [x1]"
    testDisasm "0c0047c0" "st3 { v0.4h, v1.4h, v2.4h }, [x30]"
    testDisasm "0c004bc0" "st3 { v0.2s, v1.2s, v2.2s }, [x30]"
    testDisasm "0c814043" "st3 { v3.8b, v4.8b, v5.8b }, [x2], x1"

  /// C7.2.327 ST4 (multiple structures)
  [<TestMethod>]
  member _.``C7.2.327 ST4``() =
    testDisasm "4c000020" "st4 { v0.16b - v3.16b }, [x1]"
    testDisasm "0c0007c0" "st4 { v0.4h - v3.4h }, [x30]"
    testDisasm "0c000bc0" "st4 { v0.2s - v3.2s }, [x30]"
    testDisasm "0c810043" "st4 { v3.8b - v6.8b }, [x2], x1"

  /// C7.2.33 CMHI (register)
  [<TestMethod>]
  member _.``C7.2.33 CMHI``() =
    testDisasm "2e223420" "cmhi v0.8b, v1.8b, v2.8b"
    testDisasm "2e623420" "cmhi v0.4h, v1.4h, v2.4h"
    testDisasm "2ea23420" "cmhi v0.2s, v1.2s, v2.2s"
    testDisasm "6ee23420" "cmhi v0.2d, v1.2d, v2.2d"

  /// C7.2.335 SUBHN, SUBHN2
  [<TestMethod>]
  member _.``C7.2.335 SUBHN``() =
    testDisasm "0e626020" "subhn v0.4h, v1.4s, v2.4s"
    testDisasm "0ea26020" "subhn v0.2s, v1.2d, v2.2d"
    testDisasm "0e226020" "subhn v0.8b, v1.8h, v2.8h"

  /// C7.2.335 SUBHN, SUBHN2
  [<TestMethod>]
  member _.``C7.2.335 SUBHN2``() =
    testDisasm "4e626020" "subhn2 v0.8h, v1.4s, v2.4s"
    testDisasm "4ea26020" "subhn2 v0.4s, v1.2d, v2.2d"
    testDisasm "4e226020" "subhn2 v0.16b, v1.8h, v2.8h"

  /// C7.2.336 SUDOT (by element)
  [<TestMethod>]
  member _.``C7.2.336 SUDOT``() =
    testDisasm "4f02f020" "sudot v0.4s, v1.16b, v2.4b[0]"

  /// C7.2.337 SUQADD
  [<TestMethod>]
  member _.``C7.2.337 SUQADD``() =
    testDisasm "0e203820" "suqadd v0.8b, v1.8b"
    testDisasm "0e603820" "suqadd v0.4h, v1.4h"
    testDisasm "0ea03820" "suqadd v0.2s, v1.2s"
    testDisasm "4ee03820" "suqadd v0.2d, v1.2d"

  /// C7.2.338 SXTL, SXTL2
  [<TestMethod>]
  member _.``C7.2.338 SXTL``() =
    testDisasm "0f10a420" "sshll v0.4s, v1.4h, #0x0"
    testDisasm "0f08a420" "sshll v0.8h, v1.8b, #0x0"
    testDisasm "0f20a420" "sshll v0.2d, v1.2s, #0x0"

  /// C7.2.338 SXTL, SXTL2
  [<TestMethod>]
  member _.``C7.2.338 SXTL2``() =
    testDisasm "4f08a420" "sshll2 v0.8h, v1.16b, #0x0"
    testDisasm "4f20a420" "sshll2 v0.2d, v1.4s, #0x0"
    testDisasm "4f10a420" "sshll2 v0.4s, v1.8h, #0x0"

  /// C7.2.339 TBL
  [<TestMethod>]
  member _.``C7.2.339 TBL``() =
    testDisasm "0e020020" "tbl v0.8b, { v1.16b }, v2.8b"
    testDisasm "0e012043" "tbl v3.8b, { v2.16b, v3.16b }, v1.8b"
    testDisasm "0e014043" "tbl v3.8b, { v2.16b, v3.16b, v4.16b }, v1.8b"
    testDisasm "0e016043" "tbl v3.8b, { v2.16b - v5.16b }, v1.8b"

  /// C7.2.34 CMHS (register)
  [<TestMethod>]
  member _.``C7.2.34 CMHS``() =
    testDisasm "2e223c20" "cmhs v0.8b, v1.8b, v2.8b"
    testDisasm "2e623c20" "cmhs v0.4h, v1.4h, v2.4h"
    testDisasm "2ea23c20" "cmhs v0.2s, v1.2s, v2.2s"
    testDisasm "6ee23c20" "cmhs v0.2d, v1.2d, v2.2d"

  /// C7.2.340 TBX
  [<TestMethod>]
  member _.``C7.2.340 TBX``() =
    testDisasm "0e021020" "tbx v0.8b, { v1.16b }, v2.8b"
    testDisasm "0e013043" "tbx v3.8b, { v2.16b, v3.16b }, v1.8b"
    testDisasm "0e015043" "tbx v3.8b, { v2.16b, v3.16b, v4.16b }, v1.8b"
    testDisasm "0e017043" "tbx v3.8b, { v2.16b - v5.16b }, v1.8b"

  /// C7.2.341 TRN1
  [<TestMethod>]
  member _.``C7.2.341 TRN1``() =
    testDisasm "0e022820" "trn1 v0.8b, v1.8b, v2.8b"
    testDisasm "0e422820" "trn1 v0.4h, v1.4h, v2.4h"
    testDisasm "0e822820" "trn1 v0.2s, v1.2s, v2.2s"
    testDisasm "4ec22820" "trn1 v0.2d, v1.2d, v2.2d"

  /// C7.2.342 TRN2
  [<TestMethod>]
  member _.``C7.2.342 TRN2``() =
    testDisasm "0e026820" "trn2 v0.8b, v1.8b, v2.8b"
    testDisasm "0e426820" "trn2 v0.4h, v1.4h, v2.4h"
    testDisasm "0e826820" "trn2 v0.2s, v1.2s, v2.2s"
    testDisasm "4ec26820" "trn2 v0.2d, v1.2d, v2.2d"

  /// C7.2.343 UABA
  [<TestMethod>]
  member _.``C7.2.343 UABA``() =
    testDisasm "2e227c20" "uaba v0.8b, v1.8b, v2.8b"
    testDisasm "2e627c20" "uaba v0.4h, v1.4h, v2.4h"
    testDisasm "2ea27c20" "uaba v0.2s, v1.2s, v2.2s"

  /// C7.2.344 UABAL, UABAL2
  [<TestMethod>]
  member _.``C7.2.344 UABAL``() =
    testDisasm "2e625020" "uabal v0.4s, v1.4h, v2.4h"
    testDisasm "2e225020" "uabal v0.8h, v1.8b, v2.8b"
    testDisasm "2ea25020" "uabal v0.2d, v1.2s, v2.2s"

  /// C7.2.344 UABAL, UABAL2
  [<TestMethod>]
  member _.``C7.2.344 UABAL2``() =
    testDisasm "6e225020" "uabal2 v0.8h, v1.16b, v2.16b"
    testDisasm "6ea25020" "uabal2 v0.2d, v1.4s, v2.4s"
    testDisasm "6e625020" "uabal2 v0.4s, v1.8h, v2.8h"

  /// C7.2.345 UABD
  [<TestMethod>]
  member _.``C7.2.345 UABD``() =
    testDisasm "2e227420" "uabd v0.8b, v1.8b, v2.8b"
    testDisasm "2e627420" "uabd v0.4h, v1.4h, v2.4h"
    testDisasm "2ea27420" "uabd v0.2s, v1.2s, v2.2s"

  /// C7.2.346 UABDL, UABDL2
  [<TestMethod>]
  member _.``C7.2.346 UABDL``() =
    testDisasm "2e627020" "uabdl v0.4s, v1.4h, v2.4h"
    testDisasm "2e227020" "uabdl v0.8h, v1.8b, v2.8b"
    testDisasm "2ea27020" "uabdl v0.2d, v1.2s, v2.2s"

  /// C7.2.346 UABDL, UABDL2
  [<TestMethod>]
  member _.``C7.2.346 UABDL2``() =
    testDisasm "6e227020" "uabdl2 v0.8h, v1.16b, v2.16b"
    testDisasm "6ea27020" "uabdl2 v0.2d, v1.4s, v2.4s"
    testDisasm "6e627020" "uabdl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.347 UADALP
  [<TestMethod>]
  member _.``C7.2.347 UADALP``() =
    testDisasm "2e206820" "uadalp v0.4h, v1.8b"
    testDisasm "2e606820" "uadalp v0.2s, v1.4h"
    testDisasm "6ea06820" "uadalp v0.2d, v1.4s"

  /// C7.2.348 UADDL, UADDL2
  [<TestMethod>]
  member _.``C7.2.348 UADDL``() =
    testDisasm "2e620020" "uaddl v0.4s, v1.4h, v2.4h"
    testDisasm "2e220020" "uaddl v0.8h, v1.8b, v2.8b"
    testDisasm "2ea20020" "uaddl v0.2d, v1.2s, v2.2s"

  /// C7.2.348 UADDL, UADDL2
  [<TestMethod>]
  member _.``C7.2.348 UADDL2``() =
    testDisasm "6e220020" "uaddl2 v0.8h, v1.16b, v2.16b"
    testDisasm "6ea20020" "uaddl2 v0.2d, v1.4s, v2.4s"
    testDisasm "6e620020" "uaddl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.349 UADDLP
  [<TestMethod>]
  member _.``C7.2.349 UADDLP``() =
    testDisasm "2e202820" "uaddlp v0.4h, v1.8b"
    testDisasm "2e602820" "uaddlp v0.2s, v1.4h"
    testDisasm "6ea02820" "uaddlp v0.2d, v1.4s"

  /// C7.2.35 CMLE (zero)
  [<TestMethod>]
  member _.``C7.2.35 CMLE``() =
    testDisasm "2e209820" "cmle v0.8b, v1.8b, #0x0"
    testDisasm "2e609820" "cmle v0.4h, v1.4h, #0x0"
    testDisasm "2ea09820" "cmle v0.2s, v1.2s, #0x0"
    testDisasm "6ee09820" "cmle v0.2d, v1.2d, #0x0"

  /// C7.2.350 UADDLV
  [<TestMethod>]
  member _.``C7.2.350 UADDLV``() =
    testDisasm "2e303820" "uaddlv h0, v1.8b"
    testDisasm "2e703843" "uaddlv s3, v2.4h"
    testDisasm "6eb03843" "uaddlv d3, v2.4s"

  /// C7.2.351 UADDW, UADDW2
  [<TestMethod>]
  member _.``C7.2.351 UADDW``() =
    testDisasm "2e621020" "uaddw v0.4s, v1.4s, v2.4h"
    testDisasm "2e221020" "uaddw v0.8h, v1.8h, v2.8b"
    testDisasm "2ea21020" "uaddw v0.2d, v1.2d, v2.2s"

  /// C7.2.351 UADDW, UADDW2
  [<TestMethod>]
  member _.``C7.2.351 UADDW2``() =
    testDisasm "6e221020" "uaddw2 v0.8h, v1.8h, v2.16b"
    testDisasm "6ea21020" "uaddw2 v0.2d, v1.2d, v2.4s"
    testDisasm "6e621020" "uaddw2 v0.4s, v1.4s, v2.8h"

  /// C7.2.352 UCVTF (vector, fixed-point)
  [<TestMethod>]
  member _.``C7.2.352 UCVTF``() =
    testDisasm "2f1be420" "ucvtf v0.4h, v1.4h, #5"
    testDisasm "2f3be420" "ucvtf v0.2s, v1.2s, #5"
    testDisasm "6f7be420" "ucvtf v0.2d, v1.2d, #5"
    testDisasm "7e79d820" "ucvtf h0, h1"

  /// C7.2.356 UDOT (by element)
  [<TestMethod>]
  member _.``C7.2.356 UDOT``() =
    testDisasm "2e829420" "udot v0.2s, v1.8b, v2.8b"
    testDisasm "2f81e043" "udot v3.2s, v2.8b, v1.4b[0]"

  /// C7.2.358 UHADD
  [<TestMethod>]
  member _.``C7.2.358 UHADD``() =
    testDisasm "2e220420" "uhadd v0.8b, v1.8b, v2.8b"
    testDisasm "2e620420" "uhadd v0.4h, v1.4h, v2.4h"
    testDisasm "2ea20420" "uhadd v0.2s, v1.2s, v2.2s"

  /// C7.2.359 UHSUB
  [<TestMethod>]
  member _.``C7.2.359 UHSUB``() =
    testDisasm "2e222420" "uhsub v0.8b, v1.8b, v2.8b"
    testDisasm "2e622420" "uhsub v0.4h, v1.4h, v2.4h"
    testDisasm "2ea22420" "uhsub v0.2s, v1.2s, v2.2s"

  /// C7.2.36 CMLT (zero)
  [<TestMethod>]
  member _.``C7.2.36 CMLT``() =
    testDisasm "0e20a820" "cmlt v0.8b, v1.8b, #0x0"
    testDisasm "0e60a820" "cmlt v0.4h, v1.4h, #0x0"
    testDisasm "0ea0a820" "cmlt v0.2s, v1.2s, #0x0"
    testDisasm "4ee0a820" "cmlt v0.2d, v1.2d, #0x0"

  /// C7.2.360 UMAX
  [<TestMethod>]
  member _.``C7.2.360 UMAX``() =
    testDisasm "2e226420" "umax v0.8b, v1.8b, v2.8b"
    testDisasm "2e626420" "umax v0.4h, v1.4h, v2.4h"
    testDisasm "2ea26420" "umax v0.2s, v1.2s, v2.2s"

  /// C7.2.361 UMAXP
  [<TestMethod>]
  member _.``C7.2.361 UMAXP``() =
    testDisasm "2e22a420" "umaxp v0.8b, v1.8b, v2.8b"
    testDisasm "2e62a420" "umaxp v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2a420" "umaxp v0.2s, v1.2s, v2.2s"

  /// C7.2.362 UMAXV
  [<TestMethod>]
  member _.``C7.2.362 UMAXV``() =
    testDisasm "6eb0a820" "umaxv s0, v1.4s"
    testDisasm "2e30a843" "umaxv b3, v2.8b"
    testDisasm "2e70a843" "umaxv h3, v2.4h"

  /// C7.2.363 UMIN
  [<TestMethod>]
  member _.``C7.2.363 UMIN``() =
    testDisasm "2e226c20" "umin v0.8b, v1.8b, v2.8b"
    testDisasm "2e626c20" "umin v0.4h, v1.4h, v2.4h"
    testDisasm "2ea26c20" "umin v0.2s, v1.2s, v2.2s"

  /// C7.2.364 UMINP
  [<TestMethod>]
  member _.``C7.2.364 UMINP``() =
    testDisasm "2e22ac20" "uminp v0.8b, v1.8b, v2.8b"
    testDisasm "2e62ac20" "uminp v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2ac20" "uminp v0.2s, v1.2s, v2.2s"

  /// C7.2.365 UMINV
  [<TestMethod>]
  member _.``C7.2.365 UMINV``() =
    testDisasm "6eb1a820" "uminv s0, v1.4s"
    testDisasm "2e31a843" "uminv b3, v2.8b"
    testDisasm "2e71a843" "uminv h3, v2.4h"

  /// C7.2.366 UMLAL, UMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.366 UMLAL``() =
    testDisasm "2e628020" "umlal v0.4s, v1.4h, v2.4h"
    testDisasm "2f522020" "umlal v0.4s, v1.4h, v2.h[1]"
    testDisasm "2fa22020" "umlal v0.2d, v1.2s, v2.s[1]"
    testDisasm "2e228020" "umlal v0.8h, v1.8b, v2.8b"

  /// C7.2.366 UMLAL, UMLAL2 (by element)
  [<TestMethod>]
  member _.``C7.2.366 UMLAL2``() =
    testDisasm "6f522020" "umlal2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "6fa22020" "umlal2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "6e228020" "umlal2 v0.8h, v1.16b, v2.16b"
    testDisasm "6ea28020" "umlal2 v0.2d, v1.4s, v2.4s"

  /// C7.2.368 UMLSL, UMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.368 UMLSL``() =
    testDisasm "2e62a020" "umlsl v0.4s, v1.4h, v2.4h"
    testDisasm "2f526020" "umlsl v0.4s, v1.4h, v2.h[1]"
    testDisasm "2fa26020" "umlsl v0.2d, v1.2s, v2.s[1]"
    testDisasm "2e22a020" "umlsl v0.8h, v1.8b, v2.8b"

  /// C7.2.368 UMLSL, UMLSL2 (by element)
  [<TestMethod>]
  member _.``C7.2.368 UMLSL2``() =
    testDisasm "6f526020" "umlsl2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "6fa26020" "umlsl2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "6e22a020" "umlsl2 v0.8h, v1.16b, v2.16b"
    testDisasm "6ea2a020" "umlsl2 v0.2d, v1.4s, v2.4s"

  /// C7.2.37 CMTST
  [<TestMethod>]
  member _.``C7.2.37 CMTST``() =
    testDisasm "0e228c20" "cmtst v0.8b, v1.8b, v2.8b"
    testDisasm "0e628c20" "cmtst v0.4h, v1.4h, v2.4h"
    testDisasm "0ea28c20" "cmtst v0.2s, v1.2s, v2.2s"
    testDisasm "4ee28c20" "cmtst v0.2d, v1.2d, v2.2d"

  /// C7.2.370 UMMLA (vector)
  [<TestMethod>]
  member _.``C7.2.370 UMMLA``() =
    testDisasm "6e82a420" "ummla v0.4s, v1.16b, v2.16b"

  /// C7.2.371 UMOV
  [<TestMethod>]
  member _.``C7.2.371 UMOV``() =
    testDisasm "0e0c3c20" "mov w0, v1.s[1]"
    testDisasm "4e183c20" "mov x0, v1.d[1]"
    testDisasm "0e033c20" "umov w0, v1.b[1]"
    testDisasm "0e063c20" "umov w0, v1.h[1]"

  /// C7.2.372 UMULL, UMULL2 (by element)
  [<TestMethod>]
  member _.``C7.2.372 UMULL2``() =
    testDisasm "6f52a020" "umull2 v0.4s, v1.8h, v2.h[1]"
    testDisasm "6fa2a020" "umull2 v0.2d, v1.4s, v2.s[1]"
    testDisasm "6e62c020" "umull2 v0.4s, v1.8h, v2.8h"
    testDisasm "6ea2c020" "umull2 v0.2d, v1.4s, v2.4s"

  /// C7.2.374 UQADD
  [<TestMethod>]
  member _.``C7.2.374 UQADD``() =
    testDisasm "2e220c20" "uqadd v0.8b, v1.8b, v2.8b"
    testDisasm "2e620c20" "uqadd v0.4h, v1.4h, v2.4h"
    testDisasm "2ea20c20" "uqadd v0.2s, v1.2s, v2.2s"
    testDisasm "6ee20c20" "uqadd v0.2d, v1.2d, v2.2d"

  /// C7.2.375 UQRSHL
  [<TestMethod>]
  member _.``C7.2.375 UQRSHL``() =
    testDisasm "2e225c20" "uqrshl v0.8b, v1.8b, v2.8b"
    testDisasm "2e625c20" "uqrshl v0.4h, v1.4h, v2.4h"
    testDisasm "2ea25c20" "uqrshl v0.2s, v1.2s, v2.2s"
    testDisasm "6ee25c20" "uqrshl v0.2d, v1.2d, v2.2d"

  /// C7.2.376 UQRSHRN, UQRSHRN2
  [<TestMethod>]
  member _.``C7.2.376 UQRSHRN``() =
    testDisasm "2f1f9c20" "uqrshrn v0.4h, v1.4s, #0x1"
    testDisasm "2f3f9c20" "uqrshrn v0.2s, v1.2d, #0x1"
    testDisasm "2f0f9c20" "uqrshrn v0.8b, v1.8h, #0x1"
    testDisasm "7f149eb6" "uqrshrn h22, s21, #0xc"

  /// C7.2.376 UQRSHRN, UQRSHRN2
  [<TestMethod>]
  member _.``C7.2.376 UQRSHRN2``() =
    testDisasm "6f1f9c20" "uqrshrn2 v0.8h, v1.4s, #0x1"
    testDisasm "6f3f9c20" "uqrshrn2 v0.4s, v1.2d, #0x1"
    testDisasm "6f0f9c20" "uqrshrn2 v0.16b, v1.8h, #0x1"

  /// C7.2.377 UQSHL (immediate)
  [<TestMethod>]
  member _.``C7.2.377 UQSHL``() =
    testDisasm "2f097420" "uqshl v0.8b, v1.8b, #0x1"
    testDisasm "2f117420" "uqshl v0.4h, v1.4h, #0x1"
    testDisasm "2f217420" "uqshl v0.2s, v1.2s, #0x1"
    testDisasm "6f417420" "uqshl v0.2d, v1.2d, #0x1"

  /// C7.2.379 UQSHRN, UQSHRN2
  [<TestMethod>]
  member _.``C7.2.379 UQSHRN``() =
    testDisasm "2f1f9420" "uqshrn v0.4h, v1.4s, #0x1"
    testDisasm "2f3f9420" "uqshrn v0.2s, v1.2d, #0x1"
    testDisasm "2f0f9420" "uqshrn v0.8b, v1.8h, #0x1"
    testDisasm "7f1496b6" "uqshrn h22, s21, #0xc"

  /// C7.2.379 UQSHRN, UQSHRN2
  [<TestMethod>]
  member _.``C7.2.379 UQSHRN2``() =
    testDisasm "6f1f9420" "uqshrn2 v0.8h, v1.4s, #0x1"
    testDisasm "6f3f9420" "uqshrn2 v0.4s, v1.2d, #0x1"
    testDisasm "6f0f9420" "uqshrn2 v0.16b, v1.8h, #0x1"

  /// C7.2.38 CNT
  [<TestMethod>]
  member _.``C7.2.38 CNT``() =
    testDisasm "4e205820" "cnt v0.16b, v1.16b"

  /// C7.2.380 UQSUB
  [<TestMethod>]
  member _.``C7.2.380 UQSUB``() =
    testDisasm "2e222c20" "uqsub v0.8b, v1.8b, v2.8b"
    testDisasm "2e622c20" "uqsub v0.4h, v1.4h, v2.4h"
    testDisasm "2ea22c20" "uqsub v0.2s, v1.2s, v2.2s"
    testDisasm "6ee22c20" "uqsub v0.2d, v1.2d, v2.2d"

  /// C7.2.381 UQXTN, UQXTN2
  [<TestMethod>]
  member _.``C7.2.381 UQXTN``() =
    testDisasm "2e214820" "uqxtn v0.8b, v1.8h"
    testDisasm "2ea14820" "uqxtn v0.2s, v1.2d"
    testDisasm "2e614820" "uqxtn v0.4h, v1.4s"
    testDisasm "7e214843" "uqxtn b3, h2"

  /// C7.2.381 UQXTN, UQXTN2
  [<TestMethod>]
  member _.``C7.2.381 UQXTN2``() =
    testDisasm "6e614820" "uqxtn2 v0.8h, v1.4s"
    testDisasm "6ea14820" "uqxtn2 v0.4s, v1.2d"
    testDisasm "6e214820" "uqxtn2 v0.16b, v1.8h"

  /// C7.2.382 URECPE
  [<TestMethod>]
  member _.``C7.2.382 URECPE``() =
    testDisasm "0ea1c820" "urecpe v0.2s, v1.2s"

  /// C7.2.383 URHADD
  [<TestMethod>]
  member _.``C7.2.383 URHADD``() =
    testDisasm "2e221420" "urhadd v0.8b, v1.8b, v2.8b"
    testDisasm "2e621420" "urhadd v0.4h, v1.4h, v2.4h"
    testDisasm "2ea21420" "urhadd v0.2s, v1.2s, v2.2s"

  /// C7.2.384 URSHL
  [<TestMethod>]
  member _.``C7.2.384 URSHL``() =
    testDisasm "2e225420" "urshl v0.8b, v1.8b, v2.8b"
    testDisasm "2e625420" "urshl v0.4h, v1.4h, v2.4h"
    testDisasm "2ea25420" "urshl v0.2s, v1.2s, v2.2s"
    testDisasm "6ee25420" "urshl v0.2d, v1.2d, v2.2d"

  /// C7.2.385 URSHR
  [<TestMethod>]
  member _.``C7.2.385 URSHR``() =
    testDisasm "2f0f2420" "urshr v0.8b, v1.8b, #0x1"
    testDisasm "2f1f2420" "urshr v0.4h, v1.4h, #0x1"
    testDisasm "2f3f2420" "urshr v0.2s, v1.2s, #0x1"
    testDisasm "6f7f2420" "urshr v0.2d, v1.2d, #0x1"

  /// C7.2.386 URSQRTE
  [<TestMethod>]
  member _.``C7.2.386 URSQRTE``() =
    testDisasm "2ea1c820" "ursqrte v0.2s, v1.2s"

  /// C7.2.387 URSRA
  [<TestMethod>]
  member _.``C7.2.387 URSRA``() =
    testDisasm "2f0f3420" "ursra v0.8b, v1.8b, #0x1"
    testDisasm "2f1f3420" "ursra v0.4h, v1.4h, #0x1"
    testDisasm "2f3f3420" "ursra v0.2s, v1.2s, #0x1"
    testDisasm "6f7f3420" "ursra v0.2d, v1.2d, #0x1"

  /// C7.2.388 USDOT (vector)
  [<TestMethod>]
  member _.``C7.2.388 USDOT``() =
    testDisasm "0e829c20" "usdot v0.2s, v1.8b, v2.8b"
    testDisasm "0f81f043" "usdot v3.2s, v2.8b, v1.4b[0]"

  /// C7.2.39 DUP (element)
  [<TestMethod>]
  member _.``C7.2.39 DUP``() =
    testDisasm "0e030420" "dup v0.8b, v1.b[1]"
    testDisasm "0e060420" "dup v0.4h, v1.h[1]"
    testDisasm "0e0c0420" "dup v0.2s, v1.s[1]"
    testDisasm "4e180420" "dup v0.2d, v1.d[1]"

  /// C7.2.390 USHL
  [<TestMethod>]
  member _.``C7.2.390 USHL``() =
    testDisasm "2e224420" "ushl v0.8b, v1.8b, v2.8b"
    testDisasm "2e624420" "ushl v0.4h, v1.4h, v2.4h"
    testDisasm "2ea24420" "ushl v0.2s, v1.2s, v2.2s"
    testDisasm "6ee24420" "ushl v0.2d, v1.2d, v2.2d"
