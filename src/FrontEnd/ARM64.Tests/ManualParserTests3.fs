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
/// One test for each instruction DDI0487F.c describes, STCLRH to BLR in
/// the order of its sections. Each reads words of the instruction and checks
/// the text, and each word's text is one binutils' objdump reads the word as
/// too, so what is asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualParserTests3() =
  let parser =
    Parser(BinReader.Init Endian.Big) :> IInstructionParsable

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// C6.2.251 STCLRH, STCLRLH
  [<TestMethod>]
  member _.``C6.2.251 STCLRH``() =
    testDisasm "7822103f" "stclrh w2, [x1]"
    testDisasm "783f13ff" "stclrh wzr, [sp]"

  /// C6.2.251 STCLRH, STCLRLH
  [<TestMethod>]
  member _.``C6.2.251 STCLRLH``() =
    testDisasm "7862103f" "stclrlh w2, [x1]"
    testDisasm "787f13ff" "stclrlh wzr, [sp]"

  /// C6.2.252 STCLR, STCLRL
  [<TestMethod>]
  member _.``C6.2.252 STCLR``() =
    testDisasm "f822103f" "stclr x2, [x1]"
    testDisasm "b822103f" "stclr w2, [x1]"
    testDisasm "b83f13ff" "stclr wzr, [sp]"
    testDisasm "f83f13ff" "stclr xzr, [sp]"

  /// C6.2.252 STCLR, STCLRL
  [<TestMethod>]
  member _.``C6.2.252 STCLRL``() =
    testDisasm "b862103f" "stclrl w2, [x1]"
    testDisasm "b87f13ff" "stclrl wzr, [sp]"
    testDisasm "f87f13ff" "stclrl xzr, [sp]"

  /// C6.2.253 STEORB, STEORLB
  [<TestMethod>]
  member _.``C6.2.253 STEORB``() =
    testDisasm "3822203f" "steorb w2, [x1]"
    testDisasm "383f23ff" "steorb wzr, [sp]"

  /// C6.2.253 STEORB, STEORLB
  [<TestMethod>]
  member _.``C6.2.253 STEORLB``() =
    testDisasm "3862203f" "steorlb w2, [x1]"
    testDisasm "387f23ff" "steorlb wzr, [sp]"

  /// C6.2.254 STEORH, STEORLH
  [<TestMethod>]
  member _.``C6.2.254 STEORH``() =
    testDisasm "7822203f" "steorh w2, [x1]"
    testDisasm "783f23ff" "steorh wzr, [sp]"

  /// C6.2.254 STEORH, STEORLH
  [<TestMethod>]
  member _.``C6.2.254 STEORLH``() =
    testDisasm "7862203f" "steorlh w2, [x1]"
    testDisasm "787f23ff" "steorlh wzr, [sp]"

  /// C6.2.255 STEOR, STEORL
  [<TestMethod>]
  member _.``C6.2.255 STEOR``() =
    testDisasm "f822203f" "steor x2, [x1]"
    testDisasm "b822203f" "steor w2, [x1]"
    testDisasm "b83f23ff" "steor wzr, [sp]"
    testDisasm "f83f23ff" "steor xzr, [sp]"

  /// C6.2.255 STEOR, STEORL
  [<TestMethod>]
  member _.``C6.2.255 STEORL``() =
    testDisasm "b862203f" "steorl w2, [x1]"
    testDisasm "b87f23ff" "steorl wzr, [sp]"
    testDisasm "f87f23ff" "steorl xzr, [sp]"

  /// C6.2.256 STG
  [<TestMethod>]
  member _.``C6.2.256 STG``() =
    testDisasm "d9200820" "stg x0, [x1]"
    testDisasm "d9201420" "stg x0, [x1], #0x10"
    testDisasm "d9201c20" "stg x0, [x1, #0x10]!"
    testDisasm "d9201820" "stg x0, [x1, #0x10]"

  /// C6.2.257 STGM
  [<TestMethod>]
  member _.``C6.2.257 STGM``() =
    testDisasm "d9a00020" "stgm x0, [x1]"

  /// C6.2.258 STGP
  [<TestMethod>]
  member _.``C6.2.258 STGP``() =
    testDisasm "69000820" "stgp x0, x2, [x1]"
    testDisasm "68808c22" "stgp x2, x3, [x1], #0x10"
    testDisasm "69808c22" "stgp x2, x3, [x1, #0x10]!"
    testDisasm "69008c22" "stgp x2, x3, [x1, #0x10]"

  /// C6.2.259 STLLRB
  [<TestMethod>]
  member _.``C6.2.259 STLLRB``() =
    testDisasm "089f7c20" "stllrb w0, [x1]"
    testDisasm "089f03ff" "stllrb wzr, [sp]"
    testDisasm "088a03e9" "stllrb w9, [sp]"
    testDisasm "0881005f" "stllrb wzr, [x2]"

  /// C6.2.26 B
  [<TestMethod>]
  member _.``C6.2.26 B``() =
    testDisasm "14000001" "b 0x4"

  /// C6.2.260 STLLRH
  [<TestMethod>]
  member _.``C6.2.260 STLLRH``() =
    testDisasm "489f7c20" "stllrh w0, [x1]"
    testDisasm "489f03ff" "stllrh wzr, [sp]"
    testDisasm "488a03e9" "stllrh w9, [sp]"
    testDisasm "4881005f" "stllrh wzr, [x2]"

  /// C6.2.261 STLLR
  [<TestMethod>]
  member _.``C6.2.261 STLLR``() =
    testDisasm "c89f7c20" "stllr x0, [x1]"
    testDisasm "889f7c20" "stllr w0, [x1]"
    testDisasm "889f03ff" "stllr wzr, [sp]"
    testDisasm "888a03e9" "stllr w9, [sp]"

  /// C6.2.262 STLR
  [<TestMethod>]
  member _.``C6.2.262 STLR``() =
    testDisasm "c89ffc20" "stlr x0, [x1]"
    testDisasm "889ffc20" "stlr w0, [x1]"
    testDisasm "889f83ff" "stlr wzr, [sp]"
    testDisasm "888a83e9" "stlr w9, [sp]"

  /// C6.2.263 STLRB
  [<TestMethod>]
  member _.``C6.2.263 STLRB``() =
    testDisasm "089ffc20" "stlrb w0, [x1]"
    testDisasm "089f83ff" "stlrb wzr, [sp]"
    testDisasm "088a83e9" "stlrb w9, [sp]"

  /// C6.2.264 STLRH
  [<TestMethod>]
  member _.``C6.2.264 STLRH``() =
    testDisasm "489ffc20" "stlrh w0, [x1]"
    testDisasm "489f83ff" "stlrh wzr, [sp]"
    testDisasm "488a83e9" "stlrh w9, [sp]"

  /// C6.2.265 STLUR
  [<TestMethod>]
  member _.``C6.2.265 STLUR``() =
    testDisasm "d9000020" "stlur x0, [x1]"
    testDisasm "99010020" "stlur w0, [x1, #0x10]"
    testDisasm "d9010020" "stlur x0, [x1, #0x10]"
    testDisasm "99000020" "stlur w0, [x1]"

  /// C6.2.266 STLURB
  [<TestMethod>]
  member _.``C6.2.266 STLURB``() =
    testDisasm "19000020" "stlurb w0, [x1]"
    testDisasm "19010020" "stlurb w0, [x1, #0x10]"
    testDisasm "191f03ff" "stlurb wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "190a03e9" "stlurb w9, [sp, #0xa0]"

  /// C6.2.267 STLURH
  [<TestMethod>]
  member _.``C6.2.267 STLURH``() =
    testDisasm "59000020" "stlurh w0, [x1]"
    testDisasm "59010020" "stlurh w0, [x1, #0x10]"
    testDisasm "591f03ff" "stlurh wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "590a03e9" "stlurh w9, [sp, #0xa0]"

  /// C6.2.268 STLXP
  [<TestMethod>]
  member _.``C6.2.268 STLXP``() =
    testDisasm "88238820" "stlxp w3, w0, w2, [x1]"
    testDisasm "883f83ff" "stlxp wzr, wzr, w0, [sp]"
    testDisasm "882a83e9" "stlxp w10, w9, w0, [sp]"
    testDisasm "883f83c0" "stlxp wzr, w0, w0, [x30]"

  /// C6.2.269 STLXR
  [<TestMethod>]
  member _.``C6.2.269 STLXR``() =
    testDisasm "8802fc20" "stlxr w2, w0, [x1]"
    testDisasm "881f83ff" "stlxr wzr, wzr, [sp]"
    testDisasm "880a83e9" "stlxr w10, w9, [sp]"
    testDisasm "881f83c0" "stlxr wzr, w0, [x30]"

  /// C6.2.27 BFC
  [<TestMethod>]
  member _.``C6.2.27 BFC``() =
    testDisasm "331d13e0" "bfc w0, #0x3, #0x5"
    testDisasm "b37d13e0" "bfc x0, #0x3, #0x5"
    testDisasm "331f03ff" "bfc wzr, #0x1, #0x1"
    testDisasm "b35f03ff" "bfc xzr, #0x21, #0x1"

  /// C6.2.270 STLXRB
  [<TestMethod>]
  member _.``C6.2.270 STLXRB``() =
    testDisasm "0802fc20" "stlxrb w2, w0, [x1]"
    testDisasm "081f83ff" "stlxrb wzr, wzr, [sp]"
    testDisasm "080a83e9" "stlxrb w10, w9, [sp]"
    testDisasm "081f83c0" "stlxrb wzr, w0, [x30]"

  /// C6.2.271 STLXRH
  [<TestMethod>]
  member _.``C6.2.271 STLXRH``() =
    testDisasm "4802fc20" "stlxrh w2, w0, [x1]"
    testDisasm "481f83ff" "stlxrh wzr, wzr, [sp]"
    testDisasm "480a83e9" "stlxrh w10, w9, [sp]"
    testDisasm "481f83c0" "stlxrh wzr, w0, [x30]"

  /// C6.2.272 STNP
  [<TestMethod>]
  member _.``C6.2.272 STNP``() =
    testDisasm "28000c22" "stnp w2, w3, [x1]"
    testDisasm "28020c22" "stnp w2, w3, [x1, #0x10]"
    testDisasm "a8000c22" "stnp x2, x3, [x1]"
    testDisasm "a8010c22" "stnp x2, x3, [x1, #0x10]"

  /// C6.2.273 STP
  [<TestMethod>]
  member _.``C6.2.273 STP``() =
    testDisasm "28820c22" "stp w2, w3, [x1], #0x10"
    testDisasm "a8810c22" "stp x2, x3, [x1], #0x10"
    testDisasm "29820c22" "stp w2, w3, [x1, #0x10]!"
    testDisasm "a9810c22" "stp x2, x3, [x1, #0x10]!"

  /// C6.2.274 STR (immediate)
  [<TestMethod>]
  member _.``C6.2.274 STR``() =
    testDisasm "b8010420" "str w0, [x1], #0x10"
    testDisasm "f8010420" "str x0, [x1], #0x10"
    testDisasm "b8010c20" "str w0, [x1, #0x10]!"
    testDisasm "f8010c20" "str x0, [x1, #0x10]!"

  /// C6.2.276 STRB (immediate)
  [<TestMethod>]
  member _.``C6.2.276 STRB``() =
    testDisasm "38010420" "strb w0, [x1], #0x10"
    testDisasm "38010c20" "strb w0, [x1, #0x10]!"
    testDisasm "39000020" "strb w0, [x1]"
    testDisasm "39002020" "strb w0, [x1, #0x8]"

  /// C6.2.278 STRH (immediate)
  [<TestMethod>]
  member _.``C6.2.278 STRH``() =
    testDisasm "78010420" "strh w0, [x1], #0x10"
    testDisasm "78010c20" "strh w0, [x1, #0x10]!"
    testDisasm "79000020" "strh w0, [x1]"
    testDisasm "79001020" "strh w0, [x1, #0x8]"

  /// C6.2.28 BFI
  [<TestMethod>]
  member _.``C6.2.28 BFI``() =
    testDisasm "331d1020" "bfi w0, w1, #0x3, #0x5"
    testDisasm "b37d1020" "bfi x0, x1, #0x3, #0x5"
    testDisasm "3301005f" "bfi wzr, w2, #0x1f, #0x1"
    testDisasm "b341005f" "bfi xzr, x2, #0x3f, #0x1"

  /// C6.2.280 STSETB, STSETLB
  [<TestMethod>]
  member _.``C6.2.280 STSETB``() =
    testDisasm "3822303f" "stsetb w2, [x1]"
    testDisasm "383f33ff" "stsetb wzr, [sp]"

  /// C6.2.280 STSETB, STSETLB
  [<TestMethod>]
  member _.``C6.2.280 STSETLB``() =
    testDisasm "3862303f" "stsetlb w2, [x1]"
    testDisasm "387f33ff" "stsetlb wzr, [sp]"

  /// C6.2.281 STSETH, STSETLH
  [<TestMethod>]
  member _.``C6.2.281 STSETH``() =
    testDisasm "7822303f" "stseth w2, [x1]"
    testDisasm "783f33ff" "stseth wzr, [sp]"

  /// C6.2.281 STSETH, STSETLH
  [<TestMethod>]
  member _.``C6.2.281 STSETLH``() =
    testDisasm "7862303f" "stsetlh w2, [x1]"
    testDisasm "787f33ff" "stsetlh wzr, [sp]"

  /// C6.2.282 STSET, STSETL
  [<TestMethod>]
  member _.``C6.2.282 STSET``() =
    testDisasm "f822303f" "stset x2, [x1]"
    testDisasm "b822303f" "stset w2, [x1]"
    testDisasm "b83f33ff" "stset wzr, [sp]"
    testDisasm "f83f33ff" "stset xzr, [sp]"

  /// C6.2.282 STSET, STSETL
  [<TestMethod>]
  member _.``C6.2.282 STSETL``() =
    testDisasm "b862303f" "stsetl w2, [x1]"
    testDisasm "b87f33ff" "stsetl wzr, [sp]"
    testDisasm "f87f33ff" "stsetl xzr, [sp]"

  /// C6.2.283 STSMAXB, STSMAXLB
  [<TestMethod>]
  member _.``C6.2.283 STSMAXB``() =
    testDisasm "3822403f" "stsmaxb w2, [x1]"
    testDisasm "383f43ff" "stsmaxb wzr, [sp]"

  /// C6.2.283 STSMAXB, STSMAXLB
  [<TestMethod>]
  member _.``C6.2.283 STSMAXLB``() =
    testDisasm "3862403f" "stsmaxlb w2, [x1]"
    testDisasm "387f43ff" "stsmaxlb wzr, [sp]"

  /// C6.2.284 STSMAXH, STSMAXLH
  [<TestMethod>]
  member _.``C6.2.284 STSMAXH``() =
    testDisasm "7822403f" "stsmaxh w2, [x1]"
    testDisasm "783f43ff" "stsmaxh wzr, [sp]"

  /// C6.2.284 STSMAXH, STSMAXLH
  [<TestMethod>]
  member _.``C6.2.284 STSMAXLH``() =
    testDisasm "7862403f" "stsmaxlh w2, [x1]"
    testDisasm "787f43ff" "stsmaxlh wzr, [sp]"

  /// C6.2.285 STSMAX, STSMAXL
  [<TestMethod>]
  member _.``C6.2.285 STSMAX``() =
    testDisasm "f822403f" "stsmax x2, [x1]"
    testDisasm "b822403f" "stsmax w2, [x1]"
    testDisasm "b83f43ff" "stsmax wzr, [sp]"
    testDisasm "f83f43ff" "stsmax xzr, [sp]"

  /// C6.2.285 STSMAX, STSMAXL
  [<TestMethod>]
  member _.``C6.2.285 STSMAXL``() =
    testDisasm "b862403f" "stsmaxl w2, [x1]"
    testDisasm "b87f43ff" "stsmaxl wzr, [sp]"
    testDisasm "f87f43ff" "stsmaxl xzr, [sp]"

  /// C6.2.286 STSMINB, STSMINLB
  [<TestMethod>]
  member _.``C6.2.286 STSMINB``() =
    testDisasm "3822503f" "stsminb w2, [x1]"
    testDisasm "383f53ff" "stsminb wzr, [sp]"

  /// C6.2.286 STSMINB, STSMINLB
  [<TestMethod>]
  member _.``C6.2.286 STSMINLB``() =
    testDisasm "3862503f" "stsminlb w2, [x1]"
    testDisasm "387f53ff" "stsminlb wzr, [sp]"

  /// C6.2.287 STSMINH, STSMINLH
  [<TestMethod>]
  member _.``C6.2.287 STSMINH``() =
    testDisasm "7822503f" "stsminh w2, [x1]"
    testDisasm "783f53ff" "stsminh wzr, [sp]"

  /// C6.2.287 STSMINH, STSMINLH
  [<TestMethod>]
  member _.``C6.2.287 STSMINLH``() =
    testDisasm "7862503f" "stsminlh w2, [x1]"
    testDisasm "787f53ff" "stsminlh wzr, [sp]"

  /// C6.2.288 STSMIN, STSMINL
  [<TestMethod>]
  member _.``C6.2.288 STSMIN``() =
    testDisasm "f822503f" "stsmin x2, [x1]"
    testDisasm "b822503f" "stsmin w2, [x1]"
    testDisasm "b83f53ff" "stsmin wzr, [sp]"
    testDisasm "f83f53ff" "stsmin xzr, [sp]"

  /// C6.2.288 STSMIN, STSMINL
  [<TestMethod>]
  member _.``C6.2.288 STSMINL``() =
    testDisasm "b862503f" "stsminl w2, [x1]"
    testDisasm "b87f53ff" "stsminl wzr, [sp]"
    testDisasm "f87f53ff" "stsminl xzr, [sp]"

  /// C6.2.289 STTR
  [<TestMethod>]
  member _.``C6.2.289 STTR``() =
    testDisasm "b8010820" "sttr w0, [x1, #0x10]"
    testDisasm "f8000820" "sttr x0, [x1]"
    testDisasm "f8010820" "sttr x0, [x1, #0x10]"
    testDisasm "b8000820" "sttr w0, [x1]"

  /// C6.2.29 BFM
  [<TestMethod>]
  member _.``C6.2.29 BFM``() =
    testDisasm "331d13e0" "bfc w0, #0x3, #0x5"
    testDisasm "b37d13e0" "bfc x0, #0x3, #0x5"
    testDisasm "331d1020" "bfi w0, w1, #0x3, #0x5"
    testDisasm "b37d1020" "bfi x0, x1, #0x3, #0x5"

  /// C6.2.290 STTRB
  [<TestMethod>]
  member _.``C6.2.290 STTRB``() =
    testDisasm "38010820" "sttrb w0, [x1, #0x10]"
    testDisasm "38000820" "sttrb w0, [x1]"
    testDisasm "381f0bff" "sttrb wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "380a0be9" "sttrb w9, [sp, #0xa0]"

  /// C6.2.291 STTRH
  [<TestMethod>]
  member _.``C6.2.291 STTRH``() =
    testDisasm "78010820" "sttrh w0, [x1, #0x10]"
    testDisasm "78000820" "sttrh w0, [x1]"
    testDisasm "781f0bff" "sttrh wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "780a0be9" "sttrh w9, [sp, #0xa0]"

  /// C6.2.292 STUMAXB, STUMAXLB
  [<TestMethod>]
  member _.``C6.2.292 STUMAXB``() =
    testDisasm "3822603f" "stumaxb w2, [x1]"
    testDisasm "383f63ff" "stumaxb wzr, [sp]"

  /// C6.2.292 STUMAXB, STUMAXLB
  [<TestMethod>]
  member _.``C6.2.292 STUMAXLB``() =
    testDisasm "3862603f" "stumaxlb w2, [x1]"
    testDisasm "387f63ff" "stumaxlb wzr, [sp]"

  /// C6.2.293 STUMAXH, STUMAXLH
  [<TestMethod>]
  member _.``C6.2.293 STUMAXH``() =
    testDisasm "7822603f" "stumaxh w2, [x1]"
    testDisasm "783f63ff" "stumaxh wzr, [sp]"

  /// C6.2.293 STUMAXH, STUMAXLH
  [<TestMethod>]
  member _.``C6.2.293 STUMAXLH``() =
    testDisasm "7862603f" "stumaxlh w2, [x1]"
    testDisasm "787f63ff" "stumaxlh wzr, [sp]"

  /// C6.2.294 STUMAX, STUMAXL
  [<TestMethod>]
  member _.``C6.2.294 STUMAX``() =
    testDisasm "f822603f" "stumax x2, [x1]"
    testDisasm "b822603f" "stumax w2, [x1]"
    testDisasm "b83f63ff" "stumax wzr, [sp]"
    testDisasm "f83f63ff" "stumax xzr, [sp]"

  /// C6.2.294 STUMAX, STUMAXL
  [<TestMethod>]
  member _.``C6.2.294 STUMAXL``() =
    testDisasm "b862603f" "stumaxl w2, [x1]"
    testDisasm "b87f63ff" "stumaxl wzr, [sp]"
    testDisasm "f87f63ff" "stumaxl xzr, [sp]"

  /// C6.2.295 STUMINB, STUMINLB
  [<TestMethod>]
  member _.``C6.2.295 STUMINB``() =
    testDisasm "3822703f" "stuminb w2, [x1]"
    testDisasm "383f73ff" "stuminb wzr, [sp]"

  /// C6.2.295 STUMINB, STUMINLB
  [<TestMethod>]
  member _.``C6.2.295 STUMINLB``() =
    testDisasm "3862703f" "stuminlb w2, [x1]"
    testDisasm "387f73ff" "stuminlb wzr, [sp]"

  /// C6.2.296 STUMINH, STUMINLH
  [<TestMethod>]
  member _.``C6.2.296 STUMINH``() =
    testDisasm "7822703f" "stuminh w2, [x1]"
    testDisasm "783f73ff" "stuminh wzr, [sp]"

  /// C6.2.296 STUMINH, STUMINLH
  [<TestMethod>]
  member _.``C6.2.296 STUMINLH``() =
    testDisasm "7862703f" "stuminlh w2, [x1]"
    testDisasm "787f73ff" "stuminlh wzr, [sp]"

  /// C6.2.297 STUMIN, STUMINL
  [<TestMethod>]
  member _.``C6.2.297 STUMIN``() =
    testDisasm "f822703f" "stumin x2, [x1]"
    testDisasm "b822703f" "stumin w2, [x1]"
    testDisasm "b83f73ff" "stumin wzr, [sp]"
    testDisasm "f83f73ff" "stumin xzr, [sp]"

  /// C6.2.297 STUMIN, STUMINL
  [<TestMethod>]
  member _.``C6.2.297 STUMINL``() =
    testDisasm "b862703f" "stuminl w2, [x1]"
    testDisasm "b87f73ff" "stuminl wzr, [sp]"
    testDisasm "f87f73ff" "stuminl xzr, [sp]"

  /// C6.2.298 STUR
  [<TestMethod>]
  member _.``C6.2.298 STUR``() =
    testDisasm "b8010020" "stur w0, [x1, #0x10]"
    testDisasm "f8000020" "stur x0, [x1]"
    testDisasm "f8010020" "stur x0, [x1, #0x10]"
    testDisasm "b8000020" "stur w0, [x1]"

  /// C6.2.299 STURB
  [<TestMethod>]
  member _.``C6.2.299 STURB``() =
    testDisasm "38010020" "sturb w0, [x1, #0x10]"
    testDisasm "38000020" "sturb w0, [x1]"
    testDisasm "381f03ff" "sturb wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "380a03e9" "sturb w9, [sp, #0xa0]"

  /// C6.2.3 ADD (extended register)
  [<TestMethod>]
  member _.``C6.2.3 ADD``() =
    testDisasm "0b020020" "add w0, w1, w2"
    testDisasm "11004020" "add w0, w1, #0x10"
    testDisasm "91004020" "add x0, x1, #0x10"
    testDisasm "8b020020" "add x0, x1, x2"

  /// C6.2.30 BFXIL
  [<TestMethod>]
  member _.``C6.2.30 BFXIL``() =
    testDisasm "33031420" "bfxil w0, w1, #0x3, #0x3"
    testDisasm "b3431420" "bfxil x0, x1, #0x3, #0x3"
    testDisasm "b34003e0" "bfxil x0, xzr, #0x0, #0x1"
    testDisasm "330a2be9" "bfxil w9, wzr, #0xa, #0x1"

  /// C6.2.300 STURH
  [<TestMethod>]
  member _.``C6.2.300 STURH``() =
    testDisasm "78010020" "sturh w0, [x1, #0x10]"
    testDisasm "78000020" "sturh w0, [x1]"
    testDisasm "781f03ff" "sturh wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "780a03e9" "sturh w9, [sp, #0xa0]"

  /// C6.2.301 STXP
  [<TestMethod>]
  member _.``C6.2.301 STXP``() =
    testDisasm "88230820" "stxp w3, w0, w2, [x1]"
    testDisasm "883f03ff" "stxp wzr, wzr, w0, [sp]"
    testDisasm "882a03e9" "stxp w10, w9, w0, [sp]"
    testDisasm "883f03c0" "stxp wzr, w0, w0, [x30]"

  /// C6.2.302 STXR
  [<TestMethod>]
  member _.``C6.2.302 STXR``() =
    testDisasm "88027c20" "stxr w2, w0, [x1]"
    testDisasm "881f03ff" "stxr wzr, wzr, [sp]"
    testDisasm "880a03e9" "stxr w10, w9, [sp]"
    testDisasm "881f03c0" "stxr wzr, w0, [x30]"

  /// C6.2.303 STXRB
  [<TestMethod>]
  member _.``C6.2.303 STXRB``() =
    testDisasm "08027c20" "stxrb w2, w0, [x1]"
    testDisasm "081f03ff" "stxrb wzr, wzr, [sp]"
    testDisasm "080a03e9" "stxrb w10, w9, [sp]"
    testDisasm "081f03c0" "stxrb wzr, w0, [x30]"

  /// C6.2.304 STXRH
  [<TestMethod>]
  member _.``C6.2.304 STXRH``() =
    testDisasm "48027c20" "stxrh w2, w0, [x1]"
    testDisasm "481f03ff" "stxrh wzr, wzr, [sp]"
    testDisasm "480a03e9" "stxrh w10, w9, [sp]"
    testDisasm "481f03c0" "stxrh wzr, w0, [x30]"

  /// C6.2.305 STZ2G
  [<TestMethod>]
  member _.``C6.2.305 STZ2G``() =
    testDisasm "d9e00820" "stz2g x0, [x1]"
    testDisasm "d9e01420" "stz2g x0, [x1], #0x10"
    testDisasm "d9e01c20" "stz2g x0, [x1, #0x10]!"
    testDisasm "d9e01820" "stz2g x0, [x1, #0x10]"

  /// C6.2.306 STZG
  [<TestMethod>]
  member _.``C6.2.306 STZG``() =
    testDisasm "d9600820" "stzg x0, [x1]"
    testDisasm "d9601420" "stzg x0, [x1], #0x10"
    testDisasm "d9601c20" "stzg x0, [x1, #0x10]!"
    testDisasm "d9601820" "stzg x0, [x1, #0x10]"

  /// C6.2.307 STZGM
  [<TestMethod>]
  member _.``C6.2.307 STZGM``() =
    testDisasm "d9200020" "stzgm x0, [x1]"

  /// C6.2.308 SUB (extended register)
  [<TestMethod>]
  member _.``C6.2.308 SUB``() =
    testDisasm "4b0203e0" "neg w0, w2"
    testDisasm "4b020020" "sub w0, w1, w2"
    testDisasm "51004020" "sub w0, w1, #0x10"
    testDisasm "d1004020" "sub x0, x1, #0x10"

  /// C6.2.31 BIC (shifted register)
  [<TestMethod>]
  member _.``C6.2.31 BIC``() =
    testDisasm "0a220020" "bic w0, w1, w2"
    testDisasm "2f009460" "bic v0.4h, #0x3"
    testDisasm "2f001460" "bic v0.2s, #0x3"
    testDisasm "0e621c20" "bic v0.8b, v1.8b, v2.8b"

  /// C6.2.311 SUBG
  [<TestMethod>]
  member _.``C6.2.311 SUBG``() =
    testDisasm "d1800020" "subg x0, x1, #0x0, #0x0"
    testDisasm "d19f03ff" "subg sp, sp, #0x1f0, #0x0"
    testDisasm "d18a03e9" "subg x9, sp, #0xa0, #0x0"
    testDisasm "d181005f" "subg sp, x2, #0x10, #0x0"

  /// C6.2.312 SUBP
  [<TestMethod>]
  member _.``C6.2.312 SUBP``() =
    testDisasm "9ac20020" "subp x0, x1, x2"
    testDisasm "9adf03ff" "subp xzr, sp, sp"
    testDisasm "9aca03e9" "subp x9, sp, x10"
    testDisasm "9adf03c0" "subp x0, x30, sp"

  /// C6.2.313 SUBPS
  [<TestMethod>]
  member _.``C6.2.313 SUBPS``() =
    testDisasm "bac1001f" "cmpp x0, x1"
    testDisasm "bac20020" "subps x0, x1, x2"
    testDisasm "badf03ff" "cmpp sp, sp"
    testDisasm "baca03e9" "subps x9, sp, x10"

  /// C6.2.314 SUBS (extended register)
  [<TestMethod>]
  member _.``C6.2.314 SUBS``() =
    testDisasm "6b02003f" "cmp w1, w2"
    testDisasm "7100403f" "cmp w1, #0x10"
    testDisasm "f100403f" "cmp x1, #0x10"
    testDisasm "eb02003f" "cmp x1, x2"

  /// C6.2.317 SVC
  [<TestMethod>]
  member _.``C6.2.317 SVC``() =
    testDisasm "d4010041" "svc #0x802"

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPAB``() =
    testDisasm "38a28020" "swpab w2, w0, [x1]"
    testDisasm "38bf83ff" "swpab wzr, wzr, [sp]"
    testDisasm "38aa83e9" "swpab w10, w9, [sp]"
    testDisasm "38bf83c0" "swpab wzr, w0, [x30]"

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPALB``() =
    testDisasm "38e28020" "swpalb w2, w0, [x1]"
    testDisasm "38ff83ff" "swpalb wzr, wzr, [sp]"
    testDisasm "38ea83e9" "swpalb w10, w9, [sp]"
    testDisasm "38ff83c0" "swpalb wzr, w0, [x30]"

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPB``() =
    testDisasm "38228020" "swpb w2, w0, [x1]"
    testDisasm "383f83ff" "swpb wzr, wzr, [sp]"
    testDisasm "382a83e9" "swpb w10, w9, [sp]"
    testDisasm "383f83c0" "swpb wzr, w0, [x30]"

  /// C6.2.318 SWPB, SWPAB, SWPALB, SWPLB
  [<TestMethod>]
  member _.``C6.2.318 SWPLB``() =
    testDisasm "38628020" "swplb w2, w0, [x1]"
    testDisasm "387f83ff" "swplb wzr, wzr, [sp]"
    testDisasm "386a83e9" "swplb w10, w9, [sp]"
    testDisasm "387f83c0" "swplb wzr, w0, [x30]"

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPAH``() =
    testDisasm "78a28020" "swpah w2, w0, [x1]"
    testDisasm "78bf83ff" "swpah wzr, wzr, [sp]"
    testDisasm "78aa83e9" "swpah w10, w9, [sp]"
    testDisasm "78bf83c0" "swpah wzr, w0, [x30]"

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPALH``() =
    testDisasm "78e28020" "swpalh w2, w0, [x1]"
    testDisasm "78ff83ff" "swpalh wzr, wzr, [sp]"
    testDisasm "78ea83e9" "swpalh w10, w9, [sp]"
    testDisasm "78ff83c0" "swpalh wzr, w0, [x30]"

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPH``() =
    testDisasm "78228020" "swph w2, w0, [x1]"
    testDisasm "783f83ff" "swph wzr, wzr, [sp]"
    testDisasm "782a83e9" "swph w10, w9, [sp]"
    testDisasm "783f83c0" "swph wzr, w0, [x30]"

  /// C6.2.319 SWPH, SWPAH, SWPALH, SWPLH
  [<TestMethod>]
  member _.``C6.2.319 SWPLH``() =
    testDisasm "78628020" "swplh w2, w0, [x1]"
    testDisasm "787f83ff" "swplh wzr, wzr, [sp]"
    testDisasm "786a83e9" "swplh w10, w9, [sp]"
    testDisasm "787f83c0" "swplh wzr, w0, [x30]"

  /// C6.2.32 BICS (shifted register)
  [<TestMethod>]
  member _.``C6.2.32 BICS``() =
    testDisasm "6a220020" "bics w0, w1, w2"
    testDisasm "ea220020" "bics x0, x1, x2"
    testDisasm "6a3f03ff" "bics wzr, wzr, wzr"
    testDisasm "6a2a03e9" "bics w9, wzr, w10"

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWP``() =
    testDisasm "f8228020" "swp x2, x0, [x1]"
    testDisasm "b8228020" "swp w2, w0, [x1]"
    testDisasm "b83f83ff" "swp wzr, wzr, [sp]"
    testDisasm "b82a83e9" "swp w10, w9, [sp]"

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWPA``() =
    testDisasm "b8a28020" "swpa w2, w0, [x1]"
    testDisasm "b8bf83ff" "swpa wzr, wzr, [sp]"
    testDisasm "b8aa83e9" "swpa w10, w9, [sp]"
    testDisasm "b8bf83c0" "swpa wzr, w0, [x30]"

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWPAL``() =
    testDisasm "b8e28020" "swpal w2, w0, [x1]"
    testDisasm "b8ff83ff" "swpal wzr, wzr, [sp]"
    testDisasm "b8ea83e9" "swpal w10, w9, [sp]"
    testDisasm "b8ff83c0" "swpal wzr, w0, [x30]"

  /// C6.2.320 SWP, SWPA, SWPAL, SWPL
  [<TestMethod>]
  member _.``C6.2.320 SWPL``() =
    testDisasm "b8628020" "swpl w2, w0, [x1]"
    testDisasm "b87f83ff" "swpl wzr, wzr, [sp]"
    testDisasm "b86a83e9" "swpl w10, w9, [sp]"
    testDisasm "b87f83c0" "swpl wzr, w0, [x30]"

  /// C6.2.321 SXTB
  [<TestMethod>]
  member _.``C6.2.321 SXTB``() =
    testDisasm "13001c20" "sxtb w0, w1"
    testDisasm "93401c20" "sxtb x0, w1"

  /// C6.2.322 SXTH
  [<TestMethod>]
  member _.``C6.2.322 SXTH``() =
    testDisasm "13003c20" "sxth w0, w1"
    testDisasm "93403c20" "sxth x0, w1"

  /// C6.2.323 SXTW
  [<TestMethod>]
  member _.``C6.2.323 SXTW``() =
    testDisasm "93407c20" "sxtw x0, w1"

  /// C6.2.324 SYS
  [<TestMethod>]
  member _.``C6.2.324 SYS``() =
    testDisasm "d50b7380" "cfp rctx, x0"
    testDisasm "d50b73e0" "cpp rctx, x0"
    testDisasm "d50b73a0" "dvp rctx, x0"
    testDisasm "d50a03e9" "sys #0x2, c0, c3, #0x7, x9"

  /// C6.2.325 SYSL
  [<TestMethod>]
  member _.``C6.2.325 SYSL``() =
    testDisasm "d52a03e9" "sysl x9, #0x2, c0, c3, #0x7"
    testDisasm "d528001f" "sysl xzr, #0x0, c0, c0, #0x0"

  /// C6.2.326 TBNZ
  [<TestMethod>]
  member _.``C6.2.326 TBNZ``() =
    testDisasm "37010043" "tbnz w3, #0x0, 0x2008"
    testDisasm "371f03ff" "tbnz wzr, #0x3, 0xffffffffffffe07c"
    testDisasm "b7010043" "tbnz x3, #0x20, 0x2008"
    testDisasm "b71f03ff" "tbnz xzr, #0x23, 0xffffffffffffe07c"

  /// C6.2.327 TBZ
  [<TestMethod>]
  member _.``C6.2.327 TBZ``() =
    testDisasm "36010043" "tbz w3, #0x0, 0x2008"
    testDisasm "361f03ff" "tbz wzr, #0x3, 0xffffffffffffe07c"
    testDisasm "b6010043" "tbz x3, #0x20, 0x2008"
    testDisasm "b61f03ff" "tbz xzr, #0x23, 0xffffffffffffe07c"

  /// C6.2.328 TLBI
  [<TestMethod>]
  member _.``C6.2.328 TLBI``() =
    testDisasm "d508811f" "tlbi vmalle1os"
    testDisasm "d5088120" "tlbi vae1os, x0"
    testDisasm "d508813f" "tlbi vae1os, xzr"
    testDisasm "d5088140" "tlbi aside1os, x0"

  /// C6.2.329 TSB CSYNC
  [<TestMethod>]
  member _.``C6.2.329 TSB``() =
    testDisasm "d503225f" "tsb csync"

  /// C6.2.33 BL
  [<TestMethod>]
  member _.``C6.2.33 BL``() =
    testDisasm "94000001" "bl 0x4"

  /// C6.2.330 TST (immediate)
  [<TestMethod>]
  member _.``C6.2.330 TST``() =
    testDisasm "f240783f" "tst x1, #0x7fffffff"
    testDisasm "721c003f" "tst w1, #0x10"
    testDisasm "6a02003f" "tst w1, w2"
    testDisasm "ea02003f" "tst x1, x2"

  /// C6.2.332 UBFIZ
  [<TestMethod>]
  member _.``C6.2.332 UBFIZ``() =
    testDisasm "531d1020" "ubfiz w0, w1, #0x3, #0x5"
    testDisasm "d37d1020" "ubfiz x0, x1, #0x3, #0x5"
    testDisasm "531f03ff" "ubfiz wzr, wzr, #0x1, #0x1"
    testDisasm "530a03e9" "ubfiz w9, wzr, #0x16, #0x1"

  /// C6.2.333 UBFM
  [<TestMethod>]
  member _.``C6.2.333 UBFM``() =
    testDisasm "531f7820" "lsl w0, w1, #0x1"
    testDisasm "d37ff820" "lsl x0, x1, #0x1"
    testDisasm "53017c20" "lsr w0, w1, #0x1"
    testDisasm "d341fc20" "lsr x0, x1, #0x1"

  /// C6.2.334 UBFX
  [<TestMethod>]
  member _.``C6.2.334 UBFX``() =
    testDisasm "53031420" "ubfx w0, w1, #0x3, #0x3"
    testDisasm "d3431420" "ubfx x0, x1, #0x3, #0x3"
    testDisasm "530a2be9" "ubfx w9, wzr, #0xa, #0x1"
    testDisasm "d34a2be9" "ubfx x9, xzr, #0xa, #0x1"

  /// C6.2.335 UDF
  [<TestMethod>]
  member _.``C6.2.335 UDF``() =
    testDisasm "00000005" "udf #0x5"

  /// C6.2.336 UDIV
  [<TestMethod>]
  member _.``C6.2.336 UDIV``() =
    testDisasm "1ac20820" "udiv w0, w1, w2"
    testDisasm "9ac20820" "udiv x0, x1, x2"
    testDisasm "1adf0bff" "udiv wzr, wzr, wzr"
    testDisasm "1aca0be9" "udiv w9, wzr, w10"

  /// C6.2.337 UMADDL
  [<TestMethod>]
  member _.``C6.2.337 UMADDL``() =
    testDisasm "9ba20c20" "umaddl x0, w1, w2, x3"
    testDisasm "9ba27c20" "umull x0, w1, w2"
    testDisasm "9bbf03ff" "umaddl xzr, wzr, wzr, x0"
    testDisasm "9baa03e9" "umaddl x9, wzr, w10, x0"

  /// C6.2.338 UMNEGL
  [<TestMethod>]
  member _.``C6.2.338 UMNEGL``() =
    testDisasm "9ba2fc20" "umnegl x0, w1, w2"
    testDisasm "9bbfffff" "umnegl xzr, wzr, wzr"
    testDisasm "9baaffe9" "umnegl x9, wzr, w10"
    testDisasm "9bbfffc0" "umnegl x0, w30, wzr"

  /// C6.2.339 UMSUBL
  [<TestMethod>]
  member _.``C6.2.339 UMSUBL``() =
    testDisasm "9ba2fc20" "umnegl x0, w1, w2"
    testDisasm "9ba28c20" "umsubl x0, w1, w2, x3"
    testDisasm "9bbf83ff" "umsubl xzr, wzr, wzr, x0"
    testDisasm "9baa83e9" "umsubl x9, wzr, w10, x0"

  /// C6.2.34 BLR
  [<TestMethod>]
  member _.``C6.2.34 BLR``() =
    testDisasm "d63f03c0" "blr x30"
    testDisasm "d63f03e0" "blr xzr"
