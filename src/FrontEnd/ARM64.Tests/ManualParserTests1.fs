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
/// One test for each instruction DDI0487F.c describes, ADC to LDUMAXL in
/// the order of its sections. Each reads words of the instruction and checks
/// the text, and each word's text is one binutils' objdump reads the word as
/// too, so what is asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualParserTests1() =
  let parser =
    Parser(BinReader.Init Endian.Big) :> IInstructionParsable

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// C6.2.1 ADC
  [<TestMethod>]
  member _.``C6.2.1 ADC``() =
    testDisasm "1a020020" "adc w0, w1, w2"
    testDisasm "9a020020" "adc x0, x1, x2"
    testDisasm "1a1f03ff" "adc wzr, wzr, wzr"
    testDisasm "1a0a03e9" "adc w9, wzr, w10"

  /// C6.2.10 ADR
  [<TestMethod>]
  member _.``C6.2.10 ADR``() =
    testDisasm "10000020" "adr x0, 0x4"
    testDisasm "101f03ff" "adr xzr, 0x3e07c"

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADD``() =
    testDisasm "f8220020" "ldadd x2, x0, [x1]"
    testDisasm "f822003f" "stadd x2, [x1]"
    testDisasm "b8220020" "ldadd w2, w0, [x1]"
    testDisasm "b822003f" "stadd w2, [x1]"

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADDA``() =
    testDisasm "b8a20020" "ldadda w2, w0, [x1]"
    testDisasm "b8bf03ff" "ldadda wzr, wzr, [sp]"
    testDisasm "b8aa03e9" "ldadda w10, w9, [sp]"
    testDisasm "b8bf03c0" "ldadda wzr, w0, [x30]"

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADDAL``() =
    testDisasm "b8e20020" "ldaddal w2, w0, [x1]"
    testDisasm "b8ff03ff" "ldaddal wzr, wzr, [sp]"
    testDisasm "b8ea03e9" "ldaddal w10, w9, [sp]"
    testDisasm "b8ff03c0" "ldaddal wzr, w0, [x30]"

  /// C6.2.100 LDADD, LDADDA, LDADDAL, LDADDL
  [<TestMethod>]
  member _.``C6.2.100 LDADDL``() =
    testDisasm "b8620020" "ldaddl w2, w0, [x1]"
    testDisasm "b862003f" "staddl w2, [x1]"
    testDisasm "b87f03ff" "staddl wzr, [sp]"
    testDisasm "b86a03e9" "ldaddl w10, w9, [sp]"

  /// C6.2.101 LDAPR
  [<TestMethod>]
  member _.``C6.2.101 LDAPR``() =
    testDisasm "f8bfc020" "ldapr x0, [x1]"
    testDisasm "b8bfc020" "ldapr w0, [x1]"
    testDisasm "b8bfc3ff" "ldapr wzr, [sp]"
    testDisasm "b8bfc3e0" "ldapr w0, [sp]"

  /// C6.2.102 LDAPRB
  [<TestMethod>]
  member _.``C6.2.102 LDAPRB``() =
    testDisasm "38bfc020" "ldaprb w0, [x1]"
    testDisasm "38bfc3ff" "ldaprb wzr, [sp]"
    testDisasm "38bfc3e0" "ldaprb w0, [sp]"

  /// C6.2.103 LDAPRH
  [<TestMethod>]
  member _.``C6.2.103 LDAPRH``() =
    testDisasm "78bfc020" "ldaprh w0, [x1]"
    testDisasm "78bfc3ff" "ldaprh wzr, [sp]"
    testDisasm "78bfc3e0" "ldaprh w0, [sp]"

  /// C6.2.104 LDAPUR
  [<TestMethod>]
  member _.``C6.2.104 LDAPUR``() =
    testDisasm "d9400020" "ldapur x0, [x1]"
    testDisasm "99410020" "ldapur w0, [x1, #0x10]"
    testDisasm "d9410020" "ldapur x0, [x1, #0x10]"
    testDisasm "99400020" "ldapur w0, [x1]"

  /// C6.2.105 LDAPURB
  [<TestMethod>]
  member _.``C6.2.105 LDAPURB``() =
    testDisasm "19400020" "ldapurb w0, [x1]"
    testDisasm "19410020" "ldapurb w0, [x1, #0x10]"
    testDisasm "195f03ff" "ldapurb wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "194a03e9" "ldapurb w9, [sp, #0xa0]"

  /// C6.2.106 LDAPURH
  [<TestMethod>]
  member _.``C6.2.106 LDAPURH``() =
    testDisasm "59400020" "ldapurh w0, [x1]"
    testDisasm "59410020" "ldapurh w0, [x1, #0x10]"
    testDisasm "595f03ff" "ldapurh wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "594a03e9" "ldapurh w9, [sp, #0xa0]"

  /// C6.2.107 LDAPURSB
  [<TestMethod>]
  member _.``C6.2.107 LDAPURSB``() =
    testDisasm "19800020" "ldapursb x0, [x1]"
    testDisasm "19c10020" "ldapursb w0, [x1, #0x10]"
    testDisasm "19810020" "ldapursb x0, [x1, #0x10]"
    testDisasm "19c00020" "ldapursb w0, [x1]"

  /// C6.2.108 LDAPURSH
  [<TestMethod>]
  member _.``C6.2.108 LDAPURSH``() =
    testDisasm "59800020" "ldapursh x0, [x1]"
    testDisasm "59c10020" "ldapursh w0, [x1, #0x10]"
    testDisasm "59810020" "ldapursh x0, [x1, #0x10]"
    testDisasm "59c00020" "ldapursh w0, [x1]"

  /// C6.2.109 LDAPURSW
  [<TestMethod>]
  member _.``C6.2.109 LDAPURSW``() =
    testDisasm "99800020" "ldapursw x0, [x1]"
    testDisasm "99810020" "ldapursw x0, [x1, #0x10]"
    testDisasm "999f03ff" "ldapursw xzr, [sp, #0xfffffffffffffff0]"
    testDisasm "998a03e9" "ldapursw x9, [sp, #0xa0]"

  /// C6.2.11 ADRP
  [<TestMethod>]
  member _.``C6.2.11 ADRP``() =
    testDisasm "90000000" "adrp x0, 0x0"
    testDisasm "901f03ff" "adrp xzr, 0x3e07c000"

  /// C6.2.110 LDAR
  [<TestMethod>]
  member _.``C6.2.110 LDAR``() =
    testDisasm "c8dffc20" "ldar x0, [x1]"
    testDisasm "88dffc20" "ldar w0, [x1]"

  /// C6.2.111 LDARB
  [<TestMethod>]
  member _.``C6.2.111 LDARB``() =
    testDisasm "08dffc20" "ldarb w0, [x1]"

  /// C6.2.112 LDARH
  [<TestMethod>]
  member _.``C6.2.112 LDARH``() =
    testDisasm "48dffc20" "ldarh w0, [x1]"

  /// C6.2.113 LDAXP
  [<TestMethod>]
  member _.``C6.2.113 LDAXP``() =
    testDisasm "887f8022" "ldaxp w2, w0, [x1]"
    testDisasm "887f83ff" "ldaxp wzr, w0, [sp]"
    testDisasm "886a83e9" "ldaxp w9, w0, [sp]"
    testDisasm "8861fc43" "ldaxp w3, wzr, [x2]"

  /// C6.2.114 LDAXR
  [<TestMethod>]
  member _.``C6.2.114 LDAXR``() =
    testDisasm "885ffc20" "ldaxr w0, [x1]"
    testDisasm "885f83ff" "ldaxr wzr, [sp]"
    testDisasm "884a83e9" "ldaxr w9, [sp]"
    testDisasm "c8418043" "ldaxr x3, [x2]"

  /// C6.2.115 LDAXRB
  [<TestMethod>]
  member _.``C6.2.115 LDAXRB``() =
    testDisasm "085ffc20" "ldaxrb w0, [x1]"
    testDisasm "085f83ff" "ldaxrb wzr, [sp]"
    testDisasm "084a83e9" "ldaxrb w9, [sp]"

  /// C6.2.116 LDAXRH
  [<TestMethod>]
  member _.``C6.2.116 LDAXRH``() =
    testDisasm "485ffc20" "ldaxrh w0, [x1]"
    testDisasm "485f83ff" "ldaxrh wzr, [sp]"
    testDisasm "484a83e9" "ldaxrh w9, [sp]"

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRAB``() =
    testDisasm "38a21020" "ldclrab w2, w0, [x1]"
    testDisasm "38bf13ff" "ldclrab wzr, wzr, [sp]"
    testDisasm "38aa13e9" "ldclrab w10, w9, [sp]"
    testDisasm "38bf13c0" "ldclrab wzr, w0, [x30]"

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRALB``() =
    testDisasm "38e21020" "ldclralb w2, w0, [x1]"
    testDisasm "38ff13ff" "ldclralb wzr, wzr, [sp]"
    testDisasm "38ea13e9" "ldclralb w10, w9, [sp]"
    testDisasm "38ff13c0" "ldclralb wzr, w0, [x30]"

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRB``() =
    testDisasm "38221020" "ldclrb w2, w0, [x1]"
    testDisasm "3822103f" "stclrb w2, [x1]"
    testDisasm "383f13ff" "stclrb wzr, [sp]"
    testDisasm "382a13e9" "ldclrb w10, w9, [sp]"

  /// C6.2.117 LDCLRB, LDCLRAB, LDCLRALB, LDCLRLB
  [<TestMethod>]
  member _.``C6.2.117 LDCLRLB``() =
    testDisasm "38621020" "ldclrlb w2, w0, [x1]"
    testDisasm "3862103f" "stclrlb w2, [x1]"
    testDisasm "387f13ff" "stclrlb wzr, [sp]"
    testDisasm "386a13e9" "ldclrlb w10, w9, [sp]"

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRAH``() =
    testDisasm "78a21020" "ldclrah w2, w0, [x1]"
    testDisasm "78bf13ff" "ldclrah wzr, wzr, [sp]"
    testDisasm "78aa13e9" "ldclrah w10, w9, [sp]"
    testDisasm "78bf13c0" "ldclrah wzr, w0, [x30]"

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRALH``() =
    testDisasm "78e21020" "ldclralh w2, w0, [x1]"
    testDisasm "78ff13ff" "ldclralh wzr, wzr, [sp]"
    testDisasm "78ea13e9" "ldclralh w10, w9, [sp]"
    testDisasm "78ff13c0" "ldclralh wzr, w0, [x30]"

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRH``() =
    testDisasm "78221020" "ldclrh w2, w0, [x1]"
    testDisasm "7822103f" "stclrh w2, [x1]"
    testDisasm "783f13ff" "stclrh wzr, [sp]"
    testDisasm "782a13e9" "ldclrh w10, w9, [sp]"

  /// C6.2.118 LDCLRH, LDCLRAH, LDCLRALH, LDCLRLH
  [<TestMethod>]
  member _.``C6.2.118 LDCLRLH``() =
    testDisasm "78621020" "ldclrlh w2, w0, [x1]"
    testDisasm "7862103f" "stclrlh w2, [x1]"
    testDisasm "787f13ff" "stclrlh wzr, [sp]"
    testDisasm "786a13e9" "ldclrlh w10, w9, [sp]"

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLR``() =
    testDisasm "f8221020" "ldclr x2, x0, [x1]"
    testDisasm "f822103f" "stclr x2, [x1]"
    testDisasm "b8221020" "ldclr w2, w0, [x1]"
    testDisasm "b822103f" "stclr w2, [x1]"

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLRA``() =
    testDisasm "b8a21020" "ldclra w2, w0, [x1]"
    testDisasm "b8bf13ff" "ldclra wzr, wzr, [sp]"
    testDisasm "b8aa13e9" "ldclra w10, w9, [sp]"
    testDisasm "b8bf13c0" "ldclra wzr, w0, [x30]"

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLRAL``() =
    testDisasm "b8e21020" "ldclral w2, w0, [x1]"
    testDisasm "b8ff13ff" "ldclral wzr, wzr, [sp]"
    testDisasm "b8ea13e9" "ldclral w10, w9, [sp]"
    testDisasm "b8ff13c0" "ldclral wzr, w0, [x30]"

  /// C6.2.119 LDCLR, LDCLRA, LDCLRAL, LDCLRL
  [<TestMethod>]
  member _.``C6.2.119 LDCLRL``() =
    testDisasm "b8621020" "ldclrl w2, w0, [x1]"
    testDisasm "b862103f" "stclrl w2, [x1]"
    testDisasm "b87f13ff" "stclrl wzr, [sp]"
    testDisasm "b86a13e9" "ldclrl w10, w9, [sp]"

  /// C6.2.12 AND (immediate)
  [<TestMethod>]
  member _.``C6.2.12 AND``() =
    testDisasm "9200f020" "and x0, x1, #0x5555555555555555"
    testDisasm "121c0020" "and w0, w1, #0x10"
    testDisasm "0a020020" "and w0, w1, w2"
    testDisasm "8a020020" "and x0, x1, x2"

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORAB``() =
    testDisasm "38a22020" "ldeorab w2, w0, [x1]"
    testDisasm "38bf23ff" "ldeorab wzr, wzr, [sp]"
    testDisasm "38aa23e9" "ldeorab w10, w9, [sp]"
    testDisasm "38bf23c0" "ldeorab wzr, w0, [x30]"

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORALB``() =
    testDisasm "38e22020" "ldeoralb w2, w0, [x1]"
    testDisasm "38ff23ff" "ldeoralb wzr, wzr, [sp]"
    testDisasm "38ea23e9" "ldeoralb w10, w9, [sp]"
    testDisasm "38ff23c0" "ldeoralb wzr, w0, [x30]"

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORB``() =
    testDisasm "38222020" "ldeorb w2, w0, [x1]"
    testDisasm "3822203f" "steorb w2, [x1]"
    testDisasm "383f23ff" "steorb wzr, [sp]"
    testDisasm "382a23e9" "ldeorb w10, w9, [sp]"

  /// C6.2.120 LDEORB, LDEORAB, LDEORALB, LDEORLB
  [<TestMethod>]
  member _.``C6.2.120 LDEORLB``() =
    testDisasm "38622020" "ldeorlb w2, w0, [x1]"
    testDisasm "3862203f" "steorlb w2, [x1]"
    testDisasm "387f23ff" "steorlb wzr, [sp]"
    testDisasm "386a23e9" "ldeorlb w10, w9, [sp]"

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORAH``() =
    testDisasm "78a22020" "ldeorah w2, w0, [x1]"
    testDisasm "78bf23ff" "ldeorah wzr, wzr, [sp]"
    testDisasm "78aa23e9" "ldeorah w10, w9, [sp]"
    testDisasm "78bf23c0" "ldeorah wzr, w0, [x30]"

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORALH``() =
    testDisasm "78e22020" "ldeoralh w2, w0, [x1]"
    testDisasm "78ff23ff" "ldeoralh wzr, wzr, [sp]"
    testDisasm "78ea23e9" "ldeoralh w10, w9, [sp]"
    testDisasm "78ff23c0" "ldeoralh wzr, w0, [x30]"

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORH``() =
    testDisasm "78222020" "ldeorh w2, w0, [x1]"
    testDisasm "7822203f" "steorh w2, [x1]"
    testDisasm "783f23ff" "steorh wzr, [sp]"
    testDisasm "782a23e9" "ldeorh w10, w9, [sp]"

  /// C6.2.121 LDEORH, LDEORAH, LDEORALH, LDEORLH
  [<TestMethod>]
  member _.``C6.2.121 LDEORLH``() =
    testDisasm "78622020" "ldeorlh w2, w0, [x1]"
    testDisasm "7862203f" "steorlh w2, [x1]"
    testDisasm "787f23ff" "steorlh wzr, [sp]"
    testDisasm "786a23e9" "ldeorlh w10, w9, [sp]"

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEOR``() =
    testDisasm "f8222020" "ldeor x2, x0, [x1]"
    testDisasm "f822203f" "steor x2, [x1]"
    testDisasm "b8222020" "ldeor w2, w0, [x1]"
    testDisasm "b822203f" "steor w2, [x1]"

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEORA``() =
    testDisasm "b8a22020" "ldeora w2, w0, [x1]"
    testDisasm "b8bf23ff" "ldeora wzr, wzr, [sp]"
    testDisasm "b8aa23e9" "ldeora w10, w9, [sp]"
    testDisasm "b8bf23c0" "ldeora wzr, w0, [x30]"

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEORAL``() =
    testDisasm "b8e22020" "ldeoral w2, w0, [x1]"
    testDisasm "b8ff23ff" "ldeoral wzr, wzr, [sp]"
    testDisasm "b8ea23e9" "ldeoral w10, w9, [sp]"
    testDisasm "b8ff23c0" "ldeoral wzr, w0, [x30]"

  /// C6.2.122 LDEOR, LDEORA, LDEORAL, LDEORL
  [<TestMethod>]
  member _.``C6.2.122 LDEORL``() =
    testDisasm "b8622020" "ldeorl w2, w0, [x1]"
    testDisasm "b862203f" "steorl w2, [x1]"
    testDisasm "b87f23ff" "steorl wzr, [sp]"
    testDisasm "b86a23e9" "ldeorl w10, w9, [sp]"

  /// C6.2.123 LDG
  [<TestMethod>]
  member _.``C6.2.123 LDG``() =
    testDisasm "d9600020" "ldg x0, [x1]"
    testDisasm "d9601020" "ldg x0, [x1, #0x10]"
    testDisasm "d97f03ff" "ldg xzr, [sp, #0xffffffffffffff00]"
    testDisasm "d96a03e9" "ldg x9, [sp, #0xa00]"

  /// C6.2.124 LDGM
  [<TestMethod>]
  member _.``C6.2.124 LDGM``() =
    testDisasm "d9e00020" "ldgm x0, [x1]"

  /// C6.2.125 LDLARB
  [<TestMethod>]
  member _.``C6.2.125 LDLARB``() =
    testDisasm "08df7c20" "ldlarb w0, [x1]"
    testDisasm "08df03ff" "ldlarb wzr, [sp]"
    testDisasm "08ca03e9" "ldlarb w9, [sp]"
    testDisasm "08c1005f" "ldlarb wzr, [x2]"

  /// C6.2.126 LDLARH
  [<TestMethod>]
  member _.``C6.2.126 LDLARH``() =
    testDisasm "48df7c20" "ldlarh w0, [x1]"
    testDisasm "48df03ff" "ldlarh wzr, [sp]"
    testDisasm "48ca03e9" "ldlarh w9, [sp]"
    testDisasm "48c1005f" "ldlarh wzr, [x2]"

  /// C6.2.127 LDLAR
  [<TestMethod>]
  member _.``C6.2.127 LDLAR``() =
    testDisasm "c8df7c20" "ldlar x0, [x1]"
    testDisasm "88df7c20" "ldlar w0, [x1]"
    testDisasm "88df03ff" "ldlar wzr, [sp]"
    testDisasm "88ca03e9" "ldlar w9, [sp]"

  /// C6.2.128 LDNP
  [<TestMethod>]
  member _.``C6.2.128 LDNP``() =
    testDisasm "28400c22" "ldnp w2, w3, [x1]"
    testDisasm "28420c22" "ldnp w2, w3, [x1, #0x10]"
    testDisasm "a8400c22" "ldnp x2, x3, [x1]"
    testDisasm "a8410c22" "ldnp x2, x3, [x1, #0x10]"

  /// C6.2.129 LDP
  [<TestMethod>]
  member _.``C6.2.129 LDP``() =
    testDisasm "28c20c22" "ldp w2, w3, [x1], #0x10"
    testDisasm "a8c10c22" "ldp x2, x3, [x1], #0x10"
    testDisasm "29c20c22" "ldp w2, w3, [x1, #0x10]!"
    testDisasm "a9c10c22" "ldp x2, x3, [x1, #0x10]!"

  /// C6.2.130 LDPSW
  [<TestMethod>]
  member _.``C6.2.130 LDPSW``() =
    testDisasm "68c20c22" "ldpsw x2, x3, [x1], #0x10"
    testDisasm "69c20c22" "ldpsw x2, x3, [x1, #0x10]!"
    testDisasm "69400c22" "ldpsw x2, x3, [x1]"
    testDisasm "69420c22" "ldpsw x2, x3, [x1, #0x10]"

  /// C6.2.131 LDR (immediate)
  [<TestMethod>]
  member _.``C6.2.131 LDR``() =
    testDisasm "b8410420" "ldr w0, [x1], #0x10"
    testDisasm "f8410420" "ldr x0, [x1], #0x10"
    testDisasm "b8410c20" "ldr w0, [x1, #0x10]!"
    testDisasm "f8410c20" "ldr x0, [x1, #0x10]!"

  /// C6.2.134 LDRAA, LDRAB
  [<TestMethod>]
  member _.``C6.2.134 LDRAA``() =
    testDisasm "f8200420" "ldraa x0, [x1]"
    testDisasm "f8202420" "ldraa x0, [x1, #0x10]"
    testDisasm "f8200c20" "ldraa x0, [x1]!"
    testDisasm "f8202c20" "ldraa x0, [x1, #0x10]!"

  /// C6.2.134 LDRAA, LDRAB
  [<TestMethod>]
  member _.``C6.2.134 LDRAB``() =
    testDisasm "f8a00420" "ldrab x0, [x1]"
    testDisasm "f8a10443" "ldrab x3, [x2, #0x80]"
    testDisasm "f8bf07ff" "ldrab xzr, [sp, #0xf80]"
    testDisasm "f8aa07e9" "ldrab x9, [sp, #0x500]"

  /// C6.2.135 LDRB (immediate)
  [<TestMethod>]
  member _.``C6.2.135 LDRB``() =
    testDisasm "38410420" "ldrb w0, [x1], #0x10"
    testDisasm "38410c20" "ldrb w0, [x1, #0x10]!"
    testDisasm "39400020" "ldrb w0, [x1]"
    testDisasm "39402020" "ldrb w0, [x1, #0x8]"

  /// C6.2.137 LDRH (immediate)
  [<TestMethod>]
  member _.``C6.2.137 LDRH``() =
    testDisasm "78410420" "ldrh w0, [x1], #0x10"
    testDisasm "78410c20" "ldrh w0, [x1, #0x10]!"
    testDisasm "79400020" "ldrh w0, [x1]"
    testDisasm "79401020" "ldrh w0, [x1, #0x8]"

  /// C6.2.139 LDRSB (immediate)
  [<TestMethod>]
  member _.``C6.2.139 LDRSB``() =
    testDisasm "38c10420" "ldrsb w0, [x1], #0x10"
    testDisasm "38810420" "ldrsb x0, [x1], #0x10"
    testDisasm "38c10c20" "ldrsb w0, [x1, #0x10]!"
    testDisasm "38810c20" "ldrsb x0, [x1, #0x10]!"

  /// C6.2.14 ANDS (immediate)
  [<TestMethod>]
  member _.``C6.2.14 ANDS``() =
    testDisasm "f2089c20" "ands x0, x1, #0xff00ff00ff00ff00"
    testDisasm "f240783f" "tst x1, #0x7fffffff"
    testDisasm "721c0020" "ands w0, w1, #0x10"
    testDisasm "6a020020" "ands w0, w1, w2"

  /// C6.2.141 LDRSH (immediate)
  [<TestMethod>]
  member _.``C6.2.141 LDRSH``() =
    testDisasm "78c10420" "ldrsh w0, [x1], #0x10"
    testDisasm "78810420" "ldrsh x0, [x1], #0x10"
    testDisasm "78c10c20" "ldrsh w0, [x1, #0x10]!"
    testDisasm "78810c20" "ldrsh x0, [x1, #0x10]!"

  /// C6.2.143 LDRSW (immediate)
  [<TestMethod>]
  member _.``C6.2.143 LDRSW``() =
    testDisasm "b8810420" "ldrsw x0, [x1], #0x10"
    testDisasm "b8810c20" "ldrsw x0, [x1, #0x10]!"
    testDisasm "b9800020" "ldrsw x0, [x1]"
    testDisasm "b9800820" "ldrsw x0, [x1, #0x8]"

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETAB``() =
    testDisasm "38a23020" "ldsetab w2, w0, [x1]"
    testDisasm "38bf33ff" "ldsetab wzr, wzr, [sp]"
    testDisasm "38aa33e9" "ldsetab w10, w9, [sp]"
    testDisasm "38bf33c0" "ldsetab wzr, w0, [x30]"

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETALB``() =
    testDisasm "38e23020" "ldsetalb w2, w0, [x1]"
    testDisasm "38ff33ff" "ldsetalb wzr, wzr, [sp]"
    testDisasm "38ea33e9" "ldsetalb w10, w9, [sp]"
    testDisasm "38ff33c0" "ldsetalb wzr, w0, [x30]"

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETB``() =
    testDisasm "38223020" "ldsetb w2, w0, [x1]"
    testDisasm "3822303f" "stsetb w2, [x1]"
    testDisasm "383f33ff" "stsetb wzr, [sp]"
    testDisasm "382a33e9" "ldsetb w10, w9, [sp]"

  /// C6.2.146 LDSETB, LDSETAB, LDSETALB, LDSETLB
  [<TestMethod>]
  member _.``C6.2.146 LDSETLB``() =
    testDisasm "38623020" "ldsetlb w2, w0, [x1]"
    testDisasm "3862303f" "stsetlb w2, [x1]"
    testDisasm "387f33ff" "stsetlb wzr, [sp]"
    testDisasm "386a33e9" "ldsetlb w10, w9, [sp]"

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETAH``() =
    testDisasm "78a23020" "ldsetah w2, w0, [x1]"
    testDisasm "78bf33ff" "ldsetah wzr, wzr, [sp]"
    testDisasm "78aa33e9" "ldsetah w10, w9, [sp]"
    testDisasm "78bf33c0" "ldsetah wzr, w0, [x30]"

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETALH``() =
    testDisasm "78e23020" "ldsetalh w2, w0, [x1]"
    testDisasm "78ff33ff" "ldsetalh wzr, wzr, [sp]"
    testDisasm "78ea33e9" "ldsetalh w10, w9, [sp]"
    testDisasm "78ff33c0" "ldsetalh wzr, w0, [x30]"

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETH``() =
    testDisasm "78223020" "ldseth w2, w0, [x1]"
    testDisasm "7822303f" "stseth w2, [x1]"
    testDisasm "783f33ff" "stseth wzr, [sp]"
    testDisasm "782a33e9" "ldseth w10, w9, [sp]"

  /// C6.2.147 LDSETH, LDSETAH, LDSETALH, LDSETLH
  [<TestMethod>]
  member _.``C6.2.147 LDSETLH``() =
    testDisasm "78623020" "ldsetlh w2, w0, [x1]"
    testDisasm "7862303f" "stsetlh w2, [x1]"
    testDisasm "787f33ff" "stsetlh wzr, [sp]"
    testDisasm "786a33e9" "ldsetlh w10, w9, [sp]"

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSET``() =
    testDisasm "f8223020" "ldset x2, x0, [x1]"
    testDisasm "f822303f" "stset x2, [x1]"
    testDisasm "b8223020" "ldset w2, w0, [x1]"
    testDisasm "b822303f" "stset w2, [x1]"

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSETA``() =
    testDisasm "b8a23020" "ldseta w2, w0, [x1]"
    testDisasm "b8bf33ff" "ldseta wzr, wzr, [sp]"
    testDisasm "b8aa33e9" "ldseta w10, w9, [sp]"
    testDisasm "b8bf33c0" "ldseta wzr, w0, [x30]"

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSETAL``() =
    testDisasm "b8e23020" "ldsetal w2, w0, [x1]"
    testDisasm "b8ff33ff" "ldsetal wzr, wzr, [sp]"
    testDisasm "b8ea33e9" "ldsetal w10, w9, [sp]"
    testDisasm "b8ff33c0" "ldsetal wzr, w0, [x30]"

  /// C6.2.148 LDSET, LDSETA, LDSETAL, LDSETL
  [<TestMethod>]
  member _.``C6.2.148 LDSETL``() =
    testDisasm "b8623020" "ldsetl w2, w0, [x1]"
    testDisasm "b862303f" "stsetl w2, [x1]"
    testDisasm "b87f33ff" "stsetl wzr, [sp]"
    testDisasm "b86a33e9" "ldsetl w10, w9, [sp]"

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXAB``() =
    testDisasm "38a24020" "ldsmaxab w2, w0, [x1]"
    testDisasm "38bf43ff" "ldsmaxab wzr, wzr, [sp]"
    testDisasm "38aa43e9" "ldsmaxab w10, w9, [sp]"
    testDisasm "38bf43c0" "ldsmaxab wzr, w0, [x30]"

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXALB``() =
    testDisasm "38e24020" "ldsmaxalb w2, w0, [x1]"
    testDisasm "38ff43ff" "ldsmaxalb wzr, wzr, [sp]"
    testDisasm "38ea43e9" "ldsmaxalb w10, w9, [sp]"
    testDisasm "38ff43c0" "ldsmaxalb wzr, w0, [x30]"

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXB``() =
    testDisasm "38224020" "ldsmaxb w2, w0, [x1]"
    testDisasm "3822403f" "stsmaxb w2, [x1]"
    testDisasm "383f43ff" "stsmaxb wzr, [sp]"
    testDisasm "382a43e9" "ldsmaxb w10, w9, [sp]"

  /// C6.2.149 LDSMAXB, LDSMAXAB, LDSMAXALB, LDSMAXLB
  [<TestMethod>]
  member _.``C6.2.149 LDSMAXLB``() =
    testDisasm "38624020" "ldsmaxlb w2, w0, [x1]"
    testDisasm "3862403f" "stsmaxlb w2, [x1]"
    testDisasm "387f43ff" "stsmaxlb wzr, [sp]"
    testDisasm "386a43e9" "ldsmaxlb w10, w9, [sp]"

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXAH``() =
    testDisasm "78a24020" "ldsmaxah w2, w0, [x1]"
    testDisasm "78bf43ff" "ldsmaxah wzr, wzr, [sp]"
    testDisasm "78aa43e9" "ldsmaxah w10, w9, [sp]"
    testDisasm "78bf43c0" "ldsmaxah wzr, w0, [x30]"

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXALH``() =
    testDisasm "78e24020" "ldsmaxalh w2, w0, [x1]"
    testDisasm "78ff43ff" "ldsmaxalh wzr, wzr, [sp]"
    testDisasm "78ea43e9" "ldsmaxalh w10, w9, [sp]"
    testDisasm "78ff43c0" "ldsmaxalh wzr, w0, [x30]"

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXH``() =
    testDisasm "78224020" "ldsmaxh w2, w0, [x1]"
    testDisasm "7822403f" "stsmaxh w2, [x1]"
    testDisasm "783f43ff" "stsmaxh wzr, [sp]"
    testDisasm "782a43e9" "ldsmaxh w10, w9, [sp]"

  /// C6.2.150 LDSMAXH, LDSMAXAH, LDSMAXALH, LDSMAXLH
  [<TestMethod>]
  member _.``C6.2.150 LDSMAXLH``() =
    testDisasm "78624020" "ldsmaxlh w2, w0, [x1]"
    testDisasm "7862403f" "stsmaxlh w2, [x1]"
    testDisasm "787f43ff" "stsmaxlh wzr, [sp]"
    testDisasm "786a43e9" "ldsmaxlh w10, w9, [sp]"

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAX``() =
    testDisasm "f8224020" "ldsmax x2, x0, [x1]"
    testDisasm "f822403f" "stsmax x2, [x1]"
    testDisasm "b8224020" "ldsmax w2, w0, [x1]"
    testDisasm "b822403f" "stsmax w2, [x1]"

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAXA``() =
    testDisasm "b8a24020" "ldsmaxa w2, w0, [x1]"
    testDisasm "b8bf43ff" "ldsmaxa wzr, wzr, [sp]"
    testDisasm "b8aa43e9" "ldsmaxa w10, w9, [sp]"
    testDisasm "b8bf43c0" "ldsmaxa wzr, w0, [x30]"

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAXAL``() =
    testDisasm "b8e24020" "ldsmaxal w2, w0, [x1]"
    testDisasm "b8ff43ff" "ldsmaxal wzr, wzr, [sp]"
    testDisasm "b8ea43e9" "ldsmaxal w10, w9, [sp]"
    testDisasm "b8ff43c0" "ldsmaxal wzr, w0, [x30]"

  /// C6.2.151 LDSMAX, LDSMAXA, LDSMAXAL, LDSMAXL
  [<TestMethod>]
  member _.``C6.2.151 LDSMAXL``() =
    testDisasm "b8624020" "ldsmaxl w2, w0, [x1]"
    testDisasm "b862403f" "stsmaxl w2, [x1]"
    testDisasm "b87f43ff" "stsmaxl wzr, [sp]"
    testDisasm "b86a43e9" "ldsmaxl w10, w9, [sp]"

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINAB``() =
    testDisasm "38a25020" "ldsminab w2, w0, [x1]"
    testDisasm "38bf53ff" "ldsminab wzr, wzr, [sp]"
    testDisasm "38aa53e9" "ldsminab w10, w9, [sp]"
    testDisasm "38bf53c0" "ldsminab wzr, w0, [x30]"

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINALB``() =
    testDisasm "38e25020" "ldsminalb w2, w0, [x1]"
    testDisasm "38ff53ff" "ldsminalb wzr, wzr, [sp]"
    testDisasm "38ea53e9" "ldsminalb w10, w9, [sp]"
    testDisasm "38ff53c0" "ldsminalb wzr, w0, [x30]"

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINB``() =
    testDisasm "38225020" "ldsminb w2, w0, [x1]"
    testDisasm "3822503f" "stsminb w2, [x1]"
    testDisasm "383f53ff" "stsminb wzr, [sp]"
    testDisasm "382a53e9" "ldsminb w10, w9, [sp]"

  /// C6.2.152 LDSMINB, LDSMINAB, LDSMINALB, LDSMINLB
  [<TestMethod>]
  member _.``C6.2.152 LDSMINLB``() =
    testDisasm "38625020" "ldsminlb w2, w0, [x1]"
    testDisasm "3862503f" "stsminlb w2, [x1]"
    testDisasm "387f53ff" "stsminlb wzr, [sp]"
    testDisasm "386a53e9" "ldsminlb w10, w9, [sp]"

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINAH``() =
    testDisasm "78a25020" "ldsminah w2, w0, [x1]"
    testDisasm "78bf53ff" "ldsminah wzr, wzr, [sp]"
    testDisasm "78aa53e9" "ldsminah w10, w9, [sp]"
    testDisasm "78bf53c0" "ldsminah wzr, w0, [x30]"

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINALH``() =
    testDisasm "78e25020" "ldsminalh w2, w0, [x1]"
    testDisasm "78ff53ff" "ldsminalh wzr, wzr, [sp]"
    testDisasm "78ea53e9" "ldsminalh w10, w9, [sp]"
    testDisasm "78ff53c0" "ldsminalh wzr, w0, [x30]"

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINH``() =
    testDisasm "78225020" "ldsminh w2, w0, [x1]"
    testDisasm "7822503f" "stsminh w2, [x1]"
    testDisasm "783f53ff" "stsminh wzr, [sp]"
    testDisasm "782a53e9" "ldsminh w10, w9, [sp]"

  /// C6.2.153 LDSMINH, LDSMINAH, LDSMINALH, LDSMINLH
  [<TestMethod>]
  member _.``C6.2.153 LDSMINLH``() =
    testDisasm "78625020" "ldsminlh w2, w0, [x1]"
    testDisasm "7862503f" "stsminlh w2, [x1]"
    testDisasm "787f53ff" "stsminlh wzr, [sp]"
    testDisasm "786a53e9" "ldsminlh w10, w9, [sp]"

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMIN``() =
    testDisasm "f8225020" "ldsmin x2, x0, [x1]"
    testDisasm "f822503f" "stsmin x2, [x1]"
    testDisasm "b8225020" "ldsmin w2, w0, [x1]"
    testDisasm "b822503f" "stsmin w2, [x1]"

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMINA``() =
    testDisasm "b8a25020" "ldsmina w2, w0, [x1]"
    testDisasm "b8bf53ff" "ldsmina wzr, wzr, [sp]"
    testDisasm "b8aa53e9" "ldsmina w10, w9, [sp]"
    testDisasm "b8bf53c0" "ldsmina wzr, w0, [x30]"

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMINAL``() =
    testDisasm "b8e25020" "ldsminal w2, w0, [x1]"
    testDisasm "b8ff53ff" "ldsminal wzr, wzr, [sp]"
    testDisasm "b8ea53e9" "ldsminal w10, w9, [sp]"
    testDisasm "b8ff53c0" "ldsminal wzr, w0, [x30]"

  /// C6.2.154 LDSMIN, LDSMINA, LDSMINAL, LDSMINL
  [<TestMethod>]
  member _.``C6.2.154 LDSMINL``() =
    testDisasm "b8625020" "ldsminl w2, w0, [x1]"
    testDisasm "b862503f" "stsminl w2, [x1]"
    testDisasm "b87f53ff" "stsminl wzr, [sp]"
    testDisasm "b86a53e9" "ldsminl w10, w9, [sp]"

  /// C6.2.155 LDTR
  [<TestMethod>]
  member _.``C6.2.155 LDTR``() =
    testDisasm "b8410820" "ldtr w0, [x1, #0x10]"
    testDisasm "f8400820" "ldtr x0, [x1]"
    testDisasm "f8410820" "ldtr x0, [x1, #0x10]"
    testDisasm "b8400820" "ldtr w0, [x1]"

  /// C6.2.156 LDTRB
  [<TestMethod>]
  member _.``C6.2.156 LDTRB``() =
    testDisasm "38410820" "ldtrb w0, [x1, #0x10]"
    testDisasm "38400820" "ldtrb w0, [x1]"
    testDisasm "385f0bff" "ldtrb wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "384a0be9" "ldtrb w9, [sp, #0xa0]"

  /// C6.2.157 LDTRH
  [<TestMethod>]
  member _.``C6.2.157 LDTRH``() =
    testDisasm "78410820" "ldtrh w0, [x1, #0x10]"
    testDisasm "78400820" "ldtrh w0, [x1]"
    testDisasm "785f0bff" "ldtrh wzr, [sp, #0xfffffffffffffff0]"
    testDisasm "784a0be9" "ldtrh w9, [sp, #0xa0]"

  /// C6.2.158 LDTRSB
  [<TestMethod>]
  member _.``C6.2.158 LDTRSB``() =
    testDisasm "38c10820" "ldtrsb w0, [x1, #0x10]"
    testDisasm "38800820" "ldtrsb x0, [x1]"
    testDisasm "38810820" "ldtrsb x0, [x1, #0x10]"
    testDisasm "38c00820" "ldtrsb w0, [x1]"

  /// C6.2.159 LDTRSH
  [<TestMethod>]
  member _.``C6.2.159 LDTRSH``() =
    testDisasm "78c10820" "ldtrsh w0, [x1, #0x10]"
    testDisasm "78800820" "ldtrsh x0, [x1]"
    testDisasm "78810820" "ldtrsh x0, [x1, #0x10]"
    testDisasm "78c00820" "ldtrsh w0, [x1]"

  /// C6.2.16 ASR (register)
  [<TestMethod>]
  member _.``C6.2.16 ASR``() =
    testDisasm "1ac22820" "asr w0, w1, w2"
    testDisasm "13017c20" "asr w0, w1, #0x1"
    testDisasm "9341fc20" "asr x0, x1, #0x1"
    testDisasm "9ac22820" "asr x0, x1, x2"

  /// C6.2.160 LDTRSW
  [<TestMethod>]
  member _.``C6.2.160 LDTRSW``() =
    testDisasm "b8810820" "ldtrsw x0, [x1, #0x10]"
    testDisasm "b8800820" "ldtrsw x0, [x1]"
    testDisasm "b89f0bff" "ldtrsw xzr, [sp, #0xfffffffffffffff0]"
    testDisasm "b88a0be9" "ldtrsw x9, [sp, #0xa0]"

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXAB``() =
    testDisasm "38a26020" "ldumaxab w2, w0, [x1]"
    testDisasm "38bf63ff" "ldumaxab wzr, wzr, [sp]"
    testDisasm "38aa63e9" "ldumaxab w10, w9, [sp]"
    testDisasm "38bf63c0" "ldumaxab wzr, w0, [x30]"

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXALB``() =
    testDisasm "38e26020" "ldumaxalb w2, w0, [x1]"
    testDisasm "38ff63ff" "ldumaxalb wzr, wzr, [sp]"
    testDisasm "38ea63e9" "ldumaxalb w10, w9, [sp]"
    testDisasm "38ff63c0" "ldumaxalb wzr, w0, [x30]"

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXB``() =
    testDisasm "38226020" "ldumaxb w2, w0, [x1]"
    testDisasm "3822603f" "stumaxb w2, [x1]"
    testDisasm "383f63ff" "stumaxb wzr, [sp]"
    testDisasm "382a63e9" "ldumaxb w10, w9, [sp]"

  /// C6.2.161 LDUMAXB, LDUMAXAB, LDUMAXALB, LDUMAXLB
  [<TestMethod>]
  member _.``C6.2.161 LDUMAXLB``() =
    testDisasm "38626020" "ldumaxlb w2, w0, [x1]"
    testDisasm "3862603f" "stumaxlb w2, [x1]"
    testDisasm "387f63ff" "stumaxlb wzr, [sp]"
    testDisasm "386a63e9" "ldumaxlb w10, w9, [sp]"

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXAH``() =
    testDisasm "78a26020" "ldumaxah w2, w0, [x1]"
    testDisasm "78bf63ff" "ldumaxah wzr, wzr, [sp]"
    testDisasm "78aa63e9" "ldumaxah w10, w9, [sp]"
    testDisasm "78bf63c0" "ldumaxah wzr, w0, [x30]"

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXALH``() =
    testDisasm "78e26020" "ldumaxalh w2, w0, [x1]"
    testDisasm "78ff63ff" "ldumaxalh wzr, wzr, [sp]"
    testDisasm "78ea63e9" "ldumaxalh w10, w9, [sp]"
    testDisasm "78ff63c0" "ldumaxalh wzr, w0, [x30]"

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXH``() =
    testDisasm "78226020" "ldumaxh w2, w0, [x1]"
    testDisasm "7822603f" "stumaxh w2, [x1]"
    testDisasm "783f63ff" "stumaxh wzr, [sp]"
    testDisasm "782a63e9" "ldumaxh w10, w9, [sp]"

  /// C6.2.162 LDUMAXH, LDUMAXAH, LDUMAXALH, LDUMAXLH
  [<TestMethod>]
  member _.``C6.2.162 LDUMAXLH``() =
    testDisasm "78626020" "ldumaxlh w2, w0, [x1]"
    testDisasm "7862603f" "stumaxlh w2, [x1]"
    testDisasm "787f63ff" "stumaxlh wzr, [sp]"
    testDisasm "786a63e9" "ldumaxlh w10, w9, [sp]"

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAX``() =
    testDisasm "f8226020" "ldumax x2, x0, [x1]"
    testDisasm "f822603f" "stumax x2, [x1]"
    testDisasm "b8226020" "ldumax w2, w0, [x1]"
    testDisasm "b822603f" "stumax w2, [x1]"

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAXA``() =
    testDisasm "b8a26020" "ldumaxa w2, w0, [x1]"
    testDisasm "b8bf63ff" "ldumaxa wzr, wzr, [sp]"
    testDisasm "b8aa63e9" "ldumaxa w10, w9, [sp]"
    testDisasm "b8bf63c0" "ldumaxa wzr, w0, [x30]"

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAXAL``() =
    testDisasm "b8e26020" "ldumaxal w2, w0, [x1]"
    testDisasm "b8ff63ff" "ldumaxal wzr, wzr, [sp]"
    testDisasm "b8ea63e9" "ldumaxal w10, w9, [sp]"
    testDisasm "b8ff63c0" "ldumaxal wzr, w0, [x30]"

  /// C6.2.163 LDUMAX, LDUMAXA, LDUMAXAL, LDUMAXL
  [<TestMethod>]
  member _.``C6.2.163 LDUMAXL``() =
    testDisasm "b8626020" "ldumaxl w2, w0, [x1]"
    testDisasm "b862603f" "stumaxl w2, [x1]"
    testDisasm "b87f63ff" "stumaxl wzr, [sp]"
    testDisasm "b86a63e9" "ldumaxl w10, w9, [sp]"
