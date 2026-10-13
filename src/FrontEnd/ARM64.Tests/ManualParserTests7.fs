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
/// One test for each instruction DDI0487F.c describes, USHLL to FJCVTZS in
/// the order of its sections. Each reads words of the instruction and checks
/// the text, and each word's text is one binutils' objdump reads the word as
/// too, so what is asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualParserTests7() =
  let parser =
    Parser(BinReader.Init Endian.Big) :> IInstructionParsable

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// C7.2.391 USHLL, USHLL2
  [<TestMethod>]
  member _.``C7.2.391 USHLL``() =
    testDisasm "2f11a420" "ushll v0.4s, v1.4h, #0x1"
    testDisasm "2f09a420" "ushll v0.8h, v1.8b, #0x1"
    testDisasm "2f21a420" "ushll v0.2d, v1.2s, #0x1"

  /// C7.2.391 USHLL, USHLL2
  [<TestMethod>]
  member _.``C7.2.391 USHLL2``() =
    testDisasm "6f09a420" "ushll2 v0.8h, v1.16b, #0x1"
    testDisasm "6f11a420" "ushll2 v0.4s, v1.8h, #0x1"
    testDisasm "6f21a420" "ushll2 v0.2d, v1.4s, #0x1"

  /// C7.2.392 USHR
  [<TestMethod>]
  member _.``C7.2.392 USHR``() =
    testDisasm "2f0f0420" "ushr v0.8b, v1.8b, #0x1"
    testDisasm "2f1f0420" "ushr v0.4h, v1.4h, #0x1"
    testDisasm "2f3f0420" "ushr v0.2s, v1.2s, #0x1"
    testDisasm "6f7f0420" "ushr v0.2d, v1.2d, #0x1"

  /// C7.2.393 USMMLA (vector)
  [<TestMethod>]
  member _.``C7.2.393 USMMLA``() =
    testDisasm "4e82ac20" "usmmla v0.4s, v1.16b, v2.16b"

  /// C7.2.394 USQADD
  [<TestMethod>]
  member _.``C7.2.394 USQADD``() =
    testDisasm "2e203820" "usqadd v0.8b, v1.8b"
    testDisasm "2e603820" "usqadd v0.4h, v1.4h"
    testDisasm "2ea03820" "usqadd v0.2s, v1.2s"
    testDisasm "6ee03820" "usqadd v0.2d, v1.2d"

  /// C7.2.395 USRA
  [<TestMethod>]
  member _.``C7.2.395 USRA``() =
    testDisasm "2f0f1420" "usra v0.8b, v1.8b, #0x1"
    testDisasm "2f1f1420" "usra v0.4h, v1.4h, #0x1"
    testDisasm "2f3f1420" "usra v0.2s, v1.2s, #0x1"
    testDisasm "6f7f1420" "usra v0.2d, v1.2d, #0x1"

  /// C7.2.396 USUBL, USUBL2
  [<TestMethod>]
  member _.``C7.2.396 USUBL``() =
    testDisasm "2e622020" "usubl v0.4s, v1.4h, v2.4h"
    testDisasm "2e222020" "usubl v0.8h, v1.8b, v2.8b"
    testDisasm "2ea22020" "usubl v0.2d, v1.2s, v2.2s"

  /// C7.2.396 USUBL, USUBL2
  [<TestMethod>]
  member _.``C7.2.396 USUBL2``() =
    testDisasm "6e222020" "usubl2 v0.8h, v1.16b, v2.16b"
    testDisasm "6ea22020" "usubl2 v0.2d, v1.4s, v2.4s"
    testDisasm "6e622020" "usubl2 v0.4s, v1.8h, v2.8h"

  /// C7.2.397 USUBW, USUBW2
  [<TestMethod>]
  member _.``C7.2.397 USUBW``() =
    testDisasm "2e623020" "usubw v0.4s, v1.4s, v2.4h"
    testDisasm "2e223020" "usubw v0.8h, v1.8h, v2.8b"
    testDisasm "2ea23020" "usubw v0.2d, v1.2d, v2.2s"

  /// C7.2.397 USUBW, USUBW2
  [<TestMethod>]
  member _.``C7.2.397 USUBW2``() =
    testDisasm "6e223020" "usubw2 v0.8h, v1.8h, v2.16b"
    testDisasm "6ea23020" "usubw2 v0.2d, v1.2d, v2.4s"
    testDisasm "6e623020" "usubw2 v0.4s, v1.4s, v2.8h"

  /// C7.2.398 UXTL, UXTL2
  [<TestMethod>]
  member _.``C7.2.398 UXTL``() =
    testDisasm "2f10a420" "ushll v0.4s, v1.4h, #0x0"
    testDisasm "2f08a420" "ushll v0.8h, v1.8b, #0x0"
    testDisasm "2f20a420" "ushll v0.2d, v1.2s, #0x0"

  /// C7.2.398 UXTL, UXTL2
  [<TestMethod>]
  member _.``C7.2.398 UXTL2``() =
    testDisasm "6f08a420" "ushll2 v0.8h, v1.16b, #0x0"
    testDisasm "6f20a420" "ushll2 v0.2d, v1.4s, #0x0"
    testDisasm "6f10a420" "ushll2 v0.4s, v1.8h, #0x0"

  /// C7.2.399 UZP1
  [<TestMethod>]
  member _.``C7.2.399 UZP1``() =
    testDisasm "0e021820" "uzp1 v0.8b, v1.8b, v2.8b"
    testDisasm "0e421820" "uzp1 v0.4h, v1.4h, v2.4h"
    testDisasm "0e821820" "uzp1 v0.2s, v1.2s, v2.2s"
    testDisasm "4ec21820" "uzp1 v0.2d, v1.2d, v2.2d"

  /// C7.2.4 ADDP (scalar)
  [<TestMethod>]
  member _.``C7.2.4 ADDP``() =
    testDisasm "0e22bc20" "addp v0.8b, v1.8b, v2.8b"
    testDisasm "0e62bc20" "addp v0.4h, v1.4h, v2.4h"
    testDisasm "0ea2bc20" "addp v0.2s, v1.2s, v2.2s"
    testDisasm "4ee2bc20" "addp v0.2d, v1.2d, v2.2d"

  /// C7.2.400 UZP2
  [<TestMethod>]
  member _.``C7.2.400 UZP2``() =
    testDisasm "0e025820" "uzp2 v0.8b, v1.8b, v2.8b"
    testDisasm "0e425820" "uzp2 v0.4h, v1.4h, v2.4h"
    testDisasm "0e825820" "uzp2 v0.2s, v1.2s, v2.2s"
    testDisasm "4ec25820" "uzp2 v0.2d, v1.2d, v2.2d"

  /// C7.2.401 XAR
  [<TestMethod>]
  member _.``C7.2.401 XAR``() =
    testDisasm "ce820c20" "xar v0.2d, v1.2d, v2.2d, #0x3"

  /// C7.2.402 XTN, XTN2
  [<TestMethod>]
  member _.``C7.2.402 XTN``() =
    testDisasm "0e612820" "xtn v0.4h, v1.4s"
    testDisasm "0e212820" "xtn v0.8b, v1.8h"
    testDisasm "0ea12820" "xtn v0.2s, v1.2d"

  /// C7.2.402 XTN, XTN2
  [<TestMethod>]
  member _.``C7.2.402 XTN2``() =
    testDisasm "4e212820" "xtn2 v0.16b, v1.8h"
    testDisasm "4ea12820" "xtn2 v0.4s, v1.2d"
    testDisasm "4e612820" "xtn2 v0.8h, v1.4s"

  /// C7.2.403 ZIP1
  [<TestMethod>]
  member _.``C7.2.403 ZIP1``() =
    testDisasm "0e023820" "zip1 v0.8b, v1.8b, v2.8b"
    testDisasm "0e423820" "zip1 v0.4h, v1.4h, v2.4h"
    testDisasm "0e823820" "zip1 v0.2s, v1.2s, v2.2s"
    testDisasm "4ec23820" "zip1 v0.2d, v1.2d, v2.2d"

  /// C7.2.404 ZIP2
  [<TestMethod>]
  member _.``C7.2.404 ZIP2``() =
    testDisasm "0e027820" "zip2 v0.8b, v1.8b, v2.8b"
    testDisasm "0e427820" "zip2 v0.4h, v1.4h, v2.4h"
    testDisasm "0e827820" "zip2 v0.2s, v1.2s, v2.2s"
    testDisasm "4ec27820" "zip2 v0.2d, v1.2d, v2.2d"

  /// C7.2.42 EOR3
  [<TestMethod>]
  member _.``C7.2.42 EOR3``() =
    testDisasm "ce020c20" "eor3 v0.16b, v1.16b, v2.16b, v3.16b"

  /// C7.2.43 EXT
  [<TestMethod>]
  member _.``C7.2.43 EXT``() =
    testDisasm "6e020820" "ext v0.16b, v1.16b, v2.16b, #0x1"

  /// C7.2.44 FABD
  [<TestMethod>]
  member _.``C7.2.44 FABD``() =
    testDisasm "7ec21420" "fabd h0, h1, h2"
    testDisasm "2ec21420" "fabd v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2d420" "fabd v0.2s, v1.2s, v2.2s"
    testDisasm "6ee2d420" "fabd v0.2d, v1.2d, v2.2d"

  /// C7.2.45 FABS (vector)
  [<TestMethod>]
  member _.``C7.2.45 FABS``() =
    testDisasm "0ef8f820" "fabs v0.4h, v1.4h"
    testDisasm "0ea0f820" "fabs v0.2s, v1.2s"
    testDisasm "4ee0f820" "fabs v0.2d, v1.2d"
    testDisasm "1ee0c020" "fabs h0, h1"

  /// C7.2.47 FACGE
  [<TestMethod>]
  member _.``C7.2.47 FACGE``() =
    testDisasm "7e422c20" "facge h0, h1, h2"
    testDisasm "2e422c20" "facge v0.4h, v1.4h, v2.4h"
    testDisasm "2e22ec20" "facge v0.2s, v1.2s, v2.2s"
    testDisasm "6e62ec20" "facge v0.2d, v1.2d, v2.2d"

  /// C7.2.48 FACGT
  [<TestMethod>]
  member _.``C7.2.48 FACGT``() =
    testDisasm "7ec22c20" "facgt h0, h1, h2"
    testDisasm "2ec22c20" "facgt v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2ec20" "facgt v0.2s, v1.2s, v2.2s"
    testDisasm "6ee2ec20" "facgt v0.2d, v1.2d, v2.2d"

  /// C7.2.49 FADD (vector)
  [<TestMethod>]
  member _.``C7.2.49 FADD``() =
    testDisasm "0e421420" "fadd v0.4h, v1.4h, v2.4h"
    testDisasm "0e22d420" "fadd v0.2s, v1.2s, v2.2s"
    testDisasm "4e62d420" "fadd v0.2d, v1.2d, v2.2d"
    testDisasm "1ee22820" "fadd h0, h1, h2"

  /// C7.2.51 FADDP (scalar)
  [<TestMethod>]
  member _.``C7.2.51 FADDP``() =
    testDisasm "2e421420" "faddp v0.4h, v1.4h, v2.4h"
    testDisasm "2e22d420" "faddp v0.2s, v1.2s, v2.2s"
    testDisasm "6e62d420" "faddp v0.2d, v1.2d, v2.2d"
    testDisasm "5e30d843" "faddp h3, v2.2h"

  /// C7.2.53 FCADD
  [<TestMethod>]
  member _.``C7.2.53 FCADD``() =
    testDisasm "6e82e420" "fcadd v0.4s, v1.4s, v2.4s, #0x5a"
    testDisasm "2e41e443" "fcadd v3.4h, v2.4h, v1.4h, #0x5a"
    testDisasm "6ec1e443" "fcadd v3.2d, v2.2d, v1.2d, #0x5a"

  /// C7.2.54 FCCMP
  [<TestMethod>]
  member _.``C7.2.54 FCCMP``() =
    testDisasm "1ee20429" "fccmp h1, h2, #0x9, eq"
    testDisasm "1e220429" "fccmp s1, s2, #0x9, eq"
    testDisasm "1e620429" "fccmp d1, d2, #0x9, eq"
    testDisasm "1e211443" "fccmp s2, s1, #0x3, ne"

  /// C7.2.55 FCCMPE
  [<TestMethod>]
  member _.``C7.2.55 FCCMPE``() =
    testDisasm "1ee20439" "fccmpe h1, h2, #0x9, eq"
    testDisasm "1e220439" "fccmpe s1, s2, #0x9, eq"
    testDisasm "1e620439" "fccmpe d1, d2, #0x9, eq"
    testDisasm "1e3416b6" "fccmpe s21, s20, #0x6, ne"

  /// C7.2.56 FCMEQ (register)
  [<TestMethod>]
  member _.``C7.2.56 FCMEQ``() =
    testDisasm "5e422420" "fcmeq h0, h1, h2"
    testDisasm "0e422420" "fcmeq v0.4h, v1.4h, v2.4h"
    testDisasm "0e22e420" "fcmeq v0.2s, v1.2s, v2.2s"
    testDisasm "4e62e420" "fcmeq v0.2d, v1.2d, v2.2d"

  /// C7.2.58 FCMGE (register)
  [<TestMethod>]
  member _.``C7.2.58 FCMGE``() =
    testDisasm "7e422420" "fcmge h0, h1, h2"
    testDisasm "2e422420" "fcmge v0.4h, v1.4h, v2.4h"
    testDisasm "2e22e420" "fcmge v0.2s, v1.2s, v2.2s"
    testDisasm "6e62e420" "fcmge v0.2d, v1.2d, v2.2d"

  /// C7.2.6 ADDV
  [<TestMethod>]
  member _.``C7.2.6 ADDV``() =
    testDisasm "4eb1b820" "addv s0, v1.4s"
    testDisasm "0e31b843" "addv b3, v2.8b"
    testDisasm "0e71b843" "addv h3, v2.4h"

  /// C7.2.60 FCMGT (register)
  [<TestMethod>]
  member _.``C7.2.60 FCMGT``() =
    testDisasm "7ec22420" "fcmgt h0, h1, h2"
    testDisasm "2ec22420" "fcmgt v0.4h, v1.4h, v2.4h"
    testDisasm "2ea2e420" "fcmgt v0.2s, v1.2s, v2.2s"
    testDisasm "6ee2e420" "fcmgt v0.2d, v1.2d, v2.2d"

  /// C7.2.62 FCMLA (by element)
  [<TestMethod>]
  member _.``C7.2.62 FCMLA``() =
    testDisasm "6e82cc20" "fcmla v0.4s, v1.4s, v2.4s, #0x5a"
    testDisasm "2e41c443" "fcmla v3.4h, v2.4h, v1.4h, #0x0"
    testDisasm "2f411043" "fcmla v3.4h, v2.4h, v1.h[0], #0x0"
    testDisasm "6ec1c443" "fcmla v3.2d, v2.2d, v1.2d, #0x0"

  /// C7.2.64 FCMLE (zero)
  [<TestMethod>]
  member _.``C7.2.64 FCMLE``() =
    testDisasm "7ef8d820" "fcmle h0, h1, #0.00000000"
    testDisasm "2ef8d820" "fcmle v0.4h, v1.4h, #0.00000000"
    testDisasm "2ea0d820" "fcmle v0.2s, v1.2s, #0.00000000"
    testDisasm "6ee0d820" "fcmle v0.2d, v1.2d, #0.00000000"

  /// C7.2.65 FCMLT (zero)
  [<TestMethod>]
  member _.``C7.2.65 FCMLT``() =
    testDisasm "5ef8e820" "fcmlt h0, h1, #0.00000000"
    testDisasm "0ef8e820" "fcmlt v0.4h, v1.4h, #0.00000000"
    testDisasm "0ea0e820" "fcmlt v0.2s, v1.2s, #0.00000000"
    testDisasm "4ee0e820" "fcmlt v0.2d, v1.2d, #0.00000000"

  /// C7.2.66 FCMP
  [<TestMethod>]
  member _.``C7.2.66 FCMP``() =
    testDisasm "1ee22020" "fcmp h1, h2"
    testDisasm "1ee02028" "fcmp h1, #0.00000000"
    testDisasm "1e222020" "fcmp s1, s2"
    testDisasm "1e202028" "fcmp s1, #0.00000000"

  /// C7.2.67 FCMPE
  [<TestMethod>]
  member _.``C7.2.67 FCMPE``() =
    testDisasm "1ee22030" "fcmpe h1, h2"
    testDisasm "1ee02038" "fcmpe h1, #0.00000000"
    testDisasm "1e222030" "fcmpe s1, s2"
    testDisasm "1e202038" "fcmpe s1, #0.00000000"

  /// C7.2.68 FCSEL
  [<TestMethod>]
  member _.``C7.2.68 FCSEL``() =
    testDisasm "1ee20c20" "fcsel h0, h1, h2, eq"
    testDisasm "1e220c20" "fcsel s0, s1, s2, eq"
    testDisasm "1e620c20" "fcsel d0, d1, d2, eq"
    testDisasm "1e211c43" "fcsel s3, s2, s1, ne"

  /// C7.2.69 FCVT
  [<TestMethod>]
  member _.``C7.2.69 FCVT``() =
    testDisasm "1e22c020" "fcvt d0, s1"
    testDisasm "1ee24020" "fcvt s0, h1"
    testDisasm "1e23c020" "fcvt h0, s1"
    testDisasm "1e63c020" "fcvt h0, d1"

  /// C7.2.7 AESD
  [<TestMethod>]
  member _.``C7.2.7 AESD``() =
    testDisasm "4e285820" "aesd v0.16b, v1.16b"

  /// C7.2.70 FCVTAS (vector)
  [<TestMethod>]
  member _.``C7.2.70 FCVTAS``() =
    testDisasm "9e640020" "fcvtas x0, d1"
    testDisasm "5e79c820" "fcvtas h0, h1"
    testDisasm "0e79c820" "fcvtas v0.4h, v1.4h"
    testDisasm "0e21c820" "fcvtas v0.2s, v1.2s"

  /// C7.2.72 FCVTAU (vector)
  [<TestMethod>]
  member _.``C7.2.72 FCVTAU``() =
    testDisasm "9e650020" "fcvtau x0, d1"
    testDisasm "7e79c820" "fcvtau h0, h1"
    testDisasm "2e79c820" "fcvtau v0.4h, v1.4h"
    testDisasm "2e21c820" "fcvtau v0.2s, v1.2s"

  /// C7.2.74 FCVTL, FCVTL2
  [<TestMethod>]
  member _.``C7.2.74 FCVTL``() =
    testDisasm "0e217820" "fcvtl v0.4s, v1.4h"
    testDisasm "0e617820" "fcvtl v0.2d, v1.2s"

  /// C7.2.74 FCVTL, FCVTL2
  [<TestMethod>]
  member _.``C7.2.74 FCVTL2``() =
    testDisasm "4e617820" "fcvtl2 v0.2d, v1.4s"
    testDisasm "4e217820" "fcvtl2 v0.4s, v1.8h"

  /// C7.2.75 FCVTMS (vector)
  [<TestMethod>]
  member _.``C7.2.75 FCVTMS``() =
    testDisasm "9e700020" "fcvtms x0, d1"
    testDisasm "5e79b820" "fcvtms h0, h1"
    testDisasm "0e79b820" "fcvtms v0.4h, v1.4h"
    testDisasm "0e21b820" "fcvtms v0.2s, v1.2s"

  /// C7.2.77 FCVTMU (vector)
  [<TestMethod>]
  member _.``C7.2.77 FCVTMU``() =
    testDisasm "9e710020" "fcvtmu x0, d1"
    testDisasm "7e79b820" "fcvtmu h0, h1"
    testDisasm "2e79b820" "fcvtmu v0.4h, v1.4h"
    testDisasm "2e21b820" "fcvtmu v0.2s, v1.2s"

  /// C7.2.79 FCVTN, FCVTN2
  [<TestMethod>]
  member _.``C7.2.79 FCVTN``() =
    testDisasm "0e216820" "fcvtn v0.4h, v1.4s"
    testDisasm "0e616820" "fcvtn v0.2s, v1.2d"

  /// C7.2.79 FCVTN, FCVTN2
  [<TestMethod>]
  member _.``C7.2.79 FCVTN2``() =
    testDisasm "4e616820" "fcvtn2 v0.4s, v1.2d"
    testDisasm "4e216820" "fcvtn2 v0.8h, v1.4s"

  /// C7.2.8 AESE
  [<TestMethod>]
  member _.``C7.2.8 AESE``() =
    testDisasm "4e284820" "aese v0.16b, v1.16b"

  /// C7.2.80 FCVTNS (vector)
  [<TestMethod>]
  member _.``C7.2.80 FCVTNS``() =
    testDisasm "9e600020" "fcvtns x0, d1"
    testDisasm "5e79a820" "fcvtns h0, h1"
    testDisasm "0e79a820" "fcvtns v0.4h, v1.4h"
    testDisasm "0e21a820" "fcvtns v0.2s, v1.2s"

  /// C7.2.82 FCVTNU (vector)
  [<TestMethod>]
  member _.``C7.2.82 FCVTNU``() =
    testDisasm "9e610020" "fcvtnu x0, d1"
    testDisasm "7e79a820" "fcvtnu h0, h1"
    testDisasm "2e79a820" "fcvtnu v0.4h, v1.4h"
    testDisasm "2e21a820" "fcvtnu v0.2s, v1.2s"

  /// C7.2.84 FCVTPS (vector)
  [<TestMethod>]
  member _.``C7.2.84 FCVTPS``() =
    testDisasm "9e680020" "fcvtps x0, d1"
    testDisasm "5ef9a820" "fcvtps h0, h1"
    testDisasm "0ef9a820" "fcvtps v0.4h, v1.4h"
    testDisasm "0ea1a820" "fcvtps v0.2s, v1.2s"

  /// C7.2.86 FCVTPU (vector)
  [<TestMethod>]
  member _.``C7.2.86 FCVTPU``() =
    testDisasm "9e690020" "fcvtpu x0, d1"
    testDisasm "7ef9a820" "fcvtpu h0, h1"
    testDisasm "2ef9a820" "fcvtpu v0.4h, v1.4h"
    testDisasm "2ea1a820" "fcvtpu v0.2s, v1.2s"

  /// C7.2.88 FCVTXN, FCVTXN2
  [<TestMethod>]
  member _.``C7.2.88 FCVTXN``() =
    testDisasm "2e616820" "fcvtxn v0.2s, v1.2d"
    testDisasm "7e616843" "fcvtxn s3, d2"

  /// C7.2.88 FCVTXN, FCVTXN2
  [<TestMethod>]
  member _.``C7.2.88 FCVTXN2``() =
    testDisasm "6e616820" "fcvtxn2 v0.4s, v1.2d"

  /// C7.2.89 FCVTZS (vector, fixed-point)
  [<TestMethod>]
  member _.``C7.2.89 FCVTZS``() =
    testDisasm "9e780020" "fcvtzs x0, d1"
    testDisasm "0f1bfc20" "fcvtzs v0.4h, v1.4h, #5"
    testDisasm "0f3bfc20" "fcvtzs v0.2s, v1.2s, #5"
    testDisasm "4f7bfc20" "fcvtzs v0.2d, v1.2d, #5"

  /// C7.2.9 AESIMC
  [<TestMethod>]
  member _.``C7.2.9 AESIMC``() =
    testDisasm "4e287820" "aesimc v0.16b, v1.16b"

  /// C7.2.93 FCVTZU (vector, fixed-point)
  [<TestMethod>]
  member _.``C7.2.93 FCVTZU``() =
    testDisasm "9e790020" "fcvtzu x0, d1"
    testDisasm "2f1bfc20" "fcvtzu v0.4h, v1.4h, #5"
    testDisasm "2f3bfc20" "fcvtzu v0.2s, v1.2s, #5"
    testDisasm "6f7bfc20" "fcvtzu v0.2d, v1.2d, #5"

  /// C7.2.97 FDIV (vector)
  [<TestMethod>]
  member _.``C7.2.97 FDIV``() =
    testDisasm "2e423c20" "fdiv v0.4h, v1.4h, v2.4h"
    testDisasm "2e22fc20" "fdiv v0.2s, v1.2s, v2.2s"
    testDisasm "6e62fc20" "fdiv v0.2d, v1.2d, v2.2d"
    testDisasm "1ee21820" "fdiv h0, h1, h2"

  /// C7.2.99 FJCVTZS
  [<TestMethod>]
  member _.``C7.2.99 FJCVTZS``() =
    testDisasm "1e7e0020" "fjcvtzs w0, d1"
    testDisasm "1e7e03ff" "fjcvtzs wzr, d31"
