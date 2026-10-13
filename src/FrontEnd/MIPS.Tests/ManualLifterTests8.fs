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

namespace B2R2.FrontEnd.MIPS.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.MIPS.Tests.ManualLift

/// <summary>
/// One test for each instruction of microMIPS64 5.04: NOR to XORI.
///
/// <para>A value test runs a word of the instruction under QEMU over a few
/// sets of register values, memory and FCSR, and has the lift change what
/// QEMU changed, raise what QEMU raised, and nothing else; every value it
/// expects is QEMU's (optest-mips/oracle). A structural test says in its own
/// comment what it checks and why no value test could be had.</para>
/// </summary>
[<TestClass>]
type ManualLifterTests8() =
  let um =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSISAMode.MicroMIPS)

  /// <summary>
  /// 014942d0, nor a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 NOR``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "014942d0" ]
    |> is [ G 8, 0xfffffffffffffff8UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "014942d0" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "014942d0" ]
    |> is [ G 8, 0x1030107UL ]

  /// <summary>
  /// 4413, nor v0, v1, r0, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 NOT16``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "4413" ]
    |> is [ G 2, 0xfffffffffffffffcUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "4413" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "4413" ]
    |> is [ G 2, 0xffffffffedcba987UL ]

  /// <summary>
  /// 01494290, or a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 OR``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494290" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494290" ]
    |> is [ G 8, 0xffffffffffffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494290" ]
    |> is [ G 8, 0xfffffffffefcfef8UL ]

  /// <summary>
  /// 0c22, or at, v0, r0, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 OR16``() =
    [ G 1, 0x7UL; G 2, 0x3UL ]
    |> run um [ "0c22" ]
    |> is [ G 1, 0x3UL ]
    [ G 1, 0x7fffffffUL; G 2, 0x1UL ]
    |> run um [ "0c22" ]
    |> is [ G 1, 0x1UL ]
    [ G 1, 0xffffffff89abcdefUL; G 2, 0x12345678UL ]
    |> run um [ "0c22" ]
    |> is [ G 1, 0x12345678UL ]

  /// <summary>
  /// 51090001, ori a4, a5, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ORI``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "51090001" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "51090001" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "51090001" ]
    |> is [ G 8, 0x12345679UL ]

  /// <summary>
  /// 00002800, pause, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PAUSE``() =
    []
    |> run um [ "00002800" ]
    |> is []
    []
    |> run um [ "00002800" ]
    |> is []
    []
    |> run um [ "00002800" ]
    |> is []

  /// <summary>
  /// 54c41080, pll.ps f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after pll.ps $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PLL.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run um [ "54c41080" ]
    |> is [ F 2, 0xbfc000003e800000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run um [ "54c41080" ]
    |> is [ F 2, 0x3f00000040000000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run um [ "54c41080" ]
    |> is [ F 2, 0x40400000c0800000UL ]

  /// <summary>
  /// 54c410c0, plu.ps f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after plu.ps $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PLU.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run um [ "54c410c0" ]
    |> is [ F 2, 0xbfc000003fc00000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run um [ "54c410c0" ]
    |> is [ F 2, 0x3f0000003f400000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run um [ "54c410c0" ]
    |> is [ F 2, 0x404000003e000000UL ]

  /// <summary>
  /// 60082001, pref 0x0, 1(a4), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PREF``() =
    let given0 =
      [ G 8, 0x2020007fUL
        M 0x20200078UL, 0x9fed8e50b2f1835dUL
        M 0x20200080UL, 0xf0a76f33e498cc21UL
        M 0x20200088UL, 0x984ccef41d17b580UL ]
    given0
    |> run um [ "60082001" ]
    |> is []
    let given1 =
      [ G 8, 0x2020007fUL
        M 0x20200078UL, 0xe371fa9ac2020709UL
        M 0x20200080UL, 0x69ecf5ffbd96706UL
        M 0x20200088UL, 0x888154859447e667UL ]
    given1
    |> run um [ "60082001" ]
    |> is []
    let given2 =
      [ G 8, 0x2020007fUL
        M 0x20200078UL, 0xc794c753775fbeaUL
        M 0x20200080UL, 0xc52f693ade503722UL
        M 0x20200088UL, 0xaccbb1a6ca17904aUL ]
    given2
    |> run um [ "60082001" ]
    |> is []

  /// <summary>
  /// 6008a401, prefe 0x0, 1(a4), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PREFE``() =
    let given0 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xf78ce82f5db8687UL
        M 0x20200080UL, 0xe692b88f392ce73fUL
        M 0x20200088UL, 0xfaa08d5427d67955UL ]
    given0
    |> run um [ "6008a401" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe0a6f4739cd188b8UL
        M 0x20200080UL, 0xa924079b4040c2fcUL
        M 0x20200088UL, 0x70fcb5fe6a85a1a5UL ]
    given1
    |> run um [ "6008a401" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x62c7cacc139206aUL
        M 0x20200080UL, 0xd9553313d86fe1aaUL
        M 0x20200088UL, 0x4c6dff58e38e4623UL ]
    given2
    |> run um [ "6008a401" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 552801a0, prefx 0x0, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after prefx 0x0,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PREFX``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        M 0x20200078UL, 0x21584be820f6ecbUL
        M 0x20200080UL, 0x93784e20b75c9e9bUL
        M 0x20200088UL, 0x759a4988c22b0806UL ]
    given0
    |> run um [ "552801a0" ]
    |> is []
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        M 0x20200078UL, 0xeb3d978a3fa76585UL
        M 0x20200080UL, 0xac1ac71f11641845UL
        M 0x20200088UL, 0x557782645804314UL ]
    given1
    |> run um [ "552801a0" ]
    |> is []
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        M 0x20200078UL, 0xc072434cc1d5e60fUL
        M 0x20200080UL, 0xae453f3b1f6376dbUL
        M 0x20200088UL, 0xf0c53c79b7d67ed1UL ]
    given2
    |> run um [ "552801a0" ]
    |> is []

  /// <summary>
  /// 54c41100, pul.ps f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after pul.ps $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PUL.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run um [ "54c41100" ]
    |> is [ F 2, 0x401000003e800000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run um [ "54c41100" ]
    |> is [ F 2, 0xc0c0000040000000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run um [ "54c41100" ]
    |> is [ F 2, 0x447a0000c0800000UL ]

  /// <summary>
  /// 54c41140, puu.ps f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after puu.ps $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 PUU.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run um [ "54c41140" ]
    |> is [ F 2, 0x401000003fc00000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run um [ "54c41140" ]
    |> is [ F 2, 0xc0c000003f400000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run um [ "54c41140" ]
    |> is [ F 2, 0x447a00003e000000UL ]

  /// <summary>
  /// 01026b3c, rdhwr a4, v0, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 RDHWR``() =
    [ G 8, 0x7UL ]
    |> run um [ "01026b3c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL ]
    |> run um [ "01026b3c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "01026b3c" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 0109e17c, rdpgpr a4, a5, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 RDPGPR``() =
    [ G 8, 0x7UL; G 9, 0x3UL; Status, 0x10UL ]
    |> run um [ "0109e17c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; Status, 0x10UL ]
    |> run um [ "0109e17c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; Status, 0x10UL ]
    |> run um [ "0109e17c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5444123b, recip.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after recip.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 RECIP.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x3f000000UL ]
    |> run um [ "5444123b" ]
    |> is [ F 2, 0x40000000UL ]
    [ F 2, 0x40600000UL; F 4, 0x40800000UL ]
    |> run um [ "5444123b" ]
    |> is [ F 2, 0x3e800000UL ]
    [ F 2, 0x3e800000UL; F 4, 0xbe000000UL ]
    |> run um [ "5444123b" ]
    |> is [ F 2, 0xc1000000UL ]

  /// <summary>
  /// 010908c0, rotr a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ROTR``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "010908c0" ]
    |> is [ G 8, 0xffffffff80000001UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "010908c0" ]
    |> is [ G 8, 0xffffffff80000000UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "010908c0" ]
    |> is [ G 8, 0x91a2b3cUL ]

  /// <summary>
  /// 012a40d0, rotrv a4, a5, a6, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ROTRV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "012a40d0" ]
    |> is [ G 8, 0x18000000UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "012a40d0" ]
    |> is [ G 8, 0x4UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "012a40d0" ]
    |> is [ G 8, 0x34567812UL ]

  /// <summary>
  /// 5444333b, round.l.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after round.l.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ROUND.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "5444333b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "5444333b" ]
    |> is [ F 2, 0xfffffffffffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "5444333b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 54443b3b, round.w.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after round.w.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ROUND.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "54443b3b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "54443b3b" ]
    |> is [ F 2, 0xfffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "54443b3b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 5444023b, rsqrt.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after rsqrt.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 RSQRT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x3e800000UL ]
    |> run um [ "5444023b" ]
    |> is [ F 2, 0x40000000UL ]
    [ F 2, 0x40600000UL; F 4, 0x40800000UL ]
    |> run um [ "5444023b" ]
    |> is [ F 2, 0x3f000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x41800000UL ]
    |> run um [ "5444023b" ]
    |> is []

  /// <summary>
  /// 18230001, sb at, 1(v1), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SB``() =
    let given0 =
      [ G 1, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xe31db1d4e40b049eUL
        M 0x20200080UL, 0xb1a83b67c125b555UL
        M 0x20200088UL, 0x672bfe2d0d07db0eUL ]
    given0
    |> run um [ "18230001" ]
    |> is [ M 0x20200080UL, 0x7a83b67c125b555UL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xa87d1a4ec1523488UL
        M 0x20200080UL, 0x96d6e962ebba02a3UL
        M 0x20200088UL, 0x2f4e519b5a27501fUL ]
    given1
    |> run um [ "18230001" ]
    |> is [ M 0x20200080UL, 0xffd6e962ebba02a3UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xe26611c8b114bbf6UL
        M 0x20200080UL, 0x2eced3e00e02b8b5UL
        M 0x20200088UL, 0x97d0480411238bcfUL ]
    given2
    |> run um [ "18230001" ]
    |> is [ M 0x20200080UL, 0xefced3e00e02b8b5UL ]

  /// <summary>
  /// 8901, sb v0, 1(s0), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SB16``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xce1b44f659e6e22bUL
        M 0x20200080UL, 0x3b1f35e170e10455UL
        M 0x20200088UL, 0x739aa57987156e64UL ]
    given0
    |> run um [ "8901" ]
    |> is [ M 0x20200080UL, 0x71f35e170e10455UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xdc7aebf372e796e2UL
        M 0x20200080UL, 0x6ab013ad56c2ad2UL
        M 0x20200088UL, 0xf5e923751f7e20a9UL ]
    given1
    |> run um [ "8901" ]
    |> is [ M 0x20200080UL, 0xffab013ad56c2ad2UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xfb32c091ed8b765fUL
        M 0x20200080UL, 0x24218f0b5c289f58UL
        M 0x20200088UL, 0x1f23dd0995aadb42UL ]
    given2
    |> run um [ "8901" ]
    |> is [ M 0x20200080UL, 0xef218f0b5c289f58UL ]

  /// <summary>
  /// 6109a801, sbe a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SBE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x74847bdfc1cdb628UL
        M 0x20200080UL, 0xe49d32b695d6075fUL
        M 0x20200088UL, 0xd3119bf0aa3d5e25UL ]
    given0
    |> run um [ "6109a801" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xffd38808c1161ee2UL
        M 0x20200080UL, 0x11d4c7ede95cb260UL
        M 0x20200088UL, 0xc4eecd804f30e52fUL ]
    given1
    |> run um [ "6109a801" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe26c9039ce26a8f2UL
        M 0x20200080UL, 0xb6ffaf0e28ad787fUL
        M 0x20200088UL, 0x105199724cab5f37UL ]
    given2
    |> run um [ "6109a801" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 6109b001, sc a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SC``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x68b83787debd2aacUL
        M 0x20200080UL, 0xae822a8f6a01a4acUL
        M 0x20200088UL, 0x611bddf15396ed57UL ]
    given0
    |> run um [ "6109b001" ]
    |> is [ G 8, 0x0UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x5fe09534b7680408UL
        M 0x20200080UL, 0x7421c50cf6d85c47UL
        M 0x20200088UL, 0x411ea44ed4b6b6b1UL ]
    given1
    |> run um [ "6109b001" ]
    |> is [ G 8, 0x0UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x458565c2f77a1932UL
        M 0x20200080UL, 0x655b4192beeee699UL
        M 0x20200088UL, 0x70f9260787e5af71UL ]
    given2
    |> run um [ "6109b001" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 6109f001, scd a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after scd $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SCD``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x27b652d99b98a8eeUL
        M 0x20200080UL, 0xb887d13a98693448UL
        M 0x20200088UL, 0x703a3d2947fd8a32UL ]
    given0
    |> run um [ "6109f001" ]
    |> is [ G 8, 0x0UL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xd76271ee86652eeaUL
        M 0x20200080UL, 0xefe2c7e63c75978cUL
        M 0x20200088UL, 0x62c2a69fa043e08dUL ]
    given1
    |> run um [ "6109f001" ]
    |> is [ G 8, 0x0UL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x26d6908dda78b157UL
        M 0x20200080UL, 0xbce4898c25c2715aUL
        M 0x20200088UL, 0xdec40a623d984967UL ]
    given2
    |> run um [ "6109f001" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 6109ac01, sce a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SCE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x1b8e13144ae1b932UL
        M 0x20200080UL, 0xc7485781dcedce05UL
        M 0x20200088UL, 0xcabe829bf7b62941UL ]
    given0
    |> run um [ "6109ac01" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xf5f413e672ca1d82UL
        M 0x20200080UL, 0xc15accc201175352UL
        M 0x20200088UL, 0x2baa60f0fa597a67UL ]
    given1
    |> run um [ "6109ac01" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xb6639f1fe68bea8eUL
        M 0x20200080UL, 0xa2c468e839b6f57bUL
        M 0x20200088UL, 0x31fa8fa884fe70f3UL ]
    given2
    |> run um [ "6109ac01" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// d9090001, sd a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sd $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SD``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x4e88b33a97e8ac71UL
        M 0x20200080UL, 0xb16a0832e5ef7a41UL
        M 0x20200088UL, 0x10dbb254524fda49UL ]
    given0
    |> run um [ "d9090001" ]
    |> is [ M 0x20200080UL, 0x7UL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xe141e02389ee68a3UL
        M 0x20200080UL, 0x9aa9e6abbb26a14fUL
        M 0x20200088UL, 0x63a2efeb31fbc924UL ]
    given1
    |> run um [ "d9090001" ]
    |> is [ M 0x20200080UL, 0x7fffffffffffffffUL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x74ea0307d91821ebUL
        M 0x20200080UL, 0xa16347d80ae1ff6UL
        M 0x20200088UL, 0xff2b1eb709ada1f2UL ]
    given2
    |> run um [ "d9090001" ]
    |> is [ M 0x20200080UL, 0x123456789abcdefUL ]

  /// <summary>
  /// 0020db7c, sdbbp 0x20. Not run against QEMU, whose user mode aborts on the
  /// debug exception it raises; the manual enters the debug handler, which is
  /// this architecture's breakpoint. The lift raises Breakpoint and changes
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDBBP``() =
    []
    |> run um [ "0020db7c" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// 46c1, sdbbp 0x1. Not run against QEMU, whose user mode aborts on the debug
  /// exception it raises; the manual enters the debug handler, which is this
  /// architecture's breakpoint. The lift raises Breakpoint and changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDBBP16``() =
    []
    |> run um [ "46c1" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// b8480001, sdc1 f2, 1(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sdc1 $f2,1($8), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDC1``() =
    let given0 =
      [ G 8, 0x2020007fUL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0x82ae9c6b57c82933UL
        M 0x20200080UL, 0x738615bc7ded6734UL
        M 0x20200088UL, 0xab66a974706a23abUL ]
    given0
    |> run um [ "b8480001" ]
    |> is [ M 0x20200080UL, 0xbff0000000000000UL ]
    let given1 =
      [ G 8, 0x2020007fUL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x720f7174e65e3073UL
        M 0x20200080UL, 0x8a83874d7014d546UL
        M 0x20200088UL, 0x7e3c28dd11263f0fUL ]
    given1
    |> run um [ "b8480001" ]
    |> is [ M 0x20200080UL, 0x400c000000000000UL ]
    let given2 =
      [ G 8, 0x2020007fUL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x68c610b911b90593UL
        M 0x20200080UL, 0xb3876b8f096f535eUL
        M 0x20200088UL, 0xd602eecb8e3d8468UL ]
    given2
    |> run um [ "b8480001" ]
    |> is [ M 0x20200080UL, 0x3fd0000000000000UL ]

  /// <summary>
  /// 2000a001, sdc2 0x0, 1(r0), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDC2``() =
    let given0 =
      [ M 0x20200078UL, 0x7f86485290f86669UL
        M 0x20200080UL, 0x6a7cb195f101e6edUL
        M 0x20200088UL, 0xc005b9fc1ab1b0efUL ]
    given0
    |> run um [ "2000a001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0x7465107aba6ec549UL
        M 0x20200080UL, 0x19aee2c33db97349UL
        M 0x20200088UL, 0xe55538a5cbee30eUL ]
    given1
    |> run um [ "2000a001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0x45a40bf488020461UL
        M 0x20200080UL, 0x1452c856bf1ee373UL
        M 0x20200088UL, 0x7110f90acabb77bUL ]
    given2
    |> run um [ "2000a001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 6109c001, sdl a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sdl $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDL``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x14fcc730fdcf2a72UL
        M 0x20200080UL, 0xb9bae0860de913cbUL
        M 0x20200088UL, 0x436958e4cf3f3024UL ]
    given0
    |> run um [ "6109c001" ]
    |> is [ M 0x20200080UL, 0xb900000000000000UL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0x347901df8924043fUL
        M 0x20200080UL, 0xcb3fd3f7f6926becUL
        M 0x20200088UL, 0x58eb2d41bd7de591UL ]
    given1
    |> run um [ "6109c001" ]
    |> is [ M 0x20200080UL, 0xcb3f7fffffffffffUL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0x5a3af71a36bcf7b9UL
        M 0x20200080UL, 0xf597e03c5ed1b60UL
        M 0x20200088UL, 0xdbb318a42992e253UL ]
    given2
    |> run um [ "6109c001" ]
    |> is [ M 0x20200080UL, 0xf597e03c5012345UL ]

  /// <summary>
  /// 2044f008, sdm s0, s1, 8(a0), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sd $16,8($4); sd $17,16($4), the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDM``() =
    let given0 =
      [ G 4, 0x20200078UL
        G 16, 0x7UL
        G 17, 0x3UL
        M 0x20200078UL, 0x307a19c56e2a40e7UL
        M 0x20200080UL, 0xef5d15e3659412bdUL
        M 0x20200088UL, 0x7a9cd9d48178e6c2UL ]
    given0
    |> run um [ "2044f008" ]
    |> is [ M 0x20200080UL, 0x7UL; M 0x20200088UL, 0x3UL ]
    let given1 =
      [ G 4, 0x20200078UL
        G 16, 0x7fffffffffffffffUL
        G 17, 0x1UL
        M 0x20200078UL, 0x81801b3baf7f9883UL
        M 0x20200080UL, 0x9d1fb22de1c85101UL
        M 0x20200088UL, 0x8e4f7ea92071ffe5UL ]
    given1
    |> run um [ "2044f008" ]
    |> is [ M 0x20200080UL, 0x7fffffffffffffffUL; M 0x20200088UL, 0x1UL ]
    let given2 =
      [ G 4, 0x20200078UL
        G 16, 0x123456789abcdefUL
        G 17, 0xfedcba9876543210UL
        M 0x20200078UL, 0x54075b81783759baUL
        M 0x20200080UL, 0xcb65a6e03b8068d5UL
        M 0x20200088UL, 0x76578aa7cda601b7UL ]
    let expected2 =
      [ M 0x20200080UL, 0x123456789abcdefUL
        M 0x20200088UL, 0xfedcba9876543210UL ]
    given2
    |> run um [ "2044f008" ]
    |> is expected2

  /// <summary>
  /// 2044c008, sdp v0, v1, 8(a0), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sd $2,8($4); sd $3,16($4), the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDP``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x3UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0x7e818b33ffc8db89UL
        M 0x20200080UL, 0x7303a9b4f7ec9763UL
        M 0x20200088UL, 0x26e7f23097ab44d6UL ]
    given0
    |> run um [ "2044c008" ]
    |> is [ M 0x20200080UL, 0x7UL; M 0x20200088UL, 0x3UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x1UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0x3fdc2339f3200736UL
        M 0x20200080UL, 0x1e2198731864d20fUL
        M 0x20200088UL, 0x952925cfc4779a35UL ]
    given1
    |> run um [ "2044c008" ]
    |> is [ M 0x20200080UL, 0x7fffffffffffffffUL; M 0x20200088UL, 0x1UL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0xfedcba9876543210UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0xb44bf9a119045f01UL
        M 0x20200080UL, 0x878902645b8b6baeUL
        M 0x20200088UL, 0xc5e750aefe8703e6UL ]
    let expected2 =
      [ M 0x20200080UL, 0x123456789abcdefUL
        M 0x20200088UL, 0xfedcba9876543210UL ]
    given2
    |> run um [ "2044c008" ]
    |> is expected2

  /// <summary>
  /// 6109d001, sdr a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sdr $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDR``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x7fcc95498ad586baUL
        M 0x20200080UL, 0xd9805929d91a245eUL
        M 0x20200088UL, 0x378892d7ec9fbf24UL ]
    given0
    |> run um [ "6109d001" ]
    |> is [ M 0x20200080UL, 0x75929d91a245eUL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0x4a147237baf5829aUL
        M 0x20200080UL, 0x2c2c3de620e36a2fUL
        M 0x20200088UL, 0x59214e3542aea8daUL ]
    given1
    |> run um [ "6109d001" ]
    |> is [ M 0x20200080UL, 0xffffffe620e36a2fUL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0x4d14b87cb9c78308UL
        M 0x20200080UL, 0x39af6bf8b860a7b2UL
        M 0x20200088UL, 0xd6317788ca42dcbaUL ]
    given2
    |> run um [ "6109d001" ]
    |> is [ M 0x20200080UL, 0x456789abcdefa7b2UL ]

  /// <summary>
  /// 55281108, sdxc1 f2, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sdxc1 $f2,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SDXC1``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xfac72d4d01c4c6bdUL
        M 0x20200080UL, 0xfead298fa788d6fbUL
        M 0x20200088UL, 0x58840f60509526edUL ]
    given0
    |> run um [ "55281108" ]
    |> is [ M 0x20200080UL, 0xbff0000000000000UL ]
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x445c461be083d474UL
        M 0x20200080UL, 0x36149eb348929fbdUL
        M 0x20200088UL, 0x74e82db08ce94825UL ]
    given1
    |> run um [ "55281108" ]
    |> is [ M 0x20200080UL, 0x400c000000000000UL ]
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0xc2d25d16efd1e650UL
        M 0x20200080UL, 0x692ad42cad97af8UL
        M 0x20200088UL, 0x6b443719c4c0e37eUL ]
    given2
    |> run um [ "55281108" ]
    |> is [ M 0x20200080UL, 0x3fd0000000000000UL ]

  /// <summary>
  /// 01092b3c, seb a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SEB``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01092b3c" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01092b3c" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01092b3c" ]
    |> is [ G 8, 0x78UL ]

  /// <summary>
  /// 01093b3c, seh a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SEH``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01093b3c" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01093b3c" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01093b3c" ]
    |> is [ G 8, 0x5678UL ]

  /// <summary>
  /// 38230001, sh at, 1(v1), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SH``() =
    let given0 =
      [ G 1, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xf347d039c1db73e0UL
        M 0x20200080UL, 0x5963c2a9b4c91f10UL
        M 0x20200088UL, 0x109b430fe5b2ef6UL ]
    given0
    |> run um [ "38230001" ]
    |> is [ M 0x20200080UL, 0x7c2a9b4c91f10UL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xff29b6de62a966dUL
        M 0x20200080UL, 0x8a6dc9b9c2565197UL
        M 0x20200088UL, 0x7e4f47116197bc56UL ]
    given1
    |> run um [ "38230001" ]
    |> is [ M 0x20200080UL, 0xffffc9b9c2565197UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xfc7f443587efadfdUL
        M 0x20200080UL, 0x38b40d935298d79aUL
        M 0x20200088UL, 0x37e49559cb7d529fUL ]
    given2
    |> run um [ "38230001" ]
    |> is [ M 0x20200080UL, 0xcdef0d935298d79aUL ]

  /// <summary>
  /// a901, sh v0, 2(s0), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SH16``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x295b4c11c36517deUL
        M 0x20200080UL, 0xfeb8325746993fbcUL
        M 0x20200088UL, 0x85a425ac460784bUL ]
    given0
    |> run um [ "a901" ]
    |> is [ M 0x20200080UL, 0x7325746993fbcUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xb904f8e73c542e69UL
        M 0x20200080UL, 0x6a976607cf45bacaUL
        M 0x20200088UL, 0x5e2853559a8bbd68UL ]
    given1
    |> run um [ "a901" ]
    |> is [ M 0x20200080UL, 0xffff6607cf45bacaUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x894e8fe6f5ad217cUL
        M 0x20200080UL, 0xb611a592e915bdb3UL
        M 0x20200088UL, 0xe7c43e7b6e50f0d1UL ]
    given2
    |> run um [ "a901" ]
    |> is [ M 0x20200080UL, 0xcdefa592e915bdb3UL ]

  /// <summary>
  /// 6109aa01, she a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SHE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xed6ca7bb4050f6ccUL
        M 0x20200080UL, 0x1efc3d6b47f94beaUL
        M 0x20200088UL, 0x420f8c29f14fa679UL ]
    given0
    |> run um [ "6109aa01" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xb1c9153cb6414409UL
        M 0x20200080UL, 0x3a4df6c44ac34b38UL
        M 0x20200088UL, 0x5c1ee2ebb80a6f4dUL ]
    given1
    |> run um [ "6109aa01" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xef60bd9ae8727380UL
        M 0x20200080UL, 0x3fbacec3fd7457deUL
        M 0x20200088UL, 0x1bbe4c7065c21c9bUL ]
    given2
    |> run um [ "6109aa01" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 01090800, sll a4, a5, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLL``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01090800" ]
    |> is [ G 8, 0x6UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01090800" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01090800" ]
    |> is [ G 8, 0x2468acf0UL ]

  /// <summary>
  /// 2530, sll v0, v1, 0x8, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLL16``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "2530" ]
    |> is [ G 2, 0x300UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "2530" ]
    |> is [ G 2, 0x100UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "2530" ]
    |> is [ G 2, 0x34567800UL ]

  /// <summary>
  /// 012a4010, sllv a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLLV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "012a4010" ]
    |> is [ G 8, 0x60UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "012a4010" ]
    |> is [ G 8, 0x40000000UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "012a4010" ]
    |> is [ G 8, 0x78000000UL ]

  /// <summary>
  /// 01494350, slt a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLT``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494350" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494350" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494350" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x2UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494350" ]
    |> is [ G 8, 0x1UL ]

  /// <summary>
  /// 91090001, slti a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLTI``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "91090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "91090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "91090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x2UL; G 9, 0x3UL ]
    |> run um [ "91090001" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// b1090001, sltiu a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLTIU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "b1090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "b1090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "b1090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x2UL; G 9, 0x3UL ]
    |> run um [ "b1090001" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 01494390, sltu a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SLTU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494390" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494390" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494390" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x2UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494390" ]
    |> is [ G 8, 0x1UL ]

  /// <summary>
  /// 54440a3b, sqrt.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sqrt.s $f2,$f4, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SQRT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "54440a3b" ]
    |> is [ F 2, 0x3fc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0x41800000UL ]
    |> run um [ "54440a3b" ]
    |> is [ F 2, 0x40800000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x3d800000UL ]
    |> run um [ "54440a3b" ]
    |> is []

  /// <summary>
  /// 01090880, sra a4, a5, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SRA``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01090880" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01090880" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01090880" ]
    |> is [ G 8, 0x91a2b3cUL ]

  /// <summary>
  /// 012a4090, srav a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SRAV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "012a4090" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "012a4090" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "012a4090" ]
    |> is [ G 8, 0x12UL ]

  /// <summary>
  /// 01090840, srl a4, a5, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SRL``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01090840" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01090840" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01090840" ]
    |> is [ G 8, 0x91a2b3cUL ]

  /// <summary>
  /// 2531, srl v0, v1, 0x8, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SRL16``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "2531" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "2531" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "2531" ]
    |> is [ G 2, 0x123456UL ]

  /// <summary>
  /// 012a4050, srlv a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SRLV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "012a4050" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "012a4050" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "012a4050" ]
    |> is [ G 8, 0x12UL ]

  /// <summary>
  /// 00000800, ssnop, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SSNOP``() =
    []
    |> run um [ "00000800" ]
    |> is []
    []
    |> run um [ "00000800" ]
    |> is []
    []
    |> run um [ "00000800" ]
    |> is []

  /// <summary>
  /// 01494190, sub a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGFPE (Exception IntegerOverflow here); the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SUB``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494190" ]
    |> is [ G 8, 0xfffffffffffffffeUL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494190" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494190" ]
    |> is [ G 8, 0x13579be0UL ]
    [ G 8, 0x7UL; G 9, 0xffffffff80000000UL; G 10, 0x1UL ]
    |> run um [ "01494190" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 54c41070, sub.s f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after sub.s $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SUB.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run um [ "54c41070" ]
    |> is [ F 2, 0x3f400000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run um [ "54c41070" ]
    |> is [ F 2, 0xc0d80000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run um [ "54c41070" ]
    |> is [ F 2, 0x4479f800UL ]

  /// <summary>
  /// 014941d0, subu a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SUBU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "014941d0" ]
    |> is [ G 8, 0xfffffffffffffffeUL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "014941d0" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "014941d0" ]
    |> is [ G 8, 0x13579be0UL ]

  /// <summary>
  /// 0539, subu v0, a0, v1, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SUBU16``() =
    [ G 2, 0x7UL; G 3, 0x5UL; G 4, 0x3UL ]
    |> run um [ "0539" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x7fffffffUL; G 3, 0xfffffffffffffffeUL; G 4, 0x1UL ]
    |> run um [ "0539" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0xfffffffffedcba98UL; G 4, 0x12345678UL ]
    |> run um [ "0539" ]
    |> is [ G 2, 0x13579be0UL ]

  /// <summary>
  /// 55281188, suxc1 f2, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after suxc1 $f2,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SUXC1``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0x30984d1979159f2eUL
        M 0x20200080UL, 0x1fcadc1e4d6b5745UL
        M 0x20200088UL, 0x7b6e4ced3bb45e9fUL ]
    given0
    |> run um [ "55281188" ]
    |> is [ M 0x20200080UL, 0xbff0000000000000UL ]
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x6bced19415854ffeUL
        M 0x20200080UL, 0xf84ab467a25d7998UL
        M 0x20200088UL, 0x2e29afce34d30463UL ]
    given1
    |> run um [ "55281188" ]
    |> is [ M 0x20200080UL, 0x400c000000000000UL ]
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x133e8195378d3c86UL
        M 0x20200080UL, 0xd7643ddf45f8faa6UL
        M 0x20200088UL, 0x6396849a260ed841UL ]
    given2
    |> run um [ "55281188" ]
    |> is [ M 0x20200080UL, 0x3fd0000000000000UL ]

  /// <summary>
  /// c821, sw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SW``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x437ee6ed4eb91715UL
        M 0x20200080UL, 0x95f2ddc581579062UL
        M 0x20200088UL, 0x555aaecba8bea92fUL ]
    given0
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x781579062UL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x31ebb6b5aa792dc7UL
        M 0x20200080UL, 0x28518eab29509d4UL
        M 0x20200088UL, 0xa0a9c742cd32965bUL ]
    given1
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x7fffffffb29509d4UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xea35728d05c95e0cUL
        M 0x20200080UL, 0x1ae4be633879a4d3UL
        M 0x20200088UL, 0xe5221b97f8807116UL ]
    given2
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x89abcdef3879a4d3UL ]

  /// <summary>
  /// c821, sw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SW16``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xfaaa39456e10b7f8UL
        M 0x20200080UL, 0x8a14fb8c7e45c621UL
        M 0x20200088UL, 0x973b6307f0d59179UL ]
    given0
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x77e45c621UL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xccb842b7079a5bb9UL
        M 0x20200080UL, 0x90cf0104905d85bdUL
        M 0x20200088UL, 0x410e84f61eb83cd3UL ]
    given1
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x7fffffff905d85bdUL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x94726041f158fe42UL
        M 0x20200080UL, 0xc6f811717bb984b1UL
        M 0x20200088UL, 0xec9227bc389f62b3UL ]
    given2
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x89abcdef7bb984b1UL ]

  /// <summary>
  /// 98480001, swc1 f2, 1(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after swc1 $f2,1($8), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWC1``() =
    let given0 =
      [ G 8, 0x2020007fUL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0xb93f8c99ac585435UL
        M 0x20200080UL, 0x565116df36579843UL
        M 0x20200088UL, 0x997c037d1464576UL ]
    given0
    |> run um [ "98480001" ]
    |> is [ M 0x20200080UL, 0xbf80000036579843UL ]
    let given1 =
      [ G 8, 0x2020007fUL
        F 2, 0x40600000UL
        M 0x20200078UL, 0x222944e0ea621f24UL
        M 0x20200080UL, 0xbff09f3d575be969UL
        M 0x20200088UL, 0xb8448bd24b8c2644UL ]
    given1
    |> run um [ "98480001" ]
    |> is [ M 0x20200080UL, 0x40600000575be969UL ]
    let given2 =
      [ G 8, 0x2020007fUL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0xf4b24ccafec68fb2UL
        M 0x20200080UL, 0x22165aefd95d8901UL
        M 0x20200088UL, 0x9d93e8d141a7954eUL ]
    given2
    |> run um [ "98480001" ]
    |> is [ M 0x20200080UL, 0x3e800000d95d8901UL ]

  /// <summary>
  /// 20008001, swc2 0x0, 1(r0), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWC2``() =
    let given0 =
      [ M 0x20200078UL, 0xfad92745ff7edb9dUL
        M 0x20200080UL, 0x26c4e0a1c06e013dUL
        M 0x20200088UL, 0xcdb7f47b6da29af2UL ]
    given0
    |> run um [ "20008001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0xe7e1fb5fff05c3feUL
        M 0x20200080UL, 0x5c670cab76b35b40UL
        M 0x20200088UL, 0x495661cd9d5a11bdUL ]
    given1
    |> run um [ "20008001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0x4a54692338dd5738UL
        M 0x20200080UL, 0xaf0c554729b93ef0UL
        M 0x20200088UL, 0x3f09351142f830ebUL ]
    given2
    |> run um [ "20008001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 6109ae01, swe a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x5d349a31edad6db7UL
        M 0x20200080UL, 0x70e271644920a616UL
        M 0x20200088UL, 0xeb8e0e120747f6fdUL ]
    given0
    |> run um [ "6109ae01" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x6dcecef6a336e1e2UL
        M 0x20200080UL, 0x47bbb870bbe29a61UL
        M 0x20200088UL, 0xd6c508530aeb994eUL ]
    given1
    |> run um [ "6109ae01" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x958690698f3a9915UL
        M 0x20200080UL, 0x3133fb8ea17b83f6UL
        M 0x20200088UL, 0x3d9cd05acc64a84dUL ]
    given2
    |> run um [ "6109ae01" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 61098001, swl a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWL``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0xced4a8de7264eadUL
        M 0x20200080UL, 0x3f8c3366c9aa8f5eUL
        M 0x20200088UL, 0x6fe2032404f7a790UL ]
    given0
    |> run um [ "61098001" ]
    |> is [ M 0x20200080UL, 0x3f000000c9aa8f5eUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0xfd98013dfc640287UL
        M 0x20200080UL, 0x696a5ce5e3f694ebUL
        M 0x20200088UL, 0x3d89d1dde198866aUL ]
    given1
    |> run um [ "61098001" ]
    |> is [ M 0x20200080UL, 0x696a7fffe3f694ebUL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0xc9d951ddda98aa39UL
        M 0x20200080UL, 0x81d777f30eb0419fUL
        M 0x20200088UL, 0x6c64d0d04e9e9d2aUL ]
    given2
    |> run um [ "61098001" ]
    |> is [ M 0x20200080UL, 0x81d777f30e89abcdUL ]

  /// <summary>
  /// 6109a001, swle a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWLE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0xf1693e443150864aUL
        M 0x20200080UL, 0x6e1dca6a815aeb72UL
        M 0x20200088UL, 0x5b91c8cf7dc0959UL ]
    given0
    |> run um [ "6109a001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        Status, 0x10UL
        M 0x20200078UL, 0x924a18f010ad6f89UL
        M 0x20200080UL, 0x9215a0ad682d3f22UL
        M 0x20200088UL, 0xed978f7ea38e97adUL ]
    given1
    |> run um [ "6109a001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        Status, 0x10UL
        M 0x20200078UL, 0x173843191472bf3aUL
        M 0x20200080UL, 0x8e5bea0a2bb32353UL
        M 0x20200088UL, 0x19559ba571827131UL ]
    given2
    |> run um [ "6109a001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4541, swm s0, ra, 4(sp), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWM16``() =
    let given0 =
      [ G 16, 0x7UL
        G 29, 0x2020007cUL
        G 31, 0x3UL
        M 0x20200078UL, 0xe7771764ca901cf6UL
        M 0x20200080UL, 0xd83f14ce6f5cccf4UL
        M 0x20200088UL, 0x1a04a5e5e343e95UL ]
    given0
    |> run um [ "4541" ]
    |> is [ M 0x20200080UL, 0x700000003UL ]
    let given1 =
      [ G 16, 0x7fffffffUL
        G 29, 0x2020007cUL
        G 31, 0x1UL
        M 0x20200078UL, 0xbbb802a0f3d1d44fUL
        M 0x20200080UL, 0xf78016e744f574afUL
        M 0x20200088UL, 0x21d7a3568d86288dUL ]
    given1
    |> run um [ "4541" ]
    |> is [ M 0x20200080UL, 0x7fffffff00000001UL ]
    let given2 =
      [ G 16, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        G 31, 0x12345678UL
        M 0x20200078UL, 0x17d99c3d37b41ac0UL
        M 0x20200080UL, 0xf7967a3bdd7b8d8UL
        M 0x20200088UL, 0x62c6ccb60e0284f0UL ]
    given2
    |> run um [ "4541" ]
    |> is [ M 0x20200080UL, 0x89abcdef12345678UL ]

  /// <summary>
  /// 2044d008, swm s0, s1, 8(a0), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWM32``() =
    let given0 =
      [ G 4, 0x20200078UL
        G 16, 0x7UL
        G 17, 0x3UL
        M 0x20200078UL, 0xfac1f3b3e7188f10UL
        M 0x20200080UL, 0xd9f1df9aeccbd416UL
        M 0x20200088UL, 0xbaf7edc46be38a0UL ]
    given0
    |> run um [ "2044d008" ]
    |> is [ M 0x20200080UL, 0x700000003UL ]
    let given1 =
      [ G 4, 0x20200078UL
        G 16, 0x7fffffffUL
        G 17, 0x1UL
        M 0x20200078UL, 0xff9485e04e3d6c4bUL
        M 0x20200080UL, 0x440c9a7e2da1b761UL
        M 0x20200088UL, 0xbfd78c45df5e3971UL ]
    given1
    |> run um [ "2044d008" ]
    |> is [ M 0x20200080UL, 0x7fffffff00000001UL ]
    let given2 =
      [ G 4, 0x20200078UL
        G 16, 0xffffffff89abcdefUL
        G 17, 0x12345678UL
        M 0x20200078UL, 0x42546bcd0a5ad7eaUL
        M 0x20200080UL, 0x3710f7bc653f6bbcUL
        M 0x20200088UL, 0xd87e2ffc24ddac5fUL ]
    given2
    |> run um [ "2044d008" ]
    |> is [ M 0x20200080UL, 0x89abcdef12345678UL ]

  /// <summary>
  /// 20449008, swp v0, v1, 8(a0), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWP``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x3UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0x480cf8dfc5729723UL
        M 0x20200080UL, 0x56bfdf34423df99eUL
        M 0x20200088UL, 0x85e0c305d02e6e5dUL ]
    given0
    |> run um [ "20449008" ]
    |> is [ M 0x20200080UL, 0x700000003UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x1UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0xe41fc6f2d5da524aUL
        M 0x20200080UL, 0x4908b9bfc2579e0cUL
        M 0x20200088UL, 0xee108d2bd9ea39c5UL ]
    given1
    |> run um [ "20449008" ]
    |> is [ M 0x20200080UL, 0x7fffffff00000001UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0x70ac8032b9a7c62bUL
        M 0x20200080UL, 0x5d0601b3dea7e4bdUL
        M 0x20200088UL, 0x41de56d99d25adc3UL ]
    given2
    |> run um [ "20449008" ]
    |> is [ M 0x20200080UL, 0x89abcdef12345678UL ]

  /// <summary>
  /// 61099001, swr a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWR``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x9520a9538f71ab7UL
        M 0x20200080UL, 0x7f01634ee889e65bUL
        M 0x20200088UL, 0x9153f03dc5c5e811UL ]
    given0
    |> run um [ "61099001" ]
    |> is [ M 0x20200080UL, 0x7634ee889e65bUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0x29bd0caac162c4a8UL
        M 0x20200080UL, 0x12c2cb4120070521UL
        M 0x20200088UL, 0xc7ab1658a1cbc3b3UL ]
    given1
    |> run um [ "61099001" ]
    |> is [ M 0x20200080UL, 0xffffff4120070521UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0x2f0367fc340fe3eaUL
        M 0x20200080UL, 0x621d9bdad9a8e4f3UL
        M 0x20200088UL, 0xa4288882244c506cUL ]
    given2
    |> run um [ "61099001" ]
    |> is [ M 0x20200080UL, 0x621d9bdacdefe4f3UL ]

  /// <summary>
  /// 6109a201, swre a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWRE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0x3d3d10d61eceba92UL
        M 0x20200080UL, 0x158e699bd94a5d1cUL
        M 0x20200088UL, 0x96f406466caa05eeUL ]
    given0
    |> run um [ "6109a201" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        Status, 0x10UL
        M 0x20200078UL, 0x291078743ed83d2UL
        M 0x20200080UL, 0x4cb6fbf62c94f130UL
        M 0x20200088UL, 0x71c16764dbd7869bUL ]
    given1
    |> run um [ "6109a201" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        Status, 0x10UL
        M 0x20200078UL, 0x7096163cd5eb4f0eUL
        M 0x20200080UL, 0xaccbc948d08c95e3UL
        M 0x20200088UL, 0xcb3fcdc7bc35e796UL ]
    given2
    |> run um [ "6109a201" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// c821, sw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWSP``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x2a1260c708ad28f8UL
        M 0x20200080UL, 0x32e48ac233fc28aeUL
        M 0x20200088UL, 0x684f9548e6176f74UL ]
    given0
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x733fc28aeUL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xd2f056d0bcac5fd1UL
        M 0x20200080UL, 0xe293973fab321287UL
        M 0x20200088UL, 0x74a93d3057e9a24bUL ]
    given1
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x7fffffffab321287UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xa0eb669cd8ff2fcaUL
        M 0x20200080UL, 0x5112652afd8fc361UL
        M 0x20200088UL, 0xa9601a4d458811eUL ]
    given2
    |> run um [ "c821" ]
    |> is [ M 0x20200080UL, 0x89abcdeffd8fc361UL ]

  /// <summary>
  /// 55281088, swxc1 f2, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after swxc1 $f2,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SWXC1``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0x280a2769a1f8c7d7UL
        M 0x20200080UL, 0x50343a834d10756eUL
        M 0x20200088UL, 0x346912c075149b52UL ]
    given0
    |> run um [ "55281088" ]
    |> is [ M 0x20200080UL, 0xbf8000004d10756eUL ]
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x40600000UL
        M 0x20200078UL, 0xf86038b6cad42053UL
        M 0x20200080UL, 0x48c84175832f138UL
        M 0x20200088UL, 0xac4843c639219b61UL ]
    given1
    |> run um [ "55281088" ]
    |> is [ M 0x20200080UL, 0x406000005832f138UL ]
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0xae3126bf297126f2UL
        M 0x20200080UL, 0x6a2e44c3fb920857UL
        M 0x20200088UL, 0xafceb9c3cbd3a5a6UL ]
    given2
    |> run um [ "55281088" ]
    |> is [ M 0x20200080UL, 0x3e800000fb920857UL ]

  /// <summary>
  /// 00026b7c, sync 0x2, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SYNC``() =
    []
    |> run um [ "00026b7c" ]
    |> is []
    []
    |> run um [ "00026b7c" ]
    |> is []
    []
    |> run um [ "00026b7c" ]
    |> is []

  /// <summary>
  /// 42080001, synci 1(a4), against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SYNCI``() =
    let given0 =
      [ G 8, 0x2020007fUL
        M 0x20200078UL, 0x4cfb9cb94b16b965UL
        M 0x20200080UL, 0x61c8abeaa9a577caUL
        M 0x20200088UL, 0xf9c7f550a4b646aaUL ]
    given0
    |> run um [ "42080001" ]
    |> is []
    let given1 =
      [ G 8, 0x2020007fUL
        M 0x20200078UL, 0x5ab43f6692fc3985UL
        M 0x20200080UL, 0xcc7db2214e746089UL
        M 0x20200088UL, 0x562608572db565bbUL ]
    given1
    |> run um [ "42080001" ]
    |> is []
    let given2 =
      [ G 8, 0x2020007fUL
        M 0x20200078UL, 0xe8c48f4c606884e5UL
        M 0x20200080UL, 0x3845db31077c62a0UL
        M 0x20200088UL, 0x252d416aa5318402UL ]
    given2
    |> run um [ "42080001" ]
    |> is []

  /// <summary>
  /// 00228b7c, syscall 0x22. Not run against QEMU, where a system call is the
  /// host kernel answering rather than the instruction. The lift raises SysCall
  /// and changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 SYSCALL``() =
    []
    |> run um [ "00228b7c" ]
    |> raises [ SysCall ] []

  /// <summary>
  /// 0128003c, teq a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TEQ``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0128003c" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0128003c" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0128003c" ]
    |> is []
    [ G 8, 0x7UL; G 9, 0x7UL ]
    |> run um [ "0128003c" ]
    |> raises [ Interrupt 13 ] []
    [ G 9, 0x1UL ]
    |> run um [ "0128003c" ]
    |> is []

  /// <summary>
  /// 41c80001, teqi a4, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TEQI``() =
    [ G 8, 0x7UL ]
    |> run um [ "41c80001" ]
    |> is []
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41c80001" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41c80001" ]
    |> is []
    [ G 8, 0x1UL ]
    |> run um [ "41c80001" ]
    |> raises [ Interrupt 13 ] []
    []
    |> run um [ "41c80001" ]
    |> is []

  /// <summary>
  /// 0128023c, tge a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TGE``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0128023c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0128023c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0128023c" ]
    |> is []
    [ G 8, 0x7UL; G 9, 0x7UL ]
    |> run um [ "0128023c" ]
    |> raises [ Interrupt 13 ] []
    [ G 9, 0x1UL ]
    |> run um [ "0128023c" ]
    |> is []

  /// <summary>
  /// 41280001, tgei a4, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TGEI``() =
    [ G 8, 0x7UL ]
    |> run um [ "41280001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41280001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41280001" ]
    |> is []
    [ G 8, 0x1UL ]
    |> run um [ "41280001" ]
    |> raises [ Interrupt 13 ] []
    []
    |> run um [ "41280001" ]
    |> is []

  /// <summary>
  /// 41680001, tgeiu a4, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TGEIU``() =
    [ G 8, 0x7UL ]
    |> run um [ "41680001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41680001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41680001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x1UL ]
    |> run um [ "41680001" ]
    |> raises [ Interrupt 13 ] []
    []
    |> run um [ "41680001" ]
    |> is []

  /// <summary>
  /// 0128043c, tgeu a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TGEU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0128043c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0128043c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0128043c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7UL; G 9, 0x7UL ]
    |> run um [ "0128043c" ]
    |> raises [ Interrupt 13 ] []
    [ G 9, 0x1UL ]
    |> run um [ "0128043c" ]
    |> is []

  /// <summary>
  /// 0000037c, tlbp, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBP``() =
    [ Status, 0x10UL ]
    |> run um [ "0000037c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000037c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000037c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0000137c, tlbr, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBR``() =
    [ Status, 0x10UL ]
    |> run um [ "0000137c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000137c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000137c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0000237c, tlbwi, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBWI``() =
    [ Status, 0x10UL ]
    |> run um [ "0000237c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000237c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000237c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0000337c, tlbwr, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBWR``() =
    [ Status, 0x10UL ]
    |> run um [ "0000337c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000337c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000337c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0128083c, tlt a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLT``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0128083c" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0128083c" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0128083c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7UL; G 9, 0x7UL ]
    |> run um [ "0128083c" ]
    |> is []
    [ G 9, 0x1UL ]
    |> run um [ "0128083c" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 41080001, tlti a4, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLTI``() =
    [ G 8, 0x7UL ]
    |> run um [ "41080001" ]
    |> is []
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41080001" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41080001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x1UL ]
    |> run um [ "41080001" ]
    |> is []
    []
    |> run um [ "41080001" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 41480001, tltiu a4, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLTIU``() =
    [ G 8, 0x7UL ]
    |> run um [ "41480001" ]
    |> is []
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41480001" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41480001" ]
    |> is []
    [ G 8, 0x1UL ]
    |> run um [ "41480001" ]
    |> is []
    []
    |> run um [ "41480001" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 01280a3c, tltu a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TLTU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01280a3c" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01280a3c" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01280a3c" ]
    |> is []
    [ G 8, 0x7UL; G 9, 0x7UL ]
    |> run um [ "01280a3c" ]
    |> is []
    [ G 9, 0x1UL ]
    |> run um [ "01280a3c" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 01280c3c, tne a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TNE``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01280c3c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01280c3c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01280c3c" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7UL; G 9, 0x7UL ]
    |> run um [ "01280c3c" ]
    |> is []
    [ G 9, 0x1UL ]
    |> run um [ "01280c3c" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 41880001, tnei a4, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGTRAP (Interrupt 13 here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TNEI``() =
    [ G 8, 0x7UL ]
    |> run um [ "41880001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41880001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41880001" ]
    |> raises [ Interrupt 13 ] []
    [ G 8, 0x1UL ]
    |> run um [ "41880001" ]
    |> is []
    []
    |> run um [ "41880001" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 5444233b, trunc.l.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after trunc.l.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TRUNC.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "5444233b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "5444233b" ]
    |> is [ F 2, 0xffffffffffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "5444233b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 54442b3b, trunc.w.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after trunc.w.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 TRUNC.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "54442b3b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "54442b3b" ]
    |> is [ F 2, 0xffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "54442b3b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 0022937c, wait 0x22, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 WAIT``() =
    [ Status, 0x10UL ]
    |> run um [ "0022937c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0022937c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0022937c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0109f17c, wrpgpr a4, a5, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 WRPGPR``() =
    [ G 8, 0x7UL; G 9, 0x3UL; Status, 0x10UL ]
    |> run um [ "0109f17c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; Status, 0x10UL ]
    |> run um [ "0109f17c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; Status, 0x10UL ]
    |> run um [ "0109f17c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 01097b3c, wsbh a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 WSBH``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01097b3c" ]
    |> is [ G 8, 0x300UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01097b3c" ]
    |> is [ G 8, 0x100UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01097b3c" ]
    |> is [ G 8, 0x34127856UL ]

  /// <summary>
  /// 01494310, xor a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 XOR``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494310" ]
    |> is [ G 8, 0x6UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494310" ]
    |> is [ G 8, 0xffffffffffffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494310" ]
    |> is [ G 8, 0xffffffffece8ece0UL ]

  /// <summary>
  /// 4453, xor v0, v0, v1, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 XOR16``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "4453" ]
    |> is [ G 2, 0x4UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "4453" ]
    |> is [ G 2, 0x7ffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "4453" ]
    |> is [ G 2, 0xffffffff9b9f9b97UL ]

  /// <summary>
  /// 71090001, xori a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 XORI``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "71090001" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "71090001" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "71090001" ]
    |> is [ G 8, 0x12345679UL ]
