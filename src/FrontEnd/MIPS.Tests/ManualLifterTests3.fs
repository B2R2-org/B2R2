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
/// One test for each instruction of MD00087: MSUBU to XORI.
///
/// <para>A value test runs a word of the instruction under QEMU over a few
/// sets of register values, memory and FCSR, and has the lift change what
/// QEMU changed, raise what QEMU raised, and nothing else; every value it
/// expects is QEMU's (optest-mips/oracle). A structural test says in its own
/// comment what it checks and why no value test could be had.</para>
/// </summary>
[<TestClass>]
type ManualLifterTests3() =
  let r2 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)

  let r6 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)

  /// <summary>
  /// 70430005, msubu v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MSUBU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run r2 [ "70430005" ]
    |> is [ Lo, 0xfUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run r2 [ "70430005" ]
    |> is [ Lo, 0x2UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run r2 [ "70430005" ]
    |> is [ Hi, 0xffffffffd4e3850eUL; Lo, 0x2ff18470UL ]

  /// <summary>
  /// 40800001, mtc0 r0, 0x0, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTC0``() =
    [ Status, 0x10UL ]
    |> run r2 [ "40800001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40800001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40800001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 44821000, mtc1 v0, f2, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTC1``() =
    [ G 2, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run r2 [ "44821000" ]
    |> is [ F 2, 0x1122334400000007UL ]
    [ G 2, 0x7fffffffUL; F 2, 0xbf800000UL ]
    |> run r2 [ "44821000" ]
    |> is [ F 2, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run r2 [ "44821000" ]
    |> is [ F 2, 0x8899aabb89abcdefUL ]

  /// <summary>
  /// 48821900, mtc2 v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTC2``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "48821900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "48821900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "48821900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 40c00001, mthc0 r0, 0x0, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTHC0``() =
    [ Status, 0x10UL ]
    |> run r2 [ "40c00001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40c00001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40c00001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 44e21000, mthc1 v0, f2, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTHC1``() =
    [ G 2, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run r2 [ "44e21000" ]
    |> is [ F 2, 0x755667788UL ]
    [ G 2, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run r2 [ "44e21000" ]
    |> is [ F 2, 0xffffffffbf800000UL ]
    [ G 2, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run r2 [ "44e21000" ]
    |> is [ F 2, 0x89abcdefccddeeffUL ]

  /// <summary>
  /// 48e21900, mthc2 v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTHC2``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "48e21900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "48e21900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "48e21900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00400011, mthi v0, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTHI``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "00400011" ]
    |> is [ Hi, 0x7UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "00400011" ]
    |> is [ Hi, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "00400011" ]
    |> is [ Hi, 0xffffffff89abcdefUL ]

  /// <summary>
  /// 00400013, mtlo v0, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MTLO``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "00400013" ]
    |> is [ Lo, 0x7UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "00400013" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "00400013" ]
    |> is [ Lo, 0xffffffff89abcdefUL ]

  /// <summary>
  /// 006410d8, muh v0, v1, a0, against QEMU's I6400, a Release 6 processor: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MUH``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410d8" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410d8" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "006410d8" ]
    |> is [ G 2, 0xffffffffffeb4992UL ]

  /// <summary>
  /// 006410d9, muhu v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MUHU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410d9" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410d9" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "006410d9" ]
    |> is [ G 2, 0x121fa00aUL ]

  /// <summary>
  /// 70641002, mul v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MUL``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "70641002" ]
    |> is [ G 2, 0xfUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "70641002" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "70641002" ]
    |> is [ G 2, 0x35068740UL ]

  /// <summary>
  /// 46062082, mul.s f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MUL.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run r2 [ "46062082" ]
    |> is [ F 2, 0x40580000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run r2 [ "46062082" ]
    |> is [ F 2, 0xc0900000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run r2 [ "46062082" ]
    |> is [ F 2, 0x42fa0000UL ]

  /// <summary>
  /// 00430018, mult v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MULT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430018" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430018" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430018" ]
    |> is [ Hi, 0xfffffffff795e368UL; Lo, 0xffffffffe242d208UL ]

  /// <summary>
  /// 00430019, multu v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MULTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430019" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430019" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430019" ]
    |> is [ Hi, 0x9ca39e0UL; Lo, 0xffffffffe242d208UL ]

  /// <summary>
  /// 00641099, mulu v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MULU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "00641099" ]
    |> is [ G 2, 0xfUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "00641099" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "00641099" ]
    |> is [ G 2, 0x35068740UL ]

  /// <summary>
  /// 04100000, nal 0x20100004 (binutils: bltzal $0,20100004). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: to
  /// 0x20100008, past the slot, when nothing is given; ra becomes 0x20100008
  /// and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 NAL``() =
    let words = [ "04100000"; "00000000" ]
    goes r2 words [] 0x20100008UL
    []
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 46002087, neg.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 NEG.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46002087" ]
    |> is [ F 2, 0xc0100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run r2 [ "46002087" ]
    |> is [ F 2, 0x40c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run r2 [ "46002087" ]
    |> is [ F 2, 0xc47a0000UL ]

  /// <summary>
  /// 4c8830b0, nmadd.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 NMADD.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run r2 [ "4c8830b0" ]
    |> is [ F 2, 0xc0400000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run r2 [ "4c8830b0" ]
    |> is [ F 2, 0x40400000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run r2 [ "4c8830b0" ]
    |> is [ F 2, 0xc479ec00UL ]

  /// <summary>
  /// 4c8830b8, nmsub.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 NMSUB.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run r2 [ "4c8830b8" ]
    |> is [ F 2, 0x3fc00000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run r2 [ "4c8830b8" ]
    |> is [ F 2, 0xc1100000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run r2 [ "4c8830b8" ]
    |> is [ F 2, 0x447a1400UL ]

  /// <summary>
  /// 00000000, nop, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 NOP``() =
    []
    |> run r2 [ "00000000" ]
    |> is []
    []
    |> run r2 [ "00000000" ]
    |> is []
    []
    |> run r2 [ "00000000" ]
    |> is []

  /// <summary>
  /// 00641027, nor v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 NOR``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641027" ]
    |> is [ G 2, 0xfffffffffffffff8UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641027" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641027" ]
    |> is [ G 2, 0x1030107UL ]

  /// <summary>
  /// 00641025, or v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 OR``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641025" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641025" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641025" ]
    |> is [ G 2, 0xfffffffffefcfef8UL ]

  /// <summary>
  /// 34620100, ori v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ORI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "34620100" ]
    |> is [ G 2, 0x103UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "34620100" ]
    |> is [ G 2, 0x101UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "34620100" ]
    |> is [ G 2, 0x12345778UL ]

  /// <summary>
  /// 00000140, pause, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PAUSE``() =
    []
    |> run r2 [ "00000140" ]
    |> is []
    []
    |> run r2 [ "00000140" ]
    |> is []
    []
    |> run r2 [ "00000140" ]
    |> is []

  /// <summary>
  /// 46c620ac, pll.ps f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PLL.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run r2 [ "46c620ac" ]
    |> is [ F 2, 0xbfc000003e800000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run r2 [ "46c620ac" ]
    |> is [ F 2, 0x3f00000040000000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run r2 [ "46c620ac" ]
    |> is [ F 2, 0x40400000c0800000UL ]

  /// <summary>
  /// 46c620ad, plu.ps f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PLU.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run r2 [ "46c620ad" ]
    |> is [ F 2, 0xbfc000003fc00000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run r2 [ "46c620ad" ]
    |> is [ F 2, 0x3f0000003f400000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run r2 [ "46c620ad" ]
    |> is [ F 2, 0x404000003e000000UL ]

  /// <summary>
  /// cc400008, pref 0x0, 8(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PREF``() =
    let given0 =
      [ G 2, 0x20200078UL
        M 0x20200078UL, 0x1c1e546c5e63e13eUL
        M 0x20200080UL, 0x6df88337c95d8820UL
        M 0x20200088UL, 0x6f2f5170c580c627UL ]
    given0
    |> run r2 [ "cc400008" ]
    |> is []
    let given1 =
      [ G 2, 0x20200078UL
        M 0x20200078UL, 0xd84fcc47b23abe25UL
        M 0x20200080UL, 0x64a8cf748676e8a9UL
        M 0x20200088UL, 0xafd12b48dcd42baaUL ]
    given1
    |> run r2 [ "cc400008" ]
    |> is []
    let given2 =
      [ G 2, 0x20200078UL
        M 0x20200078UL, 0x4930c92fd0fb4188UL
        M 0x20200080UL, 0xe5e1ea073929b35fUL
        M 0x20200088UL, 0xf6b959a1784cdb2fUL ]
    given2
    |> run r2 [ "cc400008" ]
    |> is []

  /// <summary>
  /// 7c400423, prefe 0x0, 8(v0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PREFE``() =
    let given0 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0xfa03be607277d0f0UL
        M 0x20200080UL, 0xe3344034af659872UL
        M 0x20200088UL, 0xeca78e2153361b45UL ]
    given0
    |> run r2 [ "7c400423" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0x126770a6a281167aUL
        M 0x20200080UL, 0x5d961e67ac447030UL
        M 0x20200088UL, 0x325241ab23d6be56UL ]
    given1
    |> run r2 [ "7c400423" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0x3f926f35cf94f3f5UL
        M 0x20200080UL, 0xd13565fdfd0ca6d5UL
        M 0x20200088UL, 0xa85d9cff64df2b4aUL ]
    given2
    |> run r2 [ "7c400423" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4c43100f, prefx 0x3, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PREFX``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        M 0x20200078UL, 0x74bb42817776fd23UL
        M 0x20200080UL, 0xf2332143af2f66c3UL
        M 0x20200088UL, 0x28e2435e8c137078UL ]
    given0
    |> run r2 [ "4c43100f" ]
    |> is []
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        M 0x20200078UL, 0xc25dda2883225b89UL
        M 0x20200080UL, 0xa211bb90cea1739dUL
        M 0x20200088UL, 0x7399a80b5ea9eacfUL ]
    given1
    |> run r2 [ "4c43100f" ]
    |> is []
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        M 0x20200078UL, 0xb4ace59c9a8e0b0cUL
        M 0x20200080UL, 0x44603cecfd55682cUL
        M 0x20200088UL, 0x2d17f3ce038a7c1aUL ]
    given2
    |> run r2 [ "4c43100f" ]
    |> is []

  /// <summary>
  /// 46c620ae, pul.ps f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PUL.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run r2 [ "46c620ae" ]
    |> is [ F 2, 0x401000003e800000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run r2 [ "46c620ae" ]
    |> is [ F 2, 0xc0c0000040000000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run r2 [ "46c620ae" ]
    |> is [ F 2, 0x447a0000c0800000UL ]

  /// <summary>
  /// 46c620af, puu.ps f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 PUU.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run r2 [ "46c620af" ]
    |> is [ F 2, 0x401000003fc00000UL ]
    let given1 =
      [ F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run r2 [ "46c620af" ]
    |> is [ F 2, 0xc0c000003f400000UL ]
    let given2 =
      [ F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run r2 [ "46c620af" ]
    |> is [ F 2, 0x447a00003e000000UL ]

  /// <summary>
  /// 7c02e83b, rdhwr v0, sp, 0x0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 RDHWR``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "7c02e83b" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "7c02e83b" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "7c02e83b" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 41431000, rdpgpr v0, v1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 RDPGPR``() =
    [ G 2, 0x7UL; G 3, 0x3UL; Status, 0x10UL ]
    |> run r2 [ "41431000" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; Status, 0x10UL ]
    |> run r2 [ "41431000" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; Status, 0x10UL ]
    |> run r2 [ "41431000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 46002095, recip.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 RECIP.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x3f000000UL ]
    |> run r2 [ "46002095" ]
    |> is [ F 2, 0x40000000UL ]
    [ F 2, 0x40600000UL; F 4, 0x40800000UL ]
    |> run r2 [ "46002095" ]
    |> is [ F 2, 0x3e800000UL ]
    [ F 2, 0x3e800000UL; F 4, 0xbe000000UL ]
    |> run r2 [ "46002095" ]
    |> is [ F 2, 0xc1000000UL ]

  /// <summary>
  /// 4600209a, rint.s f2, f4, against QEMU's I6400, a Release 6 processor: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 RINT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40200000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209a" ]
    |> is [ F 2, 0x40000000UL; Fcsr, 0xc1004UL ]
    [ F 2, 0x40600000UL; F 4, 0xbfe00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209a" ]
    |> is [ F 2, 0xc0000000UL; Fcsr, 0xc1004UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209a" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 00231102, rotr v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ROTR``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00231102" ]
    |> is [ G 2, 0x30000000UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00231102" ]
    |> is [ G 2, 0x10000000UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00231102" ]
    |> is [ G 2, 0xffffffff81234567UL ]

  /// <summary>
  /// 00831046, rotrv v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ROTRV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831046" ]
    |> is [ G 2, 0x18000000UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831046" ]
    |> is [ G 2, 0x4UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00831046" ]
    |> is [ G 2, 0x34567812UL ]

  /// <summary>
  /// 46002088, round.l.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ROUND.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "46002088" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "46002088" ]
    |> is [ F 2, 0xfffffffffffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "46002088" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 4600208c, round.w.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ROUND.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "4600208c" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "4600208c" ]
    |> is [ F 2, 0xfffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "4600208c" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 46002096, rsqrt.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 RSQRT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x3e800000UL ]
    |> run r2 [ "46002096" ]
    |> is [ F 2, 0x40000000UL ]
    [ F 2, 0x40600000UL; F 4, 0x40800000UL ]
    |> run r2 [ "46002096" ]
    |> is [ F 2, 0x3f000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x41800000UL ]
    |> run r2 [ "46002096" ]
    |> is []

  /// <summary>
  /// a0620001, sb v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SB``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x7ffcf3fe92f3c6bdUL
        M 0x20200080UL, 0x33209ee5f9697d9dUL
        M 0x20200088UL, 0xbcad3c7bc46b4bd4UL ]
    given0
    |> run r2 [ "a0620001" ]
    |> is [ M 0x20200080UL, 0x7209ee5f9697d9dUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x6582a4234a62c117UL
        M 0x20200080UL, 0x71672e43f91e6539UL
        M 0x20200088UL, 0x25936bec8dfe41d7UL ]
    given1
    |> run r2 [ "a0620001" ]
    |> is [ M 0x20200080UL, 0xff672e43f91e6539UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x613d4d336c37f17dUL
        M 0x20200080UL, 0xa2dfead807383107UL
        M 0x20200088UL, 0x42c1c9b81b97f245UL ]
    given2
    |> run r2 [ "a0620001" ]
    |> is [ M 0x20200080UL, 0xefdfead807383107UL ]

  /// <summary>
  /// 7c62011c, sbe v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SBE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xca76a3115febd09aUL
        M 0x20200080UL, 0x44f1793940666deUL
        M 0x20200088UL, 0xaf4e8f5224f2c2f9UL ]
    given0
    |> run r2 [ "7c62011c" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x1cebaea05aeeb0f9UL
        M 0x20200080UL, 0x6bc93a38d3d10ffaUL
        M 0x20200088UL, 0xc6f57d1b5929477dUL ]
    given1
    |> run r2 [ "7c62011c" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x5b45605a1db3430bUL
        M 0x20200080UL, 0xd3bf62c7ee497059UL
        M 0x20200088UL, 0x8df05ff26bc70bc5UL ]
    given2
    |> run r2 [ "7c62011c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// e0620001, sc v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SC``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x4b6aa287db97c533UL
        M 0x20200080UL, 0x91e63bf63ced6e2UL
        M 0x20200088UL, 0x7440b189faeb1b53UL ]
    given0
    |> run r2 [ "e0620001" ]
    |> is [ G 2, 0x0UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x93b964f41774590cUL
        M 0x20200080UL, 0xe3c370ef013aac28UL
        M 0x20200088UL, 0x5f83e0dc7b651ba0UL ]
    given1
    |> run r2 [ "e0620001" ]
    |> is [ G 2, 0x0UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x6ce93a9aeca368b2UL
        M 0x20200080UL, 0x972e4b8aebd2b011UL
        M 0x20200088UL, 0x677d73f7bba94428UL ]
    given2
    |> run r2 [ "e0620001" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// f0620001, scd v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SCD``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x86b35c8f09ab473cUL
        M 0x20200080UL, 0xacca2945f8c21a43UL
        M 0x20200088UL, 0x21de66b16e974ff1UL ]
    given0
    |> run r2 [ "f0620001" ]
    |> is [ G 2, 0x0UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x74c433b657679bbcUL
        M 0x20200080UL, 0xcc5954754809cc44UL
        M 0x20200088UL, 0x4e1308ccf005bdb0UL ]
    given1
    |> run r2 [ "f0620001" ]
    |> is [ G 2, 0x0UL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x5d4147bb9949a174UL
        M 0x20200080UL, 0x59b6e8d3603780ddUL
        M 0x20200088UL, 0x1b8c63a7a9813c0cUL ]
    given2
    |> run r2 [ "f0620001" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 7c242877 7c221867, lldp a0, a1, (at) then scdp v0, v1, (at). The store
  /// writes rd and rt as one quadword, rd the more significant, and sets rt
  /// to one; on a big-endian processor the more significant doubleword is the
  /// one at the lower address.
  /// No reference runs it: QEMU's I6400 reads the word as an unpaired
  /// SCD. Checked against the manual's Operation instead.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SCDP``() =
    let given =
      [ G 1, 0x20200080UL
        G 2, 0x2021222324252627UL
        G 3, 0x3031323334353637UL
        M 0x20200080UL, 0x1011121314151617UL
        M 0x20200088UL, 0x18191a1b1c1d1e1fUL ]
    given
    |> run r6 [ "7c242877"; "7c221867" ]
    |> is
      [ G 2, 0x1UL
        G 4, 0x18191a1b1c1d1e1fUL
        G 5, 0x1011121314151617UL
        M 0x20200080UL, 0x3031323334353637UL
        M 0x20200088UL, 0x2021222324252627UL ]

  /// <summary>
  /// 7c62011e, sce v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SCE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x7299521e821a027bUL
        M 0x20200080UL, 0xc868520ac964979dUL
        M 0x20200088UL, 0x6748bf6d8167f553UL ]
    given0
    |> run r2 [ "7c62011e" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x96e85f6637616550UL
        M 0x20200080UL, 0x6e2d47e377443887UL
        M 0x20200088UL, 0x2b71fcefe728cfccUL ]
    given1
    |> run r2 [ "7c62011e" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x75683761cb124365UL
        M 0x20200080UL, 0x845d6f7f97e43d12UL
        M 0x20200088UL, 0xf1c02b5118cfce06UL ]
    given2
    |> run r2 [ "7c62011e" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c242876 7c221866, llwp a0, a1, (at) then scwp v0, v1, (at). The store
  /// writes the low word of rd and the low word of rt as one doubleword, rd's
  /// the more significant, and sets rt to one; on a big-endian processor the
  /// more significant word is the one at the lower address.
  /// No reference runs it: QEMU's I6400 reads the word as an unpaired
  /// SC. Checked against the manual's Operation instead.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SCWP``() =
    let given =
      [ G 1, 0x20200080UL
        G 2, 0xa0a1a2a3UL
        G 3, 0xb0b1b2b3UL
        M 0x20200080UL, 0x1011121314151617UL ]
    given
    |> run r6 [ "7c242876"; "7c221866" ]
    |> is
      [ G 2, 0x1UL
        G 4, 0x14151617UL
        G 5, 0x10111213UL
        M 0x20200080UL, 0xb0b1b2b3a0a1a2a3UL ]

  /// <summary>
  /// 7c22185e, scwpe v0, v1, 0(at), against QEMU's I6400, a Release 6
  /// processor: QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SCWPE``() =
    let given0 =
      [ G 1, 0x20200080UL
        G 2, 0x7UL
        G 3, 0x3UL
        Status, 0x10UL
        M 0x20200078UL, 0x66fd55de177d9fb9UL
        M 0x20200080UL, 0xfd0966bc5bea070fUL
        M 0x20200088UL, 0x794aaacfe0b9eed4UL ]
    given0
    |> run r6 [ "7c22185e" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 1, 0x20200080UL
        G 2, 0x7fffffffUL
        G 3, 0x1UL
        Status, 0x10UL
        M 0x20200078UL, 0x74c2731354eeed9UL
        M 0x20200080UL, 0xebf4d770116c3a57UL
        M 0x20200088UL, 0x50a05b4ce1fe083eUL ]
    given1
    |> run r6 [ "7c22185e" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 1, 0x20200080UL
        G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        Status, 0x10UL
        M 0x20200078UL, 0x7553df5179d9424bUL
        M 0x20200080UL, 0x83a7933a9bb3ab13UL
        M 0x20200088UL, 0x3b0aa399a0d065d6UL ]
    given2
    |> run r6 [ "7c22185e" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// fc620001, sd v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SD``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x75578e48c31d4fc1UL
        M 0x20200080UL, 0x80abb8f30f69345cUL
        M 0x20200088UL, 0x515fd29a7857c407UL ]
    given0
    |> run r2 [ "fc620001" ]
    |> is [ M 0x20200080UL, 0x7UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x83c2e05feb023459UL
        M 0x20200080UL, 0x165fb1314915fa6fUL
        M 0x20200088UL, 0xa58d18523b981e48UL ]
    given1
    |> run r2 [ "fc620001" ]
    |> is [ M 0x20200080UL, 0x7fffffffffffffffUL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x53ab91abe248f9a1UL
        M 0x20200080UL, 0xc0d26baa447a5dcbUL
        M 0x20200088UL, 0xba482a4a9b252509UL ]
    given2
    |> run r2 [ "fc620001" ]
    |> is [ M 0x20200080UL, 0x123456789abcdefUL ]

  /// <summary>
  /// 7000003f, sdbbp 0x0. Not run against QEMU, whose user mode aborts on the
  /// debug exception it raises; the manual enters the debug handler, which is
  /// this architecture's breakpoint. The lift raises Breakpoint and changes
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SDBBP``() =
    []
    |> run r2 [ "7000003f" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// f4420001, sdc1 f2, 1(v0), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SDC1``() =
    let given0 =
      [ G 2, 0x2020007fUL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xef968d83af9c3484UL
        M 0x20200080UL, 0x1fc3e93cb18ec245UL
        M 0x20200088UL, 0x463182c98d1f2313UL ]
    given0
    |> run r2 [ "f4420001" ]
    |> is [ M 0x20200080UL, 0xbff0000000000000UL ]
    let given1 =
      [ G 2, 0x2020007fUL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x61464052f28ffb99UL
        M 0x20200080UL, 0xb2c06c97ade16cf5UL
        M 0x20200088UL, 0x4c9f2312774f98cUL ]
    given1
    |> run r2 [ "f4420001" ]
    |> is [ M 0x20200080UL, 0x400c000000000000UL ]
    let given2 =
      [ G 2, 0x2020007fUL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x97414070316ce4bdUL
        M 0x20200080UL, 0x14c999d09e0a3d26UL
        M 0x20200088UL, 0x5c1a569ec322d15UL ]
    given2
    |> run r2 [ "f4420001" ]
    |> is [ M 0x20200080UL, 0x3fd0000000000000UL ]

  /// <summary>
  /// f8000000, sdc2 0x0, 0(r0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SDC2``() =
    let given0 =
      [ M 0x20200078UL, 0x8366d2174f6c376UL
        M 0x20200080UL, 0x8aba5204acf474beUL
        M 0x20200088UL, 0x3dfe93e9a2253931UL ]
    given0
    |> run r2 [ "f8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0x3d7d765d031abbcfUL
        M 0x20200080UL, 0x6847dc520fc5c2d6UL
        M 0x20200088UL, 0x580ba0c2a3353f5cUL ]
    given1
    |> run r2 [ "f8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0x6908ce823ca4ae52UL
        M 0x20200080UL, 0x6a5d2a28c3bd8a52UL
        M 0x20200088UL, 0xce5e86ad6917fd0fUL ]
    given2
    |> run r2 [ "f8000000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// b0620001, sdl v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SDL``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0xaa57e9c0106410caUL
        M 0x20200080UL, 0x50ffaa8a7c92d440UL
        M 0x20200088UL, 0x24be0786506911bfUL ]
    given0
    |> run r2 [ "b0620001" ]
    |> is [ M 0x20200080UL, 0x5000000000000000UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0xf1a6593ff43043a5UL
        M 0x20200080UL, 0xce50417cbf2d5759UL
        M 0x20200088UL, 0xd27aa2f8096eb0abUL ]
    given1
    |> run r2 [ "b0620001" ]
    |> is [ M 0x20200080UL, 0xce507fffffffffffUL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0x7a1e2baa67d4bdc6UL
        M 0x20200080UL, 0x13e461ebc6a3739eUL
        M 0x20200088UL, 0xb206dfa00b46cab0UL ]
    given2
    |> run r2 [ "b0620001" ]
    |> is [ M 0x20200080UL, 0x13e461ebc6012345UL ]

  /// <summary>
  /// b4620001, sdr v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SDR``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0xb49326878a92e2c7UL
        M 0x20200080UL, 0x83fbe15c0d7ca353UL
        M 0x20200088UL, 0xbad43ac67f87f418UL ]
    given0
    |> run r2 [ "b4620001" ]
    |> is [ M 0x20200080UL, 0x7e15c0d7ca353UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0x81a274bc54a3f28eUL
        M 0x20200080UL, 0xf31957fc208e8d63UL
        M 0x20200088UL, 0x9a7eda58885c5f51UL ]
    given1
    |> run r2 [ "b4620001" ]
    |> is [ M 0x20200080UL, 0xfffffffc208e8d63UL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0x77d462a9a34ed599UL
        M 0x20200080UL, 0xbde5a53c115aa072UL
        M 0x20200088UL, 0x837ae491ccdf0244UL ]
    given2
    |> run r2 [ "b4620001" ]
    |> is [ M 0x20200080UL, 0x456789abcdefa072UL ]

  /// <summary>
  /// 4c431009, sdxc1 f2, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SDXC1``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xc51df20395e59328UL
        M 0x20200080UL, 0x91c9597defa5c176UL
        M 0x20200088UL, 0x374c17702d2c430eUL ]
    given0
    |> run r2 [ "4c431009" ]
    |> is [ M 0x20200080UL, 0xbff0000000000000UL ]
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x6adb904476411efUL
        M 0x20200080UL, 0x421b9052990b7aa6UL
        M 0x20200088UL, 0xfc48bb2c5184e1acUL ]
    given1
    |> run r2 [ "4c431009" ]
    |> is [ M 0x20200080UL, 0x400c000000000000UL ]
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x4190349898ae19aaUL
        M 0x20200080UL, 0xe435c71caf15d8a2UL
        M 0x20200088UL, 0x7ccaa2bf3e652695UL ]
    given2
    |> run r2 [ "4c431009" ]
    |> is [ M 0x20200080UL, 0x3fd0000000000000UL ]

  /// <summary>
  /// 7c021420, seb v0, v0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SEB``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "7c021420" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "7c021420" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "7c021420" ]
    |> is [ G 2, 0xffffffffffffffefUL ]

  /// <summary>
  /// 7c021620, seh v0, v0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SEH``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "7c021620" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "7c021620" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "7c021620" ]
    |> is [ G 2, 0xffffffffffffcdefUL ]

  /// <summary>
  /// 46062090, sel.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SEL.fmt``() =
    [ F 2, 0x3f800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062090" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x3f800001UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062090" ]
    |> is [ F 2, 0x3f400000UL ]
    [ F 2, 0x1UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062090" ]
    |> is [ F 2, 0x3e000000UL ]

  /// <summary>
  /// 00641035, seleqz v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SELEQZ``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "00641035" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "00641035" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "00641035" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r6 [ "00641035" ]
    |> is [ G 2, 0x3UL ]

  /// <summary>
  /// 46062094, seleqz.s f2, f4, f6, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SELEQZ.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062094" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x1UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062094" ]
    |> is [ F 2, 0x0UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3f800000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062094" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 46011817, selneqz.s f0, f3, f1, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SELNEQZ.fmt``() =
    [ F 0, 0xbf800000UL; F 3, 0x40100000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46011817" ]
    |> is [ F 0, 0x0UL ]
    [ F 0, 0x40600000UL; F 1, 0x1UL; F 3, 0xc0c00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46011817" ]
    |> is [ F 0, 0xc0c00000UL ]
    [ F 0, 0x3e800000UL; F 1, 0x3f800000UL; F 3, 0x447a0000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46011817" ]
    |> is [ F 0, 0x0UL ]

  /// <summary>
  /// 00641037, selnez v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SELNEZ``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "00641037" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "00641037" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "00641037" ]
    |> is [ G 2, 0x12345678UL ]
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r6 [ "00641037" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// a4620001, sh v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SH``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xf7a3e9b84caece6aUL
        M 0x20200080UL, 0x7026a551307b994fUL
        M 0x20200088UL, 0xd0e0487dae34b36dUL ]
    given0
    |> run r2 [ "a4620001" ]
    |> is [ M 0x20200080UL, 0x7a551307b994fUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xf60363b29582716UL
        M 0x20200080UL, 0x11ae03d72408101eUL
        M 0x20200088UL, 0x89d8be1f34323501UL ]
    given1
    |> run r2 [ "a4620001" ]
    |> is [ M 0x20200080UL, 0xffff03d72408101eUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xb9b8145ef8ce8971UL
        M 0x20200080UL, 0xf574a5b7b1b4a61UL
        M 0x20200088UL, 0xe55e28df756496e5UL ]
    given2
    |> run r2 [ "a4620001" ]
    |> is [ M 0x20200080UL, 0xcdef4a5b7b1b4a61UL ]

  /// <summary>
  /// 7c62011d, she v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SHE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x883ad4bbf8dd0eacUL
        M 0x20200080UL, 0x740c795f70a56940UL
        M 0x20200088UL, 0x72b7874095ee513dUL ]
    given0
    |> run r2 [ "7c62011d" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x74e37124bd8f191aUL
        M 0x20200080UL, 0x7292a53dcd242014UL
        M 0x20200088UL, 0xc0177ac4e0739c54UL ]
    given1
    |> run r2 [ "7c62011d" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x6715dbe58180891eUL
        M 0x20200080UL, 0xe7ec614440a394a6UL
        M 0x20200088UL, 0xf4e5e6e429df1559UL ]
    given2
    |> run r2 [ "7c62011d" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 04170001, sigrie 0x1, against QEMU's I6400, a Release 6 processor: QEMU
  /// raised SIGILL (UndefinedInstruction here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SIGRIE``() =
    []
    |> run r6 [ "04170001" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run r6 [ "04170001" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run r6 [ "04170001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00031100, sll v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SLL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00031100" ]
    |> is [ G 2, 0x30UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00031100" ]
    |> is [ G 2, 0x10UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00031100" ]
    |> is [ G 2, 0x23456780UL ]

  /// <summary>
  /// 00831004, sllv v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SLLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831004" ]
    |> is [ G 2, 0x60UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831004" ]
    |> is [ G 2, 0x40000000UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00831004" ]
    |> is [ G 2, 0x78000000UL ]

  /// <summary>
  /// 0064102a, slt v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SLT``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102a" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064102a" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "0064102a" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x2UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102a" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 28620100, slti v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SLTI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "28620100" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "28620100" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "28620100" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x2UL; G 3, 0x3UL ]
    |> run r2 [ "28620100" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 2c620100, sltiu v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SLTIU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "2c620100" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "2c620100" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "2c620100" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x2UL; G 3, 0x3UL ]
    |> run r2 [ "2c620100" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 0064102b, sltu v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SLTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102b" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064102b" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "0064102b" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x2UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102b" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 46002084, sqrt.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SQRT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46002084" ]
    |> is [ F 2, 0x3fc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0x41800000UL ]
    |> run r2 [ "46002084" ]
    |> is [ F 2, 0x40800000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x3d800000UL ]
    |> run r2 [ "46002084" ]
    |> is []

  /// <summary>
  /// 00031103, sra v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SRA``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00031103" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00031103" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00031103" ]
    |> is [ G 2, 0x1234567UL ]

  /// <summary>
  /// 00831007, srav v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SRAV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831007" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831007" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00831007" ]
    |> is [ G 2, 0x12UL ]

  /// <summary>
  /// 00031102, srl v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SRL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00031102" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00031102" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00031102" ]
    |> is [ G 2, 0x1234567UL ]

  /// <summary>
  /// 00831006, srlv v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SRLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831006" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831006" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00831006" ]
    |> is [ G 2, 0x12UL ]

  /// <summary>
  /// 00000040, ssnop, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SSNOP``() =
    []
    |> run r2 [ "00000040" ]
    |> is []
    []
    |> run r2 [ "00000040" ]
    |> is []
    []
    |> run r2 [ "00000040" ]
    |> is []

  /// <summary>
  /// 00641022, sub v0, v1, a0, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGFPE (Exception IntegerOverflow here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SUB``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641022" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641022" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641022" ]
    |> is [ G 2, 0x13579be0UL ]
    [ G 2, 0x7UL; G 3, 0xffffffff80000000UL; G 4, 0x1UL ]
    |> run r2 [ "00641022" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 46062081, sub.s f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SUB.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run r2 [ "46062081" ]
    |> is [ F 2, 0x3f400000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run r2 [ "46062081" ]
    |> is [ F 2, 0xc0d80000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run r2 [ "46062081" ]
    |> is [ F 2, 0x4479f800UL ]

  /// <summary>
  /// 00641023, subu v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SUBU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641023" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641023" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641023" ]
    |> is [ G 2, 0x13579be0UL ]

  /// <summary>
  /// 4c43100d, suxc1 f2, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SUXC1``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0x249ffb6d55382050UL
        M 0x20200080UL, 0xbdb3ed06adeb396bUL
        M 0x20200088UL, 0xd8ddc60d20cddb62UL ]
    given0
    |> run r2 [ "4c43100d" ]
    |> is [ M 0x20200080UL, 0xbff0000000000000UL ]
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0xda4cc6e6e859fb9dUL
        M 0x20200080UL, 0xe8df6f0738dc6b18UL
        M 0x20200088UL, 0xf77cef6d23f871f6UL ]
    given1
    |> run r2 [ "4c43100d" ]
    |> is [ M 0x20200080UL, 0x400c000000000000UL ]
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x80226bf10c877263UL
        M 0x20200080UL, 0x26d014cf8036b19aUL
        M 0x20200088UL, 0x60a52ccdd2c1137aUL ]
    given2
    |> run r2 [ "4c43100d" ]
    |> is [ M 0x20200080UL, 0x3fd0000000000000UL ]

  /// <summary>
  /// ac620001, sw v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SW``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xe0e12b6e04d3e1f0UL
        M 0x20200080UL, 0xe78bfacd75ab29a6UL
        M 0x20200088UL, 0xeeedc31f62ad6498UL ]
    given0
    |> run r2 [ "ac620001" ]
    |> is [ M 0x20200080UL, 0x775ab29a6UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x414e219037f4d1d4UL
        M 0x20200080UL, 0xb5bf17f8be356e7aUL
        M 0x20200088UL, 0x37b96f2e617e1821UL ]
    given1
    |> run r2 [ "ac620001" ]
    |> is [ M 0x20200080UL, 0x7fffffffbe356e7aUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x3c70d7a613f076d5UL
        M 0x20200080UL, 0xa97f310c9389e721UL
        M 0x20200088UL, 0xb8b7653822dbc228UL ]
    given2
    |> run r2 [ "ac620001" ]
    |> is [ M 0x20200080UL, 0x89abcdef9389e721UL ]

  /// <summary>
  /// e4420001, swc1 f2, 1(v0), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWC1``() =
    let given0 =
      [ G 2, 0x2020007fUL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0x592e5e9659b476e1UL
        M 0x20200080UL, 0x426a5b9489287d5aUL
        M 0x20200088UL, 0xd9072cd65b8d2c07UL ]
    given0
    |> run r2 [ "e4420001" ]
    |> is [ M 0x20200080UL, 0xbf80000089287d5aUL ]
    let given1 =
      [ G 2, 0x2020007fUL
        F 2, 0x40600000UL
        M 0x20200078UL, 0x717fa72374fba68dUL
        M 0x20200080UL, 0x55ccac50c2e72e74UL
        M 0x20200088UL, 0xc7d2537155fa1b56UL ]
    given1
    |> run r2 [ "e4420001" ]
    |> is [ M 0x20200080UL, 0x40600000c2e72e74UL ]
    let given2 =
      [ G 2, 0x2020007fUL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0xce11a24fc5d85a0fUL
        M 0x20200080UL, 0x419bd17d1a82ac1aUL
        M 0x20200088UL, 0x15e764559fb97d90UL ]
    given2
    |> run r2 [ "e4420001" ]
    |> is [ M 0x20200080UL, 0x3e8000001a82ac1aUL ]

  /// <summary>
  /// e8000000, swc2 0x0, 0(r0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWC2``() =
    let given0 =
      [ M 0x20200078UL, 0x26446f39a36fa505UL
        M 0x20200080UL, 0x4010b61daeed3ff5UL
        M 0x20200088UL, 0x1eaf992ac8dae8c0UL ]
    given0
    |> run r2 [ "e8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0xf6970766f76c7bcaUL
        M 0x20200080UL, 0xd5c4a31c0f4ef1c5UL
        M 0x20200088UL, 0x8d93345fb48241b1UL ]
    given1
    |> run r2 [ "e8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0xc86297ba2d4435f1UL
        M 0x20200080UL, 0x9ffa51c25915501bUL
        M 0x20200088UL, 0xc982b13d29f32306UL ]
    given2
    |> run r2 [ "e8000000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c62011f, swe v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x9455b0ebebc2d82UL
        M 0x20200080UL, 0xd4bba5d5d77f4ebfUL
        M 0x20200088UL, 0xa949f86eb619abd9UL ]
    given0
    |> run r2 [ "7c62011f" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x4c3087180c96bea0UL
        M 0x20200080UL, 0xe8ca5597957cacf0UL
        M 0x20200088UL, 0x74d3f468a7c1f03dUL ]
    given1
    |> run r2 [ "7c62011f" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x87bcfb907980cfedUL
        M 0x20200080UL, 0x8f3d6f1347e862d1UL
        M 0x20200088UL, 0x931ef5ea49172e91UL ]
    given2
    |> run r2 [ "7c62011f" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// a8620001, swl v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWL``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0xad8cedb51c91fab0UL
        M 0x20200080UL, 0xf1b06cc94adfbac4UL
        M 0x20200088UL, 0x397e0b8cd93cc38aUL ]
    given0
    |> run r2 [ "a8620001" ]
    |> is [ M 0x20200080UL, 0xf10000004adfbac4UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0xe6e3e5ff91b5b7bUL
        M 0x20200080UL, 0x54cd0d8dd36de91dUL
        M 0x20200088UL, 0xaae22dc75359c3a0UL ]
    given1
    |> run r2 [ "a8620001" ]
    |> is [ M 0x20200080UL, 0x54cd7fffd36de91dUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0xda9ebf63cb75d67dUL
        M 0x20200080UL, 0xad0e4b2a56d808f5UL
        M 0x20200088UL, 0x972108dd1ae5f563UL ]
    given2
    |> run r2 [ "a8620001" ]
    |> is [ M 0x20200080UL, 0xad0e4b2a5689abcdUL ]

  /// <summary>
  /// 7c620121, swle v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWLE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x1f05a20329bdc6f6UL
        M 0x20200080UL, 0xc70d42343d97352dUL
        M 0x20200088UL, 0x1e9bdad7e5e89149UL ]
    given0
    |> run r2 [ "7c620121" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0x4db76ead2fa42c39UL
        M 0x20200080UL, 0x6778f07c754e7c6dUL
        M 0x20200088UL, 0x41d7861dd0a2a670UL ]
    given1
    |> run r2 [ "7c620121" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200083UL
        Status, 0x10UL
        M 0x20200078UL, 0x9012013a89af9cb2UL
        M 0x20200080UL, 0xd5847994ceab9b7eUL
        M 0x20200088UL, 0x5d282b163d1fd92cUL ]
    given2
    |> run r2 [ "7c620121" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// b8620001, swr v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWR``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0x2827c0dc5e9a4f22UL
        M 0x20200080UL, 0x94f84263e4988f90UL
        M 0x20200088UL, 0x2e7f7390ce1e6ef8UL ]
    given0
    |> run r2 [ "b8620001" ]
    |> is [ M 0x20200080UL, 0x74263e4988f90UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0xf2bd2dcca1a2f71fUL
        M 0x20200080UL, 0x91100447a045f37aUL
        M 0x20200088UL, 0x2b82e47a88ba11a4UL ]
    given1
    |> run r2 [ "b8620001" ]
    |> is [ M 0x20200080UL, 0xffffff47a045f37aUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0x36ad5112091226efUL
        M 0x20200080UL, 0x8a450f7695b4d8ffUL
        M 0x20200088UL, 0xb6748cba1952e385UL ]
    given2
    |> run r2 [ "b8620001" ]
    |> is [ M 0x20200080UL, 0x8a450f76cdefd8ffUL ]

  /// <summary>
  /// 7c620122, swre v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWRE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xd8a576bdf4e91c5fUL
        M 0x20200080UL, 0x5740186ebfd928dUL
        M 0x20200088UL, 0xbde0d9c94818dfbeUL ]
    given0
    |> run r2 [ "7c620122" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0xf33b5075f57912c5UL
        M 0x20200080UL, 0x34384d22c440308bUL
        M 0x20200088UL, 0x1130556f3ee6fc4cUL ]
    given1
    |> run r2 [ "7c620122" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200083UL
        Status, 0x10UL
        M 0x20200078UL, 0x597a1bb5a4eb3802UL
        M 0x20200080UL, 0x2e656b0ccf0d4c4fUL
        M 0x20200088UL, 0x391823a9f4b607d7UL ]
    given2
    |> run r2 [ "7c620122" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4c431008, swxc1 f2, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SWXC1``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0x71178933329394acUL
        M 0x20200080UL, 0xffca40cdd4877733UL
        M 0x20200088UL, 0x172b6ef2a4368b08UL ]
    given0
    |> run r2 [ "4c431008" ]
    |> is [ M 0x20200080UL, 0xbf800000d4877733UL ]
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x40600000UL
        M 0x20200078UL, 0xae2f71f974d55e09UL
        M 0x20200080UL, 0xeb4ca4e722ee403fUL
        M 0x20200088UL, 0x662de2490aacaa43UL ]
    given1
    |> run r2 [ "4c431008" ]
    |> is [ M 0x20200080UL, 0x4060000022ee403fUL ]
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0x1cdff8f3a112f919UL
        M 0x20200080UL, 0x9495c7f750cf77caUL
        M 0x20200088UL, 0x509d1efdefd40765UL ]
    given2
    |> run r2 [ "4c431008" ]
    |> is [ M 0x20200080UL, 0x3e80000050cf77caUL ]

  /// <summary>
  /// 0000000f, sync 0x0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SYNC``() =
    []
    |> run r2 [ "0000000f" ]
    |> is []
    []
    |> run r2 [ "0000000f" ]
    |> is []
    []
    |> run r2 [ "0000000f" ]
    |> is []

  /// <summary>
  /// 045f0001, synci 1(v0), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SYNCI``() =
    let given0 =
      [ G 2, 0x2020007fUL
        M 0x20200078UL, 0xe15ed567d9966b43UL
        M 0x20200080UL, 0xb1eba2f02e2b6ba2UL
        M 0x20200088UL, 0x7b92ae28f301f824UL ]
    given0
    |> run r2 [ "045f0001" ]
    |> is []
    let given1 =
      [ G 2, 0x2020007fUL
        M 0x20200078UL, 0x503fefde6d7cfaf8UL
        M 0x20200080UL, 0xda475da259b62e7cUL
        M 0x20200088UL, 0x3e248080d8736424UL ]
    given1
    |> run r2 [ "045f0001" ]
    |> is []
    let given2 =
      [ G 2, 0x2020007fUL
        M 0x20200078UL, 0x7665605f94c4cd9dUL
        M 0x20200080UL, 0xb2be774364ad5117UL
        M 0x20200088UL, 0x25837d930a0571f1UL ]
    given2
    |> run r2 [ "045f0001" ]
    |> is []

  /// <summary>
  /// 0000000c, syscall. Not run against QEMU, where a system call is the host
  /// kernel answering rather than the instruction. The lift raises SysCall and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 SYSCALL``() =
    []
    |> run r2 [ "0000000c" ]
    |> raises [ SysCall ] []

  /// <summary>
  /// 00430034, teq v0, v1, against QEMU's MIPS64R2-generic: QEMU raised SIGTRAP
  /// (Interrupt 13 here); the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TEQ``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430034" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430034" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430034" ]
    |> is []
    [ G 2, 0x7UL; G 3, 0x7UL ]
    |> run r2 [ "00430034" ]
    |> raises [ Interrupt 13 ] []
    [ G 3, 0x1UL ]
    |> run r2 [ "00430034" ]
    |> is []

  /// <summary>
  /// 044c1900, teqi v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TEQI``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "044c1900" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "044c1900" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "044c1900" ]
    |> is []
    [ G 2, 0x1900UL ]
    |> run r2 [ "044c1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x18ffUL ]
    |> run r2 [ "044c1900" ]
    |> is []

  /// <summary>
  /// 00430030, tge v0, v1, against QEMU's MIPS64R2-generic: QEMU raised SIGTRAP
  /// (Interrupt 13 here); the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TGE``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430030" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430030" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430030" ]
    |> is []
    [ G 2, 0x7UL; G 3, 0x7UL ]
    |> run r2 [ "00430030" ]
    |> raises [ Interrupt 13 ] []
    [ G 3, 0x1UL ]
    |> run r2 [ "00430030" ]
    |> is []

  /// <summary>
  /// 04481900, tgei v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TGEI``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "04481900" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "04481900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "04481900" ]
    |> is []
    [ G 2, 0x1900UL ]
    |> run r2 [ "04481900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x18ffUL ]
    |> run r2 [ "04481900" ]
    |> is []

  /// <summary>
  /// 04491900, tgeiu v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TGEIU``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "04491900" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "04491900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "04491900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x1900UL ]
    |> run r2 [ "04491900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x18ffUL ]
    |> run r2 [ "04491900" ]
    |> is []

  /// <summary>
  /// 00430031, tgeu v0, v1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TGEU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430031" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430031" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430031" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7UL; G 3, 0x7UL ]
    |> run r2 [ "00430031" ]
    |> raises [ Interrupt 13 ] []
    [ G 3, 0x1UL ]
    |> run r2 [ "00430031" ]
    |> is []

  /// <summary>
  /// 42000003, tlbinv, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLBINV``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000003" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000003" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000003" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000004, tlbinvf, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLBINVF``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000004" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000004" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000004" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000008, tlbp, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLBP``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000008" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000008" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000008" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000001, tlbr, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLBR``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000002, tlbwi, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLBWI``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000002" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000002" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000002" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000006, tlbwr, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLBWR``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000006" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000006" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000006" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00430032, tlt v0, v1, against QEMU's MIPS64R2-generic: QEMU raised SIGTRAP
  /// (Interrupt 13 here); the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430032" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430032" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430032" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7UL; G 3, 0x7UL ]
    |> run r2 [ "00430032" ]
    |> is []
    [ G 3, 0x1UL ]
    |> run r2 [ "00430032" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 044a1900, tlti v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLTI``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "044a1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "044a1900" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "044a1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x1900UL ]
    |> run r2 [ "044a1900" ]
    |> is []
    [ G 2, 0x18ffUL ]
    |> run r2 [ "044a1900" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 044b1900, tltiu v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLTIU``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "044b1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "044b1900" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "044b1900" ]
    |> is []
    [ G 2, 0x1900UL ]
    |> run r2 [ "044b1900" ]
    |> is []
    [ G 2, 0x18ffUL ]
    |> run r2 [ "044b1900" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 00430033, tltu v0, v1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TLTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430033" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430033" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430033" ]
    |> is []
    [ G 2, 0x7UL; G 3, 0x7UL ]
    |> run r2 [ "00430033" ]
    |> is []
    [ G 3, 0x1UL ]
    |> run r2 [ "00430033" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 00430036, tne v0, v1, against QEMU's MIPS64R2-generic: QEMU raised SIGTRAP
  /// (Interrupt 13 here); the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TNE``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00430036" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00430036" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "00430036" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7UL; G 3, 0x7UL ]
    |> run r2 [ "00430036" ]
    |> is []
    [ G 3, 0x1UL ]
    |> run r2 [ "00430036" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 044e1900, tnei v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGTRAP (Interrupt 13 here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TNEI``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "044e1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "044e1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "044e1900" ]
    |> raises [ Interrupt 13 ] []
    [ G 2, 0x1900UL ]
    |> run r2 [ "044e1900" ]
    |> is []
    [ G 2, 0x18ffUL ]
    |> run r2 [ "044e1900" ]
    |> raises [ Interrupt 13 ] []

  /// <summary>
  /// 46002089, trunc.l.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TRUNC.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "46002089" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "46002089" ]
    |> is [ F 2, 0xffffffffffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "46002089" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 4600208d, trunc.w.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 TRUNC.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "4600208d" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "4600208d" ]
    |> is [ F 2, 0xffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "4600208d" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 42000020, wait, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 WAIT``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000020" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000020" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000020" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 41c31000, wrpgpr v0, v1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 WRPGPR``() =
    [ G 2, 0x7UL; G 3, 0x3UL; Status, 0x10UL ]
    |> run r2 [ "41c31000" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; Status, 0x10UL ]
    |> run r2 [ "41c31000" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; Status, 0x10UL ]
    |> run r2 [ "41c31000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c0210a0, wsbh v0, v0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 WSBH``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "7c0210a0" ]
    |> is [ G 2, 0x700UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "7c0210a0" ]
    |> is [ G 2, 0xffffffffff7fffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "7c0210a0" ]
    |> is [ G 2, 0xffffffffab89efcdUL ]

  /// <summary>
  /// 00641026, xor v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 XOR``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641026" ]
    |> is [ G 2, 0x6UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641026" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641026" ]
    |> is [ G 2, 0xffffffffece8ece0UL ]

  /// <summary>
  /// 38620100, xori v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 XORI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "38620100" ]
    |> is [ G 2, 0x103UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "38620100" ]
    |> is [ G 2, 0x101UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "38620100" ]
    |> is [ G 2, 0x12345778UL ]
