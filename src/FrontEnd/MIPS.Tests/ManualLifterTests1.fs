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
/// One test for each instruction of MD00087: ABS.fmt to DINSM.
///
/// <para>A value test runs a word of the instruction under QEMU over a few
/// sets of register values, memory and FCSR, and has the lift change what
/// QEMU changed, raise what QEMU raised, and nothing else; every value it
/// expects is QEMU's (optest-mips/oracle). A structural test says in its own
/// comment what it checks and why no value test could be had.</para>
/// </summary>
[<TestClass>]
type ManualLifterTests1() =
  let r2 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)

  let r6 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)

  /// <summary>
  /// 46002085, abs.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ABS.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46002085" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run r2 [ "46002085" ]
    |> is [ F 2, 0x40c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run r2 [ "46002085" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 00641020, add v0, v1, a0, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGFPE (Exception IntegerOverflow here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ADD``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641020" ]
    |> is [ G 2, 0x8UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641020" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641020" ]
    |> is [ G 2, 0x11111110UL ]
    [ G 2, 0x7UL; G 3, 0x7fffffffUL; G 4, 0x1UL ]
    |> run r2 [ "00641020" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 46062080, add.s f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ADD.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run r2 [ "46062080" ]
    |> is [ F 2, 0x40700000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run r2 [ "46062080" ]
    |> is [ F 2, 0xc0a80000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run r2 [ "46062080" ]
    |> is [ F 2, 0x447a0800UL ]

  /// <summary>
  /// 20620100, addi v0, v1, 0x100, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGFPE (Exception IntegerOverflow here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ADDI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "20620100" ]
    |> is [ G 2, 0x103UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "20620100" ]
    |> is [ G 2, 0x101UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "20620100" ]
    |> is [ G 2, 0x12345778UL ]
    [ G 2, 0x7UL; G 3, 0x7fffffffUL ]
    |> run r2 [ "20620100" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 24620100, addiu v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ADDIU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "24620100" ]
    |> is [ G 2, 0x103UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "24620100" ]
    |> is [ G 2, 0x101UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "24620100" ]
    |> is [ G 2, 0x12345778UL ]

  /// <summary>
  /// ec400001, addiupc v0, 0x20100004, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ADDIUPC``() =
    [ G 2, 0x7UL ]
    |> run r6 [ "ec400001" ]
    |> is [ G 2, 0x20100004UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r6 [ "ec400001" ]
    |> is [ G 2, 0x20100004UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r6 [ "ec400001" ]
    |> is [ G 2, 0x20100004UL ]

  /// <summary>
  /// 00641021, addu v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ADDU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641021" ]
    |> is [ G 2, 0x8UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641021" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641021" ]
    |> is [ G 2, 0x11111110UL ]

  /// <summary>
  /// 7c641260, align v0, v1, a0, 0x1, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ALIGN``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "7c641260" ]
    |> is [ G 2, 0x500UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "7c641260" ]
    |> is [ G 2, 0xfffffffffffffe00UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "7c641260" ]
    |> is [ G 2, 0xffffffffdcba9812UL ]

  /// <summary>
  /// 4c46209e, alnv.ps f2, f4, f6, v0, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ALNV.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run r2 [ "4c46209e" ]
    |> is [ F 2, 0x40100000bfc00000UL ]
    let given1 =
      [ G 2, 0x4UL
        F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run r2 [ "4c46209e" ]
    |> is [ F 2, 0x3f0000003f400000UL ]
    let given2 =
      [ G 2, 0x4UL
        F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run r2 [ "4c46209e" ]
    |> is [ F 2, 0x404000003e000000UL ]

  /// <summary>
  /// ec5f1900, aluipc v0, 0x1900, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ALUIPC``() =
    [ G 2, 0x7UL ]
    |> run r6 [ "ec5f1900" ]
    |> is [ G 2, 0x39100000UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r6 [ "ec5f1900" ]
    |> is [ G 2, 0x39100000UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r6 [ "ec5f1900" ]
    |> is [ G 2, 0x39100000UL ]

  /// <summary>
  /// 00641024, and v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 AND``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00641024" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00641024" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "00641024" ]
    |> is [ G 2, 0x12141218UL ]

  /// <summary>
  /// 30620100, andi v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ANDI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "30620100" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "30620100" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "30620100" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 3c620100, aui v0, v1, 0x100, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 AUI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r6 [ "3c620100" ]
    |> is [ G 2, 0x1000003UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r6 [ "3c620100" ]
    |> is [ G 2, 0x1000001UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r6 [ "3c620100" ]
    |> is [ G 2, 0x13345678UL ]

  /// <summary>
  /// ec5e1900, auipc v0, 0x1900, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 AUIPC``() =
    [ G 2, 0x7UL ]
    |> run r6 [ "ec5e1900" ]
    |> is [ G 2, 0x39100000UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r6 [ "ec5e1900" ]
    |> is [ G 2, 0x39100000UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r6 [ "ec5e1900" ]
    |> is [ G 2, 0x39100000UL ]

  /// <summary>
  /// 10000100, b 0x20100404 (binutils: b 20100404). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20100404 (the target
  /// binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 B``() =
    let words = [ "10000100"; "00000000" ]
    ownsJump r2 "10000100" false
    goes r2 words [] 0x20100404UL

  /// <summary>
  /// 04110100, bal 0x20100404 (binutils: bal 20100404). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when it always does; ra becomes
  /// 0x20100008 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BAL``() =
    let words = [ "04110100"; "00000000" ]
    ownsJump r2 "04110100" false
    goes r2 words [] 0x20100404UL
    []
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// e8000100, balc 0x20100404 (binutils: balc 20100404). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when it always does; ra becomes
  /// 0x20100004 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BALC``() =
    let words = [ "e8000100" ]
    ownsJump r6 "e8000100" true
    goes r6 words [] 0x20100404UL
    []
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// c8000100, bc 0x20100404 (binutils: bc 20100404). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC``() =
    let words = [ "c8000100" ]
    ownsJump r6 "c8000100" true
    goes r6 words [] 0x20100404UL

  /// <summary>
  /// 45200100, bc1eqz f0, 0x20100404 (binutils: bc1eqz $f0,20100404). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when it always does; to 0x20100008,
  /// past the slot, when F 0 is 0x1.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC1EQZ``() =
    let words = [ "45200100"; "00000000" ]
    ownsJump r6 "45200100" false
    goes r6 words [] 0x20100404UL
    goes r6 words [ F 0, 0x1UL ] 0x20100008UL

  /// <summary>
  /// 45000100, bc1f 0x20100404 (binutils: bc1f 20100404). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when it always does; to 0x20100008,
  /// past the slot, when Fcsr is 0x800000.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC1F``() =
    let words = [ "45000100"; "00000000" ]
    ownsJump r2 "45000100" false
    goes r2 words [] 0x20100404UL
    goes r2 words [ Fcsr, 0x800000UL ] 0x20100008UL

  /// <summary>
  /// 45021901, bc1fl 0x20106408 (binutils: bc1fl 20106408). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: control
  /// goes to 0x20106408 (the target binutils reads) when it always does; to
  /// 0x20100008, past the slot, when Fcsr is 0x800000.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC1FL``() =
    let words = [ "45021901"; "00000000" ]
    goes r2 words [] 0x20106408UL
    goes r2 words [ Fcsr, 0x800000UL ] 0x20100008UL

  /// <summary>
  /// 45a00100, bc1nez f0, 0x20100404 (binutils: bc1nez $f0,20100404). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when F 0 is 0x1; to 0x20100008,
  /// past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC1NEZ``() =
    let words = [ "45a00100"; "00000000" ]
    ownsJump r6 "45a00100" false
    goes r6 words [ F 0, 0x1UL ] 0x20100404UL
    goes r6 words [] 0x20100008UL

  /// <summary>
  /// 45011801, bc1t 0x20106008 (binutils: bc1t 20106008). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20106008 (the target binutils reads) when Fcsr is 0x800000; to
  /// 0x20100008, past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC1T``() =
    let words = [ "45011801"; "00000000" ]
    ownsJump r2 "45011801" false
    goes r2 words [ Fcsr, 0x800000UL ] 0x20106008UL
    goes r2 words [] 0x20100008UL

  /// <summary>
  /// 45031801, bc1tl 0x20106008 (binutils: bc1tl 20106008). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: control
  /// goes to 0x20106008 (the target binutils reads) when Fcsr is 0x800000; to
  /// 0x20100008, past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC1TL``() =
    let words = [ "45031801"; "00000000" ]
    goes r2 words [ Fcsr, 0x800000UL ] 0x20106008UL
    goes r2 words [] 0x20100008UL

  /// <summary>
  /// 49200000, bc2eqz 0x0, 0x20100004. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC2EQZ``() =
    []
    |> run r6 [ "49200000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 49000001, bc2f 0x20100008. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC2F``() =
    []
    |> run r2 [ "49000001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 49021901, bc2fl 0x20106408. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC2FL``() =
    []
    |> run r2 [ "49021901" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 49a00000, bc2nez 0x0, 0x20100004. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC2NEZ``() =
    []
    |> run r6 [ "49a00000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 49010004, bc2t 0x20100014. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC2T``() =
    []
    |> run r2 [ "49010004" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 49030002, bc2tl 0x2010000c. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BC2TL``() =
    []
    |> run r2 [ "49030002" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 10430101, beq v0, v1, 0x20100408 (binutils: beq $2,$3,20100408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100408 (the target binutils reads) when G 2 is 0x5 and G 3 is 0x5; to
  /// 0x20100008, past the slot, when G 2 is 0x5 and G 3 is 0x6.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BEQ``() =
    let words = [ "10430101"; "00000000" ]
    ownsJump r2 "10430101" false
    goes r2 words [ G 2, 0x5UL; G 3, 0x5UL ] 0x20100408UL
    goes r2 words [ G 2, 0x5UL; G 3, 0x6UL ] 0x20100008UL

  /// <summary>
  /// 20430101, beqc v0, v1, 0x20100408 (binutils: beqc $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20100408 (the target binutils reads) when G 2 is 0x5 and G 3 is 0x5;
  /// to 0x20100004, past the branch, when G 2 is 0x5 and G 3 is 0x6.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BEQC``() =
    let words = [ "20430101" ]
    ownsJump r6 "20430101" true
    goes r6 words [ G 2, 0x5UL; G 3, 0x5UL ] 0x20100408UL
    goes r6 words [ G 2, 0x5UL; G 3, 0x6UL ] 0x20100004UL

  /// <summary>
  /// 50430101, beql v0, v1, 0x20100408 (binutils: beql $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// control goes to 0x20100408 (the target binutils reads) when G 2 is 0x5 and
  /// G 3 is 0x5; to 0x20100008, past the slot, when G 2 is 0x5 and G 3 is 0x6.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BEQL``() =
    let words = [ "50430101"; "00000000" ]
    goes r2 words [ G 2, 0x5UL; G 3, 0x5UL ] 0x20100408UL
    goes r2 words [ G 2, 0x5UL; G 3, 0x6UL ] 0x20100008UL

  /// <summary>
  /// 20010100, beqzalc at, 0x20100404 (binutils: beqzalc $1,20100404). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when it always does; to 0x20100004,
  /// past the branch, when G 1 is 0x5; ra becomes 0x20100004 and nothing else
  /// changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BEQZALC``() =
    let words = [ "20010100" ]
    ownsJump r6 "20010100" true
    goes r6 words [] 0x20100404UL
    goes r6 words [ G 1, 0x5UL ] 0x20100004UL
    []
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// d8200100, beqzc at, 0x20100404 (binutils: beqzc $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when it always does; to 0x20100004,
  /// past the branch, when G 1 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BEQZC``() =
    let words = [ "d8200100" ]
    ownsJump r6 "d8200100" true
    goes r6 words [] 0x20100404UL
    goes r6 words [ G 1, 0x5UL ] 0x20100004UL

  /// <summary>
  /// 58430101, bgec v0, v1, 0x20100408 (binutils: bgec $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20100408 (the target binutils reads) when G 2 is 0x5 and G 3 is 0x3;
  /// to 0x20100004, past the branch, when G 2 is 0x3 and G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEC``() =
    let words = [ "58430101" ]
    ownsJump r6 "58430101" true
    goes r6 words [ G 2, 0x5UL; G 3, 0x3UL ] 0x20100408UL
    goes r6 words [ G 2, 0x3UL; G 3, 0x5UL ] 0x20100004UL

  /// <summary>
  /// 18430101, bgeuc v0, v1, 0x20100408 (binutils: bgeuc $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20100408 (the target binutils reads) when G 2 is 0xffffffffffffffff
  /// and G 3 is 0x3; to 0x20100004, past the branch, when G 2 is 0x3 and G 3 is
  /// 0xffffffffffffffff.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEUC``() =
    let words = [ "18430101" ]
    ownsJump r6 "18430101" true
    goes r6 words [ G 2, 0xffffffffffffffffUL; G 3, 0x3UL ] 0x20100408UL
    goes r6 words [ G 2, 0x3UL; G 3, 0xffffffffffffffffUL ] 0x20100004UL

  /// <summary>
  /// 04411901, bgez v0, 0x20106408 (binutils: bgez $2,20106408). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0x5; to 0x20100008,
  /// past the slot, when G 2 is 0xfffffffffffffffb.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEZ``() =
    let words = [ "04411901"; "00000000" ]
    ownsJump r2 "04411901" false
    goes r2 words [ G 2, 0x5UL ] 0x20106408UL
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20100008UL

  /// <summary>
  /// 04511901, bgezal v0, 0x20106408 (binutils: bgezal $2,20106408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0x5; to 0x20100008,
  /// past the slot, when G 2 is 0xfffffffffffffffb; ra becomes 0x20100008 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEZAL``() =
    let words = [ "04511901"; "00000000" ]
    ownsJump r2 "04511901" false
    goes r2 words [ G 2, 0x5UL ] 0x20106408UL
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20100008UL
    [ G 2, 0x5UL ]
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 18421901, bgezalc v0, 0x20106408 (binutils: bgezalc $2,20106408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0x5; to 0x20100004,
  /// past the branch, when G 2 is 0xfffffffffffffffb; ra becomes 0x20100004 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEZALC``() =
    let words = [ "18421901" ]
    ownsJump r6 "18421901" true
    goes r6 words [ G 2, 0x5UL ] 0x20106408UL
    goes r6 words [ G 2, 0xfffffffffffffffbUL ] 0x20100004UL
    [ G 2, 0x5UL ]
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// 04531901, bgezall v0, 0x20106408 (binutils: bgezall $2,20106408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual:
  /// control goes to 0x20106408 (the target binutils reads) when G 2 is 0x5; to
  /// 0x20100008, past the slot, when G 2 is 0xfffffffffffffffb; ra becomes
  /// 0x20100008 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEZALL``() =
    let words = [ "04531901"; "00000000" ]
    goes r2 words [ G 2, 0x5UL ] 0x20106408UL
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20100008UL
    [ G 2, 0x5UL ]
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 58421901, bgezc v0, 0x20106408 (binutils: bgezc $2,20106408). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0x5; to 0x20100004,
  /// past the branch, when G 2 is 0xfffffffffffffffb.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEZC``() =
    let words = [ "58421901" ]
    ownsJump r6 "58421901" true
    goes r6 words [ G 2, 0x5UL ] 0x20106408UL
    goes r6 words [ G 2, 0xfffffffffffffffbUL ] 0x20100004UL

  /// <summary>
  /// 04431901, bgezl v0, 0x20106408 (binutils: bgezl $2,20106408). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: control
  /// goes to 0x20106408 (the target binutils reads) when G 2 is 0x5; to
  /// 0x20100008, past the slot, when G 2 is 0xfffffffffffffffb.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGEZL``() =
    let words = [ "04431901"; "00000000" ]
    goes r2 words [ G 2, 0x5UL ] 0x20106408UL
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20100008UL

  /// <summary>
  /// 1c200100, bgtz at, 0x20100404 (binutils: bgtz $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0x5; to 0x20100008,
  /// past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGTZ``() =
    let words = [ "1c200100"; "00000000" ]
    ownsJump r2 "1c200100" false
    goes r2 words [ G 1, 0x5UL ] 0x20100404UL
    goes r2 words [] 0x20100008UL

  /// <summary>
  /// 1c010100, bgtzalc at, 0x20100404 (binutils: bgtzalc $1,20100404). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0x5; to 0x20100004,
  /// past the branch, when nothing is given; ra becomes 0x20100004 and nothing
  /// else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGTZALC``() =
    let words = [ "1c010100" ]
    ownsJump r6 "1c010100" true
    goes r6 words [ G 1, 0x5UL ] 0x20100404UL
    goes r6 words [] 0x20100004UL
    [ G 1, 0x5UL ]
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// 5c010100, bgtzc at, 0x20100404 (binutils: bgtzc $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0x5; to 0x20100004,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGTZC``() =
    let words = [ "5c010100" ]
    ownsJump r6 "5c010100" true
    goes r6 words [ G 1, 0x5UL ] 0x20100404UL
    goes r6 words [] 0x20100004UL

  /// <summary>
  /// 5c200100, bgtzl at, 0x20100404 (binutils: bgtzl $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: control
  /// goes to 0x20100404 (the target binutils reads) when G 1 is 0x5; to
  /// 0x20100008, past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BGTZL``() =
    let words = [ "5c200100"; "00000000" ]
    goes r2 words [ G 1, 0x5UL ] 0x20100404UL
    goes r2 words [] 0x20100008UL

  /// <summary>
  /// 7c031020, bitswap v0, v1, against QEMU's I6400, a Release 6 processor: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BITSWAP``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r6 [ "7c031020" ]
    |> is [ G 2, 0xc0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r6 [ "7c031020" ]
    |> is [ G 2, 0x80UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r6 [ "7c031020" ]
    |> is [ G 2, 0x482c6a1eUL ]

  /// <summary>
  /// 18200100, blez at, 0x20100404 (binutils: blez $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0xfffffffffffffffb; to
  /// 0x20100008, past the slot, when G 1 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLEZ``() =
    let words = [ "18200100"; "00000000" ]
    ownsJump r2 "18200100" false
    goes r2 words [ G 1, 0xfffffffffffffffbUL ] 0x20100404UL
    goes r2 words [ G 1, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 18010100, blezalc at, 0x20100404 (binutils: blezalc $1,20100404). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0xfffffffffffffffb; to
  /// 0x20100004, past the branch, when G 1 is 0x5; ra becomes 0x20100004 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLEZALC``() =
    let words = [ "18010100" ]
    ownsJump r6 "18010100" true
    goes r6 words [ G 1, 0xfffffffffffffffbUL ] 0x20100404UL
    goes r6 words [ G 1, 0x5UL ] 0x20100004UL
    [ G 1, 0xfffffffffffffffbUL ]
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// 58010100, blezc at, 0x20100404 (binutils: blezc $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0xfffffffffffffffb; to
  /// 0x20100004, past the branch, when G 1 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLEZC``() =
    let words = [ "58010100" ]
    ownsJump r6 "58010100" true
    goes r6 words [ G 1, 0xfffffffffffffffbUL ] 0x20100404UL
    goes r6 words [ G 1, 0x5UL ] 0x20100004UL

  /// <summary>
  /// 58200100, blezl at, 0x20100404 (binutils: blezl $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: control
  /// goes to 0x20100404 (the target binutils reads) when G 1 is
  /// 0xfffffffffffffffb; to 0x20100008, past the slot, when G 1 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLEZL``() =
    let words = [ "58200100"; "00000000" ]
    goes r2 words [ G 1, 0xfffffffffffffffbUL ] 0x20100404UL
    goes r2 words [ G 1, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 5c430101, bltc v0, v1, 0x20100408 (binutils: bltc $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20100408 (the target binutils reads) when G 2 is 0x3 and G 3 is 0x5;
  /// to 0x20100004, past the branch, when G 2 is 0x5 and G 3 is 0x3.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTC``() =
    let words = [ "5c430101" ]
    ownsJump r6 "5c430101" true
    goes r6 words [ G 2, 0x3UL; G 3, 0x5UL ] 0x20100408UL
    goes r6 words [ G 2, 0x5UL; G 3, 0x3UL ] 0x20100004UL

  /// <summary>
  /// 1c430101, bltuc v0, v1, 0x20100408 (binutils: bltuc $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20100408 (the target binutils reads) when G 2 is 0x3 and G 3 is
  /// 0xffffffffffffffff; to 0x20100004, past the branch, when G 2 is
  /// 0xffffffffffffffff and G 3 is 0x3.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTUC``() =
    let words = [ "1c430101" ]
    ownsJump r6 "1c430101" true
    goes r6 words [ G 2, 0x3UL; G 3, 0xffffffffffffffffUL ] 0x20100408UL
    goes r6 words [ G 2, 0xffffffffffffffffUL; G 3, 0x3UL ] 0x20100004UL

  /// <summary>
  /// 04200100, bltz at, 0x20100404 (binutils: bltz $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0xfffffffffffffffb; to
  /// 0x20100008, past the slot, when G 1 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTZ``() =
    let words = [ "04200100"; "00000000" ]
    ownsJump r2 "04200100" false
    goes r2 words [ G 1, 0xfffffffffffffffbUL ] 0x20100404UL
    goes r2 words [ G 1, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 04501901, bltzal v0, 0x20106408 (binutils: bltzal $2,20106408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0xfffffffffffffffb; to
  /// 0x20100008, past the slot, when G 2 is 0x5; ra becomes 0x20100008 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTZAL``() =
    let words = [ "04501901"; "00000000" ]
    ownsJump r2 "04501901" false
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20106408UL
    goes r2 words [ G 2, 0x5UL ] 0x20100008UL
    [ G 2, 0xfffffffffffffffbUL ]
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 1c421901, bltzalc v0, 0x20106408 (binutils: bltzalc $2,20106408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0xfffffffffffffffb; to
  /// 0x20100004, past the branch, when G 2 is 0x5; ra becomes 0x20100004 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTZALC``() =
    let words = [ "1c421901" ]
    ownsJump r6 "1c421901" true
    goes r6 words [ G 2, 0xfffffffffffffffbUL ] 0x20106408UL
    goes r6 words [ G 2, 0x5UL ] 0x20100004UL
    [ G 2, 0xfffffffffffffffbUL ]
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// 04521901, bltzall v0, 0x20106408 (binutils: bltzall $2,20106408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual:
  /// control goes to 0x20106408 (the target binutils reads) when G 2 is
  /// 0xfffffffffffffffb; to 0x20100008, past the slot, when G 2 is 0x5; ra
  /// becomes 0x20100008 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTZALL``() =
    let words = [ "04521901"; "00000000" ]
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20106408UL
    goes r2 words [ G 2, 0x5UL ] 0x20100008UL
    [ G 2, 0xfffffffffffffffbUL ]
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 5c421901, bltzc v0, 0x20106408 (binutils: bltzc $2,20106408). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20106408 (the target binutils reads) when G 2 is 0xfffffffffffffffb; to
  /// 0x20100004, past the branch, when G 2 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTZC``() =
    let words = [ "5c421901" ]
    ownsJump r6 "5c421901" true
    goes r6 words [ G 2, 0xfffffffffffffffbUL ] 0x20106408UL
    goes r6 words [ G 2, 0x5UL ] 0x20100004UL

  /// <summary>
  /// 04420101, bltzl v0, 0x20100408 (binutils: bltzl $2,20100408). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: control
  /// goes to 0x20100408 (the target binutils reads) when G 2 is
  /// 0xfffffffffffffffb; to 0x20100008, past the slot, when G 2 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BLTZL``() =
    let words = [ "04420101"; "00000000" ]
    goes r2 words [ G 2, 0xfffffffffffffffbUL ] 0x20100408UL
    goes r2 words [ G 2, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 14430101, bne v0, v1, 0x20100408 (binutils: bne $2,$3,20100408). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100408 (the target binutils reads) when G 2 is 0x5 and G 3 is 0x6; to
  /// 0x20100008, past the slot, when G 2 is 0x5 and G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BNE``() =
    let words = [ "14430101"; "00000000" ]
    ownsJump r2 "14430101" false
    goes r2 words [ G 2, 0x5UL; G 3, 0x6UL ] 0x20100408UL
    goes r2 words [ G 2, 0x5UL; G 3, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 60430101, bnec v0, v1, 0x20100408 (binutils: bnec $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20100408 (the target binutils reads) when G 2 is 0x5 and G 3 is 0x6;
  /// to 0x20100004, past the branch, when G 2 is 0x5 and G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BNEC``() =
    let words = [ "60430101" ]
    ownsJump r6 "60430101" true
    goes r6 words [ G 2, 0x5UL; G 3, 0x6UL ] 0x20100408UL
    goes r6 words [ G 2, 0x5UL; G 3, 0x5UL ] 0x20100004UL

  /// <summary>
  /// 54430101, bnel v0, v1, 0x20100408 (binutils: bnel $2,$3,20100408). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// control goes to 0x20100408 (the target binutils reads) when G 2 is 0x5 and
  /// G 3 is 0x6; to 0x20100008, past the slot, when G 2 is 0x5 and G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BNEL``() =
    let words = [ "54430101"; "00000000" ]
    goes r2 words [ G 2, 0x5UL; G 3, 0x6UL ] 0x20100408UL
    goes r2 words [ G 2, 0x5UL; G 3, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 60010100, bnezalc at, 0x20100404 (binutils: bnezalc $1,20100404). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0x5; to 0x20100004,
  /// past the branch, when nothing is given; ra becomes 0x20100004 and nothing
  /// else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BNEZALC``() =
    let words = [ "60010100" ]
    ownsJump r6 "60010100" true
    goes r6 words [ G 1, 0x5UL ] 0x20100404UL
    goes r6 words [] 0x20100004UL
    [ G 1, 0x5UL ]
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// f8200100, bnezc at, 0x20100404 (binutils: bnezc $1,20100404). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100404 (the target binutils reads) when G 1 is 0x5; to 0x20100004,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BNEZC``() =
    let words = [ "f8200100" ]
    ownsJump r6 "f8200100" true
    goes r6 words [ G 1, 0x5UL ] 0x20100404UL
    goes r6 words [] 0x20100004UL

  /// <summary>
  /// 60621900, bnvc v1, v0, 0x20106404 (binutils: bnvc $3,$2,20106404). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20106404 (the target binutils reads) when G 3 is 0x1 and G 2 is 0x1;
  /// to 0x20100004, past the branch, when G 3 is 0x7fffffff and G 2 is 0x1.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BNVC``() =
    let words = [ "60621900" ]
    ownsJump r6 "60621900" true
    goes r6 words [ G 3, 0x1UL; G 2, 0x1UL ] 0x20106404UL
    goes r6 words [ G 3, 0x7fffffffUL; G 2, 0x1UL ] 0x20100004UL

  /// <summary>
  /// 20621900, bovc v1, v0, 0x20106404 (binutils: bovc $3,$2,20106404). A
  /// branch is not run against QEMU: it moves the PC, and its delay slot makes
  /// one word meaningless to run alone. Checked structurally from the manual:
  /// the transfer is the branch's own, there being no delay slot; control goes
  /// to 0x20106404 (the target binutils reads) when G 3 is 0x7fffffff and G 2
  /// is 0x1; to 0x20100004, past the branch, when G 3 is 0x1 and G 2 is 0x1.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BOVC``() =
    let words = [ "20621900" ]
    ownsJump r6 "20621900" true
    goes r6 words [ G 3, 0x7fffffffUL; G 2, 0x1UL ] 0x20106404UL
    goes r6 words [ G 3, 0x1UL; G 2, 0x1UL ] 0x20100004UL

  /// <summary>
  /// 0000000d, break, against QEMU's MIPS64R2-generic: QEMU raised SIGTRAP
  /// (Breakpoint here); the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 BREAK``() =
    []
    |> run r2 [ "0000000d" ]
    |> raises [ Breakpoint ] []
    []
    |> run r2 [ "0000000d" ]
    |> raises [ Breakpoint ] []
    []
    |> run r2 [ "0000000d" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// 46241134, c.olt.d 0x1, f2, f4, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 C.cond.fmt``() =
    [ F 2, 0x4002000000000000UL; F 4, 0x3ff8000000000000UL ]
    |> run r2 [ "46241134" ]
    |> is []
    [ F 2, 0x3fe8000000000000UL; F 4, 0x3fe8000000000000UL ]
    |> run r2 [ "46241134" ]
    |> is []
    [ F 2, 0xc018000000000000UL; F 4, 0x3fc0000000000000UL ]
    |> run r2 [ "46241134" ]
    |> is [ Fcsr, 0x2000000UL ]
    [ F 2, 0x7ff8000000000000UL; F 4, 0x3ff0000000000000UL ]
    |> run r2 [ "46241134" ]
    |> is [ Fcsr, 0x10040UL ]

  /// <summary>
  /// bc400008, cache 0x0, 8(v0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CACHE``() =
    let given0 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0xbc29558e42232f1fUL
        M 0x20200080UL, 0x4c2c0472113165e0UL
        M 0x20200088UL, 0xe224577b71fb184eUL ]
    given0
    |> run r2 [ "bc400008" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0xe6d0ce3c47ae1ab2UL
        M 0x20200080UL, 0x7a13efc31d120b30UL
        M 0x20200088UL, 0x818cd3e5aba5be67UL ]
    given1
    |> run r2 [ "bc400008" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0x21215457f8d5b7fUL
        M 0x20200080UL, 0xddaa38e43822f89dUL
        M 0x20200088UL, 0xd1095995f92afcc4UL ]
    given2
    |> run r2 [ "bc400008" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c40041b, cachee 0x0, 8(v0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CACHEE``() =
    let given0 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0xffb14204fb60fa55UL
        M 0x20200080UL, 0x2216fa562948408bUL
        M 0x20200088UL, 0xab0425bfb9505a75UL ]
    given0
    |> run r2 [ "7c40041b" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0x6676a3f29cb3d821UL
        M 0x20200080UL, 0x6e994c31ef4f27dfUL
        M 0x20200088UL, 0x1c3f47dfad39b97UL ]
    given1
    |> run r2 [ "7c40041b" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0x20200078UL
        Status, 0x10UL
        M 0x20200078UL, 0x310232ba1a01e2dfUL
        M 0x20200080UL, 0xabc2d8beed84826bUL
        M 0x20200088UL, 0xb240e35996a08350UL ]
    given2
    |> run r2 [ "7c40041b" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4600208a, ceil.l.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CEIL.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "4600208a" ]
    |> is [ F 2, 0x3UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "4600208a" ]
    |> is [ F 2, 0xffffffffffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "4600208a" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 4600208e, ceil.w.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CEIL.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "4600208e" ]
    |> is [ F 2, 0x3UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "4600208e" ]
    |> is [ F 2, 0xffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "4600208e" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 4442f800, cfc1 v0, f31, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CFC1``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "4442f800" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "4442f800" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "4442f800" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 48421900, cfc2 v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CFC2``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "48421900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "48421900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "48421900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4600209b, class.s f2, f4, against QEMU's I6400, a Release 6 processor: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CLASS.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40100000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209b" ]
    |> is [ F 2, 0x80UL ]
    [ F 2, 0xbUL; F 4, 0x80000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209b" ]
    |> is [ F 2, 0x20UL ]
    [ F 2, 0xdUL; F 4, 0x7fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209b" ]
    |> is [ F 2, 0x2UL ]
    [ F 2, 0x9UL; F 4, 0xff800000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209b" ]
    |> is [ F 2, 0x4UL ]
    [ F 2, 0xbUL; F 4, 0x116c2UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4600209b" ]
    |> is [ F 2, 0x100UL ]

  /// <summary>
  /// 70621021, clo v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CLO``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "70621021" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "70621021" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "70621021" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 70621020, clz v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CLZ``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "70621020" ]
    |> is [ G 2, 0x1eUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "70621020" ]
    |> is [ G 2, 0x1fUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "70621020" ]
    |> is [ G 2, 0x3UL ]

  /// <summary>
  /// 46862080, cmp.af.s f2, f4, f6, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CMP.condn.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46862080" ]
    |> is [ F 2, 0x0UL ]
    [ F 2, 0xbUL; F 4, 0x3f400000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46862080" ]
    |> is [ F 2, 0x0UL ]
    [ F 2, 0xdUL; F 4, 0xc0c00000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46862080" ]
    |> is [ F 2, 0x0UL ]
    [ F 2, 0x9UL; F 4, 0x7fc00000UL; F 6, 0x3f800000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46862080" ]
    |> is [ F 2, 0x0UL ]

  /// <summary>
  /// 4a200000, cop2 0x200000, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 COP2``() =
    []
    |> run r2 [ "4a200000" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run r2 [ "4a200000" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run r2 [ "4a200000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c62000f, crc32b v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0xEDB88320
  /// reflected, the low 1 byte of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32B``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c62000f" ]
    |> is [ G 2, 0x1d48ef9bUL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c62000f" ]
    |> is [ G 2, 0x437bdd3cUL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c62000f" ]
    |> is [ G 2, 0xffffffffa6bc5767UL ]

  /// <summary>
  /// 7c62010f, crc32cb v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0x82F63B78
  /// reflected, the low 1 byte of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32CB``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c62010f" ]
    |> is [ G 2, 0x10a13890UL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c62010f" ]
    |> is [ G 2, 0xffffffffeb0dfffbUL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c62010f" ]
    |> is [ G 2, 0xffffffff97baa1baUL ]

  /// <summary>
  /// 7c6201cf, crc32cd v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0x82F63B78
  /// reflected, the low 8 bytes of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32CD``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c6201cf" ]
    |> is [ G 2, 0xffffffff9a4f27dcUL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c6201cf" ]
    |> is [ G 2, 0x679dfef3UL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c6201cf" ]
    |> is [ G 2, 0x51200cb7UL ]

  /// <summary>
  /// 7c62014f, crc32ch v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0x82F63B78
  /// reflected, the low 2 bytes of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32CH``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c62014f" ]
    |> is [ G 2, 0xffffffffee1d3738UL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c62014f" ]
    |> is [ G 2, 0xffffffffbbd4f0f7UL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c62014f" ]
    |> is [ G 2, 0xffffffffd960e050UL ]

  /// <summary>
  /// 7c62018f, crc32cw v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0x82F63B78
  /// reflected, the low 4 bytes of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32CW``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c62018f" ]
    |> is [ G 2, 0xffffffffee8c8012UL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c62018f" ]
    |> is [ G 2, 0x14f8d626UL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c62018f" ]
    |> is [ G 2, 0x23e246ffUL ]

  /// <summary>
  /// 7c6200cf, crc32d v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0xEDB88320
  /// reflected, the low 8 bytes of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32D``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c6200cf" ]
    |> is [ G 2, 0xffffffffbbc41db8UL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c6200cf" ]
    |> is [ G 2, 0xffffffffdf04eaaaUL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c6200cf" ]
    |> is [ G 2, 0xffffffffe2ade9e8UL ]

  /// <summary>
  /// 7c62004f, crc32h v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0xEDB88320
  /// reflected, the low 2 bytes of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32H``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c62004f" ]
    |> is [ G 2, 0xffffffff8215bc2eUL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c62004f" ]
    |> is [ G 2, 0xffffffffe7fb56daUL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c62004f" ]
    |> is [ G 2, 0xffffffffd37048acUL ]

  /// <summary>
  /// 7c62008f, crc32w v0, v1, v0. QEMU's I6400 does not implement the CRC
  /// instructions (it raises SIGILL for them), and no other model of it does,
  /// so the values are the CRC MD00087 defines: the polynomial 0xEDB88320
  /// reflected, the low 4 bytes of v1 taken least significant first, no
  /// inversion, the result sign-extended -- computed by the bitwise update in
  /// optest-mips/oracle/structural.py, which is checked against zlib's CRC-32
  /// and the CRC-32C check value of RFC 3720.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CRC32W``() =
    [ G 2, 0xffffffffffffffffUL; G 3, 0x123456789abcdefUL ]
    |> run r6 [ "7c62008f" ]
    |> is [ G 2, 0x10472a38UL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c62008f" ]
    |> is [ G 2, 0xffffffff9e6e72f6UL ]
    [ G 2, 0x0UL; G 3, 0xa5UL ]
    |> run r6 [ "7c62008f" ]
    |> is [ G 2, 0x7ab5e937UL ]

  /// <summary>
  /// 44c2f800, ctc1 v0, f31, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CTC1``() =
    [ G 2, 0x3UL ]
    |> run r2 [ "44c2f800" ]
    |> is [ Fcsr, 0x3UL ]
    [ G 2, 0x1000000UL ]
    |> run r2 [ "44c2f800" ]
    |> is [ Fcsr, 0x1000000UL ]
    [ G 2, 0xfe800002UL ]
    |> run r2 [ "44c2f800" ]
    |> is [ Fcsr, 0xfe800002UL ]

  /// <summary>
  /// 48c21900, ctc2 v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CTC2``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "48c21900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "48c21900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "48c21900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 460020a1, cvt.d.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.D.fmt``() =
    [ F 2, 0xbff0000000000000UL; F 4, 0x40200000UL ]
    |> run r2 [ "460020a1" ]
    |> is [ F 2, 0x4004000000000000UL ]
    [ F 2, 0x400c000000000000UL; F 4, 0xbfe00000UL ]
    |> run r2 [ "460020a1" ]
    |> is [ F 2, 0xbffc000000000000UL ]
    [ F 2, 0x3fd0000000000000UL; F 4, 0x447a0000UL ]
    |> run r2 [ "460020a1" ]
    |> is [ F 2, 0x408f400000000000UL ]

  /// <summary>
  /// 460020a5, cvt.l.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "460020a5" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "460020a5" ]
    |> is [ F 2, 0xfffffffffffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "460020a5" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 460620a6, cvt.ps.s f2, f4, f6, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.PS.S``() =
    [ F 2, 0xbf8000003f800000UL; F 4, 0x40200000UL; F 6, 0x3fc00000UL ]
    |> run r2 [ "460620a6" ]
    |> is [ F 2, 0x402000003fc00000UL ]
    [ F 2, 0x40600000c0600000UL; F 4, 0xbfe00000UL; F 6, 0x3f400000UL ]
    |> run r2 [ "460620a6" ]
    |> is [ F 2, 0xbfe000003f400000UL ]
    [ F 2, 0x3e8000003f400000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run r2 [ "460620a6" ]
    |> is [ F 2, 0x447a00003e000000UL ]

  /// <summary>
  /// 46c020a8, cvt.s.pl f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.S.PL``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000bfc00000UL ]
    |> run r2 [ "46c020a8" ]
    |> is [ F 2, 0xbfc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c000003f000000UL ]
    |> run r2 [ "46c020a8" ]
    |> is [ F 2, 0x3f000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a000040400000UL ]
    |> run r2 [ "46c020a8" ]
    |> is [ F 2, 0x40400000UL ]

  /// <summary>
  /// 46c020a0, cvt.s.pu f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.S.PU``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000bfc00000UL ]
    |> run r2 [ "46c020a0" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c000003f000000UL ]
    |> run r2 [ "46c020a0" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a000040400000UL ]
    |> run r2 [ "46c020a0" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 462020a0, cvt.s.d f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.S.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x4004000000000000UL ]
    |> run r2 [ "462020a0" ]
    |> is [ F 2, 0x40200000UL ]
    [ F 2, 0x40600000UL; F 4, 0xbffc000000000000UL ]
    |> run r2 [ "462020a0" ]
    |> is [ F 2, 0xbfe00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x408f400000000000UL ]
    |> run r2 [ "462020a0" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 460020a4, cvt.w.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 CVT.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "460020a4" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "460020a4" ]
    |> is [ F 2, 0xfffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "460020a4" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 0064102c, dadd v0, v1, a0, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGFPE (Exception IntegerOverflow here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DADD``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102c" ]
    |> is [ G 2, 0x8UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064102c" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "0064102c" ]
    |> is [ G 2, 0xfedcba997654320fUL ]
    [ G 2, 0x7UL; G 3, 0x7fffffffffffffffUL; G 4, 0x1UL ]
    |> run r2 [ "0064102c" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 60620100, daddi v0, v1, 0x100, against QEMU's MIPS64R2-generic: QEMU
  /// raised SIGFPE (Exception IntegerOverflow here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DADDI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "60620100" ]
    |> is [ G 2, 0x103UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "60620100" ]
    |> is [ G 2, 0x101UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "60620100" ]
    |> is [ G 2, 0xfedcba9876543310UL ]
    [ G 2, 0x7UL; G 3, 0x7fffffffffffffffUL ]
    |> run r2 [ "60620100" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 64620100, daddiu v0, v1, 0x100, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DADDIU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "64620100" ]
    |> is [ G 2, 0x103UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "64620100" ]
    |> is [ G 2, 0x101UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "64620100" ]
    |> is [ G 2, 0xfedcba9876543310UL ]

  /// <summary>
  /// 0064102d, daddu v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DADDU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102d" ]
    |> is [ G 2, 0x8UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064102d" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "0064102d" ]
    |> is [ G 2, 0xfedcba997654320fUL ]

  /// <summary>
  /// 04661900, dahi v1, 0x1900, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DAHI``() =
    [ G 3, 0x7UL ]
    |> run r6 [ "04661900" ]
    |> is [ G 3, 0x190000000007UL ]
    [ G 3, 0x7fffffffffffffffUL ]
    |> run r6 [ "04661900" ]
    |> is [ G 3, 0x800018ffffffffffUL ]
    [ G 3, 0x123456789abcdefUL ]
    |> run r6 [ "04661900" ]
    |> is [ G 3, 0x1235e6789abcdefUL ]

  /// <summary>
  /// 7c641264, dalign v0, v1, a0, 0x1, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DALIGN``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "7c641264" ]
    |> is [ G 2, 0x500UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "7c641264" ]
    |> is [ G 2, 0xfffffffffffffe00UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "7c641264" ]
    |> is [ G 2, 0xfffffffffeUL ]

  /// <summary>
  /// 047e1900, dati v1, 0x1900, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DATI``() =
    [ G 3, 0x7UL ]
    |> run r6 [ "047e1900" ]
    |> is [ G 3, 0x1900000000000007UL ]
    [ G 3, 0x7fffffffffffffffUL ]
    |> run r6 [ "047e1900" ]
    |> is [ G 3, 0x98ffffffffffffffUL ]
    [ G 3, 0x123456789abcdefUL ]
    |> run r6 [ "047e1900" ]
    |> is [ G 3, 0x1a23456789abcdefUL ]

  /// <summary>
  /// 74620100, daui v0, v1, 0x100, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DAUI``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r6 [ "74620100" ]
    |> is [ G 2, 0x1000003UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r6 [ "74620100" ]
    |> is [ G 2, 0x1000001UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "74620100" ]
    |> is [ G 2, 0xfedcba9877543210UL ]

  /// <summary>
  /// 7c031024, dbitswap v0, v1, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DBITSWAP``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r6 [ "7c031024" ]
    |> is [ G 2, 0xc0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r6 [ "7c031024" ]
    |> is [ G 2, 0x80UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r6 [ "7c031024" ]
    |> is [ G 2, 0x7f3b5d196e2a4c08UL ]

  /// <summary>
  /// 70621025, dclo v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DCLO``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "70621025" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "70621025" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "70621025" ]
    |> is [ G 2, 0x7UL ]

  /// <summary>
  /// 70621024, dclz v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DCLZ``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "70621024" ]
    |> is [ G 2, 0x3eUL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "70621024" ]
    |> is [ G 2, 0x3fUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "70621024" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 0043001e, ddiv v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DDIV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0043001e" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0043001e" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0043001e" ]
    |> is [ Hi, 0x123456789abcdefUL ]

  /// <summary>
  /// 0043001f, ddivu v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DDIVU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0043001f" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0043001f" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0043001f" ]
    |> is [ Hi, 0x123456789abcdefUL ]

  /// <summary>
  /// 4200001f, deret, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DERET``() =
    [ Status, 0x10UL ]
    |> run r2 [ "4200001f" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "4200001f" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "4200001f" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c620103, dext v0, v1, 0x4, 0x1, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DEXT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c620103" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c620103" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "7c620103" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 7c620101, dextm v0, v1, 0x4, 0x21, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DEXTM``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c620101" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c620101" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "7c620101" ]
    |> is [ G 2, 0x187654321UL ]

  /// <summary>
  /// 7c620102, dextu v0, v1, 0x24, 0x1, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DEXTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c620102" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c620102" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "7c620102" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 41626000, di v0, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DI``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r2 [ "41626000" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r2 [ "41626000" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r2 [ "41626000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c621847, dins v0, v1, 0x1, 0x3, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DINS``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c621847" ]
    |> is []
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c621847" ]
    |> is [ G 2, 0x7ffffffffffffff3UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "7c621847" ]
    |> is [ G 2, 0x123456789abcde1UL ]

  /// <summary>
  /// 7c620105, dinsm v0, v1, 0x4, 0x1d, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DINSM``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c620105" ]
    |> is [ G 2, 0x37UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c620105" ]
    |> is [ G 2, 0x7ffffffe0000001fUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "7c620105" ]
    |> is [ G 2, 0x12345676543210fUL ]
