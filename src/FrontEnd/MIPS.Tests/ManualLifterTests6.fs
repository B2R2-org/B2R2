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
/// One test for each instruction of microMIPS64 5.04: ABS.fmt to ERETNC.
///
/// <para>A value test runs a word of the instruction under QEMU over a few
/// sets of register values, memory and FCSR, and has the lift change what
/// QEMU changed, raise what QEMU raised, and nothing else; every value it
/// expects is QEMU's (optest-mips/oracle). A structural test says in its own
/// comment what it checks and why no value test could be had.</para>
/// </summary>
[<TestClass>]
type ManualLifterTests6() =
  let um =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSISAMode.MicroMIPS)

  /// <summary>
  /// 5444037b, abs.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after abs.s $f2,$f4, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ABS.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "5444037b" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run um [ "5444037b" ]
    |> is [ F 2, 0x40c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run um [ "5444037b" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 01494110, add a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGFPE (Exception IntegerOverflow here); the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADD``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494110" ]
    |> is [ G 8, 0x8UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494110" ]
    |> is [ G 8, 0xffffffffffffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494110" ]
    |> is [ G 8, 0x11111110UL ]
    [ G 8, 0x7UL; G 9, 0x7fffffffUL; G 10, 0x1UL ]
    |> run um [ "01494110" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 54c41030, add.s f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after add.s $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADD.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run um [ "54c41030" ]
    |> is [ F 2, 0x40700000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run um [ "54c41030" ]
    |> is [ F 2, 0xc0a80000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run um [ "54c41030" ]
    |> is [ F 2, 0x447a0800UL ]

  /// <summary>
  /// 11090001, addi a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGFPE (Exception IntegerOverflow here); the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDI``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "11090001" ]
    |> is [ G 8, 0x4UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "11090001" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "11090001" ]
    |> is [ G 8, 0x12345679UL ]
    [ G 8, 0x7UL; G 9, 0x7fffffffUL ]
    |> run um [ "11090001" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 31090001, addiu a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "31090001" ]
    |> is [ G 8, 0x4UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "31090001" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "31090001" ]
    |> is [ G 8, 0x12345679UL ]

  /// <summary>
  /// 79030000, addiupc v0, 0x201c0000, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUPC``() =
    [ G 2, 0x7UL ]
    |> run um [ "79030000" ]
    |> is [ G 2, 0x201c0000UL ]
    [ G 2, 0x7fffffffUL ]
    |> run um [ "79030000" ]
    |> is [ G 2, 0x201c0000UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run um [ "79030000" ]
    |> is [ G 2, 0x201c0000UL ]

  /// <summary>
  /// 6d03, addiu v0, sp, 0x4, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUR1SP``() =
    [ G 2, 0x7UL; G 29, 0x3UL ]
    |> run um [ "6d03" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 29, 0x1UL ]
    |> run um [ "6d03" ]
    |> is [ G 2, 0x5UL ]
    [ G 2, 0xffffffff89abcdefUL; G 29, 0x12345678UL ]
    |> run um [ "6d03" ]
    |> is [ G 2, 0x1234567cUL ]

  /// <summary>
  /// 6d30, addiu v0, v1, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUR2``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "6d30" ]
    |> is [ G 2, 0x4UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "6d30" ]
    |> is [ G 2, 0x2UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "6d30" ]
    |> is [ G 2, 0x12345679UL ]

  /// <summary>
  /// 4c22, addiu at, at, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUS5``() =
    [ G 1, 0x7UL ]
    |> run um [ "4c22" ]
    |> is [ G 1, 0x8UL ]
    [ G 1, 0x7fffffffUL ]
    |> run um [ "4c22" ]
    |> is [ G 1, 0xffffffff80000000UL ]
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "4c22" ]
    |> is [ G 1, 0xffffffff89abcdf0UL ]

  /// <summary>
  /// 4c01, addiu sp, sp, 0x400, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDIUSP``() =
    [ G 29, 0x7UL ]
    |> run um [ "4c01" ]
    |> is [ G 29, 0x407UL ]
    [ G 29, 0x7fffffffUL ]
    |> run um [ "4c01" ]
    |> is [ G 29, 0xffffffff800003ffUL ]
    [ G 29, 0xffffffff89abcdefUL ]
    |> run um [ "4c01" ]
    |> is [ G 29, 0xffffffff89abd1efUL ]

  /// <summary>
  /// 01494150, addu a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494150" ]
    |> is [ G 8, 0x8UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494150" ]
    |> is [ G 8, 0xffffffffffffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494150" ]
    |> is [ G 8, 0x11111110UL ]

  /// <summary>
  /// 0538, addu v0, a0, v1, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ADDU16``() =
    [ G 2, 0x7UL; G 3, 0x5UL; G 4, 0x3UL ]
    |> run um [ "0538" ]
    |> is [ G 2, 0x8UL ]
    [ G 2, 0x7fffffffUL; G 3, 0xfffffffffffffffeUL; G 4, 0x1UL ]
    |> run um [ "0538" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0xfffffffffedcba98UL; G 4, 0x12345678UL ]
    |> run um [ "0538" ]
    |> is [ G 2, 0x11111110UL ]

  /// <summary>
  /// 54c41219, alnv.ps f2, f4, f6, a4, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after alnv.ps $f2,$f4,$f6,$8, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ALNV.PS``() =
    let given0 =
      [ F 2, 0xbf8000003f800000UL
        F 4, 0x40100000bfc00000UL
        F 6, 0x3fc000003e800000UL ]
    given0
    |> run um [ "54c41219" ]
    |> is [ F 2, 0x40100000bfc00000UL ]
    let given1 =
      [ G 8, 0x4UL
        F 2, 0x40600000c0600000UL
        F 4, 0xc0c000003f000000UL
        F 6, 0x3f40000040000000UL ]
    given1
    |> run um [ "54c41219" ]
    |> is [ F 2, 0x3f0000003f400000UL ]
    let given2 =
      [ G 8, 0x4UL
        F 2, 0x3e8000003f400000UL
        F 4, 0x447a000040400000UL
        F 6, 0x3e000000c0800000UL ]
    given2
    |> run um [ "54c41219" ]
    |> is [ F 2, 0x404000003e000000UL ]

  /// <summary>
  /// 01494250, and a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 AND``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494250" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494250" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494250" ]
    |> is [ G 8, 0x12141218UL ]

  /// <summary>
  /// 4493, and v0, v0, v1, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 AND16``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "4493" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "4493" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "4493" ]
    |> is [ G 2, 0x204468UL ]

  /// <summary>
  /// d1090001, andi a4, a5, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ANDI``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "d1090001" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "d1090001" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "d1090001" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 2d30, andi v0, v1, 0x80, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ANDI16``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run um [ "2d30" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run um [ "2d30" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run um [ "2d30" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// cc10, b 0x20100022 (binutils: b 20100022). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20100022 (the target
  /// binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 B``() =
    let words = [ "cc10"; "00000000" ]
    ownsJump um "cc10" false
    goes um words [] 0x20100022UL

  /// <summary>
  /// cc10, b 0x20100022 (binutils: b 20100022). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20100022 (the target
  /// binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 B16``() =
    let words = [ "cc10"; "00000000" ]
    ownsJump um "cc10" false
    goes um words [] 0x20100022UL

  /// <summary>
  /// 40600100, bgezal r0, 0x20100204 (binutils: bal 20100204). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when it always does; ra becomes
  /// 0x20100009 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BAL``() =
    let words = [ "40600100"; "00000000" ]
    ownsJump um "40600100" false
    goes um words [] 0x20100204UL
    []
    |> run um words
    |> is [ G 31, 0x20100009UL ]

  /// <summary>
  /// 43830100, bc1f 0x0, 0x20100204 (binutils: bc1f $fcc0,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when it always does; to 0x20100008,
  /// past the slot, when Fcsr is 0x800000.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BC1F``() =
    let words = [ "43830100"; "00000000" ]
    ownsJump um "43830100" false
    goes um words [] 0x20100204UL
    goes um words [ Fcsr, 0x800000UL ] 0x20100008UL

  /// <summary>
  /// 43a30100, bc1t 0x0, 0x20100204 (binutils: bc1t $fcc0,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when Fcsr is 0x800000; to
  /// 0x20100008, past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BC1T``() =
    let words = [ "43a30100"; "00000000" ]
    ownsJump um "43a30100" false
    goes um words [ Fcsr, 0x800000UL ] 0x20100204UL
    goes um words [] 0x20100008UL

  /// <summary>
  /// 42830000, bc2f 0x0, 0x20100004. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BC2F``() =
    []
    |> run um [ "42830000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42a30000, bc2t 0x0, 0x20100004. A branch is not run against QEMU; this
  /// processor has no coprocessor 2 (Config1.C2 is clear), and every
  /// instruction that reaches it takes Coprocessor Unusable, a branch on its
  /// condition before it branches. The lift raises UndefinedInstruction and
  /// changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BC2T``() =
    []
    |> run um [ "42a30000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 94230100, beq v1, at, 0x20100204 (binutils: beq $3,$1,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0x5 and G 1 is 0x5; to
  /// 0x20100008, past the slot, when G 3 is 0x5 and G 1 is 0x6.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BEQ``() =
    let words = [ "94230100"; "00000000" ]
    ownsJump um "94230100" false
    goes um words [ G 3, 0x5UL; G 1, 0x5UL ] 0x20100204UL
    goes um words [ G 3, 0x5UL; G 1, 0x6UL ] 0x20100008UL

  /// <summary>
  /// 8d10, beq v0, r0, 0x20100022 (binutils: beqz $2,20100022). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100022 (the target binutils reads) when it always does; to 0x20100006,
  /// past the slot, when G 2 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BEQZ16``() =
    let words = [ "8d10"; "00000000" ]
    ownsJump um "8d10" false
    goes um words [] 0x20100022UL
    goes um words [ G 2, 0x5UL ] 0x20100006UL

  /// <summary>
  /// 40e30100, beqzc v1, 0x20100204 (binutils: beqzc $3,20100204). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100204 (the target binutils reads) when it always does; to 0x20100004,
  /// past the branch, when G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BEQZC``() =
    let words = [ "40e30100" ]
    ownsJump um "40e30100" true
    goes um words [] 0x20100204UL
    goes um words [ G 3, 0x5UL ] 0x20100004UL

  /// <summary>
  /// 40430100, bgez v1, 0x20100204 (binutils: bgez $3,20100204). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0x5; to 0x20100008,
  /// past the slot, when G 3 is 0xfffffffffffffffb.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BGEZ``() =
    let words = [ "40430100"; "00000000" ]
    ownsJump um "40430100" false
    goes um words [ G 3, 0x5UL ] 0x20100204UL
    goes um words [ G 3, 0xfffffffffffffffbUL ] 0x20100008UL

  /// <summary>
  /// 40610100, bgezal at, 0x20100204 (binutils: bgezal $1,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 1 is 0x5; to 0x20100008,
  /// past the slot, when G 1 is 0xfffffffffffffffb; ra becomes 0x20100009 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BGEZAL``() =
    let words = [ "40610100"; "00000000" ]
    ownsJump um "40610100" false
    goes um words [ G 1, 0x5UL ] 0x20100204UL
    goes um words [ G 1, 0xfffffffffffffffbUL ] 0x20100008UL
    [ G 1, 0x5UL ]
    |> run um words
    |> is [ G 31, 0x20100009UL ]

  /// <summary>
  /// 42630100, bgezals v1, 0x20100204 (binutils: bgezals $3,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0x5; to 0x20100006,
  /// past the slot, when G 3 is 0xfffffffffffffffb; ra becomes 0x20100007 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BGEZALS``() =
    let words = [ "42630100"; "0c00" ]
    ownsJump um "42630100" false
    goes um words [ G 3, 0x5UL ] 0x20100204UL
    goes um words [ G 3, 0xfffffffffffffffbUL ] 0x20100006UL
    [ G 3, 0x5UL ]
    |> run um words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// 40c30100, bgtz v1, 0x20100204 (binutils: bgtz $3,20100204). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0x5; to 0x20100008,
  /// past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BGTZ``() =
    let words = [ "40c30100"; "00000000" ]
    ownsJump um "40c30100" false
    goes um words [ G 3, 0x5UL ] 0x20100204UL
    goes um words [] 0x20100008UL

  /// <summary>
  /// 40830100, blez v1, 0x20100204 (binutils: blez $3,20100204). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0xfffffffffffffffb; to
  /// 0x20100008, past the slot, when G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BLEZ``() =
    let words = [ "40830100"; "00000000" ]
    ownsJump um "40830100" false
    goes um words [ G 3, 0xfffffffffffffffbUL ] 0x20100204UL
    goes um words [ G 3, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 40030100, bltz v1, 0x20100204 (binutils: bltz $3,20100204). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0xfffffffffffffffb; to
  /// 0x20100008, past the slot, when G 3 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BLTZ``() =
    let words = [ "40030100"; "00000000" ]
    ownsJump um "40030100" false
    goes um words [ G 3, 0xfffffffffffffffbUL ] 0x20100204UL
    goes um words [ G 3, 0x5UL ] 0x20100008UL

  /// <summary>
  /// 40220100, bltzal v0, 0x20100204 (binutils: bltzal $2,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 2 is 0xfffffffffffffffb; to
  /// 0x20100008, past the slot, when G 2 is 0x5; ra becomes 0x20100009 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BLTZAL``() =
    let words = [ "40220100"; "00000000" ]
    ownsJump um "40220100" false
    goes um words [ G 2, 0xfffffffffffffffbUL ] 0x20100204UL
    goes um words [ G 2, 0x5UL ] 0x20100008UL
    [ G 2, 0xfffffffffffffffbUL ]
    |> run um words
    |> is [ G 31, 0x20100009UL ]

  /// <summary>
  /// 42230100, bltzals v1, 0x20100204 (binutils: bltzals $3,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0xfffffffffffffffb; to
  /// 0x20100006, past the slot, when G 3 is 0x5; ra becomes 0x20100007 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BLTZALS``() =
    let words = [ "42230100"; "0c00" ]
    ownsJump um "42230100" false
    goes um words [ G 3, 0xfffffffffffffffbUL ] 0x20100204UL
    goes um words [ G 3, 0x5UL ] 0x20100006UL
    [ G 3, 0xfffffffffffffffbUL ]
    |> run um words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// b4230100, bne v1, at, 0x20100204 (binutils: bne $3,$1,20100204). A branch
  /// is not run against QEMU: it moves the PC, and its delay slot makes one
  /// word meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0x5 and G 1 is 0x6; to
  /// 0x20100008, past the slot, when G 3 is 0x5 and G 1 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BNE``() =
    let words = [ "b4230100"; "00000000" ]
    ownsJump um "b4230100" false
    goes um words [ G 3, 0x5UL; G 1, 0x6UL ] 0x20100204UL
    goes um words [ G 3, 0x5UL; G 1, 0x5UL ] 0x20100008UL

  /// <summary>
  /// ad10, bne v0, r0, 0x20100022 (binutils: bnez $2,20100022). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100022 (the target binutils reads) when G 2 is 0x5; to 0x20100006,
  /// past the slot, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BNEZ16``() =
    let words = [ "ad10"; "00000000" ]
    ownsJump um "ad10" false
    goes um words [ G 2, 0x5UL ] 0x20100022UL
    goes um words [] 0x20100006UL

  /// <summary>
  /// 40a30100, bnezc v1, 0x20100204 (binutils: bnezc $3,20100204). A branch is
  /// not run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100204 (the target binutils reads) when G 3 is 0x5; to 0x20100004,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BNEZC``() =
    let words = [ "40a30100" ]
    ownsJump um "40a30100" true
    goes um words [ G 3, 0x5UL ] 0x20100204UL
    goes um words [] 0x20100004UL

  /// <summary>
  /// 4681, break 0x1, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Breakpoint here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BREAK``() =
    []
    |> run um [ "4681" ]
    |> raises [ Breakpoint ] []
    []
    |> run um [ "4681" ]
    |> raises [ Breakpoint ] []
    []
    |> run um [ "4681" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// 4681, break 0x1, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Breakpoint here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 BREAK16``() =
    []
    |> run um [ "4681" ]
    |> raises [ Breakpoint ] []
    []
    |> run um [ "4681" ]
    |> raises [ Breakpoint ] []
    []
    |> run um [ "4681" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// 5482253c, c.olt.d 0x1, f2, f4, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after c.olt.d $fcc1,$f2,$f4, the MIPS64 instruction binutils reads
  /// this word as. the lift has to change what QEMU changed and nothing else,
  /// over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 C.cond.fmt``() =
    [ F 2, 0x4002000000000000UL; F 4, 0x3ff8000000000000UL ]
    |> run um [ "5482253c" ]
    |> is []
    [ F 2, 0x3fe8000000000000UL; F 4, 0x3fe8000000000000UL ]
    |> run um [ "5482253c" ]
    |> is []
    [ F 2, 0xc018000000000000UL; F 4, 0x3fc0000000000000UL ]
    |> run um [ "5482253c" ]
    |> is [ Fcsr, 0x2000000UL ]
    [ F 2, 0x7ff8000000000000UL; F 4, 0x3ff0000000000000UL ]
    |> run um [ "5482253c" ]
    |> is [ Fcsr, 0x10040UL ]

  /// <summary>
  /// 20086001, cache 0x0, 1(a4), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CACHE``() =
    let given0 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x8c18f03cb424aeedUL
        M 0x20200080UL, 0x6b45524da216e604UL
        M 0x20200088UL, 0xf935b56ea8cd86a4UL ]
    given0
    |> run um [ "20086001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x585cf66c15dc3208UL
        M 0x20200080UL, 0xaf39075837cf77d4UL
        M 0x20200088UL, 0xec074b40aa78f598UL ]
    given1
    |> run um [ "20086001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe86855e18d37e12UL
        M 0x20200080UL, 0xb0db596d8efa3134UL
        M 0x20200088UL, 0xb5e92fa639a43fedUL ]
    given2
    |> run um [ "20086001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 6008a601, cachee 0x0, 1(a4), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CACHEE``() =
    let given0 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xad2890fa6d0161acUL
        M 0x20200080UL, 0xaa51dc8275969de0UL
        M 0x20200088UL, 0x4ebe4f5602e96663UL ]
    given0
    |> run um [ "6008a601" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x97d6ebe16009e99eUL
        M 0x20200080UL, 0xbcb1be9163c835e6UL
        M 0x20200088UL, 0xd51a700c324f980bUL ]
    given1
    |> run um [ "6008a601" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x612934330ddda0f5UL
        M 0x20200080UL, 0xc5a7578e6b89def0UL
        M 0x20200088UL, 0x1ec2ed401fee773eUL ]
    given2
    |> run um [ "6008a601" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5444133b, ceil.l.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ceil.l.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CEIL.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "5444133b" ]
    |> is [ F 2, 0x3UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "5444133b" ]
    |> is [ F 2, 0xffffffffffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "5444133b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 54441b3b, ceil.w.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ceil.w.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CEIL.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "54441b3b" ]
    |> is [ F 2, 0x3UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "54441b3b" ]
    |> is [ F 2, 0xffffffffUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "54441b3b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 551f103b, cfc1 a4, f31, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cfc1 $8,$31, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CFC1``() =
    [ G 8, 0x7UL ]
    |> run um [ "551f103b" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL ]
    |> run um [ "551f103b" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "551f103b" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 0022cd3c, cfc2 at, 0x2, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CFC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "0022cd3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "0022cd3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "0022cd3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 01094b3c, clo a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CLO``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01094b3c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01094b3c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01094b3c" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 01095b3c, clz a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CLZ``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01095b3c" ]
    |> is [ G 8, 0x1eUL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01095b3c" ]
    |> is [ G 8, 0x1fUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01095b3c" ]
    |> is [ G 8, 0x3UL ]

  /// <summary>
  /// 0000000a, cop2 0x1, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 COP2``() =
    []
    |> run um [ "0000000a" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run um [ "0000000a" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run um [ "0000000a" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 551f183b, ctc1 a4, f31, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ctc1 $8,$31, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CTC1``() =
    [ G 8, 0x3UL ]
    |> run um [ "551f183b" ]
    |> is [ Fcsr, 0x3UL ]
    [ G 8, 0x1000000UL ]
    |> run um [ "551f183b" ]
    |> is [ Fcsr, 0x1000000UL ]
    [ G 8, 0xfe800002UL ]
    |> run um [ "551f183b" ]
    |> is [ Fcsr, 0xfe800002UL ]

  /// <summary>
  /// 0022dd3c, ctc2 at, 0x2, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CTC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "0022dd3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "0022dd3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "0022dd3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5444137b, cvt.d.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cvt.d.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.D.fmt``() =
    [ F 2, 0xbff0000000000000UL; F 4, 0x40200000UL ]
    |> run um [ "5444137b" ]
    |> is [ F 2, 0x4004000000000000UL ]
    [ F 2, 0x400c000000000000UL; F 4, 0xbfe00000UL ]
    |> run um [ "5444137b" ]
    |> is [ F 2, 0xbffc000000000000UL ]
    [ F 2, 0x3fd0000000000000UL; F 4, 0x447a0000UL ]
    |> run um [ "5444137b" ]
    |> is [ F 2, 0x408f400000000000UL ]

  /// <summary>
  /// 5444013b, cvt.l.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cvt.l.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "5444013b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "5444013b" ]
    |> is [ F 2, 0xfffffffffffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "5444013b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 54c41180, cvt.ps.s f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after cvt.ps.s $f2,$f4,$f6, the MIPS64 instruction binutils reads
  /// this word as. the lift has to change what QEMU changed and nothing else,
  /// over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.PS.S``() =
    [ F 2, 0xbf8000003f800000UL; F 4, 0x40200000UL; F 6, 0x3fc00000UL ]
    |> run um [ "54c41180" ]
    |> is [ F 2, 0x402000003fc00000UL ]
    [ F 2, 0x40600000c0600000UL; F 4, 0xbfe00000UL; F 6, 0x3f400000UL ]
    |> run um [ "54c41180" ]
    |> is [ F 2, 0xbfe000003f400000UL ]
    [ F 2, 0x3e8000003f400000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run um [ "54c41180" ]
    |> is [ F 2, 0x447a00003e000000UL ]

  /// <summary>
  /// 5444213b, cvt.s.pl f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cvt.s.pl $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.S.PL``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000bfc00000UL ]
    |> run um [ "5444213b" ]
    |> is [ F 2, 0xbfc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c000003f000000UL ]
    |> run um [ "5444213b" ]
    |> is [ F 2, 0x3f000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a000040400000UL ]
    |> run um [ "5444213b" ]
    |> is [ F 2, 0x40400000UL ]

  /// <summary>
  /// 5444293b, cvt.s.pu f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cvt.s.pu $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.S.PU``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000bfc00000UL ]
    |> run um [ "5444293b" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c000003f000000UL ]
    |> run um [ "5444293b" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a000040400000UL ]
    |> run um [ "5444293b" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 54441b7b, cvt.s.d f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cvt.s.d $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.S.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x4004000000000000UL ]
    |> run um [ "54441b7b" ]
    |> is [ F 2, 0x40200000UL ]
    [ F 2, 0x40600000UL; F 4, 0xbffc000000000000UL ]
    |> run um [ "54441b7b" ]
    |> is [ F 2, 0xbfe00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x408f400000000000UL ]
    |> run um [ "54441b7b" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 5444093b, cvt.w.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after cvt.w.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 CVT.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "5444093b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "5444093b" ]
    |> is [ F 2, 0xfffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "5444093b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 59494110, dadd a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dadd $8,$9,$10, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGFPE (Exception IntegerOverflow here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DADD``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "59494110" ]
    |> is [ G 8, 0x8UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "59494110" ]
    |> is [ G 8, 0xffffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "59494110" ]
    |> is [ G 8, 0xfedcba997654320fUL ]
    [ G 8, 0x7UL; G 9, 0x7fffffffffffffffUL; G 10, 0x1UL ]
    |> run um [ "59494110" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 5909005c, daddi a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after daddi $8,$9,1, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGFPE (Exception IntegerOverflow here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DADDI``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5909005c" ]
    |> is [ G 8, 0x4UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5909005c" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5909005c" ]
    |> is [ G 8, 0xfedcba9876543211UL ]
    [ G 8, 0x7UL; G 9, 0x7fffffffffffffffUL ]
    |> run um [ "5909005c" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 5d090001, daddiu a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after daddiu $8,$9,1, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DADDIU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5d090001" ]
    |> is [ G 8, 0x4UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5d090001" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5d090001" ]
    |> is [ G 8, 0xfedcba9876543211UL ]

  /// <summary>
  /// 59494150, daddu a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after daddu $8,$9,$10, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DADDU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "59494150" ]
    |> is [ G 8, 0x8UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "59494150" ]
    |> is [ G 8, 0xffffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "59494150" ]
    |> is [ G 8, 0xfedcba997654320fUL ]

  /// <summary>
  /// 59094b3c, dclo a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dclo $8,$9, the MIPS64 instruction binutils reads this word as.
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DCLO``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59094b3c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59094b3c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59094b3c" ]
    |> is [ G 8, 0x7UL ]

  /// <summary>
  /// 59095b3c, dclz a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dclz $8,$9, the MIPS64 instruction binutils reads this word as.
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DCLZ``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59095b3c" ]
    |> is [ G 8, 0x3eUL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59095b3c" ]
    |> is [ G 8, 0x3fUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59095b3c" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 5928ab3c, ddiv a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ddiv $0,$8,$9, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DDIV``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5928ab3c" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5928ab3c" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5928ab3c" ]
    |> is [ Hi, 0x123456789abcdefUL ]

  /// <summary>
  /// 5928bb3c, ddivu a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ddivu $0,$8,$9, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DDIVU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5928bb3c" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5928bb3c" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5928bb3c" ]
    |> is [ Hi, 0x123456789abcdefUL ]

  /// <summary>
  /// 0000e37c, deret, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DERET``() =
    [ Status, 0x10UL ]
    |> run um [ "0000e37c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000e37c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000e37c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5909006c, dext a4, a5, 0x1, 0x1, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after dext $8,$9,0x1,0x1, the MIPS64 instruction binutils reads
  /// this word as. the lift has to change what QEMU changed and nothing else,
  /// over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DEXT``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5909006c" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5909006c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5909006c" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 59090064, dextm a4, a5, 0x1, 0x21, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after dext $8,$9,0x1,0x21, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DEXTM``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090064" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090064" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090064" ]
    |> is [ G 8, 0x3b2a1908UL ]

  /// <summary>
  /// 59090014, dextu a4, a5, 0x20, 0x1, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after dext $8,$9,0x20,0x1, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DEXTU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090014" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090014" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090014" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 0008477c, di a4, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DI``() =
    [ G 8, 0x7UL; Status, 0x10UL ]
    |> run um [ "0008477c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "0008477c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "0008477c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5909084c, dins a4, a5, 0x1, 0x1, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after dins $8,$9,0x1,0x1, the MIPS64 instruction binutils reads
  /// this word as. the lift has to change what QEMU changed and nothing else,
  /// over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DINS``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5909084c" ]
    |> is []
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5909084c" ]
    |> is []
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5909084c" ]
    |> is [ G 8, 0x123456789abcdedUL ]

  /// <summary>
  /// 59090044, dinsm a4, a5, 0x1, 0x20, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after dins $8,$9,0x1,0x20, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DINSM``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090044" ]
    |> is []
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090044" ]
    |> is [ G 8, 0x7ffffffe00000003UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090044" ]
    |> is [ G 8, 0x1234566eca86421UL ]

  /// <summary>
  /// 59090034, dinsu a4, a5, 0x20, 0x1, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after dins $8,$9,0x20,0x1, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DINSU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090034" ]
    |> is [ G 8, 0x100000007UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090034" ]
    |> is []
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090034" ]
    |> is [ G 8, 0x123456689abcdefUL ]

  /// <summary>
  /// 0128ab3c, div a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DIV``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0128ab3c" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0128ab3c" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0128ab3c" ]
    |> is [ Hi, 0xfffffffff6e5d4bfUL; Lo, 0xfffffffffffffffaUL ]

  /// <summary>
  /// 54c410f0, div.s f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after div.s $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DIV.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run um [ "54c410f0" ]
    |> is [ F 2, 0x3fc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run um [ "54c410f0" ]
    |> is [ F 2, 0xc1000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run um [ "54c410f0" ]
    |> is [ F 2, 0x45fa0000UL ]

  /// <summary>
  /// 0128bb3c, divu a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DIVU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0128bb3c" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0128bb3c" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0128bb3c" ]
    |> is [ Hi, 0xa3d70a7UL; Lo, 0x7UL ]

  /// <summary>
  /// 582208fc, dmfc0 at, 0x2, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmfc0 $1,$2,1, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts the
  /// lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMFC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run um [ "582208fc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "582208fc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "582208fc" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5502243b, dmfc1 a4, f2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmfc1 $8,$f2, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMFC1``() =
    [ G 8, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run um [ "5502243b" ]
    |> is [ G 8, 0x1122334455667788UL ]
    [ G 8, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run um [ "5502243b" ]
    |> is [ G 8, 0xbf800000UL ]
    [ G 8, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run um [ "5502243b" ]
    |> is [ G 8, 0x8899aabbccddeeffUL ]

  /// <summary>
  /// 00226d3c, dmfc2 at, 0x2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmfc2 $1,$2, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGILL (UndefinedInstruction here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMFC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "00226d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "00226d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "00226d3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 58220afc, dmtc0 at, 0x2, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmtc0 $1,$2,1, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts the
  /// lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMTC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run um [ "58220afc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "58220afc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "58220afc" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 55022c3b, dmtc1 a4, f2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmtc1 $8,$f2, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMTC1``() =
    [ G 8, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run um [ "55022c3b" ]
    |> is [ F 2, 0x7UL ]
    [ G 8, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run um [ "55022c3b" ]
    |> is [ F 2, 0x7fffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run um [ "55022c3b" ]
    |> is [ F 2, 0x123456789abcdefUL ]

  /// <summary>
  /// 00227d3c, dmtc2 at, 0x2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmtc2 $1,$2, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGILL (UndefinedInstruction here); the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMTC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "00227d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "00227d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "00227d3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 59288b3c, dmult a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmult $8,$9, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMULT``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59288b3c" ]
    |> is [ Lo, 0x15UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59288b3c" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59288b3c" ]
    |> is [ Hi, 0xfffeb49923cc0953UL; Lo, 0x2236d88fe5618cf0UL ]

  /// <summary>
  /// 59289b3c, dmultu a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dmultu $8,$9, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DMULTU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59289b3c" ]
    |> is [ Lo, 0x15UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59289b3c" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59289b3c" ]
    |> is [ Hi, 0x121fa00ad77d742UL; Lo, 0x2236d88fe5618cf0UL ]

  /// <summary>
  /// 590908c0, drotr a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dror $8,$9,0x1, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DROTR``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "590908c0" ]
    |> is [ G 8, 0x8000000000000001UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "590908c0" ]
    |> is [ G 8, 0x8000000000000000UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "590908c0" ]
    |> is [ G 8, 0x7f6e5d4c3b2a1908UL ]

  /// <summary>
  /// 590908c8, drotr32 a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after dror32 $8,$9,0x1, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DROTR32``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "590908c8" ]
    |> is [ G 8, 0x180000000UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "590908c8" ]
    |> is [ G 8, 0x80000000UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "590908c8" ]
    |> is [ G 8, 0x3b2a19087f6e5d4cUL ]

  /// <summary>
  /// 592a40d0, drotrv a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after drorv $8,$9,$10, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DROTRV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "592a40d0" ]
    |> is [ G 8, 0x1800000000000000UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "592a40d0" ]
    |> is [ G 8, 0x4UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "592a40d0" ]
    |> is [ G 8, 0xfdb97530eca86421UL ]

  /// <summary>
  /// 59097b3c, dsbh a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsbh $8,$9, the MIPS64 instruction binutils reads this word as.
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSBH``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59097b3c" ]
    |> is [ G 8, 0x300UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59097b3c" ]
    |> is [ G 8, 0x100UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59097b3c" ]
    |> is [ G 8, 0xdcfe98ba54761032UL ]

  /// <summary>
  /// 5909fb3c, dshd a4, a5, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dshd $8,$9, the MIPS64 instruction binutils reads this word as.
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSHD``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5909fb3c" ]
    |> is [ G 8, 0x3000000000000UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "5909fb3c" ]
    |> is [ G 8, 0x1000000000000UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "5909fb3c" ]
    |> is [ G 8, 0x32107654ba98fedcUL ]

  /// <summary>
  /// 59090800, dsll a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsll $8,$9,0x1, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSLL``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090800" ]
    |> is [ G 8, 0x6UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090800" ]
    |> is [ G 8, 0x2UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090800" ]
    |> is [ G 8, 0xfdb97530eca86420UL ]

  /// <summary>
  /// 59090808, dsll32 a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsll32 $8,$9,0x1, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSLL32``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090808" ]
    |> is [ G 8, 0x600000000UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090808" ]
    |> is [ G 8, 0x200000000UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090808" ]
    |> is [ G 8, 0xeca8642000000000UL ]

  /// <summary>
  /// 592a4010, dsllv a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsllv $8,$9,$10, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSLLV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "592a4010" ]
    |> is [ G 8, 0x60UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "592a4010" ]
    |> is [ G 8, 0x4000000000000000UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "592a4010" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 59090880, dsra a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsra $8,$9,0x1, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRA``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090880" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090880" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090880" ]
    |> is [ G 8, 0xff6e5d4c3b2a1908UL ]

  /// <summary>
  /// 59090888, dsra32 a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsra32 $8,$9,0x1, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRA32``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090888" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090888" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090888" ]
    |> is [ G 8, 0xffffffffff6e5d4cUL ]

  /// <summary>
  /// 592a4090, dsrav a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsrav $8,$9,$10, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRAV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "592a4090" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "592a4090" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "592a4090" ]
    |> is [ G 8, 0xffffffffffffffffUL ]

  /// <summary>
  /// 59090840, dsrl a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsrl $8,$9,0x1, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRL``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090840" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090840" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090840" ]
    |> is [ G 8, 0x7f6e5d4c3b2a1908UL ]

  /// <summary>
  /// 59090848, dsrl32 a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsrl32 $8,$9,0x1, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRL32``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "59090848" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL ]
    |> run um [ "59090848" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL ]
    |> run um [ "59090848" ]
    |> is [ G 8, 0x7f6e5d4cUL ]

  /// <summary>
  /// 592a4050, dsrlv a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsrlv $8,$9,$10, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSRLV``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "592a4050" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "592a4050" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "592a4050" ]
    |> is [ G 8, 0x1UL ]

  /// <summary>
  /// 59494190, dsub a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsub $8,$9,$10, the MIPS64 instruction binutils reads this word
  /// as. QEMU raised SIGFPE (Exception IntegerOverflow here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSUB``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "59494190" ]
    |> is [ G 8, 0xfffffffffffffffeUL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "59494190" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "59494190" ]
    |> is [ G 8, 0xfedcba9776543211UL ]
    [ G 8, 0x7UL; G 9, 0x8000000000000000UL; G 10, 0x1UL ]
    |> run um [ "59494190" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 594941d0, dsubu a4, a5, a6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after dsubu $8,$9,$10, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 DSUBU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "594941d0" ]
    |> is [ G 8, 0xfffffffffffffffeUL ]
    [ G 8, 0x7fffffffffffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "594941d0" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x123456789abcdefUL; G 9, 0xfedcba9876543210UL; G 10, 0xffffffffUL ]
    |> run um [ "594941d0" ]
    |> is [ G 8, 0xfedcba9776543211UL ]

  /// <summary>
  /// 00001800, ehb, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 EHB``() =
    []
    |> run um [ "00001800" ]
    |> is []
    []
    |> run um [ "00001800" ]
    |> is []
    []
    |> run um [ "00001800" ]
    |> is []

  /// <summary>
  /// 0008577c, ei a4, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 EI``() =
    [ G 8, 0x7UL; Status, 0x10UL ]
    |> run um [ "0008577c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "0008577c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 8, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "0008577c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0000f37c, eret, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ERET``() =
    [ Status, 0x10UL ]
    |> run um [ "0000f37c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000f37c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0000f37c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 0001f37c, eretnc, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10 puts
  /// the lift in User Mode, the mode QEMU runs every word in; the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 ERETNC``() =
    [ Status, 0x10UL ]
    |> run um [ "0001f37c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0001f37c" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run um [ "0001f37c" ]
    |> raises [ UndefinedInstruction ] []
