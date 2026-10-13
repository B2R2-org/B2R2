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
/// One test for each instruction of microMIPS64 5.04: EXT to NOP.
///
/// <para>A value test runs a word of the instruction under QEMU over a few
/// sets of register values, memory and FCSR, and has the lift change what
/// QEMU changed, raise what QEMU raised, and nothing else; every value it
/// expects is QEMU's (optest-mips/oracle). A structural test says in its own
/// comment what it checks and why no value test could be had.</para>
/// </summary>
[<TestClass>]
type ManualLifterTests7() =
  let um =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSISAMode.MicroMIPS)

  /// <summary>
  /// 0109006c, ext a4, a5, 0x1, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 EXT``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0109006c" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0109006c" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0109006c" ]
    |> is [ G 8, 0x0UL ]

  /// <summary>
  /// 5444033b, floor.l.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after floor.l.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 FLOOR.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "5444033b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "5444033b" ]
    |> is [ F 2, 0xfffffffffffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "5444033b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 54440b3b, floor.w.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after floor.w.s $f2,$f4, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 FLOOR.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run um [ "54440b3b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run um [ "54440b3b" ]
    |> is [ F 2, 0xfffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run um [ "54440b3b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 0109084c, ins a4, a5, 0x1, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 INS``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "0109084c" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "0109084c" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "0109084c" ]
    |> is [ G 8, 0xffffffff89abcdedUL ]

  /// <summary>
  /// d4030000, j 0x20060000 (binutils: j 20060000). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20060000 (the target
  /// binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 J``() =
    let words = [ "d4030000"; "00000000" ]
    ownsJump um "d4030000" false
    goes um words [] 0x20060000UL

  /// <summary>
  /// f4030000, jal 0x20060000 (binutils: jal 20060000). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20060000 (the target binutils reads) when it always does; ra becomes
  /// 0x20100009 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JAL``() =
    let words = [ "f4030000"; "00000000" ]
    ownsJump um "f4030000" false
    goes um words [] 0x20060000UL
    []
    |> run um words
    |> is [ G 31, 0x20100009UL ]

  /// <summary>
  /// 01090f3c, jalr a4, a5 (binutils: jalr $8,$9). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20100400 when G 9 is
  /// 0x20100401; the jump goes on in MicroMIPS; the link register becomes
  /// 0x20100009 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALR``() =
    let words = [ "01090f3c"; "00000000" ]
    ownsJump um "01090f3c" false
    goes um words [ G 9, 0x20100401UL ] 0x20100400UL
    switches um words [ G 9, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 9, 0x20100401UL ]
    |> run um words
    |> is [ G 8, 0x20100009UL ]

  /// <summary>
  /// 01091f3c, jalr.hb a4, a5 (binutils: jalr.hb $8,$9). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100400 when G 9 is 0x20100401; the jump goes on in MicroMIPS; the link
  /// register becomes 0x20100009 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALR.HB``() =
    let words = [ "01091f3c"; "00000000" ]
    ownsJump um "01091f3c" false
    goes um words [ G 9, 0x20100401UL ] 0x20100400UL
    switches um words [ G 9, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 9, 0x20100401UL ]
    |> run um words
    |> is [ G 8, 0x20100009UL ]

  /// <summary>
  /// 45c1, jalr at (binutils: jalr $1). A branch is not run against QEMU: it
  /// moves the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is left to the delay
  /// slot, which holds a NOP; control goes to 0x20100400 when G 1 is
  /// 0x20100401; the jump goes on in MicroMIPS; ra becomes 0x20100007 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALR16``() =
    let words = [ "45c1"; "00000000" ]
    ownsJump um "45c1" false
    goes um words [ G 1, 0x20100401UL ] 0x20100400UL
    switches um words [ G 1, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 1, 0x20100401UL ]
    |> run um words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// 01094f3c, jalrs a4, a5 (binutils: jalrs $8,$9). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100400 when G 9 is 0x20100401; the jump goes on in MicroMIPS; the link
  /// register becomes 0x20100007 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALRS``() =
    let words = [ "01094f3c"; "0c00" ]
    ownsJump um "01094f3c" false
    goes um words [ G 9, 0x20100401UL ] 0x20100400UL
    switches um words [ G 9, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 9, 0x20100401UL ]
    |> run um words
    |> is [ G 8, 0x20100007UL ]

  /// <summary>
  /// 01095f3c, jalrs.hb a4, a5 (binutils: jalrs.hb $8,$9). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100400 when G 9 is 0x20100401; the jump goes on in MicroMIPS; the link
  /// register becomes 0x20100007 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALRS.HB``() =
    let words = [ "01095f3c"; "0c00" ]
    ownsJump um "01095f3c" false
    goes um words [ G 9, 0x20100401UL ] 0x20100400UL
    switches um words [ G 9, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 9, 0x20100401UL ]
    |> run um words
    |> is [ G 8, 0x20100007UL ]

  /// <summary>
  /// 45e1, jalrs at (binutils: jalrs $1). A branch is not run against QEMU: it
  /// moves the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is left to the delay
  /// slot, which holds a NOP; control goes to 0x20100400 when G 1 is
  /// 0x20100401; the jump goes on in MicroMIPS; ra becomes 0x20100005 and
  /// nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALRS16``() =
    let words = [ "45e1"; "0c00" ]
    ownsJump um "45e1" false
    goes um words [ G 1, 0x20100401UL ] 0x20100400UL
    switches um words [ G 1, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 1, 0x20100401UL ]
    |> run um words
    |> is [ G 31, 0x20100005UL ]

  /// <summary>
  /// 74030000, jals 0x20060000 (binutils: jals 20060000). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20060000 (the target binutils reads) when it always does; ra becomes
  /// 0x20100007 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALS``() =
    let words = [ "74030000"; "0c00" ]
    ownsJump um "74030000" false
    goes um words [] 0x20060000UL
    []
    |> run um words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// f0030000, jalx 0x200c0000 (binutils: jalx 200c0000). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x200c0000 (the target binutils reads) when it always does; the jump goes
  /// on in MIPS; ra becomes 0x20100009 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JALX``() =
    let words = [ "f0030000"; "00000000" ]
    ownsJump um "f0030000" false
    goes um words [] 0x200c0000UL
    switches um words [] InterJmpKind.SwitchToMIPS
    []
    |> run um words
    |> is [ G 31, 0x20100009UL ]

  /// <summary>
  /// 00090f3c, jalr r0, a5 (binutils: jr $9). A branch is not run against QEMU:
  /// it moves the PC, and its delay slot makes one word meaningless to run
  /// alone. Checked structurally from the manual: the transfer is left to the
  /// delay slot, which holds a NOP; control goes to 0x20100400 when G 9 is
  /// 0x20100401; the jump goes on in MicroMIPS.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JR``() =
    let words = [ "00090f3c"; "00000000" ]
    ownsJump um "00090f3c" false
    goes um words [ G 9, 0x20100401UL ] 0x20100400UL
    switches um words [ G 9, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS

  /// <summary>
  /// 00091f3c, jalr.hb r0, a5 (binutils: jr.hb $9). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20100400 when G 9 is
  /// 0x20100401; the jump goes on in MicroMIPS.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JR.HB``() =
    let words = [ "00091f3c"; "00000000" ]
    ownsJump um "00091f3c" false
    goes um words [ G 9, 0x20100401UL ] 0x20100400UL
    switches um words [ G 9, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS

  /// <summary>
  /// 4581, jr at (binutils: jr $1). A branch is not run against QEMU: it moves
  /// the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is left to the delay
  /// slot, which holds a NOP; control goes to 0x20100400 when G 1 is
  /// 0x20100401; the jump goes on in MicroMIPS.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JR16``() =
    let words = [ "4581"; "00000000" ]
    ownsJump um "4581" false
    goes um words [ G 1, 0x20100401UL ] 0x20100400UL
    switches um words [ G 1, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS

  /// <summary>
  /// 4701, jraddiusp 0x4 (binutils: jraddiusp 4). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is the
  /// branch's own, there being no delay slot; control goes to 0x20100400 when G
  /// 31 is 0x20100401; the jump goes on in MicroMIPS; sp grows by 4.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JRADDIUSP``() =
    let words = [ "4701" ]
    ownsJump um "4701" true
    goes um words [ G 31, 0x20100401UL ] 0x20100400UL
    switches um words [ G 31, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS
    [ G 29, 0x20200000UL; G 31, 0x20100401UL ]
    |> run um words
    |> is [ G 29, 0x20200004UL ]

  /// <summary>
  /// 45a1, jrc at (binutils: jrc $1). A branch is not run against QEMU: it
  /// moves the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is the branch's own,
  /// there being no delay slot; control goes to 0x20100400 when G 1 is
  /// 0x20100401; the jump goes on in MicroMIPS.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 JRC``() =
    let words = [ "45a1" ]
    ownsJump um "45a1" true
    goes um words [ G 1, 0x20100401UL ] 0x20100400UL
    switches um words [ G 1, 0x20100401UL ] InterJmpKind.SwitchToMicroMIPS

  /// <summary>
  /// 1d090001, lb a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LB``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x1d8297ff9f58fdaaUL
        M 0x20200080UL, 0x6d6d8410e74d61cdUL
        M 0x20200088UL, 0x5ca5975d620d74efUL ]
    given0
    |> run um [ "1d090001" ]
    |> is [ G 8, 0x6dUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xdabaa3b35cdb29edUL
        M 0x20200080UL, 0x8ac01adecd58805cUL
        M 0x20200088UL, 0x3881035086aeb06UL ]
    given1
    |> run um [ "1d090001" ]
    |> is [ G 8, 0xffffffffffffff8aUL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x24aba6780245a1bdUL
        M 0x20200080UL, 0x55d20d8622f6318bUL
        M 0x20200088UL, 0x206367a6776fe74dUL ]
    given2
    |> run um [ "1d090001" ]
    |> is [ G 8, 0x55UL ]

  /// <summary>
  /// 61096801, lbe a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LBE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xbdda38d14f89029fUL
        M 0x20200080UL, 0x39c761f75f5992aUL
        M 0x20200088UL, 0xc03cd94d5cf204dcUL ]
    given0
    |> run um [ "61096801" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x7f8e706de5b234ceUL
        M 0x20200080UL, 0x3247d34a4f2e299UL
        M 0x20200088UL, 0x83b0e3fca2245c8eUL ]
    given1
    |> run um [ "61096801" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xa5cb365a01bc3a11UL
        M 0x20200080UL, 0xb110f21136cc505UL
        M 0x20200088UL, 0xd9c58f2f62aa9a4cUL ]
    given2
    |> run um [ "61096801" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 15090001, lbu a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LBU``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xb3d2ce386ab30aceUL
        M 0x20200080UL, 0x102cf778e34b207UL
        M 0x20200088UL, 0x518bcd5e63511062UL ]
    given0
    |> run um [ "15090001" ]
    |> is [ G 8, 0x1UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x648d306faa163331UL
        M 0x20200080UL, 0xa81ed140378fc9d7UL
        M 0x20200088UL, 0x36ea4355abaf89b7UL ]
    given1
    |> run um [ "15090001" ]
    |> is [ G 8, 0xa8UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x3867e7561c976ef8UL
        M 0x20200080UL, 0x9efa22786c55b016UL
        M 0x20200088UL, 0x670632e7af06cd5cUL ]
    given2
    |> run um [ "15090001" ]
    |> is [ G 8, 0x9eUL ]

  /// <summary>
  /// 0901, lbu v0, 1(s0), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LBU16``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x8191332abd2fd5feUL
        M 0x20200080UL, 0x5e46ce4894ef04b1UL
        M 0x20200088UL, 0x34d3446c24a20c5dUL ]
    given0
    |> run um [ "0901" ]
    |> is [ G 2, 0x5eUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xb35ddea3470f8d22UL
        M 0x20200080UL, 0x81482865707d689fUL
        M 0x20200088UL, 0x244f1b55f084dddcUL ]
    given1
    |> run um [ "0901" ]
    |> is [ G 2, 0x81UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x7a54e044e1259e30UL
        M 0x20200080UL, 0xbdb5482467e6999eUL
        M 0x20200088UL, 0x691575f5f0f20c14UL ]
    given2
    |> run um [ "0901" ]
    |> is [ G 2, 0xbdUL ]

  /// <summary>
  /// 61096001, lbue a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LBUE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x239b7ec97e1673fbUL
        M 0x20200080UL, 0x7a28f3e9ec312eaeUL
        M 0x20200088UL, 0xc02b2f3f3ebe4d8cUL ]
    given0
    |> run um [ "61096001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe8d4bd6bb0a72edbUL
        M 0x20200080UL, 0x3d69efb9fb84ce11UL
        M 0x20200088UL, 0x51265d3a0cbde505UL ]
    given1
    |> run um [ "61096001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xd6f873ad81926bdaUL
        M 0x20200080UL, 0xf82de1737d31b6c2UL
        M 0x20200088UL, 0x95e60cbb36963ef8UL ]
    given2
    |> run um [ "61096001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// dd090001, ld a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ld $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LD``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x9ba80fdf14aeda88UL
        M 0x20200080UL, 0x1a0bfcd3a47ae116UL
        M 0x20200088UL, 0xe5d6324154ad3904UL ]
    given0
    |> run um [ "dd090001" ]
    |> is [ G 8, 0x1a0bfcd3a47ae116UL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xd3f1d2ad363ddf48UL
        M 0x20200080UL, 0x4c1cdf62cf941b1bUL
        M 0x20200088UL, 0x68eecc93b0e84cdcUL ]
    given1
    |> run um [ "dd090001" ]
    |> is [ G 8, 0x4c1cdf62cf941b1bUL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x80465652711ddceUL
        M 0x20200080UL, 0x1901e665a42727beUL
        M 0x20200088UL, 0x109de3cddd795444UL ]
    given2
    |> run um [ "dd090001" ]
    |> is [ G 8, 0x1901e665a42727beUL ]

  /// <summary>
  /// bc480001, ldc1 f2, 1(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ldc1 $f2,1($8), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDC1``() =
    let given0 =
      [ G 8, 0x2020007fUL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xa34fa19bcd672d96UL
        M 0x20200080UL, 0xb4f07a3b88c5050fUL
        M 0x20200088UL, 0x1b535e2bf5e0fe3fUL ]
    given0
    |> run um [ "bc480001" ]
    |> is [ F 2, 0xb4f07a3b88c5050fUL ]
    let given1 =
      [ G 8, 0x2020007fUL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x9eeb0ed349ddf3ccUL
        M 0x20200080UL, 0xc3e99c7cea3fbbf2UL
        M 0x20200088UL, 0x78153d049952a0a1UL ]
    given1
    |> run um [ "bc480001" ]
    |> is [ F 2, 0xc3e99c7cea3fbbf2UL ]
    let given2 =
      [ G 8, 0x2020007fUL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x82df3e0f61799ae2UL
        M 0x20200080UL, 0x43f8ba331dd84cf4UL
        M 0x20200088UL, 0x75b9f52c5b087c68UL ]
    given2
    |> run um [ "bc480001" ]
    |> is [ F 2, 0x43f8ba331dd84cf4UL ]

  /// <summary>
  /// 20002001, ldc2 0x0, 1(r0), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDC2``() =
    let given0 =
      [ M 0x20200078UL, 0xe7a2950cbe977fb4UL
        M 0x20200080UL, 0xa19062729f051c93UL
        M 0x20200088UL, 0xd148452b6d995e9aUL ]
    given0
    |> run um [ "20002001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0x7c1b4dbd10bc8a4UL
        M 0x20200080UL, 0xf170548785dfad6fUL
        M 0x20200088UL, 0xb7a8c51df44ab4f8UL ]
    given1
    |> run um [ "20002001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0x607c6e1c58c1368fUL
        M 0x20200080UL, 0x774cb6fe88d64daUL
        M 0x20200088UL, 0x124203ff468372d6UL ]
    given2
    |> run um [ "20002001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 61094001, ldl a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ldl $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDL``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x9faadc7403d56c61UL
        M 0x20200080UL, 0x20ce34dbe78cfa5fUL
        M 0x20200088UL, 0xe23249d45c4b1ceaUL ]
    given0
    |> run um [ "61094001" ]
    |> is [ G 8, 0xce34dbe78cfa5f07UL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0xc0272ce82975efbcUL
        M 0x20200080UL, 0xf062b48220306bddUL
        M 0x20200088UL, 0xef64ff168f812c55UL ]
    given1
    |> run um [ "61094001" ]
    |> is [ G 8, 0xb48220306bddffffUL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0xf24ac23eb1ecc6eaUL
        M 0x20200080UL, 0x99c87ffb4f9db22eUL
        M 0x20200088UL, 0x1623eb5eea6ed408UL ]
    given2
    |> run um [ "61094001" ]
    |> is [ G 8, 0x9db22e6789abcdefUL ]

  /// <summary>
  /// 20447008, ldm s0, s1, 8(a0), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ld $16,8($4); ld $17,16($4), the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDM``() =
    let given0 =
      [ G 4, 0x20200078UL
        G 16, 0x7UL
        G 17, 0x3UL
        M 0x20200078UL, 0x27fda155f571517bUL
        M 0x20200080UL, 0xed7895add9e8b22fUL
        M 0x20200088UL, 0xfb767eb2e017aa1eUL ]
    given0
    |> run um [ "20447008" ]
    |> is [ G 16, 0xed7895add9e8b22fUL; G 17, 0xfb767eb2e017aa1eUL ]
    let given1 =
      [ G 4, 0x20200078UL
        G 16, 0x7fffffffffffffffUL
        G 17, 0x1UL
        M 0x20200078UL, 0x50c0b28a0601c3dfUL
        M 0x20200080UL, 0xde82b872f8f274daUL
        M 0x20200088UL, 0x3c8805ccb2783439UL ]
    given1
    |> run um [ "20447008" ]
    |> is [ G 16, 0xde82b872f8f274daUL; G 17, 0x3c8805ccb2783439UL ]
    let given2 =
      [ G 4, 0x20200078UL
        G 16, 0x123456789abcdefUL
        G 17, 0xfedcba9876543210UL
        M 0x20200078UL, 0xfa10dc5d2b043858UL
        M 0x20200080UL, 0xbabaa95e5a789274UL
        M 0x20200088UL, 0x24c16fa9855a083bUL ]
    given2
    |> run um [ "20447008" ]
    |> is [ G 16, 0xbabaa95e5a789274UL; G 17, 0x24c16fa9855a083bUL ]

  /// <summary>
  /// 20444008, ldp v0, v1, 8(a0), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ld $2,8($4); ld $3,16($4), the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDP``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x3UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0x4080e5e7b00d8b62UL
        M 0x20200080UL, 0x845f704d569ecdbbUL
        M 0x20200088UL, 0x7fe419e97141fb2aUL ]
    given0
    |> run um [ "20444008" ]
    |> is [ G 2, 0x845f704d569ecdbbUL; G 3, 0x7fe419e97141fb2aUL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x1UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0x5536d28a94101c5dUL
        M 0x20200080UL, 0xb85714e23168c88dUL
        M 0x20200088UL, 0xb99318cb1d7af2e9UL ]
    given1
    |> run um [ "20444008" ]
    |> is [ G 2, 0xb85714e23168c88dUL; G 3, 0xb99318cb1d7af2e9UL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0xfedcba9876543210UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0xa84bb0a5cf63887bUL
        M 0x20200080UL, 0x67938a78d290f463UL
        M 0x20200088UL, 0x5cecc62518211570UL ]
    given2
    |> run um [ "20444008" ]
    |> is [ G 2, 0x67938a78d290f463UL; G 3, 0x5cecc62518211570UL ]

  /// <summary>
  /// 61095001, ldr a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ldr $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDR``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x3cfb40b0ef9c7459UL
        M 0x20200080UL, 0xfdedded5cf56b7abUL
        M 0x20200088UL, 0xb3f8753e878f3fd3UL ]
    given0
    |> run um [ "61095001" ]
    |> is [ G 8, 0xfdedUL ]
    let given1 =
      [ G 8, 0x7fffffffffffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0xd932f6b028fa9e7bUL
        M 0x20200080UL, 0xeb4f9b18eb7e43fcUL
        M 0x20200088UL, 0x82bce50360b30de0UL ]
    given1
    |> run um [ "61095001" ]
    |> is [ G 8, 0x7fffffffffeb4f9bUL ]
    let given2 =
      [ G 8, 0x123456789abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0xb054e8716fe14156UL
        M 0x20200080UL, 0x7ea1def79b393499UL
        M 0x20200088UL, 0x9d292378ca743515UL ]
    given2
    |> run um [ "61095001" ]
    |> is [ G 8, 0x1237ea1def79b39UL ]

  /// <summary>
  /// 552810c8, ldxc1 f2, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after ldxc1 $f2,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LDXC1``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0x9cf1a0ca54641636UL
        M 0x20200080UL, 0x4f706b4ef9483f79UL
        M 0x20200088UL, 0xdf0c38f5a46e1be1UL ]
    given0
    |> run um [ "552810c8" ]
    |> is [ F 2, 0x4f706b4ef9483f79UL ]
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x891b0ec9c8bafa51UL
        M 0x20200080UL, 0xaeabed27d22be16UL
        M 0x20200088UL, 0x170ef0ab51c624bdUL ]
    given1
    |> run um [ "552810c8" ]
    |> is [ F 2, 0xaeabed27d22be16UL ]
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x8cf99becc9551543UL
        M 0x20200080UL, 0xc87db1b66814b13bUL
        M 0x20200088UL, 0xd5997a560eb82e60UL ]
    given2
    |> run um [ "552810c8" ]
    |> is [ F 2, 0xc87db1b66814b13bUL ]

  /// <summary>
  /// 3d090001, lh a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LH``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x1269e668c5b04c54UL
        M 0x20200080UL, 0xf2ec55aed372641bUL
        M 0x20200088UL, 0xf565910831e8fdc8UL ]
    given0
    |> run um [ "3d090001" ]
    |> is [ G 8, 0xfffffffffffff2ecUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xba3995c7b79b4c9UL
        M 0x20200080UL, 0xabaac5e0fa097690UL
        M 0x20200088UL, 0x1ebcf4c499ceca88UL ]
    given1
    |> run um [ "3d090001" ]
    |> is [ G 8, 0xffffffffffffabaaUL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x1e988eca98aef980UL
        M 0x20200080UL, 0xd5cd2a13cfebb9c7UL
        M 0x20200088UL, 0xab82ba98ad43109cUL ]
    given2
    |> run um [ "3d090001" ]
    |> is [ G 8, 0xffffffffffffd5cdUL ]

  /// <summary>
  /// 61096a01, lhe a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LHE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xd3736001a222376bUL
        M 0x20200080UL, 0xa2b6a3a14c0a212fUL
        M 0x20200088UL, 0x4d122fac5cf950deUL ]
    given0
    |> run um [ "61096a01" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe406a6f32ea2ea9eUL
        M 0x20200080UL, 0x69944239bc17b670UL
        M 0x20200088UL, 0xd2e9159e9aef8884UL ]
    given1
    |> run um [ "61096a01" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xaec8ba8ee5ef3d54UL
        M 0x20200080UL, 0x40f268360331f2dfUL
        M 0x20200088UL, 0xb806285b1c4a8f46UL ]
    given2
    |> run um [ "61096a01" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 35090001, lhu a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LHU``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x8a55f23b81f4f3c6UL
        M 0x20200080UL, 0xe13f765516837fa8UL
        M 0x20200088UL, 0x3d05be6673094397UL ]
    given0
    |> run um [ "35090001" ]
    |> is [ G 8, 0xe13fUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x13c075a977686442UL
        M 0x20200080UL, 0x721044643a08132cUL
        M 0x20200088UL, 0x179ae07e7a49262fUL ]
    given1
    |> run um [ "35090001" ]
    |> is [ G 8, 0x7210UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x545ecb306c8050b7UL
        M 0x20200080UL, 0x311626417289dbd7UL
        M 0x20200088UL, 0x965b2a6b0ab0e762UL ]
    given2
    |> run um [ "35090001" ]
    |> is [ G 8, 0x3116UL ]

  /// <summary>
  /// 2901, lhu v0, 2(s0), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LHU16``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x439f0da0e050cb1eUL
        M 0x20200080UL, 0x978d421fe1f21a3fUL
        M 0x20200088UL, 0x49c62b9368eb8c50UL ]
    given0
    |> run um [ "2901" ]
    |> is [ G 2, 0x978dUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x43e6299f74c2e5ecUL
        M 0x20200080UL, 0x9556cdb84b7ec920UL
        M 0x20200088UL, 0x2d4f4444306c14c6UL ]
    given1
    |> run um [ "2901" ]
    |> is [ G 2, 0x9556UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x53de71ba0666239fUL
        M 0x20200080UL, 0xd4d0af2d0c246320UL
        M 0x20200088UL, 0x6ffd80863da46e48UL ]
    given2
    |> run um [ "2901" ]
    |> is [ G 2, 0xd4d0UL ]

  /// <summary>
  /// 61096201, lhue a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LHUE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe50ee0c6d801301UL
        M 0x20200080UL, 0xbc2a46ea3d6c7951UL
        M 0x20200088UL, 0x4b8c9c7418b889b1UL ]
    given0
    |> run um [ "61096201" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x83e8141b5d69af25UL
        M 0x20200080UL, 0xd1eb49cf70daf60bUL
        M 0x20200088UL, 0x281a751341022d53UL ]
    given1
    |> run um [ "61096201" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xd5078017d26d4230UL
        M 0x20200080UL, 0xc17c8638f32567b7UL
        M 0x20200088UL, 0xdfe277efa35999dcUL ]
    given2
    |> run um [ "61096201" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// ed01, addiu v0, r0, 0x1, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LI16``() =
    [ G 2, 0x7UL ]
    |> run um [ "ed01" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL ]
    |> run um [ "ed01" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run um [ "ed01" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 61093001, ll a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LL``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x3805cd4cd1844ed5UL
        M 0x20200080UL, 0x52d58f720b7b547eUL
        M 0x20200088UL, 0xc1d4a1f81f8388e8UL ]
    given0
    |> run um [ "61093001" ]
    |> is [ G 8, 0x52d58f72UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xed4ea7234d755650UL
        M 0x20200080UL, 0xdc3fbea550753fdfUL
        M 0x20200088UL, 0xadb1b4f44ea50c35UL ]
    given1
    |> run um [ "61093001" ]
    |> is [ G 8, 0xffffffffdc3fbea5UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x7c9464b6677d2f3UL
        M 0x20200080UL, 0xdd42d3bf350685e7UL
        M 0x20200088UL, 0xbc3c1cdb9a9d33cbUL ]
    given2
    |> run um [ "61093001" ]
    |> is [ G 8, 0xffffffffdd42d3bfUL ]

  /// <summary>
  /// 61097001, lld a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after lld $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LLD``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x636335ec30cee6cUL
        M 0x20200080UL, 0xa0f7746b2d605798UL
        M 0x20200088UL, 0xa467b575bd490bd6UL ]
    given0
    |> run um [ "61097001" ]
    |> is [ G 8, 0xa0f7746b2d605798UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x33fc2fb328a1ef88UL
        M 0x20200080UL, 0xf6f312a71bf68265UL
        M 0x20200088UL, 0x6cee1408f15643e2UL ]
    given1
    |> run um [ "61097001" ]
    |> is [ G 8, 0xf6f312a71bf68265UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x6b582c22ba15bbdcUL
        M 0x20200080UL, 0x29e0cfcb8e89d42cUL
        M 0x20200088UL, 0x7b307cdcfd140b07UL ]
    given2
    |> run um [ "61097001" ]
    |> is [ G 8, 0x29e0cfcb8e89d42cUL ]

  /// <summary>
  /// 61096c01, lle a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LLE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xebccab4105d3608UL
        M 0x20200080UL, 0xf1cd1deaa0449236UL
        M 0x20200088UL, 0x4ff8fd674aabdb96UL ]
    given0
    |> run um [ "61096c01" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xd1d1bc80cc52bf61UL
        M 0x20200080UL, 0x345481a2af77ee9UL
        M 0x20200088UL, 0xb46f14ac86b34570UL ]
    given1
    |> run um [ "61096c01" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x34aa33bdae21c38fUL
        M 0x20200080UL, 0x717c903a6a9f7795UL
        M 0x20200088UL, 0x93b533684a3976fbUL ]
    given2
    |> run um [ "61096c01" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 41a80001, lui a4, 0x1, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LUI``() =
    [ G 8, 0x7UL ]
    |> run um [ "41a80001" ]
    |> is [ G 8, 0x10000UL ]
    [ G 8, 0x7fffffffUL ]
    |> run um [ "41a80001" ]
    |> is [ G 8, 0x10000UL ]
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "41a80001" ]
    |> is [ G 8, 0x10000UL ]

  /// <summary>
  /// 55281148, luxc1 f2, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after luxc1 $f2,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LUXC1``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xb4a931434431b9d9UL
        M 0x20200080UL, 0x6e8e89ef8c5d8a44UL
        M 0x20200088UL, 0x4fce75340a133b51UL ]
    given0
    |> run um [ "55281148" ]
    |> is [ F 2, 0x6e8e89ef8c5d8a44UL ]
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x3ca0557c68c4149bUL
        M 0x20200080UL, 0xa5684c51f6d04cbaUL
        M 0x20200088UL, 0xd8f63937c1416d21UL ]
    given1
    |> run um [ "55281148" ]
    |> is [ F 2, 0xa5684c51f6d04cbaUL ]
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x3920c5c31acd265bUL
        M 0x20200080UL, 0x3ca1401d4ad0f5d2UL
        M 0x20200088UL, 0x9063bbf7b61317afUL ]
    given2
    |> run um [ "55281148" ]
    |> is [ F 2, 0x3ca1401d4ad0f5d2UL ]

  /// <summary>
  /// 4821, lw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LW``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xa020fcf6a1963728UL
        M 0x20200080UL, 0x3122c0fc221f6608UL
        M 0x20200088UL, 0x6be54e95871dc22eUL ]
    given0
    |> run um [ "4821" ]
    |> is [ G 1, 0x3122c0fcUL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x929bc8dcc123e82fUL
        M 0x20200080UL, 0xd5f5642548db8a3bUL
        M 0x20200088UL, 0xcd6be721fe9e6963UL ]
    given1
    |> run um [ "4821" ]
    |> is [ G 1, 0xffffffffd5f56425UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x930da9d86b59da06UL
        M 0x20200080UL, 0x7ca10f278c3bd4f7UL
        M 0x20200088UL, 0x28c40efa3708ad17UL ]
    given2
    |> run um [ "4821" ]
    |> is [ G 1, 0x7ca10f27UL ]

  /// <summary>
  /// 4821, lw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LW16``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xb28a0dde6bfdfa2aUL
        M 0x20200080UL, 0x69810fbc41e5e20dUL
        M 0x20200088UL, 0xa4866dc3519dd8b1UL ]
    given0
    |> run um [ "4821" ]
    |> is [ G 1, 0x69810fbcUL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xb34255fe7bbf7ca1UL
        M 0x20200080UL, 0xf4ef2b2a20d1a273UL
        M 0x20200088UL, 0x23c70b61738f6c0cUL ]
    given1
    |> run um [ "4821" ]
    |> is [ G 1, 0xfffffffff4ef2b2aUL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x7ff17e5afd0cf5afUL
        M 0x20200080UL, 0xca25dd1a9352a159UL
        M 0x20200088UL, 0x75322945a368a4d0UL ]
    given2
    |> run um [ "4821" ]
    |> is [ G 1, 0xffffffffca25dd1aUL ]

  /// <summary>
  /// 9c480001, lwc1 f2, 1(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after lwc1 $f2,1($8), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWC1``() =
    let given0 =
      [ G 8, 0x2020007fUL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0x608c1e952f1eee1eUL
        M 0x20200080UL, 0x5132041d2d6980c5UL
        M 0x20200088UL, 0x34c2454c85e3016aUL ]
    given0
    |> run um [ "9c480001" ]
    |> is [ F 2, 0x5132041dUL ]
    let given1 =
      [ G 8, 0x2020007fUL
        F 2, 0x40600000UL
        M 0x20200078UL, 0xd7d9cdce80d41453UL
        M 0x20200080UL, 0x442be94c2ccd0bc5UL
        M 0x20200088UL, 0xe4e9512d42328b5fUL ]
    given1
    |> run um [ "9c480001" ]
    |> is [ F 2, 0x442be94cUL ]
    let given2 =
      [ G 8, 0x2020007fUL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0xc31df1cc3d170e52UL
        M 0x20200080UL, 0xf9a4657ce6d67839UL
        M 0x20200088UL, 0x9850618cb605111aUL ]
    given2
    |> run um [ "9c480001" ]
    |> is [ F 2, 0xf9a4657cUL ]

  /// <summary>
  /// 20000001, lwc2 0x0, 1(r0), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWC2``() =
    let given0 =
      [ M 0x20200078UL, 0xb435616f82e24b9cUL
        M 0x20200080UL, 0x7f07d2ca3ea5a706UL
        M 0x20200088UL, 0x3dd09225650454daUL ]
    given0
    |> run um [ "20000001" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0x17645395c2836924UL
        M 0x20200080UL, 0xa7a5b4a147ffae1eUL
        M 0x20200088UL, 0x97b578160a57b9dcUL ]
    given1
    |> run um [ "20000001" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0xcd52e41d1488386cUL
        M 0x20200080UL, 0xd78e7a76af0a9c98UL
        M 0x20200088UL, 0x4db6283b0e2e44bUL ]
    given2
    |> run um [ "20000001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 61096e01, lwe a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x90b672a70898e683UL
        M 0x20200080UL, 0x59d95a8c34b18097UL
        M 0x20200088UL, 0x933a8872232a58b9UL ]
    given0
    |> run um [ "61096e01" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xde89528065b729adUL
        M 0x20200080UL, 0x912a6e097e173211UL
        M 0x20200088UL, 0x400cee05bc68dcb2UL ]
    given1
    |> run um [ "61096e01" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xf99a7bf337a4846aUL
        M 0x20200080UL, 0x2b6ef301ad5a9d75UL
        M 0x20200088UL, 0xad4e5c9eb7e287f2UL ]
    given2
    |> run um [ "61096e01" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4821, lw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWGP``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x46248a276cb0a5b5UL
        M 0x20200080UL, 0x1ae321647d7facc2UL
        M 0x20200088UL, 0xf97a06124f6d10f3UL ]
    given0
    |> run um [ "4821" ]
    |> is [ G 1, 0x1ae32164UL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xa4633f63f930b062UL
        M 0x20200080UL, 0xc5d6c089567c54daUL
        M 0x20200088UL, 0x4d121fd046dde9acUL ]
    given1
    |> run um [ "4821" ]
    |> is [ G 1, 0xffffffffc5d6c089UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x8885484d47376f4bUL
        M 0x20200080UL, 0x4492da8111833e9fUL
        M 0x20200088UL, 0x47442e79e0fbe105UL ]
    given2
    |> run um [ "4821" ]
    |> is [ G 1, 0x4492da81UL ]

  /// <summary>
  /// 61090001, lwl a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWL``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x4b34625818852a4eUL
        M 0x20200080UL, 0x6c08db015dbd4cafUL
        M 0x20200088UL, 0x6789a56dded7bfc2UL ]
    given0
    |> run um [ "61090001" ]
    |> is [ G 8, 0x8db0107UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0x34a83defb6a414c3UL
        M 0x20200080UL, 0xc0f0baa73220ba5cUL
        M 0x20200088UL, 0x409b3ebf33d7faa4UL ]
    given1
    |> run um [ "61090001" ]
    |> is [ G 8, 0xffffffffbaa7ffffUL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0xf9e2076db183bc7aUL
        M 0x20200080UL, 0x40466ca17968d23UL
        M 0x20200088UL, 0x9bea88095cde652dUL ]
    given2
    |> run um [ "61090001" ]
    |> is [ G 8, 0xffffffff968d23efUL ]

  /// <summary>
  /// 61096401, lwle a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWLE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0xa8feef83d42bd6c8UL
        M 0x20200080UL, 0xbf58575cd2c5b5e1UL
        M 0x20200088UL, 0xd8d4ced65dd53b3cUL ]
    given0
    |> run um [ "61096401" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        Status, 0x10UL
        M 0x20200078UL, 0xa3d0e9f671ebd395UL
        M 0x20200080UL, 0xb3a52e1626cc9f57UL
        M 0x20200088UL, 0xa8258fb1f64c94d4UL ]
    given1
    |> run um [ "61096401" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        Status, 0x10UL
        M 0x20200078UL, 0x3566caa61c92cff1UL
        M 0x20200080UL, 0xb7b1743528c05aefUL
        M 0x20200088UL, 0x21bc1bd66d07eed1UL ]
    given2
    |> run um [ "61096401" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4501, lwm s0, ra, 4(sp), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWM16``() =
    let given0 =
      [ G 16, 0x7UL
        G 29, 0x2020007cUL
        G 31, 0x3UL
        M 0x20200078UL, 0x91c39fb79a415bbcUL
        M 0x20200080UL, 0x7e0a4427674d1230UL
        M 0x20200088UL, 0x72121d5097db54c1UL ]
    given0
    |> run um [ "4501" ]
    |> is [ G 16, 0x7e0a4427UL; G 31, 0x674d1230UL ]
    let given1 =
      [ G 16, 0x7fffffffUL
        G 29, 0x2020007cUL
        G 31, 0x1UL
        M 0x20200078UL, 0x1473be90e2c3e3f1UL
        M 0x20200080UL, 0xc1efa49dad233ac3UL
        M 0x20200088UL, 0x4d2dd0ce2e4d61b8UL ]
    given1
    |> run um [ "4501" ]
    |> is [ G 16, 0xffffffffc1efa49dUL; G 31, 0xffffffffad233ac3UL ]
    let given2 =
      [ G 16, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        G 31, 0x12345678UL
        M 0x20200078UL, 0x5d4582b786322398UL
        M 0x20200080UL, 0x3bd4327761f93ed7UL
        M 0x20200088UL, 0x3bf14c41de39a0f4UL ]
    given2
    |> run um [ "4501" ]
    |> is [ G 16, 0x3bd43277UL; G 31, 0x61f93ed7UL ]

  /// <summary>
  /// 20445008, lwm s0, s1, 8(a0), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWM32``() =
    let given0 =
      [ G 4, 0x20200078UL
        G 16, 0x7UL
        G 17, 0x3UL
        M 0x20200078UL, 0x1a7c67698b5dabafUL
        M 0x20200080UL, 0xad2afa9e44169adcUL
        M 0x20200088UL, 0xd99ab98d253f5706UL ]
    given0
    |> run um [ "20445008" ]
    |> is [ G 16, 0xffffffffad2afa9eUL; G 17, 0x44169adcUL ]
    let given1 =
      [ G 4, 0x20200078UL
        G 16, 0x7fffffffUL
        G 17, 0x1UL
        M 0x20200078UL, 0xdd6821fb9a90120aUL
        M 0x20200080UL, 0xc39851c62cee62edUL
        M 0x20200088UL, 0xc175cd3b881a2017UL ]
    given1
    |> run um [ "20445008" ]
    |> is [ G 16, 0xffffffffc39851c6UL; G 17, 0x2cee62edUL ]
    let given2 =
      [ G 4, 0x20200078UL
        G 16, 0xffffffff89abcdefUL
        G 17, 0x12345678UL
        M 0x20200078UL, 0x1ea9084008959590UL
        M 0x20200080UL, 0xfafd707203b228faUL
        M 0x20200088UL, 0xbd0579fa31858366UL ]
    given2
    |> run um [ "20445008" ]
    |> is [ G 16, 0xfffffffffafd7072UL; G 17, 0x3b228faUL ]

  /// <summary>
  /// 20441008, lwp v0, v1, 8(a0), against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWP``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x3UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0xbcab2d2c134dcc83UL
        M 0x20200080UL, 0x3a3c983481fd5c70UL
        M 0x20200088UL, 0x25aa1e9cf94b3a29UL ]
    given0
    |> run um [ "20441008" ]
    |> is [ G 2, 0x3a3c9834UL; G 3, 0xffffffff81fd5c70UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x1UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0xec2d8aa178dff12dUL
        M 0x20200080UL, 0x846ca9bfaf89f4a7UL
        M 0x20200088UL, 0x43b35c82f273917UL ]
    given1
    |> run um [ "20441008" ]
    |> is [ G 2, 0xffffffff846ca9bfUL; G 3, 0xffffffffaf89f4a7UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        G 4, 0x20200078UL
        M 0x20200078UL, 0xa36d1196a4535b6cUL
        M 0x20200080UL, 0xa877e8fd82abdd45UL
        M 0x20200088UL, 0x7d34115bdc5dbca4UL ]
    given2
    |> run um [ "20441008" ]
    |> is [ G 2, 0xffffffffa877e8fdUL; G 3, 0xffffffff82abdd45UL ]

  /// <summary>
  /// 61091001, lwr a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWR``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        M 0x20200078UL, 0x425c08f8a3919e1bUL
        M 0x20200080UL, 0x9da069c9bcad8b8UL
        M 0x20200088UL, 0xd740c3d80e33befcUL ]
    given0
    |> run um [ "61091001" ]
    |> is [ G 8, 0x9daUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        M 0x20200078UL, 0xafc5d8062f66109cUL
        M 0x20200080UL, 0x1cc403c55f6a807UL
        M 0x20200088UL, 0xafd59e77593e5334UL ]
    given1
    |> run um [ "61091001" ]
    |> is [ G 8, 0x7f01cc40UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        M 0x20200078UL, 0x1347a8cfe223d3b1UL
        M 0x20200080UL, 0x33cfd239dee6372dUL
        M 0x20200088UL, 0xfec2421c69fbdba5UL ]
    given2
    |> run um [ "61091001" ]
    |> is [ G 8, 0xffffffff89abdee6UL ]

  /// <summary>
  /// 61096601, lwre a4, 1(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWRE``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0xf02c2da7f9332723UL
        M 0x20200080UL, 0xd3e82d880f65ac1UL
        M 0x20200088UL, 0x5d6e70dc2a9ca94aUL ]
    given0
    |> run um [ "61096601" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200081UL
        Status, 0x10UL
        M 0x20200078UL, 0xa4bb441838b725bdUL
        M 0x20200080UL, 0xfdde5998ef3ac42dUL
        M 0x20200088UL, 0x80478c9dd884fb8dUL ]
    given1
    |> run um [ "61096601" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200084UL
        Status, 0x10UL
        M 0x20200078UL, 0xd6db39b17ab40128UL
        M 0x20200080UL, 0xb33389bb8534b5a5UL
        M 0x20200088UL, 0x7638dadae6410216UL ]
    given2
    |> run um [ "61096601" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 4821, lw at, 4(sp), against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWSP``() =
    let given0 =
      [ G 1, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xbfc79a580c668794UL
        M 0x20200080UL, 0x5ab74a04244fbf28UL
        M 0x20200088UL, 0xb59fadf5c2265d52UL ]
    given0
    |> run um [ "4821" ]
    |> is [ G 1, 0x5ab74a04UL ]
    let given1 =
      [ G 1, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xb8800bf419568d4fUL
        M 0x20200080UL, 0xd8afffd02ca9ac4eUL
        M 0x20200088UL, 0x1778582e94e587fbUL ]
    given1
    |> run um [ "4821" ]
    |> is [ G 1, 0xffffffffd8afffd0UL ]
    let given2 =
      [ G 1, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x1526fdc747232cd4UL
        M 0x20200080UL, 0x19e1ce73bab116faUL
        M 0x20200088UL, 0x24e40ed190a3e69bUL ]
    given2
    |> run um [ "4821" ]
    |> is [ G 1, 0x19e1ce73UL ]

  /// <summary>
  /// 6109e001, lwu a4, 1(a5), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after lwu $8,1($9), the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWU``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0x1343e3a471a498ffUL
        M 0x20200080UL, 0x9c038af997ad7f9bUL
        M 0x20200088UL, 0x7626b3ffec9fce17UL ]
    given0
    |> run um [ "6109e001" ]
    |> is [ G 8, 0x9c038af9UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xdccba52a288c2a5fUL
        M 0x20200080UL, 0xb91ef9189222857fUL
        M 0x20200088UL, 0xe85d5fa5eb47fe8cUL ]
    given1
    |> run um [ "6109e001" ]
    |> is [ G 8, 0xb91ef918UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x2020007fUL
        M 0x20200078UL, 0xcd7c6881fe226d1cUL
        M 0x20200080UL, 0xe9477cf0b759cd3aUL
        M 0x20200088UL, 0x67c4f1615c382b46UL ]
    given2
    |> run um [ "6109e001" ]
    |> is [ G 8, 0xe9477cf0UL ]

  /// <summary>
  /// 55281048, lwxc1 f2, a5(a4), against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after lwxc1 $f2,$9($8), the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWXC1``() =
    let given0 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0xd309be4a58a640adUL
        M 0x20200080UL, 0x77126cc324337ed6UL
        M 0x20200088UL, 0x6e3bba6882d154ddUL ]
    given0
    |> run um [ "55281048" ]
    |> is [ F 2, 0x77126cc3UL ]
    let given1 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x40600000UL
        M 0x20200078UL, 0x1e5949498280908eUL
        M 0x20200080UL, 0x5dc82eb8c4f3e26bUL
        M 0x20200088UL, 0x5d3271e98784084cUL ]
    given1
    |> run um [ "55281048" ]
    |> is [ F 2, 0x5dc82eb8UL ]
    let given2 =
      [ G 8, 0x20200078UL
        G 9, 0x8UL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0xc0cfad405bce031aUL
        M 0x20200080UL, 0xe35bc70c66488c80UL
        M 0x20200088UL, 0x43f7d12fc931e042UL ]
    given2
    |> run um [ "55281048" ]
    |> is [ F 2, 0xe35bc70cUL ]

  /// <summary>
  /// 01494118, lwxs a4, a6(a5), against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 LWXS``() =
    let given0 =
      [ G 8, 0x7UL
        G 9, 0x20200078UL
        G 10, 0x2UL
        M 0x20200078UL, 0xb1166d42295d8db8UL
        M 0x20200080UL, 0x438c5438d62f127bUL
        M 0x20200088UL, 0x458119b8cde9c00bUL ]
    given0
    |> run um [ "01494118" ]
    |> is [ G 8, 0x438c5438UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x20200078UL
        G 10, 0x2UL
        M 0x20200078UL, 0xcb41bbdee547b354UL
        M 0x20200080UL, 0x947880437f777a84UL
        M 0x20200088UL, 0x6167174f25e7cee7UL ]
    given1
    |> run um [ "01494118" ]
    |> is [ G 8, 0xffffffff94788043UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x20200078UL
        G 10, 0x2UL
        M 0x20200078UL, 0x5c666081d6852d9bUL
        M 0x20200080UL, 0xdedc8fda0f0a9b16UL
        M 0x20200088UL, 0xb23a712f359c725cUL ]
    given2
    |> run um [ "01494118" ]
    |> is [ G 8, 0xffffffffdedc8fdaUL ]

  /// <summary>
  /// 0128cb3c, madd a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MADD``() =
    [ G 8, 0x7UL; G 9, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "0128cb3c" ]
    |> is [ Lo, 0x39UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run um [ "0128cb3c" ]
    |> is [ Hi, 0xffffffff80000000UL; Lo, 0x0UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run um [ "0128cb3c" ]
    |> is [ Hi, 0xffffffffd643a257UL; Lo, 0xfffffffff4772880UL ]

  /// <summary>
  /// 55061101, madd.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after madd.s $f2,$f4,$f6,$f8, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MADD.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run um [ "55061101" ]
    |> is [ F 2, 0x40400000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run um [ "55061101" ]
    |> is [ F 2, 0xc0400000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run um [ "55061101" ]
    |> is [ F 2, 0x4479ec00UL ]

  /// <summary>
  /// 0128db3c, maddu a4, a5, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MADDU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "0128db3c" ]
    |> is [ Lo, 0x39UL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run um [ "0128db3c" ]
    |> is [ Hi, 0xffffffff80000000UL; Lo, 0x0UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run um [ "0128db3c" ]
    |> is [ Hi, 0xffffffffe877f8cfUL; Lo, 0xfffffffff4772880UL ]

  /// <summary>
  /// 002208fc, mfc0 at, 0x2, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run um [ "002208fc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "002208fc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "002208fc" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5502203b, mfc1 a4, f2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after mfc1 $8,$f2, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFC1``() =
    [ G 8, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run um [ "5502203b" ]
    |> is [ G 8, 0x55667788UL ]
    [ G 8, 0x7fffffffUL; F 2, 0xbf800000UL ]
    |> run um [ "5502203b" ]
    |> is [ G 8, 0xffffffffbf800000UL ]
    [ G 8, 0xffffffff89abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run um [ "5502203b" ]
    |> is [ G 8, 0xffffffffccddeeffUL ]

  /// <summary>
  /// 00224d3c, mfc2 at, 0x2, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "00224d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "00224d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "00224d3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 002208f4, mfhc0 at, 0x2, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run um [ "002208f4" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "002208f4" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "002208f4" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5502303b, mfhc1 a4, f2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after mfhc1 $8,$f2, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHC1``() =
    [ G 8, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run um [ "5502303b" ]
    |> is [ G 8, 0x11223344UL ]
    [ G 8, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run um [ "5502303b" ]
    |> is [ G 8, 0x0UL ]
    [ G 8, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run um [ "5502303b" ]
    |> is [ G 8, 0xffffffff8899aabbUL ]

  /// <summary>
  /// 00228d3c, mfhc2 at, 0x2, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "00228d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "00228d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "00228d3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00220d7c, mfhi v0, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHI``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "00220d7c" ]
    |> is [ G 2, 0x13UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run um [ "00220d7c" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run um [ "00220d7c" ]
    |> is [ G 2, 0xffffffffdeadbeefUL ]

  /// <summary>
  /// 4601, mfhi at, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFHI16``() =
    [ G 1, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "4601" ]
    |> is [ G 1, 0x13UL ]
    [ G 1, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run um [ "4601" ]
    |> is []
    [ G 1, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run um [ "4601" ]
    |> is [ G 1, 0xffffffffdeadbeefUL ]

  /// <summary>
  /// 00221d7c, mflo v0, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFLO``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "00221d7c" ]
    |> is [ G 2, 0x24UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run um [ "00221d7c" ]
    |> is [ G 2, 0xffffffff80000001UL ]
    [ G 2, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run um [ "00221d7c" ]
    |> is [ G 2, 0x12345678UL ]

  /// <summary>
  /// 4641, mflo at, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MFLO16``() =
    [ G 1, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "4641" ]
    |> is [ G 1, 0x24UL ]
    [ G 1, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run um [ "4641" ]
    |> is [ G 1, 0xffffffff80000001UL ]
    [ G 1, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run um [ "4641" ]
    |> is [ G 1, 0x12345678UL ]

  /// <summary>
  /// 5444007b, mov.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after mov.s $f2,$f4, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOV.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "5444007b" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run um [ "5444007b" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run um [ "5444007b" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 0c22, or at, v0, r0, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVE16``() =
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
  /// 86a6, movep a0, a1, v1, v0, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVEP``() =
    [ G 2, 0x2UL; G 3, 0x5UL; G 4, 0x7UL; G 5, 0x3UL ]
    |> run um [ "86a6" ]
    |> is [ G 4, 0x5UL; G 5, 0x2UL ]
    let given1 =
      [ G 2, 0xffffffff80000000UL
        G 3, 0xfffffffffffffffeUL
        G 4, 0x7fffffffUL
        G 5, 0x1UL ]
    given1
    |> run um [ "86a6" ]
    |> is [ G 4, 0xfffffffffffffffeUL; G 5, 0xffffffff80000000UL ]
    let given2 =
      [ G 2, 0xf0f0f0fUL
        G 3, 0xfffffffffedcba98UL
        G 4, 0xffffffff89abcdefUL
        G 5, 0x12345678UL ]
    given2
    |> run um [ "86a6" ]
    |> is [ G 4, 0xfffffffffedcba98UL; G 5, 0xf0f0f0fUL ]

  /// <summary>
  /// 5509217b, movf a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after movf $8,$9,$fcc1, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVF``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5509217b" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; Fcsr, 0xfe800000UL ]
    |> run um [ "5509217b" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; Fcsr, 0x800000UL ]
    |> run um [ "5509217b" ]
    |> is [ G 8, 0x12345678UL ]
    [ G 8, 0x7UL; G 9, 0x3UL; Fcsr, 0x2000000UL ]
    |> run um [ "5509217b" ]
    |> is []

  /// <summary>
  /// 54440020, movf.s f2, f4, 0x0, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after movf.s $f2,$f4,$fcc0, the MIPS64 instruction binutils reads
  /// this word as. the lift has to change what QEMU changed and nothing else,
  /// over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVF.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "54440020" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; Fcsr, 0xfe800000UL ]
    |> run um [ "54440020" ]
    |> is []
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; Fcsr, 0x800000UL ]
    |> run um [ "54440020" ]
    |> is []
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; Fcsr, 0x2000000UL ]
    |> run um [ "54440020" ]
    |> is [ F 2, 0x40100000UL ]

  /// <summary>
  /// 01494018, movn a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVN``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494018" ]
    |> is [ G 8, 0x3UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494018" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494018" ]
    |> is [ G 8, 0x12345678UL ]
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01494018" ]
    |> is []

  /// <summary>
  /// 55041038, movn.s f2, f4, a4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after movn.s $f2,$f4,$8, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVN.fmt``() =
    [ G 8, 0x7UL; F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "55041038" ]
    |> is [ F 2, 0x40100000UL ]
    [ G 8, 0x7fffffffUL; F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run um [ "55041038" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ G 8, 0xffffffff89abcdefUL; F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run um [ "55041038" ]
    |> is [ F 2, 0x447a0000UL ]
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "55041038" ]
    |> is []

  /// <summary>
  /// 5509297b, movt a4, a5, 0x1, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after movt $8,$9,$fcc1, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVT``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "5509297b" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; Fcsr, 0xfe800000UL ]
    |> run um [ "5509297b" ]
    |> is [ G 8, 0x1UL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; Fcsr, 0x800000UL ]
    |> run um [ "5509297b" ]
    |> is []
    [ G 8, 0x7UL; G 9, 0x3UL; Fcsr, 0x2000000UL ]
    |> run um [ "5509297b" ]
    |> is [ G 8, 0x3UL ]

  /// <summary>
  /// 54440060, movt.s f2, f4, 0x0, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after movt.s $f2,$f4,$fcc0, the MIPS64 instruction binutils reads
  /// this word as. the lift has to change what QEMU changed and nothing else,
  /// over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "54440060" ]
    |> is []
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; Fcsr, 0xfe800000UL ]
    |> run um [ "54440060" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; Fcsr, 0x800000UL ]
    |> run um [ "54440060" ]
    |> is [ F 2, 0x447a0000UL ]
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; Fcsr, 0x2000000UL ]
    |> run um [ "54440060" ]
    |> is []

  /// <summary>
  /// 01494058, movz a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVZ``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494058" ]
    |> is []
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494058" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494058" ]
    |> is []
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01494058" ]
    |> is [ G 8, 0x3UL ]

  /// <summary>
  /// 55041078, movz.s f2, f4, a4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after movz.s $f2,$f4,$8, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MOVZ.fmt``() =
    [ G 8, 0x7UL; F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "55041078" ]
    |> is []
    [ G 8, 0x7fffffffUL; F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run um [ "55041078" ]
    |> is []
    [ G 8, 0xffffffff89abcdefUL; F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run um [ "55041078" ]
    |> is []
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "55041078" ]
    |> is [ F 2, 0x40100000UL ]

  /// <summary>
  /// 0128eb3c, msub a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MSUB``() =
    [ G 8, 0x7UL; G 9, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "0128eb3c" ]
    |> is [ Lo, 0xfUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run um [ "0128eb3c" ]
    |> is [ Lo, 0x2UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run um [ "0128eb3c" ]
    |> is [ Hi, 0xffffffffe717db86UL; Lo, 0x2ff18470UL ]

  /// <summary>
  /// 55061121, msub.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: QEMU has
  /// no microMIPS64 or microMIPS processor with an FPU, so the values are what
  /// it left after msub.s $f2,$f4,$f6,$f8, the MIPS64 instruction binutils
  /// reads this word as. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MSUB.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run um [ "55061121" ]
    |> is [ F 2, 0xbfc00000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run um [ "55061121" ]
    |> is [ F 2, 0x41100000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run um [ "55061121" ]
    |> is [ F 2, 0xc47a1400UL ]

  /// <summary>
  /// 0128fb3c, msubu a4, a5, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MSUBU``() =
    [ G 8, 0x7UL; G 9, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run um [ "0128fb3c" ]
    |> is [ Lo, 0xfUL ]
    let given1 =
      [ G 8, 0x7fffffffUL
        G 9, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run um [ "0128fb3c" ]
    |> is [ Lo, 0x2UL ]
    let given2 =
      [ G 8, 0xffffffff89abcdefUL
        G 9, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run um [ "0128fb3c" ]
    |> is [ Hi, 0xffffffffd4e3850eUL; Lo, 0x2ff18470UL ]

  /// <summary>
  /// 00220afc, mtc0 at, 0x2, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run um [ "00220afc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "00220afc" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "00220afc" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5502283b, mtc1 a4, f2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after mtc1 $8,$f2, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTC1``() =
    [ G 8, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run um [ "5502283b" ]
    |> is [ F 2, 0x1122334400000007UL ]
    [ G 8, 0x7fffffffUL; F 2, 0xbf800000UL ]
    |> run um [ "5502283b" ]
    |> is [ F 2, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run um [ "5502283b" ]
    |> is [ F 2, 0x8899aabb89abcdefUL ]

  /// <summary>
  /// 00225d3c, mtc2 at, 0x2, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "00225d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "00225d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "00225d3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00220af4, mthc0 at, 0x2, 0x1, against QEMU's M14Kc: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. QEMU raised SIGILL (UndefinedInstruction here); Status =
  /// 0x10 puts the lift in User Mode, the mode QEMU runs every word in; the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run um [ "00220af4" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run um [ "00220af4" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run um [ "00220af4" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 5502383b, mthc1 a4, f2, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after mthc1 $8,$f2, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHC1``() =
    [ G 8, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run um [ "5502383b" ]
    |> is [ F 2, 0x755667788UL ]
    [ G 8, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run um [ "5502383b" ]
    |> is [ F 2, 0xffffffffbf800000UL ]
    [ G 8, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run um [ "5502383b" ]
    |> is [ F 2, 0x89abcdefccddeeffUL ]

  /// <summary>
  /// 00229d3c, mthc2 at, 0x2, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHC2``() =
    [ G 1, 0x7UL ]
    |> run um [ "00229d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run um [ "00229d3c" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run um [ "00229d3c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00082d7c, mthi a4, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTHI``() =
    [ G 8, 0x7UL ]
    |> run um [ "00082d7c" ]
    |> is [ Hi, 0x7UL ]
    [ G 8, 0x7fffffffUL ]
    |> run um [ "00082d7c" ]
    |> is [ Hi, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "00082d7c" ]
    |> is [ Hi, 0xffffffff89abcdefUL ]

  /// <summary>
  /// 00083d7c, mtlo a4, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MTLO``() =
    [ G 8, 0x7UL ]
    |> run um [ "00083d7c" ]
    |> is [ Lo, 0x7UL ]
    [ G 8, 0x7fffffffUL ]
    |> run um [ "00083d7c" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL ]
    |> run um [ "00083d7c" ]
    |> is [ Lo, 0xffffffff89abcdefUL ]

  /// <summary>
  /// 01494210, mul a4, a5, a6, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MUL``() =
    [ G 8, 0x7UL; G 9, 0x3UL; G 10, 0x5UL ]
    |> run um [ "01494210" ]
    |> is [ G 8, 0xfUL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL; G 10, 0xfffffffffffffffeUL ]
    |> run um [ "01494210" ]
    |> is [ G 8, 0xfffffffffffffffeUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL; G 10, 0xfffffffffedcba98UL ]
    |> run um [ "01494210" ]
    |> is [ G 8, 0x35068740UL ]

  /// <summary>
  /// 54c410b0, mul.s f2, f4, f6, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after mul.s $f2,$f4,$f6, the MIPS64 instruction binutils reads this
  /// word as. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MUL.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run um [ "54c410b0" ]
    |> is [ F 2, 0x40580000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run um [ "54c410b0" ]
    |> is [ F 2, 0xc0900000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run um [ "54c410b0" ]
    |> is [ F 2, 0x42fa0000UL ]

  /// <summary>
  /// 01288b3c, mult a4, a5, against QEMU's M14Kc: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MULT``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01288b3c" ]
    |> is [ Lo, 0x15UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01288b3c" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01288b3c" ]
    |> is [ Hi, 0xfffffffff795e368UL; Lo, 0xffffffffe242d208UL ]

  /// <summary>
  /// 01289b3c, multu a4, a5, against QEMU's M14Kc: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 MULTU``() =
    [ G 8, 0x7UL; G 9, 0x3UL ]
    |> run um [ "01289b3c" ]
    |> is [ Lo, 0x15UL ]
    [ G 8, 0x7fffffffUL; G 9, 0x1UL ]
    |> run um [ "01289b3c" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 8, 0xffffffff89abcdefUL; G 9, 0x12345678UL ]
    |> run um [ "01289b3c" ]
    |> is [ Hi, 0x9ca39e0UL; Lo, 0xffffffffe242d208UL ]

  /// <summary>
  /// 54440b7b, neg.s f2, f4, against QEMU's MIPS64R2-generic: QEMU has no
  /// microMIPS64 or microMIPS processor with an FPU, so the values are what it
  /// left after neg.s $f2,$f4, the MIPS64 instruction binutils reads this word
  /// as. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 NEG.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run um [ "54440b7b" ]
    |> is [ F 2, 0xc0100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run um [ "54440b7b" ]
    |> is [ F 2, 0x40c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run um [ "54440b7b" ]
    |> is [ F 2, 0xc47a0000UL ]

  /// <summary>
  /// 55061102, nmadd.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after nmadd.s $f2,$f4,$f6,$f8, the MIPS64 instruction
  /// binutils reads this word as. the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 NMADD.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run um [ "55061102" ]
    |> is [ F 2, 0xc0400000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run um [ "55061102" ]
    |> is [ F 2, 0x40400000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run um [ "55061102" ]
    |> is [ F 2, 0xc479ec00UL ]

  /// <summary>
  /// 55061122, nmsub.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: QEMU
  /// has no microMIPS64 or microMIPS processor with an FPU, so the values are
  /// what it left after nmsub.s $f2,$f4,$f6,$f8, the MIPS64 instruction
  /// binutils reads this word as. the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 NMSUB.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run um [ "55061122" ]
    |> is [ F 2, 0x3fc00000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run um [ "55061122" ]
    |> is [ F 2, 0xc1100000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run um [ "55061122" ]
    |> is [ F 2, 0x447a1400UL ]

  /// <summary>
  /// 00000000, nop, against QEMU's M14Kc: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``microMIPS64 5.04 NOP``() =
    []
    |> run um [ "00000000" ]
    |> is []
    []
    |> run um [ "00000000" ]
    |> is []
    []
    |> run um [ "00000000" ]
    |> is []
