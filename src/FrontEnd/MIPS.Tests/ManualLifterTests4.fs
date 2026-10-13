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
/// One test for each instruction of MD00076 and MD00077: ADDIU to BTEQZ.
///
/// <para>A value test runs a word of the instruction under QEMU over a few
/// sets of register values, memory and FCSR, and has the lift change what
/// QEMU changed, raise what QEMU raised, and nothing else; every value it
/// expects is QEMU's (optest-mips/oracle). A structural test says in its own
/// comment what it checks and why no value test could be had.</para>
/// </summary>
[<TestClass>]
type ManualLifterTests4() =
  let m16 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32, int MIPSISAMode.MIPS16)

  let m16x64 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSISAMode.MIPS16)

  /// <summary>
  /// 4261, addiu v1, v0, 0x1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 ADDIU``() =
    [ G 2, 0x3UL; G 3, 0x7UL ]
    |> run m16 [ "4261" ]
    |> is [ G 3, 0x4UL ]
    [ G 2, 0x1UL; G 3, 0x7fffffffUL ]
    |> run m16 [ "4261" ]
    |> is [ G 3, 0x2UL ]
    [ G 2, 0x12345678UL; G 3, 0x89abcdefUL ]
    |> run m16 [ "4261" ]
    |> is [ G 3, 0x12345679UL ]

  /// <summary>
  /// e271, addu a0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 ADDU``() =
    [ G 2, 0x3UL; G 3, 0x5UL; G 4, 0x7UL ]
    |> run m16 [ "e271" ]
    |> is [ G 4, 0x8UL ]
    [ G 2, 0x1UL; G 3, 0xfffffffeUL; G 4, 0x7fffffffUL ]
    |> run m16 [ "e271" ]
    |> is [ G 4, 0xffffffffUL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba98UL; G 4, 0x89abcdefUL ]
    |> run m16 [ "e271" ]
    |> is [ G 4, 0x11111110UL ]

  /// <summary>
  /// ea6c, and v0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 AND``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea6c" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea6c" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea6c" ]
    |> is [ G 2, 0x204468UL ]

  /// <summary>
  /// f000e001, asmacro 0x1, against QEMU's 24Kf: QEMU raised SIGILL
  /// (UndefinedInstruction here); the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 ASMACRO``() =
    []
    |> run m16 [ "f000e001" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run m16 [ "f000e001" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run m16 [ "f000e001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 1010, b 0x20100022 (binutils: b 20100022). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is the
  /// branch's own, there being no delay slot; control goes to 0x20100022 (the
  /// target binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 B``() =
    let words = [ "1010" ]
    ownsJump m16 "1010" true
    goes m16 words [] 0x20100022UL

  /// <summary>
  /// 2210, beqz v0, 0x20100022 (binutils: beqz $2,20100022). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when it always does; to 0x20100002,
  /// past the branch, when G 2 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 BEQZ``() =
    let words = [ "2210" ]
    ownsJump m16 "2210" true
    goes m16 words [] 0x20100022UL
    goes m16 words [ G 2, 0x5UL ] 0x20100002UL

  /// <summary>
  /// 2a10, bnez v0, 0x20100022 (binutils: bnez $2,20100022). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when G 2 is 0x5; to 0x20100002,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 BNEZ``() =
    let words = [ "2a10" ]
    ownsJump m16 "2a10" true
    goes m16 words [ G 2, 0x5UL ] 0x20100022UL
    goes m16 words [] 0x20100002UL

  /// <summary>
  /// e825, break 0x1, against QEMU's 24Kf: QEMU raised SIGTRAP (Breakpoint
  /// here); the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 BREAK``() =
    []
    |> run m16 [ "e825" ]
    |> raises [ Breakpoint ] []
    []
    |> run m16 [ "e825" ]
    |> raises [ Breakpoint ] []
    []
    |> run m16 [ "e825" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// 6010, bteqz 0x20100022 (binutils: bteqz 20100022). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when it always does; to 0x20100002,
  /// past the branch, when G 24 is 0x1.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 BTEQZ``() =
    let words = [ "6010" ]
    ownsJump m16 "6010" true
    goes m16 words [] 0x20100022UL
    goes m16 words [ G 24, 0x1UL ] 0x20100002UL

  /// <summary>
  /// 6110, btnez 0x20100022 (binutils: btnez 20100022). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when G 24 is 0x1; to 0x20100002,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 BTNEZ``() =
    let words = [ "6110" ]
    ownsJump m16 "6110" true
    goes m16 words [ G 24, 0x1UL ] 0x20100022UL
    goes m16 words [] 0x20100002UL

  /// <summary>
  /// ea6a, cmp v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 CMP``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16 [ "ea6a" ]
    |> is [ G 24, 0x4UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 24, 0x1234UL ]
    |> run m16 [ "ea6a" ]
    |> is [ G 24, 0x7ffffffeUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL; G 24, 0x1234UL ]
    |> run m16 [ "ea6a" ]
    |> is [ G 24, 0x9b9f9b97UL ]

  /// <summary>
  /// 7201, cmpi v0, 0x1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 CMPI``() =
    [ G 2, 0x7UL; G 24, 0x1234UL ]
    |> run m16 [ "7201" ]
    |> is [ G 24, 0x6UL ]
    [ G 2, 0x7fffffffUL; G 24, 0x1234UL ]
    |> run m16 [ "7201" ]
    |> is [ G 24, 0x7ffffffeUL ]
    [ G 2, 0x89abcdefUL; G 24, 0x1234UL ]
    |> run m16 [ "7201" ]
    |> is [ G 24, 0x89abcdeeUL ]

  /// <summary>
  /// ea7a, div v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 DIV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea7a" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea7a" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea7a" ]
    |> is [ Hi, 0xf6e5d4bfUL; Lo, 0xfffffffaUL ]

  /// <summary>
  /// ea7b, divu v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 DIVU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea7b" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea7b" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea7b" ]
    |> is [ Hi, 0xa3d70a7UL; Lo, 0x7UL ]

  /// <summary>
  /// 18000100, jal 0x20000400 (binutils: jal 20000400). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20000400 (the target binutils reads) when it always does; ra becomes
  /// 0x20100007 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 JAL``() =
    let words = [ "18000100"; "6500" ]
    ownsJump m16 "18000100" false
    goes m16 words [] 0x20000400UL
    []
    |> run m16 words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// ea40, jalr ra, v0 (binutils: jalr $2). A branch is not run against QEMU:
  /// it moves the PC, and its delay slot makes one word meaningless to run
  /// alone. Checked structurally from the manual: the transfer is left to the
  /// delay slot, which holds a NOP; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16; ra becomes 0x20100005 and nothing
  /// else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 JALR``() =
    let words = [ "ea40"; "6500" ]
    ownsJump m16 "ea40" false
    goes m16 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16
    [ G 2, 0x20100401UL ]
    |> run m16 words
    |> is [ G 31, 0x20100005UL ]

  /// <summary>
  /// eac0, jalrc ra, v0 (binutils: jalrc $2). A branch is not run against QEMU:
  /// it moves the PC, and its delay slot makes one word meaningless to run
  /// alone. Checked structurally from the manual: the transfer is the branch's
  /// own, there being no delay slot; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16; ra becomes 0x20100003 and nothing
  /// else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 JALRC``() =
    let words = [ "eac0" ]
    ownsJump m16 "eac0" true
    goes m16 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16
    [ G 2, 0x20100401UL ]
    |> run m16 words
    |> is [ G 31, 0x20100003UL ]

  /// <summary>
  /// 1c000100, jalx 0x20000400 (binutils: jalx 20000400). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20000400 (the target binutils reads) when it always does; the jump goes
  /// on in MIPS; ra becomes 0x20100007 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 JALX``() =
    let words = [ "1c000100"; "6500" ]
    ownsJump m16 "1c000100" false
    goes m16 words [] 0x20000400UL
    switches m16 words [] InterJmpKind.SwitchToMIPS
    []
    |> run m16 words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// ea00, jr v0 (binutils: jr $2). A branch is not run against QEMU: it moves
  /// the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is left to the delay
  /// slot, which holds a NOP; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 JR``() =
    let words = [ "ea00"; "6500" ]
    ownsJump m16 "ea00" false
    goes m16 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16

  /// <summary>
  /// ea80, jrc v0 (binutils: jrc $2). A branch is not run against QEMU: it
  /// moves the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is the branch's own,
  /// there being no delay slot; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 JRC``() =
    let words = [ "ea80" ]
    ownsJump m16 "ea80" true
    goes m16 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16

  /// <summary>
  /// 8041, lb v0, 1(s0), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 LB``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xf2909bee6bff355bUL
        M 0x20200080UL, 0x8dcaca8e50400ea5UL
        M 0x20200088UL, 0x7e2a94a9f1bc1ab9UL ]
    given0
    |> run m16 [ "8041" ]
    |> is [ G 2, 0xffffff8dUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x301f9533d9cfbb39UL
        M 0x20200080UL, 0x2964557bcfcd77dfUL
        M 0x20200088UL, 0x472e01bb4e2dc4cUL ]
    given1
    |> run m16 [ "8041" ]
    |> is [ G 2, 0x29UL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xe7fba05932a34c5aUL
        M 0x20200080UL, 0x8151fa5c04a0f4c7UL
        M 0x20200088UL, 0x7df18c4d9caf7c1dUL ]
    given2
    |> run m16 [ "8041" ]
    |> is [ G 2, 0xffffff81UL ]

  /// <summary>
  /// a041, lbu v0, 1(s0), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 LBU``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xd5a81f7896d3b11eUL
        M 0x20200080UL, 0x6314f139636356b7UL
        M 0x20200088UL, 0xaa4c4efcbdcfc871UL ]
    given0
    |> run m16 [ "a041" ]
    |> is [ G 2, 0x63UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xd71f1f7086d58a0eUL
        M 0x20200080UL, 0x3b59d8e71a10d3e7UL
        M 0x20200088UL, 0xa94f4eb9c78ae5afUL ]
    given1
    |> run m16 [ "a041" ]
    |> is [ G 2, 0x3bUL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xde65adb4e8dfb12bUL
        M 0x20200080UL, 0x2f3bcfdcb2633a39UL
        M 0x20200088UL, 0x22a0114c2c4be47bUL ]
    given2
    |> run m16 [ "a041" ]
    |> is [ G 2, 0x2fUL ]

  /// <summary>
  /// 8841, lh v0, 2(s0), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 LH``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x37c5ac0ed6fd8f64UL
        M 0x20200080UL, 0x7619c7274f355c7UL
        M 0x20200088UL, 0xa49a8463048742d9UL ]
    given0
    |> run m16 [ "8841" ]
    |> is [ G 2, 0x761UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x64e08280089c24e7UL
        M 0x20200080UL, 0x7c406cc164a820adUL
        M 0x20200088UL, 0x854c10e5a4932f75UL ]
    given1
    |> run m16 [ "8841" ]
    |> is [ G 2, 0x7c40UL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x32d207a4e8e92adbUL
        M 0x20200080UL, 0xd192ef95f13a5f9fUL
        M 0x20200088UL, 0x62333524afc29cb3UL ]
    given2
    |> run m16 [ "8841" ]
    |> is [ G 2, 0xffffd192UL ]

  /// <summary>
  /// a841, lhu v0, 2(s0), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 LHU``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x5357de8e464fbddbUL
        M 0x20200080UL, 0xaa39e408e1c2391eUL
        M 0x20200088UL, 0x3f4f792f4bed42f7UL ]
    given0
    |> run m16 [ "a841" ]
    |> is [ G 2, 0xaa39UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x489196e321036ab6UL
        M 0x20200080UL, 0xa8e659cdb44253dUL
        M 0x20200088UL, 0x5e5a2f7a6eb6ee50UL ]
    given1
    |> run m16 [ "a841" ]
    |> is [ G 2, 0xa8eUL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x5cbd719829acf969UL
        M 0x20200080UL, 0x2e66cae7228cb336UL
        M 0x20200088UL, 0xd6bdebd1fbf9f7c3UL ]
    given2
    |> run m16 [ "a841" ]
    |> is [ G 2, 0x2e66UL ]

  /// <summary>
  /// 6a01, li v0, 0x1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 LI``() =
    [ G 2, 0x7UL ]
    |> run m16 [ "6a01" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL ]
    |> run m16 [ "6a01" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x89abcdefUL ]
    |> run m16 [ "6a01" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 9201, lw v0, 4(sp), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 LW``() =
    let given0 =
      [ G 2, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x6bdf9ccd6419029bUL
        M 0x20200080UL, 0xac45a893487971bcUL
        M 0x20200088UL, 0x31e7c46f8cf2e7c3UL ]
    given0
    |> run m16 [ "9201" ]
    |> is [ G 2, 0xac45a893UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x972fe369d09b43c2UL
        M 0x20200080UL, 0xfac3a853b119ac2cUL
        M 0x20200088UL, 0x47dd015971760f4aUL ]
    given1
    |> run m16 [ "9201" ]
    |> is [ G 2, 0xfac3a853UL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x1e278743e6863a4eUL
        M 0x20200080UL, 0x42b2a3c01654e538UL
        M 0x20200088UL, 0xae198d0b7c5f3521UL ]
    given2
    |> run m16 [ "9201" ]
    |> is [ G 2, 0x42b2a3c0UL ]

  /// <summary>
  /// ea10, mfhi v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 MFHI``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run m16 [ "ea10" ]
    |> is [ G 2, 0x13UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0x80000001UL ]
    |> run m16 [ "ea10" ]
    |> is []
    [ G 2, 0x89abcdefUL; Hi, 0xdeadbeefUL; Lo, 0x12345678UL ]
    |> run m16 [ "ea10" ]
    |> is [ G 2, 0xdeadbeefUL ]

  /// <summary>
  /// ea12, mflo v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 MFLO``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run m16 [ "ea12" ]
    |> is [ G 2, 0x24UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0x80000001UL ]
    |> run m16 [ "ea12" ]
    |> is [ G 2, 0x80000001UL ]
    [ G 2, 0x89abcdefUL; Hi, 0xdeadbeefUL; Lo, 0x12345678UL ]
    |> run m16 [ "ea12" ]
    |> is [ G 2, 0x12345678UL ]

  /// <summary>
  /// 6522, move at, v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 MOVE``() =
    [ G 1, 0x7UL; G 2, 0x3UL ]
    |> run m16 [ "6522" ]
    |> is [ G 1, 0x3UL ]
    [ G 1, 0x7fffffffUL; G 2, 0x1UL ]
    |> run m16 [ "6522" ]
    |> is [ G 1, 0x1UL ]
    [ G 1, 0x89abcdefUL; G 2, 0x12345678UL ]
    |> run m16 [ "6522" ]
    |> is [ G 1, 0x12345678UL ]

  /// <summary>
  /// ea78, mult v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 MULT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea78" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea78" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea78" ]
    |> is [ Hi, 0xf795e368UL; Lo, 0xe242d208UL ]

  /// <summary>
  /// ea79, multu v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 MULTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea79" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea79" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea79" ]
    |> is [ Hi, 0x9ca39e0UL; Lo, 0xe242d208UL ]

  /// <summary>
  /// ea6b, neg v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 NEG``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea6b" ]
    |> is [ G 2, 0xfffffffdUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea6b" ]
    |> is [ G 2, 0xffffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea6b" ]
    |> is [ G 2, 0xedcba988UL ]

  /// <summary>
  /// 6500, nop, against QEMU's 24Kf: the lift has to change what QEMU changed
  /// and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 NOP``() =
    []
    |> run m16 [ "6500" ]
    |> is []
    []
    |> run m16 [ "6500" ]
    |> is []
    []
    |> run m16 [ "6500" ]
    |> is []

  /// <summary>
  /// ea6f, not v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 NOT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea6f" ]
    |> is [ G 2, 0xfffffffcUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea6f" ]
    |> is [ G 2, 0xfffffffeUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea6f" ]
    |> is [ G 2, 0xedcba987UL ]

  /// <summary>
  /// ea6d, or v0, v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 OR``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea6d" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea6d" ]
    |> is []
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea6d" ]
    |> is [ G 2, 0x9bbfdfffUL ]

  /// <summary>
  /// 6432, restore 0x10, s0, s1, against QEMU's 24Kf: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 RESTORE``() =
    let given0 =
      [ G 16, 0x7UL
        G 17, 0x3UL
        G 29, 0x20200080UL
        M 0x20200060UL, 0xf0c4934c9077f4a3UL
        M 0x20200068UL, 0x31184a587ffac785UL
        M 0x20200070UL, 0x221b7809c6e2494eUL
        M 0x20200078UL, 0xb5e0572ead0f5c38UL
        M 0x20200080UL, 0x403735a73d1f9923UL
        M 0x20200088UL, 0xe533f6430d71c8e0UL
        M 0x20200090UL, 0x44b7ef486176c2e0UL
        M 0x20200098UL, 0x347f933a8b32a7beUL ]
    given0
    |> run m16 [ "6432" ]
    |> is [ G 16, 0xe533f643UL; G 17, 0xd71c8e0UL; G 29, 0x20200090UL ]
    let given1 =
      [ G 16, 0x7fffffffUL
        G 17, 0x1UL
        G 29, 0x20200080UL
        M 0x20200060UL, 0x71bdde44336e78b4UL
        M 0x20200068UL, 0x22c908328de8056cUL
        M 0x20200070UL, 0x5bb28184fe4428ceUL
        M 0x20200078UL, 0x9867ae5dade00f56UL
        M 0x20200080UL, 0xe569f8520b488d2cUL
        M 0x20200088UL, 0xfb52bfc27bba6386UL
        M 0x20200090UL, 0xcad601b5634a5866UL
        M 0x20200098UL, 0xc083f5d737a1479UL ]
    given1
    |> run m16 [ "6432" ]
    |> is [ G 16, 0xfb52bfc2UL; G 17, 0x7bba6386UL; G 29, 0x20200090UL ]
    let given2 =
      [ G 16, 0x89abcdefUL
        G 17, 0x12345678UL
        G 29, 0x20200080UL
        M 0x20200060UL, 0x1f8515e5030884dfUL
        M 0x20200068UL, 0x85ddf7b75e3075bbUL
        M 0x20200070UL, 0xa5c726847b70e56UL
        M 0x20200078UL, 0x262635083fbcf4e9UL
        M 0x20200080UL, 0xe416143271628b1dUL
        M 0x20200088UL, 0x978545b7e80b4deeUL
        M 0x20200090UL, 0xcd2812a253749b03UL
        M 0x20200098UL, 0x90e82824b77eaaf2UL ]
    given2
    |> run m16 [ "6432" ]
    |> is [ G 16, 0x978545b7UL; G 17, 0xe80b4deeUL; G 29, 0x20200090UL ]

  /// <summary>
  /// 64f2, save 0x10, ra, s0, s1, against QEMU's 24Kf: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SAVE``() =
    let given0 =
      [ G 16, 0x3UL
        G 17, 0x5UL
        G 29, 0x20200080UL
        G 31, 0x400cacUL
        M 0x20200060UL, 0x1821defda759663fUL
        M 0x20200068UL, 0x55cbf6dfd7f0041fUL
        M 0x20200070UL, 0x5f83004441ff181UL
        M 0x20200078UL, 0xb32b5b22e3efc784UL
        M 0x20200080UL, 0xa82e76029722abc3UL
        M 0x20200088UL, 0x1769f0e7c552b040UL
        M 0x20200090UL, 0xe4cf8e6ed4c880fdUL
        M 0x20200098UL, 0xc470897437da1cdbUL ]
    let expected0 =
      [ G 29, 0x20200070UL
        M 0x20200070UL, 0x5f8300400000003UL
        M 0x20200078UL, 0x500400cacUL ]
    given0
    |> run m16 [ "64f2" ]
    |> is expected0
    let given1 =
      [ G 16, 0x1UL
        G 17, 0xfffffffeUL
        G 29, 0x20200080UL
        G 31, 0x400cacUL
        M 0x20200060UL, 0x1e8f79a072fda07UL
        M 0x20200068UL, 0xfca64d436d2a3688UL
        M 0x20200070UL, 0x4dbcb8b42240bf02UL
        M 0x20200078UL, 0x77d89a8415ce8184UL
        M 0x20200080UL, 0xe634aeb0dab4940UL
        M 0x20200088UL, 0x85801cced6962eb6UL
        M 0x20200090UL, 0x51253ceb3fe09436UL
        M 0x20200098UL, 0x8a7c514639cf6e09UL ]
    let expected1 =
      [ G 29, 0x20200070UL
        M 0x20200070UL, 0x4dbcb8b400000001UL
        M 0x20200078UL, 0xfffffffe00400cacUL ]
    given1
    |> run m16 [ "64f2" ]
    |> is expected1
    let given2 =
      [ G 16, 0x12345678UL
        G 17, 0xfedcba98UL
        G 29, 0x20200080UL
        G 31, 0x400cacUL
        M 0x20200060UL, 0xdfd512d76464ac89UL
        M 0x20200068UL, 0x6849ffa7f9177060UL
        M 0x20200070UL, 0x83a41a487312bb23UL
        M 0x20200078UL, 0x640def0e18214fdbUL
        M 0x20200080UL, 0x9a428d53199ad16eUL
        M 0x20200088UL, 0x78ddcba26e75f764UL
        M 0x20200090UL, 0xa40ec19311239c88UL
        M 0x20200098UL, 0x80cb072a0471d302UL ]
    let expected2 =
      [ G 29, 0x20200070UL
        M 0x20200070UL, 0x83a41a4812345678UL
        M 0x20200078UL, 0xfedcba9800400cacUL ]
    given2
    |> run m16 [ "64f2" ]
    |> is expected2

  /// <summary>
  /// c041, sb v0, 1(s0), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SB``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x14e7d61cab359221UL
        M 0x20200080UL, 0x34e9220a32dedf16UL
        M 0x20200088UL, 0xd1b1361efc52a0b5UL ]
    given0
    |> run m16 [ "c041" ]
    |> is [ M 0x20200080UL, 0x7e9220a32dedf16UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xec5f190585e8cb2UL
        M 0x20200080UL, 0x5486248ad0e055ddUL
        M 0x20200088UL, 0xfcae0d2eeb611b22UL ]
    given1
    |> run m16 [ "c041" ]
    |> is [ M 0x20200080UL, 0xff86248ad0e055ddUL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x6d75574f932533baUL
        M 0x20200080UL, 0x7540fa53655a4a2UL
        M 0x20200088UL, 0x4cf5bb589bfa5353UL ]
    given2
    |> run m16 [ "c041" ]
    |> is [ M 0x20200080UL, 0xef540fa53655a4a2UL ]

  /// <summary>
  /// e821, sdbbp 0x1. Not run against QEMU, whose user mode aborts on the debug
  /// exception it raises; the manual enters the debug handler, which is this
  /// architecture's breakpoint. The lift raises Breakpoint and changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SDBBP``() =
    []
    |> run m16 [ "e821" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// ea91, seb v0, v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SEB``() =
    [ G 2, 0x7UL ]
    |> run m16 [ "ea91" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16 [ "ea91" ]
    |> is [ G 2, 0xffffffffUL ]
    [ G 2, 0x89abcdefUL ]
    |> run m16 [ "ea91" ]
    |> is [ G 2, 0xffffffefUL ]

  /// <summary>
  /// eab1, seh v0, v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SEH``() =
    [ G 2, 0x7UL ]
    |> run m16 [ "eab1" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16 [ "eab1" ]
    |> is [ G 2, 0xffffffffUL ]
    [ G 2, 0x89abcdefUL ]
    |> run m16 [ "eab1" ]
    |> is [ G 2, 0xffffcdefUL ]

  /// <summary>
  /// c841, sh v0, 2(s0), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SH``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x216f66f6e8889d03UL
        M 0x20200080UL, 0xfe0b07788aecacf5UL
        M 0x20200088UL, 0x77c25a5398f3c412UL ]
    given0
    |> run m16 [ "c841" ]
    |> is [ M 0x20200080UL, 0x707788aecacf5UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xaf372c7e649512dbUL
        M 0x20200080UL, 0x268bb0d01d7a2ac1UL
        M 0x20200088UL, 0x32f1b9399d18ec5aUL ]
    given1
    |> run m16 [ "c841" ]
    |> is [ M 0x20200080UL, 0xffffb0d01d7a2ac1UL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xbcddd1f6b46dc79cUL
        M 0x20200080UL, 0xdda6241e554fec9eUL
        M 0x20200088UL, 0x8bf481b85ce3d60bUL ]
    given2
    |> run m16 [ "c841" ]
    |> is [ M 0x20200080UL, 0xcdef241e554fec9eUL ]

  /// <summary>
  /// 3260, sll v0, v1, 0x8, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SLL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "3260" ]
    |> is [ G 2, 0x300UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "3260" ]
    |> is [ G 2, 0x100UL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "3260" ]
    |> is [ G 2, 0x34567800UL ]

  /// <summary>
  /// eb44, sllv v0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SLLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "eb44" ]
    |> is [ G 2, 0x38UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "eb44" ]
    |> is [ G 2, 0xfffffffeUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "eb44" ]
    |> is [ G 2, 0xef000000UL ]

  /// <summary>
  /// ea62, slt v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SLT``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16 [ "ea62" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 24, 0x1234UL ]
    |> run m16 [ "ea62" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL; G 24, 0x1234UL ]
    |> run m16 [ "ea62" ]
    |> is [ G 24, 0x1UL ]
    [ G 2, 0x2UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16 [ "ea62" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// 5201, slti v0, 0x1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SLTI``() =
    [ G 2, 0x7UL; G 24, 0x1234UL ]
    |> run m16 [ "5201" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 24, 0x1234UL ]
    |> run m16 [ "5201" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x89abcdefUL; G 24, 0x1234UL ]
    |> run m16 [ "5201" ]
    |> is [ G 24, 0x1UL ]
    [ G 24, 0x1234UL ]
    |> run m16 [ "5201" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// 5a01, sltiu v0, 0x1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SLTIU``() =
    [ G 2, 0x7UL; G 24, 0x1234UL ]
    |> run m16 [ "5a01" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 24, 0x1234UL ]
    |> run m16 [ "5a01" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x89abcdefUL; G 24, 0x1234UL ]
    |> run m16 [ "5a01" ]
    |> is [ G 24, 0x0UL ]
    [ G 24, 0x1234UL ]
    |> run m16 [ "5a01" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// ea63, sltu v0, v1, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SLTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16 [ "ea63" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 24, 0x1234UL ]
    |> run m16 [ "ea63" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL; G 24, 0x1234UL ]
    |> run m16 [ "ea63" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x2UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16 [ "ea63" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// 3263, sra v0, v1, 0x8, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SRA``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 31, 0x400cacUL ]
    |> run m16 [ "3263" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 31, 0x400cacUL ]
    |> run m16 [ "3263" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL; G 31, 0x400cacUL ]
    |> run m16 [ "3263" ]
    |> is [ G 2, 0x123456UL ]

  /// <summary>
  /// eb47, srav v0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SRAV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 31, 0x400cacUL ]
    |> run m16 [ "eb47" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 31, 0x400cacUL ]
    |> run m16 [ "eb47" ]
    |> is [ G 2, 0x3fffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL; G 31, 0x400cacUL ]
    |> run m16 [ "eb47" ]
    |> is [ G 2, 0xffffff89UL ]

  /// <summary>
  /// 3262, srl v0, v1, 0x8, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SRL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "3262" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "3262" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "3262" ]
    |> is [ G 2, 0x123456UL ]

  /// <summary>
  /// eb46, srlv v0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SRLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "eb46" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "eb46" ]
    |> is [ G 2, 0x3fffffffUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "eb46" ]
    |> is [ G 2, 0x89UL ]

  /// <summary>
  /// e273, subu a0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SUBU``() =
    [ G 2, 0x3UL; G 3, 0x5UL; G 4, 0x7UL ]
    |> run m16 [ "e273" ]
    |> is [ G 4, 0xfffffffeUL ]
    [ G 2, 0x1UL; G 3, 0xfffffffeUL; G 4, 0x7fffffffUL ]
    |> run m16 [ "e273" ]
    |> is [ G 4, 0x3UL ]
    [ G 2, 0x12345678UL; G 3, 0xfedcba98UL; G 4, 0x89abcdefUL ]
    |> run m16 [ "e273" ]
    |> is [ G 4, 0x13579be0UL ]

  /// <summary>
  /// d201, sw v0, 4(sp), against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 SW``() =
    let given0 =
      [ G 2, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xb4e8bdaa9dc32870UL
        M 0x20200080UL, 0x5f23fd520873435aUL
        M 0x20200088UL, 0x2b8ee80903dded35UL ]
    given0
    |> run m16 [ "d201" ]
    |> is [ M 0x20200080UL, 0x70873435aUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x2494d589b3562303UL
        M 0x20200080UL, 0xe9797ad618f4c157UL
        M 0x20200088UL, 0xfeb810f1ffe3bedaUL ]
    given1
    |> run m16 [ "d201" ]
    |> is [ M 0x20200080UL, 0x7fffffff18f4c157UL ]
    let given2 =
      [ G 2, 0x89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x3ac98b7dc74c645eUL
        M 0x20200080UL, 0x93a6c7097e97ef69UL
        M 0x20200088UL, 0xb7db38bfc5bedec9UL ]
    given2
    |> run m16 [ "d201" ]
    |> is [ M 0x20200080UL, 0x89abcdef7e97ef69UL ]

  /// <summary>
  /// ea6e, xor v0, v0, v1, against QEMU's 24Kf: the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 XOR``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16 [ "ea6e" ]
    |> is [ G 2, 0x4UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16 [ "ea6e" ]
    |> is [ G 2, 0x7ffffffeUL ]
    [ G 2, 0x89abcdefUL; G 3, 0x12345678UL ]
    |> run m16 [ "ea6e" ]
    |> is [ G 2, 0x9b9f9b97UL ]

  /// <summary>
  /// ea11, zeb v0, v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 ZEB``() =
    [ G 2, 0x7UL ]
    |> run m16 [ "ea11" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16 [ "ea11" ]
    |> is [ G 2, 0xffUL ]
    [ G 2, 0x89abcdefUL ]
    |> run m16 [ "ea11" ]
    |> is [ G 2, 0xefUL ]

  /// <summary>
  /// ea31, zeh v0, v0, against QEMU's 24Kf: the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00076 ZEH``() =
    [ G 2, 0x7UL ]
    |> run m16 [ "ea31" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16 [ "ea31" ]
    |> is [ G 2, 0xffffUL ]
    [ G 2, 0x89abcdefUL ]
    |> run m16 [ "ea31" ]
    |> is [ G 2, 0xcdefUL ]

  /// <summary>
  /// 4261, addiu v1, v0, 0x1, against QEMU's 24Kf: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 ADDIU``() =
    [ G 2, 0x3UL; G 3, 0x7UL ]
    |> run m16x64 [ "4261" ]
    |> is [ G 3, 0x4UL ]
    [ G 2, 0x1UL; G 3, 0x7fffffffUL ]
    |> run m16x64 [ "4261" ]
    |> is [ G 3, 0x2UL ]
    [ G 2, 0x12345678UL; G 3, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "4261" ]
    |> is [ G 3, 0x12345679UL ]

  /// <summary>
  /// e271, addu a0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 ADDU``() =
    [ G 2, 0x3UL; G 3, 0x5UL; G 4, 0x7UL ]
    |> run m16x64 [ "e271" ]
    |> is [ G 4, 0x8UL ]
    [ G 2, 0x1UL; G 3, 0xfffffffffffffffeUL; G 4, 0x7fffffffUL ]
    |> run m16x64 [ "e271" ]
    |> is [ G 4, 0xffffffffffffffffUL ]
    [ G 2, 0x12345678UL; G 3, 0xfffffffffedcba98UL; G 4, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "e271" ]
    |> is [ G 4, 0x11111110UL ]

  /// <summary>
  /// ea6c, and v0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 AND``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea6c" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea6c" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea6c" ]
    |> is [ G 2, 0x204468UL ]

  /// <summary>
  /// f000e001, asmacro 0x1, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGILL (UndefinedInstruction here); the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 ASMACRO``() =
    []
    |> run m16x64 [ "f000e001" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run m16x64 [ "f000e001" ]
    |> raises [ UndefinedInstruction ] []
    []
    |> run m16x64 [ "f000e001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 1010, b 0x20100022 (binutils: b 20100022). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is the
  /// branch's own, there being no delay slot; control goes to 0x20100022 (the
  /// target binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 B``() =
    let words = [ "1010" ]
    ownsJump m16x64 "1010" true
    goes m16x64 words [] 0x20100022UL

  /// <summary>
  /// 2210, beqz v0, 0x20100022 (binutils: beqz $2,20100022). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when it always does; to 0x20100002,
  /// past the branch, when G 2 is 0x5.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 BEQZ``() =
    let words = [ "2210" ]
    ownsJump m16x64 "2210" true
    goes m16x64 words [] 0x20100022UL
    goes m16x64 words [ G 2, 0x5UL ] 0x20100002UL

  /// <summary>
  /// 2a10, bnez v0, 0x20100022 (binutils: bnez $2,20100022). A branch is not
  /// run against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when G 2 is 0x5; to 0x20100002,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 BNEZ``() =
    let words = [ "2a10" ]
    ownsJump m16x64 "2a10" true
    goes m16x64 words [ G 2, 0x5UL ] 0x20100022UL
    goes m16x64 words [] 0x20100002UL

  /// <summary>
  /// e825, break 0x1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. QEMU raised SIGTRAP (Breakpoint here); the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 BREAK``() =
    []
    |> run m16x64 [ "e825" ]
    |> raises [ Breakpoint ] []
    []
    |> run m16x64 [ "e825" ]
    |> raises [ Breakpoint ] []
    []
    |> run m16x64 [ "e825" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// 6010, bteqz 0x20100022 (binutils: bteqz 20100022). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when it always does; to 0x20100002,
  /// past the branch, when G 24 is 0x1.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 BTEQZ``() =
    let words = [ "6010" ]
    ownsJump m16x64 "6010" true
    goes m16x64 words [] 0x20100022UL
    goes m16x64 words [ G 24, 0x1UL ] 0x20100002UL
