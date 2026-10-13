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
/// One test for each instruction of MD00076 and MD00077: BTNEZ to ZEW.
///
/// <para>A value test runs a word of the instruction under QEMU over a few
/// sets of register values, memory and FCSR, and has the lift change what
/// QEMU changed, raise what QEMU raised, and nothing else; every value it
/// expects is QEMU's (optest-mips/oracle). A structural test says in its own
/// comment what it checks and why no value test could be had.</para>
/// </summary>
[<TestClass>]
type ManualLifterTests5() =
  let m16x64 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSISAMode.MIPS16)

  /// <summary>
  /// 6110, btnez 0x20100022 (binutils: btnez 20100022). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100022 (the target binutils reads) when G 24 is 0x1; to 0x20100002,
  /// past the branch, when nothing is given.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 BTNEZ``() =
    let words = [ "6110" ]
    ownsJump m16x64 "6110" true
    goes m16x64 words [ G 24, 0x1UL ] 0x20100022UL
    goes m16x64 words [] 0x20100002UL

  /// <summary>
  /// ea6a, cmp v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 CMP``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea6a" ]
    |> is [ G 24, 0x4UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea6a" ]
    |> is [ G 24, 0x7ffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea6a" ]
    |> is [ G 24, 0xffffffff9b9f9b97UL ]

  /// <summary>
  /// 7201, cmpi v0, 0x1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 CMPI``() =
    [ G 2, 0x7UL; G 24, 0x1234UL ]
    |> run m16x64 [ "7201" ]
    |> is [ G 24, 0x6UL ]
    [ G 2, 0x7fffffffUL; G 24, 0x1234UL ]
    |> run m16x64 [ "7201" ]
    |> is [ G 24, 0x7ffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 24, 0x1234UL ]
    |> run m16x64 [ "7201" ]
    |> is [ G 24, 0xffffffff89abcdeeUL ]

  /// <summary>
  /// 4271, daddiu v1, v0, 0x1, against QEMU's MIPS64R2-generic: QEMU runs
  /// MIPS16e only on a 32-bit processor, so the values are what it left after
  /// daddiu $3,$2,1, the MIPS64 instruction binutils reads this word as. the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DADDIU``() =
    [ G 2, 0x3UL; G 3, 0x7UL ]
    |> run m16x64 [ "4271" ]
    |> is [ G 3, 0x4UL ]
    [ G 2, 0x1UL; G 3, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "4271" ]
    |> is [ G 3, 0x2UL ]
    [ G 2, 0xfedcba9876543210UL; G 3, 0x123456789abcdefUL ]
    |> run m16x64 [ "4271" ]
    |> is [ G 3, 0xfedcba9876543211UL ]

  /// <summary>
  /// e270, daddu a0, v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after daddu
  /// $4,$2,$3, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DADDU``() =
    [ G 2, 0x3UL; G 3, 0x5UL; G 4, 0x7UL ]
    |> run m16x64 [ "e270" ]
    |> is [ G 4, 0x8UL ]
    [ G 2, 0x1UL; G 3, 0xfffffffffffffffeUL; G 4, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "e270" ]
    |> is [ G 4, 0xffffffffffffffffUL ]
    [ G 2, 0xfedcba9876543210UL; G 3, 0xffffffffUL; G 4, 0x123456789abcdefUL ]
    |> run m16x64 [ "e270" ]
    |> is [ G 4, 0xfedcba997654320fUL ]

  /// <summary>
  /// ea7e, ddiv v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e only
  /// on a 32-bit processor, so the values are what it left after ddiv $0,$2,$3,
  /// the MIPS64 instruction binutils reads this word as. the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DDIV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea7e" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea7e" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "ea7e" ]
    |> is [ Hi, 0x123456789abcdefUL ]

  /// <summary>
  /// ea7f, ddivu v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after ddivu
  /// $0,$2,$3, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DDIVU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea7f" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea7f" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "ea7f" ]
    |> is [ Hi, 0x123456789abcdefUL ]

  /// <summary>
  /// ea7a, div v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DIV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea7a" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea7a" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea7a" ]
    |> is [ Hi, 0xfffffffff6e5d4bfUL; Lo, 0xfffffffffffffffaUL ]

  /// <summary>
  /// ea7b, divu v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DIVU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea7b" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea7b" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea7b" ]
    |> is [ Hi, 0xa3d70a7UL; Lo, 0x7UL ]

  /// <summary>
  /// ea7c, dmult v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dmult
  /// $2,$3, the MIPS64 instruction binutils reads this word as. the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DMULT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea7c" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea7c" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "ea7c" ]
    |> is [ Hi, 0xfffeb49923cc0953UL; Lo, 0x2236d88fe5618cf0UL ]

  /// <summary>
  /// ea7d, dmultu v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dmultu
  /// $2,$3, the MIPS64 instruction binutils reads this word as. the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DMULTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea7d" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea7d" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "ea7d" ]
    |> is [ Hi, 0x121fa00ad77d742UL; Lo, 0x2236d88fe5618cf0UL ]

  /// <summary>
  /// 3261, dsll v0, v1, 0x8, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsll
  /// $2,$3,8, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSLL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "3261" ]
    |> is [ G 2, 0x300UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "3261" ]
    |> is [ G 2, 0x100UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "3261" ]
    |> is [ G 2, 0xdcba987654321000UL ]

  /// <summary>
  /// eb54, dsllv v0, v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsllv
  /// $2,$2,$3, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSLLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "eb54" ]
    |> is [ G 2, 0x38UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "eb54" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "eb54" ]
    |> is [ G 2, 0x456789abcdef0000UL ]

  /// <summary>
  /// e853, dsra v0, v0, 0x8, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsra
  /// $2,8, the MIPS64 instruction binutils reads this word as. the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSRA``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "e853" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "e853" ]
    |> is [ G 2, 0x7fffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL ]
    |> run m16x64 [ "e853" ]
    |> is [ G 2, 0x123456789abcdUL ]

  /// <summary>
  /// eb57, dsrav v0, v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsrav
  /// $2,$2,$3, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSRAV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "eb57" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "eb57" ]
    |> is [ G 2, 0x3fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "eb57" ]
    |> is [ G 2, 0x123456789abUL ]

  /// <summary>
  /// e848, dsrl v0, v0, 0x8, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsrl
  /// $2,8, the MIPS64 instruction binutils reads this word as. the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSRL``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "e848" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "e848" ]
    |> is [ G 2, 0x7fffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL ]
    |> run m16x64 [ "e848" ]
    |> is [ G 2, 0x123456789abcdUL ]

  /// <summary>
  /// eb56, dsrlv v0, v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsrlv
  /// $2,$2,$3, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSRLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "eb56" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "eb56" ]
    |> is [ G 2, 0x3fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run m16x64 [ "eb56" ]
    |> is [ G 2, 0x123456789abUL ]

  /// <summary>
  /// e272, dsubu a0, v0, v1, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after dsubu
  /// $4,$2,$3, the MIPS64 instruction binutils reads this word as. the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 DSUBU``() =
    [ G 2, 0x3UL; G 3, 0x5UL; G 4, 0x7UL ]
    |> run m16x64 [ "e272" ]
    |> is [ G 4, 0xfffffffffffffffeUL ]
    [ G 2, 0x1UL; G 3, 0xfffffffffffffffeUL; G 4, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "e272" ]
    |> is [ G 4, 0x3UL ]
    [ G 2, 0xfedcba9876543210UL; G 3, 0xffffffffUL; G 4, 0x123456789abcdefUL ]
    |> run m16x64 [ "e272" ]
    |> is [ G 4, 0xfedcba9776543211UL ]

  /// <summary>
  /// 18000100, jal 0x20000400 (binutils: jal 20000400). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20000400 (the target binutils reads) when it always does; ra becomes
  /// 0x20100007 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 JAL``() =
    let words = [ "18000100"; "6500" ]
    ownsJump m16x64 "18000100" false
    goes m16x64 words [] 0x20000400UL
    []
    |> run m16x64 words
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
  member _.``MD00077 JALR``() =
    let words = [ "ea40"; "6500" ]
    ownsJump m16x64 "ea40" false
    goes m16x64 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16x64 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16
    [ G 2, 0x20100401UL ]
    |> run m16x64 words
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
  member _.``MD00077 JALRC``() =
    let words = [ "eac0" ]
    ownsJump m16x64 "eac0" true
    goes m16x64 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16x64 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16
    [ G 2, 0x20100401UL ]
    |> run m16x64 words
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
  member _.``MD00077 JALX``() =
    let words = [ "1c000100"; "6500" ]
    ownsJump m16x64 "1c000100" false
    goes m16x64 words [] 0x20000400UL
    switches m16x64 words [] InterJmpKind.SwitchToMIPS
    []
    |> run m16x64 words
    |> is [ G 31, 0x20100007UL ]

  /// <summary>
  /// ea00, jr v0 (binutils: jr $2). A branch is not run against QEMU: it moves
  /// the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is left to the delay
  /// slot, which holds a NOP; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 JR``() =
    let words = [ "ea00"; "6500" ]
    ownsJump m16x64 "ea00" false
    goes m16x64 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16x64 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16

  /// <summary>
  /// ea80, jrc v0 (binutils: jrc $2). A branch is not run against QEMU: it
  /// moves the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is the branch's own,
  /// there being no delay slot; control goes to 0x20100400 when G 2 is
  /// 0x20100401; the jump goes on in MIPS16.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 JRC``() =
    let words = [ "ea80" ]
    ownsJump m16x64 "ea80" true
    goes m16x64 words [ G 2, 0x20100401UL ] 0x20100400UL
    switches m16x64 words [ G 2, 0x20100401UL ] InterJmpKind.SwitchToMIPS16

  /// <summary>
  /// 8041, lb v0, 1(s0), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LB``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x60731e1249e481a1UL
        M 0x20200080UL, 0x2a7c89eb2f8fd28bUL
        M 0x20200088UL, 0x733109c42f3394cUL ]
    given0
    |> run m16x64 [ "8041" ]
    |> is [ G 2, 0x2aUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x5592c7b26ab880beUL
        M 0x20200080UL, 0xd250d5e84b89ab63UL
        M 0x20200088UL, 0x92490cccd873b364UL ]
    given1
    |> run m16x64 [ "8041" ]
    |> is [ G 2, 0xffffffffffffffd2UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x1f1bdc1e3c7e7630UL
        M 0x20200080UL, 0x19eb9e4f53b87ddeUL
        M 0x20200088UL, 0x2b99dec7cd501c7dUL ]
    given2
    |> run m16x64 [ "8041" ]
    |> is [ G 2, 0x19UL ]

  /// <summary>
  /// a041, lbu v0, 1(s0), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LBU``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x747a478c2285e948UL
        M 0x20200080UL, 0xd223da4bc5f3b1abUL
        M 0x20200088UL, 0x80dfb78762b42c41UL ]
    given0
    |> run m16x64 [ "a041" ]
    |> is [ G 2, 0xd2UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xc96e378611d35ae8UL
        M 0x20200080UL, 0x3783bea2bc5d1808UL
        M 0x20200088UL, 0x677170823009decbUL ]
    given1
    |> run m16x64 [ "a041" ]
    |> is [ G 2, 0x37UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x40f542d168f3aeacUL
        M 0x20200080UL, 0x32da52298c14894dUL
        M 0x20200088UL, 0xb1d7fc1242d6ad2bUL ]
    given2
    |> run m16x64 [ "a041" ]
    |> is [ G 2, 0x32UL ]

  /// <summary>
  /// 3841, ld v0, 8(s0), against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after ld
  /// $2,8($16), the MIPS64 instruction binutils reads this word as. the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LD``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x20200078UL
        M 0x20200078UL, 0x2b7df8fa90c21e64UL
        M 0x20200080UL, 0x9006ce5919877c2cUL
        M 0x20200088UL, 0xe274e8dbd5e38a79UL ]
    given0
    |> run m16x64 [ "3841" ]
    |> is [ G 2, 0x9006ce5919877c2cUL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 16, 0x20200078UL
        M 0x20200078UL, 0x3f5af6179ccddb0fUL
        M 0x20200080UL, 0x4d4fc664766c85d1UL
        M 0x20200088UL, 0x2dd28fc05a162a99UL ]
    given1
    |> run m16x64 [ "3841" ]
    |> is [ G 2, 0x4d4fc664766c85d1UL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 16, 0x20200078UL
        M 0x20200078UL, 0xb3399766106b1a55UL
        M 0x20200080UL, 0x2af7a483c1331fbeUL
        M 0x20200088UL, 0x16f752af7905faeeUL ]
    given2
    |> run m16x64 [ "3841" ]
    |> is [ G 2, 0x2af7a483c1331fbeUL ]

  /// <summary>
  /// 8841, lh v0, 2(s0), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LH``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xcf5f9772b55750deUL
        M 0x20200080UL, 0xf3d797e502a537d2UL
        M 0x20200088UL, 0xb498530b9994abb9UL ]
    given0
    |> run m16x64 [ "8841" ]
    |> is [ G 2, 0xfffffffffffff3d7UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xefa2e57b1d9b114bUL
        M 0x20200080UL, 0x383fc11eea0d8fe0UL
        M 0x20200088UL, 0x63f893bb031eafdUL ]
    given1
    |> run m16x64 [ "8841" ]
    |> is [ G 2, 0x383fUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x5ed96a3731248d7bUL
        M 0x20200080UL, 0xc3f384b76c1a405dUL
        M 0x20200088UL, 0xd62170492578efebUL ]
    given2
    |> run m16x64 [ "8841" ]
    |> is [ G 2, 0xffffffffffffc3f3UL ]

  /// <summary>
  /// a841, lhu v0, 2(s0), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LHU``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xd21229b252e9e73bUL
        M 0x20200080UL, 0xfa95031214736ee3UL
        M 0x20200088UL, 0xf9644c3a3aa90ba4UL ]
    given0
    |> run m16x64 [ "a841" ]
    |> is [ G 2, 0xfa95UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x7647e9edce01c894UL
        M 0x20200080UL, 0xfed9ee3f84156ceaUL
        M 0x20200088UL, 0x7c0585680e33d31fUL ]
    given1
    |> run m16x64 [ "a841" ]
    |> is [ G 2, 0xfed9UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x87ee2fb0c77525b5UL
        M 0x20200080UL, 0x6830a279e8d3a1a9UL
        M 0x20200088UL, 0x341e7007cabc94ebUL ]
    given2
    |> run m16x64 [ "a841" ]
    |> is [ G 2, 0x6830UL ]

  /// <summary>
  /// 6a01, li v0, 0x1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LI``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "6a01" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x7fffffffUL ]
    |> run m16x64 [ "6a01" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "6a01" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 9201, lw v0, 4(sp), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LW``() =
    let given0 =
      [ G 2, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xde67efea1b9ff1f6UL
        M 0x20200080UL, 0x8890a4f8fbdfeabcUL
        M 0x20200088UL, 0x27efcb9723250e39UL ]
    given0
    |> run m16x64 [ "9201" ]
    |> is [ G 2, 0xffffffff8890a4f8UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x13caa252adcd3891UL
        M 0x20200080UL, 0x7096319bf85dc4f1UL
        M 0x20200088UL, 0x8ffb0b43bbed2fb1UL ]
    given1
    |> run m16x64 [ "9201" ]
    |> is [ G 2, 0x7096319bUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xb4911b65967757a1UL
        M 0x20200080UL, 0x81258ad75f22ed4cUL
        M 0x20200088UL, 0x9e1f340ee0dae260UL ]
    given2
    |> run m16x64 [ "9201" ]
    |> is [ G 2, 0xffffffff81258ad7UL ]

  /// <summary>
  /// b841, lwu v0, 4(s0), against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after lwu
  /// $2,4($16), the MIPS64 instruction binutils reads this word as. the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 LWU``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007cUL
        M 0x20200078UL, 0x853e28e781a4dd39UL
        M 0x20200080UL, 0x8ca324a8fc5ea486UL
        M 0x20200088UL, 0xa310e31aa64fc94eUL ]
    given0
    |> run m16x64 [ "b841" ]
    |> is [ G 2, 0x8ca324a8UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007cUL
        M 0x20200078UL, 0x7294ded984baa8c2UL
        M 0x20200080UL, 0xb64bdaf3269ebe04UL
        M 0x20200088UL, 0xcca7b29e4844a476UL ]
    given1
    |> run m16x64 [ "b841" ]
    |> is [ G 2, 0xb64bdaf3UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007cUL
        M 0x20200078UL, 0x76b797e57cc60e5cUL
        M 0x20200080UL, 0xe71d444e4e06bec5UL
        M 0x20200088UL, 0xa245977baf8e6514UL ]
    given2
    |> run m16x64 [ "b841" ]
    |> is [ G 2, 0xe71d444eUL ]

  /// <summary>
  /// ea10, mfhi v0, against QEMU's 24Kf: that processor is 32-bit, and a 64-bit
  /// one holds each word sign-extended, which is what the values here are. the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 MFHI``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run m16x64 [ "ea10" ]
    |> is [ G 2, 0x13UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run m16x64 [ "ea10" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run m16x64 [ "ea10" ]
    |> is [ G 2, 0xffffffffdeadbeefUL ]

  /// <summary>
  /// ea12, mflo v0, against QEMU's 24Kf: that processor is 32-bit, and a 64-bit
  /// one holds each word sign-extended, which is what the values here are. the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 MFLO``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run m16x64 [ "ea12" ]
    |> is [ G 2, 0x24UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run m16x64 [ "ea12" ]
    |> is [ G 2, 0xffffffff80000001UL ]
    [ G 2, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run m16x64 [ "ea12" ]
    |> is [ G 2, 0x12345678UL ]

  /// <summary>
  /// 6522, move at, v0, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 MOVE``() =
    [ G 1, 0x7UL; G 2, 0x3UL ]
    |> run m16x64 [ "6522" ]
    |> is [ G 1, 0x3UL ]
    [ G 1, 0x7fffffffUL; G 2, 0x1UL ]
    |> run m16x64 [ "6522" ]
    |> is [ G 1, 0x1UL ]
    [ G 1, 0xffffffff89abcdefUL; G 2, 0x12345678UL ]
    |> run m16x64 [ "6522" ]
    |> is [ G 1, 0x12345678UL ]

  /// <summary>
  /// ea78, mult v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 MULT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea78" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea78" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea78" ]
    |> is [ Hi, 0xfffffffff795e368UL; Lo, 0xffffffffe242d208UL ]

  /// <summary>
  /// ea79, multu v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 MULTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea79" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea79" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea79" ]
    |> is [ Hi, 0x9ca39e0UL; Lo, 0xffffffffe242d208UL ]

  /// <summary>
  /// ea6b, neg v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 NEG``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea6b" ]
    |> is [ G 2, 0xfffffffffffffffdUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea6b" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea6b" ]
    |> is [ G 2, 0xffffffffedcba988UL ]

  /// <summary>
  /// 6500, nop, against QEMU's 24Kf: that processor is 32-bit, and a 64-bit one
  /// holds each word sign-extended, which is what the values here are. the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 NOP``() =
    []
    |> run m16x64 [ "6500" ]
    |> is []
    []
    |> run m16x64 [ "6500" ]
    |> is []
    []
    |> run m16x64 [ "6500" ]
    |> is []

  /// <summary>
  /// ea6f, not v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 NOT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea6f" ]
    |> is [ G 2, 0xfffffffffffffffcUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea6f" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea6f" ]
    |> is [ G 2, 0xffffffffedcba987UL ]

  /// <summary>
  /// ea6d, or v0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 OR``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea6d" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea6d" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea6d" ]
    |> is [ G 2, 0xffffffff9bbfdfffUL ]

  /// <summary>
  /// 6432, restore 0x10, s0, s1, against QEMU's 24Kf: that processor is 32-bit,
  /// and a 64-bit one holds each word sign-extended, which is what the values
  /// here are. the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 RESTORE``() =
    let given0 =
      [ G 16, 0x7UL
        G 17, 0x3UL
        G 29, 0x20200080UL
        M 0x20200060UL, 0xc9970bd2e7d55c49UL
        M 0x20200068UL, 0x4792c53e95b6e541UL
        M 0x20200070UL, 0x2545c6776588e42bUL
        M 0x20200078UL, 0xaf459b845d732aaaUL
        M 0x20200080UL, 0xd050173007becea8UL
        M 0x20200088UL, 0x4bd40ec00c7a8ddfUL
        M 0x20200090UL, 0x303f3d0ced60f16bUL
        M 0x20200098UL, 0xf8400ec5b3b1448bUL ]
    given0
    |> run m16x64 [ "6432" ]
    |> is [ G 16, 0x4bd40ec0UL; G 17, 0xc7a8ddfUL; G 29, 0x20200090UL ]
    let given1 =
      [ G 16, 0x7fffffffUL
        G 17, 0x1UL
        G 29, 0x20200080UL
        M 0x20200060UL, 0xafe50180b8be1463UL
        M 0x20200068UL, 0xfdfc55ce81e64b89UL
        M 0x20200070UL, 0xde77d64cdd11d9dbUL
        M 0x20200078UL, 0xf51d2f68483d944aUL
        M 0x20200080UL, 0x9a03882af8216554UL
        M 0x20200088UL, 0x6f17b3691b04e42cUL
        M 0x20200090UL, 0x5430eb91c3931ec2UL
        M 0x20200098UL, 0x4a1a7fb11c2279fbUL ]
    given1
    |> run m16x64 [ "6432" ]
    |> is [ G 16, 0x6f17b369UL; G 17, 0x1b04e42cUL; G 29, 0x20200090UL ]
    let given2 =
      [ G 16, 0xffffffff89abcdefUL
        G 17, 0x12345678UL
        G 29, 0x20200080UL
        M 0x20200060UL, 0xad8eed7154a41520UL
        M 0x20200068UL, 0xa17bb6fc66de3e43UL
        M 0x20200070UL, 0x86379530cf8b418bUL
        M 0x20200078UL, 0xfa6860f30a86e34eUL
        M 0x20200080UL, 0xe02f48ad614999acUL
        M 0x20200088UL, 0x459d352abd871421UL
        M 0x20200090UL, 0xb2032ab5f01e80d0UL
        M 0x20200098UL, 0xea0fb5c3dced07cfUL ]
    given2
    |> run m16x64 [ "6432" ]
    |> is [ G 16, 0x459d352aUL; G 17, 0xffffffffbd871421UL; G 29, 0x20200090UL ]

  /// <summary>
  /// 64f2, save 0x10, ra, s0, s1, against QEMU's 24Kf: that processor is
  /// 32-bit, and a 64-bit one holds each word sign-extended, which is what the
  /// values here are. the lift has to change what QEMU changed and nothing
  /// else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SAVE``() =
    let given0 =
      [ G 16, 0x3UL
        G 17, 0x5UL
        G 29, 0x20200080UL
        G 31, 0x400cacUL
        M 0x20200060UL, 0xef1ec0d1422d6b49UL
        M 0x20200068UL, 0x39e4dcb381721e1dUL
        M 0x20200070UL, 0xefe8bf71a3ee8c7bUL
        M 0x20200078UL, 0xcca16b8fd5a8464fUL
        M 0x20200080UL, 0x9a80220e91a88248UL
        M 0x20200088UL, 0xb26b5763ad017956UL
        M 0x20200090UL, 0x24a38da9e59a5b97UL
        M 0x20200098UL, 0x4b5110f1f094c3dUL ]
    let expected0 =
      [ G 29, 0x20200070UL
        M 0x20200070UL, 0xefe8bf7100000003UL
        M 0x20200078UL, 0x500400cacUL ]
    given0
    |> run m16x64 [ "64f2" ]
    |> is expected0
    let given1 =
      [ G 16, 0x1UL
        G 17, 0xfffffffffffffffeUL
        G 29, 0x20200080UL
        G 31, 0x400cacUL
        M 0x20200060UL, 0xaebfb9f0c23b0c51UL
        M 0x20200068UL, 0x658dd38b673e14f1UL
        M 0x20200070UL, 0xc0809c450756040fUL
        M 0x20200078UL, 0x1bfa632989064770UL
        M 0x20200080UL, 0xdb8ae71b639c748eUL
        M 0x20200088UL, 0x968318fb40df6805UL
        M 0x20200090UL, 0x45be6cd634602388UL
        M 0x20200098UL, 0xcd5973ba1de8b843UL ]
    let expected1 =
      [ G 29, 0x20200070UL
        M 0x20200070UL, 0xc0809c4500000001UL
        M 0x20200078UL, 0xfffffffe00400cacUL ]
    given1
    |> run m16x64 [ "64f2" ]
    |> is expected1
    let given2 =
      [ G 16, 0x12345678UL
        G 17, 0xfffffffffedcba98UL
        G 29, 0x20200080UL
        G 31, 0x400cacUL
        M 0x20200060UL, 0xef9e59258f9311c3UL
        M 0x20200068UL, 0xc3d3a8b3848c478bUL
        M 0x20200070UL, 0x81c4cf8d8aad3abdUL
        M 0x20200078UL, 0xe2f4f8680a5c0c47UL
        M 0x20200080UL, 0xd3580aee866e3cb4UL
        M 0x20200088UL, 0x5eb2cece265a85fbUL
        M 0x20200090UL, 0x9703504eb04d437dUL
        M 0x20200098UL, 0xc21c09996dae4cebUL ]
    let expected2 =
      [ G 29, 0x20200070UL
        M 0x20200070UL, 0x81c4cf8d12345678UL
        M 0x20200078UL, 0xfedcba9800400cacUL ]
    given2
    |> run m16x64 [ "64f2" ]
    |> is expected2

  /// <summary>
  /// c041, sb v0, 1(s0), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SB``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xd86f09e52c4578a5UL
        M 0x20200080UL, 0xf88481a46b9034aaUL
        M 0x20200088UL, 0xbb0b588f897fe96cUL ]
    given0
    |> run m16x64 [ "c041" ]
    |> is [ M 0x20200080UL, 0x78481a46b9034aaUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0xce1146d87760e1bUL
        M 0x20200080UL, 0x839980c866cd18c0UL
        M 0x20200088UL, 0xbc1393c4d338997bUL ]
    given1
    |> run m16x64 [ "c041" ]
    |> is [ M 0x20200080UL, 0xff9980c866cd18c0UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007fUL
        M 0x20200078UL, 0x1f2b206b72d8784fUL
        M 0x20200080UL, 0x18353872b0516498UL
        M 0x20200088UL, 0x60d61987751c910aUL ]
    given2
    |> run m16x64 [ "c041" ]
    |> is [ M 0x20200080UL, 0xef353872b0516498UL ]

  /// <summary>
  /// 7841, sd v0, 8(s0), against QEMU's MIPS64R2-generic: QEMU runs MIPS16e
  /// only on a 32-bit processor, so the values are what it left after sd
  /// $2,8($16), the MIPS64 instruction binutils reads this word as. the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SD``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x20200078UL
        M 0x20200078UL, 0xca45620b379b4de2UL
        M 0x20200080UL, 0x7f613f626c5f9760UL
        M 0x20200088UL, 0xd95882a1e203e6f4UL ]
    given0
    |> run m16x64 [ "7841" ]
    |> is [ M 0x20200080UL, 0x7UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 16, 0x20200078UL
        M 0x20200078UL, 0xaa2b45c4ad98890cUL
        M 0x20200080UL, 0xb8aa98dc07c8d492UL
        M 0x20200088UL, 0x49a71229fdf46308UL ]
    given1
    |> run m16x64 [ "7841" ]
    |> is [ M 0x20200080UL, 0x7fffffffffffffffUL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 16, 0x20200078UL
        M 0x20200078UL, 0x600c37e059b86d0cUL
        M 0x20200080UL, 0xc62523c5af394eedUL
        M 0x20200088UL, 0xb32a155389a67b90UL ]
    given2
    |> run m16x64 [ "7841" ]
    |> is [ M 0x20200080UL, 0x123456789abcdefUL ]

  /// <summary>
  /// e821, sdbbp 0x1. Not run against QEMU, whose user mode aborts on the debug
  /// exception it raises; the manual enters the debug handler, which is this
  /// architecture's breakpoint. The lift raises Breakpoint and changes nothing.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SDBBP``() =
    []
    |> run m16x64 [ "e821" ]
    |> raises [ Breakpoint ] []

  /// <summary>
  /// ea91, seb v0, v0, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SEB``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "ea91" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16x64 [ "ea91" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "ea91" ]
    |> is [ G 2, 0xffffffffffffffefUL ]

  /// <summary>
  /// eab1, seh v0, v0, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SEH``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "eab1" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16x64 [ "eab1" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "eab1" ]
    |> is [ G 2, 0xffffffffffffcdefUL ]

  /// <summary>
  /// ead1, sew v0, v0, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e only
  /// on a 32-bit processor, so the values are what it left after sll $2,$2,0,
  /// the MIPS64 instruction binutils reads this word as. the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SEW``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "ead1" ]
    |> is []
    [ G 2, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "ead1" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL ]
    |> run m16x64 [ "ead1" ]
    |> is [ G 2, 0xffffffff89abcdefUL ]

  /// <summary>
  /// c841, sh v0, 2(s0), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SH``() =
    let given0 =
      [ G 2, 0x7UL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xc301b029a05ed52fUL
        M 0x20200080UL, 0x29afec30e561e916UL
        M 0x20200088UL, 0x79ef19f6d68e9a6cUL ]
    given0
    |> run m16x64 [ "c841" ]
    |> is [ M 0x20200080UL, 0x7ec30e561e916UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0x117984704c2f6470UL
        M 0x20200080UL, 0x6eff424adce40b27UL
        M 0x20200088UL, 0xebbd3287be9f6f0cUL ]
    given1
    |> run m16x64 [ "c841" ]
    |> is [ M 0x20200080UL, 0xffff424adce40b27UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 16, 0x2020007eUL
        M 0x20200078UL, 0xa79bdaf709925048UL
        M 0x20200080UL, 0xd32dcfa9f0844bafUL
        M 0x20200088UL, 0xfd552f353bc712b3UL ]
    given2
    |> run m16x64 [ "c841" ]
    |> is [ M 0x20200080UL, 0xcdefcfa9f0844bafUL ]

  /// <summary>
  /// 3260, sll v0, v1, 0x8, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SLL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "3260" ]
    |> is [ G 2, 0x300UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "3260" ]
    |> is [ G 2, 0x100UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "3260" ]
    |> is [ G 2, 0x34567800UL ]

  /// <summary>
  /// eb44, sllv v0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SLLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "eb44" ]
    |> is [ G 2, 0x38UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "eb44" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "eb44" ]
    |> is [ G 2, 0xffffffffef000000UL ]

  /// <summary>
  /// ea62, slt v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SLT``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea62" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea62" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea62" ]
    |> is [ G 24, 0x1UL ]
    [ G 2, 0x2UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea62" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// 5201, slti v0, 0x1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SLTI``() =
    [ G 2, 0x7UL; G 24, 0x1234UL ]
    |> run m16x64 [ "5201" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 24, 0x1234UL ]
    |> run m16x64 [ "5201" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 24, 0x1234UL ]
    |> run m16x64 [ "5201" ]
    |> is [ G 24, 0x1UL ]
    [ G 24, 0x1234UL ]
    |> run m16x64 [ "5201" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// 5a01, sltiu v0, 0x1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SLTIU``() =
    [ G 2, 0x7UL; G 24, 0x1234UL ]
    |> run m16x64 [ "5a01" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 24, 0x1234UL ]
    |> run m16x64 [ "5a01" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 24, 0x1234UL ]
    |> run m16x64 [ "5a01" ]
    |> is [ G 24, 0x0UL ]
    [ G 24, 0x1234UL ]
    |> run m16x64 [ "5a01" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// ea63, sltu v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SLTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea63" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea63" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea63" ]
    |> is [ G 24, 0x0UL ]
    [ G 2, 0x2UL; G 3, 0x3UL; G 24, 0x1234UL ]
    |> run m16x64 [ "ea63" ]
    |> is [ G 24, 0x1UL ]

  /// <summary>
  /// 3263, sra v0, v1, 0x8, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SRA``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 31, 0x400cacUL ]
    |> run m16x64 [ "3263" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 31, 0x400cacUL ]
    |> run m16x64 [ "3263" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 31, 0x400cacUL ]
    |> run m16x64 [ "3263" ]
    |> is [ G 2, 0x123456UL ]

  /// <summary>
  /// eb47, srav v0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SRAV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 31, 0x400cacUL ]
    |> run m16x64 [ "eb47" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 31, 0x400cacUL ]
    |> run m16x64 [ "eb47" ]
    |> is [ G 2, 0x3fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 31, 0x400cacUL ]
    |> run m16x64 [ "eb47" ]
    |> is [ G 2, 0xffffffffffffff89UL ]

  /// <summary>
  /// 3262, srl v0, v1, 0x8, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SRL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "3262" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "3262" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "3262" ]
    |> is [ G 2, 0x123456UL ]

  /// <summary>
  /// eb46, srlv v0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SRLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "eb46" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "eb46" ]
    |> is [ G 2, 0x3fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "eb46" ]
    |> is [ G 2, 0x89UL ]

  /// <summary>
  /// e273, subu a0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and
  /// a 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SUBU``() =
    [ G 2, 0x3UL; G 3, 0x5UL; G 4, 0x7UL ]
    |> run m16x64 [ "e273" ]
    |> is [ G 4, 0xfffffffffffffffeUL ]
    [ G 2, 0x1UL; G 3, 0xfffffffffffffffeUL; G 4, 0x7fffffffUL ]
    |> run m16x64 [ "e273" ]
    |> is [ G 4, 0x3UL ]
    [ G 2, 0x12345678UL; G 3, 0xfffffffffedcba98UL; G 4, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "e273" ]
    |> is [ G 4, 0x13579be0UL ]

  /// <summary>
  /// d201, sw v0, 4(sp), against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 SW``() =
    let given0 =
      [ G 2, 0x7UL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0x40c519308c7bb986UL
        M 0x20200080UL, 0xfaf65414c4d22066UL
        M 0x20200088UL, 0xa1714c4cab887d85UL ]
    given0
    |> run m16x64 [ "d201" ]
    |> is [ M 0x20200080UL, 0x7c4d22066UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xd34515152f22ef99UL
        M 0x20200080UL, 0x4368fc06cbfc9602UL
        M 0x20200088UL, 0x355f5157a96e9e2bUL ]
    given1
    |> run m16x64 [ "d201" ]
    |> is [ M 0x20200080UL, 0x7fffffffcbfc9602UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 29, 0x2020007cUL
        M 0x20200078UL, 0xb3e44261bf5033f1UL
        M 0x20200080UL, 0xc05c9bf1cbd94c50UL
        M 0x20200088UL, 0xb31352c25622d8a1UL ]
    given2
    |> run m16x64 [ "d201" ]
    |> is [ M 0x20200080UL, 0x89abcdefcbd94c50UL ]

  /// <summary>
  /// ea6e, xor v0, v0, v1, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 XOR``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run m16x64 [ "ea6e" ]
    |> is [ G 2, 0x4UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run m16x64 [ "ea6e" ]
    |> is [ G 2, 0x7ffffffeUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run m16x64 [ "ea6e" ]
    |> is [ G 2, 0xffffffff9b9f9b97UL ]

  /// <summary>
  /// ea11, zeb v0, v0, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 ZEB``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "ea11" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16x64 [ "ea11" ]
    |> is [ G 2, 0xffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "ea11" ]
    |> is [ G 2, 0xefUL ]

  /// <summary>
  /// ea31, zeh v0, v0, against QEMU's 24Kf: that processor is 32-bit, and a
  /// 64-bit one holds each word sign-extended, which is what the values here
  /// are. the lift has to change what QEMU changed and nothing else, over each
  /// set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 ZEH``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "ea31" ]
    |> is []
    [ G 2, 0x7fffffffUL ]
    |> run m16x64 [ "ea31" ]
    |> is [ G 2, 0xffffUL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run m16x64 [ "ea31" ]
    |> is [ G 2, 0xcdefUL ]

  /// <summary>
  /// ea51, zew v0, v0, against QEMU's MIPS64R2-generic: QEMU runs MIPS16e only
  /// on a 32-bit processor, so the values are what it left after dext
  /// $2,$2,0,32, the MIPS64 instruction binutils reads this word as. the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00077 ZEW``() =
    [ G 2, 0x7UL ]
    |> run m16x64 [ "ea51" ]
    |> is []
    [ G 2, 0x7fffffffffffffffUL ]
    |> run m16x64 [ "ea51" ]
    |> is [ G 2, 0xffffffffUL ]
    [ G 2, 0x123456789abcdefUL ]
    |> run m16x64 [ "ea51" ]
    |> is [ G 2, 0x89abcdefUL ]
