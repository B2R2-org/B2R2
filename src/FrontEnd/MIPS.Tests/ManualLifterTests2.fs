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
/// One test for each instruction of MD00087: DINSU to MSUBF.fmt.
///
/// <para>A value test runs a word of the instruction under QEMU over a few
/// sets of register values, memory and FCSR, and has the lift change what
/// QEMU changed, raise what QEMU raised, and nothing else; every value it
/// expects is QEMU's (optest-mips/oracle). A structural test says in its own
/// comment what it checks and why no value test could be had.</para>
/// </summary>
[<TestClass>]
type ManualLifterTests2() =
  let r2 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)

  let r6 =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64, int MIPSRelease.R6)

  /// <summary>
  /// 7c621806, dinsu v0, v1, 0x20, 0x4, against QEMU's MIPS64R2-generic: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DINSU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c621806" ]
    |> is [ G 2, 0x300000007UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c621806" ]
    |> is [ G 2, 0x7ffffff1ffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "7c621806" ]
    |> is [ G 2, 0x123456089abcdefUL ]

  /// <summary>
  /// 0043001a, div v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DIV``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0043001a" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0043001a" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "0043001a" ]
    |> is [ Hi, 0xfffffffff6e5d4bfUL; Lo, 0xfffffffffffffffaUL ]

  /// <summary>
  /// 46062083, div.s f2, f4, f6, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DIV.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL ]
    |> run r2 [ "46062083" ]
    |> is [ F 2, 0x3fc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL ]
    |> run r2 [ "46062083" ]
    |> is [ F 2, 0xc1000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL ]
    |> run r2 [ "46062083" ]
    |> is [ F 2, 0x45fa0000UL ]

  /// <summary>
  /// 0043001b, divu v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DIVU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0043001b" ]
    |> is [ Hi, 0x1UL; Lo, 0x2UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0043001b" ]
    |> is [ Lo, 0x7fffffffUL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "0043001b" ]
    |> is [ Hi, 0xa3d70a7UL; Lo, 0x7UL ]

  /// <summary>
  /// 00641015, dlsa v0, v1, a0, 0x0, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DLSA``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "00641015" ]
    |> is [ G 2, 0xbUL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "00641015" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "00641015" ]
    |> is [ G 2, 0xfdb97531eca8641fUL ]

  /// <summary>
  /// 40221801, dmfc0 v0, 0x3, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMFC0``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r2 [ "40221801" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r2 [ "40221801" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r2 [ "40221801" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 44221000, dmfc1 v0, f2, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMFC1``() =
    [ G 2, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run r2 [ "44221000" ]
    |> is [ G 2, 0x1122334455667788UL ]
    [ G 2, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run r2 [ "44221000" ]
    |> is [ G 2, 0xbf800000UL ]
    [ G 2, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run r2 [ "44221000" ]
    |> is [ G 2, 0x8899aabbccddeeffUL ]

  /// <summary>
  /// 48211900, dmfc2 at, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMFC2``() =
    [ G 1, 0x7UL ]
    |> run r2 [ "48211900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run r2 [ "48211900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run r2 [ "48211900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 006410de, dmod v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMOD``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410de" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410de" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "006410de" ]
    |> is [ G 2, 0xffffffff7530eca9UL ]

  /// <summary>
  /// 006410df, dmodu v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMODU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410df" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410df" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "006410df" ]
    |> is [ G 2, 0x7530eca9UL ]

  /// <summary>
  /// 40a00001, dmtc0 r0, 0x0, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMTC0``() =
    [ Status, 0x10UL ]
    |> run r2 [ "40a00001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40a00001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40a00001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 44a21000, dmtc1 v0, f2, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMTC1``() =
    [ G 2, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run r2 [ "44a21000" ]
    |> is [ F 2, 0x7UL ]
    [ G 2, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run r2 [ "44a21000" ]
    |> is [ F 2, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run r2 [ "44a21000" ]
    |> is [ F 2, 0x123456789abcdefUL ]

  /// <summary>
  /// 48a21900, dmtc2 v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMTC2``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "48a21900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "48a21900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "48a21900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 006410dc, dmuh v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMUH``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410dc" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410dc" ]
    |> is [ G 2, 0xffffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "006410dc" ]
    |> is [ G 2, 0xfffffffffedcba98UL ]

  /// <summary>
  /// 006410dd, dmuhu v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMUHU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410dd" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410dd" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "006410dd" ]
    |> is [ G 2, 0xfedcba97UL ]

  /// <summary>
  /// 0064109c, dmul v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMUL``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "0064109c" ]
    |> is [ G 2, 0xfUL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "0064109c" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "0064109c" ]
    |> is [ G 2, 0x7777777789abcdf0UL ]

  /// <summary>
  /// 0043001c, dmult v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMULT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0043001c" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0043001c" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0043001c" ]
    |> is [ Hi, 0xfffeb49923cc0953UL; Lo, 0x2236d88fe5618cf0UL ]

  /// <summary>
  /// 0043001d, dmultu v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMULTU``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0043001d" ]
    |> is [ Lo, 0x15UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0043001d" ]
    |> is [ Lo, 0x7fffffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0043001d" ]
    |> is [ Hi, 0x121fa00ad77d742UL; Lo, 0x2236d88fe5618cf0UL ]

  /// <summary>
  /// 0064109d, dmulu v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DMULU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "0064109d" ]
    |> is [ G 2, 0xfUL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "0064109d" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r6 [ "0064109d" ]
    |> is [ G 2, 0x7777777789abcdf0UL ]

  /// <summary>
  /// 0023113a, drotr v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DROTR``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0023113a" ]
    |> is [ G 2, 0x3000000000000000UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0023113a" ]
    |> is [ G 2, 0x1000000000000000UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0023113a" ]
    |> is [ G 2, 0xfedcba987654321UL ]

  /// <summary>
  /// 0023113e, drotr32 v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DROTR32``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0023113e" ]
    |> is [ G 2, 0x30000000UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0023113e" ]
    |> is [ G 2, 0x10000000UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0023113e" ]
    |> is [ G 2, 0x876543210fedcba9UL ]

  /// <summary>
  /// 00831056, drotrv v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DROTRV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831056" ]
    |> is [ G 2, 0x1800000000000000UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831056" ]
    |> is [ G 2, 0x4UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "00831056" ]
    |> is [ G 2, 0xfdb97530eca86421UL ]

  /// <summary>
  /// 7c0210a4, dsbh v0, v0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSBH``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "7c0210a4" ]
    |> is [ G 2, 0x700UL ]
    [ G 2, 0x7fffffffffffffffUL ]
    |> run r2 [ "7c0210a4" ]
    |> is [ G 2, 0xff7fffffffffffffUL ]
    [ G 2, 0x123456789abcdefUL ]
    |> run r2 [ "7c0210a4" ]
    |> is [ G 2, 0x23016745ab89efcdUL ]

  /// <summary>
  /// 7c021164, dshd v0, v0, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSHD``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "7c021164" ]
    |> is [ G 2, 0x7000000000000UL ]
    [ G 2, 0x7fffffffffffffffUL ]
    |> run r2 [ "7c021164" ]
    |> is [ G 2, 0xffffffffffff7fffUL ]
    [ G 2, 0x123456789abcdefUL ]
    |> run r2 [ "7c021164" ]
    |> is [ G 2, 0xcdef89ab45670123UL ]

  /// <summary>
  /// 00031138, dsll v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSLL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00031138" ]
    |> is [ G 2, 0x30UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "00031138" ]
    |> is [ G 2, 0x10UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "00031138" ]
    |> is [ G 2, 0xedcba98765432100UL ]

  /// <summary>
  /// 0003113c, dsll32 v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSLL32``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0003113c" ]
    |> is [ G 2, 0x3000000000UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0003113c" ]
    |> is [ G 2, 0x1000000000UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0003113c" ]
    |> is [ G 2, 0x6543210000000000UL ]

  /// <summary>
  /// 00831014, dsllv v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSLLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831014" ]
    |> is [ G 2, 0x60UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831014" ]
    |> is [ G 2, 0x4000000000000000UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "00831014" ]
    |> is [ G 2, 0x0UL ]

  /// <summary>
  /// 0003113b, dsra v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSRA``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0003113b" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0003113b" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0003113b" ]
    |> is [ G 2, 0xffedcba987654321UL ]

  /// <summary>
  /// 0003113f, dsra32 v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSRA32``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0003113f" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0003113f" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0003113f" ]
    |> is [ G 2, 0xffffffffffedcba9UL ]

  /// <summary>
  /// 00831017, dsrav v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSRAV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831017" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831017" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "00831017" ]
    |> is [ G 2, 0xffffffffffffffffUL ]

  /// <summary>
  /// 0003113a, dsrl v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSRL``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0003113a" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0003113a" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0003113a" ]
    |> is [ G 2, 0xfedcba987654321UL ]

  /// <summary>
  /// 0003113e, dsrl32 v0, v1, 0x4, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSRL32``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0003113e" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL ]
    |> run r2 [ "0003113e" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL ]
    |> run r2 [ "0003113e" ]
    |> is [ G 2, 0xfedcba9UL ]

  /// <summary>
  /// 00831016, dsrlv v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSRLV``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "00831016" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "00831016" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "00831016" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 0064102e, dsub v0, v1, a0, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGFPE (Exception IntegerOverflow here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSUB``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102e" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064102e" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "0064102e" ]
    |> is [ G 2, 0xfedcba9776543211UL ]
    [ G 2, 0x7UL; G 3, 0x8000000000000000UL; G 4, 0x1UL ]
    |> run r2 [ "0064102e" ]
    |> raises [ Exception IntegerOverflow ] []

  /// <summary>
  /// 0064102f, dsubu v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DSUBU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064102f" ]
    |> is [ G 2, 0xfffffffffffffffeUL ]
    [ G 2, 0x7fffffffffffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064102f" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x123456789abcdefUL; G 3, 0xfedcba9876543210UL; G 4, 0xffffffffUL ]
    |> run r2 [ "0064102f" ]
    |> is [ G 2, 0xfedcba9776543211UL ]

  /// <summary>
  /// 41620024, dvp v0, against QEMU's I6400, a Release 6 processor: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 DVP``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r6 [ "41620024" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r6 [ "41620024" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r6 [ "41620024" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 000000c0, ehb, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 EHB``() =
    []
    |> run r2 [ "000000c0" ]
    |> is []
    []
    |> run r2 [ "000000c0" ]
    |> is []
    []
    |> run r2 [ "000000c0" ]
    |> is []

  /// <summary>
  /// 41626020, ei v0, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 EI``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r2 [ "41626020" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r2 [ "41626020" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r2 [ "41626020" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000018, eret, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ERET``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000018" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000018" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000018" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 42000058, eretnc, against QEMU's MIPS64R2-generic: QEMU raised SIGILL
  /// (UndefinedInstruction here); Status = 0x10 puts the lift in User Mode, the
  /// mode QEMU runs every word in; the lift has to change what QEMU changed and
  /// nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 ERETNC``() =
    [ Status, 0x10UL ]
    |> run r2 [ "42000058" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000058" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "42000058" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 41620004, evp v0, against QEMU's I6400, a Release 6 processor: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 EVP``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r6 [ "41620004" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r6 [ "41620004" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r6 [ "41620004" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c620100, ext v0, v1, 0x4, 0x1, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 EXT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c620100" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c620100" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "7c620100" ]
    |> is [ G 2, 0x1UL ]

  /// <summary>
  /// 4600208b, floor.l.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 FLOOR.L.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "4600208b" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "4600208b" ]
    |> is [ F 2, 0xfffffffffffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "4600208b" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 4600208f, floor.w.s f2, f4, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 FLOOR.W.fmt``() =
    [ F 2, 0x9UL; F 4, 0x40200000UL ]
    |> run r2 [ "4600208f" ]
    |> is [ F 2, 0x2UL; Fcsr, 0x1004UL ]
    [ F 2, 0xbUL; F 4, 0xbfe00000UL ]
    |> run r2 [ "4600208f" ]
    |> is [ F 2, 0xfffffffeUL; Fcsr, 0x1004UL ]
    [ F 2, 0xdUL; F 4, 0x447a0000UL ]
    |> run r2 [ "4600208f" ]
    |> is [ F 2, 0x3e8UL ]

  /// <summary>
  /// 7c40003d, ginvi v0, against QEMU's I6400, a Release 6 processor: QEMU
  /// raised SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in
  /// User Mode, the mode QEMU runs every word in; the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 GINVI``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r6 [ "7c40003d" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r6 [ "7c40003d" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r6 [ "7c40003d" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c4001bd, ginvt v0, 0x1, against QEMU's I6400, a Release 6 processor: QEMU
  /// raised SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in
  /// User Mode, the mode QEMU runs every word in; the lift has to change what
  /// QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 GINVT``() =
    [ G 2, 0x7UL; Status, 0x10UL ]
    |> run r6 [ "7c4001bd" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL; Status, 0x10UL ]
    |> run r6 [ "7c4001bd" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r6 [ "7c4001bd" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c621844, ins v0, v1, 0x1, 0x3, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 INS``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "7c621844" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL ]
    |> run r2 [ "7c621844" ]
    |> is [ G 2, 0x7ffffff3UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL ]
    |> run r2 [ "7c621844" ]
    |> is [ G 2, 0xffffffff89abcde1UL ]

  /// <summary>
  /// 08000000, j 0x20000000 (binutils: j 20000000). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is left to
  /// the delay slot, which holds a NOP; control goes to 0x20000000 (the target
  /// binutils reads) when it always does.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 J``() =
    let words = [ "08000000"; "00000000" ]
    ownsJump r2 "08000000" false
    goes r2 words [] 0x20000000UL

  /// <summary>
  /// 0c000000, jal 0x20000000 (binutils: jal 20000000). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20000000 (the target binutils reads) when it always does; ra becomes
  /// 0x20100008 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JAL``() =
    let words = [ "0c000000"; "00000000" ]
    ownsJump r2 "0c000000" false
    goes r2 words [] 0x20000000UL
    []
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 0040f809, jalr v0 (binutils: jalr $2). A branch is not run against QEMU:
  /// it moves the PC, and its delay slot makes one word meaningless to run
  /// alone. Checked structurally from the manual: the transfer is left to the
  /// delay slot, which holds a NOP; control goes to 0x20100400 when G 2 is
  /// 0x20100400; ra becomes 0x20100008 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JALR``() =
    let words = [ "0040f809"; "00000000" ]
    ownsJump r2 "0040f809" false
    goes r2 words [ G 2, 0x20100400UL ] 0x20100400UL
    [ G 2, 0x20100400UL ]
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// 00601409, jalr.hb v0, v1 (binutils: jalr.hb $2,$3). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20100400 when G 3 is 0x20100400; the link register becomes 0x20100008
  /// and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JALR.HB``() =
    let words = [ "00601409"; "00000000" ]
    ownsJump r2 "00601409" false
    goes r2 words [ G 3, 0x20100400UL ] 0x20100400UL
    [ G 3, 0x20100400UL ]
    |> run r2 words
    |> is [ G 2, 0x20100008UL ]

  /// <summary>
  /// 74000000, jalx 0x20000000 (binutils: jalx 20000000). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is left to the delay slot, which holds a NOP; control goes to
  /// 0x20000000 (the target binutils reads) when it always does; ra becomes
  /// 0x20100008 and nothing else changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JALX``() =
    let words = [ "74000000"; "00000000" ]
    ownsJump r2 "74000000" false
    goes r2 words [] 0x20000000UL
    []
    |> run r2 words
    |> is [ G 31, 0x20100008UL ]

  /// <summary>
  /// f8020001, jialc v0, 0x1 (binutils: jialc $2,1). A branch is not run
  /// against QEMU: it moves the PC, and its delay slot makes one word
  /// meaningless to run alone. Checked structurally from the manual: the
  /// transfer is the branch's own, there being no delay slot; control goes to
  /// 0x20100400 when G 2 is 0x201003ff; ra becomes 0x20100004 and nothing else
  /// changes.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JIALC``() =
    let words = [ "f8020001" ]
    ownsJump r6 "f8020001" true
    goes r6 words [ G 2, 0x201003ffUL ] 0x20100400UL
    [ G 2, 0x201003ffUL ]
    |> run r6 words
    |> is [ G 31, 0x20100004UL ]

  /// <summary>
  /// d8020001, jic v0, 0x1 (binutils: jic $2,1). A branch is not run against
  /// QEMU: it moves the PC, and its delay slot makes one word meaningless to
  /// run alone. Checked structurally from the manual: the transfer is the
  /// branch's own, there being no delay slot; control goes to 0x20100400 when G
  /// 2 is 0x201003ff.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JIC``() =
    let words = [ "d8020001" ]
    ownsJump r6 "d8020001" true
    goes r6 words [ G 2, 0x201003ffUL ] 0x20100400UL

  /// <summary>
  /// 00400008, jr v0 (binutils: jr $2). A branch is not run against QEMU: it
  /// moves the PC, and its delay slot makes one word meaningless to run alone.
  /// Checked structurally from the manual: the transfer is left to the delay
  /// slot, which holds a NOP; control goes to 0x20100400 when G 2 is
  /// 0x20100400.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JR``() =
    let words = [ "00400008"; "00000000" ]
    ownsJump r2 "00400008" false
    goes r2 words [ G 2, 0x20100400UL ] 0x20100400UL

  /// <summary>
  /// 00400408, jr.hb v0 (binutils: jr.hb $2). A branch is not run against QEMU:
  /// it moves the PC, and its delay slot makes one word meaningless to run
  /// alone. Checked structurally from the manual: the transfer is left to the
  /// delay slot, which holds a NOP; control goes to 0x20100400 when G 2 is
  /// 0x20100400.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 JR.HB``() =
    let words = [ "00400408"; "00000000" ]
    ownsJump r2 "00400408" false
    goes r2 words [ G 2, 0x20100400UL ] 0x20100400UL

  /// <summary>
  /// 80620001, lb v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LB``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x5b898c14e4741671UL
        M 0x20200080UL, 0xe44e31a26fcc95a3UL
        M 0x20200088UL, 0x833bf6ec1a537189UL ]
    given0
    |> run r2 [ "80620001" ]
    |> is [ G 2, 0xffffffffffffffe4UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xcb0b04e6e9078a81UL
        M 0x20200080UL, 0x52cb1e9f8f8d924eUL
        M 0x20200088UL, 0xe59b34b0448edda1UL ]
    given1
    |> run r2 [ "80620001" ]
    |> is [ G 2, 0x52UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xcba93aa0f8604546UL
        M 0x20200080UL, 0x7bd5eaa77427c95UL
        M 0x20200088UL, 0x84a2458863467545UL ]
    given2
    |> run r2 [ "80620001" ]
    |> is [ G 2, 0x7UL ]

  /// <summary>
  /// 7c62012c, lbe v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LBE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x131a6fead8721a3UL
        M 0x20200080UL, 0x992224651c812addUL
        M 0x20200088UL, 0x4c5ce054f33744a3UL ]
    given0
    |> run r2 [ "7c62012c" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xfdd2cb0fef564c4cUL
        M 0x20200080UL, 0x1fb6c4c58a400531UL
        M 0x20200088UL, 0x1bc905de1aa54576UL ]
    given1
    |> run r2 [ "7c62012c" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x2c0c5541ea9c4ac2UL
        M 0x20200080UL, 0x753ce2603920d3dcUL
        M 0x20200088UL, 0x8434903c2e134c33UL ]
    given2
    |> run r2 [ "7c62012c" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 90620001, lbu v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LBU``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xe7978f12b5e98ee7UL
        M 0x20200080UL, 0xae48ea6dbad6b0eUL
        M 0x20200088UL, 0x50ee3fc4763ed60eUL ]
    given0
    |> run r2 [ "90620001" ]
    |> is [ G 2, 0xaUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x6a4b072da0a7eafUL
        M 0x20200080UL, 0x773c4fdfe1beb93UL
        M 0x20200088UL, 0x6ce581bd0a26331dUL ]
    given1
    |> run r2 [ "90620001" ]
    |> is [ G 2, 0x7UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x2d6ec9b26d63f375UL
        M 0x20200080UL, 0xb9019ae02a3ab7beUL
        M 0x20200088UL, 0x30598ab07131eb37UL ]
    given2
    |> run r2 [ "90620001" ]
    |> is [ G 2, 0xb9UL ]

  /// <summary>
  /// 7c620128, lbue v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LBUE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xd96cb1f5f7dfd1dfUL
        M 0x20200080UL, 0x6494374e0575513UL
        M 0x20200088UL, 0x3a4fdc4e4f2fad86UL ]
    given0
    |> run r2 [ "7c620128" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x4de4545e8ec127b6UL
        M 0x20200080UL, 0xcd51e61d0b410cb3UL
        M 0x20200088UL, 0x754fe8d712b31068UL ]
    given1
    |> run r2 [ "7c620128" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x6e085f9dc5239472UL
        M 0x20200080UL, 0x21532842485782d7UL
        M 0x20200088UL, 0x2e774662e8cdf4c4UL ]
    given2
    |> run r2 [ "7c620128" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// dc620001, ld v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LD``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xc2a8e8eaa0d86d5eUL
        M 0x20200080UL, 0xd89486e7c7223995UL
        M 0x20200088UL, 0x3b4c2bdc279ab769UL ]
    given0
    |> run r2 [ "dc620001" ]
    |> is [ G 2, 0xd89486e7c7223995UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x7966abd47584f263UL
        M 0x20200080UL, 0x6e6b75c7d8ae3d7cUL
        M 0x20200088UL, 0x74a0d0e3acd90185UL ]
    given1
    |> run r2 [ "dc620001" ]
    |> is [ G 2, 0x6e6b75c7d8ae3d7cUL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xf2c6b001f2add1b9UL
        M 0x20200080UL, 0x98874ec908b172a2UL
        M 0x20200088UL, 0x1d2483a831585868UL ]
    given2
    |> run r2 [ "dc620001" ]
    |> is [ G 2, 0x98874ec908b172a2UL ]

  /// <summary>
  /// d4420001, ldc1 f2, 1(v0), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LDC1``() =
    let given0 =
      [ G 2, 0x2020007fUL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xb097842a97b61a75UL
        M 0x20200080UL, 0xa922e0d9eb5b44abUL
        M 0x20200088UL, 0x3820cffffa34343aUL ]
    given0
    |> run r2 [ "d4420001" ]
    |> is [ F 2, 0xa922e0d9eb5b44abUL ]
    let given1 =
      [ G 2, 0x2020007fUL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x2905f060c2699bf5UL
        M 0x20200080UL, 0xb61fc548733d111fUL
        M 0x20200088UL, 0xc5e3329865c573a1UL ]
    given1
    |> run r2 [ "d4420001" ]
    |> is [ F 2, 0xb61fc548733d111fUL ]
    let given2 =
      [ G 2, 0x2020007fUL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x2d9b07fba5d634abUL
        M 0x20200080UL, 0xca5407a196dea096UL
        M 0x20200088UL, 0xd044a1bc05d35890UL ]
    given2
    |> run r2 [ "d4420001" ]
    |> is [ F 2, 0xca5407a196dea096UL ]

  /// <summary>
  /// d8000000, ldc2 0x0, 0(r0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LDC2``() =
    let given0 =
      [ M 0x20200078UL, 0xf551f55a2a3a3a87UL
        M 0x20200080UL, 0x2318f89dbbdd1c67UL
        M 0x20200088UL, 0x602dc6ab9b690eb3UL ]
    given0
    |> run r2 [ "d8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0xc854ad5d228727ffUL
        M 0x20200080UL, 0x13b9c2062f8b5565UL
        M 0x20200088UL, 0xe3b7bdcc921cbc84UL ]
    given1
    |> run r2 [ "d8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0x6d0829c82bf746fUL
        M 0x20200080UL, 0x12d71a19132b4bc3UL
        M 0x20200088UL, 0x33e4d24e72b51158UL ]
    given2
    |> run r2 [ "d8000000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 68620001, ldl v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LDL``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0x97463021110a4a0dUL
        M 0x20200080UL, 0xd101443feb885be0UL
        M 0x20200088UL, 0x1112f9537b4efc91UL ]
    given0
    |> run r2 [ "68620001" ]
    |> is [ G 2, 0x1443feb885be007UL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0x82867fd9c53d3fa8UL
        M 0x20200080UL, 0x6e6cc1a590257bcbUL
        M 0x20200088UL, 0x658096dd88364d6cUL ]
    given1
    |> run r2 [ "68620001" ]
    |> is [ G 2, 0xc1a590257bcbffffUL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0xe55fa6e5b0ef26e8UL
        M 0x20200080UL, 0x1185b3316302b503UL
        M 0x20200088UL, 0xdf065129a83c6384UL ]
    given2
    |> run r2 [ "68620001" ]
    |> is [ G 2, 0x2b5036789abcdefUL ]

  /// <summary>
  /// ec580080, ldpc v0, 0x20100400, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LDPC``() =
    let given0 =
      [ G 2, 0x7UL
        M 0x201003f8UL, 0xe5ca621fa5c07aabUL
        M 0x20100400UL, 0x2fd7c9b4f199d2c8UL
        M 0x20100408UL, 0xf294d13915b163efUL ]
    given0
    |> run r6 [ "ec580080" ]
    |> is [ G 2, 0x2fd7c9b4f199d2c8UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        M 0x201003f8UL, 0x38a36c4ffc7673c4UL
        M 0x20100400UL, 0x7f923a801ba01dc1UL
        M 0x20100408UL, 0xa8891f683704ad8dUL ]
    given1
    |> run r6 [ "ec580080" ]
    |> is [ G 2, 0x7f923a801ba01dc1UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        M 0x201003f8UL, 0xd466de45a1bd74f8UL
        M 0x20100400UL, 0xc7cedd1eba65d350UL
        M 0x20100408UL, 0xefeea73ce4f902c8UL ]
    given2
    |> run r6 [ "ec580080" ]
    |> is [ G 2, 0xc7cedd1eba65d350UL ]

  /// <summary>
  /// 6c620001, ldr v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LDR``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0x2a54ba9e11889790UL
        M 0x20200080UL, 0x409a2d7d70ea1e19UL
        M 0x20200088UL, 0xdfbd2e7dc026fb22UL ]
    given0
    |> run r2 [ "6c620001" ]
    |> is [ G 2, 0x409aUL ]
    let given1 =
      [ G 2, 0x7fffffffffffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0x2062b573952bb1f8UL
        M 0x20200080UL, 0x17af9164b3f45427UL
        M 0x20200088UL, 0xcd17bb3dc2bc19dfUL ]
    given1
    |> run r2 [ "6c620001" ]
    |> is [ G 2, 0x7fffffffff17af91UL ]
    let given2 =
      [ G 2, 0x123456789abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0xbd83a2840d2384c5UL
        M 0x20200080UL, 0x82d03f33aa722795UL
        M 0x20200088UL, 0xcaba8b8ed7248f2fUL ]
    given2
    |> run r2 [ "6c620001" ]
    |> is [ G 2, 0x12382d03f33aa72UL ]

  /// <summary>
  /// 4c430081, ldxc1 f2, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LDXC1``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0xb38cb2c538065f1bUL
        M 0x20200080UL, 0xaed52993a301f505UL
        M 0x20200088UL, 0x7251b9d5083ba48cUL ]
    given0
    |> run r2 [ "4c430081" ]
    |> is [ F 2, 0xaed52993a301f505UL ]
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0xfcc49d44131c87b8UL
        M 0x20200080UL, 0x5ec848fae8888c8aUL
        M 0x20200088UL, 0xa73fefb995e0660cUL ]
    given1
    |> run r2 [ "4c430081" ]
    |> is [ F 2, 0x5ec848fae8888c8aUL ]
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0x3f8c0fb591a8afb0UL
        M 0x20200080UL, 0x776aaec866354e73UL
        M 0x20200088UL, 0x84890cf390d63c3fUL ]
    given2
    |> run r2 [ "4c430081" ]
    |> is [ F 2, 0x776aaec866354e73UL ]

  /// <summary>
  /// 84620001, lh v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LH``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x7fa02394a5eaa650UL
        M 0x20200080UL, 0xbf8a7df0819c5a6aUL
        M 0x20200088UL, 0xa329e18221629d1aUL ]
    given0
    |> run r2 [ "84620001" ]
    |> is [ G 2, 0xffffffffffffbf8aUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x59f5e92e8f9ff682UL
        M 0x20200080UL, 0xba945da918bfd2d8UL
        M 0x20200088UL, 0x1efabd76634158eeUL ]
    given1
    |> run r2 [ "84620001" ]
    |> is [ G 2, 0xffffffffffffba94UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x5d119e6f434bbc0fUL
        M 0x20200080UL, 0x29a6fc26ce347b1bUL
        M 0x20200088UL, 0x9af65f8b9fff3217UL ]
    given2
    |> run r2 [ "84620001" ]
    |> is [ G 2, 0x29a6UL ]

  /// <summary>
  /// 7c62012d, lhe v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LHE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x35fefde95cd40f8aUL
        M 0x20200080UL, 0xa264603242838ccUL
        M 0x20200088UL, 0x5e60e05fb7a26bf7UL ]
    given0
    |> run r2 [ "7c62012d" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xed0dd629d6a96d7dUL
        M 0x20200080UL, 0x75928a80dd293a0eUL
        M 0x20200088UL, 0x8c18e7a729e1fa35UL ]
    given1
    |> run r2 [ "7c62012d" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xcf3f487e99f84cafUL
        M 0x20200080UL, 0x5d796f4cc940df7fUL
        M 0x20200088UL, 0x44a4593b13e8b63aUL ]
    given2
    |> run r2 [ "7c62012d" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 94620001, lhu v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LHU``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x41dd986680d020a7UL
        M 0x20200080UL, 0x87b655536c83771aUL
        M 0x20200088UL, 0x77921f976b49a924UL ]
    given0
    |> run r2 [ "94620001" ]
    |> is [ G 2, 0x87b6UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xe6797ba15de1cf3dUL
        M 0x20200080UL, 0xef8c618a092ec4fdUL
        M 0x20200088UL, 0xf1abfcd890281ad9UL ]
    given1
    |> run r2 [ "94620001" ]
    |> is [ G 2, 0xef8cUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xe6dd6f2d951325f6UL
        M 0x20200080UL, 0xb854a7b5e0d55c80UL
        M 0x20200088UL, 0x63cffd591b38ba2bUL ]
    given2
    |> run r2 [ "94620001" ]
    |> is [ G 2, 0xb854UL ]

  /// <summary>
  /// 7c620129, lhue v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LHUE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xa67b7db236ca1ea2UL
        M 0x20200080UL, 0xc3644127126f3f7aUL
        M 0x20200088UL, 0x29e9485bd78eed45UL ]
    given0
    |> run r2 [ "7c620129" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xed5ef22346c8f12dUL
        M 0x20200080UL, 0x79ae392cc97966daUL
        M 0x20200088UL, 0xa0fdda4d105459bfUL ]
    given1
    |> run r2 [ "7c620129" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x380c0d74357f992aUL
        M 0x20200080UL, 0x1b375ea653f4a009UL
        M 0x20200088UL, 0x76ce5f41ec4cf4e6UL ]
    given2
    |> run r2 [ "7c620129" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// c0620001, ll v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LL``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x34f2bc9f7be6afcaUL
        M 0x20200080UL, 0x895d892fb9a238dUL
        M 0x20200088UL, 0x496dfa0b8bf0a483UL ]
    given0
    |> run r2 [ "c0620001" ]
    |> is [ G 2, 0x895d892UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x1fb545b050cec211UL
        M 0x20200080UL, 0x7ffab3249b4d799bUL
        M 0x20200088UL, 0xf3beeb1fc2c51259UL ]
    given1
    |> run r2 [ "c0620001" ]
    |> is [ G 2, 0x7ffab324UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x363fa599bb9d70e5UL
        M 0x20200080UL, 0x240e6f62709cbc1aUL
        M 0x20200088UL, 0xdf7a7a93dc40c7aaUL ]
    given2
    |> run r2 [ "c0620001" ]
    |> is [ G 2, 0x240e6f62UL ]

  /// <summary>
  /// d0620001, lld v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LLD``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x7b5cc91a4b664ec2UL
        M 0x20200080UL, 0xbabb0e01031b2b90UL
        M 0x20200088UL, 0x85466c9567463711UL ]
    given0
    |> run r2 [ "d0620001" ]
    |> is [ G 2, 0xbabb0e01031b2b90UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x5dd70fefb5f3fd42UL
        M 0x20200080UL, 0xd44b321c43741c3aUL
        M 0x20200088UL, 0x22792a2bd471683fUL ]
    given1
    |> run r2 [ "d0620001" ]
    |> is [ G 2, 0xd44b321c43741c3aUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x3a5c0fa44924431UL
        M 0x20200080UL, 0x8e02cc4395fbd8b6UL
        M 0x20200088UL, 0x23e74e88c7da5e4aUL ]
    given2
    |> run r2 [ "d0620001" ]
    |> is [ G 2, 0x8e02cc4395fbd8b6UL ]

  /// <summary>
  /// 7c221877, lldp v0, v1, (at). The less significant doubleword of the
  /// quadword at the base goes to rt and the more significant to rd; on a
  /// big-endian processor the more significant doubleword is the one at the
  /// lower address.
  /// No reference runs it: QEMU's I6400 reads the word as an unpaired
  /// LLD. Checked against the manual's Operation instead.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LLDP``() =
    [ G 1, 0x20200080UL
      M 0x20200080UL, 0x1011121314151617UL
      M 0x20200088UL, 0x18191a1b1c1d1e1fUL ]
    |> run r6 [ "7c221877" ]
    |> is [ G 2, 0x18191a1b1c1d1e1fUL; G 3, 0x1011121314151617UL ]

  /// <summary>
  /// 7c62012e, lle v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LLE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x8174110c4724d8eeUL
        M 0x20200080UL, 0xccc18e67a3882f72UL
        M 0x20200088UL, 0x72b4483fdb13ff88UL ]
    given0
    |> run r2 [ "7c62012e" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x289809b1e4531347UL
        M 0x20200080UL, 0x533a5b440d64a00cUL
        M 0x20200088UL, 0x461176a58155152aUL ]
    given1
    |> run r2 [ "7c62012e" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0xcf304e2ea9a75318UL
        M 0x20200080UL, 0xe8d9d9053cd1c169UL
        M 0x20200088UL, 0xe71b9fd0bf355f79UL ]
    given2
    |> run r2 [ "7c62012e" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c221876, llwp v0, v1, (at). The least significant word of the
  /// doubleword at the base goes to rt and the most significant to rd, each
  /// sign-extended; on a big-endian processor the most significant word is
  /// the one at the lower address.
  /// No reference runs it: QEMU's I6400 reads the word as an unpaired
  /// LL. Checked against the manual's Operation instead.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LLWP``() =
    [ G 1, 0x20200080UL
      M 0x20200080UL, 0x1011121394959697UL ]
    |> run r6 [ "7c221876" ]
    |> is [ G 2, 0xffffffff94959697UL; G 3, 0x10111213UL ]

  /// <summary>
  /// 7c22186e, llwpe v0, v1, 0(at), against QEMU's I6400, a Release 6
  /// processor: QEMU raised SIGILL (UndefinedInstruction here); Status = 0x10
  /// puts the lift in User Mode, the mode QEMU runs every word in; the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LLWPE``() =
    let given0 =
      [ G 1, 0x20200080UL
        G 2, 0x7UL
        G 3, 0x3UL
        Status, 0x10UL
        M 0x20200078UL, 0xab998b6b3cb3f386UL
        M 0x20200080UL, 0xda141613805ff49eUL
        M 0x20200088UL, 0xfd426b3ae3647ba5UL ]
    given0
    |> run r6 [ "7c22186e" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 1, 0x20200080UL
        G 2, 0x7fffffffUL
        G 3, 0x1UL
        Status, 0x10UL
        M 0x20200078UL, 0xf028ce7fa6953c9bUL
        M 0x20200080UL, 0xa271611633a83b41UL
        M 0x20200088UL, 0x424c31bc6d91d484UL ]
    given1
    |> run r6 [ "7c22186e" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 1, 0x20200080UL
        G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        Status, 0x10UL
        M 0x20200078UL, 0xa798c47b7be819e7UL
        M 0x20200080UL, 0x851c7d085d021feaUL
        M 0x20200088UL, 0x63b45ce2966d87aUL ]
    given2
    |> run r6 [ "7c22186e" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00641005, lsa v0, v1, a0, 0x0, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LSA``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "00641005" ]
    |> is [ G 2, 0xbUL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "00641005" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "00641005" ]
    |> is [ G 2, 0x23456788UL ]

  /// <summary>
  /// 3c020001, lui v0, 0x1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LUI``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "3c020001" ]
    |> is [ G 2, 0x10000UL ]
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "3c020001" ]
    |> is [ G 2, 0x10000UL ]
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "3c020001" ]
    |> is [ G 2, 0x10000UL ]

  /// <summary>
  /// 4c430085, luxc1 f2, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LUXC1``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0xbff0000000000000UL
        M 0x20200078UL, 0x66dc0c176450de4fUL
        M 0x20200080UL, 0xebbb4c878c0320a3UL
        M 0x20200088UL, 0x4b458f8837336314UL ]
    given0
    |> run r2 [ "4c430085" ]
    |> is [ F 2, 0xebbb4c878c0320a3UL ]
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x400c000000000000UL
        M 0x20200078UL, 0x7e200e35bbf9a72cUL
        M 0x20200080UL, 0x2944dc94848ad128UL
        M 0x20200088UL, 0xb7ff09e29410bdd6UL ]
    given1
    |> run r2 [ "4c430085" ]
    |> is [ F 2, 0x2944dc94848ad128UL ]
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x3fd0000000000000UL
        M 0x20200078UL, 0xb58c19b6910b8d4bUL
        M 0x20200080UL, 0xdf87f62d6206ace7UL
        M 0x20200088UL, 0x6096b8f97e594dd3UL ]
    given2
    |> run r2 [ "4c430085" ]
    |> is [ F 2, 0xdf87f62d6206ace7UL ]

  /// <summary>
  /// 8c620001, lw v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LW``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x19c1eac7961b0c9dUL
        M 0x20200080UL, 0x29cf09bec6f7dcecUL
        M 0x20200088UL, 0xfb8c5de5d86be136UL ]
    given0
    |> run r2 [ "8c620001" ]
    |> is [ G 2, 0x29cf09beUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x57e5ea060bb9e149UL
        M 0x20200080UL, 0x8031ea8f2a20345fUL
        M 0x20200088UL, 0xa9bc5c8034efb57UL ]
    given1
    |> run r2 [ "8c620001" ]
    |> is [ G 2, 0xffffffff8031ea8fUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xc09c7b57ae09ea6dUL
        M 0x20200080UL, 0xa25598fb36c8df84UL
        M 0x20200088UL, 0x14ab832c2048c996UL ]
    given2
    |> run r2 [ "8c620001" ]
    |> is [ G 2, 0xffffffffa25598fbUL ]

  /// <summary>
  /// c4420001, lwc1 f2, 1(v0), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWC1``() =
    let given0 =
      [ G 2, 0x2020007fUL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0xc28765bb874b9cf3UL
        M 0x20200080UL, 0x45d80cd9a44b3969UL
        M 0x20200088UL, 0xf32ca029980239a1UL ]
    given0
    |> run r2 [ "c4420001" ]
    |> is [ F 2, 0x45d80cd9UL ]
    let given1 =
      [ G 2, 0x2020007fUL
        F 2, 0x40600000UL
        M 0x20200078UL, 0xe3c5772f9ad016a4UL
        M 0x20200080UL, 0xd0028a1ed6d2bf73UL
        M 0x20200088UL, 0x384c1f666cb3bef8UL ]
    given1
    |> run r2 [ "c4420001" ]
    |> is [ F 2, 0xd0028a1eUL ]
    let given2 =
      [ G 2, 0x2020007fUL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0xc5b5bf7c0c5a4483UL
        M 0x20200080UL, 0xdbde6e1357f8ead9UL
        M 0x20200088UL, 0xf606b25fb3101ccUL ]
    given2
    |> run r2 [ "c4420001" ]
    |> is [ F 2, 0xdbde6e13UL ]

  /// <summary>
  /// c8000000, lwc2 0x0, 0(r0), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWC2``() =
    let given0 =
      [ M 0x20200078UL, 0x8e0c8848e8736669UL
        M 0x20200080UL, 0xfdf954e04dee2dc8UL
        M 0x20200088UL, 0xdcdf2d34ddbee55fUL ]
    given0
    |> run r2 [ "c8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ M 0x20200078UL, 0x20d0bee0c4f69fd3UL
        M 0x20200080UL, 0xd16f31936d3a78bdUL
        M 0x20200088UL, 0x87809dd14c4c4a3aUL ]
    given1
    |> run r2 [ "c8000000" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ M 0x20200078UL, 0x5aae1248675af81eUL
        M 0x20200080UL, 0xed7f52065ffe326cUL
        M 0x20200088UL, 0xf589ce22713d0331UL ]
    given2
    |> run r2 [ "c8000000" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 7c62012f, lwe v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x260231a6998fb87fUL
        M 0x20200080UL, 0xaa4d65c14650bbeaUL
        M 0x20200088UL, 0x55e981eeff552631UL ]
    given0
    |> run r2 [ "7c62012f" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x755c46e2da23cf68UL
        M 0x20200080UL, 0x33324ea797cdc37aUL
        M 0x20200088UL, 0x217f2544ae4bf535UL ]
    given1
    |> run r2 [ "7c62012f" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007eUL
        Status, 0x10UL
        M 0x20200078UL, 0x8d914a9e9f2a6ad7UL
        M 0x20200080UL, 0x9c61aaa774c7de14UL
        M 0x20200088UL, 0x62951807905ed1b1UL ]
    given2
    |> run r2 [ "7c62012f" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 88620001, lwl v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWL``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0x4fa784f10a71f241UL
        M 0x20200080UL, 0x535198a3396cb581UL
        M 0x20200088UL, 0xd3ac3f3d81752c57UL ]
    given0
    |> run r2 [ "88620001" ]
    |> is [ G 2, 0x5198a307UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0x2e51841d72fd5af9UL
        M 0x20200080UL, 0x7e799eddc7b52069UL
        M 0x20200088UL, 0x2c4277fda6fa7013UL ]
    given1
    |> run r2 [ "88620001" ]
    |> is [ G 2, 0xffffffff9eddffffUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0x10608c6c3399f933UL
        M 0x20200080UL, 0x5e232c871a164c6bUL
        M 0x20200088UL, 0xf8eab2e315cfbcecUL ]
    given2
    |> run r2 [ "88620001" ]
    |> is [ G 2, 0x164c6befUL ]

  /// <summary>
  /// 7c620119, lwle v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWLE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0xe662bbba78e20a3cUL
        M 0x20200080UL, 0x27d36e26d14c440cUL
        M 0x20200088UL, 0x69a2789f635889deUL ]
    given0
    |> run r2 [ "7c620119" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0x27118a9ab080defUL
        M 0x20200080UL, 0xd3d128d54b3d9c6dUL
        M 0x20200088UL, 0x30a394adcac25ecbUL ]
    given1
    |> run r2 [ "7c620119" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200083UL
        Status, 0x10UL
        M 0x20200078UL, 0x4efa15002aea4f3UL
        M 0x20200080UL, 0x2394df489f387a97UL
        M 0x20200088UL, 0x8a88b0a524970b2cUL ]
    given2
    |> run r2 [ "7c620119" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// ec480100, lwpc v0, 0x20100400, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWPC``() =
    let given0 =
      [ G 2, 0x7UL
        M 0x201003f8UL, 0xc93e2a0680be7c32UL
        M 0x20100400UL, 0x6d0780cddbc42328UL
        M 0x20100408UL, 0x1a7cc4109dad56b7UL ]
    given0
    |> run r6 [ "ec480100" ]
    |> is [ G 2, 0x6d0780cdUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        M 0x201003f8UL, 0xf867e109d8bc1822UL
        M 0x20100400UL, 0x8753a0b4dacfe1b6UL
        M 0x20100408UL, 0x35caa7c37c291577UL ]
    given1
    |> run r6 [ "ec480100" ]
    |> is [ G 2, 0xffffffff8753a0b4UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        M 0x201003f8UL, 0x5b36aa781dc614aeUL
        M 0x20100400UL, 0xe296011941d2b2ecUL
        M 0x20100408UL, 0x8ae2e38fe1135ae9UL ]
    given2
    |> run r6 [ "ec480100" ]
    |> is [ G 2, 0xffffffffe2960119UL ]

  /// <summary>
  /// 98620001, lwr v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWR``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x20200080UL
        M 0x20200078UL, 0x4fbdf3ae5b73441bUL
        M 0x20200080UL, 0x12c8872ed55a275bUL
        M 0x20200088UL, 0xc4aff3ca7c3d5b4dUL ]
    given0
    |> run r2 [ "98620001" ]
    |> is [ G 2, 0x12c8UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200081UL
        M 0x20200078UL, 0x5fd9688a4523f545UL
        M 0x20200080UL, 0x60e59cce1d79fbe2UL
        M 0x20200088UL, 0xec353354832544f9UL ]
    given1
    |> run r2 [ "98620001" ]
    |> is [ G 2, 0x7f60e59cUL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200084UL
        M 0x20200078UL, 0x720129112ffd4948UL
        M 0x20200080UL, 0xe2a3dc34a8259c54UL
        M 0x20200088UL, 0xb48202f749685d42UL ]
    given2
    |> run r2 [ "98620001" ]
    |> is [ G 2, 0xffffffff89aba825UL ]

  /// <summary>
  /// 7c62011a, lwre v0, 2(v1), against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWRE``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        Status, 0x10UL
        M 0x20200078UL, 0x4833c3d87740c952UL
        M 0x20200080UL, 0x9f765ca5dffd8a8fUL
        M 0x20200088UL, 0xb7b55a7e420c73c3UL ]
    given0
    |> run r2 [ "7c62011a" ]
    |> raises [ UndefinedInstruction ] []
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x20200080UL
        Status, 0x10UL
        M 0x20200078UL, 0x761155b405f729d3UL
        M 0x20200080UL, 0xc9d31290d95f49e0UL
        M 0x20200088UL, 0x5fceb6b4e19b5474UL ]
    given1
    |> run r2 [ "7c62011a" ]
    |> raises [ UndefinedInstruction ] []
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x20200083UL
        Status, 0x10UL
        M 0x20200078UL, 0xd0b29c8eaa16232eUL
        M 0x20200080UL, 0xf0a5799ace8fc81UL
        M 0x20200088UL, 0xf56bb135466213eeUL ]
    given2
    |> run r2 [ "7c62011a" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 9c620001, lwu v0, 1(v1), against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWU``() =
    let given0 =
      [ G 2, 0x7UL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xeb010a9ecce57475UL
        M 0x20200080UL, 0xc3f4b6c4fcca6170UL
        M 0x20200088UL, 0xab5f47ff40b118a4UL ]
    given0
    |> run r2 [ "9c620001" ]
    |> is [ G 2, 0xc3f4b6c4UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0xbfc5dee7a70fa3bUL
        M 0x20200080UL, 0xed1239103347ec0eUL
        M 0x20200088UL, 0x5ea219ba82c7ea35UL ]
    given1
    |> run r2 [ "9c620001" ]
    |> is [ G 2, 0xed123910UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x2020007fUL
        M 0x20200078UL, 0x34fcb7b1868c00eUL
        M 0x20200080UL, 0x7d732bb2bc177475UL
        M 0x20200088UL, 0x1d57c7c2e7b65c30UL ]
    given2
    |> run r2 [ "9c620001" ]
    |> is [ G 2, 0x7d732bb2UL ]

  /// <summary>
  /// ec500100, lwupc v0, 0x20100400, against QEMU's I6400, a Release 6
  /// processor: the lift has to change what QEMU changed and nothing else, over
  /// each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWUPC``() =
    let given0 =
      [ G 2, 0x7UL
        M 0x201003f8UL, 0x45b0397e4b15024fUL
        M 0x20100400UL, 0x25c994bce5f12e99UL
        M 0x20100408UL, 0x88c55495363749e6UL ]
    given0
    |> run r6 [ "ec500100" ]
    |> is [ G 2, 0x25c994bcUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        M 0x201003f8UL, 0x503624865d930e22UL
        M 0x20100400UL, 0x609939d10c1908fbUL
        M 0x20100408UL, 0x38ae56f03d29a7bUL ]
    given1
    |> run r6 [ "ec500100" ]
    |> is [ G 2, 0x609939d1UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        M 0x201003f8UL, 0x3b2c0bad8a334f4fUL
        M 0x20100400UL, 0xc23025d9b28a3a4fUL
        M 0x20100408UL, 0x68e8514084fb169bUL ]
    given2
    |> run r6 [ "ec500100" ]
    |> is [ G 2, 0xc23025d9UL ]

  /// <summary>
  /// 4c430080, lwxc1 f2, v1(v0), against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 LWXC1``() =
    let given0 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0xbf800000UL
        M 0x20200078UL, 0x9692e8496dc2d47eUL
        M 0x20200080UL, 0x5cd754bf05d21498UL
        M 0x20200088UL, 0x6b7aa45b977f74e7UL ]
    given0
    |> run r2 [ "4c430080" ]
    |> is [ F 2, 0x5cd754bfUL ]
    let given1 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x40600000UL
        M 0x20200078UL, 0x6f48bc8d1a8b0903UL
        M 0x20200080UL, 0x17688a199252ba73UL
        M 0x20200088UL, 0x6d88232363262c3cUL ]
    given1
    |> run r2 [ "4c430080" ]
    |> is [ F 2, 0x17688a19UL ]
    let given2 =
      [ G 2, 0x20200078UL
        G 3, 0x8UL
        F 2, 0x3e800000UL
        M 0x20200078UL, 0x1b1e236aa2c71c1cUL
        M 0x20200080UL, 0xc6dd785f8f290261UL
        M 0x20200088UL, 0xcdb696978d213483UL ]
    given2
    |> run r2 [ "4c430080" ]
    |> is [ F 2, 0xc6dd785fUL ]

  /// <summary>
  /// 70430000, madd v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MADD``() =
    [ G 2, 0x7UL; G 3, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run r2 [ "70430000" ]
    |> is [ Lo, 0x39UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run r2 [ "70430000" ]
    |> is [ Hi, 0xffffffff80000000UL; Lo, 0x0UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run r2 [ "70430000" ]
    |> is [ Hi, 0xffffffffd643a257UL; Lo, 0xfffffffff4772880UL ]

  /// <summary>
  /// 4c8830a0, madd.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MADD.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run r2 [ "4c8830a0" ]
    |> is [ F 2, 0x40400000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run r2 [ "4c8830a0" ]
    |> is [ F 2, 0xc0400000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run r2 [ "4c8830a0" ]
    |> is [ F 2, 0x4479ec00UL ]

  /// <summary>
  /// 46062098, maddf.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MADDF.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062098" ]
    |> is [ F 2, 0x40180000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062098" ]
    |> is [ F 2, 0xbf800000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062098" ]
    |> is [ F 2, 0x42fa8000UL ]

  /// <summary>
  /// 70430001, maddu v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MADDU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run r2 [ "70430001" ]
    |> is [ Lo, 0x39UL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run r2 [ "70430001" ]
    |> is [ Hi, 0xffffffff80000000UL; Lo, 0x0UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run r2 [ "70430001" ]
    |> is [ Hi, 0xffffffffe877f8cfUL; Lo, 0xfffffffff4772880UL ]

  /// <summary>
  /// 4606209e, max.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MAX.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209e" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209e" ]
    |> is [ F 2, 0x3f400000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209e" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 4606209f, maxa.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MAXA.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209f" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209f" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209f" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 40010001, mfc0 at, 0x0, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFC0``() =
    [ G 1, 0x7UL; Status, 0x10UL ]
    |> run r2 [ "40010001" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL; Status, 0x10UL ]
    |> run r2 [ "40010001" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL; Status, 0x10UL ]
    |> run r2 [ "40010001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 44021000, mfc1 v0, f2, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFC1``() =
    [ G 2, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run r2 [ "44021000" ]
    |> is [ G 2, 0x55667788UL ]
    [ G 2, 0x7fffffffUL; F 2, 0xbf800000UL ]
    |> run r2 [ "44021000" ]
    |> is [ G 2, 0xffffffffbf800000UL ]
    [ G 2, 0xffffffff89abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run r2 [ "44021000" ]
    |> is [ G 2, 0xffffffffccddeeffUL ]

  /// <summary>
  /// 48010001, mfc2 at, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFC2``() =
    [ G 1, 0x7UL ]
    |> run r2 [ "48010001" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0x7fffffffUL ]
    |> run r2 [ "48010001" ]
    |> raises [ UndefinedInstruction ] []
    [ G 1, 0xffffffff89abcdefUL ]
    |> run r2 [ "48010001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 40400001, mfhc0 r0, 0x0, 0x1, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); Status = 0x10 puts the lift in User
  /// Mode, the mode QEMU runs every word in; the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFHC0``() =
    [ Status, 0x10UL ]
    |> run r2 [ "40400001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40400001" ]
    |> raises [ UndefinedInstruction ] []
    [ Status, 0x10UL ]
    |> run r2 [ "40400001" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 44621000, mfhc1 v0, f2, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFHC1``() =
    [ G 2, 0x7UL; F 2, 0x1122334455667788UL ]
    |> run r2 [ "44621000" ]
    |> is [ G 2, 0x11223344UL ]
    [ G 2, 0x7fffffffffffffffUL; F 2, 0xbf800000UL ]
    |> run r2 [ "44621000" ]
    |> is [ G 2, 0x0UL ]
    [ G 2, 0x123456789abcdefUL; F 2, 0x8899aabbccddeeffUL ]
    |> run r2 [ "44621000" ]
    |> is [ G 2, 0xffffffff8899aabbUL ]

  /// <summary>
  /// 48621900, mfhc2 v0, 0x1900, against QEMU's MIPS64R2-generic: QEMU raised
  /// SIGILL (UndefinedInstruction here); the lift has to change what QEMU
  /// changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFHC2``() =
    [ G 2, 0x7UL ]
    |> run r2 [ "48621900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0x7fffffffUL ]
    |> run r2 [ "48621900" ]
    |> raises [ UndefinedInstruction ] []
    [ G 2, 0xffffffff89abcdefUL ]
    |> run r2 [ "48621900" ]
    |> raises [ UndefinedInstruction ] []

  /// <summary>
  /// 00001010, mfhi v0, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFHI``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run r2 [ "00001010" ]
    |> is [ G 2, 0x13UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run r2 [ "00001010" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run r2 [ "00001010" ]
    |> is [ G 2, 0xffffffffdeadbeefUL ]

  /// <summary>
  /// 00001012, mflo v0, against QEMU's MIPS64R2-generic: the lift has to change
  /// what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MFLO``() =
    [ G 2, 0x7UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run r2 [ "00001012" ]
    |> is [ G 2, 0x24UL ]
    [ G 2, 0x7fffffffUL; Hi, 0x7fffffffUL; Lo, 0xffffffff80000001UL ]
    |> run r2 [ "00001012" ]
    |> is [ G 2, 0xffffffff80000001UL ]
    [ G 2, 0xffffffff89abcdefUL; Hi, 0xffffffffdeadbeefUL; Lo, 0x12345678UL ]
    |> run r2 [ "00001012" ]
    |> is [ G 2, 0x12345678UL ]

  /// <summary>
  /// 4606209c, min.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MIN.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209c" ]
    |> is [ F 2, 0x3fc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209c" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209c" ]
    |> is [ F 2, 0x3e000000UL ]

  /// <summary>
  /// 4606209d, mina.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MINA.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209d" ]
    |> is [ F 2, 0x3fc00000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209d" ]
    |> is [ F 2, 0x3f400000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "4606209d" ]
    |> is [ F 2, 0x3e000000UL ]

  /// <summary>
  /// 006410da, mod v0, v1, a0, against QEMU's I6400, a Release 6 processor: the
  /// lift has to change what QEMU changed and nothing else, over each set of
  /// values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOD``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410da" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410da" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "006410da" ]
    |> is [ G 2, 0x1234560UL ]

  /// <summary>
  /// 006410db, modu v0, v1, a0, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MODU``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r6 [ "006410db" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r6 [ "006410db" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r6 [ "006410db" ]
    |> is [ G 2, 0x12345678UL ]

  /// <summary>
  /// 46002086, mov.s f2, f4, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOV.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46002086" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run r2 [ "46002086" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run r2 [ "46002086" ]
    |> is [ F 2, 0x447a0000UL ]

  /// <summary>
  /// 00641001, movf v0, v1, 0x1, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVF``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00641001" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; Fcsr, 0xfe800000UL ]
    |> run r2 [ "00641001" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; Fcsr, 0x800000UL ]
    |> run r2 [ "00641001" ]
    |> is [ G 2, 0x12345678UL ]
    [ G 2, 0x7UL; G 3, 0x3UL; Fcsr, 0x2000000UL ]
    |> run r2 [ "00641001" ]
    |> is []

  /// <summary>
  /// 46042091, movf.s f2, f4, 0x1, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVF.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46042091" ]
    |> is [ F 2, 0x40100000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; Fcsr, 0xfe800000UL ]
    |> run r2 [ "46042091" ]
    |> is []
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; Fcsr, 0x800000UL ]
    |> run r2 [ "46042091" ]
    |> is [ F 2, 0x447a0000UL ]
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; Fcsr, 0x2000000UL ]
    |> run r2 [ "46042091" ]
    |> is []

  /// <summary>
  /// 0064100b, movn v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVN``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064100b" ]
    |> is [ G 2, 0x3UL ]
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064100b" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "0064100b" ]
    |> is [ G 2, 0x12345678UL ]
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0064100b" ]
    |> is []

  /// <summary>
  /// 46022093, movn.s f2, f4, v0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVN.fmt``() =
    [ G 2, 0x7UL; F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46022093" ]
    |> is [ F 2, 0x40100000UL ]
    [ G 2, 0x7fffffffUL; F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run r2 [ "46022093" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ G 2, 0xffffffff89abcdefUL; F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run r2 [ "46022093" ]
    |> is [ F 2, 0x447a0000UL ]
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46022093" ]
    |> is []

  /// <summary>
  /// 00651001, movt v0, v1, 0x1, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVT``() =
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "00651001" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; Fcsr, 0xfe800000UL ]
    |> run r2 [ "00651001" ]
    |> is [ G 2, 0x1UL ]
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; Fcsr, 0x800000UL ]
    |> run r2 [ "00651001" ]
    |> is []
    [ G 2, 0x7UL; G 3, 0x3UL; Fcsr, 0x2000000UL ]
    |> run r2 [ "00651001" ]
    |> is [ G 2, 0x3UL ]

  /// <summary>
  /// 46052091, movt.s f2, f4, 0x1, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVT.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46052091" ]
    |> is []
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; Fcsr, 0xfe800000UL ]
    |> run r2 [ "46052091" ]
    |> is [ F 2, 0xc0c00000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; Fcsr, 0x800000UL ]
    |> run r2 [ "46052091" ]
    |> is []
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; Fcsr, 0x2000000UL ]
    |> run r2 [ "46052091" ]
    |> is [ F 2, 0x40100000UL ]

  /// <summary>
  /// 0064100a, movz v0, v1, a0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVZ``() =
    [ G 2, 0x7UL; G 3, 0x3UL; G 4, 0x5UL ]
    |> run r2 [ "0064100a" ]
    |> is []
    [ G 2, 0x7fffffffUL; G 3, 0x1UL; G 4, 0xfffffffffffffffeUL ]
    |> run r2 [ "0064100a" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; G 3, 0x12345678UL; G 4, 0xfffffffffedcba98UL ]
    |> run r2 [ "0064100a" ]
    |> is []
    [ G 2, 0x7UL; G 3, 0x3UL ]
    |> run r2 [ "0064100a" ]
    |> is [ G 2, 0x3UL ]

  /// <summary>
  /// 46022092, movz.s f2, f4, v0, against QEMU's MIPS64R2-generic: the lift has
  /// to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MOVZ.fmt``() =
    [ G 2, 0x7UL; F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46022092" ]
    |> is []
    [ G 2, 0x7fffffffUL; F 2, 0x40600000UL; F 4, 0xc0c00000UL ]
    |> run r2 [ "46022092" ]
    |> is []
    [ G 2, 0xffffffff89abcdefUL; F 2, 0x3e800000UL; F 4, 0x447a0000UL ]
    |> run r2 [ "46022092" ]
    |> is []
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL ]
    |> run r2 [ "46022092" ]
    |> is [ F 2, 0x40100000UL ]

  /// <summary>
  /// 70430004, msub v0, v1, against QEMU's MIPS64R2-generic: the lift has to
  /// change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MSUB``() =
    [ G 2, 0x7UL; G 3, 0x3UL; Hi, 0x13UL; Lo, 0x24UL ]
    |> run r2 [ "70430004" ]
    |> is [ Lo, 0xfUL ]
    let given1 =
      [ G 2, 0x7fffffffUL
        G 3, 0x1UL
        Hi, 0x7fffffffUL
        Lo, 0xffffffff80000001UL ]
    given1
    |> run r2 [ "70430004" ]
    |> is [ Lo, 0x2UL ]
    let given2 =
      [ G 2, 0xffffffff89abcdefUL
        G 3, 0x12345678UL
        Hi, 0xffffffffdeadbeefUL
        Lo, 0x12345678UL ]
    given2
    |> run r2 [ "70430004" ]
    |> is [ Hi, 0xffffffffe717db86UL; Lo, 0x2ff18470UL ]

  /// <summary>
  /// 4c8830a8, msub.s f2, f4, f6, f8, against QEMU's MIPS64R2-generic: the lift
  /// has to change what QEMU changed and nothing else, over each set of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MSUB.fmt``() =
    let given0 =
      [ F 2, 0xbf800000UL
        F 4, 0x40100000UL
        F 6, 0x3fc00000UL
        F 8, 0x3f000000UL ]
    given0
    |> run r2 [ "4c8830a8" ]
    |> is [ F 2, 0xbfc00000UL ]
    let given1 =
      [ F 2, 0x40600000UL
        F 4, 0xc0c00000UL
        F 6, 0x3f400000UL
        F 8, 0x40800000UL ]
    given1
    |> run r2 [ "4c8830a8" ]
    |> is [ F 2, 0x41100000UL ]
    let given2 =
      [ F 2, 0x3e800000UL
        F 4, 0x447a0000UL
        F 6, 0x3e000000UL
        F 8, 0xc0200000UL ]
    given2
    |> run r2 [ "4c8830a8" ]
    |> is [ F 2, 0xc47a1400UL ]

  /// <summary>
  /// 46062099, msubf.s f2, f4, f6, against QEMU's I6400, a Release 6 processor:
  /// the lift has to change what QEMU changed and nothing else, over each set
  /// of values.
  /// </summary>
  [<TestMethod>]
  member _.``MD00087 MSUBF.fmt``() =
    [ F 2, 0xbf800000UL; F 4, 0x40100000UL; F 6, 0x3fc00000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062099" ]
    |> is [ F 2, 0xc08c0000UL ]
    [ F 2, 0x40600000UL; F 4, 0xc0c00000UL; F 6, 0x3f400000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062099" ]
    |> is [ F 2, 0x41000000UL ]
    [ F 2, 0x3e800000UL; F 4, 0x447a0000UL; F 6, 0x3e000000UL; Fcsr, 0xc0000UL ]
    |> run r6 [ "46062099" ]
    |> is [ F 2, 0xc2f98000UL ]
