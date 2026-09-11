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

namespace B2R2.FrontEnd.CIL.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.CIL
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins the text the disassembler writes, which is the syntax the assembler
/// reads back: the mnemonics of ECMA-335, a variable or a constant in decimal,
/// a token at its full width, and a branch by the address it reaches.
[<TestClass>]
type DisasmTests() =
  static let parser =
    CILParser(BinReader.Init Endian.Little) :> IInstructionParsable

  static let disasmAt addr hex =
    let bytes = ByteArray.ofHexString hex
    let ins = parser.Parse(ReadOnlySpan bytes, addr)
    let builder = StringDisasmBuilder(false, null, WordSize.Bit64)
    ins.Disasm builder

  static let disasm hex = disasmAt 0UL hex

  [<TestMethod>]
  member _.``[CIL] the mnemonic is spelled the way ECMA-335 spells it test``() =
    Assert.AreEqual<string>("nop", disasm "00")
    Assert.AreEqual<string>("ldc.i4.m1", disasm "15")
    Assert.AreEqual<string>("ldc.i4.6", disasm "1c")
    Assert.AreEqual<string>("bne.un.s 0x0", disasm "33fe")
    Assert.AreEqual<string>("conv.r.un", disasm "76")
    Assert.AreEqual<string>("conv.ovf.u.un", disasm "8b")
    Assert.AreEqual<string>("unbox.any 0x02000001", disasm "a501000002")
    Assert.AreEqual<string>("endfinally", disasm "dc")
    Assert.AreEqual<string>("clt.un", disasm "fe05")

  (* A prefix is an instruction of its own, and its name ends in the dot the
     specification writes it with. *)
  [<TestMethod>]
  member _.``[CIL] a prefix keeps its trailing dot test``() =
    Assert.AreEqual<string>("unaligned. 4", disasm "fe1204")
    Assert.AreEqual<string>("volatile.", disasm "fe13")
    Assert.AreEqual<string>("tail.", disasm "fe14")
    Assert.AreEqual<string>("constrained. 0x02000001", disasm "fe1601000002")
    Assert.AreEqual<string>("no. 1", disasm "fe1901")
    Assert.AreEqual<string>("readonly.", disasm "fe1e")

  [<TestMethod>]
  member _.``[CIL] a variable and a constant are written in decimal test``() =
    Assert.AreEqual<string>("ldarg.s 5", disasm "0e05")
    Assert.AreEqual<string>("ldloc 256", disasm "fe0c0001")
    Assert.AreEqual<string>("ldc.i4.s -1", disasm "1fff")
    Assert.AreEqual<string>("ldc.i4 42", disasm "202a000000")
    Assert.AreEqual<string>("ldc.i8 -1", disasm "21ffffffffffffffff")

  (* A float is written in the shortest decimal that reads back as the same
     value, and the values a decimal cannot spell the way .NET spells them. *)
  [<TestMethod>]
  member _.``[CIL] a float is written in the shortest decimal test``() =
    Assert.AreEqual<string>("ldc.r4 1.5", disasm "220000c03f")
    Assert.AreEqual<string>("ldc.r8 1", disasm "23000000000000f03f")
    Assert.AreEqual<string>("ldc.r8 -0", disasm "230000000000000080")
    Assert.AreEqual<string>("ldc.r4 NaN", disasm "220000c07f")
    Assert.AreEqual<string>("ldc.r4 -Infinity", disasm "22000080ff")
    Assert.AreEqual<string>("ldc.r8 3.141592653589793",
                            disasm "23182d4454fb210940")

  (* A token is written at its full width, so that the table it names, which
     the top byte carries, reads off the text. *)
  [<TestMethod>]
  member _.``[CIL] a token is written at its full width test``() =
    Assert.AreEqual<string>("call 0x06000001", disasm "2801000006")
    Assert.AreEqual<string>("callvirt 0x0a000001", disasm "6f0100000a")
    Assert.AreEqual<string>("ldstr 0x70000001", disasm "7201000070")
    Assert.AreEqual<string>("ldfld 0x04000001", disasm "7b01000004")

  (* A branch is written by the address it reaches rather than by the distance
     the encoding carries, so what a line says does not depend on how wide the
     instruction is. *)
  [<TestMethod>]
  member _.``[CIL] a branch is written by the address it reaches test``() =
    Assert.AreEqual<string>("br.s 0x7", disasm "2b05")
    Assert.AreEqual<string>("br 0x105", disasmAt 0UL "3800010000")
    Assert.AreEqual<string>("brtrue.s 0x1007", disasmAt 0x1000UL "2d05")
    Assert.AreEqual<string>("leave 0x1000", disasmAt 0x1000UL "ddfbffffff")

  [<TestMethod>]
  member _.``[CIL] a switch lists its targets in parentheses test``() =
    Assert.AreEqual<string>("switch ()", disasm "4500000000")
    Assert.AreEqual<string>("switch (0xf, 0x9)",
                            disasm "450200000002000000fcffffff")

  [<TestMethod>]
  member _.``[CIL] the address marker precedes the instruction test``() =
    let bytes = ByteArray.ofHexString "00"
    let ins = parser.Parse(ReadOnlySpan bytes, 0x10UL)
    let builder = StringDisasmBuilder(true, null, WordSize.Bit64)
    Assert.AreEqual<string>("0000000000000010: nop", ins.Disasm builder)

// vim: set tw=80 sts=2 sw=2:
