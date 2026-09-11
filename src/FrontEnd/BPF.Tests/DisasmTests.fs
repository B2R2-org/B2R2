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

namespace B2R2.FrontEnd.BinLifter.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BPF
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type DisasmTests() =
  static let isa = ISA Architecture.BPF

  static let parser = BPFParser(BinReader.Init isa.Endian)

  static let disasm hex =
    let bytes = ByteArray.ofHexString hex
    let ins = (parser :> IInstructionParsable).Parse(ReadOnlySpan bytes, 0UL)
    let builder = StringDisasmBuilder(false, null, WordSize.Bit64)
    ins.Disasm builder

  [<TestMethod>]
  member _.``[BPF] the operands are written after a comma test``() =
    Assert.AreEqual<string>("add r1, r2", disasm "0f21000000000000")
    Assert.AreEqual<string>("mov r0, 0x1", disasm "b700000001000000")
    Assert.AreEqual<string>("exit", disasm "9500000000000000")

  (* Which of the two classes an instruction belongs to is part of its name,
     the one working on the lower half of a register carrying a "32". *)
  [<TestMethod>]
  member _.``[BPF] the narrow class carries a 32 test``() =
    Assert.AreEqual<string>("add32 r1, r2", disasm "0c21000000000000")
    Assert.AreEqual<string>("jeq32 r1, 0x2, 0x18", disasm "1601030002000000")

  (* The memory an instruction reaches is written as the register holding where
     to start from and how far from there to reach, in brackets. *)
  [<TestMethod>]
  member _.``[BPF] memory is a register and a distance test``() =
    Assert.AreEqual<string>("ldxw r1, [r2+0x8]", disasm "6121080000000000")
    Assert.AreEqual<string>("stxdw [r1+0x10], r2", disasm "7b21100000000000")

  (* A number below zero is written as the bits of the word it was widened to,
     so that the assembler reading it back needs to know only how wide the field
     it lands in is. *)
  [<TestMethod>]
  member _.``[BPF] a number below zero is written whole test``() =
    Assert.AreEqual<string>("ldxdw r1, [r2+0xfffffff8]",
                            disasm "7921f8ff00000000")
    Assert.AreEqual<string>("ja 0xfffffffffffffff8", disasm "0500ffff00000000")

  (* How wide a load or a store reaches, and which operation an atomic store
     performs, are part of the name rather than operands. *)
  [<TestMethod>]
  member _.``[BPF] the width is part of the name test``() =
    Assert.AreEqual<string>("stb [r1+0x0], 0x5", disasm "7201000005000000")
    Assert.AreEqual<string>("atomic_fadd_dw [r1+0x0], r2",
                            disasm "db21000001000000")
    Assert.AreEqual<string>("bswap32 r1", disasm "d701000020000000")

  (* The one instruction two words wide writes the whole quadword it carries. *)
  [<TestMethod>]
  member _.``[BPF] the quadword is written whole test``() =
    Assert.AreEqual<string>("lddw r1, 0x1122334455667788",
                            disasm "18010000887766550000000044332211")

// vim: set tw=80 sts=2 sw=2:
