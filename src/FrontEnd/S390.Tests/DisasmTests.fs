(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)

namespace B2R2.FrontEnd.BinLifter.Tests

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.S390
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type DisasmTests() =
  static let isa = ISA(Architecture.S390, endian = Endian.Big)

  static let parser =
    S390Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable

  /// The address the instructions below are parsed at, so that the branch
  /// targets are checkable constants.
  static let baseAddr = 0x1000UL

  static let disasmAt wordSize addr (bytes: byte[]) =
    let ins = parser.Parse(System.ReadOnlySpan bytes, addr)
    let builder = StringDisasmBuilder(false, null, wordSize)
    ins.Disasm builder

  static let disasm bytes = disasmAt WordSize.Bit64 baseAddr bytes

  (* S390 folded the " ; " comment delimiter into the symbol prefix and into the
     no-symbol mapper, so when neither applied the whole comment vanished and a
     relative branch printed with no target at all. Intel and ARM32 write the
     delimiter themselves and so at least left a dangling ";" behind. *)
  [<TestMethod>]
  member _.``[S390] a relative branch shows its target test``() =
    let brc = [| 0xa7uy; 0xf4uy; 0x00uy; 0x08uy |]
    Assert.AreEqual<string>("brc B'1111', +0x10 ; 0x1010", disasm brc)

  [<TestMethod>]
  member _.``[S390] a long relative branch shows its target test``() =
    let brcl = [| 0xc0uy; 0xf4uy; 0x00uy; 0x00uy; 0x00uy; 0x08uy |]
    Assert.AreEqual<string>("brcl B'1111', +0x10 ; 0x1010", disasm brcl)

  [<TestMethod>]
  member _.``[S390] a backward branch shows its target test``() =
    let brc = [| 0xa7uy; 0xf4uy; 0xffuy; 0xf8uy |]
    Assert.AreEqual<string>("brc B'1111', -0x10 ; 0xff0", disasm brc)

  (* ESA/390 forms a branch address in the 31-bit addressing mode, so a target
     that runs past the first 2 GB comes back around to the bottom of it. A
     64-bit target keeps carrying instead. *)
  [<TestMethod>]
  member _.``[S390] a 32-bit branch target wraps at 31 bits test``() =
    let brc = [| 0xa7uy; 0xf4uy; 0x00uy; 0x08uy |]
    let disasm = disasmAt WordSize.Bit32 0x7ffffff8UL brc
    Assert.AreEqual<string>("brc B'1111', +0x10 ; 0x8", disasm)

  [<TestMethod>]
  member _.``[S390] a 64-bit branch target does not wrap test``() =
    let brc = [| 0xa7uy; 0xf4uy; 0x00uy; 0x08uy |]
    let disasm = disasmAt WordSize.Bit64 0x7ffffff8UL brc
    Assert.AreEqual<string>("brc B'1111', +0x10 ; 0x80000008", disasm)

  (* A backward branch from a low address underflows, which the 31-bit
     addressing mode turns into a target near the top of the first 2 GB. *)
  [<TestMethod>]
  member _.``[S390] a 32-bit backward branch wraps at 31 bits test``() =
    let brc = [| 0xa7uy; 0xf4uy; 0xffuy; 0xf8uy |]
    let disasm = disasmAt WordSize.Bit32 0x8UL brc
    Assert.AreEqual<string>("brc B'1111', -0x10 ; 0x7ffffff8", disasm)
