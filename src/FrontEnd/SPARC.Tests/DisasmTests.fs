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

namespace B2R2.FrontEnd.SPARC.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SPARC

/// <summary>
/// Pins the text the disassembler writes for the instructions it once parsed
/// without being able to name.
///
/// An instruction the decoder understands but has no name for is worse than one
/// it does not understand: a sweep of a binary sees it as code and then fails
/// only when something asks what it says. The three below were exactly that,
/// and nothing else notices their coming back, because everything derived from
/// the decoder simply leaves out what it cannot write down.
/// </summary>
[<TestClass>]
type DisasmTests() =
  static let reader = BinReader.Init (ISA Architecture.SPARC).Endian

  static let parser = SPARCParser(reader) :> IInstructionParsable

  static let disasm hex =
    let bytes = ByteArray.ofHexString hex
    (parser.Parse(System.ReadOnlySpan bytes, 0UL)).Disasm()

  [<TestMethod>]
  member _.``[SPARC] Subtract With Borrow Disasm Test``() =
    Assert.AreEqual<string>("subc %g0, %g5, %g0", disasm "80600005")

  [<TestMethod>]
  member _.``[SPARC] Subtract With Borrow And CCs Disasm Test``() =
    Assert.AreEqual<string>("subccc %g0, %g5, %g0", disasm "80e00005")

  [<TestMethod>]
  member _.``[SPARC] Branch On Overflow Set Disasm Test``() =
    Assert.AreEqual<string>("bvs 0x14", disasm "0e800005")

// vim: set tw=80 sts=2 sw=2:
