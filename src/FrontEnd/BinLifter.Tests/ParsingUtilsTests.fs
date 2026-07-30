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

open B2R2.FrontEnd.BinLifter.ParsingUtils
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins the bit reader every architecture but S390 goes through.
[<TestClass>]
type ParsingUtilsTests() =
  [<TestMethod>]
  member _.``[ParsingUtils] Extract Reads A Field Test``() =
    Assert.AreEqual<uint32>(0b101u, Bits.extract 0b1010u 3u 1u)
    Assert.AreEqual<uint32>(0b1010u, Bits.extract 0b1010u 3u 0u)
    Assert.AreEqual<uint32>(0xabcdu, Bits.extract 0xabcd1234u 31u 16u)

  (* The order of the offsets does not matter, as the summary promises. *)
  [<TestMethod>]
  member _.``[ParsingUtils] Extract Ignores Offset Order Test``() =
    Assert.AreEqual<uint32>(Bits.extract 0xdeadbeefu 18u 14u,
                            Bits.extract 0xdeadbeefu 14u 18u)

  (* The mask was computed as pown 2 range - 1 in int arithmetic, which
     overflows at a range of 31 even though the guard admits it. A parser
     reading a field that wide got an arithmetic overflow, and the guard around
     Parse then reported the instruction as merely undecodable. *)
  [<TestMethod>]
  member _.``[ParsingUtils] Extract Reads The Widest Field Test``() =
    Assert.AreEqual<uint32>(0x3fffffffu, Bits.extract 0xffffffffu 29u 0u)
    Assert.AreEqual<uint32>(0x7fffffffu, Bits.extract 0xffffffffu 30u 0u)
    Assert.AreEqual<uint32>(0x5eadbeefu, Bits.extract 0xdeadbeefu 30u 0u)
    Assert.AreEqual<uint32>(0x7fffffffu, Bits.extract 0xffffffffu 31u 1u)

  (* A range wider than the whole word cannot come from an instruction; it means
     a call site wrote the wrong offsets. *)
  [<TestMethod>]
  member _.``[ParsingUtils] Extract Rejects A Too Wide Range Test``() =
    Assert.ThrowsExactly<System.InvalidOperationException>(fun () ->
      Bits.extract 0xffffffffu 31u 0u |> ignore) |> ignore
