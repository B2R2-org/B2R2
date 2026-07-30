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

namespace B2R2.FrontEnd.ARM64.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting

/// ARM64 carried its own copy of the shared bit extractor, differing from it
/// only in how it rejected a bad offset range. These pin the behaviour the two
/// share, so the copy could be dropped.
[<TestClass>]
type ExtractTests() =
  static let extract = B2R2.FrontEnd.ARM64.Utils.extract

  [<TestMethod>]
  member _.``[AArch64] Extract Reads A Field Test``() =
    Assert.AreEqual<uint32>(0b101u, extract 0b1010u 3u 1u)
    Assert.AreEqual<uint32>(0b1010u, extract 0b1010u 3u 0u)
    Assert.AreEqual<uint32>(0x1fu, extract 0xffffffffu 20u 16u)

  (* The offsets may be given in either order. *)
  [<TestMethod>]
  member _.``[AArch64] Extract Ignores Offset Order Test``() =
    Assert.AreEqual<uint32>(extract 0xdeadbeefu 18u 14u,
                            extract 0xdeadbeefu 14u 18u)

  (* A range wider than the guard allows cannot come from the instruction; it
     means a call site wrote the wrong offsets, which is a defect. *)
  [<TestMethod>]
  member _.``[AArch64] Extract Rejects A Too Wide Range Test``() =
    Assert.ThrowsExactly<System.InvalidOperationException>(fun () ->
      extract 0xffffffffu 31u 0u |> ignore) |> ignore
