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

namespace B2R2.Core.Tests

open System
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.Collections

[<TestClass>]
type RingBufferTests() =

  [<TestMethod>]
  member _.``Write And Read Generic Values``() =
    let buffer = RingBuffer<string>(3)
    Assert.AreEqual<int>(2, buffer.Write [| "a"; "b" |])
    Assert.AreEqual<int>(2, buffer.Count)
    CollectionAssert.AreEqual([| "a"; "b" |], buffer.Read 3)
    Assert.AreEqual<bool>(true, buffer.IsEmpty)

  [<TestMethod>]
  member _.``Wrap Around Preserves FIFO Order``() =
    let buffer = RingBuffer<int>(3)
    Assert.AreEqual<int>(3, buffer.Write [| 1; 2; 3 |])
    CollectionAssert.AreEqual([| 1; 2 |], buffer.Read 2)
    Assert.AreEqual<int>(2, buffer.Write [| 4; 5 |])
    CollectionAssert.AreEqual([| 3; 4; 5 |], buffer.Read 3)

  [<TestMethod>]
  member _.``Full Buffer Accepts Only Available Slots``() =
    let buffer = RingBuffer<int>(3)
    Assert.AreEqual<int>(2, buffer.Write [| 1; 2 |])
    Assert.AreEqual<int>(1, buffer.Write [| 3; 4 |])
    Assert.AreEqual<bool>(true, buffer.IsFull)
    CollectionAssert.AreEqual([| 1; 2; 3 |], buffer.Read 3)

  [<TestMethod>]
  member _.``Rejects Invalid Capacity``() =
    Assert.Throws<ArgumentOutOfRangeException>(fun () ->
      RingBuffer<int>(0) |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``Rejects Negative Read Count``() =
    let buffer = RingBuffer<int>(1)
    Assert.Throws<ArgumentOutOfRangeException>(fun () ->
      buffer.Read -1 |> ignore)
    |> ignore
