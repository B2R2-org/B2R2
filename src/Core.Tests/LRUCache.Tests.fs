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

open Microsoft.VisualStudio.TestTools.UnitTesting

open B2R2

open System.Threading

type TestOp () =
  let cnt = ref 0
  member __.Count with get() = !cnt
  interface ICacheableOperation<int, int> with
    member __.Perform v =
      Interlocked.Increment cnt |> ignore
      v

[<TestClass>]
type LRUCacheTests () =
  [<TestMethod>]
  member __.``GetOrAddTest`` () =
    let op = TestOp ()
    let lru = ConcurrentLRUCache<int, int>(100)
    for i = 0 to 10 do Assert.AreEqual (1, lru.GetOrAdd 1 op 1)
    Assert.AreEqual (1, op.Count)

  [<TestMethod>]
  member __.``CountTest`` () =
    let op = TestOp ()
    let lru = ConcurrentLRUCache<int, int>(100)
    for i = 0 to 99 do Assert.AreEqual (i, lru.GetOrAdd i op i)
    Assert.AreEqual (100, op.Count)
    Assert.AreEqual (100, lru.Count)
    lru.Clear ()
    Assert.AreEqual (0, lru.Count)
    for i = 0 to 99 do Assert.AreEqual (i, lru.GetOrAdd i op i)
    Assert.AreEqual (200, op.Count)
    Assert.AreEqual (100, lru.Count)

  [<TestMethod>]
  member __.``OverflowTest`` () =
    let op = TestOp ()
    let lru = ConcurrentLRUCache<int, int>(100)
    for i = 0 to 199 do Assert.AreEqual (i, lru.GetOrAdd i op i)
    Assert.AreEqual (200, op.Count)
    Assert.AreEqual (100, lru.Count)
    let op = TestOp ()
    for i = 100 to 199 do Assert.AreEqual (i, lru.GetOrAdd i op i)
    Assert.AreEqual (0, op.Count)

  [<TestMethod>]
  member __.``LRUTest`` () =
    let op = TestOp ()
    let lru = ConcurrentLRUCache<int, int>(100)
    for i = 0 to 99 do Assert.AreEqual (i, lru.GetOrAdd i op i)
    Assert.AreEqual (100, op.Count)
    Assert.AreEqual (100, lru.Count)
    Assert.AreEqual (0, lru.GetOrAdd 0 op 0)
    Assert.AreEqual (100, op.Count)
    Assert.AreEqual (100, lru.Count)
    Assert.AreEqual (100, lru.GetOrAdd 100 op 100)
    let op = TestOp ()
    Assert.AreEqual (0, lru.GetOrAdd 0 op 0)
    Assert.AreEqual (0, op.Count)
