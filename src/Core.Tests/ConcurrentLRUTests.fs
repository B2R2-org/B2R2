(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Minkyu Jung <hestati@kaist.ac.kr>

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

module B2R2.Core.Tests.ConcurrentLRU

open Microsoft.VisualStudio.TestTools.UnitTesting

open B2R2

open System.Threading

[<TestClass>]
type TestClass () =
  member __.GenTestFunc<'K, 'V> (proc: 'K -> 'V) =
    let x = ref 0
    (fun k -> Interlocked.Increment x |> ignore; proc k), x

  [<TestMethod>]
  member __.``GetOrAddTest`` () =
    let proc, cnt = __.GenTestFunc (fun x -> x)
    let lru = new ConcurrentLRU<int, int>(100)
    for i = 0 to 10 do Assert.AreEqual (1, lru.GetOrAdd 1 proc)
    Assert.AreEqual (1, !cnt)

  [<TestMethod>]
  member __.``CountTest`` () =
    let proc, cnt = __.GenTestFunc (fun x -> x)
    let lru = new ConcurrentLRU<int, int>(100)
    for i = 0 to 99 do Assert.AreEqual (i, lru.GetOrAdd i proc)
    Assert.AreEqual (100, !cnt)
    Assert.AreEqual (100, lru.Count)
    lru.Clear ()
    Assert.AreEqual (0, lru.Count)
    for i = 0 to 99 do Assert.AreEqual (i, lru.GetOrAdd i proc)
    Assert.AreEqual (200, !cnt)
    Assert.AreEqual (100, lru.Count)

  [<TestMethod>]
  member __.``OverflowTest`` () =
    let proc, cnt = __.GenTestFunc (fun x -> x)
    let lru = new ConcurrentLRU<int, int>(100)
    for i = 0 to 199 do Assert.AreEqual (i, lru.GetOrAdd i proc)
    Assert.AreEqual (200, !cnt)
    Assert.AreEqual (100, lru.Count)
    let proc2, cnt2 = __.GenTestFunc (fun x -> x)
    for i = 100 to 199 do Assert.AreEqual (i, lru.GetOrAdd i proc2)
    Assert.AreEqual (0, !cnt2)

  [<TestMethod>]
  member __.``LRUTest`` () =
    let proc, cnt = __.GenTestFunc (fun x -> x)
    let lru = new ConcurrentLRU<int, int>(100)
    for i = 0 to 99 do Assert.AreEqual (i, lru.GetOrAdd i proc)
    Assert.AreEqual (100, !cnt)
    Assert.AreEqual (100, lru.Count)
    Assert.AreEqual (0, lru.GetOrAdd 0 proc)
    Assert.AreEqual (100, !cnt)
    Assert.AreEqual (100, lru.Count)
    Assert.AreEqual (100, lru.GetOrAdd 100 proc)
    let proc2, cnt2 = __.GenTestFunc (fun x -> x)
    Assert.AreEqual (0, lru.GetOrAdd 0 proc2)
    Assert.AreEqual (0, !cnt2)
