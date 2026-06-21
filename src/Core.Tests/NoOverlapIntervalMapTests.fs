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
open B2R2.Collections

[<TestClass>]
type NoOverlapIntervalMapTests() =

  [<TestMethod>]
  member _.``Overlap Test 1``() =
    let r1 = AddrRange.create 100UL 199UL
    let r2 = AddrRange.create 200UL 299UL
    let m = NoOverlapIntervalMap.empty
    let m = NoOverlapIntervalMap.add r1 1 m
    let m = NoOverlapIntervalMap.add r2 2 m
    Assert.Throws<RangeOverlapException>(fun () ->
      NoOverlapIntervalMap.addByBounds 99UL 100UL 3 m |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``Overlap Test 2``() =
    let r1 = AddrRange.create 100UL 199UL
    let r2 = AddrRange.create 200UL 299UL
    let m = NoOverlapIntervalMap.empty
    let m = NoOverlapIntervalMap.add r1 1 m
    let m = NoOverlapIntervalMap.add r2 2 m
    Assert.Throws<RangeOverlapException>(fun () ->
      NoOverlapIntervalMap.addByBounds 0UL 400UL 3 m |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``NoOverlapIntervalMap.findOverlaps Test``() =
    let size = 0x10UL
    let num = 0x100UL
    let sprayRange m i =
      let r = AddrRange.create (size * i) (size * (i + 1UL) - 1UL)
      NoOverlapIntervalMap.add r None m
    let r = AddrRange.create 0x150UL 0x17FUL
    let l =
      [ 0UL .. num - 1UL ]
      |> List.fold sprayRange NoOverlapIntervalMap.empty
      |> NoOverlapIntervalMap.findOverlaps r
    let n1 = r.Count / size
    let n2 = uint64 <| List.length l
    Assert.AreEqual<uint64>(n1, n2)

  [<TestMethod>]
  member _.``Count Test ``() =
    let r = AddrRange.create 100UL 200UL
    let m = NoOverlapIntervalMap.empty
    let m = NoOverlapIntervalMap.add r 1 m
    Assert.AreEqual<int>(1, NoOverlapIntervalMap.count m)

  [<TestMethod>]
  member _.``Count Test2 ``() =
    let r1 = AddrRange.create 100UL 199UL
    let r2 = AddrRange.create 50UL 99UL
    let m = NoOverlapIntervalMap.empty
    let m = NoOverlapIntervalMap.add r1 1 m
    let m = NoOverlapIntervalMap.add r2 2 m
    Assert.AreEqual<int>(2, NoOverlapIntervalMap.count m)

  [<TestMethod>]
  member _.``Count Test3 ``() =
    let r1 = AddrRange.create 100UL 199UL
    let r2 = AddrRange.create 200UL 299UL
    let m = NoOverlapIntervalMap.empty
    let m = NoOverlapIntervalMap.add r1 1 m
    let m = NoOverlapIntervalMap.add r2 2 m
    Assert.AreEqual<int>(2, NoOverlapIntervalMap.count m)

  [<TestMethod>]
  member _.``Count Test4 ``() =
    let r1 = AddrRange.create 100UL 199UL
    let r2 = AddrRange.create 200UL 299UL
    let r3 = AddrRange.create 50UL 99UL
    let m = NoOverlapIntervalMap.empty
    let m = NoOverlapIntervalMap.add r1 1 m
    let m = NoOverlapIntervalMap.add r2 2 m
    let m = NoOverlapIntervalMap.add r3 3 m
    Assert.AreEqual<int>(3, NoOverlapIntervalMap.count m)

  [<TestMethod>]
  member _.``Singleton Test1``() =
    let r1 = AddrRange.singleton 0UL
    let r2 = AddrRange.singleton 1UL
    let r3 = AddrRange.singleton 2UL
    let m = NoOverlapIntervalMap.empty
    let m = NoOverlapIntervalMap.add r1 1 m
    let m = NoOverlapIntervalMap.add r2 2 m
    let m = NoOverlapIntervalMap.add r3 3 m
    Assert.AreEqual<int>(3, NoOverlapIntervalMap.count m)
    Assert.AreEqual<int>(2, NoOverlapIntervalMap.findByAddr 1UL m)
    Assert.AreEqual<AddrRange>(r2, NoOverlapIntervalMap.findRangeByAddr 1UL m)

  [<TestMethod>]
  member _.``Previous and Next By Address``() =
    let r1 = AddrRange.create 100UL 199UL
    let r2 = AddrRange.create 300UL 399UL
    let r3 = AddrRange.create 500UL 599UL
    let m =
      NoOverlapIntervalMap.empty
      |> NoOverlapIntervalMap.add r2 2
      |> NoOverlapIntervalMap.add r1 1
      |> NoOverlapIntervalMap.add r3 3
    let prevRange, prevValue =
      NoOverlapIntervalMap.tryFindPreviousByAddr 450UL m |> Option.get
    let nextRange, nextValue =
      NoOverlapIntervalMap.tryFindNextByAddr 450UL m |> Option.get
    Assert.AreEqual<AddrRange>(r2, prevRange)
    Assert.AreEqual<int>(2, prevValue)
    Assert.AreEqual<AddrRange>(r3, nextRange)
    Assert.AreEqual<int>(3, nextValue)
    Assert.AreEqual(None, NoOverlapIntervalMap.tryFindPreviousByAddr 100UL m)
    Assert.AreEqual(None, NoOverlapIntervalMap.tryFindNextByAddr 599UL m)

  [<TestMethod>]
  member _.``Remove Last Binding``() =
    let r = AddrRange.create 100UL 199UL
    let m =
      NoOverlapIntervalMap.empty
      |> NoOverlapIntervalMap.add r 1
      |> NoOverlapIntervalMap.remove r
    Assert.AreEqual<bool>(true, NoOverlapIntervalMap.isEmpty m)
    Assert.AreEqual<int>(0, NoOverlapIntervalMap.count m)

  [<TestMethod>]
  member _.``Remove Last Binding By Address``() =
    let r = AddrRange.create 100UL 199UL
    let m =
      NoOverlapIntervalMap.empty
      |> NoOverlapIntervalMap.add r 1
      |> NoOverlapIntervalMap.removeByAddr 150UL
    Assert.AreEqual<bool>(true, NoOverlapIntervalMap.isEmpty m)
    Assert.AreEqual<int>(0, NoOverlapIntervalMap.count m)
