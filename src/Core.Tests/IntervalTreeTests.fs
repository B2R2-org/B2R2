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
type IntervalTreeTests() =

  [<TestMethod>]
  member _.``IntervalSet Test tryFindByAddr``() =
    let range1 = AddrRange(0x100UL, 0x1FFUL)
    let set = IntervalSet.add range1 IntervalSet.empty
    Assert.AreEqual(Some range1, IntervalSet.tryFindByAddr 0x100UL set)
    Assert.AreEqual(Some range1, IntervalSet.tryFindByAddr 0x199UL set)
    Assert.AreEqual(None, IntervalSet.tryFindByAddr 0x200UL set)
    Assert.AreEqual(None, IntervalSet.tryFindByAddr 0x99UL set)
    let range2 = AddrRange(0x200UL, 0x2FFUL)
    let set = IntervalSet.add range2 set
    Assert.AreEqual(Some range1, IntervalSet.tryFindByAddr 0x199UL set)
    Assert.AreEqual(Some range2, IntervalSet.tryFindByAddr 0x200UL set)

  [<TestMethod>]
  member _.``IntervalSet Test contains``() =
    let range1 = AddrRange(0x100UL, 0x1FFUL)
    let range2 = AddrRange(0x200UL, 0x2FFUL)
    let range3 = AddrRange(0x300UL, 0x3FFUL)
    let set = IntervalSet.add range1 IntervalSet.empty
    let set = IntervalSet.add range2 set
    let set = IntervalSet.add range3 set
    Assert.IsTrue(IntervalSet.contains range1 set)
    Assert.IsTrue(IntervalSet.contains range2 set)
    Assert.IsTrue(IntervalSet.contains range3 set)
    let range4 = AddrRange(0x100UL, 0x199UL)
    let range5 = AddrRange(0x99UL, 0x199UL)
    let range6 = AddrRange(0x199UL, 0x301UL)
    let range7 = AddrRange(0x199UL, 0x299UL)
    Assert.IsFalse(IntervalSet.contains range4 set)
    Assert.IsFalse(IntervalSet.contains range5 set)
    Assert.IsFalse(IntervalSet.contains range6 set)
    Assert.IsFalse(IntervalSet.contains range7 set)

  [<TestMethod>]
  member _.``IntervalSet Test Overlaps``() =
    let range1 = AddrRange(0x100UL, 0x200UL)
    let range2 = AddrRange(0x50UL, 0x300UL)
    let range3 = AddrRange(0x150UL, 0x160UL)
    let range4 = AddrRange(0x120UL, 0x130UL)
    let set = IntervalSet.add range1 IntervalSet.empty
    let set = IntervalSet.add range2 set
    let set = IntervalSet.add range3 set
    let set = IntervalSet.add range4 set
    let range5 = AddrRange(0x120UL, 0x120UL)
    let overlap1 = [| range4; range1; range2 |]
    let result1 = IntervalSet.findAll range5 set |> List.toArray
    CollectionAssert.AreEqual(overlap1, result1)
    Assert.IsTrue(IntervalSet.contains range1 set)
    Assert.IsFalse(IntervalSet.contains range5 set)
    Assert.AreEqual(Some range2, IntervalSet.tryFindByAddr 0x99UL set)

  [<TestMethod>]
  member _.``IntervalSet Test Overlaps 2``() =
    let range1 = AddrRange(0x100UL, 0x200UL)
    let range2 = AddrRange(0x300UL, 0x400UL)
    let set = IntervalSet.add range1 IntervalSet.empty
    let set = IntervalSet.add range2 set
    let range = AddrRange(0x250UL, 0x2FFUL)
    Assert.AreEqual<int>(0, IntervalSet.findAll range set |> List.length)

  [<TestMethod>]
  member _.``IntervalSet Test Non-Overlapping Intervals``() =
    let range1 = AddrRange(0UL, 1UL)
    let range2 = AddrRange(2UL, 3UL)
    let range3 = AddrRange(4UL, 5UL)
    let set = IntervalSet.add range1 IntervalSet.empty
    let set = IntervalSet.add range2 set |> IntervalSet.add range3
    Assert.IsTrue(IntervalSet.tryFindByAddr 0UL set |> Option.isSome)
    Assert.IsTrue(IntervalSet.tryFindByAddr 1UL set |> Option.isSome)
    Assert.IsTrue(IntervalSet.tryFindByAddr 2UL set |> Option.isSome)
    Assert.IsTrue(IntervalSet.tryFindByAddr 3UL set |> Option.isSome)
    Assert.IsTrue(IntervalSet.tryFindByAddr 4UL set |> Option.isSome)
    Assert.IsTrue(IntervalSet.tryFindByAddr 5UL set |> Option.isSome)
    Assert.IsTrue(IntervalSet.tryFindByAddr 6UL set |> Option.isNone)
    Assert.IsTrue(IntervalSet.containsAddr 0UL set)
    Assert.IsTrue(IntervalSet.containsAddr 1UL set)
    Assert.IsTrue(IntervalSet.containsAddr 2UL set)
    Assert.IsTrue(IntervalSet.containsAddr 3UL set)
    Assert.IsTrue(IntervalSet.containsAddr 4UL set)
    Assert.IsTrue(IntervalSet.containsAddr 5UL set)
    Assert.IsFalse(IntervalSet.containsAddr 6UL set)
    Assert.IsTrue(IntervalSet.contains (AddrRange(0UL, 1UL)) set)
    Assert.IsTrue(IntervalSet.contains (AddrRange(2UL, 3UL)) set)
    Assert.IsTrue(IntervalSet.contains (AddrRange(4UL, 5UL)) set)
    Assert.IsFalse(IntervalSet.contains (AddrRange(3UL, 4UL)) set)
    Assert.IsFalse(IntervalSet.contains (AddrRange(5UL, 6UL)) set)
    Assert.IsFalse(IntervalSet.contains (AddrRange(1UL, 6UL)) set)

  [<TestMethod>]
  member _.``IntervalSet Test Non-Overlapping Intervals 2``() =
    let range1 = AddrRange(0UL, 1UL)
    let range2 = AddrRange(2UL, 3UL)
    let range3 = AddrRange(4UL, 5UL)
    let set = IntervalSet.add range1 IntervalSet.empty
    let set = IntervalSet.add range2 set |> IntervalSet.add range3
    let expected = [| range3; range2 |]
    let actual = IntervalSet.findAll (AddrRange(3UL, 4UL)) set |> List.toArray
    CollectionAssert.AreEqual(expected, actual)
    let expected = [| range2 |]
    let actual = IntervalSet.findAll (AddrRange(3UL, 3UL)) set |> List.toArray
    CollectionAssert.AreEqual(expected, actual)
    let expected = [| range2; range1 |]
    let actual = IntervalSet.findAll (AddrRange(0UL, 2UL)) set |> List.toArray
    CollectionAssert.AreEqual(expected, actual)
    let expected = [| range3; range2; range1 |]
    let actual = IntervalSet.findAll (AddrRange(1UL, 9UL)) set |> List.toArray
    CollectionAssert.AreEqual(expected, actual)
    let actual = IntervalSet.findAll (AddrRange(6UL, 7UL)) set
    Assert.IsTrue(List.isEmpty actual)

  [<TestMethod>]
  member _.``IntervalSet Test Removal``() =
    let range1 = AddrRange(1UL, 2UL)
    let range2 = AddrRange(2UL, 3UL)
    let range3 = AddrRange(3UL, 4UL)
    let set = IntervalSet.add range1 IntervalSet.empty
    let set = IntervalSet.add range2 set |> IntervalSet.add range3
    let expected = [| range3; range2; range1 |]
    let actual = IntervalSet.findAll (AddrRange(2UL, 3UL)) set |> List.toArray
    CollectionAssert.AreEqual(expected, actual)
    let removed = IntervalSet.remove range2 set
    Assert.IsFalse(IntervalSet.containsAddr 0UL removed)
    Assert.IsTrue(IntervalSet.containsAddr 1UL removed)
    Assert.IsTrue(IntervalSet.containsAddr 2UL removed)
    Assert.IsTrue(IntervalSet.containsAddr 3UL removed)
    Assert.IsTrue(IntervalSet.containsAddr 4UL removed)
    Assert.IsTrue(IntervalSet.contains (AddrRange(1UL, 2UL)) removed)
    Assert.IsTrue(IntervalSet.contains (AddrRange(3UL, 4UL)) removed)
    Assert.AreEqual<int>(2, IntervalSet.fold (fun cnt _ -> cnt + 1) 0 removed)

  [<TestMethod>]
  member _.``IntervalSet Test Removal 2``() =
    let range1 = AddrRange(1UL, 2UL)
    let range2 = AddrRange(2UL, 3UL)
    let range3 = AddrRange(3UL, 4UL)
    let set = IntervalSet.add range1 IntervalSet.empty
    let set = IntervalSet.add range2 set |> IntervalSet.add range3
    let removed = IntervalSet.remove (AddrRange(1UL, 2UL)) set
    Assert.IsFalse(IntervalSet.containsAddr 1UL removed)
    Assert.IsTrue(IntervalSet.containsAddr 2UL removed)
    Assert.IsTrue(IntervalSet.containsAddr 3UL removed)
    Assert.IsTrue(IntervalSet.containsAddr 4UL removed)
    Assert.IsTrue(IntervalSet.contains (AddrRange(2UL, 3UL)) removed)
    Assert.IsTrue(IntervalSet.contains (AddrRange(3UL, 4UL)) removed)
    Assert.AreEqual<int>(2, IntervalSet.fold (fun cnt _ -> cnt + 1) 0 removed)

  [<TestMethod>]
  member _.``IntervalMap Test tryFindByMin``() =
    let range1 = AddrRange(0x100UL, 0x1FFUL)
    let map = IntervalMap.add range1 1 IntervalMap.empty
    Assert.AreEqual(Some 1, IntervalMap.tryFindByMin 0x100UL map)
    Assert.AreEqual(None, IntervalMap.tryFindByMin 0x199UL map)
    Assert.AreEqual(None, IntervalMap.tryFindByMin 0x200UL map)
    let range2 = AddrRange(0x200UL, 0x2FFUL)
    let map = IntervalMap.add range2 2 map
    Assert.AreEqual(Some 1, IntervalMap.tryFindByMin 0x100UL map)
    Assert.AreEqual(Some 2, IntervalMap.tryFindByMin 0x200UL map)

  [<TestMethod>]
  member _.``IntervalMap Test Removal``() =
    let range1 = AddrRange(0x100UL, 0x1FFUL)
    let range2 = AddrRange(0x200UL, 0x2FFUL)
    let range3 = AddrRange(0x300UL, 0x3FFUL)
    let range4 = AddrRange(0x150UL, 0x17FUL)
    let range5 = AddrRange(0x150UL, 0x21FUL)
    let range6 = AddrRange(0x400UL, 0x4FFUL)
    let map = IntervalMap.add range2 2 IntervalMap.empty
    let map = IntervalMap.add range1 1 map
    let map = IntervalMap.add range3 3 map
    let map = IntervalMap.add range4 4 map
    let map = IntervalMap.add range5 5 map
    let map = IntervalMap.add range6 6 map
    Assert.AreEqual(Some 2, IntervalMap.tryFindByMin 0x200UL map)
    Assert.AreEqual(Some 3, IntervalMap.tryFind range3 map)
    Assert.AreEqual(Some 4, IntervalMap.tryFind range4 map)
    let map = IntervalMap.remove range4 map
    Assert.AreEqual(Some 3, IntervalMap.tryFind range3 map)
    Assert.AreEqual(Some 5, IntervalMap.tryFind range5 map)
    Assert.AreEqual(None, IntervalMap.tryFind range4 map)

  [<TestMethod>]
  [<ExpectedException(typedefof<InvalidAddrRangeException>)>]
  member _.``IntervalMap Test Removal Exception``() =
    let range1 = AddrRange(0x100UL, 0x1FFUL)
    let map = IntervalMap.add range1 1 IntervalMap.empty
    IntervalMap.remove (AddrRange(0x100UL, 0x199UL)) map |> ignore
