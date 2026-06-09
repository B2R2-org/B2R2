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

open System.Collections.Generic
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.Collections

[<AutoOpen>]
module private IntervalTreeTestHelpers =
  /// Creates an AddrRange spanning [lo, hi].
  let inline (--) lo hi = AddrRange.create lo hi

  /// Builds an IntervalSet from the given ranges.
  let setOf ranges =
    List.fold (fun s r -> IntervalSet.add r s) IntervalSet.empty ranges

  /// Builds an IntervalMap from the given range/value pairs.
  let mapOf pairs =
    List.fold (fun m (k, v) -> IntervalMap.add k v m) IntervalMap.empty pairs

[<TestClass>]
type IntervalTreeTests() =

  [<TestMethod>]
  member _.``IntervalSet Test isEmpty``() =
    Assert.AreEqual(true, IntervalSet.isEmpty IntervalSet.empty)
    Assert.AreEqual(false, IntervalSet.isEmpty (setOf [ 0x100UL -- 0x1FFUL ]))

  [<TestMethod>]
  member _.``IntervalSet Test tryFindOverlappingOneByAddr``() =
    let find a s = IntervalSet.tryFindOverlappingOneByAddr a s
    let range1 = 0x100UL -- 0x1FFUL
    let set = setOf [ range1 ]
    Assert.AreEqual(Some range1, find 0x100UL set)
    Assert.AreEqual(Some range1, find 0x199UL set)
    Assert.AreEqual(None, find 0x200UL set)
    Assert.AreEqual(None, find 0x99UL set)
    let range2 = 0x200UL -- 0x2FFUL
    let set = IntervalSet.add range2 set
    Assert.AreEqual(Some range1, find 0x199UL set)
    Assert.AreEqual(Some range2, find 0x200UL set)

  [<TestMethod>]
  member _.``IntervalSet Test contains``() =
    let range1 = 0x100UL -- 0x1FFUL
    let range2 = 0x200UL -- 0x2FFUL
    let range3 = 0x300UL -- 0x3FFUL
    let set = setOf [ range1; range2; range3 ]
    Assert.AreEqual(true, IntervalSet.containsRange range1 set)
    Assert.AreEqual(true, IntervalSet.containsRange range2 set)
    Assert.AreEqual(true, IntervalSet.containsRange range3 set)
    Assert.AreEqual(false, IntervalSet.containsRange (0x100UL -- 0x199UL) set)
    Assert.AreEqual(false, IntervalSet.containsRange (0x99UL -- 0x199UL) set)
    Assert.AreEqual(false, IntervalSet.containsRange (0x199UL -- 0x301UL) set)
    Assert.AreEqual(false, IntervalSet.containsRange (0x199UL -- 0x299UL) set)

  [<TestMethod>]
  member _.``IntervalSet Test Add Duplicate Range Exception``() =
    let range = 0x100UL -- 0x1FFUL
    let set = setOf [ range ]
    Assert.Throws<InvalidAddrRangeException>(fun () ->
      IntervalSet.add range set |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``IntervalSet Test Overlaps``() =
    let range1 = 0x100UL -- 0x200UL
    let range2 = 0x50UL -- 0x300UL
    let range3 = 0x150UL -- 0x160UL
    let range4 = 0x120UL -- 0x130UL
    let set = setOf [ range1; range2; range3; range4 ]
    let result = IntervalSet.findAll (0x120UL -- 0x120UL) set |> List.toArray
    CollectionAssert.AreEqual([| range2; range1; range4 |], result)
    Assert.AreEqual(true, IntervalSet.containsRange range1 set)
    Assert.AreEqual(false, IntervalSet.containsRange (0x120UL -- 0x120UL) set)
    let find a = IntervalSet.tryFindOverlappingOneByAddr a set
    Assert.AreEqual(Some range2, find 0x99UL)
    Assert.AreEqual(None, find 0x120UL)

  [<TestMethod>]
  member _.``IntervalSet Test Overlaps 2``() =
    let set = setOf [ 0x100UL -- 0x200UL; 0x300UL -- 0x400UL ]
    let found = IntervalSet.findAll (0x250UL -- 0x2FFUL) set
    Assert.AreEqual<int>(0, List.length found)

  [<TestMethod>]
  member _.``IntervalSet Test Non-Overlapping Intervals``() =
    let set = setOf [ 0UL -- 1UL; 2UL -- 3UL; 4UL -- 5UL ]
    let hasOne a =
      IntervalSet.tryFindOverlappingOneByAddr a set |> Option.isSome
    Assert.AreEqual(true, hasOne 0UL)
    Assert.AreEqual(true, hasOne 1UL)
    Assert.AreEqual(true, hasOne 2UL)
    Assert.AreEqual(true, hasOne 3UL)
    Assert.AreEqual(true, hasOne 4UL)
    Assert.AreEqual(true, hasOne 5UL)
    Assert.AreEqual(false, hasOne 6UL)
    Assert.AreEqual(true, IntervalSet.containsAddr 0UL set)
    Assert.AreEqual(true, IntervalSet.containsAddr 1UL set)
    Assert.AreEqual(true, IntervalSet.containsAddr 2UL set)
    Assert.AreEqual(true, IntervalSet.containsAddr 3UL set)
    Assert.AreEqual(true, IntervalSet.containsAddr 4UL set)
    Assert.AreEqual(true, IntervalSet.containsAddr 5UL set)
    Assert.AreEqual(false, IntervalSet.containsAddr 6UL set)
    Assert.AreEqual(true, IntervalSet.containsRange (0UL -- 1UL) set)
    Assert.AreEqual(true, IntervalSet.containsRange (2UL -- 3UL) set)
    Assert.AreEqual(true, IntervalSet.containsRange (4UL -- 5UL) set)
    Assert.AreEqual(false, IntervalSet.containsRange (3UL -- 4UL) set)
    Assert.AreEqual(false, IntervalSet.containsRange (5UL -- 6UL) set)
    Assert.AreEqual(false, IntervalSet.containsRange (1UL -- 6UL) set)

  [<TestMethod>]
  member _.``IntervalSet Test Non-Overlapping Intervals 2``() =
    let range1 = 0UL -- 1UL
    let range2 = 2UL -- 3UL
    let range3 = 4UL -- 5UL
    let set = setOf [ range1; range2; range3 ]
    let findArr lo hi = IntervalSet.findAll (lo -- hi) set |> List.toArray
    CollectionAssert.AreEqual([| range2; range3 |], findArr 3UL 4UL)
    CollectionAssert.AreEqual([| range2 |], findArr 3UL 3UL)
    CollectionAssert.AreEqual([| range1; range2 |], findArr 0UL 2UL)
    CollectionAssert.AreEqual([| range1; range2; range3 |], findArr 1UL 9UL)
    Assert.AreEqual(true, Array.isEmpty (findArr 6UL 7UL))

  [<TestMethod>]
  member _.``IntervalSet Test Removal``() =
    let range1 = 1UL -- 2UL
    let range2 = 2UL -- 3UL
    let range3 = 3UL -- 4UL
    let set = setOf [ range1; range2; range3 ]
    let actual = IntervalSet.findAll (2UL -- 3UL) set |> List.toArray
    CollectionAssert.AreEqual([| range1; range2; range3 |], actual)
    let removed = IntervalSet.remove range2 set
    Assert.AreEqual(false, IntervalSet.containsAddr 0UL removed)
    Assert.AreEqual(true, IntervalSet.containsAddr 1UL removed)
    Assert.AreEqual(true, IntervalSet.containsAddr 2UL removed)
    Assert.AreEqual(true, IntervalSet.containsAddr 3UL removed)
    Assert.AreEqual(true, IntervalSet.containsRange (1UL -- 2UL) removed)
    Assert.AreEqual(true, IntervalSet.containsRange (3UL -- 4UL) removed)
    Assert.AreEqual<int>(2, IntervalSet.count removed)

  [<TestMethod>]
  member _.``IntervalSet Test Removal 2``() =
    let set = setOf [ 1UL -- 2UL; 2UL -- 3UL; 3UL -- 4UL ]
    let removed = IntervalSet.remove (1UL -- 2UL) set
    Assert.AreEqual(false, IntervalSet.containsAddr 1UL removed)
    Assert.AreEqual(true, IntervalSet.containsAddr 2UL removed)
    Assert.AreEqual(true, IntervalSet.containsAddr 3UL removed)
    Assert.AreEqual(true, IntervalSet.containsAddr 4UL removed)
    Assert.AreEqual(true, IntervalSet.containsRange (2UL -- 3UL) removed)
    Assert.AreEqual(true, IntervalSet.containsRange (3UL -- 4UL) removed)
    Assert.AreEqual<int>(2, IntervalSet.count removed)

  [<TestMethod>]
  member _.``IntervalMap Test tryFindExactlyOneByMin``() =
    let find a m = IntervalMap.tryFindExactlyOneByMin a m
    let range1 = 0x100UL -- 0x1FFUL
    let map = mapOf [ range1, 1 ]
    Assert.AreEqual(Some 1, find 0x100UL map)
    Assert.AreEqual(None, find 0x199UL map)
    Assert.AreEqual(None, find 0x200UL map)
    let range2 = 0x200UL -- 0x2FFUL
    let map = IntervalMap.add range2 2 map
    Assert.AreEqual(Some 1, find 0x100UL map)
    Assert.AreEqual(Some 2, find 0x200UL map)

  [<TestMethod>]
  member _.``IntervalMap Test tryFindExactlyOneByMin With Multiple Matches``() =
    let map = mapOf [ 0x100UL -- 0x1FFUL, 1; 0x100UL -- 0x2FFUL, 2 ]
    Assert.AreEqual(None, IntervalMap.tryFindExactlyOneByMin 0x100UL map)

  [<TestMethod>]
  member _.``IntervalMap Test Add Duplicate Range Exception``() =
    let range = 0x100UL -- 0x1FFUL
    let map = mapOf [ range, 1 ]
    Assert.Throws<InvalidAddrRangeException>(fun () ->
      IntervalMap.add range 2 map |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``IntervalMap Test Removal``() =
    let range1 = 0x100UL -- 0x1FFUL
    let range2 = 0x200UL -- 0x2FFUL
    let range3 = 0x300UL -- 0x3FFUL
    let range4 = 0x150UL -- 0x17FUL
    let range5 = 0x150UL -- 0x21FUL
    let range6 = 0x400UL -- 0x4FFUL
    let map =
      mapOf [ range2, 2; range1, 1; range3, 3; range4, 4; range5, 5; range6, 6 ]
    Assert.AreEqual(Some 2, IntervalMap.tryFindExactlyOneByMin 0x200UL map)
    Assert.AreEqual(Some 3, IntervalMap.tryFindExactlyOne range3 map)
    Assert.AreEqual(Some 4, IntervalMap.tryFindExactlyOne range4 map)
    let map = IntervalMap.remove range4 map
    Assert.AreEqual(Some 3, IntervalMap.tryFindExactlyOne range3 map)
    Assert.AreEqual(Some 5, IntervalMap.tryFindExactlyOne range5 map)
    Assert.AreEqual(None, IntervalMap.tryFindExactlyOne range4 map)

  [<TestMethod>]
  member _.``IntervalMap Test Removal Exception``() =
    let range1 = 0x100UL -- 0x1FFUL
    let map = mapOf [ range1, 1 ]
    Assert.Throws<InvalidAddrRangeException>(fun () ->
      IntervalMap.remove (0x100UL -- 0x199UL) map |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``IntervalSet Test count``() =
    Assert.AreEqual<int>(0, IntervalSet.count IntervalSet.empty)
    let set = setOf [ 0UL -- 1UL; 2UL -- 3UL ]
    Assert.AreEqual<int>(2, IntervalSet.count set)

  [<TestMethod>]
  member _.``IntervalSet Test FindExactlyOneByMin``() =
    let range1 = 0x100UL -- 0x1FFUL
    let range2 = 0x200UL -- 0x2FFUL
    let set = setOf [ range1; range2 ]
    Assert.AreEqual(Some range1, IntervalSet.tryFindExactlyOneByMin 0x100UL set)
    Assert.AreEqual(None, IntervalSet.tryFindExactlyOneByMin 0x150UL set)
    Assert.AreEqual(range2, IntervalSet.findExactlyOneByMin 0x200UL set)
    Assert.Throws<KeyNotFoundException>(fun () ->
      IntervalSet.findExactlyOneByMin 0x150UL set |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``IntervalSet Test FindOverlappingOne raises``() =
    let set = setOf [ 0x100UL -- 0x1FFUL ]
    Assert.Throws<KeyNotFoundException>(fun () ->
      IntervalSet.findOverlappingOneByAddr 0x500UL set |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``IntervalMap Test count``() =
    Assert.AreEqual<int>(0, IntervalMap.count IntervalMap.empty)
    let map = mapOf [ 0UL -- 1UL, 1; 2UL -- 3UL, 2 ]
    Assert.AreEqual<int>(2, IntervalMap.count map)

  [<TestMethod>]
  member _.``IntervalMap Test FindOverlappingOneByAddr``() =
    let map = mapOf [ 0x100UL -- 0x1FFUL, 1; 0x300UL -- 0x3FFUL, 2 ]
    Assert.AreEqual(Some 1, IntervalMap.tryFindOverlappingOneByAddr 0x150UL map)
    Assert.AreEqual(None, IntervalMap.tryFindOverlappingOneByAddr 0x250UL map)
    Assert.AreEqual(2, IntervalMap.findOverlappingOneByAddr 0x350UL map)
    Assert.Throws<KeyNotFoundException>(fun () ->
      IntervalMap.findExactlyOne (0x1UL -- 0x2UL) map |> ignore)
    |> ignore
