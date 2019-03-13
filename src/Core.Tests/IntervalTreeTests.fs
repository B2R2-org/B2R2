(*
    B2R2 - the Next-Generation Reversing Platform

    Author: DongYeop Oh <oh51dy@kaist.ac.kr>

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

module B2R2.Core.Tests.IntervalTree

open Microsoft.VisualStudio.TestTools.UnitTesting

open B2R2

[<TestClass>]
type TestClass () =

    [<TestMethod>]
    member __.``IntervalSet Test tryFindByAddr`` () =
        let range1 = AddrRange (0x100UL, 0x200UL)
        let set = IntervalSet.add range1 IntervalSet.empty
        Assert.AreEqual (Some range1, IntervalSet.tryFindByAddr 0x100UL set)
        Assert.AreEqual (Some range1, IntervalSet.tryFindByAddr 0x199UL set)
        Assert.AreEqual (None, IntervalSet.tryFindByAddr 0x200UL set)
        Assert.AreEqual (None, IntervalSet.tryFindByAddr 0x99UL set)
        let range2 = AddrRange (0x200UL, 0x300UL)
        let set = IntervalSet.add range2 set
        Assert.AreEqual (Some range1, IntervalSet.tryFindByAddr 0x199UL set)
        Assert.AreEqual (Some range2, IntervalSet.tryFindByAddr 0x200UL set)

    [<TestMethod>]
    member __.``IntervalSet Test contains`` () =
        let range1 = AddrRange (0x100UL, 0x200UL)
        let range2 = AddrRange (0x200UL, 0x300UL)
        let range3 = AddrRange (0x300UL, 0x400UL)
        let set = IntervalSet.add range1 IntervalSet.empty
        let set = IntervalSet.add range2 set
        let set = IntervalSet.add range3 set
        Assert.IsTrue (IntervalSet.contains range1 set)
        Assert.IsTrue (IntervalSet.contains range2 set)
        Assert.IsTrue (IntervalSet.contains range3 set)
        let range4 = AddrRange (0x100UL, 0x199UL)
        let range5 = AddrRange (0x99UL, 0x199UL)
        let range6 = AddrRange (0x199UL, 0x301UL)
        let range7 = AddrRange (0x199UL, 0x299UL)
        Assert.IsFalse (IntervalSet.contains range4 set)
        Assert.IsFalse (IntervalSet.contains range5 set)
        Assert.IsFalse (IntervalSet.contains range6 set)
        Assert.IsFalse (IntervalSet.contains range7 set)

    [<TestMethod>]
    member __.``IntervalSet Test Overlaps`` () =
        let range1 = AddrRange (0x100UL, 0x200UL)
        let range2 = AddrRange (0x50UL, 0x300UL)
        let range3 = AddrRange (0x150UL, 0x160UL)
        let range4 = AddrRange (0x120UL, 0x130UL)
        let set = IntervalSet.add range1 IntervalSet.empty
        let set = IntervalSet.add range2 set
        let set = IntervalSet.add range3 set
        let set = IntervalSet.add range4 set
        let range5 = AddrRange (0x120UL, 0x121UL)
        let overlap1 = [| range2; range1; range4 |]
        let result1 = IntervalSet.findAll range5 set |> List.toArray
        CollectionAssert.AreEqual (overlap1, result1)
        Assert.IsTrue (IntervalSet.contains range1 set)
        Assert.IsFalse (IntervalSet.contains range5 set)
        Assert.AreEqual (Some range2, IntervalSet.tryFindByAddr 0x99UL set)

    [<TestMethod>]
    member __.``IntervalMap Test tryFindByMin`` () =
        let range1 = AddrRange (0x100UL, 0x200UL)
        let map = IntervalMap.add range1 1 IntervalMap.empty
        Assert.AreEqual (Some 1, IntervalMap.tryFindByMin 0x100UL map)
        Assert.AreEqual (None, IntervalMap.tryFindByMin 0x199UL map)
        Assert.AreEqual (None, IntervalMap.tryFindByMin 0x200UL map)
        let range2 = AddrRange (0x200UL, 0x300UL)
        let map = IntervalMap.add range2 2 map
        Assert.AreEqual (Some 1, IntervalMap.tryFindByMin 0x100UL map)
        Assert.AreEqual (Some 2, IntervalMap.tryFindByMin 0x200UL map)

    [<TestMethod>]
    member __.``IntervalMap Test Removal`` () =
        let range1 = AddrRange (0x100UL, 0x200UL)
        let range2 = AddrRange (0x200UL, 0x300UL)
        let range3 = AddrRange (0x300UL, 0x400UL)
        let range4 = AddrRange (0x150UL, 0x180UL)
        let range5 = AddrRange (0x150UL, 0x220UL)
        let range6 = AddrRange (0x400UL, 0x500UL)
        let map = IntervalMap.add range2 2 IntervalMap.empty
        let map = IntervalMap.add range1 1 map
        let map = IntervalMap.add range3 3 map
        let map = IntervalMap.add range4 4 map
        let map = IntervalMap.add range5 5 map
        let map = IntervalMap.add range6 6 map
        Assert.AreEqual (Some 2, IntervalMap.tryFindByMin 0x200UL map)
        Assert.AreEqual (Some 3, IntervalMap.tryFind range3 map)
        Assert.AreEqual (Some 4, IntervalMap.tryFind range4 map)
        let map = IntervalMap.remove range4 map
        Assert.AreEqual (Some 3, IntervalMap.tryFind range3 map)
        Assert.AreEqual (Some 5, IntervalMap.tryFind range5 map)
        Assert.AreEqual (None, IntervalMap.tryFind range4 map)

    [<TestMethod>]
    [<ExpectedException(typedefof<InvalidAddrRangeException>)>]
    member __.``IntervalMap Test Removal Exception`` () =
        let range1 = AddrRange (0x100UL, 0x200UL)
        let map = IntervalMap.add range1 1 IntervalMap.empty
        IntervalMap.remove (AddrRange (0x100UL, 0x199UL)) map |> ignore
