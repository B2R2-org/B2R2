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

[<TestClass>]
type AddrRangeTests () =

  [<TestMethod>]
  [<ExpectedException(typedefof<RangeOverlapException>)>]
  member __.``Overlap Test 1`` () =
    let r1 = AddrRange (100UL, 199UL)
    let r2 = AddrRange (200UL, 299UL)
    let m = ARMap.empty
    let m = ARMap.add r1 1 m
    let m = ARMap.add r2 2 m
    ARMap.addRange 99UL 100UL 3 m |> ignore

  [<TestMethod>]
  [<ExpectedException(typedefof<RangeOverlapException>)>]
  member __.``Overlap Test 2`` () =
    let r1 = AddrRange (100UL, 199UL)
    let r2 = AddrRange (200UL, 299UL)
    let m = ARMap.empty
    let m = ARMap.add r1 1 m
    let m = ARMap.add r2 2 m
    ARMap.addRange 0UL 400UL 3 m |> ignore

  [<TestMethod>]
  member __.``ARMap.getOverlaps Test`` () =
    let size = 0x10UL
    let num = 0x100UL
    let sprayRange m i =
      let r = AddrRange (size * i, size * (i + 1UL) - 1UL)
      ARMap.add r None m
    let r = AddrRange (0x150UL, 0x17FUL)
    let l =
      [ 0UL .. num - 1UL ]
      |> List.fold sprayRange ARMap.empty
      |> ARMap.getOverlaps r
    let n1 = r.Count / size
    let n2 = uint64 <| List.length l
    Assert.AreEqual<uint64> (n1, n2)

  [<TestMethod>]
  member __.``Count Test `` () =
    let r = AddrRange (100UL, 200UL)
    let m = ARMap.empty
    let m = ARMap.add r 1 m
    Assert.AreEqual<int> (1, ARMap.count m)

  [<TestMethod>]
  member __.``Count Test2 `` () =
    let r1 = AddrRange (100UL, 199UL)
    let r2 = AddrRange (50UL, 99UL)
    let m = ARMap.empty
    let m = ARMap.add r1 1 m
    let m = ARMap.add r2 2 m
    Assert.AreEqual<int> (2, ARMap.count m)

  [<TestMethod>]
  member __.``Count Test3 `` () =
    let r1 = AddrRange (100UL, 199UL)
    let r2 = AddrRange (200UL, 299UL)
    let m = ARMap.empty
    let m = ARMap.add r1 1 m
    let m = ARMap.add r2 2 m
    Assert.AreEqual<int> (2, ARMap.count m)

  [<TestMethod>]
  member __.``Count Test4 `` () =
    let r1 = AddrRange (100UL, 199UL)
    let r2 = AddrRange (200UL, 299UL)
    let r3 = AddrRange (50UL, 99UL)
    let m = ARMap.empty
    let m = ARMap.add r1 1 m
    let m = ARMap.add r2 2 m
    let m = ARMap.add r3 3 m
    Assert.AreEqual<int> (3, ARMap.count m)

  [<TestMethod>]
  member __.``Singleton Test1`` () =
    let r1 = AddrRange (0UL)
    let r2 = AddrRange (1UL)
    let r3 = AddrRange (2UL)
    let m = ARMap.empty
    let m = ARMap.add r1 1 m
    let m = ARMap.add r2 2 m
    let m = ARMap.add r3 3 m
    Assert.AreEqual<int> (3, ARMap.count m)
    Assert.AreEqual<int> (2, ARMap.findByAddr 1UL m)
