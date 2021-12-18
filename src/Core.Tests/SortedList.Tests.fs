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

[<TestClass>]
type SortedListTests () =

  let lst = SortedList<int, int> ()
  do lst[100] <- 1
     lst[200] <- 2
     lst[300] <- 3
     lst[400] <- 4

  [<TestMethod>]
  member __.``GLB`` () =
    let actual = SortedList.findGreatestLowerBoundKey 250 lst |> Option.get
    Assert.AreEqual (200, actual)
    let actual = SortedList.findGreatestLowerBoundKey 101 lst |> Option.get
    Assert.AreEqual (100, actual)
    let actual = SortedList.findGreatestLowerBoundKey 450 lst |> Option.get
    Assert.AreEqual (400, actual)

  [<TestMethod>]
  member __.``LUB`` () =
    let actual = SortedList.findLeastUpperBoundKey 250 lst |> Option.get
    Assert.AreEqual (300, actual)
    let actual = SortedList.findLeastUpperBoundKey 350 lst |> Option.get
    Assert.AreEqual (400, actual)
    let actual = SortedList.findLeastUpperBoundKey 99 lst |> Option.get
    Assert.AreEqual (100, actual)

  [<TestMethod>]
  member __.``Boundary Conditions`` () =
    Assert.IsTrue
      <| (SortedList.findGreatestLowerBoundKey 0 lst |> Option.isNone)
    Assert.IsTrue
      <| (SortedList.findGreatestLowerBoundKey 100 lst |> Option.isNone)
    Assert.IsTrue
      <| (SortedList.findLeastUpperBoundKey 400 lst |> Option.isNone)
    Assert.IsTrue
      <| (SortedList.findLeastUpperBoundKey 500 lst |> Option.isNone)
