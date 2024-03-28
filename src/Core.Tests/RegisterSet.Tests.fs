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
open System.Collections.Generic
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2

[<TestClass>]
type RegisterSetTests () =

  [<TestMethod>]
  member __.``Size Test 1`` () =
    let s = RegisterSet (64)
    Assert.AreEqual (64, s.MaxNumElems)
    Assert.AreEqual (1, s.BitArray.Length)

  [<TestMethod>]
  member __.``Size Test 2`` () =
    let s = RegisterSet (65)
    Assert.AreEqual (65, s.MaxNumElems)
    Assert.AreEqual (2, s.BitArray.Length)

  [<TestMethod>]
  member __.``Add Test 1`` () =
    let s = RegisterSet (65)
    let lst = List<int> ()
    s.Add 0
    s.Add 8
    s.Add 42
    s.Add 64
    s.Iterate (lst.Add >> ignore)
    CollectionAssert.AreEqual ([| 0; 8; 42; 64|], lst)

  [<TestMethod>]
  [<ExpectedException(typedefof<IndexOutOfRangeException>)>]
  member __.``Add Test 2`` () =
    let s = RegisterSet (65)
    s.Add 65

  [<TestMethod>]
  member __.``Add/Remove Test`` () =
    let s = RegisterSet (65)
    let lst = List<int> ()
    s.Add 0
    s.Add 8
    s.Add 42
    s.Add 64
    s.Remove 0
    s.Remove 42
    s.Remove 64
    s.Iterate (lst.Add >> ignore)
    CollectionAssert.AreEqual ([| 8 |], lst)

