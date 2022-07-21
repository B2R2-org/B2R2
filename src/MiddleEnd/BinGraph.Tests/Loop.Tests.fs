(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

namespace B2R2.MiddleEnd.BinGraph.Tests

open B2R2
open B2R2.MiddleEnd.BinGraph
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type LoopTest () =
  let v1 = V (1, (AddrRange (1UL)))
  let v2 = V (2, (AddrRange (2UL)))
  let v3 = V (3, (AddrRange (3UL)))
  let v4 = V (4, (AddrRange (4UL)))
  let v5 = V (5, (AddrRange (5UL)))
  let v6 = V (6, (AddrRange (6UL)))
  let v7 = V (7, (AddrRange (7UL)))
  let v8 = V (8, (AddrRange (8UL)))
  let v9 = V (9, (AddrRange (9UL)))
  let v10 = V (10, (AddrRange (10UL)))

  (* Graph example from Dragon Book (Fig. 9.38) *)
  let g1 = RangedDiGraph.init -1 ImperativeGraph
  let n1, g1 = DiGraph.AddVertex (g1, v1)   (* Node 1 *)
  let n2, g1 = DiGraph.AddVertex (g1, v2)   (* Node 2 *)
  let n3, g1 = DiGraph.AddVertex (g1, v3)   (* Node 3 *)
  let n4, g1 = DiGraph.AddVertex (g1, v4)   (* Node 4 *)
  let n5, g1 = DiGraph.AddVertex (g1, v5)   (* Node 5 *)
  let n6, g1 = DiGraph.AddVertex (g1, v6)   (* Node 6 *)
  let n7, g1 = DiGraph.AddVertex (g1, v7)   (* Node 7 *)
  let n8, g1 = DiGraph.AddVertex (g1, v8)   (* Node 8 *)
  let n9, g1 = DiGraph.AddVertex (g1, v9)   (* Node 9 *)
  let n10, g1 = DiGraph.AddVertex (g1, v10) (* Node 10 *)
  let g1 = DiGraph.AddEdge (g1, n1, n2, 1)
  let g1 = DiGraph.AddEdge (g1, n1, n3, 2)
  let g1 = DiGraph.AddEdge (g1, n2, n3, 3)
  let g1 = DiGraph.AddEdge (g1, n3, n4, 4)
  let g1 = DiGraph.AddEdge (g1, n4, n3, 5)
  let g1 = DiGraph.AddEdge (g1, n4, n5, 6)
  let g1 = DiGraph.AddEdge (g1, n4, n6, 7)
  let g1 = DiGraph.AddEdge (g1, n5, n7, 8)
  let g1 = DiGraph.AddEdge (g1, n6, n7, 9)
  let g1 = DiGraph.AddEdge (g1, n7, n4, 10)
  let g1 = DiGraph.AddEdge (g1, n7, n8, 11)
  let g1 = DiGraph.AddEdge (g1, n8, n3, 12)
  let g1 = DiGraph.AddEdge (g1, n8, n9, 13)
  let g1 = DiGraph.AddEdge (g1, n8, n10, 14)
  let g1 = DiGraph.AddEdge (g1, n9, n1, 15)
  let g1 = DiGraph.AddEdge (g1, n10, n7, 16)
  let g1root = n1

  [<TestMethod>]
  member __.`` Natural Loop Test ``() =
    let s =
      Loop.getNaturalLoops g1 g1root
      |> Seq.toArray

    Assert.AreEqual (5, s.Length)
    Assert.IsFalse  (s[0].Contains n9)
    Assert.IsTrue   (s[1].Contains n10)
    Assert.IsFalse  (s[2].Contains n1)
    Assert.IsTrue   (s[3].Contains n7)
    Assert.IsTrue   (s[4].Contains n8)
