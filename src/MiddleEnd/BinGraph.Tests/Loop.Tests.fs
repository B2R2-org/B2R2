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

open B2R2.MiddleEnd.BinGraph
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type LoopTest () =
  (* Graph example from Dragon Book (Fig. 9.38) *)
  let g1 = ImperativeDiGraph () :> IGraph<_, _>
  let n1, g1 = g1.AddVertex 1   (* Node 1 *)
  let n2, g1 = g1.AddVertex 2   (* Node 2 *)
  let n3, g1 = g1.AddVertex 3   (* Node 3 *)
  let n4, g1 = g1.AddVertex 4   (* Node 4 *)
  let n5, g1 = g1.AddVertex 5   (* Node 5 *)
  let n6, g1 = g1.AddVertex 6   (* Node 6 *)
  let n7, g1 = g1.AddVertex 7   (* Node 7 *)
  let n8, g1 = g1.AddVertex 8   (* Node 8 *)
  let n9, g1 = g1.AddVertex 9   (* Node 9 *)
  let n10, g1 = g1.AddVertex 10 (* Node 10 *)
  let g1 = g1.AddEdge (n1, n2, EdgeLabel 1)
  let g1 = g1.AddEdge (n1, n3, EdgeLabel 2)
  let g1 = g1.AddEdge (n2, n3, EdgeLabel 3)
  let g1 = g1.AddEdge (n3, n4, EdgeLabel 4)
  let g1 = g1.AddEdge (n4, n3, EdgeLabel 5)
  let g1 = g1.AddEdge (n4, n5, EdgeLabel 6)
  let g1 = g1.AddEdge (n4, n6, EdgeLabel 7)
  let g1 = g1.AddEdge (n5, n7, EdgeLabel 8)
  let g1 = g1.AddEdge (n6, n7, EdgeLabel 9)
  let g1 = g1.AddEdge (n7, n4, EdgeLabel 10)
  let g1 = g1.AddEdge (n7, n8, EdgeLabel 11)
  let g1 = g1.AddEdge (n8, n3, EdgeLabel 12)
  let g1 = g1.AddEdge (n8, n9, EdgeLabel 13)
  let g1 = g1.AddEdge (n8, n10, EdgeLabel 14)
  let g1 = g1.AddEdge (n9, n1, EdgeLabel 15)
  let g1 = g1.AddEdge (n10, n7, EdgeLabel 16)
  let g1root = n1

  [<TestMethod>]
  member __.`` Natural Loop Test ``() =
    let s =
      Loop.getNaturalLoops g1 g1root
      |> Seq.toArray
    Assert.AreEqual (5, s.Length)
    Assert.IsFalse (s[0].Contains n9)
    Assert.IsTrue (s[1].Contains n10)
    Assert.IsFalse (s[2].Contains n1)
    Assert.IsTrue (s[3].Contains n7)
    Assert.IsTrue (s[4].Contains n8)
