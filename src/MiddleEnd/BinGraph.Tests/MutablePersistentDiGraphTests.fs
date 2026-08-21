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

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.MiddleEnd.BinGraph

[<TestClass>]
type MutablePersistentDiGraphTests() =
  let makeGraph () =
    MutablePersistentDiGraph(PersistentDiGraph<int, int>())
    :> IMutableDiGraph<int, int>

  [<TestMethod>]
  member _.``Reads The Latest Snapshot Test``() =
    let g = makeGraph ()
    let v1 = g.AddVertex 1
    let v2 = g.AddVertex 2
    g.AddEdge(v1, v2, 10)
    Assert.AreEqual<int>(2, g.Size)
    Assert.AreEqual<int>(1, g.Edges.Length)
    Assert.AreEqual<int>(10, g.FindEdge(v1, v2).Label)
    CollectionAssert.AreEqual([| v2.ID |], g.GetSuccs v1 |> Array.map (_.ID))
    g.RemoveVertex v2
    Assert.AreEqual<int>(1, g.Size)
    Assert.AreEqual<int>(0, g.Edges.Length)

  [<TestMethod>]
  member _.``Snapshot Outlives Later Modifications Test``() =
    let g = MutablePersistentDiGraph(PersistentDiGraph<int, int>())
    let ig = g :> IMutableDiGraph<int, int>
    let v1 = ig.AddVertex 1
    let v2 = ig.AddVertex 2
    let taken = g.Snapshot
    ig.AddEdge(v1, v2, 10)
    (* The graph taken before the edge was added has no edge in it, while the
       graph it was taken from has moved on. *)
    Assert.AreEqual<int>(0, taken.Edges.Length)
    Assert.AreEqual<int>(1, ig.Edges.Length)
    Assert.AreEqual<int>(2, taken.Size)
    let v3 = ig.AddVertex 3
    Assert.AreEqual<bool>(false, taken.HasVertex v3.ID)
    Assert.AreEqual<bool>(true, ig.HasVertex v3.ID)

  [<TestMethod>]
  member _.``Clone Is Independent Test``() =
    let g = makeGraph ()
    let v1 = g.AddVertex 1
    let v2 = g.AddVertex 2
    g.AddEdge(v1, v2, 10)
    let g2 = g.Clone()
    g2.RemoveVertex(g2.FindVertexByID v2.ID)
    Assert.AreEqual<int>(2, g.Size)
    Assert.AreEqual<int>(1, g2.Size)
    Assert.AreEqual<int>(1, g.Edges.Length)
    Assert.AreEqual<int>(0, g2.Edges.Length)
    (* A clone continues to number its vertices where the original left off. *)
    let v3 = g.AddVertex 3
    let v3' = g2.AddVertex 3
    Assert.AreEqual<VertexID>(v3.ID, v3'.ID)

  [<TestMethod>]
  member _.``Keeps The Graph Contract Test``() =
    let g = makeGraph ()
    let v1 = g.AddVertex 1
    let v2 = g.AddVertex 2
    g.AddEdge(v1, v2, 10)
    (* An edge that is already there does not become a second one, and the
       label of the existing edge is the one that stays. *)
    g.AddEdge(v1, v2, 99)
    Assert.AreEqual<int>(1, g.Edges.Length)
    Assert.AreEqual<int>(10, g.FindEdge(v1, v2).Label)
    (* The first vertex added becomes the root, as in any other graph. *)
    CollectionAssert.AreEqual([| v1.ID |], g.GetRoots() |> Array.map (_.ID))
    g.SetRoots [| v2 |]
    CollectionAssert.AreEqual([| v2.ID |], g.GetRoots() |> Array.map (_.ID))
    Assert.AreEqual<ImplementationType>(Persistent, g.ImplementationType)

  [<TestMethod>]
  member _.``Rejects A Foreign Vertex Test``() =
    let g = makeGraph ()
    let other = makeGraph ()
    let v = g.AddVertex 1
    let foreign = other.AddVertex 1 (* Same ID, but of another graph. *)
    Assert.AreEqual<VertexID>(v.ID, foreign.ID)
    Assert.Throws<VertexNotFoundException>(fun () -> g.RemoveVertex foreign)
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () -> g.AddEdge(v, foreign))
    |> ignore
