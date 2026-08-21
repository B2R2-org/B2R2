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

/// Checks the protocol of a persistent graph, in which a modification leaves
/// the graph it was asked of untouched and returns a new one. Every other test
/// of this project goes through `IMutableDiGraph`, so this is what keeps the
/// protocol itself honest.
[<TestClass>]
type PersistentDiGraphTests() =
  let empty () = PersistentDiGraph<int, int>() :> IPersistentDiGraph<int, int>

  (* Builds 1 -> 2 -> 3, handing back the vertices along with the graph. Note
     that the vertices come from earlier snapshots, which the result shares. *)
  let build () =
    let g = empty ()
    let v1, g = g.AddVertex 1
    let v2, g = g.AddVertex 2
    let v3, g = g.AddVertex 3
    let g = g.AddEdge(v1, v2, 12)
    let g = g.AddEdge(v2, v3, 23)
    g, v1, v2, v3

  let ids (g: IDiGraphAccessible<_, _>) =
    g.Vertices |> Array.map (_.ID) |> Array.sort

  let edgeTriples (g: IDiGraphAccessible<_, _>) =
    g.Edges
    |> Array.map (fun e -> e.First.ID, e.Second.ID, e.Label)
    |> Array.sort

  let rootIDs (g: IDiGraphAccessible<_, _>) =
    g.GetRoots() |> Array.map (_.ID)

  [<TestMethod>]
  member _.``Modification Leaves The Original Intact Test``() =
    let g, v1, _, v3 = build ()
    let withoutEdge = g.RemoveEdge(v1, g.FindVertexByID 2)
    Assert.AreEqual<int>(2, g.Edges.Length)
    Assert.AreEqual<int>(1, withoutEdge.Edges.Length)
    let withoutVertex = g.RemoveVertex v3
    Assert.AreEqual<int>(3, g.Size)
    Assert.AreEqual<int>(2, withoutVertex.Size)
    Assert.AreEqual<bool>(true, g.Contains v3)
    Assert.AreEqual<bool>(false, withoutVertex.Contains v3)

  [<TestMethod>]
  member _.``A New Vertex Belongs To The New Graph Only Test``() =
    let g = empty ()
    let v, g' = g.AddVertex 1
    Assert.AreEqual<int>(0, g.Size)
    Assert.AreEqual<bool>(false, g.Contains v)
    Assert.AreEqual<int>(1, g'.Size)
    Assert.AreEqual<bool>(true, g'.Contains v)

  [<TestMethod>]
  member _.``Two Branches Of One Snapshot Are Independent Test``() =
    let g, v1, _, v3 = build ()
    let branch1 = g.AddEdge(v1, v3, 13)
    let branch2 = g.RemoveVertex v3
    Assert.AreEqual<int>(3, g.Size)
    Assert.AreEqual<int>(2, g.Edges.Length)
    Assert.AreEqual<int>(3, branch1.Size)
    Assert.AreEqual<int>(3, branch1.Edges.Length)
    Assert.AreEqual<int>(2, branch2.Size)
    Assert.AreEqual<int>(1, branch2.Edges.Length)

  [<TestMethod>]
  member _.``Roots Of The Original Stay Put Test``() =
    let g, v1, v2, _ = build ()
    let rerooted = g.SetRoots [| v2 |]
    CollectionAssert.AreEqual([| v1.ID |], rootIDs g)
    CollectionAssert.AreEqual([| v2.ID |], rootIDs rerooted)
    let tworooted = g.AddRoot v2
    Assert.AreEqual<int>(1, (rootIDs g).Length)
    Assert.AreEqual<int>(2, (rootIDs tworooted).Length)

  [<TestMethod>]
  member _.``Duplicate Edge Test``() =
    let g, v1, v2, _ = build ()
    let g' = g.AddEdge(v1, v2, 99)
    (* The edge is already there, so this changes nothing, and the label of the
       existing edge is the one that stays. *)
    Assert.AreEqual<int>(2, g'.Edges.Length)
    Assert.AreEqual<int>(12, g'.FindEdge(v1, v2).Label)

  [<TestMethod>]
  member _.``Reverse Keeps The Graph Persistent Test``() =
    let g, v1, v2, v3 = build ()
    let r = g.Reverse [ v3 ]
    Assert.AreEqual<bool>(true, r :? IPersistentDiGraph<int, int>)
    Assert.AreEqual<ImplementationType>(Persistent, r.ImplementationType)
    CollectionAssert.AreEqual([| v3.ID |], rootIDs r)
    CollectionAssert.AreEqual([| (2, 1, 12); (3, 2, 23) |], edgeTriples r)
    CollectionAssert.AreEqual([| (1, 2, 12); (2, 3, 23) |], edgeTriples g)
    Assert.AreEqual<bool>(true, (g.FindEdge(v1, v2)).HasLabel)

  [<TestMethod>]
  member _.``Threading Matches Going Through A Mutable Graph Test``() =
    let threaded, _, _, _ = build ()
    let mg = MutablePersistentDiGraph(PersistentDiGraph<int, int>())
    let img = mg :> IMutableDiGraph<int, int>
    let w1 = img.AddVertex 1
    let w2 = img.AddVertex 2
    let w3 = img.AddVertex 3
    img.AddEdge(w1, w2, 12)
    img.AddEdge(w2, w3, 23)
    let byMutable = mg.Snapshot
    CollectionAssert.AreEqual(ids threaded, ids byMutable)
    CollectionAssert.AreEqual(edgeTriples threaded, edgeTriples byMutable)
    CollectionAssert.AreEqual(rootIDs threaded, rootIDs byMutable)
