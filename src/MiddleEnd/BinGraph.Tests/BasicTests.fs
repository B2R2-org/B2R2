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
open B2R2.MiddleEnd.BinGraph.Traversal
open B2R2.MiddleEnd.BinGraph.Tests.Examples

[<TestClass>]
type BasicTests() =
  let sum acc (v: IVertex<_>) = v.VData + acc

  let inc acc (edge: Edge<_, _>) = acc + edge.Label

  static member GraphTypes = [| [| box Persistent |]; [| box Imperative |] |]

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``DiGraph Traversal Test 1``(t) =
    let g, _ = digraph1 t
    let s1 = DFS.foldPostorder g sum 0
    let s2 = DFS.foldRevPostorder g sum 0
    let s3 = DFS.foldPreorder g sum 0
    let s4 = g.FoldVertex(sum, 0)
    let s5 = g.FoldEdge(inc, 0)
    Assert.AreEqual<int>(21, s1)
    Assert.AreEqual<int>(21, s2)
    Assert.AreEqual<int>(21, s3)
    Assert.AreEqual<int>(21, s4)
    Assert.AreEqual<int>(28, s5)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``DiGraph Traversal Test 2``(t) =
    let g, _ = digraph1 t
    let s1 =
      DFS.foldPostorder g (fun acc v -> v.VData :: acc) []
      |> List.rev |> List.toArray
    let s2 =
      DFS.foldPreorder g (fun acc v -> v.VData :: acc) []
      |> List.rev |> List.toArray
    CollectionAssert.AreEqual([| 5; 3; 4; 6; 2; 1 |], s1)
    CollectionAssert.AreEqual([| 1; 2; 3; 5; 4; 6 |], s2)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``DiGraph Traversal Test 3``(t) =
    let g, _ = digraph3 t
    let s1 =
      DFS.foldPostorder g (fun acc v -> v.VData :: acc) []
      |> List.rev |> List.toArray
    let s2 =
      DFS.foldPreorder g (fun acc v -> v.VData :: acc) []
      |> List.rev |> List.toArray
    CollectionAssert.AreEqual([| 4; 2; 5; 3; 1 |], s1)
    CollectionAssert.AreEqual([| 1; 2; 4; 3; 5 |], s2)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``DiGraph Removal Test``(t) =
    let g1, _ = digraph1 t
    let g2 = g1.Clone()
    let g2 = g2.FindVertexByData 3 |> g2.RemoveVertex
    let s1 = DFS.foldPreorder g1 sum 0
    let s2 = DFS.foldPreorder g2 sum 0
    Assert.AreEqual<int>(6, g1.Size)
    Assert.AreEqual<int>(5, g2.Size)
    Assert.AreEqual<int>(21, s1)
    Assert.AreEqual<int>(18, s2)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Graph Transposition Test``(t) =
    let g1, g1vmap = digraph1 t
    let g2 = g1.Reverse [ g1vmap[6] ]
    let s1 = DFS.foldPreorder g1 sum 0
    let s2 = DFS.foldPreorder g2 sum 0
    let lst =
      g2.FoldEdge((fun acc e -> (e.First.VData, e.Second.VData) :: acc), [])
    let edges = List.sort lst |> List.toArray
    let solution = [| (2, 1); (2, 5); (3, 2); (4, 2); (5, 3); (5, 4); (6, 2) |]
    Assert.AreEqual<int>(6, g1.Size)
    Assert.AreEqual<int>(6, g2.Size)
    Assert.AreEqual<int>(21, s1)
    Assert.AreEqual<int>(21, s2)
    CollectionAssert.AreEqual(edges, solution)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Vertex Lookup Failure Test``(t) =
    let g, _ = digraph1 t
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.FindVertexByID 42 |> ignore)
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.FindVertexByData 42 |> ignore)
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.FindVertexBy(fun v -> v.VData = 42) |> ignore)
    |> ignore
    Assert.IsNull(g.TryFindVertexByID 42 |> Option.toObj)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Single Root Lookup Test``(t) =
    let empty = emptyDigraph t
    Assert.Throws<NoRootVertexException>(fun () ->
      empty.SingleRoot |> ignore)
    |> ignore
    let g, vmap = digraph1 t
    Assert.AreEqual<int>(1, g.SingleRoot.VData)
    let multi = g.SetRoots [| vmap[1]; vmap[2] |]
    Assert.Throws<MultipleRootVerticesException>(fun () ->
      multi.SingleRoot |> ignore)
    |> ignore
    let rootless = multi.SetRoots [||]
    Assert.Throws<NoRootVertexException>(fun () ->
      rootless.SingleRoot |> ignore)
    |> ignore

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Adjacency Lookup Of Removed Vertex Test``(t) =
    let g, vmap = digraph1 t
    let v = vmap[3]
    let g = g.RemoveVertex v
    Assert.AreEqual<int>(0, (g.GetPreds v).Length)
    Assert.AreEqual<int>(0, (g.GetPredEdges v).Length)
    Assert.AreEqual<int>(0, (g.GetSuccs v).Length)
    Assert.AreEqual<int>(0, (g.GetSuccEdges v).Length)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Foreign Vertex Test``(t) =
    let g, _ = digraph1 t
    let _, vmap = digraph3 t
    let foreign = vmap[3] (* Same ID, but a vertex of another graph. *)
    Assert.AreEqual<int>(0, (g.GetPreds foreign).Length)
    Assert.AreEqual<int>(0, (g.GetPredEdges foreign).Length)
    Assert.AreEqual<int>(0, (g.GetSuccs foreign).Length)
    Assert.AreEqual<int>(0, (g.GetSuccEdges foreign).Length)
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.RemoveVertex foreign |> ignore)
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.AddRoot foreign |> ignore)
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.SetRoots [| foreign |] |> ignore)
    |> ignore
    CollectionAssert.AreEqual([| 1 |], g.GetRoots() |> Array.map (_.VData))

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Mutation With Removed Vertex Test``(t) =
    let g, vmap = digraph1 t
    let removed = vmap[3]
    let other = vmap[1]
    let g = g.RemoveVertex removed
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.AddEdge(removed, other) |> ignore)
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.AddEdge(other, removed) |> ignore)
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.RemoveEdge(removed, other) |> ignore)
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.RemoveEdge(other, removed) |> ignore)
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.RemoveVertex removed |> ignore)
    |> ignore
