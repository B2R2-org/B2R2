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

open System.Collections.Generic
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinGraph.Traversal
open B2R2.MiddleEnd.BinGraph.Tests.Examples

[<TestClass>]
type BasicTests() =
  let sum acc (v: IVertex<_>) = v.VData + acc

  let inc acc (edge: Edge<_, _>) = acc + edge.Label

  (* Copying is the mutable implementation's own operation rather than one of
     the graph protocols, so a test of it reaches past the interface the
     examples are built against. *)
  let cloneOf (g: IMutableDiGraph<int, int>) =
    (g :?> MutableDiGraph<int, int>).Clone() :> IMutableDiGraph<int, int>

  static member GraphTypes = [| [| box Persistent |]; [| box Mutable |] |]

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``DiGraph Traversal Test 1``(t) =
    let g, _ = digraph1 t
    let s1 = DFS.foldPostorder g sum 0
    let s2 = DFS.foldRevPostorder g sum 0
    let s3 = DFS.foldPreorder g sum 0
    let s4 = g |> DiGraph.foldVertex sum 0
    let s5 = g |> DiGraph.foldEdge inc 0
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
    let g2, _ = digraph1 t
    g2.FindVertexByData 3 |> g2.RemoveVertex
    let s1 = DFS.foldPreorder g1 sum 0
    let s2 = DFS.foldPreorder g2 sum 0
    Assert.AreEqual<int>(6, g1.VertexCount)
    Assert.AreEqual<int>(5, g2.VertexCount)
    Assert.AreEqual<int>(21, s1)
    Assert.AreEqual<int>(18, s2)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Reverse Reads One State Test``(t) =
    let g, vmap = digraph1 t
    let r = g.Reverse [ vmap[6] ]
    let succIDs () =
      r.GetSuccs vmap[2] |> Array.map (fun v -> v.ID) |> Array.sort
    CollectionAssert.AreEqual([| 1; 5 |], succIDs ())
    (* A transpose reads the state the graph was in when it was taken, so what
       becomes of the graph afterwards is no concern of its. Its edges are made
       only once asked for, and they follow the same state, not a later one. *)
    g.RemoveEdge(vmap[1], vmap[2])
    CollectionAssert.AreEqual([| 1; 5 |], succIDs ())
    Assert.AreEqual<int>(7, r.EdgeCount)
    Assert.AreEqual<int>(7, r.Edges.Length)
    Assert.AreEqual<int>(6, g.EdgeCount)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Double Transposition Test``(t) =
    let g, vmap = digraph1 t
    let r = (g.Reverse [ vmap[6] ]).Reverse [ vmap[1] ]
    (* The transpose of a transpose spans the pairs the graph spans, and it
       spans them with the very edges of that graph, a pair turned around
       twice being the pair it was. *)
    let succIDs = r.GetSuccs vmap[2] |> Array.map (_.ID) |> Array.sort
    CollectionAssert.AreEqual([| 3; 4; 6 |], succIDs)
    Assert.AreSame(vmap[2], r.FindVertexByData 2)
    Assert.AreSame(g.FindEdge(vmap[1], vmap[2]),
                   r.FindEdge(vmap[1], vmap[2]))
    Assert.AreEqual<int>(7, r.EdgeCount)
    CollectionAssert.AreEqual([| 1 |], r.Roots |> Array.map (_.ID))
    (* It is not that graph, though, and it cannot be: it takes its roots
       anew, and it answers for the state the graph was in when the first
       transpose was taken, not for a later one. *)
    Assert.AreNotSame(box g, box r)
    g.RemoveEdge(vmap[1], vmap[2])
    Assert.AreEqual<int>(7, r.EdgeCount)
    Assert.AreEqual<int>(6, g.EdgeCount)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Induced Subgraph View Test``(t) =
    let g, vmap = digraph1 t
    (* Of the seven edges, the three among 2, 3 and 5 are the ones this set
       induces: 2 -> 3, 3 -> 5 and 5 -> 2. *)
    let vs = [| vmap[2]; vmap[3]; vmap[5] |]
    let sub = SubDiGraph(g, vs, [| vmap[2] |]) :> IDiGraph<int, int>
    Assert.AreEqual<int>(3, sub.VertexCount)
    Assert.AreEqual<int>(3, sub.EdgeCount)
    Assert.AreEqual<int>(3, sub.Edges.Length)
    CollectionAssert.AreEqual([| 3 |], sub.GetSuccs vmap[2] |> Array.map (_.ID))
    CollectionAssert.AreEqual([| 5 |], sub.GetPreds vmap[2] |> Array.map (_.ID))
    (* The vertices and the edges are the very ones of the graph it views. *)
    Assert.AreEqual<bool>(true, sub.Contains vmap[3])
    Assert.AreSame(g.FindEdge(vmap[2], vmap[3]),
                   sub.FindEdge(vmap[2], vmap[3]))
    (* A vertex the set leaves out is no vertex of this graph. *)
    Assert.AreEqual<bool>(false, sub.Contains vmap[1])
    Assert.AreEqual<int>(0, (sub.GetSuccs vmap[1]).Length)
    Assert.AreEqual<bool>(false, sub.HasEdge(vmap[2], vmap[4]))
    (* It reads the state the graph was in when it was taken. *)
    g.RemoveEdge(vmap[2], vmap[3])
    Assert.AreEqual<int>(3, sub.EdgeCount)
    Assert.AreEqual<int>(6, g.EdgeCount)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Graph Transposition Test``(t) =
    let g1, g1vmap = digraph1 t
    let g2 = g1.Reverse [ g1vmap[6] ]
    let s1 = DFS.foldPreorder g1 sum 0
    let s2 = DFS.foldPreorder g2 sum 0
    let lst =
      g2 |> DiGraph.foldEdge (fun acc e ->
        (e.First.VData, e.Second.VData) :: acc) []
    let edges = List.sort lst |> List.toArray
    let solution = [| (2, 1); (2, 5); (3, 2); (4, 2); (5, 3); (5, 4); (6, 2) |]
    Assert.AreEqual<int>(6, g1.VertexCount)
    Assert.AreEqual<int>(6, g2.VertexCount)
    Assert.AreEqual<int>(21, s1)
    Assert.AreEqual<int>(21, s2)
    CollectionAssert.AreEqual(edges, solution)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Vertex Lookup Failure Test``(t) =
    let g, _ = digraph1 t
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.FindVertexByData 42 |> ignore)
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.FindVertexBy(fun v -> v.VData = 42) |> ignore)
    |> ignore
    Assert.IsNull(g.TryFindVertexBy(fun v -> v.VData = 42) |> Option.toObj)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Reserved Vertex ID Test``(t) =
    let g = emptyDigraph t
    Assert.Throws<System.ArgumentException>(fun () ->
      g.AddVertex(1, -1) |> ignore)
    |> ignore
    Assert.AreEqual<int>(0, g.VertexCount)
    let v = g.AddVertex(1, 42)
    Assert.AreEqual<int>(42, v.ID)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Duplicate Vertex ID Test``(t) =
    let g = emptyDigraph t
    let v1 = g.AddVertex(1, 7)
    let v2 = g.AddVertex(2, 8)
    g.AddEdge(v1, v2, 1)
    Assert.Throws<System.ArgumentException>(fun () ->
      g.AddVertex(3, 8) |> ignore)
    |> ignore
    Assert.Throws<System.ArgumentException>(fun () ->
      g.AddVertexCopy v2 |> ignore)
    |> ignore
    (* A rejected vertex leaves the graph as it was, so the vertex it would
       have taken the place of is still the one the edge into it leads to. *)
    Assert.AreEqual<int>(2, g.VertexCount)
    Assert.AreEqual<int>(1, g.EdgeCount)
    Assert.AreEqual<bool>(true, g.Contains v2)
    CollectionAssert.AreEqual([| v2 |], g.GetSuccs v1)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Dummy Vertex ToString Test``(t) =
    let g = emptyDigraph t
    let v1 = g.AddVertex 1
    let v2 = g.AddVertex()
    Assert.AreEqual<string>("Vertex(1)", v1.ToString())
    Assert.AreEqual<string>($"Vertex(#{v2.ID})", v2.ToString())

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Single Root Lookup Test``(t) =
    let empty = emptyDigraph t
    Assert.Throws<NoRootVertexException>(fun () ->
      empty.SingleRoot |> ignore)
    |> ignore
    let g, vmap = digraph1 t
    Assert.AreEqual<int>(1, g.SingleRoot.VData)
    g.SetRoots [| vmap[1]; vmap[2] |]
    Assert.Throws<MultipleRootVerticesException>(fun () ->
      g.SingleRoot |> ignore)
    |> ignore
    g.SetRoots [||]
    Assert.Throws<NoRootVertexException>(fun () ->
      g.SingleRoot |> ignore)
    |> ignore

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Derived Graph Vertex Lookup Test``(t) =
    (* A subgraph view and a transpose answer a lookup out of the vertices
       they hold, which are not the vertices of the graph they were taken
       from. *)
    let g, vmap = digraph1 t
    let vs = [| vmap[2]; vmap[3]; vmap[5] |]
    let sub = SubDiGraph(g, vs, [| vmap[2] |]) :> IDiGraph<int, int>
    Assert.AreSame(vmap[2], sub.SingleRoot)
    Assert.AreSame(vmap[3], sub.FindVertexByData 3)
    Assert.AreSame(vmap[5], sub.FindVertexBy(fun v -> v.VData = 5))
    Assert.IsNull(sub.TryFindVertexByData 1 |> Option.toObj)
    Assert.IsNull(sub.TryFindVertexBy(fun v -> v.VData = 1) |> Option.toObj)
    Assert.Throws<VertexNotFoundException>(fun () ->
      sub.FindVertexByData 1 |> ignore)
    |> ignore
    Assert.Throws<NoRootVertexException>(fun () ->
      (SubDiGraph(g, vs, [||]) :> IDiGraph<int, int>).SingleRoot |> ignore)
    |> ignore
    let rev = g.Reverse [ vmap[3]; vmap[5] ]
    Assert.AreSame(vmap[1], rev.FindVertexByData 1)
    Assert.IsNull(rev.TryFindVertexByData 42 |> Option.toObj)
    Assert.Throws<MultipleRootVerticesException>(fun () ->
      rev.SingleRoot |> ignore)
    |> ignore
    Assert.AreSame(vmap[3], (g.Reverse [ vmap[3] ]).SingleRoot)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Adjacency Lookup Of Removed Vertex Test``(t) =
    let g, vmap = digraph1 t
    let v = vmap[3]
    g.RemoveVertex v
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
    (* Membership is of the vertex, not of the ID it carries. *)
    Assert.AreEqual<bool>(false, g.Contains foreign)
    Assert.AreEqual<int>(0, (g.GetPreds foreign).Length)
    Assert.AreEqual<int>(0, (g.GetPredEdges foreign).Length)
    Assert.AreEqual<int>(0, (g.GetSuccs foreign).Length)
    Assert.AreEqual<int>(0, (g.GetSuccEdges foreign).Length)
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.RemoveVertex foreign)
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.AddRoot foreign)
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.SetRoots [| foreign |])
    |> ignore
    CollectionAssert.AreEqual([| 1 |], g.Roots |> Array.map (_.VData))

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Edge Count Test``(t) =
    (* The persistent graph carries its edge count along rather than walking
       the adjacency lists for it, so every operation has to hand on the count
       it leaves behind. *)
    let g, vmap = digraph1 t
    let check () = Assert.AreEqual<int>(g.Edges.Length, g.EdgeCount)
    check ()
    g.AddEdge(vmap[1], vmap[3], 99)
    check ()
    g.AddEdge(vmap[1], vmap[3], 100)
    check ()
    g.RemoveEdge(vmap[1], vmap[3])
    check ()
    g.RemoveEdge(vmap[1], vmap[3])
    check ()
    g.AddEdge(vmap[2], vmap[2], 101)
    check ()
    g.RemoveVertex vmap[2]
    check ()
    Assert.AreEqual<int>(0, (emptyDigraph t).EdgeCount)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Vertex Identity Test``(t) =
    (* A vertex is the object it is: a graph hands out the very same object
       every time, and the vertex of another graph that carries the same ID is
       another vertex. Hashing still goes by the ID, so the two of them do
       land in one bucket. *)
    let _, vmap1 = digraph1 t
    let _, vmap2 = digraph1 t
    let v1, v2 = vmap1[2], vmap2[2]
    Assert.AreEqual<VertexID>(v1.ID, v2.ID)
    Assert.AreNotEqual<IVertex<int>>(v1, v2)
    Assert.AreEqual<int>(v1.GetHashCode(), v2.GetHashCode())
    let dict = Dictionary<IVertex<int>, int>()
    dict[v1] <- 1
    Assert.AreEqual<bool>(false, dict.ContainsKey v2)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Own Vertex Identity Test``(t) =
    let g, vmap = digraph1 t
    let v = vmap[2]
    Assert.AreSame(v, g.FindVertexBy(fun w -> w.VData = 2))
    Assert.AreEqual<bool>(true, g.Contains v)
    (* A transpose holds the very vertices of the graph it was taken from, so
       a post-dominance query has nothing to look up to cross over to it. *)
    let r = g.Reverse [ v ]
    Assert.AreEqual<bool>(true, r.Contains v)
    Assert.AreSame(v, r.FindVertexBy(fun w -> w.VData = 2))

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Edge Equality Test``(t) =
    (* An edge is the ordered pair of its endpoints and nothing else, so a
       freshly made edge naming a pair of this graph's vertices is the edge
       that spans them, whatever label either of the two carries. *)
    let g1, vmap1 = digraph1 t
    let e1 = g1.FindEdge(vmap1[1], vmap1[2])
    let named = Edge<int, int>(vmap1[1], vmap1[2], null)
    Assert.AreNotSame(e1, named)
    Assert.AreEqual<Edge<int, int>>(e1, named)
    let dict = Dictionary<Edge<int, int>, int>()
    dict[e1] <- 1
    Assert.AreEqual<int>(1, dict[named])
    g1.RemoveEdge(vmap1[1], vmap1[2])
    g1.AddEdge(vmap1[1], vmap1[2], 99)
    Assert.AreEqual<Edge<int, int>>(e1, g1.FindEdge(vmap1[1], vmap1[2]))
    Assert.AreNotEqual<Edge<int, int>>(e1, g1.FindEdge(vmap1[2], vmap1[3]))

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Foreign Edge Equality Test``(t) =
    (* An endpoint is the object it is, so the edge of another graph that spans
       a pair carrying the same IDs is another edge. *)
    let g1, vmap1 = digraph1 t
    let g2, vmap2 = digraph1 t
    let e1 = g1.FindEdge(vmap1[1], vmap1[2])
    let e2 = g2.FindEdge(vmap2[1], vmap2[2])
    Assert.AreEqual<VertexID>(e1.First.ID, e2.First.ID)
    Assert.AreEqual<VertexID>(e1.Second.ID, e2.Second.ID)
    Assert.AreNotEqual<Edge<int, int>>(e1, e2)
    let dict = Dictionary<Edge<int, int>, int>()
    dict[e1] <- 1
    Assert.AreEqual<bool>(false, dict.ContainsKey e2)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Foreign Edge Test``(t) =
    let g, gmap = digraph1 t
    let _, vmap = digraph3 t
    (* The two carry the IDs of an edge this graph does have, yet they are the
       vertices of another graph. *)
    let src, dst = vmap[1], vmap[2]
    Assert.AreEqual<bool>(true, g.HasEdge(gmap[1], gmap[2]))
    Assert.AreEqual<bool>(false, g.HasEdge(src, dst))
    Assert.AreEqual<bool>(true, (g.TryFindEdge(src, dst)).IsNone)
    Assert.Throws<EdgeNotFoundException>(fun () ->
      g.FindEdge(src, dst) |> ignore)
    |> ignore

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Mutation With Removed Vertex Test``(t) =
    let g, vmap = digraph1 t
    let removed = vmap[3]
    let other = vmap[1]
    g.RemoveVertex removed
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.AddEdge(removed, other))
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.AddEdge(other, removed))
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.RemoveEdge(removed, other))
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.RemoveEdge(other, removed))
    |> ignore
    Assert.Throws<VertexNotFoundException>(fun () ->
      g.RemoveVertex removed)
    |> ignore

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Duplicate Edge Test``(t) =
    let g, vmap = digraph1 t
    let src, dst = vmap[1], vmap[2]
    (* Adding an edge that is already there is a no-op; the label of the
       existing edge is kept, too. *)
    g.AddEdge(src, dst, 99)
    Assert.AreEqual<int>(7, g.Edges.Length)
    Assert.AreEqual<int>(28, g |> DiGraph.foldEdge inc 0)
    Assert.AreEqual<int>(1, (g.GetSuccEdges src).Length)
    Assert.AreEqual<int>(2, (g.GetPredEdges dst).Length)
    Assert.AreEqual<int>(1, g.FindEdge(src, dst).Label)

  [<TestMethod>]
  member _.``Clone Preservation Test``() =
    let g1, vmap = digraph1 Mutable
    g1.SetRoots [| vmap[1]; vmap[4] |]
    let g2 = cloneOf g1
    let vertexIDs (g: IDiGraph<_, _>) =
      g.Vertices |> Array.map (fun v -> v.ID, v.VData) |> Array.sort
    let rootIDs (g: IDiGraph<_, _>) =
      g.Roots |> Array.map (fun v -> v.ID)
    let edgeTriples (g: IDiGraph<_, _>) =
      g.Edges
      |> Array.map (fun e -> e.First.ID, e.Second.ID, e.Label)
      |> Array.sort
    CollectionAssert.AreEqual(vertexIDs g1, vertexIDs g2)
    CollectionAssert.AreEqual(rootIDs g1, rootIDs g2)
    CollectionAssert.AreEqual(edgeTriples g1, edgeTriples g2)
    (* A clone continues to number its vertices where the original left off. *)
    let v1 = g1.AddVertex 7
    let v2 = g2.AddVertex 7
    Assert.AreEqual<VertexID>(v1.ID, v2.ID)

  [<TestMethod>]
  member _.``Clone Dummy Test``() =
    let g = emptyDigraph Mutable
    let v1 = g.AddVertex 1
    let v2 = g.AddVertex()
    g.AddEdge(v1, v2)
    let g2 = cloneOf g
    let v1 = g2.FindVertexBy(fun v -> v.HasData)
    let v2 = g2.FindVertexBy(fun v -> not v.HasData)
    Assert.AreEqual<int>(1, v1.VData)
    Assert.AreEqual<bool>(false, (g2.FindEdge(v1, v2)).HasLabel)

  [<TestMethod>]
  member _.``Clone Adjacency Order Test``() =
    let g, vmap = digraph1 Mutable
    (* Re-adding an edge moves it to the end of the adjacency lists of its
       endpoints, and a clone has to follow that order, too. *)
    g.RemoveEdge(vmap[2], vmap[3])
    g.AddEdge(vmap[2], vmap[3], 2)
    g.RemoveEdge(vmap[3], vmap[5])
    g.AddEdge(vmap[3], vmap[5], 5)
    let g2 = cloneOf g
    let succIDs (g: IDiGraph<_, _>) v =
      g.GetSuccs v |> Array.map (fun s -> s.ID)
    let predIDs (g: IDiGraph<_, _>) v =
      g.GetPreds v |> Array.map (fun p -> p.ID)
    CollectionAssert.AreEqual([| 4; 6; 3 |], succIDs g vmap[2])
    CollectionAssert.AreEqual([| 4; 3 |], predIDs g vmap[5])
    let byName (g: IDiGraph<_, _>) =
      g.Vertices |> Array.sortBy (fun v -> v.ID)
    Array.iter2 (fun v v2 ->
      CollectionAssert.AreEqual(succIDs g v, succIDs g2 v2)
      CollectionAssert.AreEqual(predIDs g v, predIDs g2 v2)) (byName g)
                                                             (byName g2)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Adjacency Edge Order Test``(t) =
    let g, _ = digraph1 t
    (* The edges of a vertex come in the order its neighbors do, so that a
       caller can read one accessor against the other. *)
    let succIDs (g: IDiGraph<_, _>) v =
      g.GetSuccs v |> Array.map (fun s -> s.ID)
    let succEdgeIDs (g: IDiGraph<_, _>) v =
      g.GetSuccEdges v |> Array.map (fun e -> e.Second.ID)
    let predIDs (g: IDiGraph<_, _>) v =
      g.GetPreds v |> Array.map (fun p -> p.ID)
    let predEdgeIDs (g: IDiGraph<_, _>) v =
      g.GetPredEdges v |> Array.map (fun e -> e.First.ID)
    for v in g.Vertices do
      CollectionAssert.AreEqual(succIDs g v, succEdgeIDs g v)
      CollectionAssert.AreEqual(predIDs g v, predEdgeIDs g v)

  [<TestMethod>]
  [<DynamicData(nameof BasicTests.GraphTypes)>]
  member _.``Reverse Dummy Test``(t) =
    let g = emptyDigraph t
    let v1 = g.AddVertex 1
    let v2 = g.AddVertex()
    g.AddEdge(v1, v2)
    let r = g.Reverse [ v2 ]
    let e = r.FindEdge(v2, v1)
    Assert.AreEqual<bool>(true, v1.HasData)
    Assert.AreEqual<bool>(false, v2.HasData)
    Assert.AreEqual<bool>(false, e.HasLabel)
    CollectionAssert.AreEqual([| v2.ID |], r.Roots |> Array.map (_.ID))
