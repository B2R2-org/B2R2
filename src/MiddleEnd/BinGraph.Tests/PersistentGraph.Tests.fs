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
type BasicPersistentGraphTest () =
  let v1 = V (1, (AddrRange (1UL, 2UL)))
  let v2 = V (2, (AddrRange (2UL, 3UL)))
  let v3 = V (3, (AddrRange (3UL, 4UL)))
  let v4 = V (4, (AddrRange (4UL, 5UL)))
  let v5 = V (5, (AddrRange (5UL, 6UL)))
  let v6 = V (6, (AddrRange (6UL, 7UL)))
  let v7 = V (7, (AddrRange (7UL, 8UL)))
  let v8 = V (8, (AddrRange (8UL, 9UL)))
  let v9 = V (9, (AddrRange (9UL, 10UL)))
  let v10 = V (10, (AddrRange (10UL, 11UL)))
  let v11 = V (11, (AddrRange (11UL, 12UL)))
  let v12 = V (12, (AddrRange (12UL, 13UL)))
  let v13 = V (13, (AddrRange (13UL, 14UL)))

  (* Graph example from Wikipedia. *)
  let g1 = RangedDiGraph.init -1 PersistentGraph
  let n1, g1 = DiGraph.addVertex g1 v1 // Node 1
  let n2, g1 = DiGraph.addVertex g1 v2 // Node 2
  let n3, g1 = DiGraph.addVertex g1 v3 // Node 3
  let n4, g1 = DiGraph.addVertex g1 v4 // Node 4
  let n5, g1 = DiGraph.addVertex g1 v5 // Node 5
  let n6, g1 = DiGraph.addVertex g1 v6 // Node 6
  let g1 = DiGraph.addEdge g1 n1 n2 1
  let g1 = DiGraph.addEdge g1 n2 n3 2
  let g1 = DiGraph.addEdge g1 n2 n4 3
  let g1 = DiGraph.addEdge g1 n2 n6 4
  let g1 = DiGraph.addEdge g1 n3 n5 5
  let g1 = DiGraph.addEdge g1 n4 n5 6
  let g1 = DiGraph.addEdge g1 n5 n2 7
  let g1root = n1
  let ctxt1 = Dominator.initDominatorContext g1 g1root

  (* Graph example from Tiger book. *)
  let g2 = RangedDiGraph.init -1 PersistentGraph
  let n1, g2 = DiGraph.addVertex g2 v1 // Node 1
  let n2, g2 = DiGraph.addVertex g2 v2 // Node 2
  let n3, g2 = DiGraph.addVertex g2 v3 // Node 3
  let n4, g2 = DiGraph.addVertex g2 v4 // Node 4
  let n5, g2 = DiGraph.addVertex g2 v5 // Node 5
  let n6, g2 = DiGraph.addVertex g2 v6 // Node 6
  let g2 = DiGraph.addEdge g2 n1 n2 1
  let g2 = DiGraph.addEdge g2 n1 n3 2
  let g2 = DiGraph.addEdge g2 n3 n4 3
  let g2 = DiGraph.addEdge g2 n4 n5 4
  let g2 = DiGraph.addEdge g2 n4 n6 5
  let g2 = DiGraph.addEdge g2 n6 n4 6
  let g2root = n1
  let ctxt2 = Dominator.initDominatorContext g2 g2root

  (* Arbitrary graph example *)
  let g3 = RangedDiGraph.init -1 PersistentGraph
  let n1, g3 = DiGraph.addVertex g3 v1 // Node 1
  let n2, g3 = DiGraph.addVertex g3 v2 // Node 2
  let n3, g3 = DiGraph.addVertex g3 v3 // Node 3
  let n4, g3 = DiGraph.addVertex g3 v4 // Node 4
  let n5, g3 = DiGraph.addVertex g3 v5 // Node 5
  let g3 = DiGraph.addEdge g3 n1 n2 1
  let g3 = DiGraph.addEdge g3 n1 n3 2
  let g3 = DiGraph.addEdge g3 n2 n4 3
  let g3 = DiGraph.addEdge g3 n3 n4 4
  let g3 = DiGraph.addEdge g3 n3 n5 5
  let g3root = n1
  let ctxt3 = Dominator.initDominatorContext g3 g3root

  (* Graph example from Tiger book (Fig. 19.5) *)
  let g4 = RangedDiGraph.init -1 PersistentGraph
  let n1, g4 = DiGraph.addVertex g4 v1
  let n2, g4 = DiGraph.addVertex g4 v2
  let n3, g4 = DiGraph.addVertex g4 v3
  let n4, g4 = DiGraph.addVertex g4 v4
  let n5, g4 = DiGraph.addVertex g4 v5
  let n6, g4 = DiGraph.addVertex g4 v6
  let n7, g4 = DiGraph.addVertex g4 v7
  let n8, g4 = DiGraph.addVertex g4 v8
  let n9, g4 = DiGraph.addVertex g4 v9
  let n10, g4 = DiGraph.addVertex g4 v10
  let n11, g4 = DiGraph.addVertex g4 v11
  let n12, g4 = DiGraph.addVertex g4 v12
  let n13, g4 = DiGraph.addVertex g4 v13
  let g4 = DiGraph.addEdge g4 n1 n2 1
  let g4 = DiGraph.addEdge g4 n1 n5 2
  let g4 = DiGraph.addEdge g4 n1 n9 3
  let g4 = DiGraph.addEdge g4 n2 n3 4
  let g4 = DiGraph.addEdge g4 n3 n3 5
  let g4 = DiGraph.addEdge g4 n3 n4 6
  let g4 = DiGraph.addEdge g4 n4 n13 7
  let g4 = DiGraph.addEdge g4 n5 n6 8
  let g4 = DiGraph.addEdge g4 n5 n7 9
  let g4 = DiGraph.addEdge g4 n6 n4 10
  let g4 = DiGraph.addEdge g4 n6 n8 11
  let g4 = DiGraph.addEdge g4 n7 n8 12
  let g4 = DiGraph.addEdge g4 n7 n12 13
  let g4 = DiGraph.addEdge g4 n8 n5 14
  let g4 = DiGraph.addEdge g4 n8 n13 15
  let g4 = DiGraph.addEdge g4 n9 n10 16
  let g4 = DiGraph.addEdge g4 n9 n11 17
  let g4 = DiGraph.addEdge g4 n10 n12 18
  let g4 = DiGraph.addEdge g4 n11 n12 19
  let g4 = DiGraph.addEdge g4 n12 n13 20
  let g4root = n1
  let ctxt4 = Dominator.initDominatorContext g4 g4root

  let getVertexVal (v: Vertex<V> option) = (Option.get v).VData.Val

  let sum acc (v: Vertex<V>) = v.VData.Val + acc
  let inc acc _v1 _v2 e = acc + e

  [<TestMethod>]
  member __.``RangedDiGraph Traversal Test 1``() =
    let s1 = Traversal.foldPostorder g1 [g1root] sum 0
    let s2 = Traversal.foldRevPostorder g1 [g1root] sum 0
    let s3 = Traversal.foldPreorder g1 [g1root] sum 0
    let s4 = DiGraph.foldVertex g1 sum 0
    let s5 = DiGraph.foldEdge g1 inc 0
    Assert.AreEqual (21, s1)
    Assert.AreEqual (21, s2)
    Assert.AreEqual (21, s3)
    Assert.AreEqual (21, s4)
    Assert.AreEqual (28, s5)

  [<TestMethod>]
  member __.``RangedDiGraph Traversal Test 2``() =
    let s1 =
      Traversal.foldPostorder g1 [g1root] (fun acc v -> v.VData.Val :: acc) []
      |> List.rev |> List.toArray
    let s2 =
      Traversal.foldPreorder g1 [g1root] (fun acc v -> v.VData.Val :: acc) []
      |> List.rev |> List.toArray
    let s3 =
      Traversal.foldPostorder g3 [g3root] (fun acc v -> v.VData.Val :: acc) []
      |> List.rev |> List.toArray
    let s4 =
      Traversal.foldPreorder g3 [g3root] (fun acc v -> v.VData.Val :: acc) []
      |> List.rev |> List.toArray
    CollectionAssert.AreEqual ([| 5; 3; 4; 6; 2; 1 |], s1)
    CollectionAssert.AreEqual ([| 1; 2; 3; 5; 4; 6 |], s2)
    CollectionAssert.AreEqual ([| 4; 2; 5; 3; 1 |], s3)
    CollectionAssert.AreEqual ([| 1; 2; 4; 3; 5 |], s4)

  [<TestMethod>]
  member __.``RangedDiGraph Removal Test``() =
    let g2 = g1.Clone ()
    let g2root = DiGraph.findVertexByData g2 g1root.VData
    let g2 =
      (g2 :?> RangedDiGraph<_, _>).FindVertexByRange (AddrRange (3UL, 4UL))
      |> DiGraph.removeVertex g2
    let s1 = Traversal.foldPreorder g1 [g1root] sum 0
    let s2 = Traversal.foldPreorder g2 [g2root] sum 0
    Assert.AreEqual (6, DiGraph.getSize g1)
    Assert.AreEqual (5, DiGraph.getSize g2)
    Assert.AreEqual (21, s1)
    Assert.AreEqual (18, s2)

  [<TestMethod>]
  member __.``Graph Transposition Test``() =
    let g2 = DiGraph.reverse g1
    let g2root = DiGraph.findVertexByData g2 v6
    let s1 = Traversal.foldPreorder g1 [g1root] sum 0
    let s2 = Traversal.foldPreorder g2 [g2root] sum 0
    let lst =
      g2.FoldEdge (fun acc s d _ -> (s.VData.Val, d.VData.Val) :: acc) []
    let edges = List.sort lst |> List.toArray
    let solution = [| (2, 1); (2, 5); (3, 2); (4, 2); (5, 3); (5, 4); (6, 2) |]
    Assert.AreEqual (6, DiGraph.getSize g1)
    Assert.AreEqual (6, DiGraph.getSize g2)
    Assert.AreEqual (21, s1)
    Assert.AreEqual (21, s2)
    CollectionAssert.AreEqual (edges, solution)

  [<TestMethod>]
  member __.``Dominator Test 1``() =
    let v = Dominator.idom ctxt1 <| DiGraph.findVertexByData g1 v1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.idom ctxt1 <| DiGraph.findVertexByData g1 v2
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt1 <| DiGraph.findVertexByData g1 v3
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.idom ctxt1 <| DiGraph.findVertexByData g1 v4
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.idom ctxt1 <| DiGraph.findVertexByData g1 v5
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.idom ctxt1 <| DiGraph.findVertexByData g1 v6
    Assert.AreEqual (2, getVertexVal v)

  [<TestMethod>]
  member __.``Dominator Test 2``() =
    let v = Dominator.idom ctxt2 <| DiGraph.findVertexByData g2 v1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.idom ctxt2 <| DiGraph.findVertexByData g2 v2
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt2 <| DiGraph.findVertexByData g2 v3
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt2 <| DiGraph.findVertexByData g2 v4
    Assert.AreEqual (3, getVertexVal v)
    let v = Dominator.idom ctxt2 <| DiGraph.findVertexByData g2 v5
    Assert.AreEqual (4, getVertexVal v)
    let v = Dominator.idom ctxt2 <| DiGraph.findVertexByData g2 v6
    Assert.AreEqual (4, getVertexVal v)

  [<TestMethod>]
  member __.``Post-Dominator Test``() =
    let v = Dominator.ipdom ctxt1 <| DiGraph.findVertexByData g1 v1
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| DiGraph.findVertexByData g1 v2
    Assert.AreEqual (6, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| DiGraph.findVertexByData g1 v3
    Assert.AreEqual (5, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| DiGraph.findVertexByData g1 v4
    Assert.AreEqual (5, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| DiGraph.findVertexByData g1 v5
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| DiGraph.findVertexByData g1 v6
    Assert.IsTrue (v.IsNone)

  [<TestMethod>]
  member __.``Post-Dominator Test 2``() =
    let v = Dominator.ipdom ctxt3 <| DiGraph.findVertexByData g3 v1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.ipdom ctxt3 <| DiGraph.findVertexByData g3 v2
    Assert.AreEqual (4, getVertexVal v)
    let v = Dominator.ipdom ctxt3 <| DiGraph.findVertexByData g3 v3
    Assert.IsTrue (v.IsNone)
    let v = Dominator.ipdom ctxt3 <| DiGraph.findVertexByData g3 v4
    Assert.IsTrue (v.IsNone)
    let v = Dominator.ipdom ctxt3 <| DiGraph.findVertexByData g3 v5
    Assert.IsTrue (v.IsNone)

  [<TestMethod>]
  member __.``Dominance Frontier Test``() =
    let df =
      Dominator.frontier ctxt4 <| DiGraph.findVertexByData g4 v5 |> List.toArray
    let df = df |> Array.map (fun v -> v.VData.Val) |> Array.sort
    CollectionAssert.AreEqual (df, [|4; 5; 12; 13|])
    let df =
      Dominator.frontier ctxt4 <| DiGraph.findVertexByData g4 v9 |> List.toArray
    let df = df |> Array.map (fun v -> v.VData.Val) |> Array.sort
    CollectionAssert.AreEqual (df, [|12|])

  [<TestMethod;Timeout(1000)>]
  member __.``Root Node Loop Test``() =
    let g = RangedDiGraph.init -1 PersistentGraph
    let n1, g = DiGraph.addVertex g v1 // Node 1
    let n2, g = DiGraph.addVertex g v2 // Node 2
    let n3, g = DiGraph.addVertex g v3 // Node 3
    let n4, g = DiGraph.addVertex g v4 // Node 4
    let n5, g = DiGraph.addVertex g v5 // Node 5
    let n6, g = DiGraph.addVertex g v6 // Node 6
    let g = DiGraph.addEdge g n1 n2 1
    let g = DiGraph.addEdge g n1 n3 2
    let g = DiGraph.addEdge g n2 n4 3
    let g = DiGraph.addEdge g n3 n4 4
    let g = DiGraph.addEdge g n3 n5 5
    let g = DiGraph.addEdge g n4 n6 6
    let g = DiGraph.addEdge g n5 n6 7
    let g = DiGraph.addEdge g n6 n1 8 // Back edge to the root node.
    let ctxt = Dominator.initDominatorContext g n1
    let v = Dominator.idom ctxt <| DiGraph.findVertexByData g v1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.idom ctxt <| DiGraph.findVertexByData g v2
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt <| DiGraph.findVertexByData g v3
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt <| DiGraph.findVertexByData g v4
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt <| DiGraph.findVertexByData g v5
    Assert.AreEqual (3, getVertexVal v)
    let v = Dominator.idom ctxt <| DiGraph.findVertexByData g v6
    Assert.AreEqual (1, getVertexVal v)

  [<TestMethod>]
  member __.``Basic SCC Test``() =
    let v = DiGraph.findVertexByData g3 v1
    let sccs = SCC.compute g3 v
    Assert.AreEqual (5, Set.count sccs)

[<TestClass>]
type ExtraPersistentDomTest () =
  let v1 = V (1, (AddrRange (1UL, 2UL)))
  let v2 = V (2, (AddrRange (2UL, 3UL)))
  let v3 = V (3, (AddrRange (3UL, 4UL)))
  let v4 = V (4, (AddrRange (4UL, 5UL)))
  let v5 = V (5, (AddrRange (5UL, 6UL)))
  let v6 = V (6, (AddrRange (6UL, 7UL)))
  let v7 = V (7, (AddrRange (7UL, 8UL)))
  let v8 = V (8, (AddrRange (8UL, 9UL)))
  let v9 = V (9, (AddrRange (9UL, 10UL)))
  let v10 = V (10, (AddrRange (10UL, 11UL)))
  let v11 = V (11, (AddrRange (11UL, 12UL)))
  let v12 = V (12, (AddrRange (12UL, 13UL)))
  let v13 = V (13, (AddrRange (13UL, 14UL)))
  let v14 = V (14, (AddrRange (14UL, 15UL)))
  let v15 = V (15, (AddrRange (15UL, 16UL)))
  let v16 = V (16, (AddrRange (16UL, 17UL)))
  let v17 = V (17, (AddrRange (17UL, 18UL)))
  let v18 = V (18, (AddrRange (18UL, 19UL)))
  let v19 = V (19, (AddrRange (19UL, 20UL)))
  let v20 = V (20, (AddrRange (20UL, 21UL)))
  let v21 = V (21, (AddrRange (21UL, 22UL)))
  let v22 = V (22, (AddrRange (22UL, 23UL)))
  let v23 = V (23, (AddrRange (23UL, 24UL)))

  let g1 = RangedDiGraph.init -1 PersistentGraph
  let n1, g1 = DiGraph.addVertex g1 v1
  let n2, g1 = DiGraph.addVertex g1 v2
  let n3, g1 = DiGraph.addVertex g1 v3
  let n4, g1 = DiGraph.addVertex g1 v4
  let n5, g1 = DiGraph.addVertex g1 v5
  let n6, g1 = DiGraph.addVertex g1 v6
  let n7, g1 = DiGraph.addVertex g1 v7
  let n8, g1 = DiGraph.addVertex g1 v8
  let n9, g1 = DiGraph.addVertex g1 v9
  let n10, g1 = DiGraph.addVertex g1 v10
  let n11, g1 = DiGraph.addVertex g1 v11
  let n12, g1 = DiGraph.addVertex g1 v12
  let n13, g1 = DiGraph.addVertex g1 v13
  let n14, g1 = DiGraph.addVertex g1 v14
  let n15, g1 = DiGraph.addVertex g1 v15
  let n16, g1 = DiGraph.addVertex g1 v16
  let n17, g1 = DiGraph.addVertex g1 v17
  let n18, g1 = DiGraph.addVertex g1 v18
  let n19, g1 = DiGraph.addVertex g1 v19
  let n20, g1 = DiGraph.addVertex g1 v20
  let n21, g1 = DiGraph.addVertex g1 v21
  let n22, g1 = DiGraph.addVertex g1 v22
  let n23, g1 = DiGraph.addVertex g1 v23
  let g1 = DiGraph.addEdge g1 n1 n2 1
  let g1 = DiGraph.addEdge g1 n1 n3 2
  let g1 = DiGraph.addEdge g1 n2 n4 3
  let g1 = DiGraph.addEdge g1 n2 n7 4
  let g1 = DiGraph.addEdge g1 n3 n5 5
  let g1 = DiGraph.addEdge g1 n3 n6 6
  let g1 = DiGraph.addEdge g1 n4 n7 7
  let g1 = DiGraph.addEdge g1 n5 n8 8
  let g1 = DiGraph.addEdge g1 n5 n10 9
  let g1 = DiGraph.addEdge g1 n7 n9 10
  let g1 = DiGraph.addEdge g1 n7 n11 11
  let g1 = DiGraph.addEdge g1 n8 n10 12
  let g1 = DiGraph.addEdge g1 n9 n12 13
  let g1 = DiGraph.addEdge g1 n9 n13 14
  let g1 = DiGraph.addEdge g1 n10 n19 15
  let g1 = DiGraph.addEdge g1 n11 n22 16
  let g1 = DiGraph.addEdge g1 n12 n13 17
  let g1 = DiGraph.addEdge g1 n13 n14 18
  let g1 = DiGraph.addEdge g1 n13 n15 19
  let g1 = DiGraph.addEdge g1 n14 n16 20
  let g1 = DiGraph.addEdge g1 n15 n16 21
  let g1 = DiGraph.addEdge g1 n16 n17 22
  let g1 = DiGraph.addEdge g1 n16 n18 23
  let g1 = DiGraph.addEdge g1 n17 n18 24
  let g1 = DiGraph.addEdge g1 n18 n19 25
  let g1 = DiGraph.addEdge g1 n18 n20 26
  let g1 = DiGraph.addEdge g1 n19 n21 27
  let g1 = DiGraph.addEdge g1 n19 n23 28
  let g1 = DiGraph.addEdge g1 n20 n22 29
  let g1 = DiGraph.addEdge g1 n21 n22 30
  let g1root = n1
  let ctxt1 = Dominator.initDominatorContext g1 g1root

  let getVertexVal (v: Vertex<V> option) = (Option.get v).VData.Val

  [<TestMethod>]
  member __.``Dominator Test``() =
    let v = Dominator.idom ctxt1 <| DiGraph.findVertexByData g1 v19
    Assert.IsTrue (18 <> getVertexVal v)

[<TestClass>]
type PersistentSCCTest () =
  let v1 = V (1, (AddrRange (1UL, 2UL)))
  let v2 = V (2, (AddrRange (2UL, 3UL)))
  let v3 = V (3, (AddrRange (3UL, 4UL)))
  let v4 = V (4, (AddrRange (4UL, 5UL)))
  let v5 = V (5, (AddrRange (5UL, 6UL)))
  let v6 = V (6, (AddrRange (6UL, 7UL)))
  let v7 = V (7, (AddrRange (7UL, 8UL)))
  let v8 = V (8, (AddrRange (8UL, 9UL)))

  (* Example from article about Bourdoncle Components by Matt Elder *)
  [<TestMethod>]
  member __.``Strongly Connected Component Test1`` () =
    let g = RangedDiGraph.init -1 PersistentGraph
    let n1, g = DiGraph.addVertex g v1
    let n2, g = DiGraph.addVertex g v2
    let n3, g = DiGraph.addVertex g v3
    let n4, g = DiGraph.addVertex g v4
    let n5, g = DiGraph.addVertex g v5
    let n6, g = DiGraph.addVertex g v6
    let n7, g = DiGraph.addVertex g v7
    let n8, g = DiGraph.addVertex g v8
    let g = DiGraph.addEdge g n1 n2 1
    let g = DiGraph.addEdge g n2 n3 2
    let g = DiGraph.addEdge g n3 n4 3
    let g = DiGraph.addEdge g n4 n5 4
    let g = DiGraph.addEdge g n5 n2 5
    let g = DiGraph.addEdge g n5 n6 6
    let g = DiGraph.addEdge g n6 n3 7
    let g = DiGraph.addEdge g n6 n7 8
    let g = DiGraph.addEdge g n7 n2 9
    let g = DiGraph.addEdge g n7 n8 10
    let sccs = SCC.compute g n1
    Assert.AreEqual (3, Set.count sccs)
    let scc1 = Set.singleton n1
    Assert.IsTrue (Set.contains scc1 sccs)
    let scc2 = Set.singleton n8
    Assert.IsTrue (Set.contains scc2 sccs)
    let scc3 = Set.ofList [ n2 ; n3 ; n4 ; n5 ; n6 ; n7 ]
    Assert.IsTrue (Set.contains scc3 sccs)

  (* Example from Wikipedia *)
  [<TestMethod>]
  member __.``Strongly Connected Component Test2`` () =
    let g = RangedDiGraph.init -1 PersistentGraph
    let na, g = DiGraph.addVertex g v1
    let nb, g = DiGraph.addVertex g v2
    let nc, g = DiGraph.addVertex g v3
    let nd, g = DiGraph.addVertex g v4
    let ne, g = DiGraph.addVertex g v5
    let nf, g = DiGraph.addVertex g v6
    let ng, g = DiGraph.addVertex g v7
    let nh, g = DiGraph.addVertex g v8
    let g = DiGraph.addEdge g na nb 1
    let g = DiGraph.addEdge g nb nc 2
    let g = DiGraph.addEdge g nb ne 3
    let g = DiGraph.addEdge g nb nf 4
    let g = DiGraph.addEdge g nc nd 5
    let g = DiGraph.addEdge g nc ng 6
    let g = DiGraph.addEdge g nd nc 7
    let g = DiGraph.addEdge g nd nh 8
    let g = DiGraph.addEdge g ne na 9
    let g = DiGraph.addEdge g ne nf 10
    let g = DiGraph.addEdge g nf ng 11
    let g = DiGraph.addEdge g ng nf 12
    let g = DiGraph.addEdge g nh nd 13
    let g = DiGraph.addEdge g nh ng 14
    let sccs = SCC.compute g na
    Assert.AreEqual (3, Set.count sccs)
    let scc1 = Set.ofList [ na ; nb ; ne ]
    Assert.IsTrue (Set.contains scc1 sccs)
    let scc2 = Set.ofList [ nc ; nd ; nh ]
    Assert.IsTrue (Set.contains scc2 sccs)
    let scc3 = Set.ofList [ nf ; ng ]
    Assert.IsTrue (Set.contains scc3 sccs)
