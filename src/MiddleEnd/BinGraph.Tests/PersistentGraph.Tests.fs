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
  (* Graph example from Wikipedia. *)
  let g1 = PersistentDiGraph () :> IGraph<_, _>
  let n1, g1 = g1.AddVertex 1 // Node 1
  let n2, g1 = g1.AddVertex 2 // Node 2
  let n3, g1 = g1.AddVertex 3 // Node 3
  let n4, g1 = g1.AddVertex 4 // Node 4
  let n5, g1 = g1.AddVertex 5 // Node 5
  let n6, g1 = g1.AddVertex 6 // Node 6
  let g1 = g1.AddEdge (n1, n2, 1)
  let g1 = g1.AddEdge (n2, n3, 2)
  let g1 = g1.AddEdge (n2, n4, 3)
  let g1 = g1.AddEdge (n2, n6, 4)
  let g1 = g1.AddEdge (n3, n5, 5)
  let g1 = g1.AddEdge (n4, n5, 6)
  let g1 = g1.AddEdge (n5, n2, 7)
  let g1root = n1
  let ctxt1 = Dominator.initDominatorContext g1

  (* Graph example from Tiger book. *)
  let g2 = PersistentDiGraph () :> IGraph<_, _>
  let n1, g2 = g2.AddVertex 1 // Node 1
  let n2, g2 = g2.AddVertex 2 // Node 2
  let n3, g2 = g2.AddVertex 3 // Node 3
  let n4, g2 = g2.AddVertex 4 // Node 4
  let n5, g2 = g2.AddVertex 5 // Node 5
  let n6, g2 = g2.AddVertex 6 // Node 6
  let g2 = g2.AddEdge (n1, n2, 1)
  let g2 = g2.AddEdge (n1, n3, 2)
  let g2 = g2.AddEdge (n3, n4, 3)
  let g2 = g2.AddEdge (n4, n5, 4)
  let g2 = g2.AddEdge (n4, n6, 5)
  let g2 = g2.AddEdge (n6, n4, 6)
  let ctxt2 = Dominator.initDominatorContext g2

  (* Arbitrary graph example *)
  let g3 = PersistentDiGraph () :> IGraph<_, _>
  let n1, g3 = g3.AddVertex 1 // Node 1
  let n2, g3 = g3.AddVertex 2 // Node 2
  let n3, g3 = g3.AddVertex 3 // Node 3
  let n4, g3 = g3.AddVertex 4 // Node 4
  let n5, g3 = g3.AddVertex 5 // Node 5
  let g3 = g3.AddEdge (n1, n2, 1)
  let g3 = g3.AddEdge (n1, n3, 2)
  let g3 = g3.AddEdge (n2, n4, 3)
  let g3 = g3.AddEdge (n3, n4, 4)
  let g3 = g3.AddEdge (n3, n5, 5)
  let g3root = n1
  let ctxt3 = Dominator.initDominatorContext g3

  (* Graph example from Tiger book (Fig. 19.5) *)
  let g4 = PersistentDiGraph () :> IGraph<_, _>
  let n1, g4 = g4.AddVertex 1
  let n2, g4 = g4.AddVertex 2
  let n3, g4 = g4.AddVertex 3
  let n4, g4 = g4.AddVertex 4
  let n5, g4 = g4.AddVertex 5
  let n6, g4 = g4.AddVertex 6
  let n7, g4 = g4.AddVertex 7
  let n8, g4 = g4.AddVertex 8
  let n9, g4 = g4.AddVertex 9
  let n10, g4 = g4.AddVertex 10
  let n11, g4 = g4.AddVertex 11
  let n12, g4 = g4.AddVertex 12
  let n13, g4 = g4.AddVertex 13
  let g4 = g4.AddEdge (n1, n2, 1)
  let g4 = g4.AddEdge (n1, n5, 2)
  let g4 = g4.AddEdge (n1, n9, 3)
  let g4 = g4.AddEdge (n2, n3, 4)
  let g4 = g4.AddEdge (n3, n3, 5)
  let g4 = g4.AddEdge (n3, n4, 6)
  let g4 = g4.AddEdge (n4, n13, 7)
  let g4 = g4.AddEdge (n5, n6, 8)
  let g4 = g4.AddEdge (n5, n7, 9)
  let g4 = g4.AddEdge (n6, n4, 10)
  let g4 = g4.AddEdge (n6, n8, 11)
  let g4 = g4.AddEdge (n7, n8, 12)
  let g4 = g4.AddEdge (n7, n12, 13)
  let g4 = g4.AddEdge (n8, n5, 14)
  let g4 = g4.AddEdge (n8, n13, 15)
  let g4 = g4.AddEdge (n9, n10, 16)
  let g4 = g4.AddEdge (n9, n11, 17)
  let g4 = g4.AddEdge (n10, n12, 18)
  let g4 = g4.AddEdge (n11, n12, 19)
  let g4 = g4.AddEdge (n12, n13, 20)
  let g4root = n1
  let ctxt4 = Dominator.initDominatorContext g4

  let getVertexVal (v: IVertex<_> option) = (Option.get v).VData

  let sum acc (v: IVertex<_>) = v.VData + acc
  let inc acc (e: Edge<_, _>) = acc + e.Label

  [<TestMethod>]
  member __.``DiGraph Traversal Test 1``() =
    let s1 = Traversal.foldPostorder g1 [g1root] sum 0
    let s2 = Traversal.foldRevPostorder g1 [g1root] sum 0
    let s3 = Traversal.foldPreorder g1 [g1root] sum 0
    let s4 = g1.FoldVertex sum 0
    let s5 = g1.FoldEdge inc 0
    Assert.AreEqual (21, s1)
    Assert.AreEqual (21, s2)
    Assert.AreEqual (21, s3)
    Assert.AreEqual (21, s4)
    Assert.AreEqual (28, s5)

  [<TestMethod>]
  member __.``DiGraph Traversal Test 2``() =
    let s1 =
      Traversal.foldPostorder g1 [g1root] (fun acc v -> v.VData:: acc) []
      |> List.rev |> List.toArray
    let s2 =
      Traversal.foldPreorder g1 [g1root] (fun acc v -> v.VData :: acc) []
      |> List.rev |> List.toArray
    let s3 =
      Traversal.foldPostorder g3 [g3root] (fun acc v -> v.VData :: acc) []
      |> List.rev |> List.toArray
    let s4 =
      Traversal.foldPreorder g3 [g3root] (fun acc v -> v.VData :: acc) []
      |> List.rev |> List.toArray
    CollectionAssert.AreEqual ([| 5; 3; 4; 6; 2; 1 |], s1)
    CollectionAssert.AreEqual ([| 1; 2; 3; 5; 4; 6 |], s2)
    CollectionAssert.AreEqual ([| 4; 2; 5; 3; 1 |], s3)
    CollectionAssert.AreEqual ([| 1; 2; 4; 3; 5 |], s4)

  [<TestMethod>]
  member __.``DiGraph Removal Test``() =
    let g2 = g1.Clone ()
    let g2root = g2.FindVertexByData g1root.VData
    let g2 = g2.FindVertexByData 3 |> g2.RemoveVertex
    let s1 = Traversal.foldPreorder g1 [g1root] sum 0
    let s2 = Traversal.foldPreorder g2 [g2root] sum 0
    Assert.AreEqual (6, g1.Size)
    Assert.AreEqual (5, g2.Size)
    Assert.AreEqual (21, s1)
    Assert.AreEqual (18, s2)

  [<TestMethod>]
  member __.``Graph Transposition Test``() =
    let g2 = g1.Reverse ()
    let g2root = g2.FindVertexByData 6
    let s1 = Traversal.foldPreorder g1 [g1root] sum 0
    let s2 = Traversal.foldPreorder g2 [g2root] sum 0
    let lst =
      g2.FoldEdge (fun acc e -> (e.First.VData, e.Second.VData) :: acc) []
    let edges = List.sort lst |> List.toArray
    let solution = [| (2, 1); (2, 5); (3, 2); (4, 2); (5, 3); (5, 4); (6, 2) |]
    Assert.AreEqual (6, g1.Size)
    Assert.AreEqual (6, g2.Size)
    Assert.AreEqual (21, s1)
    Assert.AreEqual (21, s2)
    CollectionAssert.AreEqual (edges, solution)

  [<TestMethod>]
  member __.``Dominator Test 1``() =
    let v = Dominator.idom ctxt1 <| g1.FindVertexByData 1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.idom ctxt1 <| g1.FindVertexByData 2
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt1 <| g1.FindVertexByData 3
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.idom ctxt1 <| g1.FindVertexByData 4
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.idom ctxt1 <| g1.FindVertexByData 5
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.idom ctxt1 <| g1.FindVertexByData 6
    Assert.AreEqual (2, getVertexVal v)

  [<TestMethod>]
  member __.``Dominator Test 2``() =
    let v = Dominator.idom ctxt2 <| g2.FindVertexByData 1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.idom ctxt2 <| g2.FindVertexByData 2
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt2 <| g2.FindVertexByData 3
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt2 <| g2.FindVertexByData 4
    Assert.AreEqual (3, getVertexVal v)
    let v = Dominator.idom ctxt2 <| g2.FindVertexByData 5
    Assert.AreEqual (4, getVertexVal v)
    let v = Dominator.idom ctxt2 <| g2.FindVertexByData 6
    Assert.AreEqual (4, getVertexVal v)

  [<TestMethod>]
  member __.``Post-Dominator Test``() =
    let v = Dominator.ipdom ctxt1 <| g1.FindVertexByData 1
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| g1.FindVertexByData 2
    Assert.AreEqual (6, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| g1.FindVertexByData 3
    Assert.AreEqual (5, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| g1.FindVertexByData 4
    Assert.AreEqual (5, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| g1.FindVertexByData 5
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| g1.FindVertexByData 6
    Assert.IsTrue (v.IsNone)

  [<TestMethod>]
  member __.``Post-Dominator Test 2``() =
    let v = Dominator.ipdom ctxt3 <| g3.FindVertexByData 1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.ipdom ctxt3 <| g3.FindVertexByData 2
    Assert.AreEqual (4, getVertexVal v)
    let v = Dominator.ipdom ctxt3 <| g3.FindVertexByData 3
    Assert.IsTrue (v.IsNone)
    let v = Dominator.ipdom ctxt3 <| g3.FindVertexByData 4
    Assert.IsTrue (v.IsNone)
    let v = Dominator.ipdom ctxt3 <| g3.FindVertexByData 5
    Assert.IsTrue (v.IsNone)

  [<TestMethod>]
  member __.``Dominance Frontier Test``() =
    let df =
      Dominator.frontier ctxt4 <| g4.FindVertexByData 5 |> List.toArray
    let df = df |> Array.map (fun v -> v.VData) |> Array.sort
    CollectionAssert.AreEqual (df, [|4; 5; 12; 13|])
    let df =
      Dominator.frontier ctxt4 <| g4.FindVertexByData 9 |> List.toArray
    let df = df |> Array.map (fun v -> v.VData) |> Array.sort
    CollectionAssert.AreEqual (df, [|12|])

  [<TestMethod;Timeout(1000)>]
  member __.``Root Node Loop Test``() =
    let g = PersistentDiGraph () :> IGraph<_, _>
    let n1, g = g.AddVertex 1 // Node 1
    let n2, g = g.AddVertex 2 // Node 2
    let n3, g = g.AddVertex 3 // Node 3
    let n4, g = g.AddVertex 4 // Node 4
    let n5, g = g.AddVertex 5 // Node 5
    let n6, g = g.AddVertex 6 // Node 6
    let g = g.AddEdge (n1, n2, 1)
    let g = g.AddEdge (n1, n3, 2)
    let g = g.AddEdge (n2, n4, 3)
    let g = g.AddEdge (n3, n4, 4)
    let g = g.AddEdge (n3, n5, 5)
    let g = g.AddEdge (n4, n6, 6)
    let g = g.AddEdge (n5, n6, 7)
    let g = g.AddEdge (n6, n1, 8) // Back edge to the root node.
    let ctxt = Dominator.initDominatorContext g
    let v = Dominator.idom ctxt <| g.FindVertexByData 1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.idom ctxt <| g.FindVertexByData 2
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt <| g.FindVertexByData 3
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt <| g.FindVertexByData 4
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt <| g.FindVertexByData 5
    Assert.AreEqual (3, getVertexVal v)
    let v = Dominator.idom ctxt <| g.FindVertexByData 6
    Assert.AreEqual (1, getVertexVal v)

[<TestClass>]
type ExtraPersistentDomTest () =
  let g1 = PersistentDiGraph () :> IGraph<_, _>
  let n1, g1 = g1.AddVertex 1
  let n2, g1 = g1.AddVertex 2
  let n3, g1 = g1.AddVertex 3
  let n4, g1 = g1.AddVertex 4
  let n5, g1 = g1.AddVertex 5
  let n6, g1 = g1.AddVertex 6
  let n7, g1 = g1.AddVertex 7
  let n8, g1 = g1.AddVertex 8
  let n9, g1 = g1.AddVertex 9
  let n10, g1 = g1.AddVertex 10
  let n11, g1 = g1.AddVertex 11
  let n12, g1 = g1.AddVertex 12
  let n13, g1 = g1.AddVertex 13
  let n14, g1 = g1.AddVertex 14
  let n15, g1 = g1.AddVertex 15
  let n16, g1 = g1.AddVertex 16
  let n17, g1 = g1.AddVertex 17
  let n18, g1 = g1.AddVertex 18
  let n19, g1 = g1.AddVertex 19
  let n20, g1 = g1.AddVertex 20
  let n21, g1 = g1.AddVertex 21
  let n22, g1 = g1.AddVertex 22
  let n23, g1 = g1.AddVertex 23
  let g1 = g1.AddEdge (n1, n2, 1)
  let g1 = g1.AddEdge (n1, n3, 2)
  let g1 = g1.AddEdge (n2, n4, 3)
  let g1 = g1.AddEdge (n2, n7, 4)
  let g1 = g1.AddEdge (n3, n5, 5)
  let g1 = g1.AddEdge (n3, n6, 6)
  let g1 = g1.AddEdge (n4, n7, 7)
  let g1 = g1.AddEdge (n5, n8, 8)
  let g1 = g1.AddEdge (n5, n10, 9)
  let g1 = g1.AddEdge (n7, n9, 10)
  let g1 = g1.AddEdge (n7, n11, 11)
  let g1 = g1.AddEdge (n8, n10, 12)
  let g1 = g1.AddEdge (n9, n12, 13)
  let g1 = g1.AddEdge (n9, n13, 14)
  let g1 = g1.AddEdge (n10, n19, 15)
  let g1 = g1.AddEdge (n11, n22, 16)
  let g1 = g1.AddEdge (n12, n13, 17)
  let g1 = g1.AddEdge (n13, n14, 18)
  let g1 = g1.AddEdge (n13, n15, 19)
  let g1 = g1.AddEdge (n14, n16, 20)
  let g1 = g1.AddEdge (n15, n16, 21)
  let g1 = g1.AddEdge (n16, n17, 22)
  let g1 = g1.AddEdge (n16, n18, 23)
  let g1 = g1.AddEdge (n17, n18, 24)
  let g1 = g1.AddEdge (n18, n19, 25)
  let g1 = g1.AddEdge (n18, n20, 26)
  let g1 = g1.AddEdge (n19, n21, 27)
  let g1 = g1.AddEdge (n19, n23, 28)
  let g1 = g1.AddEdge (n20, n22, 29)
  let g1 = g1.AddEdge (n21, n22, 30)
  let ctxt1 = Dominator.initDominatorContext g1

  let getVertexVal (v: IVertex<_> option) = (Option.get v).VData

  [<TestMethod>]
  member __.``Dominator Test``() =
    let v = Dominator.idom ctxt1 <| g1.FindVertexByData 19
    Assert.IsTrue (18 <> getVertexVal v)
