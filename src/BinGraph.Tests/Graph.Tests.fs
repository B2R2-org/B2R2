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

namespace B2R2.BinGraph.Tests

open B2R2
open B2R2.BinGraph
open Microsoft.VisualStudio.TestTools.UnitTesting

type V (v, range) =
  inherit RangedVertexData(range)
  member __.Val : int = v
  override __.ToString () = v.ToString ()

[<TestClass>]
type TestClass () =
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
  let g1 = RangedDiGraph ()
  let n1 = g1.AddVertex v1 // Node 1
  let n2 = g1.AddVertex v2 // Node 2
  let n3 = g1.AddVertex v3 // Node 3
  let n4 = g1.AddVertex v4 // Node 4
  let n5 = g1.AddVertex v5 // Node 5
  let n6 = g1.AddVertex v6 // Node 6
  let _ = g1.AddEdge n1 n2 (Edge 1)
  let _ = g1.AddEdge n2 n3 (Edge 2)
  let _ = g1.AddEdge n2 n4 (Edge 3)
  let _ = g1.AddEdge n2 n6 (Edge 4)
  let _ = g1.AddEdge n3 n5 (Edge 5)
  let _ = g1.AddEdge n4 n5 (Edge 6)
  let _ = g1.AddEdge n5 n2 (Edge 7)
  let g1root = n1
  let ctxt1 = Dominator.initDominatorContext g1 g1root

  (* Graph example from Tiger book. *)
  let g2 = RangedDiGraph ()
  let n1 = g2.AddVertex v1 // Node 1
  let n2 = g2.AddVertex v2 // Node 2
  let n3 = g2.AddVertex v3 // Node 3
  let n4 = g2.AddVertex v4 // Node 4
  let n5 = g2.AddVertex v5 // Node 5
  let n6 = g2.AddVertex v6 // Node 6
  let _ = g2.AddEdge n1 n2 (Edge 1)
  let _ = g2.AddEdge n1 n3 (Edge 2)
  let _ = g2.AddEdge n3 n4 (Edge 3)
  let _ = g2.AddEdge n4 n5 (Edge 4)
  let _ = g2.AddEdge n4 n6 (Edge 5)
  let _ = g2.AddEdge n6 n4 (Edge 6)
  let g2root = n1
  let ctxt2 = Dominator.initDominatorContext g2 g2root

  (* Arbitrary graph example *)
  let g3 = RangedDiGraph ()
  let n1 = g3.AddVertex v1 // Node 1
  let n2 = g3.AddVertex v2 // Node 2
  let n3 = g3.AddVertex v3 // Node 3
  let n4 = g3.AddVertex v4 // Node 4
  let n5 = g3.AddVertex v5 // Node 5
  let _ = g3.AddEdge n1 n2 (Edge 1)
  let _ = g3.AddEdge n1 n3 (Edge 2)
  let _ = g3.AddEdge n2 n4 (Edge 3)
  let _ = g3.AddEdge n3 n4 (Edge 4)
  let _ = g3.AddEdge n3 n5 (Edge 5)
  let g3root = n1
  let ctxt3 = Dominator.initDominatorContext g3 g3root

  (* Graph example from Tiger book (Fig. 19.5) *)
  let g4 = RangedDiGraph ()
  let n1 = g4.AddVertex v1
  let n2 = g4.AddVertex v2
  let n3 = g4.AddVertex v3
  let n4 = g4.AddVertex v4
  let n5 = g4.AddVertex v5
  let n6 = g4.AddVertex v6
  let n7 = g4.AddVertex v7
  let n8 = g4.AddVertex v8
  let n9 = g4.AddVertex v9
  let n10 = g4.AddVertex v10
  let n11 = g4.AddVertex v11
  let n12 = g4.AddVertex v12
  let n13 = g4.AddVertex v13
  let _ = g4.AddEdge n1 n2 (Edge 1)
  let _ = g4.AddEdge n1 n5 (Edge 2)
  let _ = g4.AddEdge n1 n9 (Edge 3)
  let _ = g4.AddEdge n2 n3 (Edge 4)
  let _ = g4.AddEdge n3 n3 (Edge 5)
  let _ = g4.AddEdge n3 n4 (Edge 6)
  let _ = g4.AddEdge n4 n13 (Edge 7)
  let _ = g4.AddEdge n5 n6 (Edge 8)
  let _ = g4.AddEdge n5 n7 (Edge 9)
  let _ = g4.AddEdge n6 n4 (Edge 10)
  let _ = g4.AddEdge n6 n8 (Edge 11)
  let _ = g4.AddEdge n7 n8 (Edge 12)
  let _ = g4.AddEdge n7 n12 (Edge 13)
  let _ = g4.AddEdge n8 n5 (Edge 14)
  let _ = g4.AddEdge n8 n13 (Edge 15)
  let _ = g4.AddEdge n9 n10 (Edge 16)
  let _ = g4.AddEdge n9 n11 (Edge 17)
  let _ = g4.AddEdge n10 n12 (Edge 18)
  let _ = g4.AddEdge n11 n12 (Edge 19)
  let _ = g4.AddEdge n12 n13 (Edge 20)
  let g4root = n1
  let ctxt4 = Dominator.initDominatorContext g4 g4root

  let edgeValue (Edge d) : int = d

  let getVertexVal (v: Vertex<V> option) = (Option.get v).VData.Val

  let sum acc (v: Vertex<V>) = v.VData.Val + acc
  let inc acc _v1 _v2 e = acc + edgeValue e

  [<TestMethod>]
  member __.``RangedDiGraph Traversal Test 1``() =
    let s1 = Traversal.foldPostorder g1root sum 0
    let s2 = Traversal.foldRevPostorder g1root sum 0
    let s3 = Traversal.foldPreorder g1root sum 0
    let s4 = g1.FoldVertex sum 0
    let s5 = g1.FoldEdge inc 0
    Assert.AreEqual (s1, 21)
    Assert.AreEqual (s2, 21)
    Assert.AreEqual (s3, 21)
    Assert.AreEqual (s4, 21)
    Assert.AreEqual (s5, 28)

  [<TestMethod>]
  member __.``RangedDiGraph Traversal Test 2``() =
    let s1 =
      Traversal.foldPostorder g1root (fun acc v -> v.VData.Val :: acc) []
      |> List.rev |> List.toArray
    let s2 =
      Traversal.foldPreorder g1root (fun acc v -> v.VData.Val :: acc) []
      |> List.rev |> List.toArray
    let s3 =
      Traversal.foldPostorder g3root (fun acc v -> v.VData.Val :: acc) []
      |> List.rev |> List.toArray
    let s4 =
      Traversal.foldPreorder g3root (fun acc v -> v.VData.Val :: acc) []
      |> List.rev |> List.toArray
    CollectionAssert.AreEqual ([| 5; 3; 4; 6; 2; 1 |], s1)
    CollectionAssert.AreEqual ([| 1; 2; 3; 5; 4; 6 |], s2)
    CollectionAssert.AreEqual ([| 4; 2; 5; 3; 1 |], s3)
    CollectionAssert.AreEqual ([| 1; 2; 4; 3; 5 |], s4)

  [<TestMethod>]
  member __.``RangedDiGraph Removal Test``() =
    let g2 = g1.Clone ()
    let g2root = g2.FindVertexByData (g1root.VData)
    g2.FindVertexByRange (AddrRange (3UL, 4UL)) |> g2.RemoveVertex
    let s1 = Traversal.foldPreorder g1root sum 0
    let s2 = Traversal.foldPreorder g2root sum 0
    Assert.AreEqual (6, g1.Size ())
    Assert.AreEqual (5, g2.Size ())
    Assert.AreEqual (21, s1)
    Assert.AreEqual (18, s2)

  [<TestMethod>]
  member __.``Graph Transposition Test``() =
    let g2 = g1.Reverse ()
    let g2root = g2.FindVertexByData v6
    let s1 = Traversal.foldPreorder g1root sum 0
    let s2 = Traversal.foldPreorder g2root sum 0
    let lst =
      g2.FoldEdge (fun acc s d _ -> (s.VData.Val, d.VData.Val) :: acc) []
    let edges = List.sort lst |> List.toArray
    let solution = [| (2, 1); (2, 5); (3, 2); (4, 2); (5, 3); (5, 4); (6, 2) |]
    Assert.AreEqual (6, g1.Size ())
    Assert.AreEqual (6, g2.Size ())
    Assert.AreEqual (21, s1)
    Assert.AreEqual (21, s2)
    CollectionAssert.AreEqual (edges, solution)

  [<TestMethod>]
  member __.``Dominator Test 1``() =
    let v = Dominator.idom ctxt1 <| g1.FindVertexByData v1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.idom ctxt1 <| g1.FindVertexByData v2
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt1 <| g1.FindVertexByData v3
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.idom ctxt1 <| g1.FindVertexByData v4
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.idom ctxt1 <| g1.FindVertexByData v5
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.idom ctxt1 <| g1.FindVertexByData v6
    Assert.AreEqual (2, getVertexVal v)

  [<TestMethod>]
  member __.``Dominator Test 2``() =
    let v = Dominator.idom ctxt2 <| g2.FindVertexByData v1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.idom ctxt2 <| g2.FindVertexByData v2
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt2 <| g2.FindVertexByData v3
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt2 <| g2.FindVertexByData v4
    Assert.AreEqual (3, getVertexVal v)
    let v = Dominator.idom ctxt2 <| g2.FindVertexByData v5
    Assert.AreEqual (4, getVertexVal v)
    let v = Dominator.idom ctxt2 <| g2.FindVertexByData v6
    Assert.AreEqual (4, getVertexVal v)

  [<TestMethod>]
  member __.``Post-Dominator Test``() =
    let v = Dominator.ipdom ctxt1 <| g1.FindVertexByData v1
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| g1.FindVertexByData v2
    Assert.AreEqual (6, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| g1.FindVertexByData v3
    Assert.AreEqual (5, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| g1.FindVertexByData v4
    Assert.AreEqual (5, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| g1.FindVertexByData v5
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.ipdom ctxt1 <| g1.FindVertexByData v6
    Assert.IsTrue (v.IsNone)

  [<TestMethod>]
  member __.``Post-Dominator Test 2``() =
    let v = Dominator.ipdom ctxt3 <| g3.FindVertexByData v1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.ipdom ctxt3 <| g3.FindVertexByData v2
    Assert.AreEqual (4, getVertexVal v)
    let v = Dominator.ipdom ctxt3 <| g3.FindVertexByData v3
    Assert.IsTrue (v.IsNone)
    let v = Dominator.ipdom ctxt3 <| g3.FindVertexByData v4
    Assert.IsTrue (v.IsNone)
    let v = Dominator.ipdom ctxt3 <| g3.FindVertexByData v5
    Assert.IsTrue (v.IsNone)

  [<TestMethod>]
  member __.``Dominance Frontier Test``() =
    let df = Dominator.frontier ctxt4 <| g4.FindVertexByData v5 |> List.toArray
    let df = df |> Array.map (fun v -> v.VData.Val) |> Array.sort
    CollectionAssert.AreEqual (df, [|4; 5; 12; 13|])
    let df = Dominator.frontier ctxt4 <| g4.FindVertexByData v9 |> List.toArray
    let df = df |> Array.map (fun v -> v.VData.Val) |> Array.sort
    CollectionAssert.AreEqual (df, [|12|])

  [<TestMethod>]
  member __.``Root Node Loop Test``() =
    let g = RangedDiGraph ()
    let n1 = g.AddVertex v1 // Node 1
    let n2 = g.AddVertex v2 // Node 2
    let n3 = g.AddVertex v3 // Node 3
    let n4 = g.AddVertex v4 // Node 4
    let n5 = g.AddVertex v5 // Node 5
    let n6 = g.AddVertex v6 // Node 6
    g.AddEdge n1 n2 (Edge 1)
    g.AddEdge n1 n3 (Edge 2)
    g.AddEdge n2 n4 (Edge 3)
    g.AddEdge n3 n4 (Edge 4)
    g.AddEdge n3 n5 (Edge 5)
    g.AddEdge n4 n6 (Edge 6)
    g.AddEdge n5 n6 (Edge 7)
    g.AddEdge n6 n1 (Edge 8) // Back edge to the root node.
    let ctxt = Dominator.initDominatorContext g n1
    let v = Dominator.idom ctxt <| g.FindVertexByData v1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.idom ctxt <| g.FindVertexByData v2
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt <| g.FindVertexByData v3
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt <| g.FindVertexByData v4
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctxt <| g.FindVertexByData v5
    Assert.AreEqual (3, getVertexVal v)
    let v = Dominator.idom ctxt <| g.FindVertexByData v6
    Assert.AreEqual (1, getVertexVal v)
