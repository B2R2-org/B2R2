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
type TraversalTests() =
  let accumulate acc v = v :: acc

  let makeAnswer lst =
    List.rev lst |> List.map (fun (v: IVertex<int>) -> v.VData)

  let addVertexID acc (v: IVertex<_>) = Set.add v.ID acc

  (* Only the vertices reachable from the roots take part in a WithRoots
     traversal, so they are the ones the two postorders must agree on. *)
  let reachableIDs (g: IMutableDiGraph<_, _>) =
    let roots = g.GetRoots() |> Array.toList
    DFS.foldPreorderWithRoots g roots addVertexID Set.empty

  (* Runs the given iterating function and reports the data it walked over, so
     that it can be held against what the matching fold returns. *)
  let iterated run =
    let seen = ResizeArray<IVertex<int>>()
    run seen.Add
    seen |> Seq.map (fun v -> v.VData) |> List.ofSeq

  let examples =
    [ digraph1
      digraph2
      digraph3
      digraph4
      digraph5
      digraph6
      digraph7
      digraph8
      digraph9
      digraph10
      digraph11
      digraph12
      digraph13
      digraph14 ]

  static member GraphTypes = [| [| box Persistent |]; [| box Mutable |] |]

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Preorder traversal test 1``(t) =
    let g, _ = digraph1 t
    let actual = DFS.foldPreorder g accumulate [] |> makeAnswer
    let expected = [ 1; 2; 3; 5; 4; 6 ]
    Assert.AreEqual(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Preorder traversal test 2``(t) =
    let g, _ = digraph2 t
    let actual = DFS.foldPreorder g accumulate [] |> makeAnswer
    let expected = [ 1; 2; 3; 4; 5; 6 ]
    Assert.AreEqual(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Preorder traversal test 3``(t) =
    let g, _ = digraph3 t
    let actual = DFS.foldPreorder g accumulate [] |> makeAnswer
    let expected = [ 1; 2; 4; 3; 5 ]
    Assert.AreEqual(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Postorder traversal test 1``(t) =
    let g, _ = digraph1 t
    let actual = DFS.foldPostorder g accumulate [] |> makeAnswer
    let expected = [ 5; 3; 4; 6; 2; 1 ]
    Assert.AreEqual(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Postorder traversal test 2``(t) =
    let g, _ = digraph2 t
    let actual = DFS.foldPostorder g accumulate [] |> makeAnswer
    let expected = [ 2; 5; 6; 4; 3; 1 ]
    Assert.AreEqual(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Postorder traversal test 3``(t) =
    let g, _ = digraph3 t
    let actual = DFS.foldPostorder g accumulate [] |> makeAnswer
    let expected = [ 4; 2; 5; 3; 1 ]
    Assert.AreEqual(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Postorder traversal test 4``(t) =
    let g, _ = digraph14 t
    let actual = DFS.foldPostorder g accumulate [] |> makeAnswer
    let expected = [ 3; 2; 1 ]
    Assert.AreEqual(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Postorder with roots traversal test``(t) =
    let g, _ = digraph14 t
    let roots = g.GetRoots()
    let actual = DFS.foldPostorderWithRoots g roots accumulate [] |> makeAnswer
    let expected = [ 3; 2; 1 ]
    Assert.AreEqual(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Postorder with roots agrees with postorder``(t) =
    for makeExample in examples do
      let g, _ = makeExample t
      let reachable = reachableIDs g
      let expected =
        DFS.foldPostorder g accumulate []
        |> List.filter (fun (v: IVertex<_>) -> Set.contains v.ID reachable)
        |> makeAnswer
      let actual =
        DFS.foldPostorderWithRoots g (g.GetRoots()) accumulate [] |> makeAnswer
      Assert.AreEqual(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Breadth-first traversal test 1``(t) =
    let g, _ = digraph1 t
    let actual = BFS.foldWithRoots g (g.GetRoots()) accumulate [] |> makeAnswer
    let expected = [ 1; 2; 3; 4; 6; 5 ]
    Assert.AreEqual(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Breadth-first traversal test 2``(t) =
    let g, _ = digraph2 t
    let actual = BFS.foldWithRoots g (g.GetRoots()) accumulate [] |> makeAnswer
    let expected = [ 1; 2; 3; 4; 5; 6 ]
    Assert.AreEqual(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Breadth-first traversal reaches unreachable vertices``(t) =
    let g, _ = digraph12 t
    let roots = g.GetRoots()
    let reachable = BFS.foldWithRoots g roots accumulate [] |> makeAnswer
    let every = BFS.fold g accumulate [] |> makeAnswer
    Assert.AreEqual([ 1; 2; 3; 4 ], reachable)
    Assert.AreEqual([ 1; 2; 3; 4; 5 ], every)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Breadth-first fold covers every vertex``(t) =
    for makeExample in examples do
      let g, _ = makeExample t
      let folded = BFS.fold g accumulate [] |> makeAnswer
      Assert.AreEqual(g.Size, List.length folded)
      Assert.AreEqual(g.Size, List.distinct folded |> List.length)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Reverse breadth-first order reverses the walk``(t) =
    for makeExample in examples do
      let g, _ = makeExample t
      let roots = g.GetRoots()
      let forward = BFS.foldWithRoots g roots accumulate [] |> makeAnswer
      let backward = BFS.foldRevWithRoots g roots accumulate [] |> makeAnswer
      Assert.AreEqual(List.rev forward, backward)
      let forwardAll = BFS.fold g accumulate [] |> makeAnswer
      let backwardAll = BFS.foldRev g accumulate [] |> makeAnswer
      Assert.AreEqual(List.rev forwardAll, backwardAll)

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Breadth-first iteration agrees with folding``(t) =
    for makeExample in examples do
      let g, _ = makeExample t
      let roots = g.GetRoots()
      Assert.AreEqual(BFS.foldWithRoots g roots accumulate [] |> makeAnswer,
                      iterated (fun fn -> BFS.iterWithRoots g roots fn))
      Assert.AreEqual(BFS.fold g accumulate [] |> makeAnswer,
                      iterated (fun fn -> BFS.iter g fn))
      Assert.AreEqual(BFS.foldRevWithRoots g roots accumulate [] |> makeAnswer,
                      iterated (fun fn -> BFS.iterRevWithRoots g roots fn))
      Assert.AreEqual(BFS.foldRev g accumulate [] |> makeAnswer,
                      iterated (fun fn -> BFS.iterRev g fn))

  [<TestMethod>]
  [<DynamicData(nameof TraversalTests.GraphTypes)>]
  member _.``Duplicate roots are visited once``(t) =
    let g, _ = digraph1 t
    let r = g.SingleRoot
    let actual = BFS.foldRevWithRoots g [ r; r ] accumulate [] |> makeAnswer
    let expected = [ 5; 6; 4; 3; 2; 1 ]
    Assert.AreEqual(expected, actual)
