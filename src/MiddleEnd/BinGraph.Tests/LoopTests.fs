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
open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinGraph.Tests.Examples

[<TestClass>]
type LoopTests() =
  let toTuple (KeyValue(k, v)) = k, v

  let toSet (vmap: Map<_, _>) lst =
    lst |> List.map (fun vid -> vmap[vid]) |> HashSet

  let assertLoop (edge: Edge<_, _>, vertices)
                 (src: VertexID, dst: VertexID, expectedVS: HashSet<_>) =
    Assert.AreEqual<VertexID>(edge.First.ID, src) (* backedge src *)
    Assert.AreEqual<VertexID>(edge.Second.ID, dst) (* backedge dst *)
    Assert.AreEqual(true, expectedVS.SetEquals vertices)

  static member GraphTypes = [| [| box Persistent |]; [| box Mutable |] |]

  [<TestMethod>]
  [<DynamicData(nameof LoopTests.GraphTypes)>]
  member _.``Natural Loop Test``(t) =
    let g, vmap = digraph11 t
    let dict =
      Loop.NaturalLoop.findAll g
      |> Seq.map toTuple
      |> Seq.toArray
      |> Array.sortBy (fun (k, _) -> k.First.ID)
    Assert.AreEqual<int>(5, dict.Length)
    assertLoop dict[0] <| (4, 3, toSet vmap [ 3; 4; 5; 6; 7; 8; 10 ])
    assertLoop dict[1] <| (7, 4, toSet vmap [ 4; 5; 6; 7; 8; 10 ])
    assertLoop dict[2] <| (8, 3, toSet vmap [ 3; 4; 5; 6; 7; 8; 10 ])
    assertLoop dict[3] <| (9, 1, toSet vmap [ 1; 2; 3; 4; 5; 6; 7; 8; 9; 10 ])
    assertLoop dict[4] <| (10, 7, toSet vmap [ 7; 8; 10 ])

  [<TestMethod>]
  [<DynamicData(nameof LoopTests.GraphTypes)>]
  member _.``Irreducible Natural Loop Test``(t) =
    let g, _ = digraph15 t
    let dict = Loop.NaturalLoop.findAll g
    Assert.AreEqual<int>(0, dict.Count)

  [<TestMethod>]
  [<DynamicData(nameof LoopTests.GraphTypes)>]
  member _.``Reducible Retreating Edge Test``(t) =
    let g, _ = digraph11 t
    let edges =
      Loop.RetreatingEdge.findAll g
      |> Seq.map (fun e -> e.First.ID, e.Second.ID)
      |> Seq.sort
      |> Seq.toArray
    (* The graph is reducible, hence its retreating edges are exactly the back
       edges that the natural loops close. *)
    let expected = [| 4, 3; 7, 4; 8, 3; 9, 1; 10, 7 |]
    CollectionAssert.AreEqual(expected, edges)

  [<TestMethod>]
  [<DynamicData(nameof LoopTests.GraphTypes)>]
  member _.``Irreducible Retreating Edge Test``(t) =
    let g, _ = digraph15 t
    let edges = Loop.RetreatingEdge.findAll g
    (* One of the two edges of the cycle retreats, which one depending on the
       order the traversal reaches its vertices in, while neither closes a
       natural loop. *)
    Assert.AreEqual<int>(1, edges.Count)
    let e = Seq.head edges
    let ids = HashSet [ e.First.ID; e.Second.ID ]
    Assert.AreEqual(true, ids.SetEquals [ 2; 3 ])

  [<TestMethod>]
  [<DynamicData(nameof LoopTests.GraphTypes)>]
  member _.``Unreachable Natural Loop Test``(t) =
    let g, vmap = digraph10 t
    let dict = Loop.NaturalLoop.findAll g
    (* Nothing dominates a vertex no root reaches, hence the cycle between 4
       and 5 closes no natural loop, while the one through 3 does. *)
    Assert.AreEqual<int>(1, dict.Count)
    let edge, vertices = dict |> Seq.head |> toTuple
    assertLoop (edge, vertices) (3, 1, toSet vmap [ 1; 2; 3 ])

  [<TestMethod>]
  [<DynamicData(nameof LoopTests.GraphTypes)>]
  member _.``Acyclic Natural Loop Test``(t) =
    let g, _ = digraph12 t
    let dict = Loop.NaturalLoop.findAll g
    Assert.AreEqual<int>(0, dict.Count)
