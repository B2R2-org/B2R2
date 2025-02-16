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
type LoopTests () =
  let toTuple (KeyValue (k, v)) = k, v

  let toSet (vmap: Map<_, _>) lst =
    lst |> List.map (fun vid -> vmap[vid]) |> HashSet

  let assertLoop (edge: Edge<_, _>, vertices)
                 (src: VertexID, dst: VertexID, expectedVS) =
    Assert.AreEqual<VertexID> (edge.First.ID, src) (* backedge src *)
    Assert.AreEqual<VertexID> (edge.Second.ID, dst) (* backedge dst *)
    Assert.IsTrue <| (expectedVS: HashSet<_>).SetEquals vertices

  static member GraphTypes = [| [| box Persistent |]; [| box Imperative |] |]

  [<TestMethod>]
  [<DynamicData(nameof LoopTests.GraphTypes)>]
  member __.`` Natural Loop Test `` (t) =
    let g, vmap = digraph11 t
    let dict =
      Loop.getNaturalLoops g
      |> Seq.map toTuple
      |> Seq.toArray
      |> Array.sortBy (fun (k, _) -> k.First.ID)
    Assert.AreEqual<int> (5, dict.Length)
    assertLoop dict[0] <| (4, 3, toSet vmap [ 3; 4; 5; 6; 7; 8; 10 ])
    assertLoop dict[1] <| (7, 4, toSet vmap [ 4; 5; 6; 7; 8; 10 ])
    assertLoop dict[2] <| (8, 3, toSet vmap [ 3; 4; 5; 6; 7; 8; 10 ])
    assertLoop dict[3] <| (9, 1, toSet vmap [ 1; 2; 3; 4; 5; 6; 7; 8; 9; 10 ])
    assertLoop dict[4] <| (10, 7, toSet vmap [ 7; 8; 10 ])
