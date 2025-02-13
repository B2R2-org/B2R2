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
open B2R2.MiddleEnd.BinGraph.Tests.Examples

[<TestClass>]
type Dominator () =
  let getVertexVal (v: IVertex<_> option) = (Option.get v).VData

  static member GraphTypes = [| [| box Persistent |]; [| box Imperative |] |]

  [<TestMethod>]
  [<DynamicData(nameof Basic.GraphTypes)>]
  member __.``Dominator Test 1`` (t) =
    let g, _ = digraph1 t
    let ctx = Dominator.initDominatorContext g
    let v = Dominator.idom ctx <| g.FindVertexByData 1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.idom ctx <| g.FindVertexByData 2
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctx <| g.FindVertexByData 3
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.idom ctx <| g.FindVertexByData 4
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.idom ctx <| g.FindVertexByData 5
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.idom ctx <| g.FindVertexByData 6
    Assert.AreEqual (2, getVertexVal v)

  [<TestMethod>]
  [<DynamicData(nameof Basic.GraphTypes)>]
  member __.``Dominator Test 2`` (t) =
    let g, _ = digraph2 t
    let ctx = Dominator.initDominatorContext g
    let v = Dominator.idom ctx <| g.FindVertexByData 1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.idom ctx <| g.FindVertexByData 2
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctx <| g.FindVertexByData 3
    Assert.AreEqual (1, getVertexVal v)
    let v = Dominator.idom ctx <| g.FindVertexByData 4
    Assert.AreEqual (3, getVertexVal v)
    let v = Dominator.idom ctx <| g.FindVertexByData 5
    Assert.AreEqual (4, getVertexVal v)
    let v = Dominator.idom ctx <| g.FindVertexByData 6
    Assert.AreEqual (4, getVertexVal v)

  [<TestMethod>]
  [<DynamicData(nameof Basic.GraphTypes)>]
  member __.``Dominator Test 3`` (t) =
    let g, _ = digraph6 t
    let ctx = Dominator.initDominatorContext g
    let v = Dominator.idom ctx <| g.FindVertexByData 19
    Assert.IsTrue (18 <> getVertexVal v)

  [<TestMethod>]
  [<DynamicData(nameof Basic.GraphTypes)>]
  member __.``Post-Dominator Test`` (t) =
    let g, _ = digraph1 t
    let ctx = Dominator.initDominatorContext g
    let v = Dominator.ipdom ctx <| g.FindVertexByData 1
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.ipdom ctx <| g.FindVertexByData 2
    Assert.AreEqual (6, getVertexVal v)
    let v = Dominator.ipdom ctx <| g.FindVertexByData 3
    Assert.AreEqual (5, getVertexVal v)
    let v = Dominator.ipdom ctx <| g.FindVertexByData 4
    Assert.AreEqual (5, getVertexVal v)
    let v = Dominator.ipdom ctx <| g.FindVertexByData 5
    Assert.AreEqual (2, getVertexVal v)
    let v = Dominator.ipdom ctx <| g.FindVertexByData 6
    Assert.IsTrue (v.IsNone)

  [<TestMethod>]
  [<DynamicData(nameof Basic.GraphTypes)>]
  member __.``Post-Dominator Test 2`` (t) =
    let g, _ = digraph3 t
    let ctx = Dominator.initDominatorContext g
    let v = Dominator.ipdom ctx <| g.FindVertexByData 1
    Assert.IsTrue (v.IsNone)
    let v = Dominator.ipdom ctx <| g.FindVertexByData 2
    Assert.AreEqual (4, getVertexVal v)
    let v = Dominator.ipdom ctx <| g.FindVertexByData 3
    Assert.IsTrue (v.IsNone)
    let v = Dominator.ipdom ctx <| g.FindVertexByData 4
    Assert.IsTrue (v.IsNone)
    let v = Dominator.ipdom ctx <| g.FindVertexByData 5
    Assert.IsTrue (v.IsNone)

  [<TestMethod>]
  [<DynamicData(nameof Basic.GraphTypes)>]
  member __.``Dominance Frontier Test`` (t) =
    let g, _ = digraph4 t
    let ctx = Dominator.initDominatorContext g
    let df = Dominator.frontier ctx <| g.FindVertexByData 5 |> List.toArray
    let df = df |> Array.map (fun v -> v.VData) |> Array.sort
    CollectionAssert.AreEqual (df, [|4; 5; 12; 13|])
    let df = Dominator.frontier ctx <| g.FindVertexByData 9 |> List.toArray
    let df = df |> Array.map (fun v -> v.VData) |> Array.sort
    CollectionAssert.AreEqual (df, [|12|])

  [<TestMethod; Timeout(1000)>]
  [<DynamicData(nameof Basic.GraphTypes)>]
  member __.``Root Node Loop Test`` (t) =
    let g, _ = digraph5 t
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
