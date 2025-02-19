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

type DominatorAlgorithm =
  | Lengauer
  | Cooper

[<TestClass>]
type DominatorTests () =
  let instantiate g = function
    | Lengauer -> Dominator.LengauerTarjan.create g
    | Cooper -> Dominator.Cooper.create g

  let getDominators dom g i =
    (g: IDiGraph<_, _>).FindVertexByData i
    |> (dom: IDominator<_, _>).Dominators
    |> Seq.map (fun v -> v.VData) |> Set.ofSeq

  let getDominanceFrontier dom g i =
    (g: IDiGraph<_, _>).FindVertexByData i
    |> (dom: IDominator<_, _>).DominanceFrontier
    |> Seq.map (fun v -> v.VData) |> Set.ofSeq

  let getPostDominators dom g i =
    (g: IDiGraph<_, _>).FindVertexByData i
    |> (dom: IDominator<_, _>).PostDominators
    |> Seq.map (fun v -> v.VData) |> Set.ofSeq

  static member TestData =
    [| [| box Persistent; box Lengauer |]
       [| box Imperative; box Lengauer |]
       [| box Persistent; box Cooper |]
       [| box Imperative; box Cooper |] |]

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Immediate Dominator Test 1`` (t, alg) =
    let g, _ = digraph1 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsTrue (isNull v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    Assert.AreEqual<int> (2, v.VData)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Dominators Test 1`` (t, alg) =
    let g, _ = digraph1 t
    let dom: IDominator<_, _> = instantiate g alg
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.isEmpty ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 6
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Dominance Frontier Test 1`` (t, alg) =
    let g, _ = digraph1 t
    let dom: IDominator<_, _> = instantiate g alg
    let df = getDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 2 ] = df)
    let df = getDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 5 ] = df)
    let df = getDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 5 ] = df)
    let df = getDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 2 ] = df)
    let df = getDominanceFrontier dom g 6
    Assert.IsTrue (Set.isEmpty df)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Immediate Post-Dominator Test 1`` (t, alg) =
    let g, _ = digraph1 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (6, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (5, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (5, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    Assert.IsTrue (isNull v)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Post-Dominators Test 1`` (t, alg) =
    let g, _ = digraph1 t
    let dom: IDominator<_, _> = instantiate g alg
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 2; 6 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 6 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 2; 5; 6 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 2; 5; 6 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 2; 6 ] = pds)
    let pds = getPostDominators dom g 6
    Assert.IsTrue (Set.isEmpty pds)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Immediate Dominator Test 2`` (t, alg) =
    let g, _ = digraph2 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsTrue (isNull v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (3, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (4, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    Assert.AreEqual<int> (4, v.VData)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Dominators Test 2`` (t, alg) =
    let g, _ = digraph2 t
    let dom: IDominator<_, _> = instantiate g alg
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.isEmpty ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1; 3 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 3; 4 ] = ds)
    let ds = getDominators dom g 6
    Assert.IsTrue (Set.ofList [ 1; 3; 4 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Dominance Frontier Test 2`` (t, alg) =
    let g, _ = digraph2 t
    let dom: IDominator<_, _> = instantiate g alg
    let df = getDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getDominanceFrontier dom g 2
    Assert.IsTrue (Set.isEmpty df)
    let df = getDominanceFrontier dom g 3
    Assert.IsTrue (Set.isEmpty df)
    let df = getDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 4 ] = df)
    let df = getDominanceFrontier dom g 5
    Assert.IsTrue (Set.isEmpty df)
    let df = getDominanceFrontier dom g 6
    Assert.IsTrue (Set.ofList [ 4 ] = df)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Immediate Post-Dominator Test 2`` (t, alg) =
    let g, _ = digraph2 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.IsTrue (4 = v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    Assert.IsTrue (5 = v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    Assert.IsTrue (4 = v.VData)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Post-Dominators Test 2`` (t, alg) =
    let g, _ = digraph2 t
    let dom: IDominator<_, _> = instantiate g alg
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.isEmpty pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.isEmpty pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 4; 5 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 5 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.isEmpty pds)
    let pds = getPostDominators dom g 6
    Assert.IsTrue (Set.ofList [ 4; 5 ] = pds)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Immediate Dominator Test 3`` (t, alg) =
    let g, _ = digraph3 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsTrue (isNull v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (3, v.VData)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Dominators Test 3`` (t, alg) =
    let g, _ = digraph3 t
    let dom: IDominator<_, _> = instantiate g alg
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.isEmpty ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 3 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Dominance Frontier Test 3`` (t, alg) =
    let g, _ = digraph3 t
    let dom: IDominator<_, _> = instantiate g alg
    let df = getDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 4 ] = df)
    let df = getDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 4 ] = df)
    let df = getDominanceFrontier dom g 4
    Assert.IsTrue (Set.isEmpty df)
    let df = getDominanceFrontier dom g 5
    Assert.IsTrue (Set.isEmpty df)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Immediate Post-Dominator Test 3`` (t, alg) =
    let g, _ = digraph3 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (4, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    Assert.IsTrue (isNull v)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Post-Dominators Test 3`` (t, alg) =
    let g, _ = digraph3 t
    let dom: IDominator<_, _> = instantiate g alg
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.isEmpty pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 4 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.isEmpty pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.isEmpty pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.isEmpty pds)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Immediate Dominator Test 4`` (t, alg) =
    let g, _ = digraph4 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsTrue (isNull v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    Assert.AreEqual<int> (5, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 7
    Assert.AreEqual<int> (5, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 8
    Assert.AreEqual<int> (5, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 9
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 10
    Assert.AreEqual<int> (9, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 11
    Assert.AreEqual<int> (9, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 12
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 13
    Assert.AreEqual<int> (1, v.VData)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Dominators Test 4`` (t, alg) =
    let g, _ = digraph4 t
    let dom: IDominator<_, _> = instantiate g alg
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.isEmpty ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 6
    Assert.IsTrue (Set.ofList [ 1; 5 ] = ds)
    let ds = getDominators dom g 7
    Assert.IsTrue (Set.ofList [ 1; 5 ] = ds)
    let ds = getDominators dom g 8
    Assert.IsTrue (Set.ofList [ 1; 5 ] = ds)
    let ds = getDominators dom g 9
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 10
    Assert.IsTrue (Set.ofList [ 1; 9 ] = ds)
    let ds = getDominators dom g 11
    Assert.IsTrue (Set.ofList [ 1; 9 ] = ds)
    let ds = getDominators dom g 12
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 13
    Assert.IsTrue (Set.ofList [ 1 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Dominance Frontier Test 4`` (t, alg) =
    let g, _ = digraph4 t
    let dom: IDominator<_, _> = instantiate g alg
    let df = getDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 4 ] = df)
    let df = getDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 3; 4 ] = df)
    let df = getDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 13 ] = df)
    let df = getDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 4; 5; 12; 13 ] = df)
    let df = getDominanceFrontier dom g 6
    Assert.IsTrue (Set.ofList [ 4; 8 ] = df)
    let df = getDominanceFrontier dom g 7
    Assert.IsTrue (Set.ofList [ 8; 12 ] = df)
    let df = getDominanceFrontier dom g 8
    Assert.IsTrue (Set.ofList [ 5; 13 ] = df)
    let df = getDominanceFrontier dom g 9
    Assert.IsTrue (Set.ofList [ 12 ] = df)
    let df = getDominanceFrontier dom g 10
    Assert.IsTrue (Set.ofList [ 12 ] = df)
    let df = getDominanceFrontier dom g 11
    Assert.IsTrue (Set.ofList [ 12 ] = df)
    let df = getDominanceFrontier dom g 12
    Assert.IsTrue (Set.ofList [ 13 ] = df)
    let df = getDominanceFrontier dom g 13
    Assert.IsTrue (Set.isEmpty df)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Immediate Post-Dominator Test 4`` (t, alg) =
    let g, _ = digraph4 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.AreEqual<int> (13, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (3, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (4, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (13, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (13, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    Assert.AreEqual<int> (13, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 7
    Assert.AreEqual<int> (13, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 8
    Assert.AreEqual<int> (13, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 9
    Assert.AreEqual<int> (12, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 10
    Assert.AreEqual<int> (12, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 11
    Assert.AreEqual<int> (12, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 12
    Assert.AreEqual<int> (13, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 13
    Assert.IsTrue (isNull v)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Post-Dominators Test 4`` (t, alg) =
    let g, _ = digraph4 t
    let dom: IDominator<_, _> = instantiate g alg
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 13 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 3; 4; 13 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 4; 13 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 13 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 13 ] = pds)
    let pds = getPostDominators dom g 6
    Assert.IsTrue (Set.ofList [ 13 ] = pds)
    let pds = getPostDominators dom g 7
    Assert.IsTrue (Set.ofList [ 13 ] = pds)
    let pds = getPostDominators dom g 8
    Assert.IsTrue (Set.ofList [ 13 ] = pds)
    let pds = getPostDominators dom g 9
    Assert.IsTrue (Set.ofList [ 12; 13 ] = pds)
    let pds = getPostDominators dom g 10
    Assert.IsTrue (Set.ofList [ 12; 13 ] = pds)
    let pds = getPostDominators dom g 11
    Assert.IsTrue (Set.ofList [ 12; 13 ] = pds)
    let pds = getPostDominators dom g 12
    Assert.IsTrue (Set.ofList [ 13 ] = pds)
    let pds = getPostDominators dom g 13
    Assert.IsTrue (Set.isEmpty pds)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Immediate Dominator Test 5`` (t, alg) =
    let g, _ = digraph5 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsTrue (isNull v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (3, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    Assert.AreEqual<int> (1, v.VData)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Dominators Test 5`` (t, alg) =
    let g, _ = digraph5 t
    let dom: IDominator<_, _> = instantiate g alg
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.isEmpty ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 3 ] = ds)
    let ds = getDominators dom g 6
    Assert.IsTrue (Set.ofList [ 1 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Dominance Frontier Test 5`` (t, alg) =
    let g, _ = digraph5 t
    let dom: IDominator<_, _> = instantiate g alg
    let df = getDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 4 ] = df)
    let df = getDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 4; 6 ] = df)
    let df = getDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 6 ] = df)
    let df = getDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 6 ] = df)
    let df = getDominanceFrontier dom g 6
    Assert.IsTrue (Set.isEmpty df)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Immediate Post-Dominator Test 5`` (t, alg) =
    let g, _ = digraph5 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.AreEqual<int> (6, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (4, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (6, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (6, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (6, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    Assert.IsTrue (isNull v)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Post-Dominators Test 5`` (t, alg) =
    let g, _ = digraph5 t
    let dom: IDominator<_, _> = instantiate g alg
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 6 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 4; 6 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 6 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 6 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 6 ] = pds)
    let pds = getPostDominators dom g 6
    Assert.IsTrue (Set.isEmpty pds)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Immediate Dominator Test 6`` (t, alg) =
    let g, _ = digraph6 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsTrue (isNull v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (3, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    Assert.AreEqual<int> (3, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 7
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 8
    Assert.AreEqual<int> (5, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 9
    Assert.AreEqual<int> (7, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 10
    Assert.AreEqual<int> (5, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 11
    Assert.AreEqual<int> (7, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 12
    Assert.AreEqual<int> (9, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 13
    Assert.AreEqual<int> (9, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 14
    Assert.AreEqual<int> (13, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 15
    Assert.AreEqual<int> (13, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 16
    Assert.AreEqual<int> (13, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 17
    Assert.AreEqual<int> (16, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 18
    Assert.AreEqual<int> (16, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 19
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 20
    Assert.AreEqual<int> (18, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 21
    Assert.AreEqual<int> (19, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 22
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 23
    Assert.AreEqual<int> (19, v.VData)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Dominators Test 6`` (t, alg) =
    let g, _ = digraph6 t
    let dom: IDominator<_, _> = instantiate g alg
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.isEmpty ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 3 ] = ds)
    let ds = getDominators dom g 6
    Assert.IsTrue (Set.ofList [ 1; 3 ] = ds)
    let ds = getDominators dom g 7
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 8
    Assert.IsTrue (Set.ofList [ 1; 3; 5 ] = ds)
    let ds = getDominators dom g 9
    Assert.IsTrue (Set.ofList [ 1; 2; 7 ] = ds)
    let ds = getDominators dom g 10
    Assert.IsTrue (Set.ofList [ 1; 3; 5 ] = ds)
    let ds = getDominators dom g 11
    Assert.IsTrue (Set.ofList [ 1; 2; 7 ] = ds)
    let ds = getDominators dom g 12
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9 ] = ds)
    let ds = getDominators dom g 13
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9 ] = ds)
    let ds = getDominators dom g 14
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 13 ] = ds)
    let ds = getDominators dom g 15
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 13 ] = ds)
    let ds = getDominators dom g 16
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 13 ] = ds)
    let ds = getDominators dom g 17
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 13; 16 ] = ds)
    let ds = getDominators dom g 18
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 13; 16 ] = ds)
    let ds = getDominators dom g 19
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 20
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 13; 16; 18 ] = ds)
    let ds = getDominators dom g 21
    Assert.IsTrue (Set.ofList [ 1; 19 ] = ds)
    let ds = getDominators dom g 22
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 23
    Assert.IsTrue (Set.ofList [ 1; 19 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Dominance Frontier Test 6`` (t, alg) =
    let g, _ = digraph6 t
    let dom: IDominator<_, _> = instantiate g alg
    let df = getDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 19; 22 ] = df)
    let df = getDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 19 ] = df)
    let df = getDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 7 ] = df)
    let df = getDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 19 ] = df)
    let df = getDominanceFrontier dom g 6
    Assert.IsTrue (Set.isEmpty df)
    let df = getDominanceFrontier dom g 7
    Assert.IsTrue (Set.ofList [ 19; 22 ] = df)
    let df = getDominanceFrontier dom g 8
    Assert.IsTrue (Set.ofList [ 10 ] = df)
    let df = getDominanceFrontier dom g 9
    Assert.IsTrue (Set.ofList [ 19; 22 ] = df)
    let df = getDominanceFrontier dom g 10
    Assert.IsTrue (Set.ofList [ 19 ] = df)
    let df = getDominanceFrontier dom g 11
    Assert.IsTrue (Set.ofList [ 22 ] = df)
    let df = getDominanceFrontier dom g 12
    Assert.IsTrue (Set.ofList [ 13 ] = df)
    let df = getDominanceFrontier dom g 13
    Assert.IsTrue (Set.ofList [ 19; 22 ] = df)
    let df = getDominanceFrontier dom g 14
    Assert.IsTrue (Set.ofList [ 16 ] = df)
    let df = getDominanceFrontier dom g 15
    Assert.IsTrue (Set.ofList [ 16 ] = df)
    let df = getDominanceFrontier dom g 16
    Assert.IsTrue (Set.ofList [ 19; 22 ] = df)
    let df = getDominanceFrontier dom g 17
    Assert.IsTrue (Set.ofList [ 18 ] = df)
    let df = getDominanceFrontier dom g 18
    Assert.IsTrue (Set.ofList [ 19; 22 ] = df)
    let df = getDominanceFrontier dom g 19
    Assert.IsTrue (Set.ofList [ 22 ] = df)
    let df = getDominanceFrontier dom g 20
    Assert.IsTrue (Set.ofList [ 22 ] = df)
    let df = getDominanceFrontier dom g 21
    Assert.IsTrue (Set.ofList [ 22 ] = df)
    let df = getDominanceFrontier dom g 22
    Assert.IsTrue (Set.isEmpty df)
    let df = getDominanceFrontier dom g 23
    Assert.IsTrue (Set.isEmpty df)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Immediate Post-Dominator Test 6`` (t, alg) =
    let g, _ = digraph6 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (7, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (7, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (10, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 7
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 8
    Assert.AreEqual<int> (10, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 9
    Assert.AreEqual<int> (13, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 10
    Assert.AreEqual<int> (19, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 11
    Assert.AreEqual<int> (22, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 12
    Assert.AreEqual<int> (13, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 13
    Assert.AreEqual<int> (16, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 14
    Assert.AreEqual<int> (16, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 15
    Assert.AreEqual<int> (16, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 16
    Assert.AreEqual<int> (18, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 17
    Assert.AreEqual<int> (18, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 18
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 19
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 20
    Assert.AreEqual<int> (22, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 21
    Assert.AreEqual<int> (22, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 22
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 23
    Assert.IsTrue (isNull v)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Post-Dominators Test 6`` (t, alg) =
    let g, _ = digraph6 t
    let dom: IDominator<_, _> = instantiate g alg
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.isEmpty pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 7 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.isEmpty pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 7 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 10; 19 ] = pds)
    let pds = getPostDominators dom g 6
    Assert.IsTrue (Set.isEmpty pds)
    let pds = getPostDominators dom g 7
    Assert.IsTrue (Set.isEmpty pds)
    let pds = getPostDominators dom g 8
    Assert.IsTrue (Set.ofList [ 10; 19 ] = pds)
    let pds = getPostDominators dom g 9
    Assert.IsTrue (Set.ofList [ 13; 16; 18 ] = pds)
    let pds = getPostDominators dom g 10
    Assert.IsTrue (Set.ofList [ 19 ] = pds)
    let pds = getPostDominators dom g 11
    Assert.IsTrue (Set.ofList [ 22 ] = pds)
    let pds = getPostDominators dom g 12
    Assert.IsTrue (Set.ofList [ 13; 16; 18 ] = pds)
    let pds = getPostDominators dom g 13
    Assert.IsTrue (Set.ofList [ 16; 18 ] = pds)
    let pds = getPostDominators dom g 14
    Assert.IsTrue (Set.ofList [ 16; 18 ] = pds)
    let pds = getPostDominators dom g 15
    Assert.IsTrue (Set.ofList [ 16; 18 ] = pds)
    let pds = getPostDominators dom g 16
    Assert.IsTrue (Set.ofList [ 18 ] = pds)
    let pds = getPostDominators dom g 17
    Assert.IsTrue (Set.ofList [ 18 ] = pds)
    let pds = getPostDominators dom g 18
    Assert.IsTrue (Set.isEmpty pds)
    let pds = getPostDominators dom g 19
    Assert.IsTrue (Set.isEmpty pds)
    let pds = getPostDominators dom g 20
    Assert.IsTrue (Set.ofList [ 22 ] = pds)
    let pds = getPostDominators dom g 21
    Assert.IsTrue (Set.ofList [ 22 ] = pds)
    let pds = getPostDominators dom g 22
    Assert.IsTrue (Set.isEmpty pds)
    let pds = getPostDominators dom g 23
    Assert.IsTrue (Set.isEmpty pds)

  [<TestMethod; Timeout(1000)>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Root Node Loop Test`` (t, alg) =
    let g, _ = digraph5 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsTrue (isNull v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (3, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    Assert.AreEqual<int> (1, v.VData)