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

  static member TestData =
    [| [| box Persistent; box Lengauer |]
       [| box Imperative; box Lengauer |]
       [| box Persistent; box Cooper |]
       [| box Imperative; box Cooper |] |]

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Dominator Test 1`` (t, alg) =
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
  member __.``Dominator Test 2`` (t, alg) =
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
  member __.``Dominator Test 3`` (t, alg) =
    let g, _ = digraph6 t
    let dom: IDominator<_, _> = instantiate g alg
    let v = dom.ImmediateDominator <| g.FindVertexByData 19
    Assert.IsTrue (18 <> v.VData)

  [<TestMethod>]
  [<DynamicData(nameof DominatorTests.TestData)>]
  member __.``Post-Dominator Test`` (t, alg) =
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
  member __.``Post-Dominator Test 2`` (t, alg) =
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
  member __.``Dominance Frontier Test`` (t, alg) =
    let g, _ = digraph4 t
    let dom: IDominator<_, _> = instantiate g alg
    let df = dom.DominanceFrontier <| g.FindVertexByData 5 |> Seq.toArray
    let df = df |> Array.map (fun v -> v.VData) |> Array.sort
    CollectionAssert.AreEqual (df, [|4; 5; 12; 13|])
    let df = dom.DominanceFrontier <| g.FindVertexByData 9 |> Seq.toArray
    let df = df |> Array.map (fun v -> v.VData) |> Array.sort
    CollectionAssert.AreEqual (df, [|12|])

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
