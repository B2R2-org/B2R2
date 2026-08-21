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

open System.Diagnostics
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinGraph.Dominance
open B2R2.MiddleEnd.BinGraph.Tests.Examples

type DominanceAlgorithm =
  | DomIterative
  | DomLengauer
  | DomSimpleLengauer
  | DomSNCA
  | DomCooper
  | DBS

type DominanceFrontierAlgorithm =
  | DFCytron
  | DFCooper

[<TestClass>]
type DominanceTests() =
  let instantiate g domAlgo dfAlgo algo =
    match domAlgo, dfAlgo, algo with
    | DomIterative, DFCytron, _ ->
      IterativeDominance.create g (CytronDominanceFrontier())
    | DomIterative, DFCooper, _ ->
      IterativeDominance.create g (CooperDominanceFrontier())
    | DomLengauer, DFCytron, _ ->
      LengauerTarjanDominance.create g (CytronDominanceFrontier())
    | DomLengauer, DFCooper, _ ->
      LengauerTarjanDominance.create g (CooperDominanceFrontier())
    | DomSimpleLengauer, DFCytron, _ ->
      SimpleLengauerTarjanDominance.create g (CytronDominanceFrontier())
    | DomSimpleLengauer, DFCooper, _ ->
      SimpleLengauerTarjanDominance.create g (CooperDominanceFrontier())
    | DomSNCA, DFCytron, _ ->
      SemiNCADominance.create g (CytronDominanceFrontier())
    | DomSNCA, DFCooper, _ ->
      SemiNCADominance.create g (CooperDominanceFrontier())
    | DomCooper, DFCytron, _ ->
      CooperDominance.create g (CytronDominanceFrontier())
    | DomCooper, DFCooper, _ ->
      CooperDominance.create g (CooperDominanceFrontier())
    | DBS, DFCytron, Some sAlgo ->
      DepthBasedSearchDominance.create g (CytronDominanceFrontier()) sAlgo
    | DBS, DFCooper, Some sAlgo ->
      DepthBasedSearchDominance.create g (CooperDominanceFrontier()) sAlgo
    | _ ->
      failwithf "Invalid test: %A, %A, %A" domAlgo dfAlgo algo

  let getDominators dom g i =
    (g: IDiGraphAccessible<_, _>).FindVertexByData i
    |> (dom: IDominance<_, _>).Dominators
    |> Set.ofSeq

  let getDominanceFrontier dom g i =
    (g: IDiGraphAccessible<_, _>).FindVertexByData i
    |> (dom: IDominance<_, _>).DominanceFrontier
    |> Set.ofSeq

  let getPostDominators dom g i =
    (g: IDiGraphAccessible<_, _>).FindVertexByData i
    |> (dom: IDominance<_, _>).PostDominators
    |> Set.ofSeq

  let getPostDominanceFrontier dom g i =
    (g: IDiGraphAccessible<_, _>).FindVertexByData i
    |> (dom: IDominance<_, _>).PostDominanceFrontier
    |> Set.ofSeq

  let assertEqual (g: IDiGraphAccessible<_, _>) expectedValue v =
    let expectedVertex = g.FindVertexByData expectedValue
    Assert.AreEqual(expectedVertex, v)
    Assert.AreEqual(expectedValue, v.VData)

  let assertSetEqual (g: IDiGraphAccessible<_, _>) expectedValues vertices =
    let expectedVertices = expectedValues |> Seq.map g.FindVertexByData
    Assert.AreEqual(Set.ofSeq expectedVertices, Set.ofSeq vertices)

  let assertVertexNotFound f =
    Assert.Throws<VertexNotFoundException>(System.Action f) |> ignore

  static member TestData =
    [| [| box Persistent; box DomIterative; box DFCytron; box None |]
       [| box Persistent; box DomIterative; box DFCooper; box None |]
       [| box Imperative; box DomIterative; box DFCytron; box None |]
       [| box Imperative; box DomIterative; box DFCooper; box None |]
       [| box Persistent; box DomLengauer; box DFCytron; box None |]
       [| box Persistent; box DomLengauer; box DFCooper; box None |]
       [| box Imperative; box DomLengauer; box DFCytron; box None |]
       [| box Imperative; box DomLengauer; box DFCooper; box None |]
       [| box Persistent; box DomSimpleLengauer; box DFCytron; box None |]
       [| box Persistent; box DomSimpleLengauer; box DFCooper; box None |]
       [| box Imperative; box DomSimpleLengauer; box DFCytron; box None |]
       [| box Imperative; box DomSimpleLengauer; box DFCooper; box None |]
       [| box Persistent; box DomSNCA; box DFCytron; box None |]
       [| box Persistent; box DomSNCA; box DFCooper; box None |]
       [| box Imperative; box DomSNCA; box DFCytron; box None |]
       [| box Imperative; box DomSNCA; box DFCooper; box None |]
       [| box Persistent; box DomCooper; box DFCytron; box None |]
       [| box Persistent; box DomCooper; box DFCooper; box None |]
       [| box Imperative; box DomCooper; box DFCytron; box None |]
       [| box Imperative; box DomCooper; box DFCooper; box None |]
       [| box Persistent
          box DBS
          box DFCytron
          box (Some DepthBasedSearchDominance.SemiNCA) |]
       [| box Persistent
          box DBS
          box DFCooper
          box (Some DepthBasedSearchDominance.SemiNCA) |]
       [| box Imperative
          box DBS
          box DFCytron
          box (Some DepthBasedSearchDominance.SemiNCA) |]
       [| box Imperative
          box DBS
          box DFCooper
          box (Some DepthBasedSearchDominance.SemiNCA) |] |]

  static member ComparisonData =
    [| [| box DomLengauer
          box "99_objdump_clang_m32_O1_80b18d0.json"
          box None |]
       [| box DomLengauer
          box "499_gcc_base.amd64-m32-ccr-Ofast_clang_m32_Of_81428e0.json"
          box None |]
       [| box DomLengauer
          box "854_binutils-2.31.1_x86_gcc_nopie_o3_as-new_808b4e0.json"
          box None |]
       [| box DomLengauer
          box "4152_find_clang_O0_433cd0.json"
          box None |]
       [| box DomSNCA
          box "99_objdump_clang_m32_O1_80b18d0.json"
          box None |]
       [| box DomSNCA
          box "499_gcc_base.amd64-m32-ccr-Ofast_clang_m32_Of_81428e0.json"
          box None |]
       [| box DomSNCA
          box "854_binutils-2.31.1_x86_gcc_nopie_o3_as-new_808b4e0.json"
          box None |]
       [| box DomSNCA
          box "4152_find_clang_O0_433cd0.json"
          box None |]
       [| box DomCooper
          box "99_objdump_clang_m32_O1_80b18d0.json"
          box None |]
       [| box DomCooper
          box "499_gcc_base.amd64-m32-ccr-Ofast_clang_m32_Of_81428e0.json"
          box None |]
       [| box DomCooper
          box "854_binutils-2.31.1_x86_gcc_nopie_o3_as-new_808b4e0.json"
          box None |]
       [| box DomCooper
          box "4152_find_clang_O0_433cd0.json"
          box None |]
       [| box DBS
          box "99_objdump_clang_m32_O1_80b18d0.json"
          box (Some DepthBasedSearchDominance.SemiNCA) |]
       [| box DBS
          box "499_gcc_base.amd64-m32-ccr-Ofast_clang_m32_Of_81428e0.json"
          box (Some DepthBasedSearchDominance.SemiNCA) |]
       [| box DBS
          box "854_binutils-2.31.1_x86_gcc_nopie_o3_as-new_808b4e0.json"
          box (Some DepthBasedSearchDominance.SemiNCA) |]
       [| box DBS
          box "4152_find_clang_O0_433cd0.json"
          box (Some DepthBasedSearchDominance.SemiNCA) |] |]

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 1``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph1 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    assertEqual g 2 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    assertEqual g 2 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    assertEqual g 2 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    assertEqual g 2 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 1``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph1 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let ds = getDominators dom g 1
    assertSetEqual g [ 1 ] ds
    let ds = getDominators dom g 2
    assertSetEqual g [ 1; 2 ] ds
    let ds = getDominators dom g 3
    assertSetEqual g [ 1; 2; 3 ] ds
    let ds = getDominators dom g 4
    assertSetEqual g [ 1; 2; 4 ] ds
    let ds = getDominators dom g 5
    assertSetEqual g [ 1; 2; 5 ] ds
    let ds = getDominators dom g 6
    assertSetEqual g [ 1; 2; 6 ] ds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 1``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph1 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 2
    assertSetEqual g [ 2 ] df
    let df = getDominanceFrontier dom g 3
    assertSetEqual g [ 5 ] df
    let df = getDominanceFrontier dom g 4
    assertSetEqual g [ 5 ] df
    let df = getDominanceFrontier dom g 5
    assertSetEqual g [ 2 ] df
    let df = getDominanceFrontier dom g 6
    Assert.AreEqual<int>(0, Set.count df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 1``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph1 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    assertEqual g 2 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    assertEqual g 6 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    assertEqual g 5 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    assertEqual g 5 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    assertEqual g 2 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    Assert.IsNull(v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 1``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph1 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let pds = getPostDominators dom g 1
    assertSetEqual g [ 1; 2; 6 ] pds
    let pds = getPostDominators dom g 2
    assertSetEqual g [ 2; 6 ] pds
    let pds = getPostDominators dom g 3
    assertSetEqual g [ 2; 3; 5; 6 ] pds
    let pds = getPostDominators dom g 4
    assertSetEqual g [ 2; 4; 5; 6 ] pds
    let pds = getPostDominators dom g 5
    assertSetEqual g [ 2; 5; 6 ] pds
    let pds = getPostDominators dom g 6
    assertSetEqual g [ 6 ] pds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 1``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph1 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getPostDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getPostDominanceFrontier dom g 2
    assertSetEqual g [ 2 ] df
    let df = getPostDominanceFrontier dom g 3
    assertSetEqual g [ 2 ] df
    let df = getPostDominanceFrontier dom g 4
    assertSetEqual g [ 2 ] df
    let df = getPostDominanceFrontier dom g 5
    assertSetEqual g [ 2 ] df
    let df = getPostDominanceFrontier dom g 6
    Assert.AreEqual<int>(0, Set.count df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 2``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph2 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    assertEqual g 3 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    assertEqual g 4 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    assertEqual g 4 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 2``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph2 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let ds = getDominators dom g 1
    assertSetEqual g [ 1 ] ds
    let ds = getDominators dom g 2
    assertSetEqual g [ 1; 2 ] ds
    let ds = getDominators dom g 3
    assertSetEqual g [ 1; 3 ] ds
    let ds = getDominators dom g 4
    assertSetEqual g [ 1; 3; 4 ] ds
    let ds = getDominators dom g 5
    assertSetEqual g [ 1; 3; 4; 5 ] ds
    let ds = getDominators dom g 6
    assertSetEqual g [ 1; 3; 4; 6 ] ds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 2``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph2 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 2
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 3
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 4
    assertSetEqual g [ 4 ] df
    let df = getDominanceFrontier dom g 5
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 6
    assertSetEqual g [ 4 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 2``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph2 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    assertEqual g 4 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    assertEqual g 5 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    assertEqual g 4 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 2``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph2 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let pds = getPostDominators dom g 1
    assertSetEqual g [ 1 ] pds
    let pds = getPostDominators dom g 2
    assertSetEqual g [ 2 ] pds
    let pds = getPostDominators dom g 3
    assertSetEqual g [ 3; 4; 5 ] pds
    let pds = getPostDominators dom g 4
    assertSetEqual g [ 4; 5 ] pds
    let pds = getPostDominators dom g 5
    assertSetEqual g [ 5 ] pds
    let pds = getPostDominators dom g 6
    assertSetEqual g [ 4; 5; 6 ] pds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 2``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph2 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getPostDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getPostDominanceFrontier dom g 2
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 3
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 4
    assertSetEqual g [ 1; 4 ] df
    let df = getPostDominanceFrontier dom g 5
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 6
    assertSetEqual g [ 4 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 3``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph3 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    assertEqual g 3 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 3``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph3 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let ds = getDominators dom g 1
    assertSetEqual g [ 1 ] ds
    let ds = getDominators dom g 2
    assertSetEqual g [ 1; 2 ] ds
    let ds = getDominators dom g 3
    assertSetEqual g [ 1; 3 ] ds
    let ds = getDominators dom g 4
    assertSetEqual g [ 1; 4 ] ds
    let ds = getDominators dom g 5
    assertSetEqual g [ 1; 3; 5 ] ds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 3``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph3 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 2
    assertSetEqual g [ 4 ] df
    let df = getDominanceFrontier dom g 3
    assertSetEqual g [ 4 ] df
    let df = getDominanceFrontier dom g 4
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 5
    Assert.AreEqual<int>(0, Set.count df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 3``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph3 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    assertEqual g 4 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    Assert.IsNull(v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 3``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph3 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let pds = getPostDominators dom g 1
    assertSetEqual g [ 1 ] pds
    let pds = getPostDominators dom g 2
    assertSetEqual g [ 2; 4 ] pds
    let pds = getPostDominators dom g 3
    assertSetEqual g [ 3 ] pds
    let pds = getPostDominators dom g 4
    assertSetEqual g [ 4 ] pds
    let pds = getPostDominators dom g 5
    assertSetEqual g [ 5 ] pds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 3``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph3 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getPostDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getPostDominanceFrontier dom g 2
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 3
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 4
    assertSetEqual g [ 1; 3 ] df
    let df = getPostDominanceFrontier dom g 5
    assertSetEqual g [ 3 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 4``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph4 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    assertEqual g 2 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    assertEqual g 5 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 7
    assertEqual g 5 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 8
    assertEqual g 5 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 9
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 10
    assertEqual g 9 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 11
    assertEqual g 9 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 12
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 13
    assertEqual g 1 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 4``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph4 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let ds = getDominators dom g 1
    assertSetEqual g [ 1 ] ds
    let ds = getDominators dom g 2
    assertSetEqual g [ 1; 2 ] ds
    let ds = getDominators dom g 3
    assertSetEqual g [ 1; 2; 3 ] ds
    let ds = getDominators dom g 4
    assertSetEqual g [ 1; 4 ] ds
    let ds = getDominators dom g 5
    assertSetEqual g [ 1; 5 ] ds
    let ds = getDominators dom g 6
    assertSetEqual g [ 1; 5; 6 ] ds
    let ds = getDominators dom g 7
    assertSetEqual g [ 1; 5; 7 ] ds
    let ds = getDominators dom g 8
    assertSetEqual g [ 1; 5; 8 ] ds
    let ds = getDominators dom g 9
    assertSetEqual g [ 1; 9 ] ds
    let ds = getDominators dom g 10
    assertSetEqual g [ 1; 9; 10 ] ds
    let ds = getDominators dom g 11
    assertSetEqual g [ 1; 9; 11 ] ds
    let ds = getDominators dom g 12
    assertSetEqual g [ 1; 12 ] ds
    let ds = getDominators dom g 13
    assertSetEqual g [ 1; 13 ] ds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 4``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph4 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 2
    assertSetEqual g [ 4 ] df
    let df = getDominanceFrontier dom g 3
    assertSetEqual g [ 3; 4 ] df
    let df = getDominanceFrontier dom g 4
    assertSetEqual g [ 13 ] df
    let df = getDominanceFrontier dom g 5
    assertSetEqual g [ 4; 5; 12; 13 ] df
    let df = getDominanceFrontier dom g 6
    assertSetEqual g [ 4; 8 ] df
    let df = getDominanceFrontier dom g 7
    assertSetEqual g [ 8; 12 ] df
    let df = getDominanceFrontier dom g 8
    assertSetEqual g [ 5; 13 ] df
    let df = getDominanceFrontier dom g 9
    assertSetEqual g [ 12 ] df
    let df = getDominanceFrontier dom g 10
    assertSetEqual g [ 12 ] df
    let df = getDominanceFrontier dom g 11
    assertSetEqual g [ 12 ] df
    let df = getDominanceFrontier dom g 12
    assertSetEqual g [ 13 ] df
    let df = getDominanceFrontier dom g 13
    Assert.AreEqual<int>(0, Set.count df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 4``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph4 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    assertEqual g 13 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    assertEqual g 3 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    assertEqual g 4 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    assertEqual g 13 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    assertEqual g 13 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    assertEqual g 13 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 7
    assertEqual g 13 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 8
    assertEqual g 13 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 9
    assertEqual g 12 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 10
    assertEqual g 12 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 11
    assertEqual g 12 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 12
    assertEqual g 13 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 13
    Assert.IsNull(v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 4``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph4 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let pds = getPostDominators dom g 1
    assertSetEqual g [ 1; 13 ] pds
    let pds = getPostDominators dom g 2
    assertSetEqual g [ 2; 3; 4; 13 ] pds
    let pds = getPostDominators dom g 3
    assertSetEqual g [ 3; 4; 13 ] pds
    let pds = getPostDominators dom g 4
    assertSetEqual g [ 4; 13 ] pds
    let pds = getPostDominators dom g 5
    assertSetEqual g [ 5; 13 ] pds
    let pds = getPostDominators dom g 6
    assertSetEqual g [ 6; 13 ] pds
    let pds = getPostDominators dom g 7
    assertSetEqual g [ 7; 13 ] pds
    let pds = getPostDominators dom g 8
    assertSetEqual g [ 8; 13 ] pds
    let pds = getPostDominators dom g 9
    assertSetEqual g [ 9; 12; 13 ] pds
    let pds = getPostDominators dom g 10
    assertSetEqual g [ 10; 12; 13 ] pds
    let pds = getPostDominators dom g 11
    assertSetEqual g [ 11; 12; 13 ] pds
    let pds = getPostDominators dom g 12
    assertSetEqual g [ 12; 13 ] pds
    let pds = getPostDominators dom g 13
    assertSetEqual g [ 13 ] pds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 4``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph4 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getPostDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getPostDominanceFrontier dom g 2
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 3
    assertSetEqual g [ 1; 3 ] df
    let df = getPostDominanceFrontier dom g 4
    assertSetEqual g [ 1; 6 ] df
    let df = getPostDominanceFrontier dom g 5
    assertSetEqual g [ 1; 8 ] df
    let df = getPostDominanceFrontier dom g 6
    assertSetEqual g [ 5 ] df
    let df = getPostDominanceFrontier dom g 7
    assertSetEqual g [ 5 ] df
    let df = getPostDominanceFrontier dom g 8
    assertSetEqual g [ 6; 7 ] df
    let df = getPostDominanceFrontier dom g 9
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 10
    assertSetEqual g [ 9 ] df
    let df = getPostDominanceFrontier dom g 11
    assertSetEqual g [ 9 ] df
    let df = getPostDominanceFrontier dom g 12
    assertSetEqual g [ 1; 7 ] df
    let df = getPostDominanceFrontier dom g 13
    Assert.AreEqual<int>(0, Set.count df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 5``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph5 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    assertEqual g 3 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    assertEqual g 1 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 5``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph5 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let ds = getDominators dom g 1
    assertSetEqual g [ 1 ] ds
    let ds = getDominators dom g 2
    assertSetEqual g [ 1; 2 ] ds
    let ds = getDominators dom g 3
    assertSetEqual g [ 1; 3 ] ds
    let ds = getDominators dom g 4
    assertSetEqual g [ 1; 4 ] ds
    let ds = getDominators dom g 5
    assertSetEqual g [ 1; 3; 5 ] ds
    let ds = getDominators dom g 6
    assertSetEqual g [ 1; 6 ] ds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 5``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph5 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getDominanceFrontier dom g 1
    assertSetEqual g [ 1 ] df
    let df = getDominanceFrontier dom g 2
    assertSetEqual g [ 4 ] df
    let df = getDominanceFrontier dom g 3
    assertSetEqual g [ 4; 6 ] df
    let df = getDominanceFrontier dom g 4
    assertSetEqual g [ 6 ] df
    let df = getDominanceFrontier dom g 5
    assertSetEqual g [ 6 ] df
    let df = getDominanceFrontier dom g 6
    assertSetEqual g [ 1 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 5``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph5 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    assertEqual g 6 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    assertEqual g 4 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    assertEqual g 6 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    assertEqual g 6 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    assertEqual g 6 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    Assert.IsNull(v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 5``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph5 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let pds = getPostDominators dom g 1
    assertSetEqual g [ 1; 6 ] pds
    let pds = getPostDominators dom g 2
    assertSetEqual g [ 2; 4; 6 ] pds
    let pds = getPostDominators dom g 3
    assertSetEqual g [ 3; 6 ] pds
    let pds = getPostDominators dom g 4
    assertSetEqual g [ 4; 6 ] pds
    let pds = getPostDominators dom g 5
    assertSetEqual g [ 5; 6 ] pds
    let pds = getPostDominators dom g 6
    assertSetEqual g [ 6 ] pds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 5``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph5 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getPostDominanceFrontier dom g 1
    assertSetEqual g [ 6 ] df
    let df = getPostDominanceFrontier dom g 2
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 3
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 4
    assertSetEqual g [ 1; 3 ] df
    let df = getPostDominanceFrontier dom g 5
    assertSetEqual g [ 3 ] df
    let df = getPostDominanceFrontier dom g 6
    assertSetEqual g [ 6 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 6``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph6 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    assertEqual g 2 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    assertEqual g 3 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    assertEqual g 3 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 7
    assertEqual g 2 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 8
    assertEqual g 5 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 9
    assertEqual g 7 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 10
    assertEqual g 5 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 11
    assertEqual g 7 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 12
    assertEqual g 9 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 13
    assertEqual g 9 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 14
    assertEqual g 13 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 15
    assertEqual g 13 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 16
    assertEqual g 13 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 17
    assertEqual g 16 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 18
    assertEqual g 16 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 19
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 20
    assertEqual g 18 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 21
    assertEqual g 19 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 22
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 23
    assertEqual g 19 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 6``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph6 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let ds = getDominators dom g 1
    assertSetEqual g [ 1 ] ds
    let ds = getDominators dom g 2
    assertSetEqual g [ 1; 2 ] ds
    let ds = getDominators dom g 3
    assertSetEqual g [ 1; 3 ] ds
    let ds = getDominators dom g 4
    assertSetEqual g [ 1; 2; 4 ] ds
    let ds = getDominators dom g 5
    assertSetEqual g [ 1; 3; 5 ] ds
    let ds = getDominators dom g 6
    assertSetEqual g [ 1; 3; 6 ] ds
    let ds = getDominators dom g 7
    assertSetEqual g [ 1; 2; 7 ] ds
    let ds = getDominators dom g 8
    assertSetEqual g [ 1; 3; 5; 8 ] ds
    let ds = getDominators dom g 9
    assertSetEqual g [ 1; 2; 7; 9 ] ds
    let ds = getDominators dom g 10
    assertSetEqual g [ 1; 3; 5; 10 ] ds
    let ds = getDominators dom g 11
    assertSetEqual g [ 1; 2; 7; 11 ] ds
    let ds = getDominators dom g 12
    assertSetEqual g [ 1; 2; 7; 9; 12 ] ds
    let ds = getDominators dom g 13
    assertSetEqual g [ 1; 2; 7; 9; 13 ] ds
    let ds = getDominators dom g 14
    assertSetEqual g [ 1; 2; 7; 9; 13; 14 ] ds
    let ds = getDominators dom g 15
    assertSetEqual g [ 1; 2; 7; 9; 13; 15 ] ds
    let ds = getDominators dom g 16
    assertSetEqual g [ 1; 2; 7; 9; 13; 16 ] ds
    let ds = getDominators dom g 17
    assertSetEqual g [ 1; 2; 7; 9; 13; 16; 17 ] ds
    let ds = getDominators dom g 18
    assertSetEqual g [ 1; 2; 7; 9; 13; 16; 18 ] ds
    let ds = getDominators dom g 19
    assertSetEqual g [ 1; 19 ] ds
    let ds = getDominators dom g 20
    assertSetEqual g [ 1; 2; 7; 9; 13; 16; 18; 20 ] ds
    let ds = getDominators dom g 21
    assertSetEqual g [ 1; 19; 21 ] ds
    let ds = getDominators dom g 22
    assertSetEqual g [ 1; 22 ] ds
    let ds = getDominators dom g 23
    assertSetEqual g [ 1; 19; 23 ] ds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 6``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph6 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 2
    assertSetEqual g [ 19; 22 ] df
    let df = getDominanceFrontier dom g 3
    assertSetEqual g [ 19 ] df
    let df = getDominanceFrontier dom g 4
    assertSetEqual g [ 7 ] df
    let df = getDominanceFrontier dom g 5
    assertSetEqual g [ 19 ] df
    let df = getDominanceFrontier dom g 6
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 7
    assertSetEqual g [ 19; 22 ] df
    let df = getDominanceFrontier dom g 8
    assertSetEqual g [ 10 ] df
    let df = getDominanceFrontier dom g 9
    assertSetEqual g [ 19; 22 ] df
    let df = getDominanceFrontier dom g 10
    assertSetEqual g [ 19 ] df
    let df = getDominanceFrontier dom g 11
    assertSetEqual g [ 22 ] df
    let df = getDominanceFrontier dom g 12
    assertSetEqual g [ 13 ] df
    let df = getDominanceFrontier dom g 13
    assertSetEqual g [ 19; 22 ] df
    let df = getDominanceFrontier dom g 14
    assertSetEqual g [ 16 ] df
    let df = getDominanceFrontier dom g 15
    assertSetEqual g [ 16 ] df
    let df = getDominanceFrontier dom g 16
    assertSetEqual g [ 19; 22 ] df
    let df = getDominanceFrontier dom g 17
    assertSetEqual g [ 18 ] df
    let df = getDominanceFrontier dom g 18
    assertSetEqual g [ 19; 22 ] df
    let df = getDominanceFrontier dom g 19
    assertSetEqual g [ 22 ] df
    let df = getDominanceFrontier dom g 20
    assertSetEqual g [ 22 ] df
    let df = getDominanceFrontier dom g 21
    assertSetEqual g [ 22 ] df
    let df = getDominanceFrontier dom g 22
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 23
    Assert.AreEqual<int>(0, Set.count df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 6``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph6 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    assertEqual g 7 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    assertEqual g 7 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    assertEqual g 10 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 7
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 8
    assertEqual g 10 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 9
    assertEqual g 13 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 10
    assertEqual g 19 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 11
    assertEqual g 22 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 12
    assertEqual g 13 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 13
    assertEqual g 16 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 14
    assertEqual g 16 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 15
    assertEqual g 16 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 16
    assertEqual g 18 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 17
    assertEqual g 18 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 18
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 19
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 20
    assertEqual g 22 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 21
    assertEqual g 22 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 22
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 23
    Assert.IsNull(v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 6``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph6 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let pds = getPostDominators dom g 1
    assertSetEqual g [ 1 ] pds
    let pds = getPostDominators dom g 2
    assertSetEqual g [ 2; 7 ] pds
    let pds = getPostDominators dom g 3
    assertSetEqual g [ 3 ] pds
    let pds = getPostDominators dom g 4
    assertSetEqual g [ 4; 7 ] pds
    let pds = getPostDominators dom g 5
    assertSetEqual g [ 5; 10; 19 ] pds
    let pds = getPostDominators dom g 6
    assertSetEqual g [ 6 ] pds
    let pds = getPostDominators dom g 7
    assertSetEqual g [ 7 ] pds
    let pds = getPostDominators dom g 8
    assertSetEqual g [ 8; 10; 19 ] pds
    let pds = getPostDominators dom g 9
    assertSetEqual g [ 9; 13; 16; 18 ] pds
    let pds = getPostDominators dom g 10
    assertSetEqual g [ 10; 19 ] pds
    let pds = getPostDominators dom g 11
    assertSetEqual g [ 11; 22 ] pds
    let pds = getPostDominators dom g 12
    assertSetEqual g [ 12; 13; 16; 18 ] pds
    let pds = getPostDominators dom g 13
    assertSetEqual g [ 13; 16; 18 ] pds
    let pds = getPostDominators dom g 14
    assertSetEqual g [ 14; 16; 18 ] pds
    let pds = getPostDominators dom g 15
    assertSetEqual g [ 15; 16; 18 ] pds
    let pds = getPostDominators dom g 16
    assertSetEqual g [ 16; 18 ] pds
    let pds = getPostDominators dom g 17
    assertSetEqual g [ 17; 18 ] pds
    let pds = getPostDominators dom g 18
    assertSetEqual g [ 18 ] pds
    let pds = getPostDominators dom g 19
    assertSetEqual g [ 19 ] pds
    let pds = getPostDominators dom g 20
    assertSetEqual g [ 20; 22 ] pds
    let pds = getPostDominators dom g 21
    assertSetEqual g [ 21; 22 ] pds
    let pds = getPostDominators dom g 22
    assertSetEqual g [ 22 ] pds
    let pds = getPostDominators dom g 23
    assertSetEqual g [ 23 ] pds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 6``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph6 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getPostDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getPostDominanceFrontier dom g 2
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 3
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 4
    assertSetEqual g [ 2 ] df
    let df = getPostDominanceFrontier dom g 5
    assertSetEqual g [ 3 ] df
    let df = getPostDominanceFrontier dom g 6
    assertSetEqual g [ 3 ] df
    let df = getPostDominanceFrontier dom g 7
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 8
    assertSetEqual g [ 5 ] df
    let df = getPostDominanceFrontier dom g 9
    assertSetEqual g [ 7 ] df
    let df = getPostDominanceFrontier dom g 10
    assertSetEqual g [ 3 ] df
    let df = getPostDominanceFrontier dom g 11
    assertSetEqual g [ 7 ] df
    let df = getPostDominanceFrontier dom g 12
    assertSetEqual g [ 9 ] df
    let df = getPostDominanceFrontier dom g 13
    assertSetEqual g [ 7 ] df
    let df = getPostDominanceFrontier dom g 14
    assertSetEqual g [ 13 ] df
    let df = getPostDominanceFrontier dom g 15
    assertSetEqual g [ 13 ] df
    let df = getPostDominanceFrontier dom g 16
    assertSetEqual g [ 7 ] df
    let df = getPostDominanceFrontier dom g 17
    assertSetEqual g [ 16 ] df
    let df = getPostDominanceFrontier dom g 18
    assertSetEqual g [ 7 ] df
    let df = getPostDominanceFrontier dom g 19
    assertSetEqual g [ 3; 18 ] df
    let df = getPostDominanceFrontier dom g 20
    assertSetEqual g [ 18 ] df
    let df = getPostDominanceFrontier dom g 21
    assertSetEqual g [ 19 ] df
    let df = getPostDominanceFrontier dom g 22
    assertSetEqual g [ 7; 18; 19 ] df
    let df = getPostDominanceFrontier dom g 23
    assertSetEqual g [ 19 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 7``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph7 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    assertEqual g 3 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 7``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph7 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let ds = getDominators dom g 1
    assertSetEqual g [ 1 ] ds
    let ds = getDominators dom g 2
    assertSetEqual g [ 1; 2 ] ds
    let ds = getDominators dom g 3
    assertSetEqual g [ 1; 3 ] ds
    let ds = getDominators dom g 4
    assertSetEqual g [ 1; 4 ] ds
    let ds = getDominators dom g 5
    assertSetEqual g [ 1; 3; 5 ] ds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 7``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph7 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 2
    assertSetEqual g [ 4 ] df
    let df = getDominanceFrontier dom g 3
    assertSetEqual g [ 4 ] df
    let df = getDominanceFrontier dom g 4
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 5
    Assert.AreEqual<int>(0, Set.count df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 7``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph7 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    assertEqual g 4 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    Assert.IsNull(v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 7``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph7 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let pds = getPostDominators dom g 1
    assertSetEqual g [ 1 ] pds
    let pds = getPostDominators dom g 2
    assertSetEqual g [ 2; 4 ] pds
    let pds = getPostDominators dom g 3
    assertSetEqual g [ 3 ] pds
    let pds = getPostDominators dom g 4
    assertSetEqual g [ 4 ] pds
    let pds = getPostDominators dom g 5
    assertSetEqual g [ 5 ] pds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 7``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph7 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getPostDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getPostDominanceFrontier dom g 2
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 3
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 4
    assertSetEqual g [ 3; 1 ] df
    let df = getPostDominanceFrontier dom g 5
    assertSetEqual g [ 3 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 8``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph8 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    assertEqual g 2 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    assertEqual g 3 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    assertEqual g 4 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    assertEqual g 5 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 7
    assertEqual g 6 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 8
    assertEqual g 7 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 8``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph8 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let ds = getDominators dom g 1
    assertSetEqual g [ 1 ] ds
    let ds = getDominators dom g 2
    assertSetEqual g [ 1; 2 ] ds
    let ds = getDominators dom g 3
    assertSetEqual g [ 1; 2; 3 ] ds
    let ds = getDominators dom g 4
    assertSetEqual g [ 1; 2; 3; 4 ] ds
    let ds = getDominators dom g 5
    assertSetEqual g [ 1; 2; 3; 4; 5 ] ds
    let ds = getDominators dom g 6
    assertSetEqual g [ 1; 2; 3; 4; 5; 6 ] ds
    let ds = getDominators dom g 7
    assertSetEqual g [ 1; 2; 3; 4; 5; 6; 7 ] ds
    let ds = getDominators dom g 8
    assertSetEqual g [ 1; 2; 3; 4; 5; 6; 7; 8 ] ds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 8``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph8 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 2
    assertSetEqual g [ 2 ] df
    let df = getDominanceFrontier dom g 3
    assertSetEqual g [ 2; 3 ] df
    let df = getDominanceFrontier dom g 4
    assertSetEqual g [ 2; 3 ] df
    let df = getDominanceFrontier dom g 5
    assertSetEqual g [ 2; 3 ] df
    let df = getDominanceFrontier dom g 6
    assertSetEqual g [ 2; 3 ] df
    let df = getDominanceFrontier dom g 7
    assertSetEqual g [ 2 ] df
    let df = getDominanceFrontier dom g 8
    Assert.AreEqual<int>(0, Set.count df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 8``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph8 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    assertEqual g 2 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    assertEqual g 3 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    assertEqual g 4 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    assertEqual g 5 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    assertEqual g 6 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    assertEqual g 7 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 7
    assertEqual g 8 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 8
    Assert.IsNull(v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 8``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph8 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let pds = getPostDominators dom g 1
    assertSetEqual g [ 1; 2; 3; 4; 5; 6; 7; 8 ] pds
    let pds = getPostDominators dom g 2
    assertSetEqual g [ 2; 3; 4; 5; 6; 7; 8 ] pds
    let pds = getPostDominators dom g 3
    assertSetEqual g [ 3; 4; 5; 6; 7; 8 ] pds
    let pds = getPostDominators dom g 4
    assertSetEqual g [ 4; 5; 6; 7; 8 ] pds
    let pds = getPostDominators dom g 5
    assertSetEqual g [ 5; 6; 7; 8 ] pds
    let pds = getPostDominators dom g 6
    assertSetEqual g [ 6; 7; 8 ] pds
    let pds = getPostDominators dom g 7
    assertSetEqual g [ 7; 8 ] pds
    let pds = getPostDominators dom g 8
    assertSetEqual g [ 8 ] pds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 8``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph8 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getPostDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getPostDominanceFrontier dom g 2
    assertSetEqual g [ 5; 7 ] df
    let df = getPostDominanceFrontier dom g 3
    assertSetEqual g [ 5; 6; 7 ] df
    let df = getPostDominanceFrontier dom g 4
    assertSetEqual g [ 5; 6; 7 ] df
    let df = getPostDominanceFrontier dom g 5
    assertSetEqual g [ 5; 6; 7 ] df
    let df = getPostDominanceFrontier dom g 6
    assertSetEqual g [ 6; 7 ] df
    let df = getPostDominanceFrontier dom g 7
    assertSetEqual g [ 7 ] df
    let df = getPostDominanceFrontier dom g 8
    Assert.AreEqual<int>(0, Set.count df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 9``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph9 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    assertEqual g 2 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    assertEqual g 3 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    assertEqual g 2 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    assertEqual g 2 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 7
    assertEqual g 2 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 8
    assertEqual g 4 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 9``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph9 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let ds = getDominators dom g 1
    assertSetEqual g [ 1 ] ds
    let ds = getDominators dom g 2
    assertSetEqual g [ 1; 2 ] ds
    let ds = getDominators dom g 3
    assertSetEqual g [ 1; 2; 3 ] ds
    let ds = getDominators dom g 4
    assertSetEqual g [ 1; 2; 3; 4 ] ds
    let ds = getDominators dom g 5
    assertSetEqual g [ 1; 2; 5 ] ds
    let ds = getDominators dom g 6
    assertSetEqual g [ 1; 2; 6 ] ds
    let ds = getDominators dom g 7
    assertSetEqual g [ 1; 2; 7 ] ds
    let ds = getDominators dom g 8
    assertSetEqual g [ 1; 2; 3; 4; 8 ] ds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 9``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph9 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getDominanceFrontier dom g 1
    assertSetEqual g [ 1 ] df
    let df = getDominanceFrontier dom g 2
    assertSetEqual g [ 1 ] df
    let df = getDominanceFrontier dom g 3
    assertSetEqual g [ 3; 7 ] df
    let df = getDominanceFrontier dom g 4
    assertSetEqual g [ 3; 4; 7 ] df
    let df = getDominanceFrontier dom g 5
    assertSetEqual g [ 1; 6 ] df
    let df = getDominanceFrontier dom g 6
    assertSetEqual g [ 7 ] df
    let df = getDominanceFrontier dom g 7
    assertSetEqual g [ 6 ] df
    let df = getDominanceFrontier dom g 8
    assertSetEqual g [ 4; 7 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 9``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph9 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    assertEqual g 2 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    assertEqual g 6 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    assertEqual g 7 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    assertEqual g 7 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    assertEqual g 6 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 7
    assertEqual g 6 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 8
    assertEqual g 7 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 9``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph9 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let pds = getPostDominators dom g 1
    assertSetEqual g [ 1; 2; 6 ] pds
    let pds = getPostDominators dom g 2
    assertSetEqual g [ 2; 6 ] pds
    let pds = getPostDominators dom g 3
    assertSetEqual g [ 3; 6; 7 ] pds
    let pds = getPostDominators dom g 4
    assertSetEqual g [ 4; 6; 7 ] pds
    let pds = getPostDominators dom g 5
    assertSetEqual g [ 5; 6 ] pds
    let pds = getPostDominators dom g 6
    assertSetEqual g [ 6 ] pds
    let pds = getPostDominators dom g 7
    assertSetEqual g [ 6; 7 ] pds
    let pds = getPostDominators dom g 8
    assertSetEqual g [ 6; 7; 8 ] pds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 9``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph9 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getPostDominanceFrontier dom g 1
    assertSetEqual g [ 5 ] df
    let df = getPostDominanceFrontier dom g 2
    assertSetEqual g [ 5 ] df
    let df = getPostDominanceFrontier dom g 3
    assertSetEqual g [ 2; 4 ] df
    let df = getPostDominanceFrontier dom g 4
    assertSetEqual g [ 3; 8 ] df
    let df = getPostDominanceFrontier dom g 5
    assertSetEqual g [ 2 ] df
    let df = getPostDominanceFrontier dom g 6
    assertSetEqual g [ 6 ] df
    let df = getPostDominanceFrontier dom g 7
    assertSetEqual g [ 2; 6 ] df
    let df = getPostDominanceFrontier dom g 8
    assertSetEqual g [ 4 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 10``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph10 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    assertEqual g 2 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 10``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph10 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let ds = getDominators dom g 1
    assertSetEqual g [ 1 ] ds
    let ds = getDominators dom g 2
    assertSetEqual g [ 1; 2 ] ds
    let ds = getDominators dom g 3
    assertSetEqual g [ 1; 2; 3 ] ds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 10``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph10 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getDominanceFrontier dom g 1
    assertSetEqual g [ 1 ] df
    let df = getDominanceFrontier dom g 2
    assertSetEqual g [ 1 ] df
    let df = getDominanceFrontier dom g 3
    assertSetEqual g [ 1 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 10``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph10 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    assertEqual g 2 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    assertEqual g 3 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.IsNull(v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 10``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph10 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let pds = getPostDominators dom g 1
    assertSetEqual g [ 1; 2; 3 ] pds
    let pds = getPostDominators dom g 2
    assertSetEqual g [ 2; 3 ] pds
    let pds = getPostDominators dom g 3
    assertSetEqual g [ 3 ] pds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 10``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph10 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getPostDominanceFrontier dom g 1
    assertSetEqual g [ 3 ] df
    let df = getPostDominanceFrontier dom g 2
    assertSetEqual g [ 3 ] df
    let df = getPostDominanceFrontier dom g 3
    assertSetEqual g [ 3 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 11``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph11 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    assertEqual g 3 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    assertEqual g 4 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    assertEqual g 4 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 7
    assertEqual g 4 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 8
    assertEqual g 7 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 9
    assertEqual g 8 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 10
    assertEqual g 8 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 11``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph11 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let ds = getDominators dom g 1
    assertSetEqual g [ 1 ] ds
    let ds = getDominators dom g 2
    assertSetEqual g [ 1; 2 ] ds
    let ds = getDominators dom g 3
    assertSetEqual g [ 1; 3 ] ds
    let ds = getDominators dom g 4
    assertSetEqual g [ 1; 3; 4 ] ds
    let ds = getDominators dom g 5
    assertSetEqual g [ 1; 3; 4; 5 ] ds
    let ds = getDominators dom g 6
    assertSetEqual g [ 1; 3; 4; 6 ] ds
    let ds = getDominators dom g 7
    assertSetEqual g [ 1; 3; 4; 7 ] ds
    let ds = getDominators dom g 8
    assertSetEqual g [ 1; 3; 4; 7; 8 ] ds
    let ds = getDominators dom g 9
    assertSetEqual g [ 1; 3; 4; 7; 8; 9 ] ds
    let ds = getDominators dom g 10
    assertSetEqual g [ 1; 3; 4; 7; 8; 10 ] ds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 11``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph11 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getDominanceFrontier dom g 1
    assertSetEqual g [ 1 ] df
    let df = getDominanceFrontier dom g 2
    assertSetEqual g [ 3 ] df
    let df = getDominanceFrontier dom g 3
    assertSetEqual g [ 1; 3 ] df
    let df = getDominanceFrontier dom g 4
    assertSetEqual g [ 1; 3; 4 ] df
    let df = getDominanceFrontier dom g 5
    assertSetEqual g [ 7 ] df
    let df = getDominanceFrontier dom g 6
    assertSetEqual g [ 7 ] df
    let df = getDominanceFrontier dom g 7
    assertSetEqual g [ 1; 3; 4; 7 ] df
    let df = getDominanceFrontier dom g 8
    assertSetEqual g [ 1; 3; 7 ] df
    let df = getDominanceFrontier dom g 9
    assertSetEqual g [ 1 ] df
    let df = getDominanceFrontier dom g 10
    assertSetEqual g [ 7 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 11``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph11 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    assertEqual g 3 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    assertEqual g 3 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    assertEqual g 4 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    assertEqual g 7 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    assertEqual g 7 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    assertEqual g 7 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 7
    assertEqual g 8 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 8
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 9
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 10
    Assert.IsNull(v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 11``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph11 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let pds = getPostDominators dom g 1
    assertSetEqual g [ 1; 3; 4; 7; 8 ] pds
    let pds = getPostDominators dom g 2
    assertSetEqual g [ 2; 3; 4; 7; 8 ] pds
    let pds = getPostDominators dom g 3
    assertSetEqual g [ 3; 4; 7; 8 ] pds
    let pds = getPostDominators dom g 4
    assertSetEqual g [ 4; 7; 8 ] pds
    let pds = getPostDominators dom g 5
    assertSetEqual g [ 5; 7; 8 ] pds
    let pds = getPostDominators dom g 6
    assertSetEqual g [ 6; 7; 8 ] pds
    let pds = getPostDominators dom g 7
    assertSetEqual g [ 7; 8 ] pds
    let pds = getPostDominators dom g 8
    assertSetEqual g [ 8 ] pds
    let pds = getPostDominators dom g 9
    assertSetEqual g [ 9 ] pds
    let pds = getPostDominators dom g 10
    assertSetEqual g [ 10 ] pds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 11``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph11 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getPostDominanceFrontier dom g 1
    assertSetEqual g [ 9 ] df
    let df = getPostDominanceFrontier dom g 2
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 3
    assertSetEqual g [ 4; 8; 9 ] df
    let df = getPostDominanceFrontier dom g 4
    assertSetEqual g [ 4; 7; 8; 9 ] df
    let df = getPostDominanceFrontier dom g 5
    assertSetEqual g [ 4 ] df
    let df = getPostDominanceFrontier dom g 6
    assertSetEqual g [ 4 ] df
    let df = getPostDominanceFrontier dom g 7
    assertSetEqual g [ 7; 8; 9; 10 ] df
    let df = getPostDominanceFrontier dom g 8
    assertSetEqual g [ 8; 9; 10 ] df
    let df = getPostDominanceFrontier dom g 9
    assertSetEqual g [ 8 ] df
    let df = getPostDominanceFrontier dom g 10
    assertSetEqual g [ 8 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 12``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph12 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsNull(v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    assertEqual g 1 v
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    Assert.IsNull(v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 12``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph12 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let ds = getDominators dom g 1
    assertSetEqual g [ 1 ] ds
    let ds = getDominators dom g 2
    assertSetEqual g [ 1; 2 ] ds
    let ds = getDominators dom g 3
    assertSetEqual g [ 1; 3 ] ds
    let ds = getDominators dom g 4
    assertSetEqual g [ 1; 4 ] ds
    let ds = getDominators dom g 5
    assertSetEqual g [ 5 ] ds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 12``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph12 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 2
    assertSetEqual g [ 4 ] df
    let df = getDominanceFrontier dom g 3
    assertSetEqual g [ 4 ] df
    let df = getDominanceFrontier dom g 4
    Assert.AreEqual<int>(0, Set.count df)
    let df = getDominanceFrontier dom g 5
    Assert.AreEqual<int>(0, Set.count df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 12``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph12 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    assertEqual g 4 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    assertEqual g 4 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    assertEqual g 4 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    Assert.IsNull(v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    assertEqual g 3 v

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 12``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph12 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let pds = getPostDominators dom g 1
    assertSetEqual g [ 1; 4 ] pds
    let pds = getPostDominators dom g 2
    assertSetEqual g [ 2; 4 ] pds
    let pds = getPostDominators dom g 3
    assertSetEqual g [ 3; 4 ] pds
    let pds = getPostDominators dom g 4
    assertSetEqual g [ 4 ] pds
    let pds = getPostDominators dom g 5
    assertSetEqual g [ 3; 4; 5 ] pds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 12``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph12 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getPostDominanceFrontier dom g 1
    Assert.AreEqual<int>(0, Set.count df)
    let df = getPostDominanceFrontier dom g 2
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 3
    assertSetEqual g [ 1 ] df
    let df = getPostDominanceFrontier dom g 4
    Assert.AreEqual<int>(0, Set.count df)
    let df = getPostDominanceFrontier dom g 5
    Assert.AreEqual<int>(0, Set.count df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 13``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph13 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    assertEqual g 2 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    assertEqual g 3 v
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.IsNull(v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 13``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph13 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let pds = getPostDominators dom g 1
    assertSetEqual g [ 1; 2; 3 ] pds
    let pds = getPostDominators dom g 2
    assertSetEqual g [ 2; 3 ] pds
    let pds = getPostDominators dom g 3
    assertSetEqual g [ 3 ] pds

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 13``(t, domAlgo, dfAlgo, sAlgo) =
    let g, _ = digraph13 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    let df = getPostDominanceFrontier dom g 1
    assertSetEqual g [ 3 ] df
    let df = getPostDominanceFrontier dom g 2
    assertSetEqual g [ 3 ] df
    let df = getPostDominanceFrontier dom g 3
    assertSetEqual g [ 3 ] df

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Foreign Vertex Query Test``(t, domAlgo, dfAlgo, sAlgo) =
    let g, vmap = digraph1 t
    let removed = vmap[6]
    let g = g.RemoveVertex removed
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo sAlgo
    assertVertexNotFound (fun () -> dom.Dominators removed |> ignore)
    assertVertexNotFound (fun () -> dom.ImmediateDominator removed |> ignore)
    assertVertexNotFound (fun () -> dom.DominanceFrontier removed |> ignore)
    assertVertexNotFound (fun () -> dom.PostDominators removed |> ignore)
    assertVertexNotFound (fun () ->
      dom.ImmediatePostDominator removed |> ignore)
    assertVertexNotFound (fun () ->
      dom.PostDominanceFrontier removed |> ignore)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.ComparisonData)>]
  member _.``Comparison: Dominators Test``(domAlgo, fileName, sAlgo) =
    let constructor () = ImperativeDiGraph() :> IDiGraph<string, string>
    let json = System.IO.File.ReadAllText("TestData/" + fileName)
    let g = Serializer.FromJson(json, constructor, id, id)
    let naiveDom: IDominance<_, _> = instantiate g DomIterative DFCytron None
    let testDom: IDominance<_, _> = instantiate g domAlgo DFCytron sAlgo
    for v in g.Vertices do
      let expected = naiveDom.Dominators v |> Set.ofSeq
      let actual = testDom.Dominators v |> Set.ofSeq
      Assert.AreEqual<Set<IVertex<_>>>(expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.ComparisonData)>]
  member _.``Comparison: Immediate Dominator Test``(domAlgo, fileName, sAlgo) =
    let constructor () = ImperativeDiGraph() :> IDiGraph<string, string>
    let json = System.IO.File.ReadAllText("TestData/" + fileName)
    let g = Serializer.FromJson(json, constructor, id, id)
    let naiveDom: IDominance<_, _> = instantiate g DomIterative DFCytron None
    let testDom: IDominance<_, _> = instantiate g domAlgo DFCytron sAlgo
    for v in g.Vertices do
      let expected = naiveDom.ImmediateDominator v
      let actual = testDom.ImmediateDominator v
      Assert.AreEqual<IVertex<string>>(expected, actual)
