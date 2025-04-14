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
type DominanceTests () =
  let instantiate g domAlgo dfAlgo iStrat =
    match domAlgo, dfAlgo, iStrat with
    | DomIterative, DFCytron, _ ->
      IterativeDominance.create g (CytronDominanceFrontier ())
    | DomIterative, DFCooper, _ ->
      IterativeDominance.create g (CooperDominanceFrontier ())
    | DomLengauer, DFCytron, _ ->
      LengauerTarjanDominance.create g (CytronDominanceFrontier ())
    | DomLengauer, DFCooper, _ ->
      LengauerTarjanDominance.create g (CooperDominanceFrontier ())
    | DomSimpleLengauer, DFCytron, _ ->
      SimpleLengauerTarjanDominance.create g (CytronDominanceFrontier ())
    | DomSimpleLengauer, DFCooper, _ ->
      SimpleLengauerTarjanDominance.create g (CooperDominanceFrontier ())
    | DomSNCA, DFCytron, _ ->
      SemiNCADominance.create g (CytronDominanceFrontier ())
    | DomSNCA, DFCooper, _ ->
      SemiNCADominance.create g (CooperDominanceFrontier ())
    | DomCooper, DFCytron, _ ->
      CooperDominance.create g (CytronDominanceFrontier ())
    | DomCooper, DFCooper, _ ->
      CooperDominance.create g (CooperDominanceFrontier ())
    | DBS, DFCytron, Some strategy ->
      DepthBasedSearchDominance.create g (CytronDominanceFrontier ()) strategy
    | DBS, DFCooper, Some strategy ->
      DepthBasedSearchDominance.create g (CooperDominanceFrontier ()) strategy
    | _ ->
      failwithf "Invalid test: %A, %A, %A" domAlgo dfAlgo iStrat

  let getDominators dom g i =
    (g: IDiGraph<_, _>).FindVertexByData i
    |> (dom: IDominance<_, _>).Dominators
    |> Seq.map (fun v -> v.VData) |> Set.ofSeq

  let getDominanceFrontier dom g i =
    (g: IDiGraph<_, _>).FindVertexByData i
    |> (dom: IDominance<_, _>).DominanceFrontier
    |> Seq.map (fun v -> v.VData) |> Set.ofSeq

  let getPostDominators dom g i =
    (g: IDiGraph<_, _>).FindVertexByData i
    |> (dom: IDominance<_, _>).PostDominators
    |> Seq.map (fun v -> v.VData) |> Set.ofSeq

  let getPostDominanceFrontier dom g i =
    (g: IDiGraph<_, _>).FindVertexByData i
    |> (dom: IDominance<_, _>).PostDominanceFrontier
    |> Seq.map (fun v -> v.VData) |> Set.ofSeq

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
       [| box Persistent; box DBS; box DFCytron;
          box (Some DepthBasedSearchDominance.DynamicInit) |]
       [| box Persistent; box DBS; box DFCooper;
          box (Some DepthBasedSearchDominance.DynamicInit) |]
       [| box Imperative; box DBS; box DFCytron;
          box (Some DepthBasedSearchDominance.DynamicInit) |]
       [| box Imperative; box DBS; box DFCooper;
          box (Some DepthBasedSearchDominance.DynamicInit) |] |]

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
          box (Some DepthBasedSearchDominance.DynamicInit) |]
       [| box DBS
          box "499_gcc_base.amd64-m32-ccr-Ofast_clang_m32_Of_81428e0.json"
          box (Some DepthBasedSearchDominance.DynamicInit) |]
       [| box DBS
          box "854_binutils-2.31.1_x86_gcc_nopie_o3_as-new_808b4e0.json"
          box (Some DepthBasedSearchDominance.DynamicInit) |]
       [| box DBS
          box "4152_find_clang_O0_433cd0.json"
          box (Some DepthBasedSearchDominance.DynamicInit) |] |]

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 1`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph1 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 1`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph1 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1; 2; 3 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1; 2; 4 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 2; 5 ] = ds)
    let ds = getDominators dom g 6
    Assert.IsTrue (Set.ofList [ 1; 2; 6 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 1`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph1 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 1`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph1 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 1`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph1 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1; 2; 6 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 2; 6 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 2; 3; 5; 6 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 2; 4; 5; 6 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 2; 5; 6 ] = pds)
    let pds = getPostDominators dom g 6
    Assert.IsTrue (Set.ofList [ 6 ] = pds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 1`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph1 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getPostDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getPostDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 2 ] = df)
    let df = getPostDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 2 ] = df)
    let df = getPostDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 2 ] = df)
    let df = getPostDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 2 ] = df)
    let df = getPostDominanceFrontier dom g 6
    Assert.IsTrue (Set.isEmpty df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 2`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph2 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 2`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph2 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1; 3 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1; 3; 4 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 3; 4; 5 ] = ds)
    let ds = getDominators dom g 6
    Assert.IsTrue (Set.ofList [ 1; 3; 4; 6 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 2`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph2 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 2`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph2 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 2`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph2 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 2 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 3; 4; 5 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 4; 5 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 5 ] = pds)
    let pds = getPostDominators dom g 6
    Assert.IsTrue (Set.ofList [ 4; 5; 6 ] = pds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 2`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph2 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getPostDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getPostDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 1; 4 ] = df)
    let df = getPostDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 6
    Assert.IsTrue (Set.ofList [ 4 ] = df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 3`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph3 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 3`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph3 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1; 3 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1; 4 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 3; 5 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 3`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph3 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 3`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph3 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 3`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph3 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 2; 4 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 3 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 4 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 5 ] = pds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 3`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph3 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getPostDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getPostDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 1; 3 ] = df)
    let df = getPostDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 3 ] = df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 4`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph4 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 4`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph4 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1; 2; 3 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1; 4 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 5 ] = ds)
    let ds = getDominators dom g 6
    Assert.IsTrue (Set.ofList [ 1; 5; 6 ] = ds)
    let ds = getDominators dom g 7
    Assert.IsTrue (Set.ofList [ 1; 5; 7 ] = ds)
    let ds = getDominators dom g 8
    Assert.IsTrue (Set.ofList [ 1; 5; 8 ] = ds)
    let ds = getDominators dom g 9
    Assert.IsTrue (Set.ofList [ 1; 9 ] = ds)
    let ds = getDominators dom g 10
    Assert.IsTrue (Set.ofList [ 1; 9; 10 ] = ds)
    let ds = getDominators dom g 11
    Assert.IsTrue (Set.ofList [ 1; 9; 11 ] = ds)
    let ds = getDominators dom g 12
    Assert.IsTrue (Set.ofList [ 1; 12 ] = ds)
    let ds = getDominators dom g 13
    Assert.IsTrue (Set.ofList [ 1; 13 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 4`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph4 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 4`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph4 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 4`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph4 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1; 13 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 2; 3; 4; 13 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 3; 4; 13 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 4; 13 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 5; 13 ] = pds)
    let pds = getPostDominators dom g 6
    Assert.IsTrue (Set.ofList [ 6; 13 ] = pds)
    let pds = getPostDominators dom g 7
    Assert.IsTrue (Set.ofList [ 7; 13 ] = pds)
    let pds = getPostDominators dom g 8
    Assert.IsTrue (Set.ofList [ 8; 13 ] = pds)
    let pds = getPostDominators dom g 9
    Assert.IsTrue (Set.ofList [ 9; 12; 13 ] = pds)
    let pds = getPostDominators dom g 10
    Assert.IsTrue (Set.ofList [ 10; 12; 13 ] = pds)
    let pds = getPostDominators dom g 11
    Assert.IsTrue (Set.ofList [ 11; 12; 13 ] = pds)
    let pds = getPostDominators dom g 12
    Assert.IsTrue (Set.ofList [ 12; 13 ] = pds)
    let pds = getPostDominators dom g 13
    Assert.IsTrue (Set.ofList [ 13 ] = pds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 4`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph4 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getPostDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getPostDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 1; 3 ] = df)
    let df = getPostDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 1; 6 ] = df)
    let df = getPostDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 1; 8 ] = df)
    let df = getPostDominanceFrontier dom g 6
    Assert.IsTrue (Set.ofList [ 5 ] = df)
    let df = getPostDominanceFrontier dom g 7
    Assert.IsTrue (Set.ofList [ 5 ] = df)
    let df = getPostDominanceFrontier dom g 8
    Assert.IsTrue (Set.ofList [ 6; 7 ] = df)
    let df = getPostDominanceFrontier dom g 9
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 10
    Assert.IsTrue (Set.ofList [ 9 ] = df)
    let df = getPostDominanceFrontier dom g 11
    Assert.IsTrue (Set.ofList [ 9 ] = df)
    let df = getPostDominanceFrontier dom g 12
    Assert.IsTrue (Set.ofList [ 1; 7 ] = df)
    let df = getPostDominanceFrontier dom g 13
    Assert.IsTrue (Set.isEmpty df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 5`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph5 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 5`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph5 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1; 3 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1; 4 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 3; 5 ] = ds)
    let ds = getDominators dom g 6
    Assert.IsTrue (Set.ofList [ 1; 6 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 5`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph5 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getDominanceFrontier dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 4 ] = df)
    let df = getDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 4; 6 ] = df)
    let df = getDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 6 ] = df)
    let df = getDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 6 ] = df)
    let df = getDominanceFrontier dom g 6
    Assert.IsTrue (Set.ofList [ 1 ] = df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 5`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph5 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 5`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph5 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1; 6 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 2; 4; 6 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 3; 6 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 4; 6 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 5; 6 ] = pds)
    let pds = getPostDominators dom g 6
    Assert.IsTrue (Set.ofList [ 6 ] = pds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 5`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph5 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getPostDominanceFrontier dom g 1
    Assert.IsTrue (Set.ofList [ 6 ] = df)
    let df = getPostDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 1; 3 ] = df)
    let df = getPostDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 3 ] = df)
    let df = getPostDominanceFrontier dom g 6
    Assert.IsTrue (Set.ofList [ 6 ] = df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 6`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph6 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 6`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph6 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1; 3 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1; 2; 4 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 3; 5 ] = ds)
    let ds = getDominators dom g 6
    Assert.IsTrue (Set.ofList [ 1; 3; 6 ] = ds)
    let ds = getDominators dom g 7
    Assert.IsTrue (Set.ofList [ 1; 2; 7 ] = ds)
    let ds = getDominators dom g 8
    Assert.IsTrue (Set.ofList [ 1; 3; 5; 8 ] = ds)
    let ds = getDominators dom g 9
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9 ] = ds)
    let ds = getDominators dom g 10
    Assert.IsTrue (Set.ofList [ 1; 3; 5; 10 ] = ds)
    let ds = getDominators dom g 11
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 11 ] = ds)
    let ds = getDominators dom g 12
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 12 ] = ds)
    let ds = getDominators dom g 13
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 13 ] = ds)
    let ds = getDominators dom g 14
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 13; 14 ] = ds)
    let ds = getDominators dom g 15
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 13; 15 ] = ds)
    let ds = getDominators dom g 16
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 13; 16 ] = ds)
    let ds = getDominators dom g 17
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 13; 16; 17 ] = ds)
    let ds = getDominators dom g 18
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 13; 16; 18 ] = ds)
    let ds = getDominators dom g 19
    Assert.IsTrue (Set.ofList [ 1; 19 ] = ds)
    let ds = getDominators dom g 20
    Assert.IsTrue (Set.ofList [ 1; 2; 7; 9; 13; 16; 18; 20 ] = ds)
    let ds = getDominators dom g 21
    Assert.IsTrue (Set.ofList [ 1; 19; 21 ] = ds)
    let ds = getDominators dom g 22
    Assert.IsTrue (Set.ofList [ 1; 22 ] = ds)
    let ds = getDominators dom g 23
    Assert.IsTrue (Set.ofList [ 1; 19; 23 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 6`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph6 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 6`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph6 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 6`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph6 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 2; 7 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 3 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 4; 7 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 5; 10; 19 ] = pds)
    let pds = getPostDominators dom g 6
    Assert.IsTrue (Set.ofList [ 6 ] = pds)
    let pds = getPostDominators dom g 7
    Assert.IsTrue (Set.ofList [ 7 ] = pds)
    let pds = getPostDominators dom g 8
    Assert.IsTrue (Set.ofList [ 8; 10; 19 ] = pds)
    let pds = getPostDominators dom g 9
    Assert.IsTrue (Set.ofList [ 9; 13; 16; 18 ] = pds)
    let pds = getPostDominators dom g 10
    Assert.IsTrue (Set.ofList [ 10; 19 ] = pds)
    let pds = getPostDominators dom g 11
    Assert.IsTrue (Set.ofList [ 11; 22 ] = pds)
    let pds = getPostDominators dom g 12
    Assert.IsTrue (Set.ofList [ 12; 13; 16; 18 ] = pds)
    let pds = getPostDominators dom g 13
    Assert.IsTrue (Set.ofList [ 13; 16; 18 ] = pds)
    let pds = getPostDominators dom g 14
    Assert.IsTrue (Set.ofList [ 14; 16; 18 ] = pds)
    let pds = getPostDominators dom g 15
    Assert.IsTrue (Set.ofList [ 15; 16; 18 ] = pds)
    let pds = getPostDominators dom g 16
    Assert.IsTrue (Set.ofList [ 16; 18 ] = pds)
    let pds = getPostDominators dom g 17
    Assert.IsTrue (Set.ofList [ 17; 18 ] = pds)
    let pds = getPostDominators dom g 18
    Assert.IsTrue (Set.ofList [ 18 ] = pds)
    let pds = getPostDominators dom g 19
    Assert.IsTrue (Set.ofList [ 19 ] = pds)
    let pds = getPostDominators dom g 20
    Assert.IsTrue (Set.ofList [ 20; 22 ] = pds)
    let pds = getPostDominators dom g 21
    Assert.IsTrue (Set.ofList [ 21; 22 ] = pds)
    let pds = getPostDominators dom g 22
    Assert.IsTrue (Set.ofList [ 22 ] = pds)
    let pds = getPostDominators dom g 23
    Assert.IsTrue (Set.ofList [ 23 ] = pds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 6`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph6 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getPostDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getPostDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 2 ] = df)
    let df = getPostDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 3 ] = df)
    let df = getPostDominanceFrontier dom g 6
    Assert.IsTrue (Set.ofList [ 3 ] = df)
    let df = getPostDominanceFrontier dom g 7
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 8
    Assert.IsTrue (Set.ofList [ 5 ] = df)
    let df = getPostDominanceFrontier dom g 9
    Assert.IsTrue (Set.ofList [ 7 ] = df)
    let df = getPostDominanceFrontier dom g 10
    Assert.IsTrue (Set.ofList [ 3 ] = df)
    let df = getPostDominanceFrontier dom g 11
    Assert.IsTrue (Set.ofList [ 7 ] = df)
    let df = getPostDominanceFrontier dom g 12
    Assert.IsTrue (Set.ofList [ 9 ] = df)
    let df = getPostDominanceFrontier dom g 13
    Assert.IsTrue (Set.ofList [ 7 ] = df)
    let df = getPostDominanceFrontier dom g 14
    Assert.IsTrue (Set.ofList [ 13 ] = df)
    let df = getPostDominanceFrontier dom g 15
    Assert.IsTrue (Set.ofList [ 13 ] = df)
    let df = getPostDominanceFrontier dom g 16
    Assert.IsTrue (Set.ofList [ 7 ] = df)
    let df = getPostDominanceFrontier dom g 17
    Assert.IsTrue (Set.ofList [ 16 ] = df)
    let df = getPostDominanceFrontier dom g 18
    Assert.IsTrue (Set.ofList [ 7 ] = df)
    let df = getPostDominanceFrontier dom g 19
    Assert.IsTrue (Set.ofList [ 3; 18 ] = df)
    let df = getPostDominanceFrontier dom g 20
    Assert.IsTrue (Set.ofList [ 18 ] = df)
    let df = getPostDominanceFrontier dom g 21
    Assert.IsTrue (Set.ofList [ 19 ] = df)
    let df = getPostDominanceFrontier dom g 22
    Assert.IsTrue (Set.ofList [ 7; 18; 19 ] = df)
    let df = getPostDominanceFrontier dom g 23
    Assert.IsTrue (Set.ofList [ 19 ] = df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 7`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph7 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 7`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph7 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1; 3 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1; 4 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 3; 5 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 7`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph7 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 7`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph7 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 7`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph7 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 2; 4 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 3 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 4 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 5 ] = pds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 7`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph7 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getPostDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getPostDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 3; 1 ] = df)
    let df = getPostDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 3 ] = df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 8`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph8 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsTrue (isNull v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (3, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (4, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    Assert.AreEqual<int> (5, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 7
    Assert.AreEqual<int> (6, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 8
    Assert.AreEqual<int> (7, v.VData)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 8`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph8 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1; 2; 3 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1; 2; 3; 4 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 2; 3; 4; 5 ] = ds)
    let ds = getDominators dom g 6
    Assert.IsTrue (Set.ofList [ 1; 2; 3; 4; 5; 6 ] = ds)
    let ds = getDominators dom g 7
    Assert.IsTrue (Set.ofList [ 1; 2; 3; 4; 5; 6; 7 ] = ds)
    let ds = getDominators dom g 8
    Assert.IsTrue (Set.ofList [ 1; 2; 3; 4; 5; 6; 7; 8 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 8`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph8 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 2 ] = df)
    let df = getDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 2; 3 ] = df)
    let df = getDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 2; 3 ] = df)
    let df = getDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 2; 3 ] = df)
    let df = getDominanceFrontier dom g 6
    Assert.IsTrue (Set.ofList [ 2; 3 ] = df)
    let df = getDominanceFrontier dom g 7
    Assert.IsTrue (Set.ofList [ 2 ] = df)
    let df = getDominanceFrontier dom g 8
    Assert.IsTrue (Set.isEmpty df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 8`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph8 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (3, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (4, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (5, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (6, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    Assert.AreEqual<int> (7, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 7
    Assert.AreEqual<int> (8, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 8
    Assert.IsTrue (isNull v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 8`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph8 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1; 2; 3; 4; 5; 6; 7; 8 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 2; 3; 4; 5; 6; 7; 8 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 3; 4; 5; 6; 7; 8 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 4; 5; 6; 7; 8 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 5; 6; 7; 8 ] = pds)
    let pds = getPostDominators dom g 6
    Assert.IsTrue (Set.ofList [ 6; 7; 8 ] = pds)
    let pds = getPostDominators dom g 7
    Assert.IsTrue (Set.ofList [ 7; 8 ] = pds)
    let pds = getPostDominators dom g 8
    Assert.IsTrue (Set.ofList [ 8 ] = pds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 8`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph8 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getPostDominanceFrontier dom g 1
    Assert.IsTrue (Set.isEmpty df)
    let df = getPostDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 5; 7 ] = df)
    let df = getPostDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 5; 6; 7 ] = df)
    let df = getPostDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 5; 6; 7 ] = df)
    let df = getPostDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 5; 6; 7 ] = df)
    let df = getPostDominanceFrontier dom g 6
    Assert.IsTrue (Set.ofList [ 6; 7 ] = df)
    let df = getPostDominanceFrontier dom g 7
    Assert.IsTrue (Set.ofList [ 7 ] = df)
    let df = getPostDominanceFrontier dom g 8
    Assert.IsTrue (Set.isEmpty df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 9`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph9 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsTrue (isNull v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (3, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 6
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 7
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 8
    Assert.AreEqual<int> (4, v.VData)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 9`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph9 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1; 2; 3 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1; 2; 3; 4 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 2; 5 ] = ds)
    let ds = getDominators dom g 6
    Assert.IsTrue (Set.ofList [ 1; 2; 6 ] = ds)
    let ds = getDominators dom g 7
    Assert.IsTrue (Set.ofList [ 1; 2; 7 ] = ds)
    let ds = getDominators dom g 8
    Assert.IsTrue (Set.ofList [ 1; 2; 3; 4; 8 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 9`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph9 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getDominanceFrontier dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 3; 7 ] = df)
    let df = getDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 3; 4; 7 ] = df)
    let df = getDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 1; 6 ] = df)
    let df = getDominanceFrontier dom g 6
    Assert.IsTrue (Set.ofList [ 7 ] = df)
    let df = getDominanceFrontier dom g 7
    Assert.IsTrue (Set.ofList [ 6 ] = df)
    let df = getDominanceFrontier dom g 8
    Assert.IsTrue (Set.ofList [ 4; 7 ] = df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 9`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph9 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (6, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (7, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (7, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (6, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 7
    Assert.AreEqual<int> (6, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 8
    Assert.AreEqual<int> (7, v.VData)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 9`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph9 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1; 2; 6 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 2; 6 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 3; 6; 7 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 4; 6; 7 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 5; 6 ] = pds)
    let pds = getPostDominators dom g 6
    Assert.IsTrue (Set.ofList [ 6 ] = pds)
    let pds = getPostDominators dom g 7
    Assert.IsTrue (Set.ofList [ 6; 7 ] = pds)
    let pds = getPostDominators dom g 8
    Assert.IsTrue (Set.ofList [ 6; 7; 8 ] = pds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 9`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph9 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getPostDominanceFrontier dom g 1
    Assert.IsTrue (Set.ofList [ 5 ] = df)
    let df = getPostDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 5 ] = df)
    let df = getPostDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 2; 4 ] = df)
    let df = getPostDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 3; 8 ] = df)
    let df = getPostDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 2 ] = df)
    let df = getPostDominanceFrontier dom g 6
    Assert.IsTrue (Set.ofList [ 6 ] = df)
    let df = getPostDominanceFrontier dom g 7
    Assert.IsTrue (Set.ofList [ 2; 6 ] = df)
    let df = getPostDominanceFrontier dom g 8
    Assert.IsTrue (Set.ofList [ 4 ] = df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 10`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph10 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let v = dom.ImmediateDominator <| g.FindVertexByData 1
    Assert.IsTrue (isNull v)
    let v = dom.ImmediateDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (1, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (2, v.VData)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 10`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph10 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1; 2; 3 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 10`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph10 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getDominanceFrontier dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 1 ] = df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 10`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph10 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.AreEqual<int> (2, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (3, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.IsTrue (isNull v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 10`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph10 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1; 2; 3 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 2; 3 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 3 ] = pds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 10`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph10 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getPostDominanceFrontier dom g 1
    Assert.IsTrue (Set.ofList [ 3 ] = df)
    let df = getPostDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 3 ] = df)
    let df = getPostDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 3 ] = df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Dominator Test 11`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph11 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
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
    let v = dom.ImmediateDominator <| g.FindVertexByData 7
    Assert.AreEqual<int> (4, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 8
    Assert.AreEqual<int> (7, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 9
    Assert.AreEqual<int> (8, v.VData)
    let v = dom.ImmediateDominator <| g.FindVertexByData 10
    Assert.AreEqual<int> (8, v.VData)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominators Test 11`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph11 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let ds = getDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = ds)
    let ds = getDominators dom g 2
    Assert.IsTrue (Set.ofList [ 1; 2 ] = ds)
    let ds = getDominators dom g 3
    Assert.IsTrue (Set.ofList [ 1; 3 ] = ds)
    let ds = getDominators dom g 4
    Assert.IsTrue (Set.ofList [ 1; 3; 4 ] = ds)
    let ds = getDominators dom g 5
    Assert.IsTrue (Set.ofList [ 1; 3; 4; 5 ] = ds)
    let ds = getDominators dom g 6
    Assert.IsTrue (Set.ofList [ 1; 3; 4; 6 ] = ds)
    let ds = getDominators dom g 7
    Assert.IsTrue (Set.ofList [ 1; 3; 4; 7 ] = ds)
    let ds = getDominators dom g 8
    Assert.IsTrue (Set.ofList [ 1; 3; 4; 7; 8 ] = ds)
    let ds = getDominators dom g 9
    Assert.IsTrue (Set.ofList [ 1; 3; 4; 7; 8; 9 ] = ds)
    let ds = getDominators dom g 10
    Assert.IsTrue (Set.ofList [ 1; 3; 4; 7; 8; 10 ] = ds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Dominance Frontier Test 11`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph11 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getDominanceFrontier dom g 1
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 3 ] = df)
    let df = getDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 1; 3 ] = df)
    let df = getDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 1; 3; 4 ] = df)
    let df = getDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 7 ] = df)
    let df = getDominanceFrontier dom g 6
    Assert.IsTrue (Set.ofList [ 7 ] = df)
    let df = getDominanceFrontier dom g 7
    Assert.IsTrue (Set.ofList [ 1; 3; 4; 7 ] = df)
    let df = getDominanceFrontier dom g 8
    Assert.IsTrue (Set.ofList [ 1; 3; 7 ] = df)
    let df = getDominanceFrontier dom g 9
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getDominanceFrontier dom g 10
    Assert.IsTrue (Set.ofList [ 7 ] = df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Immediate Post-Dominator Test 11`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph11 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 1
    Assert.AreEqual<int> (3, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 2
    Assert.AreEqual<int> (3, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 3
    Assert.AreEqual<int> (4, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 4
    Assert.AreEqual<int> (7, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 5
    Assert.AreEqual<int> (7, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 6
    Assert.AreEqual<int> (7, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 7
    Assert.AreEqual<int> (8, v.VData)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 8
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 9
    Assert.IsTrue (isNull v)
    let v = dom.ImmediatePostDominator <| g.FindVertexByData 10
    Assert.IsTrue (isNull v)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominators Test 11`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph11 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let pds = getPostDominators dom g 1
    Assert.IsTrue (Set.ofList [ 1; 3; 4; 7; 8 ] = pds)
    let pds = getPostDominators dom g 2
    Assert.IsTrue (Set.ofList [ 2; 3; 4; 7; 8 ] = pds)
    let pds = getPostDominators dom g 3
    Assert.IsTrue (Set.ofList [ 3; 4; 7; 8 ] = pds)
    let pds = getPostDominators dom g 4
    Assert.IsTrue (Set.ofList [ 4; 7; 8 ] = pds)
    let pds = getPostDominators dom g 5
    Assert.IsTrue (Set.ofList [ 5; 7; 8 ] = pds)
    let pds = getPostDominators dom g 6
    Assert.IsTrue (Set.ofList [ 6; 7; 8 ] = pds)
    let pds = getPostDominators dom g 7
    Assert.IsTrue (Set.ofList [ 7; 8 ] = pds)
    let pds = getPostDominators dom g 8
    Assert.IsTrue (Set.ofList [ 8 ] = pds)
    let pds = getPostDominators dom g 9
    Assert.IsTrue (Set.ofList [ 9 ] = pds)
    let pds = getPostDominators dom g 10
    Assert.IsTrue (Set.ofList [ 10 ] = pds)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.TestData)>]
  member _.``Post-Dominance Frontier Test 11`` (t, domAlgo, dfAlgo, iStrat) =
    let g, _ = digraph11 t
    let dom: IDominance<_, _> = instantiate g domAlgo dfAlgo iStrat
    let df = getPostDominanceFrontier dom g 1
    Assert.IsTrue (Set.ofList [ 9 ] = df)
    let df = getPostDominanceFrontier dom g 2
    Assert.IsTrue (Set.ofList [ 1 ] = df)
    let df = getPostDominanceFrontier dom g 3
    Assert.IsTrue (Set.ofList [ 4; 8; 9 ] = df)
    let df = getPostDominanceFrontier dom g 4
    Assert.IsTrue (Set.ofList [ 4; 7; 8; 9 ] = df)
    let df = getPostDominanceFrontier dom g 5
    Assert.IsTrue (Set.ofList [ 4 ] = df)
    let df = getPostDominanceFrontier dom g 6
    Assert.IsTrue (Set.ofList [ 4 ] = df)
    let df = getPostDominanceFrontier dom g 7
    Assert.IsTrue (Set.ofList [ 7; 8; 9; 10 ] = df)
    let df = getPostDominanceFrontier dom g 8
    Assert.IsTrue (Set.ofList [ 8; 9; 10 ] = df)
    let df = getPostDominanceFrontier dom g 9
    Assert.IsTrue (Set.ofList [ 8 ] = df)
    let df = getPostDominanceFrontier dom g 10
    Assert.IsTrue (Set.ofList [ 8 ] = df)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.ComparisonData)>]
  member _.``Comparison: Dominators Test`` (domAlgo, fileName, iStrat) =
    let constructor () = ImperativeDiGraph () :> IDiGraph<string, string>
    let json = System.IO.File.ReadAllText ("TestData/" + fileName)
    let g = Serializer.FromJson (json, constructor, id, id)
    let naiveDom: IDominance<_, _> = instantiate g DomIterative DFCytron None
    let testDom: IDominance<_, _> = instantiate g domAlgo DFCytron iStrat
    for v in g.Vertices do
      let expected = naiveDom.Dominators v |> Set.ofSeq
      let actual = testDom.Dominators v |> Set.ofSeq
      Assert.AreEqual<Set<IVertex<_>>> (expected, actual)

  [<TestMethod>]
  [<DynamicData(nameof DominanceTests.ComparisonData)>]
  member _.``Comparison: Immediate Dominator Test``
    (domAlgo, fileName, iStrat) =
    let constructor () = ImperativeDiGraph () :> IDiGraph<string, string>
    let json = System.IO.File.ReadAllText ("TestData/" + fileName)
    let g = Serializer.FromJson (json, constructor, id, id)
    let naiveDom: IDominance<_, _> = instantiate g DomIterative DFCytron None
    let testDom: IDominance<_, _> = instantiate g domAlgo DFCytron iStrat
    for v in g.Vertices do
      let expected = naiveDom.ImmediateDominator v
      let actual = testDom.ImmediateDominator v
      Assert.AreEqual<IVertex<string>> (expected, actual)
