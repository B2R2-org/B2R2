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

/// Cooper et al.'s algorithm for dominance computation. A Simple, Fast
/// Dominance Algorithm, SPE 2001.
module B2R2.MiddleEnd.BinGraph.Dominance.CooperDominance

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

let private getPONumbersAndRPOVertices g dummyRoot =
  let dict = Dictionary ()
  let roots = (g: IDiGraphAccessible<_, _>).GetRoots () |> Array.toList
  let vs =
    Traversal.DFS.foldPostorderWithRoots g roots (fun vs v ->
      dict[v] <- dict.Count + 1
      v :: vs
    ) []
  dict[dummyRoot] <- dict.Count + 1
  dict, vs

let private getProcessedPreds g (idoms: Dictionary<_, IVertex<_>>)
                              (dummyRoot: IVertex<_>)
                              (realRoots: IVertex<_>[]) v =
  if realRoots |> Array.contains v then
    [| dummyRoot; yield! (g: IDiGraphAccessible<_, _>).GetPreds v |]
    |> Array.filter (fun p -> not (isNull idoms[p]))
  else
    (g: IDiGraphAccessible<_, _>).GetPreds v
    |> Array.filter (fun p -> not (isNull idoms[p]))

let private intersect (idoms: Dictionary<_, _>)
                      (poNumbers: Dictionary<_, _>) b1 b2 =
  let mutable f1 = b1
  let mutable f2 = b2
  while f1 <> f2 do
    while poNumbers[f1] < poNumbers[f2] do
      f1 <- idoms[f1]
    while poNumbers[f2] < poNumbers[f1] do
      f2 <- idoms[f2]
  f1

let private computeDominance (g: IDiGraphAccessible<_, _>) =
  let idoms = Dictionary<IVertex<_>, IVertex<_>> ()
  let dummyRoot = GraphUtils.makeDummyVertex ()
  let realRoots = g.GetRoots ()
  let poNumbers, rpoNodes = getPONumbersAndRPOVertices g dummyRoot
  idoms[dummyRoot] <- dummyRoot
  for v in g.Vertices do idoms[v] <- null
  for r in realRoots do idoms[r] <- dummyRoot
  let mutable changed = true
  while changed do
    changed <- false
    for b in rpoNodes do
      let processedPreds = getProcessedPreds g idoms dummyRoot realRoots b
      let mutable newIdom = processedPreds[0]
      for p in processedPreds[1..] do
        newIdom <- intersect idoms poNumbers p newIdom
      if idoms[b] <> newIdom then
        idoms[b] <- newIdom
        changed <- true
  idoms

let rec private doms acc v (idoms: Dictionary<_, IVertex<_>>) =
  let idom = idoms[v]
  if idom.ID = -1 then acc |> List.toArray
  else doms (idom :: acc) idom idoms

let private idom (idoms: Dictionary<_, IVertex<_>>) v =
  let idom = idoms[v]
  if idom.ID = -1 then null
  else idom

let private computePostDominance (g: IDiGraph<_, _>) =
  let g' = GraphUtils.findExits g |> g.Reverse
  let backwardDom = computeDominance g'
  {| Graph = g'; IDoms = backwardDom |}

[<CompiledName "Create">]
let create (g: IDiGraph<'V, 'E>) (dfp: IDominanceFrontierProvider<_, _>) =
  let idoms = computeDominance g
  let domTree = lazy DominatorTree (g, fun v -> idoms[v])
  let mutable dfProvider = null
  let backward = lazy computePostDominance g
  { new IDominance<'V, 'E> with
      member _.Dominators v =
#if DEBUG
        GraphUtils.checkVertexInGraph g v
#endif
        doms [v] v idoms

      member _.ImmediateDominator v =
#if DEBUG
        GraphUtils.checkVertexInGraph g v
#endif
        idom idoms v

      member __.DominanceFrontier v =
#if DEBUG
        GraphUtils.checkVertexInGraph g v
#endif
        if isNull dfProvider then
          dfProvider <- dfp.CreateIDominanceFrontier (g, __)
        else ()
        dfProvider.DominanceFrontier v

      member __.DominatorTree =
        domTree.Value

      member _.PostDominators v =
        doms [v] v backward.Value.IDoms

      member _.ImmediatePostDominator v =
        let g' = backward.Value.Graph
        let v = g'.FindVertexByData v.VData
        idom backward.Value.IDoms v }
