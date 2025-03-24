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

type private DomInfo<'V when 'V: equality> = {
  /// Vertex ID -> PONum
  PONumMap: Dictionary<VertexID, int>
  /// PONum -> Vertex ID
  Vertex: IVertex<'V>[]
  /// PONum -> PONum of the immediate dominator.
  IDom: int[]
}

let private initDomInfo (g: IDiGraphAccessible<_, _>) =
  (* To reserve a room for entry (dummy) node. *)
  let len = g.Size + 1
  { PONumMap = Dictionary<VertexID, int> ()
    Vertex = Array.zeroCreate len
    IDom = Array.create len -1}

let private prepareWithDummyRoot g info (dummyRoot: IVertex<_>) realRoots =
  let n =
    Traversal.DFS.foldPostorderWithRoots g
      (realRoots |> Array.toList) (fun n v ->
       info.PONumMap[v.ID] <- n
       info.Vertex[n] <- v
       n + 1) 0
  info.PONumMap[dummyRoot.ID] <- n
  info.Vertex[n] <- dummyRoot
  for i = 0 downto n - 1 do info.IDom[i] <- -1
  for r in realRoots |> Array.map (fun v -> info.PONumMap[v.ID]) do
    info.IDom[r] <- n
  info.IDom[n] <- n
  n

let private getProcessedPreds g info (dummyRoot: IVertex<_>) realRoots i =
  let v = (info: DomInfo<_>).Vertex[i]
  let preds =
    if realRoots |> Array.contains v then
      [| dummyRoot;
        yield! (g: IDiGraphAccessible<_,_>).GetPreds v |]
    else g.GetPreds v
  preds
  |> Array.map (fun p -> info.PONumMap[p.ID])
  |> Array.filter (fun p -> info.IDom[p] <> -1)

let private intersect (idoms: array<int>) b1 b2 =
  let mutable f1 = b1
  let mutable f2 = b2
  while f1 <> f2 do
    while f1 < f2 do
      f1 <- idoms[f1]
    while f2 < f1 do
      f2 <- idoms[f2]
  f1

let private computeDominance (g: IDiGraphAccessible<_, _>) =
  let info = initDomInfo g
  let dummyRoot = GraphUtils.makeDummyVertex ()
  let realRoots = (g: IDiGraphAccessible<_, _>).GetRoots ()
  let n = prepareWithDummyRoot g info dummyRoot realRoots
  let mutable changed = true
  while changed do
    changed <- false
    for i = n - 1 downto 0 do
      let processedPreds = getProcessedPreds g info dummyRoot realRoots i
      let mutable newIdom = processedPreds[0]
      for p in processedPreds[1..] do
        newIdom <- intersect info.IDom p newIdom
      if info.IDom[i] <> newIdom then
        info.IDom[i] <- newIdom
        changed <- true
  let idoms = Dictionary<IVertex<_>, IVertex<_>> ()
  for i = n - 1 downto 0 do
    let v = info.Vertex[i]
    let idom = info.IDom[i]
    if idom = -1 then
      idoms[v] <- dummyRoot
    else
      idoms[v] <- info.Vertex[idom]
  idoms[dummyRoot] <- dummyRoot
  idoms

let rec private doms acc v (idoms: Dictionary<_, IVertex<_>>) =
  let idom = idoms[v]
  if idom.ID = -1 then acc |> List.toArray
  else doms (idom :: acc) idom idoms

let private idom (idoms: Dictionary<_, IVertex<_>>) v =
  let idom = idoms[v]
  if idom.ID = -1 then null
  else idom

let private computePostDominance (g: IDiGraphAccessible<_, _>) =
  let g' = GraphUtils.findExits g |> g.Reverse
  let backwardDom = computeDominance g'
  {| Graph = g'; IDoms = backwardDom |}

[<CompiledName "Create">]
let create g (dfp: IDominanceFrontierProvider<_, _>) =
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
