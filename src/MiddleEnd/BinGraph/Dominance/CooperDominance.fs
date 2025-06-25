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

type private CPDomInfo<'V when 'V: equality> = {
  /// Vertex ID -> Num
  NumMap: Dictionary<VertexID, int>
  /// Num -> Vertex ID
  Vertex: IVertex<'V>[]
  /// Num -> Num of the immediate dominator.
  IDom: int[]
  /// Num -> array of Num of the predecessors.
  Preds: int[][]
  /// Real roots of graph
  Roots: IVertex<'V>[]
  /// Dummy root
  DummyRoot: IVertex<'V>
}

let private initDomInfo (g: IDiGraphAccessible<_, _>) =
  (* To reserve a room for entry (dummy) node. *)
  let len = g.Size + 1
  { NumMap = Dictionary<VertexID, int> ()
    Vertex = Array.zeroCreate len
    IDom = Array.create len -1
    Preds = Array.zeroCreate len
    Roots = g.GetRoots ()
    DummyRoot = GraphUtils.makeDummyVertex () }

let private prepareWithDummyRoot g info =
  let realRoots = info.Roots
  let n =
#if COOPER_USE_DFS
    Traversal.DFS.foldPostorderWithRoots3 g
#else
    Traversal.BFS.reverseFoldWithRoots g
#endif
      (realRoots |> Array.toList) (fun n v ->
       info.NumMap[v.ID] <- n
       info.Vertex[n] <- v
       n + 1) 0
  info.NumMap[info.DummyRoot.ID] <- n
  info.Vertex[n] <- info.DummyRoot
  for r in realRoots |> Array.map (fun v -> info.NumMap[v.ID]) do
    info.IDom[r] <- n
  info.IDom[n] <- n
  for i = 0 to n - 1 do
    let v = info.Vertex[i]
    let preds =
      if realRoots |> Array.contains v then
        [| n
           yield! (g: IDiGraphAccessible<_, _>).GetPreds v
                  |> Array.map (fun p -> info.NumMap[p.ID]) |]
      else
        g.GetPreds v
        |> Array.map (fun p -> info.NumMap[p.ID])
    info.Preds[i] <- preds
  n

let private getProcessedPreds info i =
  info.Preds[i]
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
let rec private domsAux acc v info =
  if info.NumMap.ContainsKey (v: IVertex<'V>).ID then
    let idom = info.IDom[info.NumMap[v.ID]]
    if idom = -1 || idom = info.NumMap[info.DummyRoot.ID]
    then acc |> List.toArray
    else domsAux (info.Vertex[idom] :: acc) info.Vertex[idom] info
  else acc |> List.toArray

let private idomAux info v =
  if info.NumMap.ContainsKey (v: IVertex<'V>).ID then
    let num = info.IDom[info.NumMap[v.ID]]
    if num <> -1 && num <> info.NumMap[info.DummyRoot.ID] then info.Vertex[num]
    else null
  else null

let private prepareDomInfo (g: IDiGraphAccessible<_, _>) =
  let info = initDomInfo g
  let n = prepareWithDummyRoot g info
  info, n

let private computeIDom info n  =
  let mutable changed = true
  while changed do
    changed <- false
    for i = n - 1 downto 0 do
      let processedPreds = getProcessedPreds info i
      let mutable newIdom = processedPreds[0]
      for p in processedPreds[1..] do
        newIdom <- intersect info.IDom p newIdom
      if info.IDom[i] <> newIdom then
        info.IDom[i] <- newIdom
        changed <- true
  info

let private computeDomInfo g =
  let info, n = prepareDomInfo g
  computeIDom info n

let private createDominance fwG (bwG: Lazy<IDiGraphAccessible<_, _>>) fwInfo
                            (fwDT: Lazy<DominatorTree<_,_>>)
                            (bwInfo: Lazy<CPDomInfo<_>>)
                            (bwDT: Lazy<DominatorTree<_,_>>)
                            (dfp: IDominanceFrontierProvider<_, _>) =
  let mutable dfProvider = null
  let mutable pdfProvider = null
  { new IDominance<'V, 'E> with
    member __.Dominators v =
#if DEBUG
      GraphUtils.checkVertexInGraph fwG v
#endif
      domsAux [v] v fwInfo

    member _.ImmediateDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph fwG v
#endif
      idomAux fwInfo v

    member __.DominatorTree =
      fwDT.Value

    member __.DominanceFrontier v =
#if DEBUG
      GraphUtils.checkVertexInGraph fwG v
#endif
      if isNull pdfProvider then
        pdfProvider <- dfp.CreateIDominanceFrontier (fwG, __, false)
      else ()
      pdfProvider.DominanceFrontier v

    member _.PostDominators v =
#if DEBUG
      GraphUtils.checkVertexInGraph bwG.Value v
#endif
      domsAux [v] v bwInfo.Value

    member _.ImmediatePostDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph bwG.Value v
#endif
      idomAux bwInfo.Value v

    member __.PostDominatorTree =
      bwDT.Value

    member __.PostDominanceFrontier v =
#if DEBUG
      GraphUtils.checkVertexInGraph bwG.Value v
#endif
      if isNull dfProvider then
        dfProvider <- dfp.CreateIDominanceFrontier (bwG.Value, __, true)
      else ()
      dfProvider.DominanceFrontier v }

let private computeDominance g (dfp: IDominanceFrontierProvider<_, _>) =
  let fwInfo = computeDomInfo g
  let fwDT = lazy DominatorTree (g, idomAux fwInfo)
  let bwG = lazy (GraphUtils.findExits g |> g.Reverse)
  let bwInfo = lazy computeDomInfo bwG.Value
  let bwDT = lazy DominatorTree (bwG.Value, idomAux bwInfo.Value)
  createDominance g bwG fwInfo fwDT bwInfo bwDT dfp, fwInfo, bwInfo

[<CompiledName "Create">]
let create g (dfp: IDominanceFrontierProvider<_, _>) =
  let dom, _, _ = computeDominance g dfp
  dom
