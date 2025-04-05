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
  /// PONum -> array of PONum of the predecessors.
  Preds: int[][]
}

let private initDomInfo (g: IDiGraphAccessible<_, _>) =
  (* To reserve a room for entry (dummy) node. *)
  let len = g.Size + 1
  { PONumMap = Dictionary<VertexID, int> ()
    Vertex = Array.zeroCreate len
    IDom = Array.create len -1
    Preds = Array.zeroCreate len }

let private prepareWithDummyRoot g info (dummyRoot: IVertex<_>) =
  let realRoots = (g: IDiGraphAccessible<_, _>).GetRoots ()
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
  for i = 0 to n - 1 do
    let v = info.Vertex[i]
    let preds =
      if realRoots |> Array.contains v then
        [| n;
           yield! (g: IDiGraphAccessible<_, _>).GetPreds v
                  |> Array.map (fun p -> info.PONumMap[p.ID]) |]
      else
        g.GetPreds v
        |> Array.map (fun p -> info.PONumMap[p.ID])
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

let private computeDominance (g: IDiGraphAccessible<_, _>) =
  let info = initDomInfo g
  let dummyRoot = GraphUtils.makeDummyVertex ()
  let n = prepareWithDummyRoot g info dummyRoot
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

let private createDomInfo g (dfp: IDominanceFrontierProvider<_, _>) =
  let idoms = computeDominance g
  let domTree = lazy DominatorTree (g, fun v -> idom idoms v)
  idoms, domTree


type private CooperDominance<'V, 'E when 'V: equality and 'E: equality>
  (g, dfp) =
  let forward = createDomInfo g dfp
  let backwardG = lazy (GraphUtils.findExits g |> g.Reverse)
  let backward = lazy (createDomInfo backwardG.Value dfp)
  let mutable dfProvider = null
  let mutable pdfProvider = null
  interface IDominance<'V, 'E> with
    member _.Dominators v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      let idoms, _ = forward
      doms [v] v idoms

    member _.ImmediateDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      let idoms, _ = forward
      idom idoms v

    member _.DominatorTree =
      let _, domTree = forward
      domTree.Value

    member this.DominanceFrontier v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      if isNull dfProvider then
        dfProvider <- dfp.CreateIDominanceFrontier (g, this, false)
      else ()
      dfProvider.DominanceFrontier v

    member _.PostDominators v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      let idoms, _ = backward.Value
      doms [v] v idoms

    member _.ImmediatePostDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      let idoms, _ = backward.Value
      idom idoms v

      member _.PostDominatorTree =
        let _, domTree = backward.Value
        domTree.Value

    member this.PostDominanceFrontier v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      if isNull pdfProvider then
        pdfProvider <-
          dfp.CreateIDominanceFrontier (backwardG.Value, this, true)
      else ()
      pdfProvider.DominanceFrontier v

[<CompiledName "Create">]
let create g (dfp: IDominanceFrontierProvider<_, _>) =
  CooperDominance (g, dfp) :> IDominance<_, _>
