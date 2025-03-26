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

/// Simplisitic iterative dominance algorithm.
module B2R2.MiddleEnd.BinGraph.Dominance.IterativeDominance

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

let private computeDoms (g: IDiGraphAccessible<_, _>) =
  let doms = Dictionary<IVertex<_>, Set<IVertex<_>>> ()
  let roots = g.GetRoots ()
  let allButRoots = List ()
  let all = Set g.Vertices
  for r in roots do doms[r] <- Set.singleton r
  for v in g.Vertices do
    if doms.ContainsKey v then ()
    else doms[v] <- all; allButRoots.Add v |> ignore
  let mutable changed = true
  while changed do
    changed <- false
    for v in allButRoots do
      let predDoms = Set.intersectMany [ for p in g.GetPreds v -> doms[p] ]
      let newDoms = Set.add v predDoms
      if newDoms <> doms[v] then
        doms[v] <- newDoms
        changed <- true
      else ()
  doms

let private computeIDoms g (doms: Dictionary<_, _>) =
  let roots = (g: IDiGraphAccessible<_, _>).GetRoots ()
  let idoms = Dictionary<IVertex<_>, IVertex<_>> ()
  let tmps = Dictionary<IVertex<_>, Set<IVertex<_>>> ()
  for v in g.Vertices do tmps[v] <- Set.remove v doms[v]
  for r in roots do idoms[r] <- null
  for v in g.Vertices do
    if idoms.ContainsKey v then ()
    else
      for s in tmps[v] do
        for t in Set.remove s tmps[v] do
          if Set.contains t tmps[s] then tmps[v] <- Set.remove t tmps[v]
          else ()
  for v in g.Vertices do
    if idoms.ContainsKey v then ()
    else
      (* ipdom may not exist when there are multiple exit nodes. *)
      idoms[v] <- if Set.isEmpty tmps[v] then null else tmps[v].MinimumElement
  idoms

let private createDomInfo g (dfp: IDominanceFrontierProvider<_, _>) =
  let doms = lazy computeDoms g
  let idoms = lazy computeIDoms g doms.Value
  let idom v = idoms.Value[v]
  let domTree = lazy DominatorTree (g, idom)
  doms, idoms, domTree

type private IterativeDominance<'V, 'E when 'V: equality and 'E: equality>
  (g, dfp) =
  let forward = createDomInfo g dfp
  let backwardG = lazy (GraphUtils.findExits g |> g.Reverse)
  let backward = lazy (createDomInfo backwardG.Value dfp)
  let mutable dfProvider = null
  let mutable pdfProvider = null
  interface IDominance<'V, 'E> with
    member __.Dominators v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      let doms, _, _ = forward
      doms.Value[v]

    member __.ImmediateDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      let _, idoms, _ = forward
      idoms.Value[v]

    member __.DominatorTree =
      let _, _, domTree = forward
      domTree.Value

    member __.DominanceFrontier v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      if isNull dfProvider then
        dfProvider <- dfp.CreateIDominanceFrontier (g, __, false)
      else ()
      dfProvider.DominanceFrontier v

    member __.PostDominators v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      let doms, _, _ = backward.Value
      doms.Value[v]

    member __.ImmediatePostDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      let _, idoms, _ = backward.Value
      idoms.Value[v]

    member __.PostDominatorTree =
      let _, _, domTree = backward.Value
      domTree.Value

    member __.PostDominanceFrontier v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      if isNull pdfProvider then
        pdfProvider <- dfp.CreateIDominanceFrontier (backwardG.Value, __, true)
      else ()
      pdfProvider.DominanceFrontier v

[<CompiledName "Create">]
let create g (dfp: IDominanceFrontierProvider<_, _>) =
  IterativeDominance (g, dfp) :> IDominance<'V, 'E>