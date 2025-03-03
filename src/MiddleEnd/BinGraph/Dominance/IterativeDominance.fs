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

let computeDoms (g: IDiGraphAccessible<_, _>) =
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

let computeIDoms (g: IDiGraphAccessible<_, _>) roots (doms: Dictionary<_, _>) =
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

let computePostDoms (g: IDiGraph<_, _>) =
  GraphUtils.findExits g
  |> g.Reverse
  |> computeDoms

[<CompiledName "Create">]
let create (g: IDiGraph<'V, 'E>)
           (dfp: IDominanceFrontierProvider<_, _>) =
  let doms = lazy computeDoms g
  let pdoms = lazy computePostDoms g
  let idoms = lazy computeIDoms g (g.GetRoots ()) doms.Value
  let ipdoms = lazy computeIDoms g (GraphUtils.findExits g) pdoms.Value
  let idom v = idoms.Value[v]
  let ipdom v = ipdoms.Value[v]
  let domTree = lazy DominatorTree (g, idom)
  let mutable dfProvider = null
  { new IDominance<'V, 'E> with
      member _.Dominators v =
        doms.Value[v]

      member _.ImmediateDominator v =
        idom v

      member __.DominatorTree =
        domTree.Value

      member _.PostDominators v =
        pdoms.Value[v]

      member _.ImmediatePostDominator v =
        ipdom v

      member __.DominanceFrontier v =
        if isNull dfProvider then
          dfProvider <- dfp.CreateIDominanceFrontier (g, __)
        else ()
        dfProvider.DominanceFrontier v }
