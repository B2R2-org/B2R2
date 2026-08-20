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

/// <namespacedoc>
///   <summary>
///   Contains implementations of dominance algorithms for directed graphs.
///   </summary>
/// </namespacedoc>
///
/// <summary>
/// Provides a simplistic iterative dominance algorithm.
/// </summary>
module B2R2.MiddleEnd.BinGraph.Dominance.IterativeDominance

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

(* A vertex unreachable from the roots has no dominator, so we compute the
   dominators of the reachable vertices only. Note that the predecessors of a
   reachable vertex may be unreachable, in which case they carry no dominance
   information and thus should not participate in the intersection below. *)
let private computeDoms (g: IDiGraphAccessible<_, _>) reachables =
  let doms = Dictionary<IVertex<_>, Set<IVertex<_>>>()
  let nonRoots = List()
  let all = Set.ofSeq (reachables: HashSet<IVertex<_>>)
  for r in g.GetRoots() do doms[r] <- Set.singleton r
  for v in reachables do
    if doms.ContainsKey v then ()
    else
      doms[v] <- all
      nonRoots.Add v
  let mutable changed = true
  while changed do
    changed <- false
    for v in nonRoots do
      let predDoms =
        g.GetPreds v
        |> Array.filter (fun p -> reachables.Contains p)
        |> Array.map (fun p -> doms[p])
      let newDoms =
        if Array.isEmpty predDoms then Set.singleton v
        else Set.add v (Set.intersectMany predDoms)
      if newDoms <> doms[v] then
        doms[v] <- newDoms
        changed <- true
      else
        ()
  doms

let private computeIDoms g (doms: Dictionary<_, _>) =
  let idoms = Dictionary<IVertex<_>, IVertex<_> | null>()
  let tmps = Dictionary<IVertex<_>, Set<IVertex<_> | null>>()
  let vertices = Array.ofSeq doms.Keys
  for v in vertices do tmps[v] <- Set.remove v doms[v]
  for r in (g: IDiGraphAccessible<_, _>).GetRoots() do idoms[r] <- null
  for v in vertices do
    if idoms.ContainsKey v then ()
    else
      for s in tmps[v] do
        for t in Set.remove s tmps[v] do
          if Set.contains t tmps[s] then tmps[v] <- Set.remove t tmps[v]
          else ()
  for v in vertices do
    if idoms.ContainsKey v then
      ()
    else
      (* ipdom may not exist when there are multiple exit nodes. *)
      idoms[v] <- if Set.isEmpty tmps[v] then null else tmps[v].MinimumElement
  idoms

(* An unreachable vertex has no entry in the tables, in which case it only
   dominates itself and has no immediate dominator. *)
let private findDoms (doms: Dictionary<_, _>) v =
  match doms.TryGetValue v with
  | true, ds -> ds
  | false, _ -> Set.singleton v

let private findIDom (idoms: Dictionary<_, _>) v: IVertex<'V> | null =
  match idoms.TryGetValue v with
  | true, idom -> idom
  | false, _ -> null

let private createDomInfo g (dfp: IDominanceFrontierProvider<_, _>) =
  let doms = lazy computeDoms g (GraphUtils.computeReachables g)
  let idoms = lazy computeIDoms g doms.Value
  let domTree = lazy DominatorTree(g, findIDom idoms.Value)
  doms, idoms, domTree

type private IterativeDominance<'V, 'E when 'V: equality and 'E: equality>
  (g, dfp) =
  let forward = createDomInfo g dfp
  let backwardG = lazy (GraphUtils.findExits g |> g.Reverse)
  let backward = lazy (createDomInfo backwardG.Value dfp)
  let mutable dfProvider = null
  let mutable pdfProvider = null
  interface IDominance<'V, 'E> with
    member _.DominatorTree =
      let _, _, domTree = forward
      domTree.Value

    member _.PostDominatorTree =
      let _, _, domTree = backward.Value
      domTree.Value

    member _.Dominators v =
      GraphUtils.checkVertexInGraph g v
      let doms, _, _ = forward
      findDoms doms.Value v

    member _.ImmediateDominator v =
      GraphUtils.checkVertexInGraph g v
      let _, idoms, _ = forward
      findIDom idoms.Value v

    member this.DominanceFrontier v =
      GraphUtils.checkVertexInGraph g v
      if isNull dfProvider then
        dfProvider <- dfp.CreateIDominanceFrontier(g, this, false)
      else
        ()
      dfProvider.DominanceFrontier v

    member _.PostDominators v =
      GraphUtils.checkVertexInGraph g v
      let doms, _, _ = backward.Value
      findDoms doms.Value v
      |> Set.map (findOriginalVertex g)
      |> Set.toSeq

    member _.ImmediatePostDominator v =
      GraphUtils.checkVertexInGraph g v
      let _, idoms, _ = backward.Value
      findIDom idoms.Value v
      |> findOriginalVertex g

    member this.PostDominanceFrontier v =
      GraphUtils.checkVertexInGraph g v
      if isNull pdfProvider then
        pdfProvider <-
          dfp.CreateIDominanceFrontier(backwardG.Value, this, true)
      else
        ()
      pdfProvider.DominanceFrontier v
      |> Seq.map (findOriginalVertex g)

/// Creates an IDominance instance that computes dominance information using a
/// simplistic iterative algorithm.
[<CompiledName "Create">]
let create g (dfp: IDominanceFrontierProvider<_, _>) =
  IterativeDominance(g, dfp) :> IDominance<'V, 'E>
