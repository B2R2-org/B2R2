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
///   Every module here exposes a single <c>create</c> function returning an
///   IDominance, and they differ only in how they arrive at it.
///   LengauerTarjanDominance is the safe default, since its worst case is
///   near-linear; SemiNCADominance is usually faster on a control-flow graph;
///   CooperDominance and IterativeDominance are the simple ones; and
///   DepthBasedSearchDominance is the one built to absorb edge insertions.
///   </summary>
/// </namespacedoc>
///
/// <summary>
/// Provides a simplistic iterative dominance algorithm.
/// </summary>
[<RequireQualifiedAccess>]
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
    if doms.ContainsKey v then
      ()
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
    if idoms.ContainsKey v then
      ()
    else
      for s in tmps[v] do
        for t in Set.remove s tmps[v] do
          if Set.contains t tmps[s] then tmps[v] <- Set.remove t tmps[v] else ()
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

let private createForwardDominance g (dfp: IDominanceFrontierProvider<_, _>) =
  let g: IDiGraphAccessible<_, _> = g
  let doms = lazy computeDoms g (GraphUtils.computeReachables g)
  let idoms = lazy computeIDoms g doms.Value
  let dt = lazy DominatorTree(g.Vertices, findIDom idoms.Value)
  let mutable dfProvider = null
  { new IForwardDominance<'V> with
      member _.Dominators v =
        GraphUtils.checkVertexInGraph g v
        findDoms doms.Value v
      member _.ImmediateDominator v =
        GraphUtils.checkVertexInGraph g v
        findIDom idoms.Value v
      member _.DominatorTree = dt.Value
      member this.DominanceFrontier v =
        GraphUtils.checkVertexInGraph g v
        if isNull dfProvider then
          dfProvider <- dfp.CreateIDominanceFrontier(g, this)
        else
          ()
        dfProvider.DominanceFrontier v }

/// <summary>
/// Creates an IDominance instance that computes dominance information using a
/// simplistic iterative algorithm, which intersects the dominator sets of the
/// predecessors of every vertex until no set changes any more. Being the
/// textbook formulation, it is the easiest to trust and the slowest to run;
/// reach for it when a reference implementation is worth more than speed.
/// </summary>
/// <param name="g">The graph to compute the dominance of.</param>
/// <param name="dfp">Provides the dominance frontier implementation, which is
/// created only when a frontier is first requested.</param>
[<CompiledName "Create">]
let create g dfp =
  let bwG = lazy (GraphUtils.findExits g |> g.Reverse)
  let fw = createForwardDominance g dfp
  let bw = lazy (createForwardDominance bwG.Value dfp)
  combineDominance g fw bw
