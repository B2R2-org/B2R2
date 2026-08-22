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
(* The dominators every predecessor of the given vertex has in common, plus
   the vertex itself, in a set of their own. A vertex with no predecessor left
   to read dominates only itself. *)
let private intersectDoms (doms: Dictionary<_, HashSet<_>>) v (preds: _[]) =
  let acc = HashSet<IVertex<_>>()
  if preds.Length > 0 then
    acc.UnionWith doms[preds[0]]
    for i in 1 .. preds.Length - 1 do acc.IntersectWith doms[preds[i]]
  else
    ()
  acc.Add v |> ignore
  acc

let private computeDoms (g: IDiGraph<_, _>) reachables =
  let doms = Dictionary<IVertex<_>, HashSet<IVertex<_>>>()
  let nonRoots = List()
  (* Every non-root starts out dominated by everything, and this one set is
     what they all start with: the loop below only ever puts a freshly built
     set in place of the one it finds, and never mutates that one. *)
  let all = HashSet(reachables: HashSet<IVertex<_>>)
  for r in g.Roots do doms[r] <- HashSet [ r ]
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
      let preds = g.GetPreds v |> Array.filter (fun p -> reachables.Contains p)
      let newDoms = intersectDoms doms v preds
      if newDoms.SetEquals doms[v] then
        ()
      else
        doms[v] <- newDoms
        changed <- true
  doms

(* The immediate dominator is the one dominator left once those that another
   dominator dominates are struck out. A graph with several exits can leave
   more than one, in which case the one carrying the smallest ID is taken, so
   that the answer does not follow the order a hash set enumerates in. *)
let private pickIDom (candidates: HashSet<IVertex<'V>>): IVertex<'V> | null =
  if candidates.Count = 0 then null
  else candidates |> Seq.minBy (fun v -> v.ID)

let private computeIDoms g (doms: Dictionary<_, HashSet<_>>) =
  let idoms = Dictionary<IVertex<_>, IVertex<_> | null>()
  let tmps = Dictionary<IVertex<_>, HashSet<IVertex<_>>>()
  let vertices = Array.ofSeq doms.Keys
  for v in vertices do
    let strict = HashSet doms[v]
    strict.Remove v |> ignore
    tmps[v] <- strict
  for r in (g: IDiGraph<_, _>).Roots do idoms[r] <- null
  for v in vertices do
    if idoms.ContainsKey v then
      ()
    else
      (* Striking one out changes what is left to read, hence each pass over
         the remainder walks a snapshot of it rather than the set itself. *)
      let strict = tmps[v]
      for s in Array.ofSeq strict do
        for t in Array.ofSeq strict do
          if obj.ReferenceEquals(s, t) || not (tmps[s].Contains t) then ()
          else strict.Remove t |> ignore
  for v in vertices do
    (* ipdom may not exist when there are multiple exit nodes. *)
    if idoms.ContainsKey v then () else idoms[v] <- pickIDom tmps[v]
  idoms

(* An unreachable vertex has no entry in the tables, in which case it only
   dominates itself and has no immediate dominator. *)
let private findDoms (doms: Dictionary<_, HashSet<_>>) v =
  match doms.TryGetValue v with
  | true, ds -> ds
  | false, _ -> HashSet [ v ]

let private findIDom (idoms: Dictionary<_, _>) v: IVertex<'V> | null =
  match idoms.TryGetValue v with
  | true, idom -> idom
  | false, _ -> null

let private createForwardDominance g (dfp: IDominanceFrontierProvider<_, _>) =
  let g: IDiGraph<_, _> = g
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
  combineDominance g bwG fw bw
