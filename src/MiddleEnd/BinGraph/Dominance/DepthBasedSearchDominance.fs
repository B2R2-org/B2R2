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

/// Provides Georgiadis et al.'s algorithm for dynamic dominance computation
/// presented in "An Experimental Study of Dynamic Dominators", ESA 2012.
[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.BinGraph.Dominance.DepthBasedSearchDominance

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

/// Represents the dominator tree that this module maintains incrementally.
/// Mutating it silently invalidates the dominance computed from it, so it stays
/// internal, visible only to the dynamic-dominance benchmark, which updates a
/// dominance edge by edge.
type internal DBSDomInfo<'V, 'E when 'V: equality and 'E: equality> =
  { /// Static dominance algorithm.
    StaticAlgo: StaticDominanceAlgorithm
    /// Dominance frontier provider.
    DFP: IDominanceFrontierProvider<'V, 'E>
    /// Vertex -> Num.
    Num: Dictionary<IVertex<'V>, int>
    /// Num -> Vertex. The dummy root takes the number after them all, and it
    /// has no vertex, hence no room here.
    Vertex: IVertex<'V>[]
    /// Num -> whether a root reaches the vertex.
    Reachable: bool[]
    /// Num -> Num of an immediate dominator, or -1 where there is none yet.
    IDom: int[]
    /// Num -> Nums of the children in the dominator tree.
    Children: HashSet<int>[]
    /// Num -> depth in the dominator tree, or -2 where the vertex has no place
    /// in it yet.
    Depth: int[]
    /// Num of the dummy root, which sits above every real root so that a graph
    /// of many roots reads as one of a single root.
    DummyNum: int }

(* Numbers every vertex of the graph, the ones no root reaches included, for an
   inserted edge can bring one of those into the tree later on. *)
let private numberVertices (g: IDiGraph<_, _>) =
  let vertices = g.Vertices
  let num = Dictionary<IVertex<_>, int>()
  for i in 0 .. vertices.Length - 1 do num[vertices[i]] <- i
  num, vertices

let private initInfo g dfp algo seedRoots =
  let num, vertices = numberVertices g
  let len = vertices.Length + 1
  let dummy = vertices.Length
  let info =
    { StaticAlgo = algo
      DFP = dfp
      Num = num
      Vertex = vertices
      Reachable = Array.zeroCreate len
      IDom = Array.create len -1
      Children = Array.init len (fun _ -> HashSet<int>())
      Depth = Array.create len -2
      DummyNum = dummy }
  info.Depth[dummy] <- -1
  for r in (g: IDiGraph<_, _>).Roots do
    let n = num[r]
    info.Depth[n] <- 0
    info.IDom[n] <- dummy
    info.Children[dummy].Add n |> ignore
    if seedRoots then info.Reachable[n] <- true else ()
  info

let private initDynamicDomInfo g dfp algo = initInfo g dfp algo true

let private initDomInfo g dfp algo = initInfo g dfp algo false

let private getNCA info v w =
  let rec bothUp v w = if v = w then v else bothUp info.IDom[v] info.IDom[w]
  let rec singleUp v w =
    if info.Depth[v] = info.Depth[w] then bothUp v w
    else singleUp v info.IDom[w]
  if info.Depth[v] < info.Depth[w] then singleUp v w
  else if info.Depth[v] > info.Depth[w] then singleUp w v
  else bothUp v w

let rec private computeTriggers g info visited nca trig state = function
  | [] ->
    state
  | n :: stack ->
    let affected, trigs = state
    (visited: HashSet<int>).Add n |> ignore
    let newAffected, newTrigs, newStack =
      (g: IDiGraph<_, _>).GetSuccs info.Vertex[n]
      |> Array.fold (fun (affected, trigs, stack) w ->
        let wn = info.Num[w]
        if visited.Contains wn then
          affected, trigs, stack
        else
          visited.Add wn |> ignore
          if info.Depth[wn] > info.Depth[trig] then
            affected, trigs, wn :: stack
          else if info.Depth[nca] + 1 < info.Depth[wn] then
            wn :: affected, wn :: trigs, stack
          else
            affected, trigs, stack) (affected, trigs, stack)
    computeTriggers g info visited nca trig (newAffected, newTrigs) newStack

let rec private computeAffectedAux g info visited nca = function
  | affected, [] ->
    affected |> Array.ofList
  | affected, trig :: trigs ->
    let state =
      computeTriggers g info visited nca trig (affected, trigs) [ trig ]
    computeAffectedAux g info visited nca state

let private computeAffected g info nca trigger =
  computeAffectedAux g info (HashSet()) nca ([ trigger ], [ trigger ])

let rec private updateDepth depth info v =
  info.Depth[v] <- depth
  info.Children[v]
  |> Seq.iter (updateDepth (depth + 1) info)

let private updateIDom newIDom info v =
  info.Children[newIDom].Add v |> ignore
  let oldIDom = info.IDom[v]
  if oldIDom = -1 then () else info.Children[oldIDom].Remove v |> ignore
  info.IDom[v] <- newIDom
  let depth = info.Depth[newIDom] + 1
  updateDepth depth info v

/// Update dominator tree when an edge from src to dst is added where
/// src and dst are both reachable from roots.
let private updateDomTree g info src dst =
  let nca = getNCA info src dst
  if nca = info.IDom[dst] || nca = dst then
    ()
  else
    let affected = computeAffected g info nca dst
    affected
    |> Array.iter (updateIDom nca info)

(* Walks the vertices the given edges lead to, collecting the ones no root
   reaches yet, and answers the edges that leave them for the reachable part.
   The pending edges wait in a queue, for appending them onto a list copies
   the whole list on every step. *)
let private collectSubGraphAux g info visited (queue: Queue<Edge<_, _>>) =
  let mutable bEdges = []
  while queue.Count > 0 do
    let edge = queue.Dequeue()
    let w = edge.Second
    if (visited: HashSet<IVertex<_>>).Contains w then
      ()
    elif info.Reachable[info.Num[w]] then
      bEdges <- edge :: bEdges
    else
      visited.Add w |> ignore
      for e in (g: IDiGraph<_, _>).GetSuccEdges w do queue.Enqueue e
  bEdges |> Array.ofList

/// Views the subgraph rooted at dst that the vertices unreachable from the
/// roots of the main graph induce, and answers the edges leaving it. Every
/// edge among those vertices is one of the subgraph, which is what lets the
/// walk collect the vertices alone.
let private constructSubGraph (g: IDiGraph<_, _>) info dst =
  let visited = HashSet [ dst ]
  let queue = Queue(g.GetSuccEdges dst)
  let bEdges = collectSubGraphAux g info visited queue
  let vs = GraphUtils.toArray visited
  SubDiGraph(g, vs, [| dst |]) :> IDiGraph<_, _>, bEdges

let private computeStaticDom info g =
  StaticDominance.create g info.DFP info.StaticAlgo

(* The pending pairs wait in a queue, for appending them onto a list copies
   the whole list on every step. *)
let private mergeDomTree info src dst (subDom: IForwardDominance<_>) =
  let subDomTree = subDom.DominatorTree
  let queue = Queue<struct (int * IVertex<_>)>()
  queue.Enqueue(struct (src, dst))
  while queue.Count > 0 do
    let struct (parent, current) = queue.Dequeue()
    let n = info.Num[current]
    updateIDom parent info n
    for child in subDomTree.GetChildren current do
      queue.Enqueue(struct (n, child))

/// insert an edge into the graph and update the dominator tree
let private insert (g: IDiGraph<_, _>) info (edge: Edge<_, _>) =
  let src = info.Num[edge.First]
  let dst = edge.Second
  let dstNum = info.Num[dst]
  match info.Reachable[src], info.Reachable[dstNum] with
  | false, _ ->
    ()
  | true, true ->
    updateDomTree g info src dstNum
  | true, false ->
    match g.GetSuccs dst with
    | [||] ->
      info.Reachable[dstNum] <- true
      updateIDom src info dstNum
    | _ ->
      let subG, bEdges = constructSubGraph g info dst
      let subDom = computeStaticDom info subG
      mergeDomTree info src dst subDom
      bEdges
      |> Array.iter (fun edge ->
        updateDomTree g info src info.Num[edge.Second])
      subG.Vertices
      |> Array.iter (fun v ->
        info.Reachable[info.Num[v]] <- true)

let private computeDomDyn (g: IDiGraph<_, _>) info =
  g.Edges
  |> Array.iter (insert g info)

let private idom info (v: IVertex<'V>) =
  let n = info.Num[v]
  let d = info.IDom[n]
  if d = -1 || d = info.DummyNum then null
  else info.Vertex[d]: IVertex<'V> | null

let rec private domsAux acc info n =
  let d = info.IDom[n]
  if d = -1 || d = info.DummyNum then acc else domsAux (d :: acc) info d

let private doms info (v: IVertex<'V>) =
  let n = info.Num[v]
  domsAux [ n ] info n
  |> List.toArray
  |> Array.map (fun i -> info.Vertex[i])

let private computeDomInfo g dfp staticAlgo =
  let info = initDynamicDomInfo g dfp staticAlgo
  computeDomDyn g info
  info

let private copyDomTree g info immediateDominator =
  (g: IDiGraph<_, _>).Vertices
  |> Array.iter (fun v ->
    let n = info.Num[v]
    if not info.Reachable[n] then
      ()
    else
      let idom: IVertex<_> | null = immediateDominator v
      let d = if isNull idom then info.DummyNum else info.Num[idom]
      info.IDom[n] <- d
      info.Children[d].Add n |> ignore)
  updateDepth -1 info info.DummyNum

(* The pending vertices wait in a queue, for appending them onto a list copies
   the whole list on every step. *)
let private initReachable (g: IDiGraph<_, _>) info =
  let queue = Queue(g.Roots)
  while queue.Count > 0 do
    let v = queue.Dequeue()
    if info.Reachable[info.Num[v]] then
      ()
    else
      info.Reachable[info.Num[v]] <- true
      for w in g.GetSuccs v do
        if info.Reachable[info.Num[w]] then () else queue.Enqueue w

let private copyDominance g dom dfp staticAlgo isForward =
  let info = initDomInfo g dfp staticAlgo
  initReachable g info
  let immediateDominator =
    if isForward then (dom: IDominance<_>).ImmediateDominator
    else dom.ImmediatePostDominator
  copyDomTree g info immediateDominator
  info

let private updateDomInfo g info edge = insert g info edge

let private createForwardDominance g info dfp =
  let g: IDiGraph<_, _> = g
  let dfp: IDominanceFrontierProvider<_, _> = dfp
  let dt = lazy DominatorTree(g.Vertices, idom info)
  let mutable dfProvider = null
  { new IForwardDominance<'V> with
      member _.Dominators v =
        GraphUtils.checkVertexInGraph g v
        doms info v
      member _.ImmediateDominator v =
        GraphUtils.checkVertexInGraph g v
        idom info v
      member _.DominatorTree = dt.Value
      member this.DominanceFrontier v =
        GraphUtils.checkVertexInGraph g v
        if isNull dfProvider then
          dfProvider <- dfp.CreateIDominanceFrontier(g, this)
        else
          ()
        dfProvider.DominanceFrontier v }

let private computeDominance g dfp staticAlgo =
  let fwInfo = computeDomInfo g dfp staticAlgo
  let bwG = lazy (GraphUtils.findExits g |> g.Reverse)
  let bwInfo = lazy (computeDomInfo bwG.Value dfp staticAlgo)
  let fw = createForwardDominance g fwInfo dfp
  let bw = lazy (createForwardDominance bwG.Value bwInfo.Value dfp)
  combineDominance fw bw, fwInfo, bwInfo

/// <summary>
/// Creates an IDominance instance that computes dominance information using
/// Georgiadis et al.'s dynamic algorithm, inserting the edges of the graph one
/// at a time. That is how the algorithm builds a dominator tree able to absorb
/// further insertions, but the incremental use it exists for is not exposed
/// yet, so the other modules in this namespace compute a dominance of a graph
/// that never changes faster than this one does.
/// </summary>
/// <param name="g">The graph to compute the dominance of.</param>
/// <param name="dfp">Provides the dominance frontier implementation, which is
/// created only when a frontier is first requested.</param>
/// <param name="staticAlgo">Selects the algorithm that computes the dominance
/// of a subgraph, which this algorithm needs whenever an inserted edge makes a
/// group of unreachable vertices reachable.</param>
[<CompiledName "Create">]
let create g dfp staticAlgo =
  let dom, _, _ = computeDominance g dfp staticAlgo
  dom

/// Computes the dominance of the given graph, and also returns the dominator
/// tree state for both directions, so that updateInfo and createFromInfo can
/// keep a dominance up to date without recomputing it.
let internal createWithInfo g dfp staticAlgo =
  let dom, fw, bw = computeDominance g dfp staticAlgo
  dom, fw, bw

/// Computes the dominance of the given graph from the dominator tree state
/// that computeInfoFromDom or updateInfo produced, skipping the initial
/// analysis.
let internal createFromInfo g fwInfo (bwInfo: Lazy<DBSDomInfo<_, _>>) dfp =
  let bwG = lazy (GraphUtils.findExits g |> g.Reverse)
  let fw = createForwardDominance g fwInfo dfp
  let bw = lazy (createForwardDominance bwG.Value bwInfo.Value dfp)
  combineDominance fw bw

/// Builds this module's dominator tree state from an already computed
/// dominance, which lets a dominance from any other algorithm serve as the
/// starting point of the incremental updates. Pass false for fw to build the
/// state of the reversed (i.e., post-dominance) direction.
let internal computeInfoFromDom g dom dfp staticAlgo fw =
  copyDominance g dom dfp staticAlgo fw

/// Updates the dominator tree state in place for the given edge that has been
/// added to the graph, and returns it.
let internal updateInfo g info (edge: Edge<_, _>) =
  updateDomInfo g info edge
  info
