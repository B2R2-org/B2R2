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
    /// Vertex ID of reachable vertices.
    Reachable: HashSet<VertexID>
    /// Vertex ID -> Vertex ID of an immediate dominator.
    IDom: Dictionary<VertexID, VertexID>
    /// Vertex ID -> Vertex ID Set of children in the dominator tree.
    Children: Dictionary<VertexID, HashSet<VertexID>>
    /// Vertex ID -> Depth of the vertex in the dominance tree.
    Depth: Dictionary<VertexID, int> }

let private addVertex (g: IMutableDiGraph<_, _>) (v: IVertex<_>) =
  g.AddVertex(v.VData, v.ID) |> ignore

let private addEdge (g: IMutableDiGraph<_, _>) (edge: Edge<_, _>) =
  let srcID = edge.First.ID
  let dstID = edge.Second.ID
  if g.HasVertexByID srcID then () else addVertex g edge.First
  if g.HasVertexByID dstID then () else addVertex g edge.Second
  g.AddEdge(g.FindVertexByID srcID, g.FindVertexByID dstID, edge.Label)

let private initDynamicDomInfo g dfp algo =
  let roots = (g: IDiGraph<_, _>).Roots
  let rootIDs = roots |> Array.map (fun v -> v.ID)
  let children = Dictionary<VertexID, HashSet<VertexID>>()
  let depth = Dictionary<VertexID, int>()
  let iDom = Dictionary<VertexID, VertexID>()
  for v in rootIDs do
    children.[v] <- HashSet()
    depth.[v] <- 0
    iDom.[v] <- GraphUtils.DummyVertexID
  children.[GraphUtils.DummyVertexID] <- HashSet(rootIDs)
  depth.[GraphUtils.DummyVertexID] <- -1
  { StaticAlgo = algo
    DFP = dfp
    Reachable = HashSet rootIDs
    IDom = iDom
    Children = children
    Depth = depth }

let private initDomInfo g dfp algo =
  let roots = (g: IDiGraph<_, _>).Roots
  let rootIDs = roots |> Array.map (fun v -> v.ID)
  let children = Dictionary<VertexID, HashSet<VertexID>>()
  let depth = Dictionary<VertexID, int>()
  let iDom = Dictionary<VertexID, VertexID>()
  for v in rootIDs do
    children.[v] <- HashSet()
    depth.[v] <- 0
    iDom.[v] <- GraphUtils.DummyVertexID
  children.[GraphUtils.DummyVertexID] <- HashSet rootIDs
  depth.[GraphUtils.DummyVertexID] <- -1
  { StaticAlgo = algo
    DFP = dfp
    Reachable = HashSet()
    IDom = iDom
    Children = children
    Depth = depth }

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
  | vID :: stack ->
    let affected, trigs = state
    (visited: HashSet<VertexID>).Add vID |> ignore
    let v = (g: IDiGraph<_, _>).FindVertexByID vID
    let newAffected, newTrigs, newStack =
      g.GetSuccs v
      |> Array.fold (fun (affected, trigs, stack) w ->
        let wID = w.ID
        if visited.Contains wID then
          affected, trigs, stack
        else
          visited.Add wID |> ignore
          if info.Depth[wID] > info.Depth[trig] then
            affected, trigs, wID :: stack
          else if info.Depth[nca] + 1 < info.Depth[wID] then
            wID :: affected, wID :: trigs, stack
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
  match info.IDom.TryGetValue v with
  | false, _ -> ()
  | true, oldIDom -> info.Children[oldIDom].Remove v |> ignore
  match info.Children.TryGetValue v with
  | false, _ -> info.Children.Add(v, HashSet()) |> ignore
  | true, _ -> ()
  info.IDom[v] <- newIDom
  let depth = info.Depth[newIDom] + 1
  updateDepth depth info v

/// Update dominator tree when an edge from src to dst is added where
/// src and dst are both reachable from roots.
let private updateDomTree g info srcID dstID =
  let nca = getNCA info srcID dstID
  if nca = info.IDom[dstID] || nca = dstID then
    ()
  else
    let affected = computeAffected g info nca dstID
    affected
    |> Array.iter (updateIDom nca info)

(* Walks the vertices the given edges lead to, copying the ones unreachable
   from the roots into the subgraph, and answers the edges that leave it for
   the reachable part. The pending edges wait in a queue, for appending them
   onto a list copies the whole list on every step. *)
let private constructSubGraphAux g info visited h (queue: Queue<Edge<_, _>>) =
  let mutable bEdges = []
  while queue.Count > 0 do
    let edge = queue.Dequeue()
    let w = edge.Second
    if (visited: HashSet<VertexID>).Contains w.ID then
      addEdge h edge
    elif info.Reachable.Contains w.ID then
      bEdges <- edge :: bEdges
    else
      visited.Add w.ID |> ignore
      addVertex h w
      addEdge h edge
      for e in (g: IDiGraph<_, _>).GetSuccEdges w do queue.Enqueue e
  bEdges |> Array.ofList

/// Construct the subgraph with root dst whose vertices are unreachable from
/// main graph.
let private constructSubGraph (g: IDiGraph<_, _>) info dst =
  let h = MutablePersistentDiGraph(PersistentDiGraph<'V, 'E>())
  let ih = h :> IMutableDiGraph<_, _>
  addVertex ih dst
  ih.SetRoots [| ih.FindVertexByID dst.ID |]
  let visited = HashSet()
  visited.Add dst.ID |> ignore
  let queue = Queue(g.GetSuccEdges dst)
  let bEdges = constructSubGraphAux g info visited ih queue
  h.Snapshot, bEdges

let private computeStaticDom info g =
  StaticDominance.create g info.DFP info.StaticAlgo

(* The pending pairs wait in a queue, for appending them onto a list copies
   the whole list on every step. *)
let private mergeDomTree info src dst (subDom: IForwardDominance<_>) =
  let subDomTree = subDom.DominatorTree
  let queue = Queue<struct (IVertex<_> * IVertex<_>)>()
  queue.Enqueue(struct (src, dst))
  while queue.Count > 0 do
    let struct (parent, current) = queue.Dequeue()
    updateIDom (parent: IVertex<_>).ID info (current: IVertex<_>).ID
    for child in subDomTree.GetChildren current do
      queue.Enqueue(struct (current, child))

/// insert an edge into the graph and update the dominator tree
let private insert (g: IDiGraph<_, _>) info (edge: Edge<_, _>) =
  let src = edge.First
  let dst = edge.Second
  match info.Reachable.Contains src.ID, info.Reachable.Contains dst.ID with
  | false, _ ->
    ()
  | true, true ->
    updateDomTree g info src.ID dst.ID
  | true, false ->
    match g.GetSuccs dst with
    | [||] ->
      info.Reachable.Add dst.ID |> ignore
      updateIDom src.ID info dst.ID
    | _ ->
      let subG, bEdges = constructSubGraph g info dst
      let subDom = computeStaticDom info subG
      mergeDomTree info src (subG.FindVertexByID dst.ID) subDom
      bEdges
      |> Array.iter (fun edge ->
        let dst' = edge.Second
        updateDomTree g info src.ID dst'.ID)
      subG.Vertices
      |> Array.iter (fun v ->
        info.Reachable.Add v.ID |> ignore)

let private computeDomDyn (g: IDiGraph<_, _>) info =
  g.Edges
  |> Array.iter (insert g info)

let private idom (g: IDiGraph<_, _>) info (v: IVertex<'V>) =
  if info.IDom.ContainsKey v.ID then
    let idomID = info.IDom[v.ID]
    if idomID = GraphUtils.DummyVertexID then null
    else g.FindVertexByID idomID: IVertex<'V> | null
  else
    null

let rec private domsAux acc info vid =
  match info.IDom.TryGetValue vid with
  | false, _ ->
    acc
  | true, idomID ->
    if idomID = GraphUtils.DummyVertexID then acc
    else domsAux (idomID :: acc) info idomID

let private doms (g: IDiGraph<_, _>) info (v: IVertex<'V>) =
  domsAux [ v.ID ] info v.ID
  |> List.toArray
  |> Array.map g.FindVertexByID

let private computeDomInfo g dfp staticAlgo =
  let info = initDynamicDomInfo g dfp staticAlgo
  computeDomDyn g info
  info

let private copyDomTree g info immediateDominator =
  (g: IDiGraph<_, _>).Vertices
  |> Array.iter (fun v ->
    if info.Reachable.Contains v.ID |> not then
      ()
    else
      if info.Children.ContainsKey v.ID then ()
      else info.Children.Add(v.ID, HashSet()) |> ignore
      let idom: IVertex<_> | null = immediateDominator v
      let idomID = if isNull idom then GraphUtils.DummyVertexID else idom.ID
      info.IDom[v.ID] <- idomID
      match info.Children.ContainsKey idomID with
      | false -> info.Children.Add(idomID, HashSet [ v.ID ]) |> ignore
      | true -> info.Children.[idomID].Add v.ID |> ignore)
  updateDepth -1 info GraphUtils.DummyVertexID

(* The pending vertices wait in a queue, for appending them onto a list copies
   the whole list on every step. *)
let private initReachable (g: IDiGraph<_, _>) info =
  let queue = Queue(g.Roots)
  while queue.Count > 0 do
    let v = queue.Dequeue()
    if info.Reachable.Contains v.ID then
      ()
    else
      info.Reachable.Add v.ID |> ignore
      for w in g.GetSuccs v do
        if info.Reachable.Contains w.ID then () else queue.Enqueue w

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
  let dt = lazy DominatorTree(g.Vertices, idom g info)
  let mutable dfProvider = null
  { new IForwardDominance<'V> with
      member _.Dominators v =
        GraphUtils.checkVertexInGraph g v
        doms g info v
      member _.ImmediateDominator v =
        GraphUtils.checkVertexInGraph g v
        idom g info v
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
