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
module B2R2.MiddleEnd.BinGraph.Dominance.DepthBasedSearchDominance

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

/// Represents the dominator tree that this module maintains incrementally.
/// Mutating it silently invalidates the dominance computed from it, so it stays
/// internal, visible only to the dynamic-dominance benchmark, which updates a
/// dominance edge by edge.
type internal DBSDomInfo<'V, 'E when 'V: equality and 'E: equality> =
  { /// Dummy root ID
    DummyRootID: VertexID
    /// Static dominance algorithm.
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
  let dummyRoot = GraphUtils.makeDummyVertex ()
  let roots = (g: IDiGraphAccessible<_, _>).GetRoots()
  let rootIDs = roots |> Array.map (fun v -> v.ID)
  let children = Dictionary<VertexID, HashSet<VertexID>>()
  let depth = Dictionary<VertexID, int>()
  let iDom = Dictionary<VertexID, VertexID>()
  for v in rootIDs do
    children.[v] <- HashSet()
    depth.[v] <- 0
    iDom.[v] <- dummyRoot.ID
  children.[dummyRoot.ID] <- HashSet(rootIDs)
  depth.[dummyRoot.ID] <- -1
  { DummyRootID = dummyRoot.ID
    StaticAlgo = algo
    DFP = dfp
    Reachable = HashSet rootIDs
    IDom = iDom
    Children = children
    Depth = depth }

let private initDomInfo g dfp algo =
  let dummyRoot = GraphUtils.makeDummyVertex ()
  let roots = (g: IDiGraphAccessible<_, _>).GetRoots()
  let rootIDs = roots |> Array.map (fun v -> v.ID)
  let children = Dictionary<VertexID, HashSet<VertexID>>()
  let depth = Dictionary<VertexID, int>()
  let iDom = Dictionary<VertexID, VertexID>()
  for v in rootIDs do
    children.[v] <- HashSet()
    depth.[v] <- 0
    iDom.[v] <- dummyRoot.ID
  children.[dummyRoot.ID] <- HashSet rootIDs
  depth.[dummyRoot.ID] <- -1
  { DummyRootID = dummyRoot.ID
    StaticAlgo = algo
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
    let v = (g: IDiGraphAccessible<_, _>).FindVertexByID vID
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

let rec private constructSubGraphAux g info visited h bEdges = function
  | [] ->
    bEdges |> Array.ofList
  | edge: Edge<_, _> :: stack ->
    let w = edge.Second
    if (visited: HashSet<VertexID>).Contains w.ID then
      addEdge h edge
      constructSubGraphAux g info visited h bEdges stack
    else
      if info.Reachable.Contains w.ID then
        constructSubGraphAux g info visited h (edge :: bEdges) stack
      else
        visited.Add w.ID |> ignore
        addVertex h w
        addEdge h edge
        let stack =
          (g: IDiGraphAccessible<_, _>).GetSuccEdges w
          |> Array.toList
          |> List.append stack
        constructSubGraphAux g info visited h bEdges stack

/// Construct the subgraph with root dst whose vertices are unreachable from
/// main graph.
let private constructSubGraph (g: IDiGraphAccessible<_, _>) info dst =
  let h = MutablePersistentDiGraph(PersistentDiGraph<'V, 'E>())
  let ih = h :> IMutableDiGraph<_, _>
  addVertex ih dst
  ih.SetRoots [| ih.FindVertexByID dst.ID |]
  let visited = HashSet()
  visited.Add dst.ID |> ignore
  let stack = g.GetSuccEdges dst |> Array.toList
  let bEdges = constructSubGraphAux g info visited ih [] stack
  h.Snapshot, bEdges

let private computeStaticDom info g =
  StaticDominance.create g info.DFP info.StaticAlgo

let rec private mergeDomTreeAux info subDomTree = function
  | [] ->
    ()
  | (parent: IVertex<_>, current: IVertex<_>) :: stack ->
    updateIDom parent.ID info current.ID
    let stack =
      (subDomTree: DominatorTree<_, _>).GetChildren current
      |> Seq.map (fun child -> current, child)
      |> Seq.toList
      |> List.append stack
    mergeDomTreeAux info subDomTree stack

let private mergeDomTree info src dst (subDom: IDominance<_, _>) =
  let subDomTree = subDom.DominatorTree
  mergeDomTreeAux info subDomTree [ (src, dst) ]

/// insert an edge into the graph and update the dominator tree
let private insert (g: IDiGraphAccessible<_, _>) info (edge: Edge<_, _>) =
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

let private computeDomDyn (g: IDiGraphAccessible<_, _>) info =
  g.Edges
  |> Array.iter (insert g info)

let private idom (g: IDiGraphAccessible<_, _>) info (v: IVertex<'V>) =
  if info.IDom.ContainsKey v.ID then
    let idomID = info.IDom[v.ID]
    if idomID = info.DummyRootID then null
    else g.FindVertexByID idomID: IVertex<'V> | null
  else
    null

let rec private domsAux acc info vid =
  match info.IDom.TryGetValue vid with
  | false, _ ->
    acc
  | true, idomID ->
    if idomID = info.DummyRootID then acc
    else domsAux (idomID :: acc) info idomID

let private doms (g: IDiGraphAccessible<_, _>) info (v: IVertex<'V>) =
  domsAux [ v.ID ] info v.ID
  |> List.toArray
  |> Array.map g.FindVertexByID

let private computeDomInfo g dfp staticAlgo =
  let info = initDynamicDomInfo g dfp staticAlgo
  computeDomDyn g info
  info

let private copyDomTree g info immediateDominator =
  (g: IDiGraphAccessible<_, _>).Vertices
  |> Array.iter (fun v ->
    if info.Reachable.Contains v.ID |> not then
      ()
    else
      if info.Children.ContainsKey v.ID then ()
      else info.Children.Add(v.ID, HashSet()) |> ignore
      let idom: IVertex<_> | null = immediateDominator v
      let idomID = if isNull idom then info.DummyRootID else idom.ID
      info.IDom[v.ID] <- idomID
      match info.Children.ContainsKey idomID with
      | false -> info.Children.Add(idomID, HashSet [ v.ID ]) |> ignore
      | true -> info.Children.[idomID].Add v.ID |> ignore)
  updateDepth -1 info info.DummyRootID

let rec private initReachableAux (g: IDiGraphAccessible<_, _>) info = function
  | [] ->
    ()
  | v: IVertex<_> :: stack ->
    if info.Reachable.Contains v.ID then
      initReachableAux g info stack
    else
      info.Reachable.Add v.ID |> ignore
      let stack =
        g.GetSuccs v
        |> Array.filter (fun w -> info.Reachable.Contains w.ID |> not)
        |> Array.toList
        |> List.append stack
      initReachableAux g info stack

let private initReachable (g: IDiGraphAccessible<_, _>) info =
  let stack =
    g.GetRoots()
    |> Seq.toList
  initReachableAux g info stack

let private copyDominance g dom dfp staticAlgo isForward =
  let info = initDomInfo g dfp staticAlgo
  initReachable g info
  let immediateDominator =
    if isForward then (dom: IDominance<_, _>).ImmediateDominator
    else dom.ImmediatePostDominator
  copyDomTree g info immediateDominator
  info

let private updateDomInfo g info edge = insert g info edge

let private createDominance fwG
                            (bwG: Lazy<IDiGraphAccessible<_, _>>)
                            fwInfo
                            (fwDT: Lazy<DominatorTree<_, _>>)
                            (bwInfo: Lazy<DBSDomInfo<_, _>>)
                            (bwDT: Lazy<DominatorTree<_, _>>)
                            (dfp: IDominanceFrontierProvider<_, _>) =
  let mutable dfProvider = null
  let mutable pdfProvider = null
  { new IDominance<'V, 'E> with
      member _.Dominators v =
        GraphUtils.checkVertexInGraph fwG v
        doms fwG fwInfo v
      member _.ImmediateDominator v =
        GraphUtils.checkVertexInGraph fwG v
        idom fwG fwInfo v
      member _.DominatorTree = fwDT.Value
      member this.DominanceFrontier v =
        GraphUtils.checkVertexInGraph fwG v
        if isNull dfProvider then
          dfProvider <- dfp.CreateIDominanceFrontier(fwG, this, false)
        else
          ()
        dfProvider.DominanceFrontier v
      member _.PostDominators v =
        GraphUtils.checkVertexInGraph bwG.Value v
        doms bwG.Value bwInfo.Value v
        |> Seq.map (findOriginalVertex fwG)
      member _.ImmediatePostDominator v =
        GraphUtils.checkVertexInGraph bwG.Value v
        idom bwG.Value bwInfo.Value v
        |> findOriginalVertex fwG
      member _.PostDominatorTree = bwDT.Value
      member this.PostDominanceFrontier v =
        GraphUtils.checkVertexInGraph bwG.Value v
        if isNull pdfProvider then
          pdfProvider <- dfp.CreateIDominanceFrontier(bwG.Value, this, true)
        else
          ()
        pdfProvider.DominanceFrontier v
        |> Seq.map (findOriginalVertex fwG) }

let private computeDominance g dfp staticAlgo =
  let fwInfo = computeDomInfo g dfp staticAlgo
  let fwDT = lazy DominatorTree(g, idom g fwInfo)
  let bwG = lazy (GraphUtils.findExits g |> g.Reverse)
  let bwInfo = lazy (computeDomInfo bwG.Value dfp staticAlgo)
  let bwDT = lazy DominatorTree(bwG.Value, idom bwG.Value bwInfo.Value)
  createDominance g bwG fwInfo fwDT bwInfo bwDT dfp, fwInfo, bwInfo

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
  let fwDT = lazy DominatorTree(g, idom g fwInfo)
  let bwG = lazy (GraphUtils.findExits g |> g.Reverse)
  let bwDT = lazy DominatorTree(bwG.Value, idom bwG.Value bwInfo.Value)
  createDominance g bwG fwInfo fwDT bwInfo bwDT dfp

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
