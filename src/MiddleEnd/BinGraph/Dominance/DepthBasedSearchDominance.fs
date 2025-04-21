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

/// Georgiadis et al.'s algorithm for dynamic dominance computation. An
/// Experimental Study of Dynamic Dominators, ESA 2012.
module B2R2.MiddleEnd.BinGraph.Dominance.DepthBasedSearchDominance

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

/// Static dominator algorithm used for sub dominator tree construction.
type StaticAlgo =
  /// Iterative dominator algorithm.
  | Iterative
  /// Simple Lengauer-Tarjan algorithm.
  | SLT
  /// Lengauer-Tarjan algorithm with tree balancing.
  | LT
  /// Semi-NCA algorithm.
  | SemiNCA
  /// Cooper's algorithm.
  | Cooper

type private GraphInfo<'V, 'E when 'V: equality and 'E: equality> = {
  /// Dummy root ID
  DummyRootID: VertexID
  /// Static dominance algorithm.
  StaticAlgo: StaticAlgo
  /// Dominance frontier provider.
  DFP: IDominanceFrontierProvider<'V, 'E>
  /// Graph
  Graph: IDiGraph<'V, 'E>
  /// Vertex ID of reachable vertices.
  Reachable: HashSet<VertexID>
  /// Vertex ID -> Vertex ID of an immediate dominator.
  IDom: Dictionary<VertexID, VertexID>
  /// Vertex ID -> Vertex ID Set of children in the dominator tree.
  Children: Dictionary<VertexID, HashSet<VertexID>>
  /// Vertex ID -> Depth of the vertex in the dominance tree.
  Depth: Dictionary<VertexID, int>
}

let private addVertex (g: IDiGraph<_, _>) (v: IVertex<_>) =
  let _, g = g.AddVertex (v.VData, v.ID)
  g

let private addEdge (g: IDiGraph<_, _>) (edge: Edge<_, _>) =
  let src = edge.First
  let dst = edge.Second
  let g = if g.HasVertex src.ID then g
          else addVertex g src
  let g = if g.HasVertex dst.ID then g
          else addVertex g dst
  g.AddEdge (src, dst, edge.Label)

let private initDynamicGraphInfo g dfp algo =
  let dummyRoot = GraphUtils.makeDummyVertex ()
  let h = PersistentDiGraph<'V, 'E> () :> IDiGraph<_, _>
  let roots = (g: IDiGraphAccessible<_, _>).GetRoots ()
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
    Graph =
      g.Vertices
      |> Array.fold addVertex h
      |> fun h' -> h'.SetRoots roots
    Reachable = HashSet rootIDs
    IDom = iDom
    Children = children
    Depth = depth }

let private initStaticGraphInfo g dfp algo =
  let dummyRoot = GraphUtils.makeDummyVertex ()
  let roots = (g: IDiGraph<_, _>).GetRoots ()
  let rootIDs = roots |> Array.map (fun v -> v.ID)
  let children = Dictionary<VertexID, HashSet<VertexID>> ()
  let depth = Dictionary<VertexID, int> ()
  let iDom = Dictionary<VertexID, VertexID> ()
  for v in rootIDs do
    children.[v] <- HashSet ()
    depth.[v] <- 0
    iDom.[v] <- dummyRoot.ID
  children.[dummyRoot.ID] <- HashSet rootIDs
  depth.[dummyRoot.ID] <- -1
  { DummyRootID = dummyRoot.ID
    StaticAlgo = algo
    DFP = dfp
    Graph = g
    Reachable = HashSet rootIDs
    IDom = iDom
    Children = children
    Depth = depth }

let private getNCA info v w =
  let rec bothUp v w =
    if v = w then v
    else
      bothUp info.IDom[v] info.IDom[w]
  let rec singleUp v w =
    if info.Depth[v] = info.Depth[w] then bothUp v w
    else
      singleUp v info.IDom[w]
  if info.Depth[v] < info.Depth[w] then
    singleUp v w
  else if info.Depth[v] > info.Depth[w] then
    singleUp w v
  else bothUp v w

let rec private computeTriggers info nca trigger vID state =
  let visited, affected, triggers = state
  let visited = (visited: Set<VertexID>).Add vID
  let v = info.Graph.FindVertexByID vID
  info.Graph.GetSuccs v
  |> Array.fold (fun (visited, affected, triggers) w ->
    let wID = w.ID
    if (visited: Set<VertexID>).Contains wID then
      visited, affected, triggers
    else
      let visited = visited.Add wID
      if info.Depth[wID] > info.Depth[trigger] then
        computeTriggers info nca trigger wID (visited, affected, triggers)
      else
        if info.Depth[nca] + 1 < info.Depth[wID] then
          visited, wID :: affected, wID :: triggers
        else visited, affected, triggers) (visited, affected, triggers)

let rec private computeAffectedAux info nca = function
  | _, affected, [] -> affected |> Array.ofList
  | visited, affected, trigger :: triggers ->
    let state =
      computeTriggers info nca trigger trigger (visited, affected, triggers)
    computeAffectedAux info nca state

let private computeAffected info nca trigger =
  computeAffectedAux info nca (Set.empty, [ trigger ], [ trigger ])

let rec private updateDepth depth info v  =
  info.Depth[v] <- depth
  info.Children[v]
  |> Seq.iter (updateDepth (depth + 1) info)

let private updateIDom newIDom info v =
  info.Children[newIDom].Add v |> ignore
  match info.IDom.TryGetValue v with
  | false, _ -> ()
  | true, oldIDom ->
    info.Children[oldIDom].Remove v |> ignore
  match info.Children.TryGetValue v with
  | false, _ -> info.Children.Add (v, HashSet ()) |> ignore
  | true, _ -> ()
  info.IDom[v] <- newIDom
  let depth = info.Depth[newIDom] + 1
  updateDepth depth info v

/// Update dominator tree when an edge from src to dst is added where
/// src and dst are both reachable from roots.
let private updateDomTree info srcID dstID =
  let nca = getNCA info srcID dstID
  if nca = info.IDom[dstID] || nca = dstID then ()
  else
    let affected = computeAffected info nca dstID
    affected
    |> Array.iter (updateIDom nca info)

let rec private constructSubGraphAux info visited (g, bEdges) = function
  | [] -> g, bEdges |> Array.ofList
  | edge: Edge<_, _> :: stack ->
    let v, w = edge.First, edge.Second
    if (visited: Set<VertexID>).Contains w.ID then
      let g = addEdge g edge
      constructSubGraphAux info visited (g, bEdges) stack
    else
      if info.Reachable.Contains w.ID then
        constructSubGraphAux info visited (g, edge :: bEdges) stack
      else
        let visited = visited.Add w.ID
        let g = addVertex g w
        let g = addEdge g edge
        let stack =
          info.Graph.GetSuccEdges w
          |> Array.toList
          |> List.append stack
        constructSubGraphAux info visited (g, bEdges) stack

/// Construct the subgraph with root dst whose vertices are unreachable from
/// main graph.
let private constructSubGraph info dst =
  let h = PersistentDiGraph<'V, 'E> () :> IDiGraph<_, _>
  let h = addVertex h dst
  let h = h.SetRoots [| dst |]
  let visited = Set.empty.Add dst.ID
  let stack = info.Graph.GetSuccEdges dst |> Array.toList
  constructSubGraphAux info visited (h, []) stack

let private computeStaticDom info g =
  let dfp = info.DFP
  match info.StaticAlgo with
  | Iterative -> IterativeDominance.create g dfp
  | SLT -> SimpleLengauerTarjanDominance.create g dfp
  | LT -> LengauerTarjanDominance.create g dfp
  | SemiNCA -> SemiNCADominance.create g dfp
  | Cooper -> CooperDominance.create g dfp

let rec private mergeDomTreeAux info subDomTree = function
  | [] -> ()
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
let private insert info edge =
  let info = { info with Graph = addEdge info.Graph edge }
  let src = edge.First
  let dst = edge.Second
  match info.Reachable.Contains src.ID, info.Reachable.Contains dst.ID with
  | false, _ -> ()
  | true, true -> updateDomTree info src.ID dst.ID
  | true, false ->
    match info.Graph.GetSuccs dst with
    | [||] ->
      info.Reachable.Add dst.ID |> ignore
      updateIDom src.ID info dst.ID
    | _ ->
      let subG, bEdges = constructSubGraph info dst
      let subDom = computeStaticDom info subG
      mergeDomTree info src dst subDom
      bEdges
      |> Array.iter (fun edge ->
        let dst' = edge.Second
        updateDomTree info src.ID dst'.ID)
      subG.Vertices
      |> Array.iter (fun v ->
        info.Reachable.Add v.ID |> ignore)
  info

let private computeDomDyn (g: IDiGraphAccessible<_, _>) info =
  g.Edges
  |> Array.fold insert info

let private idom info (v: IVertex<'V>) =
  if info.IDom.ContainsKey v.ID then
    let idomID = info.IDom[v.ID]
    if idomID = info.DummyRootID then null
    else info.Graph.FindVertexByID idomID
  else
    null

let rec private domsAux acc info vid =
  match info.IDom.TryGetValue vid with
  | false, _ -> acc
  | true, idomID ->
    if idomID = info.DummyRootID then acc
    else
      domsAux (idomID :: acc) info idomID

let private doms info (v: IVertex<'V>) =
  domsAux [ v.ID ] info v.ID
  |> List.toArray
  |> Array.map info.Graph.FindVertexByID

let private computeGraphInfo g dfp staticAlgo =
  let info = initDynamicGraphInfo g dfp staticAlgo
  computeDomDyn g info

let private copyDomTree info immediateDominator =
  info.Graph.Vertices
  |> Array.iter (fun v ->
    if info.Reachable.Contains v.ID |> not then ()
    else
      if info.Children.ContainsKey v.ID then ()
      else info.Children.Add (v.ID, HashSet ()) |> ignore
      let idom: IVertex<_> = immediateDominator v
      let idomID =
        if isNull idom then info.DummyRootID
        else idom.ID
      info.IDom[v.ID] <- idomID
      match info.Children.ContainsKey idomID with
      | false ->
        info.Children.Add (idomID, HashSet [ v.ID ]) |> ignore
      | true ->
        info.Children.[idomID].Add v.ID |> ignore)
  updateDepth -1 info info.DummyRootID

let rec private initReachableAux info = function
  | [] -> ()
  | v: IVertex<_> :: stack ->
    if info.Reachable.Contains v.ID then
      initReachableAux info stack
    else
      info.Reachable.Add v.ID |> ignore
      let stack =
        info.Graph.GetSuccs v
        |> Array.filter (fun w -> info.Reachable.Contains w.ID |> not)
        |> Array.toList
        |> List.append stack
      initReachableAux info stack

let private initReachable info =
  let g = info.Graph
  let stack =
    info.Graph.GetRoots ()
    |> Seq.toList
  initReachableAux info stack

let private copyDominance g dom dfp staticAlgo isForward =
  let info = initStaticGraphInfo g dfp staticAlgo
  initReachable info
  let immediateDominator =
    if isForward then (dom: IDominance<_, _>).ImmediateDominator
    else dom.ImmediatePostDominator
  copyDomTree info immediateDominator
  info

let private updateGraphInfo g dom dfp staticAlgo isForward edge =
  let info = copyDominance g dom dfp staticAlgo isForward
  insert info edge

type private DBSDominance<'V, 'E when 'V: equality and 'E: equality>
  (g, dfp: IDominanceFrontierProvider<_, _>, staticAlgo) =
  let fwInfo = computeGraphInfo g dfp staticAlgo
  let fwDomTree = lazy DominatorTree (g, idom fwInfo)
  let bwG = lazy (GraphUtils.findExits g |> g.Reverse)
  let bwInfo = lazy (computeGraphInfo bwG.Value dfp staticAlgo)
  let bwDomTree = lazy DominatorTree (bwG.Value, idom bwInfo.Value)
  let mutable dfProvider = null
  let mutable pdfProvider = null
  interface IDominance<'V, 'E> with
    member __.Dominators v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      doms fwInfo v

    member __.ImmediateDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      idom fwInfo v

    member __.DominatorTree =
      fwDomTree.Value

    member __.DominanceFrontier v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      if isNull dfProvider then
        dfProvider <- dfp.CreateIDominanceFrontier (g, __, false)
      dfProvider.DominanceFrontier v

    member __.PostDominators v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      doms bwInfo.Value v

    member __.ImmediatePostDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      idom bwInfo.Value v

    member __.PostDominatorTree =
      bwDomTree.Value

    member __.PostDominanceFrontier v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      if isNull pdfProvider then
        pdfProvider <- dfp.CreateIDominanceFrontier (bwG.Value, __, true)
      pdfProvider.DominanceFrontier v

type private DynamicDBSDominance<'V, 'E when 'V: equality and 'E: equality>
  (g, dom: IDominance<'V, 'E>, dfp, staticAlgo, edge) =
  let fwInfo = updateGraphInfo g dom dfp staticAlgo true edge
  let fwDomTree = lazy DominatorTree (g, idom fwInfo)
  let bwG = lazy (GraphUtils.findExits g |> g.Reverse)
  let bwInfo = lazy (updateGraphInfo bwG.Value dom dfp staticAlgo false edge)
  let bwDomTree = lazy DominatorTree (bwG.Value, idom bwInfo.Value)
  let mutable dfProvider = null
  let mutable pdfProvider = null
  interface IDominance<'V, 'E> with
    member __.Dominators v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      doms fwInfo v

    member __.ImmediateDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      idom fwInfo v

    member __.DominatorTree =
      fwDomTree.Value

    member __.DominanceFrontier v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      if isNull dfProvider then
        dfProvider <- dfp.CreateIDominanceFrontier (g, __, false)
      dfProvider.DominanceFrontier v

    member __.PostDominators v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      doms bwInfo.Value v

    member __.ImmediatePostDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      idom bwInfo.Value v

    member __.PostDominatorTree =
      bwDomTree.Value

    member __.PostDominanceFrontier v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      if isNull pdfProvider then
        pdfProvider <- dfp.CreateIDominanceFrontier (bwG.Value, __, true)
      pdfProvider.DominanceFrontier v

[<CompiledName "Create">]
let create g (dfp: IDominanceFrontierProvider<_, _>) staticAlgo =
  DBSDominance (g, dfp, staticAlgo) :> IDominance<_, _>

let insertEdge g dom dfp staticAlgo edge  =
  DynamicDBSDominance (g, dom, dfp, staticAlgo, edge) :> IDominance<_, _>