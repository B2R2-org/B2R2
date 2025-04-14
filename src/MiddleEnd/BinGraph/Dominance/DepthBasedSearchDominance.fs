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

/// Static dominator algorithm used for initial dominator tree construction.
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

/// Initial domiantor tree construction strategy.
type InitStrategy =
  /// Use static dominator algorithm to construct the dominator tree.
  | StaticInit of StaticAlgo
  /// Use dynamic dominator algorithm to construct the dominator tree.
  | DynamicInit

type private GraphInfo = {
  /// Vertex ID -> Vertex Num
  VertexNum: Dictionary<VertexID, int>
  /// Vertex Num -> Vertex ID
  VertexID: VertexID[]
  /// Vertex Num -> Vertex Num of the first predecessor.
  First: int[]
  /// Vertex Num, Vertex Num -> Vertex Num of the next predecessor.
  Next: int[][]
  /// Vertex Num -> bool, reachability from roots
  Reachability: bool[]
  /// Vertex Num -> Vertex Num of an immediate dominator.
  IDom: int[]
  /// Vertex Num -> Vertex Num Set of children in the dominator tree.
  Children: Set<int>[]
  /// Vertex Num -> Depth of the vertex in the dominance tree.
  Depth: int[]
}

let private initGraphInfo (g: IDiGraphAccessible<_, _>) =
  (* To reserve a room for entry (dummy) node. *)
  let len = g.Size + 1
  { VertexNum = Dictionary<VertexID, int> ();
    VertexID = Array.zeroCreate len;
    First = Array.create len -1;
    Next = Array.init len (fun _ -> Array.create len -1);
    Reachability = Array.create len false;
    IDom = Array.create len -1;
    Children = Array.create len Set.empty;
    Depth = Array.create len -1 }

let private computeVertexMap (g: IDiGraphAccessible<_, _>) info =
  g.FoldVertex (fun acc v ->
    let vid = v.ID
    info.VertexNum.Add (vid, acc)
    info.VertexID[acc] <- vid
    acc + 1) 1

let private getNCA info vNum wNum =
  let rec bothUp vNum wNum =
    if vNum = wNum then vNum
    else
      bothUp info.IDom[vNum] info.IDom[wNum]
  let rec singleUp vNum wNum =
    if info.Depth[vNum] = info.Depth[wNum] then bothUp vNum wNum
    else
      singleUp vNum info.IDom[wNum]
  if info.Depth[vNum] < info.Depth[wNum] then
    singleUp vNum wNum
  else if info.Depth[vNum] > info.Depth[wNum] then
    singleUp wNum vNum
  else bothUp vNum wNum

let rec private getPredsAux info vNum curr acc =
  let next = info.Next[vNum][curr]
  if next = -1 then acc
  else
    getPredsAux info vNum next (next :: acc)

let private getPreds info vNum =
  let first = info.First[vNum]
  if first = -1 then []
  else getPredsAux info vNum first [first]

let rec private getAffectedAux info nca visited trigger vNum (affected, stack) =
  if (visited: bool array)[vNum] then
    affected, stack
  else
    visited[vNum] <- true
    let wNums = getPreds info vNum |> List.toArray
    wNums
    |> Array.fold (fun (affected, stack) wNum ->
      if info.Depth[wNum] > info.Depth[trigger] then
        getAffectedAux info nca visited trigger wNum (affected, stack)
      else
        if info.Depth[nca] + 1 < info.Depth[wNum] then
          wNum :: affected, wNum :: stack
        else affected, stack) (affected, stack)

let rec private getAffected info nca visited = function
  | affected, [] -> affected
  | affected, trigger :: stack ->
    let affected, stack =
      getAffectedAux info nca visited trigger trigger (affected, stack)
    getAffected info nca visited (affected, stack)

let rec private updateDepth info vNum depth =
  info.Depth[vNum] <- depth
  match info.Children[vNum].IsEmpty with
  | false ->
    info.Children[vNum]
    |> Seq.iter (fun child ->
      updateDepth info child (depth + 1))
  | true -> ()

let private insert info src dst =
  info.Next[src][dst] <- info.First[src]
  info.First[src] <- dst
  if info.Reachability[dst] then
    let newIDom = getNCA info src dst
    if newIDom = info.IDom[dst] || newIDom = dst then ()
    else
      let visited = Array.create (info.VertexNum.Count + 1) false
      let affected = getAffected info newIDom visited ([ dst ], [ dst ])
      affected
      |> List.iter (fun vNum ->
        let oldIDom = info.IDom[vNum]
        info.IDom[vNum] <- newIDom
        info.Children[oldIDom] <- info.Children[oldIDom] |> Set.remove vNum
        info.Children[newIDom] <- info.Children[newIDom] |> Set.add vNum
        updateDepth info vNum (info.Depth[newIDom] + 1))
  else
    info.IDom[dst] <- src
    info.Children[src] <- info.Children[src] |> Set.add dst
    info.Depth[dst] <- info.Depth[src] + 1

let rec private dfsInsert (g: IDiGraphAccessible<_, _>) info = function
  | (pNum, v: IVertex<_>) :: stack ->
    let vNum = info.VertexNum[v.ID]
    insert info pNum vNum
    let stack =
      if info.Reachability[vNum] then stack
      else
        info.Reachability[vNum] <- true
        g.GetSuccs v |> Array.fold (fun acc s -> (vNum, s) :: acc) stack
    dfsInsert g info stack
  | [] -> ()

/// Dynamically compute the dominator tree.
let private computeDomTreeDyn (g: IDiGraphAccessible<_,_>) info =
  let stack = g.GetRoots () |> Array.map (fun r -> 0, r) |> Array.toList
  info.Reachability[0] <- true
  dfsInsert g info stack

let rec private dfsCopy g info domTree = function
  | (depth, v: IVertex<_>) :: stack ->
    let vNum = info.VertexNum[v.ID]
    let children =
      (domTree: DominatorTree<_, _>).GetChildren v
      |> Seq.toArray
      |> Array.map (fun child ->
        let childNum = info.VertexNum[child.ID]
        info.IDom[childNum] <- vNum
        info.Children[vNum] <- info.Children[vNum] |> Set.add childNum
        child)
    let stack =
      if info.Depth[info.VertexNum[v.ID]] <> -1 then stack
      else
        children
        |> Array.fold (fun acc child -> (depth + 1, child) :: acc) stack
    info.Depth[vNum] <- depth
    dfsCopy g info domTree stack
  | [] -> ()

/// Copy the statically computed dominator tree.
let private copyDomTree g info (domTree: DominatorTree<_, _>) =
  let stack =
    domTree.GetRoot ()
    |> domTree.GetChildren
    |> Seq.map (fun r -> 1, r)
    |> Seq.toList
  dfsCopy g info domTree stack

let private computeDomTree g dfp info = function
  | DynamicInit ->
    computeDomTreeDyn g info
  | StaticInit algo ->
    let dominance =
      match algo with
      | Iterative ->
        IterativeDominance.create g dfp
      | LT ->
        LengauerTarjanDominance.create g dfp
      | SLT ->
        SimpleLengauerTarjanDominance.create g dfp
      | SemiNCA ->
        SemiNCADominance.create g dfp
      | Cooper ->
        CooperDominance.create g dfp
    let domTree = dominance.DominatorTree
    copyDomTree g info domTree

let rec private domsAux acc info vNum =
  if vNum = -1 || vNum = 0 then acc
  else
    let idomNum = info.IDom[vNum]
    domsAux (idomNum :: acc) info idomNum

let private doms (g: IDiGraphAccessible<_, _>) info (v: IVertex<'V>) =
  let vNum = info.VertexNum[v.ID]
  domsAux [ vNum ] info vNum
  |> List.toArray
  |> Array.filter (fun vNum -> vNum <> 0 && vNum <> -1)
  |> Array.map (fun vNum -> g.FindVertexByID info.VertexID[vNum])

let private idom (g: IDiGraphAccessible<_, _>) info (v: IVertex<'V>) =
  let vNum = info.VertexNum[v.ID]
  if vNum = 0 then null
  else
    let idomNum = info.IDom[vNum]
    if idomNum = -1 || idomNum = 0 then null
    else
      let idomID = info.VertexID[idomNum]
      g.FindVertexByID idomID

let private computeGraphInfo (g: IDiGraphAccessible<_, _>) dfp initStrategy =
  let info = initGraphInfo g
  computeVertexMap g info |> ignore
  computeDomTree g dfp info initStrategy
  let domTree = lazy DominatorTree (g, idom g info)
  info, domTree


type private DBSDominance<'V, 'E when 'V: equality and 'E: equality>
  (g, dfp: IDominanceFrontierProvider<_, _>, initStrategy) =
  let forward = computeGraphInfo g dfp initStrategy
  let backwardG = lazy (GraphUtils.findExits g |> g.Reverse)
  let backward = lazy (computeGraphInfo backwardG.Value dfp initStrategy)
  let mutable dfProvider = null
  let mutable pdfProvider = null
  interface IDominance<'V, 'E> with
    member __.Dominators v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      let info, _ = forward
      doms g info v

    member __.ImmediateDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      let info, _ = forward
      idom g info v

    member __.DominatorTree =
      let _, domTree = forward
      domTree.Value

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
      let info, _ = backward.Value
      doms backwardG.Value info v

    member __.ImmediatePostDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      let info, _ = backward.Value
      idom backwardG.Value info v

    member __.PostDominatorTree =
      let _, domTree = backward.Value
      domTree.Value

    member __.PostDominanceFrontier v =
#if DEBUG
      GraphUtils.checkVertexInGraph g v
#endif
      if isNull pdfProvider then
        pdfProvider <- dfp.CreateIDominanceFrontier (backwardG.Value, __, true)
      pdfProvider.DominanceFrontier v

[<CompiledName "Create">]
let create g (dfp: IDominanceFrontierProvider<_, _>) initStrategy =
  DBSDominance (g, dfp, initStrategy) :> IDominance<_, _>