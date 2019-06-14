(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Soomin Kim <soomink@kaist.ac.kr>

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

module B2R2.BinGraph.Dominator

open B2R2.Utils
open System.Collections.Generic

type DomInfo<'V when 'V :> VertexData> = {
  /// Vertex ID -> DFNum
  DFNumMap      : Dictionary<VertexID, int>
  /// DFNum -> Vertex
  Vertex        : Vertex<'V> []
  /// DFNum -> DFNum in the ancestor chain s.t. DFNum of its Semi is minimal.
  Label         : int []
  /// DFNum -> DFNum of the parent node (zero if not exists).
  Parent        : int []
  /// DFNum -> DFNum of the child node (zero if not exists).
  Child         : int []
  /// DFNum -> DFNum of an ancestor.
  Ancestor      : int []
  /// DFNum -> DFNum of a semidominator.
  Semi          : int []
  /// DFNum -> set of DFNums (vertices that share the same sdom).
  Bucket        : Set<int> []
  /// DFNum -> Size
  Size          : int []
  /// DFNum -> DFNum of an immediate dominator.
  IDom          : int []
  /// Length of the arrays.
  MaxLength     : int
}

/// Storing DomInfo of a graph. We use this to repeatedly compute doms/pdoms of
/// the same graph.
type DominatorContext<'V, 'E when 'V :> VertexData> = {
  ForwardGraph : DiGraph<'V, 'E>
  ForwardDomInfo : DomInfo<'V>
  BackwardGraph : DiGraph<'V, 'E>
  BackwardDomInfo : DomInfo<'V>
}

let initDomInfo (g: DiGraph<_, _>) =
  let len = g.Size () + 2 (* To reserve a room for entry (dummy) node. *)
  {
    DFNumMap = Dictionary<VertexID, int>()
    Vertex = Array.zeroCreate len
    Label = Array.create len 0
    Parent = Array.create len 0
    Child = Array.create len 0
    Ancestor = Array.create len 0
    Semi = Array.create len 0
    Bucket = Array.create len Set.empty
    Size = Array.create len 1
    IDom = Array.create len 0
    MaxLength = len
  }

let inline dfnum info (v: Vertex<_>) =
  info.DFNumMap.[v.GetID ()]

let rec assignDFNum info n = function
  | (p, v: Vertex<_>) :: stack
      when not <| info.DFNumMap.ContainsKey (v.GetID ()) ->
    info.DFNumMap.Add (v.GetID (), n)
    info.Semi.[n] <- n
    info.Vertex.[n] <- v
    info.Label.[n] <- n
    info.Parent.[n] <- p
    List.fold (fun acc s -> (n, s) :: acc) stack v.Succs
    |> assignDFNum info (n+1)
  | _ :: stack -> assignDFNum info n stack
  | [] -> n

let rec compress info v =
  let a = info.Ancestor.[v]
  if info.Ancestor.[a] <> 0 then
    compress info a
    if info.Semi.[info.Label.[a]] < info.Semi.[info.Label.[v]] then
      info.Label.[v] <- info.Label.[a]
    else ()
    info.Ancestor.[v] <- info.Ancestor.[a]

let eval info v =
  let a = info.Ancestor.[v]
  if a = 0 then info.Label.[v]
  else
    compress info v
    if info.Semi.[info.Label.[a]] >= info.Semi.[info.Label.[v]] then
      info.Label.[v]
    else info.Label.[a]

/// Compute semidominator of v.
let rec computeSemiDom info v = function
  | pred :: preds ->
    let u = eval info pred
    if info.Semi.[u] < info.Semi.[v] then info.Semi.[v] <- info.Semi.[u]
    computeSemiDom info v preds
  | [] -> ()

let link info v w =
  let mutable s = w
  while info.Semi.[info.Label.[w]] < info.Semi.[info.Label.[info.Child.[s]]] do
    if info.Size.[s] + info.Size.[info.Child.[info.Child.[s]]]
       >= 2 * info.Size.[info.Child.[s]]
    then info.Ancestor.[info.Child.[s]] <- s
         info.Child.[s] <- info.Child.[info.Child.[s]]
    else info.Size.[info.Child.[s]] <- info.Size.[s]
         info.Ancestor.[s] <- info.Child.[s]
         s <- info.Ancestor.[s]
  done
  info.Label.[s] <- info.Label.[w]
  info.Size.[v] <- info.Size.[v] + info.Size.[w]
  if info.Size.[v] < 2 * info.Size.[w] then
    let t = s
    s <- info.Child.[v]
    info.Child.[v] <- t
  while s <> 0 do
    info.Ancestor.[s] <- v
    s <- info.Child.[s]
  done

let computeDom info p =
  Set.iter (fun v ->
    let u = eval info v
    if info.Semi.[u] < info.Semi.[v] then info.IDom.[v] <- u
    else info.IDom.[v] <- p) info.Bucket.[p]
  info.Bucket.[p] <- Set.empty

let rec computeDomOrDelay info parent =
  if info.Bucket.[parent].IsEmpty then ()
  else computeDom info parent

/// Temporarily connect entry dummy node and real entry nodes.
let connect (g: DiGraph<_, _>) =
  let root = g.GetRoot ()
  if root.GetID () = 0 then root
  else
    let dummyEntry = Vertex<_> ()
    dummyEntry.Succs <- [root]
    root.Preds <- dummyEntry :: root.Preds
    dummyEntry

/// Disconnect the dummy node and the entry nodes.
let disconnect (g: DiGraph<_, _>) =
  let root = g.GetRoot ()
  root.Preds <- root.Preds |> List.filter (fun p -> p.GetID () <> 0)

let initDominator (g: DiGraph<_, _>) =
  let info = initDomInfo g
  let dummyEntry = connect g
  let n = assignDFNum info 1 [(0, dummyEntry)]
  for i = n - 1 downto 2 do
    let v = info.Vertex.[i]
    let p = info.Parent.[i]
    List.map (dfnum info) v.Preds |> computeSemiDom info i
    info.Bucket.[info.Semi.[i]] <- Set.add i info.Bucket.[info.Semi.[i]]
    link info p i (* Link the parent (p) to the forest. *)
    computeDomOrDelay info p
  done
  disconnect g
  for i = 2 to n - 1 do
    if info.IDom.[i] <> info.Semi.[i] then
      info.IDom.[i] <- info.IDom.[info.IDom.[i]]
    else ()
  done
  info

let topologicalOrder (visited, stack, orderMap, cnt) v =
  let rec checkStack visited (stack: Vertex<_> list) orderMap cnt =
    match stack with
    | [] -> stack, orderMap, cnt
    | v :: stack ->
      if List.exists (fun s -> Set.contains s visited |> not) v.Succs then
        v :: stack, orderMap, cnt
      else
        let orderMap = Map.add v cnt orderMap
        checkStack visited stack orderMap (cnt - 1)
  let visited = Set.add v visited
  let stack, orderMap, cnt = checkStack visited (v :: stack) orderMap cnt
  visited, stack, orderMap, cnt

let updateReachMap bg exits reachMap =
  let rec loop reachMap = function
    | [] -> reachMap
    | (v: Vertex<_>) :: vs ->
      let reachMap = Map.add (v.GetID ()) true reachMap
      let vs =
        List.fold (fun acc (w: Vertex<_>) ->
          if Map.find (w.GetID ()) reachMap then acc else w :: acc) vs v.Succs
      loop reachMap vs
  List.filter (fun (v: Vertex<_>) -> not (Map.find (v.GetID ()) reachMap)) exits
  |> loop reachMap

let rec calculateExits (fg: DiGraph<_, _>) (bg: DiGraph<_, _>) reachMap exits =
  if Map.forall (fun _ b -> b) reachMap then exits
  else
    let reachMap = updateReachMap bg exits reachMap
    let exits =
      fg.FoldVertex (fun acc (v: Vertex<_>) ->
        if List.length v.Succs = 0 && not <| Map.find (v.GetID ()) reachMap then
          bg.FindVertexByID (v.GetID ()) :: acc
        else acc) exits
    calculateExits fg bg reachMap exits

let preparePostDomAnalysis (fg: DiGraph<_, _>) (bg: DiGraph<_, _>) =
  // Remove backedges from forward graph
  let size = fg.Size () - 1
  let _, _, order, _ =
    fg.FoldVertexDFS topologicalOrder (Set.empty, [], Map.empty, size)
  let backEdges =
    fg.FoldEdge (fun acc (src: Vertex<_>) (dst: Vertex<_>) ->
      if src.GetID () = dst.GetID () then
        let edge = fg.FindEdge src dst
        fg.RemoveEdge src dst
        (src, dst, edge) :: acc
      else acc) []
    |> fg.FoldEdge (fun acc (src: Vertex<_>) (dst: Vertex<_>) ->
      if Map.find src order > Map.find dst order then
        let edge = fg.FindEdge src dst
        fg.RemoveEdge src dst
        (src, dst, edge) :: acc
      else acc)
  let reachMap =
    bg.FoldVertex (fun acc (v: Vertex<_>) ->
      Map.add (v.GetID ()) false acc) Map.empty
  let exits = calculateExits fg bg reachMap bg.Unreachables
  // Restore backedges to backward graph
  List.iter (fun (src, dst, edge) -> fg.AddEdge src dst edge) backEdges
  let dummy = Vertex<'V> ()
  dummy.Succs <- exits
  List.iter (fun (v: Vertex<_>) -> v.Preds <- dummy :: v.Preds) exits
  bg.SetRoot dummy
  bg

let initDominatorContext g =
  let forward = initDominator g
  let g' = g.Reverse () |> preparePostDomAnalysis g
  let backward = initDominator g'
  {
    ForwardGraph = g
    ForwardDomInfo = forward
    BackwardGraph = g'
    BackwardDomInfo = backward
  }

let checkVertexInGraph (g: DiGraph<'V, 'E>) (v: Vertex<'V>) =
  let v' = g.FindVertex v
  if v === v' then ()
  else raise VertexNotFoundException

let private idomAux ctxt g v =
  let id = ctxt.IDom.[dfnum ctxt v]
  if id > 1 then Some ctxt.Vertex.[id] else None

let idom ctxt v =
  let g = ctxt.ForwardGraph
  checkVertexInGraph g v
  idomAux ctxt.ForwardDomInfo g v

let ipdom ctxt v =
  let g' = ctxt.BackwardGraph
  let v = g'.FindVertex v
  idomAux ctxt.BackwardDomInfo g' v

let rec domsAux acc v ctxt =
  let id = ctxt.IDom.[dfnum ctxt v]
  if id > 0 then domsAux (ctxt.Vertex.[id] :: acc) ctxt.Vertex.[id] ctxt
  else List.rev acc

let doms ctxt v =
  let g = ctxt.ForwardGraph
  checkVertexInGraph g v
  domsAux [] v ctxt.ForwardDomInfo

let pdoms ctxt v =
  let g' = ctxt.BackwardGraph
  domsAux [] v ctxt.BackwardDomInfo

let computeDomTree (g: DiGraph<'V, 'E>) ctxt =
  let domTree = Array.create ctxt.MaxLength []
  g.IterVertexDFS (fun v ->
    let idom = ctxt.IDom.[dfnum ctxt v]
    domTree.[idom] <- v :: domTree.[idom])
  domTree

let rec computeFrontierLocal s ctxt (parent: Vertex<_>) = function
  | succ :: rest ->
    let succID = dfnum ctxt succ
    let d = ctxt.Vertex.[ctxt.IDom.[succID]]
    let s = if d.GetID () = parent.GetID () then s else Set.add succID s
    computeFrontierLocal s ctxt parent rest
  | [] -> s

let rec computeDF
    (domTree: Vertex<_> list [])
    (frontiers: Vertex<_> list [])
    g
    ctxt
    (r: Vertex<'V>) =
  let mutable s = Set.empty
  for succ in r.Succs do
    let succID = dfnum ctxt succ
    let d = ctxt.Vertex.[ctxt.IDom.[succID]]
    if d.GetID () <> r.GetID () then s <- Set.add succID s
  done
  for child in domTree.[dfnum ctxt r] do
    computeDF domTree frontiers g ctxt child
    for node in frontiers.[dfnum ctxt child] do
      let doms = domsAux [] node ctxt
      let dominate = doms |> List.exists (fun d -> d.GetID () = r.GetID ())
      if not dominate then s <- Set.add (dfnum ctxt node) s
    done
  done
  frontiers.[dfnum ctxt r] <- Set.fold (fun df n -> ctxt.Vertex.[n] :: df) [] s

let frontier ctxt v =
  let g = ctxt.ForwardGraph
  checkVertexInGraph g v
  let root = g.GetRoot ()
  let ctxt = ctxt.ForwardDomInfo
  let frontiers = Array.create ctxt.MaxLength []
  let domTree = computeDomTree g ctxt
  computeDF domTree frontiers g ctxt root
  frontiers.[dfnum ctxt v]

let dominatorTree ctxt =
  let g = ctxt.ForwardGraph
  let ctxt = ctxt.ForwardDomInfo
  let tree = computeDomTree g ctxt
  let tree = Array.sub tree 2 (Array.length tree - 2) // Remove a dummy node
  let root = ctxt.Vertex.[2]
  let tree =
    Array.mapi (fun dfNum vs -> dfNum, vs) tree
    |> Array.fold (fun tree (dfNum, vs) ->
        Map.add ctxt.Vertex.[dfNum + 2] vs tree) Map.empty
  tree, root

// vim: set tw=80 sts=2 sw=2:
