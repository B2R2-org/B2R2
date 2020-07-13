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

module B2R2.BinGraph.Dominator

open B2R2.Utils
open System.Collections.Generic

type DomInfo<'D when 'D :> VertexData> = {
  /// Vertex ID -> DFNum
  DFNumMap: Dictionary<VertexID, int>
  /// DFNum -> Vertex
  Vertex: Vertex<'D> []
  /// DFNum -> DFNum in the ancestor chain s.t. DFNum of its Semi is minimal.
  Label: int []
  /// DFNum -> DFNum of the parent node (zero if not exists).
  Parent: int []
  /// DFNum -> DFNum of the child node (zero if not exists).
  Child: int []
  /// DFNum -> DFNum of an ancestor.
  Ancestor: int []
  /// DFNum -> DFNum of a semidominator.
  Semi: int []
  /// DFNum -> set of DFNums (vertices that share the same sdom).
  Bucket: Set<int> []
  /// DFNum -> Size
  Size: int []
  /// DFNum -> DFNum of an immediate dominator.
  IDom: int []
  /// Length of the arrays.
  MaxLength: int
}

/// Storing DomInfo of a graph. We use this to repeatedly compute doms/pdoms of
/// the same graph.
type DominatorContext<'D, 'E when 'D :> VertexData and 'D : equality> = {
  ForwardGraph: DiGraph<'D, 'E>
  ForwardRoot: Vertex<'D>
  ForwardDomInfo: DomInfo<'D>
  BackwardGraph: DiGraph<'D, 'E>
  BackwardRoot: Vertex<'D>
  BackwardDomInfo: DomInfo<'D>
}

let initDomInfo g =
  (* To reserve a room for entry (dummy) node. *)
  let len = DiGraph.getSize g + 1
  { DFNumMap = Dictionary<VertexID, int> ()
    Vertex = Array.zeroCreate len
    Label = Array.create len 0
    Parent = Array.create len 0
    Child = Array.create len 0
    Ancestor = Array.create len 0
    Semi = Array.create len 0
    Bucket = Array.create len Set.empty
    Size = Array.create len 1
    IDom = Array.create len 0
    MaxLength = len }

let inline dfnum (info: DomInfo<'D>) (v: Vertex<_>) =
  info.DFNumMap.[v.GetID ()]

let rec assignDFNum g (info: DomInfo<'D>) n = function
  | (p, v : Vertex<_>) :: stack
      when not <| info.DFNumMap.ContainsKey (v.GetID ()) ->
    info.DFNumMap.Add (v.GetID (), n)
    info.Semi.[n] <- n
    info.Vertex.[n] <- v
    info.Label.[n] <- n
    info.Parent.[n] <- p
    DiGraph.getSuccs g v
    |> List.fold (fun acc s -> (n, s) :: acc) stack
    |> assignDFNum g info (n+1)
  | _ :: stack -> assignDFNum g info n stack
  | [] -> n - 1

let rec compress info v =
  let a = info.Ancestor.[v]
  if info.Ancestor.[a] <> 0 then
    compress info a
    if info.Semi.[info.Label.[a]] < info.Semi.[info.Label.[v]] then
      info.Label.[v] <- info.Label.[a]
    else ()
    info.Ancestor.[v] <- info.Ancestor.[a]

let eval info v =
  if info.Ancestor.[v] = 0 then info.Label.[v]
  else
    compress info v
    if info.Semi.[info.Label.[info.Ancestor.[v]]] >= info.Semi.[info.Label.[v]]
    then info.Label.[v]
    else info.Label.[info.Ancestor.[v]]

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

let initDominator g root =
  let info = initDomInfo g
  let dummyEntry, g = DummyEntry.Connect g root
  let n = assignDFNum g info 0 [(0, dummyEntry)]
  for i = n downto 1 do
    let v = info.Vertex.[i]
    let p = info.Parent.[i]
    DiGraph.getPreds g v |> List.map (dfnum info) |> computeSemiDom info i
    info.Bucket.[info.Semi.[i]] <- Set.add i info.Bucket.[info.Semi.[i]]
    link info p i (* Link the parent (p) to the forest. *)
    computeDomOrDelay info p
  done
  for i = 1 to n do
    if info.IDom.[i] <> info.Semi.[i] then
      info.IDom.[i] <- info.IDom.[info.IDom.[i]]
    else ()
  done
  DiGraph.removeVertex g dummyEntry |> ignore
  info

let updateReachMap g exits reachMap =
  let rec loop reachMap = function
    | [] -> reachMap
    | (v: Vertex<_>) :: vs ->
      let reachMap = Map.add (v.GetID ()) true reachMap
      let vs =
        DiGraph.getSuccs g v
        |> List.fold (fun acc (w: Vertex<_>) ->
          if Map.find (w.GetID ()) reachMap then acc else w :: acc) vs
      loop reachMap vs
  List.filter (fun (v: Vertex<_>) ->
    not (Map.find (v.GetID ()) reachMap)) exits
  |> loop reachMap

let rec calculateExits fg bg reachMap exits =
  if Map.forall (fun _ b -> b) reachMap then exits
  else
    let reachMap = updateReachMap bg exits reachMap
    let exits =
      exits
      |> DiGraph.foldVertex fg (fun acc (v: Vertex<_>) ->
        let isExit = DiGraph.getSuccs fg v |> List.length = 0
        if isExit && not <| Map.find (v.GetID ()) reachMap then
          DiGraph.findVertexByID bg (v.GetID ()) :: acc
        else acc)
    calculateExits fg bg reachMap exits

let preparePostDomAnalysis fg root bg =
  let _, orderMap =
    Traversal.foldTopologically fg [root] (fun (cnt, map) v ->
      cnt + 1, Map.add v cnt map) (0, Map.empty)
  let backEdges =
    []
    |> DiGraph.foldEdge fg (fun acc (src: Vertex<_>) (dst: Vertex<_>) edge ->
      if src.GetID () = dst.GetID () then (src, dst, edge) :: acc
      else acc)
    |> DiGraph.foldEdge fg (fun acc (src: Vertex<_>) (dst: Vertex<_>) edge ->
      if Map.find src orderMap > Map.find dst orderMap then
        (src, dst, edge) :: acc
      else acc)
  let bgUnreachables = DiGraph.getUnreachables bg
  let bg =
    if List.isEmpty bgUnreachables then
      backEdges
      |> List.fold (fun bg (src, dst, _) ->
        let src = DiGraph.findVertexByID bg <| src.GetID ()
        let dst = DiGraph.findVertexByID bg <| dst.GetID ()
        DiGraph.removeEdge bg dst src) bg
    else bg
  let reachMap =
    Map.empty
    |> DiGraph.foldVertex bg (fun acc (v: Vertex<_>) ->
      Map.add (v.GetID ()) false acc)
  let exits =
    DiGraph.getUnreachables bg
    |> Seq.toList
    |> calculateExits fg bg reachMap
  // Restore backedges to backward graph
  let bg =
    if List.isEmpty bgUnreachables then
      backEdges
      |> List.fold (fun bg (src, dst, e) ->
        let src = DiGraph.findVertexByID bg <| src.GetID ()
        let dst = DiGraph.findVertexByID bg <| dst.GetID ()
        DiGraph.addEdge bg dst src e) bg
    else bg
  let dummy, bg = DiGraph.addDummyVertex bg
  let bg =
    exits |> List.fold (fun bg v -> DiGraph.addDummyEdge bg dummy v) bg
  bg, dummy

let initDominatorContext g root =
  let forward = initDominator g root
  let g', root' = DiGraph.reverse g |> preparePostDomAnalysis g root
  let backward = initDominator g' root'
  { ForwardGraph = g
    ForwardRoot = root
    ForwardDomInfo = forward
    BackwardGraph = g'
    BackwardRoot = root'
    BackwardDomInfo = backward }

let checkVertexInGraph g (v: Vertex<_>) =
  let v' = DiGraph.findVertexByData g v.VData
  if v === v' then ()
  else raise VertexNotFoundException

let private idomAux info v =
  let id = info.IDom.[dfnum info v]
  if id >= 1 then Some info.Vertex.[id] else None

let idom ctxt v =
  let g = ctxt.ForwardGraph
  checkVertexInGraph g v
  idomAux ctxt.ForwardDomInfo v

let ipdom ctxt (v: Vertex<_>) =
  let g' = ctxt.BackwardGraph
  let v = DiGraph.findVertexByData g' v.VData
  idomAux ctxt.BackwardDomInfo v

let rec domsAux acc v info =
  let id = info.IDom.[dfnum info v]
  if id > 0 then domsAux (info.Vertex.[id] :: acc) info.Vertex.[id] info
  else List.rev acc

let doms ctxt v =
  let g = ctxt.ForwardGraph
  checkVertexInGraph g v
  domsAux [] v ctxt.ForwardDomInfo

let pdoms ctxt v =
  domsAux [] v ctxt.BackwardDomInfo

let computeDomTree g info =
  let domTree = Array.create info.MaxLength []
  DiGraph.iterVertex g (fun v ->
    let idom = info.IDom.[dfnum info v]
    domTree.[idom] <- v :: domTree.[idom])
  domTree

let rec computeFrontierLocal s ctxt (parent: Vertex<_>) = function
  | succ :: rest ->
    let succID = dfnum ctxt succ
    let d = ctxt.Vertex.[ctxt.IDom.[succID]]
    let s = if d.GetID () = parent.GetID () then s else Set.add succID s
    computeFrontierLocal s ctxt parent rest
  | [] -> s

let rec computeDF domTree (frontiers: Vertex<_> list []) g ctxt r =
  let mutable s = Set.empty
  for succ in DiGraph.getSuccs g r do
    let succID = dfnum ctxt succ
    let domID = ctxt.IDom.[succID]
    let d = ctxt.Vertex.[ctxt.IDom.[succID]]
    if domID <> 0 && d.GetID () <> r.GetID () then s <- Set.add succID s
  done
  for child in (domTree: Vertex<_> list []).[dfnum ctxt r] do
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
  let root = ctxt.ForwardRoot
  let ctxt = ctxt.ForwardDomInfo
  let frontiers = Array.create ctxt.MaxLength []
  let domTree = computeDomTree g ctxt
  computeDF domTree frontiers g ctxt root
  frontiers.[dfnum ctxt v]

let dominatorTree ctxt =
  let g = ctxt.ForwardGraph
  let info = ctxt.ForwardDomInfo
  let tree = computeDomTree g info
  let tree = Array.sub tree 1 (Array.length tree - 1) // Remove a dummy node
  let root = info.Vertex.[1]
  let tree =
    Array.mapi (fun dfNum vs -> dfNum, vs) tree
    |> Array.fold (fun tree (dfNum, vs) ->
        Map.add info.Vertex.[dfNum + 1] vs tree) Map.empty
  tree, root

// vim: set tw=80 sts=2 sw=2:
