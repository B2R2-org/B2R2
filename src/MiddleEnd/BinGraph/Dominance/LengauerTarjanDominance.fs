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

/// Lengauer-Tarjan dominance algorithm for dominator computation. A fast
/// algorithm for finding dominators in a flow graph, TOPLAS 1979.
module B2R2.MiddleEnd.BinGraph.Dominance.LengauerTarjanDominance

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

type private DomInfo<'V when 'V: equality> = {
  /// Vertex ID -> DFNum
  DFNumMap: Dictionary<VertexID, int>
  /// DFNum -> Vertex
  Vertex: IVertex<'V>[]
  /// DFNum -> DFNum in the ancestor chain s.t. DFNum of its Semi is minimal.
  Label: int[]
  /// DFNum -> DFNum of the parent node (zero if not exists).
  Parent: int[]
  /// DFNum -> DFNum of the child node (zero if not exists).
  Child: int[]
  /// DFNum -> DFNum of an ancestor.
  Ancestor: int[]
  /// DFNum -> DFNum of a semidominator.
  Semi: int[]
  /// DFNum -> set of DFNums (vertices that share the same sdom).
  Bucket: Set<int>[]
  /// DFNum -> Size
  Size: int[]
  /// DFNum -> DFNum of an immediate dominator.
  IDom: int[]
  /// Length of the arrays.
  MaxLength: int
}

let private initDomInfo (g: IDiGraph<_, _>) =
  (* To reserve a room for entry (dummy) node. *)
  let len = g.Size + 1
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

let inline private dfnum (info: DomInfo<_>) (v: IVertex<_>) =
  info.DFNumMap[v.ID]

let rec private prepare (g: IDiGraph<_, _>) (info: DomInfo<_>) n = function
  | (p, v : IVertex<_>) :: stack when not <| info.DFNumMap.ContainsKey v.ID ->
    info.DFNumMap.Add (v.ID, n)
    info.Semi[n] <- n
    info.Vertex[n] <- v
    info.Label[n] <- n
    info.Parent[n] <- p
    let stack' = g.GetSuccs v |> Seq.fold (fun acc s -> (n, s) :: acc) stack
    prepare g info (n + 1) stack'
  | _ :: stack -> prepare g info n stack
  | [] -> n - 1

let private preparePostDomAnalysis (fg: IDiGraph<_, _>) (bg: IDiGraph<_, _>) =
  let exits =
    GraphUtils.findExits fg |> List.map (fun v -> bg.FindVertexByID v.ID)
  let dummy, bg = bg.AddVertex ()
  let bg =
    exits
    |> List.fold (fun (bg: IDiGraph<_, _>) v -> bg.AddEdge (dummy, v)) bg
  bg, dummy

let rec private compress info v =
  let a = info.Ancestor[v]
  if info.Ancestor[a] <> 0 then
    compress info a
    if info.Semi[info.Label[a]] < info.Semi[info.Label[v]] then
      info.Label[v] <- info.Label[a]
    else ()
    info.Ancestor[v] <- info.Ancestor[a]

let private eval info v =
  if info.Ancestor[v] = 0 then info.Label[v]
  else
    compress info v
    if info.Semi[info.Label[info.Ancestor[v]]] >= info.Semi[info.Label[v]]
    then info.Label[v]
    else info.Label[info.Ancestor[v]]

/// Compute semidominator of v.
let rec private computeSemiDom info v = function
  | pred :: preds ->
    let u = eval info pred
    if info.Semi[u] < info.Semi[v] then info.Semi[v] <- info.Semi[u]
    computeSemiDom info v preds
  | [] -> ()

let private link info v w =
  let mutable s = w
  while info.Semi[info.Label[w]] < info.Semi[info.Label[info.Child[s]]] do
    if info.Size[s] + info.Size[info.Child[info.Child[s]]]
       >= 2 * info.Size[info.Child[s]]
    then info.Ancestor[info.Child[s]] <- s
         info.Child[s] <- info.Child[info.Child[s]]
    else info.Size[info.Child[s]] <- info.Size[s]
         info.Ancestor[s] <- info.Child[s]
         s <- info.Ancestor[s]
  done
  info.Label[s] <- info.Label[w]
  info.Size[v] <- info.Size[v] + info.Size[w]
  if info.Size[v] < 2 * info.Size[w] then
    let t = s
    s <- info.Child[v]
    info.Child[v] <- t
  while s <> 0 do
    info.Ancestor[s] <- v
    s <- info.Child[s]
  done

let private computeDom info p =
  Set.iter (fun v ->
    let u = eval info v
    if info.Semi[u] < info.Semi[v] then info.IDom[v] <- u
    else info.IDom[v] <- p) info.Bucket[p]
  info.Bucket[p] <- Set.empty

let rec private computeDomOrDelay info parent =
  if info.Bucket[parent].IsEmpty then ()
  else computeDom info parent

let private connectDummy (g: IDiGraph<_, _>) (root: IVertex<_>) =
  if not root.HasData then root, g
  else
    let dummyEntry, g = g.AddVertex ()
    let g = g.AddEdge (dummyEntry, root)
    dummyEntry, g

let private computeDominatorInfo g root =
  let info = initDomInfo g
  let dummyEntry, g = connectDummy g root
  let n = prepare g info 0 [(0, dummyEntry)]
  for i = n downto 1 do
    let v = info.Vertex[i]
    let p = info.Parent[i]
    g.GetPreds v
    |> Array.toList
    |> List.map (dfnum info)
    |> computeSemiDom info i
    info.Bucket[info.Semi[i]] <- Set.add i info.Bucket[info.Semi[i]]
    link info p i (* Link the parent (p) to the forest. *)
    computeDomOrDelay info p
  done
  for i = 1 to n do
    if info.IDom[i] <> info.Semi[i] then
      info.IDom[i] <- info.IDom[info.IDom[i]]
    else ()
  done
  g.RemoveVertex dummyEntry |> ignore
  info

let rec private domsAux acc v info =
  if info.DFNumMap.ContainsKey (v: IVertex<'V>).ID then
    let id = info.IDom[dfnum info v]
    if id > 0 then domsAux (info.Vertex[id] :: acc) info.Vertex[id] info
    else acc |> List.toArray
  else acc |> List.toArray

let private idomAux info v =
  if info.DFNumMap.ContainsKey (v: IVertex<'V>).ID then
    let id = info.IDom[dfnum info v]
    if id >= 1 then info.Vertex[id] else null
  else null

let private computeDominanceFromReversedGraph (g: IDiGraph<_, _>) =
  let g', root' = g.Reverse [] |> preparePostDomAnalysis g
  let backwardDom = computeDominatorInfo g' root'
  {| Graph = g'; DomInfo = backwardDom |}

#if DEBUG
let private checkVertexInGraph (g: IDiGraph<_, _>) (v: IVertex<_>) =
  let v' = g.FindVertexByData v.VData
  if v.ID = v'.ID then ()
  else raise VertexNotFoundException
#endif

[<CompiledName "Create">]
let create (g: IDiGraph<'V, 'E>) (dfp: IDominanceFrontierProvider<_, _>) =
  let forwardRoot = g.GetRoots () |> Seq.exactlyOne
  let forwardDomInfo = computeDominatorInfo g forwardRoot
  let domTree = lazy DominatorTree (g, idomAux forwardDomInfo)
  let mutable dfProvider = null
  let backward = lazy computeDominanceFromReversedGraph g
  { new IDominance<'V, 'E> with
      member _.Dominators v =
#if DEBUG
        checkVertexInGraph g v
#endif
        domsAux [v] v forwardDomInfo

      member _.ImmediateDominator v =
#if DEBUG
        checkVertexInGraph g v
#endif
        idomAux forwardDomInfo v

      member __.DominatorTree =
        domTree.Value

      member _.PostDominators v =
        domsAux [v] v backward.Value.DomInfo

      member _.ImmediatePostDominator v =
        let g' = backward.Value.Graph
        let v = g'.FindVertexByData v.VData
        idomAux backward.Value.DomInfo v

      member __.DominanceFrontier v =
#if DEBUG
        checkVertexInGraph g v
#endif
        if isNull dfProvider then
          dfProvider <- dfp.CreateIDominanceFrontier (g, __)
        else ()
        dfProvider.DominanceFrontier v }
