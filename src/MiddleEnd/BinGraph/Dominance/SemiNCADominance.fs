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

/// Semi-NCA algorithm for dominator computation. Finding dominators in
/// practice, ESA 2004.
module B2R2.MiddleEnd.BinGraph.Dominance.SemiNCADominance

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

type LTDomInfo<'V when 'V: equality> =
  { /// Vertex ID -> DFPre
    DFPre: Dictionary<VertexID, int>
    /// DFPre -> Vertex
    Vertex: (IVertex<'V> | null)[]
    /// DFPre -> DFPre in the ancestor chain s.t. DFPre of its Semi is minimal.
    Label: int[]
    /// DFPre -> DFPre of the parent node (zero if not exists).
    Parent: int[]
    /// DFPre -> DFPre of an ancestor.
    Ancestor: int[]
    /// DFPre -> DFPre of a semidominator.
    Semi: int[]
    /// DFPre -> DFPre of an immediate dominator.
    IDom: int[]
    /// Length of the arrays.
    MaxLength: int
    /// Real roots of graph
    Roots: IVertex<'V>[]
    /// Dummy root
    DummyRoot: IVertex<'V> }

let private initDomInfo (g: IDiGraphAccessible<_, _>) =
  (* To reserve a room for entry (dummy) node. *)
  let len = g.Size + 1
  { DFPre = Dictionary<VertexID, int>()
    Vertex = Array.zeroCreate len
    Label = Array.create len 0
    Parent = Array.create len 0
    Ancestor = Array.create len 0
    Semi = Array.create len 0
    IDom = Array.create len -1
    MaxLength = len
    Roots = g.GetRoots()
    DummyRoot = GraphUtils.makeDummyVertex () }

let inline private dfpre (info: LTDomInfo<_>) (v: IVertex<_>) = info.DFPre[v.ID]

let rec private computePostorderAux g (post: Dictionary<_, _>) n = function
  | v: IVertex<_> :: stack when not <| post.ContainsKey v.ID ->
    post.Add(v.ID, -1)
    let stack = v :: stack
    let stack =
      (g: IDiGraphAccessible<_, _>).GetSuccs v
      |> Seq.fold (fun acc s -> s :: acc) stack
    computePostorderAux g post n stack
  | v: IVertex<_> :: stack ->
    if post[v.ID] = -1 then
      post[v.ID] <- n
      computePostorderAux g post (n + 1) stack
    else
      computePostorderAux g post n stack
  | [] -> ()

let private computePostorder (g: IDiGraphAccessible<_, _>) order =
  let stack = g.GetRoots() |> Array.toList
  computePostorderAux g order 1 stack

let rec private prepare (g: IDiGraphAccessible<_, _>) info n = function
  | (p, v : IVertex<_>) :: stack when not <| info.DFPre.ContainsKey v.ID ->
    info.DFPre.Add(v.ID, n)
    info.Semi[n] <- n
    info.Vertex[n] <- v
    info.Label[n] <- n
    info.Parent[n] <- p
    let stack' = g.GetSuccs v |> Seq.fold (fun acc s -> (n, s) :: acc) stack
    prepare g info (n + 1) stack'
  | _ :: stack -> prepare g info n stack
  | [] -> n - 1

let private prepareWithDummyRoot g info =
  info.DFPre.Add(info.DummyRoot.ID, 0)
  info.Roots |> Array.map (fun v -> 0, v) |> Array.toList |> prepare g info 1

let private getPreds g info v =
  if info.Roots |> Array.contains v then
    [| info.DummyRoot; yield! (g: IDiGraphAccessible<_, _>).GetPreds v |]
  else g.GetPreds v

let rec private compress info v =
  let a = info.Ancestor[v]
  if info.Ancestor[a] <> 0 then
    compress info a
    if info.Semi[info.Label[a]] < info.Semi[info.Label[v]] then
      info.Label[v] <- info.Label[a]
    else
      ()
    info.Ancestor[v] <- info.Ancestor[a]
  else
    ()

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
    if info.Semi[u] < info.Semi[v] then info.Semi[v] <- info.Semi[u] else ()
    computeSemiDom info v preds
  | [] -> ()

let private link info v w =
  info.Ancestor[w] <- v
  info.Label[w] <- w

let rec private computeDom info p s =
  if p <= s then p
  else computeDom info (info.IDom[p]) s

let private prepareDomInfo (g: IDiGraphAccessible<_, _>) =
  let info = initDomInfo g
  let n = prepareWithDummyRoot g info
  info, n

let private computeIDom g info n =
  for i = n downto 1 do
    let v = info.Vertex[i]
    let p = info.Parent[i]
    getPreds g info v
    |> Array.map (dfpre info)
    |> Array.toList
    |> computeSemiDom info i
    link info p i (* Link the parent (p) to the forest. *)
  done
  for i = 1 to n do
    let p = info.Parent[i]
    let s = info.Semi[i]
    info.IDom[i] <- computeDom info p s
  done
  info

let private computeDomInfo g =
  let info, n = prepareDomInfo g
  computeIDom g info n

let rec private domsAux acc v info =
  if info.DFPre.ContainsKey((v: IVertex<'V>).ID) then
    let id = info.IDom[dfpre info v]
    if id > 0 then domsAux (info.Vertex[id] :: acc) info.Vertex[id] info
    else acc |> List.toArray
  else acc |> List.toArray

let private idomAux info v =
  if info.DFPre.ContainsKey((v: IVertex<'V>).ID) then
    let id = info.IDom[dfpre info v]
    if id >= 1 then info.Vertex[id] else null
  else null

let private createDominance fwG (bwG: Lazy<IDiGraphAccessible<_, _>>) fwInfo
                            (fwDT: Lazy<DominatorTree<_, _>>)
                            (bwInfo: Lazy<LTDomInfo<_>>)
                            (bwDT: Lazy<DominatorTree<_, _>>)
                            (dfp: IDominanceFrontierProvider<_, _>) =
  let mutable dfProvider = null
  let mutable pdfProvider = null
  { new IDominance<'V, 'E> with
    member _.Dominators v =
#if DEBUG
      GraphUtils.checkVertexInGraph fwG v
#endif
      domsAux [ v ] v fwInfo
    member _.ImmediateDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph fwG v
#endif
      idomAux fwInfo v
    member _.DominatorTree = fwDT.Value
    member this.DominanceFrontier v =
#if DEBUG
      GraphUtils.checkVertexInGraph fwG v
#endif
      if isNull pdfProvider then
        pdfProvider <- dfp.CreateIDominanceFrontier(fwG, this, false)
      else ()
      pdfProvider.DominanceFrontier v
    member _.PostDominators v =
#if DEBUG
      GraphUtils.checkVertexInGraph bwG.Value v
#endif
      domsAux [ v ] v bwInfo.Value
    member _.ImmediatePostDominator v =
#if DEBUG
      GraphUtils.checkVertexInGraph bwG.Value v
#endif
      idomAux bwInfo.Value v
    member _.PostDominatorTree = bwDT.Value
    member this.PostDominanceFrontier v =
#if DEBUG
      GraphUtils.checkVertexInGraph bwG.Value v
#endif
      if isNull dfProvider then
        dfProvider <- dfp.CreateIDominanceFrontier(bwG.Value, this, true)
      else ()
      dfProvider.DominanceFrontier v }

let private computeDominance g (dfp: IDominanceFrontierProvider<_, _>) =
  let fwInfo = computeDomInfo g
  let fwDT = lazy DominatorTree(g, idomAux fwInfo)
  let bwG = lazy (GraphUtils.findExits g |> g.Reverse)
  let bwInfo = lazy (computeDomInfo bwG.Value)
  let bwDT = lazy DominatorTree(bwG.Value, idomAux bwInfo.Value)
  createDominance g bwG fwInfo fwDT bwInfo bwDT dfp, fwInfo, bwInfo

let private checkUnreachable info (src: IVertex<_>) =
  match info.DFPre.TryGetValue src.ID with
  | false, _
  | true, -1 -> true
  | _ -> false

[<CompiledName "Create">]
let create g dfp =
  let dom, _, _ = computeDominance g dfp
  dom

let createWithInfo g dfp =
  let dom, fw, bw = computeDominance g dfp
  dom, fw, bw

let creatFromInfo g fwInfo (bwInfo: Lazy<LTDomInfo<_>>) dfp =
  let fwDT = lazy DominatorTree(g, idomAux fwInfo)
  let bwG = lazy (GraphUtils.findExits g |> g.Reverse)
  let bwDT = lazy DominatorTree(bwG.Value, idomAux bwInfo.Value)
  createDominance g bwG fwInfo fwDT bwInfo bwDT dfp

let updateInfo g info (edge: Edge<_, _>) =
  let src = edge.First
  if checkUnreachable info src then info
  else computeDomInfo g