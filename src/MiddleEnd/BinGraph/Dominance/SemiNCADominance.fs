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

/// Provides the Semi-NCA algorithm for dominator computation presented in
/// "Finding dominators in practice", ESA 2004.
[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.BinGraph.Dominance.SemiNCADominance

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

/// Represents the working state of this module's analysis. Mutating any of its
/// arrays silently invalidates the dominance computed from it, so it stays
/// internal, visible only to the dynamic-dominance benchmark, which recomputes
/// a dominance from a state it has updated.
type internal LTDomInfo<'V when 'V: equality> =
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
    Roots: IVertex<'V>[] }

let private initDomInfo (g: IDiGraphAccessible<_, _>) =
  (* To reserve a room for entry (dummy) node. *)
  let len = g.VertexCount + 1
  { DFPre = Dictionary<VertexID, int>()
    Vertex = Array.zeroCreate len
    Label = Array.create len 0
    Parent = Array.create len 0
    Ancestor = Array.create len 0
    Semi = Array.create len 0
    IDom = Array.create len -1
    MaxLength = len
    Roots = g.Roots }

let inline private dfpre (info: LTDomInfo<_>) (v: IVertex<_>) = info.DFPre[v.ID]

(* Numbers the vertices in a depth-first preorder, filling in the arrays the
   computation below reads, and answers how many of them were numbered. Every
   root enters with 0 as its parent, that being the DFNum of the dummy root
   sitting above them all; no vertex of the graph takes it. The roots go onto
   the stack in reverse, so that the first of them is the first to come back
   off, and a vertex carries its own number down to its successors. *)
let private prepare (g: IDiGraphAccessible<_, _>) info =
  let stack = Stack<struct (int * IVertex<_>)>()
  let roots = info.Roots
  for i in roots.Length - 1 .. -1 .. 0 do stack.Push(struct (0, roots[i]))
  let mutable n = 1
  while stack.Count > 0 do
    let struct (p, v) = stack.Pop()
    if not <| info.DFPre.ContainsKey v.ID then
      info.DFPre.Add(v.ID, n)
      info.Semi[n] <- n
      info.Vertex[n] <- v
      info.Label[n] <- n
      info.Parent[n] <- p
      for s in g.GetSuccs v do stack.Push(struct (n, s))
      n <- n + 1
    else
      ()
  n - 1

(* A predecessor unreachable from the roots has no DFPre number assigned, so it
   cannot take part in the computation below. The dummy root above the roots is
   no vertex of the graph, hence it enters as its number, 0, alone. *)
let private predNums (g: IDiGraphAccessible<_, _>) info v =
  let nums =
    g.GetPreds v
    |> Array.filter (fun p -> info.DFPre.ContainsKey p.ID)
    |> Array.map (dfpre info)
  if info.Roots |> Array.contains v then [| 0; yield! nums |] else nums

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
  if info.Ancestor[v] = 0 then
    info.Label[v]
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
  | [] ->
    ()

let private link info v w =
  info.Ancestor[w] <- v
  info.Label[w] <- w

let rec private computeDom info p s =
  if p <= s then p else computeDom info (info.IDom[p]) s

let private prepareDomInfo (g: IDiGraphAccessible<_, _>) =
  let info = initDomInfo g
  let n = prepare g info
  info, n

let private computeIDom g info n =
  for i = n downto 1 do
    let v = info.Vertex[i]
    let p = info.Parent[i]
    predNums g info v
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
  else
    acc |> List.toArray

let private idomAux info v =
  if info.DFPre.ContainsKey((v: IVertex<'V>).ID) then
    let id = info.IDom[dfpre info v]
    if id >= 1 then info.Vertex[id] else null
  else
    null

let private createForwardDominance g info dfp =
  let g: IDiGraphAccessible<_, _> = g
  let dfp: IDominanceFrontierProvider<_, _> = dfp
  let dt = lazy DominatorTree(g.Vertices, idomAux info)
  let mutable dfProvider = null
  { new IForwardDominance<'V> with
      member _.Dominators v =
        GraphUtils.checkVertexInGraph g v
        domsAux [ v ] v info
      member _.ImmediateDominator v =
        GraphUtils.checkVertexInGraph g v
        idomAux info v
      member _.DominatorTree = dt.Value
      member this.DominanceFrontier v =
        GraphUtils.checkVertexInGraph g v
        if isNull dfProvider then
          dfProvider <- dfp.CreateIDominanceFrontier(g, this)
        else
          ()
        dfProvider.DominanceFrontier v }

let private computeDominance g (dfp: IDominanceFrontierProvider<_, _>) =
  let fwInfo = computeDomInfo g
  let bwG = lazy (GraphUtils.findExits g |> g.Reverse)
  let bwInfo = lazy (computeDomInfo bwG.Value)
  let fw = createForwardDominance g fwInfo dfp
  let bw = lazy (createForwardDominance bwG.Value bwInfo.Value dfp)
  combineDominance g fw bw, fwInfo, bwInfo

let private checkUnreachable info (src: IVertex<_>) =
  match info.DFPre.TryGetValue src.ID with
  | false, _
  | true, -1 -> true
  | _ -> false

/// <summary>
/// Creates an IDominance instance that computes dominance information using the
/// Semi-NCA algorithm. Its O(mn) worst case is worse than the Lengauer-Tarjan
/// bound, but the ESA 2004 study measured it as the faster of the two on the
/// graphs met in practice, which makes it a good fit for a control-flow graph.
/// </summary>
/// <param name="g">The graph to compute the dominance of.</param>
/// <param name="dfp">Provides the dominance frontier implementation, which is
/// created only when a frontier is first requested.</param>
[<CompiledName "Create">]
let create g dfp =
  let dom, _, _ = computeDominance g dfp
  dom

/// Computes the dominance of the given graph, and also returns the working
/// state of the analysis for both directions, so that updateInfo and
/// createFromInfo can recompute a dominance from it.
let internal createWithInfo g dfp =
  let dom, fw, bw = computeDominance g dfp
  dom, fw, bw

/// Computes the dominance of the given graph from the working state that
/// createWithInfo or updateInfo produced, skipping the initial analysis.
let internal createFromInfo g fwInfo (bwInfo: Lazy<LTDomInfo<_>>) dfp =
  let bwG = lazy (GraphUtils.findExits g |> g.Reverse)
  let fw = createForwardDominance g fwInfo dfp
  let bw = lazy (createForwardDominance bwG.Value bwInfo.Value dfp)
  combineDominance g fw bw

/// Recomputes the working state after the given edge has been added to the
/// graph. An edge leaving an unreachable vertex cannot change any dominance
/// relation, so the state is returned untouched in that case.
let internal updateInfo g info (edge: Edge<_, _>) =
  let src = edge.First
  if checkUnreachable info src then info else computeDomInfo g
