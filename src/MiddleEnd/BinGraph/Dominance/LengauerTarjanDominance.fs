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

/// Provides the original (balanced) Lengauer-Tarjan dominance algorithm for
/// dominator computation presented in "A fast algorithm for finding dominators
/// in a flow graph", TOPLAS 1979. This sophisticated version balances when
/// constructing the ancestor forest.
[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.BinGraph.Dominance.LengauerTarjanDominance

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

type private LTDomInfo<'V when 'V: equality> =
  { /// Vertex ID -> DFNum
    DFPre: Dictionary<VertexID, int>
    /// DFNum -> Vertex
    Vertex: (IVertex<'V> | null)[]
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
#if LT_USE_SET_BUCKET
    /// DFNum -> set of DFNums (vertices that share the same sdom).
    Bucket: Set<int>[]
#else
    /// DFNum -> DFNum of the first node in the bucket.
    First: int[]
    /// DFNum -> DFNum of the next node in the bucket.
    Next: int[]
#endif
    /// DFNum -> Size
    Size: int[]
    /// DFNum -> DFNum of an immediate dominator.
    IDom: int[]
    /// Length of the arrays.
    MaxLength: int
    /// Real roots of graph
    Roots: IVertex<'V>[] }

let private initDomInfo (g: IDiGraphAccessible<_, _>) =
  (* To reserve a room for entry (dummy) node. *)
  let len = g.Size + 1
  { DFPre = Dictionary<VertexID, int>()
    Vertex = Array.zeroCreate len
    Label = Array.create len 0
    Parent = Array.create len 0
    Child = Array.create len 0
    Ancestor = Array.create len 0
    Semi = Array.create len 0
#if LT_USE_SET_BUCKET
    Bucket = Array.create len Set.empty
#else
    First = Array.create len -1
    Next = Array.create len -1
#endif
    Size = Array.create len 1
    IDom = Array.create len 0
    MaxLength = len
    Roots = g.GetRoots() }

let inline private dfpre (info: LTDomInfo<_>) (v: IVertex<_>) =
  assert (info.DFPre.ContainsKey v.ID)
  info.DFPre[v.ID]

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
  else
    ()
  while s <> 0 do
    info.Ancestor[s] <- v
    s <- info.Child[s]
  done

#if LT_USE_SET_BUCKET
let private computeDomAux info v =
  Set.iter (fun u ->
    let w = eval info u
    if info.Semi[w] < info.Semi[u] then info.IDom[u] <- w
    else info.IDom[u] <- v) info.Bucket[v]
#else
let rec private computeDomAux info v s =
  let u = eval info v
  let w = info.Next[v]
  if info.Semi[u] < info.Semi[v] then info.IDom[v] <- u else info.IDom[v] <- s
  if w = -1 then () else computeDomAux info w s
#endif

#if LT_USE_SET_BUCKET
let private computeDom info v =
  if info.Bucket[v].IsEmpty then () else computeDomAux info v
#else
let private computeDom info v =
  let w = info.First[v]
  if w = -1 then () else computeDomAux info w v
#endif

let private prepareDomInfo (g: IDiGraphAccessible<_, _>) =
  let info = initDomInfo g
  let n = prepare g info
  info, n

let private computeIDom g info n =
  for i = n downto 1 do
    computeDom info i
    let v = info.Vertex[i]
    let p = info.Parent[i]
    predNums g info v
    |> Array.toList
    |> computeSemiDom info i
#if LT_USE_SET_BUCKET
    info.Bucket[info.Semi[i]] <- Set.add i info.Bucket[info.Semi[i]]
#else
    info.Next[i] <- info.First[info.Semi[i]]
    info.First[info.Semi[i]] <- i
#endif
    link info p i (* Link the parent (p) to the forest. *)
  done
  for i = 1 to n do
    if info.IDom[i] <> info.Semi[i] then info.IDom[i] <- info.IDom[info.IDom[i]]
    else ()
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

/// <summary>
/// Creates an IDominance instance that computes dominance information using the
/// balanced Lengauer-Tarjan algorithm, which runs in near-linear time, O(m)
/// times the inverse Ackermann function, on a graph of n vertices and m edges.
/// Having no bad case makes it the safe default when the shape of the graph is
/// unknown.
/// </summary>
/// <param name="g">The graph to compute the dominance of.</param>
/// <param name="dfp">Provides the dominance frontier implementation, which is
/// created only when a frontier is first requested.</param>
[<CompiledName "Create">]
let create g (dfp: IDominanceFrontierProvider<_, _>) =
  let dom, _, _ = computeDominance g dfp
  dom
