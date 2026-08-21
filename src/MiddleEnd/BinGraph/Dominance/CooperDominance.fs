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

/// Provides the Cooper et al.'s algorithm for dominance computation presented
/// in "A Simple, Fast Dominance Algorithm", SPE 2001.
module B2R2.MiddleEnd.BinGraph.Dominance.CooperDominance

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

type private CPDomInfo<'V when 'V: equality> =
  { /// Vertex ID -> Num
    NumMap: Dictionary<VertexID, int>
    /// Num -> Vertex ID
    Vertex: (IVertex<'V> | null)[]
    /// Num -> Num of the immediate dominator.
    IDom: int[]
    /// Num -> array of Num of the predecessors.
    Preds: int[][]
    /// Real roots of graph
    Roots: IVertex<'V>[]
    /// Num of the dummy root, which sits above every real root. Only the
    /// numbering pass knows it, as it is the last number handed out; until
    /// then this holds a number no vertex can take.
    mutable DummyNum: int }

let private initDomInfo (g: IDiGraphAccessible<_, _>) =
  (* To reserve a room for entry (dummy) node. *)
  let len = g.Size + 1
  { NumMap = Dictionary<VertexID, int>()
    Vertex = Array.zeroCreate len
    IDom = Array.create len -1
    Preds = Array.zeroCreate len
    Roots = g.GetRoots()
    DummyNum = len }

(* A predecessor unreachable from the roots has no number assigned, so it
   cannot take part in the computation below. *)
let private getPredNums (g: IDiGraphAccessible<_, _>) info v =
  g.GetPreds v
  |> Array.choose (fun p ->
    match info.NumMap.TryGetValue p.ID with
    | true, n -> Some n
    | false, _ -> None)

let private prepareWithDummyRoot g info =
  let realRoots = info.Roots
  let n =
#if COOPER_USE_DFS
    Traversal.DFS.foldPostorderWithRoots g
#else
    Traversal.BFS.foldRevWithRoots g
#endif
      (realRoots |> Array.toList)
      (fun n v ->
       info.NumMap[v.ID] <- n
       info.Vertex[n] <- v
       n + 1)
      0
  info.DummyNum <- n
  for r in realRoots |> Array.map (fun v -> info.NumMap[v.ID]) do
    info.IDom[r] <- n
  info.IDom[n] <- n
  for i = 0 to n - 1 do
    let v = info.Vertex[i]
    let preds =
      if realRoots |> Array.contains v then [| n; yield! getPredNums g info v |]
      else getPredNums g info v
    info.Preds[i] <- preds
  n

let private getProcessedPreds info i =
  info.Preds[i]
  |> Array.filter (fun p -> info.IDom[p] <> -1)

let private intersect (idoms: array<int>) b1 b2 =
  let mutable f1 = b1
  let mutable f2 = b2
  while f1 <> f2 do
    while f1 < f2 do
      f1 <- idoms[f1]
    while f2 < f1 do
      f2 <- idoms[f2]
  f1

let rec private domsAux acc v info =
  if info.NumMap.ContainsKey((v: IVertex<'V>).ID) then
    let idom = info.IDom[info.NumMap[v.ID]]
    if idom = -1 || idom = info.DummyNum then acc |> List.toArray
    else domsAux (info.Vertex[idom] :: acc) info.Vertex[idom] info
  else
    acc |> List.toArray

let private idomAux info v =
  if info.NumMap.ContainsKey((v: IVertex<'V>).ID) then
    let num = info.IDom[info.NumMap[v.ID]]
    if num <> -1 && num <> info.DummyNum then info.Vertex[num] else null
  else
    null

let private prepareDomInfo (g: IDiGraphAccessible<_, _>) =
  let info = initDomInfo g
  let n = prepareWithDummyRoot g info
  info, n

let private computeIDom info n =
  let mutable changed = true
  while changed do
    changed <- false
    for i = n - 1 downto 0 do
      let processedPreds = getProcessedPreds info i
      let mutable newIdom = processedPreds[0]
      for p in processedPreds[1..] do
        newIdom <- intersect info.IDom p newIdom
      if info.IDom[i] <> newIdom then
        info.IDom[i] <- newIdom
        changed <- true
      else
        ()
  info

let private computeDomInfo g =
  let info, n = prepareDomInfo g
  computeIDom info n

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
/// Creates an IDominance instance that computes dominance information using
/// Cooper et al.'s algorithm, which iterates like IterativeDominance but keeps
/// only the immediate dominator of each vertex instead of a whole dominator
/// set. Its authors measured it as beating Lengauer-Tarjan on the control-flow
/// graphs of real programs, which are small and mostly reducible.
/// </summary>
/// <param name="g">The graph to compute the dominance of.</param>
/// <param name="dfp">Provides the dominance frontier implementation, which is
/// created only when a frontier is first requested.</param>
[<CompiledName "Create">]
let create g (dfp: IDominanceFrontierProvider<_, _>) =
  let dom, _, _ = computeDominance g dfp
  dom
