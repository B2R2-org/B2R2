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

module B2R2.MiddleEnd.BinGraph.SCC

open System.Collections.Generic

type SCC<'V when 'V: equality> = Set<IVertex<'V>>

type SCCInfo<'V when 'V: equality> = {
  /// Vertex ID -> DFNum
  DFNumMap: Dictionary<VertexID, int>
  /// DFNum -> Vertex
  Vertex: IVertex<'V> []
  /// DFNum -> LowLink
  LowLink: int []
}

let initSCCInfo (g: IGraph<_, _>) =
  let len = g.Size + 1
  { DFNumMap = Dictionary<VertexID, int>()
    Vertex = Array.zeroCreate len
    LowLink = Array.zeroCreate len }

let inline dfnum ctxt (v: IVertex<_>) =
  ctxt.DFNumMap[v.ID]

let inline lowlink ctxt v =
  ctxt.LowLink[dfnum ctxt v]

let rec assignSCC ctxt vNum stack scc =
  if not (List.isEmpty stack) then
    let wNum = List.head stack
    if wNum >= vNum then
      let stack = List.tail stack
      let w = ctxt.Vertex[wNum]
      let scc = Set.add w scc
      assignSCC ctxt vNum stack scc
    else stack, scc
  else stack, scc

let createSCC ctxt v stack sccs =
  let vNum = dfnum ctxt v
  if lowlink ctxt v = vNum then
    let stack, scc = assignSCC ctxt vNum stack Set.empty
    stack, scc :: sccs
  else stack, sccs

let inline min x y = if x < y then x else y

/// R.Tarjan. Depth-first search and linear graph algorithms
let rec computeSCC (g: IGraph<_, _>) ctxt (v: IVertex<_>) n stack sccs =
  ctxt.DFNumMap[v.ID] <- n
  ctxt.LowLink[n] <- n
  ctxt.Vertex[n] <- v
  let n, stack, sccs =
    g.GetSuccs v
    |> Seq.fold (computeLowLink g ctxt v) (n + 1, n :: stack, sccs)
  let stack, sccs = createSCC ctxt v stack sccs
  n, stack, sccs

and computeLowLink g ctxt v (n, stack, sccs) (w: IVertex<_>) =
  let vNum = dfnum ctxt v
  let vLink = lowlink ctxt v
  if ctxt.DFNumMap.ContainsKey <| w.ID then
    let wNum = dfnum ctxt w
    if List.contains wNum stack then ctxt.LowLink[vNum] <- min vLink wNum
    n, stack, sccs
  else
    let n, stack, sccs = computeSCC g ctxt w n stack sccs
    let wLink = lowlink ctxt w
    ctxt.LowLink[vNum] <- min vLink wLink
    n, stack, sccs

let compute (g: IGraph<_, _>) root =
  let ctxt = initSCCInfo g
  g.Unreachables
  |> Seq.fold (fun acc v -> Set.add v acc) Set.empty
  |> Set.add root
  |> Set.fold (fun (n, acc) root ->
    let n, _, sccs = computeSCC g ctxt root n [] []
    let acc = sccs |> List.fold (fun acc scc -> Set.add scc acc) acc
    n, acc) (1, Set.empty)
  |> snd

let condensation graphInit g root =
  let sccs = compute g root
  let cGraph = graphInit ()
  let vMap, cGraph =
    sccs
    |> Set.fold (fun (acc, cGraph: IGraph<_, _>) scc ->
      let v, cGraph = cGraph.AddVertex scc
      let acc = Set.fold (fun acc w -> Map.add w v acc) acc scc
      acc, cGraph) (Map.empty, cGraph)
  Set.empty
  |> g.FoldEdge (fun acc edge ->
    let src = Map.find edge.First vMap
    let dst = Map.find edge.Second vMap
    Set.add (src, dst) acc)
  |> Set.fold (fun (condensation: IGraph<_, _>) (src, dst) ->
    condensation.AddEdge (src, dst)) cGraph
