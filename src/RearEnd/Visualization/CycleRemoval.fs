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

module internal B2R2.RearEnd.Visualization.CycleRemoval

open B2R2.MiddleEnd.BinGraph

let private collectSelfCycle backEdgeList src dst edge =
  if VisGraph.getID src = VisGraph.getID dst then (* Definition of self cycle *)
    (edge: VisEdge).IsBackEdge <- true
    (src, dst, edge, false) :: backEdgeList
  else backEdgeList

let private collectBackEdge (vGraph: VisGraph) order backEdgeList src dst edge =
  if Map.find src order > Map.find dst order then // BackEdge
    match vGraph.TryFindEdgeData dst src with
    | Some _ -> // exist opposite edges
      (edge: VisEdge).IsBackEdge <- true
      (src, dst, edge, false) :: backEdgeList
    | None -> // single backedge
      edge.IsBackEdge <- true
      (src, dst, edge, true) :: backEdgeList
  else backEdgeList

let removeBackEdge (vGraph: VisGraph) (src, dst, edge, addReverse) =
  vGraph.RemoveEdge src dst |> ignore
  if addReverse then vGraph.AddEdge dst src edge |> ignore

let private dfsCollectBackEdges vGraph roots backEdgeList =
  let _, orderMap =
    Traversal.foldTopologically vGraph roots (fun (cnt, map) v ->
      cnt + 1, Map.add v cnt map) (0, Map.empty)
  vGraph.FoldEdge (collectBackEdge vGraph orderMap) backEdgeList

let removeCycles (vGraph: VisGraph) roots =
  let backEdgeList =
    vGraph.FoldEdge collectSelfCycle []
    |> dfsCollectBackEdges vGraph roots
  backEdgeList |> List.iter (removeBackEdge vGraph)
  backEdgeList |> List.map (fun (src, dst, edge, _) -> (src, dst, edge))
