(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>

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

module internal B2R2.Visualization.CycleRemoval

let private removeSelfCycle (vGraph: VGraph) backEdgeList src dst =
  if VGraph.getID src = VGraph.getID dst then // definition of self cycle
    let edge = vGraph.FindEdge src dst
    edge.IsBackEdge <- true
    vGraph.RemoveEdge src dst // we should remove self cycles
    (src, dst, edge) :: backEdgeList
  else backEdgeList

let private removeBackEdge (vGraph: VGraph) order backEdgeList src dst =
  if Map.find src order > Map.find dst order then // BackEdge
    match vGraph.TryFindEdge dst src with
    | Some _edge -> // exist opposite edges
      let edge = vGraph.FindEdge src dst
      edge.IsBackEdge <- true
      vGraph.RemoveEdge src dst
      (src, dst, edge) :: backEdgeList
    | None -> // single backedge
      let edge = vGraph.FindEdge src dst
      edge.IsBackEdge <- true
      vGraph.RemoveEdge src dst
      vGraph.AddEdge dst src edge
      (src, dst, edge) :: backEdgeList
  else backEdgeList

let private dfsRemoveCycles vGraph backEdgeList =
  let dfsOrder = VGraph.getDFSOrder vGraph
  let backEdgeList =
    vGraph.FoldEdge (removeBackEdge vGraph dfsOrder) backEdgeList
#if DEBUG
  Dbg.logn "dfsOrder:"
  dfsOrder
  |> Map.iter (fun v o -> sprintf "%d -> %d" (VGraph.getID v) o |> Dbg.logn)
  Dbg.logn "backEdges:"
  backEdgeList
  |> List.iter (fun (v, w, _) ->
       sprintf "%d -> %d" (VGraph.getID v) (VGraph.getID w) |> Dbg.logn)
#endif
  backEdgeList

let removeCycles (vGraph: VGraph) =
  let backEdgeList = vGraph.FoldEdge (removeSelfCycle vGraph) []
  dfsRemoveCycles vGraph backEdgeList
