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

let private removeSelfCycle (vGraph: VisGraph) backEdgeList src dst _ =
  if VisGraph.getID src = VisGraph.getID dst then (* Definition of self cycle *)
    let edge = vGraph.FindEdgeData src dst
    edge.IsBackEdge <- true
    vGraph.RemoveEdge src dst (* We should remove self cycles. *)
    (src, dst, edge) :: backEdgeList
  else backEdgeList

let private removeBackEdge (vGraph: VisGraph) order backEdgeList src dst _ =
  if Map.find src order > Map.find dst order then // BackEdge
    match vGraph.TryFindEdge dst src with
    | Some edge -> // exist opposite edges
      edge.IsBackEdge <- true
      vGraph.RemoveEdge src dst
      (src, dst, edge) :: backEdgeList
    | None -> // single backedge
      let edge = vGraph.FindEdgeData src dst
      edge.IsBackEdge <- true
      vGraph.RemoveEdge src dst
      vGraph.AddEdge dst src edge
      (src, dst, edge) :: backEdgeList
  else backEdgeList

let private dfsRemoveCycles vGraph roots backEdgeList =
  let topoOrder = VisGraph.getTopologicalOrder vGraph roots
  vGraph.FoldEdge (removeBackEdge vGraph topoOrder) backEdgeList

let removeCycles (vGraph: VisGraph) roots =
  let backEdgeList = vGraph.FoldEdge (removeSelfCycle vGraph) []
  dfsRemoveCycles vGraph roots backEdgeList
