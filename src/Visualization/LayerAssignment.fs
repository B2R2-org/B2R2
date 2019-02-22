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

module internal B2R2.Visualization.LayerAssignment

open B2R2.BinGraph

let private assignLayerFromSucc v =
  let succs = VGraph.getSuccs v
  match succs with
  | [] -> VGraph.setLayer v 0
  | succs ->
    let succLayers = List.map VGraph.getLayer succs
    VGraph.setLayer v <| List.max succLayers + 1

let private adjustLayerByMax maxLayer v =
  VGraph.setLayer v <| maxLayer - VGraph.getLayer v

let private adjustLayer dfsOrdered =
  let maxLayer = Array.map VGraph.getLayer dfsOrdered |> Array.max
  Array.iter (adjustLayerByMax maxLayer) dfsOrdered

let private longestPathAssignLayers vGraph =
  let dfsOrder = VGraph.getDFSOrder vGraph
  let dfsOrdered = Array.zeroCreate <| VGraph.getSize vGraph
  Map.iter (fun v i -> Array.set dfsOrdered i v) dfsOrder
  let dfsOrdered = Array.rev dfsOrdered
#if DEBUG
  Dbg.logn "dfsOrdered:"
  dfsOrdered
  |> Array.iteri (fun i v -> sprintf "%d: %d" i (VGraph.getID v) |> Dbg.logn)
#endif
  Array.iter assignLayerFromSucc dfsOrdered
  adjustLayer dfsOrdered

let rec private promote (layerArr: int []) v =
  let preds = VGraph.getPreds v
  let succs = VGraph.getSuccs v
  let dummyDiff, layerArr = List.fold (promotePred v) (0, layerArr) preds
  layerArr.[v.GetID ()] <- layerArr.[v.GetID ()] - 1
  dummyDiff - List.length preds + List.length succs, layerArr

and private promotePred v (dummyDiff, layerArr) p =
  // Check only immediate predecessors
  if layerArr.[p.GetID ()] = layerArr.[v.GetID ()] - 1 then
    let dummyDiff_, layerArr = promote layerArr p
    dummyDiff + dummyDiff_, layerArr
  else dummyDiff, layerArr

let rec private promoteVerticesLoop (vGraph: VGraph) layerArr backUp =
  let promotion, layerArr, backUp =
    let folder (acc, layerArr, backUp) v =
      if List.length <| VGraph.getPreds v > 0 then
        let promotion, layerArr = promote layerArr v
        // If promotion is negative, we preserve the result
        if promotion < 0 then acc + 1, layerArr, Array.copy layerArr
        // otherwise, restore previous layout
        else acc, backUp, Array.copy backUp
      else acc, layerArr, backUp
    vGraph.FoldVertexDFS folder (0, layerArr, backUp)
  // If there exists at least one vertex promoted, this process should be done
  // one more time
  if promotion <> 0 then
    promoteVerticesLoop vGraph layerArr <| Array.copy layerArr
  else layerArr

let private promoteVertices (vGraph: VGraph) =
  let folder (layerArr: int []) (v: Vertex<VNode>) =
    layerArr.[v.GetID ()] <- VGraph.getLayer v; layerArr
  let layerArr = Array.zeroCreate (vGraph.GetMaxID () + 1)
  let layerArr = vGraph.FoldVertex folder layerArr
  let layerArr = promoteVerticesLoop vGraph layerArr <| Array.copy layerArr
  let minLayer = Array.min layerArr
  // Set layer from the result of vertex promotion
  Array.iteri (fun id layer ->
    VGraph.setLayer (vGraph.FindVertexByID id) (layer - minLayer)) layerArr

let private assignLayerFromPred (vGraph: VGraph) vData =
  let v = vGraph.FindVertexByData vData
  let preds = VGraph.getPreds v
  match preds with
  | [] -> VGraph.setLayer v 0
  | preds ->
    let predLayers = List.map VGraph.getLayer preds
    VGraph.setLayer v <| List.max predLayers + 1

let private kahnAssignLayers (vGraph: VGraph) =
  let sortedVertices = Algorithms.kahnTopologicalSort vGraph
  List.iter (assignLayerFromPred vGraph) sortedVertices

let rec private addDummyNode (vGraph: VGraph) (backEdgeList, dummyMap) k src dst (e: VEdge) cnt =
  if cnt = 0 then
    let edge = VEdge (VGraph.getAddr src, VGraph.getAddr dst, e.Type)
    edge.IsBackEdge <- e.IsBackEdge
    vGraph.AddEdge src dst edge
    let backEdgeList =
      if edge.IsBackEdge then (dst, src, edge) :: backEdgeList else backEdgeList
    backEdgeList, dummyMap
  else
    let vNode = VNode (vGraph.GenID (), VGraph.getAddr src, [], 0.0, 0.0, true)
    let dummy = vGraph.AddVertex (vNode)
    VGraph.setLayer dummy <| VGraph.getLayer src + 1
    let edge = VEdge (VGraph.getAddr src, VGraph.getAddr dummy, e.Type)
    edge.IsBackEdge <- e.IsBackEdge
    vGraph.AddEdge src dummy edge
    let backEdgeList =
      if edge.IsBackEdge then (dummy, src, edge) :: backEdgeList else backEdgeList
    let eData, vertices = Map.find k dummyMap
    let dummyMap = Map.add k (eData, dummy :: vertices) dummyMap
    addDummyNode vGraph (backEdgeList, dummyMap) k dummy dst e (cnt - 1)

let private addDummyNodes (vGraph: VGraph) (backEdgeList, dummyMap) src dst =
  let delta = VGraph.getLayer dst - VGraph.getLayer src
  if delta > 1 then
    let edge = vGraph.FindEdge src dst
    let backEdgeList =
      if edge.IsBackEdge then List.filter (fun (_, _, e) -> e <> edge) backEdgeList
      else backEdgeList
    vGraph.RemoveEdge src dst
    let k = if edge.IsBackEdge then dst, src else src, dst
    let dummyMap = Map.add k (edge, []) dummyMap
    let backEdgeList, dummyMap =
      addDummyNode vGraph (backEdgeList, dummyMap) k src dst edge (delta - 1)
    let dummyMap =
      if edge.IsBackEdge then
        let eData, vertices = Map.find k dummyMap
        Map.add k (eData, List.rev vertices) dummyMap
      else dummyMap
    backEdgeList, dummyMap
  else backEdgeList, dummyMap

let private assignDummyNodes (vGraph: VGraph) backEdgeList =
  vGraph.FoldEdge (addDummyNodes vGraph) (backEdgeList, Map.empty)

let assignLayers vGraph backEdgeList =
  /// XXX: We'll make an option argument to select layer assignment algorithm
  /// longestPathAssignLayers vGraph
  /// promoteVertices vGraph
  kahnAssignLayers vGraph
  assignDummyNodes vGraph backEdgeList
