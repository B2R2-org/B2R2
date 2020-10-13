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

module internal B2R2.RearEnd.Visualization.LayerAssignment

open B2R2.MiddleEnd.BinGraph

let assignLayerFromSucc vGraph v =
  let succs = VisGraph.getSuccs vGraph v
  match succs with
  | [] -> VisGraph.setLayer v 0
  | succs ->
    let succLayers = List.map VisGraph.getLayer succs
    VisGraph.setLayer v <| List.max succLayers + 1

let adjustLayerByMax maxLayer v =
  VisGraph.setLayer v <| maxLayer - VisGraph.getLayer v

let adjustLayer topoOrdered =
  let maxLayer = Array.map VisGraph.getLayer topoOrdered |> Array.max
  Array.iter (adjustLayerByMax maxLayer) topoOrdered

let longestPathAssignLayers vGraph root =
  let _, orderMap =
    Traversal.foldTopologically vGraph [root] (fun (cnt, map) v ->
      cnt + 1, Map.add v cnt map) (0, Map.empty)
  let topoOrdered = Array.zeroCreate <| vGraph.GetSize ()
  Map.iter (fun v i -> Array.set topoOrdered i v) orderMap
  let topoOrdered = Array.rev topoOrdered
  Array.iter (assignLayerFromSucc vGraph) topoOrdered
  adjustLayer topoOrdered

let rec promote vGraph (layerArr: int []) v =
  let preds = VisGraph.getPreds vGraph v
  let succs = VisGraph.getSuccs vGraph v
  let dummyDiff, layerArr = List.fold (promotePred vGraph v) (0, layerArr) preds
  layerArr.[v.GetID ()] <- layerArr.[v.GetID ()] - 1
  dummyDiff - List.length preds + List.length succs, layerArr

and promotePred vGraph v (dummyDiff, layerArr) p =
  // Check only immediate predecessors
  if layerArr.[p.GetID ()] = layerArr.[v.GetID ()] - 1 then
    let dummyDiff_, layerArr = promote vGraph layerArr p
    dummyDiff + dummyDiff_, layerArr
  else dummyDiff, layerArr

let rec promoteVerticesLoop (vGraph: VisGraph) root layerArr backUp =
  let promotion, layerArr, _ =
    let folder (acc, layerArr, backUp) v =
      if List.length <| VisGraph.getPreds vGraph v > 0 then
        let promotion, layerArr = promote vGraph layerArr v
        // If promotion is negative, we preserve the result
        if promotion < 0 then acc + 1, layerArr, Array.copy layerArr
        // otherwise, restore previous layout
        else acc, backUp, Array.copy backUp
      else acc, layerArr, backUp
    Traversal.foldPreorder vGraph root folder (0, layerArr, backUp)
  // If there exists at least one vertex promoted, this process should be done
  // one more time
  if promotion <> 0 then
    promoteVerticesLoop vGraph root layerArr <| Array.copy layerArr
  else layerArr

let promoteVertices (vGraph: VisGraph) root =
  let folder (layerArr: int []) (v: Vertex<VisBBlock>) =
    layerArr.[v.GetID ()] <- VisGraph.getLayer v; layerArr
  let layerArr = Array.zeroCreate (vGraph.GetSize ())
  let layerArr = vGraph.FoldVertex folder layerArr
  let layerArr = promoteVerticesLoop vGraph root layerArr <| Array.copy layerArr
  let minLayer = Array.min layerArr
  // Set layer from the result of vertex promotion
  Array.iteri (fun id layer ->
    VisGraph.setLayer (vGraph.FindVertexByID id) (layer - minLayer)) layerArr

let assignLayerFromPred (vGraph: VisGraph) vData =
  let v = vGraph.FindVertexByData vData
  let preds = VisGraph.getPreds vGraph v
  match preds with
  | [] -> VisGraph.setLayer v 0
  | preds ->
    let predLayers = List.map VisGraph.getLayer preds
    VisGraph.setLayer v <| List.max predLayers + 1

let kahnAssignLayers (vGraph: VisGraph) =
  Traversal.foldTopologically vGraph [] (fun acc v -> v.VData :: acc) []
  |> List.rev
  |> List.iter (assignLayerFromPred vGraph)

let rec addDummy (g: VisGraph) (backEdges, dummies) k (src: Vertex<_>) (dst: Vertex<_>) (e: VisEdge) cnt =
  if cnt = 0 then
    let edge = VisEdge (e.Type)
    edge.IsBackEdge <- e.IsBackEdge
    g.AddEdge src dst edge |> ignore
    let backEdges =
      if edge.IsBackEdge then (dst, src, edge) :: backEdges else backEdges
    backEdges, dummies
  else
    let vNode = VisBBlock (src.VData, true)
    let dummy, _ = g.AddVertex (vNode)
    VisGraph.setLayer dummy <| VisGraph.getLayer src + 1
    let edge = VisEdge (e.Type)
    edge.IsBackEdge <- e.IsBackEdge
    g.AddEdge src dummy edge |> ignore
    let backEdges =
      if edge.IsBackEdge then (dummy, src, edge) :: backEdges else backEdges
    let eData, vertices = Map.find k dummies
    let dummies = Map.add k (eData, dummy :: vertices) dummies
    addDummy g (backEdges, dummies) k dummy dst e (cnt - 1)

let chooseBackEdgesWithDummy (backEdges, withDummy) src dst edge =
  let delta = VisGraph.getLayer dst - VisGraph.getLayer src
  if delta > 1 then
    let backEdges =
      if (edge: VisEdge).IsBackEdge then
        List.filter (fun (_, _, e) -> e <> edge) backEdges
      else backEdges
    let withDummy = (src, dst, edge, delta) :: withDummy
    backEdges, withDummy
  else backEdges, withDummy

let addDummyNodes vGraph (backEdges, dummies) (src, dst, edge, delta) =
  (vGraph: VisGraph).RemoveEdge src dst |> ignore
  let k = if (edge: VisEdge).IsBackEdge then dst, src else src, dst
  let dummies = Map.add k (edge, []) dummies
  let backEdges, dummies =
    addDummy vGraph (backEdges, dummies) k src dst edge (delta - 1)
  let dummies =
    if edge.IsBackEdge then
      let eData, vertices = Map.find k dummies
      Map.add k (eData, List.rev vertices) dummies
    else dummies
  backEdges, dummies

let assignDummyNodes (vGraph: VisGraph) backEdgeList =
  let backEdgeList, withDummy =
    vGraph.FoldEdge (chooseBackEdgesWithDummy) (backEdgeList, [])
  withDummy
  |> List.fold (addDummyNodes vGraph) (backEdgeList, Map.empty)

let assignLayers vGraph backEdgeList =
  /// XXX: We'll make an option argument to select layer assignment algorithm
  /// longestPathAssignLayers vGraph
  /// promoteVertices vGraph root
  kahnAssignLayers vGraph
  assignDummyNodes vGraph backEdgeList
