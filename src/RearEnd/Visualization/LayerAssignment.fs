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

let assignLayerFromPred (vGraph: VisGraph) vData =
  let v = vGraph.FindVertexByData vData
  let preds = VisGraph.getPreds vGraph v
  if preds.Length = 0 then VisGraph.setLayer v 0
  else
    let maxLayer = (Seq.maxBy VisGraph.getLayer preds).VData.Layer
    VisGraph.setLayer v <| maxLayer + 1

let kahnAssignLayers (vGraph: VisGraph) =
  Traversal.DFS.foldRevPostorder vGraph (fun acc v -> v.VData :: acc) []
  |> List.rev
  |> List.iter (assignLayerFromPred vGraph)

let rec addDummy (g: VisGraph) (backEdges, dummies) k src dst (e: VisEdge) cnt =
  if cnt = 0 then
    let edge = VisEdge(e.Type)
    edge.IsBackEdge <- e.IsBackEdge
    g.AddEdge(src, dst, edge) |> ignore
    let backEdges =
      if edge.IsBackEdge then (dst, src, edge) :: backEdges
      else backEdges
    backEdges, dummies
  else
    let vNode = VisBBlock(src.VData, true)
    let dummy, _ = g.AddVertex vNode
    VisGraph.setLayer dummy <| VisGraph.getLayer src + 1
    let edge = VisEdge(e.Type)
    edge.IsBackEdge <- e.IsBackEdge
    g.AddEdge(src, dummy, edge) |> ignore
    let backEdges =
      if edge.IsBackEdge then (dummy, src, edge) :: backEdges
      else backEdges
    let eData, vertices = Map.find k dummies
    let dummies = Map.add k (eData, dummy :: vertices) dummies
    addDummy g (backEdges, dummies) k dummy dst e (cnt - 1)

let siftBackEdgesAndPickLongEdges (backEdges, longEdges) edge =
  let src, dst = (edge: Edge<_, VisEdge>).First, edge.Second
  let delta = VisGraph.getLayer dst - VisGraph.getLayer src
  if delta > 1 then
    (* Backedge in forward direction = Extra edge added in the cycle removal. *)
    let backEdges =
      if edge.Label.IsBackEdge then
        List.filter (fun (_, _, e) -> e <> edge.Label) backEdges
      else backEdges
    let longEdges = (src, dst, edge, delta) :: longEdges
    backEdges, longEdges
  else backEdges, longEdges

let addDummyNodes vGraph (backEdges, dummies) (src, dst, edge, delta) =
  (vGraph: VisGraph).RemoveEdge(src, dst) |> ignore
  let k =
    if (edge: Edge<_, VisEdge>).Label.IsBackEdge then dst, src
    else src, dst
  let dummies = Map.add k (edge.Label, []) dummies
  let backEdges, dummies =
    addDummy vGraph (backEdges, dummies) k src dst edge.Label (delta - 1)
  let dummies =
    if not edge.Label.IsBackEdge then
      let eData, vertices = Map.find k dummies
      Map.add k (eData, List.rev vertices) dummies
    else dummies
  backEdges, dummies

let assignDummyNodes (vGraph: VisGraph) backEdges =
  let backEdges, longEdges =
    vGraph.FoldEdge(siftBackEdgesAndPickLongEdges, (backEdges, []))
  longEdges
  |> List.fold (addDummyNodes vGraph) (backEdges, Map.empty)

/// Assign layers to each node. The root node should be layer zero (0).
let assignLayers vGraph backEdges =
  kahnAssignLayers vGraph
  assignDummyNodes vGraph backEdges
