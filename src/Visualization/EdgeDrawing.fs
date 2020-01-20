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

module internal B2R2.Visualization.EdgeDrawing

open B2R2.BinGraph

/// The X offset between starting points of two adjacent edges.
let [<Literal>] edgeOffsetX = 4.0

/// The Y offset between starting points of two adjacent edges.
let [<Literal>] edgeOffsetY = 4.0

/// The length of the last segment of an edge. This value should be at least
/// less than the half of blockIntervalY.
let [<Literal>] lastSegLen = 20.0

/// The margin to prevent an overlap between a node and its back edges.
let [<Literal>] backEdgeMargin = 10.0

let restoreBackEdge (vGraph: VisGraph) (src, dst, (edge: VisEdge)) =
  match vGraph.TryFindEdge dst src with
  | Some eData ->
    if eData.IsBackEdge then
      vGraph.RemoveEdge dst src
      vGraph.AddEdge src dst edge
    else
      vGraph.AddEdge src dst edge
  | None ->
    vGraph.AddEdge src dst edge

let restoreBackEdges vGraph backEdgeList =
  List.iter (restoreBackEdge vGraph) backEdgeList

let computeHeight vertices =
  let heights = Array.map VisGraph.getHeight vertices
  Array.max heights

let computeHPerLayer vLayout =
  Array.map computeHeight vLayout

let computeEdgeEndOffset v length (i, offsetMap) w =
  let xOffset = float i * edgeOffsetX - float (length - 1) * edgeOffsetX / 2.0
  let yOffset =
    if VisGraph.getXPos w < VisGraph.getXPos v then
      float i * edgeOffsetY + lastSegLen
    elif VisGraph.getXPos w > VisGraph.getXPos v then
      float (length - i - 1) * edgeOffsetY + lastSegLen
    else
      lastSegLen
  if List.contains w v.Preds then
    i + 1, Map.add (w, v) (xOffset, yOffset) offsetMap
  else i + 1, Map.add (v, w) (xOffset, yOffset) offsetMap

let computeEdgeEndOffsets (predEndOffsets, succEndOffsets) (v: Vertex<_>) =
  let preds = List.sortBy VisGraph.getIndex v.Preds |> List.toArray
  let succs = List.sortBy VisGraph.getIndex v.Succs |> List.toArray
  let _, predEndOffsets =
    Array.fold (computeEdgeEndOffset v (Array.length preds))
      (0, predEndOffsets) preds
  let _, succEndOffsets =
    Array.fold (computeEdgeEndOffset v (Array.length succs))
      (0, succEndOffsets) succs
  predEndOffsets, succEndOffsets

let getLeftEnd l v =
  VisGraph.getXPos v :: l

let getRightEnd l v =
  VisGraph.getXPos v + VisGraph.getWidth v :: l

let initializeLine pCoord pEndOff line =
  let pX, pY = pCoord
  let pEndOffX, pEndOffY = pEndOff
  (pX + pEndOffX, pY + pEndOffY) :: (pX + pEndOffX, pY) :: line

let extendLine (hPerLayer: _ []) p pCoord pEndOff cCoord line =
  if (p: Vertex<VisBBlock>).VData.IsDummy && snd pCoord < snd cCoord then
    let pX, pY = pCoord
    let pEndOffX, pEndOffY = pEndOff
    (pX + pEndOffX, pY + hPerLayer.[VisGraph.getLayer p] + pEndOffY)
    :: (pX + pEndOffX, pY + pEndOffY)
    :: line
  else line

let extendBackEdgeLine p pCoord pEndOff cCoord cEndOff line =
  let pX, pY = pCoord
  let pEndOffX, _ = pEndOff
  let pWidth = VisGraph.getWidth p
  let cX, cY = cCoord
  let cEndOffX, cEndOffY = cEndOff
  if pY > cY && not ((p: Vertex<VisBBlock>).VData.IsDummy) then
    if pX < cX then (* child is on the right *)
      let xEnd =
        max (pX + pWidth / 2.0 + pEndOffX + backEdgeMargin) (cX + cEndOffX)
      (xEnd, cY - cEndOffY) :: (xEnd, List.head line |> snd) :: line
    else (* child is on the left *)
      let xEnd =
        min (pX - pWidth / 2.0 + pEndOffX - backEdgeMargin) (cX + cEndOffX)
      (xEnd, cY - cEndOffY) :: (xEnd, List.head line |> snd) :: line
  else line

let buildJustBeforeLast pCoord c cCoord cEndOff line =
  let _, pY = pCoord
  let cX, cY = cCoord
  let cEndOffX, cEndOffY = cEndOff
  if not ((c: Vertex<VisBBlock>).VData.IsDummy) then
    let line =
      if pY > cY then (* back edge case. *)
        (List.head line |> fst, cY - cEndOffY) :: line
      else line
    (cX + cEndOffX, cY) :: (cX + cEndOffX, cY - cEndOffY) :: line
  else line

let buildLine hPerLayer p pEndOff c cEndOff =
  let pCoord =
    VisGraph.getXPos p + VisGraph.getWidth p / 2.0,
    VisGraph.getYPos p + VisGraph.getHeight p
  let cCoord =
    VisGraph.getXPos c + VisGraph.getWidth c / 2.0,
    VisGraph.getYPos c
  initializeLine pCoord pEndOff []
  |> extendLine hPerLayer p pCoord pEndOff cCoord
  |> extendBackEdgeLine p pCoord pEndOff cCoord cEndOff
  |> buildJustBeforeLast pCoord c cCoord cEndOff

let drawEdge (vGraph: VisGraph) hPerLayer predEndOffsets succEndOffsets p c _ =
  let pEndOff = Map.find (p, c) succEndOffsets
  let cEndOff = Map.find (p, c) predEndOffsets
  let eData = vGraph.FindEdgeData p c
  let line = buildLine hPerLayer p pEndOff c cEndOff |> List.rev
  eData.Points <- line |> List.map (fun (x,y) -> { X = x; Y = y })

let rec removeDummyLoop (vGraph: VisGraph) src c points = function
  | p :: lst ->
    let eData = vGraph.FindEdgeData p c
    vGraph.RemoveEdge p c
    let newPoints = List.tail (List.tail eData.Points)
    removeDummyLoop vGraph src p (newPoints @ points) lst
  | [] ->
    let eData = vGraph.FindEdgeData src c
    vGraph.RemoveEdge src c
    eData.Points @ points

let removeDummy (vGraph: VisGraph) (src, dst) ((edge: VisEdge), vertices) =
  let points = removeDummyLoop vGraph src dst [] vertices
  let newEdge = VisEdge (edge.Type)
  newEdge.IsBackEdge <- edge.IsBackEdge
  newEdge.Points <- points
  vGraph.AddEdge src dst newEdge
  List.iter vGraph.RemoveVertex vertices

let removeDummies (vGraph: VisGraph) dummyMap =
  Map.iter (removeDummy vGraph) dummyMap

let getBoundary (vGraph: VisGraph) =
  let leftEnds = vGraph.FoldVertex getLeftEnd []
  let rightEnds = vGraph.FoldVertex getRightEnd []
  List.min leftEnds, List.max rightEnds

let drawEdges (vGraph: VisGraph) vLayout backEdgeList dummyMap =
  restoreBackEdges vGraph backEdgeList
  let hPerLayer = computeHPerLayer vLayout
  let predEndOffsets, succEndOffsets =
    vGraph.FoldVertex computeEdgeEndOffsets (Map.empty, Map.empty)
  vGraph.IterEdge (drawEdge vGraph hPerLayer predEndOffsets succEndOffsets)
  removeDummies vGraph dummyMap
