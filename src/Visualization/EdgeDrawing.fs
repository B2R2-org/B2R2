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

module internal B2R2.Visualization.EdgeDrawing

open B2R2.BinGraph

/// The X offset between starting points of two adjacent edges.
let [<Literal>] edgeOffsetX = 4.0

/// The Y offset between starting points of two adjacent edges.
let [<Literal>] edgeOffsetY = 4.0

/// The length of the last segment of an edge. This value should be at least
/// less than the half of blockIntervalY.
let [<Literal>] lastSegLen = 20.0

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

let computeEdgeEndOffsets (predOffsets, succOffsets) (v: Vertex<_>) =
  let preds = List.sortBy VisGraph.getIndex v.Preds |> List.toArray
  let succs = List.sortBy VisGraph.getIndex v.Succs |> List.toArray
  let _, predOffsets =
    Array.fold (computeEdgeEndOffset v (Array.length preds))
      (0, predOffsets) preds
  let _, succOffsets =
    Array.fold (computeEdgeEndOffset v (Array.length succs))
      (0, succOffsets) succs
  predOffsets, succOffsets

let getLeftEnd l v =
  VisGraph.getXPos v :: l

let getRightEnd l v =
  VisGraph.getXPos v + VisGraph.getWidth v :: l

let initializeLine pCoord pOff line =
  let pX, pY = pCoord
  let pOffX, pOffY = pOff
  (pX + pOffX, pY + pOffY) :: (pX + pOffX, pY) :: line

let extendLine (hPerLayer: _ []) p pCoord pOff cCoord line =
  if (p: Vertex<VisBBlock>).VData.IsDummyBlock ()
    && snd pCoord < snd cCoord then
    let pX, pY = pCoord
    let pOffX, pOffY = pOff
    (pX + pOffX, pY + hPerLayer.[VisGraph.getLayer p] + pOffY) ::
      (pX + pOffX, pY + pOffY) :: line
  else line

let extendBackEdgeLine p pCoord pOff c cCoord cOff line =
  let pX, pY = pCoord
  let pOffX, _ = pOff
  let pWidth = VisGraph.getWidth p
  let cX, cY = cCoord
  let cOffX, cOffY = cOff
  let cWidth = VisGraph.getWidth c
  if pY > cY && not ((p: Vertex<VisBBlock>).VData.IsDummyBlock ()) then
    if pX < cX then
      let xEnd = max (pX + pOffX + pWidth / 2.0) (cX + cOffX + cWidth / 2.0)
      (xEnd, cY - cOffY) :: (xEnd, List.head line |> snd) :: line
    else
      let xEnd = min (pX + pOffX - pWidth / 2.0) (cX + cOffX + cWidth / 2.0)
      (xEnd, cY - cOffY) :: (xEnd, List.head line |> snd) :: line
  else line

let buildJustBeforeLast pCoord c cCoord cOff line =
  let _, pY = pCoord
  let cX, cY = cCoord
  let cOffX, cOffY = cOff
  if not ((c: Vertex<VisBBlock>).VData.IsDummyBlock ()) then
    let line =
      if pY > cY then (List.head line |> fst, cY - cOffY) :: line else line
    (cX + cOffX, cY) :: (cX + cOffX, cY - cOffY) :: line
  else line

let buildLine hPerLayer p pOff c cOff =
  let pCoord =
    VisGraph.getXPos p + VisGraph.getWidth p / 2.0,
    VisGraph.getYPos p + VisGraph.getHeight p
  let cCoord =
    VisGraph.getXPos c + VisGraph.getWidth c / 2.0,
    VisGraph.getYPos c
  initializeLine pCoord pOff []
  |> extendLine hPerLayer p pCoord pOff cCoord
  |> extendBackEdgeLine p pCoord pOff c cCoord cOff
  |> buildJustBeforeLast pCoord c cCoord cOff

let drawEdge (vGraph: VisGraph) hPerLayer predOffsets succOffsets p c _ =
  let pOff = Map.find (p, c) succOffsets
  let cOff = Map.find (p, c) predOffsets
  let eData = vGraph.FindEdgeData p c
  let line = buildLine hPerLayer p pOff c cOff |> List.rev
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
  let predOffsets, succOffsets =
    vGraph.FoldVertex computeEdgeEndOffsets (Map.empty, Map.empty)
  vGraph.IterEdge (drawEdge vGraph hPerLayer predOffsets succOffsets)
  removeDummies vGraph dummyMap
