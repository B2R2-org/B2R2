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

// The offset between starting points of two adjacent edges.
[<Literal>]
let private edgeOffsetX = 4.0

[<Literal>]
let private edgeOffsetY = 4.0

// The length of the last segment of an edge. This value should be at least less
// than the half of blockIntervalY.
[<Literal>]
let private lastSegLen = 20.0

let private restoreBackEdge (vGraph: VGraph) (src, dst, (edge: VEdge)) =
  match vGraph.TryFindEdge dst src with
  | Some eData ->
    if eData.IsBackEdge then
      vGraph.RemoveEdge dst src
      vGraph.AddEdge src dst edge
    else
      vGraph.AddEdge src dst edge
  | None ->
    // Self cycle case
    vGraph.AddEdge src dst edge

let private restoreBackEdges vGraph backEdgeList =
  List.iter (restoreBackEdge vGraph) backEdgeList

let private computeHeight layer vertices =
  let heights = Array.map VGraph.getHeight vertices
  Array.max heights

let private computeHPerLayer vLayout =
  Array.mapi computeHeight vLayout

let private computeEdgeEndOffset v length (i, offsetMap) w =
  let xOffset = float i * edgeOffsetX - float (length - 1) * edgeOffsetX / 2.0
  let yOffset =
    if VGraph.getXPos w < VGraph.getXPos v then
      float i * edgeOffsetY + lastSegLen
    elif VGraph.getXPos w > VGraph.getXPos v then
      float (length - i - 1) * edgeOffsetY + lastSegLen
    else
      lastSegLen
  if List.contains w v.Preds then
    i + 1, Map.add (w, v) (xOffset, yOffset) offsetMap
  else i + 1, Map.add (v, w) (xOffset, yOffset) offsetMap

let private computeEdgeEndOffsets (predOffsets, succOffsets) (v: Vertex<_>) =
  let preds = List.sortBy VGraph.getPos v.Preds |> List.toArray
  let succs = List.sortBy VGraph.getPos v.Succs |> List.toArray
  let _, predOffsets =
    Array.fold (computeEdgeEndOffset v (Array.length preds)) (0, predOffsets) preds
  let _, succOffsets =
    Array.fold (computeEdgeEndOffset v (Array.length succs)) (0, succOffsets) succs
  predOffsets, succOffsets

let private getLeftEnd l v =
  VGraph.getXPos v :: l

let private getRightEnd l v =
  VGraph.getXPos v + VGraph.getWidth v :: l

let private getBoundary (vGraph: VGraph) =
  let leftEnds = vGraph.FoldVertex getLeftEnd []
  let rightEnds = vGraph.FoldVertex getRightEnd []
  List.min leftEnds, List.max rightEnds

let private initializeLine pCoord pOff line =
  if List.isEmpty line then
    let pX, pY = pCoord
    let pOffX, pOffY = pOff
    (pX + pOffX, pY + pOffY) :: (pX + pOffX, pY) :: line
  else line

let private extendLine (hPerLayer: _ []) p pCoord pOff cCoord line =
  if VGraph.getIsDummy p && snd pCoord < snd cCoord then
    let pX, pY = pCoord
    let pOffX, pOffY = pOff
    (pX + pOffX, pY + hPerLayer.[VGraph.getLayer p] + pOffY) ::
      (pX + pOffX, pY - pOffY) :: line
  else line

let private extendBackEdgeLine p pCoord pOff c cCoord cOff line =
  let pX, pY = pCoord
  let pOffX, pOffY = pOff
  let pWidth = VGraph.getWidth p
  let cX, cY = cCoord
  let cOffX, cOffY = cOff
  let cWidth = VGraph.getWidth c
  let ratioX = 0.8
  if (pY > cY && not (VGraph.getIsDummy p)) then
    if pX < cX then
      let xEnd = max (pX + pOffX + pWidth / 2.0) (cX + cOffX + cWidth / 2.0)
      (xEnd, cY - cOffY) :: (xEnd, List.head line |> snd) :: line
    else
      let xEnd = min (pX + pOffX - pWidth / 2.0) (cX + cOffX + cWidth / 2.0)
      (xEnd, cY - cOffY) :: (xEnd, List.head line |> snd) :: line
  else line

let private buildJustBeforeLast pCoord c cCoord cOff line =
  let _, pY = pCoord
  let cX, cY = cCoord
  let cOffX, cOffY = cOff
  if not (VGraph.getIsDummy c) then
    let line =
      if pY > cY then (List.head line |> fst, cY - cOffY) :: line else line
    (cX + cOffX, cY) :: (cX + cOffX, cY - cOffY) :: line
  else line

let private buildLine hPerLayer p pOff c cOff line =
  let pCoord =
    VGraph.getXPos p + VGraph.getWidth p / 2.0, VGraph.getYPos p + VGraph.getHeight p
  let cCoord = VGraph.getXPos c + VGraph.getWidth c / 2.0, VGraph.getYPos c
  initializeLine pCoord pOff line
  |> extendLine hPerLayer p pCoord pOff cCoord
  |> extendBackEdgeLine p pCoord pOff c cCoord cOff
  |> buildJustBeforeLast pCoord c cCoord cOff

let private drawEdge (vGraph: VGraph) hPerLayer predOffsets succOffsets p c =
  let pOff = Map.find (p, c) succOffsets
  let cOff = Map.find (p, c) predOffsets
  let eData = vGraph.FindEdge p c
  let line = buildLine hPerLayer p pOff c cOff []
  eData.Points <- List.rev line

let rec private removeDummyLoop (vGraph: VGraph) src c points = function
  | p :: lst ->
    let eData = vGraph.FindEdge p c
    vGraph.RemoveEdge p c
    let newPoints = List.tail (List.tail eData.Points)
    removeDummyLoop vGraph src p (newPoints @ points) lst
  | [] ->
    let eData = vGraph.FindEdge src c
    vGraph.RemoveEdge src c
    eData.Points @ points

let private removeDummy (vGraph: VGraph) (src, dst) ((edge: VEdge), vertices) =
  let points = removeDummyLoop vGraph src dst [] vertices
  let newEdge = VEdge (edge.From, edge.To, edge.Type)
  newEdge.IsBackEdge <- edge.IsBackEdge
  newEdge.Points <- points
  vGraph.AddEdge src dst newEdge
  List.iter vGraph.RemoveVertex vertices

let private removeDummies (vGraph: VGraph) dummyMap =
  Map.iter (removeDummy vGraph) dummyMap

let drawEdges (vGraph: VGraph) vLayout backEdgeList dummyMap =
  restoreBackEdges vGraph backEdgeList
  let hPerLayer = computeHPerLayer vLayout
  let predOffsets, succOffsets =
    vGraph.FoldVertex computeEdgeEndOffsets (Map.empty, Map.empty)
  // let boundary = getBoundary vGraph
  vGraph.IterEdge (drawEdge vGraph hPerLayer predOffsets succOffsets)
  removeDummies vGraph dummyMap
