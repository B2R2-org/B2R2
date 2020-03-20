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

open B2R2
open B2R2.BinGraph

/// The X offset between starting points of two adjacent edges.
let [<Literal>] private edgeOffsetX = 4.0

/// The Y offset between starting points of two adjacent edges.
let [<Literal>] private edgeOffsetY = 4.0

/// The length of the last segment of an edge. This value should be at least
/// less than the half of blockIntervalY.
let [<Literal>] private lastSegLen = 20.0

/// The margin to prevent an overlap between a node and its back edges.
let [<Literal>] private backEdgeMargin = 10.0

let private restoreBackEdge (vGraph: VisGraph) (src, dst, (edge: VisEdge)) =
  match vGraph.TryFindEdge dst src with
  | Some eData ->
    if eData.IsBackEdge then
      vGraph.RemoveEdge dst src
      vGraph.AddEdge src dst edge
    else
      vGraph.AddEdge src dst edge
  | None ->
    vGraph.AddEdge src dst edge

let private restoreBackEdges vGraph backEdgeList =
  List.iter (restoreBackEdge vGraph) backEdgeList

let private computeHeight vertices =
  let heights = Array.map VisGraph.getHeight vertices
  Array.max heights

let private computeHeightPerLayer vLayout =
  Array.map computeHeight vLayout

let private computeEdgeEndOffset v neighbors map isPred =
  let len = Array.length neighbors
  neighbors
  |> Array.foldi (fun map idx neighbor ->
    let xOffset = float idx * edgeOffsetX - float (len - 1) * edgeOffsetX / 2.0
    let yOffset =
      if VisGraph.getXPos neighbor < VisGraph.getXPos v then
        float idx * edgeOffsetY + lastSegLen
      elif VisGraph.getXPos neighbor > VisGraph.getXPos v then
        float (len - idx - 1) * edgeOffsetY + lastSegLen
      else
        lastSegLen
    let key = if isPred then (neighbor, v) else (v, neighbor)
    Map.add key (xOffset, yOffset) map
    ) map
  |> fst

let private computeEdgeEndOffsets (predEndOffsets, succEndOffsets) v =
  let preds = List.sortBy VisGraph.getIndex (v: Vertex<_>).Preds |> List.toArray
  let succs = List.sortBy VisGraph.getIndex (v: Vertex<_>).Succs |> List.toArray
  computeEdgeEndOffset v preds predEndOffsets true,
  computeEdgeEndOffset v succs succEndOffsets false

let inline private goingUp pY cY = pY > cY

let inline private goingDown pY cY = pY < cY

let inline private goingRight pX cX = pX < cX

let inline private isDummy (v: Vertex<VisBBlock>) = v.VData.IsDummy

let private initializeLine p pX pY c cY (pEndOffX, pEndOffY) line =
  if goingUp pY cY && isDummy p then
    (pX + pEndOffX, pY + pEndOffY) :: line
  else
    (pX + pEndOffX, pY + pEndOffY) :: (pX + pEndOffX, pY) :: line

let private extendForward (hPerLayer: _ []) p pX pY _cX cY pEndOff line =
  if goingDown pY cY && isDummy p then
    let pEndOffX, pEndOffY = pEndOff
    let x, y = pX + pEndOffX, pY + pEndOffY
    (x, y + hPerLayer.[VisGraph.getLayer p]) :: (x, y) :: line
  else line

let inline private computeHorizontalX v vX vEndOffX toRight =
  let width = VisGraph.getWidth v
  if toRight then
    vX + vEndOffX + width / 2.0 + backEdgeMargin
  else
    vX + vEndOffX - width / 2.0 - backEdgeMargin

let private extendHorizontallyForParent p pX pEndOff cX line =
  let pEndOffX, _ = pEndOff
  let _, prevY = List.head line
  if (pX = cX && pEndOffX > 0.0) || goingRight pX cX then
    (computeHorizontalX p pX pEndOffX true, prevY) :: line
  else
    (computeHorizontalX p pX pEndOffX false, prevY) :: line

let private extendHorizontallyForChild pX c cX cEndOff line =
  let cEndOffX, cEndOffY = cEndOff
  let _, prevY = List.head line
  if goingRight pX cX then
    (computeHorizontalX c cX cEndOffX false, prevY + cEndOffY) :: line
  else
    (computeHorizontalX c cX cEndOffX true, prevY + cEndOffY) :: line

let private extendBackward hPerLayer p pX pY pEndOff c cX cY cEndOff line =
  if goingUp pY cY then
    if not (isDummy p) then
      let line = extendHorizontallyForParent p pX pEndOff cX line
      let prevX, _ = List.head line
      let height = (hPerLayer: float []).[VisGraph.getLayer p]
      (prevX, pY - height - backEdgeMargin) :: line
    elif not (isDummy c) then
      let line = extendHorizontallyForChild pX c cX cEndOff line
      let prevX, _ = List.head line
      let height = hPerLayer.[VisGraph.getLayer c]
      (prevX, cY + height + backEdgeMargin) :: line
    else line
  else line

let private finalizeLine p pX pY c cX cY (cEndOffX, cEndOffY) line =
  if isDummy c then line
  else
    let lastX, seLastY = cX + cEndOffX, cY - cEndOffY
    [
      yield (lastX, cY)
      yield (lastX, seLastY)
      if goingUp pY cY then
        let extX = computeHorizontalX c cX cEndOffX (not (goingRight pX cX))
        if p = c then yield (lastX, cY); yield (lastX, seLastY); yield! line
        elif not (isDummy p) then
          let prevY = List.head line |> snd
          yield (extX, seLastY); yield (extX, prevY); yield! line
        else yield (extX, seLastY); yield! line
      else yield! line
    ]

let private buildLine hPerLayer p pEndOff c cEndOff =
  let pX = VisGraph.getXPos p + VisGraph.getWidth p / 2.0
  let pY = VisGraph.getYPos p + VisGraph.getHeight p
  let cX = VisGraph.getXPos c + VisGraph.getWidth c / 2.0
  let cY = VisGraph.getYPos c
  initializeLine p pX pY c cY pEndOff []
  |> extendForward hPerLayer p pX pY cX cY pEndOff
  |> extendBackward hPerLayer p pX pY pEndOff c cX cY cEndOff
  |> finalizeLine p pX pY c cX cY cEndOff

let private drawEdge vGraph hPerLayer predEndOffsets succEndOffsets p c _ =
  let pEndOff = Map.find (p, c) succEndOffsets
  let cEndOff = Map.find (p, c) predEndOffsets
  let eData = (vGraph: VisGraph).FindEdgeData p c
  let line = buildLine hPerLayer p pEndOff c cEndOff |> List.rev
  eData.Points <- line |> List.map (fun (x,y) -> { X = x; Y = y })

let rec private removeDummyLoop (vGraph: VisGraph) src c points = function
  | p :: lst ->
    let eData = vGraph.FindEdgeData p c
    vGraph.RemoveEdge p c
    removeDummyLoop vGraph src p (eData.Points @ points) lst
  | [] ->
    let eData = vGraph.FindEdgeData src c
    vGraph.RemoveEdge src c
    eData.Points @ points

let private makeSmooth isBack points =
  let rec loop acc prev = function
    | [] -> acc
    | h1 :: h2 :: [] -> List.rev (h2 :: h1 :: acc)
    | (hd: VisPosition) :: tl ->
      match prev with
      | None -> loop (hd :: acc) (Some hd.Y) tl
      | Some p ->
        if (isBack && p >= hd.Y) || (not isBack && p <= hd.Y) then
          loop (hd :: acc) (Some hd.Y) tl
        else loop acc prev tl
  match points with
  | hd1 :: hd2 :: rest ->
    hd1 :: hd2 :: loop [] None rest
  | _ -> points

let private removeDummy vGraph (src, dst) ((edge: VisEdge), dummies) =
  let points =
    removeDummyLoop vGraph src dst [] dummies |> makeSmooth edge.IsBackEdge
  let newEdge = VisEdge (edge.Type)
  newEdge.IsBackEdge <- edge.IsBackEdge
  newEdge.Points <- points
  vGraph.AddEdge src dst newEdge
  List.iter vGraph.RemoveVertex dummies

let private removeDummies (vGraph: VisGraph) dummyMap =
  Map.iter (removeDummy vGraph) dummyMap

let drawEdges (vGraph: VisGraph) vLayout backEdgeList dummyMap =
  restoreBackEdges vGraph backEdgeList
  let hPerLayer = computeHeightPerLayer vLayout
  let predEndOffsets, succEndOffsets =
    vGraph.FoldVertex computeEdgeEndOffsets (Map.empty, Map.empty)
  vGraph.IterEdge (drawEdge vGraph hPerLayer predEndOffsets succEndOffsets)
  removeDummies vGraph dummyMap
