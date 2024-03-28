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

/// A modified version of Gasner et al.
module internal B2R2.RearEnd.Visualization.EdgeDrawing

open B2R2
open B2R2.MiddleEnd.BinGraph

/// Very simple Box record consisting of four corner points.
type private Box = {
  TopLeft: VisPosition
  TopRight: VisPosition
  BottomLeft: VisPosition
  BottomRight: VisPosition
  IsVirtual: bool
}

/// An intersecting line between two boxes.
type private Line = {
  Left: VisPosition
  Right: VisPosition
}

/// Categorized edges.
type private PartitionedEdges = {
  ForwardEdges: VisEdge list
  BackEdgesFromLeft: VisEdge list
  BackEdgesFromRight: VisEdge list
  SelfLoops: VisEdge list
}

let private emptyPartitionedEdges =
  { ForwardEdges = []
    BackEdgesFromLeft = []
    BackEdgesFromRight = []
    SelfLoops = [] }

/// The X offset between starting points of two adjacent edges.
let [<Literal>] private EdgeOffsetX = 4.0

/// The Y offset between starting points of two adjacent edges.
let [<Literal>] private EdgeOffsetY = 4.0

/// The length of the last segment of an edge. This value should be at least
/// less than the half of blockIntervalY.
let [<Literal>] private LastSegLen = 20.0

/// An offset from a node to the surrounding box. This is to give some margin
/// for the box.
let [<Literal>] private NodeBoxOffset = 20.0

/// The margin to prevent an overlap between a node and its back edges.
let [<Literal>] private BackEdgeMargin = 10.0

/// A margin for deciding line fitness.
let [<Literal>] private FitErrorMargin = 1.0

/// If the number of incoming/outgoing edges of a layer exceeds this threshold,
/// then we expand the layer's height.
let [<Literal>] private LayerHeightExpansionThreshold = 15

let inline private isDummy (v: IVertex<VisBBlock>) = v.VData.IsDummy

let private restoreBackEdge (g: VisGraph) (src, dst, edge: VisEdge) =
  match g.TryFindEdge (dst, src) with
  | Some e when e.Label.IsBackEdge -> g.RemoveEdge (dst, src) |> ignore
  | _ -> ()
  g.AddEdge (src, dst, edge) |> ignore

let private restoreBackEdges g backEdgeList =
  List.iter (restoreBackEdge g) backEdgeList

/// Compute the original destination vertex, given dummy source node src.
let rec private getOriginalDst (g: IGraph<_, _>) (v: IVertex<VisBBlock>) =
  if isDummy v then
    let succs = g.GetSuccs v
    getOriginalDst g (Seq.head succs)
  else v

/// Given src is original, add original edge to acc.
let private accOriginalEdge g acc (edge: Edge<_, VisEdge>) =
  let src, dst = edge.First, edge.Second
  if isDummy src then acc
  elif isDummy dst then (src, getOriginalDst g dst, edge.Label) :: acc
  else (src, dst, edge.Label) :: acc

/// Sort vertices by the x-coordinates.
let private sortLayers vLayout =
  vLayout |> Array.map (fun layer ->
    Array.sortBy (fun v -> (VisGraph.getXPos v)) layer)

let private countDegree edges (getter: _ -> IVertex<VisBBlock>) v =
  edges
  |> List.fold (fun cnt e -> if getter e = v then cnt + 1 else cnt) 0

let private getMaxDegree edges getter layer =
  layer
  |> Array.map (countDegree edges getter)
  |> Array.max

let private downShiftLayers layers degree =
  Array.iter (Array.iter (fun (v: IVertex<VisBBlock>) ->
    let blk = v.VData
    let newY = blk.Coordinate.Y + EdgeOffsetY * float degree
    blk.Coordinate.Y <- newY)) layers

let rec private adjustLayers isIncoming layerNum vLayout = function
  | [] -> ()
  | degree :: tl ->
    if degree >= LayerHeightExpansionThreshold then
      let shiftStart = if isIncoming then layerNum else layerNum + 1
      if shiftStart < Array.length vLayout then
        downShiftLayers vLayout[ shiftStart .. ] degree
      else ()
    else ()
    adjustLayers isIncoming (layerNum + 1) vLayout tl

/// Expand a layer's height if it contains excessive number of incoming/outgoing
/// edges.
let private adjustLayerYPositions edges vLayout =
  let maxIncomingDegrees =
    vLayout |> Array.map (getMaxDegree edges Utils.sndOfTriple) |> Array.toList
  let maxOutgoingDegrees =
    vLayout |> Array.map (getMaxDegree edges Utils.fstOfTriple) |> Array.toList
  adjustLayers true 0 vLayout maxIncomingDegrees
  adjustLayers false 0 vLayout maxOutgoingDegrees

let private getEntryPoint (v: IVertex<VisBBlock>) =
  let x, y = VisGraph.getXPos v, VisGraph.getYPos v
  (x + VisGraph.getWidth v / 2.0), (y + VisGraph.getHeight v)

let private getExitPoint (v: IVertex<VisBBlock>) =
  let x, y = VisGraph.getXPos v, VisGraph.getYPos v
  (x + VisGraph.getWidth v / 2.0), y

let private makeVisPos (x, y): VisPosition = { X = x; Y = y }

let private makeBox left right top bottom isVirtual =
  { TopLeft = makeVisPos (left, top);
    TopRight = makeVisPos (right, top);
    BottomLeft = makeVisPos (left, bottom);
    BottomRight = makeVisPos (right, bottom);
    IsVirtual = isVirtual }

let private makeDummyBox () = makeBox 0.0 0.0 0.0 0.0 true

/// Convert a Vertex into a Box.
let private vertexToBox (v: IVertex<VisBBlock>): Box =
  let left = VisGraph.getXPos v - if (isDummy v) then 0.0 else NodeBoxOffset
  let right =
    (VisGraph.getXPos v + VisGraph.getWidth v
    * if (isDummy v) then 0.5 else 1.0)
    + if (isDummy v) then 0.0 else NodeBoxOffset
  let top = VisGraph.getYPos v - NodeBoxOffset
  let bottom = (VisGraph.getYPos v + VisGraph.getHeight v) + NodeBoxOffset
  makeBox left right top bottom (isDummy v)

/// Converts vertex arrays to Box arrays.
let private verticesToBoxes1D vertices =
  Array.map vertexToBox vertices

let private verticesToBoxes2D vLayout =
  Array.map verticesToBoxes1D vLayout

let private makeLine left right y =
  { Left = makeVisPos (left, y); Right = makeVisPos (right, y) }

let private makeDummyLine () =
  { Left = makeVisPos (-10000.0, 0.0); Right = makeVisPos (-10000.0, 0.0) }

/// Get intersection line segment between two neighbouring boxes.
let private getIntersection upper lower =
  let upperBottom, lowerTop = upper.BottomLeft.Y, lower.TopLeft.Y
  if int upperBottom <> int lowerTop then makeDummyLine ()
  else
    let left = max (upper.BottomLeft.X) (lower.TopLeft.X)
    let right = min (upper.BottomRight.X) (lower.BottomRight.X)
    makeLine left right upperBottom

let private getIntersectingLines boxes =
  let rec aux acc (hd: Box) (tl: Box list)  =
    match tl with
    | [] ->
      List.rev ((makeLine hd.TopLeft.X hd.TopRight.X hd.BottomLeft.Y) :: acc)
    | th :: tt -> aux ((getIntersection hd th) :: acc) th tt
  match boxes with
  | hd :: tl ->
    (makeLine hd.TopLeft.X hd.TopRight.X hd.TopLeft.Y) :: (aux [] hd tl)
  | _ -> Utils.impossible ()

let private getBasicComponents (vLayout: _[][]) (boxes: _[][]) v =
  let layer = VisGraph.getLayer (v: IVertex<VisBBlock>)
  let nth = Array.findIndex ((=) v) vLayout[layer]
  let boxarr = boxes[layer]
  let box: Box = boxes[layer][nth]
  struct (layer, boxarr, box)

let private computeLayerDiff q r =
  abs (VisGraph.getLayer r - VisGraph.getLayer q)

let private findDummies q r (edge: VisEdge) dummyMap =
  match (Map.tryFind (q, r) dummyMap) with
  | Some (_, dummies) ->
    if edge.IsBackEdge then List.rev dummies, false
    else dummies, false
  | None ->
    if not edge.IsBackEdge || (computeLayerDiff q r) = 1 then [], false
    else (* Dummy node deleted. Refer to existing forward edge. *)
      match Map.tryFind (r, q) dummyMap with
      | Some (_, dummies) -> dummies, true
      | None -> [], false

let private computeBoxHeight (box: Box) =
  box.BottomLeft.Y - box.TopLeft.Y

let private computeLayerHeight layer =
  Array.map computeBoxHeight layer |> Array.max

let private computeHeightPerLayer boxes =
  Array.map computeLayerHeight boxes

/// Computes starting and ending y-coordinates for each layer.
let private computeYPositionsPerLayer boxes =
  let heights = computeHeightPerLayer boxes
  let starts = Array.map (fun (layer: Box []) -> layer[0].TopLeft.Y) boxes
  let ends = Array.map2 (+) starts heights
  Array.map2 (fun x y -> (x, y)) starts ends

/// Given vertex boxes, return two x-coordinates defining the width line of the
/// graph.
let private computeWidthLine boxes =
   let lefts = Array.map (Array.map (fun b -> b.TopLeft.X)) boxes
   let rights = Array.map (Array.map (fun b -> b.TopRight.X)) boxes
   let leftmost = Array.min (Array.concat lefts)
   let rightmost = Array.max (Array.concat rights)
   leftmost, rightmost

/// Return a list of layers between q (qLayer) and r (rLayer).
let getLayersBetween (dummies: IVertex<VisBBlock> list) qLayer rLayer =
  if dummies.IsEmpty then [ (min qLayer rLayer) ]
  else [ (min qLayer rLayer) .. (max qLayer rLayer) - 1 ]

/// Assume leftBox is on the left of rightBox, check if those two boxes overlap.
let private boxesOverlapping leftBox rightBox =
  let left1, right1 = leftBox.TopLeft.X, leftBox.TopRight.X
  let left2, _ = rightBox.TopLeft.X, rightBox.TopRight.X
  left2 >= left1 && left2 <= right1

let rec private getBoxLeftBound reference index (boxarr: Box []) widthLine =
  match index with
  | i when i < 0 -> fst widthLine
  | i ->
    if not (boxesOverlapping boxarr[i] boxarr[reference])
      || (reference <> i && not (boxarr[i].IsVirtual))
    then boxarr[i].TopRight.X
    else getBoxLeftBound reference (i - 1) boxarr widthLine

let rec private getBoxRightBound reference index (boxarr: Box []) widthLine =
  match index with
  | i when i > (Array.length boxarr) - 1 -> snd widthLine
  | i ->
    if not (boxesOverlapping boxarr[reference] boxarr[i])
      || (reference <> i && not (boxarr[i].IsVirtual))
    then boxarr[i].TopLeft.X
    else getBoxRightBound reference (i + 1) boxarr widthLine

let private initialBox box (boxarr: Box []) widthLine (_, bottom) =
  let idx = Array.findIndex ((=) box) boxarr
  let left = getBoxLeftBound idx idx boxarr widthLine
  let right = getBoxRightBound idx idx boxarr widthLine
  let top = box.BottomLeft.Y
  makeBox left right top bottom true

/// Computes an inter-layer Box right under given layerNum.
let private interLayerBox yPositions (left, right) layerNum =
  if layerNum >= Array.length yPositions - 1 then makeDummyBox ()
  else
    let top = yPositions[layerNum] |> snd
    let bottom = yPositions[layerNum + 1] |> fst
    makeBox left right top bottom true

/// Computes a box corresponding to a particular dummy node.
let private virtualNodeBox boxes widthLine (yPositions: _ []) shrinkBox dummy =
  let dBox = dummy |> vertexToBox
  let dRow = Array.findIndex (Array.contains dBox) boxes
  let boxarr = boxes[dRow]
  let dCol = Array.findIndex ((=) dBox) boxarr
  let left = getBoxLeftBound dCol dCol boxarr widthLine
  let right = getBoxRightBound dCol dCol boxarr widthLine
  let top = yPositions[dRow] |> fst
  let bottom = yPositions[dRow] |> snd
  let delta = (right - left) / 3.0
  if shrinkBox then makeBox (left + delta) (right - delta) top bottom true
  else makeBox left right top bottom true

let private nodeIsLeft (q: IVertex<VisBBlock>) (r: IVertex<VisBBlock>) =
  let qx, rx = VisGraph.getXPos q, VisGraph.getXPos r
  qx + 1.5 * (VisGraph.getWidth q) < rx

let private centerX (box: Box) =
  box.TopLeft.X + (box.TopRight.X - box.TopLeft.X) / 2.0

let private boxIsLeft b1 b2 = centerX b1 < centerX b2

/// Compute tuple of (distance between q-r line and the line segment, left
/// endpoint is closer or not).
let private lineFits (q: VisPosition) (r: VisPosition) line =
  let left, right = line.Left, line.Right
  let qx, qy, rx, ry = q.X, q.Y, r.X, r.Y
  let dy = (ry - qy)
  let m = (rx - qx) / dy
  let x = qx + m * (left.Y - qy)
  let xFits = (x >= left.X - FitErrorMargin && x <= right.X + FitErrorMargin)
  if xFits || (abs dy) < 0.1 then (-1, false)
  else
    if x < left.X then abs (int (x - left.X)), true
    else abs (int (x - right.X)), false

let private getLineFitArray lArray (q: VisPosition) (r: VisPosition) =
  Array.map (lineFits q r) lArray

let rec private computePList (interLines: Line array) q r =
  let fitTupleArray = getLineFitArray interLines q r
  let furthestLineIndex =
    fitTupleArray
    |> Array.mapi (fun i v -> i, v)
    |> Array.maxBy (fun (_, (dist, _)) -> dist)
    |> fst
  let farthestDist, isAtLeft = fitTupleArray[furthestLineIndex]
  let splitLine = interLines[furthestLineIndex]
  if farthestDist > 0 then
    let p = if isAtLeft then splitLine.Left else splitLine.Right
    let slice1 = interLines[ .. furthestLineIndex ]
    let slice2 = interLines[ furthestLineIndex .. ]
    let segment1 = (computePList slice1 q p)
    let segment2 = (computePList slice2 p r)
    segment1 @ (p :: segment2)
  else []

let private computeRegularEdgePoints isBackEdge dummies boxes q r qBox rBox =
  let intersectingLines = getIntersectingLines boxes
  let tailQ, headR = getEntryPoint q, getExitPoint r (* Key points *)
  let q1 = makeVisPos tailQ
  let q2 = { q1 with Y = q1.Y + NodeBoxOffset }
  let r1 = makeVisPos headR
  let r2 = { r1 with Y = r1.Y - NodeBoxOffset }
  let qWidth = VisGraph.getWidth q
  if isBackEdge then
    let dummyBoxes = dummies |> Array.ofList |> Array.map vertexToBox
    let n = Array.length dummyBoxes
    let departLeft, arriveLeft =
      if n < 1 then nodeIsLeft r q, nodeIsLeft q r
      else boxIsLeft dummyBoxes[ n - 1 ] qBox, boxIsLeft dummyBoxes[0] rBox
    let q3 =
      { q2 with X = q2.X + 0.55 * qWidth * if departLeft then -1.0 else 1.0 }
    let r3 =
      { r2 with X = r2.X + 0.55 * qWidth * if arriveLeft then -1.0 else 1.0 }
    let q4 = { q3 with Y = qBox.TopLeft.Y }
    let r4 = { r3 with Y = rBox.BottomLeft.Y }
    [ q1; q2; q3; q4
      yield! (computePList (Array.ofList intersectingLines) r4 q4 |> List.rev)
      r4; r3; r2; r1 ]
  else
    [ q1; q2
      yield! (computePList (intersectingLines |> Array.ofList) q2 r2)
      r2; r1 ]

/// Draw a regular edge from q to r.
let private drawRegular g vLayout boxes dummyMap (q, r, edge: VisEdge) =
  let isBackEdge = edge.IsBackEdge
  let struct (qLayer, qBoxArr, qBox) = getBasicComponents vLayout boxes q
  let struct (rLayer, rBoxArr, rBox) = getBasicComponents vLayout boxes r
  let dummies, isRecovered = findDummies q r edge dummyMap
  let yPositions = computeYPositionsPerLayer boxes
  let wLine = computeWidthLine boxes
  let interLayers = getLayersBetween dummies qLayer rLayer
  let initBox =
    if isBackEdge then initialBox rBox rBoxArr wLine yPositions[rLayer]
    else initialBox qBox qBoxArr wLine yPositions[qLayer]
  let interLayerBoxes = List.map (interLayerBox yPositions wLine) interLayers
  let virtualNodeBoxes =
    List.map (virtualNodeBox boxes wLine yPositions isRecovered) dummies
  let boxes = (* Boxes between nodes q and r, from upper layer to lower *)
    initBox ::
    ((List.fold2 (fun acc v i ->  i :: v :: acc) [interLayerBoxes.Head]
        virtualNodeBoxes interLayerBoxes.Tail) |> List.rev)
  let points = computeRegularEdgePoints isBackEdge dummies boxes q r qBox rBox
  match (g: VisGraph).TryFindEdge (q, r) with
  | None -> (* Imaginary edges for display purposes only *)
    let newEdge = VisEdge (edge.Type)
    newEdge.IsBackEdge <- isBackEdge
    newEdge.Points <- points
    g.AddEdge (q, r, newEdge) |> ignore
  | Some e -> e.Label.Points <- points

let private drawSelfLoop g (v: IVertex<VisBBlock>) =
  let nodeWidth = VisGraph.getWidth v
  let e = (g: VisGraph).FindEdge (v, v)
  let startP, endP = getEntryPoint v, getExitPoint v
  let p1 = (fst startP), (snd startP + LastSegLen)
  let p2 = ((fst p1) + nodeWidth / 2.0 + BackEdgeMargin), (snd p1)
  let p3 = (fst p2), (snd endP) - LastSegLen
  let p4 = (fst endP), snd p3
  let points = [ startP;  p1;  p2;  p3; p4; endP ] |> List.map makeVisPos
  e.Label.Points <- points

let private drawBoxes g vLayout boxes dummyMap (src, dst, edge) =
  if isDummy src || isDummy dst then ()
  elif src = dst then drawSelfLoop g src
  else drawRegular g vLayout boxes dummyMap (src, dst, edge)

let rec private removeDummyLoop (g: VisGraph) src dst points = function
  | dummy :: rest ->
    let e = g.FindEdge (src, dummy)
    g.RemoveEdge (src, dummy) |> ignore
    removeDummyLoop g dummy dst (points @ e.Label.Points) rest
  | [] ->
    let e = g.FindEdge (src, dst)
    g.RemoveEdge (src, dst) |> ignore
    points @ e.Label.Points

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
  | hd1 :: hd2 :: rest -> hd1 :: hd2 :: loop [] None rest
  | _ -> points

let private removeDummy g (src, dst) ((edge: VisEdge), dummies) =
  let pts = removeDummyLoop g src dst [] dummies |> makeSmooth edge.IsBackEdge
  let newEdge = VisEdge (edge.Type)
  newEdge.IsBackEdge <- edge.IsBackEdge
  newEdge.Points <- pts
  g.AddEdge (src, dst, newEdge) |> ignore
  dummies |> List.iter (g.RemoveVertex >> ignore)

let private categorizeEdge isHeadPort acc (q, r, edge: Edge<_, VisEdge>) =
  let edge = edge.Label
  let points = edge.Points |> Array.ofList
  let n = Array.length points
  if n < 4 then acc
  else
    if q = r then { acc with SelfLoops = edge :: acc.SelfLoops }
    elif edge.IsBackEdge then
      let p1Index, p2Index = if isHeadPort then n - 2, n - 3 else 1, 2
      if points[p2Index].X < points[p1Index].X then
        { acc with BackEdgesFromLeft = edge :: acc.BackEdgesFromLeft }
      else { acc with BackEdgesFromRight  = edge :: acc.BackEdgesFromRight }
    else { acc with ForwardEdges = edge :: acc.ForwardEdges }

/// Compute the slope of the given vector q -> r under an assumption: the vector
/// always directed downwards (q.Y < r.Y).
let private computeSlope (q: VisPosition) (r: VisPosition) =
  let qx, qy, rx, ry = q.X, q.Y, r.X, r.Y
  let dy = (ry - qy)
  if abs dy < 0.1 then (* Approximately horizontal line. *)
    if qx < rx then infinity else -infinity
  else (* Non-horizontal slope. *) (rx - qx) / dy

let private getEdgeSlope isBackEdge isHeadPort (edge: VisEdge) =
  let points = edge.Points |> Array.ofList
  let n = Array.length points
  let qIndex, rIndex =
    match isBackEdge, isHeadPort with
    | true, true -> n - 4, n - 5
    | true, false -> 4, 3
    | false, true -> n - 3, n - 2
    | false, false -> 1, 2
  computeSlope points[qIndex] points[rIndex]

let private sortPartitions isHead descending p =
  let sort = if descending then List.sortByDescending else List.sortBy
  { ForwardEdges = sort (getEdgeSlope false isHead) p.ForwardEdges
    BackEdgesFromLeft = sort (getEdgeSlope true isHead) p.BackEdgesFromLeft
    BackEdgesFromRight = sort (getEdgeSlope true isHead) p.BackEdgesFromRight
    SelfLoops = sort (getEdgeSlope true isHead) p.SelfLoops }

let rec private shiftHorizontally toLeft (edges: VisEdge list) offset =
  match edges with
  | [] -> ()
  | edge :: rest ->
    let points = edge.Points |> Array.ofList
    let n = Array.length points
    points[ n - 3 ].X <- points[ n - 3 ].X + offset
    points[ n - 4 ].X <- points[ n - 4 ].X + offset
    let nextOffset = offset + if toLeft then -EdgeOffsetX else EdgeOffsetX
    shiftHorizontally toLeft rest nextOffset

let private splitAux isHeadPort edge =
  if not isHeadPort then getEdgeSlope false false edge > 0.0
  else getEdgeSlope false true edge < 0.0

let rec private splitEdgeList isHeadPort edges =
  let edgeArray = Array.ofList edges
  match Array.tryFindIndex (splitAux isHeadPort) edgeArray with
  | None -> edges, []
  | Some v ->
    let left, right = Array.splitAt v edgeArray
    List.ofArray left, List.ofArray right

let private partitionsToMergedList partition =
  partition.BackEdgesFromLeft
  @ partition.ForwardEdges
  @ partition.BackEdgesFromRight
  @ partition.SelfLoops

let private offsetX center i = float (i - center) * EdgeOffsetX

let private shiftSegments isHeadPort (edge: VisEdge) offset =
  let pts = edge.Points |> Array.ofList
  let n = Array.length pts
  let i1, i2 =
    match edge.IsBackEdge, isHeadPort with
    | true, true -> n - 2, n - 1
    | true, false -> 0, 1
    | false, true -> n - 2, n - 1
    | false, false -> 0, 1
  pts[i1].X <- pts[i1].X + offset
  pts[i2].X <- pts[i2].X + offset

let rec private shiftVertically isHeadPort offset = function
  | [] -> ()
  | (edge: VisEdge) :: rest ->
    let pts = edge.Points |> Array.ofList
    if isHeadPort then
      let n = Array.length pts
      pts[n - 2].Y <- pts[n - 2].Y + offset
      if edge.IsBackEdge then pts[n - 3].Y <- pts[n - 3].Y + offset else ()
    else
      pts[1].Y <- pts[1].Y + offset
      if edge.IsBackEdge then pts[2].Y <- pts[2].Y + offset else ()
    let offset = offset + (if isHeadPort then -EdgeOffsetY else EdgeOffsetY)
    shiftVertically isHeadPort offset rest

/// Give some offsets to each neighboring edge of v.
let private giveOffsets (g: VisGraph) (v: IVertex<VisBBlock>) =
  let preds = g.GetPreds v |> Seq.toArray
  let succs = g.GetSuccs v |> Seq.toArray
  let incoming = preds |> Array.map (fun p -> p, v, g.FindEdge (p, v))
  let outgoing = succs |> Array.map (fun s -> v, s, g.FindEdge (v, s))
  let ins =
    Array.fold (categorizeEdge true) emptyPartitionedEdges incoming
    |> sortPartitions true true
  let outs =
    Array.fold (categorizeEdge false) emptyPartitionedEdges outgoing
    |> sortPartitions false false
  shiftHorizontally true ins.BackEdgesFromLeft 0.0
  shiftHorizontally true outs.BackEdgesFromLeft 0.0
  shiftHorizontally false (List.rev ins.BackEdgesFromRight) 0.0
  shiftHorizontally false (List.rev outs.BackEdgesFromRight) 0.0
  let inFwdFromLeft, inFwdFromRight = splitEdgeList true ins.ForwardEdges
  let outFwdToLeft, outFwdToRight = splitEdgeList false outs.ForwardEdges
  let incomingFromLeft, incomingFromRight =
    ins.BackEdgesFromLeft @ inFwdFromLeft,
    inFwdFromRight @ ins.BackEdgesFromRight @ ins.SelfLoops
  let outgoingToLeft, outgoingToRight =
    outs.BackEdgesFromLeft @ outFwdToLeft,
    outFwdToRight @ outs.BackEdgesFromRight @ outs.SelfLoops
  let incomingMerged = partitionsToMergedList ins
  let outGoingMerged = partitionsToMergedList outs
  let iCenter = (List.length incomingMerged) / 2
  let oCenter = (List.length outGoingMerged) / 2
  let headOffsets = List.mapi (fun i _ -> offsetX iCenter i) incomingMerged
  let tailOffsets = List.mapi (fun i _ -> offsetX oCenter i) outGoingMerged
  List.iter2 (shiftSegments true) incomingMerged headOffsets
  List.iter2 (shiftSegments false) outGoingMerged tailOffsets
  shiftVertically true 0.0 incomingFromLeft
  shiftVertically true 0.0 (incomingFromRight |> List.rev)
  shiftVertically false 0.0 outgoingToLeft
  shiftVertically false 0.0 (outgoingToRight |> List.rev)

let drawEdges (g: VisGraph) vLayout backEdgeList dummyMap =
  restoreBackEdges g backEdgeList
  let originalEdgeList = g.FoldEdge (accOriginalEdge g) []
  let vLayoutSorted = sortLayers vLayout
  adjustLayerYPositions originalEdgeList vLayoutSorted
  let boxes = verticesToBoxes2D vLayoutSorted
  List.iter (drawBoxes g vLayoutSorted boxes dummyMap) originalEdgeList
  Map.iter (removeDummy g) dummyMap
  g.IterVertex (giveOffsets g)
