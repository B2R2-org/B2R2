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

module internal B2R2.RearEnd.Visualization.EdgeDrawing

open B2R2
open B2R2.MiddleEnd.BinGraph

let mutable private count = 0
let private LEGACY = false

/// The X offset between starting points of two adjacent edges.
let [<Literal>] private edgeOffsetX = 4.0

/// The Y offset between starting points of two adjacent edges.
let [<Literal>] private edgeOffsetY = 4.0

/// The length of the last segment of an edge. This value should be at least
/// less than the half of blockIntervalY.
/// original value: 20.0
let [<Literal>] private lastSegLen = 20.0
let [<Literal>] private nodeBoxOffset = 20.0

/// The margin to prevent an overlap between a node and its back edges.
/// original value: 10.0
let [<Literal>] private backEdgeMargin = 10.0
let [<Literal>] private backEdgeBoxHeight = 15.0

let [<Literal>] private fitErrorMargin = 1.0

/// Offset to prevent edges from 'touching' nodes.





/// Triple helper functions.
let first (a, _, _) = a
let second (_, b, _) = b
let third (_, _, c) = c


let private restoreBackEdge (vGraph: VisGraph) (src, dst, (edge: VisEdge)) =
  match vGraph.TryFindEdgeData dst src with
  | Some eData ->
    if eData.IsBackEdge then
      vGraph.RemoveEdge dst src |> ignore
      vGraph.AddEdge src dst edge |> ignore
    else
      vGraph.AddEdge src dst edge |> ignore
  | None ->
    vGraph.AddEdge src dst edge |> ignore

let private restoreBackEdges vGraph backEdgeList =
  List.iter (restoreBackEdge vGraph) backEdgeList

/// Might be modefied to return different heights for different vertices?
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

let private computeEdgeEndOffsets vGraph (predEndOffsets, succEndOffsets) v =
  /// predecessors of v.
  let preds =
    DiGraph.getPreds vGraph v |> List.sortBy VisGraph.getIndex |> List.toArray
  /// successors of v.
  let succs =
    DiGraph.getSuccs vGraph v |> List.sortBy VisGraph.getIndex |> List.toArray

  computeEdgeEndOffset v preds predEndOffsets true,
  computeEdgeEndOffset v succs succEndOffsets false

let inline private goingUp pY cY = pY > cY

let inline private goingDown pY cY = pY < cY

let inline private goingRight pX cX = pX < cX

let inline private isDummy (v: Vertex<VisBBlock>) = v.VData.IsDummy

/// Key function to be rewritten. 
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
  /// pX, pY : Edge starting point. Bottom center of vertex p.
  /// cX, cY : Edge ending  point. Top center of vertex c.
  let pX = VisGraph.getXPos p + VisGraph.getWidth p / 2.0
  let pY = VisGraph.getYPos p + VisGraph.getHeight p
  let cX = VisGraph.getXPos c + VisGraph.getWidth c / 2.0
  let cY = VisGraph.getYPos c

  /// Old steps to build simple lines. Needs almost complete rewriting.
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
    vGraph.RemoveEdge p c |> ignore
    removeDummyLoop vGraph src p (eData.Points @ points) lst
  | [] ->
    let eData = vGraph.FindEdgeData src c
    vGraph.RemoveEdge src c |> ignore
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
  vGraph.AddEdge src dst newEdge |> ignore

  dummies
  |> List.iter (fun (v: Vertex<_>) -> vGraph.RemoveVertex v |> ignore)

let private removeDummies (vGraph: VisGraph) dummyMap =
  Map.iter (removeDummy vGraph) dummyMap

















(* START NEW EDGE DRAWING *)

// Change in layer number of edge q -> r.
let private getEuclideanDist (q: VisPosition) (r: VisPosition) =
  (q.X - r.X) ** 2.0 + (q.Y - r.Y) ** 2.0
  |> sqrt

let private getLayerDiff q r = 
  VisGraph.getLayer r - VisGraph.getLayer q

let private entryPoint (v: Vertex<VisBBlock>) = 
  let x , y = VisGraph.getXPos v, VisGraph.getYPos v
  (x + VisGraph.getWidth v/2.0), (y + VisGraph.getHeight v)

let private exitPoint (v: Vertex<VisBBlock>) = 
  let x , y = VisGraph.getXPos v, VisGraph.getYPos v
  (x + (VisGraph.getWidth v)/2.0), y

let private isOnLeft (q: Vertex<VisBBlock>) (r: Vertex<VisBBlock>) = 
  let qx, rx = VisGraph.getXPos q, VisGraph.getXPos r
  qx + 1.5 * (VisGraph.getWidth q) < rx

/// Very simple Box record consisting of four corner points.
type Box = {
  tl : VisPosition
  tr : VisPosition
  bl : VisPosition
  br : VisPosition
  isVirtual: bool
}
let private VisPosition (x,y) : VisPosition = {X = x; Y = y}

let private Box _tl _tr _bl _br _isVirtual: Box = 
  {
    tl = VisPosition (fst _tl, snd _tl); 
    tr = VisPosition (fst _tr, snd _tr); 
    bl = VisPosition (fst _bl, snd _bl); 
    br = VisPosition (fst _br, snd _br);
    isVirtual = _isVirtual
  }

let private getBox left right top bottom _isVirtual: Box = 
  {
    tl = VisPosition (left, top); 
    tr = VisPosition (right, top); 
    bl = VisPosition (left, bottom);
    br = VisPosition (right, bottom);
    isVirtual = _isVirtual
  }

// Converts a Vertex into a Box.
let private vertexToBox (v:Vertex<VisBBlock>) : Box =
  let left = VisGraph.getXPos v - if (isDummy v) then 0.0 else nodeBoxOffset
  let right = 
      (VisGraph.getXPos v + VisGraph.getWidth v
      * if (isDummy v) then 0.5 else 1.0) // TODO: check effect.
      + if (isDummy v) then 0.0 else nodeBoxOffset
  let top = VisGraph.getYPos v - nodeBoxOffset
  let bottom = (VisGraph.getYPos v + VisGraph.getHeight v) + nodeBoxOffset

  getBox left right top bottom (isDummy v)
/// Converts vertex arrays to Box arrays.
let private verticesToBoxes1D (vertices: Vertex<VisBBlock> array): Box array = 
  Array.map vertexToBox vertices
let private verticesToBoxes2D (vLayout: Vertex<VisBBlock> array array): Box array array = 
  Array.map verticesToBoxes1D vLayout

let private dummyBox : Box = {
    tl = {X = 0.0; Y = 0.0} 
    tr = {X = 0.0; Y = 0.0}
    bl = {X = 0.0; Y = 0.0}
    br = {X = 0.0; Y = 0.0}
    isVirtual = true
  }



let private getBoxWidth (box: Box) = box.tr.X - box.tl.X
let private getBoxHeight (box: Box) = box.bl.Y - box.tl.Y

// Center point of a box.
let private center (box: Box): VisPosition = 
  { X = box.tl.X + (box.tr.X - box.tl.X) / 2.0
    Y = box.tl.Y + (box.bl.Y - box.tl.Y) / 2.0 }

let boxesOverlapping leftBox rightBox = 
  // let leftBox = if box1.tl.X < box2.tl.X then box1 else box2
  // let rightBox = if box1.tl.X < box2.tl.X then box2 else box1
  let left1, right1 = leftBox.tl.X, leftBox.tr.X
  let left2, right2 = rightBox.tl.X, rightBox.tr.X

  left2 >= left1  && left2 <= right1 

// Computes the right side of the closest box to the left of layer.[i]
// let rec private getBoxLeftBound index (layer: Box array) widthLine = 
//   match index with
//   | 0 -> fst widthLine
//   | i -> 
//     if layer.[i - 1].isVirtual then 
//       getBoxLeftBound (i - 1) layer widthLine 
//     else 
//       layer.[i - 1].tr.X
    
// let rec private getBoxRightBound index (layer: Box array) widthLine = 
//   match index with
//   | m when m >= (Array.length layer) - 1 -> snd widthLine
//   | i -> 
//     if layer.[i + 1].isVirtual then 
//       getBoxRightBound (i + 1) layer widthLine
//     else 
//       layer.[i + 1].tl.X

// TODO: Reconsider mechanism later?
let rec private getBoxLeftBound reference index (layer: Box array) widthLine = 
  match index with
  | i when i < 0 -> fst widthLine
  | i -> 
    if not (boxesOverlapping layer.[i] layer.[reference]) || (reference <> i && not (layer.[i].isVirtual))  then 
      layer.[i].tr.X
    else
      getBoxLeftBound reference (i - 1) layer widthLine 
    
let rec private getBoxRightBound reference index (layer: Box array) widthLine = 
  match index with
  | i when i > (Array.length layer) - 1 -> snd widthLine
  | i -> 
    if not (boxesOverlapping layer.[reference] layer.[i]) || (reference <> i && not (layer.[i].isVirtual)) then 
      layer.[i].tl.X
    else
      getBoxRightBound reference (i + 1) layer widthLine 
      

let private getLayerHeight layer =
  let heights = Array.map getBoxHeight layer
  Array.max heights

let private getHeightPerLayer vLayoutBoxes =
  Array.map getLayerHeight vLayoutBoxes

let private drawSelfLoop (vGraph) (q:Vertex<VisBBlock>) = 
  let nodeWidth = VisGraph.getWidth q
  let eData = (vGraph: VisGraph).FindEdgeData q q
  let tailP, headP = entryPoint q, exitPoint q
  let startP = ((fst tailP), snd tailP)
  let endP = ((fst headP), snd headP)

  let point1 = (fst startP), (snd startP + lastSegLen)
  let point2 = ((fst point1) + nodeWidth/2.0 + backEdgeMargin), (snd point1)
  let point3 = (fst point2), (snd endP) - lastSegLen
  let point4 = (fst endP), snd point3
  eData.Points <- (startP::point1::point2::point3::point4::endP::[]) |> List.map VisPosition


/// Given vertex boxes, returns two x-coordinates defining the width line of the graph.
let private getWidthLine (vLayout: Vertex<VisBBlock> array array): float*float =
   let boxes = verticesToBoxes2D vLayout
   let lefts = Array.map (Array.map (fun b -> b.tl.X)) boxes
   let rights = Array.map (Array.map (fun b -> b.tr.X)) boxes
   let leftmost = Array.min (Array.concat lefts)
   let rightmost = Array.max (Array.concat rights)
   leftmost, rightmost

/// Computes starting and ending y-coordinates for each layer.
let private getLayerPositions (boxes: Box array array) (heights: float array): ((float*float) array) = 
  let starts = Array.map (fun (layer: Box array) -> layer.[0].tl.Y) boxes
  let ends = Array.map2 (+) starts heights
  Array.map2 (fun x y -> (x,y)) starts ends
  


let private srcNodeBox2  (qBox: Box) (layer: Box array) (widthLine) (layerPosition) : (Box) = 
  let index = Array.findIndex ((=) qBox ) layer
  let left = getBoxLeftBound index index layer widthLine
  let right = getBoxRightBound index index layer widthLine
  let top = qBox.bl.Y
  let bottom = layerPosition |> snd

  getBox left right top bottom true



/// Computes an inter-layer Box right under given layerNum.
let private interLayerBox2 layerPositions widthLine layerNum = 
  if layerNum >= Array.length layerPositions - 1 then
    dummyBox
  else
    let top =  (layerPositions.[layerNum] |> snd)
    let bottom = layerPositions.[layerNum + 1] |> fst
    let left, right = widthLine
    getBox left right top bottom true

/// Computes a box corresponding to a particular dummy node.
let private virtualNodeBox2  vLayoutBoxes widthLine (layerPositions: (float*float) array) shrinkBox dummy = 
  let dBox = dummy |> vertexToBox
  let dRow = Array.findIndex (Array.contains (dBox)) vLayoutBoxes
  let layer = vLayoutBoxes.[dRow]
  let dCol = Array.findIndex ((=) dBox ) layer

  let left = getBoxLeftBound dCol dCol layer widthLine
  let right = getBoxRightBound dCol dCol layer widthLine
  let top = layerPositions.[dRow] |> fst
  let bottom = layerPositions.[dRow] |> snd

  let shrinkDelta = (right - left) / 3.0

  if shrinkBox then
    getBox (left + shrinkDelta) (right - shrinkDelta) top bottom true
  else
    getBox left right top bottom true





type Line = {
  left: VisPosition
  right: VisPosition
}
// Line builder & helper functions
let private Line left right y: Line= {left = VisPosition (left, y);  right = VisPosition (right, y)}
let private getLineLength line = line.right.X - line.left.X
let private getLineY line = line.left.Y
let private isDummyLine line = getLineLength line = 0.0
let private dummyLine: Line  = {left = VisPosition(-10000.0, 0.0); right = VisPosition(-10000.0,0.0)  }
let private getMidpoint (line:Line) = VisPosition ((line.left.X + (line.right.X - line.left.X)/2.0), (line.left.Y))
  

// Get intersection line segment between two neighbouring boxes. Return
let private getIntersection upper lower: Line =
  let upperBottom, lowerTop = upper.bl.Y, lower.tl.Y
  // No intersection between boxes. Return a dummy line.
  if int upperBottom <> int lowerTop then
     printfn "ERROR: no intersection between two boxes!"
     dummyLine
  else 
    let left, right = max (upper.bl.X) (lower.tl.X), min (upper.br.X) (lower.br.X)
    Line left right upperBottom
    
let private getIntersections (boxes: list<Box>): list<Line> = 
  let first = boxes.Head
  
  let rec aux acc (h:Box) (t:list<Box>)  = 
    //printfn "called getIntersections aux"
    match t with
    | [] -> 
      (Line h.tl.X h.tr.X h.bl.Y)::acc
    | th::tt -> 
      aux ((getIntersection h th)::acc) th tt
  // append the starting line at the start.
  ((aux [] first boxes.Tail )@[Line first.tl.X first.tr.X (first.tl.Y)])  |> List.rev


/// Computes tuple (distance between q-r line and midpoint, left endpoint is closer).
let private lineFits (q: VisPosition) (r: VisPosition) (line: Line): (int * bool) = 
  let qx, qy, rx, ry = q.X, q.Y, r.X, r.Y
  let dy = (ry - qy)
  let m = (rx - qx) / dy
  let x = qx + m * (line.left.Y - qy)
  let left, right = line.left, line.right
  //printfn "x: %d, left: %d, right: %d" (int x) (int left.X) (int right.X)
  let xFits = (x >= left.X - fitErrorMargin && x <= right.X + fitErrorMargin)
    
  if xFits || (abs dy) < 0.1 then
    (-1, false)
  else 
    // printfn "m: %d,\try-qy: %.0f,\tmidpoint: %d" ((int)m) (ry-qy)  ((int)(getMidpoint line).X)
    // abs (int x - int (getMidpoint line).X), abs (x - left.X) < abs (x - right.X)

    if x < left.X then // x is to the left of segment
      abs (int (x - left.X)), true
    else
      abs (int (x - right.X)), false


let private getLineFitArray (l_array: Line array) (q: VisPosition) (r: VisPosition) = 
  Array.map (lineFits q r) l_array

let rec private compute_P_list (l_array: Line array) q r = 
  count <- count + 1
  // printfn "L length: %d\t" (Array.length l_array)

  // if (count > 200) then
  //   printfn "Stack overflow. Abort compute_P_list."
  //   [] 
  // else

  let interLines = l_array

  let fitTupleArray = 
    getLineFitArray interLines q r
  // printfn "%A" fitTupleArray
  let furthestLineIndex = 
    fitTupleArray 
    |> Array.mapi (fun i v -> i, v) 
    |> Array.maxBy (fun x -> fst (snd x)) 
    |> fst
  let furthestFitTuple = fitTupleArray.[furthestLineIndex]
  
  let splitLine = interLines.[furthestLineIndex]
  if fst furthestFitTuple > 0 then
    // Splitting point p. Defined as one of two endpoints of split line that is closer to q-r line segment.
    let p = if snd furthestFitTuple then splitLine.left else splitLine.right
    // Partition l_array into two parts, and make recursive calls.
    let slice1 = l_array.[ .. furthestLineIndex ]
    let slice2 = l_array.[ furthestLineIndex .. ]
    // printf "Split at line %d\t" furthestLineIndex
    // printfn "L1: %d\tL2: %d" (Array.length slice1) (Array.length slice2)
    let segment1 = (compute_P_list slice1 q p)
    let segment2 = (compute_P_list slice2 p r)
    segment1 @ (p :: segment2)
  else
    []

let private boxIsOnLeft b1 b2 = 
  (center b1).X < (center b2).X

let private drawNonLoop vGraph vLayout dummyMap (q, r, edge: VisEdge)  = 
  let isBackEdge = edge.IsBackEdge
  let vLayoutBoxes = verticesToBoxes2D vLayout

  let qRow = VisGraph.getLayer q
  let qCol = Array.findIndex ((=) q) vLayout.[qRow]
  let qLayer = vLayoutBoxes.[qRow]
  let qBox = vLayoutBoxes.[qRow].[qCol]

  let rRow = VisGraph.getLayer r
  let rCol = Array.findIndex ((=) r) vLayout.[rRow]
  let rLayer = vLayoutBoxes.[rRow]
  let rBox = vLayoutBoxes.[rRow].[rCol]

  // List of dummy vertices along edge (q,r)
  let dummies, shrinkBox = 
      match (Map.tryFind (q, r) dummyMap) with
      | Some v -> 
        if isBackEdge then
          snd v, false 
        else 
          snd v |> List.rev, false
      | None ->
        if not isBackEdge || abs (getLayerDiff q r) = 1 then 
          [], false // span-1 edge or forward edge
        else // Dummy node data deleted. Refer to existing forward edge.
          match Map.tryFind (r, q) dummyMap with
          | Some v -> snd v |> List.rev, true
          | None -> [], false
            
       

  let heights = getHeightPerLayer vLayoutBoxes
  let layerPositions = getLayerPositions (vLayoutBoxes) heights
  let widthLine = getWidthLine vLayout
  // Layer numbers of q and r.
  
  let interLayerNums =
    // Edge with span 1. Single inter-layer node
    if dummies.IsEmpty then
      [ (min qRow rRow) ]
    // Layers from top to bottom
    else [ (min qRow rRow) .. (max qRow rRow) - 1 ]

  let boxBelowUpper = 
    if isBackEdge then
      srcNodeBox2 rBox rLayer widthLine layerPositions.[rRow]
    else 
      srcNodeBox2 qBox qLayer widthLine layerPositions.[qRow]

  let interLayerBoxes = List.map (interLayerBox2 (layerPositions) widthLine ) interLayerNums 
  let virtualNodeBoxes = List.map (virtualNodeBox2 vLayoutBoxes widthLine layerPositions shrinkBox) dummies 
  
  // Boxes between nodes q and r, from upper layer to lower.
  let boxes = 
    boxBelowUpper::((List.fold2 (fun acc v i ->  i::v::acc) [interLayerBoxes.Head] virtualNodeBoxes interLayerBoxes.Tail) |> List.rev)
  
  

  let qOnLeft = isOnLeft q r
  let qOnRight = isOnLeft r q


  // Upper -> lower layer
  let intersectionLines = getIntersections boxes

  // Key points
  let tailQ, headR = entryPoint q, exitPoint r

  let tailQ1 = VisPosition ((fst tailQ), snd tailQ)
  let headR1 = VisPosition ((fst headR), snd headR)


  let tailQ2 = { tailQ1 with Y = tailQ1.Y + nodeBoxOffset }
  let headR2 = { headR1 with Y = headR1.Y - nodeBoxOffset } 

  let boxPoints = List.fold (fun acc b ->  b.tl::b.bl::b.br::b.tr::b.tl::acc) [] boxes |> List.rev
  let linePoints = List.fold (fun acc l ->  l.left::l.right::l.left::acc) [] intersectionLines |> List.rev

  let p_list = 
    if isBackEdge then
      let dummyBoxes = 
        dummies
        |> Array.ofList
        |> Array.map vertexToBox

      let n = Array.length dummyBoxes

      let departLeft, arriveLeft = 
        if n < 1 then
          isOnLeft r q,
          isOnLeft q r
        else
          boxIsOnLeft dummyBoxes.[ n - 1 ] qBox,
          boxIsOnLeft dummyBoxes.[0] rBox
              
      let tailQ3 =
          { tailQ2 with
              X = tailQ2.X 
                  + 0.55 * (VisGraph.getWidth q)
                  * if departLeft then -1.0 else 1.0 }
      let headR3 = 
          { headR2 with 
              X = headR2.X 
                  + 0.55 * (VisGraph.getWidth q)
                  * if arriveLeft then -1.0 else 1.0 }
      
      let tailQ4 = { tailQ3 with Y = qBox.tl.Y }
      let headR4 = { headR3 with Y = rBox.bl.Y }              

      // printfn "%d dummy nodes for backedge" (List.length dummies)
      tailQ1 :: tailQ2 :: tailQ3 :: tailQ4 :: 
      (compute_P_list (intersectionLines |> Array.ofList) (headR4) (tailQ4) |> List.rev) @
      [headR4; headR3; headR2; headR1]
    else
      tailQ1 :: tailQ2 :: 
      (compute_P_list (intersectionLines |> Array.ofList) (tailQ2) (headR2)) @
      [headR2; headR1]
  count <- 0

  // printf "q (%d, %d) -> " qRow (Array.findIndex ((=) q) vLayout.[qRow])
  // printfn "r (%d, %d)" rRow (Array.findIndex ((=) r) vLayout.[rRow])

  // Final list of points to be drawn.
  let displayPoints = p_list

  

  let eData =  (vGraph: VisGraph).TryFindEdgeData q r
  match eData with
  | None -> 
     /// Imaginary edges for display purposes only.q
    let newEdge = VisEdge (edge.Type)
    newEdge.IsBackEdge <- isBackEdge
    newEdge.Points <-  displayPoints
    vGraph.AddEdge q r newEdge |> ignore
  | Some v -> 
    v.Points <-  displayPoints


let private drawBoxes vGraph (vLayout: Vertex<VisBBlock> [] []) dummyMap (q, r, edge: VisEdge) =
  
  // Abort conditions
  if isDummy q 
    || isDummy r 
    // || not (q = vLayout.[1].[0]) 
    // || not (r = vLayout.[13].[1]) 
    // || not (abs (VisGraph.getLayer r - VisGraph.getLayer q) = 3)
    // || not edge.IsBackEdge
    then ()
  // Self-loop case
  elif q = r then
    drawSelfLoop vGraph q
  else
    drawNonLoop vGraph vLayout dummyMap (q, r, edge)
 
(* END NEW EDGE DRAWING *)


/// Computes mapping src -> (dst). WARNING: Original src nodes may become overwritten!!!
let private getEdgeMap (vGraph:VisGraph)  = 
  vGraph.FoldEdge (fun acc src dst _ -> Map.add src dst acc) Map.empty

/// Computes the original destination vertex, given dummy source node src.
let private getOriginalDst (src: Vertex<VisBBlock>) (edgeMap: Map<Vertex<VisBBlock>, Vertex<VisBBlock>>)  = 
    let rec findR (x:Vertex<VisBBlock>) = 
      if isDummy x then findR (Map.find x edgeMap)
      else x
    findR src

/// Given src is original, adds original edge to acc.
let private accOriginalEdge edgeMap acc  (src:Vertex<VisBBlock>) (dst:Vertex<VisBBlock>) (edge: VisEdge) = 
  if isDummy src then acc
  elif isDummy dst then (src, (getOriginalDst dst edgeMap), edge ) :: acc
  else (src, dst, edge) :: acc

let private sortLayer (layer: Vertex<VisBBlock> array) = 
  Array.sortBy (fun x -> (VisGraph.getXPos x)) layer

let private countIncidentEdges edges incoming v =
  let getter = if incoming then second else first
  edges
  |> List.filter ( fun edge -> (getter edge) = v )
  |> List.length

let private getMaxIncidentEdges edges incoming layer = 
  layer
  |> Array.map (countIncidentEdges edges incoming)
  |> Array.max

let private downShiftLayers layers units = 
  Array.iter (Array.iter (fun (v: Vertex<VisBBlock>) -> 
    let vData = v.VData
    let newY = vData.Coordinate.Y + edgeOffsetY * float units
    vData.Coordinate.Y <- newY)) layers

let rec private adjustLayers incoming edgeNums layerNum vLayout =
  match edgeNums with
  | [] -> ()
  | hd :: tl ->
    if hd >= 15 then // NOTE: turn this into literal?
      let shiftStart = 
        if incoming then 
          layerNum 
        else layerNum + 1
      if shiftStart < Array.length vLayout then
        downShiftLayers vLayout.[ layerNum .. ] hd
    adjustLayers incoming tl (layerNum + 1) vLayout


let private adjustLayerPositions edges vLayout = 
  let maxIncoming, maxOutgoing = 
    vLayout 
    |> Array.map (getMaxIncidentEdges edges true)
    |> List.ofArray,
    vLayout 
    |> Array.map (getMaxIncidentEdges edges false)
    |> List.ofArray

  vLayout
  |> adjustLayers true maxIncoming 0

  vLayout
  |> adjustLayers false maxOutgoing 0

let private condenseOffsets edgeMap acc (src, dst) offset  = 
  if isDummy src then acc
  elif isDummy dst then 
    let nodePair =  (src, getOriginalDst dst edgeMap)
    Map.add nodePair (offset) acc
  else
    Map.add (src, dst) (offset) acc



let private getPortOffsets (originalEdgeList: list<Vertex<VisBBlock> * Vertex<VisBBlock> * VisEdge>) (headOffsetMap, tailOffsetMap) (v: Vertex<VisBBlock>) = 
  let srcsToV =  
    (List.filter ( fun edge -> (second edge) = v ) originalEdgeList)
    |> List.map first
    |> List.sortBy (VisGraph.getXPos)
  let dstsFromV =  
    (List.filter ( fun edge -> (first edge) = v  ) originalEdgeList)
    |> List.map second
    |> List.sortBy (VisGraph.getXPos)
  
  let srcCenterIndex, dstCenterIndex = (List.length srcsToV) / 2, (List.length dstsFromV) / 2

  let headOffsets = List.mapi (fun i _ -> float (i - srcCenterIndex) * edgeOffsetX) srcsToV
  let tailOffsets = List.mapi (fun i _ -> float (i - dstCenterIndex) * edgeOffsetX) dstsFromV
  
  let newHeadOffsetMap = List.fold2 (fun map src offset -> Map.add (src, v) (offset, 0.0) map) headOffsetMap srcsToV headOffsets
  let newTailOffsetMap = List.fold2 (fun map dst offset -> Map.add (v, dst) (offset, 0.0) map) tailOffsetMap dstsFromV tailOffsets
  newHeadOffsetMap, newTailOffsetMap


// e1: Backedges from the left
// e2: Forward edges 
// e3: Backedge from the right 
// e4: Self-loop (must be singular)

let private categorizeEdge isHeadPort (e1, e2, e3, e4) (q, r, edge: VisEdge) =
  let points = edge.Points |> Array.ofList
  let n = Array.length points
  if n < 4 then 
    printfn "WARNING: weird edge detected. Length %d" n
    e1, e2, e3, e4
  else
  if q = r then // Self-loop
    e1, e2, e3, edge :: e4
  elif edge.IsBackEdge then
    let p1Index, p2Index = 
      if isHeadPort then
        n - 2, n - 3
      else
        1, 2
    if points.[p2Index].X < points.[p1Index].X then // Backedge from left
      edge :: e1, e2, e3, e4
    else // Backedge from right
      e1, e2, edge :: e3, e4
  
  else // Forward edge
    e1, edge :: e2, e3, e4

// Vector q -> r always directed downwards (q.Y < r.Y)
let private getSlope (q: VisPosition) (r: VisPosition) = 
  let qx, qy, rx, ry = q.X, q.Y, r.X, r.Y
  let dy = (ry - qy)
  // let m = (rx - qx) / dy
  if abs dy < 0.1 then // Approximately horizontal line
    if qx < rx then infinity else -infinity
  else // Non-horizontal slope
    (rx - qx) / dy


// NOTE: head port => converging, tail port => diverging
let private getSegmentSlope isBackEdge isHeadPort (edge: VisEdge) = 
  let points = edge.Points |> Array.ofList
  let n = Array.length points
  let qIndex, rIndex = 
    match isBackEdge, isHeadPort with
    | true, true -> n - 4, n - 5
    | true, false -> 4, 3
    | false, true -> n - 3, n - 2
    | false, false -> 1, 2
  getSlope points.[qIndex] points.[rIndex]

let private shiftSegments isHeadPort shiftY (edge: VisEdge) offset = 
  let points = edge.Points |> Array.ofList
  let n = Array.length points
  let shiftXStart, shiftXEnd = 
    match edge.IsBackEdge, isHeadPort with
    | true, true -> n - 2, n - 1
    | true, false -> 0, 1
    | false, true -> n - 2, n - 1
    | false, false -> 0, 1
  let shiftYStart, shiftYEnd = 
    match edge.IsBackEdge, isHeadPort with
    | true, true -> n - 3, n - 2
    | true, false -> 1, 2
    | false, true -> n - 2, n - 2
    | false, false -> 1, 1
 
  points
  |> Array.iteri 
    (fun i (p: VisPosition) -> 
      if i >= shiftXStart && i <= shiftXEnd then p.X <- p.X + fst offset)
  
  if shiftY then
    points
    |> Array.iteri 
      (fun i (p: VisPosition) -> 
        if i >= shiftYStart && i <= shiftYEnd then p.Y <- p.Y + snd offset)
  edge.Points <- points |> List.ofArray

let rec private shiftHorizontally toLeft (edges: VisEdge list) offset = 
  match edges with
  | [] -> 
    ()
  | hd :: tl -> 
    let points = hd.Points |> Array.ofList
    let n = Array.length points
    points.[ n - 3 ].X <- points.[ n - 3 ].X + offset
    points.[ n - 4 ].X <- points.[ n - 4 ].X + offset

    let nextOffset = offset + if toLeft then -edgeOffsetX else edgeOffsetX
    shiftHorizontally toLeft tl nextOffset


let private giveOffsets edges (v: Vertex<VisBBlock>) =
  // For head port
  let incoming =
    List.filter ( fun edge -> (second edge) = v ) edges
  let i1, i2, i3, i4 = 
    List.fold (categorizeEdge true) ([], [], [], []) incoming
  let si1, si2, si3, si4 = 
    List.sortBy (getSegmentSlope true true) i1,
    List.sortBy (getSegmentSlope false true) i2,
    List.sortBy (getSegmentSlope true true) i3,
    List.sortBy (getSegmentSlope true true) i4
 
  shiftHorizontally true (List.rev si1) 0.0
  shiftHorizontally false si3 0.0

  let incomingMerged = 
    (si1 |> List.rev) @
    (si2 |> List.rev) @
    (si3 |> List.rev) @
    si4

  // For tail port
  let outgoing =  
    List.filter ( fun edge -> (first edge) = v ) edges
  let o1, o2, o3, o4 = 
    List.fold (categorizeEdge false) ([], [], [], []) outgoing
  let so1, so2, so3, so4 = 
    List.sortBy (getSegmentSlope true false) o1,
    List.sortBy (getSegmentSlope false false) o2,
    List.sortBy (getSegmentSlope true false) o3,
    List.sortBy (getSegmentSlope true false) o4

  shiftHorizontally true so1 0.0
  shiftHorizontally false (List.rev so3) 0.0

  let outGoingMerged = so1 @ so2 @ so3 @ so4

  let offsetX center i = float (i - center) * edgeOffsetX
  let offsetY center i = float (center - abs (i - center)) * edgeOffsetY

  let iCenter = (List.length incomingMerged) / 2
  let oCenter = (List.length outGoingMerged) / 2

  let headOffsets = List.mapi (fun i _ -> offsetX iCenter i, - (offsetY iCenter i)) incomingMerged
  let tailOffsets = List.mapi (fun i _ -> offsetX oCenter i, (offsetY oCenter i)) outGoingMerged
  // printfn "%A" headOffsets
  List.iter2 (shiftSegments true (List.length incomingMerged >= 3)) incomingMerged headOffsets
  List.iter2 (shiftSegments false (List.length incomingMerged >= 3)) outGoingMerged tailOffsets
  ()

/// NOTE: vLayout is not sorted in order of coordinates. May have to re-compute the array in the order of increasing x-coordinate values.
let drawEdges (vGraph: VisGraph) vLayout backEdgeList dummyMap =
  restoreBackEdges vGraph backEdgeList
  /// Currently set as the highest vertex in the layer. Consider changing from single height representing entire layer -> varying heights?
  let hPerLayer = computeHeightPerLayer vLayout
  let predEndOffsets, succEndOffsets =
    vGraph.FoldVertex (computeEdgeEndOffsets vGraph) (Map.empty, Map.empty)

  /// NOTE: Map is one-to-one mapping. Cannot filter correct edge numbers with edgeMap.
  let edgeMap = getEdgeMap vGraph
  let originalEdgeList = vGraph.FoldEdge (accOriginalEdge edgeMap) []


  /// Original vLayout is not sorted by the x-coordinates. Compute a resorted version for box drawing.
  let vLayoutSorted = 
    vLayout
    |> Array.map (sortLayer)


  if not LEGACY then 
    adjustLayerPositions originalEdgeList vLayoutSorted
    List.iter (drawBoxes vGraph vLayoutSorted dummyMap) originalEdgeList
    removeDummies vGraph dummyMap

    let finalEdges = 
      VisGraph.foldEdge vGraph (fun acc q r (edge: VisEdge) -> (q, r, edge) :: acc ) []
    // printfn "final edges: %d" (List.length finalEdges)
    // printfn "original edges: %d" (List.length originalEdgeList)
    vGraph.IterVertex (giveOffsets finalEdges)
  else
    vGraph.IterEdge (drawEdge vGraph hPerLayer predEndOffsets succEndOffsets)
    removeDummies vGraph dummyMap

  let correctEdgeNum = (vGraph.FoldEdge (fun acc src dst _ -> src::acc ) []).Length
  // printfn "correctEdgeNum: %d" correctEdgeNum
  ()