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

/// TODO: too many features in this module, refactor it by separating the
/// concerns (e.g., port assignment, routing, etc.) into different modules.
module internal B2R2.RearEnd.Visualization.EdgeDrawing

open System.Collections.Generic
open B2R2
open B2R2.MiddleEnd.BinGraph

/// TODO: move all constants in this project into a separate module.
let [<Literal>] private StubMargin = 30.0

/// Minimum separation between parallel backward edge rails.
let [<Literal>] private EdgeOffset = 4.0

/// If the number of incoming/outgoing edges of a layer exceeds this threshold,
/// then we expand the layer's height.
let [<Literal>] private LayerHeightExpansionThreshold = 15

/// Calculate floating-point number of crossings for a candidate bend point
let [<Literal>] private CoordEpsilon = 0.001

let private pos x y = VisPosition.Create(x, y)

let private getDefault (dict: Dictionary<'Key, 'Value>) key defaultValue =
  match dict.TryGetValue key with
  | true, value -> value
  | _ -> defaultValue

let private populatePortMap (portMap: Dictionary<_, _>) assignments =
  assignments |> List.iter (fun (edge, x) -> portMap[edge] <- x)

let private addPoint (pts: ResizeArray<VisPosition>) x y = pts.Add(pos x y)

let private assignBackwardEdgeBendPoint portMap edge upperLayerVertexIndex =
  (portMap: PortMap).BwdEdgeBendPoints[edge] <- upperLayerVertexIndex

let private getCXPos (v: IVertex<VisBBlock>) =
  VisGraph.getXPos v + VisGraph.getWidth v / 2.0

let private partitionPairsByCentre cx edges =
  let isLeft (v, _) = getCXPos v < cx - EdgeOffset
  let isCentre (v, _) = abs (getCXPos v - cx) <= EdgeOffset
  let lefts, rest = List.partition isLeft edges
  let centres, rights = List.partition isCentre rest
  lefts, centres, rights

let private assignCPortsOffset cx edges =
  edges |> List.mapi (fun i (_, edge) ->
    edge, cx + (float i - float (List.length edges - 1) / 2.0) * 4.0)

let private assignLPortsOffset baseX edges =
  edges |> List.mapi (fun i (_, edge) -> edge, baseX - float (i + 1) * 4.0)

let private assignRPortsOffset baseX edges =
  edges |> List.mapi (fun i (_, edge) -> edge, baseX + float (i + 1) * 4.0)

let private assignPartitionedPorts cx lefts centres rights =
  assignLPortsOffset cx lefts @
  assignCPortsOffset cx centres @
  assignRPortsOffset cx rights

let private layerBotY (layer: IVertex<VisBBlock>[]) =
  layer
  |> Array.map (fun v -> VisGraph.getYPos v + VisGraph.getHeight v)
  |> Array.max

let private getMaxDegree edges layer =
  layer |> Array.map (edges >> List.length) |> Array.max

let private downShiftLayers layers deltaY =
  if deltaY > 0.0 then
    Array.iter (Array.iter (fun (v: IVertex<VisBBlock>) ->
      let blk = v.VData
      blk.Coordinate.Y <- blk.Coordinate.Y + deltaY)) layers

let private expandLayerGap (edgeSet: EdgeSet) (layout: IVertex<VisBBlock>[][]) =
  let layerCount = layout.Length
  let maxInDegrees = layout |> Array.map (getMaxDegree edgeSet.GetInEdges)
  let maxOutDegrees = layout |> Array.map (getMaxDegree edgeSet.GetOutEdges)
  for layerIdx in 0 .. layerCount - 1 do
    let inDeg = maxInDegrees[layerIdx]
    let outDeg = maxOutDegrees[layerIdx]
    if inDeg >= LayerHeightExpansionThreshold then
      let deltaY = EdgeOffset * float inDeg
      downShiftLayers layout[layerIdx..] deltaY
    else
      ()
    if outDeg >= LayerHeightExpansionThreshold then
      let shiftStart = layerIdx + 1
      if shiftStart < layerCount then
        let deltaY = EdgeOffset * float outDeg
        downShiftLayers layout[shiftStart..] deltaY
      else
        ()
    else
      ()
  for bandIdx in 0 .. layerCount - 2 do
    let curLayerBottom = layerBotY layout[bandIdx]
    let nextLayerTop =
      layout[bandIdx + 1] |> Array.map VisGraph.getYPos |> Array.min
    let botCount =
      layout[bandIdx]
      |> Array.sumBy (fun v -> edgeSet.GetBwdOutEdges v |> List.length)
    let topCount =
      layout[bandIdx + 1]
      |> Array.sumBy (fun v -> edgeSet.GetBwdInEdges v |> List.length)
    let total = botCount + topCount
    if total > 0 then
      let requiredGap = 2.0 * StubMargin + float total * EdgeOffset
      let currentGap = nextLayerTop - curLayerBottom
      let deficit = requiredGap - currentGap
      if deficit > 0.0 then
        downShiftLayers layout[bandIdx + 1..] deficit
      else
        ()
    else
      ()

let private createFwdPorts v (edgeSet: EdgeSet) edgeFlow portMap =
  let edges =
    match edgeFlow with
    | EdgeFlow.Outgoing -> edgeSet.GetFwdOutEdges v
    | EdgeFlow.Incoming -> edgeSet.GetFwdInEdges v
  let centerXPos = getCXPos v
  if List.isEmpty edges then
    ()
  else
    let lefts, centres, rights = partitionPairsByCentre centerXPos edges
    let port = List.sortBy (fst >> fun src -> abs (getCXPos src - centerXPos))
    assignPartitionedPorts centerXPos (port lefts) centres (port rights)
    |> fun ports ->
      match edgeFlow with
      | EdgeFlow.Outgoing -> populatePortMap portMap.FwdOutPorts ports
      | EdgeFlow.Incoming -> populatePortMap portMap.FwdInPorts ports

let private assignForwardEdgePorts (edgeSet: EdgeSet) layout portMap =
  layout
  |> Array.iter (Array.iter (fun v ->
    createFwdPorts v edgeSet EdgeFlow.Outgoing portMap
    createFwdPorts v edgeSet EdgeFlow.Incoming portMap)
  )

let private inBetween (x: float) (a: float) (b: float) =
  let lo, hi = min a b, max a b
  x >= lo - CoordEpsilon && x <= hi + CoordEpsilon

/// Count the solutions where x = bendX and e = (pred(neighbor), neighbor).
let private countVerticalCrossings bendX edgeSet neighbor =
  (edgeSet: EdgeSet).GetFwdInEdges(neighbor)
  |> List.map fst
  |> List.filter (fun p -> inBetween bendX (getCXPos p) (getCXPos neighbor))
  |> List.length

/// TODO: For source to destination edges, we should consider both bend points
/// in the source layer and the destination layer.
let private getBendX v = function
  | FromDummyToDest(isLeft) | FromSourceToDummy(isLeft)
  | FromSourceToDest(isLeft, _) ->
     if isLeft then VisGraph.getXPos v - StubMargin
     else VisGraph.getXPos v + VisGraph.getWidth v + StubMargin

/// Assign per-edge bendX offset so edges sharing the same raw bendX get
/// distinct X coordinates. Edges whose src is closer to the raw bendX get
/// inner offsets (closer to bendX); farther src gets outer offsets.
let private getBendSlots layout (edgeSet: EdgeSet) (portMap: PortMap) =
  let dict = Dictionary<VisEdge, float>()
  layout
  |> Array.collect id
  |> Array.collect (fun src ->
    edgeSet.GetBwdOutEdges src
    |> List.choose (fun (_, edge) ->
      match portMap.BwdEdgeBendPoints.TryGetValue edge with
      | true, bp -> Some(src, getCXPos src, bp, edge)
      | _ -> None)
    |> List.toArray)
  |> Array.groupBy (fun (src, _, bp, _) -> getBendX src bp)
  |> Array.iter (fun (rawBendX, group) ->
    // Sort by distance from src to rawBendX: closer src → smaller offset (inner).
    // Left rail: offset is negative (going left), inner = less negative = index 0.
    // Right rail: offset is positive (going right), inner = less positive = index 0.
    group
    |> Array.sortBy (fun (_, srcCx, _, _) -> abs (srcCx - rawBendX))
    |> Array.iteri (fun i (_, _, bp, edge) ->
      let isLeft =
        match bp with
        | FromDummyToDest(isLeft) | FromSourceToDummy(isLeft)
        | FromSourceToDest(isLeft, _) -> isLeft
      let offset =
        if isLeft then -float i * EdgeOffset
        else float i * EdgeOffset
      dict[edge] <- rawBendX + offset))
  dict

(*
/// We perform a rough approximation of the crossing count by considering the
/// relative positions of the forward and backward edges. We assume that we have
/// already assigned the ports for backward edges below the current layer, which
/// is ensured by the order of our port assignment process.
/// Time complexity: O(|neighbors| * |prevLayer| + |neighbors| * |nextLayer|)
/// = O(|neighbors| * (|prevLayer| + |nextLayer|))
/// = O(|L|^2) where L is the maximum number of vertices in a layer.
/// TODO: We can think this problem as moving the bend point to see if the
/// existing edges cross the candidate route who moves to the right side, so we
/// can optimize this process by ignoring the edges that are not crossed while
/// preceding the candidate bend point. A careful implementation will reduce
/// the overall time complexity to O(|L| * log |L|).
/// Roughly approximate the crossing count of a candidate backward route.
/// This function assumes only previously chosen backward bend points are known.
/// It does NOT depend on final backward out/in port assignments.
let private approximateCrossings edgeSet (layout: _[]) bwdBendPoints src
                                 candidateBendPoint =
  let srcX = getCXPos src
  let vertices = layout[src.VData.Layer]
  let approxBendX = getBendX candidateBendPoint
  (* 1. Crossings by forward edges. *)
  let crossingsByFwdEdges1 =
    vertices |> Array.sumBy (countVerticalCrossings approxBendX edgeSet)
  let crossingsByFwdEdges2 =
    vertices
    |> Array.sumBy (fun neighbor ->
      edgeSet.GetFwdOutEdges(neighbor)
      |> List.sumBy (fun _ ->
        if inBetween (getCXPos neighbor) approxBendX srcX then 1 else 0))
  let crossingsByFwdEdges = crossingsByFwdEdges1 + crossingsByFwdEdges2
  (* 2. Crossings by already-chosen backward edges. *)
  let crossingsByBwdEdges =
    vertices
    |> Array.sumBy (fun neighbor ->
      edgeSet.GetBwdInEdges(neighbor)
      |> List.sumBy (fun (pred, predBwdEdge) ->
        match (bwdBendPoints: Dictionary<_, _>).TryGetValue(predBwdEdge) with
        | true, predBendPoint ->
          let predBendX = getBendX predBendPoint
          let predX = getCXPos pred
          let neighborX = getCXPos neighbor
          let crossedByRow = inBetween predBendX srcX approxBendX
          let crossedByCol = inBetween approxBendX predX neighborX
          (if crossedByRow then 1 else 0) + if crossedByCol then 1 else 0
        | _ -> (* We do not record bend points for dummy to dummy edges. *)
          assert(pred.VData.IsDummy && neighbor.VData.IsDummy)
          if inBetween (getCXPos neighbor) approxBendX srcX then 1 else 0)
    )
  let totalCrossings = crossingsByFwdEdges + crossingsByBwdEdges
  totalCrossings, candidateBendPoint

let private isSubsumedBy layer x =
  layer |> Array.exists (fun v ->
    let left = VisGraph.getXPos v
    let right = left + VisGraph.getWidth v
    inBetween x left right)
*)

(*
let private collectCandidateBendPoints (layout: IVertex<_>[][]) src dst =
  let srcLayer = layout[(src: IVertex<VisBBlock>).VData.Layer]
  (* All vertices in the source layer are candidate bend points. *)
  let leftSides =
    srcLayer
    |> Array.map (fun v ->
      { BendPointKind = FromSourceToDest; Vertex = v; IsLeft = true })
  let rightSide =
    srcLayer
    |> Array.last
    |> fun v -> { BendPointKind = FromSourceToDest; Vertex = v; IsLeft = false }
  (* Consider the destination vertex if it is not overlapped by the lower
     layer. *)
  let dstX = VisGraph.getXPos dst
  let dstRightX = dstX + VisGraph.getWidth dst
  let nearDst =
    [| if not <| isSubsumedBy srcLayer dstX then
         { BendPointKind = FromSourceToDest; Vertex = dst; IsLeft = true }
       if not <| isSubsumedBy srcLayer dstRightX then
         { BendPointKind = FromSourceToDest; Vertex = dst; IsLeft = false } |]
  (* We additionally consider the source vertex itself, when we want to turn
     around the source vertex. *)
  let nearSrc =
    [| { BendPointKind = FromSourceToDest; Vertex = src; IsLeft = true }
       { BendPointKind = FromSourceToDest; Vertex = src; IsLeft = false } |]
  leftSides
  |> Array.append [| rightSide |]
  |> Array.append nearDst
  |> Array.append nearSrc

let private sortBendPoints bendPoints =
  bendPoints
  |> Array.sortBy (fun bp ->
    if bp.IsLeft then getCXPos bp.Vertex
    else getCXPos bp.Vertex + VisGraph.getWidth bp.Vertex)

let private getBendXOfEdge (portMap: PortMap) centerX (_, edge) =
  match portMap.BwdEdgeBendPoints.TryGetValue edge with
  | true, bp ->
    if bp.IsLeft then VisGraph.getXPos bp.Vertex - StubMargin
    else VisGraph.getXPos bp.Vertex + VisGraph.getWidth bp.Vertex + StubMargin
  | _ -> centerX
*)

let private computeIncomingEdgeCountOnSide (edgeSet: EdgeSet) portMap
                                           (v: IVertex<VisBBlock>) isLeft =
  assert(not v.VData.IsDummy)
  let forwardIncomingEdgeCount =
    edgeSet.GetFwdInEdges(v)
    |> List.filter (fun (src, _) -> getCXPos src < getCXPos v = isLeft)
    |> List.length
  let backwardIncomingEdgeCount =
    edgeSet.GetBwdInEdges(v)
    |> List.filter (fun (pred, e) ->
      (* From dummy to non-dummy. *)
      if pred.VData.IsDummy then getCXPos pred < getCXPos v = isLeft
      (* From non-dummy to non-dummy. *)
      else
        match (portMap: PortMap).BwdEdgeBendPoints.TryGetValue(e) with
        | false, _ -> false
        | true, bendPoint -> getBendX pred bendPoint < getCXPos v = isLeft)
    |> List.length
  forwardIncomingEdgeCount + backwardIncomingEdgeCount

let private chooseBackwardEdgeBendSide edgeSet portMap v =
  let leftSideEdges = computeIncomingEdgeCountOnSide edgeSet portMap v true
  let rightSideEdges = computeIncomingEdgeCountOnSide edgeSet portMap v false
  leftSideEdges <= rightSideEdges

/// To minimize the edge crossings, we assign ports for backward edges
/// by considering the forward edges. We also assign the ports backwards from
/// the most downstream layer to the most upstream layer, so that we can
/// consider both forward and backward edges when assigning ports for backward
/// edges. We approximate the crossing count to reduce the time complexity.
/// Note that the algorithm is not optimal (i.e., due to its greedy nature), but
/// it is efficient and effective in practice.
let private chooseBackwardEdgeBendPoints (edgeSet: EdgeSet) layout portMap =
  for layer in Array.rev layout do
    for src in layer do
      for dst, edge in edgeSet.GetBwdOutEdges(src) do
        assert(dst.VData.Layer + 1 = src.VData.Layer)
        match src.VData.IsDummy, dst.VData.IsDummy with
        (* From dummy to dummy, no need to assign a bend point because the edge
           will be routed as a straight line. *)
        | true, true -> ()
        (* From dummy to destination. The bend point is created in the upper
           layer. *)
        | true, false ->
          chooseBackwardEdgeBendSide edgeSet portMap dst
          |> FromDummyToDest
          |> assignBackwardEdgeBendPoint portMap edge
        (* From source to dummy. The bend point is created in the current layer.
           *)
        | false, true ->
          chooseBackwardEdgeBendSide edgeSet portMap src
          |> FromSourceToDummy
          |> assignBackwardEdgeBendPoint portMap edge
        (* From source to destination. *)
        | false, false ->
          let isLeftForSrc = chooseBackwardEdgeBendSide edgeSet portMap src
          let isLeftForDst = chooseBackwardEdgeBendSide edgeSet portMap dst
          FromSourceToDest(isLeftForSrc, isLeftForDst)
          |> assignBackwardEdgeBendPoint portMap edge

let private assignBackwardEdgeInPorts (edgeSet: EdgeSet) layout portMap =
  // For each real dst, assign bwd in-ports adjacent to fwd in-ports.
  // Left-side: base = leftmost fwd in-port (or cx if none), step outward left.
  // Right-side: base = rightmost fwd in-port (or cx if none), step outward right.
  // Edges sorted by srcCx distance to dstCx: closer = idx 0 = innermost port.
  layout
  |> Array.collect id
  |> Array.filter (fun (v: IVertex<VisBBlock>) -> not v.VData.IsDummy)
  |> Array.iter (fun dst ->
    let cx = getCXPos dst
    let fwdInXs =
      edgeSet.GetFwdInEdges dst
      |> List.map (fun (_, e) -> getDefault (portMap: PortMap).FwdInPorts e cx)
    let leftBase  =
      match fwdInXs |> List.filter (fun x -> x <= cx) with
      | [] -> cx | xs -> List.min xs
    let rightBase =
      match fwdInXs |> List.filter (fun x -> x > cx) with
      | [] -> cx | xs -> List.max xs
    let inEdges =
      edgeSet.GetBwdInEdges dst
      |> List.map (fun (src, edge) -> getCXPos src, edge)
    // Left-side: srcCx < dstCx. Sorted by srcCx descending (closer to dst = inner = idx 0).
    inEdges
    |> List.filter (fun (srcCx, _) -> srcCx < cx - CoordEpsilon)
    |> List.sortBy fst
    |> List.iteri (fun i (_, edge) ->
      portMap.BwdInPorts[edge] <- leftBase - float (i + 1) * EdgeOffset)
    // Right-side: srcCx >= dstCx. Sorted by srcCx ascending (closer to dst = inner = idx 0).
    inEdges
    |> List.filter (fun (srcCx, _) -> srcCx >= cx - CoordEpsilon)
    |> List.sortByDescending fst
    |> List.iteri (fun i (_, edge) ->
      portMap.BwdInPorts[edge] <- rightBase + float (i + 1) * EdgeOffset))

let private assignBackwardEdgePorts (edgeSet: EdgeSet) layout portMap =
  chooseBackwardEdgeBendPoints edgeSet layout portMap
  assignBackwardEdgeInPorts edgeSet layout portMap

let private assignSelfCycleEdgePort (edgeSet: EdgeSet) layout portMap =
  let minOrDefault def xs =
    match xs with
    | [] -> def
    | _ -> List.min xs
  layout
  |> Array.iter (Array.iter (fun v ->
    let cx = getCXPos v
    let fwdOutXs =
      edgeSet.GetFwdOutEdges v
      |> List.map (fun (_, edge) -> getDefault portMap.FwdOutPorts edge cx)
    let fwdInXs =
      edgeSet.GetFwdInEdges v
      |> List.map (fun (_, edge) -> getDefault portMap.FwdInPorts edge cx)
    let outermostOut =
      minOrDefault cx fwdOutXs
    let outermostIn =
      minOrDefault cx fwdInXs
    edgeSet.GetSelfCycleEdge v
    |> List.iteri (fun i (_, edge) ->
      let step = float (i + 1) * EdgeOffset
      portMap.SelfOutPort[edge] <- outermostOut - step
      portMap.SelfInPort[edge] <- outermostIn - step)))

let private assignPorts g layout =
  let portMap = PortMap.Empty
  let edgeSet = (g: VisGraph).Edges |> EdgeSet.Create
  assignForwardEdgePorts edgeSet layout portMap
  assignBackwardEdgePorts edgeSet layout portMap
  assignSelfCycleEdgePort edgeSet layout portMap
  edgeSet, portMap

let private layerY (layer: IVertex<VisBBlock>[]) =
  layer
  |> Array.map VisGraph.getYPos |> Array.min,
  layer
  |> Array.map (fun v -> VisGraph.getYPos v + VisGraph.getHeight v)
  |> Array.max

let private vertexGeometryWithDummyHeight (layerYMap: (float * float)[]) v =
  let cx = getCXPos v
  let top, bot =
    if v.VData.IsDummy then
      let layer = VisGraph.getLayer v
      layerYMap[layer]
    else
      let top = VisGraph.getYPos v
      let bot = top + VisGraph.getHeight v
      top, bot
  cx, top, bot

let private getPortX portMap (edge: VisEdge) (v: IVertex<VisBBlock>) cx =
  if v.VData.IsDummy then getCXPos v else getDefault portMap edge cx

let private routeForwardEdges (edgeSet: EdgeSet) layout portMap =
  let layerYMap = layout |> Array.map layerY
  let addFwdEdgePoint srcX srcBotY dstX dstTopY =
    let pts = ResizeArray<VisPosition>()
    addPoint pts srcX srcBotY
    addPoint pts srcX (srcBotY + StubMargin)
    addPoint pts dstX (dstTopY - StubMargin)
    addPoint pts dstX dstTopY
    pts |> Seq.toArray
  layout
  |> Array.iter (Array.iter (fun src ->
    let srcCx, _, sBotY = vertexGeometryWithDummyHeight layerYMap src
    edgeSet.GetFwdOutEdges src
    |> List.iter (fun (dst, edge) ->
      let dstCx, dTopY, _ = vertexGeometryWithDummyHeight layerYMap dst
      let sPortX = getPortX portMap.FwdOutPorts edge src srcCx
      let dPortX = getPortX portMap.FwdInPorts edge dst dstCx
      edge.Points <- addFwdEdgePoint sPortX sBotY dPortX dTopY)))

/// Compute the safe zone around a vertex: no non-incident edge may enter.
let private safeBox (v: IVertex<VisBBlock>) =
  let x = VisGraph.getXPos v
  let y = VisGraph.getYPos v
  x - StubMargin,
  x + VisGraph.getWidth v + StubMargin,
  y - StubMargin,
  y + VisGraph.getHeight v + StubMargin

/// Check if an X coordinate falls inside a safeBox horizontally.
let private xInSafeBox x (sLeft, sRight, _, _) =
  x > sLeft + CoordEpsilon && x < sRight - CoordEpsilon

/// Check if a vertical segment (at constant X, from y1 to y2) intersects a
/// safeBox vertically. Both the X must be inside and the Y range must overlap.
let private segmentHitsSafeBox x y1 y2 (sLeft, sRight, sTop, sBot) =
  let yLo, yHi = min y1 y2, max y1 y2
  xInSafeBox x (sLeft, sRight, sTop, sBot)
  && yLo < sBot - CoordEpsilon && yHi > sTop + CoordEpsilon

/// Collect safeBoxes of all real (non-dummy) vertices in the layout,
/// excluding given src and dst vertices.
let private collectObstacles (layout: IVertex<VisBBlock>[][])
                             (excludeSrc: IVertex<VisBBlock>)
                             (excludeDst: IVertex<VisBBlock>) =
  layout
  |> Array.collect id
  |> Array.filter (fun v ->
    not v.VData.IsDummy && v <> excludeSrc && v <> excludeDst)
  |> Array.map safeBox

/// Route a vertical segment from (x, y1) to (x, y2), bypassing any safeBox
/// obstacles by detouring around their left or right edge. Returns a list of
/// points (excluding the start point, including the end point).
/// The detour picks the nearer side (left or right) of each obstacle.
let private routeVerticalWithBypass x y1 y2 (obstacles: (float*float*float*float)[]) =
  let goingDown = y2 > y1
  // Find all obstacles that this vertical segment would hit.
  let hits =
    obstacles
    |> Array.filter (fun box -> segmentHitsSafeBox x y1 y2 box)
    |> Array.sortBy (fun (_, _, sTop, _) -> if goingDown then sTop else -sTop)
  if Array.isEmpty hits then
    // No obstacles, straight vertical.
    [ pos x y2 ]
  else
    let mutable pts = []
    let mutable curY = y1
    for (sLeft, sRight, sTop, sBot) in hits do
      let enterY = if goingDown then sTop else sBot
      let exitY  = if goingDown then sBot else sTop
      // Pick bypass side: whichever edge of the safeBox is nearer.
      let bypassX =
        if abs (x - sLeft) <= abs (x - sRight) then sLeft
        else sRight
      // Vertical to obstacle entry.
      pts <- pos x enterY :: pts
      // Horizontal detour to bypass X.
      pts <- pos bypassX enterY :: pts
      // Vertical past the obstacle.
      pts <- pos bypassX exitY :: pts
      // Horizontal back to original X.
      pts <- pos x exitY :: pts
      curY <- exitY
    // Final vertical to destination.
    pts <- pos x y2 :: pts
    List.rev pts

/// Route a straight-line segment from (x1, y1) to (x2, y2) as an orthogonal
/// path, bypassing any safeBox obstacles along the way. The segment is broken
/// into: horizontal move to midX, then vertical move, then horizontal to x2.
/// If x1 = x2, it's a pure vertical with bypass.
/// Returns all points including start and end.
let private routeSegmentWithBypass x1 y1 x2 y2
                                   (obstacles: (float*float*float*float)[]) =
  if abs (x1 - x2) < CoordEpsilon then
    // Pure vertical.
    pos x1 y1 :: routeVerticalWithBypass x1 y1 y2 obstacles
  else
    // Orthogonal L-shape: vertical first on x1, then horizontal to x2.
    // Vertical from (x1, y1) to (x1, y2) with bypass, then horizontal to x2.
    let vertPts = routeVerticalWithBypass x1 y1 y2 obstacles
    pos x1 y1 :: vertPts @ [ pos x2 y2 ]

/// Allocate the next backward out-port X for real vertex v on the given side.
/// Ports are placed outside any existing forward out-ports.
let private createBwdOutPort (edgeSet: EdgeSet) (portMap: PortMap)
                             (outPortCounter: Dictionary<IVertex<VisBBlock>, int * int>)
                             (v: IVertex<VisBBlock>) isLeft =
  let cx = getCXPos v
  let lc, rc =
    match outPortCounter.TryGetValue v with
    | true, counts -> counts
    | _ -> 0, 0
  let fwdOutXs =
    edgeSet.GetFwdOutEdges v
    |> List.map (fun (_, e) -> getDefault portMap.FwdOutPorts e cx)
  if isLeft then
    let leftBase =
      match fwdOutXs |> List.filter (fun x -> x < cx) with
      | [] -> cx | xs -> List.min xs   // fwd 없으면 cx 기준
    let portX = leftBase - float (lc + 1) * EdgeOffset
    outPortCounter[v] <- (lc + 1, rc)
    portX
  else
    let rightBase =
      match fwdOutXs |> List.filter (fun x -> x >= cx) with
      | [] -> cx | xs -> List.max xs   // fwd 없으면 cx 기준
    let portX = rightBase + float (rc + 1) * EdgeOffset
    outPortCounter[v] <- (lc, rc + 1)
    portX

/// Allocate the next backward in-port X for real vertex v on the given side.
/// The port is guaranteed to lie on the correct side of the vertex boundary,
/// so the horizontal stub from bendX to dPortX never crosses the vertex body.
/// Returns (portX, approachIdx) where approachIdx is the 0-based per-side
/// arrival order — used to offset the horizontal approach Y so that parallel
/// incoming stubs on the same side do not overlap.
/// Left side:  lc=0 is innermost (closest to cx), lc increases outward.
///             Higher lc → farther bendX → higher up (smaller Y).
/// Right side: rc=0 is innermost, rc increases outward.
///             Higher rc → farther bendX → higher up (smaller Y).
/// In both cases approachIdx = side-specific counter before increment,
/// so approachY = dstTopY - StubMargin - approachIdx * EdgeOffset.
let private createBwdInPort (edgeSet: EdgeSet) (portMap: PortMap)
                            (inPortCounter: Dictionary<IVertex<VisBBlock>, int * int>)
                            (v: IVertex<VisBBlock>) isLeft =
  let cx = getCXPos v
  let lc, rc =
    match inPortCounter.TryGetValue v with
    | true, counts -> counts
    | _ -> 0, 0
  let fwdInXs =
    edgeSet.GetFwdInEdges v
    |> List.map (fun (_, e) -> getDefault portMap.FwdInPorts e cx)
  if isLeft then
    // Port goes to the left of dst.  lc is the per-left-side index (0 = innermost).
    let vLeft = VisGraph.getXPos v
    let leftBase =
      match fwdInXs |> List.filter (fun x -> x < cx) with
      | [] -> vLeft | xs -> List.min xs
    let portX = leftBase - float (lc + 1) * EdgeOffset
    let approachIdx = lc
    inPortCounter[v] <- (lc + 1, rc)
    portX, approachIdx
  else
    // Port goes to the right of dst.  rc is the per-right-side index (0 = innermost).
    let vRight = VisGraph.getXPos v + VisGraph.getWidth v
    let rightBase =
      match fwdInXs |> List.filter (fun x -> x >= cx) with
      | [] -> vRight | xs -> List.max xs
    let portX = rightBase + float (rc + 1) * EdgeOffset
    let approachIdx = rc
    inPortCounter[v] <- (lc, rc + 1)
    portX, approachIdx

/// Assign backward edge ports dynamically and route in a single bottom-to-top
/// pass. For each vertex's BwdOutEdges we assign ports and emit polyline points.
///
/// The in-port side is determined by where bendX lies relative to dst, so the
/// horizontal stub from bendX to dPortX never crosses the dst vertex body.
///
/// For dummy-involving segments (dummy→dummy, real→dummy tail, dummy→real head),
/// the straight-line path is routed orthogonally with safeBox bypass to avoid
/// penetrating other vertices' safe zones.
///
/// Segment shapes:
///   real→real : sPortX,srcBotY → sPortX,srcBotY+stub → bendX,srcBotY+stub
///               → bendX,dstTopY-stub → dPortX,dstTopY-stub → dPortX,dstTopY
///   real→dummy: sPortX,srcBotY → sPortX,srcBotY+stub → bendX,srcBotY+stub
///               → [bypass-aware path to] dstCx,dstTopY
///   dummy→dummy: [bypass-aware path from] srcCx,srcBotY → dstCx,dstTopY
///   dummy→real : [bypass-aware path from] srcCx,srcBotY+stub → bendX,dstTopY-stub
///                → dPortX,dstTopY-stub → dPortX,dstTopY
let private assignAndRouteBackwardEdges (edgeSet: EdgeSet) layout portMap =
  let layerYMap = layout |> Array.map layerY
  let bendSlots = getBendSlots layout edgeSet portMap
  let outPortCounter = Dictionary<IVertex<VisBBlock>, int * int>()
  let resolveBendX edge fallbackX =
    match bendSlots.TryGetValue edge with
    | true, x -> x
    | _ -> fallbackX
  // src가 dst 좌측에 있으면 좌측 safeBox로 도달.
  let dstSideIsLeft srcCx dstCx = srcCx < dstCx - CoordEpsilon
  // Pre-pass: for each real dst, assign per-side approachIdx.
  // idx=0: innermost (safeBox 경계에 가장 가깝게, 가장 아래 Y).
  // Left side: bendX 내림차순 (dstCx에 가까울수록 inner).
  // Right side: bendX 오름차순 (dstCx에 가까울수록 inner).
  let approachIdxMap = Dictionary<VisEdge, int>()
  layout
  |> Array.collect id
  |> Array.filter (fun v -> not v.VData.IsDummy)
  |> Array.iter (fun dst ->
    let dstCx = getCXPos dst
    let inEdges =
      edgeSet.GetBwdInEdges dst
      |> List.map (fun (src, edge) ->
        let srcCx_ = getCXPos src
        let isLeft = dstSideIsLeft srcCx_ dstCx
        srcCx_, isLeft, edge)
    // Left-side: srcCx 내림차순 (가장 가까운 src = idx 0 = safeBox 가장 하단 railX)
    inEdges
    |> List.filter (fun (_, isLeft, _) -> isLeft)
    |> List.sortByDescending (fun (srcCx_, _, _) -> srcCx_)
    |> List.iteri (fun i (_, _, edge) -> approachIdxMap[edge] <- i)
    // Right-side: srcCx 오름차순 (가장 가까운 src = idx 0 = safeBox 가장 하단 railX)
    inEdges
    |> List.filter (fun (_, isLeft, _) -> not isLeft)
    |> List.sortBy (fun (srcCx_, _, _) -> srcCx_)
    |> List.iteri (fun i (_, _, edge) -> approachIdxMap[edge] <- i))
  // Arrival geometry for a real dst:
  // railX  = safeBox 측면 레일 X (외부, idx에 따라 이격)
  // inPortX = portMap.BwdInPorts (정점 내부 포트 X)
  // sideY  = dstBotY - StubMargin - idx*EdgeOffset
  // topY   = dstTopY - StubMargin - idx*EdgeOffset
  //
  // 경로: 사선→(railX,sideY) → 수직→(railX,topY) → 수평→(inPortX,topY) → 수직→(inPortX,dstTopY)
  let computeArrival (dst: IVertex<VisBBlock>) (edge: VisEdge) isLeft idx =
    let dstLeft  = VisGraph.getXPos dst
    let dstRight = dstLeft + VisGraph.getWidth dst
    let dstTopY  = VisGraph.getYPos dst
    let dstBotY  = dstTopY + VisGraph.getHeight dst
    let dstSafeX = if isLeft then dstLeft  - StubMargin
                   else           dstRight + StubMargin
    // railX: idx=0은 safeBox 경계, 이후 바깥으로 이격
    let railX    = if isLeft then dstSafeX - float idx * EdgeOffset
                   else           dstSafeX + float idx * EdgeOffset
    let sideY    = dstBotY - float idx * EdgeOffset
    let topY     = dstTopY - StubMargin - float idx * EdgeOffset
    let inPortX  = getDefault portMap.BwdInPorts edge (getCXPos dst)
    railX, sideY, topY, inPortX, dstTopY
  for layerIdx in Array.length layout - 1 .. -1 .. 0 do
    for src in layout[layerIdx] do
      let srcCx = getCXPos src
      let srcIsDummy = src.VData.IsDummy
      let srcBotY =
        if srcIsDummy then layerYMap[src.VData.Layer] |> snd
        else VisGraph.getYPos src + VisGraph.getHeight src
      edgeSet.GetBwdOutEdges src |> List.iter (fun (dst, edge) ->
        let dstCx = getCXPos dst
        let dstIsDummy = dst.VData.IsDummy
        let dstTopY =
          if dstIsDummy then layerYMap[dst.VData.Layer] |> fst
          else VisGraph.getYPos dst
        let obs = collectObstacles layout src dst
        match srcIsDummy, dstIsDummy with
        | true, true ->
          let srcCx_, sTopY, sBotY = vertexGeometryWithDummyHeight layerYMap src
          let dstCx_, dTopY, _ = vertexGeometryWithDummyHeight layerYMap dst
          edge.Points <-
            [| pos srcCx_ sTopY
               pos dstCx_ dTopY |]
        | false, false ->
          let bendX     = resolveBendX edge srcCx
          let srcIsLeft = bendX < srcCx
          let sPortX    = createBwdOutPort edgeSet portMap outPortCounter src srcIsLeft
          let dstIsLeft = dstSideIsLeft srcCx dstCx
          let idx       = getDefault approachIdxMap edge 0
          let railX, sideY, topY, inPortX, dstTopY_ = computeArrival dst edge dstIsLeft idx
          let srcTopY   = VisGraph.getYPos src
          let srcSafeX  =
            if srcIsLeft then VisGraph.getXPos src - StubMargin
            else VisGraph.getXPos src + VisGraph.getWidth src + StubMargin
          edge.Points <-
            [| pos sPortX   srcBotY
               pos sPortX   (srcBotY + StubMargin)
               pos srcSafeX (srcBotY + StubMargin)
               pos srcSafeX (srcTopY - StubMargin)
               pos bendX    (srcTopY - StubMargin)
               pos railX    sideY    // 사선: safeBox 측면 레일 도달
               pos railX    topY     // 수직: dst 상단 위
               pos inPortX  topY     // 수평: 내부 포트로 90도
               pos inPortX  dstTopY_ |] // 수직: dst top 진입
        | false, true ->
          let bendX   = resolveBendX edge srcCx
          let srcIsLeft = bendX < srcCx
          let sPortX  = createBwdOutPort edgeSet portMap outPortCounter src srcIsLeft
          let srcTopY = VisGraph.getYPos src
          let srcSafeX =
            if srcIsLeft then VisGraph.getXPos src - StubMargin
            else VisGraph.getXPos src + VisGraph.getWidth src + StubMargin
          let dstCx_, dTopY, _ = vertexGeometryWithDummyHeight layerYMap dst
          edge.Points <-
            [| pos sPortX   srcBotY
               pos sPortX   (srcBotY + StubMargin)
               pos srcSafeX (srcBotY + StubMargin)
               pos srcSafeX (srcTopY - StubMargin)
               pos dstCx_   dTopY |]
        | true, false ->
          let dstIsLeft = dstSideIsLeft srcCx dstCx
          let idx       = getDefault approachIdxMap edge 0
          let railX, sideY, topY, inPortX, dstTopY_ = computeArrival dst edge dstIsLeft idx
          let srcTopY   = VisGraph.getYPos src
          edge.Points <-
            [| pos srcCx   srcTopY
               pos railX   sideY    // 사선: dst safeBox 측면 레일
               pos railX   topY     // 수직: dst 상단 위
               pos inPortX topY     // 수평: 내부 포트로 90도
               pos inPortX dstTopY_ |]) // 수직: dst top 진입

let private routeSelfCycleEdge (edgeSet: EdgeSet) layout portMap =
  layout
  |> Array.iter (Array.iter (fun v ->
    let pts = ResizeArray<VisPosition>()
    if List.isEmpty (edgeSet.GetSelfCycleEdge v) |> not then
      let srcCx = getCXPos v
      let topY = VisGraph.getYPos v
      let leftX = srcCx - VisGraph.getWidth v / 2.0
      let botY = topY + VisGraph.getHeight v
      edgeSet.GetSelfCycleEdge v
      |> List.iter (fun (_, edge: VisEdge) ->
        let sPortX = getPortX portMap.SelfOutPort edge v srcCx
        let dPortX = getPortX portMap.SelfInPort edge v srcCx
        addPoint pts sPortX botY
        addPoint pts sPortX (botY + 20.0)
        addPoint pts (leftX - 20.0) (botY + 20.0)
        addPoint pts (leftX - 20.0) (topY - 20.0)
        addPoint pts dPortX (topY - 20.0)
        addPoint pts dPortX topY
        edge.Points <- pts |> Seq.toArray)
    else
      ()))

let private routeEdges layout (edgeSet, portMap) =
  expandLayerGap edgeSet layout
  //routeForwardEdges edgeSet layout portMap
  assignAndRouteBackwardEdges edgeSet layout portMap
  routeSelfCycleEdge edgeSet layout portMap

let private restoreBackEdges (g: VisGraph) backEdgeList =
  backEdgeList
  |> List.iter (fun (src, dst, edge) ->
    match g.TryFindEdge(dst, src) with
    | Some e when e.Label.IsBackEdge -> g.RemoveEdge(dst, src) |> ignore
    | _ -> ()
    g.AddEdge(src, dst, edge) |> ignore
  )

let rec private removeDummyLoop (g: VisGraph) src dst points = function
  | dummy :: rest ->
    let e = g.FindEdge(src, dummy)
    g.RemoveEdge(src, dummy) |> ignore
    removeDummyLoop g dummy dst (Array.append points e.Label.Points) rest
  | [] ->
    let e = g.FindEdge(src, dst)
    g.RemoveEdge(src, dst) |> ignore
    Array.append points e.Label.Points

let private makeSmooth (points: VisPosition array) =
  let rec loop acc prev = function
    | [] -> acc
    | h1 :: h2 :: [] -> List.rev (h2 :: h1 :: acc)
    | (hd: VisPosition) :: tl ->
      match prev with
      | None -> loop (hd :: acc) (Some hd.Y) tl
      | Some p ->
        if p <= hd.Y then loop (hd :: acc) (Some hd.Y) tl else loop acc prev tl
  match Array.toList points with
  | hd1 :: hd2 :: rest -> hd1 :: hd2 :: loop [] None rest |> List.toArray
  | xs -> List.toArray xs

/// Collapse redundant points in a concatenated backward edge path.
/// Pass 1: remove exact duplicate consecutive points.
/// Pass 2: remove interior point b when a-b-c are collinear (same X or same Y).
let private smoothBwdEdge (points: VisPosition array) =
  let sameX (a: VisPosition) (b: VisPosition) = abs (a.X - b.X) < CoordEpsilon
  let sameY (a: VisPosition) (b: VisPosition) = abs (a.Y - b.Y) < CoordEpsilon
  // Remove exact duplicates
  let dedup (pts: VisPosition list) =
    pts |> List.fold (fun acc p ->
      match acc with
      | prev :: _ when sameX prev p && sameY prev p -> acc
      | _ -> p :: acc) []
    |> List.rev
  // Remove collinear interior points
  let rec collapse = function
    | [] | [ _ ] | [ _; _ ] as xs -> xs
    | a :: b :: c :: rest when (sameX a b && sameX b c)
                             || (sameY a b && sameY b c) ->
      collapse (a :: c :: rest)
    | hd :: tl -> hd :: collapse tl
  points |> Array.toList |> dedup |> collapse |> List.toArray

let private makeEdgeSmooth g (src, dst) (edge: VisEdge, dummies) =
  if List.isEmpty dummies then
    ()
  else
    let rawPts = removeDummyLoop g src dst [||] dummies
    let pts =
      if edge.IsBackEdge then smoothBwdEdge rawPts
      else makeSmooth rawPts
    let newEdge = VisEdge edge.Type
    newEdge.IsBackEdge <- edge.IsBackEdge
    newEdge.Points <- pts
    g.AddEdge(src, dst, newEdge) |> ignore
  dummies |> List.iter (g.RemoveVertex >> ignore)

let private postprocessEdges (g: VisGraph) dummyMap =
  dummyMap |> Map.iter (makeEdgeSmooth g)

let drawEdges g vLayout backEdgeList dummyMap =
  restoreBackEdges g backEdgeList
  routeEdges vLayout (assignPorts g vLayout)
  postprocessEdges g dummyMap