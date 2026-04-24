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

let private layerY (layer: IVertex<VisBBlock>[]) =
  layer |> Array.map VisGraph.getYPos |> Array.min, layerBotY layer

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

let private getMaxDegree edges layer =
  layer |> Array.map (edges >> List.length) |> Array.max

let private downShiftLayers layers deltaY =
  if deltaY > 0.0 then
    Array.iter (Array.iter (fun (v: IVertex<VisBBlock>) ->
      let blk = v.VData
      blk.Coordinate.Y <- blk.Coordinate.Y + deltaY)) layers
  else
    ()

let private expandLayerGap (edgeSet: EdgeSet) (layout: IVertex<VisBBlock>[][]) =
  let layerCount = layout.Length
  let maxInDegrees = layout |> Array.map (getMaxDegree edgeSet.GetInEdges)
  let maxOutDegrees = layout |> Array.map (getMaxDegree edgeSet.GetOutEdges)
  let layerBounds = layout |> Array.map layerY
  let bwdOutCounts =
    layout
    |> Array.map (fun layer ->
      layer |> Array.sumBy (fun v -> edgeSet.GetBwdOutEdges v |> List.length))
  let bwdInCounts =
    layout
    |> Array.map (fun layer ->
      layer |> Array.sumBy (fun v -> edgeSet.GetBwdInEdges v |> List.length))
  let degreeShifts = Array.zeroCreate<float> layerCount
  let gapShifts = Array.zeroCreate<float> layerCount
  let mutable cumulativeShift = 0.0
  for layerIdx in 0 .. layerCount - 1 do
    let inDeg = maxInDegrees[layerIdx]
    if inDeg >= LayerHeightExpansionThreshold then
      cumulativeShift <- cumulativeShift + EdgeOffset * float inDeg
    else
      ()
    degreeShifts[layerIdx] <- cumulativeShift
    let outDeg = maxOutDegrees[layerIdx]
    if outDeg >= LayerHeightExpansionThreshold && layerIdx + 1 < layerCount then
      cumulativeShift <- cumulativeShift + EdgeOffset * float outDeg
    else
      ()
  let mutable cumulativeGapShift = 0.0
  for bandIdx in 0 .. layerCount - 2 do
    let _, curLayerBottom = layerBounds[bandIdx]
    let nextLayerTop, _ = layerBounds[bandIdx + 1]
    let total = bwdOutCounts[bandIdx] + bwdInCounts[bandIdx + 1]
    if total > 0 then
      let requiredGap = 2.0 * StubMargin + float total * EdgeOffset
      let currentGap =
        (nextLayerTop + degreeShifts[bandIdx + 1])
        - (curLayerBottom + degreeShifts[bandIdx])
      let deficit = requiredGap - currentGap
      if deficit > 0.0 then
        cumulativeGapShift <- cumulativeGapShift + deficit
      else
        ()
    else
      ()
    gapShifts[bandIdx + 1] <- cumulativeGapShift
  for layerIdx in 0 .. layerCount - 1 do
    let deltaY = degreeShifts[layerIdx] + gapShifts[layerIdx]
    if deltaY > 0.0 then
      layout[layerIdx]
      |> Array.iter (fun (v: IVertex<VisBBlock>) ->
        let blk = v.VData
        blk.Coordinate.Y <- blk.Coordinate.Y + deltaY)
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

let private computeCrossings edgeSet portMap edges src srcBendX dstBendX =
  let isSrcLeft = srcBendX < getCXPos src
  let crossingsWithFowards =
    edges
    |> List.filter (fun (x1, x2) ->
      (x1 < dstBendX && x2 > srcBendX) || (x1 > dstBendX && x2 < srcBendX))
    |> List.length
  let crossingsWithBackwards =
    (edgeSet: EdgeSet).GetBwdInEdges(src)
    |> List.filter (fun (_, e) ->
      match (portMap: PortMap).BwdEdgeBendPoints.TryGetValue e with
      | true, FromSourceToDest(_, isDstLeft)
      | true, FromDummyToDest(isDstLeft) -> isDstLeft = isSrcLeft
      | _ -> false)
    |> List.length
  crossingsWithFowards + crossingsWithBackwards

/// Consider only the forward edges from the upper layer, as backward edges from
/// this layer will fairly affect the crossing count regardless of the bend
/// point choice by either increasing the same amount of crossings or not
/// affecting the crossing count at all. This can be proven logically.
let private collectInEdgesFromUpperLayer (edgeSet: EdgeSet) layer =
  (layer: IVertex<VisBBlock>[])
  |> Seq.collect (fun dst ->
    edgeSet.GetFwdInEdges(dst)
    |> List.map (fun (src, _) -> getCXPos src, getCXPos dst))
  |> Seq.toList

let private collectPossibleBendPoints edgeSet portMap edges src dst =
  [ for isLeftForSrc in [ true; false ] do
      for isLeftForDst in [ true; false ] do
        let srcX = getCXPos src + if isLeftForSrc then -1. else 1.
        let dstX = getCXPos dst + if isLeftForDst then -1. else 1.
        computeCrossings edgeSet portMap edges src srcX dstX,
        isLeftForSrc, isLeftForDst ]

/// To minimize the edge crossings, we assign ports for backward edges
/// by considering the forward edges. We also assign the ports backwards from
/// the most downstream layer to the most upstream layer, so that we can
/// consider both forward and backward edges when assigning ports for backward
/// edges. We approximate the crossing count to reduce the time complexity.
/// Note that the algorithm is not optimal (i.e., due to its greedy nature), but
/// it is efficient and effective in practice.
let private chooseBackwardEdgeBendPoints (edgeSet: EdgeSet) layout portMap =
  for layer in Array.rev layout do
    let edges = collectInEdgesFromUpperLayer edgeSet layer
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
          let srcXPos = getCXPos src
          let dstXPos = getCXPos dst
          [ computeCrossings edgeSet portMap edges src srcXPos (dstXPos - 1.),
            true
            computeCrossings edgeSet portMap edges src srcXPos (dstXPos + 1.),
            false ]
          |> List.sortBy (fun (sum, _) -> sum)
          |> List.head
          |> snd
          |> FromDummyToDest
          |> assignBackwardEdgeBendPoint portMap edge
        (* From source to dummy. The bend point is created in the current layer.
           *)
        | false, true ->
          let srcXPos = getCXPos src
          let dstXPos = getCXPos dst
          [ computeCrossings edgeSet portMap edges src (srcXPos - 1.) dstXPos,
            true
            computeCrossings edgeSet portMap edges src (srcXPos + 1.) dstXPos,
            false ]
          |> List.sortBy (fun (sum, _) -> sum)
          |> List.head
          |> snd
          |> FromSourceToDummy
          |> assignBackwardEdgeBendPoint portMap edge
        (* From source to destination. *)
        | false, false ->
          collectPossibleBendPoints edgeSet portMap edges src dst
          |> List.sortBy (fun (sum, _, _) -> sum)
          |> List.head
          |> fun (_, isLeftForSrc, isLeftForDst) ->
            FromSourceToDest(isLeftForSrc, isLeftForDst)
            |> assignBackwardEdgeBendPoint portMap edge

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
  chooseBackwardEdgeBendPoints edgeSet layout portMap
  assignSelfCycleEdgePort edgeSet layout portMap
  edgeSet, portMap

let private getPortX portMap (edge: VisEdge) (v: IVertex<VisBBlock>) cx =
  if v.VData.IsDummy then getCXPos v else getDefault portMap edge cx

let private routeForwardEdges (edgeSet: EdgeSet) layout portMap fwdArrivalTopY =
  let layerYMap = layout |> Array.map layerY
  let addFwdEdgePoint srcX srcBotY dstX arrivalTopY dstTopY =
    let pts = ResizeArray<VisPosition>()
    addPoint pts srcX srcBotY
    addPoint pts srcX (srcBotY + StubMargin)
    addPoint pts dstX arrivalTopY
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
      let arrivalTopY =
        getDefault fwdArrivalTopY edge (dTopY - StubMargin)
      edge.Points <- addFwdEdgePoint sPortX sBotY dPortX arrivalTopY dTopY)))

let private findRealBwdDst (edgeSet: EdgeSet) (dst: IVertex<VisBBlock>) =
  let rec loop (v: IVertex<VisBBlock>) =
    if not v.VData.IsDummy then v
    else
      match edgeSet.GetBwdOutEdges v with
      | (next, _) :: _ -> loop next
      | [] -> v
  loop dst

/// Compute the layer distance between src and the ultimate real destination.
let private computeEdgeDistance edgeSet (src: IVertex<VisBBlock>) dst =
  let srcLayer = src.VData.Layer
  let realDst = findRealBwdDst edgeSet dst
  srcLayer - realDst.VData.Layer

/// Extract the destination-side direction from a BendPoint.
let private getDstIsLeft = function
  | FromSourceToDest(_, isDstLeft) -> isDstLeft
  | FromDummyToDest(isDstLeft) -> isDstLeft
  | FromSourceToDummy _ -> failwith "no dst side for src→dummy"

/// Extract the source-side direction from a BendPoint.
let private getSrcIsLeft = function
  | FromSourceToDest(isSrcLeft, _) -> isSrcLeft
  | FromSourceToDummy(isSrcLeft) -> isSrcLeft
  | FromDummyToDest _ -> failwith "no src side for dummy→dst"

/// Compute arrival geometry for a backward edge arriving at a real destination.
/// Returns railX, sideY, topY, dstTopY.
/// sideY is placed below the dst safe zone so the edge approaches the rail
/// without penetrating the dst vertex box.
let private computeArrivalGeometry (dst: IVertex<VisBBlock>) isLeft idx =
  let dstLeft = VisGraph.getXPos dst
  let dstRight = dstLeft + VisGraph.getWidth dst
  let dstTopY = VisGraph.getYPos dst
  let dstSafeX = if isLeft then dstLeft - StubMargin else dstRight + StubMargin
  let railX =
    if isLeft then dstSafeX - float idx * EdgeOffset
    else dstSafeX + float idx * EdgeOffset
  let topY = dstTopY - StubMargin - float idx * EdgeOffset
  railX, topY, dstTopY

/// Assign backward in-ports for a real destination vertex based on BendPoint
/// direction and railX positions. Port ordering follows railX within each side.
let private assignBwdInPorts (edgeSet: EdgeSet) portMap railX rDsts =
  for dst in rDsts do
    if edgeSet.GetBwdInEdges dst |> List.isEmpty |> not then
      let cx = getCXPos dst
      let fwdInXs =
        edgeSet.GetFwdInEdges dst
        |> List.map (fun (_, e) -> getDefault portMap.FwdInPorts e cx)
      let leftBase =
        match fwdInXs |> List.filter (fun x -> x <= cx) with
        | [] -> cx
        | xs -> List.min xs
      let rightBase =
        match fwdInXs |> List.filter (fun x -> x > cx) with
        | [] -> cx
        | xs -> List.max xs
      let inEdges =
        edgeSet.GetBwdInEdges dst
        |> List.choose (fun (_, edge) ->
          match portMap.BwdEdgeBendPoints.TryGetValue edge with
          | true, bp ->
            let isDstLeft = getDstIsLeft bp
            let rx = getDefault railX edge cx
            Some(isDstLeft, rx, edge)
          | _ -> None)
      inEdges
      |> List.filter (fun (isDstLeft, _, _) -> isDstLeft)
      |> List.sortBy (fun (_, rx, _) -> rx)
      |> List.iteri (fun i (_, _, edge) ->
        portMap.BwdInPorts[edge] <- leftBase - float (i + 1) * EdgeOffset)
      inEdges
      |> List.filter (fun (isDstLeft, _, _) -> not isDstLeft)
      |> List.sortByDescending (fun (_, rx, _) -> rx)
      |> List.iteri (fun i (_, _, edge) ->
        portMap.BwdInPorts[edge] <- rightBase + float (i + 1) * EdgeOffset)
    else
      ()

let private allocateBwdOutPorts edgeSet portMap departureIdx v srcIsLeft edges =
  let cx = getCXPos v
  let fwdOutXs =
    (edgeSet: EdgeSet).GetFwdOutEdges v
    |> List.map (fun (_, e) -> getDefault portMap.FwdOutPorts e cx)
  let baseX =
    if srcIsLeft then
      match fwdOutXs |> List.filter (fun x -> x < cx) with
      | [] -> cx
      | xs -> List.min xs
    else
      match fwdOutXs |> List.filter (fun x -> x >= cx) with
      | [] -> cx
      | xs -> List.max xs
  let cross, same =
    edges |> List.partition (fun (_, _, isCross, _) -> isCross)
  let crossSorted =
    cross |> List.sortByDescending (fun (_, _, _, dist) -> dist)
  let sameSorted =
    same |> List.sortBy (fun (_, _, _, dist) -> dist)
  let ordered = crossSorted @ sameSorted
  let count = List.length ordered
  ordered |> List.iteri (fun i (_, edge, _, _) ->
    let outerIdx = count - i
    let portX =
      if srcIsLeft then baseX - float outerIdx * EdgeOffset
      else baseX + float outerIdx * EdgeOffset
    portMap.BwdOutPorts[edge] <- portX
    (departureIdx: Dictionary<_, _>)[edge] <- i)

let private getRealVertices layout =
  layout
  |> Array.collect id
  |> Array.filter (fun (v: IVertex<VisBBlock>) -> not v.VData.IsDummy)

let private isCrossAtDstSafeX dst dstIsLeft src =
  let dstSafeX =
    if dstIsLeft then VisGraph.getXPos dst - StubMargin
    else VisGraph.getXPos dst + VisGraph.getWidth dst + StubMargin
  let srcCx = getCXPos src
  if dstIsLeft then srcCx > dstSafeX else srcCx < dstSafeX

let private assignBwdOutPorts (edgeSet: EdgeSet) portMap depIdx rSrcs =
  for src in rSrcs do
    let outEdges = edgeSet.GetBwdOutEdges src
    if not (List.isEmpty outEdges) then
      let edgesWithInfo =
        outEdges |> List.choose (fun (dst, edge) ->
          match portMap.BwdEdgeBendPoints.TryGetValue edge with
          | true, bp ->
            let srcIsLeft = getSrcIsLeft bp
            let realDst = findRealBwdDst edgeSet dst
            let dstIsLeft =
              match bp with
              | FromSourceToDest(_, d) -> d
              | FromSourceToDummy _ -> srcIsLeft
              | FromDummyToDest _ -> Terminator.impossible ()
            let isCross = isCrossAtDstSafeX realDst dstIsLeft src
            let dist = computeEdgeDistance edgeSet src dst
            Some(dst, edge, srcIsLeft, isCross, dist)
          | _ -> None)
      let leftEdges =
        edgesWithInfo
        |> List.filter (fun (_, _, srcIsLeft, _, _) -> srcIsLeft)
        |> List.map (fun (d, e, _, isCross, dist) -> d, e, isCross, dist)
      allocateBwdOutPorts edgeSet portMap depIdx src true leftEdges
      let rightEdges =
        edgesWithInfo
        |> List.filter (fun (_, _, srcIsLeft, _, _) -> not srcIsLeft)
        |> List.map (fun (d, e, _, isCross, dist) -> d, e, isCross, dist)
      allocateBwdOutPorts edgeSet portMap depIdx src false rightEdges
    else
      ()

let private assignCrossMidYOffset dst crossEdges crossMidYOffset =
  let dstTopY = VisGraph.getYPos dst
  let dstBotY = dstTopY + VisGraph.getHeight dst
  let baseY = dstBotY + StubMargin
  crossEdges
  |> List.iteri (fun i (_, edge, _) ->
    (crossMidYOffset: Dictionary<_, _>)[edge] <- baseY + float i * EdgeOffset)

let private computeForwardArrivalTopY (edgeSet: EdgeSet) portMap realVertices =
  let fwdArrivalTopY = Dictionary<VisEdge, float>()
  for dst in (realVertices: _[]) do
    let dstTopY = VisGraph.getYPos dst
    let fwdInEdges = edgeSet.GetFwdInEdges dst
    if not (List.isEmpty fwdInEdges) then
      let bwdInEdges =
        edgeSet.GetBwdInEdges dst
        |> List.choose (fun (_, edge) ->
          match portMap.BwdEdgeBendPoints.TryGetValue edge with
          | true, bp ->
            let isLeft = getDstIsLeft bp
            Some(edge, isLeft)
          | _ -> None)
      let leftMaxIdx =
        bwdInEdges |> List.filter snd |> List.length
      let rightMaxIdx =
        bwdInEdges |> List.filter (snd >> not) |> List.length
      let leftBarrierY =
        if leftMaxIdx = 0 then dstTopY - StubMargin
        else dstTopY - StubMargin - float (leftMaxIdx - 1) * EdgeOffset
      let rightBarrierY =
        if rightMaxIdx = 0 then dstTopY - StubMargin
        else dstTopY - StubMargin - float (rightMaxIdx - 1) * EdgeOffset
      fwdInEdges
      |> List.iter (fun (src, edge) ->
        let dPortX = getDefault portMap.FwdInPorts edge (getCXPos dst)
        let isLeft = dPortX < getCXPos dst
        let barrierY = if isLeft then leftBarrierY else rightBarrierY
        fwdArrivalTopY[edge] <- barrierY - EdgeOffset)
    else
      ()
  fwdArrivalTopY

let private assignApproachIndices (approachMap: Dictionary<_, _>) first second =
  let mutable index = 0
  for _, edge, _ in first do
    approachMap[edge] <- index
    index <- index + 1
  for _, edge, _ in second do
    approachMap[edge] <- index
    index <- index + 1

let private computeRailXForEdgeArriving (edgeSet: EdgeSet)
                                        portMap
                                        (railXMap: Dictionary<VisEdge, float>)
                                        (crossMidYOffset: Dictionary<_, _>)
                                        (approachMap: Dictionary<VisEdge, int>)
                                        (approachIdx: Dictionary<_, _>)
                                        rDsts =
  for dst in rDsts do
    let inEdges = edgeSet.GetBwdInEdges dst
    if not (List.isEmpty inEdges) then
      let edgesWithInfo =
        inEdges
        |> List.choose (fun (src, edge) ->
          match portMap.BwdEdgeBendPoints.TryGetValue edge with
          | true, bp ->
            let dstIsLeft = getDstIsLeft bp
            Some(src, edge, dstIsLeft)
          | _ -> None)
      let leftArrivals =
        edgesWithInfo |> List.filter (fun (_, _, dstIsLeft) -> dstIsLeft)
      let leftCross =
        leftArrivals
        |> List.filter (fun (src, _, _) -> isCrossAtDstSafeX dst true src)
        |> List.sortByDescending (fun (src, _, _) -> getCXPos src)
      let leftSame =
        leftArrivals
        |> List.filter (fun (src, _, _) -> not (isCrossAtDstSafeX dst true src))
        |> List.sortByDescending (fun (src, _, _) -> getCXPos src)
      assignCrossMidYOffset dst leftCross crossMidYOffset
      assignApproachIndices approachMap leftCross leftSame
      let rightArrivals =
        edgesWithInfo
        |> List.filter (fun (_, _, dstIsLeft) -> not dstIsLeft)
      let rightCross =
        rightArrivals
        |> List.filter (fun (src, _, _) -> isCrossAtDstSafeX dst false src)
        |> List.sortBy (fun (src, _, _) -> getCXPos src)
      let rightSame =
        rightArrivals
        |> List.filter (fun (src, _, _) ->
          not (isCrossAtDstSafeX dst false src))
        |> List.sortBy (fun (src, _, _) -> getCXPos src)
      assignCrossMidYOffset dst rightCross crossMidYOffset
      assignApproachIndices approachMap rightCross rightSame
      approachIdx[dst] <- approachMap
      for (_, edge, dstIsLeft) in edgesWithInfo do
        let idx = getDefault approachMap edge 0
        let railXVal, _, _ = computeArrivalGeometry dst dstIsLeft idx
        railXMap[edge] <- railXVal
    else
      ()

let private preprocessBackwardRouting (edgeSet: EdgeSet) layout portMap =
  let dIdx = Dictionary<VisEdge, int>()
  let aMap = Dictionary<VisEdge, int>()
  let aIdx = Dictionary<IVertex<VisBBlock>, Dictionary<VisEdge, int>>()
  let railMap = Dictionary<VisEdge, float>()
  let crossYOffset = Dictionary<VisEdge, float>()
  let realVertices = getRealVertices layout
  assignBwdOutPorts edgeSet portMap dIdx realVertices
  computeRailXForEdgeArriving
    edgeSet portMap railMap crossYOffset aMap aIdx realVertices
  assignBwdInPorts edgeSet portMap railMap realVertices
  dIdx, aIdx, crossYOffset, realVertices

let private routeBackwardEdges (edgeSet: EdgeSet) layout portMap dIdx aIdx
  crossYOffset =
  let layerYMap = layout |> Array.map layerY
  let bendX v isLeft =
    if isLeft then VisGraph.getXPos v - StubMargin
    else VisGraph.getXPos v + VisGraph.getWidth v + StubMargin
  for layerIdx in Array.length layout - 1 .. -1 .. 0 do
    for src in layout[layerIdx] do
      let srcCx = getCXPos src
      let srcIsDummy = src.VData.IsDummy
      let srcBotY =
        if srcIsDummy then layerYMap[src.VData.Layer] |> snd
        else VisGraph.getYPos src + VisGraph.getHeight src
      edgeSet.GetBwdOutEdges src
      |> List.iter (fun (dst, edge) ->
        let dstIsDummy = dst.VData.IsDummy
        match srcIsDummy, dstIsDummy with
        | true, true ->
          let srcCx, sTopY, _ = vertexGeometryWithDummyHeight layerYMap src
          let dstCx, dTopY, _ = vertexGeometryWithDummyHeight layerYMap dst
          edge.Points <-
            [| pos srcCx sTopY
               pos dstCx dTopY |]
        | false, true ->
          let srcIsLeft = getSrcIsLeft (portMap.BwdEdgeBendPoints[edge])
          let sPortX = getDefault portMap.BwdOutPorts edge srcCx
          let depIdx = getDefault dIdx edge 0
          let srcTopY = VisGraph.getYPos src
          let stubY = srcBotY + StubMargin + float depIdx * EdgeOffset
          let srcSafeX =
            if srcIsLeft then
              VisGraph.getXPos src - StubMargin - float depIdx * EdgeOffset
            else
              VisGraph.getXPos src + VisGraph.getWidth src + StubMargin
              + float depIdx * EdgeOffset
          let dstCx, dTopY, dBotY = vertexGeometryWithDummyHeight layerYMap dst
          edge.Points <-
            [| pos sPortX srcBotY
               pos sPortX stubY
               pos srcSafeX stubY
               pos srcSafeX (srcTopY - StubMargin)
               pos dstCx (dBotY + StubMargin)
               pos dstCx dTopY |]
        | false, false ->
          let bp = portMap.BwdEdgeBendPoints[edge]
          let srcIsLeft = getSrcIsLeft bp
          let dstIsLeft = getDstIsLeft bp
          let bendX = bendX src srcIsLeft
          let sPortX = getDefault portMap.BwdOutPorts edge srcCx
          let depIdx = getDefault dIdx edge 0
          let idx =
            match (aIdx: Dictionary<_, _>).TryGetValue dst with
            | true, m -> getDefault m edge 0
            | _ -> 0
          let railX, topY, dstTopY =
            computeArrivalGeometry dst dstIsLeft idx
          let adjustedY = getDefault crossYOffset edge topY
          let inPortX = getDefault portMap.BwdInPorts edge (getCXPos dst)
          let srcTopY = VisGraph.getYPos src
          let stubY = srcBotY + StubMargin + float depIdx * EdgeOffset
          let srcSafeX =
            if srcIsLeft then
              VisGraph.getXPos src - StubMargin - float depIdx * EdgeOffset
            else
              VisGraph.getXPos src + VisGraph.getWidth src + StubMargin
              + float depIdx * EdgeOffset
          edge.Points <-
            [| pos sPortX srcBotY
               pos sPortX stubY
               pos srcSafeX stubY
               pos srcSafeX (srcTopY - StubMargin)
               pos bendX (srcTopY - StubMargin)
               pos railX adjustedY
               if adjustedY = topY then () else pos railX topY
               pos inPortX topY
               pos inPortX dstTopY |]
        | true, false ->
          let dstIsLeft = getDstIsLeft (portMap.BwdEdgeBendPoints[edge])
          let idx =
            match aIdx.TryGetValue dst with
            | true, m -> getDefault m edge 0
            | _ -> 0
          let railX, topY, dstTopY = computeArrivalGeometry dst dstIsLeft idx
          let adjustedY = getDefault crossYOffset edge topY
          let inPortX = getDefault portMap.BwdInPorts edge (getCXPos dst)
          let srcTopY = VisGraph.getYPos src
          edge.Points <-
            [| pos srcCx srcTopY
               pos railX adjustedY
               if adjustedY = topY then () else pos railX topY
               pos inPortX topY
               pos inPortX dstTopY |])

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
        addPoint pts sPortX (botY + 5.0)
        addPoint pts (leftX - 5.0) (botY + 5.0)
        addPoint pts (leftX - 5.0) (topY - 5.0)
        addPoint pts dPortX (topY - 5.0)
        addPoint pts dPortX topY
        edge.Points <- pts |> Seq.toArray)
    else
      ()))

let private restoreBackEdges (g: VisGraph) backEdgeList =
  backEdgeList
  |> List.iter (fun (src, dst, edge) ->
    match g.TryFindEdge(dst, src) with
    | Some e when e.Label.IsBackEdge -> g.RemoveEdge(dst, src) |> ignore
    | _ -> ()
    g.AddEdge(src, dst, edge) |> ignore
  )

let private routeEdges layout (edgeSet, portMap) =
  expandLayerGap edgeSet layout
  let depIdx, approachIdx, crossYOffset, realVertices =
    preprocessBackwardRouting edgeSet layout portMap
  let fwdArrivalTopY = computeForwardArrivalTopY edgeSet portMap realVertices
  routeForwardEdges edgeSet layout portMap fwdArrivalTopY
  routeBackwardEdges edgeSet layout portMap depIdx approachIdx crossYOffset
  routeSelfCycleEdge edgeSet layout portMap

let drawEdges g vLayout backEdgeList dummyMap =
  restoreBackEdges g backEdgeList
  routeEdges vLayout (assignPorts g vLayout)
  EdgePost.postprocessEdges g dummyMap
