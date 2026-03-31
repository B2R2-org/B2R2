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

open System
open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

let [<Literal>] private StubMargin = 50.0
let [<Literal>] private EdgeOffset = 4.0
let [<Literal>] private XTolerance = 4.0

let private portOffset = max EdgeOffset 4.0

type private Layout = IVertex<VisBBlock>[][]
type private EdgeInfo = IVertex<VisBBlock> * IVertex<VisBBlock> * VisEdge
type private PortMap = Dictionary<VisEdge, float>
type private BandBuckets = Dictionary<int, ResizeArray<float * VisEdge>>
type private BypassSlots = Dictionary<VertexID * bool, int>
type private BackGeomMap = Dictionary<VisEdge, bool * float * float * float>

let private pos x y = VisPosition.Create(x, y)

let private chooseEdges chooser (edges: EdgeInfo list) =
  edges |> List.choose chooser

let private selectEdges predicate project (edges: EdgeInfo list) =
  chooseEdges (fun (src, dst, edge) ->
    if predicate src dst edge then Some(project src dst edge) else None) edges

let private getOrDefault (dict: Dictionary<'Key, 'Value>) key defaultValue =
  match dict.TryGetValue key with
  | true, value -> value
  | _ -> defaultValue

let private getOrCreateBucket (buckets: BandBuckets) bandIndex =
  match buckets.TryGetValue bandIndex with
  | true, bucket -> bucket
  | _ ->
    let bucket = ResizeArray()
    buckets[bandIndex] <- bucket
    bucket

let private backGeomValue selector defaultValue (backGeom: BackGeomMap) edge =
  match backGeom.TryGetValue edge with
  | true, geom -> selector geom
  | _ -> defaultValue

let private populatePortMap (portMap: PortMap) assignments =
  assignments |> List.iter (fun (edge, x) -> portMap[edge] <- x)

let private addPoint (pts: ResizeArray<VisPosition>) x y = pts.Add(pos x y)

let private geomCx (v: IVertex<VisBBlock>) =
  VisGraph.getXPos v + VisGraph.getWidth v / 2.0

let private vertexGeom (v: IVertex<VisBBlock>) =
  let cx = geomCx v
  let top = VisGraph.getYPos v
  let bot = top + VisGraph.getHeight v
  cx, top, bot

let private safeBox (v: IVertex<VisBBlock>) =
  let x = VisGraph.getXPos v
  let y = VisGraph.getYPos v
  x - StubMargin,
  x + VisGraph.getWidth v + StubMargin,
  y - StubMargin,
  y + VisGraph.getHeight v + StubMargin

let private layerBotY (layer: IVertex<VisBBlock>[]) =
  layer
  |> Array.map (fun v -> VisGraph.getYPos v + VisGraph.getHeight v)
  |> Array.max

let private layerTopY (layer: IVertex<VisBBlock>[]) =
  layer |> Array.map VisGraph.getYPos |> Array.min

let private layoutBounds (layout: Layout) =
  let left =
    layout
    |> Array.collect (fun layer ->
      layer |> Array.map (fun v -> let l, _, _, _ = safeBox v in l))
    |> Array.min
  let right =
    layout
    |> Array.collect (fun layer ->
      layer |> Array.map (fun v -> let _, r, _, _ = safeBox v in r))
    |> Array.max
  left, right

let private prefersRightRail globalLeft globalRight (v: IVertex<VisBBlock>) =
  let cx = geomCx v
  globalRight - cx <= cx - globalLeft

let private backGeomSide defaultValue backGeom edge =
  backGeomValue (fun (goRight, _, _, _) -> goRight) defaultValue backGeom edge

let private backGeomStubBotY backGeom edge =
  backGeomValue (fun (_, _, stubBotY, _) -> stubBotY) 0.0 backGeom edge

let private backGeomStubTopY backGeom edge =
  backGeomValue (fun (_, _, _, stubTopY) -> stubTopY) 0.0 backGeom edge

let private intermediateLayers (layout: Layout) src dst =
  let srcLayer = VisGraph.getLayer src
  let dstLayer = VisGraph.getLayer dst
  if dstLayer - srcLayer <= 1 then [||] else layout[srcLayer + 1..dstLayer - 1]

let private outFwdEdges (v: IVertex<VisBBlock>) (edges: EdgeInfo list) =
  selectEdges (fun src dst edge -> src = v && dst <> v && not edge.IsBackEdge)
    (fun _ dst edge -> dst, edge) edges

let private inFwdEdges (v: IVertex<VisBBlock>) (edges: EdgeInfo list) =
  selectEdges (fun src dst edge -> dst = v && src <> v && not edge.IsBackEdge)
    (fun src _ edge -> src, edge) edges

let private selfCycleEdges (v: IVertex<VisBBlock>) (edges: EdgeInfo list) =
  selectEdges (fun src dst _ -> src = v && dst = v) (fun _ _ edge -> edge) edges

let private outBackEdges (v: IVertex<VisBBlock>) (edges: EdgeInfo list) =
  selectEdges (fun src dst edge -> src = v && dst <> v && edge.IsBackEdge)
    (fun _ dst edge -> dst, edge) edges

let private inBackEdges (v: IVertex<VisBBlock>) (edges: EdgeInfo list) =
  selectEdges (fun src dst edge -> dst = v && src <> v && edge.IsBackEdge)
    (fun src _ edge -> src, edge) edges

let private restoreBackEdge (g: VisGraph) (src, dst, edge: VisEdge) =
  match g.TryFindEdge(dst, src) with
  | Some e when e.Label.IsBackEdge -> g.RemoveEdge(dst, src) |> ignore
  | _ -> ()
  g.AddEdge(src, dst, edge) |> ignore

let private removeDummy (g: VisGraph) (src, dst) ((edge: VisEdge), dummies) =
  let rec chain prev = function
    | dummy :: rest ->
      g.RemoveEdge(prev, dummy) |> ignore
      chain dummy rest
    | [] -> g.RemoveEdge(prev, dst) |> ignore
  chain src dummies
  let edgeCreated = VisEdge(edge.Type)
  edgeCreated.IsBackEdge <- edge.IsBackEdge
  g.AddEdge(src, dst, edgeCreated) |> ignore
  dummies |> List.iter (g.RemoveVertex >> ignore)

let private cleanupGraph g vLayout backEdgeList dummyMap =
  Map.iter (removeDummy g) dummyMap
  backEdgeList
  |> List.filter (fun (src: IVertex<VisBBlock>, dst: IVertex<VisBBlock>, _) ->
    not src.VData.IsDummy && not dst.VData.IsDummy)
  |> List.iter (restoreBackEdge g)
  let layoutWithoutDummy =
    vLayout
    |> Array.map (
      Array.filter (fun (v: IVertex<VisBBlock>) -> not v.VData.IsDummy))
    |> Array.filter (fun layer -> layer.Length > 0)
  let edges =
    (g: VisGraph).FoldEdge((fun acc (e: Edge<_, VisEdge>) ->
      (e.First, e.Second, e.Label) :: acc), [])
  layoutWithoutDummy, edges

let private centreHalfWidth count =
  if count = 0 then 0.0 else float ((count + 1) / 2) * portOffset

let private partitionByX cx edges =
  let lefts, midRights =
    edges |> List.partition (fun (v, _) -> geomCx v < cx - XTolerance)
  let centres, rights =
    midRights
    |> List.partition (fun (v, _) -> abs (geomCx v - cx) <= XTolerance)
  lefts, centres, rights

let private assignCentrePorts cx edges =
  let count = List.length edges
  edges |> List.mapi (fun i (_, edge) ->
    edge, cx + (float i - float (count - 1) / 2.0) * portOffset)

let private assignSidePorts cx centreCount goRight edges =
  let sideCount = List.length edges
  let offset = centreHalfWidth centreCount
  edges |> List.mapi (fun i (_, edge) ->
    let distance = offset + float (sideCount - i) * portOffset
    let portX = if goRight then cx + distance else cx - distance
    edge, portX)

let private layerGap dstLayer (src: IVertex<VisBBlock>) =
  abs (VisGraph.getLayer src - dstLayer)

let private sortByLayerGap dstLayer sortBucket edges =
  edges
  |> List.groupBy (fun (src, _) -> layerGap dstLayer src)
  |> List.sortBy fst
  |> List.collect (fun (_, bucket) -> sortBucket bucket)

let private assignPorts getEdges sortL sortR (v: IVertex<VisBBlock>) edges =
  let cx = geomCx v
  let portEdges = getEdges v edges
  if List.isEmpty portEdges then
    []
  else
    let lefts, centres, rights = partitionByX cx portEdges
    let centreCount = List.length centres
    let leftPorts = lefts |> sortL |> assignSidePorts cx centreCount false
    let rightPorts = rights |> sortR |> assignSidePorts cx centreCount true
    leftPorts @ assignCentrePorts cx centres @ rightPorts

let private assignOutPorts (v: IVertex<VisBBlock>) (edges: EdgeInfo list) =
  assignPorts outFwdEdges (List.sortBy (fun (dst, _) -> geomCx dst))
    (List.sortByDescending (fun (dst, _) -> geomCx dst)) v edges

let private assignInPorts (v: IVertex<VisBBlock>) (edges: EdgeInfo list) =
  let dstLayer = VisGraph.getLayer v
  assignPorts inFwdEdges
    (sortByLayerGap dstLayer (List.sortBy (fun (s, _) -> geomCx s)))
    (sortByLayerGap dstLayer (List.sortByDescending (fun (s, _) -> geomCx s)))
    v edges

let private buildPortMaps (layout: Layout) (edges: EdgeInfo list) =
  let outMap = PortMap()
  let inMap = PortMap()
  layout
  |> Array.iter (fun layer ->
    layer
    |> Array.iter (fun v ->
      assignOutPorts v edges |> populatePortMap outMap
      assignInPorts v edges |> populatePortMap inMap))
  outMap, inMap

let private outermostFwdX (portMap: PortMap) getEdges goRight cx v edges =
  let sideXs =
    getEdges v edges
    |> List.choose (fun (_, edge) ->
      match portMap.TryGetValue edge with
      | true, x when goRight && x >= cx - XTolerance -> Some x
      | true, x when not goRight && x <= cx + XTolerance -> Some x
      | _ -> None)
  if List.isEmpty sideXs then cx
  elif goRight then List.max sideXs
  else List.min sideXs

let private assignBackPorts getEdges getFwdEdges defaultGoRight getSortKey
  (v: IVertex<VisBBlock>) (edges: EdgeInfo list) (fwdMap: PortMap)
  (backGeom: BackGeomMap) =
  let cx = geomCx v
  let backEdges = getEdges v edges
  if List.isEmpty backEdges then
    []
  else
    let fwdBaseLeft = outermostFwdX fwdMap getFwdEdges false cx v edges
    let fwdBaseRight = outermostFwdX fwdMap getFwdEdges true cx v edges
    let fallbackGoRight = defaultGoRight cx backEdges
    let rightEdges, leftEdges =
      backEdges
      |> List.partition (fun (_, edge) ->
        backGeomSide fallbackGoRight backGeom edge)
    let buildSidePorts goRight baseX sideEdges =
      sideEdges
      |> List.sortBy getSortKey
      |> List.mapi (fun i (_, edge) ->
        let offset = float (i + 1) * portOffset
        edge, baseX + (if goRight then offset else -offset))
    buildSidePorts false fwdBaseLeft leftEdges
    @ buildSidePorts true fwdBaseRight rightEdges

let private assignBackOutPorts (v: IVertex<VisBBlock>) (edges: EdgeInfo list)
  (fwdOutMap: PortMap) (backGeom: BackGeomMap) =
  assignBackPorts outBackEdges outFwdEdges
    (fun cx outs -> geomCx (fst (List.head outs)) >= cx)
    (fun (_, edge) -> -backGeomStubBotY backGeom edge)
    v edges fwdOutMap backGeom

let private assignBackInPorts (v: IVertex<VisBBlock>) (edges: EdgeInfo list)
  (fwdInMap: PortMap) (backGeom: BackGeomMap) =
  assignBackPorts inBackEdges inFwdEdges (fun _ _ -> true)
    (fun (_, edge) -> backGeomStubTopY backGeom edge)
    v edges fwdInMap backGeom

let private buildBackPortMaps layout edges outMap inMap (bGeom: BackGeomMap) =
  let backOutMap = PortMap()
  let backInMap = PortMap()
  layout
  |> Array.iter (fun layer ->
    layer
    |> Array.iter (fun v ->
      assignBackOutPorts v edges outMap bGeom |> populatePortMap backOutMap
      assignBackInPorts v edges inMap bGeom |> populatePortMap backInMap))
  backOutMap, backInMap

let private sideSpace layer (v: IVertex<VisBBlock>) goRight =
  let vx = VisGraph.getXPos v
  (layer: IVertex<VisBBlock>[])
  |> Array.choose (fun u ->
    let ux = VisGraph.getXPos u
    if u = v then None
    elif goRight && ux > vx then Some(ux - (vx + VisGraph.getWidth v))
    elif not goRight && ux < vx then Some(vx - (ux + VisGraph.getWidth u))
    else None)
  |> fun distances ->
    if distances.Length = 0 then Double.MaxValue else Array.min distances

let private portXsOnSide (portMap: PortMap) getEdges goRight cx v edges =
  getEdges v edges
  |> List.choose (fun (_, edge) ->
    match portMap.TryGetValue edge with
    | true, x when goRight && x >= cx || not goRight && x <= cx -> Some x
    | _ -> None)

let private outermostPort goRight cx portXs =
  if List.isEmpty portXs then cx
  elif goRight then List.max portXs
  else List.min portXs

let private routeSelfCycles v layer edges outMap inMap backOutMap backInMap =
  let cycles = selfCycleEdges (v: IVertex<VisBBlock>) edges
  if not (List.isEmpty cycles) then
    let cx, topY, botY = vertexGeom v
    let goRight = sideSpace layer v true >= sideSpace layer v false
    let leftX, rightX, _, _ = safeBox v
    let sideX = if goRight then rightX else leftX
    let fwdOutXs = portXsOnSide outMap outFwdEdges goRight cx v edges
    let fwdInXs = portXsOnSide inMap inFwdEdges goRight cx v edges
    let backOutXs = portXsOnSide backOutMap outBackEdges goRight cx v edges
    let backInXs = portXsOnSide backInMap inBackEdges goRight cx v edges
    let outermostOut =
      let fwdBase = outermostPort goRight cx fwdOutXs
      let backBase = outermostPort goRight cx backOutXs
      if goRight then max fwdBase backBase else min fwdBase backBase
    let outermostIn =
      let fwdBase = outermostPort goRight cx fwdInXs
      let backBase = outermostPort goRight cx backInXs
      if goRight then max fwdBase backBase else min fwdBase backBase
    cycles |> List.iteri (fun i edge ->
      let step = float (i + 1) * portOffset
      let outX = outermostOut + if goRight then step else -step
      let inX = outermostIn + if goRight then step else -step
      edge.Points <-
        [ pos outX botY
          pos outX (botY + StubMargin)
          pos sideX (botY + StubMargin)
          pos sideX (topY - StubMargin)
          pos inX (topY - StubMargin)
          pos inX topY ])
  else
    ()

let private isBlocked x src dst obstacle =
  if obstacle = src || obstacle = dst then false
  else
    let leftX, rightX, _, _ = safeBox obstacle
    x > leftX && x < rightX

let private findBlocker layer src dst x =
  (layer: IVertex<VisBBlock>[]) |> Array.tryFind (isBlocked x src dst)

let private nearSide (blocker: IVertex<VisBBlock>) x =
  let leftX, rightX, _, _ = safeBox blocker
  if abs (x - leftX) <= abs (x - rightX) then leftX else rightX

let private computeBypassX (slots: BypassSlots) layout src dst columnX =
  let midLayers = intermediateLayers layout src dst
  let allBlockers =
    midLayers |> Array.choose (fun layer -> findBlocker layer src dst columnX)
  if allBlockers.Length = 0 then None
  else
    let baseX = nearSide allBlockers[0] columnX
    let goRight = baseX > columnX
    let key = allBlockers[0].ID, goRight
    let slotIndex = getOrDefault slots key 0
    slots[key] <- slotIndex + 1
    let candidateX =
      if goRight then baseX + float (slotIndex + 1) * EdgeOffset
      else baseX - float (slotIndex + 1) * EdgeOffset
    let worstX =
      midLayers
      |> Array.fold (fun acc layer ->
        match findBlocker layer src dst acc with
        | None -> acc
        | Some obstacle ->
          let leftX, rightX, _, _ = safeBox obstacle
          if goRight then rightX + float (slotIndex + 1) * EdgeOffset
          else leftX - float (slotIndex + 1) * EdgeOffset) candidateX
    Some(worstX, goRight, slotIndex)

let private getApproachColumnX (slots: BypassSlots) layout src dst dstPortX =
  match computeBypassX slots layout src dst dstPortX with
  | None -> dstPortX
  | Some(safeX, _, _) -> safeX

let private appendBlockerDetours slots layout src dst columnX pts =
  let midLayers = intermediateLayers layout src dst
  if midLayers.Length > 0 then
    match computeBypassX slots layout src dst columnX with
    | None -> ()
    | Some(bypassX, _, slotIndex) ->
      let blockers =
        midLayers
        |> Array.choose (fun layer -> findBlocker layer src dst columnX)
      let firstBlocker = blockers[0]
      let lastBlocker = blockers[blockers.Length - 1]
      let _, _, enterTop, _ = safeBox firstBlocker
      let _, _, _, exitBot = safeBox lastBlocker
      let jogTop = enterTop - float slotIndex * EdgeOffset
      let jogBot = exitBot + float slotIndex * EdgeOffset
      addPoint pts columnX jogTop
      addPoint pts bypassX jogTop
      addPoint pts bypassX jogBot
      addPoint pts columnX jogBot
  else
    ()

let private routeVertical slots layout src dst portX srcBotY dstTopY =
  let pts = ResizeArray<VisPosition>()
  addPoint pts portX srcBotY
  addPoint pts portX (srcBotY + StubMargin)
  appendBlockerDetours slots layout src dst portX pts
  addPoint pts portX (dstTopY - StubMargin)
  addPoint pts portX dstTopY
  pts |> Seq.toList

let private routeHorizontal slots layout src dst sPortX dPortX botY topY bandY =
  let pts = ResizeArray<VisPosition>()
  let approachX = getApproachColumnX slots layout src dst dPortX
  addPoint pts sPortX botY
  addPoint pts sPortX (botY + StubMargin)
  addPoint pts sPortX bandY
  addPoint pts approachX bandY
  appendBlockerDetours slots layout src dst approachX pts
  addPoint pts approachX (topY - StubMargin)
  if abs (approachX - dPortX) > XTolerance
  then addPoint pts dPortX (topY - StubMargin)
  else ()
  addPoint pts dPortX topY
  pts |> Seq.toList

let private routeBackEdgeOuter sPortX dPortX sBotY dTopY rX stubBotY stubTopY =
  [ pos sPortX sBotY
    pos sPortX stubBotY
    pos rX stubBotY
    pos rX stubTopY
    pos dPortX stubTopY
    pos dPortX dTopY ]

let private routeBackEdges layout edges backOutMap backInMap backGeom =
  layout
  |> Array.iter (fun layer ->
    layer
    |> Array.sortBy VisGraph.getXPos
    |> Array.iter (fun src ->
      let srcCx = geomCx src
      let _, _, sBotY = vertexGeom src
      outBackEdges src edges
      |> List.iter (fun (dst, edge) ->
        let dstCx = geomCx dst
        let sPortX = getOrDefault backOutMap edge srcCx
        let dPortX = getOrDefault backInMap edge dstCx
        let _, dTopY, _ = vertexGeom dst
        match (backGeom: BackGeomMap).TryGetValue edge with
        | true, (_, railX, stubBotY, stubTopY) ->
          edge.Points <-
            routeBackEdgeOuter sPortX dPortX sBotY dTopY railX stubBotY stubTopY
        | _ -> ())))

let private addBandEdge (buckets: BandBuckets) bandIndex portX edge =
  let bucket = getOrCreateBucket buckets bandIndex
  bucket.Add(portX, edge)

let private collectBandEdges layout edges outMap =
  let bandEdgesRight = BandBuckets()
  let bandEdgesLeft = BandBuckets()
  layout
  |> Array.iteri (fun layerIndex layer ->
    layer
    |> Array.iter (fun v ->
      let srcCx = geomCx v
      outFwdEdges v edges
      |> List.iter (fun (dst, edge) ->
        let dstCx = geomCx dst
        let srcPortX = getOrDefault outMap edge srcCx
        if dstCx > srcCx + XTolerance then
          addBandEdge bandEdgesRight layerIndex srcPortX edge
        elif dstCx < srcCx - XTolerance then
          addBandEdge bandEdgesLeft layerIndex srcPortX edge
        else
          ())))
  bandEdgesRight, bandEdgesLeft

let private bucketCount (buckets: BandBuckets) bandIndex =
  match buckets.TryGetValue bandIndex with
  | true, bucket -> bucket.Count
  | _ -> 0

let private countBackEdges edges predicate =
  edges |> List.sumBy (fun (src: IVertex<VisBBlock>, dst, edge: VisEdge) ->
    if edge.IsBackEdge && src <> dst && predicate src dst then 1 else 0)

let private shiftLayersDown (layout: Layout) startIndex delta =
  for layerIndex in startIndex .. layout.Length - 1 do
    layout[layerIndex]
    |> Array.iter (fun v ->
      v.VData.Coordinate.Y <- v.VData.Coordinate.Y + delta)

let private expandBands (layout: Layout) bandEdgesRight bandEdgesLeft edges =
  for bandIndex in 0 .. layout.Length - 2 do
    let fwdCount =
      bucketCount bandEdgesRight bandIndex + bucketCount bandEdgesLeft bandIndex
    let backBotCount =
      countBackEdges edges (fun src _ -> VisGraph.getLayer src = bandIndex)
    let backTopCount =
      countBackEdges edges (fun _ dst -> VisGraph.getLayer dst = bandIndex + 1)
    let totalCount = fwdCount + backBotCount + backTopCount
    if totalCount > 0 then
      let topY = layerBotY layout[bandIndex]
      let botY = layerTopY layout[bandIndex + 1]
      let required = 2.0 * StubMargin + float totalCount * EdgeOffset
      let deficit = required - (botY - topY)
      if deficit > 0.0 then shiftLayersDown layout (bandIndex + 1) deficit
      else ()
    else
      ()

let private safeRailX (layout: Layout) goRight slotIndex =
  let globalLeft, globalRight = layoutBounds layout
  let boundary = if goRight then globalRight else globalLeft
  if goRight then boundary + float (slotIndex + 1) * EdgeOffset
  else boundary - float (slotIndex + 1) * EdgeOffset

let private nonSelfBackEdges edges =
  edges
  |> List.choose (fun (src: IVertex<VisBBlock>, dst, edge: VisEdge) ->
    if edge.IsBackEdge && src <> dst then Some(src, dst, edge) else None)

let private assignBandSlots (bandYMap: Dictionary<VisEdge, float>) bandStartY
  sortPorts bucket =
  bucket
  |> Seq.toArray
  |> sortPorts
  |> Array.iteri (fun slotIndex (_, edge) ->
    bandYMap[edge] <- bandStartY + float slotIndex * EdgeOffset)

let private buildBandYMap layout bandEdgesRight bandEdgesLeft edges =
  let bandYMap = Dictionary<VisEdge, float>()
  let globalLeft, globalRight = layoutBounds layout
  for bandIndex in 0 .. layout.Length - 2 do
    let bandStartY = layerBotY layout[bandIndex] + StubMargin
    let countBackEdgesOnSide goRight =
      countBackEdges edges (fun src _ ->
        VisGraph.getLayer src = bandIndex
        && prefersRightRail globalLeft globalRight src = goRight)
    let backBotRight = countBackEdgesOnSide true
    let backBotLeft = countBackEdgesOnSide false
    let fwdStartY = bandStartY + float (backBotRight + backBotLeft) * EdgeOffset
    let rightCount =
      match (bandEdgesRight: BandBuckets).TryGetValue bandIndex with
      | true, bucket ->
        assignBandSlots bandYMap fwdStartY (Array.sortByDescending fst) bucket
        bucket.Count
      | _ -> 0
    match (bandEdgesLeft: BandBuckets).TryGetValue bandIndex with
    | true, bucket ->
      let leftStartY = fwdStartY + float rightCount * EdgeOffset
      assignBandSlots bandYMap leftStartY (Array.sortBy fst) bucket
    | _ -> ()
  bandYMap

let private computeBackEdgeGeometry layout edges bandEdgesRight bandEdgesLeft =
  let result = BackGeomMap()
  let globalLeft, globalRight = layoutBounds layout
  let backEdges =
    nonSelfBackEdges edges
    |> List.sortBy (fun (src, dst, _) ->
      -(VisGraph.getLayer src - VisGraph.getLayer dst),
      VisGraph.getLayer dst,
      geomCx dst)
  let goRightOf src = prefersRightRail globalLeft globalRight src
  let fwdCount bandIndex =
    bucketCount bandEdgesRight bandIndex + bucketCount bandEdgesLeft bandIndex
  let countBackForBand selector bandIndex goRight =
    backEdges |> List.sumBy (fun (src, dst, _) ->
      if selector src dst bandIndex && goRightOf src = goRight then 1 else 0)
  let botBaseY = Dictionary<int * bool, float>()
  let topBaseY = Dictionary<int * bool, float>()
  for bandIndex in 0 .. layout.Length - 2 do
    let bandStartY = layerBotY layout[bandIndex] + StubMargin
    let botRight =
      countBackForBand
        (fun src _ currentBand -> VisGraph.getLayer src = currentBand)
        bandIndex true
    let botLeft =
      countBackForBand
        (fun src _ currentBand -> VisGraph.getLayer src = currentBand)
        bandIndex false
    botBaseY[(bandIndex, true)] <- bandStartY
    botBaseY[(bandIndex, false)] <- bandStartY + float botRight * EdgeOffset
    let topStart =
      bandStartY + float (botRight + botLeft + fwdCount bandIndex) * EdgeOffset
    let topRight =
      countBackForBand
        (fun _ dst currentBand -> VisGraph.getLayer dst = currentBand + 1)
        bandIndex true
    topBaseY[(bandIndex + 1, true)] <- topStart
    topBaseY[(bandIndex + 1, false)] <- topStart + float topRight * EdgeOffset
  let edgeSlotMap = Dictionary<VisEdge, int * int>()
  let edgeRailSlot = Dictionary<VisEdge, int>()
  let railGroups =
    backEdges
    |> List.groupBy (fun (src, _, _) -> VisGraph.getLayer src, goRightOf src)
  let railBase = Dictionary<bool, int>()
  for (_, goRight), group in railGroups do
    let baseIndex = getOrDefault railBase goRight 0
    railBase[goRight] <- baseIndex + group.Length
    let sorted =
      if goRight then
        group |> List.sortByDescending (fun (src, _, _) -> geomCx src)
      else
        group |> List.sortBy (fun (src, _, _) -> geomCx src)
    sorted |> List.iteri (fun i (_, _, edge) ->
      edgeRailSlot[edge] <- baseIndex + i
      edgeSlotMap[edge] <- i, group.Length - 1 - i)
  let topGroups =
    backEdges
    |> List.groupBy (fun (src, dst, _) -> VisGraph.getLayer dst, goRightOf src)
  for (_, goRight), group in topGroups do
    let sorted =
      if goRight then
        group |> List.sortByDescending (fun (src, _, _) -> geomCx src)
      else
        group |> List.sortBy (fun (src, _, _) -> geomCx src)
    sorted |> List.iteri (fun i (_, _, edge) ->
      let botSlot, _ = getOrDefault edgeSlotMap edge (0, 0)
      edgeSlotMap[edge] <- botSlot, group.Length - 1 - i)
  for src, dst, edge in backEdges do
    let srcLayer = VisGraph.getLayer src
    let dstLayer = VisGraph.getLayer dst
    let goRight = goRightOf src
    let railX = safeRailX layout goRight (getOrDefault edgeRailSlot edge 0)
    let botSlot, topSlot = getOrDefault edgeSlotMap edge (0, 0)
    let stubBotY =
      match botBaseY.TryGetValue((srcLayer, goRight)) with
      | true, baseY -> baseY + float botSlot * EdgeOffset
      | _ -> layerBotY layout[srcLayer] + StubMargin
    let stubTopY =
      match topBaseY.TryGetValue((dstLayer, goRight)) with
      | true, baseY -> baseY + float topSlot * EdgeOffset
      | _ -> layerTopY layout[dstLayer] - StubMargin
    result[edge] <- goRight, railX, stubBotY, stubTopY
  result

let private routeForwardEdges layout edges outMap inMap bandYMap =
  let slots = BypassSlots()
  layout
  |> Array.iter (fun layer ->
    layer
    |> Array.sortBy VisGraph.getXPos
    |> Array.iter (fun src ->
      let srcCx = geomCx src
      let srcLayer = VisGraph.getLayer src
      let _, _, sBotY = vertexGeom src
      outFwdEdges src edges
      |> List.iter (fun (dst, edge) ->
        let dstCx = geomCx dst
        let sPortX = getOrDefault outMap edge srcCx
        let dPortX = getOrDefault inMap edge dstCx
        let _, dTopY, _ = vertexGeom dst
        if abs (srcCx - dstCx) <= XTolerance then
          edge.Points <- routeVertical slots layout src dst sPortX sBotY dTopY
        else
          let defaultBandY = layerBotY layout[srcLayer] + StubMargin
          let bandY = getOrDefault bandYMap edge defaultBandY
          edge.Points <-
            routeHorizontal slots layout src dst sPortX dPortX sBotY dTopY bandY
      )))

let drawEdges g vLayout backEdgeList dummyMap =
  let layout, edges = cleanupGraph g vLayout backEdgeList dummyMap
  let outMap, inMap = buildPortMaps layout edges
  let bandEdgesRight, bandEdgesLeft = collectBandEdges layout edges outMap
  expandBands layout bandEdgesRight bandEdgesLeft edges
  let bandYMap = buildBandYMap layout bandEdgesRight bandEdgesLeft edges
  let backGeom =
    computeBackEdgeGeometry layout edges bandEdgesRight bandEdgesLeft
  let backOutMap, backInMap =
    buildBackPortMaps layout edges outMap inMap backGeom
  routeForwardEdges layout edges outMap inMap bandYMap
  routeBackEdges layout edges backOutMap backInMap backGeom
  layout
  |> Array.iter (fun layer ->
    layer
    |> Array.iter (fun v ->
      routeSelfCycles v layer edges outMap inMap backOutMap backInMap))