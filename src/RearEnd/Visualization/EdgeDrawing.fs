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
type private Layout = IVertex<VisBBlock>[][]
type private EdgeInfo = IVertex<VisBBlock> * IVertex<VisBBlock> * VisEdge
type private PortMap = Dictionary<VisEdge, float>
type private BandBuckets = Dictionary<int, ResizeArray<float * VisEdge>>
type private BypassSlots = Dictionary<VertexID * bool, int>

let private pos x y = VisPosition.Create(x, y)

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
  |> Array.map (fun v -> VisGraph.getYPos v + VisGraph.getHeight v) |> Array.max

let private layerTopY (layer: IVertex<VisBBlock>[]) =
  layer |> Array.map VisGraph.getYPos |> Array.min

let private intermediateLayers (layout: Layout) src dst =
  let srcLayer = VisGraph.getLayer src
  let dstLayer = VisGraph.getLayer dst
  if dstLayer - srcLayer <= 1 then [||] else layout[srcLayer + 1..dstLayer - 1]

let private outFwdEdges (v: IVertex<VisBBlock>) (edges: EdgeInfo list) =
  edges |> List.choose (fun (s, d, e) ->
    if s = v && d <> v && not e.IsBackEdge then Some(d, e) else None)

let private inFwdEdges (v: IVertex<VisBBlock>) (edges: EdgeInfo list) =
  edges |> List.choose (fun (s, d, e) ->
    if d = v && s <> v && not e.IsBackEdge then Some(s, e) else None)

let private selfCycleEdges (v: IVertex<VisBBlock>) (edges: EdgeInfo list) =
  edges |> List.choose (fun (s, d, e) ->
    if s = v && d = v then Some e else None)

let private restoreBackEdge (g: VisGraph) (src, dst, edge: VisEdge) =
  match g.TryFindEdge(dst, src) with
  | Some e when e.Label.IsBackEdge -> g.RemoveEdge(dst, src) |> ignore
  | _ -> ()
  g.AddEdge(src, dst, edge) |> ignore

let private removeDummy (g: VisGraph) (src, dst) ((edge: VisEdge), dummies) =
  let rec chain prev = function
    | d :: rest -> g.RemoveEdge(prev, d) |> ignore; chain d rest
    | [] -> g.RemoveEdge(prev, dst) |> ignore
  chain src dummies
  let edgeCreated = VisEdge(edge.Type)
  edgeCreated.IsBackEdge <- edge.IsBackEdge
  g.AddEdge(src, dst, edgeCreated) |> ignore
  dummies |> List.iter (g.RemoveVertex >> ignore)

let private cleanupGraph g vLayout backEdgeList dummyMap =
  Map.iter (removeDummy g) dummyMap
  backEdgeList
  |> List.filter (fun (s: IVertex<VisBBlock>, d: IVertex<VisBBlock>, _) ->
    not s.VData.IsDummy && not d.VData.IsDummy)
  |> List.iter (restoreBackEdge g)
  let layoutWithoutDummy =
    vLayout
    |> Array.map (Array.filter (fun (v: IVertex<VisBBlock>) ->
      not v.VData.IsDummy))
    |> Array.filter (fun l -> l.Length > 0)
  let edges =
    (g: VisGraph).FoldEdge((fun acc (e: Edge<_, VisEdge>) ->
      (e.First, e.Second, e.Label) :: acc), [])
  layoutWithoutDummy, edges

let private centreHalfWidth count =
  if count = 0 then 0.0 else float ((count + 1) / 2) * EdgeOffset

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
    edge, cx + (float i - float (count - 1) / 2.0) * EdgeOffset)

let private assignSidePorts cx centreCount goRight edges =
  let sideCount = List.length edges
  let offset = centreHalfWidth centreCount
  edges |> List.mapi (fun i (_, edge) ->
    let distance = offset + float (sideCount - i) * EdgeOffset
    let portX = if goRight then cx + distance else cx - distance
    edge, portX)

let private assignOutPorts (v: IVertex<VisBBlock>) (edges: EdgeInfo list) =
  let cx = geomCx v
  let outs = outFwdEdges v edges
  if List.isEmpty outs then []
  else
    let lefts, centres, rights = partitionByX cx outs
    let centreCount = List.length centres
    let leftPorts =
      lefts
      |> List.sortBy (fun (dst, _) -> geomCx dst)
      |> assignSidePorts cx centreCount false
    let rightPorts =
      rights
      |> List.sortByDescending (fun (dst, _) -> geomCx dst)
      |> assignSidePorts cx centreCount true
    let centrePorts = assignCentrePorts cx centres
    leftPorts @ centrePorts @ rightPorts

let private layerGap dstLayer (src: IVertex<VisBBlock>) =
  abs (VisGraph.getLayer src - dstLayer)

let private sortByLayerGap dstLayer sortBucket edges =
  edges
  |> List.groupBy (fun (src, _) -> layerGap dstLayer src)
  |> List.sortBy fst
  |> List.collect (fun (_, bucket) -> sortBucket bucket)

let private assignInPorts (v: IVertex<VisBBlock>) (edges: EdgeInfo list) =
  let cx = geomCx v
  let dstLayer = VisGraph.getLayer v
  let ins = inFwdEdges v edges
  if List.isEmpty ins then
    []
  else
    let lefts, centres, rights = partitionByX cx ins
    let centreCount = List.length centres
    let leftPorts =
      lefts
      |> sortByLayerGap dstLayer (List.sortBy (fun (src, _) -> geomCx src))
      |> assignSidePorts cx centreCount false
    let rightPorts =
      rights
      |> sortByLayerGap dstLayer
        (List.sortByDescending (fun (src, _) -> geomCx src))
      |> assignSidePorts cx centreCount true
    let centrePorts = assignCentrePorts cx centres
    leftPorts @ centrePorts @ rightPorts

let private buildPortMaps (layout: Layout) (edges: EdgeInfo list) =
  let outMap = PortMap()
  let inMap = PortMap()
  layout
  |> Array.iter (fun layer ->
    layer
    |> Array.iter (fun v ->
      assignOutPorts v edges |> List.iter (fun (e, x) -> outMap[e] <- x)
      assignInPorts v edges |> List.iter (fun (e, x) -> inMap[e]  <- x)
    )
  )
  outMap, inMap

let private sideSpace layer (v: IVertex<VisBBlock>) goRight =
  let vx = VisGraph.getXPos v
  (layer: IVertex<VisBBlock>[])
  |> Array.choose (fun u ->
    let ux = VisGraph.getXPos u
    if u = v then None
    elif goRight && ux > vx then Some(ux - (vx + VisGraph.getWidth v))
    elif not goRight && ux < vx then Some(vx - (ux + VisGraph.getWidth u))
    else None)
  |> fun d -> if d.Length = 0 then Double.MaxValue else Array.min d

let private portXsOnSide (portMap: PortMap) getEdges goRight cx v edges =
  getEdges v edges
  |> List.choose (fun (_, edge) ->
    match portMap.TryGetValue edge with
    | true, x when (goRight && x >= cx) || (not goRight && x <= cx) -> Some x
    | _ -> None
  )

let private outermostPort goRight cx portXs =
  if List.isEmpty portXs then cx
  else if goRight then List.max portXs else List.min portXs

let private routeSelfCycles v layer edges outMap inMap =
  let cycles = selfCycleEdges (v: IVertex<VisBBlock>) edges
  if List.isEmpty cycles then
    ()
  else
    let cx, topY, botY = vertexGeom v
    let goRight = sideSpace layer v true >= sideSpace layer v false
    let l, r, _, _ = safeBox v
    let sideX = if goRight then r else l
    let fwdOutXsOnSide = portXsOnSide outMap outFwdEdges goRight cx v edges
    let fwdInXsOnSide = portXsOnSide inMap inFwdEdges goRight cx v edges
    let outermostOut = outermostPort goRight cx fwdOutXsOnSide
    let outermostIn = outermostPort goRight cx fwdInXsOnSide
    cycles |> List.iteri (fun i edge ->
      let step = float (i + 1) * EdgeOffset
      let outX = outermostOut + (if goRight then step else -step)
      let inX = outermostIn + (if goRight then step else -step)
      edge.Points <-
        [ pos outX botY
          pos outX (botY + StubMargin)
          pos sideX (botY + StubMargin)
          pos sideX (topY - StubMargin)
          pos inX (topY - StubMargin)
          pos inX topY ]
    )

let private isBlocked x src dst obs =
  if obs = src || obs = dst then
    false
  else
    let l, r, _, _ = safeBox obs
    x > l && x < r

let private findBlocker layer src dst x =
  (layer: IVertex<VisBBlock>[]) |> Array.tryFind (isBlocked x src dst)

let private nearSide (blocker: IVertex<VisBBlock>) x =
  let l, r, _, _ = safeBox blocker
  if abs (x - l) <= abs (x - r) then l else r

let private collectColumnBlockers layout src dst columnX =
  intermediateLayers layout src dst
  |> Array.choose (fun midLayer -> findBlocker midLayer src dst columnX)

let private tryGetOrDefault (dict: Dictionary<'Key, 'Value>) key defaultValue =
  match dict.TryGetValue key with
  | true, value -> value
  | _ -> defaultValue

let private getOrCreateBucket (buckets: BandBuckets) bandIndex =
  match buckets.TryGetValue bandIndex with
  | true, bucket ->
    bucket
  | _ ->
    let bucket = ResizeArray()
    buckets[bandIndex] <- bucket
    bucket

let private getApproachColumnX (slots: BypassSlots) layout src dst dstPortX =
  let blockers = collectColumnBlockers layout src dst dstPortX
  if blockers.Length = 0 then
    dstPortX
  else
    let dstLeft, _, _, _ = safeBox dst
    let key = dst.ID, false
    let slotIndex =
      match slots.TryGetValue key with
      | true, n -> n
      | _ -> 0
    slots[key] <- slotIndex + 1
    let approachX = dstLeft - float (slotIndex + 1) * EdgeOffset
    let maxRight =
      blockers
      |> Array.map (fun b ->
        let _, r, _, _ = safeBox b
        r)
      |> Array.max
    if approachX <= maxRight then maxRight + float (slotIndex + 1) * EdgeOffset
    else approachX

let private appendBlockerDetours slots layout src dst columnX pts =
  let blockers = collectColumnBlockers layout src dst columnX
  if blockers.Length = 0 then
    ()
  else
    let firstBlocker = blockers[0]
    let lastBlocker = blockers[blockers.Length - 1]
    let baseX = nearSide firstBlocker columnX
    let goRight = baseX > columnX
    let key = firstBlocker.ID, goRight
    let slotIndex =
      match (slots: BypassSlots).TryGetValue key with
      | true, n -> n
      | _ -> 0
    slots[key] <- slotIndex + 1
    let bypassX =
      if goRight then baseX + float (slotIndex + 1) * EdgeOffset
      else baseX - float (slotIndex + 1) * EdgeOffset
    let _, _, enterTop, _ = safeBox firstBlocker
    let _, _, _, exitBot = safeBox lastBlocker
    let jogTop = enterTop - float slotIndex * EdgeOffset
    let jogBot = exitBot + float slotIndex * EdgeOffset
    (pts: ResizeArray<VisPosition>).Add(pos columnX jogTop)
    pts.Add(pos bypassX jogTop)
    pts.Add(pos bypassX jogBot)
    pts.Add(pos columnX jogBot)

let private routeVertical slots layout src dst portX srcBotY dstTopY =
  let pts = ResizeArray<VisPosition>()
  pts.Add(pos portX srcBotY)
  pts.Add(pos portX (srcBotY + StubMargin))
  appendBlockerDetours slots layout src dst portX pts
  pts.Add(pos portX (dstTopY - StubMargin))
  pts.Add(pos portX dstTopY)
  pts |> Seq.toList

let private routeHorizontal slots layout src dst sPortX dPortX botY topY bandY =
  let pts = ResizeArray<VisPosition>()
  let approachX = getApproachColumnX slots layout src dst dPortX
  pts.Add(pos sPortX botY)
  pts.Add(pos sPortX (botY + StubMargin))
  pts.Add(pos sPortX bandY)
  pts.Add(pos approachX bandY)
  appendBlockerDetours slots layout src dst approachX pts
  pts.Add(pos approachX (topY - StubMargin))
  if abs (approachX - dPortX) > XTolerance then
    pts.Add(pos dPortX (topY - StubMargin))
  else
    ()
  pts.Add(pos dPortX topY)
  pts |> Seq.toList

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
        let srcPortX = tryGetOrDefault outMap edge srcCx
        if dstCx > srcCx + XTolerance then
          let bucket = getOrCreateBucket bandEdgesRight layerIndex
          bucket.Add(srcPortX, edge)
        elif dstCx < srcCx - XTolerance then
          let bucket = getOrCreateBucket bandEdgesLeft layerIndex
          bucket.Add(srcPortX, edge)
        else
          ())
    )
  )
  bandEdgesRight, bandEdgesLeft

let private bucketCount (buckets: BandBuckets) bandIndex =
  match buckets.TryGetValue bandIndex with
  | true, bucket -> bucket.Count
  | _ -> 0

let private shiftLayersDown (layout: Layout) startIndex delta =
  for layerIndex in startIndex .. layout.Length - 1 do
    layout[layerIndex] |> Array.iter (fun v ->
      v.VData.Coordinate.Y <- v.VData.Coordinate.Y + delta)

let private expandBands (layout: Layout) bandEdgesRight bandEdgesLeft =
  for bandIndex in 0 .. layout.Length - 2 do
    let edgeCount =
      bucketCount bandEdgesRight bandIndex + bucketCount bandEdgesLeft bandIndex
    if edgeCount > 0 then
      let topY = layerBotY layout[bandIndex]
      let botY = layerTopY layout[bandIndex + 1]
      let required = 2.0 * StubMargin + float edgeCount * EdgeOffset
      let deficit = required - (botY - topY)
      if deficit > 0.0 then shiftLayersDown layout (bandIndex + 1) deficit
      else ()
    else
      ()

let private assignBandSlots bandYMap bandStartY sortPorts bucket =
  (bucket: ResizeArray<float * VisEdge>)
  |> Seq.toArray
  |> sortPorts
  |> Array.iteri (fun slotIndex (_, edge) ->
    (bandYMap: Dictionary<VisEdge, float>)[edge] <-
      bandStartY + float slotIndex * EdgeOffset)

let private buildBandYMap (layout: Layout) bandEdgesRight bandEdgesLeft =
  let bandYMap = Dictionary<VisEdge, float>()
  for bandIndex in 0 .. layout.Length - 2 do
    let bandStartY = layerBotY layout[bandIndex] + StubMargin
    let rightCount =
      match (bandEdgesRight: BandBuckets).TryGetValue bandIndex with
      | true, bucket ->
        assignBandSlots bandYMap bandStartY (Array.sortByDescending fst) bucket
        bucket.Count
      | _ -> 0
    match (bandEdgesLeft: BandBuckets).TryGetValue bandIndex with
    | true, bucket ->
      let leftStartY = bandStartY + float rightCount * EdgeOffset
      assignBandSlots bandYMap leftStartY (Array.sortBy fst) bucket
    | _ -> ()
  bandYMap

let private routeForwardEdges layout edges outMap inMap
  (bandYMap: Dictionary<VisEdge, float>) =
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
        let sPortX = tryGetOrDefault outMap edge srcCx
        let dPortX = tryGetOrDefault inMap edge dstCx
        let _, dTopY, _ = vertexGeom dst
        if abs (srcCx - dstCx) <= XTolerance then
          edge.Points <- routeVertical slots layout src dst sPortX sBotY dTopY
        else
          let defaultBandY = layerBotY layout[srcLayer] + StubMargin
          let bandY = tryGetOrDefault bandYMap edge defaultBandY
          edge.Points <-
            routeHorizontal slots layout src dst sPortX dPortX sBotY dTopY bandY
      )
    )
  )

let drawEdges g vLayout backEdgeList dummyMap =
  let layout, edges = cleanupGraph g vLayout backEdgeList dummyMap
  let outMap, inMap = buildPortMaps layout edges
  let bandEdgesRight, bandEdgesLeft = collectBandEdges layout edges outMap
  expandBands layout bandEdgesRight bandEdgesLeft
  let bandYMap = buildBandYMap layout bandEdgesRight bandEdgesLeft
  routeForwardEdges layout edges outMap inMap bandYMap
  layout
  |> Array.iter (fun layer ->
    layer |> Array.iter (fun v -> routeSelfCycles v layer edges outMap inMap))