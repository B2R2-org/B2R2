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
open B2R2.MiddleEnd.BinGraph

/// TODO: move all constants in this project into a separate module.
let [<Literal>] private StubMargin = 30.0

/// If the number of incoming/outgoing edges of a layer exceeds this threshold,
/// then we expand the layer's height.
let [<Literal>] private LayerHeightExpansionThreshold = 15

let private pos x y = VisPosition.Create(x, y)

let private getOrDefault (dict: Dictionary<'Key, 'Value>) key defaultValue =
  match dict.TryGetValue key with
  | true, value -> value
  | _ -> defaultValue

let private sortLayers vLayout =
  vLayout |> Array.map (fun layer -> Array.sortBy VisGraph.getXPos layer)

let private getMaxDegree (edges: EdgeSet) getter layer =
  layer
  |> Array.map (edges.GetEdges >> List.length)
  |> Array.max

let private downShiftLayers layers degree =
  Array.iter (Array.iter (fun (v: IVertex<VisBBlock>) ->
    let blk = v.VData
    let newY = blk.Coordinate.Y + 4.0 * float degree
    blk.Coordinate.Y <- newY)) layers

let rec private adjustLayers (edgeFlow: EdgeFlow) layerNum layout = function
  | [] ->
    ()
  | degree :: tl ->
    if degree >= LayerHeightExpansionThreshold then
      let shiftStart = if edgeFlow.IsIncoming then layerNum else layerNum + 1
      if shiftStart < Array.length layout
      then downShiftLayers layout[shiftStart..] degree
      else ()
    else ()
    adjustLayers edgeFlow (layerNum + 1) layout tl

/// Expand a layer's height if it contains excessive number of incoming/outgoing
/// edges.
let private adjustLayerYPositions edges layout =
  let maxIncomingDegrees =
    layout
    |> Array.map (getMaxDegree edges (fun (_, d, _) -> d))
    |> Array.toList
  let maxOutgoingDegrees =
    layout
    |> Array.map (getMaxDegree edges (fun (s, _, _) -> s))
    |> Array.toList
  adjustLayers EdgeFlow.Incoming 0 layout maxIncomingDegrees
  adjustLayers EdgeFlow.Outgoing 0 layout maxOutgoingDegrees

let private populatePortMap (portMap: Dictionary<_, _>) assignments =
  assignments |> List.iter (fun (edge, x) -> portMap[edge] <- x)

let private addPoint (pts: ResizeArray<VisPosition>) x y = pts.Add(pos x y)

let private assignBackwardEdgeBend portMap edge bend =
  (portMap: PortMap).BwdEdgeBends[edge] <- bend

let private getCXPos (v: IVertex<VisBBlock>) =
  VisGraph.getXPos v + VisGraph.getWidth v / 2.0

let private vertexGeom (v: IVertex<VisBBlock>) =
  let cx = getCXPos v
  let top = VisGraph.getYPos v
  let bot = top + VisGraph.getHeight v
  cx, top, bot

let private partitionPairsByCentre cx edges =
  let isLeft (v, _) = getCXPos v < cx - 4.0
  let isCentre (v, _) = abs (getCXPos v - cx) <= 4.0
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
  |> Array.iter (fun layer -> layer |> Array.iter (fun v ->
    createFwdPorts v edgeSet EdgeFlow.Outgoing portMap
    createFwdPorts v edgeSet EdgeFlow.Incoming portMap)
  )

/// We perform a rough approximation of the crossing count by considering the
/// relative positions of the forward and backward edges. We assume that we have
/// already assigned the ports for backward edges below the current layer, which
/// is ensured by the order of our port assignment process.
let private computeEdgeCrossesByBackwardEdge portMap src dst edgeBend =
  0, edgeBend

/// To minimize the edge crossings, we assign ports for backward edges
/// by considering the forward edges. We also assign the ports backwards from
/// the most downstream layer to the most upstream layer, so that we can
/// consider both forward and backward edges. We approximate the crossing count
/// to reduce the time complexity. Note that the algorithm is not optimal (i.e.,
/// due to its greedy nature), but it is efficient and effective in practice.
/// TODO: this involves an approximation of actual routing, so we may merge the
/// port assignment and routing phases at least for backward edges.
let private assignBackwardEdgePorts (edgeSet: EdgeSet) layout portMap =
  (layout: IVertex<VisBBlock>[][])
  |> Array.rev
  |> Array.iter (fun layer -> layer |> Array.iter (fun src ->
    edgeSet.GetBwdOutEdges src
    |> List.iter (fun (dst, edge) ->
      [ EdgeBend.Left; EdgeBend.Right; EdgeBend.Mid ]
      |> List.map (computeEdgeCrossesByBackwardEdge portMap src dst)
      |> List.sortBy fst
      |> List.head
      |> snd
      |> assignBackwardEdgeBend portMap edge)
    )
  )

let private assignPorts g layout =
  let portMap = PortMap.Empty
  let edgeSet = (g: VisGraph).Edges |> EdgeSet.Create
  assignForwardEdgePorts edgeSet layout portMap
  assignBackwardEdgePorts edgeSet layout portMap
  portMap

let private layerY (layer: IVertex<VisBBlock>[]) =
  layer
  |> Array.map VisGraph.getYPos |> Array.min,
  layer
  |> Array.map (fun v -> VisGraph.getYPos v + VisGraph.getHeight v)
  |> Array.max

let private virtualVertexGeom (layerYMap: (float * float)[]) v =
  let cx = getCXPos v
  let top, bot =
    if v.VData.IsDummy then
      let layer = VisGraph.getLayer v
      layerYMap[layer]
    else
      let _, top, bot = vertexGeom v
      top, bot
  cx, top, bot

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
      let srcCx, sTopY, sBotY = virtualVertexGeom layerYMap src
      edgeSet.GetFwdOutEdges src
      |> List.iter (fun (dst, edge) ->
        let dstCx, dTopY, dBotY = virtualVertexGeom layerYMap dst
        let sPortX = getOrDefault portMap.FwdOutPorts edge srcCx
        let dPortX = getOrDefault portMap.FwdInPorts edge dstCx
        edge.Points <- addFwdEdgePoint sPortX sBotY dPortX dTopY)))

let private routeBackwardEdges edges layout portMap =
  ()

let private routeSelfCycleEdge (edgeSet: EdgeSet) layout portMap =
  ()
  // layout
  // |> Array.iter (fun layer ->
  //   layer
  //   |> Array.iter (fun v ->
  //     if List.isEmpty (edgeSet.GetSelfCycleEdge v) |> not then
  //       let cx, topY, botY = vertexGeom v
  //       let leftX, rightX, _, _ = safeBox v
  //       let sideX = if goRight then rightX else leftX
  //       let fwdOutXs = sidePortX outMap outFwdEdges goRight cx v edges
  //       let fwdInXs = sidePortX inMap inFwdEdges goRight cx v edges
  //       let backOutXs = sidePortX backOutMap outBackEdges goRight cx v edges
  //       let backInXs = sidePortX backInMap inBackEdges goRight cx v edges
  //       let outermostOut =
  //         let fwdBase = outermostPort goRight cx fwdOutXs
  //         let backBase = outermostPort goRight cx backOutXs
  //         if goRight then max fwdBase backBase else min fwdBase backBase
  //       let outermostIn =
  //         let fwdBase = outermostPort goRight cx fwdInXs
  //         let backBase = outermostPort goRight cx backInXs
  //         if goRight then max fwdBase backBase else min fwdBase backBase
  //       cycles |> List.iteri (fun i edge ->
  //         let step = float (i + 1) * portOffset
  //         let outX = outermostOut + if goRight then step else -step
  //         let inX = outermostIn + if goRight then step else -step
  //         edge.Points <-
  //           [| pos outX botY
  //              pos outX (botY + StubMargin - EdgeOffset)
  //              pos sideX (botY + StubMargin - EdgeOffset)
  //              pos sideX (topY - StubMargin + EdgeOffset)
  //              pos inX (topY - StubMargin + EdgeOffset)
  //              pos inX topY |])
  //     else
  //       ()))

let private routeEdges g layout portMap =
  let edgeSet = (g: VisGraph).Edges |> EdgeSet.Create
  adjustLayerYPositions edgeSet layout
  routeForwardEdges edgeSet layout portMap
  routeBackwardEdges edgeSet layout portMap
  routeSelfCycleEdge edgeSet layout portMap

let private restoreBackEdge (g: VisGraph) (src, dst, edge: VisEdge) =
  match g.TryFindEdge(dst, src) with
  | Some e when e.Label.IsBackEdge -> g.RemoveEdge(dst, src) |> ignore
  | _ -> ()
  g.AddEdge(src, dst, edge) |> ignore

let private restoreEdges (g: VisGraph) backEdgeList =
  backEdgeList
  |> List.filter (fun (src: IVertex<VisBBlock>, dst: IVertex<VisBBlock>, _) ->
    not src.VData.IsDummy && not dst.VData.IsDummy)
  |> List.iter (restoreBackEdge g)

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

let private makeFwdEdgeSmooth g (src, dst) (edge: VisEdge, dummies) =
  if edge.IsBackEdge then
    ()
  else
    let pts = removeDummyLoop g src dst [||] dummies |> makeSmooth
    let newEdge = VisEdge edge.Type
    newEdge.IsBackEdge <- false
    newEdge.Points <- pts
    g.AddEdge(src, dst, newEdge) |> ignore
  dummies |> List.iter (g.RemoveVertex >> ignore)

let private postprocessEdges (g: VisGraph) dummyMap =
  dummyMap |> Map.iter (makeFwdEdgeSmooth g)

let drawEdges g vLayout backEdgeList dummyMap =
  restoreEdges g backEdgeList
  let layout = sortLayers vLayout
  routeEdges g layout (assignPorts g layout)
  postprocessEdges g dummyMap