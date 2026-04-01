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

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

/// TODO: move all constants in this project into a separate module.
let [<Literal>] private StubMargin = 30.0

let private pos x y = VisPosition.Create(x, y)

let private selectEdges predicate project edges =
  (edges: Edge<VisBBlock, VisEdge>[])
  |> Array.choose (fun e ->
    let src, dst, kind = e.First, e.Second, e.Label
    if predicate src dst kind then Some(project src dst kind) else None)
  |> Array.toList

let private getOrDefault (dict: Dictionary<'Key, 'Value>) key defaultValue =
  match dict.TryGetValue key with
  | true, value -> value
  | _ -> defaultValue

let private populatePortMap (portMap: Dictionary<_, _>) assignments =
  assignments |> List.iter (fun (edge, x) -> portMap[edge] <- x)

let private addPoint (pts: ResizeArray<VisPosition>) x y = pts.Add(pos x y)

let private geomCx (v: IVertex<VisBBlock>) =
  VisGraph.getXPos v + VisGraph.getWidth v / 2.0

let private vertexGeom (v: IVertex<VisBBlock>) =
  let cx = geomCx v
  let top = VisGraph.getYPos v
  let bot = top + VisGraph.getHeight v
  cx, top, bot

/// TODO: optimize this by using per-vertex edge information.
let private outFwdEdges (v: IVertex<VisBBlock>) edges =
  selectEdges (fun src dst edge ->
    src = v && dst <> v && not edge.IsBackEdge)
    (fun _ dst kind -> dst, kind) edges

let private inFwdEdges (v: IVertex<VisBBlock>) edges =
  selectEdges (fun src dst edge ->
    dst = v && src <> v && not edge.IsBackEdge)
    (fun src _ edge -> src, edge) edges

let private partitionPairsByCentre cx edges =
  let isLeft (v, _) = geomCx v < cx - 4.0
  let isCentre (v, _) = abs (geomCx v - cx) <= 4.0
  let lefts, rest = List.partition isLeft edges
  let centres, rights = List.partition isCentre rest
  lefts, centres, rights

let private assignCentrePorts cx edges =
  edges |> List.mapi (fun i (_, edge) ->
    edge, cx + (float i - float (List.length edges - 1) / 2.0) * 4.0)

let private assignSidePortsFrom baseX goRight edges =
  edges |> List.mapi (fun i (_, edge) ->
    let offset = float (i + 1) * 4.0
    edge, baseX + (if goRight then offset else -offset))

let private assignFwdPorts cx lefts centres rights =
  assignSidePortsFrom cx false lefts @ assignCentrePorts cx centres
  @ assignSidePortsFrom cx true rights

let private layerGap nearByLayer (v: IVertex<VisBBlock>) =
  abs (VisGraph.getLayer v - nearByLayer)

let private assignFwdOutPorts (v: IVertex<VisBBlock>) edges =
  let cx = geomCx v
  if List.isEmpty (outFwdEdges v edges) then
    []
  else
    let lefts, centres, rights = partitionPairsByCentre cx (outFwdEdges v edges)
    let sortKey (dst: IVertex<VisBBlock>, _) =
      layerGap (VisGraph.getLayer v) dst, -abs (geomCx dst - cx)
    assignFwdPorts cx (List.sortByDescending sortKey lefts) centres
      (List.sortByDescending sortKey rights)

let private assignFwdInPorts v edges =
  let cx = geomCx v
  let dstLay = VisGraph.getLayer v
  let fwdIns = inFwdEdges v edges
  if List.isEmpty fwdIns then
    []
  else
    let lefts, centres, rights = partitionPairsByCentre cx fwdIns
    let sortKey (src: IVertex<VisBBlock>, _) =
      let gap = abs (VisGraph.getLayer src - dstLay)
      let xDist = abs (geomCx src - cx)
      -gap, xDist
    assignFwdPorts cx (List.sortBy sortKey lefts)
      (List.sortBy sortKey centres) (List.sortBy sortKey rights)

let private assignForwardEdgePorts edges layout portMap =
  layout
  |> Array.iter (Array.iter (fun v ->
    assignFwdOutPorts v edges |> populatePortMap portMap.FwdOutPorts
    assignFwdInPorts v edges |> populatePortMap portMap.FwdInPorts))

let private assignBackwardEdgePorts edges layout portMap =
  ()

let private assignPorts g layout =
  let portMap = PortMap.Empty
  let edges = (g: VisGraph).Edges
  assignForwardEdgePorts edges layout portMap
  assignBackwardEdgePorts edges layout portMap
  portMap

let private routeNoBand srcX srcY dstX dstY =
  let pts = ResizeArray<VisPosition>()
  addPoint pts srcX srcY
  addPoint pts srcX (srcY + StubMargin)
  addPoint pts dstX (dstY - StubMargin)
  addPoint pts dstX dstY
  pts |> Seq.toArray

let private routeForwardEdges edges layout portMap =
  layout
  |> Array.iter (fun layer ->
    layer
    |> Array.sortBy VisGraph.getXPos
    |> Array.iter (fun src ->
      let srcCx, _, sBotY = vertexGeom src
      outFwdEdges src edges
      |> List.iter (fun (dst, edge) ->
        let dstCx, dTopY, _ = vertexGeom dst
        let sPortX = getOrDefault portMap.FwdOutPorts edge srcCx
        let dPortX = getOrDefault portMap.FwdInPorts edge dstCx
        edge.Points <- routeNoBand sPortX sBotY dPortX dTopY)))

let private routeBackwardEdges edges layout portMap =
  ()

let private routeEdges g layout portMap =
  let edges = (g: VisGraph).Edges
  routeForwardEdges edges layout portMap
  routeBackwardEdges edges layout portMap

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

let private makeFwdEdgeSmooth g (src, dst) ((edge: VisEdge), dummies) =
  if edge.IsBackEdge then
    ()
  else
    let pts = removeDummyLoop g src dst [||] dummies |> makeSmooth
    let newEdge = VisEdge(edge.Type)
    newEdge.IsBackEdge <- false
    newEdge.Points <- pts
    g.AddEdge(src, dst, newEdge) |> ignore
  dummies |> List.iter (g.RemoveVertex >> ignore)

let private postprocessEdges (g: VisGraph) dummyMap =
  dummyMap |> Map.iter (makeFwdEdgeSmooth g)

let drawEdges g vLayout backEdgeList dummyMap =
  restoreEdges g backEdgeList
  routeEdges g vLayout (assignPorts g vLayout)
  postprocessEdges g dummyMap