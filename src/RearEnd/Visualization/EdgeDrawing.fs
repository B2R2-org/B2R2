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

/// Orthogonal edge drawing for hierarchical (Sugiyama-style) graphs.
/// Forward edges only. All segments are strictly horizontal or vertical.
module internal B2R2.RearEnd.Visualization.EdgeDrawing

open System
open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

let [<Literal>] private PortSpacingX = 4.0

let [<Literal>] private BendStepY = 4.0

let [<Literal>] private StubMargin = 20.0

let private pos x y = VisPosition.Create(x, y)

let private posOfCenterOutEdge (v: IVertex<VisBBlock>) =
  let x = VisGraph.getXPos v + VisGraph.getWidth v / 2.0
  let y = VisGraph.getYPos v + VisGraph.getHeight v
  x, y

let private posOfCenterInEdge (v: IVertex<VisBBlock>) =
  let x = VisGraph.getXPos v + VisGraph.getWidth v / 2.0
  let y = VisGraph.getYPos v
  x, y

let private isNearlyEqualX srcX dstX = abs (dstX - srcX) <= 4.0

let private restoreBackEdge (g: VisGraph) (src, dst, edge: VisEdge) =
  match g.TryFindEdge(dst, src) with
  | Some e when e.Label.IsBackEdge -> g.RemoveEdge(dst, src) |> ignore
  | _ -> ()
  g.AddEdge(src, dst, edge) |> ignore

let rec private removeDummyLoop (g: VisGraph) src dst acc = function
  | dummy :: rest ->
    let e = g.FindEdge(src, dummy)
    g.RemoveEdge(src, dummy) |> ignore
    removeDummyLoop g dummy dst (e.Label.Points :: acc) rest
  | [] ->
    let e = g.FindEdge(src, dst)
    g.RemoveEdge(src, dst) |> ignore
    (e.Label.Points :: acc) |> List.rev |> List.concat

let private removeDummy g (src, dst) ((edge: VisEdge), dummies) =
  let points =
    removeDummyLoop g src dst [] dummies
  VisEdge(edge.Type).IsBackEdge <- edge.IsBackEdge
  VisEdge(edge.Type).Points <- points
  g.AddEdge(src, dst, VisEdge(edge.Type)) |> ignore
  dummies |> List.iter (g.RemoveVertex >> ignore)

let private restoreOriginEdge g acc (edge: Edge<_, VisEdge>) =
  let (src: IVertex<VisBBlock>), (dst: IVertex<VisBBlock>) =
    edge.First, edge.Second
  let rec findDstVertex (g: IDiGraph<_, _>) (v: IVertex<VisBBlock>) =
    if v.VData.IsDummy then findDstVertex g (g.GetSuccs v |> Seq.head) else v
  if src.VData.IsDummy then acc
  elif dst.VData.IsDummy then (src, findDstVertex g dst, edge.Label) :: acc
  else (src, dst, edge.Label) :: acc

let private outForwardEdge src originalEdges =
  (originalEdges: (IVertex<VisBBlock> * IVertex<VisBBlock> * VisEdge) list)
  |> List.choose (fun (s, d, e) ->
    if s = src && not e.IsBackEdge && d <> src then Some(d, e) else None)

let private inForwardEdge dst originalEdges =
  (originalEdges: (IVertex<VisBBlock> * IVertex<VisBBlock> * VisEdge) list)
  |> List.choose (fun (s, d, e) ->
    if d = dst && not e.IsBackEdge && s <> dst then Some(s, e) else None)

let private vertexBounds vertex =
  let left = VisGraph.getXPos vertex - StubMargin
  let right = left + VisGraph.getWidth vertex + 2.0 * StubMargin
  let top = VisGraph.getYPos vertex - StubMargin
  let bottom = top + VisGraph.getHeight vertex + 2.0 * StubMargin
  left, right, top, bottom

let private assignPortOffset point edges =
  edges
  |> List.mapi (fun i (src, edge) ->
    let offset = (float i - float (List.length edges - 1) / 2.0) * PortSpacingX
    src, edge, point + offset
  )

let private horizonGap curLayer nextLayer =
  let upperLayerBottom =
    curLayer
    |> Array.map (fun v -> VisGraph.getYPos v + VisGraph.getHeight v)
    |> Array.max
  let nextLayerTop = nextLayer |> Array.map VisGraph.getYPos |> Array.min
  max 0.0 (upperLayerBottom + StubMargin * 2.0 + BendStepY - nextLayerTop)

let secureHorizontalEdgePathByLayerShift (layers: IVertex<VisBBlock>[][]) =
  Array.init (layers.Length - 1) (fun i -> horizonGap layers[i] layers[i + 1])
  |> Array.scan (+) 0.0
  |> Array.iteri (fun i shift ->
    if i > 0 && shift > 0.0 then
      layers[i]
      |> Array.iter (fun v ->
        v.VData.Coordinate.Y <- v.VData.Coordinate.Y + shift
      )
    else
      ()
  )

let private sharedBendY (vLayout: IVertex<VisBBlock>[][]) =
  Array.init (vLayout.Length - 1) (fun i ->
    let maxBottom =
      vLayout.[i]
      |> Array.map (fun v -> VisGraph.getYPos v + VisGraph.getHeight v)
      |> Array.max
    let minTop =
      vLayout.[i + 1]
      |> Array.map (fun v -> VisGraph.getYPos v)
      |> Array.min
    (maxBottom + minTop) / 2.0
  )

let private verticalGapInLayer (layer: IVertex<VisBBlock>[]) =
  let gaps = List<float * float * float>()
  let vertices =
    layer
    |> Array.filter (fun vertex -> vertex.VData.IsDummy |> not)
    |> Array.sortBy VisGraph.getXPos
  if vertices.Length = 0 then
    [||]
  else
    let leftmost, _, _, _ = vertexBounds vertices[0]
    gaps.Add((Double.NegativeInfinity, leftmost, leftmost - StubMargin))
    for i in 0 .. vertices.Length - 2 do
      let _, right, _, _ = vertexBounds vertices[i]
      let left, _, _, _ = vertexBounds vertices[i + 1]
      if left > right then
        gaps.Add((right, left, (right + left) / 2.0))
      else
        ()
    let _, rightmost, _, _ = vertexBounds vertices[vertices.Length - 1]
    gaps.Add((rightmost, Double.PositiveInfinity, rightmost + StubMargin))
    gaps.ToArray()

let private sharedBendX gaps curX =
  gaps
  |> Array.tryFind (fun (left, right, _) -> curX >= left && curX <= right)
  |> Option.map (fun (_, _, mid) -> mid)
  |> Option.defaultValue curX

let private checkEdgeHitsVertex (layer: IVertex<VisBBlock>[]) src dst curX =
  layer
  |> Array.tryFind (fun v ->
    (v.VData.IsDummy |> not && v <> src && v <> dst) &&
    let left, right, _, _ = vertexBounds v
    curX > left && curX < right
  )

let private gapDir gaps blocker preferRight =
  let left, right, _, _ = vertexBounds blocker
  if preferRight then
    gaps
    |> Array.tryFind (fun (gLeft, _, _) -> gLeft >= right)
    |> Option.map (fun (_, _, mid) -> mid)
    |> Option.defaultValue right
  else
    gaps
    |> Array.filter (fun (_, gRight, _) -> gRight <= left)
    |> Array.tryLast
    |> Option.map (fun (_, _, mid) -> mid)
    |> Option.defaultValue left

let private decideBendPoint (layerGaps: (float * float * float)[][])
  sharedBendY src dst srcX dstX vLayout =
  let srcLayer = VisGraph.getLayer src
  let dstLayer = VisGraph.getLayer dst
  let curX, bendPoint =
    [ srcLayer + 1 .. dstLayer - 1 ]
    |> List.fold (fun (curX, acc) layerIdx ->
      let curLayer = (vLayout: IVertex<VisBBlock>[][])[layerIdx]
      let nextX =
        match checkEdgeHitsVertex curLayer src dst curX with
        | Some blocker -> gapDir layerGaps[layerIdx] blocker (dstX >= curX)
        | None -> sharedBendX layerGaps[layerIdx] curX
      if abs (nextX - curX) > 0.5 then
        let bendY = (sharedBendY: float[])[layerIdx - 1]
        nextX, pos nextX bendY :: pos curX bendY :: acc
      else
        nextX, acc
    ) (srcX, [])
  if abs (curX - dstX) > 0.5 then
    let bendY = sharedBendY[dstLayer - 1]
    pos dstX bendY :: pos curX bendY :: bendPoint
  else
    bendPoint

let private routeEdge vLayout layerGaps (bendY: float[]) src dst
  (edge: VisEdge) srcX srcY dstX dstY =
  if VisGraph.getLayer dst - VisGraph.getLayer src = 1 then
    if isNearlyEqualX srcX dstX then
      edge.Points <-
        [ pos srcX srcY
          pos dstX dstY ]
    else
      edge.Points <-
        [ pos srcX srcY
          pos srcX bendY[VisGraph.getLayer src]
          pos dstX bendY[VisGraph.getLayer src]
          pos dstX dstY ]
  else
    let bendPoint = decideBendPoint layerGaps bendY src dst srcX dstX vLayout
    let pts = pos dstX dstY :: pos dstX (dstY - StubMargin) :: bendPoint
    edge.Points <- pos srcX srcY :: pos srcX (srcY + StubMargin) :: List.rev pts

let drawForwardEdges layerGaps sharedBendY vLayout originalEdges src =
  let outEdges = outForwardEdge src originalEdges
  if List.isEmpty outEdges then
    ()
  else
  let srcCenterX, srcY = posOfCenterOutEdge src
  let srcTagged = assignPortOffset srcCenterX outEdges
  for (dst, edge, srcX) in srcTagged do
    let dstCenterX, dstY = posOfCenterInEdge dst
    let inEdges = inForwardEdge dst originalEdges
    let dstX =
      assignPortOffset dstCenterX inEdges
      |> List.tryPick (fun (s, _, x) -> if s = src then Some x else None)
      |> Option.defaultValue dstCenterX
    routeEdge vLayout layerGaps sharedBendY src dst edge srcX srcY dstX dstY

let drawEdges g vLayout backEdgeList dummyMap =
  List.iter (restoreBackEdge g) backEdgeList
  let originEdges = g.FoldEdge(restoreOriginEdge g, [])
  secureHorizontalEdgePathByLayerShift vLayout
  let sharedBendY = sharedBendY vLayout
  let verticalGaps = Array.map verticalGapInLayer vLayout
  g.IterVertex(fun v ->
    if v.VData.IsDummy |> not then
      drawForwardEdges verticalGaps sharedBendY vLayout originEdges v
    else
      ())
  Map.iter (removeDummy g) dummyMap