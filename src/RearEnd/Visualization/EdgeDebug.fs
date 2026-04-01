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

[<RequireQualifiedAccess>]
module internal B2R2.RearEnd.Visualization.EdgeDebug

open System
open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph
open B2R2.RearEnd.Visualization

type private EdgeInfo = IVertex<VisBBlock> * IVertex<VisBBlock> * VisEdge

type private RoutedSegment =
  { Edge: VisEdge
    Src: IVertex<VisBBlock>
    Dst: IVertex<VisBBlock>
    Orientation: SegmentOrientation
    Coord: float
    A0: float
    A1: float
    P0: int
    P1: int }

and private SegmentOrientation = | Vertical | Horizontal

type VisValidationIssue =
  { Kind: VisValidationKind
    Message: string
    VertexID: VertexID option
    Edge1: VisEdge
    Edge2: VisEdge option
    PointA: VisPosition option
    PointB: VisPosition option }

and VisValidationKind = | SafeBoxIntrusion | CollinearEdgeOverlap

let [<Literal>] private StubMargin = 50.0
let [<Literal>] private XTolerance = 4.0
let [<Literal>] private CoordEpsilon = 0.001

let private pos x y = VisPosition.Create(x, y)

let private approxEq a b = abs (a - b) <= XTolerance

let private quantizeCoord (x: float) = int (Math.Round(x * 1000.0))

let private rangesOverlap a0 a1 b0 b1 =
  let loA, hiA = min a0 a1, max a0 a1
  let loB, hiB = min b0 b1, max b0 b1
  not (hiA <= loB + XTolerance || hiB <= loA + XTolerance)

let private rangesOverlapStrict a0 a1 b0 b1 =
  let loA, hiA = min a0 a1, max a0 a1
  let loB, hiB = min b0 b1, max b0 b1
  not (hiA <= loB + CoordEpsilon || hiB <= loA + CoordEpsilon)

let private getEdgeInfos (g: VisGraph) =
  g.FoldEdge((fun acc e -> (e.First, e.Second, e.Label) :: acc), [])

let private safeBox (v: IVertex<VisBBlock>) =
  let x = VisGraph.getXPos v
  let y = VisGraph.getYPos v
  x - StubMargin,
  x + VisGraph.getWidth v + StubMargin,
  y - StubMargin,
  y + VisGraph.getHeight v + StubMargin

let private segmentPoints (seg: RoutedSegment) =
  match seg.Orientation with
  | Vertical -> pos seg.Coord seg.A0, pos seg.Coord seg.A1
  | Horizontal -> pos seg.A0 seg.Coord, pos seg.A1 seg.Coord

let private fmtVertex (v: IVertex<VisBBlock>) =
  $"id={VisGraph.getID v}, addr=0x{v.VData.BlockAddress:x}, \
  layer={VisGraph.getLayer v}, idx={v.VData.Index}"

let private fmtEdgeEnds (src: IVertex<VisBBlock>) (dst: IVertex<VisBBlock>) =
  $"src({fmtVertex src}) -> dst({fmtVertex dst})"

let private fmtSegment (seg: RoutedSegment) =
  let orient =
    match seg.Orientation with
    | Vertical -> "V"
    | Horizontal -> "H"
  $"{orient}[P{seg.P0}-P{seg.P1}] {fmtEdgeEnds seg.Src seg.Dst}"

let private segmentsOfEdge ((src, dst, edge): EdgeInfo) =
  edge.Points
  |> Array.mapi (fun i p -> i, p)
  |> Array.pairwise
  |> Array.choose (fun ((i0, p0), (i1, p1)) ->
    if approxEq p0.X p1.X && not (approxEq p0.Y p1.Y) then
      Some
        { Edge = edge
          Src = src
          Dst = dst
          Orientation = Vertical
          Coord = p0.X
          A0 = p0.Y
          A1 = p1.Y
          P0 = i0
          P1 = i1 }
    elif approxEq p0.Y p1.Y && not (approxEq p0.X p1.X) then
      Some
        { Edge = edge
          Src = src
          Dst = dst
          Orientation = Horizontal
          Coord = p0.Y
          A0 = p0.X
          A1 = p1.X
          P0 = i0
          P1 = i1 }
    else
      None)

let private isIncidentEdge (v: IVertex<VisBBlock>) ((src, dst, _): EdgeInfo) =
  src = v || dst = v

let private segmentIntersectsSafeBoxInterior (left, right, top, bottom) seg =
  match seg.Orientation with
  | Vertical ->
    let xInside =
      seg.Coord > left + XTolerance && seg.Coord < right - XTolerance
    let yOverlap = rangesOverlap seg.A0 seg.A1 top bottom
    xInside && yOverlap
  | Horizontal ->
    let yInside =
      seg.Coord > top + XTolerance && seg.Coord < bottom - XTolerance
    let xOverlap = rangesOverlap seg.A0 seg.A1 left right
    yInside && xOverlap

let private validateSafeBox (g: VisGraph) =
  let edgeInfos = getEdgeInfos g
  let issues = ResizeArray<VisValidationIssue>()
  g.IterVertex(fun v ->
    if not v.VData.IsDummy then
      let left, right, top, bottom = safeBox v
      let allowedEdges =
        edgeInfos
        |> List.filter (isIncidentEdge v)
        |> List.map (fun (_, _, e) -> e)
        |> HashSet
      edgeInfos
      |> List.collect (segmentsOfEdge >> Array.toList)
      |> List.iter (fun seg ->
        if not (allowedEdges.Contains seg.Edge) &&
          segmentIntersectsSafeBoxInterior (left, right, top, bottom) seg then
          let p0, p1 = segmentPoints seg
          issues.Add
            { Kind = SafeBoxIntrusion
              Message =
                $"Edge intrudes safe box of vertex " +
                $"id={VisGraph.getID v}, addr=0x{v.VData.BlockAddress:x}. " +
                $"edge={fmtSegment seg}"
              VertexID = Some(VisGraph.getID v)
              Edge1 = seg.Edge
              Edge2 = None
              PointA = Some p0
              PointB = Some p1 }))
  issues |> Seq.toList

let private validateOverlaps (g: VisGraph) =
  let edgeInfos = getEdgeInfos g
  let allSegments = edgeInfos |> List.collect (segmentsOfEdge >> Array.toList)
  let issues = ResizeArray<VisValidationIssue>()
  let verticals =
    allSegments
    |> List.filter (fun s -> s.Orientation = Vertical)
    |> List.groupBy (fun s -> quantizeCoord s.Coord)
  for _, group in verticals do
    let sorted = group |> List.sortBy (fun s -> min s.A0 s.A1)
    for i in 0 .. sorted.Length - 1 do
      for j in i + 1 .. sorted.Length - 1 do
        let a = sorted[i]
        let b = sorted[j]
        if not (obj.ReferenceEquals(a.Edge, b.Edge)) &&
          rangesOverlapStrict a.A0 a.A1 b.A0 b.A1 then
          let lo = max (min a.A0 a.A1) (min b.A0 b.A1)
          let hi = min (max a.A0 a.A1) (max b.A0 b.A1)
          issues.Add
            { Kind = CollinearEdgeOverlap
              Message =
                $"Two vertical edge segments overlap on the same X. " +
                $"edge1={fmtSegment a}, edge2={fmtSegment b}, " +
                $"x={a.Coord}, overlapY=[{lo}..{hi}]"
              VertexID = None
              Edge1 = a.Edge
              Edge2 = Some b.Edge
              PointA = Some(pos a.Coord lo)
              PointB = Some(pos a.Coord hi) }
        else
          ()
  let horizontals =
    allSegments
    |> List.filter (fun s -> s.Orientation = Horizontal)
    |> List.groupBy (fun s -> quantizeCoord s.Coord)
  for _, group in horizontals do
    let sorted = group |> List.sortBy (fun s -> min s.A0 s.A1)
    for i in 0 .. sorted.Length - 1 do
      for j in i + 1 .. sorted.Length - 1 do
        let a = sorted[i]
        let b = sorted[j]
        if not (obj.ReferenceEquals(a.Edge, b.Edge)) &&
          rangesOverlapStrict a.A0 a.A1 b.A0 b.A1 then
          let lo = max (min a.A0 a.A1) (min b.A0 b.A1)
          let hi = min (max a.A0 a.A1) (max b.A0 b.A1)
          issues.Add
            { Kind = CollinearEdgeOverlap
              Message =
                $"Two horizontal edge segments overlap on the same Y. " +
                $"edge1={fmtSegment a}, edge2={fmtSegment b}, " +
                $"y={a.Coord}, overlapX=[{lo}..{hi}]"
              VertexID = None
              Edge1 = a.Edge
              Edge2 = Some b.Edge
              PointA = Some(pos lo a.Coord)
              PointB = Some(pos hi a.Coord) }
        else
          ()
  issues |> Seq.toList

let validate (g: VisGraph) =
  let safeBoxIssues = validateSafeBox g
  let overlapIssues = validateOverlaps g
  safeBoxIssues @ overlapIssues

let hasIssue (g: VisGraph) = not (List.isEmpty (validate g))