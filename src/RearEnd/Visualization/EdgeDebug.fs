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
open System.IO
open System.Text
open B2R2.MiddleEnd.BinGraph
open B2R2.RearEnd.Visualization

type private EdgeInfo = IVertex<VisBBlock> * IVertex<VisBBlock> * VisEdge

type private RoutedSegment =
  { Edge: VisEdge
    Src: IVertex<VisBBlock>
    Dst: IVertex<VisBBlock>
    X0: float
    Y0: float
    X1: float
    Y1: float
    P0: int
    P1: int }

type VisValidationKind =
  | SafeBoxIntrusion

type VisValidationIssue =
  { Kind: VisValidationKind
    Message: string
    VertexID: VertexID option
    Edge1: VisEdge
    Edge2: VisEdge option
    PointA: VisPosition option
    PointB: VisPosition option }

type VisEdgeRelationshipMetrics =
  { ForwardCrossingCount: int
    BackCrossingCount: int
    TotalCrossingCount: int
    ForwardBentEdgeCount: int
    BackBentEdgeCount: int
    TotalBentEdgeCount: int }

type VisGraphAnalysis =
  { Metrics: VisEdgeRelationshipMetrics
    ValidationIssues: VisValidationIssue list }

let [<Literal>] private StubMargin = 30.0
let [<Literal>] private XTolerance = 4.0
let [<Literal>] private CoordTolerance = 0.001

let private pos x y = VisPosition.Create(x, y)

let private approxEq a b = abs (a - b) <= XTolerance

let private coordEq a b = abs (a - b) <= CoordTolerance

let private getEdgeInfos (g: VisGraph): EdgeInfo list =
  g.FoldEdge((fun acc e -> (e.First, e.Second, e.Label) :: acc), [])

let private samePos (p1: VisPosition) (p2: VisPosition) =
  coordEq p1.X p2.X && coordEq p1.Y p2.Y

let private preserveDirection
    (a: VisPosition) (b: VisPosition) (c: VisPosition) =
  let abx = b.X - a.X
  let aby = b.Y - a.Y
  let bcx = c.X - b.X
  let bcy = c.Y - b.Y
  let cross = abx * bcy - aby * bcx
  let dot = abx * bcx + aby * bcy
  abs cross <= CoordTolerance && dot >= -CoordTolerance

let private simplifyPoints (points: VisPosition[]) =
  let dedup =
    points
    |> Array.fold (fun acc p ->
      match acc with
      | prev :: _ when samePos prev p -> acc
      | _ -> p :: acc) []
    |> List.rev
  let rec collapse = function
    | [] | [ _ ] | [ _; _ ] as xs -> xs
    | a :: b :: c :: rest when preserveDirection a b c ->
      collapse (a :: c :: rest)
    | hd :: tl -> hd :: collapse tl
  dedup |> collapse |> List.toArray

let private safeBox (v: IVertex<VisBBlock>) =
  let x = VisGraph.getXPos v
  let y = VisGraph.getYPos v
  x - StubMargin,
  x + VisGraph.getWidth v + StubMargin,
  y - StubMargin,
  y + VisGraph.getHeight v + StubMargin

let private segmentPoints (seg: RoutedSegment) =
  pos seg.X0 seg.Y0, pos seg.X1 seg.Y1

let private fmtVertex (v: IVertex<VisBBlock>) =
  $"id={VisGraph.getID v}, addr=0x{v.VData.BlockAddress:x}, " +
  $"layer={VisGraph.getLayer v}, idx={v.VData.Index}"

let private fmtEdgeEnds (src: IVertex<VisBBlock>) (dst: IVertex<VisBBlock>) =
  $"src({fmtVertex src}) -> dst({fmtVertex dst})"

let private fmtSegment (seg: RoutedSegment) =
  $"S[P{seg.P0}-P{seg.P1}] {fmtEdgeEnds seg.Src seg.Dst}"

let private segmentsOfEdge ((src, dst, edge): EdgeInfo) =
  simplifyPoints edge.Points
  |> Array.mapi (fun i p -> i, p)
  |> Array.pairwise
  |> Array.choose (fun ((i0, p0), (i1, p1)) ->
    if approxEq p0.X p1.X && approxEq p0.Y p1.Y then
      None
    else
      Some
        { Edge = edge
          Src = src
          Dst = dst
          X0 = p0.X
          Y0 = p0.Y
          X1 = p1.X
          Y1 = p1.Y
          P0 = i0
          P1 = i1 })

let private collectSegments (edgeInfos: EdgeInfo list): RoutedSegment list =
  edgeInfos |> List.collect (segmentsOfEdge >> Array.toList)

let private isIncidentEdge (v: IVertex<VisBBlock>) ((src, dst, _): EdgeInfo) =
  src = v || dst = v

let private pointInsideRectInterior (left, right, top, bottom) x y =
  x > left + XTolerance && x < right - XTolerance &&
  y > top + XTolerance && y < bottom - XTolerance

let private segmentIntersectsRectInterior (left, right, top, bottom)
                                          (x0, y0) (x1, y1) =
  if pointInsideRectInterior (left, right, top, bottom) x0 y0 ||
     pointInsideRectInterior (left, right, top, bottom) x1 y1 then
    true
  else
    let dx = x1 - x0
    let dy = y1 - y0
    let p = [| -dx; dx; -dy; dy |]
    let q =
      [| x0 - (left + XTolerance)
         (right - XTolerance) - x0
         y0 - (top + XTolerance)
         (bottom - XTolerance) - y0 |]
    let mutable t0 = 0.0
    let mutable t1 = 1.0
    let mutable ok = true
    for i in 0 .. 3 do
      let pi = p[i]
      let qi = q[i]
      if approxEq pi 0.0 then
        if qi < 0.0 then ok <- false else ()
      else
        let r = qi / pi
        if pi < 0.0 then
          if r > t1 then ok <- false
          elif r > t0 then t0 <- r
          else ()
        else
          if r < t0 then ok <- false
          elif r < t1 then t1 <- r
          else ()
    ok && t0 < t1 + XTolerance

let private segmentIntersectsSafeBoxInterior (left, right, top, bottom) seg =
  segmentIntersectsRectInterior (left, right, top, bottom)
                                (seg.X0, seg.Y0) (seg.X1, seg.Y1)

let private validateSafeBoxes
    (edgeInfos: EdgeInfo list)
    (segments: RoutedSegment list)
    (g: VisGraph) =
  let issues = ResizeArray<VisValidationIssue>()
  g.IterVertex(fun v ->
    if not v.VData.IsDummy then
      let left, right, top, bottom = safeBox v
      let allowedEdges =
        edgeInfos
        |> List.filter (isIncidentEdge v)
        |> List.map (fun (_, _, e) -> e)
        |> HashSet
      segments
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
              PointB = Some p1 }
        else
          ()))
  issues |> Seq.toList

let private orientation
    (p1: VisPosition) (p2: VisPosition) (p3: VisPosition) =
  (p2.X - p1.X) * (p3.Y - p1.Y) - (p2.Y - p1.Y) * (p3.X - p1.X)

let private orientationSign x =
  if x > CoordTolerance then 1
  elif x < -CoordTolerance then -1
  else 0

let private segmentsProperlyCross seg1 seg2 =
  let a = pos seg1.X0 seg1.Y0
  let b = pos seg1.X1 seg1.Y1
  let c = pos seg2.X0 seg2.Y0
  let d = pos seg2.X1 seg2.Y1
  let o1 = orientationSign (orientation a b c)
  let o2 = orientationSign (orientation a b d)
  let o3 = orientationSign (orientation c d a)
  let o4 = orientationSign (orientation c d b)
  o1 * o2 < 0 && o3 * o4 < 0

let private countCrossings (edgeInfos: EdgeInfo list) =
  let segments = collectSegments edgeInfos |> List.toArray
  let mutable count = 0
  for i in 0 .. segments.Length - 2 do
    let seg1 = segments[i]
    for j in i + 1 .. segments.Length - 1 do
      let seg2 = segments[j]
      if not (obj.ReferenceEquals(seg1.Edge, seg2.Edge)) &&
         segmentsProperlyCross seg1 seg2 then
        count <- count + 1
      else
        ()
  count

type private SegmentDirection =
  | Vertical
  | Horizontal
  | Diagonal

let private segmentDirection (p0: VisPosition) (p1: VisPosition) =
  if coordEq p0.X p1.X then Vertical
  elif coordEq p0.Y p1.Y then Horizontal
  else Diagonal

let private hasDirectionChange (points: VisPosition[]) =
  points
  |> Array.pairwise
  |> Array.map (fun (p0, p1) -> segmentDirection p0 p1)
  |> Array.pairwise
  |> Array.exists (fun (d0, d1) -> d0 <> d1)

let private isVerticalSegment (p0: VisPosition) (p1: VisPosition) =
  coordEq p0.X p1.X && not (coordEq p0.Y p1.Y)

let private leavesSafeZoneVertically
    (src: IVertex<VisBBlock>) (points: VisPosition[]) =
  src.VData.IsDummy || points.Length < 2
  || isVerticalSegment points[0] points[1]

let private entersSafeZoneVertically
    (dst: IVertex<VisBBlock>) (points: VisPosition[]) =
  dst.VData.IsDummy || points.Length < 2 ||
  isVerticalSegment points[points.Length - 2] points[points.Length - 1]

let private isBentEdge ((src, dst, edge): EdgeInfo) =
  let points = simplifyPoints edge.Points
  points.Length >= 2 &&
  (hasDirectionChange points ||
   not (leavesSafeZoneVertically src points) ||
   not (entersSafeZoneVertically dst points))

let private countBentEdges (edgeInfos: EdgeInfo list) =
  edgeInfos |> List.filter isBentEdge |> List.length

let private computeMetrics (edgeInfos: EdgeInfo list) =
  let forwardEdges =
    edgeInfos |> List.filter (fun (_, _, edge) -> not edge.IsBackEdge)
  let backEdges =
    edgeInfos |> List.filter (fun (_, _, edge) -> edge.IsBackEdge)
  { ForwardCrossingCount = countCrossings forwardEdges
    BackCrossingCount = countCrossings backEdges
    TotalCrossingCount = countCrossings edgeInfos
    ForwardBentEdgeCount = countBentEdges forwardEdges
    BackBentEdgeCount = countBentEdges backEdges
    TotalBentEdgeCount = countBentEdges edgeInfos }

let private analyzeCore
    (g: VisGraph)
    (edgeInfos: EdgeInfo list)
    (segments: RoutedSegment list) : VisGraphAnalysis =
  { Metrics = computeMetrics edgeInfos
    ValidationIssues = validateSafeBoxes edgeInfos segments g }

let analyze (g: VisGraph) =
  let edgeInfos = getEdgeInfos g
  let segments = collectSegments edgeInfos
  analyzeCore g edgeInfos segments

let evaluate (g: VisGraph) = (analyze g).Metrics

let validate (g: VisGraph) = (analyze g).ValidationIssues

let hasIssue (g: VisGraph) =
  analyze g |> fun analysis -> not (List.isEmpty analysis.ValidationIssues)

let private fmtPos (p: VisPosition) =
  $"({p.X}, {p.Y})"

let private fmtPoints (pts: VisPosition[]) =
  if Array.isEmpty pts then "[]"
  else
    pts
    |> Array.map fmtPos
    |> String.concat " -> "
    |> sprintf "[%s]"

let private fmtVertexShort (v: IVertex<VisBBlock>) =
  $"id={VisGraph.getID v}, addr=0x{v.VData.BlockAddress:x}, " +
  $"dummy={v.VData.IsDummy}, layer={VisGraph.getLayer v}, " +
  $"idx={VisGraph.getIndex v}"

let private fmtVertexGeom (v: IVertex<VisBBlock>) =
  let x = VisGraph.getXPos v
  let y = VisGraph.getYPos v
  let w = VisGraph.getWidth v
  let h = VisGraph.getHeight v
  $"x={x}, y={y}, w={w}, h={h}"

let private fmtEdgeShort
    (src: IVertex<VisBBlock>) (dst: IVertex<VisBBlock>) (e: VisEdge) =
  $"{fmtVertexShort src} -> {fmtVertexShort dst}, type={e.Type}, " +
  $"back={e.IsBackEdge}"

let private tryFindEdgeInfo
    (edgeInfos: EdgeInfo list)
    (edge: VisEdge) : EdgeInfo option =
  edgeInfos
  |> List.tryFind (fun (_, _, e) -> obj.ReferenceEquals(e, edge))

let private fmtIssueEdge (edgeInfos: EdgeInfo list) (edge: VisEdge) =
  match tryFindEdgeInfo edgeInfos edge with
  | Some(src, dst, e) -> fmtEdgeShort src dst e
  | None -> $"type={edge.Type}, back={edge.IsBackEdge}"

let private fmtValidationKind = function
  | SafeBoxIntrusion -> "SafeBoxIntrusion"

let private appendLine (sb: StringBuilder) (s: string) =
  sb.AppendLine(s) |> ignore

let private dumpSummary
    (sb: StringBuilder)
    (g: VisGraph)
    (edgeInfos: EdgeInfo list)
    (analysis: VisGraphAnalysis) =
  let metrics = analysis.Metrics
  let mutable vertexCount = 0
  let mutable dummyCount = 0
  g.IterVertex(fun v ->
    vertexCount <- vertexCount + 1
    if v.VData.IsDummy then dummyCount <- dummyCount + 1)
  appendLine sb "==== Summary ===="
  appendLine sb $"Vertices            : {vertexCount}"
  appendLine sb $"Dummy vertices      : {dummyCount}"
  appendLine sb $"Edges               : {List.length edgeInfos}"
  appendLine sb $"Safe-box issues     : {List.length analysis.ValidationIssues}"
  appendLine sb $"Forward crossings   : {metrics.ForwardCrossingCount}"
  appendLine sb $"Back crossings      : {metrics.BackCrossingCount}"
  appendLine sb $"Total crossings     : {metrics.TotalCrossingCount}"
  appendLine sb $"Forward bent edges  : {metrics.ForwardBentEdgeCount}"
  appendLine sb $"Back bent edges     : {metrics.BackBentEdgeCount}"
  appendLine sb $"Total bent edges    : {metrics.TotalBentEdgeCount}"
  appendLine sb ""

let private dumpValidationIssues
    (sb: StringBuilder)
    (edgeInfos: EdgeInfo list)
    (analysis: VisGraphAnalysis) =
  appendLine sb "==== Validation Issues ===="
  if List.isEmpty analysis.ValidationIssues then
    appendLine sb "[]"
  else
    analysis.ValidationIssues
    |> List.iteri (fun i issue ->
      appendLine sb $"[Issue {i}] kind={fmtValidationKind issue.Kind}"
      appendLine sb $"  Message : {issue.Message}"
      appendLine sb $"  VertexID: {defaultArg issue.VertexID -1}"
      appendLine sb $"  Edge1   : {fmtIssueEdge edgeInfos issue.Edge1}"
      match issue.Edge2 with
      | Some edge -> appendLine sb $"  Edge2   : {fmtIssueEdge edgeInfos edge}"
      | None -> appendLine sb "  Edge2   : None"
      match issue.PointA with
      | Some p -> appendLine sb $"  PointA  : {fmtPos p}"
      | None -> appendLine sb "  PointA  : None"
      match issue.PointB with
      | Some p -> appendLine sb $"  PointB  : {fmtPos p}"
      | None -> appendLine sb "  PointB  : None"
      appendLine sb "")
  appendLine sb ""

let private dumpVertices
    (sb: StringBuilder)
    (g: VisGraph)
    (edgeInfos: EdgeInfo list) =
  appendLine sb "==== Vertices ===="
  g.IterVertex(fun v ->
    let preds =
      edgeInfos |> List.filter (fun (_, dst, _) -> dst = v)
    let succs =
      edgeInfos |> List.filter (fun (src, _, _) -> src = v)
    appendLine sb $"[Vertex] {fmtVertexShort v}"
    appendLine sb $"  Geom: {fmtVertexGeom v}"
    appendLine sb
      ($"  PredCount={List.length preds}, " + $"SuccCount={List.length succs}")
    if List.isEmpty preds then
      appendLine sb "  Preds: []"
    else
      appendLine sb "  Preds:"
      preds |> List.iter (fun (src, _, e) ->
        appendLine sb
          $"    <- {fmtVertexShort src}, type={e.Type}, back={e.IsBackEdge}")
    if List.isEmpty succs then
      appendLine sb "  Succs: []"
    else
      appendLine sb "  Succs:"
      succs |> List.iter (fun (_, dst, e) ->
        appendLine sb
          $"    -> {fmtVertexShort dst}, type={e.Type}, back={e.IsBackEdge}")
    appendLine sb "")

let private dumpEdges (sb: StringBuilder) (edgeInfos: EdgeInfo list) =
  appendLine sb "==== Edges ===="
  edgeInfos
  |> List.iteri (fun i (src, dst, e) ->
    appendLine sb $"[Edge {i}] {fmtEdgeShort src dst e}"
    appendLine sb $"  SrcGeom: {fmtVertexGeom src}"
    appendLine sb $"  DstGeom: {fmtVertexGeom dst}"
    appendLine sb $"  Points : {fmtPoints e.Points}"
    appendLine sb $"  Simple : {fmtPoints (simplifyPoints e.Points)}"
    appendLine sb "")

let private dumpDummyVerticesOnly
    (sb: StringBuilder)
    (g: VisGraph)
    (edgeInfos: EdgeInfo list) =
  appendLine sb "==== Dummy Vertices Only ===="
  g.IterVertex(fun v ->
    if v.VData.IsDummy then
      let inEdges =
        edgeInfos |> List.filter (fun (_, dst, _) -> dst = v)
      let outEdges =
        edgeInfos |> List.filter (fun (src, _, _) -> src = v)
      appendLine sb $"[Dummy] {fmtVertexShort v}"
      appendLine sb $"  Geom: {fmtVertexGeom v}"
      if List.isEmpty inEdges then
        appendLine sb "  Incoming: []"
      else
        appendLine sb "  Incoming:"
        inEdges |> List.iter (fun (src, _, e) ->
          appendLine sb
            ($"    <- {fmtVertexShort src}, type={e.Type}, " +
             $"back={e.IsBackEdge}, points={fmtPoints e.Points}"))
      if List.isEmpty outEdges then
        appendLine sb "  Outgoing: []"
      else
        appendLine sb "  Outgoing:"
        outEdges |> List.iter (fun (_, dst, e) ->
          appendLine sb
            ($"    -> {fmtVertexShort dst}, type={e.Type}, " +
             $"back={e.IsBackEdge}, points={fmtPoints e.Points}"))
      appendLine sb "")

let dumpToFile (path: string) (title: string) (g: VisGraph) =
  let edgeInfos = getEdgeInfos g
  let segments = collectSegments edgeInfos
  let analysis = analyzeCore g edgeInfos segments
  let sb = StringBuilder(65536)
  appendLine sb $"Graph Dump: {title}"
  dumpSummary sb g edgeInfos analysis
  dumpValidationIssues sb edgeInfos analysis
  dumpVertices sb g edgeInfos
  dumpEdges sb edgeInfos
  dumpDummyVerticesOnly sb g edgeInfos
  let dir = Path.GetDirectoryName path
  if String.IsNullOrWhiteSpace dir |> not then
    Directory.CreateDirectory dir |> ignore
  File.WriteAllText(path, sb.ToString())

let dumpWithAutoName (dir: string) (tag: string) (g: VisGraph) =
  Directory.CreateDirectory dir |> ignore
  let fileName = $"graph_dump_{tag}_{DateTime.Now:yyyyMMdd_HHmmss_fff}.log"
  let path = Path.Combine(dir, fileName)
  dumpToFile path $"Graph dump: {tag}" g
  path
