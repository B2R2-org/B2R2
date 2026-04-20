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

module internal B2R2.RearEnd.Visualization.EdgePost

open System.Collections.Generic
open B2R2.MiddleEnd.BinGraph

let [<Literal>] private CoordEpsilon = 0.001
let [<Literal>] private EdgeOffset = 4.0
let [<Literal>] private StubMargin = 30.0
let [<Literal>] private SafeMargin = 15.0

/// Axis-aligned rectangle as (left, right, top, bottom).
type private Box = float * float * float * float

/// Cached polyline segments for a graph edge. Computed once per
/// postprocess pass and reused across all crossing checks.
type private SegCacheEntry =
  { Edge: VisEdge
    Second: IVertex<VisBBlock>
    Segs: (VisPosition * VisPosition) array }

type private EdgePlan =
  { Src: IVertex<VisBBlock>
    Dst: IVertex<VisBBlock>
    Edge: VisEdge
    Dummies: IVertex<VisBBlock> list
    ChainInfos: (IVertex<VisBBlock> * IVertex<VisBBlock> * VisEdge) list
    ChainEdges: VisEdge list
    Merged: VisPosition array
    FinalPoints: VisPosition array }

let private sameX (a: VisPosition) (b: VisPosition) =
  abs (a.X - b.X) < CoordEpsilon

let private sameY (a: VisPosition) (b: VisPosition) =
  abs (a.Y - b.Y) < CoordEpsilon

let private samePos (a: VisPosition) (b: VisPosition) =
  sameX a b && sameY a b

let private pos x y = VisPosition.Create(x, y)

let private vertexBox (v: IVertex<VisBBlock>): Box =
  let x = VisGraph.getXPos v
  let y = VisGraph.getYPos v
  let w = VisGraph.getWidth v
  let h = VisGraph.getHeight v
  x, x + w, y, y + h

/// Use a small margin; larger overlaps are detected as intrusions.
let private safeBox (v: IVertex<VisBBlock>): Box =
  let x = VisGraph.getXPos v
  let y = VisGraph.getYPos v
  let w = VisGraph.getWidth v
  let h = VisGraph.getHeight v
  x - SafeMargin, x + w + SafeMargin,
  y - SafeMargin, y + h + SafeMargin

/// Return non-degenerate consecutive segments of the polyline.
let private polySegments (pts: VisPosition array) =
  let n = pts.Length
  if n < 2 then
    [||]
  else
    let buf = ResizeArray<VisPosition * VisPosition>(n - 1)
    for i in 0 .. n - 2 do
      let a = pts[i]
      let b = pts[i + 1]
      if not (samePos a b) then buf.Add(a, b) else ()
    buf.ToArray()

let private countBends (pts: VisPosition array) =
  let n = pts.Length
  if n < 3 then 0
  else
    let mutable acc = 0
    for i in 0 .. n - 3 do
      let a = pts[i]
      let b = pts[i + 1]
      let c = pts[i + 2]
      let straight =
        (sameX a b && sameX b c) || (sameY a b && sameY b c)
      if not straight then acc <- acc + 1 else ()
    acc

/// Drop adjacent duplicates and collapse axis-aligned collinear triples
/// in a single pass.
let private dedupAndCollapse (points: VisPosition array) =
  let n = points.Length
  if n = 0 then [||]
  else
    let out = ResizeArray<VisPosition>(n)
    for i in 0 .. n - 1 do
      let p = points[i]
      let k = out.Count
      if k = 0 then out.Add p
      elif samePos out[k - 1] p then ()
      elif k >= 2 then
        let a = out[k - 2]
        let b = out[k - 1]
        let collinear =
          (sameX a b && sameX b p) || (sameY a b && sameY b p)
        if collinear then out[k - 1] <- p
        else out.Add p
      else out.Add p
    out.ToArray()

let private orientation ax ay bx by cx cy =
  let v = (bx - ax) * (cy - ay) - (by - ay) * (cx - ax)
  if abs v <= CoordEpsilon then 0
  elif v > 0.0 then 1
  else -1

let private onSegment ax ay bx by px py =
  px >= min ax bx - CoordEpsilon
  && px <= max ax bx + CoordEpsilon
  && py >= min ay by - CoordEpsilon
  && py <= max ay by + CoordEpsilon

let private segmentsIntersectRaw (a0: VisPosition) (a1: VisPosition)
                                 (b0: VisPosition) (b1: VisPosition) =
  let ax, ay = a0.X, a0.Y
  let bx, by = a1.X, a1.Y
  let cx, cy = b0.X, b0.Y
  let dx, dy = b1.X, b1.Y
  let o1 = orientation ax ay bx by cx cy
  let o2 = orientation ax ay bx by dx dy
  let o3 = orientation cx cy dx dy ax ay
  let o4 = orientation cx cy dx dy bx by
  if o1 <> o2 && o3 <> o4 then true
  elif o1 = 0 && onSegment ax ay bx by cx cy then true
  elif o2 = 0 && onSegment ax ay bx by dx dy then true
  elif o3 = 0 && onSegment cx cy dx dy ax ay then true
  elif o4 = 0 && onSegment cx cy dx dy bx by then true
  else false

let private onlyTouchesAtEndpoint a0 a1 b0 b1 =
  let shared =
    samePos a0 b0 || samePos a0 b1
    || samePos a1 b0 || samePos a1 b1
  if not shared then false
  else
    let collinear =
      (sameX a0 a1 && sameX b0 b1 && sameX a0 b0)
      || (sameY a0 a1 && sameY b0 b1 && sameY a0 b0)
    not collinear

let private segmentsProperlyIntersect a0 a1 b0 b1 =
  segmentsIntersectRaw a0 a1 b0 b1
  && not (onlyTouchesAtEndpoint a0 a1 b0 b1)

/// One Liang-Barsky clip step. Updates t0/t1/ok through byrefs so that
/// segIntersectsRect allocates no helper arrays.
let private clipLB p q (t0: byref<float>) (t1: byref<float>) (ok: byref<bool>) =
  if abs p <= CoordEpsilon then
    if q < 0.0 then ok <- false else ()
  else
    let r = q / p
    if p < 0.0 then
      if r > t1 then ok <- false
      elif r > t0 then t0 <- r
      else ()
    elif r < t0 then ok <- false
    elif r < t1 then t1 <- r
    else ()

let private segIntersectsRect ((l, r, t, b): Box) (x0, y0)
                              (x1: float, y1: float) =
  let eL = l + CoordEpsilon
  let eR = r - CoordEpsilon
  let eT = t + CoordEpsilon
  let eB = b - CoordEpsilon
  let insideA = x0 > eL && x0 < eR && y0 > eT && y0 < eB
  let insideB = x1 > eL && x1 < eR && y1 > eT && y1 < eB
  if insideA || insideB then true
  else
    let dx = x1 - x0
    let dy = y1 - y0
    let mutable t0 = 0.0
    let mutable t1 = 1.0
    let mutable ok = true
    clipLB -dx (x0 - eL) &t0 &t1 &ok
    if ok then clipLB dx (eR - x0) &t0 &t1 &ok else ()
    if ok then clipLB -dy (y0 - eT) &t0 &t1 &ok else ()
    if ok then clipLB dy (eB - y0) &t0 &t1 &ok else ()
    ok && t0 <= t1 + CoordEpsilon

let private buildSafeBoxes (realVertices: IVertex<VisBBlock> array) =
  realVertices |> Array.map (fun v -> v, safeBox v)

let private segmentHitsAnySafeBox (safeBoxes: (IVertex<VisBBlock> * Box) array)
  (src: IVertex<VisBBlock>) (dst: IVertex<VisBBlock>) (p0: VisPosition)
  (p1: VisPosition) =
  let mutable hit = false
  let mutable i = 0
  while not hit && i < safeBoxes.Length do
    let v, box = safeBoxes[i]
    if v <> src && v <> dst && segIntersectsRect box (p0.X, p0.Y) (p1.X, p1.Y)
    then hit <- true
    else ()
    i <- i + 1
  hit

let private polylineViolatesSafeBox safeBoxes src dst (pts: VisPosition array) =
  let n = pts.Length
  let mutable hit = false
  let mutable i = 0
  while not hit && i < n - 1 do
    let a = pts[i]
    let b = pts[i + 1]
    if not (samePos a b) && segmentHitsAnySafeBox safeBoxes src dst a b then
      hit <- true
    else
      ()
    i <- i + 1
  hit

let private buildEdgeSegCache (g: VisGraph) =
  g.Edges
  |> Array.map (fun e ->
    { Edge = e.Label
      Second = e.Second
      Segs = polySegments e.Label.Points })

/// Count proper crossings between mySegs and every non-ignored graph
/// edge. Uses an axis-aligned bounding-box prefilter to avoid calling
/// the full intersection test for clearly disjoint segments.
let private countCrossings (cache: SegCacheEntry array) (ignored: HashSet<_>)
  isBackEdge dst (mySegs: (VisPosition * VisPosition) array) =
  let mutable n = 0
  for i in 0 .. cache.Length - 1 do
    let entry = cache[i]
    let other = entry.Edge
    let skip =
      ignored.Contains other
      || (isBackEdge && other.IsBackEdge && entry.Second = dst)
    if not skip then
      let otherSegs = entry.Segs
      for j in 0 .. mySegs.Length - 1 do
        let a0, a1 = mySegs[j]
        let aMinX = min a0.X a1.X
        let aMaxX = max a0.X a1.X
        let aMinY = min a0.Y a1.Y
        let aMaxY = max a0.Y a1.Y
        for k in 0 .. otherSegs.Length - 1 do
          let b0, b1 = otherSegs[k]
          let bMinX = min b0.X b1.X
          let bMaxX = max b0.X b1.X
          if not (aMaxX < bMinX - CoordEpsilon || bMaxX < aMinX - CoordEpsilon)
          then
            let bMinY = min b0.Y b1.Y
            let bMaxY = max b0.Y b1.Y
            if not (aMaxY < bMinY - CoordEpsilon
              || bMaxY < aMinY - CoordEpsilon)
              && segmentsProperlyIntersect a0 a1 b0 b1
            then n <- n + 1
            else ()
          else
            ()
    else
      ()
  n

let private forwardEdgeAvoidNeighborBigBox (g: VisGraph) realVertices =
  let vertexBoxes = realVertices |> Array.map vertexBox
  let hitMap =
    Dictionary<struct (int * int * int * int),
               ResizeArray<IVertex<VisBBlock> * VisEdge>>()
  let requiredYMap = Dictionary<VisEdge, float>(HashIdentity.Reference)
  let boxKey ((l, r, t, b): Box) = struct (int l, int r, int t, int b)
  for e in g.Edges do
    let src = e.First
    let dst = e.Second
    let edge = e.Label
    if not edge.IsBackEdge && not src.VData.IsDummy
      && not dst.VData.IsDummy && edge.Points.Length >= 3 then
      let p0 = edge.Points[0]
      let p1 = edge.Points[1]
      let p2 = edge.Points[2]
      for i in 0 .. realVertices.Length - 1 do
        let v = realVertices[i]
        if v <> src && v <> dst then
          let box = vertexBoxes[i]
          let hit = segIntersectsRect box (p0.X, p0.Y) (p1.X, p1.Y)
                    || segIntersectsRect box (p1.X, p1.Y) (p2.X, p2.Y)
          if hit then
            let key = boxKey box
            match hitMap.TryGetValue key with
            | true, xs -> xs.Add(src, edge)
            | _ ->
              let xs = ResizeArray()
              xs.Add(src, edge)
              hitMap[key] <- xs
          else
            ()
        else
          ()
    else
      ()
  for kv in hitMap do
    let struct (_, _, _, bInt) = kv.Key
    let boxBottom = float bInt
    kv.Value
    |> Seq.groupBy fst
    |> Seq.iter (fun (_, edgesFromSameSrc) ->
      edgesFromSameSrc
      |> Seq.map snd
      |> Seq.distinct
      |> Seq.sortBy (fun edge ->
        if edge.Points.Length >= 3 then edge.Points[2].X else edge.Points[0].X)
      |> Seq.iteri (fun i edge ->
        let requiredY = boxBottom + StubMargin + float i * EdgeOffset
        match requiredYMap.TryGetValue edge with
        | true, oldY -> requiredYMap[edge] <- max oldY requiredY
        | _ -> requiredYMap[edge] <- requiredY))
  for kv in requiredYMap do
    let edge = kv.Key
    let newStubY = kv.Value
    if edge.Points.Length >= 4 then
      let pts = Array.copy edge.Points
      let stubY = max pts[1].Y newStubY
      pts[1] <- VisPosition.Create(pts[1].X, stubY)
      pts[2] <- VisPosition.Create(pts[2].X, max pts[2].Y stubY)
      edge.Points <- pts
    else
      ()

let private collectChainEdgeInfos (g: VisGraph) src dst dummies =
  let rec loop acc cur = function
    | dummy :: rest ->
      let e = g.FindEdge(cur, dummy)
      loop ((cur, dummy, e.Label) :: acc) dummy rest
    | [] ->
      let e = g.FindEdge(cur, dst)
      List.rev ((cur, dst, e.Label) :: acc)
  loop [] src dummies

let private collectMergedPoints chainInfos =
  let buf = ResizeArray<VisPosition>()
  for (_, _, e: VisEdge) in chainInfos do for p in e.Points do buf.Add p
  buf.ToArray()

let private buildIgnoredEdgeSet edges =
  let hs = HashSet<VisEdge>(HashIdentity.Reference)
  edges |> List.iter (fun e -> hs.Add e |> ignore)
  hs

/// Merge shortcut fragments and collapse the resulting polyline.
let private buildShortcutCandidate prefix middle suffix =
  Array.concat [| prefix; middle; suffix |] |> dedupAndCollapse

let private tryAcceptShortcut
    cache safeBoxes src dst ignoredEdges isBackEdge oldCross cand =
  if polylineViolatesSafeBox safeBoxes src dst cand then None
  else
    let segs = polySegments cand
    if countCrossings cache ignoredEdges isBackEdge dst segs <= oldCross
    then Some cand
    else None

let private tryIntersectYOnSegment targetY (a: VisPosition) (b: VisPosition) =
  let minY = min a.Y b.Y
  let maxY = max a.Y b.Y
  if targetY < minY - CoordEpsilon || targetY > maxY + CoordEpsilon then
    None
  elif sameY a b then
    if abs (a.Y - targetY) <= CoordEpsilon then Some a.X else None
  else
    let t = (targetY - a.Y) / (b.Y - a.Y)
    if t < -CoordEpsilon || t > 1.0 + CoordEpsilon then None
    else Some(a.X + t * (b.X - a.X))

let private tryFindPointAtY targetY segStart segEnd pickFirst
                            (pts: VisPosition array) =
  let mutable best: (int * VisPosition) option = None
  let mutable i = segStart
  let mutable stop = false
  while not stop && i <= segEnd do
    match tryIntersectYOnSegment targetY pts[i] pts[i + 1] with
    | Some x ->
      best <- Some(i, pos x targetY)
      if pickFirst then stop <- true else ()
    | None -> ()
    i <- i + 1
  best

/// Backward-edge postprocessing.
let private tryExtractBackwardPrefix (pts: VisPosition array) =
  if pts.Length < 8 then None else Some pts[0..3]

let private buildLayerTopMap (g: VisGraph) =
  g.Vertices
  |> Seq.groupBy (fun (v: IVertex<VisBBlock>) -> v.VData.Layer)
  |> Seq.map (fun (layer, vs) ->
    layer, vs |> Seq.map VisGraph.getYPos |> Seq.min)
  |> Map.ofSeq

let private dummyTopPoint (layerTopMap: Map<int, float>) v =
  let cx = VisGraph.getXPos v + VisGraph.getWidth v / 2.0
  let topY =
    if v.VData.IsDummy then
      match Map.tryFind v.VData.Layer layerTopMap with
      | Some y -> y
      | None -> VisGraph.getYPos v
    else
      VisGraph.getYPos v
  VisPosition.Create(cx, topY)

let private tryFindPointIndex (p: VisPosition) (pts: VisPosition array) =
  let mutable found = -1
  let mutable i = 0
  while found < 0 && i < pts.Length do
    if samePos p pts[i] then found <- i else ()
    i <- i + 1
  if found < 0 then None else Some found

let private tryBackwardNearestDummyShortcut cache layerTopMap safeBoxes src dst
  ignoredEdges prefix dummies (pts: VisPosition array) =
  let hits =
    dummies
    |> List.choose (fun dummy ->
      let targetTop = dummyTopPoint layerTopMap dummy
      match tryFindPointIndex targetTop pts with
      | Some idx -> Some(idx, targetTop)
      | None -> None)
    |> List.sortByDescending fst
  match hits with
  | [] -> None
  | _ ->
    let oldCross = countCrossings cache ignoredEdges true dst (polySegments pts)
    hits
    |> List.tryPick (fun (idx, targetTop) ->
      let cand = buildShortcutCandidate prefix [| targetTop |] pts[idx + 1..]
      tryAcceptShortcut cache safeBoxes src dst ignoredEdges true oldCross cand)

let private tryBackwardInsertPointAtAdjustedY cache safeBoxes src dst
  ignoredEdges (pts: VisPosition array) =
  if pts.Length < 7 then
    None
  else
    let n = pts.Length
    let prefix = pts[0..3]
    let approachY =
      let ab = min pts[n - 2].Y pts[n - 3].Y
      if n >= 5 then min ab pts[n - 4].Y else ab
    match tryFindPointAtY approachY 3 (n - 2) true pts with
    | Some(segIdx, targetPt)
      when segIdx > 3 || not (samePos targetPt pts[3]) ->
      let cand = buildShortcutCandidate prefix [| targetPt |] pts[segIdx + 1..]
      let oldBends = countBends pts
      let newBends = countBends cand
      if newBends >= oldBends then None
      elif polylineViolatesSafeBox safeBoxes src dst cand then None
      else
        let old = countCrossings cache ignoredEdges true dst (polySegments pts)
        let neC = countCrossings cache ignoredEdges true dst (polySegments cand)
        if neC > old then None else Some cand
    | _ -> None

let private optimizeBackwardStage1 cache layerTopMap safeBoxes src dst
  ignoredEdges dummies (merged: VisPosition array) =
  match tryExtractBackwardPrefix merged with
  | None -> merged
  | Some prefix ->
    match tryBackwardNearestDummyShortcut cache layerTopMap safeBoxes src dst
      ignoredEdges prefix dummies merged with
    | Some optimized -> optimized
    | None -> merged

let private optimizeBackwardStage2 cache safeBoxes src dst ignoredEdges
  (merged: VisPosition array) =
  match tryBackwardInsertPointAtAdjustedY cache safeBoxes src dst ignoredEdges
    merged with
  | Some optimized -> optimized
  | None -> merged

/// Segments of the edge polyline excluding the final port-offset segment
/// (pts[n-2] → pts[n-1]), which commonly creates spurious crossings among
/// backward edges arriving at the same destination box.
let private approachSegs (pts: VisPosition array) =
  if pts.Length < 3 then [||] else polySegments pts[0..pts.Length - 2]

/// True when the approach segments (all but the last) of two backward-edge
/// polylines properly intersect each other.
let private approachSegsCross ptsA ptsB =
  let segsA = approachSegs ptsA
  let segsB = approachSegs ptsB
  segsA |> Array.exists (fun (a0, a1) ->
    let aMinX = min a0.X a1.X
    let aMaxX = max a0.X a1.X
    let aMinY = min a0.Y a1.Y
    let aMaxY = max a0.Y a1.Y
    segsB |> Array.exists (fun (b0, b1) ->
      let bMinX = min b0.X b1.X
      let bMaxX = max b0.X b1.X
      let bMinY = min b0.Y b1.Y
      let bMaxY = max b0.Y b1.Y
      not (aMaxX < bMinX - CoordEpsilon || bMaxX < aMinX - CoordEpsilon
      || aMaxY < bMinY - CoordEpsilon || bMaxY < aMinY - CoordEpsilon)
      && segmentsProperlyIntersect a0 a1 b0 b1))

let private buildRawPlans (g: VisGraph) dummyMap =
  dummyMap
  |> Map.toList
  |> List.choose (fun ((src, dst), (edge: VisEdge, dummies)) ->
    if List.isEmpty dummies then
      None
    else
      let chainInfos = collectChainEdgeInfos g src dst dummies
      let chainEdges = chainInfos |> List.map (fun (_, _, e) -> e)
      let merged = collectMergedPoints chainInfos |> dedupAndCollapse
      Some
        { Src = src
          Dst = dst
          Edge = edge
          Dummies = dummies
          ChainInfos = chainInfos
          ChainEdges = chainEdges
          Merged = merged
          FinalPoints = merged })

let private runStage1 cache layerTopMap safeBoxes plans =
  plans
  |> List.map (fun plan ->
    let ignoredEdges = buildIgnoredEdgeSet plan.ChainEdges
    let pts =
      if plan.Edge.IsBackEdge then
        optimizeBackwardStage1 cache layerTopMap safeBoxes plan.Src plan.Dst
          ignoredEdges plan.Dummies plan.Merged
      else
        plan.Merged
    { plan with FinalPoints = pts })

let private runStage2 cache safeBoxes plans =
  let backGroups =
    plans
    |> List.filter (fun plan -> plan.Edge.IsBackEdge)
    |> List.groupBy (fun plan -> plan.Dst)
    |> Map.ofList
  plans
  |> List.map (fun plan ->
    if not plan.Edge.IsBackEdge then
      plan
    else
      let groupPlans = Map.find plan.Dst backGroups
      let groupEdges = groupPlans |> List.collect (fun p -> p.ChainEdges)
      let ignoredEdges = buildIgnoredEdgeSet groupEdges
      let pts =
        optimizeBackwardStage2 cache safeBoxes plan.Src plan.Dst ignoredEdges
          plan.FinalPoints
      { plan with FinalPoints = pts })

/// Stage 3: among backward edges that share the same destination, reject
/// (revert to Merged) any plan whose FinalPoints cross another plan's
/// FinalPoints in the approach zone. The final port-offset segment is
/// excluded from both sides to avoid spurious hits caused by short offsets
/// at the destination end.
let private runStage3 plans =
  let backGroupsMap =
    plans
    |> List.filter (fun p -> p.Edge.IsBackEdge)
    |> List.groupBy (fun p -> p.Dst)
    |> Map.ofList
  plans
  |> List.map (fun plan ->
    if not plan.Edge.IsBackEdge then
      plan
    else
      match Map.tryFind plan.Dst backGroupsMap with
      | None | Some [] | Some [ _ ] -> plan
      | Some groupPlans ->
        let hasCrossing =
          groupPlans |> List.exists (fun other ->
            not (obj.ReferenceEquals(other.Edge, plan.Edge)) &&
            approachSegsCross plan.FinalPoints other.FinalPoints)
        if hasCrossing then { plan with FinalPoints = plan.Merged } else plan)

let private applyEdgePlan (g: VisGraph) (plan: EdgePlan) =
  plan.ChainInfos
  |> List.iter (fun (src, dst, _) -> g.RemoveEdge(src, dst) |> ignore)
  let newEdge = VisEdge plan.Edge.Type
  newEdge.IsBackEdge <- plan.Edge.IsBackEdge
  newEdge.Points <- plan.FinalPoints
  g.AddEdge(plan.Src, plan.Dst, newEdge) |> ignore
  plan.Dummies |> List.iter (g.RemoveVertex >> ignore)

let postprocessEdges (g: VisGraph) dummyMap =
  let realVertices =
    g.Vertices
    |> Seq.filter (fun (v: IVertex<VisBBlock>) -> not v.VData.IsDummy)
    |> Seq.toArray
  forwardEdgeAvoidNeighborBigBox g realVertices
  let layerTopMap = buildLayerTopMap g
  let safeBoxes = buildSafeBoxes realVertices
  let cache = buildEdgeSegCache g
  buildRawPlans g dummyMap
  |> runStage1 cache layerTopMap safeBoxes
  |> runStage2 cache safeBoxes
  |> runStage3
  |> List.iter (applyEdgePlan g)
