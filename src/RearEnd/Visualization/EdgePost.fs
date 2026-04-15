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

/// Calculate floating-point number of crossings for a candidate bend point
let [<Literal>] private CoordEpsilon = 0.001
let [<Literal>] private EdgeOffset = 4.0
let [<Literal>] private StubMargin = 30.0

let private segmentIntersectsRectInterior (left, right, top, bottom)
                                          (x0, y0) (x1, y1) =
  let inside x y =
    x > left + CoordEpsilon && x < right - CoordEpsilon &&
    y > top + CoordEpsilon && y < bottom - CoordEpsilon
  if inside x0 y0 || inside x1 y1 then
    true
  else
    let dx = x1 - x0
    let dy = y1 - y0
    let p = [| -dx; dx; -dy; dy |]
    let q =
      [| x0 - (left + CoordEpsilon)
         (right - CoordEpsilon) - x0
         y0 - (top + CoordEpsilon)
         (bottom - CoordEpsilon) - y0 |]
    let mutable t0 = 0.0
    let mutable t1 = 1.0
    let mutable ok = true
    for i in 0 .. 3 do
      let pi = p[i]
      let qi = q[i]
      if abs pi <= CoordEpsilon then
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
    ok && t0 <= t1 + CoordEpsilon

let private vertexBox (v: IVertex<VisBBlock>) =
  let x = VisGraph.getXPos v
  let y = VisGraph.getYPos v
  let w = VisGraph.getWidth v
  let h = VisGraph.getHeight v
  x, x + w, y, y + h

let private forwardEdgeAvoidNeighborBigBox (g: VisGraph) =
  let requiredYMap = Dictionary<VisEdge, float>()
  let hitMap = Dictionary<struct (_ * _ * _ * _), ResizeArray<_ * VisEdge>>()
  let realVertices =
    g.Vertices
    |> Seq.filter (fun (v: IVertex<VisBBlock>) -> not v.VData.IsDummy)
    |> Seq.toArray
  let boxKey (l: float, r: float, t: float, b: float) =
    struct (int l, int r, int t, int b)
  g.FoldEdge((fun () e ->
    let src = e.First
    let dst = e.Second
    let edge = e.Label
    if (not edge.IsBackEdge) && (not src.VData.IsDummy) &&
      (not dst.VData.IsDummy) && edge.Points.Length >= 3 then
      let p0 = edge.Points[0]
      let p1 = edge.Points[1]
      let p2 = edge.Points[2]
      let segs = [| (p0, p1); (p1, p2) |]
      for v in realVertices do
        if v <> src && v <> dst then
          let l, r, t, b = vertexBox v
          let hit =
            segs
            |> Array.exists (fun (a, bpos) ->
              segmentIntersectsRectInterior (l, r, t, b) (a.X, a.Y)
                (bpos.X, bpos.Y))
          if hit then
            let key = boxKey (l, r, t, b)
            let arr =
              match hitMap.TryGetValue key with
              | true, xs -> xs
              | _ ->
                let xs = ResizeArray<_>()
                hitMap[key] <- xs
                xs
            arr.Add(src, edge)
          else
            ()
        else ()
    else
      ()
    ()), ())
  hitMap
  |> Seq.iter (fun kv ->
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
        | _ -> requiredYMap[edge] <- requiredY)))
  requiredYMap
  |> Seq.iter (fun kv ->
    let edge = kv.Key
    let newStubY = kv.Value
    if edge.Points.Length >= 4 then
      let pts = Array.copy edge.Points
      let p1 = pts[1]
      let p2 = pts[2]
      let stubY = max p1.Y newStubY
      pts[1] <- VisPosition.Create(p1.X, stubY)
      pts[2] <- VisPosition.Create(p2.X, max p2.Y stubY)
      edge.Points <- pts
    else
      ())

let rec private removeDummyLoop (g: VisGraph) src dst points = function
  | dummy :: rest ->
    let e = g.FindEdge(src, dummy)
    g.RemoveEdge(src, dummy) |> ignore
    removeDummyLoop g dummy dst (Array.append points e.Label.Points) rest
  | [] ->
    let e = g.FindEdge(src, dst)
    g.RemoveEdge(src, dst) |> ignore
    Array.append points e.Label.Points

let private makeForwardEdgeSmooth (points: VisPosition array) =
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

let private makeBackwardEdgeSmooth (points: VisPosition array) =
  let sameX (a: VisPosition) (b: VisPosition) = abs (a.X - b.X) < CoordEpsilon
  let sameY (a: VisPosition) (b: VisPosition) = abs (a.Y - b.Y) < CoordEpsilon
  let dedup (pts: VisPosition list) =
    pts
    |> List.fold (fun acc p ->
      match acc with
      | prev :: _ when sameX prev p && sameY prev p -> acc
      | _ -> p :: acc) []
    |> List.rev
  let rec collapse = function
    | [] | [ _ ] | [ _; _ ] as xs -> xs
    | a :: b :: c :: rest
      when (sameX a b && sameX b c) || (sameY a b && sameY b c) ->
      collapse (a :: c :: rest)
    | hd :: tl -> hd :: collapse tl
  points |> Array.toList |> dedup |> collapse |> List.toArray

let private makeEdgeSmooth g (src, dst) (edge: VisEdge, dummies) =
  if List.isEmpty dummies then
    ()
  else
    let removeDummyLoop = removeDummyLoop g src dst [||] dummies
    let pts =
      if edge.IsBackEdge then makeBackwardEdgeSmooth removeDummyLoop
      else makeForwardEdgeSmooth removeDummyLoop
    let newEdge = VisEdge edge.Type
    newEdge.IsBackEdge <- edge.IsBackEdge
    newEdge.Points <- pts
    g.AddEdge(src, dst, newEdge) |> ignore
  dummies |> List.iter (g.RemoveVertex >> ignore)

let postprocessEdges (g: VisGraph) dummyMap =
  forwardEdgeAvoidNeighborBigBox g
  dummyMap |> Map.iter (makeEdgeSmooth g)