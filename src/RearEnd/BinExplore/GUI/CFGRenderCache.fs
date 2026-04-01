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

namespace B2R2.RearEnd.BinExplore.GUI

open System
open B2R2.RearEnd.Visualization

type CFGRenderCache =
  { EdgeBounds: EdgeBounds array
    EdgeSegmentBounds: EdgeBounds array array }

and EdgeBounds =
  { MinX: float
    MaxX: float
    MinY: float
    MaxY: float }
with
  member this.Intersects(left: float, right: float, top: float, bottom: float) =
    this.MinX < right
    && this.MaxX > left
    && this.MinY < bottom
    && this.MaxY > top

[<RequireQualifiedAccess>]
module CFGRenderCache =
  let hasVisibleSegment renderCache edgeID left right top bottom =
    renderCache.EdgeSegmentBounds[edgeID]
    |> Array.exists (fun bounds -> bounds.Intersects(left, right, top, bottom))

  let isEdgeVisible renderCache edgeID left right top bottom =
    renderCache.EdgeBounds[edgeID].Intersects(left, right, top, bottom)
    && hasVisibleSegment renderCache edgeID left right top bottom

  let private computeEdgeBounds (pts: VisPosition[]) =
    if pts.Length < 2 then
      { MinX = Double.PositiveInfinity
        MaxX = Double.NegativeInfinity
        MinY = Double.PositiveInfinity
        MaxY = Double.NegativeInfinity }
    else
      let mutable minX = pts[0].X
      let mutable maxX = pts[0].X
      let mutable minY = pts[0].Y
      let mutable maxY = pts[0].Y
      for i in 1 .. pts.Length - 1 do
        let p = pts[i]
        minX <- min minX p.X
        maxX <- max maxX p.X
        minY <- min minY p.Y
        maxY <- max maxY p.Y
      { MinX = minX
        MaxX = maxX
        MinY = minY
        MaxY = maxY }

  let private computeSegmentBounds (pts: VisPosition[]) =
    Array.init (max 0 (pts.Length - 1)) (fun i ->
      let p1 = pts[i]
      let p2 = pts[i + 1]
      { MinX = min p1.X p2.X
        MaxX = max p1.X p2.X
        MinY = min p1.Y p2.Y
        MaxY = max p1.Y p2.Y })

  let create (graph: VisGraph) =
    let edgeBounds, edgeSegmentBounds =
      graph.Edges
      |> Array.map (fun e ->
        let pts = e.Label.Points
        computeEdgeBounds pts, computeSegmentBounds pts)
      |> Array.unzip
    { EdgeBounds = edgeBounds
      EdgeSegmentBounds = edgeSegmentBounds }
