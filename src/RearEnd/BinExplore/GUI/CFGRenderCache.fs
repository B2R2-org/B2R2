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

open Avalonia
open B2R2.RearEnd.Visualization

/// Spatial queries shared by the retained graph layers.
type CFGRenderCache =
  { NodeIndex: CFGSpatialIndex
    EdgeIndex: CFGSpatialIndex }

[<RequireQualifiedAccess>]
module CFGRenderCache =
  let private nodeBounds (graph: VisGraph) =
    graph.Vertices |> Array.mapi (fun id v ->
      let data = v.VData
      id, Rect(data.Coordinate.X, data.Coordinate.Y, data.Width, data.Height))
    |> Array.filter (fun (id, _) -> not graph.Vertices[id].VData.IsDummy)

  let private edgeSegments (graph: VisGraph) =
    graph.Edges |> Array.mapi (fun id edge ->
      let points = edge.Label.Points
      Array.init (max 0 (points.Length - 1)) (fun i ->
        let a, b = points[i], points[i + 1]
        let left, top = min a.X b.X, min a.Y b.Y
        let width, height = abs (a.X - b.X), abs (a.Y - b.Y)
        (* Give horizontal and vertical segments nonempty bounds. *)
        id, Rect(left, top, width, height).Inflate(1.0)))
    |> Array.concat

  let create graph =
    { NodeIndex = CFGSpatialIndex.create (nodeBounds graph)
      EdgeIndex = CFGSpatialIndex.create (edgeSegments graph) }
