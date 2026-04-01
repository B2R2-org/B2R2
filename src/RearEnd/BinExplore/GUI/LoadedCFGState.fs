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

type LoadedCFGState =
  { Graph: VisGraph
    ViewState: CFGViewState
    RenderCache: CFGRenderCache
    Minimap: MinimapStaticCache }

and MinimapStaticCache =
  { Width: float
    Height: float
    Scale: float
    OffsetX: float
    OffsetY: float
    EdgePolylines: Point[][]
    NodeRects: Rect[] }

[<RequireQualifiedAccess>]
module MinimapStaticCache =
  let [<Literal>] private MaxSize = 220.0

  let private computeDimension viewportWidth viewportHeight gWidth gHeight =
    let referenceWidth = max gWidth viewportWidth |> max 1.0
    let referenceHeight = max gHeight viewportHeight |> max 1.0
    let aspectRatio = referenceWidth / referenceHeight
    let ratio = MaxSize / referenceWidth
    let maxLen = if ratio < 0.01 then viewportWidth / 3.0 else MaxSize
    if aspectRatio >= 1.0 then
      let w = maxLen
      let h = maxLen / aspectRatio
      let scale = maxLen / referenceWidth
      w, h, scale
    else
      let w = maxLen * aspectRatio
      let h = maxLen
      let scale = maxLen / referenceHeight
      w, h, scale

  let private buildEdgePolylines minX minY scale offsetX offsetY graph =
    (graph: VisGraph).Edges
    |> Array.map (fun e ->
      e.Label.Points
      |> Array.map (fun p ->
        Point((p.X - minX) * scale + offsetX, (p.Y - minY) * scale + offsetY)))

  let private buildNodeRects minX minY scale offsetX offsetY (graph: VisGraph) =
    graph.Vertices
    |> Array.map (fun n ->
      Rect(
        (n.VData.Coordinate.X - minX) * scale + offsetX,
        (n.VData.Coordinate.Y - minY) * scale + offsetY,
        n.VData.Width * scale,
        n.VData.Height * scale
      ))

  let create (viewportWidth, viewportHeight) viewState (graph: VisGraph) =
    let width, height, scale =
      computeDimension viewportWidth viewportHeight
        viewState.GraphWidth viewState.GraphHeight
    let offsetX = (width - viewState.GraphWidth * scale) / 2.0
    let offsetY = (height - viewState.GraphHeight * scale) / 2.0
    let minX = viewState.GraphMinX
    let minY = viewState.GraphMinY
    let edgePolylines =
      buildEdgePolylines minX minY scale offsetX offsetY graph
    let nodeRects =
      buildNodeRects minX minY scale offsetX offsetY graph
    { Width = width
      Height = height
      Scale = scale
      OffsetX = offsetX
      OffsetY = offsetY
      EdgePolylines = edgePolylines
      NodeRects = nodeRects }