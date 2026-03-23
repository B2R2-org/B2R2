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
module B2R2.RearEnd.BinExplore.GUI.CFGContent

open System
open Avalonia
open Avalonia.Controls
open Avalonia.Controls.Shapes
open Avalonia.Layout
open Avalonia.Media
open Avalonia.Input
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types
open Avalonia.Controls.Documents
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.RearEnd.Visualization

let [<Literal>] private MinimapMaxSize = 220.0

type private Dimension =
  { Width: float
    Height: float
    Scale: float
    OffsetX: float
    OffsetY: float }

let private unloadedView model text =
  Border.create [
    Border.background model.Theme.Window.Background
    Border.child (
      TextBlock.create [
        TextBlock.text text
        TextBlock.foreground model.Theme.Text.Primary
        TextBlock.fontSize 14.0
        TextBlock.margin 12.0
      ]
    )
  ] :> IView

let private computeMinimapDimension model graphWidth graphHeight =
  let viewportWidth, viewportHeight = model.CFGViewportSize
  let referenceWidth = max graphWidth viewportWidth
  let referenceHeight = max graphHeight viewportHeight
  let aspectRatio = referenceWidth / referenceHeight
  let ratio = MinimapMaxSize / referenceWidth
  let maxLen = if ratio < 0.01 then viewportWidth / 3.0 else MinimapMaxSize
  if aspectRatio >= 1.0 then
    let w = maxLen
    let h = maxLen / aspectRatio
    let scale = maxLen / referenceWidth
    { Width = w
      Height = h
      Scale = scale
      OffsetX = (w - graphWidth * scale) / 2.0
      OffsetY = (h - graphHeight * scale) / 2.0 }
  else
    let w = maxLen * aspectRatio
    let h = maxLen
    let scale = maxLen / referenceHeight
    { Width = w
      Height = h
      Scale = scale
      OffsetX = (w - graphWidth * scale) / 2.0
      OffsetY = (h - graphHeight * scale) / 2.0 }

let private getEdgeColor model = function
  | InterJmpEdge -> model.Theme.Graph.InterJmpEdge
  | InterCJmpTrueEdge -> model.Theme.Graph.InterCJmpTrue
  | InterCJmpFalseEdge -> model.Theme.Graph.InterCJmpFalse
  | IntraJmpEdge -> model.Theme.Graph.IntraJmpEdge
  | IntraCJmpTrueEdge -> model.Theme.Graph.IntraCJmpTrue
  | IntraCJmpFalseEdge -> model.Theme.Graph.IntraCJmpFalse
  | FallThroughEdge -> model.Theme.Graph.Fallthrough
  | CallEdge -> model.Theme.Graph.Call
  | RetEdge -> model.Theme.Graph.Return
  | _ -> model.Theme.Graph.InterJmpEdge

let private arrowheadPoints (tip: Point) (angleDeg: float) (size: float) =
  let rad = angleDeg * Math.PI / 180.0
  let bx = tip.X - size * cos rad
  let by = tip.Y - size * sin rad
  let lx, ly = bx + (size / 2.0) * sin rad, by - (size / 2.0) * cos rad
  let rx, ry = bx - (size / 2.0) * sin rad, by + (size / 2.0) * cos rad
  [| tip; Point(lx, ly); Point(rx, ry) |]

let private edgeLineView (pts: Point array) zoom (color: string) =
  Polyline.create [
    Polyline.points pts
    Polyline.stroke color
    Polyline.strokeThickness (1.0 * zoom)
    Polyline.isHitTestVisible false
  ] :> IView

let private edgeHitAreaThickness zoom =
  5.0 / sqrt zoom |> max 6.0 |> min 14.0

let private edgeHitAreaView dispatch (pts: Point array) zoom edgeID =
  Polyline.create [
    Polyline.points pts
    Polyline.stroke "#00FFFFFF"
    Polyline.strokeThickness (edgeHitAreaThickness zoom)
    Control.onPointerEntered (fun _ ->
      dispatch (SetHoveredCFGEdge(Some edgeID)))
    Control.onPointerExited (fun _ -> dispatch (SetHoveredCFGEdge None))
  ] :> IView

let private arrowheadView (tip: Point) (angle: float) zoom (color: string) =
  Polygon.create [
    Polygon.points (arrowheadPoints tip angle (8.0 * zoom))
    Polygon.fill color
    Polygon.isHitTestVisible false
  ] :> IView

let private edgeView dispatch pts zoom panX panY color edgeID =
  match (pts: VisPosition list) with
  | _ :: _ :: _ ->
    let scaled =
      pts
      |> Array.ofList
      |> Array.map (fun p -> Point(p.X * zoom + panX, p.Y * zoom + panY))
    let tip = scaled[scaled.Length - 1]
    let prev = scaled[scaled.Length - 2]
    let angle = Math.Atan2(tip.Y - prev.Y, tip.X - prev.X) * 180.0 / Math.PI
    Canvas.create [
      Canvas.children [
        edgeHitAreaView dispatch scaled zoom edgeID
        edgeLineView scaled zoom color
        arrowheadView tip angle zoom color
      ]
    ] |> View.withKey $"edge-{edgeID}" :> IView |> List.singleton
  | _ -> []

let private graphEdges model dispatch hovered cfg zoom panX panY isEdgeVisible =
  [ for edgeID, e in Array.indexed (cfg: VisGraph).Edges do
      let pts = e.Label.Points
      if isEdgeVisible pts then
        let color =
          if hovered = Some edgeID then model.Theme.Graph.HoveredEdge
          else getEdgeColor model e.Label.Type
        yield! edgeView dispatch pts zoom panX panY color edgeID
      else
        () ]

let private disasmView model lines =
  [ for words in lines do
      for word in words do
        Run.create
          [ Run.text word.AsmWordValue
            match word.AsmWordKind with
            | AsmWordKind.Address ->
              Run.foreground model.Theme.Text.Address
            | AsmWordKind.Mnemonic ->
              Run.foreground model.Theme.Text.Mnemonic
            | AsmWordKind.Variable ->
              Run.foreground model.Theme.Text.Variable
            | AsmWordKind.Value ->
              Run.foreground model.Theme.Text.Value
            | _ ->
              () ] :> IView
      LineBreak.create [] :> IView ]

let private nodeView model zoom panX panY fontSize x y w h lines =
  Border.create [
    Canvas.left (x * zoom + panX)
    Canvas.top (y * zoom + panY)
    Border.clipToBounds false
    Border.isHitTestVisible false
    Border.width w
    Border.height h
    Border.background model.Theme.Panel.AltBackground
    Border.borderBrush model.Theme.Panel.Border
    Border.borderThickness (1.0 * zoom)
    Border.cornerRadius 4.0
    Border.child (
      TextBlock.create [
        TextBlock.inlines (disasmView model lines)
        TextBlock.foreground model.Theme.Text.Primary
        TextBlock.fontSize (fontSize * zoom)
        TextBlock.margin (4.0 * zoom)
        TextBlock.padding 0.0
        TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
        TextBlock.textWrapping TextWrapping.NoWrap
      ]
    )
  ] |> View.withKey $"node-{x}.{y}-{zoom}-{panX}-{panY}" :> IView

let private graphNodes model (cfg: VisGraph) zoom panX panY isNodeVisible =
  let fontSize = model.Theme.Font.Monospace.FontSize
  [ for n in cfg.Vertices do
      let x, y = n.VData.Coordinate.X, n.VData.Coordinate.Y
      let w, h = n.VData.Width, n.VData.Height
      if not (isNodeVisible x y w h) then
        ()
      else
        let w = ceil (w * zoom) + 1.1 (* margin to avoid clipping *)
        let h = ceil (h * zoom) + 1.1
        let lines =
          if fontSize * zoom < 6.0 then [||]
          else (n.VData :> IVisualizable).Visualize()
        nodeView model zoom panX panY fontSize x y w h lines ]

let [<Literal>] private ZoomDelta = 0.05

let private pointerXY (e: PointerEventArgs) =
  match e.Source with
  | :? Control as ctrl ->
    let root = TopLevel.GetTopLevel ctrl
    let p =
      if isNull root then e.GetPosition ctrl
      else e.GetPosition root
    struct (p.X, p.Y)
  | _ -> struct (0.0, 0.0)

let private onWheel dispatch (e: PointerWheelEventArgs) =
  let delta = if e.Delta.Y > 0.0 then ZoomDelta else -ZoomDelta
  let struct (x, y) = pointerXY e
  dispatch (SetCFGZoom(delta, x, y))
  e.Handled <- true

let private onPressed dispatch (e: PointerPressedEventArgs) =
  let struct (x, y) = pointerXY e
  dispatch (StartCFGPan(x, y))
  match e.Source with
  | :? Control as ctrl -> e.Pointer.Capture ctrl
  | _ -> ()
  e.Handled <- true

let private onMoved dispatch (e: PointerEventArgs) =
  let struct (x, y) = pointerXY e
  dispatch (MoveCFGPan(x, y, ViewportSpace))
  e.Handled <- true

let private onReleased dispatch (e: PointerReleasedEventArgs) =
  dispatch EndCFGPan
  match e.Source with
  | :? Control -> e.Pointer.Capture null
  | _ -> ()
  e.Handled <- true

let private graphCanvasView model dispatch (cfg: VisGraph) viewState =
  let zoom = viewState.Zoom
  let panX, panY = viewState.PanX, viewState.PanY
  let hovered = viewState.HoveredEdge
  let viewportWidth, viewportHeight = model.CFGViewportSize
  let vpLeft = -panX / zoom
  let vpRight = (viewportWidth - panX) / zoom
  let vpTop = -panY / zoom
  let vpBottom = (viewportHeight - panY) / zoom
  let rec isEdgeVisible pts =
    match pts with
    | p1 :: ((p2 :: _) as rest) ->
      let minX, maxX = min p1.X p2.X, max p1.X p2.X
      let minY, maxY = min p1.Y p2.Y, max p1.Y p2.Y
      if minX < vpRight && maxX > vpLeft && minY < vpBottom && maxY > vpTop then
        true
      else
        isEdgeVisible rest
    | _ ->
      false
  let isNodeVisible x y w h =
    x < vpRight && x + w > vpLeft && y < vpBottom && y + h > vpTop
  Canvas.create [
    Canvas.background model.Theme.Window.Background
    Control.onPointerWheelChanged (onWheel dispatch)
    Control.onPointerPressed (onPressed dispatch)
    Control.onPointerMoved (onMoved dispatch)
    Control.onPointerReleased (onReleased dispatch)
    Canvas.children [
      yield! graphEdges model dispatch hovered cfg zoom panX panY isEdgeVisible
      yield! graphNodes model cfg zoom panX panY isNodeVisible
    ]
  ]

let private onMinimapClick dispatch minimapDim viewState e =
  match (e: PointerPressedEventArgs).Source with
  | :? Control as ctrl ->
    let p = e.GetPosition ctrl
    let scale = minimapDim.Scale
    let gx = (p.X - minimapDim.OffsetX) / scale + viewState.GraphMinX
    let gy = (p.Y - minimapDim.OffsetY) / scale + viewState.GraphMinY
    dispatch (JumpCFGPan(gx, gy))
    let struct (sx, sy) = pointerXY e
    dispatch (StartCFGPan(sx, sy))
    e.Pointer.Capture ctrl
    e.Handled <- true
  | _ -> ()

let private onRectMoved dispatch minimapScale e =
  let struct (x, y) = pointerXY e
  dispatch (MoveCFGPan(x, y, MinimapSpace minimapScale))
  e.Handled <- true

let private onRectReleased dispatch (e: PointerReleasedEventArgs) =
  dispatch EndCFGPan
  match e.Source with
  | :? Control -> e.Pointer.Capture null
  | _ -> ()
  e.Handled <- true

let private minimapEdges model scale minX minY offX offY (g: VisGraph) =
  g.Edges
  |> Array.map (fun e ->
    let pts =
      e.Label.Points
      |> List.map (fun p ->
        Point((p.X - minX) * scale + offX, (p.Y - minY) * scale + offY))
    Polyline.create [
        Polyline.points (pts |> Array.ofList)
        Polyline.stroke model.Theme.Graph.MinimapEdge
        Polyline.strokeThickness 0.5
        Polyline.isHitTestVisible false
    ] :> IView
  )

let private minimapNodes model scale minX minY offX offY (g: VisGraph) =
  g.Vertices
  |> Array.map (fun n ->
    Border.create [
      Canvas.left ((n.VData.Coordinate.X - minX) * scale + offX)
      Canvas.top ((n.VData.Coordinate.Y - minY) * scale + offY)
      Border.width (n.VData.Width * scale)
      Border.height (n.VData.Height * scale)
      Border.background model.Theme.Graph.MinimapNode
      Border.isHitTestVisible false
    ] :> IView
  )

let private minimapView model dispatch minimapDim (graph: VisGraph) viewState =
  let scale = minimapDim.Scale
  let minX, minY = viewState.GraphMinX, viewState.GraphMinY
  let offX, offY = minimapDim.OffsetX, minimapDim.OffsetY
  Border.create [
    Border.width minimapDim.Width
    Border.height minimapDim.Height
    Border.background "#44000000"
    Border.borderBrush model.Theme.Panel.Border
    Border.borderThickness 1.0
    Border.cornerRadius 4.0
    Border.cursor (new Cursor(StandardCursorType.SizeAll))
    Border.child (
      Canvas.create [
        Canvas.width minimapDim.Width
        Canvas.height minimapDim.Height
        Canvas.background model.Theme.Panel.AltBackground
        Canvas.opacity 0.9
        Control.onPointerPressed (onMinimapClick dispatch minimapDim viewState)
        Control.onPointerMoved (onRectMoved dispatch minimapDim.Scale)
        Control.onPointerReleased (onRectReleased dispatch)
        Canvas.children [
          yield! minimapEdges model scale minX minY offX offY graph
          yield! minimapNodes model scale minX minY offX offY graph
        ]
      ]
    )
  ]

let private onRectPressed dispatch e =
  let struct (x, y) = pointerXY e
  dispatch (StartCFGPan(x, y))
  match e.Source with
  | :? Control as ctrl -> e.Pointer.Capture ctrl
  | _ -> ()
  e.Handled <- true

let private minimapViewport model dispatch minimapDim viewState =
  let scale = minimapDim.Scale
  let viewportWidth, viewportHeight = model.CFGViewportSize
  let zoom, panX, panY = viewState.Zoom, viewState.PanX, viewState.PanY
  let minX, minY = viewState.GraphMinX, viewState.GraphMinY
  let offX, offY = minimapDim.OffsetX, minimapDim.OffsetY
  let graphLeft = -panX / zoom
  let graphTop = -panY / zoom
  let graphRight = (viewportWidth - panX) / zoom
  let graphBottom = (viewportHeight - panY) / zoom
  let minimapLeft = (graphLeft - minX) * scale + offX
  let minimapTop = (graphTop - minY) * scale + offY
  let minimapRight = (graphRight - minX) * scale + offX
  let minimapBottom = (graphBottom - minY) * scale + offY
  let minimapViewportWidth = minimapRight - minimapLeft
  let minimapViewportHeight = minimapBottom - minimapTop
  Border.create [
    Border.horizontalAlignment HorizontalAlignment.Right
    Border.verticalAlignment VerticalAlignment.Bottom
    Border.margin 12.0
    Border.child (
      Canvas.create [
        Canvas.width minimapDim.Width
        Canvas.height minimapDim.Height
        Canvas.clipToBounds true
        Canvas.children [
          Border.create [
            Canvas.left minimapLeft
            Canvas.top minimapTop
            Border.width minimapViewportWidth
            Border.height minimapViewportHeight
            Border.background Brushes.Transparent
            Border.borderBrush model.Theme.Graph.ViewportRect
            Border.borderThickness 3.0
            Border.cursor (new Cursor(StandardCursorType.SizeAll))
            Control.onPointerPressed (onRectPressed dispatch)
            Control.onPointerMoved (onRectMoved dispatch scale)
            Control.onPointerReleased (onRectReleased dispatch)
          ]
        ]
      ]
    )
  ]

let private minimapOverlayView model dispatch minimapDim cfg viewState =
  if viewState.ShowMinimap then
    [ Border.create [
        Border.horizontalAlignment HorizontalAlignment.Right
        Border.verticalAlignment VerticalAlignment.Bottom
        Border.margin 12.0
        Border.child (minimapView model dispatch minimapDim cfg viewState)
      ] :> IView
      minimapViewport model dispatch minimapDim viewState ]
  else
    []

let private loadedView model dispatch cfg viewState =
  let cfgWidth = viewState.GraphWidth
  let cfgHeight = viewState.GraphHeight
  let minimapDim = computeMinimapDimension model cfgWidth cfgHeight
  Border.create [
    Border.background model.Theme.Window.Background
    Border.clipToBounds true
    Border.child (
      Grid.create [
        Grid.children [
          graphCanvasView model dispatch cfg viewState
          yield! minimapOverlayView model dispatch minimapDim cfg viewState
        ]
      ]
    )
  ]

let view (model: Model) dispatch =
  Border.create [
    Border.background model.Theme.Window.Background
    Border.borderThickness 0.0
    Border.child (
      match model.ActiveTab with
      | Some { Content = CFGContent(_, NotLoaded) } ->
        unloadedView model "CFG is not loaded."
      | Some { Content = CFGContent(_, Loading) } ->
        unloadedView model "CFG is now loading ..."
      | Some { Content = CFGContent(_, Loaded(cfg, viewState)) } ->
        loadedView model dispatch cfg viewState
      | _ ->
        unloadedView model "Select a function to view its CFG."
    )
  ]
