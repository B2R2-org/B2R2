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
module B2R2.RearEnd.BinExplore.GUI.CFGTab

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

type Dimension =
  { Width: float
    Height: float
    Scale: float }

let private stateTextView model text =
  Border.create
    [ Border.background model.Theme.Window.Background
      Border.child (
        TextBlock.create [
          TextBlock.text text
          TextBlock.foreground model.Theme.Text.Primary
          TextBlock.fontSize 14.0
          TextBlock.margin 12.0
        ]) ] :> IView

let private arrowheadPoints (tip: Point) (angleDeg: float) (size: float) =
  let rad = angleDeg * Math.PI / 180.0
  let bx = tip.X - size * cos rad
  let by = tip.Y - size * sin rad
  let lx, ly = bx + (size / 2.0) * sin rad, by - (size / 2.0) * cos rad
  let rx, ry = bx - (size / 2.0) * sin rad, by + (size / 2.0) * cos rad
  [| tip; Point(lx, ly); Point(rx, ry) |]

let private edgeView (pts: VisPosition list) zoom panX panY (color: string) =
  match pts with
  | _ :: _ :: _ ->
    let scaled =
      pts |> List.map (fun p -> Point(p.X * zoom + panX, p.Y * zoom + panY))
    let tip = List.last scaled
    let prev = scaled |> List.item (scaled.Length - 2)
    let angle = Math.Atan2(tip.Y - prev.Y, tip.X - prev.X) * 180.0 / Math.PI
    [ Polyline.create
        [ Polyline.points (scaled |> Array.ofList)
          Polyline.stroke color
          Polyline.strokeThickness (1.0 * zoom)
          Polyline.isHitTestVisible false ] :> IView
      Polygon.create
        [ Polygon.points (arrowheadPoints tip angle (8.0 * zoom))
          Polygon.fill color
          Polygon.isHitTestVisible false ] :> IView ]
  | _ -> []

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

let private graphCanvas model (cfg: VisGraph) viewState =
  let zoom = viewState.Zoom
  let panX, panY = viewState.PanX, viewState.PanY
  let fontSize = model.Theme.Font.Disassembly.FontSize
  Canvas.create [
    Canvas.background model.Theme.Window.Background
    Canvas.children (
      [ for e in cfg.Edges do
          let color = getEdgeColor model e.Label.Type
          yield! edgeView e.Label.Points zoom panX panY color
        for n in cfg.Vertices do
          let x, y = n.VData.Coordinate.X, n.VData.Coordinate.Y
          let w = ceil (n.VData.Width * zoom) + 1.1 (* to avoid clipping *)
          let h = ceil (n.VData.Height * zoom) + 1.1
          let lines = (n.VData :> IVisualizable).Visualize()
          Border.create
            [ Canvas.left (x * zoom + panX)
              Canvas.top (y * zoom + panY)
              Border.clipToBounds false
              Border.width w
              Border.height h
              Border.background model.Theme.Panel.AltBackground
              Border.borderBrush model.Theme.Panel.Border
              Border.borderThickness (1.0 * zoom)
              Border.cornerRadius 4.0
              Border.child (
                TextBlock.create
                  [ TextBlock.inlines (
                      [ for words in lines do
                          for word in words do
                            Run.create
                              [ match word.AsmWordKind with
                                | AsmWordKind.Address ->
                                  Run.text word.AsmWordValue
                                  Run.foreground model.Theme.Text.Address
                                | AsmWordKind.Mnemonic ->
                                  Run.text word.AsmWordValue
                                  Run.foreground model.Theme.Text.Mnemonic
                                | AsmWordKind.Variable ->
                                  Run.text word.AsmWordValue
                                  Run.foreground model.Theme.Text.Variable
                                | AsmWordKind.Value ->
                                  Run.text word.AsmWordValue
                                  Run.foreground model.Theme.Text.Value
                                | _ ->
                                  Run.text word.AsmWordValue ] :> IView
                          LineBreak.create [] :> IView ]
                    )
                    TextBlock.foreground model.Theme.Text.Primary
                    TextBlock.fontSize (fontSize * zoom)
                    TextBlock.margin (4.0 * zoom)
                    TextBlock.padding 0.0
                    TextBlock.fontFamily model.Theme.Font.Disassembly.FontFamily
                    TextBlock.textWrapping TextWrapping.NoWrap ]
              ) ]
            |> View.withKey $"node-{x}.{y}-{zoom}-{panX}-{panY}" :> IView ]
    )
  ]

let private pointerXY (e: PointerEventArgs) =
  match e.Source with
  | :? Control as ctrl ->
    let root = TopLevel.GetTopLevel ctrl
    let p =
      if isNull root then e.GetPosition ctrl
      else e.GetPosition root
    struct (p.X, p.Y)
  | _ -> struct (0.0, 0.0)

let private minimapPanFactor viewState minimapScale =
  if minimapScale <= 0.0 then 0.0
  else viewState.Zoom / -minimapScale

let private onMinimapClicked dispatch model minimapDim viewState e =
  match (e: PointerPressedEventArgs).Source with
  | :? Control as ctrl ->
    let p = e.GetPosition ctrl
    let scale = minimapDim.Scale
    let offsetX = minimapDim.Width / 2.0
    let gx = (p.X - offsetX) / scale
    let gy = p.Y / scale
    let viewportWidth, viewportHeight = model.CFGViewportSize
    let newPanX = viewportWidth / 2.0 - gx * viewState.Zoom
    let newPanY = viewportHeight / 2.0 - gy * viewState.Zoom
    dispatch (JumpCFGPan(newPanX, newPanY))
    let struct (sx, sy) = pointerXY e
    let factor = minimapPanFactor viewState scale
    dispatch (StartCFGPan(sx * factor, sy * factor))
    e.Pointer.Capture ctrl
    e.Handled <- true
  | _ -> ()

let private onRectMoved dispatch viewState minimapScale e =
  let struct (x, y) = pointerXY e
  let factor = minimapPanFactor viewState minimapScale
  dispatch (MoveCFGPan(x * factor, y * factor))
  e.Handled <- true

let private onRectReleased dispatch (e: PointerReleasedEventArgs) =
  dispatch EndCFGPan
  match e.Source with
  | :? Control -> e.Pointer.Capture null
  | _ -> ()
  e.Handled <- true

let private minimapEdgeView model scale offsetX (positions: VisPosition list) =
  match positions with
  | _ :: _ :: _ ->
    let pts =
      positions
      |> List.map (fun p ->
        Point(p.X * scale + offsetX, p.Y * scale))
    [ Polyline.create
        [ Polyline.points (pts |> Array.ofList)
          Polyline.stroke model.Theme.Text.Secondary
          Polyline.strokeThickness 0.5
          Polyline.isHitTestVisible false ] :> IView ]
  | _ -> []

let private minimapView model dispatch minimapDim (graph: VisGraph) viewState =
  let scale = minimapDim.Scale
  let offsetX = minimapDim.Width / 2.0
  Border.create
    [ Border.width minimapDim.Width
      Border.height minimapDim.Height
      Border.background "#44000000"
      Border.borderBrush model.Theme.Panel.Border
      Border.borderThickness 1.0
      Border.cornerRadius 4.0
      Border.cursor (new Cursor(StandardCursorType.SizeAll))
      Border.child (
        Canvas.create
          [ Canvas.width minimapDim.Width
            Canvas.height minimapDim.Height
            Canvas.background model.Theme.Panel.AltBackground
            Canvas.opacity 0.9
            Control.onPointerPressed (
              onMinimapClicked dispatch model minimapDim viewState
            )
            Control.onPointerMoved (
              onRectMoved dispatch viewState minimapDim.Scale
            )
            Control.onPointerReleased (onRectReleased dispatch)
            Canvas.children (
              [ for e in graph.Edges do
                  yield! minimapEdgeView model scale offsetX e.Label.Points
                for n in graph.Vertices do
                  Border.create
                    [ Canvas.left (n.VData.Coordinate.X * scale + offsetX)
                      Canvas.top (n.VData.Coordinate.Y * scale)
                      Border.width (n.VData.Width * scale)
                      Border.height (n.VData.Height * scale)
                      Border.background model.Theme.Text.Secondary
                      Border.isHitTestVisible false ] ]
            ) ]) ]

let [<Literal>] private ZoomDelta = 0.05

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
  dispatch (MoveCFGPan(x, y))
  e.Handled <- true

let private onReleased dispatch (e: PointerReleasedEventArgs) =
  dispatch EndCFGPan
  match e.Source with
  | :? Control -> e.Pointer.Capture null
  | _ -> ()
  e.Handled <- true

let private onRectPressed dispatch viewState minimapScale e =
  let struct (x, y) = pointerXY e
  let factor = minimapPanFactor viewState minimapScale
  dispatch (StartCFGPan(x * factor, y * factor))
  match e.Source with
  | :? Control as ctrl -> e.Pointer.Capture ctrl
  | _ -> ()
  e.Handled <- true

let [<Literal>] private MinimapDefaultWidth = 220.0

let private computeMinimapDimension model graphWidth graphHeight =
  let viewportWidth, viewportHeight = model.CFGViewportSize
  let referenceWidth = max graphWidth viewportWidth
  let referenceHeight = max graphHeight viewportHeight
  let aspectRatio = referenceWidth / referenceHeight
  let ratio = MinimapDefaultWidth / referenceWidth
  let maxLen =
    if ratio < 0.01 then viewportWidth / 3.0
    else MinimapDefaultWidth
  if aspectRatio >= 1.0 then
    { Width = maxLen
      Height = maxLen / aspectRatio
      Scale = maxLen / referenceWidth }
  else
    { Width = maxLen * aspectRatio
      Height = maxLen
      Scale = maxLen / referenceHeight }

let private minimapViewport model dispatch minimapDim viewState =
  let scale = minimapDim.Scale
  let offsetX = minimapDim.Width / 2.0
  let viewportWidth, viewportHeight = model.CFGViewportSize
  let zoom, panX, panY = viewState.Zoom, viewState.PanX, viewState.PanY
  let graphLeft = -panX / zoom
  let graphTop = -panY / zoom
  let graphRight = (viewportWidth - panX) / zoom
  let graphBottom = (viewportHeight - panY) / zoom
  let minimapLeft = graphLeft * scale + offsetX
  let minimapTop = graphTop * scale
  let minimapRight = graphRight * scale + offsetX
  let minimapBottom = graphBottom * scale
  let minimapViewportWidth = minimapRight - minimapLeft
  let minimapViewportHeight = minimapBottom - minimapTop
  Border.create
    [ Border.horizontalAlignment HorizontalAlignment.Right
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
              Border.borderBrush Brushes.White
              Border.borderThickness 3.0
              Border.cursor (new Cursor(StandardCursorType.SizeAll))
              Control.onPointerPressed (onRectPressed dispatch viewState scale)
              Control.onPointerMoved (onRectMoved dispatch viewState scale)
              Control.onPointerReleased (onRectReleased dispatch)
            ]
          ]
        ]) ] :> IView

let private loadedView model dispatch cfg viewState =
  let cfgWidth = viewState.GraphWidth
  let cfgHeight = viewState.GraphHeight
  let minimapDim = computeMinimapDimension model cfgWidth cfgHeight
  Grid.create
    [ Grid.children
        [ Border.create
            [ Border.background model.Theme.Window.Background
              Border.clipToBounds true
              Border.child (
                Grid.create [
                  Grid.children [
                    graphCanvas model cfg viewState
                    Border.create [
                      Border.background model.Theme.Common.Transparent
                      Border.cursor Cursor.Default
                      Border.horizontalAlignment HorizontalAlignment.Stretch
                      Border.verticalAlignment VerticalAlignment.Stretch
                      Control.onPointerWheelChanged (onWheel dispatch)
                      Control.onPointerPressed (onPressed dispatch)
                      Control.onPointerMoved (onMoved dispatch)
                      Control.onPointerReleased (onReleased dispatch)
                    ]
                    Border.create [
                      Border.horizontalAlignment HorizontalAlignment.Right
                      Border.verticalAlignment VerticalAlignment.Bottom
                      Border.margin 12.0
                      Border.child (
                        minimapView model dispatch minimapDim cfg viewState
                      )
                    ]
                    minimapViewport model dispatch minimapDim viewState
                  ]
                ]) ] ] ]

let view (model: Model) dispatch =
  Border.create [
    Border.background model.Theme.Window.Background
    Border.borderThickness 0.0
    Border.child (
      match model.ActiveTab with
      | Some { Content = CFGTab(_, NotLoaded) } ->
        stateTextView model "CFG is not loaded."
      | Some { Content = CFGTab(_, Loading) } ->
        stateTextView model "CFG is now loading ..."
      | Some { Content = CFGTab(_, Loaded(cfg, viewState)) } ->
        loadedView model dispatch cfg viewState
      | _ ->
        stateTextView model "Select a function to view its control flow graph"
    )
  ]
