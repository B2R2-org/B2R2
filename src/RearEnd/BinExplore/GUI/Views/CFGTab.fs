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

open Avalonia.Controls
open Avalonia.Layout
open Avalonia.Media
open Avalonia.Input
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types
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

let private graphCanvas model (cfg: VisGraph) viewState =
  let zoom = viewState.Zoom
  let panX, panY = viewState.PanX, viewState.PanY
  Canvas.create [
    Canvas.background model.Theme.Window.Background
    Canvas.children (
      cfg.Vertices
      |> Array.toList
      |> List.map (fun n ->
        let x, y = n.VData.Coordinate.X, n.VData.Coordinate.Y
        Border.create
          [ Canvas.left (x * zoom + panX)
            Canvas.top (y * zoom + panY)
            Border.width (n.VData.Width * zoom)
            Border.height (n.VData.Height * zoom)
            Border.background model.Theme.Panel.AltBackground
            Border.borderBrush model.Theme.Panel.Border
            Border.borderThickness 1.0
            Border.cornerRadius 4.0
            Border.child (
              TextBlock.create
                [ TextBlock.text $"{(n.VData :> IVisualizable).BlockAddress:x}"
                  TextBlock.foreground model.Theme.Text.Primary
                  TextBlock.fontSize (12.0 * zoom |> max 10.0 |> min 20.0)
                  TextBlock.margin 6.0
                  TextBlock.textTrimming TextTrimming.CharacterEllipsis
                  TextBlock.textWrapping TextWrapping.NoWrap ]
            ) ] |> View.withKey $"node-{x}.{y}-{zoom}-{panX}-{panY}" :> IView)
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

let [<Literal>] private ZoomDelta = 0.02

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

let [<Literal>] private MinimapDefaultWidth = 220.0

let private computeMinimapDimension model graphWidth graphHeight =
  let viewportWidth, viewportHeight = model.CFGViewportSize
  let referenceWidth = max graphWidth viewportWidth
  let referenceHeight = max graphHeight viewportHeight
  let aspectRatio = referenceWidth / referenceHeight
  let ratio = MinimapDefaultWidth / referenceWidth
  let maxLen =
    if ratio < 0.01 then viewportWidth / 2.0
    else MinimapDefaultWidth
  if aspectRatio >= 1.0 then
    { Width = maxLen
      Height = maxLen / aspectRatio
      Scale = maxLen / referenceWidth }
  else
    { Width = maxLen * aspectRatio
      Height = maxLen
      Scale = maxLen / referenceHeight }

let private minimapView model minimapDim (graph: VisGraph) =
  let scale = minimapDim.Scale
  let offsetX = minimapDim.Width / 2.0
  Border.create
    [ Border.width minimapDim.Width
      Border.height minimapDim.Height
      Border.background "#44000000"
      Border.borderBrush model.Theme.Panel.Border
      Border.borderThickness 1.0
      Border.cornerRadius 4.0
      Border.child (
        Canvas.create
          [ Canvas.width minimapDim.Width
            Canvas.height minimapDim.Height
            Canvas.children (
              (graph.Vertices
              |> Array.toList
              |> List.map (fun n ->
                Border.create
                  [ Canvas.left (n.VData.Coordinate.X * scale + offsetX)
                    Canvas.top (n.VData.Coordinate.Y * scale)
                    Border.width (n.VData.Width * scale)
                    Border.height (n.VData.Height * scale)
                    Border.background model.Theme.Text.Secondary
                    Border.opacity 0.45 ]))
              ) ]) ]

let private minimapViewport model minimapDim viewState =
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
                      Border.child (minimapView model minimapDim cfg)
                    ]
                    minimapViewport model minimapDim viewState
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
