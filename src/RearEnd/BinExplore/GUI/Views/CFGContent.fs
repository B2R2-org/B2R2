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
open System.Collections.Generic
open Avalonia
open Avalonia.Controls
open Avalonia.Controls.Shapes
open Avalonia.FuncUI.Builder
open Avalonia.Layout
open Avalonia.Media
open Avalonia.Input
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.RearEnd.Visualization

let mutable private graphCanvas: Canvas option = None

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

let private brushOfColor =
  let cache = Dictionary<string, IBrush>()
  fun color ->
    match cache.TryGetValue color with
    | true, brush -> brush
    | _ ->
      let brush = Brush.Parse color
      cache[color] <- brush
      brush

type private MinimapStaticLayer() =
  inherit Control()

  static let cacheProperty =
    AvaloniaProperty.Register<MinimapStaticLayer, MinimapStaticCache>(
      nameof Unchecked.defaultof<MinimapStaticLayer>.CurrentCache,
      Unchecked.defaultof<MinimapStaticCache>
    )

  static let themeProperty =
    AvaloniaProperty.Register<MinimapStaticLayer, Theme>(
      nameof Unchecked.defaultof<MinimapStaticLayer>.CurrentTheme,
      Unchecked.defaultof<Theme>
    )

  static member CacheProperty = cacheProperty

  static member ThemeProperty = themeProperty

  member this.CurrentCache
    with get() = this.GetValue cacheProperty
    and set value = this.SetValue(cacheProperty, value) |> ignore

  member this.CurrentTheme
    with get() = this.GetValue themeProperty
    and set value = this.SetValue(themeProperty, value) |> ignore

  static member Cache value =
    AttrBuilder<'t>.CreateProperty<MinimapStaticCache>(
      MinimapStaticLayer.CacheProperty, value, ValueNone
    )

  static member Theme value =
    AttrBuilder<'t>.CreateProperty<Theme>(
      MinimapStaticLayer.ThemeProperty, value, ValueNone
    )

  override this.OnPropertyChanged change =
    base.OnPropertyChanged change
    if change.Property = cacheProperty || change.Property = themeProperty then
      this.InvalidateVisual()
    else
      ()

  override this.Render(ctx: DrawingContext) =
    base.Render ctx
    let cache = this.CurrentCache
    let theme = this.CurrentTheme
    if isNull (box cache) || isNull (box theme) then
      ()
    else
      let edgePen = Pen(brushOfColor theme.Graph.MinimapEdge, 0.5)
      let nodeBrush = brushOfColor theme.Graph.MinimapNode
      for pts in cache.EdgePolylines do
        for i in 0 .. pts.Length - 2 do
          ctx.DrawLine(edgePen, pts[i], pts[i + 1])
      for rect in cache.NodeRects do
        ctx.FillRectangle(nodeBrush, rect)

[<RequireQualifiedAccess>]
module private MinimapStaticLayer =
  let create (attrs: IAttr<MinimapStaticLayer> list) =
    View.createGeneric<MinimapStaticLayer> attrs

let private getEdgeColor model = function
  | InterJmpEdge -> model.Theme.Graph.InterJmpEdge
  | InterCJmpTrueEdge -> model.Theme.Graph.InterCJmpTrueEdge
  | InterCJmpFalseEdge -> model.Theme.Graph.InterCJmpFalseEdge
  | IntraJmpEdge -> model.Theme.Graph.IntraJmpEdge
  | IntraCJmpTrueEdge -> model.Theme.Graph.IntraCJmpTrueEdge
  | IntraCJmpFalseEdge -> model.Theme.Graph.IntraCJmpFalseEdge
  | FallThroughEdge -> model.Theme.Graph.FallthroughEdge
  | CallEdge -> model.Theme.Graph.CallEdge
  | RetEdge -> model.Theme.Graph.ReturnEdge
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

let private distSquared x1 y1 x2 y2 =
  let dx = x1 - x2
  let dy = y1 - y2
  dx * dx + dy * dy

let private pointerXYOnGraphCanvas (e: PointerEventArgs) =
  match graphCanvas with
  | Some canvas ->
    let p = e.GetPosition canvas
    struct (p.X, p.Y)
  | None ->
    struct (0.0, 0.0)

let private onEdgePressed dispatch zoom panX panY p1 p2 e =
  if (e: PointerPressedEventArgs).ClickCount = 2 then
    let struct (x, y) = pointerXYOnGraphCanvas e
    let gx = (x - panX) / zoom
    let gy = (y - panY) / zoom
    let distToP1 = distSquared gx gy p1.X p1.Y
    let distToP2 = distSquared gx gy p2.X p2.Y
    let target = if distToP1 <= distToP2 then p2 else p1
    dispatch (CFGMsg(JumpPan(target.X, target.Y)))
    e.Handled <- true
  else
    ()

let private edgeHitAreaView dispatch (pts: Point[]) zoom panX panY p1 p2 eid =
  let eid = Some eid
  Polyline.create [
    Polyline.points pts
    Polyline.stroke "#01FFFFFF"
    Polyline.strokeThickness (edgeHitAreaThickness zoom)
    Control.onPointerEntered (fun _ -> dispatch (CFGMsg(SetHoveredEdge eid)))
    Control.onPointerExited (fun _ -> dispatch (CFGMsg(SetHoveredEdge None)))
    Control.onPointerPressed (onEdgePressed dispatch zoom panX panY p1 p2)
  ] :> IView

let private arrowheadView (tip: Point) (angle: float) zoom (color: string) =
  Polygon.create [
    Polygon.points (arrowheadPoints tip angle (8.0 * zoom))
    Polygon.fill color
    Polygon.isHitTestVisible false
  ] :> IView

let private edgeView model dispatch pts zoom panX panY color edgeID =
  if Array.length pts >= 2 then
    let p1 = Array.head pts
    let p2 = Array.last pts
    let scaled =
      pts
      |> Array.map (fun p -> Point(p.X * zoom + panX, p.Y * zoom + panY))
    let tip = scaled[scaled.Length - 1]
    let prev = scaled[scaled.Length - 2]
    let angle = Math.Atan2(tip.Y - prev.Y, tip.X - prev.X) * 180.0 / Math.PI
    Canvas.create [
      Canvas.children [
        if model.CFGIsPanning then ()
        else edgeHitAreaView dispatch scaled zoom panX panY p1 p2 edgeID
        edgeLineView scaled zoom color
        arrowheadView tip angle zoom color
      ]
    ]
    |> View.withKey $"edge-{edgeID}" :> IView
    |> List.singleton
  else
    []

let private graphEdges model dispatch hovered cfg zoom panX panY isEdgeVisible =
  [ for edgeID, e in Array.indexed (cfg: VisGraph).Edges do
      let pts = e.Label.Points
      if isEdgeVisible edgeID then
        let color =
          if hovered = Some edgeID then model.Theme.Graph.HoveredEdge
          else getEdgeColor model e.Label.Type
        yield! edgeView model dispatch pts zoom panX panY color edgeID
      else
        () ]

let private tokenForeground model word =
  match word.AsmWordKind with
  | AsmWordKind.Address -> model.Theme.Text.Address
  | AsmWordKind.Mnemonic -> model.Theme.Text.Mnemonic
  | AsmWordKind.Variable -> model.Theme.Text.Variable
  | AsmWordKind.Value -> model.Theme.Text.Value
  | _ -> model.Theme.Text.Primary

let inline private isSelectableToken word =
  word.AsmWordKind <> AsmWordKind.String

let private tokenTextView model word =
  TextBlock.create [
    TextBlock.text word.AsmWordValue
    TextBlock.foreground (tokenForeground model word)
    TextBlock.fontSize model.Theme.Font.Monospace.FontSize
    TextBlock.padding 0.0
    TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
    TextBlock.textWrapping TextWrapping.NoWrap
  ]

let private tokenView model dispatch selected nID lineIdx wordIdx word range =
  if not (isSelectableToken word) then
    tokenTextView model word :> IView
  else
    let isSelected =
      match selected with
      | Some sel ->
        sel.NodeID = nID &&
        sel.LineIndex = lineIdx &&
        sel.WordIndex = wordIdx
      | None ->
        false
    Border.create [
      Border.background (
        if isSelected then model.Theme.Search.SelectedBackground
        else model.Theme.Common.Transparent
      )
      Border.cornerRadius 2.0
      Control.onTapped (fun e ->
        dispatch (CFGMsg(SelectToken(nID, lineIdx, wordIdx, range)))
        e.Handled <- true
      )
      Border.child (tokenTextView model word)
    ] |> View.withKey $"token-{nID}-{lineIdx}-{wordIdx}" :> IView

let private disasmLineView model dispatch selected nodeID lineIdx words range =
  StackPanel.create [
    StackPanel.orientation Orientation.Horizontal
    StackPanel.children [
      for wordIdx, word in Array.indexed words do
        tokenView model dispatch selected nodeID lineIdx wordIdx word range
    ]
  ] |> View.withKey $"line-{nodeID}-{lineIdx}" :> IView

let private disasmView model dispatch selected nodeID zoom n =
  let lines =
    if model.Theme.Font.Monospace.FontSize * zoom < 6.0 then [||]
    else ((n: IVertex<_>).VData :> IVisualizable).Visualize()
  let range = (n.VData :> IAddressable).Range
  StackPanel.create [
    StackPanel.orientation Orientation.Vertical
    StackPanel.horizontalAlignment HorizontalAlignment.Left
    StackPanel.verticalAlignment VerticalAlignment.Top
    StackPanel.children [
      for lineIdx, words in Array.indexed lines do
        disasmLineView model dispatch selected nodeID lineIdx words range
    ]
  ]

let private nodeView model dispatch selected nID zoom panX panY x y w h n =
  Border.create [
    Canvas.left (x * zoom + panX)
    Canvas.top (y * zoom + panY)
    Border.clipToBounds false
    Border.width w
    Border.height h
    Border.background model.Theme.Panel.AltBackground
    Border.borderBrush model.Theme.Panel.Border
    Border.borderThickness (1.0 * zoom)
    Border.cornerRadius 4.0
    Border.child (
      Border.create [
        Border.margin (4.0 * zoom)
        Border.background model.Theme.Common.Transparent
        Border.child (
          Viewbox.create [
            Viewbox.stretch Stretch.Uniform
            Viewbox.horizontalAlignment HorizontalAlignment.Left
            Viewbox.verticalAlignment VerticalAlignment.Top
            Viewbox.child (disasmView model dispatch selected nID zoom n)
          ]
        )
      ]
    )
  ] |> View.withKey $"node-{nID}" :> IView

let private graphNodes model dispatch selected cfg zoom panX panY isVisible =
  [ for nodeID, n in Array.indexed (cfg: VisGraph).Vertices do
      let x, y = n.VData.Coordinate.X, n.VData.Coordinate.Y
      let w, h = n.VData.Width, n.VData.Height
      if not (isVisible x y w h) then
        ()
      else
        let w = ceil (w * zoom) + 1.1 (* margin to avoid clipping *)
        let h = ceil (h * zoom) + 1.1
        nodeView model dispatch selected nodeID zoom panX panY x y w h n ]

let [<Literal>] private ZoomDelta = 0.05
let [<Literal>] private CFGPanStartThresholdSquared = 16.0

let private pointerXY (e: PointerEventArgs) =
  match graphCanvas with
  | Some canvas ->
    let p = e.GetPosition canvas
    struct (p.X, p.Y)
  | None ->
    match e.Source with
    | :? Control as ctrl ->
      let root = TopLevel.GetTopLevel ctrl
      let p =
        if isNull root then e.GetPosition ctrl
        else e.GetPosition root
      struct (p.X, p.Y)
    | _ -> struct (0.0, 0.0)

let private setPointerCapture shouldCapture (e: PointerEventArgs) =
  match graphCanvas with
  | Some canvas ->
    e.Pointer.Capture(if shouldCapture then canvas else null)
  | None ->
    match e.Source with
    | :? Control as ctrl ->
      e.Pointer.Capture(if shouldCapture then ctrl else null)
    | _ -> ()

let private capturePointer e =
  setPointerCapture true e

let private releasePointer e =
  setPointerCapture false e

let private onWheel dispatch (e: PointerWheelEventArgs) =
  let delta = if e.Delta.Y > 0.0 then ZoomDelta else -ZoomDelta
  let struct (x, y) = pointerXY e
  dispatch (CFGMsg(SetZoom(delta, x, y)))
  e.Handled <- true

let private onPressed dispatch (e: PointerPressedEventArgs) =
  let struct (x, y) = pointerXY e
  dispatch (CFGMsg(StartPan(x, y)))

let private onMoved model dispatch (e: PointerEventArgs) =
  let struct (x, y) = pointerXY e
  let shouldStartPan =
    match model.CFGPressedPointer with
    | Some(pressedX, pressedY) when not model.CFGIsPanning ->
      let dx = x - pressedX
      let dy = y - pressedY
      dx * dx + dy * dy >= CFGPanStartThresholdSquared
    | _ -> false
  if shouldStartPan then capturePointer e else ()
  dispatch (CFGMsg(MovePan(x, y, ViewportSpace)))
  if shouldStartPan || model.CFGIsPanning then e.Handled <- true else ()

let private onReleased model dispatch (e: PointerReleasedEventArgs) =
  dispatch (CFGMsg EndPan)
  if model.CFGIsPanning then releasePointer e else ()
  if model.CFGIsPanning || model.CFGPressedPointer.IsSome then e.Handled <- true
  else ()

let private graphCanvasView model dispatch cfg renderCache viewState =
  let zoom = viewState.Zoom
  let panX, panY = viewState.PanX, viewState.PanY
  let hovered = viewState.HoveredEdge
  let selected = viewState.SelectedToken
  let viewportWidth, viewportHeight = model.ContentViewportSize
  let vpLeft, vpRight = -panX / zoom, (viewportWidth - panX) / zoom
  let vpTop, vpBottom = -panY / zoom, (viewportHeight - panY) / zoom
  let isEdgeVisible eID =
    CFGRenderCache.isEdgeVisible renderCache eID vpLeft vpRight vpTop vpBottom
  let isNodeVisible x y w h =
    x < vpRight && x + w > vpLeft && y < vpBottom && y + h > vpTop
  Canvas.create [
    Canvas.background model.Theme.Window.Background
    Control.onPointerWheelChanged (onWheel dispatch)
    Control.onPointerPressed (onPressed dispatch)
    Control.onPointerMoved (onMoved model dispatch)
    Control.onPointerReleased (onReleased model dispatch)
    Canvas.children [
      yield! graphEdges model dispatch hovered cfg zoom panX panY isEdgeVisible
      yield! graphNodes model dispatch selected cfg zoom panX panY isNodeVisible
    ]
  ] |> View.withOutlet (fun (canvas: Canvas) -> graphCanvas <- Some canvas)

let private onMinimapClick dispatch (minimap: MinimapStaticCache) viewState e =
  match (e: PointerPressedEventArgs).Source with
  | :? Control as ctrl ->
    let p = e.GetPosition ctrl
    let scale = minimap.Scale
    let gx = (p.X - minimap.OffsetX) / scale + viewState.GraphMinX
    let gy = (p.Y - minimap.OffsetY) / scale + viewState.GraphMinY
    dispatch (CFGMsg(JumpPan(gx, gy)))
    let struct (sx, sy) = pointerXY e
    dispatch (CFGMsg(StartPan(sx, sy)))
    e.Pointer.Capture ctrl
    e.Handled <- true
  | _ -> ()

let private onRectMoved dispatch minimapScale e =
  let struct (x, y) = pointerXY e
  dispatch (CFGMsg(MovePan(x, y, MinimapSpace minimapScale)))
  e.Handled <- true

let private onRectReleased dispatch (e: PointerReleasedEventArgs) =
  dispatch (CFGMsg EndPan)
  match e.Source with
  | :? Control -> e.Pointer.Capture null
  | _ -> ()
  e.Handled <- true

let private minimapView model dispatch (minimap: MinimapStaticCache) viewState =
  Border.create [
    Border.width minimap.Width
    Border.height minimap.Height
    Border.background "#44000000"
    Border.borderBrush model.Theme.Panel.Border
    Border.borderThickness 1.0
    Border.cornerRadius 4.0
    Border.cursor (new Cursor(StandardCursorType.SizeAll))
    Border.child (
      Canvas.create [
        Canvas.width minimap.Width
        Canvas.height minimap.Height
        Canvas.background model.Theme.Panel.AltBackground
        Canvas.opacity 0.9
        Control.onPointerPressed (onMinimapClick dispatch minimap viewState)
        Control.onPointerMoved (onRectMoved dispatch minimap.Scale)
        Control.onPointerReleased (onRectReleased dispatch)
        Canvas.children [
          MinimapStaticLayer.create [
            Control.width minimap.Width
            Control.height minimap.Height
            Control.isHitTestVisible false
            MinimapStaticLayer.Cache minimap
            MinimapStaticLayer.Theme model.Theme
          ]
        ]
      ]
    )
  ]

let private onRectPressed dispatch e =
  let struct (x, y) = pointerXY e
  dispatch (CFGMsg(StartPan(x, y)))
  match e.Source with
  | :? Control as ctrl -> e.Pointer.Capture ctrl
  | _ -> ()
  e.Handled <- true

let private minimapViewport model dispatch minimap viewState =
  let scale = minimap.Scale
  let viewportWidth, viewportHeight = model.ContentViewportSize
  let zoom, panX, panY = viewState.Zoom, viewState.PanX, viewState.PanY
  let minX, minY = viewState.GraphMinX, viewState.GraphMinY
  let offX, offY = minimap.OffsetX, minimap.OffsetY
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
        Canvas.width minimap.Width
        Canvas.height minimap.Height
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

let private minimapOverlayView model dispatch minimap viewState =
  if viewState.ShowMinimap then
    [ Border.create [
        Border.horizontalAlignment HorizontalAlignment.Right
        Border.verticalAlignment VerticalAlignment.Bottom
        Border.margin 12.0
        Border.child (minimapView model dispatch minimap viewState)
      ] :> IView
      minimapViewport model dispatch minimap viewState ]
  else
    []

let private loadedView model dispatch (loaded: LoadedCFGState) =
  let cfg = loaded.Graph
  let viewState = loaded.ViewState
  let minimap = loaded.Minimap
  Border.create [
    Border.background model.Theme.Window.Background
    Border.clipToBounds true
    Border.child (
      Grid.create [
        Grid.children [
          graphCanvasView model dispatch cfg loaded.RenderCache viewState
          yield! minimapOverlayView model dispatch minimap viewState
        ]
      ]
    )
  ]

let view (model: Model) dispatch =
  let viewKey =
    match model.ActiveTab with
    | Some tab -> $"cfg-{tab.ID}"
    | None -> "cfg-none"
  Border.create [
    Border.background model.Theme.Window.Background
    Border.borderThickness 0.0
    Border.child (
      match model.ActiveTab with
      | Some { Content = CFGContent(_, NotLoaded) } ->
        unloadedView model "CFG is not loaded."
      | Some { Content = CFGContent(_, Loading) } ->
        unloadedView model "CFG is now loading ..."
      | Some { Content = CFGContent(_, Loaded loaded) } ->
        loadedView model dispatch loaded
      | _ ->
        unloadedView model "Select a function to view its CFG."
    )
  ] |> View.withKey viewKey
