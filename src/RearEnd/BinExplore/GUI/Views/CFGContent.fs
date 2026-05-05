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
open System.Globalization
open System.Collections.Generic
open Avalonia
open Avalonia.Controls
open Avalonia.Controls.Shapes
open Avalonia.Controls.Primitives
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

type private GraphCanvas() =
  inherit Canvas()

[<RequireQualifiedAccess>]
module private GraphCanvas =
  let create (attrs: IAttr<GraphCanvas> list) =
    View.createGeneric<GraphCanvas> attrs

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

let rec private tryFindGraphCanvas (source: obj) =
  match source with
  | :? GraphCanvas as canvas ->
    Some canvas
  | :? StyledElement as element when not (isNull element.Parent) ->
    tryFindGraphCanvas (element.Parent :> obj)
  | _ ->
    None

let private pointerXYOnGraphCanvas (e: PointerEventArgs) =
  match tryFindGraphCanvas e.Source with
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
    dispatch (CFGPaneMsg(JumpPan(target.X, target.Y)))
    e.Handled <- true
  else
    ()

let private edgeHitAreaView dispatch (pts: Point[]) zoom panX panY p1 p2 eid =
  let eid = Some eid
  Polyline.create [
    Polyline.points pts
    Polyline.stroke "#01FFFFFF"
    Polyline.strokeThickness (edgeHitAreaThickness zoom)
    Control.onPointerEntered (fun _ ->
      dispatch (CFGPaneMsg(SetHoveredEdge eid)))
    Control.onPointerExited (fun _ ->
      dispatch (CFGPaneMsg(SetHoveredEdge None)))
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

let private tokenTextView model word =
  TextBlock.create [
    TextBlock.text word.AsmWordValue
    TextBlock.foreground (tokenForeground model word)
    TextBlock.fontSize model.Theme.Font.Monospace.FontSize
    TextBlock.padding 0.0
    TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
    TextBlock.textWrapping TextWrapping.NoWrap
  ]

let private tokenTextViewUnselectable model txt =
  TextBlock.create [
    TextBlock.text txt
    TextBlock.foreground model.Theme.Text.Secondary
    TextBlock.fontSize 12.0
  ]

let private makeDisasmLine words =
  words
  |> Array.filter (fun word ->
    word.AsmWordKind <> AsmWordKind.Address &&
    word.AsmWordKind <> AsmWordKind.InstructionDelimiter)
  |> Array.map (fun word -> word.AsmWordValue)
  |> String.concat ""

let private compactMenuItemPadding =
  AttrBuilder<MenuItem>.CreateProperty<Thickness>(
    TemplatedControl.PaddingProperty,
    Thickness(12.0, 1.0, 12.0, 1.0),
    ValueNone
  )

let private compactMenuItemMinHeight =
  AttrBuilder<MenuItem>.CreateProperty<float>(
    Layoutable.MinHeightProperty,
    0.0,
    ValueNone
  )

let private compactTitleMenuItem model dispatch txt txtToCopy =
  MenuItem.create [
    compactMenuItemPadding
    compactMenuItemMinHeight
    MenuItem.header (tokenTextViewUnselectable model txt)
    MenuItem.onClick (fun e ->
      Clipboard.setText
        (fun msg -> dispatch (UpdateStatusMsg msg))
        e.Source
        txtToCopy
    )
  ]

let private monoTextBlock model (txt: string) =
  TextBlock.create [
    TextBlock.text txt
    TextBlock.fontSize model.Theme.Font.Monospace.FontSize
    TextBlock.padding 0.0
    TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
  ]

let private compactMonoMenuItem dispatch (header: IView) txtToCopy =
  MenuItem.create [
    compactMenuItemPadding
    compactMenuItemMinHeight
    MenuItem.header header
    MenuItem.onClick (fun e ->
      Clipboard.setText
        (fun msg -> dispatch (UpdateStatusMsg msg))
        e.Source
        txtToCopy
    )
  ]

let private compactMonoMenuItemWithString model dispatch txt txtToCopy =
  match txtToCopy with
  | Some copy -> compactMonoMenuItem dispatch (monoTextBlock model txt) copy
  | None -> compactMonoMenuItem dispatch (monoTextBlock model txt) txt

let private compactMonoActionMenuItem model onClick txt =
  MenuItem.create [
    compactMenuItemPadding
    compactMenuItemMinHeight
    MenuItem.header (monoTextBlock model txt)
    MenuItem.onClick (fun _ -> onClick ())
  ]

let private addressTokenMenuItems fnAddr provider model dispatch word =
  let callers = (provider: ITokenContextProvider).GetCallers fnAddr
  [ compactTitleMenuItem model dispatch "Address" word.AsmWordValue :> IView
    compactMonoMenuItemWithString model dispatch word.AsmWordValue None
    if callers.Length > 0 then
      Separator.create []
      compactTitleMenuItem model dispatch "Caller(s) of this function" ""
      for caller in callers do
        let callerText = $"0x{caller:X}"
        model.Functions
        |> List.tryFind (fun fn -> fn.Address = caller)
        |> function
          | Some fnItem ->
            compactMonoActionMenuItem
              model
              (fun () -> dispatch (OpenCFGTab fnItem))
              $"Jump to {callerText}"
          | None ->
            compactMonoMenuItemWithString model dispatch callerText None
    else
      () ]

let private appendMenuSection title items model dispatch =
  if Array.isEmpty items then []
  else
    [ Separator.create [] :> IView
      compactTitleMenuItem model dispatch title ""
      for item in items do
        compactMonoMenuItemWithString model dispatch item None ]

let private mnemonicTokenMenuItems provider model dispatch addr words =
  let disasmLine = makeDisasmLine words
  let info = (provider: ITokenContextProvider).GetInstructionInfo addr
  let irBlock = info.Stmts |> String.concat Environment.NewLine
  let readAddrs = info.ReadAddrs |> Array.map (fun addr -> $"0x{addr}")
  let writeAddrs = info.WriteAddrs |> Array.map (fun addr -> $"0x{addr}")
  [ compactTitleMenuItem model dispatch "Instruction" disasmLine :> IView
    compactMonoMenuItemWithString model dispatch disasmLine None
    Separator.create []
    compactTitleMenuItem model dispatch "Semantics" irBlock
    compactMonoMenuItemWithString model dispatch irBlock None
    yield! appendMenuSection "Address(es) to Read" readAddrs model dispatch
    yield! appendMenuSection "Address(es) to Write" writeAddrs model dispatch
    if info.ConstDefs.Length > 0 then
      Separator.create []
      compactTitleMenuItem model dispatch "Register Constant Definitions" ""
      for r, v in info.ConstDefs do
        compactMonoMenuItemWithString model dispatch $"{r} = {v}" (Some v)
    else
      () ]

let private valueTokenMenuItems provider model dispatch word =
  let value = word.AsmWordValue
  let normalized = if value.StartsWith "0x" then value.Substring 2 else value
  [ compactTitleMenuItem model dispatch "Value" value :> IView
    match UInt64.TryParse(normalized, NumberStyles.HexNumber, null) with
    | true, num ->
      let sectionSuffix =
        (provider: ITokenContextProvider).TryGetSectionName num
        |> Option.map (fun name -> $" ({name})")
        |> Option.defaultValue ""
      let menuText = $"{value}{sectionSuffix}"
      compactMonoMenuItemWithString model dispatch menuText (Some value)
    | false, _ ->
      compactMonoMenuItemWithString model dispatch value None ]

let private tokenContextMenu fnAddr provider model dispatch word token words =
  ContextMenu.create [
    ContextMenu.viewItems [
      match word.AsmWordKind, (token: SelectedToken).Range with
      | AsmWordKind.Address, _ ->
        yield! addressTokenMenuItems fnAddr provider model dispatch word
      | AsmWordKind.Mnemonic, Some range ->
        yield! mnemonicTokenMenuItems provider model dispatch range.Min words
      | AsmWordKind.Value, _ ->
        yield! valueTokenMenuItems provider model dispatch word
      | _ ->
        compactTitleMenuItem model dispatch "Copy" word.AsmWordValue
    ]
  ]

let private onTokenPressed dispatch token e =
  let props = (e: PointerPressedEventArgs).GetCurrentPoint(null).Properties
  if props.IsRightButtonPressed then
    Some token
    |> SetSelectedToken
    |> CFGPaneMsg
    |> dispatch
    e.Handled <- true
  else
    ()

let inline private isSelectableToken word =
  match word.AsmWordKind with
  | AsmWordKind.String
  | AsmWordKind.CommentDelimiter
  | AsmWordKind.InstructionDelimiter -> false
  | _ -> true

let private tokenView fnAddr provider model dispatch selected word token words =
  if not (isSelectableToken word) then
    tokenTextView model word :> IView
  else
    Border.create [
      Border.background (
        if selected then model.Theme.Search.SelectedBackground
        else model.Theme.Common.Transparent
      )
      Border.cornerRadius 2.0
      Control.contextMenu (
        tokenContextMenu fnAddr provider model dispatch word token words
      )
      Control.onPointerPressed (onTokenPressed dispatch token)
      Border.child (tokenTextView model word)
    ]

let private disasmLnView fnAddr provider model dispatch tokenAt selected words =
  StackPanel.create [
    StackPanel.orientation Orientation.Horizontal
    StackPanel.children [
      for wordIdx, word in Array.indexed words do
        let token = tokenAt wordIdx
        let isSelected = selected wordIdx
        tokenView fnAddr provider model dispatch isSelected word token words
    ]
  ]

let private selectedTokenOf nID lineIdx wordIdx range =
  { NodeID = nID
    LineIndex = lineIdx
    WordIndex = wordIdx
    Range = range }

let private disasmView provider model dispatch loaded nID n =
  let viewState = loaded.ViewState
  let fnAddr = loaded.FunctionAddress
  let lines =
    if model.Theme.Font.Monospace.FontSize * viewState.Zoom < 6.0 then [||]
    else ((n: IVertex<_>).VData :> IVisualizable).Visualize()
  let ranges = (n.VData :> IVisualizable).LineAddrRanges
  StackPanel.create [
    StackPanel.orientation Orientation.Vertical
    StackPanel.horizontalAlignment HorizontalAlignment.Left
    StackPanel.verticalAlignment VerticalAlignment.Top
    StackPanel.children [
      for lnIdx, words in Array.indexed lines do
        let range = if lnIdx < ranges.Length then Some ranges[lnIdx] else None
        let tokenAt wordIdx = selectedTokenOf nID lnIdx wordIdx range
        let selected wordIdx =
          match viewState.SelectedToken with
          | Some sel ->
            sel.NodeID = nID && sel.LineIndex = lnIdx && sel.WordIndex = wordIdx
          | None ->
            false
        disasmLnView fnAddr provider model dispatch tokenAt selected words
    ]
  ]

let private nodeView provider model dispatch nID loaded x y w h n =
  let viewState = loaded.ViewState
  let zoom, panX, panY = viewState.Zoom, viewState.PanX, viewState.PanY
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
            Viewbox.child (disasmView provider model dispatch loaded nID n)
          ]
        )
      ]
    )
  ] |> View.withKey $"node-{nID}" :> IView

let private graphNodes provider model dispatch loaded isVisible =
  let zoom = loaded.ViewState.Zoom
  [ for nodeID, n in Array.indexed loaded.Graph.Vertices do
      let x, y = n.VData.Coordinate.X, n.VData.Coordinate.Y
      let w, h = n.VData.Width, n.VData.Height
      if not (isVisible x y w h) then
        ()
      else
        let w = ceil (w * zoom) + 1.1 (* margin to avoid clipping *)
        let h = ceil (h * zoom) + 1.1
        nodeView provider model dispatch nodeID loaded x y w h n ]

let [<Literal>] private ZoomDelta = 0.05
let [<Literal>] private CFGPanStartThresholdSquared = 16.0

let private tryGetCapturedGraphCanvas (e: PointerEventArgs) =
  match e.Pointer.Captured with
  | null -> None
  | captured -> tryFindGraphCanvas (captured :> obj)

let private pointerXY (e: PointerEventArgs) =
  match tryGetCapturedGraphCanvas e with
  | Some canvas ->
    let p = e.GetPosition canvas
    struct (p.X, p.Y)
  | None ->
    match tryFindGraphCanvas e.Source with
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
  match tryFindGraphCanvas e.Source with
  | Some canvas ->
    let target: IInputElement =
      if shouldCapture then canvas :> IInputElement
      else null
    e.Pointer.Capture target
  | None ->
    match e.Source with
    | :? Control as ctrl ->
      let target: IInputElement =
        if shouldCapture then ctrl :> IInputElement
        else null
      e.Pointer.Capture target
    | _ -> ()

let private capturePointer e =
  setPointerCapture true e

let private releasePointer e =
  setPointerCapture false e

let private onWheel dispatch (e: PointerWheelEventArgs) =
  let delta = if e.Delta.Y > 0.0 then ZoomDelta else -ZoomDelta
  let struct (x, y) = pointerXY e
  dispatch (CFGPaneMsg(SetZoom(delta, x, y)))
  e.Handled <- true

let private onPressed dispatch (e: PointerPressedEventArgs) =
  let struct (x, y) = pointerXY e
  dispatch (CFGPaneMsg(StartPan(x, y)))

let private onTapped dispatch (e: TappedEventArgs) =
  dispatch (CFGPaneMsg(SetSelectedToken None))
  e.Handled <- true

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
  dispatch (CFGPaneMsg(MovePan(x, y, ViewportSpace)))
  if shouldStartPan || model.CFGIsPanning then e.Handled <- true else ()

let private onReleased model dispatch (e: PointerReleasedEventArgs) =
  dispatch (CFGPaneMsg EndPan)
  if model.CFGIsPanning then releasePointer e else ()
  if model.CFGIsPanning || model.CFGPressedPointer.IsSome then e.Handled <- true
  else ()

let private graphCanvasView provider model vpSize dispatch loaded =
  let cfg = loaded.Graph
  let viewState = loaded.ViewState
  let cache = loaded.RenderCache
  let zoom, panX, panY = viewState.Zoom, viewState.PanX, viewState.PanY
  let hovered = viewState.HoveredEdge
  let viewportWidth, viewportHeight = vpSize
  let vpLeft, vpRight = -panX / zoom, (viewportWidth - panX) / zoom
  let vpTop, vpBottom = -panY / zoom, (viewportHeight - panY) / zoom
  let isEdgeVisible eID =
    CFGRenderCache.isEdgeVisible cache eID vpLeft vpRight vpTop vpBottom
  let isNodeVisible x y w h =
    x < vpRight && x + w > vpLeft && y < vpBottom && y + h > vpTop
  GraphCanvas.create [
    Canvas.background model.Theme.Window.Background
    Control.onPointerWheelChanged (onWheel dispatch)
    Control.onPointerPressed (onPressed dispatch)
    Control.onTapped (onTapped dispatch)
    Control.onPointerMoved (onMoved model dispatch)
    Control.onPointerReleased (onReleased model dispatch)
    Canvas.children [
      yield! graphEdges model dispatch hovered cfg zoom panX panY isEdgeVisible
      yield! graphNodes provider model dispatch loaded isNodeVisible
    ]
  ]

let private onMinimapClick dispatch (minimap: MinimapStaticCache) viewState e =
  match (e: PointerPressedEventArgs).Source with
  | :? Control as ctrl ->
    let p = e.GetPosition ctrl
    let scale = minimap.Scale
    let gx = (p.X - minimap.OffsetX) / scale + viewState.GraphMinX
    let gy = (p.Y - minimap.OffsetY) / scale + viewState.GraphMinY
    dispatch (CFGPaneMsg(JumpPan(gx, gy)))
    let struct (sx, sy) = pointerXY e
    dispatch (CFGPaneMsg(StartPan(sx, sy)))
    e.Pointer.Capture ctrl
    e.Handled <- true
  | _ -> ()

let private onRectMoved dispatch minimapScale e =
  let struct (x, y) = pointerXY e
  dispatch (CFGPaneMsg(MovePan(x, y, MinimapSpace minimapScale)))
  e.Handled <- true

let private onRectReleased dispatch (e: PointerReleasedEventArgs) =
  dispatch (CFGPaneMsg EndPan)
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
  dispatch (CFGPaneMsg(StartPan(x, y)))
  match e.Source with
  | :? Control as ctrl -> e.Pointer.Capture ctrl
  | _ -> ()
  e.Handled <- true

let private minimapViewport model vpSize dispatch minimap viewState =
  let scale = minimap.Scale
  let viewportWidth, viewportHeight = vpSize
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

let private minimapOverlayView model vpSize dispatch loaded =
  let viewState, minimap = loaded.ViewState, loaded.Minimap
  if viewState.ShowMinimap then
    [ Border.create [
        Border.horizontalAlignment HorizontalAlignment.Right
        Border.verticalAlignment VerticalAlignment.Bottom
        Border.margin 12.0
        Border.child (minimapView model dispatch minimap viewState)
      ] :> IView
      minimapViewport model vpSize dispatch minimap viewState ]
  else
    []

let private loadedView provider model vpSize dispatch loaded =
  Border.create [
    Border.background model.Theme.Window.Background
    Border.clipToBounds true
    Border.child (
      Grid.create [
        Grid.children [
          graphCanvasView provider model vpSize dispatch loaded
          yield! minimapOverlayView model vpSize dispatch loaded
        ]
      ]
    )
  ]

let view tokenContextProvider pane (model: Model) dispatch =
  let viewKey =
    match pane.ActiveTab with
    | Some tab -> $"cfg-{tab.ID}"
    | None -> "cfg-none"
  Border.create [
    Border.background model.Theme.Window.Background
    Border.borderThickness 0.0
    Border.child (
      match pane.ActiveTab with
      | Some { Content = CFGContent(_, NotLoaded) } ->
        unloadedView model "CFG is not loaded."
      | Some { Content = CFGContent(_, Loading) } ->
        unloadedView model "CFG is now loading ..."
      | Some { Content = CFGContent(_, Loaded loaded) } ->
        let viewportSize = pane.ContentViewportSize
        loadedView tokenContextProvider model viewportSize dispatch loaded
      | _ ->
        unloadedView model "Select a function to view its CFG."
    )
  ] |> View.withKey viewKey :> IView
