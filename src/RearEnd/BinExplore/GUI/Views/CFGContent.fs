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
open Avalonia.FuncUI.VirtualDom
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
    Border.background model.Theme.Graph.Background
    Border.child (
      TextBlock.create [
        TextBlock.text text
        TextBlock.foreground model.Theme.Text.Primary
        TextBlock.fontSize model.Theme.Font.Scale.Medium
        TextBlock.margin 12.0
      ]
    )
  ] :> IView

let private brushOfColor =
  let cache = Dictionary<string, IBrush>()
  fun color ->
    match cache.TryGetValue color with
    | true, brush ->
      brush
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

let private edgeHitAreaThickness zoom = 5.0 / sqrt zoom |> max 6.0 |> min 14.0

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

let private onEdgeEntered dispatch eid _ =
  dispatch (CFGPaneMsg(SetHoveredEdge eid))

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
    Control.onPointerEntered (onEdgeEntered dispatch eid, OnChangeOf eid)
    Control.onPointerExited (fun _ ->
      dispatch (CFGPaneMsg(SetHoveredEdge None)))
    Tunnel.OnPointerPressed(
      onEdgePressed dispatch zoom panX panY p1 p2,
      OnChangeOf(zoom, panX, panY, p1, p2)
    )
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
    ] :> IView
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

let private tokenTextViewUnselectable model txt =
  TextBlock.create [
    TextBlock.text txt
    TextBlock.foreground model.Theme.Text.Secondary
    TextBlock.fontSize model.Theme.Font.Scale.Small
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
        (fun msg -> dispatch (UpdateStatusMsg msg)) e.Source txtToCopy
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
        (fun msg -> dispatch (UpdateStatusMsg msg)) e.Source txtToCopy
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
              $"Call from {callerText}"
          | None ->
            compactMonoMenuItemWithString model dispatch callerText None
    else
      () ]

let private appendMenuSection title items model dispatch =
  if Array.isEmpty items then
    []
  else
    [ Separator.create [] :> IView
      compactTitleMenuItem model dispatch title ""
      for item in items do
        compactMonoMenuItemWithString model dispatch item None ]

let private openPCTarget provider model dispatch fnAddr target =
  if (provider: ITokenContextProvider).IsAddressInFunction(fnAddr, target) then
    dispatch (CFGPaneMsg(JumpPanToAddr target))
  else
    model.Functions
    |> List.tryFind (fun fn -> fn.Address = target)
    |> function
      | Some fnItem -> dispatch (OpenCFGTab fnItem)
      | None -> ()

let private pcTargetMenuItem provider model dispatch fnAddr target =
  let targetText = $"0x{target:X}"
  compactMonoActionMenuItem
    model
    (fun () -> openPCTarget provider model dispatch fnAddr target)
    $"Jump to {targetText}"

let private mnemonicTokenMenuItems provider model dispatch fnAddr addr words =
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
      ()
    if info.PCTargets.Length > 0 then
      Separator.create []
      compactTitleMenuItem model dispatch "PC Target(s)" ""
      for target in info.PCTargets do
        pcTargetMenuItem provider model dispatch fnAddr target
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
        let addr = range.Min
        yield! mnemonicTokenMenuItems provider model dispatch fnAddr addr words
      | AsmWordKind.Value, _ ->
        yield! valueTokenMenuItems provider model dispatch word
      | _ ->
        compactTitleMenuItem model dispatch "Copy" word.AsmWordValue
    ]
  ]

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
        let p = if isNull root then e.GetPosition ctrl else e.GetPosition root
        struct (p.X, p.Y)
      | _ ->
        struct (0.0, 0.0)

let private setPointerCapture shouldCapture (e: PointerEventArgs) =
  match tryFindGraphCanvas e.Source with
  | Some canvas ->
    let target: IInputElement =
      if shouldCapture then canvas :> IInputElement else null
    e.Pointer.Capture target
  | None ->
    match e.Source with
    | :? Control as ctrl ->
      let target: IInputElement =
        if shouldCapture then ctrl :> IInputElement else null
      e.Pointer.Capture target
    | _ ->
      ()

let private capturePointer e = setPointerCapture true e

let private releasePointer e = setPointerCapture false e

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

let private onMoved (pressed, isPanning) dispatch (e: PointerEventArgs) =
  let struct (x, y) = pointerXY e
  let shouldStartPan =
    match pressed with
    | Some(pressedX, pressedY) when not isPanning ->
      let dx = x - pressedX
      let dy = y - pressedY
      dx * dx + dy * dy >= CFGPanStartThresholdSquared
    | _ ->
      false
  if shouldStartPan then capturePointer e else ()
  dispatch (CFGPaneMsg(MovePan(x, y, ViewportSpace)))
  if shouldStartPan || isPanning then e.Handled <- true else ()

(* A release that ends a pan is the pan's; any other release, a click, is
   left to the controls beneath, which is where a right click finds the
   context menu of a token. *)
let private onReleased isPanning dispatch (e: PointerReleasedEventArgs) =
  dispatch (CFGPaneMsg EndPan)
  if isPanning then
    releasePointer e
    e.Handled <- true
  else
    ()

(* The border and padding that VisBBlock lays out around the text of a node. *)
let [<Literal>] private NodeInset = 5.0

(* Below this on-screen font size the text of a node cannot be read, so only
   the box of the node is drawn. *)
let [<Literal>] private MinReadableFontSize = 6.0

let inline private isSelectableToken word =
  match word.AsmWordKind with
  | AsmWordKind.String
  | AsmWordKind.CommentDelimiter
  | AsmWordKind.InstructionDelimiter -> false
  | _ -> true

let private tokenForeground (theme: Theme) = function
  | AsmWordKind.Address -> theme.Text.Address
  | AsmWordKind.Mnemonic -> theme.Text.Mnemonic
  | AsmWordKind.Variable -> theme.Text.Variable
  | AsmWordKind.Value -> theme.Text.Value
  | _ -> theme.Text.Primary

let private makeMonoText (theme: Theme) text (brush: IBrush) =
  let mono = theme.Font.Monospace
  FormattedText(
    text,
    CultureInfo.CurrentCulture,
    FlowDirection.LeftToRight,
    Typeface(FontFamily mono.FontFamily),
    mono.FontSize,
    brush
  )

/// Measures a character of the monospace font the way the layout measured it,
/// so that drawn text and laid-out boxes agree on how big a character is.
let private measureCharSize theme =
  let txt = makeMonoText theme "M" Brushes.Black
  Size(txt.Width, txt.Height)

/// Makes one line of a node into a single text, each token in its own color.
let private makeLineText theme (words: AsmWord[]) =
  let text = words |> Array.map (fun w -> w.AsmWordValue) |> String.concat ""
  let txt = makeMonoText theme text (brushOfColor theme.Text.Primary)
  let mutable start = 0
  for word in words do
    let len = AsmWord.Width word
    let color = tokenForeground theme word.AsmWordKind
    if len > 0 then txt.SetForegroundBrush(brushOfColor color, start, len)
    else ()
    start <- start + len
  txt

/// Represents the text of a node, ready to draw.
type private NodeText =
  { /// One text per line of the node.
    Lines: FormattedText[]
    /// The factor that fits the text, at the size it is drawn, into the box
    /// laid out for it; 1.0 whenever the two agree on the font.
    Fit: float }

let private widestLine (lines: AsmWord[][]) =
  lines |> Array.fold (fun widest line ->
    max widest (Array.sumBy AsmWord.Width line)) 0

let private fitOf (vData: VisBBlock) (charSize: Size) (lines: AsmWord[][]) =
  let widest = widestLine lines
  if widest = 0 || lines.Length = 0 then
    1.0
  else
    let textWidth = float widest * charSize.Width
    let textHeight = float lines.Length * charSize.Height
    let fitX = (vData.Width - 2.0 * NodeInset) / textWidth
    let fitY = (vData.Height - 2.0 * NodeInset) / textHeight
    min fitX fitY

let private makeNodeText theme charSize (vData: VisBBlock) =
  let lines = (vData :> IVisualizable).Visualize()
  { Lines = lines |> Array.map (makeLineText theme)
    Fit = fitOf vData charSize lines }

let private isTextShown (theme: Theme) (view: CFGViewState) =
  theme.Font.Monospace.FontSize * view.Zoom >= MinReadableFontSize

let private selectedTokenOf nID lineIdx wordIdx range =
  { NodeID = nID
    LineIndex = lineIdx
    WordIndex = wordIdx
    Range = range }

let rec private tryFindWordFrom (words: AsmWord[]) col idx start =
  if idx >= words.Length || col < start then
    None
  else
    let next = start + AsmWord.Width words[idx]
    if col < next then Some idx else tryFindWordFrom words col (idx + 1) next

let private tryFindTokenAt nodeID (vData: VisBBlock) row col =
  let lines = (vData :> IVisualizable).Visualize()
  if row < 0 || row >= lines.Length then
    None
  else
    let words = lines[row]
    match tryFindWordFrom words col 0 0 with
    | Some wordIdx when isSelectableToken words[wordIdx] ->
      let ranges = (vData :> IVisualizable).LineAddrRanges
      let range = if row < ranges.Length then Some ranges[row] else None
      Some(selectedTokenOf nodeID row wordIdx range)
    | _ ->
      None

/// Draws one node of a CFG, its box and its text, in the coordinates of the
/// graph. The layer holding it pans and zooms by transforming itself, which
/// leaves what a node has drawn in place, so a node draws only when it first
/// appears or when what it shows changes.
type private CFGNodeVisual(nodeID, vData: VisBBlock, theme, charSize: Size) =
  inherit Control()

  let mutable text = None

  let mutable showText = false

  let mutable selection = None

  member _.NodeID = nodeID

  member this.SetShowText value =
    if showText <> value then
      showText <- value
      this.InvalidateVisual()
    else
      ()

  /// Sets the line and word of the token selected in this node, if any.
  member this.SetSelection(value: (int * int) option) =
    if selection <> value then
      selection <- value
      this.InvalidateVisual()
    else
      ()

  member _.GetText() =
    match text with
    | Some text ->
      text
    | None ->
      let made = makeNodeText theme charSize vData
      text <- Some made
      made

  /// Returns the selectable token at the given point, given in the coordinates
  /// of this node.
  member this.TryFindToken(p: Point) =
    if showText then
      let fit = this.GetText().Fit
      let col = floor ((p.X - NodeInset) / (charSize.Width * fit)) |> int
      let row = floor ((p.Y - NodeInset) / (charSize.Height * fit)) |> int
      tryFindTokenAt nodeID vData row col
    else
      None

  member _.DrawSelection(ctx: DrawingContext) =
    match selection with
    | Some(row, wordIdx) ->
      let lines = (vData :> IVisualizable).Visualize()
      if row < lines.Length && wordIdx < lines[row].Length then
        let words = lines[row]
        let start = words[..wordIdx - 1] |> Array.sumBy AsmWord.Width
        let len = AsmWord.Width words[wordIdx]
        let x, y = float start * charSize.Width, float row * charSize.Height
        let rect = Rect(x, y, float len * charSize.Width, charSize.Height)
        let brush = brushOfColor theme.Search.SelectedBackground
        ctx.DrawRectangle(brush, null, rect, 2.0, 2.0)
      else
        ()
    | None ->
      ()

  member this.DrawText(ctx: DrawingContext) =
    let text = this.GetText()
    let transform =
      Matrix.CreateScale(text.Fit, text.Fit)
      * Matrix.CreateTranslation(NodeInset, NodeInset)
    use _ = ctx.PushTransform transform
    this.DrawSelection ctx
    text.Lines
    |> Array.iteri (fun row line ->
      ctx.DrawText(line, Point(0.0, float row * charSize.Height)))

  override _.MeasureOverride _ = Size(vData.Width, vData.Height)

  override this.Render(ctx: DrawingContext) =
    base.Render ctx
    let pen = Pen(brushOfColor theme.Panel.Border, 1.0)
    let rect = Rect(0.0, 0.0, vData.Width, vData.Height).Deflate 0.5
    let background = brushOfColor theme.Panel.AltBackground
    ctx.DrawRectangle(background, pen, rect, 4.0, 4.0)
    if showText then this.DrawText ctx else ()

let private selectionIn nodeID (token: SelectedToken option) =
  token
  |> Option.filter (fun token -> token.NodeID = nodeID)
  |> Option.map (fun token -> token.LineIndex, token.WordIndex)

/// Returns the part of the graph that the viewport shows, in the coordinates
/// of the graph.
let private shownRect (view: CFGViewState) (viewport: Size) =
  let x, y = -view.PanX / view.Zoom, -view.PanY / view.Zoom
  Rect(x, y, viewport.Width / view.Zoom, viewport.Height / view.Zoom)

/// Holds the nodes of a CFG. It pans and zooms by transforming itself rather
/// than by moving the nodes, so that a pan redraws nothing that is already on
/// screen. Only the nodes near the viewport are made into controls; a node is
/// made when it comes near, and dropped once it has gone well past.
type private CFGNodeLayer() =
  inherit Canvas()

  let nodes = Dictionary<int, CFGNodeVisual>()

  let mutable charSize = Size()

  let mutable showText = false

  let mutable selected = None

  static let graphProperty =
    AvaloniaProperty.Register<CFGNodeLayer, VisGraph>(
      nameof Unchecked.defaultof<CFGNodeLayer>.CurrentGraph,
      Unchecked.defaultof<VisGraph>
    )

  static let viewStateProperty =
    AvaloniaProperty.Register<CFGNodeLayer, CFGViewState>(
      nameof Unchecked.defaultof<CFGNodeLayer>.CurrentViewState,
      Unchecked.defaultof<CFGViewState>
    )

  static let themeProperty =
    AvaloniaProperty.Register<CFGNodeLayer, Theme>(
      nameof Unchecked.defaultof<CFGNodeLayer>.CurrentTheme,
      Unchecked.defaultof<Theme>
    )

  static let viewportProperty =
    AvaloniaProperty.Register<CFGNodeLayer, Size>(
      nameof Unchecked.defaultof<CFGNodeLayer>.CurrentViewport,
      Size()
    )

  static member GraphProperty = graphProperty

  static member ViewStateProperty = viewStateProperty

  static member ThemeProperty = themeProperty

  static member ViewportProperty = viewportProperty

  member this.CurrentGraph
    with get() = this.GetValue graphProperty
    and set value = this.SetValue(graphProperty, value) |> ignore

  member this.CurrentViewState
    with get() = this.GetValue viewStateProperty
    and set value = this.SetValue(viewStateProperty, value) |> ignore

  member this.CurrentTheme
    with get() = this.GetValue themeProperty
    and set value = this.SetValue(themeProperty, value) |> ignore

  member this.CurrentViewport
    with get() = this.GetValue viewportProperty
    and set value = this.SetValue(viewportProperty, value) |> ignore

  member this.IsReady =
    not (isNull (box this.CurrentGraph))
    && not (isNull (box this.CurrentViewState))
    && not (isNull (box this.CurrentTheme))

  (* A graph is compared by identity: it does not change in place, and walking
     it for equality on every render would cost what this layer saves. *)
  static member Graph value =
    let isSame (a: obj, b: obj) = obj.ReferenceEquals(a, b)
    AttrBuilder<'t>.CreateProperty<VisGraph>(
      CFGNodeLayer.GraphProperty, value, ValueSome isSame
    )

  static member ViewState value =
    AttrBuilder<'t>.CreateProperty<CFGViewState>(
      CFGNodeLayer.ViewStateProperty, value, ValueNone
    )

  static member Theme value =
    AttrBuilder<'t>.CreateProperty<Theme>(
      CFGNodeLayer.ThemeProperty, value, ValueNone
    )

  static member Viewport value =
    AttrBuilder<'t>.CreateProperty<Size>(
      CFGNodeLayer.ViewportProperty, value, ValueNone
    )

  member this.SyncTransform() =
    let view = this.CurrentViewState
    let zoom = view.Zoom
    let matrix = Matrix(zoom, 0.0, 0.0, zoom, view.PanX, view.PanY)
    this.RenderTransformOrigin <- RelativePoint.TopLeft
    this.RenderTransform <- MatrixTransform matrix

  member _.SyncShowText(show) =
    if show <> showText then
      showText <- show
      for node in nodes.Values do node.SetShowText show
    else
      ()

  member _.SyncSelection(next: SelectedToken option) =
    if next <> selected then
      let touched =
        [ selected; next ]
        |> List.choose (Option.map (fun token -> token.NodeID))
        |> List.distinct
      selected <- next
      for nodeID in touched do
        match nodes.TryGetValue nodeID with
        | true, node -> node.SetSelection(selectionIn nodeID next)
        | false, _ -> ()
    else
      ()

  member this.Realize(nodeID, vData: VisBBlock) =
    let node = CFGNodeVisual(nodeID, vData, this.CurrentTheme, charSize)
    node.SetShowText showText
    node.SetSelection(selectionIn nodeID selected)
    Canvas.SetLeft(node, vData.Coordinate.X)
    Canvas.SetTop(node, vData.Coordinate.Y)
    nodes[nodeID] <- node
    this.Children.Add node

  member this.Unrealize(node: CFGNodeVisual) =
    nodes.Remove node.NodeID |> ignore
    this.Children.Remove node |> ignore

  member this.SyncNodes() =
    let shown = shownRect this.CurrentViewState this.CurrentViewport
    let near = shown.Inflate(Thickness(shown.Width / 2.0, shown.Height / 2.0))
    let kept = shown.Inflate(Thickness(shown.Width, shown.Height))
    for nodeID, v in Array.indexed this.CurrentGraph.Vertices do
      let vData = v.VData
      let pos = vData.Coordinate
      let rect = Rect(pos.X, pos.Y, vData.Width, vData.Height)
      match nodes.TryGetValue nodeID with
      | true, node when not (rect.Intersects kept) ->
        this.Unrealize node
      | false, _ when not vData.IsDummy && rect.Intersects near ->
        this.Realize(nodeID, vData)
      | _ ->
        ()

  member this.Sync() =
    if this.IsReady then
      let view = this.CurrentViewState
      this.SyncTransform()
      this.SyncShowText(isTextShown this.CurrentTheme view)
      this.SyncSelection view.SelectedToken
      this.SyncNodes()
    else
      ()

  member this.Rebuild() =
    this.Children.Clear()
    nodes.Clear()
    if this.IsReady then
      charSize <- measureCharSize this.CurrentTheme
      this.Sync()
    else
      ()

  override this.OnPropertyChanged change =
    base.OnPropertyChanged change
    if change.Property = graphProperty || change.Property = themeProperty then
      this.Rebuild()
    elif change.Property = viewStateProperty
         || change.Property = viewportProperty then
      this.Sync()
    else
      ()

[<RequireQualifiedAccess>]
module private CFGNodeLayer =
  let create (attrs: IAttr<CFGNodeLayer> list) =
    View.createGeneric<CFGNodeLayer> attrs

let private onNodeTapped dispatch (e: TappedEventArgs) =
  match e.Source with
  | :? CFGNodeVisual as node ->
    let token = node.TryFindToken(e.GetPosition node)
    dispatch (CFGPaneMsg(SetSelectedToken token))
    e.Handled <- true
  | _ ->
    ()

let private tokenWords loaded token =
  let vertex = loaded.Graph.Vertices[token.NodeID]
  let lines = (vertex.VData :> IVisualizable).Visualize()
  lines[token.LineIndex]

/// Opens the context menu of the given token. Building the menu lifts the
/// instruction, so it happens here, once per request, rather than for every
/// visible token on every render.
let private openTokenMenu provider model dispatch loaded token target =
  let words = tokenWords loaded token
  let word = words[token.WordIndex]
  let fnAddr = loaded.FunctionAddress
  let menu = tokenContextMenu fnAddr provider model dispatch word token words
  (VirtualDom.create menu :?> ContextMenu).Open target

let private onNodeContextRequested provider model dispatch loaded e =
  match (e: ContextRequestedEventArgs).Source with
  | :? CFGNodeVisual as node ->
    match e.TryGetPosition(node) with
    | true, p ->
      match node.TryFindToken p with
      | Some token ->
        openTokenMenu provider model dispatch loaded token node
        e.Handled <- true
      | None ->
        ()
    | false, _ ->
      ()
  | _ ->
    ()

let private nodeLayerView provider model vpSize dispatch loaded =
  let width, height = vpSize
  CFGNodeLayer.create [
    CFGNodeLayer.Graph loaded.Graph
    CFGNodeLayer.ViewState loaded.ViewState
    CFGNodeLayer.Theme model.Theme
    CFGNodeLayer.Viewport(Size(width, height))
    Control.onTapped (onNodeTapped dispatch)
    Tunnel.OnContextRequested(
      onNodeContextRequested provider model dispatch loaded,
      SubPatchOptions.Always
    )
  ] :> IView

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
  let pan = model.CFGPressedPointer, model.CFGIsPanning
  GraphCanvas.create [
    Canvas.background model.Theme.Graph.Background
    Tunnel.OnPointerWheelChanged(onWheel dispatch)
    Tunnel.OnPointerPressed(onPressed dispatch)
    Control.onTapped (onTapped dispatch)
    Tunnel.OnPointerMoved(onMoved pan dispatch, OnChangeOf pan)
    Tunnel.OnPointerReleased(
      onReleased model.CFGIsPanning dispatch,
      OnChangeOf model.CFGIsPanning
    )
    Canvas.children [
      yield! graphEdges model dispatch hovered cfg zoom panX panY isEdgeVisible
      nodeLayerView provider model vpSize dispatch loaded
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
  | _ ->
    ()

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
  let origin = viewState.GraphMinX, viewState.GraphMinY
  let clickScope = minimap.Scale, minimap.OffsetX, minimap.OffsetY, origin
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
        Tunnel.OnPointerPressed(
          onMinimapClick dispatch minimap viewState,
          OnChangeOf clickScope
        )
        Tunnel.OnPointerMoved(
          onRectMoved dispatch minimap.Scale,
          OnChangeOf minimap.Scale
        )
        Tunnel.OnPointerReleased(onRectReleased dispatch)
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
            Tunnel.OnPointerPressed(onRectPressed dispatch)
            Tunnel.OnPointerMoved(
              onRectMoved dispatch scale,
              OnChangeOf scale
            )
            Tunnel.OnPointerReleased(onRectReleased dispatch)
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
    Border.background model.Theme.Graph.Background
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
    Border.background model.Theme.Graph.Background
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
