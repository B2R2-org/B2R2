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
module B2R2.RearEnd.BinExplore.GUI.Hexdump

open System
open System.Collections.Generic
open Avalonia
open Avalonia.Controls
open Avalonia.Controls.Documents
open Avalonia.FuncUI.Builder
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types
open Avalonia.Media

let [<Literal>] private OverscanRows = 12

type private RowHighlightSegment =
  { StartOffset: int
    Length: int
    Background: string }

type private TextHighlightRange =
  { Start: int
    Length: int
    Brush: IBrush }

type private HexdumpLayout =
  { PaddingX: float
    RowHeight: float
    BytesPerRow: int
    CharWidth: float
    AddressWidth: float
    AddressGap: float
    HexLeft: float
    HexCellWidth: float
    HexWidth: float
    AsciiGap: float
    AsciiLeft: float
    AsciiWidth: float
    LineWidth: float }

let private computeLayout (viewState: HexViewState) =
  let bytesPerRow = max 1 viewState.BytesPerRow
  let charWidth = max viewState.CharWidth 1.0
  let rowHeight = max viewState.RowHeight 1.0
  let addressWidth = charWidth * float (viewState.AddressDigits + 2)
  let addressGap = 8.0
  let hexCellWidth = charWidth * 3.0
  let hexWidth = charWidth * float (max 0 (bytesPerRow * 3 - 1))
  let asciiGap = 12.0
  let asciiWidth = charWidth * float bytesPerRow
  let hexLeft = addressWidth + addressGap
  let asciiLeft = hexLeft + hexWidth + asciiGap
  { PaddingX = 8.0
    RowHeight = rowHeight
    BytesPerRow = bytesPerRow
    CharWidth = charWidth
    AddressWidth = addressWidth
    AddressGap = addressGap
    HexLeft = hexLeft
    HexCellWidth = hexCellWidth
    HexWidth = hexWidth
    AsciiGap = asciiGap
    AsciiLeft = asciiLeft
    AsciiWidth = asciiWidth
    LineWidth = asciiLeft + asciiWidth }

type private HexdumpInteractionCanvas() =
  inherit Canvas()

  let mutable pressedByte = None
  let mutable pendingSelectionToggle = None

  let clampIfNeeded shouldClamp minValue maxValue value =
    if shouldClamp then max minValue (min maxValue value)
    else value

  let selectionRange selection =
    min selection.Anchor selection.Caret, max selection.Anchor selection.Caret

  let isByteSelected state byteIndex =
    match state.Selection with
    | Some selection ->
      let startByte, endByte = selectionRange selection
      startByte <= byteIndex && byteIndex <= endByte
    | None ->
      false

  let tryGetRow shouldClamp maxRow rowHeight y =
    let row = int64 (floor (y / rowHeight))
    let row = clampIfNeeded shouldClamp 0L maxRow row
    if row < 0L || row > maxRow then None else Some row

  let tryGetHexColumn shouldClamp (layout: HexdumpLayout) x =
    let localX = x - layout.PaddingX
    let hexX = localX - layout.HexLeft
    let hexX = clampIfNeeded shouldClamp 0.0 layout.HexWidth hexX
    if hexX < 0.0 || hexX > layout.HexWidth then None
    else
      let maxCol = int64 (layout.BytesPerRow - 1)
      let col = int64 (floor (hexX / layout.HexCellWidth))
      let col = clampIfNeeded shouldClamp 0L maxCol col
      if col < 0L || col > maxCol then None else Some col

  let tryGetByteIndex docLength bytesPerRow shouldClamp row col =
    let byteIndex = row * int64 bytesPerRow + col
    if byteIndex < docLength then Some byteIndex
    elif shouldClamp then Some(docLength - 1L)
    else None

  let tryGetByteIndexAtPoint state shouldClamp x y =
    let doc = state.Document
    if doc.Length <= 0L then
      None
    else
      let layout = computeLayout state.View
      let totalRows =
        int ((doc.Length + int64 layout.BytesPerRow - 1L) / int64 layout.BytesPerRow)
      let maxRow = int64 totalRows - 1L
      match tryGetRow shouldClamp maxRow layout.RowHeight y with
      | None ->
        None
      | Some row ->
        match tryGetHexColumn shouldClamp layout x with
        | None -> None
        | Some col -> tryGetByteIndex doc.Length layout.BytesPerRow shouldClamp row col

  static let stateProperty =
    AvaloniaProperty.Register<HexdumpInteractionCanvas, HexdumpState option>(
      nameof Unchecked.defaultof<HexdumpInteractionCanvas>.CurrentState, None
    )

  static let dispatchProperty =
    AvaloniaProperty.Register<HexdumpInteractionCanvas, Message -> unit>(
      nameof Unchecked.defaultof<HexdumpInteractionCanvas>.Dispatcher, ignore
    )

  static member StateProperty = stateProperty

  static member DispatchProperty = dispatchProperty

  static member State value =
    AttrBuilder<'t>.CreateProperty<HexdumpState option>(
      HexdumpInteractionCanvas.StateProperty, value, ValueNone
    )

  static member Dispatch value =
    AttrBuilder<'t>.CreateProperty<Message -> unit>(
      HexdumpInteractionCanvas.DispatchProperty, value, ValueNone
    )

  member this.CurrentState
    with get() = this.GetValue stateProperty
    and set value = this.SetValue(stateProperty, value) |> ignore

  member this.Dispatcher
    with get() = this.GetValue dispatchProperty
    and set value = this.SetValue(dispatchProperty, value) |> ignore

  member this.DispatchHexdump msg =
    this.Dispatcher(HexdumpMsg msg)

  override this.OnPointerPressed e =
    base.OnPointerPressed e
    match this.CurrentState with
    | Some state ->
      let p = e.GetPosition this
      match tryGetByteIndexAtPoint state false p.X p.Y with
      | Some byteIndex ->
        pressedByte <- Some byteIndex
        e.Pointer.Capture this
        if isByteSelected state byteIndex then
          pendingSelectionToggle <- Some byteIndex
        else
          pendingSelectionToggle <- None
          this.DispatchHexdump(StartSelection byteIndex)
          this.DispatchHexdump(SetHoveredByte(Some byteIndex))
        e.Handled <- true
      | None ->
        ()
    | None ->
      ()

  override this.OnPointerMoved e =
    base.OnPointerMoved e
    match this.CurrentState with
    | Some state ->
      let p = e.GetPosition this
      this.DispatchHexdump(
        SetHoveredByte(tryGetByteIndexAtPoint state false p.X p.Y)
      )
      if e.Pointer.Captured = this then
        match tryGetByteIndexAtPoint state true p.X p.Y with
        | Some byteIndex ->
          match pendingSelectionToggle, pressedByte with
          | Some pendingByte, Some anchorByte when byteIndex <> pendingByte ->
            pendingSelectionToggle <- None
            this.DispatchHexdump(StartSelection anchorByte)
            this.DispatchHexdump(UpdateSelection byteIndex)
          | None, _ ->
            this.DispatchHexdump(UpdateSelection byteIndex)
          | _ ->
            ()
          e.Handled <- true
        | None ->
          ()
      else
        ()
    | None ->
      ()

  override this.OnPointerReleased e =
    base.OnPointerReleased e
    match this.CurrentState with
    | Some state when e.Pointer.Captured = this ->
      let p = e.GetPosition this
      let releasedByte = tryGetByteIndexAtPoint state false p.X p.Y
      match pendingSelectionToggle, pressedByte, releasedByte with
      | Some pendingByte, Some anchorByte, Some byteIndex
        when pendingByte = anchorByte && byteIndex = anchorByte ->
        this.DispatchHexdump(SetSelection None)
        this.DispatchHexdump(SetCaret None)
      | Some _, _, _ ->
        ()
      | None, _, Some byteIndex ->
        this.DispatchHexdump(UpdateSelection byteIndex)
        this.DispatchHexdump EndSelection
      | None, _, None ->
        this.DispatchHexdump EndSelection
      this.DispatchHexdump(SetHoveredByte releasedByte)
      pressedByte <- None
      pendingSelectionToggle <- None
      e.Pointer.Capture null
      e.Handled <- true
    | _ ->
      pressedByte <- None
      pendingSelectionToggle <- None
      ()

  override this.OnPointerExited e =
    base.OnPointerExited e
    if e.Pointer.Captured <> this then
      this.DispatchHexdump(SetHoveredByte None)
    else
      ()

[<RequireQualifiedAccess>]
module private HexdumpInteractionCanvas =
  let create (attrs: IAttr<HexdumpInteractionCanvas> list) =
    View.createGeneric<HexdumpInteractionCanvas> attrs

type private HexdumpRowTextBlock() =
  inherit TextBlock()

  static let highlightRangesProperty =
    AvaloniaProperty.Register<HexdumpRowTextBlock, TextHighlightRange list>(
      nameof Unchecked.defaultof<HexdumpRowTextBlock>.HighlightRanges, []
    )

  static member HighlightRangesProperty = highlightRangesProperty

  static member Highlight value =
    AttrBuilder<'t>.CreateProperty<TextHighlightRange list>(
      HexdumpRowTextBlock.HighlightRangesProperty, value, ValueNone
    )

  member this.HighlightRanges
    with get() = this.GetValue highlightRangesProperty
    and set value = this.SetValue(highlightRangesProperty, value) |> ignore

  static member FillHighlightRect(context, origin: Point, brush, rect: Rect) =
    if rect.Width > 0.0 && rect.Height > 0.0 then
      let rect =
        Rect(
          origin.X + rect.X,
          origin.Y + rect.Y,
          rect.Width,
          rect.Height
        )
      (context: DrawingContext).FillRectangle(brush, rect)
    else
      ()

  override this.OnPropertyChanged change =
    base.OnPropertyChanged change
    if change.Property = highlightRangesProperty then this.InvalidateVisual()
    else ()

  override this.RenderTextLayout(context: DrawingContext, origin: Point) =
    let textLayout = this.TextLayout
    for range in this.HighlightRanges do
      let brush = range.Brush
      if range.Length > 0 then
        for rect in textLayout.HitTestTextRange(range.Start, range.Length) do
          HexdumpRowTextBlock.FillHighlightRect(context, origin, brush, rect)
      else
        ()
    base.RenderTextLayout(context, origin)

[<RequireQualifiedAccess>]
module private HexdumpRowTextBlock =
  let create (attrs: IAttr<HexdumpRowTextBlock> list) =
    View.createGeneric<HexdumpRowTextBlock> attrs

let private onScrollChanged dispatch (args: ScrollChangedEventArgs) =
  let deltaY = args.OffsetDelta.Y
  dispatch (HexdumpMsg(HandleScrollChanged deltaY))

let private byteToAscii b =
  if b >= 0x20uy && b <= 0x7Euy then char b
  else '.'

let private formatAddress digits baseAddress offset =
  let addr = baseAddress + uint64 offset
  let txt = addr.ToString("X").PadLeft(digits, '0')
  $"0x{txt}"

let private formatHexBytes bytes =
  bytes |> Array.map (fun b -> $"{b:X2}") |> String.concat " "

let private formatAscii bytes =
  bytes |> Array.map byteToAscii |> String

let private selectionRange selection =
  min selection.Anchor selection.Caret, max selection.Anchor selection.Caret

let private gapText charWidth gap =
  let spaces = max 1 (int (round (gap / max charWidth 1.0)))
  String.replicate spaces " "

let private rowTextRuns model addr addrGapText hexText asciiGapText asciiText =
  [
    Run.create [
      Run.text addr
      Run.foreground model.Theme.Text.Address
    ] :> IView
    Run.create [ Run.text addrGapText ]
    Run.create [
      Run.text hexText
      Run.foreground model.Theme.Text.Primary
    ]
    Run.create [ Run.text asciiGapText ]
    Run.create [
      Run.text asciiText
      Run.foreground model.Theme.Text.Secondary
    ]
  ]

let private hexTextRangeLength count =
  if count <= 0 then 0
  else count * 3 - 1

let private brushOfColor =
  let cache = Dictionary<string, IBrush>()
  fun color ->
    match cache.TryGetValue color with
    | true, brush -> brush
    | _ ->
      let brush = Brush.Parse color
      cache[color] <- brush
      brush

let private rowHighlightRanges hexStart asciiStart segments =
  (segments: RowHighlightSegment list)
  |> List.collect (fun segment ->
    let hexLength = hexTextRangeLength segment.Length
    let brush = brushOfColor segment.Background
    let hexRange: TextHighlightRange =
      { Start = hexStart + segment.StartOffset * 3
        Length = hexLength
        Brush = brush }
    let asciiRange: TextHighlightRange =
      { Start = asciiStart + segment.StartOffset
        Length = segment.Length
        Brush = brush }
    [ hexRange; asciiRange ]
  )

let private addSegs buckets startRow endRow width spanStart spanEnd background =
  let buckets: List<_> array = buckets
  if spanStart < spanEnd then
    let firstRow = int (spanStart / width)
    let lastRow = int ((spanEnd - 1L) / width)
    for rowIdx in max startRow firstRow .. min (endRow - 1) lastRow do
      let rowStart = int64 rowIdx * width
      let segStart = max rowStart spanStart
      let segEnd = min (rowStart + width) spanEnd
      let count = int (segEnd - segStart)
      if count > 0 then
        buckets[rowIdx - startRow].Add
          { StartOffset = int (segStart - rowStart)
            Length = count
            Background = background }
      else
        ()
  else
    ()

let private addSpan model buckets startRow endRow width visStart visEnd span =
  if (span: HexSpanStyle).Length > 0L then
    let spanStart = max visStart span.Start
    let spanEnd = min visEnd (span.Start + span.Length)
    let bg =
      span.Background
      |> Option.defaultValue model.Theme.Search.SelectedBackground
    addSegs buckets startRow endRow width spanStart spanEnd bg
  else
    ()

let private addSelectionHighlight model buckets startRow endRow rowWidth sel =
  let selStart, selEnd = selectionRange sel
  let background = model.Theme.Search.SelectedBackground
  addSegs buckets startRow endRow rowWidth selStart (selEnd + 1L) background

let private rowTextBlock model layout (textRuns: IView list) highlightRanges =
  HexdumpRowTextBlock.create [
    Canvas.left 0.0
    Canvas.top 0.0
    TextBlock.width layout.LineWidth
    TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
    TextBlock.fontSize model.Theme.Font.Monospace.FontSize
    TextBlock.inlines textRuns
    HexdumpRowTextBlock.Highlight highlightRanges
    TextBlock.isHitTestVisible false
  ]

let private sliceHighlights model bytesPerRow startRow endRow state =
  let visibleRowCount = max 0 (endRow - startRow)
  let buckets = Array.init visibleRowCount (fun _ -> ResizeArray<_>())
  let rowWidth = int64 (max 1 bytesPerRow)
  let visStart = int64 startRow * rowWidth
  let visEnd = int64 endRow * rowWidth
  let spans =
    state.HighlightSpans |> List.sortByDescending (fun s -> s.Priority)
  for span in spans do
    addSpan model buckets startRow endRow rowWidth visStart visEnd span
  match state.Selection with
  | Some selection ->
    addSelectionHighlight model buckets startRow endRow rowWidth selection
  | None ->
    ()
  buckets
  |> Array.map (fun bucket -> bucket |> Seq.toList)

let private rowView model state doc segments bytesPerRow rowIdx rowBytes =
  let offset = rowIdx * bytesPerRow
  let numDigits = state.View.AddressDigits
  let layout = computeLayout state.View
  let address = formatAddress numDigits doc.BaseAddress offset
  let hexText = formatHexBytes rowBytes
  let asciiText = formatAscii rowBytes
  let addrGapText = gapText layout.CharWidth layout.AddressGap
  let asciiGapText = gapText layout.CharWidth layout.AsciiGap
  let hexStart = address.Length + addrGapText.Length
  let asciiStart = hexStart + hexText.Length + asciiGapText.Length
  let textRuns =
    rowTextRuns model address addrGapText hexText asciiGapText asciiText
  let highlightRanges = rowHighlightRanges hexStart asciiStart segments
  Border.create [
    Canvas.left 0.0
    Canvas.top (float rowIdx * layout.RowHeight)
    Border.height layout.RowHeight
    Border.padding (8.0, 1.0, 8.0, 1.0)
    Border.child (
      Canvas.create [
        Canvas.height layout.RowHeight
        Canvas.children [ rowTextBlock model layout textRuns highlightRanges ]
      ]
    )
  ] |> View.withKey $"hex-row-{rowIdx}" :> IView

let private computeTotalRows docLength bytesPerRow =
  if docLength <= 0L then 0
  else int ((docLength + int64 bytesPerRow - 1L) / int64 bytesPerRow)

let private sliceRowBytes (doc: HexDocument) bytesPerRow rowIdx =
  let offset = rowIdx * bytesPerRow
  let remaining = doc.Bytes.Length - offset
  let count = min bytesPerRow remaining
  Array.sub doc.Bytes offset count

let private computeVisibleRowRange (viewState: HexViewState) totalRows =
  if totalRows <= 0 then
    0, 0
  else
    let rowHeight = max viewState.RowHeight 1.0
    let visibleRows =
      max 1 (int (ceil (viewState.ViewportHeight / rowHeight)))
    let scrollRow = int (floor (viewState.ScrollOffsetY / rowHeight))
    let startRow = max 0 (scrollRow - OverscanRows)
    let endRow = min totalRows (scrollRow + visibleRows + OverscanRows)
    startRow, endRow

let private emptyStateView model =
  TextBlock.create [
    TextBlock.text "No bytes loaded."
    TextBlock.margin 10.0
    TextBlock.foreground model.Theme.Text.Muted
    TextBlock.fontSize 13.0
  ]

let private bodyView model dispatch =
  match model.ActiveTab with
  | Some { Content = HexContent state } ->
    let viewState, doc = state.View, state.Document
    let bytesPerRow = max 1 viewState.BytesPerRow
    let totalRows = computeTotalRows doc.Length bytesPerRow
    let startRow, endRow = computeVisibleRowRange viewState totalRows
    let visibleRowHighlights =
      sliceHighlights model bytesPerRow startRow endRow state
    let layout = computeLayout viewState
    let canvasHeight = layout.RowHeight * float totalRows
    let scrollOffsetY = viewState.ScrollOffsetY
    ScrollViewer.create [
      ScrollViewer.offset (Vector(0.0, scrollOffsetY))
      ScrollViewer.onScrollChanged (onScrollChanged dispatch)
      ScrollViewer.content (
        HexdumpInteractionCanvas.create [
          HexdumpInteractionCanvas.State(Some state)
          HexdumpInteractionCanvas.Dispatch dispatch
          Canvas.background model.Theme.Common.Transparent
          Canvas.height canvasHeight
          Canvas.children [
            for rowIdx in startRow .. endRow - 1 do
              let rowBytes = sliceRowBytes doc bytesPerRow rowIdx
              let rowHighlights = visibleRowHighlights[rowIdx - startRow]
              rowView model state doc rowHighlights bytesPerRow rowIdx rowBytes
          ]
        ]
      )
    ]
    |> View.withKey "hexdump-scroll" :> IView
  | _ ->
    emptyStateView model :> IView

let view model dispatch =
  Border.create [
    Border.background model.Theme.Window.Background
    Border.borderThickness 0.0
    Border.child (bodyView model dispatch)
  ]
