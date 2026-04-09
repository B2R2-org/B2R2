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
module B2R2.RearEnd.BinExplore.GUI.HexContent

open System
open System.Collections.Generic
open Avalonia
open Avalonia.Controls
open Avalonia.Controls.Primitives
open Avalonia.FuncUI.Builder
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types
open Avalonia.Media

let [<Literal>] private OverscanRows = 12

type private RowHighlightSegment =
  { StartOffset: int
    Length: int
    Background: string }

type private CachedRowVisual =
  { Address: FormattedText
    Hex: FormattedText
    Ascii: FormattedText }

type private HexviewLayout =
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

let private byteToAscii b =
  if b >= 0x20uy && b <= 0x7Euy then char b
  else '.'

let private formatHexString bytes =
  bytes |> Array.map (fun b -> $"{b:X2}") |> String.concat ""

let private formatEscapedHexString bytes =
  bytes |> Array.map (fun b -> $"\\x{b:X2}") |> String.concat ""

let private formatAsciiString bytes =
  bytes |> Array.map byteToAscii |> String

let private tryGetHostTopLevel (source: obj) =
  match source with
  | :? Control as control ->
    match TopLevel.GetTopLevel control with
    | :? PopupRoot as popup when not (isNull popup.ParentTopLevel) ->
      popup.ParentTopLevel
    | topLevel ->
      topLevel
  | _ ->
    null

let private tryGetSelectionBytes state =
  match state.Selection with
  | Some selection ->
    let startByte = min selection.Anchor selection.Caret
    let endByte = max selection.Anchor selection.Caret
    let offset = int startByte
    let count = int (endByte - startByte + 1L)
    let docLength = state.Document.Bytes.Length
    if count > 0 && offset >= 0 && offset + count <= docLength then
      Some(Array.sub state.Document.Bytes offset count)
    else
      None
  | None ->
    None

let private copySelection formatBytes dispatch source state =
  match tryGetSelectionBytes state with
  | Some bytes ->
    let topLevel = tryGetHostTopLevel source
    if isNull topLevel then
      dispatch (UpdateStatusMsg "Clipboard is unavailable.")
    else
      Async.StartImmediate(async {
        try
          let text = formatBytes bytes
          do! topLevel.Clipboard.SetTextAsync text |> Async.AwaitTask
        with ex ->
          dispatch (UpdateStatusMsg $"Failed to copy bytes: {ex.Message}")
      })
  | None ->
    ()

type private HexdumpInteractionCanvas() as this =
  inherit Canvas()

  let mutable pressedByte = None
  let mutable pendingSelectionToggle = None
  let copyHexMenuItem = MenuItem(Header = "Copy Hex")
  let copyEscapedHexMenuItem = MenuItem(Header = "Copy Escaped Hex")
  let copyAsciiMenuItem = MenuItem(Header = "Copy ASCII")
  let ctxMenu = ContextMenu()

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

  let tryGetColumn shouldClamp paddingX left width cellWidth maxCol x =
    let localX = x - paddingX
    let columnX = localX - left
    let columnX = clampIfNeeded shouldClamp 0.0 width columnX
    if columnX < 0.0 || columnX > width then
      None
    else
      let col = int64 (floor (columnX / cellWidth))
      let col = clampIfNeeded shouldClamp 0L maxCol col
      if col < 0L || col > maxCol then None else Some col

  let tryGetHexColumn shouldClamp (layout: HexviewLayout) x =
    let maxCol = int64 (layout.BytesPerRow - 1)
    let paddingX, left, width = layout.PaddingX, layout.HexLeft, layout.HexWidth
    tryGetColumn shouldClamp paddingX left width layout.HexCellWidth maxCol x

  let tryGetAsciiColumn shouldClamp (layout: HexviewLayout) x =
    let maxCol = int64 (layout.BytesPerRow - 1)
    let paddingX = layout.PaddingX
    let left, width = layout.AsciiLeft, layout.AsciiWidth
    tryGetColumn shouldClamp paddingX left width layout.CharWidth maxCol x

  let tryGetColumnAtPoint shouldClamp (layout: HexviewLayout) x =
    let localX = x - layout.PaddingX
    let hexRight = layout.HexLeft + layout.HexWidth
    let asciiRight = layout.AsciiLeft + layout.AsciiWidth
    let gapMid = hexRight + ((layout.AsciiLeft - hexRight) / 2.0)
    if localX < layout.HexLeft then
      if shouldClamp then tryGetHexColumn true layout x else None
    elif localX <= hexRight then
      tryGetHexColumn shouldClamp layout x
    elif localX < layout.AsciiLeft then
      if shouldClamp then
        if localX < gapMid then tryGetHexColumn true layout x
        else tryGetAsciiColumn true layout x
      else
        None
    elif localX <= asciiRight then
      tryGetAsciiColumn shouldClamp layout x
    elif shouldClamp then
      tryGetAsciiColumn true layout x
    else
      None

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
      let rowWidth = int64 layout.BytesPerRow
      let totalRows = int ((doc.Length + rowWidth - 1L) / rowWidth)
      let maxRow = int64 totalRows - 1L
      match tryGetRow shouldClamp maxRow layout.RowHeight y with
      | None ->
        None
      | Some row ->
        match tryGetColumnAtPoint shouldClamp layout x with
        | None ->
          None
        | Some col ->
          tryGetByteIndex doc.Length layout.BytesPerRow shouldClamp row col

  let openContextMenu () =
    match this.CurrentState with
    | Some state ->
      let isEnabled = state.Selection.IsSome
      copyHexMenuItem.IsEnabled <- isEnabled
      copyEscapedHexMenuItem.IsEnabled <- isEnabled
      copyAsciiMenuItem.IsEnabled <- isEnabled
      ctxMenu.Open this |> ignore
    | None ->
      ()

  let copyCurrentSelection formatBytes =
    match this.CurrentState with
    | Some state -> copySelection formatBytes this.Dispatcher this state
    | None -> ()

  do
    copyHexMenuItem.Click.Add(fun _ -> copyCurrentSelection formatHexString)
    copyEscapedHexMenuItem.Click.Add(fun _ ->
      copyCurrentSelection formatEscapedHexString
    )
    copyAsciiMenuItem.Click.Add(fun _ -> copyCurrentSelection formatAsciiString)
    ctxMenu.ItemsSource <-
      [| copyHexMenuItem
         copyEscapedHexMenuItem
         copyAsciiMenuItem |]
    this.ContextMenu <- ctxMenu

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
      let props = e.GetCurrentPoint(this).Properties
      match tryGetByteIndexAtPoint state false p.X p.Y with
      | Some byteIndex ->
        if props.IsRightButtonPressed then
          pressedByte <- None
          pendingSelectionToggle <- None
          if isByteSelected state byteIndex then
            openContextMenu ()
            e.Handled <- true
          else
            this.DispatchHexdump(StartSelection byteIndex)
            this.DispatchHexdump(EndSelection)
            e.Handled <- true
        else
          pressedByte <- Some byteIndex
          e.Pointer.Capture this
          if isByteSelected state byteIndex then
            pendingSelectionToggle <- Some byteIndex
          else
            pendingSelectionToggle <- None
            this.DispatchHexdump(StartSelection byteIndex)
          e.Handled <- true
      | None ->
        if props.IsRightButtonPressed then e.Handled <- true else ()
    | None ->
      ()

  override this.OnPointerMoved e =
    base.OnPointerMoved e
    match this.CurrentState with
    | Some state ->
      let p = e.GetPosition this
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
      pressedByte <- None
      pendingSelectionToggle <- None
      e.Pointer.Capture null
      e.Handled <- true
    | _ ->
      pressedByte <- None
      pendingSelectionToggle <- None
      ()

  override _.OnPointerExited e =
    base.OnPointerExited e
    ()

[<RequireQualifiedAccess>]
module private HexdumpInteractionCanvas =
  let create (attrs: IAttr<HexdumpInteractionCanvas> list) =
    View.createGeneric<HexdumpInteractionCanvas> attrs

let private onScrollChanged dispatch (args: ScrollChangedEventArgs) =
  let deltaY = args.OffsetDelta.Y
  let currentOffsetY =
    match args.Source with
    | :? ScrollViewer as scrollViewer ->
      scrollViewer.Offset.Y
    | _ ->
      Double.NaN
  dispatch (HexdumpMsg(HandleScrollChanged(currentOffsetY, deltaY)))

let private formatAddress digits baseAddress offset =
  let addr = baseAddress + uint64 offset
  let txt = addr.ToString("X").PadLeft(digits, '0')
  $"0x{txt}"

let private hexDigit value =
  if value < 10 then char (int '0' + value)
  else char (int 'A' + value - 10)

let private formatRowTexts (doc: HexDocument) bytesPerRow rowIdx =
  let offset = rowIdx * bytesPerRow
  let remaining = doc.Bytes.Length - offset
  let count = min bytesPerRow remaining
  let hexChars =
    if count > 0 then Array.create (count * 3 - 1) ' ' else Array.empty
  let asciiChars = Array.create count '.'
  for i = 0 to count - 1 do
    let byteValue = int doc.Bytes[offset + i]
    let hexPos = i * 3
    hexChars[hexPos] <- hexDigit (byteValue >>> 4)
    hexChars[hexPos + 1] <- hexDigit (byteValue &&& 0xF)
    asciiChars[i] <- byteToAscii doc.Bytes[offset + i]
  String hexChars, String asciiChars

let private selectionRange selection =
  min selection.Anchor selection.Caret, max selection.Anchor selection.Caret

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

let private addSpan theme buckets startRow endRow width visStart visEnd span =
  if (span: HexSpanStyle).Length > 0L then
    let spanStart = max visStart span.Start
    let spanEnd = min visEnd (span.Start + span.Length)
    let bg =
      span.Background
      |> Option.defaultValue theme.Search.SelectedBackground
    addSegs buckets startRow endRow width spanStart spanEnd bg
  else
    ()

let private addSelectionHighlight theme buckets startRow endRow rowWidth sel =
  let selStart, selEnd = selectionRange sel
  let background = theme.Search.SelectedBackground
  addSegs buckets startRow endRow rowWidth selStart (selEnd + 1L) background

let private addSpans theme buckets startRow endRow rowWidth spans =
  let visStart = int64 startRow * rowWidth
  let visEnd = int64 endRow * rowWidth
  let spans =
    spans |> List.sortByDescending (fun (s: HexSpanStyle) -> s.Priority)
  for span in spans do
    addSpan theme buckets startRow endRow rowWidth visStart visEnd span

let private collectBuckets buckets =
  buckets |> Array.map (fun bucket -> bucket |> Seq.toList)

let private buildAnnotationRows theme docLength bytesPerRow spans =
  let totalRows =
    if docLength <= 0L then 0
    else int ((docLength + int64 bytesPerRow - 1L) / int64 bytesPerRow)
  if totalRows <= 0 || List.isEmpty spans then
    [||]
  else
    let buckets = Array.init totalRows (fun _ -> ResizeArray<_>())
    let rowWidth = int64 (max 1 bytesPerRow)
    addSpans theme buckets 0 totalRows rowWidth spans
    collectBuckets buckets

let private sliceTransientHighlights theme layout startRow endRow state =
  let bytesPerRow = layout.BytesPerRow
  let visibleRowCount = max 0 (endRow - startRow)
  let buckets = Array.init visibleRowCount (fun _ -> ResizeArray<_>())
  let rowWidth = int64 (max 1 bytesPerRow)
  addSpans theme buckets startRow endRow rowWidth state.HighlightSpans
  match state.Selection with
  | Some selection ->
    addSelectionHighlight theme buckets startRow endRow rowWidth selection
  | None ->
    ()
  collectBuckets buckets

let private expandRowRangeWithOverscan totalRows (startRow, endRow) =
  max 0 (startRow - OverscanRows),
  min totalRows (endRow + OverscanRows)

type private HexdumpRenderLayer() =
  inherit Control()

  let rowCache = Dictionary<int, CachedRowVisual>()
  let mutable cachedBytes: byte[] = null
  let mutable cachedBytesPerRow = 0
  let mutable cachedAddressDigits = 0
  let mutable cachedFontFamily = ""
  let mutable cachedFontSize = 0.0
  let mutable cachedAddressColor = ""
  let mutable cachedPrimaryColor = ""
  let mutable cachedSecondaryColor = ""
  let mutable cachedAnnotationBytes: byte[] = null
  let mutable cachedAnnotationSpans: HexSpanStyle list = []
  let mutable cachedAnnotationBytesPerRow = 0
  let mutable cachedAnnotationFallback = ""
  let mutable cachedAnnotationRows: RowHighlightSegment list array = [||]

  let clearRowCache () =
    rowCache.Clear()

  let makeFormattedText typeface fontSize brush text =
    FormattedText(
      text,
      Globalization.CultureInfo.CurrentCulture,
      FlowDirection.LeftToRight,
      typeface,
      fontSize,
      brush
    )

  let ensureCacheSignature (state: HexdumpState) (theme: Theme) =
    let view = state.View
    let fontFamily = theme.Font.Monospace.FontFamily
    let fontSize = theme.Font.Monospace.FontSize
    let cacheInvalid =
      not (obj.ReferenceEquals(cachedBytes, state.Document.Bytes))
      || cachedBytesPerRow <> view.BytesPerRow
      || cachedAddressDigits <> view.AddressDigits
      || cachedFontFamily <> fontFamily
      || cachedFontSize <> fontSize
      || cachedAddressColor <> theme.Text.Address
      || cachedPrimaryColor <> theme.Text.Primary
      || cachedSecondaryColor <> theme.Text.Secondary
    if cacheInvalid then
      clearRowCache ()
      cachedBytes <- state.Document.Bytes
      cachedBytesPerRow <- view.BytesPerRow
      cachedAddressDigits <- view.AddressDigits
      cachedFontFamily <- fontFamily
      cachedFontSize <- fontSize
      cachedAddressColor <- theme.Text.Address
      cachedPrimaryColor <- theme.Text.Primary
      cachedSecondaryColor <- theme.Text.Secondary
    else
      ()
    Typeface(FontFamily fontFamily), fontSize

  let ensureAnnotationCache (state: HexdumpState) theme layout =
    let cacheInvalid =
      not (obj.ReferenceEquals(cachedAnnotationBytes, state.Document.Bytes))
      || not (obj.ReferenceEquals(box cachedAnnotationSpans,
                                  box state.AnnotationSpans))
      || cachedAnnotationBytesPerRow <> layout.BytesPerRow
      || cachedAnnotationFallback <> theme.Search.SelectedBackground
    if cacheInvalid then
      cachedAnnotationBytes <- state.Document.Bytes
      cachedAnnotationSpans <- state.AnnotationSpans
      cachedAnnotationBytesPerRow <- layout.BytesPerRow
      cachedAnnotationFallback <- theme.Search.SelectedBackground
      cachedAnnotationRows <-
        buildAnnotationRows theme state.Document.Length
                            layout.BytesPerRow state.AnnotationSpans
    else
      ()
    cachedAnnotationRows

  let pruneRowCache startRow endRow =
    let minKeep = max 0 (startRow - OverscanRows * 2)
    let maxKeep = endRow + OverscanRows * 2
    rowCache.Keys
    |> Seq.toArray
    |> Array.iter (fun rowIdx ->
      if rowIdx < minKeep || rowIdx > maxKeep then
        rowCache.Remove rowIdx |> ignore
      else ())

  let getOrCreateRowVisual state theme layout typeface fontSize rowIdx =
    match rowCache.TryGetValue rowIdx with
    | true, cached -> cached
    | _ ->
      let offset = rowIdx * layout.BytesPerRow
      let address =
        formatAddress state.View.AddressDigits state.Document.BaseAddress offset
      let hexText, asciiText =
        formatRowTexts state.Document layout.BytesPerRow rowIdx
      let cached =
        { Address =
            makeFormattedText
              typeface fontSize (brushOfColor theme.Text.Address) address
          Hex =
            makeFormattedText
              typeface fontSize (brushOfColor theme.Text.Primary) hexText
          Ascii =
            makeFormattedText
              typeface fontSize (brushOfColor theme.Text.Primary) asciiText }
      rowCache[rowIdx] <- cached
      cached

  let drawHighlightRow (ctx: DrawingContext) layout rowTop brush segment =
    let txtTop = rowTop + 1.0
    let txtHeight = max 1.0 (layout.RowHeight - 2.0)
    let hexX =
      layout.PaddingX + layout.HexLeft
      + float (segment.StartOffset * 3) * layout.CharWidth
    let hexWidth = float (hexTextRangeLength segment.Length) * layout.CharWidth
    let asciiX =
      layout.PaddingX + layout.AsciiLeft
      + float segment.StartOffset * layout.CharWidth
    let asciiWidth = float segment.Length * layout.CharWidth
    if hexWidth > 0.0 then
      ctx.FillRectangle(brush, Rect(hexX, txtTop, hexWidth, txtHeight))
    else ()
    if asciiWidth > 0.0 then
      ctx.FillRectangle(brush, Rect(asciiX, txtTop, asciiWidth, txtHeight))
    else ()

  let drawRow ctx state theme layout typeface fontSize startRow rowIdx segs =
    let rowTop = float (rowIdx - startRow) * layout.RowHeight
    let cached =
      getOrCreateRowVisual state theme layout typeface fontSize rowIdx
    for seg in segs do
      drawHighlightRow ctx layout rowTop (brushOfColor seg.Background) seg
    ctx.DrawText(cached.Address, Point(layout.PaddingX, rowTop + 1.0))
    ctx.DrawText(
      cached.Hex,
      Point(layout.PaddingX + layout.HexLeft, rowTop + 1.0)
    )
    ctx.DrawText(
      cached.Ascii,
      Point(layout.PaddingX + layout.AsciiLeft, rowTop + 1.0)
    )

  static let stateProperty =
    AvaloniaProperty.Register<HexdumpRenderLayer, HexdumpState option>(
      nameof Unchecked.defaultof<HexdumpRenderLayer>.CurrentState, None
    )

  static let themeProperty =
    AvaloniaProperty.Register<HexdumpRenderLayer, Theme>(
      nameof Unchecked.defaultof<HexdumpRenderLayer>.CurrentTheme,
      Unchecked.defaultof<Theme>
    )

  static let startRowProperty =
    AvaloniaProperty.Register<HexdumpRenderLayer, int>(
      nameof Unchecked.defaultof<HexdumpRenderLayer>.RenderStartRow, 0
    )

  static let endRowProperty =
    AvaloniaProperty.Register<HexdumpRenderLayer, int>(
      nameof Unchecked.defaultof<HexdumpRenderLayer>.RenderEndRow, 0
    )

  static member StateProperty = stateProperty
  static member ThemeProperty = themeProperty
  static member StartRowProperty = startRowProperty
  static member EndRowProperty = endRowProperty

  static member State value =
    AttrBuilder<'t>.CreateProperty<HexdumpState option>(
      HexdumpRenderLayer.StateProperty, value, ValueNone
    )

  static member Theme value =
    AttrBuilder<'t>.CreateProperty<Theme>(
      HexdumpRenderLayer.ThemeProperty, value, ValueNone
    )

  static member StartRow value =
    AttrBuilder<'t>.CreateProperty<int>(
      HexdumpRenderLayer.StartRowProperty, value, ValueNone
    )

  static member EndRow value =
    AttrBuilder<'t>.CreateProperty<int>(
      HexdumpRenderLayer.EndRowProperty, value, ValueNone
    )

  member this.CurrentState
    with get() = this.GetValue stateProperty
    and set value = this.SetValue(stateProperty, value) |> ignore

  member this.CurrentTheme
    with get() = this.GetValue themeProperty
    and set value = this.SetValue(themeProperty, value) |> ignore

  member this.RenderStartRow
    with get() = this.GetValue startRowProperty
    and set value = this.SetValue(startRowProperty, value) |> ignore

  member this.RenderEndRow
    with get() = this.GetValue endRowProperty
    and set value = this.SetValue(endRowProperty, value) |> ignore

  override this.OnPropertyChanged change =
    base.OnPropertyChanged change
    if change.Property = stateProperty
      || change.Property = themeProperty
      || change.Property = startRowProperty
      || change.Property = endRowProperty then
      this.InvalidateVisual()
    else ()

  override this.Render(ctx: DrawingContext) =
    base.Render ctx
    try
      match this.CurrentState with
      | Some state when not (isNull (box this.CurrentTheme))
                   && this.RenderEndRow > this.RenderStartRow ->
        let theme = this.CurrentTheme
        let layout = computeLayout state.View
        let startRow = this.RenderStartRow
        let endRow = this.RenderEndRow
        let annotationRows = ensureAnnotationCache state theme layout
        let transientRows =
          sliceTransientHighlights theme layout startRow endRow state
        let typeface, fontSize = ensureCacheSignature state theme
        pruneRowCache startRow endRow
        for rowIdx in startRow .. endRow - 1 do
          let annotationHighlights =
            if rowIdx < annotationRows.Length then annotationRows[rowIdx]
            else []
          let transientHighlights = transientRows[rowIdx - startRow]
          let rowHighlights =
            List.append annotationHighlights transientHighlights
          drawRow ctx state theme layout typeface fontSize
                  startRow rowIdx rowHighlights
      | _ ->
        ()
    with ex ->
      let fallback =
        FormattedText(
          $"Hexdump render failed: {ex.Message}",
          Globalization.CultureInfo.CurrentCulture,
          FlowDirection.LeftToRight,
          Typeface("Consolas", FontStyle.Normal, FontWeight.Normal,
                   FontStretch.Normal),
          12.0,
          Brushes.Red
        )
      ctx.DrawText(fallback, Point(8.0, 8.0))

[<RequireQualifiedAccess>]
module private HexdumpRenderLayer =
  let create (attrs: IAttr<HexdumpRenderLayer> list) =
    View.createGeneric<HexdumpRenderLayer> attrs

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
    let totalRows = HexdumpState.computeTotalRows doc.Length bytesPerRow
    let startRow, endRow =
      HexdumpState.computeViewportRowRange viewState totalRows
      |> expandRowRangeWithOverscan totalRows
    let layout = computeLayout viewState
    let canvasWidth = layout.PaddingX * 2.0 + layout.LineWidth
    let canvasHeight = layout.RowHeight * float totalRows
    let renderTop = float startRow * layout.RowHeight
    let renderHeight = float (max 0 (endRow - startRow)) * layout.RowHeight
    let scrollOffsetY = viewState.ScrollOffsetY
    ScrollViewer.create [
      ScrollViewer.onScrollChanged (onScrollChanged dispatch)
      ScrollViewer.content (
        HexdumpInteractionCanvas.create [
          HexdumpInteractionCanvas.State(Some state)
          HexdumpInteractionCanvas.Dispatch dispatch
          Canvas.background model.Theme.Common.Transparent
          Canvas.width canvasWidth
          Canvas.height canvasHeight
          Canvas.children [
            HexdumpRenderLayer.create [
              Canvas.left 0.0
              Canvas.top renderTop
              Control.width canvasWidth
              Control.height renderHeight
              Control.isHitTestVisible false
              HexdumpRenderLayer.State(Some state)
              HexdumpRenderLayer.Theme model.Theme
              HexdumpRenderLayer.StartRow startRow
              HexdumpRenderLayer.EndRow endRow
            ]
          ]
        ]
      )
      ScrollViewer.offset (Vector(0.0, scrollOffsetY))
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
