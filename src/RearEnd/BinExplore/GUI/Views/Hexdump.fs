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

let private rowBackground model rowStart rowLength selection =
  match selection with
  | Some sel ->
    let selStart, selEnd = selectionRange sel
    let rowEnd = rowStart + int64 rowLength - 1L
    if selStart <= rowEnd && rowStart <= selEnd then
      model.Theme.Search.SelectedBackground
    else
      model.Theme.Common.Transparent
  | None ->
    model.Theme.Common.Transparent

let private gapText charWidth gap =
  let spaces = max 1 (int (round (gap / max charWidth 1.0)))
  String.replicate spaces " "

let private rowTextRuns model addr addrGapText hexText asciiGapText asciiText =
  [ Run.create [
      Run.text addr
      Run.foreground model.Theme.Text.Address
    ] :> IView
    Run.create [
      Run.text addrGapText
    ] :> IView
    Run.create [
      Run.text hexText
      Run.foreground model.Theme.Text.Primary
    ] :> IView
    Run.create [
      Run.text asciiGapText
    ] :> IView
    Run.create [
      Run.text asciiText
      Run.foreground model.Theme.Text.Secondary
    ] :> IView ]

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

let private rowHighlightRanges hexStart asciiStart
    (segments: RowHighlightSegment list) =
  segments
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
    [ hexRange; asciiRange ])

let private sliceHighlights model bytesPerRow startRow endRow state =
  let visibleRowCount = max 0 (endRow - startRow)
  let rowBuckets = Array.init visibleRowCount (fun _ -> ResizeArray<_>())
  let rowWidth = int64 (max 1 bytesPerRow)
  let visibleStart = int64 startRow * rowWidth
  let visibleEnd = int64 endRow * rowWidth
  let highlights = state.HighlightSpans
  let addSegment rowIdx segment = rowBuckets[rowIdx - startRow].Add segment
  for span in highlights |> List.sortByDescending (fun s -> s.Priority) do
    if span.Length > 0L then
      let spanStart = max visibleStart span.Start
      let spanEnd = min visibleEnd (span.Start + span.Length)
      if spanStart < spanEnd then
        let firstRow = int (spanStart / rowWidth)
        let lastRow = int ((spanEnd - 1L) / rowWidth)
        let background =
          span.Background
          |> Option.defaultValue model.Theme.Search.SelectedBackground
        for rowIdx in max startRow firstRow .. min (endRow - 1) lastRow do
          let rowStart = int64 rowIdx * rowWidth
          let segStart = max rowStart spanStart
          let segEnd = min (rowStart + rowWidth) spanEnd
          let count = int (segEnd - segStart)
          if count > 0 then
            addSegment rowIdx
              { StartOffset = int (segStart - rowStart)
                Length = count
                Background = background }
  rowBuckets
  |> Array.map (fun bucket -> bucket |> Seq.toList)

let private rowView model state doc segments bytesPerRow rowIdx rowBytes =
  let offset = rowIdx * bytesPerRow
  let rowStart = int64 offset
  let numDigits = state.View.AddressDigits
  let charWidth = max state.View.CharWidth 1.0
  let rowHeight = max state.View.RowHeight 1.0
  let addressWidth = charWidth * float (numDigits + 2)
  let addressGap = 8.0
  let hexWidth = charWidth * float (max 0 (bytesPerRow * 3 - 1))
  let asciiGap = 12.0
  let asciiWidth = charWidth * float bytesPerRow
  let hexLeft = addressWidth + addressGap
  let asciiLeft = hexLeft + hexWidth + asciiGap
  let address = formatAddress numDigits doc.BaseAddress offset
  let hexText = formatHexBytes rowBytes
  let asciiText = formatAscii rowBytes
  let addrGapText = gapText charWidth addressGap
  let asciiGapText = gapText charWidth asciiGap
  let lineWidth = asciiLeft + asciiWidth
  let hexStart = address.Length + addrGapText.Length
  let asciiStart = hexStart + hexText.Length + asciiGapText.Length
  let textRuns =
    rowTextRuns model address addrGapText hexText asciiGapText asciiText
  let highlightRanges = rowHighlightRanges hexStart asciiStart segments
  Border.create [
    Canvas.left 0.0
    Canvas.top (float rowIdx * rowHeight)
    Border.height rowHeight
    Border.padding (8.0, 1.0, 8.0, 1.0)
    Border.background (
      rowBackground model rowStart rowBytes.Length state.Selection
    )
    Border.child (
      Canvas.create [
        Canvas.height rowHeight
        Canvas.children [
          HexdumpRowTextBlock.create [
            Canvas.left 0.0
            Canvas.top 0.0
            TextBlock.width lineWidth
            TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
            TextBlock.fontSize model.Theme.Font.Monospace.FontSize
            TextBlock.inlines textRuns
            HexdumpRowTextBlock.Highlight highlightRanges
            TextBlock.isHitTestVisible false
          ]
        ]
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

let private computeVisibleRowRange viewState totalRows =
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
    let rowHeight = max viewState.RowHeight 1.0
    let canvasHeight = rowHeight * float totalRows
    let scrollOffsetY = viewState.ScrollOffsetY
    ScrollViewer.create [
      ScrollViewer.offset (Vector(0.0, scrollOffsetY))
      ScrollViewer.onScrollChanged (onScrollChanged dispatch)
      ScrollViewer.content (
        Canvas.create [
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
