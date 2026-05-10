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
module B2R2.RearEnd.BinExplore.GUI.LinearContent

open System.Collections.Generic
open System.Globalization
open Avalonia
open Avalonia.Controls
open Avalonia.FuncUI.Builder
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types
open Avalonia.Media

let [<Literal>] private OverscanPixels = 240.0

let private onScrollChanged dispatch (args: ScrollChangedEventArgs) =
  let currentOffsetY =
    match args.Source with
    | :? ScrollViewer as scrollViewer -> scrollViewer.Offset.Y
    | _ -> System.Double.NaN
  dispatch (
    LinearPaneMsg(LinearPaneMessage.HandleScrollChanged(
      currentOffsetY, args.OffsetDelta.Y
    ))
  )

type private LinearLayoutMetrics =
  { PaddingX: float
    OffsetX: float
    AddressX: float
    KindX: float
    HexX: float
    AsciiX: float }

type private LinearCellKind =
  | OffsetCell
  | AddressCell
  | KindCell
  | ValueCell
  | AsciiCell

type private LinearTextRole =
  | PrimaryText
  | SecondaryText

type private LinearCell =
  { Kind: LinearCellKind
    Text: string
    Role: LinearTextRole }

type private LinearRowVisualModel =
  | Cells of LinearCell list
  | FullWidthHeader of title: string

type private CachedRowVisual =
  | CellRowVisual of cells: (LinearCellKind * FormattedText) list
  | FullWidthHeaderVisual of title: FormattedText

let private addressDigits (doc: LinearDocument) =
  let maxAddr =
    if doc.LinearTotalLength <= 0L then
      doc.LinearBaseAddress
    else
      doc.LinearBaseAddress + uint64 (doc.LinearTotalLength - 1L)
  max 1 (maxAddr.ToString("X").Length)

let private offsetDigits (doc: LinearDocument) =
  let maxOffset =
    if doc.LinearTotalLength <= 0L then 0L
    else doc.LinearTotalLength - 1L
  max 1 (maxOffset.ToString("X").Length)

let private computeLayoutMetrics doc (state: LinearViewState) =
  let charWidth = max state.CharWidth 1.0
  let paddingX = 10.0
  let offsetWidth = charWidth * float (offsetDigits doc + 6)
  let addrWidth = charWidth * float (addressDigits doc + 2)
  let offsetX = paddingX
  let addressX = offsetX + offsetWidth + charWidth * 2.0
  let kindX = addressX + addrWidth + charWidth * 2.0
  let kindWidth = charWidth * 3.0
  let hexX = kindX + kindWidth + charWidth * 2.0
  let asciiX = hexX + charWidth * 4.0
  { PaddingX = paddingX
    OffsetX = offsetX
    AddressX = addressX
    KindX = kindX
    HexX = hexX
    AsciiX = asciiX }

let private cellX layout = function
  | OffsetCell -> layout.OffsetX
  | AddressCell -> layout.AddressX
  | KindCell -> layout.KindX
  | ValueCell -> layout.HexX
  | AsciiCell -> layout.AsciiX

let private asciiOfByte value =
  if value >= 0x20uy && value <= 0x7Euy then string (char value)
  else "."

let private toRowVisualModel = function
  | RawByte(loc, value) ->
    Cells [
      { Kind = OffsetCell
        Text = $"off+0x{loc.Offset:X}"
        Role = SecondaryText }
      { Kind = AddressCell
        Text = $"0x{loc.Address:X}"
        Role = PrimaryText }
      { Kind = KindCell
        Text = "(b)"
        Role = SecondaryText }
      { Kind = ValueCell
        Text = $"{value:X2}"
        Role = PrimaryText }
      { Kind = AsciiCell
        Text = asciiOfByte value
        Role = SecondaryText }
    ]
  | SectionHeader(_, name, _) ->
    FullWidthHeader $"Section {name}"

type private LinearRenderLayer() =
  inherit Control()

  let textCache = Dictionary<int, CachedRowVisual>()
  let mutable lastFontFamily = ""
  let mutable lastFontSize = 0.0
  let mutable lastForeground = ""
  let mutable lastSecondary = ""

  let clearCache () =
    textCache.Clear()

  let makeFormattedText fontFamily fontSize foreground text =
    FormattedText(
      text,
      CultureInfo.CurrentCulture,
      FlowDirection.LeftToRight,
      Typeface(FontFamily fontFamily),
      fontSize,
      Brush.Parse foreground
    )

  let ensureCacheSignature (state: LinearViewState) theme =
    let fontFamily = theme.Font.Monospace.FontFamily
    let fontSize = state.FontSize
    let foreground = theme.Text.Primary
    let secondary = theme.Text.Secondary
    if lastFontFamily <> fontFamily
       || lastFontSize <> fontSize
       || lastForeground <> foreground
       || lastSecondary <> secondary then
      clearCache ()
      lastFontFamily <- fontFamily
      lastFontSize <- fontSize
      lastForeground <- foreground
      lastSecondary <- secondary
    else
      ()
    fontFamily, fontSize, foreground, secondary

  let textColor foreground secondary = function
    | PrimaryText -> foreground
    | SecondaryText -> secondary

  let getOrCreateText doc state theme index =
    match textCache.TryGetValue index with
    | true, txt -> txt
    | _ ->
      let item = doc.LinearItems[index]
      let fontFamily, fontSize, foreground, secondary =
        ensureCacheSignature state theme
      let txt =
        match toRowVisualModel item with
        | Cells cells ->
          cells
          |> List.map (fun cell ->
            let color = textColor foreground secondary cell.Role
            cell.Kind,
            makeFormattedText fontFamily fontSize color cell.Text)
          |> CellRowVisual
        | FullWidthHeader title ->
          FullWidthHeaderVisual(
            makeFormattedText
              fontFamily
              (LinearViewState.sectionHeaderFontSize fontSize)
              foreground
              title
          )
      textCache[index] <- txt
      txt

  static let docProperty =
    AvaloniaProperty.Register<LinearRenderLayer, LinearDocument option>(
      nameof Unchecked.defaultof<LinearRenderLayer>.CurrentDocument, None
    )

  static let stateProperty =
    AvaloniaProperty.Register<LinearRenderLayer, LinearViewState option>(
      nameof Unchecked.defaultof<LinearRenderLayer>.CurrentState, None
    )

  static let themeProperty =
    AvaloniaProperty.Register<LinearRenderLayer, Theme>(
      nameof Unchecked.defaultof<LinearRenderLayer>.CurrentTheme,
      Unchecked.defaultof<Theme>
    )

  static let startIndexProperty =
    AvaloniaProperty.Register<LinearRenderLayer, int>(
      nameof Unchecked.defaultof<LinearRenderLayer>.RenderStartIndex, 0
    )

  static let endIndexProperty =
    AvaloniaProperty.Register<LinearRenderLayer, int>(
      nameof Unchecked.defaultof<LinearRenderLayer>.RenderEndIndex, 0
    )

  static member DocumentProperty = docProperty
  static member StateProperty = stateProperty
  static member ThemeProperty = themeProperty
  static member StartIndexProperty = startIndexProperty
  static member EndIndexProperty = endIndexProperty

  member this.CurrentDocument
    with get() = this.GetValue docProperty
    and set value = this.SetValue(docProperty, value) |> ignore

  member this.CurrentState
    with get() = this.GetValue stateProperty
    and set value = this.SetValue(stateProperty, value) |> ignore

  member this.CurrentTheme
    with get() = this.GetValue themeProperty
    and set value = this.SetValue(themeProperty, value) |> ignore

  member this.RenderStartIndex
    with get() = this.GetValue startIndexProperty
    and set value = this.SetValue(startIndexProperty, value) |> ignore

  member this.RenderEndIndex
    with get() = this.GetValue endIndexProperty
    and set value = this.SetValue(endIndexProperty, value) |> ignore

  static member Document value =
    AttrBuilder<'t>.CreateProperty<LinearDocument option>(
      LinearRenderLayer.DocumentProperty, value, ValueNone
    )

  static member State value =
    AttrBuilder<'t>.CreateProperty<LinearViewState option>(
      LinearRenderLayer.StateProperty, value, ValueNone
    )

  static member Theme value =
    AttrBuilder<'t>.CreateProperty<Theme>(
      LinearRenderLayer.ThemeProperty, value, ValueNone
    )

  static member StartIndex value =
    AttrBuilder<'t>.CreateProperty<int>(
      LinearRenderLayer.StartIndexProperty, value, ValueNone
    )

  static member EndIndex value =
    AttrBuilder<'t>.CreateProperty<int>(
      LinearRenderLayer.EndIndexProperty, value, ValueNone
    )

  member _.DrawCellRow(ctx: DrawingContext, layout, rowTop, rowHeight, cells) =
    let textHeight =
      cells
      |> List.map (fun (_, txt: FormattedText) -> txt.Height)
      |> List.fold max 0.0
    let textY = rowTop + max 0.0 ((rowHeight - textHeight) / 2.0)
    for kind, txt in cells do
      ctx.DrawText(txt, Point(cellX layout kind, textY))

  member this.DrawFullWidthHeader(ctx, theme, layout, rowTop, rowHeight, txt) =
    let titleHeight = (txt: FormattedText).Height
    let titleY = rowTop + max 0.0 ((rowHeight - titleHeight) / 2.0)
    let headerBg = Brush.Parse theme.Panel.AltBackground
    let borderBrush = Brush.Parse theme.Panel.Border
    let borderPen = Pen(borderBrush, 1.0)
    (ctx: DrawingContext).FillRectangle(
      headerBg,
      Rect(0.0, rowTop, this.Bounds.Width, rowHeight)
    )
    ctx.DrawLine(
      borderPen,
      Point(layout.PaddingX, rowTop),
      Point(this.Bounds.Width - layout.PaddingX, rowTop)
    )
    ctx.DrawLine(
      borderPen,
      Point(layout.PaddingX, rowTop + rowHeight - 1.0),
      Point(this.Bounds.Width - layout.PaddingX, rowTop + rowHeight - 1.0)
    )
    ctx.DrawText(txt, Point(layout.PaddingX, titleY))

  override this.OnPropertyChanged change =
    base.OnPropertyChanged change
    if change.Property = stateProperty
       || change.Property = themeProperty
       || change.Property = startIndexProperty
       || change.Property = endIndexProperty then
      this.InvalidateVisual()
    else
      ()

  override this.Render(ctx: DrawingContext) =
    base.Render ctx
    match this.CurrentDocument, this.CurrentState with
    | Some doc, Some state when not (isNull (box this.CurrentTheme))
                             && this.RenderEndIndex > this.RenderStartIndex ->
      let theme = this.CurrentTheme
      let layout = computeLayoutMetrics doc state
      let renderTop = LinearViewState.itemTop state this.RenderStartIndex
      for i in this.RenderStartIndex .. this.RenderEndIndex - 1 do
        let rowTop = LinearViewState.itemTop state i - renderTop
        let rowHeight = LinearViewState.itemHeight state i
        let txt = getOrCreateText doc state theme i
        match txt with
        | CellRowVisual cells ->
          this.DrawCellRow(ctx, layout, rowTop, rowHeight, cells)
        | FullWidthHeaderVisual txt ->
          this.DrawFullWidthHeader(ctx, theme, layout, rowTop, rowHeight, txt)
    | _ ->
      ()

[<RequireQualifiedAccess>]
module private LinearRenderLayer =
  let create (attrs: IAttr<LinearRenderLayer> list) =
    View.createGeneric<LinearRenderLayer> attrs

let private visibleItemsView model doc (state: LinearViewState) =
  let startIdx, endIdxExclusive =
    LinearProjection.findVisibleRange OverscanPixels doc state
  let renderTop =
    if startIdx < endIdxExclusive then LinearViewState.itemTop state startIdx
    else 0.0
  let renderBottom =
    if startIdx < endIdxExclusive then
      let lastIndex = endIdxExclusive - 1
      LinearViewState.itemTop state lastIndex +
      LinearViewState.itemHeight state lastIndex
    else
      0.0
  let renderHeight = max 0.0 (renderBottom - renderTop)
  Canvas.create [
    Canvas.width (max state.ViewportWidth 0.0)
    Canvas.height (LinearViewState.totalHeight state)
    Canvas.background model.Theme.Window.Background
    Canvas.children [
      LinearRenderLayer.create [
        Canvas.left 0.0
        Canvas.top renderTop
        Control.width (max state.ViewportWidth 0.0)
        Control.height renderHeight
        Control.isHitTestVisible false
        LinearRenderLayer.Document(Some doc)
        LinearRenderLayer.State(Some state)
        LinearRenderLayer.Theme model.Theme
        LinearRenderLayer.StartIndex startIdx
        LinearRenderLayer.EndIndex endIdxExclusive
      ]
    ]
  ]

let private bodyView model dispatch doc (state: LinearViewState) =
  ScrollViewer.create [
    ScrollViewer.onScrollChanged (onScrollChanged dispatch)
    ScrollViewer.offset (Vector(0.0, state.ScrollOffsetY))
    ScrollViewer.content (visibleItemsView model doc state)
  ] :> IView

let private emptyStateView model =
  Border.create [
    Border.background model.Theme.Window.Background
    Border.borderThickness 0.0
    Border.child (
      TextBlock.create [
        TextBlock.text "No linear items loaded."
        TextBlock.foreground model.Theme.Text.Muted
        TextBlock.fontSize 13.0
        TextBlock.margin 10.0
      ]
    )
  ] :> IView

let view pane model dispatch =
  match pane.ActiveTab, model.LinearDocument, model.LinearViewState with
  | Some { Content = LinearContent }, Some doc, Some state ->
    bodyView model dispatch doc state
  | _ ->
    emptyStateView model
