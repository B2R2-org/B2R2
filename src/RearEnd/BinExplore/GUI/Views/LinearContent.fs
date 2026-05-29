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
open Avalonia.Input
open Avalonia.Media
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter

let [<Literal>] private OverscanPixels = 240.0
let [<Literal>] private HeaderTopGap = 8.0

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

let private scrollLinearTo dispatch offsetY =
  dispatch (LinearPaneMsg(LinearPaneMessage.SetScrollOffset offsetY))

let private pageScrollDelta (state: LinearViewState) =
  let lineHeight = max state.RowHeight 1.0
  max lineHeight (state.ViewportHeight - lineHeight)

let private onNavigationKeyDown dispatch (state: LinearViewState) e =
  let lineHeight = max state.RowHeight 1.0
  let targetOffset =
    match (e: KeyEventArgs).Key with
    | Key.Home -> Some 0.0
    | Key.End ->
      Some(max 0.0 (LinearViewState.totalHeight state - state.ViewportHeight))
    | Key.Up -> Some(state.ScrollOffsetY - lineHeight)
    | Key.Down -> Some(state.ScrollOffsetY + lineHeight)
    | Key.PageUp -> Some(state.ScrollOffsetY - pageScrollDelta state)
    | Key.PageDown -> Some(state.ScrollOffsetY + pageScrollDelta state)
    | _ -> None
  match targetOffset with
  | Some offsetY ->
    scrollLinearTo dispatch offsetY
    e.Handled <- true
  | None ->
    ()

let private focusPointerSource (e: PointerPressedEventArgs) =
  match e.Source with
  | :? Control as ctrl -> ctrl.Focus() |> ignore
  | _ -> ()

type private LinearCommonLayout =
  { PaddingX: float
    OffsetX: float
    AddressX: float
    KindX: float
    ValueX: float
    DisasmX: float
    CharWidth: float }

type private LinearRowKind =
  | RawByteRow
  | DisassemblyRow
  | LinkageRow

type private LinearRowLayout =
  | RawByteLayout of asciiX: float
  | DisassemblyLayout of disasmX: float
  | LinkageLayout of disasmX: float * symbolX: float

type private LinearCellKind =
  | OffsetCell
  | AddressCell
  | KindCell
  | ValueCell
  | DisasmCell
  | RawAsciiCell
  | LinkageNameCell

type private LinearTextRole =
  | PrimaryText
  | SecondaryText
  | TokenText of AsmWordKind

type private LinearTextSegment =
  { Text: string
    Role: LinearTextRole }

type private LinearCell =
  { Kind: LinearCellKind
    Segments: LinearTextSegment list
    Line: int }

type private LinearHeaderKind =
  | SectionHeaderVisual
  | FunctionHeaderVisual
  | LinkageTableHeaderVisual

type private LinearRowVisualModel =
  | Cells of LinearRowKind * LinearCell list
  | FullWidthHeader of LinearHeaderKind * title: string

type private CachedRowVisual =
  | CellRowVisual of
      LinearRowKind * cells: (LinearCellKind * int * FormattedText list) list
  | FullWidthHeaderVisual of LinearHeaderKind * title: FormattedText

let private addressDigits (doc: LinearDocument) =
  let mutable maxAddr = doc.LinearBaseAddress
  for item in doc.LinearItems do
    let loc = LinearItem.location item
    let lastAddr =
      if loc.ItemLength <= 0 then loc.Address
      else loc.Address + uint64 (loc.ItemLength - 1)
    if lastAddr > maxAddr then maxAddr <- lastAddr
    else ()
  max 1 (maxAddr.ToString("X").Length)

let private offsetDigits (doc: LinearDocument) =
  let maxOffset =
    if doc.LinearTotalLength <= 0L then 0L
    else doc.LinearTotalLength - 1L
  max 1 (maxOffset.ToString("X").Length)

let private valueColumnChars () =
  max 2 (LinearViewState.ValueColumnByteCapacity * 3 - 1)

let private computeCommonLayout doc (state: LinearViewState) =
  let charWidth = max state.CharWidth 1.0
  let paddingX = 10.0
  let offsetWidth = charWidth * float (offsetDigits doc + 6)
  let addrWidth = charWidth * float (addressDigits doc + 2)
  let offsetX = paddingX
  let addressX = offsetX + offsetWidth + charWidth * 2.0
  let kindX = addressX + addrWidth + charWidth * 2.0
  let kindWidth = charWidth * 3.0
  let valueX = kindX + kindWidth + charWidth * 2.0
  let valueWidth = charWidth * float (valueColumnChars ())
  let disasmX = valueX + valueWidth + charWidth * 4.0
  { PaddingX = paddingX
    OffsetX = offsetX
    AddressX = addressX
    KindX = kindX
    ValueX = valueX
    DisasmX = disasmX
    CharWidth = charWidth }

let private formattedTextWidthOf kind cells =
  cells
  |> List.choose (fun (cellKind, _, texts: FormattedText list) ->
    if cellKind = kind then
      texts
      |> List.sumBy (fun txt -> txt.WidthIncludingTrailingWhitespace)
      |> Some
    else
      None)
  |> List.fold max 0.0

let private rowLayoutOf common rowKind cells =
  let valueWidth = formattedTextWidthOf ValueCell cells
  let disasmWidth = formattedTextWidthOf DisasmCell cells
  match rowKind with
  | RawByteRow ->
    RawByteLayout(common.ValueX + valueWidth + common.CharWidth * 2.0)
  | DisassemblyRow ->
    DisassemblyLayout common.DisasmX
  | LinkageRow ->
    let disasmX = common.DisasmX
    let fixedSymbolX = common.DisasmX + common.CharWidth * 32.0
    let symbolX = disasmX + disasmWidth + common.CharWidth * 4.0
    LinkageLayout(disasmX, max fixedSymbolX symbolX)

let private cellX common rowLayout = function
  | OffsetCell -> common.OffsetX
  | AddressCell -> common.AddressX
  | KindCell -> common.KindX
  | ValueCell -> common.ValueX
  | DisasmCell ->
    match rowLayout with
    | DisassemblyLayout disasmX -> disasmX
    | LinkageLayout(disasmX, _) -> disasmX
    | _ -> common.ValueX
  | RawAsciiCell ->
    match rowLayout with
    | RawByteLayout asciiX -> asciiX
    | _ -> common.ValueX
  | LinkageNameCell ->
    match rowLayout with
    | LinkageLayout(_, symbolX) -> symbolX
    | _ -> common.ValueX

let private asciiOfByte value =
  if value >= 0x20uy && value <= 0x7Euy then string (char value)
  else "."

let private linearCell kind text role =
  { Kind = kind
    Segments = [ { Text = text; Role = role } ]
    Line = 0 }

let private linearCellAt line kind text role =
  { Kind = kind
    Segments = [ { Text = text; Role = role } ]
    Line = line }

let private disasmCellFromWords fallback words =
  let segments =
    words
    |> Array.toList
    |> List.map (fun word ->
      { Text = word.AsmWordValue
        Role = TokenText word.AsmWordKind })
  if List.isEmpty segments then
    linearCell DisasmCell fallback PrimaryText
  else
    { Kind = DisasmCell
      Segments = segments
      Line = 0 }

let private disasmCellFromAddress (lifter: LiftingUnit) address fallback =
  try
    lifter.DecomposeInstruction(addr = address)
    |> disasmCellFromWords fallback
  with _ ->
    linearCell DisasmCell fallback PrimaryText

let private bytesText (bytes: byte[]) =
  bytes |> Array.map (fun b -> $"{b:X2}") |> String.concat " "

let private readItemBytes (hdl: BinHandle) (loc: ILinearItemLocation) =
  let rawBytes = hdl.File.RawBytes
  if loc.Offset < 0 || loc.Offset >= rawBytes.Length || loc.ItemLength <= 0 then
    [||]
  else
    let length = min loc.ItemLength (rawBytes.Length - loc.Offset)
    Array.sub rawBytes loc.Offset length

let private valueCellsOfBytes (bytes: byte[]) =
  let capacity = LinearViewState.ValueColumnByteCapacity
  if bytes.Length <= capacity then
    [ linearCell ValueCell (bytesText bytes) PrimaryText ]
  else
    [ linearCell ValueCell
        (bytes |> Array.take capacity |> bytesText) PrimaryText
      linearCellAt 1 ValueCell
        (bytes |> Array.skip capacity |> bytesText) PrimaryText ]

let private toRowVisualModel (hdl: BinHandle) (lifter: LiftingUnit) = function
  | RawByte(loc, value) ->
    Cells(RawByteRow, [
      linearCell OffsetCell $"off+0x{loc.Offset:X}" SecondaryText
      linearCell AddressCell $"0x{loc.Address:X}" PrimaryText
      linearCell KindCell "(b)" SecondaryText
      linearCell ValueCell $"{value:X2}" PrimaryText
      linearCell RawAsciiCell (asciiOfByte value) SecondaryText
    ])
  | SectionHeader(_, name, _, _) ->
    FullWidthHeader(SectionHeaderVisual, $"Section {name}")
  | FunctionHeader(_, name) ->
    FullWidthHeader(FunctionHeaderVisual, $"Function {name}")
  | Disassembly(loc, disasm) ->
    let bytes = readItemBytes hdl loc
    Cells(
      DisassemblyRow,
      [ linearCell OffsetCell $"off+0x{loc.Offset:X}" SecondaryText
        linearCell AddressCell $"0x{loc.Address:X}" PrimaryText
        linearCell KindCell "(i)" SecondaryText
        yield! valueCellsOfBytes bytes
        disasmCellFromAddress lifter loc.Address disasm ]
    )
  | LinkageTableHeader(_, name) ->
    FullWidthHeader(LinkageTableHeaderVisual, name)
  | LinkageTableEntry(loc, disasm) ->
    let bytes = readItemBytes hdl loc
    Cells(LinkageRow, [
      linearCell OffsetCell $"off+0x{loc.Offset:X}" SecondaryText
      linearCell AddressCell $"0x{loc.Address:X}" PrimaryText
      linearCell KindCell "(l)" SecondaryText
      yield! valueCellsOfBytes bytes
      disasmCellFromAddress lifter loc.Address disasm
    ])

type private LinearRenderLayer() =
  inherit Control()

  let textCache = Dictionary<int, CachedRowVisual>()
  let mutable lastFontFamily = ""
  let mutable lastFontSize = 0.0
  let mutable lastForeground = ""
  let mutable lastSecondary = ""
  let mutable lastAddress = ""
  let mutable lastMnemonic = ""
  let mutable lastVariable = ""
  let mutable lastValue = ""

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

  let ensureCacheSignature (state: LinearViewState) (theme: Theme) =
    let fontFamily = theme.Font.Monospace.FontFamily
    let fontSize = state.FontSize
    let foreground = theme.Text.Primary
    let secondary = theme.Text.Secondary
    if lastFontFamily <> fontFamily
       || lastFontSize <> fontSize
       || lastForeground <> foreground
       || lastSecondary <> secondary
       || lastAddress <> theme.Text.Address
       || lastMnemonic <> theme.Text.Mnemonic
       || lastVariable <> theme.Text.Variable
       || lastValue <> theme.Text.Value then
      clearCache ()
      lastFontFamily <- fontFamily
      lastFontSize <- fontSize
      lastForeground <- foreground
      lastSecondary <- secondary
      lastAddress <- theme.Text.Address
      lastMnemonic <- theme.Text.Mnemonic
      lastVariable <- theme.Text.Variable
      lastValue <- theme.Text.Value
    else
      ()
    fontFamily, fontSize, foreground, secondary

  let textColor (theme: Theme) foreground secondary = function
    | PrimaryText -> foreground
    | SecondaryText -> secondary
    | TokenText AsmWordKind.Address -> theme.Text.Address
    | TokenText AsmWordKind.Mnemonic -> theme.Text.Mnemonic
    | TokenText AsmWordKind.Variable -> theme.Text.Variable
    | TokenText AsmWordKind.Value -> theme.Text.Value
    | TokenText _ -> foreground

  let getOrCreateText doc state theme index =
    let fontFamily, fontSize, foreground, secondary =
      ensureCacheSignature state theme
    match textCache.TryGetValue index with
    | true, txt -> txt
    | _ ->
      let item = doc.LinearItems[index]
      let txt =
        match toRowVisualModel doc.BinHandle doc.LiftingUnit item with
        | Cells(rowKind, cells) ->
          cells
          |> List.map (fun cell ->
            let texts =
              cell.Segments
              |> List.map (fun segment ->
                let color = textColor theme foreground secondary segment.Role
                makeFormattedText fontFamily fontSize color segment.Text)
            cell.Kind,
            cell.Line,
            texts)
          |> fun cells -> CellRowVisual(rowKind, cells)
        | FullWidthHeader(headerKind, title) ->
          let headerFontSize =
            match headerKind with
            | SectionHeaderVisual ->
              LinearViewState.sectionHeaderFontSize fontSize
            | FunctionHeaderVisual ->
              fontSize
            | LinkageTableHeaderVisual ->
              fontSize
          FullWidthHeaderVisual(
            headerKind,
            makeFormattedText
              fontFamily
              headerFontSize
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

  member _.DrawCellRow(ctx, common, rowKind, rowTop, rowHeight, cells) =
    let textHeight =
      cells
      |> List.collect (fun (_, _, texts: FormattedText list) -> texts)
      |> List.map (fun txt -> txt.Height)
      |> List.fold max 0.0
    let lineCount =
      cells
      |> List.map (fun (_, line, _) -> line)
      |> List.fold max 0
      |> (+) 1
    let lineStep =
      if lineCount <= 1 then 0.0 else rowHeight / float lineCount
    let blockHeight =
      if lineCount <= 1 then textHeight
      else lineStep * float (lineCount - 1) + textHeight
    let firstTextY = rowTop + max 0.0 ((rowHeight - blockHeight) / 2.0)
    let rowLayout = rowLayoutOf common rowKind cells
    for kind, line, texts in cells do
      let textY = firstTextY + lineStep * float line
      let mutable textX = cellX common rowLayout kind
      for txt in texts do
        (ctx: DrawingContext).DrawText(txt, Point(textX, textY))
        textX <- textX + txt.WidthIncludingTrailingWhitespace

  member this.DrawHeader(ctx, common, rowTop, rowHeight, headerKind, txt) =
    let theme = this.CurrentTheme
    let topGap = min HeaderTopGap (max 0.0 rowHeight)
    let headerTop = rowTop + topGap
    let headerHeight = max 0.0 (rowHeight - topGap)
    let titleHeight = (txt: FormattedText).Height
    let titleY = headerTop + max 0.0 ((headerHeight - titleHeight) / 2.0)
    let bounds = this.Bounds
    let headerBg =
      match headerKind with
      | SectionHeaderVisual ->
        Brush.Parse theme.Linear.SectionHeaderBackground
      | FunctionHeaderVisual ->
        Brush.Parse theme.Linear.FunctionHeaderBackground
      | LinkageTableHeaderVisual ->
        Brush.Parse theme.Linear.LinkageTableHeaderBackground
    let borderBrush = Brush.Parse theme.Linear.HeaderBorder
    let borderPen = Pen(borderBrush, 1.0)
    (ctx: DrawingContext).FillRectangle(
      headerBg,
      Rect(0.0, headerTop, bounds.Width, headerHeight)
    )
    match headerKind with
    | SectionHeaderVisual ->
      ctx.DrawLine(
        borderPen,
        Point(common.PaddingX, headerTop),
        Point(bounds.Width - common.PaddingX, headerTop)
      )
      ctx.DrawLine(
        borderPen,
        Point(common.PaddingX, headerTop + headerHeight - 1.0),
        Point(bounds.Width - common.PaddingX, headerTop + headerHeight - 1.0)
      )
      ctx.DrawText(txt, Point(common.PaddingX, titleY))
    | FunctionHeaderVisual ->
      ctx.DrawLine(
        borderPen,
        Point(common.PaddingX, headerTop + headerHeight - 1.0),
        Point(bounds.Width - common.PaddingX, headerTop + headerHeight - 1.0)
      )
      ctx.DrawText(txt, Point(common.PaddingX, titleY))
    | LinkageTableHeaderVisual ->
      ctx.DrawLine(
        borderPen,
        Point(common.PaddingX, headerTop + headerHeight - 1.0),
        Point(bounds.Width - common.PaddingX, headerTop + headerHeight - 1.0)
      )
      ctx.DrawText(txt, Point(common.PaddingX, titleY))

  override this.OnPropertyChanged change =
    base.OnPropertyChanged change
    if change.Property = docProperty
       || change.Property = stateProperty
       || change.Property = themeProperty
       || change.Property = startIndexProperty
       || change.Property = endIndexProperty then
      if change.Property = docProperty then clearCache ()
      else ()
      this.InvalidateVisual()
    else
      ()

  override this.Render(ctx: DrawingContext) =
    base.Render ctx
    match this.CurrentDocument, this.CurrentState with
    | Some doc, Some state when not (isNull (box this.CurrentTheme))
                             && this.RenderEndIndex > this.RenderStartIndex ->
      let theme = this.CurrentTheme
      let common = computeCommonLayout doc state
      let renderTop = LinearViewState.itemTop state this.RenderStartIndex
      for i in this.RenderStartIndex .. this.RenderEndIndex - 1 do
        let rowTop = LinearViewState.itemTop state i - renderTop
        let rowHeight = LinearViewState.itemHeight state i
        let txt = getOrCreateText doc state theme i
        match txt with
        | CellRowVisual(rowKind, cells) ->
          this.DrawCellRow(ctx, common, rowKind, rowTop, rowHeight, cells)
        | FullWidthHeaderVisual(headerKind, txt) ->
          this.DrawHeader(ctx, common, rowTop, rowHeight, headerKind, txt)
    | _ ->
      ()

[<RequireQualifiedAccess>]
module private LinearRenderLayer =
  let create (attrs: IAttr<LinearRenderLayer> list) =
    View.createGeneric<LinearRenderLayer> attrs

let private visibleItemsView model dispatch doc (state: LinearViewState) =
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
    Canvas.background model.Theme.Linear.Background
    Control.focusable true
    Control.onPointerPressed focusPointerSource
    Control.onKeyDown (
      onNavigationKeyDown dispatch state,
      OnChangeOf state.ScrollOffsetY
    )
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
    Control.focusable true
    Control.onKeyDown (
      onNavigationKeyDown dispatch state,
      OnChangeOf state.ScrollOffsetY
    )
    ScrollViewer.onScrollChanged (onScrollChanged dispatch)
    ScrollViewer.offset (Vector(0.0, state.ScrollOffsetY))
    ScrollViewer.content (visibleItemsView model dispatch doc state)
  ] :> IView

let private emptyStateView model text =
  Border.create [
    Border.background model.Theme.Linear.Background
    Border.borderThickness 0.0
    Border.child (
      TextBlock.create [
        TextBlock.text text
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
  | Some { Content = LinearContent }, _, _ when model.LoadedBinary.IsSome ->
    emptyStateView model "Analyzing linear view..."
  | _ ->
    emptyStateView model "No linear items loaded."
