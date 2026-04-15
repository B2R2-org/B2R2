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
module B2R2.RearEnd.BinExplore.GUI.HexOverview

open System
open System.Collections.Generic
open Avalonia
open Avalonia.Controls
open Avalonia.FuncUI.Builder
open Avalonia.Layout
open Avalonia.Media
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types

let private brushOfColor =
  let cache = Dictionary<string, IBrush>()
  fun color ->
    match cache.TryGetValue color with
    | true, brush -> brush
    | _ ->
      let brush = Brush.Parse color
      cache[color] <- brush
      brush

let [<Literal>] private MaxBarWidth = 10.0

let [<Literal>] private MinBarWidth = 6.0

let [<Literal>] private HorizontalPadding = 8.0

let private computeBarRect width height =
  let barWidth =
    width - HorizontalPadding * 2.0
    |> min MaxBarWidth
    |> max MinBarWidth
  let barLeft = (width - barWidth) / 2.0
  Rect(barLeft, 0.0, barWidth, height)

let private computeBucketCount height =
  max 1 (int (floor height))

let private computeBucketRange docLength bucketCount bucketIdx =
  let rangeStart = int64 (float docLength * float bucketIdx / float bucketCount)
  let rangeEndExclusive =
    if bucketIdx = bucketCount - 1 then docLength
    else int64 (float docLength * float (bucketIdx + 1) / float bucketCount)
  rangeStart, rangeEndExclusive

let private tryGetCurrentOffsetRange model =
  model.OffsetSnapshot.Selection
  |> Option.map (fun ctx -> ctx.Range)

let private hasBytes (state: HexdumpState) =
  state.Document.Length > 0L

let private getColoredSpans (state: HexdumpState): HexSpanStyle list =
  state.AnnotationSpans
  |> List.filter (fun (span: HexSpanStyle) ->
    span.Length > 0L && span.Background.IsSome)

let private tryPickBucketColor
    (spans: HexSpanStyle list) rangeStart rangeEnd =
  let step (bestPrio, bestOverlap, bestColor) (span: HexSpanStyle) =
    let spanEnd = span.Start + span.Length
    let overlapStart = max rangeStart span.Start
    let overlapEnd = min rangeEnd spanEnd
    let overlap = max 0L (overlapEnd - overlapStart)
    if overlap <= 0L then
      bestPrio, bestOverlap, bestColor
    elif span.Priority > bestPrio
      || (span.Priority = bestPrio && overlap > bestOverlap) then
      span.Priority, overlap, span.Background
    else
      bestPrio, bestOverlap, bestColor
  let _, _, color =
    List.fold step (Int32.MinValue, 0L, None) spans
  color

let private drawBuckets (ctx: DrawingContext) state (barRect: Rect) height =
  let bucketCount = computeBucketCount height
  let bucketHeight = height / float bucketCount
  let spans = getColoredSpans state
  for bucketIdx in 0 .. bucketCount - 1 do
    let rangeStart, rangeEnd =
      computeBucketRange state.Document.Length bucketCount bucketIdx
    match tryPickBucketColor spans rangeStart rangeEnd with
    | Some color ->
      let top = float bucketIdx * bucketHeight
      let rect = Rect(barRect.X, top, barRect.Width, bucketHeight)
      ctx.FillRectangle(brushOfColor color, rect)
    | None ->
      ()

let private tryGetRangeOverlayRect
    docLength width height (range: FileOffsetRange) =
  let clampOffset offset =
    max 0L (min (docLength - 1L) offset)
  if docLength <= 0L || width <= 0.0 || height <= 0.0 then
    None
  else
    let startOff = clampOffset (int64 range.Start)
    let endOff = clampOffset (int64 range.End)
    let clampedStart = min startOff endOff
    let clampedEnd = max startOff endOff
    let top = float clampedStart / float docLength * height
    let bottomExclusive = float (clampedEnd + 1L) / float docLength * height
    let overlayHeight = max 1.0 (bottomExclusive - top)
    Some(Rect(0.0, top, width, overlayHeight))

type private HexOverviewLayer() =
  inherit Control()

  static let stateProperty =
    AvaloniaProperty.Register<HexOverviewLayer, HexdumpState option>(
      nameof Unchecked.defaultof<HexOverviewLayer>.CurrentState, None
    )

  static let themeProperty =
    AvaloniaProperty.Register<HexOverviewLayer, Theme>(
      nameof Unchecked.defaultof<HexOverviewLayer>.CurrentTheme,
      Unchecked.defaultof<Theme>
    )

  static let rangeProperty =
    AvaloniaProperty.Register<HexOverviewLayer, FileOffsetRange option>(
      nameof Unchecked.defaultof<HexOverviewLayer>.CurrentRange, None
    )

  static member StateProperty = stateProperty

  static member ThemeProperty = themeProperty

  static member RangeProperty = rangeProperty

  member this.CurrentState
    with get() = this.GetValue stateProperty
    and set value = this.SetValue(stateProperty, value) |> ignore

  member this.CurrentTheme
    with get() = this.GetValue themeProperty
    and set value = this.SetValue(themeProperty, value) |> ignore

  member this.CurrentRange
    with get() = this.GetValue rangeProperty
    and set value = this.SetValue(rangeProperty, value) |> ignore

  static member State value =
    AttrBuilder<'t>.CreateProperty<HexdumpState option>(
      HexOverviewLayer.StateProperty, value, ValueNone
    )

  static member Theme value =
    AttrBuilder<'t>.CreateProperty<Theme>(
      HexOverviewLayer.ThemeProperty, value, ValueNone
    )

  static member Range value =
    AttrBuilder<'t>.CreateProperty<FileOffsetRange option>(
      HexOverviewLayer.RangeProperty, value, ValueNone
    )

  member this.DrawCurrentRangeOverlay(ctx, width, height, docLength) =
    match this.CurrentRange
          |> Option.bind (tryGetRangeOverlayRect docLength width height) with
    | Some overlayRect ->
      use _ = (ctx: DrawingContext).PushOpacity(0.35)
      let brush = brushOfColor this.CurrentTheme.Text.Highlight
      ctx.FillRectangle(brush, overlayRect)
    | None ->
      ()

  override this.OnPropertyChanged change =
    base.OnPropertyChanged change
    if change.Property = stateProperty
      || change.Property = themeProperty
      || change.Property = rangeProperty then
      this.InvalidateVisual()
    else
      ()

  override this.Render(ctx: DrawingContext) =
    base.Render ctx
    let state = this.CurrentState
    let theme = this.CurrentTheme
    let bounds = this.Bounds
    let width = bounds.Width
    let height = bounds.Height
    if isNull (box theme) || width <= 0.0 || height <= 0.0 then
      ()
    else
      let barRect = computeBarRect width height
      ctx.FillRectangle(brushOfColor theme.Panel.AltBackground, barRect)
      match state with
      | Some state when hasBytes state ->
        drawBuckets ctx state barRect height
        this.DrawCurrentRangeOverlay(ctx, width, height, state.Document.Length)
      | _ ->
        ()
      let pen = Pen(brushOfColor theme.Panel.Border, 1.0)
      ctx.DrawRectangle(null, pen, barRect)

[<RequireQualifiedAccess>]
module private HexOverviewLayer =
  let create (attrs: IAttr<HexOverviewLayer> list) =
    View.createGeneric<HexOverviewLayer> attrs

let private overviewBodyView model =
  HexOverviewLayer.create [
    Control.horizontalAlignment HorizontalAlignment.Stretch
    Control.verticalAlignment VerticalAlignment.Stretch
    Control.isHitTestVisible true
    HexOverviewLayer.State model.Hexdump
    HexOverviewLayer.Theme model.Theme
    HexOverviewLayer.Range(tryGetCurrentOffsetRange model)
  ] :> IView

let view model dispatch =
  Border.create [
    Border.horizontalAlignment HorizontalAlignment.Stretch
    Border.verticalAlignment VerticalAlignment.Stretch
    Border.background model.Theme.Panel.Background
    Border.borderThickness 1.0
    Border.borderBrush model.Theme.Panel.Border
    Border.child (
      DockPanel.create [
        DockPanel.children [
          overviewBodyView model
        ]
      ]
    )
  ]
