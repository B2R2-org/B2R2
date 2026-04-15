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
open Avalonia.Input
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

let private tryGetViewportOffsetRange model =
  model.OffsetSnapshot.Viewport
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

type private CachedBucketSegment =
  { StartBucket: int
    EndBucketExclusive: int
    Background: string }

type private OverviewStaticCache =
  { BucketCount: int
    Segments: CachedBucketSegment list }

let private buildBucketCache state height =
  let bucketCount = computeBucketCount height
  let spans = getColoredSpans state
  if bucketCount <= 0 || List.isEmpty spans then
    { BucketCount = bucketCount
      Segments = [] }
  else
    let segments = ResizeArray<_>()
    let mutable segmentStart = 0
    let mutable currentColor = None
    let flushSegment endBucketExclusive colorOpt =
      match colorOpt with
      | Some color when endBucketExclusive > segmentStart ->
        segments.Add
          { StartBucket = segmentStart
            EndBucketExclusive = endBucketExclusive
            Background = color }
      | _ ->
        ()
    for bucketIdx in 0 .. bucketCount - 1 do
      let rangeStart, rangeEnd =
        computeBucketRange state.Document.Length bucketCount bucketIdx
      let color = tryPickBucketColor spans rangeStart rangeEnd
      if color <> currentColor then
        flushSegment bucketIdx currentColor
        segmentStart <- bucketIdx
        currentColor <- color
      else
        ()
    flushSegment bucketCount currentColor
    { BucketCount = bucketCount
      Segments = segments |> Seq.toList }

let private drawCachedBuckets
    (ctx: DrawingContext) (barRect: Rect) height cache =
  if cache.BucketCount > 0 then
    let bucketHeight = height / float cache.BucketCount
    for segment in cache.Segments do
      let top = float segment.StartBucket * bucketHeight
      let segmentHeight =
        float (segment.EndBucketExclusive - segment.StartBucket) * bucketHeight
      let rect = Rect(barRect.X, top, barRect.Width, segmentHeight)
      ctx.FillRectangle(brushOfColor segment.Background, rect)
  else
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

  let mutable dragOffsetY = None
  let mutable cachedDocLength = -1L
  let mutable cachedAnnotationSpans: HexSpanStyle list = []
  let mutable cachedBucketCount = -1
  let mutable cachedStaticSegments: CachedBucketSegment list = []

  let clearStaticCache () =
    cachedDocLength <- -1L
    cachedAnnotationSpans <- []
    cachedBucketCount <- -1
    cachedStaticSegments <- []

  let isStaticCacheReusable (state: HexdumpState) =
    cachedDocLength = state.Document.Length
    && obj.ReferenceEquals(
      box cachedAnnotationSpans, box state.AnnotationSpans
    )

  let ensureStaticCache (state: HexdumpState) height =
    let bucketCount = computeBucketCount height
    let shouldRebuild =
      not (isStaticCacheReusable state)
      || cachedBucketCount <> bucketCount
    if shouldRebuild then
      let cache = buildBucketCache state height
      cachedDocLength <- state.Document.Length
      cachedAnnotationSpans <- state.AnnotationSpans
      cachedBucketCount <- cache.BucketCount
      cachedStaticSegments <- cache.Segments
    else
      ()
    { BucketCount = cachedBucketCount
      Segments = cachedStaticSegments }

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

  static let viewportRangeProperty =
    AvaloniaProperty.Register<HexOverviewLayer, FileOffsetRange option>(
      nameof Unchecked.defaultof<HexOverviewLayer>.CurrentViewportRange, None
    )

  static let dispatchProperty =
    AvaloniaProperty.Register<HexOverviewLayer, Message -> unit>(
      nameof Unchecked.defaultof<HexOverviewLayer>.Dispatcher, ignore
    )

  static member StateProperty = stateProperty

  static member ThemeProperty = themeProperty

  static member RangeProperty = rangeProperty

  static member ViewportRangeProperty = viewportRangeProperty

  static member DispatchProperty = dispatchProperty

  member this.CurrentState
    with get() = this.GetValue stateProperty
    and set value = this.SetValue(stateProperty, value) |> ignore

  member this.CurrentTheme
    with get() = this.GetValue themeProperty
    and set value = this.SetValue(themeProperty, value) |> ignore

  member this.CurrentRange
    with get() = this.GetValue rangeProperty
    and set value = this.SetValue(rangeProperty, value) |> ignore

  member this.CurrentViewportRange
    with get() = this.GetValue viewportRangeProperty
    and set value = this.SetValue(viewportRangeProperty, value) |> ignore

  member this.Dispatcher
    with get() = this.GetValue dispatchProperty
    and set value = this.SetValue(dispatchProperty, value) |> ignore

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

  static member ViewportRange value =
    AttrBuilder<'t>.CreateProperty<FileOffsetRange option>(
      HexOverviewLayer.ViewportRangeProperty, value, ValueNone
    )

  static member Dispatch value =
    AttrBuilder<'t>.CreateProperty<Message -> unit>(
      HexOverviewLayer.DispatchProperty, value, ValueNone
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

  member this.DrawViewportRangeOverlay(ctx, width, height, docLength) =
    match this.CurrentViewportRange
          |> Option.bind (tryGetRangeOverlayRect docLength width height) with
    | Some overlayRect ->
      use _ = (ctx: DrawingContext).PushOpacity(0.2)
      let brush = brushOfColor this.CurrentTheme.Graph.ViewportRect
      ctx.FillRectangle(brush, overlayRect)
      let pen = Pen(brushOfColor this.CurrentTheme.Graph.ViewportRect, 1.0)
      ctx.DrawRectangle(null, pen, overlayRect)
    | None ->
      ()

  member this.TryGetViewportOverlayRect(width, height, docLength) =
    this.CurrentViewportRange
    |> Option.bind (tryGetRangeOverlayRect docLength width height)

  member this.ScrollHexdumpToOverlayTop(pointerY, overlayRect: Rect, state) =
    let height = this.Bounds.Height
    if height > 0.0 then
      let targetTop =
        pointerY - dragOffsetY.Value
        |> max 0.0
        |> min (max 0.0 (height - overlayRect.Height))
      let targetStartOffset =
        int64 (floor (targetTop / height * float state.Document.Length))
      let targetRow =
        targetStartOffset / int64 (max 1 state.View.BytesPerRow)
      this.Dispatcher(HexdumpPaneMsg(SetScrollRow targetRow))
    else
      ()

  override this.OnPropertyChanged change =
    base.OnPropertyChanged change
    if change.Property = stateProperty
      || change.Property = themeProperty
      || change.Property = rangeProperty
      || change.Property = viewportRangeProperty
      || change.Property = dispatchProperty then
      if change.Property = stateProperty then
        match this.CurrentState with
        | Some state ->
          if not (isStaticCacheReusable state) then
            clearStaticCache ()
          else
            ()
        | None ->
          clearStaticCache ()
      else
        ()
      this.InvalidateVisual()
    else
      ()

  override this.OnPointerPressed e =
    base.OnPointerPressed e
    match this.CurrentState with
    | Some state ->
      let props = e.GetCurrentPoint(this).Properties
      let p = e.GetPosition this
      match this.TryGetViewportOverlayRect(
              this.Bounds.Width, this.Bounds.Height, state.Document.Length) with
      | Some overlayRect
        when props.IsLeftButtonPressed && overlayRect.Contains p ->
        dragOffsetY <- Some(p.Y - overlayRect.Y)
        e.Pointer.Capture this
        e.Handled <- true
      | Some overlayRect when props.IsLeftButtonPressed ->
        dragOffsetY <- Some(overlayRect.Height / 2.0)
        this.ScrollHexdumpToOverlayTop(p.Y, overlayRect, state)
        e.Pointer.Capture this
        e.Handled <- true
      | _ ->
        ()
    | None ->
      ()

  override this.OnPointerMoved e =
    base.OnPointerMoved e
    match dragOffsetY, this.CurrentState with
    | Some _, Some state when e.Pointer.Captured = this ->
      let p = e.GetPosition this
      match this.TryGetViewportOverlayRect(
              this.Bounds.Width, this.Bounds.Height, state.Document.Length) with
      | Some overlayRect ->
        this.ScrollHexdumpToOverlayTop(p.Y, overlayRect, state)
        e.Handled <- true
      | None ->
        ()
    | _ ->
      ()

  override this.OnPointerReleased e =
    base.OnPointerReleased e
    match dragOffsetY, this.CurrentState with
    | Some _, Some state when e.Pointer.Captured = this ->
      let p = e.GetPosition this
      match this.TryGetViewportOverlayRect(
              this.Bounds.Width, this.Bounds.Height, state.Document.Length) with
      | Some overlayRect ->
        this.ScrollHexdumpToOverlayTop(p.Y, overlayRect, state)
      | None ->
        ()
      dragOffsetY <- None
      e.Pointer.Capture null
      e.Handled <- true
    | _ ->
      dragOffsetY <- None

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
      (* Fill the whole control with a transparent brush so clicks on the
         horizontal padding are also hit-tested by this layer. *)
      ctx.FillRectangle(Brushes.Transparent, bounds)
      let barRect = computeBarRect width height
      ctx.FillRectangle(brushOfColor theme.Panel.AltBackground, barRect)
      match state with
      | Some state when hasBytes state ->
        let cache = ensureStaticCache state height
        drawCachedBuckets ctx barRect height cache
        this.DrawViewportRangeOverlay(ctx, width, height, state.Document.Length)
        this.DrawCurrentRangeOverlay(ctx, width, height, state.Document.Length)
      | _ ->
        ()
      let pen = Pen(brushOfColor theme.Panel.Border, 1.0)
      ctx.DrawRectangle(null, pen, barRect)

[<RequireQualifiedAccess>]
module private HexOverviewLayer =
  let create (attrs: IAttr<HexOverviewLayer> list) =
    View.createGeneric<HexOverviewLayer> attrs

let private overviewBodyView model dispatch =
  HexOverviewLayer.create [
    Control.horizontalAlignment HorizontalAlignment.Stretch
    Control.verticalAlignment VerticalAlignment.Stretch
    Control.isHitTestVisible true
    HexOverviewLayer.State model.Hexdump
    HexOverviewLayer.Theme model.Theme
    HexOverviewLayer.Range(tryGetCurrentOffsetRange model)
    HexOverviewLayer.ViewportRange(tryGetViewportOffsetRange model)
    HexOverviewLayer.Dispatch dispatch
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
          overviewBodyView model dispatch
        ]
      ]
    )
  ]
