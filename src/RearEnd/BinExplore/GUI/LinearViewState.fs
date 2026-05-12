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

namespace B2R2.RearEnd.BinExplore.GUI

/// Represents UI state for the linear view. The document data lives separately
/// in LinearDocument; this state keeps layout, viewport, and font metrics.
type LinearViewState =
  { Layout: LinearLayoutIndex
    ScrollOffsetY: float
    ViewportWidth: float
    ViewportHeight: float
    FontSize: float
    CharWidth: float
    RowHeight: float }

/// Caches layout metadata for linear-view items. This allows the view to map
/// pixel scroll positions to visible item ranges without scanning every item.
and LinearLayoutIndex =
  { ItemHeights: ResizeArray<float>
    ItemTops: ResizeArray<float>
    TotalHeight: float }

[<RequireQualifiedAccess>]
module LinearViewState =
  let [<Literal>] private SectionHeaderFontScale = 1.1
  let [<Literal>] private HeaderVerticalPadding = 8.0
  let [<Literal>] ValueColumnByteCapacity = 8

  let sectionHeaderFontSize fontSize =
    fontSize * SectionHeaderFontScale

  let private itemLineCount = function
    | Disassembly(loc, _) when loc.ItemLength > ValueColumnByteCapacity ->
      2.0
    | _ ->
      1.0

  let private measureItemHeight defaultItemHeight item =
    match item with
    | RawByte _
    | Disassembly _
    | LinkageTableEntry _ ->
      max defaultItemHeight 1.0 * itemLineCount item
    | SectionHeader _ ->
      max 1.0
        (defaultItemHeight * SectionHeaderFontScale
         + HeaderVerticalPadding)
    | LinkageTableHeader _ ->
      max 1.0 (defaultItemHeight + HeaderVerticalPadding)

  let private buildLayoutIndex (items: ResizeArray<_>) defaultItemHeight =
    let heights = ResizeArray<float> items.Count
    let tops = ResizeArray<float> items.Count
    let mutable top = 0.0
    for i = 0 to items.Count - 1 do
      let itemHeight = measureItemHeight defaultItemHeight items[i]
      tops.Add top
      heights.Add itemHeight
      top <- top + itemHeight
    { ItemHeights = heights
      ItemTops = tops
      TotalHeight = top }

  let ofDocument doc fontSize =
    { Layout = buildLayoutIndex doc.LinearItems 1.0
      ScrollOffsetY = 0.0
      ViewportWidth = 0.0
      ViewportHeight = 0.0
      FontSize = fontSize
      CharWidth = 0.0
      RowHeight = 0.0 }

  let itemTop state index =
    if index < 0 || index >= state.Layout.ItemTops.Count then 0.0
    else state.Layout.ItemTops[index]

  let itemHeight state index =
    if index < 0 || index >= state.Layout.ItemHeights.Count then 0.0
    else state.Layout.ItemHeights[index]

  let totalHeight state =
    state.Layout.TotalHeight

  let rebuildUniformLayout rowHeight doc state =
    { state with Layout = buildLayoutIndex doc.LinearItems rowHeight }

  let private findFirstIndexAtOrAfterY
      (tops: ResizeArray<float>) targetY =
    let rec loop low high =
      if low >= high then low
      else
        let mid = low + (high - low) / 2
        if tops[mid] < targetY then loop (mid + 1) high
        else loop low mid
    loop 0 tops.Count

  let private findFirstIndexAfterBottom state targetY =
    let tops: ResizeArray<float> = state.Layout.ItemTops
    let heights: ResizeArray<float> = state.Layout.ItemHeights
    let rec loop low high =
      if low >= high then low
      else
        let mid = low + (high - low) / 2
        let bottom = tops[mid] + heights[mid]
        if bottom <= targetY then loop (mid + 1) high
        else loop low mid
    loop 0 tops.Count

  let findVisibleRange overscanPx state =
    let totalItems = state.Layout.ItemTops.Count
    if totalItems <= 0 || state.Layout.ItemTops.Count = 0 then
      0, 0
    else
      let overscanPx = max overscanPx 0.0
      let visibleTop =
        max 0.0 (state.ScrollOffsetY - overscanPx)
      let visibleBottom =
        min state.Layout.TotalHeight
          (state.ScrollOffsetY
           + state.ViewportHeight + overscanPx)
      let startIndex =
        min (max 0 (totalItems - 1))
          (findFirstIndexAfterBottom state visibleTop)
      let endIndexExclusive =
        let idx =
          findFirstIndexAtOrAfterY state.Layout.ItemTops visibleBottom
        max (startIndex + 1) idx |> min totalItems
      startIndex, endIndexExclusive
