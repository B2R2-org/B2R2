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

/// Provides coordinate conversions that need both the immutable linear
/// document and the current linear view state. Document-only queries belong in
/// LinearDocument, and layout-only queries belong in LinearViewState; this
/// module handles projections between file offsets, item indexes, and scroll
/// positions.
[<RequireQualifiedAccess>]
module B2R2.RearEnd.BinExplore.GUI.LinearProjection

let private findFirstIndexAtOrAfterOffset doc targetOffset =
  let rec loop low high =
    if low >= high then low
    else
      let mid = low + (high - low) / 2
      match LinearDocument.itemOffset doc mid with
      | Some offset when offset < targetOffset ->
        loop (mid + 1) high
      | _ ->
        loop low mid
  loop 0 doc.LinearItems.Count

let findVisibleRange overscanPx doc state =
  let startIndex, endIndexExclusive =
    LinearViewState.findVisibleRange overscanPx state
  let totalItems = doc.LinearItems.Count
  min startIndex totalItems, min endIndexExclusive totalItems

let tryGetScrollOffsetForFileOffset doc state targetOffset =
  if doc.LinearItems.Count = 0 then
    None
  else
    let targetOffset =
      max 0 targetOffset |> min (int doc.LinearTotalLength)
    let idx =
      findFirstIndexAtOrAfterOffset doc targetOffset
      |> min (max 0 (doc.LinearItems.Count - 1))
    Some(LinearViewState.itemTop state idx)

let tryGetTopVisibleFileOffset doc state =
  match findVisibleRange 0.0 doc state with
  | startIndex, endIndexExclusive when startIndex < endIndexExclusive ->
    LinearDocument.itemOffset doc startIndex
  | _ ->
    None

let tryGetVisibleFileOffsetRange doc state =
  match findVisibleRange 0.0 doc state with
  | startIndex, endIndexExclusive when startIndex < endIndexExclusive ->
    match LinearDocument.tryGetItem doc startIndex,
          LinearDocument.tryGetItem doc (endIndexExclusive - 1) with
    | Some startItem, Some endItem ->
      let startLoc = LinearItem.location startItem
      let endLoc = LinearItem.location endItem
      let endOffset =
        endLoc.Offset + max 0 (endLoc.ItemLength - 1)
      Some(startLoc.Offset, endOffset)
    | _ ->
      None
  | _ ->
    None
