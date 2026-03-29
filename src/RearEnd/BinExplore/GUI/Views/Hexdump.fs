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
open Avalonia
open Avalonia.Controls
open Avalonia.Layout
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types

let [<Literal>] private OverscanRows = 12

let private onScrollChanged viewState dispatch (args: ScrollChangedEventArgs) =
  let deltaY = args.OffsetDelta.Y
  match viewState.PendingScrollRestoreDelta, args.Source with
  | Some expected, :? ScrollViewer when abs (deltaY - expected) <= 0.5 ->
    dispatch (HexdumpMsg ClearPendingScrollRestore)
  | Some _, _ when abs deltaY <= 0.0 ->
    dispatch (HexdumpMsg ClearPendingScrollRestore)
  | Some _, _ ->
    dispatch (HexdumpMsg ClearPendingScrollRestore)
    dispatch (HexdumpMsg(ScrollOffsetBy(deltaY)))
  | None, _ ->
    if abs deltaY <= 0.0 then
      ()
    else
      dispatch (HexdumpMsg(ScrollOffsetBy(deltaY)))

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

let private addressView model width address =
  TextBlock.create [
    TextBlock.width width
    TextBlock.margin (0.0, 0.0, 8.0, 0.0)
    TextBlock.text address
    TextBlock.foreground model.Theme.Text.Address
    TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
    TextBlock.fontSize model.Theme.Font.Monospace.FontSize
  ]

let private hexBytesView model width hexText =
  TextBlock.create [
    TextBlock.width width
    TextBlock.text hexText
    TextBlock.foreground model.Theme.Text.Primary
    TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
    TextBlock.fontSize model.Theme.Font.Monospace.FontSize
  ]

let private asciiView model width asciiText =
  TextBlock.create [
    TextBlock.width width
    TextBlock.margin (12.0, 0.0, 0.0, 0.0)
    TextBlock.text asciiText
    TextBlock.foreground model.Theme.Text.Secondary
    TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
    TextBlock.fontSize model.Theme.Font.Monospace.FontSize
  ]

let private rowView model viewState doc bytesPerRow rowIndex rowBytes =
  let offset = rowIndex * bytesPerRow
  let numDigits = viewState.AddressDigits
  let charWidth = max viewState.CharWidth 1.0
  let rowHeight = max viewState.RowHeight 1.0
  let addressWidth = charWidth * float (numDigits + 2)
  let hexWidth = charWidth * float (max 0 (bytesPerRow * 3 - 1))
  let asciiWidth = charWidth * float bytesPerRow
  let address = formatAddress numDigits doc.BaseAddress offset
  let hexText = formatHexBytes rowBytes
  let asciiText = formatAscii rowBytes
  Border.create [
    Canvas.left 0.0
    Canvas.top (float rowIndex * rowHeight)
    Border.height rowHeight
    Border.padding (8.0, 1.0, 8.0, 1.0)
    Border.background model.Theme.Common.Transparent
    Border.child (
      StackPanel.create [
        StackPanel.orientation Orientation.Horizontal
        StackPanel.children [
          addressView model addressWidth address :> IView
          hexBytesView model hexWidth hexText
          if viewState.ShowAscii then asciiView model asciiWidth asciiText
          else ()
        ]
      ]
    )
  ] |> View.withKey $"hex-row-{rowIndex}" :> IView

let private computeTotalRows docLength bytesPerRow =
  if docLength <= 0L then 0
  else int ((docLength + int64 bytesPerRow - 1L) / int64 bytesPerRow)

let private sliceRowBytes (doc: HexDocument) bytesPerRow rowIndex =
  let offset = rowIndex * bytesPerRow
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
  match model.Hexdump.Document, model.Hexdump.View with
  | Some doc, Some viewState ->
    let bytesPerRow = max 1 viewState.BytesPerRow
    let totalRows = computeTotalRows doc.Length bytesPerRow
    let startRow, endRow = computeVisibleRowRange viewState totalRows
    let rowHeight = max viewState.RowHeight 1.0
    let canvasHeight = rowHeight * float totalRows
    let scrollOffsetY = viewState.ScrollOffsetY
    ScrollViewer.create [
      ScrollViewer.offset (Vector(0.0, scrollOffsetY))
      ScrollViewer.onScrollChanged (onScrollChanged viewState dispatch)
      ScrollViewer.content (
        Canvas.create [
          Canvas.height canvasHeight
          Canvas.children [
            for rowIndex in startRow .. endRow - 1 do
              let rowBytes = sliceRowBytes doc bytesPerRow rowIndex
              rowView model viewState doc bytesPerRow rowIndex rowBytes
          ]
        ]
      )
    ] :> IView
  | _ ->
    emptyStateView model :> IView

let view model dispatch =
  Border.create [
    Border.background model.Theme.Window.Background
    Border.borderThickness 0.0
    Border.child (bodyView model dispatch)
  ]
