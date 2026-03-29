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
open Avalonia.Controls
open Avalonia.Layout
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types

let [<Literal>] private MaxPreviewRows = 256

let private panelHeaderView model (doc: HexDocument option) =
  let title =
    match doc with
    | Some doc -> $"Hexdump ({doc.Length} bytes)"
    | None -> "Hexdump"
  Border.create [
    Border.dock Dock.Top
    Border.background model.Theme.Panel.AltBackground
    Border.padding 8.0
    Border.child (
      TextBlock.create [
        TextBlock.text title
        TextBlock.fontSize 13.0
        TextBlock.foreground model.Theme.Text.Secondary
      ]
    )
  ]

let private emptyStateView model =
  TextBlock.create [
    TextBlock.text "No bytes loaded."
    TextBlock.margin 10.0
    TextBlock.foreground model.Theme.Text.Muted
    TextBlock.fontSize 13.0
  ]

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

let private addressView model address =
  TextBlock.create [
    TextBlock.margin (0.0, 0.0, 8.0, 0.0)
    TextBlock.text address
    TextBlock.foreground model.Theme.Text.Address
    TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
    TextBlock.fontSize model.Theme.Font.Monospace.FontSize
  ]

let private hexBytesView model hexText =
  TextBlock.create [
    TextBlock.text hexText
    TextBlock.foreground model.Theme.Text.Primary
    TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
    TextBlock.fontSize model.Theme.Font.Monospace.FontSize
  ]

let private asciiView model asciiText =
  TextBlock.create [
    TextBlock.margin (12.0, 0.0, 0.0, 0.0)
    TextBlock.text asciiText
    TextBlock.foreground model.Theme.Text.Secondary
    TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
    TextBlock.fontSize model.Theme.Font.Monospace.FontSize
  ]

let private rowView model (doc: HexDocument) bytesPerRow rowIndex rowBytes =
  let offset = rowIndex * bytesPerRow
  let numDigits = model.Hexdump.SideView.AddressDigits
  let address = formatAddress numDigits doc.BaseAddress offset
  let hexText = formatHexBytes rowBytes
  let asciiText = formatAscii rowBytes
  StackPanel.create [
    StackPanel.orientation Orientation.Horizontal
    StackPanel.margin (8.0, 1.0, 8.0, 1.0)
    StackPanel.children [
      addressView model address :> IView
      hexBytesView model hexText :> IView
      if model.Hexdump.SideView.ShowAscii then
        asciiView model asciiText :> IView
      else
        ()
    ]
  ]

let private previewNoticeView model totalRows =
  TextBlock.create [
    TextBlock.text $"Showing first {MaxPreviewRows} of {totalRows} rows."
    TextBlock.margin (8.0, 8.0, 8.0, 4.0)
    TextBlock.foreground model.Theme.Text.Muted
    TextBlock.fontSize 12.0
  ]

let private bodyView model =
  match model.Hexdump.Document with
  | None ->
    emptyStateView model :> IView
  | Some doc ->
    let bytesPerRow = max 1 model.Hexdump.SideView.BytesPerRow
    let rows = doc.Bytes |> Array.chunkBySize bytesPerRow
    let totalRows = rows.Length
    let previewRows = rows |> Array.truncate MaxPreviewRows
    ScrollViewer.create [
      ScrollViewer.content (
        StackPanel.create [
          StackPanel.children [
            if totalRows > MaxPreviewRows then
              previewNoticeView model totalRows :> IView
            yield!
              previewRows
              |> Array.mapi (fun rowIndex rowBytes ->
                rowView model doc bytesPerRow rowIndex rowBytes :> IView)
              |> Array.toList
          ]
        ]
      )
    ]

let view model dispatch =
  Border.create [
    Border.background model.Theme.Panel.Background
    Border.borderThickness 1.0
    Border.borderBrush model.Theme.Panel.Border
    Border.child (
      DockPanel.create [
        DockPanel.children [
          panelHeaderView model model.Hexdump.Document
          bodyView model
        ]
      ]
    )
  ]
