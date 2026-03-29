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

open Avalonia.Controls
open Avalonia.Layout
open Avalonia.Media
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types

let private popoutIconView model =
  Image.create [
    Image.source (IconAssets.popoutIcon model)
    Image.width 14.0
    Image.height 14.0
    Image.stretch Stretch.Uniform
  ]

let private headerView model dispatch =
  Border.create [
    Border.dock Dock.Top
    Border.background model.Theme.Panel.AltBackground
    Border.padding 8.0
    Border.child (
      Grid.create [
        Grid.columnDefinitions "*,Auto"
        Grid.children [
          TextBlock.create [
            TextBlock.text "Hex Overview"
            TextBlock.fontSize 13.0
            TextBlock.foreground model.Theme.Text.Secondary
            TextBlock.verticalAlignment VerticalAlignment.Center
          ]
          Button.create [
            Grid.column 1
            Button.width 24.0
            Button.height 24.0
            Button.padding 0.0
            Button.background model.Theme.Common.Transparent
            Button.borderThickness 0.0
            Button.content (popoutIconView model)
            Button.onClick (fun _ -> dispatch OpenHexdumpTab)
            ToolTip.tip "Open in Tab"
          ]
        ]
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

let private overviewBodyView model =
  match model.Hexdump.Document with
  | None ->
    emptyStateView model :> IView
  | Some doc ->
    StackPanel.create [
      StackPanel.margin 10.0
      StackPanel.spacing 8.0
      StackPanel.children [
        TextBlock.create [
          TextBlock.text $"Binary size: {doc.Length} bytes"
          TextBlock.foreground model.Theme.Text.Primary
          TextBlock.fontSize 14.0
        ]
        TextBlock.create [
          TextBlock.text $"Base address: 0x{doc.BaseAddress:X}"
          TextBlock.foreground model.Theme.Text.Secondary
          TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
          TextBlock.fontSize model.Theme.Font.Monospace.FontSize
        ]
        TextBlock.create [
          TextBlock.text "Overview minimap placeholder."
          TextBlock.foreground model.Theme.Text.Muted
          TextBlock.fontSize 13.0
        ]
        TextBlock.create [
          TextBlock.text "This panel will become a high-level binary minimap."
          TextBlock.foreground model.Theme.Text.Muted
          TextBlock.textWrapping TextWrapping.Wrap
          TextBlock.fontSize 12.0
        ]
      ]
    ] :> IView

let view model dispatch =
  Border.create [
    Border.background model.Theme.Panel.Background
    Border.borderThickness 1.0
    Border.borderBrush model.Theme.Panel.Border
    Border.child (
      DockPanel.create [
        DockPanel.children [
          headerView model dispatch
          overviewBodyView model
        ]
      ]
    )
  ]
