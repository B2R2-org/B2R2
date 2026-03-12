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

module B2R2.RearEnd.BinExplore.GUI.Toolbar

open Avalonia
open Avalonia.Controls
open Avalonia.Layout
open Avalonia.Media
open Avalonia.FuncUI.DSL

let view (model: Model) (_dispatch: Message -> unit) =
  Border.create [
    Border.dock Dock.Top
    Border.background model.Theme.Panel.AltBackground
    Border.borderThickness (0.0, 0.0, 0.0, 1.0)
    Border.borderBrush model.Theme.Panel.Border
    Border.padding (8.0, 4.0, 8.0, 4.0)
    Border.child (
      StackPanel.create [
        StackPanel.orientation Orientation.Horizontal
        StackPanel.spacing 4.0
        StackPanel.children [
          TextBox.create [
            TextBox.width 240.0
            TextBox.height 24.0
            TextBox.fontSize 12.0
            TextBox.watermark "Search..."
            TextBox.verticalContentAlignment VerticalAlignment.Center
            TextBox.background model.Theme.Panel.Background
            TextBox.foreground model.Theme.Text.Primary
            TextBox.borderBrush model.Theme.Panel.Border
            TextBox.borderThickness (1.0, 1.0, 1.0, 1.0)
            TextBox.cornerRadius (CornerRadius(4.0, 0.0, 0.0, 4.0))
            TextBox.padding (6.0, 0.0)
          ]
          Button.create [
            Button.width 26.0
            Button.height 24.0
            Button.background model.Theme.Panel.Background
            Button.borderBrush model.Theme.Panel.Border
            Button.borderThickness (1.0, 1.0, 1.0, 1.0)
            Button.cornerRadius (CornerRadius(0.0, 4.0, 4.0, 0.0))
            Button.padding (4.0, 0.0)
            Button.content (
              Image.create [
                Image.source (IconAssets.searchIcon model)
                Image.width 14.0
                Image.height 14.0
                Image.stretch Stretch.Uniform
                Image.verticalAlignment VerticalAlignment.Center
                Image.horizontalAlignment HorizontalAlignment.Center
              ]
            )
          ]
        ]
      ]
    )
  ]
