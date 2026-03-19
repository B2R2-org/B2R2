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

module B2R2.RearEnd.BinExplore.GUI.StatusBar

open Avalonia.FuncUI.DSL
open Avalonia.Controls
open Avalonia.Layout

let private separator model =
  Border.create [
    Border.dock Dock.Left
    Border.width 1.0
    Border.margin (5.0, 2.0, 5.0, 2.0)
    Border.background model.Theme.Panel.Border
  ]

let view (model: Model) =
  let s = model.StatusBarState
  Border.create [
    Border.dock Dock.Bottom
    Border.background model.Theme.Panel.AltBackground
    Border.borderThickness 1.0
    Border.borderBrush model.Theme.Panel.Border
    Border.padding 5.0
    Border.child (
      DockPanel.create [
        DockPanel.children [
          TextBlock.create [
            TextBlock.dock Dock.Left
            TextBlock.width 300.0
            TextBlock.clipToBounds true
            TextBlock.text s.FilePath
            TextBlock.fontSize 12.0
            TextBlock.foreground model.Theme.Text.Secondary
            TextBlock.verticalAlignment VerticalAlignment.Center
          ]
          separator model
          TextBlock.create [
            TextBlock.dock Dock.Left
            TextBlock.width 50.0
            TextBlock.clipToBounds true
            TextBlock.text s.FileType
            TextBlock.fontSize 12.0
            TextBlock.foreground model.Theme.Text.Secondary
            TextBlock.verticalAlignment VerticalAlignment.Center
          ]
          separator model
          TextBlock.create [
            TextBlock.text s.Message
            TextBlock.fontSize 12.0
            TextBlock.foreground model.Theme.Text.Secondary
            TextBlock.verticalAlignment VerticalAlignment.Center
          ]
        ]
      ]
    )
  ]