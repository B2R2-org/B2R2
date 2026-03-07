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
module B2R2.RearEnd.BinExplore.GUI.CFGPanel

open Avalonia.Controls
open Avalonia.FuncUI.DSL

let view (model: Model) _dispatch =
  Border.create [
    Border.background model.Theme.Window.Background
    Border.borderThickness 1.0
    Border.borderBrush model.Theme.Panel.Border
    Border.child (
      ScrollViewer.create [
        ScrollViewer.content (
          TextBlock.create [
            TextBlock.text (
              match model.ActiveFunction with
              | Some _ ->
                $"Control Flow Graph."
              | None ->
                "Select a function to view its control flow graph"
            )
            TextBlock.foreground model.Theme.Text.Primary
            TextBlock.fontSize 14.0
            TextBlock.margin 10.0
          ]
        )
      ]
    )
  ]
