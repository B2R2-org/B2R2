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

module B2R2.RearEnd.BinExplore.GUI.Welcome

open Avalonia.FuncUI.DSL
open Avalonia.Controls
open Avalonia.Layout
open Avalonia.Media

let view model _dispatch =
  Grid.create [
    Grid.background model.Theme.Window.Background
    Grid.children [
      Border.create [
        Border.child (
          StackPanel.create [
            StackPanel.verticalAlignment VerticalAlignment.Center
            StackPanel.horizontalAlignment HorizontalAlignment.Center
            StackPanel.children [
              TextBlock.create [
                TextBlock.text "B2R2 BinExplore"
                TextBlock.fontSize 32.0
                TextBlock.fontWeight FontWeight.Bold
                TextBlock.foreground model.Theme.Text.Primary
                TextBlock.horizontalAlignment HorizontalAlignment.Center
                TextBlock.margin (0.0, 0.0, 0.0, 20.0)
              ]
              TextBlock.create [
                TextBlock.text "Open a binary file to start exploring"
                TextBlock.fontSize 16.0
                TextBlock.foreground model.Theme.Text.Muted
                TextBlock.horizontalAlignment HorizontalAlignment.Center
              ]
            ]
          ]
        )
      ]
    ]
  ]
