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

open System
open Avalonia.FuncUI.DSL
open Avalonia.Input
open Avalonia.Controls
open Avalonia.Layout
open Avalonia.Media
open Avalonia.Media.Imaging
open Avalonia.Platform

let private tryGetDroppedFilePath (e: DragEventArgs) =
  let files = DataTransferExtensions.TryGetFiles e.DataTransfer
  if isNull files then
    None
  else
    files
    |> Seq.tryHead
    |> Option.map (fun f -> f.Path.LocalPath)

let private onDragOver (e: DragEventArgs) =
  e.DragEffects <-
    if e.DataTransfer.Contains DataFormat.File then DragDropEffects.Copy
    else DragDropEffects.None
  e.Handled <- true

let private onDrop dispatch (e: DragEventArgs) =
  tryGetDroppedFilePath e
  |> Option.iter (fun path -> dispatch (OpenBinary path))
  e.Handled <- true

let private imageView imageUri =
  Image.create [
    Image.source (new Bitmap(AssetLoader.Open(imageUri)))
    Image.width 200.0
    Image.height 200.0
    Image.stretch Stretch.Uniform
    Image.verticalAlignment VerticalAlignment.Center
    Image.margin (0.0, 0.0, 40.0, 0.0)
  ]

let private textPanelView model =
  StackPanel.create [
    StackPanel.verticalAlignment VerticalAlignment.Center
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

let view model dispatch =
  let imageUri = Uri "avares://B2R2.RearEnd.BinExplore/Assets/b2r2.png"
  Grid.create [
    Grid.background model.Theme.Panel.Background
    Control.allowDrop true
    Control.onDragOver onDragOver
    Control.onDrop (onDrop dispatch)
    Grid.children [
      Border.create [
        Border.child (
          StackPanel.create [
            StackPanel.verticalAlignment VerticalAlignment.Center
            StackPanel.horizontalAlignment HorizontalAlignment.Center
            StackPanel.orientation Orientation.Horizontal
            StackPanel.children [
              imageView imageUri
              textPanelView model
            ]
          ]
        )
      ]
    ]
  ]
