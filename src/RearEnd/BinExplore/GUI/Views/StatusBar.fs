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
open Avalonia.FuncUI.Types
open Avalonia.Controls
open Avalonia.Layout
open Avalonia.Media

let private messageView model msg =
  TextBlock.create [
    TextBlock.dock Dock.Left
    TextBlock.margin (8.0, 0.0)
    TextBlock.text msg
    TextBlock.fontSize model.Theme.Font.Scale.Small
    TextBlock.foreground model.Theme.StatusBar.Foreground
    TextBlock.verticalAlignment VerticalAlignment.Center
  ]

let private separator model =
  Border.create [
    Border.dock Dock.Left
    Border.width 1.0
    Border.margin (5.0, 2.0, 5.0, 2.0)
    Border.background model.Theme.StatusBar.Separator
  ]

let private filePathView model path =
  SelectableTextBlock.create [
    TextBlock.dock Dock.Left
    TextBlock.margin (8.0, 0.0)
    TextBlock.width 300.0
    TextBlock.clipToBounds true
    TextBlock.text path
    TextBlock.fontSize model.Theme.Font.Scale.Small
    TextBlock.foreground model.Theme.StatusBar.Foreground
    TextBlock.verticalAlignment VerticalAlignment.Center
    ToolTip.tip (
      TextBlock.create [
        TextBlock.text path
        TextBlock.textWrapping TextWrapping.NoWrap
      ]
    )
  ]

let private fileFormatView model fmt =
  TextBlock.create [
    TextBlock.dock Dock.Left
    TextBlock.margin (8.0, 0.0)
    TextBlock.text fmt
    TextBlock.fontSize model.Theme.Font.Scale.Small
    TextBlock.foreground model.Theme.StatusBar.Foreground
    TextBlock.verticalAlignment VerticalAlignment.Center
    TextBlock.textAlignment TextAlignment.Center
  ]

let private offsetTextView model (foreground: string) text =
  SelectableTextBlock.create [
    TextBlock.text text
    TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
    TextBlock.fontSize model.Theme.Font.Monospace.FontSize
    TextBlock.foreground foreground
    TextBlock.verticalAlignment VerticalAlignment.Center
  ] :> IView

let private rangeSeparatorView model =
  offsetTextView model model.Theme.StatusBar.MutedForeground " - "

let private addressRangeViews model range =
  if range.Start = range.End then
    [ offsetTextView model model.Theme.StatusBar.HighlightForeground
        $"0x{range.Start:X8}" ]
  else
    [ offsetTextView model model.Theme.StatusBar.HighlightForeground
        $"0x{range.Start:X8}"
      rangeSeparatorView model
      offsetTextView model model.Theme.StatusBar.HighlightForeground
        $"0x{range.End:X8}" ]

let private sectionRangeViews model sectionRange =
  match sectionRange with
  | NoSection -> []
  | SingleSection name ->
    [ offsetTextView model model.Theme.StatusBar.MutedForeground " ("
      offsetTextView model model.Theme.StatusBar.PrimaryForeground name
      offsetTextView model model.Theme.StatusBar.MutedForeground ")" ]
  | MultipleSections(s1, s2) ->
    [ offsetTextView model model.Theme.StatusBar.MutedForeground " ("
      offsetTextView model model.Theme.StatusBar.PrimaryForeground s1
      rangeSeparatorView model
      offsetTextView model model.Theme.StatusBar.PrimaryForeground s2
      offsetTextView model model.Theme.StatusBar.MutedForeground ")" ]

let private fileOffsetCtxView model offsetCtx =
  match offsetCtx with
  | Some ctx ->
    StackPanel.create [
      StackPanel.dock Dock.Left
      StackPanel.margin (8.0, 0.0)
      StackPanel.orientation Orientation.Horizontal
      StackPanel.spacing 0.0
      StackPanel.verticalAlignment VerticalAlignment.Center
      StackPanel.children [
        yield! addressRangeViews model ctx.Range
        yield! sectionRangeViews model ctx.SectionRange
      ]
    ] :> IView
  | None ->
    messageView model "" :> IView

let private getDisplayedOffsetRangeInfo model =
  model.OffsetSnapshot.Selection
  |> Option.orElse model.OffsetSnapshot.Viewport

let view (model: Model) =
  Border.create [
    Border.dock Dock.Bottom
    Border.background model.Theme.StatusBar.Background
    Border.padding 4.0
    Border.child (
      DockPanel.create [
        DockPanel.children (
          match model.StatusBarState with
          | EmptyStatus ->
            [ messageView model "" ]
          | MessageOnly msg ->
            [ messageView model msg ]
          | FileLoaded(path, fmt) ->
            [ filePathView model path
              separator model
              fileFormatView model fmt
              separator model
              fileOffsetCtxView model (getDisplayedOffsetRangeInfo model) ]
        )
      ]
    )
  ]
