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
open Avalonia.FuncUI
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types
open B2R2.RearEnd.BinExplore

let searchView model =
  Grid.create [
    Grid.width 240.0
    Grid.height 24.0
    Grid.children [
      TextBox.create
        [ TextBox.width 240.0
          TextBox.height 24.0
          TextBox.fontSize 12.0
          TextBox.watermark "Search..."
          TextBox.verticalContentAlignment VerticalAlignment.Center
          TextBox.background model.Theme.Panel.Background
          TextBox.foreground model.Theme.Text.Primary
          TextBox.borderBrush model.Theme.Panel.Border
          TextBox.borderThickness (1.0, 1.0, 1.0, 1.0)
          TextBox.cornerRadius (CornerRadius(4.0, 0.0, 0.0, 4.0))
          TextBox.padding (6.0, 0.0, 28.0, 0.0) ] :> IView
      Button.create
        [ Button.width 26.0
          Button.height 24.0
          Button.horizontalAlignment HorizontalAlignment.Right
          Button.background model.Theme.Panel.Background
          Button.borderBrush model.Theme.Panel.Border
          Button.borderThickness (1.0, 1.0, 1.0, 1.0)
          Button.cornerRadius (CornerRadius(0.0, 4.0, 4.0, 0.0))
          Button.padding (4.0, 0.0)
          Button.margin (0.0, 0.0, 2.0, 0.0)
          Button.content (
            Image.create [
              Image.source (IconAssets.searchIcon model)
              Image.width 14.0
              Image.height 14.0
              Image.stretch Stretch.Uniform
              Image.verticalAlignment VerticalAlignment.Center
              Image.horizontalAlignment HorizontalAlignment.Center
            ]) ]
    ]
  ]

let private graphSelectView model dispatch =
  let currentCFGKind, isEnabled, tabKey =
    match model.ActiveTab with
    | Some { ID = id; Content = CFGTab(_, Loaded(_, { CFGKind = kind })) } ->
      kind, true, id
    | _ -> CFGKind.Disasm, false, "none"
  ComboBox.create [
    ComboBox.width 100.0
    ComboBox.maxHeight 200.0
    ComboBox.background model.Theme.Panel.Background
    ComboBox.foreground model.Theme.Text.Primary
    ComboBox.borderBrush model.Theme.Panel.Border
    ComboBox.borderThickness 1.0
    ComboBox.dataItems [ CFGKind.Disasm; CFGKind.LowUIR; CFGKind.SSA ]
    ComboBox.selectedItem (box currentCFGKind)
    ComboBox.isEnabled isEnabled
    ComboBox.onSelectedItemChanged (fun args ->
      match args with
      | :? CFGKind as newKind -> dispatch (ChangeCFGKind newKind)
      | _ -> ())
    ItemsControl.itemTemplate (
      DataTemplateView<string>.create (fun txt ->
        TextBlock.create [
          TextBlock.text txt
          TextBlock.foreground model.Theme.Text.Primary
          TextBlock.fontFamily model.Theme.Font.Function.FontFamily
          TextBlock.fontSize 12.0
          TextBlock.padding (4.0, 2.0)
        ]
      )
    )
  ] |> View.withKey $"graph-select-{tabKey}"

let view (model: Model) (dispatch: Message -> unit) =
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
          searchView model
          graphSelectView model dispatch
        ]
      ]
    )
  ]
