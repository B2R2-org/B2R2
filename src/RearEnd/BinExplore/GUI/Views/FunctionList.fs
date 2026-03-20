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
module B2R2.RearEnd.BinExplore.GUI.FunctionList

open System
open Avalonia.Controls
open Avalonia.Controls.Presenters
open Avalonia.Layout
open Avalonia.Media
open Avalonia.Input
open Avalonia.FuncUI
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types

let private userInputView model dispatch =
  Border.create [
    Border.dock Dock.Top
    Border.background model.Theme.Panel.AltBackground
    Border.padding 5.0
    Border.child (
      TextBox.create [
        TextBox.text model.FunctionFilter
        TextBox.watermark "Filter functions..."
        TextBox.fontSize 13.0
        TextBox.foreground model.Theme.Text.Primary
        TextBox.onTextChanged (fun text -> dispatch (UpdateFunctionFilter text))
      ]
    )
  ]

let private filterFunctions model =
  if String.IsNullOrWhiteSpace model.FunctionFilter then
    model.Functions
  else
    model.Functions
    |> List.filter (fun func ->
      FunctionItem.displayName(func).Contains(
        model.FunctionFilter,
        StringComparison.OrdinalIgnoreCase
      ))

let private functionContextMenu model dispatch func =
  ContextMenu.create [
    ContextMenu.viewItems [
      MenuItem.create [
        MenuItem.header "Open CFG"
        MenuItem.onClick (fun _ -> dispatch (OpenCFGTab func))
      ]
      MenuItem.create [
        MenuItem.header "Pin CFG Tab"
        MenuItem.onClick (fun _ -> dispatch (PinCFGTab func))
      ]
    ]
  ]

let private onFunctionPressed dispatch func (e: PointerPressedEventArgs) =
  let props = e.GetCurrentPoint(null).Properties
  if props.IsLeftButtonPressed then
    dispatch (OpenCFGTab func)
  elif props.IsRightButtonPressed then
    e.Handled <- true
  else
    ()

let private mkText model (color: string) isBold txt =
  TextBlock.create
    [ TextBlock.text txt
      TextBlock.foreground color
      TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
      TextBlock.fontWeight
        (if isBold then FontWeight.Bold else FontWeight.Regular) ] :> IView

let private functionLabelWithHighlight model func =
  let label = FunctionItem.displayName func
  let addressPrefix = $"{func.Address:X}: "
  let addressPrefixLen = addressPrefix.Length
  let query = model.FunctionFilter
  let parts =
    if String.IsNullOrWhiteSpace query then [ false, label ]
    else StringUtils.splitByMatch query label
  let rec build pos parts acc =
    match parts with
    | [] -> List.rev acc
    | (isMatch, segment) :: rest ->
      if isMatch then
        let view = mkText model model.Theme.Text.Highlight true segment
        build (pos + segment.Length) rest (view :: acc)
      else
        let remainingInAddress = max 0 (addressPrefixLen - pos)
        if remainingInAddress <= 0 then
          let view = mkText model model.Theme.Text.Primary false segment
          build (pos + segment.Length) rest (view :: acc)
        elif remainingInAddress >= segment.Length then
          let view = mkText model model.Theme.Text.Muted false segment
          build (pos + segment.Length) rest (view :: acc)
        else
          let addrPart = segment.Substring(0, remainingInAddress)
          let namePart = segment.Substring remainingInAddress
          let nameView = mkText model model.Theme.Text.Primary false namePart
          let addrView = mkText model model.Theme.Text.Muted false addrPart
          build (pos + segment.Length) rest (nameView :: addrView :: acc)
  build 0 parts []

let private listItemTemplate model dispatch =
  DataTemplateView<FunctionItem>.create (fun fn ->
    Border.create [
      Border.background Brushes.Transparent
      Control.contextMenu (functionContextMenu model dispatch fn)
      Control.onPointerPressed (onFunctionPressed dispatch fn)
      Border.child (
        StackPanel.create [
          StackPanel.orientation Orientation.Horizontal
          StackPanel.children (functionLabelWithHighlight model fn)
        ]
      )
    ]
  )

let private onSelectedItemChanged dispatch (item: obj) =
  if not (isNull item) then
    let fn = item :?> FunctionItem
    dispatch (OpenCFGTab fn)
  else
    ()

let onDoubleClick dispatch (e: TappedEventArgs) =
  match e.Source with
  | :? ContentPresenter as presenter ->
    let fn = presenter.Content :?> FunctionItem
    dispatch (PinCFGTab fn)
  | :? TextBlock as textBlock ->
    let fn = textBlock.DataContext :?> FunctionItem
    dispatch (PinCFGTab fn)
  | _ ->
    ()

let private listBoxView model dispatch =
  let filteredFunctions = filterFunctions model
  let themeViewKey =
    match model.ThemeMode with
    | Builtin Dark -> "builtin-dark"
    | Builtin Light -> "builtin-light"
    | Custom(ThemeId themeId) -> $"custom-{themeId}"
  let selectedFunction =
    match model.ActiveTab with
    | Some { Content = CFGTab(func, _) } ->
      if List.contains func filteredFunctions then box func
      else null
    | _ -> null
  ListBox.create [
    ListBox.background model.Theme.Panel.Background
    ListBox.foreground model.Theme.Text.Primary
    ListBox.dataItems filteredFunctions
    ItemsControl.itemTemplate (listItemTemplate model dispatch)
    ListBox.selectedItem selectedFunction
    ListBox.autoScrollToSelectedItem true
    ListBox.onSelectedItemChanged (onSelectedItemChanged dispatch)
    ListBox.onDoubleTapped (onDoubleClick dispatch)
  ] |> View.withKey $"fnlist-{themeViewKey}-{model.FunctionFilter}"

let view (model: Model) dispatch =
  Border.create [
    Border.background model.Theme.Panel.Background
    Border.borderThickness 1.0
    Border.borderBrush model.Theme.Panel.Border
    Border.child (
      DockPanel.create [
        DockPanel.children [
          userInputView model dispatch
          listBoxView model dispatch
        ]
      ]
    )
  ]
