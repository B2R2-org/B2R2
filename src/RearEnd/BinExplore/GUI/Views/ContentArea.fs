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

module B2R2.RearEnd.BinExplore.GUI.ContentArea

open System
open Avalonia.Controls
open Avalonia.Controls.Primitives
open Avalonia.Controls.Presenters
open Avalonia.Layout
open Avalonia.Media
open Avalonia.Input
open Avalonia.FuncUI
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types
open Avalonia.Svg.Skia

let private splitByMatch (text: string) (query: string) =
  let rec loop start acc =
    let idx = text.IndexOf(query, start, StringComparison.OrdinalIgnoreCase)
    if idx < 0 then
      if start < text.Length then
        List.rev ((false, text.Substring start) :: acc)
      else
        List.rev acc
    else
      let acc =
        if idx > start then (false, text.Substring(start, idx - start)) :: acc
        else acc
      let matched = text.Substring(idx, query.Length)
      loop (idx + query.Length) ((true, matched) :: acc)
  if String.IsNullOrEmpty query then [ false, text ]
  else loop 0 []

let private functionLabelWithHighlight model func =
  let label = FunctionItem.displayName func
  let addressPrefix = $"{func.Address:X}: "
  let addressPrefixLen = addressPrefix.Length
  let query = model.FunctionFilter
  let parts =
    if String.IsNullOrWhiteSpace query then [ false, label ]
    else splitByMatch label query
  let mkText (color: string) isBold txt =
    TextBlock.create
      [ TextBlock.text txt
        TextBlock.foreground color
        TextBlock.fontFamily model.Theme.Font.FunctionText
        TextBlock.fontWeight
          (if isBold then FontWeight.Bold else FontWeight.Regular) ] :> IView
  let rec build pos parts acc =
    match parts with
    | [] -> List.rev acc
    | (isMatch, segment) :: rest ->
      if isMatch then
        let view = mkText model.Theme.Text.Highlight true segment
        build (pos + segment.Length) rest (view :: acc)
      else
        let remainingInAddress = max 0 (addressPrefixLen - pos)
        if remainingInAddress <= 0 then
          let view = mkText model.Theme.Text.Primary false segment
          build (pos + segment.Length) rest (view :: acc)
        elif remainingInAddress >= segment.Length then
          let view = mkText model.Theme.Text.Muted false segment
          build (pos + segment.Length) rest (view :: acc)
        else
          let addrPart = segment.Substring(0, remainingInAddress)
          let namePart = segment.Substring remainingInAddress
          let nameView = mkText model.Theme.Text.Primary false namePart
          let addrView = mkText model.Theme.Text.Muted false addrPart
          build (pos + segment.Length) rest (nameView :: addrView :: acc)
  build 0 parts []

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

let private functionList (model: Model) dispatch =
  let filteredFunctions = filterFunctions model
  let themeViewKey =
    match model.ThemeMode with
    | Builtin Dark -> "builtin-dark"
    | Builtin Light -> "builtin-light"
    | Custom(ThemeId themeId) -> $"custom-{themeId}"
  let selectedFunction =
    match model.ActiveFunction with
    | Some func when List.contains func filteredFunctions -> box func
    | _ -> null
  Border.create [
    Border.background model.Theme.Panel.Background
    Border.borderThickness 1.0
    Border.borderBrush model.Theme.Panel.Border
    Border.child (
      DockPanel.create [
        DockPanel.children [
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
                TextBox.onTextChanged (fun text ->
                  dispatch (UpdateFunctionFilter text))
              ]
            )
          ]
          ListBox.create [
            ListBox.background model.Theme.Panel.Background
            ListBox.foreground model.Theme.Text.Primary
            ListBox.dataItems filteredFunctions
            ItemsControl.itemTemplate (
              DataTemplateView<FunctionItem>.create (fun func ->
                StackPanel.create [
                  StackPanel.orientation Orientation.Horizontal
                  StackPanel.children (functionLabelWithHighlight model func)
                ]
              )
            )
            ListBox.selectedItem selectedFunction
            ListBox.autoScrollToSelectedItem true
            ListBox.onSelectedItemChanged (fun item ->
              if not (isNull item) then
                let func = item :?> FunctionItem
                dispatch (OpenTab func)
              else
                ()
            )
            ListBox.onDoubleTapped (fun e ->
              match e.Source with
              | :? ContentPresenter as presenter ->
                let func = presenter.Content :?> FunctionItem
                dispatch (PinTab func)
              | _ ->
                ()
            )
          ] |> View.withKey $"fnlist-{themeViewKey}-{model.FunctionFilter}"
        ]
      ]
    )
  ]

let private getTabBorderColor (model: Model) tab =
  if model.ActiveFunction = Some tab then model.Theme.Tab.ActiveBackground
  else model.Theme.Tab.InactiveBackground

let private getTabTextColor (model: Model) tab =
  if model.ActiveFunction = Some tab then model.Theme.Text.Primary
  else model.Theme.Text.Secondary

let private getTabFontStyle (model: Model) tab =
  if model.PreviewTab = Some tab then FontStyle.Italic
  else FontStyle.Normal

let [<Literal>] private TabMaxWidth = 220.0

let [<Literal>] private TabTextMaxWidth = 165.0

let private cfgTabIconLightSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/cfg-light.svg"
  svgImage :> IImage

let private cfgTabIconDarkSource: IImage =
  let svgImage = SvgImage()
  svgImage.Source <-
    SvgSource.Load "avares://B2R2.RearEnd.BinExplore/Assets/cfg-dark.svg"
  svgImage :> IImage

let private getCfgTabIconSource model =
  let isBrightTextColor =
    match Color.TryParse model.Theme.Text.Primary with
    | true, color ->
      let luminance =
        (0.299 * float color.R + 0.587 * float color.G + 0.114 * float color.B)
        / 255.0
      luminance >= 0.5
    | _ ->
      match model.ThemeMode with
      | Builtin Dark -> true
      | _ -> false
  if isBrightTextColor then cfgTabIconDarkSource
  else cfgTabIconLightSource

let private findTabByFuncID model funcID =
  let allTabs =
    match model.PreviewTab with
    | Some preview -> preview :: model.OpenTabs
    | None -> model.OpenTabs
  allTabs |> List.tryFind (fun tab -> tab.FuncID = funcID)

let private onTabDrag model targetTab dispatch (e: DragEventArgs) =
  let draggedTabID = DataTransferExtensions.TryGetText e.DataTransfer
  if not (String.IsNullOrWhiteSpace draggedTabID) then
    match findTabByFuncID model draggedTabID with
    | Some draggedTab ->
      dispatch (ReorderTab(draggedTab, targetTab))
      e.DragEffects <- DragDropEffects.Move
    | None ->
      e.DragEffects <- DragDropEffects.None
  else
    e.DragEffects <- DragDropEffects.None
  e.Handled <- true

let private onTabClick tab dispatch (e: PointerPressedEventArgs) =
  dispatch (SwitchTab tab)
  dispatch (StartTabDrag tab)
  let data = new DataTransfer()
  data.Add(DataTransferItem.CreateText tab.FuncID)
  DragDrop.DoDragDropAsync(e, data, DragDropEffects.Move)
  |> ignore

let private tabDisplayName (item: FunctionItem) = item.Name

let private tabKeySuffix tab = tab.FuncID

let private tabBar (model: Model) dispatch =
  let allTabs =
    match model.PreviewTab with
    | Some preview -> preview :: model.OpenTabs
    | _ -> model.OpenTabs
  Border.create [
    Border.dock Dock.Top
    Border.background model.Theme.Panel.AltBackground
    Border.borderThickness 0.0
    Border.child (
      ScrollViewer.create [
        Control.allowDrop true
        ScrollViewer.horizontalScrollBarVisibility ScrollBarVisibility.Auto
        ScrollViewer.verticalScrollBarVisibility ScrollBarVisibility.Disabled
        ScrollViewer.onPointerReleased (fun _ ->
          dispatch EndTabDrag)
        ScrollViewer.content (
          StackPanel.create [
            Control.allowDrop true
            StackPanel.orientation Orientation.Horizontal
            StackPanel.children (
              allTabs
              |> List.map (fun tab ->
                Border.create [
                  Border.background (getTabBorderColor model tab)
                  Border.maxWidth TabMaxWidth
                  Border.borderThickness (0.0, 0.0, 1.0, 0.0)
                  Border.borderBrush model.Theme.Panel.Border
                  Border.padding (10.0, 5.0, 5.0, 5.0)
                  Control.allowDrop true
                  Control.onDragOver (onTabDrag model tab dispatch)
                  Control.onDrop (fun e ->
                    dispatch EndTabDrag
                    e.Handled <- true)
                  Border.child (
                    StackPanel.create [
                      StackPanel.orientation Orientation.Horizontal
                      StackPanel.children [
                        StackPanel.create [
                          StackPanel.orientation Orientation.Horizontal
                          StackPanel.verticalAlignment VerticalAlignment.Center
                          StackPanel.background model.Theme.Common.Transparent
                          Control.onPointerPressed (fun e ->
                            onTabClick tab dispatch e)
                          Control.onPointerReleased (fun _ ->
                            dispatch EndTabDrag)
                          ToolTip.tip (tabDisplayName tab)
                          StackPanel.children [
                            Image.create [
                              Image.source (getCfgTabIconSource model)
                              Image.width 14.0
                              Image.height 14.0
                              Image.stretch Stretch.Uniform
                              Image.verticalAlignment VerticalAlignment.Center
                              Image.margin (0.0, 0.0, 4.0, 0.0)
                            ] |> View.withKey $"{tabKeySuffix tab}-icon"
                            TextBlock.create [
                              StackPanel.verticalAlignment
                                VerticalAlignment.Center
                              TextBlock.text (tabDisplayName tab)
                              TextBlock.fontFamily
                                model.Theme.Font.FunctionText
                              TextBlock.background
                                model.Theme.Common.Transparent
                              TextBlock.foreground
                                (getTabTextColor model tab)
                              TextBlock.padding (5.0, 0.0, 5.0, 0.0)
                              TextBlock.fontSize 14.0
                              TextBlock.fontStyle
                                (getTabFontStyle model tab)
                              TextBlock.maxWidth TabTextMaxWidth
                              TextBlock.textWrapping TextWrapping.NoWrap
                              TextBlock.textTrimming
                                TextTrimming.CharacterEllipsis
                            ] |> View.withKey $"{tabKeySuffix tab}-label"
                          ]
                        ] |> View.withKey $"{tabKeySuffix tab}-clickarea"
                        Button.create [
                          StackPanel.verticalAlignment VerticalAlignment.Center
                          Button.content "\u00D7"
                          Button.background model.Theme.Common.Transparent
                          Button.foreground model.Theme.Tab.CloseForeground
                          Button.borderThickness 0.0
                          Button.padding (5.0, 0.0, 5.0, 0.0)
                          Button.fontSize 16.0
                          Button.onClick (fun _ ->
                            dispatch (CloseTab tab))
                        ] |> View.withKey $"{tabKeySuffix tab}-close"
                      ]
                    ]
                  )
                ] |> View.withKey $"{tabKeySuffix tab}-tab" :> IView
              )
            )
          ]
        )
      ]
    )
  ]

let private cfgViewPanel (model: Model) dispatch =
  Border.create [
    Grid.column 2 (* Third column *)
    Border.background model.Theme.Window.Background
    Border.borderThickness 1.0
    Border.borderBrush model.Theme.Panel.Border
    Border.child (
      DockPanel.create [
        DockPanel.children [
          tabBar model dispatch
          ScrollViewer.create [
            ScrollViewer.content (
              TextBlock.create [
                TextBlock.text (
                  match model.ActiveFunction with
                  | Some func ->
                    $"Control Flow Graph for: {tabDisplayName func}"
                  | None ->
                    "Select a function to view its control flow graph"
                )
                TextBlock.foreground model.Theme.Text.Primary
                TextBlock.fontSize 14.0
                TextBlock.margin 10.0
              ]
            )
          ]
        ]
      ]
    )
  ]

let view model dispatch =
  Grid.create [
    Grid.columnDefinitions "250,5,*"
    Grid.children [
      functionList model dispatch
      GridSplitter.create [
        GridSplitter.column 1
        GridSplitter.background model.Theme.Panel.Border
        GridSplitter.resizeDirection GridResizeDirection.Columns
      ]
      cfgViewPanel model dispatch
    ]
  ]
