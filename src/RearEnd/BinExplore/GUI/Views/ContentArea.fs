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
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types

let private filterFunctions model =
  if String.IsNullOrWhiteSpace model.FunctionFilter then
    model.Functions
  else
    model.Functions
    |> List.filter (fun name ->
      name.Contains(model.FunctionFilter, StringComparison.OrdinalIgnoreCase))

let private functionList (model: Model) dispatch =
  let filteredFunctions = filterFunctions model
  let selectedFunction =
    match model.ActiveFunction with
    | Some func when List.contains func filteredFunctions -> box func
    | _ -> null
  Border.create [
    Border.background "#252526"
    Border.borderThickness 1.0
    Border.borderBrush "#3E3E42"
    Border.child (
      DockPanel.create [
        DockPanel.children [
          Border.create [
            Border.dock Dock.Top
            Border.background "#2D2D30"
            Border.padding 5.0
            Border.child (
              TextBox.create [
                TextBox.text model.FunctionFilter
                TextBox.watermark "Filter functions..."
                TextBox.fontSize 13.0
                TextBox.onTextChanged (fun text ->
                  dispatch (UpdateFunctionFilter text))
              ]
            )
          ]
          ListBox.create [
            ListBox.background "#252526"
            ListBox.dataItems filteredFunctions
            ListBox.selectedItem selectedFunction
            ListBox.autoScrollToSelectedItem true
            ListBox.onSelectedItemChanged (fun item ->
              if not (isNull item) then
                let funcName = item :?> string
                dispatch (OpenTab funcName)
              else
                ()
            )
            ListBox.onDoubleTapped (fun e ->
              match e.Source with
              | :? ContentPresenter as presenter ->
                let text = presenter.Content :?> string
                dispatch (PinTab text)
              | :? TextBlock as textBlock ->
                dispatch (PinTab textBlock.Text)
              | _ ->
                ()
            )
          ]
        ]
      ]
    )
  ]

let private getTabBorderColor (model: Model) tabName =
  if model.ActiveFunction = Some tabName then "#1E1E1E"
  else "#2D2D30"

let private getTabTextColor (model: Model) tabName =
  if model.ActiveFunction = Some tabName then "#FFFFFF"
  else "#AAAAAA"

let private getTabFontStyle (model: Model) tabName =
  if model.PreviewTab = Some tabName then FontStyle.Italic
  else FontStyle.Normal

let [<Literal>] private TabMaxWidth = 220.0

let [<Literal>] private TabTextMaxWidth = 165.0

let private onTabDrag tabName dispatch (e: DragEventArgs) =
  let draggedTab = DataTransferExtensions.TryGetText e.DataTransfer
  if not (String.IsNullOrWhiteSpace draggedTab) then
    dispatch (ReorderTab(draggedTab, tabName))
    e.DragEffects <- DragDropEffects.Move
  else
    e.DragEffects <- DragDropEffects.None
  e.Handled <- true

let private onTabClick tabName dispatch (e: PointerPressedEventArgs) =
  dispatch (SwitchTab tabName)
  dispatch (StartTabDrag tabName)
  let data = new DataTransfer()
  data.Add(DataTransferItem.CreateText tabName)
  DragDrop.DoDragDropAsync(e, data, DragDropEffects.Move)
  |> ignore

let private tabBar (model: Model) dispatch =
  let allTabs =
    match model.PreviewTab with
    | Some preview -> preview :: model.OpenTabs
    | _ -> model.OpenTabs
  Border.create [
    Border.dock Dock.Top
    Border.background "#2D2D30"
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
              |> List.map (fun tabName ->
                Border.create [
                  Border.background (getTabBorderColor model tabName)
                  Border.maxWidth TabMaxWidth
                  Border.borderThickness (0.0, 0.0, 1.0, 0.0)
                  Border.borderBrush "#3E3E42"
                  Border.padding (10.0, 5.0, 5.0, 5.0)
                  Control.allowDrop true
                  Control.onDragOver (onTabDrag tabName dispatch)
                  Control.onDrop (fun e ->
                    dispatch EndTabDrag
                    e.Handled <- true)
                  Border.child (
                    StackPanel.create [
                      StackPanel.orientation Orientation.Horizontal
                      StackPanel.children [
                        TextBlock.create [
                          StackPanel.verticalAlignment VerticalAlignment.Center
                          TextBlock.text tabName
                          TextBlock.background "Transparent"
                          TextBlock.foreground (getTabTextColor model tabName)
                          TextBlock.padding (5.0, 0.0, 0.0, 0.0)
                          TextBlock.fontSize 12.0
                          TextBlock.fontStyle (getTabFontStyle model tabName)
                          TextBlock.maxWidth TabTextMaxWidth
                          TextBlock.textWrapping TextWrapping.NoWrap
                          TextBlock.textTrimming TextTrimming.CharacterEllipsis
                          ToolTip.tip tabName
                          TextBlock.onPointerPressed (fun e ->
                            onTabClick tabName dispatch e)
                          TextBlock.onPointerReleased (fun _ ->
                            dispatch EndTabDrag)
                        ] |> View.withKey $"{tabName}-label"
                        Button.create [
                          Button.content "\u00D7"
                          Button.background "Transparent"
                          Button.foreground "#AAAAAA"
                          Button.borderThickness 0.0
                          Button.padding (5.0, 0.0, 5.0, 0.0)
                          Button.fontSize 16.0
                          Button.onClick (fun _ ->
                            dispatch (CloseTab tabName))
                        ] |> View.withKey $"{tabName}-close"
                      ]
                    ]
                  )
                ] |> View.withKey $"{tabName}-tab" :> IView
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
    Border.background "#1E1E1E"
    Border.borderThickness 1.0
    Border.borderBrush "#3E3E42"
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
                    $"Control Flow Graph for: {func}\n\n(Coming Soon)"
                  | None ->
                    "Select a function to view its control flow graph"
                )
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
        GridSplitter.background "#3E3E42"
        GridSplitter.resizeDirection GridResizeDirection.Columns
      ]
      cfgViewPanel model dispatch
    ]
  ]
