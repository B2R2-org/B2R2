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

open Avalonia.Controls
open Avalonia.Controls.Primitives
open Avalonia.Controls.Presenters
open Avalonia.Layout
open Avalonia.Media
open Avalonia.FuncUI.DSL

let private functionList (model: Model) dispatch =
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
              TextBlock.create [
                TextBlock.text "Functions"
                TextBlock.fontSize 14.0
                TextBlock.fontWeight FontWeight.Bold
              ]
            )
          ]
          ListBox.create [
            ListBox.background "#252526"
            ListBox.dataItems model.Functions
            ListBox.selectedItem (
              match model.ActiveFunction with
              | None -> null
              | Some func -> box func
            )
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
        ScrollViewer.horizontalScrollBarVisibility ScrollBarVisibility.Auto
        ScrollViewer.verticalScrollBarVisibility ScrollBarVisibility.Disabled
        ScrollViewer.content (
          StackPanel.create [
            StackPanel.orientation Orientation.Horizontal
            StackPanel.children (
              allTabs
              |> List.map (fun tabName ->
                Border.create [
                  Border.background (getTabBorderColor model tabName)
                  Border.borderThickness (0.0, 0.0, 1.0, 0.0)
                  Border.borderBrush "#3E3E42"
                  Border.padding (10.0, 5.0, 5.0, 5.0)
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
                          TextBlock.onPointerPressed (fun _ ->
                            dispatch (SwitchTab tabName))
                        ] |> View.withKey tabName
                        Button.create [
                          Button.content "\u00D7"
                          Button.background "Transparent"
                          Button.foreground "#AAAAAA"
                          Button.borderThickness 0.0
                          Button.padding (5.0, 0.0, 5.0, 0.0)
                          Button.fontSize 16.0
                          Button.onClick (fun _ ->
                            dispatch (CloseTab tabName))
                        ] |> View.withKey tabName
                      ]
                    ]
                  )
                ]
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
