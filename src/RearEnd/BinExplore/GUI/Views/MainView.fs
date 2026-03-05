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

module B2R2.RearEnd.BinExplore.GUI.MainView

open Avalonia.FuncUI.DSL
open Avalonia.Controls
open Avalonia.Layout
open Avalonia.Media

let private menuBar (model: Model) dispatch =
  Menu.create [
    Menu.dock Dock.Top
    Menu.viewItems [
      MenuItem.create [
        MenuItem.header "File"
        MenuItem.viewItems [
          MenuItem.create [
            MenuItem.header "Open Binary..."
            MenuItem.onClick (fun _ -> dispatch (LoadBinary ""))
          ]
          MenuItem.create [
            MenuItem.header "Close Workspace"
            MenuItem.isEnabled (model.LoadedBinary.IsSome)
            MenuItem.onClick (fun _ -> dispatch CloseWorkspace)
          ]
          MenuItem.create [
            MenuItem.header "-"
          ]
          MenuItem.create [
            MenuItem.header "Exit"
            MenuItem.onClick (fun _ -> dispatch NoOp)
          ]
        ]
      ]
    ]
  ]

let private statusBar (model: Model) =
  Border.create [
    Border.dock Dock.Bottom
    Border.background "#2D2D30"
    Border.borderThickness 1.0
    Border.borderBrush "#3E3E42"
    Border.padding 5.0
    Border.child (
      TextBlock.create [
        TextBlock.text model.StatusMessage
        TextBlock.fontSize 12.0
      ]
    )
  ]

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
          ScrollViewer.create [
            ScrollViewer.content (
              StackPanel.create [
                StackPanel.children (
                  model.Functions
                  |> List.map (fun funcName ->
                    Button.create [
                      Button.content funcName
                      Button.horizontalAlignment HorizontalAlignment.Stretch
                      Button.horizontalContentAlignment HorizontalAlignment.Left
                      Button.padding 5.0
                      Button.background (
                        if model.SelectedFunction = Some funcName then "#094771"
                        else "Transparent"
                      )
                      Button.onClick (fun _ ->
                        dispatch (SelectFunction funcName))
                    ]
                  )
                )
              ]
            )
          ]
        ]
      ]
    )
  ]

let private cfgViewPanel (model: Model) =
  Border.create [
    Grid.column 2
    Border.background "#1E1E1E"
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
                TextBlock.text (
                  match model.SelectedFunction with
                  | Some func -> $"Control Flow Graph - {func}"
                  | None -> "Control Flow Graph"
                )
                TextBlock.fontSize 14.0
                TextBlock.fontWeight FontWeight.Bold
              ]
            )
          ]
          ScrollViewer.create [
            ScrollViewer.content (
              TextBlock.create [
                TextBlock.text (
                  match model.SelectedFunction with
                  | Some func -> $"CFG for function: {func}\n(Coming Soon)"
                  | None -> "Select a function to view its control flow graph"
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

let private welcomeScreen =
  Grid.create [
    Grid.background "#1E1E1E"
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
                TextBlock.foreground "#FFFFFF"
                TextBlock.horizontalAlignment HorizontalAlignment.Center
                TextBlock.margin (0.0, 0.0, 0.0, 20.0)
              ]
              TextBlock.create [
                TextBlock.text "Open a binary file to start exploring"
                TextBlock.fontSize 16.0
                TextBlock.foreground "#A0A0A0"
                TextBlock.horizontalAlignment HorizontalAlignment.Center
              ]
            ]
          ]
        )
      ]
    ]
  ]

let private splitView (model: Model) dispatch =
  Grid.create [
    Grid.columnDefinitions "250,5,*"
    Grid.children [
      functionList model dispatch
      GridSplitter.create [
        GridSplitter.column 1
        GridSplitter.background "#3E3E42"
        GridSplitter.resizeDirection GridResizeDirection.Columns
      ]
      cfgViewPanel model
    ]
  ]

let private mainContent (model: Model) dispatch =
  match model.LoadedBinary with
  | None -> welcomeScreen
  | Some _ -> splitView model dispatch

let view (model: Model) (dispatch: Message -> unit) =
  DockPanel.create [
    DockPanel.children [
      menuBar model dispatch
      statusBar model
      mainContent model dispatch
    ]
  ]
