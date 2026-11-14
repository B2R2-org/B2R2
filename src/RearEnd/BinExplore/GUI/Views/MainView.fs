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

open Avalonia.Controls
open Avalonia.Input
open Avalonia.Layout
open Avalonia.FuncUI
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types
open Avalonia.Media

let private navButton model isSelected (icon: IView) (tooltip: string) onClick =
  let model: Model = model
  let isSelected = isSelected model.WorkspacePanel
  Button.create [
    Button.width 36.0
    Button.height 36.0
    Button.margin (8.0, 6.0, 8.0, 0.0)
    Button.background (
      if isSelected then model.Theme.Tab.ActiveBackground
      else model.Theme.Common.Transparent
    )
    Button.foreground model.Theme.Text.Primary
    Button.borderThickness 0.0
    Button.content icon
    Button.onClick onClick
    ToolTip.tip tooltip
  ]

let private menuIconView iconSource model =
  Image.create [
    Image.source (iconSource model)
    Image.width 16.0
    Image.height 16.0
    Image.stretch Stretch.Uniform
  ]

let private cfgMenuIconView model = menuIconView IconAssets.cfgIcon model

let private sectionMenuIconView model = menuIconView IconAssets.listIcon model

let private functionNavButtonView model dispatch =
  navButton
    model
    (fun wp -> wp = FunctionPanel)
    (cfgMenuIconView model)
    "Functions and CFGs"
    (fun _ -> dispatch (SelectWorkspacePanel FunctionPanel))

let private sectionNavButtonView model dispatch =
  navButton
    model
    (fun wp -> wp = SectionPanel)
    (sectionMenuIconView model)
    "Sections"
    (fun _ -> dispatch (SelectWorkspacePanel SectionPanel))

let private sideMenuSeparatorView model =
  Border.create [
    Border.width 50.0
    Border.height 2.0
    Border.margin (0.0, 20.0, 0.0, 20.0)
    Border.background model.Theme.Panel.Border
  ]

let private sideMenuView model dispatch =
  Border.create [
    Border.background model.Theme.Panel.AltBackground
    Border.borderThickness (0.0, 0.0, 1.0, 0.0)
    Border.borderBrush model.Theme.Panel.Border
    Border.child (
      DockPanel.create [
        DockPanel.lastChildFill true
        DockPanel.children [
          StackPanel.create [
            DockPanel.dock Dock.Top
            StackPanel.orientation Orientation.Vertical
            StackPanel.horizontalAlignment HorizontalAlignment.Center
            StackPanel.children [
              functionNavButtonView model dispatch
              sectionNavButtonView model dispatch
              sideMenuSeparatorView model
            ]
          ]
          HexOverview.view model dispatch
        ]
      ]
    )
  ]

let private isFocusedPane model paneID = model.FocusedPaneID = Some paneID

let private onPanePressed paneID dispatch _ = dispatch (FocusPane paneID)

let private onContentSizeChanged paneID dispatch (e: SizeChangedEventArgs) =
  let w, h = e.NewSize.Width, e.NewSize.Height
  dispatch (UpdateViewportSize(paneID, w, h))

let [<Literal>] private MinSidePanelWidth = 190.0

let private tabContentView createProvider pane model dispatch =
  let provider =
    pane.ActiveTab |> Option.map (fun tab -> createProvider tab.BinaryID)
  let dispatch message =
    pane.ActiveTab
    |> Option.iter (fun tab -> dispatch (TabMsg(tab.ID, message)))
  match pane.ActiveTab, provider with
  | Some { Content = CFGContent _ }, Some tokenContextProvider ->
    CFGContent.view tokenContextProvider pane model dispatch
  | Some { Content = LinearContent }, _ ->
    LinearContent.view pane model dispatch
  | Some { Content = HexContent }, _ ->
    HexContent.view pane model dispatch
  | Some { Content = SectionContent }, _ ->
    Border.create [
      Border.borderThickness 0.0
      Border.child (
          TextBlock.create [
          TextBlock.text "Section tab view placeholder."
          TextBlock.foreground model.Theme.Text.Primary
          TextBlock.fontSize model.Theme.Font.Scale.Medium
          TextBlock.margin 10.0
        ]
      )
    ]
  | _ ->
    Border.create [
      Border.child (
        TextBlock.create [
          TextBlock.text "Select a function to open its CFG."
          TextBlock.foreground model.Theme.Text.Muted
          TextBlock.margin 10.0
        ])
    ]

let rec private paneView tokenContextProvider pane model dispatch =
  match pane with
  | Leaf(paneID, paneState) ->
    let patch = OnChangeOf paneID
    let contentModel = Model.forPane paneID model
    let contentKey =
      paneState.ActiveTab |> Option.map (fun tab -> tab.ID)
      |> Option.defaultValue "empty"
    Border.create [
      Border.borderThickness 1.0
      Border.borderBrush (
        if isFocusedPane model paneID then model.Theme.Panel.Border
        else model.Theme.Common.Transparent
      )
      Tunnel.OnPointerPressed(onPanePressed paneID dispatch, patch)
      Border.child (
        DockPanel.create [
          DockPanel.children [
            WorkspaceTabs.view paneID model dispatch
            Border.create [
              Border.padding 0.0
              Border.margin 0.0
              Border.borderThickness 0.0
              Control.onSizeChanged (
                onContentSizeChanged paneID dispatch,
                patch
              )
              Border.child (
                tabContentView
                  tokenContextProvider paneState contentModel dispatch
              )
            ] |> View.withKey contentKey
          ]
        ]
      )
    ] :> IView
  | Split(_, LeftRight, first, second) ->
    Grid.create [
      Grid.columnDefinitions (ColumnDefinitions.Parse "*,5,*")
      Grid.children [
        paneView tokenContextProvider first model dispatch
        GridSplitter.create [
          GridSplitter.column 1
          GridSplitter.background model.Theme.Panel.Border
          GridSplitter.resizeDirection GridResizeDirection.Columns
        ]
        Border.create [
          Grid.column 2
          Border.child (paneView tokenContextProvider second model dispatch)
        ]
      ]
    ] :> IView
  | Split(_, TopBottom, first, second) ->
    Grid.create [
      Grid.rowDefinitions (RowDefinitions.Parse "*,5,*")
      Grid.children [
        paneView tokenContextProvider first model dispatch
        GridSplitter.create [
          GridSplitter.row 1
          GridSplitter.background model.Theme.Panel.Border
          GridSplitter.resizeDirection GridResizeDirection.Rows
        ]
        Border.create [
          Grid.row 2
          Border.child (paneView tokenContextProvider second model dispatch)
        ]
      ]
    ] :> IView

let private workspaceView tokenContextProvider model dispatch =
  let columnDefs = ColumnDefinitions.Parse "52,250,5,*"
  columnDefs[1].MinWidth <- MinSidePanelWidth
  Grid.create [
    Grid.columnDefinitions columnDefs
    Control.allowDrop true
    Control.onDragOver FileDrop.onDragOver
    Control.onDrop (FileDrop.onDrop dispatch)
    Grid.children [
      sideMenuView model dispatch
      Grid.create [
        Grid.column 1
        Grid.children [
          NavigationPanel.view model dispatch
        ]
      ]
      GridSplitter.create [
        GridSplitter.column 2
        GridSplitter.background model.Theme.Panel.Border
        GridSplitter.resizeDirection GridResizeDirection.Columns
      ]
      DockPanel.create [
        Grid.column 3
        DockPanel.children [
          Toolbar.view model dispatch
          paneView tokenContextProvider model.RootPane model dispatch
        ]
      ]
    ]
  ]

let private mainArea tokenContextProvider (model: Model) dispatch =
  if model.Binaries.IsEmpty && model.BinaryLoads.IsEmpty then
    Welcome.view model dispatch
  else
    workspaceView tokenContextProvider model dispatch

let private onMainViewKeyDown (e: KeyEventArgs) =
  if e.Key = Key.F && e.KeyModifiers.HasFlag KeyModifiers.Control then
    Toolbar.SearchBox.focus ()
    e.Handled <- true
  else
    ()

let view tokenContextProvider (model: Model) (dispatch: Message -> unit) =
  DockPanel.create [
    Tunnel.OnKeyDown onMainViewKeyDown
    DockPanel.children [
      MenuBar.view model dispatch
      StatusBar.view model
      mainArea tokenContextProvider model dispatch
    ]
  ]
