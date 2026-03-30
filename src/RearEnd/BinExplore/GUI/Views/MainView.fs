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
open Avalonia.Layout
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types
open Avalonia.Media

let private navButton model panel (icon: IView) (tooltip: string) onClick =
  let isSelected = model.WorkspacePanel = panel
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

let private cfgMenuIconView model =
  Image.create [
    Image.source (IconAssets.cfgIcon model)
    Image.width 16.0
    Image.height 16.0
    Image.stretch Stretch.Uniform
  ]

let private binaryMenuIconView model =
  Image.create [
    Image.source (IconAssets.binaryIcon model)
    Image.width 16.0
    Image.height 16.0
    Image.stretch Stretch.Uniform
  ]

let private sectionMenuIconView model =
  Image.create [
    Image.source (IconAssets.listIcon model)
    Image.width 16.0
    Image.height 16.0
    Image.stretch Stretch.Uniform
  ]

let private functionNavButtonView model dispatch =
  navButton
    model
    FunctionPanel
    (cfgMenuIconView model)
    "Functions and CFGs"
    (fun _ -> dispatch (SelectWorkspacePanel FunctionPanel))

let private hexOverviewNavButtonView model dispatch =
  navButton
    model
    HexOverviewPanel
    (binaryMenuIconView model)
    "Hex Overview"
    (fun _ -> dispatch (SelectWorkspacePanel HexOverviewPanel))

let private sectionNavButtonView model dispatch =
  navButton
    model
    SectionPanel
    (sectionMenuIconView model)
    "Sections"
    (fun _ -> dispatch (SelectWorkspacePanel SectionPanel))

let private sideMenuView model dispatch =
  Border.create [
    Border.background model.Theme.Panel.AltBackground
    Border.borderThickness (0.0, 0.0, 1.0, 0.0)
    Border.borderBrush model.Theme.Panel.Border
    Border.child (
      StackPanel.create [
        StackPanel.orientation Orientation.Vertical
        StackPanel.horizontalAlignment HorizontalAlignment.Center
        StackPanel.children [
          functionNavButtonView model dispatch
          hexOverviewNavButtonView model dispatch
          sectionNavButtonView model dispatch
        ]
      ]
    )
  ]

let private leftPanelView model dispatch =
  match model.WorkspacePanel with
  | FunctionPanel -> FunctionList.view model dispatch :> IView
  | HexOverviewPanel -> HexOverview.view model dispatch
  | SectionPanel -> SectionList.view model dispatch

let private onContentSizeChanged model dispatch (e: SizeChangedEventArgs) =
  let w, h = e.NewSize.Width, e.NewSize.Height
  dispatch (CFGMsg(UpdateViewportSize(w, h)))
  match model.ActiveTab with
  | Some { Content = HexContent _ } ->
    dispatch (HexdumpMsg(UpdateViewport(w, h)))
  | _ ->
    ()

let [<Literal>] private MinSidePanelWidth = 190.0

let private tabContentView model dispatch =
  match model.ActiveTab with
  | Some { Content = CFGContent _ } ->
    CFGContent.view model dispatch
  | Some { Content = HexContent _ } ->
    Hexdump.view model dispatch
  | Some { Content = SectionContent } ->
    Border.create [
      Border.background model.Theme.Window.Background
      Border.borderThickness 0.0
      Border.child (
        TextBlock.create [
          TextBlock.text "Section tab view placeholder."
          TextBlock.foreground model.Theme.Text.Primary
          TextBlock.fontSize 14.0
          TextBlock.margin 10.0
        ]
      )
    ]
  | None ->
    CFGContent.view model dispatch

let private workspaceView model dispatch =
  let columnDefs = ColumnDefinitions.Parse "52,250,5,*"
  columnDefs[1].MinWidth <- MinSidePanelWidth
  Grid.create [
    Grid.columnDefinitions columnDefs
    Grid.children [
      sideMenuView model dispatch
      Grid.create [
        Grid.column 1
        Grid.children [
          leftPanelView model dispatch
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
          WorkspaceTabs.view model dispatch
          Border.create [
            Border.padding 0.0
            Border.margin 0.0
            Border.borderThickness 0.0
            Control.onSizeChanged (onContentSizeChanged model dispatch)
            Border.child (tabContentView model dispatch)
          ]
        ]
      ]
    ]
  ]

let private mainArea (model: Model) dispatch =
  match model.LoadedBinary with
  | None -> Welcome.view model dispatch
  | Some _ -> workspaceView model dispatch

let view (model: Model) (dispatch: Message -> unit) =
  DockPanel.create [
    DockPanel.children [
      MenuBar.view model dispatch
      StatusBar.view model
      mainArea model dispatch
    ]
  ]
