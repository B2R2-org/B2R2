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
module B2R2.RearEnd.BinExplore.GUI.NavigationPanel

open System.IO
open Avalonia.Controls
open Avalonia.Controls.Primitives
open Avalonia.Input
open Avalonia.Layout
open Avalonia.Media
open Avalonia.FuncUI
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types

let [<Literal>] private HeaderHeight = 28.0

let [<Literal>] private RowHeight = 30.0

let private filePathView path =
  TextBlock.create [
    TextBlock.text path
    TextBlock.textWrapping TextWrapping.NoWrap
  ]

let private binaryStatus binary =
  match binary.LinearRequest, binary.LinearError, binary.StatusBarState with
  | Some _, _, _ -> "Analyzing"
  | _, Some _, _ | _, _, MessageOnly _ -> "Failed"
  | _ -> "Ready"

let private binaryIconView model =
  Image.create [
    Image.source (IconAssets.binaryIcon model)
    Image.width 14.0
    Image.height 14.0
    Image.verticalAlignment VerticalAlignment.Center
  ]

let private binaryRowContentView model id selected status =
  Grid.create [
    Grid.columnDefinitions "20,*,Auto"
    Grid.children [
      binaryIconView model
      TextBlock.create [
        Grid.column 1
        TextBlock.text (Model.getBinaryLabel id model)
        TextBlock.foreground model.Theme.Text.Primary
        TextBlock.fontSize model.Theme.Font.Scale.Normal
        TextBlock.fontWeight (
          if selected then FontWeight.SemiBold else FontWeight.Normal)
        TextBlock.verticalAlignment VerticalAlignment.Center
        TextBlock.textTrimming TextTrimming.CharacterEllipsis
        TextBlock.margin (0.0, 0.0, 6.0, 0.0)
      ]
      TextBlock.create [
        Grid.column 2
        TextBlock.text status
        TextBlock.foreground model.Theme.Text.Muted
        TextBlock.fontSize model.Theme.Font.Scale.XSmall
        TextBlock.verticalAlignment VerticalAlignment.Center
      ]
    ]
  ]

let private binaryRowView model dispatch (binary: BinaryModel) =
  let id = binary.Info.BinaryID
  let selected = model.SelectedBinaryID = Some id
  let status = binaryStatus binary
  Button.create [
    Button.height RowHeight
    Button.horizontalAlignment HorizontalAlignment.Stretch
    Button.horizontalContentAlignment HorizontalAlignment.Stretch
    Button.padding (8.0, 0.0, 8.0, 0.0)
    Button.borderThickness (2.0, 0.0, 0.0, 0.0)
    Button.borderBrush (
      if selected then model.Theme.Text.Highlight
      else model.Theme.Common.Transparent)
    Button.background (
      if selected then model.Theme.Tab.ActiveBackground
      else model.Theme.Common.Transparent)
    Button.onClick (fun _ -> dispatch (Message.SelectBinary id))
    ToolTip.tip (filePathView binary.Info.Path)
    Button.content (binaryRowContentView model id selected status)
  ] :> IView

let private loadActionView model label message dispatch =
  let label: string = label
  Button.create [
    Button.content label
    Button.padding (4.0, 0.0, 4.0, 0.0)
    Button.fontSize model.Theme.Font.Scale.XSmall
    Button.foreground model.Theme.Text.Secondary
    Button.background model.Theme.Common.Transparent
    Button.onClick ((fun _ -> dispatch message), OnChangeOf message)
  ]

let private loadingStatus request =
  let request: BinaryLoad = request
  match request.State with
  | Queued ->
    "Queued", request.Path
  | LoadingBinary ->
    "Loading", request.Path
  | LoadCanceled ->
    "Canceled", request.Path
  | BinaryLoadState.LoadFailed reason ->
    "Failed", $"{request.Path}\n{reason}"

let private loadActionsView model dispatch request =
  let request: BinaryLoad = request
  let retry = RetryBinaryLoad request.RequestID
  let dismiss = DismissBinaryLoad request.RequestID
  let cancel = Message.CancelBinaryLoad request.RequestID
  StackPanel.create [
    Grid.column 2
    StackPanel.orientation Orientation.Horizontal
    StackPanel.children [
      match request.State with
      | Queued | LoadingBinary ->
        loadActionView model "Cancel" cancel dispatch
      | BinaryLoadState.LoadFailed _ | LoadCanceled ->
        loadActionView model "Retry" retry dispatch
        loadActionView model "\u00D7" dismiss dispatch
    ]
  ]

let private loadingRowView model dispatch request =
  let request: BinaryLoad = request
  let status, tooltip = loadingStatus request
  Grid.create [
    Grid.height RowHeight
    Grid.columnDefinitions "*,Auto,Auto"
    Grid.margin (10.0, 0.0, 8.0, 0.0)
    ToolTip.tip (filePathView tooltip)
    Grid.children [
      TextBlock.create [
        TextBlock.text (Path.GetFileName request.Path)
        TextBlock.foreground model.Theme.Text.Muted
        TextBlock.fontSize model.Theme.Font.Scale.Small
        TextBlock.verticalAlignment VerticalAlignment.Center
        TextBlock.textTrimming TextTrimming.CharacterEllipsis
      ]
      TextBlock.create [
        Grid.column 1
        TextBlock.text status
        TextBlock.foreground model.Theme.Text.Muted
        TextBlock.fontSize model.Theme.Font.Scale.XSmall
        TextBlock.verticalAlignment VerticalAlignment.Center
        TextBlock.margin (6.0, 0.0, 0.0, 0.0)
      ]
      loadActionsView model dispatch request
    ]
  ] |> View.withKey $"load-{request.RequestID}" :> IView

let private binaryRowsView (model: Model) dispatch =
  ScrollViewer.create [
    ScrollViewer.verticalScrollBarVisibility ScrollBarVisibility.Auto
    ScrollViewer.horizontalScrollBarVisibility ScrollBarVisibility.Disabled
    ScrollViewer.content (
      StackPanel.create [
        StackPanel.children [
          for id in model.BinaryOrder do
            match Map.tryFind id model.Binaries with
            | Some binary -> binaryRowView model dispatch binary
            | None -> ()
          for request in model.BinaryLoads do
            loadingRowView model dispatch request
        ]
      ])
  ]

let private binaryListHeaderView model dispatch =
  let expanded = model.BinaryListExpanded
  let arrow = if expanded then "\u25BE" else "\u25B8"
  let count = model.BinaryOrder.Length + model.BinaryLoads.Length
  let toggle _ = dispatch (SetBinaryListExpanded(not expanded))
  Button.create [
    Button.dock Dock.Top
    Button.height HeaderHeight
    Button.horizontalAlignment HorizontalAlignment.Stretch
    Button.horizontalContentAlignment HorizontalAlignment.Left
    Button.background model.Theme.Panel.AltBackground
    Button.foreground model.Theme.Text.Secondary
    Button.borderThickness 0.0
    Button.padding (8.0, 0.0, 8.0, 0.0)
    Button.fontSize model.Theme.Font.Scale.Small
    Button.fontWeight FontWeight.SemiBold
    Button.content $"{arrow} OPEN BINARIES ({count})"
    Button.onClick (toggle, OnChangeOf expanded)
    ToolTip.tip (
      if expanded then "Collapse open binaries" else "Expand open binaries")
  ]

let private binaryListView model dispatch =
  DockPanel.create [
    DockPanel.background model.Theme.Panel.Background
    DockPanel.children [
      binaryListHeaderView model dispatch
      if model.BinaryListExpanded then binaryRowsView model dispatch
      else ()
    ]
  ]

let private navigationBodyView (model: Model) dispatch =
  let content =
    match model.WorkspacePanel with
    | FunctionPanel -> FunctionList.view model dispatch :> IView
    | SectionPanel -> SectionList.view model dispatch
  Border.create [
    Border.child content
  ] |> View.withKey $"navigation-{model.SelectedBinaryID}"

let requiredHeight count =
  HeaderHeight + RowHeight * float (max 1 (min 5 count))

let private binaryListHeight model =
  if model.BinaryListExpanded then
    let count = model.BinaryOrder.Length + model.BinaryLoads.Length
    model.BinaryListHeight
    |> Option.defaultValue (requiredHeight count)
  else
    HeaderHeight

let private onSplitterDragCompleted dispatch (e: VectorEventArgs) =
  match e.Source with
  | :? GridSplitter as splitter ->
    match splitter.Parent with
    | :? Grid as grid ->
      let height = grid.RowDefinitions[0].Height.Value
      dispatch (SetBinaryListHeight height)
    | _ ->
      ()
  | _ ->
    ()

let view model dispatch =
  let height = binaryListHeight model
  let splitterHeight = if model.BinaryListExpanded then 5 else 0
  let rows = RowDefinitions.Parse $"{int height},{splitterHeight},*"
  rows[0].MinHeight <- if model.BinaryListExpanded then 56.0 else HeaderHeight
  rows[0].MaxHeight <- 300.0
  rows[2].MinHeight <- 120.0
  Grid.create [
    Grid.rowDefinitions rows
    Grid.children [
      binaryListView model dispatch
      GridSplitter.create [
        GridSplitter.row 1
        GridSplitter.background model.Theme.Panel.Border
        GridSplitter.resizeDirection GridResizeDirection.Rows
        GridSplitter.isVisible model.BinaryListExpanded
        Thumb.onDragCompleted (onSplitterDragCompleted dispatch)
      ]
      Border.create [
        Grid.row 2
        Border.child (navigationBodyView model dispatch)
      ]
    ]
  ]
