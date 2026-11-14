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
module B2R2.RearEnd.BinExplore.GUI.WorkspaceTabs

open System
open System.Globalization
open System.IO
open Avalonia.Controls
open Avalonia.Controls.Primitives
open Avalonia.Layout
open Avalonia.Media
open Avalonia.Input
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types

let [<Literal>] private TabMaxWidth = 260.0

let [<Literal>] private TabTextMaxWidth = 205.0

let [<Literal>] private MaxFileNameLength = 10

let [<Literal>] private DragPayloadSeparator = "|"

let rec private originatedFromButton (source: obj) =
  match source with
  | :? Button ->
    true
  | :? Control as control when not (isNull control.Parent) ->
    originatedFromButton (control.Parent :> obj)
  | _ ->
    false

let private buildDragPayload paneID tabID =
  $"{paneID}{DragPayloadSeparator}{tabID}"

let private tryParseDragPayload (e: DragEventArgs) =
  let payload = DataTransferExtensions.TryGetText e.DataTransfer
  if String.IsNullOrWhiteSpace payload then
    None
  else
    let parts =
      payload.Split([| DragPayloadSeparator |], 2, StringSplitOptions.None)
    if parts.Length <> 2 then
      None
    else
      match Guid.TryParse parts[0] with
      | true, paneID -> Some(paneID, parts[1])
      | _ -> None

let private getVisibleTabs pane =
  match pane.PreviewTab with
  | Some preview -> preview :: pane.OpenTabs
  | None -> pane.OpenTabs

let private onTabClick paneID tabID dispatch (e: PointerPressedEventArgs) =
  if originatedFromButton e.Source then
    ()
  else
    let props = e.GetCurrentPoint(null).Properties
    if props.IsRightButtonPressed then
      dispatch (SwitchTab(paneID, tabID))
    elif props.IsLeftButtonPressed then
      dispatch (SwitchTab(paneID, tabID))
      dispatch (StartTabDrag(paneID, tabID))
      let data = new DataTransfer()
      data.Add(DataTransferItem.CreateText(buildDragPayload paneID tabID))
      DragDrop.DoDragDropAsync(e, data, DragDropEffects.Move)
      |> ignore
    else
      ()

let private tabContextMenu paneID (pane: PaneState) dispatch (tab: Tab) =
  let moveMenuItem (header: string) placement =
    let move _ = dispatch (MoveTabRelative(placement, tab.ID))
    MenuItem.create [
      MenuItem.header header
      MenuItem.onClick (move, OnChangeOf(placement, tab.ID))
    ]
  let pinMenu =
    match tab.Content with
    | CFGContent(func, _) when pane.PreviewTab = Some tab ->
      let pin _ = dispatch (TabMsg(tab.ID, PinCFGTab func))
      [ MenuItem.create [
          MenuItem.header "Pin this tab"
          MenuItem.onClick (pin, OnChangeOf func)
        ] :> IView
        Separator.create [] ]
    | _ ->
      []
  let items =
    [ yield! pinMenu
      moveMenuItem "Move to Left" (LeftOf paneID)
      moveMenuItem "Move to Right" (RightOf paneID)
      moveMenuItem "Move to Top" (Above paneID)
      moveMenuItem "Move to Bottom" (Below paneID) ]
  ContextMenu.create [ ContextMenu.viewItems items ]

let private onTabDrag paneID targetTabID dispatch e =
  match tryParseDragPayload e with
  | Some(sourcePaneID, draggedTabID) ->
    if sourcePaneID = paneID then
      dispatch (ReorderTab(paneID, draggedTabID, targetTabID))
    else
      ()
    e.DragEffects <- DragDropEffects.Move
  | None ->
    e.DragEffects <- DragDropEffects.None
  e.Handled <- true

let private onTabDrop paneID dispatch e =
  match tryParseDragPayload e with
  | Some(sourcePaneID, draggedTabID) when sourcePaneID <> paneID ->
    dispatch (MoveTabToPane(sourcePaneID, paneID, draggedTabID))
  | _ ->
    ()
  dispatch EndTabDrag
  e.Handled <- true

let private onPaneDragOver e =
  match tryParseDragPayload e with
  | Some _ ->
    e.DragEffects <- DragDropEffects.Move
    e.Handled <- true
  | None ->
    e.DragEffects <- DragDropEffects.None

let private onPaneDrop paneID dispatch e =
  match tryParseDragPayload e with
  | Some(sourcePaneID, draggedTabID) when sourcePaneID <> paneID ->
    dispatch (MoveTabToPane(sourcePaneID, paneID, draggedTabID))
  | _ ->
    ()
  dispatch EndTabDrag
  e.Handled <- true

let private getTabBackground model pane tab =
  if pane.ActiveTab = Some tab then model.Theme.Tab.ActiveBackground
  else model.Theme.Tab.InactiveBackground

let private getTabTextColor model pane tab =
  if pane.ActiveTab = Some tab then model.Theme.Tab.ActiveForeground
  else model.Theme.Tab.InactiveForeground

let private getTabFontStyle pane tab =
  if pane.PreviewTab = Some tab then FontStyle.Italic else FontStyle.Normal

let private themedTabIconView model iconSource =
  Image.create [
    Image.source (iconSource model)
    Image.width 14.0
    Image.height 14.0
    Image.stretch Stretch.Uniform
    Image.verticalAlignment VerticalAlignment.Center
    Image.margin (0.0, 0.0, 4.0, 0.0)
  ] :> IView

let private tabIconView model pane (tab: Tab) =
  match tab.Content with
  | CFGContent _ ->
    themedTabIconView model IconAssets.cfgIcon
  | LinearContent ->
    themedTabIconView model IconAssets.linearIcon
  | HexContent ->
    themedTabIconView model IconAssets.binaryIcon
  | _ ->
    TextBlock.create [
      TextBlock.text ""
      TextBlock.fontSize model.Theme.Font.Scale.XSmall
      TextBlock.fontWeight FontWeight.Bold
      TextBlock.foreground (getTabTextColor model pane tab)
      TextBlock.verticalAlignment VerticalAlignment.Center
      TextBlock.margin (0.0, 0.0, 4.0, 0.0)
    ] :> IView

let private shortFileName path =
  let name = Path.GetFileName(path: string)
  let starts = StringInfo.ParseCombiningCharacters name
  let suffix = "..."
  if starts.Length > MaxFileNameLength then
    name.Substring(0, starts[MaxFileNameLength - suffix.Length]) + suffix
  else
    name

let private tabLabelView model pane tab =
  let title =
    match Map.tryFind tab.BinaryID model.Binaries with
    | Some binary ->
      $"{shortFileName binary.Info.Path} - {tab.Title}"
    | None ->
      tab.Title
  TextBlock.create [
    StackPanel.verticalAlignment VerticalAlignment.Center
    TextBlock.text title
    TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
    TextBlock.background model.Theme.Common.Transparent
    TextBlock.foreground (getTabTextColor model pane tab)
    TextBlock.padding (5.0, 0.0, 5.0, 0.0)
    TextBlock.fontSize model.Theme.Font.Scale.Medium
    TextBlock.fontStyle (getTabFontStyle pane tab)
    TextBlock.maxWidth TabTextMaxWidth
    TextBlock.textWrapping TextWrapping.NoWrap
    TextBlock.textTrimming TextTrimming.CharacterEllipsis
  ] :> IView

let private tabButtonView paneID model dispatch tab =
  let close _ = dispatch (CloseTab(paneID, tab.ID))
  Button.create [
    StackPanel.verticalAlignment VerticalAlignment.Center
    Button.content "\u00D7"
    Button.background model.Theme.Common.Transparent
    Button.foreground model.Theme.Tab.CloseForeground
    Button.borderThickness 0.0
    Button.padding (5.0, 0.0, 5.0, 0.0)
    Button.fontSize model.Theme.Font.Scale.Large
    Button.onClick (close, OnChangeOf(paneID, tab.ID))
  ]

let private tabContentView paneID pane model dispatch (tab: Tab) =
  let tooltip =
    match Map.tryFind tab.BinaryID model.Binaries with
    | Some binary -> $"{binary.Info.Path}\n{tab.Title}"
    | None -> tab.Title
  StackPanel.create [
    StackPanel.orientation Orientation.Horizontal
    StackPanel.children [
      StackPanel.create [
        StackPanel.orientation Orientation.Horizontal
        StackPanel.verticalAlignment VerticalAlignment.Center
        StackPanel.background model.Theme.Common.Transparent
        Control.focusable true
        ToolTip.tip (
          TextBlock.create [
            TextBlock.text tooltip
            TextBlock.textWrapping TextWrapping.NoWrap
          ])
        StackPanel.children [
          tabIconView model pane tab
          tabLabelView model pane tab
        ]
      ]
      tabButtonView paneID model dispatch tab
    ]
  ]

let private tabStripView paneID pane model dispatch =
  StackPanel.create [
    Control.allowDrop true
    Control.onDragOver onPaneDragOver
    Control.onDrop (onPaneDrop paneID dispatch, OnChangeOf paneID)
    StackPanel.orientation Orientation.Horizontal
    StackPanel.children (
      getVisibleTabs pane
      |> List.map (fun tab ->
        let patch = OnChangeOf(paneID, tab.ID)
        Border.create [
          Border.background (getTabBackground model pane tab)
          Border.maxWidth TabMaxWidth
          Border.borderThickness (0.0, 0.0, 0.0, 0.0)
          Border.borderBrush model.Theme.Tab.Border
          Border.padding (10.0, 5.0, 5.0, 5.0)
          Control.contextMenu (tabContextMenu paneID pane dispatch tab)
          Control.allowDrop true
          Tunnel.OnPointerPressed(onTabClick paneID tab.ID dispatch, patch)
          Tunnel.OnPointerReleased(fun _ -> dispatch EndTabDrag)
          Control.onDragOver (onTabDrag paneID tab.ID dispatch, patch)
          Control.onDrop (onTabDrop paneID dispatch, OnChangeOf paneID)
          Border.child (tabContentView paneID pane model dispatch tab)
        ] :> IView
      )
    )
  ]

let view paneID model dispatch =
  match Pane.tryFindLeaf paneID model.RootPane with
  | Some pane ->
    Border.create [
      Border.dock Dock.Top
      Border.background model.Theme.Tab.StripBackground
      Border.borderThickness 0.0
      Border.child (
        ScrollViewer.create [
          Control.allowDrop true
          Control.onDragOver onPaneDragOver
          Control.onDrop (onPaneDrop paneID dispatch, OnChangeOf paneID)
          ScrollViewer.horizontalScrollBarVisibility ScrollBarVisibility.Auto
          ScrollViewer.verticalScrollBarVisibility ScrollBarVisibility.Disabled
          Tunnel.OnPointerReleased(fun _ -> dispatch EndTabDrag)
          ScrollViewer.content (tabStripView paneID pane model dispatch)
        ]
      )
    ]
  | None ->
    Border.create []
