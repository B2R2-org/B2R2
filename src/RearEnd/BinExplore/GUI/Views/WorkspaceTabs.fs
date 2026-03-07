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
open Avalonia.Controls
open Avalonia.Controls.Primitives
open Avalonia.Layout
open Avalonia.Media
open Avalonia.Input
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types

let [<Literal>] private TabMaxWidth = 220.0

let [<Literal>] private TabTextMaxWidth = 165.0

let private getTabBorderColor (model: Model) tab =
  if model.ActiveTab = Some tab then model.Theme.Tab.ActiveBackground
  else model.Theme.Tab.InactiveBackground

let private getTabTextColor (model: Model) tab =
  if model.ActiveTab = Some tab then model.Theme.Text.Primary
  else model.Theme.Text.Secondary

let private getTabFontStyle (model: Model) tab =
  if model.PreviewTab = Some tab then FontStyle.Italic
  else FontStyle.Normal

let private getTabIconText (tab: Tab) =
  match tab.Content with
  | CFGTab _ -> None
  | HexTab _ -> Some "Hx"
  | SectionTab -> Some "\u2261"

let private tabIconView model tab =
  match getTabIconText tab with
  | Some iconText ->
    TextBlock.create [
      TextBlock.text iconText
      TextBlock.fontFamily model.Theme.Font.FunctionText
      TextBlock.foreground (getTabTextColor model tab)
      TextBlock.verticalAlignment VerticalAlignment.Center
      TextBlock.margin (0.0, 0.0, 6.0, 0.0)
    ] |> View.withKey $"{tab.ID}-icon-text" :> IView
  | None ->
    Image.create [
      Image.source (IconAssets.cfgIcon model)
      Image.width 14.0
      Image.height 14.0
      Image.stretch Stretch.Uniform
      Image.verticalAlignment VerticalAlignment.Center
      Image.margin (0.0, 0.0, 4.0, 0.0)
    ] |> View.withKey $"{tab.ID}-icon" :> IView

let private tabLabelView model tab =
  TextBlock.create [
    StackPanel.verticalAlignment VerticalAlignment.Center
    TextBlock.text tab.Title
    TextBlock.fontFamily model.Theme.Font.FunctionText
    TextBlock.background model.Theme.Common.Transparent
    TextBlock.foreground (getTabTextColor model tab)
    TextBlock.padding (5.0, 0.0, 5.0, 0.0)
    TextBlock.fontSize 14.0
    TextBlock.fontStyle (getTabFontStyle model tab)
    TextBlock.maxWidth TabTextMaxWidth
    TextBlock.textWrapping TextWrapping.NoWrap
    TextBlock.textTrimming TextTrimming.CharacterEllipsis
  ] |> View.withKey $"{tab.ID}-label" :> IView

let private findTabByID model id =
  let allTabs =
    match model.PreviewTab with
    | Some preview -> preview :: model.OpenTabs
    | None -> model.OpenTabs
  allTabs |> List.tryFind (fun tab -> tab.ID = id)

let private onTabDrag model targetTab dispatch (e: DragEventArgs) =
  let draggedTabID = DataTransferExtensions.TryGetText e.DataTransfer
  if not (String.IsNullOrWhiteSpace draggedTabID) then
    match findTabByID model draggedTabID with
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
  data.Add(DataTransferItem.CreateText tab.ID)
  DragDrop.DoDragDropAsync(e, data, DragDropEffects.Move)
  |> ignore

let view (model: Model) dispatch =
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
                          ToolTip.tip tab.Title
                          StackPanel.children [
                            tabIconView model tab
                            tabLabelView model tab
                          ]
                        ] |> View.withKey $"{tab.ID}-clickarea"
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
                        ] |> View.withKey $"{tab.ID}-close"
                      ]
                    ]
                  )
                ] |> View.withKey $"{tab.ID}-tab" :> IView
              )
            )
          ]
        )
      ]
    )
  ]
