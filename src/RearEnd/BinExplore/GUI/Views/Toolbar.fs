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

module B2R2.RearEnd.BinExplore.GUI.Toolbar

open System
open Avalonia
open Avalonia.Controls
open Avalonia.Controls.Primitives
open Avalonia.Input
open Avalonia.Layout
open Avalonia.Media
open Avalonia.FuncUI
open Avalonia.FuncUI.DSL
open Avalonia.FuncUI.Types
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.RearEnd.BinExplore
open B2R2.RearEnd.Visualization

let [<Literal>] private ToolbarHeight = 32.0

let private splitByMatch (query: string) (s: string) =
  let rec loop start acc =
    let idx = s.IndexOf(query, start, StringComparison.OrdinalIgnoreCase)
    if idx < 0 then
      if start < s.Length then List.rev ((false, s.Substring start) :: acc)
      else List.rev acc
    else
      let acc =
        if idx > start then (false, s.Substring(start, idx - start)) :: acc
        else acc
      loop (idx + query.Length) ((true, s.Substring(idx, query.Length)) :: acc)
  if String.IsNullOrEmpty query then [ false, s ]
  else loop 0 []

let private searchResultView model query result =
  StackPanel.create
    [ StackPanel.orientation Orientation.Horizontal
      StackPanel.children (
        splitByMatch query result
        |> List.map (fun (isMatch, segment) ->
          TextBlock.create
            [ TextBlock.text segment
              TextBlock.fontFamily model.Theme.Font.Disassembly.FontFamily
              TextBlock.foreground (
                if isMatch then model.Theme.Text.Highlight
                else model.Theme.Search.Foreground)
              TextBlock.fontWeight (
                if isMatch then FontWeight.Bold
                else FontWeight.Regular)
              TextBlock.fontSize model.Theme.Font.Function.FontSize ] :> IView)
      ) ]

let [<Literal>] private SearchItemHeight = 28.0

type private DropdownState =
  { Results: (string * float * float) list
    SelectedIdx: int
    Query: string }

let private searchDropdownView model state svRef onSelect =
  ScrollViewer.create
    [ ScrollViewer.maxHeight 300.0
      ScrollViewer.content (
        StackPanel.create
          [ StackPanel.background model.Theme.Search.Background
            StackPanel.children (
              state.Results
              |> List.mapi (fun i (result: string, cx, cy) ->
                Button.create
                  [ Button.height SearchItemHeight
                    Button.verticalContentAlignment VerticalAlignment.Center
                    Button.background (
                      if i = state.SelectedIdx then
                        model.Theme.Search.SelectedBackground
                      else
                        model.Theme.Search.Background
                    )
                    Button.foreground model.Theme.Search.Foreground
                    Button.borderThickness 0.0
                    Button.horizontalAlignment HorizontalAlignment.Stretch
                    Button.content (searchResultView model state.Query result)
                    Button.onClick ((fun _ -> onSelect cx cy),
                                    OnChangeOf(cx, cy)) ]
                  :> IView)) ]
      ) ]
  |> View.withOutlet (fun sv ->
    (svRef: ScrollViewer option ref).Value <- Some sv)

let inline private asmLinetoString (asmLine: AsmWord[]) =
  asmLine
  |> Array.fold (fun acc word -> acc + word.AsmWordValue) ""

let private search model (input: string) =
  if String.IsNullOrWhiteSpace input then
    []
  else
    match model.ActiveTab with
    | Some { Content = CFGTab(_, Loaded(g, _)) } ->
      [ for v in g.Vertices do
          let cx = v.VData.Coordinate.X + v.VData.Width / 2.0
          let cy = v.VData.Coordinate.Y + v.VData.Height / 2.0
          for line in (v.VData :> IVisualizable).Visualize() do
            let s = asmLinetoString line
            if s.Contains(input, StringComparison.OrdinalIgnoreCase) then
              (s, cx, cy)
            else
              () ]
    | _ ->
      []

let private searchView model dispatch =
  let tabID =
    match model.ActiveTab with
    | Some { ID = id; Content = CFGTab(_, Loaded _) } -> $"{id}-loaded"
    | Some { ID = id } -> $"{id}"
    | None -> "none"
  Component.create ($"search-view-{tabID}", fun ctx ->
    let searchText = ctx.useState ""
    let isOpen = ctx.useState false
    let selectedIdx = ctx.useState -1
    let svRef = (ctx.useState (ref<ScrollViewer option> None)).Current
    let results = search model searchText.Current
    let scrollToItem idx =
      match svRef.Value with
      | Some sv when sv.Viewport.Height > 0.0 ->
        let itemTop = float idx * SearchItemHeight
        let itemBottom = itemTop + SearchItemHeight
        let viewTop = sv.Offset.Y
        let viewBottom = viewTop + sv.Viewport.Height
        if itemTop < viewTop then
          sv.Offset <- Vector(0.0, itemTop)
        elif itemBottom > viewBottom then
          sv.Offset <- Vector(0.0, itemBottom - sv.Viewport.Height)
        else
          ()
      | _ -> ()
    let onSelect cx cy =
      dispatch (JumpCFGPan(cx, cy))
      isOpen.Set false
      selectedIdx.Set -1
    Grid.create
      [ Grid.width 240.0
        Grid.height ToolbarHeight
        Grid.children
          [ TextBox.create
              [ TextBox.width 240.0
                TextBox.height ToolbarHeight
                TextBox.fontSize 12.0
                TextBox.watermark "Search..."
                TextBox.verticalContentAlignment VerticalAlignment.Center
                TextBox.background model.Theme.Panel.Background
                TextBox.foreground model.Theme.Text.Primary
                TextBox.borderBrush model.Theme.Panel.Border
                TextBox.borderThickness (1.0, 1.0, 1.0, 1.0)
                TextBox.cornerRadius (CornerRadius(4.0, 0.0, 0.0, 4.0))
                TextBox.padding (6.0, 0.0, 28.0, 0.0)
                TextBox.onTextChanged (fun txt ->
                  searchText.Set txt
                  selectedIdx.Set -1
                  isOpen.Set(not (String.IsNullOrWhiteSpace txt)))
                TextBox.onKeyDown ((fun e ->
                  let count = results.Length
                  match e.Key with
                  | Key.Escape ->
                    searchText.Set ""
                    isOpen.Set false
                    selectedIdx.Set -1
                  | Key.Down when count > 0 ->
                    let newIdx = min (selectedIdx.Current + 1) (count - 1)
                    selectedIdx.Set newIdx
                    scrollToItem newIdx
                    e.Handled <- true
                  | Key.Up when count > 0 ->
                    let newIdx = max (selectedIdx.Current - 1) -1
                    selectedIdx.Set newIdx
                    if newIdx >= 0 then scrollToItem newIdx else ()
                    e.Handled <- true
                  | Key.Enter when selectedIdx.Current >= 0 ->
                    let _, cx, cy = results[selectedIdx.Current]
                    onSelect cx cy
                    e.Handled <- true
                  | _ ->
                    ()), OnChangeOf results) ] :> IView
            Button.create
              [ Button.width 26.0
                Button.height (ToolbarHeight - 4.0)
                Button.isHitTestVisible false
                Button.focusable false
                Button.horizontalAlignment HorizontalAlignment.Right
                Button.background model.Theme.Panel.Background
                Button.borderBrush model.Theme.Panel.Border
                Button.borderThickness (1.0, 1.0, 1.0, 1.0)
                Button.padding (4.0, 0.0)
                Button.margin (0.0, 0.0, 2.0, 0.0)
                Button.content (
                  Image.create [
                    Image.source (IconAssets.searchIcon model)
                    Image.width 14.0
                    Image.height 14.0
                    Image.stretch Stretch.Uniform
                    Image.verticalAlignment VerticalAlignment.Center
                    Image.horizontalAlignment HorizontalAlignment.Center
                  ]) ]
            Popup.create
              [ Popup.isOpen (isOpen.Current && not results.IsEmpty)
                Popup.placement PlacementMode.Bottom
                Popup.verticalOffset 4.0
                Popup.width 240.0
                Popup.isLightDismissEnabled true
                Popup.onClosed (fun _ -> isOpen.Set false)
                Popup.child (
                  let state =
                    { Results = results
                      SelectedIdx = selectedIdx.Current
                      Query = searchText.Current }
                  searchDropdownView model state svRef onSelect
                ) ] ] ]
  )

let private minimapToggleView model dispatch =
  let isEnabled, isActive, tabKey =
    match model.ActiveTab with
    | Some { ID = id; Content = CFGTab(_, Loaded(_, { ShowMinimap = flg })) } ->
      true, flg, id
    | _ -> false, false, "none"
  ToggleButton.create
    [ ToggleButton.width 26.0
      ToggleButton.height ToolbarHeight
      ToggleButton.padding (4.0, 0.0)
      ToggleButton.isChecked isActive
      ToggleButton.isEnabled isEnabled
      ToggleButton.background (
        if isActive then model.Theme.Tab.ActiveBackground
        else model.Theme.Panel.Background)
      ToggleButton.foreground model.Theme.Text.Primary
      ToggleButton.borderBrush model.Theme.Panel.Border
      ToggleButton.borderThickness 1.0
      ToggleButton.cornerRadius 4.0
      ToggleButton.onChecked (fun _ ->
        dispatch (ToggleMinimap(tabKey, true)))
      ToggleButton.onUnchecked (fun _ ->
        dispatch (ToggleMinimap(tabKey, false)))
      ToggleButton.content (
        Image.create [
          Image.source (IconAssets.mapIcon model)
          Image.width 20.0
          Image.height 20.0
          Image.stretch Stretch.Uniform
          Image.verticalAlignment VerticalAlignment.Center
          Image.horizontalAlignment HorizontalAlignment.Center
        ]) ] |> View.withKey $"minimap-toggle-{tabKey}"

let private graphSelectView model dispatch =
  let currentCFGKind, isEnabled, tabKey =
    match model.ActiveTab with
    | Some { ID = id; Content = CFGTab(_, Loaded(_, { CFGKind = kind })) } ->
      kind, true, id
    | _ -> CFGKind.Disasm, false, "none"
  ComboBox.create [
    ComboBox.width 100.0
    ComboBox.height ToolbarHeight
    ComboBox.maxHeight 200.0
    ComboBox.background model.Theme.Panel.Background
    ComboBox.foreground model.Theme.Text.Primary
    ComboBox.borderBrush model.Theme.Panel.Border
    ComboBox.borderThickness 1.0
    ComboBox.dataItems [ CFGKind.Disasm; CFGKind.LowUIR; CFGKind.SSA ]
    ComboBox.selectedItem (box currentCFGKind)
    ComboBox.isEnabled isEnabled
    ComboBox.onSelectedItemChanged (fun args ->
      match args with
      | :? CFGKind as newKind -> dispatch (ChangeCFGKind newKind)
      | _ -> ())
    ItemsControl.itemTemplate (
      DataTemplateView<string>.create (fun txt ->
        TextBlock.create [
          TextBlock.text txt
          TextBlock.foreground model.Theme.Text.Primary
          TextBlock.fontFamily model.Theme.Font.Function.FontFamily
          TextBlock.fontSize 12.0
          TextBlock.padding (4.0, 2.0)
        ]
      )
    )
  ] |> View.withKey $"graph-select-{tabKey}"

let view (model: Model) (dispatch: Message -> unit) =
  Border.create [
    Border.dock Dock.Top
    Border.background model.Theme.Panel.AltBackground
    Border.borderThickness (0.0, 0.0, 0.0, 1.0)
    Border.borderBrush model.Theme.Panel.Border
    Border.padding (8.0, 4.0, 8.0, 4.0)
    Border.child (
      StackPanel.create [
        StackPanel.orientation Orientation.Horizontal
        StackPanel.spacing 4.0
        StackPanel.children [
          searchView model dispatch
          graphSelectView model dispatch
          minimapToggleView model dispatch
        ]
      ]
    )
  ]
