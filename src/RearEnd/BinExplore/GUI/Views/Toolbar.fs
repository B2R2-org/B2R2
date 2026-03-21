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

let private mkIcon (img: IImage) size =
  Image.create [
    Image.source img
    Image.width size
    Image.height size
    Image.stretch Stretch.Uniform
    Image.verticalAlignment VerticalAlignment.Center
    Image.horizontalAlignment HorizontalAlignment.Center
  ]

/// The search box component of the toolbar.
module private SearchBox = begin

  let [<Literal>] SearchItemHeight = 28.0

  type SearchLocalState =
    { SearchText: IWritable<string>
      IsOpen: IWritable<bool>
      SelectedIdx: IWritable<int>
      ScrollViewer: IWritable<ScrollViewer option> }

  let getTabID model =
    match model.ActiveTab with
    | Some { ID = id; Content = CFGContent(_, Loaded _) } -> $"{id}-loaded"
    | Some { ID = id } -> $"{id}"
    | None -> "none"

  let getThemeKey model =
    match model.ThemeMode with
    | Builtin Dark -> "dark"
    | Builtin Light -> "light"
    | _ -> "custom"

  let inline asmLineToString (asmLine: AsmWord[]) =
    asmLine
    |> Array.fold (fun acc word -> acc + word.AsmWordValue) ""

  let search model (input: string) =
    if String.IsNullOrWhiteSpace input then
      [||]
    else
      match model.ActiveTab with
      | Some { Content = CFGContent(_, Loaded(g, _)) } ->
        [| for v in g.Vertices do
             let cx = v.VData.Coordinate.X + v.VData.Width / 2.0
             let cy = v.VData.Coordinate.Y + v.VData.Height / 2.0
             for line in (v.VData :> IVisualizable).Visualize() do
               let s = asmLineToString line
               if s.Contains(input, StringComparison.OrdinalIgnoreCase) then
                 (s, cx, cy)
               else
                 () |]
      | _ ->
        [||]

  let scrollToItem localState idx =
    let svRef = localState.ScrollViewer
    match svRef.Current with
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

  let onSearchItemSelect dispatch localState cx cy _evt =
    dispatch (JumpCFGPan(cx, cy))
    localState.IsOpen.Set false
    localState.SelectedIdx.Set -1

  let onSearchTextChanged localState (txt: string) =
    localState.SearchText.Set txt
    localState.SelectedIdx.Set -1
    localState.IsOpen.Set(not (String.IsNullOrWhiteSpace txt))

  let onSearchKeyDown dispatch localState (results: _[]) (e: KeyEventArgs) =
    let count = Array.length results
    match e.Key with
    | Key.Escape ->
      localState.SearchText.Set ""
      localState.IsOpen.Set false
      localState.SelectedIdx.Set -1
    | Key.Down when count > 0 ->
      let newIdx = min (localState.SelectedIdx.Current + 1) (count - 1)
      localState.SelectedIdx.Set newIdx
      scrollToItem localState newIdx
      e.Handled <- true
    | Key.Up when count > 0 ->
      let newIdx = max (localState.SelectedIdx.Current - 1) -1
      localState.SelectedIdx.Set newIdx
      if newIdx >= 0 then scrollToItem localState newIdx else ()
      e.Handled <- true
    | Key.Enter when localState.SelectedIdx.Current >= 0 ->
      let _, cx, cy = results[localState.SelectedIdx.Current]
      onSearchItemSelect dispatch localState cx cy null
      e.Handled <- true
    | _ -> ()

  let searchInputView model dispatch localState (results: _[]) =
    TextBox.create [
      TextBox.width 240.0
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
      TextBox.onTextChanged (onSearchTextChanged localState)
      TextBox.onKeyDown (
        onSearchKeyDown dispatch localState results, OnChangeOf results
      )
    ] :> IView

  let searchIconView model =
    Button.create [
      Button.width 26.0
      Button.height (ToolbarHeight - 4.0)
      Button.isHitTestVisible false
      Button.focusable false
      Button.horizontalAlignment HorizontalAlignment.Right
      Button.background model.Theme.Panel.Background
      Button.borderBrush model.Theme.Panel.Border
      Button.borderThickness (1.0, 1.0, 1.0, 1.0)
      Button.padding (4.0, 0.0)
      Button.margin (0.0, 0.0, 2.0, 0.0)
      Button.content (mkIcon (IconAssets.searchIcon model) 14.0)
    ]

  let searchResultColor model isMatch =
    if isMatch then model.Theme.Text.Highlight
    else model.Theme.Search.Foreground

  let searchResultFontWeight isMatch =
    if isMatch then FontWeight.Bold
    else FontWeight.Regular

  let searchResultDecorated model query result =
    StringUtils.splitByMatch query result
    |> List.map (fun (isMatch, segment) ->
      TextBlock.create [
        TextBlock.text segment
        TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
        TextBlock.foreground (searchResultColor model isMatch)
        TextBlock.fontWeight (searchResultFontWeight isMatch)
        TextBlock.fontSize model.Theme.Font.Monospace.FontSize
      ] :> IView)

  let searchResultItemView model query result =
    StackPanel.create [
      StackPanel.orientation Orientation.Horizontal
      StackPanel.children (searchResultDecorated model query result)
    ]

  let searchResultBgColor model i selectedIdx =
    if i = selectedIdx then model.Theme.Search.SelectedBackground
    else model.Theme.Search.Background

  let searchResultsToButtons model dispatch localState results =
    let selectedIdx = localState.SelectedIdx.Current
    let query = localState.SearchText.Current
    results
    |> Array.toList
    |> List.mapi (fun i (result: string, cx, cy) ->
      let patch = OnChangeOf(cx, cy)
      Button.create [
          Button.height SearchItemHeight
          Button.verticalContentAlignment VerticalAlignment.Center
          Button.background (searchResultBgColor model i selectedIdx)
          Button.foreground model.Theme.Search.Foreground
          Button.borderThickness 0.0
          Button.horizontalAlignment HorizontalAlignment.Stretch
          Button.content (searchResultItemView model query result)
          Button.onClick (onSearchItemSelect dispatch localState cx cy, patch)
      ] :> IView
    )

  let searchResultListView model dispatch localState results =
    ScrollViewer.create [
      ScrollViewer.maxHeight 300.0
      ScrollViewer.content (
        StackPanel.create [
          StackPanel.background model.Theme.Search.Background
          StackPanel.children (
            searchResultsToButtons model dispatch localState results
          )
        ]
      )
    ] |> View.withOutlet (fun sv -> localState.ScrollViewer.Set(Some sv))

  let searchResultView model dispatch localState (results: _[]) =
    Popup.create [
      Popup.isOpen (localState.IsOpen.Current && results.Length > 0)
      Popup.placement PlacementMode.Bottom
      Popup.verticalOffset 4.0
      Popup.width 240.0
      Popup.isLightDismissEnabled true
      Popup.onClosed (fun _ -> localState.IsOpen.Set false)
      Popup.child (searchResultListView model dispatch localState results)
    ]

  let view model dispatch =
    let tabID = getTabID model
    let themeKey = getThemeKey model
    Component.create ($"search-view-{tabID}-{themeKey}", fun ctx ->
      let localState =
        { SearchText = ctx.useState ""
          IsOpen = ctx.useState false
          SelectedIdx = ctx.useState -1
          ScrollViewer = ctx.useState None }
      let results = search model localState.SearchText.Current
      Grid.create [
        Grid.width 240.0
        Grid.height ToolbarHeight
        Grid.children [
          searchInputView model dispatch localState results
          searchIconView model
          searchResultView model dispatch localState results
        ]
      ]
    )

end

module private CFGKindSelect = begin

  let getState model =
    match model.ActiveTab with
    | Some { ID = id; Content = CFGContent(_, Loaded(_, { CFGKind = cfg })) } ->
      cfg, true, id
    | _ -> CFGKind.Disasm, false, "none"

  let onGraphKindChanged dispatch (args: obj) =
    match args with
    | :? CFGKind as newKind -> dispatch (ChangeCFGKind newKind)
    | _ -> ()

  let itemTemplate model =
    DataTemplateView<string>.create (fun txt ->
      TextBlock.create [
        TextBlock.text txt
        TextBlock.foreground model.Theme.Text.Primary
        TextBlock.fontFamily model.Theme.Font.Monospace.FontFamily
        TextBlock.fontSize 12.0
        TextBlock.padding (4.0, 2.0)
      ]
    )

  let view model dispatch =
    let currentCFGKind, isEnabled, tabKey = getState model
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
      ComboBox.onSelectedItemChanged (onGraphKindChanged dispatch)
      ItemsControl.itemTemplate (itemTemplate model)
    ] |> View.withKey $"graph-select-{tabKey}"

end

module private MinimapToggle = begin

  let getState model =
    match model.ActiveTab with
    | Some { ID = id
             Content = CFGContent(_, Loaded(_, { ShowMinimap = flg })) } ->
      true, flg, id
    | _ -> false, false, "none"

  let background model isActive =
    if isActive then model.Theme.Tab.ActiveBackground
    else model.Theme.Panel.Background

  let view model dispatch =
    let isEnabled, isActive, tabKey = getState model
    ToggleButton.create
      [ ToggleButton.width 26.0
        ToggleButton.height ToolbarHeight
        ToggleButton.padding (4.0, 0.0)
        ToggleButton.isChecked isActive
        ToggleButton.isEnabled isEnabled
        ToggleButton.background (background model isActive)
        ToggleButton.foreground model.Theme.Text.Primary
        ToggleButton.borderBrush model.Theme.Panel.Border
        ToggleButton.borderThickness 1.0
        ToggleButton.cornerRadius 4.0
        ToggleButton.onChecked (fun _ -> dispatch (ToggleMinimap(tabKey, true)))
        ToggleButton.onUnchecked (fun _ ->
          dispatch (ToggleMinimap(tabKey, false)))
        ToggleButton.content (mkIcon (IconAssets.mapIcon model) 20.0) ]
      |> View.withKey $"minimap-toggle-{tabKey}"

end

/// The main toolbar view, which contains the search box and other controls.
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
          SearchBox.view model dispatch
          CFGKindSelect.view model dispatch
          MinimapToggle.view model dispatch
        ]
      ]
    )
  ]
