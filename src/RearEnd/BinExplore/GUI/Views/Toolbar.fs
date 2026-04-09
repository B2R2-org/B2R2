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
  let [<Literal>] MaxSearchResults = 50

  type SearchTarget =
    | CFGPoint of gx: float * gy: float
    | HexRange of byteIndex: int64 * length: int64

  type SearchResult =
    { Label: string
      Target: SearchTarget }

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

  let appendResult acc item =
    if List.length acc < MaxSearchResults then item :: acc
    else acc

  let normalizeHexDigits (input: string) =
    input
    |> Seq.filter (fun ch -> not (Char.IsWhiteSpace ch))
    |> Array.ofSeq
    |> String

  let tryParseHexAddress (input: string) =
    let trimmed = input.Trim()
    let digits =
      if trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        trimmed.Substring 2
      else
        trimmed
    if String.IsNullOrWhiteSpace digits then None
    elif digits |> Seq.forall Uri.IsHexDigit then
      match UInt64.TryParse(
        digits,
        Globalization.NumberStyles.HexNumber,
        Globalization.CultureInfo.InvariantCulture
      ) with
      | true, addr -> Some addr
      | _ -> None
    else None

  let tryParseHexBytes (input: string) =
    let digits = normalizeHexDigits input
    if String.IsNullOrWhiteSpace digits || digits.Length % 2 <> 0 then None
    elif digits |> Seq.forall Uri.IsHexDigit then
      let bytes =
        [| for i in 0 .. 2 .. digits.Length - 2 do
             Convert.ToByte(digits.Substring(i, 2), 16) |]
      Some bytes
    else None

  let tryGetAsciiBytes (input: string) =
    if input |> Seq.forall (fun ch -> int ch <= 0x7F) then
      Some(input |> Seq.map byte |> Array.ofSeq)
    else None

  let findBytePattern (haystack: byte[]) (needle: byte[]) =
    if needle.Length = 0 || haystack.Length < needle.Length then
      [||]
    else
      [| for startIdx in 0 .. haystack.Length - needle.Length do
           let mutable matched = true
           let mutable i = 0
           while matched && i < needle.Length do
             if haystack[startIdx + i] <> needle[i] then matched <- false
             else ()
             i <- i + 1
           if matched then int64 startIdx else () |]

  let formatAddressLabel addr =
    $"[addr] 0x{addr:X}"

  let formatHexLabel addr (matched: byte[]) =
    let hexText =
      matched
      |> Array.map (fun b -> $"{b:X2}")
      |> String.concat " "
    $"[hex] 0x{addr:X}: {hexText}"

  let formatAsciiLabel addr (matched: string) =
    $"[ascii] 0x{addr:X}: {matched}"

  let searchHexdump doc (input: string) =
    let input = input.Trim()
    let mutable results = []
    match tryParseHexAddress input with
    | Some addr when addr >= doc.BaseAddress
                     && addr < doc.BaseAddress + uint64 doc.Length ->
      let byteIndex = int64 (addr - doc.BaseAddress)
      results <-
        appendResult results
          { Label = formatAddressLabel addr
            Target = HexRange(byteIndex, 1L) }
    | _ -> ()
    match tryParseHexBytes input with
    | Some needle ->
      for idx in findBytePattern doc.Bytes needle do
        let addr = doc.BaseAddress + uint64 idx
        let result =
          { Label = formatHexLabel addr needle
            Target = HexRange(idx, int64 needle.Length) }
        results <- appendResult results result
    | None -> ()
    match tryGetAsciiBytes input with
    | Some asciiBytes when asciiBytes.Length > 0 ->
      for idx in findBytePattern doc.Bytes asciiBytes do
        let addr = doc.BaseAddress + uint64 idx
        let result =
          { Label = formatAsciiLabel addr input
            Target = HexRange(idx, int64 asciiBytes.Length) }
        results <- appendResult results result
    | _ -> ()
    results |> List.rev |> List.truncate MaxSearchResults |> List.toArray

  let searchCFGTab (g: VisGraph) (input: string) =
    [| for v in g.Vertices do
         let cx = v.VData.Coordinate.X + v.VData.Width / 2.0
         let cy = v.VData.Coordinate.Y + v.VData.Height / 2.0
         for line in (v.VData :> IVisualizable).Visualize() do
           let s = asmLineToString line
           if s.Contains(input, StringComparison.OrdinalIgnoreCase) then
             { Label = s
               Target = CFGPoint(cx, cy) }
           else
             () |]

  let searchHexTab state (input: string) =
    searchHexdump state.Document input

  let search model (input: string) =
    if String.IsNullOrWhiteSpace input then
      [||]
    else
      match model.ActiveTab with
      | Some { Content = CFGContent(_, Loaded loaded) } ->
        searchCFGTab loaded.Graph input
      | Some { Content = HexContent state } ->
        searchHexTab state input
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

  let onSearchItemSelect dispatch localState target _evt =
    match target with
    | CFGPoint(cx, cy) ->
      dispatch (CFGMsg(JumpPan(cx, cy)))
    | HexRange(byteIndex, length) ->
      dispatch (HexdumpMsg(JumpToRange(byteIndex, length)))
    localState.IsOpen.Set false
    localState.SelectedIdx.Set -1

  let onSearchTextChanged localState (txt: string) =
    localState.SearchText.Set txt
    localState.SelectedIdx.Set -1
    localState.IsOpen.Set(not (String.IsNullOrWhiteSpace txt))

  let clearSearch model dispatch localState =
    localState.SearchText.Set ""
    localState.IsOpen.Set false
    localState.SelectedIdx.Set -1
    match model.ActiveTab with
    | Some { Content = HexContent _ } ->
      dispatch (HexdumpMsg(SetHighlightSpans []))
      dispatch (HexdumpMsg(SetSelection None))
    | _ ->
      ()

  let onSearchKeyDown model dispatch localState (results: _[]) e =
    let count = Array.length results
    match (e: KeyEventArgs).Key with
    | Key.Escape ->
      clearSearch model dispatch localState
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
      let result = results[localState.SelectedIdx.Current]
      onSearchItemSelect dispatch localState result.Target null
      e.Handled <- true
    | _ -> ()

  let searchInputView model dispatch localState (results: _[]) =
    let hasSearchText =
      not (String.IsNullOrEmpty localState.SearchText.Current)
    TextBox.create [
      TextBox.width 240.0
      TextBox.height ToolbarHeight
      TextBox.text localState.SearchText.Current
      TextBox.fontSize 12.0
      TextBox.watermark "Search..."
      TextBox.verticalContentAlignment VerticalAlignment.Center
      TextBox.background model.Theme.Panel.Background
      TextBox.foreground model.Theme.Text.Primary
      TextBox.borderBrush model.Theme.Panel.Border
      TextBox.borderThickness (1.0, 1.0, 1.0, 1.0)
      TextBox.cornerRadius (CornerRadius(4.0, 0.0, 0.0, 4.0))
      TextBox.padding (
        if hasSearchText then Thickness(6.0, 0.0, 54.0, 0.0)
        else Thickness(6.0, 0.0, 28.0, 0.0)
      )
      TextBox.onTextChanged (onSearchTextChanged localState)
      TextBox.onKeyDown (
        onSearchKeyDown model dispatch localState results, OnChangeOf results
      )
    ] :> IView

  let searchClearView model dispatch localState =
    Button.create [
      Button.width 26.0
      Button.height (ToolbarHeight - 4.0)
      Button.focusable false
      Button.background model.Theme.Common.Transparent
      Button.borderBrush model.Theme.Common.Transparent
      Button.borderThickness 0.0
      Button.padding 0.0
      Control.onPointerPressed (fun args ->
        clearSearch model dispatch localState
        args.Handled <- true)
      Button.content (
        TextBlock.create [
          TextBlock.text "x"
          TextBlock.foreground model.Theme.Search.ClearForeground
          TextBlock.fontSize 14.0
          TextBlock.fontWeight FontWeight.Bold
          TextBlock.verticalAlignment VerticalAlignment.Center
          TextBlock.horizontalAlignment HorizontalAlignment.Center
        ]
      )
      Button.onClick (fun _ -> clearSearch model dispatch localState)
    ]

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

  let searchAdornmentView model dispatch localState =
    let hasSearchText =
      not (String.IsNullOrEmpty localState.SearchText.Current)
    StackPanel.create [
      StackPanel.orientation Orientation.Horizontal
      StackPanel.horizontalAlignment HorizontalAlignment.Right
      StackPanel.children [
        if hasSearchText then
          yield searchClearView model dispatch localState :> IView
        else
          ()
        yield searchIconView model :> IView
      ]
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
    |> List.mapi (fun i result ->
      let patch = OnChangeOf result.Target
      Button.create [
          Button.height SearchItemHeight
          Button.verticalContentAlignment VerticalAlignment.Center
          Button.background (searchResultBgColor model i selectedIdx)
          Button.foreground model.Theme.Search.Foreground
          Button.borderThickness 0.0
          Button.horizontalAlignment HorizontalAlignment.Stretch
          Button.content (searchResultItemView model query result.Label)
          Button.onClick (
            onSearchItemSelect dispatch localState result.Target, patch
          )
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
      Popup.isLightDismissEnabled false
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
          searchAdornmentView model dispatch localState
          searchResultView model dispatch localState results
        ]
      ]
    )

end

module private CFGKindSelect = begin

  let getState model =
    match model.ActiveTab with
    | Some { ID = id; Content = CFGContent(_, Loaded { ViewState = view }) } ->
      view.CFGKind, true, id
    | _ ->
      CFGKind.Disasm, false, "none"

  let onGraphKindChanged dispatch (args: obj) =
    match args with
    | :? CFGKind as newKind -> dispatch (CFGMsg(ChangeKind newKind))
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
    | Some { ID = id; Content = CFGContent(_, Loaded { ViewState = view }) } ->
      true, view.ShowMinimap, id
    | _ ->
      false, false, "none"

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
        ToggleButton.onChecked (fun _ ->
          dispatch (CFGMsg(ToggleMinimap(tabKey, true))))
        ToggleButton.onUnchecked (fun _ ->
          dispatch (CFGMsg(ToggleMinimap(tabKey, false))))
        ToggleButton.content (mkIcon (IconAssets.mapIcon model) 20.0) ]
      |> View.withKey $"minimap-toggle-{tabKey}"

end

module private HexSyncToggle = begin

  let view model dispatch =
    ToggleButton.create
      [ ToggleButton.width 26.0
        ToggleButton.height ToolbarHeight
        ToggleButton.padding (4.0, 0.0)
        ToggleButton.isChecked model.HexSyncEnabled
        ToggleButton.isEnabled model.ActiveTab.IsSome
        ToggleButton.background model.Theme.Panel.Background
        ToggleButton.foreground model.Theme.Text.Primary
        ToggleButton.borderBrush model.Theme.Panel.Border
        ToggleButton.borderThickness 1.0
        ToggleButton.cornerRadius 4.0
        ToggleButton.onChecked (fun _ -> dispatch (SetHexSyncEnabled true))
        ToggleButton.onUnchecked (fun _ -> dispatch (SetHexSyncEnabled false))
        ToggleButton.content (mkIcon (IconAssets.syncIcon model) 20.0) ]
      |> View.withKey "hex-sync-toggle"

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
          HexSyncToggle.view model dispatch
        ]
      ]
    )
  ]
