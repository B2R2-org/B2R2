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

module B2R2.RearEnd.BinExplore.GUI.Update

open System
open System.IO
open Avalonia.Controls
open Avalonia.Media
open Avalonia.Styling
open Avalonia.Threading
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.BinExplore
open B2R2.RearEnd.Visualization

let private dispatchOnUi dispatch msg =
  Dispatcher.UIThread.Post(fun () -> dispatch msg)

let private cmdOfSub sub: Elmish.Cmd<Message> =
  [ sub ]

let private deferHexdumpScrollCmd offsetY: Elmish.Cmd<Message> =
  cmdOfSub (fun dispatch ->
    Dispatcher.UIThread.Post(
      (fun () ->
        Dispatcher.UIThread.Post(
          (fun () -> dispatch (HexdumpMsg(SetScrollOffset offsetY))),
          DispatcherPriority.Background
        )),
      DispatcherPriority.Background
    ))

let private loadBinaryAsync (arbiter: Arbiter<_, _>) (filePath: string) =
  async {
    return arbiter.AddBinary filePath
  }

let private startLoadWorkflowCmd (arbiter: Arbiter<_, _>) (filePath: string) =
  cmdOfSub (fun dispatch ->
    let displayName = Path.GetFileName filePath
    let mutable running = true
    let dots = [| "."; ".."; "..." |]
    let animate =
      async {
        let mutable i = 0
        while running do
          dispatchOnUi dispatch
          <| UpdateStatus $"Loading {displayName} {dots[i % dots.Length]}"
          do! Async.Sleep 250
          i <- i + 1
      }
    Async.Start animate
    Async.Start(async {
      try
        match! loadBinaryAsync arbiter filePath with
        | Ok() ->
          running <- false
          dispatchOnUi dispatch (OpenBinaryCompleted filePath)
        | Error reason ->
          running <- false
          dispatchOnUi dispatch (OpenBinaryFailed(filePath, reason))
      with ex ->
        running <- false
        dispatchOnUi dispatch (OpenBinaryFailed(filePath, ex.Message))
    }))

let openBinary (arbiter: Arbiter<_, _>) model filePath =
  if String.IsNullOrWhiteSpace filePath then
    model, Elmish.Cmd.none
  else
    { model with LoadingBinaryPath = Some filePath },
    startLoadWorkflowCmd arbiter filePath

let private mkText typeface fontSize text =
  FormattedText(
    text,
    Globalization.CultureInfo.CurrentCulture,
    FlowDirection.LeftToRight,
    typeface,
    fontSize,
    Brushes.Black
  )

let private measureMaxCharSize model =
  let fontFamily = FontFamily model.Theme.Font.Monospace.FontFamily
  let fontSize = model.Theme.Font.Monospace.FontSize
  let typeface = Typeface fontFamily
  let txt = mkText typeface fontSize "M"
  txt.Width, txt.Height

let private computeHexBytesPerRow viewState =
  let charWidth = max viewState.CharWidth 1.0
  let viewportChars = max 0.0 ((viewState.ViewportWidth - 16.0) / charWidth)
  let addressChars = float (viewState.AddressDigits + 3)
  let asciiGapChars = 2.0
  let perByteChars = 4.0
  let bytes =
    floor ((viewportChars - addressChars - asciiGapChars) / perByteChars)
    |> int
  let quantized = if bytes <= 4 then 4 else bytes / 4 * 4
  max 4 quantized

let private computeHexTotalRows hexdump viewState =
  let doc = hexdump.Document
  let bytesPerRow = max 1 viewState.BytesPerRow
  if doc.Length <= 0L then 0L
  else (doc.Length + int64 bytesPerRow - 1L) / int64 bytesPerRow

let private clampHexScrollState hexdump viewState =
  let totalRows = computeHexTotalRows hexdump viewState
  let rowHeight = max viewState.RowHeight 1.0
  let contentHeight = float totalRows * rowHeight
  let maxScrollOffset = max 0.0 (contentHeight - viewState.ViewportHeight)
  let scrollOffsetY = max 0.0 (min maxScrollOffset viewState.ScrollOffsetY)
  let scrollRow = int64 (floor (scrollOffsetY / rowHeight))
  { viewState with ScrollOffsetY = scrollOffsetY; ScrollRow = scrollRow }

let private initializeHexdumpTabView model hexdump =
  let view = hexdump.View
  let viewportWidth, viewportHeight = model.ContentViewportSize
  let charWidth, rowHeight =
    if view.CharWidth > 0.0 && view.RowHeight > 0.0 then
      view.CharWidth, view.RowHeight
    else
      measureMaxCharSize model
  let nextView =
    { view with
        ViewportWidth = viewportWidth
        ViewportHeight = viewportHeight
        CharWidth = charWidth
        RowHeight = rowHeight }
  { hexdump with
      View =
        { nextView with
            BytesPerRow =
              if viewportWidth > 0.0 then computeHexBytesPerRow nextView
              else nextView.BytesPerRow } }

let private prepareHexdumpViewForActivation hexdump =
  let viewState = hexdump.View
  { hexdump with
      View =
        { viewState with
            ScrollGuard =
              if viewState.ScrollOffsetY > 0.0 then
                IgnoreNextProgrammatic viewState.ScrollOffsetY
              else
                NoScrollGuard } }

let private activateHexdumpView model =
  initializeHexdumpTabView model >> prepareHexdumpViewForActivation

let openBinaryCompleted (arbiter: Arbiter<_, _>) model filePath =
  if model.LoadingBinaryPath = Some filePath then
    let functions, statusBar =
      match API.getFunctions arbiter true, API.getFile arbiter with
      | Ok fns, Ok file ->
        fns |> Array.map FunctionItem.ofFunction |> List.ofArray,
        FileLoaded(filePath, FileFormat.toString file.Format)
      | _ ->
        [], EmptyStatus
    { model with
        LoadedBinary = Some filePath
        LoadingBinaryPath = None
        Functions = functions
        FunctionFilter = ""
        ActiveTab = None
        OpenTabs = []
        PreviewTab = None
        DraggingTab = None
        WorkspacePanel = FunctionPanel
        StatusBarState = statusBar },
    Elmish.Cmd.none
  else
    model, Elmish.Cmd.none

let openBinaryFailed model filePath reason =
  if model.LoadingBinaryPath = Some filePath then
    { model with
        LoadingBinaryPath = None
        StatusBarState = MessageOnly $"Failed to load binary: {reason}" },
    Elmish.Cmd.none
  else
    model, Elmish.Cmd.none

let closeWorkspace (arbiter: Arbiter<_, _>) model =
  arbiter.CloseSession()
  { model with
      LoadedBinary = None
      LoadingBinaryPath = None
      Functions = []
      FunctionFilter = ""
      ActiveTab = None
      OpenTabs = []
      PreviewTab = None
      DraggingTab = None
      WorkspacePanel = FunctionPanel
      StatusBarState = EmptyStatus },
  Elmish.Cmd.none

let private tryFindTab tabs tabID =
  tabs |> List.tryFind (fun t -> t.ID = tabID)

let private replaceTabByID tabID newTab oldTab =
  if oldTab.ID = tabID then newTab
  else oldTab

let private replaceTabReferences model tab =
  let opens = model.OpenTabs |> List.map (replaceTabByID tab.ID tab)
  let preview = model.PreviewTab |> Option.map (replaceTabByID tab.ID tab)
  let active = model.ActiveTab |> Option.map (replaceTabByID tab.ID tab)
  { model with
      OpenTabs = opens
      PreviewTab = preview
      ActiveTab = active }

let openHexdumpTab (arbiter: Arbiter<_, _>) model =
  let visibleTabs = Model.getVisibleTabs model
  match visibleTabs |> List.tryFind (fun t -> t.ID = Tab.HexdumpTabID) with
  | Some tab ->
    let tab = Tab.mapHexdumpState (activateHexdumpView model) tab
    let opens = model.OpenTabs |> List.map (replaceTabByID tab.ID tab)
    let preview = model.PreviewTab |> Option.map (replaceTabByID tab.ID tab)
    { model with
        ActiveTab = Some tab
        OpenTabs = opens
        PreviewTab = preview },
    Elmish.Cmd.none
  | None ->
    match API.getFile arbiter with
    | Ok file ->
      let numDigits = (file.ISA.WordSize |> B2R2.WordSize.toByteWidth) * 2
      let hexdump =
        HexdumpState.ofBytes file.BaseAddress file.RawBytes numDigits
        |> activateHexdumpView model
      let tab = Tab.ofHexdump hexdump
      { model with
          ActiveTab = Some tab
          OpenTabs = tab :: model.OpenTabs },
      Elmish.Cmd.none
    | Error _ ->
      model, Elmish.Cmd.none

let private mapCFGTabState newState (tab: Tab) =
  match tab.Content with
  | CFGContent(func, _) ->
    { tab with Content = CFGContent(func, newState) }
  | _ ->
    tab

let private updateHexdumpState model update =
  let visibleTabs = Model.getVisibleTabs model
  match visibleTabs |> List.tryFind (fun t -> t.ID = Tab.HexdumpTabID) with
  | Some({ Content = HexContent hexdump } as tab) ->
    let hexdump =
      update hexdump
      |> fun state ->
        let view = clampHexScrollState state state.View
        { state with View = view }
    let tab = Tab.mapHexdumpState (fun _ -> hexdump) tab
    replaceTabReferences model tab, Elmish.Cmd.none
  | _ ->
    model, Elmish.Cmd.none

let private updateHexViewState model updateView =
  updateHexdumpState model (fun hexdump ->
    let view = updateView hexdump.View
    { hexdump with View = view })

let private getActiveHexScrollGuard model =
  match model.ActiveTab with
  | Some { Content = HexContent hexdump } -> hexdump.View.ScrollGuard
  | _ -> NoScrollGuard

let private recomputeHexViewLayout model updateView =
  let charWidth, rowHeight = measureMaxCharSize model
  updateHexdumpState model (fun hexdump ->
    let viewState = hexdump.View
    let topByte = viewState.ScrollRow * int64 (max 1 viewState.BytesPerRow)
    let nextView =
      updateView viewState
      |> fun v -> { v with CharWidth = charWidth; RowHeight = rowHeight }
    let nextView =
      { nextView with BytesPerRow = computeHexBytesPerRow nextView }
    let nextScrollRow = topByte / int64 (max 1 nextView.BytesPerRow)
    let view =
      { nextView with
          ScrollRow = nextScrollRow
          ScrollOffsetY = float nextScrollRow * nextView.RowHeight }
    { hexdump with View = view })

let private resizeOpenedHexdumpTab model width height =
  let hasOpenedHexdumpTab =
    model.OpenTabs |> List.exists (fun tab -> tab.ID = Tab.HexdumpTabID)
  if hasOpenedHexdumpTab then
    updateHexdumpState model (fun hexdump ->
      let viewState = hexdump.View
      let charWidth, rowHeight = measureMaxCharSize model
      let nextView =
        { viewState with
            ViewportWidth = width
            ViewportHeight = height
            CharWidth = charWidth
            RowHeight = rowHeight }
      let view = { nextView with BytesPerRow = computeHexBytesPerRow nextView }
      { hexdump with View = view })
    |> fst
  else
    model

let private jumpHexdump model byteIndex length =
  match model.ActiveTab with
  | Some { Content = HexContent hexdump } ->
    let doc = hexdump.Document
    let viewState = hexdump.View
    let byteIndex = max 0L (min (doc.Length - 1L) byteIndex)
    let matchLength = max 1L length
    let selectionEnd = min (doc.Length - 1L) (byteIndex + matchLength - 1L)
    let highlightLength = selectionEnd - byteIndex + 1L
    let rowHeight = max viewState.RowHeight 1.0
    let bytesPerRow = max 1 viewState.BytesPerRow
    let targetRow = byteIndex / int64 bytesPerRow
    let targetOffsetY = float targetRow * rowHeight
    let scrolledView =
      { viewState with ScrollGuard = NoScrollGuard }
      |> clampHexScrollState hexdump
    let targetOffsetY =
      max 0.0
        (min targetOffsetY
          (let totalRows = computeHexTotalRows hexdump scrolledView
           let contentHeight = float totalRows * rowHeight
           max 0.0 (contentHeight - scrolledView.ViewportHeight)))
    let currentOffsetY = float viewState.ScrollRow * rowHeight
    let pendingDelta = targetOffsetY - currentOffsetY
    let nextView =
      { scrolledView with
          ScrollGuard =
            if abs pendingDelta > 0.5 then
              IgnoreNextProgrammatic pendingDelta
            else
              NoScrollGuard }
    let nextHexdump =
      { hexdump with
          Caret = Some byteIndex
          Selection = None
          HighlightSpans =
            [ { Start = byteIndex
                Length = highlightLength
                Foreground = Some model.Theme.Search.Foreground
                Background = Some model.Theme.Search.SelectedBackground
                Priority = 100 } ]
          View = nextView }
    let activeTab =
      model.ActiveTab
      |> Option.map (Tab.mapHexdumpState (fun _ -> nextHexdump))
    let model =
      match activeTab with
      | Some tab -> replaceTabReferences model tab
      | None -> model
    let cmd =
      if abs pendingDelta > 0.5 then
        deferHexdumpScrollCmd targetOffsetY
      else
        Elmish.Cmd.none
    model, cmd
  | _ ->
    model, Elmish.Cmd.none

let private clampHexByteIndex hexdump byteIndex =
  if hexdump.Document.Length <= 0L then None
  else Some(max 0L (min (hexdump.Document.Length - 1L) byteIndex))

let updateHexdump model msg =
  match msg with
  | SetHighlightSpans spans ->
    updateHexdumpState model (fun hexdump ->
      { hexdump with HighlightSpans = spans })
  | UpdateViewport(width, height) when width > 0.0 && height > 0.0 ->
    recomputeHexViewLayout model (fun viewState ->
      { viewState with ViewportWidth = width; ViewportHeight = height })
  | UpdateFontMetrics(charWidth, rowHeight)
    when charWidth > 0.0 && rowHeight > 0.0 ->
    updateHexViewState model (fun viewState ->
      let topByte = viewState.ScrollRow * int64 (max 1 viewState.BytesPerRow)
      let nextView =
        { viewState with CharWidth = charWidth; RowHeight = rowHeight }
      let nextView =
        { nextView with BytesPerRow = computeHexBytesPerRow nextView }
      let nextScrollRow = topByte / int64 (max 1 nextView.BytesPerRow)
      { nextView with
          ScrollRow = nextScrollRow
          ScrollOffsetY = float nextScrollRow * nextView.RowHeight })
  | JumpToRange(byteIndex, length) ->
    jumpHexdump model byteIndex length
  | HandleScrollChanged(deltaY) ->
    let currentGuard = getActiveHexScrollGuard model
    match currentGuard with
    | IgnoreNextProgrammatic _ when abs deltaY <= 0.0 ->
      model, Elmish.Cmd.none
    | IgnoreNextProgrammatic _ ->
      updateHexdumpState model (fun hexdump ->
        let view =
          { hexdump.View with ScrollGuard = NoScrollGuard }
        { hexdump with View = view })
    | IgnoreNextEcho _ when abs deltaY <= 0.0 ->
      model, Elmish.Cmd.none
    | IgnoreNextEcho _ ->
      updateHexdumpState model (fun hexdump ->
        let view =
          { hexdump.View with ScrollGuard = NoScrollGuard }
        { hexdump with View = view })
    | _ when abs deltaY <= 0.0 ->
      model, Elmish.Cmd.none
    | _ ->
      updateHexdumpState model (fun hexdump ->
        let viewState = hexdump.View
        let nextOffsetY = viewState.ScrollOffsetY + deltaY
        let rowHeight = max viewState.RowHeight 1.0
        let scrollRow = int64 (floor (nextOffsetY / rowHeight))
        let view =
          { viewState with
              ScrollOffsetY = nextOffsetY
              ScrollRow = scrollRow
              ScrollGuard = NoScrollGuard }
        { hexdump with View = view })
  | SetScrollOffset(offsetY) ->
    updateHexdumpState model (fun hexdump ->
      let viewState = hexdump.View
      let rowHeight = max viewState.RowHeight 1.0
      let scrollRow = int64 (floor (offsetY / rowHeight))
      let view =
        { viewState with
            ScrollOffsetY = offsetY
            ScrollRow = scrollRow
            ScrollGuard = viewState.ScrollGuard }
      { hexdump with View = view })
  | SetScrollRow(row) ->
    updateHexdumpState model (fun hexdump ->
      let viewState = hexdump.View
      let rowHeight = max viewState.RowHeight 1.0
      let view =
        { viewState with
            ScrollRow = row
            ScrollOffsetY = float row * rowHeight
            ScrollGuard = NoScrollGuard }
      { hexdump with View = view })
  | ScrollRows(delta) ->
    updateHexdumpState model (fun hexdump ->
      let viewState = hexdump.View
      let rowHeight = max viewState.RowHeight 1.0
      let scrollRow = viewState.ScrollRow + delta
      let view =
        { viewState with
            ScrollRow = scrollRow
            ScrollOffsetY = float scrollRow * rowHeight
            ScrollGuard = NoScrollGuard }
      { hexdump with View = view })
  | SetCaret byteIndex ->
    updateHexdumpState model (fun hexdump ->
      let caret = byteIndex |> Option.bind (clampHexByteIndex hexdump)
      { hexdump with Caret = caret })
  | SetSelection selection ->
    updateHexdumpState model (fun hexdump ->
      let selection =
        selection
        |> Option.bind (fun sel ->
          match clampHexByteIndex hexdump sel.Anchor,
                clampHexByteIndex hexdump sel.Caret with
          | Some anchor, Some caret -> Some { Anchor = anchor; Caret = caret }
          | _ -> None)
      { hexdump with Selection = selection })
  | StartSelection byteIndex ->
    updateHexdumpState model (fun hexdump ->
      match clampHexByteIndex hexdump byteIndex with
      | Some byteIndex ->
        { hexdump with
            Caret = Some byteIndex
            Selection = Some { Anchor = byteIndex; Caret = byteIndex }
            View = { hexdump.View with IsSelecting = true } }
      | None ->
        hexdump)
  | UpdateSelection byteIndex ->
    updateHexdumpState model (fun hexdump ->
      match hexdump.View.IsSelecting,
            clampHexByteIndex hexdump byteIndex,
            hexdump.Selection with
      | true, Some byteIndex, Some selection ->
        { hexdump with
            Caret = Some byteIndex
            Selection = Some { selection with Caret = byteIndex } }
      | true, Some byteIndex, None ->
        { hexdump with
            Caret = Some byteIndex
            Selection = Some { Anchor = byteIndex; Caret = byteIndex } }
      | _ ->
        hexdump)
  | EndSelection ->
    updateHexdumpState model (fun hexdump ->
      { hexdump with View = { hexdump.View with IsSelecting = false } })
  | SetHoveredByte byteIndex ->
    updateHexViewState model (fun viewState ->
      let hovered =
        match model.ActiveTab with
        | Some { Content = HexContent hexdump } ->
          byteIndex |> Option.bind (clampHexByteIndex hexdump)
        | _ -> None
      { viewState with HoveredByte = hovered })
  | _ ->
    model, Elmish.Cmd.none

let private getCFG (arbiter: Arbiter<_, _>) model cfgKind addr =
  match cfgKind with
  | CFGKind.Disasm ->
    measureMaxCharSize model
    ||> API.getDisasmCFG arbiter addr
  | CFGKind.LowUIR ->
    measureMaxCharSize model
    ||> API.getLowUIRCFG arbiter addr
  | CFGKind.SSA ->
    measureMaxCharSize model
    ||> API.getSSACFG arbiter addr
  | _ ->
    API.getCallCFG arbiter

let private loadCFGCmd arbiter model (fn: FunctionItem) cfgKind (tab: Tab) =
  cmdOfSub (fun dispatch ->
    Async.Start(async {
      try
        match getCFG arbiter model cfgKind fn.Address with
        | Ok cfg ->
          dispatchOnUi dispatch (CFGMsg(LoadCompleted(tab.ID, cfgKind, cfg)))
        | Error e ->
          dispatchOnUi dispatch (CFGMsg(LoadFailed(tab.ID, e)))
      with ex ->
        dispatchOnUi dispatch (CFGMsg(LoadFailed(tab.ID, ex.Message)))
    }))

let private startLoadIfNeeded (arbiter: Arbiter<_, _>) tab model =
  match tab.Content with
  | CFGContent(fn, NotLoaded) ->
    let loadingTab = mapCFGTabState Loading tab
    let opens = model.OpenTabs |> List.map (replaceTabByID tab.ID loadingTab)
    let preview =
      model.PreviewTab |> Option.map (replaceTabByID tab.ID loadingTab)
    { model with
        ActiveTab = Some loadingTab
        OpenTabs = opens
        PreviewTab = preview },
    loadCFGCmd arbiter model fn CFGKind.Disasm loadingTab
  | _ ->
    model, Elmish.Cmd.none

let openCFGTab (arbiter: Arbiter<_, _>) model fnItem =
  let visibleTabs = Model.getVisibleTabs model
  let tab = Tab.ofFunctionItem fnItem
  match tryFindTab visibleTabs tab.ID with
  | Some tab ->
    startLoadIfNeeded arbiter tab { model with ActiveTab = Some tab }
  | None ->
    startLoadIfNeeded arbiter tab
      { model with
          ActiveTab = Some tab
          PreviewTab = Some tab }

let pinCFGTab (arbiter: Arbiter<_, _>) model fnItem =
  let tab = Tab.ofFunctionItem fnItem
  let newOpenTabs, tab, preview =
    match tryFindTab model.OpenTabs tab.ID, model.PreviewTab with
    | Some tab, preview -> model.OpenTabs, tab, preview
    | None, Some tab -> tab :: model.OpenTabs, tab, None
    | None, None -> tab :: model.OpenTabs, tab, None
  startLoadIfNeeded arbiter tab
    { model with
        ActiveTab = Some tab
        OpenTabs = newOpenTabs
        PreviewTab = preview }

let closeTab model tabID =
  let openTabs = model.OpenTabs |> List.filter (fun t -> t.ID <> tabID)
  let preview = model.PreviewTab |> Option.filter (fun t -> t.ID <> tabID)
  let dragging = model.DraggingTab |> Option.filter (fun t -> t.ID <> tabID)
  let active =
    match model.ActiveTab with
    | Some t when t.ID = tabID ->
      openTabs |> List.tryHead |> Option.orElse preview
    | _ ->
      model.ActiveTab
  { model with
      ActiveTab = active
      OpenTabs = openTabs
      PreviewTab = preview
      DraggingTab = dragging },
  Elmish.Cmd.none

let switchTab model tabID =
  let visibleTabs = Model.getVisibleTabs model
  match tryFindTab visibleTabs tabID with
  | Some tab ->
    let tab =
      if tab.ID = Tab.HexdumpTabID then
        Tab.mapHexdumpState prepareHexdumpViewForActivation tab
      else
        tab
    replaceTabReferences { model with ActiveTab = Some tab } tab,
    Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let startTabDrag model tabID =
  let visibleTabs = Model.getVisibleTabs model
  match tryFindTab visibleTabs tabID with
  | Some tab -> { model with DraggingTab = Some tab }, Elmish.Cmd.none
  | None -> model, Elmish.Cmd.none

let private findTwoTabs model tabID1 tabID2 =
  let tab1 = model.OpenTabs |> List.tryFind (fun t -> t.ID = tabID1)
  let tab2 = model.OpenTabs |> List.tryFind (fun t -> t.ID = tabID2)
  tab1, tab2

let private reorderOpenTabs model draggedTabID targetTabID =
  match findTwoTabs model draggedTabID targetTabID with
  | Some draggedTab, Some targetTab ->
    if draggedTab = targetTab then
      None
    else
      match List.tryFindIndex (fun t -> t = targetTab) model.OpenTabs with
      | Some targetIdx ->
        let filtered = model.OpenTabs |> List.filter ((<>) draggedTab)
        Some(filtered |> List.insertAt targetIdx draggedTab, draggedTab)
      | _ ->
        None
  | _ -> None

let reorderTab model draggedTabID targetTabID =
  match reorderOpenTabs model draggedTabID targetTabID with
  | Some(reorderedTabs, draggedTab) ->
    { model with
        OpenTabs = reorderedTabs
        DraggingTab = Some draggedTab },
    Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let endTabDrag model =
  if model.DraggingTab.IsSome then
    { model with DraggingTab = None }, Elmish.Cmd.none
  else
    model, Elmish.Cmd.none

let registerCustomTheme model themeId theme =
  let customThemes = model.CustomThemes |> Map.add themeId theme
  let currentTheme =
    match model.ThemeMode with
    | Custom selected when selected = themeId -> theme
    | _ -> model.Theme
  { model with
      CustomThemes = customThemes
      Theme = currentTheme },
  Elmish.Cmd.none

let private applyThemeVariant (window: Window) mode =
  match mode with
  | Builtin Light -> window.RequestedThemeVariant <- ThemeVariant.Light
  | Builtin Dark -> window.RequestedThemeVariant <- ThemeVariant.Dark
  | Custom _ -> ()

let setThemeMode window model mode =
  applyThemeVariant window mode
  let theme = Theme.resolve mode model.CustomThemes
  { model with
      ThemeMode = mode
      Theme = theme },
  Elmish.Cmd.none

let updateFunctionFilter model text =
  { model with FunctionFilter = text }, Elmish.Cmd.none

let selectWorkspacePanel (arbiter: Arbiter<_, _>) model panel =
  match panel with
  | SectionPanel ->
    let sections =
      match API.getSections arbiter with
      | Ok secs ->
        secs
        |> Array.map SectionItem.make
        |> List.ofArray
      | Error _ ->
        []
    { model with
        Sections = sections
        WorkspacePanel = SectionPanel }, Elmish.Cmd.none
  | _ ->
    { model with WorkspacePanel = panel }, Elmish.Cmd.none

let private findTopNodeAndBounds (cfg: VisGraph) =
  let vs = cfg.Vertices
  let mutable topNode = vs[0]
  let mutable minX = vs[0].VData.Coordinate.X
  let mutable minY = vs[0].VData.Coordinate.Y
  let mutable maxX = vs[0].VData.Coordinate.X + vs[0].VData.Width
  let mutable maxY = vs[0].VData.Coordinate.Y + vs[0].VData.Height
  for v in vs do
    if v.VData.Coordinate.Y < topNode.VData.Coordinate.Y then topNode <- v
    else ()
    let x = v.VData.Coordinate.X
    let y = v.VData.Coordinate.Y
    let right = x + v.VData.Width
    let bottom = y + v.VData.Height
    minX <- min minX x
    minY <- min minY y
    maxX <- max maxX right
    maxY <- max maxY bottom
  for e in cfg.Edges do
    for p in e.Label.Points do
      minX <- min minX p.X
      minY <- min minY p.Y
      maxX <- max maxX p.X
      maxY <- max maxY p.Y
  struct (topNode, minX, minY, maxX, maxY)

let private computeInitialCFGViewState cfgKind (cfg: VisGraph) model =
  let vs = cfg.Vertices
  if vs.Length = 0 then
    CFGViewState.init
  else
    let struct (topNode, minX, minY, maxX, maxY) = findTopNodeAndBounds cfg
    let graphWidth = maxX - minX
    let graphHeight = maxY - minY
    let rootCenterX = topNode.VData.Coordinate.X + topNode.VData.Width / 2.0
    let rootCenterY = topNode.VData.Coordinate.Y + topNode.VData.Height / 2.0
    let viewportWidth, viewportHeight = model.ContentViewportSize
    let minZoomW = min (viewportWidth * 0.9 / graphWidth) 1.0
    let minZoomH = min (viewportHeight * 0.9 / graphHeight) 1.0
    let minZoom = min minZoomW minZoomH
    { CFGViewState.init with
        PanX = viewportWidth / 2.0 - rootCenterX
        PanY = viewportHeight / 2.0 - rootCenterY
        CFGKind = cfgKind
        MinimumZoom = minZoom
        GraphWidth = graphWidth
        GraphHeight = graphHeight
        GraphMinX = minX
        GraphMinY = minY
        GraphMaxX = maxX
        GraphMaxY = maxY }

let loadCFGCompleted model tabID cfgKind cfg =
  let visibleTabs = Model.getVisibleTabs model
  match tryFindTab visibleTabs tabID with
  | Some tab ->
    let viewState = computeInitialCFGViewState cfgKind cfg model
    let tab = mapCFGTabState (Loaded(cfg, viewState)) tab
    replaceTabReferences model tab, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let loadCFGFailed model tabID _reason =
  let visibleTabs = Model.getVisibleTabs model
  match tryFindTab visibleTabs tabID with
  | Some tab ->
    let tab = mapCFGTabState NotLoaded tab
    replaceTabReferences model tab, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let private updateCFGViewState target update =
  match target with
  | { Content = CFGContent(fn, Loaded(cfg, viewState)) } ->
    let viewState' = update viewState
    { target with Content = CFGContent(fn, Loaded(cfg, viewState')) }
  | _ -> target

let private clampPanToGraphBounds panX panY viewState model =
  let viewportWidth, viewportHeight = model.ContentViewportSize
  let cameraCenterX = (viewportWidth / 2.0 - panX) / viewState.Zoom
  let cameraCenterY = (viewportHeight / 2.0 - panY) / viewState.Zoom
  let clampedCenterX =
    max viewState.GraphMinX (min viewState.GraphMaxX cameraCenterX)
  let clampedCenterY =
    max viewState.GraphMinY (min viewState.GraphMaxY cameraCenterY)
  let clampedPanX = viewportWidth / 2.0 - clampedCenterX * viewState.Zoom
  let clampedPanY = viewportHeight / 2.0 - clampedCenterY * viewState.Zoom
  clampedPanX, clampedPanY

let setCFGZoom model delta mouseX mouseY =
  match model.ActiveTab with
  | Some tab ->
    let update viewState =
      let oldZoom = viewState.Zoom
      let newZoom = min (max (oldZoom + delta) viewState.MinimumZoom) 2.0
      let graphX = (mouseX - viewState.PanX) / oldZoom
      let graphY = (mouseY - viewState.PanY) / oldZoom
      let newPanX = mouseX - graphX * newZoom
      let newPanY = mouseY - graphY * newZoom
      let clampedPanX, clampedPanY =
        clampPanToGraphBounds newPanX newPanY
          { viewState with Zoom = newZoom } model
      { viewState with
          Zoom = newZoom
          PanX = clampedPanX
          PanY = clampedPanY }
    let tab = updateCFGViewState tab update
    replaceTabReferences model tab, Elmish.Cmd.none
  | _ ->
    model, Elmish.Cmd.none

let [<Literal>] private CFGPanStartThresholdSquared = 16.0

let startCFGPan model x y =
  { model with
      CFGIsPanning = false
      CFGPressedPointer = Some(x, y)
      CFGPanPointer = None }, Elmish.Cmd.none

let moveCFGPan model x y space =
  match model.CFGPressedPointer, model.ActiveTab with
  | Some(pressedX, pressedY), Some tab when not model.CFGIsPanning ->
    let dx = x - pressedX
    let dy = y - pressedY
    if dx * dx + dy * dy < CFGPanStartThresholdSquared then
      model, Elmish.Cmd.none
    else
      { model with
          CFGIsPanning = true
          CFGPanPointer = Some(x, y) }, Elmish.Cmd.none
  | Some _, Some tab ->
    match model.CFGPanPointer with
    | Some(prevX, prevY) ->
      let update viewState =
        let dx = x - prevX
        let dy = y - prevY
        let dx, dy =
          match space with
          | ViewportSpace ->
            dx, dy
          | MinimapSpace minimapScale when minimapScale > 0.0 ->
            let factor = viewState.Zoom / -minimapScale
            dx * factor, dy * factor
          | MinimapSpace _ ->
            0.0, 0.0
        let newPanX = viewState.PanX + dx
        let newPanY = viewState.PanY + dy
        let clampedPanX, clampedPanY =
          clampPanToGraphBounds newPanX newPanY viewState model
        { viewState with
            PanX = clampedPanX
            PanY = clampedPanY }
      let tab = updateCFGViewState tab update
      { replaceTabReferences model tab with CFGPanPointer = Some(x, y) },
      Elmish.Cmd.none
    | None ->
      { model with CFGPanPointer = Some(x, y) }, Elmish.Cmd.none
  | _ ->
    model, Elmish.Cmd.none

let endCFGPan model =
  { model with
      CFGIsPanning = false
      CFGPressedPointer = None
      CFGPanPointer = None }, Elmish.Cmd.none

let jumpCFGPan model gx gy =
  match model.ActiveTab with
  | Some tab ->
    let update viewState =
      let viewportWidth, viewportHeight = model.ContentViewportSize
      let panX = viewportWidth / 2.0 - gx * viewState.Zoom
      let panY = viewportHeight / 2.0 - gy * viewState.Zoom
      let clampedPanX, clampedPanY =
        clampPanToGraphBounds panX panY viewState model
      { viewState with PanX = clampedPanX; PanY = clampedPanY }
    let tab = updateCFGViewState tab update
    replaceTabReferences model tab, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let selectCFGToken model nodeID lineIdx wordIdx =
  match model.ActiveTab with
  | Some tab ->
    let update viewState =
      { viewState with SelectedToken = Some(nodeID, lineIdx, wordIdx) }
    let tab = updateCFGViewState tab update
    replaceTabReferences model tab, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let setHoveredCFGEdge model edgeID =
  match model.ActiveTab with
  | Some tab ->
    let update viewState =
      { viewState with CFGViewState.HoveredEdge = edgeID }
    let tab = updateCFGViewState tab update
    replaceTabReferences model tab, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let updateCFGViewportSize model width height =
  if width <= 0.0 || height <= 0.0 then
    model, Elmish.Cmd.none
  else
    let currentWidth, currentHeight = model.ContentViewportSize
    let model = { model with ContentViewportSize = (width, height) }
    let model = resizeOpenedHexdumpTab model width height
    match model.ActiveTab with
    | Some tab ->
      let deltaX = width / 2.0 - currentWidth / 2.0
      let deltaY = height / 2.0 - currentHeight / 2.0
      let update viewState =
        { viewState with
            PanX = viewState.PanX + deltaX
            PanY = viewState.PanY + deltaY }
      let tab = updateCFGViewState tab update
      replaceTabReferences model tab, Elmish.Cmd.none
    | None ->
      model, Elmish.Cmd.none

let changeCFGKind (arbiter: Arbiter<_, _>) model kind =
  match model.ActiveTab with
  | Some { Content = CFGContent(fn, Loaded(_, { CFGKind = currentKind })) }
    when currentKind <> kind ->
    let tabContent = CFGContent(fn, NotLoaded)
    let tab = { model.ActiveTab.Value with Content = tabContent }
    replaceTabReferences model tab, loadCFGCmd arbiter model fn kind tab
  | _ ->
    model, Elmish.Cmd.none

let toggleMinimap model tabID activate =
  match model.ActiveTab with
  | Some { ID = activeID; Content = CFGContent(fn, Loaded(cfg, viewState)) }
    when activeID = tabID && viewState.ShowMinimap <> activate ->
    let newViewState = { viewState with ShowMinimap = activate }
    let tab =
      { model.ActiveTab.Value
          with Content = CFGContent(fn, Loaded(cfg, newViewState)) }
    replaceTabReferences model tab, Elmish.Cmd.none
  | _ ->
    model, Elmish.Cmd.none

let updateStatus model msg =
  { model with StatusBarState = MessageOnly msg }, Elmish.Cmd.none
