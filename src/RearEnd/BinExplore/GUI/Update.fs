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
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.ELF
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
          (fun () -> dispatch (HexdumpPaneMsg(SetScrollOffset offsetY))),
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
          <| UpdateStatusMsg $"Loading {displayName} {dots[i % dots.Length]}"
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

let private startLinearAnalysisCmd arbiter filePath sections fontSize =
  cmdOfSub (fun dispatch ->
    Async.Start(async {
      try
        match API.getFile arbiter with
        | Ok file ->
          let doc =
            LinearDocument.ofBytes file.BaseAddress file.RawBytes sections
          let state =
            LinearViewState.ofDocument doc fontSize
          dispatchOnUi dispatch (LinearAnalysisCompleted(filePath, doc, state))
        | _ ->
          dispatchOnUi dispatch
          <| LinearAnalysisFailed(filePath, "Failed to get loaded file.")
      with ex ->
        dispatchOnUi dispatch (LinearAnalysisFailed(filePath, ex.Message))
    }))

let openBinary (arbiter: Arbiter<_, _>) model filePath =
  if String.IsNullOrWhiteSpace filePath then
    model, Elmish.Cmd.none
  else
    { model with
        LoadingBinaryPath = Some filePath
        OffsetSnapshot = OffsetSnapshot.empty },
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

let [<Literal>] private MinHexdumpFontSize = 8.0

let [<Literal>] private MaxHexdumpFontSize = 32.0

let private clampHexdumpFontSize fontSize =
  max MinHexdumpFontSize (min MaxHexdumpFontSize fontSize)

let private measureMaxCharSizeWithFontSize model fontSize =
  let fontFamily = FontFamily model.Theme.Font.Monospace.FontFamily
  let typeface = Typeface fontFamily
  let txt = mkText typeface fontSize "M"
  txt.Width, txt.Height

let private measureMaxCharSize model =
  measureMaxCharSizeWithFontSize model model.Theme.Font.Monospace.FontSize

let private clampLinearScrollState linearViewState =
  let contentHeight = LinearViewState.totalHeight linearViewState
  let maxScrollOffset =
    max 0.0 (contentHeight - linearViewState.ViewportHeight)
  { linearViewState with
      ScrollOffsetY =
        max 0.0 (min maxScrollOffset linearViewState.ScrollOffsetY) }

let private initializeLinearView model linearDoc (state: LinearViewState) =
  let viewportWidth, viewportHeight = (model: Model).ContentViewportSize
  let fontSize =
    if state.FontSize > 0.0 then state.FontSize
    else model.Theme.Font.Monospace.FontSize
  let charWidth, rowHeight =
    if state.CharWidth > 0.0 && state.RowHeight > 0.0 then
      state.CharWidth, state.RowHeight
    else
      measureMaxCharSizeWithFontSize model fontSize
  { state with
      ViewportWidth = viewportWidth
      ViewportHeight = viewportHeight
      FontSize = fontSize
      CharWidth = charWidth
      RowHeight = rowHeight }
  |> LinearViewState.rebuildUniformLayout rowHeight linearDoc

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

let private initializeHexdumpTabView (model: Model) hexdump =
  let view = hexdump.View
  let viewportWidth, viewportHeight = model.ContentViewportSize
  let fontSize =
    if view.FontSize > 0.0 then clampHexdumpFontSize view.FontSize
    else model.Theme.Font.Monospace.FontSize
  let charWidth, rowHeight =
    if view.CharWidth > 0.0 && view.RowHeight > 0.0 then
      view.CharWidth, view.RowHeight
    else
      measureMaxCharSizeWithFontSize model fontSize
  let nextView =
    { view with
        ViewportWidth = viewportWidth
        ViewportHeight = viewportHeight
        FontSize = fontSize
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

let private activateHexdumpView (model: Model) =
  initializeHexdumpTabView model >> prepareHexdumpViewForActivation

let private buildSectionRange sections =
  match sections with
  | [] -> NoSection
  | [ sec ] -> SingleSection sec
  | [ sec1; sec2 ] -> MultipleSections(sec1, sec2)
  | _ -> MultipleSections(List.head sections, List.last sections)

let private isLinkageSectionName = function
  | ".plt" | ".plt.sec" | ".plt.got"
  | ".got" | ".got.plt"
  | ".dynamic"
  | ".rela.plt" | ".rel.plt" -> true
  | _ -> false

let private isExceptionSectionName = function
  | ".eh_frame" | ".eh_frame_hdr" | ".gcc_except_table"
  | ".ARM.exidx" | ".ARM.extab" -> true
  | _ -> false

let private isMetadataSectionType = function
  | SectionType.SHT_NULL
  | SectionType.SHT_SYMTAB
  | SectionType.SHT_STRTAB
  | SectionType.SHT_RELA
  | SectionType.SHT_HASH
  | SectionType.SHT_NOTE
  | SectionType.SHT_REL
  | SectionType.SHT_SHLIB
  | SectionType.SHT_DYNSYM
  | SectionType.SHT_GROUP
  | SectionType.SHT_SYMTAB_SHNDX
  | SectionType.SHT_GNU_HASH
  | SectionType.SHT_GNU_verdef
  | SectionType.SHT_GNU_verneed
  | SectionType.SHT_GNU_versym -> true
  | _ -> false

let private selectionHighlightSpec (theme: Theme) (shdr: SectionHeader) =
  let name = shdr.SecName
  if isExceptionSectionName name then
    struct (theme.Hex.ExceptionArea, 8)
  elif isLinkageSectionName name then
    struct (theme.Hex.LinkageArea, 9)
  elif shdr.SecFlags.HasFlag SectionFlags.SHF_EXECINSTR then
    struct (theme.Hex.CodeArea, 10)
  elif shdr.SecFlags.HasFlag SectionFlags.SHF_ALLOC
       && not (isMetadataSectionType shdr.SecType) then
    if shdr.SecFlags.HasFlag SectionFlags.SHF_WRITE then
      struct (theme.Hex.WritableDataArea, 7)
    else
      struct (theme.Hex.ReadOnlyDataArea, 7)
  else
    struct (theme.Hex.MetadataArea, 6)

let private buildSpansForELF (theme: Theme) (elf: ELFBinFile) =
  let fileLength = int64 (elf :> IBinFile).RawBytes.Length
  [ for shdr in elf.SectionHeaders do
      let start, length = shdr.SecOffset, shdr.SecSize
      let isFileBacked = shdr.SecType <> SectionType.SHT_NOBITS
      let start = int64 start
      let length = int64 length
      if isFileBacked && length > 0L && start >= 0L && start < fileLength then
        let length = min length (fileLength - start)
        let struct (bg, prio) = selectionHighlightSpec theme shdr
        { Start = int64 start
          Length = length
          Foreground = None
          Background = Some bg
          Priority = prio }
      else
        () ]

let private buildHexAnnotations
    (theme: Theme) (file: IBinFile) (state: HexdumpState) =
  match file.Format with
  | FileFormat.ELFBinary ->
    let elf = file :?> ELFBinFile
    let spans = buildSpansForELF theme elf
    { state with AnnotationSpans = spans }
  | _ ->
    state

let private buildLoadedBinaryState (arbiter: Arbiter<_, _>) model filePath =
  match API.getFunctions arbiter true,
        API.getSections arbiter,
        API.getFile arbiter with
  | Ok fns, Ok secs, Ok file ->
    let sections =
      secs |> Array.map SectionItem.make |> List.ofArray
    let numDigits = (file.ISA.WordSize |> WordSize.toByteWidth) * 2
    let fontSize = model.Theme.Font.Monospace.FontSize
    let hexdump =
      HexdumpState.ofBytes file.BaseAddress file.RawBytes numDigits fontSize
      |> buildHexAnnotations model.Theme file
      |> initializeHexdumpTabView model
    let initialTab = Some(Tab.ofLinearView ())
    fns |> Array.map (FunctionItem.ofFunction file) |> List.ofArray,
    sections,
    Some hexdump,
    FileLoaded(filePath, FileFormat.toString file.Format),
    initialTab
  | _ ->
    [], [], None, EmptyStatus, None

let openBinaryCompleted (arbiter: Arbiter<_, _>) (model: Model) filePath =
  if model.LoadingBinaryPath = Some filePath then
    let fns, sections, hexdump, statusBar, initialTab =
      buildLoadedBinaryState arbiter model filePath
    let nextModel =
      Model.mapFocusedPane
        (fun pane ->
          { pane with
              ActiveTab = initialTab
              OpenTabs = [ match initialTab with
                           | Some tab -> tab
                           | None -> () ]
              PreviewTab = None })
        { model with
            LoadedBinary = Some filePath
            LoadingBinaryPath = None
            Functions = fns
            Sections = sections
            FunctionFilter = ""
            DraggingTab = None
            WorkspacePanel = FunctionPanel
            LinearDocument = None
            LinearViewState = None
            Hexdump = hexdump
            OffsetSnapshot = OffsetSnapshot.empty
            StatusBarState = statusBar }
    let cmd =
      match initialTab with
      | Some _ ->
        startLinearAnalysisCmd
          arbiter
          filePath
          sections
          model.Theme.Font.Monospace.FontSize
      | None ->
        Elmish.Cmd.none
    nextModel, cmd
  else
    model, Elmish.Cmd.none

let openBinaryFailed model filePath reason =
  if model.LoadingBinaryPath = Some filePath then
    { model with
        LoadingBinaryPath = None
        OffsetSnapshot = OffsetSnapshot.empty
        StatusBarState = MessageOnly $"Failed to load binary: {reason}" },
    Elmish.Cmd.none
  else
    model, Elmish.Cmd.none

let closeWorkspace (arbiter: Arbiter<_, _>) (model: Model) =
  arbiter.CloseSession()
  Model.mapFocusedPane
    (fun pane ->
      { pane with
          ActiveTab = None
          OpenTabs = []
          PreviewTab = None })
    { model with
        LoadedBinary = None
        LoadingBinaryPath = None
        Functions = []
        FunctionFilter = ""
        DraggingTab = None
        WorkspacePanel = FunctionPanel
        LinearDocument = None
        LinearViewState = None
        Hexdump = None
        OffsetSnapshot = OffsetSnapshot.empty
        StatusBarState = EmptyStatus },
  Elmish.Cmd.none

let private tryGetSelectedFileOffsetRange selection =
  let startOffset = min selection.Anchor selection.Caret
  let endOffset = max selection.Anchor selection.Caret
  let maxOffset = int64 UInt32.MaxValue
  if startOffset < 0L || endOffset < 0L then
    None
  elif startOffset > maxOffset || endOffset > maxOffset then
    None
  else
    Some(uint32 startOffset, uint32 endOffset)

let private findSectionRange (f: IBinFile) (sOff: uint32) (eOff: uint32) =
  match f.TryFindSectionName sOff, f.TryFindSectionName eOff with
  | Ok secStart, Ok secEnd when secStart = secEnd -> [ secStart ]
  | Ok secStart, Ok secEnd -> [ secStart; secEnd ]
  | _ -> []

let private mkOffsetRangeInfo sOff eOff sections =
  { Range = { Start = sOff; End = eOff }
    SectionRange = buildSectionRange sections }

let private tryGetOffsetRangeInfo arbiter (sOff: uint32) (eOff: uint32) =
  match API.getFile arbiter with
  | Ok file ->
    let sec = findSectionRange file sOff eOff
    Some(mkOffsetRangeInfo sOff eOff sec)
  | Error _ ->
    None

let private tryGetVisibleFileOffsetRange hexdump =
  match HexdumpState.tryGetVisibleByteRange hexdump with
  | Some(startOffset, endOffset) ->
    let maxOffset = int64 UInt32.MaxValue
    if startOffset > maxOffset then
      None
    else
      Some(uint32 startOffset, uint32 (min maxOffset endOffset))
  | None ->
    None

let private tryGetVisibleLinearOffsetRange linearDoc linearViewState =
  LinearProjection.tryGetVisibleFileOffsetRange linearDoc linearViewState
  |> Option.map (fun (startOffset, endOffset) ->
    uint32 startOffset, uint32 endOffset)

let private tryGetSelectionOffsetRangeInfo arbiter (model: Model) =
  match model.ActiveTab, model.Hexdump with
  | Some { Content = HexContent }, Some { Selection = Some sel } ->
    tryGetSelectedFileOffsetRange sel
    |> Option.bind (fun (sOff, eOff) -> tryGetOffsetRangeInfo arbiter sOff eOff)
  | Some { Content = CFGContent(func, Loaded st) }, _ ->
    match st.ViewState.SelectedToken with
    | Some { Range = Some range } ->
      tryGetOffsetRangeInfo arbiter (uint32 range.Min) (uint32 range.Max)
    | _ ->
      tryGetOffsetRangeInfo
        arbiter
        (uint32 func.OffsetRange.Value.Min)
        (uint32 func.OffsetRange.Value.Max)
  | _ ->
    None

let private tryGetViewportOffsetRangeInfo arbiter (model: Model) =
  match model.ActiveTab with
  | Some { Content = LinearContent } ->
    match model.LinearDocument, model.LinearViewState with
    | Some doc, Some state ->
      tryGetVisibleLinearOffsetRange doc state
      |> Option.bind (fun (sOff, eOff) ->
        tryGetOffsetRangeInfo arbiter sOff eOff)
    | _ ->
      None
  | _ ->
    match model.Hexdump, Model.tryFindTab model Tab.HexdumpTabID with
    | Some hexdump, Some _ ->
      tryGetVisibleFileOffsetRange hexdump
      |> Option.bind (fun (sOff, eOff) ->
        tryGetOffsetRangeInfo arbiter sOff eOff)
    | _ ->
      None

let private syncOffsetSnapshotWithActiveTab arbiter (model: Model) =
  let snapshot =
    { Selection = tryGetSelectionOffsetRangeInfo arbiter model
      Viewport = tryGetViewportOffsetRangeInfo arbiter model }
  { model with OffsetSnapshot = snapshot }

let linearAnalysisCompleted arbiter model filePath doc state =
  if model.LoadedBinary = Some filePath then
    let state = initializeLinearView model doc state
    { model with
        LinearDocument = Some doc
        LinearViewState = Some state }
    |> syncOffsetSnapshotWithActiveTab arbiter,
    Elmish.Cmd.none
  else
    model, Elmish.Cmd.none

let linearAnalysisFailed model filePath reason =
  if model.LoadedBinary = Some filePath then
    { model with
        StatusBarState =
          MessageOnly $"Failed to analyze linear view: {reason}" },
    Elmish.Cmd.none
  else
    model, Elmish.Cmd.none

let private replaceTabByID tabID newTab oldTab =
  if oldTab.ID = tabID then newTab
  else oldTab

let private replaceTabReferences (model: Model) tab =
  let paneID =
    Pane.tryFindLeafByTabID tab.ID model.RootPane
    |> Option.defaultValue (Model.getFocusedPaneID model)
  Model.mapPaneByID paneID (fun pane ->
    let opens = pane.OpenTabs |> List.map (replaceTabByID tab.ID tab)
    let preview = pane.PreviewTab |> Option.map (replaceTabByID tab.ID tab)
    let active = pane.ActiveTab |> Option.map (replaceTabByID tab.ID tab)
    { pane with
        OpenTabs = opens
        PreviewTab = preview
        ActiveTab = active }) model

let openHexdumpTab (arbiter: Arbiter<_, _>) (model: Model) =
  let model =
    match model.Hexdump with
    | Some hexdump ->
      { model with Hexdump = Some(activateHexdumpView model hexdump) }
    | None ->
      model
  match Model.tryFindTab model Tab.HexdumpTabID with
  | Some(paneID, _, tab, _) ->
    Model.mapPaneByID paneID (fun pane ->
      { pane with
          ActiveTab = Some tab
          OpenTabs = pane.OpenTabs
          PreviewTab = pane.PreviewTab }) model
    |> fun nextModel ->
      { nextModel with FocusedPaneID = Some paneID }
      |> syncOffsetSnapshotWithActiveTab arbiter,
      Elmish.Cmd.none
  | None ->
    match model.Hexdump with
    | Some _ ->
      let tab = Tab.ofHexdump ()
      Model.mapFocusedPane (fun pane ->
          { pane with
              ActiveTab = Some tab
              OpenTabs = tab :: pane.OpenTabs }) model
      |> syncOffsetSnapshotWithActiveTab arbiter,
        Elmish.Cmd.none
    | None ->
      model, Elmish.Cmd.none

let openLinearViewTab (arbiter: Arbiter<_, _>) (model: Model) =
  let model =
    match model.LinearDocument, model.LinearViewState with
    | Some doc, Some state ->
      { model with
          LinearViewState = Some(initializeLinearView model doc state) }
    | _ ->
      model
  match Model.tryFindTab model Tab.LinearViewTabID with
  | Some(paneID, _, tab, _) ->
    Model.mapPaneByID paneID (fun pane ->
      { pane with
          ActiveTab = Some tab
          OpenTabs = pane.OpenTabs
          PreviewTab = pane.PreviewTab }) model
    |> fun nextModel ->
      { nextModel with FocusedPaneID = Some paneID }
      |> syncOffsetSnapshotWithActiveTab arbiter,
      Elmish.Cmd.none
  | None ->
    match model.LinearViewState with
    | Some _ ->
      let tab = Tab.ofLinearView ()
      Model.mapFocusedPane (fun pane ->
          { pane with
              ActiveTab = Some tab
              OpenTabs = tab :: pane.OpenTabs }) model
      |> syncOffsetSnapshotWithActiveTab arbiter,
        Elmish.Cmd.none
    | None ->
      model, Elmish.Cmd.none

let private mapCFGTabState newState (tab: Tab) =
  match tab.Content with
  | CFGContent(func, _) ->
    { tab with Content = CFGContent(func, newState) }
  | _ ->
    tab

let private createMinimapCache (model: Model) viewState cfg =
  MinimapStaticCache.create model.ContentViewportSize viewState cfg

let private refreshCFGTabMinimap (model: Model) tab =
  match tab.Content with
  | CFGContent(fn, Loaded loaded) ->
    let loaded =
      { loaded with
          Minimap = createMinimapCache model loaded.ViewState loaded.Graph }
    { tab with Content = CFGContent(fn, Loaded loaded) }
  | _ ->
    tab

let private refreshCFGTabMinimapForViewport viewportSize tab =
  match tab.Content with
  | CFGContent(fn, Loaded loaded) ->
    let loaded =
      { loaded with
          Minimap =
            MinimapStaticCache.create
              viewportSize loaded.ViewState loaded.Graph }
    { tab with Content = CFGContent(fn, Loaded loaded) }
  | _ ->
    tab

let private updateHexdumpState arbiter (model: Model) update =
  match model.Hexdump with
  | Some hexdump ->
    let hexdump =
      update hexdump
      |> fun state ->
        let view = clampHexScrollState state state.View
        { state with View = view }
    { model with Hexdump = Some hexdump }
    |> syncOffsetSnapshotWithActiveTab arbiter
  | _ ->
    model

let private updateHexViewState arbiter (model: Model) updateView =
  updateHexdumpState arbiter model (fun hexdump ->
    let view = updateView hexdump.View
    { hexdump with View = view }), Elmish.Cmd.none

let private syncHexViewportWithLinear model =
  match model.LinearDocument, model.LinearViewState, model.Hexdump with
  | Some doc, Some state, Some hexdump ->
    match LinearProjection.tryGetTopVisibleFileOffset doc state with
    | Some offset ->
      let row = int64 offset / int64 (max 1 hexdump.View.BytesPerRow)
      let rowHeight = max hexdump.View.RowHeight 1.0
      let view =
        { hexdump.View with
            ScrollRow = row
            ScrollOffsetY = float row * rowHeight
            ScrollGuard = NoScrollGuard }
        |> clampHexScrollState hexdump
      { model with Hexdump = Some { hexdump with View = view } }
    | None ->
      model
  | _ ->
    model

let private updateLinearViewState arbiter (model: Model) update =
  match model.LinearDocument, model.LinearViewState with
  | Some doc, Some state ->
    let linearViewState =
      update doc state
      |> fun state -> clampLinearScrollState state
    { model with LinearViewState = Some linearViewState }
    |> syncHexViewportWithLinear
    |> syncOffsetSnapshotWithActiveTab arbiter
  | _ ->
    model

let private getActiveHexScrollGuard (model: Model) =
  match model.Hexdump with
  | Some hexdump -> hexdump.View.ScrollGuard
  | _ -> NoScrollGuard

let private syncHexScrollOffset hexdump offsetY scrollGuard =
  let rowHeight = max hexdump.View.RowHeight 1.0
  let view =
    { hexdump.View with
        ScrollOffsetY = offsetY
        ScrollRow = int64 (floor (offsetY / rowHeight))
        ScrollGuard = scrollGuard }
    |> clampHexScrollState hexdump
  { hexdump with View = { view with ScrollGuard = scrollGuard } }

let private recomputeHexViewLayout arbiter (model: Model) updateView =
  updateHexdumpState arbiter model (fun hexdump ->
    let viewState = hexdump.View
    let topByte = viewState.ScrollRow * int64 (max 1 viewState.BytesPerRow)
    let nextView = updateView viewState
    let fontSize = clampHexdumpFontSize nextView.FontSize
    let charWidth, rowHeight = measureMaxCharSizeWithFontSize model fontSize
    let nextView =
      { nextView with
          FontSize = fontSize
          CharWidth = charWidth
          RowHeight = rowHeight }
    let nextView =
      { nextView with BytesPerRow = computeHexBytesPerRow nextView }
    let nextScrollRow = topByte / int64 (max 1 nextView.BytesPerRow)
    let view =
      { nextView with
          ScrollRow = nextScrollRow
          ScrollOffsetY = float nextScrollRow * nextView.RowHeight }
    { hexdump with View = view }), Elmish.Cmd.none

let private resizeOpenedHexdumpTab arbiter (model: Model) paneID width height =
  let containsHexdumpTab pane =
    Model.getVisibleTabsFromPane pane
    |> List.exists (fun t -> t.ID = Tab.HexdumpTabID)
  match Pane.tryFindLeaf paneID model.RootPane with
  | Some pane when containsHexdumpTab pane ->
    updateHexdumpState arbiter model (fun hexdump ->
      let viewState = hexdump.View
      let topByte = viewState.ScrollRow * int64 (max 1 viewState.BytesPerRow)
      let fontSize = clampHexdumpFontSize viewState.FontSize
      let charWidth, rowHeight =
        measureMaxCharSizeWithFontSize model fontSize
      let nextView =
        { viewState with
            ViewportWidth = width
            ViewportHeight = height
            FontSize = fontSize
            CharWidth = charWidth
            RowHeight = rowHeight }
      let nextView =
        { nextView with BytesPerRow = computeHexBytesPerRow nextView }
      let nextScrollRow = topByte / int64 (max 1 nextView.BytesPerRow)
      let view =
        { nextView with
            ScrollRow = nextScrollRow
            ScrollOffsetY = float nextScrollRow * nextView.RowHeight }
      { hexdump with View = view })
  | _ ->
    model

let private resizeOpenedLinearTab arbiter (model: Model) paneID width height =
  let containsLinearTab pane =
    Model.getVisibleTabsFromPane pane
    |> List.exists (fun t -> t.ID = Tab.LinearViewTabID)
  match Pane.tryFindLeaf paneID model.RootPane with
  | Some pane when containsLinearTab pane ->
    updateLinearViewState arbiter model (fun doc linearViewState ->
      let fontSize =
        if linearViewState.FontSize > 0.0 then
          linearViewState.FontSize
        else model.Theme.Font.Monospace.FontSize
      let charWidth, rowHeight =
        measureMaxCharSizeWithFontSize model fontSize
      { linearViewState with
          ViewportWidth = width
          ViewportHeight = height
          FontSize = fontSize
          CharWidth = charWidth
          RowHeight = rowHeight }
      |> LinearViewState.rebuildUniformLayout rowHeight doc)
  | _ ->
    model

let private computeJumpedHexdump theme hexdump byteIndex length =
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
  let targetScrollRow = int64 (floor (targetOffsetY / rowHeight))
  let currentOffsetY = viewState.ScrollOffsetY
  let pendingDelta = targetOffsetY - currentOffsetY
  let nextView =
    { scrolledView with
        ScrollOffsetY = targetOffsetY
        ScrollRow = targetScrollRow
        ScrollGuard =
          if abs pendingDelta > 0.5 then
            IgnoreNextProgrammatic pendingDelta
          else
            NoScrollGuard }
  { hexdump with
      HighlightSpans =
        [ { Start = byteIndex
            Length = highlightLength
            Foreground = Some theme.Search.Foreground
            Background = Some theme.Search.SelectedBackground
            Priority = 100 } ]
      View = nextView },
  targetOffsetY,
  pendingDelta

let private jumpHexdump (model: Model) byteIndex length =
  match model.Hexdump with
  | Some hexdump ->
    let nextHexdump, targetOffsetY, pendingDelta =
      computeJumpedHexdump model.Theme hexdump byteIndex length
    let model = { model with Hexdump = Some nextHexdump }
    let hasHexdumpTab = Model.tryFindTab model Tab.HexdumpTabID |> Option.isSome
    let cmd =
      if hasHexdumpTab && abs pendingDelta > 0.5 then
        deferHexdumpScrollCmd targetOffsetY
      else
        Elmish.Cmd.none
    model, cmd
  | _ ->
    model, Elmish.Cmd.none

let private jumpHexdumpToOffset arbiter model (offset: uint64) =
  updateHexdumpState arbiter model (fun hexdump ->
    computeJumpedHexdump model.Theme hexdump (int64 offset) 1L
    |> fun (nextHexdump, _, _) -> nextHexdump)

let private jumpHexdumpToAddress arbiter model addr =
  match API.getFile arbiter with
  | Ok file when file.IsValidAddr addr ->
    let ptr = file.GetBoundedPointer addr
    jumpHexdumpToOffset arbiter model (uint64 ptr.Offset)
  | _ ->
    model

let private clampHexByteIndex hexdump byteIndex =
  if hexdump.Document.Length <= 0L then None
  else Some(max 0L (min (hexdump.Document.Length - 1L) byteIndex))

let private clampHexSelection hexdump selection =
  selection
  |> Option.bind (fun sel ->
    match clampHexByteIndex hexdump sel.Anchor,
          clampHexByteIndex hexdump sel.Caret with
    | Some anchor, Some caret -> Some { Anchor = anchor; Caret = caret }
    | _ -> None)

let private setHexdumpSelection arbiter model selection =
  updateHexdumpState arbiter model (fun hexdump ->
    { hexdump with Selection = clampHexSelection hexdump selection })

let private setHexdumpSelectionFromAddrRange arbiter model (range: AddrRange) =
  match API.getFile arbiter with
  | Ok file when file.IsValidAddr range.Min ->
    let startPtr = file.GetBoundedPointer range.Min
    let endPtr =
      if file.IsValidAddr range.Max then file.GetBoundedPointer range.Max
      else startPtr
    let selection =
      Some
        { Anchor = int64 startPtr.Offset
          Caret = max (int64 startPtr.Offset) (int64 endPtr.Offset) }
    setHexdumpSelection arbiter model selection
  | _ ->
    model

let private setHexdumpSelectionFromOffsetRange arbiter model (r: AddrRange) =
  let selection = Some { Anchor = int64 r.Min; Caret = int64 r.Max }
  setHexdumpSelection arbiter model selection

type private CFGSyncTarget =
  | CFGAddressRange of AddrRange
  | CFGOffsetRange of AddrRange

let private tryGetActiveCFGSyncTarget (model: Model) =
  match model.ActiveTab with
  | Some { Content = CFGContent(fn, Loaded st) } ->
    match st.ViewState.SelectedToken with
    | Some { Range = Some range } -> Some(CFGAddressRange range)
    | _ -> Some(CFGOffsetRange fn.OffsetRange.Value)
  | _ ->
    None

let private tryGetTargetFileOffset arbiter = function
  | CFGAddressRange range ->
    match API.getFile arbiter with
    | Ok file when file.IsValidAddr range.Min ->
      let ptr = file.GetBoundedPointer range.Min
      Some ptr.Offset
    | _ ->
      None
  | CFGOffsetRange range ->
    Some(int range.Min)

let private syncHexdumpWithCFGTarget arbiter (model: Model) = function
  | CFGAddressRange range ->
    let model = setHexdumpSelectionFromAddrRange arbiter model range
    jumpHexdumpToAddress arbiter model range.Min
  | CFGOffsetRange range ->
    let model = setHexdumpSelectionFromOffsetRange arbiter model range
    jumpHexdumpToOffset arbiter model range.Min

let private syncLinearWithFileOffset (model: Model) offset =
  match model.LinearViewState, model.LinearDocument with
  | Some state, Some doc when offset >= 0 && offset <= Int32.MaxValue ->
    match LinearProjection.tryGetScrollOffsetForFileOffset doc state offset with
    | Some offsetY ->
      let state =
        { state with ScrollOffsetY = offsetY }
        |> clampLinearScrollState
      { model with LinearViewState = Some state }
    | None ->
      model
  | _ ->
    model

let private syncLinearWithCFGTarget arbiter (model: Model) target =
  match tryGetTargetFileOffset arbiter target with
  | Some offset -> syncLinearWithFileOffset model offset
  | None -> model

let private syncViewsWithActiveCFG arbiter (model: Model) =
  match tryGetActiveCFGSyncTarget model with
  | Some target ->
    let model = syncHexdumpWithCFGTarget arbiter model target
    syncLinearWithCFGTarget arbiter model target
  | None ->
    model

let private syncViewsWithActiveCFGIfEnabled arbiter (model: Model) =
  if model.SyncEnabled then syncViewsWithActiveCFG arbiter model
  else model

let setTopFileOffset arbiter (model: Model) offset =
  let model =
    match model.Hexdump with
    | Some hexdump ->
      let offset =
        if hexdump.Document.Length <= 0L then 0L
        else max 0L (min (hexdump.Document.Length - 1L) offset)
      let viewState = hexdump.View
      let rowHeight = max viewState.RowHeight 1.0
      let row = offset / int64 (max 1 viewState.BytesPerRow)
      let view =
        { viewState with
            ScrollRow = row
            ScrollOffsetY = float row * rowHeight
            ScrollGuard = NoScrollGuard }
      { model with Hexdump = Some { hexdump with View = view } }
    | None ->
      model
  syncLinearWithFileOffset model (int offset)
  |> syncOffsetSnapshotWithActiveTab arbiter,
  Elmish.Cmd.none

let updateHexdump arbiter (model: Model) msg =
  match msg with
  | SetHighlightSpans spans ->
    updateHexdumpState arbiter model (fun hexdump ->
      { hexdump with HighlightSpans = spans }),
    Elmish.Cmd.none
  | ChangeFontSize delta when abs delta > 0.0 ->
    recomputeHexViewLayout arbiter model (fun viewState ->
      let fontSize = clampHexdumpFontSize (viewState.FontSize + delta)
      { viewState with FontSize = fontSize })
  | UpdateFontMetrics(charWidth, rowHeight)
    when charWidth > 0.0 && rowHeight > 0.0 ->
    updateHexViewState arbiter model (fun viewState ->
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
    let model = setHexdumpSelection arbiter model None
    let model = syncLinearWithFileOffset model (int byteIndex)
    jumpHexdump model byteIndex length
  | HandleScrollChanged(offsetY, deltaY) ->
    let currentGuard = getActiveHexScrollGuard model
    if Double.IsNaN offsetY then
      model, Elmish.Cmd.none
    else
      match currentGuard with
      | IgnoreNextProgrammatic _ when abs deltaY <= 0.0 ->
        model, Elmish.Cmd.none
      | IgnoreNextProgrammatic _ ->
        updateHexdumpState arbiter model (fun hexdump ->
          syncHexScrollOffset hexdump offsetY NoScrollGuard), Elmish.Cmd.none
      | IgnoreNextEcho _ when abs deltaY <= 0.0 ->
        model, Elmish.Cmd.none
      | IgnoreNextEcho _ ->
        updateHexdumpState arbiter model (fun hexdump ->
          syncHexScrollOffset hexdump offsetY NoScrollGuard), Elmish.Cmd.none
      | _ ->
        updateHexdumpState arbiter model (fun hexdump ->
          syncHexScrollOffset hexdump offsetY NoScrollGuard), Elmish.Cmd.none
  | SetScrollOffset(offsetY) ->
    updateHexdumpState arbiter model (fun hexdump ->
      syncHexScrollOffset hexdump offsetY hexdump.View.ScrollGuard),
    Elmish.Cmd.none
  | ScrollRows(delta) ->
    updateHexdumpState arbiter model (fun hexdump ->
      let viewState = hexdump.View
      let rowHeight = max viewState.RowHeight 1.0
      let scrollRow = viewState.ScrollRow + delta
      let view =
        { viewState with
            ScrollRow = scrollRow
            ScrollOffsetY = float scrollRow * rowHeight
            ScrollGuard = NoScrollGuard }
      { hexdump with View = view }), Elmish.Cmd.none
  | SetSelection selection ->
    setHexdumpSelection arbiter model selection, Elmish.Cmd.none
  | StartSelection byteIndex ->
    updateHexdumpState arbiter model (fun hexdump ->
      match clampHexByteIndex hexdump byteIndex with
      | Some byteIndex ->
        { hexdump with
            Selection = Some { Anchor = byteIndex; Caret = byteIndex }
            View = { hexdump.View with IsSelecting = true } }
      | None ->
        hexdump), Elmish.Cmd.none
  | UpdateSelection byteIndex ->
    updateHexdumpState arbiter model (fun hexdump ->
      match hexdump.View.IsSelecting,
            clampHexByteIndex hexdump byteIndex,
            hexdump.Selection with
      | true, Some byteIndex, Some selection ->
        { hexdump with
            Selection = Some { selection with Caret = byteIndex } }
      | true, Some byteIndex, None ->
        { hexdump with
            Selection = Some { Anchor = byteIndex; Caret = byteIndex } }
      | _ ->
        hexdump), Elmish.Cmd.none
  | EndSelection ->
    updateHexdumpState arbiter model (fun hexdump ->
      { hexdump with View = { hexdump.View with IsSelecting = false } }),
    Elmish.Cmd.none
  | SetHoveredByte byteIndex ->
    updateHexViewState arbiter model (fun viewState ->
      let hovered =
        match model.Hexdump with
        | Some hexdump ->
          byteIndex |> Option.bind (clampHexByteIndex hexdump)
        | _ -> None
      { viewState with HoveredByte = hovered })
  | _ ->
    model, Elmish.Cmd.none

let updateLinear arbiter (model: Model) msg =
  match msg with
  | LinearPaneMessage.HandleScrollChanged(offsetY, _) ->
    updateLinearViewState arbiter model (fun _ viewState ->
      { viewState with ScrollOffsetY = offsetY }),
    Elmish.Cmd.none
  | LinearPaneMessage.SetScrollOffset offsetY ->
    updateLinearViewState arbiter model (fun _ viewState ->
      { viewState with ScrollOffsetY = offsetY }),
    Elmish.Cmd.none
  | LinearPaneMessage.UpdateFontMetrics(charWidth, rowHeight)
    when charWidth > 0.0 && rowHeight > 0.0 ->
    updateLinearViewState arbiter model (fun doc linearViewState ->
      { linearViewState with
          CharWidth = charWidth
          RowHeight = rowHeight }
      |> LinearViewState.rebuildUniformLayout rowHeight doc),
    Elmish.Cmd.none
  | _ ->
    model, Elmish.Cmd.none

let private getCFG (arbiter: Arbiter<_, _>) (model: Model) cfgKind addr =
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

let private loadCFGCmd arbiter model (fn: FunctionItem) kind (tab: Tab) =
  let id, addr = tab.ID, fn.Address
  cmdOfSub (fun dispatch ->
    Async.Start(async {
      try
        match getCFG arbiter model kind addr with
        | Ok cfg ->
          dispatchOnUi dispatch (CFGLoadMsg(LoadCompleted(id, addr, kind, cfg)))
        | Error e ->
          dispatchOnUi dispatch (CFGLoadMsg(LoadFailed(id, e)))
      with ex ->
        dispatchOnUi dispatch (CFGLoadMsg(LoadFailed(id, ex.Message)))
    }))

let private startLoadIfNeeded arbiter tab (model: Model) =
  match tab.Content with
  | CFGContent(fn, NotLoaded) ->
    let loadingTab = mapCFGTabState Loading tab
    let model =
      Model.mapFocusedPane (fun pane ->
        let opens = pane.OpenTabs |> List.map (replaceTabByID tab.ID loadingTab)
        let preview =
          pane.PreviewTab |> Option.map (replaceTabByID tab.ID loadingTab)
        { pane with
            ActiveTab = Some loadingTab
            OpenTabs = opens
            PreviewTab = preview }) model
    model,
    loadCFGCmd arbiter model fn CFGKind.Disasm loadingTab
  | _ ->
    let tab = refreshCFGTabMinimap model tab
    replaceTabReferences model tab |> syncOffsetSnapshotWithActiveTab arbiter,
    Elmish.Cmd.none

let openCFGTab (arbiter: Arbiter<_, _>) (model: Model) fnItem =
  let tab = Tab.ofFunctionItem fnItem
  match Model.tryFindTab model tab.ID with
  | Some(paneID, _, tab, _) ->
    startLoadIfNeeded arbiter tab (Model.mapPaneByID paneID
      (fun pane -> { pane with ActiveTab = Some tab }) model)
    |> fun (nextModel, cmd) ->
      { nextModel with FocusedPaneID = Some paneID }
      |> syncViewsWithActiveCFGIfEnabled arbiter, cmd
  | None ->
    startLoadIfNeeded arbiter tab (Model.mapFocusedPane
      (fun pane -> { pane with ActiveTab = Some tab; PreviewTab = Some tab })
      model)
    |> fun (nextModel, cmd) ->
      let syncedModel = syncViewsWithActiveCFGIfEnabled arbiter nextModel
      syncedModel, cmd

let pinCFGTab (arbiter: Arbiter<_, _>) (model: Model) fnItem =
  let tab = Tab.ofFunctionItem fnItem
  let paneID, newOpenTabs, tab =
    match Model.tryFindTab model tab.ID with
    | Some(paneID, paneState, tab, isPreview) ->
      if isPreview then paneID, tab :: paneState.OpenTabs, tab
      else paneID, paneState.OpenTabs, tab
    | None ->
      let paneID = Model.getFocusedPaneID model
      paneID, tab :: model.OpenTabs, tab
  startLoadIfNeeded arbiter tab (Model.mapPaneByID paneID
    (fun pane ->
      { pane with
          ActiveTab = Some tab
          OpenTabs = newOpenTabs
          PreviewTab = None }) model)
  |> fun (nextModel, cmd) ->
    { nextModel with FocusedPaneID = Some paneID }
    |> syncViewsWithActiveCFGIfEnabled arbiter, cmd

let private isPaneEmpty pane =
  pane.ActiveTab.IsNone
  && pane.PreviewTab.IsNone
  && List.isEmpty pane.OpenTabs

let rec private collapseEmptyPanes = function
  | Leaf(_, paneState) when isPaneEmpty paneState ->
    None
  | Leaf _ as leaf ->
    Some leaf
  | Split(_, axis, first, second) ->
    match collapseEmptyPanes first, collapseEmptyPanes second with
    | Some first, Some second ->
      Some(Split(Guid.NewGuid(), axis, first, second))
    | Some only, None
    | None, Some only ->
      Some only
    | None, None ->
      None

let private normalizePaneModel model =
  let rootPane =
    collapseEmptyPanes model.RootPane
    |> Option.defaultValue model.RootPane
  let focusedPaneID =
    match model.FocusedPaneID with
    | Some paneID when Pane.tryFindLeaf paneID rootPane |> Option.isSome ->
      Some paneID
    | _ ->
      Model.tryFindFirstLeaf rootPane |> Option.map fst
  { model with RootPane = rootPane; FocusedPaneID = focusedPaneID }

let closeTab arbiter (model: Model) paneID tabID =
  match Pane.tryFindLeaf paneID model.RootPane with
  | Some pane ->
    let openTabs = pane.OpenTabs |> List.filter (fun t -> t.ID <> tabID)
    let preview = pane.PreviewTab |> Option.filter (fun t -> t.ID <> tabID)
    let dragging =
      model.DraggingTab |> Option.filter (fun drag -> drag.Tab.ID <> tabID)
    let active =
      match pane.ActiveTab with
      | Some t when t.ID = tabID ->
        openTabs |> List.tryHead |> Option.orElse preview
      | _ ->
        pane.ActiveTab
    Model.mapPaneByID paneID
      (fun pane ->
        { pane with
            ActiveTab = active
            OpenTabs = openTabs
            PreviewTab = preview })
      { model with
          FocusedPaneID = Some paneID
          DraggingTab = dragging }
    |> normalizePaneModel
    |> syncOffsetSnapshotWithActiveTab arbiter, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let switchTab arbiter (model: Model) paneID tabID =
  let model = { model with FocusedPaneID = Some paneID }
  match Model.tryFindVisibleTab model tabID with
  | Some tab ->
    let model =
      if tab.ID = Tab.HexdumpTabID then
        match model.Hexdump with
        | Some hexdump ->
          { model with
              Hexdump = Some(prepareHexdumpViewForActivation hexdump) }
        | None ->
          model
      else
        model
    let tab =
      if tab.ID = Tab.HexdumpTabID then tab
      else refreshCFGTabMinimap model tab
    replaceTabReferences (Model.mapFocusedPane
      (fun pane -> { pane with ActiveTab = Some tab }) model) tab
    |> syncOffsetSnapshotWithActiveTab arbiter
    |> syncViewsWithActiveCFGIfEnabled arbiter,
    Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let setSyncEnabled (arbiter: Arbiter<_, _>) (model: Model) enabled =
  let model = { model with SyncEnabled = enabled }
  if enabled then syncViewsWithActiveCFGIfEnabled arbiter model, Elmish.Cmd.none
  else model, Elmish.Cmd.none

let startTabDrag (model: Model) paneID tabID =
  let model = { model with FocusedPaneID = Some paneID }
  match Model.tryFindVisibleTab model tabID with
  | Some tab ->
    { model with DraggingTab = Some { SourcePaneID = paneID; Tab = tab } },
    Elmish.Cmd.none
  | None -> model, Elmish.Cmd.none

let private findTwoTabs (model: Model) paneID tabID1 tabID2 =
  let tabs =
    Pane.tryFindLeaf paneID model.RootPane
    |> Option.map Model.getVisibleTabsFromPane
    |> Option.defaultValue []
  let tab1 = tabs |> List.tryFind (fun t -> t.ID = tabID1)
  let tab2 = tabs |> List.tryFind (fun t -> t.ID = tabID2)
  tab1, tab2

let private reorderOpenTabs (model: Model) paneID draggedTabID targetTabID =
  match findTwoTabs model paneID draggedTabID targetTabID with
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

let reorderTab (model: Model) paneID draggedTabID targetTabID =
  let model = { model with FocusedPaneID = Some paneID }
  match reorderOpenTabs model paneID draggedTabID targetTabID with
  | Some(reorderedTabs, draggedTab) ->
    Model.mapFocusedPane
      (fun pane -> { pane with OpenTabs = reorderedTabs })
      { model with
          DraggingTab = Some { SourcePaneID = paneID; Tab = draggedTab } },
    Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let endTabDrag (model: Model) =
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

let private computeInitialCFGViewState cfgKind (cfg: VisGraph) (model: Model) =
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

let loadCFGCompleted arbiter (model: Model) tabID addr cfgKind cfg =
  match Model.tryFindTab model tabID with
  | Some(_, _, tab, _) ->
    let viewState = computeInitialCFGViewState cfgKind cfg model
    let loaded =
      { Graph = cfg
        FunctionAddress = addr
        ViewState = viewState
        Minimap = createMinimapCache model viewState cfg
        RenderCache = CFGRenderCache.create cfg }
    let tab = mapCFGTabState (Loaded loaded) tab
    replaceTabReferences model tab
    |> syncOffsetSnapshotWithActiveTab arbiter
    |> syncViewsWithActiveCFGIfEnabled arbiter,
    Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let loadCFGFailed (model: Model) tabID _reason =
  match Model.tryFindTab model tabID with
  | Some(_, _, tab, _) ->
    let tab = mapCFGTabState NotLoaded tab
    replaceTabReferences model tab, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let private updateCFGViewState target update =
  match target.Content with
  | CFGContent(fn, Loaded loaded) ->
    let viewState = update loaded.ViewState
    let loaded = { loaded with ViewState = viewState }
    { target with Content = CFGContent(fn, Loaded loaded) }
  | _ -> target

let private clampPanToGraphBounds panX panY viewState (model: Model) =
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

let setCFGZoom (model: Model) delta mouseX mouseY =
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

let startCFGPan (model: Model) x y =
  { model with
      CFGIsPanning = false
      CFGPressedPointer = Some(x, y)
      CFGPanPointer = None }, Elmish.Cmd.none

let moveCFGPan (model: Model) x y space =
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

let endCFGPan (model: Model) =
  { model with
      CFGIsPanning = false
      CFGPressedPointer = None
      CFGPanPointer = None }, Elmish.Cmd.none

let jumpCFGPan (model: Model) gx gy =
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

let private tryFindCFGNodeCenterByAddr loaded addr =
  loaded.Graph.Vertices
  |> Array.tryPick (fun n ->
    if n.VData.BlockAddress = addr then
      let x = n.VData.Coordinate.X + n.VData.Width / 2.0
      let y = n.VData.Coordinate.Y + n.VData.Height / 2.0
      Some(x, y)
    else
      None)

let jumpCFGPanToAddr (model: Model) addr =
  match model.ActiveTab with
  | Some { Content = CFGContent(_, Loaded loaded) } ->
    match tryFindCFGNodeCenterByAddr loaded addr with
    | Some(gx, gy) -> jumpCFGPan model gx gy
    | None -> model, Elmish.Cmd.none
  | _ ->
    model, Elmish.Cmd.none

let setCFGSelectedToken arbiter (model: Model) selectedToken =
  match model.ActiveTab with
  | Some tab ->
    let update viewState =
      { viewState with SelectedToken = selectedToken }
    let tab = updateCFGViewState tab update
    replaceTabReferences model tab
    |> syncOffsetSnapshotWithActiveTab arbiter
    |> syncViewsWithActiveCFGIfEnabled arbiter,
    Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let setHoveredCFGEdge (model: Model) edgeID =
  match model.ActiveTab with
  | Some tab ->
    let update viewState =
      { viewState with CFGViewState.HoveredEdge = edgeID }
    let tab = updateCFGViewState tab update
    replaceTabReferences model tab, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let updateCFGViewportSize arbiter (model: Model) paneID width height =
  if width <= 0.0 || height <= 0.0 then
    model, Elmish.Cmd.none
  else
    match Pane.tryFindLeaf paneID model.RootPane with
    | None ->
      model, Elmish.Cmd.none
    | Some pane ->
      let currentWidth, currentHeight = pane.ContentViewportSize
      let viewportSize = (width, height)
      let model =
        Model.mapPaneByID paneID
          (fun pane -> { pane with ContentViewportSize = viewportSize })
          model
      let model = resizeOpenedHexdumpTab arbiter model paneID width height
      let model = resizeOpenedLinearTab arbiter model paneID width height
      match pane.ActiveTab with
      | Some { Content = CFGContent _ } as activeTab ->
        let tab = activeTab.Value
        let deltaX = width / 2.0 - currentWidth / 2.0
        let deltaY = height / 2.0 - currentHeight / 2.0
        let update viewState =
          { viewState with
              PanX = viewState.PanX + deltaX
              PanY = viewState.PanY + deltaY }
        let tab =
          updateCFGViewState tab update
          |> refreshCFGTabMinimapForViewport viewportSize
        replaceTabReferences model tab, Elmish.Cmd.none
      | Some _ ->
        model, Elmish.Cmd.none
      | None ->
        model, Elmish.Cmd.none

let changeCFGKind (arbiter: Arbiter<_, _>) (model: Model) kind =
  match model.ActiveTab with
  | Some { Content = CFGContent(fn, Loaded { ViewState = view }) }
    when view.CFGKind <> kind ->
    let tabContent = CFGContent(fn, NotLoaded)
    let tab = { model.ActiveTab.Value with Content = tabContent }
    replaceTabReferences model tab, loadCFGCmd arbiter model fn kind tab
  | _ ->
    model, Elmish.Cmd.none

let toggleMinimap (model: Model) tabID activate =
  match model.ActiveTab with
  | Some { ID = activeID; Content = CFGContent(fn, Loaded loaded) }
    when activeID = tabID && loaded.ViewState.ShowMinimap <> activate ->
    let newViewState = { loaded.ViewState with ShowMinimap = activate }
    let content = { loaded with ViewState = newViewState }
    let tab =
      { model.ActiveTab.Value with Content = CFGContent(fn, Loaded content) }
    replaceTabReferences model tab, Elmish.Cmd.none
  | _ ->
    model, Elmish.Cmd.none

let focusPane (arbiter: Arbiter<_, _>) (model: Model) paneID =
  if model.FocusedPaneID = Some paneID then
    model, Elmish.Cmd.none
  elif Pane.tryFindLeaf paneID model.RootPane |> Option.isSome then
    { model with FocusedPaneID = Some paneID }
    |> syncOffsetSnapshotWithActiveTab arbiter,
    Elmish.Cmd.none
  else
    model, Elmish.Cmd.none

let private removeTabFromPane tabID pane =
  match Model.getVisibleTabsFromPane pane with
  | [] | [ _ ] ->
    pane, None, false
  | visibleTabs ->
    match List.tryFind (fun t -> t.ID = tabID) visibleTabs, pane.PreviewTab with
    | Some _, Some preview when preview.ID = tabID ->
      let active =
        match pane.ActiveTab with
        | Some active when active.ID = tabID -> pane.OpenTabs |> List.tryHead
        | _ -> pane.ActiveTab
      { pane with
          ActiveTab = active
          PreviewTab = None }, Some preview, true
    | Some tab, _ ->
      let openTabs = pane.OpenTabs |> List.filter (fun t -> t.ID <> tabID)
      let active =
        match pane.ActiveTab with
        | Some active when active.ID = tabID ->
          openTabs |> List.tryHead |> Option.orElse pane.PreviewTab
        | _ ->
          pane.ActiveTab
      { pane with
          ActiveTab = active
          OpenTabs = openTabs }, Some tab, false
    | None, _ ->
      pane, None, false

let private insertMovedTabToPane tab wasPreview pane =
  let openTabs = pane.OpenTabs |> List.filter (fun t -> t.ID <> tab.ID)
  let preview =
    match pane.PreviewTab with
    | Some existing when existing.ID = tab.ID -> None
    | existing -> existing
  if wasPreview && preview.IsNone then
    { pane with
        ActiveTab = Some tab
        OpenTabs = openTabs
        PreviewTab = Some tab }
  else
    { pane with
        ActiveTab = Some tab
        OpenTabs = tab :: openTabs
        PreviewTab = preview }

let rec private replacePane paneID replacement = function
  | Leaf(id, _) when id = paneID ->
    replacement
  | Leaf _ as leaf ->
    leaf
  | Split(id, axis, first, second) ->
    Split(
      id,
      axis,
      replacePane paneID replacement first,
      replacePane paneID replacement second
    )

let private finalizeMovedTab arbiter model =
  model
  |> syncOffsetSnapshotWithActiveTab arbiter
  |> syncViewsWithActiveCFGIfEnabled arbiter

let private moveTabBetweenPanes arbiter model sourcePaneID targetPaneID tabID =
  match Pane.tryFindLeaf sourcePaneID model.RootPane,
        Pane.tryFindLeaf targetPaneID model.RootPane with
  | Some sourcePane, Some targetPane when sourcePaneID <> targetPaneID ->
    let sourcePane, tabOpt, wasPreview = removeTabFromPane tabID sourcePane
    match tabOpt with
    | Some tab ->
      let targetPane = insertMovedTabToPane tab wasPreview targetPane
      let nextRoot =
        model.RootPane
        |> replacePane sourcePaneID (Leaf(sourcePaneID, sourcePane))
        |> replacePane targetPaneID (Leaf(targetPaneID, targetPane))
      { model with
          RootPane = nextRoot
          FocusedPaneID = Some targetPaneID
          DraggingTab = None }
      |> normalizePaneModel
      |> finalizeMovedTab arbiter,
      Elmish.Cmd.none
    | None ->
      model, Elmish.Cmd.none
  | _ ->
    model, Elmish.Cmd.none

let private decomposePlacement = function
  | LeftOf srcID -> srcID, LeftRight, fun src dst -> dst, src
  | RightOf srcID -> srcID, LeftRight, fun src dst -> src, dst
  | Above srcID -> srcID, TopBottom, fun src dst -> dst, src
  | Below srcID -> srcID, TopBottom, fun src dst -> src, dst

let private moveTabToNewSibling arbiter model placement tabID =
  let sourcePaneID, axis, swapChildren = decomposePlacement placement
  match Pane.tryFindLeaf sourcePaneID model.RootPane with
  | Some sourcePane ->
    let sourcePane, tabOpt, wasPreview = removeTabFromPane tabID sourcePane
    match tabOpt with
    | Some tab ->
      match Pane.createLeaf () with
      | Leaf(targetPaneID, targetPane) ->
        let targetPane =
          { targetPane with
              ContentViewportSize = sourcePane.ContentViewportSize }
        let targetPane = insertMovedTabToPane tab wasPreview targetPane
        let src = Leaf(sourcePaneID, sourcePane)
        let dst = Leaf(targetPaneID, targetPane)
        let left, right = swapChildren src dst
        let replacement = Split(Guid.NewGuid(), axis, left, right)
        let nextRoot = replacePane sourcePaneID replacement model.RootPane
        { model with
            RootPane = nextRoot
            FocusedPaneID = Some targetPaneID
            DraggingTab = None }
        |> normalizePaneModel
        |> finalizeMovedTab arbiter,
        Elmish.Cmd.none
      | Split _ ->
        model, Elmish.Cmd.none
    | None ->
      model, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let moveTabToPane arbiter model sourcePaneID targetPaneID tabID =
  moveTabBetweenPanes arbiter model sourcePaneID targetPaneID tabID

let rec private tryFindParentSplitOfLeaf paneID = function
  | Split(_, _, Leaf(id, _), _) as split when id = paneID ->
    Some split
  | Split(_, _, _, Leaf(id, _)) as split when id = paneID ->
    Some split
  | Split(_, _, first, second) ->
    tryFindParentSplitOfLeaf paneID first
    |> Option.orElse (tryFindParentSplitOfLeaf paneID second)
  | Leaf _ ->
    None

let rec private tryFindEdgeLeafID pickChild = function
  | Leaf(id, _) ->
    Some id
  | Split(_, _, first, second) ->
    tryFindEdgeLeafID pickChild (pickChild first second)

let private tryResolveAdjacentPaneIDs model = function
  | LeftOf srcID ->
    match tryFindParentSplitOfLeaf srcID model.RootPane with
    | Some(Split(_, LeftRight, left, Leaf(id, _))) when id = srcID ->
      tryFindEdgeLeafID (fun _ r -> r) left
      |> Option.map (fun dstID -> srcID, dstID)
    | _ -> None
  | RightOf srcID ->
    match tryFindParentSplitOfLeaf srcID model.RootPane with
    | Some(Split(_, LeftRight, Leaf(id, _), right)) when id = srcID ->
      tryFindEdgeLeafID (fun l _ -> l) right
      |> Option.map (fun dstID -> srcID, dstID)
    | _ -> None
  | Above srcID ->
    match tryFindParentSplitOfLeaf srcID model.RootPane with
    | Some(Split(_, TopBottom, above, Leaf(id, _))) when id = srcID ->
      tryFindEdgeLeafID (fun _ r -> r) above
      |> Option.map (fun dstID -> srcID, dstID)
    | _ -> None
  | Below srcID ->
    match tryFindParentSplitOfLeaf srcID model.RootPane with
    | Some(Split(_, TopBottom, Leaf(id, _), below)) when id = srcID ->
      tryFindEdgeLeafID (fun l _ -> l) below
      |> Option.map (fun dstID -> srcID, dstID)
    | _ -> None

let moveTabRelative arbiter model placement tabID =
  match tryResolveAdjacentPaneIDs model placement with
  | Some(srcID, dstID) ->
    moveTabBetweenPanes arbiter model srcID dstID tabID
  | _ ->
    moveTabToNewSibling arbiter model placement tabID

let updateViewportSize arbiter (model: Model) paneID width height =
  updateCFGViewportSize arbiter model paneID width height

let updateCFGLoad arbiter (model: Model) msg =
  match msg with
  | LoadCompleted(tabID, addr, cfgKind, cfg) ->
    loadCFGCompleted arbiter model tabID addr cfgKind cfg
  | LoadFailed(tabID, reason) ->
    loadCFGFailed model tabID reason

let updateCFG arbiter (model: Model) msg =
  match msg with
  | SetZoom(delta, mouseX, mouseY) ->
    setCFGZoom model delta mouseX mouseY
  | StartPan(x, y) ->
    startCFGPan model x y
  | MovePan(x, y, space) ->
    moveCFGPan model x y space
  | EndPan ->
    endCFGPan model
  | JumpPan(gx, gy) ->
    jumpCFGPan model gx gy
  | JumpPanToAddr addr ->
    jumpCFGPanToAddr model addr
  | SetSelectedToken token ->
    setCFGSelectedToken arbiter model token
  | SetHoveredEdge edgeID ->
    setHoveredCFGEdge model edgeID
  | ChangeKind kind ->
    changeCFGKind arbiter model kind
  | ToggleMinimap(tabID, activate) ->
    toggleMinimap model tabID activate

let updateStatusMsg (model: Model) msg =
  { model with StatusBarState = MessageOnly msg }, Elmish.Cmd.none

let updateStatusOffsetCtx (model: Model) sOff eOff sections =
  let selection = Some(mkOffsetRangeInfo sOff eOff sections)
  { model with
      OffsetSnapshot =
        { model.OffsetSnapshot with Selection = selection } },
  Elmish.Cmd.none
