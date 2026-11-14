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
open B2R2.Collections
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.BinExplore
open B2R2.RearEnd.Visualization

let private dispatchOnUi dispatch msg =
  Dispatcher.UIThread.Post(fun () -> dispatch msg)

let private cmdOfSub sub: Elmish.Cmd<Message> = [ sub ]

let private getBinarySource (arbiter: Arbiter<_, _>) (model: Model) =
  match model.SelectedBinaryID with
  | Some id ->
    arbiter.ForBinary id
  | None ->
    { new IBinarySource<_, _> with
        member _.GetBinaryBrew() = Error "No binary is selected." }

let private deferHexdumpScrollCmd tabID offsetY: Elmish.Cmd<Message> =
  cmdOfSub (fun dispatch ->
    Dispatcher.UIThread.Post(
      (fun () ->
        Dispatcher.UIThread.Post(
          (fun () ->
            dispatch (TabMsg(tabID, HexdumpPaneMsg(SetScrollOffset offsetY)))),
          DispatcherPriority.Background
        )),
      DispatcherPriority.Background
    ))

let private startLoadWorkflowCmd (arbiter: Arbiter<_, _>) request =
  let request: BinaryLoad = request
  cmdOfSub (fun dispatch ->
    let operation =
      arbiter.OpenBinaryAsync(request.Path, requestID = request.RequestID)
    Async.Start(async {
      try
        match! operation |> Async.AwaitTask with
        | Ok info ->
          dispatchOnUi dispatch (OpenBinaryCompleted(request.RequestID, info))
        | Error reason ->
          dispatchOnUi dispatch
          <| OpenBinaryFailed(request.RequestID, reason)
      with ex ->
        dispatchOnUi dispatch
        <| OpenBinaryFailed(request.RequestID, ex.Message)
    }))

let private startNextBinaryLoad arbiter (model: Model) =
  if model.BinaryLoads |> List.exists (fun r -> r.State = LoadingBinary) then
    model, Elmish.Cmd.none
  else
    match model.BinaryLoads |> List.tryFind (fun r -> r.State = Queued) with
    | Some request ->
      let loads =
        model.BinaryLoads |> List.map (fun r ->
          if r.RequestID = request.RequestID then
            { r with State = LoadingBinary }
          else
            r)
      { model with BinaryLoads = loads }, startLoadWorkflowCmd arbiter request
    | None ->
      model, Elmish.Cmd.none

let private growBinaryList (model: Model) =
  let count = model.BinaryOrder.Length + model.BinaryLoads.Length
  { model with
      BinaryListHeight =
        model.BinaryListHeight
        |> Option.map (max (NavigationPanel.requiredHeight count)) }

let private enqueueBinary (model: Model) path =
  if String.IsNullOrWhiteSpace path then
    model
  else
    let request = BinaryLoad.create path
    let exists =
      model.Binaries |> Map.exists (fun _ b ->
        BinaryLoad.samePath b.Info.Path request.Path)
    let pending =
      model.BinaryLoads |> List.tryFind (fun r ->
        BinaryLoad.samePath r.Path request.Path)
    match exists, pending with
    | true, _ ->
      model
    | false, Some { State = BinaryLoadState.LoadFailed _ }
    | false, Some { State = LoadCanceled } ->
      let loads =
        model.BinaryLoads |> List.map (fun r ->
          if BinaryLoad.samePath r.Path request.Path then request else r)
      { model with BinaryLoads = loads }
    | false, Some _ ->
      model
    | false, None ->
      { model with BinaryLoads = model.BinaryLoads @ [ request ] }

let private selectExistingBinaryCmd (model: Model) paths =
  paths
  |> List.tryLast
  |> Option.map BinaryLoad.create
  |> Option.bind (fun request ->
    model.Binaries |> Map.toList |> List.tryFind (fun (_, binary) ->
      BinaryLoad.samePath binary.Info.Path request.Path))
  |> Option.map (fun (id, _) -> Elmish.Cmd.ofMsg (Message.SelectBinary id))
  |> Option.defaultValue Elmish.Cmd.none

let openBinaries arbiter model paths =
  let selectCmd = selectExistingBinaryCmd model paths
  let model = List.fold enqueueBinary model paths
  let model, loadCmd =
    { model with StatusMessage = None }
    |> growBinaryList
    |> startNextBinaryLoad arbiter
  model, Elmish.Cmd.batch [ selectCmd; loadCmd ]

let retryBinaryLoad arbiter (model: Model) requestID =
  let loads =
    model.BinaryLoads |> List.map (fun request ->
      match request.State with
      | BinaryLoadState.LoadFailed _ | LoadCanceled
        when request.RequestID = requestID ->
        BinaryLoad.create request.Path
      | _ ->
        request)
  { model with BinaryLoads = loads } |> startNextBinaryLoad arbiter

let cancelBinaryLoad (arbiter: Arbiter<_, _>) model requestID =
  let loads =
    model.BinaryLoads |> List.map (fun request ->
      if request.RequestID <> requestID then
        request
      else
        match request.State with
        | Queued ->
          { request with State = LoadCanceled }
        | LoadingBinary when arbiter.CancelBinaryLoad requestID ->
          { request with State = LoadCanceled }
        | _ ->
          request)
  { model with BinaryLoads = loads } |> startNextBinaryLoad arbiter

let dismissBinaryLoad (model: Model) requestID =
  let loads =
    model.BinaryLoads |> List.filter (fun request ->
      match request.State with
      | BinaryLoadState.LoadFailed _ | LoadCanceled ->
        request.RequestID <> requestID
      | _ ->
        true)
  { model with BinaryLoads = loads }, Elmish.Cmd.none

let private startLinearAnalysisCmd source request sections fontSize =
  cmdOfSub (fun dispatch ->
    Async.Start(async {
      try
        match (source: IBinarySource<_, _>).GetBinaryBrew() with
        | Ok brew ->
          let doc = LinearDocument.load brew sections
          let state = LinearViewState.ofDocument doc fontSize
          dispatchOnUi dispatch (LinearAnalysisCompleted(request, doc, state))
        | _ ->
          dispatchOnUi dispatch
          <| LinearAnalysisFailed(request, "Failed to get loaded file.")
      with ex ->
        dispatchOnUi dispatch (LinearAnalysisFailed(request, ex.Message))
    }))

let private ensureLinearAnalysis arbiter (model: Model) id =
  match Map.tryFind id model.Binaries with
  | Some binary
    when binary.Hexdump.IsSome
      && binary.LinearDocument.IsNone
      && binary.LinearRequest.IsNone ->
    let request = AnalysisRequest.create id
    let source = (arbiter: Arbiter<_, _>).ForBinary id
    let model =
      Model.mapBinary id (fun binary ->
        { binary with
            LinearRequest = Some request
            LinearError = None }) model
    let cmd =
      startLinearAnalysisCmd
        source request binary.Sections model.Theme.Font.Monospace.FontSize
    model, cmd
  | _ ->
    model, Elmish.Cmd.none

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

let [<Literal>] private MinLinearFontSize = 8.0

let [<Literal>] private MaxLinearFontSize = 32.0

let private clampHexdumpFontSize fontSize =
  max MinHexdumpFontSize (min MaxHexdumpFontSize fontSize)

let private clampLinearFontSize fontSize =
  max MinLinearFontSize (min MaxLinearFontSize fontSize)

let private measureMaxCharSizeWithFontSize model fontSize =
  let fontFamily = FontFamily model.Theme.Font.Monospace.FontFamily
  let typeface = Typeface fontFamily
  let txt = mkText typeface fontSize "M"
  txt.Width, txt.Height

let private measureMaxCharSize model =
  measureMaxCharSizeWithFontSize model model.Theme.Font.Monospace.FontSize

let private clampLinearScrollState linearViewState =
  let contentHeight = LinearViewState.totalHeight linearViewState
  let maxScrollOffset = max 0.0 (contentHeight - linearViewState.ViewportHeight)
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

let private selectionHighlightSpec (theme: Theme) (sec: BinSection) =
  if isExceptionSectionName sec.Name then
    struct (theme.Hex.ExceptionArea, 8)
  elif isLinkageSectionName sec.Name then
    struct (theme.Hex.LinkageArea, 9)
  elif sec.Permission.HasFlag Permission.Executable then
    struct (theme.Hex.CodeArea, 10)
  elif sec.Permission.HasFlag Permission.Readable
       && sec.Kind <> MetadataSection then
    if sec.Permission.HasFlag Permission.Writable then
      struct (theme.Hex.WritableDataArea, 7)
    else
      struct (theme.Hex.ReadOnlyDataArea, 7)
  else
    struct (theme.Hex.MetadataArea, 6)

let private buildSpans (theme: Theme) (file: IBinFile) =
  let fileLength = int64 file.RawBytes.Length
  [ for sec in BinFileOps.getSections file do
      match sec.Offset with
      | Some offset when sec.FileSize > 0UL ->
        let start = int64 offset
        let length = int64 sec.FileSize
        if start >= 0L && start < fileLength then
          let length = min length (fileLength - start)
          let struct (bg, prio) = selectionHighlightSpec theme sec
          { Start = start
            Length = length
            Foreground = None
            Background = Some bg
            Priority = prio }
        else
          ()
      | _ ->
        () ]

let private buildHexAnnotations theme (file: IBinFile) (state: HexdumpState) =
  { state with AnnotationSpans = buildSpans theme file }

let private buildLoadedBinaryModel source model info =
  let binary = BinaryModel.init info
  match API.getFunctions source true,
        API.getSections source,
        API.getFile source with
  | Ok fns, Ok secs, Ok file ->
    let sections =
      secs |> ImmutableArray.map SectionItem.make |> List.ofArray
    let numDigits = (file.ISA.WordSize |> WordSize.toByteWidth) * 2
    let fontSize = model.Theme.Font.Monospace.FontSize
    let hexdump =
      HexdumpState.ofBytes file.BaseAddress file.RawBytes numDigits fontSize
      |> buildHexAnnotations model.Theme file
      |> initializeHexdumpTabView model
    let functionItems =
      fns |> Array.map (FunctionItem.ofFunction file) |> List.ofArray
    { binary with
        Functions = functionItems
        Sections = sections
        Hexdump = Some hexdump
        StatusBarState =
          FileLoaded(info.Path, FileFormat.toString file.Format) }
  | Error reason, _, _
  | _, Error reason, _
  | _, _, Error reason ->
    { binary with StatusBarState = MessageOnly reason }

let private activateLoadedBinary arbiter (model: Model) id =
  match Map.tryFind id model.Binaries with
  | Some binary ->
    let model =
      { model with
          SelectedBinaryID = Some id
          DraggingTab = None
          StatusMessage = None }
    let existing =
      binary.LastActiveTabID
      |> Option.bind (Model.tryFindTab model)
      |> Option.orElseWith (fun () ->
        Model.tryFindBinaryTab id Tab.isLinearView model)
      |> Option.orElseWith (fun () ->
        Model.tryFindBinaryTab id (fun _ -> true) model)
    let model =
      match existing with
      | Some(paneID, _, tab, _) ->
        Model.mapPaneByID paneID
          (fun pane -> { pane with ActiveTab = Some tab })
          { model with FocusedPaneID = Some paneID }
      | None when binary.Hexdump.IsSome ->
        let tab = Tab.ofLinearView id
        Model.mapFocusedPane (fun pane ->
          { pane with
              ActiveTab = Some tab
              OpenTabs = pane.OpenTabs @ [ tab ] }) model
      | None ->
        model
    let model =
      match model.ActiveTab with
      | Some tab when tab.BinaryID = id -> Model.followFocusedTab model
      | _ -> model
    ensureLinearAnalysis arbiter model id
  | None ->
    model, Elmish.Cmd.none

let initializeSession (arbiter: Arbiter<_, _>) model =
  let snapshot = arbiter.GetSessionSnapshot()
  let binaries =
    snapshot.Binaries
    |> List.map (fun info ->
      let source = arbiter.ForBinary info.BinaryID
      info.BinaryID, buildLoadedBinaryModel source model info)
    |> Map.ofList
  let model =
    let order = snapshot.Binaries |> List.map (fun info -> info.BinaryID)
    { model with
        Binaries = binaries
        BinaryOrder = order }
  match snapshot.CurrentBinaryID with
  | Some id -> activateLoadedBinary arbiter model id
  | None -> model, Elmish.Cmd.none

let private isActiveBinaryLoad (model: Model) requestID =
  model.BinaryLoads |> List.exists (fun request ->
    request.RequestID = requestID && request.State = LoadingBinary)

let openBinaryCompleted arbiter model requestID (info: BinaryInfo) =
  let arbiter: Arbiter<_, _> = arbiter
  if isActiveBinaryLoad model requestID then
    let id = info.BinaryID
    let model =
      { model with
          BinaryLoads =
            model.BinaryLoads |> List.filter (fun request ->
              request.RequestID <> requestID) }
    let model =
      if Map.containsKey id model.Binaries then
        model
      else
        let source = arbiter.ForBinary id
        let binary = buildLoadedBinaryModel source model info
        { model with
            Binaries = Map.add id binary model.Binaries
            BinaryOrder = model.BinaryOrder @ [ id ] }
        |> growBinaryList
    let model, analysisCmd = activateLoadedBinary arbiter model id
    let model, loadCmd = startNextBinaryLoad arbiter model
    model, Elmish.Cmd.batch [ analysisCmd; loadCmd ]
  else
    model, Elmish.Cmd.none

let openBinaryFailed arbiter model requestID reason =
  if isActiveBinaryLoad model requestID then
    let loads =
      model.BinaryLoads |> List.map (fun request ->
        if request.RequestID = requestID then
          { request with State = BinaryLoadState.LoadFailed reason }
        else
          request)
    { model with BinaryLoads = loads } |> startNextBinaryLoad arbiter
  else
    model, Elmish.Cmd.none

let closeWorkspace (arbiter: Arbiter<_, _>) (model: Model) =
  arbiter.CloseSession()
  let rootPane = Pane.createLeaf ()
  { model with
      Binaries = Map.empty
      BinaryOrder = []
      SelectedBinaryID = None
      BinaryLoads = []
      RootPane = rootPane
      FocusedPaneID = Some rootPane.ID
      DraggingTab = None
      CFGIsPanning = false
      CFGPressedPointer = None
      CFGPanPointer = None
      StatusMessage = None }, Elmish.Cmd.none

let private tryGetSelectedFileOffsetRange selection =
  let startOffset = min selection.Anchor selection.Caret
  let endOffset = max selection.Anchor selection.Caret
  let maxOffset = int64 UInt32.MaxValue
  if startOffset < 0L || endOffset < 0L then None
  elif startOffset > maxOffset || endOffset > maxOffset then None
  else Some(uint32 startOffset, uint32 endOffset)

let private findSectionRange (f: IBinFile) (sOff: uint32) (eOff: uint32) =
  match BinFileOps.tryFindSectionNameByOffset f sOff,
        BinFileOps.tryFindSectionNameByOffset f eOff with
  | Ok secStart, Ok secEnd when secStart = secEnd -> [ secStart ]
  | Ok secStart, Ok secEnd -> [ secStart; secEnd ]
  | _ -> []

let private mkOffsetRangeInfo sOff eOff sections =
  { Range = { Start = sOff; End = eOff }
    SectionRange = buildSectionRange sections }

let private tryGetOffsetRangeInfo source (sOff: uint32) (eOff: uint32) =
  match API.getFile source with
  | Ok file ->
    let sec = findSectionRange file sOff eOff
    Some(mkOffsetRangeInfo sOff eOff sec)
  | Error _ ->
    None

let private tryGetVisibleFileOffsetRange hexdump =
  match HexdumpState.tryGetVisibleByteRange hexdump with
  | Some(startOffset, endOffset) ->
    let maxOffset = int64 UInt32.MaxValue
    if startOffset > maxOffset then None
    else Some(uint32 startOffset, uint32 (min maxOffset endOffset))
  | None ->
    None

let private tryGetVisibleLinearOffsetRange linearDoc linearViewState =
  LinearProjection.tryGetVisibleFileOffsetRange linearDoc linearViewState
  |> Option.map (fun (startOffset, endOffset) ->
    uint32 startOffset, uint32 endOffset)

let private tryGetSelectionOffsetRangeInfo arbiter (model: Model) =
  let source = getBinarySource arbiter model
  match model.ActiveTab, model.Hexdump with
  | Some { Content = HexContent }, Some { Selection = Some sel } ->
    tryGetSelectedFileOffsetRange sel
    |> Option.bind (fun (sOff, eOff) -> tryGetOffsetRangeInfo source sOff eOff)
  | Some { Content = CFGContent(func, Loaded st) }, _ ->
    match st.ViewState.SelectedToken with
    | Some { Range = Some range } ->
      tryGetOffsetRangeInfo source (uint32 range.Min) (uint32 range.Max)
    | _ ->
      tryGetOffsetRangeInfo
        source
        (uint32 func.OffsetRange.Value.Min)
        (uint32 func.OffsetRange.Value.Max)
  | _ ->
    None

let private tryGetViewportOffsetRangeInfo arbiter (model: Model) =
  let source = getBinarySource arbiter model
  match model.ActiveTab with
  | Some { Content = LinearContent } ->
    match model.LinearDocument, model.LinearViewState with
    | Some doc, Some state ->
      tryGetVisibleLinearOffsetRange doc state
      |> Option.bind (fun (sOff, eOff) ->
        tryGetOffsetRangeInfo source sOff eOff)
    | _ ->
      None
  | _ ->
    match model.Hexdump, Model.tryFindSelectedBinaryTab Tab.isHexdump model with
    | Some hexdump, Some _ ->
      tryGetVisibleFileOffsetRange hexdump
      |> Option.bind (fun (sOff, eOff) ->
        tryGetOffsetRangeInfo source sOff eOff)
    | _ ->
      None

let private syncOffsetSnapshotWithActiveTab arbiter (model: Model) =
  match model.ActiveTab with
  | Some tab when Some tab.BinaryID <> model.SelectedBinaryID ->
    model
  | _ ->
    let snapshot =
      { Selection = tryGetSelectionOffsetRangeInfo arbiter model
        Viewport = tryGetViewportOffsetRangeInfo arbiter model }
    Model.mapSelectedBinary (fun binary ->
      { binary with OffsetSnapshot = snapshot }) model

let linearAnalysisCompleted arbiter model request doc state =
  let model: Model = model
  let request: AnalysisRequest = request
  match Map.tryFind request.BinaryID model.Binaries with
  | Some binary when binary.LinearRequest = Some request ->
    let context =
      match Model.tryFindBinaryTab request.BinaryID Tab.isLinearView model with
      | Some(paneID, _, _, _) -> Model.forPane paneID model
      | None -> model
    let state = initializeLinearView context doc state
    let model =
      Model.mapBinary request.BinaryID (fun binary ->
        { binary with
            LinearRequest = None
            LinearError = None
            LinearDocument = Some doc
            LinearViewState = Some state }) model
    let model =
      if model.SelectedBinaryID = Some request.BinaryID then
        syncOffsetSnapshotWithActiveTab arbiter model
      else
        model
    model, Elmish.Cmd.none
  | _ ->
    model, Elmish.Cmd.none

let linearAnalysisFailed (model: Model) request reason =
  let request: AnalysisRequest = request
  match Map.tryFind request.BinaryID model.Binaries with
  | Some binary when binary.LinearRequest = Some request ->
    let reason = $"Failed to analyze linear view: {reason}"
    Model.mapBinary request.BinaryID (fun binary ->
      { binary with
          LinearRequest = None
          LinearError = Some reason }) model, Elmish.Cmd.none
  | _ ->
    model, Elmish.Cmd.none

let private replaceTabByID tabID newTab oldTab =
  if oldTab.ID = tabID then newTab else oldTab

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

let private activateOrOpenTab predicate createTab (model: Model) =
  match model.SelectedBinaryID with
  | Some id ->
    match Model.tryFindBinaryTab id predicate model with
    | Some(paneID, _, tab, _) ->
      Model.mapPaneByID paneID
        (fun pane -> { pane with ActiveTab = Some tab })
        { model with FocusedPaneID = Some paneID }
      |> Model.followFocusedTab
    | None ->
      let tab = createTab id
      Model.mapFocusedPane (fun pane ->
        { pane with
            ActiveTab = Some tab
            OpenTabs = pane.OpenTabs @ [ tab ] }) model
      |> Model.followFocusedTab
  | None ->
    model

let openHexdumpTab arbiter (model: Model) =
  match model.Hexdump with
  | Some hexdump ->
    Model.mapSelectedBinary (fun binary ->
      { binary with Hexdump = Some(activateHexdumpView model hexdump) }) model
    |> activateOrOpenTab Tab.isHexdump Tab.ofHexdump
    |> syncOffsetSnapshotWithActiveTab arbiter, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let openLinearViewTab arbiter (model: Model) =
  match model.SelectedBinaryID with
  | Some id ->
    let model, cmd = ensureLinearAnalysis arbiter model id
    let model =
      match model.LinearDocument, model.LinearViewState with
      | Some doc, Some state ->
        let state = initializeLinearView model doc state
        Model.mapSelectedBinary (fun binary ->
          { binary with LinearViewState = Some state }) model
      | _ ->
        model
    activateOrOpenTab Tab.isLinearView Tab.ofLinearView model
    |> syncOffsetSnapshotWithActiveTab arbiter, cmd
  | None ->
    model, Elmish.Cmd.none

let private mapCFGTabState newState (tab: Tab) =
  match tab.Content with
  | CFGContent(func, _) -> { tab with Content = CFGContent(func, newState) }
  | _ -> tab

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
    Model.mapSelectedBinary (fun b -> { b with Hexdump = Some hexdump }) model
    |> syncOffsetSnapshotWithActiveTab arbiter
  | _ ->
    model

let private updateHexViewState arbiter (model: Model) updateView =
  updateHexdumpState arbiter model (fun hexdump ->
    let view = updateView hexdump.View
    { hexdump with View = view }), Elmish.Cmd.none

let private syncHexViewportWithLinear (model: Model) =
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
      Model.mapSelectedBinary (fun binary ->
        { binary with Hexdump = Some { hexdump with View = view } }) model
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
    Model.mapSelectedBinary (fun binary ->
      { binary with LinearViewState = Some linearViewState }) model
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
    |> List.exists (fun tab ->
      Some tab.BinaryID = model.SelectedBinaryID && Tab.isHexdump tab)
  match Pane.tryFindLeaf paneID model.RootPane with
  | Some pane when containsHexdumpTab pane ->
    updateHexdumpState arbiter model (fun hexdump ->
      let viewState = hexdump.View
      let topByte = viewState.ScrollRow * int64 (max 1 viewState.BytesPerRow)
      let fontSize = clampHexdumpFontSize viewState.FontSize
      let charWidth, rowHeight = measureMaxCharSizeWithFontSize model fontSize
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
    |> List.exists (fun tab ->
      Some tab.BinaryID = model.SelectedBinaryID && Tab.isLinearView tab)
  match Pane.tryFindLeaf paneID model.RootPane with
  | Some pane when containsLinearTab pane ->
    updateLinearViewState arbiter model (fun doc linearViewState ->
      let fontSize =
        if linearViewState.FontSize > 0.0 then linearViewState.FontSize
        else model.Theme.Font.Monospace.FontSize
      let charWidth, rowHeight = measureMaxCharSizeWithFontSize model fontSize
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
          if abs pendingDelta > 0.5 then IgnoreNextProgrammatic pendingDelta
          else NoScrollGuard }
  { hexdump with
      HighlightSpans =
        [ { Start = byteIndex
            Length = highlightLength
            Foreground = Some theme.Search.Foreground
            Background = Some theme.Search.SelectedBackground
            Priority = 100 } ]
      View = nextView }, targetOffsetY, pendingDelta

let private jumpHexdump (model: Model) byteIndex length =
  match model.Hexdump with
  | Some hexdump ->
    let nextHexdump, targetOffsetY, pendingDelta =
      computeJumpedHexdump model.Theme hexdump byteIndex length
    let model =
      Model.mapSelectedBinary (fun binary ->
        { binary with Hexdump = Some nextHexdump }) model
    let hasHexdumpTab =
      Model.tryFindSelectedBinaryTab Tab.isHexdump model |> Option.isSome
    let cmd =
      match model.ActiveTab with
      | Some tab when hasHexdumpTab && abs pendingDelta > 0.5 ->
        deferHexdumpScrollCmd tab.ID targetOffsetY
      | _ ->
        Elmish.Cmd.none
    model, cmd
  | _ ->
    model, Elmish.Cmd.none

let private jumpHexdumpToOffset arbiter model (offset: uint64) =
  updateHexdumpState arbiter model (fun hexdump ->
    computeJumpedHexdump model.Theme hexdump (int64 offset) 1L
    |> fun (nextHexdump, _, _) -> nextHexdump)

let private jumpHexdumpToAddress arbiter model addr =
  match API.getFile (getBinarySource arbiter model) with
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
  match API.getFile (getBinarySource arbiter model) with
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
  | Some { BinaryID = id; Content = CFGContent(fn, Loaded st) }
    when Some id = model.SelectedBinaryID ->
    match st.ViewState.SelectedToken with
    | Some { Range = Some range } -> Some(CFGAddressRange range)
    | _ -> Some(CFGOffsetRange fn.OffsetRange.Value)
  | _ ->
    None

let private tryGetTargetFileOffset source = function
  | CFGAddressRange range ->
    match API.getFile source with
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
      Model.mapSelectedBinary (fun binary ->
        { binary with LinearViewState = Some state }) model
    | None ->
      model
  | _ ->
    model

let private syncLinearWithCFGTarget arbiter (model: Model) target =
  match tryGetTargetFileOffset (getBinarySource arbiter model) target with
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
  if model.SyncEnabled then syncViewsWithActiveCFG arbiter model else model

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
      Model.mapSelectedBinary (fun binary ->
        { binary with Hexdump = Some { hexdump with View = view } }) model
    | None ->
      model
  syncLinearWithFileOffset model (int offset)
  |> syncOffsetSnapshotWithActiveTab arbiter, Elmish.Cmd.none

let updateHexdump arbiter (model: Model) msg =
  match msg with
  | SetHighlightSpans spans ->
    updateHexdumpState arbiter model (fun hexdump ->
      { hexdump with HighlightSpans = spans }), Elmish.Cmd.none
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
    let updateState =
      updateHexdumpState arbiter model (fun hexdump ->
        syncHexScrollOffset hexdump offsetY hexdump.View.ScrollGuard)
    updateState, Elmish.Cmd.none
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
    let updateState =
      updateHexdumpState arbiter model (fun hexdump ->
        { hexdump with View = { hexdump.View with IsSelecting = false } })
    updateState, Elmish.Cmd.none
  | SetHoveredByte byteIndex ->
    updateHexViewState arbiter model (fun viewState ->
      let hovered =
        match model.Hexdump with
        | Some hexdump -> byteIndex |> Option.bind (clampHexByteIndex hexdump)
        | _ -> None
      { viewState with HoveredByte = hovered })
  | _ ->
    model, Elmish.Cmd.none

let updateLinear arbiter (model: Model) msg =
  match msg with
  | LinearPaneMessage.HandleScrollChanged(offsetY, _) ->
    updateLinearViewState arbiter model (fun _ viewState ->
      { viewState with ScrollOffsetY = offsetY }), Elmish.Cmd.none
  | LinearPaneMessage.SetScrollOffset offsetY ->
    updateLinearViewState arbiter model (fun _ viewState ->
      { viewState with ScrollOffsetY = offsetY }), Elmish.Cmd.none
  | LinearPaneMessage.ChangeFontSize delta when abs delta > 0.0 ->
    updateLinearViewState arbiter model (fun doc linearViewState ->
      let topIndex, _ = LinearViewState.findVisibleRange 0.0 linearViewState
      let topItemOffset =
        linearViewState.ScrollOffsetY
        - LinearViewState.itemTop linearViewState topIndex
      let fontSize = clampLinearFontSize (linearViewState.FontSize + delta)
      let charWidth, rowHeight = measureMaxCharSizeWithFontSize model fontSize
      let nextState =
        { linearViewState with
            FontSize = fontSize
            CharWidth = charWidth
            RowHeight = rowHeight }
        |> LinearViewState.rebuildUniformLayout rowHeight doc
      { nextState with
          ScrollOffsetY =
            LinearViewState.itemTop nextState topIndex
            + max 0.0 topItemOffset }), Elmish.Cmd.none
  | LinearPaneMessage.UpdateFontMetrics(charWidth, rowHeight)
    when charWidth > 0.0 && rowHeight > 0.0 ->
    updateLinearViewState arbiter model (fun doc linearViewState ->
      { linearViewState with
          CharWidth = charWidth
          RowHeight = rowHeight }
      |> LinearViewState.rebuildUniformLayout rowHeight doc), Elmish.Cmd.none
  | _ ->
    model, Elmish.Cmd.none

let private getCFG source (request: CFGRequest) (cw, ch) =
  match request.Kind with
  | CFGKind.Disasm -> API.getDisasmCFG source request.Address cw ch
  | CFGKind.LowUIR -> API.getLowUIRCFG source request.Address cw ch
  | CFGKind.SSA -> API.getSSACFG source request.Address cw ch
  | _ -> API.getCallCFG source

let private loadCFGCmd arbiter request charSize =
  let source = (arbiter: Arbiter<_, _>).ForBinary request.Analysis.BinaryID
  cmdOfSub (fun dispatch ->
    Async.Start(async {
      try
        match getCFG source request charSize with
        | Ok cfg ->
          dispatchOnUi dispatch (CFGLoadMsg(LoadCompleted(request, cfg)))
        | Error e ->
          dispatchOnUi dispatch (CFGLoadMsg(LoadFailed(request, e)))
      with ex ->
        dispatchOnUi dispatch (CFGLoadMsg(LoadFailed(request, ex.Message)))
    }))

let private startCFGLoad arbiter model tab kind =
  match tab.Content with
  | CFGContent(fn, _) ->
    let request =
      { Analysis = AnalysisRequest.create tab.BinaryID
        TabID = tab.ID
        Address = fn.Address
        Kind = kind }
    let tab = mapCFGTabState (Loading request.Analysis) tab
    let model = replaceTabReferences model tab
    model, loadCFGCmd arbiter request (measureMaxCharSize model)
  | _ ->
    model, Elmish.Cmd.none

let private startLoadIfNeeded arbiter tab (model: Model) =
  match tab.Content with
  | CFGContent(_, NotLoaded) ->
    startCFGLoad arbiter model tab CFGKind.Disasm
  | _ ->
    let tab = refreshCFGTabMinimap model tab
    let model =
      replaceTabReferences model tab |> syncOffsetSnapshotWithActiveTab arbiter
    model, Elmish.Cmd.none

let private openCFGTabForBinary arbiter model fnItem id =
  let tab = Tab.ofFunctionItem id fnItem
  let model =
    match Model.tryFindBinaryTab id (Tab.isFunction fnItem) model with
    | Some(paneID, _, tab, _) ->
      Model.mapPaneByID paneID
        (fun pane -> { pane with ActiveTab = Some tab })
        (Model.forPane paneID model)
    | None ->
      Model.mapFocusedPane
        (fun pane -> { pane with ActiveTab = Some tab; PreviewTab = Some tab })
        model
    |> Model.followFocusedTab
  let tab = model.ActiveTab.Value
  let model, cmd = startLoadIfNeeded arbiter tab model
  syncViewsWithActiveCFGIfEnabled arbiter model, cmd

let openCFGTab arbiter (model: Model) fnItem =
  match model.SelectedBinaryID with
  | Some id -> openCFGTabForBinary arbiter model fnItem id
  | None -> model, Elmish.Cmd.none

let private pinCFGTabForBinary arbiter model fnItem id =
  let tab = Tab.ofFunctionItem id fnItem
  let paneID, newOpenTabs, tab =
    match Model.tryFindBinaryTab id (Tab.isFunction fnItem) model with
    | Some(paneID, paneState, tab, isPreview) ->
      if isPreview then paneID, tab :: paneState.OpenTabs, tab
      else paneID, paneState.OpenTabs, tab
    | None ->
      let paneID = Model.getFocusedPaneID model
      paneID, tab :: model.OpenTabs, tab
  let model =
    Model.mapPaneByID paneID (fun pane ->
      { pane with
          ActiveTab = Some tab
          OpenTabs = newOpenTabs
          PreviewTab = None }) (Model.forPane paneID model)
    |> Model.followFocusedTab
  let model, cmd = startLoadIfNeeded arbiter tab model
  syncViewsWithActiveCFGIfEnabled arbiter model, cmd

let pinCFGTab arbiter (model: Model) fnItem =
  match model.SelectedBinaryID with
  | Some id -> pinCFGTabForBinary arbiter model fnItem id
  | None -> model, Elmish.Cmd.none

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
    |> Model.followFocusedTab
    |> syncOffsetSnapshotWithActiveTab arbiter, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let switchTab arbiter (model: Model) paneID tabID =
  let model = { model with FocusedPaneID = Some paneID }
  match Model.tryFindVisibleTab model tabID with
  | Some tab ->
    let model = { model with SelectedBinaryID = Some tab.BinaryID }
    let model =
      if Tab.isHexdump tab then
        match model.Hexdump with
        | Some hexdump ->
          Model.mapSelectedBinary (fun binary ->
            { binary with
                Hexdump = Some(prepareHexdumpViewForActivation hexdump) }) model
        | None ->
          model
      else
        model
    let tab =
      if Tab.isHexdump tab then tab else refreshCFGTabMinimap model tab
    replaceTabReferences (Model.mapFocusedPane
      (fun pane -> { pane with ActiveTab = Some tab }) model) tab
    |> Model.followFocusedTab
    |> syncOffsetSnapshotWithActiveTab arbiter
    |> syncViewsWithActiveCFGIfEnabled arbiter, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let setSyncEnabled (arbiter: Arbiter<_, _>) (model: Model) enabled =
  let model =
    Model.mapSelectedBinary (fun b -> { b with SyncEnabled = enabled }) model
  if enabled then syncViewsWithActiveCFGIfEnabled arbiter model, Elmish.Cmd.none
  else model, Elmish.Cmd.none

let selectBinary arbiter (model: Model) id =
  if Map.containsKey id model.Binaries then
    let model, cmd = activateLoadedBinary arbiter model id
    match model.ActiveTab with
    | Some tab when tab.BinaryID = id ->
      let paneID = Model.getFocusedPaneID model
      let model, switchCmd = switchTab arbiter model paneID tab.ID
      model, Elmish.Cmd.batch [ cmd; switchCmd ]
    | _ ->
      model, cmd
  else
    model, Elmish.Cmd.none

let setBinaryListExpanded model expanded =
  { model with BinaryListExpanded = expanded }, Elmish.Cmd.none

let setBinaryListHeight model height =
  if Double.IsFinite height then
    let model =
      { model with BinaryListHeight = Some(max 56.0 (min 300.0 height)) }
    model, Elmish.Cmd.none
  else
    model, Elmish.Cmd.none

let startTabDrag (model: Model) paneID tabID =
  let model = { model with FocusedPaneID = Some paneID }
  match Model.tryFindVisibleTab model tabID with
  | Some tab ->
    let updatedModel =
      { model with DraggingTab = Some { SourcePaneID = paneID; Tab = tab } }
    updatedModel, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

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
  | _ ->
    None

let reorderTab (model: Model) paneID draggedTabID targetTabID =
  let model = { model with FocusedPaneID = Some paneID }
  match reorderOpenTabs model paneID draggedTabID targetTabID with
  | Some(reorderedTabs, draggedTab) ->
    let focus =
      Model.mapFocusedPane
        (fun pane -> { pane with OpenTabs = reorderedTabs })
        { model with
            DraggingTab = Some { SourcePaneID = paneID; Tab = draggedTab } }
    focus, Elmish.Cmd.none
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
      Theme = currentTheme }, Elmish.Cmd.none

let private applyThemeVariant (window: Window) mode =
  match mode with
  | Builtin Light -> window.RequestedThemeVariant <- ThemeVariant.Light
  | Builtin Dark -> window.RequestedThemeVariant <- ThemeVariant.Dark
  | Custom _ -> ()

let setThemeMode window arbiter model mode =
  let arbiter: Arbiter<_, _> = arbiter
  applyThemeVariant window mode
  let theme = Theme.resolve mode model.CustomThemes
  let binaries =
    model.Binaries
    |> Map.map (fun id binary ->
      match binary.Hexdump, API.getFile (arbiter.ForBinary id) with
      | Some hexdump, Ok file ->
        { binary with Hexdump = Some(buildHexAnnotations theme file hexdump) }
      | _ ->
        binary)
  { model with
      ThemeMode = mode
      Theme = theme
      Binaries = binaries }, Elmish.Cmd.none

let updateFunctionFilter model text =
  let model =
    Model.mapSelectedBinary (fun b -> { b with FunctionFilter = text }) model
  model, Elmish.Cmd.none

let selectWorkspacePanel model panel =
  let model =
    Model.mapSelectedBinary (fun b -> { b with WorkspacePanel = panel }) model
  model, Elmish.Cmd.none

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

let private isPendingCFG request (tab: Tab) =
  tab.BinaryID = request.Analysis.BinaryID
  && match tab.Content with
     | CFGContent(_, Loading pending) -> pending = request.Analysis
     | _ -> false

let loadCFGCompleted arbiter model request cfg =
  match Model.tryFindTab model request.TabID with
  | Some(paneID, _, tab, _) when isPendingCFG request tab ->
    let context = Model.forPane paneID model
    let viewState = computeInitialCFGViewState request.Kind cfg context
    let loaded =
      { Graph = cfg
        FunctionAddress = request.Address
        ViewState = viewState
        Minimap = createMinimapCache context viewState cfg
        RenderCache = CFGRenderCache.create cfg }
    let tab = mapCFGTabState (Loaded loaded) tab
    let model = replaceTabReferences model tab
    let model =
      match model.ActiveTab with
      | Some active when active.ID = tab.ID ->
        syncOffsetSnapshotWithActiveTab arbiter model
        |> syncViewsWithActiveCFGIfEnabled arbiter
      | _ ->
        model
    model, Elmish.Cmd.none
  | _ ->
    model, Elmish.Cmd.none

let loadCFGFailed (model: Model) request _reason =
  match Model.tryFindTab model request.TabID with
  | Some(_, _, tab, _) when isPendingCFG request tab ->
    let tab = mapCFGTabState NotLoaded tab
    replaceTabReferences model tab, Elmish.Cmd.none
  | _ ->
    model, Elmish.Cmd.none

let private updateCFGViewState target update =
  match target.Content with
  | CFGContent(fn, Loaded loaded) ->
    let viewState = update loaded.ViewState
    let loaded = { loaded with ViewState = viewState }
    { target with Content = CFGContent(fn, Loaded loaded) }
  | _ ->
    target

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
        clampPanToGraphBounds newPanX
          newPanY
          { viewState with Zoom = newZoom }
          model
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
      let updated =
        { replaceTabReferences model tab with CFGPanPointer = Some(x, y) }
      updated, Elmish.Cmd.none
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
    let update viewState = { viewState with SelectedToken = selectedToken }
    let tab = updateCFGViewState tab update
    replaceTabReferences model tab
    |> syncOffsetSnapshotWithActiveTab arbiter
    |> syncViewsWithActiveCFGIfEnabled arbiter, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let setHoveredCFGEdge (model: Model) edgeID =
  match model.ActiveTab with
  | Some tab ->
    let update viewState = { viewState with CFGViewState.HoveredEdge = edgeID }
    let tab = updateCFGViewState tab update
    replaceTabReferences model tab, Elmish.Cmd.none
  | None ->
    model, Elmish.Cmd.none

let private resizePaneDocuments arbiter model paneID size =
  match Pane.tryFindLeaf paneID model.RootPane with
  | Some pane ->
    Model.getVisibleTabsFromPane pane
    |> List.distinctBy (fun tab -> tab.BinaryID)
    |> List.fold (fun model tab ->
      let context =
        { model with
            SelectedBinaryID = Some tab.BinaryID
            FocusedPaneID = Some paneID }
      let width, height = size
      let updated = resizeOpenedHexdumpTab arbiter context paneID width height
      let updated = resizeOpenedLinearTab arbiter updated paneID width height
      Model.restoreContext model updated) model
  | None ->
    model

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
      let model = resizePaneDocuments arbiter model paneID viewportSize
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
  | Some { Content = CFGContent(_, Loaded { ViewState = view }) }
    when view.CFGKind = kind ->
    model, Elmish.Cmd.none
  | Some({ Content = CFGContent _ } as tab) ->
    startCFGLoad arbiter model tab kind
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
    Model.forPane paneID model
    |> Model.followFocusedTab
    |> syncOffsetSnapshotWithActiveTab arbiter, Elmish.Cmd.none
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
  |> Model.followFocusedTab
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
      |> finalizeMovedTab arbiter, Elmish.Cmd.none
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
        |> finalizeMovedTab arbiter, Elmish.Cmd.none
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
    | _ ->
      None
  | RightOf srcID ->
    match tryFindParentSplitOfLeaf srcID model.RootPane with
    | Some(Split(_, LeftRight, Leaf(id, _), right)) when id = srcID ->
      tryFindEdgeLeafID (fun l _ -> l) right
      |> Option.map (fun dstID -> srcID, dstID)
    | _ ->
      None
  | Above srcID ->
    match tryFindParentSplitOfLeaf srcID model.RootPane with
    | Some(Split(_, TopBottom, above, Leaf(id, _))) when id = srcID ->
      tryFindEdgeLeafID (fun _ r -> r) above
      |> Option.map (fun dstID -> srcID, dstID)
    | _ ->
      None
  | Below srcID ->
    match tryFindParentSplitOfLeaf srcID model.RootPane with
    | Some(Split(_, TopBottom, Leaf(id, _), below)) when id = srcID ->
      tryFindEdgeLeafID (fun l _ -> l) below
      |> Option.map (fun dstID -> srcID, dstID)
    | _ ->
      None

let moveTabRelative arbiter model placement tabID =
  match tryResolveAdjacentPaneIDs model placement with
  | Some(srcID, dstID) -> moveTabBetweenPanes arbiter model srcID dstID tabID
  | _ -> moveTabToNewSibling arbiter model placement tabID

let updateViewportSize arbiter (model: Model) paneID width height =
  updateCFGViewportSize arbiter model paneID width height

let updateCFGLoad arbiter (model: Model) msg =
  match msg with
  | LoadCompleted(request, cfg) ->
    loadCFGCompleted arbiter model request cfg
  | LoadFailed(request, reason) ->
    loadCFGFailed model request reason

let updateCFG arbiter (model: Model) msg =
  match msg with
  | SetZoom(delta, mouseX, mouseY) -> setCFGZoom model delta mouseX mouseY
  | StartPan(x, y) -> startCFGPan model x y
  | MovePan(x, y, space) -> moveCFGPan model x y space
  | EndPan -> endCFGPan model
  | JumpPan(gx, gy) -> jumpCFGPan model gx gy
  | JumpPanToAddr addr -> jumpCFGPanToAddr model addr
  | SetSelectedToken token -> setCFGSelectedToken arbiter model token
  | SetHoveredEdge edgeID -> setHoveredCFGEdge model edgeID
  | ChangeKind kind -> changeCFGKind arbiter model kind
  | ToggleMinimap(tabID, activate) -> toggleMinimap model tabID activate

let updateStatusMsg (model: Model) msg =
  { model with StatusMessage = Some msg }, Elmish.Cmd.none

let clearStatusMsg (model: Model) =
  { model with StatusMessage = None }, Elmish.Cmd.none

let updateStatusOffsetCtx (model: Model) sOff eOff sections =
  let selection = Some(mkOffsetRangeInfo sOff eOff sections)
  let model =
    Model.mapSelectedBinary (fun binary ->
      { binary with
          OffsetSnapshot =
            { binary.OffsetSnapshot with Selection = selection } }) model
  model, Elmish.Cmd.none

let routeTabMessage update model tabID message =
  match Model.tryFindTab model tabID with
  | Some(paneID, pane, tab, _)
    when pane.ActiveTab |> Option.exists (fun active -> active.ID = tabID)
      && Map.containsKey tab.BinaryID model.Binaries ->
    let updated, cmd = update message (Model.forPane paneID model)
    let updated =
      match message with
      | OpenCFGTab _ | PinCFGTab _ | OpenHexdumpTab | OpenLinearViewTab ->
        updated
      | _ ->
        Model.restoreContext model updated
    updated, cmd
  | _ ->
    model, Elmish.Cmd.none
