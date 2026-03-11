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

namespace B2R2.RearEnd.BinExplore.GUI

open System
open System.IO
open Avalonia.FuncUI
open Avalonia.FuncUI.Hosts
open Avalonia.Controls
open Avalonia.Styling
open Avalonia.Threading
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.RearEnd.BinExplore
open B2R2.RearEnd.Visualization

type MainWindow<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                                and 'FnCtx: (new: unit -> 'FnCtx)
                                and 'GlCtx: (new: unit -> 'GlCtx)>
  public(arbiter: Arbiter<'FnCtx, 'GlCtx>) as this =
  inherit HostWindow()

  let [<Literal>] WelcomeMessage = "Welcome to BinExplore!"

  let init () =
    let themeMode = Theme.defaultMode
    let customThemes = Map.empty
    { LoadedBinary = None
      LoadingBinaryPath = None
      Functions = []
      FunctionFilter = ""
      ActiveTab = None
      OpenTabs = []
      PreviewTab = None
      CustomThemes = customThemes
      ThemeMode = themeMode
      Theme = Theme.resolve themeMode customThemes
      DraggingTab = None
      WorkspacePanel = FunctionPanel
      CFGIsPanning = false
      CFGPanPointer = None
      CFGViewportSize = (0.0, 0.0)
      StatusMessage = WelcomeMessage }, Elmish.Cmd.none

  let loadBinaryAsync (filePath: string) =
    async {
      return arbiter.AddBinary filePath
    }

  let dispatchOnUi dispatch msg =
    Dispatcher.UIThread.Post(fun () -> dispatch msg)

  let cmdOfSub (sub: Elmish.Dispatch<Message> -> unit): Elmish.Cmd<Message> =
    [ sub ]

  let startLoadWorkflowCmd (filePath: string) =
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
          match! loadBinaryAsync filePath with
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

  let findTwoTabs model tabID1 tabID2 =
    let tab1 = model.OpenTabs |> List.tryFind (fun t -> t.ID = tabID1)
    let tab2 = model.OpenTabs |> List.tryFind (fun t -> t.ID = tabID2)
    tab1, tab2

  let reorderOpenTabs model draggedTabID targetTabID =
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

  let tryFindTab tabs tabID =
    tabs |> List.tryFind (fun t -> t.ID = tabID)

  let mapCFGTabState newState (tab: Tab) =
    match tab.Content with
    | CFGTab(func, _) ->
      { tab with Content = CFGTab(func, newState) }
    | _ ->
      tab

  let getAllVisibleTabs model =
    match model.PreviewTab with
    | Some preview -> preview :: model.OpenTabs
    | None -> model.OpenTabs

  let replaceTabByID tabID newTab oldTab =
    if oldTab.ID = tabID then newTab
    else oldTab

  let loadCFGCmd (fn: FunctionItem) (tab: Tab) =
    cmdOfSub (fun dispatch ->
      Async.Start(async {
        try
          match arbiter.GetBinaryBrew() with
          | Some brew ->
            let file = brew.BinHandle.File
            let wordSize = file.ISA.WordSize
            let disasmBuilder = AsmWordDisasmBuilder(true, file, wordSize)
            let cfg = brew.Functions[fn.Address].CFG
            let disasmCFG = DisasmCFG(disasmBuilder, cfg)
            let roots = disasmCFG.Roots |> List.ofArray
            let visGraph = Visualizer.toVisGraph disasmCFG roots
            dispatchOnUi dispatch (LoadCFGCompleted(tab.ID, visGraph))
          | None ->
            dispatchOnUi dispatch (LoadCFGFailed(tab.ID, "No binary loaded"))
        with ex ->
          dispatchOnUi dispatch (LoadCFGFailed(tab.ID, ex.Message))
      }))

  let startLoadIfNeeded tab model =
    match tab.Content with
    | CFGTab(fn, NotLoaded) ->
      let loadingTab = mapCFGTabState Loading tab
      { model with
          ActiveTab = Some loadingTab
          PreviewTab = Some loadingTab },
      loadCFGCmd fn loadingTab
    | _ ->
      model, Elmish.Cmd.none

  let updateCFGViewState target update =
    match target with
    | { Content = CFGTab(fn, Loaded(cfg, viewState)) } ->
      let viewState' = update viewState
      { target with Content = CFGTab(fn, Loaded(cfg, viewState')) }
    | _ -> target

  let clampPanToGraphBounds panX panY viewState model =
    let viewportWidth, viewportHeight = model.CFGViewportSize
    let cameraCenterX = (viewportWidth / 2.0 - panX) / viewState.Zoom
    let cameraCenterY = (viewportHeight / 2.0 - panY) / viewState.Zoom
    let clampedCenterX =
      max viewState.GraphMinX (min viewState.GraphMaxX cameraCenterX)
    let clampedCenterY =
      max viewState.GraphMinY (min viewState.GraphMaxY cameraCenterY)
    let clampedPanX = viewportWidth / 2.0 - clampedCenterX * viewState.Zoom
    let clampedPanY = viewportHeight / 2.0 - clampedCenterY * viewState.Zoom
    clampedPanX, clampedPanY

  let computeInitialCFGViewState (cfg: VisGraph) model =
    let vs = cfg.Vertices
    if vs.Length = 0 then
      CFGViewState.init
    else
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
      let graphWidth = maxX - minX
      let graphHeight = maxY - minY
      let rootCenterX = topNode.VData.Coordinate.X + topNode.VData.Width / 2.0
      let rootCenterY = topNode.VData.Coordinate.Y + topNode.VData.Height / 2.0
      let viewportWidth, viewportHeight = model.CFGViewportSize
      let minZoomW = min ((viewportWidth * 0.9) / graphWidth) 1.0
      let minZoomH = min ((viewportHeight * 0.9) / graphHeight) 1.0
      let minZoom = min minZoomW minZoomH
      { CFGViewState.init with
          PanX = viewportWidth / 2.0 - rootCenterX
          PanY = viewportHeight / 2.0 - rootCenterY
          MinimumZoom = minZoom
          GraphWidth = graphWidth
          GraphHeight = graphHeight
          GraphMinX = minX
          GraphMinY = minY
          GraphMaxX = maxX
          GraphMaxY = maxY }

  let update (msg: Message) (model: Model) =
    let applyThemeVariant mode =
      match mode with
      | Builtin Light -> this.RequestedThemeVariant <- ThemeVariant.Light
      | Builtin Dark -> this.RequestedThemeVariant <- ThemeVariant.Dark
      | Custom _ -> ()
    match msg with
    | OpenBinary filePath ->
      if String.IsNullOrWhiteSpace filePath then
        model, Elmish.Cmd.none
      else
        let displayName = Path.GetFileName filePath
        let updatedModel =
          { model with
              LoadingBinaryPath = Some filePath
              StatusMessage = $"Loading {displayName} ." }
        updatedModel, startLoadWorkflowCmd filePath
    | OpenBinaryCompleted filePath ->
      if model.LoadingBinaryPath = Some filePath then
        let statusFileName = Path.GetFileName filePath
        let brew = arbiter.GetBinaryBrew filePath |> Option.get
        let functions =
          brew.Functions.Sequence
          |> Seq.filter (fun fn -> not fn.IsExternal)
          |> Seq.map FunctionItem.ofFunction
          |> Seq.toList
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
            StatusMessage = statusFileName },
        Elmish.Cmd.none
      else
        model, Elmish.Cmd.none
    | OpenBinaryFailed(filePath, reason) ->
      if model.LoadingBinaryPath = Some filePath then
        { model with
            LoadingBinaryPath = None
            StatusMessage = $"Failed to load binary: {reason}" },
        Elmish.Cmd.none
      else
        model, Elmish.Cmd.none
    | CloseBinary ->
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
          StatusMessage = "Workspace closed. Open a file to start exploring." },
      Elmish.Cmd.none
    | OpenCFGTab fnItem ->
      let visibleTabs = getAllVisibleTabs model
      let tab = Tab.ofFunctionItem fnItem
      match tryFindTab visibleTabs tab.ID with
      | Some tab ->
        startLoadIfNeeded tab
          { model with
              ActiveTab = Some tab
              StatusMessage = $"Switched to tab: {tab.Title}" }
      | None ->
        startLoadIfNeeded tab
          { model with
              ActiveTab = Some tab
              PreviewTab = Some tab
              StatusMessage = $"Opened tab: {tab.Title}" }
    | PinCFGTab fnItem ->
      let tab = Tab.ofFunctionItem fnItem
      let isPreview = model.PreviewTab |> Option.exists (fun t -> t.ID = tab.ID)
      let newOpenTabs, tab =
        match tryFindTab model.OpenTabs tab.ID, model.PreviewTab with
        | Some tab, _ -> model.OpenTabs, tab
        | None, Some tab -> tab :: model.OpenTabs, tab
        | None, None -> tab :: model.OpenTabs, tab
      startLoadIfNeeded tab
        { model with
            ActiveTab = Some tab
            OpenTabs = newOpenTabs
            PreviewTab = if isPreview then None else model.PreviewTab
            StatusMessage = $"Pinned tab: {tab.Title}" }
    | CloseTab tabID ->
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
          DraggingTab = dragging
          StatusMessage = $"Closed tab: {tabID}" },
      Elmish.Cmd.none
    | SwitchTab tabID ->
      let visibleTabs = getAllVisibleTabs model
      match tryFindTab visibleTabs tabID with
      | Some tab ->
        { model with
            ActiveTab = Some tab
            StatusMessage = $"Switched to tab: {tab.Title}" }, Elmish.Cmd.none
      | None ->
        model, Elmish.Cmd.none
    | StartTabDrag tabID ->
      let visibleTabs = getAllVisibleTabs model
      match tryFindTab visibleTabs tabID with
      | Some tab -> { model with DraggingTab = Some tab }, Elmish.Cmd.none
      | None -> model, Elmish.Cmd.none
    | ReorderTab(draggedTabID, targetTabID) ->
      match reorderOpenTabs model draggedTabID targetTabID with
      | Some(reorderedTabs, draggedTab) ->
        { model with
            OpenTabs = reorderedTabs
            DraggingTab = Some draggedTab },
        Elmish.Cmd.none
      | None ->
        model, Elmish.Cmd.none
    | EndTabDrag ->
      if model.DraggingTab.IsSome then
        { model with DraggingTab = None }, Elmish.Cmd.none
      else
        model, Elmish.Cmd.none
    | RegisterCustomTheme(themeId, theme) ->
      let customThemes = model.CustomThemes |> Map.add themeId theme
      let currentTheme =
        match model.ThemeMode with
        | Custom selected when selected = themeId -> theme
        | _ -> model.Theme
      { model with
          CustomThemes = customThemes
          Theme = currentTheme
          StatusMessage = $"Registered theme: {theme.Name}" },
      Elmish.Cmd.none
    | SetThemeMode mode ->
      applyThemeVariant mode
      let theme = Theme.resolve mode model.CustomThemes
      { model with
          ThemeMode = mode
          Theme = theme
          StatusMessage = $"Theme changed: {Theme.modeName mode}" },
      Elmish.Cmd.none
    | UpdateFunctionFilter text ->
      { model with FunctionFilter = text }, Elmish.Cmd.none
    | SelectWorkspacePanel panel ->
      { model with WorkspacePanel = panel }, Elmish.Cmd.none
    | LoadCFGCompleted(tabID, cfg) ->
      let visibleTabs = getAllVisibleTabs model
      match tryFindTab visibleTabs tabID with
      | Some tab ->
        let viewState = computeInitialCFGViewState cfg model
        let tab = mapCFGTabState (Loaded(cfg, viewState)) tab
        let opens = model.OpenTabs |> List.map (replaceTabByID tabID tab)
        let preview = model.PreviewTab |> Option.map (replaceTabByID tabID tab)
        let active = model.ActiveTab |> Option.map (replaceTabByID tabID tab)
        { model with
            OpenTabs = opens
            PreviewTab = preview
            ActiveTab = active
            StatusMessage = $"CFG loaded for: {tab.Title}" },
        Elmish.Cmd.none
      | None ->
        model, Elmish.Cmd.none
    | LoadCFGFailed(tabID, reason) ->
      let visibleTabs = getAllVisibleTabs model
      match tryFindTab visibleTabs tabID with
      | Some tab ->
        let tab = mapCFGTabState NotLoaded tab
        let opens = model.OpenTabs |> List.map (replaceTabByID tabID tab)
        let preview = model.PreviewTab |> Option.map (replaceTabByID tabID tab)
        let active = model.ActiveTab |> Option.map (replaceTabByID tabID tab)
        { model with
            OpenTabs = opens
            PreviewTab = preview
            ActiveTab = active
            StatusMessage = $"CFG load failed: {reason}" },
        Elmish.Cmd.none
      | None ->
        model, Elmish.Cmd.none
    | SetCFGZoom(delta, mouseX, mouseY) ->
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
        let opens = model.OpenTabs |> List.map (replaceTabByID tab.ID tab)
        let preview = model.PreviewTab |> Option.map (replaceTabByID tab.ID tab)
        let active = model.ActiveTab |> Option.map (replaceTabByID tab.ID tab)
        { model with
            OpenTabs = opens
            PreviewTab = preview
            ActiveTab = active }, Elmish.Cmd.none
      | _ ->
        model, Elmish.Cmd.none
    | StartCFGPan(x, y) ->
      { model with
          CFGIsPanning = true
          CFGPanPointer = Some(x, y) }, Elmish.Cmd.none
    | MoveCFGPan(x, y) ->
      match model.CFGIsPanning, model.CFGPanPointer, model.ActiveTab with
      | true, Some(prevX, prevY), Some tab ->
        let update viewState =
          let newPanX = viewState.PanX + x - prevX
          let newPanY = viewState.PanY + y - prevY
          let clampedPanX, clampedPanY =
            clampPanToGraphBounds newPanX newPanY viewState model
          { viewState with
              PanX = clampedPanX
              PanY = clampedPanY }
        let tab = updateCFGViewState tab update
        let opens = model.OpenTabs |> List.map (replaceTabByID tab.ID tab)
        let preview = model.PreviewTab |> Option.map (replaceTabByID tab.ID tab)
        let active = model.ActiveTab |> Option.map (replaceTabByID tab.ID tab)
        { model with
            OpenTabs = opens
            PreviewTab = preview
            ActiveTab = active
            CFGPanPointer = Some(x, y) }, Elmish.Cmd.none
      | _ ->
        model, Elmish.Cmd.none
    | EndCFGPan ->
      { model with
          CFGIsPanning = false
          CFGPanPointer = None }, Elmish.Cmd.none
    | UpdateCFGViewportSize(width, height) ->
      match model.ActiveTab with
      | Some tab when width > 0.0 && height > 0.0 ->
        let currentWidth, currentHeight = model.CFGViewportSize
        let deltaX = width / 2.0 - currentWidth / 2.0
        let deltaY = height / 2.0 - currentHeight / 2.0
        let update viewState =
          { viewState with
              PanX = viewState.PanX + deltaX
              PanY = viewState.PanY + deltaY }
        let tab = updateCFGViewState tab update
        let opens = model.OpenTabs |> List.map (replaceTabByID tab.ID tab)
        let preview = model.PreviewTab |> Option.map (replaceTabByID tab.ID tab)
        let active = model.ActiveTab |> Option.map (replaceTabByID tab.ID tab)
        { model with
            OpenTabs = opens
            PreviewTab = preview
            ActiveTab = active
            CFGViewportSize = (width, height) }, Elmish.Cmd.none
      | _ ->
        model, Elmish.Cmd.none
    | UpdateStatus msg ->
      { model with StatusMessage = msg }, Elmish.Cmd.none
    | ExitApplication ->
      this.Close()
      model, Elmish.Cmd.none

  do
    base.Title <- "BinExplore"
    base.MinWidth <- 800.0
    base.MinHeight <- 600.0
    let screen = this.Screens.Primary
    if screen <> null then
      base.Width <- float screen.WorkingArea.Width * 0.8
      base.Height <- float screen.WorkingArea.Height * 0.8
      base.WindowStartupLocation <- WindowStartupLocation.CenterScreen
    else
      ()
    Elmish.Program.mkProgram init update MainView.view
    |> Elmish.Program.withHost this
    |> Elmish.Program.run
