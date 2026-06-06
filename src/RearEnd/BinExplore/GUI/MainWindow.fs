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
open Avalonia.FuncUI
open Avalonia.FuncUI.Hosts
open Avalonia.Controls
open Avalonia.Platform
open B2R2
open B2R2.BinIR
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.RearEnd.BinExplore

type MainWindow<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                                and 'FnCtx: (new: unit -> 'FnCtx)
                                and 'GlCtx: (new: unit -> 'GlCtx)>
  public(arbiter: Arbiter<'FnCtx, 'GlCtx>, useDarkTheme) as this =
  inherit HostWindow()

  let init () =
    let themeMode = if useDarkTheme then Builtin Dark else Builtin Light
    let customThemes = Map.empty
    let rootPane = Pane.createLeaf ()
    { LoadedBinary = None
      LoadingBinaryPath = None
      Functions = []
      FunctionFilter = ""
      Sections = []
      RootPane = rootPane
      FocusedPaneID = Some rootPane.ID
      DraggingTab = None
      CustomThemes = customThemes
      ThemeMode = themeMode
      Theme = Theme.resolve themeMode customThemes
      WorkspacePanel = FunctionPanel
      CFGIsPanning = false
      CFGPressedPointer = None
      CFGPanPointer = None
      LinearDocument = None
      LinearViewState = None
      SyncEnabled = true
      Hexdump = None
      OffsetSnapshot = OffsetSnapshot.empty
      StatusBarState = EmptyStatus }, Elmish.Cmd.none

  let update (msg: Message) (model: Model) =
    match msg with
    | OpenBinary filePath ->
      Update.openBinary arbiter model filePath
    | OpenBinaryCompleted filePath ->
      Update.openBinaryCompleted arbiter model filePath
    | OpenBinaryFailed(filePath, reason) ->
      Update.openBinaryFailed model filePath reason
    | LinearAnalysisCompleted(filePath, doc, state) ->
      Update.linearAnalysisCompleted arbiter model filePath doc state
    | LinearAnalysisFailed(filePath, reason) ->
      Update.linearAnalysisFailed model filePath reason
    | CloseWorkspace ->
      Update.closeWorkspace arbiter model
    | OpenCFGTab fnItem ->
      Update.openCFGTab arbiter model fnItem
    | OpenHexdumpTab ->
      Update.openHexdumpTab arbiter model
    | OpenLinearViewTab ->
      Update.openLinearViewTab arbiter model
    | PinCFGTab fnItem ->
      Update.pinCFGTab arbiter model fnItem
    | FocusPane paneID ->
      Update.focusPane arbiter model paneID
    | CloseTab(paneID, tabID) ->
      Update.closeTab arbiter model paneID tabID
    | SwitchTab(paneID, tabID) ->
      Update.switchTab arbiter model paneID tabID
    | StartTabDrag(paneID, tabID) ->
      Update.startTabDrag model paneID tabID
    | ReorderTab(paneID, draggedTabID, targetTabID) ->
      Update.reorderTab model paneID draggedTabID targetTabID
    | MoveTabToPane(sourcePaneID, targetPaneID, tabID) ->
      Update.moveTabToPane arbiter model sourcePaneID targetPaneID tabID
    | MoveTabRelative(placement, tabID) ->
      Update.moveTabRelative arbiter model placement tabID
    | EndTabDrag ->
      Update.endTabDrag model
    | UpdateViewportSize(paneID, width, height) ->
      Update.updateViewportSize arbiter model paneID width height
    | CFGLoadMsg cfgMsg ->
      Update.updateCFGLoad arbiter model cfgMsg
    | CFGPaneMsg cfgMsg ->
      Update.updateCFG arbiter model cfgMsg
    | LinearPaneMsg msg ->
      Update.updateLinear arbiter model msg
    | HexdumpPaneMsg msg ->
      Update.updateHexdump arbiter model msg
    | SetTopFileOffset offset ->
      Update.setTopFileOffset arbiter model offset
    | RegisterCustomTheme(themeId, theme) ->
      Update.registerCustomTheme model themeId theme
    | SetThemeMode mode ->
      Update.setThemeMode this arbiter model mode
    | UpdateFunctionFilter text ->
      Update.updateFunctionFilter model text
    | SelectWorkspacePanel panel ->
      Update.selectWorkspacePanel arbiter model panel
    | SetSyncEnabled enabled ->
      Update.setSyncEnabled arbiter model enabled
    | UpdateStatusMsg msg ->
      Update.updateStatusMsg model msg
    | UpdateStatusOffsetCtx(sOff, eOff, sects) ->
      Update.updateStatusOffsetCtx model sOff eOff sects
    | ExitApplication ->
      this.Close()
      model, Elmish.Cmd.none

  let tokenContextProvider =
    { new ITokenContextProvider with
        member _.GetInstructionInfo addr =
          match arbiter.GetBinaryBrew() with
          | Ok brew ->
            let liftingUnit = brew.BinHandle.NewLiftingUnit()
            let ins = liftingUnit.ParseInstruction addr
            let stmts = liftingUnit.LiftInstruction ins
            let facts = LowUIR.StaticValueFacts.ofStmts ins.Address stmts
            let reads = facts.MemReadAddrs |> Array.map (fun a -> $"{a:X}")
            let writes = facts.MemWriteAddrs |> Array.map (fun a -> $"{a:X}")
            let defs =
              facts.RegConstDefs
              |> Array.map (fun (r, v) ->
                brew.BinHandle.RegisterFactory.GetRegisterName r,
                $"{v.ToValueString():X}")
            {| Stmts = stmts |> Array.map PrettyPrinter.ToString
               ReadAddrs = reads
               WriteAddrs = writes
               ConstDefs = defs
               PCTargets = facts.PCDefs |}
          | Error _ ->
            {| Stmts = [||]
               ReadAddrs = [||]
               WriteAddrs = [||]
               ConstDefs = [||]
               PCTargets = [||] |}

        member _.GetCallers funcAddr =
          match arbiter.GetBinaryBrew() with
          | Ok brew -> brew.Functions[funcAddr].Callers |> Seq.toArray
          | Error _ -> [||]

        member _.IsAddressInFunction(fnAddr, queryAddr) =
          match arbiter.GetBinaryBrew() with
          | Ok brew ->
            brew.Functions[fnAddr].CFG.Vertices
            |> Array.exists (fun v ->
              not v.VData.Internals.IsAbstract &&
              v.VData.Internals.Range.IsIncluding queryAddr)
          | Error _ ->
            false

        member _.TryGetSectionName addr =
          match arbiter.GetBinaryBrew() with
          | Ok brew ->
            brew.BinHandle.File.TryFindSectionName addr |> Result.toOption
          | Error _ ->
            None }

  do
    base.Title <- "BinExplore"
    let iconUri = Uri "avares://B2R2.RearEnd.BinExplore/Assets/b2r2.ico"
    use iconStream = AssetLoader.Open iconUri
    base.Icon <- WindowIcon iconStream
    base.MinWidth <- 800.0
    base.MinHeight <- 600.0
    let screen = this.Screens.Primary
    if screen <> null then
      base.Width <- float screen.WorkingArea.Width / screen.Scaling * 0.8
      base.Height <- float screen.WorkingArea.Height / screen.Scaling * 0.8
      base.WindowStartupLocation <- WindowStartupLocation.CenterScreen
    else
      ()
    Elmish.Program.mkProgram init update (MainView.view tokenContextProvider)
    |> Elmish.Program.withHost this
    |> Elmish.Program.run
