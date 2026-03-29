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
    { LoadedBinary = None
      LoadingBinaryPath = None
      Functions = []
      FunctionFilter = ""
      Sections = []
      ActiveTab = None
      OpenTabs = []
      PreviewTab = None
      CustomThemes = customThemes
      ThemeMode = themeMode
      Theme = Theme.resolve themeMode customThemes
      DraggingTab = None
      WorkspacePanel = FunctionPanel
      Hexdump = HexdumpState.empty
      CFGIsPanning = false
      CFGPressedPointer = None
      CFGPanPointer = None
      CFGViewportSize = (0.0, 0.0)
      StatusBarState = EmptyStatus }, Elmish.Cmd.none

  let update (msg: Message) (model: Model) =
    match msg with
    | OpenBinary filePath ->
      Update.openBinary arbiter model filePath
    | OpenBinaryCompleted filePath ->
      Update.openBinaryCompleted arbiter model filePath
    | OpenBinaryFailed(filePath, reason) ->
      Update.openBinaryFailed model filePath reason
    | CloseWorkspace ->
      Update.closeWorkspace arbiter model
    | OpenCFGTab fnItem ->
      Update.openCFGTab arbiter model fnItem
    | PinCFGTab fnItem ->
      Update.pinCFGTab arbiter model fnItem
    | CloseTab tabID ->
      Update.closeTab model tabID
    | SwitchTab tabID ->
      Update.switchTab model tabID
    | StartTabDrag tabID ->
      Update.startTabDrag model tabID
    | ReorderTab(draggedTabID, targetTabID) ->
      Update.reorderTab model draggedTabID targetTabID
    | EndTabDrag ->
      Update.endTabDrag model
    | RegisterCustomTheme(themeId, theme) ->
      Update.registerCustomTheme model themeId theme
    | SetThemeMode mode ->
      Update.setThemeMode this model mode
    | UpdateFunctionFilter text ->
      Update.updateFunctionFilter model text
    | SelectWorkspacePanel panel ->
      Update.selectWorkspacePanel arbiter model panel
    | LoadCFGCompleted(tabID, cfgKind, cfg) ->
      Update.loadCFGCompleted model tabID cfgKind cfg
    | LoadCFGFailed(tabID, _reason) ->
      Update.loadCFGFailed model tabID _reason
    | SetCFGZoom(delta, mouseX, mouseY) ->
      Update.setCFGZoom model delta mouseX mouseY
    | StartCFGPan(x, y) ->
      Update.startCFGPan model x y
    | MoveCFGPan(x, y, space) ->
      Update.moveCFGPan model x y space
    | EndCFGPan ->
      Update.endCFGPan model
    | JumpCFGPan(gx, gy) ->
      Update.jumpCFGPan model gx gy
    | SelectCFGToken(nodeID, lineIdx, wordIdx) ->
      Update.selectCFGToken model nodeID lineIdx wordIdx
    | SetHoveredCFGEdge edgeID ->
      Update.setHoveredCFGEdge model edgeID
    | UpdateCFGViewportSize(width, height) ->
      Update.updateCFGViewportSize model width height
    | ChangeCFGKind kind ->
      Update.changeCFGKind arbiter model kind
    | ToggleMinimap(tabID, activate) ->
      Update.toggleMinimap model tabID activate
    | HexdumpMsg msg ->
      Update.updateHexdump model msg
    | UpdateStatus msg ->
      Update.updateStatus model msg
    | ExitApplication ->
      this.Close()
      model, Elmish.Cmd.none

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
    Elmish.Program.mkProgram init update MainView.view
    |> Elmish.Program.withHost this
    |> Elmish.Program.run
