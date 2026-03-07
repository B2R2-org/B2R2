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
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.RearEnd.BinExplore

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
      Functions = []
      FunctionFilter = ""
      ActiveTab = None
      OpenTabs = []
      PreviewTab = None
      CustomThemes = customThemes
      ThemeMode = themeMode
      Theme = Theme.resolve themeMode customThemes
      DraggingTab = None
      LoadingBinaryPath = None
      StatusMessage = WelcomeMessage }, Elmish.Cmd.none

  let loadBinaryAsync (filePath: string) =
    async {
      return arbiter.AddBinary filePath
    }

  let cmdOfSub (sub: Elmish.Dispatch<Message> -> unit): Elmish.Cmd<Message> =
    [ sub ]

  let startLoadWorkflowCmd (filePath: string) =
    cmdOfSub (fun dispatch ->
      let displayName = Path.GetFileName filePath
      let dispatchOnUi msg =
        Dispatcher.UIThread.Post(fun () -> dispatch msg)
      let mutable running = true
      let dots = [| "."; ".."; "..." |]
      let animate =
        async {
          let mutable i = 0
          while running do
            dispatchOnUi
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
            dispatchOnUi (OpenBinaryCompleted filePath)
          | Error reason ->
            running <- false
            dispatchOnUi (OpenBinaryFailed(filePath, reason))
        with ex ->
          running <- false
          dispatchOnUi (OpenBinaryFailed(filePath, ex.Message))
      }))

  let reorderOpenTabs model draggedTab targetTab =
    if draggedTab <> targetTab
        && List.contains draggedTab model.OpenTabs
        && List.contains targetTab model.OpenTabs then
      let draggedIndex = model.OpenTabs |> List.findIndex ((=) draggedTab)
      let targetIndex = model.OpenTabs |> List.findIndex ((=) targetTab)
      let openTabsWithoutDragged =
        model.OpenTabs |> List.filter ((<>) draggedTab)
      let targetIndexInNew =
        openTabsWithoutDragged |> List.findIndex ((=) targetTab)
      let insertIndex =
        if draggedIndex < targetIndex then targetIndexInNew + 1
        else targetIndexInNew
      openTabsWithoutDragged |> List.insertAt insertIndex draggedTab |> Some
    else
      None

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
          |> Seq.map FunctionItem.ofFunction
          |> Seq.toList
        { model with
            LoadedBinary = Some filePath
            Functions = functions
            FunctionFilter = ""
            ActiveTab = None
            OpenTabs = []
            PreviewTab = None
            DraggingTab = None
            LoadingBinaryPath = None
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
          Functions = []
          FunctionFilter = ""
          ActiveTab = None
          OpenTabs = []
          PreviewTab = None
          DraggingTab = None
          LoadingBinaryPath = None
          StatusMessage = "Workspace closed. Open a file to start exploring." },
      Elmish.Cmd.none
    | OpenTab tab ->
      if List.contains tab model.OpenTabs then
        { model with
            ActiveTab = Some tab
            StatusMessage = $"Switched to tab: {tab.Title}" },
        Elmish.Cmd.none
      else
        { model with
            ActiveTab = Some tab
            PreviewTab = Some tab
            StatusMessage = $"Opened tab: {tab.Title}" },
        Elmish.Cmd.none
    | PinTab tab ->
      let isPreview = model.PreviewTab = Some tab
      let newOpenTabs =
        if List.contains tab model.OpenTabs then model.OpenTabs
        else tab :: model.OpenTabs
      { model with
          ActiveTab = Some tab
          OpenTabs = newOpenTabs
          PreviewTab = if isPreview then None else model.PreviewTab
          StatusMessage = $"Pinned tab: {tab.Title}" },
      Elmish.Cmd.none
    | CloseTab tab ->
      let newOpenTabs = model.OpenTabs |> List.filter ((<>) tab)
      let isPreview = model.PreviewTab = Some tab
      let newPreviewTab = if isPreview then None else model.PreviewTab
      let newDraggingTab =
        if model.DraggingTab = Some tab then None
        else model.DraggingTab
      let newActiveFunction =
        if model.ActiveTab = Some tab then
          newOpenTabs |> List.tryHead |> Option.orElse newPreviewTab
        else
          model.ActiveTab
      { model with
          ActiveTab = newActiveFunction
          OpenTabs = newOpenTabs
          PreviewTab = newPreviewTab
          DraggingTab = newDraggingTab
          StatusMessage = $"Closed tab: {tab.Title}" },
      Elmish.Cmd.none
    | SwitchTab tab ->
      { model with
          ActiveTab = Some tab
          StatusMessage = $"Switched to tab: {tab.Title}" },
      Elmish.Cmd.none
    | StartTabDrag tab ->
      if List.contains tab model.OpenTabs then
        { model with DraggingTab = Some tab }, Elmish.Cmd.none
      else
        model, Elmish.Cmd.none
    | ReorderTab(draggedTab, targetTab) ->
      match reorderOpenTabs model draggedTab targetTab with
      | Some reorderedTabs ->
        { model with
            OpenTabs = reorderedTabs
            DraggingTab = Some draggedTab },
        Elmish.Cmd.none
      | None -> model, Elmish.Cmd.none
    | EndTabDrag ->
      if model.DraggingTab.IsSome then
        { model with DraggingTab = None }, Elmish.Cmd.none
      else
        model, Elmish.Cmd.none
    | RegisterCustomTheme(themeId, theme) ->
      let customThemes = model.CustomThemes |> Map.add themeId theme
      let currentTheme =
        match model.ThemeMode with
        | ThemeMode.Custom selected when selected = themeId -> theme
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
