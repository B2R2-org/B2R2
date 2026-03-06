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

open Avalonia.FuncUI
open Avalonia.FuncUI.Hosts
open Avalonia.Controls

type MainWindow(arbiter) as this =
  inherit HostWindow()

  let [<Literal>] WelcomeMessage = "Welcome to BinExplore!"

  let init arbiter =
    { LoadedBinary = None
      Functions = []
      FunctionFilter = ""
      ActiveFunction = None
      OpenTabs = []
      PreviewTab = None
      Theme = Theme.defaultTheme
      DraggingTab = None
      StatusMessage = WelcomeMessage }

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
    match msg with
    | OpenBinary _path ->
      { model with
          LoadedBinary = Some "sample_binary.exe"
          Functions = [
            "main"
            "foo"
            "bar"
            "baz"
          ]
          FunctionFilter = ""
          StatusMessage = "Loaded binary: sample_binary.exe" }
    | CloseBinary ->
      { model with
          LoadedBinary = None
          Functions = []
          FunctionFilter = ""
          ActiveFunction = None
          OpenTabs = []
          PreviewTab = None
          DraggingTab = None
          StatusMessage = "Workspace closed. Open a file to start exploring." }
    | OpenTab funcName ->
      if List.contains funcName model.OpenTabs then
        { model with
            ActiveFunction = Some funcName
            StatusMessage = $"Switched to tab: {funcName}" }
      else
        { model with
            ActiveFunction = Some funcName
            PreviewTab = Some funcName
            StatusMessage = $"Opened tab: {funcName}" }
    | PinTab funcName ->
      let isPreview = model.PreviewTab = Some funcName
      let newOpenTabs =
        if List.contains funcName model.OpenTabs then model.OpenTabs
        else funcName :: model.OpenTabs
      { model with
          ActiveFunction = Some funcName
          OpenTabs = newOpenTabs
          PreviewTab = if isPreview then None else model.PreviewTab
          StatusMessage = $"Pinned tab: {funcName}" }
    | CloseTab funcName ->
      let newOpenTabs = model.OpenTabs |> List.filter ((<>) funcName)
      let isPreview = model.PreviewTab = Some funcName
      let newPreviewTab = if isPreview then None else model.PreviewTab
      let newDraggingTab =
        if model.DraggingTab = Some funcName then None
        else model.DraggingTab
      let newActiveFunction =
        if model.ActiveFunction = Some funcName then
          newOpenTabs |> List.tryHead |> Option.orElse newPreviewTab
        else
          model.ActiveFunction
      { model with
          ActiveFunction = newActiveFunction
          OpenTabs = newOpenTabs
          PreviewTab = newPreviewTab
          DraggingTab = newDraggingTab
          StatusMessage = $"Closed tab: {funcName}" }
    | SwitchTab funcName ->
      { model with
          ActiveFunction = Some funcName
          StatusMessage = $"Switched to tab: {funcName}" }
    | StartTabDrag funcName ->
      if List.contains funcName model.OpenTabs then
        { model with DraggingTab = Some funcName }
      else
        model
    | ReorderTab(draggedTab, targetTab) ->
      match reorderOpenTabs model draggedTab targetTab with
      | Some reorderedTabs ->
        { model with
            OpenTabs = reorderedTabs
            DraggingTab = Some draggedTab }
      | None -> model
    | EndTabDrag ->
      if model.DraggingTab.IsSome then
        { model with DraggingTab = None }
      else
        model
    | UpdateFunctionFilter text ->
      { model with FunctionFilter = text }
    | UpdateStatus msg ->
      { model with StatusMessage = msg }
    | ExitApplication ->
      this.Close()
      model

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
    Elmish.Program.mkSimple (fun () -> init arbiter) update MainView.view
    |> Elmish.Program.withHost this
    |> Elmish.Program.run
