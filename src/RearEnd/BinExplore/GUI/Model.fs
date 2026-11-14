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

open B2R2.RearEnd.BinExplore

/// Represents the state of the main view.
type Model =
  { /// Analysis and navigation state keyed by binary identity.
    Binaries: Map<BinaryID, BinaryModel>
    /// Opened binaries in their original loading order.
    BinaryOrder: BinaryID list
    /// Binary currently shown in the navigation panels.
    SelectedBinaryID: BinaryID option
    /// Path of the binary currently loading.
    LoadingBinaryPath: string option
    /// Root of the editor pane tree.
    RootPane: Pane
    /// Currently focused leaf pane.
    FocusedPaneID: PaneID option
    /// Tab currently being dragged across panes/tabs, if any.
    DraggingTab: TabDragState option
    /// Registered custom themes.
    CustomThemes: Map<ThemeId, Theme>
    /// Current theme mode.
    ThemeMode: ThemeMode
    /// Current UI theme.
    Theme: Theme
    /// Flag indicating whether the user is currently panning in the CFG view.
    CFGIsPanning: bool
    /// Initial pointer position recorded when the user presses in the CFG view.
    CFGPressedPointer: (float * float) option
    /// Last pointer position used for CFG panning.
    CFGPanPointer: (float * float) option
    /// Transient status message overriding the selected binary's status.
    StatusMessage: string option }

and TabDragState =
  { SourcePaneID: PaneID
    Tab: Tab }

module Model =
  let tryGetSelectedBinary (model: Model) =
    model.SelectedBinaryID
    |> Option.bind (fun id -> Map.tryFind id model.Binaries)

  let getSelectedValue fallback project model =
    tryGetSelectedBinary model
    |> Option.map project
    |> Option.defaultValue fallback

  let mapBinary id update (model: Model) =
    match Map.tryFind id model.Binaries with
    | Some binary ->
      { model with Binaries = Map.add id (update binary) model.Binaries }
    | None ->
      model

  let mapSelectedBinary update model =
    match model.SelectedBinaryID with
    | Some id -> mapBinary id update model
    | None -> model

  let rec tryFindFirstLeaf = function
    | Leaf(paneID, paneState) ->
      Some(paneID, paneState)
    | Split(_, _, first, second) ->
      match tryFindFirstLeaf first with
      | Some _ as found -> found
      | None -> tryFindFirstLeaf second

  let getDefaultPaneID model =
    match tryFindFirstLeaf model.RootPane with
    | Some(paneID, _) -> paneID
    | None -> model.RootPane.ID

  let getFocusedPaneID model =
    match model.FocusedPaneID with
    | Some paneID -> paneID
    | None -> getDefaultPaneID model

  let tryGetFocusedPane model =
    match model.FocusedPaneID with
    | Some paneID -> Pane.tryFindLeaf paneID model.RootPane
    | None -> None

  let getFocusedPaneOrDefault model =
    match tryGetFocusedPane model with
    | Some pane ->
      pane
    | None ->
      match tryFindFirstLeaf model.RootPane with
      | Some(_, pane) -> pane
      | None -> failwith "No leaf pane exists in the model."

  let tryGetFocusedActiveTab model =
    tryGetFocusedPane model
    |> Option.bind (fun pane -> pane.ActiveTab)

  let rec private mapPaneState paneID fn = function
    | Leaf(id, paneState) when id = paneID ->
      Leaf(id, fn paneState)
    | Leaf _ as leaf ->
      leaf
    | Split(id, axis, fst, snd) ->
      Split(id, axis, mapPaneState paneID fn fst, mapPaneState paneID fn snd)

  let mapPaneByID paneID fn model =
    { model with RootPane = mapPaneState paneID fn model.RootPane }

  let mapFocusedPane fn model =
    let paneID = getFocusedPaneID model
    mapPaneByID paneID fn { model with FocusedPaneID = Some paneID }

  let getVisibleTabsFromPane pane =
    match pane.PreviewTab with
    | Some preview -> preview :: pane.OpenTabs
    | None -> pane.OpenTabs

  let tryFindVisibleTab model tabID =
    match tryGetFocusedPane model with
    | Some pane ->
      getVisibleTabsFromPane pane
      |> List.tryFind (fun tab -> tab.ID = tabID)
    | None ->
      None

  let tryFindTab model tabID =
    let rec findAllPane = function
      | Leaf(paneID, paneState) ->
        match paneState.PreviewTab with
        | Some preview when preview.ID = tabID ->
          Some(paneID, paneState, preview, true)
        | _ ->
          paneState.OpenTabs
          |> List.tryFind (fun tab -> tab.ID = tabID)
          |> Option.map (fun tab -> paneID, paneState, tab, false)
      | Split(_, _, first, second) ->
        match findAllPane first with
        | Some result -> Some result
        | None -> findAllPane second
    findAllPane model.RootPane

type Model with
  member this.SelectedBinary = Model.tryGetSelectedBinary this

  member this.LoadedBinary =
    this.SelectedBinary |> Option.map (fun binary -> binary.Info.Path)

  member this.Functions =
    Model.getSelectedValue [] (fun binary -> binary.Functions) this

  member this.FunctionFilter =
    Model.getSelectedValue "" (fun binary -> binary.FunctionFilter) this

  member this.Sections =
    Model.getSelectedValue [] (fun binary -> binary.Sections) this

  member this.WorkspacePanel =
    Model.getSelectedValue FunctionPanel (fun b -> b.WorkspacePanel) this

  member this.LinearDocument =
    Model.getSelectedValue None (fun binary -> binary.LinearDocument) this

  member this.LinearViewState =
    Model.getSelectedValue None (fun binary -> binary.LinearViewState) this

  member this.SyncEnabled =
    Model.getSelectedValue true (fun binary -> binary.SyncEnabled) this

  member this.Hexdump =
    Model.getSelectedValue None (fun binary -> binary.Hexdump) this

  member this.OffsetSnapshot =
    Model.getSelectedValue OffsetSnapshot.empty (fun b -> b.OffsetSnapshot) this

  member this.StatusBarState =
    match this.StatusMessage with
    | Some message ->
      MessageOnly message
    | None ->
      Model.getSelectedValue EmptyStatus (fun b -> b.StatusBarState) this

  member this.ActiveTab = (Model.getFocusedPaneOrDefault this).ActiveTab

  member this.OpenTabs = (Model.getFocusedPaneOrDefault this).OpenTabs

  member this.PreviewTab = (Model.getFocusedPaneOrDefault this).PreviewTab

  member this.ContentViewportSize =
    (Model.getFocusedPaneOrDefault this).ContentViewportSize
