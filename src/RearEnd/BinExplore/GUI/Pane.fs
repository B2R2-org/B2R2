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

/// Represents a pane in the UI.
type Pane =
  | Leaf of id: PaneID * PaneState
  | Split of id: PaneID * axis: SplitAxis * first: Pane * second: Pane
with
  member this.ID with get() =
    match this with
    | Leaf(id, _) -> id
    | Split(id, _, _, _) -> id

and PaneID = System.Guid

/// Represents the state of a pane in the UI, which can contain multiple tabs
/// and a preview tab.
and PaneState =
  { /// Currently active (selected) tab in this pane.
    ActiveTab: Tab option
    /// List of currently open tabs in this pane, excluding the preview tab.
    OpenTabs: Tab list
    /// Currently open preview tab in this pane, if any.
    PreviewTab: Tab option
    /// Width and height of this pane's content viewport.
    ContentViewportSize: float * float }

/// Represents the axis along which a pane is split.
and SplitAxis =
  | TopBottom
  | LeftRight

/// Represents the placement of a new pane relative to an existing pane.
and PanePlacement =
  | LeftOf of PaneID
  | RightOf of PaneID
  | Above of PaneID
  | Below of PaneID

[<RequireQualifiedAccess>]
module Pane =
  let createLeaf () =
    let paneID = System.Guid.NewGuid()
    let emptyState =
      { ActiveTab = None
        OpenTabs = []
        PreviewTab = None
        ContentViewportSize = (0.0, 0.0) }
    Leaf(paneID, emptyState)

  let rec tryFindLeaf paneID = function
    | Leaf(id, state) when id = paneID -> Some state
    | Leaf _ -> None
    | Split(_, _, first, second) ->
      match tryFindLeaf paneID first with
      | Some state -> Some state
      | None -> tryFindLeaf paneID second

  let rec tryFindLeafByTabID tabID = function
    | Leaf(id, state) ->
      let visibleTabs =
        match state.PreviewTab with
        | Some preview -> preview :: state.OpenTabs
        | None -> state.OpenTabs
      if visibleTabs |> List.exists (fun tab -> tab.ID = tabID) then Some id
      else None
    | Split(_, _, first, second) ->
      match tryFindLeafByTabID tabID first with
      | Some id -> Some id
      | None -> tryFindLeafByTabID tabID second