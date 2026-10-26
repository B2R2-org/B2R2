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

namespace B2R2.RearEnd.Transformer

open System

[<RequireQualifiedAccess>]
type TuiInputResult =
  | Update of TransformerTuiModel
  | Execute of TransformerTuiModel * string
  | ExecuteCommand of TransformerTuiModel * string
  | Stop of TransformerTuiModel

module TransformerTuiInputController =
  [<Literal>]
  let private MultiClickWindowMilliseconds = 500L

  [<Literal>]
  let private MouseAutoScrollIntervalMilliseconds = 75L

  let private hasModifier modifier (key: ConsoleKeyInfo) =
    key.Modifiers &&& modifier = modifier

  let private toggleHelp model =
    match model.Overlay, model.ViewPane with
    | TuiOverlay.View, Some pane when pane.Title = "Help" ->
      TransformerTuiModel.closeViewPane model
    | _ ->
      TransformerTuiModel.openTextView
        "Help"
        (ReplHelp.guideLines
         |> List.map (fun text ->
           { Kind = TuiLineKind.Output; Text = text }))
        model

  let private toggleView model =
    if model.Overlay = TuiOverlay.View then
      TransformerTuiModel.closeViewPane model
    else
      model
      |> TransformerTuiModel.openSelectedViewPane

  let private toggleCommandPalette model =
    if model.Overlay = TuiOverlay.CommandPalette then
      TransformerTuiModel.closeOverlay model
    else
      TransformerTuiModel.openCommandPalette model

  let private scrollPage direction model =
    match model.Overlay with
    | TuiOverlay.None ->
      let width, height = TransformerTuiTerminal.dimensions ()
      let bodyWidth = TransformerTuiModel.transcriptBodyWidth width model
      let bodyHeight = TransformerTuiModel.transcriptHeight height model
      TransformerTuiModel.scrollTranscript
        bodyWidth bodyHeight (-direction) model
    | _ ->
      TransformerTuiModel.scroll (-direction) model

  let private pageHeight model =
    let _, height = TransformerTuiTerminal.dimensions ()
    TransformerTuiModel.transcriptHeight height model

  let private transcriptPageSize model =
    let width, height = TransformerTuiTerminal.dimensions ()
    let bodyWidth = TransformerTuiModel.transcriptBodyWidth width model
    bodyWidth, TransformerTuiModel.transcriptHeight height model

  let private inspectionItems model =
    model.Session.Current
    |> Option.map TransformerReplInspection.inspect
    |> Option.defaultValue []

  let private overlayItemCount model =
    match model.Overlay with
    | TuiOverlay.Inspect ->
      inspectionItems model |> List.length
    | TuiOverlay.Values ->
      model.Session.ValueHistory |> List.length
    | _ ->
      0

  let private selectedOverlayCommand model =
    match model.Overlay with
    | TuiOverlay.Inspect ->
      inspectionItems model
      |> List.tryItem model.OverlaySelection
      |> Option.map (fun item -> item.Command)
    | TuiOverlay.Values ->
      model.Session.ValueHistory
      |> List.rev
      |> List.tryItem model.OverlaySelection
      |> Option.map (fun entry -> $":restore {entry.ID}")
    | _ ->
      None

  let private acceptOverlaySelection model =
    match selectedOverlayCommand model with
    | Some command ->
      model
      |> TransformerTuiModel.setInput command command.Length
      |> TransformerTuiModel.closeOverlay
      |> TuiInputResult.Update
    | None ->
      TransformerTuiModel.closeOverlay model |> TuiInputResult.Update

  let private parseInt (value: string) =
    match Int32.TryParse value with
    | true, number ->
      Some number
    | _ ->
      None

  let private layoutSummary (model: TransformerTuiModel) =
    let sidebar =
      match model.SidebarWidth with
      | None ->
        "auto"
      | Some 0 ->
        "off"
      | Some width ->
        string width
    $"layout sidebar={sidebar} "
    + $"suggestions={model.SuggestionHeight} "
    + $"order={TransformerTuiModel.bottomPaneOrderName model}"

  let private applyLayoutOption (optionText: string) model =
    let index = optionText.IndexOf '='
    if index <= 0 then
      Error $"Invalid layout option: {optionText}"
    else
      let key = optionText.Substring(0, index).Trim().ToLowerInvariant()
      let value =
        optionText.Substring(index + 1).Trim().ToLowerInvariant()
      match key, value with
      | "suggestions", "auto" ->
        Ok(TransformerTuiModel.setSuggestionHeight
             TransformerTuiModel.defaultSuggestionHeight
             model)
      | "suggestions", _ ->
        match parseInt value with
        | Some height ->
          Ok(TransformerTuiModel.setSuggestionHeight height model)
        | None ->
          Error "suggestions must be a number."
      | "order", "toggle" ->
        Ok(TransformerTuiModel.toggleBottomPaneOrder model)
      | "order", "shell-first" ->
        Ok(TransformerTuiModel.setBottomPaneOrder
             TuiBottomPaneOrder.ShellAboveSuggestions
             model)
      | "order", "suggestions-first" ->
        Ok(TransformerTuiModel.setBottomPaneOrder
             TuiBottomPaneOrder.SuggestionsAboveShell
             model)
      | "order", _ ->
        Error "order must be toggle, shell-first, or suggestions-first."
      | "sidebar", "auto" ->
        Ok(TransformerTuiModel.setSidebarWidth None model)
      | "sidebar", "off" ->
        Ok(TransformerTuiModel.setSidebarWidth (Some 0) model)
      | "sidebar", _ ->
        match parseInt value with
        | Some width ->
          Ok(TransformerTuiModel.setSidebarWidth (Some width) model)
        | None ->
          Error "sidebar must be a number."
      | _ ->
        Error $"Unknown layout option: {key}"

  let private applyLayoutCommand
    (command: string)
    (model: TransformerTuiModel) =
    let command = command.TrimStart()
    let command =
      if command.StartsWith ':' then command else ":" + command
    let words = InputAnalysis.splitWords command
    let model =
      model
      |> TransformerTuiModel.appendCommand command
      |> TransformerTuiModel.clearInput
    let result =
      match words with
      | [ ":layout" ] ->
        Ok model
      | ":layout" :: options ->
        let folder result optionText =
          result |> Result.bind (applyLayoutOption optionText)
        List.fold folder (Ok model) options
      | _ ->
        Error "Invalid layout command."
    match result with
    | Ok next ->
      let summary = layoutSummary next
      next
      |> TransformerTuiModel.appendLines TuiLineKind.Output [ summary ]
      |> TransformerTuiModel.setStatus summary
      |> TuiInputResult.Update
    | Error message ->
      model
      |> TransformerTuiModel.appendLines TuiLineKind.Error [ message ]
      |> TransformerTuiModel.setStatus "Layout failed"
      |> TuiInputResult.Update

  let private isLayoutCommand (input: string) =
    let input = input.TrimStart()
    let input =
      if input.StartsWith ':' then input[1..] else input
    input.Equals("layout", StringComparison.OrdinalIgnoreCase)
    || input.StartsWith("layout ", StringComparison.OrdinalIgnoreCase)

  let private submitPhrase command model =
    if isLayoutCommand command then
      applyLayoutCommand command model
    else
      TuiInputResult.Execute(model, command)

  let private trySubmitPhrase model =
    match InputAnalysis.tryTakeInteractivePhrase model.Input with
    | Some command ->
      submitPhrase command model
    | None ->
      TuiInputResult.Update model

  let appendShellText text model =
    TransformerTuiModel.insertText text model |> TuiInputResult.Update

  let private pressShellEnter model =
    match trySubmitPhrase model with
    | TuiInputResult.Update _ ->
      appendShellText "\n" model
    | result ->
      result

  let private submitShellInput model =
    submitPhrase model.Input model

  let private isBrowsingHistory (model: TransformerTuiModel) =
    model.ShellInputMode = TuiShellInputMode.HistoryBrowsing

  let private isEditingHistoryInput (model: TransformerTuiModel) =
    model.ShellInputMode = TuiShellInputMode.HistoryEditing

  let private isNormalInput (model: TransformerTuiModel) =
    model.ShellInputMode = TuiShellInputMode.Normal

  let private hasMultipleInputLines model =
    (model: TransformerTuiModel).Input.Contains '\n'

  let private hasInput model =
    not (String.IsNullOrEmpty (model: TransformerTuiModel).Input)

  let private hasSuggestions completion =
    not (List.isEmpty completion.Items)

  let private copySelection model =
    let text = TransformerTuiModel.selectedText model
    if String.IsNullOrEmpty text then
      TransformerTuiModel.setStatus "There is no selected text" model
    elif TransformerTuiTerminal.tryCopyText text then
      TransformerTuiModel.setStatus "Copied selection" model
    else
      TransformerTuiModel.setStatus "Clipboard is unavailable" model

  let private insertPipeOperator model =
    let input = (model: TransformerTuiModel).Input
    let cursor = max 0 (min model.Cursor input.Length)
    let before =
      if cursor = 0 then "" else input[..cursor - 1]
    let after =
      if cursor >= input.Length then "" else input[cursor..]
    let before = before.TrimEnd()
    let after = after.TrimStart()
    let input = before + " |> " + after
    TransformerTuiModel.replaceInput input (before.Length + 4) model

  let private isPipeShortcut control (key: ConsoleKeyInfo) =
    if key.Key = ConsoleKey.Spacebar then
      control || key.KeyChar = char 0
    elif key.Key = ConsoleKey.NoName then
      key.KeyChar = char 0
    else
      false

  let private tryHandleLayoutShortcut (key: ConsoleKeyInfo) model =
    let width, height = TransformerTuiTerminal.dimensions ()
    let defaultWidth = if width >= 100 then min 34 (width / 3) else 34
    match key.Key with
    | ConsoleKey.LeftArrow ->
      TransformerTuiModel.adjustSidebarWidth defaultWidth 2 model
      |> TuiInputResult.Update
      |> Some
    | ConsoleKey.RightArrow ->
      TransformerTuiModel.adjustSidebarWidth defaultWidth -2 model
      |> TuiInputResult.Update
      |> Some
    | ConsoleKey.UpArrow ->
      TransformerTuiModel.adjustSuggestionHeight height 1 model
      |> TuiInputResult.Update
      |> Some
    | ConsoleKey.DownArrow ->
      TransformerTuiModel.adjustSuggestionHeight height -1 model
      |> TuiInputResult.Update
      |> Some
    | _ ->
      None

  let private handleControlKey completion key model =
    let canEditInput =
      (model: TransformerTuiModel).Overlay = TuiOverlay.None
      && model.Focus = TuiFocus.Shell
    match (key: ConsoleKeyInfo).Key, canEditInput with
    | ConsoleKey.A, true ->
      TransformerTuiModel.moveHome model
    | ConsoleKey.E, true ->
      TransformerTuiModel.moveEnd model
    | ConsoleKey.W, true
    | ConsoleKey.Backspace, true ->
      TransformerTuiModel.deleteWord model
    | ConsoleKey.U, true ->
      TransformerTuiModel.deleteToStart model
    | ConsoleKey.K, true ->
      TransformerTuiModel.deleteToEnd model
    | ConsoleKey.L, _ ->
      TransformerTuiModel.clearTranscript model
    | ConsoleKey.N, _ ->
      let count = List.length (completion: SuggestionSet).Items
      TransformerTuiModel.selectSuggestion 1 count model
    | ConsoleKey.P, _ ->
      let count = List.length completion.Items
      TransformerTuiModel.selectSuggestion -1 count model
    | _ ->
      model

  let private handleViewFindKey (key: ConsoleKeyInfo)
                                (model: TransformerTuiModel) =
    match key.Key with
    | ConsoleKey.Enter ->
      TransformerTuiModel.findInView model |> TuiInputResult.Update
    | ConsoleKey.Escape ->
      TransformerTuiModel.setViewFind false model |> TuiInputResult.Update
    | ConsoleKey.LeftArrow ->
      TransformerTuiModel.moveViewFindCursor -1 model
      |> TuiInputResult.Update
    | ConsoleKey.RightArrow ->
      TransformerTuiModel.moveViewFindCursor 1 model
      |> TuiInputResult.Update
    | ConsoleKey.Home ->
      TransformerTuiModel.setViewFindCursor 0 model
      |> TuiInputResult.Update
    | ConsoleKey.End ->
      let length =
        model.ViewPane |> Option.map (fun pane -> pane.FindText.Length)
        |> Option.defaultValue 0
      TransformerTuiModel.setViewFindCursor length model
      |> TuiInputResult.Update
    | ConsoleKey.Backspace ->
      TransformerTuiModel.backspaceViewFind model |> TuiInputResult.Update
    | _ when not (Char.IsControl key.KeyChar) ->
      TransformerTuiModel.appendViewFind key.KeyChar model
      |> TuiInputResult.Update
    | _ ->
      TuiInputResult.Update model

  let private handleTranscriptFindKey (key: ConsoleKeyInfo) model =
    match key.Key with
    | ConsoleKey.Enter ->
      let width, height = transcriptPageSize model
      TransformerTuiModel.findInTranscript width height model
      |> TuiInputResult.Update
    | ConsoleKey.Escape ->
      TransformerTuiModel.setTranscriptFind false model |> TuiInputResult.Update
    | ConsoleKey.LeftArrow ->
      TransformerTuiModel.moveTranscriptFindCursor -1 model
      |> TuiInputResult.Update
    | ConsoleKey.RightArrow ->
      TransformerTuiModel.moveTranscriptFindCursor 1 model
      |> TuiInputResult.Update
    | ConsoleKey.Home ->
      TransformerTuiModel.setTranscriptFindCursor 0 model
      |> TuiInputResult.Update
    | ConsoleKey.End ->
      TransformerTuiModel.setTranscriptFindCursor
        model.TranscriptFindText.Length model
      |> TuiInputResult.Update
    | ConsoleKey.Backspace ->
      TransformerTuiModel.backspaceTranscriptFind model |> TuiInputResult.Update
    | _ when not (Char.IsControl key.KeyChar) ->
      TransformerTuiModel.appendTranscriptFind key.KeyChar model
      |> TuiInputResult.Update
    | _ ->
      TuiInputResult.Update model

  let private handleViewKey
    control
    shift
    (key: ConsoleKeyInfo)
    (model: TransformerTuiModel) =
    if control && key.Key = ConsoleKey.F then
      TransformerTuiModel.setViewFind true model |> TuiInputResult.Update
    elif control && key.Key = ConsoleKey.Enter then
      TransformerTuiModel.insertViewSelection model |> TuiInputResult.Update
    else
      match key.Key with
      | ConsoleKey.Escape
      | ConsoleKey.F4 ->
        TransformerTuiModel.closeViewPane model |> TuiInputResult.Update
      | ConsoleKey.PageUp ->
        let width, height = TransformerTuiTerminal.dimensions ()
        TransformerTuiRenderer.moveViewCursorByRows
          width height (-(pageHeight model)) shift model
        |> TuiInputResult.Update
      | ConsoleKey.PageDown ->
        let width, height = TransformerTuiTerminal.dimensions ()
        TransformerTuiRenderer.moveViewCursorByRows
          width height (pageHeight model) shift model
        |> TuiInputResult.Update
      | ConsoleKey.UpArrow ->
        let width, height = TransformerTuiTerminal.dimensions ()
        TransformerTuiRenderer.moveViewCursorByRows
          width height -1 shift model
        |> TuiInputResult.Update
      | ConsoleKey.DownArrow ->
        let width, height = TransformerTuiTerminal.dimensions ()
        TransformerTuiRenderer.moveViewCursorByRows
          width height 1 shift model
        |> TuiInputResult.Update
      | ConsoleKey.LeftArrow ->
        TransformerTuiModel.moveViewCursor 0 -1 shift model
        |> TuiInputResult.Update
      | ConsoleKey.RightArrow ->
        TransformerTuiModel.moveViewCursor 0 1 shift model
        |> TuiInputResult.Update
      | ConsoleKey.Home ->
        TransformerTuiModel.moveViewToFirstLine shift model
        |> TuiInputResult.Update
      | ConsoleKey.End ->
        TransformerTuiModel.moveViewToLastLine shift model
        |> TuiInputResult.Update
      | _ ->
        TuiInputResult.Update model

  let private handleTranscriptKey
    control
    (key: ConsoleKeyInfo)
    (model: TransformerTuiModel) =
    match key.Key with
    | ConsoleKey.Escape ->
      TransformerTuiModel.focusShell model |> TuiInputResult.Update
    | ConsoleKey.Enter
    | ConsoleKey.F4 ->
      TransformerTuiModel.openSelectedViewPane model |> TuiInputResult.Update
    | ConsoleKey.Home ->
      let width, height = transcriptPageSize model
      TransformerTuiModel.moveTranscriptToFirstCommand width height model
      |> TuiInputResult.Update
    | ConsoleKey.End ->
      let width, height = transcriptPageSize model
      TransformerTuiModel.moveTranscriptToLastCommand width height model
      |> TuiInputResult.Update
    | ConsoleKey.PageUp ->
      let width, height = transcriptPageSize model
      TransformerTuiModel.moveTranscriptCursorInView
        width height (-height) 0 model
      |> TuiInputResult.Update
    | ConsoleKey.PageDown ->
      let width, height = transcriptPageSize model
      TransformerTuiModel.moveTranscriptCursorInView
        width height height 0 model
      |> TuiInputResult.Update
    | ConsoleKey.UpArrow when control ->
      let width, height = transcriptPageSize model
      TransformerTuiModel.moveTranscriptCommand width height -1 model
      |> TuiInputResult.Update
    | ConsoleKey.DownArrow when control ->
      let width, height = transcriptPageSize model
      TransformerTuiModel.moveTranscriptCommand width height 1 model
      |> TuiInputResult.Update
    | ConsoleKey.UpArrow ->
      let width, height = transcriptPageSize model
      TransformerTuiModel.moveTranscriptCursorInView width height -1 0 model
      |> TuiInputResult.Update
    | ConsoleKey.DownArrow ->
      let width, height = transcriptPageSize model
      TransformerTuiModel.moveTranscriptCursorInView width height 1 0 model
      |> TuiInputResult.Update
    | ConsoleKey.LeftArrow ->
      let width, height = transcriptPageSize model
      TransformerTuiModel.moveTranscriptCursorInView width height 0 -1 model
      |> TuiInputResult.Update
    | ConsoleKey.RightArrow ->
      let width, height = transcriptPageSize model
      TransformerTuiModel.moveTranscriptCursorInView width height 0 1 model
      |> TuiInputResult.Update
    | _ ->
      TuiInputResult.Update model

  let private submitCommandPalette model =
    let command = model.PaletteInput.Trim()
    let model = TransformerTuiModel.closeOverlay model
    if String.IsNullOrEmpty command then
      TuiInputResult.Update model
    elif isLayoutCommand command then
      applyLayoutCommand command model
    else
      TuiInputResult.ExecuteCommand(model, command)

  let private handleCommandPaletteKey (key: ConsoleKeyInfo) model =
    let candidates = Suggestions.commandPaletteCandidates model.PaletteFilter
    match key.Key with
    | ConsoleKey.Escape
    | ConsoleKey.F2 ->
      TransformerTuiModel.closeOverlay model |> TuiInputResult.Update
    | ConsoleKey.Enter ->
      submitCommandPalette model
    | ConsoleKey.Tab ->
      TransformerTuiModel.applyPaletteSuggestion candidates model
      |> TuiInputResult.Update
    | ConsoleKey.UpArrow ->
      TransformerTuiModel.selectPaletteSuggestion -1 candidates model
      |> TuiInputResult.Update
    | ConsoleKey.DownArrow ->
      TransformerTuiModel.selectPaletteSuggestion 1 candidates model
      |> TuiInputResult.Update
    | ConsoleKey.LeftArrow ->
      TransformerTuiModel.movePaletteCursor -1 model |> TuiInputResult.Update
    | ConsoleKey.RightArrow ->
      TransformerTuiModel.movePaletteCursor 1 model |> TuiInputResult.Update
    | ConsoleKey.Home ->
      TransformerTuiModel.movePaletteHome model |> TuiInputResult.Update
    | ConsoleKey.End ->
      TransformerTuiModel.movePaletteEnd model |> TuiInputResult.Update
    | ConsoleKey.Backspace ->
      TransformerTuiModel.backspacePalette model |> TuiInputResult.Update
    | ConsoleKey.Delete ->
      TransformerTuiModel.deletePalette model |> TuiInputResult.Update
    | _ when not (Char.IsControl key.KeyChar) ->
      TransformerTuiModel.insertPaletteText (string key.KeyChar) model
      |> TuiInputResult.Update
    | _ ->
      TuiInputResult.Update model

  let private scrollWithMouse width height completion mouse direction model =
    let row = (mouse: TuiMouseEvent).Row
    let column = mouse.Column
    match model.Overlay with
    | TuiOverlay.None ->
      if TransformerTuiRenderer.isSidebarAt
           width height model row column then
        let visible = TransformerTuiModel.transcriptHeight height model
        TransformerTuiModel.scrollSidebar visible (-direction) model
      elif TransformerTuiRenderer.isSuggestionPaneAt
             width height model row column then
        TransformerTuiModel.selectSuggestion
          (-direction) (List.length (completion: SuggestionSet).Items) model
      elif TransformerTuiRenderer.tryInputCursorAt
             width height model row column |> Option.isSome then
        model
      elif TransformerTuiRenderer.isMainBodyAt
             width height model row column then
        let bodyWidth = TransformerTuiModel.transcriptBodyWidth width model
        let bodyHeight = TransformerTuiModel.transcriptHeight height model
        TransformerTuiModel.scrollTranscript
          bodyWidth bodyHeight (-direction) model
      else
        model
    | TuiOverlay.View ->
      if TransformerTuiRenderer.isSidebarAt
           width height model row column then
        let visible = TransformerTuiModel.transcriptHeight height model
        TransformerTuiModel.scrollSidebar visible (-direction) model
      elif TransformerTuiRenderer.isMainBodyAt
             width height model row column then
        TransformerTuiRenderer.moveViewCursorByRows
          width height (-direction) false model
      else
        model
    | TuiOverlay.CommandPalette ->
      match TransformerTuiRenderer.paletteHitAt
              width height model row column with
      | TransformerTuiRenderer.PaletteCandidate _
      | TransformerTuiRenderer.PaletteInside ->
        let candidates =
          Suggestions.commandPaletteCandidates model.PaletteFilter
        TransformerTuiModel.selectPaletteSuggestion
          (if direction > 0 then -1 else 1) candidates model
      | _ ->
        model
    | _ ->
      if TransformerTuiRenderer.isMainBodyAt
           width height model row column then
        TransformerTuiModel.scroll (-direction) model
      else
        model

  let private selectViewText width height (mouse: TuiMouseEvent) extend model =
    match TransformerTuiRenderer.tryViewCursorAt
            width height model mouse.Row mouse.Column with
    | Some cursor ->
      let model =
        TransformerTuiModel.moveViewCursorTo
          cursor.Line cursor.Column extend model
      let scrollOffset =
        TransformerTuiRenderer.viewScrollOffset width height model
      { model with ScrollOffset = scrollOffset }
    | None ->
      model

  let private applySuggestionClick
    width
    height
    completion
    (mouse: TuiMouseEvent)
    model =
    match TransformerTuiRenderer.trySuggestionIndexAt
            width height completion model mouse.Row mouse.Column with
    | Some index ->
      let count = List.length completion.Items
      let model =
        TransformerTuiModel.selectSuggestion
          (index - model.SuggestionIndex)
          count
          model
      TransformerTuiModel.applyCompletion completion model
    | None ->
      model

  let private applySidebarValue name model =
    let model =
      if model.Overlay = TuiOverlay.View then
        TransformerTuiModel.closeViewPane model
      else
        model
    model
    |> TransformerTuiModel.focusShell
    |> TransformerTuiModel.insertText name

  let private applyHeaderClick hit model =
    match hit, model.Overlay with
    | TransformerTuiRenderer.HeaderRun, TuiOverlay.None ->
      submitShellInput model
    | TransformerTuiRenderer.HeaderCopy, _ ->
      copySelection model |> TuiInputResult.Update
    | TransformerTuiRenderer.HeaderKey ConsoleKey.F1, _ ->
      toggleHelp model |> TuiInputResult.Update
    | TransformerTuiRenderer.HeaderKey ConsoleKey.F2, _ ->
      toggleCommandPalette model |> TuiInputResult.Update
    | TransformerTuiRenderer.HeaderKey ConsoleKey.F3, TuiOverlay.View ->
      TransformerTuiModel.setViewFind true model |> TuiInputResult.Update
    | TransformerTuiRenderer.HeaderKey ConsoleKey.F3, TuiOverlay.None ->
      TransformerTuiModel.setTranscriptFind true model
      |> TuiInputResult.Update
    | TransformerTuiRenderer.HeaderKey ConsoleKey.F4, TuiOverlay.View
    | TransformerTuiRenderer.HeaderKey ConsoleKey.F4, TuiOverlay.None ->
      toggleView model |> TuiInputResult.Update
    | _ ->
      TuiInputResult.Update model

  let private applyPaletteClick
    width height (mouse: TuiMouseEvent) clickCount model =
    match TransformerTuiRenderer.paletteHitAt
            width height model mouse.Row mouse.Column with
    | TransformerTuiRenderer.PaletteOutside ->
      TransformerTuiModel.closeOverlay model |> TuiInputResult.Update
    | TransformerTuiRenderer.PaletteInput cursor ->
      TransformerTuiModel.movePaletteCursor
        (cursor - model.PaletteCursor) model
      |> TuiInputResult.Update
    | TransformerTuiRenderer.PaletteCandidate index ->
      let candidates =
        Suggestions.commandPaletteCandidates model.PaletteFilter
      let model =
        model
        |> TransformerTuiModel.selectPaletteSuggestion
          (index - model.PaletteSuggestionIndex) candidates
        |> TransformerTuiModel.applyPaletteSuggestion candidates
      if clickCount = 2 then submitCommandPalette model
      else TuiInputResult.Update model
    | TransformerTuiRenderer.PaletteInside ->
      TuiInputResult.Update model

  let private selectTranscriptLine
    width
    height
    (mouse: TuiMouseEvent)
    extend
    model =
    TransformerTuiModel.trySelectTranscriptAt
      width height mouse.Row mouse.Column extend model

  let private selectInputText width height (mouse: TuiMouseEvent) extend model =
    TransformerTuiRenderer.tryInputCursorAt
      width height model mouse.Row mouse.Column
    |> Option.map (fun cursor ->
      TransformerTuiModel.moveInputCursorTo cursor extend model)

  let private extendMouseSelection width height (mouse: TuiMouseEvent) model =
    match model.MouseDragTarget with
    | Some TuiMouseDragTarget.View ->
      selectViewText width height mouse true model
    | Some TuiMouseDragTarget.Input ->
      match selectInputText width height mouse true model with
      | Some model ->
        model
      | None ->
        model
    | Some TuiMouseDragTarget.Transcript ->
      match selectTranscriptLine width height mouse true model with
      | Some model ->
        model
      | None ->
        model
    | _ ->
      model

  let private resizeWithMouse width height (mouse: TuiMouseEvent) model =
    match model.MouseDragTarget with
    | Some TuiMouseDragTarget.SidebarDivider ->
      TransformerTuiModel.setSidebarWidth
        (Some(width - mouse.Column)) model
    | Some TuiMouseDragTarget.SuggestionDivider ->
      let inputRows = TransformerTuiModel.visibleShellInputRows height model
      let spaceBelow =
        match model.BottomPaneOrder with
        | TuiBottomPaneOrder.ShellAboveSuggestions ->
          0
        | TuiBottomPaneOrder.SuggestionsAboveShell ->
          inputRows
      TransformerTuiModel.setSuggestionHeight
        (height - spaceBelow - mouse.Row) model
    | _ ->
      model

  let private moveMouseDrag width height mouse model =
    match model.MouseDragTarget with
    | Some TuiMouseDragTarget.SidebarDivider
    | Some TuiMouseDragTarget.SuggestionDivider ->
      resizeWithMouse width height mouse model
    | _ ->
      extendMouseSelection width height mouse model

  let private autoScrollTranscript width height mouse direction model =
    let bodyWidth = TransformerTuiModel.transcriptBodyWidth width model
    let bodyHeight = TransformerTuiModel.transcriptHeight height model
    let model =
      TransformerTuiModel.scrollTranscript
        bodyWidth bodyHeight direction model
    let edgeRow = if direction < 0 then 4 else 3 + bodyHeight
    let edgeColumn = max 2 (min (bodyWidth - 1) mouse.Column)
    let edge = { mouse with Row = edgeRow; Column = edgeColumn }
    selectTranscriptLine width height edge true model
    |> Option.defaultValue model

  let private inputAutoScrollDirection height mouse model =
    let bodyHeight = TransformerTuiModel.transcriptHeight height model
    let suggestions = TransformerTuiModel.suggestionHeight height model
    let inputRows = TransformerTuiModel.visibleShellInputRows height model
    let start =
      match model.BottomPaneOrder with
      | TuiBottomPaneOrder.ShellAboveSuggestions ->
        5 + bodyHeight
      | TuiBottomPaneOrder.SuggestionsAboveShell ->
        5 + bodyHeight + suggestions
    if mouse.Row < start then -1
    elif mouse.Row >= start + inputRows then 1
    else 0

  let private autoScrollInput direction model =
    let anchor = model.InputAnchor |> Option.orElse (Some model.Cursor)
    let model = TransformerTuiModel.moveCursorLine direction model
    { model with InputAnchor = anchor }

  let advanceMouseDrag width height (model: TransformerTuiModel) =
    let interactive = TransformerTuiRenderer.isInteractiveSize width height
    match interactive, model.MouseDragTarget, model.MouseDragPosition with
    | true, Some target, Some(row, column) ->
      let now = Environment.TickCount64
      if now - model.LastMouseScrollAt <
         MouseAutoScrollIntervalMilliseconds then
        model
      else
        let mouse =
          { Button = 0
            Row = row
            Column = column
            IsRelease = false
            IsDrag = true }
        let bodyHeight = TransformerTuiModel.transcriptHeight height model
        let direction =
          if row < 4 then -1
          elif row >= 4 + bodyHeight then 1
          else 0
        let inputDirection =
          if target = TuiMouseDragTarget.Input then
            inputAutoScrollDirection height mouse model
          else
            0
        let shouldScroll =
          match target with
          | TuiMouseDragTarget.View
          | TuiMouseDragTarget.Transcript -> direction <> 0
          | TuiMouseDragTarget.Input -> inputDirection <> 0
          | _ -> false
        let next =
          match target with
          | TuiMouseDragTarget.View when direction <> 0 ->
            TransformerTuiRenderer.moveViewCursorByRows
              width height direction true model
          | TuiMouseDragTarget.Transcript when direction <> 0 ->
            autoScrollTranscript width height mouse direction model
          | TuiMouseDragTarget.Input when inputDirection <> 0 ->
            autoScrollInput inputDirection model
          | _ ->
            model
        if shouldScroll then
          { next with LastMouseScrollAt = now }
        else
          model
    | _ ->
      model

  let private hasMouseSelection model =
    match model.Overlay, model.ViewPane, model.Focus with
    | TuiOverlay.View, Some pane, _ ->
      pane.Anchor.IsSome
    | TuiOverlay.None, _, TuiFocus.Shell ->
      model.InputAnchor.IsSome
    | TuiOverlay.None, _, TuiFocus.Transcript ->
      model.TranscriptAnchor.IsSome
    | _ ->
      false

  let private rememberClick (mouse: TuiMouseEvent) model =
    if mouse.IsRelease || mouse.IsDrag || mouse.Button >= 64 then
      model, 0
    else
      let now = Environment.TickCount64
      let count =
        match model.RecentClick with
        | Some previous when previous.Button = mouse.Button
                             && previous.Row = mouse.Row
                             && abs (previous.Column - mouse.Column) <= 1
                             && now - previous.At <=
                                MultiClickWindowMilliseconds ->
          min 3 (previous.Count + 1)
        | _ ->
          1
      let recent =
        { Button = mouse.Button
          Row = mouse.Row
          Column = mouse.Column
          At = now
          Count = count }
      { model with RecentClick = Some recent }, count

  let private handleContentClick
    width height completion (mouse: TuiMouseEvent) clickCount model =
    match selectTranscriptLine width height mouse false model with
    | Some model ->
      let model =
        match clickCount with
        | 2 -> TransformerTuiModel.selectTranscriptWord model
        | 3 -> TransformerTuiModel.selectTranscriptLine model
        | _ -> model
      let model =
        { model with
            MouseDragTarget = Some TuiMouseDragTarget.Transcript }
      TuiInputResult.Update model
    | None ->
      match selectInputText width height mouse false model with
      | Some model ->
        let model =
          match clickCount with
          | 2 -> TransformerTuiModel.selectInputWord model
          | 3 -> TransformerTuiModel.selectInputLine model
          | _ -> model
        { model with MouseDragTarget = Some TuiMouseDragTarget.Input }
        |> TuiInputResult.Update
      | None ->
        applySuggestionClick width height completion mouse model
        |> TuiInputResult.Update

  let private applyViewClick clickCount model =
    let itemCommand =
      model.ViewPane
      |> Option.bind (fun pane ->
        pane.ItemCommands |> Array.tryItem pane.Cursor.Line)
    match clickCount, itemCommand with
    | 2, Some command when command.StartsWith ':' ->
      model
      |> TransformerTuiModel.closeViewPane
      |> TransformerTuiModel.openCommandPaletteWith command[1..]
    | 2, Some command ->
      model
      |> TransformerTuiModel.closeViewPane
      |> TransformerTuiModel.setInput command command.Length
    | 2, None ->
      TransformerTuiModel.selectViewWord model
    | 3, _ ->
      TransformerTuiModel.selectViewLine model
    | _ ->
      model

  let private applyFindClick cursor model =
    let model =
      if model.Overlay = TuiOverlay.View then
        TransformerTuiModel.setViewFindCursor cursor model
      else
        TransformerTuiModel.setTranscriptFindCursor cursor model
    TuiInputResult.Update model

  let private applyViewPress width height mouse clickCount model =
    let model = selectViewText width height mouse false model
    let model = applyViewClick clickCount model
    let target =
      if model.Overlay = TuiOverlay.View then
        Some TuiMouseDragTarget.View
      else
        None
    { model with MouseDragTarget = target } |> TuiInputResult.Update

  let private cancelTransientWithMouse model =
    match model.Overlay with
    | TuiOverlay.View ->
      match model.ViewPane with
      | Some pane when pane.IsFinding ->
        TransformerTuiModel.setViewFind false model
      | _ ->
        TransformerTuiModel.closeViewPane model
    | TuiOverlay.None when model.IsFindingTranscript ->
      TransformerTuiModel.setTranscriptFind false model
    | TuiOverlay.None ->
      model
    | _ ->
      TransformerTuiModel.closeOverlay model

  let private handleBodyPress
    width height completion (mouse: TuiMouseEvent) clickCount model =
    if TransformerTuiRenderer.isSidebarDividerAt
         width height model mouse.Row mouse.Column then
      { model with
          MouseDragTarget = Some TuiMouseDragTarget.SidebarDivider }
      |> TuiInputResult.Update
    elif model.Overlay = TuiOverlay.None
         && TransformerTuiRenderer.isSuggestionDividerAt
              width height model mouse.Row mouse.Column then
      { model with
          MouseDragTarget = Some TuiMouseDragTarget.SuggestionDivider }
      |> TuiInputResult.Update
    elif model.Overlay = TuiOverlay.View then
      applyViewPress width height mouse clickCount model
    else
      handleContentClick width height completion mouse clickCount model

  let private handleMousePress
    width height completion (mouse: TuiMouseEvent) clickCount model =
    let header =
      TransformerTuiRenderer.tryHeaderHitAt
        width mouse.Row mouse.Column
    let findCursor =
      TransformerTuiRenderer.tryFindCursorAt
        width height model mouse.Row mouse.Column
    let sidebarValue =
      TransformerTuiRenderer.trySidebarValueAt
        width height model mouse.Row mouse.Column
    if mouse.Button = 2 then
      cancelTransientWithMouse model |> TuiInputResult.Update
    elif mouse.Button &&& 3 <> 0 || mouse.Button >= 64 then
      TuiInputResult.Update model
    elif model.Overlay = TuiOverlay.CommandPalette then
      applyPaletteClick width height mouse clickCount model
    elif model.Overlay = TuiOverlay.Message then
      TransformerTuiModel.closeOverlay model |> TuiInputResult.Update
    elif header.IsSome then
      header
      |> Option.map (fun key -> applyHeaderClick key model)
      |> Option.defaultValue (TuiInputResult.Update model)
    elif findCursor.IsSome then
      findCursor
      |> Option.map (fun cursor -> applyFindClick cursor model)
      |> Option.defaultValue (TuiInputResult.Update model)
    elif sidebarValue.IsSome then
      sidebarValue
      |> Option.map (fun name -> applySidebarValue name model)
      |> Option.map TuiInputResult.Update
      |> Option.defaultValue (TuiInputResult.Update model)
    else
      handleBodyPress width height completion mouse clickCount model

  let private handleMouseAtSize
    width height completion (mouse: TuiMouseEvent) model =
    let model, clickCount = rememberClick mouse model
    if mouse.Button = 64 || mouse.Button = 65 then
      let direction = if mouse.Button = 64 then 3 else -3
      scrollWithMouse width height completion mouse direction model
      |> TuiInputResult.Update
    elif mouse.IsDrag && mouse.Button = 0 then
      match model.MouseDragTarget with
      | Some _ ->
        let model =
          { model with MouseDragPosition = Some(mouse.Row, mouse.Column) }
        moveMouseDrag width height mouse model |> TuiInputResult.Update
      | None ->
        TuiInputResult.Update model
    elif mouse.IsDrag then
      TuiInputResult.Update model
    elif mouse.IsRelease then
      let model =
        if model.MouseDragPosition.IsSome && hasMouseSelection model then
          moveMouseDrag width height mouse model
        else
          resizeWithMouse width height mouse model
      { model with MouseDragTarget = None; MouseDragPosition = None }
      |> TuiInputResult.Update
    else
      handleMousePress width height completion mouse clickCount model

  let handleMouse width height completion (mouse: TuiMouseEvent) model =
    if not (TransformerTuiRenderer.isInteractiveSize width height) then
      let model =
        if mouse.IsRelease then
          { model with MouseDragTarget = None; MouseDragPosition = None }
        else
          model
      TuiInputResult.Update model
    else
      handleMouseAtSize width height completion mouse model

  let private handlePassiveSelection width height mouse model =
    if model.Overlay = TuiOverlay.View then
      let model = selectViewText width height mouse false model
      let target =
        if TransformerTuiRenderer.isMainBodyAt
             width height model mouse.Row mouse.Column then
          Some TuiMouseDragTarget.View
        else
          None
      { model with MouseDragTarget = target }
    elif model.Overlay = TuiOverlay.None then
      match selectTranscriptLine width height mouse false model with
      | Some model ->
        { model with
            MouseDragTarget = Some TuiMouseDragTarget.Transcript }
      | None ->
        selectInputText width height mouse false model
        |> Option.defaultValue model
    else
      model

  let private handlePassiveMouseAtSize
    width height completion mouse model =
    let isWheel = mouse.Button = 64 || mouse.Button = 65
    let isMotion = mouse.IsDrag || mouse.IsRelease
    let isCopy =
      match TransformerTuiRenderer.tryHeaderHitAt
              width mouse.Row mouse.Column with
      | Some TransformerTuiRenderer.HeaderCopy -> true
      | _ -> false
    if isWheel || isMotion then
      handleMouse width height completion mouse model
    elif mouse.Button = 0 && isCopy then
      copySelection model |> TuiInputResult.Update
    elif mouse.Button = 2 then
      cancelTransientWithMouse model |> TuiInputResult.Update
    elif mouse.Button = 0 then
      handlePassiveSelection width height mouse model
      |> TuiInputResult.Update
    else
      TuiInputResult.Update model

  let handlePassiveMouse width height completion mouse model =
    if TransformerTuiRenderer.isInteractiveSize width height then
      handlePassiveMouseAtSize width height completion mouse model
    else
      handleMouse width height completion mouse model

  let handle completion (key: ConsoleKeyInfo) model =
    let control = hasModifier ConsoleModifiers.Control key
    let shift = hasModifier ConsoleModifiers.Shift key
    let alt = hasModifier ConsoleModifiers.Alt key
    let layoutShortcut =
      if alt then tryHandleLayoutShortcut key model else None
    match layoutShortcut with
    | Some result ->
      result
    | None ->
      if key.Key = ConsoleKey.F2 then
        toggleCommandPalette model |> TuiInputResult.Update
      elif control && key.Key = ConsoleKey.C then
        copySelection model |> TuiInputResult.Update
      elif key.Key = ConsoleKey.F1 then
        toggleHelp model |> TuiInputResult.Update
      elif model.Overlay = TuiOverlay.CommandPalette then
        handleCommandPaletteKey key model
      elif model.Overlay = TuiOverlay.View && key.Key = ConsoleKey.F3 then
        TransformerTuiModel.setViewFind true model |> TuiInputResult.Update
      elif model.Overlay = TuiOverlay.View
         && (model.ViewPane |> Option.exists (fun pane -> pane.IsFinding)) then
        handleViewFindKey key model
      elif model.IsFindingTranscript then
        handleTranscriptFindKey key model
      elif model.Overlay = TuiOverlay.View then
        handleViewKey control shift key model
      elif model.Overlay = TuiOverlay.None && key.Key = ConsoleKey.F3 then
        TransformerTuiModel.setTranscriptFind true model
        |> TuiInputResult.Update
      elif model.Focus = TuiFocus.Transcript
           && model.Overlay = TuiOverlay.None
           && not (shift && key.Key = ConsoleKey.DownArrow) then
        handleTranscriptKey control key model
      elif control && key.Key = ConsoleKey.D then
        if String.IsNullOrEmpty model.Input then
          TuiInputResult.Stop model
        else
          TransformerTuiModel.delete model |> TuiInputResult.Update
      elif
        control
        && key.Key = ConsoleKey.Enter
           && model.Overlay = TuiOverlay.None
           && model.Focus = TuiFocus.Shell then
        submitShellInput model
      elif isPipeShortcut control key
           && model.Overlay = TuiOverlay.None
           && model.Focus = TuiFocus.Shell then
        insertPipeOperator model |> TuiInputResult.Update
      elif control then
        handleControlKey completion key model |> TuiInputResult.Update
      else
        match key.Key with
        | ConsoleKey.F4 ->
          toggleView model |> TuiInputResult.Update
        | ConsoleKey.Escape when model.Overlay <> TuiOverlay.None ->
          TransformerTuiModel.closeOverlay model |> TuiInputResult.Update
        | ConsoleKey.Escape ->
          TransformerTuiModel.clearInput model |> TuiInputResult.Update
        | ConsoleKey.Enter when model.Overlay = TuiOverlay.Inspect
                                || model.Overlay = TuiOverlay.Values ->
          acceptOverlaySelection model
        | ConsoleKey.Enter when model.Overlay <> TuiOverlay.None ->
          TransformerTuiModel.closeOverlay model |> TuiInputResult.Update
        | ConsoleKey.Enter ->
          pressShellEnter model
        | ConsoleKey.PageUp ->
          scrollPage (pageHeight model) model |> TuiInputResult.Update
        | ConsoleKey.PageDown ->
          scrollPage (-(pageHeight model)) model |> TuiInputResult.Update
        | ConsoleKey.UpArrow when shift && model.Overlay = TuiOverlay.None ->
          model
          |> TransformerTuiModel.focusTranscriptAt 0
          |> TuiInputResult.Update
        | ConsoleKey.DownArrow when shift && model.Overlay = TuiOverlay.None ->
          model
          |> TransformerTuiModel.focusShell
          |> TuiInputResult.Update
        | ConsoleKey.UpArrow when model.Overlay = TuiOverlay.Inspect
                                  || model.Overlay = TuiOverlay.Values ->
          let count = overlayItemCount model
          TransformerTuiModel.selectOverlay -1 count model
          |> TuiInputResult.Update
        | ConsoleKey.DownArrow when model.Overlay = TuiOverlay.Inspect
                                    || model.Overlay = TuiOverlay.Values ->
          let count = overlayItemCount model
          TransformerTuiModel.selectOverlay 1 count model
          |> TuiInputResult.Update
        | ConsoleKey.Tab when shift ->
          TransformerTuiModel.insertText "  " model |> TuiInputResult.Update
        | ConsoleKey.Tab ->
          TransformerTuiModel.applyCompletion completion model
          |> TuiInputResult.Update
        | ConsoleKey.Home when isBrowsingHistory model ->
          TransformerTuiModel.historyOldest model |> TuiInputResult.Update
        | ConsoleKey.End when isBrowsingHistory model ->
          TransformerTuiModel.historyNewest model |> TuiInputResult.Update
        | ConsoleKey.UpArrow when isBrowsingHistory model ->
          TransformerTuiModel.historyPrevious model |> TuiInputResult.Update
        | ConsoleKey.DownArrow when isBrowsingHistory model ->
          TransformerTuiModel.historyNext model |> TuiInputResult.Update
        | ConsoleKey.Home when model.Overlay = TuiOverlay.None
                               && model.Focus = TuiFocus.Shell
                               && isNormalInput model
                               && hasInput model
                               && hasSuggestions completion ->
          let count = List.length completion.Items
          let offset = -model.SuggestionIndex
          TransformerTuiModel.selectSuggestion offset count model
          |> TuiInputResult.Update
        | ConsoleKey.End when model.Overlay = TuiOverlay.None
                              && model.Focus = TuiFocus.Shell
                              && isNormalInput model
                              && hasSuggestions completion ->
          let count = List.length completion.Items
          let offset = count - 1 - model.SuggestionIndex
          TransformerTuiModel.selectSuggestion offset count model
          |> TuiInputResult.Update
        | ConsoleKey.UpArrow when model.Overlay = TuiOverlay.None
                                 && model.Focus = TuiFocus.Shell
                                 && isNormalInput model
                                 && hasInput model
                                 && hasSuggestions completion ->
          let count = List.length completion.Items
          TransformerTuiModel.selectSuggestion -1 count model
          |> TuiInputResult.Update
        | ConsoleKey.DownArrow when model.Overlay = TuiOverlay.None
                                   && model.Focus = TuiFocus.Shell
                                   && isNormalInput model
                                   && hasSuggestions completion ->
          let count = List.length completion.Items
          TransformerTuiModel.selectSuggestion 1 count model
          |> TuiInputResult.Update
        | ConsoleKey.UpArrow when model.Overlay = TuiOverlay.None
                                 && model.Focus = TuiFocus.Shell
                                 && hasMultipleInputLines model ->
          TransformerTuiModel.moveCursorLine -1 model |> TuiInputResult.Update
        | ConsoleKey.DownArrow when model.Overlay = TuiOverlay.None
                                   && model.Focus = TuiFocus.Shell
                                   && hasMultipleInputLines model ->
          TransformerTuiModel.moveCursorLine 1 model |> TuiInputResult.Update
        | ConsoleKey.UpArrow when isEditingHistoryInput model ->
          TransformerTuiModel.historyPrevious model |> TuiInputResult.Update
        | ConsoleKey.DownArrow when isEditingHistoryInput model ->
          TransformerTuiModel.historyNext model |> TuiInputResult.Update
        | ConsoleKey.UpArrow when model.Overlay = TuiOverlay.None
                                 && model.Focus = TuiFocus.Shell ->
          TransformerTuiModel.historyPrevious model |> TuiInputResult.Update
        | ConsoleKey.DownArrow when model.Overlay = TuiOverlay.None
                                   && model.Focus = TuiFocus.Shell ->
          TransformerTuiModel.historyNext model |> TuiInputResult.Update
        | ConsoleKey.LeftArrow ->
          TransformerTuiModel.moveCursor -1 model |> TuiInputResult.Update
        | ConsoleKey.RightArrow ->
          TransformerTuiModel.moveCursor 1 model |> TuiInputResult.Update
        | ConsoleKey.Home ->
          TransformerTuiModel.moveHome model |> TuiInputResult.Update
        | ConsoleKey.End ->
          TransformerTuiModel.moveEnd model |> TuiInputResult.Update
        | ConsoleKey.Backspace ->
          TransformerTuiModel.backspace model |> TuiInputResult.Update
        | ConsoleKey.Delete ->
          TransformerTuiModel.delete model |> TuiInputResult.Update
        | _ when not (Char.IsControl key.KeyChar) ->
          appendShellText (string key.KeyChar) model
        | _ ->
          TuiInputResult.Update model
