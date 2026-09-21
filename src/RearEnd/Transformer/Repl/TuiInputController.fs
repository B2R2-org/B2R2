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
  let private hasModifier modifier (key: ConsoleKeyInfo) =
    key.Modifiers &&& modifier = modifier

  let private toggleOverlay overlay model =
    if model.Overlay = overlay then
      TransformerTuiModel.closeOverlay model
    else
      TransformerTuiModel.setOverlay overlay model

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
      TransformerTuiModel.scroll (direction) model
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
    let transcript =
      match model.TranscriptHeight with
      | None ->
        "auto"
      | Some height ->
        string height
    $"layout sidebar={sidebar} "
    + $"transcript={transcript} shell={model.ShellHeight}"

  let private applyLayoutOption (optionText: string) model =
    let index = optionText.IndexOf '='
    if index <= 0 then
      Error $"Invalid layout option: {optionText}"
    else
      let key = optionText.Substring(0, index).Trim().ToLowerInvariant()
      let value =
        optionText.Substring(index + 1).Trim().ToLowerInvariant()
      match key, value with
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
      | "transcript", "auto" ->
        Ok(TransformerTuiModel.setTranscriptHeight None model)
      | "transcript", _ ->
        match parseInt value with
        | Some height ->
          Ok(TransformerTuiModel.setTranscriptHeight (Some height) model)
        | None ->
          Error "transcript must be a number."
      | "shell", "auto" ->
        let height = TransformerTuiModel.defaultShellHeight
        Ok(TransformerTuiModel.setShellHeight height model)
      | "shell", _ ->
        match parseInt value with
        | Some height ->
          Ok(TransformerTuiModel.setShellHeight height model)
        | None ->
          Error "shell must be a number."
      | _ ->
        Error $"Unknown layout option: {key}"

  let private applyLayoutCommand command model =
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
    input.Equals(":layout", StringComparison.OrdinalIgnoreCase)
    || input.StartsWith(":layout ", StringComparison.OrdinalIgnoreCase)

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

  let private isBrowsingHistory model =
    Option.isSome (model: TransformerTuiModel).HistoryIndex

  let private hasMultipleInputLines model =
    (model: TransformerTuiModel).Input.Contains '\n'

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
    TransformerTuiModel.setInput input (before.Length + 4) model

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
    let defaultHeight =
      TransformerTuiModel.defaultTranscriptHeight height model
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
      TransformerTuiModel.adjustTranscriptHeight defaultHeight -1 model
      |> TuiInputResult.Update
      |> Some
    | ConsoleKey.DownArrow ->
      TransformerTuiModel.adjustTranscriptHeight defaultHeight 1 model
      |> TuiInputResult.Update
      |> Some
    | _ ->
      None

  let private handleControlKey completion key model =
    let completion: SuggestionSet = completion
    let key: ConsoleKeyInfo = key
    match key.Key with
    | ConsoleKey.L ->
      TransformerTuiModel.clearTranscript model
    | ConsoleKey.N ->
      let count = List.length completion.Items
      TransformerTuiModel.selectSuggestion 1 count model
    | ConsoleKey.P ->
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
        TransformerTuiModel.pageViewCursor (-(pageHeight model)) shift model
        |> TuiInputResult.Update
      | ConsoleKey.PageDown ->
        TransformerTuiModel.pageViewCursor (pageHeight model) shift model
        |> TuiInputResult.Update
      | ConsoleKey.UpArrow ->
        TransformerTuiModel.moveViewCursor -1 0 shift model
        |> TuiInputResult.Update
      | ConsoleKey.DownArrow ->
        TransformerTuiModel.moveViewCursor 1 0 shift model
        |> TuiInputResult.Update
      | ConsoleKey.LeftArrow ->
        TransformerTuiModel.moveViewCursor 0 -1 shift model
        |> TuiInputResult.Update
      | ConsoleKey.RightArrow ->
        TransformerTuiModel.moveViewCursor 0 1 shift model
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
          TuiInputResult.Update model
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
        | ConsoleKey.F1 ->
          toggleOverlay TuiOverlay.Help model |> TuiInputResult.Update
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
        | ConsoleKey.UpArrow when model.Overlay = TuiOverlay.None
                                 && model.Focus = TuiFocus.Shell
                                 && hasMultipleInputLines model ->
          TransformerTuiModel.moveCursorLine -1 model |> TuiInputResult.Update
        | ConsoleKey.DownArrow when model.Overlay = TuiOverlay.None
                                   && model.Focus = TuiFocus.Shell
                                   && hasMultipleInputLines model ->
          TransformerTuiModel.moveCursorLine 1 model |> TuiInputResult.Update
        | ConsoleKey.UpArrow when isBrowsingHistory model ->
          TransformerTuiModel.historyPrevious model |> TuiInputResult.Update
        | ConsoleKey.DownArrow when isBrowsingHistory model ->
          TransformerTuiModel.historyNext model |> TuiInputResult.Update
        | ConsoleKey.UpArrow when not (String.IsNullOrEmpty model.Input) ->
          let count = List.length completion.Items
          TransformerTuiModel.selectSuggestion -1 count model
          |> TuiInputResult.Update
        | ConsoleKey.DownArrow when not (String.IsNullOrEmpty model.Input) ->
          let count = List.length completion.Items
          TransformerTuiModel.selectSuggestion 1 count model
          |> TuiInputResult.Update
        | ConsoleKey.UpArrow ->
          TransformerTuiModel.historyPrevious model |> TuiInputResult.Update
        | ConsoleKey.DownArrow ->
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
