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

/// Visual role of one line retained in the TUI transcript.
[<RequireQualifiedAccess>]
type TuiLineKind =
  | Command
  | Output
  | Error
  | System
  | Selection
  | Cursor

/// One logical, unwrapped line in the TUI transcript.
type TuiLine =
  { Kind: TuiLineKind
    Text: string }

/// Source represented by one rendered transcript row.
[<RequireQualifiedAccess>]
type TuiTranscriptSource =
  | Line of int
  | HiddenRange of int * int
  | Synthetic

/// One logical transcript row after folding and large-output compaction.
type TuiTranscriptLine =
  { Source: TuiTranscriptSource
    Line: TuiLine }

/// Full-screen panels that temporarily replace the transcript view.
[<RequireQualifiedAccess>]
type TuiOverlay =
  | None
  | Help
  | Actions
  | Bindings
  | View
  | Inspect
  | Values
  | Log

/// Which pane receives Up/Down when no overlay is open.
[<RequireQualifiedAccess>]
type TuiFocus =
  | Shell
  | Transcript

/// Cursor location inside a text pane.
type TuiTextCursor =
  { Line: int
    Column: int }

/// View pane state for one command result.
type TuiViewPane =
  { BlockIndex: int
    Lines: TuiLine list
    Cursor: TuiTextCursor
    Anchor: TuiTextCursor option
    FindText: string
    IsFinding: bool }

/// UI state independent from terminal rendering and key reading.
type TransformerTuiModel =
  { Session: TransformerReplState
    Transcript: TuiLine list
    ResultBlocks: Map<int, Lazy<TuiLine list>>
    LastViewLines: TuiLine list
    Input: string
    Cursor: int
    ScrollOffset: int
    TranscriptCursor: TuiTextCursor
    ViewPane: TuiViewPane option
    HistoryIndex: int option
    SuggestionIndex: int
    Overlay: TuiOverlay
    Focus: TuiFocus
    OverlaySelection: int
    FoldTarget: int option
    CollapsedCommands: Set<int>
    SidebarWidth: int option
    TranscriptHeight: int option
    ShellHeight: int
    Status: string
    IsBusy: bool
    SpinnerFrame: int }

module TransformerTuiModel =
  let private maximumTranscriptLines = 5000

  let private isCommandLine line =
    line.Kind = TuiLineKind.Command

  let initial =
    { Session = TransformerReplState.empty
      Transcript =
        [ { Kind = TuiLineKind.System
            Text = "Welcome to B2R2 Transformer interactive analysis." }
          { Kind = TuiLineKind.System
            Text =
              "Load a binary or press F1 to see the interactive guide." } ]
      ResultBlocks = Map.empty
      LastViewLines = []
      Input = ""
      Cursor = 0
      ScrollOffset = 0
      TranscriptCursor = { Line = 0; Column = 0 }
      ViewPane = None
      HistoryIndex = None
      SuggestionIndex = 0
      Overlay = TuiOverlay.None
      Focus = TuiFocus.Shell
      OverlaySelection = 0
      FoldTarget = None
      CollapsedCommands = Set.empty
      SidebarWidth = None
      TranscriptHeight = None
      ShellHeight = 4
      Status = "Ready"
      IsBusy = false
      SpinnerFrame = 0 }

  let private trimTranscript lines =
    if List.length lines <= maximumTranscriptLines then
      lines
    else
      let commandCount =
        lines |> List.filter isCommandLine |> List.length
      let outputBudget = max 0 (maximumTranscriptLines - commandCount)
      let folder (remaining, output) line =
        if isCommandLine line then
          remaining, line :: output
        elif remaining > 0 then
          remaining - 1, line :: output
        else
          remaining, output
      lines
      |> List.rev
      |> List.fold folder (outputBudget, [])
      |> snd

  let private commandCount model =
    model.Transcript
    |> List.filter (fun line -> line.Kind = TuiLineKind.Command)
    |> List.length

  let appendLines kind lines model =
    let additions =
      lines |> List.map (fun text -> { Kind = kind; Text = text })
    { model with
        Transcript = trimTranscript (model.Transcript @ additions)
        ScrollOffset = 0 }

  let appendTuiLines lines model =
    { model with
        Transcript = trimTranscript (model.Transcript @ lines)
        ScrollOffset = 0 }

  let appendCommand command model =
    let index = commandCount model + 1
    { appendLines TuiLineKind.Command [ command ] model with
        FoldTarget = Some index }

  let clearTranscript model =
    { model with
        Transcript = []
        ResultBlocks = Map.empty
        LastViewLines = []
        TranscriptCursor = { Line = 0; Column = 0 }
        ViewPane = None
        CollapsedCommands = Set.empty
        FoldTarget = None
        ScrollOffset = 0
        Status = "Transcript cleared" }

  let setSession session model = { model with Session = session }

  let setLastViewLines lines model = { model with LastViewLines = lines }

  let setResultBlock blockIndex lines model =
    { model with ResultBlocks = Map.add blockIndex lines model.ResultBlocks }

  let setStatus status (model: TransformerTuiModel) =
    { model with Status = status }

  let setBusy isBusy model =
    { model with IsBusy = isBusy; SpinnerFrame = 0 }

  let advanceSpinner model =
    { model with SpinnerFrame = model.SpinnerFrame + 1 }

  let setOverlay overlay model =
    { model with
        Overlay = overlay
        Focus = TuiFocus.Shell
        OverlaySelection = 0
        ScrollOffset = 0 }

  let closeOverlay model =
    { setOverlay TuiOverlay.None model with ViewPane = None }

  let closeViewPane model =
    { model with
        Overlay = TuiOverlay.None
        ViewPane = None
        ScrollOffset = 0
        Status = "View closed" }

  let focusShell model =
    { model with
        Focus = TuiFocus.Shell }

  let focusTranscript model =
    let target =
      model.FoldTarget
      |> Option.defaultValue (commandCount model)
      |> function
        | 0 -> None
        | index -> Some index
    { model with
        Focus = TuiFocus.Transcript
        FoldTarget = target }

  let setInput input cursor model =
    { model with
        Input = input
        Cursor = max 0 (min cursor input.Length)
        Focus = TuiFocus.Shell
        HistoryIndex = None
        SuggestionIndex = 0
        ScrollOffset = 0 }

  let clearInput model = setInput "" 0 model

  let insert character model =
    let before = model.Input[..model.Cursor - 1]
    let after = model.Input[model.Cursor..]
    setInput (before + string character + after) (model.Cursor + 1) model

  let insertText text model =
    if String.IsNullOrEmpty text then
      model
    else
      let before = model.Input[..model.Cursor - 1]
      let after = model.Input[model.Cursor..]
      setInput (before + text + after) (model.Cursor + text.Length) model

  let backspace model =
    if model.Cursor = 0 then
      model
    else
      let before = model.Input[..model.Cursor - 2]
      let after = model.Input[model.Cursor..]
      setInput (before + after) (model.Cursor - 1) model

  let delete model =
    if model.Cursor >= model.Input.Length then
      model
    else
      let before = model.Input[..model.Cursor - 1]
      let after = model.Input[(model.Cursor + 1)..]
      setInput (before + after) model.Cursor model

  let moveCursor offset (model: TransformerTuiModel) =
    { model with
        Cursor = max 0 (min (model.Cursor + offset) model.Input.Length) }

  let moveHome (model: TransformerTuiModel) = { model with Cursor = 0 }

  let moveEnd (model: TransformerTuiModel) =
    { model with Cursor = model.Input.Length }

  let deleteToStart model =
    let input = model.Input[model.Cursor..]
    setInput input 0 model

  let deleteToEnd model =
    let input = model.Input[..model.Cursor - 1]
    setInput input model.Cursor model

  let deleteWord model =
    let rec skipSpaces index =
      if index > 0 && Char.IsWhiteSpace model.Input[index - 1] then
        skipSpaces (index - 1)
      else
        index
    let rec skipWord index =
      if index > 0 && not (Char.IsWhiteSpace model.Input[index - 1]) then
        skipWord (index - 1)
      else
        index
    let start = skipWord (skipSpaces model.Cursor)
    let before = model.Input[..start - 1]
    let after = model.Input[model.Cursor..]
    setInput (before + after) start model

  let private historyItem index model =
    model.Session.CommandHistory |> List.tryItem index

  let historyPrevious model =
    let index =
      model.HistoryIndex
      |> Option.map ((+) 1)
      |> Option.defaultValue 0
    match historyItem index model with
    | Some command ->
      { setInput command command.Length model with HistoryIndex = Some index }
    | None ->
      model

  let historyNext model =
    match model.HistoryIndex with
    | Some index when index > 0 ->
      let index = index - 1
      match historyItem index model with
      | Some command ->
        { setInput command command.Length model with
            HistoryIndex = Some index }
      | None ->
        model
    | Some _ ->
      clearInput model
    | None ->
      model

  let selectSuggestion offset count model =
    if count = 0 then
      { model with SuggestionIndex = 0 }
    else
      let index = Completion.select offset count model.SuggestionIndex
      { model with SuggestionIndex = index }

  let selectOverlay offset count model =
    if count = 0 then
      { model with OverlaySelection = 0 }
    else
      let index = (model.OverlaySelection + offset + count) % count
      { model with OverlaySelection = index }

  let setSidebarWidth width model =
    { model with SidebarWidth = width }

  let setTranscriptHeight height model =
    { model with TranscriptHeight = height }

  let setShellHeight height model =
    { model with ShellHeight = max 1 height }

  let adjustSidebarWidth defaultWidth delta model =
    let width = model.SidebarWidth |> Option.defaultValue defaultWidth
    let width = max 0 (width + delta)
    { model with
        SidebarWidth = Some width
        Status = $"Sidebar width: {width}" }

  let adjustTranscriptHeight defaultHeight delta model =
    let height = model.TranscriptHeight |> Option.defaultValue defaultHeight
    let height = max 1 (height + delta)
    { model with
        TranscriptHeight = Some height
        Status = $"Transcript height: {height}" }

  let applyCompletion completion model =
    match Completion.apply completion model.SuggestionIndex model.Input with
    | Some(input, cursor) -> setInput input cursor model
    | None -> model

  let selectFoldTarget offset model =
    let count = commandCount model
    if count = 0 then
      { model with Status = "There is no command result to select" }
    else
      let current = model.FoldTarget |> Option.defaultValue count
      let index = max 1 (min count (current + offset))
      { model with
          Focus = TuiFocus.Transcript
          FoldTarget = Some index
          Status = $"Selected result #{index}" }

  let toggleLatestFold model =
    let target =
      model.FoldTarget
      |> Option.orElse (commandCount model |> function
        | 0 -> None
        | index -> Some index)
    match target with
    | None ->
      { model with Status = "There is no command result to fold" }
    | Some index when Set.contains index model.CollapsedCommands ->
      { model with
          FoldTarget = Some index
          CollapsedCommands = Set.remove index model.CollapsedCommands
          Status = $"Unfolded result #{index}" }
    | Some index ->
      { model with
          FoldTarget = Some index
          CollapsedCommands = Set.add index model.CollapsedCommands
          Status = $"Folded result #{index}" }

  let scroll amount model =
    { model with ScrollOffset = max 0 (model.ScrollOffset + amount) }

  let private clampCursor lines cursor =
    let lineCount = List.length lines
    let line = max 0 (min cursor.Line (max 0 (lineCount - 1)))
    let text =
      lines |> List.tryItem line |> Option.map _.Text |> Option.defaultValue ""
    { Line = line; Column = max 0 (min cursor.Column text.Length) }

  let private commandPositions transcript =
    transcript
    |> List.mapi (fun index line -> index, line)
    |> List.choose (fun (index, line) ->
      if line.Kind = TuiLineKind.Command then Some index else None)

  let private blockRange blockIndex transcript =
    let positions = commandPositions transcript
    positions
    |> List.tryItem (blockIndex - 1)
    |> Option.map (fun start ->
      let finish =
        positions
        |> List.tryItem blockIndex
        |> Option.defaultValue (List.length transcript)
      start, finish)

  let private blockAtLine line transcript =
    commandPositions transcript
    |> List.mapi (fun index start -> index + 1, start)
    |> List.filter (fun (_, start) -> start <= line)
    |> List.tryLast
    |> Option.map fst

  let outputLinesOfBlock blockIndex transcript =
    match blockRange blockIndex transcript with
    | Some(start, finish) ->
      transcript
      |> List.skip (start + 1)
      |> List.truncate (max 0 (finish - start - 1))
    | None ->
      []

  let private selectedTextKind selected kind =
    if selected then TuiLineKind.Selection else kind

  let private sourceContains line source =
    match source with
    | TuiTranscriptSource.Line index -> index = line
    | TuiTranscriptSource.HiddenRange(first, last) ->
      first <= line && line <= last
    | TuiTranscriptSource.Synthetic -> false

  let private cursorOnSource model source =
    model.Focus = TuiFocus.Transcript
    && model.Overlay = TuiOverlay.None
    && sourceContains model.TranscriptCursor.Line source

  let private markTranscriptCursor model
                                   (line: TuiTranscriptLine)
                                   : TuiTranscriptLine =
    { line with
        Line =
          { line.Line with
              Kind =
                selectedTextKind
                  (cursorOnSource model line.Source)
                  line.Line.Kind } }

  let private sourceRange (lines: TuiTranscriptLine list) =
    let sourceLines =
      lines
      |> List.choose (fun line ->
        match line.Source with
        | TuiTranscriptSource.Line index -> Some index
        | TuiTranscriptSource.HiddenRange(first, last) -> Some first
        | TuiTranscriptSource.Synthetic -> None)
    match sourceLines with
    | [] -> TuiTranscriptSource.Synthetic
    | first :: _ ->
      let last = sourceLines |> List.last
      TuiTranscriptSource.HiddenRange(first, last)

  let private compactTranscriptBlock model height index
                                     (lines: TuiTranscriptLine list) =
    let maxInline = max 6 (height - 2)
    let keep = max 2 (min 8 ((height - 3) / 2))
    let command, output =
      match lines with
      | command :: output when command.Line.Kind = TuiLineKind.Command ->
        [ markTranscriptCursor model command ], output
      | _ -> [], lines
    if Set.contains index model.CollapsedCommands then
      let source = sourceRange output
      let selected = cursorOnSource model source
      let kind = selectedTextKind selected TuiLineKind.System
      command @
        [ { Source = source
            Line = { Kind = kind; Text = $"<< result #{index} folded >>" } } ]
    elif List.length output <= maxInline then
      command @ (output |> List.map (markTranscriptCursor model))
    else
      let head = output |> List.truncate keep
      let hidden =
        output
        |> List.skip keep
        |> List.truncate (List.length output - (keep * 2))
      let tail = output |> List.skip (List.length output - keep)
      let source = sourceRange hidden
      let hiddenCount = List.length hidden
      let selected = cursorOnSource model source
      let kind = selectedTextKind selected TuiLineKind.System
      let text =
        $"<< {hiddenCount} transcript lines hidden; Enter opens view >>"
      let marker =
        { Source = source
          Line =
            { Kind = kind
              Text = text } }
      command
      @ (head |> List.map (markTranscriptCursor model))
      @ [ marker ]
      @ (tail |> List.map (markTranscriptCursor model))

  let transcriptDisplayLines height (model: TransformerTuiModel)
      : TuiTranscriptLine list =
    let flush index block output =
      match block with
      | [] -> output
      | block ->
        output @ compactTranscriptBlock model height index (List.rev block)
    let folder (index, block, output) (line: TuiTranscriptLine) =
      match line.Line.Kind with
      | TuiLineKind.Command ->
        let output = flush index block output
        index + 1, [ line ], output
      | _ ->
        index, line :: block, output
    let index, block, output =
      model.Transcript
      |> List.mapi (fun index (line: TuiLine) ->
        { Source = TuiTranscriptSource.Line index
          Line = line })
      |> List.fold folder (0, [], [])
    flush index block output

  let private transcriptDisplayCursorIndex height model =
    transcriptDisplayLines height model
    |> List.tryFindIndex (fun (line: TuiTranscriptLine) ->
      sourceContains model.TranscriptCursor.Line line.Source)

  let private transcriptLineOfSource direction model source =
    match source with
    | TuiTranscriptSource.Line index -> Some index
    | TuiTranscriptSource.HiddenRange(first, last) ->
      if direction < 0 then Some last else Some first
    | TuiTranscriptSource.Synthetic ->
      Some model.TranscriptCursor.Line

  let moveTranscriptCursorInView height rowDelta columnDelta model =
    let displayLines = transcriptDisplayLines height model
    let current =
      transcriptDisplayCursorIndex height model
      |> Option.defaultValue 0
    let target =
      max 0 (min (List.length displayLines - 1) (current + rowDelta))
    let line =
      displayLines
      |> List.tryItem target
      |> Option.bind (fun (line: TuiTranscriptLine) ->
        transcriptLineOfSource rowDelta model line.Source)
      |> Option.defaultValue model.TranscriptCursor.Line
    let cursor =
      { Line = line
        Column = model.TranscriptCursor.Column + columnDelta }
      |> clampCursor model.Transcript
    { model with
        TranscriptCursor = cursor
        FoldTarget = blockAtLine cursor.Line model.Transcript
        Status = "Transcript focused" }

  let focusTranscriptAt offset model =
    let baseLine =
      if model.Focus = TuiFocus.Shell then
        commandPositions model.Transcript
        |> List.tryLast
        |> Option.defaultValue (max 0 (List.length model.Transcript - 1))
      else
        model.TranscriptCursor.Line
    let cursor =
      { model.TranscriptCursor with Line = baseLine + offset }
      |> clampCursor model.Transcript
    { model with
        Focus = TuiFocus.Transcript
        TranscriptCursor = cursor
        FoldTarget = blockAtLine cursor.Line model.Transcript
        Status = "Transcript focused" }

  let moveTranscriptCursor lineDelta columnDelta model =
    let cursor =
      { Line = model.TranscriptCursor.Line + lineDelta
        Column = model.TranscriptCursor.Column + columnDelta }
      |> clampCursor model.Transcript
    { model with
        TranscriptCursor = cursor
        FoldTarget = blockAtLine cursor.Line model.Transcript
        Status = "Transcript focused" }

  let moveTranscriptCommand offset model =
    let positions = commandPositions model.Transcript
    if List.isEmpty positions then
      { model with Status = "There is no command in the transcript" }
    else
      let current =
        positions
        |> List.tryFindIndex (fun line -> line >= model.TranscriptCursor.Line)
        |> Option.defaultValue (List.length positions - 1)
      let index = max 0 (min (List.length positions - 1) (current + offset))
      let line = positions[index]
      let cursor = { Line = line; Column = 0 }
      { model with
          Focus = TuiFocus.Transcript
          TranscriptCursor = cursor
          FoldTarget = Some(index + 1)
          Status = $"Selected result #{index + 1}" }

  let openViewPane blockIndex model =
    let lines =
      model.ResultBlocks
      |> Map.tryFind blockIndex
      |> Option.map (fun lines -> lines.Value)
      |> Option.defaultWith (fun () ->
        outputLinesOfBlock blockIndex model.Transcript)
    let lines =
      if List.isEmpty lines then
        [ { Kind = TuiLineKind.System; Text = "This command has no output." } ]
      else
        lines
    let pane =
      { BlockIndex = blockIndex
        Lines = lines
        Cursor = { Line = 0; Column = 0 }
        Anchor = None
        FindText = ""
        IsFinding = false }
    { model with
        Overlay = TuiOverlay.View
        ViewPane = Some pane
        LastViewLines = lines
        ScrollOffset = 0
        Status = $"View result #{blockIndex}" }

  let openSelectedViewPane model =
    let blockIndex =
      blockAtLine model.TranscriptCursor.Line model.Transcript
      |> Option.orElse model.FoldTarget
      |> Option.orElse (commandCount model |> function
        | 0 -> None
        | count -> Some count)
    match blockIndex with
    | Some index -> openViewPane index model
    | None -> { model with Status = "There is no command result to view" }

  let private clampViewCursor pane cursor =
    clampCursor pane.Lines cursor

  let private updateViewPane updater model =
    match model.ViewPane with
    | Some pane ->
      { model with ViewPane = Some(updater pane) }
    | None ->
      model

  let moveViewCursor lineDelta columnDelta extend model =
    let update pane =
      let anchor =
        if extend then
          pane.Anchor |> Option.defaultValue pane.Cursor |> Some
        else
          None
      let cursor =
        { Line = pane.Cursor.Line + lineDelta
          Column = pane.Cursor.Column + columnDelta }
        |> clampViewCursor pane
      { pane with Cursor = cursor; Anchor = anchor }
    updateViewPane update model

  let pageViewCursor amount extend model =
    moveViewCursor amount 0 extend model

  let setViewFind active model =
    let update pane = { pane with IsFinding = active; FindText = "" }
    updateViewPane update model

  let appendViewFind chr model =
    let update pane =
      { pane with FindText = pane.FindText + string chr }
    updateViewPane update model

  let backspaceViewFind model =
    let update pane =
      if String.IsNullOrEmpty pane.FindText then
        pane
      else
        { pane with FindText = pane.FindText[..pane.FindText.Length - 2] }
    updateViewPane update model

  let private lineContains (needle: string) (line: TuiLine) =
    line.Text.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0

  let findInView model =
    match model.ViewPane with
    | Some pane when not (String.IsNullOrEmpty pane.FindText) ->
      let start = min (pane.Cursor.Line + 1) (List.length pane.Lines)
      let indexed = pane.Lines |> List.mapi (fun index line -> index, line)
      let candidates =
        (indexed |> List.skip start) @ (indexed |> List.truncate start)
      match candidates |> List.tryFind (snd >> lineContains pane.FindText) with
      | Some(index, line) ->
        let column =
          line.Text.IndexOf(pane.FindText, StringComparison.OrdinalIgnoreCase)
        let cursor = { Line = index; Column = max 0 column }
        let pane = { pane with Cursor = cursor; IsFinding = false }
        { model with
            ViewPane = Some pane
            Status = $"Found '{pane.FindText}' at {index + 1}:{column + 1}" }
      | None ->
        { model with Status = $"Not found: {pane.FindText}" }
    | _ ->
      model

  let private orderedSelection anchor cursor =
    if anchor.Line < cursor.Line then anchor, cursor
    elif anchor.Line > cursor.Line then cursor, anchor
    elif anchor.Column <= cursor.Column then anchor, cursor
    else cursor, anchor

  let selectedViewText pane =
    let sliceText start finish (text: string) =
      let start = max 0 (min start text.Length)
      let finish = max start (min finish text.Length)
      if start >= finish then "" else text[start..finish - 1]
    match pane.Anchor with
    | None ->
      pane.Lines
      |> List.tryItem pane.Cursor.Line
      |> Option.map _.Text
      |> Option.defaultValue ""
    | Some anchor ->
      let first, last = orderedSelection anchor pane.Cursor
      pane.Lines
      |> List.mapi (fun index line -> index, line.Text)
      |> List.choose (fun (index, text) ->
        if index < first.Line || index > last.Line then
          None
        elif first.Line = last.Line then
          Some(sliceText first.Column last.Column text)
        elif index = first.Line then
          Some(sliceText first.Column text.Length text)
        elif index = last.Line then
          Some(sliceText 0 last.Column text)
        else
          Some text)
      |> String.concat " "

  let insertViewSelection model =
    match model.ViewPane with
    | Some pane ->
      let text = selectedViewText pane
      model
      |> closeViewPane
      |> insertText text
      |> setStatus "Inserted view selection"
    | None ->
      model
