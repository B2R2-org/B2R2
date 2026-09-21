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
open System.Text.RegularExpressions

/// Visual role of one line retained in the TUI transcript.
[<RequireQualifiedAccess>]
type TuiLineKind =
  | Command
  | CommandContinuation
  | Output
  | Error
  | System
  | Selection
  | Cursor

/// One logical, unwrapped line in the TUI transcript.
type TuiLine =
  { Kind: TuiLineKind
    Text: string }

[<RequireQualifiedAccess>]
module TransformerTuiText =
  let private ansiPattern = Regex("\x1B\[[0-?]*[ -/]*[@-~]")

  let containsAnsi (text: string) =
    not (isNull text) && ansiPattern.IsMatch text

  let matchAnsi text index = ansiPattern.Match(text, index)

  let stripAnsi (text: string) = ansiPattern.Replace(text, "")

  let sanitize (text: string) =
    let builder = Text.StringBuilder()
    for chr in stripAnsi text do
      if chr = '\t' then
        builder.Append ' ' |> ignore
      elif Char.IsControl chr then
        ()
      else
        builder.Append chr |> ignore
    builder.ToString()

  let wrapWithOffsets width text =
    let text = sanitize text
    let rec loop lines start =
      let remaining = text.Length - start
      if remaining <= width then
        let line = if remaining = 0 then "" else text[start..]
        List.rev ((start, text.Length, line) :: lines)
      else
        let candidate = text.Substring(start, width)
        let breakAt = candidate.LastIndexOf ' '
        let breakAt = if breakAt <= 0 then width else breakAt
        let finish = start + breakAt
        let line = text.Substring(start, breakAt)
        let rec skipWhitespace index =
          if index < text.Length && Char.IsWhiteSpace text[index] then
            skipWhitespace (index + 1)
          else
            index
        loop ((start, finish, line) :: lines) (skipWhitespace finish)
    if width <= 0 then
      [ 0, 0, "" ]
    elif String.IsNullOrEmpty text then
      [ 0, 0, "" ]
    else
      loop [] 0

  let wrap width text =
    wrapWithOffsets width text |> List.map (fun (_, _, line) -> line)

  let linePrefix = function
    | TuiLineKind.Command ->
      "> "
    | TuiLineKind.CommandContinuation ->
      "  "
    | TuiLineKind.Error ->
      "! "
    | TuiLineKind.System ->
      "* "
    | TuiLineKind.Output ->
      "  "
    | TuiLineKind.Selection ->
      "> "
    | TuiLineKind.Cursor ->
      "  "

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
  | Message
  | CommandPalette

/// Which pane receives Up/Down when no overlay is open.
[<RequireQualifiedAccess>]
type TuiFocus =
  | Shell
  | Transcript

/// Relative placement of the shell input and completion panes.
[<RequireQualifiedAccess>]
type TuiBottomPaneOrder =
  | ShellAboveSuggestions
  | SuggestionsAboveShell

/// Cursor location inside a text pane.
type TuiTextCursor =
  { Line: int
    Column: int }

/// View pane state for one command result.
type TuiViewPane =
  { BlockIndex: int
    Lines: TuiLine array
    Cursor: TuiTextCursor
    Anchor: TuiTextCursor option
    FindText: string
    IsFinding: bool }

/// Persistent transcript optimized for appending small batches of lines.
type TuiTranscript =
  private
    { Leading: TuiLine list
      Trailing: TuiLine list
      Length: int
      CommandCount: int }

[<RequireQualifiedAccess>]
module TuiTranscript =
  let empty =
    { Leading = []
      Trailing = []
      Length = 0
      CommandCount = 0 }

  let ofList lines =
    { Leading = lines
      Trailing = []
      Length = List.length lines
      CommandCount =
        lines
        |> List.filter (fun line -> line.Kind = TuiLineKind.Command)
        |> List.length }

  let toList transcript =
    if List.isEmpty transcript.Trailing then
      transcript.Leading
    else
      transcript.Leading @ List.rev transcript.Trailing

  let append lines transcript =
    let folder (trailing, length, commands) line =
      let commands =
        if line.Kind = TuiLineKind.Command then commands + 1 else commands
      line :: trailing, length + 1, commands
    let trailing, length, commands =
      lines
      |> List.fold folder
        (transcript.Trailing, transcript.Length, transcript.CommandCount)
    { transcript with
        Trailing = trailing
        Length = length
        CommandCount = commands }

  let length transcript = transcript.Length

  let commandCount transcript = transcript.CommandCount

/// UI state independent from terminal rendering and key reading.
type TransformerTuiModel =
  { Session: TransformerReplState
    Transcript: TuiTranscript
    ResultBlocks: Map<int, Lazy<TuiLine list>>
    LastViewLines: TuiLine list
    Input: string
    Cursor: int
    PaletteInput: string
    PaletteCursor: int
    PaletteFilter: string
    PaletteSuggestionIndex: int
    PreferredInputColumn: int option
    ScrollOffset: int
    TranscriptViewportStart: int option
    TranscriptCursor: TuiTextCursor
    TranscriptFindText: string
    IsFindingTranscript: bool
    ViewPane: TuiViewPane option
    HistoryIndex: int option
    SuggestionIndex: int
    Overlay: TuiOverlay
    Focus: TuiFocus
    OverlaySelection: int
    FoldTarget: int option
    CollapsedCommands: Set<int>
    SidebarWidth: int option
    SuggestionHeight: int
    BottomPaneOrder: TuiBottomPaneOrder
    Status: string
    IsBusy: bool
    SpinnerFrame: int }

module TransformerTuiModel =
  let private maximumTranscriptLines = 5000

  let defaultSuggestionHeight = 7

  let private fixedFrameRows = 5

  let private inputLineCount (input: string) =
    input.Replace("\r\n", "\n").Replace('\r', '\n').Split '\n'
    |> Array.length

  let private maximumSuggestionHeight terminalHeight =
    max 1 (terminalHeight - fixedFrameRows - 2)

  let suggestionHeight terminalHeight (model: TransformerTuiModel) =
    let maximum = maximumSuggestionHeight terminalHeight
    max 1 (min maximum model.SuggestionHeight)

  let shellInputCapacity terminalHeight model =
    let suggestions = suggestionHeight terminalHeight model
    max 1 (terminalHeight - fixedFrameRows - suggestions - 1)

  let visibleShellInputRows terminalHeight model =
    min (shellInputCapacity terminalHeight model) (inputLineCount model.Input)

  let transcriptHeight terminalHeight model =
    let suggestions = suggestionHeight terminalHeight model
    let inputRows = visibleShellInputRows terminalHeight model
    max 1 (terminalHeight - fixedFrameRows - suggestions - inputRows)

  let transcriptBodyWidth terminalWidth model =
    let defaultRightWidth =
      if terminalWidth >= 100 then min 34 (terminalWidth / 3) else 0
    let rightWidth =
      match (model: TransformerTuiModel).SidebarWidth with
      | Some requested when requested <= 0 ->
        0
      | Some requested when terminalWidth >= 60 ->
        max 20 (min (terminalWidth - 40) requested)
      | Some _ ->
        0
      | None ->
        defaultRightWidth
    terminalWidth - rightWidth - (if rightWidth > 0 then 1 else 0)

  let private isCommandLine line =
    line.Kind = TuiLineKind.Command

  let private isCommandContinuation line =
    line.Kind = TuiLineKind.CommandContinuation

  let initial =
    { Session = TransformerReplState.empty
      Transcript =
        [ { Kind = TuiLineKind.System
            Text = "Welcome to B2R2 Transformer interactive analysis." }
          { Kind = TuiLineKind.System
            Text =
              "Load a binary or press F1 to see the interactive guide." } ]
        |> TuiTranscript.ofList
      ResultBlocks = Map.empty
      LastViewLines = []
      Input = ""
      Cursor = 0
      PaletteInput = ""
      PaletteCursor = 0
      PaletteFilter = ""
      PaletteSuggestionIndex = 0
      PreferredInputColumn = None
      ScrollOffset = 0
      TranscriptViewportStart = None
      TranscriptCursor = { Line = 0; Column = 0 }
      TranscriptFindText = ""
      IsFindingTranscript = false
      ViewPane = None
      HistoryIndex = None
      SuggestionIndex = 0
      Overlay = TuiOverlay.None
      Focus = TuiFocus.Shell
      OverlaySelection = 0
      FoldTarget = None
      CollapsedCommands = Set.empty
      SidebarWidth = None
      SuggestionHeight = defaultSuggestionHeight
      BottomPaneOrder = TuiBottomPaneOrder.ShellAboveSuggestions
      Status = "Ready"
      IsBusy = false
      SpinnerFrame = 0 }

  let private trimTranscript transcript =
    if TuiTranscript.length transcript <= maximumTranscriptLines then
      transcript
    else
      let lines = TuiTranscript.toList transcript
      let commandCount =
        TuiTranscript.commandCount transcript
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
      |> TuiTranscript.ofList

  let private commandCount model =
    TuiTranscript.commandCount model.Transcript

  let private transcriptLines model =
    TuiTranscript.toList model.Transcript

  let appendLines kind lines model =
    let additions =
      lines |> List.map (fun text -> { Kind = kind; Text = text })
    { model with
        Transcript =
          model.Transcript
          |> TuiTranscript.append additions
          |> trimTranscript
        ScrollOffset = 0
        TranscriptViewportStart = None }

  let appendTuiLines lines model =
    { model with
        Transcript =
          model.Transcript
          |> TuiTranscript.append lines
          |> trimTranscript
        ScrollOffset = 0
        TranscriptViewportStart = None }

  let private commandLines (command: string) =
    command.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n')
    |> Array.toList
    |> function
      | [] ->
        []
      | first :: rest ->
        { Kind = TuiLineKind.Command; Text = first }
        :: (rest
            |> List.map (fun line ->
              { Kind = TuiLineKind.CommandContinuation; Text = line }))

  let appendCommand command model =
    let index = commandCount model + 1
    { appendTuiLines (commandLines command) model with
        FoldTarget = Some index }

  let clearTranscript model =
    { model with
        Transcript = TuiTranscript.empty
        ResultBlocks = Map.empty
        LastViewLines = []
        TranscriptCursor = { Line = 0; Column = 0 }
        TranscriptFindText = ""
        IsFindingTranscript = false
        ViewPane = None
        CollapsedCommands = Set.empty
        FoldTarget = None
        ScrollOffset = 0
        TranscriptViewportStart = None
        Status = "Transcript cleared" }

  let setSession session model = { model with Session = session }

  let setLastViewLines lines model = { model with LastViewLines = lines }

  let setResultBlock blockIndex lines model =
    { model with ResultBlocks = Map.add blockIndex lines model.ResultBlocks }

  let setStatus status (model: TransformerTuiModel) =
    { model with Status = status }

  let private clearTranscriptFocusStatus model =
    if model.Status = "Transcript focused" then
      { model with Status = "" }
    else
      model

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

  let openCommandPalette model =
    { setOverlay TuiOverlay.CommandPalette model with
        PaletteInput = ""
        PaletteCursor = 0
        PaletteFilter = ""
        PaletteSuggestionIndex = 0 }

  let closeViewPane model =
    { model with
        Overlay = TuiOverlay.None
        ViewPane = None
        ScrollOffset = 0
        TranscriptViewportStart = None
        Status = "View closed" }

  let focusShell model =
    { model with
        Focus = TuiFocus.Shell
        TranscriptViewportStart = None }
    |> clearTranscriptFocusStatus

  let focusTranscript model =
    let target =
      model.FoldTarget
      |> Option.defaultValue (commandCount model)
      |> function
        | 0 ->
          None
        | index ->
          Some index
    { model with
        Focus = TuiFocus.Transcript
        FoldTarget = target }

  let setInput input cursor model =
    { model with
        Input = input
        Cursor = max 0 (min cursor input.Length)
        PreferredInputColumn = None
        Focus = TuiFocus.Shell
        HistoryIndex = None
        SuggestionIndex = 0
        ScrollOffset = 0
        TranscriptViewportStart = None }
    |> clearTranscriptFocusStatus

  let clearInput model = setInput "" 0 model

  let private setPaletteInput input cursor model =
    { model with
        PaletteInput = input
        PaletteCursor = max 0 (min cursor input.Length)
        PaletteFilter = input
        PaletteSuggestionIndex = 0 }

  let insertPaletteText text model =
    if String.IsNullOrEmpty text then
      model
    else
      let before = model.PaletteInput[..model.PaletteCursor - 1]
      let after = model.PaletteInput[model.PaletteCursor..]
      setPaletteInput
        (before + text + after)
        (model.PaletteCursor + text.Length)
        model

  let backspacePalette model =
    if model.PaletteCursor = 0 then
      model
    else
      let before = model.PaletteInput[..model.PaletteCursor - 2]
      let after = model.PaletteInput[model.PaletteCursor..]
      setPaletteInput (before + after) (model.PaletteCursor - 1) model

  let deletePalette model =
    if model.PaletteCursor >= model.PaletteInput.Length then
      model
    else
      let before = model.PaletteInput[..model.PaletteCursor - 1]
      let after = model.PaletteInput[(model.PaletteCursor + 1)..]
      setPaletteInput (before + after) model.PaletteCursor model

  let movePaletteCursor offset model =
    setPaletteInput model.PaletteInput (model.PaletteCursor + offset) model

  let movePaletteHome model = setPaletteInput model.PaletteInput 0 model

  let movePaletteEnd model =
    setPaletteInput model.PaletteInput model.PaletteInput.Length model

  let selectPaletteSuggestion offset candidates model =
    match candidates with
    | [] ->
      { model with PaletteSuggestionIndex = 0 }
    | _ ->
      let count = List.length candidates
      let index = model.PaletteSuggestionIndex + offset
      let index = (index % count + count) % count
      let command, _ = List.item index candidates
      { model with
          PaletteInput = command
          PaletteCursor = command.Length
          PaletteSuggestionIndex = index }

  let applyPaletteSuggestion candidates model =
    candidates
    |> List.tryItem model.PaletteSuggestionIndex
    |> Option.map fst
    |> Option.map (fun command ->
      { model with PaletteInput = command; PaletteCursor = command.Length })
    |> Option.defaultValue model

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
        Cursor = max 0 (min (model.Cursor + offset) model.Input.Length)
        PreferredInputColumn = None }

  let moveHome (model: TransformerTuiModel) =
    { model with Cursor = 0; PreferredInputColumn = None }

  let moveEnd (model: TransformerTuiModel) =
    { model with
        Cursor = model.Input.Length
        PreferredInputColumn = None }

  let moveCursorLine direction (model: TransformerTuiModel) =
    let input = model.Input
    let cursor = max 0 (min model.Cursor input.Length)
    let lineStart = input.LastIndexOf('\n', max 0 (cursor - 1)) + 1
    let column =
      model.PreferredInputColumn |> Option.defaultValue (cursor - lineStart)
    let lineEnd =
      let index = input.IndexOf('\n', lineStart)
      if index < 0 then input.Length else index
    let nextStart, nextEnd =
      if direction < 0 && lineStart > 0 then
        let endIndex = lineStart - 1
        let startIndex = input.LastIndexOf('\n', max 0 (endIndex - 1)) + 1
        Some startIndex, Some endIndex
      elif direction > 0 && lineEnd < input.Length then
        let startIndex = lineEnd + 1
        let endIndex = input.IndexOf('\n', startIndex)
        let endIndex = if endIndex < 0 then input.Length else endIndex
        Some startIndex, Some endIndex
      else
        None, None
    match nextStart, nextEnd with
    | Some startIndex, Some endIndex ->
      { model with
          Cursor = min (startIndex + column) endIndex
          PreferredInputColumn = Some column }
    | _ ->
      model

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

  let setSuggestionHeight height model =
    { model with SuggestionHeight = max 1 height }

  let bottomPaneOrderName model =
    match model.BottomPaneOrder with
    | TuiBottomPaneOrder.ShellAboveSuggestions ->
      "shell-first"
    | TuiBottomPaneOrder.SuggestionsAboveShell ->
      "suggestions-first"

  let setBottomPaneOrder order model =
    { model with BottomPaneOrder = order }

  let toggleBottomPaneOrder model =
    match model.BottomPaneOrder with
    | TuiBottomPaneOrder.ShellAboveSuggestions ->
      setBottomPaneOrder TuiBottomPaneOrder.SuggestionsAboveShell model
    | TuiBottomPaneOrder.SuggestionsAboveShell ->
      setBottomPaneOrder TuiBottomPaneOrder.ShellAboveSuggestions model

  let adjustSidebarWidth defaultWidth delta model =
    let width = model.SidebarWidth |> Option.defaultValue defaultWidth
    let width = max 0 (width + delta)
    { model with
        SidebarWidth = Some width
        Status = $"Sidebar width: {width}" }

  let adjustSuggestionHeight terminalHeight delta model =
    let maximum = maximumSuggestionHeight terminalHeight
    let height = suggestionHeight terminalHeight model
    let height = max 1 (min maximum (height + delta))
    { model with
        SuggestionHeight = height
        Status = $"Suggestion height: {height}" }

  let applyCompletion completion model =
    match Completion.apply completion model.SuggestionIndex model.Input with
    | Some(input, cursor) ->
      setInput input cursor model
    | None ->
      model

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
        | 0 ->
          None
        | index ->
          Some index)
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
      |> List.filter (isCommandContinuation >> not)
    | None ->
      []

  let private selectedTextKind selected kind =
    if selected then TuiLineKind.Selection else kind

  let private wrapTranscriptLine width (line: TuiTranscriptLine) =
    let prefix = TransformerTuiText.linePrefix line.Line.Kind
    if TransformerTuiText.containsAnsi line.Line.Text then
      [ { line with
            Line = { line.Line with Text = prefix + line.Line.Text } } ]
    else
      TransformerTuiText.wrap (max 1 (width - prefix.Length)) line.Line.Text
      |> List.mapi (fun index text ->
        let prefix = if index = 0 then prefix else "  "
        { line with Line = { line.Line with Text = prefix + text } })

  let private sourceContains line source =
    match source with
    | TuiTranscriptSource.Line index ->
      index = line
    | TuiTranscriptSource.HiddenRange(first, last) ->
      first <= line && line <= last
    | TuiTranscriptSource.Synthetic ->
      false

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
        | TuiTranscriptSource.Line index ->
          Some index
        | TuiTranscriptSource.HiddenRange(first, last) ->
          Some first
        | TuiTranscriptSource.Synthetic ->
          None)
    match sourceLines with
    | [] ->
      TuiTranscriptSource.Synthetic
    | first :: _ ->
      let last = sourceLines |> List.last
      TuiTranscriptSource.HiddenRange(first, last)

  let private compactTranscriptBlock
    model
    height
    index
    (lines: TuiTranscriptLine list) =
    let maxInline = max 6 (height - 2)
    let keep = max 2 (min 8 ((height - 3) / 2))
    let command, output =
      let isCommandText (line: TuiTranscriptLine) =
        line.Line.Kind = TuiLineKind.Command
        || line.Line.Kind = TuiLineKind.CommandContinuation
      List.takeWhile isCommandText lines, List.skipWhile isCommandText lines
    let command = command |> List.map (markTranscriptCursor model)
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
    let output = ResizeArray<TuiTranscriptLine>()
    let block = ResizeArray<TuiTranscriptLine>()
    let mutable blockIndex = 0
    let flush () =
      if block.Count > 0 then
        block
        |> Seq.toList
        |> compactTranscriptBlock model height blockIndex
        |> output.AddRange
        block.Clear()
      else
        ()
    let mutable lineIndex = 0
    for line in transcriptLines model do
      let line =
        { Source = TuiTranscriptSource.Line lineIndex
          Line = line }
      match line.Line.Kind with
      | TuiLineKind.Command ->
        flush ()
        blockIndex <- blockIndex + 1
        block.Add line
      | _ ->
        block.Add line
      lineIndex <- lineIndex + 1
    flush ()
    Seq.toList output

  let transcriptDisplayRows width height model =
    transcriptDisplayLines height model
    |> List.collect (wrapTranscriptLine width)

  let private latestDisplayCommandIndex
    (lines: TuiTranscriptLine list) =
    lines
    |> List.mapi (fun index line -> index, line)
    |> List.filter (fun (_, line) -> line.Line.Kind = TuiLineKind.Command)
    |> List.tryLast
    |> Option.map fst

  let private selectedDisplayLineIndex
    (lines: TuiTranscriptLine list) =
    lines
    |> List.tryFindIndex (fun line ->
      line.Line.Kind = TuiLineKind.Selection)

  let private clampViewportStart height count start =
    max 0 (min start (max 0 (count - height)))

  let private autoTranscriptViewportStart height
                                          (lines: TuiTranscriptLine list) =
    let anchor = latestDisplayCommandIndex lines |> Option.defaultValue 0
    let maximumStart = max 0 (List.length lines - height)
    let start =
      match selectedDisplayLineIndex lines with
      | Some selected when selected < anchor ->
        selected
      | Some selected when selected >= anchor + height ->
        selected - height + 1
      | _ ->
        anchor
    max 0 (min maximumStart start)

  let transcriptViewportStart width height model =
    let lines = transcriptDisplayRows width height model
    match model.TranscriptViewportStart with
    | Some start ->
      clampViewportStart height (List.length lines) start
    | None ->
      autoTranscriptViewportStart height lines

  let private transcriptDisplayCursorIndex direction width height model =
    transcriptDisplayRows width height model
    |> List.mapi (fun index line -> index, line)
    |> List.choose (fun (index, line: TuiTranscriptLine) ->
      if sourceContains model.TranscriptCursor.Line line.Source then
        Some index
      else
        None)
    |> fun matches ->
      if direction > 0 then
        List.tryLast matches
      else
        List.tryHead matches

  let private transcriptLineOfSource direction model source =
    match source with
    | TuiTranscriptSource.Line index ->
      Some index
    | TuiTranscriptSource.HiddenRange(first, last) ->
      let cursor = model.TranscriptCursor.Line
      if first <= cursor && cursor <= last then
        if direction < 0 then
          Some(first - 1)
        elif direction > 0 then
          Some(last + 1)
        else
          Some cursor
      elif direction < 0 then
        Some last
      else
        Some first
    | TuiTranscriptSource.Synthetic ->
      Some model.TranscriptCursor.Line

  let moveTranscriptCursorInView width height rowDelta columnDelta model =
    let transcript = transcriptLines model
    let displayLines = transcriptDisplayRows width height model
    let current =
      transcriptDisplayCursorIndex rowDelta width height model
      |> Option.defaultValue 0
    let currentStart = transcriptViewportStart width height model
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
      |> clampCursor transcript
    let next =
      { model with
          TranscriptCursor = cursor
          FoldTarget = blockAtLine cursor.Line transcript
          ScrollOffset = 0
          Status = "Transcript focused" }
    let nextLines = transcriptDisplayRows width height next
    let nextCursor =
      transcriptDisplayCursorIndex rowDelta width height next
      |> Option.defaultValue target
    let nextStart =
      if rowDelta = -1 && nextCursor <= currentStart then
        nextCursor - 1
      elif rowDelta = 1 && nextCursor >= currentStart + height - 1 then
        nextCursor - height + 2
      elif nextCursor < currentStart then
        nextCursor
      elif nextCursor >= currentStart + height then
        nextCursor - height + 1
      else
        currentStart
    { next with
        TranscriptViewportStart =
          Some(clampViewportStart height (List.length nextLines) nextStart) }

  let focusTranscriptAt offset model =
    let transcript = transcriptLines model
    let baseLine =
      if model.Focus = TuiFocus.Shell then
        commandPositions transcript
        |> List.tryLast
        |> Option.defaultValue (max 0 (List.length transcript - 1))
      else
        model.TranscriptCursor.Line
    let cursor =
      { model.TranscriptCursor with Line = baseLine + offset }
      |> clampCursor transcript
    { model with
        Focus = TuiFocus.Transcript
        TranscriptCursor = cursor
        FoldTarget = blockAtLine cursor.Line transcript
        ScrollOffset = 0
        Status = "Transcript focused" }

  let moveTranscriptCursor lineDelta columnDelta model =
    let transcript = transcriptLines model
    let cursor =
      { Line = model.TranscriptCursor.Line + lineDelta
        Column = model.TranscriptCursor.Column + columnDelta }
      |> clampCursor transcript
    { model with
        TranscriptCursor = cursor
        FoldTarget = blockAtLine cursor.Line transcript
        Status = "Transcript focused" }

  let moveTranscriptCommand width height offset model =
    let positions = commandPositions (transcriptLines model)
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
      let next =
        { model with
            Focus = TuiFocus.Transcript
            TranscriptCursor = cursor
            FoldTarget = Some(index + 1)
            ScrollOffset = 0
            Status = $"Selected result #{index + 1}" }
      let lines = transcriptDisplayRows width height next
      let cursorIndex =
        transcriptDisplayCursorIndex 0 width height next
        |> Option.defaultValue 0
      let start =
        cursorIndex - (height / 2)
        |> clampViewportStart height (List.length lines)
      { next with TranscriptViewportStart = Some start }

  let setTranscriptFind active model =
    { model with IsFindingTranscript = active; TranscriptFindText = "" }

  let appendTranscriptFind chr model =
    { model with TranscriptFindText = model.TranscriptFindText + string chr }

  let backspaceTranscriptFind model =
    if String.IsNullOrEmpty model.TranscriptFindText then
      model
    else
      { model with
          TranscriptFindText =
            model.TranscriptFindText[..model.TranscriptFindText.Length - 2] }

  let private transcriptLineContains
    (needle: string)
    (line: TuiTranscriptLine) =
    line.Line.Text.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0

  let private transcriptFindCandidates width height model =
    let lines = transcriptDisplayRows width height model |> List.toArray
    let cursor =
      if model.Focus = TuiFocus.Transcript then
        transcriptDisplayCursorIndex 1 width height model
        |> Option.defaultValue -1
      else
        transcriptViewportStart width height model - 1
    let start = max 0 (min lines.Length (cursor + 1))
    let indexed = lines |> Array.mapi (fun index line -> index, line)
    Array.append (indexed |> Array.skip start) (indexed |> Array.truncate start)

  let private transcriptFindCursor model (line: TuiTranscriptLine) =
    let transcript = transcriptLines model
    match line.Source with
    | TuiTranscriptSource.Line index ->
      let text =
        transcript
        |> List.tryItem index
        |> Option.map (fun (line: TuiLine) -> line.Text)
        |> Option.defaultValue ""
      let column =
        text.IndexOf(model.TranscriptFindText,
                     StringComparison.OrdinalIgnoreCase)
      { Line = index; Column = max 0 column }
    | source ->
      let line =
        transcriptLineOfSource 0 model source
        |> Option.defaultValue model.TranscriptCursor.Line
      { Line = line; Column = 0 }
    |> clampCursor transcript

  /// Searches only rows kept in the compact transcript, never expanded output.
  let findInTranscript width height model =
    if String.IsNullOrEmpty model.TranscriptFindText then
      model
    else
      let candidates = transcriptFindCandidates width height model
      let contains =
        snd >> transcriptLineContains model.TranscriptFindText
      match candidates |> Array.tryFind contains with
      | Some(index, line) ->
        let transcript = transcriptLines model
        let cursor = transcriptFindCursor model line
        let next =
          { model with
              Focus = TuiFocus.Transcript
              TranscriptCursor = cursor
              IsFindingTranscript = false
              FoldTarget = blockAtLine cursor.Line transcript
              ScrollOffset = 0
              Status =
                $"Found '{model.TranscriptFindText}' at "
                + $"{cursor.Line + 1}:{cursor.Column + 1}" }
        let lineCount = transcriptDisplayRows width height next |> List.length
        let start = clampViewportStart height lineCount (index - (height / 2))
        { next with TranscriptViewportStart = Some start }
      | None ->
        { model with Status = $"Not found: {model.TranscriptFindText}" }

  let openViewPane blockIndex model =
    let lines =
      model.ResultBlocks
      |> Map.tryFind blockIndex
      |> Option.map (fun lines -> lines.Value)
      |> Option.defaultWith (fun () ->
        outputLinesOfBlock blockIndex (transcriptLines model))
    let lines =
      if List.isEmpty lines then
        [ { Kind = TuiLineKind.System; Text = "This command has no output." } ]
      else
        lines
    let pane =
      { BlockIndex = blockIndex
        Lines = List.toArray lines
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
      transcriptLines model
      |> blockAtLine model.TranscriptCursor.Line
      |> Option.orElse model.FoldTarget
      |> Option.orElse (commandCount model |> function
        | 0 ->
          None
        | count ->
          Some count)
    match blockIndex with
    | Some index ->
      openViewPane index model
    | None ->
      { model with
          Status = "There is no command result to view"
          Overlay = TuiOverlay.Message }

  let private clampViewCursor pane cursor =
    let lineCount = pane.Lines.Length
    let line = max 0 (min cursor.Line (max 0 (lineCount - 1)))
    let text =
      pane.Lines
      |> Array.tryItem line
      |> Option.map _.Text
      |> Option.defaultValue ""
    { Line = line; Column = max 0 (min cursor.Column text.Length) }

  let private moveViewCursorHorizontally pane offset =
    let cursor = clampViewCursor pane pane.Cursor
    let direction = sign offset
    let mutable line = cursor.Line
    let mutable column = cursor.Column
    let mutable remaining = abs offset
    while remaining > 0 do
      let text =
        pane.Lines
        |> Array.tryItem line
        |> Option.map _.Text
        |> Option.defaultValue ""
      if direction > 0 && column < text.Length then
        column <- column + 1
        remaining <- remaining - 1
      elif direction > 0 && line < pane.Lines.Length - 1 then
        line <- line + 1
        column <- 0
        remaining <- remaining - 1
      elif direction < 0 && column > 0 then
        column <- column - 1
        remaining <- remaining - 1
      elif direction < 0 && line > 0 then
        line <- line - 1
        column <- pane.Lines[line].Text.Length
        remaining <- remaining - 1
      else
        remaining <- 0
    { Line = line; Column = column }

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
        if lineDelta = 0 && columnDelta <> 0 then
          moveViewCursorHorizontally pane columnDelta
        else
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
      let start = min (pane.Cursor.Line + 1) pane.Lines.Length
      let indexed = pane.Lines |> Array.mapi (fun index line -> index, line)
      let candidates =
        Array.append (indexed |> Array.skip start)
          (indexed |> Array.truncate start)
      match candidates |> Array.tryFind (snd >> lineContains pane.FindText) with
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
    if anchor.Line < cursor.Line then
      anchor, cursor
    elif anchor.Line > cursor.Line then
      cursor, anchor
    elif anchor.Column <= cursor.Column then
      anchor, cursor
    else
      cursor, anchor

  let selectedViewText pane =
    let cleanText (text: string) =
      let text = TransformerTuiText.stripAnsi text
      text
      |> Seq.map (fun chr ->
        if chr = '\t' then
          ' '
        elif Char.IsControl chr then
          ' '
        else
          chr)
      |> Array.ofSeq
      |> String
    let sliceText start finish (text: string) =
      let text = cleanText text
      let start = max 0 (min start text.Length)
      let finish = max start (min finish text.Length)
      if start >= finish then "" else text[start..finish - 1]
    match pane.Anchor with
    | None ->
      pane.Lines
      |> Array.tryItem pane.Cursor.Line
      |> Option.map (fun line -> cleanText line.Text)
      |> Option.defaultValue ""
    | Some anchor ->
      let first, last = orderedSelection anchor pane.Cursor
      pane.Lines
      |> Array.mapi (fun index line -> index, line.Text)
      |> Array.choose (fun (index, text) ->
        let text = cleanText text
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
      |> String.concat "\n"

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
