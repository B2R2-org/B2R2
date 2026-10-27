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

  let private styleAfterAnsi style (sequence: string) =
    if sequence.EndsWith "m" then
      let parameters = sequence[2..sequence.Length - 2]
      if parameters = "" || parameters = "0" then
        ""
      elif parameters.Split(';')[0] = "0" then
        sequence
      else
        style + sequence
    else
      style

  let wrapPreservingAnsiWithOffsets width (text: string) =
    let rows = wrapWithOffsets width text
    if not (containsAnsi text) then
      rows
    else
      let mutable rawIndex = 0
      let mutable visibleIndex = 0
      let mutable ansiMatch = ansiPattern.Match text
      let mutable style = ""
      let advance (builder: Text.StringBuilder option) =
        if ansiMatch.Success && ansiMatch.Index = rawIndex then
          let sequence = ansiMatch.Value
          builder |> Option.iter (fun b -> b.Append sequence |> ignore)
          style <- styleAfterAnsi style sequence
          rawIndex <- rawIndex + ansiMatch.Length
          ansiMatch <- ansiMatch.NextMatch()
        else
          let chr = text[rawIndex]
          if chr = '\t' then
            builder |> Option.iter (fun b -> b.Append ' ' |> ignore)
            visibleIndex <- visibleIndex + 1
          elif not (Char.IsControl chr) then
            builder |> Option.iter (fun b -> b.Append chr |> ignore)
            visibleIndex <- visibleIndex + 1
          else
            ()
          rawIndex <- rawIndex + 1
      let advanceTo finish builder =
        while visibleIndex < finish && rawIndex < text.Length do
          advance builder
      rows
      |> List.map (fun (start, finish, _) ->
        advanceTo start None
        let builder = Text.StringBuilder style
        advanceTo finish (Some builder)
        builder.Append "\x1b[0m" |> ignore
        start, finish, builder.ToString())

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
    OriginalLine: TuiLine
    CommandSyntax: (string * int) option
    TextStart: int
    TextEnd: int
    Line: TuiLine }

/// Width-dependent transcript rows and their visible starting row.
type TuiTranscriptLayout =
  { Rows: TuiTranscriptLine array
    ViewportStart: int }

/// Full-screen panels that temporarily replace the transcript view.
[<RequireQualifiedAccess>]
type TuiOverlay =
  | None
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

/// Last press retained to recognize multi-clicks across terminal backends.
type TuiRecentClick =
  { Button: int
    Row: int
    Column: int
    At: int64
    Count: int }

[<RequireQualifiedAccess>]
type TuiMouseDragTarget =
  | Input
  | Transcript
  | View
  | SidebarDivider
  | SuggestionDivider

/// View pane state for one command result.
type TuiViewPane =
  { Title: string
    BlockIndex: int
    Lines: TuiLine array
    ItemCommands: string array
    VisibleLengths: int array
    Cursor: TuiTextCursor
    Anchor: TuiTextCursor option
    FindText: string
    FindCursor: int
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

[<RequireQualifiedAccess>]
type TuiShellInputMode =
  | Normal
  | HistoryBrowsing
  | HistoryEditing

[<RequireQualifiedAccess>]
type TuiLayout =
  | Pane
  | Console

module TuiLayout =
  let name = function
    | TuiLayout.Pane -> "pane"
    | TuiLayout.Console -> "console"

  let tryParse = function
    | "pane" -> Some TuiLayout.Pane
    | "console" -> Some TuiLayout.Console
    | _ -> None

/// UI state independent from terminal rendering and key reading.
type TransformerTuiModel =
  { Session: TransformerReplState
    Transcript: TuiTranscript
    ResultBlocks: Map<int, Lazy<TuiLine list>>
    LastViewLines: TuiLine list
    Input: string
    Cursor: int
    InputAnchor: int option
    PaletteInput: string
    PaletteCursor: int
    PaletteFilter: string
    PaletteSuggestionIndex: int
    PreferredInputColumn: int option
    ScrollOffset: int
    TranscriptViewportStart: int option
    TranscriptCursor: TuiTextCursor
    TranscriptAnchor: TuiTextCursor option
    TranscriptFindText: string
    TranscriptFindCursor: int
    IsFindingTranscript: bool
    ViewPane: TuiViewPane option
    HistoryIndex: int option
    HistoryDraft: (string * int) option
    ShellInputMode: TuiShellInputMode
    SuggestionIndex: int
    Overlay: TuiOverlay
    Focus: TuiFocus
    RecentClick: TuiRecentClick option
    MouseDragTarget: TuiMouseDragTarget option
    MouseDragPosition: (int * int) option
    LastMouseScrollAt: int64
    OverlaySelection: int
    FoldTarget: int option
    CollapsedCommands: Set<int>
    SidebarWidth: int option
    SidebarScrollOffset: int
    SuggestionHeight: int
    BottomPaneOrder: TuiBottomPaneOrder
    Layout: TuiLayout
    Status: string
    IsBusy: bool
    SpinnerFrame: int }

module TransformerTuiModel =
  type private TranscriptLayoutCache =
    { Model: TransformerTuiModel
      Width: int
      Height: int
      TranscriptLayout: TuiTranscriptLayout }

  let mutable private transcriptLayoutCache: TranscriptLayoutCache option = None

  let private transcriptLineBudget = 5000

  let defaultSuggestionHeight = 7

  let private paneFrameRows = 5

  let private fixedFrameRows model =
    match model.Layout with
    | TuiLayout.Pane ->
      paneFrameRows
    | TuiLayout.Console ->
      let viewFind =
        model.Overlay = TuiOverlay.View
        && (model.ViewPane |> Option.exists _.IsFinding)
      if model.IsFindingTranscript || viewFind then 1 else 0

  let bodyStartRow model =
    match model.Layout with
    | TuiLayout.Pane -> 4
    | TuiLayout.Console -> 1

  let private inputLineCount (input: string) =
    input.Replace("\r\n", "\n").Replace('\r', '\n').Split '\n'
    |> Array.length

  let private maximumSuggestionHeight terminalHeight =
    max 1 (terminalHeight - paneFrameRows - 2)

  let suggestionHeight terminalHeight (model: TransformerTuiModel) =
    match model.Layout with
    | TuiLayout.Pane ->
      let maximum = maximumSuggestionHeight terminalHeight
      max 1 (min maximum model.SuggestionHeight)
    | TuiLayout.Console ->
      0

  let shellInputCapacity terminalHeight model =
    let suggestions = suggestionHeight terminalHeight model
    max 1 (terminalHeight - (fixedFrameRows model) - suggestions - 1)

  let visibleShellInputRows terminalHeight model =
    min (shellInputCapacity terminalHeight model) (inputLineCount model.Input)

  let transcriptHeight terminalHeight model =
    let suggestions = suggestionHeight terminalHeight model
    let inputRows = visibleShellInputRows terminalHeight model
    max 1 (terminalHeight - (fixedFrameRows model) - suggestions - inputRows)

  let inputStartRow terminalHeight model =
    let bodyEnd = transcriptHeight terminalHeight model
    match model.Layout, model.BottomPaneOrder with
    | TuiLayout.Console, _ ->
      bodyStartRow model + bodyEnd
    | TuiLayout.Pane, TuiBottomPaneOrder.ShellAboveSuggestions ->
      5 + bodyEnd
    | TuiLayout.Pane, TuiBottomPaneOrder.SuggestionsAboveShell ->
      5 + bodyEnd + suggestionHeight terminalHeight model

  let transcriptBodyWidth terminalWidth model =
    match model.Layout with
    | TuiLayout.Console ->
      terminalWidth
    | TuiLayout.Pane ->
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

  let private welcomeLines =
    [ { Kind = TuiLineKind.System
        Text = "Welcome to B2R2 Transformer interactive analysis." }
      { Kind = TuiLineKind.System
        Text =
          "Enter a pipeline below. Tab completes; F1 opens the guide." } ]

  let initial =
    { Session = TransformerReplState.empty
      Transcript = welcomeLines |> TuiTranscript.ofList
      ResultBlocks = Map.empty
      LastViewLines = []
      Input = ""
      Cursor = 0
      InputAnchor = None
      PaletteInput = ""
      PaletteCursor = 0
      PaletteFilter = ""
      PaletteSuggestionIndex = 0
      PreferredInputColumn = None
      ScrollOffset = 0
      TranscriptViewportStart = None
      TranscriptCursor = { Line = 0; Column = 0 }
      TranscriptAnchor = None
      TranscriptFindText = ""
      TranscriptFindCursor = 0
      IsFindingTranscript = false
      ViewPane = None
      HistoryIndex = None
      HistoryDraft = None
      ShellInputMode = TuiShellInputMode.Normal
      SuggestionIndex = 0
      Overlay = TuiOverlay.None
      Focus = TuiFocus.Shell
      RecentClick = None
      MouseDragTarget = None
      MouseDragPosition = None
      LastMouseScrollAt = 0L
      OverlaySelection = 0
      FoldTarget = None
      CollapsedCommands = Set.empty
      SidebarWidth = None
      SidebarScrollOffset = 0
      SuggestionHeight = defaultSuggestionHeight
      BottomPaneOrder = TuiBottomPaneOrder.ShellAboveSuggestions
      Layout = TuiLayout.Pane
      Status = "Ready"
      IsBusy = false
      SpinnerFrame = 0 }

  let private trimTranscript transcript =
    if TuiTranscript.length transcript <= transcriptLineBudget then
      transcript, 0, 0
    else
      let lines = TuiTranscript.toList transcript |> List.toArray
      let starts =
        lines
        |> Array.indexed
        |> Array.choose (fun (index, line) ->
          if isCommandLine line then Some index else None)
      (* Keep the newest block intact even when it exceeds the budget. *)
      let first =
        if Array.isEmpty starts then
          max 0 (lines.Length - transcriptLineBudget)
        else
          starts
          |> Array.tryFind (fun start ->
            lines.Length - start <= transcriptLineBudget)
          |> Option.defaultValue (Array.last starts)
      let removedCommands =
        starts |> Array.takeWhile (fun start -> start < first) |> Array.length
      let retained =
        lines[first..] |> Array.toList |> TuiTranscript.ofList
      retained, first, removedCommands

  let private commandCount model =
    TuiTranscript.commandCount model.Transcript

  let private transcriptLines model =
    TuiTranscript.toList model.Transcript

  let private shiftCommandIndex removed index =
    if index > removed then Some(index - removed) else None

  let private shiftTranscriptState removedLines removedCommands model =
    let shiftIndex = shiftCommandIndex removedCommands
    let cursor = model.TranscriptCursor
    let cursor =
      if cursor.Line < removedLines then
        { Line = 0; Column = 0 }
      else
        { cursor with Line = cursor.Line - removedLines }
    let anchor =
      model.TranscriptAnchor
      |> Option.bind (fun anchor ->
        if anchor.Line < removedLines then None
        else Some { anchor with Line = anchor.Line - removedLines })
    let blocks =
      model.ResultBlocks
      |> Map.toSeq
      |> Seq.choose (fun (index, lines) ->
        shiftIndex index |> Option.map (fun index -> index, lines))
      |> Map.ofSeq
    let collapsed =
      model.CollapsedCommands |> Seq.choose shiftIndex |> Set.ofSeq
    let pane =
      model.ViewPane
      |> Option.map (fun pane ->
        if pane.BlockIndex < 1 then
          pane
        else
          match shiftIndex pane.BlockIndex with
          | Some index ->
            { pane with
                BlockIndex = index
                Title = $"View result #{index}" }
          | None ->
            { pane with
                BlockIndex = -1
                Title = "View result (no longer in transcript)" })
    { model with
        ResultBlocks = blocks
        TranscriptCursor = cursor
        TranscriptAnchor = anchor
        ViewPane = pane
        FoldTarget = model.FoldTarget |> Option.bind shiftIndex
        CollapsedCommands = collapsed }

  let appendTuiLines lines model =
    let transcript, removedLines, removedCommands =
      model.Transcript |> TuiTranscript.append lines |> trimTranscript
    let model =
      if removedLines = 0 then model
      else shiftTranscriptState removedLines removedCommands model
    { model with
        Transcript = transcript
        ScrollOffset = 0
        TranscriptViewportStart = None }

  let appendLines kind lines model =
    let additions =
      lines |> List.map (fun text -> { Kind = kind; Text = text })
    appendTuiLines additions model

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
    let model = appendTuiLines (commandLines command) model
    { model with FoldTarget = Some(commandCount model) }

  let clearTranscript model =
    { model with
        Transcript = TuiTranscript.empty
        ResultBlocks = Map.empty
        LastViewLines = []
        TranscriptCursor = { Line = 0; Column = 0 }
        TranscriptAnchor = None
        TranscriptFindText = ""
        TranscriptFindCursor = 0
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

  let openCommandPaletteWith input model =
    { openCommandPalette model with
        PaletteInput = input
        PaletteCursor = input.Length
        PaletteFilter = input }

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
        TranscriptAnchor = None
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

  let private setInputState input cursor model =
    { model with
        Input = input
        Cursor = max 0 (min cursor input.Length)
        InputAnchor = None
        PreferredInputColumn = None
        Focus = TuiFocus.Shell
        SuggestionIndex = 0
        ScrollOffset = 0
        TranscriptViewportStart = None }
    |> clearTranscriptFocusStatus

  let private setNormalInput input cursor model =
    { setInputState input cursor model with
        HistoryIndex = None
        HistoryDraft = None
        ShellInputMode = TuiShellInputMode.Normal }

  let setInput input cursor model = setNormalInput input cursor model

  let private editInput input cursor model =
    let mode =
      match model.ShellInputMode with
      | TuiShellInputMode.HistoryBrowsing
      | TuiShellInputMode.HistoryEditing ->
        TuiShellInputMode.HistoryEditing
      | TuiShellInputMode.Normal ->
        TuiShellInputMode.Normal
    let historyIndex =
      if mode = TuiShellInputMode.HistoryEditing then
        model.HistoryIndex
      else
        None
    let historyDraft =
      if mode = TuiShellInputMode.HistoryEditing then
        model.HistoryDraft
      else
        None
    { setInputState input cursor model with
        HistoryIndex = historyIndex
        HistoryDraft = historyDraft
        ShellInputMode = mode }

  let replaceInput input cursor model = editInput input cursor model

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

  let private inputSelectionBounds model =
    model.InputAnchor
    |> Option.map (fun anchor ->
      min anchor model.Cursor, max anchor model.Cursor)
    |> Option.filter (fun (first, last) -> first < last)

  let private replaceInputSelection text model =
    match inputSelectionBounds model with
    | Some(first, last) ->
      let before = model.Input[..first - 1]
      let after = model.Input[last..]
      editInput (before + text + after) (first + text.Length) model
    | None ->
      let before = model.Input[..model.Cursor - 1]
      let after = model.Input[model.Cursor..]
      editInput (before + text + after) (model.Cursor + text.Length) model

  let insert character model = replaceInputSelection (string character) model

  let insertText text model =
    if String.IsNullOrEmpty text then
      model
    else
      replaceInputSelection text model

  let backspace model =
    match inputSelectionBounds model with
    | Some _ ->
      replaceInputSelection "" model
    | None when model.Cursor = 0 ->
      model
    | None ->
      let before = model.Input[..model.Cursor - 2]
      let after = model.Input[model.Cursor..]
      editInput (before + after) (model.Cursor - 1) model

  let delete model =
    match inputSelectionBounds model with
    | Some _ ->
      replaceInputSelection "" model
    | None when model.Cursor >= model.Input.Length ->
      model
    | None ->
      let before = model.Input[..model.Cursor - 1]
      let after = model.Input[(model.Cursor + 1)..]
      editInput (before + after) model.Cursor model

  let private inputModeAfterCursorMove model =
    match model.ShellInputMode with
    | TuiShellInputMode.HistoryBrowsing ->
      TuiShellInputMode.HistoryEditing
    | mode ->
      mode

  let private historyIndexAfterCursorMove model =
    if inputModeAfterCursorMove model = TuiShellInputMode.HistoryEditing then
      model.HistoryIndex
    else
      None

  let moveCursor offset (model: TransformerTuiModel) =
    { model with
        Cursor = max 0 (min (model.Cursor + offset) model.Input.Length)
        InputAnchor = None
        PreferredInputColumn = None
        HistoryIndex = historyIndexAfterCursorMove model
        ShellInputMode = inputModeAfterCursorMove model }

  let moveHome (model: TransformerTuiModel) =
    { model with
        Cursor = 0
        InputAnchor = None
        PreferredInputColumn = None
        HistoryIndex = historyIndexAfterCursorMove model
        ShellInputMode = inputModeAfterCursorMove model }

  let moveEnd (model: TransformerTuiModel) =
    { model with
        Cursor = model.Input.Length
        InputAnchor = None
        PreferredInputColumn = None
        HistoryIndex = historyIndexAfterCursorMove model
        ShellInputMode = inputModeAfterCursorMove model }

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
          InputAnchor = None
          PreferredInputColumn = Some column
          HistoryIndex = historyIndexAfterCursorMove model
          ShellInputMode = inputModeAfterCursorMove model }
    | _ ->
      model

  let moveInputCursorTo cursor extend model =
    let cursor = max 0 (min cursor model.Input.Length)
    let anchor =
      if extend then
        model.InputAnchor |> Option.orElse (Some model.Cursor)
      else
        None
    { model with
        Cursor = cursor
        InputAnchor = anchor
        PreferredInputColumn = None
        Focus = TuiFocus.Shell
        HistoryIndex = historyIndexAfterCursorMove model
        ShellInputMode = inputModeAfterCursorMove model
        TranscriptAnchor = None
        TranscriptViewportStart = None }
    |> clearTranscriptFocusStatus

  let private isWordCharacter character =
    Char.IsLetterOrDigit character || character = '_'

  let private wordRange (text: string) cursor =
    if String.IsNullOrEmpty text then
      0, 0
    else
      let index = min (text.Length - 1) cursor
      let index =
        let previousWord =
          index > 0 && isWordCharacter text[index - 1]
        if previousWord && not (isWordCharacter text[index]) then
          index - 1
        else
          index
      if not (isWordCharacter text[index]) then
        index, index + 1
      else
        let mutable start = index
        let mutable finish = index + 1
        while start > 0 && isWordCharacter text[start - 1] do
          start <- start - 1
        while finish < text.Length && isWordCharacter text[finish] do
          finish <- finish + 1
        start, finish

  let selectInputWord model =
    let start, finish = wordRange model.Input model.Cursor
    { moveInputCursorTo finish false model with InputAnchor = Some start }

  let selectInputLine model =
    let cursor = model.Cursor
    let start =
      if cursor = 0 then 0
      else model.Input.LastIndexOf('\n', cursor - 1) + 1
    let finish = model.Input.IndexOf('\n', cursor)
    let finish = if finish < 0 then model.Input.Length else finish
    { moveInputCursorTo finish false model with InputAnchor = Some start }

  let deleteToStart model =
    let input = model.Input[model.Cursor..]
    editInput input 0 model

  let deleteToEnd model =
    let input = model.Input[..model.Cursor - 1]
    editInput input model.Cursor model

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
    editInput (before + after) start model

  let private historyItem index model =
    model.Session.CommandHistory |> List.tryItem index

  let private historyDraft model =
    match model.ShellInputMode with
    | TuiShellInputMode.Normal ->
      Some(model.Input, model.Cursor)
    | _ ->
      model.HistoryDraft

  let private setHistoryInput index command model =
    { setInputState command command.Length model with
        HistoryIndex = Some index
        HistoryDraft = historyDraft model
        ShellInputMode = TuiShellInputMode.HistoryBrowsing }

  let private restoreHistoryDraft model =
    match model.HistoryDraft with
    | Some(input, cursor) ->
      setNormalInput input cursor model
    | None ->
      setNormalInput "" 0 model

  let historyPrevious model =
    let index =
      model.HistoryIndex
      |> Option.map ((+) 1)
      |> Option.defaultValue 0
    match historyItem index model with
    | Some command ->
      setHistoryInput index command model
    | None ->
      model

  let historyNext model =
    match model.HistoryIndex with
    | Some index when index > 0 ->
      let index = index - 1
      match historyItem index model with
      | Some command ->
        setHistoryInput index command model
      | None ->
        model
    | Some _ ->
      restoreHistoryDraft model
    | None ->
      model

  let historyOldest model =
    let index = List.length model.Session.CommandHistory - 1
    match historyItem index model with
    | Some command ->
      setHistoryInput index command model
    | None ->
      model

  let historyNewest model =
    match historyItem 0 model with
    | Some command ->
      setHistoryInput 0 command model
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

  let sidebarValues model =
    let lastResult =
      TransformerReplState.tryLastResult model.Session
      |> Option.map (fun value ->
        TransformerReplState.LastResultName, value)
      |> Option.toList
    let bindings = model.Session.Bindings |> Map.toList
    lastResult @ bindings

  let sidebarWindowStart visibleRows model =
    let count = sidebarValues model |> List.length
    min model.SidebarScrollOffset (max 0 (count - visibleRows))

  let scrollSidebar visibleRows amount model =
    let count = sidebarValues model |> List.length
    let maximum = max 0 (count - visibleRows)
    let offset =
      model.SidebarScrollOffset + amount |> max 0 |> min maximum
    { model with SidebarScrollOffset = offset }

  let setSuggestionHeight height model =
    { model with SuggestionHeight = max 1 height }

  let setLayout layout model =
    { model with
        Layout = layout
        TranscriptViewportStart = None
        ScrollOffset = 0
        MouseDragTarget = None
        MouseDragPosition = None }

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
      editInput input cursor model
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
    let length = TransformerTuiText.sanitize text |> String.length
    { Line = line; Column = max 0 (min cursor.Column length) }

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

  let private transcriptSelectionRange model source length =
    match model.TranscriptAnchor, source with
    | Some anchor, TuiTranscriptSource.Line line ->
      let cursor = model.TranscriptCursor
      let isBefore =
        anchor.Line < cursor.Line
        || (anchor.Line = cursor.Line && anchor.Column <= cursor.Column)
      let first, last = if isBefore then anchor, cursor else cursor, anchor
      if line < first.Line || line > last.Line then
        None
      elif first.Line = last.Line then
        Some(first.Column, last.Column)
      elif line = first.Line then
        Some(first.Column, length)
      elif line = last.Line then
        Some(0, last.Column)
      else
        Some(0, length)
    | _ ->
      None

  let private markTranscriptSelection selection start finish (text: string) =
    match selection with
    | Some(first, last) ->
      let first = max first start
      let last = min last finish
      if first < last then
        let first = first - start
        let last = last - start
        let before = if first = 0 then "" else text[..first - 1]
        let selected = text[first..last - 1]
        let after = if last = text.Length then "" else text[last..]
        before + "\x1b[7m" + selected + "\x1b[0m" + after
      else
        text
    | None ->
      text

  let private wrapTranscriptLine width model (line: TuiTranscriptLine) =
    let prefix = TransformerTuiText.linePrefix line.Line.Kind
    let cleanText = TransformerTuiText.sanitize line.Line.Text
    let selection =
      transcriptSelectionRange model line.Source cleanText.Length
    let text =
      if selection.IsSome then cleanText else line.Line.Text
    text
    |> TransformerTuiText.wrapPreservingAnsiWithOffsets
      (max 1 (width - prefix.Length))
    |> List.mapi (fun index (start, finish, text) ->
      let prefix = if index = 0 then prefix else "  "
      let text = markTranscriptSelection selection start finish text
      { line with
          TextStart = start
          TextEnd = finish
          Line = { line.Line with Text = prefix + text } })

  let private sourceContains line source =
    match source with
    | TuiTranscriptSource.Line index ->
      index = line
    | TuiTranscriptSource.HiddenRange(first, last) ->
      first <= line && line <= last
    | TuiTranscriptSource.Synthetic ->
      false

  let private transcriptSelectionContains model source =
    let first, last =
      model.TranscriptAnchor
      |> Option.map (fun anchor ->
        let first = min anchor.Line model.TranscriptCursor.Line
        let last = max anchor.Line model.TranscriptCursor.Line
        first, last)
      |> Option.defaultValue
        (model.TranscriptCursor.Line, model.TranscriptCursor.Line)
    let overlaps firstSource lastSource =
      first <= lastSource && firstSource <= last
    match source with
    | TuiTranscriptSource.Line line ->
      first <= line && line <= last
    | TuiTranscriptSource.HiddenRange(firstSource, lastSource) ->
      overlaps firstSource lastSource
    | TuiTranscriptSource.Synthetic ->
      false

  let private cursorOnSource model source =
    model.Focus = TuiFocus.Transcript
    && model.Overlay = TuiOverlay.None
    && transcriptSelectionContains model source

  let private markTranscriptCursor model
                                   (line: TuiTranscriptLine)
                                   : TuiTranscriptLine =
    let selected =
      model.TranscriptAnchor.IsNone && cursorOnSource model line.Source
    { line with
        Line =
          { line.Line with
              Kind =
                selectedTextKind
                  selected
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

  let private renderTranscriptBlock
    model
    index
    (lines: TuiTranscriptLine list) =
    let command, output =
      let isCommandText (line: TuiTranscriptLine) =
        line.Line.Kind = TuiLineKind.Command
        || line.Line.Kind = TuiLineKind.CommandContinuation
      List.takeWhile isCommandText lines, List.skipWhile isCommandText lines
    let commandText =
      command
      |> List.map (fun line ->
        TransformerTuiText.sanitize line.OriginalLine.Text)
      |> String.concat "\n"
    let rec annotateCommand offset = function
      | [] ->
        []
      | line :: rest ->
        let text = TransformerTuiText.sanitize line.OriginalLine.Text
        { line with CommandSyntax = Some(commandText, offset) }
        :: annotateCommand (offset + text.Length + 1) rest
    let command =
      command |> annotateCommand 0 |> List.map (markTranscriptCursor model)
    if Set.contains index model.CollapsedCommands then
      let source = sourceRange output
      let selected = cursorOnSource model source
      let kind = selectedTextKind selected TuiLineKind.System
      let folded = { Kind = kind; Text = $"<< result #{index} folded >>" }
      command @
        [ { Source = source
            OriginalLine = folded
            CommandSyntax = None
            TextStart = 0
            TextEnd = 0
            Line = folded } ]
    else
      command @ (output |> List.map (markTranscriptCursor model))

  let transcriptDisplayLines (model: TransformerTuiModel)
      : TuiTranscriptLine list =
    let output = ResizeArray<TuiTranscriptLine>()
    let block = ResizeArray<TuiTranscriptLine>()
    let mutable blockIndex = 0
    let flush () =
      if block.Count > 0 then
        block
        |> Seq.toList
        |> renderTranscriptBlock model blockIndex
        |> output.AddRange
        block.Clear()
      else
        ()
    let mutable lineIndex = 0
    for line in transcriptLines model do
      let line =
        { Source = TuiTranscriptSource.Line lineIndex
          OriginalLine = line
          CommandSyntax = None
          TextStart = 0
          TextEnd = 0
          Line = line }
      let isWelcome =
        model.Layout = TuiLayout.Console
        && (welcomeLines |> List.tryItem lineIndex) = Some line.Line
      if not isWelcome then
        match line.Line.Kind with
        | TuiLineKind.Command ->
          flush ()
          blockIndex <- blockIndex + 1
          block.Add line
        | _ ->
          block.Add line
      else
        ()
      lineIndex <- lineIndex + 1
    flush ()
    Seq.toList output

  let private latestDisplayCommandIndex
    (lines: TuiTranscriptLine array) =
    lines
    |> Array.indexed
    |> Array.filter (fun (_, line) ->
      line.Line.Kind = TuiLineKind.Command)
    |> Array.tryLast
    |> Option.map fst

  let private transcriptCursorRowIndex model
                                       (rows: TuiTranscriptLine array) =
    let column = model.TranscriptCursor.Column
    let mutable first = None
    let mutable preceding = None
    let mutable containing = None
    for index in 0..rows.Length - 1 do
      let row = rows[index]
      if sourceContains model.TranscriptCursor.Line row.Source then
        if first.IsNone then first <- Some index else ()
        if row.TextStart <= column then preceding <- Some index else ()
        if row.TextStart <= column && column <= row.TextEnd then
          containing <- Some index
        else
          ()
      else
        ()
    containing |> Option.orElse preceding |> Option.orElse first

  let private clampViewportStart height count start =
    max 0 (min start (max 0 (count - height)))

  let private autoTranscriptViewportStart height model lines =
    let anchor = latestDisplayCommandIndex lines |> Option.defaultValue 0
    let maximumStart = max 0 (lines.Length - height)
    let selected =
      if model.Focus = TuiFocus.Transcript
         && model.Overlay = TuiOverlay.None then
        transcriptCursorRowIndex model lines
      else
        None
    let start =
      if model.Layout = TuiLayout.Console && selected.IsNone then
        maximumStart
      else
        match selected with
        | Some selected when selected < anchor ->
          selected
        | Some selected when selected >= anchor + height ->
          selected - height + 1
        | _ ->
          anchor
    max 0 (min maximumStart start)

  let transcriptLayout width height model =
    match transcriptLayoutCache with
    | Some cache when cache.Width = width
                      && cache.Height = height
                      && Object.ReferenceEquals(cache.Model, model) ->
      cache.TranscriptLayout
    | _ ->
      let rows =
        transcriptDisplayLines model
        |> List.collect (wrapTranscriptLine width model)
        |> List.toArray
      let start =
        match model.TranscriptViewportStart with
        | Some start ->
          clampViewportStart height rows.Length start
        | None ->
          autoTranscriptViewportStart height model rows
      let layout = { Rows = rows; ViewportStart = start }
      transcriptLayoutCache <-
        Some { Model = model
               Width = width
               Height = height
               TranscriptLayout = layout }
      layout

  let transcriptTopPadding height model layout =
    match model.Layout, model.Overlay with
    | TuiLayout.Console, TuiOverlay.None
    | TuiLayout.Console, TuiOverlay.Message
    | TuiLayout.Console, TuiOverlay.CommandPalette ->
      max 0 (height - layout.Rows.Length)
    | _ ->
      0

  let scrollTranscript width height amount model =
    let layout = transcriptLayout width height model
    let nextStart = layout.ViewportStart + amount
    { model with
        ScrollOffset = 0
        TranscriptViewportStart =
          Some(clampViewportStart height layout.Rows.Length nextStart) }

  let transcriptCursorDisplayPosition width height model =
    if model.Focus <> TuiFocus.Transcript
       || model.Overlay <> TuiOverlay.None then
      None
    else
      let layout = transcriptLayout width height model
      let padding = transcriptTopPadding height model layout
      transcriptCursorRowIndex model layout.Rows
      |> Option.bind (fun index ->
        if index < layout.ViewportStart
           || index >= layout.ViewportStart + height then
          None
        else
          let row = layout.Rows[index]
          let local =
            model.TranscriptCursor.Column - row.TextStart
            |> max 0
            |> min (row.TextEnd - row.TextStart)
          let column =
            match model.Layout with
            | TuiLayout.Pane -> 3 + local
            | TuiLayout.Console -> 2 + local
          Some(padding + index - layout.ViewportStart, column))

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

  let private transcriptCursorAt model (displayLine: TuiTranscriptLine) column =
    let transcript = transcriptLines model
    let line =
      transcriptLineOfSource 0 model displayLine.Source
      |> Option.defaultValue model.TranscriptCursor.Line
    let length = displayLine.TextEnd - displayLine.TextStart
    let prefix =
      match model.Layout with
      | TuiLayout.Pane -> 4
      | TuiLayout.Console -> 3
    let local = max 0 (min length (column - prefix))
    { Line = line; Column = displayLine.TextStart + local }
    |> clampCursor transcript

  let trySelectTranscriptAt width height row column extend model =
    let bodyWidth = transcriptBodyWidth width model
    let bodyHeight = transcriptHeight height model
    let bodyRow = row - bodyStartRow model
    let layout = transcriptLayout bodyWidth bodyHeight model
    let padding = transcriptTopPadding bodyHeight model layout
    let displayIndex = layout.ViewportStart + bodyRow - padding
    let inColumn =
      match model.Layout with
      | TuiLayout.Console -> column >= 1 && column <= bodyWidth
      | TuiLayout.Pane -> column >= 2 && column < bodyWidth
    let isInBody =
      model.Overlay = TuiOverlay.None
      && bodyRow >= 0
      && bodyRow < bodyHeight
      && inColumn
    if not isInBody then
      None
    else
      layout.Rows
      |> Array.tryItem displayIndex
      |> Option.map (fun displayLine ->
        let transcript = transcriptLines model
        let cursor = transcriptCursorAt model displayLine column
        let anchor =
          if extend then
            model.TranscriptAnchor
            |> Option.orElse (Some model.TranscriptCursor)
          else
            None
        { model with
            Focus = TuiFocus.Transcript
            TranscriptCursor = cursor
            TranscriptAnchor = anchor
            FoldTarget = blockAtLine cursor.Line transcript
            ScrollOffset = 0
            TranscriptViewportStart = Some layout.ViewportStart
            Status = "Transcript focused" })

  let selectTranscriptWord model =
    let cursor = model.TranscriptCursor
    transcriptLines model
    |> List.tryItem cursor.Line
    |> Option.map (fun line ->
      let text = TransformerTuiText.sanitize line.Text
      let start, finish = wordRange text cursor.Column
      { model with
          TranscriptCursor = { cursor with Column = finish }
          TranscriptAnchor = Some { cursor with Column = start } })
    |> Option.defaultValue model

  let selectTranscriptLine model =
    let cursor = model.TranscriptCursor
    transcriptLines model
    |> List.tryItem cursor.Line
    |> Option.map (fun line ->
      let length = TransformerTuiText.sanitize line.Text |> String.length
      { model with
          TranscriptCursor = { cursor with Column = length }
          TranscriptAnchor = Some { cursor with Column = 0 } })
    |> Option.defaultValue model

  let private horizontalTranscriptColumn rows current offset column =
    let row = (rows: TuiTranscriptLine array)[current]
    if offset > 0 && column >= row.TextEnd then
      match Array.tryItem (current + 1) rows with
      | Some next when next.Source = row.Source ->
        max (column + offset) next.TextStart
      | _ ->
        column + offset
    elif offset < 0 && column <= row.TextStart then
      match Array.tryItem (current - 1) rows with
      | Some previous when previous.Source = row.Source ->
        min (column + offset) previous.TextEnd
      | _ ->
        column + offset
    else
      column + offset

  let moveTranscriptCursorInView width height rowDelta columnDelta model =
    let transcript = transcriptLines model
    let layout = transcriptLayout width height model
    let current =
      transcriptCursorRowIndex model layout.Rows
      |> Option.defaultValue 0
    let currentStart = layout.ViewportStart
    let target =
      max 0 (min (layout.Rows.Length - 1) (current + rowDelta))
    let line =
      layout.Rows
      |> Array.tryItem target
      |> Option.bind (fun (line: TuiTranscriptLine) ->
        transcriptLineOfSource rowDelta model line.Source)
      |> Option.defaultValue model.TranscriptCursor.Line
    let column =
      if rowDelta = 0 then
        horizontalTranscriptColumn
          layout.Rows current columnDelta model.TranscriptCursor.Column
      else
        let currentRow = layout.Rows[current]
        let targetRow = layout.Rows[target]
        let local =
          model.TranscriptCursor.Column - currentRow.TextStart
          |> max 0
          |> min (targetRow.TextEnd - targetRow.TextStart)
        targetRow.TextStart + local
    let cursor =
      { Line = line
        Column = column }
      |> clampCursor transcript
    let next =
      { model with
          TranscriptCursor = cursor
          TranscriptAnchor = None
          FoldTarget = blockAtLine cursor.Line transcript
          ScrollOffset = 0
          Status = "Transcript focused" }
    let nextCursor =
      transcriptCursorRowIndex next layout.Rows
      |> Option.defaultValue target
    let nextStart =
      if nextCursor < currentStart then
        nextCursor
      elif nextCursor >= currentStart + height then
        nextCursor - height + 1
      else
        currentStart
    { next with
        TranscriptViewportStart =
          Some(clampViewportStart height layout.Rows.Length nextStart) }

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
        TranscriptAnchor = None
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
        TranscriptAnchor = None
        FoldTarget = blockAtLine cursor.Line transcript
        Status = "Transcript focused" }

  let private selectTranscriptCommand
    width height (positions: int list) index model =
    let line = positions[index]
    let cursor = { Line = line; Column = 0 }
    let next =
      { model with
          Focus = TuiFocus.Transcript
          TranscriptCursor = cursor
          TranscriptAnchor = None
          FoldTarget = Some(index + 1)
          ScrollOffset = 0
          Status = $"Selected result #{index + 1}" }
    let layout = transcriptLayout width height next
    let cursorIndex =
      transcriptCursorRowIndex next layout.Rows
      |> Option.defaultValue 0
    let start =
      cursorIndex - (height / 2)
      |> clampViewportStart height layout.Rows.Length
    { next with TranscriptViewportStart = Some start }

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
      selectTranscriptCommand width height positions index model

  let moveTranscriptToFirstCommand width height model =
    let positions = commandPositions (transcriptLines model)
    if List.isEmpty positions then
      { model with Status = "There is no command in the transcript" }
    else
      selectTranscriptCommand width height positions 0 model

  let moveTranscriptToLastCommand width height model =
    let positions = commandPositions (transcriptLines model)
    if List.isEmpty positions then
      { model with Status = "There is no command in the transcript" }
    else
      let index = List.length positions - 1
      selectTranscriptCommand width height positions index model

  let private insertFindChar (text: string) cursor chr =
    let cursor = max 0 (min text.Length cursor)
    text.Insert(cursor, string chr), cursor + 1

  let private backspaceFindChar (text: string) cursor =
    let cursor = max 0 (min text.Length cursor)
    if cursor = 0 then text, cursor
    else text.Remove(cursor - 1, 1), cursor - 1

  let setTranscriptFind active model =
    { model with
        IsFindingTranscript = active
        TranscriptFindText = ""
        TranscriptFindCursor = 0 }

  let setTranscriptFindCursor cursor model =
    { model with
        TranscriptFindCursor =
          max 0 (min model.TranscriptFindText.Length cursor) }

  let moveTranscriptFindCursor offset model =
    setTranscriptFindCursor (model.TranscriptFindCursor + offset) model

  let appendTranscriptFind chr model =
    let text, cursor =
      insertFindChar model.TranscriptFindText model.TranscriptFindCursor chr
    { model with
        TranscriptFindText = text
        TranscriptFindCursor = cursor }

  let backspaceTranscriptFind model =
    let text, cursor =
      backspaceFindChar model.TranscriptFindText model.TranscriptFindCursor
    { model with
        TranscriptFindText = text
        TranscriptFindCursor = cursor }

  let private transcriptLineContains
    (needle: string)
    (line: TuiTranscriptLine) =
    line.Line.Text.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0

  let private transcriptFindCandidates width height model =
    let layout = transcriptLayout width height model
    let lines = layout.Rows
    let cursor =
      if model.Focus = TuiFocus.Transcript then
        transcriptCursorRowIndex model lines
        |> Option.defaultValue -1
      else
        layout.ViewportStart - 1
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
              TranscriptAnchor = None
              IsFindingTranscript = false
              FoldTarget = blockAtLine cursor.Line transcript
              ScrollOffset = 0
              Status =
                $"Found '{model.TranscriptFindText}' at "
                + $"{cursor.Line + 1}:{cursor.Column + 1}" }
        let lineCount = (transcriptLayout width height next).Rows.Length
        let start = clampViewportStart height lineCount (index - (height / 2))
        { next with TranscriptViewportStart = Some start }
      | None ->
        { model with Status = $"Not found: {model.TranscriptFindText}" }

  let private openViewPaneWithLines title blockIndex lines model =
    let lines =
      if List.isEmpty lines then
        [ { Kind = TuiLineKind.System; Text = "This command has no output." } ]
      else
        lines
    let lineArray = List.toArray lines
    let visibleLengths =
      lineArray
      |> Array.map (fun line ->
        TransformerTuiText.sanitize line.Text |> String.length)
    let pane =
      { Title = title
        BlockIndex = blockIndex
        Lines = lineArray
        ItemCommands = [||]
        VisibleLengths = visibleLengths
        Cursor = { Line = 0; Column = 0 }
        Anchor = None
        FindText = ""
        FindCursor = 0
        IsFinding = false }
    { model with
        Overlay = TuiOverlay.View
        ViewPane = Some pane
        LastViewLines = lines
        ScrollOffset = 0
        Status = title }

  let openTextView title lines model =
    openViewPaneWithLines title -1 lines model

  let openCommandView title lines commands model =
    let model = openTextView title lines model
    match model.ViewPane with
    | Some pane ->
      { model with
          ViewPane = Some { pane with ItemCommands = commands } }
    | None ->
      model

  let openViewPane blockIndex model =
    let lines =
      model.ResultBlocks
      |> Map.tryFind blockIndex
      |> Option.map (fun lines -> lines.Value)
      |> Option.defaultWith (fun () ->
        outputLinesOfBlock blockIndex (transcriptLines model))
    openViewPaneWithLines $"View result #{blockIndex}" blockIndex lines model

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
    let length = pane.VisibleLengths[line]
    { Line = line; Column = max 0 (min cursor.Column length) }

  let private moveViewCursorHorizontally pane offset =
    let cursor = clampViewCursor pane pane.Cursor
    let direction = sign offset
    let mutable line = cursor.Line
    let mutable column = cursor.Column
    let mutable length = pane.VisibleLengths[line]
    let mutable remaining = abs offset
    while remaining > 0 do
      if direction > 0 && column < length then
        column <- column + 1
        remaining <- remaining - 1
      elif direction > 0 && line < pane.Lines.Length - 1 then
        line <- line + 1
        column <- 0
        length <- pane.VisibleLengths[line]
        remaining <- remaining - 1
      elif direction < 0 && column > 0 then
        column <- column - 1
        remaining <- remaining - 1
      elif direction < 0 && line > 0 then
        line <- line - 1
        length <- pane.VisibleLengths[line]
        column <- length
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

  let moveViewCursorTo line column extend model =
    let update pane =
      let anchor =
        if extend then
          pane.Anchor |> Option.defaultValue pane.Cursor |> Some
        else
          None
      let line = max 0 (min line (pane.Lines.Length - 1))
      let maximumColumn = pane.VisibleLengths[line]
      let cursor =
        { Line = line; Column = max 0 (min column maximumColumn) }
      { pane with Cursor = cursor; Anchor = anchor }
    updateViewPane update model

  let selectViewWord model =
    match model.ViewPane with
    | Some pane ->
      let line = pane.Cursor.Line
      let text = TransformerTuiText.sanitize pane.Lines[line].Text
      let start, finish = wordRange text pane.Cursor.Column
      let cursor = { Line = line; Column = finish }
      let anchor = { Line = line; Column = start }
      { model with
          ViewPane = Some { pane with Cursor = cursor; Anchor = Some anchor } }
    | None ->
      model

  let selectViewLine model =
    match model.ViewPane with
    | Some pane ->
      let line = pane.Cursor.Line
      let cursor = { Line = line; Column = pane.VisibleLengths[line] }
      let anchor = { Line = line; Column = 0 }
      { model with
          ViewPane = Some { pane with Cursor = cursor; Anchor = Some anchor } }
    | None ->
      model

  let moveViewToFirstLine extend model = moveViewCursorTo 0 0 extend model

  let moveViewToLastLine extend model =
    match model.ViewPane with
    | Some pane ->
      let line = pane.Lines.Length - 1
      let column = pane.VisibleLengths[line]
      moveViewCursorTo line column extend model
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

  let setViewFind active model =
    let update pane =
      { pane with IsFinding = active; FindText = ""; FindCursor = 0 }
    updateViewPane update model

  let setViewFindCursor cursor model =
    let update pane =
      { pane with FindCursor = max 0 (min pane.FindText.Length cursor) }
    updateViewPane update model

  let moveViewFindCursor offset model =
    let cursor =
      model.ViewPane |> Option.map _.FindCursor |> Option.defaultValue 0
    setViewFindCursor (cursor + offset) model

  let appendViewFind chr model =
    let update pane =
      let text, cursor = insertFindChar pane.FindText pane.FindCursor chr
      { pane with FindText = text; FindCursor = cursor }
    updateViewPane update model

  let backspaceViewFind model =
    let update pane =
      let text, cursor = backspaceFindChar pane.FindText pane.FindCursor
      { pane with FindText = text; FindCursor = cursor }
    updateViewPane update model

  let private lineContains (needle: string) (line: TuiLine) =
    let text = TransformerTuiText.sanitize line.Text
    text.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0

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
        let text = TransformerTuiText.sanitize line.Text
        let column =
          text.IndexOf(pane.FindText, StringComparison.OrdinalIgnoreCase)
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
    let cleanText = TransformerTuiText.sanitize
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

  let selectedInputText model =
    model.InputAnchor
    |> Option.map (fun anchor ->
      min anchor model.Cursor, max anchor model.Cursor)
    |> Option.bind (fun (first, last) ->
      if first = last then None else Some model.Input[first..last - 1])
    |> Option.defaultValue ""

  let selectedTranscriptText model =
    let cleanText = TransformerTuiText.sanitize
    let sliceText start finish (text: string) =
      let text = cleanText text
      let start = max 0 (min start text.Length)
      let finish = max start (min finish text.Length)
      if start >= finish then "" else text[start..finish - 1]
    let transcript = transcriptLines model
    match model.TranscriptAnchor with
    | None ->
      transcript
      |> List.tryItem model.TranscriptCursor.Line
      |> Option.map (fun line -> cleanText line.Text)
      |> Option.defaultValue ""
    | Some anchor ->
      let first, last = orderedSelection anchor model.TranscriptCursor
      transcript
      |> List.mapi (fun index line -> index, line.Text)
      |> List.choose (fun (index, text) ->
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

  let selectedText model =
    match model.Overlay, model.ViewPane, model.Focus with
    | TuiOverlay.View, Some pane, _ ->
      selectedViewText pane
    | TuiOverlay.None, _, TuiFocus.Transcript ->
      selectedTranscriptText model
    | _ ->
      selectedInputText model

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
