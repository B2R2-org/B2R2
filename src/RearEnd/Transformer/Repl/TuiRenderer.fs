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
open System.IO
open System.Text

/// A fully rendered terminal frame and its input cursor location.
type TransformerTuiFrame =
  { Lines: string array
    CursorRow: int
    CursorColumn: int }

module TransformerTuiRenderer =
  let private reset = "\x1b[0m"
  let private bold = "\x1b[1m"
  let private dim = "\x1b[2m"
  let private red = "\x1b[31m"
  let private green = "\x1b[32m"
  let private cyan = "\x1b[36m"
  let private underline = "\x1b[4m"
  let private reverse = "\x1b[7m"
  let private clearLine = "\x1b[2K"
  /// Bright blue used for generic panel borders and dividers.
  let private border = "\x1b[94m"
  let private maxRenderableChars = 4096

  let private paint style text = style + text + reset

  let private displayText (text: string) =
    if isNull text then
      ""
    elif text.Length > maxRenderableChars then
      text[..maxRenderableChars - 1] + " ... <line truncated>"
    else
      text

  let private normalizePath (path: string) =
    path.Replace('\\', '/')

  let private compactPath (path: string) =
    let fullPath = Path.GetFullPath path
    let root = Path.GetPathRoot fullPath |> normalizePath
    let root = if root.EndsWith "/" then root else root + "/"
    let current = DirectoryInfo(fullPath).Name
    if String.IsNullOrEmpty current then
      root
    else
      root + ".../" + current

  let private sanitize (text: string) =
    let text = displayText text
    TransformerTuiText.sanitize text

  let private containsAnsi (text: string) =
    TransformerTuiText.containsAnsi text

  let private fitAnsi width (text: string) =
    let text = displayText text
    let builder = StringBuilder()
    let rec loop index visible =
      if index >= text.Length || visible >= width then
        visible
      else
        let matched = TransformerTuiText.matchAnsi text index
        if matched.Success && matched.Index = index then
          builder.Append matched.Value |> ignore
          loop (index + matched.Length) visible
        else
          let chr = text[index]
          if chr = '\t' then
            builder.Append ' ' |> ignore
            loop (index + 1) (visible + 1)
          elif Char.IsControl chr then
            loop (index + 1) visible
          else
            builder.Append chr |> ignore
            loop (index + 1) (visible + 1)
    if width <= 0 then
      ""
    else
      let visible = loop 0 0
      let padding = String.replicate (max 0 (width - visible)) " "
      builder.Append padding |> ignore
      builder.ToString()

  let private fit width (text: string) =
    if width <= 0 then
      ""
    elif containsAnsi text then
      fitAnsi width text
    else
      let text = sanitize text
      if text.Length > width then
        text[..width - 1]
      else
        text.PadRight width

  let private wrap width text =
    displayText text |> TransformerTuiText.wrap width

  let private lineStyle = function
    | TuiLineKind.Command ->
      cyan
    | TuiLineKind.CommandContinuation ->
      cyan
    | TuiLineKind.Output ->
      ""
    | TuiLineKind.Error ->
      red
    | TuiLineKind.System ->
      dim
    | TuiLineKind.Selection ->
      reverse
    | TuiLineKind.Cursor ->
      ""

  let private wrapLine width (line: TuiLine) =
    let prefix = TransformerTuiText.linePrefix line.Kind
    if containsAnsi line.Text then
      [ line.Kind, prefix + line.Text ]
    else
      wrap (max 1 (width - prefix.Length)) line.Text
      |> List.mapi (fun index text ->
        let prefix = if index = 0 then prefix else "  "
        line.Kind, prefix + text)

  let private valueTypeDescription value =
    ReplValueKind.toString (value: ReplValue).Kind

  let private helpLines =
    [ "REPL GUIDE"
      ""
      "Pipelines"
      "  let <name> = <expression>       Bind an analysis result"
      "  <value> |> @<action> [args]      Transform the preceding value"
      "  <expression>                      Evaluate without binding"
      ""
      "Reference"
      "  :actions                      List actions and usage forms"
      "  :show [name|expression]       Show a value or expression result"
      "  :type [name|expression]       Show an inferred value kind"
      "  :inspect [name]               List functions and sections"
      "  :needs <ctx> [k=v]            List required concrete context"
      ""
      "Session"
      "  :values                       List retained values"
      "  :restore <id>                 Restore a historical value"
      "  :history                      List evaluated commands"
      "  :log                          Show execution history"
      "  :undo                         Undo the last value change"
      "  :reset                        Reset analysis values"
      ""
      "Scripts and environment"
      "  :script save|load|record ...  Manage replay scripts"
      "  :export <name> path=<path>    Export a named value"
      "  :plugin load path=<dll>        Load a plugin"
      "  :layout [k=v ...]             Resize TUI panes"
      "  :clear                        Clear the visible transcript"
      "  # <text>                      Record a script comment"
      "  :quit                         Leave the TUI"
      ""
      "Shell"
      "  Enter                          Insert a new line"
      "  ;; then Enter                  Execute the current input"
      "  Tab / Shift+Tab                Apply completion / insert spaces"
      "  Up / Down                      Browse history or suggestions"
      "  Ctrl+N / Ctrl+P                Select next / previous completion"
      "  Ctrl+C                         Cancel a running action"
      "  Ctrl+D                         Leave when input is empty"
      "  Copy / paste                   Use the terminal's shortcuts"
      ""
      "Transcript and view"
      "  Shift+Up / Shift+Down          Enter / leave transcript focus"
      "  Enter or F4                    Open the selected result in view"
      "  PageUp / PageDown              Scroll the active pane"
      "  Ctrl+Up / Ctrl+Down            Move by command in transcript"
      "  Shift+Arrows                   Select text in view"
      "  Ctrl+F                         Find text in view"
      "  Ctrl+Enter                     Insert view selection into input"
      "  Alt+Arrows                     Resize sidebar or transcript"
      "  Esc                            Close a panel or clear input" ]

  let private actionLines registry =
    let format registered =
      let metadata = (registered: RegisteredAction).Metadata
      ActionMetadata.documentationLines metadata @ [ "" ]
    "AVAILABLE ACTIONS" :: "" ::
      (ActionRegistry.getAll registry |> List.collect format)

  let private bindingLines model =
    let bindings =
      model.Session.Bindings
      |> Map.toList
      |> List.map (fun (name, value) ->
        $"{name}  {valueTypeDescription value}")
    if List.isEmpty bindings then
      [ "SESSION BINDINGS"; ""; "No named values yet." ]
    else
      "SESSION BINDINGS" :: "" :: bindings

  let private selectionLine selected text =
    { Kind =
        if selected then TuiLineKind.Selection else TuiLineKind.System
      Text = text }

  let private inspectionItems model =
    model.Session.Current
    |> Option.map TransformerReplInspection.inspect
    |> Option.defaultValue []

  let private inspectionLines model =
    let items = inspectionItems model
    if List.isEmpty items then
      [ { Kind = TuiLineKind.System
          Text = "No inspectable Binary is current." } ]
    else
      { Kind = TuiLineKind.System
        Text = "FUNCTIONS AND SECTIONS - Enter inserts an operation" }
      :: (items
          |> List.mapi (fun index item ->
            let text = $"{item.Label}  {item.Detail}"
            selectionLine (index = model.OverlaySelection) text))

  let private valueLines model =
    let entries = model.Session.ValueHistory |> List.rev
    if List.isEmpty entries then
      [ { Kind = TuiLineKind.System; Text = "No retained values." } ]
    else
      { Kind = TuiLineKind.System
        Text = "VALUE HISTORY - Enter inserts :restore" }
      :: (entries
          |> List.mapi (fun index entry ->
            let kind = valueTypeDescription entry.Value
            let name = entry.Name |> Option.defaultValue "<unnamed>"
            let text = $"{entry.ID}: {name}  {kind}"
            selectionLine (index = model.OverlaySelection) text))

  let private logLines model =
    let entries = model.Session.ExecutionLog |> List.rev
    if List.isEmpty entries then
      [ { Kind = TuiLineKind.System; Text = "The execution log is empty." } ]
    else
      entries
      |> List.map (fun entry ->
        let status = entry.Status.ToString().ToLowerInvariant()
        let elapsed = entry.Duration.TotalMilliseconds
        { Kind = TuiLineKind.System
          Text = $"{entry.ID}: {status} {elapsed:F1} ms  {entry.Command}" })

  let private overlayLines width registry model =
    match model.Overlay with
    | TuiOverlay.View ->
      let pane = model.ViewPane
      let lines =
        pane
        |> Option.map (fun pane -> Array.toList pane.Lines)
        |> Option.defaultValue
          [ { Kind = TuiLineKind.System; Text = "No result to view." } ]
      lines |> List.collect (wrapLine width)
    | TuiOverlay.Inspect ->
      inspectionLines model |> List.collect (wrapLine width)
    | TuiOverlay.Values ->
      valueLines model |> List.collect (wrapLine width)
    | TuiOverlay.Log ->
      logLines model |> List.collect (wrapLine width)
    | overlay ->
      let lines =
        match overlay with
        | TuiOverlay.Help ->
          helpLines
        | TuiOverlay.Actions ->
          actionLines registry
        | TuiOverlay.Bindings ->
          bindingLines model
        | TuiOverlay.None | TuiOverlay.View | TuiOverlay.Inspect
        | TuiOverlay.Values | TuiOverlay.Log ->
          []
      lines
      |> List.collect (fun text ->
        wrapLine width { Kind = TuiLineKind.System; Text = text })

  let private selectedTextKind selected kind =
    if selected then TuiLineKind.Selection else kind

  let private viewSelectionContains pane line =
    match pane.Anchor with
    | None ->
      false
    | Some anchor ->
      let first, last =
        if anchor.Line <= pane.Cursor.Line then
          anchor, pane.Cursor
        else
          pane.Cursor, anchor
      line >= first.Line && line <= last.Line

  let private orderedViewSelection pane =
    pane.Anchor
    |> Option.map (fun anchor ->
      if anchor.Line < pane.Cursor.Line then
        anchor, pane.Cursor
      elif anchor.Line > pane.Cursor.Line then
        pane.Cursor, anchor
      elif anchor.Column <= pane.Cursor.Column then
        anchor, pane.Cursor
      else
        pane.Cursor, anchor)

  let private inlineSelection start finish (text: string) =
    let start = max 0 (min start text.Length)
    let finish = max start (min finish text.Length)
    if start = finish then
      text
    else
      let before = if start = 0 then "" else text[..start - 1]
      let selected = text[start..finish - 1]
      let after = if finish >= text.Length then "" else text[finish..]
      before + reverse + selected + reset + after

  let private viewSelectionRange pane index length =
    match orderedViewSelection pane with
    | None ->
      None
    | Some(first, last) when index < first.Line || index > last.Line ->
      None
    | Some(first, last) when first.Line = last.Line ->
      Some(first.Column, last.Column)
    | Some(first, _) when index = first.Line ->
      Some(first.Column, length)
    | Some(_, last) when index = last.Line ->
      Some(0, last.Column)
    | Some _ ->
      Some(0, length)

  let private selectViewRow pane index start finish length (text: string) =
    match viewSelectionRange pane index length with
    | Some(selectionStart, selectionFinish) ->
      let selectionStart = max start selectionStart
      let selectionFinish = min finish selectionFinish
      if selectionStart < selectionFinish then
        inlineSelection (selectionStart - start) (selectionFinish - start) text
      else
        text
    | None ->
      text

  type private ViewDisplayRow =
    { SourceLine: int
      Start: int
      Finish: int
      IsFirst: bool
      Kind: TuiLineKind
      Length: int
      Text: string }

  type private ViewRows =
    { Rows: ViewDisplayRow array
      Ranges: (int * int) array }

  type private PlainViewRowsCache =
    { Lines: TuiLine array
      Width: int
      ViewRows: ViewRows }

  (* View-pane lines are retained without mutation while the pane is open. *)
  let mutable private plainViewRowsCache: PlainViewRowsCache option = None

  let private viewRowRanges lineCount (rows: ViewDisplayRow array) =
    let first = Array.create lineCount -1
    let last = Array.create lineCount -1
    rows
    |> Array.iteri (fun index row ->
      if first[row.SourceLine] = -1 then
        first[row.SourceLine] <- index
      else
        ()
      last[row.SourceLine] <- index)
    Array.init lineCount (fun index ->
      if first[index] = -1 then
        0, 0
      else
        first[index], last[index])

  let private makeViewRows (lines: TuiLine array) (rows: ViewDisplayRow list) =
    let rows = rows |> List.toArray
    { Rows = rows
      Ranges = viewRowRanges lines.Length rows }

  let private plainViewDisplayRows width (lines: TuiLine array) =
    lines
    |> Array.indexed
    |> Array.toList
    |> List.collect (fun (index, line) ->
      let prefix = TransformerTuiText.linePrefix line.Kind
      let text = displayText line.Text
      let length = TransformerTuiText.sanitize text |> String.length
      text
      |> TransformerTuiText.wrapWithOffsets (max 1 (width - prefix.Length))
      |> List.mapi (fun row (start, finish, text) ->
        { SourceLine = index
          Start = start
          Finish = finish
          IsFirst = row = 0
          Kind = line.Kind
          Length = length
          Text = text }))
    |> makeViewRows lines

  let private dynamicViewDisplayRows width (pane: TuiViewPane) =
    pane.Lines
    |> Array.indexed
    |> Array.toList
    |> List.collect (fun (index, line) ->
      let selected =
        viewSelectionContains pane index || pane.Cursor.Line = index
      let kind =
        match pane.Anchor with
        | Some _ when selected ->
          TuiLineKind.Cursor
        | Some _ ->
          line.Kind
        | None ->
          selectedTextKind selected line.Kind
      let text =
        if selected && containsAnsi line.Text then
          sanitize line.Text
        else
          line.Text
      let prefix = TransformerTuiText.linePrefix kind
      if containsAnsi text then
        [ { SourceLine = index
            Start = 0
            Finish = TransformerTuiText.stripAnsi text |> String.length
            IsFirst = true
            Kind = kind
            Length = TransformerTuiText.stripAnsi text |> String.length
            Text = text } ]
      else
        let text = displayText text
        let length = TransformerTuiText.sanitize text |> String.length
        text
        |> TransformerTuiText.wrapWithOffsets (max 1 (width - prefix.Length))
        |> List.mapi (fun row (start, finish, text) ->
          { SourceLine = index
            Start = start
            Finish = finish
            IsFirst = row = 0
            Kind = kind
            Length = length
            Text = text }))
    |> makeViewRows pane.Lines

  let private viewRows width (pane: TuiViewPane) =
    match plainViewRowsCache with
    | Some cache
      when cache.Width = width
           && Object.ReferenceEquals(cache.Lines, pane.Lines) ->
      cache.ViewRows
    | _ when pane.Lines |> Array.exists (fun line ->
      containsAnsi line.Text) ->
      dynamicViewDisplayRows width pane
    | _ ->
      let rows = plainViewDisplayRows width pane.Lines
      plainViewRowsCache <-
        Some { Lines = pane.Lines; Width = width; ViewRows = rows }
      rows

  type private ViewPaneLayout =
    { Lines: (TuiLineKind * string) list
      Offset: int
      CursorPosition: (int * int) option }

  let private viewCursorRow rows pane first last =
    let rows: ViewDisplayRow array = rows
    let pane: TuiViewPane = pane
    let column = pane.Cursor.Column
    let mutable index = first
    let mutable cursor = None
    while cursor.IsNone && index <= last do
      let row = rows[index]
      if row.Start <= column && column <= row.Finish then
        cursor <- Some index
      else
        index <- index + 1
    cursor |> Option.defaultValue first

  let private renderViewRow pane (row: ViewDisplayRow) =
    let selected =
      viewSelectionContains pane row.SourceLine
      || pane.Cursor.Line = row.SourceLine
    let kind =
      match pane.Anchor with
      | Some _ when selected ->
        TuiLineKind.Cursor
      | Some _ ->
        row.Kind
      | None ->
        selectedTextKind selected row.Kind
    let prefix =
      if row.IsFirst then TransformerTuiText.linePrefix kind else "  "
    let text =
      selectViewRow pane row.SourceLine row.Start row.Finish row.Length row.Text
    kind, prefix + text

  let private viewPaneLayout width height offset (model: TransformerTuiModel) =
    match model.ViewPane with
    | Some pane ->
      let layoutRows = viewRows width pane
      let rows = layoutRows.Rows
      let first, last = layoutRows.Ranges[pane.Cursor.Line]
      let maximumOffset = max 0 (rows.Length - height)
      let offset = min offset maximumOffset
      let offset =
        if last - first + 1 >= height then
          first
        elif first < offset then
          first
        elif last >= offset + height then
          last - height + 1
        else
          offset
      let cursorRow = viewCursorRow rows pane first last
      let cursor =
        if offset <= cursorRow && cursorRow < offset + height then
          let row = rows[cursorRow]
          let column = max row.Start (min pane.Cursor.Column row.Finish)
          Some(cursorRow - offset, 3 + column - row.Start)
        else
          None
      { Lines =
          Array.sub rows offset (min height (rows.Length - offset))
          |> Array.map (renderViewRow pane)
          |> Array.toList
        Offset = offset
        CursorPosition = cursor }
    | None ->
      { Lines = [ TuiLineKind.System, "No result to view." ]
        Offset = 0
        CursorPosition = None }

  let private takeLast count offset lines =
    let length = List.length lines
    let offset = min offset (max 0 (length - count))
    let last = max 0 (length - offset)
    let first = max 0 (last - count)
    lines |> List.skip first |> List.truncate (last - first)

  let private takeTranscriptRows count offset start lines =
    if offset = 0 then
      lines |> List.skip start |> List.truncate count
    else
      takeLast count offset lines

  let private takeBody bodyHeight bodyWidth registry model =
    match model.Overlay with
    | TuiOverlay.None ->
      let lines: (TuiLineKind * string) list =
        TransformerTuiModel.transcriptDisplayRows bodyWidth bodyHeight model
        |> List.map (fun (line: TuiTranscriptLine) ->
          line.Line.Kind, line.Line.Text)
      let start =
        TransformerTuiModel.transcriptViewportStart
          bodyWidth bodyHeight model
      takeTranscriptRows bodyHeight model.ScrollOffset start lines
    | _ ->
      let lines = overlayLines bodyWidth registry model
      let maximumOffset = max 0 (List.length lines - bodyHeight)
      lines
      |> List.skip (min model.ScrollOffset maximumOffset)
      |> List.truncate bodyHeight

  let private currentSummary model =
    match model.Session.Current with
    | Some value ->
      valueTypeDescription value
    | None ->
      "none"

  let private scriptRecordText = function
    | ReplReplayMode.Reproducible ->
      "on"
    | ReplReplayMode.Exploratory ->
      "off"

  let private scriptPath model =
    model.Session.SessionPath |> Option.defaultValue "<none>"

  let private paneStatus model fallback =
    match model.Overlay, model.ViewPane with
    | TuiOverlay.View, Some pane ->
      let count = pane.Lines.Length
      let line = min (pane.Cursor.Line + 1) (max 1 count)
      let column = pane.Cursor.Column + 1
      let find =
        if pane.IsFinding then
          $"  find: {pane.FindText}"
        else
          ""
      $"view result #{pane.BlockIndex}  {line}/{count}:{column}{find}"
    | _ when model.Focus = TuiFocus.Transcript
             && fallback = "Transcript focused" ->
      ""
    | _ ->
      fallback

  let private selectedBodyIndex body =
    body
    |> List.tryFindIndex (fun (kind, _) ->
      kind = TuiLineKind.Selection || kind = TuiLineKind.Cursor)

  let private transcriptCursorColumn model =
    model.TranscriptCursor.Column + 3

  let private transcriptCursorPosition model body =
    if model.Focus = TuiFocus.Transcript
       && model.Overlay = TuiOverlay.None then
      selectedBodyIndex body
      |> Option.map (fun row -> row, transcriptCursorColumn model)
    else
      None

  let private spinner frame =
    let frames = [| "-"; "\\"; "|"; "/" |]
    frames[frame % frames.Length]

  let private boxTop color width title =
    let inner = max 0 (width - 2)
    let dashes = max 0 (inner - String.length title - 2)
    paint color ("+-" + title + " " + String.replicate dashes "-" + "+")

  let private boxBottom color width =
    let inner = max 0 (width - 2)
    paint color ("+" + String.replicate inner "-" + "+")

  let private boxSide color (content: string) =
    paint color "|" + content + paint color "|"

  /// Style marker for a sidebar row that is already a full-width, rendered
  /// box border line, so `renderBodyRow` must not wrap it in "|...|" again.
  let private rawBoxRow = "\x00raw\x00"

  let private sidebarLines rightWidth height model =
    let current = currentSummary model
    let focus = model.Focus.ToString().ToLowerInvariant()
    let busy =
      if model.IsBusy then
        $"{spinner model.SpinnerFrame} running"
      else
        model.Status
    let extra = paneStatus model busy
    let status = if String.IsNullOrWhiteSpace extra then busy else extra
    let bindingCount = Map.count model.Session.Bindings
    let state =
      [ "", $"current   {current}"
        "", $"commands  {List.length model.Session.CommandHistory}"
        "", $"focus     {focus}"
        "", $"status    {status}" ]
    let boundary =
      [ rawBoxRow, boxBottom border rightWidth
        rawBoxRow, boxTop border rightWidth $"Bindings ({bindingCount})" ]
    let bindings =
      model.Session.Bindings
      |> Map.toList
      |> List.map (fun (name, value) ->
        let kind = valueTypeDescription value
        "", $"{name}: {kind}")
    let error =
      match model.Session.LastError with
      | Some message ->
        [ "", ""; red, "LAST ERROR"; red, message ]
      | None ->
        []
    state @ boundary @ bindings @ error
    |> List.truncate height

  let private renderBodyRow leftWidth rightWidth left right =
    let leftKind, leftText = left
    let leftInner = max 0 (leftWidth - 2)
    let left =
      boxSide border (paint (lineStyle leftKind) (fit leftInner leftText))
    if rightWidth = 0 then
      left
    else
      let rightStyle, rightText = right
      let right =
        if rightStyle = rawBoxRow then
          fit rightWidth rightText
        else
          let rightInner = max 0 (rightWidth - 2)
          boxSide border (paint rightStyle (fit rightInner rightText))
      left + " " + right

  let private highlightedHint width text highlights =
    let text = sanitize text
    let text =
      if text.Length > width then text[..width - 1] else text
    let visible = text.Length
    let padding = String.replicate (max 0 (width - visible)) " "
    let highlights =
      highlights
      |> List.choose (fun (start, length) ->
        let start = max 0 start
        let finish = min visible (start + length)
        if start < visible && start < finish then
          Some(start, finish)
        else
          None)
      |> List.sortBy fst
    if List.isEmpty highlights then
      paint dim (text + padding)
    else
      let rec loop index chunks = function
        | [] ->
          if index >= visible then
            List.rev chunks
          else
            let suffix = text[index..]
            List.rev (paint dim suffix :: chunks)
        | (start, finish) :: rest ->
          let chunks =
            if index < start then
              let before = text[index..start - 1]
              paint dim before :: chunks
            else
              chunks
          let current = text[start..finish - 1]
          loop finish (paint reverse current :: chunks) rest
      String.concat "" (loop 0 [] highlights) + padding

  let private splitHintText (text: string): string list =
    text.Replace("\r\n", "\n").Replace('\r', '\n').Split '\n'
    |> Array.toList

  let private lineHighlights lineStart lineLength highlights =
    let lineEnd = lineStart + lineLength
    highlights
    |> List.choose (fun (start, length) ->
      let finish = start + length
      let start = max start lineStart
      let finish = min finish lineEnd
      if start < finish then
        Some(start - lineStart, finish - start)
      else
        None)

  let private styleDiagnostics (text: string) highlights =
    let ranges =
      highlights
      |> List.choose (fun (start, length) ->
        let start = max 0 start
        let finish = min text.Length (start + length)
        if start < finish then Some(start, finish) else None)
      |> List.sortBy fst
    let rec loop index chunks = function
      | [] ->
        if index >= text.Length then
          List.rev chunks
        else
          List.rev (text[index..] :: chunks)
      | (start, finish) :: rest ->
        let start = max index start
        if start >= finish then
          loop index chunks rest
        else
          let chunks =
            if index < start then
              text[index..start - 1] :: chunks
            else
              chunks
          let marked = paint (red + underline) text[start..finish - 1]
          loop finish (marked :: chunks) rest
    String.concat "" (loop 0 [] ranges)

  let private hintRows width completion =
    match completion.Hint with
    | None ->
      []
    | Some text ->
      let lines = splitHintText text
      let rec loop offset rows (lines: string list) =
        match lines with
        | [] ->
          List.rev rows
        | line :: rest ->
          let highlights =
            lineHighlights offset line.Length completion.HintHighlights
          let row = highlightedHint width line highlights
          loop (offset + line.Length + 1) (row :: rows) rest
      loop 0 [] lines

  let private fitSuggestionRows rowCount width rows =
    let rows = List.truncate rowCount rows
    rows @ List.replicate (rowCount - List.length rows) (fit width "")

  let private suggestionRows rowCount width completion selected =
    let rowCount = max 1 rowCount
    let count = List.length completion.Items
    let boxed = rowCount > 2
    let innerWidth = if boxed then max 1 (width - 2) else width
    let hint = hintRows innerWidth completion
    let contentRows =
      if count = 0 then
        match hint with
        | first :: rest ->
          first :: (rest |> List.truncate (rowCount - 1))
        | [] ->
          [ paint dim (fit innerWidth
                        "Suggestions appear here as you type.") ]
      else
        let selected = min selected (count - 1)
        let visible =
          max 0 ((if boxed then rowCount - 2 else rowCount) - List.length hint)
        let start =
          if visible <= 0 then
            0
          else
            let pageStart = selected / visible * visible
            max 0 (min pageStart (count - visible))
        let itemRows =
          completion.Items
          |> List.skip start
          |> List.truncate visible
          |> List.mapi (fun offset item ->
            let index = start + offset
            let marker = if index = selected then "> " else "  "
            let text = $"{marker}{item.Label}  {item.Detail}"
            let style = if index = selected then reverse else dim
            paint style (fit innerWidth text))
        hint @ itemRows
    if boxed then
      [ boxTop cyan width "Suggestions" ]
      @ (contentRows |> List.map (boxSide cyan))
      @ [ boxBottom cyan width ]
      |> fitSuggestionRows rowCount width
    else
      contentRows |> fitSuggestionRows rowCount width

  let private ghostText completion selected model =
    let completion: SuggestionSet = completion
    if completion.Start + completion.Length <> model.Cursor then
      ""
    else
      completion.Items
      |> List.tryItem selected
      |> Option.bind (fun item ->
        let prefix =
          if model.Cursor <= completion.Start then
            ""
          else
            model.Input[completion.Start..model.Cursor - 1]
        let after = model.Input[model.Cursor..]
        let insert = Completion.insertionText item after
        if insert.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) then
          let suffix = insert[prefix.Length..]
          if String.IsNullOrEmpty suffix then None else Some suffix
        else
          None)
      |> Option.defaultValue ""

  let private splitInputLines (input: string) =
    input.Replace("\r\n", "\n").Replace('\r', '\n').Split '\n'
    |> Array.toList

  let private cursorInputPosition (input: string) cursor =
    let before =
      if cursor = 0 then "" else input[..cursor - 1]
    let lines = splitInputLines before
    let line = max 0 (List.length lines - 1)
    let column = lines |> List.tryLast |> Option.map _.Length
    line, Option.defaultValue 0 column

  let private inputRow
    width
    (prompt: string)
    (line: string)
    lineStart
    cursorColumn
    (ghost: string)
    diagnostics =
    let available = max 1 (width - prompt.Length)
    let cursorColumn = max 0 (min cursorColumn line.Length)
    let start =
      if cursorColumn < available then 0 else cursorColumn - available + 1
    let before =
      if cursorColumn <= start then
        ""
      else
        line[start..cursorColumn - 1]
    let ghost =
      let length = max 0 (available - before.Length)
      if length = 0 then
        ""
      elif ghost.Length > length then
        ghost[..length - 1]
      else
        ghost
    let after =
      if cursorColumn >= line.Length then "" else line[cursorColumn..]
    let afterLength = max 0 (available - before.Length - ghost.Length)
    let after =
      if afterLength = 0 then
        ""
      elif after.Length > afterLength then
        after[..afterLength - 1]
      else
        after
    let visibleLength = before.Length + ghost.Length + after.Length
    let beforeHighlights =
      lineHighlights (lineStart + start) before.Length diagnostics
    let afterHighlights =
      lineHighlights (lineStart + cursorColumn) after.Length diagnostics
    let before = styleDiagnostics before beforeHighlights
    let after = styleDiagnostics after afterHighlights
    let padding = String.replicate (available - visibleLength) " "
    let cursor = prompt.Length + cursorColumn - start + 1
    paint green prompt + before + paint dim ghost + after + padding, cursor

  let private indexedInputLines (input: string) =
    let rec loop start output = function
      | [] ->
        List.rev output
      | (line: string) :: rest ->
        loop (start + line.Length + 1) ((start, line) :: output) rest
    splitInputLines input |> loop 0 []

  let private inputView
    width
    maxRows
    (model: TransformerTuiModel)
    (completion: SuggestionSet) =
    let lines = indexedInputLines model.Input
    let cursorLine, cursorColumn =
      cursorInputPosition model.Input model.Cursor
    let first =
      if cursorLine < maxRows then 0 else cursorLine - maxRows + 1
    let visible = lines |> List.skip first |> List.truncate maxRows
    let rows, cursor =
      visible
      |> List.mapi (fun offset (lineStart, line) ->
        let absolute = first + offset
        let prompt =
          if model.IsBusy then
            "  "
          elif absolute = 0 then
            "> "
          else
            "  "
        let isCursorLine = absolute = cursorLine
        let ghost =
          if isCursorLine then
            ghostText completion model.SuggestionIndex model
          else
            ""
        let column = if isCursorLine then cursorColumn else 0
        let diagnostics =
          completion.Diagnostics
          |> List.map (fun item -> item.Start, item.Length)
        let row =
          inputRow width prompt line lineStart column ghost diagnostics
        row, isCursorLine)
      |> List.fold (fun (rows, cursor) (row, isCursorLine) ->
        let cursor =
          if isCursorLine then
            Some(List.length rows, row |> snd)
          else
            cursor
        (row |> fst) :: rows, cursor) ([], None)
    let rows = List.rev rows
    let cursor = cursor |> Option.defaultValue (0, 1)
    rows, cursor

  let private contextFooter width model =
    let cwd = compactPath Environment.CurrentDirectory
    let script = normalizePath (scriptPath model)
    let record = scriptRecordText model.Session.ReplayMode
    let text = $" cwd: {cwd}  script: {script}  record: {record}"
    paint dim (fit width text)

  let private keyHeader width =
    " F1 help  F4 view "
    |> fit width
    |> paint dim

  let viewScrollOffset width height model =
    if model.Overlay = TuiOverlay.View then
      let bodyHeight = TransformerTuiModel.transcriptHeight height model
      let bodyWidth = TransformerTuiModel.transcriptBodyWidth width model
      viewPaneLayout bodyWidth bodyHeight model.ScrollOffset model
      |> fun layout -> layout.Offset
    else
      model.ScrollOffset

  let render width height registry model completion =
    if width < 40 || height < 15 then
      let message = "Terminal too small. Resize to at least 40 x 15."
      { Lines = [| clearLine + fit width message |]
        CursorRow = 1
        CursorColumn = 1 }
    else
      let shellInputRows = TransformerTuiModel.shellInputCapacity model
      let inputRows, inputCursor =
        inputView width shellInputRows model completion
      let availableBodyAndCompletion =
        TransformerTuiModel.availableBodyAndCompletion height model
      let bodyHeight =
        TransformerTuiModel.transcriptHeight height model
      let suggestionCount =
        max 1 (availableBodyAndCompletion - bodyHeight)
      let leftWidth = TransformerTuiModel.transcriptBodyWidth width model
      let rightWidth =
        if leftWidth < width then width - leftWidth - 1 else 0
      let hasSidebar = rightWidth > 0
      let viewLayout =
        if model.Overlay = TuiOverlay.View then
          Some(viewPaneLayout leftWidth bodyHeight model.ScrollOffset model)
        else
          None
      let body =
        viewLayout
        |> Option.map _.Lines
        |> Option.defaultWith (fun () ->
          takeBody bodyHeight leftWidth registry model)
      let padding =
        List.replicate (bodyHeight - List.length body)
          (TuiLineKind.Output, "")
      let cursorBodyPosition =
        transcriptCursorPosition model body
        |> Option.orElse (viewLayout |> Option.bind _.CursorPosition)
      let body = body @ padding
      let sidebar = sidebarLines rightWidth bodyHeight model
      let sidebar = sidebar @ List.replicate (bodyHeight - List.length sidebar)
                                      ("", "")
      let bodyRows =
        List.map2 (renderBodyRow leftWidth rightWidth) body sidebar
      let title = paint bold " B2R2 TRANSFORMER "
      let subtitle = paint dim " Interactive Binary Analysis"
      let boxTopRow =
        if hasSidebar then
          boxTop border leftWidth "Main Window"
          + " " + boxTop border rightWidth "State"
        else
          boxTop border leftWidth "Main Window"
      let boxBottomRow =
        if hasSidebar then
          boxBottom border leftWidth + " " + boxBottom border rightWidth
        else
          boxBottom border leftWidth
      let suggestions =
        suggestionRows suggestionCount width completion model.SuggestionIndex
      let context = contextFooter width model
      let rows =
        [ title + subtitle |> fun text -> text + fit (max 0 (width - 47)) ""
          keyHeader width
          boxTopRow ]
        @ bodyRows
        @ [ boxBottomRow ]
        @ suggestions
        @ inputRows
        @ [ context ]
      let lines =
        rows
        |> List.map (fun row -> clearLine + row + reset)
        |> List.toArray
      { Lines = lines
        CursorRow =
          cursorBodyPosition
          |> Option.map (fun (row, _) -> 4 + row)
          |> Option.defaultValue (
            let row, _ = inputCursor
            height - List.length inputRows + row)
        CursorColumn =
          cursorBodyPosition
          |> Option.map (fun (_, column) -> min (leftWidth - 1) (column + 1))
          |> Option.defaultValue (
            let _, column = inputCursor
            min width column) }
