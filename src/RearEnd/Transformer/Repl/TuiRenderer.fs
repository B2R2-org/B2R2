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
open System.Collections.Generic
open System.IO
open System.Text

/// A fully rendered terminal frame and its input cursor location.
type TransformerTuiFrame =
  { Lines: string array
    CursorRow: int
    CursorColumn: int }

type private TuiInputRow =
  { Prompt: string
    Text: string
    TextStart: int
    CursorColumn: int
    Ghost: string
    Diagnostics: (int * int) list
    Styles: string array
    Selection: (int * int) option }

type private TuiInputRenderState =
  { Completion: SuggestionSet
    Model: TransformerTuiModel
    CursorLine: int
    CursorColumn: int
    Styles: string array
    Selection: (int * int) option }

module TransformerTuiRenderer =
  [<Literal>]
  let private MinimumTerminalWidth = 40

  [<Literal>]
  let private MinimumTerminalHeight = 15

  let isInteractiveSize width height =
    width >= MinimumTerminalWidth && height >= MinimumTerminalHeight

  type HeaderHit =
    | HeaderKey of ConsoleKey
    | HeaderRun
    | HeaderCopy

  type PaletteHit =
    | PaletteInput of int
    | PaletteCandidate of int
    | PaletteInside
    | PaletteOutside

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
  /// Bright blue background used for the top title banner.
  let private bannerBg = "\x1b[104m"
  /// Bright white foreground used for the top title banner.
  let private bannerFg = "\x1b[97m"
  /// Bright yellow background used for the notice dialog.
  let private noticeBg = "\x1b[103m"
  /// Black foreground used for text on the notice dialog.
  let private noticeFg = "\x1b[30m"
  /// Gray background used for the command palette input.
  let private paletteInputBg = "\x1b[100m"
  /// Bright white foreground used for the command palette.
  let private paletteFg = "\x1b[97m"
  /// Light gray foreground used for the command palette completion preview.
  let private paletteGhostFg = "\x1b[38;2;184;184;184m"
  let private identifierFg = "\x1b[38;2;212;212;212m"
  let private actionFg = "\x1b[38;2;220;220;170m"
  let private parameterFg = "\x1b[38;2;206;145;120m"
  let private numberFg = "\x1b[38;2;181;206;168m"
  let private stringFg = "\x1b[38;2;156;220;254m"
  let private keywordFg = "\x1b[38;2;197;134;192m"
  let private commentFg = "\x1b[38;2;106;153;85m"
  let private commandBg = "\x1b[48;2;37;47;60m"
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
    let builder = StringBuilder()
    let mutable ansiMatch = TransformerTuiText.matchAnsi text 0
    let rec loop index visible =
      if index >= text.Length || visible >= width then
        visible
      else
        if ansiMatch.Success && ansiMatch.Index = index then
          builder.Append ansiMatch.Value |> ignore
          let next = index + ansiMatch.Length
          ansiMatch <- ansiMatch.NextMatch()
          loop next visible
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
      let text = TransformerTuiText.sanitize text
      if text.Length > width then
        text[..width - 1]
      else
        text.PadRight width

  let private lineStyle = function
    | TuiLineKind.Command ->
      ""
    | TuiLineKind.CommandContinuation ->
      ""
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
    displayText line.Text
    |> TransformerTuiText.wrapPreservingAnsiWithOffsets
      (max 1 (width - prefix.Length))
    |> List.mapi (fun index (_, _, text) ->
      let prefix = if index = 0 then prefix else "  "
      line.Kind, prefix + text)

  let private valueTypeDescription value =
    ReplValueKind.toString (value: ReplValue).Kind

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

  let private overlayLines width model =
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
    | TuiOverlay.None | TuiOverlay.Message | TuiOverlay.CommandPalette ->
      []

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

  type private ViewRowsCache =
    { Lines: TuiLine array
      Width: int
      ViewRows: ViewRows }

  (* View-pane lines are retained without mutation while the pane is open. *)
  let mutable private viewRowsCache: ViewRowsCache option = None

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

  let private viewDisplayRows width (lines: TuiLine array) =
    lines
    |> Array.indexed
    |> Array.toList
    |> List.collect (fun (index, line) ->
      let prefix = TransformerTuiText.linePrefix line.Kind
      let text = line.Text
      let length = TransformerTuiText.sanitize text |> String.length
      text
      |> TransformerTuiText.wrapPreservingAnsiWithOffsets
        (max 1 (width - prefix.Length))
      |> List.mapi (fun row (start, finish, text) ->
        { SourceLine = index
          Start = start
          Finish = finish
          IsFirst = row = 0
          Kind = line.Kind
          Length = length
          Text = text }))
    |> makeViewRows lines

  let private viewRows width (pane: TuiViewPane) =
    match viewRowsCache with
    | Some cache
      when cache.Width = width
           && Object.ReferenceEquals(cache.Lines, pane.Lines) ->
      cache.ViewRows
    | _ ->
      let rows = viewDisplayRows width pane.Lines
      viewRowsCache <-
        Some { Lines = pane.Lines; Width = width; ViewRows = rows }
      rows

  type private ViewPaneLayout =
    { Lines: (TuiLineKind * string) list
      Offset: int
      CursorPosition: (int * int) option }

  let private viewCursorRow (rows: ViewDisplayRow array) pane first last =
    let column = (pane: TuiViewPane).Cursor.Column
    let mutable index = first
    while index < last && rows[index + 1].Start <= column do
      index <- index + 1
    index

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
      if selected && containsAnsi row.Text then
        TransformerTuiText.sanitize row.Text
      else
        row.Text
    let text =
      selectViewRow pane row.SourceLine row.Start row.Finish row.Length text
    kind, prefix + text

  let private viewPaneLayout width height offset (model: TransformerTuiModel) =
    match model.ViewPane with
    | Some pane ->
      let layoutRows = viewRows width pane
      let rows = layoutRows.Rows
      let first, last = layoutRows.Ranges[pane.Cursor.Line]
      let maximumOffset = max 0 (rows.Length - height)
      let offset = min offset maximumOffset
      let cursorRow = viewCursorRow rows pane first last
      let offset =
        if last - first + 1 >= height then
          if cursorRow < offset then
            cursorRow
          elif cursorRow >= offset + height then
            cursorRow - height + 1
          else
            offset
        elif first < offset then
          first
        elif last >= offset + height then
          last - height + 1
        else
          offset
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

  let private takeTranscriptRows count start (lines: TuiTranscriptLine array) =
    lines |> Array.skip start |> Array.truncate count |> Array.toList

  let private scriptRecordText = function
    | ReplReplayMode.Reproducible ->
      "on"
    | ReplReplayMode.Exploratory ->
      "off"

  let private scriptPath model =
    model.Session.SessionPath |> Option.defaultValue "<none>"

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
    TransformerTuiModel.sidebarValues model
    |> List.skip (TransformerTuiModel.sidebarWindowStart height model)
    |> List.truncate height
    |> List.map (fun (name, value) ->
      let kind = valueTypeDescription value
      "", $"{name}: {kind}")

  let isSidebarAt width height model row column =
    let leftWidth = TransformerTuiModel.transcriptBodyWidth width model
    let bodyHeight = TransformerTuiModel.transcriptHeight height model
    let rightStart = leftWidth + 2
    rightStart < width
    && row >= 4
    && row < 4 + bodyHeight
    && column > rightStart
    && column < width

  let isMainBodyAt width height model row column =
    let leftWidth = TransformerTuiModel.transcriptBodyWidth width model
    let bodyHeight = TransformerTuiModel.transcriptHeight height model
    let start = TransformerTuiModel.bodyStartRow model
    let inColumn =
      match model.Layout with
      | TuiLayout.Console -> column >= 1 && column <= leftWidth
      | TuiLayout.Pane -> column >= 2 && column < leftWidth
    row >= start && row < start + bodyHeight
    && inColumn

  let trySidebarValueAt width height model row column =
    let bodyHeight = TransformerTuiModel.transcriptHeight height model
    let index =
      TransformerTuiModel.sidebarWindowStart bodyHeight model + row - 4
    let hasSidebarValue =
      model.Overlay = TuiOverlay.None
      || model.Overlay = TuiOverlay.View
    if not hasSidebarValue
       || not (isSidebarAt width height model row column) then
      None
    else
      TransformerTuiModel.sidebarValues model
      |> List.tryItem index
      |> Option.map fst

  let isSuggestionPaneAt width height model row column =
    let bodyHeight = TransformerTuiModel.transcriptHeight height model
    let suggestions = TransformerTuiModel.suggestionHeight height model
    let inputRows = TransformerTuiModel.visibleShellInputRows height model
    let start =
      match model.BottomPaneOrder with
      | TuiBottomPaneOrder.ShellAboveSuggestions ->
        5 + bodyHeight + inputRows
      | TuiBottomPaneOrder.SuggestionsAboveShell ->
        5 + bodyHeight
    model.Layout = TuiLayout.Pane
    && column >= 1 && column <= width
    && row >= start && row < start + suggestions

  let isSidebarDividerAt width height model row column =
    let leftWidth = TransformerTuiModel.transcriptBodyWidth width model
    let bodyHeight = TransformerTuiModel.transcriptHeight height model
    leftWidth < width
    && column = leftWidth + 1
    && row >= 3 && row <= 4 + bodyHeight

  let isSuggestionDividerAt width height model row column =
    let suggestions = TransformerTuiModel.suggestionHeight height model
    let bodyHeight = TransformerTuiModel.transcriptHeight height model
    let inputRows = TransformerTuiModel.visibleShellInputRows height model
    let start =
      match model.BottomPaneOrder with
      | TuiBottomPaneOrder.ShellAboveSuggestions ->
        5 + bodyHeight + inputRows
      | TuiBottomPaneOrder.SuggestionsAboveShell ->
        5 + bodyHeight
    suggestions > 2
    && row = start
    && column >= 1 && column <= width

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

  let private isIdentifierStart chr = Char.IsLetter chr || chr = '_'

  let private isIdentifierPart chr =
    Char.IsLetterOrDigit chr || chr = '_' || chr = '-'

  let private scanWhile predicate (text: string) start =
    let mutable finish = start
    while finish < text.Length && predicate text[finish] do
      finish <- finish + 1
    finish

  let private markSyntaxStyle (styles: string array) start finish style =
    for index in start..finish - 1 do
      styles[index] <- style

  let private stringEnd (input: string) quote start =
    let mutable finish = start + 1
    let mutable closed = false
    while finish < input.Length && not closed do
      if input[finish] = '\\' && finish + 1 < input.Length then
        finish <- finish + 2
      elif input[finish] = quote then
        finish <- finish + 1
        closed <- true
      else
        finish <- finish + 1
    finish

  let private wordStyle (input: string) bindingStart binding start finish =
    let word = input[start..finish - 1]
    let next = scanWhile Char.IsWhiteSpace input finish
    let isBinding =
      start = bindingStart
      && (binding |> Option.exists (fun header -> header.Name = word))
    let hasEquals = next < input.Length && input[next] = '='
    let isAssignment =
      hasEquals && (next + 1 = input.Length || input[next + 1] <> '=')
    if word = "iter" || word = "iteri" || word = "fun" then
      keywordFg
    elif word = "true" || word = "false" then
      numberFg
    elif not isBinding && isAssignment then
      parameterFg
    else
      identifierFg

  let private numberEnd (input: string) index =
    let isHex =
      if index + 1 < input.Length then
        input[index] = '0'
        && (input[index + 1] = 'x' || input[index + 1] = 'X')
      else
        false
    if isHex then
      scanWhile Uri.IsHexDigit input (index + 2)
    else
      scanWhile Char.IsDigit input (index + 1)

  let private syntaxStyles (input: string) =
    let styles = Array.create input.Length ""
    let binding = ReplLanguage.bindingHeader input
    let bindingStart = scanWhile Char.IsWhiteSpace input 0
    let rec scan index =
      if index >= input.Length then
        ()
      else
        match input[index] with
        | '#' ->
          let finish = scanWhile ((<>) '\n') input index
          markSyntaxStyle styles index finish commentFg
          scan finish
        | '"' | '\'' as quote ->
          let finish = stringEnd input quote index
          markSyntaxStyle styles index finish stringFg
          scan finish
        | '@' when index + 1 < input.Length
                   && isIdentifierStart input[index + 1] ->
          let finish = scanWhile isIdentifierPart input (index + 2)
          markSyntaxStyle styles index finish actionFg
          scan finish
        | chr when isIdentifierStart chr ->
          let finish = scanWhile isIdentifierPart input (index + 1)
          let style = wordStyle input bindingStart binding index finish
          markSyntaxStyle styles index finish style
          scan finish
        | chr when Char.IsDigit chr ->
          let finish = numberEnd input index
          markSyntaxStyle styles index finish numberFg
          scan finish
        | _ ->
          scan (index + 1)
    scan 0
    styles

  let private transcriptSelectionFlags (text: string) =
    let length = TransformerTuiText.stripAnsi text |> String.length
    let flags = Array.create length false
    let mutable index = 0
    let mutable visible = 0
    let mutable selected = false
    while index < text.Length do
      let matched = TransformerTuiText.matchAnsi text index
      if matched.Success && matched.Index = index then
        match matched.Value with
        | value when value = reverse -> selected <- true
        | value when value = reset -> selected <- false
        | _ -> ()
        index <- index + matched.Length
      else
        flags[visible] <- selected
        visible <- visible + 1
        index <- index + 1
    flags

  let private appendTranscriptStyle
    (builder: StringBuilder) color selected previousColor previousSelection =
    if color <> previousColor then
      builder.Append(if color = "" then "\x1b[39m" else color) |> ignore
    else
      ()
    if selected <> previousSelection then
      builder.Append(if selected then reverse else "\x1b[27m") |> ignore
    else
      ()

  let private colorTranscriptText
    (styles: string array) lineStart (row: TuiTranscriptLine) =
    let text = TransformerTuiText.stripAnsi row.Line.Text
    let prefixLength = min 2 text.Length
    let selected = transcriptSelectionFlags row.Line.Text
    let prefix = if prefixLength = 0 then "" else text[..prefixLength - 1]
    let background =
      if row.Line.Kind = TuiLineKind.Selection then "" else commandBg
    let builder = StringBuilder(background + prefix)
    let mutable previousColor = ""
    let mutable previousSelection = false
    for index in prefixLength..text.Length - 1 do
      let sourceIndex = lineStart + row.TextStart + index - prefixLength
      let color =
        if sourceIndex < styles.Length then styles[sourceIndex] else ""
      let isSelected = selected[index]
      appendTranscriptStyle
        builder color isSelected previousColor previousSelection
      builder.Append text[index] |> ignore
      previousColor <- color
      previousSelection <- isSelected
    if previousColor <> "" then builder.Append "\x1b[39m" |> ignore
    else ()
    if previousSelection then builder.Append "\x1b[27m" |> ignore
    else ()
    builder.ToString()

  let private transcriptSyntaxStyles
    (cache: Dictionary<string, string array>) source =
    match cache.TryGetValue source with
    | true, styles ->
      styles
    | _ ->
      let styles = syntaxStyles source
      cache.Add(source, styles)
      styles

  let private renderTranscriptLine cache (row: TuiTranscriptLine) =
    let kind = row.Line.Kind
    match row.CommandSyntax with
    | Some(source, lineStart) when not (containsAnsi row.OriginalLine.Text) ->
      let styles = transcriptSyntaxStyles cache source
      kind, colorTranscriptText styles lineStart row
    | _ ->
      kind, row.Line.Text

  let private takeBody bodyHeight bodyWidth model =
    match model.Overlay with
    | TuiOverlay.None | TuiOverlay.Message | TuiOverlay.CommandPalette ->
      let styles = Dictionary<string, string array>(StringComparer.Ordinal)
      let layout =
        TransformerTuiModel.transcriptLayout bodyWidth bodyHeight model
      takeTranscriptRows
        bodyHeight layout.ViewportStart layout.Rows
      |> List.map (renderTranscriptLine styles)
    | _ ->
      let lines = overlayLines bodyWidth model
      let maximumOffset = max 0 (List.length lines - bodyHeight)
      lines
      |> List.skip (min model.ScrollOffset maximumOffset)
      |> List.truncate bodyHeight

  let private clippedInputRange length (start, count) =
    let start = max 0 start
    let finish = min length (start + count)
    if start < finish then Some(start, finish) else None

  let private syntaxBoundaries start length (styles: string array) =
    if length < 2 then
      []
    else
      styles[start..start + length - 1]
      |> Array.pairwise
      |> Array.indexed
      |> Array.choose (fun (index, (left, right)) ->
        if left = right then None else Some(index + 1))
      |> Array.toList

  let private inputStyleBoundaries length start styles ranges selection =
    [ 0; length ]
    @ syntaxBoundaries start length styles
    @ (ranges |> List.collect (fun (first, last) -> [ first; last ]))
    @ (selection
       |> Option.map (fun (first, last) -> [ first; last ])
       |> Option.defaultValue [])
    |> List.distinct
    |> List.sort

  let private styleInputText
    (text: string) startIndex (styles: string array) diagnostics selection =
    let ranges =
      diagnostics
      |> List.choose (clippedInputRange text.Length)
    let selection = selection |> Option.bind (clippedInputRange text.Length)
    let boundaries =
      inputStyleBoundaries text.Length startIndex styles ranges selection
    boundaries
    |> List.pairwise
    |> List.map (fun (start, finish) ->
      let isDiagnostic =
        ranges
        |> List.exists (fun (first, last) -> first <= start && start < last)
      let isSelected =
        selection
        |> Option.exists (fun (first, last) -> first <= start && start < last)
      let style =
        if isSelected then reverse
        elif isDiagnostic then red + underline
        else styles[startIndex + start]
      paint style text[start..finish - 1])
    |> String.concat ""

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

  let private slicePart (text: string) startAt endAt =
    let startAt = max 0 (min text.Length startAt)
    let endAt = max startAt (min text.Length endAt)
    text.Substring(startAt, endAt - startAt)

  let private suggestionItemLine innerWidth selected index item =
    let marker = if index = selected then "> " else "  "
    let markerStyle = if index = selected then reverse else ""
    let labelStyle = if index = selected then reverse + bold else bold
    let detailStyle = if index = selected then reverse + dim else dim
    let label: string = item.Label
    let padded = fit innerWidth $"{marker}{label}  {item.Detail}"
    let labelEnd = marker.Length + label.Length
    let markerPart = slicePart padded 0 marker.Length
    let labelPart = slicePart padded marker.Length labelEnd
    let restPart = slicePart padded labelEnd padded.Length
    paint markerStyle markerPart
    + paint labelStyle labelPart
    + paint detailStyle restPart

  let private suggestionItemWindow rowCount width completion selected =
    let count = List.length completion.Items
    let boxed = rowCount > 2
    let innerWidth = if boxed then max 1 (width - 2) else width
    let hint = hintRows innerWidth completion
    let visible =
      max 0 ((if boxed then rowCount - 2 else rowCount) - List.length hint)
    let start =
      if visible <= 0 then
        0
      else
        let pageStart = selected / visible * visible
        max 0 (min pageStart (count - visible))
    boxed, hint, start, visible

  let private suggestionRows rowCount width completion selected =
    let rowCount = max 1 rowCount
    let count = List.length completion.Items
    let boxed, hint, start, visible =
      suggestionItemWindow rowCount width completion selected
    let innerWidth = if boxed then max 1 (width - 2) else width
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
        let itemRows =
          completion.Items
          |> List.skip start
          |> List.truncate visible
          |> List.mapi (fun offset item ->
            let index = start + offset
            suggestionItemLine innerWidth selected index item)
        hint @ itemRows
    if boxed then
      [ boxTop cyan width "Suggestions" ]
      @ (contentRows |> List.map (boxSide cyan))
      @ [ boxBottom cyan width ]
      |> fitSuggestionRows rowCount width
    else
      contentRows |> fitSuggestionRows rowCount width

  let trySuggestionIndexAt
    width
    height
    (completion: SuggestionSet)
    (model: TransformerTuiModel)
    row
    column =
    let itemCount = List.length completion.Items
    if model.Layout = TuiLayout.Console
       || model.Overlay <> TuiOverlay.None
       || model.IsBusy
       || itemCount = 0
       || row < 1
       || column < 1
       || column > width then
      None
    else
      let suggestionCount = TransformerTuiModel.suggestionHeight height model
      let inputRows = TransformerTuiModel.visibleShellInputRows height model
      let bodyHeight = TransformerTuiModel.transcriptHeight height model
      let suggestionStart =
        match model.BottomPaneOrder with
        | TuiBottomPaneOrder.ShellAboveSuggestions ->
          5 + bodyHeight + inputRows
        | TuiBottomPaneOrder.SuggestionsAboveShell ->
          5 + bodyHeight
      let boxed, hint, start, visible =
        suggestionItemWindow
          suggestionCount width completion model.SuggestionIndex
      let firstItem =
        suggestionStart + (if boxed then 1 else 0) + List.length hint
      let offset = row - firstItem
      if offset < 0 || offset >= visible then
        None
      else
        Some(start + offset)

  let private ghostText (completion: SuggestionSet) selected model =
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

  let private inputSegments available (row: TuiInputRow) =
    let cursorColumn = max 0 (min row.CursorColumn row.Text.Length)
    let start =
      if cursorColumn < available then 0 else cursorColumn - available + 1
    let before =
      if cursorColumn <= start then
        ""
      else
        row.Text[start..cursorColumn - 1]
    let ghost =
      let length = max 0 (available - before.Length)
      if length = 0 then
        ""
      elif row.Ghost.Length > length then
        row.Ghost[..length - 1]
      else
        row.Ghost
    let after =
      if cursorColumn >= row.Text.Length then "" else row.Text[cursorColumn..]
    let afterLength = max 0 (available - before.Length - ghost.Length)
    let after =
      if afterLength = 0 then
        ""
      elif after.Length > afterLength then
        after[..afterLength - 1]
      else
        after
    start, cursorColumn, before, ghost, after

  let private selectionInInputRow (row: TuiInputRow) start length =
    row.Selection
    |> Option.bind (fun (first, last) ->
      let finish = start + length
      let first = max first start
      let last = min last finish
      if first < last then Some(first - start, last - first) else None)

  let private styleInputSegment
    (row: TuiInputRow) start (text: string) diagnostics =
    let selection = selectionInInputRow row start text.Length
    styleInputText text start row.Styles diagnostics selection

  let private inputRow width (row: TuiInputRow) =
    let available = max 1 (width - row.Prompt.Length)
    let start, cursorColumn, before, ghost, after = inputSegments available row
    let visibleLength = before.Length + ghost.Length + after.Length
    let beforeHighlights =
      lineHighlights (row.TextStart + start) before.Length row.Diagnostics
    let afterHighlights =
      lineHighlights (row.TextStart + cursorColumn) after.Length row.Diagnostics
    let before =
      styleInputSegment row (row.TextStart + start) before beforeHighlights
    let after =
      styleInputSegment row (row.TextStart + cursorColumn) after afterHighlights
    let padding = String.replicate (available - visibleLength) " "
    let cursor = row.Prompt.Length + cursorColumn - start + 1
    paint green row.Prompt + before + paint dim ghost + after + padding, cursor

  let private indexedInputLines (input: string) =
    let rec loop start output = function
      | [] ->
        List.rev output
      | (line: string) :: rest ->
        loop (start + line.Length + 1) ((start, line) :: output) rest
    splitInputLines input |> loop 0 []

  let private inputSelection model =
    model.InputAnchor
    |> Option.map (fun anchor ->
      min anchor model.Cursor, max anchor model.Cursor)
    |> Option.filter (fun (first, last) -> first < last)

  let private renderInputRow
    width
    (state: TuiInputRenderState)
    (first, offset)
    (lineStart, line) =
    let absolute = first + offset
    let prompt =
      if state.Model.IsBusy then
        "  "
      elif absolute = 0 then
        "> "
      else
        "  "
    let isCursorLine = absolute = state.CursorLine
    let ghost =
      if isCursorLine then
        ghostText state.Completion state.Model.SuggestionIndex state.Model
      else
        ""
    let column = if isCursorLine then state.CursorColumn else 0
    let diagnostics =
      state.Completion.Diagnostics
      |> List.map (fun item -> item.Start, item.Length)
    let row: TuiInputRow =
      { Prompt = prompt
        Text = line
        TextStart = lineStart
        CursorColumn = column
        Ghost = ghost
        Diagnostics = diagnostics
        Styles = state.Styles
        Selection = state.Selection }
    inputRow width row, isCursorLine

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
    let state =
      { Completion = completion
        Model = model
        CursorLine = cursorLine
        CursorColumn = cursorColumn
        Styles = syntaxStyles model.Input
        Selection = inputSelection model }
    let rows, cursor =
      visible
      |> List.mapi (fun offset (lineStart, line) ->
        renderInputRow width state (first, offset) (lineStart, line))
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

  let tryInputCursorAt width height (model: TransformerTuiModel) row column =
    if model.Overlay <> TuiOverlay.None || model.IsBusy then
      None
    else
      let maxRows = TransformerTuiModel.shellInputCapacity height model
      let visibleRows =
        TransformerTuiModel.visibleShellInputRows height model
      let lines = indexedInputLines model.Input
      let cursorLine, cursorColumn =
        cursorInputPosition model.Input model.Cursor
      let first =
        if cursorLine < maxRows then 0 else cursorLine - maxRows + 1
      let inputStart = TransformerTuiModel.inputStartRow height model
      let offset = row - inputStart
      let absolute = first + offset
      let isOutsideInput = offset < 0 || offset >= visibleRows
      let isOutsideFrame = column < 1 || column > width
      if isOutsideInput || isOutsideFrame then
        None
      else
        lines
        |> List.tryItem absolute
        |> Option.map (fun (lineStart, line) ->
          let cursorColumn = if absolute = cursorLine then cursorColumn else 0
          let available = max 1 (width - 2)
          let start =
            if cursorColumn < available then 0 else cursorColumn - available + 1
          let local = max 0 (min line.Length (start + column - 3))
          lineStart + local)

  let private contextFooter width model =
    let cwd = compactPath Environment.CurrentDirectory
    let script = normalizePath (scriptPath model)
    let record = scriptRecordText model.Session.ReplayMode
    let text =
      $" {model.Status}  cwd: {cwd}  script: {script}  record: {record}"
    paint dim (fit width text)

  let private activeFindInput model =
    match model.ViewPane with
    | Some pane when model.Overlay = TuiOverlay.View && pane.IsFinding ->
      Some(pane.FindText, pane.FindCursor)
    | _ when model.IsFindingTranscript ->
      Some(model.TranscriptFindText, model.TranscriptFindCursor)
    | _ ->
      None

  let private findInputStart width (text: string) cursor =
    let inputWidth = max 0 (width - " find: ".Length)
    max 0 (cursor - inputWidth + 1) |> min text.Length

  let tryFindCursorAt width height model row column =
    match activeFindInput model with
    | Some(text, cursor) when row = height
                              && column >= 1
                              && column <= width ->
      let start = findInputStart width text cursor
      let position = start + max 0 (column - " find: ".Length - 1)
      Some(min text.Length position)
    | _ ->
      None

  let private findFooter width model =
    match activeFindInput model with
    | Some(findText, cursor) ->
      let prompt = " find: "
      let inputWidth = max 0 (width - prompt.Length)
      let start = findInputStart width findText cursor
      let length = min inputWidth (findText.Length - start)
      let input = findText.Substring(start, length)
      let padding = String.replicate (inputWidth - input.Length) " "
      let row = paint (paletteInputBg + paletteFg) (prompt + input + padding)
      row, Some(prompt.Length + cursor - start + 1)
    | _ ->
      contextFooter width model, None

  let private keyButton active label =
    if active then paint reverse $" {label} " else paint dim $" {label} "

  let private headerButtons =
    [ HeaderKey ConsoleKey.F1, "F1 help"
      HeaderKey ConsoleKey.F2, "F2 command"
      HeaderKey ConsoleKey.F3, "F3 find"
      HeaderKey ConsoleKey.F4, "F4 view"
      HeaderRun, "Run"
      HeaderCopy, "Copy" ]

  let private headerMargin = " "

  let private headerGap = "  "

  let private keyHeader width model =
    let isHelpView =
      match model.Overlay, model.ViewPane with
      | TuiOverlay.View, Some pane ->
        pane.Title = "Help"
      | _ ->
        false
    let buttons =
      headerButtons
      |> List.map (fun (hit, label) ->
        let active =
          match hit with
          | HeaderKey ConsoleKey.F1 ->
            isHelpView
          | HeaderKey ConsoleKey.F2 ->
            model.Overlay = TuiOverlay.CommandPalette
          | HeaderKey ConsoleKey.F3 ->
            activeFindInput model |> Option.isSome
          | HeaderKey ConsoleKey.F4 ->
            model.Overlay = TuiOverlay.View
          | _ ->
            false
        keyButton active label)
    fit width
      (headerMargin + String.concat headerGap buttons + headerMargin)

  let tryHeaderHitAt width model row column =
    let isOutside =
      model.Layout = TuiLayout.Console
      || row <> 2
      || column < 1
      || column > width
    if isOutside then
      None
    else
      headerButtons
      |> List.fold (fun (start, found) (hit, label) ->
        let finish = start + label.Length + 1
        let found =
          if column >= start && column <= finish then Some hit else found
        finish + headerGap.Length + 1, found)
        (headerMargin.Length + 1, None)
      |> snd

  let private centerPad width (text: string) =
    let text = if text.Length > width then text[..width - 1] else text
    let extra = width - text.Length
    let left = extra / 2
    String.replicate left " " + text + String.replicate (extra - left) " "

  let private messageBoxRows boxWidth (message: string) =
    let wrapped =
      TransformerTuiText.wrapWithOffsets boxWidth message
      |> List.map (fun (_, _, line) -> line)
    let blank = paint noticeBg (centerPad boxWidth "")
    let dismiss =
      paint (noticeBg + noticeFg)
        (centerPad boxWidth "Press Enter (or Esc) to dismiss.")
    [ blank ]
    @ (wrapped
       |> List.map (fun line ->
         paint (noticeBg + noticeFg + bold) (centerPad boxWidth line)))
    @ [ blank; dismiss ]

  let private commandPaletteGhost
    inputWidth
    (input: string)
    (model: TransformerTuiModel)
    (candidates: (string * string) list) =
    let ghost =
      if model.PaletteCursor = model.PaletteInput.Length then
        candidates
        |> List.tryItem model.PaletteSuggestionIndex
        |> Option.map fst
        |> Option.filter (fun command ->
          command.StartsWith(model.PaletteInput,
                             StringComparison.OrdinalIgnoreCase))
        |> Option.map (fun command -> command[model.PaletteInput.Length..])
        |> Option.defaultValue ""
      else
        ""
    let ghostWidth = max 0 (inputWidth - input.Length)
    if ghostWidth = 0 then
      ""
    elif ghost.Length > ghostWidth then
      ghost[..ghostWidth - 1]
    else
      ghost

  let private commandPaletteCandidateRows
    boxWidth
    (model: TransformerTuiModel)
    (candidates: (string * string) list) =
    candidates
    |> List.mapi (fun index (command, detail) ->
      let marker = if index = model.PaletteSuggestionIndex then "> " else "  "
      let style =
        if index = model.PaletteSuggestionIndex then
          noticeBg + noticeFg + bold
        else
          noticeBg + noticeFg
      paint style (fit boxWidth $"{marker}{command}  {detail}"))

  let private commandPaletteRows boxWidth model =
    let candidates = Suggestions.commandPaletteCandidates model.PaletteFilter
    let inputWidth = max 1 (boxWidth - 2)
    let start = max 0 (model.PaletteCursor - inputWidth + 1)
    let length = min inputWidth (model.PaletteInput.Length - start)
    let input = model.PaletteInput.Substring(start, length)
    let ghost = commandPaletteGhost inputWidth input model candidates
    let prompt = ": " + input
    let paddingLength = inputWidth - input.Length - ghost.Length
    let padding = String.replicate paddingLength " "
    let blank = paint noticeBg (centerPad boxWidth "")
    let prompt =
      paint (paletteInputBg + paletteFg) prompt
      + paint (paletteInputBg + paletteGhostFg) ghost
      + paint paletteInputBg padding
    let candidateRows = commandPaletteCandidateRows boxWidth model candidates
    let padding =
      List.replicate
        (Suggestions.commandPaletteMaxItems - List.length candidateRows)
        blank
    [ blank; prompt ] @ candidateRows @ padding @ [ blank ], start

  let private paletteBoxWidth width = max 24 (min 60 (width - 8))

  let private paletteOrigin width height boxWidth boxHeight =
    let startCol = max 0 ((width - boxWidth) / 2)
    let startRow = max 0 ((height - boxHeight) / 2)
    startCol, startRow

  let paletteHitAt width height model row column =
    let boxWidth = paletteBoxWidth width
    let boxHeight = Suggestions.commandPaletteMaxItems + 3
    let startCol, startRow =
      paletteOrigin width height boxWidth boxHeight
    let inside =
      row > startRow && row <= startRow + boxHeight
      && column > startCol && column <= startCol + boxWidth
    if not inside then
      PaletteOutside
    elif row = startRow + 2 then
      let inputWidth = max 1 (boxWidth - 2)
      let start = max 0 (model.PaletteCursor - inputWidth + 1)
      let cursor = start + max 0 (column - startCol - 3)
      PaletteInput(min model.PaletteInput.Length cursor)
    elif row >= startRow + 3
         && row < startRow + 3 + Suggestions.commandPaletteMaxItems then
      let index = row - startRow - 3
      let candidates =
        Suggestions.commandPaletteCandidates model.PaletteFilter
      if index < List.length candidates then
        PaletteCandidate index
      else
        PaletteInside
    else
      PaletteInside

  /// Paints `boxContent` over `line`, starting at the visible column
  /// `startCol`; `boxContent` must already be exactly `boxWidth` visible
  /// columns wide. Text outside the box keeps its position but loses its
  /// original color, since the box opaquely covers whatever was behind it.
  let private overwriteColumns startCol boxWidth (boxContent: string) line =
    let plain = TransformerTuiText.stripAnsi line
    let plain =
      if plain.Length < startCol + boxWidth then
        plain.PadRight(startCol + boxWidth)
      else
        plain
    let left = plain[..startCol - 1]
    let right = plain[startCol + boxWidth..]
    clearLine + left + boxContent + right + reset

  let private overlayMessageBox width height model lines =
    if model.Overlay <> TuiOverlay.Message then
      lines
    else
      let boxWidth = max 30 (min 60 (width - 8))
      let boxRows = messageBoxRows boxWidth model.Status
      let boxHeight = List.length boxRows
      let startCol = max 0 ((width - boxWidth) / 2)
      let startRow = max 0 ((height - boxHeight) / 2)
      boxRows
      |> List.iteri (fun offset boxRow ->
        let row = startRow + offset
        if row < Array.length lines then
          lines[row] <- overwriteColumns startCol boxWidth boxRow lines[row]
        else
          ())
      lines

  let private overlayCommandPalette width height model lines =
    if model.Overlay <> TuiOverlay.CommandPalette then
      lines, None
    else
      let boxWidth = paletteBoxWidth width
      let boxRows, inputStart = commandPaletteRows boxWidth model
      let boxHeight = List.length boxRows
      let startCol, startRow =
        paletteOrigin width height boxWidth boxHeight
      boxRows
      |> List.iteri (fun offset boxRow ->
        let row = startRow + offset
        if row < Array.length lines then
          lines[row] <- overwriteColumns startCol boxWidth boxRow lines[row]
        else
          ())
      let cursorRow = startRow + 2
      let cursorColumn = startCol + 3 + model.PaletteCursor - inputStart
      lines, Some(cursorRow, cursorColumn)

  let viewScrollOffset width height model =
    if model.Overlay = TuiOverlay.View then
      let bodyHeight = TransformerTuiModel.transcriptHeight height model
      let bodyWidth = TransformerTuiModel.transcriptBodyWidth width model
      viewPaneLayout bodyWidth bodyHeight model.ScrollOffset model
      |> fun layout -> layout.Offset
    else
      model.ScrollOffset

  let moveViewCursorByRows width height amount extend model =
    match model.ViewPane with
    | Some pane ->
      let bodyWidth = TransformerTuiModel.transcriptBodyWidth width model
      let layout = viewRows bodyWidth pane
      let rows = layout.Rows
      let first, last = layout.Ranges[pane.Cursor.Line]
      let current = viewCursorRow rows pane first last
      let target = max 0 (min (rows.Length - 1) (current + amount))
      let column = max 0 (pane.Cursor.Column - rows[current].Start)
      let row = rows[target]
      let column = min row.Finish (row.Start + column)
      let model =
        TransformerTuiModel.moveViewCursorTo
          row.SourceLine column extend model
      { model with ScrollOffset = viewScrollOffset width height model }
    | None ->
      model

  let tryViewCursorAt width height model row column =
    match model.ViewPane with
    | Some pane when model.Overlay = TuiOverlay.View ->
      let bodyHeight = TransformerTuiModel.transcriptHeight height model
      let bodyWidth = TransformerTuiModel.transcriptBodyWidth width model
      let bodyRow = row - TransformerTuiModel.bodyStartRow model
      let layout = viewPaneLayout bodyWidth bodyHeight model.ScrollOffset model
      let rowIndex = layout.Offset + bodyRow
      let rows = viewRows bodyWidth pane
      let isInBody =
        bodyRow >= 0
        && bodyRow < bodyHeight
        && isMainBodyAt width height model row column
      let isDisplayRow = rowIndex >= 0 && rowIndex < rows.Rows.Length
      if not isInBody || not isDisplayRow then
        None
      else
        let row = rows.Rows[rowIndex]
        let contentStart =
          if model.Layout = TuiLayout.Console then 3 else 4
        let cursor =
          { Line = row.SourceLine
            Column =
              max row.Start (min row.Finish
                (column - contentStart + row.Start)) }
        Some cursor
    | _ ->
      None

  let render width height _registry model completion =
    if not (isInteractiveSize width height) then
      let message = "Terminal too small. Resize to at least 40 x 15."
      { Lines = [| clearLine + fit width message |]
        CursorRow = 1
        CursorColumn = 1 }
    else
      let shellInputRows =
        TransformerTuiModel.shellInputCapacity height model
      let inputRows, inputCursor =
        inputView width shellInputRows model completion
      let bodyHeight =
        TransformerTuiModel.transcriptHeight height model
      let suggestionCount =
        TransformerTuiModel.suggestionHeight height model
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
          takeBody bodyHeight leftWidth model)
      let body =
        if model.Layout = TuiLayout.Console
           && viewLayout.IsNone then
          let layout =
            TransformerTuiModel.transcriptLayout leftWidth bodyHeight model
          let count =
            TransformerTuiModel.transcriptTopPadding bodyHeight model layout
          List.replicate count (TuiLineKind.Output, "") @ body
        else
          body
      let padding =
        List.replicate (bodyHeight - List.length body)
          (TuiLineKind.Output, "")
      let cursorBodyPosition =
        TransformerTuiModel.transcriptCursorDisplayPosition
          leftWidth bodyHeight model
        |> Option.orElse (viewLayout |> Option.bind _.CursorPosition)
      let body = body @ padding
      let sidebar =
        if hasSidebar then sidebarLines rightWidth bodyHeight model else []
      let sidebar = sidebar @ List.replicate (bodyHeight - List.length sidebar)
                                      ("", "")
      let bodyRows =
        if model.Layout = TuiLayout.Console then
          body
          |> List.map (fun (kind, text) ->
            paint (lineStyle kind) (fit width text))
        else
          List.map2 (renderBodyRow leftWidth rightWidth) body sidebar
      let titleBar =
        let text = " B2R2 TRANSFORMER   Interactive Binary Analysis"
        paint (bannerBg + bannerFg + bold) (fit width text)
      let boxTopRow =
        let title =
          match model.Overlay, model.ViewPane with
          | TuiOverlay.View, Some pane ->
            pane.Title
          | _ ->
            "Main Window"
        if hasSidebar then
          boxTop border leftWidth title
          + " " + boxTop border rightWidth "Values"
        else
          boxTop border leftWidth title
      let boxBottomRow =
        if hasSidebar then
          boxBottom border leftWidth + " " + boxBottom border rightWidth
        else
          boxBottom border leftWidth
      let suggestions =
        if model.Layout = TuiLayout.Console then
          []
        else
          suggestionRows
            suggestionCount width completion model.SuggestionIndex
      let context, findCursor =
        match model.Layout, activeFindInput model with
        | TuiLayout.Console, None -> "", None
        | _ -> findFooter width model
      let bottomRows =
        if model.Layout = TuiLayout.Console then
          inputRows
        else
          match model.BottomPaneOrder with
          | TuiBottomPaneOrder.ShellAboveSuggestions ->
            inputRows @ suggestions
          | TuiBottomPaneOrder.SuggestionsAboveShell ->
            suggestions @ inputRows
      let inputStartRow = TransformerTuiModel.inputStartRow height model
      let rows =
        if model.Layout = TuiLayout.Console then
          bodyRows @ bottomRows
          @ (if findCursor.IsSome then [ context ] else [])
        else
          [ titleBar
            keyHeader width model
            boxTopRow ]
          @ bodyRows
          @ [ boxBottomRow ]
          @ bottomRows
          @ [ context ]
      let lines =
        rows
        |> List.map (fun row -> clearLine + row + reset)
        |> List.toArray
        |> overlayMessageBox width height model
      let lines, paletteCursor =
        overlayCommandPalette width height model lines
      { Lines = lines
        CursorRow =
          paletteCursor
          |> Option.map fst
          |> Option.orElse (findCursor |> Option.map (fun _ -> height))
          |> Option.orElseWith (fun () ->
            cursorBodyPosition
            |> Option.map (fun (row, _) ->
              TransformerTuiModel.bodyStartRow model + row))
          |> Option.defaultValue (
            let row, _ = inputCursor
            inputStartRow + row)
        CursorColumn =
          paletteCursor
          |> Option.map snd
          |> Option.orElse findCursor
          |> Option.orElseWith (fun () ->
            cursorBodyPosition
            |> Option.map (fun (_, column) ->
              let offset =
                if model.Layout = TuiLayout.Console
                   && model.Overlay = TuiOverlay.View then 0 else 1
              min width (column + offset)))
          |> Option.defaultValue (
            let _, column = inputCursor
            min width column) }
