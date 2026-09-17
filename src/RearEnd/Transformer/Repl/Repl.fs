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
open System.Text
open System.Threading
open System.Threading.Tasks

type private RunningEvaluation =
  { Task: Task<ReplEvaluation>
    Cancellation: CancellationTokenSource
    Command: string
    StartedAt: DateTimeOffset }

type private ScriptReplayOutput =
  { Parent: TuiLine list
    Commands: (string * TuiLine list) list }

type private SuggestionCache =
  { Input: string
    Cursor: int
    Session: TransformerReplState
    Suggestions: SuggestionSet }

module TransformerRepl =
  let private printOutput output =
    (output: ReplOutput).Lines |> List.iter (printfn "%s")

  let private runLineMode registry =
    printfn "B2R2 Transformer interactive analysis"
    printfn "Type :help for commands and :actions for available actions."
    let rec loop state =
      let input = Console.ReadLine()
      if isNull input then
        ()
      elif input.Trim() = ":clear" then
        loop state
      else
        match TransformerReplEvaluator.evaluateLine registry state input with
        | Exit _ ->
          ()
        | Continue(state, output) ->
          printOutput output
          loop state
    loop TransformerReplState.empty

  let private scriptLines path =
    if not (System.IO.File.Exists path) then
      Error $"Script file not found: {path}"
    else
      System.IO.File.ReadAllLines path
      |> Array.toList
      |> InputAnalysis.combineCommandLines

  let runScript registry path =
    match scriptLines path with
    | Error message ->
      eprintfn "%s" message
      1
    | Ok lines ->
      let rec loop state = function
        | [] -> 0
        | line :: rest ->
          let evaluation =
            TransformerReplEvaluator.evaluateTuiLine registry state line
              CancellationToken.None
          match evaluation with
          | Exit _ ->
            0
          | Continue(next, output) ->
            printOutput output
            let failed =
              output.Lines
              |> List.exists (fun text ->
                text.StartsWith("Error:", StringComparison.Ordinal))
            if failed then 1 else loop next rest
      loop TransformerReplState.empty lines

  let private hasModifier modifier (key: ConsoleKeyInfo) =
    key.Modifiers &&& modifier = modifier

  let private isTextKey key =
    not (hasModifier ConsoleModifiers.Control key)
    && not (hasModifier ConsoleModifiers.Alt key)
    && not (Char.IsControl key.KeyChar)

  let private toTuiLine (line: string) =
    let kind =
      if line.StartsWith("Error:", StringComparison.Ordinal) then
        TuiLineKind.Error
      else
        TuiLineKind.Output
    { Kind = kind; Text = line }

  let private replayCommandPrefix = "> "

  let private isScriptReplayOutput (output: ReplOutput) =
    output.Lines
    |> List.tryHead
    |> Option.exists (fun line ->
      line.StartsWith("Script loaded:", StringComparison.Ordinal))

  let private tryReplayCommand (line: string) =
    if line.StartsWith(replayCommandPrefix, StringComparison.Ordinal) then
      Some line[replayCommandPrefix.Length..]
    else
      None

  let private splitScriptReplayLines lines =
    let parent = ResizeArray<TuiLine>()
    let commands = ResizeArray<string * ResizeArray<TuiLine>>()
    let mutable current: ResizeArray<TuiLine> option = None
    for line in lines do
      match tryReplayCommand line with
      | Some command ->
        let output = ResizeArray<TuiLine>()
        commands.Add((command, output))
        current <- Some output
      | None ->
        let line = toTuiLine line
        match current with
        | Some output -> output.Add line
        | None -> parent.Add line
    { Parent = Seq.toList parent
      Commands =
        commands
        |> Seq.map (fun (command, output) -> command, Seq.toList output)
        |> Seq.toList }

  let private replayTranscriptLines replay =
    let commandLines =
      replay.Commands
      |> List.collect (fun (command, output) ->
        { Kind = TuiLineKind.Command; Text = command } :: output)
    replay.Parent @ commandLines

  let private setReplayResultBlocks
    parentIndex
    (fullReplay: Lazy<ScriptReplayOutput>)
    model =
    let model =
      TransformerTuiModel.setResultBlock parentIndex
        (lazy fullReplay.Value.Parent) model
    fullReplay.Value.Commands
    |> List.mapi (fun index (_, lines) -> parentIndex + index + 1, lines)
    |> List.fold (fun model (index, lines) ->
      TransformerTuiModel.setResultBlock index (lazy lines) model) model

  let private appendScriptReplayOutput (output: ReplOutput) model =
    let maximumRetainedLines = 5000
    let retained = output.Lines |> List.truncate maximumRetainedLines
    let hidden = List.length output.Lines - List.length retained
    let retained =
      if hidden > 0 then
        retained @ [ $"{hidden} more output lines omitted." ]
      else
        retained
    let replay = splitScriptReplayLines retained
    let fullReplay: Lazy<ScriptReplayOutput> =
      lazy (splitScriptReplayLines output.FullLines.Value)
    let lines = replayTranscriptLines replay
    let blockIndex = model.FoldTarget
    model
    |> TransformerTuiModel.setLastViewLines lines
    |> fun model ->
      match blockIndex with
      | Some index -> setReplayResultBlocks index fullReplay model
      | None -> model
    |> TransformerTuiModel.appendTuiLines lines

  let private appendEvaluationOutput (output: ReplOutput) model =
    if isScriptReplayOutput output then
      appendScriptReplayOutput output model
    else
      let maximumRetainedLines = 5000
      let retained = output.Lines |> List.truncate maximumRetainedLines
      let hidden = List.length output.Lines - List.length retained
      let lines = retained |> List.map toTuiLine
      let lines =
        if hidden > 0 then
          lines
          @ [ { Kind = TuiLineKind.System
                Text = $"{hidden} more output lines omitted." } ]
        else
          lines
      let fullLines =
        lazy (output.FullLines.Value |> List.map toTuiLine)
      let blockIndex = model.FoldTarget
      model
      |> TransformerTuiModel.setLastViewLines lines
      |> fun model ->
        match blockIndex with
        | Some index -> TransformerTuiModel.setResultBlock index fullLines model
        | None -> model
      |> TransformerTuiModel.appendTuiLines lines

  let private finishEvaluation evaluation model =
    match evaluation with
    | Exit session ->
      TransformerTuiModel.setSession session model, true
    | Continue(session, output) ->
      let hasError =
        output.Lines
        |> List.exists (fun line ->
          line.StartsWith("Error:", StringComparison.Ordinal))
      let status = if hasError then "Command failed" else "Ready"
      model
      |> TransformerTuiModel.setSession session
      |> appendEvaluationOutput output
      |> TransformerTuiModel.setBusy false
      |> TransformerTuiModel.setStatus status,
      false

  let private failEvaluation (error: exn) model =
    let message = error.GetBaseException().Message
    model
    |> TransformerTuiModel.appendLines TuiLineKind.Error
      [ $"Internal error: {message}" ]
    |> TransformerTuiModel.setBusy false
    |> TransformerTuiModel.setStatus "Command failed"

  let private startEvaluation registry command model =
    let model =
      model
      |> TransformerTuiModel.appendCommand command
      |> TransformerTuiModel.clearInput
    if command.Trim() = ":clear" then
      let session =
        TransformerReplState.recordCommand command model.Session
      let model =
        model
        |> TransformerTuiModel.clearTranscript
        |> TransformerTuiModel.setSession session
      model, None
    else
      let session = model.Session
      let cancellation = new CancellationTokenSource()
      let task =
        Task.Run((fun () ->
          TransformerReplEvaluator.evaluateTuiLine registry session command
            cancellation.Token), cancellation.Token)
      let model =
        model
        |> TransformerTuiModel.setBusy true
        |> TransformerTuiModel.setStatus "Running action"
      let running =
        { Task = task
          Cancellation = cancellation
          Command = command
          StartedAt = DateTimeOffset.Now }
      model, Some running

  let private cancelEvaluation running (model: TransformerTuiModel) =
    running.Cancellation.Cancel()
    running.Task.ContinueWith(fun (_: Task<ReplEvaluation>) ->
      running.Cancellation.Dispose())
    |> ignore
    let duration = DateTimeOffset.Now - running.StartedAt
    let session =
      model.Session
      |> TransformerReplState.recordCommand running.Command
      |> TransformerReplState.recordExecution running.StartedAt duration
        ReplExecutionStatus.Cancelled running.Command None
    model
    |> TransformerTuiModel.setSession session
    |> TransformerTuiModel.appendLines TuiLineKind.System
      [ "Action cancelled; any late result will be discarded." ]
    |> TransformerTuiModel.setBusy false
    |> TransformerTuiModel.setStatus "Cancelled"

  let private runTui registry =
    let restoreTerminal = TransformerTuiTerminal.enter ()
    let mutable model = TransformerTuiModel.initial
    let mutable running: RunningEvaluation option = None
    let mutable shouldExit = false
    let mutable dirty = true
    let mutable suggestionCache: SuggestionCache option = None
    let mutable pendingKeys: ConsoleKeyInfo list = []
    let mutable lastWidth, lastHeight = 0, 0
    let mutable lastSpinner = Environment.TickCount64
    let addPending key =
      pendingKeys <- pendingKeys @ [ key ]
    let readKey () =
      match pendingKeys with
      | key :: rest ->
        pendingKeys <- rest
        Some key
      | [] when Console.KeyAvailable ->
        Some(Console.ReadKey true)
      | [] ->
        None
    let readTextBurst first =
      let builder = StringBuilder()
      builder.Append((first: ConsoleKeyInfo).KeyChar) |> ignore
      let mutable keepReading = true
      while keepReading && Console.KeyAvailable do
        let key = Console.ReadKey true
        if isTextKey key then
          builder.Append(key.KeyChar) |> ignore
        else
          addPending key
          keepReading <- false
      builder.ToString()
    let samePhysicalKey (left: ConsoleKeyInfo) (right: ConsoleKeyInfo) =
      left.Key = right.Key && left.Modifiers = right.Modifiers
    let isViewNavigationKey (key: ConsoleKeyInfo) =
      not (hasModifier ConsoleModifiers.Control key)
      && not (hasModifier ConsoleModifiers.Alt key)
      && model.Overlay = TuiOverlay.View
      && (model.ViewPane |> Option.exists (fun pane -> not pane.IsFinding))
      && (match key.Key with
          | ConsoleKey.UpArrow
          | ConsoleKey.DownArrow
          | ConsoleKey.LeftArrow
          | ConsoleKey.RightArrow
          | ConsoleKey.PageUp
          | ConsoleKey.PageDown -> true
          | _ -> false)
    let repeatedKeyCount first =
      let mutable count = 1
      let mutable keepReading = true
      while keepReading && Console.KeyAvailable do
        let key = Console.ReadKey true
        if samePhysicalKey first key then
          count <- count + 1
        else
          addPending key
          keepReading <- false
      count
    let pageHeight model =
      let _, height = TransformerTuiTerminal.dimensions ()
      let contentHeight = height - 7
      let defaultBodyHeight = max 1 (contentHeight - model.ShellHeight)
      match model.TranscriptHeight with
      | Some requested -> max 1 (min (contentHeight - 1) requested)
      | None -> defaultBodyHeight
    let applyViewNavigation count (key: ConsoleKeyInfo) model =
      let shift = hasModifier ConsoleModifiers.Shift key
      match key.Key with
      | ConsoleKey.UpArrow ->
        TransformerTuiModel.moveViewCursor -count 0 shift model
      | ConsoleKey.DownArrow ->
        TransformerTuiModel.moveViewCursor count 0 shift model
      | ConsoleKey.LeftArrow ->
        TransformerTuiModel.moveViewCursor 0 -count shift model
      | ConsoleKey.RightArrow ->
        TransformerTuiModel.moveViewCursor 0 count shift model
      | ConsoleKey.PageUp ->
        TransformerTuiModel.pageViewCursor (-(pageHeight model) * count)
          shift model
      | ConsoleKey.PageDown ->
        TransformerTuiModel.pageViewCursor ((pageHeight model) * count)
          shift model
      | _ ->
        model
    let currentSuggestions () =
      match suggestionCache with
      | Some cached
        when cached.Input = model.Input
             && cached.Cursor = model.Cursor
             && Object.ReferenceEquals(cached.Session, model.Session) ->
        cached.Suggestions
      | _ ->
        let suggestions =
          Suggestions.get registry model.Session model.Input model.Cursor
        suggestionCache <-
          Some
            { Input = model.Input
              Cursor = model.Cursor
              Session = model.Session
              Suggestions = suggestions }
        suggestions
    try
      while not shouldExit do
        let width, height = TransformerTuiTerminal.dimensions ()
        if width <> lastWidth || height <> lastHeight then
          lastWidth <- width
          lastHeight <- height
          dirty <- true
        else
          ()
        match running with
        | Some runningEvaluation when runningEvaluation.Task.IsCompleted ->
          let task = runningEvaluation.Task
          if task.IsCanceled then
            model <-
              model
              |> TransformerTuiModel.appendLines TuiLineKind.System
                [ "Action cancelled." ]
              |> TransformerTuiModel.setBusy false
              |> TransformerTuiModel.setStatus "Cancelled"
          else
            try
              let nextModel, exit = finishEvaluation task.Result model
              model <- nextModel
              shouldExit <- exit
            with error -> model <- failEvaluation error model
          runningEvaluation.Cancellation.Dispose()
          running <- None
          dirty <- true
        | Some _ when Environment.TickCount64 - lastSpinner >= 80L ->
          model <- TransformerTuiModel.advanceSpinner model
          lastSpinner <- Environment.TickCount64
          dirty <- true
        | _ ->
          ()
        if not shouldExit then
          match readKey () with
          | None ->
            ()
          | Some key ->
            match running with
            | Some runningEvaluation
              when hasModifier ConsoleModifiers.Control key
                   && key.Key = ConsoleKey.C ->
              model <- cancelEvaluation runningEvaluation model
              running <- None
            | Some _ ->
              ()
            | None when isTextKey key
                        && model.Overlay = TuiOverlay.None
                        && model.Focus = TuiFocus.Shell ->
              let text = readTextBurst key
              model <- TransformerTuiModel.insertText text model
            | None when isViewNavigationKey key ->
              let count = repeatedKeyCount key
              model <- applyViewNavigation count key model
            | None ->
              let completion = currentSuggestions ()
              let input =
                TransformerTuiInputController.handle completion key model
              match input with
              | TuiInputResult.Stop next ->
                model <- next
                shouldExit <- true
              | TuiInputResult.Update next ->
                model <- next
              | TuiInputResult.Execute(next, command) ->
                let next, task = startEvaluation registry command next
                model <- next
                running <- task
            dirty <- true
        else
          ()
        if not shouldExit && dirty then
          let completion = currentSuggestions ()
          let frame =
            TransformerTuiRenderer.render width height registry model completion
          TransformerTuiTerminal.draw model.IsBusy frame
          dirty <- false
        else
          ()
        if not shouldExit then Thread.Sleep 20
        else ()
    finally
      restoreTerminal ()

  let run registry =
    if TransformerTuiTerminal.isInteractive () then runTui registry
    else runLineMode registry
