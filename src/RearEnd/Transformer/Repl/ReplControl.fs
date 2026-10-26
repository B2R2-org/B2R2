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

/// Handles REPL control commands apart from pipeline evaluation.
module internal ReplControl =
  open ReplArguments
  open ReplEvaluation
  open ReplRendering

  let showType registry state name =
    match selectValue name state with
    | Error message ->
      fail registry state message
    | Ok(name, value) ->
      continueWith registry state [ $"{name}: {typeDescription value}" ]

  let private pipelineText segments =
    segments
    |> List.map (fun segment ->
      String.concat " " (segment.Head :: segment.Arguments))
    |> String.concat " |> "

  let showExpressionType registry state segments =
    let expression = pipelineText segments
    let analysis = ReplTypeAnalysis.analyze registry state 0 expression
    match analysis.Output, analysis.Diagnostics with
    | Some kind, [] ->
      continueWith registry state [ $"{expression}: {formatKind kind}" ]
    | _, diagnostic :: _ ->
      fail registry state diagnostic.Message
    | None, [] ->
      fail registry state $"Could not infer the type of: {expression}"

  let showActions registry state =
    ReplHelp.actionsLines registry
    |> continueWith registry state

  let showActionHelp registry state (name: string) =
    let name = name.TrimStart '@'
    match ActionRegistry.tryFind name registry with
    | Some action ->
      ReplHelp.actionLines action |> continueWith registry state
    | None ->
      fail registry state $"Unknown action: @{name}"

  let showHistory registry state =
    state.CommandHistory
    |> List.rev
    |> List.mapi (fun index command -> $"{index}: {command}")
    |> continueWith registry state

  let showValues registry state =
    state.ValueHistory
    |> List.rev
    |> List.map (fun entry ->
      let kind = typeDescription entry.Value
      let name = entry.Name |> Option.defaultValue "<unnamed>"
      $"{entry.ID}: {name}  {kind}")
    |> function
      | [] ->
        [ "No values have been produced." ]
      | output ->
        output
    |> continueWith registry state

  let inspect registry state name =
    match selectValue name state with
    | Error message ->
      fail registry state message
    | Ok(_, value) ->
      let items = TransformerReplInspection.inspect value
      if List.isEmpty items then
        let message =
          "The selected value has no inspectable functions or sections."
        fail registry state message
      else
        items
        |> List.mapi (fun index item ->
          let command =
            match name with
            | Some name ->
              $"{name} |> {item.Command}"
            | None ->
              item.Command
          $"{index}: {item.Label}  {item.Detail}  => {command}")
        |> continueWith registry state

  let needs registry state name args =
    match TransformerReplState.tryFind name state with
    | None ->
      fail registry state $"Unknown binding: {name}"
    | Some value ->
      match value.Collection.Values with
      | [| :? ConcExecutorValue as executor |] ->
        match normalizeNeedsArguments state args with
        | Error message ->
          fail registry state message
        | Ok args ->
          try
            let requirements = executor.Needs args
            let state = TransformerReplState.setLastNeeds requirements state
            continueWith registry state (renderRequirements requirements)
          with error ->
            fail registry state error.Message
      | _ ->
        fail registry state $":needs expects a ConcExecutor binding: {name}"

  let restore registry state id name command =
    match TransformerReplState.restoreValue id name state with
    | Error message ->
      fail registry state message
    | Ok state ->
      let state = TransformerReplState.recordReplayCommand command state
      let value = state.Current |> Option.get
      continueWith registry state [ describeValue name value ]

  let undo registry state =
    match TransformerReplState.undo state with
    | Error message ->
      fail registry state message
    | Ok state ->
      let current =
        state.Current
        |> Option.map typeDescription
        |> Option.defaultValue "none"
      continueWith
        registry
        state
        [ $"Undid the last value change; current: {current}" ]

  let showLog registry state =
    state.ExecutionLog
    |> List.rev
    |> List.map (fun entry ->
      let status = entry.Status.ToString().ToLowerInvariant()
      let elapsed = entry.Duration.TotalMilliseconds
      $"{entry.ID}: {status} {elapsed:F1} ms  {entry.Command}")
    |> function
      | [] ->
        [ "The execution log is empty." ]
      | output ->
        output
    |> continueWith registry state

  let exportValue registry state name path =
    match TransformerReplState.tryFind name state with
    | None ->
      fail registry state $"Unknown binding: {name}"
    | Some value ->
      try
        let fullPath = Path.GetFullPath path
        if value.Collection.Values.Length = 1 then
          ReplArtifactWriter.write fullPath value.Collection.Values[0]
        else
          value.Collection.Values
          |> Array.iteri (fun index item ->
            ReplArtifactWriter.write $"{fullPath}.{index}" item)
        continueWith
          registry
          state
          [ $"Exported {name}: {normalizePath fullPath}" ]
      with error ->
        fail registry state error.Message

  let saveScript registry state path =
    try
      let header = "# B2R2 Transformer script v1"
      let lines = header :: List.rev state.ReplayCommands |> List.toArray
      let fullPath = Path.GetFullPath path
      File.WriteAllLines(fullPath, lines)
      let state =
        TransformerReplState.setSessionPath (normalizePath path) state
      continueWith registry state [ $"Script saved: {normalizePath fullPath}" ]
    with error ->
      fail registry state error.Message

  let private scriptRecordText = function
    | ReplReplayMode.Reproducible ->
      "on"
    | ReplReplayMode.Exploratory ->
      "off"

  let setScriptRecord registry state enabled =
    match enabled with
    | Some true ->
      let state =
        TransformerReplState.setReplayMode ReplReplayMode.Reproducible state
      continueWith registry state [ "Script recording: on" ]
    | Some false ->
      let state =
        TransformerReplState.setReplayMode ReplReplayMode.Exploratory state
      continueWith registry state [ "Script recording: off" ]
    | None ->
      let status = scriptRecordText state.ReplayMode
      continueWith registry state [ $"Script recording: {status}" ]

  let addScriptComment registry state text =
    let state = TransformerReplState.recordReplayComment text state
    continueWith registry state [ "Script comment recorded." ]

  let loadPlugin registry state path command =
    match ReplPlugins.load registry state path command with
    | Ok(registry, state, lines) ->
      continueWith registry state lines
    | Error message ->
      fail registry state message
