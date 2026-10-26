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
open System.Diagnostics
open System.IO
open System.Threading

module TransformerReplEvaluator =
  open ReplEvaluation

  let private scriptCommands path =
    if not (File.Exists path) then
      Error $"Script file not found: {path}"
    else
      File.ReadAllLines path
      |> Array.toList
      |> InputAnalysis.combineCommandLines

  let private resultState = function
    | Continue(registry, state, output) ->
      Ok(registry, state, output)
    | Exit _ ->
      Error "A script cannot contain :quit."

  let private addExecutionLog
    timestamp
    (stopwatch: Stopwatch)
    (input: string)
    evaluation =
    if String.IsNullOrWhiteSpace input then
      evaluation
    else
      let status, detail =
        match evaluation with
        | Continue(_, _, output) when output.HasError ->
          output.Lines
          |> Seq.tryFind (fun line ->
            line.StartsWith("Error:", StringComparison.Ordinal))
          |> function
            | Some error ->
              ReplExecutionStatus.Failed, Some error
            | None ->
              ReplExecutionStatus.Succeeded, None
        | Continue _ ->
          ReplExecutionStatus.Succeeded, None
        | Exit _ ->
          ReplExecutionStatus.Succeeded, None
      let record (state: TransformerReplState) =
        TransformerReplState.recordExecution
          timestamp
          stopwatch.Elapsed
          status
          input
          detail
          state
      match evaluation with
      | Continue(registry, state, output) ->
        Continue(registry, record state, output)
      | Exit(registry, state) ->
        Exit(registry, record state)

  let rec private evaluateInput
    includeSuggestions
    registry
    state
    (input: string)
    (ct: CancellationToken) =
    match InputAnalysis.splitTopLevelCommands input with
    | _ :: _ :: _ as commands ->
      let outputs = ResizeArray<string>()
      let folder result command =
        result
        |> Result.bind (fun (currentRegistry, currentState) ->
          ct.ThrowIfCancellationRequested()
          evaluateInput
            includeSuggestions
            currentRegistry
            currentState
            command
            ct
          |> resultState
          |> Result.map (fun (nextRegistry, nextState, output) ->
            outputs.AddRange output.Lines
            nextRegistry, nextState))
      commands
      |> List.fold folder (Ok(registry, state))
      |> function
        | Ok(registry, state) ->
          continueWith registry state (Seq.toList outputs)
        | Error message ->
          fail registry state message
    | _ ->
      let timestamp = DateTimeOffset.Now
      let stopwatch = Stopwatch.StartNew()
      let state =
        if String.IsNullOrWhiteSpace input then
          state
        else
          TransformerReplState.recordCommand input state
      let evaluation =
        evaluateCore includeSuggestions registry state input ct
      stopwatch.Stop()
      addExecutionLog timestamp stopwatch input evaluation

  and private evaluateCore
    includeSuggestions
    registry
    state
    input
    ct =
    evaluateParsed
      includeSuggestions
      registry
      state
      input
      ct
      (TransformerReplParser.parse input)

  and private evaluateControlCore
    includeSuggestions
    registry
    state
    input
    ct =
    evaluateParsed
      includeSuggestions
      registry
      state
      input
      ct
      (TransformerReplParser.parseControl input)

  and private evaluateParsed
    includeSuggestions
    registry
    state
    input
    ct
    parsed =
    let load path =
      loadScript includeSuggestions registry state path ct
    ReplDispatch.dispatch
      includeSuggestions
      registry
      state
      input
      ct
      load
      parsed

  and private loadScript
    _includeSuggestions
    registry
    state
    path
    ct =
    let fullPath = Path.GetFullPath path
    match scriptCommands fullPath with
    | Error message ->
      fail registry state message
    | Ok commands ->
      let outputs = ResizeArray<string>()
      commands
      |> List.fold (fun result command ->
        result
        |> Result.bind (fun (loadedRegistry, loadedState) ->
          ct.ThrowIfCancellationRequested()
          evaluateInput
            false
            loadedRegistry
            loadedState
            command
            ct
          |> resultState
          |> Result.bind (fun (nextRegistry, nextState, output) ->
            if output.HasError then
              let error =
                output.Lines
                |> Seq.find (fun line ->
                  line.StartsWith("Error:", StringComparison.Ordinal))
              Error error
            else
              outputs.Add $"> {command}"
              outputs.AddRange output.Lines
              Ok(nextRegistry, nextState))))
        (Ok(registry, TransformerReplState.empty))
      |> function
        | Error message ->
          fail registry state $"Script replay failed: {message}"
        | Ok(registry, loaded) ->
          let state = TransformerReplState.replaceAnalysis loaded state
          let state =
            TransformerReplState.setSessionPath
              (ReplRendering.normalizePath path) state
          let header =
            [ $"Script loaded: {ReplRendering.normalizePath fullPath}" ]
          continueWith registry state (header @ Seq.toList outputs)

  let evaluateCommand registry state input ct =
    evaluateInput false registry state input ct

  let evaluateControlCommand registry state input ct =
    let timestamp = DateTimeOffset.Now
    let stopwatch = Stopwatch.StartNew()
    let state = TransformerReplState.recordCommand input state
    let evaluation =
      evaluateControlCore false registry state input ct
    stopwatch.Stop()
    addExecutionLog timestamp stopwatch input evaluation
