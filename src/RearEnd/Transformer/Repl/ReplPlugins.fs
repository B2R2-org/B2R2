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
open System.Threading

/// Loads explicit plugins and resolves symbolic solver plugins on demand.
module internal ReplPlugins =
  open ReplArguments
  open ReplActionRuntime
  open ReplRendering

  let private pluginSearchRoots () =
    [ Path.Combine(Directory.GetCurrentDirectory(), "plugins")
      Path.Combine(AppContext.BaseDirectory, "plugins") ]
    |> List.distinct
    |> List.filter Directory.Exists

  let private pluginDllIndex =
    lazy
      pluginSearchRoots ()
      |> List.collect (fun root ->
        Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories)
        |> Seq.toList)
      |> List.sortWith (fun left right ->
        StringComparer.OrdinalIgnoreCase.Compare(left, right))

  let private tryLoadPlugin registry path =
    try
      ActionRegistry.loadPlugin path registry |> Ok
    with error ->
      let file = Path.GetFileName path
      Error $"{file}: {error.Message}"

  let private pluginFailureText solverID failures =
    let shown = failures |> List.rev |> List.truncate 5
    let omitted = max 0 (List.length failures - List.length shown)
    let details = shown |> List.map (fun error -> "  - " + error)
    let details =
      if omitted = 0 then
        details
      else
        details @ [ $"  - ... and {omitted} more failure(s)" ]
    let heading =
      if List.isEmpty details then
        []
      else
        [ "Plugin load failures:" ]
    [ $"Solver plugin not found: {solverID}"
      yield! heading
      yield! details ]
    |> String.concat Environment.NewLine

  let private tryAutoLoadSolver registry solverID (ct: CancellationToken) =
    let hasSolver registry =
      Option.isSome (SymbSolverRegistry.create solverID)
      || Option.isSome (tryFindAction registry solverID)
    if hasSolver registry then
      Ok registry
    else
      pluginDllIndex.Value
      |> List.fold (fun (registry, failures) path ->
        ct.ThrowIfCancellationRequested()
        if hasSolver registry then
          registry, failures
        else
          match tryLoadPlugin registry path with
          | Ok registry ->
            registry, failures
          | Error error ->
            registry, error :: failures)
        (registry, [])
      |> fun (registry, failures) ->
        if hasSolver registry then
          Ok registry
        else
          pluginFailureText solverID failures |> Error

  let registerSymbSolver registry args ct =
    match args |> List.tryPick (parameterValue "solver") with
    | None ->
      Ok registry
    | Some solverID ->
      match SymbSolverRegistry.create solverID with
      | Some _ ->
        Ok registry
      | None ->
        tryAutoLoadSolver registry solverID ct
        |> Result.bind (fun registry ->
          match tryFindAction registry solverID with
          | None ->
            Error $"Unknown symbolic solver: {solverID}"
          | Some registered ->
            let metadata = registered.Metadata
            let isSource =
              ActionMetadata.acceptedInputs metadata
              |> List.contains ReplValueKind.Unit
            if not isSource
               || not (ReplValueKind.isCompatible metadata.Output
                         ReplValueKind.SymbSolver) then
              Error $"{solverID} is not a symbolic solver action."
            else
              try
                let segment =
                  { Head = ActionMetadata.actionName metadata.ID
                    Arguments = [] }
                let collection =
                  transform
                    registered
                    ReplValue.emptyInput
                    segment
                    ct
                match collection.Values with
                | [| :? SymbSolverValue as solver |] ->
                  let factory =
                    Func<B2R2.MiddleEnd.SymbEval.ISolver>(fun () ->
                      solver.Create())
                  SymbSolverRegistry.register
                    solver.ID
                    solver.Description
                    factory
                  Ok registry
                | _ ->
                  Error $"{solverID} did not return a SymbSolver."
              with
              | :? OperationCanceledException ->
                reraise ()
              | error ->
                Error error.Message)

  let private actionIDs registry =
    (registry: ActionRegistry).Actions |> Map.toSeq |> Seq.map fst |> Set.ofSeq

  let load registry state path command =
    try
      let before = actionIDs registry
      let fullPath = Path.GetFullPath path
      let registry = ActionRegistry.loadPlugin fullPath registry
      let added =
        ActionRegistry.getAll registry
        |> List.filter (fun action ->
          Set.contains action.Metadata.ID before |> not)
        |> List.map (fun action -> ActionMetadata.actionName action.Metadata.ID)
      let addedText =
        match added with
        | [] ->
          "none"
        | _ ->
          String.concat ", " added
      let state = TransformerReplState.recordReplayCommand command state
      let lines =
        [ $"Plugin loaded: {normalizePath fullPath}"
          $"  actions: {addedText}" ]
      Ok(registry, state, lines)
    with error ->
      Error error.Message
