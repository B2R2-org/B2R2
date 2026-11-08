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

module TransformerReplParser =
  let parsePipelineTokens tokens =
    ReplLanguage.parsePipelineTokens tokens

  let private parseInt (value: string) =
    match Int32.TryParse value with
    | true, value ->
      Ok value
    | _ ->
      Error "Value history ID must be an integer."

  let private parseRestore id name =
    parseInt id |> Result.map (fun id -> Restore(id, name))

  let private parsePathArgument command (value: string) =
    if value.StartsWith("path=", StringComparison.OrdinalIgnoreCase) then
      let path = value[5..] |> ReplLanguage.unquote
      if String.IsNullOrWhiteSpace path then
        Error $"{command} path= requires a path."
      else
        Ok path
    else
      Ok value

  type private ControlForm =
    { Words: string list
      Detail: string
      Parse: string list -> Result<TransformerReplCommand, string>
      Suggest: bool }

  let private form words detail parse =
    { Words = words; Detail = detail; Parse = parse; Suggest = true }

  let private fixedForm words detail command =
    form words detail (function
      | [] ->
        Ok command
      | _ ->
        let name = String.concat " " words
        Error $"Invalid arguments for {name}.")

  let private pathForm words detail command =
    let name = ":" + String.concat " " words
    form words detail (function
      | [ path ] -> parsePathArgument name path |> Result.map command
      | _ -> Error $"{name} requires a path.")

  let private layoutForm words detail options =
    form words detail (fun rest -> Ok(Layout(options @ rest)))

  let private layoutOption option detail =
    layoutForm [ "layout"; option ] detail [ option ]

  let private recordingForm name enabled detail =
    fixedForm [ "script"; "record"; name ] detail (ScriptRecord(Some enabled))

  let private controlForms =
    [ form [ "help" ] "Show guide or action help" (function
        | [] -> Ok(Help None)
        | [ action ] -> Ok(Help(Some action))
        | _ -> Error "help accepts one action name.")
      fixedForm [ "actions" ] "List action documentation" Actions
      fixedForm [ "history" ] "Show evaluated commands" History
      fixedForm [ "values" ] "Show retained values" Values
      fixedForm [ "undo" ] "Undo the last value change" Undo
      fixedForm [ "log" ] "Show command execution records" Log
      form [ "export" ] "Export a named value" (function
        | [ name; path ] when ReplLanguage.isValidName name ->
          parsePathArgument ":export" path
          |> Result.map (fun path -> ExportValue(name, path))
        | _ ->
          Error "export requires a binding and a path.")
      form [ "inspect" ] "Inspect a value" (function
        | [] -> Ok(Inspect None)
        | [ name ] -> Ok(Inspect(Some name))
        | _ -> Error "inspect accepts one binding name.")
      form [ "needs" ] "Show missing executor context" (function
        | name :: args when ReplLanguage.isValidName name ->
          Ok(Needs(name, args))
        | _ ->
          Error ":needs requires an executor binding.")
      form [ "restore" ] "Restore a value-history entry" (function
        | [ id ] ->
          parseRestore id None
        | [ id; "as"; name ] when ReplLanguage.isValidName name ->
          parseRestore id (Some name)
        | _ ->
          Error "restore requires a value ID.")
      pathForm [ "script"; "save" ] "Save the replay script" SaveScript
      pathForm [ "script"; "load" ] "Load a replay script" LoadScript
      form [ "script"; "record" ] "Show or change recording" (function
        | [] -> Ok(ScriptRecord None)
        | [ "on" ] -> Ok(ScriptRecord(Some true))
        | [ "off" ] -> Ok(ScriptRecord(Some false))
        | _ -> Error "script record expects on or off.")
      recordingForm "on" true "Enable script recording"
      recordingForm "off" false "Disable script recording"
      pathForm [ "plugin"; "load" ] "Load a plugin DLL" PluginLoad
      { form [ "plugin" ] "" (fun _ ->
          Error ":plugin requires an operation: load.") with
          Suggest = false }
      layoutOption "pane" "Show pane layout"
      layoutOption "console" "Show console layout"
      layoutOption "resize" "Adjust pane sizes"
      layoutForm
        [ "layout"; "pane"; "swap" ]
        "Swap input and suggestions"
        [ "pane"; "swap" ]
      layoutOption "sidebar=auto" "Auto sidebar"
      layoutOption "sidebar=off" "Hide sidebar"
      layoutOption "suggestions=auto" "Auto suggestions"
      layoutOption "mode=pane" "Pane layout"
      layoutOption "mode=console" "Console layout"
      layoutForm [ "layout" ] "Configure REPL layout" []
      fixedForm [ "reset" ] "Reset analysis state" Reset
      form [ "type" ] "Show a value or expression type" (function
        | [] ->
          Ok(TypeOf None)
        | [ name ] ->
          Ok(TypeOf(Some name))
        | rest ->
          ReplLanguage.parsePipelineTokens rest
          |> Result.map TypeOfExpression)
      fixedForm [ "quit" ] "Leave the Transformer TUI" Quit
      { fixedForm [ "q" ] "" Quit with Suggest = false } ]

  let private controlAliases =
    Map.ofList
      [ ([], "h"), "help"
        ([], "a"), "actions"
        ([], "hi"), "history"
        ([], "v"), "values"
        ([], "t"), "type"
        ([], "i"), "inspect"
        ([], "n"), "needs"
        ([], "lg"), "log"
        ([], "e"), "export"
        ([], "r"), "restore"
        ([], "u"), "undo"
        ([], "rs"), "reset"
        ([], "s"), "script"
        ([], "p"), "plugin"
        ([], "l"), "layout"
        ([], "q"), "quit"
        ([ "script" ], "s"), "save"
        ([ "script" ], "l"), "load"
        ([ "script" ], "r"), "record"
        ([ "plugin" ], "l"), "load"
        ([ "layout" ], "c"), "console"
        ([ "layout" ], "p"), "pane"
        ([ "layout" ], "r"), "resize"
        ([ "layout"; "pane" ], "s"), "swap" ]

  let private firstWord (input: string) =
    let index = input.IndexOfAny([| ' '; '\t'; '\r'; '\n' |])
    if index < 0 then input, ""
    else input[..index - 1], input[index..]

  let rec private expandAliasWords context input =
    let word, rest = firstWord input
    let canonical =
      Map.tryFind (context, word) controlAliases
      |> Option.defaultValue word
    let next = rest.TrimStart()
    if String.IsNullOrEmpty next then
      canonical + rest
    else
      let padding = rest[..rest.Length - next.Length - 1]
      canonical + padding
      + expandAliasWords (context @ [ canonical ]) next

  let expandControlAliases (input: string) =
    let input = input.TrimStart()
    if input.StartsWith ':' then
      ":" + expandAliasWords [] input[1..]
    else
      expandAliasWords [] input

  let private startsWithWords prefix words =
    List.length prefix <= List.length words
    && List.forall2 (=) prefix (words |> List.take (List.length prefix))

  let private parseMetaCommand tokens =
    match tokens with
    | [] ->
      Ok NoInput
    | "#" :: rest ->
      Ok(ScriptComment(String.concat " " rest))
    | command :: rest ->
      let command = command.TrimStart ':'
      let words = command :: rest
      controlForms
      |> List.filter (fun entry -> startsWithWords entry.Words words)
      |> List.sortByDescending (fun entry -> List.length entry.Words)
      |> List.tryHead
      |> function
        | Some entry ->
          words
          |> List.skip (List.length entry.Words)
          |> entry.Parse
        | None when command = "script" ->
          Error ":script requires save, load, or record."
        | None ->
          Error $"Unknown REPL command: {command}"

  let private completePath prefix =
    let path = (prefix: string).TrimStart([| '\''; '"' |])
    let directory = Path.GetDirectoryName path
    let directory = if isNull directory then "" else directory
    let searchDirectory = if directory = "" then "." else directory
    let filePrefix = Path.GetFileName path
    try
      Directory.EnumerateFileSystemEntries searchDirectory
      |> Seq.choose (fun entry ->
        let name = Path.GetFileName entry
        if name.StartsWith(filePrefix, StringComparison.OrdinalIgnoreCase) then
          let relative =
            if directory = "" then name
            else directory.TrimEnd([| '/'; '\\' |]) + "/" + name
          let relative = relative.Replace('\\', '/')
          let isDirectory = Directory.Exists entry
          let value = if isDirectory then relative + "/" else relative
          let value = if value.Contains ' ' then $"\"{value}\"" else value
          let detail = if isDirectory then "Directory" else "File"
          Some(value, detail)
        else
          None)
      |> Seq.truncate 20
      |> Seq.toList
    with _ ->
      []

  let private pathCandidates head (input: string) =
    if input.StartsWith(head + " ", StringComparison.OrdinalIgnoreCase) then
      let suffix = input[(head.Length + 1)..]
      let named = suffix.StartsWith("path=", StringComparison.OrdinalIgnoreCase)
      let prefix = if named then suffix[5..] else suffix
      let label = if named then head + " path=" else head + " "
      let marker =
        if suffix = "" then [ head + " path=", "Enter a path" ] else []
      marker
      @ (completePath prefix
         |> List.map (fun (path, detail) -> label + path, detail))
    else
      []

  let private bindingNames state =
    let names = state.Bindings |> Map.toList |> List.map fst
    match TransformerReplState.tryLastResult state with
    | Some _ ->
      TransformerReplState.LastResultName :: names
    | None ->
      names

  let private namedCandidates registry state =
    let actions =
      registry.AllSorted
      |> List.map (fun action ->
        let name = ActionMetadata.actionName action.Metadata.ID
        $"help {name}", "Show action usage")
    let bindings =
      bindingNames state
      |> List.collect (fun name ->
        [ $"inspect {name}", "Inspect this value"
          $"type {name}", "Show this value's type"
          $"export {name}", "Export this value" ])
    let executors =
      state.Bindings
      |> Map.toList
      |> List.choose (fun (name, value) ->
        if value.Kind = ReplValueKind.ConcExecutor then
          Some($"needs {name}", "Show missing context")
        else
          None)
    let history =
      state.ValueHistory
      |> List.collect (fun entry ->
        [ $"restore {entry.ID}", "Restore this value"
          $"restore {entry.ID} as", "Name this restored value" ])
    actions @ bindings @ executors @ history

  let private controlPathCandidates input bindings =
    let paths =
      [ "script save"; "script load"; "plugin load" ]
      |> List.collect (fun head -> pathCandidates head input)
    let exportPaths =
      match InputAnalysis.splitWords input with
      | "export" :: name :: _ when List.contains name bindings ->
        pathCandidates ("export " + name) input
      | _ ->
        []
    paths @ exportPaths

  let controlCandidates registry state (input: string) =
    let input = expandControlAliases input
    let input = input.TrimStart ':'
    let staticCandidates =
      controlForms
      |> List.filter (fun entry -> entry.Suggest)
      |> List.map (fun entry ->
        String.concat " " entry.Words, entry.Detail)
    let fixedArguments =
      [ "layout sidebar=", "Enter a sidebar width"
        "layout suggestions=", "Enter a suggestion height" ]
    staticCandidates @ fixedArguments @ namedCandidates registry state
    @ controlPathCandidates input (bindingNames state)
    |> List.filter (fun (command, _) ->
      command.StartsWith(input, StringComparison.OrdinalIgnoreCase))
    |> List.distinctBy fst

  let private normalizeControlTokens (tokens: string list) =
    match tokens with
    | command :: rest when not (command.StartsWith ':') ->
      (":" + command) :: rest
    | tokens ->
      tokens

  let parseControl (input: string) =
    expandControlAliases input
    |> InputAnalysis.tokenizeStrict
    |> Result.bind
      (List.map ReplLanguage.unquote
       >> normalizeControlTokens
       >> parseMetaCommand)

  let parse (input: string) =
    let trimmed = input.TrimStart()
    if trimmed.StartsWith "#" then
      Ok(ScriptComment(trimmed[1..].TrimStart()))
    else
      InputAnalysis.tokenizeStrict input
      |> Result.bind (ReplLanguage.parseEvaluation input)
