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

module TransformerReplParser =
  let parsePipelineTokens tokens =
    ReplLanguage.parsePipelineTokens tokens

  let private parseInt (value: string) =
    match Int32.TryParse value with
    | true, value -> Ok value
    | _ -> Error "Value history ID must be an integer."

  let private parseRestore id name =
    parseInt id |> Result.map (fun id -> Restore(id, name))

  let private parsePluginLoad (value: string) =
    if value.StartsWith("path=", StringComparison.OrdinalIgnoreCase) then
      let path = value[5..]
      if String.IsNullOrWhiteSpace path then
        Error ":plugin load path= requires a DLL path."
      else
        Ok(PluginLoad path)
    else
      Ok(PluginLoad value)

  let private parseMetaCommand = function
    | [] -> Ok NoInput
    | [ ":quit" ] | [ ":q" ] -> Ok Quit
    | [ ":help" ] -> Ok Help
    | [ ":actions" ] -> Ok Actions
    | [ ":history" ] -> Ok History
    | [ ":values" ] -> Ok Values
    | [ ":undo" ] -> Ok Undo
    | [ ":log" ] -> Ok Log
    | [ ":export"; name; path ] when ReplLanguage.isValidName name ->
      Ok(ExportValue(name, path))
    | [ ":inspect" ] -> Ok(Inspect None)
    | [ ":inspect"; name ] -> Ok(Inspect(Some name))
    | ":needs" :: name :: args when ReplLanguage.isValidName name ->
      Ok(Needs(name, args))
    | [ ":needs" ] ->
      Error ":needs requires an executor binding."
    | [ ":restore"; id ] -> parseRestore id None
    | [ ":restore"; id; "as"; name ] when ReplLanguage.isValidName name ->
      parseRestore id (Some name)
    | [ ":script"; "save"; path ] -> Ok(SaveScript path)
    | [ ":script"; "load"; path ] -> Ok(LoadScript path)
    | [ ":script"; "record" ] -> Ok(ScriptRecord None)
    | [ ":script"; "record"; "on" ] -> Ok(ScriptRecord(Some true))
    | [ ":script"; "record"; "off" ] -> Ok(ScriptRecord(Some false))
    | [ ":plugin"; "load"; path ] -> parsePluginLoad path
    | [ ":plugin"; "load" ] -> Error ":plugin load requires a DLL path."
    | [ ":plugin" ] -> Error ":plugin requires an operation: load."
    | ":layout" :: options -> Ok(Layout options)
    | "#" :: rest -> Ok(ScriptComment(String.concat " " rest))
    | [ ":reset" ] -> Ok Reset
    | [ ":show" ] -> Ok(Show None)
    | ":show" :: rest ->
      ReplLanguage.parsePipelineTokens rest |> Result.map ShowExpression
    | [ ":type" ] -> Ok(TypeOf None)
    | [ ":type"; name ] -> Ok(TypeOf(Some name))
    | command :: _ when command.StartsWith ':' ->
      Error $"Unknown REPL command: {command}"
    | tokens ->
      let command = String.concat " " tokens
      Error $"Unknown REPL command: {command}"

  let parse (input: string) =
    let trimmed = input.TrimStart()
    if trimmed.StartsWith "#" then
      Ok(ScriptComment(trimmed[1..].TrimStart()))
    else
      InputAnalysis.tokenizeStrict input
      |> Result.bind (function
        | [] -> Ok NoInput
        | command :: _ as tokens when command.StartsWith ':' ->
          parseMetaCommand tokens
        | tokens ->
          ReplLanguage.parseEvaluation input tokens)
