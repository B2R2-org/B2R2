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

module B2R2.RearEnd.Transformer.Program

open B2R2.RearEnd.Transformer

let private usage = """Usage:
  b2r2 transformer [repl [-d <plugin>] [--layout pane|console]]
  b2r2 transformer script [-d <plugin>] <script>

Start the interactive Transformer REPL, or evaluate a saved REPL script.
Press F1 in the interactive REPL for the usage guide."""

let private printUsage () =
  printfn "%s" usage

let private runRepl plugin layout =
  ActionRegistry.create plugin |> TransformerRepl.runWithLayout layout
  0

let private parseReplOptions args =
  let rec loop (plugin: string option) layout = function
    | [] ->
      Some(plugin, layout)
    | "-d" :: file :: rest when plugin.IsNone ->
      loop (Some file) layout rest
    | "--layout" :: name :: rest ->
      TuiLayout.tryParse name
      |> Option.bind (fun layout -> loop plugin layout rest)
    | option :: rest when option.StartsWith "--layout=" ->
      TuiLayout.tryParse option[9..]
      |> Option.bind (fun layout -> loop plugin layout rest)
    | _ ->
      None
  loop None TuiLayout.Pane args

let private runScript plugin path =
  ActionRegistry.create plugin
  |> fun registry -> TransformerRepl.runScript registry path

[<EntryPoint>]
let main argv =
  match List.ofArray argv with
  | [] ->
    runRepl None TuiLayout.Pane
  | "repl" :: options ->
    match parseReplOptions options with
    | Some(plugin, layout) ->
      runRepl plugin layout
    | None ->
      eprintfn "%s" usage
      1
  | "script" :: path :: [] ->
    runScript None path
  | "script" :: "-d" :: file :: path :: [] ->
    runScript (Some file) path
  | [ "-h" ]
  | [ "--help" ] ->
    printUsage ()
    0
  | _ ->
    eprintfn "%s" usage
    1
