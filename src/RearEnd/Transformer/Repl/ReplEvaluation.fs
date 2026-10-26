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

/// The result of evaluating one interactive command.
type ReplEvaluation =
  | Continue of ActionRegistry * TransformerReplState * output: ReplOutput
  | Exit of ActionRegistry * TransformerReplState

module internal ReplEvaluation =
  open ReplRendering
  let ofOption error = function
    | Some value ->
      Ok value
    | None ->
      Error error

  let private formatAction registered =
    let metadata = (registered: RegisteredAction).Metadata
    let name = ActionMetadata.actionName metadata.ID
    $"{name.PadRight 28} {metadata.Description}"

  let private outputLines lines =
    ReplOutput.ofLines lines

  let private continueOutput registry state output =
    Continue(registry, state, output)

  let continueWith registry state lines =
    continueOutput registry state (outputLines lines)

  let continueValue registry state value =
    continueOutput registry state (outputValue value)

  let continuePrintResult registry state result =
    continueOutput registry state (outputPrintResult result)

  let describeValue name value =
    let count = value.Collection.Values.Length
    let description =
      if (value: ReplValue).IsCollection then
        $"{typeDescription value} ({count} values)"
      else
        typeDescription value
    match name with
    | Some name ->
      $"{name}: {description}"
    | None ->
      description

  let suggestions registry kind =
    let actions = ActionRegistry.getApplicable kind registry
    if List.isEmpty actions || kind = ReplValueKind.Unit then
      []
    else
      "Available next actions:" :: List.map formatAction actions

  let selectValue name state =
    match name with
    | Some name ->
      TransformerReplState.tryFind name state
      |> Option.map (fun value -> name, value)
      |> ofOption $"Unknown binding: {name}"
    | None ->
      state.Current
      |> Option.map (fun value -> "current value", value)
      |> ofOption "There is no current value."

  let fail registry state message =
    let state = TransformerReplState.setError message state
    continueWith registry state [ $"Error: {message}" ]
