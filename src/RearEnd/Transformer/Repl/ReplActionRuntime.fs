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
open System.Threading

/// Executes validated actions and reports action input mismatches.
module internal ReplActionRuntime =
  open ReplRendering

  let isActionReference (head: string) =
    head.StartsWith("@", StringComparison.Ordinal) && head.Length > 1

  let actionID (head: string) =
    if isActionReference head then head[1..] else head

  let tryFindAction registry head =
    ActionRegistry.tryFind (actionID head) registry

  let transform
    (registered: RegisteredAction)
    input
    (segment: ReplPipelineSegment)
    (ct: CancellationToken) =
    ct.ThrowIfCancellationRequested()
    let action = registered.Action :?> ICancellableAction
    let collection =
      action.Transform(segment.Arguments, input.Collection, ct)
    ct.ThrowIfCancellationRequested()
    collection

  let actionInputError (input: ReplValue) (metadata: ActionMetadata) =
    let actual = formatKind input.Kind
    let expected =
      ActionMetadata.acceptedInputs metadata
      |> List.map formatKind
      |> String.concat " | "
    match metadata.ID, input.Kind with
    | "save", ReplValueKind.Collection _
    | "save", ReplValueKind.List _
    | "save", ReplValueKind.Array _ ->
      "save expects one Binary; use iteri to save collection items."
    | _ ->
      $"{metadata.ID} expects {expected}, but received {actual}."

  let transformWith
    (registered: RegisteredAction)
    (input: ReplValue)
    (segment: ReplPipelineSegment)
    (ct: CancellationToken)
    (outputKind: ReplValueKind)
    (args: string list)
    assignments =
    let segment: ReplPipelineSegment =
      { segment with Arguments = args }
    try
      let collection =
        match assignments, registered.Action with
        | Some arguments,
          (:? ICancellableNamedArgumentsAction as namedAction) ->
          let collection = input.Collection
          namedAction.TransformNamed(arguments, collection, ct)
        | _ ->
          transform registered input segment ct
      collection
      |> ReplValue.ofCollection outputKind
      |> Ok
    with
    | :? OperationCanceledException ->
      reraise ()
    | error ->
      Error error.Message
