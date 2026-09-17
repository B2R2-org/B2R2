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

/// A type error located in the expression currently being edited.
type ReplTypeDiagnostic =
  { Start: int
    Length: int
    Message: string }

/// Type flow through the pipeline currently being edited.
type ReplPipelineTypeAnalysis =
  { CurrentInput: ReplValueKind option
    Output: ReplValueKind option
    Diagnostics: ReplTypeDiagnostic list }

/// Shared type-flow analysis for completion and live diagnostics.
module ReplTypeAnalysis =
  type private TextSegment =
    { Text: string
      Start: int
      Length: int
      Tokens: string list }

  type private SegmentResult =
    { Input: ReplValueKind option
      Output: ReplValueKind option
      Diagnostics: ReplTypeDiagnostic list }

  let private isActionReference (head: string) =
    head.StartsWith("@", StringComparison.Ordinal) && head.Length > 1

  let private actionID (head: string) =
    if isActionReference head then head[1..] else head

  let private isIterHead head =
    String.Equals(head, "iter", StringComparison.OrdinalIgnoreCase)
    || String.Equals(head, "iteri", StringComparison.OrdinalIgnoreCase)

  let private trimSegment (text: string) start finish =
    let mutable first = start
    let mutable last = finish
    while first < last && Char.IsWhiteSpace text[first] do
      first <- first + 1
    while last > first && Char.IsWhiteSpace text[last - 1] do
      last <- last - 1
    let content = if first = last then "" else text[first..last - 1]
    { Text = content
      Start = first
      Length = last - first
      Tokens = InputAnalysis.splitWords content }

  let private textSegments (text: string) =
    let rec loop start segments = function
      | pipeline :: rest ->
        let segment = trimSegment text start pipeline
        loop (pipeline + 2) (segment :: segments) rest
      | [] ->
        trimSegment text start text.Length :: segments |> List.rev
    ReplLanguage.topLevelPipelinePositions text |> loop 0 []

  let private splitLiteralElements separator tokens =
    ReplLanguage.splitTopLevel separator tokens

  let private kindOfElement state = function
    | [ name ] ->
      TransformerReplState.tryFind name state
      |> Option.map (fun value -> value.Kind)
    | _ -> None

  let private homogeneousKind kinds =
    let kinds =
      kinds
      |> List.filter (fun kind -> kind <> ReplValueKind.Unit)
      |> List.distinct
    match kinds with
    | [ kind ] -> kind
    | _ -> ReplValueKind.Any

  let private literalKind state tokens =
    match tokens, List.rev tokens with
    | "(" :: body, ")" :: _ ->
      let body = body |> List.rev |> List.tail |> List.rev
      if List.contains "," body then
        let elements = splitLiteralElements "," body
        let kinds = elements |> List.map (kindOfElement state)
        if List.forall Option.isSome kinds then
          kinds |> List.map Option.get |> ReplValueKind.Tuple |> Some
        else
          None
      else
        None
    | "[" :: body, "]" :: _ ->
      let body = body |> List.rev |> List.tail |> List.rev
      let elements = splitLiteralElements ";" body
      let kinds = elements |> List.map (kindOfElement state)
      if List.forall Option.isSome kinds then
        kinds
        |> List.map Option.get
        |> homogeneousKind
        |> ReplValueKind.List
        |> Some
      else
        None
    | "[|" :: body, "|]" :: _ ->
      let body = body |> List.rev |> List.tail |> List.rev
      let elements = splitLiteralElements ";" body
      let kinds = elements |> List.map (kindOfElement state)
      if List.forall Option.isSome kinds then
        kinds
        |> List.map Option.get
        |> homogeneousKind
        |> ReplValueKind.Array
        |> Some
      else
        None
    | _ -> None

  let collectionElementKind = function
    | ReplValueKind.Collection kind
    | ReplValueKind.List kind
    | ReplValueKind.Array kind -> Some kind
    | ReplValueKind.Tuple kinds ->
      match List.distinct kinds with
      | [ kind ] -> Some kind
      | _ -> Some ReplValueKind.Any
    | _ -> None

  let acceptsInput kind (metadata: ActionMetadata) =
    ActionMetadata.acceptedInputs metadata
    |> List.exists (ReplValueKind.isCompatible kind)

  let private actionOutput (metadata: ActionMetadata) inputKind args =
    if metadata.ID = "pick" then
      inputKind
      |> Option.bind collectionElementKind
      |> Option.defaultValue metadata.Output
    else
      ActionMetadata.outputForArguments metadata inputKind args

  let private headDiagnostic baseOffset (segment: TextSegment) (head: string)
                             actual (metadata: ActionMetadata) =
    let expected =
      ActionMetadata.acceptedInputs metadata
      |> List.map ReplValueKind.toString
      |> String.concat " | "
    let actual = ReplValueKind.toString actual
    let relative =
      segment.Text.IndexOf(head, StringComparison.OrdinalIgnoreCase)
    let relative = if relative < 0 then 0 else relative
    { Start = baseOffset + segment.Start + relative
      Length = head.Length
      Message = $"{head} expects {expected}, but receives {actual}." }

  let private directResult registry baseOffset input
                           (segment: TextSegment) (tokens: string list) =
    match tokens with
    | head :: args ->
      match ActionRegistry.tryFind (actionID head) registry with
      | None ->
        { Input = input; Output = None; Diagnostics = [] }
      | Some registered ->
        let metadata = registered.Metadata
        match input with
        | Some kind when kind <> ReplValueKind.Any
                         && not (acceptsInput kind metadata) ->
          { Input = input
            Output = None
            Diagnostics =
              [ headDiagnostic baseOffset segment head kind metadata ] }
        | _ ->
          { Input = input
            Output = Some(actionOutput metadata input args)
            Diagnostics = [] }
    | [] ->
      { Input = input; Output = input; Diagnostics = [] }

  let private tryParameterValue name (token: string) =
    let index = token.IndexOf '='
    if index <= 0 then
      None
    else
      let key = token[..index - 1]
      let typeIndex = key.IndexOf ':'
      let key = if typeIndex <= 0 then key else key[..typeIndex - 1]
      if String.Equals(key, name, StringComparison.OrdinalIgnoreCase) then
        Some token[index + 1..]
      else
        None

  let private tryIterTarget (tokens: string list) =
    let named =
      tokens |> List.tryPick (tryParameterValue "action")
    match named with
    | Some target -> Some target
    | None ->
      tokens
      |> List.skip 1
      |> List.takeWhile (fun token -> token <> "(" && token <> "params=")
      |> List.tryFind isActionReference

  let private iterArguments (tokens: string list) =
    match tokens |> List.tryFindIndex ((=) "->") with
    | None -> []
    | Some index ->
      tokens
      |> List.skip (index + 1)
      |> List.takeWhile ((<>) ")")

  let private iterResult registry baseOffset input
                         (segment: TextSegment) (tokens: string list) =
    match input |> Option.bind collectionElementKind with
    | None ->
      match input, tokens with
      | Some kind, head :: _ when kind <> ReplValueKind.Any ->
        let message = $"{head} expects a collection, but receives "
                      + $"{ReplValueKind.toString kind}."
        { Input = input
          Output = None
          Diagnostics =
            [ { Start = baseOffset + segment.Start
                Length = head.Length
                Message = message } ] }
      | _ ->
        { Input = input; Output = None; Diagnostics = [] }
    | Some elementKind ->
      match tryIterTarget tokens with
      | None ->
        { Input = input; Output = None; Diagnostics = [] }
      | Some target ->
        match ActionRegistry.tryFind (actionID target) registry with
        | None ->
          { Input = input; Output = None; Diagnostics = [] }
        | Some registered ->
          let metadata = registered.Metadata
          if elementKind <> ReplValueKind.Any
             && not (acceptsInput elementKind metadata) then
            { Input = input
              Output = None
              Diagnostics =
                [ headDiagnostic baseOffset segment target elementKind
                    metadata ] }
          else
            let args = iterArguments tokens
            let output = actionOutput metadata (Some elementKind) args
            { Input = input
              Output = Some(ReplValueKind.Collection output)
              Diagnostics = [] }

  let private transformResult registry baseOffset input
                              (segment: TextSegment) =
    let tokens = segment.Tokens
    match tokens with
    | head :: _ when isIterHead head ->
      iterResult registry baseOffset input segment tokens
    | _ ->
      directResult registry baseOffset input segment tokens

  let private firstResult registry state baseOffset (segment: TextSegment) =
    let tokens = segment.Tokens
    match literalKind state tokens with
    | Some kind ->
      { Input = None; Output = Some kind; Diagnostics = [] }
    | None ->
      match tokens with
      | [] ->
        { Input = None; Output = None; Diagnostics = [] }
      | head :: args ->
        match TransformerReplState.tryFind head state with
        | Some value when List.isEmpty args ->
          { Input = None; Output = Some value.Kind; Diagnostics = [] }
        | _ when isIterHead head ->
          let input = state.Current |> Option.map (fun value -> value.Kind)
          iterResult registry baseOffset input segment tokens
        | _ ->
          match ActionRegistry.tryFind (actionID head) registry with
          | None ->
            { Input = None; Output = None; Diagnostics = [] }
          | Some registered ->
            let metadata = registered.Metadata
            let input =
              if acceptsInput ReplValueKind.Unit metadata then
                Some ReplValueKind.Unit
              else
                state.Current |> Option.map (fun value -> value.Kind)
            directResult registry baseOffset input segment tokens

  let private analyzeSegments registry state baseOffset segments =
    match segments with
    | [] ->
      { CurrentInput = None; Output = None; Diagnostics = [] }
    | first :: rest ->
      let first = firstResult registry state baseOffset first
      let folder (previous, results) segment =
        let result =
          transformResult registry baseOffset previous.Output segment
        result, result :: results
      let last, reversed = List.fold folder (first, [ first ]) rest
      let results = List.rev reversed
      let currentInput = results |> List.last |> fun result -> result.Input
      { CurrentInput = currentInput
        Output = last.Output
        Diagnostics = results |> List.collect _.Diagnostics }

  let analyze registry state baseOffset (expression: string) =
    textSegments expression |> analyzeSegments registry state baseOffset

  let analyzePartial registry state baseOffset (expression: string)
                     (pipeline: ReplPartialPipeline) =
    pipeline.Segments
    |> List.map (fun segment ->
      let text =
        if segment.Start >= expression.Length then ""
        else
          let last = min (expression.Length - 1) (segment.End - 1)
          expression[segment.Start..last]
      { Text = text
        Start = segment.Start
        Length = segment.End - segment.Start
        Tokens = segment.Tokens })
    |> analyzeSegments registry state baseOffset

  let outputBeforeLastPartial registry state baseOffset
                              (expression: string)
                              (pipeline: ReplPartialPipeline) =
    let segments =
      match List.rev pipeline.Segments with
      | _ :: rest -> List.rev rest
      | [] -> []
    let pipeline = { pipeline with Segments = segments }
    (analyzePartial registry state baseOffset expression pipeline).Output

  let inputKind registry state expression =
    (analyze registry state 0 expression).CurrentInput

  let outputKind registry state expression =
    (analyze registry state 0 expression).Output
