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
open System.Globalization
open System.Numerics
open System.Threading

/// Evaluates typed pipelines and records their resulting analysis values.
module internal ReplPipeline =
  open ReplRendering
  open ReplArguments
  open ReplActionRuntime
  open ReplPlugins
  open ReplEvaluation
  open ReplLiterals

  let private isIterHead head =
    equalsIgnoreCase head "iter" || equalsIgnoreCase head "iteri"

  let private mergeSeparatedEquals tokens =
    let rec loop output = function
      | key :: "=" :: value :: rest ->
        loop ($"{key}={value}" :: output) rest
      | token :: rest ->
        loop (token :: output) rest
      | [] ->
        List.rev output
    loop [] tokens

  let private replaceTemplate name replacement (text: string) =
    if name = "_" then
      text
    else
      text.Replace("{" + name + "}", replacement)

  let private iterArguments (spec: ReplIterSpec) (index: int) (item: obj) =
    let unresolvedItem = "\u0000unrepresentable-iter-item\u0000"
    let itemText =
      ReplValue.tryArgumentText item |> Option.defaultValue unresolvedItem
    let indexText = index.ToString(CultureInfo.InvariantCulture)
    let apply token =
      token
      |> replaceTemplate (spec: ReplIterSpec).ItemName itemText
      |> replaceTemplate spec.IndexName indexText
      |> fun text -> text.Replace("{index}", indexText)
    let body = spec.Body |> List.map apply |> mergeSeparatedEquals
    if body |> List.exists (fun text -> text.Contains unresolvedItem) then
      let kind = ReplValue.kindOf item |> formatKind
      Error $"{spec.ItemName} of type {kind} cannot be an action argument."
    else
      Ok body

  let private singletonValue item =
    ReplValue.ofCollection ReplValueKind.Any { Values = [| item |] }

  let private iterOutputKind kinds =
    let rec elementKind = function
      | ReplValueKind.Collection kind
      | ReplValueKind.List kind
      | ReplValueKind.Array kind ->
        kind
      | kind ->
        kind
    kinds
    |> List.tryFind (fun kind -> kind <> ReplValueKind.Unit)
    |> Option.map (elementKind >> ReplValueKind.Collection)
    |> Option.defaultValue ReplValueKind.Unit

  let private printedResult values =
    let printed: PrintedValue = { Values = values }
    { Kind = ReplValueKind.Unit
      IsCollection = false
      Collection = { Values = [| box printed |] } }

  let private tryGetPrintedValue (value: ReplValue) =
    match value.Kind, value.Collection.Values with
    | ReplValueKind.Unit, [| :? PrintedValue as printed |] ->
      Some printed
    | _ ->
      None

  let private combinePrintedValues
    (outputKinds: ResizeArray<ReplValueKind>)
    (outputValues: obj[]) =
    let arePrintedValues =
      outputValues.Length > 0
      && (outputValues |> Array.forall (fun value -> value :? PrintedValue))
    if outputKinds.Count = 0 && arePrintedValues then
      outputValues
      |> Array.collect (fun value ->
        let printed = unbox<PrintedValue> value
        printed.Values |> List.toArray)
      |> Array.toList
      |> printedResult
      |> Some
    else
      None

  let private completeIter
    (output: ResizeArray<obj>)
    (outputKinds: ResizeArray<ReplValueKind>) =
    let outputValues = output.ToArray()
    match combinePrintedValues outputKinds outputValues with
    | Some value ->
      value
    | None ->
      let kind = outputKinds |> Seq.toList |> iterOutputKind
      let collection: ObjCollection = { Values = outputValues }
      ReplValue.ofCollection kind collection

  let rec private invoke
    registry
    state
    (registered: RegisteredAction)
    (input: ReplValue)
    (segment: ReplPipelineSegment)
    cancellationToken =
    let metadata = registered.Metadata
    if not (ReplTypeAnalysis.acceptsInput input.Kind metadata) then
      actionInputError input metadata |> Error
    else
      let args =
        segment.Arguments
        |> resolveArgumentBindings state
        |> List.map ReplLanguage.unquote
        |> compactBracketArguments
      let transformWith =
        transformWith registered input segment cancellationToken
      let isDirectSymbolic =
        metadata.ID = "run-symbolic"
        && (input.Kind = ReplValueKind.Binary
            || input.Kind = ReplValueKind.BinarySlice)
      let ready =
        if metadata.ID = "make-symbolic-executor" || isDirectSymbolic then
          let solverArgs =
            if args |> List.exists (parameterValue "solver" >> Option.isSome)
            then args
            else "solver=symb-z3" :: args
          registerSymbSolver registry solverArgs cancellationToken
        else
          Ok registry
      ready
      |> Result.bind (fun _ -> validateArguments input metadata args)
      |> Result.bind (fun validated ->
        if metadata.ID = "print" then
          printedResult [ input ] |> Ok
        else
          let outputKind =
            ActionMetadata.outputForSyntax
              metadata (Some input.Kind) validated.Syntax
          transformWith
            outputKind validated.Arguments validated.Assignments)

  and private appendIterValue
    (output: ResizeArray<obj>)
    (outputKinds: ResizeArray<ReplValueKind>)
    (value: ReplValue) =
    match tryGetPrintedValue value with
    | Some printed ->
      output.Add(box printed)
    | None when value.Kind <> ReplValueKind.Unit ->
      outputKinds.Add value.Kind
      output.AddRange value.Collection.Values
    | None ->
      ()

  and private invokeIterItem
    registry
    state
    registered
    spec
    segment
    cancellationToken
    output
    outputKinds
    index
    item =
    match iterArguments spec index item with
    | Error message ->
      Error $"{segment.Head} item {index}: {message}"
    | Ok arguments ->
      let itemSegment =
        { Head = ActionMetadata.actionName registered.Metadata.ID
          Arguments = arguments }
      invoke
        registry
        state
        registered
        (singletonValue item)
        itemSegment
        cancellationToken
      |> Result.map (fun value ->
        appendIterValue output outputKinds value)

  and private invokeIter
    registry
    state
    (input: ReplValue)
    (segment: ReplPipelineSegment)
    (cancellationToken: CancellationToken) =
    let output = ResizeArray<obj>()
    let outputKinds = ResizeArray<ReplValueKind>()
    if not input.IsCollection then
      Error $"{segment.Head} expects a collection input."
    else
      ReplLanguage.parseIter segment.Head segment.Arguments
      |> Result.bind (fun spec ->
        match tryFindAction registry spec.ActionID with
        | None ->
          Error $"Unknown iter action: {spec.ActionID}"
        | Some registered ->
          let values = input.Collection.Values
          let rec loop index =
            if index >= values.Length then
              completeIter output outputKinds |> Ok
            else
              cancellationToken.ThrowIfCancellationRequested()
              let item = values[index]
              invokeIterItem
                registry
                state
                registered
                spec
                segment
                cancellationToken
                output
                outputKinds
                index
                item
              |> Result.bind (fun () -> loop (index + 1))
          loop 0)

  let private runRemaining registry state initial segments cancellationToken =
    segments
    |> List.fold (fun result segment ->
      result
      |> Result.bind (fun input ->
        if isIterHead segment.Head then
          invokeIter registry state input segment cancellationToken
        else
          match tryFindAction registry segment.Head with
          | Some registered ->
            invoke registry state registered input segment cancellationToken
          | None ->
            Error $"Unknown action: {actionID segment.Head}")) (Ok initial)

  let rec private runPipeline registry state segments cancellationToken =
    match segments with
    | [] ->
      Error "An expression is required."
    | first :: rest ->
      let evalElement segments =
        runPipeline registry state segments cancellationToken
      match tryLiteral state evalElement first with
      | Error message ->
        Error message
      | Ok(Some value) ->
        runRemaining registry state value rest cancellationToken
      | Ok None ->
        let binding =
          if isActionReference first.Head
             || not (List.isEmpty first.Arguments) then
            None
          else
            TransformerReplState.tryFind first.Head state
        match binding with
        | Some value ->
          runRemaining registry state value rest cancellationToken
        | None ->
          if isIterHead first.Head then
            state.Current
            |> ofOption $"{first.Head} requires a current collection."
            |> Result.bind (fun value ->
              invokeIter registry state value first cancellationToken)
            |> Result.bind (fun value ->
              runRemaining registry state value rest cancellationToken)
          else
            match tryFindAction registry first.Head with
            | Some registered ->
              let input =
                if ActionMetadata.acceptedInputs registered.Metadata
                   |> List.contains ReplValueKind.Unit then
                  Ok ReplValue.emptyInput
                else
                  state.Current
                  |> ofOption
                    $"{registered.Metadata.ID} requires a current value."
              input
              |> Result.bind (fun value ->
                invoke registry state registered value first cancellationToken)
              |> Result.bind (fun value ->
                runRemaining registry state value rest cancellationToken)
            | None ->
              Error $"Unknown value or action: {first.Head}"

  let private validateOutput
    (expected: ReplValueKind option)
    (value: ReplValue) =
    match expected with
    | Some expected when not (ReplValueKind.isCompatible value.Kind expected) ->
      let actual = formatKind value.Kind
      let expected = formatKind expected
      Error $"Binding annotation expects {expected}, but received {actual}."
    | _ ->
      Ok value

  let private sourceActionLabel registry segment =
    let segment: ReplPipelineSegment = segment
    if isIterHead segment.Head then
      ReplLanguage.analyzeIter segment.Head segment.Arguments
      |> _.ActionID
      |> Option.map ActionMetadata.actionName
    elif segment.Head.StartsWith("@", StringComparison.Ordinal) then
      let id = segment.Head.TrimStart '@'
      let name = ActionMetadata.actionName id
      let trigger =
        ActionRegistry.tryFind id registry
        |> Option.bind (fun registered ->
          let triggers =
            registered.Metadata.Syntaxes
            |> List.choose _.Trigger
            |> List.distinct
          segment.Arguments
          |> List.tryHead
          |> Option.bind (fun argument ->
            triggers
            |> List.tryFind (fun trigger ->
              equalsIgnoreCase trigger argument)))
      trigger |> Option.map (fun trigger -> $"{name} {trigger}")
      |> Option.orElse (Some name)
    else
      None

  let private printInputAction registry segments =
    match List.rev segments with
    | _ :: input :: _ ->
      sourceActionLabel registry input
    | _ ->
      None

  let private observePrintedPipelineValue registry segments printed state =
    match printInputAction registry segments with
    | Some action ->
      printed.Values
      |> List.fold (fun state value ->
        TransformerReplState.observeValue
          state.NextLogID action value state) state
    | None ->
      state

  let private observePipelineValue registry segments value state =
    match tryGetPrintedValue value with
    | Some printed ->
      observePrintedPipelineValue registry segments printed state
    | None ->
      segments
      |> List.tryLast
      |> Option.bind (sourceActionLabel registry)
      |> Option.map (fun action ->
        TransformerReplState.observeValue
          state.NextLogID action value state)
      |> Option.defaultValue state

  let evaluate
    includeSuggestions
    registry
    state
    segments
    binding
    expected
    command
    cancellationToken =
    match runPipeline registry state segments cancellationToken with
    | Error message ->
      fail registry state message
    | Ok value ->
      match validateOutput expected value with
      | Error message ->
        fail registry state message
      | Ok value ->
        let command =
          let nondeterministic =
            segments
            |> List.exists (fun segment ->
              let id = segment.Head.TrimStart '@'
              equalsIgnoreCase id "random")
          match nondeterministic, value.Collection.Values with
          | true, [| :? BigInteger as number |] ->
            let literal = number.ToString(CultureInfo.InvariantCulture)
            binding
            |> Option.map (fun name -> $"{name} = {literal}")
            |> Option.defaultValue literal
          | _ ->
            command
        let state =
          TransformerReplState.setValue binding value state
          |> observePipelineValue registry segments value
          |> TransformerReplState.recordReplayCommand command
        match tryGetPrintedValue value with
        | Some printed ->
          continuePrintResult registry state printed
        | None ->
          let output =
            if includeSuggestions then
              describeValue binding value :: suggestions registry value.Kind
            else
              [ describeValue binding value ]
          continueWith registry state output
