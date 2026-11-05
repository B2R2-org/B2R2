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

/// Validation and normalization of REPL action arguments.
module internal ReplArguments =
  type private ParsedArguments =
    { Positional: string list
      Named: Map<string, string option * string> }

  type private NormalizedSyntax =
    { Syntax: ActionSyntax
      Arguments: string list
      Assignments: (ActionArgument * string) list option }

  type ValidatedActionArguments =
    { Syntax: ActionSyntax
      Arguments: string list
      Assignments: (string * string) list option }

  let private bindingText (state: TransformerReplState) name =
    TransformerReplState.tryFind name state
    |> Option.bind (fun value ->
      match value.Collection.Values with
      | [| value |] ->
        ReplValue.tryArgumentText value
      | _ ->
        None)

  let private resolveAssignmentValue state (token: string) =
    let index = token.IndexOf '='
    if index <= 0 then
      token
    else
      let lhs = token[..index - 1].Trim()
      let rhs = token[index + 1..].Trim()
      let rhs = bindingText state rhs |> Option.defaultValue rhs
      lhs + "=" + rhs

  let resolveArgumentBindings state args =
    args |> List.map (resolveAssignmentValue state)

  let private joinBracketValue opener rest =
    let rec loop depth output = function
      | [] ->
        None
      | token :: tail ->
        let depth = InputAnalysis.updateDepth depth token
        let output = token :: output
        if depth = 0 then
          Some(List.rev output, tail)
        else
          loop depth output tail
    loop 1 [ opener ] rest

  let compactBracketArguments args =
    let rec loop output = function
      | token :: ("(" | "[" as opener) :: rest
          when token.EndsWith("=", StringComparison.Ordinal) ->
        match joinBracketValue opener rest with
        | Some(value, tail) ->
          let value = value |> String.concat " "
          loop ((token + value) :: output) tail
        | None ->
          (List.rev output) @ (token :: opener :: rest)
      | token :: rest ->
        loop (token :: output) rest
      | [] ->
        List.rev output
    loop [] args

  let private parseArguments args =
    let folder result value =
      result
      |> Result.bind (fun parsed ->
        match ActionMetadata.tryParseNamedArgument value with
        | Some(key, _, _) when Map.containsKey key parsed.Named ->
          Error $"duplicate parameter: {key}."
        | Some(key, annotation, value) ->
          let named = Map.add key (annotation, value) parsed.Named
          Ok { parsed with Named = named }
        | None ->
          Ok { parsed with Positional = value :: parsed.Positional })
    let initial = Ok { Positional = []; Named = Map.empty }
    args
    |> List.fold folder initial
    |> Result.map (fun parsed ->
      { parsed with Positional = List.rev parsed.Positional })

  let equalsIgnoreCase left right =
    String.Equals(left, right, StringComparison.OrdinalIgnoreCase)

  let private positionalArgumentsAllowed
    (parsed: ParsedArguments) (syntax: ActionSyntax) =
    let positional = parsed.Positional
    let arguments = List.truncate (List.length positional) syntax.Arguments
    List.length arguments = List.length positional
    && arguments
       |> List.forall (fun argument ->
         argument.Kind = ActionArgumentKind.Action)

  let private tryTakeTrigger parsed (syntax: ActionSyntax) =
    match syntax.Trigger with
    | None ->
      Some parsed
    | Some expected ->
      match parsed.Positional with
      | actual :: rest when equalsIgnoreCase actual expected ->
        Some { parsed with Positional = rest }
      | _ ->
        None

  let private tryFindNamed named argument =
    ActionMetadata.argumentKeys argument
    |> List.tryPick (fun key ->
      Map.tryFind key named |> Option.map (fun value -> key, value))

  let private defaultArgumentValue = function
    | ActionArgumentDefault.Zero ->
      "0"
    | ActionArgumentDefault.EmptyList ->
      "[]"

  let rec private fillArguments positional named arguments output assignments =
    match arguments with
    | [] when List.isEmpty positional && Map.isEmpty named ->
      Ok(List.rev output, List.rev assignments)
    | [] when not (List.isEmpty positional) ->
      Error "too many positional arguments."
    | [] ->
      let keys = named |> Map.toList |> List.map fst |> String.concat ", "
      Error $"unknown parameter(s): {keys}."
    | argument :: rest ->
      match tryFindNamed named argument with
      | Some(key, (annotation, value)) ->
        match annotation with
        | Some annotation when
            not (ActionMetadata.annotationMatches argument annotation) ->
          let expected = ActionMetadata.argumentKindName argument.Kind
          Error $"{argument.Name} is {expected}, not {annotation}."
        | _ ->
          fillArguments
            positional
            (Map.remove key named)
            rest
            (value :: output)
            ((argument, value) :: assignments)
      | None ->
        match positional with
        | value :: tail ->
          fillArguments
            tail
            named
            rest
            (value :: output)
            ((argument, value) :: assignments)
        | [] when argument.IsOptional
                 && Option.isSome argument.DefaultValue ->
          let value =
            argument.DefaultValue |> Option.get |> defaultArgumentValue
          fillArguments [] named rest (value :: output) assignments
        | [] when argument.IsOptional ->
          fillArguments [] named rest output assignments
        | [] ->
          Error $"missing parameter: {argument.Name}."

  let private normalizeSyntax parsed syntax =
    let addTrigger args =
      match (syntax: ActionSyntax).Trigger with
      | Some trigger ->
        trigger :: args
      | None ->
        args
    tryTakeTrigger parsed syntax
    |> Option.map (fun parsed ->
      if not (List.isEmpty parsed.Positional)
         && not (positionalArgumentsAllowed parsed syntax) then
        Error "positional arguments are not supported; use name=value."
      elif Map.isEmpty parsed.Named then
        Ok
          ({ Syntax = syntax
             Arguments = addTrigger parsed.Positional
             Assignments = None }: NormalizedSyntax)
      else
        fillArguments parsed.Positional parsed.Named syntax.Arguments [] []
        |> Result.map (fun (args, assignments) ->
           ({ Syntax = syntax
              Arguments = addTrigger args
              Assignments = Some assignments }: NormalizedSyntax)))

  let private matchesArity (candidate: NormalizedSyntax) =
    let args =
      match candidate.Syntax.Trigger, candidate.Arguments with
      | Some _, _ :: rest ->
        rest
      | _ ->
        candidate.Arguments
    let required =
      candidate.Syntax.Arguments
      |> List.filter (fun argument -> not argument.IsOptional)
      |> List.length
    let maximum = List.length candidate.Syntax.Arguments
    List.length args >= required && List.length args <= maximum

  let private validateSyntax input (candidate: NormalizedSyntax) =
    let pairs =
      match candidate.Assignments with
      | Some assignments ->
        assignments
      | None ->
        let args =
          match candidate.Syntax.Trigger, candidate.Arguments with
          | Some _, _ :: rest ->
            rest
          | _ ->
            candidate.Arguments
        List.zip
          (List.truncate (List.length args) candidate.Syntax.Arguments)
          args
    pairs
    |> List.map (fun (argument, value) ->
      ActionArgumentValidation.validate input argument value)
    |> List.tryFind Result.isError
    |> Option.defaultValue (Ok())

  let private canonicalArguments (candidate: NormalizedSyntax) =
    let rec loop output arguments values =
      match arguments, values with
      | argument :: arguments, value :: values ->
        let value = ActionArgumentValidation.canonicalize argument value
        loop (value :: output) arguments values
      | _, [] ->
        List.rev output
      | [], values ->
        List.rev output @ values
    match candidate.Syntax.Trigger, candidate.Arguments with
    | Some trigger, actual :: values when equalsIgnoreCase trigger actual ->
      trigger :: loop [] candidate.Syntax.Arguments values
    | _ ->
      loop [] candidate.Syntax.Arguments candidate.Arguments

  let private canonicalAssignments (candidate: NormalizedSyntax) =
    candidate.Assignments
    |> Option.map (fun assignments ->
      assignments
      |> List.map (fun (argument, value) ->
        argument.Name,
        ActionArgumentValidation.canonicalize argument value))

  let private invalidArguments
    (input: ReplValue)
    (metadata: ActionMetadata)
    args
    detail =
    let signature =
      ActionMetadata.typedSignatureFor metadata (Some input.Kind) args
    Error(
      $"Invalid arguments for {metadata.ID}: {detail} "
      + $"Expected: {signature}")

  let validateArguments
    (input: ReplValue)
    (metadata: ActionMetadata)
    args =
    match parseArguments args with
    | Error message ->
      invalidArguments input metadata args message
    | Ok parsed ->
      let matching =
        ActionMetadata.matchingSyntaxes metadata (Some input.Kind) args
        |> List.choose (normalizeSyntax parsed)
      if List.isEmpty matching then
        let operations =
          metadata.Syntaxes
          |> List.choose (fun syntax -> syntax.Trigger)
          |> List.distinct
        let detail =
          match operations with
          | [] ->
            "the argument layout is invalid."
          | operations ->
            let choices = String.concat "|" operations
            $"operation must be one of {choices}."
        invalidArguments input metadata args detail
      else
        let matching =
          matching
          |> List.choose (function
            | Ok candidate when matchesArity candidate ->
              Some(Ok candidate)
            | Ok _ ->
              None
            | Error error ->
              Some(Error error))
        if List.isEmpty matching then
          invalidArguments
            input metadata args "the number of arguments does not match."
        else
          let results =
            matching
            |> List.map (function
              | Ok candidate ->
                validateSyntax input candidate |> Result.map (fun () ->
                  { Syntax = candidate.Syntax
                    Arguments = canonicalArguments candidate
                    Assignments = canonicalAssignments candidate })
              | Error error ->
                Error error)
          match results |> List.tryFind Result.isOk with
          | Some(Ok normalizedArgs) ->
            Ok normalizedArgs
          | _ ->
            results
            |> List.choose (function Error error -> Some error | Ok _ -> None)
            |> List.distinct
            |> List.tryHead
            |> Option.defaultValue "the argument layout is invalid."
            |> invalidArguments input metadata args

  let parameterValue name (token: string) =
    let index = token.IndexOf '='
    if index <= 0 then
      None
    else
      let key = token[..index - 1].Trim()
      let key =
        let index = key.IndexOf ':'
        if index <= 0 then key else key[..index - 1]
      if equalsIgnoreCase key name then
        Some(token[index + 1..].Trim())
      else
        None

  let normalizeNeedsArguments state args =
    let args = args |> resolveArgumentBindings state |> compactBracketArguments
    match parseArguments args with
    | Error message ->
      Error message
    | Ok parsed when not (List.isEmpty parsed.Positional) ->
      Error ":needs only accepts named parameters after the executor name."
    | Ok parsed ->
      let allowed = set [ "start"; "count"; "end" ]
      let unknown =
        parsed.Named
        |> Map.toList
        |> List.map fst
        |> List.filter (fun name -> not (Set.contains name allowed))
      match unknown with
      | name :: _ ->
        Error $"Unknown :needs parameter: {name}"
      | [] ->
        let find name = Map.tryFind name parsed.Named |> Option.map snd
        match find "start", find "count", find "end" with
        | None, None, None ->
          Ok []
        | None, Some count, None ->
          Ok [ count ]
        | Some start, Some count, None ->
          Ok [ start; count ]
        | Some start, None, Some finish ->
          Ok [ start; finish ]
        | Some start, None, None ->
          Ok [ start; "1" ]
        | None, _, Some _ ->
          Error ":needs end= requires start=."
        | Some _, Some _, Some _ ->
          Error ":needs accepts either count= or end=, not both."


