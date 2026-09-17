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

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

namespace B2R2.RearEnd.Transformer

open System
open System.Text

/// One action or value reference in a pipeline expression.
type ReplPipelineSegment =
  { Head: string
    Arguments: string list }

/// A parsed Transformer REPL command.
type TransformerReplCommand =
  | Evaluate of ReplPipelineSegment list * binding: string option
                * expected: ReplValueKind option
  | Show of binding: string option
  | ShowExpression of ReplPipelineSegment list
  | TypeOf of binding: string option
  | Inspect of binding: string option
  | Actions
  | History
  | Values
  | Restore of id: int * binding: string option
  | Undo
  | Log
  | ExportValue of binding: string * path: string
  | SaveScript of path: string
  | LoadScript of path: string
  | ScriptRecord of enabled: bool option
  | ScriptComment of text: string
  | Layout of options: string list
  | Help
  | Reset
  | Quit
  | NoInput

/// Parsed `let` header shared by strict parsing and partial suggestions.
type ReplBindingHeader =
  { Name: string option
    TypeAnnotation: string option
    TypePrefix: string option
    TypePrefixStart: int option
    HasEquals: bool
    Expression: string option
    ExpressionStart: int option }

module ReplLanguage =
  [<RequireQualifiedAccess>]
  type TokenizeMode =
    | Strict
    | Partial

  let private finishToken (builder: StringBuilder) tokens =
    if builder.Length = 0 then
      tokens
    else
      let token = builder.ToString()
      builder.Clear() |> ignore
      token :: tokens

  let tokenizeWith mode (text: string) =
    let builder = StringBuilder()
    let punctuation = set [ '('; ')'; '['; ']'; ','; ';' ]
    let rec loop index quote tokens =
      if index = text.Length then
        match quote, mode with
        | Some _, TokenizeMode.Strict ->
          Error "Unterminated quoted string."
        | _ ->
          finishToken builder tokens |> List.rev |> Ok
      else
        let chr = text[index]
        match quote with
        | Some delimiter when chr = delimiter ->
          loop (index + 1) None tokens
        | Some _ ->
          builder.Append chr |> ignore
          loop (index + 1) quote tokens
        | None when chr = '\'' || chr = '"' ->
          loop (index + 1) (Some chr) tokens
        | None when Char.IsWhiteSpace chr ->
          let tokens = finishToken builder tokens
          loop (index + 1) None tokens
        | None when chr = '|' && index + 1 < text.Length
          && text[index + 1] = '>' ->
          let tokens = finishToken builder tokens
          loop (index + 2) None ("|>" :: tokens)
        | None when chr = '|' && index + 1 < text.Length
          && text[index + 1] = ']' ->
          let tokens = finishToken builder tokens
          loop (index + 2) None ("|]" :: tokens)
        | None when chr = '|' && mode = TokenizeMode.Strict ->
          Error "Use |> as the pipeline operator."
        | None when chr = '[' && index + 1 < text.Length
          && text[index + 1] = '|' ->
          let tokens = finishToken builder tokens
          loop (index + 2) None ("[|" :: tokens)
        | None when Set.contains chr punctuation ->
          let tokens = finishToken builder tokens
          loop (index + 1) None (string chr :: tokens)
        | None when chr = '=' && builder.Length = 0 ->
          let tokens = finishToken builder tokens
          loop (index + 1) None (string chr :: tokens)
        | None ->
          builder.Append chr |> ignore
          loop (index + 1) quote tokens
    loop 0 None []

  let tokenize text =
    tokenizeWith TokenizeMode.Partial text |> Result.defaultValue []

  let tokenizeStrict text = tokenizeWith TokenizeMode.Strict text

  let splitWords text = tokenize text

  let updateDepth depth = function
    | "(" | "[" | "[|" -> depth + 1
    | ")" | "]" | "|]" -> max 0 (depth - 1)
    | _ -> depth

  let splitPipelineElements tokens =
    let rec loop depth segments current = function
      | [] ->
        List.rev (List.rev current :: segments)
      | "|>" :: rest when depth = 0 ->
        loop depth (List.rev current :: segments) [] rest
      | token :: rest ->
        loop (updateDepth depth token) segments (token :: current) rest
    loop 0 [] [] tokens

  let splitPipelineText text =
    tokenize text |> splitPipelineElements

  let splitPipeline text =
    splitPipelineText text |> List.map (String.concat " ")

  let private scanTopLevelSeparator (separator: char) (text: string) =
    let addSegment start finish segments =
      let segment =
        if finish < start then "" else text[start..finish].Trim()
      if String.IsNullOrWhiteSpace segment then segments
      else segment :: segments
    let rec loop index quote depth start segments =
      if index >= String.length text then
        addSegment start (String.length text - 1) segments |> List.rev
      else
        let chr = text[index]
        match quote with
        | Some delimiter when chr = delimiter ->
          loop (index + 1) None depth start segments
        | Some _ ->
          loop (index + 1) quote depth start segments
        | None when chr = '\'' || chr = '"' ->
          loop (index + 1) (Some chr) depth start segments
        | None when chr = '[' && index + 1 < text.Length
          && text[index + 1] = '|' ->
          loop (index + 2) None (depth + 1) start segments
        | None when chr = '(' || chr = '[' ->
          loop (index + 1) None (depth + 1) start segments
        | None when chr = ')' || chr = ']' ->
          loop (index + 1) None (max 0 (depth - 1)) start segments
        | None when chr = separator && depth = 0 ->
          let segments = addSegment start (index - 1) segments
          loop (index + 1) None depth (index + 1) segments
        | None ->
          loop (index + 1) None depth start segments
    if String.IsNullOrWhiteSpace text then [] else loop 0 None 0 0 []

  let splitTopLevelCommands text = scanTopLevelSeparator ';' text

  let isIncomplete (text: string) =
    let rec loop index quote depth =
      if index >= String.length text then
        Option.isSome quote || depth > 0
      else
        let chr = text[index]
        match quote with
        | Some delimiter when chr = delimiter ->
          loop (index + 1) None depth
        | Some _ ->
          loop (index + 1) quote depth
        | None when chr = '\'' || chr = '"' ->
          loop (index + 1) (Some chr) depth
        | None when chr = '[' && index + 1 < text.Length
          && text[index + 1] = '|' ->
          loop (index + 2) None (depth + 1)
        | None when chr = '(' || chr = '[' ->
          loop (index + 1) None (depth + 1)
        | None when chr = ')' || chr = ']' ->
          loop (index + 1) None (max 0 (depth - 1))
        | None ->
          loop (index + 1) None depth
    let trimmed = text.TrimEnd()
    loop 0 None 0 || trimmed.EndsWith("->", StringComparison.Ordinal)

  let combineCommandLines lines =
    let rec collect commands current = function
      | [] ->
        match current with
        | [] -> Ok(List.rev commands)
        | _ ->
          let command = current |> List.rev |> String.concat "\n"
          if isIncomplete command then
            Error $"Incomplete script command: {command}"
          else
            Ok(List.rev (command :: commands))
      | (line: string) :: rest ->
        let line = line.TrimEnd()
        let trimmed = line.TrimStart()
        if String.IsNullOrWhiteSpace line || trimmed.StartsWith '#' then
          collect commands current rest
        else
          let current = line :: current
          let command = current |> List.rev |> String.concat "\n"
          if isIncomplete command then collect commands current rest
          else collect (command :: commands) [] rest
    collect [] [] lines

  let private isIdentifierStart chr =
    Char.IsLetter chr || chr = '_'

  let private isIdentifierPart chr =
    Char.IsLetterOrDigit chr || chr = '_'

  let isValidName (name: string) =
    if String.IsNullOrWhiteSpace name then
      false
    else
      isIdentifierStart name[0]
      && name
         |> Seq.skip 1
         |> Seq.forall isIdentifierPart

  let private skipSpaces (input: string) index =
    let rec loop index =
      if index < input.Length && Char.IsWhiteSpace input[index] then
        loop (index + 1)
      else
        index
    loop index

  let private parseIdentifier (input: string) index =
    if index >= input.Length || not (isIdentifierStart input[index]) then
      None
    else
      let rec loop index =
        if index < input.Length && isIdentifierPart input[index] then
          loop (index + 1)
        else
          index
      let finish = loop (index + 1)
      Some(input[index..finish - 1], finish)

  let private startsWithLet (input: string) =
    let start = skipSpaces input 0
    if start + 3 > input.Length then
      None
    elif input[start..start + 2] <> "let" then
      None
    elif start + 3 < input.Length && isIdentifierPart input[start + 3] then
      None
    else
      Some(start + 3)

  let private trimType (input: string) start finish =
    let mutable first = start
    let mutable last = finish
    while first < last && Char.IsWhiteSpace input[first] do
      first <- first + 1
    while last > first && Char.IsWhiteSpace input[last - 1] do
      last <- last - 1
    if first >= last then "", first else input[first..last - 1], first

  let private parseTypeAnnotation (input: string) index =
    let start = skipSpaces input (index + 1)
    let rec loop index =
      if index >= input.Length then
        index
      else
        match input[index] with
        | ')' | '=' -> index
        | _ -> loop (index + 1)
    let finish = loop start
    let typ, typStart = trimType input start finish
    typ, typStart, finish

  let bindingHeader (input: string) =
    startsWithLet input
    |> Option.map (fun index ->
      let index = skipSpaces input index
      let hasOpenParen = index < input.Length && input[index] = '('
      let index = if hasOpenParen then skipSpaces input (index + 1) else index
      let name, index =
        match parseIdentifier input index with
        | Some(name, index) -> Some name, index
        | None -> None, index
      let index = skipSpaces input index
      let typ, typStart, index =
        if index < input.Length && input[index] = ':' then
          let typ, typStart, index = parseTypeAnnotation input index
          Some typ, Some typStart, index
        else
          None, None, index
      let index = skipSpaces input index
      let index =
        if hasOpenParen && index < input.Length && input[index] = ')' then
          skipSpaces input (index + 1)
        else
          index
      let hasEquals = index < input.Length && input[index] = '='
      let expressionStart = if hasEquals then Some(index + 1) else None
      { Name = name
        TypeAnnotation = typ
        TypePrefix = if hasEquals then None else typ
        TypePrefixStart = if hasEquals then None else typStart
        HasEquals = hasEquals
        Expression = expressionStart |> Option.map (fun index -> input[index..])
        ExpressionStart = expressionStart })

  let bindingExpected input =
    bindingHeader input
    |> Option.bind (fun header ->
      if header.HasEquals then header.TypeAnnotation else None)
    |> Option.bind ReplValueKind.tryParse

  let expressionPortion input =
    match bindingHeader input with
    | Some header when header.HasEquals ->
      header.Expression |> Option.defaultValue ""
    | _ -> input

  let splitTopLevel separator tokens =
    let rec loop depth current elements = function
      | [] when List.isEmpty current -> List.rev elements
      | [] -> List.rev (List.rev current :: elements)
      | token :: rest when token = separator && depth = 0 ->
        loop depth [] (List.rev current :: elements) rest
      | token :: rest ->
        loop (updateDepth depth token) (token :: current) elements rest
    loop 0 [] [] tokens

  let splitTopLevelStrict separator tokens =
    let rec loop depth current elements = function
      | [] when List.isEmpty current ->
        Ok(List.rev elements)
      | [] ->
        Ok(List.rev (List.rev current :: elements))
      | token :: _ when token = separator && depth = 0
        && List.isEmpty current ->
        Error "Empty literal element."
      | token :: rest when token = separator && depth = 0 ->
        loop depth [] (List.rev current :: elements) rest
      | token :: rest ->
        loop (updateDepth depth token) (token :: current) elements rest
    loop 0 [] [] tokens

  let splitPipelineTokens tokens =
    let rec loop depth segments current = function
      | [] when List.isEmpty current ->
        Error "Empty pipeline segment."
      | [] ->
        Ok(List.rev (List.rev current :: segments))
      | token :: _ when token = "|>" && depth = 0 && List.isEmpty current ->
        Error "Empty pipeline segment."
      | token :: rest when token = "|>" && depth = 0 ->
        loop depth (List.rev current :: segments) [] rest
      | token :: rest ->
        loop (updateDepth depth token) segments (token :: current) rest
    loop 0 [] [] tokens

  let private toSegment = function
    | head :: arguments -> Ok { Head = head; Arguments = arguments }
    | [] -> Error "Empty pipeline segment."

  let parsePipelineTokens tokens =
    splitPipelineTokens tokens
    |> Result.bind (List.map toSegment >> List.fold (fun state item ->
      Result.bind (fun values ->
        Result.map (fun value -> value :: values) item) state
    ) (Ok []))
    |> Result.map List.rev

  let private parseKind token =
    match ReplValueKind.tryParse token with
    | Some kind -> Ok kind
    | None -> Error $"Unknown type annotation: {token}"

  let private rejectPostfixBinding tokens =
    match List.rev tokens with
    | name :: "as" :: _ when isValidName name ->
      Error "Postfix binding is not supported. Use let <name> = <expression>."
    | _ ->
      Ok tokens

  let private parseSegments tokens =
    rejectPostfixBinding tokens
    |> Result.bind parsePipelineTokens

  let topLevelLastPipeline (input: string) =
    let rec loop index quote depth last =
      if index >= input.Length then
        last
      else
        let chr = input[index]
        match quote with
        | Some delimiter when chr = delimiter ->
          loop (index + 1) None depth last
        | Some _ ->
          loop (index + 1) quote depth last
        | None when chr = '\'' || chr = '"' ->
          loop (index + 1) (Some chr) depth last
        | None when chr = '(' || chr = '[' ->
          if chr = '[' && index + 1 < input.Length
             && input[index + 1] = '|' then
            loop (index + 2) None (depth + 1) last
          else
            loop (index + 1) None (depth + 1) last
        | None when chr = ')' || chr = ']' ->
          loop (index + 1) None (max 0 (depth - 1)) last
        | None when chr = '|' && index + 1 < input.Length
          && input[index + 1] = '>' && depth = 0 ->
          loop (index + 2) None depth (Some index)
        | None ->
          loop (index + 1) None depth last
    loop 0 None 0 None

  let activeExpression (input: string) =
    let updateTop separator = function
      | (openIndex, _) :: rest -> (openIndex, Some separator) :: rest
      | [] -> []
    let rec loop index quote stack =
      if index >= input.Length then
        stack
      else
        let chr = input[index]
        match quote with
        | Some delimiter when chr = delimiter ->
          loop (index + 1) None stack
        | Some _ ->
          loop (index + 1) quote stack
        | None when chr = '\'' || chr = '"' ->
          loop (index + 1) (Some chr) stack
        | None when chr = '[' && index + 1 < input.Length
          && input[index + 1] = '|' ->
          loop (index + 2) None ((index, None) :: stack)
        | None when chr = '(' || chr = '[' ->
          loop (index + 1) None ((index, None) :: stack)
        | None when chr = ')' || chr = ']' ->
          let stack =
            match stack with
            | _ :: rest -> rest
            | [] -> []
          loop (index + 1) None stack
        | None when (chr = ',' || chr = ';') && not (List.isEmpty stack) ->
          loop (index + 1) None (updateTop index stack)
        | None ->
          loop (index + 1) None stack
    match loop 0 None [] with
    | (openIndex, separator) :: _ ->
      let start =
        separator |> Option.map ((+) 1) |> Option.defaultValue
          (openIndex + 1)
      input[start..]
    | [] ->
      input

  let parseEvaluation input tokens =
    match bindingHeader input with
    | Some header ->
      match header.Name, header.HasEquals, header.Expression with
      | Some name, true, Some expression when isValidName name ->
        let expected =
          match header.TypeAnnotation with
          | Some "" | None -> Ok None
          | Some typ -> parseKind typ |> Result.map Some
        expected
        |> Result.bind (fun expected ->
          tokenizeStrict expression
          |> Result.bind (fun tokens ->
            if List.isEmpty tokens then Error "An expression is required."
            else
              parseSegments tokens
              |> Result.map (fun segments ->
                Evaluate(segments, Some name, expected))))
      | Some name, _, _ when not (isValidName name) ->
        Error $"Invalid binding name: {name}"
      | None, _, _ ->
        Error "A binding name is required after let."
      | _, false, _ ->
        Error "Expected '=' after binding."
      | _, _, None ->
        Error "An expression is required."
      | Some name, _, _ ->
        Error $"Invalid binding name: {name}"
    | None ->
      match tokens with
      | name :: "=" :: _ when isValidName name ->
        Error "Assignment without let is not supported. Use let <name> = ..."
      | _ ->
        parseSegments tokens
        |> Result.map (fun segments -> Evaluate(segments, None, None))
