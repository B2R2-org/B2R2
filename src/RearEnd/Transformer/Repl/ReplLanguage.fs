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

/// One segment recovered from an incomplete pipeline expression.
type ReplPartialSegment =
  { Start: int
    End: int
    Nodes: ReplPartialSyntax list
    Tokens: string list }

/// A node recovered while parsing an incomplete pipeline expression.
and ReplPartialSyntax =
  | PartialToken of text: string * start: int * finish: int
  | PartialDelimited of opening: string * closing: string option * start: int
                        * finish: int * children: ReplPartialSyntax list

/// The innermost incomplete literal at the current input position.
type ReplPartialScope =
  { Start: int
    End: int
    Tokens: string list }

/// A tolerant syntax tree used while completing a pipeline expression.
type ReplPartialPipeline =
  { Segments: ReplPartialSegment list
    LastPipelineStart: int option
    HasTrailingPipeline: bool }

/// A parsed Transformer REPL command.
type TransformerReplCommand =
  | Evaluate of ReplPipelineSegment list * binding: string option
                * expected: ReplValueKind option
  | Show of binding: string option
  | ShowExpression of ReplPipelineSegment list
  | TypeOf of binding: string option
  | TypeOfExpression of ReplPipelineSegment list
  | Inspect of binding: string option
  | Needs of binding: string * arguments: string list
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
  | PluginLoad of path: string
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
    ExpressionStart: int option
    SyntaxError: string option }

/// Partial syntax facts for an `iter` or `iteri` expression.
type ReplIterAnalysis =
  { ActionID: string option
    LambdaParameters: string list option
    ExpectedParameterCount: int
    HasOpeningDelimiter: bool
    HasArrow: bool
    HasClosingDelimiter: bool
    Body: string list }

/// A complete, validated `iter` or `iteri` expression.
type ReplIterSpec =
  { ActionID: string
    ItemName: string
    IndexName: string
    Body: string list }

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

  let isTokenPunctuation = function
    | '(' | ')' | '[' | ']' | ',' | ';' -> true
    | _ -> false

  let tokenizeWith mode (text: string) =
    let builder = StringBuilder()
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
          builder.Append chr |> ignore
          loop (index + 1) None tokens
        | Some _ ->
          builder.Append chr |> ignore
          loop (index + 1) quote tokens
        | None when chr = '\'' || chr = '"' ->
          builder.Append chr |> ignore
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
        | None when isTokenPunctuation chr ->
          let tokens = finishToken builder tokens
          loop (index + 1) None (string chr :: tokens)
        | None when chr = '=' && builder.Length = 0 ->
          let tokens = finishToken builder tokens
          loop (index + 1) None (string chr :: tokens)
        | None ->
          builder.Append chr |> ignore
          loop (index + 1) quote tokens
    loop 0 None []

  let private matchingClose = function
    | "(" -> Some ")"
    | "[" -> Some "]"
    | "[|" -> Some "|]"
    | _ -> None

  let private isClosing = function
    | ")" | "]" | "|]" -> true
    | _ -> false

  let private validateDelimiters tokens =
    let rec loop stack = function
      | [] ->
        match stack with
        | [] -> Ok tokens
        | opener :: _ ->
          let closer = matchingClose opener |> Option.defaultValue "?"
          Error $"Unclosed '{opener}'; expected '{closer}'."
      | token :: rest ->
        match matchingClose token, isClosing token, stack with
        | Some _, _, _ ->
          loop (token :: stack) rest
        | None, true, [] ->
          Error $"Unexpected '{token}' with no matching opener."
        | None, true, opener :: tail ->
          let expected = matchingClose opener |> Option.defaultValue "?"
          if token = expected then loop tail rest
          else
            let message =
              $"Mismatched delimiter: expected '{expected}' before '{token}'."
            Error message
        | None, false, _ ->
          loop stack rest
    loop [] tokens

  let tokenize text =
    tokenizeWith TokenizeMode.Partial text |> Result.defaultValue []

  let tokenizeStrict text =
    tokenizeWith TokenizeMode.Strict text |> Result.bind validateDelimiters

  let tryQuotedString (text: string) =
    if text.Length >= 2
       && (text[0] = '\'' || text[0] = '"')
       && text[text.Length - 1] = text[0] then
      Some(text[1..text.Length - 2])
    else
      None

  let unquote (text: string) =
    let builder = StringBuilder()
    let rec loop index quote =
      if index = text.Length then
        builder.ToString()
      else
        let chr = text[index]
        match quote with
        | Some delimiter when chr = delimiter ->
          loop (index + 1) None
        | Some _ ->
          builder.Append chr |> ignore
          loop (index + 1) quote
        | None when chr = '\'' || chr = '"' ->
          loop (index + 1) (Some chr)
        | None ->
          builder.Append chr |> ignore
          loop (index + 1) None
    loop 0 None

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

  let private hasUnterminatedQuote (text: string) =
    let rec loop index quote =
      if index >= text.Length then
        Option.isSome quote
      else
        let chr = text[index]
        match quote with
        | Some delimiter when chr = delimiter ->
          loop (index + 1) None
        | Some _ ->
          loop (index + 1) quote
        | None when chr = '\'' || chr = '"' ->
          loop (index + 1) (Some chr)
        | None ->
          loop (index + 1) None
    loop 0 None

  let tryTakeInteractivePhrase (text: string) =
    let trimmed = text.TrimEnd()
    if not (trimmed.EndsWith(";;", StringComparison.Ordinal)) then
      None
    elif hasUnterminatedQuote trimmed then
      None
    else
      let finish = trimmed.Length - 3
      let phrase = if finish < 0 then "" else trimmed[..finish].TrimEnd()
      Some phrase

  let private needsNextLine (text: string) =
    let trimmed = text.TrimEnd()
    trimmed.EndsWith("=", StringComparison.Ordinal)
    || trimmed.EndsWith("|>", StringComparison.Ordinal)
    || trimmed.EndsWith("->", StringComparison.Ordinal)

  let private isContinuationLine (line: string) =
    let trimmed = line.TrimStart()
    line.Length <> trimmed.Length
    || trimmed.StartsWith("|>", StringComparison.Ordinal)

  let private continuationDetail (command: string) =
    let trimmed = command.TrimEnd()
    if trimmed.EndsWith("->", StringComparison.Ordinal) then
      "lambda body is missing after '->'."
    elif trimmed.EndsWith("|>", StringComparison.Ordinal) then
      "pipeline operator '|>' must be followed by an expression."
    elif trimmed.EndsWith("=", StringComparison.Ordinal) then
      "an expression is missing after '='."
    else
      match tokenizeStrict command with
      | Error message -> message
      | Ok _ -> command

  let combineCommandLines lines =
    let commandText current =
      current |> List.rev |> String.concat "\n"
    let pendingNeedsNext current =
      let command = commandText current
      isIncomplete command || needsNextLine command
    let rec collect commands current = function
      | [] ->
        match current with
        | [] -> Ok(List.rev commands)
        | _ ->
          let command = commandText current
          if isIncomplete command || needsNextLine command then
            let detail = continuationDetail command
            Error $"Incomplete script command: {detail}"
          else
            Ok(List.rev (command :: commands))
      | (line: string) :: rest ->
        let line = line.TrimEnd()
        let trimmed = line.TrimStart()
        if String.IsNullOrWhiteSpace line || trimmed.StartsWith '#' then
          collect commands current rest
        else
          match current with
          | [] -> collect commands [ line ] rest
          | _ when pendingNeedsNext current || isContinuationLine line ->
            collect commands (line :: current) rest
          | _ ->
            let command = commandText current
            collect (command :: commands) [ line ] rest
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

  let private parameterValue name (token: string) =
    let index = token.IndexOf '='
    if index <= 0 then
      None
    else
      let key = token[..index - 1].Trim()
      let annotation = key.IndexOf ':'
      let key = if annotation <= 0 then key else key[..annotation - 1]
      if String.Equals(key, name, StringComparison.OrdinalIgnoreCase) then
        Some(token[index + 1..])
      else
        None

  let private actionID (value: string) =
    if value.StartsWith("@", StringComparison.Ordinal) then value[1..]
    else value

  let private takeNamedParameter name tokens =
    let rec loop before = function
      | [] -> None
      | token :: rest ->
        match parameterValue name token with
        | Some value ->
          let values =
            if String.IsNullOrEmpty value then rest else value :: rest
          Some(List.rev before, values)
        | None ->
          loop (token :: before) rest
    loop [] tokens

  let private iterParts args =
    match takeNamedParameter "params" args with
    | Some(action, lambda) -> action, lambda
    | None ->
      match args with
      | action :: lambda -> [ action ], lambda
      | [] -> [], []

  let private stripLambdaDelimiters tokens =
    let rec findClose depth body = function
      | [] -> None
      | token :: rest ->
        let depth = updateDepth depth token
        if depth = 0 then Some(List.rev body, rest)
        else findClose depth (token :: body) rest
    match tokens with
    | "(" :: rest ->
      match findClose 1 [] rest with
      | Some(body, []) -> body, true, true
      | _ -> tokens, true, false
    | _ -> tokens, false, false

  let private tryActionID tokens =
    let named =
      tokens
      |> List.choose (parameterValue "action")
    let positional =
      tokens |> List.filter (fun token -> not (token.Contains '='))
    match named, positional with
    | [ value ], [] when not (String.IsNullOrWhiteSpace value) ->
      Some(actionID value)
    | [], [ value ] -> Some(actionID value)
    | _ -> None

  let private mergeSeparatedEquals tokens =
    let rec loop output = function
      | key :: "=" :: value :: rest ->
        loop ($"{key}={value}" :: output) rest
      | token :: rest ->
        loop (token :: output) rest
      | [] ->
        List.rev output
    loop [] tokens

  let private normalizeIterBody tokens =
    let tokens =
      match tokens with
      | "{" :: rest ->
        match List.rev rest with
        | "}" :: body -> List.rev body
        | _ -> tokens
      | _ -> tokens
    mergeSeparatedEquals tokens

  let private expectedIterParameterCount keyword =
    if String.Equals(keyword, "iteri", StringComparison.OrdinalIgnoreCase) then
      2
    else
      1

  let analyzeIter keyword args =
    let action, lambda = iterParts args
    let lambda, hasOpen, hasClose = stripLambdaDelimiters lambda
    let afterFun =
      match lambda |> List.tryFindIndex ((=) "fun") with
      | Some index -> Some(List.skip (index + 1) lambda)
      | None -> None
    let parameters, hasArrow, body =
      match afterFun with
      | Some tokens ->
        match tokens |> List.tryFindIndex ((=) "->") with
        | Some index ->
          Some(List.take index tokens), true,
          List.skip (index + 1) tokens |> normalizeIterBody
        | None ->
          let parameters = tokens |> List.takeWhile ((<>) ")")
          Some parameters, false, []
      | None -> None, false, []
    { ActionID = tryActionID action
      LambdaParameters = parameters
      ExpectedParameterCount = expectedIterParameterCount keyword
      HasOpeningDelimiter = hasOpen
      HasArrow = hasArrow
      HasClosingDelimiter = hasClose
      Body = body }

  let private parseIterAction keyword tokens =
    let named = tokens |> List.choose (parameterValue "action")
    let positional =
      tokens |> List.filter (fun token -> not (token.Contains '='))
    match named, positional with
    | [ action ], [] when not (String.IsNullOrWhiteSpace action) ->
      Ok(actionID action)
    | [], [ action ] -> Ok(actionID action)
    | [], [] -> Error $"{keyword} requires an action."
    | _ :: _ :: _, _ -> Error "duplicate parameter: action."
    | _ :: _, _ ->
      Error $"{keyword} action must not be mixed with positional arguments."
    | [], _ ->
      Error $"{keyword} expects exactly one action before the function."

  let private validLambdaParameter name =
    name = "_" || isValidName name

  let private emptyIterSpec action =
    { ItemName = "_"; IndexName = "_"; Body = []; ActionID = action }

  let private parseIterLambda (keyword: string) action tokens =
    let tokens, _, _ = stripLambdaDelimiters tokens
    match keyword.ToLowerInvariant(), tokens with
    | "iter", [] -> Ok(emptyIterSpec action)
    | "iter", "fun" :: item :: "->" :: body
      when validLambdaParameter item ->
      Ok
        { ItemName = item
          IndexName = "_"
          Body = normalizeIterBody body
          ActionID = action }
    | "iter", "fun" :: item :: index :: "->" :: body
      when validLambdaParameter item && validLambdaParameter index ->
      Ok
        { ItemName = item
          IndexName = index
          Body = normalizeIterBody body
          ActionID = action }
    | "iter", "fun" :: _ ->
      Error "iter function must be: fun item -> <action-parameters>."
    | "iter", _ ->
      Error "iter expects an action or function: iter @action (fun item -> ...)"
    | "iteri", [] ->
      Error "iteri requires a function: fun index item -> ..."
    | "iteri", "fun" :: index :: item :: "->" :: body
      when validLambdaParameter index && validLambdaParameter item ->
      Ok
        { ItemName = item
          IndexName = index
          Body = normalizeIterBody body
          ActionID = action }
    | "iteri", "fun" :: _ ->
      Error "iteri function must be: fun index item -> <action-parameters>."
    | "iteri", _ ->
      Error "iteri requires a function: fun index item -> ..."
    | _, _ -> Error $"Unknown collection operator: {keyword}."

  let parseIter keyword args =
    let actionTokens, lambdaTokens = iterParts args
    parseIterAction keyword actionTokens
    |> Result.bind (fun action ->
      parseIterLambda keyword action lambdaTokens)

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
      let hasCloseParen =
        hasOpenParen && index < input.Length && input[index] = ')'
      let index =
        if hasCloseParen then
          skipSpaces input (index + 1)
        else
          index
      let syntaxError =
        if hasOpenParen && not hasCloseParen then
          Some "Expected ')' after parenthesized binding."
        else
          None
      let hasEquals = index < input.Length && input[index] = '='
      let expressionStart = if hasEquals then Some(index + 1) else None
      { Name = name
        TypeAnnotation = typ
        TypePrefix = if hasEquals then None else typ
        TypePrefixStart = if hasEquals then None else typStart
        HasEquals = hasEquals
        Expression = expressionStart |> Option.map (fun index -> input[index..])
        ExpressionStart = expressionStart
        SyntaxError = syntaxError })

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
    let rec loop depth current elements sawSeparator = function
      | [] when List.isEmpty current ->
        if sawSeparator then
          Error $"Trailing '{separator}' in literal."
        else
          Ok(List.rev elements)
      | [] ->
        Ok(List.rev (List.rev current :: elements))
      | token :: _ when token = separator && depth = 0
        && List.isEmpty current ->
        Error "Empty literal element."
      | token :: rest when token = separator && depth = 0 ->
        loop depth [] (List.rev current :: elements) true rest
      | token :: rest ->
        loop (updateDepth depth token) (token :: current) elements false rest
    loop 0 [] [] false tokens

  let splitPipelineTokens tokens =
    let rec loop depth segments current sawPipeline = function
      | [] when List.isEmpty current ->
        if sawPipeline then
          Error "Pipeline operator '|>' must be followed by an expression."
        else
          Error "An expression is required."
      | [] ->
        Ok(List.rev (List.rev current :: segments))
      | token :: _ when token = "|>" && depth = 0 && List.isEmpty current ->
        if List.isEmpty segments then
          Error "Pipeline operator '|>' cannot start an expression."
        else
          Error "Pipeline operator '|>' must be followed by an expression."
      | token :: rest when token = "|>" && depth = 0 ->
        loop depth (List.rev current :: segments) [] true rest
      | token :: rest ->
        loop (updateDepth depth token) segments (token :: current) false rest
    loop 0 [] [] false tokens

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

  let private isBareCharacter chr =
    not (Char.IsWhiteSpace chr)
    && chr <> '(' && chr <> ')'
    && chr <> '[' && chr <> ']'
    && chr <> ',' && chr <> ';'
    && chr <> '|' && chr <> '\'' && chr <> '"'

  module private Grammar =
    open FParsec

    let symbol text = pstring text .>> spaces

    let quoted delimiter =
      pchar delimiter >>. manyCharsTill anyChar (pchar delimiter)
      |>> fun text -> string delimiter + text + string delimiter

    let bareCharacter = isBareCharacter

    let word =
      let quoted = quoted '\'' <|> quoted '"'
      let bare = many1Satisfy bareCharacter |>> string
      many1 (quoted <|> bare)
      |>> String.concat ""
      .>> spaces

    let nestedToken, nestedTokenRef =
      createParserForwardedToRef<string list, unit>()

    let delimited opening closing =
      between (symbol opening) (symbol closing) (many nestedToken)
      |>> fun body -> opening :: List.concat body @ [ closing ]

    let nested =
      choice
        [ attempt (delimited "[|" "|]")
          attempt (delimited "(" ")")
          attempt (delimited "[" "]")
          symbol "|>" |>> List.singleton
          symbol "," |>> List.singleton
          symbol ";" |>> List.singleton
          word |>> List.singleton ]

    do nestedTokenRef.Value <- nested

    let topLevelToken =
      choice
        [ attempt (delimited "[|" "|]")
          attempt (delimited "(" ")")
          attempt (delimited "[" "]")
          symbol "," |>> List.singleton
          symbol ";" |>> List.singleton
          word |>> List.singleton ]

    let pipeline =
      spaces >>. sepBy1 (many1 topLevelToken |>> List.concat)
        (symbol "|>") .>> eof

    let parse text =
      match run pipeline text with
      | Success(segments, _, _) -> Result.Ok segments
      | Failure(message, _, _) ->
        Result.Error $"Invalid pipeline expression: {message}"

    let partialQuoted delimiter =
      pchar delimiter >>. manyChars (satisfy ((<>) delimiter))
      .>>. opt (pchar delimiter)
      |>> fun (text, closing) ->
        let closing = closing |> Option.map string |> Option.defaultValue ""
        string delimiter + text + closing

    let partialWordText =
      let bare = many1Satisfy bareCharacter |>> string
      let part =
        lookAhead anyChar >>= function
        | '\'' -> partialQuoted '\''
        | '"' -> partialQuoted '"'
        | _ -> bare
      many1 part
      |>> String.concat ""

    let partialSymbol text =
      (getPosition .>> pstring text .>>. getPosition .>> spaces)
      |>> fun (start, finish) ->
        PartialToken(text, int start.Index, int finish.Index)

    let startsWith text parser = lookAhead (pstring text) >>. parser

    let partialWord =
      (getPosition .>>. partialWordText .>>. getPosition .>> spaces)
      |>> fun ((start, text), finish) ->
        PartialToken(text, int start.Index, int finish.Index)

    let partialNode, partialNodeRef =
      createParserForwardedToRef<ReplPartialSyntax, unit>()

    let partialDelimited opening closing =
      pipe4
        (getPosition .>> pstring opening .>> spaces)
        (many partialNode)
        (opt (pstring closing .>> spaces))
        getPosition
        (fun start children close finish ->
          PartialDelimited(opening, close, int start.Index, int finish.Index,
                           children))

    let partialBracket =
      startsWith "[|" (partialDelimited "[|" "|]")
      <|> partialDelimited "[" "]"

    let rec nodeTokens = function
      | PartialToken(text, _, _) -> [ text ]
      | PartialDelimited(opening, closing, _, _, children) ->
        let closing =
          closing |> Option.map List.singleton |> Option.defaultValue []
        opening :: (children |> List.collect nodeTokens) @ closing

    let partialNested =
      lookAhead anyChar >>= function
      | '[' -> partialBracket
      | '(' -> partialDelimited "(" ")"
      | '|' -> startsWith "|>" (partialSymbol "|>")
      | ',' -> partialSymbol ","
      | ';' -> partialSymbol ";"
      | _ -> partialWord

    do partialNodeRef.Value <- partialNested

    let partialTopLevelToken =
      lookAhead anyChar >>= function
      | '[' -> partialBracket
      | '(' -> partialDelimited "(" ")"
      | ')' -> partialSymbol ")"
      | ']' -> partialSymbol "]"
      | '|' -> startsWith "|]" (partialSymbol "|]")
      | ',' -> partialSymbol ","
      | ';' -> partialSymbol ";"
      | _ -> partialWord

    let partialSegment =
      getPosition .>>. many1 partialTopLevelToken .>>. getPosition
      |>> fun ((start, nodes), finish) ->
        { Start = int start.Index
          End = int finish.Index
          Nodes = nodes
          Tokens = nodes |> List.collect nodeTokens }

    let partialPipeline =
      let pipe =
        getPosition .>> symbol "|>" |>> fun position -> int position.Index
      let rec parseTail segments lastPipe =
        (attempt (pipe .>>. partialSegment)
         >>= fun (position, segment) ->
           parseTail (segment :: segments) (Some position))
        <|> (attempt pipe
             |>> fun position ->
               List.rev segments, Some position, true)
        <|> preturn (List.rev segments, lastPipe, false)
      spaces >>. opt partialSegment
      >>= function
        | None -> preturn { Segments = []; LastPipelineStart = None
                            HasTrailingPipeline = false }
        | Some segment ->
          parseTail [ segment ] None
          |>> fun (segments, lastPipe, hasTrailing) ->
            { Segments = segments
              LastPipelineStart = lastPipe
              HasTrailingPipeline = hasTrailing }
      .>> eof

    let parsePartial text =
      match run partialPipeline text with
      | Success(result, _, _) -> Some result
      | Failure _ -> None

  let parsePipeline text =
    Grammar.parse text
    |> Result.bind (fun segments ->
      segments
      |> List.map toSegment
      |> List.fold (fun state item ->
        Result.bind (fun values ->
          Result.map (fun value -> value :: values) item) state
      ) (Ok [])
      |> Result.map List.rev)

  let tryParsePartialPipeline text = Grammar.parsePartial text

  let rec private partialSyntaxTokens = function
    | PartialToken(text, _, _) -> [ text ]
    | PartialDelimited(opening, closing, _, _, children) ->
      let closing =
        closing |> Option.map List.singleton |> Option.defaultValue []
      opening :: (children |> List.collect partialSyntaxTokens) @ closing

  let rec private offsetPartialSyntax offset = function
    | PartialToken(text, start, finish) ->
      PartialToken(text, start + offset, finish + offset)
    | PartialDelimited(opening, closing, start, finish, children) ->
      PartialDelimited(opening, closing, start + offset, finish + offset,
                       children |> List.map (offsetPartialSyntax offset))

  let private offsetPartialSegment offset (segment: ReplPartialSegment) =
    { Start = segment.Start + offset
      End = segment.End + offset
      Nodes = segment.Nodes |> List.map (offsetPartialSyntax offset)
      Tokens = segment.Tokens }

  let rec private updateLastSyntax (update: string -> string option) = function
    | PartialToken(token, start, finish) ->
      update token
      |> Option.map (fun text ->
        let delta = text.Length - token.Length
        PartialToken(text, start, finish + delta), delta)
    | PartialDelimited(opening, None, start, finish, children) ->
      updateLastSyntaxList update children
      |> Option.map (fun (children, delta) ->
        PartialDelimited(opening, None, start, finish + delta, children),
        delta)
    | PartialDelimited _ ->
      None

  and private updateLastSyntaxList (update: string -> string option)
                                   (nodes: ReplPartialSyntax list) =
    match List.rev nodes with
    | [] -> None
    | node :: nodes ->
      updateLastSyntax update node
      |> Option.map (fun (node, delta) ->
        List.rev (node :: nodes), delta)

  let private updateLastSegment (update: string -> string option)
                                (previousText: string)
                                (pipeline: ReplPartialPipeline) =
    match List.rev pipeline.Segments with
    | segment :: segments when segment.End = previousText.Length ->
      updateLastSyntaxList update segment.Nodes
      |> Option.map (fun (nodes, delta) ->
        let segment =
          { segment with
              End = segment.End + delta
              Nodes = nodes
              Tokens = nodes |> List.collect partialSyntaxTokens }
        { pipeline with Segments = List.rev (segment :: segments) })
    | _ ->
      None

  let private endsWithBareCharacter (text: string) =
    text.Length > 0 && isBareCharacter text[text.Length - 1]

  let private tryAppendToLastToken (previousText: string)
                                   (pipeline: ReplPartialPipeline)
                                   (text: string) =
    if text.StartsWith(previousText, StringComparison.Ordinal) then
      let suffix = text[previousText.Length..]
      if endsWithBareCharacter previousText
         && suffix |> Seq.forall isBareCharacter then
        updateLastSegment (fun token ->
          if token |> Seq.forall isBareCharacter then Some(token + suffix)
          else None) previousText pipeline
      else
        None
    else
      None

  let private tryRemoveFromLastToken (previousText: string)
                                     (pipeline: ReplPartialPipeline)
                                     (text: string) =
    if previousText.StartsWith(text, StringComparison.Ordinal) then
      let suffix = previousText[text.Length..]
      if endsWithBareCharacter text
         && suffix |> Seq.forall isBareCharacter then
        updateLastSegment (fun token ->
          let length = token.Length - suffix.Length
          if length > 0 && token.EndsWith(suffix, StringComparison.Ordinal) then
            Some token[..length - 1]
          else
            None) previousText pipeline
      else
        None
    else
      None

  let private commonPrefixLength (left: string) (right: string) =
    let limit = min left.Length right.Length
    let mutable index = 0
    while index < limit && left[index] = right[index] do
      index <- index + 1
    index

  let private tryReparseChangedSegment (previousText: string)
                                       (pipeline: ReplPartialPipeline)
                                       (text: string) =
    let changed = commonPrefixLength previousText text
    let index =
      pipeline.Segments
      |> List.tryFindIndex (fun segment ->
        segment.Start <= changed && changed <= segment.End)
    match index with
    | Some index ->
      let segment = pipeline.Segments[index]
      let suffix = text[segment.Start..]
      if String.IsNullOrWhiteSpace suffix then
        None
      else
        tryParsePartialPipeline suffix
        |> Option.map (fun reparsed ->
          let prefix = pipeline.Segments |> List.take index
          let segments =
            reparsed.Segments
            |> List.map (offsetPartialSegment segment.Start)
          let previousPipe =
            pipeline.LastPipelineStart
            |> Option.filter (fun position -> position < segment.Start)
          let lastPipe =
            reparsed.LastPipelineStart
            |> Option.map ((+) segment.Start)
            |> Option.orElse previousPipe
          { Segments = prefix @ segments
            LastPipelineStart = lastPipe
            HasTrailingPipeline = reparsed.HasTrailingPipeline })
    | None ->
      None

  let tryUpdatePartialPipeline (previousText: string)
                               (pipeline: ReplPartialPipeline) (text: string) =
    if text = previousText then
      Some pipeline
    else
      tryAppendToLastToken previousText pipeline text
      |> Option.orElseWith (fun () ->
        tryRemoveFromLastToken previousText pipeline text)
      |> Option.orElseWith (fun () ->
        tryReparseChangedSegment previousText pipeline text)

  let private tryUnclosedNode nodes =
    let rec loop = function
      | [] -> None
      | PartialDelimited(opening, closing, start, finish, children) :: rest ->
        match loop (List.rev children) with
        | Some node -> Some node
        | None when Option.isNone closing ->
          Some(opening, start, finish, children)
        | None -> loop rest
      | _ :: rest -> loop rest
    loop (List.rev nodes)

  let tryPartialScope (pipeline: ReplPartialPipeline) =
    let scope (opening: string) start finish
              (children: ReplPartialSyntax list) =
      let separator =
        children
        |> List.mapi (fun index node -> index, node)
        |> List.choose (fun (index, node) ->
          match node with
          | PartialToken(("," | ";"), _, tokenEnd) ->
            Some(index, tokenEnd)
          | _ -> None)
        |> List.tryLast
      let start, nodes =
        match separator with
        | Some(index, tokenEnd) -> tokenEnd, children |> List.skip (index + 1)
        | None -> start + opening.Length, children
      { Start = start
        End = finish
        Tokens = nodes |> List.collect partialSyntaxTokens }
    pipeline.Segments
    |> List.tryLast
    |> Option.bind (fun segment -> tryUnclosedNode segment.Nodes)
    |> Option.map (fun (opening, start, finish, children) ->
      scope opening start finish children)

  let private parseKind token =
    match ReplValueKind.tryParse token with
    | Some kind -> Ok kind
    | None -> Error $"Unknown type annotation: {token}"

  let topLevelPipelinePositions (input: string) =
    let rec loop index quote depth positions =
      if index >= input.Length then
        List.rev positions
      else
        let chr = input[index]
        match quote with
        | Some delimiter when chr = delimiter ->
          loop (index + 1) None depth positions
        | Some _ ->
          loop (index + 1) quote depth positions
        | None when chr = '\'' || chr = '"' ->
          loop (index + 1) (Some chr) depth positions
        | None when chr = '(' || chr = '[' ->
          if chr = '[' && index + 1 < input.Length
             && input[index + 1] = '|' then
            loop (index + 2) None (depth + 1) positions
          else
            loop (index + 1) None (depth + 1) positions
        | None when chr = ')' || chr = ']' ->
          loop (index + 1) None (max 0 (depth - 1)) positions
        | None when chr = '|' && index + 1 < input.Length
          && input[index + 1] = '>' && depth = 0 ->
          loop (index + 2) None depth (index :: positions)
        | None ->
          loop (index + 1) None depth positions
    loop 0 None 0 []

  let topLevelLastPipeline input =
    topLevelPipelinePositions input |> List.tryLast

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
      match header.SyntaxError with
      | Some message -> Error message
      | None ->
      match header.Name, header.HasEquals, header.Expression with
      | Some name, true, Some expression when isValidName name ->
        let expected =
          match header.TypeAnnotation with
          | Some typ when String.IsNullOrWhiteSpace typ ->
            Error "Type annotation is missing after ':'."
          | None -> Ok None
          | Some typ -> parseKind typ |> Result.map Some
        expected
        |> Result.bind (fun expected ->
          if String.IsNullOrWhiteSpace expression then
            Error "An expression is required."
          else
            parsePipeline expression
            |> Result.map (fun segments ->
              Evaluate(segments, Some name, expected)))
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
        parsePipeline input
        |> Result.map (fun segments -> Evaluate(segments, None, None))
