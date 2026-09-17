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
open B2R2.FrontEnd.BinFile

/// The semantic category of an interactive completion candidate.
[<RequireQualifiedAccess>]
type SuggestionKind =
  | Command
  | Action
  | Binding
  | Argument
  | Path

/// One candidate displayed and inserted by the Transformer TUI.
type SuggestionItem =
  { Text: string
    Label: string
    Detail: string
    Kind: SuggestionKind
    AppendSpace: bool }

/// Candidates and the input range they replace.
type SuggestionSet =
  { Items: SuggestionItem list
    Start: int
    Length: int
    Hint: string option
    HintHighlights: (int * int) list }

module Suggestions =
  let private metaCommands =
    [ ":actions", "Show every available Transformer action"
      ":help", "Show interactive help"
      ":history", "Show commands evaluated in this REPL"
      ":inspect", "Select functions and sections from a binary"
      ":export", "Export a named value"
      ":layout", "Resize REPL panes"
      ":log", "Show detailed command execution records"
      ":needs", "List missing concrete execution context"
      ":plugin", "Load REPL actions from a plugin DLL"
      ":quit", "Leave the Transformer TUI"
      ":reset", "Clear values and reset the analysis state"
      ":restore", "Restore a value-history entry"
      ":script", "Save, load, or configure replay recording"
      ":show", "Show the full current or named value"
      ":type", "Show the current or named value type"
      ":undo", "Undo the most recent value change"
      ":values", "Show retained value history" ]

  let private matches prefix (candidate: string) =
    candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)

  let private isActionReference (head: string) =
    head.StartsWith("@", StringComparison.Ordinal) && head.Length > 1

  let private actionID (head: string) =
    if isActionReference head then head[1..] else head

  let private actionItem registered =
    let metadata = (registered: RegisteredAction).Metadata
    let name = ActionMetadata.actionName metadata.ID
    { Text = name
      Label = name
      Detail = ActionMetadata.typedSignature metadata
      Kind = SuggestionKind.Action
      AppendSpace = true }

  let private valueTypeDescription value =
    let kind = ReplValueKind.toString (value: ReplValue).Kind
    match value.Shape with
    | ReplValueShape.Tuple -> kind
    | ReplValueShape.List -> kind
    | ReplValueShape.Array -> kind
    | ReplValueShape.Collection -> kind
    | ReplValueShape.Scalar -> kind

  let private bindingItem (name, value: ReplValue) =
    { Text = name
      Label = name
      Detail = valueTypeDescription value
      Kind = SuggestionKind.Binding
      AppendSpace = true }

  let private commandItem (command, detail) =
    { Text = command
      Label = command
      Detail = detail
      Kind = SuggestionKind.Command
      AppendSpace =
        command = ":show" || command = ":type" || command = ":inspect"
        || command = ":restore" || command = ":export"
        || command = ":layout" || command = ":script"
        || command = ":plugin" }

  let private argumentItem kind detail text =
    { Text = text
      Label = text
      Detail = detail
      Kind = kind
      AppendSpace = true }

  let private argumentItemWithSpacing kind detail text appendSpace =
    { Text = text
      Label = text
      Detail = detail
      Kind = kind
      AppendSpace = appendSpace }

  let private parameterItem (name: string) detail =
    { Text = name + "="
      Label = name + "="
      Detail = detail
      Kind = SuggestionKind.Argument
      AppendSpace = false }

  let private letItem =
    { Text = "let"
      Label = "let"
      Detail = "bind an analysis result"
      Kind = SuggestionKind.Command
      AppendSpace = true }

  let private typeItem kind =
    let name = ReplValueKind.toString kind
    { Text = name
      Label = name
      Detail = "value type"
      Kind = SuggestionKind.Argument
      AppendSpace = true }

  let private typeCandidates prefix =
    ReplValueKind.all
    |> List.filter (ReplValueKind.toString >> matches prefix)
    |> List.map typeItem

  let private typeAnnotationCompletion input =
    match ReplLanguage.bindingHeader input with
    | Some header when not header.HasEquals ->
      match header.TypePrefix, header.TypePrefixStart with
      | Some prefix, Some start ->
        Some(typeCandidates prefix, start, prefix.Length)
      | _ -> None
    | _ -> None

  let private expectedOutput input =
    ReplLanguage.bindingExpected input

  let private tryActionOutput registry head =
    ActionRegistry.tryFind (actionID head) registry
    |> Option.map (fun action -> action.Metadata.Output)

  let private actionOutput registry inputKind segment =
    match segment with
    | head :: args ->
      ActionRegistry.tryFind (actionID head) registry
      |> Option.map (fun action ->
        if action.Metadata.ID = "pick" then
          match inputKind with
          | Some(ReplValueKind.Collection kind)
          | Some(ReplValueKind.List kind)
          | Some(ReplValueKind.Array kind) -> kind
          | _ -> action.Metadata.Output
        else
          ActionMetadata.outputForArguments action.Metadata inputKind args)
    | [] -> None

  let private splitLiteralElements separator tokens =
    ReplLanguage.splitTopLevel separator tokens

  let private kindOfElement state = function
    | [ name ] ->
      TransformerReplState.tryFind name state
      |> Option.map (fun value -> value.Kind)
    | _ -> None

  let private homogeneousKind kinds =
    kinds
    |> List.tryFind (fun kind -> kind <> ReplValueKind.Unit)
    |> Option.defaultValue ReplValueKind.Any

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

  let private firstSegmentKind registry state tokens =
    let state: TransformerReplState = state
    match literalKind state tokens with
    | Some kind -> Some kind
    | None ->
      match tokens with
      | head :: _ ->
        match TransformerReplState.tryFind head state with
        | Some value ->
          Some value.Kind
        | None ->
          actionOutput registry None tokens
      | [] ->
        state.Current |> Option.map (fun value -> value.Kind)

  let private inferInputKind registry state expression =
    let state: TransformerReplState = state
    let expression: string = expression
    let expression = ReplLanguage.expressionPortion expression
    let segments = InputAnalysis.splitPipelineTokens expression
    match segments with
    | [] | [ _ ] ->
      state.Current |> Option.map (fun value -> value.Kind)
    | first :: rest ->
      let completed =
        match List.rev rest with
        | [] -> []
        | _ :: rest -> List.rev rest
      completed
      |> List.fold (fun kind segment ->
        match segment with
        | _ :: _ ->
          actionOutput registry kind segment |> Option.orElse kind
        | [] ->
          kind) (firstSegmentKind registry state first)

  let private outputMatches inputKind expected registered =
    let registered: RegisteredAction = registered
    match expected with
    | Some kind ->
      ActionMetadata.possibleOutputs registered.Metadata inputKind
      |> List.exists (fun output -> ReplValueKind.isCompatible output kind)
    | None ->
      true

  let private valueMatches expected (value: ReplValue) =
    match expected with
    | Some kind -> ReplValueKind.isCompatible value.Kind kind
    | None -> true

  let private actionCandidates registry kind expected prefix =
    let actions =
      match kind with
      | Some kind ->
        ActionRegistry.getApplicable kind registry
      | None ->
        ActionRegistry.getAll registry
        |> List.filter (fun action ->
          ActionMetadata.acceptedInputs action.Metadata
          |> List.contains ReplValueKind.Unit)
    actions
    |> List.filter (outputMatches kind expected)
    |> List.filter (fun action ->
      matches prefix (ActionMetadata.actionName action.Metadata.ID))
    |> List.map actionItem

  let private initialCandidates registry state prefix includeLet includeCurrent
                                      expected =
    let state: TransformerReplState = state
    let keywords =
      if includeLet && matches prefix letItem.Text then [ letItem ]
      else []
    let bindings =
      state.Bindings
      |> Map.toList
      |> List.filter (fun (_, value) -> valueMatches expected value)
      |> List.filter (fst >> matches prefix)
      |> List.map bindingItem
    let sourceActions = actionCandidates registry None expected prefix
    let currentActions =
      if includeCurrent then
        state.Current
        |> Option.map (fun value ->
          actionCandidates registry (Some value.Kind) expected prefix)
        |> Option.defaultValue []
      else
        []
    keywords @ bindings @ sourceActions @ currentActions
    |> List.distinctBy (fun item -> item.Text)

  let private literalBindingCandidates state expression prefix =
    let push token stack =
      match token with
      | "(" | "[" | "[|" -> token :: stack
      | ")" ->
        match stack with
        | "(" :: rest -> rest
        | _ -> stack
      | "]" ->
        match stack with
        | "[" :: rest -> rest
        | _ -> stack
      | "|]" ->
        match stack with
        | "[|" :: rest -> rest
        | _ -> stack
      | _ -> stack
    let stack =
      InputAnalysis.tokenize expression |> List.fold (fun stack token ->
        push token stack) []
    match stack with
    | ("(" | "[" | "[|") :: _ ->
      state.Bindings
      |> Map.toList
      |> List.filter (fun (name, value) ->
        matches prefix name && value.Collection.Values.Length = 1)
      |> List.map bindingItem
      |> Some
    | _ -> None

  let private quotePath (path: string) =
    if path.Contains ' ' then $"\"{path}\"" else path

  let private normalizePath (path: string) =
    path.Replace('\\', '/')

  let private pathCandidates (prefix: string) =
    let cleanPrefix = prefix.TrimStart([| '\''; '"' |])
    let directoryPart = Path.GetDirectoryName cleanPrefix
    let directoryPart = if isNull directoryPart then "" else directoryPart
    let filePart = Path.GetFileName cleanPrefix
    let searchDirectory =
      if String.IsNullOrEmpty directoryPart then "." else directoryPart
    try
      Directory.EnumerateFileSystemEntries searchDirectory
      |> Seq.choose (fun path ->
        let name = Path.GetFileName path
        if matches filePart name then
          let relative =
            if String.IsNullOrEmpty directoryPart then
              name
            else
              directoryPart.TrimEnd([| '/'; '\\' |]) + "/" + name
          let isDirectory = Directory.Exists path
          let text =
            let relative = normalizePath relative
            if isDirectory then relative + "/" else relative
          Some
            { Text = quotePath text
              Label = text
              Detail = if isDirectory then "directory" else "file"
              Kind = SuggestionKind.Path
              AppendSpace = not isDirectory }
        else
          None)
      |> Seq.truncate 20
      |> Seq.toList
    with _ -> []

  let private valueCandidates kind detail prefix values =
    values
    |> List.filter (matches prefix)
    |> List.map (argumentItem kind detail)

  let private isaCandidates =
    [ "x86"
      "x86-64"
      "armv7"
      "thumb"
      "aarch64"
      "mips32"
      "mips32le"
      "mips64"
      "ppc32"
      "ppc64"
      "riscv64"
      "sparc64"
      "s390x"
      "sh4"
      "parisc"
      "m68k"
      "avr"
      "tms320c6000"
      "evm"
      "python"
      "wasm"
      "cil" ]

  let private tryCurrentBinary (state: TransformerReplState) =
    state.Current
    |> Option.bind (fun value ->
      value.Collection.Values
      |> Array.tryPick (function
        | :? Binary as binary -> Some binary
        | _ -> None))

  let private tryCurrentSlice (state: TransformerReplState) =
    state.Current
    |> Option.bind (fun value ->
      value.Collection.Values
      |> Array.tryPick (function
        | :? BinarySlice as slice -> Some slice
        | _ -> None))

  let private tryCurrentRequirements (state: TransformerReplState) =
    match state.LastNeeds with
    | Some needs -> Some needs
    | None ->
      state.Current
      |> Option.bind (fun value ->
        value.Collection.Values
        |> Array.tryPick (function
          | :? ContextRequirements as needs -> Some needs
          | _ -> None))

  let private sectionCandidates state prefix =
    try
      let sectionItems binary inside =
        let hdl = Binary.Handle binary
        BinFileOps.getSections hdl.File
        |> Array.filter (fun section -> section.FileSize > 0UL)
        |> Array.filter inside
        |> Array.choose (fun section ->
          if String.IsNullOrWhiteSpace section.Name then None
          else
            let finish = section.Address + section.FileSize
            let detail =
              $"section 0x{section.Address:x}-0x{finish:x}"
            Some(section.Name, detail))
        |> Array.toList
        |> List.filter (fst >> matches prefix)
        |> List.map (fun (name, detail) ->
          argumentItem SuggestionKind.Argument detail name)
      match tryCurrentSlice state with
      | Some slice ->
        let inside section =
          let finish = section.Address + section.FileSize
          section.Address >= slice.StartAddress && finish <= slice.EndAddress
        sectionItems slice.Source inside
      | None ->
        match tryCurrentBinary state with
        | Some binary ->
          sectionItems binary (fun _ -> true)
        | None ->
          []
    with _ -> []

  let private addressCandidates state prefix =
    try
      match tryCurrentSlice state with
      | Some slice ->
        [ $"0x{slice.StartAddress:x}", "slice start"
          $"0x{slice.EndAddress:x}", "slice end" ]
        |> List.filter (fst >> matches prefix)
        |> List.map (fun (text, detail) ->
          argumentItem SuggestionKind.Argument detail text)
      | None ->
        match tryCurrentBinary state with
        | Some binary ->
          let hdl = Binary.Handle binary
          let sections = BinFileOps.getSections hdl.File
          let sectionName address =
            sections
            |> Array.tryFind (fun section ->
              let finish = section.Address + section.FileSize
              section.FileSize > 0UL
              && section.Address <= address && address < finish)
            |> Option.map (fun section ->
              if String.IsNullOrWhiteSpace section.Name then "<unnamed>"
              else section.Name)
            |> Option.defaultValue "<no section>"
          let entryPoint = hdl.File.EntryPoint |> Option.toList
          let functions =
            BinFileOps.getFunctionAddresses hdl.File |> Array.toList
          let sectionStarts =
            sections
            |> Array.map (fun section -> section.Address)
            |> Array.toList
          entryPoint @ functions @ sectionStarts
          |> List.distinct
          |> List.map (fun address ->
            let text = $"0x{address:x}"
            let detail = $"address {sectionName address}"
            text, detail)
          |> List.filter (fst >> matches prefix)
          |> List.map (fun (text, detail) ->
            argumentItem SuggestionKind.Argument detail text)
        | None ->
          []
    with _ -> []

  let private requiredRegisterCandidates suffix state prefix =
    match tryCurrentRequirements state with
    | Some needs ->
      needs.Registers
      |> Array.toList
      |> List.map (fun item ->
        let detail = $"required at 0x{item.Address:x}"
        item.Name + suffix, detail)
      |> List.filter (fst >> matches prefix)
      |> List.map (fun (name, detail) ->
        argumentItemWithSpacing SuggestionKind.Argument detail name
          (String.IsNullOrEmpty suffix))
    | None -> []

  let private requiredMemoryCandidates suffix state prefix =
    match tryCurrentRequirements state with
    | Some needs ->
      needs.Memory
      |> Array.toList
      |> List.choose (fun item ->
        item.Address
        |> Option.map (fun addr ->
          let text = $"0x{addr:x}"
          let detail = $"required memory size={item.Size}"
          text + suffix, detail))
      |> List.filter (fst >> matches prefix)
      |> List.map (fun (text, detail) ->
        argumentItemWithSpacing SuggestionKind.Argument detail text
          (String.IsNullOrEmpty suffix))
    | None -> []

  let private innermostOpenBracket (text: string) =
    let rec loop index quote stack =
      if index >= text.Length then
        stack |> List.tryHead
      else
        let chr = text[index]
        match quote with
        | Some delimiter when chr = delimiter ->
          loop (index + 1) None stack
        | Some _ ->
          loop (index + 1) quote stack
        | None when chr = '\'' || chr = '"' ->
          loop (index + 1) (Some chr) stack
        | None when chr = '[' ->
          loop (index + 1) None (index :: stack)
        | None when chr = ']' ->
          let stack =
            match stack with
            | _ :: rest -> rest
            | [] -> []
          loop (index + 1) None stack
        | None ->
          loop (index + 1) None stack
    loop 0 None []

  let private parameterBeforeBracket (segment: string) openIndex =
    if openIndex <= 0 then
      None
    else
      let prefix = segment[..openIndex - 1].TrimEnd()
      let equals = prefix.LastIndexOf '='
      if equals < 0 then
        None
      else
        let before = prefix[..equals - 1].TrimEnd()
        let separators = [| ' '; '\t'; '('; '['; ';'; ',' |]
        let start = before.LastIndexOfAny separators + 1
        if start >= before.Length then
          None
        else
          Some(before[start..].ToLowerInvariant())

  let private currentListEntry (segment: string) openIndex =
    let body = segment[openIndex + 1..]
    let lastSemicolon = body.LastIndexOf ';'
    let lastComma = body.LastIndexOf ','
    let start = max lastSemicolon lastComma + 1
    body[start..].TrimStart()

  let private contextListValueCandidates parameter prefix =
    match parameter with
    | "regs" ->
      valueCandidates SuggestionKind.Argument "register value" prefix
        [ "0x0"; "0x1"; "0xffffffffffffffff" ]
    | "mem" ->
      valueCandidates SuggestionKind.Argument "memory bytes" prefix
        [ "00"; "90"; "0011223344556677" ]
    | "sym-mem" ->
      valueCandidates SuggestionKind.Argument "symbolic memory" prefix
        [ "input@0x70000000:16"
          "password@0x70000000:18"
          "buffer@0x70000000:32" ]
    | _ -> []

  let private isContextAction head =
    let id = actionID head
    id = "set-context" || id = "symb-context"

  let private setContextListCandidates state (context: InputContext) =
    match context.SegmentWords with
    | head :: _ when isContextAction head ->
      match innermostOpenBracket context.Segment with
      | None -> None
      | Some openIndex ->
        match parameterBeforeBracket context.Segment openIndex with
        | Some "regs" ->
          let entry = currentListEntry context.Segment openIndex
          if entry.Contains "=" then
            contextListValueCandidates "regs" context.Prefix |> Some
          else
            requiredRegisterCandidates "=" state context.Prefix |> Some
        | Some "mem" ->
          let entry = currentListEntry context.Segment openIndex
          if entry.Contains "=" then
            contextListValueCandidates "mem" context.Prefix |> Some
          else
            requiredMemoryCandidates "=" state context.Prefix |> Some
        | Some "sym-mem" ->
          contextListValueCandidates "sym-mem" context.Prefix |> Some
        | _ -> None
    | _ -> None

  let private semanticCandidates state argument prefix =
    let argument: ActionArgument = argument
    let values detail values =
      valueCandidates SuggestionKind.Argument detail prefix values
    match argument.Kind with
    | ActionArgumentKind.Path
    | ActionArgumentKind.ExistingPath
    | ActionArgumentKind.OutputPath ->
      pathCandidates prefix
    | ActionArgumentKind.ISA ->
      values "instruction-set architecture" isaCandidates
    | ActionArgumentKind.Integer ->
      values argument.Description [ "0"; "1"; "4"; "16" ]
    | ActionArgumentKind.Float ->
      values argument.Description [ "0.2"; "0.5"; "1.0" ]
    | ActionArgumentKind.HexPattern ->
      values argument.Description [ "7f454c46"; "3031.." ]
    | ActionArgumentKind.HexBytes ->
      values argument.Description [ "00"; "90"; "9090" ]
    | ActionArgumentKind.Address ->
      addressCandidates state prefix
    | ActionArgumentKind.Size ->
      values argument.Description [ "64"; "0x40"; "+64" ]
    | ActionArgumentKind.Section ->
      sectionCandidates state prefix
    | ActionArgumentKind.Action
    | ActionArgumentKind.ParameterFunction ->
      []
    | ActionArgumentKind.Choice ->
      values argument.Description argument.Choices
    | ActionArgumentKind.Text ->
      []

  let private tryParameterName (token: string) =
    let index = token.IndexOf '='
    if index <= 0 then None
    else
      let key = token[..index - 1]
      let typeIndex = key.IndexOf ':'
      let key = if typeIndex <= 0 then key else key[..typeIndex - 1]
      Some(key.ToLowerInvariant())

  let private tryParameterValue (token: string) =
    let index = token.IndexOf '='
    if index <= 0 then None
    else
      let key = token[..index - 1]
      let typeIndex = key.IndexOf ':'
      let key = if typeIndex <= 0 then key else key[..typeIndex - 1]
      Some(key.ToLowerInvariant(), token[index + 1..])

  let private isAttachedValuePrefix (segment: string) tokenStart =
    tokenStart > 0 && not (Char.IsWhiteSpace segment[tokenStart - 1])

  let private matchesArgumentName (name: string) argument =
    ActionMetadata.argumentKeys argument
    |> List.contains (name.ToLowerInvariant())

  let private collectionElementKind = function
    | ReplValueKind.Collection kind
    | ReplValueKind.List kind
    | ReplValueKind.Array kind -> Some kind
    | _ -> None

  let private isBatchParameterStart token =
    match tryParameterName token with
    | Some name -> name = "params"
    | None -> false

  let private tryBatchTargetAction words =
    let named =
      words
      |> List.tryPick (fun token ->
        match tryParameterValue token with
        | Some(name, value) when name = "action" -> Some value
        | _ -> None)
    match named with
    | Some action -> Some(actionID action)
    | None ->
      let positional =
        match words with
        | [] -> []
        | _ :: rest -> rest
      positional
      |> List.takeWhile (fun token ->
        token <> "(" && not (isBatchParameterStart token))
      |> List.tryFind (fun token ->
        token.StartsWith("@", StringComparison.Ordinal))
      |> Option.map actionID

  let private sampleParameterValue argument =
    let argument: ActionArgument = argument
    match argument.Kind with
    | ActionArgumentKind.OutputPath
    | ActionArgumentKind.Path
    | ActionArgumentKind.ExistingPath -> "out/{index}.bin"
    | ActionArgumentKind.ISA -> "x86-64"
    | ActionArgumentKind.Integer -> "0"
    | ActionArgumentKind.Float -> "0.2"
    | ActionArgumentKind.HexPattern -> "7f454c46"
    | ActionArgumentKind.HexBytes -> "90"
    | ActionArgumentKind.Address -> ""
    | ActionArgumentKind.Size -> "64"
    | ActionArgumentKind.Section -> ""
    | ActionArgumentKind.Choice ->
      argument.Choices |> List.tryHead |> Option.defaultValue ""
    | ActionArgumentKind.Action -> "@action"
    | ActionArgumentKind.ParameterFunction -> "fun item _ ->"
    | ActionArgumentKind.Text -> "text"

  let private parameterTemplate argument =
    let argument: ActionArgument = argument
    let key = ActionMetadata.argumentKeys argument |> List.head
    $"{key}={sampleParameterValue argument}"

  let private functionTemplate syntax =
    let body =
      (syntax: ActionSyntax).Arguments
      |> List.filter (fun argument -> not argument.IsOptional)
      |> function
        | [] ->
          syntax.Arguments
          |> List.tryHead
          |> Option.map parameterTemplate
          |> Option.defaultValue ""
        | arguments ->
          arguments |> List.map parameterTemplate |> String.concat " "
    $"(fun item _ -> {body})"

  let private functionTemplateCandidates registry target inputKind prefix =
    match ActionRegistry.tryFind target registry with
    | None -> []
    | Some registered ->
      registered.Metadata.Syntaxes
      |> List.filter (ActionMetadata.syntaxAccepts inputKind)
      |> List.map functionTemplate
      |> List.distinct
      |> valueCandidates SuggestionKind.Argument "parameter function" prefix

  let private syntaxArgument metadata inputKind completed argumentIndex =
    let metadata: ActionMetadata = metadata
    let syntaxes =
      ActionMetadata.matchingSyntaxes metadata inputKind completed
    let triggered =
      match completed with
      | trigger :: _ ->
        syntaxes |> List.filter (fun syntax -> syntax.Trigger = Some trigger)
      | [] ->
        []
    let syntaxes =
      if List.isEmpty triggered then
        syntaxes |> List.filter (fun syntax -> syntax.Trigger.IsNone)
      else
        triggered
    let argumentIndex =
      if List.isEmpty triggered then argumentIndex else argumentIndex - 1
    let names = completed |> List.choose tryParameterName
    if List.isEmpty names then
      syntaxes
      |> List.choose (fun syntax ->
        syntax.Arguments |> List.tryItem argumentIndex)
    else
      syntaxes
      |> List.collect (fun syntax -> syntax.Arguments)
      |> List.filter (fun argument ->
        names
        |> List.exists (fun name -> matchesArgumentName name argument)
        |> not)

  let private triggerCandidates metadata inputKind argumentIndex prefix =
    let metadata: ActionMetadata = metadata
    if argumentIndex = 0 then
      metadata.Syntaxes
      |> List.filter (ActionMetadata.syntaxAccepts inputKind)
      |> List.choose (fun syntax -> syntax.Trigger)
      |> List.distinct
      |> valueCandidates SuggestionKind.Argument "operation" prefix
    else
      []

  let private argumentNameItem argument =
    let argument: ActionArgument = argument
    let key = ActionMetadata.argumentKeys argument |> List.head
    let typ = ActionMetadata.argumentKindName argument.Kind
    { Text = key + "="
      Label = key + "="
      Detail = $"{typ} parameter"
      Kind = SuggestionKind.Argument
      AppendSpace = false }

  let private argumentNameCandidates registry metadata inputKind completed
                                     argumentIndex prefix =
    let metadata: ActionMetadata = metadata
    let batchActions () =
      match inputKind with
      | Some(ReplValueKind.Collection kind)
      | Some(ReplValueKind.List kind)
      | Some(ReplValueKind.Array kind) ->
        actionCandidates registry (Some kind) None prefix
        |> List.filter (fun item -> item.Text <> "@batch")
      | _ -> []
    let arguments =
      syntaxArgument metadata inputKind completed argumentIndex
      |> List.distinctBy (fun argument -> argument.Name)
      |> List.filter (fun argument ->
        ActionMetadata.argumentKeys argument
        |> List.exists (fun key -> matches prefix (key + "=")))
      |> List.map argumentNameItem
    let candidates =
      if metadata.ID = "batch" && argumentIndex = 0
         && prefix.StartsWith("@", StringComparison.Ordinal) then
        batchActions ()
      else
        triggerCandidates metadata inputKind argumentIndex prefix @ arguments
    candidates |> List.distinctBy (fun item -> item.Text)

  let private argumentCandidates registry state head completed argumentIndex
                                 inputKind prefix =
    match ActionRegistry.tryFind (actionID head) registry with
    | None ->
      []
    | Some registered ->
      let metadata = registered.Metadata
      argumentNameCandidates registry metadata inputKind completed
        argumentIndex prefix
      |> List.distinctBy (fun item -> item.Text)

  let private historyCandidates state prefix =
    state.ValueHistory
    |> List.rev
    |> List.map (fun entry ->
      let id = string entry.ID
      let kind = valueTypeDescription entry.Value
      let name = entry.Name |> Option.defaultValue "<unnamed>"
      id, $"{name}  {kind}")
    |> List.filter (fst >> matches prefix)
    |> List.map (fun (id, detail) ->
      argumentItem SuggestionKind.Argument detail id)

  let private namedArgumentCandidates registry state head name inputKind
                                      completed prefix =
    match ActionRegistry.tryFind (actionID head) registry with
    | None ->
      []
    | Some registered ->
      let batchActionCandidates () =
        match inputKind with
        | Some(ReplValueKind.Collection kind)
        | Some(ReplValueKind.List kind)
        | Some(ReplValueKind.Array kind) ->
          actionCandidates registry (Some kind) None prefix
          |> List.filter (fun item -> item.Text <> "@batch")
        | _ -> []
      let batchFunctionCandidates () =
        let inputKind = inputKind |> Option.bind collectionElementKind
        let words =
          ActionMetadata.actionName registered.Metadata.ID :: completed
        match tryBatchTargetAction words, inputKind with
        | Some target, Some kind ->
          functionTemplateCandidates registry target (Some kind) prefix
        | Some target, None ->
          functionTemplateCandidates registry target None prefix
        | None, _ ->
          []
      if registered.Metadata.ID = "batch" && name = "action" then
        batchActionCandidates ()
      elif registered.Metadata.ID = "batch" && name = "params" then
        batchFunctionCandidates ()
      elif registered.Metadata.ID = "set-reg" && name = "name" then
        requiredRegisterCandidates "" state prefix
      elif registered.Metadata.ID = "mem" && name = "addr" then
        requiredMemoryCandidates "" state prefix
      elif registered.Metadata.ID = "set-context" && name = "regs" then
        requiredRegisterCandidates "=" state prefix
      elif registered.Metadata.ID = "set-context" && name = "mem" then
        requiredMemoryCandidates "=" state prefix
      elif registered.Metadata.ID = "symb-context" && name = "regs" then
        requiredRegisterCandidates "=" state prefix
      elif registered.Metadata.ID = "symb-context" && name = "mem" then
        requiredMemoryCandidates "=" state prefix
      elif registered.Metadata.ID = "symb-context" && name = "sym-mem" then
        contextListValueCandidates "sym-mem" prefix
      else
        ActionMetadata.matchingSyntaxes registered.Metadata inputKind completed
        |> List.filter (ActionMetadata.syntaxHasParameter name)
        |> List.collect (fun syntax -> syntax.Arguments)
        |> List.distinctBy (fun argument -> argument.Name)
        |> List.filter (matchesArgumentName name)
        |> List.collect (fun argument ->
          semanticCandidates state argument prefix)
        |> List.distinctBy (fun item -> item.Text)
        |> List.distinctBy (fun item -> item.Text)

  let private splitAtLastSemicolon tokens =
    let rec loop depth current = function
      | [] -> List.rev current
      | ";" :: rest when depth = 0 -> loop 0 [] rest
      | token :: rest ->
        let depth = InputAnalysis.updateDepth depth token
        loop depth (token :: current) rest
    loop 0 [] tokens

  let private noArgumentCandidate metadata inputKind prefix =
    let metadata: ActionMetadata = metadata
    let hasNoArgumentSyntax =
      metadata.Syntaxes
      |> List.exists (fun syntax ->
        ActionMetadata.syntaxAccepts inputKind syntax
        && List.isEmpty syntax.Arguments)
    if hasNoArgumentSyntax && matches prefix ")" then
      [ { Text = ")"
          Label = ")"
          Detail = "no action parameters"
          Kind = SuggestionKind.Argument
          AppendSpace = false } ]
    else
      []

  let private batchBodyCandidates registry state context =
    let context: InputContext = context
    let fullExpression =
      ReplLanguage.expressionPortion context.InputBeforeCursor
    let lastPipeline = InputAnalysis.topLevelLastPipeline fullExpression
    let segment =
      lastPipeline
      |> Option.map (fun index -> fullExpression[index + 2..])
      |> Option.defaultValue context.Segment
    let words = InputAnalysis.splitWords segment
    match words with
    | head :: _ when actionID head = "batch" ->
      match tryBatchTargetAction words with
      | None -> None
      | Some target ->
        match ActionRegistry.tryFind target registry with
        | None -> None
        | Some registered ->
          let sourceExpression =
            lastPipeline
            |> Option.map (fun index -> fullExpression[..index - 1])
            |> Option.defaultValue context.Expression
          let itemKind =
            inferInputKind registry state sourceExpression
            |> Option.bind collectionElementKind
          match words |> List.tryFindIndex ((=) "->"), itemKind with
          | Some arrow, Some kind ->
            let body =
              words
              |> List.skip (arrow + 1)
              |> splitAtLastSemicolon
            let prefix = context.Prefix
            let lastIndex = context.InputBeforeCursor.Length - 1
            let endsWithSpace =
              context.InputBeforeCursor.Length > 0
              && Char.IsWhiteSpace context.InputBeforeCursor[lastIndex]
            let current =
              if endsWithSpace then None else body |> List.tryLast
            let before =
              if endsWithSpace then body else InputAnalysis.allButLast body
            let inputKind = Some kind
            let candidates =
              match current |> Option.bind tryParameterName with
              | Some name ->
                namedArgumentCandidates registry state
                  (ActionMetadata.actionName registered.Metadata.ID) name
                  inputKind before prefix
              | None ->
                let index =
                  if endsWithSpace then List.length body
                  else max 0 (List.length body - 1)
                argumentNameCandidates registry registered.Metadata inputKind
                  before index prefix
            let candidates =
              noArgumentCandidate registered.Metadata inputKind prefix
              @ candidates
            Some candidates
          | _ -> None
    | _ -> None

  let private scriptOperationCandidates prefix =
    [ "save"; "load"; "record" ]
    |> valueCandidates SuggestionKind.Argument "script operation" prefix

  let private scriptRecordCandidates prefix =
    [ "on"; "off" ]
    |> valueCandidates SuggestionKind.Argument "record mode" prefix

  let private pluginOperationCandidates prefix =
    [ "load" ]
    |> valueCandidates SuggestionKind.Argument "plugin operation" prefix

  let private pathArgumentCandidates
    (name: string) (detail: string) (prefix: string) (args: string list) =
    let key = name + "="
    let parameter = parameterItem name detail
    let paths = pathCandidates prefix
    match List.tryLast args with
    | Some token when
        token.StartsWith(key, StringComparison.OrdinalIgnoreCase) ->
      paths
    | Some token when token.Contains "=" -> []
    | Some _ when matches prefix key -> parameter :: paths
    | Some _ -> paths
    | None -> [ parameter ]

  let private scriptPathCandidates prefix words =
    match words with
    | [ ":script"; ("save" | "load") ] ->
      pathArgumentCandidates "path" "script path" prefix []
    | ":script" :: ("save" | "load") :: args ->
      pathArgumentCandidates "path" "script path" prefix args
    | _ -> []

  let private pluginPathCandidates prefix words =
    match words with
    | [ ":plugin"; "load" ] ->
      pathArgumentCandidates "path" "plugin DLL path" prefix []
    | ":plugin" :: "load" :: args ->
      pathArgumentCandidates "path" "plugin DLL path" prefix args
    | _ -> []

  let private exportPathCandidates prefix words =
    match words with
    | [ ":export"; _ ] -> []
    | ":export" :: _ :: args ->
      pathArgumentCandidates "path" "export path" prefix args
    | _ -> []

  let private layoutCandidates prefix =
    [ "sidebar=40"
      "sidebar=off"
      "output=20"
      "output=auto"
      "shell=4"
      "shell=6" ]
    |> valueCandidates SuggestionKind.Argument "layout option" prefix

  let private completeMeta (state: TransformerReplState) input prefix words =
    let input: string = input
    if input.TrimStart().StartsWith(":script save ")
      || input.TrimStart().StartsWith(":script load ") then
      scriptPathCandidates prefix words
    elif input.TrimStart().StartsWith(":script record ") then
      scriptRecordCandidates prefix
    elif input.TrimStart().StartsWith(":script") then
      scriptOperationCandidates prefix
    elif input.TrimStart().StartsWith(":plugin load ") then
      pluginPathCandidates prefix words
    elif input.TrimStart().StartsWith(":plugin") then
      pluginOperationCandidates prefix
    elif input.TrimStart().StartsWith(":layout") then
      layoutCandidates prefix
    elif input.TrimStart().StartsWith(":export ") then
      match words with
      | [ ":export"; _ ] when input.EndsWith " " ->
        pathArgumentCandidates "path" "export path" prefix []
      | [ ":export"; _; _ ] ->
        exportPathCandidates prefix words
      | _ ->
        state.Bindings
        |> Map.toList
        |> List.filter (fst >> matches prefix)
        |> List.map bindingItem
    else
      match words with
      | command :: _ when command = ":show" || command = ":type"
                          || command = ":inspect" ->
        state.Bindings
        |> Map.toList
        |> List.filter (fst >> matches prefix)
        |> List.map bindingItem
      | command :: _ when command = ":restore" ->
        historyCandidates state prefix
      | _ ->
        metaCommands
        |> List.filter (fst >> matches prefix)
        |> List.map commandItem

  let private completeExpression registry state context =
    let context: InputContext = context
    let expected = expectedOutput context.InputBeforeCursor
    let expression = context.Expression
    let segment = context.Segment
    let words = context.SegmentWords
    let hasPipeline = context.HasPipeline
    let endsWithSpace =
      segment.Length > 0 && Char.IsWhiteSpace segment[segment.Length - 1]
    let argumentState =
      InputAnalysis.splitPipeline expression
      |> List.tryHead
      |> Option.bind (InputAnalysis.splitWords >> List.tryHead)
      |> Option.bind (fun name -> TransformerReplState.tryFind name state)
      |> Option.map (fun value -> { state with Current = Some value })
      |> Option.defaultValue state
    let inputKindFor head =
      match ActionRegistry.tryFind (actionID head) registry with
      | Some registered when
          ActionMetadata.acceptedInputs registered.Metadata
          |> List.contains ReplValueKind.Unit ->
        Some ReplValueKind.Unit
      | _ when hasPipeline ->
        inferInputKind registry state expression
      | _ ->
        state.Current |> Option.map (fun value -> value.Kind)
    let completeArguments head completed argumentIndex =
      let inputKind = inputKindFor head
      argumentCandidates registry argumentState head completed argumentIndex
        inputKind context.Prefix
    match setContextListCandidates argumentState context with
    | Some candidates -> candidates
    | None ->
      match batchBodyCandidates registry argumentState context with
      | Some candidates -> candidates
      | None ->
        match literalBindingCandidates state expression context.Prefix with
        | Some candidates -> candidates
        | None ->
          match words with
          | [] ->
            if hasPipeline then
              let kind = inferInputKind registry state expression
              actionCandidates registry kind expected context.Prefix
            else
              initialCandidates registry state context.Prefix
                (not context.HasBinding) (not context.HasBinding) expected
          | [ head ] when endsWithSpace ->
            completeArguments head [] 0
          | [ _ ] when hasPipeline ->
            let kind = inferInputKind registry state expression
            actionCandidates registry kind expected context.Prefix
          | [ _ ] ->
            initialCandidates registry state context.Prefix
              (not context.HasBinding) (not context.HasBinding) expected
          | head :: _ ->
            let tokenStart = max 0 (segment.Length - context.Prefix.Length)
            let beforeToken =
              if tokenStart <= 0 then "" else segment[..tokenStart - 1]
            let beforeWords = InputAnalysis.splitWords beforeToken
            let parameter =
              if isAttachedValuePrefix segment tokenStart then
                beforeWords
                |> List.rev
                |> List.tryHead
                |> Option.bind tryParameterName
              else
                None
            match parameter with
            | Some name ->
              let inputKind = inputKindFor head
              let completed =
                match beforeWords with
                | _ :: completed -> completed
                | [] -> []
              namedArgumentCandidates registry argumentState head name
                inputKind completed context.Prefix
            | None ->
              let wordCount = List.length beforeWords
              let argumentIndex = max 0 (wordCount - 1)
              let completed =
                match beforeWords with
                | _ :: completed -> completed
                | [] -> []
              completeArguments head completed argumentIndex

  let private expressionContext context expression =
    let context: InputContext = context
    let lastPipeline = InputAnalysis.topLevelLastPipeline expression
    let segmentStart =
      lastPipeline |> Option.map ((+) 2) |> Option.defaultValue 0
    let segment = expression[segmentStart..]
    { context with
        Expression = expression
        Segment = segment
        SegmentWords = InputAnalysis.splitWords segment
        HasBinding = false
        HasPipeline = Option.isSome lastPipeline }

  let private showExpressionInput (input: string) =
    let trimmed = input.TrimStart()
    if trimmed.StartsWith(":show ", StringComparison.Ordinal) then
      let commandStart =
        input.IndexOf(":show", StringComparison.Ordinal)
      Some(input[(commandStart + 5)..])
    else
      None

  let private currentParameters metadata inputKind segment =
    let segment: string = segment
    let words = InputAnalysis.splitWords segment
    match words with
    | [] -> []
    | _ :: args ->
      let endsWithSpace =
        segment.Length > 0 && Char.IsWhiteSpace segment[segment.Length - 1]
      let token = if endsWithSpace then None else args |> List.tryLast
      let arguments =
        metadata.Syntaxes
        |> List.filter (ActionMetadata.syntaxAccepts inputKind)
        |> List.collect (fun syntax -> syntax.Arguments)
        |> List.distinctBy (fun argument -> argument.Name)
      let findArgument name =
        arguments
        |> List.tryFind (fun argument -> matchesArgumentName name argument)
      let current =
        token
        |> Option.bind tryParameterName
        |> Option.bind findArgument
      match current with
      | Some argument -> [ argument ]
      | None ->
        let completed =
          if endsWithSpace then args
          else InputAnalysis.allButLast args
        let argumentIndex =
          if endsWithSpace then List.length args
          else max 0 (List.length args - 1)
        let candidates =
          syntaxArgument metadata inputKind completed argumentIndex
          |> List.distinctBy (fun argument -> argument.Name)
        match token with
        | Some prefix when not (String.IsNullOrWhiteSpace prefix) ->
          candidates
          |> List.filter (fun argument ->
            ActionMetadata.argumentKeys argument
            |> List.exists (fun key -> matches prefix (key + "=")))
        | _ ->
          candidates

  let private findRanges (needle: string) (text: string) =
    if String.IsNullOrEmpty needle then
      []
    else
      let rec loop start ranges =
        let index =
          text.IndexOf(needle, start, StringComparison.OrdinalIgnoreCase)
        if index < 0 then
          List.rev ranges
        else
          loop (index + needle.Length) ((index, needle.Length) :: ranges)
      loop 0 []

  let private highlightRanges signature arguments =
    arguments
    |> List.collect (fun argument ->
      ActionMetadata.formatArgument argument
      |> fun text -> findRanges text signature)

  let private completionHint registry state context =
    let context: InputContext = context
    match context.SegmentWords with
    | head :: _ ->
      ActionRegistry.tryFind (actionID head) registry
      |> Option.map (fun registered ->
        let metadata = registered.Metadata
        let inputKind =
          if ActionMetadata.acceptedInputs metadata
             |> List.contains ReplValueKind.Unit then
            Some ReplValueKind.Unit
          elif context.HasPipeline then
            inferInputKind registry state context.Expression
          else
            state.Current |> Option.map (fun value -> value.Kind)
        let signature =
          let args =
            match context.SegmentWords with
            | _ :: args -> args
            | [] -> []
          ActionMetadata.typedSignatureForLines metadata inputKind args
          |> String.concat "\n"
        let highlight =
          currentParameters metadata inputKind context.Segment
          |> highlightRanges signature
        signature, highlight)
    | [] ->
      None

  let get registry (state: TransformerReplState) (input: string) cursor =
    let context = InputAnalysis.analyze input cursor
    let expressionContext =
      showExpressionInput context.InputBeforeCursor
      |> Option.map (expressionContext context)
      |> Option.defaultValue context
    match typeAnnotationCompletion context.InputBeforeCursor with
    | Some(items, start, length) ->
      { Items = List.truncate 20 items
        Start = start
        Length = length
        Hint = Some "type annotation"
        HintHighlights = [] }
    | None ->
      let hint = completionHint registry state expressionContext
      let items =
        if context.InputBeforeCursor.TrimStart().StartsWith ':' then
          match showExpressionInput context.InputBeforeCursor with
          | Some _ ->
            completeExpression registry state expressionContext
          | None ->
            completeMeta state context.InputBeforeCursor context.Prefix
              context.Words
        else
          completeExpression registry state expressionContext
      { Items =
          items
          |> List.distinctBy (fun item -> item.Text)
          |> List.truncate 20
        Start = context.TokenStart
        Length = context.TokenLength
        Hint = hint |> Option.map fst
        HintHighlights =
          hint
          |> Option.map snd
          |> Option.defaultValue [] }
