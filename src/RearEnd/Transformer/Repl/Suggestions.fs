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
open System.Collections.Concurrent
open System.IO
open System.Runtime.CompilerServices
open B2R2.FrontEnd.BinFile

/// The semantic category of an interactive completion candidate.
[<RequireQualifiedAccess>]
type SuggestionKind =
  | Command
  | Action
  | Binding
  | Argument
  | Path

/// Whether a candidate completes one token or starts a syntax fragment.
[<RequireQualifiedAccess>]
type SuggestionForm =
  | Token
  | SyntaxSnippet

/// One candidate displayed and inserted by the Transformer TUI.
type SuggestionItem =
  { Text: string
    Label: string
    Detail: string
    Kind: SuggestionKind
    AppendSpace: bool
    Form: SuggestionForm
    CursorOffset: int option }

/// Candidates and the input range they replace.
type SuggestionSet =
  { Items: SuggestionItem list
    Start: int
    Length: int
    Hint: string option
    HintHighlights: (int * int) list
    Diagnostics: ReplTypeDiagnostic list }

module Suggestions =
  type private DirectoryCacheEntry =
    { LastWrite: DateTime
      Entries: (string * bool)[] }

  let private directoryCache =
    ConcurrentDictionary<string, DirectoryCacheEntry>()

  let private addressCache =
    ConditionalWeakTable<Binary, Lazy<(string * string) list>>()

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
      AppendSpace = true
      Form = SuggestionForm.Token
      CursorOffset = None }

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
      AppendSpace = true
      Form = SuggestionForm.Token
      CursorOffset = None }

  let private commandItem (command, detail) =
    { Text = command
      Label = command
      Detail = detail
      Kind = SuggestionKind.Command
      AppendSpace =
        command = ":show" || command = ":type" || command = ":inspect"
        || command = ":restore" || command = ":export"
        || command = ":layout" || command = ":script"
        || command = ":plugin"
      Form = SuggestionForm.Token
      CursorOffset = None }

  let private argumentItem kind detail text =
    { Text = text
      Label = text
      Detail = detail
      Kind = kind
      AppendSpace = true
      Form = SuggestionForm.Token
      CursorOffset = None }

  let private argumentItemWithSpacing kind detail text appendSpace =
    { Text = text
      Label = text
      Detail = detail
      Kind = kind
      AppendSpace = appendSpace
      Form = SuggestionForm.Token
      CursorOffset = None }

  let private parameterItem (name: string) detail =
    { Text = name + "="
      Label = name + "="
      Detail = detail
      Kind = SuggestionKind.Argument
      AppendSpace = false
      Form = SuggestionForm.Token
      CursorOffset = None }

  let private letItem =
    { Text = "let"
      Label = "let"
      Detail = "bind an analysis result"
      Kind = SuggestionKind.Command
      AppendSpace = true
      Form = SuggestionForm.Token
      CursorOffset = None }

  let private typeItem kind =
    let name = ReplValueKind.toString kind
    { Text = name
      Label = name
      Detail = "value type"
      Kind = SuggestionKind.Argument
      AppendSpace = true
      Form = SuggestionForm.Token
      CursorOffset = None }

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

  let private isCollectionKind = function
    | ReplValueKind.Collection _
    | ReplValueKind.List _
    | ReplValueKind.Array _ -> true
    | _ -> false

  let private iterKeywordItem text detail =
    { Text = text
      Label = text
      Detail = detail
      Kind = SuggestionKind.Action
      AppendSpace = true
      Form = SuggestionForm.Token
      CursorOffset = None }

  let private iterKeywordCandidates kind prefix =
    match kind with
    | Some kind when isCollectionKind kind ->
      [ iterKeywordItem "iter"
          "syntax: iter @action [(fun item -> parameters)]"
        iterKeywordItem "iteri"
          "syntax: iteri @action [(fun index item -> parameters)]" ]
      |> List.filter (fun item -> matches prefix item.Text)
    | _ -> []

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
          actionCandidates registry (Some value.Kind) expected prefix
          @ iterKeywordCandidates (Some value.Kind) prefix)
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

  let private directoryEntries path =
    let fullPath = Path.GetFullPath path
    let lastWrite = Directory.GetLastWriteTimeUtc fullPath
    match directoryCache.TryGetValue fullPath with
    | true, cached when cached.LastWrite = lastWrite -> cached.Entries
    | _ ->
      let entries =
        Directory.EnumerateFileSystemEntries fullPath
        |> Seq.map (fun path -> path, Directory.Exists path)
        |> Seq.sortBy (fst >> Path.GetFileName)
        |> Seq.toArray
      directoryCache[fullPath] <-
        { LastWrite = lastWrite
          Entries = entries }
      entries

  let private pathCandidates (prefix: string) =
    let cleanPrefix = prefix.TrimStart([| '\''; '"' |])
    let directoryPart = Path.GetDirectoryName cleanPrefix
    let directoryPart = if isNull directoryPart then "" else directoryPart
    let filePart = Path.GetFileName cleanPrefix
    let searchDirectory =
      if String.IsNullOrEmpty directoryPart then "." else directoryPart
    try
      directoryEntries searchDirectory
      |> Seq.choose (fun (path, isDirectory) ->
        let name = Path.GetFileName path
        if matches filePart name then
          let relative =
            if String.IsNullOrEmpty directoryPart then
              name
            else
              directoryPart.TrimEnd([| '/'; '\\' |]) + "/" + name
          let text =
            let relative = normalizePath relative
            if isDirectory then relative + "/" else relative
          Some
            { Text = quotePath text
              Label = text
              Detail = if isDirectory then "directory" else "file"
              Kind = SuggestionKind.Path
              AppendSpace = not isDirectory
              Form = SuggestionForm.Token
              CursorOffset = None }
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
          let buildAddressIndex binary =
            lazy
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
          addressCache.GetValue(binary, buildAddressIndex).Value
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
    | "regions" ->
      valueCandidates SuggestionKind.Argument "memory region" prefix
        [ "buf=0x70000000..0x70001000:rw"
          "stack=0x70fff000..0x71000000:rw"
          "code=0x401000..0x402000:rx" ]
    | _ -> []

  let private isContextAction head =
    let id = actionID head
    id = "make-concrete-context" || id = "make-symbolic-context"

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
        | Some "regions" ->
          contextListValueCandidates "regions" context.Prefix |> Some
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

  let private isIterParameterStart token =
    match tryParameterName token with
    | Some name -> name = "params"
    | None -> false

  let private isIterHead head =
    String.Equals(head, "iter", StringComparison.OrdinalIgnoreCase)
    || String.Equals(head, "iteri", StringComparison.OrdinalIgnoreCase)

  let private tryIterTargetAction words =
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
        token <> "(" && not (isIterParameterStart token))
      |> List.tryFind (fun token ->
        token.StartsWith("@", StringComparison.Ordinal))
      |> Option.map actionID

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
      AppendSpace = false
      Form = SuggestionForm.Token
      CursorOffset = None }

  let private argumentNameCandidates registry metadata inputKind completed
                                     argumentIndex prefix =
    let metadata: ActionMetadata = metadata
    let arguments =
      syntaxArgument metadata inputKind completed argumentIndex
      |> List.distinctBy (fun argument -> argument.Name)
      |> List.filter (fun argument ->
        ActionMetadata.argumentKeys argument
        |> List.exists (fun key -> matches prefix (key + "=")))
      |> List.map argumentNameItem
    let candidates =
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
      if registered.Metadata.ID = "mem" && name = "addr" then
        requiredMemoryCandidates "" state prefix
      elif
        registered.Metadata.ID = "make-concrete-context"
        && name = "regs"
      then
        requiredRegisterCandidates "=" state prefix
      elif
        registered.Metadata.ID = "make-concrete-context"
        && name = "mem"
      then
        requiredMemoryCandidates "=" state prefix
      elif
        registered.Metadata.ID = "make-concrete-context"
        && name = "regions"
      then
        contextListValueCandidates "regions" prefix
      elif
        registered.Metadata.ID = "make-symbolic-context"
        && name = "regs"
      then
        requiredRegisterCandidates "=" state prefix
      elif
        registered.Metadata.ID = "make-symbolic-context"
        && name = "mem"
      then
        requiredMemoryCandidates "=" state prefix
      elif
        registered.Metadata.ID = "make-symbolic-context"
        && name = "sym-mem"
      then
        contextListValueCandidates "sym-mem" prefix
      elif
        registered.Metadata.ID = "make-symbolic-context"
        && name = "regions"
      then
        contextListValueCandidates "regions" prefix
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
          AppendSpace = false
          Form = SuggestionForm.Token
          CursorOffset = None } ]
    else
      []

  let private lambdaSkeletonCandidate =
    let text = "(fun )"
    let cursorOffset =
      text.LastIndexOf(")", StringComparison.Ordinal)
      |> fun index -> if index < 0 then text.Length else index
    [ { Text = text
        Label = "(fun )"
        Detail = "start item-parameter function"
        Kind = SuggestionKind.Argument
        AppendSpace = false
        Form = SuggestionForm.SyntaxSnippet
        CursorOffset = Some cursorOffset } ]

  let private hasNoArgumentSyntax metadata inputKind =
    let metadata: ActionMetadata = metadata
    metadata.Syntaxes
    |> List.exists (fun syntax ->
      ActionMetadata.syntaxAccepts inputKind syntax
      && List.isEmpty syntax.Arguments)

  let private firstParameterName metadata inputKind =
    syntaxArgument metadata inputKind [] 0
    |> List.tryHead
    |> Option.map (ActionMetadata.argumentKeys >> List.head)

  let private arrowCandidate metadata inputKind =
    firstParameterName metadata inputKind
    |> Option.map (fun name ->
      [ { Text = "-> " + name + "="
          Label = "-> " + name + "="
          Detail = "start item action parameters"
          Kind = SuggestionKind.Argument
          AppendSpace = false
          Form = SuggestionForm.SyntaxSnippet
          CursorOffset = None } ])
    |> Option.defaultValue []

  let private parameterNameSet tokens =
    tokens |> List.choose tryParameterName |> Set.ofList

  let private hasCompleteRequiredParameters metadata inputKind completed =
    let metadata: ActionMetadata = metadata
    let names = parameterNameSet completed
    metadata.Syntaxes
    |> List.exists (fun syntax ->
      ActionMetadata.syntaxAccepts inputKind syntax
      && (syntax.Arguments
          |> List.filter (fun argument -> not argument.IsOptional)
          |> List.forall (fun argument ->
            ActionMetadata.argumentKeys argument
            |> List.exists (fun key -> Set.contains key names))))

  let private closeLambdaCandidate metadata inputKind completed =
    if hasCompleteRequiredParameters metadata inputKind completed then
      [ { Text = ")"
          Label = ")"
          Detail = "close item-parameter function"
          Kind = SuggestionKind.Argument
          AppendSpace = false
          Form = SuggestionForm.Token
          CursorOffset = None } ]
    else
      []

  let private expectedLambdaArgumentCount = function
    | head when
        String.Equals(head, "iteri", StringComparison.OrdinalIgnoreCase) ->
      2
    | _ -> 1

  let private lambdaArgumentsBeforeArrow words =
    match words |> List.tryFindIndex ((=) "fun") with
    | None -> None
    | Some index ->
      words
      |> List.skip (index + 1)
      |> List.takeWhile (fun token -> token <> "->" && token <> ")")
      |> Some

  let private hasClosedLambda arrow words =
    words |> List.skip (arrow + 1) |> List.contains ")"

  let private iterElementKind registry state context =
    let context: InputContext = context
    let fullExpression = context.Expression
    let lastPipeline = InputAnalysis.topLevelLastPipeline fullExpression
    let sourceExpression =
      lastPipeline
      |> Option.map (fun index -> fullExpression[..index - 1])
      |> Option.defaultValue context.Expression
    ReplTypeAnalysis.outputKind registry state sourceExpression
    |> Option.bind ReplTypeAnalysis.collectionElementKind

  let private iterActionCandidates registry state context prefix =
    match iterElementKind registry state context with
    | Some kind -> actionCandidates registry (Some kind) None prefix
    | None -> []

  let private isCurrentIterKeyword head (context: InputContext) =
    String.Equals(head, context.Prefix, StringComparison.OrdinalIgnoreCase)

  let private isCurrentIterAction target (context: InputContext) =
    context.CompletionPhase = InputCompletionPhase.EditingToken
    && String.Equals(
      target, actionID context.Prefix, StringComparison.OrdinalIgnoreCase)

  let private iterBodyCandidates registry state context =
    let context: InputContext = context
    let fullExpression = context.Expression
    let lastPipeline = InputAnalysis.topLevelLastPipeline fullExpression
    let segment =
      lastPipeline
      |> Option.map (fun index -> fullExpression[index + 2..])
      |> Option.defaultValue context.Segment
    let words = InputAnalysis.splitWords segment
    match words with
    | head :: _ when isIterHead head ->
      match tryIterTargetAction words with
      | None when isCurrentIterKeyword head context ->
        None
      | None ->
        iterActionCandidates registry state context context.Prefix |> Some
      | Some target when isCurrentIterAction target context ->
        iterActionCandidates registry state context context.Prefix |> Some
      | Some target ->
        match ActionRegistry.tryFind target registry with
        | None ->
          if context.Prefix.StartsWith("@", StringComparison.Ordinal) then
            iterActionCandidates registry state context context.Prefix |> Some
          else
            None
        | Some registered ->
          let itemKind =
            iterElementKind registry state context
          let lastIndex = context.InputBeforeCursor.Length - 1
          let endsWithSpace =
            context.InputBeforeCursor.Length > 0
            && Char.IsWhiteSpace context.InputBeforeCursor[lastIndex]
          match words |> List.tryFindIndex ((=) "->"), itemKind with
          | Some arrow, _ when hasClosedLambda arrow words ->
            Some []
          | Some arrow, Some kind ->
            let body =
              words
              |> List.skip (arrow + 1)
              |> splitAtLastSemicolon
            let prefix = context.Prefix
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
              let closing =
                if endsWithSpace then
                  closeLambdaCandidate registered.Metadata inputKind before
                else
                  []
              closing
              @ noArgumentCandidate registered.Metadata inputKind prefix
              @ candidates
            Some candidates
          | _, Some kind ->
            let inputKind = Some kind
            let afterTarget =
              match words with
              | _ :: _ :: rest -> rest
              | _ -> []
            match lambdaArgumentsBeforeArrow afterTarget with
            | None ->
              if not (hasNoArgumentSyntax registered.Metadata inputKind) then
                lambdaSkeletonCandidate |> Some
              elif context.Prefix.StartsWith("@", StringComparison.Ordinal) then
                iterActionCandidates registry state context context.Prefix
                |> Some
              else
                None
            | Some args ->
              let expected = expectedLambdaArgumentCount head
              if List.length args = expected && endsWithSpace then
                arrowCandidate registered.Metadata inputKind |> Some
              else
                Some []
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

  let private metaCommandCandidates prefix =
    metaCommands
    |> List.filter (fst >> matches prefix)
    |> List.map commandItem

  let private completeMeta (state: TransformerReplState) context =
    let context: InputContext = context
    let input = context.InputBeforeCursor
    let prefix = context.Prefix
    let words = context.Words
    if context.CompletionPhase = InputCompletionPhase.EditingToken
       && List.length words = 1 then
      metaCommandCandidates prefix
    else
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
          metaCommandCandidates prefix

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
        ReplTypeAnalysis.inputKind registry state expression
      | _ ->
        state.Current |> Option.map (fun value -> value.Kind)
    let completeArguments head completed argumentIndex =
      let inputKind = inputKindFor head
      argumentCandidates registry argumentState head completed argumentIndex
        inputKind context.Prefix
    match setContextListCandidates argumentState context with
    | Some candidates -> candidates
    | None ->
      match iterBodyCandidates registry argumentState context with
      | Some candidates -> candidates
      | None ->
        match literalBindingCandidates state expression context.Prefix with
        | Some candidates -> candidates
        | None ->
          match words with
          | [] ->
            if hasPipeline then
              let kind = ReplTypeAnalysis.inputKind registry state expression
              actionCandidates registry kind expected context.Prefix
              @ iterKeywordCandidates kind context.Prefix
            else
              initialCandidates registry state context.Prefix
                (not context.HasBinding) (not context.HasBinding) expected
          | [ head ] when endsWithSpace ->
            completeArguments head [] 0
          | [ _ ] when hasPipeline ->
            let kind = ReplTypeAnalysis.inputKind registry state expression
            let actions =
              actionCandidates registry kind expected context.Prefix
            let iterations = iterKeywordCandidates kind context.Prefix
            actions @ iterations
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

  let private expressionContext context (expression, _) =
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
      let start = commandStart + 5
      Some(input[start..], start)
    else
      None

  let private currentParameters metadata inputKind args endsWithSpace =
    match args with
    | [] -> []
    | _ ->
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

  let private directHintTarget registry state context head args =
    ActionRegistry.tryFind (actionID head) registry
    |> Option.map (fun registered ->
      let metadata = registered.Metadata
      let inputKind =
        if ActionMetadata.acceptedInputs metadata
           |> List.contains ReplValueKind.Unit then
          Some ReplValueKind.Unit
        elif context.HasPipeline then
          ReplTypeAnalysis.inputKind registry state context.Expression
        else
          state.Current |> Option.map (fun value -> value.Kind)
      registered, inputKind, args)

  let private iterHintArguments words =
    match words |> List.tryFindIndex ((=) "->") with
    | Some index ->
      words
      |> List.skip (index + 1)
      |> List.takeWhile ((<>) ")")
    | None ->
      []

  let private iterHintTarget registry state context words =
    tryIterTargetAction words
    |> Option.bind (fun target -> ActionRegistry.tryFind target registry)
    |> Option.map (fun registered ->
      let inputKind = iterElementKind registry state context
      registered, inputKind, iterHintArguments words)

  let private hintTarget registry state context =
    match context.SegmentWords with
    | head :: _ when isIterHead head ->
      iterHintTarget registry state context context.SegmentWords
    | head :: args ->
      directHintTarget registry state context head args
    | [] ->
      None

  let private completionHint registry state context =
    let context: InputContext = context
    hintTarget registry state context
    |> Option.map (fun (registered, inputKind, args) ->
      let metadata = registered.Metadata
      let signature =
        ActionMetadata.typedSignatureForLines metadata inputKind args
        |> String.concat "\n"
      let endsWithSpace =
        let segment = context.Segment
        segment.Length > 0
        && Char.IsWhiteSpace segment[segment.Length - 1]
      let highlight =
        currentParameters metadata inputKind args endsWithSpace
        |> highlightRanges signature
      signature, highlight)

  let private candidateFitsPhase context item =
    let context: InputContext = context
    match context.CompletionPhase with
    | InputCompletionPhase.StartingToken ->
      true
    | InputCompletionPhase.EditingToken ->
      matches context.Prefix item.Text
      && item.Form = SuggestionForm.Token

  let private isClosingDelimiter = function
    | ")" | "]" | "}" | "|]" -> true
    | _ -> false

  let private duplicatesClosingDelimiter (after: string) item =
    let item: SuggestionItem = item
    isClosingDelimiter item.Text
    && after.StartsWith(item.Text, StringComparison.Ordinal)

  let private prepareItems context items =
    let context: InputContext = context
    let after = context.InputAfterCursor.TrimStart()
    items
    |> List.filter (candidateFitsPhase context)
    |> List.filter (duplicatesClosingDelimiter after >> not)
    |> List.distinctBy (fun item -> item.Text)
    |> List.truncate 20

  let get registry (state: TransformerReplState) (input: string) cursor =
    let context = InputAnalysis.analyze input cursor
    let showExpression = showExpressionInput context.InputBeforeCursor
    let expressionContext =
      showExpression
      |> Option.map (expressionContext context)
      |> Option.defaultValue context
    let expression, expressionStart =
      match showExpression with
      | Some expression -> expression
      | None ->
        match ReplLanguage.bindingHeader context.InputBeforeCursor with
        | Some header when header.HasEquals ->
          let start = header.ExpressionStart |> Option.defaultValue 0
          context.InputBeforeCursor[start..], start
        | _ ->
          context.InputBeforeCursor, 0
    let diagnostics =
      ReplTypeAnalysis.analyze registry state expressionStart expression
      |> fun analysis -> analysis.Diagnostics
    match typeAnnotationCompletion context.InputBeforeCursor with
    | Some(items, start, length) ->
      { Items = prepareItems context items
        Start = start
        Length = length
        Hint = Some "type annotation"
        HintHighlights = []
        Diagnostics = [] }
    | None ->
      let hint = completionHint registry state expressionContext
      let items =
        if context.InputBeforeCursor.TrimStart().StartsWith ':' then
          match showExpression with
          | Some _ ->
            completeExpression registry state expressionContext
          | None ->
            completeMeta state context
        else
          completeExpression registry state expressionContext
      { Items =
          prepareItems context items
        Start = context.TokenStart
        Length = context.TokenLength
        Hint =
          diagnostics
          |> List.tryHead
          |> Option.map _.Message
          |> Option.orElse (hint |> Option.map fst)
        HintHighlights =
          if List.isEmpty diagnostics then
            hint |> Option.map snd |> Option.defaultValue []
          else
            []
        Diagnostics = diagnostics }
