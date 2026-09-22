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
      ":layout order=toggle", "Swap shell and suggestion panes"
      ":log", "Show detailed command execution records"
      ":needs", "List missing concrete execution context"
      ":plugin", "Load REPL actions from a plugin DLL"
      ":quit", "Leave the Transformer TUI"
      ":reset", "Clear values and reset the analysis state"
      ":restore", "Restore a value-history entry"
      ":script", "Save, load, or configure replay recording"
      ":type", "Show the current, named, or expression type"
      ":undo", "Undo the most recent value change"
      ":values", "Show retained value history" ]

  let commandPaletteCandidates (input: string) =
    let input = input.TrimStart()
    let input =
      if input.StartsWith ':' then input[1..] else input
    metaCommands
    |> List.map (fun (command, detail) -> command[1..], detail)
    |> List.filter (fun (command, _) ->
      command.StartsWith(input, StringComparison.OrdinalIgnoreCase))
    |> List.truncate 5

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
    ReplValueKind.toString (value: ReplValue).Kind

  let private bindingItem (name, value: ReplValue) =
    { Text = name
      Label = name
      Detail = valueTypeDescription value
      Kind = SuggestionKind.Binding
      AppendSpace = true
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
      | _ ->
        None
    | _ ->
      None

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
    | Some kind ->
      ReplValueKind.isCompatible value.Kind kind
    | None ->
      true

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
    | ReplValueKind.Array _ ->
      true
    | _ ->
      false

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
    | _ ->
      []

  let private initialCandidates
    registry
    state
    prefix
    includeLet
    includeCurrent
    expected =
    let state: TransformerReplState = state
    let keywords =
      if includeLet && matches prefix letItem.Text then
        [ letItem ]
      else
        []
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
      | "(" | "[" | "[|" ->
        token :: stack
      | ")" ->
        match stack with
        | "(" :: rest ->
          rest
        | _ ->
          stack
      | "]" ->
        match stack with
        | "[" :: rest ->
          rest
        | _ ->
          stack
      | "|]" ->
        match stack with
        | "[|" :: rest ->
          rest
        | _ ->
          stack
      | _ ->
        stack
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
    | _ ->
      None

  let private quotePath (path: string) =
    if path.Contains ' ' then $"\"{path}\"" else path

  let private normalizePath (path: string) =
    path.Replace('\\', '/')

  let private directoryEntries path =
    let fullPath = Path.GetFullPath path
    let lastWrite = Directory.GetLastWriteTimeUtc fullPath
    match directoryCache.TryGetValue fullPath with
    | true, cached when cached.LastWrite = lastWrite ->
      cached.Entries
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
    with _ ->
      []

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
        | :? Binary as binary ->
          Some binary
        | _ ->
          None))

  let private tryCurrentSlice (state: TransformerReplState) =
    state.Current
    |> Option.bind (fun value ->
      value.Collection.Values
      |> Array.tryPick (function
        | :? BinarySlice as slice ->
          Some slice
        | _ ->
          None))

  let private tryCurrentRequirements (state: TransformerReplState) =
    match state.LastNeeds with
    | Some needs ->
      Some needs
    | None ->
      state.Current
      |> Option.bind (fun value ->
        value.Collection.Values
        |> Array.tryPick (function
          | :? ContextRequirements as needs ->
            Some needs
          | _ ->
            None))

  let private sectionCandidates state prefix =
    try
      let sectionItems binary inside =
        let hdl = Binary.Handle binary
        BinFileOps.getSections hdl.File
        |> Array.filter (fun section -> section.FileSize > 0UL)
        |> Array.filter inside
        |> Array.choose (fun section ->
          if String.IsNullOrWhiteSpace section.Name then
            None
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
    with _ ->
      []

  let private binaryAddressCandidates state prefix =
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
                  if String.IsNullOrWhiteSpace section.Name then
                    "<unnamed>"
                  else
                    section.Name)
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
    with _ ->
      []

  let private observedAddressCandidates state prefix =
    TransformerReplState.findObservedAddresses prefix 20 state
    |> List.map (fun observation ->
      let text = $"0x{observation.Address:x}"
      let detail =
        $"command #{observation.CommandID} · {observation.Action}"
      argumentItem SuggestionKind.Argument detail text)

  let private observedHexValueCandidates state prefix =
    TransformerReplState.findObservedHexValues prefix 20 state
    |> List.map (fun observation ->
      let detail =
        $"command #{observation.CommandID} · {observation.Action}"
        + $" · {observation.Symbol}"
      argumentItem SuggestionKind.Argument detail observation.Text)

  let private addressCandidates state prefix =
    observedAddressCandidates state prefix
    @ binaryAddressCandidates state prefix

  let private hexLiteralCandidates state prefix =
    observedHexValueCandidates state prefix
    @ addressCandidates state prefix

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
        argumentItemWithSpacing
          SuggestionKind.Argument
          detail
          name
          (String.IsNullOrEmpty suffix))
    | None ->
      []

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
        argumentItemWithSpacing
          SuggestionKind.Argument
          detail
          text
          (String.IsNullOrEmpty suffix))
    | None ->
      []

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
            | _ :: rest ->
              rest
            | [] ->
              []
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
      valueCandidates
        SuggestionKind.Argument
        "register value"
        prefix
        [ "0x0"; "0x1"; "0xffffffffffffffff" ]
    | "mem" ->
      valueCandidates
        SuggestionKind.Argument
        "memory bytes"
        prefix
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
    | _ ->
      []

  let private isContextAction head =
    let id = actionID head
    id = "make-concrete-context" || id = "make-symbolic-context"

  let private setContextListCandidates state (context: InputContext) =
    match context.SegmentWords with
    | head :: _ when isContextAction head ->
      match innermostOpenBracket context.Segment with
      | None ->
        None
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
        | _ ->
          None
    | _ ->
      None

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

  let private expectedBindingKinds = function
    | ActionArgumentKind.Text
    | ActionArgumentKind.Path
    | ActionArgumentKind.ExistingPath
    | ActionArgumentKind.OutputPath
    | ActionArgumentKind.ISA
    | ActionArgumentKind.HexPattern
    | ActionArgumentKind.HexBytes
    | ActionArgumentKind.Section
    | ActionArgumentKind.Choice ->
      [ ReplValueKind.Text ]
    | ActionArgumentKind.Integer
    | ActionArgumentKind.Size ->
      [ ReplValueKind.Int ]
    | ActionArgumentKind.Float ->
      [ ReplValueKind.Float ]
    | ActionArgumentKind.Address ->
      [ ReplValueKind.Address ]
    | ActionArgumentKind.Action ->
      [ ReplValueKind.SymbSolver ]
    | ActionArgumentKind.ParameterFunction ->
      []

  let private argumentBindingCandidates state argument prefix =
    let argument: ActionArgument = argument
    let expected = expectedBindingKinds argument.Kind
    state.Bindings
    |> Map.toList
    |> List.filter (fun (name, value) ->
      matches prefix name
      && (expected
          |> List.exists (ReplValueKind.isCompatible value.Kind))
      && match value.Collection.Values with
         | [| item |] ->
           ReplValue.tryArgumentText item |> Option.isSome
         | _ ->
           false)
    |> List.map bindingItem

  let private tryParameterName (token: string) =
    let index = token.IndexOf '='
    if index <= 0 then
      None
    else
      let key = token[..index - 1]
      let typeIndex = key.IndexOf ':'
      let key = if typeIndex <= 0 then key else key[..typeIndex - 1]
      Some(key.ToLowerInvariant())

  let private isAttachedValuePrefix (segment: string) tokenStart =
    tokenStart > 0 && not (Char.IsWhiteSpace segment[tokenStart - 1])

  let private matchesArgumentName (name: string) argument =
    ActionMetadata.argumentKeys argument
    |> List.contains (name.ToLowerInvariant())

  let private isIterHead head =
    String.Equals(head, "iter", StringComparison.OrdinalIgnoreCase)
    || String.Equals(head, "iteri", StringComparison.OrdinalIgnoreCase)

  let private syntaxArguments metadata inputKind completed =
    let metadata: ActionMetadata = metadata
    let syntaxes =
      ActionMetadata.matchingSyntaxes metadata inputKind completed
    let triggered =
      match completed with
      | trigger :: _ ->
        syntaxes
        |> List.filter (fun syntax ->
          syntax.Trigger
          |> Option.exists (fun expected ->
            String.Equals(
              expected,
              trigger,
              StringComparison.OrdinalIgnoreCase
            )))
      | [] ->
        []
    let syntaxes =
      if List.isEmpty triggered then
        syntaxes |> List.filter (fun syntax -> syntax.Trigger.IsNone)
      else
        triggered
    let names = completed |> List.choose tryParameterName
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

  let private argumentNameCandidates
    registry
    metadata
    inputKind
    completed
    argumentIndex
    prefix =
    let metadata: ActionMetadata = metadata
    let arguments =
      syntaxArguments metadata inputKind completed
      |> List.distinctBy (fun argument -> argument.Name)
      |> List.filter (fun argument ->
        ActionMetadata.argumentKeys argument
        |> List.exists (fun key -> matches prefix (key + "=")))
      |> List.map argumentNameItem
    let candidates =
      triggerCandidates metadata inputKind argumentIndex prefix @ arguments
    candidates |> List.distinctBy (fun item -> item.Text)

  let private argumentCandidates
    registry
    state
    head
    completed
    argumentIndex
    inputKind
    prefix =
    match ActionRegistry.tryFind (actionID head) registry with
    | None ->
      []
    | Some registered ->
      let metadata = registered.Metadata
      argumentNameCandidates
        registry
        metadata
        inputKind
        completed
        argumentIndex
        prefix
      |> List.distinctBy (fun item -> item.Text)

  let private namedArgumentCandidates
    registry
    state
    head
    name
    inputKind
    completed
    prefix =
    match ActionRegistry.tryFind (actionID head) registry with
    | None ->
      []
    | Some registered ->
      let arguments =
        ActionMetadata.matchingSyntaxes registered.Metadata inputKind completed
        |> List.filter (ActionMetadata.syntaxHasParameter name)
        |> List.collect (fun syntax -> syntax.Arguments)
        |> List.distinctBy (fun argument -> argument.Name)
        |> List.filter (matchesArgumentName name)
      let bindings =
        arguments
        |> List.collect (fun argument ->
          argumentBindingCandidates state argument prefix)
      let semantic =
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
          arguments
          |> List.collect (fun argument ->
            semanticCandidates state argument prefix)
      bindings @ semantic |> List.distinctBy (fun item -> item.Text)

  let private splitAtLastSemicolon tokens =
    let rec loop depth current = function
      | [] ->
        List.rev current
      | ";" :: rest when depth = 0 ->
        loop 0 [] rest
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

  let private lambdaKeywordCandidate =
    [ { Text = "fun "
        Label = "fun "
        Detail = "start item-parameter function"
        Kind = SuggestionKind.Argument
        AppendSpace = false
        Form = SuggestionForm.SyntaxSnippet
        CursorOffset = None } ]

  let private hasNoArgumentSyntax metadata inputKind =
    let metadata: ActionMetadata = metadata
    metadata.Syntaxes
    |> List.exists (fun syntax ->
      ActionMetadata.syntaxAccepts inputKind syntax
      && List.isEmpty syntax.Arguments)

  let private arrowCandidate =
    [ { Text = "-> "
        Label = "-> "
        Detail = "start item action parameters"
        Kind = SuggestionKind.Argument
        AppendSpace = false
        Form = SuggestionForm.SyntaxSnippet
        CursorOffset = None } ]

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

  let private iterElementKind typeAnalysis =
    typeAnalysis.CurrentInput
    |> Option.bind ReplTypeAnalysis.collectionElementKind

  let private iterActionCandidates registry typeAnalysis prefix =
    match iterElementKind typeAnalysis with
    | Some kind ->
      actionCandidates registry (Some kind) None prefix
    | None ->
      []

  let private isCurrentIterKeyword head (context: InputContext) =
    String.Equals(head, context.Prefix, StringComparison.OrdinalIgnoreCase)

  let private isCurrentIterAction target (context: InputContext) =
    context.CompletionPhase = InputCompletionPhase.EditingToken
    && String.Equals(
      target,
      actionID context.Prefix,
      StringComparison.OrdinalIgnoreCase
    )

  let private fullSegmentWords context =
    let context: InputContext = context
    context.PartialPipeline
    |> Option.bind (fun pipeline ->
      if pipeline.HasTrailingPipeline then
        None
      else
        pipeline.Segments |> List.tryLast)
    |> Option.map _.Tokens
    |> Option.defaultValue context.SegmentWords

  let private iterBodyCandidates registry state context typeAnalysis =
    let context: InputContext = context
    let words = fullSegmentWords context
    match words with
    | head :: args when isIterHead head ->
      let analysis = ReplLanguage.analyzeIter head args
      match analysis.ActionID with
      | None when isCurrentIterKeyword head context ->
        None
      | None ->
        iterActionCandidates registry typeAnalysis context.Prefix
        |> Some
      | Some target when isCurrentIterAction target context ->
        iterActionCandidates registry typeAnalysis context.Prefix
        |> Some
      | Some target ->
        match ActionRegistry.tryFind target registry with
        | None ->
          if context.Prefix.StartsWith("@", StringComparison.Ordinal) then
            iterActionCandidates registry typeAnalysis context.Prefix
            |> Some
          else
            None
        | Some registered ->
          let itemKind = iterElementKind typeAnalysis
          let lastIndex = context.InputBeforeCursor.Length - 1
          let endsWithSpace =
            context.InputBeforeCursor.Length > 0
            && Char.IsWhiteSpace context.InputBeforeCursor[lastIndex]
          match analysis.HasArrow, itemKind with
          | true, _ when analysis.HasClosingDelimiter ->
            Some []
          | true, Some kind ->
            let body =
              analysis.Body |> splitAtLastSemicolon
            let prefix = context.Prefix
            let current =
              if endsWithSpace then None else body |> List.tryLast
            let before =
              if endsWithSpace then body else InputAnalysis.allButLast body
            let inputKind = Some kind
            let candidates =
              match current |> Option.bind tryParameterName with
              | Some name ->
                namedArgumentCandidates
                  registry
                  state
                  (ActionMetadata.actionName registered.Metadata.ID)
                  name
                  inputKind
                  before
                  prefix
              | None ->
                let index =
                  if endsWithSpace then
                    List.length body
                  else
                    max 0 (List.length body - 1)
                argumentNameCandidates
                  registry
                  registered.Metadata
                  inputKind
                  before
                  index
                  prefix
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
          | false, Some kind ->
            let inputKind = Some kind
            match analysis.LambdaParameters with
            | None ->
              if not (hasNoArgumentSyntax registered.Metadata inputKind) then
                if analysis.HasOpeningDelimiter
                   && not analysis.HasClosingDelimiter then
                  lambdaKeywordCandidate |> Some
                else
                  lambdaSkeletonCandidate |> Some
              elif context.Prefix.StartsWith("@", StringComparison.Ordinal) then
                iterActionCandidates registry typeAnalysis context.Prefix
                |> Some
              else
                None
            | Some args ->
              let expected = analysis.ExpectedParameterCount
              if List.length args = expected && endsWithSpace then
                arrowCandidate |> Some
              else
                Some []
          | _ ->
            None
    | _ ->
      None

  let private completeExpression registry state context typeAnalysis =
    let context: InputContext = context
    let expected = expectedOutput context.InputBeforeCursor
    let expression = context.Expression
    let segment = context.Segment
    let words = context.SegmentWords
    let hasPipeline = context.HasPipeline
    let endsWithSpace =
      segment.Length > 0 && Char.IsWhiteSpace segment[segment.Length - 1]
    let argumentState =
      context.PartialPipeline
      |> Option.bind (fun pipeline -> pipeline.Segments |> List.tryHead)
      |> Option.bind (fun segment -> segment.Tokens |> List.tryHead)
      |> Option.orElseWith (fun () ->
        InputAnalysis.splitPipeline expression
        |> List.tryHead
        |> Option.bind (InputAnalysis.splitWords >> List.tryHead))
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
        typeAnalysis.CurrentInput
      | _ ->
        state.Current |> Option.map (fun value -> value.Kind)
    let completeArguments head completed argumentIndex =
      let inputKind = inputKindFor head
      argumentCandidates
        registry
        argumentState
        head
        completed
        argumentIndex
        inputKind
        context.Prefix
    let literalHexCandidates =
      match words with
      | [ token ] when
          token = context.Prefix
          && token.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ->
        Some(hexLiteralCandidates state context.Prefix)
      | _ ->
        None
    let completeCurrent () =
      match words with
      | [] ->
        if hasPipeline then
          let kind = typeAnalysis.CurrentInput
          actionCandidates registry kind expected context.Prefix
          @ iterKeywordCandidates kind context.Prefix
        else
          initialCandidates
            registry
            state
            context.Prefix
            (not context.HasBinding)
            (not context.HasBinding)
            expected
      | [ head ] when endsWithSpace ->
        completeArguments head [] 0
      | [ _ ] when hasPipeline ->
        let kind = typeAnalysis.CurrentInput
        let actions = actionCandidates registry kind expected context.Prefix
        let iterations = iterKeywordCandidates kind context.Prefix
        actions @ iterations
      | [ _ ] ->
        initialCandidates
          registry
          state
          context.Prefix
          (not context.HasBinding)
          (not context.HasBinding)
          expected
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
            | _ :: completed ->
              completed
            | [] ->
              []
          namedArgumentCandidates
            registry
            argumentState
            head
            name
            inputKind
            completed
            context.Prefix
        | None ->
          let wordCount = List.length beforeWords
          let argumentIndex = max 0 (wordCount - 1)
          let completed =
            match beforeWords with
            | _ :: completed ->
              completed
            | [] ->
              []
          completeArguments head completed argumentIndex
    let completeLiteral () =
      literalHexCandidates
      |> Option.orElseWith (fun () ->
        literalBindingCandidates state expression context.Prefix)
      |> Option.defaultWith completeCurrent
    match setContextListCandidates argumentState context with
    | Some candidates ->
      candidates
    | None ->
      match iterBodyCandidates registry argumentState context typeAnalysis with
      | Some candidates ->
        candidates
      | None ->
        completeLiteral ()

  let private currentParameters metadata inputKind args endsWithSpace =
    match args with
    | [] ->
      []
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
      | Some argument ->
        [ argument ]
      | None ->
        let completed =
          if endsWithSpace then
            args
          else
            InputAnalysis.allButLast args
        let candidates =
          syntaxArguments metadata inputKind completed
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

  let private directHintTarget registry state typeAnalysis context head args =
    ActionRegistry.tryFind (actionID head) registry
    |> Option.map (fun registered ->
      let metadata = registered.Metadata
      let inputKind =
        if ActionMetadata.acceptedInputs metadata
           |> List.contains ReplValueKind.Unit then
          Some ReplValueKind.Unit
        elif context.HasPipeline then
          typeAnalysis.CurrentInput
        else
          state.Current |> Option.map (fun value -> value.Kind)
      registered, inputKind, args)

  let private iterHintTarget registry typeAnalysis words =
    match words with
    | head :: args ->
      let analysis = ReplLanguage.analyzeIter head args
      analysis.ActionID
      |> Option.bind (fun target -> ActionRegistry.tryFind target registry)
      |> Option.map (fun registered ->
        let inputKind = iterElementKind typeAnalysis
        registered, inputKind, analysis.Body)
    | [] ->
      None

  let private hintTarget registry state typeAnalysis context =
    let context: InputContext = context
    let words = fullSegmentWords context
    match words with
    | head :: _ when isIterHead head ->
      iterHintTarget registry typeAnalysis words
    | head :: args ->
      directHintTarget registry state typeAnalysis context head args
    | [] ->
      None

  let private completionHint registry state typeAnalysis context =
    let context: InputContext = context
    hintTarget registry state typeAnalysis context
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
    | ")" | "]" | "}" | "|]" ->
      true
    | _ ->
      false

  let private duplicatesClosingDelimiter (after: string) item =
    let item: SuggestionItem = item
    isClosingDelimiter item.Text
    && after.StartsWith(item.Text, StringComparison.Ordinal)

  let private needsParameterSeparator context =
    let context: InputContext = context
    let last = context.InputBeforeCursor.Length - 1
    context.CompletionPhase = InputCompletionPhase.StartingToken
    && context.InputBeforeCursor.Length > 0
    && not (Char.IsWhiteSpace context.InputBeforeCursor[last])

  let private prependParameterSeparator context item =
    let item: SuggestionItem = item
    if needsParameterSeparator context
       && item.Kind = SuggestionKind.Argument
       && item.Form = SuggestionForm.Token
       && item.Text.EndsWith("=", StringComparison.Ordinal) then
      { item with Text = " " + item.Text }
    else
      item

  let private prepareItems context items =
    let context: InputContext = context
    let after = context.InputAfterCursor.TrimStart()
    items
    |> List.filter (candidateFitsPhase context)
    |> List.filter (duplicatesClosingDelimiter after >> not)
    |> List.map (prependParameterSeparator context)
    |> List.distinctBy (fun item -> item.Text)
    |> List.truncate 20

  let private analyzeInput
    (previousContext: InputContext option)
    (registry: ActionRegistry)
    (state: TransformerReplState)
    (input: string)
    cursor =
    let cursor = max 0 (min cursor input.Length)
    let inputBeforeCursor =
      if cursor = 0 then
        ""
      else
        input[..cursor - 1]
    let context = InputAnalysis.analyzeWithCache previousContext input cursor
    let expression, expressionStart =
      match ReplLanguage.bindingHeader context.InputBeforeCursor with
      | Some header when header.HasEquals ->
        let start = header.ExpressionStart |> Option.defaultValue 0
        context.InputBeforeCursor[start..], start
      | _ ->
        context.InputBeforeCursor, 0
    let typeAnalysis =
      match context.PartialPipeline with
      | Some pipeline ->
        ReplTypeAnalysis.analyzePartial
          registry
          state
          expressionStart
          expression
          pipeline
      | None ->
        ReplTypeAnalysis.analyze registry state expressionStart expression
    context, typeAnalysis

  let getWithInputContext
    previousContext
    registry
    (state: TransformerReplState)
    (input: string)
    cursor =
    let context, typeAnalysis =
      analyzeInput previousContext registry state input cursor
    if context.InputBeforeCursor.TrimStart().StartsWith ':' then
      { Items =
          []
        Start = context.TokenStart
        Length = context.TokenLength
        Hint = None
        HintHighlights = []
        Diagnostics = [] }, context
    else
      let diagnostics = typeAnalysis.Diagnostics
      match typeAnnotationCompletion context.InputBeforeCursor with
      | Some(items, start, length) ->
        { Items = prepareItems context items
          Start = start
          Length = length
          Hint = Some "type annotation"
          HintHighlights = []
          Diagnostics = [] }, context
      | None ->
        let hint = completionHint registry state typeAnalysis context
        let items = completeExpression registry state context typeAnalysis
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
          Diagnostics = diagnostics }, context

  let get registry state input cursor =
    getWithInputContext None registry state input cursor |> fst
