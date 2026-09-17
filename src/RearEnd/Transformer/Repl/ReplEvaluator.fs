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
open System.Diagnostics
open System.Globalization
open System.IO
open System.Text
open System.Text.RegularExpressions
open System.Threading
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Lines rendered for the transcript, plus a deferred full rendering for view.
type ReplOutput =
  { Lines: string list
    FullLines: Lazy<string list> }

module ReplOutput =
  let ofLines lines =
    { Lines = lines
      FullLines = lazy lines }

  let ofLazy lines fullLines =
    { Lines = lines
      FullLines = fullLines }

/// The result of evaluating one interactive command.
type ReplEvaluation =
  | Continue of ActionRegistry * TransformerReplState * output: ReplOutput
  | Exit of ActionRegistry * TransformerReplState

module TransformerReplEvaluator =
  type private RenderMode =
    | Preview
    | Full

  type private ParsedArguments =
    { Positional: string list
      Named: Map<string, string option * string> }

  type private NormalizedSyntax =
    { Syntax: ActionSyntax
      Arguments: string list
      Assignments: (ActionArgument * string) list option }

  let private formatKind kind = ReplValueKind.toString kind

  let private normalizePath (path: string) =
    path.Replace('\\', '/')

  let [<Literal>] MaxPreviewTextLines = 256

  let [<Literal>] MaxPreviewCollectionItems = 128

  let private omittedLine omitted =
    $"{omitted} more lines omitted; use @write to save the value."

  let private renderedTextLimit = function
    | Preview -> Some MaxPreviewTextLines
    | Full -> None

  let private renderedCollectionLimit = function
    | Preview -> Some MaxPreviewCollectionItems
    | Full -> None

  let private splitTextForDisplay mode (text: string) =
    let normalized = text.Replace("\r\n", "\n")
    use reader = new StringReader(normalized)
    let lines = ResizeArray<string>()
    let limit = renderedTextLimit mode
    let mutable keepReading = true
    let mutable omitted = 0
    while keepReading do
      let line = reader.ReadLine()
      if isNull line then
        keepReading <- false
      elif limit |> Option.forall (fun limit -> lines.Count < limit) then
        lines.Add line
      else
        omitted <- omitted + 1
    if omitted > 0 then lines.Add(omittedLine omitted)
    lines |> Seq.toList

  let private ofOption error = function
    | Some value -> Ok value
    | None -> Error error

  let private firstDescriptionLine (description: string) =
    description.Split([| '\r'; '\n' |], StringSplitOptions.RemoveEmptyEntries)
    |> Array.tryHead
    |> Option.defaultValue ""
    |> fun line -> line.Trim()

  let private formatAction registered =
    let metadata = (registered: RegisteredAction).Metadata
    let name = ActionMetadata.actionName metadata.ID
    $"{name.PadRight 10} {ActionMetadata.typedSignature metadata}"

  let private actionDetails registered =
    let metadata = (registered: RegisteredAction).Metadata
    let summary = firstDescriptionLine metadata.Description
    let role = metadata.Role.ToString().ToLowerInvariant()
    let examples =
      metadata.Examples |> List.map (fun example -> $"  e.g. {example}")
    [ formatAction registered; $"  role: {role}. {summary}" ] @ examples

  let private typeDescription value =
    let kind = formatKind (value: ReplValue).Kind
    match value.Shape with
    | ReplValueShape.Tuple -> kind
    | ReplValueShape.List -> kind
    | ReplValueShape.Array -> kind
    | ReplValueShape.Collection -> kind
    | ReplValueShape.Scalar -> kind

  let private tryVertexRange (vertex: IVertex<LowUIRBasicBlock>) =
    try
      let internals = vertex.VData.Internals
      if internals.IsAbstract then
        None
      else
        let range = internals.Range
        Some(range.Min, range.Max + 1UL)
    with _ ->
      None

  let private foldRange ranges =
    ranges
    |> Array.fold (fun acc (start, finish) ->
      match acc with
      | None -> Some(start, finish)
      | Some(minimum, maximum) ->
        Some(min minimum start, max maximum finish)) None

  let private cfgRange entry (cfg: LowUIRCFG) =
    let ranges = cfg.Vertices |> Array.choose tryVertexRange
    let entryRanges =
      ranges |> Array.filter (fun (start, _) -> start >= entry)
    if Array.isEmpty entryRanges then foldRange ranges
    else foldRange entryRanges

  let private renderCFG index = function
    | CFG(entry, cfg, _) ->
      let label =
        match index with
        | Some index -> $"cfg #{index}"
        | None -> "cfg"
      let range =
        cfgRange entry cfg
        |> Option.map (fun (start, finish) ->
          $"0x{start:x}-0x{finish:x} (end exclusive)")
        |> Option.defaultValue "unknown"
      [ $"{label}"
        $"  entry: 0x{entry:x}"
        $"  range: {range}"
        $"  vertices: {cfg.Vertices.Length}"
        $"  edges: {cfg.Edges.Length}"
        $"  roots: {cfg.Roots.Length}"
        $"  exits: {cfg.Exits.Length}" ]
    | NoCFG error ->
      let label =
        match index with
        | Some index -> $"cfg #{index}"
        | None -> "cfg"
      [ $"{label}"
        $"  error: {error}" ]

  let private truncateByMode mode (values: 'a seq) =
    match renderedCollectionLimit mode with
    | Some limit -> values |> Seq.truncate limit
    | None -> values

  let private renderInstructionArray mode (values: Instruction[]) =
    let header = $"instruction array ({values.Length} values)"
    let visible = values |> truncateByMode mode |> Seq.toArray
    let lines =
      visible
      |> Array.map (fun value -> value.ToString())
      |> Array.toList
    let omitted = values.Length - visible.Length
    if omitted > 0 then header :: lines @ [ omittedLine omitted ]
    else header :: lines

  let private renderBinaryBytes bytes =
    let bytes: BinaryBytes = bytes
    [ bytes.ToString()
      $"  size: {bytes.Bytes.Length} bytes"
      $"  base: 0x{bytes.BaseAddress:x}"
      $"  isa: {bytes.ISA}" ]

  let private renderFingerprint fingerprint =
    let fingerprint: Fingerprint = fingerprint
    [ $"fingerprint ({List.length fingerprint.Patterns} patterns)"
      $"  n-gram: {fingerprint.NGramSize}"
      $"  window: {fingerprint.WindowSize}" ]
    @ (fingerprint.Patterns
       |> List.truncate 16
       |> List.map (fun (hash, position) -> $"  {hash:x2}@{position}"))

  let private renderClusterResult result =
    let result: ClusterResult = result
    let header = $"cluster result ({result.Clusters.Length} clusters)"
    let clusters =
      result.Clusters
      |> Array.mapi (fun index cluster ->
        $"  cluster #{index + 1}: {cluster.Length} values")
      |> Array.toList
    header :: clusters

  let private renderSlice slice =
    let slice: BinarySlice = slice
    [ slice.ToString()
      $"  source: {slice.Source}"
      $"  start: 0x{slice.StartAddress:x}"
      $"  end: 0x{slice.EndAddress:x}"
      $"  size: {slice.Size} bytes" ]

  let private renderSection section =
    let section: SectionInfo = section
    [ section.ToString()
      $"  address: 0x{section.Address:x}"
      $"  size: {section.Size} bytes"
      $"  file-size: {section.FileSize} bytes"
      $"  kind: {section.Kind}" ]

  let private renderFunction fn =
    let fn: FunctionInfo = fn
    let symbol = fn.Symbol |> Option.defaultValue "<none>"
    [ fn.ToString(); $"  entry: 0x{fn.Entry:x}"; $"  symbol: {symbol}" ]

  let private renderStringMatch stringMatch =
    let stringMatch: StringMatch = stringMatch
    [ stringMatch.ToString() ]

  let private formatBytes address (bytes: byte[]) =
    let hex = bytes |> Array.map (sprintf "%02x") |> String.concat " "
    let ascii =
      bytes
      |> Array.map (fun byte ->
        if byte >= 0x20uy && byte <= 0x7euy then char byte else '.')
      |> String
    $"0x{address:x}: {hex}  {ascii}"

  let private renderRegisterView view =
    let view: RegisterView = view
    let lines =
      view.Registers
      |> Array.map (fun reg -> $"  {reg.Name}= {reg.Value}")
      |> Array.toList
    $"registers pc=0x{view.PC:x}" :: lines

  let private renderMemoryView view =
    let view: MemoryView = view
    [ "memory"
      $"  {formatBytes view.Address view.Bytes}" ]

  let private renderMemoryDiff diff =
    let diff: MemoryDiff = diff
    match diff.Before, diff.After with
    | Some before, Some after when before = after ->
      [ $"  unchanged {formatBytes diff.Address after}" ]
    | Some before, Some after ->
      [ $"  before {formatBytes diff.Address before}"
        $"  after  {formatBytes diff.Address after}" ]
    | Some before, None ->
      [ $"  before {formatBytes diff.Address before}"
        "  after  <unreadable>" ]
    | None, Some after ->
      [ "  before <unreadable>"
        $"  after  {formatBytes diff.Address after}" ]
    | None, None ->
      [ "  before <unreadable>"
        "  after  <unreadable>" ]

  let private renderAccessBytes label addr bytes =
    match bytes with
    | Some bytes -> $"    {label} {formatBytes addr bytes}"
    | None -> $"    {label} <unreadable>"

  let private renderMemoryAccess access =
    let access: MemoryAccess = access
    let head =
      match access.Kind with
      | MemoryAccessKind.Read ->
        $"  read  at 0x{access.Instruction:x}"
      | MemoryAccessKind.Write ->
        $"  write at 0x{access.Instruction:x}"
    let head =
      head + $" addr=0x{access.Address:x} size={access.Size}"
    match access.Kind with
    | MemoryAccessKind.Read ->
      [ head
        renderAccessBytes "value " access.Address access.After ]
    | MemoryAccessKind.Write ->
      [ head
        renderAccessBytes "before" access.Address access.Before
        renderAccessBytes "after " access.Address access.After ]

  let private renderTrace trace =
    let trace: ExecutionTrace = trace
    let header =
      [ $"trace {trace.InstructionCount} executed instructions"
        $"  attempted: {trace.Instructions.Length}"
        $"  start: 0x{trace.Start:x}"
        $"  final-pc: 0x{trace.FinalPC:x}" ]
    let instructions =
      trace.Instructions
      |> Array.map (fun ins ->
        $"  0x{ins.Address:x}: {ins.Disassembly}")
      |> Array.toList
    let registers =
      if Array.isEmpty trace.RegisterDiffs then
        [ "registers: no visible changes" ]
      else
        "registers:"
        :: (trace.RegisterDiffs |> Array.toList |> List.map (fun line ->
          "  " + line))
    let accesses =
      if Array.isEmpty trace.MemoryAccesses then
        [ "memory accesses: none" ]
      else
        "memory accesses:"
        :: (trace.MemoryAccesses |> Array.toList |> List.collect
          renderMemoryAccess)
    let watch =
      if Array.isEmpty trace.MemoryDiffs then []
      else
        "memory watch:"
        :: (trace.MemoryDiffs |> Array.toList |> List.collect
          renderMemoryDiff)
    let stops =
      if Array.isEmpty trace.StopReasons then []
      else "stop-reasons:" :: (trace.StopReasons |> Array.toList
        |> List.map (fun reason -> "  " + reason))
    header @ instructions @ registers @ accesses @ watch @ stops

  let private renderRequirements needs =
    let needs: ContextRequirements = needs
    let target =
      match needs.EndAddress, needs.Count with
      | Some finish, _ -> $"0x{needs.Start:x}-0x{finish:x}"
      | None, Some count -> $"0x{needs.Start:x} count={count}"
      | None, None -> $"0x{needs.Start:x}"
    let header =
      [ $"context requirements for {target}"
        $"  registers: {needs.Registers.Length}"
        $"  memory: {needs.Memory.Length}" ]
    let registers =
      if Array.isEmpty needs.Registers then
        [ "required registers: none" ]
      else
        "required registers:"
        :: (needs.Registers |> Array.toList |> List.map (fun item ->
          $"  {item.Name} read at 0x{item.Address:x}  {item.Disassembly}"
          + $"  => @set-reg name={item.Name} value=<value>"))
    let memory =
      if Array.isEmpty needs.Memory then
        [ "required memory: none" ]
      else
        "required memory:"
        :: (needs.Memory |> Array.toList |> List.map (fun item ->
          match item.Address with
          | Some addr ->
            $"  0x{addr:x} size={item.Size} at 0x{item.At:x}"
            + $"  => @mem write addr=0x{addr:x} bytes=<hex>"
          | None ->
            $"  <unknown> size={item.Size} at 0x{item.At:x}"
            + $"  ({item.Reason})"))
    header @ registers @ memory

  let private renderAddressValue (value: AddressValue) =
    [ $"0x{value.Address:x}" ]

  let private ansiOfColor = function
    | NoColor -> ""
    | Red -> "\x1b[31m"
    | Green -> "\x1b[32m"
    | Yellow -> "\x1b[33m"
    | Blue -> "\x1b[34m"
    | DarkCyan -> "\x1b[36m"
    | DarkYellow -> "\x1b[33m"
    | RedHighlight -> "\x1b[37;41m"
    | GreenHighlight -> "\x1b[30;42m"

  let private renderOutString mode (output: OutString) =
    let reset = "\x1b[0m"
    let builder = StringBuilder()
    output.Render(fun color text ->
      match ansiOfColor color with
      | "" -> builder.Append text |> ignore
      | ansi ->
        builder.Append ansi |> ignore
        builder.Append text |> ignore
        builder.Append reset |> ignore)
    splitTextForDisplay mode (builder.ToString())

  let rec private renderObject mode index (value: obj) =
    match value with
    | null ->
      [ "()" ]
    | :? CFG as cfg ->
      renderCFG index cfg
    | :? BinaryBytes as bytes ->
      renderBinaryBytes bytes
    | :? (Instruction[]) as instructions ->
      renderInstructionArray mode instructions
    | :? TextArtifact as artifact ->
      splitTextForDisplay mode artifact.Content
    | :? string as text ->
      splitTextForDisplay mode text
    | :? OutString as output ->
      renderOutString mode output
    | :? Fingerprint as fingerprint ->
      renderFingerprint fingerprint
    | :? ClusterResult as result ->
      renderClusterResult result
    | :? BinarySlice as slice ->
      renderSlice slice
    | :? SectionInfo as section ->
      renderSection section
    | :? FunctionInfo as fn ->
      renderFunction fn
    | :? StringMatch as stringMatch ->
      renderStringMatch stringMatch
    | :? RegisterView as view ->
      renderRegisterView view
    | :? MemoryView as view ->
      renderMemoryView view
    | :? ExecutionTrace as trace ->
      renderTrace trace
    | :? ContextRequirements as needs ->
      renderRequirements needs
    | :? AddressValue as value ->
      renderAddressValue value
    | :? ConcExecutorValue as executor ->
      executor.SummaryLines
    | :? Array as values ->
      let header = $"{value.GetType().GetElementType().Name} array"
      let header = $"{header} ({values.Length} values)"
      let visible =
        values
        |> Seq.cast<obj>
        |> truncateByMode mode
        |> Seq.toList
      let lines =
        visible
        |> Seq.mapi (fun index value ->
          renderObject mode (Some(index + 1)) value)
        |> Seq.collect id
        |> Seq.toList
      let omitted = values.Length - visible.Length
      if omitted > 0 then header :: lines @ [ omittedLine omitted ]
      else header :: lines
    | value ->
      [ value.ToString() ]

  let private renderValue mode value =
    let value: ReplValue = value
    let values = value.Collection.Values
    let visible = values |> truncateByMode mode |> Seq.toArray
    let body =
      visible
      |> Array.mapi (fun index item ->
        let itemIndex = if value.IsCollection then Some(index + 1) else None
        renderObject mode itemIndex item)
      |> Array.toList
      |> List.collect id
    let omitted = values.Length - visible.Length
    let body =
      if omitted > 0 then body @ [ omittedLine omitted ] else body
    if value.IsCollection then
      $"{typeDescription value} ({values.Length} values)" :: body
    else
      body

  let private outputLines lines =
    ReplOutput.ofLines lines

  let private outputValue value =
    ReplOutput.ofLazy (renderValue Preview value)
      (lazy (renderValue Full value))

  let private continueWith registry state lines =
    Continue(registry, state, outputLines lines)

  let private continueValue registry state value =
    Continue(registry, state, outputValue value)

  let private describeValue name value =
    let count = value.Collection.Values.Length
    let description =
      if (value: ReplValue).IsCollection then
        $"{typeDescription value} ({count} values)"
      else
        typeDescription value
    match name with
    | Some name -> $"{name}: {description}"
    | None -> description

  let private suggestions registry kind =
    let actions = ActionRegistry.getApplicable kind registry
    if List.isEmpty actions || kind = ReplValueKind.Unit then []
    else "Available next actions:" :: List.map formatAction actions

  let private selectValue name state =
    match name with
    | Some name ->
      TransformerReplState.tryFind name state
      |> Option.map (fun value -> name, value)
      |> ofOption $"Unknown binding: {name}"
    | None ->
      state.Current
      |> Option.map (fun value -> "current value", value)
      |> ofOption "There is no current value."

  let private isHexString (value: string) =
    not (String.IsNullOrWhiteSpace value)
    && value.Length % 2 = 0
    && value |> Seq.forall Uri.IsHexDigit

  let private tryParseUInt64 (value: string) =
    let style, value =
      if value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        NumberStyles.HexNumber, value[2..]
      else
        NumberStyles.Integer, value
    match UInt64.TryParse(value, style, CultureInfo.InvariantCulture) with
    | true, number -> Some number
    | _ -> None

  let private isAddress (value: string) =
    if value.StartsWith '+' then
      false
    else
      match tryParseUInt64 value with
      | Some _ -> true
      | None -> false

  let private isSize (value: string) =
    if value.StartsWith "+0x" then isAddress value[1..]
    elif value.StartsWith '+' then
      match tryParseUInt64 value[1..] with
      | Some size -> size > 0UL
      | None -> false
    else
      match tryParseUInt64 value with
      | Some size -> size > 0UL
      | None -> false

  let private isInteger (value: string) =
    if value.StartsWith '+' then
      false
    else
      let style, value =
        if value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
          NumberStyles.HexNumber, value[2..]
        else
          NumberStyles.Integer, value
      match Int32.TryParse(value, style, CultureInfo.InvariantCulture) with
      | true, _ -> true
      | _ -> false

  let private isFloat (value: string) =
    let style = NumberStyles.Float
    match Double.TryParse(value, style, CultureInfo.InvariantCulture) with
    | true, _ -> true
    | _ ->
      match Double.TryParse value with
      | true, _ -> true
      | _ -> false

  let private isISA (value: string) =
    try
      ISA value |> ignore
      true
    with _ -> false

  let private isRegex (value: string) =
    try
      Regex value |> ignore
      true
    with :? ArgumentException -> false

  let private isPath (value: string) =
    if String.IsNullOrWhiteSpace value then
      false
    else
      try
        Path.GetFullPath value |> ignore
        true
      with _ -> false

  let private sectionExists input sectionName =
    let sectionInsideSlice (slice: BinarySlice) section =
      let section: BinSection = section
      let finish = section.Address + section.FileSize
      section.Address >= slice.StartAddress && finish <= slice.EndAddress
    (input: ReplValue).Collection.Values
    |> Array.exists (function
      | :? Binary as binary ->
        let file = (Binary.Handle binary).File
        BinFileOps.tryFindSectionByName file sectionName |> Result.isOk
      | :? BinarySlice as slice ->
        let file = (Binary.Handle slice.Source).File
        match BinFileOps.tryFindSectionByName file sectionName with
        | Ok section -> sectionInsideSlice slice section
        | Error _ -> false
      | _ -> false)

  let private validateArgument input argument value =
    let argument: ActionArgument = argument
    let valid, expected =
      match argument.Kind with
      | ActionArgumentKind.Text ->
        not (String.IsNullOrWhiteSpace value), "non-empty text"
      | ActionArgumentKind.Path ->
        isPath value, "a valid path"
      | ActionArgumentKind.ExistingPath ->
        File.Exists value || Directory.Exists value, "an existing path"
      | ActionArgumentKind.OutputPath ->
        isPath value, "a valid output path"
      | ActionArgumentKind.ISA ->
        isISA value, "a supported ISA name"
      | ActionArgumentKind.Integer ->
        isInteger value, "a 32-bit integer (0x... hex or decimal)"
      | ActionArgumentKind.Float ->
        isFloat value, "a floating-point number"
      | ActionArgumentKind.HexPattern ->
        isRegex value, "a valid hexadecimal regular expression"
      | ActionArgumentKind.HexBytes ->
        isHexString value, "even-length hexadecimal bytes"
      | ActionArgumentKind.Address ->
        isAddress value, "an address (0x... hex or decimal)"
      | ActionArgumentKind.Size ->
        isSize value, "a positive size (0x... hex or decimal)"
      | ActionArgumentKind.Section ->
        sectionExists input value, "a section in the current binary"
      | ActionArgumentKind.Action ->
        not (String.IsNullOrWhiteSpace value), "an action reference"
      | ActionArgumentKind.ParameterFunction ->
        not (String.IsNullOrWhiteSpace value),
        "a parameter function"
      | ActionArgumentKind.Choice ->
        List.contains value argument.Choices,
        String.concat "|" argument.Choices
    if valid then Ok()
    else Error $"{argument.Name} must be {expected}; received '{value}'."

  let private tryNamedArgument (value: string) =
    let index = value.IndexOf '='
    if index <= 0 then None
    else
      let key = value[..index - 1].Trim()
      let key, annotation =
        let index = key.IndexOf ':'
        if index <= 0 then key, None
        else key[..index - 1], Some key[index + 1..]
      let value = value[index + 1..]
      if String.IsNullOrWhiteSpace key then None
      else Some(key.ToLowerInvariant(), annotation, value)

  let private bindingText (state: TransformerReplState) name =
    state.Bindings
    |> Map.tryFind name
    |> Option.bind (fun value ->
      match value.Collection.Values with
      | [| :? AddressValue as value |] -> Some $"0x{value.Address:x}"
      | [| :? int as value |] -> Some(string value)
      | [| :? string as value |] -> Some value
      | _ -> None)

  let private resolveAssignmentValue state (token: string) =
    let index = token.IndexOf '='
    if index <= 0 then token
    else
      let lhs = token[..index - 1].Trim()
      let rhs = token[index + 1..].Trim()
      let lhs = bindingText state lhs |> Option.defaultValue lhs
      let rhs = bindingText state rhs |> Option.defaultValue rhs
      lhs + "=" + rhs

  let private resolveArgumentBindings state args =
    args |> List.map (resolveAssignmentValue state)

  let private joinBracketValue opener rest =
    let rec loop depth output = function
      | [] -> None
      | token :: tail ->
        let depth = InputAnalysis.updateDepth depth token
        let output = token :: output
        if depth = 0 then
          Some(List.rev output, tail)
        else
          loop depth output tail
    loop 1 [ opener ] rest

  let private compactBracketArguments args =
    let rec loop output = function
      | token :: "[" :: rest
          when token.EndsWith("=", StringComparison.Ordinal) ->
        match joinBracketValue "[" rest with
        | Some(value, tail) ->
          let value = value |> String.concat " "
          loop ((token + value) :: output) tail
        | None -> (List.rev output) @ (token :: "[" :: rest)
      | token :: rest -> loop (token :: output) rest
      | [] -> List.rev output
    loop [] args

  let private typeAliases argument =
    let argument: ActionArgument = argument
    let primary = ActionMetadata.argumentKindName argument.Kind
    let aliases =
      match argument.Kind with
      | ActionArgumentKind.Text
      | ActionArgumentKind.Path
      | ActionArgumentKind.ExistingPath
      | ActionArgumentKind.OutputPath
      | ActionArgumentKind.ISA
      | ActionArgumentKind.Section
      | ActionArgumentKind.Action
      | ActionArgumentKind.ParameterFunction
      | ActionArgumentKind.Choice -> [ "String" ]
      | ActionArgumentKind.Integer -> [ "Integer" ]
      | ActionArgumentKind.Size -> [ "Integer" ]
      | _ -> []
    primary :: aliases

  let private annotationMatches argument annotation =
    typeAliases argument
    |> List.exists (fun alias ->
      String.Equals(alias, annotation, StringComparison.OrdinalIgnoreCase))

  let private parseArguments args =
    let folder result value =
      result
      |> Result.bind (fun parsed ->
        match tryNamedArgument value with
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

  let private equalsIgnoreCase left right =
    String.Equals(left, right, StringComparison.OrdinalIgnoreCase)

  let private positionalArgumentsAllowed parsed syntax =
    let parsed: ParsedArguments = parsed
    let syntax: ActionSyntax = syntax
    let positional = parsed.Positional
    let arguments = List.truncate (List.length positional) syntax.Arguments
    List.length arguments = List.length positional
    && arguments
       |> List.forall (fun argument ->
         argument.Kind = ActionArgumentKind.Action)

  let private tryTakeTrigger parsed syntax =
    let syntax: ActionSyntax = syntax
    match syntax.Trigger with
    | None -> Some parsed
    | Some expected ->
      match parsed.Positional with
      | actual :: rest when equalsIgnoreCase actual expected ->
        Some { parsed with Positional = rest }
      | _ -> None

  let private tryFindNamed named argument =
    ActionMetadata.argumentKeys argument
    |> List.tryPick (fun key ->
      Map.tryFind key named |> Option.map (fun value -> key, value))

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
        | Some annotation when not (annotationMatches argument annotation) ->
          let expected = ActionMetadata.argumentKindName argument.Kind
          Error $"{argument.Name} is {expected}, not {annotation}."
        | _ ->
          fillArguments positional (Map.remove key named) rest
            (value :: output) ((argument, value) :: assignments)
      | None ->
        match positional with
        | value :: tail ->
          fillArguments tail named rest (value :: output)
            ((argument, value) :: assignments)
        | [] when argument.IsOptional ->
          fillArguments [] named rest output assignments
        | [] ->
          Error $"missing parameter: {argument.Name}."

  let private normalizeSyntax parsed syntax =
    let addTrigger args =
      match (syntax: ActionSyntax).Trigger with
      | Some trigger -> trigger :: args
      | None -> args
    tryTakeTrigger parsed syntax
    |> Option.map (fun parsed ->
      if not (List.isEmpty parsed.Positional)
         && not (positionalArgumentsAllowed parsed syntax) then
        Error "positional arguments are not supported; use name=value."
      elif Map.isEmpty parsed.Named then
        Ok
          { Syntax = syntax
            Arguments = addTrigger parsed.Positional
            Assignments = None }
      else
        fillArguments parsed.Positional parsed.Named syntax.Arguments [] []
        |> Result.map (fun (args, assignments) ->
          { Syntax = syntax
            Arguments = addTrigger args
            Assignments = Some assignments }))

  let private matchesArity (candidate: NormalizedSyntax) =
    let args =
      match candidate.Syntax.Trigger, candidate.Arguments with
      | Some _, _ :: rest -> rest
      | _ -> candidate.Arguments
    let required =
      candidate.Syntax.Arguments
      |> List.filter (fun argument -> not argument.IsOptional)
      |> List.length
    let maximum = List.length candidate.Syntax.Arguments
    List.length args >= required && List.length args <= maximum

  let private validateSyntax input (candidate: NormalizedSyntax) =
    let pairs =
      match candidate.Assignments with
      | Some assignments -> assignments
      | None ->
        let args =
          match candidate.Syntax.Trigger, candidate.Arguments with
          | Some _, _ :: rest -> rest
          | _ -> candidate.Arguments
        List.zip
          (List.truncate (List.length args) candidate.Syntax.Arguments)
          args
    pairs
    |> List.map (fun (argument, value) -> validateArgument input argument value)
    |> List.tryFind Result.isError
    |> Option.defaultValue (Ok())

  let private canonicalArgumentValue argument (value: string) =
    let argument: ActionArgument = argument
    match argument.Kind with
    | ActionArgumentKind.Size
        when not (value.StartsWith '+') -> "+" + value
    | _ -> value

  let private canonicalArguments candidate =
    let candidate: NormalizedSyntax = candidate
    let rec loop output arguments values =
      match arguments, values with
      | argument :: arguments, value :: values ->
        let value = canonicalArgumentValue argument value
        loop (value :: output) arguments values
      | _, [] -> List.rev output
      | [], values -> List.rev output @ values
    match candidate.Syntax.Trigger, candidate.Arguments with
    | Some trigger, actual :: values when equalsIgnoreCase trigger actual ->
      trigger :: loop [] candidate.Syntax.Arguments values
    | _ ->
      loop [] candidate.Syntax.Arguments candidate.Arguments

  let private invalidArguments (metadata: ActionMetadata) detail =
    let signature = ActionMetadata.typedSignature metadata
    Error(
      $"Invalid arguments for {metadata.ID}: {detail} "
      + $"Expected: {signature}")

  let private validateArguments (input: ReplValue)
                                (metadata: ActionMetadata) args =
    match parseArguments args with
    | Error message -> invalidArguments metadata message
    | Ok parsed ->
      let matching =
        metadata.Syntaxes
        |> List.filter (ActionMetadata.syntaxAccepts (Some input.Kind))
        |> List.filter (ActionMetadata.syntaxMatchesParameters args)
        |> List.choose (normalizeSyntax parsed)
      if List.isEmpty matching then
        let operations =
          metadata.Syntaxes
          |> List.choose (fun syntax -> syntax.Trigger)
          |> List.distinct
        let detail =
          match operations with
          | [] -> "the argument layout is invalid."
          | operations ->
            let choices = String.concat "|" operations
            $"operation must be one of {choices}."
        invalidArguments metadata detail
      else
        let matching =
          matching
          |> List.choose (function
            | Ok candidate when matchesArity candidate -> Some(Ok candidate)
            | Ok _ -> None
            | Error error -> Some(Error error))
        if List.isEmpty matching then
          invalidArguments metadata "the number of arguments does not match."
        else
          let results =
            matching
            |> List.map (function
              | Ok candidate ->
                validateSyntax input candidate |> Result.map (fun () ->
                  canonicalArguments candidate)
              | Error error -> Error error)
          match results |> List.tryFind Result.isOk with
          | Some(Ok normalizedArgs) -> Ok normalizedArgs
          | _ ->
            results
            |> List.choose (function Error error -> Some error | Ok _ -> None)
            |> List.distinct
            |> List.tryHead
            |> Option.defaultValue "the argument layout is invalid."
            |> invalidArguments metadata

  let private isActionReference (head: string) =
    head.StartsWith("@", StringComparison.Ordinal) && head.Length > 1

  let private actionID (head: string) =
    if isActionReference head then head[1..] else head

  let private tryFindAction registry head =
    ActionRegistry.tryFind (actionID head) registry

  type private BatchSpec =
    { ActionID: string
      ItemName: string
      IndexName: string
      Body: string list }

  let private isValidLambdaParameter (name: string) =
    if name = "_" then
      true
    elif String.IsNullOrWhiteSpace name then
      false
    else
      let first = Char.IsLetter name[0] || name[0] = '_'
      first
      && name
         |> Seq.skip 1
         |> Seq.forall (fun chr -> Char.IsLetterOrDigit chr || chr = '_')

  let private tryTakeNamedParameter (names: string list) tokens =
    let names = names |> List.map (fun name -> name.ToLowerInvariant())
    let rec loop before = function
      | [] -> None
      | token :: rest ->
        match tryNamedArgument token with
        | Some(key, _, value) when List.contains key names ->
          let valueTokens =
            if String.IsNullOrEmpty value then rest else value :: rest
          Some(List.rev before, valueTokens)
        | _ ->
          loop (token :: before) rest
    loop [] tokens

  let private parseBatchAction tokens =
    parseArguments tokens
    |> Result.bind (fun parsed ->
      let named = Map.tryFind "action" parsed.Named |> Option.map snd
      match named, parsed.Positional with
      | Some action, [] -> Ok action
      | None, [ action ] -> Ok action
      | None, [] -> Error "batch requires an action parameter."
      | Some _, _ ->
        Error "batch action must not be mixed with positional arguments."
      | None, _ ->
        Error "batch expects exactly one action before the params function.")
    |> Result.map actionID

  let private trimEnclosed openToken closeToken tokens =
    match tokens with
    | first :: rest when first = openToken ->
      match List.rev rest with
      | last :: body when last = closeToken -> List.rev body
      | _ -> tokens
    | _ -> tokens

  let private mergeSeparatedEquals tokens =
    let rec loop output = function
      | key :: "=" :: value :: rest ->
        loop ($"{key}={value}" :: output) rest
      | token :: rest ->
        loop (token :: output) rest
      | [] ->
        List.rev output
    loop [] tokens

  let private normalizeBatchBody tokens =
    tokens
    |> trimEnclosed "{" "}"
    |> mergeSeparatedEquals

  let private parseBatchLambda tokens =
    let tokens = trimEnclosed "(" ")" tokens
    match tokens with
    | "fun" :: itemName :: indexName :: "->" :: body
      when isValidLambdaParameter itemName
           && isValidLambdaParameter indexName ->
      Ok
        { ItemName = itemName
          IndexName = indexName
          Body = normalizeBatchBody body
          ActionID = "" }
    | "fun" :: _ ->
      Error "batch params must be: fun item index -> <action-parameters>."
    | _ ->
      Error "batch params must be a function: fun item index -> ..."

  let private parseBatchSpec args =
    match tryTakeNamedParameter [ "params" ] args with
    | Some(actionTokens, parameterTokens) ->
      parseBatchAction actionTokens
      |> Result.bind (fun action ->
        parseBatchLambda parameterTokens
        |> Result.map (fun spec -> { spec with ActionID = action }))
    | None ->
      match args with
      | action :: parameterTokens ->
        parseBatchAction [ action ]
        |> Result.bind (fun action ->
          parseBatchLambda parameterTokens
          |> Result.map (fun spec -> { spec with ActionID = action }))
      | [] ->
        Error "batch requires an action and a params function."

  let private replaceTemplate name replacement (text: string) =
    if name = "_" then
      text
    else
      text.Replace("{" + name + "}", replacement)

  let private splitBatchStatements tokens =
    let rec loop depth current statements = function
      | [] ->
        List.rev (List.rev current :: statements)
        |> List.filter (fun statement -> not (List.isEmpty statement))
      | ";" :: rest when depth = 0 ->
        loop depth [] (List.rev current :: statements) rest
      | token :: rest ->
        loop (InputAnalysis.updateDepth depth token) (token :: current)
          statements rest
    loop 0 [] [] tokens

  let private tryLocalBinding tokens =
    match mergeSeparatedEquals tokens with
    | "let" :: name :: valueTokens when name.Contains "=" ->
      let index = name.IndexOf '='
      let name, value = name[..index - 1], name[index + 1..]
      if List.isEmpty valueTokens then Some(name, [ value ])
      else Some(name, value :: valueTokens)
    | "let" :: name :: "=" :: valueTokens when not (List.isEmpty valueTokens) ->
      Some(name, valueTokens)
    | _ -> None

  let private applyLocalBindings (bindings: (string * string) list)
                                 (token: string) =
    let replaceBinding (text: string) (name: string, value: string) =
      let text = text.Replace("{" + name + "}", value)
      let index = text.IndexOf '='
      if index < 0 then
        if text = name then value else text
      else
        let prefix = text[..index]
        let suffix = text[index + 1..]
        if suffix = name then prefix + value else text
    bindings |> List.fold replaceBinding token

  let private batchArguments (spec: BatchSpec) (index: int) (item: obj) =
    let itemText = if isNull item then "" else item.ToString()
    let indexText = index.ToString(CultureInfo.InvariantCulture)
    let apply token =
      token
      |> replaceTemplate (spec: BatchSpec).ItemName itemText
      |> replaceTemplate spec.IndexName indexText
      |> fun text -> text.Replace("{index}", indexText)
    let statements = splitBatchStatements spec.Body
    let folder result statement =
      result
      |> Result.bind (fun (bindings, body) ->
        if not (List.isEmpty body) then
          Error "batch params can have only one final parameter expression."
        else
          match tryLocalBinding statement with
          | Some(name, valueTokens) ->
            let value =
              valueTokens
              |> List.map apply
              |> String.concat " "
              |> applyLocalBindings bindings
            Ok((name, value) :: bindings, [])
          | None ->
            let body =
              statement
              |> List.map apply
              |> List.map (applyLocalBindings bindings)
              |> mergeSeparatedEquals
            Ok(bindings, body))
    statements
    |> List.fold folder (Ok([], []))
    |> Result.map snd

  let private singletonValue item =
    ReplValue.ofCollection ReplValueKind.Any { Values = [| item |] }

  let private batchOutputKind kinds =
    let rec elementKind = function
      | ReplValueKind.Collection kind
      | ReplValueKind.List kind
      | ReplValueKind.Array kind -> kind
      | kind -> kind
    kinds
    |> List.tryFind (fun kind -> kind <> ReplValueKind.Unit)
    |> Option.map (elementKind >> ReplValueKind.Collection)
    |> Option.defaultValue ReplValueKind.Unit

  let private transform registered input segment
                        (cancellationToken: CancellationToken) =
    let registered: RegisteredAction = registered
    let segment: ReplPipelineSegment = segment
    cancellationToken.ThrowIfCancellationRequested()
    let action = registered.Action :?> ICancellableAction
    let collection =
      action.Transform(segment.Arguments, input.Collection, cancellationToken)
    cancellationToken.ThrowIfCancellationRequested()
    collection

  let rec private invoke registry state (registered: RegisteredAction)
                          (input: ReplValue) (segment: ReplPipelineSegment)
                          cancellationToken =
    let metadata = registered.Metadata
    if metadata.ID = "print" then
      Error "The print action is unavailable in the REPL; use :show instead."
    elif
      ActionMetadata.acceptedInputs metadata
      |> List.exists (ReplValueKind.isCompatible input.Kind)
      |> not
    then
      let actual = formatKind input.Kind
      let expected =
        ActionMetadata.acceptedInputs metadata
        |> List.map formatKind
        |> String.concat " | "
      match metadata.ID, input.Kind with
      | "save", ReplValueKind.Collection _
      | "save", ReplValueKind.List _
      | "save", ReplValueKind.Array _ ->
        Error "save expects one Binary; use batch to save collection items."
      | _ ->
        Error $"{metadata.ID} expects {expected}, but received {actual}."
    elif metadata.ID = "batch" then
      invokeBatch registry state input segment cancellationToken
    elif metadata.ID = "set-context" then
      let args =
        segment.Arguments
        |> resolveArgumentBindings state
        |> compactBracketArguments
      let segment = { segment with Arguments = args }
      try
        transform registered input segment cancellationToken
        |> ReplValue.ofCollection ReplValueKind.ConcExecutor
        |> Ok
      with
      | :? OperationCanceledException -> reraise ()
      | error -> Error error.Message
    else
      let args =
        segment.Arguments
        |> resolveArgumentBindings state
        |> compactBracketArguments
      validateArguments input metadata args
      |> Result.bind (fun normalizedArgs ->
      try
        let rawArgs = args
        let segment = { segment with Arguments = normalizedArgs }
        let outputKind =
          ActionMetadata.outputForArguments metadata (Some input.Kind)
            rawArgs
        transform registered input segment cancellationToken
        |> ReplValue.ofCollection outputKind
        |> Ok
      with
      | :? OperationCanceledException -> reraise ()
      | error -> Error error.Message)

  and private invokeBatch registry state input segment cancellationToken =
    let output = ResizeArray<obj>()
    let outputKinds = ResizeArray<ReplValueKind>()
    parseBatchSpec segment.Arguments
    |> Result.bind (fun spec ->
      match tryFindAction registry spec.ActionID with
      | None ->
        Error $"Unknown batch action: {spec.ActionID}"
      | Some registered when registered.Metadata.ID = "batch" ->
        Error "batch cannot invoke batch recursively."
      | Some registered ->
        let values = input.Collection.Values
        let rec loop index =
          if index >= values.Length then
            let kind = outputKinds |> Seq.toList |> batchOutputKind
            let collection = { Values = output.ToArray() }
            ReplValue.ofCollection kind collection |> Ok
          else
            cancellationToken.ThrowIfCancellationRequested()
            let item = values[index]
            match batchArguments spec index item with
            | Error message ->
              Error $"batch item {index}: {message}"
            | Ok arguments ->
              let segment =
                { Head = ActionMetadata.actionName registered.Metadata.ID
                  Arguments = arguments }
              match
                invoke registry state registered (singletonValue item) segment
                  cancellationToken
              with
              | Error message ->
                Error $"batch item {index}: {message}"
              | Ok value ->
                if value.Kind <> ReplValueKind.Unit then
                  outputKinds.Add value.Kind
                  output.AddRange value.Collection.Values
                loop (index + 1)
        loop 0)

  let private splitLiteralElements separator tokens =
    ReplLanguage.splitTopLevelStrict separator tokens

  let private scalarObject name (value: ReplValue) =
    if value.Collection.Values.Length = 1 then
      Ok value.Collection.Values[0]
    else
      Error $"Literal element must be a scalar value: {name}"

  let private resolveLiteralElement state eval tokens =
    match tokens with
    | [ name ] ->
      match TransformerReplState.tryFind name state with
      | Some value -> scalarObject name value
      | None ->
        TransformerReplParser.parsePipelineTokens tokens
        |> Result.bind eval
        |> Result.bind (scalarObject name)
    | [] ->
      Error "Empty literal element."
    | _ ->
      TransformerReplParser.parsePipelineTokens tokens
      |> Result.bind eval
      |> Result.bind (scalarObject (String.concat " " tokens))

  let private resolveLiteralElements state eval separator tokens =
    splitLiteralElements separator tokens
    |> Result.bind (List.fold (fun result tokens ->
      result
      |> Result.bind (fun values ->
        resolveLiteralElement state eval tokens
        |> Result.map (fun value -> value :: values))) (Ok []))
    |> Result.map (List.rev >> List.toArray)

  let private tryTrimmedLiteral closeToken tokens =
    match List.rev tokens with
    | token :: body when token = closeToken -> Some(List.rev body)
    | _ -> None

  let private validateLiteralSeparators separator tokens =
    let invalid =
      if separator = ";" then "," else ";"
    if List.contains invalid tokens then
      Error $"Use '{separator}' to separate literal elements."
    else
      Ok tokens

  let private tryLiteral state eval segment =
    let tokens = segment.Head :: segment.Arguments
    match tokens with
    | "(" :: rest ->
      match tryTrimmedLiteral ")" rest with
      | Some [] -> Ok(Some ReplValue.emptyInput)
      | Some body when List.contains "," body ->
        body
        |> validateLiteralSeparators ","
        |> Result.bind (resolveLiteralElements state eval ",")
        |> Result.map (ReplValue.ofTuple >> Some)
      | Some _ -> Ok None
      | None -> Ok None
    | "[" :: rest ->
      match tryTrimmedLiteral "]" rest with
      | Some body ->
        body
        |> validateLiteralSeparators ";"
        |> Result.bind (resolveLiteralElements state eval ";")
        |> Result.map (ReplValue.ofList >> Some)
      | None -> Ok None
    | "[|" :: rest ->
      match tryTrimmedLiteral "|]" rest with
      | Some body ->
        body
        |> validateLiteralSeparators ";"
        |> Result.bind (resolveLiteralElements state eval ";")
        |> Result.map (ReplValue.ofArray >> Some)
      | None -> Ok None
    | _ ->
      Ok None

  let private runRemaining registry state initial segments cancellationToken =
    segments
    |> List.fold (fun result segment ->
      result
      |> Result.bind (fun input ->
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
      | Error message -> Error message
      | Ok(Some value) ->
        runRemaining registry state value rest cancellationToken
      | Ok None ->
        let binding =
          if isActionReference first.Head || not (List.isEmpty first.Arguments)
          then None
          else TransformerReplState.tryFind first.Head state
        match binding with
        | Some value ->
          runRemaining registry state value rest cancellationToken
        | None ->
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

  let private fail registry state message =
    let state = TransformerReplState.setError message state
    continueWith registry state [ $"Error: {message}" ]

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

  let private evaluate includeSuggestions registry state segments binding
                       expected command cancellationToken =
    match runPipeline registry state segments cancellationToken with
    | Error message ->
      fail registry state message
    | Ok value ->
      match validateOutput expected value with
      | Error message ->
        fail registry state message
      | Ok value ->
        let state =
          TransformerReplState.setValue binding value state
          |> TransformerReplState.recordReplayCommand command
        let output =
          if includeSuggestions then
            describeValue binding value :: suggestions registry value.Kind
          else
            [ describeValue binding value ]
        continueWith registry state output

  let private show registry state name =
    match selectValue name state with
    | Error message ->
      fail registry state message
    | Ok(_, value) ->
      continueValue registry state value

  let private showExpression registry state segments cancellationToken =
    match runPipeline registry state segments cancellationToken with
    | Error message ->
      fail registry state message
    | Ok value ->
      continueValue registry state value

  let private showType registry state name =
    match selectValue name state with
    | Error message ->
      fail registry state message
    | Ok(name, value) ->
      continueWith registry state [ $"{name}: {typeDescription value}" ]

  let private showActions registry state =
    ActionRegistry.getAll registry
    |> List.collect actionDetails
    |> continueWith registry state

  let private showHistory registry state =
    state.CommandHistory
    |> List.rev
    |> List.mapi (fun index command -> $"{index + 1}: {command}")
    |> continueWith registry state

  let private showValues registry state =
    state.ValueHistory
    |> List.rev
    |> List.map (fun entry ->
      let kind = typeDescription entry.Value
      let name = entry.Name |> Option.defaultValue "<unnamed>"
      $"{entry.ID}: {name}  {kind}")
    |> function
      | [] -> [ "No values have been produced." ]
      | output -> output
    |> continueWith registry state

  let private inspect registry state name =
    match selectValue name state with
    | Error message ->
      fail registry state message
    | Ok(_, value) ->
      let items = TransformerReplInspection.inspect value
      if List.isEmpty items then
        let message =
          "The selected value has no inspectable functions or sections."
        fail registry state message
      else
        items
        |> List.mapi (fun index item ->
          let command =
            match name with
            | Some name -> $"{name} |> {item.Command}"
            | None -> item.Command
          $"{index + 1}: {item.Label}  {item.Detail}  => {command}")
        |> continueWith registry state

  let private normalizeNeedsArguments state args =
    let args = args |> resolveArgumentBindings state |> compactBracketArguments
    match parseArguments args with
    | Error message -> Error message
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
      | name :: _ -> Error $"Unknown :needs parameter: {name}"
      | [] ->
        let find name = Map.tryFind name parsed.Named |> Option.map snd
        match find "start", find "count", find "end" with
        | None, None, None -> Ok []
        | None, Some count, None -> Ok [ count ]
        | Some start, Some count, None -> Ok [ start; count ]
        | Some start, None, Some finish -> Ok [ start; finish ]
        | Some start, None, None -> Ok [ start; "1" ]
        | None, _, Some _ -> Error ":needs end= requires start=."
        | Some _, Some _, Some _ ->
          Error ":needs accepts either count= or end=, not both."

  let private needs registry state name args =
    match TransformerReplState.tryFind name state with
    | None ->
      fail registry state $"Unknown binding: {name}"
    | Some value ->
      match value.Collection.Values with
      | [| :? ConcExecutorValue as executor |] ->
        match normalizeNeedsArguments state args with
        | Error message -> fail registry state message
        | Ok args ->
          try
            let requirements = executor.Needs args
            let state = TransformerReplState.setLastNeeds requirements state
            continueWith registry state (renderRequirements requirements)
          with error ->
            fail registry state error.Message
      | _ ->
        fail registry state $":needs expects a ConcExecutor binding: {name}"

  let private restore registry state id name command =
    match TransformerReplState.restoreValue id name state with
    | Error message ->
      fail registry state message
    | Ok state ->
      let state = TransformerReplState.recordReplayCommand command state
      let value = state.Current |> Option.get
      continueWith registry state [ describeValue name value ]

  let private undo registry state =
    match TransformerReplState.undo state with
    | Error message -> fail registry state message
    | Ok state ->
      let current =
        state.Current
        |> Option.map typeDescription
        |> Option.defaultValue "none"
      continueWith registry state
        [ $"Undid the last value change; current: {current}" ]

  let private showLog registry state =
    state.ExecutionLog
    |> List.rev
    |> List.map (fun entry ->
      let status = entry.Status.ToString().ToLowerInvariant()
      let elapsed = entry.Duration.TotalMilliseconds
      $"{entry.ID}: {status} {elapsed:F1} ms  {entry.Command}")
    |> function
      | [] -> [ "The execution log is empty." ]
      | output -> output
    |> continueWith registry state

  let private exportValue registry state name path =
    match TransformerReplState.tryFind name state with
    | None ->
      fail registry state $"Unknown binding: {name}"
    | Some value ->
      try
        let fullPath = Path.GetFullPath path
        if value.Collection.Values.Length = 1 then
          ReplArtifactWriter.write fullPath value.Collection.Values[0]
        else
          value.Collection.Values
          |> Array.iteri (fun index item ->
            ReplArtifactWriter.write $"{fullPath}.{index}" item)
        continueWith registry state
          [ $"Exported {name}: {normalizePath fullPath}" ]
      with error ->
        fail registry state error.Message

  let private saveScript registry state path =
    try
      let header = "# B2R2 Transformer script v1"
      let lines = header :: state.ReplayCommands |> List.toArray
      let fullPath = Path.GetFullPath path
      File.WriteAllLines(fullPath, lines)
      let state =
        TransformerReplState.setSessionPath (normalizePath path) state
      continueWith registry state [ $"Script saved: {normalizePath fullPath}" ]
    with error -> fail registry state error.Message

  let private scriptRecordText = function
    | ReplReplayMode.Reproducible -> "on"
    | ReplReplayMode.Exploratory -> "off"

  let private setScriptRecord registry state enabled =
    match enabled with
    | Some true ->
      let state =
        TransformerReplState.setReplayMode ReplReplayMode.Reproducible state
      continueWith registry state [ "Script recording: on" ]
    | Some false ->
      let state =
        TransformerReplState.setReplayMode ReplReplayMode.Exploratory state
      continueWith registry state [ "Script recording: off" ]
    | None ->
      let status = scriptRecordText state.ReplayMode
      continueWith registry state [ $"Script recording: {status}" ]

  let private addScriptComment registry state text =
    let state = TransformerReplState.recordReplayComment text state
    continueWith registry state [ "Script comment recorded." ]

  let private actionIDs registry =
    (registry: ActionRegistry).Actions |> Map.toSeq |> Seq.map fst |> Set.ofSeq

  let private loadPlugin registry state path command =
    try
      let before = actionIDs registry
      let fullPath = Path.GetFullPath path
      let registry = ActionRegistry.loadPlugin fullPath registry
      let added =
        ActionRegistry.getAll registry
        |> List.filter (fun action ->
          Set.contains action.Metadata.ID before |> not)
        |> List.map (fun action -> ActionMetadata.actionName action.Metadata.ID)
      let addedText =
        match added with
        | [] -> "none"
        | _ -> String.concat ", " added
      let state = TransformerReplState.recordReplayCommand command state
      continueWith registry state
        [ $"Plugin loaded: {normalizePath fullPath}"
          $"  actions: {addedText}" ]
    with error ->
      fail registry state error.Message

  let private scriptCommands path =
    if not (File.Exists path) then
      Error $"Script file not found: {path}"
    else
      File.ReadAllLines path
      |> Array.toList
      |> InputAnalysis.combineCommandLines

  let private resultState = function
    | Continue(registry, state, output) -> Ok(registry, state, output)
    | Exit _ -> Error "A script cannot contain :quit."

  let private help =
    [ "Transformer interactive commands:"
      "  let <name> = <expression>"
      "  let <name> = @load path=<path>"
      "  let <name> : Binary = @load path=<path>"
      "  let <name> = <value> |> @<action> [argument ...]"
      "  <expression>          evaluate without binding"
      "  :inspect [name]       list selectable functions and sections"
      "  :needs <ctx> [k=v]    list required concrete context"
      "  :values               list retained value history"
      "  :restore <id> [as n]  restore a historical value"
      "  :undo                 undo the last value-producing command"
      "  :log                  show the detailed execution log"
      "  :export <name> <path> export a named value"
      "  :script save <path>   save recorded analysis commands"
      "  :script load <path>   reset and replay a script"
      "  :script record [on|off]"
      "                        show or set script recording"
      "  :plugin load <dll>    load REPL actions from a plugin DLL"
      "  # <text>              record a script comment"
      "  :layout [k=v ...]     resize TUI panes"
      "  :actions              list available actions"
      "  :type [name]          show a value type"
      "  :show [expression]    show a value or expression result"
      "  :history              show command history"
      "  :reset                clear analysis values"
      "  :quit                 leave the REPL" ]

  let private addExecutionLog timestamp (stopwatch: Stopwatch)
                              (input: string) evaluation =
    if String.IsNullOrWhiteSpace input then
      evaluation
    else
      let status, detail =
        match evaluation with
        | Continue(_, _, output) ->
          output.Lines
          |> List.tryFind (fun line ->
            line.StartsWith("Error:", StringComparison.Ordinal))
          |> function
            | Some error -> ReplExecutionStatus.Failed, Some error
            | None -> ReplExecutionStatus.Succeeded, None
        | Exit _ -> ReplExecutionStatus.Succeeded, None
      let record (state: TransformerReplState) =
        TransformerReplState.recordExecution timestamp stopwatch.Elapsed
          status input detail state
      match evaluation with
      | Continue(registry, state, output) ->
        Continue(registry, record state, output)
      | Exit(registry, state) -> Exit(registry, record state)

  let rec private evaluateInput includeSuggestions registry state
                                (input: string)
                                (cancellationToken: CancellationToken) =
    match InputAnalysis.splitTopLevelCommands input with
    | _ :: _ :: _ as commands ->
      let outputs = ResizeArray<string>()
      let folder result command =
        result
        |> Result.bind (fun (currentRegistry, currentState) ->
          cancellationToken.ThrowIfCancellationRequested()
          evaluateInput includeSuggestions currentRegistry currentState command
            cancellationToken
          |> resultState
          |> Result.map (fun (nextRegistry, nextState, output) ->
            outputs.AddRange output.Lines
            nextRegistry, nextState))
      commands
      |> List.fold folder (Ok(registry, state))
      |> function
        | Ok(registry, state) ->
          continueWith registry state (Seq.toList outputs)
        | Error message -> fail registry state message
    | _ ->
      let timestamp = DateTimeOffset.Now
      let stopwatch = Stopwatch.StartNew()
      let state =
        if String.IsNullOrWhiteSpace input then state
        else TransformerReplState.recordCommand input state
      let evaluation =
        evaluateCore includeSuggestions registry state input cancellationToken
      stopwatch.Stop()
      addExecutionLog timestamp stopwatch input evaluation

  and private evaluateCore includeSuggestions registry state input
                           cancellationToken =
    match TransformerReplParser.parse input with
    | Error message ->
      fail registry state message
    | Ok NoInput ->
      continueWith registry state []
    | Ok Quit ->
      Exit(registry, state)
    | Ok Help ->
      continueWith registry state help
    | Ok Actions ->
      showActions registry state
    | Ok History ->
      showHistory registry state
    | Ok Values ->
      showValues registry state
    | Ok Undo ->
      undo registry state
    | Ok Log ->
      showLog registry state
    | Ok(ExportValue(name, path)) ->
      exportValue registry state name path
    | Ok(Inspect name) ->
      inspect registry state name
    | Ok(Needs(name, args)) ->
      needs registry state name args
    | Ok(Restore(id, name)) ->
      restore registry state id name input
    | Ok(SaveScript path) ->
      saveScript registry state path
    | Ok(LoadScript path) ->
      loadScript includeSuggestions registry state path cancellationToken
    | Ok(ScriptRecord enabled) ->
      setScriptRecord registry state enabled
    | Ok(ScriptComment text) ->
      addScriptComment registry state text
    | Ok(PluginLoad path) ->
      loadPlugin registry state path input
    | Ok(Layout _) ->
      continueWith registry state [ ":layout is only available in the TUI." ]
    | Ok Reset ->
      continueWith registry (TransformerReplState.reset state)
        [ "Analysis state reset." ]
    | Ok(Show name) ->
      show registry state name
    | Ok(ShowExpression segments) ->
      showExpression registry state segments cancellationToken
    | Ok(TypeOf name) ->
      showType registry state name
    | Ok(Evaluate(segments, binding, expected)) ->
      evaluate includeSuggestions registry state segments binding expected input
        cancellationToken

  and private loadScript _includeSuggestions registry state path
                         cancellationToken =
    let fullPath = Path.GetFullPath path
    match scriptCommands fullPath with
    | Error message ->
      fail registry state message
    | Ok commands ->
      let outputs = ResizeArray<string>()
      commands
      |> List.fold (fun result command ->
        result
        |> Result.bind (fun (loadedRegistry, loadedState) ->
          cancellationToken.ThrowIfCancellationRequested()
          evaluateInput false loadedRegistry loadedState command
            cancellationToken
          |> resultState
          |> Result.bind (fun (nextRegistry, nextState, output) ->
            match output.Lines |> List.tryFind (fun line ->
              line.StartsWith("Error:", StringComparison.Ordinal)) with
            | Some error -> Error error
            | None ->
              outputs.Add $"> {command}"
              outputs.AddRange output.Lines
              Ok(nextRegistry, nextState))))
        (Ok(registry, TransformerReplState.empty))
      |> function
        | Error message ->
          fail registry state $"Script replay failed: {message}"
        | Ok(registry, loaded) ->
          let state = TransformerReplState.replaceAnalysis loaded state
          let state =
            TransformerReplState.setSessionPath (normalizePath path) state
          let header = [ $"Script loaded: {normalizePath fullPath}" ]
          continueWith registry state (header @ Seq.toList outputs)

  let evaluateLine registry state input =
    evaluateInput true registry state input CancellationToken.None

  let evaluateTuiLine registry state input cancellationToken =
    evaluateInput false registry state input cancellationToken
