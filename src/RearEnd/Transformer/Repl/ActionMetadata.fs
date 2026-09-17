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
open System.Reflection

/// A stable value category used to validate and suggest Transformer actions.
[<RequireQualifiedAccess>]
type ReplValueKind =
  | Unit
  | Binary
  | ByteArray
  | InstructionArray
  | CFG
  | Text
  | TextArtifact
  | Fingerprint
  | ClusterResult
  | ConcExecutor
  | Range
  | StringMatch
  | SectionInfo
  | FunctionInfo
  | Int
  | Float
  | Bool
  | Collection of ReplValueKind
  | Tuple of ReplValueKind list
  | List of ReplValueKind
  | Array of ReplValueKind
  | Any

/// How an action participates in an analysis pipeline.
[<RequireQualifiedAccess>]
type ActionRole =
  | Source
  | Transform
  | Reducer
  | Sink

/// The semantic category of one action argument.
[<RequireQualifiedAccess>]
type ActionArgumentKind =
  | Text
  | Path
  | ExistingPath
  | OutputPath
  | PathOrHex
  | ISA
  | Integer
  | Float
  | HexPattern
  | HexBytes
  | Address
  | AddressOrSize
  | Section
  | Action
  | ParameterFunction
  | Choice

/// A command-line argument accepted by an action.
type ActionArgument =
  { Name: string
    Kind: ActionArgumentKind
    IsOptional: bool
    Choices: string list
    Description: string }

/// One valid argument layout for an action.
type ActionSyntax =
  { Trigger: string option
    Arguments: ActionArgument list
    Inputs: ReplValueKind list
    Output: ReplValueKind option }

/// Machine-readable information describing an action's public contract.
type ActionMetadata =
  { ID: string
    Input: ReplValueKind
    AlternativeInputs: ReplValueKind list
    Output: ReplValueKind
    Role: ActionRole
    Syntaxes: ActionSyntax list
    Signature: string
    Description: string
    Examples: string list
    Priority: int }

/// Implemented by external actions that support the interactive environment.
type IActionMetadataProvider =
  abstract member Metadata: ActionMetadata

/// An action paired with its structured metadata.
type RegisteredAction =
  { Action: IAction
    Metadata: ActionMetadata }

/// All actions available to one Transformer invocation.
type ActionRegistry =
  { Actions: Map<string, RegisteredAction>
    AllSorted: RegisteredAction list
    Compatible: Map<ReplValueKind, RegisteredAction list> }

module ReplValueKind =
  let rec toString kind =
    let nested kind =
      match kind with
      | ReplValueKind.Tuple _ -> $"({toString kind})"
      | _ -> toString kind
    match kind with
    | ReplValueKind.Unit -> "Unit"
    | ReplValueKind.Binary -> "Binary"
    | ReplValueKind.ByteArray -> "ByteArray"
    | ReplValueKind.InstructionArray -> "InstructionArray"
    | ReplValueKind.CFG -> "CFG"
    | ReplValueKind.Text -> "Text"
    | ReplValueKind.TextArtifact -> "TextArtifact"
    | ReplValueKind.Fingerprint -> "Fingerprint"
    | ReplValueKind.ClusterResult -> "ClusterResult"
    | ReplValueKind.ConcExecutor -> "ConcExecutor"
    | ReplValueKind.Range -> "Range"
    | ReplValueKind.StringMatch -> "StringMatch"
    | ReplValueKind.SectionInfo -> "SectionInfo"
    | ReplValueKind.FunctionInfo -> "FunctionInfo"
    | ReplValueKind.Int -> "Int"
    | ReplValueKind.Float -> "Float"
    | ReplValueKind.Bool -> "Bool"
    | ReplValueKind.Collection kind -> $"{nested kind} collection"
    | ReplValueKind.Tuple kinds ->
      kinds |> List.map toString |> String.concat " * "
    | ReplValueKind.List kind -> $"{nested kind} list"
    | ReplValueKind.Array kind -> $"{nested kind} array"
    | ReplValueKind.Any -> "Any"

  let all =
    [ ReplValueKind.Binary
      ReplValueKind.ByteArray
      ReplValueKind.InstructionArray
      ReplValueKind.CFG
      ReplValueKind.Text
      ReplValueKind.TextArtifact
      ReplValueKind.Fingerprint
      ReplValueKind.ClusterResult
      ReplValueKind.ConcExecutor
      ReplValueKind.Range
      ReplValueKind.StringMatch
      ReplValueKind.SectionInfo
      ReplValueKind.FunctionInfo
      ReplValueKind.Int
      ReplValueKind.Float
      ReplValueKind.Bool ]

  let private parseAtomic (text: string) =
    all
    |> List.tryFind (fun kind ->
      String.Equals(
        toString kind,
        text,
        StringComparison.OrdinalIgnoreCase))

  let tryParse (text: string) =
    let rec parse (text: string) =
      let text = text.Trim()
      if text.StartsWith "(" && text.EndsWith ")" then
        parse text[1..text.Length - 2]
      elif text.EndsWith(" list", StringComparison.OrdinalIgnoreCase) then
        let inner = text[..text.Length - 6]
        parse inner |> Option.map ReplValueKind.List
      elif text.EndsWith(" array", StringComparison.OrdinalIgnoreCase) then
        let inner = text[..text.Length - 7]
        parse inner |> Option.map ReplValueKind.Array
      elif text.EndsWith(" collection", StringComparison.OrdinalIgnoreCase) then
        let inner = text[..text.Length - 12]
        parse inner |> Option.map ReplValueKind.Collection
      elif text.Contains "*" then
        text.Split '*'
        |> Array.toList
        |> List.map parse
        |> function
          | kinds when List.forall Option.isSome kinds ->
            kinds |> List.map Option.get |> ReplValueKind.Tuple |> Some
          | _ -> None
      else
        parseAtomic text
    parse text

  let rec isCompatible actual expected =
    expected = ReplValueKind.Any
    || actual = expected
    || expected = ReplValueKind.Text
       && actual = ReplValueKind.TextArtifact
    || match actual, expected with
       | ReplValueKind.Tuple actual, ReplValueKind.Tuple expected ->
         List.length actual = List.length expected
         && List.forall2 isCompatible actual expected
       | ReplValueKind.Collection actual, ReplValueKind.Collection expected ->
         isCompatible actual expected
       | ReplValueKind.Collection actual, expected ->
         isCompatible actual expected
       | ReplValueKind.List actual, ReplValueKind.List expected
       | ReplValueKind.Array actual, ReplValueKind.Array expected ->
         isCompatible actual expected
       | _ -> false

module ActionMetadata =
  let actionName id = "@" + id

  let acceptedInputs metadata =
    let metadata: ActionMetadata = metadata
    metadata.Input :: metadata.AlternativeInputs

  let argumentKindName = function
    | ActionArgumentKind.Text -> "String"
    | ActionArgumentKind.Path -> "Path"
    | ActionArgumentKind.ExistingPath -> "Path"
    | ActionArgumentKind.OutputPath -> "Path"
    | ActionArgumentKind.PathOrHex -> "PathOrHex"
    | ActionArgumentKind.ISA -> "ISA"
    | ActionArgumentKind.Integer -> "Int"
    | ActionArgumentKind.Float -> "Float"
    | ActionArgumentKind.HexPattern -> "HexPattern"
    | ActionArgumentKind.HexBytes -> "HexBytes"
    | ActionArgumentKind.Address -> "Address"
    | ActionArgumentKind.AddressOrSize -> "AddressOrSize"
    | ActionArgumentKind.Section -> "Section"
    | ActionArgumentKind.Action -> "Action"
    | ActionArgumentKind.ParameterFunction -> "ParameterFunction"
    | ActionArgumentKind.Choice -> "Choice"

  let private argumentPlaceholder = function
    | ActionArgumentKind.Text -> "text"
    | ActionArgumentKind.Path
    | ActionArgumentKind.ExistingPath
    | ActionArgumentKind.OutputPath -> "path"
    | ActionArgumentKind.PathOrHex -> "path-or-hex"
    | ActionArgumentKind.ISA -> "isa"
    | ActionArgumentKind.Integer -> "n"
    | ActionArgumentKind.Float -> "n"
    | ActionArgumentKind.HexPattern -> "hex-pattern"
    | ActionArgumentKind.HexBytes -> "hex-bytes"
    | ActionArgumentKind.Address -> "addr"
    | ActionArgumentKind.AddressOrSize -> "addr-or-size"
    | ActionArgumentKind.Section -> "section"
    | ActionArgumentKind.Action -> "action"
    | ActionArgumentKind.ParameterFunction -> "fun"
    | ActionArgumentKind.Choice -> "choice"

  let formatArgument argument =
    let argument: ActionArgument = argument
    let kind = argumentKindName argument.Kind
    let placeholder = argumentPlaceholder argument.Kind
    let text = $"{argument.Name}:{kind}=<{placeholder}>"
    if argument.IsOptional then $"[{text}]" else text

  let private formatSyntax syntax =
    let trigger = (syntax: ActionSyntax).Trigger |> Option.toList
    let args = syntax.Arguments |> List.map formatArgument
    String.concat " " (trigger @ args)

  let typedSignature metadata =
    let metadata: ActionMetadata = metadata
    let formatInputs inputs =
      inputs
      |> List.map ReplValueKind.toString
      |> String.concat " | "
    let hasSyntaxSpecifics =
      metadata.Syntaxes
      |> List.exists (fun syntax ->
        Option.isSome syntax.Output || not (List.isEmpty syntax.Inputs))
    if not hasSyntaxSpecifics then
      let input = formatInputs (acceptedInputs metadata)
      let output = ReplValueKind.toString metadata.Output
      let syntaxes =
        metadata.Syntaxes
        |> List.map formatSyntax
        |> List.map (fun syntax ->
          if String.IsNullOrWhiteSpace syntax then actionName metadata.ID
          else actionName metadata.ID + " " + syntax)
        |> List.distinct
      let body =
        match syntaxes with
        | [] -> actionName metadata.ID
        | syntaxes -> String.concat " | " syntaxes
      $"{input} -> {body} -> {output}"
    else
      metadata.Syntaxes
      |> List.map (fun syntax ->
        let inputs =
          if List.isEmpty syntax.Inputs then acceptedInputs metadata
          else syntax.Inputs
        let input = formatInputs inputs
        let output =
          syntax.Output
          |> Option.defaultValue metadata.Output
          |> ReplValueKind.toString
        let syntaxText = formatSyntax syntax
        let body =
          if String.IsNullOrWhiteSpace syntaxText then actionName metadata.ID
          else actionName metadata.ID + " " + syntaxText
        $"{input} -> {body} -> {output}")
      |> List.distinct
      |> String.concat " | "

  let argumentKeys (argument: ActionArgument) =
    let keys =
      match argument.Name with
      | "base-name" -> [ "base-name"; "basename"; "base"; "name" ]
      | "break" -> [ "break"; "breakpoint"; "bp" ]
      | "bytes-after" -> [ "bytes-after"; "after" ]
      | "bytes-before" -> [ "bytes-before"; "before" ]
      | "directory" -> [ "directory"; "dir" ]
      | "end" -> [ "end" ]
      | "end-or-size" -> [ "end-or-size"; "end"; "offset"; "size" ]
      | "entry" -> [ "entry"; "address"; "addr" ]
      | "extension" -> [ "extension"; "ext" ]
      | "hex" -> [ "hex"; "bytes"; "hex-bytes" ]
      | "hex-bytes" -> [ "hex-bytes"; "hex"; "bytes" ]
      | "hex-pattern" -> [ "hex-pattern"; "pattern" ]
      | "min-points" -> [ "min-points"; "min"; "minpts" ]
      | "n-gram-size" -> [ "n-gram-size"; "ngram"; "n" ]
      | "path" -> [ "path" ]
      | "path-or-hex" -> [ "path-or-hex"; "path"; "hex" ]
      | "params" -> [ "params"; "parameters" ]
      | "window-size" -> [ "window-size"; "window" ]
      | name -> [ name ]
    keys |> List.map (fun key -> key.ToLowerInvariant())

  let private argument name kind isOptional choices description =
    { Name = name
      Kind = kind
      IsOptional = isOptional
      Choices = choices
      Description = description }

  let private required name kind description =
    argument name kind false [] description

  let private optional name kind description =
    argument name kind true [] description

  let private choice name isOptional choices description =
    argument name ActionArgumentKind.Choice isOptional choices description

  let private syntax trigger arguments =
    { Trigger = trigger
      Arguments = arguments
      Inputs = []
      Output = None }

  let private syntaxOutput trigger output arguments =
    { Trigger = trigger
      Arguments = arguments
      Inputs = []
      Output = Some output }

  let private syntaxFor inputs trigger arguments =
    { Trigger = trigger
      Arguments = arguments
      Inputs = inputs
      Output = None }

  let private syntaxForOutput inputs trigger output arguments =
    { Trigger = trigger
      Arguments = arguments
      Inputs = inputs
      Output = Some output }

  let private contract id input output role priority signature =
    let create examples syntaxes =
      { ID = id
        Input = input
        AlternativeInputs = []
        Output = output
        Role = role
        Syntaxes = syntaxes
        Signature = signature
        Description = ""
        Examples = examples
        Priority = priority }
    create

  let private overloadContract id inputs output role priority signature =
    let primary, alternatives =
      match inputs with
      | head :: tail -> head, tail
      | [] -> invalidArg (nameof inputs) "Action input overloads are empty."
    let create examples syntaxes =
      { ID = id
        Input = primary
        AlternativeInputs = alternatives
        Output = output
        Role = role
        Syntaxes = syntaxes
        Signature = signature
        Description = ""
        Examples = examples
        Priority = priority }
    create

  let syntaxAccepts inputKind syntax =
    let syntax: ActionSyntax = syntax
    match inputKind with
    | None -> true
    | Some kind when List.isEmpty syntax.Inputs -> true
    | Some kind ->
      syntax.Inputs
      |> List.exists (fun expected -> ReplValueKind.isCompatible kind expected)

  let outputForArguments metadata inputKind args =
    let metadata: ActionMetadata = metadata
    let tokenParameterName (token: string) =
      let index = token.IndexOf '='
      if index <= 0 then None
      else
        let key = token[..index - 1]
        let typeIndex = key.IndexOf ':'
        let key = if typeIndex <= 0 then key else key[..typeIndex - 1]
        Some(key.ToLowerInvariant())
    let matchesParameters syntax =
      let names = args |> List.choose tokenParameterName
      if List.isEmpty args || List.isEmpty names then true
      else
        names
        |> List.forall (fun name ->
          (syntax: ActionSyntax).Arguments
          |> List.exists (fun argument ->
            argumentKeys argument |> List.contains name))
    let matchesTrigger syntax =
      match (syntax: ActionSyntax).Trigger, args with
      | None, _ -> true
      | Some trigger, actual :: _ ->
        String.Equals(trigger, actual, StringComparison.OrdinalIgnoreCase)
      | Some _, [] -> false
    metadata.Syntaxes
    |> List.filter (syntaxAccepts inputKind)
    |> List.tryPick (fun syntax ->
      if matchesTrigger syntax && matchesParameters syntax then syntax.Output
      else None)
    |> Option.defaultValue metadata.Output

  let private tokenParameterName (token: string) =
    let index = token.IndexOf '='
    if index <= 0 then None
    else
      let key = token[..index - 1]
      let typeIndex = key.IndexOf ':'
      let key = if typeIndex <= 0 then key else key[..typeIndex - 1]
      Some(key.ToLowerInvariant())

  let syntaxHasParameter (name: string) syntax =
    (syntax: ActionSyntax).Arguments
    |> List.exists (fun argument ->
      argumentKeys argument |> List.contains (name.ToLowerInvariant()))

  let syntaxMatchesParameters args syntax =
    let names = args |> List.choose tokenParameterName
    names |> List.forall (fun name -> syntaxHasParameter name syntax)

  let matchingSyntaxes metadata inputKind args =
    let metadata: ActionMetadata = metadata
    metadata.Syntaxes
    |> List.filter (syntaxAccepts inputKind)
    |> List.filter (syntaxMatchesParameters args)

  let typedSignatureFor metadata inputKind args =
    let metadata: ActionMetadata = metadata
    let syntaxes = matchingSyntaxes metadata inputKind args
    let syntaxes =
      if List.isEmpty syntaxes then metadata.Syntaxes else syntaxes
    typedSignature { metadata with Syntaxes = syntaxes }

  let private cfg =
    let address =
      required "entry" ActionArgumentKind.Address
        "Function entry address. Omit this to recover all CFGs."
    overloadContract "cfg"
      [ ReplValueKind.Binary; ReplValueKind.FunctionInfo ]
      ReplValueKind.CFG
      ActionRole.Transform 20
      "cfg -> CFG collection | cfg entry=<address> -> CFG"
      [ "binary |> @cfg"
        "binary |> @cfg entry=0x401000"
        "function |> @cfg" ]
      [ syntaxForOutput [ ReplValueKind.Binary ] None
          (ReplValueKind.Collection ReplValueKind.CFG) []
        syntaxFor [ ReplValueKind.Binary ] None [ address ]
        syntaxFor [ ReplValueKind.FunctionInfo ] None []
      ]

  let private bytes =
    contract "bytes" ReplValueKind.Binary ReplValueKind.ByteArray
      ActionRole.Transform 20 "bytes -> ByteArray"
      [ "binary |> @bytes" ] [ syntax None [] ]

  let private asBinary =
    contract "as-binary" ReplValueKind.ByteArray ReplValueKind.Binary
      ActionRole.Transform 10 "as-binary -> Binary"
      [ "rawBytes |> @as-binary" ] [ syntax None [] ]

  let private arg =
    let index =
      required "index" ActionArgumentKind.Integer
        "Zero-based integer argument index."
    let value =
      required "value" ActionArgumentKind.Address
        "Concrete integer or pointer value."
    contract "arg" ReplValueKind.ConcExecutor ReplValueKind.ConcExecutor
      ActionRole.Transform 20 "arg index=<n> value=<value> -> ConcExecutor"
      [ "executor |> @arg index=0 value=0x70000000" ]
      [ syntax None [ index; value ] ]

  let private count =
    contract "count" ReplValueKind.Any ReplValueKind.Int
      ActionRole.Reducer 60 "count -> Int"
      [ "matches |> @count" ] [ syntax None [] ]

  let private batch =
    let action =
      required "action" ActionArgumentKind.Action
        "Action to apply to each collection item."
    let parameters =
      required "params" ActionArgumentKind.ParameterFunction
        "Function that returns action parameters for each item."
    let inputs =
      [ ReplValueKind.Collection ReplValueKind.Any
        ReplValueKind.List ReplValueKind.Any
        ReplValueKind.Array ReplValueKind.Any ]
    let signature =
      "'a collection -> batch action=<action> params=<fun> -> 'b collection"
    overloadContract "batch" inputs (ReplValueKind.Collection ReplValueKind.Any)
      ActionRole.Transform 80 signature
      [ "bins |> @batch action=@save params=(fun item i -> path=out/{i}.bin)"
        "texts |> @batch @write (fun item _ -> path=out.txt)" ]
      [ syntax None [ action; parameters ] ]

  let private concExec =
    contract "concExec" ReplValueKind.Binary ReplValueKind.ConcExecutor
      ActionRole.Transform 20 "concExec -> ConcExecutor"
      [ "binary |> @concExec" ] [ syntax None [] ]

  let private dbscan =
    let eps = optional "eps" ActionArgumentKind.Float "Maximum distance."
    let minPts =
      optional "min-points" ActionArgumentKind.Integer
        "Minimum number of neighboring fingerprints."
    contract "dbscan" (ReplValueKind.Collection ReplValueKind.Fingerprint)
      ReplValueKind.ClusterResult ActionRole.Reducer 50
      "dbscan [<eps>] [<min-points>] -> ClusterResult"
      [ "fingerprints |> @dbscan 0.2 3" ]
      [ syntax None [ eps; minPts ] ]

  let private detect =
    let path =
      required "path" ActionArgumentKind.ExistingPath
        "File or directory to compare with the fingerprint."
    contract "detect" ReplValueKind.Fingerprint ReplValueKind.Text
      ActionRole.Transform 30 "detect <path> -> Text"
      [ "fingerprint |> @detect temp/bin" ] [ syntax None [ path ] ]

  let private diff =
    let pair kind = ReplValueKind.Tuple [ kind; kind ]
    overloadContract "diff"
      [ pair ReplValueKind.Binary
        pair ReplValueKind.ByteArray
        pair ReplValueKind.InstructionArray
        pair ReplValueKind.CFG
        pair ReplValueKind.Text
        pair ReplValueKind.TextArtifact ]
      ReplValueKind.Text ActionRole.Reducer 60
      "supported same-type pair -> @diff -> Text"
      [ "let binaries = (oldBin, newBin)"
        "binaries |> @diff"
        "let code = (oldCode, newCode)"
        "code |> @diff" ] [ syntax None [] ]

  let private disasm =
    contract "disasm" ReplValueKind.Binary ReplValueKind.InstructionArray
      ActionRole.Transform 30 "disasm -> InstructionArray"
      [ "binary |> @disasm" ] [ syntax None [] ]

  let private dot =
    contract "dot" ReplValueKind.CFG ReplValueKind.TextArtifact
      ActionRole.Transform 10 "dot -> TextArtifact"
      [ "graph |> @dot" ] [ syntax None [] ]

  let private edit =
    let offset =
      required "offset" ActionArgumentKind.Integer "Zero-based file offset."
    let endOffset =
      required "end" ActionArgumentKind.AddressOrSize
        "Exclusive end offset or +size."
    let bytes =
      required "hex-bytes" ActionArgumentKind.HexBytes
        "Replacement bytes as a hexadecimal string."
    let insert = syntax (Some "insert") [ offset; bytes ]
    let delete = syntax (Some "delete") [ offset; endOffset ]
    let replace = syntax (Some "replace") [ offset; endOffset; bytes ]
    contract "edit" ReplValueKind.Binary ReplValueKind.Binary
      ActionRole.Transform 40 "edit <operation> ... -> Binary"
      [ "binary |> @edit insert offset=0 hex=90"
        "binary |> @edit delete offset=0 end=+4"
        "binary |> @edit replace offset=0 end=+2 hex=9090" ]
      [ insert; delete; replace ]

  let private grep =
    let pattern =
      required "pattern" ActionArgumentKind.HexPattern
        "Regular expression over hexadecimal byte pairs."
    let before =
      optional "bytes-before" ActionArgumentKind.Integer
        "Context bytes preceding each match."
    let after =
      optional "bytes-after" ActionArgumentKind.Integer
        "Context bytes following each match."
    let signature =
      "grep <hex-pattern> [<bytes-before>] [<bytes-after>] -> Binary"
    contract "grep" ReplValueKind.Binary ReplValueKind.Binary
      ActionRole.Transform 30 signature
      [ "binary |> @grep 7f454c46 0 16" ]
      [ syntax None [ pattern; before; after ] ]

  let private hexdump =
    contract "hexdump" ReplValueKind.Binary ReplValueKind.Text
      ActionRole.Transform 30 "hexdump -> Text"
      [ "binary |> @hexdump" ] [ syntax None [] ]

  let private jaccard =
    let input =
      ReplValueKind.Tuple
        [ ReplValueKind.Fingerprint; ReplValueKind.Fingerprint ]
    contract "jaccard" input ReplValueKind.Float
      ActionRole.Reducer 60 "Fingerprint * Fingerprint -> @jaccard -> Float"
      [ "let fingerprints = (fp0, fp1)"
        "fingerprints |> @jaccard" ] [ syntax None [] ]

  let private regs =
    let register =
      optional "register" ActionArgumentKind.Text
        "Register name to print; defaults to all defined registers."
    contract "regs" ReplValueKind.ConcExecutor ReplValueKind.Text
      ActionRole.Transform 20 "regs [register=<name>] -> Text"
      [ "executor |> @regs"; "executor |> @regs register=RAX" ]
      [ syntax None [ register ] ]

  let private run =
    let entry =
      optional "entry" ActionArgumentKind.Address
        "Start address; defaults to current PC or file entry point."
    let limit =
      optional "limit" ActionArgumentKind.Integer
        "Maximum machine instruction count."
    let breakpoint =
      optional "break" ActionArgumentKind.Address
        "Stop before executing this address."
    contract "run" ReplValueKind.ConcExecutor ReplValueKind.ConcExecutor
      ActionRole.Transform 20
      "run [entry=<addr>] [limit=<n>] [break=<addr>] -> ConcExecutor"
      [ "executor |> @run entry=0x401000 limit=10"
        "executor |> @run entry=0x401000 limit=100 break=0x401020" ]
      [ syntax None [ entry; limit; breakpoint ] ]

  let private lift =
    contract "lift" ReplValueKind.Binary ReplValueKind.Text
      ActionRole.Transform 40 "lift -> Text"
      [ "binary |> @lift" ] [ syntax None [] ]

  let private list =
    let sections =
      syntaxOutput (Some "sections")
        (ReplValueKind.Collection ReplValueKind.SectionInfo) []
    let functions =
      syntaxOutput (Some "functions")
        (ReplValueKind.Collection ReplValueKind.FunctionInfo) []
    contract "list" ReplValueKind.Binary ReplValueKind.Any
      ActionRole.Transform 10
      "list <sections|functions> -> SectionInfo|FunctionInfo collection"
      [ "binary |> @list sections"; "binary |> @list functions" ]
      [ sections; functions ]

  let private llvm =
    contract "llvm" ReplValueKind.Binary ReplValueKind.TextArtifact
      ActionRole.Transform 50 "llvm -> TextArtifact"
      [ "binary |> @llvm" ] [ syntax None [] ]

  let private load =
    let source =
      required "path" ActionArgumentKind.ExistingPath
        "File or directory to parse."
    let hex =
      required "hex" ActionArgumentKind.HexBytes
        "Hexadecimal bytes to load as a raw image."
    let optionalISA =
      optional "isa" ActionArgumentKind.ISA "Instruction-set architecture."
    let requiredISA =
      required "isa" ActionArgumentKind.ISA "Instruction-set architecture."
    contract "load" ReplValueKind.Unit ReplValueKind.Binary
      ActionRole.Source 0
      "load path=<path> [isa=<isa>] | hex=<hex> isa=<isa> -> Binary"
      [ "@load path=temp/bin/base32"
        "@load hex=9090c3 isa=x86-64" ]
      [ syntax None [ source; optionalISA ]
        syntax None [ hex; requiredISA ] ]

  let private memRead =
    let address =
      required "address" ActionArgumentKind.Address
        "Starting concrete memory address."
    let size =
      required "size" ActionArgumentKind.Integer
        "Number of bytes to read."
    contract "mem-read" ReplValueKind.ConcExecutor ReplValueKind.Text
      ActionRole.Transform 20
      "mem-read address=<addr> size=<n> -> Text"
      [ "executor |> @mem-read address=0x70000000 size=16" ]
      [ syntax None [ address; size ] ]

  let private memWrite =
    let address =
      required "address" ActionArgumentKind.Address
        "Starting concrete memory address."
    let bytes =
      required "hex-bytes" ActionArgumentKind.HexBytes
        "Bytes to write as a hexadecimal string."
    contract "mem-write" ReplValueKind.ConcExecutor ReplValueKind.ConcExecutor
      ActionRole.Transform 20
      "mem-write address=<addr> bytes=<hex> -> ConcExecutor"
      [ "executor |> @mem-write address=0x70000000 bytes=41424300" ]
      [ syntax None [ address; bytes ] ]

  let private pick =
    let index =
      required "index" ActionArgumentKind.Integer
        "1-based value index in the current collection."
    contract "pick" (ReplValueKind.Collection ReplValueKind.Any)
      ReplValueKind.Any
      ActionRole.Transform 5 "pick <index> -> Any"
      [ "graphs |> @pick 1" ] [ syntax None [ index ] ]

  let private print =
    contract "print" ReplValueKind.Any ReplValueKind.Unit
      ActionRole.Sink 100 "print -> Unit" [] [ syntax None [] ]

  let private slice =
    let section =
      required "section" ActionArgumentKind.Section "Section name."
    let start =
      required "start" ActionArgumentKind.Address "Starting address."
    let finish =
      required "end" ActionArgumentKind.AddressOrSize
        "Exclusive end address."
    let offset =
      required "offset" ActionArgumentKind.AddressOrSize
        "Positive size relative to the start address."
    let signature =
      "slice section=<name>|start=<addr> (end=<addr>|offset=+n) -> Binary"
    contract "slice" ReplValueKind.Binary
      ReplValueKind.Binary
      ActionRole.Transform 10 signature
      [ "binary |> @slice section=.text"
        "binary |> @slice start=0x401000 offset=+32" ]
      [ syntax None [ section ]
        syntax None [ start; finish ]
        syntax None [ start; offset ] ]

  let private step =
    let count =
      optional "count" ActionArgumentKind.Integer
        "Number of machine instructions; defaults to 1."
    contract "step" ReplValueKind.ConcExecutor ReplValueKind.ConcExecutor
      ActionRole.Transform 20 "step [count=<n>] -> ConcExecutor"
      [ "executor |> @step"; "executor |> @step count=4" ]
      [ syntax None [ count ] ]

  let private trace =
    let count =
      required "count" ActionArgumentKind.Integer
        "Number of machine instructions; defaults to 1."
    let address =
      required "address" ActionArgumentKind.Address
        "Starting concrete memory address to watch."
    let size =
      required "size" ActionArgumentKind.Integer
        "Number of watched memory bytes."
    contract "trace" ReplValueKind.ConcExecutor ReplValueKind.Text
      ActionRole.Transform 20
      "trace [count=<n>] [address=<addr> size=<n>] -> Text"
      [ "executor |> @trace"
        "executor |> @trace count=4"
        "executor |> @trace count=1 address=0x70000000 size=16" ]
      [ syntax None []
        syntax None [ count ]
        syntax None [ address; size ]
        syntax None [ count; address; size ] ]

  let private strings =
    let minimum =
      optional "min" ActionArgumentKind.Integer
        "Minimum printable string length; defaults to 4."
    let pattern =
      optional "pattern" ActionArgumentKind.Text
        "Case-insensitive substring filter."
    contract "strings" ReplValueKind.Binary
      (ReplValueKind.Collection ReplValueKind.StringMatch)
      ActionRole.Transform 10
      "strings [min=<n>] [pattern=<text>] -> StringMatch collection"
      [ "binary |> @strings"
        "binary |> @strings pattern=ADMIN"
        "binary |> @strings min=8 pattern=EXPORT" ]
      [ syntax None [ minimum; pattern ] ]

  let private save =
    let path =
      required "path" ActionArgumentKind.OutputPath "Destination file path."
    contract "save" ReplValueKind.Binary ReplValueKind.Unit
      ActionRole.Sink 90 "save path=<path> -> Unit"
      [ "binary |> @save path=out.bin" ] [ syntax None [ path ] ]

  let private winnowing =
    let ngram =
      optional "n-gram-size" ActionArgumentKind.Integer
        "N-gram size; defaults to 4."
    let window =
      optional "window-size" ActionArgumentKind.Integer
        "Window size; defaults to 4."
    contract "winnowing" ReplValueKind.Binary ReplValueKind.Fingerprint
      ActionRole.Transform 40
      "winnowing [<n-gram-size>] [<window-size>] -> Fingerprint"
      [ "binary |> @winnowing 4 4" ]
      [ syntax None [ ngram; window ] ]

  let private write =
    let path =
      required "path" ActionArgumentKind.OutputPath "Destination file path."
    overloadContract "write"
      [ ReplValueKind.Text
        ReplValueKind.TextArtifact
        ReplValueKind.InstructionArray ]
      ReplValueKind.Unit ActionRole.Sink 90 "write path=<path> -> Unit"
      [ "dump |> @write path=output.txt"
        "code |> @write path=disasm.txt" ] [ syntax None [ path ] ]

  let private builtIns =
    [ cfg
      bytes
      asBinary
      arg
      batch
      count
      concExec
      dbscan
      detect
      diff
      disasm
      dot
      edit
      grep
      hexdump
      jaccard
      lift
      list
      llvm
      load
      pick
      print
      memRead
      memWrite
      regs
      run
      slice
      step
      trace
      strings
      save
      winnowing
      write ]
    |> List.map (fun metadata -> metadata.ID.ToLowerInvariant(), metadata)
    |> Map.ofList

  let private normalize action metadata =
    let actionID = (action: IAction).ActionID.ToLowerInvariant()
    if metadata.ID.ToLowerInvariant() <> actionID then
      invalidOp $"Action metadata ID does not match action ID: {actionID}"
    else
      let description =
        if String.IsNullOrWhiteSpace metadata.Description then
          action.Description.Trim()
        else
          metadata.Description.Trim()
      { metadata with Description = description }

  let ofAction (action: IAction) =
    match action with
    | :? IActionMetadataProvider as provider ->
      normalize action provider.Metadata
    | _ ->
      let actionID = action.ActionID.ToLowerInvariant()
      match Map.tryFind actionID builtIns with
      | Some metadata -> normalize action metadata
      | None ->
        let message = $"External action '{actionID}' must implement "
        invalidOp (message + "IActionMetadataProvider.")

module ActionRegistry =
  let private valueKinds =
    [ ReplValueKind.Unit
      ReplValueKind.Binary
      ReplValueKind.ByteArray
      ReplValueKind.InstructionArray
      ReplValueKind.CFG
      ReplValueKind.Text
      ReplValueKind.TextArtifact
      ReplValueKind.Fingerprint
      ReplValueKind.ClusterResult
      ReplValueKind.ConcExecutor
      ReplValueKind.Range
      ReplValueKind.StringMatch
      ReplValueKind.SectionInfo
      ReplValueKind.FunctionInfo
      ReplValueKind.Collection ReplValueKind.CFG
      ReplValueKind.Collection ReplValueKind.Fingerprint
      ReplValueKind.Collection ReplValueKind.SectionInfo
      ReplValueKind.Collection ReplValueKind.FunctionInfo
      ReplValueKind.Collection ReplValueKind.StringMatch
      ReplValueKind.Collection ReplValueKind.Any
      ReplValueKind.List ReplValueKind.Any
      ReplValueKind.Array ReplValueKind.Any
      ReplValueKind.Int
      ReplValueKind.Float
      ReplValueKind.Bool
      ReplValueKind.Tuple [ ReplValueKind.Binary; ReplValueKind.Binary ]
      ReplValueKind.Tuple [ ReplValueKind.Any; ReplValueKind.Any ]
      ReplValueKind.Tuple
        [ ReplValueKind.Fingerprint; ReplValueKind.Fingerprint ]
      ReplValueKind.Any ]

  let private sortActions actions =
    actions
    |> Map.toList
    |> List.map snd
    |> List.sortBy (fun action -> action.Metadata.ID.ToLowerInvariant())

  let private compatibleActions kind actions =
    actions
    |> List.filter (fun registered ->
      registered.Metadata.ID <> "print"
      && (ActionMetadata.acceptedInputs registered.Metadata
          |> List.exists (fun input ->
            ReplValueKind.isCompatible kind input)))

  let private fromMap actions =
    let all = sortActions actions
    let compatible =
      valueKinds
      |> List.map (fun kind -> kind, compatibleActions kind all)
      |> Map.ofList
    { Actions = actions
      AllSorted = all
      Compatible = compatible }

  let private addTypes registry (types: Type[]) =
    types
    |> Array.filter (fun typ ->
      typ.IsPublic
      && not typ.IsAbstract
      && not (isNull (typ.GetInterface(nameof IAction))))
    |> Array.fold (fun actions typ ->
      let action = Activator.CreateInstance typ :?> IAction
      if not (typeof<ICancellableAction>.IsAssignableFrom typ) then
        invalidOp
          $"REPL action '{action.ActionID}' must implement ICancellableAction."
      else
        ()
      let metadata = ActionMetadata.ofAction action
      let metadataID = metadata.ID.ToLowerInvariant()
      if Map.containsKey metadataID actions then
        invalidOp $"Duplicate action ID: {metadata.ID}"
      else
        Map.add metadataID { Action = action; Metadata = metadata } actions
    ) registry

  let private loadAssembly path registry =
    if File.Exists path then
      let assembly = Assembly.LoadFile(Path.GetFullPath path)
      addTypes registry (assembly.GetExportedTypes())
    else
      invalidOp $"File not found: {path}"

  let create dllPath =
    let initial =
      match dllPath with
      | Some path -> loadAssembly path Map.empty
      | None -> Map.empty
    let assembly = typeof<IAction>.Assembly
    assembly.GetExportedTypes()
    |> addTypes initial
    |> fromMap

  let tryFind (id: string) registry =
    registry.Actions |> Map.tryFind (id.ToLowerInvariant())

  let getAll registry =
    registry.AllSorted

  let getCompatible kind registry =
    match Map.tryFind kind registry.Compatible with
    | Some actions -> actions
    | None -> compatibleActions kind registry.AllSorted

  let toActionMap registry =
    registry.Actions |> Map.map (fun _ registered -> registered.Action)
