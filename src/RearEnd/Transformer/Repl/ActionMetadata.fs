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
  | SymbExecutor
  | SymbSolver
  | SymbRunResult
  | RegisterView
  | MemoryView
  | ExecutionTrace
  | ContextRequirements
  | Address
  | BinarySlice
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
  | ISA
  | Integer
  | Float
  | HexPattern
  | HexBytes
  | Address
  | Size
  | Section
  | Action
  | ParameterFunction
  | Choice

[<RequireQualifiedAccess>]
type ActionArgumentDefault =
  | Zero

/// A command-line argument accepted by an action.
type ActionArgument =
  { Name: string
    Kind: ActionArgumentKind
    IsOptional: bool
    DefaultValue: ActionArgumentDefault option
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
    Applicable: Map<ReplValueKind, RegisteredAction list> }

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
    | ReplValueKind.SymbExecutor -> "SymbExecutor"
    | ReplValueKind.SymbSolver -> "SymbSolver"
    | ReplValueKind.SymbRunResult -> "SymbRunResult"
    | ReplValueKind.RegisterView -> "RegisterView"
    | ReplValueKind.MemoryView -> "MemoryView"
    | ReplValueKind.ExecutionTrace -> "ExecutionTrace"
    | ReplValueKind.ContextRequirements -> "ContextRequirements"
    | ReplValueKind.Address -> "Address"
    | ReplValueKind.BinarySlice -> "BinarySlice"
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
      ReplValueKind.SymbExecutor
      ReplValueKind.SymbSolver
      ReplValueKind.SymbRunResult
      ReplValueKind.RegisterView
      ReplValueKind.MemoryView
      ReplValueKind.ExecutionTrace
      ReplValueKind.ContextRequirements
      ReplValueKind.Address
      ReplValueKind.BinarySlice
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
    | ActionArgumentKind.ISA -> "ISA"
    | ActionArgumentKind.Integer -> "Int"
    | ActionArgumentKind.Float -> "Float"
    | ActionArgumentKind.HexPattern -> "HexPattern"
    | ActionArgumentKind.HexBytes -> "HexBytes"
    | ActionArgumentKind.Address -> "Address"
    | ActionArgumentKind.Size -> "Size"
    | ActionArgumentKind.Section -> "Section"
    | ActionArgumentKind.Action -> "Action"
    | ActionArgumentKind.ParameterFunction -> "ParameterFunction"
    | ActionArgumentKind.Choice -> "Choice"

  let private argumentPlaceholder = function
    | ActionArgumentKind.Text -> "text"
    | ActionArgumentKind.Path
    | ActionArgumentKind.ExistingPath
    | ActionArgumentKind.OutputPath -> "path"
    | ActionArgumentKind.ISA -> "isa"
    | ActionArgumentKind.Integer -> "n"
    | ActionArgumentKind.Float -> "n"
    | ActionArgumentKind.HexPattern -> "hex-pattern"
    | ActionArgumentKind.HexBytes -> "hex"
    | ActionArgumentKind.Address -> "addr"
    | ActionArgumentKind.Size -> "size"
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

  let private signatureRows metadata =
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
      match syntaxes with
      | [] -> [ input, actionName metadata.ID, output ]
      | syntaxes -> syntaxes |> List.map (fun syntax -> input, syntax, output)
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
        input, body, output)
      |> List.distinct

  let typedSignature metadata =
    signatureRows metadata
    |> List.map (fun (input, body, output) ->
      $"{input} -> {body} -> {output}")
    |> String.concat " | "

  let typedSignatureLines metadata =
    match signatureRows metadata with
    | [] -> []
    | [ input, body, output ] -> [ $"{input} -> {body} -> {output}" ]
    | rows ->
      let firstInput, _, firstOutput = List.head rows
      let sameInputOutput =
        rows
        |> List.forall (fun (input, _, output) ->
          input = firstInput && output = firstOutput)
      if sameInputOutput then
        let prefix = $"{firstInput} -> "
        let continuation =
          String.replicate prefix.Length " " + "| "
        rows
        |> List.mapi (fun index (_, body, _) ->
          let line =
            if index = 0 then prefix + body else continuation + body
          if index = List.length rows - 1 then line + $" -> {firstOutput}"
          else line)
      else
        rows
        |> List.map (fun (input, body, output) ->
          $"{input} -> {body} -> {output}")
      |> List.distinct

  let argumentKeys (argument: ActionArgument) =
    [ argument.Name.ToLowerInvariant() ]

  let private argument name kind isOptional choices description =
    { Name = name
      Kind = kind
      IsOptional = isOptional
      DefaultValue = None
      Choices = choices
      Description = description }

  let private argumentDefault name kind defaultValue description =
    { Name = name
      Kind = kind
      IsOptional = true
      DefaultValue = Some defaultValue
      Choices = []
      Description = description }

  let private required name kind description =
    argument name kind false [] description

  let private optional name kind description =
    argument name kind true [] description

  let private optionalDefault name kind defaultValue description =
    argumentDefault name kind defaultValue description

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

  let possibleOutputs metadata inputKind =
    let metadata: ActionMetadata = metadata
    let outputs =
      metadata.Syntaxes
      |> List.filter (syntaxAccepts inputKind)
      |> List.choose (fun syntax -> syntax.Output)
      |> List.distinct
    if List.isEmpty outputs then [ metadata.Output ] else outputs

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

  let typedSignatureForLines metadata inputKind args =
    let metadata: ActionMetadata = metadata
    let syntaxes = matchingSyntaxes metadata inputKind args
    let syntaxes =
      if List.isEmpty syntaxes then metadata.Syntaxes else syntaxes
    typedSignatureLines { metadata with Syntaxes = syntaxes }

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
        "binary |> @cfg entry=<entry>"
        "function |> @cfg" ]
      [ syntaxForOutput [ ReplValueKind.Binary ] None
          (ReplValueKind.Collection ReplValueKind.CFG) []
        syntaxFor [ ReplValueKind.Binary ] None [ address ]
        syntaxFor [ ReplValueKind.FunctionInfo ] None [] ]

  let private bytes =
    overloadContract "bytes"
      [ ReplValueKind.Binary; ReplValueKind.BinarySlice ]
      ReplValueKind.ByteArray
      ActionRole.Transform 20 "bytes -> ByteArray"
      [ "binary |> @bytes" ] [ syntax None [] ]

  let private asBinary =
    contract "as-binary" ReplValueKind.ByteArray ReplValueKind.Binary
      ActionRole.Transform 10 "as-binary -> Binary"
      [ "rawBytes |> @as-binary" ] [ syntax None [] ]

  let private asm =
    let code =
      required "code" ActionArgumentKind.Text
        "Assembly instruction text."
    let isa =
      optional "isa" ActionArgumentKind.ISA
        "Instruction-set architecture."
    let baseAddress =
      optional "base" ActionArgumentKind.Address
        "Base address used for relative encodings."
    overloadContract "asm"
      [ ReplValueKind.Unit ]
      ReplValueKind.ByteArray
      ActionRole.Source 5
      "asm code=<text> [isa=<isa>] [base=<addr>] -> ByteArray"
      [ "@asm code=<assembly> isa=<isa>"
        "@asm code=<assembly> isa=<isa> base=<addr>" ]
      [ syntax None [ code ]
        syntax None [ code; isa ]
        syntax None [ code; baseAddress ]
        syntax None [ code; isa; baseAddress ] ]

  let private arg =
    let index =
      required "index" ActionArgumentKind.Integer
        "Zero-based integer argument index."
    let value =
      required "value" ActionArgumentKind.Address
        "Concrete integer or pointer value."
    contract "arg" ReplValueKind.ConcExecutor ReplValueKind.ConcExecutor
      ActionRole.Transform 20 "arg index=<n> value=<addr> -> ConcExecutor"
      [ "executor |> @arg index=<index> value=<addr>" ]
      [ syntax None [ index; value ] ]

  let private setReg =
    let name =
      required "name" ActionArgumentKind.Text "Register name."
    let value =
      required "value" ActionArgumentKind.Address
        "Concrete integer or pointer value."
    contract "set-reg" ReplValueKind.ConcExecutor
      ReplValueKind.ConcExecutor
      ActionRole.Transform 20
      "set-reg name=<reg> value=<value> -> ConcExecutor"
      [ "executor |> @set-reg name=<reg> value=<addr>" ]
      [ syntax None [ name; value ] ]

  let private setContext =
    let stack =
      optional "stack" ActionArgumentKind.Address
        "Stack pointer value to set."
    let regs =
      optional "regs" ActionArgumentKind.Text
        "Register assignments: [<reg>=<value>; RSP=sp]."
    let mem =
      optional "mem" ActionArgumentKind.Text
        "Memory assignments: [<addr>=<hex>]."
    let regions =
      optional "regions" ActionArgumentKind.Text
        "Memory regions: [name=<start>..<end>:rw]."
    contract "set-context" ReplValueKind.ConcExecutor
      ReplValueKind.ConcExecutor
      ActionRole.Transform 18
      ("set-context [stack=<addr>] [regs=[...]] [mem=[...]] "
       + "[regions=[...]] -> ConcExecutor")
      [ "executor |> @set-context regs=[<reg>=<value>; RSP=sp]"
        "executor |> @set-context mem=[<addr>=<hex>]"
        "executor |> @set-context regions=[buf=<start>..<end>:rw]" ]
      [ syntax None [ stack ]
        syntax None [ regs ]
        syntax None [ mem ]
        syntax None [ regions ]
        syntax None [ stack; regs ]
        syntax None [ stack; mem ]
        syntax None [ regs; mem ]
        syntax None [ stack; regs; mem ]
        syntax None [ stack; regs; mem; regions ] ]

  let private count =
    contract "count" ReplValueKind.Any ReplValueKind.Int
      ActionRole.Reducer 60 "count -> Int"
      [ "matches |> @count" ] [ syntax None [] ]

  let private concExec =
    overloadContract "make-concrete-executor"
      [ ReplValueKind.Binary; ReplValueKind.BinarySlice ]
      ReplValueKind.ConcExecutor
      ActionRole.Transform 20 "make-concrete-executor -> ConcExecutor"
      [ "binary |> @make-concrete-executor" ] [ syntax None [] ]

  let private dbscan =
    let eps = optional "eps" ActionArgumentKind.Float "Maximum distance."
    let minPts =
      optional "min-points" ActionArgumentKind.Integer
        "Minimum number of neighboring fingerprints."
    contract "dbscan" (ReplValueKind.Collection ReplValueKind.Fingerprint)
      ReplValueKind.ClusterResult ActionRole.Reducer 50
      "dbscan [eps=<n>] [min-points=<n>] -> ClusterResult"
      [ "fingerprints |> @dbscan eps=<eps> min-points=<minimum>" ]
      [ syntax None [ eps; minPts ] ]

  let private detect =
    let path =
      required "path" ActionArgumentKind.ExistingPath
        "File or directory to compare with the fingerprint."
    contract "detect" ReplValueKind.Fingerprint ReplValueKind.Text
      ActionRole.Transform 30 "detect path=<path> -> Text"
      [ "fingerprint |> @detect path=temp/bin" ] [ syntax None [ path ] ]

  let private diff =
    let pair left right = ReplValueKind.Tuple [ left; right ]
    let samePair kind = pair kind kind
    overloadContract "diff"
      [ samePair ReplValueKind.Binary
        samePair ReplValueKind.BinarySlice
        pair ReplValueKind.Binary ReplValueKind.BinarySlice
        pair ReplValueKind.BinarySlice ReplValueKind.Binary
        samePair ReplValueKind.ByteArray
        samePair ReplValueKind.InstructionArray
        samePair ReplValueKind.CFG
        samePair ReplValueKind.ConcExecutor
        samePair ReplValueKind.Text
        samePair ReplValueKind.TextArtifact ]
      ReplValueKind.Text ActionRole.Reducer 60
      "supported pair -> @diff -> Text"
      [ "let binaries = (oldBin, newBin)"
        "binaries |> @diff"
        "let code = (oldCode, newCode)"
        "code |> @diff" ] [ syntax None [] ]

  let private disasm =
    overloadContract "disasm"
      [ ReplValueKind.Binary; ReplValueKind.BinarySlice ]
      ReplValueKind.InstructionArray
      ActionRole.Transform 30 "disasm -> InstructionArray"
      [ "binary |> @disasm" ] [ syntax None [] ]

  let private dot =
    contract "dot" ReplValueKind.CFG ReplValueKind.TextArtifact
      ActionRole.Transform 10 "dot -> TextArtifact"
      [ "graph |> @dot" ] [ syntax None [] ]

  let private edit =
    let start =
      required "start" ActionArgumentKind.Address "Starting address."
    let finish =
      required "end" ActionArgumentKind.Address
        "Exclusive end address."
    let size =
      required "size" ActionArgumentKind.Size
        "Positive byte count relative to the start address."
    let bytes =
      required "hex" ActionArgumentKind.HexBytes
        "Replacement bytes as a hexadecimal string."
    let binary = [ ReplValueKind.Binary ]
    let slice = [ ReplValueKind.BinarySlice ]
    let forEditInputs trigger args =
      [ syntaxForOutput binary trigger ReplValueKind.Binary args
        syntaxForOutput slice trigger ReplValueKind.BinarySlice args ]
    let syntaxes =
      [ yield! forEditInputs (Some "insert") [ start; bytes ]
        yield! forEditInputs (Some "delete") [ start; finish ]
        yield! forEditInputs (Some "delete") [ start; size ]
        yield! forEditInputs (Some "replace") [ start; finish; bytes ]
        yield! forEditInputs (Some "replace") [ start; size; bytes ] ]
    overloadContract "edit"
      [ ReplValueKind.Binary; ReplValueKind.BinarySlice ]
      ReplValueKind.Binary
      ActionRole.Transform 40 "edit <operation> ..."
      [ "binary |> @edit insert start=<addr> hex=<hex>"
        "binary |> @edit delete start=<addr> size=<size>"
        "binary |> @edit replace start=<addr> size=<size> hex=<hex>" ]
      syntaxes

  let private grep =
    let pattern =
      required "pattern" ActionArgumentKind.HexPattern
        "Regular expression over hexadecimal byte pairs."
    let context =
      optional "context" ActionArgumentKind.Integer
        "Context bytes on both sides of each match."
    let before =
      optionalDefault "before" ActionArgumentKind.Integer
        ActionArgumentDefault.Zero
        "Context bytes preceding each match."
    let after =
      optionalDefault "after" ActionArgumentKind.Integer
        ActionArgumentDefault.Zero
        "Context bytes following each match."
    let byPattern =
      "grep pattern=<hex> [context=<n>] | "
      + "pattern=<hex> [before=<n>] [after=<n>] "
      + "-> BinarySlice collection"
    let byBytes =
      "grep [context=<n>] | [before=<n>] [after=<n>] "
      + "-> BinarySlice collection"
    overloadContract "grep"
      [ ReplValueKind.Binary
        ReplValueKind.BinarySlice
        ReplValueKind.Tuple [ ReplValueKind.Binary; ReplValueKind.ByteArray ]
        ReplValueKind.Tuple
          [ ReplValueKind.BinarySlice; ReplValueKind.ByteArray ] ]
      (ReplValueKind.Collection ReplValueKind.BinarySlice)
      ActionRole.Transform 30 (byPattern + " | " + byBytes)
      [ "binary |> @grep pattern=<hex-pattern>"
        "binary |> @grep pattern=<hex-pattern> context=<size>"
        "binary |> @grep pattern=<hex-pattern> before=<n> after=<n>"
        "(binary, needle) |> @grep before=<n> after=<n>" ]
      [ syntaxFor [ ReplValueKind.Binary; ReplValueKind.BinarySlice ]
          None [ pattern; context ]
        syntaxFor [ ReplValueKind.Binary; ReplValueKind.BinarySlice ]
          None [ pattern; before; after ]
        syntaxFor
          [ ReplValueKind.Tuple
              [ ReplValueKind.Binary; ReplValueKind.ByteArray ]
            ReplValueKind.Tuple
              [ ReplValueKind.BinarySlice; ReplValueKind.ByteArray ] ]
          None [ context ]
        syntaxFor
          [ ReplValueKind.Tuple
              [ ReplValueKind.Binary; ReplValueKind.ByteArray ]
            ReplValueKind.Tuple
              [ ReplValueKind.BinarySlice; ReplValueKind.ByteArray ] ]
          None [ before; after ] ]

  let private hexdump =
    overloadContract "hexdump"
      [ ReplValueKind.Binary; ReplValueKind.BinarySlice ]
      ReplValueKind.Text
      ActionRole.Transform 30 "hexdump -> Text"
      [ "binary |> @hexdump" ] [ syntax None [] ]

  let private jaccard =
    let input =
      ReplValueKind.Tuple
        [ ReplValueKind.Fingerprint; ReplValueKind.Fingerprint ]
    contract "jaccard" input ReplValueKind.Float
      ActionRole.Reducer 60 "Fingerprint * Fingerprint -> @jaccard -> Float"
      [ "let fingerprints = (leftFingerprint, rightFingerprint)"
        "fingerprints |> @jaccard" ] [ syntax None [] ]

  let private regs =
    let register =
      optional "name" ActionArgumentKind.Text
        "Register name to print; defaults to all defined registers."
    contract "regs" ReplValueKind.ConcExecutor ReplValueKind.RegisterView
      ActionRole.Transform 20 "regs [name=<reg>] -> RegisterView"
      [ "executor |> @regs"; "executor |> @regs name=RAX" ]
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
    contract "run-concrete" ReplValueKind.ConcExecutor
      ReplValueKind.ConcExecutor
      ActionRole.Transform 20
      ("run-concrete [entry=<addr>] [limit=<n>] [break=<addr>]"
       + " -> ConcExecutor")
      [ "executor |> @run-concrete entry=<entry> limit=<limit>"
        "executor |> @run-concrete entry=<entry> limit=<limit> break=<addr>" ]
      [ syntax None [ entry; limit; breakpoint ] ]

  let private lift =
    overloadContract "lift"
      [ ReplValueKind.Binary; ReplValueKind.BinarySlice ]
      ReplValueKind.Text
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
      [ "@load path=<path>"
        "@load hex=<hex> isa=<isa>" ]
      [ syntax None [ source; optionalISA ]
        syntax None [ hex; requiredISA ] ]

  let private random =
    let minAddress =
      required "min" ActionArgumentKind.Address
        "Inclusive lower address bound."
    let maxAddress =
      required "max" ActionArgumentKind.Address
        "Exclusive upper address bound."
    contract "random" ReplValueKind.Unit ReplValueKind.Address
      ActionRole.Source 20
      "random min=<addr> max=<addr> -> Address"
      [ "let ptr = @random min=<min> max=<max>" ]
      [ syntax None [ minAddress; maxAddress ] ]

  let private userStack =
    contract "user-stack" ReplValueKind.Unit ReplValueKind.Address
      ActionRole.Source 19 "user-stack -> Address"
      [ "let sp = @user-stack" ] [ syntax None [] ]

  let private mem =
    let addr =
      required "addr" ActionArgumentKind.Address
        "Starting concrete memory address."
    let size =
      required "size" ActionArgumentKind.Integer
        "Number of bytes to read."
    let bytes =
      required "bytes" ActionArgumentKind.HexBytes
        "Bytes to write as a hexadecimal string."
    let signature =
      "mem read addr=<addr> size=<n> -> MemoryView | "
      + "mem write addr=<addr> bytes=<hex> -> ConcExecutor"
    contract "mem" ReplValueKind.ConcExecutor
      ReplValueKind.Any
      ActionRole.Transform 20
      signature
      [ "executor |> @mem read addr=<addr> size=<size>"
        "executor |> @mem write addr=<addr> bytes=<hex>" ]
      [ syntaxOutput (Some "read") ReplValueKind.MemoryView [ addr; size ]
        syntaxOutput (Some "write") ReplValueKind.ConcExecutor
          [ addr; bytes ] ]

  let private pick =
    let index =
      required "index" ActionArgumentKind.Integer
        "One-based value index in the current collection."
    contract "pick" (ReplValueKind.Collection ReplValueKind.Any)
      ReplValueKind.Any
      ActionRole.Transform 5 "pick index=<n> -> Any"
      [ "graphs |> @pick index=<index>" ] [ syntax None [ index ] ]

  let private print =
    contract "print" ReplValueKind.Any ReplValueKind.Unit
      ActionRole.Sink 100 "print -> Unit" [] [ syntax None [] ]

  let private slice =
    let section =
      required "section" ActionArgumentKind.Section "Section name."
    let start =
      required "start" ActionArgumentKind.Address "Starting address."
    let finish =
      required "end" ActionArgumentKind.Address
        "Exclusive end address."
    let offset =
      required "offset" ActionArgumentKind.Size
        "Positive size relative to the start address."
    let signature =
      "slice section=<section> | start=<addr> end=<addr> | "
      + "start=<addr> offset=<size> -> BinarySlice"
    overloadContract "slice"
      [ ReplValueKind.Binary; ReplValueKind.BinarySlice ]
      ReplValueKind.BinarySlice
      ActionRole.Transform 10 signature
      [ "binary |> @slice section=.text"
        "binary |> @slice start=<start> offset=<size>" ]
      [ syntax None [ section ]
        syntax None [ start; finish ]
        syntax None [ start; offset ] ]

  let private step =
    let count =
      optional "count" ActionArgumentKind.Integer
        "Number of machine instructions; defaults to one."
    contract "step" ReplValueKind.ConcExecutor ReplValueKind.ConcExecutor
      ActionRole.Transform 20 "step [count=<n>] -> ConcExecutor"
      [ "executor |> @step"; "executor |> @step count=<count>" ]
      [ syntax None [ count ] ]

  let private trace =
    let count =
      optional "count" ActionArgumentKind.Integer
        "Number of machine instructions; defaults to one."
    let watch =
      required "watch" ActionArgumentKind.Address
        "Optional memory address for before/after watch output."
    let size =
      required "size" ActionArgumentKind.Integer
        "Number of watched memory bytes."
    contract "trace" ReplValueKind.ConcExecutor ReplValueKind.ExecutionTrace
      ActionRole.Transform 20
      "trace [count=<n>] [watch=<addr> size=<n>] -> ExecutionTrace"
      [ "executor |> @trace"
        "executor |> @trace count=<count>"
        "executor |> @trace count=<count> watch=<addr> size=<size>" ]
      [ syntax None []
        syntax None [ count ]
        syntax None [ watch; size ]
        syntax None [ count; watch; size ] ]

  let private strings =
    let minimum =
      optional "min" ActionArgumentKind.Integer
        "Minimum printable string length; defaults to four."
    let pattern =
      optional "pattern" ActionArgumentKind.Text
        "Case-insensitive substring filter."
    overloadContract "strings"
      [ ReplValueKind.Binary; ReplValueKind.BinarySlice ]
      (ReplValueKind.Collection ReplValueKind.StringMatch)
      ActionRole.Transform 10
      "strings [min=<n>] [pattern=<text>] -> StringMatch collection"
      [ "binary |> @strings"
        "binary |> @strings pattern=ADMIN"
        "binary |> @strings min=<length> pattern=EXPORT" ]
      [ syntax None [ minimum; pattern ] ]

  let private save =
    let path =
      required "path" ActionArgumentKind.OutputPath "Destination file path."
    overloadContract "save"
      [ ReplValueKind.Binary; ReplValueKind.BinarySlice ]
      ReplValueKind.Unit
      ActionRole.Sink 90 "save path=<path> -> Unit"
      [ "binary |> @save path=out.bin" ] [ syntax None [ path ] ]

  let private winnowing =
    let ngram =
      optional "n-gram-size" ActionArgumentKind.Integer
        "N-gram size; defaults to four."
    let window =
      optional "window-size" ActionArgumentKind.Integer
        "Window size; defaults to four."
    overloadContract "winnowing"
      [ ReplValueKind.Binary; ReplValueKind.BinarySlice ]
      ReplValueKind.Fingerprint
      ActionRole.Transform 40
      "winnowing [n-gram-size=<n>] [window-size=<n>] -> Fingerprint"
      [ "binary |> @winnowing n-gram-size=<n> window-size=<n>" ]
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
      asm
      arg
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
      mem
      pick
      print
      random
      regs
      run
      setContext
      setReg
      slice
      step
      trace
      userStack
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
      ReplValueKind.SymbExecutor
      ReplValueKind.SymbSolver
      ReplValueKind.SymbRunResult
      ReplValueKind.RegisterView
      ReplValueKind.MemoryView
      ReplValueKind.ExecutionTrace
      ReplValueKind.ContextRequirements
      ReplValueKind.Address
      ReplValueKind.BinarySlice
      ReplValueKind.StringMatch
      ReplValueKind.SectionInfo
      ReplValueKind.FunctionInfo
      ReplValueKind.Collection ReplValueKind.CFG
      ReplValueKind.Collection ReplValueKind.Fingerprint
      ReplValueKind.Collection ReplValueKind.SectionInfo
      ReplValueKind.Collection ReplValueKind.FunctionInfo
      ReplValueKind.Collection ReplValueKind.StringMatch
      ReplValueKind.Collection ReplValueKind.BinarySlice
      ReplValueKind.Collection ReplValueKind.Any
      ReplValueKind.List ReplValueKind.Any
      ReplValueKind.Array ReplValueKind.Any
      ReplValueKind.Int
      ReplValueKind.Float
      ReplValueKind.Bool
      ReplValueKind.Tuple [ ReplValueKind.Binary; ReplValueKind.ByteArray ]
      ReplValueKind.Tuple
        [ ReplValueKind.BinarySlice; ReplValueKind.ByteArray ]
      ReplValueKind.Tuple [ ReplValueKind.Binary; ReplValueKind.Binary ]
      ReplValueKind.Tuple
        [ ReplValueKind.BinarySlice; ReplValueKind.BinarySlice ]
      ReplValueKind.Tuple
        [ ReplValueKind.Binary; ReplValueKind.BinarySlice ]
      ReplValueKind.Tuple
        [ ReplValueKind.BinarySlice; ReplValueKind.Binary ]
      ReplValueKind.Tuple
        [ ReplValueKind.ConcExecutor; ReplValueKind.ConcExecutor ]
      ReplValueKind.Tuple [ ReplValueKind.Any; ReplValueKind.Any ]
      ReplValueKind.Tuple
        [ ReplValueKind.Fingerprint; ReplValueKind.Fingerprint ]
      ReplValueKind.Any ]

  let private sortActions actions =
    actions
    |> Map.toList
    |> List.map snd
    |> List.sortBy (fun action -> action.Metadata.ID.ToLowerInvariant())

  let private applicableActions kind actions =
    actions
    |> List.filter (fun registered ->
      registered.Metadata.ID <> "print"
      && (ActionMetadata.acceptedInputs registered.Metadata
          |> List.exists (fun input ->
            ReplValueKind.isCompatible kind input)))

  let private fromMap actions =
    let all = sortActions actions
    let applicable =
      valueKinds
      |> List.map (fun kind -> kind, applicableActions kind all)
      |> Map.ofList
    { Actions = actions
      AllSorted = all
      Applicable = applicable }

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
    TransformerPluginLoader.exportedTypes path
    |> addTypes registry

  let create dllPath =
    let initial =
      match dllPath with
      | Some path -> loadAssembly path Map.empty
      | None -> Map.empty
    let assembly = typeof<IAction>.Assembly
    assembly.GetExportedTypes()
    |> addTypes initial
    |> fromMap

  let loadPlugin path registry =
    loadAssembly path (registry: ActionRegistry).Actions |> fromMap

  let tryFind (id: string) registry =
    registry.Actions |> Map.tryFind (id.ToLowerInvariant())

  let getAll registry =
    registry.AllSorted

  let getApplicable kind registry =
    match Map.tryFind kind registry.Applicable with
    | Some actions -> actions
    | None -> applicableActions kind registry.AllSorted

  let toActionMap registry =
    registry.Actions |> Map.map (fun _ registered -> registered.Action)
