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
open System.Globalization
open System.Text
open System.Text.RegularExpressions
open System.Threading
open B2R2
open B2R2.BinIR
open B2R2.MiddleEnd.SymbEval

type SymbSolverFactory = Func<ISolver>

type SymbSolverValue(id: string,
                     description: string,
                     create: SymbSolverFactory) =
  member _.ID = id

  member _.Description = description

  member _.Create() = create.Invoke()

  override _.ToString() =
    $"SymbSolver{Environment.NewLine}  id: @{id}"
    + $"{Environment.NewLine}  description: {description}"

module SymbSolverRegistry =
  let private factories =
    ConcurrentDictionary<string, string * SymbSolverFactory>()

  let private normalize (id: string) =
    let id = id.Trim()
    let id =
      if id.StartsWith("@", StringComparison.Ordinal) then id[1..]
      else id
    id.ToLowerInvariant()

  let register id description factory =
    factories[normalize id] <- description, factory

  let create id =
    match factories.TryGetValue(normalize id) with
    | true, (description, factory) ->
      SymbSolverValue(normalize id, description, factory) |> Some
    | _ -> None

type SymbolicInput =
  { Name: string
    Address: Addr
    Size: int
    Buffer: SymbByteBuffer }

type SymbMemoryAssignment =
  { Address: Addr
    Bytes: byte[] }

type SymbSymbolicMemoryAssignment =
  { Name: string
    Address: Addr
    Size: int }

type SymbContextSpec =
  { PC: Addr option
    Stack: Addr option
    Registers: (string * Addr) list
    Memory: SymbMemoryAssignment list
    SymbolicMemory: SymbSymbolicMemoryAssignment list }

type SymbExecutorValue(binary: Binary,
                       state: SymbState,
                       inputs: SymbolicInput list,
                       avoids: Set<Addr>,
                       hooks: SymbCallHookRegistry option,
                       hookText: string list,
                       solver: SymbSolverValue option) as this =
  let executor = SymbExecutor(Binary.Handle binary)

  new(binary: Binary) =
    let executor = SymbExecutor(Binary.Handle binary)
    SymbExecutorValue(binary,
                      executor.CreateState(),
                      [],
                      Set.empty,
                      None,
                      [],
                      None)

  member _.Binary = binary

  member _.State = state

  member _.Inputs = inputs

  member _.Avoids = avoids

  member _.Hooks = hooks

  member _.Solver = solver

  member _.WithSolver solverValue =
    SymbExecutorValue(binary,
                      state,
                      inputs,
                      avoids,
                      hooks,
                      hookText,
                      Some solverValue)

  member _.WithPC pc =
    let state = state.Clone()
    state.PC <- pc
    SymbExecutorValue(binary, state, inputs, avoids, hooks, hookText, solver)

  member _.WithStack top =
    let state = state.Clone()
    let accessor = SymbStateAccessor(Binary.Handle binary, state)
    match accessor.TrySetStackPointer top with
    | Ok() ->
      SymbExecutorValue(binary, state, inputs, avoids, hooks, hookText, solver)
    | Error error -> invalidOp $"{error}"

  member _.WithRegister(name: string, value) =
    let state = state.Clone()
    let accessor = SymbStateAccessor(Binary.Handle binary, state)
    accessor.SetRegister(name, accessor.WordValue value)
    SymbExecutorValue(binary, state, inputs, avoids, hooks, hookText, solver)

  member _.WithConcreteMemory(addr, bytes: byte[]) =
    let state = state.Clone()
    bytes |> Array.iteri (fun idx byte ->
      let value = SymbExpr.Const(BitVector(uint64 byte, 8<rt>))
      state.Memory.ByteWrite(addr + uint64 idx, value))
    SymbExecutorValue(binary, state, inputs, avoids, hooks, hookText, solver)

  member _.WithSymbolicMemory(addr, name, size) =
    let state = state.Clone()
    let accessor = SymbStateAccessor(Binary.Handle binary, state)
    let buffer = accessor.WriteSymbolicBuffer(name, addr, size)
    let input =
      { Name = name
        Address = buffer.Address
        Size = size
        Buffer = buffer }
    SymbExecutorValue(binary,
                      state,
                      input :: inputs,
                      avoids,
                      hooks,
                      hookText,
                      solver)

  member _.WithSymbolicArgument(index, name, size) =
    let state = state.Clone()
    let accessor = SymbStateAccessor(Binary.Handle binary, state)
    let buffer = accessor.AllocateSymbolicBuffer(name, size)
    accessor.SetArgumentBuffer(index, buffer)
    let input =
      { Name = name
        Address = buffer.Address
        Size = size
        Buffer = buffer }
    SymbExecutorValue(binary,
                      state,
                      input :: inputs,
                      avoids,
                      hooks,
                      hookText,
                      solver)

  member _.WithAvoid addr =
    SymbExecutorValue(binary,
                      state,
                      inputs,
                      Set.add addr avoids,
                      hooks,
                      hookText,
                      solver)

  member _.WithStrlenHook addr =
    let registry =
      hooks
      |> Option.defaultValue (SymbCallHookRegistry())
      |> fun registry -> registry.Register(addr, SymbCallHooks.strlen)
    let hookText = $"strlen@0x{addr:x}" :: hookText
    SymbExecutorValue(binary,
                      state,
                      inputs,
                      avoids,
                      Some registry,
                      hookText,
                      solver)

  member this.WithContext(spec: SymbContextSpec) =
    let applyPC (executor: SymbExecutorValue) =
      spec.PC
      |> Option.map executor.WithPC
      |> Option.defaultValue executor
    let applyStack (executor: SymbExecutorValue) =
      spec.Stack
      |> Option.map executor.WithStack
      |> Option.defaultValue executor
    let applyRegister (executor: SymbExecutorValue) (name, value) =
      executor.WithRegister(name, value)
    let applyMemory (executor: SymbExecutorValue)
                    (assignment: SymbMemoryAssignment) =
      executor.WithConcreteMemory(assignment.Address, assignment.Bytes)
    let applySymbolicMemory (executor: SymbExecutorValue)
                            (assignment: SymbSymbolicMemoryAssignment) =
      executor.WithSymbolicMemory(assignment.Address,
                                  assignment.Name,
                                  assignment.Size)
    let executor = applyPC this |> applyStack
    let executor = spec.Registers |> List.fold applyRegister executor
    let executor = spec.Memory |> List.fold applyMemory executor
    spec.SymbolicMemory |> List.fold applySymbolicMemory executor

  member _.CallPolicy =
    match hooks with
    | Some registry -> UseCallHooks registry
    | None -> FollowDirectInternalCalls

  member _.SolverBackend =
    solver
    |> Option.map (fun solver -> CustomSolver(solver.Create()))
    |> Option.defaultValue NoSolver

  member _.RunSatisfy(target, maxDepth, maxStates, loopBound, prune) =
    let query =
      { Query = SatisfyAddress target
        QueryValues =
          inputs
          |> List.rev
          |> List.map (fun input -> input.Buffer :> IQueryExpr)
          |> QueryExpr.Values }
    let options =
      { SymbRunOptions.Default(query, this.SolverBackend) with
          Calls = this.CallPolicy
          Avoid = AvoidAddresses avoids
          MaxDepth = maxDepth
          MaxStates = maxStates
          LoopBound = loopBound
          PruneInfeasiblePaths = prune }
    executor.Run(state.PC, state, options)
    |> fun result -> SymbRunValue(this, "satisfy", target, result)

  member _.RunReach(target, maxDepth, maxStates, loopBound, prune) =
    let options =
      { SymbRunOptions.Default(ReachAddress target, this.SolverBackend) with
          Calls = this.CallPolicy
          Avoid = AvoidAddresses avoids
          MaxDepth = maxDepth
          MaxStates = maxStates
          LoopBound = loopBound
          PruneInfeasiblePaths = prune }
    executor.Run(state.PC, state, options)
    |> fun result -> SymbRunValue(this, "reach", target, result)

  override _.ToString() =
    let inputText =
      match List.rev inputs with
      | [] -> "none"
      | inputs ->
        inputs
        |> List.map (fun input ->
          $"{input.Name}@0x{input.Address:x}({input.Size} bytes)")
        |> String.concat ", "
    let avoidText =
      if Set.isEmpty avoids then
        "none"
      else
        avoids
        |> Seq.map (fun addr -> $"0x{addr:x}")
        |> String.concat ", "
    let hookText =
      match List.rev hookText with
      | [] -> "none"
      | hooks -> String.concat ", " hooks
    let solverText =
      solver
      |> Option.map (fun solver -> "@" + solver.ID)
      |> Option.defaultValue "none"
    "SymbExecutor"
    + $"{Environment.NewLine}  binary: {binary}"
    + $"{Environment.NewLine}  pc: 0x{state.PC:x}"
    + $"{Environment.NewLine}  solver: {solverText}"
    + $"{Environment.NewLine}  symbolic inputs: {inputText}"
    + $"{Environment.NewLine}  avoid: {avoidText}"
    + $"{Environment.NewLine}  hooks: {hookText}"

and SymbRunValue(source: SymbExecutorValue,
                 query: string,
                 target: Addr,
                 result: SymbRunResult) =
  let valueText (value: SolverValue) =
    $"  {value.Name}: {value.Value}"

  let tryIndexedByte (value: SolverValue) =
    let m = Regex.Match(value.Name, "^(.+)_([0-9]+)$")
    if m.Success && value.Value.Length = 8<rt> then
      let prefix = m.Groups[1].Value
      let index = Int32.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture)
      Some(prefix, index, byte (value.Value.ToUInt64()))
    else
      None

  let printableAscii bytes =
    bytes
    |> Array.map (fun byte ->
      if byte >= 0x20uy && byte <= 0x7euy then char byte else '.')
    |> String

  let appendAsciiGroups (sb: StringBuilder) values =
    let groups =
      values
      |> List.choose tryIndexedByte
      |> List.groupBy (fun (prefix, _, _) -> prefix)
      |> List.choose (fun (prefix, indexed) ->
        let indexed = indexed |> List.sortBy (fun (_, index, _) -> index)
        let indexes = indexed |> List.map (fun (_, index, _) -> index)
        let expected = [ 0 .. List.length indexes - 1 ]
        if indexes = expected then
          indexed
          |> List.map (fun (_, _, value) -> value)
          |> List.toArray
          |> fun bytes -> Some(prefix, printableAscii bytes)
        else
          None)
    if List.isEmpty groups then
      ()
    else
      sb.AppendLine("  ascii:") |> ignore
      groups |> List.iter (fun (prefix, text) ->
        sb.AppendLine($"    {prefix}: {text}") |> ignore)

  let statusText =
    match result with
    | SymbRunResult.Reachable answers ->
      $"reachable ({List.length answers} answer(s))"
    | SymbRunResult.Unreachable -> "unreachable"
    | SymbRunResult.Satisfiable answers ->
      $"satisfiable ({List.length answers} model(s))"
    | SymbRunResult.Unsatisfiable -> "unsatisfiable"
    | SymbRunResult.Unknown failures ->
      $"unknown ({List.length failures} failure(s))"
    | SymbRunResult.TimedOut(timeout, _) ->
      $"timed out after {timeout} ms"

  let appendInputModels (sb: StringBuilder) values =
    if List.isEmpty values then
      sb.AppendLine("  values: none") |> ignore
    else
      sb.AppendLine("  values:") |> ignore
      values |> List.iter (fun value ->
        sb.AppendLine(valueText value) |> ignore)
      appendAsciiGroups sb values

  let appendSatAnswer
        (sb: StringBuilder)
        index
        (answer: SymbSatisfiabilityAnswer) =
    sb.AppendLine($"answer #{index}") |> ignore
    sb.AppendLine($"  target: 0x{answer.Target:x}") |> ignore
    sb.AppendLine(
      $"  path-conditions: {List.length answer.State.PathCondition}")
    |> ignore
    appendInputModels sb answer.Values

  let appendReachAnswer
        (sb: StringBuilder)
        index
        (answer: SymbReachabilityAnswer) =
    sb.AppendLine($"answer #{index}") |> ignore
    sb.AppendLine($"  target: 0x{answer.Target:x}") |> ignore
    sb.AppendLine(
      $"  path-conditions: {List.length answer.State.PathCondition}")
    |> ignore

  let appendFailure (sb: StringBuilder) index (failure: SymbRunFailure) =
    sb.AppendLine($"failure #{index}: {failure}") |> ignore

  member _.Source = source

  member _.Result = result

  member _.ModelText() =
    let sb = StringBuilder()
    let rec appendResult = function
      | SymbRunResult.Satisfiable answers ->
        answers |> List.iteri (fun idx answer ->
          appendSatAnswer sb (idx + 1) answer)
      | SymbRunResult.Reachable answers ->
        answers |> List.iteri (fun idx answer ->
          appendReachAnswer sb (idx + 1) answer)
      | SymbRunResult.Unknown failures ->
        failures |> List.iteri (fun idx failure ->
          appendFailure sb (idx + 1) failure)
      | SymbRunResult.TimedOut(_, result) -> appendResult result
      | SymbRunResult.Unreachable ->
        sb.AppendLine("unreachable") |> ignore
      | SymbRunResult.Unsatisfiable ->
        sb.AppendLine("unsatisfiable") |> ignore
    appendResult result
    sb.ToString().TrimEnd()

  override this.ToString() =
    let header =
      "SymbRunResult"
      + $"{Environment.NewLine}  query: {query}"
      + $"{Environment.NewLine}  target: 0x{target:x}"
      + $"{Environment.NewLine}  status: {statusText}"
    let model = this.ModelText()
    if String.IsNullOrWhiteSpace model then header
    else header + Environment.NewLine + model

module private SymbArgs =
  let parseAddr (text: string) =
    if text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
      UInt64.Parse(text.Substring 2, NumberStyles.HexNumber,
                   CultureInfo.InvariantCulture)
    else
      UInt64.Parse(text, CultureInfo.InvariantCulture)

  let parseInt (text: string) =
    Int32.Parse(text, CultureInfo.InvariantCulture)

  let parseBool (text: string) =
    match text.ToLowerInvariant() with
    | "true" | "yes" | "on" -> true
    | "false" | "no" | "off" -> false
    | _ -> invalidArg (nameof text) $"Invalid boolean value: {text}"

  let parseHexBytes (text: string) =
    let text =
      text.Replace(" ", String.Empty).Replace("_", String.Empty)
    let text =
      if text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        text.Substring 2
      else
        text
    if text.Length % 2 <> 0 then
      invalidArg (nameof text) "Hex byte strings must have an even length."
    else
      [| for index in 0 .. 2 .. text.Length - 2 ->
           Byte.Parse(text.Substring(index, 2),
                      NumberStyles.HexNumber,
                      CultureInfo.InvariantCulture) |]

  let private trimBrackets (text: string) =
    let text = text.Trim()
    if text.StartsWith("[", StringComparison.Ordinal)
       && text.EndsWith("]", StringComparison.Ordinal) then
      text[1..text.Length - 2].Trim()
    else
      text

  let private contextEntries text =
    let text = trimBrackets text
    text.Split([| ';'; ',' |], StringSplitOptions.RemoveEmptyEntries)
    |> Array.map _.Trim()
    |> Array.filter (String.IsNullOrWhiteSpace >> not)

  let private splitAssignment (entry: string) =
    let index = entry.IndexOf '='
    if index <= 0 then
      invalidArg (nameof entry) $"Expected key=value entry: {entry}"
    else
      entry[..index - 1].Trim(), entry[index + 1..].Trim()

  let private parseMemoryAssignment entry =
    let addr, hex = splitAssignment entry
    { Address = parseAddr addr
      Bytes = parseHexBytes hex }

  let private parseSymbolicMemoryAssignment (entry: string) =
    let nameIndex = entry.IndexOf '@'
    let sizeIndex = entry.LastIndexOf ':'
    if nameIndex <= 0 || sizeIndex <= nameIndex + 1 then
      invalidArg (nameof entry)
        $"Expected symbolic memory entry name@addr:size: {entry}"
    else
      { Name = entry[..nameIndex - 1].Trim()
        Address = parseAddr (entry[nameIndex + 1..sizeIndex - 1].Trim())
        Size = parseInt (entry[sizeIndex + 1..].Trim()) }

  let parseContext args =
    let rec loop spec = function
      | [] -> spec
      | (token: string) :: rest ->
        let index = token.IndexOf '='
        if index <= 0 then
          invalidArg (nameof args) $"Expected name=value parameter: {token}"
        else
          let key = token[..index - 1].Trim().ToLowerInvariant()
          let value = token[index + 1..].Trim()
          let spec =
            match key with
            | "pc" ->
              { spec with PC = Some(parseAddr value) }
            | "stack" ->
              { spec with Stack = Some(parseAddr value) }
            | "regs" | "registers" ->
              let registers =
                contextEntries value
                |> Array.toList
                |> List.map (fun entry ->
                  let name, value = splitAssignment entry
                  name, parseAddr value)
              { spec with Registers = spec.Registers @ registers }
            | "mem" | "memory" ->
              let memory =
                contextEntries value
                |> Array.toList
                |> List.map parseMemoryAssignment
              { spec with Memory = spec.Memory @ memory }
            | "sym-mem" | "symbolic-memory" ->
              let symbolic =
                contextEntries value
                |> Array.toList
                |> List.map parseSymbolicMemoryAssignment
              { spec with SymbolicMemory = spec.SymbolicMemory @ symbolic }
            | _ ->
              invalidArg (nameof args) $"Unknown symb-context parameter: {key}"
          loop spec rest
    let empty =
      { PC = None
        Stack = None
        Registers = []
        Memory = []
        SymbolicMemory = [] }
    loop empty args

  let defaults args =
    let maxDepth =
      args |> List.tryItem 0 |> Option.map parseInt |> Option.defaultValue 512
    let maxStates =
      args |> List.tryItem 1 |> Option.map parseInt |> Option.defaultValue 2048
    let loopBound =
      args |> List.tryItem 2 |> Option.map parseInt |> Option.defaultValue 2
    let prune =
      args |> List.tryItem 3 |> Option.map parseBool |> Option.defaultValue true
    maxDepth, maxStates, loopBound, prune

module private SymbMetadata =
  let arg name kind optional description =
    { Name = name
      Kind = kind
      IsOptional = optional
      Choices = []
      Description = description }

  let choice name optional choices description =
    { Name = name
      Kind = ActionArgumentKind.Choice
      IsOptional = optional
      Choices = choices
      Description = description }

  let syntax trigger args =
    { Trigger = trigger
      Arguments = args
      Inputs = []
      Output = None }

  let metadata id input output role signature description examples =
    { ID = id
      Input = input
      AlternativeInputs = []
      Output = output
      Role = role
      Syntaxes = []
      Signature = signature
      Description = description
      Examples = examples
      Priority = 20 }

type SymbExecAction() =
  let solver =
    SymbMetadata.arg "solver" ActionArgumentKind.Action true
      "Solver provider action, such as @symb-z3."
  let metadata =
    let signature =
      "Binary | BinarySlice -> @symb-exec [solver:Action=<action>] "
      + "-> SymbExecutor"
    { SymbMetadata.metadata
        "symb-exec"
        ReplValueKind.Binary
        ReplValueKind.SymbExecutor
        ActionRole.Transform
        signature
        "Create a symbolic executor over a binary or binary slice."
        [ "let sx = bin |> @symb-exec solver=@symb-z3" ] with
        AlternativeInputs = [ ReplValueKind.BinarySlice ]
        Syntaxes = [ SymbMetadata.syntax None [ solver ] ] }

  let findSolver = function
    | [] -> None
    | [ solver ] ->
      match SymbSolverRegistry.create solver with
      | Some solver -> Some solver
      | None -> invalidArg (nameof solver) $"Unknown solver: {solver}"
    | _ -> invalidArg "args" "Invalid symb-exec arguments."

  let transformOne solver (value: obj) =
    let executor =
      match value with
      | :? Binary as binary -> SymbExecutorValue binary
      | :? BinarySlice as slice -> SymbExecutorValue(slice.ToBinary())
      | value -> invalidOp $"symb-exec expects Binary: {value}"
    solver
    |> Option.map executor.WithSolver
    |> Option.defaultValue executor
    |> box

  let transform args (collection: ObjCollection) =
    let solver = findSolver args
    collection.Values |> Array.map (transformOne solver) |> fun values ->
      { Values = values }

  interface IAction with
    member _.ActionID with get() = metadata.ID
    member _.Signature with get() = metadata.Signature
    member _.Description with get() = metadata.Description
    member _.Transform(args, collection) = transform args collection

  interface IActionMetadataProvider with
    member _.Metadata with get() = metadata

  interface ICancellableAction with
    member _.Transform(args, collection, _cancellationToken) =
      transform args collection

type SymbStackAction() =
  let top =
    SymbMetadata.arg "top" ActionArgumentKind.Address false
      "Concrete stack top address."
  let metadata =
    { SymbMetadata.metadata
        "symb-stack"
        ReplValueKind.SymbExecutor
        ReplValueKind.SymbExecutor
        ActionRole.Transform
        "SymbExecutor -> @symb-stack top:Address=<addr> -> SymbExecutor"
        "Set the symbolic executor stack pointer."
        [ "sx |> @symb-stack top=0x7fffffffe000" ] with
        Syntaxes = [ SymbMetadata.syntax None [ top ] ] }

  let transformOne args (value: obj) =
    match value with
    | :? SymbExecutorValue as executor ->
      match args with
      | [ top ] -> executor.WithStack(SymbArgs.parseAddr top) |> box
      | _ -> invalidArg (nameof args) "Invalid symb-stack arguments."
    | value -> invalidOp $"symb-stack expects SymbExecutor: {value}"

  let transform args (collection: ObjCollection) =
    collection.Values |> Array.map (transformOne args) |> fun values ->
      { Values = values }

  interface IAction with
    member _.ActionID with get() = metadata.ID
    member _.Signature with get() = metadata.Signature
    member _.Description with get() = metadata.Description
    member _.Transform(args, collection) = transform args collection

  interface IActionMetadataProvider with
    member _.Metadata with get() = metadata

  interface ICancellableAction with
    member _.Transform(args, collection, _cancellationToken) =
      transform args collection

type SymbPCAction() =
  let addr =
    SymbMetadata.arg "addr" ActionArgumentKind.Address false
      "Concrete instruction address."
  let metadata =
    { SymbMetadata.metadata
        "symb-pc"
        ReplValueKind.SymbExecutor
        ReplValueKind.SymbExecutor
        ActionRole.Transform
        "SymbExecutor -> @symb-pc addr:Address=<addr> -> SymbExecutor"
        "Set the address where the next symbolic run starts."
        [ "sx |> @symb-pc addr=0x401000" ] with
        Syntaxes = [ SymbMetadata.syntax None [ addr ] ] }

  let transformOne args (value: obj) =
    match value with
    | :? SymbExecutorValue as executor ->
      match args with
      | [ addr ] -> executor.WithPC(SymbArgs.parseAddr addr) |> box
      | _ -> invalidArg (nameof args) "Invalid symb-pc arguments."
    | value -> invalidOp $"symb-pc expects SymbExecutor: {value}"

  let transform args (collection: ObjCollection) =
    collection.Values |> Array.map (transformOne args) |> fun values ->
      { Values = values }

  interface IAction with
    member _.ActionID with get() = metadata.ID
    member _.Signature with get() = metadata.Signature
    member _.Description with get() = metadata.Description
    member _.Transform(args, collection) = transform args collection

  interface IActionMetadataProvider with
    member _.Metadata with get() = metadata

  interface ICancellableAction with
    member _.Transform(args, collection, _cancellationToken) =
      transform args collection

type SymbMemAction() =
  let addr =
    SymbMetadata.arg "addr" ActionArgumentKind.Address false
      "Concrete memory address."
  let hex =
    SymbMetadata.arg "hex" ActionArgumentKind.HexBytes false
      "Concrete bytes to write."
  let name =
    SymbMetadata.arg "name" ActionArgumentKind.Text false
      "Symbolic byte variable prefix."
  let size =
    SymbMetadata.arg "size" ActionArgumentKind.Integer false
      "Number of symbolic bytes."
  let writeSignature =
    "SymbExecutor -> @symb-mem write addr:Address=<addr> "
    + "hex:HexBytes=<hex> -> SymbExecutor"
  let symbolicSignature =
    "SymbExecutor -> @symb-mem symbolic addr:Address=<addr> "
    + "name:String=<name> size:Int=<n> -> SymbExecutor"
  let metadata =
    { SymbMetadata.metadata
        "symb-mem"
        ReplValueKind.SymbExecutor
        ReplValueKind.SymbExecutor
        ActionRole.Transform
        (writeSignature + " | " + symbolicSignature)
        "Write concrete or symbolic bytes into executor memory."
        [ "sx |> @symb-mem write addr=0x70000000 hex=4142"
          "sx |> @symb-mem symbolic addr=0x70000000 name=input size=2" ]
        with
        Syntaxes =
          [ SymbMetadata.syntax (Some "write") [ addr; hex ]
            SymbMetadata.syntax (Some "symbolic") [ addr; name; size ] ] }

  let transformOne args (value: obj) =
    match value with
    | :? SymbExecutorValue as executor ->
      match args with
      | [ "write"; addr; hex ] ->
        executor.WithConcreteMemory(SymbArgs.parseAddr addr,
                                    SymbArgs.parseHexBytes hex)
        |> box
      | [ "symbolic"; addr; name; size ] ->
        executor.WithSymbolicMemory(SymbArgs.parseAddr addr,
                                    name,
                                    SymbArgs.parseInt size)
        |> box
      | _ -> invalidArg (nameof args) "Invalid symb-mem arguments."
    | value -> invalidOp $"symb-mem expects SymbExecutor: {value}"

  let transform args (collection: ObjCollection) =
    collection.Values |> Array.map (transformOne args) |> fun values ->
      { Values = values }

  interface IAction with
    member _.ActionID with get() = metadata.ID
    member _.Signature with get() = metadata.Signature
    member _.Description with get() = metadata.Description
    member _.Transform(args, collection) = transform args collection

  interface IActionMetadataProvider with
    member _.Metadata with get() = metadata

  interface ICancellableAction with
    member _.Transform(args, collection, _cancellationToken) =
      transform args collection

type SymbContextAction() =
  let pc =
    SymbMetadata.arg "pc" ActionArgumentKind.Address true
      "Address where the next symbolic run starts."
  let stack =
    SymbMetadata.arg "stack" ActionArgumentKind.Address true
      "Concrete stack pointer value."
  let regs =
    SymbMetadata.arg "regs" ActionArgumentKind.Text true
      "Register assignments: [RBP=0x1; RDI=0x70000000]."
  let mem =
    SymbMetadata.arg "mem" ActionArgumentKind.Text true
      "Concrete memory assignments: [0x70000012=00]."
  let symMem =
    SymbMetadata.arg "sym-mem" ActionArgumentKind.Text true
      "Symbolic memory assignments: [password@0x70000000:18]."
  let signature =
    "SymbExecutor -> @symb-context [pc:Address=<addr>] "
    + "[stack:Address=<addr>] [regs:String=<regs>] "
    + "[mem:String=<mem>] [sym-mem:String=<sym-mem>] -> SymbExecutor"
  let metadata =
    { SymbMetadata.metadata
        "symb-context"
        ReplValueKind.SymbExecutor
        ReplValueKind.SymbExecutor
        ActionRole.Transform
        signature
        "Set symbolic execution PC, stack, registers, and memory at once."
        [ "sx |> @symb-context pc=0x401136 stack=0x7fffffffe000"
          "sx |> @symb-context regs=[RBP=0x1; RDI=0x70000000]"
          "sx |> @symb-context sym-mem=[password@0x70000000:18]" ] with
        Syntaxes =
          [ SymbMetadata.syntax None [ pc; stack; regs; mem; symMem ] ] }

  let transformOne args (value: obj) =
    match value with
    | :? SymbExecutorValue as executor ->
      SymbArgs.parseContext args |> executor.WithContext |> box
    | value -> invalidOp $"symb-context expects SymbExecutor: {value}"

  let transform args (collection: ObjCollection) =
    collection.Values |> Array.map (transformOne args) |> fun values ->
      { Values = values }

  interface IAction with
    member _.ActionID with get() = metadata.ID
    member _.Signature with get() = metadata.Signature
    member _.Description with get() = metadata.Description
    member _.Transform(args, collection) = transform args collection

  interface IActionMetadataProvider with
    member _.Metadata with get() = metadata

  interface ICancellableAction with
    member _.Transform(args, collection, _cancellationToken) =
      transform args collection

type SymbAvoidAction() =
  let addr =
    SymbMetadata.arg "addr" ActionArgumentKind.Address false
      "Address to discard during symbolic exploration."
  let metadata =
    { SymbMetadata.metadata
        "symb-avoid"
        ReplValueKind.SymbExecutor
        ReplValueKind.SymbExecutor
        ActionRole.Transform
        "SymbExecutor -> @symb-avoid addr:Address=<addr> -> SymbExecutor"
        "Add one avoid address to the symbolic executor."
        [ "sx |> @symb-avoid addr=0x401050" ] with
        Syntaxes = [ SymbMetadata.syntax None [ addr ] ] }

  let transformOne args (value: obj) =
    match value with
    | :? SymbExecutorValue as executor ->
      match args with
      | [ addr ] -> executor.WithAvoid(SymbArgs.parseAddr addr) |> box
      | _ -> invalidArg (nameof args) "Invalid symb-avoid arguments."
    | value -> invalidOp $"symb-avoid expects SymbExecutor: {value}"

  let transform args (collection: ObjCollection) =
    collection.Values |> Array.map (transformOne args) |> fun values ->
      { Values = values }

  interface IAction with
    member _.ActionID with get() = metadata.ID
    member _.Signature with get() = metadata.Signature
    member _.Description with get() = metadata.Description
    member _.Transform(args, collection) = transform args collection

  interface IActionMetadataProvider with
    member _.Metadata with get() = metadata

  interface ICancellableAction with
    member _.Transform(args, collection, _cancellationToken) =
      transform args collection

type SymbHookAction() =
  let addr =
    SymbMetadata.arg "addr" ActionArgumentKind.Address false
      "Address of an external call stub to model."
  let metadata =
    let signature =
      "SymbExecutor -> @symb-hook strlen addr:Address=<addr> "
      + "-> SymbExecutor"
    { SymbMetadata.metadata
        "symb-hook"
        ReplValueKind.SymbExecutor
        ReplValueKind.SymbExecutor
        ActionRole.Transform
        signature
        "Attach a built-in symbolic model for an external function."
        [ "sx |> @symb-hook strlen addr=0x401040" ] with
        Syntaxes = [ SymbMetadata.syntax (Some "strlen") [ addr ] ] }

  let transformOne args (value: obj) =
    match value with
    | :? SymbExecutorValue as executor ->
      match args with
      | [ "strlen"; addr ] -> executor.WithStrlenHook(SymbArgs.parseAddr addr)
      | _ -> invalidArg (nameof args) "Invalid symb-hook arguments."
      |> box
    | value -> invalidOp $"symb-hook expects SymbExecutor: {value}"

  let transform args (collection: ObjCollection) =
    collection.Values |> Array.map (transformOne args) |> fun values ->
      { Values = values }

  interface IAction with
    member _.ActionID with get() = metadata.ID
    member _.Signature with get() = metadata.Signature
    member _.Description with get() = metadata.Description
    member _.Transform(args, collection) = transform args collection

  interface IActionMetadataProvider with
    member _.Metadata with get() = metadata

  interface ICancellableAction with
    member _.Transform(args, collection, _cancellationToken) =
      transform args collection

type SymbArgAction() =
  let index =
    SymbMetadata.arg "index" ActionArgumentKind.Integer false
      "Zero-based ABI argument index."
  let name =
    SymbMetadata.arg "name" ActionArgumentKind.Text false
      "Symbolic input variable prefix."
  let size =
    SymbMetadata.arg "size" ActionArgumentKind.Integer false
      "Number of symbolic bytes."
  let signature =
    "SymbExecutor -> @symb-arg index:Int=<n> name:String=<name> "
    + "size:Int=<n> -> SymbExecutor"
  let metadata =
    { SymbMetadata.metadata
        "symb-arg"
        ReplValueKind.SymbExecutor
        ReplValueKind.SymbExecutor
        ActionRole.Transform
        signature
        "Allocate a symbolic byte buffer and pass it as an ABI argument."
        [ "sx |> @symb-arg index=0 name=input size=2" ] with
        Syntaxes = [ SymbMetadata.syntax None [ index; name; size ] ] }

  let transformOne args (value: obj) =
    match value with
    | :? SymbExecutorValue as executor ->
      match args with
      | [ index; name; size ] ->
        executor.WithSymbolicArgument(SymbArgs.parseInt index,
                                      name,
                                      SymbArgs.parseInt size)
        |> box
      | _ -> invalidArg (nameof args) "Invalid symb-arg arguments."
    | value -> invalidOp $"symb-arg expects SymbExecutor: {value}"

  let transform args (collection: ObjCollection) =
    collection.Values |> Array.map (transformOne args) |> fun values ->
      { Values = values }

  interface IAction with
    member _.ActionID with get() = metadata.ID
    member _.Signature with get() = metadata.Signature
    member _.Description with get() = metadata.Description
    member _.Transform(args, collection) = transform args collection

  interface IActionMetadataProvider with
    member _.Metadata with get() = metadata

  interface ICancellableAction with
    member _.Transform(args, collection, _cancellationToken) =
      transform args collection

type SymbRegAction() =
  let name =
    SymbMetadata.arg "name" ActionArgumentKind.Text false "Register name."
  let value =
    SymbMetadata.arg "value" ActionArgumentKind.Address false
      "Concrete register value."
  let signature =
    "SymbExecutor -> @symb-reg name:String=<reg> "
    + "value:Address=<addr> -> SymbExecutor"
  let metadata =
    { SymbMetadata.metadata
        "symb-reg"
        ReplValueKind.SymbExecutor
        ReplValueKind.SymbExecutor
        ActionRole.Transform
        signature
        "Set one concrete register value."
        [ "sx |> @symb-reg name=RAX value=0x0" ] with
        Syntaxes = [ SymbMetadata.syntax None [ name; value ] ] }

  let transformOne args (value: obj) =
    match value with
    | :? SymbExecutorValue as executor ->
      let next =
        match args with
        | [ name; value ] ->
          executor.WithRegister(name, SymbArgs.parseAddr value)
        | _ -> invalidArg (nameof args) "Invalid symb-reg arguments."
      next |> box
    | value -> invalidOp $"symb-reg expects SymbExecutor: {value}"

  let transform args (collection: ObjCollection) =
    collection.Values |> Array.map (transformOne args) |> fun values ->
      { Values = values }

  interface IAction with
    member _.ActionID with get() = metadata.ID
    member _.Signature with get() = metadata.Signature
    member _.Description with get() = metadata.Description
    member _.Transform(args, collection) = transform args collection

  interface IActionMetadataProvider with
    member _.Metadata with get() = metadata

  interface ICancellableAction with
    member _.Transform(args, collection, _cancellationToken) =
      transform args collection

type SymbRunAction() =
  let target =
    SymbMetadata.arg "target" ActionArgumentKind.Address false
      "Target address to reach or satisfy."
  let maxDepth =
    SymbMetadata.arg "max-depth" ActionArgumentKind.Integer true
      "Maximum instructions per path. Default: 512."
  let maxStates =
    SymbMetadata.arg "max-states" ActionArgumentKind.Integer true
      "Maximum states to expand. Default: 2048."
  let loopBound =
    SymbMetadata.arg "loop-bound" ActionArgumentKind.Integer true
      "Maximum visits to the same address. Default: 2."
  let prune =
    SymbMetadata.choice "prune" true [ "true"; "false" ]
      "Use the solver to prune infeasible paths. Default: true."
  let runArgs = [ target; maxDepth; maxStates; loopBound; prune ]
  let signature =
    "SymbExecutor -> @symb-run <reach|satisfy> "
    + "target:Address=<addr> [max-depth:Int=<n>] "
    + "[max-states:Int=<n>] [loop-bound:Int=<n>] "
    + "[prune:Choice=<true|false>] -> SymbRunResult"
  let metadata =
    { SymbMetadata.metadata
        "symb-run"
        ReplValueKind.SymbExecutor
        ReplValueKind.SymbRunResult
        ActionRole.Transform
        signature
        "Run a bounded symbolic reachability or satisfiability query."
        [ "sx |> @symb-run satisfy target=0xb max-depth=8"
          "sx |> @symb-run reach target=0x11 max-depth=8" ] with
        Syntaxes =
          [ SymbMetadata.syntax (Some "reach") runArgs
            SymbMetadata.syntax (Some "satisfy") runArgs ] }

  let transformOne args (value: obj) =
    match value with
    | :? SymbExecutorValue as executor ->
      match args with
      | op :: target :: rest ->
        let maxDepth, maxStates, loopBound, prune = SymbArgs.defaults rest
        let target = SymbArgs.parseAddr target
        match op.ToLowerInvariant() with
        | "reach" ->
          executor.RunReach(target, maxDepth, maxStates, loopBound, prune)
          |> box
        | "satisfy" ->
          executor.RunSatisfy(target, maxDepth, maxStates, loopBound, prune)
          |> box
        | _ -> invalidArg (nameof args) "Unknown symb-run operation."
      | _ -> invalidArg (nameof args) "Invalid symb-run arguments."
    | value -> invalidOp $"symb-run expects SymbExecutor: {value}"

  let transform args (collection: ObjCollection) =
    collection.Values |> Array.map (transformOne args) |> fun values ->
      { Values = values }

  interface IAction with
    member _.ActionID with get() = metadata.ID
    member _.Signature with get() = metadata.Signature
    member _.Description with get() = metadata.Description
    member _.Transform(args, collection) = transform args collection

  interface IActionMetadataProvider with
    member _.Metadata with get() = metadata

  interface ICancellableAction with
    member _.Transform(args, collection, _cancellationToken) =
      transform args collection

type SymbModelAction() =
  let metadata =
    { SymbMetadata.metadata
        "symb-model"
        ReplValueKind.SymbRunResult
        ReplValueKind.Text
        ActionRole.Transform
        "SymbRunResult -> @symb-model -> Text"
        "Print model assignments from a symbolic execution result."
        [ "result |> @symb-model" ] with
        Syntaxes = [ SymbMetadata.syntax None [] ] }

  let transformOne (value: obj) =
    match value with
    | :? SymbRunValue as result -> result.ModelText() |> box
    | value -> invalidOp $"symb-model expects SymbRunResult: {value}"

  let transform (collection: ObjCollection) =
    collection.Values |> Array.map transformOne |> fun values ->
      { Values = values }

  interface IAction with
    member _.ActionID with get() = metadata.ID
    member _.Signature with get() = metadata.Signature
    member _.Description with get() = metadata.Description
    member _.Transform(_args, collection) = transform collection

  interface IActionMetadataProvider with
    member _.Metadata with get() = metadata

  interface ICancellableAction with
    member _.Transform(_args, collection, _cancellationToken) =
      transform collection
