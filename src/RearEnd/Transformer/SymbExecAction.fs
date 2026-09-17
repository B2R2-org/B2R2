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
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.Executor
open B2R2.MiddleEnd.SymbEval

type LowUIRExpr = B2R2.BinIR.LowUIR.Expr

type LowUIRStmt = B2R2.BinIR.LowUIR.Stmt

type SymbCallHookRegistry = CallHookRegistry<SymbCallHook>

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
    Location: string
    Size: int
    Query: IQueryExpr }

type SymbSymbolicRegisterAssignment =
  { Register: string
    Name: string
    Size: int }

type SymbRegionPermission =
  { Read: bool
    Write: bool
    Execute: bool }

type SymbMemoryRegion =
  { Name: string
    Start: Addr
    Finish: Addr
    Permission: SymbRegionPermission }

type SymbMemoryAccessKind =
  | MemoryRead
  | MemoryWrite

module private SymbRegionPerm =
  let format permission =
    let chars =
      [ if permission.Read then Some "r" else None
        if permission.Write then Some "w" else None
        if permission.Execute then Some "x" else None ]
      |> List.choose id
    match chars with
    | [] -> "-"
    | chars -> String.concat "" chars

  let allows kind permission =
    match kind with
    | MemoryRead -> permission.Read
    | MemoryWrite -> permission.Write

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
    SymbolicMemory: SymbSymbolicMemoryAssignment list
    SymbolicRegisters: SymbSymbolicRegisterAssignment list
    Regions: SymbMemoryRegion list }

type SymbExecutorValue(binary: Binary,
                       state: SymbState,
                       inputs: SymbolicInput list,
                       avoids: Set<Addr>,
                       regions: SymbMemoryRegion list,
                       hooks: SymbCallHookRegistry option,
                       hookText: string list,
                       solver: SymbSolverValue option) as this =
  let executor = SymbExecutor(Binary.Handle binary)

  let x64ParentRegister (name: string) =
    match name.ToUpperInvariant() with
    | "EAX" -> Some "RAX"
    | "EBX" -> Some "RBX"
    | "ECX" -> Some "RCX"
    | "EDX" -> Some "RDX"
    | "ESI" -> Some "RSI"
    | "EDI" -> Some "RDI"
    | "ESP" -> Some "RSP"
    | "EBP" -> Some "RBP"
    | "R8D" -> Some "R8"
    | "R9D" -> Some "R9"
    | "R10D" -> Some "R10"
    | "R11D" -> Some "R11"
    | "R12D" -> Some "R12"
    | "R13D" -> Some "R13"
    | "R14D" -> Some "R14"
    | "R15D" -> Some "R15"
    | _ -> None

  new(binary: Binary) =
    let executor = SymbExecutor(Binary.Handle binary)
    SymbExecutorValue(binary,
                      executor.CreateState(),
                      [],
                      Set.empty,
                      [],
                      None,
                      [],
                      None)

  member _.Binary = binary

  member _.State = state

  member _.Inputs = inputs

  member _.Avoids = avoids

  member _.Regions = regions

  member _.Hooks = hooks

  member _.Solver = solver

  member _.CallPolicy =
    match hooks with
    | Some registry -> CallPolicy.UseCallHooks registry
    | None -> CallPolicy.FollowDirectInternalCalls

  member _.SolverBackend =
    solver
    |> Option.map (fun solver -> CustomSolver(solver.Create()))
    |> Option.defaultValue NoSolver

  member _.WithSolver solverValue =
    SymbExecutorValue(binary,
                      state,
                      inputs,
                      avoids,
                      regions,
                      hooks,
                      hookText,
                      Some solverValue)

  member _.WithPC pc =
    let state = state.Clone()
    state.PC <- pc
    SymbExecutorValue(binary,
                      state,
                      inputs,
                      avoids,
                      regions,
                      hooks,
                      hookText,
                      solver)

  member _.WithStack top =
    let state = state.Clone()
    let accessor = SymbStateAccessor(Binary.Handle binary, state)
    match accessor.TrySetStackPointer top with
    | Ok() ->
      SymbExecutorValue(binary,
                        state,
                        inputs,
                        avoids,
                        regions,
                        hooks,
                        hookText,
                        solver)
    | Error error -> invalidOp $"{error}"

  member _.WithRegister(name: string, value) =
    let state = state.Clone()
    let accessor = SymbStateAccessor(Binary.Handle binary, state)
    accessor.SetRegister(name, accessor.WordValue value)
    SymbExecutorValue(binary,
                      state,
                      inputs,
                      avoids,
                      regions,
                      hooks,
                      hookText,
                      solver)

  member _.WithConcreteMemory(addr, bytes: byte[]) =
    let state = state.Clone()
    bytes |> Array.iteri (fun idx byte ->
      let value = SymbExpr.Const(BitVector(uint64 byte, 8<rt>))
      state.Memory.ByteWrite(addr + uint64 idx, value))
    SymbExecutorValue(binary,
                      state,
                      inputs,
                      avoids,
                      regions,
                      hooks,
                      hookText,
                      solver)

  member _.WithSymbolicMemory(addr, name, size) =
    let state = state.Clone()
    let accessor = SymbStateAccessor(Binary.Handle binary, state)
    let buffer = accessor.WriteSymbolicBuffer(name, addr, size)
    let input =
      { Name = name
        Location = $"mem@0x{buffer.Address:x}"
        Size = size
        Query = buffer :> IQueryExpr }
    SymbExecutorValue(binary,
                      state,
                      input :: inputs,
                      avoids,
                      regions,
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
        Location = $"arg{index}@0x{buffer.Address:x}"
        Size = size
        Query = buffer :> IQueryExpr }
    SymbExecutorValue(binary,
                      state,
                      input :: inputs,
                      avoids,
                      regions,
                      hooks,
                      hookText,
                      solver)

  member _.WithSymbolicRegister(register: string, name: string, size: int) =
    let state = state.Clone()
    let hdl = Binary.Handle binary
    let accessor = SymbStateAccessor(hdl, state)
    let rid = hdl.RegisterFactory.GetRegisterID(name = register)
    let registerType = hdl.RegisterFactory.GetRegType rid
    let bytes = accessor.CreateSymbolicBytes(name, size)
    let concat (lhs: SymbExpr) (rhs: SymbExpr) =
      let typ = RegType.fromBitWidth (int lhs.Type + int rhs.Type)
      SymbExpr.binop BinOpType.CONCAT typ lhs rhs
    let ordered =
      match hdl.ISA.Endian with
      | Endian.Little -> List.rev bytes
      | _ -> bytes
    let value =
      match ordered with
      | [] -> invalidArg (nameof size) "Symbolic register size must be > 0."
      | head :: tail -> List.fold concat head tail
    let value =
      if value.Type = registerType then value
      elif value.Type < registerType then
        SymbExpr.cast CastKind.ZeroExt registerType value
      else
        invalidArg (nameof size) "Symbolic register value is too wide."
    let query =
      bytes
      |> List.map (fun byte -> QueryExpr.Value byte :> IQueryExpr)
      |> QueryExpr.Values
      :> IQueryExpr
    accessor.SetRegister(rid, value)
    if hdl.ISA.WordSize = WordSize.Bit64 then
      match x64ParentRegister register with
      | Some parent ->
        let parentRid = hdl.RegisterFactory.GetRegisterID(name = parent)
        let parentType = hdl.RegisterFactory.GetRegType parentRid
        let parentValue = SymbExpr.cast CastKind.ZeroExt parentType value
        accessor.SetRegister(parentRid, parentValue)
      | None -> ()
    else
      ()
    let input =
      { Name = name
        Location = $"reg:{register}"
        Size = size
        Query = query }
    SymbExecutorValue(binary,
                      state,
                      input :: inputs,
                      avoids,
                      regions,
                      hooks,
                      hookText,
                      solver)

  member _.WithAvoid addr =
    SymbExecutorValue(binary,
                      state,
                      inputs,
                      Set.add addr avoids,
                      regions,
                      hooks,
                      hookText,
                      solver)

  member _.WithRegion region =
    SymbExecutorValue(binary,
                      state,
                      inputs,
                      avoids,
                      region :: regions,
                      hooks,
                      hookText,
                      solver)

  member _.WithPrecondition(condition: StopPoint<SymbState> -> bool) =
    let state = state.Clone()
    let point =
      { Address = state.PC
        InstructionCount = 0
        Instruction = None
        Statements = [||]
        State = state }
    if condition point then
      SymbExecutorValue(binary,
                        state,
                        inputs,
                        avoids,
                        regions,
                        hooks,
                        hookText,
                        solver)
    else
      invalidOp "The symbolic precondition is unsatisfiable."

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
                      regions,
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
    let applySymbolicRegister (executor: SymbExecutorValue)
                              (assignment: SymbSymbolicRegisterAssignment) =
      executor.WithSymbolicRegister(assignment.Register,
                                    assignment.Name,
                                    assignment.Size)
    let applyRegion (executor: SymbExecutorValue)
                    (region: SymbMemoryRegion) =
      executor.WithRegion region
    let executor = applyPC this |> applyStack
    let executor = spec.Registers |> List.fold applyRegister executor
    let executor = spec.Memory |> List.fold applyMemory executor
    let executor = spec.SymbolicMemory |> List.fold applySymbolicMemory executor
    let executor =
      spec.SymbolicRegisters |> List.fold applySymbolicRegister executor
    spec.Regions |> List.fold applyRegion executor

  member _.RunSatisfy(target, maxDepth, maxStates, loopBound, prune) =
    let query =
      { Query = SymbQuery.SatisfyAddress target
        QueryValues =
          inputs
          |> List.rev
          |> List.map (fun input -> input.Query)
          |> QueryExpr.Values }
    let options =
      { SymbRunOptions.Default(query, this.SolverBackend) with
          Calls = this.CallPolicy
          AvoidConditions =
            avoids
            |> Seq.map SymbAvoidCondition.AvoidAddress
            |> Seq.toList
          MaxDepth = maxDepth
          MaxStates = maxStates
          LoopBound = loopBound
          PruneInfeasiblePaths = prune }
    executor.Run(state.PC, state, options)
    |> fun result -> SymbRunValue(this, "satisfy", Some target, result)

  member _.RunSatisfyCondition(predicate,
                               maxDepth,
                               maxStates,
                               loopBound,
                               prune) =
    let query =
      { Query = SymbQuery.SatisfyWhen predicate
        QueryValues =
          inputs
          |> List.rev
          |> List.map (fun input -> input.Query)
          |> QueryExpr.Values }
    let options =
      { SymbRunOptions.Default(query, this.SolverBackend) with
          Calls = this.CallPolicy
          AvoidConditions =
            avoids
            |> Seq.map SymbAvoidCondition.AvoidAddress
            |> Seq.toList
          MaxDepth = maxDepth
          MaxStates = maxStates
          LoopBound = loopBound
          PruneInfeasiblePaths = prune }
    executor.Run(state.PC, state, options)
    |> fun result -> SymbRunValue(this, "cond", None, result)

  member _.RunReach(target, maxDepth, maxStates, loopBound, prune) =
    let options =
      { SymbRunOptions.Default(SymbQuery.ReachAddress target,
                               this.SolverBackend) with
          Calls = this.CallPolicy
          AvoidConditions =
            avoids
            |> Seq.map SymbAvoidCondition.AvoidAddress
            |> Seq.toList
          MaxDepth = maxDepth
          MaxStates = maxStates
          LoopBound = loopBound
          PruneInfeasiblePaths = prune }
    executor.Run(state.PC, state, options)
    |> fun result -> SymbRunValue(this, "reach", Some target, result)

  override _.ToString() =
    let inputText =
      match List.rev inputs with
      | [] -> "none"
      | inputs ->
        inputs
        |> List.map (fun input ->
          $"{input.Name}@{input.Location}({input.Size} bytes)")
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
    let regionText =
      match List.rev regions with
      | [] -> "none"
      | regions ->
        regions
        |> List.map (fun region ->
          let perms = SymbRegionPerm.format region.Permission
          $"{region.Name}=0x{region.Start:x}-0x{region.Finish:x}:{perms}")
        |> String.concat ", "
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
    + $"{Environment.NewLine}  regions: {regionText}"
    + $"{Environment.NewLine}  hooks: {hookText}"

and SymbRunValue(source: SymbExecutorValue,
                 query: string,
                 target: Addr option,
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
    match result.Timeout with
    | Some timeout ->
      $"timed out after {timeout} ms"
    | None ->
      match result.Answer with
      | SymbAnswer.Reachable answers ->
        $"reachable ({List.length answers} answer(s))"
      | SymbAnswer.Unreachable -> "unreachable"
      | SymbAnswer.Satisfiable answers ->
        $"satisfiable ({List.length answers} model(s))"
      | SymbAnswer.Unsatisfiable -> "unsatisfiable"
      | SymbAnswer.Unknown failures ->
        $"unknown ({List.length failures} failure(s))"

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

  let indentLines spaces (text: string) =
    let prefix = String.replicate spaces " "
    text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n')
    |> Array.map (fun line -> prefix + line)
    |> String.concat Environment.NewLine

  member _.Source = source

  member _.Result = result

  member _.ModelText() =
    let sb = StringBuilder()
    let appendResult = function
      | SymbAnswer.Satisfiable answers ->
        answers |> List.iteri (fun idx answer ->
          appendSatAnswer sb (idx + 1) answer)
      | SymbAnswer.Reachable answers ->
        answers |> List.iteri (fun idx answer ->
          appendReachAnswer sb (idx + 1) answer)
      | SymbAnswer.Unknown failures ->
        failures |> List.iteri (fun idx failure ->
          appendFailure sb (idx + 1) failure)
      | SymbAnswer.Unreachable ->
        sb.AppendLine("unreachable") |> ignore
      | SymbAnswer.Unsatisfiable ->
        sb.AppendLine("unsatisfiable") |> ignore
    appendResult result.Answer
    sb.ToString().TrimEnd()

  override this.ToString() =
    let targetText =
      target
      |> Option.map (fun target -> $"0x{target:x}")
      |> Option.defaultValue "condition"
    let header =
      "SymbRunResult"
      + $"{Environment.NewLine}  query: {query}"
      + $"{Environment.NewLine}  target: {targetText}"
      + $"{Environment.NewLine}  status: {statusText}"
    let model = this.ModelText()
    let appendSection name =
      if String.IsNullOrWhiteSpace model then
        header
      else
        header
        + $"{Environment.NewLine}  {name}:"
        + Environment.NewLine
        + indentLines 4 model
    match result.Answer with
    | SymbAnswer.Reachable _ | SymbAnswer.Satisfiable _ ->
      appendSection "answers"
    | SymbAnswer.Unknown _ ->
      appendSection "failures"
    | SymbAnswer.Unreachable | SymbAnswer.Unsatisfiable ->
      header

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

  let trimBrackets (text: string) =
    let text = text.Trim()
    if text.StartsWith("[", StringComparison.Ordinal)
       && text.EndsWith("]", StringComparison.Ordinal) then
      text[1..text.Length - 2].Trim()
    else
      text

  let contextEntries text =
    let text = trimBrackets text
    text.Split([| ';'; ',' |], StringSplitOptions.RemoveEmptyEntries)
    |> Array.map _.Trim()
    |> Array.filter (String.IsNullOrWhiteSpace >> not)

  let splitAssignment (entry: string) =
    let index = entry.IndexOf '='
    if index <= 0 then
      invalidArg (nameof entry) $"Expected key=value entry: {entry}"
    else
      entry[..index - 1].Trim(), entry[index + 1..].Trim()

  let parseMemoryAssignment entry =
    let addr, hex = splitAssignment entry
    { Address = parseAddr addr
      Bytes = parseHexBytes hex }

  let parseSymbolicMemoryAssignment (entry: string) =
    let nameIndex = entry.IndexOf '@'
    let sizeIndex = entry.LastIndexOf ':'
    if nameIndex <= 0 || sizeIndex <= nameIndex + 1 then
      invalidArg (nameof entry)
        $"Expected symbolic memory entry name@addr:size: {entry}"
    else
      { Name = entry[..nameIndex - 1].Trim()
        Address = parseAddr (entry[nameIndex + 1..sizeIndex - 1].Trim())
        Size = parseInt (entry[sizeIndex + 1..].Trim()) }

  let parseSymbolicRegisterAssignment (entry: string) =
    let register, spec = splitAssignment entry
    let sizeIndex = spec.LastIndexOf ':'
    if sizeIndex <= 0 then
      invalidArg (nameof entry)
        $"Expected symbolic register entry REG=name:size: {entry}"
    else
      { Register = register
        Name = spec[..sizeIndex - 1].Trim()
        Size = parseInt (spec[sizeIndex + 1..].Trim()) }

  let parseRegionPermission (entry: string) (text: string) =
    let text = text.Trim().ToLowerInvariant()
    let valid =
      text.Length > 0
      && (text |> Seq.forall (fun ch ->
        ch = 'r' || ch = 'w' || ch = 'x'))
    if valid then
      { Read = text.Contains "r"
        Write = text.Contains "w"
        Execute = text.Contains "x" }
    else
      invalidArg (nameof entry) $"Invalid region permission: {entry}"

  let parseRegionAssignment (entry: string) =
    let name, spec = splitAssignment entry
    let permIndex = spec.LastIndexOf ':'
    if permIndex <= 0 then
      invalidArg (nameof entry) $"Expected region name=start..end:perm: {entry}"
    else
      let range = spec[..permIndex - 1].Trim()
      let permission = parseRegionPermission entry spec[permIndex + 1..]
      let rangeParts =
        range.Split([| ".." |], StringSplitOptions.None)
      if rangeParts.Length <> 2 then
        invalidArg (nameof entry)
          $"Expected region range start..end: {entry}"
      else
        let startAddress = parseAddr (rangeParts[0].Trim())
        let endAddress = parseAddr (rangeParts[1].Trim())
        if startAddress >= endAddress then
          invalidArg (nameof entry)
            $"Region start must be smaller than end: {entry}"
        else
          { Name = name
            Start = startAddress
            Finish = endAddress
            Permission = permission }

  let parseContext args =
    let rec loop (spec: SymbContextSpec) = function
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
            | "sym-regs" | "symbolic-registers" ->
              let symbolic =
                contextEntries value
                |> Array.toList
                |> List.map parseSymbolicRegisterAssignment
              { spec with
                  SymbolicRegisters = spec.SymbolicRegisters @ symbolic }
            | "regions" ->
              let regions =
                contextEntries value
                |> Array.toList
                |> List.map parseRegionAssignment
              { spec with Regions = spec.Regions @ regions }
            | _ ->
              invalidArg (nameof args) $"Unknown symb-context parameter: {key}"
          loop spec rest
    let empty: SymbContextSpec =
      { PC = None
        Stack = None
        Registers = []
        Memory = []
        SymbolicMemory = []
        SymbolicRegisters = []
        Regions = [] }
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

module private SymbCondition =
  type Term =
    | Register of string
    | Memory of Addr * RegType
    | WriteAddress

  type Condition =
    | At of Addr
    | Compare of Term * RelOpType * Addr
    | MemoryPolicyViolation of SymbMemoryAccessKind option
    | And of Condition list

  let norm (text: string) =
    Regex.Replace(text.Trim(), @"\s+", " ")

  let stripOuterParens (text: string) =
    let text = text.Trim()
    if text.StartsWith("(", StringComparison.Ordinal)
       && text.EndsWith(")", StringComparison.Ordinal) then
      text[1..text.Length - 2].Trim()
    else
      text

  let parseRelOp = function
    | "=" | "==" -> RelOpType.EQ
    | "!=" | "<>" -> RelOpType.NEQ
    | "<" -> RelOpType.LT
    | "<=" -> RelOpType.LE
    | ">" -> RelOpType.GT
    | ">=" -> RelOpType.GE
    | op -> invalidArg (nameof op) $"Unsupported condition operator: {op}"

  let tryMatch pattern text =
    let options = RegexOptions.IgnoreCase ||| RegexOptions.CultureInvariant
    let m = Regex.Match(text, pattern, options)
    if m.Success then Some m else None

  let parseConditionList atomParser body =
    Regex.Split(body, @"\s*&&\s*")
    |> Array.toList
    |> List.map atomParser
    |> function
      | [ atom ] -> atom
      | atoms -> And atoms

  let parseAtom text =
    let number = @"(0x[0-9a-f]+|[0-9]+)"
    let op = @"(==|=|!=|<>|<=|>=|<|>)"
    let text = norm text
    let atPattern = @"^pp\.at\s*\(\s*" + number + @"\s*\)$"
    match tryMatch atPattern text with
    | Some m -> At(SymbArgs.parseAddr m.Groups[1].Value)
    | None ->
      if Regex.IsMatch(text, @"^(mem|memory)\.accessViolation\s*\(\s*\)$",
                       RegexOptions.IgnoreCase) then
        MemoryPolicyViolation None
      elif Regex.IsMatch(text, @"^(mem|memory)\.readViolation\s*\(\s*\)$",
                         RegexOptions.IgnoreCase) then
        MemoryPolicyViolation(Some MemoryRead)
      elif Regex.IsMatch(text, @"^(mem|memory)\.writeViolation\s*\(\s*\)$",
                         RegexOptions.IgnoreCase) then
        MemoryPolicyViolation(Some MemoryWrite)
      else
        let regPattern =
          @"^pp\.REG\s*\[\s*([A-Za-z0-9_]+)\s*\]\s*"
          + op + @"\s*" + number + "$"
        let memPattern =
          @"^pp\.MEM\s*\[\s*" + number + @"(?::([0-9]+))?\s*\]\s*"
          + op + @"\s*" + number + "$"
        let writePattern =
          @"^pp\.WRITE\s*" + op + @"\s*" + number + "$"
        match tryMatch regPattern text with
        | Some m ->
          let term = Register m.Groups[1].Value
          let relop = parseRelOp m.Groups[2].Value
          Compare(term, relop, SymbArgs.parseAddr m.Groups[3].Value)
        | None ->
          match tryMatch memPattern text with
          | Some m ->
            let size =
              if m.Groups[2].Success then SymbArgs.parseInt m.Groups[2].Value
              else 8
            let term =
              Memory(SymbArgs.parseAddr m.Groups[1].Value,
                     RegType.fromByteWidth size)
            let relop = parseRelOp m.Groups[3].Value
            Compare(term, relop, SymbArgs.parseAddr m.Groups[4].Value)
          | None ->
            match tryMatch writePattern text with
            | Some m ->
              let relop = parseRelOp m.Groups[1].Value
              Compare(WriteAddress, relop, SymbArgs.parseAddr m.Groups[2].Value)
            | None ->
              invalidArg (nameof text) $"Invalid pp condition: {text}"

  let parseBody body =
    parseConditionList parseAtom body

  let parse text =
    let text = stripOuterParens text
    let pattern = @"^fun\s+([A-Za-z_][A-Za-z0-9_]*|_)\s*->\s*(.+)$"
    match tryMatch pattern text with
    | Some m -> parseBody m.Groups[2].Value
    | None ->
      invalidArg (nameof text)
        "Expected condition function: fun pp -> <predicate>."

  let stripListBrackets (text: string) =
    let text = text.Trim()
    if text.StartsWith("[", StringComparison.Ordinal)
       && text.EndsWith("]", StringComparison.Ordinal) then
      text[1..text.Length - 2].Trim()
    else
      text

  let parsePreconditionAtom text =
    let number = @"(0x[0-9a-f]+|[0-9]+)"
    let op = @"(==|=|!=|<>|<=|>=|<|>)"
    let text = norm text
    let regPattern =
      @"^([A-Za-z][A-Za-z0-9_]*)\s*" + op + @"\s*" + number + "$"
    let memPattern =
      @"^MEM\s*\[\s*" + number + @"(?::([0-9]+))?\s*\]\s*"
      + op + @"\s*" + number + "$"
    match tryMatch regPattern text with
    | Some m ->
      let term = Register m.Groups[1].Value
      let relop = parseRelOp m.Groups[2].Value
      Compare(term, relop, SymbArgs.parseAddr m.Groups[3].Value)
    | None ->
      match tryMatch memPattern text with
      | Some m ->
        let size =
          if m.Groups[2].Success then SymbArgs.parseInt m.Groups[2].Value
          else 8
        let term =
          Memory(SymbArgs.parseAddr m.Groups[1].Value,
                 RegType.fromByteWidth size)
        let relop = parseRelOp m.Groups[3].Value
        Compare(term, relop, SymbArgs.parseAddr m.Groups[4].Value)
      | None ->
        invalidArg (nameof text) $"Invalid precondition: {text}"

  let parsePreconditions text =
    stripListBrackets text
    |> fun text -> Regex.Split(text, @"\s*(?:;|&&)\s*")
    |> Array.toList
    |> List.filter (String.IsNullOrWhiteSpace >> not)
    |> List.map parsePreconditionAtom
    |> function
      | [ atom ] -> atom
      | atoms -> And atoms

  let constFor (expr: SymbExpr) (value: Addr) =
    SymbExpr.Const(BitVector(uint64 value, expr.Type))

  let addCondition (state: SymbState) (expr: SymbExpr) =
    match expr with
    | SymbExpr.Const bv when bv.IsTrue -> true
    | SymbExpr.Const bv when bv.IsFalse -> false
    | _ -> state.AddPathCondition expr; true

  let compareExpr (state: SymbState) lhs relop rhs =
    SymbExpr.relop relop lhs (constFor lhs rhs) |> addCondition state

  let tryRegister (hdl: BinHandle) (point: StopPoint<SymbState>) name =
    let factory = hdl.RegisterFactory
    let rid =
      try
        factory.GetRegisterID(name = name) |> Some
      with _ ->
        try factory.GetRegisterID(name.ToUpperInvariant()) |> Some
        with _ -> None
    rid |> Option.bind (fun rid ->
      match point.State.TryGetReg rid with
      | ValueSome expr -> Some expr
      | ValueNone -> None)

  let tryMemory (hdl: BinHandle) (point: StopPoint<SymbState>)
                (addr: Addr) (typ: RegType) =
    SymbMemoryOperation.load addr hdl.ISA.Endian typ point.State.Memory
    |> function
      | Ok expr -> Some expr
      | Error _ -> None

  type MemoryAccess =
    { Kind: SymbMemoryAccessKind
      Address: SymbExpr }

  let boolConst (value: bool): SymbExpr =
    SymbExpr.Const(if value then BitVector.T else BitVector.F)

  let notExpr (expr: SymbExpr) =
    match expr with
    | SymbExpr.Const bv when bv.IsTrue -> boolConst false
    | SymbExpr.Const bv when bv.IsFalse -> boolConst true
    | expr -> SymbExpr.unop UnOpType.NOT expr

  let orExpr (lhs: SymbExpr) (rhs: SymbExpr) =
    match lhs, rhs with
    | SymbExpr.Const bv, _ when bv.IsTrue -> lhs
    | _, SymbExpr.Const bv when bv.IsTrue -> rhs
    | SymbExpr.Const bv, expr when bv.IsFalse -> expr
    | expr, SymbExpr.Const bv when bv.IsFalse -> expr
    | _ -> SymbExpr.binop BinOpType.OR 1<rt> lhs rhs

  let anyExpr (exprs: SymbExpr list) =
    exprs |> List.fold orExpr (boolConst false)

  let tryAddress (point: StopPoint<SymbState>) (addr: LowUIRExpr) =
    match SymbExprEvaluator.eval point.State addr with
    | Ok expr -> Some expr
    | Error _ -> None

  let rec readAddresses (point: StopPoint<SymbState>) (expr: LowUIRExpr) =
    match expr with
    | LowUIRExpr.Load(_, _, addr, _) ->
      match tryAddress point addr with
      | Some expr -> [ expr ]
      | None -> []
    | LowUIRExpr.ExprList(exprs, _) ->
      exprs |> List.collect (readAddresses point)
    | LowUIRExpr.UnOp(_, expr, _)
    | LowUIRExpr.Cast(_, _, expr, _)
    | LowUIRExpr.Extract(expr, _, _, _) ->
      readAddresses point expr
    | LowUIRExpr.BinOp(_, _, lhs, rhs, _)
    | LowUIRExpr.RelOp(_, lhs, rhs, _) ->
      readAddresses point lhs @ readAddresses point rhs
    | LowUIRExpr.Ite(cond, thenExpr, elseExpr, _) ->
      readAddresses point cond
      @ readAddresses point thenExpr
      @ readAddresses point elseExpr
    | LowUIRExpr.RoundCtrl(mode, body, _) ->
      readAddresses point mode @ readAddresses point body
    | _ -> []

  let readAccesses point (expr: LowUIRExpr) =
    readAddresses point expr
    |> List.map (fun addr -> { Kind = MemoryRead; Address = addr })

  let tryWriteAccess point (addr: LowUIRExpr) =
    tryAddress point addr
    |> Option.map (fun addr -> { Kind = MemoryWrite; Address = addr })

  let stmtAccesses point (stmt: LowUIRStmt) =
    match stmt with
    | LowUIRStmt.Put(_, rhs, _) -> readAccesses point rhs
    | LowUIRStmt.Store(_, addr, value, _) ->
      let reads = readAccesses point addr @ readAccesses point value
      match tryWriteAccess point addr with
      | Some write -> write :: reads
      | None -> reads
    | LowUIRStmt.Jmp(target, _)
    | LowUIRStmt.InterJmp(target, _, _) ->
      readAccesses point target
    | LowUIRStmt.CJmp(cond, trueTarget, falseTarget, _)
    | LowUIRStmt.InterCJmp(cond, trueTarget, falseTarget, _) ->
      readAccesses point cond
      @ readAccesses point trueTarget
      @ readAccesses point falseTarget
    | LowUIRStmt.ExternalCall(expr, _) -> readAccesses point expr
    | _ -> []

  let memoryAccesses (point: StopPoint<SymbState>) =
    point.Statements
    |> Array.toList
    |> List.collect (stmtAccesses point)

  let inRegionExpr (expr: SymbExpr) (region: SymbMemoryRegion) =
    match expr with
    | SymbExpr.Const bv ->
      let addr = bv.ToUInt64()
      boolConst (addr >= region.Start && addr < region.Finish)
    | _ ->
      let lower = SymbExpr.relop RelOpType.GE expr (constFor expr region.Start)
      let upper = SymbExpr.relop RelOpType.LT expr (constFor expr region.Finish)
      SymbExpr.binop BinOpType.AND 1<rt> lower upper

  let allowedRegions kind regions =
    regions
    |> List.filter (fun region ->
      SymbRegionPerm.allows kind region.Permission)

  let allowedExpr regions access =
    allowedRegions access.Kind regions
    |> List.map (inRegionExpr access.Address)
    |> anyExpr

  let violationExpr regions access =
    allowedExpr regions access |> notExpr

  let testMemoryViolation kind regions point =
    memoryAccesses point
    |> List.filter (fun access ->
      match kind with
      | Some kind -> access.Kind = kind
      | None -> true)
    |> List.exists (fun access ->
      violationExpr regions access |> addCondition point.State)

  let rec evaluate
    (hdl: BinHandle) (regions: SymbMemoryRegion list)
    (condition: Condition) (point: StopPoint<SymbState>) =
    match condition with
    | At addr -> point.Address = addr
    | Compare(Register name, relop, value) ->
      match tryRegister hdl point name with
      | Some expr -> compareExpr point.State expr relop value
      | None -> false
    | Compare(Memory(addr, typ), relop, value) ->
      match tryMemory hdl point addr typ with
      | Some expr -> compareExpr point.State expr relop value
      | None -> false
    | Compare(WriteAddress, relop, value) ->
      memoryAccesses point
      |> List.choose (fun access ->
        match access.Kind with
        | MemoryWrite -> Some access.Address
        | MemoryRead -> None)
      |> List.exists (fun expr -> compareExpr point.State expr relop value)
    | MemoryPolicyViolation kind -> testMemoryViolation kind regions point
    | And conditions ->
      conditions
      |> List.forall (fun condition ->
        evaluate hdl regions condition point)

  let toPredicate hdl regions condition =
    StopPredicate<SymbState>(fun point ->
      evaluate hdl regions condition point
    )

  let trySatisfyAddress = function
    | At addr -> Some addr
    | _ -> None

module private SymbMetadata =
  let arg name kind optional description =
    { Name = name
      Kind = kind
      IsOptional = optional
      DefaultValue = None
      Choices = []
      Description = description }

  let choice name optional choices description =
    { Name = name
      Kind = ActionArgumentKind.Choice
      IsOptional = optional
      DefaultValue = None
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
  let symRegs =
    SymbMetadata.arg "sym-regs" ActionArgumentKind.Text true
      "Symbolic register assignments: [ESI=idx:4]."
  let regions =
    SymbMetadata.arg "regions" ActionArgumentKind.Text true
      "Memory regions: [track=0x70000000..0x70000400:rw]."
  let signature =
    "SymbExecutor -> @symb-context [pc:Address=<addr>] "
    + "[stack:Address=<addr>] [regs:String=<regs>] "
    + "[mem:String=<mem>] [sym-mem:String=<sym-mem>] "
    + "[sym-regs:String=<regs>] [regions:String=<regions>] "
    + "-> SymbExecutor"
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
          "sx |> @symb-context sym-regs=[ESI=idx:4]"
          "sx |> @symb-context regions=[buf=0x70000000..0x70001000:rw]" ]
        with
        Syntaxes =
          [ SymbMetadata.syntax None
              [ pc; stack; regs; mem; symMem; symRegs; regions ] ] }

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

type SymbSearchAction() =
  let cond =
    SymbMetadata.arg "cond" ActionArgumentKind.ParameterFunction false
      "Program-point predicate: fun pp -> pp.at(0x401000)."
  let precond =
    SymbMetadata.arg "precond" ActionArgumentKind.Text true
      "Initial constraints: ESI>99 or [ESI>99;RDX!=0]."
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
  let condArgs = [ cond; precond; maxDepth; maxStates; loopBound; prune ]
  let signature =
    "SymbExecutor -> @symb-search cond:ParameterFunction=<fun> "
    + "[precond:String=<conditions>] [max-depth:Int=<n>] "
    + "[max-states:Int=<n>] "
    + "[loop-bound:Int=<n>] [prune:Choice=<true|false>] -> SymbRunResult"
  let metadata =
    { SymbMetadata.metadata
        "symb-search"
        ReplValueKind.SymbExecutor
        ReplValueKind.SymbRunResult
        ActionRole.Transform
        signature
        "Search for symbolic inputs satisfying a state condition."
        [ "sx |> @symb-search cond=(fun pp -> pp.at(0x401000))"
          "sx |> @symb-search precond=ESI>99 "
          + "cond=(fun _ -> mem.accessViolation())"
          "sx |> @symb-search cond=(fun _ -> mem.accessViolation())" ]
        with
        Syntaxes =
          [ SymbMetadata.syntax None condArgs ] }

  let isBoolText (text: string) =
    match text.Trim().ToLowerInvariant() with
    | "true" | "false" -> true
    | _ -> false

  let isOptionValue (text: string) =
    match Int32.TryParse text with
    | true, _ -> true
    | _ -> isBoolText text

  let splitPrecondition = function
    | candidate :: rest when isOptionValue candidate |> not ->
      Some candidate, rest
    | args -> None, args

  let transformOne args (value: obj) =
    match value with
    | :? SymbExecutorValue as executor ->
      match args with
      | cond :: rest ->
        let hdl = Binary.Handle executor.Binary
        let precond, rest = splitPrecondition rest
        let executor =
          match precond with
          | Some precond ->
            let condition = SymbCondition.parsePreconditions precond
            let predicate =
              SymbCondition.toPredicate hdl executor.Regions condition
            executor.WithPrecondition predicate.Invoke
          | None -> executor
        let maxDepth, maxStates, loopBound, prune = SymbArgs.defaults rest
        let condition = SymbCondition.parse cond
        let result =
          match SymbCondition.trySatisfyAddress condition with
          | Some target ->
            executor.RunSatisfy(target, maxDepth, maxStates, loopBound, prune)
          | None ->
            let predicate =
              SymbCondition.toPredicate hdl executor.Regions condition
            executor.RunSatisfyCondition(predicate,
                                         maxDepth,
                                         maxStates,
                                         loopBound,
                                         prune)
        result |> box
      | _ -> invalidArg (nameof args) "Invalid symb-search arguments."
    | value -> invalidOp $"symb-search expects SymbExecutor: {value}"

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
