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
open B2R2.Collections
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.Executor
open B2R2.MiddleEnd.SymbEval

type LowUIRExpr = B2R2.BinIR.LowUIR.Expr

type LowUIRStmt = B2R2.BinIR.LowUIR.Stmt

type SymbCallHookRegistry = CallHookRegistry<SymbCallHook>

type SymbSolverFactory = Func<ISolver>

module private SymbCallModels =
  let fwrite (ctx: CallContext) (st: SymbState) =
    if ctx.ArgumentRegisters.Length < 3 then
      Error(UnsupportedOperation "fwrite requires three argument registers.")
    else
      match st.TryGetReg ctx.ArgumentRegisters[2] with
      | ValueSome count ->
        st.SetReg(ctx.ReturnRegister, count)
        Ok [ st ]
      | ValueNone ->
        Error(UninitializedRegister ctx.ArgumentRegisters[2])

  let tryFind = function
    | "fwrite" -> Some fwrite
    | "strlen" -> Some SymbCallHooks.strlen
    | _ -> None

  let bindImports (hdl: BinHandle) =
    BinFileOps.getImports hdl.File
    |> ImmutableArray.choose (fun entry ->
      match entry.TrampolineAddress, tryFind entry.Name with
      | Some addr, Some hook -> Some(addr, hook, entry.Name)
      | _ -> None)

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
      if id.StartsWith("@", StringComparison.Ordinal) then
        id[1..]
      else
        id
    id.ToLowerInvariant()

  let register id description factory =
    factories[normalize id] <- description, factory

  let create id =
    match factories.TryGetValue(normalize id) with
    | true, (description, factory) ->
      SymbSolverValue(normalize id, description, factory) |> Some
    | _ ->
      None

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

type SymbMemoryViolation =
  { Kind: SymbMemoryAccessKind
    Address: Addr }

module private SymbRegionPerm =
  let format permission =
    let chars =
      [ if permission.Read then Some "r" else None
        if permission.Write then Some "w" else None
        if permission.Execute then Some "x" else None ]
      |> List.choose id
    match chars with
    | [] ->
      "-"
    | chars ->
      String.concat "" chars

  let allows kind permission =
    match kind with
    | MemoryRead ->
      permission.Read
    | MemoryWrite ->
      permission.Write

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
    | "EAX" ->
      Some "RAX"
    | "EBX" ->
      Some "RBX"
    | "ECX" ->
      Some "RCX"
    | "EDX" ->
      Some "RDX"
    | "ESI" ->
      Some "RSI"
    | "EDI" ->
      Some "RDI"
    | "ESP" ->
      Some "RSP"
    | "EBP" ->
      Some "RBP"
    | "R8D" ->
      Some "R8"
    | "R9D" ->
      Some "R9"
    | "R10D" ->
      Some "R10"
    | "R11D" ->
      Some "R11"
    | "R12D" ->
      Some "R12"
    | "R13D" ->
      Some "R13"
    | "R14D" ->
      Some "R14"
    | "R15D" ->
      Some "R15"
    | _ ->
      None

  let symbolicRegisterValue
    endian
    registerType
    (bytes: SymbExpr list)
    size =
    let concat (lhs: SymbExpr) (rhs: SymbExpr) =
      let typ = RegType.fromBitWidth (int lhs.Type + int rhs.Type)
      SymbExpr.binop BinOpType.CONCAT typ lhs rhs
    let ordered =
      match endian with
      | Endian.Little ->
        List.rev bytes
      | _ ->
        bytes
    let value =
      match ordered with
      | [] ->
        invalidArg (nameof size) "Symbolic register size must be > 0."
      | head :: tail ->
        List.fold concat head tail
    if value.Type = registerType then
      value
    elif value.Type < registerType then
      SymbExpr.cast CastKind.ZeroExt registerType value
    else
      invalidArg (nameof size) "Symbolic register value is too wide."

  let symbolicRegisterQuery (bytes: SymbExpr list) =
    bytes
    |> List.map (fun byte -> QueryExpr.Value byte :> IQueryExpr)
    |> QueryExpr.Values
    :> IQueryExpr

  let setX64ParentRegister
    (hdl: BinHandle)
    (accessor: SymbStateAccessor)
    (register: string)
    (value: SymbExpr) =
    if hdl.ISA.WordSize = WordSize.Bit64 then
      match x64ParentRegister register with
      | Some parent ->
        let parentRid = hdl.RegisterFactory.GetRegisterID(name = parent)
        let parentType = hdl.RegisterFactory.GetRegType parentRid
        let parentValue = SymbExpr.cast CastKind.ZeroExt parentType value
        accessor.SetRegister(parentRid, parentValue)
      | None ->
        ()
    else
      ()

  let displayInputs (inputs: SymbolicInput list) =
    match List.rev inputs with
    | [] ->
      "none"
    | inputs ->
      inputs
      |> List.map (fun input ->
        $"{input.Name}@{input.Location}({input.Size} bytes)")
      |> String.concat ", "

  let displayAddresses (addresses: Set<Addr>) =
    if Set.isEmpty addresses then
      "none"
    else
      addresses
      |> Seq.map (fun addr -> $"0x{addr:x}")
      |> String.concat ", "

  let displayHooks (hooks: string list) =
    match List.rev hooks with
    | [] ->
      "none"
    | hooks ->
      String.concat ", " hooks

  let displayRegions (regions: SymbMemoryRegion list) =
    match List.rev regions with
    | [] ->
      "none"
    | regions ->
      regions
      |> List.map (fun region ->
        let perms = SymbRegionPerm.format region.Permission
        $"{region.Name}=0x{region.Start:x}-0x{region.Finish:x}:{perms}")
      |> String.concat ", "

  new(binary: Binary) =
    let hdl = Binary.Handle binary
    let executor = SymbExecutor hdl
    let bindings = SymbCallModels.bindImports hdl
    let hooks =
      if Array.isEmpty bindings then
        None
      else
        bindings
        |> Array.map (fun (addr, hook, _) -> addr, hook)
        |> SymbCallHookRegistry
        |> Some
    let hookText =
      bindings
      |> Array.map (fun (addr, _, name) -> $"{name}@0x{addr:x} (automatic)")
      |> Array.toList
      |> List.rev
    let regions =
      ContextParsing.imageRegions hdl.File
      |> List.map (fun region ->
        { Name = region.Name
          Start = region.Start
          Finish = region.Finish
          Permission =
            { Read = region.Permission.Read
              Write = region.Permission.Write
              Execute = region.Permission.Execute } })
    SymbExecutorValue(binary,
                      executor.CreateState(),
                      [],
                      Set.empty,
                      regions,
                      hooks,
                      hookText,
                      None)

  member _.Binary = binary

  member _.State = state

  member _.Inputs = inputs

  member _.Avoids = avoids

  member _.Regions = regions

  member _.Hooks = hooks

  member _.HookDescriptions = hookText

  member _.Solver = solver

  member _.CallPolicy =
    match hooks with
    | Some registry ->
      CallPolicy.UseCallHooks registry
    | None ->
      CallPolicy.FollowDirectInternalCalls

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
    | Error error ->
      invalidOp $"{error}"

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
    let value = symbolicRegisterValue hdl.ISA.Endian registerType bytes size
    let query = symbolicRegisterQuery bytes
    accessor.SetRegister(rid, value)
    setX64ParentRegister hdl accessor register value
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

  member _.WithFwriteHook addr =
    let registry =
      hooks
      |> Option.defaultValue (SymbCallHookRegistry())
      |> fun registry -> registry.Register(addr, SymbCallModels.fwrite)
    let hookText = $"fwrite@0x{addr:x}" :: hookText
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

  member _.WithExecutionSetup(entry, layout: ExecutionLayout, symRegs) =
    ((symRegs: SymbSymbolicRegisterAssignment list)
     |> List.map _.Register)
    @ (layout.Buffers |> List.map _.Register)
    |> ExecutionSetup.validateRegisterNames (Binary.Handle binary)
    let nextState = state.Clone()
    nextState.PC <- entry
    let accessor = SymbStateAccessor(Binary.Handle binary, nextState)
    accessor.SetStackPointer layout.InitialStackPointer
    accessor.InitializeFramePointer()
    let prepared =
      SymbExecutorValue(binary,
                        nextState,
                        inputs,
                        avoids,
                        regions,
                        hooks,
                        hookText,
                        solver)
    let withBuffers =
      layout.Buffers
      |> List.fold (fun (current: SymbExecutorValue) buffer ->
        current.WithRegister(buffer.Register, buffer.Address)) prepared
    let withRegions =
      ExecutionSetup.regions layout
      |> List.fold (fun (current: SymbExecutorValue) region ->
        current.WithRegion
          { Name = region.Name
            Start = region.Start
            Finish = region.Finish
            Permission =
              { Read = region.Permission.Read
                Write = region.Permission.Write
                Execute = region.Permission.Execute } }) withBuffers
    symRegs
    |> List.fold (fun (current: SymbExecutorValue)
                      (assignment: SymbSymbolicRegisterAssignment) ->
      current.WithSymbolicRegister(assignment.Register,
                                   assignment.Name,
                                   assignment.Size)) withRegions

  member _.RunSatisfy(target, maxDepth, maxStates, loopBound, prune, ct) =
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
    executor.Run(state.PC, state, options, ct)
    |> fun result -> SymbRunValue(this, "satisfy", Some target, result)

  member this.RunSatisfy(target, maxDepth, maxStates, loopBound, prune) =
    this.RunSatisfy(
      target,
      maxDepth,
      maxStates,
      loopBound,
      prune,
      CancellationToken.None
    )

  member _.RunSatisfyCondition(predicate,
                               maxDepth,
                               maxStates,
                               loopBound,
                               prune,
                               ct,
                               ?stopWhen: StopPredicate<SymbState>,
                               ?violationAnalyzer:
                                 SymbSatisfiabilityAnswer ->
                                   SymbMemoryViolation option) =
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
            (stopWhen
             |> Option.map SymbAvoidCondition.AvoidWhen
             |> Option.toList)
            @ (avoids
               |> Seq.map SymbAvoidCondition.AvoidAddress
               |> Seq.toList)
          MaxDepth = maxDepth
          MaxStates = maxStates
          LoopBound = loopBound
          PruneInfeasiblePaths = prune }
    let result = executor.Run(state.PC, state, options, ct)
    let violations =
      violationAnalyzer
      |> Option.map (fun analyze ->
        result.SatisfiabilityAnswers
        |> List.map (fun answer ->
          ct.ThrowIfCancellationRequested()
          analyze answer))
    SymbRunValue(this,
                 "cond",
                 None,
                 result,
                 ?violations = violations)

  member this.RunSatisfyCondition(predicate,
                                  maxDepth,
                                  maxStates,
                                  loopBound,
                                  prune) =
    this.RunSatisfyCondition(predicate,
                             maxDepth,
                             maxStates,
                             loopBound,
                             prune,
                             CancellationToken.None)

  member _.RunReach(target, maxDepth, maxStates, loopBound, prune, ct) =
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
    executor.Run(state.PC, state, options, ct)
    |> fun result -> SymbRunValue(this, "reach", Some target, result)

  member this.RunReach(target, maxDepth, maxStates, loopBound, prune) =
    this.RunReach(
      target,
      maxDepth,
      maxStates,
      loopBound,
      prune,
      CancellationToken.None
    )

  override _.ToString() =
    let inputText = displayInputs inputs
    let avoidText = displayAddresses avoids
    let hookText = displayHooks hookText
    let regionText = displayRegions regions
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
                 result: SymbRunResult,
                 ?violations: SymbMemoryViolation option list) =
  let violations =
    violations
    |> Option.defaultWith (fun () ->
      result.SatisfiabilityAnswers |> List.map (fun _ -> None))

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

  let indexedByteGroups values =
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
        |> fun bytes -> Some(prefix, bytes)
      else
        None)

  let appendAsciiGroups (sb: StringBuilder) values =
    let groups = indexedByteGroups values
    if List.isEmpty groups then
      ()
    else
      sb.AppendLine("  ascii:") |> ignore
      groups |> List.iter (fun (prefix, bytes) ->
        sb.AppendLine($"    {prefix}: {printableAscii bytes}") |> ignore)

  let statusText =
    match result.Timeout with
    | Some timeout ->
      $"timed out after {timeout} ms"
    | None ->
      match result.Answer with
      | SymbAnswer.Reachable answers ->
        $"reachable ({List.length answers} answer(s))"
      | SymbAnswer.Unreachable ->
        "unreachable"
      | SymbAnswer.Satisfiable answers ->
        $"satisfiable ({List.length answers} model(s))"
      | SymbAnswer.Unsatisfiable ->
        "unsatisfiable"
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
        violation
        (answer: SymbSatisfiabilityAnswer) =
    sb.AppendLine($"answer #{index}") |> ignore
    sb.AppendLine($"  target: 0x{answer.Target:x}") |> ignore
    match violation with
    | Some violation ->
      let kind =
        match violation.Kind with
        | MemoryRead -> "read"
        | MemoryWrite -> "write"
      sb.AppendLine($"  access violation: {kind} at "
                    + $"0x{violation.Address:x}")
      |> ignore
    | None ->
      ()
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

  member _.ConcreteInputs =
    result.SatisfiabilityAnswers
    |> List.collect (fun answer -> indexedByteGroups answer.Values)

  member _.InputModels =
    result.SatisfiabilityAnswers
    |> List.map (fun answer ->
      answer.Target, answer.Values, indexedByteGroups answer.Values)

  member _.Violations = violations

  member _.ModelText() =
    let sb = StringBuilder()
    let appendResult = function
      | SymbAnswer.Satisfiable answers ->
        List.zip answers violations
        |> List.iteri (fun idx (answer, violation) ->
          appendSatAnswer sb (idx + 1) violation answer)
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
  let parseAddr text = ContextParsing.parseAddress text

  let parseInt (text: string) =
    Int32.Parse(text, CultureInfo.InvariantCulture)

  let parseBool (text: string) =
    match text.ToLowerInvariant() with
    | "true" | "yes" | "on" ->
      true
    | "false" | "no" | "off" ->
      false
    | _ ->
      invalidArg (nameof text) $"Invalid boolean value: {text}"

  let parseHexBytes text = ContextParsing.parseHexBytes text

  let contextEntries text = ContextParsing.entries text

  let splitAssignment text = ContextParsing.splitAssignment text

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

  let parseRegionAssignment (entry: string) =
    let region = ContextParsing.parseRegion entry
    { Name = region.Name
      Start = region.Start
      Finish = region.Finish
      Permission =
        { Read = region.Permission.Read
          Write = region.Permission.Write
          Execute = region.Permission.Execute } }

  let parseContext args =
    let rec loop (spec: SymbContextSpec) = function
      | [] ->
        spec
      | (token: string) :: rest ->
        let key, value = ContextParsing.splitParameter token
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
            { spec with SymbolicRegisters = spec.SymbolicRegisters @ symbolic }
          | "regions" ->
            let regions =
              contextEntries value
              |> Array.toList
              |> List.map parseRegionAssignment
            { spec with Regions = spec.Regions @ regions }
          | _ ->
            invalidArg (nameof args)
              $"Unknown symbolic execution parameter: {key}"
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
  type IntegerLiteral =
    { Value: Addr
      Type: RegType option
      IsSigned: bool }

  type Term =
    | Register of string
    | Memory of Addr * RegType
    | WriteAddress

  type Condition =
    | At of Addr
    | Compare of Term * RelOpType * IntegerLiteral
    | MemoryPolicyViolation of SymbMemoryAccessKind option
    | And of Condition list

  let private parseRelOp = function
    | "=" | "==" ->
      RelOpType.EQ
    | "!=" | "<>" ->
      RelOpType.NEQ
    | "<" ->
      RelOpType.LT
    | "<=" ->
      RelOpType.LE
    | ">" ->
      RelOpType.GT
    | ">=" ->
      RelOpType.GE
    | op ->
      invalidArg (nameof op) $"Unsupported condition operator: {op}"

  module Grammar =
    open FParsec

    let private identifier = regex "[A-Za-z_][A-Za-z0-9_]*"

    let private numberText = regex "0[xX][0-9a-fA-F]+|[0-9]+"

    let tryAddress (text: string) =
      if text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        let digits = text[2..]
        let style = NumberStyles.HexNumber
        match UInt64.TryParse(digits, style, CultureInfo.InvariantCulture) with
        | true, value ->
          Some value
        | _ ->
          None
      else
        match UInt64.TryParse(text, CultureInfo.InvariantCulture) with
        | true, value ->
          Some value
        | _ ->
          None

    let private address =
      numberText >>= fun text ->
        match tryAddress text with
        | Some value ->
          preturn value
        | None ->
          fail "64-bit address"

    let private byteWidth =
      regex "[0-9]+" >>= fun text ->
        match Int32.TryParse(text, CultureInfo.InvariantCulture) with
        | true, width ->
          preturn width
        | _ ->
          fail "byte width"

    let private integerLiteral =
      let suffix =
        pchar ':' >>. anyOf "iIuU" .>>. regex "8|16|32|64"
      numberText .>>. opt suffix >>= fun (text, suffix) ->
        match tryAddress text with
        | None ->
          fail "64-bit integer"
        | Some value ->
          match suffix with
          | None ->
            preturn { Value = value; Type = None; IsSigned = false }
          | Some(sign, widthText) ->
            let width = Int32.Parse widthText
            let maximum =
              if width = 64 then UInt64.MaxValue else (1UL <<< width) - 1UL
            if value > maximum then
              fail $"value that fits in {width} bits"
            else
              preturn
                { Value = value
                  Type = Some(RegType.fromBitWidth width)
                  IsSigned = sign = 'i' || sign = 'I' }

    let private relOp =
      regex "==|!=|<>|<=|>=|=|<|>" |>> parseRelOp

    let private memoryTerm =
      between
        (pchar '[' .>> spaces)
        (spaces >>. pchar ']')
        (address .>>. opt (pchar ':' >>. byteWidth))
      |>> fun (addr, size) ->
        Memory(addr, RegType.fromByteWidth (defaultArg size 8))

    let comparison term =
      pipe3
        term
        (spaces >>. relOp .>> spaces)
        integerLiteral
        (fun subject op value -> Compare(subject, op, value))

    let private ppAtom =
      let term =
        choice
          [ pstringCI "REG" >>. spaces >>.
              between
                (pchar '[' .>> spaces)
                (spaces >>. pchar ']')
                identifier |>> Register
            pstringCI "MEM" >>. spaces >>. memoryTerm
            pstringCI "WRITE" >>% WriteAddress ]
      let at =
        pstringCI "at" >>. spaces >>.
          between
            (pchar '(' .>> spaces)
            (spaces >>. pchar ')')
            address
        |>> At
      pstringCI "pp." >>. (at <|> comparison term)

    let private memoryPolicy =
      let kind =
        choice
          [ pstringCI "accessViolation" >>% None
            pstringCI "readViolation" >>% Some MemoryRead
            pstringCI "writeViolation" >>% Some MemoryWrite ]
      pstringCI "mem" >>. opt (pstringCI "ory") >>. pchar '.' >>.
        kind .>> spaces .>> between
          (pchar '(' .>> spaces)
          (pchar ')')
          spaces
      |>> MemoryPolicyViolation

    let private preconditionAtom =
      let register = identifier |>> Register
      let term =
        attempt (pstringCI "MEM" >>. spaces >>. memoryTerm)
        <|> register
      comparison term

    let conjunction atom separator =
      let expression, expressionRef =
        createParserForwardedToRef<Condition, unit>()
      let group =
        between
          (pchar '(' .>> spaces)
          (spaces >>. pchar ')')
          expression
      let element = group <|> atom
      expressionRef.Value <-
        sepBy1 element (attempt (spaces >>. separator .>> spaces))
        |>> function
          | [ condition ] -> condition
          | conditions -> And conditions
      expression

    let private condition =
      let atom = ppAtom <|> memoryPolicy
      let body = conjunction atom (pstring "&&")
      let lambda =
        pstring "fun" >>. spaces1 >>. identifier .>> spaces
        .>> pstring "->" .>> spaces >>. body
      spaces >>. opt (pchar '(' .>> spaces) >>= fun opening ->
        let closing =
          if Option.isSome opening then
            spaces >>. pchar ')' >>% ()
          else
            preturn ()
        lambda .>> closing .>> spaces .>> eof

    let private precondition =
      let separator = pstring "&&" <|> pstring ";"
      let body = conjunction preconditionAtom separator
      spaces >>. opt (pchar '[' .>> spaces) >>= fun opening ->
        let body =
          if Option.isSome opening then
            opt body |>> Option.defaultValue (And [])
            .>> spaces .>> pchar ']'
          else
            opt body |>> Option.defaultValue (And [])
        body .>> spaces .>> eof

    let parse name parser text =
      match run parser text with
      | Success(condition, _, _) ->
        condition
      | Failure(message, _, _) ->
        invalidArg (nameof text) $"Invalid {name}: {message}"

    let parseCondition text = parse "condition" condition text

    let parsePrecondition text = parse "precondition" precondition text

  let parse text = Grammar.parseCondition text

  let parsePreconditions text = Grammar.parsePrecondition text

  let constFor (expr: SymbExpr) (value: Addr) =
    SymbExpr.Const(BitVector(uint64 value, expr.Type))

  let addCondition (state: SymbState) (expr: SymbExpr) =
    match expr with
    | SymbExpr.Const bv when bv.IsTrue ->
      true
    | SymbExpr.Const bv when bv.IsFalse ->
      false
    | _ ->
      state.AddPathCondition expr; true

  let signedRelOp = function
    | RelOpType.GT ->
      RelOpType.SGT
    | RelOpType.GE ->
      RelOpType.SGE
    | RelOpType.LT ->
      RelOpType.SLT
    | RelOpType.LE ->
      RelOpType.SLE
    | relop ->
      relop

  let compareExpr
    (state: SymbState)
    (lhs: SymbExpr)
    relop
    (literal: IntegerLiteral) =
    match literal.Type with
    | Some typ when typ <> lhs.Type ->
      invalidArg (nameof literal)
        $"Literal type {int typ} does not match operand width {int lhs.Type}."
    | _ ->
      let relop = if literal.IsSigned then signedRelOp relop else relop
      SymbExpr.relop relop lhs (constFor lhs literal.Value)
      |> addCondition state

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
      | ValueSome expr ->
        Some expr
      | ValueNone ->
        None)

  let tryMemory
    (hdl: BinHandle)
    (point: StopPoint<SymbState>)
    (addr: Addr)
    (typ: RegType) =
    SymbMemoryOperation.load addr hdl.ISA.Endian typ point.State.Memory
    |> function
      | Ok expr ->
        Some expr
      | Error _ ->
        None

  type MemoryAccess =
    { Kind: SymbMemoryAccessKind
      Address: SymbExpr }

  let boolConst (value: bool): SymbExpr =
    SymbExpr.Const(if value then BitVector.T else BitVector.F)

  let notExpr (expr: SymbExpr) =
    match expr with
    | SymbExpr.Const bv when bv.IsTrue ->
      boolConst false
    | SymbExpr.Const bv when bv.IsFalse ->
      boolConst true
    | expr ->
      SymbExpr.unop UnOpType.NOT expr

  let orExpr (lhs: SymbExpr) (rhs: SymbExpr) =
    match lhs, rhs with
    | SymbExpr.Const bv, _ when bv.IsTrue ->
      lhs
    | _, SymbExpr.Const bv when bv.IsTrue ->
      rhs
    | SymbExpr.Const bv, expr when bv.IsFalse ->
      expr
    | expr, SymbExpr.Const bv when bv.IsFalse ->
      expr
    | _ ->
      SymbExpr.binop BinOpType.OR 1<rt> lhs rhs

  let anyExpr (exprs: SymbExpr list) =
    exprs |> List.fold orExpr (boolConst false)

  let tryAddress (point: StopPoint<SymbState>) (addr: LowUIRExpr) =
    match SymbExprEvaluator.eval point.State addr with
    | Ok expr ->
      Some expr
    | Error _ ->
      None

  let rec readAddresses (point: StopPoint<SymbState>) (expr: LowUIRExpr) =
    match expr with
    | LowUIRExpr.Load(Addr = addr) ->
      match tryAddress point addr with
      | Some expr ->
        [ expr ]
      | None ->
        []
    | LowUIRExpr.ExprList(Elements = exprs) ->
      exprs |> List.collect (readAddresses point)
    | LowUIRExpr.UnOp(Operand = expr)
    | LowUIRExpr.Cast(Operand = expr)
    | LowUIRExpr.Extract(Operand = expr) ->
      readAddresses point expr
    | LowUIRExpr.BinOp(Left = lhs; Right = rhs)
    | LowUIRExpr.RelOp(Left = lhs; Right = rhs) ->
      readAddresses point lhs @ readAddresses point rhs
    | LowUIRExpr.Ite(Cond = cond; TrueExpr = thenExpr; FalseExpr = elseExpr) ->
      readAddresses point cond
      @ readAddresses point thenExpr
      @ readAddresses point elseExpr
    | LowUIRExpr.RoundCtrl(Mode = mode; Body = body) ->
      readAddresses point mode @ readAddresses point body
    | _ ->
      []

  let readAccesses point (expr: LowUIRExpr) =
    readAddresses point expr
    |> List.map (fun addr -> { Kind = MemoryRead; Address = addr })

  let tryWriteAccess point (addr: LowUIRExpr) =
    tryAddress point addr
    |> Option.map (fun addr -> { Kind = MemoryWrite; Address = addr })

  let stmtAccesses point (stmt: LowUIRStmt) =
    match stmt with
    | LowUIRStmt.Put(Src = rhs) ->
      readAccesses point rhs
    | LowUIRStmt.Store(Addr = addr; Value = value) ->
      let reads = readAccesses point addr @ readAccesses point value
      match tryWriteAccess point addr with
      | Some write ->
        write :: reads
      | None ->
        reads
    | LowUIRStmt.Jmp(Target = target)
    | LowUIRStmt.InterJmp(Target = target) ->
      readAccesses point target
    | LowUIRStmt.CJmp(Cond = cond
                      TrueTarget = trueTarget
                      FalseTarget = falseTarget)
    | LowUIRStmt.InterCJmp(Cond = cond
                           TrueTarget = trueTarget
                           FalseTarget = falseTarget) ->
      readAccesses point cond
      @ readAccesses point trueTarget
      @ readAccesses point falseTarget
    | LowUIRStmt.ExternalCall(Call = expr) ->
      readAccesses point expr
    | _ ->
      []

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
      | Some kind ->
        access.Kind = kind
      | None ->
        true)
    |> List.exists (fun access ->
      violationExpr regions access |> addCondition point.State)

  let witnessAddressExpr (expr: SymbExpr) =
    if expr.Type = 64<rt> then expr
    elif expr.Type < 64<rt> then SymbExpr.cast CastKind.ZeroExt 64<rt> expr
    else SymbExpr.extract expr 64<rt> 0

  let rec evaluate
    (hdl: BinHandle)
    (regions: SymbMemoryRegion list)
    (condition: Condition)
    (point: StopPoint<SymbState>) =
    match condition with
    | At addr ->
      point.Address = addr
    | Compare(Register name, relop, literal) ->
      match tryRegister hdl point name with
      | Some expr ->
        compareExpr point.State expr relop literal
      | None ->
        false
    | Compare(Memory(addr, typ), relop, literal) ->
      match tryMemory hdl point addr typ with
      | Some expr ->
        compareExpr point.State expr relop literal
      | None ->
        false
    | Compare(WriteAddress, relop, literal) ->
      memoryAccesses point
      |> List.choose (fun access ->
        match access.Kind with
        | MemoryWrite ->
          Some access.Address
        | MemoryRead ->
          None)
      |> List.exists (fun expr -> compareExpr point.State expr relop literal)
    | MemoryPolicyViolation kind ->
      testMemoryViolation kind regions point
    | And conditions ->
      conditions
      |> List.forall (fun condition ->
        evaluate hdl regions condition point)

  let toPredicate hdl regions condition =
    StopPredicate<SymbState>(fun point ->
      evaluate hdl regions condition point
    )

  let fixedModelConditions (answer: SymbSatisfiabilityAnswer) =
    answer.Values
    |> List.map (fun value ->
      let variable = SymbExpr.Var(value.Name, value.Value.Length)
      SymbExpr.relop RelOpType.EQ variable (SymbExpr.Const value.Value))

  let trySolveViolation solver path regions access =
    let violation = violationExpr regions access
    match violation, access.Address with
    | SymbExpr.Const violated, SymbExpr.Const address
        when violated.IsTrue ->
      Some({ Kind = access.Kind
             Address = address.ToUInt64() }: SymbMemoryViolation)
    | _ ->
      (solver: Lazy<ISolver option>).Value
      |> Option.bind (fun (solver: ISolver) ->
        let name = "__b2r2_violation_address_" + Guid.NewGuid().ToString("N")
        let witness = SymbExpr.Var(name, 64<rt>)
        let address = witnessAddressExpr access.Address
        let addressConstraint =
          SymbExpr.relop RelOpType.EQ witness address
        let conditions =
          violation :: addressConstraint :: path
        let smt = SMTLibSerializer.serializeAssertions conditions [ witness ]
        let status =
          solver.CheckSat smt
          |> Result.bind SolverOutputParser.parseStatus
        match status with
        | Ok SolverStatus.Sat ->
          match solver.GetModels smt
                |> Result.bind (SolverOutputParser.extract [ witness ]) with
          | Ok { Values = [ value ] } ->
            Some({ Kind = access.Kind
                   Address = value.Value.ToUInt64() }: SymbMemoryViolation)
          | _ ->
            None
        | _ ->
          None)

  let violationAnalyzer hdl regions solver kind =
    let liftCache = LiftCache hdl
    let solver =
      lazy (solver |> Option.map (fun (value: SymbSolverValue) ->
        value.Create()))
    fun (answer: SymbSatisfiabilityAnswer) ->
      match liftCache.TryLift answer.Target with
      | Error _ ->
        None
      | Ok lifted ->
        let point =
          { Address = answer.Target
            InstructionCount = 0
            Instruction = Some lifted.Instruction
            Statements = lifted.Stmts
            State = answer.State }
        let pathCondition =
          fixedModelConditions answer @ answer.State.PathCondition
        memoryAccesses point
        |> List.filter (fun access ->
          kind |> Option.forall ((=) access.Kind))
        |> List.tryPick (trySolveViolation solver pathCondition regions)

  let toQueryPredicate hdl regions solver condition =
    let predicate = toPredicate hdl regions condition
    match condition with
    | MemoryPolicyViolation kind ->
      predicate, Some(violationAnalyzer hdl regions solver kind)
    | _ ->
      predicate, None

  let trySatisfyAddress = function
    | At addr ->
      Some addr
    | _ ->
      None

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
      OutputRelation = ActionOutputRelation.Fixed
      Role = role
      Syntaxes = []
      Signature = signature
      Description = description
      Examples = examples
      Priority = 20 }

module private SymbExecutorSetup =
  let private contextKeys =
    Set.ofList
      [ "pc"; "stack"; "regs"; "mem"; "sym-mem"; "sym-regs"; "regions" ]

  let symbolicArguments text =
    ContextParsing.entries text
    |> Array.map (fun entry ->
      let index, spec = ContextParsing.splitAssignment entry
      let separator = spec.LastIndexOf ':'
      if separator <= 0 then
        invalidArg (nameof text)
          $"Expected ABI argument index=name:size: {entry}"
      else
        let index = SymbArgs.parseInt index
        let name = spec[..separator - 1].Trim()
        let size = SymbArgs.parseInt (spec[separator + 1..].Trim())
        if index < 0 || size <= 0 || String.IsNullOrWhiteSpace name then
          invalidArg (nameof text) $"Invalid symbolic ABI argument: {entry}"
        else
          index, name, size)
    |> Array.toList

  let parseOptions args =
    args
    |> List.map ContextParsing.splitParameter
    |> Map.ofList

  let context options =
    options
    |> Map.toList
    |> List.choose (fun (key, value) ->
      if Set.contains key contextKeys then Some $"{key}={value}" else None)
    |> SymbArgs.parseContext

  let layout binary context options hasArguments =
    ExecutionSetup.requestedBufferSpec options hasArguments
    |> Option.map (fun buffers ->
      let hdl = Binary.Handle binary
      ExecutionSetup.layoutForStack hdl context.Stack buffers)

  let applyLayout binary layout context (executor: SymbExecutorValue) =
    match layout with
    | Some layout ->
      let hdl = Binary.Handle binary
      let entry =
        context.PC
        |> Option.defaultWith (fun () ->
          hdl.File.EntryPoint |> Option.defaultValue hdl.File.BaseAddress)
      let executor =
        executor.WithExecutionSetup(entry, layout, context.SymbolicRegisters)
      executor, { context with Stack = None; SymbolicRegisters = [] }
    | None ->
      executor, context

  let configure options (executor: SymbExecutorValue) =
    let executor =
      match Map.tryFind "avoid" options with
      | Some text ->
        ContextParsing.entries text
        |> Array.fold (fun (current: SymbExecutorValue) address ->
          current.WithAvoid(SymbArgs.parseAddr address)) executor
      | None ->
        executor
    match Map.tryFind "hooks" options with
    | Some text ->
      ContextParsing.entries text
      |> Array.fold (fun (current: SymbExecutorValue) entry ->
        let name, address = ContextParsing.splitAssignment entry
        let address = SymbArgs.parseAddr address
        match name.Trim().ToLowerInvariant() with
        | "strlen" -> current.WithStrlenHook address
        | "fwrite" -> current.WithFwriteHook address
        | _ -> invalidArg (nameof text) $"Unknown call hook: {name}")
        executor
    | None ->
      executor

  let create (binary: Binary) options =
    let solverID =
      options |> Map.tryFind "solver" |> Option.defaultValue "symb-z3"
    let solver =
      SymbSolverRegistry.create solverID
      |> Option.defaultWith (fun () ->
        invalidOp $"The {solverID} solver is unavailable. Load its plugin.")
    let context = context options
    let arguments =
      options
      |> Map.tryFind "sym-args"
      |> Option.map symbolicArguments
      |> Option.defaultValue []
    let layout = layout binary context options (not (List.isEmpty arguments))
    let executor = SymbExecutorValue(binary).WithSolver solver
    let executor, context = applyLayout binary layout context executor
    let executor = executor.WithContext context
    let executor =
      arguments
      |> List.fold (fun (current: SymbExecutorValue) (index, name, size) ->
        current.WithSymbolicArgument(index, name, size)) executor
    configure options executor, layout

type SymbExecAction() =
  let solver =
    SymbMetadata.arg
      "solver"
      ActionArgumentKind.Action
      true
      "Solver provider action, such as @symb-z3."
  let pc =
    SymbMetadata.arg
      "pc"
      ActionArgumentKind.Address
      true
      "Address where symbolic execution starts."
  let stack =
    SymbMetadata.arg
      "stack"
      ActionArgumentKind.Address
      true
      "Initial stack pointer."
  let regs =
    SymbMetadata.arg
      "regs"
      ActionArgumentKind.Text
      true
      "Concrete register assignments: [RDI=0x70000000]."
  let mem =
    SymbMetadata.arg
      "mem"
      ActionArgumentKind.Text
      true
      "Concrete memory assignments: [0x70000000=00]."
  let symMem =
    SymbMetadata.arg
      "sym-mem"
      ActionArgumentKind.Text
      true
      "Symbolic memory assignments: [input@0x70000000:16]."
  let symRegs =
    SymbMetadata.arg
      "sym-regs"
      ActionArgumentKind.Text
      true
      "Symbolic register assignments: [ESI=idx:4]."
  let regions =
    SymbMetadata.arg
      "regions"
      ActionArgumentKind.Text
      true
      "Memory regions: [buf=0x70000000..0x70000400:rw]."
  let symArgs =
    SymbMetadata.arg
      "sym-args"
      ActionArgumentKind.Text
      true
      "Symbolic ABI buffers: [0=input:32]."
  let buffers =
    SymbMetadata.arg
      "buffers"
      ActionArgumentKind.Text
      true
      "Allocated buffers: [RDI=track:0x400:rw]."
  let avoid =
    SymbMetadata.arg
      "avoid"
      ActionArgumentKind.Text
      true
      "Addresses to exclude from exploration: [0x401e62]."
  let hooks =
    SymbMetadata.arg
      "hooks"
      ActionArgumentKind.Text
      true
      "External call models: [strlen=0x401000; fwrite=0x401220]."
  let metadata =
    let signature =
      "Binary | BinarySlice -> @make-symbolic-executor "
      + "[solver=<action>] [pc=<addr>] [stack=<addr>] "
      + "[regs=[...]] [mem=[...]] [sym-mem=[...]] "
      + "[sym-regs=[...]] [regions=[...]] [sym-args=[...]] "
      + "[buffers=[...]] [avoid=[...]] [hooks=[...]] "
      + "-> SymbExecutor"
    { SymbMetadata.metadata
        "make-symbolic-executor"
        ReplValueKind.Binary
        ReplValueKind.SymbExecutor
        ActionRole.Transform
        signature
        "Create a symbolic executor over a binary or binary slice."
        [ "binary |> @make-symbolic-executor pc=<addr> "
          + "sym-regs=[ESI=idx:4]" ] with
        AlternativeInputs = [ ReplValueKind.BinarySlice ]
        Syntaxes =
          [ SymbMetadata.syntax None
              [ solver
                pc
                stack
                regs
                mem
                symMem
                symRegs
                regions
                symArgs
                buffers
                avoid
                hooks ] ] }

  let transformNamed args (collection: ObjCollection) =
    let options = Map.ofList args
    let values =
      collection.Values
      |> Array.map (function
        | :? Binary as binary ->
          SymbExecutorSetup.create binary options |> fst |> box
        | :? BinarySlice as slice ->
          SymbExecutorSetup.create (slice.ToBinary()) options
          |> fst
          |> box
        | value ->
          invalidOp $"make-symbolic-executor expects Binary: {value}")
    { Values = values }

  let transform args collection =
    SymbExecutorSetup.parseOptions args
    |> Map.toList
    |> fun options -> transformNamed options collection

  interface IAction with
    member _.ActionID with get() = metadata.ID
    member _.Signature with get() = metadata.Signature
    member _.Description with get() = metadata.Description
    member _.Transform(args, collection) = transform args collection

  interface IActionMetadataProvider with
    member _.Metadata with get() = metadata

  interface ICancellableAction with
    member _.Transform(args, collection, _) =
      transform args collection

  interface ICancellableNamedArgumentsAction with
    member _.TransformNamed(args, collection, _) =
      transformNamed args collection

type SymbSearchAction() =
  let entry =
    SymbMetadata.arg
      "entry"
      ActionArgumentKind.Address
      false
      "Address of the function to explore."
  let solver =
    SymbMetadata.arg
      "solver"
      ActionArgumentKind.Action
      true
      "Symbolic solver provider. Default: @symb-z3."
  let stack =
    SymbMetadata.arg
      "stack"
      ActionArgumentKind.Address
      true
      "Initial stack pointer."
  let registers =
    SymbMetadata.arg
      "regs"
      ActionArgumentKind.Text
      true
      "Concrete register assignments."
  let memory =
    SymbMetadata.arg
      "mem"
      ActionArgumentKind.Text
      true
      "Concrete memory assignments."
  let symbolicMemory =
    SymbMetadata.arg
      "sym-mem"
      ActionArgumentKind.Text
      true
      "Symbolic memory assignments."
  let symbolicRegisters =
    { SymbMetadata.arg
        "sym-regs"
        ActionArgumentKind.Text
        false
        "Symbolic arguments: [ESI=idx:4; RDX=ind:8]." with
        IsOptional = true
        DefaultValue = Some ActionArgumentDefault.EmptyList
        Choices = [ "[]" ] }
  let regions =
    SymbMetadata.arg
      "regions"
      ActionArgumentKind.Text
      true
      "Additional memory regions."
  let symbolicArguments =
    SymbMetadata.arg
      "sym-args"
      ActionArgumentKind.Text
      true
      "Symbolic ABI buffers: [0=input:32]."
  let buffers =
    { SymbMetadata.arg
        "buffers"
        ActionArgumentKind.Text
        false
        "Allocated buffers: [RDI=track:0x400:rw]." with
        IsOptional = true
        DefaultValue = Some ActionArgumentDefault.EmptyList
        Choices = [ "[]" ] }
  let avoid =
    SymbMetadata.arg
      "avoid"
      ActionArgumentKind.Text
      true
      "Addresses to exclude from exploration: [0x401e62]."
  let hooks =
    SymbMetadata.arg
      "hooks"
      ActionArgumentKind.Text
      true
      "External call models: [strlen=0x401000; fwrite=0x401220]."
  let check =
    SymbMetadata.choice
      "check"
      true
      [ "access-violation" ]
      "Condition to search for. Default: access-violation."
  let cond =
    SymbMetadata.arg
      "cond"
      ActionArgumentKind.ParameterFunction
      false
      "Program-point predicate: fun pp -> pp.at(0x401000)."
  let precond =
    SymbMetadata.arg
      "precond"
      ActionArgumentKind.Text
      true
      "Initial constraints: ESI>99:u32 or [ESI>99:i32;RDX!=0]."
  let maxDepth =
    SymbMetadata.arg
      "max-depth"
      ActionArgumentKind.Integer
      true
      "Maximum instructions per path. Default: 512."
  let maxStates =
    SymbMetadata.arg
      "max-states"
      ActionArgumentKind.Integer
      true
      "Maximum states to expand. Default: 2048."
  let loopBound =
    SymbMetadata.arg
      "loop-bound"
      ActionArgumentKind.Integer
      true
      "Maximum visits to the same address. Default: 2."
  let prune =
    SymbMetadata.choice
      "prune"
      true
      [ "true"; "false" ]
      "Use the solver to prune infeasible paths. Default: true."
  let executorCondArgs =
    [ cond; precond; maxDepth; maxStates; loopBound; prune; avoid; hooks ]
  let executorDefaultArgs =
    [ check; precond; maxDepth; maxStates; loopBound; prune; avoid; hooks ]
  let setupArgs =
    [ entry
      solver
      stack
      registers
      memory
      symbolicMemory
      symbolicRegisters
      regions
      symbolicArguments
      buffers
      avoid
      hooks ]
  let directArgs =
    setupArgs
    @ [ check
        precond
        maxDepth
        maxStates
        loopBound
        prune ]
  let directCondArgs =
    setupArgs @ [ cond; precond; maxDepth; maxStates; loopBound; prune ]
  let signature =
    "Binary -> @run-symbolic entry=<addr> [solver=<action>] "
    + "[stack=<addr>] [regs=[...]] [mem=[...]] [sym-mem=[...]] "
    + "[sym-regs=[...]] [regions=[...]] [sym-args=[...]] "
    + "[buffers=[...]] [avoid=[...]] [hooks=[...]] "
    + "[check=access-violation | cond=<fun>] | "
    + "SymbExecutor -> @run-symbolic "
    + "[check=access-violation | cond:ParameterFunction=<fun>] "
    + "[precond:String=<conditions>] [max-depth:Int=<n>] "
    + "[max-states:Int=<n>] "
    + "[loop-bound:Int=<n>] [prune:Choice=<true|false>] "
    + "[avoid=[...]] [hooks=[...]] -> SymbRunResult"
  let metadata =
    { SymbMetadata.metadata
        "run-symbolic"
        ReplValueKind.Binary
        ReplValueKind.SymbRunResult
        ActionRole.Transform
        signature
        ("Search for symbolic inputs satisfying a state condition. "
         + "By default, search for a memory access violation.")
        [ "binary |> @run-symbolic entry=<addr> "
          + "sym-regs=[ESI=idx:4] buffers=[RDI=buf:0x400:rw]"
          "sx |> @run-symbolic cond=(fun pp -> pp.at(<addr>))"
          "sx |> @run-symbolic precond=ESI>99:u32 "
          + "cond=(fun _ -> mem.accessViolation())"
          "sx |> @run-symbolic cond=(fun _ -> mem.accessViolation())" ]
        with
        AlternativeInputs =
          [ ReplValueKind.BinarySlice; ReplValueKind.SymbExecutor ]
        Syntaxes =
          [ { SymbMetadata.syntax None directArgs with
                Inputs =
                  [ ReplValueKind.Binary; ReplValueKind.BinarySlice ] }
            { SymbMetadata.syntax None directCondArgs with
                Inputs =
                  [ ReplValueKind.Binary; ReplValueKind.BinarySlice ] }
            { SymbMetadata.syntax None executorDefaultArgs with
                Inputs = [ ReplValueKind.SymbExecutor ] }
            { SymbMetadata.syntax None executorCondArgs with
                Inputs = [ ReplValueKind.SymbExecutor ] } ] }

  let withPrecondition hdl options (executor: SymbExecutorValue) =
    match Map.tryFind "precond" options with
    | Some text ->
      let condition = SymbCondition.parsePreconditions text
      let predicate =
        SymbCondition.toPredicate hdl executor.Regions condition
      executor.WithPrecondition predicate.Invoke
    | None ->
      executor

  let defaultCondition = "(fun _ -> mem.accessViolation())"

  let conditionText options =
    match Map.tryFind "check" options, Map.tryFind "cond" options with
    | None, None
    | Some "access-violation", None ->
      defaultCondition
    | None, Some condition ->
      condition
    | Some check, None ->
      invalidArg (nameof options) $"Unsupported check: {check}"
    | _ ->
      invalidArg (nameof options) "Specify either check= or cond=."

  let stopAtReturn hdl (executor: SymbExecutorValue) =
    let returnSP =
      let accessor = SymbStateAccessor(hdl, executor.State)
      match accessor.TryGetStackPointer() with
      | Ok stackPointer ->
        stackPointer
      | Error error ->
        invalidOp $"Cannot determine the initial stack pointer: {error}"
    StopPredicate<SymbState>(fun point ->
      match point.Instruction with
      | Some instruction when instruction.IsRET ->
        let accessor = SymbStateAccessor(hdl, point.State)
        match accessor.TryGetStackPointer() with
        | Ok stackPointer ->
          stackPointer = returnSP
        | Error _ ->
          false
      | _ ->
        false)

  let directLimits options =
    let optionInt name fallback =
      options
      |> Map.tryFind name
      |> Option.map SymbArgs.parseInt
      |> Option.defaultValue fallback
    let maxDepth = optionInt "max-depth" 512
    let maxStates = optionInt "max-states" 2048
    let loopBound = optionInt "loop-bound" 2
    let prune =
      options
      |> Map.tryFind "prune"
      |> Option.map SymbArgs.parseBool
      |> Option.defaultValue true
    maxDepth, maxStates, loopBound, prune

  let runBinaryNamed ct options binary =
    let entry = Map.find "entry" options
    let setup = options |> Map.add "pc" entry
    let setup =
      if Map.containsKey "buffers" setup
         || Map.containsKey "stack" setup then
        setup
      else
        Map.add "buffers" "[]" setup
    let executor, _ = SymbExecutorSetup.create binary setup
    let hdl = Binary.Handle binary
    let executor = withPrecondition hdl options executor
    let condition =
      conditionText options
      |> SymbCondition.parse
    let predicate, analyzer =
      SymbCondition.toQueryPredicate
        hdl executor.Regions executor.Solver condition
    let stopAtReturn = stopAtReturn hdl executor
    let maxDepth, maxStates, loopBound, prune = directLimits options
    executor.RunSatisfyCondition(predicate,
                                 maxDepth,
                                 maxStates,
                                 loopBound,
                                 prune,
                                 ct,
                                 stopWhen = stopAtReturn,
                                 ?violationAnalyzer = analyzer)
    |> box

  let runBinary ct args binary =
    match args with
    | [ entry; registers; buffers ] ->
      Map.ofList
        [ "entry", entry
          "sym-regs", registers
          "buffers", buffers ]
      |> fun options -> runBinaryNamed ct options binary
    | [ entry; registers; buffers; check ] ->
      Map.ofList
        [ "entry", entry
          "sym-regs", registers
          "buffers", buffers
          "check", check ]
      |> fun options -> runBinaryNamed ct options binary
    | _ ->
      invalidArg (nameof args) "Invalid binary run-symbolic arguments."

  let isBoolText (text: string) =
    match text.Trim().ToLowerInvariant() with
    | "true" | "false" ->
      true
    | _ ->
      false

  let isOptionValue (text: string) =
    match Int32.TryParse text with
    | true, _ ->
      true
    | _ ->
      isBoolText text

  let splitPrecondition = function
    | candidate :: rest when isOptionValue candidate |> not ->
      Some candidate, rest
    | args ->
      None, args

  let transformOne ct args (value: obj) =
    match value with
    | :? Binary as binary ->
      runBinary ct args binary
    | :? BinarySlice as slice ->
      runBinary ct args (slice.ToBinary())
    | :? SymbExecutorValue as executor ->
      let cond, rest =
        match args with
        | [] -> defaultCondition, []
        | cond :: rest -> cond, rest
      let hdl = Binary.Handle executor.Binary
      let precond, rest = splitPrecondition rest
      let executor =
        match precond with
        | Some precond ->
          let condition = SymbCondition.parsePreconditions precond
          let predicate =
            SymbCondition.toPredicate hdl executor.Regions condition
          executor.WithPrecondition predicate.Invoke
        | None ->
          executor
      let maxDepth, maxStates, loopBound, prune = SymbArgs.defaults rest
      let condition = SymbCondition.parse cond
      let result =
        match SymbCondition.trySatisfyAddress condition with
        | Some target ->
          executor.RunSatisfy(target,
                              maxDepth,
                              maxStates,
                              loopBound,
                              prune,
                              ct)
        | None ->
          let predicate, analyzer =
            SymbCondition.toQueryPredicate
              hdl executor.Regions executor.Solver condition
          executor.RunSatisfyCondition(predicate,
                                       maxDepth,
                                       maxStates,
                                       loopBound,
                                       prune,
                                       ct,
                                       ?violationAnalyzer = analyzer)
      result |> box
    | value ->
      invalidOp $"run-symbolic expects SymbExecutor: {value}"

  let transform ct args (collection: ObjCollection) =
    collection.Values
    |> Array.map (transformOne ct args)
    |> fun values ->
      { Values = values }

  let transformNamed ct args (collection: ObjCollection) =
    let options = Map.ofList args
    let option name fallback =
      Map.tryFind name options |> Option.defaultValue fallback
    let executorArgs () =
      [ conditionText options ]
      @ (Map.tryFind "precond" options |> Option.toList)
      @ [ option "max-depth" "512"
          option "max-states" "2048"
          option "loop-bound" "2"
          option "prune" "true" ]
    { Values =
        collection.Values
        |> Array.map (function
          | :? Binary as binary ->
            runBinaryNamed ct options binary
          | :? BinarySlice as slice ->
            runBinaryNamed ct options (slice.ToBinary())
          | :? SymbExecutorValue as executor ->
            let executor = SymbExecutorSetup.configure options executor
            transformOne ct (executorArgs ()) executor
          | value ->
            invalidOp $"run-symbolic expects Binary or SymbExecutor: {value}") }

  interface IAction with
    member _.ActionID with get() = metadata.ID
    member _.Signature with get() = metadata.Signature
    member _.Description with get() = metadata.Description
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface IActionMetadataProvider with
    member _.Metadata with get() = metadata

  interface ICancellableAction with
    member _.Transform(args, collection, ct) =
      transform ct args collection

  interface ICancellableNamedArgumentsAction with
    member _.TransformNamed(args, collection, ct) =
      transformNamed ct args collection
