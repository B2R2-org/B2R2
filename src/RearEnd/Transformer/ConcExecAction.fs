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
open System.Collections.Generic
open System.Globalization
open System.Security.Cryptography
open System.Threading
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.Collections
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ConcEval
open B2R2.MiddleEnd.Executor

type private ConcMemory = IMemory<byte>

type private ConcRegionPermission =
  { Read: bool
    Write: bool
    Execute: bool }

type private ConcMemoryRegion =
  { Name: string
    Start: Addr
    Finish: Addr
    Permission: ConcRegionPermission }

module private ConcCallModels =
  let fwrite (ctx: CallContext) (st: ConcState) =
    if ctx.ArgumentRegisters.Length < 3 then
      Error "fwrite requires three argument registers."
    else
      match st.TryGetReg ctx.ArgumentRegisters[2] with
      | Def count ->
        st.SetReg(ctx.ReturnRegister, count)
        Ok()
      | Undef ->
        Error "fwrite count argument is uninitialized."

  let tryFind = function
    | "fwrite" -> Some fwrite
    | _ -> None

  let bindImports (file: IBinFile) =
    BinFileOps.getImports file
    |> ImmutableArray.choose (fun entry ->
      match entry.TrampolineAddress, tryFind entry.Name with
      | Some addr, Some hook -> Some(addr, hook, entry.Name)
      | _ -> None)

module private ConcRegionPerm =
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
    | MemoryAccessKind.Read ->
      permission.Read
    | MemoryAccessKind.Write ->
      permission.Write

  let executeViolation regions addr =
    if List.isEmpty regions then
      None
    else
      let finish = addr + 1UL
      let contains region =
        addr >= region.Start && finish <= region.Finish && finish >= addr
      match regions |> List.tryFind contains with
      | None ->
        Some "outside configured regions"
      | Some region when not region.Permission.Execute ->
        let permission = format region.Permission
        Some $"not permitted by {region.Name}:{permission}"
      | Some _ ->
        None

module private ConcActionParsing =
  let parseUInt64 value = ContextParsing.parseAddress value

  let randomAddress minAddress maxAddress: AddressValue =
    if minAddress >= maxAddress then
      invalidArg (nameof maxAddress) "max must be greater than min."
    else
      let span = maxAddress - minAddress
      let bytes = Array.zeroCreate<byte> 8
      RandomNumberGenerator.Fill bytes
      let offset = BitConverter.ToUInt64(bytes, 0) % span
      { Address = minAddress + offset }

  let alignDown align (value: Addr) =
    if align = 0UL then value else value - (value % align)

type private TracingMemory(inner: ConcMemory,
                           regions: ConcMemoryRegion list) =
  let accesses = ResizeArray<MemoryAccess>()
  let mutable instruction = 0UL
  let mutable hasViolation = false

  let accessViolation kind addr size =
    if List.isEmpty regions then
      None
    else
      let finish = addr + uint64 size
      let contains region =
        addr >= region.Start && finish <= region.Finish && finish >= addr
      match regions |> List.tryFind contains with
      | None ->
        Some "outside configured regions"
      | Some region when not (ConcRegionPerm.allows kind region.Permission) ->
        let permission = ConcRegionPerm.format region.Permission
        Some $"not permitted by {region.Name}:{permission}"
      | Some _ ->
        None

  let readBytes addr count =
    let bytes = Array.zeroCreate<byte> count
    let mutable ok = true
    let mutable index = 0
    while ok && index < count do
      match inner.ByteRead(addr + uint64 index) with
      | ValueSome value ->
        bytes[index] <- value
        index <- index + 1
      | ValueNone ->
        ok <- false
    if ok then Some bytes else None

  let addAccess kind addr size before after =
    let violation = accessViolation kind addr size
    if Option.isSome violation then hasViolation <- true else ()
    accesses.Add
      { Instruction = instruction
        Kind = kind
        Address = addr
        Size = size
        Before = before
        After = after
        Violation = violation }

  let appendBytes left right =
    match left, right with
    | Some left, Some right ->
      Array.append left right |> Some
    | _ ->
      None

  let tryMerge (last: MemoryAccess) (access: MemoryAccess) =
    if last.Instruction <> access.Instruction || last.Kind <> access.Kind then
      None
    elif access.Address = last.Address + uint64 last.Size then
      { last with
          Size = last.Size + access.Size
          Before = appendBytes last.Before access.Before
          After = appendBytes last.After access.After }
      |> Some
    elif access.Address + uint64 access.Size = last.Address then
      { last with
          Address = access.Address
          Size = last.Size + access.Size
          Before = appendBytes access.Before last.Before
          After = appendBytes access.After last.After }
      |> Some
    else
      None

  let coalesceAccesses () =
    accesses
    |> Seq.fold (fun acc access ->
      match acc with
      | last :: rest ->
        match tryMerge last access with
        | Some merged ->
          merged :: rest
        | None ->
          access :: acc
      | [] ->
        [ access ]) []
    |> List.rev
    |> List.toArray

  member _.Accesses = coalesceAccesses ()

  member _.HasViolation = hasViolation

  member _.SetInstruction addr = instruction <- addr

  interface IMemory<byte> with

    member _.ByteRead(addr) =
      let result = inner.ByteRead addr
      let bytes =
        match result with
        | ValueSome value ->
          Some [| value |]
        | ValueNone ->
          None
      addAccess MemoryAccessKind.Read addr 1 None bytes
      result

    member _.ByteWrite(addr, b) =
      let before = readBytes addr 1
      inner.ByteWrite(addr, b)
      addAccess MemoryAccessKind.Write addr 1 before (Some [| b |])

    member _.Clear() = inner.Clear()

    member _.Clone() =
      TracingMemory(inner.Clone(), regions) :> ConcMemory

/// Stateful concrete executor used by the Transformer REPL.
type ConcExecutorValue private(binary: Binary,
                               initialState: ConcState option,
                               previousResult: ConcRunResult option,
                               previousTrace: ExecutionTrace option,
                               memoryRanges: (Addr * int) list,
                               regions: ConcMemoryRegion list,
                               hooks: CallHookRegistry<ConcCallHook> option,
                               hookText: string list) as this =
  let hdl = Binary.Handle binary
  let executor = ConcExecutor hdl

  let createInitialState () =
    executor.CreateState()

  let state =
    match initialState with
    | Some state ->
      state
    | None ->
      createInitialState ()

  let parseUInt64 (value: string) =
    ConcActionParsing.parseUInt64 value

  let parseInt (value: string) =
    Int32.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture)

  let defaultStart () =
    if state.PC <> 0UL then
      state.PC
    else
      hdl.File.EntryPoint |> Option.defaultValue hdl.File.BaseAddress

  let accessorFor state = ConcStateAccessor(hdl, state)

  let withState state result trace ranges regions =
    ConcExecutorValue(binary,
                      Some state,
                      result,
                      trace,
                      ranges,
                      regions,
                      hooks,
                      hookText)

  let clearRunState state ranges regions =
    withState state None None ranges regions

  let formatStopReason = function
    | ConcStopReason.StoppedAtAddress addr ->
      $"breakpoint at 0x{addr:x}"
    | ConcStopReason.StoppedAfterAddress addr ->
      $"after breakpoint at 0x{addr:x}"
    | ConcStopReason.StoppedAtReturn addr ->
      $"return at 0x{addr:x}"
    | ConcStopReason.StoppedAfterReturn addr ->
      $"after return at 0x{addr:x}"
    | ConcStopReason.StoppedAtCall(addr, Some target) ->
      $"call at 0x{addr:x} target=0x{target:x}"
    | ConcStopReason.StoppedAtCall(addr, None) ->
      $"call at 0x{addr:x}"
    | ConcStopReason.StoppedAtSideEffect(addr, effect) ->
      $"side effect at 0x{addr:x}: {effect}"
    | ConcStopReason.UndefinedValue addr ->
      $"undefined value at 0x{addr:x}"
    | ConcStopReason.InstructionLimitReached _ ->
      "instruction limit"
    | ConcStopReason.EvaluationError(addr, error) ->
      $"evaluation error at 0x{addr:x}: {error}"
    | ConcStopReason.UserStopConditionMet addr ->
      $"user condition at 0x{addr:x}"
    | ConcStopReason.InvalidInstructionAddress addr ->
      $"invalid address 0x{addr:x}"
    | ConcStopReason.CallHandlingFailure(addr, Some target, reason) ->
      $"call handling failure at 0x{addr:x} target=0x{target:x}: {reason}"
    | ConcStopReason.CallHandlingFailure(addr, None, reason) ->
      $"call handling failure at 0x{addr:x}: {reason}"

  let isLimitReason = function
    | ConcStopReason.InstructionLimitReached _ ->
      true
    | _ ->
      false

  let hasNonLimitStop reasons =
    reasons |> List.exists (isLimitReason >> not)

  let tryGetRegisterID (name: string) =
    let factory = hdl.RegisterFactory
    try
      Some(factory.GetRegisterID name)
    with _ ->
      try
        Some(factory.GetRegisterID(name.ToUpperInvariant()))
      with _ ->
        None

  let getStackPointerID () =
    match hdl.RegisterFactory.StackPointer with
    | Some rid ->
      rid
    | None ->
      invalidOp "Stack pointer register is unavailable for this ISA."

  let registerText (targetState: ConcState) rid =
    match targetState.TryGetReg rid with
    | Def value ->
      Some(value.ToString())
    | Undef ->
      None

  let stackText () =
    match hdl.RegisterFactory.StackPointer with
    | Some rid ->
      registerText state rid |> Option.defaultValue "<undef>"
    | None ->
      "<unavailable>"

  let isRegisterDefined (targetState: ConcState) rid =
    match targetState.TryGetReg rid with
    | Def _ ->
      true
    | Undef ->
      false

  let registerDiffs beforeState afterState =
    hdl.RegisterFactory.GetAllRegisterNames()
    |> Array.choose (fun name ->
      match tryGetRegisterID name with
      | None ->
        None
      | Some rid ->
        let before = registerText beforeState rid
        let after = registerText afterState rid
        if before = after then
          None
        else
          let before = before |> Option.defaultValue "<undef>"
          let after = after |> Option.defaultValue "<undef>"
          Some $"{name}: {before} -> {after}")
    |> Array.toList

  let instructionAt (addr: Addr) =
    let lifter = hdl.NewLiftingUnit()
    match lifter.TryParseInstruction addr with
    | Ok instruction ->
      instruction.Disasm()
    | Error error ->
      $"<decode failed: {error}>"

  let collectReadRegisters (rset: RegisterSet) = function
    | Put(Src = rhs) ->
      AST.updateRegsUses rset rhs
    | Store(Addr = addr; Value = value) ->
      AST.updateRegsUses rset addr
      AST.updateRegsUses rset value
    | CJmp(Cond = cond) ->
      AST.updateRegsUses rset cond
    | InterJmp(Target = target) ->
      AST.updateRegsUses rset target
    | InterCJmp(Cond = cond; TrueTarget = target1; FalseTarget = target2) ->
      AST.updateRegsUses rset cond
      AST.updateRegsUses rset target1
      AST.updateRegsUses rset target2
    | ExternalCall(Call = args) ->
      AST.updateRegsUses rset args
    | ISMark _
    | IEMark _
    | LMark _
    | Jmp _
    | SideEffect _ ->
      ()

  let rec collectLoads acc = function
    | Load(Endian = endian; Type = typ; Addr = addr) ->
      (endian, typ, addr) :: collectLoads acc addr
    | ExprList(Elements = exprs) ->
      List.fold collectLoads acc exprs
    | UnOp(Operand = expr) ->
      collectLoads acc expr
    | BinOp(Left = left; Right = right) ->
      collectLoads (collectLoads acc left) right
    | RelOp(Left = left; Right = right) ->
      collectLoads (collectLoads acc left) right
    | Ite(Cond = cond; TrueExpr = left; FalseExpr = right) ->
      collectLoads (collectLoads (collectLoads acc cond) left) right
    | Cast(Operand = expr) ->
      collectLoads acc expr
    | RoundCtrl(Mode = mode; Body = body) ->
      collectLoads (collectLoads acc mode) body
    | Extract(Operand = expr) ->
      collectLoads acc expr
    | Num _
    | Var _
    | PCVar _
    | TempVar _
    | Undefined _
    | JmpDest _
    | FuncName _ ->
      acc

  let collectStmtLoads = function
    | Put(Src = rhs) ->
      collectLoads [] rhs
    | Store(Addr = addr; Value = value) ->
      collectLoads (collectLoads [] addr) value
    | CJmp(Cond = cond) ->
      collectLoads [] cond
    | InterJmp(Target = target) ->
      collectLoads [] target
    | InterCJmp(Cond = cond; TrueTarget = target1; FalseTarget = target2) ->
      collectLoads (collectLoads (collectLoads [] cond) target1) target2
    | ExternalCall(Call = args) ->
      collectLoads [] args
    | ISMark _
    | IEMark _
    | LMark _
    | Jmp _
    | SideEffect _ ->
      []

  let tryReadBytes (addr: Addr) (count: int) (targetState: ConcState) =
    try (accessorFor targetState).ReadBytes(addr, count) |> Some
    with _ -> None

  let memoryDiff (watch: (Addr * int) option) beforeState afterState =
    watch
    |> Option.bind (fun (addr, count) ->
      let before = tryReadBytes addr count beforeState
      let after = tryReadBytes addr count afterState
      Some { Address = addr; Before = before; After = after })
    |> Option.toArray

  let stopReasons result =
    result.StopReasons |> List.map formatStopReason |> List.toArray

  let hasViolationAccess accesses =
    accesses
    |> Array.exists (fun access -> Option.isSome access.Violation)

  let stopReasonsForTrace result accesses =
    if hasViolationAccess accesses then
      let reasons =
        result.StopReasons
        |> List.filter (isLimitReason >> not)
        |> List.map formatStopReason
        |> List.toArray
      Array.append reasons [| "access violation" |]
    else
      stopReasons result

  let aggregateStopReasons total reasons =
    if hasNonLimitStop reasons then
      reasons |> List.filter (isLimitReason >> not)
    else
      reasons
      |> List.map (function
        | ConcStopReason.InstructionLimitReached(addr, _) ->
          ConcStopReason.InstructionLimitReached(addr, total)
        | reason ->
          reason)

  let makeRunOptions (stops: ConcStopCondition list)
                     (limit: int)
                     : ConcRunOptions =
    let options =
      ConcRunOptions.Default(stops)
        .WithMaxInstructions(limit)
        .ZeroCallerContext()
    match hooks with
    | Some hooks -> options.WithCallHooks hooks
    | None -> options

  let runOne ct stops (addr: Addr) (runState: ConcState) =
    match ConcRegionPerm.executeViolation regions addr with
    | Some reason ->
      invalidOp $"Execute access violation at 0x{addr:x}: {reason}."
    | None ->
      ()
    match runState.Memory with
    | :? TracingMemory as memory ->
      memory.SetInstruction addr
    | _ ->
      ()
    let instruction =
      { Address = addr
        Disassembly = instructionAt addr }
    let options: ConcRunOptions = makeRunOptions stops 1
    let result: ConcRunResult =
      executor.Run(addr, runState, options, ct)
    result, instruction

  let hasAccessViolation (runState: ConcState) =
    match runState.Memory with
    | :? TracingMemory as memory ->
      memory.HasViolation
    | _ ->
      false

  let runSteps
    (ct: CancellationToken)
    stops
    (start: Addr)
    count
    (runState: ConcState) =
    let rec loop
      addr
      remaining
      instructions
      total
      (lastResult: ConcRunResult option) =
      ct.ThrowIfCancellationRequested()
      if remaining <= 0 then
        lastResult, List.rev instructions
      else
        let result, instruction =
          runOne ct stops addr runState
        let instructions = instruction :: instructions
        let executed = result.InstructionCount
        let total = total + result.InstructionCount
        let result =
          { result with
              InstructionCount = total
              StopReasons = aggregateStopReasons total result.StopReasons }
        let stopped =
          executed = 0
          || hasNonLimitStop result.StopReasons
          || hasAccessViolation runState
        if stopped then
          Some result, List.rev instructions
        else
          loop
            result.FinalAddress
            (remaining - 1)
            instructions
            total
            (Some result)
    loop start count [] 0 None

  let traceFromResult
    start
    beforeState
    (result: ConcRunResult option)
    instructions
    accesses
    watch =
    let result: ConcRunResult =
      match result with
      | Some result ->
        result
      | None ->
        { StopReasons = []
          FinalAddress = start
          InstructionCount = 0
          State = beforeState }
    { Start = start
      FinalPC = result.FinalAddress
      InstructionCount = result.InstructionCount
      Instructions = instructions |> List.toArray
      RegisterDiffs = registerDiffs beforeState result.State |> List.toArray
      MemoryAccesses = accesses
      MemoryDiffs = memoryDiff watch beforeState result.State
      StopReasons = stopReasonsForTrace result accesses }

  let runWithTrace
    ct
    start
    count
    (sourceState: ConcState)
    watch
    stops =
    let traceMemory = TracingMemory(sourceState.Memory.Clone(), regions)
    let runState = sourceState.Clone(traceMemory :> ConcMemory)
    let beforeState = runState.Clone()
    let result, instructions =
      runSteps ct stops start count runState
    let trace =
      traceFromResult
        start
        beforeState
        result
        instructions
        traceMemory.Accesses
        watch
    result, trace

  let parseNeedsArgs args =
    match args with
    | [] ->
      defaultStart (), Some 1, None
    | [ count ] ->
      defaultStart (), Some(parseInt count), None
    | [ start; finishOrCount ]
        when finishOrCount.StartsWith("0x", StringComparison.Ordinal) ->
      parseUInt64 start, None, Some(parseUInt64 finishOrCount)
    | [ start; count ] ->
      parseUInt64 start, Some(parseInt count), None
    | _ ->
      invalidArg (nameof args) "Invalid needs argument layout."

  let memoryRequirement at reason addr size =
    { Address = addr
      Size = size
      At = at
      Reason = reason }

  let registerRequirement at disasm rid =
    let name = hdl.RegisterFactory.GetRegisterName rid
    { Name = name
      Address = at
      Disassembly = disasm }

  let uniqueRegisters (items: RequiredRegister seq) =
    let seen = HashSet<string>(StringComparer.OrdinalIgnoreCase)
    items
    |> Seq.filter (fun item -> seen.Add item.Name)
    |> Seq.toArray

  let uniqueMemory (items: RequiredMemory seq) =
    let key (item: RequiredMemory) =
      match item.Address with
      | Some addr ->
        $"0x{addr:x}:{item.Size}"
      | None ->
        $"{item.At:x}:{item.Reason}"
    let seen = HashSet<string>()
    items
    |> Seq.filter (fun item -> seen.Add(key item))
    |> Seq.toArray

  let inspectRegisterNeeds at disasm (derived: HashSet<int>) state stmt =
    let rset = RegisterSet()
    collectReadRegisters rset stmt
    let output = ResizeArray<RequiredRegister>()
    rset.Iterate(fun ridx ->
      let rid = RegisterID.create ridx
      if isRegisterDefined state rid || derived.Contains ridx then
        ()
      else
        output.Add(registerRequirement at disasm rid))
    output

  let updateDerivedRegisters (derived: HashSet<int>) state stmt =
    let update rid rhs =
      match SafeEvaluator.evalExpr state rhs with
      | Ok(Def _) ->
        derived.Remove rid |> ignore
      | Ok Undef
      | Result.Error _ ->
        derived.Add rid |> ignore
    match stmt with
    | Put(Dst = Var(RegisterID = rid); Src = rhs) ->
      update (int rid) rhs
    | _ ->
      ()

  let inspectLoadNeed at state (endian, typ, addrExpr) =
    match SafeEvaluator.evalExpr state addrExpr with
    | Ok(Def addr) ->
      let addr = addr.ToUInt64()
      match Memory.read addr endian typ state.Memory with
      | Ok _ ->
        None
      | Result.Error _ ->
        let size = RegType.toByteWidth typ
        Some(memoryRequirement at "memory read" (Some addr) size)
    | Ok Undef
    | Result.Error _ ->
      let size = RegType.toByteWidth typ
      Some(memoryRequirement at "memory address is undefined" None size)

  let evalRequirementStmt state stmt =
    match SafeEvaluator.evalStmt state stmt with
    | Ok() ->
      ()
    | Result.Error _ ->
      ()

  let needsForWindow start count finish =
    let lifter = hdl.NewLiftingUnit()
    let state = state.Clone()
    let derived = HashSet<int>()
    let registers = ResizeArray<RequiredRegister>()
    let memory = ResizeArray<RequiredMemory>()
    let rec loop addr remaining =
      let inRange =
        match finish with
        | Some finish ->
          addr < finish
        | None ->
          remaining > 0
      if not inRange || not (hdl.File.IsValidAddr addr) then
        ()
      else
        match lifter.TryParseInstruction addr with
        | Error _ ->
          ()
        | Ok instruction ->
          let disasm = instruction.Disasm()
          let stmts = lifter.LiftInstruction instruction
          state.PC <- addr
          state.PrepareInstrEval stmts
          for stmt in stmts do
            inspectRegisterNeeds addr disasm derived state stmt
            |> registers.AddRange
            collectStmtLoads stmt
            |> List.choose (inspectLoadNeed addr state)
            |> memory.AddRange
            updateDerivedRegisters derived state stmt
            evalRequirementStmt state stmt
          let next = addr + uint64 instruction.Length
          let remaining = max 0 (remaining - 1)
          loop next remaining
    loop start (count |> Option.defaultValue Int32.MaxValue)
    { Executor = this
      Start = start
      EndAddress = finish
      Count = count
      Registers = uniqueRegisters registers
      Memory = uniqueMemory memory }

  let memoryRangeLines () =
    match memoryRanges with
    | [] ->
      [ "  user-memory: <none>" ]
    | ranges ->
      "  user-memory:"
      :: (ranges |> List.rev |> List.map (fun (addr, count) ->
        let finish = addr + uint64 count
        $"    0x{addr:x}-0x{finish:x} ({count} bytes)"))

  let parseRegionAssignment (entry: string) =
    let region = ContextParsing.parseRegion entry
    { Name = region.Name
      Start = region.Start
      Finish = region.Finish
      Permission =
        { Read = region.Permission.Read
          Write = region.Permission.Write
          Execute = region.Permission.Execute } }

  let parseContextArgs (args: string list) =
    let rec loop (stack: Addr option)
                 (regs: (string * string) list)
                 (memory: (string * string) list)
                 (nextRegions: ConcMemoryRegion list) = function
      | [] ->
        stack, List.rev regs, List.rev memory, List.rev nextRegions
      | (token: string) :: rest ->
        let key, value = ContextParsing.splitParameter token
        match key with
        | "stack" ->
          loop (Some(parseUInt64 value)) regs memory nextRegions rest
        | "regs" | "registers" ->
          let regs =
            ContextParsing.entries value
            |> Array.fold (fun regs entry ->
              ContextParsing.splitAssignment entry :: regs) regs
          loop stack regs memory nextRegions rest
        | "mem" | "memory" ->
          let memory =
            ContextParsing.entries value
            |> Array.fold (fun memory entry ->
              ContextParsing.splitAssignment entry :: memory) memory
          loop stack regs memory nextRegions rest
        | "regions" ->
          let nextRegions =
            ContextParsing.entries value
            |> Array.fold (fun regions entry ->
              parseRegionAssignment entry :: regions) nextRegions
          loop stack regs memory nextRegions rest
        | _ ->
          invalidArg (nameof args)
            $"Unknown make-concrete-context parameter: {key}"
    loop None [] [] [] args

  let lastRunLines () =
    match previousResult with
    | None ->
      [ "  last-run: <none>" ]
    | Some result ->
      let reasons =
        match previousTrace with
        | Some trace ->
          String.concat ", " trace.StopReasons
        | None ->
          result.StopReasons
          |> List.map formatStopReason
          |> String.concat ", "
      [ "  last-run:"
        $"    instructions: {result.InstructionCount}"
        $"    final-pc: 0x{result.FinalAddress:x}"
        $"    stopped: {reasons}" ]

  let traceSummary (trace: ExecutionTrace option) =
    match trace with
    | None ->
      "<none>"
    | Some trace ->
      $"start=0x{trace.Start:x} final-pc=0x{trace.FinalPC:x} "
      + $"instructions={trace.InstructionCount}"

  let lastViolationLines () =
    match previousTrace with
    | None ->
      []
    | Some trace ->
      let violations =
        trace.MemoryAccesses
        |> Array.choose (fun access ->
          access.Violation
          |> Option.map (fun message ->
            let kind =
              match access.Kind with
              | MemoryAccessKind.Read ->
                "read"
              | MemoryAccessKind.Write ->
                "write"
            $"    {kind} at=0x{access.Instruction:x} "
            + $"addr=0x{access.Address:x} size={access.Size} {message}"))
        |> Array.toList
      match violations with
      | [] ->
        []
      | lines ->
        "  access-violations:" :: lines

  let regionLines () =
    match regions with
    | [] ->
      [ "  regions: <none>" ]
    | regions ->
      "  regions:"
      :: (regions |> List.map (fun region ->
        let permission = ConcRegionPerm.format region.Permission
        $"    {region.Name}=0x{region.Start:x}..0x{region.Finish:x}:"
        + permission))

  let hookLines () =
    match hookText with
    | [] ->
      [ "  hooks: <none>" ]
    | hooks ->
      "  hooks:" :: List.map (fun hook -> "    " + hook) hooks

  new(binary) =
    let hdl = Binary.Handle binary
    let bindings = ConcCallModels.bindImports hdl.File
    let hooks =
      if Array.isEmpty bindings then
        None
      else
        bindings
        |> Array.map (fun (addr, hook, _) -> addr, hook)
        |> CallHookRegistry
        |> Some
    let hookText =
      bindings
      |> Array.map (fun (addr, _, name) -> $"{name}@0x{addr:x} (automatic)")
      |> Array.toList
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
    ConcExecutorValue(binary, None, None, None, [], regions, hooks, hookText)

  member _.State = state

  member _.Binary = binary

  member _.LastTrace = previousTrace

  member _.SummaryLines =
    let path =
      if String.IsNullOrWhiteSpace hdl.File.Path then
        "<raw>"
      else
        hdl.File.Path
    [ "ConcExecutor"
      $"  binary: {path}"
      $"  isa: {hdl.ISA}"
      $"  entry: 0x{(defaultStart ()):x}"
      $"  pc: 0x{state.PC:x}"
      $"  stack: {stackText ()}" ]
    @ memoryRangeLines ()
    @ regionLines ()
    @ hookLines ()
    @ lastRunLines ()
    @ lastViolationLines ()

  member this.Summary = String.concat Environment.NewLine this.SummaryLines

  member _.Run(args: string list, ct) =
    let start, limit, breakpoint =
      match args with
      | [] ->
        defaultStart (), 50000, None
      | [ entry ] ->
        parseUInt64 entry, 50000, None
      | [ entry; limit ] ->
        parseUInt64 entry, parseInt limit, None
      | [ entry; limit; breakpoint ] ->
        parseUInt64 entry, parseInt limit, Some(parseUInt64 breakpoint)
      | _ ->
        invalidArg (nameof args) "Invalid run argument layout."
    let stops =
      breakpoint
      |> Option.map ConcStopCondition.StopAtAddress
      |> Option.toList
    let runState = state.Clone()
    let result, trace =
      runWithTrace ct start limit runState None stops
    match result with
    | Some result ->
      withState result.State (Some result) (Some trace) memoryRanges regions
    | None ->
      withState runState None (Some trace) memoryRanges regions

  member this.Run(args: string list) =
    this.Run(args, CancellationToken.None)

  member _.Step(count: int, ct) =
    let start = defaultStart ()
    let runState = state.Clone()
    let result, trace =
      runWithTrace ct start count runState None []
    match result with
    | Some result ->
      withState result.State (Some result) (Some trace) memoryRanges regions
    | None ->
      withState runState None (Some trace) memoryRanges regions

  member this.Step(count: int) =
    this.Step(count, CancellationToken.None)

  member _.Trace(args: string list, ct) =
    let count, watch =
      match args with
      | [] ->
        1, None
      | [ count ] ->
        parseInt count, None
      | [ addr; size ] ->
        1, Some(parseUInt64 addr, parseInt size)
      | [ count; addr; size ] ->
        parseInt count, Some(parseUInt64 addr, parseInt size)
      | _ ->
        invalidArg (nameof args) "Invalid trace argument layout."
    let runState = state.Clone()
    let _, trace =
      runWithTrace ct (defaultStart ()) count runState watch []
    trace

  member this.Trace(args: string list) =
    this.Trace(args, CancellationToken.None)

  member _.Needs(args: string list) =
    let start, count, finish = parseNeedsArgs args
    needsForWindow start count finish

  member _.SetArgument(args: string list) =
    match args with
    | [ index; value ] ->
      let index = parseInt index
      let value = parseUInt64 value
      let nextState = state.Clone()
      let accessor = accessorFor nextState
      accessor.SetArgument(index, accessor.WordValue value)
      clearRunState nextState memoryRanges regions
    | _ ->
      invalidArg (nameof args) "Invalid arg argument layout."

  member _.WriteMemory(args: string list) =
    match args with
    | [ addr; bytes ] ->
      let addr = parseUInt64 addr
      let bytes = ByteArray.ofHexString bytes
      let nextState = state.Clone()
      let accessor = accessorFor nextState
      accessor.WriteBytes(addr, bytes)
      let ranges = (addr, bytes.Length) :: memoryRanges
      clearRunState nextState ranges regions
    | _ ->
      invalidArg (nameof args) "Invalid mem write argument layout."

  member _.SetContext(args: string list) =
    let stack, registers, memory, nextRegions = parseContextArgs args
    let nextState = state.Clone()
    let accessor = accessorFor nextState
    stack |> Option.iter (fun addr ->
      accessor.SetRegister(getStackPointerID (), accessor.WordValue addr))
    registers |> List.iter (fun (name, value) ->
      match tryGetRegisterID name with
      | None ->
        invalidArg (nameof args) $"Unknown register: {name}"
      | Some rid ->
        let value = parseUInt64 value
        accessor.SetRegister(rid, accessor.WordValue value))
    let ranges =
      memory
      |> List.fold (fun ranges (addr, bytes) ->
        let addr = parseUInt64 addr
        let bytes = ByteArray.ofHexString bytes
        accessor.WriteBytes(addr, bytes)
        (addr, bytes.Length) :: ranges) memoryRanges
    clearRunState nextState ranges (nextRegions @ regions)

  member _.ReadMemory(args: string list) =
    match args with
    | [ addr; count ] ->
      let addr = parseUInt64 addr
      let count = parseInt count
      { Address = addr
        Bytes = (accessorFor state).ReadBytes(addr, count) }
    | _ ->
      invalidArg (nameof args) "Invalid mem read argument layout."

  member _.Registers(args: string list) =
    let factory = hdl.RegisterFactory
    let registerNames =
      if List.isEmpty args then
        factory.GetAllRegisterNames()
      else
        args |> List.toArray
    let requested = not (List.isEmpty args)
    let registers =
      registerNames
      |> Array.choose (fun name ->
        match tryGetRegisterID name with
        | None when requested ->
          Some { Name = name; Value = "<unknown>" }
        | None ->
          None
        | Some rid ->
          let name = factory.GetRegisterName rid
          match registerText state rid with
          | Some value ->
            Some { Name = name; Value = value }
          | None when requested ->
            Some { Name = name; Value = "<undef>" }
          | None ->
            None)
    { PC = state.PC; Registers = registers }

  member _.DiffLines(other: ConcExecutorValue) =
    let pcLine =
      if state.PC = other.State.PC then
        []
      else
        [ $"pc: 0x{state.PC:x} -> 0x{other.State.PC:x}" ]
    let regLines = registerDiffs state other.State
    let traceLines =
      [ $"left-trace: {traceSummary previousTrace}"
        $"right-trace: {traceSummary other.LastTrace}" ]
    match pcLine @ regLines with
    | [] ->
      traceLines @ [ "registers: no visible changes" ]
    | lines ->
      traceLines @ ("registers:" :: List.map (fun s -> "  " + s) lines)

  override this.ToString() = this.Summary

/// Create a concrete executor from a Binary.
type ConcExecAction() =
  let transform cancellationToken _args collection =
    let cancellationToken: CancellationToken = cancellationToken
    { Values =
        collection.Values
        |> Array.map (fun input ->
          cancellationToken.ThrowIfCancellationRequested()
          match input with
          | :? Binary as binary ->
            ConcExecutorValue(binary) |> box
          | :? BinarySlice as slice ->
            ConcExecutorValue(slice.ToBinary()) |> box
          | _ ->
            invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "make-concrete-executor"
    member _.Signature with get() =
      "Binary | BinarySlice -> make-concrete-executor -> ConcExecutor"
    member _.Description with get() =
      "Create a stateful concrete executor backed by binary section memory."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

/// Run a concrete executor.
type RunAction() =
  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    { Values =
        collection.Values
        |> Array.map (fun input ->
          cancellationToken.ThrowIfCancellationRequested()
          match input with
          | :? ConcExecutorValue as executor ->
            executor.Run(args, cancellationToken) |> box
          | _ ->
            invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "run-concrete"
    member _.Signature with get() =
      "ConcExecutor -> run-concrete [entry=<addr>] [limit=<n>] "
      + "[break=<addr>] -> ConcExecutor"
    member _.Description with get() =
      "Run concrete execution and update the executor state."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

/// Set one integer or pointer argument register for concrete execution.
type ArgAction() =
  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    { Values =
        collection.Values
        |> Array.map (fun input ->
          cancellationToken.ThrowIfCancellationRequested()
          match input with
          | :? ConcExecutorValue as executor ->
            executor.SetArgument args |> box
          | _ ->
            invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "arg"
    member _.Signature with get() =
      "ConcExecutor -> arg index=<n> value=<addr> -> ConcExecutor"
    member _.Description with get() =
      "Set an integer or pointer argument register for concrete execution."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

/// Set multiple concrete registers and memory ranges.
type SetContextAction() =
  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    { Values =
        collection.Values
        |> Array.map (fun input ->
          cancellationToken.ThrowIfCancellationRequested()
          match input with
          | :? ConcExecutorValue as executor ->
            executor.SetContext args |> box
          | _ ->
            invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "make-concrete-context"
    member _.Signature with get() =
      "ConcExecutor -> make-concrete-context [stack=<addr>] [regs=[...]]"
      + " [mem=[...]]"
      + " [regions=[additional regions]]"
      + " -> ConcExecutor"
    member _.Description with get() =
      "Create a concrete context with automatic image permissions."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

/// Read or write concrete executor memory.
type MemAction() =
  let transformOne args (executor: ConcExecutorValue) =
    match args with
    | "read" :: args ->
      executor.ReadMemory args |> box
    | "write" :: args ->
      executor.WriteMemory args |> box
    | _ ->
      invalidArg (nameof args) "Expected: mem read|write ..."

  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    { Values =
        collection.Values
        |> Array.map (fun input ->
          cancellationToken.ThrowIfCancellationRequested()
          match input with
          | :? ConcExecutorValue as executor ->
            executor |> transformOne args
          | _ ->
            invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "mem"
    member _.Signature with get() =
      "ConcExecutor -> mem read addr=<addr> size=<n> -> MemoryView | "
      + "mem write addr=<addr> bytes=<hex> -> ConcExecutor"
    member _.Description with get() =
      "Read or write concrete bytes in executor memory."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

/// Step a concrete executor by a small instruction count.
type StepAction() =
  let parseCount = function
    | [] ->
      1
    | [ (count: string) ] ->
      Int32.Parse(count, NumberStyles.Integer, CultureInfo.InvariantCulture)
    | _ ->
      invalidArg "args" "At most one step count is allowed."

  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    let count = parseCount args
    { Values =
        collection.Values
        |> Array.map (fun input ->
          cancellationToken.ThrowIfCancellationRequested()
          match input with
          | :? ConcExecutorValue as executor ->
            executor.Step(count, cancellationToken) |> box
          | _ ->
            invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "step"
    member _.Signature with get() =
      "ConcExecutor -> step [count=<n>] -> ConcExecutor"
    member _.Description with get() =
      "Execute one or more machine instructions from the current PC."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

/// Trace concrete execution without replacing the executor value.
type TraceAction() =
  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    { Values =
        collection.Values
        |> Array.map (fun input ->
          cancellationToken.ThrowIfCancellationRequested()
          match input with
          | :? ConcExecutorValue as executor ->
            executor.Trace(args, cancellationToken) |> box
          | _ ->
            invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "trace"
    member _.Signature with get() =
      "ConcExecutor -> trace [count=<n>] [watch=<addr> size=<n>]"
      + " -> ExecutionTrace"
    member _.Description with get() =
      "Show executed instructions, register changes, and watched memory."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

/// Produce a random address in the half-open range [min, max).
type RandomAction() =
  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    let minAddress =
      match args with
      | [ minAddress; maxAddress ] ->
        ConcActionParsing.parseUInt64 minAddress
      | _ ->
        invalidArg (nameof args) "Expected: random min=<addr> max=<addr>."
    let maxAddress =
      match args with
      | [ minAddress; maxAddress ] ->
        ConcActionParsing.parseUInt64 maxAddress
      | _ ->
        invalidArg (nameof args) "Expected: random min=<addr> max=<addr>."
    cancellationToken.ThrowIfCancellationRequested()
    let address = ConcActionParsing.randomAddress minAddress maxAddress
    { Values = [| address |> box |] }

  interface IAction with
    member _.ActionID with get() = "random"
    member _.Signature with get() =
      "Unit -> random min=<addr> max=<addr> -> Address"
    member _.Description with get() =
      "Return a random address in the half-open range [min, max)."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

/// Produce a randomized high user-space stack address.
type UserStackAction() =
  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    let top = 0x7fffffffe000UL
    let window = 0x100000UL
    let address =
      ConcActionParsing.randomAddress (top - window) top
    let address =
      { address with
          Address = ConcActionParsing.alignDown 16UL address.Address }
    cancellationToken.ThrowIfCancellationRequested()
    { Values = [| address |> box |] }

  interface IAction with
    member _.ActionID with get() = "user-stack"
    member _.Signature with get() = "Unit -> Address"
    member _.Description with get() =
      "Return an aligned random address near the top of user stack space."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

/// Show defined concrete registers.
type RegsAction() =
  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    { Values =
        collection.Values
        |> Array.map (fun input ->
          cancellationToken.ThrowIfCancellationRequested()
          match input with
          | :? ConcExecutorValue as executor ->
            executor.Registers args |> box
          | _ ->
            invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "regs"
    member _.Signature with get() =
      "ConcExecutor -> regs [name=<register>] -> RegisterView"
    member _.Description with get() =
      "Show currently defined concrete register values."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
