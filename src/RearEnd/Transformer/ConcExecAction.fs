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
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ConcEval

module private ConcActionParsing =
  let parseUInt64 (value: string) =
    let style, value =
      if value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        NumberStyles.HexNumber, value[2..]
      else
        NumberStyles.Integer, value
    UInt64.Parse(value, style, CultureInfo.InvariantCulture)

  let randomAddress minAddress maxAddress =
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

type private TracingMemory(inner: IMemory) =
  let accesses = ResizeArray<MemoryAccess>()
  let mutable instruction = 0UL

  let byteCount typ = RegType.toByteWidth typ

  let readBytes addr count =
    let bytes = Array.zeroCreate<byte> count
    let mutable ok = true
    let mutable index = 0
    while ok && index < count do
      match inner.ByteRead(addr + uint64 index) with
      | Ok value ->
        bytes[index] <- value
        index <- index + 1
      | Result.Error _ ->
        ok <- false
    if ok then Some bytes else None

  let addAccess kind addr size before after =
    accesses.Add
      { Instruction = instruction
        Kind = kind
        Address = addr
        Size = size
        Before = before
        After = after }

  member _.Accesses = accesses.ToArray()

  member _.SetInstruction addr = instruction <- addr

  interface IUndefinedMemory with

    member _.MarkUndefined(addr, count) =
      let before = readBytes addr count
      match inner with
      | :? IUndefinedMemory as mem -> mem.MarkUndefined(addr, count)
      | _ -> ()
      addAccess MemoryAccessKind.Write addr count before None

  interface IMemory with

    member _.ByteRead(addr) = inner.ByteRead addr

    member _.ByteWrite(addr, b) =
      let before = readBytes addr 1
      inner.ByteWrite(addr, b)
      addAccess MemoryAccessKind.Write addr 1 before (Some [| b |])

    member _.Read(addr, endian, typ) =
      let size = byteCount typ
      let result = inner.Read(addr, endian, typ)
      let bytes =
        match result with
        | Ok _ -> readBytes addr size
        | Result.Error _ -> None
      addAccess MemoryAccessKind.Read addr size None bytes
      result

    member _.Write(addr, value, endian) =
      let size = value.Length |> RegType.toByteWidth
      let before = readBytes addr size
      inner.Write(addr, value, endian)
      let after = readBytes addr size
      addAccess MemoryAccessKind.Write addr size before after

    member _.Clear() = inner.Clear()

    member _.Clone() = TracingMemory(inner.Clone()) :> IMemory

/// Stateful concrete executor used by the Transformer REPL.
type ConcExecutorValue(binary: Binary,
                       initialState: EvalState option,
                       previousResult: ConcRunResult<EvalState> option,
                       previousTrace: ExecutionTrace option,
                       memoryRanges: (Addr * int) list) as this =
  let hdl = Binary.Handle binary
  let executor = ConcExecutor hdl

  let createInitialState () =
    executor.CreateState()

  let state =
    match initialState with
    | Some state -> state
    | None -> createInitialState ()

  let parseUInt64 (value: string) =
    ConcActionParsing.parseUInt64 value

  let parseInt (value: string) =
    Int32.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture)

  let defaultStart () =
    if state.PC <> 0UL then state.PC
    else hdl.File.EntryPoint |> Option.defaultValue hdl.File.BaseAddress

  let accessorFor state = ConcStateAccessor(hdl, state)

  let withState state result trace ranges =
    ConcExecutorValue(binary, Some state, result, trace, ranges)

  let clearRunState state ranges = withState state None None ranges

  let formatStopReason = function
    | StoppedAtAddress addr -> $"stopped-at=0x{addr:x}"
    | StoppedAfterAddress addr -> $"stopped-after=0x{addr:x}"
    | StoppedAtReturn addr -> $"return-at=0x{addr:x}"
    | StoppedAfterReturn addr -> $"return-after=0x{addr:x}"
    | StoppedAtCall(addr, Some target) ->
      $"call-at=0x{addr:x} target=0x{target:x}"
    | StoppedAtCall(addr, None) -> $"call-at=0x{addr:x}"
    | StoppedAtSideEffect(addr, effect) ->
      $"side-effect-at=0x{addr:x} effect={effect}"
    | UndefinedValue addr -> $"undefined-at=0x{addr:x}"
    | InstructionLimitReached(addr, limit) ->
      $"limit={limit} at=0x{addr:x}"
    | EvaluationError(addr, error) -> $"error-at=0x{addr:x} error={error}"
    | UserStopConditionMet addr -> $"user-stop-at=0x{addr:x}"
    | InvalidInstructionAddress addr -> $"invalid-address=0x{addr:x}"

  let isLimitReason = function
    | InstructionLimitReached _ -> true
    | _ -> false

  let hasNonLimitStop reasons =
    reasons |> List.exists (isLimitReason >> not)

  let tryGetRegisterID (name: string) =
    let factory = hdl.RegisterFactory
    try Some(factory.GetRegisterID name)
    with _ ->
      try Some(factory.GetRegisterID(name.ToUpperInvariant()))
      with _ -> None

  let getStackPointerID () =
    match hdl.RegisterFactory.StackPointer with
    | Some rid -> rid
    | None ->
      invalidOp "Stack pointer register is unavailable for this ISA."

  let registerText (targetState: EvalState) rid =
    match targetState.TryGetReg rid with
    | Def value -> Some(value.ToString())
    | Undef -> None

  let stackText () =
    match hdl.RegisterFactory.StackPointer with
    | Some rid ->
      registerText state rid |> Option.defaultValue "<undef>"
    | None -> "<unavailable>"

  let isRegisterDefined (targetState: EvalState) rid =
    match targetState.TryGetReg rid with
    | Def _ -> true
    | Undef -> false

  let registerDiffs beforeState afterState =
    hdl.RegisterFactory.GetAllRegisterNames()
    |> Array.choose (fun name ->
      match tryGetRegisterID name with
      | None -> None
      | Some rid ->
        let before = registerText beforeState rid
        let after = registerText afterState rid
        if before = after then None
        else
          let before = before |> Option.defaultValue "<undef>"
          let after = after |> Option.defaultValue "<undef>"
          Some $"{name}: {before} -> {after}")
    |> Array.toList

  let instructionAt (addr: Addr) =
    let lifter = hdl.NewLiftingUnit()
    match lifter.TryParseInstruction addr with
    | Ok instruction -> instruction.Disasm()
    | Error error -> $"<decode failed: {error}>"

  let collectReadRegisters (rset: RegisterSet) = function
    | Put(_, rhs, _) ->
      AST.updateRegsUses rset rhs
    | Store(_, addr, value, _) ->
      AST.updateRegsUses rset addr
      AST.updateRegsUses rset value
    | CJmp(cond, _, _, _) ->
      AST.updateRegsUses rset cond
    | InterJmp(target, _, _) ->
      AST.updateRegsUses rset target
    | InterCJmp(cond, target1, target2, _) ->
      AST.updateRegsUses rset cond
      AST.updateRegsUses rset target1
      AST.updateRegsUses rset target2
    | ExternalCall(args, _) ->
      AST.updateRegsUses rset args
    | ISMark _
    | IEMark _
    | LMark _
    | Jmp _
    | SideEffect _ ->
      ()

  let rec collectLoads acc = function
    | Load(endian, typ, addr, _) ->
      (endian, typ, addr) :: collectLoads acc addr
    | ExprList(exprs, _) ->
      List.fold collectLoads acc exprs
    | UnOp(_, expr, _) ->
      collectLoads acc expr
    | BinOp(_, _, left, right, _) ->
      collectLoads (collectLoads acc left) right
    | RelOp(_, left, right, _) ->
      collectLoads (collectLoads acc left) right
    | Ite(cond, left, right, _) ->
      collectLoads (collectLoads (collectLoads acc cond) left) right
    | Cast(_, _, expr, _) ->
      collectLoads acc expr
    | RoundCtrl(mode, body, _) ->
      collectLoads (collectLoads acc mode) body
    | Extract(expr, _, _, _) ->
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
    | Put(_, rhs, _) ->
      collectLoads [] rhs
    | Store(_, addr, value, _) ->
      collectLoads (collectLoads [] addr) value
    | CJmp(cond, _, _, _) ->
      collectLoads [] cond
    | InterJmp(target, _, _) ->
      collectLoads [] target
    | InterCJmp(cond, target1, target2, _) ->
      collectLoads (collectLoads (collectLoads [] cond) target1) target2
    | ExternalCall(args, _) ->
      collectLoads [] args
    | ISMark _
    | IEMark _
    | LMark _
    | Jmp _
    | SideEffect _ ->
      []

  let tryReadBytes (addr: Addr) (count: int) (targetState: EvalState) =
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

  let aggregateStopReasons total reasons =
    reasons
    |> List.map (function
      | InstructionLimitReached(addr, _) -> InstructionLimitReached(addr, total)
      | reason -> reason)

  let runOne (addr: Addr) (runState: EvalState) =
    match runState.Memory with
    | :? TracingMemory as memory -> memory.SetInstruction addr
    | _ -> ()
    let instruction =
      { Address = addr
        Disassembly = instructionAt addr }
    let result =
      executor.Run(addr, runState,
        ConcRunOptions.Default(StopAfterInstructionCount 1))
    result, instruction

  let rec runSteps (start: Addr) count (runState: EvalState) =
    let rec loop addr remaining instructions total lastResult =
      if remaining <= 0 then
        lastResult, List.rev instructions
      else
        let result, instruction = runOne addr runState
        let instructions = instruction :: instructions
        let executed = result.InstructionCount
        let total = total + result.InstructionCount
        let result =
          { result with
              InstructionCount = total
              StopReasons = aggregateStopReasons total result.StopReasons }
        let stopped =
          executed = 0 || hasNonLimitStop result.StopReasons
        if stopped then
          Some result, List.rev instructions
        else
          loop result.FinalAddress (remaining - 1) instructions total
            (Some result)
    loop start count [] 0 None

  let traceFromResult start beforeState result instructions accesses watch =
    let result =
      match result with
      | Some result -> result
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
      StopReasons = stopReasons result }

  let runWithTrace start count (sourceState: EvalState) watch =
    let traceMemory = TracingMemory(sourceState.Memory.Clone())
    let runState = sourceState.Clone(traceMemory :> IMemory)
    let beforeState = runState.Clone()
    let result, instructions = runSteps start count runState
    let trace =
      traceFromResult start beforeState result instructions
        traceMemory.Accesses watch
    result, trace

  let parseNeedsArgs args =
    match args with
    | [] -> defaultStart (), Some 1, None
    | [ count ] -> defaultStart (), Some(parseInt count), None
    | [ start; finishOrCount ]
        when finishOrCount.StartsWith("0x", StringComparison.Ordinal) ->
      parseUInt64 start, None, Some(parseUInt64 finishOrCount)
    | [ start; count ] -> parseUInt64 start, Some(parseInt count), None
    | _ -> invalidArg (nameof args) "Invalid needs argument layout."

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
      | Some addr -> $"0x{addr:x}:{item.Size}"
      | None -> $"{item.At:x}:{item.Reason}"
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
      else output.Add(registerRequirement at disasm rid))
    output

  let updateDerivedRegisters (derived: HashSet<int>) state stmt =
    let update rid rhs =
      match SafeEvaluator.evalExpr state rhs with
      | Ok(Def _) -> derived.Remove rid |> ignore
      | Ok Undef
      | Result.Error _ -> derived.Add rid |> ignore
    match stmt with
    | Put(Var(_, rid, _, _), rhs, _) -> update (int rid) rhs
    | _ -> ()

  let inspectLoadNeed at state (endian, typ, addrExpr) =
    match SafeEvaluator.evalExpr state addrExpr with
    | Ok(Def addr) ->
      let addr = addr.ToUInt64()
      match state.Memory.Read(addr, endian, typ) with
      | Ok _ -> None
      | Result.Error _ ->
        let size = RegType.toByteWidth typ
        Some(memoryRequirement at "memory read" (Some addr) size)
    | Ok Undef
    | Result.Error _ ->
      let size = RegType.toByteWidth typ
      Some(memoryRequirement at "memory address is undefined" None size)

  let evalRequirementStmt state stmt =
    match SafeEvaluator.evalStmt state stmt with
    | Ok() -> ()
    | Result.Error _ -> ()

  let needsForWindow start count finish =
    let lifter = hdl.NewLiftingUnit()
    let state = state.Clone()
    let derived = HashSet<int>()
    let registers = ResizeArray<RequiredRegister>()
    let memory = ResizeArray<RequiredMemory>()
    let rec loop addr remaining =
      let inRange =
        match finish with
        | Some finish -> addr < finish
        | None -> remaining > 0
      if not inRange || not (hdl.File.IsValidAddr addr) then
        ()
      else
        match lifter.TryParseInstruction addr with
        | Error _ -> ()
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
    | [] -> [ "  user-memory: <none>" ]
    | ranges ->
      "  user-memory:"
      :: (ranges |> List.rev |> List.map (fun (addr, count) ->
        let finish = addr + uint64 count
        $"    0x{addr:x}-0x{finish:x} ({count} bytes)"))

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

  let splitContextEntry (entry: string) =
    let index = entry.IndexOf '='
    if index <= 0 then
      invalidArg (nameof entry) $"Expected key=value entry: {entry}"
    else
      entry[..index - 1].Trim(), entry[index + 1..].Trim()

  let parseContextArgs (args: string list) =
    let rec loop (stack: Addr option)
                 (regs: (string * string) list)
                 (memory: (string * string) list) = function
      | [] -> stack, List.rev regs, List.rev memory
      | (token: string) :: rest ->
        let index = token.IndexOf '='
        if index <= 0 then
          invalidArg (nameof args) $"Expected name=value parameter: {token}"
        else
          let key = token[..index - 1].Trim().ToLowerInvariant()
          let value = token[index + 1..].Trim()
          match key with
          | "stack" ->
            loop (Some(parseUInt64 value)) regs memory rest
          | "regs" | "registers" ->
            let regs =
              contextEntries value
              |> Array.fold (fun regs entry ->
                splitContextEntry entry :: regs) regs
            loop stack regs memory rest
          | "mem" | "memory" ->
            let memory =
              contextEntries value
              |> Array.fold (fun memory entry ->
                splitContextEntry entry :: memory) memory
            loop stack regs memory rest
          | _ ->
            invalidArg (nameof args) $"Unknown set-context parameter: {key}"
    loop None [] [] args

  let lastRunLines () =
    match previousResult with
    | None -> [ "  last-run: <none>" ]
    | Some result ->
      let reasons =
        result.StopReasons
        |> List.map formatStopReason
        |> String.concat ", "
      [ "  last-run:"
        $"    instructions: {result.InstructionCount}"
        $"    final-pc: 0x{result.FinalAddress:x}"
        $"    stop: [{reasons}]" ]

  let traceSummary (trace: ExecutionTrace option) =
    match trace with
    | None -> "<none>"
    | Some trace ->
      $"start=0x{trace.Start:x} final-pc=0x{trace.FinalPC:x} "
      + $"instructions={trace.InstructionCount}"

  new(binary) = ConcExecutorValue(binary, None, None, None, [])

  member _.State = state

  member _.Binary = binary

  member _.LastTrace = previousTrace

  member _.SummaryLines =
    let path =
      if String.IsNullOrWhiteSpace hdl.File.Path then "<raw>"
      else hdl.File.Path
    [ "ConcExecutor"
      $"  binary: {path}"
      $"  isa: {hdl.ISA}"
      $"  entry: 0x{(defaultStart ()):x}"
      $"  pc: 0x{state.PC:x}"
      $"  stack: {stackText ()}" ]
    @ memoryRangeLines ()
    @ lastRunLines ()

  member this.Summary = String.concat Environment.NewLine this.SummaryLines

  member _.Run(args: string list) =
    let start, limit, breakpoint =
      match args with
      | [] -> defaultStart (), 50000, None
      | [ entry ] -> parseUInt64 entry, 50000, None
      | [ entry; limit ] -> parseUInt64 entry, parseInt limit, None
      | [ entry; limit; breakpoint ] ->
        parseUInt64 entry, parseInt limit, Some(parseUInt64 breakpoint)
      | _ -> invalidArg (nameof args) "Invalid run argument layout."
    let stops =
      StopAfterInstructionCount limit
      :: (breakpoint |> Option.map StopAtAddress |> Option.toList)
    let beforeState = state.Clone()
    let runState = state.Clone()
    let result = executor.Run(start, runState, ConcRunOptions.Default stops)
    let instruction =
      { Address = start
        Disassembly = instructionAt start }
    let trace =
      traceFromResult start beforeState (Some result) [ instruction ] [||] None
    withState result.State (Some result) (Some trace) memoryRanges

  member _.Step(count: int) =
    let start = defaultStart ()
    let runState = state.Clone()
    let result, trace = runWithTrace start count runState None
    match result with
    | Some result ->
      withState result.State (Some result) (Some trace) memoryRanges
    | None -> withState runState None (Some trace) memoryRanges

  member _.Trace(args: string list) =
    let count, watch =
      match args with
      | [] -> 1, None
      | [ count ] -> parseInt count, None
      | [ addr; size ] -> 1, Some(parseUInt64 addr, parseInt size)
      | [ count; addr; size ] ->
        parseInt count, Some(parseUInt64 addr, parseInt size)
      | _ -> invalidArg (nameof args) "Invalid trace argument layout."
    let runState = state.Clone()
    let _, trace = runWithTrace (defaultStart ()) count runState watch
    trace

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
      clearRunState nextState memoryRanges
    | _ -> invalidArg (nameof args) "Invalid arg argument layout."

  member _.SetRegister(args: string list) =
    match args with
    | [ name; value ] ->
      match tryGetRegisterID name with
      | None -> invalidArg (nameof args) $"Unknown register: {name}"
      | Some rid ->
        let value = parseUInt64 value
        let nextState = state.Clone()
        let accessor = accessorFor nextState
        accessor.SetRegister(rid, accessor.WordValue value)
        clearRunState nextState memoryRanges
    | _ -> invalidArg (nameof args) "Invalid set-reg argument layout."

  member _.WriteMemory(args: string list) =
    match args with
    | [ addr; bytes ] ->
      let addr = parseUInt64 addr
      let bytes = ByteArray.ofHexString bytes
      let nextState = state.Clone()
      let accessor = accessorFor nextState
      accessor.WriteBytes(addr, bytes)
      let ranges = (addr, bytes.Length) :: memoryRanges
      clearRunState nextState ranges
    | _ -> invalidArg (nameof args) "Invalid mem write argument layout."

  member _.SetContext(args: string list) =
    let stack, registers, memory = parseContextArgs args
    let nextState = state.Clone()
    let accessor = accessorFor nextState
    stack |> Option.iter (fun addr ->
      accessor.SetRegister(getStackPointerID (), accessor.WordValue addr))
    registers |> List.iter (fun (name, value) ->
      match tryGetRegisterID name with
      | None -> invalidArg (nameof args) $"Unknown register: {name}"
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
    clearRunState nextState ranges

  member _.ReadMemory(args: string list) =
    match args with
    | [ addr; count ] ->
      let addr = parseUInt64 addr
      let count = parseInt count
      { Address = addr
        Bytes = (accessorFor state).ReadBytes(addr, count) }
    | _ -> invalidArg (nameof args) "Invalid mem read argument layout."

  member _.Registers(args: string list) =
    let factory = hdl.RegisterFactory
    let registerNames =
      if List.isEmpty args then factory.GetAllRegisterNames()
      else args |> List.toArray
    let requested = not (List.isEmpty args)
    let registers =
      registerNames
      |> Array.choose (fun name ->
        match tryGetRegisterID name with
        | None when requested ->
          Some { Name = name; Value = "<unknown>" }
        | None -> None
        | Some rid ->
          let name = factory.GetRegisterName rid
          match registerText state rid with
          | Some value -> Some { Name = name; Value = value }
          | None when requested -> Some { Name = name; Value = "<undef>" }
          | None -> None)
    { PC = state.PC; Registers = registers }

  member _.DiffLines(other: ConcExecutorValue) =
    let pcLine =
      if state.PC = other.State.PC then []
      else [ $"pc: 0x{state.PC:x} -> 0x{other.State.PC:x}" ]
    let regLines = registerDiffs state other.State
    let traceLines =
      [ $"left-trace: {traceSummary previousTrace}"
        $"right-trace: {traceSummary other.LastTrace}" ]
    match pcLine @ regLines with
    | [] -> traceLines @ [ "registers: no visible changes" ]
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
          | :? Binary as binary -> ConcExecutorValue(binary) |> box
          | :? BinarySlice as slice ->
            ConcExecutorValue(slice.ToBinary()) |> box
          | _ -> invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "conc-exec"
    member _.Signature with get() = "Binary | BinarySlice -> ConcExecutor"
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
          | :? ConcExecutorValue as executor -> executor.Run args |> box
          | _ -> invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "run"
    member _.Signature with get() =
      "ConcExecutor -> run [entry=<addr>] [limit=<n>] [break=<addr>]"
      + " -> ConcExecutor"
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
          | _ -> invalidArg (nameof input) "Invalid input type.") }

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

/// Set one concrete register value.
type SetRegAction() =
  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    { Values =
        collection.Values
        |> Array.map (fun input ->
          cancellationToken.ThrowIfCancellationRequested()
          match input with
          | :? ConcExecutorValue as executor ->
            executor.SetRegister args |> box
          | _ -> invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "set-reg"
    member _.Signature with get() =
      "ConcExecutor -> set-reg name=<register> value=<addr> -> ConcExecutor"
    member _.Description with get() =
      "Set a concrete register value in the executor context."
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
          | _ -> invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "set-context"
    member _.Signature with get() =
      "ConcExecutor * [stack=<addr>] [regs=[...]] [mem=[...]]"
      + " -> ConcExecutor"
    member _.Description with get() =
      "Set multiple register and memory values in one concrete context."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

/// Read or write concrete executor memory.
type MemAction() =
  let transformOne args (executor: ConcExecutorValue) =
    match args with
    | "read" :: args -> executor.ReadMemory args |> box
    | "write" :: args -> executor.WriteMemory args |> box
    | _ -> invalidArg (nameof args) "Expected: mem read|write ..."

  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    { Values =
        collection.Values
        |> Array.map (fun input ->
          cancellationToken.ThrowIfCancellationRequested()
          match input with
          | :? ConcExecutorValue as executor ->
            executor |> transformOne args
          | _ -> invalidArg (nameof input) "Invalid input type.") }

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
    | [] -> 1
    | [ (count: string) ] ->
      Int32.Parse(count, NumberStyles.Integer, CultureInfo.InvariantCulture)
    | _ -> invalidArg "args" "At most one step count is allowed."

  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    let count = parseCount args
    { Values =
        collection.Values
        |> Array.map (fun input ->
          cancellationToken.ThrowIfCancellationRequested()
          match input with
          | :? ConcExecutorValue as executor -> executor.Step count |> box
          | _ -> invalidArg (nameof input) "Invalid input type.") }

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
          | :? ConcExecutorValue as executor -> executor.Trace args |> box
          | _ -> invalidArg (nameof input) "Invalid input type.") }

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
    let minAddress, maxAddress =
      match args with
      | [ minAddress; maxAddress ] ->
        ConcActionParsing.parseUInt64 minAddress,
        ConcActionParsing.parseUInt64 maxAddress
      | _ ->
        invalidArg (nameof args) "Expected: random min=<addr> max=<addr>."
    { Values =
        collection.Values
        |> Array.map (fun _ ->
          cancellationToken.ThrowIfCancellationRequested()
          ConcActionParsing.randomAddress minAddress maxAddress |> box) }

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
    let top = ConcStateAccessor.DefaultStackTop
    let window = 0x100000UL
    let address =
      ConcActionParsing.randomAddress (top - window) top
    let address =
      { address with
          Address = ConcActionParsing.alignDown 16UL address.Address }
    { Values =
        collection.Values
        |> Array.map (fun _ ->
          cancellationToken.ThrowIfCancellationRequested()
          address |> box) }

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
          | :? ConcExecutorValue as executor -> executor.Registers args |> box
          | _ -> invalidArg (nameof input) "Invalid input type.") }

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
