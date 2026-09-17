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
open System.Globalization
open System.Text
open System.Threading
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ConcEval

/// Stateful concrete executor used by the Transformer REPL.
type ConcExecutorValue(binary: Binary,
                       initialState: EvalState option,
                       previousResult: ConcRunResult<EvalState> option) =
  let hdl = Binary.Handle binary
  let executor = ConcExecutor hdl

  let createInitialState () =
    let state = executor.CreateState()
    ConcStateAccessor(hdl, state).InitializeDefaultStack()
    state

  let state: EvalState =
    match initialState with
    | Some state -> state
    | None -> createInitialState ()

  let lastResult: ConcRunResult<EvalState> option = previousResult

  let parseUInt64 (value: string) =
    let style, value =
      if value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        NumberStyles.HexNumber, value[2..]
      else
        NumberStyles.Integer, value
    UInt64.Parse(value, style, CultureInfo.InvariantCulture)

  let parseInt (value: string) =
    Int32.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture)

  let parseByteCount = parseInt

  let defaultStart () =
    if state.PC <> 0UL then state.PC
    else hdl.File.EntryPoint |> Option.defaultValue 0UL

  let accessor () = ConcStateAccessor(hdl, state)

  let withState state result =
    ConcExecutorValue(binary, Some state, result)

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

  let tryGetRegisterID (name: string) =
    let factory = hdl.RegisterFactory
    try Some(factory.GetRegisterID name)
    with _ ->
      try Some(factory.GetRegisterID(name.ToUpperInvariant()))
      with _ -> None

  let formatRegister (name: string) =
    let factory = hdl.RegisterFactory
    match tryGetRegisterID name with
    | None -> Some $"{name}= <unknown>"
    | Some rid ->
      match state.TryGetReg rid with
      | Def value -> Some $"{factory.GetRegisterName rid}= {value}"
      | Undef -> None

  let registerValue state rid =
    match (state: EvalState).TryGetReg rid with
    | Def value -> Some(value.ToString())
    | Undef -> None

  let registerDiffs (beforeState: EvalState) (afterState: EvalState) =
    hdl.RegisterFactory.GetAllRegisterNames()
    |> Array.choose (fun name ->
      match tryGetRegisterID name with
      | None -> None
      | Some rid ->
        let before = registerValue beforeState rid
        let after = registerValue afterState rid
        if before = after then None
        else
          let before = before |> Option.defaultValue "<undef>"
          let after = after |> Option.defaultValue "<undef>"
          Some $"{name}: {before} -> {after}")
    |> Array.toList

  let instructionAt (address: Addr) =
    let lifter = hdl.NewLiftingUnit()
    match lifter.TryParseInstruction address with
    | Ok instruction -> instruction.Disasm()
    | Error error -> $"<decode failed: {error}>"

  let tryReadBytes address count state =
    try
      ConcStateAccessor(hdl, state).ReadBytes(address, count) |> Some
    with _ ->
      None

  let formatBytes address (bytes: byte[]) =
    let hex = bytes |> Array.map (sprintf "%02x") |> String.concat " "
    let ascii =
      bytes
      |> Array.map (fun b ->
        if b >= 0x20uy && b <= 0x7euy then char b else '.')
      |> String
    $"0x{address:x}: {hex}  {ascii}"

  member _.Summary =
    match lastResult with
    | None -> "concrete executor: not run"
    | Some result ->
      let reasons =
        result.StopReasons
        |> List.map formatStopReason
        |> String.concat ", "
      "concrete executor: "
      + $"pc=0x{result.FinalAddress:x} insns={result.InstructionCount} "
      + $"reasons=[{reasons}]"

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
    let runState = state.Clone()
    let result = executor.Run(start, runState, ConcRunOptions.Default stops)
    withState result.State (Some result)

  member _.Step(count: int) =
    let start = defaultStart ()
    let runState = state.Clone()
    let result =
      executor.Run(start, runState, ConcRunOptions.Default
        (StopAfterInstructionCount count))
    withState result.State (Some result)

  member _.Trace(args: string list) =
    let count, watch =
      match args with
      | [] -> 1, None
      | [ count ] -> parseInt count, None
      | [ address; size ] ->
        let watch = parseUInt64 address, parseInt size
        1, Some watch
      | [ count; address; size ] ->
        let watch = parseUInt64 address, parseInt size
        parseInt count, Some watch
      | _ -> invalidArg (nameof args) "Invalid trace argument layout."
    let start = defaultStart ()
    let instruction = instructionAt start
    let runState = state.Clone()
    let beforeMemory =
      watch |> Option.bind (fun (address, size) ->
        tryReadBytes address size runState)
    let result =
      executor.Run(start, runState, ConcRunOptions.Default
        (StopAfterInstructionCount count))
    let afterMemory =
      watch |> Option.bind (fun (address, size) ->
        tryReadBytes address size result.State)
    let lines =
      [ $"start: 0x{start:x}"
        $"instruction: {instruction}"
        $"final-pc: 0x{result.FinalAddress:x}"
        $"instructions: {result.InstructionCount}" ]
    let diffs = registerDiffs state result.State
    let registerLines =
      match diffs with
      | [] -> [ "registers: no visible changes" ]
      | diffs -> "registers:" :: (diffs |> List.map (fun line -> "  " + line))
    let memoryLines =
      match watch, beforeMemory, afterMemory with
      | None, _, _ ->
        [ "memory: no watch range; use address=<addr> size=<n>." ]
      | Some(address, _), Some before, Some after when before <> after ->
        [ "memory:"
          $"  before {formatBytes address before}"
          $"  after  {formatBytes address after}" ]
      | Some(address, _), Some bytes, Some _ ->
        [ "memory:"
          $"  unchanged {formatBytes address bytes}" ]
      | Some(address, size), _, _ ->
        [ $"memory: could not read 0x{address:x} size={size}" ]
    String.concat Environment.NewLine (lines @ registerLines @ memoryLines)

  member _.SetArgument(args: string list) =
    match args with
    | [ index; value ] ->
      let index = parseInt index
      let value = parseUInt64 value
      let nextState = state.Clone()
      let accessor = ConcStateAccessor(hdl, nextState)
      accessor.SetArgument(index, accessor.WordValue value)
      withState nextState lastResult
    | _ -> invalidArg (nameof args) "Invalid arg argument layout."

  member _.WriteMemory(args: string list) =
    match args with
    | [ address; bytes ] ->
      let address = parseUInt64 address
      let bytes = ByteArray.ofHexString bytes
      let nextState = state.Clone()
      let accessor = ConcStateAccessor(hdl, nextState)
      accessor.WriteBytes(address, bytes)
      withState nextState lastResult
    | _ -> invalidArg (nameof args) "Invalid mem-write argument layout."

  member _.ReadMemory(args: string list) =
    match args with
    | [ address; count ] ->
      let address = parseUInt64 address
      let count = parseByteCount count
      let accessor = accessor ()
      accessor.ReadBytes(address, count) |> formatBytes address
    | _ -> invalidArg (nameof args) "Invalid mem-read argument layout."

  member _.Registers(args: string list) =
    let registerLines =
      if List.isEmpty args then hdl.RegisterFactory.GetAllRegisterNames()
      else List.toArray args
      |> Array.choose formatRegister
      |> Array.toList
    $"PC= 0x{state.PC:x}" :: registerLines

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
            ConcExecutorValue(binary, None, None) |> box
          | _ -> invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "concExec"
    member _.Signature with get() = "Binary -> ConcExecutor"
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
            executor.Run args |> box
          | _ -> invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "run"
    member _.Signature with get() =
      "ConcExecutor * [entry] [limit] [break] -> ConcExecutor"
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
    member _.Signature with get() = "ConcExecutor * <index> <value>"
    member _.Description with get() =
      "Set an integer or pointer argument register for concrete execution."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

/// Write concrete bytes to executor memory.
type MemWriteAction() =
  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    { Values =
        collection.Values
        |> Array.map (fun input ->
          cancellationToken.ThrowIfCancellationRequested()
          match input with
          | :? ConcExecutorValue as executor ->
            executor.WriteMemory args |> box
          | _ -> invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "mem-write"
    member _.Signature with get() = "ConcExecutor * <address> <bytes>"
    member _.Description with get() =
      "Write hexadecimal bytes to concrete executor memory."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

/// Read concrete bytes from executor memory.
type MemReadAction() =
  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    { Values =
        collection.Values
        |> Array.map (fun input ->
          cancellationToken.ThrowIfCancellationRequested()
          match input with
          | :? ConcExecutorValue as executor ->
            executor.ReadMemory args |> box
          | _ -> invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "mem-read"
    member _.Signature with get() = "ConcExecutor * <address> <size>"
    member _.Description with get() =
      "Read bytes from concrete executor memory as hex and ASCII."
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
          | :? ConcExecutorValue as executor ->
            executor.Step count |> box
          | _ -> invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "step"
    member _.Signature with get() = "ConcExecutor * [count] -> ConcExecutor"
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
            executor.Trace args |> box
          | _ -> invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "trace"
    member _.Signature with get() =
      "ConcExecutor * [count] [address] [size] -> Text"
    member _.Description with get() =
      "Show executed instruction, register changes, and watched memory."
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
            executor.Registers args
            |> String.concat Environment.NewLine
            |> box
          | _ -> invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "regs"
    member _.Signature with get() = "ConcExecutor -> Text"
    member _.Description with get() =
      "Show currently defined concrete register values."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
