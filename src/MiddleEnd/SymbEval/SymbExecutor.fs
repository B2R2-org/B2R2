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

namespace B2R2.MiddleEnd.SymbEval

open System.Collections.Generic
open System.Diagnostics
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.Executor

/// Represents a symbolic execution point inspected by SymbExecutor queries.
type SymbStopPoint =
  { /// Address of the symbolic state.
    Address: Addr
    /// Number of instructions executed before reaching the state.
    InstructionCount: int
    /// Instruction about to execute at the stop point, if parsable.
    Instruction: IInstruction option
    /// Symbolic state at the stop point.
    State: SymbState }

/// Represents an avoid condition used by SymbExecutor.Run.
type SymbAvoid =
  /// Discard states whose PC reaches one of the given addresses.
  | AvoidAddresses of addrs: Set<Addr>
  /// Discard states satisfying the given predicate.
  | AvoidState of predicate: (SymbStopPoint -> bool)

/// Represents a symbolic query evaluated by SymbExecutor.Run.
type SymbQuery =
  /// Ask whether execution can reach the given address.
  | ReachAddress of target: Addr
  /// Ask whether execution can reach a state satisfying the predicate.
  | ReachState of predicate: (SymbStopPoint -> bool)
  /// Ask for concrete symbolic-input values reaching the given address.
  | SatisfyAddress of target: Addr
  /// Ask for concrete symbolic-input values reaching a matching state.
  | SatisfyState of predicate: (SymbStopPoint -> bool)

/// Represents a symbolic query and the values to extract for model queries.
type SymbQueryRequest =
  { /// Query to answer.
    Query: SymbQuery
    /// Symbolic values to extract for satisfiability queries.
    QueryValues: IQueryExpr }

/// Represents a solver backend used by SymbExecutor.
type SymbSolver =
  /// Do not use a solver.
  | NoSolver
  /// Use a caller-provided solver implementation.
  | CustomSolver of solver: ISolver

/// Represents how the symbolic executor should handle call instructions.
type SymbCallPolicy =
  /// Stop before evaluating any call instruction.
  | StopAtCalls
  /// Follow direct calls whose target belongs to the current binary.
  | FollowDirectInternalCalls
  /// Dispatch matching call hooks, and follow direct internal calls otherwise.
  | UseCallHooks of hooks: SymbCallHookRegistry

/// Represents options for bounded symbolic execution.
type SymbRunOptions =
  { /// Call-handling policy.
    Calls: SymbCallPolicy
    /// Query to answer.
    Query: SymbQuery
    /// Symbolic values to extract for satisfiability queries.
    QueryValues: IQueryExpr
    /// Address or state predicates to discard before further exploration.
    Avoid: SymbAvoid
    /// Maximum instructions to execute per path. Zero means unlimited.
    MaxDepth: int
    /// Maximum number of states to expand. Zero means unlimited.
    MaxStates: int
    /// Maximum visits allowed at the same address. Zero means unlimited.
    LoopBound: int
    /// Solver backend used for path queries and optional pruning.
    Solver: SymbSolver
    /// Maximum milliseconds to spend in Run. Zero means unlimited.
    RunTimeout: int
    /// Enable solver-backed infeasible path pruning.
    PruneInfeasiblePaths: bool
    /// Stop exploration as soon as the first query answer is found.
    StopAtFirstAnswer: bool
    /// Half-open address ranges [start, finish) to pre-lift before Run.
    /// Empty means no pre-lifting.
    WarmUpRanges: (Addr * Addr) list }
with
  static member Default(query: SymbQuery, solver: SymbSolver) =
    { Calls = FollowDirectInternalCalls
      Query = query
      QueryValues = (QueryExpr.Empty :> IQueryExpr)
      Avoid = AvoidAddresses Set.empty
      MaxDepth = 500
      MaxStates = 4096
      LoopBound = 1
      Solver = solver
      RunTimeout = 30000
      PruneInfeasiblePaths = false
      StopAtFirstAnswer = true
      WarmUpRanges = [] }

  static member Default(query: SymbQuery) =
    SymbRunOptions.Default(query, NoSolver)

  static member Default(query: SymbQueryRequest, solver: SymbSolver) =
    { SymbRunOptions.Default(query.Query, solver) with
        QueryValues = query.QueryValues }

  static member Default(query: SymbQueryRequest) =
    SymbRunOptions.Default(query, NoSolver)

  static member private MatchesAvoid(avoid, point) =
    match avoid with
    | AvoidAddresses addrs -> Set.contains point.Address addrs
    | AvoidState pred -> pred point

  static member private CombineAvoid(lhs, rhs) =
    match lhs, rhs with
    | AvoidAddresses addrs1, AvoidAddresses addrs2 ->
      AvoidAddresses(Set.union addrs1 addrs2)
    | AvoidAddresses addrs, avoid when Set.isEmpty addrs -> avoid
    | avoid, AvoidAddresses addrs when Set.isEmpty addrs -> avoid
    | avoid1, avoid2 ->
      AvoidState(fun point ->
        SymbRunOptions.MatchesAvoid(avoid1, point)
        || SymbRunOptions.MatchesAvoid(avoid2, point))

  /// Adds one symbolic value to solver value extraction.
  member opts.AddQueryValue value =
    { opts with
        QueryValues =
          QueryExpr.Values
            [ opts.QueryValues
              QueryExpr.Value value :> IQueryExpr ] }

  /// Adds symbolic values to solver value extraction.
  member opts.AddQueryValues values =
    let values =
      values
      |> Seq.map (fun value -> QueryExpr.Value value :> IQueryExpr)
      |> Seq.toList
    { opts with
        QueryValues =
          QueryExpr.Values(opts.QueryValues :: values) }

  /// Uses the given symbolic values for solver value extraction.
  member opts.WithQueryValues values =
    let values =
      values
      |> Seq.map (fun value -> QueryExpr.Value value :> IQueryExpr)
      |> Seq.toList
    { opts with QueryValues = QueryExpr.Values values }

  /// Uses the given query expression for solver value extraction.
  member opts.WithQueryValues(values: IQueryExpr) =
    { opts with QueryValues = values }

  /// Adds all symbolic bytes of the given buffer to value extraction.
  member opts.AddQueryBuffer(buffer: SymbByteBuffer) =
    { opts with
        QueryValues =
          QueryExpr.Values
            [ opts.QueryValues
              buffer :> IQueryExpr ] }

  /// Adds all symbolic bytes of the given buffers to value extraction.
  member opts.AddQueryBuffers(buffers: seq<SymbByteBuffer>) =
    let buffers =
      buffers
      |> Seq.map (fun buffer -> buffer :> IQueryExpr)
      |> Seq.toList
    { opts with
        QueryValues =
          QueryExpr.Values(opts.QueryValues :: buffers) }

  /// Adds one address to the avoid set.
  member opts.AddAvoidAddress addr =
    { opts with
        Avoid =
          SymbRunOptions.CombineAvoid(opts.Avoid,
                                     AvoidAddresses(Set.singleton addr)) }

  /// Adds addresses to the avoid set.
  member opts.AddAvoidAddresses addrs =
    { opts with
        Avoid =
          SymbRunOptions.CombineAvoid(opts.Avoid,
                                     AvoidAddresses(Set.ofSeq addrs)) }

  /// Replaces the avoid set.
  member opts.WithAvoidAddresses addrs =
    { opts with Avoid = AvoidAddresses(Set.ofSeq addrs) }

  /// Uses the given avoid condition.
  member opts.WithAvoid avoid =
    { opts with Avoid = avoid }

  /// Adds one avoid condition.
  member opts.AddAvoid avoid =
    { opts with Avoid = SymbRunOptions.CombineAvoid(opts.Avoid, avoid) }

  /// Adds one state predicate to the avoid conditions.
  member opts.AddAvoidState predicate =
    opts.AddAvoid(AvoidState predicate)

  /// Stops before evaluating call instructions.
  member opts.StopAtCalls() =
    { opts with Calls = StopAtCalls }

  /// Follows direct internal calls without using external-call hooks.
  member opts.FollowDirectInternalCalls() =
    { opts with Calls = FollowDirectInternalCalls }

  /// Uses a prepared call hook registry for external-call dispatch.
  member opts.WithCallHooks hooks =
    { opts with Calls = UseCallHooks hooks }

  /// Registers a call hook and enables hook-based call handling.
  member opts.RegisterCallHook(target, hook) =
    let hooks =
      match opts.Calls with
      | UseCallHooks hooks -> hooks
      | StopAtCalls
      | FollowDirectInternalCalls -> SymbCallHookRegistry()
    { opts with
        Calls = UseCallHooks(hooks.Register(target, hook)) }

  /// Registers call hooks and enables hook-based call handling.
  member opts.RegisterCallHooks hooks =
    let registry =
      match opts.Calls with
      | UseCallHooks registry -> registry
      | StopAtCalls
      | FollowDirectInternalCalls -> SymbCallHookRegistry()
    { opts with
        Calls = UseCallHooks(registry.RegisterMany hooks) }

  /// Uses the given solver backend.
  member opts.WithSolver solver =
    { opts with Solver = solver }

  /// Enables solver-backed infeasible path pruning.
  member opts.EnablePathPruning() =
    { opts with PruneInfeasiblePaths = true }

  /// Disables solver-backed infeasible path pruning.
  member opts.DisablePathPruning() =
    { opts with PruneInfeasiblePaths = false }

  /// Stops exploration as soon as the first query answer is found.
  member opts.EnableStopAtFirstAnswer() =
    { opts with StopAtFirstAnswer = true }

  /// Continues exploration after finding a query answer.
  member opts.DisableStopAtFirstAnswer() =
    { opts with StopAtFirstAnswer = false }

  /// Uses the given half-open address ranges for pre-lifting.
  member opts.WithWarmUpRanges ranges =
    { opts with WarmUpRanges = ranges }

/// Represents a non-target state where exploration stopped.
type SymbRunStopReason =
  /// Exploration reached a call according to the configured call policy.
  | StoppedAtCall of callSite: Addr * target: Addr option
  /// Exploration reached the configured maximum path depth.
  | DepthLimitReached of addr: Addr * limit: int
  /// Exploration reached the configured maximum expanded-state count.
  | StateLimitReached of limit: int
  /// No instruction could be fetched or lifted at the given address.
  | InvalidInstructionStopped of addr: Addr
  /// Evaluation reached a LowUIR statement with architectural side effects.
  | SideEffectStopped of addr: Addr * sideEffect: SideEffect
  /// Evaluation failed while executing the instruction at the given address.
  | EvaluationFailed of addr: Addr * error: SymbEvalError
  /// A query needed a solver, but none was available.
  | MissingSolverForQuery of addr: Addr
  /// Solver query failed at a matching state.
  | SolverQueryFailed of addr: Addr * error: SymbEvalError
  /// Exploration reached the configured run timeout.
  | RunTimeoutReached of timeout: int

/// Represents a state that was discarded before further exploration.
type SymbRunPruneReason =
  /// The state reached an avoided instruction address.
  | AvoidedAddress of addr: Addr
  /// The state matched an avoided state predicate.
  | AvoidedState of addr: Addr
  /// The state exceeded the per-path loop bound.
  | LoopBoundReached of addr: Addr * limit: int
  /// The solver proved the state's path condition unsatisfiable.
  | InfeasiblePath of addr: Addr
  /// Solver pruning failed while checking the state's path condition.
  | SolverPruningFailed of addr: Addr * error: SymbEvalError

/// Represents one positive answer to a reachability query.
type SymbReachabilityAnswer =
  { /// Target address reached by this answer.
    Target: Addr
    /// State at the target address.
    State: SymbState }

/// Represents one concrete-input answer to a satisfiability query.
type SymbSatisfiabilityAnswer =
  { /// Target address reached by this answer.
    Target: Addr
    /// State at the target address.
    State: SymbState
    /// Concrete assignments for requested symbolic values.
    Values: SolverValue list }
with
  /// Concrete solver model for this satisfiability answer.
  member this.Model = SymbModel this.Values

/// Represents why a symbolic query could not be fully answered.
type SymbRunFailure =
  /// A state stopped before it could reach a target.
  | Stopped of SymbState * SymbRunStopReason
  /// A state was pruned before it could reach a target.
  | Pruned of SymbState * SymbRunPruneReason

/// Represents the answer to a bounded symbolic execution query.
type SymbRunResult =
  /// One or more states reached the requested target.
  | Reachable of SymbReachabilityAnswer list
  /// No state reached the requested target in the explored state space.
  | Unreachable
  /// One or more concrete assignments satisfy the requested target.
  | Satisfiable of SymbSatisfiabilityAnswer list
  /// No concrete assignment satisfies the requested target.
  | Unsatisfiable
  /// Execution could not prove satisfiability or unsatisfiability.
  | Unknown of SymbRunFailure list
  /// Execution timed out and produced the given partial result.
  | TimedOut of timeout: int * result: SymbRunResult
with
  /// Returns the first satisfiability answer, or raises when unavailable.
  member this.GetSatisfiabilityAnswer() =
    let rec loop = function
      | Satisfiable(answer :: _) -> answer
      | TimedOut(_, result) -> loop result
      | result ->
        raise
          (System.InvalidOperationException
            $"Satisfiability answer is unavailable: {result}.")
    loop this

type private SymbRunWorkItem =
  { State: SymbState
    Depth: int
    Visits: Map<Addr, int>
    CheckedPathCondLen: int }

type private SymbRunContext =
  { mutable ReachAnswers: SymbReachabilityAnswer list
    mutable SatAnswers: SymbSatisfiabilityAnswer list
    mutable StoppedStates: (SymbState * SymbRunStopReason) list
    mutable PrunedStates: (SymbState * SymbRunPruneReason) list
    mutable GeneratedStates: int
    mutable StopExploration: bool
    mutable RunTimeout: int option }
with
  static member Init() =
    { ReachAnswers = []
      SatAnswers = []
      StoppedStates = []
      PrunedStates = []
      GeneratedStates = 0
      StopExploration = false
      RunTimeout = None }

  member ctx.AddStopped st reason =
    ctx.StoppedStates <- (st, reason) :: ctx.StoppedStates

  member ctx.AddPruned st reason =
    ctx.PrunedStates <- (st, reason) :: ctx.PrunedStates

  member ctx.AddReachAnswer target st =
    ctx.ReachAnswers <- { Target = target; State = st } :: ctx.ReachAnswers

  member ctx.AddSatAnswer target st values =
    ctx.SatAnswers <- { Target = target; State = st; Values = values }
                      :: ctx.SatAnswers

  member ctx.MarkStateGenerated() =
    ctx.GeneratedStates <- ctx.GeneratedStates + 1

  member ctx.Stop() =
    ctx.StopExploration <- true

  member ctx.MarkTimeout timeout =
    ctx.RunTimeout <- Some timeout
    ctx.Stop()

type private SymbQueryEvalResult =
  | QueryReachable
  | QuerySatisfiable of SolverValue list
  | QueryUnsat of SymbRunPruneReason
  | QueryUnknown of SymbRunStopReason

type private SymbMatchedQuery =
  | MatchedReachabilityQuery
  | MatchedSatisfiabilityQuery

type private SymbValueQuery =
  SymbExpr list * SymbExpr list -> Result<SolverOutput, SymbEvalError>

type private SymbSolverRunner =
  { CheckSat: SymbExpr list -> Result<SolverStatus, SymbEvalError>
    GetModels: SymbValueQuery }

type private SymbInstructionAction =
  | EvaluateInstruction
  | SkipInstruction of SymbEvaluator.SymbEvalSuccessor list
  | StopBeforeInstruction of SymbRunStopReason

type private SymbLiftedInstruction =
  { Instruction: IInstruction
    Stmts: Stmt[] }

/// Represents a symbolic executor over SymbEval's evaluation state.
type SymbExecutor(hdl: BinHandle) =
  let lifter = hdl.NewLiftingUnit()
  let liftCache = Dictionary<Addr, Result<SymbLiftedInstruction, ErrorCase>>()
  let defaultStateCreationOptions =
    { Memory = BinSectionBackedMemory
      Registers = [||] }

  let createState = function
    | EmptyMemory -> SymbState()
    | PreinitializedMemory mem -> SymbState mem
    | BinSectionBackedMemory -> SymbState(BinSectionSymbMemory hdl)

  let initializeState start opts =
    let st = createState opts.Memory
    st.InitializeContext(start, opts.Registers)
    st

  let tryParseInstruction addr =
    if hdl.File.IsValidAddr addr then lifter.TryParseInstruction addr
    else Error ErrorCase.ParsingFailure

  let tryLiftInstruction (ins: IInstruction) =
    try lifter.LiftInstruction ins |> Ok
    with _ -> Error ErrorCase.ParsingFailure

  let cacheLiftResult addr result =
    liftCache[addr] <- result
    result

  let tryLiftParsedInstruction (ins: IInstruction) =
    tryLiftInstruction ins
    |> Result.map (fun stmts -> { Instruction = ins; Stmts = stmts })

  let tryParseAndLiftInstruction addr =
    match tryParseInstruction addr with
    | Error e -> Error e
    | Ok ins -> tryLiftParsedInstruction ins

  let tryGetLiftedInstruction addr =
    match liftCache.TryGetValue addr with
    | true, result -> result
    | false, _ ->
      tryParseAndLiftInstruction addr
      |> cacheLiftResult addr

  let advanceAddress addr amount finishAddr =
    let nextAddr = addr + amount
    if nextAddr <= addr then finishAddr else nextAddr

  let instructionAlignment () = uint64 lifter.InstructionAlignment

  let rec warmUpLiftCacheRange addr finishAddr =
    if addr >= finishAddr then ()
    else
      match liftCache.TryGetValue addr with
      | true, Ok lifted ->
        warmUpLiftCacheRange
          (advanceAddress addr (uint64 lifted.Instruction.Length) finishAddr)
          finishAddr
      | true, Error _ ->
        warmUpLiftCacheRange
          (advanceAddress addr (instructionAlignment ()) finishAddr)
          finishAddr
      | false, _ ->
        match tryParseInstruction addr with
        | Ok ins ->
          tryLiftParsedInstruction ins
          |> cacheLiftResult addr
          |> ignore
          warmUpLiftCacheRange
            (advanceAddress addr (uint64 ins.Length) finishAddr)
            finishAddr
        | Error e ->
          Error e
          |> cacheLiftResult addr
          |> ignore
          warmUpLiftCacheRange
            (advanceAddress addr (instructionAlignment ()) finishAddr)
            finishAddr

  let warmUpLiftCache (ranges: (Addr * Addr) list) =
    ranges
    |> List.iter (fun (startAddr, finishAddr) ->
      if startAddr >= finishAddr then ()
      else warmUpLiftCacheRange startAddr finishAddr)

  let tryGetDirectTargetAddr (ins: IInstruction) =
    match ins.DirectBranchTarget() with
    | true, target -> Some target
    | false, _ -> None

  let tryGetConcreteReg rid (st: SymbState) =
    match st.TryGetReg rid with
    | Ok(Const bv) -> Some(bv.ToUInt64())
    | _ -> None

  let tryGetCallTargetAddr (ins: IInstruction) (st: SymbState) =
    match tryGetDirectTargetAddr ins with
    | Some target -> Some target
    | None ->
      match hdl.File.ISA with
      | MIPS ->
        let rid = MIPS.Register.R25 |> MIPS.Register.toRegID
        tryGetConcreteReg rid st
      | _ -> None

  let getCallFallThroughAddr addr (ins: IInstruction) =
    match hdl.File.ISA with
    | MIPS ->
      let delaySlotAddr = addr + uint64 ins.Length
      match tryParseInstruction delaySlotAddr with
      | Ok delaySlot -> delaySlotAddr + uint64 delaySlot.Length
      | Error _ -> delaySlotAddr + uint64 ins.Length
    | _ -> addr + uint64 ins.Length

  let isInternalTarget target = hdl.File.IsValidAddr target

  let wordType = hdl.File.ISA.WordSize |> WordSize.toRegType

  let endian = hdl.File.ISA.Endian

  let syncPC (addr: Addr) (st: SymbState) =
    st.SetReg(hdl.RegisterFactory.ProgramCounter,
              SymbExpr.Const(BitVector(addr, wordType)))

  let getArgumentRegisters os =
    [| 1 .. 6 |]
    |> Array.map (fun idx ->
      CallingConvention.FunctionArgRegister(hdl, os, idx))

  let mkCallContext callSite target returnAddress =
    { CallSite = callSite
      Target = target
      ReturnAddress = returnAddress
      WordType = wordType
      Endian = endian
      ArgumentRegisters = getArgumentRegisters OS.Linux
      ReturnRegister = CallingConvention.ReturnRegister hdl }

  let pushReturnAddress returnAddress (st: SymbState) =
    let accessor = SymbStateAccessor(hdl, st, OS.Linux)
    accessor.TryPushToStack(accessor.WordValue returnAddress)
    |> Result.map ignore

  let popReturnAddress (st: SymbState) =
    let accessor = SymbStateAccessor(hdl, st, OS.Linux)
    match accessor.TryPopFromStack() with
    | Ok(Const ret) -> Ok(ret.ToUInt64())
    | Ok expr -> Error(UnsupportedSymbolicAddress expr)
    | Error e -> Error e

  let finishHookState returnAddress (st: SymbState) =
    match popReturnAddress st with
    | Ok retAddr when retAddr = returnAddress ->
      st.PC <- returnAddress
      SymbEvaluator.Continue st
    | Ok retAddr ->
      let msg = $"Hook returned to unexpected address {retAddr:x}."
      SymbEvaluator.EvalError(UnsupportedOperation msg)
    | Error e -> SymbEvaluator.EvalError e

  let dispatchCallHook callSite target returnAddress hook (st: SymbState) =
    let hookState = st.Clone()
    let ctx = mkCallContext callSite target returnAddress
    match pushReturnAddress returnAddress hookState with
    | Error e -> [ SymbEvaluator.EvalError e ]
    | Ok() ->
      match hook ctx hookState with
      | Error e -> [ SymbEvaluator.EvalError e ]
      | Ok states ->
        states |> List.map (finishHookState returnAddress)

  let handleCallInstruction addr (ins: IInstruction)
                            (opts: SymbRunOptions) (st: SymbState) =
    if not ins.IsCall then EvaluateInstruction
    else
      let target = tryGetCallTargetAddr ins st
      match opts.Calls with
      | StopAtCalls -> StopBeforeInstruction(StoppedAtCall(addr, target))
      | FollowDirectInternalCalls ->
        match target with
        | Some target when isInternalTarget target -> EvaluateInstruction
        | _ ->
          let msg = "Cannot follow call without a concrete internal target."
          SymbEvaluator.EvalError(UnsupportedOperation msg)
          |> List.singleton
          |> SkipInstruction
      | UseCallHooks hooks ->
        match target with
        | Some target ->
          match hooks.TryFind target with
          | Some hook ->
            let returnAddress = getCallFallThroughAddr addr ins
            dispatchCallHook addr target returnAddress hook st
            |> SkipInstruction
          | None when isInternalTarget target -> EvaluateInstruction
          | None ->
            let msg = $"No symbolic call hook for target {target:x}."
            SymbEvaluator.EvalError(UnsupportedOperation msg)
            |> List.singleton
            |> SkipInstruction
        | None ->
          let msg = "Cannot dispatch call hook without a concrete target."
          SymbEvaluator.EvalError(UnsupportedOperation msg)
          |> List.singleton
          |> SkipInstruction

  let solverFailure failure = SolverFailure failure |> Error

  let trySerialize fn =
    try fn () |> Ok with
    | :? System.ArgumentException as ex ->
      SolverSerializationFailure ex.Message |> solverFailure
    | :? System.InvalidOperationException as ex ->
      SolverSerializationFailure ex.Message |> solverFailure

  let parseSolverStatus stdout =
    match SolverOutputParser.parseStatus stdout with
    | Ok status -> Ok status
    | Error(SolverFailure(SolverOutputParseFailure(msg, _))) ->
      SolverOutputParseFailure(msg, stdout) |> solverFailure
    | Error err -> Error err

  let checkSmt2 (solver: ISolver) pathCond =
    trySerialize (fun () -> SMTLibSerializer.serializeAssertions pathCond [])
    |> Result.bind solver.CheckSat
    |> Result.bind parseSolverStatus

  let getModelsSmt2 (solver: ISolver) (pathCond, values) =
    SolverOutputParser.validate values
    |> Result.bind (fun () ->
      trySerialize (fun () ->
        SMTLibSerializer.serializeAssertions pathCond values))
    |> Result.bind (fun smt2 ->
      solver.CheckSat smt2
      |> Result.bind parseSolverStatus
      |> Result.bind (function
        | SolverStatus.Sat when List.isEmpty values ->
          Ok { Status = SolverStatus.Sat; Values = [] }
        | SolverStatus.Sat ->
          solver.GetModels smt2
          |> Result.bind (SolverOutputParser.extract values)
        | SolverStatus.Unsat ->
          Ok { Status = SolverStatus.Unsat; Values = [] }
        | SolverStatus.Unknown ->
          Ok { Status = SolverStatus.Unknown; Values = [] }))

  let createSolver (opts: SymbRunOptions) =
    match opts.Solver with
    | NoSolver -> None
    | CustomSolver solver ->
      Some
        { CheckSat = fun pathCond -> checkSmt2 solver pathCond
          GetModels = fun query -> getModelsSmt2 solver query }

  let isRunTimeoutReached (stopwatch: Stopwatch) (opts: SymbRunOptions) =
    match opts.RunTimeout with
    | timeout when timeout > 0
                && stopwatch.ElapsedMilliseconds >= int64 timeout ->
      Some timeout
    | _ -> None

  let isMaxDepthReached depth (opts: SymbRunOptions) =
    match opts.MaxDepth with
    | limit when limit > 0 && depth >= limit -> Some limit
    | _ -> None

  let isStateLimitReached count (opts: SymbRunOptions) =
    match opts.MaxStates with
    | limit when limit > 0 && count >= limit -> Some limit
    | _ -> None

  let tryGetVisitCount addr visits =
    Map.tryFind addr visits |> Option.defaultValue 0

  let tryUpdateVisitCount addr visits (opts: SymbRunOptions) =
    let count = tryGetVisitCount addr visits
    match opts.LoopBound with
    | limit when limit > 0 && count >= limit -> Error limit
    | _ -> Ok(Map.add addr (count + 1) visits)

  let checkPathFeasibility (solver: SymbSolverRunner option) addr
                           (opts: SymbRunOptions) (st: SymbState) =
    if opts.PruneInfeasiblePaths then
      match solver with
      | Some solver ->
        match solver.CheckSat st.PathCondition with
        | Ok SolverStatus.Unsat -> Error(InfeasiblePath addr)
        | Ok SolverStatus.Sat | Ok SolverStatus.Unknown -> Ok()
        | Error e -> Error(SolverPruningFailed(addr, e))
      | None -> Ok()
    else Ok()

  let isUnknownStop = function
    | StoppedAtCall _
    | DepthLimitReached _
    | StateLimitReached _
    | InvalidInstructionStopped _
    | SideEffectStopped _
    | EvaluationFailed _
    | MissingSolverForQuery _
    | SolverQueryFailed _
    | RunTimeoutReached _ -> true

  let isUnknownPrune = function
    | AvoidedAddress _
    | AvoidedState _
    | InfeasiblePath _ -> false
    | LoopBoundReached _
    | SolverPruningFailed _ -> true

  let makeUnknown stopped pruned =
    let failures =
      (stopped
       |> List.choose (fun (st, reason) ->
         if isUnknownStop reason then Some(Stopped(st, reason))
         else None))
      @
      (pruned
       |> List.choose (fun (st, reason) ->
         if isUnknownPrune reason then Some(Pruned(st, reason))
         else None))
    if List.isEmpty failures then None
    else Some(SymbRunResult.Unknown(List.rev failures))

  let finishReachabilityRun answers stopped pruned =
    match List.rev answers with
    | _ :: _ as answers -> SymbRunResult.Reachable answers
    | [] ->
      match makeUnknown stopped pruned with
      | Some result -> result
      | None -> SymbRunResult.Unreachable

  let finishSatisfiabilityRun answers stopped pruned =
    match List.rev answers with
    | _ :: _ as answers -> SymbRunResult.Satisfiable answers
    | [] ->
      match makeUnknown stopped pruned with
      | Some result -> result
      | None -> SymbRunResult.Unsatisfiable

  let finishRun (opts: SymbRunOptions) reachAnswers satAnswers stopped pruned =
    match opts.Query with
    | ReachAddress _
    | ReachState _ -> finishReachabilityRun reachAnswers stopped pruned
    | SatisfyAddress _
    | SatisfyState _ -> finishSatisfiabilityRun satAnswers stopped pruned

  let solveReachabilityQuery (solver: SymbSolverRunner option) addr pathCond =
    match solver, pathCond with
    | None, [] -> QueryReachable
    | None, _ -> QueryUnknown(MissingSolverForQuery addr)
    | Some solver, _ ->
      match solver.CheckSat pathCond with
      | Ok SolverStatus.Sat -> QueryReachable
      | Ok SolverStatus.Unsat -> QueryUnsat(InfeasiblePath addr)
      | Ok SolverStatus.Unknown ->
        SolverFailure SolverReturnedUnknown
        |> fun err -> QueryUnknown(SolverQueryFailed(addr, err))
      | Error e -> QueryUnknown(SolverQueryFailed(addr, e))

  let solveInputQuery (solver: SymbSolverRunner option) addr pathCond values =
    match solver, pathCond, values with
    | None, [], [] -> QuerySatisfiable []
    | None, _, _ -> QueryUnknown(MissingSolverForQuery addr)
    | Some solver, _, _ ->
      match solver.GetModels(pathCond, values) with
      | Ok output when output.Status = SolverStatus.Sat ->
        QuerySatisfiable output.Values
      | Ok output when output.Status = SolverStatus.Unsat ->
        QueryUnsat(InfeasiblePath addr)
      | Ok _ ->
        SolverFailure SolverReturnedUnknown
        |> fun err -> QueryUnknown(SolverQueryFailed(addr, err))
      | Error e -> QueryUnknown(SolverQueryFailed(addr, e))

  let makeStopPoint depth (st: SymbState) =
    let instruction =
      match tryGetLiftedInstruction st.PC with
      | Ok lifted -> Some lifted.Instruction
      | Error _ -> None
    { Address = st.PC
      InstructionCount = depth
      Instruction = instruction
      State = st }

  let tryFindAvoid depth (avoid: SymbAvoid) (st: SymbState) =
    let point = makeStopPoint depth st
    match avoid with
    | AvoidAddresses addrs when Set.contains point.Address addrs ->
      Some(AvoidedAddress point.Address)
    | AvoidAddresses _ -> None
    | AvoidState pred when pred point -> Some(AvoidedState point.Address)
    | AvoidState _ -> None

  let tryMatchUserQuery (query: SymbQuery) (point: SymbStopPoint) =
    match query with
    | ReachAddress target when point.Address = target ->
      Some MatchedReachabilityQuery
    | ReachAddress _ -> None
    | ReachState pred when pred point -> Some MatchedReachabilityQuery
    | ReachState _ -> None
    | SatisfyAddress target when point.Address = target ->
      Some MatchedSatisfiabilityQuery
    | SatisfyAddress _ -> None
    | SatisfyState pred when pred point -> Some MatchedSatisfiabilityQuery
    | SatisfyState _ -> None

  let solveMatchedUserQuery solver opts addr (st: SymbState) = function
    | MatchedReachabilityQuery ->
      solveReachabilityQuery solver addr st.PathCondition
    | MatchedSatisfiabilityQuery ->
      solveInputQuery solver addr st.PathCondition opts.QueryValues.QueryValues

  let trySolveUserQueryAtState solver opts depth (st: SymbState) =
    let point = makeStopPoint depth st
    let addr = point.Address
    tryMatchUserQuery opts.Query point
    |> Option.map (solveMatchedUserQuery solver opts addr st)

  let tryCheckDepthLimit opts item =
    let addr = item.State.PC
    match isMaxDepthReached item.Depth opts with
    | Some limit ->
      Stopped(item.State, DepthLimitReached(addr, limit))
      |> Error
    | None -> Ok item

  let tryUpdateVisitCountForItem opts item =
    let addr = item.State.PC
    match tryUpdateVisitCount addr item.Visits opts with
    | Error limit ->
      Pruned(item.State, LoopBoundReached(addr, limit))
      |> Error
    | Ok visits -> Ok visits

  let tryGetInstructionStmts addr ins =
    match liftCache.TryGetValue addr with
    | true, Ok lifted -> Ok lifted.Stmts
    | true, Error e -> Error e
    | false, _ ->
      tryLiftParsedInstruction ins
      |> cacheLiftResult addr
      |> Result.map (fun lifted -> lifted.Stmts)

  let rec evalStmtsFrom (st: SymbState) (stmts: Stmt[]) =
    let numStmts = Array.length stmts
    if st.StmtIdx >= numStmts then [ SymbEvaluator.Continue st ]
    elif st.IsInstrTerminated then
      if st.NeedToEvaluateIEMark then
        SymbEvaluator.evalStmt st stmts[numStmts - 1]
        |> evalSuccessor stmts
      else [ SymbEvaluator.Continue st ]
    else
      SymbEvaluator.evalStmt st stmts[st.StmtIdx]
      |> evalSuccessor stmts

  and evalSuccessor stmts = function
    | SymbEvaluator.Continue st -> evalStmtsFrom st stmts
    | SymbEvaluator.Fork(trueState, falseState) ->
      evalStmtsFrom trueState stmts @ evalStmtsFrom falseState stmts
    | SymbEvaluator.Stopped _ as stopped -> [ stopped ]
    | SymbEvaluator.EvalError _ as error -> [ error ]

  let evalInstr addr (st: SymbState) stmts =
    syncPC addr st
    st.PrepareInstrEval stmts
    evalStmtsFrom st stmts

  let evaluateInstruction (opts: SymbRunOptions) addr (st: SymbState) =
    match tryParseInstruction addr with
    | Error _ -> Error(InvalidInstructionStopped addr)
    | Ok ins ->
      match handleCallInstruction addr ins opts st with
      | StopBeforeInstruction reason -> Error reason
      | SkipInstruction successors -> Ok(false, successors)
      | EvaluateInstruction ->
        match tryGetInstructionStmts addr ins with
        | Error _ -> Error(InvalidInstructionStopped addr)
        | Ok stmts -> Ok(true, evalInstr addr st stmts)

  let tryStopOnRunTimeout stopwatch opts (worklist: Queue<_>) onTimeout () =
    match isRunTimeoutReached stopwatch opts with
    | Some timeout ->
      let item = worklist.Peek()
      onTimeout item timeout
      None
    | None -> Some()

  let tryDequeueNextItem (worklist: Queue<_>) = function
    | Some() -> worklist.Dequeue() |> Some
    | None -> None

  let tryAnswerUserQuery solver opts onQuery = function
    | Some item ->
      let st = item.State
      let addr = st.PC
      match trySolveUserQueryAtState solver opts item.Depth st with
      | Some result ->
        onQuery addr st result
        None
      | None -> Some item
    | None -> None

  let tryStopOnDepthLimit opts onFailure = function
    | Some item ->
      match tryCheckDepthLimit opts item with
      | Ok item -> Some item
      | Error failure ->
        onFailure failure
        None
    | None -> None

  let tryStopOnLoopLimit opts onFailure = function
    | Some item ->
      match tryUpdateVisitCountForItem opts item with
      | Ok visits -> Some(item, visits)
      | Error failure ->
        onFailure failure
        None
    | None -> None

  let handleRunFailure addStopped addPruned stopExploration = function
    | Stopped(st, (StateLimitReached _ as reason)) ->
      addStopped st reason
      stopExploration ()
    | Stopped(st, reason) -> addStopped st reason
    | Pruned(st, reason) -> addPruned st reason

  let run start (st: SymbState) (opts: SymbRunOptions) =
    warmUpLiftCache opts.WarmUpRanges
    let worklist = Queue<SymbRunWorkItem>()
    let stopwatch = Stopwatch.StartNew()
    let solver = createSolver opts
    let ctx = SymbRunContext.Init()
    let initialState = st.Clone()
    initialState.PC <- start
    let handleQuery addr (st: SymbState) = function
      | QueryReachable ->
        ctx.AddReachAnswer addr st
        if opts.StopAtFirstAnswer then ctx.Stop()
        else ()
      | QuerySatisfiable values ->
        ctx.AddSatAnswer addr st values
        if opts.StopAtFirstAnswer then ctx.Stop()
        else ()
      | QueryUnsat reason -> ctx.AddPruned st reason
      | QueryUnknown reason -> ctx.AddStopped st reason
    let enqueue checkedPathCondLen depth visits (st: SymbState) =
      let addr = st.PC
      if ctx.StopExploration then ()
      else
        match tryFindAvoid depth opts.Avoid st with
        | Some reason -> ctx.AddPruned st reason
        | None ->
          let pathCondLen = List.length st.PathCondition
          let shouldCheck =
            opts.PruneInfeasiblePaths
            && pathCondLen > checkedPathCondLen
          let pruning =
            if shouldCheck then
              checkPathFeasibility solver addr opts st
            else Ok()
          match pruning with
          | Error reason -> ctx.AddPruned st reason
          | Ok() ->
            match isStateLimitReached ctx.GeneratedStates opts with
            | Some limit ->
              ctx.AddStopped st (StateLimitReached limit)
              ctx.Stop()
            | None ->
              worklist.Enqueue
                { State = st
                  Depth = depth
                  Visits = visits
                  CheckedPathCondLen =
                    if shouldCheck then pathCondLen else checkedPathCondLen }
              ctx.MarkStateGenerated()
    let handleSuccessor addr checkedPathCondLen depth visits = function
      | SymbEvaluator.Continue st ->
        enqueue checkedPathCondLen (depth + 1) visits st
      | SymbEvaluator.Fork(trueState, falseState) ->
        enqueue checkedPathCondLen (depth + 1) visits trueState
        enqueue checkedPathCondLen (depth + 1) visits falseState
      | SymbEvaluator.Stopped(st, SymbEvaluator.SideEffectStop eff) ->
        ctx.AddStopped st (SideEffectStopped(addr, eff))
      | SymbEvaluator.EvalError e ->
        ctx.AddStopped st (EvaluationFailed(addr, e))
    let handleSuccessors item addr visits successors =
      successors
      |> List.iter
           (handleSuccessor addr item.CheckedPathCondLen item.Depth visits)
    let handleInstruction = function
      | None -> ()
      | Some(item, visits) ->
        let st = item.State
        let addr = st.PC
        match evaluateInstruction opts addr st with
        | Error reason -> ctx.AddStopped st reason
        | Ok(_, successors) ->
          handleSuccessors item addr visits successors
    let handleRunTimeout item timeout =
      ctx.AddStopped item.State (RunTimeoutReached timeout)
      ctx.MarkTimeout timeout
    let handleFailure =
      handleRunFailure ctx.AddStopped ctx.AddPruned ctx.Stop
    enqueue 0 0 Map.empty initialState
    while worklist.Count > 0 && not ctx.StopExploration do
      ()
      |> tryStopOnRunTimeout stopwatch opts worklist handleRunTimeout
      |> tryDequeueNextItem worklist
      |> tryAnswerUserQuery solver opts handleQuery
      |> tryStopOnDepthLimit opts handleFailure
      |> tryStopOnLoopLimit opts handleFailure
      |> handleInstruction
    let result =
      finishRun opts ctx.ReachAnswers ctx.SatAnswers
                ctx.StoppedStates ctx.PrunedStates
    match ctx.RunTimeout with
    | Some timeout -> SymbRunResult.TimedOut(timeout, result)
    | None -> result

  member _.CreateState() = initializeState 0UL defaultStateCreationOptions

  member _.CreateState options = initializeState 0UL options

  member _.Run(start, state, options) = run start state options

  member _.Run(start, state, calls, query: SymbQueryRequest, solver) =
    let options =
      { SymbRunOptions.Default(query, solver) with
          Calls = calls }
    run start state options

  interface IExecutor<SymbState,
                      ISymbMemory,
                      SymbExpr,
                      SymbRunOptions,
                      SymbRunResult> with

    member this.CreateState() = this.CreateState()

    member this.CreateState options = this.CreateState options

    member this.Run(start, state, options) = this.Run(start, state, options)
