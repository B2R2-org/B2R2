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

/// Represents a symbolic execution avoid condition.
[<RequireQualifiedAccess>]
type SymbAvoidCondition =
  /// Discard states whose PC reaches the given address.
  | AvoidAddress of addr: Addr
  /// Discard states satisfying the given predicate.
  | AvoidWhen of predicate: StopPredicate<SymbState>

/// Represents a symbolic query evaluated by SymbExecutor.Run.
[<RequireQualifiedAccess>]
type SymbQuery =
  /// Ask whether execution can reach the given address.
  | ReachAddress of target: Addr
  /// Ask whether execution can reach a state satisfying the predicate.
  | ReachWhen of predicate: StopPredicate<SymbState>
  /// Ask for concrete symbolic-input values reaching the given address.
  | SatisfyAddress of target: Addr
  /// Ask for concrete symbolic-input values reaching a matching state.
  | SatisfyWhen of predicate: StopPredicate<SymbState>

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
/// Represents options for bounded symbolic execution.
type SymbRunOptions =
  { /// Call-handling policy.
    Calls: CallPolicy<SymbCallHook>
    /// Query to answer.
    Query: SymbQuery
    /// Symbolic values to extract for satisfiability queries.
    QueryValues: IQueryExpr
    /// Conditions on which to discard a state before exploring it further.
    AvoidConditions: SymbAvoidCondition list
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
    { Calls = CallPolicy.FollowDirectInternalCalls
      Query = query
      QueryValues = (QueryExpr.Empty :> IQueryExpr)
      AvoidConditions = []
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

  /// Adds one avoid condition, after the ones already configured.
  member opts.AddAvoidCondition condition =
    { opts with AvoidConditions = opts.AvoidConditions @ [ condition ] }

  /// Adds avoid conditions, after the ones already configured.
  member opts.AddAvoidConditions conditions =
    { opts with
        AvoidConditions = opts.AvoidConditions @ List.ofSeq conditions }

  /// Replaces the configured avoid conditions.
  member opts.WithAvoidConditions conditions =
    { opts with AvoidConditions = List.ofSeq conditions }

  /// Discards states whose PC reaches the given address.
  member opts.AvoidAddress addr =
    opts.AddAvoidCondition(SymbAvoidCondition.AvoidAddress addr)

  /// Discards states whose PC reaches any of the given addresses.
  member opts.AvoidAddresses addrs =
    addrs
    |> Seq.map SymbAvoidCondition.AvoidAddress
    |> opts.AddAvoidConditions

  /// Discards states satisfying the given predicate.
  member opts.AvoidWhen predicate =
    opts.AddAvoidCondition(SymbAvoidCondition.AvoidWhen predicate)

  /// Stops before evaluating call instructions.
  member opts.StopAtCalls() = { opts with Calls = CallPolicy.StopAtCalls }

  /// Follows direct internal calls without using external-call hooks.
  member opts.FollowDirectInternalCalls() =
    { opts with Calls = CallPolicy.FollowDirectInternalCalls }

  /// Uses a prepared call hook registry for external-call dispatch.
  member opts.WithCallHooks hooks =
    { opts with Calls = CallPolicy.UseCallHooks hooks }

  /// Registers a call hook and enables hook-based call handling.
  member opts.RegisterCallHook(target, hook) =
    let hooks =
      match opts.Calls with
      | CallPolicy.UseCallHooks hooks -> hooks
      | CallPolicy.StopAtCalls
      | CallPolicy.FollowDirectInternalCalls -> CallHookRegistry()
    { opts with
        Calls = CallPolicy.UseCallHooks(hooks.Register(target, hook)) }

  /// Registers call hooks and enables hook-based call handling.
  member opts.RegisterCallHooks hooks =
    let registry =
      match opts.Calls with
      | CallPolicy.UseCallHooks registry -> registry
      | CallPolicy.StopAtCalls
      | CallPolicy.FollowDirectInternalCalls -> CallHookRegistry()
    { opts with
        Calls = CallPolicy.UseCallHooks(registry.RegisterMany hooks) }

  /// Uses the given solver backend.
  member opts.WithSolver solver = { opts with Solver = solver }

  /// Enables solver-backed infeasible path pruning.
  member opts.EnablePathPruning() = { opts with PruneInfeasiblePaths = true }

  /// Disables solver-backed infeasible path pruning.
  member opts.DisablePathPruning() = { opts with PruneInfeasiblePaths = false }

  /// Stops exploration as soon as the first query answer is found.
  member opts.EnableStopAtFirstAnswer() = { opts with StopAtFirstAnswer = true }

  /// Continues exploration after finding a query answer.
  member opts.DisableStopAtFirstAnswer() =
    { opts with StopAtFirstAnswer = false }

  /// Uses the given half-open address ranges for pre-lifting.
  member opts.WithWarmUpRanges ranges = { opts with WarmUpRanges = ranges }

/// Represents a non-target state where exploration stopped.
[<RequireQualifiedAccess>]
type SymbStopReason =
  /// Exploration reached a call according to the configured call policy.
  | StoppedAtCall of callSite: Addr * target: Addr option
  /// Exploration reached the configured maximum path depth.
  | DepthLimitReached of addr: Addr * limit: int
  /// Exploration reached the configured maximum expanded-state count.
  | StateLimitReached of limit: int
  /// No instruction could be fetched or lifted at the given address.
  | InvalidInstructionAddress of addr: Addr
  /// Evaluation reached a LowUIR statement with architectural side effects.
  | StoppedAtSideEffect of addr: Addr * sideEffect: SideEffect
  /// Evaluation failed while executing the instruction at the given address.
  | EvaluationError of addr: Addr * error: SymbEvalError
  /// A query needed a solver, but none was available.
  | MissingSolverForQuery of addr: Addr
  /// Solver query failed at a matching state.
  | SolverQueryFailed of addr: Addr * error: SymbEvalError
  /// Exploration reached the configured run timeout.
  | RunTimeoutReached of timeout: int

/// Represents a state that was discarded before further exploration.
[<RequireQualifiedAccess>]
type SymbPruneReason =
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
with
  /// Whether this reason leaves the query's answer inconclusive, as opposed
  /// to the user asking for the path to die, or the solver proving it dead.
  member this.IsInconclusive =
    match this with
    | SymbPruneReason.LoopBoundReached _
    | SymbPruneReason.SolverPruningFailed _ -> true
    | _ -> false

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
[<RequireQualifiedAccess>]
type SymbRunFailure =
  /// A state stopped before it could reach a target.
  | Stopped of SymbState * SymbStopReason
  /// A state was pruned before it could reach a target.
  | Pruned of SymbState * SymbPruneReason

/// Represents the answer to a bounded symbolic execution query.
[<RequireQualifiedAccess>]
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
      | SymbRunResult.Satisfiable(answer :: _) ->
        answer
      | SymbRunResult.TimedOut(_, result) ->
        loop result
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
    mutable StoppedStates: (SymbState * SymbStopReason) list
    mutable PrunedStates: (SymbState * SymbPruneReason) list
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

  member ctx.Stop() = ctx.StopExploration <- true

  member ctx.MarkTimeout timeout =
    ctx.RunTimeout <- Some timeout
    ctx.Stop()

type private SymbQueryEvalResult =
  | QueryReachable
  | QuerySatisfiable of SolverValue list
  | QueryUnsat of SymbPruneReason
  | QueryUnknown of SymbStopReason

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
  | StopBeforeInstruction of SymbStopReason

/// What one run of the executor carries along: the solver it was given, the
/// options it was asked for, the answers and counts it accumulates as it goes,
/// and the states still waiting to be explored.
type private SymbRunKit =
  { Solver: SymbSolverRunner option
    Opts: SymbRunOptions
    Ctx: SymbRunContext
    Worklist: Queue<SymbRunWorkItem> }

/// Represents a symbolic executor over SymbEval's evaluation state.
type SymbExecutor(hdl: BinHandle) =
  let liftCache = LiftCache hdl
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

  let tryGetDirectTargetAddr (ins: IInstruction) =
    match ins.DirectBranchTarget() with
    | true, target -> Some target
    | false, _ -> None

  let tryGetConcreteReg rid (st: SymbState) =
    match st.TryGetReg rid with
    | ValueSome(Const bv) -> Some(bv.ToUInt64())
    | _ -> None

  let tryGetCallTargetAddr (ins: IInstruction) (st: SymbState) =
    match tryGetDirectTargetAddr ins with
    | Some target ->
      Some target
    | None ->
      match hdl.ISA with
      | MIPS ->
        let rid = MIPS.Register.R25 |> MIPS.Register.toRegID
        tryGetConcreteReg rid st
      | _ ->
        None

  let isInternalTarget target = hdl.File.IsValidAddr target

  let wordType = hdl.ISA.WordSize |> WordSize.toRegType

  let syncPC (addr: Addr) (st: SymbState) =
    st.SetReg(hdl.RegisterFactory.ProgramCounter,
              SymbExpr.Const(BitVector(addr, wordType)))

  let pushReturnAddress returnAddress (st: SymbState) =
    let accessor = SymbStateAccessor(hdl, st)
    accessor.TryPushToStack(accessor.WordValue returnAddress)
    |> Result.map ignore

  let popReturnAddress (st: SymbState) =
    let accessor = SymbStateAccessor(hdl, st)
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
    | Error e ->
      SymbEvaluator.EvalError e

  let dispatchCallHook callSite target returnAddress hook (st: SymbState) =
    let hookState = st.Clone()
    let ctx = CallContext.Create(hdl, callSite, target, returnAddress)
    match pushReturnAddress returnAddress hookState with
    | Error e ->
      [ SymbEvaluator.EvalError e ]
    | Ok() ->
      match hook ctx hookState with
      | Error e -> [ SymbEvaluator.EvalError e ]
      | Ok states -> states |> List.map (finishHookState returnAddress)

  let handleCallInstruction addr
                            (ins: IInstruction)
                            (opts: SymbRunOptions)
                            (st: SymbState) =
    if not ins.IsCall then
      EvaluateInstruction
    else
      let target = tryGetCallTargetAddr ins st
      match opts.Calls with
      | CallPolicy.StopAtCalls ->
        StopBeforeInstruction(SymbStopReason.StoppedAtCall(addr, target))
      | CallPolicy.FollowDirectInternalCalls ->
        match target with
        | Some target when isInternalTarget target ->
          EvaluateInstruction
        | _ ->
          let msg = "Cannot follow call without a concrete internal target."
          SymbEvaluator.EvalError(UnsupportedOperation msg)
          |> List.singleton
          |> SkipInstruction
      | CallPolicy.UseCallHooks hooks ->
        match target with
        | Some target ->
          match hooks.TryFind target with
          | Some hook ->
            let returnAddress = liftCache.FallThroughAddr(addr, ins.Length)
            dispatchCallHook addr target returnAddress hook st
            |> SkipInstruction
          | None when isInternalTarget target ->
            EvaluateInstruction
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
    try
      fn () |> Ok with
    | :? System.ArgumentException as ex ->
      SolverSerializationFailure ex.Message |> solverFailure
    | :? System.InvalidOperationException as ex ->
      SolverSerializationFailure ex.Message |> solverFailure

  let parseSolverStatus stdout =
    match SolverOutputParser.parseStatus stdout with
    | Ok status ->
      Ok status
    | Error(SolverFailure(SolverOutputParseFailure(msg, _))) ->
      SolverOutputParseFailure(msg, stdout) |> solverFailure
    | Error err ->
      Error err

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
    | NoSolver ->
      None
    | CustomSolver solver ->
      Some
        { CheckSat = fun pathCond -> checkSmt2 solver pathCond
          GetModels = fun query -> getModelsSmt2 solver query }

  let isRunTimeoutReached (stopwatch: Stopwatch) (opts: SymbRunOptions) =
    match opts.RunTimeout with
    | timeout when timeout > 0
                && stopwatch.ElapsedMilliseconds >= int64 timeout ->
      Some timeout
    | _ ->
      None

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

  let checkPathFeasibility (solver: SymbSolverRunner option)
                           addr
                           (opts: SymbRunOptions)
                           (st: SymbState) =
    if opts.PruneInfeasiblePaths then
      match solver with
      | Some solver ->
        match solver.CheckSat st.PathCondition with
        | Ok SolverStatus.Unsat -> Error(SymbPruneReason.InfeasiblePath addr)
        | Ok SolverStatus.Sat | Ok SolverStatus.Unknown -> Ok()
        | Error e -> Error(SymbPruneReason.SolverPruningFailed(addr, e))
      | None ->
        Ok()
    else
      Ok()

  (* A state that stopped was neither shown to reach a target nor shown unable
     to reach one, so every stop reason leaves the answer inconclusive; only a
     pruned state can have died for a reason that settles it. *)
  let makeUnknown stopped pruned =
    let stoppedFailures = stopped |> List.map SymbRunFailure.Stopped
    let prunedFailures =
      pruned
      |> List.filter (fun (_, reason: SymbPruneReason) -> reason.IsInconclusive)
      |> List.map SymbRunFailure.Pruned
    match stoppedFailures @ prunedFailures with
    | [] -> None
    | failures -> Some(SymbRunResult.Unknown(List.rev failures))

  let finishReachabilityRun answers stopped pruned =
    match List.rev answers with
    | _ :: _ as answers ->
      SymbRunResult.Reachable answers
    | [] ->
      match makeUnknown stopped pruned with
      | Some result -> result
      | None -> SymbRunResult.Unreachable

  let finishSatisfiabilityRun answers stopped pruned =
    match List.rev answers with
    | _ :: _ as answers ->
      SymbRunResult.Satisfiable answers
    | [] ->
      match makeUnknown stopped pruned with
      | Some result -> result
      | None -> SymbRunResult.Unsatisfiable

  let finishRun (opts: SymbRunOptions) reachAnswers satAnswers stopped pruned =
    match opts.Query with
    | SymbQuery.ReachAddress _
    | SymbQuery.ReachWhen _ ->
      finishReachabilityRun reachAnswers stopped pruned
    | SymbQuery.SatisfyAddress _
    | SymbQuery.SatisfyWhen _ ->
      finishSatisfiabilityRun satAnswers stopped pruned

  let solveReachabilityQuery (solver: SymbSolverRunner option) addr pathCond =
    match solver, pathCond with
    | None, [] ->
      QueryReachable
    | None, _ ->
      QueryUnknown(SymbStopReason.MissingSolverForQuery addr)
    | Some solver, _ ->
      match solver.CheckSat pathCond with
      | Ok SolverStatus.Sat ->
        QueryReachable
      | Ok SolverStatus.Unsat ->
        QueryUnsat(SymbPruneReason.InfeasiblePath addr)
      | Ok SolverStatus.Unknown ->
        let err = SolverFailure SolverReturnedUnknown
        QueryUnknown(SymbStopReason.SolverQueryFailed(addr, err))
      | Error e ->
        QueryUnknown(SymbStopReason.SolverQueryFailed(addr, e))

  let solveInputQuery (solver: SymbSolverRunner option) addr pathCond values =
    match solver, pathCond, values with
    | None, [], [] ->
      QuerySatisfiable []
    | None, _, _ ->
      QueryUnknown(SymbStopReason.MissingSolverForQuery addr)
    | Some solver, _, _ ->
      match solver.GetModels(pathCond, values) with
      | Ok output when output.Status = SolverStatus.Sat ->
        QuerySatisfiable output.Values
      | Ok output when output.Status = SolverStatus.Unsat ->
        QueryUnsat(SymbPruneReason.InfeasiblePath addr)
      | Ok _ ->
        let err = SolverFailure SolverReturnedUnknown
        QueryUnknown(SymbStopReason.SolverQueryFailed(addr, err))
      | Error e ->
        QueryUnknown(SymbStopReason.SolverQueryFailed(addr, e))

  let makeStopPoint depth (st: SymbState) =
    let instruction =
      match liftCache.TryParse st.PC with
      | Ok ins -> Some ins
      | Error _ -> None
    { Address = st.PC
      InstructionCount = depth
      Instruction = instruction
      State = st }

  let tryFindAvoid depth (opts: SymbRunOptions) (st: SymbState) =
    let point = makeStopPoint depth st
    opts.AvoidConditions
    |> List.tryPick (function
      | SymbAvoidCondition.AvoidAddress addr when addr = point.Address ->
        Some(SymbPruneReason.AvoidedAddress point.Address)
      | SymbAvoidCondition.AvoidWhen pred when pred.Invoke point ->
        Some(SymbPruneReason.AvoidedState point.Address)
      | _ ->
        None)

  let tryMatchUserQuery (query: SymbQuery) (point: StopPoint<SymbState>) =
    match query with
    | SymbQuery.ReachAddress target when point.Address = target ->
      Some MatchedReachabilityQuery
    | SymbQuery.ReachAddress _ ->
      None
    | SymbQuery.ReachWhen pred when pred.Invoke point ->
      Some MatchedReachabilityQuery
    | SymbQuery.ReachWhen _ ->
      None
    | SymbQuery.SatisfyAddress target when point.Address = target ->
      Some MatchedSatisfiabilityQuery
    | SymbQuery.SatisfyAddress _ ->
      None
    | SymbQuery.SatisfyWhen pred when pred.Invoke point ->
      Some MatchedSatisfiabilityQuery
    | SymbQuery.SatisfyWhen _ ->
      None

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
      let reason = SymbStopReason.DepthLimitReached(addr, limit)
      Error(SymbRunFailure.Stopped(item.State, reason))
    | None ->
      Ok item

  let tryUpdateVisitCountForItem opts item =
    let addr = item.State.PC
    match tryUpdateVisitCount addr item.Visits opts with
    | Error limit ->
      let reason = SymbPruneReason.LoopBoundReached(addr, limit)
      Error(SymbRunFailure.Pruned(item.State, reason))
    | Ok visits ->
      Ok visits

  let whileContinuing _ = function
    | SymbEvaluator.Continue st -> ValueSome st
    | _ -> ValueNone

  let rec evalStmtsFrom (st: SymbState) stmts =
    match StmtLoop.run SymbEvaluator.evalStmt whileContinuing st stmts with
    | Completed st ->
      [ SymbEvaluator.Continue st ]
    | Interrupted(SymbEvaluator.Fork(trueState, falseState)) ->
      evalStmtsFrom trueState stmts @ evalStmtsFrom falseState stmts
    | Interrupted outcome ->
      [ outcome ]

  let evalInstr addr (st: SymbState) stmts =
    syncPC addr st
    st.PrepareInstrEval stmts
    evalStmtsFrom st stmts

  let evaluateInstruction (opts: SymbRunOptions) addr (st: SymbState) =
    match liftCache.TryParse addr with
    | Error _ ->
      Error(SymbStopReason.InvalidInstructionAddress addr)
    | Ok ins ->
      match handleCallInstruction addr ins opts st with
      | StopBeforeInstruction reason ->
        Error reason
      | SkipInstruction successors ->
        Ok(false, successors)
      | EvaluateInstruction ->
        match liftCache.TryLift addr with
        | Error _ -> Error(SymbStopReason.InvalidInstructionAddress addr)
        | Ok lifted -> Ok(true, evalInstr addr st lifted.Stmts)

  let tryStopOnRunTimeout stopwatch opts (worklist: Queue<_>) onTimeout () =
    match isRunTimeoutReached stopwatch opts with
    | Some timeout ->
      let item = worklist.Peek()
      onTimeout item timeout
      None
    | None ->
      Some()

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
      | None ->
        Some item
    | None ->
      None

  let tryStopOnDepthLimit opts onFailure = function
    | Some item ->
      match tryCheckDepthLimit opts item with
      | Ok item ->
        Some item
      | Error failure ->
        onFailure failure
        None
    | None ->
      None

  let tryStopOnLoopLimit opts onFailure = function
    | Some item ->
      match tryUpdateVisitCountForItem opts item with
      | Ok visits ->
        Some(item, visits)
      | Error failure ->
        onFailure failure
        None
    | None ->
      None

  let handleRunFailure addStopped addPruned stopExploration = function
    | SymbRunFailure.Stopped(st,
                             (SymbStopReason.StateLimitReached _ as reason)) ->
      addStopped st reason
      stopExploration ()
    | SymbRunFailure.Stopped(st, reason) ->
      addStopped st reason
    | SymbRunFailure.Pruned(st, reason) ->
      addPruned st reason

  /// What an answered query means for the run: the answer is recorded, and
  /// where the run wanted only one it stops there. A path the solver calls
  /// unsatisfiable is pruned, and one it cannot decide is stopped.
  let answerQuery (kit: SymbRunKit) addr (st: SymbState) = function
    | QueryReachable ->
      kit.Ctx.AddReachAnswer addr st
      if kit.Opts.StopAtFirstAnswer then kit.Ctx.Stop() else ()
    | QuerySatisfiable values ->
      kit.Ctx.AddSatAnswer addr st values
      if kit.Opts.StopAtFirstAnswer then kit.Ctx.Stop() else ()
    | QueryUnsat reason ->
      kit.Ctx.AddPruned st reason
    | QueryUnknown reason ->
      kit.Ctx.AddStopped st reason

  /// Puts a state on the worklist unless something rules it out: it stands on
  /// a path being avoided, the solver finds its path condition infeasible, or
  /// the run has already generated as many states as it was allowed. The
  /// feasibility check costs a solver call, so it is made only where the path
  /// condition has actually grown since it was last checked.
  let enqueueState (kit: SymbRunKit) checkedPathCondLen depth visits st =
    let addr = (st: SymbState).PC
    if kit.Ctx.StopExploration then
      ()
    else
      match tryFindAvoid depth kit.Opts st with
      | Some reason ->
        kit.Ctx.AddPruned st reason
      | None ->
        let pathCondLen = List.length st.PathCondition
        let shouldCheck =
          kit.Opts.PruneInfeasiblePaths
          && pathCondLen > checkedPathCondLen
        let pruning =
          if shouldCheck then checkPathFeasibility kit.Solver addr kit.Opts st
          else Ok()
        match pruning with
        | Error reason ->
          kit.Ctx.AddPruned st reason
        | Ok() ->
          match isStateLimitReached kit.Ctx.GeneratedStates kit.Opts with
          | Some limit ->
            kit.Ctx.AddStopped st (SymbStopReason.StateLimitReached limit)
            kit.Ctx.Stop()
          | None ->
            kit.Worklist.Enqueue
              { State = st
                Depth = depth
                Visits = visits
                CheckedPathCondLen =
                  if shouldCheck then pathCondLen else checkedPathCondLen }
            kit.Ctx.MarkStateGenerated()

  /// Where one successor of an instruction goes: a plain one carries on a step
  /// deeper, a fork puts both sides on the worklist, and one that stopped or
  /// failed is recorded against the address it stopped at.
  ///
  /// A failed evaluation has no successor state to record, so it is charged to
  /// `callerState` -- the state handed to `run`, before it was cloned and moved
  /// to the starting address. That state is not the one the exploration began
  /// from and its PC is whatever the caller left it at; what it does offer is
  /// that nothing here mutates it, where the run's own initial state is
  /// advanced in place as the first path is walked.
  let handleSuccessor kit callerState addr item visits successor =
    let condLen = (item: SymbRunWorkItem).CheckedPathCondLen
    let depth = item.Depth + 1
    match successor with
    | SymbEvaluator.Continue st ->
      enqueueState kit condLen depth visits st
    | SymbEvaluator.Fork(trueState, falseState) ->
      enqueueState kit condLen depth visits trueState
      enqueueState kit condLen depth visits falseState
    | SymbEvaluator.Stopped(st, SymbEvaluator.SideEffectStop eff) ->
      let reason = SymbStopReason.StoppedAtSideEffect(addr, eff)
      (kit: SymbRunKit).Ctx.AddStopped st reason
    | SymbEvaluator.EvalError e ->
      let reason = SymbStopReason.EvaluationError(addr, e)
      kit.Ctx.AddStopped callerState reason

  /// One instruction taken off the worklist: evaluate it and route each
  /// successor, or record why it could not be evaluated at all. Nothing to do
  /// means an earlier step in the pipeline has already answered for this item.
  /// `callerState` is only passed through, for `handleSuccessor` to charge an
  /// evaluation failure to.
  let handleInstruction kit callerState = function
    | None ->
      ()
    | Some(item: SymbRunWorkItem, visits) ->
      let st = item.State
      let addr = st.PC
      match evaluateInstruction (kit: SymbRunKit).Opts addr st with
      | Error reason ->
        kit.Ctx.AddStopped st reason
      | Ok(_, successors) ->
        successors
        |> List.iter (handleSuccessor kit callerState addr item visits)

  let run start (st: SymbState) (opts: SymbRunOptions) =
    liftCache.WarmUp opts.WarmUpRanges
    let worklist = Queue<SymbRunWorkItem>()
    let stopwatch = Stopwatch.StartNew()
    let solver = createSolver opts
    let ctx = SymbRunContext.Init()
    let kit =
      { Solver = solver; Opts = opts; Ctx = ctx; Worklist = worklist }
    let initialState = st.Clone()
    initialState.PC <- start
    let handleRunTimeout item timeout =
      ctx.AddStopped item.State (SymbStopReason.RunTimeoutReached timeout)
      ctx.MarkTimeout timeout
    let handleFailure = handleRunFailure ctx.AddStopped ctx.AddPruned ctx.Stop
    enqueueState kit 0 0 Map.empty initialState
    while worklist.Count > 0 && not ctx.StopExploration do
      ()
      |> tryStopOnRunTimeout stopwatch opts worklist handleRunTimeout
      |> tryDequeueNextItem worklist
      |> tryAnswerUserQuery solver opts (answerQuery kit)
      |> tryStopOnDepthLimit opts handleFailure
      |> tryStopOnLoopLimit opts handleFailure
      |> handleInstruction kit st
    let result =
      finishRun opts
                ctx.ReachAnswers
                ctx.SatAnswers
                ctx.StoppedStates
                ctx.PrunedStates
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
                      IMemory<SymbExpr>,
                      SymbExpr,
                      SymbRunOptions,
                      SymbRunResult> with

    member this.CreateState() = this.CreateState()

    member this.CreateState options = this.CreateState options

    member this.Run(start, state, options) = this.Run(start, state, options)
