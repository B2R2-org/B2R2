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

namespace B2R2.MiddleEnd.SymEval

open System.Collections.Generic
open System.Diagnostics
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.Executor

/// Represents a symbolic execution point inspected by SymExecutor queries.
type SymStopPoint =
  { /// Address of the symbolic state.
    Address: Addr
    /// Number of instructions executed before reaching the state.
    InstructionCount: int
    /// Symbolic state at the stop point.
    State: SymState }

/// Represents a symbolic query evaluated by SymExecutor.Run.
type SymQuery =
  /// Ask whether execution can reach the given address.
  | ReachAddress of target: Addr
  /// Ask whether execution can reach a state satisfying the predicate.
  | ReachState of predicate: (SymStopPoint -> bool)
  /// Ask for concrete symbolic-input values reaching the given address.
  | SatisfyAddress of target: Addr
  /// Ask for concrete symbolic-input values reaching a matching state.
  | SatisfyState of predicate: (SymStopPoint -> bool)

/// Represents a solver backend used by SymExecutor.
type SymSolver =
  /// Do not use a solver.
  | NoSolver
  /// Use the default Z3 command-line solver.
  | Z3
  /// Use a caller-provided solver implementation.
  | CustomSolver of solver: ISolver

/// Represents options for bounded symbolic execution.
type SymRunOptions =
  { /// Query to answer.
    Query: SymQuery
    /// Symbolic values to extract for satisfiability queries.
    Values: SymExpr list
    /// Instruction addresses to discard before execution.
    Avoid: Set<Addr>
    /// Maximum instructions to execute per path. Zero means unlimited.
    MaxDepth: int
    /// Maximum number of states to expand. Zero means unlimited.
    MaxStates: int
    /// Maximum visits allowed at the same address. Zero means unlimited.
    LoopBound: int
    /// Solver backend used for path queries and optional pruning.
    Solver: SymSolver
    /// Maximum milliseconds for each solver query. Zero uses solver default.
    SolverTimeout: int
    /// Maximum milliseconds to spend in Run. Zero means unlimited.
    RunTimeout: int
    /// Enable solver-backed infeasible path pruning.
    PruneInfeasiblePaths: bool }

/// Represents a non-target state where exploration stopped.
type SymRunStopReason =
  /// Exploration reached the configured maximum path depth.
  | DepthLimitReached of addr: Addr * limit: int
  /// Exploration reached the configured maximum expanded-state count.
  | StateLimitReached of limit: int
  /// No instruction could be fetched or lifted at the given address.
  | InvalidInstructionStopped of addr: Addr
  /// Evaluation reached a LowUIR statement with architectural side effects.
  | SideEffectStopped of addr: Addr * sideEffect: SideEffect
  /// Evaluation failed while executing the instruction at the given address.
  | EvaluationFailed of addr: Addr * error: SymEvalError
  /// A query needed a solver, but none was available.
  | MissingSolverForQuery of addr: Addr
  /// Solver query failed at a matching state.
  | SolverQueryFailed of addr: Addr * error: SymEvalError
  /// Exploration reached the configured run timeout.
  | RunTimeoutReached of timeout: int

/// Represents a state that was discarded before further exploration.
type SymRunPruneReason =
  /// The state reached an avoided instruction address.
  | AvoidedAddress of addr: Addr
  /// The state exceeded the per-path loop bound.
  | LoopBoundReached of addr: Addr * limit: int
  /// The solver proved the state's path condition unsatisfiable.
  | InfeasiblePath of addr: Addr
  /// Solver pruning failed while checking the state's path condition.
  | SolverPruningFailed of addr: Addr * error: SymEvalError

/// Represents one positive answer to a reachability query.
type SymReachabilityAnswer =
  { /// Target address reached by this answer.
    Target: Addr
    /// State at the target address.
    State: SymState }

/// Represents one concrete-input answer to a satisfiability query.
type SymSatisfiabilityAnswer =
  { /// Target address reached by this answer.
    Target: Addr
    /// State at the target address.
    State: SymState
    /// Concrete assignments for requested symbolic values.
    Values: SolverValue list }

/// Represents why a symbolic query could not be fully answered.
type SymRunFailure =
  /// A state stopped before it could reach a target.
  | Stopped of SymState * SymRunStopReason
  /// A state was pruned before it could reach a target.
  | Pruned of SymState * SymRunPruneReason

/// Represents the answer to a bounded symbolic execution query.
type SymRunResult =
  /// One or more states reached the requested target.
  | Reachable of SymReachabilityAnswer list
  /// No state reached the requested target in the explored state space.
  | Unreachable
  /// One or more concrete assignments satisfy the requested target.
  | Satisfiable of SymSatisfiabilityAnswer list
  /// No concrete assignment satisfies the requested target.
  | Unsatisfiable
  /// Execution could not prove satisfiability or unsatisfiability.
  | Unknown of SymRunFailure list
  /// Execution timed out and produced the given partial result.
  | TimedOut of timeout: int * result: SymRunResult

type private SymRunWorkItem =
  { State: SymState
    Depth: int
    Visits: Map<Addr, int> }

type private SymQueryEvalResult =
  | QueryReachable
  | QuerySatisfiable of SolverValue list
  | QueryUnsat of SymRunPruneReason
  | QueryUnknown of SymRunStopReason

type private SymSolverRunner =
  { CheckSat: SymExpr list -> Result<SolverStatus, SymEvalError>
    GetValues: SymExpr list * SymExpr list -> Result<SolverOutput, SymEvalError> }

/// Represents a symbolic executor over SymEval's evaluation state.
type SymExecutor(hdl: BinHandle) =
  let lifter = hdl.NewLiftingUnit()

  let createState = function
    | EmptyMemory -> SymState()
    | PreinitializedMemory mem -> SymState mem
    | BinSectionBackedMemory -> SymState(BinSectionSymMemory hdl)

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

  let getSolverTimeout (opts: SymRunOptions) =
    if opts.SolverTimeout > 0 then opts.SolverTimeout
    else Z3Solver.DefaultTimeout

  let getRemainingRunTimeout (stopwatch: Stopwatch) (opts: SymRunOptions) =
    match opts.RunTimeout with
    | timeout when timeout > 0 ->
      Some(max 0 (timeout - int stopwatch.ElapsedMilliseconds))
    | _ -> None

  let getZ3Timeout stopwatch opts =
    match getRemainingRunTimeout stopwatch opts with
    | Some remaining -> min (getSolverTimeout opts) remaining |> max 1
    | None -> getSolverTimeout opts

  let createZ3Runner stopwatch opts =
    { CheckSat = fun pathCond ->
        let timeout = getZ3Timeout stopwatch opts
        let solver = Z3Solver { Z3Solver.DefaultOptions with Timeout = timeout }
        solver.CheckSat pathCond
      GetValues = fun (pathCond, values) ->
        let timeout = getZ3Timeout stopwatch opts
        let solver = Z3Solver { Z3Solver.DefaultOptions with Timeout = timeout }
        solver.GetValues(pathCond, values) }

  let createSolver (stopwatch: Stopwatch) (opts: SymRunOptions) =
    match opts.Solver with
    | NoSolver -> None
    | Z3 -> createZ3Runner stopwatch opts |> Some
    | CustomSolver solver ->
      Some
        { CheckSat = fun pathCond -> solver.CheckSat pathCond
          GetValues = fun (pathCond, values) ->
            solver.GetValues(pathCond, values) }

  let isRunTimeoutReached (stopwatch: Stopwatch) (opts: SymRunOptions) =
    match opts.RunTimeout with
    | timeout when timeout > 0
                && stopwatch.ElapsedMilliseconds >= int64 timeout ->
      Some timeout
    | _ -> None

  let isMaxDepthReached depth (opts: SymRunOptions) =
    match opts.MaxDepth with
    | limit when limit > 0 && depth >= limit -> Some limit
    | _ -> None

  let isStateLimitReached count (opts: SymRunOptions) =
    match opts.MaxStates with
    | limit when limit > 0 && count >= limit -> Some limit
    | _ -> None

  let tryGetVisitCount addr visits =
    Map.tryFind addr visits |> Option.defaultValue 0

  let tryEnterAddress addr visits (opts: SymRunOptions) =
    let count = tryGetVisitCount addr visits
    match opts.LoopBound with
    | limit when limit > 0 && count >= limit -> Error limit
    | _ -> Ok(Map.add addr (count + 1) visits)

  let checkPathFeasibility (solver: SymSolverRunner option) addr
                           (opts: SymRunOptions) (st: SymState) =
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
    else Some(SymRunResult.Unknown(List.rev failures))

  let finishReachabilityRun answers stopped pruned =
    match List.rev answers with
    | _ :: _ as answers -> SymRunResult.Reachable answers
    | [] ->
      match makeUnknown stopped pruned with
      | Some result -> result
      | None -> SymRunResult.Unreachable

  let finishSatisfiabilityRun answers stopped pruned =
    match List.rev answers with
    | _ :: _ as answers -> SymRunResult.Satisfiable answers
    | [] ->
      match makeUnknown stopped pruned with
      | Some result -> result
      | None -> SymRunResult.Unsatisfiable

  let finishRun (opts: SymRunOptions) reachAnswers satAnswers stopped pruned =
    match opts.Query with
    | ReachAddress _
    | ReachState _ -> finishReachabilityRun reachAnswers stopped pruned
    | SatisfyAddress _
    | SatisfyState _ -> finishSatisfiabilityRun satAnswers stopped pruned

  let solveReachabilityQuery (solver: SymSolverRunner option) addr pathCond =
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

  let solveInputQuery (solver: SymSolverRunner option) addr pathCond values =
    match solver, pathCond, values with
    | None, [], [] -> QuerySatisfiable []
    | None, _, _ -> QueryUnknown(MissingSolverForQuery addr)
    | Some solver, _, _ ->
      match solver.GetValues(pathCond, values) with
      | Ok output when output.Status = SolverStatus.Sat ->
        QuerySatisfiable output.Values
      | Ok output when output.Status = SolverStatus.Unsat ->
        QueryUnsat(InfeasiblePath addr)
      | Ok _ ->
        SolverFailure SolverReturnedUnknown
        |> fun err -> QueryUnknown(SolverQueryFailed(addr, err))
      | Error e -> QueryUnknown(SolverQueryFailed(addr, e))

  let makeStopPoint depth (st: SymState) =
    { Address = st.PC
      InstructionCount = depth
      State = st }

  let trySolveAtState (solver: SymSolverRunner option) (opts: SymRunOptions)
                      depth (st: SymState) =
    let point = makeStopPoint depth st
    let addr = point.Address
    match opts.Query with
    | ReachAddress target when addr = target ->
      Some(solveReachabilityQuery solver addr st.PathCondition)
    | ReachAddress _ -> None
    | ReachState pred when pred point ->
      Some(solveReachabilityQuery solver addr st.PathCondition)
    | ReachState _ -> None
    | SatisfyAddress target when addr = target ->
      Some(solveInputQuery solver addr st.PathCondition opts.Values)
    | SatisfyAddress _ -> None
    | SatisfyState pred when pred point ->
      Some(solveInputQuery solver addr st.PathCondition opts.Values)
    | SatisfyState _ -> None

  let rec evalStmtsFrom (st: SymState) (stmts: Stmt[]) =
    let numStmts = Array.length stmts
    if st.StmtIdx >= numStmts then [ SymEvaluator.Continue st ]
    elif st.IsInstrTerminated then
      if st.NeedToEvaluateIEMark then
        SymEvaluator.evalStmt st stmts[numStmts - 1]
        |> evalSuccessor stmts
      else [ SymEvaluator.Continue st ]
    else
      SymEvaluator.evalStmt st stmts[st.StmtIdx]
      |> evalSuccessor stmts

  and evalSuccessor stmts = function
    | SymEvaluator.Continue st -> evalStmtsFrom st stmts
    | SymEvaluator.Fork(trueState, falseState) ->
      evalStmtsFrom trueState stmts @ evalStmtsFrom falseState stmts
    | SymEvaluator.Stopped _ as stopped -> [ stopped ]
    | SymEvaluator.EvalError _ as error -> [ error ]

  let evalInstr (st: SymState) stmts =
    st.PrepareInstrEval stmts
    evalStmtsFrom st stmts

  let run start (st: SymState) (opts: SymRunOptions) =
    let worklist = Queue<SymRunWorkItem>()
    let stopwatch = Stopwatch.StartNew()
    let solver = createSolver stopwatch opts
    let initialState = st.Clone()
    initialState.PC <- start
    worklist.Enqueue
      { State = initialState
        Depth = 0
        Visits = Map.empty }
    let mutable reachAnswers: SymReachabilityAnswer list = []
    let mutable satAnswers: SymSatisfiabilityAnswer list = []
    let mutable stoppedStates: (SymState * SymRunStopReason) list = []
    let mutable prunedStates: (SymState * SymRunPruneReason) list = []
    let mutable exploredStates = 0
    let mutable stopExploration = false
    let mutable runTimeout = None
    let addStopped (st: SymState) reason =
      stoppedStates <- (st, reason) :: stoppedStates
    let addPruned (st: SymState) reason =
      prunedStates <- (st, reason) :: prunedStates
    let addReachAnswer target (st: SymState) =
      reachAnswers <- { Target = target; State = st } :: reachAnswers
    let addSatAnswer target (st: SymState) values =
      satAnswers <- { Target = target; State = st; Values = values }
                    :: satAnswers
    let handleQuery addr (st: SymState) = function
      | QueryReachable -> addReachAnswer addr st
      | QuerySatisfiable values -> addSatAnswer addr st values
      | QueryUnsat reason -> addPruned st reason
      | QueryUnknown reason -> addStopped st reason
    let enqueue depth visits (st: SymState) =
      let addr = st.PC
      match checkPathFeasibility solver addr opts st with
      | Ok() ->
        worklist.Enqueue
          { State = st
            Depth = depth
            Visits = visits }
      | Error reason -> addPruned st reason
    let handleSuccessor addr depth visits = function
      | SymEvaluator.Continue st -> enqueue (depth + 1) visits st
      | SymEvaluator.Fork(trueState, falseState) ->
        enqueue (depth + 1) visits trueState
        enqueue (depth + 1) visits falseState
      | SymEvaluator.Stopped(st, SymEvaluator.SideEffectStop eff) ->
        addStopped st (SideEffectStopped(addr, eff))
      | SymEvaluator.EvalError e ->
        addStopped st (EvaluationFailed(addr, e))
    while worklist.Count > 0 && not stopExploration do
      match isRunTimeoutReached stopwatch opts with
      | Some timeout ->
        let item = worklist.Peek()
        addStopped item.State (RunTimeoutReached timeout)
        runTimeout <- Some timeout
        stopExploration <- true
      | None ->
        let item = worklist.Dequeue()
        let st = item.State
        let addr = st.PC
        if Set.contains addr opts.Avoid then addPruned st (AvoidedAddress addr)
        else
          match trySolveAtState solver opts item.Depth st with
          | Some result -> handleQuery addr st result
          | None ->
            match isStateLimitReached exploredStates opts with
            | Some limit ->
              addStopped st (StateLimitReached limit)
              stopExploration <- true
            | None ->
              match isMaxDepthReached item.Depth opts with
              | Some limit ->
                addStopped st (DepthLimitReached(addr, limit))
              | None ->
                match tryEnterAddress addr item.Visits opts with
                | Error limit -> addPruned st (LoopBoundReached(addr, limit))
                | Ok visits ->
                  match tryParseInstruction addr with
                  | Error _ ->
                    addStopped st (InvalidInstructionStopped addr)
                  | Ok ins ->
                    match tryLiftInstruction ins with
                    | Error _ ->
                      addStopped st (InvalidInstructionStopped addr)
                    | Ok stmts ->
                      exploredStates <- exploredStates + 1
                      evalInstr st stmts
                      |> List.iter (handleSuccessor addr item.Depth visits)
    let result = finishRun opts reachAnswers satAnswers stoppedStates prunedStates
    match runTimeout with
    | Some timeout -> SymRunResult.TimedOut(timeout, result)
    | None -> result

  member _.CreateState() = SymState()

  member _.CreateState options = initializeState 0UL options

  member _.Run(start, state, options) = run start state options

  interface IExecutor<SymState,
                      ISymMemory,
                      SymExpr,
                      SymRunOptions,
                      SymRunResult> with

    member this.CreateState() = this.CreateState()

    member this.CreateState options = this.CreateState options

    member this.Run(start, state, options) = this.Run(start, state, options)
