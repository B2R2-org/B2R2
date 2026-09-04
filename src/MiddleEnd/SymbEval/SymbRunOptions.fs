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

open B2R2
open B2R2.MiddleEnd.Executor

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
    { opts with Calls = CallPolicy.register target hook opts.Calls }

  /// Registers call hooks and enables hook-based call handling.
  member opts.RegisterCallHooks hooks =
    { opts with Calls = CallPolicy.registerMany hooks opts.Calls }

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

/// Represents a solver backend used by SymbExecutor.
and SymbSolver =
  /// Do not use a solver.
  | NoSolver
  /// Use a caller-provided solver implementation.
  | CustomSolver of solver: ISolver
