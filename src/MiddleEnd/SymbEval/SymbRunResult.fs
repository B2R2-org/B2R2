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

/// Represents the result of a bounded symbolic execution run.
type SymbRunResult =
  { /// Answer to the query this run asked.
    Answer: SymbAnswer
    /// States that stopped before reaching a target, and why.
    StopReasons: (SymbState * SymbStopReason) list
    /// States discarded before further exploration, and why.
    PruneReasons: (SymbState * SymbPruneReason) list
    /// Number of states the run put on its worklist.
    StateCount: int
    /// Timeout that ended the run, when one did.
    Timeout: int option }
with
  /// Whether one or more states reached the requested target.
  member this.IsReachable =
    match this.Answer with
    | SymbAnswer.Reachable _ -> true
    | _ -> false

  /// Whether one or more concrete assignments reach the requested target.
  member this.IsSatisfiable =
    match this.Answer with
    | SymbAnswer.Satisfiable _ -> true
    | _ -> false

  /// Whether the run ran out of the time it was given.
  member this.IsTimedOut = Option.isSome this.Timeout

  /// Whether the run could settle the query neither way.
  member this.IsFailed =
    match this.Answer with
    | SymbAnswer.Unknown _ -> true
    | _ -> false

  /// Returns the first reason the query could not be settled, if any.
  member this.TryGetFailure() =
    match this.Answer with
    | SymbAnswer.Unknown(failure :: _) -> Some failure
    | _ -> None

  /// Positive answers to a reachability query, empty when there are none.
  member this.ReachabilityAnswers =
    match this.Answer with
    | SymbAnswer.Reachable answers -> answers
    | _ -> []

  /// Concrete-input answers to a satisfiability query, empty when there are
  /// none.
  member this.SatisfiabilityAnswers =
    match this.Answer with
    | SymbAnswer.Satisfiable answers -> answers
    | _ -> []

  /// Returns the first satisfiability answer, if any.
  member this.TryGetSatisfiabilityAnswer() =
    List.tryHead this.SatisfiabilityAnswers

  /// Returns the first satisfiability answer, or raises when there is none.
  member this.GetSatisfiabilityAnswer() =
    match this.TryGetSatisfiabilityAnswer() with
    | Some answer ->
      answer
    | None ->
      raise
        (System.InvalidOperationException
          $"Satisfiability answer is unavailable: {this.Answer}.")

/// Represents the answer to a bounded symbolic execution query.
and [<RequireQualifiedAccess>] SymbAnswer =
  /// One or more states reached the requested target.
  | Reachable of answers: SymbReachabilityAnswer list
  /// No state reached the requested target in the explored state space.
  | Unreachable
  /// One or more concrete assignments satisfy the requested target.
  | Satisfiable of answers: SymbSatisfiabilityAnswer list
  /// No concrete assignment satisfies the requested target.
  | Unsatisfiable
  /// The run could prove neither that a target is out of reach nor that it is
  /// reachable, for the reasons it carries.
  | Unknown of failures: SymbRunFailure list

/// Represents why a symbolic query could not be fully answered.
and [<RequireQualifiedAccess>] SymbRunFailure =
  /// A state stopped before it could reach a target.
  | Stopped of SymbState * SymbStopReason
  /// A state was pruned before it could reach a target.
  | Pruned of SymbState * SymbPruneReason

/// Represents one positive answer to a reachability query.
and SymbReachabilityAnswer =
  { /// Target address reached by this answer.
    Target: Addr
    /// State at the target address.
    State: SymbState }

/// Represents one concrete-input answer to a satisfiability query.
and SymbSatisfiabilityAnswer =
  { /// Target address reached by this answer.
    Target: Addr
    /// State at the target address.
    State: SymbState
    /// Concrete assignments for requested symbolic values.
    Values: SolverValue list }
with
  /// Concrete solver model for this satisfiability answer.
  member this.Model = SymbModel this.Values
