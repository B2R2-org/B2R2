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
