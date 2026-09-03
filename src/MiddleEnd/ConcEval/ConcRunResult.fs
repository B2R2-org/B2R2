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

namespace B2R2.MiddleEnd.ConcEval

open B2R2

/// Represents the result of a concrete execution run.
type ConcRunResult =
  { /// Reasons why execution stopped.
    StopReasons: ConcStopReason list
    /// Final instruction address or program counter.
    FinalAddress: Addr
    /// Number of executed machine instructions.
    InstructionCount: int
    /// Final concrete executor state.
    State: ConcState }
with
  /// Returns true when execution stopped before the given address.
  member this.IsStoppedAtAddress addr =
    this.StopReasons
    |> List.exists (function
      | ConcStopReason.StoppedAtAddress stopped -> stopped = addr
      | _ -> false)

  /// Returns true when execution stopped after the given address.
  member this.IsStoppedAfterAddress addr =
    this.StopReasons
    |> List.exists (function
      | ConcStopReason.StoppedAfterAddress stopped -> stopped = addr
      | _ -> false)

  /// Returns true when execution stopped at a function return.
  member this.IsStoppedAtReturn =
    this.StopReasons |> List.exists (fun r -> r.IsStoppedAtReturn)

  /// Returns true when execution stopped after a function return.
  member this.IsStoppedAfterReturn =
    this.StopReasons |> List.exists (fun r -> r.IsStoppedAfterReturn)

  /// Returns true when execution stopped at a call instruction.
  member this.IsStoppedAtCall =
    this.StopReasons |> List.exists (fun r -> r.IsStoppedAtCall)

  /// Returns true when execution stopped at a side-effect statement.
  member this.IsStoppedAtSideEffect =
    this.StopReasons |> List.exists (fun r -> r.IsStoppedAtSideEffect)

  /// Returns true when execution reached the configured instruction limit.
  member this.IsInstructionLimitReached =
    this.StopReasons |> List.exists (fun r -> r.IsInstructionLimitReached)

  /// Returns true when a user-defined stop predicate ended the run.
  member this.IsUserStopConditionMet =
    this.StopReasons |> List.exists (fun r -> r.IsUserStopConditionMet)

  /// Returns true when execution stopped because it could not go on.
  member this.IsFailed =
    this.StopReasons |> List.exists (fun r -> r.IsFailure)

  /// Returns the first reason execution could not go on, if any.
  member this.TryGetFailure() =
    this.StopReasons |> List.tryFind (fun r -> r.IsFailure)
