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
open B2R2.BinIR

/// Represents the reason why concrete execution stopped.
[<RequireQualifiedAccess>]
type ConcStopReason =
  /// Execution reached an address requested by a stop condition.
  | StoppedAtAddress of addr: Addr
  /// Execution completed an instruction at the requested address.
  | StoppedAfterAddress of addr: Addr
  /// Execution reached a function return.
  | StoppedAtReturn of addr: Addr
  /// Execution completed a function return.
  | StoppedAfterReturn of addr: Addr
  /// Execution reached a call instruction. The target may be unknown.
  | StoppedAtCall of callSite: Addr * target: Addr option
  /// Execution reached a side-effect statement.
  | StoppedAtSideEffect of addr: Addr * sideEffect: SideEffect
  /// Execution stopped because an undefined value was observed.
  | UndefinedValue of addr: Addr
  /// Execution reached the configured instruction limit.
  | InstructionLimitReached of addr: Addr * limit: int
  /// Evaluation failed with a B2R2 error case.
  | EvaluationError of addr: Addr * error: ErrorCase
  /// A user-defined stop predicate requested termination.
  | UserStopConditionMet of addr: Addr
  /// No instruction could be fetched or lifted at the given address.
  | InvalidInstructionAddress of addr: Addr
  /// A call could not be handled under the configured call policy. The target
  /// is absent when the call is indirect.
  | CallHandlingFailure of callSite: Addr * target: Addr option * reason: string
with
  /// Whether execution stopped because it could not go on, as opposed to
  /// stopping where it was asked to.
  member this.IsFailure =
    match this with
    | ConcStopReason.UndefinedValue _
    | ConcStopReason.EvaluationError _
    | ConcStopReason.InvalidInstructionAddress _
    | ConcStopReason.CallHandlingFailure _ -> true
    | _ -> false
