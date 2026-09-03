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
open B2R2.BinIR

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
