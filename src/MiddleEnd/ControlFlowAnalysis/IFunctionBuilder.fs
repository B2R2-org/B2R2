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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open System.Collections.Generic
open B2R2

/// Represents what the CFG recovery keeps for every function, whether it builds
/// the function or the function is defined outside of the binary.
type IFunctionBuilder =
  inherit ILinkage

  /// Returns the current state of the function builder.
  abstract BuilderState: CFGBuilderState

  /// Returns the entry point of the function.
  abstract EntryPoint: Addr

  /// Gets or sets the address of the next function if there is any. Otherwise,
  /// this is None.
  abstract NextFunctionAddress: Addr option with get, set

  /// Returns the functions that call this function, which the manager fills in
  /// once the recovery is over.
  abstract Callers: HashSet<Addr>

  /// Returns what the callers of this function need to know about it, as of
  /// when the builder last finished. Other functions read this snapshot rather
  /// than the building context, which only the building thread may touch.
  abstract CalleeInfo: CalleeInfo

  /// Converts this builder to a function.
  abstract ToFunction: unit -> Function

and CFGBuilderState =
  /// Initialized but not started.
  | Initialized
  /// Currently building.
  | InProgress
  /// Stopped and will be resumed later.
  | Stopped
  /// Error occurred so this builder is invalid. We can re-authorize this
  /// builder later, but converting this builder to a function will fail.
  | Invalid
  /// Forcefully finished due to cyclic dependency. This builder has a
  /// under-approximated CFG because every unknown callee is considered
  /// non-returning.
  | ForceFinished
  /// Waiting for the builder to be finalized, while performing some
  /// verification.
  | Verifying
  /// Finished building and everything has been valid.
  | Finished
