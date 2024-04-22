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

open B2R2
open B2R2.MiddleEnd.ControlFlowGraph

/// The interface for building a function.
type IFunctionBuildable<'V,
                        'E,
                        'Abs,
                        'FnCtx,
                        'GlCtx when 'V :> IRBasicBlock<'Abs>
                                and 'V: equality
                                and 'E: equality
                                and 'Abs: null
                                and 'FnCtx :> IResettable
                                and 'GlCtx: (new: unit -> 'GlCtx)> =
  /// The current state of the function builder.
  abstract BuilderState: FunctionBuilderState

  /// Entry point of the function that is being built.
  abstract EntryPoint: Addr

  /// Return the operation mode of the function.
  abstract Mode: ArchOperationMode

  /// Return the current building context.
  abstract Context: CFGBuildingContext<'V, 'E, 'Abs, 'FnCtx, 'GlCtx>

  /// Authorize the function builder to start building the function. This will
  /// change the state of the function builder to `InProgress`, meaning that the
  /// same function will not be scheduled again, and a single worker will soon
  /// start building the function.
  abstract Authorize: unit -> unit

  /// Stop the current building process. This will change the state of the
  /// function builder to `Stopped`, meaning that this function can always be
  /// scheduled again later.
  abstract Stop: unit -> unit

  /// Finalize the function building process. This will change the state of the
  /// function builder to `Finished`, meaning that the function has been built
  /// successfully.
  abstract Finalize: unit -> unit

  /// Mark the state to be invalid. This means that there has been a fatal error
  /// while building the function.
  abstract Invalidate: unit -> unit

  /// Build the function CFG.
  abstract Build: unit -> CFGResult

  /// Remember that the callee and my function have a cyclic dependency in the
  /// call graph. This information is later used by the building strategy to
  /// resolve a deadlock caused by a no-return analysis.
  abstract AddCyclicDependency: calleeAddr: Addr -> unit

  /// Check if the function has a cyclic dependency with the given callee.
  abstract HasCyclicDependency: calleeAddr: Addr -> bool

  /// Reset the current state in order to rebuild the function from scratch.
  abstract Reset: unit -> unit

  /// Convert this builder to a function.
  abstract ToFunction: unit -> Function<'V, 'E, 'Abs>

and FunctionBuilderState =
  /// Initialized but not started.
  | Initialized
  /// Currently building.
  | InProgress
  /// Stopped and will be resumed later.
  | Stopped
  /// Error occurred so this builder is invalid. We can re-initalize this
  /// builder later, but converting this builder to a function will fail.
  | Invalid
  /// Finished building and everything has been valid.
  | Finished