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

/// Represents the interface for building a function that the binary defines.
/// A function defined outside of the binary is only an IFunctionBuilder, as
/// there is nothing to build.
type ICFGBuildable<'FnCtx, 'GlCtx> =
  inherit IFunctionBuilder

  /// Returns the current building context.
  abstract Context: CFGBuildingContext<'FnCtx, 'GlCtx>

  /// Returns the currently pending DelayedBuilderRequest(s). This queue can
  /// only be populated when another builder wants to update the status of this
  /// builder while it is running. Note that this queue is not thread-safe, and
  /// thus, it should be accessed only by the task manager.
  abstract DelayedBuilderRequests: Queue<DelayedBuilderRequest>

  /// Gets or sets the current activation status of the function builder. The
  /// default value is Activated, and it can be initially set to Deactivated
  /// when the builder is created but not scheduled yet.
  abstract Activation: CFGBuilderActivation with get, set

  /// Authorizes the function builder to start building the function. This will
  /// change the state of the function builder to `InProgress`, meaning that the
  /// same function will not be scheduled again, and a single worker will soon
  /// start building the function.
  abstract Authorize: unit -> unit

  /// Stops the current building process. This will change the state of the
  /// function builder to `Stopped`, meaning that this function can always be
  /// scheduled again later.
  abstract Stop: unit -> unit

  /// Forcefully finishes the function building process because of a cyclic
  /// dependency. This will change the state of the function builder to
  /// `ForceFinished`, and the given information becomes what its callers know
  /// about it.
  abstract ForceFinish: CalleeInfo -> unit

  /// Marks the state to be `Verifying`. This means that the function builder is
  /// currently verifying the built function.
  abstract StartVerifying: unit -> unit

  /// Finalizes the function building process. This will change the state of the
  /// function builder to `Finished`, meaning that the function has been built
  /// successfully.
  abstract Finalize: unit -> unit

  /// Re-initializes the function builder. This will change the state of the
  /// function builder to `Initialized`, meaning that the function can be
  /// scheduled again. This can only be called during the post-recovery phase.
  abstract ReInitialize: unit -> unit

  /// Marks the state to be invalid. This means that there has been a fatal
  /// error while building the function.
  abstract Invalidate: unit -> unit

  /// Builds the function CFG using the given strategy.
  abstract Build: ICFGBuildingStrategy<'FnCtx, 'GlCtx> -> CFGResult

  /// Resets the current state in order to rebuild the function from scratch.
  /// The given provider resets the user context.
  abstract Reset: IContextProvidable<'FnCtx, 'GlCtx> -> unit

and CFGBuilderActivation =
  /// The builder has been once scheduled (i.e., activated).
  | Activated
  /// The builder has not been scheduled and built; it is waiting to be
  /// scheduled but may remain deactivated until then (e.g., when we are not
  /// interested in building this function at all).
  | Deactivated

/// Represents a strategy that defines how CFGActions are handled to build a
/// function. This interface will be accessed in parallel by multiple threads,
/// so every operation should be thread-safe. Note that a CFGBuildingContext,
/// including its 'FnCtx, is only accessed by one thread at a time: the worker
/// building the function, or the manager while nobody builds it. Other
/// functions learn about it only through CalleeStatus.
and ICFGBuildingStrategy<'FnCtx, 'GlCtx> =
  inherit IContextProvidable<'FnCtx, 'GlCtx>

  /// Returns the prioritizer that orders the CFG actions. Every action queue
  /// is fixed to it when created, so all actions of a function share one order.
  abstract ActionPrioritizer: IPrioritizable

  /// Returns the recovery targets to build.
  abstract RecoveryTargets: RecoveryTargets

  /// Handles every CFGAction generated for a function. Each action may discover
  /// a new basic block, add a new edge, etc. This function returns a CFGResult
  /// that indicates whether the function building should continue, postpone, or
  /// exit with an error.
  abstract OnAction:
       CFGBuildingContext<'FnCtx, 'GlCtx>
     * CFGActionQueue
     * CFGAction
    -> CFGResult

  /// Handles the creation of a new function builder.
  abstract OnCreate:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    -> unit

  /// Handles the end of the building, i.e., when all CFGActions are processed
  /// and CFGActionQueue is empty.
  abstract OnFinish:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    -> CFGResult

  /// Handles a cyclic dependency detected by the TaskManager. The array of
  /// dependent functions is passed as an argument, and this function returns
  /// the function builder that should be built first. When the given array is
  /// empty, this function will raise an exception.
  abstract OnCyclicDependency:
       (Addr * ICFGBuildable<'FnCtx, 'GlCtx>)[]
    -> ICFGBuildable<'FnCtx, 'GlCtx>

  /// Finds candidate functions to analyze based on the given list of function
  /// builders, once all function builders are done building. When it returns an
  /// empty array, it means that there are no candidates to analyze, and the
  /// recovery process is done.
  abstract FindCandidatesForPostProcessing: IFunctionBuilder[] -> Addr[]

/// Represents the recovery targets to build. This is used for filtering the
/// candidates to build, and it is defined as part of the strategy because some
/// strategies may want to build only a subset of the candidates.
and RecoveryTargets =
  | All
  | Specific of Addr[]