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
type ICFGBuildable<'FnCtx,
                   'GlCtx when 'FnCtx :> IResettable
                           and 'FnCtx: (new: unit -> 'FnCtx)
                           and 'GlCtx: (new: unit -> 'GlCtx)> =
  inherit ILinkage

  /// The current state of the function builder.
  abstract BuilderState: CFGBuilderState

  /// Entry point of the function that is being built.
  abstract EntryPoint: Addr

  /// Return the operation mode of the function.
  abstract Mode: ArchOperationMode

  /// Return the current building context.
  abstract Context: CFGBuildingContext<'FnCtx, 'GlCtx>

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

  /// Build the function CFG using the given strategy.
  abstract Build: ICFGBuildingStrategy<'FnCtx, 'GlCtx> -> CFGResult

  /// Reset the current state in order to rebuild the function from scratch.
  abstract Reset: LowUIRCFG.IConstructable -> unit

  /// Make a new builder with a new agent by copying the current one.
  abstract MakeNew:
       Agent<TaskMessage<'FnCtx, 'GlCtx>>
    -> ICFGBuildable<'FnCtx, 'GlCtx>

  /// Convert this builder to a function.
  abstract ToFunction: unit -> Function

and CFGBuilderState =
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

/// A strategy that defines how CFGActions are handled to build a function. This
/// interface will be accessed in parallel by multiple threads, so every
/// operation should be thread-safe. Note that CFGBuildingContext as well as
/// 'FnCtx are only accessed by a single thread, though.
and ICFGBuildingStrategy<'FnCtx,
                         'GlCtx when 'FnCtx :> IResettable
                                 and 'FnCtx: (new: unit -> 'FnCtx)
                                 and 'GlCtx: (new: unit -> 'GlCtx)> =
  /// Return the prioritizer to use for the CFG actions.
  abstract ActionPrioritizer: IPrioritizable

  /// This is a callback that is called when a recovery mission starts. It finds
  /// a list of candidate functions to analyze based on the given list of
  /// function builders.
  abstract FindCandidates:
    ICFGBuildable<'FnCtx, 'GlCtx>[] -> (Addr * ArchOperationMode)[]

  /// This is a callback that is called for every CFGAction generated for a
  /// function. Each action may discover a new basic block, add a new edge, etc.
  /// This function returns a CFGResult that indicates whether the function
  /// building should continue, postpone, or exit with an error.
  abstract OnAction:
       CFGBuildingContext<'FnCtx, 'GlCtx>
     * CFGActionQueue
     * CFGAction
    -> CFGResult

  /// This is a callback that is called when all CFGActions are processed, i.e.,
  /// when CFGActionQueue is empty.
  abstract OnFinish:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    -> CFGResult

  /// This is a callback that is called when a cyclic dependency is detected
  /// from the TaskManager. The array of dependent functions is passed as an
  /// argument, and this function returns the function builder that should be
  /// built first. When the given array is empty, this function will raise an
  /// exception.
  abstract OnCyclicDependency:
       (Addr * ICFGBuildable<'FnCtx, 'GlCtx>)[]
    -> ICFGBuildable<'FnCtx, 'GlCtx>
