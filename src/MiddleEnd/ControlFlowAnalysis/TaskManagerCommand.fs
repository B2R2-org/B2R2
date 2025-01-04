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

/// Request messages for the task manager.
type TaskManagerCommand<'FnCtx,
                        'GlCtx when 'FnCtx :> IResettable
                                and 'FnCtx: (new: unit -> 'FnCtx)
                                and 'GlCtx: (new: unit -> 'GlCtx)> =
  /// Start building a CFG for a function at the given address using the given
  /// operation mode.
  | StartBuilding of Addr * ArchOperationMode
  /// Add a dependency between two functions.
  | AddDependency of caller: Addr
                   * callee: Addr
                   * ArchOperationMode
                   * AgentReplyChannel<BuildingCtxMsg<'FnCtx, 'GlCtx>>
  /// Report the result of a task.
  | ReportCFGResult of Addr * CFGResult
  /// Retrieve the non-returning status of a function.
  | GetNonReturningStatus of Addr * AgentReplyChannel<NonReturningStatus>
  /// Retrieve the building context of a function.
  | GetBuildingContext of
    Addr * AgentReplyChannel<BuildingCtxMsg<'FnCtx, 'GlCtx>>
  /// Get the next function of the given function address.
  | GetNextFunctionAddress of Addr * AgentReplyChannel<Addr option>
  /// Notify the manager that a new jump table entry is about to be recovered.
  /// The manager returns the decision about the next action.
  | NotifyJumpTableRecovery of
    fn: Addr * tbl: JmpTableInfo * AgentReplyChannel<JumpTableRecoveryDecision>
  /// Notify the manager that we found a bogus jump table entry. The manager
  /// returns whether the recovery should continue or not.
  | NotifyBogusJumpTableEntry of
    fn: Addr * tbl: Addr * idx: int * AgentReplyChannel<bool>
  /// Cancel the jump table recovery because we found that the indirect branch
  /// is not using a jump table.
  | CancelJumpTableRecovery of fn:Addr * ins: Addr * tbl: Addr
  /// Report jump entry recovery result (success only) to the manager. The
  /// manager will then decide whether to continue the analysis or not.
  | ReportJumpTableSuccess of
    fn: Addr * tbl: Addr * idx: int * next: Addr * AgentReplyChannel<bool>
  /// Access the global context with the accessor, which has a side effect.
  | AccessGlobalContext of accessor: ('GlCtx -> unit) * AgentReplyChannel<unit>
  /// Update global context.
  | UpdateGlobalContext of updater: ('GlCtx -> 'GlCtx)
