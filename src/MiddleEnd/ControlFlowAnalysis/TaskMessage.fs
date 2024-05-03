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

/// A kind of messages to be handled by TaskManager.
type TaskMessage<'V,
                 'E,
                 'FnCtx,
                 'GlCtx when 'V :> IRBasicBlock
                         and 'V: equality
                         and 'E: equality
                         and 'FnCtx :> IResettable
                         and 'GlCtx: (new: unit -> 'GlCtx)> =
  /// Add an address to recover the CFG.
  | AddTask of Addr * ArchOperationMode
  /// Add a dependency between two functions.
  | AddDependency of caller: Addr * callee: Addr * mode: ArchOperationMode
  /// Report the result of a task.
  | ReportResult of Addr * CFGResult
  /// Retrieve the non-returning status of a function.
  | RetrieveNonReturningStatus of Addr * AgentReplyChannel<NonReturningStatus>
  /// Retrieve the building context of a function.
  | RetrieveBuildingContext of
      Addr * AgentReplyChannel<BuildingCtxMsg<'V, 'E, 'FnCtx, 'GlCtx>>
  /// Access the global context with the accessor, which has a side effect.
  | AccessGlobalContext of accessor: ('GlCtx -> unit) * AgentReplyChannel<unit>
  /// Update global context.
  | UpdateGlobalContext of updater: ('GlCtx -> 'GlCtx)
