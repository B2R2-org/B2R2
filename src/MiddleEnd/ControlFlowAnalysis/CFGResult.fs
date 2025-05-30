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

/// The result obtained from recovering a CFG.
type CFGResult =
  /// We have successfully handled the task, so move on to the next task.
  | MoveOn
  /// We have successfully handled the task, but we found the function's
  /// internal state has been changed, so we need to reload caller functions,
  /// too. This result is only used in the post-recovery phase.
  | MoveOnButReloadCallers of previousStatus: NonReturningStatus
  /// We need to postpone the current task because the current function depends
  /// on other function(s) that have not been recovered yet.
  | Wait
  /// We need to stop and reload the current task.
  | StopAndReload
  /// We need to stop the current task due to a fatal error.
  | FailStop of ErrorCase
