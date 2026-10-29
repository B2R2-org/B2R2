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

/// Represents the channel through which a function builder coordinates jump
/// table recovery with the TaskManager. Jump tables can be shared or overlapped
/// by multiple functions, so the TaskManager arbitrates them globally.
type IJumpTableChannel =
  /// Notifies the manager that a new jump table entry is about to be recovered,
  /// and gets the decision about what to do next.
  abstract NotifyRecovery:
       fnAddr: Addr
     * jmptbl: JmpTableInfo
    -> JumpTableRecoveryDecision

  /// Notifies the manager that a bogus jump table entry is found, and gets the
  /// decision whether to continue the analysis or not.
  abstract NotifyBogusEntry:
       fnAddr: Addr
     * tblAddr: Addr
     * idx: int
    -> bool

  /// Lets the manager know that the jump table recovery is canceled.
  abstract CancelRecovery:
       fnAddr: Addr
     * insAddr: Addr
     * tblAddr: Addr
    -> unit

  /// Reports the success of jump table entry recovery to the manager, and gets
  /// the decision whether to continue the analysis or not.
  abstract ReportSuccess:
       fnAddr: Addr
     * tblAddr: Addr
     * idx: int
     * potentialNextTarget: Addr
     * isFunctionPointerTable: bool
    -> bool

/// Represents a decision about what to do next in the jump table registration
/// process.
and JumpTableRecoveryDecision =
  /// Continue the recovery process.
  | GoRecovery
  /// Error occurred during the recovery process, but we can recover it, so
  /// reload the builder.
  | StopRecoveryButReload
  /// Stop the recovery process since this is a fatal error that we cannot
  /// handle.
  | StopRecoveryAndContinue
