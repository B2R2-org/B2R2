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

/// Our CFG reconstruction algorithm is performed by consuming actions
/// (CFGAction). Each action has a priority, which is used to determine the
/// order of the actions to run.
type CFGAction =
  /// Build an initial CFG that is reachable from the given function start
  /// address.
  | InitiateCFG
  /// Add more reachable edges to the initial CFG using the new program points.
  | ExpandCFG of addrs: seq<Addr>
  /// Create an abstract call node and connect it to the caller and fallthrough
  /// nodes when necessary.
  | MakeCall of callSite: Addr * callee: Addr * CalleeInfo
  /// Create an abstract tail-call node and connect it to the caller and
  /// fallthrough nodes when necessary.
  | MakeTlCall of callSite: Addr * callee: Addr * CalleeInfo
  /// Create an abstract call node for an indirect call and connect it to the
  /// caller and the fallthrough node.
  | MakeIndCall of callSite: Addr
  /// Create an abstract syscall node and connect it to the caller and
  /// fallthrough nodes when necessary.
  | MakeSyscall of callSite: Addr * exit: bool
  /// Create edges for an indirect branch. We find the possible targets of the
  /// indirect branch and connect them with the given basic block.
  | MakeIndEdges of bbl: Addr * ins: Addr
  /// Wait for the callee to be resolved.
  | WaitForCallee of calleeAddr: Addr
  /// Start recovering a jump table entry (only single entry at a time).
  | StartTblRec of tbl: JmpTableInfo * idx: int * src: Addr * dst: Addr
  /// Report the recovery result of a jump table entry. This will always be
  /// followed by a `StartTblRec` action to denote the end of the recovery.
  | EndTblRec of tbl: JmpTableInfo * idx: int
with
  /// The priority of the action. Higher values mean higher priority.
  member this.Priority (p: IPrioritizable) = p.GetPriority this

/// Callee's abstract information.
and CalleeInfo = NonReturningStatus * int

/// Interface for setting the priority of an action.
and IPrioritizable =
  /// Get the priority of the action. A higher value means higher priority.
  abstract GetPriority: CFGAction -> int

