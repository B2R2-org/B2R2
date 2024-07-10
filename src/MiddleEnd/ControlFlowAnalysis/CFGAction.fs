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
  | InitiateCFG of fnAddr: Addr * mode: ArchOperationMode
  /// Add more reachable edges to the initial CFG using the new program points.
  | ExpandCFG of fnAddr: Addr * mode: ArchOperationMode * addrs: seq<Addr>
  /// Create an abstract call node and connect it to the caller and fallthrough
  /// nodes when necessary.
  | MakeCall of fnAddr: Addr * ArchOperationMode * caller: Addr * callee: Addr
  /// Create an abstract tail-call node and connect it to the caller and
  /// fallthrough nodes when necessary.
  | MakeTlCall of fnAddr: Addr * ArchOperationMode * caller: Addr * callee: Addr
  /// Create an abstract call node for an indirect call and connect it to the
  /// caller and the fallthrough node.
  | MakeIndCall of fnAddr: Addr * ArchOperationMode * caller: Addr
  /// Create an abstract syscall node and connect it to the caller and
  /// fallthrough nodes when necessary.
  | MakeSyscall of fnAddr: Addr * ArchOperationMode * caller: Addr * exit: bool
  | IndirectEdge of IRBasicBlock
  | SyscallEdge of IRBasicBlock
  | JumpTableEntryStart of IRBasicBlock * Addr * Addr
  | JumpTableEntryEnd of IRBasicBlock * Addr * Addr
with
  /// The priority of the action. Higher values mean higher priority.
  member this.Priority (p: IPrioritizable) = p.GetPriority this

/// Interface for setting the priority of an action.
and IPrioritizable =
  /// Get the priority of the action. A higher value means higher priority.
  abstract GetPriority: CFGAction -> int

