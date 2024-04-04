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
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowGraph

/// The context for building a control flow graph. A user-defined state can be
/// stored in the context, too.
type CFGBuildingContext<'V,
                        'E,
                        'Abs,
                        'State,
                        'Req,
                        'Res when 'V :> IRBasicBlock<'Abs>
                              and 'V: equality
                              and 'E: equality
                              and 'Abs: null
                              and 'State :> IResettable> = {
  /// The binary handle.
  BinHandle: BinHandle
  /// The control flow graph.
  mutable CFG: IRCFG<'V, 'E, 'Abs>
  /// The basic block factory.
  BBLFactory: BBLFactory<'Abs>
  /// The call instructions encountered so far. Callsite (call instruction)
  /// address to its callee kind.
  Calls: SortedList<Addr, CalleeKind>
  /// The user-defined state.
  State: 'State
  /// The channel for accessing the state of the TaskManager.
  ManagerState: IManagerState<'Req, 'Res>
  /// Thread ID that is currently building this function.
  mutable ThreadID: int
}

/// What kind of callee is this?
and CalleeKind =
  /// Callee is a regular function.
  | RegularCallee of Addr
  /// Callee is a syscall of the given number.
  | SyscallCallee of number: int
  /// Callee is a set of indirect call targets. This means potential callees
  /// have been analyzed already.
  | IndirectCallees of Set<Addr>
  /// Callee (call target) is unresolved yet. This eventually will become
  /// IndirectCallees after indirect call analyses.
  | UnresolvedIndirectCallees
  /// There can be "call 0" to call an external function. This pattern is
  /// typically observed by object files, but sometimes we do see this pattern
  /// in regular executables, e.g., GNU libc.
  | NullCallee

/// The state of the TaskManager.
and IManagerState<'Req, 'Res> =
  inherit IStateQueryable<'Req, 'Res>
  inherit IStateUpdatable
