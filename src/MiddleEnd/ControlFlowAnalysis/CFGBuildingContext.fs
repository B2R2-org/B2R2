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
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// The context for building a control flow graph of a function. This exists per
/// function, and it can include a user-defined, too.
type CFGBuildingContext<'V,
                        'E,
                        'Abs,
                        'FnCtx,
                        'GlCtx when 'V :> IRBasicBlock<'Abs>
                                and 'V: equality
                                and 'E: equality
                                and 'Abs: null
                                and 'FnCtx :> IResettable
                                and 'GlCtx: (new: unit -> 'GlCtx)> = {
  /// The address of the function that is being built.
  FunctionAddress: Addr
  /// The binary handle.
  BinHandle: BinHandle
  /// Mapping from a program point to a vertex in the IRCFG.
  Vertices: Dictionary<ProgramPoint, IVertex<'V>>
  /// The control flow graph.
  mutable CFG: IRCFG<'V, 'E, 'Abs>
  /// The basic block factory.
  BBLFactory: BBLFactory<'Abs>
  /// Is this function a no-return function?
  mutable IsNoRet: bool
  /// The callees of this function. This is a mapping from a callsite (call
  /// instruction) address to its callee kind.
  Callees: SortedList<Addr, CalleeKind>
  /// The callers of this function.
  Callers: HashSet<Addr>
  /// The calling nodes (which terminate a basic block with a call instruction)
  /// in this function. This is a mapping from a callee address to its calling
  /// nodes.
  CallingNodes: Dictionary<Addr, HashSet<IVertex<'V>>>
  /// The user-defined per-function context.
  UserContext: 'FnCtx
  /// The channel for accessing the state of the TaskManager.
  ManagerChannel: IManagerAccessible<'V, 'E, 'Abs, 'FnCtx, 'GlCtx>
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

/// The interface for accessing the state of the TaskManager.
and IManagerAccessible<'V,
                       'E,
                       'Abs,
                       'FnCtx,
                       'GlCtx when 'V :> IRBasicBlock<'Abs>
                               and 'V: equality
                               and 'E: equality
                               and 'Abs: null
                               and 'FnCtx :> IResettable
                               and 'GlCtx: (new: unit -> 'GlCtx)> =
  /// Update the dependency between two functions.
  abstract UpdateDependency:
    caller: Addr * callee: Addr * ArchOperationMode -> unit

  /// Get the builder of a function located at `addr` if it is available (i.e.,
  /// not in progress and valid). If the function builder is not available,
  /// return None.
  abstract GetBuildingContext:
       addr: Addr
    -> BuildingCtxMsg<'V, 'E, 'Abs, 'FnCtx, 'GlCtx>

  /// Get the current user-defined global state of the TaskManager.
  abstract GetGlobalContext: accessor: ('GlCtx -> 'Res) -> 'Res

  /// Update the user-defined global state of the TaskManager.
  abstract UpdateGlobalContext: updater: ('GlCtx -> 'GlCtx) -> unit

/// Message containing the building context of a function.
and BuildingCtxMsg<'V,
                   'E,
                   'Abs,
                   'FnCtx,
                   'GlCtx when 'V :> IRBasicBlock<'Abs>
                           and 'V: equality
                           and 'E: equality
                           and 'Abs: null
                           and 'FnCtx :> IResettable
                           and 'GlCtx: (new: unit -> 'GlCtx)> =
  /// The building process is finished, and this is the final context.
  | FinalCtx of CFGBuildingContext<'V, 'E, 'Abs, 'FnCtx, 'GlCtx>
  /// The building process is still ongoing.
  | StillBuilding
  /// The building process failed.
  | FailedBuilding
