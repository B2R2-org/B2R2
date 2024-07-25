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
type CFGBuildingContext<'FnCtx,
                        'GlCtx when 'FnCtx :> IResettable
                                and 'GlCtx: (new: unit -> 'GlCtx)> = {
  /// The address of the function that is being built.
  FunctionAddress: Addr
  /// Function name.
  FunctionName: string
  /// Function operation mode (for ARM Thumb).
  FunctionMode: ArchOperationMode
  /// The binary handle.
  BinHandle: BinHandle
  /// Mapping from a program point to a vertex in the LowUIRCFG.
  Vertices: Dictionary<ProgramPoint, IVertex<LowUIRBasicBlock>>
  /// Mapping from a call edge to an abstracted vertex in the LowUIRCFG.
  AbsVertices: Dictionary<AbsCallEdge, IVertex<LowUIRBasicBlock>>
  /// The control flow graph in LowUIR.
  mutable CFG: LowUIRCFG
  /// The basic block factory.
  BBLFactory: BBLFactory
  /// Is this function a no-return function?
  mutable NonReturningStatus: NonReturningStatus
  /// Table for maintaining function call information of this function.
  CallTable: CallTable
  /// The set of visited BBL program points. This is to prevent visiting the
  /// same basic block multiple times when constructing the CFG.
  VisitedPPoints: HashSet<ProgramPoint>
  /// The action queue for the CFG building process.
  ActionQueue: CFGActionQueue
  /// The user-defined per-function context.
  mutable UserContext: 'FnCtx
  /// Is this an external function or not.
  IsExternal: bool
  /// The channel for accessing the state of the TaskManager.
  mutable ManagerChannel: IManagerAccessible<'FnCtx, 'GlCtx>
  /// Thread ID that is currently building this function.
  mutable ThreadID: int
}

/// Call edge from its callsite address to the callee's address. This is to
/// uniquely identify call edges for abstracted vertices. We create an abstract
/// vertex for each call instruction even though multiple call instructions may
/// target the same callee. The callee address can be None for an indirect call.
and AbsCallEdge = Addr * Addr option

/// The interface for accessing the state of the TaskManager.
and [<AllowNullLiteral>]
  IManagerAccessible<'FnCtx,
                     'GlCtx when 'FnCtx :> IResettable
                             and 'GlCtx: (new: unit -> 'GlCtx)> =
  /// Update the dependency between two functions.
  abstract UpdateDependency:
    caller: Addr * callee: Addr * ArchOperationMode -> unit

  /// Get the non-returning status of a function located at `addr`.
  abstract GetNonReturningStatus: addr: Addr -> NonReturningStatus

  /// Get the builder of a function located at `addr` if it is available (i.e.,
  /// not in progress and valid). If the function builder is not available,
  /// return None.
  abstract GetBuildingContext:
       addr: Addr
    -> BuildingCtxMsg<'FnCtx, 'GlCtx>

  /// Get the current user-defined global state of the TaskManager.
  abstract GetGlobalContext: accessor: ('GlCtx -> 'Res) -> 'Res

  /// Update the user-defined global state of the TaskManager.
  abstract UpdateGlobalContext: updater: ('GlCtx -> 'GlCtx) -> unit

/// Message containing the building context of a function.
and BuildingCtxMsg<'FnCtx,
                   'GlCtx when 'FnCtx :> IResettable
                           and 'GlCtx: (new: unit -> 'GlCtx)> =
  /// The building process is finished, and this is the final context.
  | FinalCtx of CFGBuildingContext<'FnCtx, 'GlCtx>
  /// The building process is still ongoing.
  | StillBuilding of CFGBuildingContext<'FnCtx, 'GlCtx>
  /// The building process failed.
  | FailedBuilding
