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
  /// Function name.
  FunctionName: string
  /// The binary handle.
  BinHandle: BinHandle
  /// Mapping from a program point to a vertex in the IRCFG.
  Vertices: Dictionary<ProgramPoint, IVertex<'V>>
  /// Mapping from a call edge to an abstracted vertex in the IRCFG.
  AbsVertices: Dictionary<AbsCallEdge, IVertex<'V>>
  /// The control flow graph.
  mutable CFG: IRCFG<'V, 'E, 'Abs>
  /// The basic block factory.
  BBLFactory: BBLFactory<'Abs>
  /// Is this function a no-return function?
  mutable NonReturningStatus: NonReturningStatus
  /// Table for maintaining function call information of this function.
  CallTable: CallTable
  /// Function summary, which is available only after finalizing the CFG.
  mutable Summary: 'Abs
  /// The set of visited BBL program points. This is to prevent visiting the
  /// same basic block multiple times when constructing the CFG.
  VisitedPPoints: HashSet<ProgramPoint>
  /// The user-defined per-function context.
  UserContext: 'FnCtx
  /// Is this an external function or not.
  IsExternal: bool
  /// The channel for accessing the state of the TaskManager.
  ManagerChannel: IManagerAccessible<'V, 'E, 'Abs, 'FnCtx, 'GlCtx>
  /// Thread ID that is currently building this function.
  mutable ThreadID: int
}

/// Call edge from its callsite address to the callee's address. This is to
/// uniquely identify call edges for abstracted vertices. We create an abstract
/// vertex for each call instruction even though multiple call instructions may
/// target the same callee.
and AbsCallEdge = Addr * Addr

/// The result of non-returning function analysis.
and NonReturningStatus =
  /// This function will never return. For example, the "exit" function should
  /// have this property.
  | NoRet
  /// Regular case: *not* no-return.
  | NotNoRet
  /// Conditionally no-return; function does not return only if the n-th
  /// argument (starting from one) specified is non-zero.
  | ConditionalNoRet of int
  /// We don't know yet: we need further analyses.
  | UnknownNoRet

/// The interface for accessing the state of the TaskManager.
and [<AllowNullLiteral>]
  IManagerAccessible<'V,
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

  /// Get the non-returning status of a function located at `addr`.
  abstract GetNonReturningStatus: addr: Addr -> NonReturningStatus

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
