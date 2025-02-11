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
open B2R2.MiddleEnd.DataFlow

/// The context for building a control flow graph of a function. This exists per
/// function, and it can include a user-defined context, too.
type CFGBuildingContext<'FnCtx,
                        'GlCtx when 'FnCtx :> IResettable
                                and 'FnCtx: (new: unit -> 'FnCtx)
                                and 'GlCtx: (new: unit -> 'GlCtx)> = {
  /// The address of the function that is being built.
  FunctionAddress: Addr
  /// Function name.
  FunctionName: string
  /// Function operation mode (for ARM Thumb).
  FunctionMode: ArchOperationMode
  /// The binary handle.
  BinHandle: BinHandle
  /// The exception information of the binary.
  ExnInfo: ExceptionInfo
  /// Mapping from a program point to a vertex in the LowUIRCFG.
  Vertices: Dictionary<ProgramPoint, IVertex<LowUIRBasicBlock>>
  /// The control flow graph in LowUIR.
  mutable CFG: LowUIRCFG
  /// The state of constant propagation.
  CPState: VarBasedDataFlowState<ConstantDomain.Lattice>
  /// The basic block factory.
  BBLFactory: BBLFactory
  /// Is this function a no-return function?
  mutable NonReturningStatus: NonReturningStatus
  /// Which jump table entry is currently being recovered? (table addr, index)
  JumpTableRecoveryStatus: Stack<Addr * int>
  /// Jump tables associated with this function.
  JumpTables: List<JmpTableInfo>
  /// Table for maintaining intra-function call information of this function.
  IntraCallTable: IntraCallTable
  /// Set of callers of this function.
  Callers: HashSet<Addr>
  /// The set of visited BBL program points. This is to prevent visiting the
  /// same basic block multiple times when constructing the CFG.
  VisitedPPoints: HashSet<ProgramPoint>
  /// The action queue for the CFG building process.
  ActionQueue: CFGActionQueue
  /// Pending call-edge connection actions (e.g., MakeCall, MakeTlCall, etc) for
  /// each callee address. This is to remember the actions that are waiting for
  /// the callee to be built.
  PendingCallActions: Dictionary<Addr, List<CFGAction>>
  /// From a call site of a caller vertex to the caller vertex itself.
  CallerVertices: Dictionary<Addr, IVertex<LowUIRBasicBlock>>
  /// The number of unwinding bytes of the stack when this function returns.
  mutable UnwindingBytes: int
  /// The user-defined per-function context.
  mutable UserContext: 'FnCtx
  /// Is this an external function or not.
  IsExternal: bool
  /// The channel for accessing the state of the TaskManager.
  mutable ManagerChannel: IManagerAccessible<'FnCtx, 'GlCtx>
  /// Thread ID that is currently building this function.
  mutable ThreadID: int
}
with
  /// Reset the context to its initial state.
  member __.Reset cfg =
    __.Vertices.Clear ()
    __.CFG <- cfg
    if isNull __.CPState then () else __.CPState.Reset ()
    (* N.B. We should keep the value of `NonReturningStatus` (i.e., leave the
       below line commented out) because we should be able to compare the
       difference before/after rebuilding the CFG. *)
    (* __.NonReturningStatus <- UnknownNoRet *)
    __.JumpTableRecoveryStatus.Clear ()
    __.JumpTables.Clear ()
    __.IntraCallTable.Reset ()
    __.Callers.Clear ()
    __.VisitedPPoints.Clear ()
    __.ActionQueue.Clear ()
    __.PendingCallActions.Clear ()
    __.CallerVertices.Clear ()
    __.UnwindingBytes <- 0
    __.UserContext.Reset ()

  /// Scan basic blocks starting from the given entry points. This function
  /// returns a sequence of divided edges created by discovering new basic
  /// blocks. By discovering new basic blocks, existing blocks can be divided
  /// into multiple blocks.
  member __.ScanBBLs mode entryPoints =
    __.BBLFactory.ScanBBLs (mode, entryPoints)
    |> Async.AwaitTask
    |> Async.RunSynchronously

  member private __.UpdateDictionary (dict: Dictionary<_, _>) k v delta =
    match dict.TryGetValue k with
    | true, (sum, _) -> dict[k] <- (sum + delta, v)
    | false, _ -> dict[k] <- (delta, v)

  /// Search for the first overlapping vertex in the CFG by reverse traversing
  /// the vertices. Since there can be many vertices beyond the range of the
  /// current function, we should return the first one (with the smallest
  /// addrress).
  member private __.FindFunctionOverlap lst nextFnAddr idx res =
    if idx = 0 then
#if DEBUG
      (* This is a fatal error when our function identification or noreturn
         analysis failed. *)
      System.Console.Error.WriteLine
        $"{__.FunctionAddress:x} overlapped with {nextFnAddr:x}"
      Utils.impossible ()
#else
      None (* Ignore this error in release mode. *)
#endif
    else
      let _, v = (lst: SortedList<_, _ * IVertex<LowUIRBasicBlock>>).Values[idx]
      if v.VData.Internals.Range.Max >= nextFnAddr then
        __.FindFunctionOverlap lst nextFnAddr (idx - 1) v
      elif isNull res then None
      else Some res

  /// Find the first overlapping vertex in the CFG. We consider two cases: (1)
  /// two vertices share the same address, or (2) a vertex is beyond the range
  /// of the current function. If there's no such an overlap, return None.
  ///
  /// This function will check for the first case by traversing the vertices in
  /// the ascending order of addresses. This is crucial for the correctness of
  /// the rollback mechanism as we need to figure out which vertex is causing
  /// the overlap. Since we run this function after fully over-appriximating the
  /// CFG, we can assume that the first overlapping vertex is the problematic
  /// one.
  ///
  /// We then check the second case by assuming that the current function's
  /// boundary is determined by the next function's address. If there's a vertex
  /// that is located beyond the boundary, we consider it as an overlap.
  ///
  /// This function will return only the first overlapping vertex even though
  /// there may be multiple overlapping vertices.
  member __.FindOverlap (nextFnAddrOpt) =
    let vertices = __.CFG.Vertices
    let dict = Dictionary (vertices.Length * 2)
    for v in vertices do
      let vData = v.VData.Internals
      if not vData.IsAbstract && vData.PPoint.Position = 0 then
        let range = v.VData.Internals.Range
        __.UpdateDictionary dict range.Min v 1
        __.UpdateDictionary dict (range.Max + 1UL) v -1
      else ()
    let lst = SortedList dict
    let enumerator = lst.GetEnumerator ()
    let mutable hasOverlap = false
    let mutable overlapVertex = null
    let mutable sum = 0
    while not hasOverlap && enumerator.MoveNext () do
      let (delta, v) = enumerator.Current.Value
      sum <- sum + delta
      if sum > 1 then
        hasOverlap <- true
        overlapVertex <- v
      else ()
    if hasOverlap then Some overlapVertex
    else
      match nextFnAddrOpt with
      | Some nextFnAddr ->
        __.FindFunctionOverlap lst nextFnAddr (lst.Count - 1) null
      | None -> None

  member private __.AddOrIgnore acc gapStart gapEnd =
    match __.ScanBBLs __.FunctionMode [ gapStart ] with
    | Ok _dividedEdges ->
      let bbl = __.BBLFactory.Find <| ProgramPoint (gapStart, 0)
      if bbl.Internals.Range.Max > gapEnd then acc
      else (AddrRange (gapStart, gapEnd)) :: acc
    | Error _ -> acc

  [<TailCall>]
  member private __.FindGap acc fnEnd gapAddr ranges =
    match ranges with
    | [] ->
      if gapAddr < fnEnd then __.AddOrIgnore acc gapAddr fnEnd
      else acc
    | (range: AddrRange) :: tl ->
      if gapAddr < range.Min then
        let acc = __.AddOrIgnore acc gapAddr (range.Min - 1UL)
        __.FindGap acc fnEnd (range.Max + 1UL) tl
      elif gapAddr >= range.Min && gapAddr <= range.Max then
        __.FindGap acc fnEnd (range.Max + 1UL) tl
      else acc

  /// Find a gap between the current function and the next function. This
  /// function finds every gap between the current function and the next
  /// function. If there are multiple gaps, return all of them.
  member __.AnalyzeGap (nextFnAddrOpt) =
    match nextFnAddrOpt with
    | Some nextFnAddr ->
      let endAddr = nextFnAddr - 1UL
      __.CFG.Vertices
      |> Array.fold (fun acc v ->
        if v.VData.Internals.IsAbstract then acc
        else v.VData.Internals.Range :: acc) []
      |> List.sortBy (fun r -> r.Min)
      |> __.FindGap [] endAddr __.FunctionAddress
      |> List.rev
    | None -> []

/// Call edge from its callsite address to the callee's address. This is to
/// uniquely identify call edges for abstracted vertices. We create an abstract
/// vertex for each call instruction even though multiple call instructions may
/// target the same callee. The callee address can be None for an indirect call.
and AbsCallEdge = Addr * Addr option

/// The interface for accessing the state of the TaskManager.
and [<AllowNullLiteral>]
  IManagerAccessible<'FnCtx,
                     'GlCtx when 'FnCtx :> IResettable
                             and 'FnCtx: (new: unit -> 'FnCtx)
                             and 'GlCtx: (new: unit -> 'GlCtx)> =
  /// Update the dependency between two functions and return the current
  /// building context of the callee.
  abstract AddDependency:
       caller: Addr
     * callee: Addr
     * ArchOperationMode
    -> BuildingCtxMsg<'FnCtx, 'GlCtx>

  /// Get the non-returning status of a function located at `addr`.
  abstract GetNonReturningStatus: addr: Addr -> NonReturningStatus

  /// Get the builder of a function located at `addr` if it is available (i.e.,
  /// not in progress and valid). If the function builder is not available,
  /// return None.
  abstract GetBuildingContext:
       addr: Addr
    -> BuildingCtxMsg<'FnCtx, 'GlCtx>

  /// Get the next function address of the given function address. If there's no
  /// next function, return None.
  abstract GetNextFunctionAddress: addr: Addr -> Addr option

  /// Notify the manager that a new jump table entry is about to be recovered,
  /// and get the decision about what to do next.
  abstract NotifyJumpTableRecovery:
       fnAddr: Addr
     * jmptbl: JmpTableInfo
    -> JumpTableRecoveryDecision

  /// Notify the manager that a bogus jump table entry is found, and get the
  /// decision whether to continue the analysis or not.
  abstract NotifyBogusJumpTableEntry:
       fnAddr: Addr
     * tblAddr: Addr
     * idx: int
    -> bool

  /// Let the manager know that the jump table recovery is canceled.
  abstract CancelJumpTableRecovery:
       fnAddr: Addr
     * insAddr: Addr
     * tblAddr: Addr
    -> unit

  /// Report the success of jump table entry recovery to the manager, and get
  /// the decision whether to continue the analysis or not.
  abstract ReportJumpTableSuccess:
       fnAddr: Addr
     * tblAddr: Addr
     * idx: int
     * potentialNextTarget: Addr
    -> bool

  /// Get the current user-defined global state of the TaskManager.
  abstract GetGlobalContext: accessor: ('GlCtx -> 'Res) -> 'Res

  /// Update the user-defined global state of the TaskManager.
  abstract UpdateGlobalContext: updater: ('GlCtx -> 'GlCtx) -> unit

/// Decision about what to do next in the jump table registration process.
and JumpTableRecoveryDecision =
  /// Continue the recovery process.
  | GoRecovery
  /// Error occurred during the recovery process, but we can recover it, so
  /// reload the builder.
  | StopRecoveryButReload
  /// Stop the recovery process since this is a fatal error that we cannot
  /// handle.
  | StopRecoveryAndContinue

/// Message containing the building context of a function.
and BuildingCtxMsg<'FnCtx,
                   'GlCtx when 'FnCtx :> IResettable
                           and 'FnCtx: (new: unit -> 'FnCtx)
                           and 'GlCtx: (new: unit -> 'GlCtx)> =
  /// The building process is finished, and this is the final context.
  | FinalCtx of CFGBuildingContext<'FnCtx, 'GlCtx>
  /// The building process is still ongoing.
  | StillBuilding of CFGBuildingContext<'FnCtx, 'GlCtx>
  /// The building process failed.
  | FailedBuilding
