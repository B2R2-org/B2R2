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

/// Represents the context for building a control flow graph of a function. This
/// exists per function, and it can include a user-defined context, too. A
/// strategy sees only what it may use to analyze the function; the rest is the
/// bookkeeping of the CFG recovery itself, which stays internal.
type CFGBuildingContext<'FnCtx, 'GlCtx>
  internal(hdl, exnInfo, entryPoint, name, bblFactory, userCtx, prioritizer) =

  let vertices = Dictionary<ProgramPoint, IVertex<LowUIRBasicBlock>>()

  let mutable cfg = LowUIRCFG.create Mutable

  let cp = ConstantPropagation((hdl: BinHandle), cfg.Vertices)

  let mutable noretStatus = UnknownNoRet

  let jmptblRecoveryStatus = Stack<Addr * int>()

  let mutable gapToAnalyze: Addr option = None

  let gapAnalysisVertices = HashSet<ProgramPoint>()

  let gapBlacklist = HashSet<Addr>()

  let jumpTables = Dictionary<Addr, JmpTableInfo>()

  let intraCallTable = IntraCallTable()

  let callers = HashSet<Addr>()

  let visitedPPoints = HashSet<ProgramPoint>()

  let actionQueue = CFGActionQueue prioritizer

  let pendingCallActions = Dictionary<Addr, List<CFGAction>>()

  let callerVertices = Dictionary<CallSite, IVertex<LowUIRBasicBlock>>()

  let mutable unwindingBytes = 0

  let clobberedRegs = HashSet(ClobberedRegisters.ofCallingConvention hdl)

  let mutable managerChannel: IManagerAccessible<'FnCtx, 'GlCtx> | null = null

  let mutable jumpTableChannel: IJumpTableChannel | null = null

  let mutable threadID = -1

  /// The address of the function that is being built.
  member _.FunctionAddress with get(): Addr = entryPoint

  /// Function name.
  member _.FunctionName with get(): string = name

  /// The binary handle.
  member _.BinHandle with get() = hdl

  /// The exception information of the binary.
  member _.ExnInfo with get(): ExceptionInfo = exnInfo

  /// Mapping from a program point to a vertex in the LowUIRCFG.
  member _.Vertices with get() = vertices

  /// The control flow graph in LowUIR.
  member _.CFG with get() = cfg and internal set v = cfg <- v

  /// Constant propagation analyzer that is used to incrementally update
  /// the dataflow state of the CFG as we recover it.
  member _.CP with get() = cp

  /// The basic block factory.
  member _.BBLFactory with get(): BBLFactory = bblFactory

  /// Is this function a no-return function? Analyses of the function set this.
  member _.NonReturningStatus
    with get() = noretStatus
     and set v = noretStatus <- v

  /// Which jump table entry is currently being recovered? (table addr, index)
  member internal _.JumpTableRecoveryStatus with get() = jmptblRecoveryStatus

  /// Gap to be processed.
  member internal _.GapToAnalyze
    with get() = gapToAnalyze
     and set v = gapToAnalyze <- v

  /// Vertices created during gap analysis. These will be added as a
  /// unreachable code segment by default. The only exception is when we find
  /// a non-returning call instruction and a gap starts right after it, as
  /// this indicates that the gap has been considered reachable by the
  /// compiler when generating the binary although our non-returning analysis
  /// is more conservative (and precise), so we regard this gap as
  /// non-reachable.
  member _.GapAnalysisVertices with get() = gapAnalysisVertices

  /// Gap addresses, which have been identified as data. By adding these
  /// addresses to this blacklist, we prevent performing gap analysis on
  /// these addresses again.
  member internal _.GapBlacklist with get() = gapBlacklist

  /// Jump tables associated with this function, keyed by table address.
  /// Recovery records a table once per entry it expands, so keying on the
  /// address keeps one slot per table.
  member _.JumpTables with get() = jumpTables

  /// Table for maintaining intra-function call information of this function.
  member _.IntraCallTable with get() = intraCallTable

  /// Set of callers of this function.
  member _.Callers with get() = callers

  /// The set of visited BBL program points. This is to prevent visiting the
  /// same basic block multiple times when constructing the CFG.
  member internal _.VisitedPPoints with get() = visitedPPoints

  /// The action queue for the CFG building process.
  member internal _.ActionQueue with get() = actionQueue

  /// Pending call-edge connection actions (e.g., MakeCall, MakeTlCall, etc)
  /// for each callee address. This is to remember the actions that are
  /// waiting for the callee to be built.
  member internal _.PendingCallActions with get() = pendingCallActions

  /// From a call site of a caller vertex to the caller vertex itself.
  member internal _.CallerVertices with get() = callerVertices

  /// The number of unwinding bytes of the stack when this function returns.
  member _.UnwindingBytes
    with get() = unwindingBytes
     and internal set v = unwindingBytes <- v

  /// The caller-saved registers that this function may modify. It starts
  /// with every register that the calling convention lets a callee modify,
  /// which is the safe assumption, and the analysis at the end of the
  /// recovery narrows it down.
  member _.ClobberedRegs with get() = clobberedRegs

  /// The user-defined per-function context.
  member _.UserContext with get(): 'FnCtx = userCtx

  /// The channel for accessing the state of the TaskManager.
  member internal _.ManagerChannel
    with get() = managerChannel
     and set v = managerChannel <- v

  /// The channel for coordinating jump table recovery with the TaskManager.
  member internal _.JumpTableChannel
    with get() = jumpTableChannel
     and set v = jumpTableChannel <- v

  /// Thread ID that is currently building this function.
  member internal _.ThreadID
    with get() = threadID
     and set v = threadID <- v

  /// Reads the global context, which is shared by all the functions, through
  /// the given accessor. The task manager runs the accessor, so it is safe.
  member _.GetGlobalContext(accessor: 'GlCtx -> 'Res): 'Res =
    managerChannel.GetGlobalContext accessor

  /// Updates the global context, which is shared by all the functions, with
  /// the given updater. The task manager runs the updater later, in order.
  member _.UpdateGlobalContext(updater: 'GlCtx -> 'GlCtx) =
    managerChannel.UpdateGlobalContext updater

  /// Takes a snapshot of what the callers of this function need to know about
  /// it, which stays valid even after this context changes.
  member internal this.ToCalleeInfo() =
    { Status = this.NonReturningStatus
      Unwinding = this.UnwindingBytes
      Clobbered = Set.ofSeq this.ClobberedRegs
      IsExternal = false }

  /// Resets the context to its initial state.
  member internal this.Reset() =
    this.Vertices.Clear()
    this.CFG <- LowUIRCFG.create this.CFG.ImplementationType
    this.CP.State.Reset()
    (* N.B. We should keep the value of `NonReturningStatus` (i.e., leave the
       below line commented out) because we should be able to compare the
       difference before/after rebuilding the CFG. *)
    (* this.NonReturningStatus <- UnknownNoRet *)
    (* N.B. For the same reason, `ClobberedRegs` is not reset either. *)
    this.JumpTableRecoveryStatus.Clear()
    this.JumpTables.Clear()
    this.GapToAnalyze <- None
    this.GapAnalysisVertices.Clear()
    this.IntraCallTable.Reset()
    this.Callers.Clear()
    this.VisitedPPoints.Clear()
    this.ActionQueue.Clear()
    this.PendingCallActions.Clear()
    this.CallerVertices.Clear()
    this.UnwindingBytes <- 0

  /// Scans basic blocks starting from the given entry points. By discovering
  /// new basic blocks, existing blocks can be divided into multiple blocks, in
  /// which case this will return a sequence of divided edges created by
  /// discovering new basic blocks.
  member internal this.ScanBBLs entryPoints =
    this.BBLFactory.ScanBBLs entryPoints

  member private _.UpdateDictionary(dict: Dictionary<_, _>, k, v, delta) =
    match dict.TryGetValue k with
    | true, (sum, _) -> dict[k] <- (sum + delta, v)
    | false, _ -> dict[k] <- (delta, v)

  /// Searches for the first overlapping vertex in the CFG by reverse traversing
  /// the vertices. Since there can be many vertices beyond the range of the
  /// current function, we should return the first one (with the smallest
  /// address).
  member private this.FindFunctionOverlap(lst, nextFnAddr, idx, res) =
    if idx = 0 then
#if DEBUG
      (* This is a fatal error when our function identification or noreturn
         analysis failed. *)
      let fnAddr = this.FunctionAddress
      $"{fnAddr:x} overlapped with {nextFnAddr:x}"
      |> System.InvalidOperationException
      |> raise
#else
      None (* Ignore this error in release mode. *)
#endif
    else
      let _, v = (lst: SortedList<_, _ * IVertex<LowUIRBasicBlock>>).Values[idx]
      if v.VData.Internals.Range.Max >= nextFnAddr then
        this.FindFunctionOverlap(lst, nextFnAddr, idx - 1, Some v)
      elif Option.isNone res then
        None
      else
        res

  /// Finds the first overlapping vertex in the CFG. We consider two cases: (1)
  /// two vertices share the same address, or (2) a vertex is beyond the range
  /// of the current function. If there's no such overlap, this returns None.
  ///
  /// This function will check for the first case by traversing the vertices in
  /// the ascending order of addresses. This is crucial for the correctness of
  /// the rollback mechanism as we need to figure out which vertex is causing
  /// the overlap. Since we run this function after fully over-approximating the
  /// CFG, we can assume that the first overlapping vertex is the problematic
  /// one.
  ///
  /// We then check the second case by assuming that the current function's
  /// boundary is determined by the next function's address. If there's a vertex
  /// that is located beyond the boundary, we consider it as an overlap.
  ///
  /// This function will return only the first overlapping vertex even though
  /// there may be multiple overlapping vertices.
  member internal this.FindOverlap(nextFnAddrOpt) =
    let vertices = this.CFG.Vertices
    let dict = Dictionary(vertices.Length * 2)
    for v in vertices do
      let vData = v.VData.Internals
      if not vData.IsAbstract && vData.PPoint.Position = 0 then
        let range = v.VData.Internals.Range
        this.UpdateDictionary(dict, range.Min, v, 1)
        this.UpdateDictionary(dict, range.Max + 1UL, v, -1)
      else
        ()
    let lst = SortedList dict
    let enumerator = lst.GetEnumerator()
    let mutable hasOverlap = false
    let mutable overlapVertex = null
    let mutable sum = 0
    while not hasOverlap && enumerator.MoveNext() do
      let (delta, v) = enumerator.Current.Value
      sum <- sum + delta
      if sum > 1 then
        hasOverlap <- true
        overlapVertex <- v
      else
        ()
    if hasOverlap then
      Some overlapVertex
    else
      match nextFnAddrOpt with
      | Some nextFnAddr ->
        this.FindFunctionOverlap(lst, nextFnAddr, lst.Count - 1, None)
      | None ->
        None

  member private this.AddOrIgnore(acc, gapStart, gapEnd) =
    match this.ScanBBLs [ gapStart ] with
    | Ok _dividedEdges ->
      let bbl = this.BBLFactory.Find <| ProgramPoint(gapStart, 0)
      if bbl.Internals.Range.Max > gapEnd then acc
      else (AddrRange.create gapStart gapEnd) :: acc
    | Error _ ->
      acc

  [<TailCall>]
  member private this.FindGap(acc, fnEnd, gapAddr, ranges) =
    match ranges with
    | [] ->
      if gapAddr < fnEnd then this.AddOrIgnore(acc, gapAddr, fnEnd) else acc
    | (range: AddrRange) :: tl ->
      if gapAddr < range.Min then
        let acc = this.AddOrIgnore(acc, gapAddr, range.Min - 1UL)
        this.FindGap(acc, fnEnd, range.Max + 1UL, tl)
      elif gapAddr >= range.Min && gapAddr <= range.Max then
        this.FindGap(acc, fnEnd, range.Max + 1UL, tl)
      else
        acc

  /// Finds a gap between the current function and the next function. This
  /// function finds every gap between the current function and the next
  /// function. If there are multiple gaps, this returns all of them.
  member internal this.AnalyzeGap(nextFnAddrOpt) =
    match nextFnAddrOpt with
    | Some nextFnAddr ->
      let endAddr = nextFnAddr - 1UL
      this.CFG.Vertices
      |> Array.fold (fun acc v ->
        if v.VData.Internals.IsAbstract then acc
        else v.VData.Internals.Range :: acc) []
      |> List.sortBy (fun r -> r.Min)
      |> fun ranges -> this.FindGap([], endAddr, this.FunctionAddress, ranges)
      |> List.rev
    | None ->
      []

/// Represents a call edge from its callsite address to the callee's address.
/// This is to uniquely identify call edges for abstracted vertices. We create
/// an abstract vertex for each call instruction even though multiple call
/// instructions may target the same callee. The callee address can be None for
/// an indirect call.
and AbsCallEdge = Addr * Addr option

/// Describes the binary location used to refer to an external function.
/// This is a reference location, not necessarily the entry address of code in
/// the external library.
and ExternalFunctionReference =
  /// An executable import trampoline. For ELF binaries this is a PLT entry,
  /// whose address can be the direct target of a call instruction.
  | PLTTrampoline of trampolineAddress: Addr
  /// A non-executable relocation slot. The loader fills this slot with the
  /// external function's address, and an indirect call reads it from the slot.
  | RelocationSlot of slotAddress: Addr
with
  /// Address in this binary at which the external function is referenced.
  member this.ReferenceAddress =
    match this with
    | PLTTrampoline addr
    | RelocationSlot addr -> addr

/// Represents the interface for accessing the state of the TaskManager.
and IManagerAccessible<'FnCtx, 'GlCtx> =
  /// Starts building a function at the given address if it is not (being)
  /// built.
  abstract StartBuilding:
       addr: Addr
    -> unit

  /// Updates the dependency between two functions and returns the current
  /// status of the callee.
  abstract AddDependency:
       caller: Addr
     * callee: Addr
    -> CalleeStatus

  /// Gets the status of the function located at `addr`, which tells whether it
  /// has been built, and if so, what its callers need to know about it.
  abstract GetCalleeStatus:
       addr: Addr
    -> CalleeStatus

  /// Gets the status of an external function, creating its builder if needed.
  abstract GetExternalCalleeStatus:
       reference: ExternalFunctionReference
     * name: string
    -> CalleeStatus

  /// Gets the next function address of the given function address. If there's
  /// no next function, this returns None.
  abstract GetNextFunctionAddress: addr: Addr -> Addr option

  /// Gets the current user-defined global state of the TaskManager.
  abstract GetGlobalContext: accessor: ('GlCtx -> 'Res) -> 'Res

  /// Updates the user-defined global state of the TaskManager.
  abstract UpdateGlobalContext: updater: ('GlCtx -> 'GlCtx) -> unit

/// Represents what the manager knows about a function that another function
/// refers to. It never hands out the context of the function, which only the
/// thread building that function may touch.
and CalleeStatus =
  /// The function has been built, and this is what its callers need to know.
  | Built of CalleeInfo
  /// The function is still being built.
  | Building
  /// The function failed to be built, or it is not a function at all.
  | Failed
