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

open System
open System.Threading
open System.Threading.Tasks
open System.Threading.Tasks.Dataflow
open System.Collections.Generic
open B2R2
open B2R2.MiddleEnd.ControlFlowGraph

type RecoveryMission<'FnCtx,
                     'GlCtx when 'FnCtx :> IResettable
                             and 'FnCtx: (new: unit -> 'FnCtx)
                             and 'GlCtx: (new: unit -> 'GlCtx)>
  public (strategy: ICFGBuildingStrategy<'FnCtx, 'GlCtx>) =

  member _.Execute (builders: CFGBuilderTable<_, _>) =
    let numThreads = Environment.ProcessorCount / 2
    let manager = TaskManager<'FnCtx, 'GlCtx> (builders, strategy, numThreads)
#if CFGDEBUG
    initLogger numThreads
#endif
    manager.Start ()

/// Task manager for control flow analysis.
and private TaskManager<'FnCtx,
                        'GlCtx when 'FnCtx :> IResettable
                                and 'FnCtx: (new: unit -> 'FnCtx)
                                and 'GlCtx: (new: unit -> 'GlCtx)>
  public (builders: CFGBuilderTable<'FnCtx, 'GlCtx>,
          strategy: ICFGBuildingStrategy<'FnCtx, 'GlCtx>,
          numThreads) =

  let workingSet = HashSet<Addr> ()
  let toWorkers = BufferBlock<ICFGBuildable<_, _>> ()
  let cts = new CancellationTokenSource ()
  let ct = cts.Token
  let dependenceMap = FunctionDependenceMap ()
  let msgbox = Dictionary<Addr, List<TaskMessage>> () (* for each caller *)

  /// Globally maintained context. This context can only be accessed through a
  /// TaskMessage.
  let mutable globalCtx = new 'GlCtx ()

  let jmptblNotes = JmpTableRecoveryNotebook ()

  let isFinished entryPoint =
    match builders.TryGetBuilder entryPoint with
    | Ok builder -> builder.BuilderState = Finished
    | Error _ -> false

  let isInvalid entryPoint =
    match builders.TryGetBuilder entryPoint with
    | Ok builder -> builder.BuilderState = Invalid
    | Error _ -> false

  let makeInvalid builder =
    match (builder: ICFGBuildable<_, _>).BuilderState with
    | Finished | Invalid -> ()
    | InProgress ->
      builder.Invalidate ()
    | _ ->
      builder.Authorize ()
      builder.Invalidate ()

  let terminateWorkers () =
    toWorkers.Complete ()

  let toBuilderMessage = function
    | Ok (builder: ICFGBuildable<_, _>) ->
      match builder.BuilderState with
      | Invalid -> FailedBuilding
      | Finished -> FinalCtx builder.Context
      | _ -> StillBuilding builder.Context
    | Error _ -> FailedBuilding

  let rec schedule (inbox: IAgentMessageReceivable<_>) =
    while not inbox.IsCancelled do
      match inbox.Receive () with
      | AddTask (entryPoint, mode) ->
        let builder = builders.GetOrCreateBuilder agent entryPoint mode
        if builder.BuilderState = InProgress ||
           builder.BuilderState = Invalid ||
           builder.BuilderState = Finished then ()
        else
          msgbox[entryPoint] <- List ()
          workingSet.Add entryPoint |> ignore
          builder.Authorize ()
          toWorkers.Post builder |> ignore
      | InvalidateBuilder (entryPoint, mode) ->
        let builder = builders.GetOrCreateBuilder agent entryPoint mode
#if CFGDEBUG
        let jt =
          match builder.Context.JumpTableRecoveryStatus.TryPeek () with
          | true, (addr, idx) -> $"!{addr:x}[{idx}]"
          | false, _ -> "n/a"
        dbglog ManagerTid (nameof InvalidateBuilder) $"{jt} @ {entryPoint:x}"
#endif
        rollbackOrPropagateInvalidation entryPoint builder
        terminateIfAllDone ()
      | AddDependency (caller, callee, mode, ch) ->
        dependenceMap.AddDependency (caller, callee, not <| isFinished callee)
        let builder = builders.TryGetBuilder callee
        if Result.isOk builder then () else addTask callee mode
        toBuilderMessage builder |> ch.Reply
      | ReportCFGResult (entryPoint, result) ->
        try handleResult entryPoint result
        with e -> Console.Error.WriteLine $"Failed to handle result:\n{e}"
        terminateIfAllDone ()
      | GetNonReturningStatus (addr, ch) ->
        match builders.TryGetBuilder addr with
        | Ok builder -> ch.Reply builder.Context.NonReturningStatus
        | Error _ -> ch.Reply UnknownNoRet
      | GetBuildingContext (addr, ch) ->
        builders.TryGetBuilder addr
        |> toBuilderMessage
        |> ch.Reply
      | GetNextFunctionAddress (addr, ch) ->
        builders.TryGetNextBuilder addr
        |> Result.map (fun builder -> builder.EntryPoint)
        |> Result.toOption
        |> ch.Reply
      | NotifyJumpTableRecovery (fnAddr, jmptbl, ch) ->
        ch.Reply <| handleJumpTableRecoveryRequest fnAddr jmptbl
      | NotifyBogusJumpTableEntry (fnAddr, tblAddr, idx, ch) ->
        ch.Reply <| handleBogusJumpTableEntry fnAddr tblAddr idx
      | CancelJumpTableRecovery (fnAddr, tblAddr) ->
#if CFGDEBUG
        let insAddr = jmptblNotes.GetIndBranchAddress tblAddr
        dbglog ManagerTid "JumpTable canceled" $"{insAddr:x} @ {fnAddr:x}"
#endif
        jmptblNotes.Unregister tblAddr
      | ReportJumpTableSuccess (fnAddr, tblAddr, idx, nextTarget, ch) ->
        ch.Reply <| handleJumpTableRecoverySuccess fnAddr tblAddr idx nextTarget
      | AccessGlobalContext (accessor, ch) ->
        ch.Reply <| accessor globalCtx
      | UpdateGlobalContext updater ->
        try globalCtx <- updater globalCtx
        with e -> Console.Error.WriteLine $"Failed to update global ctx:\n{e}"

  and agent = Agent<_>.Start (schedule, ct)

  and addTask entryPoint mode =
    AddTask (entryPoint, mode) |> agent.Post

  and reloadBuilder (builder: ICFGBuildable<_, _>) =
    if builder.BuilderState <> InProgress then
      resetBuilder builder
      addTask builder.EntryPoint builder.Mode
    else msgbox[builder.EntryPoint].Add BuilderReset

  and rollbackOrPropagateInvalidation entryPoint builder =
    match builder.Context.JumpTableRecoveryStatus.TryPeek () with
    | true, (tblAddr, idx) ->
      assert (idx > 0)
#if CFGDEBUG
      dbglog ManagerTid "rollback" $"{builder.Context.FunctionAddress:x}"
#endif
      jmptblNotes.SetPotentialEndPointByIndex tblAddr (idx - 1)
      reloadBuilder builder
    | false, _ ->
      let tempCallers =
        dependenceMap.RemoveFunctionAndGetDependentAddrs entryPoint true
      let confirmedCallers =
        dependenceMap.RemoveFunctionAndGetDependentAddrs entryPoint false
      makeInvalid builder
      tempCallers
      |> Array.append confirmedCallers
      |> Array.iter propagateInvalidation

  and terminateIfAllDone () =
    if workingSet.Count = 0 then
      match builders.GetTerminationStatus () with
      | AllDone ->
        terminateWorkers ()
#if CFGDEBUG
        dbglog ManagerTid "Termination" "All done."
#endif
      | ForceTerminated blds ->
        blds
        |> Array.iter (fun builder ->
#if CFGDEBUG
          dbglog ManagerTid "Restart" $"{builder.EntryPoint:x}"
#endif
          builder.Context.ForceFinish <- false
          builder.ReInitialize ()
          addTask builder.EntryPoint builder.Mode)
      | YetDone ->
        checkAndResolveCyclicDependencies ()
    else ()

  and rechargeActionQueue callerCtx callee calleeInfo =
    let callerPendingActions = callerCtx.PendingActions
    let callerActionQueue = callerCtx.ActionQueue
    if not <| callerPendingActions.ContainsKey callee then ()
    else
      callerPendingActions[callee]
      |> Seq.map (function
        | MakeCall (callSite, callee, _) ->
          MakeCall (callSite, callee, calleeInfo)
        | MakeTlCall (callSite, callee, _) ->
          MakeTlCall (callSite, callee, calleeInfo)
        | _ -> Utils.impossible ())
      |> Seq.iter (callerActionQueue.Push strategy.ActionPrioritizer)
      callerPendingActions.Remove callee |> ignore

  /// Returns true if there was one or more pending reset messages.
  and consumePendingMessages (builder: ICFGBuildable<_, _>) entryPoint =
    let ctx = builder.Context
    let messages = msgbox[entryPoint]
    if Seq.isEmpty messages then false
    else
      let mutable pendingReset = false
      for msg in messages do
        match msg with
        | CalleeSuccess (calleeAddr, calleeInfo) ->
#if CFGDEBUG
          dbglog ManagerTid "PendingMsg" $"CalleeSuccess {calleeAddr:x}"
#endif
          rechargeActionQueue ctx calleeAddr calleeInfo
        | BuilderReset ->
#if CFGDEBUG
          dbglog ManagerTid "PendingMsg" $"BuilderReset"
#endif
          resetBuilder builder
          pendingReset <- true
      addTask entryPoint builder.Mode
#if CFGDEBUG
      if pendingReset then
        dbglog ManagerTid "HandleResult" $"{entryPoint:x}: had a pending reset"
      else ()
#endif
      pendingReset

  and propagateInvalidation entryPoint =
    if builders[entryPoint].Context.ForceFinish then ()
    else InvalidateBuilder (entryPoint, ArchOperationMode.NoMode) |> agent.Post

  and propagateSuccess calleeAddr calleeInfo callerAddr =
    assert (fst calleeInfo <> UnknownNoRet)
    let callerBuilder = builders[callerAddr]
#if CFGDEBUG
    dbglog ManagerTid "PropagateSuccess" $"{calleeAddr:x} to {callerAddr:x}"
#endif
    match callerBuilder.BuilderState with
    | Stopped ->
      rechargeActionQueue callerBuilder.Context calleeAddr calleeInfo
      addTask callerAddr callerBuilder.Mode
    | InProgress ->
      msgbox[callerAddr].Add <| CalleeSuccess (calleeAddr, calleeInfo)
    | Initialized -> () (* Ignore since it has been reset. *)
    | Invalid -> Utils.fatalExit $"[!] FATAL Error with {callerAddr:x}"
    | _ -> Utils.impossible ()

  and getAllStoppedCycle (cycleAddrs: Addr[]) =
    let tuples = Array.zeroCreate cycleAddrs.Length
    let mutable isAllStopped = true
    for i = 0 to cycleAddrs.Length - 1 do
      let addr = cycleAddrs[i]
      let builder = builders[addr]
      tuples[i] <- addr, builder
      if builder.BuilderState <> Stopped then isAllStopped <- false else ()
    done
    if isAllStopped then Ok tuples
    else Error ErrorCase.ItemNotFound

  /// Forcefully complete the target builder by under-approximating it as a
  /// "non-returning" function.
  and forceFinish (targetBuilder: ICFGBuildable<_, _>) =
    let nextStatus = targetBuilder.Context.NonReturningStatus
    let nextStatus = (* preserve old status so the algo terminates. *)
      if nextStatus = UnknownNoRet then NoRet else nextStatus
    let unwindingBytes = targetBuilder.Context.UnwindingBytes
    let calleeInfo = nextStatus, unwindingBytes
    let calleeAddr = targetBuilder.EntryPoint
    resetBuilder targetBuilder
    targetBuilder.Context.ForceFinish <- true
    targetBuilder.Context.NonReturningStatus <- nextStatus
    targetBuilder.Finalize true (* mark as Finished *)
#if CFGDEBUG
    dbglog ManagerTid "CyclicDependencies"
    <| $"force finish {targetBuilder.EntryPoint:x}"
#endif
    dependenceMap.RemoveFunctionAndGetDependentAddrs calleeAddr true
    |> dependenceMap.AddResolvedDependencies calleeAddr
    |> Array.filter (not << isFinished)
    |> Array.iter (propagateSuccess calleeAddr calleeInfo)

  and checkAndResolveCyclicDependencies () =
    let deps = dependenceMap.GetCyclicDependencies ()
    if Array.isEmpty deps then
#if CFGDEBUG
      dbglog ManagerTid "CyclicDependencies" $"No cycle"
      builders.Values
      |> Array.iter (fun bld ->
        let state = bld.BuilderState
        if state <> Finished && state <> Invalid then
          let addr = bld.Context.FunctionAddress
          let forceFinished = bld.Context.ForceFinish
          dbglog ManagerTid "Terminate" $"? {addr:x} ({state}, {forceFinished})"
      )
#endif
      ()
    else
      deps
      |> Array.iter (fun cycleAddrs ->
        match getAllStoppedCycle cycleAddrs with
        | Ok deps -> strategy.OnCyclicDependency deps |> forceFinish
        | Error _ ->
#if CFGDEBUG
          dbglog ManagerTid "CyclicDependencies" "No stopped cycle found yet."
#endif
          ()
      )

  and handleResult entryPoint result =
    let builder = builders[entryPoint]
    workingSet.Remove entryPoint |> ignore
    match result with
    | Continue ->
#if CFGDEBUG
      dbglog ManagerTid "HandleResult" $"{entryPoint:x}: finished"
#endif
      if consumePendingMessages builder entryPoint then ()
      else
        finalizeBuilder builder entryPoint
    | ContinueAndReloadCallers prevStatus ->
#if CFGDEBUG
      dbglog ManagerTid "HandleResult"
      <| $"{entryPoint:x}: finished, but result changed"
#endif
      if consumePendingMessages builder entryPoint then
        (* We need to recover the previous status so that we can detect the
           change again. *)
        builders[entryPoint].Context.NonReturningStatus <- prevStatus
      else
        reloadConfirmedCallers entryPoint
        finalizeBuilder builder entryPoint
    | Wait ->
      if isInvalid entryPoint then
        dependenceMap.RemoveFunctionAndGetDependentAddrs entryPoint true
        |> Array.append (dependenceMap.GetConfirmedCallers entryPoint)
        |> Array.iter propagateInvalidation
      else
        builder.Stop ()
#if CFGDEBUG
        dbglog ManagerTid "HandleResult" $"{entryPoint:x}: stopped"
#endif
        consumePendingMessages builder entryPoint |> ignore
    | StopAndReload ->
      resetBuilder builder
      addTask builder.Context.FunctionAddress builder.Mode
#if CFGDEBUG
      dbglog ManagerTid "HandleResult" $"{entryPoint:x}: reloaded"
#endif
    | FailStop e ->
      match builder.Context.JumpTableRecoveryStatus.TryPeek () with
      | true, (tblAddr, idx) ->
        assert (idx > 0)
        jmptblNotes.SetPotentialEndPointByIndex tblAddr (idx - 1)
        resetBuilder builder
        addTask entryPoint builder.Mode
      | false, _ ->
        let tempCallers =
          dependenceMap.RemoveFunctionAndGetDependentAddrs entryPoint true
        let confirmedCallers =
          dependenceMap.RemoveFunctionAndGetDependentAddrs entryPoint false
        makeInvalid builder
        tempCallers
        |> Array.append confirmedCallers
        |> Array.iter propagateInvalidation
#if CFGDEBUG
      dbglog ManagerTid "HandleResult" $"{entryPoint:x}: {ErrorCase.toString e}"
#endif

  /// This function is called when a callee has been successfully built. It
  /// propagates the success to its callers who are waiting for the builder.
  and finalizeBuilder builder entryPoint =
    builder.Finalize ()
    msgbox.Remove entryPoint |> ignore
    let retStatus = builder.Context.NonReturningStatus
    let unwindingBytes = builder.Context.UnwindingBytes
    let calleeInfo = retStatus, unwindingBytes
    dependenceMap.RemoveFunctionAndGetDependentAddrs entryPoint true
    |> dependenceMap.AddResolvedDependencies entryPoint
    |> Array.iter (propagateSuccess entryPoint calleeInfo)

  and reloadConfirmedCallers entryPoint =
    dependenceMap.GetConfirmedCallers entryPoint
    |> Array.iter (fun callerAddr ->
#if CFGDEBUG
      dbglog ManagerTid "HandleResult"
      <| $"{entryPoint:x} -> reload: {callerAddr:x}"
#endif
      reloadBuilder builders[callerAddr]
    )

  and handleJumpTableRecoveryRequest fnAddr (jmptbl: JmpTableInfo) =
    match jmptblNotes.Register fnAddr jmptbl with
    | RegistrationSucceeded ->
#if CFGDEBUG
      dbglog ManagerTid "JumpTable registered"
      <| jmptblNotes.GetNoteString jmptbl.TableAddress
#endif
      GoRecovery
    | SharedByFunctions oldFnAddr ->
#if CFGDEBUG
      dbglog ManagerTid "JumpTable failed"
      <| $"{jmptbl.TableAddress:x} @ {jmptbl.InsAddr:x} shared by two funcs."
#endif
      (* We found two distinct functions for the same jump table. This is only
         possible when a function had a bogus edge that goes beyond the boundary
         of a function, but we were unlucky to find the bogus edge because the
         next function was not loaded yet. But we happened to find the next
         function and both functions share the same basic block, which includes
         the indirect branch instruction. In this case, a function that has a
         greater address is closer to the indirect branch instruction and should
         be the one that includes the indirect branch. Therefore, if we simply
         reload the function that has the lower address (which has a problematic
         CFG expansion), then we will be able to detect the bogus edge. *)
      if oldFnAddr < fnAddr then
#if CFGDEBUG
        dbglog ManagerTid "JumpTable failed" $"so, reload {oldFnAddr:x}"
#endif
        reloadBuilder builders[oldFnAddr]
        GoRecovery
      else
#if CFGDEBUG
        dbglog ManagerTid "JumpTable failed" $"so, reload {fnAddr:x}"
#endif
        StopRecoveryButReload
    | SharedByInstructions ->
#if CFGDEBUG
      dbglog ManagerTid "JumpTable failed"
      <| $"{jmptbl.TableAddress:x} @ {jmptbl.InsAddr:x} shared by two instrs."
#endif
      (* We found two different jmp instructions for the same jump table, in
         which case we cannot decide which one is wrong. Thus, we just ignore
         this error, meaning that we ignore the later found one. *)
      StopRecoveryAndContinue
    | OverlappingNote oldNote ->
      let oldTblAddr, newTblAddr = oldNote.StartingPoint, jmptbl.TableAddress
      let entrySize = uint64 jmptbl.EntrySize
      let newEndPoint = newTblAddr - entrySize
      let entryBeingAnalyzed = oldNote.ConfirmedEndPoint + entrySize
#if CFGDEBUG
      let str = jmptblNotes.GetNoteString oldNote.StartingPoint
      dbglog ManagerTid "JumpTable overlap"
      <| $"{newTblAddr:x} @ {jmptbl.InsAddr:x} overlapped with ({str})"
#endif
      jmptblNotes.SetPotentialEndPointByAddr oldTblAddr newEndPoint
      if entryBeingAnalyzed <= newEndPoint then
#if CFGDEBUG
        dbglog ManagerTid "JumpTable" $"overlap resolved and continue"
#endif
        let result = jmptblNotes.Register fnAddr jmptbl
        assert (result = RegistrationSucceeded)
        GoRecovery
      else
#if CFGDEBUG
        dbglog ManagerTid "JumpTable rollback"
        <| $"changed potential endpoint to {oldNote.PotentialEndPoint:x}"
#endif
        if oldNote.HostFunctionAddr <> fnAddr then
          let hostAddr = oldNote.HostFunctionAddr
          let builder = builders[hostAddr]
          reloadBuilder builder
        else ()
        StopRecoveryButReload

  and handleBogusJumpTableEntry fnAddr tblAddr idx =
    let currentIdx = jmptblNotes.GetPotentialEndPointIndex tblAddr
    if idx > 0 && (idx - 1) <= currentIdx then
#if CFGDEBUG
      dbglog ManagerTid "BogusJumpTableEntry"
      <| $"{tblAddr:x}:[{idx}] @ {fnAddr:x} is bogus so set the idx to {idx-1}"
#endif
      jmptblNotes.SetPotentialEndPointByIndex tblAddr (idx - 1)
      true
    elif idx = 0 && idx < currentIdx then
#if CFGDEBUG
      dbglog ManagerTid "BogusJumpTableEntry"
      <| $"{tblAddr:x}:[{idx}] @ {fnAddr:x} is bogus so set the idx to 0"
#endif
      jmptblNotes.SetPotentialEndPointByIndex tblAddr 0
      true
    else
#if CFGDEBUG
      dbglog ManagerTid "BogusJumpTableEntry"
      <| $"{tblAddr:x}:[{idx}] @ {fnAddr:x} is bogus but didn't rollback"
#endif
      false

  and handleJumpTableRecoverySuccess fnAddr tblAddr idx nextJumpTarget =
#if CFGDEBUG
    dbglog ManagerTid "JumpTable success" $"{tblAddr:x}[{idx}] @ {fnAddr:x}"
#endif
    jmptblNotes.SetConfirmedEndPoint tblAddr idx
    if jmptblNotes.IsExpandable tblAddr (idx + 1) then
      match builders.TryGetNextBuilder fnAddr with
      | Ok nextBuilder ->
        fnAddr < nextJumpTarget && nextJumpTarget < nextBuilder.EntryPoint
      | Error _ -> false
    else false

  and resetBuilder (builder: ICFGBuildable<_, _>) =
    dependenceMap.RemoveCallEdgesFrom builder.EntryPoint
    builder.Reset builders.CFGConstructor

  let workers =
    Array.init numThreads (fun idx ->
      TaskWorker(idx, agent, strategy, toWorkers, ct).Task)

  let waitForWorkers () =
    Task.WhenAll workers (* all done *)
    |> Async.AwaitTask
    |> Async.RunSynchronously

  member __.Start () =
    match strategy.FindCandidates builders.Values with
    | [||] -> terminateWorkers ()
    | candidates ->
      for (addr, mode) in candidates do
        let builder = builders.GetOrCreateBuilder agent addr mode
        if builder.IsExternal then ()
        else builders.Reload builder agent
      (* Tasks should be added at last to avoid a race for builders. *)
      for (addr, mode) in candidates do addTask addr mode done
    waitForWorkers ()
    for builder in builders.Values do (* Update callers of each builder. *)
      dependenceMap.GetConfirmedCallers builder.EntryPoint
      |> builder.Context.Callers.UnionWith
#if CFGDEBUG
    for tid in 0 .. numThreads do flushLog tid
#endif
    builders

/// Task worker for control flow recovery.
and private TaskWorker<'FnCtx,
                       'GlCtx when 'FnCtx :> IResettable
                               and 'FnCtx: (new: unit -> 'FnCtx)
                               and 'GlCtx: (new: unit -> 'GlCtx)>
  public (tid: int,
          agent: Agent<TaskMessage<'FnCtx, 'GlCtx>>,
          strategy: ICFGBuildingStrategy<'FnCtx, 'GlCtx>,
          ch: BufferBlock<ICFGBuildable<'FnCtx, 'GlCtx>>,
          token) =

  let worker = task {
    while! ch.OutputAvailableAsync (token) do
      match ch.TryReceive () with
      | true, builder ->
        builder.Context.ThreadID <- tid
        try
          let res = builder.Build strategy
          agent.Post <| ReportCFGResult (builder.EntryPoint, res)
        with e ->
          Console.Error.WriteLine $"Worker ({tid}) failed:\n{e}"
          let failure = FailStop ErrorCase.UnexpectedError
          agent.Post <| ReportCFGResult (builder.EntryPoint, failure)
#if CFGDEBUG
        flushLog tid
#endif
      | false, _ -> ()
  }

  member _.Task with get() = worker

and private TaskMessage =
  /// Callee has been successfully built.
  | CalleeSuccess of callee: Addr * calleeInfo: CalleeInfo
  /// Reset the builder.
  | BuilderReset
