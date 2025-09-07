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
open System.Collections.Generic
open B2R2
open B2R2.MiddleEnd.ControlFlowGraph

type TaskScheduler<'FnCtx,
                   'GlCtx when 'FnCtx :> IResettable
                           and 'FnCtx: (new: unit -> 'FnCtx)
                           and 'GlCtx: (new: unit -> 'GlCtx)>
  public(builders: CFGBuilderTable<'FnCtx, 'GlCtx>,
         strategy: ICFGBuildingStrategy<'FnCtx, 'GlCtx>,
         taskStream: TaskWorkerCommandStream<'FnCtx, 'GlCtx>,
         dependenceMap: FunctionDependenceMap) =

  /// Globally maintained context. This context can only be accessed through a
  /// Command.
  let mutable globalCtx = new 'GlCtx()

  let jmptblNotes = JmpTableRecoveryNotebook()

  let workingSet = HashSet<Addr>()

  let mutable msgbox: Agent<TaskManagerCommand<'FnCtx, 'GlCtx>> | null = null

  let assignCFGBuildingTaskNow (builder: ICFGBuildable<_, _>) =
    builder.Authorize()
    taskStream.Post <| BuildCFG builder

  let isBuilderFinished (builder: ICFGBuildable<_, _>) =
    builder.BuilderState = Finished || builder.BuilderState = ForceFinished

  let isFinished entryPoint =
    match builders.TryGetBuilder entryPoint with
    | Ok builder -> isBuilderFinished builder
    | Error _ -> false

  let toBuilderMessage = function
    | Ok(builder: ICFGBuildable<_, _>) ->
      match builder.BuilderState with
      | Invalid -> FailedBuilding
      | ForceFinished | Finished -> FinalCtx builder.Context
      | _ -> StillBuilding builder.Context
    | Error _ -> FailedBuilding

  let terminateWorkers () =
    taskStream.Close()

  let scheduleCFGBuilding entryPoint =
    StartBuilding entryPoint |> msgbox.Post

  let resetBuilder (builder: ICFGBuildable<_, _>) =
    dependenceMap.RemoveCallEdgesFrom builder.EntryPoint
    builder.Reset()

  /// Restart = reset and reschedule builder.
  let restartBuilder (builder: ICFGBuildable<_, _>) =
    resetBuilder builder
    scheduleCFGBuilding builder.EntryPoint

  /// Conditionally restart (reset and reload) builder based on its state. If
  /// the builder is currently building, then it will send a delayed request to
  /// the builder to reset itself after the current building process is done.
  /// N.B. the BuilderState is not a reliable indicator of the builder's status
  /// especially when the manager is handling the result of the builder. Thus,
  /// this function should be only used for builders that are not currently
  /// handled by the manager.
  let restartBuilderIfNotInProgress (builder: ICFGBuildable<_, _>) =
    if builder.BuilderState <> InProgress then restartBuilder builder
    else builder.DelayedBuilderRequests.Enqueue ResetBuilder

  let rechargeActionQueue ctx callee calleeInfo =
    let callerPendingActions = ctx.PendingCallActions
    let callerActionQueue = ctx.ActionQueue
    if not <| callerPendingActions.ContainsKey callee then false
    else
      callerPendingActions[callee]
      |> Seq.map (function
        | MakeCall(callSite, callee, _) ->
          MakeCall(callSite, callee, calleeInfo)
        | MakeTlCall(callSite, callee, _) ->
          MakeTlCall(callSite, callee, calleeInfo)
        | _ -> Terminator.impossible ())
      |> Seq.iter (fun action ->
        callerActionQueue.Push(strategy.ActionPrioritizer, action))
      callerPendingActions.Remove callee

  let notifySuccessToCaller calleeAddr calleeInfo callerAddr =
    let callerBuilder = builders[callerAddr]
    assert (fst calleeInfo <> UnknownNoRet)
    assert (callerBuilder.BuilderState <> Invalid)
#if CFGDEBUG
    dbglog ManagerTid "NotifySuccess" $"{calleeAddr:x} -> {callerAddr:x}"
#endif
    match callerBuilder.BuilderState with
    | InProgress ->
      callerBuilder.DelayedBuilderRequests.Enqueue
      <| NotifyCalleeSuccess(calleeAddr, calleeInfo)
    | _ ->
      if rechargeActionQueue callerBuilder.Context calleeAddr calleeInfo then
        assignCFGBuildingTaskNow callerBuilder
      else ()

  /// Rollback the current builder and notify the callers to rollback if
  /// necessary. N.B. the target builder should not be currently building,
  /// otherwise its `JumpTableRecoveryStatus` could be invalid.
  let rec rollback (builder: ICFGBuildable<_, _>) =
    match builder.Context.JumpTableRecoveryStatus.TryPeek() with
    | true, (tblAddr, idx) ->
#if CFGDEBUG
      dbglog ManagerTid "Rollback"
      <| $"{tblAddr:x}[{idx}] @ {builder.EntryPoint:x}"
#endif
      assert (idx > 0)
      jmptblNotes.SetPotentialEndPointByIndex(tblAddr, idx - 1)
      restartBuilder builder
    | false, _ ->
      let fnAddr = builder.EntryPoint
      let tempCallers = dependenceMap.RemoveTemporary fnAddr
      let confirmedCallers = dependenceMap.RemoveConfirmed fnAddr
      let callers = Array.append tempCallers confirmedCallers
      builder.Invalidate() (* the builder will stop later *)
      for callerFnAddr in callers do invalidateBuilder builders[callerFnAddr]

  and invalidateBuilder builder =
#if CFGDEBUG
    dbglog ManagerTid "Invalidate" $"{builder.EntryPoint:x}"
#endif
    match builder.BuilderState with
    | ForceFinished -> ()
    | InProgress -> builder.DelayedBuilderRequests.Enqueue Rollback
    | _ -> rollback builder

  let getAllStoppedCycle (cycleAddrs: Addr[]) =
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
  let forceFinish (targetBuilder: ICFGBuildable<_, _>) =
    let nextStatus = targetBuilder.Context.NonReturningStatus
    let nextStatus = (* preserve old status so the algo terminates. *)
      if nextStatus = UnknownNoRet then NoRet else nextStatus
    let unwindingBytes = targetBuilder.Context.UnwindingBytes
    let calleeInfo = nextStatus, unwindingBytes
    let calleeAddr = targetBuilder.EntryPoint
    resetBuilder targetBuilder
    targetBuilder.ForceFinish()
    targetBuilder.Context.NonReturningStatus <- nextStatus
#if CFGDEBUG
    dbglog ManagerTid "CyclicDependencies"
    <| $"force finish {targetBuilder.EntryPoint:x}"
#endif
    dependenceMap.Confirm calleeAddr
    |> Array.filter (not << isFinished)
    |> Array.iter (notifySuccessToCaller calleeAddr calleeInfo)

  let checkAndResolveCyclicDependencies () =
    let deps = dependenceMap.GetCyclicDependencies()
    if Seq.isEmpty deps then
#if CFGDEBUG
      dbglog ManagerTid "CyclicDependencies" $"No cycle"
      builders.Values
      |> Array.iter (fun bld ->
        let state = bld.BuilderState
        if state <> Finished && state <> Invalid then
          let addr = bld.Context.FunctionAddress
          let forceFinished = bld.BuilderState = ForceFinished
          dbglog ManagerTid "Terminate" $"? {addr:x} ({state}, {forceFinished})"
      )
#endif
      ()
    else
      deps
      |> Seq.iter (fun cycleAddrs ->
        match getAllStoppedCycle cycleAddrs with
        | Ok deps -> strategy.OnCyclicDependency deps |> forceFinish
        | Error _ ->
#if CFGDEBUG
          dbglog ManagerTid "CyclicDependencies" "No stopped cycle found yet."
#endif
          ()
      )

  let terminateIfAllDone () =
    if workingSet.Count = 0 then
      match builders.GetTerminationStatus() with
      | AllDone ->
        match strategy.FindCandidatesForPostProcessing builders.Values with
        | [||] ->
          terminateWorkers ()
        | nextCandidates ->
          nextCandidates |> Array.iter (msgbox.Post << StartBuilding)
#if CFGDEBUG
        dbglog ManagerTid "Termination" "All done."
#endif
      | ForceTerminated blds ->
        blds
        |> Array.iter (fun builder ->
#if CFGDEBUG
          dbglog ManagerTid "Restart" $"{builder.EntryPoint:x}"
#endif
          builder.ReInitialize()
          scheduleCFGBuilding builder.EntryPoint)
      | YetDone ->
        checkAndResolveCyclicDependencies ()
    else ()

  let rec consumeUntilPendingReset (builder: ICFGBuildable<_, _>) =
    match builder.DelayedBuilderRequests.TryDequeue() with
    | true, NotifyCalleeSuccess(calleeAddr, calleeInfo) ->
#if CFGDEBUG
      dbglog ManagerTid (nameof NotifyCalleeSuccess) $"{calleeAddr:x}"
#endif
      rechargeActionQueue builder.Context calleeAddr calleeInfo |> ignore
      consumeUntilPendingReset builder
    | true, Rollback ->
#if CFGDEBUG
      dbglog ManagerTid (nameof Rollback) $"{builder.EntryPoint:x}"
#endif
      rollback builder
      builder.DelayedBuilderRequests.Clear()
    | true, NotifyCalleeChange(calleeAddr, calleeInfo) ->
#if CFGDEBUG
      dbglog ManagerTid (nameof NotifyCalleeChange)
      <| $"{calleeAddr:x} @ {builder.EntryPoint:x}"
#endif
      builder.Context.ActionQueue.Push(strategy.ActionPrioritizer,
        UpdateCallEdges(calleeAddr, calleeInfo))
      consumeUntilPendingReset builder
    | true, ResetBuilder ->
#if CFGDEBUG
      dbglog ManagerTid (nameof ResetBuilder) $"{builder.EntryPoint:x}"
#endif
      restartBuilder builder
    | false, _ ->
      (* if the builder has a jump table, then it is safer to restart the whole
         process instead of incrementally updating the CFG because the
         under-approximated CFG can introduce a bogus edge in some rare cases
         where we have some bogus dataflows due to the under-approximation,
         making our switch table identification wrong (e.g., the switch table
         size is over-approximated or it has a wrong base address). *)
      if builder.HasJumpTable then restartBuilder builder
      else scheduleCFGBuilding builder.EntryPoint

  /// Returns true if there was a consumed request.
  let consumeDelayedRequests (builder: ICFGBuildable<_, _>) =
    if builder.DelayedBuilderRequests.Count = 0 then false
    else consumeUntilPendingReset builder; true

  /// Conditionally update builder based on its state. If the builder is
  /// currently building, then it will send a delayed request to the builder to
  /// update itself after the current building process is done. N.B. the
  /// BuilderState is not a reliable indicator of the builder's status
  /// especially when the manager is handling the result of the builder. Thus,
  /// this function should be only used for builders that are not currently
  /// handled by the manager.
  let updateCallers (callee: ICFGBuildable<_, _>) caller =
    let calleeCtx = callee.Context
    let calleeAddr = callee.EntryPoint
    let calleeInfo = calleeCtx.NonReturningStatus, calleeCtx.UnwindingBytes
    if (caller: ICFGBuildable<_, _>).BuilderState <> InProgress then
#if CFGDEBUG
      dbglog ManagerTid "ReloadDueCalleeChange"
      <| $"{callee.EntryPoint:x} -> {caller.EntryPoint:x}"
#endif
      (* We restart the caller builder if it has a jump table as the
         under-approximated CFG can introduce a bogus edge in some rare cases
         as described in the `consumeUntilPendingReset` function. *)
      if caller.HasJumpTable then restartBuilder caller
      else
        if isBuilderFinished caller then caller.ReInitialize() else ()
        caller.Context.ActionQueue.Push(strategy.ActionPrioritizer,
          UpdateCallEdges(calleeAddr, calleeInfo))
        scheduleCFGBuilding caller.EntryPoint
    else
#if CFGDEBUG
      dbglog ManagerTid "ReloadDueCalleeChange"
      <| $"{callee.EntryPoint:x} -> {caller.EntryPoint:x} (delayed)"
#endif
      caller.DelayedBuilderRequests.Enqueue
      <| NotifyCalleeChange(calleeAddr, calleeInfo)

  /// This function is called when a callee has been successfully built. It
  /// propagates the success to its callers who are waiting for the builder.
  let finalizeBuilder (builder: ICFGBuildable<_, _>) entryPoint =
    assert (builder.DelayedBuilderRequests.Count = 0)
#if CFGDEBUG
    let nextFnAddrOpt = builder.NextFunctionAddress
    if builder.Context.JumpTables.Count > 0 then
      let gap = builder.Context.AnalyzeGap nextFnAddrOpt
      if List.isEmpty gap then
        dbglog ManagerTid "Gap" $"none @ {builder.EntryPoint:x}"
      else
        gap
        |> List.iter (fun range ->
          dbglog ManagerTid "Gap" $"{range} @ {builder.EntryPoint:x}")
    else ()
#endif
    builder.Finalize()
    let retStatus = builder.Context.NonReturningStatus
    let unwindingBytes = builder.Context.UnwindingBytes
    let calleeInfo = retStatus, unwindingBytes
    dependenceMap.Confirm entryPoint
    |> Array.iter (notifySuccessToCaller entryPoint calleeInfo)

  let reloadCallersAndFinalizeBuilder builder entryPoint =
    for callerAddr in dependenceMap.GetConfirmedCallers entryPoint do
      updateCallers builder builders[callerAddr]
    finalizeBuilder builder entryPoint

  let handleResult entryPoint result =
    let builder = builders[entryPoint]
    workingSet.Remove entryPoint |> ignore
    match result with
    | MoveOn ->
#if CFGDEBUG
      dbglog ManagerTid (nameof MoveOn) $"{entryPoint:x}"
#endif
      builder.StartVerifying()
      if consumeDelayedRequests builder then ()
      else finalizeBuilder builder entryPoint
    | MoveOnButReloadCallers prevStatus ->
#if CFGDEBUG
      dbglog ManagerTid (nameof MoveOnButReloadCallers)
      <| $"{entryPoint:x}, prev: {prevStatus}"
#endif
      builder.StartVerifying()
      if consumeDelayedRequests builder then
        (* Recover the previous status in order to detect the change again. *)
        builder.Context.NonReturningStatus <- prevStatus
      else reloadCallersAndFinalizeBuilder builder entryPoint
    | Wait ->
#if CFGDEBUG
      dbglog ManagerTid (nameof Wait) $"{entryPoint:x}"
#endif
      builder.Stop()
      consumeDelayedRequests builder |> ignore
    | StopAndReload ->
#if CFGDEBUG
      dbglog ManagerTid (nameof StopAndReload) $"{entryPoint:x}"
#endif
      restartBuilder builder
    | FailStop e ->
#if CFGDEBUG
      dbglog ManagerTid (nameof FailStop)
      <| $"{entryPoint:x}: {ErrorCase.toString e}"
#endif
      (* invalid builder will be auto-reloaded later *)
      if builder.BuilderState = Invalid then ()
      else rollback builder

  let handleJumpTableRecoveryRequest fnAddr (jmptbl: JmpTableInfo) =
    match jmptblNotes.Register(fnAddr, jmptbl) with
    | RegistrationSucceeded ->
#if CFGDEBUG
      dbglog ManagerTid "JumpTable registered"
      <| jmptblNotes.GetNoteString jmptbl.TableAddress
#endif
      GoRecovery
    | SharedByFunctions oldFnAddr ->
#if CFGDEBUG
      dbglog ManagerTid "JumpTable failed"
      <| $"{jmptbl.InsAddr:x}:{jmptbl.TableAddress:x} shared by two funcs."
#endif
      (* We found two distinct functions for the same jump table. This is only
         possible when a function had a bogus edge that goes beyond the boundary
         of a function, but we were unlucky to find the bogus edge because the
         next function was not fully loaded yet. But we happened to find the
         next function and both functions share the same basic block, which
         includes the indirect branch instruction. In this case, a function that
         has a greater address is closer to the indirect branch instruction and
         should be the one that includes the indirect branch. Therefore, if we
         simply reload the function that has the lower address (which has a
         problematic CFG expansion), then we will be able to detect the bogus
         edge. *)
      if oldFnAddr < fnAddr then
#if CFGDEBUG
        dbglog ManagerTid "JumpTable failed" $"so, reload {oldFnAddr:x}"
#endif
        jmptblNotes.Unregister(jmptbl.TableAddress, oldFnAddr)
        jmptblNotes.Register(fnAddr, jmptbl) |> ignore
        restartBuilderIfNotInProgress builders[oldFnAddr]
        GoRecovery
      else
#if CFGDEBUG
        dbglog ManagerTid "JumpTable failed" $"so, reload {fnAddr:x}"
#endif
        StopRecoveryButReload
    | SharedByInstructions ->
#if CFGDEBUG
      let insAddr = jmptbl.InsAddr
      dbglog ManagerTid "JumpTable failed"
      <| $"{insAddr:x}:{jmptbl.TableAddress:x}) shared by two instrs."
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
      <| $"{jmptbl.InsAddr:x}:{newTblAddr:x} overlapped with ({str})"
#endif
      jmptblNotes.SetPotentialEndPointByAddr(oldTblAddr, newEndPoint)
      if entryBeingAnalyzed <= newEndPoint then
#if CFGDEBUG
        dbglog ManagerTid "JumpTable" $"overlap resolved and continue"
#endif
        let result = jmptblNotes.Register(fnAddr, jmptbl)
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
          restartBuilderIfNotInProgress builder
        else ()
        StopRecoveryButReload

  let handleBogusJumpTableEntry fnAddr tblAddr idx =
    let currentIdx = jmptblNotes.GetPotentialEndPointIndex tblAddr
    if idx > 0 && (idx - 1) <= currentIdx then
#if CFGDEBUG
      dbglog ManagerTid "BogusJumpTableEntry"
      <| $"{tblAddr:x}:[{idx}] @ {fnAddr:x} is bogus so set the idx to {idx-1}"
#endif
      jmptblNotes.SetPotentialEndPointByIndex(tblAddr, idx - 1)
      true
    elif idx = 0 && idx < currentIdx then
#if CFGDEBUG
      dbglog ManagerTid "BogusJumpTableEntry"
      <| $"{tblAddr:x}:[{idx}] @ {fnAddr:x} is bogus so set the idx to 0"
#endif
      jmptblNotes.SetPotentialEndPointByIndex(tblAddr, 0)
      true
    else
#if CFGDEBUG
      dbglog ManagerTid "BogusJumpTableEntry"
      <| $"{tblAddr:x}:[{idx}] @ {fnAddr:x} is bogus but didn't rollback"
#endif
      false

  let handleJumpTableRecoverySuccess fnAddr tblAddr idx nextJumpTarget =
#if CFGDEBUG
    dbglog ManagerTid "JumpTable success"
    <| $"{tblAddr:x}[{idx}] @ {fnAddr:x} -> {nextJumpTarget:x}"
#endif
    jmptblNotes.SetConfirmedEndPoint(tblAddr, idx)
    if jmptblNotes.IsExpandable(tblAddr, idx + 1) then
      match builders[fnAddr].NextFunctionAddress with
      | Some nextFnAddr ->
        let nextBuilder = builders[nextFnAddr]
        fnAddr < nextJumpTarget && nextJumpTarget < nextBuilder.EntryPoint
      | None -> false
    else false

  let rec schedule (inbox: IAgentMessageReceivable<_>) =
    while not inbox.IsCancelled do
      match inbox.Receive() with
      | StartBuilding entryPoint ->
        let builder = builders.GetOrCreateBuilder(msgbox, entryPoint)
        if builder.BuilderState = InProgress ||
           builder.BuilderState = Invalid ||
           builder.BuilderState = ForceFinished ||
           builder.BuilderState = Finished then ()
        else
          workingSet.Add entryPoint |> ignore
          strategy.OnCreate builder.Context
          assignCFGBuildingTaskNow builder
      | AddDependency(caller, callee, ch) ->
        dependenceMap.AddDependency(caller, callee, not <| isFinished callee)
        let builder = builders.TryGetBuilder callee
        if Result.isOk builder then () else scheduleCFGBuilding callee
        toBuilderMessage builder |> ch.Reply
      | ReportCFGResult(entryPoint, result) ->
        try handleResult entryPoint result
        with e -> Console.Error.WriteLine $"Failed to handle result:\n{e}"
        terminateIfAllDone ()
      | GetNonReturningStatus(addr, ch) ->
        match builders.TryGetBuilder addr with
        | Ok builder -> ch.Reply builder.Context.NonReturningStatus
        | Error _ -> ch.Reply UnknownNoRet
      | GetBuildingContext(addr, ch) ->
        builders.TryGetBuilder addr
        |> toBuilderMessage
        |> ch.Reply
      | GetNextFunctionAddress(addr, ch) ->
        builders[addr].NextFunctionAddress
        |> ch.Reply
      | NotifyJumpTableRecovery(fnAddr, jmptbl, ch) ->
        ch.Reply <| handleJumpTableRecoveryRequest fnAddr jmptbl
      | NotifyBogusJumpTableEntry(fnAddr, tblAddr, idx, ch) ->
        ch.Reply <| handleBogusJumpTableEntry fnAddr tblAddr idx
      | CancelJumpTableRecovery(fnAddr, insAddr, tblAddr) ->
#if CFGDEBUG
        dbglog ManagerTid "JumpTable canceled" $"{insAddr:x} @ {fnAddr:x}"
#endif
        jmptblNotes.Unregister(tblAddr, fnAddr)
      | ReportJumpTableSuccess(fnAddr, tblAddr, idx, nextTarget, ch) ->
        ch.Reply <| handleJumpTableRecoverySuccess fnAddr tblAddr idx nextTarget
      | AccessGlobalContext(accessor, ch) ->
        ch.Reply <| accessor globalCtx
      | UpdateGlobalContext updater ->
        try globalCtx <- updater globalCtx
        with e -> Console.Error.WriteLine $"Failed to update global ctx:\n{e}"

  /// Start the scheduler and return the command message box.
  member _.Start(token) =
    msgbox <- Agent<_>.Start(schedule, token)
    msgbox

  /// Terminate the scheduler.
  member _.Terminate() =
    terminateWorkers ()

  /// Post a `StartBuilding` message to the msgbox to start building this
  /// function.
  member _.StartBuilding entryPoint =
    scheduleCFGBuilding entryPoint

  /// Post a command to the msgbox.
  member _.PostCommand cmd =
    msgbox.Post cmd