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
  public (builders: CFGBuilderTable<'FnCtx, 'GlCtx>,
          strategy: ICFGBuildingStrategy<'FnCtx, 'GlCtx>,
          taskStream: TaskWorkerCommandStream<'FnCtx, 'GlCtx>,
          dependenceMap: FunctionDependenceMap) =

  /// Globally maintained context. This context can only be accessed through a
  /// Command.
  let mutable globalCtx = new 'GlCtx ()

  let jmptblNotes = JmpTableRecoveryNotebook ()

  let workingSet = HashSet<Addr> ()

  let mutable msgbox: Agent<TaskManagerCommand<'FnCtx, 'GlCtx>> = null

  let assignCFGBuildingTaskNow (builder: ICFGBuildable<_, _>) =
    builder.Authorize ()
    taskStream.Post <| BuildCFG builder

  let isFinished entryPoint =
    match builders.TryGetBuilder entryPoint with
    | Ok builder -> builder.BuilderState = Finished
    | Error _ -> false

  let toBuilderMessage = function
    | Ok (builder: ICFGBuildable<_, _>) ->
      match builder.BuilderState with
      | Invalid -> FailedBuilding
      | Finished -> FinalCtx builder.Context
      | _ -> StillBuilding builder.Context
    | Error _ -> FailedBuilding

  let terminateWorkers () =
    taskStream.Close ()

  let scheduleCFGBuilding entryPoint mode =
    StartBuilding (entryPoint, mode) |> msgbox.Post

  let resetBuilder (builder: ICFGBuildable<_, _>) =
    dependenceMap.RemoveCallEdgesFrom builder.EntryPoint
    builder.Reset builders.CFGConstructor

  let restartBuilder (builder: ICFGBuildable<_, _>) forceRestart =
    if forceRestart || builder.BuilderState <> InProgress then
      resetBuilder builder
      scheduleCFGBuilding builder.EntryPoint builder.Mode
    else builder.DelayedBuilderRequests.Enqueue ResetBuilder

  let rechargeActionQueue ctx callee calleeInfo =
    let callerPendingActions = ctx.PendingCallActions
    let callerActionQueue = ctx.ActionQueue
    if not <| callerPendingActions.ContainsKey callee then false
    else
      callerPendingActions[callee]
      |> Seq.map (function
        | MakeCall (callSite, callee, _) ->
          MakeCall (callSite, callee, calleeInfo)
        | MakeTlCall (callSite, callee, _) ->
          MakeTlCall (callSite, callee, calleeInfo)
        | _ -> Utils.impossible ())
      |> Seq.iter (callerActionQueue.Push strategy.ActionPrioritizer)
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
      <| NotifyCalleeSuccess (calleeAddr, calleeInfo)
    | _ ->
      if rechargeActionQueue callerBuilder.Context calleeAddr calleeInfo then
        assignCFGBuildingTaskNow callerBuilder
      else ()

  let rec rollbackOrPropagateInvalidation builder forceRestart =
    let fnAddr = (builder: ICFGBuildable<_, _>).EntryPoint
    match builder.Context.JumpTableRecoveryStatus.TryPeek () with
    | true, (tblAddr, idx) ->
      assert (idx > 0)
#if CFGDEBUG
      dbglog ManagerTid "Rollback" $"{tblAddr:x}[{idx}] @ {fnAddr:x}"
#endif
      jmptblNotes.SetPotentialEndPointByIndex tblAddr (idx - 1)
      restartBuilder builder forceRestart
    | false, _ ->
      let tempCallers = dependenceMap.RemoveTemporary fnAddr
      let confirmedCallers = dependenceMap.RemoveConfirmed fnAddr
      let callers = Array.append tempCallers confirmedCallers
      builder.Invalidate ()
      for callerFnAddr in callers do invalidateBuilder builders[callerFnAddr]

  and invalidateBuilder builder =
#if CFGDEBUG
    dbglog ManagerTid "Invalidate" $"{builder.EntryPoint:x}"
#endif
    if builder.Context.ForceFinish then ()
    else rollbackOrPropagateInvalidation builder false

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
    targetBuilder.Context.ForceFinish <- true
    targetBuilder.Context.NonReturningStatus <- nextStatus
    targetBuilder.Finalize true (* mark as Finished *)
#if CFGDEBUG
    dbglog ManagerTid "CyclicDependencies"
    <| $"force finish {targetBuilder.EntryPoint:x}"
#endif
    dependenceMap.RemoveTemporary calleeAddr
    |> dependenceMap.AddResolvedDependencies calleeAddr
    |> Array.filter (not << isFinished)
    |> Array.iter (notifySuccessToCaller calleeAddr calleeInfo)

  let checkAndResolveCyclicDependencies () =
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

  let terminateIfAllDone () =
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
          scheduleCFGBuilding builder.EntryPoint builder.Mode)
      | YetDone ->
        checkAndResolveCyclicDependencies ()
    else ()

  let recoverPrevNonReturningStatus (builder: ICFGBuildable<_, _>) prevStatus =
    if builder.DelayedBuilderRequests.Count = 0 then ()
    else
      (* Recover the previous status in order to detect the change again. *)
      builder.Context.NonReturningStatus <- prevStatus

  let rec consumeUntilPendingReset (builder: ICFGBuildable<_, _>) =
    match builder.DelayedBuilderRequests.TryDequeue () with
    | true, NotifyCalleeSuccess (calleeAddr, calleeInfo) ->
#if CFGDEBUG
      dbglog ManagerTid (nameof NotifyCalleeSuccess) $"{calleeAddr:x}"
#endif
      rechargeActionQueue builder.Context calleeAddr calleeInfo |> ignore
      consumeUntilPendingReset builder
    | true, ResetBuilder ->
#if CFGDEBUG
      dbglog ManagerTid (nameof ResetBuilder) $"{builder.EntryPoint:x}"
#endif
      resetBuilder builder
      builder.DelayedBuilderRequests.Clear ()
      scheduleCFGBuilding builder.EntryPoint builder.Mode
      true
    | false, _ ->
      scheduleCFGBuilding builder.EntryPoint builder.Mode
      false

  /// Returns true if there was a reset request.
  let consumeDelayedRequests (builder: ICFGBuildable<_, _>) =
    if builder.DelayedBuilderRequests.Count = 0 then false
    else consumeUntilPendingReset builder

  /// This function is called when a callee has been successfully built. It
  /// propagates the success to its callers who are waiting for the builder.
  let finalizeBuilder (builder: ICFGBuildable<_, _>) entryPoint =
    assert (builder.DelayedBuilderRequests.Count = 0)
    builder.Finalize ()
    let retStatus = builder.Context.NonReturningStatus
    let unwindingBytes = builder.Context.UnwindingBytes
    let calleeInfo = retStatus, unwindingBytes
    dependenceMap.RemoveTemporary entryPoint
    |> dependenceMap.AddResolvedDependencies entryPoint
    |> Array.iter (notifySuccessToCaller entryPoint calleeInfo)

  let reloadConfirmedCallers entryPoint =
    dependenceMap.GetConfirmedCallers entryPoint
    |> Array.iter (fun callerAddr ->
#if CFGDEBUG
      dbglog ManagerTid "HandleResult"
      <| $"{entryPoint:x} -> reload: {callerAddr:x}"
#endif
      restartBuilder builders[callerAddr] false
    )

  let handleResult entryPoint result =
    let builder = builders[entryPoint]
    workingSet.Remove entryPoint |> ignore
    match result with
    | Continue ->
#if CFGDEBUG
      dbglog ManagerTid "HandleResult" $"{entryPoint:x}: finished"
#endif
      if consumeDelayedRequests builder then ()
      else finalizeBuilder builder entryPoint
    | ContinueAndReloadCallers prevStatus ->
#if CFGDEBUG
      dbglog ManagerTid "HandleResult"
      <| $"{entryPoint:x}: finished, but result changed"
#endif
      recoverPrevNonReturningStatus builder prevStatus
      if consumeDelayedRequests builder then ()
      else
        reloadConfirmedCallers entryPoint
        finalizeBuilder builder entryPoint
    | Wait ->
#if CFGDEBUG
      dbglog ManagerTid "HandleResult" $"{entryPoint:x}: stopped"
#endif
      builder.Stop ()
      consumeDelayedRequests builder |> ignore
    | StopAndReload ->
      resetBuilder builder
      scheduleCFGBuilding builder.Context.FunctionAddress builder.Mode
#if CFGDEBUG
      dbglog ManagerTid "HandleResult" $"{entryPoint:x}: reloaded"
#endif
    | FailStop e ->
#if CFGDEBUG
      dbglog ManagerTid "HandleResult" $"{entryPoint:x}: {ErrorCase.toString e}"
#endif
      rollbackOrPropagateInvalidation builder true

  let handleJumpTableRecoveryRequest fnAddr (jmptbl: JmpTableInfo) =
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
        restartBuilder builders[oldFnAddr] false
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
          restartBuilder builder false
        else ()
        StopRecoveryButReload

  let handleBogusJumpTableEntry fnAddr tblAddr idx =
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

  let handleJumpTableRecoverySuccess fnAddr tblAddr idx nextJumpTarget =
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

  let rec schedule (inbox: IAgentMessageReceivable<_>) =
    while not inbox.IsCancelled do
      match inbox.Receive () with
      | StartBuilding (entryPoint, mode) ->
        let builder = builders.GetOrCreateBuilder msgbox entryPoint mode
        if builder.BuilderState = InProgress ||
           builder.BuilderState = Invalid ||
           builder.BuilderState = Finished then ()
        else
          workingSet.Add entryPoint |> ignore
          assignCFGBuildingTaskNow builder
      | AddDependency (caller, callee, mode, ch) ->
        dependenceMap.AddDependency (caller, callee, not <| isFinished callee)
        let builder = builders.TryGetBuilder callee
        if Result.isOk builder then () else scheduleCFGBuilding callee mode
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

  /// Start the scheduler and return the command message box.
  member _.Start (token) =
    msgbox <- Agent<_>.Start (schedule, token)
    msgbox

  /// Terminate the scheduler.
  member _.Terminate () =
    terminateWorkers ()

  /// Post a `StartBuilding` message to the msgbox to start building this
  /// function.
  member _.StartBuilding entryPoint mode =
    scheduleCFGBuilding entryPoint mode

  /// Post a command to the msgbox.
  member _.PostCommand cmd =
    msgbox.Post cmd