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
open B2R2.MiddleEnd.ControlFlowGraph

type TaskScheduler<'FnCtx, 'GlCtx>
  public(builders: CFGBuilderTable<'FnCtx, 'GlCtx>,
         strategy: ICFGBuildingStrategy<'FnCtx, 'GlCtx>,
         taskStream: TaskWorkerCommandStream<'FnCtx, 'GlCtx>,
         dependenceMap: FunctionDependenceMap,
         identification: IIncrementalFunctionIdentifiable option) =

  /// Globally maintained context. This context can only be accessed through a
  /// Command.
  let mutable globalCtx = strategy.CreateGlobalContext()

  let workingSet = HashSet<Addr>()

  /// Functions whose recovery raised an unexpected exception.
  let failures = List<CFGRecoveryFailure>()

  /// Errors that broke the scheduler itself, which abort the whole recovery.
  let fatalErrors = List<exn>()

  /// Whether the identification may still find functions in what has been
  /// built. Gap analysis waits until it finds no more, since a gap may hold
  /// such a function.
  let mutable isIdentifying = Option.isSome identification

  /// Functions with a jump table that finished while gap analysis waited.
  let functionsAwaitingGaps = HashSet<Addr>()

  /// Functions that start only on the guess that the jumps to them call them
  /// as their tail. A call or the identification proves one, which then is a
  /// function like any other.
  let guessedEntries = HashSet<Addr>()

  /// Addresses where a guess that a function starts has been given up. A jump
  /// there stays within its function, unless a call proves a function there
  /// after all.
  let refutedEntries = HashSet<Addr>()

  let mutable msgbox: Agent<TaskManagerCommand<'FnCtx, 'GlCtx>> | null = null

  let assignCFGBuildingTaskNow (builder: ICFGBuildable<_, _>) =
    builder.Authorize()
    taskStream.Post <| BuildCFG builder

  let isBuilderFinished (builder: IFunctionBuilder) =
    builder.BuilderState = Finished || builder.BuilderState = ForceFinished

  /// Checks if the builder is being built or done with, so that there is
  /// nothing to schedule.
  let isBusyOrDone (builder: ICFGBuildable<_, _>) =
    match builder.BuilderState with
    | InProgress | Invalid | ForceFinished | Finished -> true
    | _ -> false

  let isFinished entryPoint =
    match builders.TryGetBuilder entryPoint with
    | Ok builder -> isBuilderFinished builder
    | Error _ -> false

  let toCalleeStatus = function
    | Ok(builder: IFunctionBuilder) ->
      match builder.BuilderState with
      | Invalid -> Failed
      | ForceFinished | Finished -> Built builder.CalleeInfo
      | _ -> Building
    | Error _ ->
      Failed

  let terminateWorkers () = taskStream.Close()

  /// Aborts the whole recovery, as the scheduler state can no longer be
  /// trusted.
  let abort e =
    fatalErrors.Add e
    terminateWorkers ()

  let scheduleCFGBuilding entryPoint = StartBuilding entryPoint |> msgbox.Post

  let startGapAnalysis (builder: ICFGBuildable<_, _>) addr =
    builder.Context.ActionQueue.Push(StartGapAnalysis addr)
    builder.Context.ActionQueue.Push EndGapAnalysis

  let resetBuilder (builder: ICFGBuildable<_, _>) =
    dependenceMap.RemoveCallEdgesFrom builder.EntryPoint
    builder.Reset strategy

  /// Restarts the builder, i.e., resets and reschedules it.
  let restartBuilder (builder: ICFGBuildable<_, _>) =
    resetBuilder builder
    scheduleCFGBuilding builder.EntryPoint

  /// Conditionally restarts (resets and reloads) the builder based on its
  /// state. If the builder is currently building, then it will send a delayed
  /// request to the builder to reset itself after the current building process
  /// is done. N.B. the BuilderState is not a reliable indicator of the
  /// builder's status especially when the manager is handling the result of the
  /// builder. Thus, this function should be only used for builders that are not
  /// currently handled by the manager.
  let restartBuilderIfNotInProgress (builder: ICFGBuildable<_, _>) =
    if builder.BuilderState <> InProgress then restartBuilder builder
    else builder.DelayedBuilderRequests.Enqueue ResetBuilder

  let jumpTables = JumpTableCoordinator(builders, restartBuilderIfNotInProgress)

  let rechargeActionQueue (ctx: CFGBuildingContext<_, _>) callee calleeInfo =
    let callerPendingActions = ctx.PendingCallActions
    let callerActionQueue = ctx.ActionQueue
    if not <| callerPendingActions.ContainsKey callee then
      false
    else
      callerPendingActions[callee]
      |> Seq.map (function
        | MakeCall(callSite, callee, _) ->
          MakeCall(callSite, callee, calleeInfo)
        | MakeTlCall(callSite, callee, _) ->
          MakeTlCall(callSite, callee, calleeInfo)
        | _ ->
          Terminator.impossible ())
      |> Seq.iter (fun action ->
        callerActionQueue.Push action)
      callerPendingActions.Remove callee

  let notifySuccessToCaller calleeAddr calleeInfo callerAddr =
    let callerBuilder = builders[callerAddr]
    assert (calleeInfo.Status <> UnknownNoRet)
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
      else
        ()

  /// Gives up the guess that a function starts where the given builder does,
  /// as its building failed or a function that calls it as its tail refuted
  /// it. The functions that call it as their tail, which only jumps there do,
  /// build again, and their jumps there stay within them from then on.
  let giveUpGuess (builder: ICFGBuildable<_, _>) =
    let fnAddr = builder.EntryPoint
#if CFGDEBUG
    dbglog ManagerTid "GiveUpGuess" $"{fnAddr:x}"
#endif
    let tempCallers = dependenceMap.RemoveTemporary fnAddr
    let confirmedCallers = dependenceMap.RemoveConfirmed fnAddr
    builder.Invalidate()
    builders.Retire fnAddr
    guessedEntries.Remove fnAddr |> ignore
    refutedEntries.Add fnAddr |> ignore
    for callerFnAddr in Array.append tempCallers confirmedCallers do
      let caller = builders[callerFnAddr]
      if caller.BuilderState <> Invalid then
        restartBuilderIfNotInProgress caller
      else
        ()

  let rec rollback (builder: ICFGBuildable<_, _>) =
    if rollbackOnGapAnalysis builder || jumpTables.Rollback builder then
      restartBuilder builder
    elif guessedEntries.Contains builder.EntryPoint then
      giveUpGuess builder
    else
      let fnAddr = builder.EntryPoint
      let tempCallers = dependenceMap.RemoveTemporary fnAddr
      let confirmedCallers = dependenceMap.RemoveConfirmed fnAddr
      let callers = Array.append tempCallers confirmedCallers
      builder.Invalidate() (* the builder will stop later *)
      for callerFnAddr in callers do invalidateBuilder builders[callerFnAddr]

  /// Rolls back a builder that was performing a gap analysis, adding the gap
  /// address to the blacklist to avoid re-analyzing it.
  and rollbackOnGapAnalysis (builder: ICFGBuildable<_, _>) =
    match builder.Context.GapToAnalyze with
    | None ->
      false
    | Some(addr) ->
#if CFGDEBUG
      dbglog ManagerTid "Rollback for gap completion"
      <| $"{addr:x} @ {builder.EntryPoint:x}"
#endif
      builder.Context.GapBlacklist.Add(addr) |> ignore
      true

  and invalidateBuilder builder =
#if CFGDEBUG
    dbglog ManagerTid "Invalidate" $"{builder.EntryPoint:x}"
#endif
    match builder.BuilderState with
    | ForceFinished -> ()
    | InProgress -> builder.DelayedBuilderRequests.Enqueue Rollback
    | _ -> rollback builder

  /// Refutes the guess that a function starts at the given address. A builder
  /// that is building there gives it up once it reports its result.
  let refuteEntry addr =
    match builders.TryGetBuilder addr with
    | Ok builder when guessedEntries.Contains addr ->
      refutedEntries.Add addr |> ignore
      if builder.BuilderState <> InProgress then giveUpGuess builders[addr]
      else ()
    | Ok _ ->
      ()
    | Error _ ->
      guessedEntries.Remove addr |> ignore

  /// Checks if a function refuted the guess that a function starts at the
  /// given address while it was being built.
  let isRefutedGuess addr =
    guessedEntries.Contains addr && refutedEntries.Contains addr

  let getAllStoppedCycle (cycleAddrs: Addr[]) =
    let tuples = Array.zeroCreate cycleAddrs.Length
    let mutable isAllStopped = true
    for i = 0 to cycleAddrs.Length - 1 do
      let addr = cycleAddrs[i]
      let builder = builders[addr]
      tuples[i] <- addr, builder
      if builder.BuilderState <> Stopped then isAllStopped <- false else ()
    done
    if isAllStopped then Ok tuples else Error ErrorCase.ItemNotFound

  /// Forcefully completes the target builder by under-approximating it as a
  /// "non-returning" function.
  let forceFinish (targetBuilder: ICFGBuildable<_, _>) =
    let nextStatus = targetBuilder.Context.NonReturningStatus
    let nextStatus = (* preserve old status so the algo terminates. *)
      if nextStatus = UnknownNoRet then NoRet else nextStatus
    let calleeInfo =
      { targetBuilder.Context.ToCalleeInfo() with Status = nextStatus }
    let calleeAddr = targetBuilder.EntryPoint
    resetBuilder targetBuilder
    targetBuilder.ForceFinish calleeInfo
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
          let addr = bld.EntryPoint
          let forceFinished = bld.BuilderState = ForceFinished
          dbglog ManagerTid "Terminate" $"? {addr:x} ({state}, {forceFinished})"
        else
          ()
      )
#endif
      ()
    else
      deps
      |> Seq.iter (fun cycleAddrs ->
        match getAllStoppedCycle cycleAddrs with
        | Ok deps ->
          (* A guess gives way first, as forcing a function to finish takes
             for granted what a guess is yet to show. *)
          match Array.tryFind guessedEntries.Contains cycleAddrs with
          | Some addr -> refuteEntry addr
          | None -> strategy.OnCyclicDependency deps |> forceFinish
        | Error _ ->
#if CFGDEBUG
          dbglog ManagerTid "CyclicDependencies" "No stopped cycle found yet."
#endif
          ()
      )

  /// Proves that a function starts at the given address, as a call or the
  /// identification shows: a guess there is a guess no more, and the builder
  /// that a given-up guess left there starts over.
  let proveEntry addr =
    match builders.TryGetBuilder addr with
    | Ok builder when refutedEntries.Contains addr ->
      if builder.BuilderState = Invalid then
        refutedEntries.Remove addr |> ignore
        builders.Revive addr
        resetBuilder builders[addr]
      else
        ()
    | _ ->
      guessedEntries.Remove addr |> ignore

  /// Tells whether a function that the identification finds at the given
  /// address is to be built: no builder starts there yet, or the one that a
  /// given-up guess left there starts over, as the identification proves it.
  let isToBuild addr =
    proveEntry addr
    match builders.TryGetBuilder addr with
    | Ok builder -> builder.BuilderState = Initialized
    | Error _ -> true

  /// Asks the identification for more functions in what has been built,
  /// keeping those that no builder starts at yet: a function that is built or
  /// failed to be needs no second start.
  let identifyMore (identification: IIncrementalFunctionIdentifiable) =
    builders.Values
    |> Array.filter (fun builder -> builder.BuilderState = Finished)
    |> Array.map (fun builder -> builder.ToFunction())
    |> identification.IdentifyMore
    |> Array.map builders.RegisterEntry
    |> Array.distinct
    |> Array.filter isToBuild

  /// Finds the functions to build once every builder is done: those that the
  /// strategy asks for and, while it identifies, those that the identification
  /// finds.
  let findMoreCandidates () =
    let candidates = strategy.FindCandidatesForPostProcessing builders.Values
    match identification with
    | Some identification when isIdentifying ->
      Array.append candidates (identifyMore identification)
    | _ ->
      candidates

  /// Finds the first gap of the function that is worth analyzing, if any. Only
  /// a function with a jump table has one, as its table may reach code that
  /// nothing else leads to.
  let tryFindGap (builder: ICFGBuildable<_, _>) =
    if builder.Context.JumpTables.Count > 0 then
      let gaps = builder.Context.AnalyzeGap builder.NextFunctionAddress
#if CFGDEBUG
      if List.isEmpty gaps then
        dbglog ManagerTid "Gap" $"none @ {builder.EntryPoint:x}"
      else
        gaps
        |> List.iter (fun gap ->
          dbglog ManagerTid "Gap" $"{gap} @ {builder.EntryPoint:x}")
#endif
      gaps
      |> List.map (fun range -> range.Min)
      |> List.filter (not << builder.Context.GapBlacklist.Contains)
      |> List.sort
      |> List.tryHead
    else
      None

  /// Reopens a function that finished while gap analysis waited to analyze its
  /// first gap, telling whether it has one.
  let resumeGapAnalysis addr =
    let builder = builders[addr]
    if builder.BuilderState <> Finished then
      false
    else
      match tryFindGap builder with
      | Some gap ->
        builder.ReInitialize()
        startGapAnalysis builder gap
        scheduleCFGBuilding addr
        true
      | None ->
        false

  /// Stops identifying and resumes the gap analyses that waited for it,
  /// telling whether any of them started.
  let stopIdentifying () =
    isIdentifying <- false
    let resumed =
      functionsAwaitingGaps
      |> Seq.toArray
      |> Array.fold (fun any addr -> resumeGapAnalysis addr || any) false
    functionsAwaitingGaps.Clear()
    resumed

  /// Builds again the functions that the strategy revises once every builder
  /// is done, telling whether there are any.
  let rebuildRevised () =
    match strategy with
    | :? ICFGRevisingStrategy<'FnCtx, 'GlCtx> as revising ->
      let addrs = revising.FindFunctionsToRebuild builders.Values
      for addr in addrs do
#if CFGDEBUG
        dbglog ManagerTid "Revise" $"{addr:x}"
#endif
        restartBuilder builders[addr]
      not (Array.isEmpty addrs)
    | _ ->
      false

  /// Builds the functions that turn up once every builder is done, or ends the
  /// recovery when none does.
  let buildMoreOrTerminate () =
    match findMoreCandidates () with
    | [||] ->
      if isIdentifying && stopIdentifying () then ()
      else terminateWorkers ()
    | nextCandidates ->
      nextCandidates |> Array.iter (msgbox.Post << StartBuilding)

  /// Gives up the guesses that no function calls as its tail any longer, once
  /// every builder is done, as the functions that did were built again since
  /// without the jumps there. Giving up one may leave another uncalled.
  let rec giveUpUncalledGuesses () =
    let isUncalled addr =
      dependenceMap.GetConfirmedCallers addr
      |> Array.forall (fun caller -> builders[caller].BuilderState <> Finished)
    match guessedEntries |> Seq.filter isUncalled |> Seq.toArray with
    | [||] ->
      ()
    | uncalled ->
      Array.iter refuteEntry uncalled
      giveUpUncalledGuesses ()

  let terminateIfAllDone () =
    match builders.GetTerminationStatus() with
    | AllDone ->
      giveUpUncalledGuesses ()
      if not (rebuildRevised ()) then buildMoreOrTerminate () else ()
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
      builder.Context.ActionQueue.Push(UpdateCallEdges(calleeAddr, calleeInfo))
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
      if jumpTables.HasJumpTable builder.EntryPoint then restartBuilder builder
      else scheduleCFGBuilding builder.EntryPoint

  /// Returns true if there was a consumed request.
  let consumeDelayedRequests (builder: ICFGBuildable<_, _>) =
    if builder.DelayedBuilderRequests.Count = 0 then false
    else consumeUntilPendingReset builder; true

  /// Conditionally updates the builder based on its state. If the builder is
  /// currently building, then it will send a delayed request to the builder to
  /// update itself after the current building process is done. N.B. the
  /// BuilderState is not a reliable indicator of the builder's status
  /// especially when the manager is handling the result of the builder. Thus,
  /// this function should be only used for builders that are not currently
  /// handled by the manager.
  let updateCallers (callee: ICFGBuildable<_, _>) caller =
    let calleeAddr = callee.EntryPoint
    let calleeInfo = callee.Context.ToCalleeInfo()
    if (caller: ICFGBuildable<_, _>).BuilderState <> InProgress then
#if CFGDEBUG
      dbglog ManagerTid "ReloadDueCalleeChange"
      <| $"{callee.EntryPoint:x} -> {caller.EntryPoint:x}"
#endif
      (* We restart the caller builder if it has a jump table as the
         under-approximated CFG can introduce a bogus edge in some rare cases
         as described in the `consumeUntilPendingReset` function. *)
      if jumpTables.HasJumpTable caller.EntryPoint then
        restartBuilder caller
      else
        if isBuilderFinished caller then caller.ReInitialize() else ()
        caller.Context.ActionQueue.Push(UpdateCallEdges(calleeAddr, calleeInfo))
        scheduleCFGBuilding caller.EntryPoint
    else
#if CFGDEBUG
      dbglog ManagerTid "ReloadDueCalleeChange"
      <| $"{callee.EntryPoint:x} -> {caller.EntryPoint:x} (delayed)"
#endif
      caller.DelayedBuilderRequests.Enqueue
      <| NotifyCalleeChange(calleeAddr, calleeInfo)

  /// Analyzes gaps and returns true if there was a meaningful gap to analyze so
  /// that we have to resume the building process. While the identification
  /// may still find functions, a function with a jump table waits for it.
  let analyzeGaps (builder: ICFGBuildable<_, _>) =
    if isIdentifying then
      if builder.Context.JumpTables.Count > 0 then
        functionsAwaitingGaps.Add builder.EntryPoint |> ignore
      else
        ()
      false
    else
      match tryFindGap builder with
      | Some addr ->
        startGapAnalysis builder addr
        scheduleCFGBuilding builder.EntryPoint
        true
      | None ->
        false

  /// Finalizes a callee that has been successfully built. It propagates the
  /// success to its callers who are waiting for the builder.
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
    else
      ()
#endif
    builder.Finalize()
    dependenceMap.Confirm entryPoint
    |> Array.iter (notifySuccessToCaller entryPoint builder.CalleeInfo)

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
      if consumeDelayedRequests builder || analyzeGaps builder then ()
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
      else
        reloadCallersAndFinalizeBuilder builder entryPoint
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
      <| $"{entryPoint:x}: {ErrorCase.toMessage e}"
#endif
      (* invalid builder will be auto-reloaded later *)
      if builder.BuilderState = Invalid then () else rollback builder

  /// Handles the result of a builder, or gives up the guess that a function
  /// starts where it does, which a function refuted while it was building.
  let handleResultOrGiveUp entryPoint result =
    if isRefutedGuess entryPoint then
      workingSet.Remove entryPoint |> ignore
      giveUpGuess builders[entryPoint]
    else
      handleResult entryPoint result

  /// Handles the result of a builder, unless the recovery has been aborted.
  let reportResult entryPoint result =
    if fatalErrors.Count > 0 then
      ()
    else
      try
        handleResultOrGiveUp entryPoint result
        if workingSet.Count = 0 then terminateIfAllDone () else ()
      with e ->
        abort e

  /// Records an exception that a builder raised. A critical one, such as
  /// running out of memory, says nothing about the function, so it aborts the
  /// whole recovery instead.
  let reportException entryPoint e =
    if Terminator.isCritical e then
      abort e
    else
      failures.Add { EntryPoint = entryPoint; Exception = e }
      reportResult entryPoint (FailStop ErrorCase.UnexpectedError)

  /// Adds the dependency of the caller on the callee, building the callee if
  /// it is yet to be, and returns the status of the callee.
  let addDependency caller callee =
    builders.InheritEntryMode(callee, caller)
    let builder = builders.TryGetBuilder callee
    match builder with
    | Ok(:? ICFGBuildable<'FnCtx, 'GlCtx> as builder)
      when builder.Activation.IsDeactivated ->
      assert builder.BuilderState.IsFinished
      builder.Activation <- Activated
      builder.ReInitialize()
      scheduleCFGBuilding callee
      dependenceMap.AddDependency(caller, callee, true)
    | _ ->
      scheduleCFGBuilding callee
      dependenceMap.AddDependency(caller, callee, not <| isFinished callee)
    toCalleeStatus builder

  /// Takes the code at the given address for a function on the guess that a
  /// jump calls it as its tail, telling whether it may: no guess there has
  /// been given up, and no builder there has failed.
  let guessEntry addr =
    if refutedEntries.Contains addr then
      false
    else
      match builders.TryGetBuilder addr with
      | Ok builder ->
        builder.BuilderState <> Invalid
      | Error _ ->
        guessedEntries.Add addr |> ignore
        true

  /// Tells the given status of a function that a jump calls as its tail, and
  /// whether it is a function only on a guess.
  let toTailCalleeStatus callee status =
    if guessedEntries.Contains callee || refutedEntries.Contains callee then
      GuessedTailCallee status
    else
      KnownTailCallee status

  let rec schedule (inbox: IAgentMessageReceivable<_>) =
    while not inbox.IsCancelled do
      match inbox.Receive() with
      | StartBuilding entryPoint ->
        match builders.TryGetOrCreateBuilder(msgbox, entryPoint) with
        | Some builder when not (isBusyOrDone builder) ->
          builder.Context.IsGuessedEntry <- guessedEntries.Contains entryPoint
          workingSet.Add entryPoint |> ignore
          strategy.OnCreate builder.Context
          assignCFGBuildingTaskNow builder
        | _ ->
          ()
      | NoteEntryMode(addr, mode) ->
        builders.NoteEntryMode(addr, mode)
      | AddDependency(caller, callee, ch) ->
        proveEntry callee
        addDependency caller callee |> ch.Reply
      | GuessTailCallee(callee, ch) ->
        guessEntry callee |> ch.Reply
      | AddTailCallDependency(caller, callee, ch) ->
        addDependency caller callee
        |> toTailCalleeStatus callee
        |> ch.Reply
      | RefuteTailCallee callee ->
        refuteEntry callee
      | ReportCFGResult(entryPoint, result) ->
        reportResult entryPoint result
      | ReportCFGException(entryPoint, e) ->
        reportException entryPoint e
      | GetCalleeStatus(addr, ch) ->
        builders.TryGetBuilder addr
        |> toCalleeStatus
        |> ch.Reply
      | GetExternalCalleeStatus(reference, name, ch) ->
        builders.GetOrCreateExternalBuilder(reference, name)
        |> Ok
        |> toCalleeStatus
        |> ch.Reply
      | GetNextFunctionAddress(addr, ch) ->
        builders[addr].NextFunctionAddress
        |> ch.Reply
      | JumpTable req ->
        jumpTables.Handle req
      | AccessGlobalContext(accessor, ch) ->
        ch.Reply <| accessor globalCtx
      | UpdateGlobalContext updater ->
        try globalCtx <- updater globalCtx
        with e -> abort e

  new(builders, strategy, taskStream, dependenceMap) =
    TaskScheduler(builders, strategy, taskStream, dependenceMap, None)

  /// Functions whose recovery raised an unexpected exception. This is only
  /// valid after the scheduler has stopped.
  member _.Failures with get() = failures.ToArray()

  /// Errors that aborted the whole recovery. This is only valid after the
  /// scheduler has stopped.
  member _.FatalErrors with get() = fatalErrors.ToArray()

  /// The global context that the recovery has built up. This is only valid
  /// after the scheduler has stopped.
  member _.GlobalContext with get() = globalCtx

  /// Starts the scheduler and returns the command message box.
  member _.Start(token) =
    msgbox <- Agent<_>.Start(schedule, token)
    msgbox

  /// Terminates the scheduler.
  member _.Terminate() = terminateWorkers ()

  /// Posts a `StartBuilding` message to the msgbox to start building this
  /// function.
  member _.StartBuilding entryPoint = scheduleCFGBuilding entryPoint

  /// Posts a command to the msgbox.
  member _.PostCommand cmd = msgbox.Post cmd
