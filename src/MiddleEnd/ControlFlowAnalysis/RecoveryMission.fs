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

  let removeFromWorkingSet entryPoint =
    workingSet.Remove entryPoint |> ignore

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
        dbglog ManagerTid (nameof InvalidateBuilder) $"{entryPoint:x}"
#endif
        makeInvalid builder
        rollbackIfNecessary entryPoint builder
        if isAllDone () then terminate () else ()
      | AddDependency (_, callee, _) when isFinished callee -> ()
      | AddDependency (caller, callee, mode) ->
        dependenceMap.AddDependency (caller, callee)
        if builders.TryGetBuilder callee |> Result.isOk then
          checkAndResolveCyclicDependencies caller callee
        else
          addTask callee mode
      | ReportCFGResult (entryPoint, result) ->
        try handleResult entryPoint result
        with e -> Console.Error.WriteLine $"Failed to handle result:\n{e}"
        if isAllDone () then terminate () else ()
      | RetrieveNonReturningStatus (addr, ch) ->
        match builders.TryGetBuilder addr with
        | Ok builder -> ch.Reply builder.Context.NonReturningStatus
        | Error _ -> ch.Reply UnknownNoRet
      | RetrieveBuildingContext (addr, ch) ->
        match builders.TryGetBuilder addr with
        | Ok builder ->
          match builder.BuilderState with
          | Invalid -> ch.Reply FailedBuilding
          | Finished -> ch.Reply <| FinalCtx builder.Context
          | _ -> ch.Reply <| StillBuilding builder.Context
        | Error _ -> ch.Reply <| FailedBuilding
      | NotifyJumpTableRecovery (fnAddr, jmptbl) ->
        handleJumpTableRecoveryRequest fnAddr jmptbl
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

  and rollbackIfNecessary entryPoint builder =
    match builder.Context.JumpTableRecoveryStatus with
    | Some (tblAddr, idx) ->
      jmptblNotes.SetPotentialEndPoint tblAddr (idx - 1)
      builder.Reset builders.CFGConstructor
      addTask builder.Context.FunctionAddress builder.Mode
#if CFGDEBUG
      dbglog ManagerTid "rollback" $"{builder.Context.FunctionAddress:x}"
#endif
    | None ->
      dependenceMap.RemoveAndGetCallers entryPoint
      |> List.iter propagateInvalidation

  and rechargeActionQueue callerCtx callee =
    let callerPendingActions = callerCtx.PendingActions
    let callerActionQueue = callerCtx.ActionQueue
    if not <| callerPendingActions.ContainsKey callee then ()
    else
      callerPendingActions[callee]
      |> Seq.iter (callerActionQueue.Push strategy.ActionPrioritizer)
      callerPendingActions.Remove callee |> ignore

  and consumePendingMessages (builder: ICFGBuildable<_, _>) entryPoint =
    let messages = msgbox[entryPoint]
    if Seq.isEmpty messages then ()
    else
      for msg in messages do
        match msg with
        | CalleeSuccess calleeAddr ->
          rechargeActionQueue builders[entryPoint].Context calleeAddr
      addTask entryPoint builder.Mode

  and propagateInvalidation entryPoint =
    InvalidateBuilder (entryPoint, ArchOperationMode.NoMode) |> agent.Post

  and propagateSuccess entryPoint caller =
    let callerBuilder = builders[caller]
    match callerBuilder.BuilderState with
    | Stopped ->
      rechargeActionQueue callerBuilder.Context entryPoint
      addTask caller callerBuilder.Mode
    | InProgress -> msgbox[caller].Add <| CalleeSuccess entryPoint
    | _ -> Utils.impossible ()

  and handleResult entryPoint result =
    let builder = builders[entryPoint]
    removeFromWorkingSet entryPoint
    match result with
    | Continue ->
      builder.Finalize ()
      msgbox.Remove entryPoint |> ignore
      dependenceMap.RemoveAndGetCallers entryPoint
      |> List.iter (propagateSuccess entryPoint)
#if CFGDEBUG
      dbglog ManagerTid "handleResult" $"{entryPoint:x}: ok"
#endif
    | Wait ->
      if isInvalid entryPoint then
        dependenceMap.RemoveAndGetCallers entryPoint
        |> List.iter propagateInvalidation
      else
        consumePendingMessages builder entryPoint
        builder.Stop ()
#if CFGDEBUG
      dbglog ManagerTid "handleResult" $"{entryPoint:x}: stopped"
#endif
    | FailStop e ->
      propagateInvalidation entryPoint
#if CFGDEBUG
      dbglog ManagerTid "handleResult" $"{entryPoint:x}: {ErrorCase.toString e}"
#endif

  and handleJumpTableRecoveryRequest fnAddr (jmptbl: JmpTableInfo) =
    match jmptblNotes.Register fnAddr jmptbl with
    | Ok _ -> ()
    | Error note -> propagateInvalidation note.HostFunctionAddr
#if CFGDEBUG
    dbglog ManagerTid "JumpTable"
    <| jmptblNotes.GetNoteString jmptbl.TableAddress
#endif

  and handleJumpTableRecoverySuccess fnAddr tblAddr idx nextJumpTarget =
    jmptblNotes.SetConfirmedEndPoint tblAddr idx
    if jmptblNotes.IsExpandable tblAddr (idx + 1) then
      match builders.TryGetNextBuilder fnAddr with
      | Ok nextBuilder ->
        fnAddr < nextJumpTarget && nextJumpTarget < nextBuilder.EntryPoint
      | Error _ -> false
    else false

  and checkAndResolveCyclicDependencies entryPoint calleeAddr =
    let deps = dependenceMap.GetCyclicDependencies entryPoint
    if Seq.contains calleeAddr deps then
      deps
      |> Seq.map (fun addr -> addr, builders[addr])
      |> strategy.OnCyclicDependency
      |> function
        | None -> ()
        | Some builder ->
          builder.Context.NonReturningStatus <- NotNoRet
          dependenceMap.GetCallers builder.EntryPoint
          |> List.iter (propagateSuccess builder.EntryPoint)
    else ()

  and isAllDone () =
    workingSet.Count = 0
    && builders.AllTerminated ()

  and terminate () =
    toWorkers.Complete ()

  let workers =
    Array.init numThreads (fun idx ->
      TaskWorker(idx, agent, strategy, toWorkers, ct).Task)

  let waitForWorkers () =
    Task.WhenAll workers (* all done *)
    |> Async.AwaitTask
    |> Async.RunSynchronously

  member __.Start () =
    match strategy.FindCandidates builders.Values with
    | [||] -> terminate ()
    | candidates ->
      for (addr, mode) in candidates do
        let builder = builders.GetOrCreateBuilder agent addr mode
        if builder.IsExternal then ()
        else builders.Reload builder agent
      (* Tasks should be added at last to avoid a race for builders. *)
      for (addr, mode) in candidates do addTask addr mode done
    waitForWorkers ()
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
  | CalleeSuccess of callee: Addr
