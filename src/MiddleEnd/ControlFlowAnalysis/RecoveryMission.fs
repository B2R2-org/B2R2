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
    let manager = TaskManager<'FnCtx, 'GlCtx> (builders, strategy)
    manager.Start ()

/// Task manager for control flow analysis.
and private TaskManager<'FnCtx,
                        'GlCtx when 'FnCtx :> IResettable
                                and 'FnCtx: (new: unit -> 'FnCtx)
                                and 'GlCtx: (new: unit -> 'GlCtx)>
  public (builders: CFGBuilderTable<'FnCtx, 'GlCtx>,
          strategy: ICFGBuildingStrategy<'FnCtx, 'GlCtx>,
          ?numThreads) =

  let numThreads = defaultArg numThreads (Environment.ProcessorCount / 2)
  let workingSet = HashSet<Addr> ()
  let toWorkers = BufferBlock<ICFGBuildable<_, _>> ()
  let cts = new CancellationTokenSource ()
  let ct = cts.Token
  let dependenceMap = FunctionDependenceMap ()
  let pendingMessages = Dictionary<Addr, List<Addr>> () (* message to caller *)

  /// Globally maintained context. This context can only be accessed through a
  /// TaskMessage.
  let mutable globalCtx = new 'GlCtx ()

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
    | InProgress -> builder.Invalidate ()
    | _ ->
      builder.Authorize ()
      builder.Invalidate ()

  let removeFromWorkingSet entryPoint =
    workingSet.Remove entryPoint |> ignore

  let processPendingActions callerCtx callee =
    let callerPendingActions = callerCtx.PendingActions
    let callerActionQueue = callerCtx.ActionQueue
    (* when a cycle appears, a builder may be notified two times for a single
       callee from (1) cycle handling and (2) the callee's completion. *)
    if not <| callerPendingActions.ContainsKey callee then ()
    else
      callerPendingActions[callee]
      |> Seq.iter (callerActionQueue.Push strategy.ActionPrioritizer)
      callerPendingActions.Remove callee |> ignore

  let rec schedule (inbox: IAgentMessageReceivable<_>) =
    while not inbox.IsCancelled do
      match inbox.Receive () with
      | AddTask (entryPoint, mode) ->
        let builder = builders.GetOrCreateBuilder agent entryPoint mode
        if builder.BuilderState = InProgress ||
           builder.BuilderState = Invalid ||
           builder.BuilderState = Finished then ()
        else
          pendingMessages[entryPoint] <- List ()
          workingSet.Add entryPoint |> ignore
          builder.Authorize ()
          toWorkers.Post builder |> ignore
      | InvalidateBuilder (entryPoint, mode) ->
        let builder = builders.GetOrCreateBuilder agent entryPoint mode
        makeInvalid builder
        propagateInvalidation entryPoint
      | AddDependency (_, callee, _) when isFinished callee -> ()
      | AddDependency (caller, callee, mode) ->
        dependenceMap.AddDependency (caller, callee)
        if builders.TryGetBuilder callee |> Result.isOk then
          checkAndResolveCyclicDependencies caller callee
        else
          addTask callee mode
      | ReportResult (entryPoint, result) ->
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
      | AccessGlobalContext (accessor, ch) ->
        ch.Reply <| accessor globalCtx
      | UpdateGlobalContext updater ->
        try globalCtx <- updater globalCtx
        with e -> Console.Error.WriteLine $"Failed to update global ctx:\n{e}"

  and agent = Agent<_>.Start (schedule, ct)

  and addTask entryPoint mode =
    AddTask (entryPoint, mode) |> agent.Post

  and invalidateBuilder entryPoint mode =
    InvalidateBuilder (entryPoint, mode) |> agent.Post

  and consumePendingMessages (builder: ICFGBuildable<_, _>) entryPoint =
    let pendingMessages = pendingMessages[entryPoint]
    if Seq.isEmpty pendingMessages then ()
    else
      for callee in pendingMessages do
        processPendingActions builders[entryPoint].Context callee
      addTask entryPoint builder.Mode

  and propagateInvalidation entryPoint =
    dependenceMap.RemoveAndGetCallers entryPoint
    |> List.iter (fun addr -> invalidateBuilder addr ArchOperationMode.NoMode)

  and propagateSuccess entryPoint caller =
    let callerBuilder = builders[caller]
    match callerBuilder.BuilderState with
    | Stopped ->
      processPendingActions callerBuilder.Context entryPoint
      addTask caller callerBuilder.Mode
    | InProgress -> pendingMessages[caller].Add entryPoint
    | _ -> Utils.impossible ()

  and handleResult entryPoint result =
    let builder = builders[entryPoint]
    match result with
    | Success ->
      removeFromWorkingSet entryPoint
      builder.Finalize ()
      pendingMessages.Remove entryPoint |> ignore
      dependenceMap.RemoveAndGetCallers entryPoint
      |> List.iter (propagateSuccess entryPoint)
#if CFGDEBUG
      dbglog 0 "handleResult" $"{entryPoint:x} finished."
#endif
    | Wait ->
      if isInvalid entryPoint then
        removeFromWorkingSet entryPoint
        propagateInvalidation entryPoint
      else
        consumePendingMessages builder entryPoint
        builder.Stop ()
    | Failure _ ->
      builder.Invalidate ()
      removeFromWorkingSet entryPoint
      propagateInvalidation entryPoint
#if CFGDEBUG
      dbglog 0 "handleResult" $"{entryPoint:x} failed."
#endif

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

#if CFGDEBUG
  do initLogger numThreads
#endif

  member __.Start () =
    match strategy.FindCandidates builders.Values with
    | [||] -> terminate ()
    | candidates ->
      candidates
      |> Array.iter (fun (addr, mode) ->
        let builder = builders.GetOrCreateBuilder agent addr mode
        builders.Reload builder agent
        addTask addr mode)
    waitForWorkers ()
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
          agent.Post <| ReportResult (builder.EntryPoint, res)
        with e ->
          Console.Error.WriteLine $"Worker ({tid}) failed:\n{e}"
          let failure = Failure ErrorCase.UnexpectedError
          agent.Post <| ReportResult (builder.EntryPoint, failure)
#if CFGDEBUG
        flushLog tid
#endif
      | false, _ -> ()
  }

  member _.Task with get() = worker
