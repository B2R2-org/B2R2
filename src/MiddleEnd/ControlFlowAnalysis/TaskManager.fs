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
open B2R2

/// Represents a task manager for control flow analysis.
type TaskManager<'FnCtx, 'GlCtx>
  public(builders: CFGBuilderTable<'FnCtx, 'GlCtx>,
         strategy: ICFGBuildingStrategy<'FnCtx, 'GlCtx>,
         numThreads) =

  let stream = TaskWorkerCommandStream<'FnCtx, 'GlCtx>()

  let cts = new CancellationTokenSource()

  let depMap = FunctionDependenceMap()

  let scheduler = TaskScheduler<_, _>(builders, strategy, stream, depMap)

  let managerMsgbox = scheduler.Start(cts.Token)

  let workers =
    Array.init numThreads (fun idx ->
      TaskWorker(idx, scheduler, strategy, stream, cts.Token).Task)

  let waitForWorkers () =
    Task.WhenAll workers (* all done *)
    |> Async.AwaitTask
    |> Async.RunSynchronously

  /// Stops the scheduler, which would otherwise wait forever for a message once
  /// the workers are done, holding on to every builder while it waits.
  let stopScheduler () =
    cts.Cancel()
    managerMsgbox.Task.Wait()
    cts.Dispose()

  /// Raises the errors that made the scheduler abort the recovery, if any.
  let raiseIfAborted () =
    match scheduler.FatalErrors with
    | [||] -> ()
    | errors -> raise (AggregateException("CFG recovery aborted.", errors))

  /// Updates callers of each builder.
  let updateCallers () =
    for builder in builders.Values do
      depMap.GetConfirmedCallers builder.EntryPoint
      |> builder.Callers.UnionWith

  /// Creates builders for the given addresses.
  let createBuilders candidates targetAddrs =
    let targetAddrSet = Set.ofArray targetAddrs
    for candidate in candidates do
      match builders.TryGetOrCreateBuilder(managerMsgbox, candidate) with
      | Some builder when not <| Set.contains candidate targetAddrSet ->
        (* For candidates that are not in the initial recovery targets, we
           create their builders but set them to deactivated. This is because
           they might be added as recovery targets later when their callers are
           being built. *)
        builder.Activation <- Deactivated
        builder.Authorize()
        builder.StartVerifying()
        builder.Finalize() (* Initially make them finished without building. *)
      | _ ->
        ()

  let startBuildingCFGs recoveryTargets =
    for targetAddr in recoveryTargets do
      scheduler.StartBuilding targetAddr

  let getInitialRecoveryAddrs candidates =
    match strategy.RecoveryTargets with
    | All -> candidates
    | Specific addrs -> addrs

#if CFGDEBUG
  do initLogger numThreads
#endif

  /// Functions whose recovery raised an unexpected exception.
  member _.Failures with get(): CFGRecoveryFailure[] = scheduler.Failures

  /// The global context that the recovery has built up.
  member _.GlobalContext with get(): 'GlCtx = scheduler.GlobalContext

  member _.StartAndWait candidates =
    let targetAddrs = getInitialRecoveryAddrs candidates
    createBuilders candidates targetAddrs
    startBuildingCFGs targetAddrs
    waitForWorkers ()
    stopScheduler ()
    raiseIfAborted ()
    updateCallers ()
#if CFGDEBUG
    for tid in 0 .. numThreads do flushLog tid
#endif

/// Represents a task worker for control flow recovery.
and private TaskWorker<'FnCtx, 'GlCtx>
  public(tid: int,
         scheduler: TaskScheduler<'FnCtx, 'GlCtx>,
         strategy: ICFGBuildingStrategy<'FnCtx, 'GlCtx>,
         stream: TaskWorkerCommandStream<'FnCtx, 'GlCtx>,
         token) =

  let mutable doContinue = true

  let worker =
    task {
      while doContinue do
        match! stream.Receive(token) with
        | NotAvailable ->
          doContinue <- false
        | AvailableButNotReceived ->
          ()
        | Received(BuildCFG builder) ->
          builder.Context.ThreadID <- tid
          try
            let res = builder.Build strategy
            scheduler.PostCommand <| ReportCFGResult(builder.EntryPoint, res)
          with e ->
            scheduler.PostCommand <| ReportCFGException(builder.EntryPoint, e)
#if CFGDEBUG
          flushLog tid
#endif
    }

  member _.Task with get() = worker
