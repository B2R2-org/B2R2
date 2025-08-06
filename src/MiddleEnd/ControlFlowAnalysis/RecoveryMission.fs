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

type RecoveryMission<'FnCtx,
                     'GlCtx when 'FnCtx :> IResettable
                             and 'FnCtx: (new: unit -> 'FnCtx)
                             and 'GlCtx: (new: unit -> 'GlCtx)>
  public(strategy: ICFGBuildingStrategy<'FnCtx, 'GlCtx>) =

  member _.Execute(builders: CFGBuilderTable<_, _>) =
    let numThreads = Environment.ProcessorCount / 2
    let manager = TaskManager<'FnCtx, 'GlCtx>(builders, strategy, numThreads)
#if CFGDEBUG
    initLogger numThreads
#endif
    manager.Start()

/// Task manager for control flow analysis.
and private TaskManager<'FnCtx,
                        'GlCtx when 'FnCtx :> IResettable
                                and 'FnCtx: (new: unit -> 'FnCtx)
                                and 'GlCtx: (new: unit -> 'GlCtx)>
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

  member _.Start() =
    match strategy.FindCandidates builders.Values with
    | [||] -> scheduler.Terminate()
    | candidates ->
      for addr in candidates do
        let builder = builders.GetOrCreateBuilder(managerMsgbox, addr)
        if builder.IsExternal then ()
        else builders.Reload(builder, managerMsgbox)
      (* Tasks should be added at last to avoid a race for builders. *)
      for addr in candidates do scheduler.StartBuilding addr done
    waitForWorkers ()
    for builder in builders.Values do (* Update callers of each builder. *)
      depMap.GetConfirmedCallers builder.EntryPoint
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
  public(tid: int,
         scheduler: TaskScheduler<'FnCtx, 'GlCtx>,
         strategy: ICFGBuildingStrategy<'FnCtx, 'GlCtx>,
         stream: TaskWorkerCommandStream<'FnCtx, 'GlCtx>,
         token) =

  let mutable doContinue = true

  let worker = task {
    while doContinue do
      match! stream.Receive(token) with
      | NotAvailable -> doContinue <- false
      | AvailableButNotReceived -> ()
      | Received(BuildCFG builder) ->
        builder.Context.ThreadID <- tid
        try
          let res = builder.Build strategy
          scheduler.PostCommand <| ReportCFGResult(builder.EntryPoint, res)
        with e ->
          Console.Error.WriteLine $"Worker ({tid}) failed:\n{e}"
          let failure = FailStop ErrorCase.UnexpectedError
          scheduler.PostCommand <| ReportCFGResult(builder.EntryPoint, failure)
#if CFGDEBUG
        flushLog tid
#endif
  }

  member _.Task with get() = worker
