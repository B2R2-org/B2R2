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
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowGraph

/// Task manager for control flow recovery.
type TaskManager<'V,
                 'E,
                 'FnCtx,
                 'GlCtx when 'V :> IRBasicBlock
                           and 'V: equality
                           and 'E: equality
                           and 'FnCtx :> IResettable
                           and 'FnCtx: (new: unit -> 'FnCtx)
                           and 'GlCtx: (new: unit -> 'GlCtx)>
  public (hdl,
          instrs: InstructionCollection,
          cfgConstructor: IRCFG.IConstructable<'V, 'E>,
          strategy: IFunctionBuildingStrategy<'V, 'E, 'FnCtx, 'GlCtx>,
          ?numThreads) =

  let numThreads = defaultArg numThreads (Environment.ProcessorCount / 2)
  let builders = FunctionBuilderTable (hdl, instrs, cfgConstructor, strategy)
  let workingSet = HashSet<Addr> ()
  let toWorkers = BufferBlock<IFunctionBuildable<_, _, _, _>> ()
  let cts = new CancellationTokenSource ()
  let ct = cts.Token
  let dependenceMap = FunctionDependenceMap ()

  /// Globally maintained context. This context can only be accessed through a
  /// TaskMessage.
  let mutable globalCtx = new 'GlCtx ()

  let isFinished entryPoint =
    match builders.TryGetBuilder entryPoint with
    | Ok builder -> builder.BuilderState = Finished
    | Error _ -> false

  let rec managerTask (inbox: IAgentMessageReceivable<_>) =
    while not inbox.IsCancelled do
      match inbox.Receive () with
      | AddTask (entryPoint, mode) ->
        let builder = builders.GetOrCreateBuilder manager entryPoint mode
        if builder.BuilderState = InProgress ||
           builder.BuilderState = Finished then ()
        else
          workingSet.Add entryPoint |> ignore
          builder.Authorize ()
          toWorkers.Post builder |> ignore
      | AddDependency (_, callee, _) when isFinished callee -> ()
      | AddDependency (caller, callee, mode) ->
        dependenceMap.AddDependency (caller, callee)
        builders.GetOrCreateBuilder manager callee mode |> ignore
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

  and manager = Agent<_>.Start (managerTask, ct)

  and addTask entryPoint mode =
    AddTask (entryPoint, mode) |> manager.Post

  and handleResult entryPoint result =
    let builder = builders[entryPoint]
    match result with
    | Success ->
      workingSet.Remove entryPoint |> ignore
      builder.Finalize ()
      dependenceMap.RemoveAndGetCallers entryPoint
      |> List.iter (fun addr -> addTask addr ArchOperationMode.NoMode)
#if CFGDEBUG
      dbglog 0 "handleResult" $"{entryPoint:x} finished."
#endif
    | Wait calleeAddr ->
      checkAndResolveCyclicDependencies entryPoint calleeAddr
      builder.Stop ()
      addTask entryPoint builder.Mode
    | Failure _ ->
      workingSet.Remove entryPoint |> ignore
      builder.Invalidate ()
      dependenceMap.RemoveAndGetCallers entryPoint
      |> List.iter (fun addr -> addTask addr ArchOperationMode.NoMode)
#if CFGDEBUG
      dbglog 0 "handleResult" $"{entryPoint:x} failed."
#endif

  and checkAndResolveCyclicDependencies entryPoint calleeAddr =
    let deps = dependenceMap.GetCyclicDependencies entryPoint
    if Seq.contains calleeAddr deps then
      deps
      |> Seq.map (fun addr -> addr, builders[addr])
      |> strategy.OnCyclicDependency
    else ()

  and isAllDone () =
    workingSet.Count = 0
    && builders.Values
       |> Seq.forall (fun builder -> builder.BuilderState = Finished)

  and terminate () =
    toWorkers.Complete ()

  let workers =
    Array.init numThreads (fun idx ->
      TaskWorker(idx, manager, toWorkers, ct).Task)

  let waitForWorkers () =
    Task.WhenAll workers (* all done *)
    |> Async.AwaitTask
    |> Async.RunSynchronously

  let sanityCheck arr =
    arr
    |> Array.partition (fun (builder: IFunctionBuildable<_, _, _, _>) ->
      builder.BuilderState = Finished)
    |> fun (succs, fails) ->
      Console.WriteLine $"[*] Done (total {succs.Length} functions)"
      fails
      |> Array.iter (fun b ->
        Console.WriteLine $"[!] Failure: {b.EntryPoint:x} w/ {b.BuilderState}")
      if fails.Length > 0 then Utils.impossible ()
      else ()
    arr

#if CFGDEBUG
  do initLogger numThreads
#endif

  /// Recover the CFGs from the given sequence of entry points. This function
  /// will potentially discover more functions and then return the whole set of
  /// recovered functions (dictionary) as output.
  member __.RecoverCFGs (entryPoints: (Addr * ArchOperationMode)[]) =
    entryPoints |> Seq.iter (fun (addr, mode) -> addTask addr mode)
    waitForWorkers ()
    builders.ToArray ()
#if DEBUG
    |> sanityCheck
#endif
    |> FunctionCollection

/// Task worker for control flow recovery.
and private TaskWorker<'V,
                       'E,
                       'FnCtx,
                       'GlCtx when 'V :> IRBasicBlock
                               and 'V: equality
                               and 'E: equality
                               and 'FnCtx :> IResettable
                               and 'FnCtx: (new: unit -> 'FnCtx)
                               and 'GlCtx: (new: unit -> 'GlCtx)>
  public (tid: int,
          manager: Agent<TaskMessage<'V, 'E, 'FnCtx, 'GlCtx>>,
          ch: BufferBlock<IFunctionBuildable<'V, 'E, 'FnCtx, 'GlCtx>>,
          token) =

  let worker = task {
    while! ch.OutputAvailableAsync (token) do
      match ch.TryReceive () with
      | true, builder ->
        builder.Context.ThreadID <- tid
        try
          let res = builder.Build ()
          manager.Post <| ReportResult (builder.EntryPoint, res)
        with e ->
          Console.Error.WriteLine $"Worker ({tid}) failed:\n{e}"
          let failure = Failure ErrorCase.FailedToRecoverCFG
          manager.Post <| ReportResult (builder.EntryPoint, failure)
#if CFGDEBUG
        flushLog tid
#endif
      | false, _ -> ()
  }

  member _.Task with get() = worker
