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
                 'Abs,
                 'Act,
                 'FnCtx,
                 'GlCtx when 'V :> IRBasicBlock<'Abs>
                           and 'V: equality
                           and 'E: equality
                           and 'Abs: null
                           and 'Act :> ICFGAction
                           and 'FnCtx :> IResettable
                           and 'FnCtx: (new: unit -> 'FnCtx)
                           and 'GlCtx: (new: unit -> 'GlCtx)>
  public (hdl,
          instrs: InstructionCollection,
          cfgConstructor: IRCFG.IConstructable<'V, 'E, 'Abs>,
          strategy: IFunctionBuildingStrategy<'V,
                                              'E,
                                              'Abs,
                                              'Act,
                                              'FnCtx,
                                              'GlCtx>,
          ?numThreads) =

  let numThreads = defaultArg numThreads (Environment.ProcessorCount / 2)
  let builders =
    Dictionary<Addr, IFunctionBuildable<'V, 'E, 'Abs, 'FnCtx, 'GlCtx>> ()
  let workingSet = HashSet<Addr> ()
  let toWorkers = BufferBlock<IFunctionBuildable<_, _, _, _, _>> ()
  let cts = new CancellationTokenSource ()
  let ct = cts.Token
  let dependenceMap = FunctionDependenceMap ()

  /// Globally maintained context. This context can only be accessed through a
  /// TaskMessage.
  let mutable globalCtx = new 'GlCtx ()

  let rec managerTask (inbox: IAgentMessageReceivable<_>) =
    while not inbox.IsCancelled do
      match inbox.Receive () with
      | AddTask (entryPoint, mode) ->
        let builder = getOrCreateBuilder entryPoint mode
        if builder.BuilderState = InProgress ||
           builder.BuilderState = Finished then ()
        else
          workingSet.Add entryPoint |> ignore
          builder.Authorize ()
          toWorkers.Post builder |> ignore
      | AddDependency (caller, callee, mode) ->
        dependenceMap.AddDependency (caller, callee)
        let _ = getOrCreateBuilder callee mode
        addTask callee mode
      | ReportResult (entryPoint, result) ->
        try handleResult entryPoint result
        with e -> Console.Error.WriteLine $"Failed to handle result:\n{e}"
        if isAllDone () then terminate () else ()
      | RetrieveContext (addr, ch) ->
        match builders.TryGetValue addr with
        | true, builder ->
          if builder.BuilderState <> Finished then ch.Reply None
          else ch.Reply <| Some builder.Context
        | false, _ -> ch.Reply None
      | AccessGlobalContext (accessor, ch) ->
        ch.Reply <| accessor globalCtx
      | UpdateGlobalContext updater ->
        try globalCtx <- updater globalCtx
        with e -> Console.Error.WriteLine $"Failed to update global ctxt:\n{e}"

  and getOrCreateBuilder addr mode: IFunctionBuildable<_, _, _, _, _> =
    match builders.TryGetValue addr with
    | true, builder -> builder
    | false, _ ->
      let builder =
        FunctionBuilder (hdl, instrs, addr, mode,
                         cfgConstructor, manager, strategy)
      builders[addr] <- builder
      builder

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
    | Postponement ->
      builder.Stop ()
      addTask entryPoint builder.Mode
    | Failure _ ->
      workingSet.Remove entryPoint |> ignore
      builder.Invalidate ()
      dependenceMap.RemoveAndGetCallers entryPoint
      |> List.iter (fun addr -> addTask addr ArchOperationMode.NoMode)

  and isAllDone () =
    workingSet.Count = 0
    && builders.Values
       |> Seq.forall (fun builder -> builder.BuilderState = Finished)

  and terminate () =
    toWorkers.Complete ()

  let workers =
    Array.init numThreads (fun idx ->
      TaskWorker(idx, manager, toWorkers, ct).Task)

#if CFGDEBUG
  do initLogger numThreads
#endif

  let waitForWorkers () =
    Task.WhenAll workers (* all done *)
    |> Async.AwaitTask
    |> Async.RunSynchronously

  let buildersToArray () =
    let builders = builders.Values |> Seq.toArray
    builders
#if DEBUG
    |> Array.partition (fun builder -> builder.BuilderState = Finished)
    |> fun (succs, fails) ->
      Console.Error.WriteLine $"# of succs: {succs.Length}"
      Console.Error.WriteLine $"# of fails: {fails.Length}"
      fails
      |> Array.iter (fun b ->
        Console.Error.WriteLine $"- {b.EntryPoint:x} {b.BuilderState}")
      Console.Error.WriteLine $"[*] working set? {workingSet.Count}"
      if fails.Length > 0 then None
      else Some succs
#else
    |> Array.filter (fun builder -> not builder.InProgress && builder.IsValid)
    |> Some
#endif

  /// Recover the CFGs from the given sequence of entry points. This function
  /// will potentially discover more functions and then return the whole set of
  /// recovered functions (dictionary) as output.
  member __.RecoverCFGs (entryPoints: (Addr * ArchOperationMode)[]) =
    entryPoints |> Seq.iter (fun (addr, mode) -> addTask addr mode)
    waitForWorkers ()
    Console.Error.WriteLine $"[*] All done: {workingSet.Count}"
    match buildersToArray () with
    | Some builders -> FunctionCollection builders
    | None ->
      Utils.impossible ()

/// Task worker for control flow recovery.
and private TaskWorker<'V,
                       'E,
                       'Abs,
                       'Act,
                       'FnCtx,
                       'GlCtx when 'V :> IRBasicBlock<'Abs>
                               and 'V: equality
                               and 'E: equality
                               and 'Abs: null
                               and 'Act :> ICFGAction
                               and 'FnCtx :> IResettable
                               and 'FnCtx: (new: unit -> 'FnCtx)
                               and 'GlCtx: (new: unit -> 'GlCtx)>
  public (tid: int,
          manager: Agent<TaskMessage<'V, 'E, 'Abs, 'FnCtx, 'GlCtx>>,
          ch: BufferBlock<IFunctionBuildable<'V, 'E, 'Abs, 'FnCtx, 'GlCtx>>,
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
          let result = Failure ErrorCase.FailedToRecoverCFG
          manager.Post <| ReportResult (builder.EntryPoint, result)
      | false, _ -> ()
  }

  member _.Task with get() = worker
