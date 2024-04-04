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
                 'State,
                 'Req,
                 'Res when 'V :> IRBasicBlock<'Abs>
                       and 'V: equality
                       and 'E: equality
                       and 'Abs: null
                       and 'Act :> ICFGAction
                       and 'State :> IResettable
                       and 'State: (new: unit -> 'State)>
    (hdl,
     instrs: InstructionCollection,
     cfgConstructor: IRCFG.IConstructable<'V, 'E, 'Abs>,
     strategy: IFunctionBuildingStrategy<_, _, _, 'Act, 'State, 'Req, 'Res>,
     ?numThreads) =

  let numThreads = defaultArg numThreads Environment.ProcessorCount
  let builders = Dictionary<Addr, FunctionBuilder<_, _, _, _, _, _, _>> ()
  let workingSet = HashSet<Addr> ()
  let toWorkers = BufferBlock<FunctionBuilder<_, _, _, _, _, _, _>> ()
  let cts = new CancellationTokenSource ()
  let dependenceMap = FunctionDependenceMap ()

  let rec managerTask (inbox: IAgentMessageReceivable<_>) =
    while not inbox.IsCancelled do
      match inbox.Receive () with
      | AddTask (entryPoint, mode) ->
        workingSet.Add entryPoint |> ignore
        let builder = getOrCreateBuilder entryPoint mode
        if builder.InProgress then ()
        else
          builder.InProgress <- true
          toWorkers.Post builder |> ignore
      | AddDependency (caller, callee, mode) ->
        dependenceMap.AddDependency (caller, callee)
        addTask callee mode
      | ReportResult (entryPoint, result) ->
        handleResult entryPoint result
        if isAllDone () then terminate () else ()
      | Query (entryPoint, _, _) as msg ->
        let builder = builders[entryPoint]
        strategy.OnQuery (msg, builder :> IValidityCheck)

  and getOrCreateBuilder addr mode: FunctionBuilder<_, _, _, _, _, _, _> =
    match builders.TryGetValue addr with
    | true, builder -> builder
    | false, _ ->
      let builder =
        FunctionBuilder (hdl, instrs, addr, mode,
                         cfgConstructor, manager, strategy)
      builders[addr] <- builder
      builder

  and manager = Agent<_>.Start (managerTask, cts.Token)

  and addTask entryPoint mode =
    AddTask (entryPoint, mode) |> manager.Post

  and handleResult entryPoint result =
    let builder = builders[entryPoint]
    match result with
    | Success ->
      workingSet.Remove entryPoint |> ignore
      builder.InProgress <- false
      dependenceMap.RemoveAndGetCallers entryPoint
      |> List.iter (fun addr -> toWorkers.Post builders[addr] |> ignore)
    | Postponement ->
      builder.InProgress <- false
      addTask entryPoint builder.Mode
    | Failure _ ->
      workingSet.Remove entryPoint |> ignore
      (builder :> IValidityCheck).Invalidate ()
      dependenceMap.RemoveAndGetCallers entryPoint
      |> List.iter (fun addr -> addTask addr ArchOperationMode.NoMode)

  and isAllDone () =
    workingSet.Count = 0

  and terminate () =
    toWorkers.Complete ()
    cts.Cancel ()

  let workers =
    Array.init numThreads (fun idx -> TaskWorker(idx, manager, toWorkers).Task)

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
    |> Array.filter (fun builder ->
      not builder.InProgress && (builder :> IValidityCheck).IsValid)
#if DEBUG
    |> fun filtered ->
      if filtered.Length = builders.Length then Some builders
      else None
#else
    |> Some
#endif

  /// Recover the CFGs from the given sequence of entry points. This function
  /// will potentially discover more functions and then return the whole set of
  /// recovered functions (dictionary) as output.
  member __.RecoverCFGs (entryPoints: (Addr * ArchOperationMode)[]) =
    entryPoints |> Seq.iter (fun (addr, mode) -> addTask addr mode)
    waitForWorkers ()
    match buildersToArray () with
    | Some builders -> FunctionCollection builders
    | None -> Utils.impossible ()

/// Task worker for control flow recovery.
and private TaskWorker<'V,
                       'E,
                       'Abs,
                       'Act,
                       'State,
                       'Req,
                       'Res when 'V :> IRBasicBlock<'Abs>
                             and 'V: equality
                             and 'E: equality
                             and 'Abs: null
                             and 'Act :> ICFGAction
                             and 'State :> IResettable
                             and 'State: (new: unit -> 'State)>
  public
    (tid: int,
     manager: Agent<TaskMessage<'Req, 'Res>>,
     chan: BufferBlock<FunctionBuilder<'V, 'E, 'Abs, 'Act, 'State, 'Req, 'Res>>)
  =

  let worker = task {
    while! chan.OutputAvailableAsync () do
      match chan.TryReceive () with
      | true, builder ->
        builder.Context.ThreadID <- tid
        try
          let res = builder.Recover ()
          manager.Post <| ReportResult (builder.EntryPoint, res)
        with e ->
          Console.Error.WriteLine $"{e}"
          let result = Failure ErrorCase.FailedToRecoverCFG
          manager.Post <| ReportResult (builder.EntryPoint, result)
      | false, _ -> ()
  }

  member _.Task with get() = worker
