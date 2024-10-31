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
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow

/// The main builder for an internal function. This is responsible for building
/// the function CFG while maintaining its internal state. By "internal", we
/// mean that the function is defined within the target binary as opposed to
/// external (library) functions.
type InternalFnCFGBuilder<'FnCtx,
                          'GlCtx when 'FnCtx :> IResettable
                                  and 'FnCtx: (new: unit -> 'FnCtx)
                                  and 'GlCtx: (new: unit -> 'GlCtx)>
  public (ctx, agent: Agent<TaskMessage<'FnCtx, 'GlCtx>>) =

  /// Internal builder state.
  let mutable state = Initialized

  let managerChannel =
    { new IManagerAccessible<'FnCtx, 'GlCtx> with
        member _.AddDependency (caller, callee, mode) =
          agent.PostAndReply (fun _ ch ->
            AddDependency (caller, callee, mode, ch))

        member _.GetNonReturningStatus (addr) =
          agent.PostAndReply (fun _ ch -> GetNonReturningStatus (addr, ch))

        member _.GetBuildingContext (addr) =
          agent.PostAndReply (fun _ ch -> GetBuildingContext (addr, ch))

        member _.NotifyJumpTableRecovery (fnAddr, tblInfo) =
          agent.PostAndReply (fun _ ch ->
            NotifyJumpTableRecovery (fnAddr, tblInfo, ch))

        member _.CancelJumpTableRecovery (fnAddr, tblAddr) =
          agent.Post <| CancelJumpTableRecovery (fnAddr, tblAddr)

        member _.ReportJumpTableSuccess (fnAddr, tblAddr, idx, nextAddr) =
          agent.PostAndReply (fun _ ch ->
            ReportJumpTableSuccess (fnAddr, tblAddr, idx, nextAddr, ch))

        member _.GetGlobalContext accessor =
          let mutable v = Unchecked.defaultof<_>
          agent.PostAndReply (fun _ ch ->
            let fn = fun glCtx -> (v <- accessor glCtx)
            AccessGlobalContext (fn, ch))
          v

        member _.UpdateGlobalContext (updater) =
          agent.Post <| UpdateGlobalContext updater }

  let rec build (strategy: ICFGBuildingStrategy<_, _>) queue =
    if (queue: CFGActionQueue).IsEmpty () then strategy.OnFinish ctx
    else
      let action = queue.Pop ()
      match strategy.OnAction (ctx, queue, action) with
      | Continue -> build strategy queue
      | ContinueAndReloadCallers -> Utils.impossible ()
      | Wait -> queue.Push strategy.ActionPrioritizer action; Wait
      | StopAndReload -> StopAndReload
      | FailStop e -> FailStop e

  do ctx.ManagerChannel <- managerChannel

  new (hdl: BinHandle,
       instrs,
       entryPoint,
       mode,
       cfgConstructor: LowUIRCFG.IConstructable,
       agent) =
    let name =
      match hdl.File.TryFindFunctionName entryPoint with
      | Ok name -> name
      | Error _ -> Addr.toFuncName entryPoint
    let cfg = cfgConstructor.Construct Imperative
    let bblFactory = BBLFactory (hdl, instrs, cfgConstructor.AllowBBLOverlap)
    let fnCtx = new 'FnCtx ()
    let cp = ConstantPropagation hdl :> IDataFlowAnalysis<_, _, _, _>
    let cpState = cp.InitializeState cfg.Vertices
    let ctx =
      { FunctionAddress = entryPoint
        FunctionName = name
        FunctionMode = mode
        BinHandle = hdl
        Vertices = Dictionary ()
        CFG = cfg
        CPState = cpState
        BBLFactory = bblFactory
        ForceFinish = false
        NonReturningStatus = UnknownNoRet
        JumpTableRecoveryStatus = None
        JumpTables = List ()
        Callers = HashSet ()
        IntraCallTable = IntraCallTable ()
        VisitedPPoints = HashSet ()
        ActionQueue = CFGActionQueue ()
        PendingActions = Dictionary ()
        CallerVertices = Dictionary ()
        UnwindingBytes = 0
        UserContext = fnCtx
        IsExternal = false
        ManagerChannel = null
        ThreadID = -1 }
    InternalFnCFGBuilder (ctx, agent)

  interface ICFGBuildable<'FnCtx, 'GlCtx> with
    member __.BuilderState with get() = state

    member __.EntryPoint with get(): Addr = ctx.FunctionAddress

    member __.Mode with get() = ctx.FunctionMode

    member __.Context with get() = ctx

    member __.IsExternal with get() = false

    member __.Authorize () =
      assert (state <> InProgress)
      state <- InProgress

    member __.Stop () =
      assert (state = InProgress)
      state <- Stopped

    member __.Finalize (isForceful) =
      assert (state = InProgress || isForceful)
      state <- Finished

    member __.ReInitialize () =
      assert (state = Finished)
      state <- Initialized

    member __.Invalidate () =
      assert (state = InProgress)
      state <- Invalid

    member __.Build strategy =
      ctx.ActionQueue.Push strategy.ActionPrioritizer InitiateCFG
      build strategy ctx.ActionQueue

    member __.Reset (cfgConstructor: LowUIRCFG.IConstructable) =
      state <- Initialized
      cfgConstructor.Construct Imperative
      |> ctx.Reset

    member __.MakeNew (agent) =
      InternalFnCFGBuilder (ctx, agent)

    member __.ToFunction () =
      assert (state = Finished)
      Function (ctx.FunctionAddress,
                ctx.FunctionName,
                ctx.CFG,
                ctx.NonReturningStatus,
                ctx.IntraCallTable.Callees,
                ctx.Callers,
                ctx.JumpTables,
                false)
