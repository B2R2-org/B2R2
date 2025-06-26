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
  public (ctx, nextFnAddr, manager: Agent<TaskManagerCommand<'FnCtx, 'GlCtx>>) =

  /// Internal builder state.
  let mutable state = Initialized

  let mutable nextFnAddr = nextFnAddr

  let delayedBuilderRequests = Queue<DelayedBuilderRequest> ()

  let mutable hasJumpTable = false

  let managerChannel =
    { new IManagerAccessible<'FnCtx, 'GlCtx> with
        member _.StartBuilding (addr) =
          manager.Post <| StartBuilding addr

        member _.AddDependency (caller, callee) =
          manager.PostAndReply (fun _ ch ->
            AddDependency (caller, callee, ch))

        member _.GetNonReturningStatus (addr) =
          manager.PostAndReply (fun _ ch -> GetNonReturningStatus (addr, ch))

        member _.GetBuildingContext (addr) =
          manager.PostAndReply (fun _ ch -> GetBuildingContext (addr, ch))

        member _.GetNextFunctionAddress (addr) =
          manager.PostAndReply (fun _ ch -> GetNextFunctionAddress (addr, ch))

        member _.NotifyJumpTableRecovery (fnAddr, tblInfo) =
          manager.PostAndReply (fun _ ch ->
            NotifyJumpTableRecovery (fnAddr, tblInfo, ch))

        member _.NotifyBogusJumpTableEntry (fnAddr, tblAddr, idx) =
          manager.PostAndReply (fun _ ch ->
            NotifyBogusJumpTableEntry (fnAddr, tblAddr, idx, ch))

        member _.CancelJumpTableRecovery (fnAddr, insAddr, tblAddr) =
          manager.Post <| CancelJumpTableRecovery (fnAddr, insAddr, tblAddr)

        member _.ReportJumpTableSuccess (fnAddr, tblAddr, idx, nextAddr) =
          hasJumpTable <- true
          manager.PostAndReply (fun _ ch ->
            ReportJumpTableSuccess (fnAddr, tblAddr, idx, nextAddr, ch))

        member _.GetGlobalContext accessor =
          let mutable v = Unchecked.defaultof<_>
          manager.PostAndReply (fun _ ch ->
            let fn = fun glCtx -> (v <- accessor glCtx)
            AccessGlobalContext (fn, ch))
          v

        member _.UpdateGlobalContext (updater) =
          manager.Post <| UpdateGlobalContext updater }

  let rec build (strategy: ICFGBuildingStrategy<_, _>) queue =
    if (queue: CFGActionQueue).IsEmpty () then strategy.OnFinish ctx
    elif state = Invalid then FailStop ErrorCase.UnexpectedError
    else
      let action = queue.Pop ()
      match strategy.OnAction (ctx, queue, action) with
      | MoveOn -> build strategy queue
      | MoveOnButReloadCallers _ -> Terminator.impossible ()
      | Wait -> queue.Push strategy.ActionPrioritizer action; Wait
      | StopAndReload -> StopAndReload
      | FailStop e -> FailStop e

  do ctx.ManagerChannel <- managerChannel

  new (hdl: BinHandle,
       exnInfo,
       instrs,
       entryPoint,
       manager) =
    let name =
      match hdl.File.TryFindName entryPoint with
      | Ok name -> name
      | Error _ -> Addr.toFuncName entryPoint
    let cfg = LowUIRCFG Imperative
    let bblFactory = BBLFactory (hdl, instrs)
    let fnCtx = new 'FnCtx ()
    let cp = ConstantPropagation hdl :> IDataFlowAnalysis<_, _, _, _>
    let cpState = cp.InitializeState cfg.Vertices
    let ctx =
      { FunctionAddress = entryPoint
        FunctionName = name
        BinHandle = hdl
        ExnInfo = exnInfo
        Vertices = Dictionary ()
        CFG = cfg
        CPState = cpState
        BBLFactory = bblFactory
        NonReturningStatus = UnknownNoRet
        JumpTableRecoveryStatus = Stack ()
        JumpTables = List ()
        Callers = HashSet ()
        IntraCallTable = IntraCallTable ()
        VisitedPPoints = HashSet ()
        ActionQueue = CFGActionQueue ()
        PendingCallActions = Dictionary ()
        CallerVertices = Dictionary ()
        UnwindingBytes = 0
        UserContext = fnCtx
        IsExternal = false
        ManagerChannel = null
        ThreadID = -1 }
    InternalFnCFGBuilder (ctx, None, manager)

  interface ICFGBuildable<'FnCtx, 'GlCtx> with
    member _.BuilderState with get() = state

    member _.EntryPoint with get(): Addr = ctx.FunctionAddress

    member _.NextFunctionAddress
      with get() = nextFnAddr
       and set(v) = nextFnAddr <- v

    member _.Context with get() = ctx

    member _.DelayedBuilderRequests with get() = delayedBuilderRequests

    member _.HasJumpTable with get() = hasJumpTable

    member _.IsExternal with get() = false

    member _.Authorize () =
      assert (state <> InProgress)
      state <- InProgress

    member _.Stop () =
      assert (state = InProgress)
      state <- Stopped

    member _.ForceFinish () =
      state <- ForceFinished

    member _.StartVerifying () =
      assert (state = InProgress)
      state <- Verifying

    member _.Finalize () =
      assert (state = Verifying)
      state <- Finished

    member _.ReInitialize () =
      assert (state = Finished || state = ForceFinished)
      state <- Initialized

    member _.Invalidate () =
      state <- Invalid

    member _.Build strategy =
      ctx.ActionQueue.Push strategy.ActionPrioritizer InitiateCFG
      build strategy ctx.ActionQueue

    member _.Reset () =
      state <- Initialized
      delayedBuilderRequests.Clear ()
      ctx.Reset ()

    member _.MakeNew (manager) =
      InternalFnCFGBuilder (ctx, nextFnAddr, manager)

    member _.ToFunction () =
      assert (state = Finished)
      Function (ctx.FunctionAddress,
                ctx.FunctionName,
                ctx.CFG,
                ctx.NonReturningStatus,
                ctx.IntraCallTable.Callees,
                ctx.Callers,
                ctx.JumpTables,
                false)
