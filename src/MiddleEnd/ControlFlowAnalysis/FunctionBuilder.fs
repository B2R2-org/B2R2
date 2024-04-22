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
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// The main builder for a function, which is responsible for building a
/// function CFG while maintaining its internal state.
type FunctionBuilder<'V,
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
          instrs,
          entryPoint,
          mode: ArchOperationMode,
          cfgConstructor: IRCFG.IConstructable<'V, 'E, 'Abs>,
          agent: Agent<TaskMessage<'V, 'E, 'Abs, 'FnCtx, 'GlCtx>>,
          strategy: IFunctionBuildingStrategy<_, _, _, _, _, _>) =

  /// Internal builder state.
  let mutable state = Initialized

  let bblFactory = BBLFactory (hdl, instrs)
  let ircfg = cfgConstructor.Construct Imperative
  let fnCtx = new 'FnCtx ()
  let blacklist = HashSet<Addr> ()

  let managerChannel =
    { new IManagerAccessible<'V, 'E, 'Abs, 'FnCtx, 'GlCtx> with
        member _.UpdateDependency (caller, callee, mode) =
          agent.Post <| AddDependency (caller, callee, mode)

        member _.GetBuildingContext (addr) =
          agent.PostAndReply (fun _ ch -> RetrieveBuildingContext (addr, ch))

        member _.GetGlobalContext accessor =
          let mutable v = Unchecked.defaultof<_>
          agent.PostAndReply (fun _ ch ->
            let fn = fun glCtx -> (v <- accessor glCtx)
            AccessGlobalContext (fn, ch))
          v

        member _.UpdateGlobalContext (updater) =
          agent.Post <| UpdateGlobalContext updater }

  let ctxt =
    { FunctionAddress = entryPoint
      BinHandle = hdl
      Vertices = Dictionary ()
      CFG = ircfg
      BBLFactory = bblFactory
      IsNoRet = false
      Callees = SortedList ()
      Callers = HashSet ()
      CallingNodes = Dictionary ()
      UserContext = fnCtx
      ManagerChannel = managerChannel
      ThreadID = -1 }

  let queue = CFGActionQueue<'Act> ()

  let rec build () =
    if queue.IsEmpty () then strategy.OnFinish ctxt
    else
      let action = queue.Pop ()
      match strategy.OnAction (ctxt, queue, action) with
      | Success -> build ()
      | Wait fnAddr ->
        if blacklist.Contains fnAddr then
          strategy.OnCyclicDependency (ctxt, queue, action, fnAddr)
        else queue.Push action; Wait fnAddr
      | Failure e -> Failure e

  do strategy.PopulateInitialAction (entryPoint, mode) |> queue.Push

  interface IFunctionBuildable<'V, 'E, 'Abs, 'FnCtx, 'GlCtx> with
    member __.BuilderState with get() = state

    member __.EntryPoint with get(): Addr = entryPoint

    member __.Mode with get() = mode

    member __.Context with get() = ctxt

    member __.Authorize () =
      assert (state <> InProgress)
      state <- InProgress

    member __.Stop () =
      assert (state = InProgress)
      state <- Stopped

    member __.Finalize () =
      assert (state = InProgress)
      state <- Finished

    member __.Invalidate () =
      assert (state = InProgress)
      state <- Invalid

    member __.Build () =
      build ()

    member __.AddCyclicDependency calleeAddr =
      blacklist.Add calleeAddr |> ignore

    member __.HasCyclicDependency calleeAddr =
      blacklist.Contains calleeAddr

    member __.Reset () =
      fnCtx.Reset ()
      // XXX: cfg reset
      // XXX: bblFactory.Reset ()

    member __.ToFunction () =
      assert (state = Finished)
      let name =
        match hdl.File.TryFindFunctionName entryPoint with
        | Ok name -> name
        | Error _ -> Addr.toFuncName entryPoint
      Function (entryPoint,
                name,
                ircfg,
                ctxt.IsNoRet,
                ctxt.Callees,
                ctxt.Callers)
