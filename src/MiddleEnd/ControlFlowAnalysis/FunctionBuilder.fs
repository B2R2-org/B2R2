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

open B2R2
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// The main builder for a function, which is responsible for building a
/// function from a given state and a strategy.
type FunctionBuilder<'V,
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
     instrs,
     entryPoint,
     cfgConstructor: IRCFG.IConstructable<'V, 'E, 'Abs>,
     agent: Agent<TaskMessage<'Req, 'Res>>,
     strategy: IFunctionBuildingStrategy<_, _, _, _, _, _, _>,
     noRetAnalyzer) =

  let mutable inProgress = true

  /// ID of the thread that is currently building this function.
  let mutable threadId = -1

  /// This function is invalid; we encountered a fatal error while recovering
  /// the function.
  let mutable isBad = false

  let bblFactory = BBLFactory (hdl, instrs, &threadId)
  let ircfg = cfgConstructor.Construct Imperative
  let state = new 'State ()

  let ms =
    { new IManagerState<'Req, 'Res> with
        member _.Query req =
          agent.PostAndReply (fun ch -> Query (entryPoint, req, ch))
        member _.UpdateDependency (caller, callee) =
          agent.Post <| AddDependency (caller, callee) }

  let ctxt =
    { CFG = ircfg; BBLFactory = bblFactory; State = state; ManagerState = ms }

  let queue = CFGActionQueue<'Act> ()

  /// Entry point of the function that is being built.
  member __.EntryPoint with get(): Addr = entryPoint

  /// Is the function building in progress?
  member __.InProgress
    with get() = inProgress
    and set(v) =
#if CFGDEBUG
      if not v then flushLog threadId else ()
#endif
      inProgress <- v

  /// Which thread is building this function?
  member __.ThreadId with get() = threadId and set(v) = threadId <- v

  /// The current context of the function building process.
  member __.Context with get() = ctxt

  /// Start the recovery process.
  member __.Recover () =
    if queue.IsEmpty () then strategy.OnFinish (ctxt, noRetAnalyzer)
    else
      let action = queue.Pop ()
      match strategy.OnAction (ctxt, queue, action) with
      | Success -> __.Recover ()
      | Postponement -> queue.Push action; Postponement
      | Failure e -> Failure e

  member __.Reset () =
    state.Reset ()
    // XXX: cfg reset
    // XXX: bblFactory.Reset ()

  /// Convert this builder to a function.
  member __.ToFunction () =
    assert (not isBad && not inProgress)
    Function (entryPoint, ircfg)

  interface IValidityCheck with
    member __.IsValid with get() = not isBad

    member __.Invalidate () =
      isBad <- true
      __.InProgress <- false
