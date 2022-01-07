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

namespace B2R2.MiddleEnd.ConcEval

open B2R2
open B2R2.BinIR

type PerInstrHandler =
  delegate of EvalState -> EvalState

and LoadEventHandler =
  delegate of Addr * Addr * BitVector -> unit

and LoadFailureEventHandler =
  delegate of Addr * Addr * RegType * ErrorCase -> Result<BitVector, ErrorCase>

and StoreEventHandler =
  delegate of Addr * Addr * BitVector -> unit

and PutEventHandler =
  delegate of Addr * BitVector -> unit

and SideEffectEventHandler =
  delegate of SideEffect * EvalState -> unit

and StmtEvalEventHandler =
  delegate of LowUIR.Stmt -> unit

and EvalCallBacks () =
  /// Per-instruction handler.
  member val PerInstrHandler: PerInstrHandler =
    PerInstrHandler id with get, set

  /// Memory load event handler.
  member val LoadEventHandler: LoadEventHandler =
    LoadEventHandler (fun _ _ _ -> ()) with get, set

  /// Memory load failure (access violation) event handler.
  member val LoadFailureEventHandler: LoadFailureEventHandler =
    LoadFailureEventHandler (fun _ _ _ e -> Error e) with get, set

  /// Memory store event handler.
  member val StoreEventHandler: StoreEventHandler =
    StoreEventHandler (fun _ _ _ -> ()) with get, set

  /// Put event handler. The first parameter is PC, and the second is the value
  /// that is put to the destination.
  member val PutEventHandler: PutEventHandler =
    PutEventHandler (fun _ _ -> ()) with get, set

  /// Side-effect event handler.
  member val SideEffectEventHandler: SideEffectEventHandler =
    SideEffectEventHandler (fun _ st -> ()) with get, set

  /// Statement evaluation event handler.
  member val StmtEvalEventHandler: StmtEvalEventHandler =
    StmtEvalEventHandler (fun _ -> ()) with get, set

  member __.OnInstr st =
    __.PerInstrHandler.Invoke st

  member __.OnLoad pc addr v =
    __.LoadEventHandler.Invoke (pc, addr, v)

  member __.OnLoadFailure pc addr rt e =
    __.LoadFailureEventHandler.Invoke (pc, addr, rt, e)

  member __.OnStore pc addr v =
    __.StoreEventHandler.Invoke (pc, addr, v)

  member __.OnPut pc v =
    __.PutEventHandler.Invoke (pc, v)

  member __.OnSideEffect eff st =
    __.SideEffectEventHandler.Invoke (eff, st)

  member __.OnStmtEval stmt =
    __.StmtEvalEventHandler.Invoke (stmt)

/// The main evaluation state that will be updated by evaluating every statement
/// encountered during the course of execution.
and EvalState (?memory, ?ignoreundef) =
  let m = Option.defaultWith (fun () -> NonsharableMemory () :> Memory) memory

  /// The current thread ID. We use thread IDs starting from zero. We assign new
  /// thread IDs by incrementing it by one at a time. The first thread is 0, the
  /// second is 1, and so on.
  member val ThreadId = 0 with get, set

  /// Current PC.
  member __.PC
    with get() = __.Contexts[__.ThreadId].PC
     and set(addr) = __.Contexts[__.ThreadId].PC <- addr

  /// Per-thread context.
  member val Contexts: Context [] = [||] with get, set

  /// Memory.
  member val Memory = m with get

  /// Callback functions.
  member val Callbacks = EvalCallBacks () with get

  /// Indicate whether to terminate the current instruction or not. This flag is
  /// set to true when we encounter an inter-jump statement, so that we can
  /// ignore the rest of the statements.
  member val IsInstrTerminated = false with get, set

  /// Indicate whether we are in an abnormal state. If so, the rest of the
  /// evaluation should be aborted. This flag should never be set in normal
  /// situation.
  member val InPrematureState = false with get, set

  /// Whether to ignore statements that cannot be evaluated due to undef values.
  /// This is particularly useful to quickly check some constants.
  member val IgnoreUndef = defaultArg ignoreundef false with get

  /// Get the context of a specific thread.
  member inline __.GetContext tid =
    __.Contexts[tid]

  /// Get the current context of the current thread.
  member inline __.GetCurrentContext () =
    __.Contexts[__.ThreadId]

  /// Update the current statement index to be the next (current + 1) statement.
  member inline __.NextStmt () =
    __.Contexts[__.ThreadId].StmtIdx <- __.Contexts[__.ThreadId].StmtIdx + 1

  /// Stop evaluating further statements of the current instruction, and move on
  /// the next instruction.
  member inline __.AbortInstr () =
    __.IsInstrTerminated <- true
    __.NextStmt ()

  /// Start evaluating the instruction.
  member inline __.StartInstr () =
    __.IsInstrTerminated <- false

  /// Get the value of the given temporary variable.
  member inline __.TryGetTmp n =
    let found, v = __.Contexts[__.ThreadId].Temporaries.TryGet (n)
    if found then Def v else Undef

  /// Get the value of the given temporary variable.
  member inline __.GetTmp n =
    __.Contexts[__.ThreadId].Temporaries.Get (n)

  /// Set the value for the given temporary variable.
  member inline __.SetTmp n v =
    __.Contexts[__.ThreadId].Temporaries.Set n v

  /// Unset the given temporary variable.
  member inline __.UnsetTmp n =
    __.Contexts[__.ThreadId].Temporaries.Unset n

  /// Get the value of the given register.
  member inline __.TryGetReg r =
    let found, v = __.Contexts[__.ThreadId].Registers.TryGet r
    if found then Def v else Undef

  /// Get the value of the given register.
  member inline __.GetReg r =
    __.Contexts[__.ThreadId].Registers.Get r

  /// Set the value for the given register.
  member inline __.SetReg r v =
    __.Contexts[__.ThreadId].Registers.Set r v

  /// Unset the given register.
  member inline __.UnsetReg r =
    __.Contexts[__.ThreadId].Registers.Unset r

  /// Get the program counter (PC).
  member inline __.GetPC =
    __.PC

  /// Set the program counter (PC).
  member inline __.SetPC addr =
    __.PC <- addr

  member inline __.IncPC (amount: uint32) =
    __.PC <- __.PC + uint64 amount

  /// Thread context switch. If the given thread ID does not exist, we create a
  /// new context for it.
  member __.ContextSwitch tid =
    __.ThreadId <- tid
    if Array.length __.Contexts <= tid then
      __.Contexts <- Array.append __.Contexts [| Context () |]
    else ()

  /// Prepare the initial context of the given thread id (tid). This function
  /// will set the current thread to be tid.
  member __.PrepareContext tid pc regs =
    __.ContextSwitch tid
    __.SetPC pc
    regs |> List.iter (fun (r, v) -> __.SetReg r v)

  /// Go to the statement of the given label.
  member inline __.GoToLabel lbl =
    let ctxt = __.Contexts[__.ThreadId]
    ctxt.StmtIdx <- ctxt.Labels.Index lbl

  /// Get ready for evaluating an instruction.
  member inline __.PrepareInstrEval stmts =
    __.StartInstr ()
    __.Contexts[__.ThreadId].Labels.Update stmts
    __.Contexts[__.ThreadId].StmtIdx <- 0

  /// Get the current architecture operation mode.
  member inline __.GetMode () =
    __.Contexts[__.ThreadId].Mode

  /// Set the architecture operation mode.
  member inline __.SetMode mode =
    __.Contexts[__.ThreadId].Mode <- mode

  /// Delete temporary states variables and get ready for evaluating the next
  /// block of isntructions.
  member inline __.CleanUp () =
    __.Contexts[__.ThreadId].Temporaries.Clear ()
