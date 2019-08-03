(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.ConcEval

open B2R2
open B2R2.BinIR

type Context () =
  /// The current index of the statement to evaluate within the scope of a
  /// machine instruction. This index behaves like a PC for statements of an
  /// instruction.
  member val StmtIdx = 0 with get, set

  /// Store named register values.
  member val Registers = Variables<RegisterID>() with get

  /// Store temporary variable values.
  member val Temporaries = Variables<int>() with get

  /// Store labels and their corresponding statement indices.
  member val Labels = Labels () with get

  /// Architecture mode.
  member val Mode = ArchOperationMode.NoMode with get, set

type EvalCallBacks () =
  /// Memory load event handler.
  member val LoadEventHandler: Addr -> Addr -> BitVector -> unit =
    fun _ _ _ -> () with get, set

  /// Memory store event handler.
  member val StoreEventHandler: Addr -> Addr -> BitVector -> unit =
    fun _ _ _ -> () with get, set

  /// Put event handler. The first parameter is PC, and the second is the value
  /// that is put to the destination.
  member val PutEventHandler: Addr -> EvalValue -> unit =
    fun _ _ -> () with get, set

  /// Side-effect event handler.
  member val SideEffectEventHandler: SideEffect -> EvalState -> EvalState =
    fun _ st -> st with get, set

  /// Statement evaluation event handler.
  member val StmtEvalEventHandler: LowUIR.Stmt -> unit =
    fun _ -> () with get, set

  member __.OnLoad pc addr v = __.LoadEventHandler pc addr v

  member __.OnStore pc addr v = __.StoreEventHandler pc addr v

  member __.OnPut pc v = __.PutEventHandler pc v

  member __.OnSideEffect eff = __.SideEffectEventHandler eff

  member __.OnStmtEval stmt = __.StmtEvalEventHandler stmt

/// The main evaluation state that will be updated by evaluating every statement
/// encountered during the course of execution.
and EvalState (?reader, ?ignoreundef) =
  /// Memory reader.
  let reader = defaultArg reader (fun _ _ -> None)

  /// The current thread ID. We use thread IDs starting from zero. We assign new
  /// thread IDs by incrementing it by one at a time. The first thread is 0, the
  /// second is 1, and so on.
  member val ThreadId = 0 with get, set

  /// The current program counter.
  member val PC: Addr = 0UL with get, set

  /// Per-thread context.
  member val Contexts: Context [] = [||] with get, set

  /// Memory.
  member val Memory = Memory (Reader = reader) with get

  /// Callback functions.
  member val Callbacks = EvalCallBacks () with get

  /// Indicate whether to terminate the current instruction or not. This flag is
  /// set to true when we encounter an ISMark within a block. In other words, we
  /// should proceed to the next instruction if this flag is set to true.
  member val TerminateInstr = false with get, set

  /// Whether to ignore statements that cannot be evaluated due to undef values.
  /// This is particularly useful to quickly check some constants.
  member val IgnoreUndef = defaultArg ignoreundef false with get

  /// Prepare the initial context of the given thread id (tid). This function
  /// will set the current thread to be tid.
  static member PrepareContext (st: EvalState) tid pc regs =
    let st = EvalState.ContextSwitch tid st
    let st = EvalState.SetPC st pc
    regs |> List.fold (fun st (r, v) -> EvalState.SetReg st r v) st

  /// Get the context of a specific thread.
  static member inline GetContext (st: EvalState) tid =
    st.Contexts.[tid]

  /// Get the current context of the current thread.
  static member inline GetCurrentContext (st: EvalState) =
    st.Contexts.[st.ThreadId]

  /// Thread context switch. If the given thread ID does not exist, we create a
  /// new context for it.
  static member ContextSwitch tid (st: EvalState) =
    st.ThreadId <- tid
    if Array.length st.Contexts <= tid then
      st.Contexts <- Array.append st.Contexts [| Context () |]
    else ()
    st

  /// Update the current statement index to be the next (current + 1) statement.
  static member NextStmt (st: EvalState) =
    st.Contexts.[st.ThreadId].StmtIdx <- st.Contexts.[st.ThreadId].StmtIdx + 1
    st

  /// Stop evaluating further statements of the current instruction, and move on
  /// the next instruction.
  static member AbortInstr (st: EvalState) =
    st.TerminateInstr <- true
    EvalState.NextStmt st

  /// Start evaluating the instruction.
  static member StartInstr (st: EvalState) pc =
    st.PC <- pc
    st.TerminateInstr <- false
    st

  /// Should we stop evaluating further statements of the current instruction,
  /// and move on to the next instruction?
  static member IsInstrTerminated (st: EvalState) =
    st.TerminateInstr

  /// Get the value of the given temporary variable.
  static member GetTmp (st: EvalState) n =
    st.Contexts.[st.ThreadId].Temporaries.Get (n)

  /// Set the value for the given temporary variable.
  static member SetTmp (st: EvalState) n v =
    st.Contexts.[st.ThreadId].Temporaries.Set n v
    st

  /// Get the value of the given register.
  static member GetReg (st: EvalState) r =
    st.Contexts.[st.ThreadId].Registers.Get r

  /// Set the value for the given register.
  static member SetReg (st: EvalState) r v =
    st.Contexts.[st.ThreadId].Registers.Set r v
    st

  /// Set the program counter (PC).
  static member SetPC (st: EvalState) addr =
    st.PC <- addr
    st

  /// Go to the statement of the given label.
  static member GoToLabel (st: EvalState) lbl =
    st.Contexts.[st.ThreadId].StmtIdx <-
      st.Contexts.[st.ThreadId].Labels.Index lbl
    st

  /// Get ready for block-level evaluation (evalBlock).
  static member PrepareBlockEval stmts (st: EvalState) =
    st.Contexts.[st.ThreadId].Labels.Update stmts
    st.Contexts.[st.ThreadId].StmtIdx <- 0
    st

  /// Get the current architecture operation mode.
  static member GetMode (st: EvalState) =
    st.Contexts.[st.ThreadId].Mode

  /// Set the architecture operation mode.
  static member SetMode (st: EvalState) mode =
    st.Contexts.[st.ThreadId].Mode <- mode
    st

  /// Delete temporary states variables and get ready for evaluating the next
  /// block of isntructions.
  static member CleanUp (st: EvalState) =
    st.Contexts.[st.ThreadId].Temporaries.Clear ()
    st
