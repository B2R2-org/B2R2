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

open System.Runtime.InteropServices
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

and ExternalCallEventHandler =
  delegate of BitVector list * EvalState -> unit

and SideEffectEventHandler =
  delegate of SideEffect * EvalState -> unit

and StmtEvalEventHandler =
  delegate of LowUIR.Stmt -> unit

/// The main evaluation state that will be updated by evaluating every statement
/// encountered during the course of execution. This can be considered as a
/// single-threaded CPU context.
and EvalState (regs, temps, lbls, mem, ignoreUndef) =
  let mutable pc = 0UL
  let mutable stmtIdx = 0
  let mutable mode = ArchOperationMode.NoMode
  let mutable currentInsLen = 0u
  let mutable isInstrTerminated = false
  let mutable needToEvaluateIEMark = false
  let mutable perInstrHdl = PerInstrHandler id
  let mutable loadEventHdl = LoadEventHandler (fun _ _ _ -> ())
  let mutable loadFailureHdl = LoadFailureEventHandler (fun _ _ _ e -> Error e)
  let mutable storeEventHdl = StoreEventHandler (fun _ _ _ -> ())
  let mutable putEventHdl = PutEventHandler (fun _ _ -> ())
  let mutable externalCallEventHdl = ExternalCallEventHandler (fun _ _ -> ())
  let mutable sideEffectHdl = SideEffectEventHandler (fun _ _ -> ())
  let mutable stmtEvalHdl = StmtEvalEventHandler ignore

  /// This constructor will simply create a fresh new EvalState.
  new () =
    EvalState (Variables (Variables.MaxNumVars),
               Variables (Variables.MaxNumTemporaries),
               Labels (),
               NonsharableMemory () :> Memory,
               false)

  /// This constructor will simply create a fresh new EvalState with the given
  /// memory.
  new (mem) =
    EvalState (Variables (Variables.MaxNumVars),
               Variables (Variables.MaxNumTemporaries),
               Labels (),
               mem,
               false)

  /// This constructor will simply create a fresh new EvalState. Depending on
  /// the `ignoreUndef` parameter, the evaluator using this EvalState will
  /// silently ignore Undef values. Such a feature is only useful for some
  /// static analyses.
  new (ignoreUndef) =
    EvalState (Variables (Variables.MaxNumVars),
               Variables (Variables.MaxNumTemporaries),
               Labels (),
               NonsharableMemory () :> Memory,
               ignoreUndef)

  /// Current PC.
  member __.PC with get() = pc and set(addr) = pc <- addr

  /// The current index of the statement to evaluate within the scope of a
  /// machine instruction. This index behaves like a PC for statements of an
  /// instruction.
  member __.StmtIdx with get() = stmtIdx and set(i) = stmtIdx <- i

  /// Architecture mode.
  member __.Mode with get() = mode and set(m) = mode <- m

  /// Current instruction length.
  member __.CurrentInsLen
    with get() = currentInsLen and set(l) = currentInsLen <- l

  /// Named register values.
  member __.Registers with get() = regs

  /// Temporary variable values.
  member __.Temporaries with get() = temps

  /// Memory.
  member __.Memory with get() = mem

  /// Store labels and their corresponding statement indices.
  member __.Labels with get() = lbls

  /// Indicate whether to terminate the current instruction or not. This flag is
  /// set to true when we encounter an inter-jump statement or SideEffect, so
  /// that we can ignore the rest of the statements.
  member __.IsInstrTerminated
    with get() = isInstrTerminated and set(f) = isInstrTerminated <- f

  /// Indicate whether to evaluate IEMark while ignoring the other instructions.
  /// This means, the evaluation of the instruction is over, but we need to
  /// advance the PC to the next instruction using IEMark. Thus, this flag is
  /// only meaningful when `IsInstrTerminated` is true.
  member __.NeedToEvaluateIEMark
    with get() = needToEvaluateIEMark and set(f) = needToEvaluateIEMark <- f

  /// Whether to ignore statements that cannot be evaluated due to undef values.
  /// This is particularly useful to quickly check some constants.
  member __.IgnoreUndef with get() = ignoreUndef

  /// Update the current statement index to be the next (current + 1) statement.
  member inline __.NextStmt () =
    __.StmtIdx <- __.StmtIdx + 1

  /// Stop evaluating further statements of the current instruction, and move on
  /// the next instruction.
  member __.AbortInstr ([<Optional; DefaultParameterValue(false)>]
                        needToUpdatePC: bool) =
    isInstrTerminated <- true
    needToEvaluateIEMark <- needToUpdatePC
    __.NextStmt ()

  /// Get the value of the given temporary variable.
  member inline __.TryGetTmp n =
    match __.Temporaries.TryGet (n) with
    | Ok v -> Def v
    | Error _ -> Undef

  /// Get the value of the given temporary variable.
  member inline __.GetTmp n =
    __.Temporaries.Get (n)

  /// Set the value for the given temporary variable.
  member inline __.SetTmp n v =
    __.Temporaries.Set n v

  /// Unset the given temporary variable.
  member inline __.UnsetTmp n =
    __.Temporaries.Unset n

  /// Get the value of the given register.
  member inline __.TryGetReg (r: RegisterID) =
    match __.Registers.TryGet (int r) with
    | Ok v -> Def v
    | Error _ -> Undef

  /// Get the value of the given register.
  member inline __.GetReg (r: RegisterID) =
    __.Registers.Get (int r)

  /// Set the value for the given register.
  member inline __.SetReg (r: RegisterID) v =
    __.Registers.Set (int r) v

  /// Unset the given register.
  member inline __.UnsetReg (r: RegisterID) =
    __.Registers.Unset (int r)

  /// Advance PC by `amount`.
  member inline __.AdvancePC (amount: uint32) =
    __.PC <- __.PC + uint64 amount

  /// Initialize the current context by updating register values.
  member __.InitializeContext pc regs =
    __.PC <- pc
    regs |> List.iter (fun (r, v) -> __.SetReg r v)

  /// Go to the statement of the given label.
  member inline __.GoToLabel lbl =
    __.StmtIdx <- __.Labels.Index lbl

  /// Get ready for evaluating a new instruction.
  member inline __.PrepareInstrEval stmts =
    __.IsInstrTerminated <- false
    __.NeedToEvaluateIEMark <- false
    __.Labels.Update stmts
    __.StmtIdx <- 0

  /// Per-instruction handler.
  member __.PerInstrHandler
    with get() = perInstrHdl and set(f) = perInstrHdl <- f

  /// Memory load event handler.
  member __.LoadEventHandler
    with get() = loadEventHdl and set(f) = loadEventHdl <- f

  /// Memory load failure (access violation) event handler.
  member __.LoadFailureEventHandler
    with get() = loadFailureHdl and set(f) = loadFailureHdl <- f

  /// Memory store event handler.
  member __.StoreEventHandler
    with get() = storeEventHdl and set(f) = storeEventHdl <- f

  /// Put event handler. The first parameter is PC, and the second is the value
  /// that is put to the destination.
  member __.PutEventHandler
    with get() = putEventHdl and set(f) = putEventHdl <- f

  /// External call event handler.
  member __.ExternalCallEventHandler
    with get() = externalCallEventHdl and set(f) = externalCallEventHdl <- f

  /// Side-effect event handler.
  member __.SideEffectEventHandler
    with get() = sideEffectHdl and set(f) = sideEffectHdl <- f

  /// Statement evaluation event handler.
  member __.StmtEvalEventHandler
    with get() = stmtEvalHdl and set(f) = stmtEvalHdl <- f

  member internal __.OnInstr st =
    __.PerInstrHandler.Invoke st

  member internal __.OnLoad pc addr v =
    __.LoadEventHandler.Invoke (pc, addr, v)

  member internal __.OnLoadFailure pc addr rt e =
    __.LoadFailureEventHandler.Invoke (pc, addr, rt, e)

  member internal __.OnStore pc addr v =
    __.StoreEventHandler.Invoke (pc, addr, v)

  member internal __.OnPut pc v =
    __.PutEventHandler.Invoke (pc, v)

  member internal __.OnExternalCall args st =
    __.ExternalCallEventHandler.Invoke (args, st)

  member internal __.OnSideEffect eff st =
    __.SideEffectEventHandler.Invoke (eff, st)

  member internal __.OnStmtEval stmt =
    __.StmtEvalEventHandler.Invoke (stmt)

  /// Make a copy of this EvalState with a given new Memory.
  member __.Clone (newMem) =
    EvalState (regs.Clone (),
               temps.Clone (),
               lbls.Clone (),
               newMem,
               ignoreUndef,
               PC=pc,
               StmtIdx=stmtIdx,
               Mode=mode,
               CurrentInsLen=currentInsLen,
               IsInstrTerminated=isInstrTerminated,
               NeedToEvaluateIEMark=needToEvaluateIEMark,
               PerInstrHandler=perInstrHdl,
               LoadEventHandler=loadEventHdl,
               LoadFailureEventHandler=loadFailureHdl,
               StoreEventHandler=storeEventHdl,
               PutEventHandler=putEventHdl,
               ExternalCallEventHandler=externalCallEventHdl,
               SideEffectEventHandler=sideEffectHdl,
               StmtEvalEventHandler=stmtEvalHdl)

  /// Make a copy of this EvalState.
  member __.Clone () = __.Clone (mem)
