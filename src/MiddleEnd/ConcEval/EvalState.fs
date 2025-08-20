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

/// Represents the main evaluation state that will be updated by evaluating
/// every LowUIR statement encountered during the course of execution. This can
/// be considered as a single-threaded CPU context.
type EvalState(regs, temps, lbls, mem, ignoreUndef) =
  let mutable pc = 0UL
  let mutable stmtIdx = 0
  let mutable currentInsLen = 0u
  let mutable isInstrTerminated = false
  let mutable needToEvaluateIEMark = false
  let mutable loadFailureHdl = LoadFailureEventHandler(fun _ _ _ e -> Error e)
  let mutable externalCallEventHdl = ExternalCallEventHandler(fun _ _ -> ())
  let mutable sideEffectHdl = SideEffectEventHandler(fun _ _ -> ())

  /// This constructor will simply create a fresh new EvalState.
  new() =
    EvalState(Variables(),
              Variables(),
              Labels(),
              NonsharableMemory() :> IMemory,
              false)

  /// This constructor will simply create a fresh new EvalState with the given
  /// memory.
  new(mem) =
    EvalState(Variables(),
              Variables(),
              Labels(),
              mem,
              false)

  /// This constructor will simply create a fresh new EvalState. Depending on
  /// the `ignoreUndef` parameter, the evaluator using this EvalState will
  /// silently ignore Undef values. Such a feature is only useful for some
  /// static analyses.
  new(ignoreUndef) =
    EvalState(Variables(),
              Variables(),
              Labels(),
              NonsharableMemory() :> IMemory,
              ignoreUndef)

  /// Current PC.
  member _.PC with get() = pc and set(addr) = pc <- addr

  /// The current index of the statement to evaluate within the scope of a
  /// machine instruction. This index behaves like a PC for statements of an
  /// instruction.
  member _.StmtIdx with get() = stmtIdx and set(i) = stmtIdx <- i

  /// Current instruction length.
  member _.CurrentInsLen
    with get() = currentInsLen and set(l) = currentInsLen <- l

  /// Named register values.
  member _.Registers with get() = regs

  /// Temporary variable values.
  member _.Temporaries with get() = temps

  /// Memory.
  member _.Memory with get() = mem

  /// Store labels and their corresponding statement indices.
  member _.Labels with get() = lbls

  /// Indicate whether to terminate the current instruction or not. This flag is
  /// set to true when we encounter an inter-jump statement or SideEffect, so
  /// that we can ignore the rest of the statements.
  member _.IsInstrTerminated
    with get() = isInstrTerminated and set(f) = isInstrTerminated <- f

  /// Indicate whether to evaluate IEMark while ignoring the other instructions.
  /// This means, the evaluation of the instruction is over, but we need to
  /// advance the PC to the next instruction using IEMark. Thus, this flag is
  /// only meaningful when `IsInstrTerminated` is true.
  member _.NeedToEvaluateIEMark
    with get() = needToEvaluateIEMark and set(f) = needToEvaluateIEMark <- f

  /// Whether to ignore statements that cannot be evaluated due to undef values.
  /// This is particularly useful to quickly check some constants.
  member _.IgnoreUndef with get() = ignoreUndef

  /// Update the current statement index to be the next (current + 1) statement.
  member inline this.NextStmt() =
    this.StmtIdx <- this.StmtIdx + 1

  /// Stop evaluating further statements of the current instruction, and move on
  /// the next instruction.
  member this.AbortInstr([<Optional; DefaultParameterValue(false)>]
                         needToUpdatePC: bool) =
    isInstrTerminated <- true
    needToEvaluateIEMark <- needToUpdatePC
    this.NextStmt()

  /// Get the value of the given temporary variable.
  member inline this.TryGetTmp n =
    match this.Temporaries.TryGet(n) with
    | Ok v -> Def v
    | Error _ -> Undef

  /// Get the value of the given temporary variable.
  member inline this.GetTmp n =
    this.Temporaries.Get(n)

  /// Set the value for the given temporary variable.
  member inline this.SetTmp(n, v) =
    this.Temporaries.Set(n, v)

  /// Unset the given temporary variable.
  member inline this.UnsetTmp n =
    this.Temporaries.Unset n

  /// Get the value of the given register.
  member inline this.TryGetReg(r: RegisterID) =
    match this.Registers.TryGet(int r) with
    | Ok v -> Def v
    | Error _ -> Undef

  /// Get the value of the given register.
  member inline this.GetReg(r: RegisterID) =
    this.Registers.Get(int r)

  /// Set the value for the given register.
  member inline this.SetReg(r: RegisterID, v) =
    this.Registers.Set(int r, v)

  /// Unset the given register.
  member inline this.UnsetReg(r: RegisterID) =
    this.Registers.Unset(int r)

  /// Advance PC by `amount`.
  member inline this.AdvancePC(amount: uint32) =
    this.PC <- this.PC + uint64 amount

  /// Initialize the current context by updating register values.
  member this.InitializeContext(pc, regs) =
    this.PC <- pc
    regs |> Array.iter (fun (r, v) -> this.SetReg(r, v))

  /// Go to the statement of the given label.
  member inline this.GoToLabel lbl =
    this.StmtIdx <- this.Labels.Index lbl

  /// Get ready for evaluating a new instruction.
  member inline this.PrepareInstrEval stmts =
    this.IsInstrTerminated <- false
    this.NeedToEvaluateIEMark <- false
    this.Labels.Update stmts
    this.StmtIdx <- 0

  /// Memory load failure (access violation) event handler.
  member _.LoadFailureEventHandler
    with get() = loadFailureHdl and set(f) = loadFailureHdl <- f

  /// External call event handler.
  member _.ExternalCallEventHandler
    with get() = externalCallEventHdl and set(f) = externalCallEventHdl <- f

  /// Side-effect event handler.
  member _.SideEffectEventHandler
    with get() = sideEffectHdl and set(f) = sideEffectHdl <- f

  member internal this.OnLoadFailure(pc, addr, rt, e) =
    this.LoadFailureEventHandler.Invoke(pc, addr, rt, e)

  member internal this.OnExternalCall(args, st) =
    this.ExternalCallEventHandler.Invoke(args, st)

  member internal this.OnSideEffect(eff, st) =
    this.SideEffectEventHandler.Invoke(eff, st)

  /// Make a copy of this EvalState with a given new Memory.
  member _.Clone(newMem) =
    EvalState(regs.Clone(),
              temps.Clone(),
              lbls.Clone(),
              newMem,
              ignoreUndef,
              PC = pc,
              StmtIdx = stmtIdx,
              CurrentInsLen = currentInsLen,
              IsInstrTerminated = isInstrTerminated,
              NeedToEvaluateIEMark = needToEvaluateIEMark,
              LoadFailureEventHandler = loadFailureHdl,
              ExternalCallEventHandler = externalCallEventHdl,
              SideEffectEventHandler = sideEffectHdl)

  /// Make a copy of this EvalState.
  member this.Clone() = this.Clone(mem)

/// Represents a callback function that is invoked when a memory load fails.
and LoadFailureEventHandler =
  delegate of Addr * Addr * RegType * ErrorCase -> Result<BitVector, ErrorCase>

/// Represents a callback function that is invoked when an external call is
/// encountered during the evaluation.
and ExternalCallEventHandler =
  delegate of BitVector list * EvalState -> unit

/// Represents a callback function that is invoked when a side effect is
/// encountered during the evaluation.
and SideEffectEventHandler =
  delegate of SideEffect * EvalState -> unit
