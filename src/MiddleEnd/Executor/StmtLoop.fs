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

namespace B2R2.MiddleEnd.Executor

open B2R2.BinIR.LowUIR

/// Represents an evaluation state that walks the statements lifted from a
/// single machine instruction.
type IStmtCursor =
  /// Index of the statement to evaluate next within the current instruction.
  abstract StmtIdx: int

  /// Whether a statement has ended the current instruction.
  abstract IsInstrTerminated: bool

/// Represents how the statement loop of a single instruction came to an end.
type StmtLoopEnd<'State, 'Outcome> =
  /// The instruction ended, leaving the given state behind.
  | Completed of 'State
  /// A statement reported the given outcome, which ended the loop before the
  /// instruction itself did.
  | Interrupted of 'Outcome

/// Provides the statement loop of a single instruction, which every evaluator
/// drives and none of them should rebuild.
[<RequireQualifiedAccess>]
module StmtLoop =
  (* Two rules are easy to get wrong, which is why this loop lives here alone:
     a statement advances StmtIdx itself, so the loop never does; and a
     statement that ends the instruction is the end of it, which is why the
     loop reads no statement by position and holds no belief about which one
     comes last, since optimization trims a trailing IEMark that follows an
     inter-jump. *)
  /// Hands every statement of the instruction to `step`, carrying on with the
  /// state that `next` reads out of a step's outcome and stopping as soon as
  /// it reads none.
  let rec run step next (st: #IStmtCursor) (stmts: Stmt[]) =
    if st.StmtIdx >= Array.length stmts || st.IsInstrTerminated then
      Completed st
    else
      let outcome = step st stmts[st.StmtIdx]
      match next st outcome with
      | ValueSome st -> run step next st stmts
      | ValueNone -> Interrupted outcome

  /// Carries on with the state at hand, whatever a step reports.
  let carryOn st _ = ValueSome st

  /// Carries on with the state at hand while a step reports success.
  let whileOk st = function
    | Ok() -> ValueSome st
    | Error _ -> ValueNone
