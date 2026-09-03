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

module internal B2R2.MiddleEnd.ConcEval.EvalUtils

open B2R2
open B2R2.BinIR.LowUIR

/// The one-bit true value that evaluated conditions are tested against.
let tr = BitVector.One 1<rt>

/// Unsets the register or temporary that the given assignment target names, so
/// that it reads back as undefined rather than keeping a stale value.
let markUndefAfterFailure (st: EvalState) lhs =
  match lhs with
  | Var(_, n, _, _) -> st.UnsetReg n
  | TempVar(_, n, _) -> st.UnsetTmp n
  | _ -> ()

(* The statement loop of a single instruction, which both evaluators drive and
   which no consumer should have to rebuild. Two rules are easy to get wrong: a
   statement advances StmtIdx itself, so the loop never does; and a statement
   that ends the instruction is the end of it, which is why the loop reads no
   statement by position and holds no belief about which one comes last. The
   two loops below differ only in how a step reports failure, and are kept side
   by side so that the rules cannot drift apart. *)
let rec evalStmtsWith step (st: EvalState) (stmts: Stmt[]) =
  if st.StmtIdx >= Array.length stmts || st.IsInstrTerminated then
    ()
  else
    step st stmts[st.StmtIdx]
    evalStmtsWith step st stmts

let rec tryEvalStmtsWith step (st: EvalState) (stmts: Stmt[]) =
  if st.StmtIdx >= Array.length stmts || st.IsInstrTerminated then
    Ok()
  else
    match step st stmts[st.StmtIdx] with
    | Ok() -> tryEvalStmtsWith step st stmts
    | error -> error
