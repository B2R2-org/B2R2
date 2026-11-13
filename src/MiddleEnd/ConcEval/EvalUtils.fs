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
open B2R2.BinIR
open B2R2.BinIR.LowUIR

/// The one-bit true value that evaluated conditions are tested against.
let tr = BitVector.One 1<rt>

/// Unsets the register or temporary that the given assignment target names, so
/// that it reads back as undefined rather than keeping a stale value.
let markUndefAfterFailure (st: ConcState) lhs =
  match lhs with
  | Var(RegisterID = n) -> st.UnsetReg n
  | TempVar(Index = n) -> st.UnsetTmp n
  | _ -> ()

/// Hands a side effect to the state's handler, which is what carries it out.
/// Whether the statements after it run is the IR's to say rather than the
/// handler's: an effect that takes control away from the instruction ends it
/// and advances the PC past it, unless the handler has ended it already, and
/// any other effect lets evaluation go on to the next statement.
let evalSideEffect (st: ConcState) eff =
  st.OnSideEffect(eff, st)
  if st.IsInstrTerminated then ()
  elif SideEffect.endsInstruction eff then st.AbortInstr true
  else st.NextStmt()
