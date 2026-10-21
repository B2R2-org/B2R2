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

/// <summary>
/// The embedded floating-point categories of the Signal Processing Engine's
/// processors, which keep floating-point numbers in the general registers: a
/// single in a word (the scalar ones in the low word of the register, the
/// vector ones in both words) and a double in the whole register. They do not
/// follow IEEE 754 to the letter: an infinity, a NaN or a denormalized number
/// is not an operand but an input error, which has a default result of its
/// own, and a result that overflows or underflows is the largest number or a
/// zero, never an infinity or a denormalized number. SPEFSCR records what
/// each element found.
/// </summary>
module internal B2R2.FrontEnd.PPC.SPEFloatLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.SPELifter

/// The sign instructions on the words of the registers: the same operation on
/// the low word of the register (the scalar single, which leaves the rest of
/// RT as it is), on both words (the vector of two singles) or on the high word
/// of a double, which holds its sign.
let private signOnWords ins bld high low (op: Expr -> Expr) =
  lift bld ins {
    let struct (rt, ra) = getTwoOprs ins
    let struct (ah, al) = wordsOf bld ra
    if high then
      putWords bld rt (op ah) (if low then op al else al)
    else
      putLow bld rt (op al)
  }

let private clearSign (word: Expr) = word .& numU32 0x7fffffffu 32<rt>

let private setSign (word: Expr) = word .| numU32 0x80000000u 32<rt>

let private flipSign (word: Expr) = word <+> numU32 0x80000000u 32<rt>

let efsabs ins bld = signOnWords ins bld false true clearSign

let efsnabs ins bld = signOnWords ins bld false true setSign

let efsneg ins bld = signOnWords ins bld false true flipSign

let evfsabs ins bld = signOnWords ins bld true true clearSign

let evfsnabs ins bld = signOnWords ins bld true true setSign

let evfsneg ins bld = signOnWords ins bld true true flipSign

let efdabs ins bld = signOnWords ins bld true false clearSign

let efdnabs ins bld = signOnWords ins bld true false setSign

let efdneg ins bld = signOnWords ins bld true false flipSign
