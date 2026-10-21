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
/// Encodes the instructions the embedded environment adds to primary opcode 31
/// (Power ISA 2.07B Book II and Book III-E).
/// </summary>
module internal B2R2.Assembly.PPC.AsmEmbedded

open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField

/// A cache-locking instruction, "CT, rA, rB", given its extended opcode and
/// its record bit: CT is the four bits 7:10.
let private cacheLock xo rc ins =
  match ins.Operands with
  | [ Im ct; Rg a; Rg b ] -> xForm 31u (unsigned 4 ct) (gpr a) (gpr b) xo rc
  | _ -> wrongOperands ins

/// The cache-locking instructions.
let private cacheLockEncoders () =
  [ Op.DCBLC, cacheLock 390u 0u
    Op.DCBLQdot, cacheLock 422u 1u
    Op.DCBTLS, cacheLock 166u 0u
    Op.DCBTSTLS, cacheLock 134u 0u
    Op.ICBLC, cacheLock 230u 0u
    Op.ICBLQdot, cacheLock 198u 1u
    Op.ICBTLS, cacheLock 486u 0u ]

/// Every instruction the embedded environment adds.
let embeddedEncoders () =
  cacheLockEncoders ()
