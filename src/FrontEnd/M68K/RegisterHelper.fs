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

namespace B2R2.FrontEnd.M68K

open System.Runtime.CompilerServices
open B2R2

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.M68K.Tests")>]
do ()

/// Shortcut for Register type.
type internal R = Register

/// Provides several useful functions for working with m68k registers.
[<RequireQualifiedAccess>]
module internal RegisterHelper =
  (* Every model of the family gives its general registers and its control
     registers 32 bits, and MOVEC transfers a control register as a long word
     however few bits the register itself is implemented with. The condition
     code register is the low byte of the status register, and a floating-point
     data register always holds an extended-precision value. *)
  let toRegType = function
    | R.D0 | R.D1 | R.D2 | R.D3 | R.D4 | R.D5 | R.D6 | R.D7
    | R.A0 | R.A1 | R.A2 | R.A3 | R.A4 | R.A5 | R.A6 | R.A7
    | R.PC | R.USP | R.ISP | R.MSP | R.VBR | R.SFC | R.DFC
    | R.CACR | R.CAAR | R.TC | R.ITT0 | R.ITT1 | R.DTT0 | R.DTT1
    | R.MMUSR | R.URP | R.SRP | R.FPCR | R.FPSR | R.FPIAR -> 32<rt>
    | R.CCR -> 8<rt>
    | R.SR -> 16<rt>
    | R.FP0 | R.FP1 | R.FP2 | R.FP3
    | R.FP4 | R.FP5 | R.FP6 | R.FP7 -> 80<rt>
    | _ -> Terminator.impossible ()

  /// Returns the data register that the given three-bit register field names.
  let toDataReg (n: uint32) =
    match n with
    | 0u -> R.D0
    | 1u -> R.D1
    | 2u -> R.D2
    | 3u -> R.D3
    | 4u -> R.D4
    | 5u -> R.D5
    | 6u -> R.D6
    | 7u -> R.D7
    | _ -> Terminator.impossible ()

  /// Returns the floating-point data register that the given three-bit register
  /// field names.
  let toFloatReg (n: uint32) =
    match n with
    | 0u -> R.FP0
    | 1u -> R.FP1
    | 2u -> R.FP2
    | 3u -> R.FP3
    | 4u -> R.FP4
    | 5u -> R.FP5
    | 6u -> R.FP6
    | 7u -> R.FP7
    | _ -> Terminator.impossible ()

  /// Returns the address register that the given three-bit register field
  /// names.
  let toAddrReg (n: uint32) =
    match n with
    | 0u -> R.A0
    | 1u -> R.A1
    | 2u -> R.A2
    | 3u -> R.A3
    | 4u -> R.A4
    | 5u -> R.A5
    | 6u -> R.A6
    | 7u -> R.A7
    | _ -> Terminator.impossible ()
