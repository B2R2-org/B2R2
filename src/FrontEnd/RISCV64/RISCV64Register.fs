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

namespace B2R2.FrontEnd.RISCV64

open B2R2

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle RISCV64
/// registers.
[<RequireQualifiedAccess>]
module Register =
  let toRegType wordSize = function
    | R.PC | R.X0 | R.X1 | R.X2 | R.X3 | R.X4 | R.X5 | R.X6 | R.X7 | R.X8
    | R.X9 | R.X10 | R.X11 | R.X12 | R.X13 | R.X14 | R.X15 | R.X16 | R.X17
    | R.X18 | R.X19 | R.X20 | R.X21 | R.X22 | R.X23 | R.X24 | R.X25 | R.X26
    | R.X27 | R.X28 | R.X29 | R.X30 | R.X31 -> WordSize.toRegType wordSize
    | R.F0 | R.F1 | R.F2 | R.F3 | R.F4 | R.F5 | R.F6 | R.F7 | R.F8 | R.F9
    | R.F10 | R.F11 | R.F12 | R.F13 | R.F14 | R.F15 | R.F16 | R.F17 | R.F18
    | R.F19 | R.F20 | R.F21 | R.F22 | R.F23 | R.F24 | R.F25 | R.F26 | R.F27
    | R.F28 | R.F29 | R.F30 | R.F31 -> 64<rt>
    | R.FCSR | R.FFLAGS | R.FRM -> 32<rt>
    | _ -> Terminator.impossible ()
