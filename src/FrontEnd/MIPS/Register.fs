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

namespace B2R2.FrontEnd.MIPS

open System.Runtime.CompilerServices
open B2R2

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.MIPS.Tests")>]
do ()

/// Shortcut for Register type.
type internal R = Register

/// Provides several useful functions to handle MIPS registers.
[<RequireQualifiedAccess>]
module internal Register =
  let getFPPairReg = function
    | R.F0 -> R.F1
    | R.F2 -> R.F3
    | R.F4 -> R.F5
    | R.F6 -> R.F7
    | R.F8 -> R.F9
    | R.F10 -> R.F11
    | R.F12 -> R.F13
    | R.F14 -> R.F15
    | R.F16 -> R.F17
    | R.F18 -> R.F19
    | R.F20 -> R.F21
    | R.F22 -> R.F23
    | R.F24 -> R.F25
    | R.F26 -> R.F27
    | R.F28 -> R.F29
    | R.F30 -> R.F31
    | _ -> Terminator.impossible ()
