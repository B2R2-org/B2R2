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

namespace B2R2.FrontEnd.S390

open System.Runtime.CompilerServices
open B2R2

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.S390.Tests")>]
do ()

/// Shortcut for Register type.
type internal R = Register

/// Provides several useful functions for working with s390/s390x registers.
[<RequireQualifiedAccess>]
module internal Register =
  let getRpairReg = function
    | R.R0 -> R.R1
    | R.R2 -> R.R3
    | R.R4 -> R.R5
    | R.R6 -> R.R7
    | R.R8 -> R.R9
    | R.R10 -> R.R11
    | R.R12 -> R.R13
    | R.R14 -> R.R15
    | _ -> Terminator.impossible ()

  let getFPRpairReg = function
    | R.FPR0 -> R.FPR2
    | R.FPR1 -> R.FPR3
    | R.FPR4 -> R.FPR6
    | R.FPR5 -> R.FPR7
    | R.FPR8 -> R.FPR10
    | R.FPR9 -> R.FPR11
    | R.FPR12 -> R.FPR14
    | R.FPR13 -> R.FPR15
    | _ -> Terminator.impossible ()

  let toRegType wordSize = function
    | R.R0 | R.R1 | R.R2 | R.R3 | R.R4 | R.R5 | R.R6 | R.R7 | R.R8 | R.R9
    | R.R10 | R.R11 | R.R12 | R.R13 | R.R14 | R.R15 -> 64<rt>
    | R.FPR0 | R.FPR1 | R.FPR2 | R.FPR3 | R.FPR4 | R.FPR5 | R.FPR6 | R.FPR7
    | R.FPR8 | R.FPR9 | R.FPR10 | R.FPR11 | R.FPR12 | R.FPR13 | R.FPR14
    | R.FPR15 -> 64<rt>
    | R.FPC -> 32<rt>
    | R.VR0 | R.VR1 | R.VR2 | R.VR3 | R.VR4 | R.VR5 | R.VR6 | R.VR7 | R.VR8
    | R.VR9 | R.VR10 | R.VR11 | R.VR12 | R.VR13 | R.VR14 | R.VR15 | R.VR16
    | R.VR17 | R.VR18 | R.VR19 | R.VR20 | R.VR21 | R.VR22 | R.VR23 | R.VR24
    | R.VR25 | R.VR26 | R.VR27 | R.VR28 | R.VR29 | R.VR30 | R.VR31 -> 128<rt>
    | R.CR0 | R.CR1 | R.CR2 | R.CR3 | R.CR4 | R.CR5 | R.CR6 | R.CR7 | R.CR8
    | R.CR9 | R.CR10 | R.CR11 | R.CR12 | R.CR13 | R.CR14 | R.CR15 -> 64<rt>
    | R.AR0 | R.AR1 | R.AR2 | R.AR3 | R.AR4 | R.AR5 | R.AR6 | R.AR7 | R.AR8
    | R.AR9 | R.AR10 | R.AR11 | R.AR12 | R.AR13 | R.AR14 | R.AR15 -> 32<rt>
    | R.BEAR -> 64<rt>
    | R.PSW when wordSize = WordSize.Bit32 -> 64<rt>
    | R.PSW when wordSize = WordSize.Bit64 -> 128<rt>
    | _ -> Terminator.impossible ()

  let getAliases =
    function
    | R.FPR0 | R.VR0 -> [| R.FPR0; R.VR0 |]
    | R.FPR1 | R.VR1 -> [| R.FPR1; R.VR1 |]
    | R.FPR2 | R.VR2 -> [| R.FPR2; R.VR2 |]
    | R.FPR3 | R.VR3 -> [| R.FPR3; R.VR3 |]
    | R.FPR4 | R.VR4 -> [| R.FPR4; R.VR4 |]
    | R.FPR5 | R.VR5 -> [| R.FPR5; R.VR5 |]
    | R.FPR6 | R.VR6 -> [| R.FPR6; R.VR6 |]
    | R.FPR7 | R.VR7 -> [| R.FPR7; R.VR7 |]
    | R.FPR8 | R.VR8 -> [| R.FPR8; R.VR8 |]
    | R.FPR9 | R.VR9 -> [| R.FPR9; R.VR9 |]
    | R.FPR10 | R.VR10 -> [| R.FPR10; R.VR10 |]
    | R.FPR11 | R.VR11 -> [| R.FPR11; R.VR11 |]
    | R.FPR12 | R.VR12 -> [| R.FPR12; R.VR12 |]
    | R.FPR13 | R.VR13 -> [| R.FPR13; R.VR13 |]
    | R.FPR14 | R.VR14 -> [| R.FPR14; R.VR14 |]
    | R.FPR15 | R.VR15 -> [| R.FPR15; R.VR15 |]
    | r -> [| r |]
