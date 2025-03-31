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

namespace B2R2.FrontEnd.BinLifter.PARISC

open B2R2

/// Shortcut for Register type.
type internal R = FrontEnd.Register.PARISC

/// This module exposes several useful functions to handle s390/s390x
/// registers.
[<RequireQualifiedAccess>]
module Register =
  let toRegType wordSize = function
    | R.GR0 | R.GR1 | R.GR2 | R.GR3 | R.GR4 | R.GR5 | R.GR6 | R.GR7
    | R.GR8 | R.GR9 | R.GR10 | R.GR11 | R.GR12 | R.GR13 | R.GR14 | R.GR15
    | R.GR16 | R.GR17 | R.GR18 | R.GR19 | R.GR20 | R.GR21 | R.GR22 | R.GR23
    | R.GR24 | R.GR25 | R.GR26 | R.GR27 | R.GR28 | R.GR29 | R.GR30 | R.GR31
    | R.SR0 | R.SR1 | R.SR2 | R.SR3 | R.SR4 | R.SR5 | R.SR6 | R.SR7
    | R.IAOQ_Front | R.IAOQ_Back | R.IASQ_Front | R.IASQ_Back | R.PSW
    | R.CR0 | R.CR1 | R.CR2 | R.CR3 | R.CR4 | R.CR5 | R.CR6 | R.CR7
    | R.CR8 | R.CR9 | R.CR10 | R.CR11 | R.CR12 | R.CR13 | R.CR14 | R.CR15
    | R.CR16 | R.CR17 | R.CR18 | R.CR19 | R.CR20 | R.CR21 | R.CR22 | R.CR23
    | R.CR24 | R.CR25 | R.CR26 | R.CR27 | R.CR28 | R.CR29 | R.CR30 | R.CR31
    | R.FPR0 | R.FPR1 | R.FPR2 | R.FPR3 | R.FPR4 | R.FPR5 | R.FPR6 | R.FPR7
    | R.FPR8 | R.FPR9 | R.FPR10 | R.FPR11 | R.FPR12 | R.FPR13 | R.FPR14
    | R.FPR15 | R.FPR16 | R.FPR17 | R.FPR18 | R.FPR19 | R.FPR20 | R.FPR21
    | R.FPR22 | R.FPR23 | R.FPR24 | R.FPR25 | R.FPR26 | R.FPR27 | R.FPR28
    | R.FPR29 | R.FPR30 | R.FPR31 -> WordSize.toRegType wordSize
    | _ -> Utils.impossible ()

