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

namespace B2R2.FrontEnd.ARM32

open B2R2

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle ARMv8 registers.
[<RequireQualifiedAccess>]
module Register =
  let toRegType = function
    | R.R0 | R.R1 | R.R2 | R.R3 | R.R4 | R.R5 | R.R6 | R.R7 | R.R8
    | R.SB | R.SL | R.FP | R.IP | R.SP | R.LR | R.PC
    | R.S0 | R.S1 | R.S2 | R.S3 | R.S4 | R.S5 | R.S6 | R.S7 | R.S8 | R.S9
    | R.S10 | R.S11 | R.S12 | R.S13 | R.S14 | R.S15 | R.S16 | R.S17
    | R.S18 | R.S19 | R.S20 | R.S21 | R.S22 | R.S23 | R.S24 | R.S25
    | R.S26 | R.S27 | R.S28 | R.S29 | R.S30 | R.S31
    | R.APSR | R.CPSR | R.SPSR | R.SCR | R.SCTLR | R.NSACR | R.FPSCR -> 32<rt>
    | R.D0 | R.D1 | R.D2 | R.D3 | R.D4 | R.D5 | R.D6 | R.D7 | R.D8 | R.D9
    | R.D10 | R.D11 | R.D12 | R.D13 | R.D14 | R.D15 | R.D16 | R.D17
    | R.D18 | R.D19 | R.D20 | R.D21 | R.D22 | R.D23 | R.D24 | R.D25
    | R.D26 | R.D27 | R.D28 | R.D29 | R.D30 | R.D31 | R.Q0A | R.Q0B
    | R.Q1A | R.Q1B | R.Q2A | R.Q2B | R.Q3A | R.Q3B | R.Q4A | R.Q4B
    | R.Q5A | R.Q5B | R.Q6A | R.Q6B | R.Q7A | R.Q7B | R.Q8A | R.Q8B
    | R.Q9A | R.Q9B | R.Q10A | R.Q10B | R.Q11A | R.Q11B | R.Q12A | R.Q12B
    | R.Q13A | R.Q13B | R.Q14A | R.Q14B | R.Q15A | R.Q15B -> 64<rt>
    | R.Q0 | R.Q1 | R.Q2 | R.Q3 | R.Q4 | R.Q5 | R.Q6 | R.Q7 | R.Q8 | R.Q9
    | R.Q10 | R.Q11 | R.Q12 | R.Q13 | R.Q14 | R.Q15 -> 128<rt>
    | _ -> Terminator.impossible ()
