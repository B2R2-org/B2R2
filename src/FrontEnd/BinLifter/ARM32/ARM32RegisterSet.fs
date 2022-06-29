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

namespace B2R2.FrontEnd.BinLifter.ARM32

open B2R2

module private RegisterSetLiteral =
  let [<Literal>] ArrLen = 1

open RegisterSetLiteral

type ARM32RegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  new () = ARM32RegisterSet (RegisterSet.MakeInternalBitArray ArrLen, Set.empty)

  override __.Tag = RegisterSetTag.ARM32

  override __.ArrSize = ArrLen

  override __.New x s = new ARM32RegisterSet (x, s) :> RegisterSet

  override __.RegIDToIndex rid =
    match Register.ofRegID rid with
    | R.Q0 -> 0
    | R.Q1 -> 1
    | R.Q2 -> 2
    | R.Q3 -> 3
    | R.Q4 -> 4
    | R.Q5 -> 5
    | R.Q6 -> 6
    | R.Q7 -> 7
    | R.Q8 -> 8
    | R.Q9 -> 9
    | R.Q10 -> 10
    | R.Q11 -> 11
    | R.Q12 -> 12
    | R.Q13 -> 13
    | R.Q14 -> 14
    | R.Q15 -> 15
    | R.R0 -> 16
    | R.R1 -> 17
    | R.R2 -> 18
    | R.R3 -> 19
    | R.R4 -> 20
    | R.R5 -> 21
    | R.R6 -> 22
    | R.R7 -> 23
    | R.R8 -> 24
    | R.SB -> 25
    | R.SL -> 26
    | R.FP -> 27
    | R.IP -> 28
    | R.SP -> 29
    | R.LR -> 30
    | R.APSR -> 31
    | R.SPSR -> 32
    | R.CPSR -> 33
    | R.FPSCR -> 34
    | R.SCTLR -> 35
    | R.SCR -> 36
    | R.NSACR -> 37
    | _ -> -1

  override __.IndexToRegID index =
    match index with
    | 0 -> R.Q0
    | 1 -> R.Q1
    | 2 -> R.Q2
    | 3 -> R.Q3
    | 4 -> R.Q4
    | 5 -> R.Q5
    | 6 -> R.Q6
    | 7 -> R.Q7
    | 8 -> R.Q8
    | 9 -> R.Q9
    | 10 -> R.Q10
    | 11 -> R.Q11
    | 12 -> R.Q12
    | 13 -> R.Q13
    | 14 -> R.Q14
    | 15 -> R.Q15
    | 16 -> R.R0
    | 17 -> R.R1
    | 18 -> R.R2
    | 19 -> R.R3
    | 20 -> R.R4
    | 21 -> R.R5
    | 22 -> R.R6
    | 23 -> R.R7
    | 24 -> R.R8
    | 25 -> R.SB
    | 26 -> R.SL
    | 27 -> R.FP
    | 28 -> R.IP
    | 29 -> R.SP
    | 30 -> R.LR
    | 31 -> R.APSR
    | 32 -> R.SPSR
    | 33 -> R.CPSR
    | 34 -> R.FPSCR
    | 35 -> R.SCTLR
    | 36 -> R.SCR
    | 37 -> R.NSACR
    | _ -> Utils.impossible ()
    |> Register.toRegID

  override __.ToString () =
    sprintf "ARM32RegisterSet<%x>" __.BitArray[0]

[<RequireQualifiedAccess>]
module ARM32RegisterSet =
  let singleton rid = ARM32RegisterSet().Add(rid)
  let empty = ARM32RegisterSet () :> RegisterSet
