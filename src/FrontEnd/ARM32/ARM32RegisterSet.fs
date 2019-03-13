(*
    B2R2 - the Next-Generation Reversing Platform

    Author: Seung Il Jung <sijung@kaist.ac.kr>

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

type ARM32RegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
    inherit NonEmptyRegisterSet (bitArray, s)

    static let defaultSize = 1
    static let emptyArr = Array.init defaultSize (fun _ -> 0UL)
    static member EmptySet =
        new ARM32RegisterSet (emptyArr, Set.empty) :> RegisterSet

    override __.Tag = RegisterSetTag.ARM32
    override __.ArrSize = defaultSize
    override __.New x s = new ARM32RegisterSet (x, s) :> RegisterSet
    override __.Empty = ARM32RegisterSet.EmptySet
    override __.EmptyArr = emptyArr
    override __.Project x =
        match Register.ofRegID x with
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

    override __.ToString () =
        sprintf "ARM32RegisterSet<%x>" __.BitArray.[0]

[<RequireQualifiedAccess>]
module ARM32RegisterSet =
    let singleton = RegisterSetBuilder.singletonBuilder ARM32RegisterSet.EmptySet
    let empty = ARM32RegisterSet.EmptySet
