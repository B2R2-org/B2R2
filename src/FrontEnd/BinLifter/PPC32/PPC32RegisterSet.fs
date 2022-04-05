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

namespace B2R2.FrontEnd.BinLifter.PPC32

open B2R2

module private RegisterSetLiteral =
  let [<Literal>] ArrLen = 2

open RegisterSetLiteral

type PPC32RegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  new () =
    PPC32RegisterSet (RegisterSet.MakeInternalBitArray ArrLen, Set.empty)

  override __.Tag = RegisterSetTag.PPC32

  override __.ArrSize = ArrLen

  override __.New arr s = new PPC32RegisterSet (arr, s) :> RegisterSet

  override __.RegIDToIndex rid =
    match Register.ofRegID rid with
    | R.GPR0 -> 0
    | R.GPR1 -> 1
    | R.GPR2 -> 2
    | R.GPR3 -> 3
    | R.GPR4 -> 4
    | R.GPR5 -> 5
    | R.GPR6 -> 6
    | R.GPR7 -> 7
    | R.GPR8 -> 8
    | R.GPR9 -> 9
    | R.GPR10 -> 10
    | R.GPR11 -> 11
    | R.GPR12 -> 12
    | R.GPR13 -> 13
    | R.GPR14 -> 14
    | R.GPR15 -> 15
    | R.GPR16 -> 16
    | R.GPR17 -> 17
    | R.GPR18 -> 18
    | R.GPR19 -> 19
    | R.GPR20 -> 20
    | R.GPR21 -> 21
    | R.GPR22 -> 22
    | R.GPR23 -> 23
    | R.GPR24 -> 24
    | R.GPR25 -> 25
    | R.GPR26 -> 26
    | R.GPR27 -> 27
    | R.GPR28 -> 28
    | R.GPR29 -> 29
    | R.GPR30 -> 30
    | R.GPR31 -> 31
    | _ -> -1

  override __.IndexToRegID _index: RegisterID =
    Utils.futureFeature ()

  override __.ToString () =
    sprintf "PPC32RegisterSet<%x, %x>" __.BitArray.[0] __.BitArray.[1]

[<RequireQualifiedAccess>]
module PPC32RegisterSet =
  let singleton rid = PPC32RegisterSet().Add(rid)
  let empty = PPC32RegisterSet () :> RegisterSet
