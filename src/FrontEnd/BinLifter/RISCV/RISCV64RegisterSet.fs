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

namespace B2R2.FrontEnd.BinLifter.RISCV

open B2R2

module private RegisterSetLiteral =
  let [<Literal>] ArrLen = 2

open RegisterSetLiteral

type RISCV64RegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  new () =
    RISCV64RegisterSet (RegisterSet.MakeInternalBitArray ArrLen, Set.empty)

  override __.Tag = RegisterSetTag.RISCV64

  override __.ArrSize = ArrLen

  override __.New arr s = new RISCV64RegisterSet (arr, s) :> RegisterSet

  override __.RegIDToIndex rid =
    match Register.ofRegID rid with
    | R.X0 -> 0
    | R.X1 -> 1
    | R.X2 -> 2
    | R.X3 -> 3
    | R.X4 -> 4
    | R.X5 -> 5
    | R.X6 -> 6
    | R.X7 -> 7
    | R.X8 -> 8
    | R.X9 -> 9
    | R.X10 -> 10
    | R.X11 -> 11
    | R.X12 -> 12
    | R.X13 -> 13
    | R.X14 -> 14
    | R.X15 -> 15
    | R.X16 -> 16
    | R.X17 -> 17
    | R.X18 -> 18
    | R.X19 -> 19
    | R.X20 -> 20
    | R.X21 -> 21
    | R.X22 -> 22
    | R.X23 -> 23
    | R.X24 -> 24
    | R.X25 -> 25
    | R.X26 -> 26
    | R.X27 -> 27
    | R.X28 -> 28
    | R.X29 -> 29
    | R.X30 -> 30
    | R.X31 -> 31
    | R.F0 -> 32
    | R.F1 -> 33
    | R.F2 -> 34
    | R.F3 -> 35
    | R.F4 -> 36
    | R.F5 -> 37
    | R.F6 -> 38
    | R.F7 -> 39
    | R.F8 -> 40
    | R.F9 -> 41
    | R.F10 -> 42
    | R.F11 -> 43
    | R.F12 -> 44
    | R.F13 -> 45
    | R.F14 -> 46
    | R.F15 -> 47
    | R.F16 -> 48
    | R.F17 -> 49
    | R.F18 -> 50
    | R.F19 -> 51
    | R.F20 -> 52
    | R.F21 -> 53
    | R.F22 -> 54
    | R.F23 -> 55
    | R.F24 -> 56
    | R.F25 -> 57
    | R.F26 -> 58
    | R.F27 -> 59
    | R.F28 -> 60
    | R.F29 -> 61
    | R.F30 -> 62
    | R.F31 -> 63
    | R.PC -> 64
    | _ -> -1

  override __.IndexToRegID _index: RegisterID =
    match _index with
    | 0 -> R.X0
    | 1 -> R.X1
    | 2 -> R.X2
    | 3 -> R.X3
    | 4 -> R.X4
    | 5 -> R.X5
    | 6 -> R.X6
    | 7 -> R.X7
    | 8 -> R.X8
    | 9 -> R.X9
    | 10 -> R.X10
    | 11 -> R.X11
    | 12 -> R.X12
    | 13 -> R.X13
    | 14 -> R.X14
    | 15 -> R.X15
    | 16 -> R.X16
    | 17 -> R.X17
    | 18 -> R.X18
    | 19 -> R.X19
    | 20 -> R.X20
    | 21 -> R.X21
    | 22 -> R.X22
    | 23 -> R.X23
    | 24 -> R.X24
    | 25 -> R.X25
    | 26 -> R.X26
    | 27 -> R.X27
    | 28 -> R.X28
    | 29 -> R.X29
    | 30 -> R.X30
    | 31 -> R.X31
    | 32 -> R.F0
    | 33 -> R.F1
    | 34 -> R.F2
    | 35 -> R.F3
    | 36 -> R.F4
    | 37 -> R.F5
    | 38 -> R.F6
    | 39 -> R.F7
    | 40 -> R.F8
    | 41 -> R.F9
    | 42 -> R.F10
    | 43 -> R.F11
    | 44 -> R.F12
    | 45 -> R.F13
    | 46 -> R.F14
    | 47 -> R.F15
    | 48 -> R.F16
    | 49 -> R.F17
    | 50 -> R.F18
    | 51 -> R.F19
    | 52 -> R.F20
    | 53 -> R.F21
    | 54 -> R.F22
    | 55 -> R.F23
    | 56 -> R.F24
    | 57 -> R.F25
    | 58 -> R.F26
    | 59 -> R.F27
    | 60 -> R.F28
    | 61 -> R.F29
    | 62 -> R.F30
    | 63 -> R.F31
    | 64 -> R.PC
    | _ -> Utils.impossible ()
    |> Register.toRegID

  override __.ToString () =
    sprintf "RISCV64RegisterSet<%x, %x>" __.BitArray.[0] __.BitArray.[1]

[<RequireQualifiedAccess>]
module RISCV64RegisterSet =
  let singleton rid = RISCV64RegisterSet().Add(rid)
  let empty = RISCV64RegisterSet () :> RegisterSet
