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

namespace B2R2.FrontEnd.BinLifter.ARM64

open B2R2

module private RegisterSetLiteral =
  let [<Literal>] arrLen = 2

open RegisterSetLiteral

type ARM64RegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  new () = ARM64RegisterSet (RegisterSet.MakeInternalBitArray arrLen, Set.empty)

  override __.Tag = RegisterSetTag.ARM64

  override __.ArrSize = arrLen

  override __.New x s = new ARM64RegisterSet (x, s) :> RegisterSet

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
    | R.XZR -> 31
    | R.SP -> 32
    | R.V0 -> 33
    | R.V1 -> 34
    | R.V2 -> 35
    | R.V3 -> 36
    | R.V4 -> 37
    | R.V5 -> 38
    | R.V6 -> 39
    | R.V7 -> 40
    | R.V8 -> 41
    | R.V9 -> 42
    | R.V10 -> 43
    | R.V11 -> 44
    | R.V12 -> 45
    | R.V13 -> 46
    | R.V14 -> 47
    | R.V15 -> 48
    | R.V16 -> 49
    | R.V17 -> 50
    | R.V18 -> 51
    | R.V19 -> 52
    | R.V20 -> 53
    | R.V21 -> 54
    | R.V22 -> 55
    | R.V23 -> 56
    | R.V24 -> 57
    | R.V25 -> 58
    | R.V26 -> 59
    | R.V27 -> 60
    | R.V28 -> 61
    | R.V29 -> 62
    | R.V30 -> 63
    | R.V31 -> 64
    | R.FPCR -> 65
    | R.FPSR -> 66
    | R.N -> 67
    | R.Z -> 68
    | R.C -> 69
    | R.V -> 70
    | _ -> -1

  override __.IndexToRegID index =
    match index with
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
    | 31 -> R.XZR
    | 32 -> R.SP
    | 33 -> R.V0
    | 34 -> R.V1
    | 35 -> R.V2
    | 36 -> R.V3
    | 37 -> R.V4
    | 38 -> R.V5
    | 39 -> R.V6
    | 40 -> R.V7
    | 41 -> R.V8
    | 42 -> R.V9
    | 43 -> R.V10
    | 44 -> R.V11
    | 45 -> R.V12
    | 46 -> R.V13
    | 47 -> R.V14
    | 48 -> R.V15
    | 49 -> R.V16
    | 50 -> R.V17
    | 51 -> R.V18
    | 52 -> R.V19
    | 53 -> R.V20
    | 54 -> R.V21
    | 55 -> R.V22
    | 56 -> R.V23
    | 57 -> R.V24
    | 58 -> R.V25
    | 59 -> R.V26
    | 60 -> R.V27
    | 61 -> R.V28
    | 62 -> R.V29
    | 63 -> R.V30
    | 64 -> R.V31
    | 65 -> R.FPCR
    | 66 -> R.FPSR
    | 67 -> R.N
    | 68 -> R.Z
    | 69 -> R.C
    | 70 -> R.V
    | _ -> Utils.impossible ()
    |> Register.toRegID

  override __.ToString () =
    sprintf "ARM64RegisterSet<%x, %x>" __.BitArray[0] __.BitArray[1]

[<RequireQualifiedAccess>]
module ARM64RegisterSet =
  let singleton rid = ARM64RegisterSet().Add(rid)
  let empty = ARM64RegisterSet () :> RegisterSet
