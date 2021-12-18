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

namespace B2R2.FrontEnd.BinLifter.MIPS

open B2R2

module private RegisterSetLiteral =
  let [<Literal>] arrLen = 2

open RegisterSetLiteral

type MIPSRegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  new () = MIPSRegisterSet (RegisterSet.MakeInternalBitArray arrLen, Set.empty)

  override __.Tag = RegisterSetTag.MIPS

  override __.ArrSize = arrLen

  override __.New arr s = new MIPSRegisterSet (arr, s) :> RegisterSet

  override __.RegIDToIndex rid =
    match Register.ofRegID rid with
    | R.R0 -> 0
    | R.R1 -> 1
    | R.R2 -> 2
    | R.R3 -> 3
    | R.R4 -> 4
    | R.R5 -> 5
    | R.R6 -> 6
    | R.R7 -> 7
    | R.R8 -> 8
    | R.R9 -> 9
    | R.R10 -> 10
    | R.R11 -> 11
    | R.R12 -> 12
    | R.R13 -> 13
    | R.R14 -> 14
    | R.R15 -> 15
    | R.R16 -> 16
    | R.R17 -> 17
    | R.R18 -> 18
    | R.R19 -> 19
    | R.R20 -> 20
    | R.R21 -> 21
    | R.R22 -> 22
    | R.R23 -> 23
    | R.R24 -> 24
    | R.R25 -> 25
    | R.R26 -> 26
    | R.R27 -> 27
    | R.R28 -> 28
    | R.R29 -> 29
    | R.R30 -> 30
    | R.R31 -> 31
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
    | R.HI -> 64
    | R.LO -> 65
    | R.PC -> 66
    | _ -> -1

  override __.IndexToRegID index =
    match index with
    | 0 -> R.R0
    | 1 -> R.R1
    | 2 -> R.R2
    | 3 -> R.R3
    | 4 -> R.R4
    | 5 -> R.R5
    | 6 -> R.R6
    | 7 -> R.R7
    | 8 -> R.R8
    | 9 -> R.R9
    | 10 -> R.R10
    | 11 -> R.R11
    | 12 -> R.R12
    | 13 -> R.R13
    | 14 -> R.R14
    | 15 -> R.R15
    | 16 -> R.R16
    | 17 -> R.R17
    | 18 -> R.R18
    | 19 -> R.R19
    | 20 -> R.R20
    | 21 -> R.R21
    | 22 -> R.R22
    | 23 -> R.R23
    | 24 -> R.R24
    | 25 -> R.R25
    | 26 -> R.R26
    | 27 -> R.R27
    | 28 -> R.R28
    | 29 -> R.R29
    | 30 -> R.R30
    | 31 -> R.R31
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
    | 64 -> R.HI
    | 65 -> R.LO
    | 66 -> R.PC
    | _ -> Utils.impossible ()
    |> Register.toRegID

  override __.ToString () =
    sprintf "MIPSRegisterSet<%x, %x>" __.BitArray[0] __.BitArray[1]

[<RequireQualifiedAccess>]
module MIPSRegisterSet =
  let singleton rid = MIPSRegisterSet().Add(rid)
  let empty = MIPSRegisterSet () :> RegisterSet
