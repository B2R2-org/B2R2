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

namespace B2R2.FrontEnd.BinLifter.AVR

open B2R2

module private RegisterSetLiteral =
  let [<Literal>] ArrLen = 2

open RegisterSetLiteral

type AVRRegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  new () =
    AVRRegisterSet (RegisterSet.MakeInternalBitArray ArrLen, Set.empty)

  override __.Tag = RegisterSetTag.AVR

  override __.ArrSize = ArrLen

  override __.New arr s = AVRRegisterSet (arr, s) :> RegisterSet

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
    | R.X -> 32
    | R.Y -> 33
    | R.Z -> 34
    | R.IF -> 35
    | R.TF -> 36
    | R.HF -> 37
    | R.SF -> 38
    | R.VF -> 39
    | R.NF -> 40
    | R.ZF -> 41
    | R.CF -> 42
    | R.PC -> 43
    | R.SP -> 44
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
    | 32 -> R.X
    | 33 -> R.Y
    | 34 -> R.Z
    | 35 -> R.IF
    | 36 -> R.TF
    | 37 -> R.HF
    | 38 -> R.SF
    | 39 -> R.VF
    | 40 -> R.NF
    | 41 -> R.ZF
    | 42 -> R.CF
    | 43 -> R.PC
    | 44 -> R.SP
    | _ -> Utils.impossible ()
    |> Register.toRegID

  override __.ToString () =
    sprintf "AVRRegisterSet<%x, %x>" __.BitArray[0] __.BitArray[1]

[<RequireQualifiedAccess>]
module AVRRegisterSet =
  let singleton rid = AVRRegisterSet().Add(rid)
  let empty = AVRRegisterSet () :> RegisterSet
