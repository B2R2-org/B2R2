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

namespace B2R2.FrontEnd.MIPS

open B2R2

type MIPSRegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  static let defaultSize = 2
  static let emptyArr = Array.init defaultSize (fun _ -> 0UL)
  static member EmptySet =
    new MIPSRegisterSet (emptyArr, Set.empty) :> RegisterSet

  override __.Tag = RegisterSetTag.MIPS
  override __.ArrSize = defaultSize
  override __.New x s = new MIPSRegisterSet (x, s) :> RegisterSet
  override __.Empty = MIPSRegisterSet.EmptySet
  override __.EmptyArr = emptyArr
  override __.Project x =
    match Register.ofRegID x with
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

  override __.ToString () =
    sprintf "MIPSRegisterSet<%x, %x>" __.BitArray.[0] __.BitArray.[1]

[<RequireQualifiedAccess>]
module MIPSRegisterSet =
  let singleton = RegisterSetBuilder.singletonBuilder MIPSRegisterSet.EmptySet
  let empty = MIPSRegisterSet.EmptySet
