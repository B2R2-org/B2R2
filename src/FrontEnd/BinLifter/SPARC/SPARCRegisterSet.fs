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

namespace B2R2.FrontEnd.BinLifter.SPARC

open B2R2

module private RegisterSetLiteral =
  let [<Literal>] ArrLen = 2

open RegisterSetLiteral

type SPARCRegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  new () =
    SPARCRegisterSet (RegisterSet.MakeInternalBitArray ArrLen, Set.empty)

  override __.Tag = RegisterSetTag.SPARC

  override __.ArrSize = ArrLen

  override __.New arr s = SPARCRegisterSet (arr, s) :> RegisterSet

  override __.RegIDToIndex rid =
    match Register.ofRegID rid with
    | R.G0 -> 0
    | R.G1 -> 1
    | R.G2 -> 2
    | R.G3 -> 3
    | R.G4 -> 4
    | R.G5 -> 5
    | R.G6 -> 6
    | R.G7 -> 7
    | R.O0 -> 8
    | R.O1 -> 9
    | R.O2 -> 10
    | R.O3 -> 11
    | R.O4 -> 12
    | R.O5 -> 13
    | R.O6 -> 14
    | R.O7 -> 15
    | R.L0 -> 16
    | R.L1 -> 17
    | R.L2 -> 18
    | R.L3 -> 19
    | R.L4 -> 20
    | R.L5 -> 21
    | R.L6 -> 22
    | R.L7 -> 23
    | R.I0 -> 24
    | R.I1 -> 25
    | R.I2 -> 26
    | R.I3 -> 27
    | R.I4 -> 28
    | R.I5 -> 29
    | R.I6 -> 30
    | R.I7 -> 31
    | R.PC -> 32
    | R.NPC -> 33
    | R.Y -> 34
    | R.ASRs -> 35
    | R.CCR -> 36
    | R.FPRS -> 37
    | R.FSR -> 38
    | R.ASI -> 39
    | R.TICK -> 40
    | R.PSTATE -> 41
    | R.TL -> 42
    | R.PIL -> 43
    | R.TPC -> 44
    | R.TNPC -> 45
    | R.TSTATE -> 46
    | R.TT -> 47
    | R.TBA -> 48
    | R.VER -> 49
    | R.CWP -> 50
    | R.CANSAVE -> 51
    | R.CANRESTORE -> 52
    | R.OTHERWIN -> 53
    | R.WSTATE -> 54
    | R.CLEANWIN -> 55
    | R.F0 -> 56
    | R.F1 -> 57
    | R.F2 -> 58
    | R.F3 -> 59
    | R.F4 -> 60
    | R.F5 -> 61
    | R.F6 -> 62
    | R.F7 -> 63
    | R.F8 -> 64
    | R.F9 -> 65
    | R.F10 -> 66
    | R.F11 -> 67
    | R.F12 -> 68
    | R.F13 -> 69
    | R.F14 -> 70
    | R.F15 -> 71
    | R.F16 -> 72
    | R.F17 -> 73
    | R.F18 -> 74
    | R.F19 -> 75
    | R.F20 -> 76
    | R.F21 -> 77
    | R.F22 -> 78
    | R.F23 -> 79
    | R.F24 -> 80
    | R.F25 -> 81
    | R.F26 -> 82
    | R.F27 -> 83
    | R.F28 -> 84
    | R.F29 -> 85
    | R.F30 -> 86
    | R.F31 -> 87
    | R.F32 -> 88
    | R.F34 -> 89
    | R.F36 -> 90
    | R.F38 -> 91
    | R.F40 -> 92
    | R.F42 -> 93
    | R.F44 -> 94
    | R.F46 -> 95
    | R.F48 -> 96
    | R.F50 -> 97
    | R.F52 -> 98
    | R.F54 -> 99
    | R.F56 -> 100
    | R.F58 -> 101
    | R.F60 -> 102
    | R.F62 -> 103
    | _ -> -1

  override __.IndexToRegID index =
    match index with
    | 0 -> R.G0
    | 1 -> R.G1
    | 2 -> R.G2
    | 3 -> R.G3
    | 4 -> R.G4
    | 5 -> R.G5
    | 6 -> R.G6
    | 7 -> R.G7
    | 8 -> R.O0
    | 9 -> R.O1
    | 10 -> R.O2
    | 11 -> R.O3
    | 12 -> R.O4
    | 13 -> R.O5
    | 14 -> R.O6
    | 15 -> R.O7
    | 16 -> R.L0
    | 17 -> R.L1
    | 18 -> R.L2
    | 19 -> R.L3
    | 20 -> R.L4
    | 21 -> R.L5
    | 22 -> R.L6
    | 23 -> R.L7
    | 24 -> R.I0
    | 25 -> R.I1
    | 26 -> R.I2
    | 27 -> R.I3
    | 28 -> R.I4
    | 29 -> R.I5
    | 30 -> R.I6
    | 31 -> R.I7
    | 32 -> R.PC
    | 33 -> R.NPC
    | 34 -> R.Y
    | 35 -> R.ASRs
    | 36 -> R.CCR
    | 37 -> R.FPRS
    | 38 -> R.FSR
    | 39 -> R.ASI
    | 40 -> R.TICK
    | 41 -> R.PSTATE
    | 42 -> R.TL
    | 43 -> R.PIL
    | 44 -> R.TPC
    | 45 -> R.TNPC
    | 46 -> R.TSTATE
    | 47 -> R.TT
    | 48 -> R.TBA
    | 49 -> R.VER
    | 50 -> R.CWP
    | 51 -> R.CANSAVE
    | 52 -> R.CANRESTORE
    | 53 -> R.OTHERWIN
    | 54 -> R.WSTATE
    | 55 -> R.CLEANWIN
    | 56 -> R.F0
    | 57 -> R.F1
    | 58 -> R.F2
    | 59 -> R.F3
    | 60 -> R.F4
    | 61 -> R.F5
    | 62 -> R.F6
    | 63 -> R.F7
    | 64 -> R.F8
    | 65 -> R.F9
    | 66 -> R.F10
    | 67 -> R.F11
    | 68 -> R.F12
    | 69 -> R.F13
    | 70 -> R.F14
    | 71 -> R.F15
    | 72 -> R.F16
    | 73 -> R.F17
    | 74 -> R.F18
    | 75 -> R.F19
    | 76 -> R.F20
    | 77 -> R.F21
    | 78 -> R.F22
    | 79 -> R.F23
    | 80 -> R.F24
    | 81 -> R.F25
    | 82 -> R.F26
    | 83 -> R.F27
    | 84 -> R.F28
    | 85 -> R.F29
    | 86 -> R.F30
    | 87 -> R.F31
    | 88 -> R.F32
    | 89 -> R.F34
    | 90 -> R.F36
    | 91 -> R.F38
    | 92 -> R.F40
    | 93 -> R.F42
    | 94 -> R.F44
    | 95 -> R.F46
    | 96 -> R.F48
    | 97 -> R.F50
    | 98 -> R.F52
    | 99 -> R.F54
    | 100 -> R.F56
    | 101 -> R.F58
    | 102 -> R.F60
    | 103 -> R.F62
    | _ -> Utils.impossible ()
    |> Register.toRegID

  override __.ToString () =
    sprintf "SPARCRegisterSet<%x, %x>" __.BitArray.[0] __.BitArray.[1]

[<RequireQualifiedAccess>]
module SPARCRegisterSet =
  let singleton rid = SPARCRegisterSet().Add(rid)
  let empty = SPARCRegisterSet () :> RegisterSet
