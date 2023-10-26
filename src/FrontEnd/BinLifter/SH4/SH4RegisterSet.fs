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

namespace B2R2.FrontEnd.BinLifter.SH4

open B2R2

type SH4RegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  new () = SH4RegisterSet (RegisterSet.MakeInternalBitArray 3, Set.empty)

  override __.Tag = RegisterSetTag.SH4

  override __.ArrSize = 3

  override __.New arr s = SH4RegisterSet (arr, s) :> RegisterSet

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
    | R.R0_BANK -> 16
    | R.R1_BANK -> 17
    | R.R2_BANK -> 18
    | R.R3_BANK -> 19
    | R.R4_BANK -> 20
    | R.R5_BANK -> 21
    | R.R6_BANK -> 22
    | R.R7_BANK -> 23
    | R.SR -> 24
    | R.GBR -> 25
    | R.SSR -> 26
    | R.SPC -> 27
    | R.SGR -> 28
    | R.DBR -> 29
    | R.VBR -> 30
    | R.MACH -> 31
    | R.MACL -> 32
    | R.PR -> 33
    | R.FPUL -> 34
    | R.PC -> 35
    | R.FPSCR -> 36
    | R.FPR0 -> 37
    | R.FPR1 -> 38
    | R.FPR2 -> 39
    | R.FPR3 -> 40
    | R.FPR4 -> 41
    | R.FPR5 -> 42
    | R.FPR6 -> 43
    | R.FPR7 -> 44
    | R.FPR8 -> 45
    | R.FPR9 -> 46
    | R.FPR10 -> 47
    | R.FPR11 -> 48
    | R.FPR12 -> 49
    | R.FPR13 -> 50
    | R.FPR14 -> 51
    | R.FPR15 -> 52
    | R.FR0 -> 53
    | R.FR1 -> 54
    | R.FR2 -> 55
    | R.FR3 -> 56
    | R.FR4 -> 57
    | R.FR5 -> 58
    | R.FR6 -> 59
    | R.FR7 -> 60
    | R.FR8 -> 61
    | R.FR9 -> 62
    | R.FR10 -> 63
    | R.FR11 -> 64
    | R.FR12 -> 65
    | R.FR13 -> 66
    | R.FR14 -> 67
    | R.FR15 -> 68
    | R.DR0 -> 69
    | R.DR2 -> 70
    | R.DR4 -> 71
    | R.DR6 -> 72
    | R.DR8 -> 73
    | R.DR10 -> 74
    | R.DR12 -> 75
    | R.DR14 -> 76
    | R.FV0 -> 77
    | R.FV4 -> 78
    | R.FV8 -> 79
    | R.FV12 -> 80
    | R.XD0 -> 81
    | R.XD2 -> 82
    | R.XD4 -> 83
    | R.XD6 -> 84
    | R.XD8 -> 85
    | R.XD10 -> 86
    | R.XD12 -> 87
    | R.XD14 -> 88
    | R.XF0 -> 89
    | R.XF1 -> 90
    | R.XF2 -> 91
    | R.XF3 -> 92
    | R.XF4 -> 93
    | R.XF5 -> 94
    | R.XF6 -> 95
    | R.XF7 -> 96
    | R.XF8 -> 97
    | R.XF9 -> 98
    | R.XF10 -> 99
    | R.XF11 -> 100
    | R.XF12 -> 101
    | R.XF13 -> 102
    | R.XF14 -> 103
    | R.XF15 -> 104
    | R.XMTRX -> 105
    | R.PTEH -> 106
    | R.PTEL -> 107
    | R.PTEA -> 108
    | R.TTB -> 109
    | R.TEA -> 110
    | R.MMUCR -> 111
    | R.CCR -> 112
    | R.QACR0 -> 113
    | R.QACR1 -> 114
    | R.TRA -> 115
    | R.EXPEVT -> 116
    | R.INTEVT -> 117
    | R.MD -> 118
    | R.RB -> 119
    | R.BL -> 120
    | R.FD -> 121
    | R.M -> 122
    | R.Q -> 123
    | R.IMASK -> 124
    | R.S -> 125
    | R.T -> 126
    | R.FPSCR_RM -> 127
    | R.FPSCR_FLAG -> 128
    | R.FPSCR_ENABLE -> 129
    | R.FPSCR_CAUSE -> 130
    | R.FPSCR_DN -> 131
    | R.FPSCR_PR -> 132
    | R.FPSCR_SZ -> 133
    | R.FPSCR_FR -> 134
    | _ -> Utils.impossible ()

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
    | 16 -> R.R0_BANK
    | 17 -> R.R1_BANK
    | 18 -> R.R2_BANK
    | 19 -> R.R3_BANK
    | 20 -> R.R4_BANK
    | 21 -> R.R5_BANK
    | 22 -> R.R6_BANK
    | 23 -> R.R7_BANK
    | 24 -> R.SR
    | 25 -> R.GBR
    | 26 -> R.SSR
    | 27 -> R.SPC
    | 28 -> R.SGR
    | 29 -> R.DBR
    | 30 -> R.VBR
    | 31 -> R.MACH
    | 32 -> R.MACL
    | 33 -> R.PR
    | 34 -> R.FPUL
    | 35 -> R.PC
    | 36 -> R.FPSCR
    | 37 -> R.FPR0
    | 38 -> R.FPR1
    | 39 -> R.FPR2
    | 40 -> R.FPR3
    | 41 -> R.FPR4
    | 42 -> R.FPR5
    | 43 -> R.FPR6
    | 44 -> R.FPR7
    | 45 -> R.FPR8
    | 46 -> R.FPR9
    | 47 -> R.FPR10
    | 48 -> R.FPR11
    | 49 -> R.FPR12
    | 50 -> R.FPR13
    | 51 -> R.FPR14
    | 52 -> R.FPR15
    | 53 -> R.FR0
    | 54 -> R.FR1
    | 55 -> R.FR2
    | 56 -> R.FR3
    | 57 -> R.FR4
    | 58 -> R.FR5
    | 59 -> R.FR6
    | 60 -> R.FR7
    | 61 -> R.FR8
    | 62 -> R.FR9
    | 63 -> R.FR10
    | 64 -> R.FR11
    | 65 -> R.FR12
    | 66 -> R.FR13
    | 67 -> R.FR14
    | 68 -> R.FR15
    | 69 -> R.DR0
    | 70 -> R.DR2
    | 71 -> R.DR4
    | 72 -> R.DR6
    | 73 -> R.DR8
    | 74 -> R.DR10
    | 75 -> R.DR12
    | 76 -> R.DR14
    | 77 -> R.FV0
    | 78 -> R.FV4
    | 79 -> R.FV8
    | 80 -> R.FV12
    | 81 -> R.XD0
    | 82 -> R.XD2
    | 83 -> R.XD4
    | 84 -> R.XD6
    | 85 -> R.XD8
    | 86 -> R.XD10
    | 87 -> R.XD12
    | 88 -> R.XD14
    | 89 -> R.XF0
    | 90 -> R.XF1
    | 91 -> R.XF2
    | 92 -> R.XF3
    | 93 -> R.XF4
    | 94 -> R.XF5
    | 95 -> R.XF6
    | 96 -> R.XF7
    | 97 -> R.XF8
    | 98 -> R.XF9
    | 99 -> R.XF10
    | 100 -> R.XF11
    | 101 -> R.XF12
    | 102 -> R.XF13
    | 103 -> R.XF14
    | 104 -> R.XF15
    | 105 -> R.XMTRX
    | 106 -> R.PTEH
    | 107 -> R.PTEL
    | 108 -> R.PTEA
    | 109 -> R.TTB
    | 110 -> R.TEA
    | 111 -> R.MMUCR
    | 112 -> R.CCR
    | 113 -> R.QACR0
    | 114 -> R.QACR1
    | 115 -> R.TRA
    | 116 -> R.EXPEVT
    | 117 -> R.INTEVT
    | 118 -> R.MD
    | 119 -> R.RB
    | 120 -> R.BL
    | 121 -> R.FD
    | 122 -> R.M
    | 123 -> R.Q
    | 124 -> R.IMASK
    | 125 -> R.S
    | 126 -> R.T
    | 127 -> R.FPSCR_RM
    | 128 -> R.FPSCR_FLAG
    | 129 -> R.FPSCR_ENABLE
    | 130 -> R.FPSCR_CAUSE
    | 131 -> R.FPSCR_DN
    | 132 -> R.FPSCR_PR
    | 133 -> R.FPSCR_SZ
    | 134 -> R.FPSCR_FR
    | _ -> Utils.impossible ()
    |> Register.toRegID

  override __.ToString () =
    sprintf "SH4ReisterSet<%x, %x>" __.BitArray[0] __.BitArray[1]

[<RequireQualifiedAccess>]
module SH4RegisterSet =
  let singleton rid = SH4RegisterSet().Add(rid)
  let empty = SH4RegisterSet () :> RegisterSet
