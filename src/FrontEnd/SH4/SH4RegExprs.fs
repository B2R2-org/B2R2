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

namespace B2R2.FrontEnd.SH4

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type RegExprs (wordSize) =

  let var sz t name = AST.var sz t name

  let rt = WordSize.toRegType wordSize

  member val R0 = var rt (Register.toRegID R.R0) "R0" with get
  member val R1 = var rt (Register.toRegID R.R1) "R1" with get
  member val R2 = var rt (Register.toRegID R.R2) "R2" with get
  member val R3 = var rt (Register.toRegID R.R3) "R3" with get
  member val R4 = var rt (Register.toRegID R.R4) "R4" with get
  member val R5 = var rt (Register.toRegID R.R5) "R5" with get
  member val R6 = var rt (Register.toRegID R.R6) "R6" with get
  member val R7 = var rt (Register.toRegID R.R7) "R7" with get
  member val R8 = var rt (Register.toRegID R.R8) "R8" with get
  member val R9 = var rt (Register.toRegID R.R9) "R9" with get
  member val R10 = var rt (Register.toRegID R.R10) "R10" with get
  member val R11 = var rt (Register.toRegID R.R11) "R11" with get
  member val R12 = var rt (Register.toRegID R.R12) "R12" with get
  member val R13 = var rt (Register.toRegID R.R13) "R13" with get
  member val R14 = var rt (Register.toRegID R.R14) "R14" with get
  member val R15 = var rt (Register.toRegID R.R15) "R15" with get
  member val R0_BANK = var rt (Register.toRegID R.R0_BANK) "R0_BANK" with get
  member val R1_BANK = var rt (Register.toRegID R.R1_BANK) "R1_BANK" with get
  member val R2_BANK = var rt (Register.toRegID R.R2_BANK) "R2_BANK" with get
  member val R3_BANK = var rt (Register.toRegID R.R3_BANK) "R3_BANK" with get
  member val R4_BANK = var rt (Register.toRegID R.R4_BANK) "R4_BANK" with get
  member val R5_BANK = var rt (Register.toRegID R.R5_BANK) "R5_BANK" with get
  member val R6_BANK = var rt (Register.toRegID R.R6_BANK) "R6_BANK" with get
  member val R7_BANK = var rt (Register.toRegID R.R7_BANK) "R7_BANK" with get
  member val SR = var rt (Register.toRegID R.SR) "SR" with get
  member val GBR = var rt (Register.toRegID R.GBR) "GBR" with get
  member val SSR = var rt (Register.toRegID R.SSR) "SSR" with get
  member val SPC = var rt (Register.toRegID R.SPC) "SPC" with get
  member val SGR = var rt (Register.toRegID R.SGR) "SGR" with get
  member val DBR = var rt (Register.toRegID R.DBR) "DBR" with get
  member val VBR = var rt (Register.toRegID R.VBR) "VBR" with get
  member val MACH = var rt (Register.toRegID R.MACH) "MACH" with get
  member val MACL = var rt (Register.toRegID R.MACL) "MACL" with get
  member val PR = var rt (Register.toRegID R.PR) "PR" with get
  member val FPUL = var rt (Register.toRegID R.FPUL) "FPUL" with get
  member val PC = var rt (Register.toRegID R.PC) "PC" with get
  member val FPSCR = var rt (Register.toRegID R.FPSCR) "FPSCR" with get
  member val FPR0 = var rt (Register.toRegID R.FPR0) "FPR0" with get
  member val FPR1 = var rt (Register.toRegID R.FPR1) "FPR1" with get
  member val FPR2 = var rt (Register.toRegID R.FPR2) "FPR2" with get
  member val FPR3 = var rt (Register.toRegID R.FPR3) "FPR3" with get
  member val FPR4 = var rt (Register.toRegID R.FPR4) "FPR4" with get
  member val FPR5 = var rt (Register.toRegID R.FPR5) "FPR5" with get
  member val FPR6 = var rt (Register.toRegID R.FPR6) "FPR6" with get
  member val FPR7 = var rt (Register.toRegID R.FPR7) "FPR7" with get
  member val FPR8 = var rt (Register.toRegID R.FPR8) "FPR8" with get
  member val FPR9 = var rt (Register.toRegID R.FPR9) "FPR9" with get
  member val FPR10 = var rt (Register.toRegID R.FPR10) "FPR10" with get
  member val FPR11 = var rt (Register.toRegID R.FPR11) "FPR11" with get
  member val FPR12 = var rt (Register.toRegID R.FPR12) "FPR12" with get
  member val FPR13 = var rt (Register.toRegID R.FPR13) "FPR13" with get
  member val FPR14 = var rt (Register.toRegID R.FPR14) "FPR14" with get
  member val FPR15 = var rt (Register.toRegID R.FPR15) "FPR15" with get
  member val FR0 = var rt (Register.toRegID R.FR0) "FR0" with get
  member val FR1 = var rt (Register.toRegID R.FR1) "FR1" with get
  member val FR2 = var rt (Register.toRegID R.FR2) "FR2" with get
  member val FR3 = var rt (Register.toRegID R.FR3) "FR3" with get
  member val FR4 = var rt (Register.toRegID R.FR4) "FR4" with get
  member val FR5 = var rt (Register.toRegID R.FR5) "FR5" with get
  member val FR6 = var rt (Register.toRegID R.FR6) "FR6" with get
  member val FR7 = var rt (Register.toRegID R.FR7) "FR7" with get
  member val FR8 = var rt (Register.toRegID R.FR8) "FR8" with get
  member val FR9 = var rt (Register.toRegID R.FR9) "FR9" with get
  member val FR10 = var rt (Register.toRegID R.FR10) "FR10" with get
  member val FR11 = var rt (Register.toRegID R.FR11) "FR11" with get
  member val FR12 = var rt (Register.toRegID R.FR12) "FR12" with get
  member val FR13 = var rt (Register.toRegID R.FR13) "FR13" with get
  member val FR14 = var rt (Register.toRegID R.FR14) "FR14" with get
  member val FR15 = var rt (Register.toRegID R.FR15) "FR15" with get
  member val DR0 = var rt (Register.toRegID R.DR0) "DR0" with get
  member val DR2 = var rt (Register.toRegID R.DR2) "DR2" with get
  member val DR4 = var rt (Register.toRegID R.DR4) "DR4" with get
  member val DR6 = var rt (Register.toRegID R.DR6) "DR6" with get
  member val DR8 = var rt (Register.toRegID R.DR8) "DR8" with get
  member val DR10 = var rt (Register.toRegID R.DR10) "DR10" with get
  member val DR12 = var rt (Register.toRegID R.DR12) "DR12" with get
  member val DR14 = var rt (Register.toRegID R.DR14) "DR14" with get
  member val FV0 = var rt (Register.toRegID R.FV0) "FV0" with get
  member val FV4 = var rt (Register.toRegID R.FV4) "FV4" with get
  member val FV8 = var rt (Register.toRegID R.FV8) "FV8" with get
  member val FV12 = var rt (Register.toRegID R.FV12) "FV12" with get
  member val XD0 = var rt (Register.toRegID R.XD0) "XD0" with get
  member val XD2 = var rt (Register.toRegID R.XD2) "XD2" with get
  member val XD4 = var rt (Register.toRegID R.XD4) "XD4" with get
  member val XD6 = var rt (Register.toRegID R.XD6) "XD6" with get
  member val XD8 = var rt (Register.toRegID R.XD8) "XD8" with get
  member val XD10 = var rt (Register.toRegID R.XD10) "XD10" with get
  member val XD12 = var rt (Register.toRegID R.XD12) "XD12" with get
  member val XD14 = var rt (Register.toRegID R.XD14) "XD14" with get
  member val XF0 = var rt (Register.toRegID R.XF0) "XF0" with get
  member val XF1 = var rt (Register.toRegID R.XF1) "XF1" with get
  member val XF2 = var rt (Register.toRegID R.XF2) "XF2" with get
  member val XF3 = var rt (Register.toRegID R.XF3) "XF3" with get
  member val XF4 = var rt (Register.toRegID R.XF4) "XF4" with get
  member val XF5 = var rt (Register.toRegID R.XF5) "XF5" with get
  member val XF6 = var rt (Register.toRegID R.XF6) "XF6" with get
  member val XF7 = var rt (Register.toRegID R.XF7) "XF7" with get
  member val XF8 = var rt (Register.toRegID R.XF8) "XF8" with get
  member val XF9 = var rt (Register.toRegID R.XF9) "XF9" with get
  member val XF10 = var rt (Register.toRegID R.XF10) "XF10" with get
  member val XF11 = var rt (Register.toRegID R.XF11) "XF11" with get
  member val XF12 = var rt (Register.toRegID R.XF12) "XF12" with get
  member val XF13 = var rt (Register.toRegID R.XF13) "XF13" with get
  member val XF14 = var rt (Register.toRegID R.XF14) "XF14" with get
  member val XF15 = var rt (Register.toRegID R.XF15) "XF15" with get
  member val XMTRX = var rt (Register.toRegID R.XMTRX) "XMTRX" with get
  member val PTEH = var rt (Register.toRegID R.PTEH) "PTEH" with get
  member val PTEL = var rt (Register.toRegID R.PTEL) "PTEL" with get
  member val PTEA = var rt (Register.toRegID R.PTEA) "PTEA" with get
  member val TTB = var rt (Register.toRegID R.TTB) "TTB" with get
  member val TEA = var rt (Register.toRegID R.TEA) "TEA" with get
  member val MMUCR = var rt (Register.toRegID R.MMUCR) "MMUCR" with get
  member val CCR = var rt (Register.toRegID R.CCR) "CCR" with get
  member val QACR0 = var rt (Register.toRegID R.QACR0) "QACR0" with get
  member val QACR1 = var rt (Register.toRegID R.QACR1) "QACR1" with get
  member val TRA = var rt (Register.toRegID R.TRA) "TRA" with get
  member val EXPEVT = var rt (Register.toRegID R.EXPEVT) "EXPEVT" with get
  member val INTEVT = var rt (Register.toRegID R.INTEVT) "INTEVT" with get
  member val MD = var rt (Register.toRegID R.MD) "MD" with get
  member val RB = var rt (Register.toRegID R.RB) "RB" with get
  member val BL = var rt (Register.toRegID R.BL) "BL" with get
  member val FD = var rt (Register.toRegID R.FD) "FD" with get
  member val M = var rt (Register.toRegID R.M) "M" with get
  member val Q = var rt (Register.toRegID R.Q) "Q" with get
  member val IMASK = var rt (Register.toRegID R.IMASK) "IMASK" with get
  member val S = var rt (Register.toRegID R.S) "S" with get
  member val T = var rt (Register.toRegID R.T) "T" with get
  member val FPSCR_RM = var rt (Register.toRegID R.FPSCR_RM) "FPSCR_RM" with get
  member val FPSCR_FLAG =
    var rt (Register.toRegID R.FPSCR_FLAG) "FPSCR_FLAG" with get
  member val FPSCR_ENABLE =
    var rt (Register.toRegID R.FPSCR_ENABLE) "FPSCR_ENABLE" with get
  member val FPSCR_CAUSE =
    var rt (Register.toRegID R.FPSCR_CAUSE) "FPSCR_CAUSE" with get
  member val FPSCR_DN = var rt (Register.toRegID R.FPSCR_DN) "FPSCR_DN" with get
  member val FPSCR_PR = var rt (Register.toRegID R.FPSCR_PR) "FPSCR_PR" with get
  member val FPSCR_SZ = var rt (Register.toRegID R.FPSCR_SZ) "FPSCR_SZ" with get
  member val FPSCR_FR = var rt (Register.toRegID R.FPSCR_FR) "FPSCR_FR" with get

  member this.GetRegVar (name) =
    match name with
    | R.R0 -> this.R0
    | R.R1 -> this.R1
    | R.R2 -> this.R2
    | R.R3 -> this.R3
    | R.R4 -> this.R4
    | R.R5 -> this.R5
    | R.R6 -> this.R6
    | R.R7 -> this.R7
    | R.R8 -> this.R8
    | R.R9 -> this.R9
    | R.R10 -> this.R10
    | R.R11 -> this.R11
    | R.R12 -> this.R12
    | R.R13 -> this.R13
    | R.R14 -> this.R14
    | R.R15 -> this.R15
    | R.R0_BANK -> this.R0_BANK
    | R.R1_BANK -> this.R1_BANK
    | R.R2_BANK -> this.R2_BANK
    | R.R3_BANK -> this.R3_BANK
    | R.R4_BANK -> this.R4_BANK
    | R.R5_BANK -> this.R5_BANK
    | R.R6_BANK -> this.R6_BANK
    | R.R7_BANK -> this.R7_BANK
    | R.SR -> this.SR
    | R.GBR -> this.GBR
    | R.SSR -> this.SSR
    | R.SPC -> this.SPC
    | R.SGR -> this.SGR
    | R.DBR -> this.DBR
    | R.VBR -> this.VBR
    | R.MACH -> this.MACH
    | R.MACL -> this.MACL
    | R.PR -> this.PR
    | R.FPUL -> this.FPUL
    | R.PC -> this.PC
    | R.FPSCR -> this.FPSCR
    | R.FPR0 -> this.FPR0
    | R.FPR1 -> this.FPR1
    | R.FPR2 -> this.FPR2
    | R.FPR3 -> this.FPR3
    | R.FPR4 -> this.FPR4
    | R.FPR5 -> this.FPR5
    | R.FPR6 -> this.FPR6
    | R.FPR7 -> this.FPR7
    | R.FPR8 -> this.FPR8
    | R.FPR9 -> this.FPR9
    | R.FPR10 -> this.FPR10
    | R.FPR11 -> this.FPR11
    | R.FPR12 -> this.FPR12
    | R.FPR13 -> this.FPR13
    | R.FPR14 -> this.FPR14
    | R.FPR15 -> this.FPR15
    | R.FR0 -> this.FR0
    | R.FR1 -> this.FR1
    | R.FR2 -> this.FR2
    | R.FR3 -> this.FR3
    | R.FR4 -> this.FR4
    | R.FR5 -> this.FR5
    | R.FR6 -> this.FR6
    | R.FR7 -> this.FR7
    | R.FR8 -> this.FR8
    | R.FR9 -> this.FR9
    | R.FR10 -> this.FR10
    | R.FR11 -> this.FR11
    | R.FR12 -> this.FR12
    | R.FR13 -> this.FR13
    | R.FR14 -> this.FR14
    | R.FR15 -> this.FR15
    | R.DR0 -> this.DR0
    | R.DR2 -> this.DR2
    | R.DR4 -> this.DR4
    | R.DR6 -> this.DR6
    | R.DR8 -> this.DR8
    | R.DR10 -> this.DR10
    | R.DR12 -> this.DR12
    | R.DR14 -> this.DR14
    | R.FV0 -> this.FV0
    | R.FV4 -> this.FV4
    | R.FV8 -> this.FV8
    | R.FV12 -> this.FV12
    | R.XD0 -> this.XD0
    | R.XD2 -> this.XD2
    | R.XD4 -> this.XD4
    | R.XD6 -> this.XD6
    | R.XD8 -> this.XD8
    | R.XD10 -> this.XD10
    | R.XD12 -> this.XD12
    | R.XD14 -> this.XD14
    | R.XF0 -> this.XF0
    | R.XF1 -> this.XF1
    | R.XF2 -> this.XF2
    | R.XF3 -> this.XF3
    | R.XF4 -> this.XF4
    | R.XF5 -> this.XF5
    | R.XF6 -> this.XF6
    | R.XF7 -> this.XF7
    | R.XF8 -> this.XF8
    | R.XF9 -> this.XF9
    | R.XF10 -> this.XF10
    | R.XF11 -> this.XF11
    | R.XF12 -> this.XF12
    | R.XF13 -> this.XF13
    | R.XF14 -> this.XF14
    | R.XF15 -> this.XF15
    | R.XMTRX -> this.XMTRX
    | R.PTEH -> this.PTEH
    | R.PTEL -> this.PTEL
    | R.PTEA -> this.PTEA
    | R.TTB -> this.TTB
    | R.TEA -> this.TEA
    | R.MMUCR -> this.MMUCR
    | R.CCR -> this.CCR
    | R.QACR0 -> this.QACR0
    | R.QACR1 -> this.QACR1
    | R.TRA -> this.TRA
    | R.EXPEVT -> this.EXPEVT
    | R.INTEVT -> this.INTEVT
    | R.MD -> this.MD
    | R.RB -> this.RB
    | R.BL -> this.BL
    | R.FD -> this.FD
    | R.M -> this.M
    | R.Q -> this.Q
    | R.IMASK -> this.IMASK
    | R.S -> this.S
    | R.T -> this.T
    | R.FPSCR_RM -> this.FPSCR_RM
    | R.FPSCR_FLAG -> this.FPSCR_FLAG
    | R.FPSCR_ENABLE -> this.FPSCR_ENABLE
    | R.FPSCR_CAUSE -> this.FPSCR_CAUSE
    | R.FPSCR_DN -> this.FPSCR_DN
    | R.FPSCR_PR -> this.FPSCR_PR
    | R.FPSCR_SZ -> this.FPSCR_SZ
    | R.FPSCR_FR -> this.FPSCR_FR
    | _ -> raise UnhandledRegExprException
