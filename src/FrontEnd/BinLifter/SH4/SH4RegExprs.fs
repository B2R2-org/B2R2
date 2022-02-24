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
open B2R2.BinIR.LowUIR

type internal RegExprs (wordSize) =

  let var sz t name = AST.var sz t name (SH4RegisterSet.singleton t)

  let regType = WordSize.toRegType wordSize

  member val R0 = var (regType) (Register.toRegID Register.R0) "R0" with get
  member val R1 = var (regType) (Register.toRegID Register.R1) "R1" with get
  member val R2 = var (regType) (Register.toRegID Register.R2) "R2" with get
  member val R3 = var (regType) (Register.toRegID Register.R3) "R3" with get
  member val R4 = var (regType) (Register.toRegID Register.R4) "R4" with get
  member val R5 = var (regType) (Register.toRegID Register.R5) "R5" with get
  member val R6 = var (regType) (Register.toRegID Register.R6) "R6" with get
  member val R7 = var (regType) (Register.toRegID Register.R7) "R7" with get
  member val R8 = var (regType) (Register.toRegID Register.R8) "R8" with get
  member val R9 = var (regType) (Register.toRegID Register.R9) "R9" with get
  member val R10 = var (regType) (Register.toRegID Register.R10) "R10" with get
  member val R11 = var (regType) (Register.toRegID Register.R11) "R11" with get
  member val R12 = var (regType) (Register.toRegID Register.R12) "R12" with get
  member val R13 = var (regType) (Register.toRegID Register.R13) "R13" with get
  member val R14 = var (regType) (Register.toRegID Register.R14) "R14" with get
  member val R15 = var (regType) (Register.toRegID Register.R15) "R15" with get
  member val R0_BANK = var (regType) (Register.toRegID Register.R0_BANK) "R0_BANK" with get
  member val R1_BANK = var (regType) (Register.toRegID Register.R1_BANK) "R1_BANK" with get
  member val R2_BANK = var (regType) (Register.toRegID Register.R2_BANK) "R2_BANK" with get
  member val R3_BANK = var (regType) (Register.toRegID Register.R3_BANK) "R3_BANK" with get
  member val R4_BANK = var (regType) (Register.toRegID Register.R4_BANK) "R4_BANK" with get
  member val R5_BANK = var (regType) (Register.toRegID Register.R5_BANK) "R5_BANK" with get
  member val R6_BANK = var (regType) (Register.toRegID Register.R6_BANK) "R6_BANK" with get
  member val R7_BANK = var (regType) (Register.toRegID Register.R7_BANK) "R7_BANK" with get
  member val SR = var (regType) (Register.toRegID Register.SR) "SR" with get
  member val GBR = var (regType) (Register.toRegID Register.GBR) "GBR" with get
  member val SSR = var (regType) (Register.toRegID Register.SSR) "SSR" with get
  member val SPC = var (regType) (Register.toRegID Register.SPC) "SPC" with get
  member val SGR = var (regType) (Register.toRegID Register.SGR) "SGR" with get
  member val DBR = var (regType) (Register.toRegID Register.DBR) "DBR" with get
  member val VBR = var (regType) (Register.toRegID Register.VBR) "VBR" with get
  member val MACH = var (regType) (Register.toRegID Register.MACH) "MACH" with get
  member val MACL = var (regType) (Register.toRegID Register.MACL) "MACL" with get
  member val PR = var (regType) (Register.toRegID Register.PR) "PR" with get
  member val FPUL = var (regType) (Register.toRegID Register.FPUL) "FPUL" with get
  member val PC = var (regType) (Register.toRegID Register.PC) "PC" with get
  member val FPSCR = var (regType) (Register.toRegID Register.FPSCR) "FPSCR" with get
  member val FPR0 = var (regType) (Register.toRegID Register.FPR0) "FPR0" with get
  member val FPR1 = var (regType) (Register.toRegID Register.FPR1) "FPR1" with get
  member val FPR2 = var (regType) (Register.toRegID Register.FPR2) "FPR2" with get
  member val FPR3 = var (regType) (Register.toRegID Register.FPR3) "FPR3" with get
  member val FPR4 = var (regType) (Register.toRegID Register.FPR4) "FPR4" with get
  member val FPR5 = var (regType) (Register.toRegID Register.FPR5) "FPR5" with get
  member val FPR6 = var (regType) (Register.toRegID Register.FPR6) "FPR6" with get
  member val FPR7 = var (regType) (Register.toRegID Register.FPR7) "FPR7" with get
  member val FPR8 = var (regType) (Register.toRegID Register.FPR8) "FPR8" with get
  member val FPR9 = var (regType) (Register.toRegID Register.FPR9) "FPR9" with get
  member val FPR10 = var (regType) (Register.toRegID Register.FPR10) "FPR10" with get
  member val FPR11 = var (regType) (Register.toRegID Register.FPR11) "FPR11" with get
  member val FPR12 = var (regType) (Register.toRegID Register.FPR12) "FPR12" with get
  member val FPR13 = var (regType) (Register.toRegID Register.FPR13) "FPR13" with get
  member val FPR14 = var (regType) (Register.toRegID Register.FPR14) "FPR14" with get
  member val FPR15 = var (regType) (Register.toRegID Register.FPR15) "FPR15" with get
  member val FR0 = var (regType) (Register.toRegID Register.FR0) "FR0" with get
  member val FR1 = var (regType) (Register.toRegID Register.FR1) "FR1" with get
  member val FR2 = var (regType) (Register.toRegID Register.FR2) "FR2" with get
  member val FR3 = var (regType) (Register.toRegID Register.FR3) "FR3" with get
  member val FR4 = var (regType) (Register.toRegID Register.FR4) "FR4" with get
  member val FR5 = var (regType) (Register.toRegID Register.FR5) "FR5" with get
  member val FR6 = var (regType) (Register.toRegID Register.FR6) "FR6" with get
  member val FR7 = var (regType) (Register.toRegID Register.FR7) "FR7" with get
  member val FR8 = var (regType) (Register.toRegID Register.FR8) "FR8" with get
  member val FR9 = var (regType) (Register.toRegID Register.FR9) "FR9" with get
  member val FR10 = var (regType) (Register.toRegID Register.FR10) "FR10" with get
  member val FR11 = var (regType) (Register.toRegID Register.FR11) "FR11" with get
  member val FR12 = var (regType) (Register.toRegID Register.FR12) "FR12" with get
  member val FR13 = var (regType) (Register.toRegID Register.FR13) "FR13" with get
  member val FR14 = var (regType) (Register.toRegID Register.FR14) "FR14" with get
  member val FR15 = var (regType) (Register.toRegID Register.FR15) "FR15" with get
  member val DR0 = var (regType) (Register.toRegID Register.DR0) "DR0" with get
  member val DR2 = var (regType) (Register.toRegID Register.DR2) "DR2" with get
  member val DR4 = var (regType) (Register.toRegID Register.DR4) "DR4" with get
  member val DR6 = var (regType) (Register.toRegID Register.DR6) "DR6" with get
  member val DR8 = var (regType) (Register.toRegID Register.DR8) "DR8" with get
  member val DR10 = var (regType) (Register.toRegID Register.DR10) "DR10" with get
  member val DR12 = var (regType) (Register.toRegID Register.DR12) "DR12" with get
  member val DR14 = var (regType) (Register.toRegID Register.DR14) "DR14" with get
  member val FV0 = var (regType) (Register.toRegID Register.FV0) "FV0" with get
  member val FV4 = var (regType) (Register.toRegID Register.FV4) "FV4" with get
  member val FV8 = var (regType) (Register.toRegID Register.FV8) "FV8" with get
  member val FV12 = var (regType) (Register.toRegID Register.FV12) "FV12" with get
  member val XD0 = var (regType) (Register.toRegID Register.XD0) "XD0" with get
  member val XD2 = var (regType) (Register.toRegID Register.XD2) "XD2" with get
  member val XD4 = var (regType) (Register.toRegID Register.XD4) "XD4" with get
  member val XD6 = var (regType) (Register.toRegID Register.XD6) "XD6" with get
  member val XD8 = var (regType) (Register.toRegID Register.XD8) "XD8" with get
  member val XD10 = var (regType) (Register.toRegID Register.XD10) "XD10" with get
  member val XD12 = var (regType) (Register.toRegID Register.XD12) "XD12" with get
  member val XD14 = var (regType) (Register.toRegID Register.XD14) "XD14" with get
  member val XF0 = var (regType) (Register.toRegID Register.XF0) "XF0" with get
  member val XF1 = var (regType) (Register.toRegID Register.XF1) "XF1" with get
  member val XF2 = var (regType) (Register.toRegID Register.XF2) "XF2" with get
  member val XF3 = var (regType) (Register.toRegID Register.XF3) "XF3" with get
  member val XF4 = var (regType) (Register.toRegID Register.XF4) "XF4" with get
  member val XF5 = var (regType) (Register.toRegID Register.XF5) "XF5" with get
  member val XF6 = var (regType) (Register.toRegID Register.XF6) "XF6" with get
  member val XF7 = var (regType) (Register.toRegID Register.XF7) "XF7" with get
  member val XF8 = var (regType) (Register.toRegID Register.XF8) "XF8" with get
  member val XF9 = var (regType) (Register.toRegID Register.XF9) "XF9" with get
  member val XF10 = var (regType) (Register.toRegID Register.XF10) "XF10" with get
  member val XF11 = var (regType) (Register.toRegID Register.XF11) "XF11" with get
  member val XF12 = var (regType) (Register.toRegID Register.XF12) "XF12" with get
  member val XF13 = var (regType) (Register.toRegID Register.XF13) "XF13" with get
  member val XF14 = var (regType) (Register.toRegID Register.XF14) "XF14" with get
  member val XF15 = var (regType) (Register.toRegID Register.XF15) "XF15" with get
  member val XMTRX = var (regType) (Register.toRegID Register.XMTRX) "XMTRX" with get
  member val PTEH = var (regType) (Register.toRegID Register.PTEH) "PTEH" with get
  member val PTEL = var (regType) (Register.toRegID Register.PTEL) "PTEL" with get
  member val PTEA = var (regType) (Register.toRegID Register.PTEA) "PTEA" with get
  member val TTB = var (regType) (Register.toRegID Register.TTB) "TTB" with get
  member val TEA = var (regType) (Register.toRegID Register.TEA) "TEA" with get
  member val MMUCR = var (regType) (Register.toRegID Register.MMUCR) "MMUCR" with get
  member val CCR = var (regType) (Register.toRegID Register.CCR) "CCR" with get
  member val QACR0 = var (regType) (Register.toRegID Register.QACR0) "QACR0" with get
  member val QACR1 = var (regType) (Register.toRegID Register.QACR1) "QACR1" with get
  member val TRA = var (regType) (Register.toRegID Register.TRA) "TRA" with get
  member val EXPEVT = var (regType) (Register.toRegID Register.EXPEVT) "EXPEVT" with get
  member val INTEVT = var (regType) (Register.toRegID Register.INTEVT) "INTEVT" with get
  member val MD = var (regType) (Register.toRegID Register.MD) "MD" with get
  member val RB = var (regType) (Register.toRegID Register.RB) "RB" with get
  member val BL = var (regType) (Register.toRegID Register.BL) "BL" with get
  member val FD = var (regType) (Register.toRegID Register.FD) "FD" with get
  member val M = var (regType) (Register.toRegID Register.M) "M" with get
  member val Q = var (regType) (Register.toRegID Register.Q) "Q" with get
  member val IMASK = var (regType) (Register.toRegID Register.IMASK) "IMASK" with get
  member val S = var (regType) (Register.toRegID Register.S) "S" with get
  member val T = var (regType) (Register.toRegID Register.T) "T" with get
  member val FPSCR_RM = var (regType) (Register.toRegID Register.FPSCR_RM) "FPSCR_RM" with get
  member val FPSCR_FLAG = var (regType) (Register.toRegID Register.FPSCR_FLAG) "FPSCR_FLAG" with get
  member val FPSCR_ENABLE = var (regType) (Register.toRegID Register.FPSCR_ENABLE) "FPSCR_ENABLE" with get
  member val FPSCR_CAUSE = var (regType) (Register.toRegID Register.FPSCR_CAUSE) "FPSCR_CAUSE" with get
  member val FPSCR_DN = var (regType) (Register.toRegID Register.FPSCR_DN) "FPSCR_DN" with get
  member val FPSCR_PR = var (regType) (Register.toRegID Register.FPSCR_PR) "FPSCR_PR" with get
  member val FPSCR_SZ = var (regType) (Register.toRegID Register.FPSCR_SZ) "FPSCR_SZ" with get
  member val FPSCR_FR = var (regType) (Register.toRegID Register.FPSCR_FR) "FPSCR_FR" with get

  member __.GetRegVar (name) =
    match name with
    | R.R0 -> __.R0
    | R.R1 -> __.R1
    | R.R2 -> __.R2
    | R.R3 -> __.R3
    | R.R4 -> __.R4
    | R.R5 -> __.R5
    | R.R6 -> __.R6
    | R.R7 -> __.R7
    | R.R8 -> __.R8
    | R.R9 -> __.R9
    | R.R10 -> __.R10
    | R.R11 -> __.R11
    | R.R12 -> __.R12
    | R.R13 -> __.R13
    | R.R14 -> __.R14
    | R.R15 -> __.R15
    | R.R0_BANK -> __.R0_BANK
    | R.R1_BANK -> __.R1_BANK
    | R.R2_BANK -> __.R2_BANK
    | R.R3_BANK -> __.R3_BANK
    | R.R4_BANK -> __.R4_BANK
    | R.R5_BANK -> __.R5_BANK
    | R.R6_BANK -> __.R6_BANK
    | R.R7_BANK -> __.R7_BANK
    | R.SR -> __.SR
    | R.GBR -> __.GBR
    | R.SSR -> __.SSR
    | R.SPC -> __.SPC
    | R.SGR -> __.SGR
    | R.DBR -> __.DBR
    | R.VBR -> __.VBR
    | R.MACH -> __.MACH
    | R.MACL -> __.MACL
    | R.PR -> __.PR
    | R.FPUL -> __.FPUL
    | R.PC -> __.PC
    | R.FPSCR -> __.FPSCR
    | R.FPR0 -> __.FPR0
    | R.FPR1 -> __.FPR1
    | R.FPR2 -> __.FPR2
    | R.FPR3 -> __.FPR3
    | R.FPR4 -> __.FPR4
    | R.FPR5 -> __.FPR5
    | R.FPR6 -> __.FPR6
    | R.FPR7 -> __.FPR7
    | R.FPR8 -> __.FPR8
    | R.FPR9 -> __.FPR9
    | R.FPR10 -> __.FPR10
    | R.FPR11 -> __.FPR11
    | R.FPR12 -> __.FPR12
    | R.FPR13 -> __.FPR13
    | R.FPR14 -> __.FPR14
    | R.FPR15 -> __.FPR15
    | R.FR0 -> __.FR0
    | R.FR1 -> __.FR1
    | R.FR2 -> __.FR2
    | R.FR3 -> __.FR3
    | R.FR4 -> __.FR4
    | R.FR5 -> __.FR5
    | R.FR6 -> __.FR6
    | R.FR7 -> __.FR7
    | R.FR8 -> __.FR8
    | R.FR9 -> __.FR9
    | R.FR10 -> __.FR10
    | R.FR11 -> __.FR11
    | R.FR12 -> __.FR12
    | R.FR13 -> __.FR13
    | R.FR14 -> __.FR14
    | R.FR15 -> __.FR15
    | R.DR0 -> __.DR0
    | R.DR2 -> __.DR2
    | R.DR4 -> __.DR4
    | R.DR6 -> __.DR6
    | R.DR8 -> __.DR8
    | R.DR10 -> __.DR10
    | R.DR12 -> __.DR12
    | R.DR14 -> __.DR14
    | R.FV0 -> __.FV0
    | R.FV4 -> __.FV4
    | R.FV8 -> __.FV8
    | R.FV12 -> __.FV12
    | R.XD0 -> __.XD0
    | R.XD2 -> __.XD2
    | R.XD4 -> __.XD4
    | R.XD6 -> __.XD6
    | R.XD8 -> __.XD8
    | R.XD10 -> __.XD10
    | R.XD12 -> __.XD12
    | R.XD14 -> __.XD14
    | R.XF0 -> __.XF0
    | R.XF1 -> __.XF1
    | R.XF2 -> __.XF2
    | R.XF3 -> __.XF3
    | R.XF4 -> __.XF4
    | R.XF5 -> __.XF5
    | R.XF6 -> __.XF6
    | R.XF7 -> __.XF7
    | R.XF8 -> __.XF8
    | R.XF9 -> __.XF9
    | R.XF10 -> __.XF10
    | R.XF11 -> __.XF11
    | R.XF12 -> __.XF12
    | R.XF13 -> __.XF13
    | R.XF14 -> __.XF14
    | R.XF15 -> __.XF15
    | R.XMTRX -> __.XMTRX
    | R.PTEH -> __.PTEH
    | R.PTEL -> __.PTEL
    | R.PTEA -> __.PTEA
    | R.TTB -> __.TTB
    | R.TEA -> __.TEA
    | R.MMUCR -> __.MMUCR
    | R.CCR -> __.CCR
    | R.QACR0 -> __.QACR0
    | R.QACR1 -> __.QACR1
    | R.TRA -> __.TRA
    | R.EXPEVT -> __.EXPEVT
    | R.INTEVT -> __.INTEVT
    | R.MD -> __.MD
    | R.RB -> __.RB
    | R.BL -> __.BL
    | R.FD -> __.FD
    | R.M -> __.M
    | R.Q -> __.Q
    | R.IMASK -> __.IMASK
    | R.S -> __.S
    | R.T -> __.T
    | R.FPSCR_RM -> __.FPSCR_RM
    | R.FPSCR_FLAG -> __.FPSCR_FLAG
    | R.FPSCR_ENABLE -> __.FPSCR_ENABLE
    | R.FPSCR_CAUSE -> __.FPSCR_CAUSE
    | R.FPSCR_DN -> __.FPSCR_DN
    | R.FPSCR_PR -> __.FPSCR_PR
    | R.FPSCR_SZ -> __.FPSCR_SZ
    | R.FPSCR_FR -> __.FPSCR_FR
    | _ -> raise B2R2.FrontEnd.BinLifter.UnhandledRegExprException
