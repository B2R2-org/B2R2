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

/// <summary>
/// Represents registers for SH4.<para/>
/// </summary>
type Register =
  | R0 = 0x0
  | R1 = 0x1
  | R2 = 0x2
  | R3 = 0x3
  | R4 = 0x4
  | R5 = 0x5
  | R6 = 0x6
  | R7 = 0x7
  | R8 = 0x8
  | R9 = 0x9
  | R10 = 0xA
  | R11 = 0xB
  | R12 = 0xC
  | R13 = 0xD
  | R14 = 0xE
  | R15 = 0xF
  | R0_BANK = 0x10
  | R1_BANK = 0x11
  | R2_BANK = 0x12
  | R3_BANK = 0x13
  | R4_BANK = 0x14
  | R5_BANK = 0x15
  | R6_BANK = 0x16
  | R7_BANK = 0x17
  | SR = 0x18
  | GBR = 0x19
  | SSR = 0x1A
  | SPC = 0x1B
  | SGR = 0x1C
  | DBR = 0x1D
  | VBR = 0x1E
  | MACH = 0x1F
  | MACL = 0x20
  | PR = 0x21
  | FPUL = 0x22
  | PC = 0x23
  | FPSCR = 0x24
  | FPR0 = 0x25
  | FPR1 = 0x26
  | FPR2 = 0x27
  | FPR3 = 0x28
  | FPR4 = 0x29
  | FPR5 = 0x2A
  | FPR6 = 0x2B
  | FPR7 = 0x2C
  | FPR8 = 0x2D
  | FPR9 = 0x2E
  | FPR10 = 0x2F
  | FPR11 = 0x30
  | FPR12 = 0x31
  | FPR13 = 0X32
  | FPR14 = 0x33
  | FPR15 = 0x34
  | FR0 = 0x35
  | FR1 = 0x36
  | FR2 = 0x37
  | FR3 = 0x38
  | FR4 = 0x39
  | FR5 = 0x3A
  | FR6 = 0x3B
  | FR7 = 0x3C
  | FR8 = 0x3D
  | FR9 = 0x3E
  | FR10 = 0x3F
  | FR11 = 0x40
  | FR12 = 0x41
  | FR13 = 0x42
  | FR14 = 0x43
  | FR15 = 0x44
  | XF0 = 0x45
  | XF1 = 0x46
  | XF2 = 0x47
  | XF3 = 0x48
  | XF4 = 0x49
  | XF5 = 0x4A
  | XF6 = 0x4B
  | XF7 = 0x4C
  | XF8 = 0x4D
  | XF9 = 0x4E
  | XF10 = 0x4F
  | XF11 = 0x50
  | XF12 = 0x51
  | XF13 = 0x52
  | XF14 = 0x53
  | XF15 = 0x54
  | XMTRX = 0x55
  | DR0 = 0x56
  | DR2 = 0x57
  | DR4 = 0x58
  | DR6 = 0x59
  | DR8 = 0x5A
  | DR10 = 0x5B
  | DR12 = 0x5C
  | DR14 = 0x5D
  | XD0 = 0x5E
  | XD2 = 0x5F
  | XD4 = 0x60
  | XD6 = 0x61
  | XD8 = 0x62
  | XD10 = 0x63
  | XD12 = 0x64
  | XD14 = 0x65
  | FV0 = 0x66
  | FV4 = 0x67
  | FV8 = 0x68
  | FV12 = 0x69
  | PTEH = 0x6A
  | PTEL = 0x6B
  | PTEA = 0x6C
  | TTB = 0x6D
  | TEA = 0x6E
  | MMUCR = 0x6F
  | CCR = 0x70
  | QACR0 = 0x71
  | QACR1 = 0x72
  | TRA = 0x73
  | EXPEVT = 0x74
  | INTEVT = 0x75
  | MD = 0x76
  | RB = 0x77
  | BL = 0x78
  | FD = 0x79
  | M = 0x7A
  | Q = 0x7B
  | IMASK = 0x7C
  | S = 0x7D
  | T = 0x7E
  | FPSCR_RM = 0X7F
  | FPSCR_FLAG = 0x80
  | FPSCR_ENABLE = 0x81
  | FPSCR_CAUSE = 0x82
  | FPSCR_DN = 0x83
  | FPSCR_PR = 0x84
  | FPSCR_SZ = 0x85
  | FPSCR_FR = 0x86

/// Provides functions to handle SH4 registers.
module Register =
  /// Returns the SH4 register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Returns the SH4 register from a string representation.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant() with
    | "r0" -> Register.R0
    | "r1" -> Register.R1
    | "r2" -> Register.R2
    | "r3" -> Register.R3
    | "r4" -> Register.R4
    | "r5" -> Register.R5
    | "r6" -> Register.R6
    | "r7" -> Register.R7
    | "r8" -> Register.R8
    | "r9" -> Register.R9
    | "r10" -> Register.R10
    | "r11" -> Register.R11
    | "r12" -> Register.R12
    | "r13" -> Register.R13
    | "r14" -> Register.R14
    | "r15" -> Register.R15
    | "r0_bank" -> Register.R0_BANK
    | "r1_bank" -> Register.R1_BANK
    | "r2_bank" -> Register.R2_BANK
    | "r3_bank" -> Register.R3_BANK
    | "r4_bank" -> Register.R4_BANK
    | "r5_bank" -> Register.R5_BANK
    | "r6_bank" -> Register.R6_BANK
    | "r7_bank" -> Register.R7_BANK
    | "sr" -> Register.SR
    | "gbr" -> Register.GBR
    | "ssr" -> Register.SSR
    | "spc" -> Register.SPC
    | "sgr" -> Register.SGR
    | "dbr" -> Register.DBR
    | "vbr" -> Register.VBR
    | "mach" -> Register.MACH
    | "macl" -> Register.MACL
    | "pr" -> Register.PR
    | "fpul" -> Register.FPUL
    | "pc" -> Register.PC
    | "fpscr" -> Register.FPSCR
    | "fpr0" -> Register.FPR0
    | "fpr1" -> Register.FPR1
    | "fpr2" -> Register.FPR2
    | "fpr3" -> Register.FPR3
    | "fpr4" -> Register.FPR4
    | "fpr5" -> Register.FPR5
    | "fpr6" -> Register.FPR6
    | "fpr7" -> Register.FPR7
    | "fpr8" -> Register.FPR8
    | "fpr9" -> Register.FPR9
    | "fpr10" -> Register.FPR10
    | "fpr11" -> Register.FPR11
    | "fpr12" -> Register.FPR12
    | "fpr13" -> Register.FPR13
    | "fpr14" -> Register.FPR14
    | "fpr15" -> Register.FPR15
    | "fr0" -> Register.FR0
    | "fr1" -> Register.FR1
    | "fr2" -> Register.FR2
    | "fr3" -> Register.FR3
    | "fr4" -> Register.FR4
    | "fr5" -> Register.FR5
    | "fr6" -> Register.FR6
    | "fr7" -> Register.FR7
    | "fr8" -> Register.FR8
    | "fr9" -> Register.FR9
    | "fr10" -> Register.FR10
    | "fr11" -> Register.FR11
    | "fr12" -> Register.FR12
    | "fr13" -> Register.FR13
    | "fr14" -> Register.FR14
    | "fr15" -> Register.FR15
    | "dr0" -> Register.DR0
    | "dr2" -> Register.DR2
    | "dr4" -> Register.DR4
    | "dr6" -> Register.DR6
    | "dr8" -> Register.DR8
    | "dr10" -> Register.DR10
    | "dr12" -> Register.DR12
    | "dr14" -> Register.DR14
    | "fv0" -> Register.FV0
    | "fv4" -> Register.FV4
    | "fv8" -> Register.FV8
    | "fv12" -> Register.FV12
    | "xd0" -> Register.XD0
    | "xd2" -> Register.XD2
    | "xd4" -> Register.XD4
    | "xd6" -> Register.XD6
    | "xd8" -> Register.XD8
    | "xd10" -> Register.XD10
    | "xd12" -> Register.XD12
    | "xd14" -> Register.XD14
    | "xf0" -> Register.XF0
    | "xf1" -> Register.XF1
    | "xf2" -> Register.XF2
    | "xf3" -> Register.XF3
    | "xf4" -> Register.XF4
    | "xf5" -> Register.XF5
    | "xf6" -> Register.XF6
    | "xf7" -> Register.XF7
    | "xf8" -> Register.XF8
    | "xf9" -> Register.XF9
    | "xf10" -> Register.XF10
    | "xf11" -> Register.XF11
    | "xf12" -> Register.XF12
    | "xf13" -> Register.XF13
    | "xf14" -> Register.XF14
    | "xf15" -> Register.XF15
    | "xmtrx" -> Register.XMTRX
    | "pteh" -> Register.PTEH
    | "ptel" -> Register.PTEL
    | "ptea" -> Register.PTEA
    | "ttb" -> Register.TTB
    | "tea" -> Register.TEA
    | "mmucr" -> Register.MMUCR
    | "ccr" -> Register.CCR
    | "qacr0" -> Register.QACR0
    | "qacr1" -> Register.QACR1
    | "tra" -> Register.TRA
    | "expevt" -> Register.EXPEVT
    | "intevt" -> Register.INTEVT
    | "md" -> Register.MD
    | "rb" -> Register.RB
    | "bl" -> Register.BL
    | "fd" -> Register.FD
    | "m" -> Register.M
    | "q" -> Register.Q
    | "imask" -> Register.IMASK
    | "s" -> Register.S
    | "t" -> Register.T
    | "fpscr_rm" -> Register.FPSCR_RM
    | "fpscr_flag" -> Register.FPSCR_FLAG
    | "fpscr_enable" -> Register.FPSCR_ENABLE
    | "fpscr_cause" -> Register.FPSCR_CAUSE
    | "fpscr_dn" -> Register.FPSCR_DN
    | "fpscr_pr" -> Register.FPSCR_PR
    | "fpscr_sz" -> Register.FPSCR_SZ
    | "fpscr_fr" -> Register.FPSCR_FR
    | _ -> Terminator.impossible ()

  /// Returns the register ID of a SH4 register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue(reg) |> RegisterID.create

  /// Returns the string representation of a SH4 register.
  [<CompiledName "ToString">]
  let toString reg =
    match reg with
    | Register.R0 -> "r0"
    | Register.R1 -> "r1"
    | Register.R2 -> "r2"
    | Register.R3 -> "r3"
    | Register.R4 -> "r4"
    | Register.R5 -> "r5"
    | Register.R6 -> "r6"
    | Register.R7 -> "r7"
    | Register.R8 -> "r8"
    | Register.R9 -> "r9"
    | Register.R10 -> "r10"
    | Register.R11 -> "r11"
    | Register.R12 -> "r12"
    | Register.R13 -> "r13"
    | Register.R14 -> "r14"
    | Register.R15 -> "r15"
    | Register.R0_BANK -> "r0_bank"
    | Register.R1_BANK -> "r1_bank"
    | Register.R2_BANK -> "r2_bank"
    | Register.R3_BANK -> "r3_bank"
    | Register.R4_BANK -> "r4_bank"
    | Register.R5_BANK -> "r5_bank"
    | Register.R6_BANK -> "r6_bank"
    | Register.R7_BANK -> "r7_bank"
    | Register.SR -> "sr"
    | Register.GBR -> "gbr"
    | Register.SSR -> "ssr"
    | Register.SPC -> "spc"
    | Register.SGR -> "sgr"
    | Register.DBR -> "dbr"
    | Register.VBR -> "vbr"
    | Register.MACH -> "mach"
    | Register.MACL -> "macl"
    | Register.PR -> "pr"
    | Register.FPUL -> "fpul"
    | Register.PC -> "pc"
    | Register.FPSCR -> "fpscr"
    | Register.FPR0 -> "fpr0"
    | Register.FPR1 -> "fpr1"
    | Register.FPR2 -> "fpr2"
    | Register.FPR3 -> "fpr3"
    | Register.FPR4 -> "fpr4"
    | Register.FPR5 -> "fpr5"
    | Register.FPR6 -> "fpr6"
    | Register.FPR7 -> "fpr7"
    | Register.FPR8 -> "fpr8"
    | Register.FPR9 -> "fpr9"
    | Register.FPR10 -> "fpr10"
    | Register.FPR11 -> "fpr11"
    | Register.FPR12 -> "fpr12"
    | Register.FPR13 -> "fpr13"
    | Register.FPR14 -> "fpr14"
    | Register.FPR15 -> "fpr15"
    | Register.FR0 -> "fr0"
    | Register.FR1 -> "fr1"
    | Register.FR2 -> "fr2"
    | Register.FR3 -> "fr3"
    | Register.FR4 -> "fr4"
    | Register.FR5 -> "fr5"
    | Register.FR6 -> "fr6"
    | Register.FR7 -> "fr7"
    | Register.FR8 -> "fr8"
    | Register.FR9 -> "fr9"
    | Register.FR10 -> "fr10"
    | Register.FR11 -> "fr11"
    | Register.FR12 -> "fr12"
    | Register.FR13 -> "fr13"
    | Register.FR14 -> "fr14"
    | Register.FR15 -> "fr15"
    | Register.DR0 -> "dr0"
    | Register.DR2 -> "dr2"
    | Register.DR4 -> "dr4"
    | Register.DR6 -> "dr6"
    | Register.DR8 -> "dr8"
    | Register.DR10 -> "dr10"
    | Register.DR12 -> "dr12"
    | Register.DR14 -> "dr14"
    | Register.FV0 -> "fv0"
    | Register.FV4 -> "fv4"
    | Register.FV8 -> "fv8"
    | Register.FV12 -> "fv12"
    | Register.XD0 -> "xd0"
    | Register.XD2 -> "xd2"
    | Register.XD4 -> "xd4"
    | Register.XD6 -> "xd6"
    | Register.XD8 -> "xd8"
    | Register.XD10 -> "xd10"
    | Register.XD12 -> "xd12"
    | Register.XD14 -> "xd14"
    | Register.XF0 -> "xf0"
    | Register.XF1 -> "xf1"
    | Register.XF2 -> "xf2"
    | Register.XF3 -> "xf3"
    | Register.XF4 -> "xf4"
    | Register.XF5 -> "xf5"
    | Register.XF6 -> "xf6"
    | Register.XF7 -> "xf7"
    | Register.XF8 -> "xf8"
    | Register.XF9 -> "xf9"
    | Register.XF10 -> "xf10"
    | Register.XF11 -> "xf11"
    | Register.XF12 -> "xf12"
    | Register.XF13 -> "xf13"
    | Register.XF14 -> "xf14"
    | Register.XF15 -> "xf15"
    | Register.XMTRX -> "xmtrx"
    | Register.PTEH -> "pteh"
    | Register.PTEL -> "ptel"
    | Register.PTEA -> "ptea"
    | Register.TTB -> "ttb"
    | Register.TEA -> "tea"
    | Register.MMUCR -> "mmucr"
    | Register.CCR -> "ccr"
    | Register.QACR0 -> "qacr0"
    | Register.QACR1 -> "qacr1"
    | Register.TRA -> "tra"
    | Register.EXPEVT -> "expevt"
    | Register.INTEVT -> "intevt"
    | Register.MD -> "md"
    | Register.RB -> "rb"
    | Register.BL -> "bl"
    | Register.FD -> "fd"
    | Register.M -> "m"
    | Register.Q -> "q"
    | Register.IMASK -> "imask"
    | Register.S -> "s"
    | Register.T -> "t"
    | Register.FPSCR_RM -> "fpscr_rm"
    | Register.FPSCR_FLAG -> "fpscr_flag"
    | Register.FPSCR_ENABLE -> "fpscr_enable"
    | Register.FPSCR_CAUSE -> "fpscr_cause"
    | Register.FPSCR_DN -> "fpscr_dn"
    | Register.FPSCR_PR -> "fpscr_pr"
    | Register.FPSCR_SZ -> "fpscr_sz"
    | Register.FPSCR_FR -> "fpscr_fr"
    | _ -> Terminator.impossible ()
