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

type Register =
  // General Registers (32-bit)
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
  // Control Registers (32-bit)
  | SR = 0x18
  | GBR = 0x19
  | SSR = 0x1A
  | SPC = 0x1B
  | SGR = 0x1C
  | DBR = 0x1D
  | VBR = 0x1E
  // System Registers (32-bit)
  | MACH = 0x1F
  | MACL = 0x20
  | PR = 0x21
  | FPUL = 0x22
  | PC = 0x23
  | FPSCR = 0x24
  // Single-Precision Floating-point Registers (32-bit)
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
  // Floating-Point Registers (32-bit)
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
  // Single-Precision Floating-Point Extended Registers (32-bit)
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
  // Single-precision floating-point extended register matrix. (512-bit)
  | XMTRX = 0x55
  // Double-Precision Floating-point Registers (64-bit)
  | DR0 = 0x56
  | DR2 = 0x57
  | DR4 = 0x58
  | DR6 = 0x59
  | DR8 = 0x5A
  | DR10 = 0x5B
  | DR12 = 0x5C
  | DR14 = 0x5D
  // Single-Precision Floatig-Point Extended Register Pairs (64-bit)
  | XD0 = 0x5E
  | XD2 = 0x5F
  | XD4 = 0x60
  | XD6 = 0x61
  | XD8 = 0x62
  | XD10 = 0x63
  | XD12 = 0x64
  | XD14 = 0x65
  // Single-Precison Floating-point Vector Registers (128-bit)
  | FV0 = 0x66
  | FV4 = 0x67
  | FV8 = 0x68
  | FV12 = 0x69
  // MMU-Related Registers (32-bit)
  | PTEH = 0x6A
  | PTEL = 0x6B
  | PTEA = 0x6C
  | TTB = 0x6D
  | TEA = 0x6E
  | MMUCR = 0x6F
  // Cache and Store Queue Control Registers (32-bit)
  | CCR = 0x70
  | QACR0 = 0x71
  | QACR1 = 0x72
  // Exception-Related Registers (32-bit)
  | TRA = 0x73
  | EXPEVT = 0x74
  | INTEVT = 0x75
  // Flags in the SR (Status Register) (1-bit)
  | MD = 0x76
  | RB = 0x77
  | BL = 0x78
  | FD = 0x79
  | M = 0x7A
  | Q = 0x7B
  | IMASK = 0x7C
  | S = 0x7D
  | T = 0x7E
  // Flags in the FPSCR (Floating-point Status Control Register) (1-bit)
  | FPSCR_RM = 0X7F
  | FPSCR_FLAG = 0x80
  | FPSCR_ENABLE = 0x81
  | FPSCR_CAUSE = 0x82
  | FPSCR_DN = 0x83
  | FPSCR_PR = 0x84
  | FPSCR_SZ = 0x85
  | FPSCR_FR = 0x86

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle SH4 registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "r0" -> R.R0
    | "r1" -> R.R1
    | "r2" -> R.R2
    | "r3" -> R.R3
    | "r4" -> R.R4
    | "r5" -> R.R5
    | "r6" -> R.R6
    | "r7" -> R.R7
    | "r8" -> R.R8
    | "r9" -> R.R9
    | "r10" -> R.R10
    | "r11" -> R.R11
    | "r12" -> R.R12
    | "r13" -> R.R13
    | "r14" -> R.R14
    | "r15" -> R.R15
    | "r0_bank" -> R.R0_BANK
    | "r1_bank" -> R.R1_BANK
    | "r2_bank" -> R.R2_BANK
    | "r3_bank" -> R.R3_BANK
    | "r4_bank" -> R.R4_BANK
    | "r5_bank" -> R.R5_BANK
    | "r6_bank" -> R.R6_BANK
    | "r7_bank" -> R.R7_BANK
    | "sr" -> R.SR
    | "gbr" -> R.GBR
    | "ssr" -> R.SSR
    | "spc" -> R.SPC
    | "sgr" -> R.SGR
    | "dbr" -> R.DBR
    | "vbr" -> R.VBR
    | "mach" -> R.MACH
    | "macl" -> R.MACL
    | "pr" -> R.PR
    | "fpul" -> R.FPUL
    | "pc" -> R.PC
    | "fpscr" -> R.FPSCR
    | "fpr0" -> R.FPR0
    | "fpr1" -> R.FPR1
    | "fpr2" -> R.FPR2
    | "fpr3" -> R.FPR3
    | "fpr4" -> R.FPR4
    | "fpr5" -> R.FPR5
    | "fpr6" -> R.FPR6
    | "fpr7" -> R.FPR7
    | "fpr8" -> R.FPR8
    | "fpr9" -> R.FPR9
    | "fpr10" -> R.FPR10
    | "fpr11" -> R.FPR11
    | "fpr12" -> R.FPR12
    | "fpr13" -> R.FPR13
    | "fpr14" -> R.FPR14
    | "fpr15" -> R.FPR15
    | "fr0" -> R.FR0
    | "fr1" -> R.FR1
    | "fr2" -> R.FR2
    | "fr3" -> R.FR3
    | "fr4" -> R.FR4
    | "fr5" -> R.FR5
    | "fr6" -> R.FR6
    | "fr7" -> R.FR7
    | "fr8" -> R.FR8
    | "fr9" -> R.FR9
    | "fr10" -> R.FR10
    | "fr11" -> R.FR11
    | "fr12" -> R.FR12
    | "fr13" -> R.FR13
    | "fr14" -> R.FR14
    | "fr15" -> R.FR15
    | "dr0" -> R.DR0
    | "dr2" -> R.DR2
    | "dr4" -> R.DR4
    | "dr6" -> R.DR6
    | "dr8" -> R.DR8
    | "dr10" -> R.DR10
    | "dr12" -> R.DR12
    | "dr14" -> R.DR14
    | "fv0" -> R.FV0
    | "fv4" -> R.FV4
    | "fv8" -> R.FV8
    | "fv12" -> R.FV12
    | "xd0" -> R.XD0
    | "xd2" -> R.XD2
    | "xd4" -> R.XD4
    | "xd6" -> R.XD6
    | "xd8" -> R.XD8
    | "xd10" -> R.XD10
    | "xd12" -> R.XD12
    | "xd14" -> R.XD14
    | "xf0" -> R.XF0
    | "xf1" -> R.XF1
    | "xf2" -> R.XF2
    | "xf3" -> R.XF3
    | "xf4" -> R.XF4
    | "xf5" -> R.XF5
    | "xf6" -> R.XF6
    | "xf7" -> R.XF7
    | "xf8" -> R.XF8
    | "xf9" -> R.XF9
    | "xf10" -> R.XF10
    | "xf11" -> R.XF11
    | "xf12" -> R.XF12
    | "xf13" -> R.XF13
    | "xf14" -> R.XF14
    | "xf15" -> R.XF15
    | "xmtrx" -> R.XMTRX
    | "pteh" -> R.PTEH
    | "ptel" -> R.PTEL
    | "ptea" -> R.PTEA
    | "ttb" -> R.TTB
    | "tea" -> R.TEA
    | "mmucr" -> R.MMUCR
    | "ccr" -> R.CCR
    | "qacr0" -> R.QACR0
    | "qacr1" -> R.QACR1
    | "tra" -> R.TRA
    | "expevt" -> R.EXPEVT
    | "intevt" -> R.INTEVT
    | "md" -> R.MD
    | "rb" -> R.RB
    | "bl" -> R.BL
    | "fd" -> R.FD
    | "m" -> R.M
    | "q" -> R.Q
    | "imask" -> R.IMASK
    | "s" -> R.S
    | "t" -> R.T
    | "fpscr_rm" -> R.FPSCR_RM
    | "fpscr_flag" -> R.FPSCR_FLAG
    | "fpscr_enable" -> R.FPSCR_ENABLE
    | "fpscr_cause" -> R.FPSCR_CAUSE
    | "fpscr_dn" -> R.FPSCR_DN
    | "fpscr_pr" -> R.FPSCR_PR
    | "fpscr_sz" -> R.FPSCR_SZ
    | "fpscr_fr" -> R.FPSCR_FR
    | _ -> Utils.impossible ()

  let toString = function
    | R.R0 -> "r0"
    | R.R1 -> "r1"
    | R.R2 -> "r2"
    | R.R3 -> "r3"
    | R.R4 -> "r4"
    | R.R5 -> "r5"
    | R.R6 -> "r6"
    | R.R7 -> "r7"
    | R.R8 -> "r8"
    | R.R9 -> "r9"
    | R.R10 -> "r10"
    | R.R11 -> "r11"
    | R.R12 -> "r12"
    | R.R13 -> "r13"
    | R.R14 -> "r14"
    | R.R15 -> "r15"
    | R.R0_BANK -> "r0_bank"
    | R.R1_BANK -> "r1_bank"
    | R.R2_BANK -> "r2_bank"
    | R.R3_BANK -> "r3_bank"
    | R.R4_BANK -> "r4_bank"
    | R.R5_BANK -> "r5_bank"
    | R.R6_BANK -> "r6_bank"
    | R.R7_BANK -> "r7_bank"
    | R.SR -> "sr"
    | R.GBR -> "gbr"
    | R.SSR -> "ssr"
    | R.SPC -> "spc"
    | R.SGR -> "sgr"
    | R.DBR -> "dbr"
    | R.VBR -> "vbr"
    | R.MACH -> "mach"
    | R.MACL -> "macl"
    | R.PR -> "pr"
    | R.FPUL -> "fpul"
    | R.PC -> "pc"
    | R.FPSCR -> "fpscr"
    | R.FPR0 -> "fpr0"
    | R.FPR1 -> "fpr1"
    | R.FPR2 -> "fpr2"
    | R.FPR3 -> "fpr3"
    | R.FPR4 -> "fpr4"
    | R.FPR5 -> "fpr5"
    | R.FPR6 -> "fpr6"
    | R.FPR7 -> "fpr7"
    | R.FPR8 -> "fpr8"
    | R.FPR9 -> "fpr9"
    | R.FPR10 -> "fpr10"
    | R.FPR11 -> "fpr11"
    | R.FPR12 -> "fpr12"
    | R.FPR13 -> "fpr13"
    | R.FPR14 -> "fpr14"
    | R.FPR15 -> "fpr15"
    | R.FR0 -> "fr0"
    | R.FR1 -> "fr1"
    | R.FR2 -> "fr2"
    | R.FR3 -> "fr3"
    | R.FR4 -> "fr4"
    | R.FR5 -> "fr5"
    | R.FR6 -> "fr6"
    | R.FR7 -> "fr7"
    | R.FR8 -> "fr8"
    | R.FR9 -> "fr9"
    | R.FR10 -> "fr10"
    | R.FR11 -> "fr11"
    | R.FR12 -> "fr12"
    | R.FR13 -> "fr13"
    | R.FR14 -> "fr14"
    | R.FR15 -> "fr15"
    | R.DR0 -> "dr0"
    | R.DR2 -> "dr2"
    | R.DR4 -> "dr4"
    | R.DR6 -> "dr6"
    | R.DR8 -> "dr8"
    | R.DR10 -> "dr10"
    | R.DR12 -> "dr12"
    | R.DR14 -> "dr14"
    | R.FV0 -> "fv0"
    | R.FV4 -> "fv4"
    | R.FV8 -> "fv8"
    | R.FV12 -> "fv12"
    | R.XD0 -> "xd0"
    | R.XD2 -> "xd2"
    | R.XD4 -> "xd4"
    | R.XD6 -> "xd6"
    | R.XD8 -> "xd8"
    | R.XD10 -> "xd10"
    | R.XD12 -> "xd12"
    | R.XD14 -> "xd14"
    | R.XF0 -> "xf0"
    | R.XF1 -> "xf1"
    | R.XF2 -> "xf2"
    | R.XF3 -> "xf3"
    | R.XF4 -> "xf4"
    | R.XF5 -> "xf5"
    | R.XF6 -> "xf6"
    | R.XF7 -> "xf7"
    | R.XF8 -> "xf8"
    | R.XF9 -> "xf9"
    | R.XF10 -> "xf10"
    | R.XF11 -> "xf11"
    | R.XF12 -> "xf12"
    | R.XF13 -> "xf13"
    | R.XF14 -> "xf14"
    | R.XF15 -> "xf15"
    | R.XMTRX -> "xmtrx"
    | R.PTEH -> "pteh"
    | R.PTEL -> "ptel"
    | R.PTEA -> "ptea"
    | R.TTB -> "ttb"
    | R.TEA -> "tea"
    | R.MMUCR -> "mmucr"
    | R.CCR -> "ccr"
    | R.QACR0 -> "qacr0"
    | R.QACR1 -> "qacr1"
    | R.TRA -> "tra"
    | R.EXPEVT -> "expevt"
    | R.INTEVT -> "intevt"
    | R.MD -> "md"
    | R.RB -> "rb"
    | R.BL -> "bl"
    | R.FD -> "fd"
    | R.M -> "m"
    | R.Q -> "q"
    | R.IMASK -> "imask"
    | R.S -> "s"
    | R.T -> "t"
    | R.FPSCR_RM -> "fpscr_rm"
    | R.FPSCR_FLAG -> "fpscr_flag"
    | R.FPSCR_ENABLE -> "fpscr_enable"
    | R.FPSCR_CAUSE -> "fpscr_cause"
    | R.FPSCR_DN -> "fpscr_dn"
    | R.FPSCR_PR -> "fpscr_pr"
    | R.FPSCR_SZ -> "fpscr_sz"
    | R.FPSCR_FR -> "fpscr_fr"
    | _ -> Utils.impossible ()

  let toRegType = function
    | R.MD | R.RB | R.BL | R.FD | R.M | R.Q | R.IMASK | R.S | R.T
    | R.FPSCR_RM | R.FPSCR_FLAG | R.FPSCR_ENABLE | R.FPSCR_CAUSE | R.FPSCR_DN
    | R.FPSCR_PR | R.FPSCR_SZ | R.FPSCR_FR -> 1<rt>
    | R.R0 | R.R1 | R.R2 | R.R3 | R.R4 | R.R5 | R.R6 | R.R7 | R.R8 | R.R9
    | R.R10 | R.R11 | R.R12 | R.R13 | R.R14 | R.R15 | R.R0_BANK | R.R1_BANK
    | R.R2_BANK | R.R3_BANK | R.R4_BANK | R.R5_BANK | R.R6_BANK | R.R7_BANK
    | R.SR | R.GBR | R.SSR
    | R.SPC | R.SGR | R.DBR | R.VBR | R.MACH | R.MACL | R.PR | R.FPUL | R.PC
    | R.FPSCR | R.FPR0 | R.FPR1 | R.FPR2 | R.FPR3 | R.FPR4 | R.FPR5 | R.FPR6
    | R.FPR7 | R.FPR8 | R.FPR9 | R.FPR10 | R.FPR11 | R.FPR12 | R.FPR13
    | R.FPR14 | R.FPR15 | R.FR0 | R.FR1 | R.FR2 | R.FR3 | R.FR4 | R.FR5
    | R.FR6 | R.FR7 | R.FR8 | R.FR9 | R.FR10 | R.FR11 | R.FR12 | R.FR13
    | R.FR14 | R.FR15 | R.XF0 | R.XF1 | R.XF2 | R.XF3 | R.XF4 | R.XF5 | R.XF6
    | R.XF7 | R.XF8 | R.XF9 | R.XF10 | R.XF11 | R.XF12 | R.XF13 | R.XF14
    | R.XF15 | R.PTEH | R.PTEL | R.PTEA | R.TTB | R.TEA | R.MMUCR | R.CCR
    | R.QACR0 | R.QACR1 | R.TRA | R.EXPEVT | R.INTEVT -> 32<rt>
    | R.DR0 | R.DR2 | R.DR4 | R.DR6 | R.DR8 | R.DR10 | R.DR12 | R.DR14
    | R.XD0 | R.XD2 | R.XD4 | R.XD6 | R.XD8 | R.XD10 | R.XD12
    | R.XD14  -> 64<rt>
    | R.FV0 | R.FV4 | R.FV8 | R.FV12 -> 128<rt>
    | R.XMTRX -> 512<rt>
    | _ -> Utils.impossible()


type Const = int32

type AddressingMode =
  | Regdir of Register
  | RegIndir of Register
  | PostInc of Register
  | PreDec of Register
  | RegDisp of Const * Register
  | IdxIndir of Register * Register
  | GbrDisp of Const * Register
  | IdxGbr of Register * Register
  | PCrDisp of Const * Register
  | PCr of Const
  | Imm of Const

type Operand =
  | OpImm of Const
  | OpAddr of Const
  | OpReg of AddressingMode

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand

[<NoComparison; CustomEquality>]
type InsInfo = {
  // Address.
  Address: Addr
  // Instruction Length.
  NumBytes: uint32
  // Opcode.
  Opcode: Opcode
  // Operands.
  Operands: Operands
}
with
  override __.GetHashCode () =
    hash (__.Address,
          __.NumBytes,
          __.Opcode)
  override __.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = __.Address
      && i.NumBytes = __.NumBytes
      && i.Opcode = __.Opcode
    | _ -> false
