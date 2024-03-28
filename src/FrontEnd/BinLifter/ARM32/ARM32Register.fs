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

namespace B2R2.FrontEnd.BinLifter.ARM32

open B2R2

/// ARMv7, ARMv8 AARCH32 registers.
type Register =
  /// R0.
  | R0 = 0x0
  /// R1.
  | R1 = 0x1
  /// R2.
  | R2 = 0x2
  /// R3.
  | R3 = 0x3
  /// R4.
  | R4 = 0x4
  /// R5.
  | R5 = 0x5
  /// R6.
  | R6 = 0x6
  /// R7.
  | R7 = 0x7
  /// R8.
  | R8 = 0x8
  /// SB.
  | SB = 0x9
  /// SL.
  | SL = 0xA
  /// FP.
  | FP = 0xB
  /// IP.
  | IP = 0xC
  /// SP, the stack pointer.
  | SP = 0xD
  /// LR, the link register.
  | LR = 0xE
  /// PC, the program counter.
  | PC = 0xF
  /// S0.
  | S0 = 0x10
  /// S1.
  | S1 = 0x11
  /// S2.
  | S2 = 0x12
  /// S3.
  | S3 = 0x13
  /// S4.
  | S4 = 0x14
  /// S5.
  | S5 = 0x15
  /// S6.
  | S6 = 0x16
  /// S7.
  | S7 = 0x17
  /// S8.
  | S8 = 0x18
  /// S9.
  | S9 = 0x19
  /// S10.
  | S10 = 0x1A
  /// S11.
  | S11 = 0x1B
  /// S12.
  | S12 = 0x1C
  /// S13.
  | S13 = 0x1D
  /// S14.
  | S14 = 0x1E
  /// S15.
  | S15 = 0x1F
  /// S16.
  | S16 = 0x20
  /// S17.
  | S17 = 0x21
  /// S18.
  | S18 = 0x22
  /// S19.
  | S19 = 0x23
  /// S20.
  | S20 = 0x24
  /// S21.
  | S21 = 0x25
  /// S22.
  | S22 = 0x26
  /// S23.
  | S23 = 0x27
  /// S24.
  | S24 = 0x28
  /// S25.
  | S25 = 0x29
  /// S26.
  | S26 = 0x2A
  /// S27.
  | S27 = 0x2B
  /// S28.
  | S28 = 0x2C
  /// S29.
  | S29 = 0x2D
  /// S30.
  | S30 = 0x2E
  /// S31.
  | S31 = 0x2F
  /// D0.
  | D0 = 0x30
  /// D1.
  | D1 = 0x31
  /// D2.
  | D2 = 0x32
  /// D3.
  | D3 = 0x33
  /// D4.
  | D4 = 0x34
  /// D5.
  | D5 = 0x35
  /// D6.
  | D6 = 0x36
  /// D7.
  | D7 = 0x37
  /// D8.
  | D8 = 0x38
  /// D9.
  | D9 = 0x39
  /// D10.
  | D10 = 0x3A
  /// D11.
  | D11 = 0x3B
  /// D12.
  | D12 = 0x3C
  /// D13.
  | D13 = 0x3D
  /// D14.
  | D14 = 0x3E
  /// D15.
  | D15 = 0x3F
  /// D16.
  | D16 = 0x40
  /// D17.
  | D17 = 0x41
  /// D18.
  | D18 = 0x42
  /// D19.
  | D19 = 0x43
  /// D20.
  | D20 = 0x44
  /// D21.
  | D21 = 0x45
  /// D22.
  | D22 = 0x46
  /// D23.
  | D23 = 0x47
  /// D24.
  | D24 = 0x48
  /// D25.
  | D25 = 0x49
  /// D26.
  | D26 = 0x4A
  /// D27.
  | D27 = 0x4B
  /// D28.
  | D28 = 0x4C
  /// D29.
  | D29 = 0x4D
  /// D30.
  | D30 = 0x4E
  /// D31.
  | D31 = 0x4F
  /// FPINST2.
  | FPINST2 = 0x50
  /// MVFR0.
  | MVFR0 = 0x51
  /// MVFR1.
  | MVFR1 = 0x52
  /// Q0.
  | Q0 = 0x53
  /// Q1.
  | Q1 = 0x54
  /// Q2.
  | Q2 = 0x55
  /// Q3.
  | Q3 = 0x56
  /// Q4.
  | Q4 = 0x57
  /// Q5.
  | Q5 = 0x58
  /// Q6.
  | Q6 = 0x59
  /// Q7.
  | Q7 = 0x5A
  /// Q8.
  | Q8 = 0x5B
  /// Q9.
  | Q9 = 0x5C
  /// Q10.
  | Q10 = 0x5D
  /// Q11.
  | Q11 = 0x5E
  /// Q12.
  | Q12 = 0x5F
  /// Q13.
  | Q13 = 0x60
  /// Q14.
  | Q14 = 0x61
  /// Q15.
  | Q15 = 0x62
  /// C0.
  | C0 = 0x63
  /// C1.
  | C1 = 0x64
  /// C2.
  | C2 = 0x65
  /// C3.
  | C3 = 0x66
  /// C4.
  | C4 = 0x67
  /// C5.
  | C5 = 0x68
  /// C6.
  | C6 = 0x69
  /// C7.
  | C7 = 0x6A
  /// C8.
  | C8 = 0x6B
  /// C9.
  | C9 = 0x6C
  /// C10.
  | C10 = 0x6D
  /// C11.
  | C11 = 0x6E
  /// C12.
  | C12 = 0x6F
  /// C13.
  | C13 = 0x70
  /// C14.
  | C14 = 0x71
  /// C15.
  | C15 = 0x72
  /// P0.
  | P0 = 0x73
  /// P1.
  | P1 = 0x74
  /// P2.
  | P2 = 0x75
  /// P3.
  | P3 = 0x76
  /// P4.
  | P4 = 0x77
  /// P5.
  | P5 = 0x78
  /// P6.
  | P6 = 0x79
  /// P7.
  | P7 = 0x7A
  /// P8.
  | P8 = 0x7B
  /// P9.
  | P9 = 0x7C
  /// P10.
  | P10 = 0x7D
  /// P11.
  | P11 = 0x7E
  /// P12.
  | P12 = 0x7F
  /// P13.
  | P13 = 0x80
  /// P14.
  | P14 = 0x81
  /// P15.
  | P15 = 0x82
  /// R8usr.
  | R8usr = 0x83
  /// R9usr.
  | R9usr = 0x84
  /// R10usr.
  | R10usr = 0x85
  /// R11usr.
  | R11usr = 0x86
  /// R12usr.
  | R12usr = 0x87
  /// SPusr.
  | SPusr = 0x88
  /// LRusr.
  | LRusr = 0x89
  /// SPhyp.
  | SPhyp = 0x8A
  /// SPSRhyp.
  | SPSRhyp = 0x8B
  /// ELRhyp.
  | ELRhyp = 0x8C
  /// SPsvc.
  | SPsvc = 0x8D
  /// LRsvc.
  | LRsvc = 0x8E
  /// SPSRsvc.
  | SPSRsvc = 0x8F
  /// SPabt.
  | SPabt = 0x90
  /// LRabt.
  | LRabt = 0x91
  /// SPSRabt.
  | SPSRabt = 0x92
  /// SPund.
  | SPund = 0x93
  /// LRund.
  | LRund = 0x94
  /// SPSRund.
  | SPSRund = 0x95
  /// SPmon.
  | SPmon = 0x96
  /// LRmon.
  | LRmon = 0x97
  /// SPSRmon.
  | SPSRmon = 0x98
  /// SPirq.
  | SPirq = 0x99
  /// LRirq.
  | LRirq = 0x9A
  /// SPSRirq.
  | SPSRirq = 0x9B
  /// R8fiq.
  | R8fiq = 0x9C
  /// R9fiq.
  | R9fiq = 0x9D
  /// R10fiq.
  | R10fiq = 0x9E
  /// R11fiq.
  | R11fiq = 0x9F
  /// R12fiq.
  | R12fiq = 0xA0
  /// SPfiq.
  | SPfiq = 0xA1
  /// LRfiq.
  | LRfiq = 0xA2
  /// SPSRfiq.
  | SPSRfiq = 0xA3
  /// Application Program Status Register.
  | APSR = 0xA4
  /// Current Program Status Register.
  | CPSR = 0xA5
  /// Saved Program Status Register.
  | SPSR = 0xA6
  /// Secure Configuration Register.
  | SCR = 0xA7
  /// System Control register
  | SCTLR = 0xA8
  /// Non-Secure Access Control Register.
  | NSACR = 0xA9
  /// FPSCR, Floating-point Status and Control Register, VMSA.
  | FPSCR = 0xAA
  /// Q0A is the 1st 64-bit chunk of Q0A.
  | Q0A = 0xAB
  /// Q0B is the 2nd 64-bit chunk of Q0B.
  | Q0B = 0xAC
  /// Q1A is the 1st 64-bit chunk of Q1A.
  | Q1A = 0xAD
  /// Q1B is the 2nd 64-bit chunk of Q1B.
  | Q1B = 0xAE
  /// Q2A is the 1st 64-bit chunk of Q2A.
  | Q2A = 0xAF
  /// Q2B is the 2nd 64-bit chunk of Q2B.
  | Q2B = 0xB0
  /// Q3A is the 1st 64-bit chunk of Q3A.
  | Q3A = 0xB1
  /// Q3B is the 2nd 64-bit chunk of Q3B.
  | Q3B = 0xB2
  /// Q4A is the 1st 64-bit chunk of Q4A.
  | Q4A = 0xB3
  /// Q4B is the 2nd 64-bit chunk of Q4B.
  | Q4B = 0xB4
  /// Q5A is the 1st 64-bit chunk of Q5A.
  | Q5A = 0xB5
  /// Q5B is the 2nd 64-bit chunk of Q5B.
  | Q5B = 0xB6
  /// Q6A is the 1st 64-bit chunk of Q6A.
  | Q6A = 0xB7
  /// Q6B is the 2nd 64-bit chunk of Q6B.
  | Q6B = 0xB8
  /// Q7A is the 1st 64-bit chunk of Q7A.
  | Q7A = 0xB9
  /// Q7B is the 2nd 64-bit chunk of Q7B.
  | Q7B = 0xBA
  /// Q8A is the 1st 64-bit chunk of Q8A.
  | Q8A = 0xBB
  /// Q8B is the 2nd 64-bit chunk of Q8B.
  | Q8B = 0xBC
  /// Q9A is the 1st 64-bit chunk of Q9A.
  | Q9A = 0xBD
  /// Q9B is the 2nd 64-bit chunk of Q9B.
  | Q9B = 0xBE
  /// Q10A is the 1st 64-bit chunk of Q10A.
  | Q10A = 0xBF
  /// Q10B is the 2nd 64-bit chunk of Q10B.
  | Q10B = 0xC0
  /// Q11A is the 1st 64-bit chunk of Q11A.
  | Q11A = 0xC1
  /// Q11B is the 2nd 64-bit chunk of Q11B.
  | Q11B = 0xC2
  /// Q12A is the 1st 64-bit chunk of Q12A.
  | Q12A = 0xC3
  /// Q12B is the 2nd 64-bit chunk of Q12B.
  | Q12B = 0xC4
  /// Q13A is the 1st 64-bit chunk of Q13A.
  | Q13A = 0xC5
  /// Q13B is the 2nd 64-bit chunk of Q13B.
  | Q13B = 0xC6
  /// Q14A is the 1st 64-bit chunk of Q14A.
  | Q14A = 0xC7
  /// Q14B is the 2nd 64-bit chunk of Q14B.
  | Q14B = 0xC8
  /// Q15A is the 1st 64-bit chunk of Q15A.
  | Q15A = 0xC9
  /// Q15B is the 2nd 64-bit chunk of Q15B.
  | Q15B = 0xCA

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle ARMv8 registers.
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
    | "sB" -> R.SB
    | "sL" -> R.SL
    | "fP" -> R.FP
    | "iP" -> R.IP
    | "sP" -> R.SP
    | "lR" -> R.LR
    | "pC" -> R.PC
    | "s0" -> R.S0
    | "s1" -> R.S1
    | "s2" -> R.S2
    | "s3" -> R.S3
    | "s4" -> R.S4
    | "s5" -> R.S5
    | "s6" -> R.S6
    | "s7" -> R.S7
    | "s8" -> R.S8
    | "s9" -> R.S9
    | "s10" -> R.S10
    | "s11" -> R.S11
    | "s12" -> R.S12
    | "s13" -> R.S13
    | "s14" -> R.S14
    | "s15" -> R.S15
    | "s16" -> R.S16
    | "s17" -> R.S17
    | "s18" -> R.S18
    | "s19" -> R.S19
    | "s20" -> R.S20
    | "s21" -> R.S21
    | "s22" -> R.S22
    | "s23" -> R.S23
    | "s24" -> R.S24
    | "s25" -> R.S25
    | "s26" -> R.S26
    | "s27" -> R.S27
    | "s28" -> R.S28
    | "s29" -> R.S29
    | "s30" -> R.S30
    | "s31" -> R.S31
    | "d0" -> R.D0
    | "d1" -> R.D1
    | "d2" -> R.D2
    | "d3" -> R.D3
    | "d4" -> R.D4
    | "d5" -> R.D5
    | "d6" -> R.D6
    | "d7" -> R.D7
    | "d8" -> R.D8
    | "d9" -> R.D9
    | "d10" -> R.D10
    | "d11" -> R.D11
    | "d12" -> R.D12
    | "d13" -> R.D13
    | "d14" -> R.D14
    | "d15" -> R.D15
    | "d16" -> R.D16
    | "d17" -> R.D17
    | "d18" -> R.D18
    | "d19" -> R.D19
    | "d20" -> R.D20
    | "d21" -> R.D21
    | "d22" -> R.D22
    | "d23" -> R.D23
    | "d24" -> R.D24
    | "d25" -> R.D25
    | "d26" -> R.D26
    | "d27" -> R.D27
    | "d28" -> R.D28
    | "d29" -> R.D29
    | "d30" -> R.D30
    | "d31" -> R.D31
    | "fpinst2" -> R.FPINST2
    | "mvfr0" -> R.MVFR0
    | "mvfr1" -> R.MVFR1
    | "q0" -> R.Q0
    | "q1" -> R.Q1
    | "q2" -> R.Q2
    | "q3" -> R.Q3
    | "q4" -> R.Q4
    | "q5" -> R.Q5
    | "q6" -> R.Q6
    | "q7" -> R.Q7
    | "q8" -> R.Q8
    | "q9" -> R.Q9
    | "q10" -> R.Q10
    | "q11" -> R.Q11
    | "q12" -> R.Q12
    | "q13" -> R.Q13
    | "q14" -> R.Q14
    | "q15" -> R.Q15
    | "q0a" -> R.Q0A
    | "q0b" -> R.Q0B
    | "q1a" -> R.Q1A
    | "q1b" -> R.Q1B
    | "q2a" -> R.Q2A
    | "q2b" -> R.Q2B
    | "q3a" -> R.Q3A
    | "q3b" -> R.Q3B
    | "q4a" -> R.Q4A
    | "q4b" -> R.Q4B
    | "q5a" -> R.Q5A
    | "q5b" -> R.Q5B
    | "q6a" -> R.Q6A
    | "q6b" -> R.Q6B
    | "q7a" -> R.Q7A
    | "q7b" -> R.Q7B
    | "q8a" -> R.Q8A
    | "q8b" -> R.Q8B
    | "q9a" -> R.Q9A
    | "q9b" -> R.Q9B
    | "q10a" -> R.Q10A
    | "q10b" -> R.Q10B
    | "q11a" -> R.Q11A
    | "q11b" -> R.Q11B
    | "q12a" -> R.Q12A
    | "q12b" -> R.Q12B
    | "q13a" -> R.Q13A
    | "q13b" -> R.Q13B
    | "q14a" -> R.Q14A
    | "q14b" -> R.Q14B
    | "q15a" -> R.Q15A
    | "q15b" -> R.Q15B
    | "c0" -> R.C0
    | "c1" -> R.C1
    | "c2" -> R.C2
    | "c3" -> R.C3
    | "c4" -> R.C4
    | "c5" -> R.C5
    | "c6" -> R.C6
    | "c7" -> R.C7
    | "c8" -> R.C8
    | "c9" -> R.C9
    | "c10" -> R.C10
    | "c11" -> R.C11
    | "c12" -> R.C12
    | "c13" -> R.C13
    | "c14" -> R.C14
    | "c15" -> R.C15
    | "p0" -> R.P0
    | "p1" -> R.P1
    | "p2" -> R.P2
    | "p3" -> R.P3
    | "p4" -> R.P4
    | "p5" -> R.P5
    | "p6" -> R.P6
    | "p7" -> R.P7
    | "p8" -> R.P8
    | "p9" -> R.P9
    | "p10" -> R.P10
    | "p11" -> R.P11
    | "p12" -> R.P12
    | "p13" -> R.P13
    | "p14" -> R.P14
    | "p15" -> R.P15
    | "r8usr" -> R.R8usr
    | "r9usr" -> R.R9usr
    | "r10usr" -> R.R10usr
    | "r11usr" -> R.R11usr
    | "r12usr" -> R.R12usr
    | "spusr" -> R.SPusr
    | "lrusr" -> R.LRusr
    | "sphyp" -> R.SPhyp
    | "spsrhyp" -> R.SPSRhyp
    | "elrhyp" -> R.ELRhyp
    | "spsvc" -> R.SPsvc
    | "lrsvc" -> R.LRsvc
    | "spsrsvc" -> R.SPSRsvc
    | "spabt" -> R.SPabt
    | "lrabt" -> R.LRabt
    | "spsrabt" -> R.SPSRabt
    | "spund" -> R.SPund
    | "lrund" -> R.LRund
    | "spsrund" -> R.SPSRund
    | "spmon" -> R.SPmon
    | "lrmon" -> R.LRmon
    | "spsrmon" -> R.SPSRmon
    | "spirq" -> R.SPirq
    | "lrirq" -> R.LRirq
    | "spsrirq" -> R.SPSRirq
    | "r8fiq" -> R.R8fiq
    | "r9fiq" -> R.R9fiq
    | "r10fiq" -> R.R10fiq
    | "r11fiq" -> R.R11fiq
    | "r12fiq" -> R.R12fiq
    | "spfiq" -> R.SPfiq
    | "lrfiq" -> R.LRfiq
    | "spsrfiq" -> R.SPSRfiq
    | "apsr" -> R.APSR
    | "cpsr" -> R.CPSR
    | "spsr" -> R.SPSR
    | "scr" -> R.SCR
    | "sctlr" -> R.SCTLR
    | "nsacr" -> R.NSACR
    | "fpscr" -> R.FPSCR
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
    | R.SB -> "sb"
    | R.SL -> "sl"
    | R.FP -> "fp"
    | R.IP -> "ip"
    | R.SP -> "sp"
    | R.LR -> "lr"
    | R.PC -> "pc"
    | R.S0 -> "s0"
    | R.S1 -> "s1"
    | R.S2 -> "s2"
    | R.S3 -> "s3"
    | R.S4 -> "s4"
    | R.S5 -> "s5"
    | R.S6 -> "s6"
    | R.S7 -> "s7"
    | R.S8 -> "s8"
    | R.S9 -> "s9"
    | R.S10 -> "s10"
    | R.S11 -> "s11"
    | R.S12 -> "s12"
    | R.S13 -> "s13"
    | R.S14 -> "s14"
    | R.S15 -> "s15"
    | R.S16 -> "s16"
    | R.S17 -> "s17"
    | R.S18 -> "s18"
    | R.S19 -> "s19"
    | R.S20 -> "s20"
    | R.S21 -> "s21"
    | R.S22 -> "s22"
    | R.S23 -> "s23"
    | R.S24 -> "s24"
    | R.S25 -> "s25"
    | R.S26 -> "s26"
    | R.S27 -> "s27"
    | R.S28 -> "s28"
    | R.S29 -> "s29"
    | R.S30 -> "s30"
    | R.S31 -> "s31"
    | R.D0 -> "d0"
    | R.D1 -> "d1"
    | R.D2 -> "d2"
    | R.D3 -> "d3"
    | R.D4 -> "d4"
    | R.D5 -> "d5"
    | R.D6 -> "d6"
    | R.D7 -> "d7"
    | R.D8 -> "d8"
    | R.D9 -> "d9"
    | R.D10 -> "d10"
    | R.D11 -> "d11"
    | R.D12 -> "d12"
    | R.D13 -> "d13"
    | R.D14 -> "d14"
    | R.D15 -> "d15"
    | R.D16 -> "d16"
    | R.D17 -> "d17"
    | R.D18 -> "d18"
    | R.D19 -> "d19"
    | R.D20 -> "d20"
    | R.D21 -> "d21"
    | R.D22 -> "d22"
    | R.D23 -> "d23"
    | R.D24 -> "d24"
    | R.D25 -> "d25"
    | R.D26 -> "d26"
    | R.D27 -> "d27"
    | R.D28 -> "d28"
    | R.D29 -> "d29"
    | R.D30 -> "d30"
    | R.D31 -> "d31"
    | R.FPINST2 -> "fpinst2"
    | R.MVFR0 -> "mvfr0"
    | R.MVFR1 -> "mvfr1"
    | R.Q0 -> "q0"
    | R.Q1 -> "q1"
    | R.Q2 -> "q2"
    | R.Q3 -> "q3"
    | R.Q4 -> "q4"
    | R.Q5 -> "q5"
    | R.Q6 -> "q6"
    | R.Q7 -> "q7"
    | R.Q8 -> "q8"
    | R.Q9 -> "q9"
    | R.Q10 -> "q10"
    | R.Q11 -> "q11"
    | R.Q12 -> "q12"
    | R.Q13 -> "q13"
    | R.Q14 -> "q14"
    | R.Q15 -> "q15"
    | R.Q0A -> "q0a"
    | R.Q0B -> "q0b"
    | R.Q1A -> "q1a"
    | R.Q1B -> "q1b"
    | R.Q2A -> "q2a"
    | R.Q2B -> "q2b"
    | R.Q3A -> "q3a"
    | R.Q3B -> "q3b"
    | R.Q4A -> "q4a"
    | R.Q4B -> "q4b"
    | R.Q5A -> "q5a"
    | R.Q5B -> "q5b"
    | R.Q6A -> "q6a"
    | R.Q6B -> "q6b"
    | R.Q7A -> "q7a"
    | R.Q7B -> "q7b"
    | R.Q8A -> "q8a"
    | R.Q8B -> "q8b"
    | R.Q9A -> "q9a"
    | R.Q9B -> "q9b"
    | R.Q10A -> "q10a"
    | R.Q10B -> "q10b"
    | R.Q11A -> "q11a"
    | R.Q11B -> "q11b"
    | R.Q12A -> "q12a"
    | R.Q12B -> "q12b"
    | R.Q13A -> "q13a"
    | R.Q13B -> "q13b"
    | R.Q14A -> "q14a"
    | R.Q14B -> "q14b"
    | R.Q15A -> "q15a"
    | R.Q15B -> "q15b"
    | R.C0 -> "c0"
    | R.C1 -> "c1"
    | R.C2 -> "c2"
    | R.C3 -> "c3"
    | R.C4 -> "c4"
    | R.C5 -> "c5"
    | R.C6 -> "c6"
    | R.C7 -> "c7"
    | R.C8 -> "c8"
    | R.C9 -> "c9"
    | R.C10 -> "c10"
    | R.C11 -> "c11"
    | R.C12 -> "c12"
    | R.C13 -> "c13"
    | R.C14 -> "c14"
    | R.C15 -> "c15"
    | R.P0 -> "p0"
    | R.P1 -> "p1"
    | R.P2 -> "p2"
    | R.P3 -> "p3"
    | R.P4 -> "p4"
    | R.P5 -> "p5"
    | R.P6 -> "p6"
    | R.P7 -> "p7"
    | R.P8 -> "p8"
    | R.P9 -> "p9"
    | R.P10 -> "p10"
    | R.P11 -> "p11"
    | R.P12 -> "p12"
    | R.P13 -> "p13"
    | R.P14 -> "p14"
    | R.P15 -> "p15"
    | R.APSR -> "apsr"
    | R.CPSR -> "cpsr"
    | R.SPSR -> "spsr"
    | R.SCR -> "scr"
    | R.SCTLR -> "sctlr"
    | R.NSACR -> "nsacr"
    | R.FPSCR -> "fpscr"
    | R.R8usr -> "r8_usr"
    | R.R9usr -> "r9_usr"
    | R.R10usr -> "r10_usr"
    | R.R11usr -> "r11_usr"
    | R.R12usr -> "r12_usr"
    | R.SPusr -> "sp_usr"
    | R.LRusr -> "lr_usr"
    | R.SPhyp -> "sp_hyp"
    | R.SPSRhyp -> "spsr_hyp"
    | R.ELRhyp -> "elr_hyp"
    | R.SPsvc -> "sp_svc"
    | R.LRsvc -> "lr_svc"
    | R.SPSRsvc -> "spsr_svc"
    | R.SPabt -> "sp_abt"
    | R.LRabt -> "lr_abt"
    | R.SPSRabt -> "spsr_abt"
    | R.SPund -> "sp_und"
    | R.LRund -> "lr_und"
    | R.SPSRund -> "spsr_und"
    | R.SPmon -> "sp_mon"
    | R.LRmon -> "lr_mon"
    | R.SPSRmon -> "spsr_mon"
    | R.SPirq -> "sp_irq"
    | R.LRirq -> "lr_irq"
    | R.SPSRirq -> "spsr_irq"
    | R.R8fiq -> "r8_fiq"
    | R.R9fiq -> "r9_fiq"
    | R.R10fiq -> "r10_fiq"
    | R.R11fiq -> "r11_fiq"
    | R.R12fiq -> "r12_fiq"
    | R.SPfiq -> "sp_fiq"
    | R.LRfiq -> "lr_fiq"
    | R.SPSRfiq -> "spsr_fiq"
    | _ -> Utils.impossible ()

  let toRegType = function
    | R.R0 | R.R1 | R.R2 | R.R3 | R.R4 | R.R5 | R.R6 | R.R7 | R.R8
    | R.SB | R.SL | R.FP | R.IP | R.SP | R.LR | R.PC
    | R.S0 | R.S1 | R.S2 | R.S3 | R.S4 | R.S5 | R.S6 | R.S7 | R.S8 | R.S9
    | R.S10 | R.S11 | R.S12 | R.S13 | R.S14 | R.S15 | R.S16 | R.S17
    | R.S18 | R.S19 | R.S20 | R.S21 | R.S22 | R.S23 | R.S24 | R.S25
    | R.S26 | R.S27 | R.S28 | R.S29 | R.S30 | R.S31
    | R.APSR | R.CPSR | R.SPSR | R.SCR | R.SCTLR | R.NSACR | R.FPSCR -> 32<rt>
    | R.D0 | R.D1 | R.D2 | R.D3 | R.D4 | R.D5 | R.D6 | R.D7 | R.D8 | R.D9
    | R.D10 | R.D11 | R.D12 | R.D13 | R.D14 | R.D15 | R.D16 | R.D17
    | R.D18 | R.D19 | R.D20 | R.D21 | R.D22 | R.D23 | R.D24 | R.D25
    | R.D26 | R.D27 | R.D28 | R.D29 | R.D30 | R.D31 | R.Q0A | R.Q0B
    | R.Q1A | R.Q1B | R.Q2A | R.Q2B | R.Q3A | R.Q3B | R.Q4A | R.Q4B
    | R.Q5A | R.Q5B | R.Q6A | R.Q6B | R.Q7A | R.Q7B | R.Q8A | R.Q8B
    | R.Q9A | R.Q9B | R.Q10A | R.Q10B | R.Q11A | R.Q11B | R.Q12A | R.Q12B
    | R.Q13A | R.Q13B | R.Q14A | R.Q14B | R.Q15A | R.Q15B -> 64<rt>
    | R.Q0 | R.Q1 | R.Q2 | R.Q3 | R.Q4 | R.Q5 | R.Q6 | R.Q7 | R.Q8 | R.Q9
    | R.Q10 | R.Q11 | R.Q12 | R.Q13 | R.Q14 | R.Q15 -> 128<rt>
    | _ -> Utils.impossible ()
