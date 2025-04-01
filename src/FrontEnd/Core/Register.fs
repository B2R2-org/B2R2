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

/// Register module contains register enum values of all supported
/// architectures.
module B2R2.FrontEnd.Register

open B2R2

/// <summary>
/// Registers for ARMv7, ARMv8 AArch32.<para/>
/// </summary>
type ARM32 =
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

/// Helper module for ARM32 registers.
type ARM32Register =
  /// Get the Intel register from a register ID.
  static member inline Get (rid: RegisterID): ARM32 =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the ARM32 register from a string representation.
  static member Get (str: string): ARM32 =
    match str.ToLowerInvariant () with
    | "r0" -> ARM32.R0
    | "r1" -> ARM32.R1
    | "r2" -> ARM32.R2
    | "r3" -> ARM32.R3
    | "r4" -> ARM32.R4
    | "r5" -> ARM32.R5
    | "r6" -> ARM32.R6
    | "r7" -> ARM32.R7
    | "r8" -> ARM32.R8
    | "sB" -> ARM32.SB
    | "sL" -> ARM32.SL
    | "fP" -> ARM32.FP
    | "iP" -> ARM32.IP
    | "sP" -> ARM32.SP
    | "lR" -> ARM32.LR
    | "pC" -> ARM32.PC
    | "s0" -> ARM32.S0
    | "s1" -> ARM32.S1
    | "s2" -> ARM32.S2
    | "s3" -> ARM32.S3
    | "s4" -> ARM32.S4
    | "s5" -> ARM32.S5
    | "s6" -> ARM32.S6
    | "s7" -> ARM32.S7
    | "s8" -> ARM32.S8
    | "s9" -> ARM32.S9
    | "s10" -> ARM32.S10
    | "s11" -> ARM32.S11
    | "s12" -> ARM32.S12
    | "s13" -> ARM32.S13
    | "s14" -> ARM32.S14
    | "s15" -> ARM32.S15
    | "s16" -> ARM32.S16
    | "s17" -> ARM32.S17
    | "s18" -> ARM32.S18
    | "s19" -> ARM32.S19
    | "s20" -> ARM32.S20
    | "s21" -> ARM32.S21
    | "s22" -> ARM32.S22
    | "s23" -> ARM32.S23
    | "s24" -> ARM32.S24
    | "s25" -> ARM32.S25
    | "s26" -> ARM32.S26
    | "s27" -> ARM32.S27
    | "s28" -> ARM32.S28
    | "s29" -> ARM32.S29
    | "s30" -> ARM32.S30
    | "s31" -> ARM32.S31
    | "d0" -> ARM32.D0
    | "d1" -> ARM32.D1
    | "d2" -> ARM32.D2
    | "d3" -> ARM32.D3
    | "d4" -> ARM32.D4
    | "d5" -> ARM32.D5
    | "d6" -> ARM32.D6
    | "d7" -> ARM32.D7
    | "d8" -> ARM32.D8
    | "d9" -> ARM32.D9
    | "d10" -> ARM32.D10
    | "d11" -> ARM32.D11
    | "d12" -> ARM32.D12
    | "d13" -> ARM32.D13
    | "d14" -> ARM32.D14
    | "d15" -> ARM32.D15
    | "d16" -> ARM32.D16
    | "d17" -> ARM32.D17
    | "d18" -> ARM32.D18
    | "d19" -> ARM32.D19
    | "d20" -> ARM32.D20
    | "d21" -> ARM32.D21
    | "d22" -> ARM32.D22
    | "d23" -> ARM32.D23
    | "d24" -> ARM32.D24
    | "d25" -> ARM32.D25
    | "d26" -> ARM32.D26
    | "d27" -> ARM32.D27
    | "d28" -> ARM32.D28
    | "d29" -> ARM32.D29
    | "d30" -> ARM32.D30
    | "d31" -> ARM32.D31
    | "fpinst2" -> ARM32.FPINST2
    | "mvfr0" -> ARM32.MVFR0
    | "mvfr1" -> ARM32.MVFR1
    | "q0" -> ARM32.Q0
    | "q1" -> ARM32.Q1
    | "q2" -> ARM32.Q2
    | "q3" -> ARM32.Q3
    | "q4" -> ARM32.Q4
    | "q5" -> ARM32.Q5
    | "q6" -> ARM32.Q6
    | "q7" -> ARM32.Q7
    | "q8" -> ARM32.Q8
    | "q9" -> ARM32.Q9
    | "q10" -> ARM32.Q10
    | "q11" -> ARM32.Q11
    | "q12" -> ARM32.Q12
    | "q13" -> ARM32.Q13
    | "q14" -> ARM32.Q14
    | "q15" -> ARM32.Q15
    | "q0a" -> ARM32.Q0A
    | "q0b" -> ARM32.Q0B
    | "q1a" -> ARM32.Q1A
    | "q1b" -> ARM32.Q1B
    | "q2a" -> ARM32.Q2A
    | "q2b" -> ARM32.Q2B
    | "q3a" -> ARM32.Q3A
    | "q3b" -> ARM32.Q3B
    | "q4a" -> ARM32.Q4A
    | "q4b" -> ARM32.Q4B
    | "q5a" -> ARM32.Q5A
    | "q5b" -> ARM32.Q5B
    | "q6a" -> ARM32.Q6A
    | "q6b" -> ARM32.Q6B
    | "q7a" -> ARM32.Q7A
    | "q7b" -> ARM32.Q7B
    | "q8a" -> ARM32.Q8A
    | "q8b" -> ARM32.Q8B
    | "q9a" -> ARM32.Q9A
    | "q9b" -> ARM32.Q9B
    | "q10a" -> ARM32.Q10A
    | "q10b" -> ARM32.Q10B
    | "q11a" -> ARM32.Q11A
    | "q11b" -> ARM32.Q11B
    | "q12a" -> ARM32.Q12A
    | "q12b" -> ARM32.Q12B
    | "q13a" -> ARM32.Q13A
    | "q13b" -> ARM32.Q13B
    | "q14a" -> ARM32.Q14A
    | "q14b" -> ARM32.Q14B
    | "q15a" -> ARM32.Q15A
    | "q15b" -> ARM32.Q15B
    | "c0" -> ARM32.C0
    | "c1" -> ARM32.C1
    | "c2" -> ARM32.C2
    | "c3" -> ARM32.C3
    | "c4" -> ARM32.C4
    | "c5" -> ARM32.C5
    | "c6" -> ARM32.C6
    | "c7" -> ARM32.C7
    | "c8" -> ARM32.C8
    | "c9" -> ARM32.C9
    | "c10" -> ARM32.C10
    | "c11" -> ARM32.C11
    | "c12" -> ARM32.C12
    | "c13" -> ARM32.C13
    | "c14" -> ARM32.C14
    | "c15" -> ARM32.C15
    | "p0" -> ARM32.P0
    | "p1" -> ARM32.P1
    | "p2" -> ARM32.P2
    | "p3" -> ARM32.P3
    | "p4" -> ARM32.P4
    | "p5" -> ARM32.P5
    | "p6" -> ARM32.P6
    | "p7" -> ARM32.P7
    | "p8" -> ARM32.P8
    | "p9" -> ARM32.P9
    | "p10" -> ARM32.P10
    | "p11" -> ARM32.P11
    | "p12" -> ARM32.P12
    | "p13" -> ARM32.P13
    | "p14" -> ARM32.P14
    | "p15" -> ARM32.P15
    | "r8usr" -> ARM32.R8usr
    | "r9usr" -> ARM32.R9usr
    | "r10usr" -> ARM32.R10usr
    | "r11usr" -> ARM32.R11usr
    | "r12usr" -> ARM32.R12usr
    | "spusr" -> ARM32.SPusr
    | "lrusr" -> ARM32.LRusr
    | "sphyp" -> ARM32.SPhyp
    | "spsrhyp" -> ARM32.SPSRhyp
    | "elrhyp" -> ARM32.ELRhyp
    | "spsvc" -> ARM32.SPsvc
    | "lrsvc" -> ARM32.LRsvc
    | "spsrsvc" -> ARM32.SPSRsvc
    | "spabt" -> ARM32.SPabt
    | "lrabt" -> ARM32.LRabt
    | "spsrabt" -> ARM32.SPSRabt
    | "spund" -> ARM32.SPund
    | "lrund" -> ARM32.LRund
    | "spsrund" -> ARM32.SPSRund
    | "spmon" -> ARM32.SPmon
    | "lrmon" -> ARM32.LRmon
    | "spsrmon" -> ARM32.SPSRmon
    | "spirq" -> ARM32.SPirq
    | "lrirq" -> ARM32.LRirq
    | "spsrirq" -> ARM32.SPSRirq
    | "r8fiq" -> ARM32.R8fiq
    | "r9fiq" -> ARM32.R9fiq
    | "r10fiq" -> ARM32.R10fiq
    | "r11fiq" -> ARM32.R11fiq
    | "r12fiq" -> ARM32.R12fiq
    | "spfiq" -> ARM32.SPfiq
    | "lrfiq" -> ARM32.LRfiq
    | "spsrfiq" -> ARM32.SPSRfiq
    | "apsr" -> ARM32.APSR
    | "cpsr" -> ARM32.CPSR
    | "spsr" -> ARM32.SPSR
    | "scr" -> ARM32.SCR
    | "sctlr" -> ARM32.SCTLR
    | "nsacr" -> ARM32.NSACR
    | "fpscr" -> ARM32.FPSCR
    | _ -> Utils.impossible ()

  /// Get the register ID of an ARM32 register.
  static member inline ID (reg: ARM32) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of an ARM32 register.
  static member String (reg: ARM32) =
    match reg with
    | ARM32.R0 -> "r0"
    | ARM32.R1 -> "r1"
    | ARM32.R2 -> "r2"
    | ARM32.R3 -> "r3"
    | ARM32.R4 -> "r4"
    | ARM32.R5 -> "r5"
    | ARM32.R6 -> "r6"
    | ARM32.R7 -> "r7"
    | ARM32.R8 -> "r8"
    | ARM32.SB -> "sb"
    | ARM32.SL -> "sl"
    | ARM32.FP -> "fp"
    | ARM32.IP -> "ip"
    | ARM32.SP -> "sp"
    | ARM32.LR -> "lr"
    | ARM32.PC -> "pc"
    | ARM32.S0 -> "s0"
    | ARM32.S1 -> "s1"
    | ARM32.S2 -> "s2"
    | ARM32.S3 -> "s3"
    | ARM32.S4 -> "s4"
    | ARM32.S5 -> "s5"
    | ARM32.S6 -> "s6"
    | ARM32.S7 -> "s7"
    | ARM32.S8 -> "s8"
    | ARM32.S9 -> "s9"
    | ARM32.S10 -> "s10"
    | ARM32.S11 -> "s11"
    | ARM32.S12 -> "s12"
    | ARM32.S13 -> "s13"
    | ARM32.S14 -> "s14"
    | ARM32.S15 -> "s15"
    | ARM32.S16 -> "s16"
    | ARM32.S17 -> "s17"
    | ARM32.S18 -> "s18"
    | ARM32.S19 -> "s19"
    | ARM32.S20 -> "s20"
    | ARM32.S21 -> "s21"
    | ARM32.S22 -> "s22"
    | ARM32.S23 -> "s23"
    | ARM32.S24 -> "s24"
    | ARM32.S25 -> "s25"
    | ARM32.S26 -> "s26"
    | ARM32.S27 -> "s27"
    | ARM32.S28 -> "s28"
    | ARM32.S29 -> "s29"
    | ARM32.S30 -> "s30"
    | ARM32.S31 -> "s31"
    | ARM32.D0 -> "d0"
    | ARM32.D1 -> "d1"
    | ARM32.D2 -> "d2"
    | ARM32.D3 -> "d3"
    | ARM32.D4 -> "d4"
    | ARM32.D5 -> "d5"
    | ARM32.D6 -> "d6"
    | ARM32.D7 -> "d7"
    | ARM32.D8 -> "d8"
    | ARM32.D9 -> "d9"
    | ARM32.D10 -> "d10"
    | ARM32.D11 -> "d11"
    | ARM32.D12 -> "d12"
    | ARM32.D13 -> "d13"
    | ARM32.D14 -> "d14"
    | ARM32.D15 -> "d15"
    | ARM32.D16 -> "d16"
    | ARM32.D17 -> "d17"
    | ARM32.D18 -> "d18"
    | ARM32.D19 -> "d19"
    | ARM32.D20 -> "d20"
    | ARM32.D21 -> "d21"
    | ARM32.D22 -> "d22"
    | ARM32.D23 -> "d23"
    | ARM32.D24 -> "d24"
    | ARM32.D25 -> "d25"
    | ARM32.D26 -> "d26"
    | ARM32.D27 -> "d27"
    | ARM32.D28 -> "d28"
    | ARM32.D29 -> "d29"
    | ARM32.D30 -> "d30"
    | ARM32.D31 -> "d31"
    | ARM32.FPINST2 -> "fpinst2"
    | ARM32.MVFR0 -> "mvfr0"
    | ARM32.MVFR1 -> "mvfr1"
    | ARM32.Q0 -> "q0"
    | ARM32.Q1 -> "q1"
    | ARM32.Q2 -> "q2"
    | ARM32.Q3 -> "q3"
    | ARM32.Q4 -> "q4"
    | ARM32.Q5 -> "q5"
    | ARM32.Q6 -> "q6"
    | ARM32.Q7 -> "q7"
    | ARM32.Q8 -> "q8"
    | ARM32.Q9 -> "q9"
    | ARM32.Q10 -> "q10"
    | ARM32.Q11 -> "q11"
    | ARM32.Q12 -> "q12"
    | ARM32.Q13 -> "q13"
    | ARM32.Q14 -> "q14"
    | ARM32.Q15 -> "q15"
    | ARM32.Q0A -> "q0a"
    | ARM32.Q0B -> "q0b"
    | ARM32.Q1A -> "q1a"
    | ARM32.Q1B -> "q1b"
    | ARM32.Q2A -> "q2a"
    | ARM32.Q2B -> "q2b"
    | ARM32.Q3A -> "q3a"
    | ARM32.Q3B -> "q3b"
    | ARM32.Q4A -> "q4a"
    | ARM32.Q4B -> "q4b"
    | ARM32.Q5A -> "q5a"
    | ARM32.Q5B -> "q5b"
    | ARM32.Q6A -> "q6a"
    | ARM32.Q6B -> "q6b"
    | ARM32.Q7A -> "q7a"
    | ARM32.Q7B -> "q7b"
    | ARM32.Q8A -> "q8a"
    | ARM32.Q8B -> "q8b"
    | ARM32.Q9A -> "q9a"
    | ARM32.Q9B -> "q9b"
    | ARM32.Q10A -> "q10a"
    | ARM32.Q10B -> "q10b"
    | ARM32.Q11A -> "q11a"
    | ARM32.Q11B -> "q11b"
    | ARM32.Q12A -> "q12a"
    | ARM32.Q12B -> "q12b"
    | ARM32.Q13A -> "q13a"
    | ARM32.Q13B -> "q13b"
    | ARM32.Q14A -> "q14a"
    | ARM32.Q14B -> "q14b"
    | ARM32.Q15A -> "q15a"
    | ARM32.Q15B -> "q15b"
    | ARM32.C0 -> "c0"
    | ARM32.C1 -> "c1"
    | ARM32.C2 -> "c2"
    | ARM32.C3 -> "c3"
    | ARM32.C4 -> "c4"
    | ARM32.C5 -> "c5"
    | ARM32.C6 -> "c6"
    | ARM32.C7 -> "c7"
    | ARM32.C8 -> "c8"
    | ARM32.C9 -> "c9"
    | ARM32.C10 -> "c10"
    | ARM32.C11 -> "c11"
    | ARM32.C12 -> "c12"
    | ARM32.C13 -> "c13"
    | ARM32.C14 -> "c14"
    | ARM32.C15 -> "c15"
    | ARM32.P0 -> "p0"
    | ARM32.P1 -> "p1"
    | ARM32.P2 -> "p2"
    | ARM32.P3 -> "p3"
    | ARM32.P4 -> "p4"
    | ARM32.P5 -> "p5"
    | ARM32.P6 -> "p6"
    | ARM32.P7 -> "p7"
    | ARM32.P8 -> "p8"
    | ARM32.P9 -> "p9"
    | ARM32.P10 -> "p10"
    | ARM32.P11 -> "p11"
    | ARM32.P12 -> "p12"
    | ARM32.P13 -> "p13"
    | ARM32.P14 -> "p14"
    | ARM32.P15 -> "p15"
    | ARM32.APSR -> "apsr"
    | ARM32.CPSR -> "cpsr"
    | ARM32.SPSR -> "spsr"
    | ARM32.SCR -> "scr"
    | ARM32.SCTLR -> "sctlr"
    | ARM32.NSACR -> "nsacr"
    | ARM32.FPSCR -> "fpscr"
    | ARM32.R8usr -> "r8_usr"
    | ARM32.R9usr -> "r9_usr"
    | ARM32.R10usr -> "r10_usr"
    | ARM32.R11usr -> "r11_usr"
    | ARM32.R12usr -> "r12_usr"
    | ARM32.SPusr -> "sp_usr"
    | ARM32.LRusr -> "lr_usr"
    | ARM32.SPhyp -> "sp_hyp"
    | ARM32.SPSRhyp -> "spsr_hyp"
    | ARM32.ELRhyp -> "elr_hyp"
    | ARM32.SPsvc -> "sp_svc"
    | ARM32.LRsvc -> "lr_svc"
    | ARM32.SPSRsvc -> "spsr_svc"
    | ARM32.SPabt -> "sp_abt"
    | ARM32.LRabt -> "lr_abt"
    | ARM32.SPSRabt -> "spsr_abt"
    | ARM32.SPund -> "sp_und"
    | ARM32.LRund -> "lr_und"
    | ARM32.SPSRund -> "spsr_und"
    | ARM32.SPmon -> "sp_mon"
    | ARM32.LRmon -> "lr_mon"
    | ARM32.SPSRmon -> "spsr_mon"
    | ARM32.SPirq -> "sp_irq"
    | ARM32.LRirq -> "lr_irq"
    | ARM32.SPSRirq -> "spsr_irq"
    | ARM32.R8fiq -> "r8_fiq"
    | ARM32.R9fiq -> "r9_fiq"
    | ARM32.R10fiq -> "r10_fiq"
    | ARM32.R11fiq -> "r11_fiq"
    | ARM32.R12fiq -> "r12_fiq"
    | ARM32.SPfiq -> "sp_fiq"
    | ARM32.LRfiq -> "lr_fiq"
    | ARM32.SPSRfiq -> "spsr_fiq"
    | _ -> Utils.impossible ()

/// <summary>
/// Registers for ARMv8 (AArch64).<para/>
/// </summary>
type ARM64 =
  /// X0.
  | X0 = 0x0
  /// X1.
  | X1 = 0x1
  /// X2.
  | X2 = 0x2
  /// X3.
  | X3 = 0x3
  /// X4.
  | X4 = 0x4
  /// X5.
  | X5 = 0x5
  /// X6.
  | X6 = 0x6
  /// X7.
  | X7 = 0x7
  /// X8.
  | X8 = 0x8
  /// X9.
  | X9 = 0x9
  /// X10.
  | X10 = 0xA
  /// X11.
  | X11 = 0xB
  /// X12.
  | X12 = 0xC
  /// X13.
  | X13 = 0xD
  /// X14.
  | X14 = 0xE
  /// X15.
  | X15 = 0xF
  /// X16.
  | X16 = 0x10
  /// X17.
  | X17 = 0x11
  /// X18.
  | X18 = 0x12
  /// X19.
  | X19 = 0x13
  /// X20.
  | X20 = 0x14
  /// X21.
  | X21 = 0x15
  /// X22.
  | X22 = 0x16
  /// X23.
  | X23 = 0x17
  /// X24.
  | X24 = 0x18
  /// X25.
  | X25 = 0x19
  /// X26.
  | X26 = 0x1A
  /// X27.
  | X27 = 0x1B
  /// X28.
  | X28 = 0x1C
  /// X29 (FP).
  | X29 = 0x1D
  /// X30.
  | X30 = 0x1E
  /// XZR.
  | XZR = 0x1F
  /// W0.
  | W0 = 0x20
  /// W1.
  | W1 = 0x21
  /// W2.
  | W2 = 0x22
  /// W3.
  | W3 = 0x23
  /// W4.
  | W4 = 0x24
  /// W5.
  | W5 = 0x25
  /// W6.
  | W6 = 0x26
  /// W7.
  | W7 = 0x27
  /// W8.
  | W8 = 0x28
  /// W9.
  | W9 = 0x29
  /// W10.
  | W10 = 0x2A
  /// W11.
  | W11 = 0x2B
  /// W12.
  | W12 = 0x2C
  /// W13.
  | W13 = 0x2D
  /// W14.
  | W14 = 0x2E
  /// W15.
  | W15 = 0x2F
  /// W16.
  | W16 = 0x30
  /// W17.
  | W17 = 0x31
  /// W18.
  | W18 = 0x32
  /// W19.
  | W19 = 0x33
  /// W20.
  | W20 = 0x34
  /// W21.
  | W21 = 0x35
  /// W22.
  | W22 = 0x36
  /// W23.
  | W23 = 0x37
  /// W24.
  | W24 = 0x38
  /// W25.
  | W25 = 0x39
  /// W26.
  | W26 = 0x3A
  /// W27.
  | W27 = 0x3B
  /// W28.
  | W28 = 0x3C
  /// W29.
  | W29 = 0x3D
  /// W30.
  | W30 = 0x3E
  /// WZR.
  | WZR = 0x3F
  /// Stack pointer (64bit).
  | SP = 0x40
  /// Stack pointer (32bit).
  | WSP = 0x41
  /// Program counter.
  | PC = 0x42
  /// V0.
  | V0 = 0x43
  /// V1.
  | V1 = 0x44
  /// V2.
  | V2 = 0x45
  /// V3.
  | V3 = 0x46
  /// V4.
  | V4 = 0x47
  /// V5.
  | V5 = 0x48
  /// V6.
  | V6 = 0x49
  /// V7.
  | V7 = 0x4A
  /// V8.
  | V8 = 0x4B
  /// V9.
  | V9 = 0x4C
  /// v10.
  | V10 = 0x4D
  /// V11.
  | V11 = 0x4E
  /// V12.
  | V12 = 0x4F
  /// V13.
  | V13 = 0x50
  /// V14.
  | V14 = 0x51
  /// V15.
  | V15 = 0x52
  /// V16.
  | V16 = 0x53
  /// V17.
  | V17 = 0x54
  /// V18.
  | V18 = 0x55
  /// V19.
  | V19 = 0x56
  /// V20.
  | V20 = 0x57
  /// V21.
  | V21 = 0x58
  /// V22.
  | V22 = 0x59
  /// V23.
  | V23 = 0x5A
  /// V24.
  | V24 = 0x5B
  /// V25.
  | V25 = 0x5C
  /// V26.
  | V26 = 0x5D
  /// V27.
  | V27 = 0x5E
  /// V28.
  | V28 = 0x5F
  /// V29.
  | V29 = 0x60
  /// V30.
  | V30 = 0x61
  /// V31.
  | V31 = 0x62
  /// B0.
  | B0 = 0x63
  /// B1.
  | B1 = 0x64
  /// B2.
  | B2 = 0x65
  /// B3.
  | B3 = 0x66
  /// B4.
  | B4 = 0x67
  /// B5.
  | B5 = 0x68
  /// B6.
  | B6 = 0x69
  /// B7.
  | B7 = 0x6A
  /// B8.
  | B8 = 0x6B
  /// B9.
  | B9 = 0x6C
  /// B10.
  | B10 = 0x6D
  /// B11.
  | B11 = 0x6E
  /// B12.
  | B12 = 0x6F
  /// B13.
  | B13 = 0x70
  /// B14.
  | B14 = 0x71
  /// B15.
  | B15 = 0x72
  /// B16.
  | B16 = 0x73
  /// B17.
  | B17 = 0x74
  /// B18.
  | B18 = 0x75
  /// B19.
  | B19 = 0x76
  /// B20.
  | B20 = 0x77
  /// B21.
  | B21 = 0x78
  /// B22.
  | B22 = 0x79
  /// B23.
  | B23 = 0x7A
  /// B24.
  | B24 = 0x7B
  /// B25.
  | B25 = 0x7C
  /// B26.
  | B26 = 0x7D
  /// B27.
  | B27 = 0x7E
  /// B28.
  | B28 = 0x7F
  /// B29.
  | B29 = 0x80
  /// B30.
  | B30 = 0x81
  /// B31.
  | B31 = 0x82
  /// H0.
  | H0 = 0x83
  /// H1.
  | H1 = 0x84
  /// H2.
  | H2 = 0x85
  /// H3.
  | H3 = 0x86
  /// H4.
  | H4 = 0x87
  /// H5.
  | H5 = 0x88
  /// H6.
  | H6 = 0x89
  /// H7.
  | H7 = 0x8A
  /// H8.
  | H8 = 0x8B
  /// H9.
  | H9 = 0x8C
  /// H10.
  | H10 = 0x8D
  /// H11.
  | H11 = 0x8E
  /// H12.
  | H12 = 0x8F
  /// H13.
  | H13 = 0x90
  /// H14.
  | H14 = 0x91
  /// H15.
  | H15 = 0x92
  /// H16.
  | H16 = 0x93
  /// H17.
  | H17 = 0x94
  /// H18.
  | H18 = 0x95
  /// H19.
  | H19 = 0x96
  /// H20.
  | H20 = 0x97
  /// H21.
  | H21 = 0x98
  /// H22.
  | H22 = 0x99
  /// H23.
  | H23 = 0x9A
  /// H24.
  | H24 = 0x9B
  /// H25.
  | H25 = 0x9C
  /// H26.
  | H26 = 0x9D
  /// H27.
  | H27 = 0x9E
  /// H28.
  | H28 = 0x9F
  /// H29.
  | H29 = 0xA0
  /// H30.
  | H30 = 0xA1
  /// H31.
  | H31 = 0xA2
  /// S0.
  | S0 = 0xA3
  /// S1.
  | S1 = 0xA4
  /// S2.
  | S2 = 0xA5
  /// S3.
  | S3 = 0xA6
  /// S4.
  | S4 = 0xA7
  /// S5.
  | S5 = 0xA8
  /// S6.
  | S6 = 0xA9
  /// S7.
  | S7 = 0xAA
  /// S8.
  | S8 = 0xAB
  /// S9.
  | S9 = 0xAC
  /// S10.
  | S10 = 0xAD
  /// S11.
  | S11 = 0xAE
  /// S12.
  | S12 = 0xAF
  /// S13.
  | S13 = 0xB0
  /// S14.
  | S14 = 0xB1
  /// S15.
  | S15 = 0xB2
  /// S16.
  | S16 = 0xB3
  /// S17.
  | S17 = 0xB4
  /// S18.
  | S18 = 0xB5
  /// S19.
  | S19 = 0xB6
  /// S20.
  | S20 = 0xB7
  /// S21.
  | S21 = 0xB8
  /// S22.
  | S22 = 0xB9
  /// S23.
  | S23 = 0xBA
  /// S24.
  | S24 = 0xBB
  /// S25.
  | S25 = 0xBC
  /// S26.
  | S26 = 0xBD
  /// S27.
  | S27 = 0xBE
  /// S28.
  | S28 = 0xBF
  /// S29.
  | S29 = 0xC0
  /// S30.
  | S30 = 0xC1
  /// S31.
  | S31 = 0xC2
  /// D0.
  | D0 = 0xC3
  /// D1.
  | D1 = 0xC4
  /// D2.
  | D2 = 0xC5
  /// D3.
  | D3 = 0xC6
  /// D4.
  | D4 = 0xC7
  /// D5.
  | D5 = 0xC8
  /// D6.
  | D6 = 0xC9
  /// D7.
  | D7 = 0xCA
  /// D8.
  | D8 = 0xCB
  /// D9.
  | D9 = 0xCC
  /// D10.
  | D10 = 0xCD
  /// D11.
  | D11 = 0xCE
  /// D12.
  | D12 = 0xCF
  /// D13.
  | D13 = 0xD0
  /// D14.
  | D14 = 0xD1
  /// D15.
  | D15 = 0xD2
  /// D16.
  | D16 = 0xD3
  /// D17.
  | D17 = 0xD4
  /// D18.
  | D18 = 0xD5
  /// D19.
  | D19 = 0xD6
  /// D20.
  | D20 = 0xD7
  /// D21.
  | D21 = 0xD8
  /// D22.
  | D22 = 0xD9
  /// D23.
  | D23 = 0xDA
  /// D24.
  | D24 = 0xDB
  /// D25.
  | D25 = 0xDC
  /// D26.
  | D26 = 0xDD
  /// D27.
  | D27 = 0xDE
  /// D28.
  | D28 = 0xDF
  /// D29.
  | D29 = 0xE0
  /// D30.
  | D30 = 0xE1
  /// D31.
  | D31 = 0xE2
  /// Q0.
  | Q0 = 0xE3
  /// Q1.
  | Q1 = 0xE4
  /// Q2.
  | Q2 = 0xE5
  /// Q3.
  | Q3 = 0xE6
  /// Q4.
  | Q4 = 0xE7
  /// Q5.
  | Q5 = 0xE8
  /// Q6.
  | Q6 = 0xE9
  /// Q7.
  | Q7 = 0xEA
  /// Q8.
  | Q8 = 0xEB
  /// Q9.
  | Q9 = 0xEC
  /// Q10.
  | Q10 = 0xED
  /// Q11.
  | Q11 = 0xEE
  /// Q12.
  | Q12 = 0xEF
  /// Q13.
  | Q13 = 0xF0
  /// Q14.
  | Q14 = 0xF1
  /// Q15.
  | Q15 = 0xF2
  /// Q16.
  | Q16 = 0xF3
  /// Q17.
  | Q17 = 0xF4
  /// Q18.
  | Q18 = 0xF5
  /// Q19.
  | Q19 = 0xF6
  /// Q20.
  | Q20 = 0xF7
  /// Q21.
  | Q21 = 0xF8
  /// Q22.
  | Q22 = 0xF9
  /// Q23.
  | Q23 = 0xFA
  /// Q24.
  | Q24 = 0xFB
  /// Q25.
  | Q25 = 0xFC
  /// Q26.
  | Q26 = 0xFD
  /// Q27.
  | Q27 = 0xFE
  /// Q28.
  | Q28 = 0xFF
  /// Q29.
  | Q29 = 0x100
  /// Q30.
  | Q30 = 0x101
  /// Q31.
  | Q31 = 0x102
  /// V0A is the 1st 64-bit chunk of V0A.
  | V0A = 0x103
  /// V0B is the 2nd 64-bit chunk of V0B.
  | V0B = 0x104
  ///  V1A is the 1st 64-bit chunk of V1A.
  | V1A = 0x105
  /// V1B is the 2nd 64-bit chunk of V1B.
  | V1B = 0x106
  /// V2A is the 1st 64-bit chunk of V2A.
  | V2A = 0x107
  /// V2B is the 2nd 64-bit chunk of V2B.
  | V2B = 0x108
  /// V3A is the 1st 64-bit chunk of V3A.
  | V3A = 0x109
  /// V3B is the 2nd 64-bit chunk of V3B.
  | V3B = 0x10A
  /// V4A is the 1st 64-bit chunk of V4A.
  | V4A = 0x10B
  /// V4B is the 2nd 64-bit chunk of V4B.
  | V4B = 0x10C
  /// V5A is the 1st 64-bit chunk of V5A.
  | V5A = 0x10D
  /// V5B is the 2nd 64-bit chunk of V5B.
  | V5B = 0x10E
  /// V6A is the 1st 64-bit chunk of V6A.
  | V6A = 0x10F
  /// V6B is the 2nd 64-bit chunk of V6B.
  | V6B = 0x110
  /// V7A is the 1st 64-bit chunk of V7A.
  | V7A = 0x111
  /// V7B is the 2nd 64-bit chunk of V7B.
  | V7B = 0x112
  /// V8A is the 1st 64-bit chunk of V8A.
  | V8A = 0x113
  /// V8B is the 2nd 64-bit chunk of V8B.
  | V8B = 0x114
  /// V9A is the 1st 64-bit chunk of V9A.
  | V9A = 0x115
  /// V9B is the 2nd 64-bit chunk of V9B.
  | V9B = 0x116
  /// V10A is the 1st 64-bit chunk of V10A.
  | V10A = 0x117
  /// V10B is the 2nd 64-bit chunk of V10B.
  | V10B = 0x118
  /// V11A is the 1st 64-bit chunk of V11A.
  | V11A = 0x119
  /// V11B is the 2nd 64-bit chunk of V11B.
  | V11B = 0x11A
  /// V12A is the 1st 64-bit chunk of V12A.
  | V12A = 0x11B
  /// V12B is the 2nd 64-bit chunk of V12B.
  | V12B = 0x11C
  /// V13A is the 1st 64-bit chunk of V13A.
  | V13A = 0x11D
  /// V13B is the 2nd 64-bit chunk of V13B.
  | V13B = 0x11E
  /// V14A is the 1st 64-bit chunk of V14A.
  | V14A = 0x11F
  /// V14B is the 2nd 64-bit chunk of V14B.
  | V14B = 0x120
  /// V15A is the 1st 64-bit chunk of V15A.
  | V15A = 0x121
  /// V15B is the 2nd 64-bit chunk of V15B.
  | V15B = 0x122
  /// V16A is the 1st 64-bit chunk of V16A.
  | V16A = 0x123
  /// V16B is the 2nd 64-bit chunk of V16B.
  | V16B = 0x124
  /// V17A is the 1st 64-bit chunk of V17A.
  | V17A = 0x125
  /// V17B is the 2nd 64-bit chunk of V17B.
  | V17B = 0x126
  /// V18A is the 1st 64-bit chunk of V18A.
  | V18A = 0x127
  /// V18B is the 2nd 64-bit chunk of V18B.
  | V18B = 0x128
  /// V19A is the 1st 64-bit chunk of V19A.
  | V19A = 0x129
  /// V19B is the 2nd 64-bit chunk of V19B.
  | V19B = 0x12A
  /// V20A is the 1st 64-bit chunk of V20A.
  | V20A = 0x12B
  /// V20B is the 2nd 64-bit chunk of V20B.
  | V20B = 0x12C
  /// V21A is the 1st 64-bit chunk of V21A.
  | V21A = 0x12D
  /// V21B is the 2nd 64-bit chunk of V21B.
  | V21B = 0x12E
  /// V22A is the 1st 64-bit chunk of V22A.
  | V22A = 0x12F
  /// V22B is the 2nd 64-bit chunk of V22B.
  | V22B = 0x130
  /// V23A is the 1st 64-bit chunk of V23A.
  | V23A = 0x131
  /// V23B is the 2nd 64-bit chunk of V23B.
  | V23B = 0x132
  /// V24A is the 1st 64-bit chunk of V24A.
  | V24A = 0x133
  /// V24B is the 2nd 64-bit chunk of V24B.
  | V24B = 0x134
  /// V25A is the 1st 64-bit chunk of V25A.
  | V25A = 0x135
  /// V25B is the 2nd 64-bit chunk of V25B.
  | V25B = 0x136
  /// V26A is the 1st 64-bit chunk of V26A.
  | V26A = 0x137
  /// V26B is the 2nd 64-bit chunk of V26B.
  | V26B = 0x138
  /// V27A is the 1st 64-bit chunk of V27A.
  | V27A = 0x139
  /// V27B is the 2nd 64-bit chunk of V27B.
  | V27B = 0x13A
  /// V28A is the 1st 64-bit chunk of V28A.
  | V28A = 0x13B
  /// V28B is the 2nd 64-bit chunk of V28B.
  | V28B = 0x13C
  /// V29A is the 1st 64-bit chunk of V29A.
  | V29A = 0x13D
  /// V29B is the 2nd 64-bit chunk of V29B.
  | V29B = 0x13E
  /// V30A is the 1st 64-bit chunk of V30A.
  | V30A = 0x13F
  /// V30B is the 2nd 64-bit chunk of V30B.
  | V30B = 0x140
  /// V31A is the 1st 64-bit chunk of V31A.
  | V31A = 0x141
  /// V31B is the 2nd 64-bit chunk of V31B.
  | V31B = 0x142
  /// C0.
  | C0 = 0x143
  /// C1.
  | C1 = 0x144
  /// C2.
  | C2 = 0x145
  /// C3.
  | C3 = 0x146
  /// C4.
  | C4 = 0x147
  /// C5.
  | C5 = 0x148
  /// C6
  | C6 = 0x149
  /// C7.
  | C7 = 0x14A
  /// C8.
  | C8 = 0x14B
  /// C9.
  | C9 = 0x14C
  /// C10.
  | C10 = 0x14D
  /// C11.
  | C11 = 0x14E
  /// C12.
  | C12 = 0x14F
  /// C13.
  | C13 = 0x150
  /// C14.
  | C14 = 0x151
  /// C15.
  | C15 = 0x152
  /// Negative condition flag.
  | N = 0x153
  /// Zero condition flag.
  | Z = 0x154
  /// Carry condition flag.
  | C = 0x155
  /// Overflow condition flag.
  | V = 0x156
  /// Auxiliary Control Register (EL1).
  | ACTLREL1 = 0x157
  /// Auxiliary Control Register (EL2).
  | ACTLREL2 = 0x158
  /// Auxiliary Control Register (EL3).
  | ACTLREL3 = 0x159
  /// Auxiliary Fault Status Register 0 (EL1).
  | AFSR0EL1 = 0x15A
  /// Auxiliary Fault Status Register 0 (EL2).
  | AFSR0EL2 = 0x15B
  /// Auxiliary Fault Status Register 0 (EL3).
  | AFSR0EL3 = 0x15C
  /// Auxiliary Fault Status Register 1 (EL1).
  | AFSR1EL1 = 0x15D
  /// Auxiliary Fault Status Register 1 (EL2).
  | AFSR1EL2 = 0x15E
  /// Auxiliary Fault Status Register 1 (EL3).
  | AFSR1EL3 = 0x15F
  /// Auxiliary ID Register.
  | AIDREL1 = 0x160
  /// Auxiliary Memory Attribute Indirection Register (EL1).
  | AMAIREL1 = 0x161
  /// Auxiliary Memory Attribute Indirection Register (EL2).
  | AMAIREL2 = 0x162
  /// Auxiliary Memory Attribute Indirection Register (EL3).
  | AMAIREL3 = 0x163
  /// Current Cache Size ID Register.
  | CCSIDREL1 = 0x164
  /// Cache Level ID Register.
  | CLIDREL1 = 0x165
  /// Context ID Register (EL1).
  | CONTEXTIDREL1 = 0x166
  /// Architectural Feature Access Control Register.
  | CPACREL1 = 0x167
  /// Architectural Feature Trap Register (EL2).
  | CPTREL2 = 0x168
  /// Architectural Feature Trap Register (EL3).
  | CPTREL3 = 0x169
  /// Cache Size Selection Register.
  | CSSELREL1 = 0x16A
  /// Cache Type Register.
  | CTREL0 = 0x16B
  /// Domain Access Control Register.
  | DACR32EL2 = 0x16C
  /// Data Cache Zero ID register.
  | DCZIDEL0 = 0x16D
  /// Exception Syndrome Register (EL1).
  | ESREL1 = 0x16E
  /// Exception Syndrome Register (EL2).
  | ESREL2 = 0x16F
  /// Exception Syndrome Register (EL3).
  | ESREL3 = 0x170
  /// Hypervisor IPA Fault Address Register.
  | HPFAREL2 = 0x171
  /// EL0 Read/Write Software Thread ID Register.
  | TPIDREL0 = 0x172
  /// Main ID Register.
  | MIDREL1 = 0x173
  /// Floating-point Control Register.
  | FPCR = 0x174
  /// Floating-point Status Register.
  | FPSR = 0x175
  /// Pseudo register for passing a return value from an external call. This is
  /// used to handle instruction semantics for Exclusive Monitor (EM).
  | ERET = 0x176
  /// Condition Flags.
  | NZCV = 0x177
  /// S<op0>_<op1>_<Cn>_<Cm>_<op2>.
  | S3_5_C3_C2_0 = 0x178
  | S3_7_C2_C2_7 = 0x179
  | S0_0_C2_C9_3 = 0x180
  | S2_7_C12_C7_6 = 0x181

/// Helper module for ARM64 registers.
type ARM64Register =
  /// Get the ARM64 register from a register ID.
  static member inline Get (rid: RegisterID): ARM64 =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the ARM64 register from a string representation.
  static member Get (str: string): ARM64 =
    match str.ToLowerInvariant () with
    | "x0" -> ARM64.X0
    | "x1" -> ARM64.X1
    | "x2" -> ARM64.X2
    | "x3" -> ARM64.X3
    | "x4" -> ARM64.X4
    | "x5" -> ARM64.X5
    | "x6" -> ARM64.X6
    | "x7" -> ARM64.X7
    | "x8" -> ARM64.X8
    | "x9" -> ARM64.X9
    | "x10" -> ARM64.X10
    | "x11" -> ARM64.X11
    | "x12" -> ARM64.X12
    | "x13" -> ARM64.X13
    | "x14" -> ARM64.X14
    | "x15" -> ARM64.X15
    | "x16" -> ARM64.X16
    | "x17" -> ARM64.X17
    | "x18" -> ARM64.X18
    | "x19" -> ARM64.X19
    | "x20" -> ARM64.X20
    | "x21" -> ARM64.X21
    | "x22" -> ARM64.X22
    | "x23" -> ARM64.X23
    | "x24" -> ARM64.X24
    | "x25" -> ARM64.X25
    | "x26" -> ARM64.X26
    | "x27" -> ARM64.X27
    | "x28" -> ARM64.X28
    | "x29" -> ARM64.X29
    | "x30" -> ARM64.X30
    | "xzr" -> ARM64.XZR
    | "w0" -> ARM64.W0
    | "w1" -> ARM64.W1
    | "w2" -> ARM64.W2
    | "w3" -> ARM64.W3
    | "w4" -> ARM64.W4
    | "w5" -> ARM64.W5
    | "w6" -> ARM64.W6
    | "w7" -> ARM64.W7
    | "w8" -> ARM64.W8
    | "w9" -> ARM64.W9
    | "w10" -> ARM64.W10
    | "w11" -> ARM64.W11
    | "w12" -> ARM64.W12
    | "w13" -> ARM64.W13
    | "w14" -> ARM64.W14
    | "w15" -> ARM64.W15
    | "w16" -> ARM64.W16
    | "w17" -> ARM64.W17
    | "w18" -> ARM64.W18
    | "w19" -> ARM64.W19
    | "w20" -> ARM64.W20
    | "w21" -> ARM64.W21
    | "w22" -> ARM64.W22
    | "w23" -> ARM64.W23
    | "w24" -> ARM64.W24
    | "w25" -> ARM64.W25
    | "w26" -> ARM64.W26
    | "w27" -> ARM64.W27
    | "w28" -> ARM64.W28
    | "w29" -> ARM64.W29
    | "w30" -> ARM64.W30
    | "wzr" -> ARM64.WZR
    | "sp" -> ARM64.SP
    | "wsp" -> ARM64.WSP
    | "pc" -> ARM64.PC
    | "v0" -> ARM64.V0
    | "v1" -> ARM64.V1
    | "v2" -> ARM64.V2
    | "v3" -> ARM64.V3
    | "v4" -> ARM64.V4
    | "v5" -> ARM64.V5
    | "v6" -> ARM64.V6
    | "v7" -> ARM64.V7
    | "v8" -> ARM64.V8
    | "v9" -> ARM64.V9
    | "v10" -> ARM64.V10
    | "v11" -> ARM64.V11
    | "v12" -> ARM64.V12
    | "v13" -> ARM64.V13
    | "v14" -> ARM64.V14
    | "v15" -> ARM64.V15
    | "v16" -> ARM64.V16
    | "v17" -> ARM64.V17
    | "v18" -> ARM64.V18
    | "v19" -> ARM64.V19
    | "v20" -> ARM64.V20
    | "v21" -> ARM64.V21
    | "v22" -> ARM64.V22
    | "v23" -> ARM64.V23
    | "v24" -> ARM64.V24
    | "v25" -> ARM64.V25
    | "v26" -> ARM64.V26
    | "v27" -> ARM64.V27
    | "v28" -> ARM64.V28
    | "v29" -> ARM64.V29
    | "v30" -> ARM64.V30
    | "v31" -> ARM64.V31
    | "b0" -> ARM64.B0
    | "b1" -> ARM64.B1
    | "b2" -> ARM64.B2
    | "b3" -> ARM64.B3
    | "b4" -> ARM64.B4
    | "b5" -> ARM64.B5
    | "b6" -> ARM64.B6
    | "b7" -> ARM64.B7
    | "b8" -> ARM64.B8
    | "b9" -> ARM64.B9
    | "b10" -> ARM64.B10
    | "b11" -> ARM64.B11
    | "b12" -> ARM64.B12
    | "b13" -> ARM64.B13
    | "b14" -> ARM64.B14
    | "b15" -> ARM64.B15
    | "b16" -> ARM64.B16
    | "b17" -> ARM64.B17
    | "b18" -> ARM64.B18
    | "b19" -> ARM64.B19
    | "b20" -> ARM64.B20
    | "b21" -> ARM64.B21
    | "b22" -> ARM64.B22
    | "b23" -> ARM64.B23
    | "b24" -> ARM64.B24
    | "b25" -> ARM64.B25
    | "b26" -> ARM64.B26
    | "b27" -> ARM64.B27
    | "b28" -> ARM64.B28
    | "b29" -> ARM64.B29
    | "b30" -> ARM64.B30
    | "b31" -> ARM64.B31
    | "h0" -> ARM64.H0
    | "h1" -> ARM64.H1
    | "h2" -> ARM64.H2
    | "h3" -> ARM64.H3
    | "h4" -> ARM64.H4
    | "h5" -> ARM64.H5
    | "h6" -> ARM64.H6
    | "h7" -> ARM64.H7
    | "h8" -> ARM64.H8
    | "h9" -> ARM64.H9
    | "h10" -> ARM64.H10
    | "h11" -> ARM64.H11
    | "h12" -> ARM64.H12
    | "h13" -> ARM64.H13
    | "h14" -> ARM64.H14
    | "h15" -> ARM64.H15
    | "h16" -> ARM64.H16
    | "h17" -> ARM64.H17
    | "h18" -> ARM64.H18
    | "h19" -> ARM64.H19
    | "h20" -> ARM64.H20
    | "h21" -> ARM64.H21
    | "h22" -> ARM64.H22
    | "h23" -> ARM64.H23
    | "h24" -> ARM64.H24
    | "h25" -> ARM64.H25
    | "h26" -> ARM64.H26
    | "h27" -> ARM64.H27
    | "h28" -> ARM64.H28
    | "h29" -> ARM64.H29
    | "h30" -> ARM64.H30
    | "h31" -> ARM64.H31
    | "s0" -> ARM64.S0
    | "s1" -> ARM64.S1
    | "s2" -> ARM64.S2
    | "s3" -> ARM64.S3
    | "s4" -> ARM64.S4
    | "s5" -> ARM64.S5
    | "s6" -> ARM64.S6
    | "s7" -> ARM64.S7
    | "s8" -> ARM64.S8
    | "s9" -> ARM64.S9
    | "s10" -> ARM64.S10
    | "s11" -> ARM64.S11
    | "s12" -> ARM64.S12
    | "s13" -> ARM64.S13
    | "s14" -> ARM64.S14
    | "s15" -> ARM64.S15
    | "s16" -> ARM64.S16
    | "s17" -> ARM64.S17
    | "s18" -> ARM64.S18
    | "s19" -> ARM64.S19
    | "s20" -> ARM64.S20
    | "s21" -> ARM64.S21
    | "s22" -> ARM64.S22
    | "s23" -> ARM64.S23
    | "s24" -> ARM64.S24
    | "s25" -> ARM64.S25
    | "s26" -> ARM64.S26
    | "s27" -> ARM64.S27
    | "s28" -> ARM64.S28
    | "s29" -> ARM64.S29
    | "s30" -> ARM64.S30
    | "s31" -> ARM64.S31
    | "d0" -> ARM64.D0
    | "d1" -> ARM64.D1
    | "d2" -> ARM64.D2
    | "d3" -> ARM64.D3
    | "d4" -> ARM64.D4
    | "d5" -> ARM64.D5
    | "d6" -> ARM64.D6
    | "d7" -> ARM64.D7
    | "d8" -> ARM64.D8
    | "d9" -> ARM64.D9
    | "d10" -> ARM64.D10
    | "d11" -> ARM64.D11
    | "d12" -> ARM64.D12
    | "d13" -> ARM64.D13
    | "d14" -> ARM64.D14
    | "d15" -> ARM64.D15
    | "d16" -> ARM64.D16
    | "d17" -> ARM64.D17
    | "d18" -> ARM64.D18
    | "d19" -> ARM64.D19
    | "d20" -> ARM64.D20
    | "d21" -> ARM64.D21
    | "d22" -> ARM64.D22
    | "d23" -> ARM64.D23
    | "d24" -> ARM64.D24
    | "d25" -> ARM64.D25
    | "d26" -> ARM64.D26
    | "d27" -> ARM64.D27
    | "d28" -> ARM64.D28
    | "d29" -> ARM64.D29
    | "d30" -> ARM64.D30
    | "d31" -> ARM64.D31
    | "q0" -> ARM64.Q0
    | "q1" -> ARM64.Q1
    | "q2" -> ARM64.Q2
    | "q3" -> ARM64.Q3
    | "q4" -> ARM64.Q4
    | "q5" -> ARM64.Q5
    | "q6" -> ARM64.Q6
    | "q7" -> ARM64.Q7
    | "q8" -> ARM64.Q8
    | "q9" -> ARM64.Q9
    | "q10" -> ARM64.Q10
    | "q11" -> ARM64.Q11
    | "q12" -> ARM64.Q12
    | "q13" -> ARM64.Q13
    | "q14" -> ARM64.Q14
    | "q15" -> ARM64.Q15
    | "q16" -> ARM64.Q16
    | "q17" -> ARM64.Q17
    | "q18" -> ARM64.Q18
    | "q19" -> ARM64.Q19
    | "q20" -> ARM64.Q20
    | "q21" -> ARM64.Q21
    | "q22" -> ARM64.Q22
    | "q23" -> ARM64.Q23
    | "q24" -> ARM64.Q24
    | "q25" -> ARM64.Q25
    | "q26" -> ARM64.Q26
    | "q27" -> ARM64.Q27
    | "q28" -> ARM64.Q28
    | "q29" -> ARM64.Q29
    | "q30" -> ARM64.Q30
    | "q31" -> ARM64.Q31
    | "v0a" -> ARM64.V0A
    | "v0b" -> ARM64.V0B
    | "v1a" -> ARM64.V1A
    | "v1b" -> ARM64.V1B
    | "v2a" -> ARM64.V2A
    | "v2b" -> ARM64.V2B
    | "v3a" -> ARM64.V3A
    | "v3b" -> ARM64.V3B
    | "v4a" -> ARM64.V4A
    | "v4b" -> ARM64.V4B
    | "v5a" -> ARM64.V5A
    | "v5b" -> ARM64.V5B
    | "v6a" -> ARM64.V6A
    | "v6b" -> ARM64.V6B
    | "v7a" -> ARM64.V7A
    | "v7b" -> ARM64.V7B
    | "v8a" -> ARM64.V8A
    | "v8b" -> ARM64.V8B
    | "v9a" -> ARM64.V9A
    | "v9b" -> ARM64.V9B
    | "v10a" -> ARM64.V10A
    | "v10b" -> ARM64.V10B
    | "v11a" -> ARM64.V11A
    | "v11b" -> ARM64.V11B
    | "v12a" -> ARM64.V12A
    | "v12b" -> ARM64.V12B
    | "v13a" -> ARM64.V13A
    | "v13b" -> ARM64.V13B
    | "v14a" -> ARM64.V14A
    | "v14b" -> ARM64.V14B
    | "v15a" -> ARM64.V15A
    | "v15b" -> ARM64.V15B
    | "v16a" -> ARM64.V16A
    | "v16b" -> ARM64.V16B
    | "v17a" -> ARM64.V17A
    | "v17b" -> ARM64.V17B
    | "v18a" -> ARM64.V18A
    | "v18b" -> ARM64.V18B
    | "v19a" -> ARM64.V19A
    | "v19b" -> ARM64.V19B
    | "v20a" -> ARM64.V20A
    | "v20b" -> ARM64.V20B
    | "v21a" -> ARM64.V21A
    | "v21b" -> ARM64.V21B
    | "v22a" -> ARM64.V22A
    | "v22b" -> ARM64.V22B
    | "v23a" -> ARM64.V23A
    | "v23b" -> ARM64.V23B
    | "v24a" -> ARM64.V24A
    | "v24b" -> ARM64.V24B
    | "v25a" -> ARM64.V25A
    | "v25b" -> ARM64.V25B
    | "v26a" -> ARM64.V26A
    | "v26b" -> ARM64.V26B
    | "v27a" -> ARM64.V27A
    | "v27b" -> ARM64.V27B
    | "v28a" -> ARM64.V28A
    | "v28b" -> ARM64.V28B
    | "v29a" -> ARM64.V29A
    | "v29b" -> ARM64.V29B
    | "v30a" -> ARM64.V30A
    | "v30b" -> ARM64.V30B
    | "v31a" -> ARM64.V31A
    | "v31b" -> ARM64.V31B
    | "c0" -> ARM64.C0
    | "c1" -> ARM64.C1
    | "c2" -> ARM64.C2
    | "c3" -> ARM64.C3
    | "c4" -> ARM64.C4
    | "c5" -> ARM64.C5
    | "c6" -> ARM64.C6
    | "c7" -> ARM64.C7
    | "c8" -> ARM64.C8
    | "c9" -> ARM64.C9
    | "c10" -> ARM64.C10
    | "c11" -> ARM64.C11
    | "c12" -> ARM64.C12
    | "c13" -> ARM64.C13
    | "c14" -> ARM64.C14
    | "c15" -> ARM64.C15
    | "n" -> ARM64.N
    | "z" -> ARM64.Z
    | "c" -> ARM64.C
    | "v" -> ARM64.V
    | "actlrel1" -> ARM64.ACTLREL1
    | "actlrel2" -> ARM64.ACTLREL2
    | "actlrel3" -> ARM64.ACTLREL3
    | "afsr0el1" -> ARM64.AFSR0EL1
    | "afsr0el2" -> ARM64.AFSR0EL2
    | "afsr0el3" -> ARM64.AFSR0EL3
    | "afsr1el1" -> ARM64.AFSR1EL1
    | "afsr1el2" -> ARM64.AFSR1EL2
    | "afsr1el3" -> ARM64.AFSR1EL3
    | "aidrel1" -> ARM64.AIDREL1
    | "amairel1" -> ARM64.AMAIREL1
    | "amairel2" -> ARM64.AMAIREL2
    | "amairel3" -> ARM64.AMAIREL3
    | "ccsidrel1" -> ARM64.CCSIDREL1
    | "clidrel1" -> ARM64.CLIDREL1
    | "contextidrel1" -> ARM64.CONTEXTIDREL1
    | "cpacrel1" -> ARM64.CPACREL1
    | "cptrel2" -> ARM64.CPTREL2
    | "cptrel3" -> ARM64.CPTREL3
    | "csselrel1" -> ARM64.CSSELREL1
    | "ctrel0" -> ARM64.CTREL0
    | "dacr32el2" -> ARM64.DACR32EL2
    | "dczidel0" -> ARM64.DCZIDEL0
    | "esrel1" -> ARM64.ESREL1
    | "esrel2" -> ARM64.ESREL2
    | "esrel3" -> ARM64.ESREL3
    | "hpfarel2" -> ARM64.HPFAREL2
    | "tpidrel0" -> ARM64.TPIDREL0
    | "midrel1" -> ARM64.MIDREL1
    | "fpcr" -> ARM64.FPCR
    | "fpsr" -> ARM64.FPSR
    | "eret" -> ARM64.ERET
    | "nzcv" -> ARM64.NZCV
    | "s3_5_c3_c2_0" -> ARM64.S3_5_C3_C2_0
    | "s3_7_c2_c2_7" -> ARM64.S3_7_C2_C2_7
    | "s0_0_c2_c9_3" -> ARM64.S0_0_C2_C9_3
    | "s2_7_c12_c7_6" -> ARM64.S2_7_C12_C7_6
    | _ -> Utils.impossible ()

  /// Get the register ID of an ARM64 register.
  static member inline ID (reg: ARM64) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of an ARM64 register.
  static member String (reg: ARM64) =
    match reg with
    | ARM64.X0 -> "x0"
    | ARM64.X1 -> "x1"
    | ARM64.X2 -> "x2"
    | ARM64.X3 -> "x3"
    | ARM64.X4 -> "x4"
    | ARM64.X5 -> "x5"
    | ARM64.X6 -> "x6"
    | ARM64.X7 -> "x7"
    | ARM64.X8 -> "x8"
    | ARM64.X9 -> "x9"
    | ARM64.X10 -> "x10"
    | ARM64.X11 -> "x11"
    | ARM64.X12 -> "x12"
    | ARM64.X13 -> "x13"
    | ARM64.X14 -> "x14"
    | ARM64.X15 -> "x15"
    | ARM64.X16 -> "x16"
    | ARM64.X17 -> "x17"
    | ARM64.X18 -> "x18"
    | ARM64.X19 -> "x19"
    | ARM64.X20 -> "x20"
    | ARM64.X21 -> "x21"
    | ARM64.X22 -> "x22"
    | ARM64.X23 -> "x23"
    | ARM64.X24 -> "x24"
    | ARM64.X25 -> "x25"
    | ARM64.X26 -> "x26"
    | ARM64.X27 -> "x27"
    | ARM64.X28 -> "x28"
    | ARM64.X29 -> "x29"
    | ARM64.X30 -> "x30"
    | ARM64.XZR -> "xzr"
    | ARM64.W0 -> "w0"
    | ARM64.W1 -> "w1"
    | ARM64.W2 -> "w2"
    | ARM64.W3 -> "w3"
    | ARM64.W4 -> "w4"
    | ARM64.W5 -> "w5"
    | ARM64.W6 -> "w6"
    | ARM64.W7 -> "w7"
    | ARM64.W8 -> "w8"
    | ARM64.W9 -> "w9"
    | ARM64.W10 -> "w10"
    | ARM64.W11 -> "w11"
    | ARM64.W12 -> "w12"
    | ARM64.W13 -> "w13"
    | ARM64.W14 -> "w14"
    | ARM64.W15 -> "w15"
    | ARM64.W16 -> "w16"
    | ARM64.W17 -> "w17"
    | ARM64.W18 -> "w18"
    | ARM64.W19 -> "w19"
    | ARM64.W20 -> "w20"
    | ARM64.W21 -> "w21"
    | ARM64.W22 -> "w22"
    | ARM64.W23 -> "w23"
    | ARM64.W24 -> "w24"
    | ARM64.W25 -> "w25"
    | ARM64.W26 -> "w26"
    | ARM64.W27 -> "w27"
    | ARM64.W28 -> "w28"
    | ARM64.W29 -> "w29"
    | ARM64.W30 -> "w30"
    | ARM64.WZR -> "wzr"
    | ARM64.SP -> "sp"
    | ARM64.WSP -> "wsp"
    | ARM64.PC -> "pc"
    | ARM64.V0 -> "v0"
    | ARM64.V1 -> "v1"
    | ARM64.V2 -> "v2"
    | ARM64.V3 -> "v3"
    | ARM64.V4 -> "v4"
    | ARM64.V5 -> "v5"
    | ARM64.V6 -> "v6"
    | ARM64.V7 -> "v7"
    | ARM64.V8 -> "v8"
    | ARM64.V9 -> "v9"
    | ARM64.V10 -> "v10"
    | ARM64.V11 -> "v11"
    | ARM64.V12 -> "v12"
    | ARM64.V13 -> "v13"
    | ARM64.V14 -> "v14"
    | ARM64.V15 -> "v15"
    | ARM64.V16 -> "v16"
    | ARM64.V17 -> "v17"
    | ARM64.V18 -> "v18"
    | ARM64.V19 -> "v19"
    | ARM64.V20 -> "v20"
    | ARM64.V21 -> "v21"
    | ARM64.V22 -> "v22"
    | ARM64.V23 -> "v23"
    | ARM64.V24 -> "v24"
    | ARM64.V25 -> "v25"
    | ARM64.V26 -> "v26"
    | ARM64.V27 -> "v27"
    | ARM64.V28 -> "v28"
    | ARM64.V29 -> "v29"
    | ARM64.V30 -> "v30"
    | ARM64.V31 -> "v31"
    | ARM64.B0 -> "b0"
    | ARM64.B1 -> "b1"
    | ARM64.B2 -> "b2"
    | ARM64.B3 -> "b3"
    | ARM64.B4 -> "b4"
    | ARM64.B5 -> "b5"
    | ARM64.B6 -> "b6"
    | ARM64.B7 -> "b7"
    | ARM64.B8 -> "b8"
    | ARM64.B9 -> "b9"
    | ARM64.B10 -> "b10"
    | ARM64.B11 -> "b11"
    | ARM64.B12 -> "b12"
    | ARM64.B13 -> "b13"
    | ARM64.B14 -> "b14"
    | ARM64.B15 -> "b15"
    | ARM64.B16 -> "b16"
    | ARM64.B17 -> "b17"
    | ARM64.B18 -> "b18"
    | ARM64.B19 -> "b19"
    | ARM64.B20 -> "b20"
    | ARM64.B21 -> "b21"
    | ARM64.B22 -> "b22"
    | ARM64.B23 -> "b23"
    | ARM64.B24 -> "b24"
    | ARM64.B25 -> "b25"
    | ARM64.B26 -> "b26"
    | ARM64.B27 -> "b27"
    | ARM64.B28 -> "b28"
    | ARM64.B29 -> "b29"
    | ARM64.B30 -> "b30"
    | ARM64.B31 -> "b31"
    | ARM64.H0 -> "h0"
    | ARM64.H1 -> "h1"
    | ARM64.H2 -> "h2"
    | ARM64.H3 -> "h3"
    | ARM64.H4 -> "h4"
    | ARM64.H5 -> "h5"
    | ARM64.H6 -> "h6"
    | ARM64.H7 -> "h7"
    | ARM64.H8 -> "h8"
    | ARM64.H9 -> "h9"
    | ARM64.H10 -> "h10"
    | ARM64.H11 -> "h11"
    | ARM64.H12 -> "h12"
    | ARM64.H13 -> "h13"
    | ARM64.H14 -> "h14"
    | ARM64.H15 -> "h15"
    | ARM64.H16 -> "h16"
    | ARM64.H17 -> "h17"
    | ARM64.H18 -> "h18"
    | ARM64.H19 -> "h19"
    | ARM64.H20 -> "h20"
    | ARM64.H21 -> "h21"
    | ARM64.H22 -> "h22"
    | ARM64.H23 -> "h23"
    | ARM64.H24 -> "h24"
    | ARM64.H25 -> "h25"
    | ARM64.H26 -> "h26"
    | ARM64.H27 -> "h27"
    | ARM64.H28 -> "h28"
    | ARM64.H29 -> "h29"
    | ARM64.H30 -> "h30"
    | ARM64.H31 -> "h31"
    | ARM64.S0 -> "s0"
    | ARM64.S1 -> "s1"
    | ARM64.S2 -> "s2"
    | ARM64.S3 -> "s3"
    | ARM64.S4 -> "s4"
    | ARM64.S5 -> "s5"
    | ARM64.S6 -> "s6"
    | ARM64.S7 -> "s7"
    | ARM64.S8 -> "s8"
    | ARM64.S9 -> "s9"
    | ARM64.S10 -> "s10"
    | ARM64.S11 -> "s11"
    | ARM64.S12 -> "s12"
    | ARM64.S13 -> "s13"
    | ARM64.S14 -> "s14"
    | ARM64.S15 -> "s15"
    | ARM64.S16 -> "s16"
    | ARM64.S17 -> "s17"
    | ARM64.S18 -> "s18"
    | ARM64.S19 -> "s19"
    | ARM64.S20 -> "s20"
    | ARM64.S21 -> "s21"
    | ARM64.S22 -> "s22"
    | ARM64.S23 -> "s23"
    | ARM64.S24 -> "s24"
    | ARM64.S25 -> "s25"
    | ARM64.S26 -> "s26"
    | ARM64.S27 -> "s27"
    | ARM64.S28 -> "s28"
    | ARM64.S29 -> "s29"
    | ARM64.S30 -> "s30"
    | ARM64.S31 -> "s31"
    | ARM64.D0 -> "d0"
    | ARM64.D1 -> "d1"
    | ARM64.D2 -> "d2"
    | ARM64.D3 -> "d3"
    | ARM64.D4 -> "d4"
    | ARM64.D5 -> "d5"
    | ARM64.D6 -> "d6"
    | ARM64.D7 -> "d7"
    | ARM64.D8 -> "d8"
    | ARM64.D9 -> "d9"
    | ARM64.D10 -> "d10"
    | ARM64.D11 -> "d11"
    | ARM64.D12 -> "d12"
    | ARM64.D13 -> "d13"
    | ARM64.D14 -> "d14"
    | ARM64.D15 -> "d15"
    | ARM64.D16 -> "d16"
    | ARM64.D17 -> "d17"
    | ARM64.D18 -> "d18"
    | ARM64.D19 -> "d19"
    | ARM64.D20 -> "d20"
    | ARM64.D21 -> "d21"
    | ARM64.D22 -> "d22"
    | ARM64.D23 -> "d23"
    | ARM64.D24 -> "d24"
    | ARM64.D25 -> "d25"
    | ARM64.D26 -> "d26"
    | ARM64.D27 -> "d27"
    | ARM64.D28 -> "d28"
    | ARM64.D29 -> "d29"
    | ARM64.D30 -> "d30"
    | ARM64.D31 -> "d31"
    | ARM64.Q0 -> "q0"
    | ARM64.Q1 -> "q1"
    | ARM64.Q2 -> "q2"
    | ARM64.Q3 -> "q3"
    | ARM64.Q4 -> "q4"
    | ARM64.Q5 -> "q5"
    | ARM64.Q6 -> "q6"
    | ARM64.Q7 -> "q7"
    | ARM64.Q8 -> "q8"
    | ARM64.Q9 -> "q9"
    | ARM64.Q10 -> "q10"
    | ARM64.Q11 -> "q11"
    | ARM64.Q12 -> "q12"
    | ARM64.Q13 -> "q13"
    | ARM64.Q14 -> "q14"
    | ARM64.Q15 -> "q15"
    | ARM64.Q16 -> "q16"
    | ARM64.Q17 -> "q17"
    | ARM64.Q18 -> "q18"
    | ARM64.Q19 -> "q19"
    | ARM64.Q20 -> "q20"
    | ARM64.Q21 -> "q21"
    | ARM64.Q22 -> "q22"
    | ARM64.Q23 -> "q23"
    | ARM64.Q24 -> "q24"
    | ARM64.Q25 -> "q25"
    | ARM64.Q26 -> "q26"
    | ARM64.Q27 -> "q27"
    | ARM64.Q28 -> "q28"
    | ARM64.Q29 -> "q29"
    | ARM64.Q30 -> "q30"
    | ARM64.Q31 -> "q31"
    | ARM64.V0A -> "v0a"
    | ARM64.V0B -> "v0b"
    | ARM64.V1A -> "v1a"
    | ARM64.V1B -> "v1b"
    | ARM64.V2A -> "v2a"
    | ARM64.V2B -> "v2b"
    | ARM64.V3A -> "v3a"
    | ARM64.V3B -> "v3b"
    | ARM64.V4A -> "v4a"
    | ARM64.V4B -> "v4b"
    | ARM64.V5A -> "v5a"
    | ARM64.V5B -> "v5b"
    | ARM64.V6A -> "v6a"
    | ARM64.V6B -> "v6b"
    | ARM64.V7A -> "v7a"
    | ARM64.V7B -> "v7b"
    | ARM64.V8A -> "v8a"
    | ARM64.V8B -> "v8b"
    | ARM64.V9A -> "v9a"
    | ARM64.V9B -> "v9b"
    | ARM64.V10A -> "v10a"
    | ARM64.V10B -> "v10b"
    | ARM64.V11A -> "v11a"
    | ARM64.V11B -> "v11b"
    | ARM64.V12A -> "v12a"
    | ARM64.V12B -> "v12b"
    | ARM64.V13A -> "v13a"
    | ARM64.V13B -> "v13b"
    | ARM64.V14A -> "v14a"
    | ARM64.V14B -> "v14b"
    | ARM64.V15A -> "v15a"
    | ARM64.V15B -> "v15b"
    | ARM64.V16A -> "v16a"
    | ARM64.V16B -> "v16b"
    | ARM64.V17A -> "v17a"
    | ARM64.V17B -> "v17b"
    | ARM64.V18A -> "v18a"
    | ARM64.V18B -> "v18b"
    | ARM64.V19A -> "v19a"
    | ARM64.V19B -> "v19b"
    | ARM64.V20A -> "v20a"
    | ARM64.V20B -> "v20b"
    | ARM64.V21A -> "v21a"
    | ARM64.V21B -> "v21b"
    | ARM64.V22A -> "v22a"
    | ARM64.V22B -> "v22b"
    | ARM64.V23A -> "v23a"
    | ARM64.V23B -> "v23b"
    | ARM64.V24A -> "v24a"
    | ARM64.V24B -> "v24b"
    | ARM64.V25A -> "v25a"
    | ARM64.V25B -> "v25b"
    | ARM64.V26A -> "v26a"
    | ARM64.V26B -> "v26b"
    | ARM64.V27A -> "v27a"
    | ARM64.V27B -> "v27b"
    | ARM64.V28A -> "v28a"
    | ARM64.V28B -> "v28b"
    | ARM64.V29A -> "v29a"
    | ARM64.V29B -> "v29b"
    | ARM64.V30A -> "v30a"
    | ARM64.V30B -> "v30b"
    | ARM64.V31A -> "v31a"
    | ARM64.V31B -> "v31b"
    | ARM64.C0 -> "c0"
    | ARM64.C1 -> "c1"
    | ARM64.C2 -> "c2"
    | ARM64.C3 -> "c3"
    | ARM64.C4 -> "c4"
    | ARM64.C5 -> "c5"
    | ARM64.C6 -> "c6"
    | ARM64.C7 -> "c7"
    | ARM64.C8 -> "c8"
    | ARM64.C9 -> "c9"
    | ARM64.C10 -> "c10"
    | ARM64.C11 -> "c11"
    | ARM64.C12 -> "c12"
    | ARM64.C13 -> "c13"
    | ARM64.C14 -> "c14"
    | ARM64.C15 -> "c15"
    | ARM64.N -> "n"
    | ARM64.Z -> "z"
    | ARM64.C -> "c"
    | ARM64.V -> "v"
    | ARM64.ACTLREL1 -> "actlr_el1"
    | ARM64.ACTLREL2 -> "actlr_el2"
    | ARM64.ACTLREL3 -> "actlr_el3"
    | ARM64.AFSR0EL1 -> "afsr0_el1"
    | ARM64.AFSR0EL2 -> "afsr0_el2"
    | ARM64.AFSR0EL3 -> "afsr0_el3"
    | ARM64.AFSR1EL1 -> "afsr1_el1"
    | ARM64.AFSR1EL2 -> "afsr1_el2"
    | ARM64.AFSR1EL3 -> "afsr1_el3"
    | ARM64.AIDREL1 -> "aidr_el1"
    | ARM64.AMAIREL1 -> "amair_el1"
    | ARM64.AMAIREL2 -> "amair_el2"
    | ARM64.AMAIREL3 -> "amair_el3"
    | ARM64.CCSIDREL1 -> "ccsidr_el1"
    | ARM64.CLIDREL1 -> "clidr_el1"
    | ARM64.CONTEXTIDREL1 -> "contextidr_el1"
    | ARM64.CPACREL1 -> "cpacr_el1"
    | ARM64.CPTREL2 -> "cptr_el2"
    | ARM64.CPTREL3 -> "cptr_el3"
    | ARM64.CSSELREL1 -> "csselr_el1"
    | ARM64.CTREL0 -> "ctr_el0"
    | ARM64.DACR32EL2 -> "dacr32_el2"
    | ARM64.DCZIDEL0 -> "dczid_el0"
    | ARM64.ESREL1 -> "esr_el1"
    | ARM64.ESREL2 -> "esr_el2"
    | ARM64.ESREL3 -> "esr_el3"
    | ARM64.HPFAREL2 -> "hpfar_el2"
    | ARM64.TPIDREL0 -> "tpidr_el0"
    | ARM64.MIDREL1 -> "midr_el1"
    | ARM64.FPCR -> "fpcr"
    | ARM64.FPSR -> "fpsr"
    | ARM64.ERET -> "eret"
    | ARM64.NZCV -> "nzcv"
    | ARM64.S3_5_C3_C2_0 -> "s3_5_c3_c2_0"
    | ARM64.S3_7_C2_C2_7 -> "s3_7_c2_c2_7"
    | ARM64.S0_0_C2_C9_3 -> "s0_0_c2_c9_3"
    | ARM64.S2_7_C12_C7_6 -> "s2_7_c12_c7_6"
    | _ -> Utils.impossible ()

/// <summary>
/// Registers for AVR.<para/>
/// </summary>
type AVR =
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
  | R16 = 0x10
  | R17 = 0x11
  | R18 = 0x12
  | R19 = 0x13
  | R20 = 0x14
  | R21 = 0x15
  | R22 = 0x16
  | R23 = 0x17
  | R24 = 0x18
  | R25 = 0x19
  | R26 = 0x1A
  | R27 = 0x1B
  | R28 = 0x1C
  | R29 = 0x1D
  | R30 = 0x1E
  | R31 = 0x1F
  | X = 0x20
  | Y = 0x21
  | Z = 0x22
  | IF = 0x23
  | TF = 0x24
  | HF = 0x25
  | SF = 0x26
  | VF = 0x27
  | NF = 0x28
  | ZF = 0x29
  | CF = 0x2A
  | PC = 0x2B
  | SP = 0x2C

/// Helper module for AVR registers.
type AVRRegister =
  /// Get the AVR register from a register ID.
  static member inline Get (rid: RegisterID): AVR =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the AVR register from a string representation.
  static member Get (str: string): AVR =
    match str.ToLowerInvariant () with
    | "r1" -> AVR.R0
    | "r2" -> AVR.R1
    | "r3" -> AVR.R2
    | "r4" -> AVR.R3
    | "r5" -> AVR.R4
    | "r6" -> AVR.R5
    | "r7" -> AVR.R6
    | "r8" -> AVR.R7
    | "r9" -> AVR.R8
    | "r10" -> AVR.R9
    | "r11" -> AVR.R10
    | "r12" -> AVR.R11
    | "r13" -> AVR.R12
    | "r14" -> AVR.R13
    | "r15" -> AVR.R14
    | "r16" -> AVR.R15
    | "r17" -> AVR.R16
    | "r18" -> AVR.R17
    | "r19" -> AVR.R18
    | "r20" -> AVR.R19
    | "r21" -> AVR.R20
    | "r22" -> AVR.R21
    | "r23" -> AVR.R22
    | "r24" -> AVR.R23
    | "r25" -> AVR.R24
    | "r26" -> AVR.R25
    | "r27" -> AVR.R26
    | "r28" -> AVR.R27
    | "r29" -> AVR.R28
    | "r30" -> AVR.R29
    | "r31" -> AVR.R30
    | "r32" -> AVR.R31
    | "IF" -> AVR.IF
    | "TF" -> AVR.TF
    | "HF" -> AVR.HF
    | "SF" -> AVR.SF
    | "VF" -> AVR.VF
    | "NF" -> AVR.NF
    | "ZF" -> AVR.ZF
    | "CF" -> AVR.CF
    | "PC" -> AVR.PC
    | "SP" -> AVR.SP
    | _ -> Utils.impossible ()

  /// Get the register ID of an AVR register.
  static member inline ID (reg: AVR) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of an AVR register.
  static member String (reg: AVR) =
    match reg with
    | AVR.R0 -> "r0"
    | AVR.R1 -> "r1"
    | AVR.R2 -> "r2"
    | AVR.R3 -> "r3"
    | AVR.R4 -> "r4"
    | AVR.R5  -> "r5"
    | AVR.R6 -> "r6"
    | AVR.R7 -> "r7"
    | AVR.R8 -> "r8"
    | AVR.R9 -> "r9"
    | AVR.R10 -> "r10"
    | AVR.R11 -> "r11"
    | AVR.R12  -> "r12"
    | AVR.R13 -> "r13"
    | AVR.R14 -> "r14"
    | AVR.R15 -> "r15"
    | AVR.R16  -> "r16"
    | AVR.R17 -> "r17"
    | AVR.R18 -> "r18"
    | AVR.R19 -> "r19"
    | AVR.R20  -> "r20"
    | AVR.R21 -> "r21"
    | AVR.R22 -> "r22"
    | AVR.R23 -> "r23"
    | AVR.R24 -> "r24"
    | AVR.R25  -> "r25"
    | AVR.R26 -> "r26"
    | AVR.R27 -> "r27"
    | AVR.R28 -> "r28"
    | AVR.R29  -> "r29"
    | AVR.R30 -> "r30"
    | AVR.R31 -> "r31"
    | AVR.X -> "X"
    | AVR.Y -> "Y"
    | AVR.Z -> "Z"
    | AVR.PC -> "pc"
    | AVR.SP -> "sp"
    | _ -> Utils.impossible ()

/// <summary>
/// Registers for Intel x86 and x86-64.<para/>
/// </summary>
type Intel =
  /// Accumulator for operands and results data (64bit).
  | RAX = 0x0
  /// TCounter for string and loop operations (64bit).
  | RCX = 0x1
  /// I/O pointer (64bit).
  | RDX = 0x2
  /// Pointer to data in the DS segment (64bit).
  | RBX = 0x3
  /// Stack pointer (in the SS segment) (64bit).
  | RSP = 0x4
  /// Pointer to data on the stack (in the SS segment) (64bit).
  | RBP = 0x5
  /// Pointer to data in the segment pointed to by the DS register (64bit).
  | RSI = 0x6
  /// Pointer to data in the segment pointed to by the ES register (64bit).
  | RDI = 0x7
  /// General-Purpose Registers for 64bit Mode.
  | R8 = 0x8
  /// General-Purpose Registers for 64bit Mode.
  | R9 = 0x9
  /// General-Purpose Registers for 64bit Mode.
  | R10 = 0xA
  /// General-Purpose Registers for 64bit Mode.
  | R11 = 0xB
  /// General-Purpose Registers for 64bit Mode.
  | R12 = 0xC
  /// General-Purpose Registers for 64bit Mode.
  | R13 = 0xD
  /// General-Purpose Registers for 64bit Mode.
  | R14 = 0xE
  /// General-Purpose Registers for 64bit Mode.
  | R15 = 0xF
  /// Accumulator for operands and results data (32bit).
  | EAX = 0x10
  /// TCounter for string and loop operations (32bit).
  | ECX = 0x11
  /// I/O pointer (32bit).
  | EDX = 0x12
  /// Pointer to data in the DS segment (32bit).
  | EBX = 0x13
  /// Stack pointer (in the SS segment) (32bit).
  | ESP = 0x14
  /// Pointer to data on the stack (in the SS segment) (32bit).
  | EBP = 0x15
  /// Pointer to data in the segment pointed to by the DS register (32bit).
  | ESI = 0x16
  /// Pointer to data in the segment pointed to by the ES register (32bit).
  | EDI = 0x17
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R8D = 0x18
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R9D = 0x19
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R10D = 0x1A
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R11D = 0x1B
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R12D = 0x1C
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R13D = 0x1D
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R14D = 0x1E
  /// General-Purpose Registers for 64bit Mode (Doubleword Register).
  | R15D = 0x1F
  /// General-Purpose Registers (lower 16bits EAX).
  | AX = 0x20
  /// General-Purpose Registers (lower 16bits ECX).
  | CX = 0x21
  /// General-Purpose Registers (lower 16bits EDX).
  | DX = 0x22
  /// General-Purpose Registers (lower 16bits EBX).
  | BX = 0x23
  /// General-Purpose Registers (lower 16bits ESP).
  | SP = 0x24
  /// General-Purpose Registers (lower 16bits EBP).
  | BP = 0x25
  /// General-Purpose Registers (lower 16bits ESI).
  | SI = 0x26
  /// General-Purpose Registers (lower 16bits EDI).
  | DI = 0x27
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R8W = 0x28
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R9W = 0x29
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R10W = 0x2A
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R11W = 0x2B
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R12W = 0x2C
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R13W = 0x2D
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R14W = 0x2E
  /// General-Purpose Registers for 64bit Mode (Word Register).
  | R15W = 0x2F
  /// General-Purpose Registers (lower 8bits AX).
  | AL = 0x30
  /// General-Purpose Registers (lower 8bits CX).
  | CL = 0x31
  /// General-Purpose Registers (lower 8bits DX).
  | DL = 0x32
  /// General-Purpose Registers (lower 8bits BX).
  | BL = 0x33
  /// General-Purpose Registers (Higher 8bits AX).
  | AH = 0x34
  /// General-Purpose Registers (Higher 8bits CX).
  | CH = 0x35
  /// General-Purpose Registers (Higher 8bits DX).
  | DH = 0x36
  /// General-Purpose Registers (Higher 8bits BX).
  | BH = 0x37
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R8B = 0x38
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R9B = 0x39
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R10B = 0x3A
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R11B = 0x3B
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R12B = 0x3C
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R13B = 0x3D
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R14B = 0x3E
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | R15B = 0x3F
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | SPL = 0x40
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | BPL = 0x41
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | SIL = 0x42
  /// General-Purpose Registers for 64bit Mode (Byte Register).
  | DIL = 0x43
  /// Instruction Pointer (32Bit).
  | EIP = 0x44
  /// Instruction Pointer (64Bit).
  | RIP = 0x45
  /// x87 FPU registers.
  | ST0 = 0x46
  /// x87 FPU registers.
  | ST1 = 0x47
  /// x87 FPU registers.
  | ST2 = 0x48
  /// x87 FPU registers.
  | ST3 = 0x49
  /// x87 FPU registers.
  | ST4 = 0x4A
  /// x87 FPU registers.
  | ST5 = 0x4B
  /// x87 FPU registers.
  | ST6 = 0x4C
  /// x87 FPU registers.
  | ST7 = 0x4D
  /// C87 FPU Control Word.
  | FCW = 0x4E
  /// x87 FPU Status Word.
  | FSW = 0x4F
  /// x87 FPU Tag Word.
  | FTW = 0x50
  /// x87 FPU Opcode.
  | FOP = 0x51
  /// x87 FPU Instruction Pointer Offset.
  | FIP = 0x52
  /// x87 FPU Instruction Pointer Selector.
  | FCS = 0x53
  /// x87 FPU Data Pointer Offset.
  | FDP = 0x54
  /// x87 FPU Data Pointer Selector.
  | FDS = 0x55
  /// x87 FPU Top indicator bits of Status Word.
  | FTOP = 0x56
  /// x87 FPU Tag word section.
  | FTW0 = 0x57
  /// x87 FPU Tag word section.
  | FTW1 = 0x58
  /// x87 FPU Tag word section.
  | FTW2 = 0x59
  /// x87 FPU Tag word section.
  | FTW3 = 0x5A
  /// x87 FPU Tag word section.
  | FTW4 = 0x5B
  /// x87 FPU Tag word section.
  | FTW5 = 0x5C
  /// x87 FPU Tag word section.
  | FTW6 = 0x5D
  /// x87 FPU Tag word section.
  | FTW7 = 0x5E
  /// x87 FPU Status Word C flag.
  | FSWC0 = 0x5F
  /// x87 FPU Status Word C flag.
  | FSWC1 = 0x60
  /// x87 FPU Status Word C flag.
  | FSWC2 = 0x61
  /// x87 FPU Status Word C flag.
  | FSWC3 = 0x62
  /// MXCSR Control and Status Register.
  | MXCSR = 0x63
  /// MXCSR_MASK.
  | MXCSRMASK = 0x64
  /// MMX registers.
  | MM0 = 0x65
  /// MMX registers.
  | MM1 = 0x66
  /// MMX registers.
  | MM2 = 0x67
  /// MMX registers.
  | MM3 = 0x68
  /// MMX registers.
  | MM4 = 0x69
  /// MMX registers.
  | MM5 = 0x6A
  /// MMX registers.
  | MM6 = 0x6B
  /// MMX registers.
  | MM7 = 0x6C
  /// XMM registers.
  | XMM0 = 0x6D
  /// XMM registers.
  | XMM1 = 0x6E
  /// XMM registers.
  | XMM2 = 0x6F
  /// XMM registers.
  | XMM3 = 0x70
  /// XMM registers.
  | XMM4 = 0x71
  /// XMM registers.
  | XMM5 = 0x72
  /// XMM registers.
  | XMM6 = 0x73
  /// XMM registers.
  | XMM7 = 0x74
  /// XMM registers.
  | XMM8 = 0x75
  /// XMM registers.
  | XMM9 = 0x76
  /// XMM registers.
  | XMM10 = 0x77
  /// XMM registers.
  | XMM11 = 0x78
  /// XMM registers.
  | XMM12 = 0x79
  /// XMM registers.
  | XMM13 = 0x7A
  /// XMM registers.
  | XMM14 = 0x7B
  /// XMM registers.
  | XMM15 = 0x7C
  /// 256-bit vector registers.
  | YMM0 = 0x7D
  /// 256-bit vector registers.
  | YMM1 = 0x7E
  /// 256-bit vector registers.
  | YMM2 = 0x7F
  /// 256-bit vector registers.
  | YMM3 = 0x80
  /// 256-bit vector registers.
  | YMM4 = 0x81
  /// 256-bit vector registers.
  | YMM5 = 0x82
  /// 256-bit vector registers.
  | YMM6 = 0x83
  /// 256-bit vector registers.
  | YMM7 = 0x84
  /// 256-bit vector registers.
  | YMM8 = 0x85
  /// 256-bit vector registers.
  | YMM9 = 0x86
  /// 256-bit vector registers.
  | YMM10 = 0x87
  /// 256-bit vector registers.
  | YMM11 = 0x88
  /// 256-bit vector registers.
  | YMM12 = 0x89
  /// 256-bit vector registers.
  | YMM13 = 0x8A
  /// 256-bit vector registers.
  | YMM14 = 0x8B
  /// 256-bit vector registers.
  | YMM15 = 0x8C
  /// 512-bit vector registers.
  | ZMM0 = 0x8D
  /// 512-bit vector registers.
  | ZMM1 = 0x8E
  /// 512-bit vector registers.
  | ZMM2 = 0x8F
  /// 512-bit vector registers.
  | ZMM3 = 0x90
  /// 512-bit vector registers.
  | ZMM4 = 0x91
  /// 512-bit vector registers.
  | ZMM5 = 0x92
  /// 512-bit vector registers.
  | ZMM6 = 0x93
  /// 512-bit vector registers.
  | ZMM7 = 0x94
  /// 512-bit vector registers.
  | ZMM8 = 0x95
  /// 512-bit vector registers.
  | ZMM9 = 0x96
  /// 512-bit vector registers.
  | ZMM10 = 0x97
  /// 512-bit vector registers.
  | ZMM11 = 0x98
  /// 512-bit vector registers.
  | ZMM12 = 0x99
  /// 512-bit vector registers.
  | ZMM13 = 0x9A
  /// 512-bit vector registers.
  | ZMM14 = 0x9B
  /// 512-bit vector registers.
  | ZMM15 = 0x9C
  /// Segment registers.
  | ES = 0x9D
  /// Segment registers.
  | CS = 0x9E
  /// Segment registers.
  | SS = 0x9F
  /// Segment registers.
  | DS = 0xA0
  /// Segment registers.
  | FS = 0xA1
  /// Segment registers.
  | GS = 0xA2
  /// ES.base.
  | ESBase = 0xA3
  /// CS.base.
  | CSBase = 0xA4
  /// SS.base.
  | SSBase = 0xA5
  /// DS.base.
  | DSBase = 0xA6
  /// FS.base.
  | FSBase = 0xA7
  /// GS.base.
  | GSBase = 0xA8
  /// Control registers.
  | CR0 = 0xA9
  /// Control registers.
  | CR2 = 0xAA
  /// Control registers.
  | CR3 = 0xAB
  /// Control registers.
  | CR4 = 0xAC
  /// Control registers.
  | CR8 = 0xAD
  /// Debug registers.
  | DR0 = 0xAE
  /// Debug registers.
  | DR1 = 0xAF
  /// Debug registers.
  | DR2 = 0xB0
  /// Debug registers.
  | DR3 = 0xB1
  /// Debug registers.
  | DR6 = 0xB2
  /// Debug registers.
  | DR7 = 0xB3
  /// BND registers.
  | BND0 = 0xB4
  /// BND registers.
  | BND1 = 0xB5
  /// BND registers.
  | BND2 = 0xB6
  /// BND registers.
  | BND3 = 0xB7
  /// Overflow Flag in EFLAGS Register
  | OF = 0xB8
  /// Direction Flag in EFLAGS Register
  | DF = 0xB9
  /// Interrupt Enable Flag in EFLAGS Register
  | IF = 0xBA
  /// Trap Flag in EFLAGS Register
  | TF = 0xBB
  /// Sign Flag in EFLAGS Register
  | SF = 0xBC
  /// Zero Flag in EFLAGS Register
  | ZF = 0xBD
  /// Auxiliary Carry Flag in EFLAGS Register
  | AF = 0xBE
  /// Parity Flag in EFLAGS Register
  | PF = 0xBF
  /// Carry Flag in EFLAGS Register
  | CF = 0xC0
  /// Protection-key features register.
  | PKRU = 0xC1
  /// BND Register (lower 64bits BND0).
  | BND0A = 0xC2
  /// BND Register (Higher 64bits BND0).
  | BND0B = 0xC3
  /// BND Register (lower 64bits BND1).
  | BND1A = 0xC4
  /// BND Register (Higher 64bits BND1).
  | BND1B = 0xC5
  /// BND Register (lower 64bits BND2).
  | BND2A = 0xC6
  /// BND Register (Higher 64bits BND2).
  | BND2B = 0xC7
  /// BND Register (lower 64bits BND3).
  | BND3A = 0xC8
  /// BND Register (Higher 64bits BND3).
  | BND3B = 0xC9
  /// ST Register (lower 64bits ST0).
  | ST0A = 0xCA
  /// ST Register (Higher 16bits ST0).
  | ST0B = 0xCB
  /// ST Register (lower 64bits ST1).
  | ST1A = 0xCC
  /// ST Register (Higher 16bits ST1).
  | ST1B = 0xCD
  /// ST Register (lower 64bits ST2).
  | ST2A = 0xCE
  /// ST Register (Higher 16bits ST2).
  | ST2B = 0xCF
  /// ST Register (lower 64bits ST3).
  | ST3A = 0xD0
  /// ST Register (Higher 16bits ST3).
  | ST3B = 0xD1
  /// ST Register (lower 64bits ST4).
  | ST4A = 0xD2
  /// ST Register (Higher 16bits ST4).
  | ST4B = 0xD3
  /// ST Register (lower 64bits ST5).
  | ST5A = 0xD4
  /// ST Register (Higher 16bits ST5).
  | ST5B = 0xD5
  /// ST Register (lower 64bits ST6).
  | ST6A = 0xD6
  /// ST Register (Higher 16bits ST6).
  | ST6B = 0xD7
  /// ST Register (lower 64bits ST7).
  | ST7A = 0xD8
  /// ST Register (Higher 16bits ST7).
  | ST7B = 0xD9
  /// ZMM0A is the 1st 64-bit chunk of ZMM0.
  | ZMM0A = 0xDA
  /// ZMM0B is the 2nd 64-bit chunk of ZMM0.
  | ZMM0B = 0xDB
  /// ZMM0C is the 3rd 64-bit chunk of ZMM0.
  | ZMM0C = 0xDC
  /// ZMM0D is the 4th 64-bit chunk of ZMM0.
  | ZMM0D = 0xDD
  /// ZMM0E is the 5th 64-bit chunk of ZMM0.
  | ZMM0E = 0xDE
  /// ZMM0F is the 6th 64-bit chunk of ZMM0.
  | ZMM0F = 0xDF
  /// ZMM0G is the 7th 64-bit chunk of ZMM0.
  | ZMM0G = 0xE0
  /// ZMM0H is the 8th 64-bit chunk of ZMM0.
  | ZMM0H = 0xE1
  /// ZMM1A is the 1st 64-bit chunk of ZMM1.
  | ZMM1A = 0xE2
  /// ZMM1B is the 2nd 64-bit chunk of ZMM1.
  | ZMM1B = 0xE3
  /// ZMM1C is the 3rd 64-bit chunk of ZMM1.
  | ZMM1C = 0xE4
  /// ZMM1D is the 4th 64-bit chunk of ZMM1.
  | ZMM1D = 0xE5
  /// ZMM1E is the 5th 64-bit chunk of ZMM1.
  | ZMM1E = 0xE6
  /// ZMM1F is the 6th 64-bit chunk of ZMM1.
  | ZMM1F = 0xE7
  /// ZMM1G is the 7th 64-bit chunk of ZMM1.
  | ZMM1G = 0xE8
  /// ZMM1H is the 8th 64-bit chunk of ZMM1.
  | ZMM1H = 0xE9
  /// ZMM2A is the 1st 64-bit chunk of ZMM2.
  | ZMM2A = 0xEA
  /// ZMM2B is the 2nd 64-bit chunk of ZMM2.
  | ZMM2B = 0xEB
  /// ZMM2C is the 3rd 64-bit chunk of ZMM2.
  | ZMM2C = 0xEC
  /// ZMM2D is the 4th 64-bit chunk of ZMM2.
  | ZMM2D = 0xED
  /// ZMM2E is the 5th 64-bit chunk of ZMM2.
  | ZMM2E = 0xEE
  /// ZMM2F is the 6th 64-bit chunk of ZMM2.
  | ZMM2F = 0xEF
  /// ZMM2G is the 7th 64-bit chunk of ZMM2.
  | ZMM2G = 0xF0
  /// ZMM2H is the 8th 64-bit chunk of ZMM2.
  | ZMM2H = 0xF1
  /// ZMM3A is the 1st 64-bit chunk of ZMM3.
  | ZMM3A = 0xF2
  /// ZMM3B is the 2nd 64-bit chunk of ZMM3.
  | ZMM3B = 0xF3
  /// ZMM3C is the 3rd 64-bit chunk of ZMM3.
  | ZMM3C = 0xF4
  /// ZMM3D is the 4th 64-bit chunk of ZMM3.
  | ZMM3D = 0xF5
  /// ZMM3E is the 5th 64-bit chunk of ZMM3.
  | ZMM3E = 0xF6
  /// ZMM3F is the 6th 64-bit chunk of ZMM3.
  | ZMM3F = 0xF7
  /// ZMM3G is the 7th 64-bit chunk of ZMM3.
  | ZMM3G = 0xF8
  /// ZMM3H is the 8th 64-bit chunk of ZMM3.
  | ZMM3H = 0xF9
  /// ZMM4A is the 1st 64-bit chunk of ZMM4.
  | ZMM4A = 0xFA
  /// ZMM4B is the 2nd 64-bit chunk of ZMM4.
  | ZMM4B = 0xFB
  /// ZMM4C is the 3rd 64-bit chunk of ZMM4.
  | ZMM4C = 0xFC
  /// ZMM4D is the 4th 64-bit chunk of ZMM4.
  | ZMM4D = 0xFD
  /// ZMM4E is the 5th 64-bit chunk of ZMM4.
  | ZMM4E = 0xFE
  /// ZMM4F is the 6th 64-bit chunk of ZMM4.
  | ZMM4F = 0xFF
  /// ZMM4G is the 7th 64-bit chunk of ZMM4.
  | ZMM4G = 0x100
  /// ZMM4H is the 8th 64-bit chunk of ZMM4.
  | ZMM4H = 0x101
  /// ZMM5A is the 1st 64-bit chunk of ZMM5.
  | ZMM5A = 0x102
  /// ZMM5B is the 2nd 64-bit chunk of ZMM5.
  | ZMM5B = 0x103
  /// ZMM5C is the 3rd 64-bit chunk of ZMM5.
  | ZMM5C = 0x104
  /// ZMM5D is the 4th 64-bit chunk of ZMM5.
  | ZMM5D = 0x105
  /// ZMM5E is the 5th 64-bit chunk of ZMM5.
  | ZMM5E = 0x106
  /// ZMM5F is the 6th 64-bit chunk of ZMM5.
  | ZMM5F = 0x107
  /// ZMM5G is the 7th 64-bit chunk of ZMM5.
  | ZMM5G = 0x108
  /// ZMM5H is the 8th 64-bit chunk of ZMM5.
  | ZMM5H = 0x109
  /// ZMM6A is the 1st 64-bit chunk of ZMM6.
  | ZMM6A = 0x10A
  /// ZMM6B is the 2nd 64-bit chunk of ZMM6.
  | ZMM6B = 0x10B
  /// ZMM6C is the 3rd 64-bit chunk of ZMM6.
  | ZMM6C = 0x10C
  /// ZMM6D is the 4th 64-bit chunk of ZMM6.
  | ZMM6D = 0x10D
  /// ZMM6E is the 5th 64-bit chunk of ZMM6.
  | ZMM6E = 0x10E
  /// ZMM6F is the 6th 64-bit chunk of ZMM6.
  | ZMM6F = 0x10F
  /// ZMM6G is the 7th 64-bit chunk of ZMM6.
  | ZMM6G = 0x110
  /// ZMM6H is the 8th 64-bit chunk of ZMM6.
  | ZMM6H = 0x111
  /// ZMM7A is the 1st 64-bit chunk of ZMM7.
  | ZMM7A = 0x112
  /// ZMM7B is the 2nd 64-bit chunk of ZMM7.
  | ZMM7B = 0x113
  /// ZMM7C is the 3rd 64-bit chunk of ZMM7.
  | ZMM7C = 0x114
  /// ZMM7D is the 4th 64-bit chunk of ZMM7.
  | ZMM7D = 0x115
  /// ZMM7E is the 5th 64-bit chunk of ZMM7.
  | ZMM7E = 0x116
  /// ZMM7F is the 6th 64-bit chunk of ZMM7.
  | ZMM7F = 0x117
  /// ZMM7G is the 7th 64-bit chunk of ZMM7.
  | ZMM7G = 0x118
  /// ZMM7H is the 8th 64-bit chunk of ZMM7.
  | ZMM7H = 0x119
  /// ZMM8A is the 1st 64-bit chunk of ZMM8.
  | ZMM8A = 0x11A
  /// ZMM8B is the 2nd 64-bit chunk of ZMM8.
  | ZMM8B = 0x11B
  /// ZMM8C is the 3rd 64-bit chunk of ZMM8.
  | ZMM8C = 0x11C
  /// ZMM8D is the 4th 64-bit chunk of ZMM8.
  | ZMM8D = 0x11D
  /// ZMM8E is the 5th 64-bit chunk of ZMM8.
  | ZMM8E = 0x11E
  /// ZMM8F is the 6th 64-bit chunk of ZMM8.
  | ZMM8F = 0x11F
  /// ZMM8G is the 7th 64-bit chunk of ZMM8.
  | ZMM8G = 0x120
  /// ZMM8H is the 8th 64-bit chunk of ZMM8.
  | ZMM8H = 0x121
  /// ZMM9A is the 1st 64-bit chunk of ZMM9.
  | ZMM9A = 0x122
  /// ZMM9B is the 2nd 64-bit chunk of ZMM9.
  | ZMM9B = 0x123
  /// ZMM9C is the 3rd 64-bit chunk of ZMM9.
  | ZMM9C = 0x124
  /// ZMM9D is the 4th 64-bit chunk of ZMM9.
  | ZMM9D = 0x125
  /// ZMM9E is the 5th 64-bit chunk of ZMM9.
  | ZMM9E = 0x126
  /// ZMM9F is the 6th 64-bit chunk of ZMM9.
  | ZMM9F = 0x127
  /// ZMM9G is the 7th 64-bit chunk of ZMM9.
  | ZMM9G = 0x128
  /// ZMM9H is the 8th 64-bit chunk of ZMM9.
  | ZMM9H = 0x129
  /// ZMM10A is the 1st 64-bit chunk of ZMM10.
  | ZMM10A = 0x12A
  /// ZMM10B is the 2nd 64-bit chunk of ZMM10.
  | ZMM10B = 0x12B
  /// ZMM10C is the 3rd 64-bit chunk of ZMM10.
  | ZMM10C = 0x12C
  /// ZMM10D is the 4th 64-bit chunk of ZMM10.
  | ZMM10D = 0x12D
  /// ZMM10E is the 5th 64-bit chunk of ZMM10.
  | ZMM10E = 0x12E
  /// ZMM10F is the 6th 64-bit chunk of ZMM10.
  | ZMM10F = 0x12F
  /// ZMM10G is the 7th 64-bit chunk of ZMM10.
  | ZMM10G = 0x130
  /// ZMM10H is the 8th 64-bit chunk of ZMM10.
  | ZMM10H = 0x131
  /// ZMM11A is the 1st 64-bit chunk of ZMM11.
  | ZMM11A = 0x132
  /// ZMM11B is the 2nd 64-bit chunk of ZMM11.
  | ZMM11B = 0x133
  /// ZMM11C is the 3rd 64-bit chunk of ZMM11.
  | ZMM11C = 0x134
  /// ZMM11D is the 4th 64-bit chunk of ZMM11.
  | ZMM11D = 0x135
  /// ZMM11E is the 5th 64-bit chunk of ZMM11.
  | ZMM11E = 0x136
  /// ZMM11F is the 6th 64-bit chunk of ZMM11.
  | ZMM11F = 0x137
  /// ZMM11G is the 7th 64-bit chunk of ZMM11.
  | ZMM11G = 0x138
  /// ZMM11H is the 8th 64-bit chunk of ZMM11.
  | ZMM11H = 0x139
  /// ZMM12A is the 1st 64-bit chunk of ZMM12.
  | ZMM12A = 0x13A
  /// ZMM12B is the 2nd 64-bit chunk of ZMM12.
  | ZMM12B = 0x13B
  /// ZMM12C is the 3rd 64-bit chunk of ZMM12.
  | ZMM12C = 0x13C
  /// ZMM12D is the 4th 64-bit chunk of ZMM12.
  | ZMM12D = 0x13D
  /// ZMM12E is the 5th 64-bit chunk of ZMM12.
  | ZMM12E = 0x13E
  /// ZMM12F is the 6th 64-bit chunk of ZMM12.
  | ZMM12F = 0x13F
  /// ZMM12G is the 7th 64-bit chunk of ZMM12.
  | ZMM12G = 0x140
  /// ZMM12H is the 8th 64-bit chunk of ZMM12.
  | ZMM12H = 0x141
  /// ZMM13A is the 1st 64-bit chunk of ZMM13.
  | ZMM13A = 0x142
  /// ZMM13B is the 2nd 64-bit chunk of ZMM13.
  | ZMM13B = 0x143
  /// ZMM13C is the 3rd 64-bit chunk of ZMM13.
  | ZMM13C = 0x144
  /// ZMM13D is the 4th 64-bit chunk of ZMM13.
  | ZMM13D = 0x145
  /// ZMM13E is the 5th 64-bit chunk of ZMM13.
  | ZMM13E = 0x146
  /// ZMM13F is the 6th 64-bit chunk of ZMM13.
  | ZMM13F = 0x147
  /// ZMM13G is the 7th 64-bit chunk of ZMM13.
  | ZMM13G = 0x148
  /// ZMM13H is the 8th 64-bit chunk of ZMM13.
  | ZMM13H = 0x149
  /// ZMM14A is the 1st 64-bit chunk of ZMM14.
  | ZMM14A = 0x14A
  /// ZMM14B is the 2nd 64-bit chunk of ZMM14.
  | ZMM14B = 0x14B
  /// ZMM14C is the 3rd 64-bit chunk of ZMM14.
  | ZMM14C = 0x14C
  /// ZMM14D is the 4th 64-bit chunk of ZMM14.
  | ZMM14D = 0x14D
  /// ZMM14E is the 5th 64-bit chunk of ZMM14.
  | ZMM14E = 0x14E
  /// ZMM14F is the 6th 64-bit chunk of ZMM14.
  | ZMM14F = 0x14F
  /// ZMM14G is the 7th 64-bit chunk of ZMM14.
  | ZMM14G = 0x150
  /// ZMM14H is the 8th 64-bit chunk of ZMM14.
  | ZMM14H = 0x151
  /// ZMM15A is the 1st 64-bit chunk of ZMM15.
  | ZMM15A = 0x152
  /// ZMM15B is the 2nd 64-bit chunk of ZMM15.
  | ZMM15B = 0x153
  /// ZMM15C is the 3rd 64-bit chunk of ZMM15.
  | ZMM15C = 0x154
  /// ZMM15D is the 4th 64-bit chunk of ZMM15.
  | ZMM15D = 0x155
  /// ZMM15E is the 5th 64-bit chunk of ZMM15.
  | ZMM15E = 0x156
  /// ZMM15F is the 6th 64-bit chunk of ZMM15.
  | ZMM15F = 0x157
  /// ZMM15G is the 7th 64-bit chunk of ZMM15.
  | ZMM15G = 0x158
  /// ZMM15H is the 8th 64-bit chunk of ZMM15.
  | ZMM15H = 0x159
  /// Opmask registers. For EVEX.
  | K0 = 0x15A
  /// Opmask registers. For EVEX.
  | K1 = 0x15B
  /// Opmask registers. For EVEX.
  | K2 = 0x15C
  /// Opmask registers. For EVEX.
  | K3 = 0x15D
  /// Opmask registers. For EVEX.
  | K4 = 0x15E
  /// Opmask registers. For EVEX.
  | K5 = 0x15F
  /// Opmask registers. For EVEX.
  | K6 = 0x160
  /// Opmask registers. For EVEX.
  | K7 = 0x161
  /// Unknown Register.
  | UnknownReg = 0x162
#if EMULATION
  /// Opcode of the last instruction that modified EFlags
  | CCOP = 0x163
  /// Result value of the last instruction that modified EFlags
  | CCDST = 0x164
  | CCDSTD = 0x165
  | CCDSTW = 0x166
  | CCDSTB = 0x167
  /// First source operand of the last instruction that modified EFlags
  | CCSRC1 = 0x168
  | CCSRC1D = 0x169
  | CCSRC1W = 0x16a
  | CCSRC1B = 0x16b
  /// Second source operand of the last instruction that modified EFlags
  | CCSRC2 = 0x16c
  | CCSRC2D = 0x16d
  | CCSRC2W = 0x16e
  | CCSRC2B = 0x16f
#endif

/// Helper module for Intel registers.
type IntelRegister =
  /// Get the Intel register from a register ID.
  static member inline Get (rid: RegisterID): Intel =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the Intel register from a string representation.
  static member Get (str: string): Intel =
    match str.ToLowerInvariant () with
    | "rax" -> Intel.RAX
    | "rbx" -> Intel.RBX
    | "rcx" -> Intel.RCX
    | "rdx" -> Intel.RDX
    | "rsp" -> Intel.RSP
    | "rbp" -> Intel.RBP
    | "rsi" -> Intel.RSI
    | "rdi" -> Intel.RDI
    | "eax" -> Intel.EAX
    | "ebx" -> Intel.EBX
    | "ecx" -> Intel.ECX
    | "edx" -> Intel.EDX
    | "esp" -> Intel.ESP
    | "ebp" -> Intel.EBP
    | "esi" -> Intel.ESI
    | "edi" -> Intel.EDI
    | "ax" -> Intel.AX
    | "bx" -> Intel.BX
    | "cx" -> Intel.CX
    | "dx" -> Intel.DX
    | "sp" -> Intel.SP
    | "bp" -> Intel.BP
    | "si" -> Intel.SI
    | "di" -> Intel.DI
    | "al" -> Intel.AL
    | "bl" -> Intel.BL
    | "cl" -> Intel.CL
    | "dl" -> Intel.DL
    | "ah" -> Intel.AH
    | "bh" -> Intel.BH
    | "ch" -> Intel.CH
    | "dh" -> Intel.DH
    | "r8" -> Intel.R8
    | "r9" -> Intel.R9
    | "r10" -> Intel.R10
    | "r11" -> Intel.R11
    | "r12" -> Intel.R12
    | "r13" -> Intel.R13
    | "r14" -> Intel.R14
    | "r15" -> Intel.R15
    | "r8d" -> Intel.R8D
    | "r9d" -> Intel.R9D
    | "r10d" -> Intel.R10D
    | "r11d" -> Intel.R11D
    | "r12d" -> Intel.R12D
    | "r13d" -> Intel.R13D
    | "r14d" -> Intel.R14D
    | "r15d" -> Intel.R15D
    | "r8w" -> Intel.R8W
    | "r9w" -> Intel.R9W
    | "r10w" -> Intel.R10W
    | "r11w" -> Intel.R11W
    | "r12w" -> Intel.R12W
    | "r13w" -> Intel.R13W
    | "r14w" -> Intel.R14W
    | "r15w" -> Intel.R15W
    | "r8b" -> Intel.R8B
    | "r9b" -> Intel.R9B
    | "r10b" -> Intel.R10B
    | "r11b" -> Intel.R11B
    | "r12b" -> Intel.R12B
    | "r13b" -> Intel.R13B
    | "r14b" -> Intel.R14B
    | "r15b" -> Intel.R15B
    | "spl" -> Intel.SPL
    | "bpl" -> Intel.BPL
    | "sil" -> Intel.SIL
    | "dil" -> Intel.DIL
    | "eip" -> Intel.EIP
    | "rip" -> Intel.RIP
    | "st0" -> Intel.ST0
    | "st1" -> Intel.ST1
    | "st2" -> Intel.ST2
    | "st3" -> Intel.ST3
    | "st4" -> Intel.ST4
    | "st5" -> Intel.ST5
    | "st6" -> Intel.ST6
    | "st7" -> Intel.ST7
    | "mm0" -> Intel.MM0
    | "mm1" -> Intel.MM1
    | "mm2" -> Intel.MM2
    | "mm3" -> Intel.MM3
    | "mm4" -> Intel.MM4
    | "mm5" -> Intel.MM5
    | "mm6" -> Intel.MM6
    | "mm7" -> Intel.MM7
    | "xmm0" -> Intel.XMM0
    | "xmm1" -> Intel.XMM1
    | "xmm2" -> Intel.XMM2
    | "xmm3" -> Intel.XMM3
    | "xmm4" -> Intel.XMM4
    | "xmm5" -> Intel.XMM5
    | "xmm6" -> Intel.XMM6
    | "xmm7" -> Intel.XMM7
    | "xmm8" -> Intel.XMM8
    | "xmm9" -> Intel.XMM9
    | "xmm10" -> Intel.XMM10
    | "xmm11" -> Intel.XMM11
    | "xmm12" -> Intel.XMM12
    | "xmm13" -> Intel.XMM13
    | "xmm14" -> Intel.XMM14
    | "xmm15" -> Intel.XMM15
    | "ymm0" -> Intel.YMM0
    | "ymm1" -> Intel.YMM1
    | "ymm2" -> Intel.YMM2
    | "ymm3" -> Intel.YMM3
    | "ymm4" -> Intel.YMM4
    | "ymm5" -> Intel.YMM5
    | "ymm6" -> Intel.YMM6
    | "ymm7" -> Intel.YMM7
    | "ymm8" -> Intel.YMM8
    | "ymm9" -> Intel.YMM9
    | "ymm10" -> Intel.YMM10
    | "ymm11" -> Intel.YMM11
    | "ymm12" -> Intel.YMM12
    | "ymm13" -> Intel.YMM13
    | "ymm14" -> Intel.YMM14
    | "ymm15" -> Intel.YMM15
    | "zmm0" -> Intel.ZMM0
    | "zmm1" -> Intel.ZMM1
    | "zmm2" -> Intel.ZMM2
    | "zmm3" -> Intel.ZMM3
    | "zmm4" -> Intel.ZMM4
    | "zmm5" -> Intel.ZMM5
    | "zmm6" -> Intel.ZMM6
    | "zmm7" -> Intel.ZMM7
    | "zmm8" -> Intel.ZMM8
    | "zmm9" -> Intel.ZMM9
    | "zmm10" -> Intel.ZMM10
    | "zmm11" -> Intel.ZMM11
    | "zmm12" -> Intel.ZMM12
    | "zmm13" -> Intel.ZMM13
    | "zmm14" -> Intel.ZMM14
    | "zmm15" -> Intel.ZMM15
    | "es" -> Intel.ES
    | "cs" -> Intel.CS
    | "ss" -> Intel.SS
    | "ds" -> Intel.DS
    | "fs" -> Intel.FS
    | "gs" -> Intel.GS
    | "esbASE" -> Intel.ESBase
    | "csbASE" -> Intel.CSBase
    | "ssbASE" -> Intel.SSBase
    | "dsbASE" -> Intel.DSBase
    | "fsbASE" -> Intel.FSBase
    | "gsbASE" -> Intel.GSBase
    | "cr0" -> Intel.CR0
    | "cr2" -> Intel.CR2
    | "cr3" -> Intel.CR3
    | "cr4" -> Intel.CR4
    | "cr8" -> Intel.CR8
    | "dr0" -> Intel.DR0
    | "dr1" -> Intel.DR1
    | "dr2" -> Intel.DR2
    | "dr3" -> Intel.DR3
    | "dr6" -> Intel.DR6
    | "dr7" -> Intel.DR7
    | "bnd0" -> Intel.BND0
    | "bnd1" -> Intel.BND1
    | "bnd2" -> Intel.BND2
    | "bnd3" -> Intel.BND3
    | "of" -> Intel.OF
    | "df" -> Intel.DF
    | "if" -> Intel.IF
    | "tf" -> Intel.TF
    | "sf" -> Intel.SF
    | "zf" -> Intel.ZF
    | "af" -> Intel.AF
    | "pf" -> Intel.PF
    | "cf" -> Intel.CF
    | "fcw" -> Intel.FCW
    | "fsw" -> Intel.FSW
    | "ftw" -> Intel.FTW
    | "fop" -> Intel.FOP
    | "fip" -> Intel.FIP
    | "fcs" -> Intel.FCS
    | "fdp" -> Intel.FDP
    | "fds" -> Intel.FDS
    | "ftop" -> Intel.FTOP
    | "ftw0" -> Intel.FTW0
    | "ftw1" -> Intel.FTW1
    | "ftw2" -> Intel.FTW2
    | "ftw3" -> Intel.FTW3
    | "ftw4" -> Intel.FTW4
    | "ftw5" -> Intel.FTW5
    | "ftw6" -> Intel.FTW6
    | "ftw7" -> Intel.FTW7
    | "fswc0" -> Intel.FSWC0
    | "fswc1" -> Intel.FSWC1
    | "fswc2" -> Intel.FSWC2
    | "fswc3" -> Intel.FSWC3
    | "mxcsr" -> Intel.MXCSR
    | "mxcsrmask" -> Intel.MXCSRMASK
    | "pkru" -> Intel.PKRU
    | "bnd0a" -> Intel.BND0A
    | "bnd0b" -> Intel.BND0B
    | "bnd1a" -> Intel.BND1A
    | "bnd1b" -> Intel.BND1B
    | "bnd2a" -> Intel.BND2A
    | "bnd2b" -> Intel.BND2B
    | "bnd3a" -> Intel.BND3A
    | "bnd3b" -> Intel.BND3B
    | "st0a" -> Intel.ST0A
    | "st0b" -> Intel.ST0B
    | "st1a" -> Intel.ST1A
    | "st1b" -> Intel.ST1B
    | "st2a" -> Intel.ST2A
    | "st2b" -> Intel.ST2B
    | "st3a" -> Intel.ST3A
    | "st3b" -> Intel.ST3B
    | "st4a" -> Intel.ST4A
    | "st4b" -> Intel.ST4B
    | "st5a" -> Intel.ST5A
    | "st5b" -> Intel.ST5B
    | "st6a" -> Intel.ST6A
    | "st6b" -> Intel.ST6B
    | "st7a" -> Intel.ST7A
    | "st7b" -> Intel.ST7B
    | "zmm0a" -> Intel.ZMM0A
    | "zmm0b" -> Intel.ZMM0B
    | "zmm0c" -> Intel.ZMM0C
    | "zmm0d" -> Intel.ZMM0D
    | "zmm0e" -> Intel.ZMM0E
    | "zmm0f" -> Intel.ZMM0F
    | "zmm0g" -> Intel.ZMM0G
    | "zmm0h" -> Intel.ZMM0H
    | "zmm1a" -> Intel.ZMM1A
    | "zmm1b" -> Intel.ZMM1B
    | "zmm1c" -> Intel.ZMM1C
    | "zmm1d" -> Intel.ZMM1D
    | "zmm1e" -> Intel.ZMM1E
    | "zmm1f" -> Intel.ZMM1F
    | "zmm1g" -> Intel.ZMM1G
    | "zmm1h" -> Intel.ZMM1H
    | "zmm2a" -> Intel.ZMM2A
    | "zmm2b" -> Intel.ZMM2B
    | "zmm2c" -> Intel.ZMM2C
    | "zmm2d" -> Intel.ZMM2D
    | "zmm2e" -> Intel.ZMM2E
    | "zmm2f" -> Intel.ZMM2F
    | "zmm2g" -> Intel.ZMM2G
    | "zmm2h" -> Intel.ZMM2H
    | "zmm3a" -> Intel.ZMM3A
    | "zmm3b" -> Intel.ZMM3B
    | "zmm3c" -> Intel.ZMM3C
    | "zmm3d" -> Intel.ZMM3D
    | "zmm3e" -> Intel.ZMM3E
    | "zmm3f" -> Intel.ZMM3F
    | "zmm3g" -> Intel.ZMM3G
    | "zmm3h" -> Intel.ZMM3H
    | "zmm4a" -> Intel.ZMM4A
    | "zmm4b" -> Intel.ZMM4B
    | "zmm4c" -> Intel.ZMM4C
    | "zmm4d" -> Intel.ZMM4D
    | "zmm4e" -> Intel.ZMM4E
    | "zmm4f" -> Intel.ZMM4F
    | "zmm4g" -> Intel.ZMM4G
    | "zmm4h" -> Intel.ZMM4H
    | "zmm5a" -> Intel.ZMM5A
    | "zmm5b" -> Intel.ZMM5B
    | "zmm5c" -> Intel.ZMM5C
    | "zmm5d" -> Intel.ZMM5D
    | "zmm5e" -> Intel.ZMM5E
    | "zmm5f" -> Intel.ZMM5F
    | "zmm5g" -> Intel.ZMM5G
    | "zmm5h" -> Intel.ZMM5H
    | "zmm6a" -> Intel.ZMM6A
    | "zmm6b" -> Intel.ZMM6B
    | "zmm6c" -> Intel.ZMM6C
    | "zmm6d" -> Intel.ZMM6D
    | "zmm6e" -> Intel.ZMM6E
    | "zmm6f" -> Intel.ZMM6F
    | "zmm6g" -> Intel.ZMM6G
    | "zmm6h" -> Intel.ZMM6H
    | "zmm7a" -> Intel.ZMM7A
    | "zmm7b" -> Intel.ZMM7B
    | "zmm7c" -> Intel.ZMM7C
    | "zmm7d" -> Intel.ZMM7D
    | "zmm7e" -> Intel.ZMM7E
    | "zmm7f" -> Intel.ZMM7F
    | "zmm7g" -> Intel.ZMM7G
    | "zmm7h" -> Intel.ZMM7H
    | "zmm8a" -> Intel.ZMM8A
    | "zmm8b" -> Intel.ZMM8B
    | "zmm8c" -> Intel.ZMM8C
    | "zmm8d" -> Intel.ZMM8D
    | "zmm8e" -> Intel.ZMM8E
    | "zmm8f" -> Intel.ZMM8F
    | "zmm8g" -> Intel.ZMM8G
    | "zmm8h" -> Intel.ZMM8H
    | "zmm9a" -> Intel.ZMM9A
    | "zmm9b" -> Intel.ZMM9B
    | "zmm9c" -> Intel.ZMM9C
    | "zmm9d" -> Intel.ZMM9D
    | "zmm9e" -> Intel.ZMM9E
    | "zmm9f" -> Intel.ZMM9F
    | "zmm9g" -> Intel.ZMM9G
    | "zmm9h" -> Intel.ZMM9H
    | "zmm10a" -> Intel.ZMM10A
    | "zmm10b" -> Intel.ZMM10B
    | "zmm10c" -> Intel.ZMM10C
    | "zmm10d" -> Intel.ZMM10D
    | "zmm10e" -> Intel.ZMM10E
    | "zmm10f" -> Intel.ZMM10F
    | "zmm10g" -> Intel.ZMM10G
    | "zmm10h" -> Intel.ZMM10H
    | "zmm11a" -> Intel.ZMM11A
    | "zmm11b" -> Intel.ZMM11B
    | "zmm11c" -> Intel.ZMM11C
    | "zmm11d" -> Intel.ZMM11D
    | "zmm11e" -> Intel.ZMM11E
    | "zmm11f" -> Intel.ZMM11F
    | "zmm11g" -> Intel.ZMM11G
    | "zmm11h" -> Intel.ZMM11H
    | "zmm12a" -> Intel.ZMM12A
    | "zmm12b" -> Intel.ZMM12B
    | "zmm12c" -> Intel.ZMM12C
    | "zmm12d" -> Intel.ZMM12D
    | "zmm12e" -> Intel.ZMM12E
    | "zmm12f" -> Intel.ZMM12F
    | "zmm12g" -> Intel.ZMM12G
    | "zmm12h" -> Intel.ZMM12H
    | "zmm13a" -> Intel.ZMM13A
    | "zmm13b" -> Intel.ZMM13B
    | "zmm13c" -> Intel.ZMM13C
    | "zmm13d" -> Intel.ZMM13D
    | "zmm13e" -> Intel.ZMM13E
    | "zmm13f" -> Intel.ZMM13F
    | "zmm13g" -> Intel.ZMM13G
    | "zmm13h" -> Intel.ZMM13H
    | "zmm14a" -> Intel.ZMM14A
    | "zmm14b" -> Intel.ZMM14B
    | "zmm14c" -> Intel.ZMM14C
    | "zmm14d" -> Intel.ZMM14D
    | "zmm14e" -> Intel.ZMM14E
    | "zmm14f" -> Intel.ZMM14F
    | "zmm14g" -> Intel.ZMM14G
    | "zmm14h" -> Intel.ZMM14H
    | "zmm15a" -> Intel.ZMM15A
    | "zmm15b" -> Intel.ZMM15B
    | "zmm15c" -> Intel.ZMM15C
    | "zmm15d" -> Intel.ZMM15D
    | "zmm15e" -> Intel.ZMM15E
    | "zmm15f" -> Intel.ZMM15F
    | "zmm15g" -> Intel.ZMM15G
    | "zmm15h" -> Intel.ZMM15H
    | "k0" -> Intel.K0
    | "k1" -> Intel.K1
    | "k2" -> Intel.K2
    | "k3" -> Intel.K3
    | "k4" -> Intel.K4
    | "k5" -> Intel.K5
    | "k6" -> Intel.K6
    | "k7" -> Intel.K7
    | _ -> Utils.impossible ()

  /// Get the register ID of an Intel register.
  static member inline ID (reg: Intel) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of an Intel register.
  static member String (reg: Intel) =
    match reg with
    | Intel.RAX -> "RAX"
    | Intel.RBX -> "RBX"
    | Intel.RCX -> "RCX"
    | Intel.RDX -> "RDX"
    | Intel.RSP -> "RSP"
    | Intel.RBP -> "RBP"
    | Intel.RSI -> "RSI"
    | Intel.RDI -> "RDI"
    | Intel.EAX -> "EAX"
    | Intel.EBX -> "EBX"
    | Intel.ECX -> "ECX"
    | Intel.EDX -> "EDX"
    | Intel.ESP -> "ESP"
    | Intel.EBP -> "EBP"
    | Intel.ESI -> "ESI"
    | Intel.EDI -> "EDI"
    | Intel.AX -> "AX"
    | Intel.BX -> "BX"
    | Intel.CX -> "CX"
    | Intel.DX -> "DX"
    | Intel.SP -> "SP"
    | Intel.BP -> "BP"
    | Intel.SI -> "SI"
    | Intel.DI -> "DI"
    | Intel.AL -> "AL"
    | Intel.BL -> "BL"
    | Intel.CL -> "CL"
    | Intel.DL -> "DL"
    | Intel.AH -> "AH"
    | Intel.BH -> "BH"
    | Intel.CH -> "CH"
    | Intel.DH -> "DH"
    | Intel.R8 -> "R8"
    | Intel.R9 -> "R9"
    | Intel.R10 -> "R10"
    | Intel.R11 -> "R11"
    | Intel.R12 -> "R12"
    | Intel.R13 -> "R13"
    | Intel.R14 -> "R14"
    | Intel.R15 -> "R15"
    | Intel.R8D -> "R8D"
    | Intel.R9D -> "R9D"
    | Intel.R10D -> "R10D"
    | Intel.R11D -> "R11D"
    | Intel.R12D -> "R12D"
    | Intel.R13D -> "R13D"
    | Intel.R14D -> "R14D"
    | Intel.R15D -> "R15D"
    | Intel.R8W -> "R8W"
    | Intel.R9W -> "R9W"
    | Intel.R10W -> "R10W"
    | Intel.R11W -> "R11W"
    | Intel.R12W -> "R12W"
    | Intel.R13W -> "R13W"
    | Intel.R14W -> "R14W"
    | Intel.R15W -> "R15W"
    | Intel.R8B -> "R8B"
    | Intel.R9B -> "R9B"
    | Intel.R10B -> "R10B"
    | Intel.R11B -> "R11B"
    | Intel.R12B -> "R12B"
    | Intel.R13B -> "R13B"
    | Intel.R14B -> "R14B"
    | Intel.R15B -> "R15B"
    | Intel.SPL -> "SPL"
    | Intel.BPL -> "BPL"
    | Intel.SIL -> "SIL"
    | Intel.DIL -> "DIL"
    | Intel.EIP -> "EIP"
    | Intel.RIP -> "RIP"
    | Intel.ST0 -> "ST0"
    | Intel.ST1 -> "ST1"
    | Intel.ST2 -> "ST2"
    | Intel.ST3 -> "ST3"
    | Intel.ST4 -> "ST4"
    | Intel.ST5 -> "ST5"
    | Intel.ST6 -> "ST6"
    | Intel.ST7 -> "ST7"
    | Intel.FCW -> "FCW"
    | Intel.FSW -> "FSW"
    | Intel.FTW -> "FTW"
    | Intel.FOP -> "FOP"
    | Intel.FIP -> "FIP"
    | Intel.FCS -> "FCS"
    | Intel.FDP -> "FDP"
    | Intel.FDS -> "FDS"
    | Intel.FTOP -> "FTOP"
    | Intel.FTW0 -> "FTW0"
    | Intel.FTW1 -> "FTW1"
    | Intel.FTW2 -> "FTW2"
    | Intel.FTW3 -> "FTW3"
    | Intel.FTW4 -> "FTW4"
    | Intel.FTW5 -> "FTW5"
    | Intel.FTW6 -> "FTW6"
    | Intel.FTW7 -> "FTW7"
    | Intel.FSWC0 -> "FSWC0"
    | Intel.FSWC1 -> "FSWC1"
    | Intel.FSWC2 -> "FSWC2"
    | Intel.FSWC3 -> "FSWC3"
    | Intel.MXCSR -> "MXCSR"
    | Intel.MXCSRMASK -> "MXCSRMASK"
    | Intel.MM0 -> "MM0"
    | Intel.MM1 -> "MM1"
    | Intel.MM2 -> "MM2"
    | Intel.MM3 -> "MM3"
    | Intel.MM4 -> "MM4"
    | Intel.MM5 -> "MM5"
    | Intel.MM6 -> "MM6"
    | Intel.MM7 -> "MM7"
    | Intel.XMM0 -> "XMM0"
    | Intel.XMM1 -> "XMM1"
    | Intel.XMM2 -> "XMM2"
    | Intel.XMM3 -> "XMM3"
    | Intel.XMM4 -> "XMM4"
    | Intel.XMM5 -> "XMM5"
    | Intel.XMM6 -> "XMM6"
    | Intel.XMM7 -> "XMM7"
    | Intel.XMM8 -> "XMM8"
    | Intel.XMM9 -> "XMM9"
    | Intel.XMM10 -> "XMM10"
    | Intel.XMM11 -> "XMM11"
    | Intel.XMM12 -> "XMM12"
    | Intel.XMM13 -> "XMM13"
    | Intel.XMM14 -> "XMM14"
    | Intel.XMM15 -> "XMM15"
    | Intel.YMM0 -> "YMM0"
    | Intel.YMM1 -> "YMM1"
    | Intel.YMM2 -> "YMM2"
    | Intel.YMM3 -> "YMM3"
    | Intel.YMM4 -> "YMM4"
    | Intel.YMM5 -> "YMM5"
    | Intel.YMM6 -> "YMM6"
    | Intel.YMM7 -> "YMM7"
    | Intel.YMM8 -> "YMM8"
    | Intel.YMM9 -> "YMM9"
    | Intel.YMM10 -> "YMM10"
    | Intel.YMM11 -> "YMM11"
    | Intel.YMM12 -> "YMM12"
    | Intel.YMM13 -> "YMM13"
    | Intel.YMM14 -> "YMM14"
    | Intel.YMM15 -> "YMM15"
    | Intel.ZMM0 -> "ZMM0"
    | Intel.ZMM1 -> "ZMM1"
    | Intel.ZMM2 -> "ZMM2"
    | Intel.ZMM3 -> "ZMM3"
    | Intel.ZMM4 -> "ZMM4"
    | Intel.ZMM5 -> "ZMM5"
    | Intel.ZMM6 -> "ZMM6"
    | Intel.ZMM7 -> "ZMM7"
    | Intel.ZMM8 -> "ZMM8"
    | Intel.ZMM9 -> "ZMM9"
    | Intel.ZMM10 -> "ZMM10"
    | Intel.ZMM11 -> "ZMM11"
    | Intel.ZMM12 -> "ZMM12"
    | Intel.ZMM13 -> "ZMM13"
    | Intel.ZMM14 -> "ZMM14"
    | Intel.ZMM15 -> "ZMM15"
    | Intel.CS -> "CS"
    | Intel.DS -> "DS"
    | Intel.SS -> "SS"
    | Intel.ES -> "ES"
    | Intel.FS -> "FS"
    | Intel.GS -> "GS"
    | Intel.CSBase -> "CSBase"
    | Intel.DSBase -> "DSBase"
    | Intel.ESBase -> "ESBase"
    | Intel.FSBase -> "FSBase"
    | Intel.GSBase -> "GSBase"
    | Intel.SSBase -> "SSBase"
    | Intel.CR0 -> "CR0"
    | Intel.CR2 -> "CR2"
    | Intel.CR3 -> "CR3"
    | Intel.CR4 -> "CR4"
    | Intel.CR8 -> "CR8"
    | Intel.DR0 -> "DR0"
    | Intel.DR1 -> "DR1"
    | Intel.DR2 -> "DR2"
    | Intel.DR3 -> "DR3"
    | Intel.DR6 -> "DR6"
    | Intel.DR7 -> "DR7"
    | Intel.BND0 -> "BND0"
    | Intel.BND1 -> "BND1"
    | Intel.BND2 -> "BND2"
    | Intel.BND3 -> "BND3"
    | Intel.OF -> "OF"
    | Intel.DF -> "DF"
    | Intel.IF -> "IF"
    | Intel.TF -> "TF"
    | Intel.SF -> "SF"
    | Intel.ZF -> "ZF"
    | Intel.AF -> "AF"
    | Intel.PF -> "PF"
    | Intel.CF -> "CF"
    | Intel.ST0A -> "ST0A"
    | Intel.ST0B -> "ST0B"
    | Intel.ST1A -> "ST1A"
    | Intel.ST1B -> "ST1B"
    | Intel.ST2A -> "ST2A"
    | Intel.ST2B -> "ST2B"
    | Intel.ST3A -> "ST3A"
    | Intel.ST3B -> "ST3B"
    | Intel.ST4A -> "ST4A"
    | Intel.ST4B -> "ST4B"
    | Intel.ST5A -> "ST5A"
    | Intel.ST5B -> "ST5B"
    | Intel.ST6A -> "ST6A"
    | Intel.ST6B -> "ST6B"
    | Intel.ST7A -> "ST7A"
    | Intel.ST7B -> "ST7B"
    | Intel.ZMM0A -> "ZMM0A"
    | Intel.ZMM0B -> "ZMM0B"
    | Intel.ZMM0C -> "ZMM0C"
    | Intel.ZMM0D -> "ZMM0D"
    | Intel.ZMM0E -> "ZMM0E"
    | Intel.ZMM0F -> "ZMM0F"
    | Intel.ZMM0G -> "ZMM0G"
    | Intel.ZMM0H -> "ZMM0H"
    | Intel.ZMM1A -> "ZMM1A"
    | Intel.ZMM1B -> "ZMM1B"
    | Intel.ZMM1C -> "ZMM1C"
    | Intel.ZMM1D -> "ZMM1D"
    | Intel.ZMM1E -> "ZMM1E"
    | Intel.ZMM1F -> "ZMM1F"
    | Intel.ZMM1G -> "ZMM1G"
    | Intel.ZMM1H -> "ZMM1H"
    | Intel.ZMM2A -> "ZMM2A"
    | Intel.ZMM2B -> "ZMM2B"
    | Intel.ZMM2C -> "ZMM2C"
    | Intel.ZMM2D -> "ZMM2D"
    | Intel.ZMM2E -> "ZMM2E"
    | Intel.ZMM2F -> "ZMM2F"
    | Intel.ZMM2G -> "ZMM2G"
    | Intel.ZMM2H -> "ZMM2H"
    | Intel.ZMM3A -> "ZMM3A"
    | Intel.ZMM3B -> "ZMM3B"
    | Intel.ZMM3C -> "ZMM3C"
    | Intel.ZMM3D -> "ZMM3D"
    | Intel.ZMM3E -> "ZMM3E"
    | Intel.ZMM3F -> "ZMM3F"
    | Intel.ZMM3G -> "ZMM3G"
    | Intel.ZMM3H -> "ZMM3H"
    | Intel.ZMM4A -> "ZMM4A"
    | Intel.ZMM4B -> "ZMM4B"
    | Intel.ZMM4C -> "ZMM4C"
    | Intel.ZMM4D -> "ZMM4D"
    | Intel.ZMM4E -> "ZMM4E"
    | Intel.ZMM4F -> "ZMM4F"
    | Intel.ZMM4G -> "ZMM4G"
    | Intel.ZMM4H -> "ZMM4H"
    | Intel.ZMM5A -> "ZMM5A"
    | Intel.ZMM5B -> "ZMM5B"
    | Intel.ZMM5C -> "ZMM5C"
    | Intel.ZMM5D -> "ZMM5D"
    | Intel.ZMM5E -> "ZMM5E"
    | Intel.ZMM5F -> "ZMM5F"
    | Intel.ZMM5G -> "ZMM5G"
    | Intel.ZMM5H -> "ZMM5H"
    | Intel.ZMM6A -> "ZMM6A"
    | Intel.ZMM6B -> "ZMM6B"
    | Intel.ZMM6C -> "ZMM6C"
    | Intel.ZMM6D -> "ZMM6D"
    | Intel.ZMM6E -> "ZMM6E"
    | Intel.ZMM6F -> "ZMM6F"
    | Intel.ZMM6G -> "ZMM6G"
    | Intel.ZMM6H -> "ZMM6H"
    | Intel.ZMM7A -> "ZMM7A"
    | Intel.ZMM7B -> "ZMM7B"
    | Intel.ZMM7C -> "ZMM7C"
    | Intel.ZMM7D -> "ZMM7D"
    | Intel.ZMM7E -> "ZMM7E"
    | Intel.ZMM7F -> "ZMM7F"
    | Intel.ZMM7G -> "ZMM7G"
    | Intel.ZMM7H -> "ZMM7H"
    | Intel.ZMM8A -> "ZMM8A"
    | Intel.ZMM8B -> "ZMM8B"
    | Intel.ZMM8C -> "ZMM8C"
    | Intel.ZMM8D -> "ZMM8D"
    | Intel.ZMM8E -> "ZMM8E"
    | Intel.ZMM8F -> "ZMM8F"
    | Intel.ZMM8G -> "ZMM8G"
    | Intel.ZMM8H -> "ZMM8H"
    | Intel.ZMM9A -> "ZMM9A"
    | Intel.ZMM9B -> "ZMM9B"
    | Intel.ZMM9C -> "ZMM9C"
    | Intel.ZMM9D -> "ZMM9D"
    | Intel.ZMM9E -> "ZMM9E"
    | Intel.ZMM9F -> "ZMM9F"
    | Intel.ZMM9G -> "ZMM9G"
    | Intel.ZMM9H -> "ZMM9H"
    | Intel.ZMM10A -> "ZMM10A"
    | Intel.ZMM10B -> "ZMM10B"
    | Intel.ZMM10C -> "ZMM10C"
    | Intel.ZMM10D -> "ZMM10D"
    | Intel.ZMM10E -> "ZMM10E"
    | Intel.ZMM10F -> "ZMM10F"
    | Intel.ZMM10G -> "ZMM10G"
    | Intel.ZMM10H -> "ZMM10H"
    | Intel.ZMM11A -> "ZMM11A"
    | Intel.ZMM11B -> "ZMM11B"
    | Intel.ZMM11C -> "ZMM11C"
    | Intel.ZMM11D -> "ZMM11D"
    | Intel.ZMM11E -> "ZMM11E"
    | Intel.ZMM11F -> "ZMM11F"
    | Intel.ZMM11G -> "ZMM11G"
    | Intel.ZMM11H -> "ZMM11H"
    | Intel.ZMM12A -> "ZMM12A"
    | Intel.ZMM12B -> "ZMM12B"
    | Intel.ZMM12C -> "ZMM12C"
    | Intel.ZMM12D -> "ZMM12D"
    | Intel.ZMM12E -> "ZMM12E"
    | Intel.ZMM12F -> "ZMM12F"
    | Intel.ZMM12G -> "ZMM12G"
    | Intel.ZMM12H -> "ZMM12H"
    | Intel.ZMM13A -> "ZMM13A"
    | Intel.ZMM13B -> "ZMM13B"
    | Intel.ZMM13C -> "ZMM13C"
    | Intel.ZMM13D -> "ZMM13D"
    | Intel.ZMM13E -> "ZMM13E"
    | Intel.ZMM13F -> "ZMM13F"
    | Intel.ZMM13G -> "ZMM13G"
    | Intel.ZMM13H -> "ZMM13H"
    | Intel.ZMM14A -> "ZMM14A"
    | Intel.ZMM14B -> "ZMM14B"
    | Intel.ZMM14C -> "ZMM14C"
    | Intel.ZMM14D -> "ZMM14D"
    | Intel.ZMM14E -> "ZMM14E"
    | Intel.ZMM14F -> "ZMM14F"
    | Intel.ZMM14G -> "ZMM14G"
    | Intel.ZMM14H -> "ZMM14H"
    | Intel.ZMM15A -> "ZMM15A"
    | Intel.ZMM15B -> "ZMM15B"
    | Intel.ZMM15C -> "ZMM15C"
    | Intel.ZMM15D -> "ZMM15D"
    | Intel.ZMM15E -> "ZMM15E"
    | Intel.ZMM15F -> "ZMM15F"
    | Intel.ZMM15G -> "ZMM15G"
    | Intel.ZMM15H -> "ZMM15H"
    | Intel.K0 -> "K0"
    | Intel.K1 -> "K1"
    | Intel.K2 -> "K2"
    | Intel.K3 -> "K3"
    | Intel.K4 -> "K4"
    | Intel.K5 -> "K5"
    | Intel.K6 -> "K6"
    | Intel.K7 -> "K7"
    | Intel.PKRU -> "PKRU"
#if EMULATION
    | Intel.CCOP -> "CCOP"
    | Intel.CCDST -> "CCDST"
    | Intel.CCSRC1 -> "CCSRC1"
    | Intel.CCSRC2 -> "CCSRC2"
#endif
#if DEBUG
    | _ -> Utils.impossible ()
#else
    | _ -> "?"
#endif

/// <summary>
/// Registers for MIPS32 and MIPS64.<para/>
/// </summary>
type MIPS =
  /// $zero or $r0 - Always zero
  | R0 = 0x0
  /// $at - Reservd for assembler.
  | R1 = 0x1
  /// $v0 - First and second return values, respectively.
  | R2 = 0x2
  /// $v1 - First and second return values, respectively.
  | R3 = 0x3
  /// $a0 - First four arguments to functions.
  | R4 = 0x4
  /// $a1 - First four arguments to functions.
  | R5 = 0x5
  /// $a2 - First four arguments to functions.
  | R6 = 0x6
  /// $a3 - First four arguments to functions.
  | R7 = 0x7
  /// $t0 - Temporary register.
  | R8 = 0x8
  /// $t1 - Temporary register.
  | R9 = 0x9
  /// $t2 - Temporary register.
  | R10 = 0xA
  /// $t3 - Temporary register.
  | R11 = 0xB
  /// $t4 - Temporary register.
  | R12 = 0xC
  /// $t5 - Temporary register.
  | R13 = 0xD
  /// $t6 - Temporary register.
  | R14 = 0xE
  /// $t7 - Temporary register.
  | R15 = 0xF
  /// $s0 - Saved register.
  | R16 = 0x10
  /// $s1 - Saved register.
  | R17 = 0x11
  /// $s2 - Saved register.
  | R18 = 0x12
  /// $s3 - Saved register.
  | R19 = 0x13
  /// $s4 - Saved register.
  | R20 = 0x14
  /// $s5 - Saved register.
  | R21 = 0x15
  /// $s6 - Saved register.
  | R22 = 0x16
  /// $s7 - Saved register.
  | R23 = 0x17
  /// $t8 - More temporary register.
  | R24 = 0x18
  /// $t9 - More temporary register.
  | R25 = 0x19
  /// $k0 - Reserved for kernel (operating system).
  | R26 = 0x1A
  /// $k1 - Reserved for kernel (operating system).
  | R27 = 0x1B
  /// $gp - Global pointer.
  | R28 = 0x1C
  /// $sp - Stack pointer.
  | R29 = 0x1D
  /// $fp - Frame pointer.
  | R30 = 0x1E
  /// $ra - Return address.
  | R31 = 0x1F
  /// Floating point Register.
  | F0 = 0x20
  /// Floating point Register.
  | F1 = 0x21
  /// Floating point Register.
  | F2 = 0x22
  /// Floating point Register.
  | F3 = 0x23
  /// Floating point Register.
  | F4 = 0x24
  /// Floating point Register.
  | F5 = 0x25
  /// Floating point Register.
  | F6 = 0x26
  /// Floating point Register.
  | F7 = 0x27
  /// Floating point Register.
  | F8 = 0x28
  /// Floating point Register.
  | F9 = 0x29
  /// Floating point Register.
  | F10 =0x2A
  /// Floating point Register.
  | F11 = 0x2B
  /// Floating point Register.
  | F12 = 0x2C
  /// Floating point Register.
  | F13 = 0x2D
  /// Floating point Register.
  | F14 = 0x2E
  /// Floating point Register.
  | F15 = 0x2F
  /// Floating point Register.
  | F16 = 0x30
  /// Floating point Register.
  | F17 = 0x31
  /// Floating point Register.
  | F18 = 0x32
  /// Floating point Register.
  | F19 = 0x33
  /// Floating point Register.
  | F20 = 0x34
  /// Floating point Register.
  | F21 = 0x35
  /// Floating point Register.
  | F22 = 0x36
  /// Floating point Register.
  | F23 = 0x37
  /// Floating point Register.
  | F24 = 0x38
  /// Floating point Register.
  | F25 = 0x39
  /// Floating point Register.
  | F26 = 0x3A
  /// Floating point Register.
  | F27 = 0x3B
  /// Floating point Register.
  | F28 = 0x3C
  /// Floating point Register.
  | F29 = 0x3D
  /// Floating point Register.
  | F30 = 0x3E
  /// Floating point Register.
  | F31 = 0x3F
  /// Accumulator High (Acc 63:32)
  | HI = 0x100
  /// Accumulator Low (Acc 31:0)
  | LO = 0x101
  /// Program Counter.
  | PC = 0x102
  /// Pseudo register for the next PC (nPC).
  | NPC = 0x103
  /// Pseudo register for LLBit. This is used to store the actual LLBit value
  /// from the CPU after an exception.
  | LLBit = 0x104
  /// Floating Point Control and Status Register.
  | FCSR = 0x105
  /// Floating Point Implementation Register.
  | FIR = 0x106

/// Helper module for MIPS registers.
type MIPSRegister =
  /// Get the MIPS register from a register ID.
  static member inline Get (rid: RegisterID): MIPS =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the MIPS register from a string representation.
  static member Get (str: string, wordSize): MIPS =
    match str.ToLowerInvariant () with
    | "r0" -> MIPS.R0
    | "r1" | "at" -> MIPS.R1
    | "r2" | "v0" -> MIPS.R2
    | "r3" | "v1" -> MIPS.R3
    | "r4" | "a0" -> MIPS.R4
    | "r5" | "a1" -> MIPS.R5
    | "r6" | "a2" -> MIPS.R6
    | "r7" | "a3" -> MIPS.R7
    | "r8" | "a4" -> MIPS.R8
    | "r9" | "a5" -> MIPS.R9
    | "r10" | "a6" -> MIPS.R10
    | "r11" | "a7" -> MIPS.R11
    | "t0" -> if wordSize = WordSize.Bit32 then MIPS.R8 else MIPS.R12
    | "t1" -> if wordSize = WordSize.Bit32 then MIPS.R9 else MIPS.R13
    | "t2" -> if wordSize = WordSize.Bit32 then MIPS.R10 else MIPS.R14
    | "t3" -> if wordSize = WordSize.Bit32 then MIPS.R11 else MIPS.R15
    | "r12" | "t4" -> MIPS.R12
    | "r13" | "t5" -> MIPS.R13
    | "r14" | "t6" -> MIPS.R14
    | "r15" | "t7" -> MIPS.R15
    | "r16" | "s0" -> MIPS.R16
    | "r17" | "s1" -> MIPS.R17
    | "r18" | "s2" -> MIPS.R18
    | "r19" | "s3" -> MIPS.R19
    | "r20" | "s4" -> MIPS.R20
    | "r21" | "s5" -> MIPS.R21
    | "r22" | "s6" -> MIPS.R22
    | "r23" | "s7" -> MIPS.R23
    | "r24" | "t8" -> MIPS.R24
    | "r25" | "t9" -> MIPS.R25
    | "r26" | "k0" -> MIPS.R26
    | "r27" | "k1" -> MIPS.R27
    | "r28" | "gp" -> MIPS.R28
    | "r29" | "sp" -> MIPS.R29
    | "r30" | "fp" -> MIPS.R30
    | "r31" | "ra" -> MIPS.R31
    | "f0" -> MIPS.F0
    | "f1" -> MIPS.F1
    | "f2" -> MIPS.F2
    | "f3" -> MIPS.F3
    | "f4" -> MIPS.F4
    | "f5" -> MIPS.F5
    | "f6" -> MIPS.F6
    | "f7" -> MIPS.F7
    | "f8" -> MIPS.F8
    | "f9" -> MIPS.F9
    | "f10" -> MIPS.F10
    | "f11" -> MIPS.F11
    | "f12" -> MIPS.F12
    | "f13" -> MIPS.F13
    | "f14" -> MIPS.F14
    | "f15" -> MIPS.F15
    | "f16" -> MIPS.F16
    | "f17" -> MIPS.F17
    | "f18" -> MIPS.F18
    | "f19" -> MIPS.F19
    | "f20" -> MIPS.F20
    | "f21" -> MIPS.F21
    | "f22" -> MIPS.F22
    | "f23" -> MIPS.F23
    | "f24" -> MIPS.F24
    | "f25" -> MIPS.F25
    | "f26" -> MIPS.F26
    | "f27" -> MIPS.F27
    | "f28" -> MIPS.F28
    | "f29" -> MIPS.F29
    | "f30" -> MIPS.F30
    | "f31" -> MIPS.F31
    | "hi" -> MIPS.HI
    | "lo" -> MIPS.LO
    | "pc" -> MIPS.PC
    | "llbit" -> MIPS.LLBit
    | "fcsr" -> MIPS.FCSR
    | "fir" -> MIPS.FIR
    | _ -> Utils.impossible ()

  /// Get the register ID of a MIPS register.
  static member inline ID (reg: MIPS) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of a MIPS register.
  static member String (reg: MIPS, wordSize) =
    match wordSize with
    | WordSize.Bit32 ->
      match reg with
      | MIPS.R0  -> "r0"
      | MIPS.R1  -> "at"
      | MIPS.R2  -> "v0"
      | MIPS.R3  -> "v1"
      | MIPS.R4  -> "a0"
      | MIPS.R5  -> "a1"
      | MIPS.R6  -> "a2"
      | MIPS.R7  -> "a3"
      | MIPS.R8  -> "t0"
      | MIPS.R9  -> "t1"
      | MIPS.R10 -> "t2"
      | MIPS.R11 -> "t3"
      | MIPS.R12 -> "t4"
      | MIPS.R13 -> "t5"
      | MIPS.R14 -> "t6"
      | MIPS.R15 -> "t7"
      | MIPS.R16 -> "s0"
      | MIPS.R17 -> "s1"
      | MIPS.R18 -> "s2"
      | MIPS.R19 -> "s3"
      | MIPS.R20 -> "s4"
      | MIPS.R21 -> "s5"
      | MIPS.R22 -> "s6"
      | MIPS.R23 -> "s7"
      | MIPS.R24 -> "t8"
      | MIPS.R25 -> "t9"
      | MIPS.R26 -> "k0"
      | MIPS.R27 -> "k1"
      | MIPS.R28 -> "gp"
      | MIPS.R29 -> "sp"
      | MIPS.R30 -> "fp"
      | MIPS.R31 -> "ra"
      | MIPS.F0  -> "f0"
      | MIPS.F1  -> "f1"
      | MIPS.F2  -> "f2"
      | MIPS.F3  -> "f3"
      | MIPS.F4  -> "f4"
      | MIPS.F5  -> "f5"
      | MIPS.F6  -> "f6"
      | MIPS.F7  -> "f7"
      | MIPS.F8  -> "f8"
      | MIPS.F9  -> "f9"
      | MIPS.F10 -> "f10"
      | MIPS.F11 -> "f11"
      | MIPS.F12 -> "f12"
      | MIPS.F13 -> "f13"
      | MIPS.F14 -> "f14"
      | MIPS.F15 -> "f15"
      | MIPS.F16 -> "f16"
      | MIPS.F17 -> "f17"
      | MIPS.F18 -> "f18"
      | MIPS.F19 -> "f19"
      | MIPS.F20 -> "f20"
      | MIPS.F21 -> "f21"
      | MIPS.F22 -> "f22"
      | MIPS.F23 -> "f23"
      | MIPS.F24 -> "f24"
      | MIPS.F25 -> "f25"
      | MIPS.F26 -> "f26"
      | MIPS.F27 -> "f27"
      | MIPS.F28 -> "f28"
      | MIPS.F29 -> "f29"
      | MIPS.F30 -> "f30"
      | MIPS.F31 -> "f31"
      | MIPS.HI  -> "hi"
      | MIPS.LO  -> "lo"
      | MIPS.PC  -> "pc"
      | MIPS.LLBit -> "LLBit"
      | MIPS.FCSR -> "fcsr"
      | MIPS.FIR -> "fir"
      | _ -> Utils.impossible ()
    | WordSize.Bit64 ->
      match reg with
      | MIPS.R0  -> "r0"
      | MIPS.R1  -> "at"
      | MIPS.R2  -> "v0"
      | MIPS.R3  -> "v1"
      | MIPS.R4  -> "a0"
      | MIPS.R5  -> "a1"
      | MIPS.R6  -> "a2"
      | MIPS.R7  -> "a3"
      | MIPS.R8  -> "a4"
      | MIPS.R9  -> "a5"
      | MIPS.R10 -> "a6"
      | MIPS.R11 -> "a7"
      | MIPS.R12 -> "t0"
      | MIPS.R13 -> "t1"
      | MIPS.R14 -> "t2"
      | MIPS.R15 -> "t3"
      | MIPS.R16 -> "s0"
      | MIPS.R17 -> "s1"
      | MIPS.R18 -> "s2"
      | MIPS.R19 -> "s3"
      | MIPS.R20 -> "s4"
      | MIPS.R21 -> "s5"
      | MIPS.R22 -> "s6"
      | MIPS.R23 -> "s7"
      | MIPS.R24 -> "t8"
      | MIPS.R25 -> "t9"
      | MIPS.R26 -> "k0"
      | MIPS.R27 -> "k1"
      | MIPS.R28 -> "gp"
      | MIPS.R29 -> "sp"
      | MIPS.R30 -> "s8"
      | MIPS.R31 -> "ra"
      | MIPS.F0  -> "f0"
      | MIPS.F1  -> "f1"
      | MIPS.F2  -> "f2"
      | MIPS.F3  -> "f3"
      | MIPS.F4  -> "f4"
      | MIPS.F5  -> "f5"
      | MIPS.F6  -> "f6"
      | MIPS.F7  -> "f7"
      | MIPS.F8  -> "f8"
      | MIPS.F9  -> "f9"
      | MIPS.F10 -> "f10"
      | MIPS.F11 -> "f11"
      | MIPS.F12 -> "f12"
      | MIPS.F13 -> "f13"
      | MIPS.F14 -> "f14"
      | MIPS.F15 -> "f15"
      | MIPS.F16 -> "f16"
      | MIPS.F17 -> "f17"
      | MIPS.F18 -> "f18"
      | MIPS.F19 -> "f19"
      | MIPS.F20 -> "f20"
      | MIPS.F21 -> "f21"
      | MIPS.F22 -> "f22"
      | MIPS.F23 -> "f23"
      | MIPS.F24 -> "f24"
      | MIPS.F25 -> "f25"
      | MIPS.F26 -> "f26"
      | MIPS.F27 -> "f27"
      | MIPS.F28 -> "f28"
      | MIPS.F29 -> "f29"
      | MIPS.F30 -> "f30"
      | MIPS.F31 -> "f31"
      | MIPS.HI  -> "hi"
      | MIPS.LO  -> "lo"
      | MIPS.PC  -> "pc"
      | MIPS.LLBit -> "LLBit"
      | MIPS.FCSR -> "fcsr"
      | MIPS.FIR -> "fir"
      | _ -> Utils.impossible ()
    | _ -> Utils.impossible ()

/// <summary>
/// Registers for PA-RISC.<para/>
/// </summary>
type PARISC =
  | GR0 = 0x0
  | GR1 = 0x1
  | GR2 = 0x2
  | GR3 = 0x3
  | GR4 = 0x4
  | GR5 = 0x5
  | GR6 = 0x6
  | GR7 = 0x7
  | GR8 = 0x8
  | GR9 = 0x9
  | GR10 = 0xA
  | GR11 = 0xB
  | GR12 = 0xC
  | GR13 = 0xD
  | GR14 = 0xE
  | GR15 = 0xF
  | GR16 = 0x10
  | GR17 = 0x11
  | GR18 = 0x12
  | GR19 = 0x13
  | GR20 = 0x14
  | GR21 = 0x15
  | GR22 = 0x16
  | GR23 = 0x17
  | GR24 = 0x18
  | GR25 = 0x19
  | GR26 = 0x1A
  | GR27 = 0x1B
  | GR28 = 0x1C
  | GR29 = 0x1D
  | GR30 = 0x1E
  | GR31 = 0x1F
  | SR0 = 0x20
  | SR1 = 0x21
  | SR2 = 0x22
  | SR3 = 0x23
  | SR4 = 0x24
  | SR5 = 0x25
  | SR6 = 0x26
  | SR7 = 0x27
  | IAOQ_Front = 0x28
  | IAOQ_Back = 0x29
  | IASQ_Front = 0x2A
  | IASQ_Back = 0x2B
  | PSW = 0x2C
  | CR0 = 0x2D
  | CR1 = 0x2E
  | CR2 = 0x2F
  | CR3 = 0x30
  | CR4 = 0x31
  | CR5 = 0x32
  | CR6 = 0x33
  | CR7 = 0x34
  | CR8 = 0x35
  | CR9 = 0x36
  | CR10 = 0x37
  | CR11 = 0x38
  | CR12 = 0x39
  | CR13 = 0x3A
  | CR14 = 0x3B
  | CR15 = 0x3C
  | CR16 = 0x3D
  | CR17 = 0x3E
  | CR18 = 0x3F
  | CR19 = 0x40
  | CR20 = 0x41
  | CR21 = 0x42
  | CR22 = 0x43
  | CR23 = 0x44
  | CR24 = 0x45
  | CR25 = 0x46
  | CR26 = 0x47
  | CR27 = 0x48
  | CR28 = 0x49
  | CR29 = 0x4A
  | CR30 = 0x4B
  | CR31 = 0x4C
  | FPR0 = 0x4D
  | FPR1 = 0x4E
  | FPR2 = 0x4F
  | FPR3 = 0x50
  | FPR4 = 0x51
  | FPR5 = 0x52
  | FPR6 = 0x53
  | FPR7 = 0x54
  | FPR8 = 0x55
  | FPR9 = 0x56
  | FPR10 = 0x57
  | FPR11 = 0x58
  | FPR12 = 0x59
  | FPR13 = 0x5A
  | FPR14 = 0x5B
  | FPR15 = 0x5C
  | FPR16 = 0x5D
  | FPR17 = 0x5E
  | FPR18 = 0x5F
  | FPR19 = 0x60
  | FPR20 = 0x61
  | FPR21 = 0x62
  | FPR22 = 0x63
  | FPR23 = 0x64
  | FPR24 = 0x65
  | FPR25 = 0x66
  | FPR26 = 0x67
  | FPR27 = 0x68
  | FPR28 = 0x69
  | FPR29 = 0x6A
  | FPR30 = 0x6B
  | FPR31 = 0x6C

/// Helper module for PARISC registers.
type PARISCRegister =
  /// Get the PARISC register from a register ID.
  static member inline Get (rid: RegisterID): PARISC =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the PARISC register from a string representation.
  static member Get (str: string): PARISC =
    match str.ToLowerInvariant () with
    | "flags" -> PARISC.GR0
    | "r1" -> PARISC.GR1
    | "rp" -> PARISC.GR2
    | "r3" -> PARISC.GR3
    | "r4" -> PARISC.GR4
    | "r5" -> PARISC.GR5
    | "r6" -> PARISC.GR6
    | "r7" -> PARISC.GR7
    | "r8" -> PARISC.GR8
    | "r9" -> PARISC.GR9
    | "r10" -> PARISC.GR10
    | "r11" -> PARISC.GR11
    | "r12" -> PARISC.GR12
    | "r13" -> PARISC.GR13
    | "r14" -> PARISC.GR14
    | "r15" -> PARISC.GR15
    | "r16" -> PARISC.GR16
    | "r17" -> PARISC.GR17
    | "r18" -> PARISC.GR18
    | "r19" -> PARISC.GR19
    | "r20" -> PARISC.GR20
    | "r21" -> PARISC.GR21
    | "r22" -> PARISC.GR22
    | "r23" -> PARISC.GR23
    | "r24" -> PARISC.GR24
    | "r25" -> PARISC.GR25
    | "r26" -> PARISC.GR26
    | "dp" -> PARISC.GR27
    | "ret0" -> PARISC.GR28
    | "ret1" -> PARISC.GR29
    | "sp" -> PARISC.GR30
    | "r31" -> PARISC.GR31
    | "sr0" -> PARISC.SR0
    | "sr1" -> PARISC.SR1
    | "sr2" -> PARISC.SR2
    | "sr3" -> PARISC.SR3
    | "sr4" -> PARISC.SR4
    | "sr5" -> PARISC.SR5
    | "sr6" -> PARISC.SR6
    | "sr7" -> PARISC.SR7
    | "iaoq_front" -> PARISC.IAOQ_Front
    | "iaoq_back" -> PARISC.IAOQ_Back
    | "iasq_front" -> PARISC.IASQ_Front
    | "iasq_back" -> PARISC.IASQ_Back
    | "psw" -> PARISC.PSW
    | "rctr" -> PARISC.CR0
    | "cr1" -> PARISC.CR1
    | "cr2" -> PARISC.CR2
    | "cr3" -> PARISC.CR3
    | "cr4" -> PARISC.CR4
    | "cr5" -> PARISC.CR5
    | "cr6" -> PARISC.CR6
    | "cr7" -> PARISC.CR7
    | "pidr1" -> PARISC.CR8
    | "pidr2" -> PARISC.CR9
    | "ccr" -> PARISC.CR10
    | "sar" -> PARISC.CR11
    | "pidr3" -> PARISC.CR12
    | "pidr4" -> PARISC.CR13
    | "iva" -> PARISC.CR14
    | "eiem" -> PARISC.CR15
    | "itmr" -> PARISC.CR16
    | "pcsq" -> PARISC.CR17
    | "pcoq" -> PARISC.CR18
    | "iir" -> PARISC.CR19
    | "isr" -> PARISC.CR20
    | "ior" -> PARISC.CR21
    | "ipsw" -> PARISC.CR22
    | "eirr" -> PARISC.CR23
    | "tr0" -> PARISC.CR24
    | "tr1" -> PARISC.CR25
    | "tr2" -> PARISC.CR26
    | "tr3" -> PARISC.CR27
    | "tr4" -> PARISC.CR28
    | "tr5" -> PARISC.CR29
    | "tr6" -> PARISC.CR30
    | "tr7" -> PARISC.CR31
    | "fpsr" -> PARISC.FPR0
    | "fpe2" -> PARISC.FPR1
    | "fpe4" -> PARISC.FPR2
    | "fpe6" -> PARISC.FPR3
    | "fr4" -> PARISC.FPR4
    | "fr5" -> PARISC.FPR5
    | "fr6" -> PARISC.FPR6
    | "fr7" -> PARISC.FPR7
    | "fr8" -> PARISC.FPR8
    | "fr9" -> PARISC.FPR9
    | "fr10" -> PARISC.FPR10
    | "fr11" -> PARISC.FPR11
    | "fr12" -> PARISC.FPR12
    | "fr13" -> PARISC.FPR13
    | "fr14" -> PARISC.FPR14
    | "fr15" -> PARISC.FPR15
    | "fr16" -> PARISC.FPR16
    | "fr17" -> PARISC.FPR17
    | "fr18" -> PARISC.FPR18
    | "fr19" -> PARISC.FPR19
    | "fr20" -> PARISC.FPR20
    | "fr21" -> PARISC.FPR21
    | "fr22" -> PARISC.FPR22
    | "fr23" -> PARISC.FPR23
    | "fr24" -> PARISC.FPR24
    | "fr25" -> PARISC.FPR25
    | "fr26" -> PARISC.FPR26
    | "fr27" -> PARISC.FPR27
    | "fr28" -> PARISC.FPR28
    | "fr29" -> PARISC.FPR29
    | "fr30" -> PARISC.FPR30
    | "fr31" -> PARISC.FPR31
    | _ -> Utils.impossible ()

  /// Get the register ID of a PARISC register.
  static member inline ID (reg: PARISC) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of a PARISC register.
  static member String (reg: PARISC) =
    match reg with
    | PARISC.GR0 -> "flags"
    | PARISC.GR1 -> "r1"
    | PARISC.GR2 -> "rp"
    | PARISC.GR3 -> "r3"
    | PARISC.GR4 -> "r4"
    | PARISC.GR5 -> "r5"
    | PARISC.GR6 -> "r6"
    | PARISC.GR7 -> "r7"
    | PARISC.GR8 -> "r8"
    | PARISC.GR9 -> "r9"
    | PARISC.GR10 -> "r10"
    | PARISC.GR11 -> "r11"
    | PARISC.GR12 -> "r12"
    | PARISC.GR13 -> "r13"
    | PARISC.GR14 -> "r14"
    | PARISC.GR15 -> "r15"
    | PARISC.GR16 -> "r16"
    | PARISC.GR17 -> "r17"
    | PARISC.GR18 -> "r18"
    | PARISC.GR19 -> "r19"
    | PARISC.GR20 -> "r20"
    | PARISC.GR21 -> "r21"
    | PARISC.GR22 -> "r22"
    | PARISC.GR23 -> "r23"
    | PARISC.GR24 -> "r24"
    | PARISC.GR25 -> "r25"
    | PARISC.GR26 -> "r26"
    | PARISC.GR27 -> "dp"
    | PARISC.GR28 -> "ret0"
    | PARISC.GR29 -> "ret1"
    | PARISC.GR30 -> "sp"
    | PARISC.GR31 -> "r31"
    | PARISC.SR0 -> "sr0"
    | PARISC.SR1 -> "sr1"
    | PARISC.SR2 -> "sr2"
    | PARISC.SR3 -> "sr3"
    | PARISC.SR4 -> "sr4"
    | PARISC.SR5 -> "sr5"
    | PARISC.SR6 -> "sr6"
    | PARISC.SR7 -> "sr7"
    | PARISC.IAOQ_Front -> "iaoq_front"
    | PARISC.IAOQ_Back -> "iaoq_back"
    | PARISC.IASQ_Front -> "iasq_front"
    | PARISC.IASQ_Back -> "iasq_back"
    | PARISC.PSW -> "psw"
    | PARISC.CR0 -> "rctr"
    | PARISC.CR1 -> "cr1"
    | PARISC.CR2 -> "cr2"
    | PARISC.CR3 -> "cr3"
    | PARISC.CR4 -> "cr4"
    | PARISC.CR5 -> "cr5"
    | PARISC.CR6 -> "cr6"
    | PARISC.CR7 -> "cr7"
    | PARISC.CR8 -> "pidr1"
    | PARISC.CR9 -> "pidr2"
    | PARISC.CR10 -> "ccr"
    | PARISC.CR11 -> "sar"
    | PARISC.CR12 -> "pidr3"
    | PARISC.CR13 -> "pidr4"
    | PARISC.CR14 -> "iva"
    | PARISC.CR15 -> "eiem"
    | PARISC.CR16 -> "itmr"
    | PARISC.CR17 -> "pcsq"
    | PARISC.CR18 -> "pcoq"
    | PARISC.CR19 -> "iir"
    | PARISC.CR20 -> "isr"
    | PARISC.CR21 -> "ior"
    | PARISC.CR22 -> "ipsw"
    | PARISC.CR23 -> "eirr"
    | PARISC.CR24 -> "tr0"
    | PARISC.CR25 -> "tr1"
    | PARISC.CR26 -> "tr2"
    | PARISC.CR27 -> "tr3"
    | PARISC.CR28 -> "tr4"
    | PARISC.CR29 -> "tr5"
    | PARISC.CR30 -> "tr6"
    | PARISC.CR31 -> "tr7"
    | PARISC.FPR0 -> "fpsr"
    | PARISC.FPR1 -> "fpe2"
    | PARISC.FPR2 -> "fpe4"
    | PARISC.FPR3 -> "fpe6"
    | PARISC.FPR4 -> "fr4"
    | PARISC.FPR5 -> "fr5"
    | PARISC.FPR6 -> "fr6"
    | PARISC.FPR7 -> "fr7"
    | PARISC.FPR8 -> "fr8"
    | PARISC.FPR9 -> "fr9"
    | PARISC.FPR10 -> "fr10"
    | PARISC.FPR11 -> "fr11"
    | PARISC.FPR12 -> "fr12"
    | PARISC.FPR13 -> "fr13"
    | PARISC.FPR14 -> "fr14"
    | PARISC.FPR15 -> "fr15"
    | PARISC.FPR16 -> "fr16"
    | PARISC.FPR17 -> "fr17"
    | PARISC.FPR18 -> "fr18"
    | PARISC.FPR19 -> "fr19"
    | PARISC.FPR20 -> "fr20"
    | PARISC.FPR21 -> "fr21"
    | PARISC.FPR22 -> "fr22"
    | PARISC.FPR23 -> "fr23"
    | PARISC.FPR24 -> "fr24"
    | PARISC.FPR25 -> "fr25"
    | PARISC.FPR26 -> "fr26"
    | PARISC.FPR27 -> "fr27"
    | PARISC.FPR28 -> "fr28"
    | PARISC.FPR29 -> "fr29"
    | PARISC.FPR30 -> "fr30"
    | PARISC.FPR31 -> "fr31"
    | _ -> Utils.impossible ()

/// <summary>
/// Registers for PPC32.<para/>
/// </summary>
type PPC32 =
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
  | R16 = 0x10
  | R17 = 0x11
  | R18 = 0x12
  | R19 = 0x13
  | R20 = 0x14
  | R21 = 0x15
  | R22 = 0x16
  | R23 = 0x17
  | R24 = 0x18
  | R25 = 0x19
  | R26 = 0x1A
  | R27 = 0x1B
  | R28 = 0x1C
  | R29 = 0x1D
  | R30 = 0x1E
  | R31 = 0x1F
  | F0 = 0x20
  | F1 = 0x21
  | F2 = 0x22
  | F3 = 0x23
  | F4 = 0x24
  | F5 = 0x25
  | F6 = 0x26
  | F7 = 0x27
  | F8 = 0x28
  | F9 = 0x29
  | F10 = 0x2A
  | F11 = 0x2B
  | F12 = 0x2C
  | F13 = 0x2D
  | F14 = 0x2E
  | F15 = 0x2F
  | F16 = 0x30
  | F17 = 0x31
  | F18 = 0x32
  | F19 = 0x33
  | F20 = 0x34
  | F21 = 0x35
  | F22 = 0x36
  | F23 = 0x37
  | F24 = 0x38
  | F25 = 0x39
  | F26 = 0x3A
  | F27 = 0x3B
  | F28 = 0x3C
  | F29 = 0x3D
  | F30 = 0x3E
  | F31 = 0x3F
  /// CR0 - CR7 is 4bit chunk of CR.
  | CR0 = 0x40
  | CR1 = 0x41
  | CR2 = 0x42
  | CR3 = 0x43
  | CR4 = 0x44
  | CR5 = 0x45
  | CR6 = 0x46
  | CR7 = 0x47
  /// CR0_0 is the 1st 1-bit chunk of CR0.
  | CR0_0 = 0x48
  /// CR0_1 is the 2nd 1-bit chunk of CR0.
  | CR0_1 = 0x49
  /// CR0_2 is the 3rd 1-bit chunk of CR0.
  | CR0_2 = 0x4A
  /// CR0_3 is the 4th 1-bit chunk of CR0.
  | CR0_3 = 0x4B
  /// CR1_0 is the 1st 1-bit chunk of CR1.
  | CR1_0 = 0x4C
  /// CR1_1 is the 2nd 1-bit chunk of CR1.
  | CR1_1 = 0x4D
  /// CR1_2 is the 3rd 1-bit chunk of CR1.
  | CR1_2 = 0x4E
  /// CR1_3 is the 4th 1-bit chunk of CR1.
  | CR1_3 = 0x4F
  /// CR2_0 is the 1st 1-bit chunk of CR2.
  | CR2_0 = 0x50
  /// CR2_1 is the 2nd 1-bit chunk of CR2.
  | CR2_1 = 0x51
  /// CR2_2 is the 3rd 1-bit chunk of CR2.
  | CR2_2 = 0x52
  /// CR2_3 is the 4th 1-bit chunk of CR2.
  | CR2_3 = 0x53
  /// CR3_0 is the 1st 1-bit chunk of CR3.
  | CR3_0 = 0x54
  /// CR3_1 is the 2nd 1-bit chunk of CR3.
  | CR3_1 = 0x55
  /// CR3_2 is the 3rd 1-bit chunk of CR3.
  | CR3_2 = 0x56
  /// CR3_3 is the 4th 1-bit chunk of CR3.
  | CR3_3 = 0x57
  /// CR4_0 is the 1st 1-bit chunk of CR4.
  | CR4_0 = 0x58
  /// CR4_1 is the 2nd 1-bit chunk of CR4.
  | CR4_1 = 0x59
  /// CR4_2 is the 3rd 1-bit chunk of CR4.
  | CR4_2 = 0x5A
  /// CR4_3 is the 4th 1-bit chunk of CR4.
  | CR4_3 = 0x5B
  /// CR5_0 is the 1st 1-bit chunk of CR5.
  | CR5_0 = 0x5C
  /// CR5_1 is the 2nd 1-bit chunk of CR5.
  | CR5_1 = 0x5D
  /// CR5_2 is the 3rd 1-bit chunk of CR5.
  | CR5_2 = 0x5E
  /// CR5_3 is the 4th 1-bit chunk of CR5.
  | CR5_3 = 0x5F
  /// CR6_0 is the 1st 1-bit chunk of CR6.
  | CR6_0 = 0x60
  /// CR6_1 is the 2nd 1-bit chunk of CR6.
  | CR6_1 = 0x61
  /// CR6_2 is the 3rd 1-bit chunk of CR6.
  | CR6_2 = 0x62
  /// CR6_3 is the 4th 1-bit chunk of CR6.
  | CR6_3 = 0x63
  /// CR7_0 is the 1st 1-bit chunk of CR7.
  | CR7_0 = 0x64
  /// CR7_1 is the 2nd 1-bit chunk of CR7.
  | CR7_1 = 0x65
  /// CR7_2 is the 3rd 1-bit chunk of CR7.
  | CR7_2 = 0x66
  /// CR7_3 is the 4th 1-bit chunk of CR7.
  | CR7_3 = 0x67
  /// XER Register.
  | XER = 0x70
  /// LR Register.
  | LR = 0x71
  /// Count Register.
  | CTR = 0x72
  /// FPSCR Register
  | FPSCR = 0x73
  /// Processor Version Register.
  | PVR = 0x74
  /// Pseudo register for Reserve.
  | RES = 0x75

/// Helper module for PPC32 registers.
type PPC32Register =
  /// Get the PPC32 register from a register ID.
  static member inline Get (rid: RegisterID): PPC32 =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the PPC32 register from a string representation.
  static member Get (str: string): PPC32 =
    match str.ToLowerInvariant () with
    | "r0" -> PPC32.R0
    | "r1" -> PPC32.R1
    | "r2" -> PPC32.R2
    | "r3" -> PPC32.R3
    | "r4" -> PPC32.R4
    | "r5" -> PPC32.R5
    | "r6" -> PPC32.R6
    | "r7" -> PPC32.R7
    | "r8" -> PPC32.R8
    | "r9" -> PPC32.R9
    | "r10" -> PPC32.R10
    | "r11" -> PPC32.R11
    | "r12" -> PPC32.R12
    | "r13" -> PPC32.R13
    | "r14" -> PPC32.R14
    | "r15" -> PPC32.R15
    | "r16" -> PPC32.R16
    | "r17" -> PPC32.R17
    | "r18" -> PPC32.R18
    | "r19" -> PPC32.R19
    | "r20" -> PPC32.R20
    | "r21" -> PPC32.R21
    | "r22" -> PPC32.R22
    | "r23" -> PPC32.R23
    | "r24" -> PPC32.R24
    | "r25" -> PPC32.R25
    | "r26" -> PPC32.R26
    | "r27" -> PPC32.R27
    | "r28" -> PPC32.R28
    | "r29" -> PPC32.R29
    | "r30" -> PPC32.R30
    | "r31" -> PPC32.R31
    | "f0" -> PPC32.F0
    | "f1" -> PPC32.F1
    | "f2" -> PPC32.F2
    | "f3" -> PPC32.F3
    | "f4" -> PPC32.F4
    | "f5" -> PPC32.F5
    | "f6" -> PPC32.F6
    | "f7" -> PPC32.F7
    | "f8" -> PPC32.F8
    | "f9" -> PPC32.F9
    | "f10" -> PPC32.F10
    | "f11" -> PPC32.F11
    | "f12" -> PPC32.F12
    | "f13" -> PPC32.F13
    | "f14" -> PPC32.F14
    | "f15" -> PPC32.F15
    | "f16" -> PPC32.F16
    | "f17" -> PPC32.F17
    | "f18" -> PPC32.F18
    | "f19" -> PPC32.F19
    | "f20" -> PPC32.F20
    | "f21" -> PPC32.F21
    | "f22" -> PPC32.F22
    | "f23" -> PPC32.F23
    | "f24" -> PPC32.F24
    | "f25" -> PPC32.F25
    | "f26" -> PPC32.F26
    | "f27" -> PPC32.F27
    | "f28" -> PPC32.F28
    | "f29" -> PPC32.F29
    | "f30" -> PPC32.F30
    | "f31" -> PPC32.F31
    | "cr0" -> PPC32.CR0
    | "cr1" -> PPC32.CR1
    | "cr2" -> PPC32.CR2
    | "cr3" -> PPC32.CR3
    | "cr4" -> PPC32.CR4
    | "cr5" -> PPC32.CR5
    | "cr6" -> PPC32.CR6
    | "cr7" -> PPC32.CR7
    | "cr0_0" -> PPC32.CR0_0
    | "cr0_1" -> PPC32.CR0_1
    | "cr0_2" -> PPC32.CR0_2
    | "cr0_3" -> PPC32.CR0_3
    | "cr1_0" -> PPC32.CR1_0
    | "cr1_1" -> PPC32.CR1_1
    | "cr1_2" -> PPC32.CR1_2
    | "cr1_3" -> PPC32.CR1_3
    | "cr2_0" -> PPC32.CR2_0
    | "cr2_1" -> PPC32.CR2_1
    | "cr2_2" -> PPC32.CR2_2
    | "cr2_3" -> PPC32.CR2_3
    | "cr3_0" -> PPC32.CR3_0
    | "cr3_1" -> PPC32.CR3_1
    | "cr3_2" -> PPC32.CR3_2
    | "cr3_3" -> PPC32.CR3_3
    | "cr4_0" -> PPC32.CR4_0
    | "cr4_1" -> PPC32.CR4_1
    | "cr4_2" -> PPC32.CR4_2
    | "cr4_3" -> PPC32.CR4_3
    | "cr5_0" -> PPC32.CR5_0
    | "cr5_1" -> PPC32.CR5_1
    | "cr5_2" -> PPC32.CR5_2
    | "cr5_3" -> PPC32.CR5_3
    | "cr6_0" -> PPC32.CR6_0
    | "cr6_1" -> PPC32.CR6_1
    | "cr6_2" -> PPC32.CR6_2
    | "cr6_3" -> PPC32.CR6_3
    | "cr7_0" -> PPC32.CR7_0
    | "cr7_1" -> PPC32.CR7_1
    | "cr7_2" -> PPC32.CR7_2
    | "cr7_3" -> PPC32.CR7_3
    | "res" -> PPC32.RES
    | _ -> Utils.impossible ()

  /// Get the register ID of a PPC32 register.
  static member inline ID (reg: PPC32) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of a PPC32 register.
  static member String (reg: PPC32) =
    match reg with
    | PPC32.R0 -> "r0"
    | PPC32.R1 -> "r1"
    | PPC32.R2 -> "r2"
    | PPC32.R3 -> "r3"
    | PPC32.R4 -> "r4"
    | PPC32.R5 -> "r5"
    | PPC32.R6 -> "r6"
    | PPC32.R7 -> "r7"
    | PPC32.R8 -> "r8"
    | PPC32.R9 -> "r9"
    | PPC32.R10 -> "r10"
    | PPC32.R11 -> "r11"
    | PPC32.R12 -> "r12"
    | PPC32.R13 -> "r13"
    | PPC32.R14 -> "r14"
    | PPC32.R15 -> "r15"
    | PPC32.R16 -> "r16"
    | PPC32.R17 -> "r17"
    | PPC32.R18 -> "r18"
    | PPC32.R19 -> "r19"
    | PPC32.R20 -> "r20"
    | PPC32.R21 -> "r21"
    | PPC32.R22 -> "r22"
    | PPC32.R23 -> "r23"
    | PPC32.R24 -> "r24"
    | PPC32.R25 -> "r25"
    | PPC32.R26 -> "r26"
    | PPC32.R27 -> "r27"
    | PPC32.R28 -> "r28"
    | PPC32.R29 -> "r29"
    | PPC32.R30 -> "r30"
    | PPC32.R31 -> "r31"
    | PPC32.F0 -> "f0"
    | PPC32.F1 -> "f1"
    | PPC32.F2 -> "f2"
    | PPC32.F3 -> "f3"
    | PPC32.F4 -> "f4"
    | PPC32.F5 -> "f5"
    | PPC32.F6 -> "f6"
    | PPC32.F7 -> "f7"
    | PPC32.F8 -> "f8"
    | PPC32.F9 -> "f9"
    | PPC32.F10 -> "f10"
    | PPC32.F11 -> "f11"
    | PPC32.F12 -> "f12"
    | PPC32.F13 -> "f13"
    | PPC32.F14 -> "f14"
    | PPC32.F15 -> "f15"
    | PPC32.F16 -> "f16"
    | PPC32.F17 -> "f17"
    | PPC32.F18 -> "f18"
    | PPC32.F19 -> "f19"
    | PPC32.F20 -> "f20"
    | PPC32.F21 -> "f21"
    | PPC32.F22 -> "f22"
    | PPC32.F23 -> "f23"
    | PPC32.F24 -> "f24"
    | PPC32.F25 -> "f25"
    | PPC32.F26 -> "f26"
    | PPC32.F27 -> "f27"
    | PPC32.F28 -> "f28"
    | PPC32.F29 -> "f29"
    | PPC32.F30 -> "f30"
    | PPC32.F31 -> "f31"
    | PPC32.CR0 -> "cr0"
    | PPC32.CR1 -> "cr1"
    | PPC32.CR2 -> "cr2"
    | PPC32.CR3 -> "cr3"
    | PPC32.CR4 -> "cr4"
    | PPC32.CR5 -> "cr5"
    | PPC32.CR6 -> "cr6"
    | PPC32.CR7 -> "cr7"
    | PPC32.CR0_0 -> "cr0_0"
    | PPC32.CR0_1 -> "cr0_1"
    | PPC32.CR0_2 -> "cr0_2"
    | PPC32.CR0_3 -> "cr0_3"
    | PPC32.CR1_0 -> "cr1_0"
    | PPC32.CR1_1 -> "cr1_1"
    | PPC32.CR1_2 -> "cr1_2"
    | PPC32.CR1_3 -> "cr1_3"
    | PPC32.CR2_0 -> "cr2_0"
    | PPC32.CR2_1 -> "cr2_1"
    | PPC32.CR2_2 -> "cr2_2"
    | PPC32.CR2_3 -> "cr2_3"
    | PPC32.CR3_0 -> "cr3_0"
    | PPC32.CR3_1 -> "cr3_1"
    | PPC32.CR3_2 -> "cr3_2"
    | PPC32.CR3_3 -> "cr3_3"
    | PPC32.CR4_0 -> "cr4_0"
    | PPC32.CR4_1 -> "cr4_1"
    | PPC32.CR4_2 -> "cr4_2"
    | PPC32.CR4_3 -> "cr4_3"
    | PPC32.CR5_0 -> "cr5_0"
    | PPC32.CR5_1 -> "cr5_1"
    | PPC32.CR5_2 -> "cr5_2"
    | PPC32.CR5_3 -> "cr5_3"
    | PPC32.CR6_0 -> "cr6_0"
    | PPC32.CR6_1 -> "cr6_1"
    | PPC32.CR6_2 -> "cr6_2"
    | PPC32.CR6_3 -> "cr6_3"
    | PPC32.CR7_0 -> "cr7_0"
    | PPC32.CR7_1 -> "cr7_1"
    | PPC32.CR7_2 -> "cr7_2"
    | PPC32.CR7_3 -> "cr7_3"
    | PPC32.RES -> "res"
    | _ -> Utils.impossible ()

/// <summary>
/// Registers for RISC-V.<para/>
/// </summary>
type RISCV64 =
  /// zero - Hard-wired zero.
  | X0 = 0x0
  /// ra - Return address.
  | X1 = 0x1
  /// sp - Stack pointer.
  | X2 = 0x2
  /// gp - Global pointer.
  | X3 = 0x3
  /// tp - Thread pointer.
  | X4 = 0x4
  /// t0 - Temporary/alternate link register.
  | X5 = 0x5
  /// t1 - Temporary register.
  | X6 = 0x6
  /// t2 - Temporary register.
  | X7 = 0x7
  /// s0 or fp - Saved register/frame pointer.
  | X8 = 0x8
  /// s1 - Saved register.
  | X9 = 0x9
  /// a0 - Function argument/return value.
  | X10 = 0xA
  /// a1 - Function argument/return value.
  | X11 = 0xB
  /// a2 - Function argument.
  | X12 = 0xC
  /// a3 - Function argument.
  | X13 = 0xD
  /// a4 - Function argument.
  | X14 = 0xE
  /// a5 - Function argument.
  | X15 = 0xF
  /// a6 - Function argument.
  | X16 = 0x10
  /// a7 - Function argument.
  | X17 = 0x11
  /// s2 - Saved register.
  | X18 = 0x12
  /// s3 - Saved register.
  | X19 = 0x13
  /// s4 - Saved register.
  | X20 = 0x14
  /// s5 - Saved register.
  | X21 = 0x15
  /// s6 - Saved register.
  | X22 = 0x16
  /// s7 - Saved register.
  | X23 = 0x17
  /// s8 - Saved register.
  | X24 = 0x18
  /// s9 - Saved register.
  | X25 = 0x19
  /// s10 - Saved register.
  | X26 = 0x1A
  /// s11 - Saved registers
  | X27 = 0x1B
  /// t3 - Temporary register.
  | X28 = 0x1C
  /// t4 - Temporary register.
  | X29 = 0x1D
  /// t5 - Temporary register.
  | X30 = 0x1E
  /// t6 - Temporary register.
  | X31 = 0x1F
  /// ft0 - FP temporary register.
  | F0 = 0x20
  /// ft1 - FP temporary register.
  | F1 = 0x21
  /// ft2 - FP temporary register.
  | F2 = 0x22
  /// ft3 - FP temporary register.
  | F3 = 0x23
  /// ft4 - FP temporary register.
  | F4 = 0x24
  /// ft5 - FP temporary register.
  | F5 = 0x25
  /// ft6 - FP temporary register.
  | F6 = 0x26
  /// ft7 - FP temporary register.
  | F7 = 0x27
  /// fs0 - FP saved register.
  | F8 = 0x28
  /// fs1 - FP saved register.
  | F9 = 0x29
  /// fa0 - FP argument/return value.
  | F10 = 0x2A
  /// fa1 - FP argument/return value.
  | F11 = 0x2B
  /// fa2 - FP argument.
  | F12 = 0x2C
  /// fa3 - FP argument.
  | F13 = 0x2D
  /// fa4 - FP argument.
  | F14 = 0x2E
  /// fa5 - FP argument.
  | F15 = 0x2F
  /// fa6 - FP argument.
  | F16 = 0x30
  /// fa7 - FP argument.
  | F17 = 0x31
  /// fs2 - FP saved register.
  | F18 = 0x32
  /// fs3 - FP saved register.
  | F19 = 0x33
  /// fs4 - FP saved register.
  | F20 = 0x34
  /// fs5 - FP saved register.
  | F21 = 0x35
  /// fs6 - FP saved register.
  | F22 = 0x36
  /// fs7 - FP saved register.
  | F23 = 0x37
  /// fs8 - FP saved register.
  | F24 = 0x38
  /// fs9 - FP saved register.
  | F25 = 0x39
  /// fs10 - FP saved register.
  | F26 = 0x3A
  /// fs11 - FP saved register.
  | F27 = 0x3B
  /// ft8 - FP temporary register.
  | F28 = 0x3C
  /// ft9 - FP temporary register.
  | F29 = 0x3D
  /// ft10 - FP temporary register.
  | F30 = 0x3E
  /// ft11 - FP temporary register.
  | F31 = 0x3F
  /// Program Counter.
  | PC = 0x40
  /// Floating point control and status register.
  | FCSR = 0x41
  /// Floating-Point Accrued Exceptions.
  | FFLAGS = 0x42
  | CSR0768 = 0x43
  | CSR0769 = 0x44
  | CSR0770 = 0x45
  | CSR0771 = 0x46
  | CSR0772 = 0x47
  | CSR0773 = 0x48
  | CSR0784 = 0x49
  | CSR0832 = 0x4A
  | CSR0833 = 0x4B
  | CSR0834 = 0x4C
  | CSR0835 = 0x4D
  | CSR0836 = 0x4E
  | CSR0842 = 0x4F
  | CSR0843 = 0x50
  | CSR3857 = 0x51
  | CSR3858 = 0x52
  | CSR3859 = 0x53
  | CSR3860 = 0x54
  | CSR0928 = 0x55
  | CSR0930 = 0x56
  | CSR0932 = 0x57
  | CSR0934 = 0x58
  | CSR0936 = 0x59
  | CSR0938 = 0x5A
  | CSR0940 = 0x5B
  | CSR0942 = 0x5C
  | CSR0944 = 0x5D
  | CSR0945 = 0x5E
  | CSR0946 = 0x5F
  | CSR0947 = 0x60
  | CSR0948 = 0x61
  | CSR0949 = 0x62
  | CSR0950 = 0x63
  | CSR0951 = 0x64
  | CSR0952 = 0x65
  | CSR0953 = 0x66
  | CSR0954 = 0x67
  | CSR0955 = 0x68
  | CSR0956 = 0x69
  | CSR0957 = 0x6A
  | CSR0958 = 0x6B
  | CSR0959 = 0x6C
  | CSR0960 = 0x6D
  | CSR0961 = 0x6E
  | CSR0962 = 0x6F
  | CSR0963 = 0x70
  | CSR0964 = 0x71
  | CSR0965 = 0x72
  | CSR0966 = 0x73
  | CSR0967 = 0x74
  | CSR0968 = 0x75
  | CSR0969 = 0x76
  | CSR0970 = 0x77
  | CSR0971 = 0x78
  | CSR0972 = 0x79
  | CSR0973 = 0x7A
  | CSR0974 = 0x7B
  | CSR0975 = 0x7C
  | CSR0976 = 0x7D
  | CSR0977 = 0x7E
  | CSR0978 = 0x7F
  | CSR0979 = 0x80
  | CSR0980 = 0x81
  | CSR0981 = 0x82
  | CSR0982 = 0x83
  | CSR0983 = 0x84
  | CSR0984 = 0x85
  | CSR0985 = 0x86
  | CSR0986 = 0x87
  | CSR0987 = 0x88
  | CSR0988 = 0x89
  | CSR0989 = 0x8A
  | CSR0990 = 0x8B
  | CSR0991 = 0x8C
  | CSR0992 = 0x8D
  | CSR0993 = 0x8E
  | CSR0994 = 0x8F
  | CSR0995 = 0x90
  | CSR0996 = 0x91
  | CSR0997 = 0x92
  | CSR0998 = 0x93
  | CSR0999 = 0x94
  | CSR1000 = 0x95
  | CSR1001 = 0x96
  | CSR1002 = 0x97
  | CSR1003 = 0x98
  | CSR1004 = 0x99
  | CSR1005 = 0x9A
  | CSR1006 = 0x9B
  | CSR1007 = 0x9C
  | CSR2816 = 0x9D
  | CSR2818 = 0x9E
  | CSR2819 = 0x9F
  | CSR2820 = 0xA0
  | CSR2821 = 0xA1
  | CSR2822 = 0xA2
  | CSR2823 = 0x103
  | CSR2824 = 0x104
  | CSR2825 = 0x105
  | CSR2826 = 0x106
  | CSR2827 = 0x107
  | CSR2828 = 0x108
  | CSR2829 = 0x109
  | CSR2830 = 0x10A
  | CSR2831 = 0x10B
  | CSR2832 = 0x10C
  | CSR2833 = 0x10D
  | CSR2834 = 0x10E
  | CSR2835 = 0x10F
  | CSR2836 = 0x110
  | CSR2837 = 0x111
  | CSR2838 = 0x112
  | CSR2839 = 0x113
  | CSR2840 = 0x114
  | CSR2841 = 0x115
  | CSR2842 = 0x116
  | CSR2843 = 0x117
  | CSR2844 = 0x118
  | CSR2845 = 0x119
  | CSR2846 = 0x11A
  | CSR2847 = 0x11B
  | CSR0800 = 0x11C
  | CSR0803 = 0x11D
  | CSR0804 = 0x11E
  | CSR0805 = 0x11F
  | CSR0806 = 0x120
  | CSR0807 = 0x121
  | CSR0808 = 0x122
  | CSR0809 = 0x123
  | CSR0810 = 0x124
  | CSR0811 = 0x125
  | CSR0812 = 0x126
  | CSR0813 = 0x127
  | CSR0814 = 0x128
  | CSR0815 = 0x129
  | CSR0816 = 0x12A
  | CSR0817 = 0x12B
  | CSR0818 = 0x12C
  | CSR0819 = 0x12D
  | CSR0820 = 0x12E
  | CSR0821 = 0x12F
  | CSR0822 = 0x130
  | CSR0823 = 0x131
  | CSR0824 = 0x132
  | CSR0825 = 0x133
  | CSR0826 = 0x134
  | CSR0827 = 0x135
  | CSR0828 = 0x136
  | CSR0829 = 0x137
  | CSR0830 = 0x138
  | CSR0831 = 0x139
  | CSR1952 = 0x13A
  | CSR1953 = 0x13B
  | CSR1954 = 0x13C
  | CSR1955 = 0x13D
  | CSR1968 = 0x13E
  | CSR1969 = 0x13F
  | CSR1970 = 0x140
  | CSR1971 = 0x141
  | CSR3787 = 0x142
  | CSR2617 = 0x143
  | CSR3114 = 0x144
  | CSR2145 = 0X145
  | CSR2945 = 0x146
  /// Floating-Point Dynamic Rounding Mode.
  | FRM = 0x147
  /// Pseudo register for reservation check and follows the same format as ARM.
  | RC = 0x148

/// Helper module for RISC-V registers.
type RISCV64Register =
  /// Get the RISC-V register from a register ID.
  static member inline Get (rid: RegisterID): RISCV64 =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the RISC-V register from a string representation.
  static member Get (str: string): RISCV64 =
    match str.ToLowerInvariant () with
    | "x0" -> RISCV64.X0
    | "x1" -> RISCV64.X1
    | "x2" -> RISCV64.X2
    | "x3" -> RISCV64.X3
    | "x4" -> RISCV64.X4
    | "x5" -> RISCV64.X5
    | "x6" -> RISCV64.X6
    | "x7" -> RISCV64.X7
    | "x8" -> RISCV64.X8
    | "x9" -> RISCV64.X9
    | "x10" -> RISCV64.X10
    | "x11" -> RISCV64.X11
    | "x12" -> RISCV64.X12
    | "x13" -> RISCV64.X13
    | "x14" -> RISCV64.X14
    | "x15" -> RISCV64.X15
    | "x16" -> RISCV64.X16
    | "x17" -> RISCV64.X17
    | "x18" -> RISCV64.X18
    | "x19" -> RISCV64.X19
    | "x20" -> RISCV64.X20
    | "x21" -> RISCV64.X21
    | "x22" -> RISCV64.X22
    | "x23" -> RISCV64.X23
    | "x24" -> RISCV64.X24
    | "x25" -> RISCV64.X25
    | "x26" -> RISCV64.X26
    | "x27" -> RISCV64.X27
    | "x28" -> RISCV64.X28
    | "x29" -> RISCV64.X29
    | "x30" -> RISCV64.X30
    | "x31" -> RISCV64.X31
    | "f0" -> RISCV64.F0
    | "f1" -> RISCV64.F1
    | "f2" -> RISCV64.F2
    | "f3" -> RISCV64.F3
    | "f4" -> RISCV64.F4
    | "f5" -> RISCV64.F5
    | "f6" -> RISCV64.F6
    | "f7" -> RISCV64.F7
    | "f8" -> RISCV64.F8
    | "f9" -> RISCV64.F9
    | "f10" -> RISCV64.F10
    | "f11" -> RISCV64.F11
    | "f12" -> RISCV64.F12
    | "f13" -> RISCV64.F13
    | "f14" -> RISCV64.F14
    | "f15" -> RISCV64.F15
    | "f16" -> RISCV64.F16
    | "f17" -> RISCV64.F17
    | "f18" -> RISCV64.F18
    | "f19" -> RISCV64.F19
    | "f20" -> RISCV64.F20
    | "f21" -> RISCV64.F21
    | "f22" -> RISCV64.F22
    | "f23" -> RISCV64.F23
    | "f24" -> RISCV64.F24
    | "f25" -> RISCV64.F25
    | "f26" -> RISCV64.F26
    | "f27" -> RISCV64.F27
    | "f28" -> RISCV64.F28
    | "f29" -> RISCV64.F29
    | "f30" -> RISCV64.F30
    | "f31" -> RISCV64.F31
    | "pc" -> RISCV64.PC
    | "fcsr" -> RISCV64.FCSR
    | "fflags" -> RISCV64.FFLAGS
    | "frm" -> RISCV64.FRM
    | "rc" -> RISCV64.RC
    | _ -> Utils.impossible ()

  /// Get the register ID of a RISC-V register.
  static member inline ID (reg: RISCV64) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of a RISC-V register.
  static member String (reg: RISCV64) =
    match reg with
    | RISCV64.X0 -> "zero"
    | RISCV64.X1 -> "ra"
    | RISCV64.X2 -> "sp"
    | RISCV64.X3 -> "gp"
    | RISCV64.X4 -> "tp"
    | RISCV64.X5 -> "t0"
    | RISCV64.X6 -> "t1"
    | RISCV64.X7 -> "t2"
    | RISCV64.X8 -> "s0"
    | RISCV64.X9 -> "s1"
    | RISCV64.X10 -> "a0"
    | RISCV64.X11 -> "a1"
    | RISCV64.X12 -> "a2"
    | RISCV64.X13 -> "a3"
    | RISCV64.X14 -> "a4"
    | RISCV64.X15 -> "a5"
    | RISCV64.X16 -> "a6"
    | RISCV64.X17 -> "a7"
    | RISCV64.X18 -> "s2"
    | RISCV64.X19 -> "s3"
    | RISCV64.X20 -> "s4"
    | RISCV64.X21 -> "s5"
    | RISCV64.X22 -> "s6"
    | RISCV64.X23 -> "s7"
    | RISCV64.X24 -> "s8"
    | RISCV64.X25 -> "s9"
    | RISCV64.X26 -> "s10"
    | RISCV64.X27 -> "s11"
    | RISCV64.X28 -> "t3"
    | RISCV64.X29 -> "t4"
    | RISCV64.X30 -> "t5"
    | RISCV64.X31 -> "t6"
    | RISCV64.F0 -> "ft0"
    | RISCV64.F1 -> "ft1"
    | RISCV64.F2 -> "ft2"
    | RISCV64.F3 -> "ft3"
    | RISCV64.F4 -> "ft4"
    | RISCV64.F5 -> "ft5"
    | RISCV64.F6 -> "ft6"
    | RISCV64.F7 -> "ft7"
    | RISCV64.F8 -> "fs0"
    | RISCV64.F9 -> "fs1"
    | RISCV64.F10 -> "fa0"
    | RISCV64.F11 -> "fa1"
    | RISCV64.F12 -> "fa2"
    | RISCV64.F13 -> "fa3"
    | RISCV64.F14 -> "fa4"
    | RISCV64.F15 -> "fa5"
    | RISCV64.F16 -> "fa6"
    | RISCV64.F17 -> "fa7"
    | RISCV64.F18 -> "fs2"
    | RISCV64.F19 -> "fs3"
    | RISCV64.F20 -> "fs4"
    | RISCV64.F21 -> "fs5"
    | RISCV64.F22 -> "fs6"
    | RISCV64.F23 -> "fs7"
    | RISCV64.F24 -> "fs8"
    | RISCV64.F25 -> "fs9"
    | RISCV64.F26 -> "fs10"
    | RISCV64.F27 -> "fs11"
    | RISCV64.F28 -> "ft8"
    | RISCV64.F29 -> "ft9"
    | RISCV64.F30 -> "ft10"
    | RISCV64.F31 -> "ft11"
    | RISCV64.FCSR -> "fcsr"
    | RISCV64.FFLAGS -> "fflags"
    | RISCV64.FRM -> "frm"
    | RISCV64.RC -> "rc"
    | _ -> Utils.impossible ()

/// <summary>
/// Registers for SH4.<para/>
/// </summary>
type SH4 =
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

/// Helper module for SH4 registers.
type SH4Register =
  /// Get the SH4 register from a register ID.
  static member inline Get (rid: RegisterID): SH4 =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the SH4 register from a string representation.
  static member Get (str: string): SH4 =
    match str.ToLowerInvariant () with
    | "r0" -> SH4.R0
    | "r1" -> SH4.R1
    | "r2" -> SH4.R2
    | "r3" -> SH4.R3
    | "r4" -> SH4.R4
    | "r5" -> SH4.R5
    | "r6" -> SH4.R6
    | "r7" -> SH4.R7
    | "r8" -> SH4.R8
    | "r9" -> SH4.R9
    | "r10" -> SH4.R10
    | "r11" -> SH4.R11
    | "r12" -> SH4.R12
    | "r13" -> SH4.R13
    | "r14" -> SH4.R14
    | "r15" -> SH4.R15
    | "r0_bank" -> SH4.R0_BANK
    | "r1_bank" -> SH4.R1_BANK
    | "r2_bank" -> SH4.R2_BANK
    | "r3_bank" -> SH4.R3_BANK
    | "r4_bank" -> SH4.R4_BANK
    | "r5_bank" -> SH4.R5_BANK
    | "r6_bank" -> SH4.R6_BANK
    | "r7_bank" -> SH4.R7_BANK
    | "sr" -> SH4.SR
    | "gbr" -> SH4.GBR
    | "ssr" -> SH4.SSR
    | "spc" -> SH4.SPC
    | "sgr" -> SH4.SGR
    | "dbr" -> SH4.DBR
    | "vbr" -> SH4.VBR
    | "mach" -> SH4.MACH
    | "macl" -> SH4.MACL
    | "pr" -> SH4.PR
    | "fpul" -> SH4.FPUL
    | "pc" -> SH4.PC
    | "fpscr" -> SH4.FPSCR
    | "fpr0" -> SH4.FPR0
    | "fpr1" -> SH4.FPR1
    | "fpr2" -> SH4.FPR2
    | "fpr3" -> SH4.FPR3
    | "fpr4" -> SH4.FPR4
    | "fpr5" -> SH4.FPR5
    | "fpr6" -> SH4.FPR6
    | "fpr7" -> SH4.FPR7
    | "fpr8" -> SH4.FPR8
    | "fpr9" -> SH4.FPR9
    | "fpr10" -> SH4.FPR10
    | "fpr11" -> SH4.FPR11
    | "fpr12" -> SH4.FPR12
    | "fpr13" -> SH4.FPR13
    | "fpr14" -> SH4.FPR14
    | "fpr15" -> SH4.FPR15
    | "fr0" -> SH4.FR0
    | "fr1" -> SH4.FR1
    | "fr2" -> SH4.FR2
    | "fr3" -> SH4.FR3
    | "fr4" -> SH4.FR4
    | "fr5" -> SH4.FR5
    | "fr6" -> SH4.FR6
    | "fr7" -> SH4.FR7
    | "fr8" -> SH4.FR8
    | "fr9" -> SH4.FR9
    | "fr10" -> SH4.FR10
    | "fr11" -> SH4.FR11
    | "fr12" -> SH4.FR12
    | "fr13" -> SH4.FR13
    | "fr14" -> SH4.FR14
    | "fr15" -> SH4.FR15
    | "dr0" -> SH4.DR0
    | "dr2" -> SH4.DR2
    | "dr4" -> SH4.DR4
    | "dr6" -> SH4.DR6
    | "dr8" -> SH4.DR8
    | "dr10" -> SH4.DR10
    | "dr12" -> SH4.DR12
    | "dr14" -> SH4.DR14
    | "fv0" -> SH4.FV0
    | "fv4" -> SH4.FV4
    | "fv8" -> SH4.FV8
    | "fv12" -> SH4.FV12
    | "xd0" -> SH4.XD0
    | "xd2" -> SH4.XD2
    | "xd4" -> SH4.XD4
    | "xd6" -> SH4.XD6
    | "xd8" -> SH4.XD8
    | "xd10" -> SH4.XD10
    | "xd12" -> SH4.XD12
    | "xd14" -> SH4.XD14
    | "xf0" -> SH4.XF0
    | "xf1" -> SH4.XF1
    | "xf2" -> SH4.XF2
    | "xf3" -> SH4.XF3
    | "xf4" -> SH4.XF4
    | "xf5" -> SH4.XF5
    | "xf6" -> SH4.XF6
    | "xf7" -> SH4.XF7
    | "xf8" -> SH4.XF8
    | "xf9" -> SH4.XF9
    | "xf10" -> SH4.XF10
    | "xf11" -> SH4.XF11
    | "xf12" -> SH4.XF12
    | "xf13" -> SH4.XF13
    | "xf14" -> SH4.XF14
    | "xf15" -> SH4.XF15
    | "xmtrx" -> SH4.XMTRX
    | "pteh" -> SH4.PTEH
    | "ptel" -> SH4.PTEL
    | "ptea" -> SH4.PTEA
    | "ttb" -> SH4.TTB
    | "tea" -> SH4.TEA
    | "mmucr" -> SH4.MMUCR
    | "ccr" -> SH4.CCR
    | "qacr0" -> SH4.QACR0
    | "qacr1" -> SH4.QACR1
    | "tra" -> SH4.TRA
    | "expevt" -> SH4.EXPEVT
    | "intevt" -> SH4.INTEVT
    | "md" -> SH4.MD
    | "rb" -> SH4.RB
    | "bl" -> SH4.BL
    | "fd" -> SH4.FD
    | "m" -> SH4.M
    | "q" -> SH4.Q
    | "imask" -> SH4.IMASK
    | "s" -> SH4.S
    | "t" -> SH4.T
    | "fpscr_rm" -> SH4.FPSCR_RM
    | "fpscr_flag" -> SH4.FPSCR_FLAG
    | "fpscr_enable" -> SH4.FPSCR_ENABLE
    | "fpscr_cause" -> SH4.FPSCR_CAUSE
    | "fpscr_dn" -> SH4.FPSCR_DN
    | "fpscr_pr" -> SH4.FPSCR_PR
    | "fpscr_sz" -> SH4.FPSCR_SZ
    | "fpscr_fr" -> SH4.FPSCR_FR
    | _ -> Utils.impossible ()

  /// Get the register ID of a SH4 register.
  static member inline ID (reg: SH4) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of a SH4 register.
  static member String (reg: SH4) =
    match reg with
    | SH4.R0 -> "r0"
    | SH4.R1 -> "r1"
    | SH4.R2 -> "r2"
    | SH4.R3 -> "r3"
    | SH4.R4 -> "r4"
    | SH4.R5 -> "r5"
    | SH4.R6 -> "r6"
    | SH4.R7 -> "r7"
    | SH4.R8 -> "r8"
    | SH4.R9 -> "r9"
    | SH4.R10 -> "r10"
    | SH4.R11 -> "r11"
    | SH4.R12 -> "r12"
    | SH4.R13 -> "r13"
    | SH4.R14 -> "r14"
    | SH4.R15 -> "r15"
    | SH4.R0_BANK -> "r0_bank"
    | SH4.R1_BANK -> "r1_bank"
    | SH4.R2_BANK -> "r2_bank"
    | SH4.R3_BANK -> "r3_bank"
    | SH4.R4_BANK -> "r4_bank"
    | SH4.R5_BANK -> "r5_bank"
    | SH4.R6_BANK -> "r6_bank"
    | SH4.R7_BANK -> "r7_bank"
    | SH4.SR -> "sr"
    | SH4.GBR -> "gbr"
    | SH4.SSR -> "ssr"
    | SH4.SPC -> "spc"
    | SH4.SGR -> "sgr"
    | SH4.DBR -> "dbr"
    | SH4.VBR -> "vbr"
    | SH4.MACH -> "mach"
    | SH4.MACL -> "macl"
    | SH4.PR -> "pr"
    | SH4.FPUL -> "fpul"
    | SH4.PC -> "pc"
    | SH4.FPSCR -> "fpscr"
    | SH4.FPR0 -> "fpr0"
    | SH4.FPR1 -> "fpr1"
    | SH4.FPR2 -> "fpr2"
    | SH4.FPR3 -> "fpr3"
    | SH4.FPR4 -> "fpr4"
    | SH4.FPR5 -> "fpr5"
    | SH4.FPR6 -> "fpr6"
    | SH4.FPR7 -> "fpr7"
    | SH4.FPR8 -> "fpr8"
    | SH4.FPR9 -> "fpr9"
    | SH4.FPR10 -> "fpr10"
    | SH4.FPR11 -> "fpr11"
    | SH4.FPR12 -> "fpr12"
    | SH4.FPR13 -> "fpr13"
    | SH4.FPR14 -> "fpr14"
    | SH4.FPR15 -> "fpr15"
    | SH4.FR0 -> "fr0"
    | SH4.FR1 -> "fr1"
    | SH4.FR2 -> "fr2"
    | SH4.FR3 -> "fr3"
    | SH4.FR4 -> "fr4"
    | SH4.FR5 -> "fr5"
    | SH4.FR6 -> "fr6"
    | SH4.FR7 -> "fr7"
    | SH4.FR8 -> "fr8"
    | SH4.FR9 -> "fr9"
    | SH4.FR10 -> "fr10"
    | SH4.FR11 -> "fr11"
    | SH4.FR12 -> "fr12"
    | SH4.FR13 -> "fr13"
    | SH4.FR14 -> "fr14"
    | SH4.FR15 -> "fr15"
    | SH4.DR0 -> "dr0"
    | SH4.DR2 -> "dr2"
    | SH4.DR4 -> "dr4"
    | SH4.DR6 -> "dr6"
    | SH4.DR8 -> "dr8"
    | SH4.DR10 -> "dr10"
    | SH4.DR12 -> "dr12"
    | SH4.DR14 -> "dr14"
    | SH4.FV0 -> "fv0"
    | SH4.FV4 -> "fv4"
    | SH4.FV8 -> "fv8"
    | SH4.FV12 -> "fv12"
    | SH4.XD0 -> "xd0"
    | SH4.XD2 -> "xd2"
    | SH4.XD4 -> "xd4"
    | SH4.XD6 -> "xd6"
    | SH4.XD8 -> "xd8"
    | SH4.XD10 -> "xd10"
    | SH4.XD12 -> "xd12"
    | SH4.XD14 -> "xd14"
    | SH4.XF0 -> "xf0"
    | SH4.XF1 -> "xf1"
    | SH4.XF2 -> "xf2"
    | SH4.XF3 -> "xf3"
    | SH4.XF4 -> "xf4"
    | SH4.XF5 -> "xf5"
    | SH4.XF6 -> "xf6"
    | SH4.XF7 -> "xf7"
    | SH4.XF8 -> "xf8"
    | SH4.XF9 -> "xf9"
    | SH4.XF10 -> "xf10"
    | SH4.XF11 -> "xf11"
    | SH4.XF12 -> "xf12"
    | SH4.XF13 -> "xf13"
    | SH4.XF14 -> "xf14"
    | SH4.XF15 -> "xf15"
    | SH4.XMTRX -> "xmtrx"
    | SH4.PTEH -> "pteh"
    | SH4.PTEL -> "ptel"
    | SH4.PTEA -> "ptea"
    | SH4.TTB -> "ttb"
    | SH4.TEA -> "tea"
    | SH4.MMUCR -> "mmucr"
    | SH4.CCR -> "ccr"
    | SH4.QACR0 -> "qacr0"
    | SH4.QACR1 -> "qacr1"
    | SH4.TRA -> "tra"
    | SH4.EXPEVT -> "expevt"
    | SH4.INTEVT -> "intevt"
    | SH4.MD -> "md"
    | SH4.RB -> "rb"
    | SH4.BL -> "bl"
    | SH4.FD -> "fd"
    | SH4.M -> "m"
    | SH4.Q -> "q"
    | SH4.IMASK -> "imask"
    | SH4.S -> "s"
    | SH4.T -> "t"
    | SH4.FPSCR_RM -> "fpscr_rm"
    | SH4.FPSCR_FLAG -> "fpscr_flag"
    | SH4.FPSCR_ENABLE -> "fpscr_enable"
    | SH4.FPSCR_CAUSE -> "fpscr_cause"
    | SH4.FPSCR_DN -> "fpscr_dn"
    | SH4.FPSCR_PR -> "fpscr_pr"
    | SH4.FPSCR_SZ -> "fpscr_sz"
    | SH4.FPSCR_FR -> "fpscr_fr"
    | _ -> Utils.impossible ()

/// <summary>
/// Registers for SPARC.<para/>
/// </summary>
type SPARC =
  | G0 = 0x0
  | G1 = 0x1
  | G2 = 0x2
  | G3 = 0x3
  | G4 = 0x4
  | G5 = 0x5
  | G6 = 0x6
  | G7 = 0x7
  | O0 = 0x8
  | O1 = 0x9
  | O2 = 0xA
  | O3 = 0xB
  | O4 = 0xC
  | O5 = 0xD
  | O6 = 0xE
  | O7 = 0xF
  | L0 = 0x10
  | L1 = 0x11
  | L2 = 0x12
  | L3 = 0x13
  | L4 = 0x14
  | L5 = 0x15
  | L6 = 0x16
  | L7 = 0x17
  | I0 = 0x18
  | I1 = 0x19
  | I2 = 0x1A
  | I3 = 0x1B
  | I4 = 0x1C
  | I5 = 0x1D
  | I6 = 0x1E
  | I7 = 0x1F
  | PC = 0x20
  | NPC = 0x21
  | Y = 0x22
  | ASRs = 0x23
  | CCR = 0x24
  | FPRS = 0x25
  | FSR = 0x26
  | ASI = 0x27
  | TICK = 0x28
  | PSTATE = 0x29
  | TL = 0x2A
  | PIL = 0x2B
  | TPC = 0x2C
  | TNPC = 0x2D
  | TSTATE = 0x2E
  | TT = 0x2F
  | TBA = 0x30
  | VER = 0x31
  | CWP = 0x32
  | CANSAVE = 0x33
  | CANRESTORE = 0x34
  | OTHERWIN = 0x35
  | WSTATE = 0x36
  | FQ = 0x37
  | CLEANWIN = 0x38
  | F0 = 0x39
  | F1 = 0x3a
  | F2 = 0x3b
  | F3 = 0x3c
  | F4 = 0x3d
  | F5 = 0x3e
  | F6 = 0x3f
  | F7 = 0x40
  | F8 = 0x41
  | F9 = 0x42
  | F10 = 0x43
  | F11 = 0x44
  | F12 = 0x45
  | F13 = 0x46
  | F14 = 0x47
  | F15 = 0x48
  | F16 = 0x49
  | F17 = 0x4a
  | F18 = 0x4b
  | F19 = 0x4c
  | F20 = 0x4d
  | F21 = 0x4e
  | F22 = 0x4f
  | F23 = 0x50
  | F24 = 0x51
  | F25 = 0x52
  | F26 = 0x53
  | F27 = 0x54
  | F28 = 0x55
  | F29 = 0x56
  | F30 = 0x57
  | F31 = 0x58
  | F32 = 0x59
  | F34 = 0x5a
  | F36 = 0x5b
  | F38 = 0x5c
  | F40 = 0x5d
  | F42 = 0x5e
  | F44 = 0x5f
  | F46 = 0x60
  | F48 = 0x61
  | F50 = 0x62
  | F52 = 0x63
  | F54 = 0x64
  | F56 = 0x65
  | F58 = 0x66
  | F60 = 0x67
  | F62 = 0x68

/// Helper module for SPARC registers.
type SPARCRegister =
  /// Get the SPARC register from a register ID.
  static member inline Get (rid: RegisterID): SPARC =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the SPARC register from a string representation.
  static member Get (str: string): SPARC =
    match str.ToLowerInvariant () with
    | "g0" -> SPARC.G0
    | "g1" -> SPARC.G1
    | "g2" -> SPARC.G2
    | "g3" -> SPARC.G3
    | "g4" -> SPARC.G4
    | "g5" -> SPARC.G5
    | "g6" -> SPARC.G6
    | "g7" -> SPARC.G7
    | "o0" -> SPARC.O0
    | "o1" -> SPARC.O1
    | "o2" -> SPARC.O2
    | "o3" -> SPARC.O3
    | "o4" -> SPARC.O4
    | "o5" -> SPARC.O5
    | "o6" -> SPARC.O6
    | "o7" -> SPARC.O7
    | "l0" -> SPARC.L0
    | "l1" -> SPARC.L1
    | "l2" -> SPARC.L2
    | "l3" -> SPARC.L3
    | "l4" -> SPARC.L4
    | "l5" -> SPARC.L5
    | "l6" -> SPARC.L6
    | "l7" -> SPARC.L7
    | "i0" -> SPARC.I0
    | "i1" -> SPARC.I1
    | "i2" -> SPARC.I2
    | "i3" -> SPARC.I3
    | "i4" -> SPARC.I4
    | "i5" -> SPARC.I5
    | "i6" -> SPARC.I6
    | "i7" -> SPARC.I7
    | "pc" -> SPARC.PC
    | "npc" -> SPARC.NPC
    | "y" -> SPARC.Y
    | "asrs" -> SPARC.ASRs
    | "ccr" -> SPARC.CCR
    | "fprs" -> SPARC.FPRS
    | "fsr" -> SPARC.FSR
    | "asi" -> SPARC.ASI
    | "tick" -> SPARC.TICK
    | "pstate" -> SPARC.PSTATE
    | "tl" -> SPARC.TL
    | "pil" -> SPARC.PIL
    | "tpc" -> SPARC.TPC
    | "tnpc" -> SPARC.TNPC
    | "tstate" -> SPARC.TSTATE
    | "tt" -> SPARC.TT
    | "tba" -> SPARC.TBA
    | "ver" -> SPARC.VER
    | "cwp" -> SPARC.CWP
    | "cansave" -> SPARC.CANSAVE
    | "canrestore" -> SPARC.CANRESTORE
    | "otherwin" -> SPARC.OTHERWIN
    | "wstate" -> SPARC.WSTATE
    | "fq" -> SPARC.FQ
    | "cleanwin" -> SPARC.CLEANWIN
    | "f0" -> SPARC.F0
    | "f1" -> SPARC.F1
    | "f2" -> SPARC.F2
    | "f3" -> SPARC.F3
    | "f4" -> SPARC.F4
    | "f5" -> SPARC.F5
    | "f6" -> SPARC.F6
    | "f7" -> SPARC.F7
    | "f8" -> SPARC.F8
    | "f9" -> SPARC.F9
    | "f10" -> SPARC.F10
    | "f11" -> SPARC.F11
    | "f12" -> SPARC.F12
    | "f13" -> SPARC.F13
    | "f14" -> SPARC.F14
    | "f15" -> SPARC.F15
    | "f16" -> SPARC.F16
    | "f17" -> SPARC.F17
    | "f18" -> SPARC.F18
    | "f19" -> SPARC.F19
    | "f20" -> SPARC.F20
    | "f21" -> SPARC.F21
    | "f22" -> SPARC.F22
    | "f23" -> SPARC.F23
    | "f24" -> SPARC.F24
    | "f25" -> SPARC.F25
    | "f26" -> SPARC.F26
    | "f27" -> SPARC.F27
    | "f28" -> SPARC.F28
    | "f29" -> SPARC.F29
    | "f30" -> SPARC.F30
    | "f31" -> SPARC.F31
    | "f32" -> SPARC.F32
    | "f34" -> SPARC.F34
    | "f36" -> SPARC.F36
    | "f38" -> SPARC.F38
    | "f40" -> SPARC.F40
    | "f42" -> SPARC.F42
    | "f44" -> SPARC.F44
    | "f46" -> SPARC.F46
    | "f48" -> SPARC.F48
    | "f50" -> SPARC.F50
    | "f52" -> SPARC.F52
    | "f54" -> SPARC.F54
    | "f56" -> SPARC.F56
    | "f58" -> SPARC.F58
    | "f60" -> SPARC.F60
    | "f62" -> SPARC.F62
    | _ -> Utils.impossible ()

  /// Get the register ID of a SPARC register.
  static member inline ID (reg: SPARC) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of a SPARC register.
  static member String (reg: SPARC) =
    match reg with
    | SPARC.G0 -> "%g0"
    | SPARC.G1 -> "%g1"
    | SPARC.G2 -> "%g2"
    | SPARC.G3 -> "%g3"
    | SPARC.G4 -> "%g4"
    | SPARC.G5 -> "%g5"
    | SPARC.G6 -> "%g6"
    | SPARC.G7 -> "%g7"
    | SPARC.O0 -> "%o0"
    | SPARC.O1 -> "%o1"
    | SPARC.O2 -> "%o2"
    | SPARC.O3 -> "%o3"
    | SPARC.O4 -> "%o4"
    | SPARC.O5 -> "%o5"
    | SPARC.O6 -> "%o6"
    | SPARC.O7 -> "%o7"
    | SPARC.L0 -> "%l0"
    | SPARC.L1 -> "%l1"
    | SPARC.L2 -> "%l2"
    | SPARC.L3 -> "%l3"
    | SPARC.L4 -> "%l4"
    | SPARC.L5 -> "%l5"
    | SPARC.L6 -> "%l6"
    | SPARC.L7 -> "%l7"
    | SPARC.I0 -> "%i0"
    | SPARC.I1 -> "%i1"
    | SPARC.I2 -> "%i2"
    | SPARC.I3 -> "%i3"
    | SPARC.I4 -> "%i4"
    | SPARC.I5 -> "%i5"
    | SPARC.I6 -> "%i6"
    | SPARC.I7 -> "%i7"
    | SPARC.PC -> "pc"
    | SPARC.NPC -> "npc"
    | SPARC.Y -> "y"
    | SPARC.ASRs -> "asrs"
    | SPARC.CCR -> "ccr"
    | SPARC.FPRS -> "fprs"
    | SPARC.FSR -> "%fsr"
    | SPARC.ASI -> "%asi"
    | SPARC.TICK -> "%tick"
    | SPARC.PSTATE -> "%pstate"
    | SPARC.TL -> "%tl"
    | SPARC.PIL -> "%pil"
    | SPARC.TPC -> "%tpc"
    | SPARC.TNPC -> "%tnpc"
    | SPARC.TSTATE -> "%tstate"
    | SPARC.TT -> "%tt"
    | SPARC.TBA -> "%tba"
    | SPARC.VER -> "%ver"
    | SPARC.CWP -> "%cwp"
    | SPARC.CANSAVE -> "%cansave"
    | SPARC.CANRESTORE -> "%canrestore"
    | SPARC.OTHERWIN -> "%otherwin"
    | SPARC.WSTATE -> "%wstate"
    | SPARC.FQ -> "%fq"
    | SPARC.CLEANWIN -> "%cleanwin"
    | SPARC.F0 -> "%f0"
    | SPARC.F1 -> "%f1"
    | SPARC.F2 -> "%f2"
    | SPARC.F3 -> "%f3"
    | SPARC.F4 -> "%f4"
    | SPARC.F5 -> "%f5"
    | SPARC.F6 -> "%f6"
    | SPARC.F7 -> "%f7"
    | SPARC.F8 -> "%f8"
    | SPARC.F9 -> "%f9"
    | SPARC.F10 -> "%f10"
    | SPARC.F11 -> "%f11"
    | SPARC.F12 -> "%f12"
    | SPARC.F13 -> "%f13"
    | SPARC.F14 -> "%f14"
    | SPARC.F15 -> "%f15"
    | SPARC.F16 -> "%f16"
    | SPARC.F17 -> "%f17"
    | SPARC.F18 -> "%f18"
    | SPARC.F19 -> "%f19"
    | SPARC.F20 -> "%f20"
    | SPARC.F21 -> "%f21"
    | SPARC.F22 -> "%f22"
    | SPARC.F23 -> "%f23"
    | SPARC.F24 -> "%f24"
    | SPARC.F25 -> "%f25"
    | SPARC.F26 -> "%f26"
    | SPARC.F27 -> "%f27"
    | SPARC.F28 -> "%f28"
    | SPARC.F29 -> "%f29"
    | SPARC.F30 -> "%f30"
    | SPARC.F31 -> "%f31"
    | SPARC.F32 -> "%f32"
    | SPARC.F34 -> "%f34"
    | SPARC.F36 -> "%f36"
    | SPARC.F38 -> "%f38"
    | SPARC.F40 -> "%f40"
    | SPARC.F42 -> "%f42"
    | SPARC.F44 -> "%f44"
    | SPARC.F46 -> "%f46"
    | SPARC.F48 -> "%f48"
    | SPARC.F50 -> "%f50"
    | SPARC.F52 -> "%f52"
    | SPARC.F54 -> "%f54"
    | SPARC.F56 -> "%f56"
    | SPARC.F58 -> "%f58"
    | SPARC.F60 -> "%f60"
    | SPARC.F62 -> "%f62"
    | _ -> Utils.impossible ()

/// <summary>
/// Registers for TMS320C6000.<para/>
/// </summary>
type TMS320C6000 =
  | A0 = 0x0
  | A1 = 0x1
  | A2 = 0x2
  | A3 = 0x3
  | A4 = 0x4
  | A5 = 0x5
  | A6 = 0x6
  | A7 = 0x7
  | A8 = 0x8
  | A9 = 0x9
  | A10 = 0xA
  | A11 = 0xB
  | A12 = 0xC
  | A13 = 0xD
  | A14 = 0xE
  | A15 = 0xF
  | A16 = 0x10
  | A17 = 0x11
  | A18 = 0x12
  | A19 = 0x13
  | A20 = 0x14
  | A21 = 0x15
  | A22 = 0x16
  | A23 = 0x17
  | A24 = 0x18
  | A25 = 0x19
  | A26 = 0x1A
  | A27 = 0x1B
  | A28 = 0x1C
  | A29 = 0x1D
  | A30 = 0x1E
  | A31 = 0x1F
  | B0 = 0x20
  | B1 = 0x21
  | B2 = 0x22
  | B3 = 0x23
  | B4 = 0x24
  | B5 = 0x25
  | B6 = 0x26
  | B7 = 0x27
  | B8 = 0x28
  | B9 = 0x29
  | B10 = 0x2A
  | B11 = 0x2B
  | B12 = 0x2C
  | B13 = 0x2D
  | B14 = 0x2E
  | B15 = 0x2F
  | B16 = 0x30
  | B17 = 0x31
  | B18 = 0x32
  | B19 = 0x33
  | B20 = 0x34
  | B21 = 0x35
  | B22 = 0x36
  | B23 = 0x37
  | B24 = 0x38
  | B25 = 0x39
  | B26 = 0x3A
  | B27 = 0x3B
  | B28 = 0x3C
  | B29 = 0x3D
  | B30 = 0x3E
  | B31 = 0x3F
  | AMR = 0x40
  | CSR = 0x41
  | DIER = 0x42
  | DNUM = 0x43
  | ECR = 0x44
  | EFR = 0x45
  | FADCR = 0x46
  | FAUCR = 0x47
  | FMCR = 0x48
  | GFPGFR = 0x49
  | GPLYA = 0x4A
  | GPLYB = 0x4B
  | ICR = 0x4C
  | IER = 0x4D
  | IERR = 0x4E
  | IFR = 0x4F
  | ILC = 0x50
  | IRP = 0x51
  | ISR = 0x52
  | ISTP = 0x53
  | ITSR = 0x54
  | NRP = 0x55
  | NTSR = 0x56
  | PCE1 = 0x57
  | REP = 0x58
  | RILC = 0x59
  | SSR = 0x5A
  | TSCH = 0x5B
  | TSCL = 0x5C
  | TSR = 0x5D

/// Helper module for TMS320C6000 registers.
type TMS320C6000Register =
  /// Get the TMS320C6000 register from a register ID.
  static member inline Get (rid: RegisterID): TMS320C6000 =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the TMS320C6000 register from a string representation.
  static member Get (str: string): TMS320C6000 =
    match str.ToLowerInvariant () with
    | "a0" -> TMS320C6000.A0
    | "a1" -> TMS320C6000.A1
    | "a2" -> TMS320C6000.A2
    | "a3" -> TMS320C6000.A3
    | "a4" -> TMS320C6000.A4
    | "a5" -> TMS320C6000.A5
    | "a6" -> TMS320C6000.A6
    | "a7" -> TMS320C6000.A7
    | "a8" -> TMS320C6000.A8
    | "a9" -> TMS320C6000.A9
    | "a10" -> TMS320C6000.A10
    | "a11" -> TMS320C6000.A11
    | "a12" -> TMS320C6000.A12
    | "a13" -> TMS320C6000.A13
    | "a14" -> TMS320C6000.A14
    | "a15" -> TMS320C6000.A15
    | "a16" -> TMS320C6000.A16
    | "a17" -> TMS320C6000.A17
    | "a18" -> TMS320C6000.A18
    | "a19" -> TMS320C6000.A19
    | "a20" -> TMS320C6000.A20
    | "a21" -> TMS320C6000.A21
    | "a22" -> TMS320C6000.A22
    | "a23" -> TMS320C6000.A23
    | "a24" -> TMS320C6000.A24
    | "a25" -> TMS320C6000.A25
    | "a26" -> TMS320C6000.A26
    | "a27" -> TMS320C6000.A27
    | "a28" -> TMS320C6000.A28
    | "a29" -> TMS320C6000.A29
    | "a30" -> TMS320C6000.A30
    | "a31" -> TMS320C6000.A31
    | "b0" -> TMS320C6000.B0
    | "b1" -> TMS320C6000.B1
    | "b2" -> TMS320C6000.B2
    | "b3" -> TMS320C6000.B3
    | "b4" -> TMS320C6000.B4
    | "b5" -> TMS320C6000.B5
    | "b6" -> TMS320C6000.B6
    | "b7" -> TMS320C6000.B7
    | "b8" -> TMS320C6000.B8
    | "b9" -> TMS320C6000.B9
    | "b10" -> TMS320C6000.B10
    | "b11" -> TMS320C6000.B11
    | "b12" -> TMS320C6000.B12
    | "b13" -> TMS320C6000.B13
    | "b14" -> TMS320C6000.B14
    | "b15" -> TMS320C6000.B15
    | "b16" -> TMS320C6000.B16
    | "b17" -> TMS320C6000.B17
    | "b18" -> TMS320C6000.B18
    | "b19" -> TMS320C6000.B19
    | "b20" -> TMS320C6000.B20
    | "b21" -> TMS320C6000.B21
    | "b22" -> TMS320C6000.B22
    | "b23" -> TMS320C6000.B23
    | "b24" -> TMS320C6000.B24
    | "b25" -> TMS320C6000.B25
    | "b26" -> TMS320C6000.B26
    | "b27" -> TMS320C6000.B27
    | "b28" -> TMS320C6000.B28
    | "b29" -> TMS320C6000.B29
    | "b30" -> TMS320C6000.B30
    | "b31" -> TMS320C6000.B31
    | "amr" -> TMS320C6000.AMR
    | "csr" -> TMS320C6000.CSR
    | "dier" -> TMS320C6000.DIER
    | "dnum" -> TMS320C6000.DNUM
    | "ecr" -> TMS320C6000.ECR
    | "efr" -> TMS320C6000.EFR
    | "fadcr" -> TMS320C6000.FADCR
    | "faucr" -> TMS320C6000.FAUCR
    | "fmcr" -> TMS320C6000.FMCR
    | "gfpgfr" -> TMS320C6000.GFPGFR
    | "gplya" -> TMS320C6000.GPLYA
    | "gplyb" -> TMS320C6000.GPLYB
    | "icr" -> TMS320C6000.ICR
    | "ier" -> TMS320C6000.IER
    | "ierr" -> TMS320C6000.IERR
    | "ifr" -> TMS320C6000.IFR
    | "ilc" -> TMS320C6000.ILC
    | "irp" -> TMS320C6000.IRP
    | "isr" -> TMS320C6000.ISR
    | "istp" -> TMS320C6000.ISTP
    | "itsr" -> TMS320C6000.ITSR
    | "nrp" -> TMS320C6000.NRP
    | "ntsr" -> TMS320C6000.NTSR
    | "pce1" -> TMS320C6000.PCE1
    | "rep" -> TMS320C6000.REP
    | "rilc" -> TMS320C6000.RILC
    | "ssr" -> TMS320C6000.SSR
    | "tsch" -> TMS320C6000.TSCH
    | "tscl" -> TMS320C6000.TSCL
    | "tsr" -> TMS320C6000.TSR
    | _ -> Utils.impossible ()

  /// Get the register ID of a TMS320C6000 register.
  static member inline ID (reg: TMS320C6000) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of a TMS320C6000 register.
  static member String (reg: TMS320C6000) =
    match reg with
    | TMS320C6000.A0 -> "A0"
    | TMS320C6000.A1 -> "A1"
    | TMS320C6000.A2 -> "A2"
    | TMS320C6000.A3 -> "A3"
    | TMS320C6000.A4 -> "A4"
    | TMS320C6000.A5 -> "A5"
    | TMS320C6000.A6 -> "A6"
    | TMS320C6000.A7 -> "A7"
    | TMS320C6000.A8 -> "A8"
    | TMS320C6000.A9 -> "A9"
    | TMS320C6000.A10 -> "A10"
    | TMS320C6000.A11 -> "A11"
    | TMS320C6000.A12 -> "A12"
    | TMS320C6000.A13 -> "A13"
    | TMS320C6000.A14 -> "A14"
    | TMS320C6000.A15 -> "A15"
    | TMS320C6000.A16 -> "A16"
    | TMS320C6000.A17 -> "A17"
    | TMS320C6000.A18 -> "A18"
    | TMS320C6000.A19 -> "A19"
    | TMS320C6000.A20 -> "A20"
    | TMS320C6000.A21 -> "A21"
    | TMS320C6000.A22 -> "A22"
    | TMS320C6000.A23 -> "A23"
    | TMS320C6000.A24 -> "A24"
    | TMS320C6000.A25 -> "A25"
    | TMS320C6000.A26 -> "A26"
    | TMS320C6000.A27 -> "A27"
    | TMS320C6000.A28 -> "A28"
    | TMS320C6000.A29 -> "A29"
    | TMS320C6000.A30 -> "A30"
    | TMS320C6000.A31 -> "A31"
    | TMS320C6000.B0 -> "B0"
    | TMS320C6000.B1 -> "B1"
    | TMS320C6000.B2 -> "B2"
    | TMS320C6000.B3 -> "B3"
    | TMS320C6000.B4 -> "B4"
    | TMS320C6000.B5 -> "B5"
    | TMS320C6000.B6 -> "B6"
    | TMS320C6000.B7 -> "B7"
    | TMS320C6000.B8 -> "B8"
    | TMS320C6000.B9 -> "B9"
    | TMS320C6000.B10 -> "B10"
    | TMS320C6000.B11 -> "B11"
    | TMS320C6000.B12 -> "B12"
    | TMS320C6000.B13 -> "B13"
    | TMS320C6000.B14 -> "B14"
    | TMS320C6000.B15 -> "B15"
    | TMS320C6000.B16 -> "B16"
    | TMS320C6000.B17 -> "B17"
    | TMS320C6000.B18 -> "B18"
    | TMS320C6000.B19 -> "B19"
    | TMS320C6000.B20 -> "B20"
    | TMS320C6000.B21 -> "B21"
    | TMS320C6000.B22 -> "B22"
    | TMS320C6000.B23 -> "B23"
    | TMS320C6000.B24 -> "B24"
    | TMS320C6000.B25 -> "B25"
    | TMS320C6000.B26 -> "B26"
    | TMS320C6000.B27 -> "B27"
    | TMS320C6000.B28 -> "B28"
    | TMS320C6000.B29 -> "B29"
    | TMS320C6000.B30 -> "B30"
    | TMS320C6000.B31 -> "B31"
    | TMS320C6000.AMR -> "AMR"
    | TMS320C6000.CSR -> "CSR"
    | TMS320C6000.DIER -> "DIER"
    | TMS320C6000.DNUM -> "DNUM"
    | TMS320C6000.ECR -> "ECR"
    | TMS320C6000.EFR -> "EFR"
    | TMS320C6000.FADCR -> "FADCR"
    | TMS320C6000.FAUCR -> "FAUCR"
    | TMS320C6000.FMCR -> "FMCR"
    | TMS320C6000.GFPGFR -> "GFPGFR"
    | TMS320C6000.GPLYA -> "GPLYA"
    | TMS320C6000.GPLYB -> "GPLYB"
    | TMS320C6000.ICR -> "ICR"
    | TMS320C6000.IER -> "IER"
    | TMS320C6000.IERR -> "IERR"
    | TMS320C6000.IFR -> "IFR"
    | TMS320C6000.ILC -> "ILC"
    | TMS320C6000.IRP -> "IRP"
    | TMS320C6000.ISR -> "ISR"
    | TMS320C6000.ISTP -> "ISTP"
    | TMS320C6000.ITSR -> "ITSR"
    | TMS320C6000.NRP -> "NRP"
    | TMS320C6000.NTSR -> "NTSR"
    | TMS320C6000.PCE1 -> "PCE1"
    | TMS320C6000.REP -> "REP"
    | TMS320C6000.RILC -> "RILC"
    | TMS320C6000.SSR -> "SSR"
    | TMS320C6000.TSCH -> "TSCH"
    | TMS320C6000.TSCL -> "TSCL"
    | TMS320C6000.TSR -> "TSR"
    | _ -> Utils.impossible ()
