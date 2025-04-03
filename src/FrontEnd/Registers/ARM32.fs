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

namespace B2R2.FrontEnd.ARM32

open B2R2

/// <summary>
/// Registers for ARMv7, ARMv8 AArch32.<para/>
/// </summary>
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

/// Helper module for ARM32 registers.
[<RequireQualifiedAccess>]
module Register =
  /// Get the ARM32 register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Get the ARM32 register from a string representation.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "r0" -> Register.R0
    | "r1" -> Register.R1
    | "r2" -> Register.R2
    | "r3" -> Register.R3
    | "r4" -> Register.R4
    | "r5" -> Register.R5
    | "r6" -> Register.R6
    | "r7" -> Register.R7
    | "r8" -> Register.R8
    | "sB" -> Register.SB
    | "sL" -> Register.SL
    | "fP" -> Register.FP
    | "iP" -> Register.IP
    | "sP" -> Register.SP
    | "lR" -> Register.LR
    | "pC" -> Register.PC
    | "s0" -> Register.S0
    | "s1" -> Register.S1
    | "s2" -> Register.S2
    | "s3" -> Register.S3
    | "s4" -> Register.S4
    | "s5" -> Register.S5
    | "s6" -> Register.S6
    | "s7" -> Register.S7
    | "s8" -> Register.S8
    | "s9" -> Register.S9
    | "s10" -> Register.S10
    | "s11" -> Register.S11
    | "s12" -> Register.S12
    | "s13" -> Register.S13
    | "s14" -> Register.S14
    | "s15" -> Register.S15
    | "s16" -> Register.S16
    | "s17" -> Register.S17
    | "s18" -> Register.S18
    | "s19" -> Register.S19
    | "s20" -> Register.S20
    | "s21" -> Register.S21
    | "s22" -> Register.S22
    | "s23" -> Register.S23
    | "s24" -> Register.S24
    | "s25" -> Register.S25
    | "s26" -> Register.S26
    | "s27" -> Register.S27
    | "s28" -> Register.S28
    | "s29" -> Register.S29
    | "s30" -> Register.S30
    | "s31" -> Register.S31
    | "d0" -> Register.D0
    | "d1" -> Register.D1
    | "d2" -> Register.D2
    | "d3" -> Register.D3
    | "d4" -> Register.D4
    | "d5" -> Register.D5
    | "d6" -> Register.D6
    | "d7" -> Register.D7
    | "d8" -> Register.D8
    | "d9" -> Register.D9
    | "d10" -> Register.D10
    | "d11" -> Register.D11
    | "d12" -> Register.D12
    | "d13" -> Register.D13
    | "d14" -> Register.D14
    | "d15" -> Register.D15
    | "d16" -> Register.D16
    | "d17" -> Register.D17
    | "d18" -> Register.D18
    | "d19" -> Register.D19
    | "d20" -> Register.D20
    | "d21" -> Register.D21
    | "d22" -> Register.D22
    | "d23" -> Register.D23
    | "d24" -> Register.D24
    | "d25" -> Register.D25
    | "d26" -> Register.D26
    | "d27" -> Register.D27
    | "d28" -> Register.D28
    | "d29" -> Register.D29
    | "d30" -> Register.D30
    | "d31" -> Register.D31
    | "fpinst2" -> Register.FPINST2
    | "mvfr0" -> Register.MVFR0
    | "mvfr1" -> Register.MVFR1
    | "q0" -> Register.Q0
    | "q1" -> Register.Q1
    | "q2" -> Register.Q2
    | "q3" -> Register.Q3
    | "q4" -> Register.Q4
    | "q5" -> Register.Q5
    | "q6" -> Register.Q6
    | "q7" -> Register.Q7
    | "q8" -> Register.Q8
    | "q9" -> Register.Q9
    | "q10" -> Register.Q10
    | "q11" -> Register.Q11
    | "q12" -> Register.Q12
    | "q13" -> Register.Q13
    | "q14" -> Register.Q14
    | "q15" -> Register.Q15
    | "q0a" -> Register.Q0A
    | "q0b" -> Register.Q0B
    | "q1a" -> Register.Q1A
    | "q1b" -> Register.Q1B
    | "q2a" -> Register.Q2A
    | "q2b" -> Register.Q2B
    | "q3a" -> Register.Q3A
    | "q3b" -> Register.Q3B
    | "q4a" -> Register.Q4A
    | "q4b" -> Register.Q4B
    | "q5a" -> Register.Q5A
    | "q5b" -> Register.Q5B
    | "q6a" -> Register.Q6A
    | "q6b" -> Register.Q6B
    | "q7a" -> Register.Q7A
    | "q7b" -> Register.Q7B
    | "q8a" -> Register.Q8A
    | "q8b" -> Register.Q8B
    | "q9a" -> Register.Q9A
    | "q9b" -> Register.Q9B
    | "q10a" -> Register.Q10A
    | "q10b" -> Register.Q10B
    | "q11a" -> Register.Q11A
    | "q11b" -> Register.Q11B
    | "q12a" -> Register.Q12A
    | "q12b" -> Register.Q12B
    | "q13a" -> Register.Q13A
    | "q13b" -> Register.Q13B
    | "q14a" -> Register.Q14A
    | "q14b" -> Register.Q14B
    | "q15a" -> Register.Q15A
    | "q15b" -> Register.Q15B
    | "c0" -> Register.C0
    | "c1" -> Register.C1
    | "c2" -> Register.C2
    | "c3" -> Register.C3
    | "c4" -> Register.C4
    | "c5" -> Register.C5
    | "c6" -> Register.C6
    | "c7" -> Register.C7
    | "c8" -> Register.C8
    | "c9" -> Register.C9
    | "c10" -> Register.C10
    | "c11" -> Register.C11
    | "c12" -> Register.C12
    | "c13" -> Register.C13
    | "c14" -> Register.C14
    | "c15" -> Register.C15
    | "p0" -> Register.P0
    | "p1" -> Register.P1
    | "p2" -> Register.P2
    | "p3" -> Register.P3
    | "p4" -> Register.P4
    | "p5" -> Register.P5
    | "p6" -> Register.P6
    | "p7" -> Register.P7
    | "p8" -> Register.P8
    | "p9" -> Register.P9
    | "p10" -> Register.P10
    | "p11" -> Register.P11
    | "p12" -> Register.P12
    | "p13" -> Register.P13
    | "p14" -> Register.P14
    | "p15" -> Register.P15
    | "r8usr" -> Register.R8usr
    | "r9usr" -> Register.R9usr
    | "r10usr" -> Register.R10usr
    | "r11usr" -> Register.R11usr
    | "r12usr" -> Register.R12usr
    | "spusr" -> Register.SPusr
    | "lrusr" -> Register.LRusr
    | "sphyp" -> Register.SPhyp
    | "spsrhyp" -> Register.SPSRhyp
    | "elrhyp" -> Register.ELRhyp
    | "spsvc" -> Register.SPsvc
    | "lrsvc" -> Register.LRsvc
    | "spsrsvc" -> Register.SPSRsvc
    | "spabt" -> Register.SPabt
    | "lrabt" -> Register.LRabt
    | "spsrabt" -> Register.SPSRabt
    | "spund" -> Register.SPund
    | "lrund" -> Register.LRund
    | "spsrund" -> Register.SPSRund
    | "spmon" -> Register.SPmon
    | "lrmon" -> Register.LRmon
    | "spsrmon" -> Register.SPSRmon
    | "spirq" -> Register.SPirq
    | "lrirq" -> Register.LRirq
    | "spsrirq" -> Register.SPSRirq
    | "r8fiq" -> Register.R8fiq
    | "r9fiq" -> Register.R9fiq
    | "r10fiq" -> Register.R10fiq
    | "r11fiq" -> Register.R11fiq
    | "r12fiq" -> Register.R12fiq
    | "spfiq" -> Register.SPfiq
    | "lrfiq" -> Register.LRfiq
    | "spsrfiq" -> Register.SPSRfiq
    | "apsr" -> Register.APSR
    | "cpsr" -> Register.CPSR
    | "spsr" -> Register.SPSR
    | "scr" -> Register.SCR
    | "sctlr" -> Register.SCTLR
    | "nsacr" -> Register.NSACR
    | "fpscr" -> Register.FPSCR
    | _ -> Terminator.impossible ()

  /// Get the register ID of an ARM32 register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Get the string representation of an ARM32 register.
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
    | Register.SB -> "sb"
    | Register.SL -> "sl"
    | Register.FP -> "fp"
    | Register.IP -> "ip"
    | Register.SP -> "sp"
    | Register.LR -> "lr"
    | Register.PC -> "pc"
    | Register.S0 -> "s0"
    | Register.S1 -> "s1"
    | Register.S2 -> "s2"
    | Register.S3 -> "s3"
    | Register.S4 -> "s4"
    | Register.S5 -> "s5"
    | Register.S6 -> "s6"
    | Register.S7 -> "s7"
    | Register.S8 -> "s8"
    | Register.S9 -> "s9"
    | Register.S10 -> "s10"
    | Register.S11 -> "s11"
    | Register.S12 -> "s12"
    | Register.S13 -> "s13"
    | Register.S14 -> "s14"
    | Register.S15 -> "s15"
    | Register.S16 -> "s16"
    | Register.S17 -> "s17"
    | Register.S18 -> "s18"
    | Register.S19 -> "s19"
    | Register.S20 -> "s20"
    | Register.S21 -> "s21"
    | Register.S22 -> "s22"
    | Register.S23 -> "s23"
    | Register.S24 -> "s24"
    | Register.S25 -> "s25"
    | Register.S26 -> "s26"
    | Register.S27 -> "s27"
    | Register.S28 -> "s28"
    | Register.S29 -> "s29"
    | Register.S30 -> "s30"
    | Register.S31 -> "s31"
    | Register.D0 -> "d0"
    | Register.D1 -> "d1"
    | Register.D2 -> "d2"
    | Register.D3 -> "d3"
    | Register.D4 -> "d4"
    | Register.D5 -> "d5"
    | Register.D6 -> "d6"
    | Register.D7 -> "d7"
    | Register.D8 -> "d8"
    | Register.D9 -> "d9"
    | Register.D10 -> "d10"
    | Register.D11 -> "d11"
    | Register.D12 -> "d12"
    | Register.D13 -> "d13"
    | Register.D14 -> "d14"
    | Register.D15 -> "d15"
    | Register.D16 -> "d16"
    | Register.D17 -> "d17"
    | Register.D18 -> "d18"
    | Register.D19 -> "d19"
    | Register.D20 -> "d20"
    | Register.D21 -> "d21"
    | Register.D22 -> "d22"
    | Register.D23 -> "d23"
    | Register.D24 -> "d24"
    | Register.D25 -> "d25"
    | Register.D26 -> "d26"
    | Register.D27 -> "d27"
    | Register.D28 -> "d28"
    | Register.D29 -> "d29"
    | Register.D30 -> "d30"
    | Register.D31 -> "d31"
    | Register.FPINST2 -> "fpinst2"
    | Register.MVFR0 -> "mvfr0"
    | Register.MVFR1 -> "mvfr1"
    | Register.Q0 -> "q0"
    | Register.Q1 -> "q1"
    | Register.Q2 -> "q2"
    | Register.Q3 -> "q3"
    | Register.Q4 -> "q4"
    | Register.Q5 -> "q5"
    | Register.Q6 -> "q6"
    | Register.Q7 -> "q7"
    | Register.Q8 -> "q8"
    | Register.Q9 -> "q9"
    | Register.Q10 -> "q10"
    | Register.Q11 -> "q11"
    | Register.Q12 -> "q12"
    | Register.Q13 -> "q13"
    | Register.Q14 -> "q14"
    | Register.Q15 -> "q15"
    | Register.Q0A -> "q0a"
    | Register.Q0B -> "q0b"
    | Register.Q1A -> "q1a"
    | Register.Q1B -> "q1b"
    | Register.Q2A -> "q2a"
    | Register.Q2B -> "q2b"
    | Register.Q3A -> "q3a"
    | Register.Q3B -> "q3b"
    | Register.Q4A -> "q4a"
    | Register.Q4B -> "q4b"
    | Register.Q5A -> "q5a"
    | Register.Q5B -> "q5b"
    | Register.Q6A -> "q6a"
    | Register.Q6B -> "q6b"
    | Register.Q7A -> "q7a"
    | Register.Q7B -> "q7b"
    | Register.Q8A -> "q8a"
    | Register.Q8B -> "q8b"
    | Register.Q9A -> "q9a"
    | Register.Q9B -> "q9b"
    | Register.Q10A -> "q10a"
    | Register.Q10B -> "q10b"
    | Register.Q11A -> "q11a"
    | Register.Q11B -> "q11b"
    | Register.Q12A -> "q12a"
    | Register.Q12B -> "q12b"
    | Register.Q13A -> "q13a"
    | Register.Q13B -> "q13b"
    | Register.Q14A -> "q14a"
    | Register.Q14B -> "q14b"
    | Register.Q15A -> "q15a"
    | Register.Q15B -> "q15b"
    | Register.C0 -> "c0"
    | Register.C1 -> "c1"
    | Register.C2 -> "c2"
    | Register.C3 -> "c3"
    | Register.C4 -> "c4"
    | Register.C5 -> "c5"
    | Register.C6 -> "c6"
    | Register.C7 -> "c7"
    | Register.C8 -> "c8"
    | Register.C9 -> "c9"
    | Register.C10 -> "c10"
    | Register.C11 -> "c11"
    | Register.C12 -> "c12"
    | Register.C13 -> "c13"
    | Register.C14 -> "c14"
    | Register.C15 -> "c15"
    | Register.P0 -> "p0"
    | Register.P1 -> "p1"
    | Register.P2 -> "p2"
    | Register.P3 -> "p3"
    | Register.P4 -> "p4"
    | Register.P5 -> "p5"
    | Register.P6 -> "p6"
    | Register.P7 -> "p7"
    | Register.P8 -> "p8"
    | Register.P9 -> "p9"
    | Register.P10 -> "p10"
    | Register.P11 -> "p11"
    | Register.P12 -> "p12"
    | Register.P13 -> "p13"
    | Register.P14 -> "p14"
    | Register.P15 -> "p15"
    | Register.APSR -> "apsr"
    | Register.CPSR -> "cpsr"
    | Register.SPSR -> "spsr"
    | Register.SCR -> "scr"
    | Register.SCTLR -> "sctlr"
    | Register.NSACR -> "nsacr"
    | Register.FPSCR -> "fpscr"
    | Register.R8usr -> "r8_usr"
    | Register.R9usr -> "r9_usr"
    | Register.R10usr -> "r10_usr"
    | Register.R11usr -> "r11_usr"
    | Register.R12usr -> "r12_usr"
    | Register.SPusr -> "sp_usr"
    | Register.LRusr -> "lr_usr"
    | Register.SPhyp -> "sp_hyp"
    | Register.SPSRhyp -> "spsr_hyp"
    | Register.ELRhyp -> "elr_hyp"
    | Register.SPsvc -> "sp_svc"
    | Register.LRsvc -> "lr_svc"
    | Register.SPSRsvc -> "spsr_svc"
    | Register.SPabt -> "sp_abt"
    | Register.LRabt -> "lr_abt"
    | Register.SPSRabt -> "spsr_abt"
    | Register.SPund -> "sp_und"
    | Register.LRund -> "lr_und"
    | Register.SPSRund -> "spsr_und"
    | Register.SPmon -> "sp_mon"
    | Register.LRmon -> "lr_mon"
    | Register.SPSRmon -> "spsr_mon"
    | Register.SPirq -> "sp_irq"
    | Register.LRirq -> "lr_irq"
    | Register.SPSRirq -> "spsr_irq"
    | Register.R8fiq -> "r8_fiq"
    | Register.R9fiq -> "r9_fiq"
    | Register.R10fiq -> "r10_fiq"
    | Register.R11fiq -> "r11_fiq"
    | Register.R12fiq -> "r12_fiq"
    | Register.SPfiq -> "sp_fiq"
    | Register.LRfiq -> "lr_fiq"
    | Register.SPSRfiq -> "spsr_fiq"
    | _ -> Terminator.impossible ()
