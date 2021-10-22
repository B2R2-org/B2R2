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
  | S0 = 0x100
  /// S1.
  | S1 = 0x101
  /// S2.
  | S2 = 0x102
  /// S3.
  | S3 = 0x103
  /// S4.
  | S4 = 0x104
  /// S5.
  | S5 = 0x105
  /// S6.
  | S6 = 0x106
  /// S7.
  | S7 = 0x107
  /// S8.
  | S8 = 0x108
  /// S9.
  | S9 = 0x109
  /// S10.
  | S10 = 0x10A
  /// S11.
  | S11 = 0x10B
  /// S12.
  | S12 = 0x10C
  /// S13.
  | S13 = 0x10D
  /// S14.
  | S14 = 0x10E
  /// S15.
  | S15 = 0x10F
  /// S16.
  | S16 = 0x110
  /// S17.
  | S17 = 0x111
  /// S18.
  | S18 = 0x112
  /// S19.
  | S19 = 0x113
  /// S20.
  | S20 = 0x114
  /// S21.
  | S21 = 0x115
  /// S22.
  | S22 = 0x116
  /// S23.
  | S23 = 0x117
  /// S24.
  | S24 = 0x118
  /// S25.
  | S25 = 0x119
  /// S26.
  | S26 = 0x11A
  /// S27.
  | S27 = 0x11B
  /// S28.
  | S28 = 0x11C
  /// S29.
  | S29 = 0x11D
  /// S30.
  | S30 = 0x11E
  /// S31.
  | S31 = 0x11F
  /// D0.
  | D0 = 0x200
  /// D1.
  | D1 = 0x201
  /// D2.
  | D2 = 0x202
  /// D3.
  | D3 = 0x203
  /// D4.
  | D4 = 0x204
  /// D5.
  | D5 = 0x205
  /// D6.
  | D6 = 0x206
  /// D7.
  | D7 = 0x207
  /// D8.
  | D8 = 0x208
  /// D9.
  | D9 = 0x209
  /// D10.
  | D10 = 0x20A
  /// D11.
  | D11 = 0x20B
  /// D12.
  | D12 = 0x20C
  /// D13.
  | D13 = 0x20D
  /// D14.
  | D14 = 0x20E
  /// D15.
  | D15 = 0x20F
  /// D16.
  | D16 = 0x210
  /// D17.
  | D17 = 0x211
  /// D18.
  | D18 = 0x212
  /// D19.
  | D19 = 0x213
  /// D20.
  | D20 = 0x214
  /// D21.
  | D21 = 0x215
  /// D22.
  | D22 = 0x216
  /// D23.
  | D23 = 0x217
  /// D24.
  | D24 = 0x218
  /// D25.
  | D25 = 0x219
  /// D26.
  | D26 = 0x21A
  /// D27.
  | D27 = 0x21B
  /// D28.
  | D28 = 0x21C
  /// D29.
  | D29 = 0x21D
  /// D30.
  | D30 = 0x21E
  /// D31.
  | D31 = 0x21F
  /// FPINST2.
  | FPINST2 = 0x220
  /// MVFR0.
  | MVFR0 = 0x221
  /// MVFR1.
  | MVFR1 = 0x222
  /// Q0.
  | Q0 = 0x300
  /// Q1.
  | Q1 = 0x301
  /// Q2.
  | Q2 = 0x302
  /// Q3.
  | Q3 = 0x303
  /// Q4.
  | Q4 = 0x304
  /// Q5.
  | Q5 = 0x305
  /// Q6.
  | Q6 = 0x306
  /// Q7.
  | Q7 = 0x307
  /// Q8.
  | Q8 = 0x308
  /// Q9.
  | Q9 = 0x309
  /// Q10.
  | Q10 = 0x30A
  /// Q11.
  | Q11 = 0x30B
  /// Q12.
  | Q12 = 0x30C
  /// Q13.
  | Q13 = 0x30D
  /// Q14.
  | Q14 = 0x30E
  /// Q15.
  | Q15 = 0x30F
  /// C0.
  | C0 = 0x400
  /// C1.
  | C1 = 0x401
  /// C2.
  | C2 = 0x402
  /// C3.
  | C3 = 0x403
  /// C4.
  | C4 = 0x404
  /// C5.
  | C5 = 0x405
  /// C6.
  | C6 = 0x406
  /// C7.
  | C7 = 0x407
  /// C8.
  | C8 = 0x408
  /// C9.
  | C9 = 0x409
  /// C10.
  | C10 = 0x40A
  /// C11.
  | C11 = 0x40B
  /// C12.
  | C12 = 0x40C
  /// C13.
  | C13 = 0x40D
  /// C14.
  | C14 = 0x40E
  /// C15.
  | C15 = 0x40F
  /// P0.
  | P0 = 0x500
  /// P1.
  | P1 = 0x501
  /// P2.
  | P2 = 0x502
  /// P3.
  | P3 = 0x503
  /// P4.
  | P4 = 0x504
  /// P5.
  | P5 = 0x505
  /// P6.
  | P6 = 0x506
  /// P7.
  | P7 = 0x507
  /// P8.
  | P8 = 0x508
  /// P9.
  | P9 = 0x509
  /// P10.
  | P10 = 0x50A
  /// P11.
  | P11 = 0x50B
  /// P12.
  | P12 = 0x50C
  /// P13.
  | P13 = 0x50D
  /// P14.
  | P14 = 0x50E
  /// P15.
  | P15 = 0x50F
  /// R8usr.
  | R8usr = 0x600
  /// R9usr.
  | R9usr = 0x601
  /// R10usr.
  | R10usr = 0x602
  /// R11usr.
  | R11usr = 0x603
  /// R12usr.
  | R12usr = 0x604
  /// SPusr.
  | SPusr = 0x605
  /// LRusr.
  | LRusr = 0x606
  /// SPhyp.
  | SPhyp = 0x607
  /// SPSRhyp.
  | SPSRhyp = 0x608
  /// ELRhyp.
  | ELRhyp = 0x609
  /// SPsvc.
  | SPsvc = 0x60A
  /// LRsvc.
  | LRsvc = 0x60B
  /// SPSRsvc.
  | SPSRsvc = 0x60C
  /// SPabt.
  | SPabt = 0x60D
  /// LRabt.
  | LRabt = 0x60E
  /// SPSRabt.
  | SPSRabt = 0x60F
  /// SPund.
  | SPund = 0x610
  /// LRund.
  | LRund = 0x611
  /// SPSRund.
  | SPSRund = 0x612
  /// SPmon.
  | SPmon = 0x613
  /// LRmon.
  | LRmon = 0x614
  /// SPSRmon.
  | SPSRmon = 0x615
  /// SPirq.
  | SPirq = 0x616
  /// LRirq.
  | LRirq = 0x617
  /// SPSRirq.
  | SPSRirq = 0x618
  /// R8fiq.
  | R8fiq = 0x619
  /// R9fiq.
  | R9fiq = 0x61A
  /// R10fiq.
  | R10fiq = 0x61B
  /// R11fiq.
  | R11fiq = 0x61C
  /// R12fiq.
  | R12fiq = 0x61D
  /// SPfiq.
  | SPfiq = 0x61E
  /// LRfiq.
  | LRfiq = 0x61F
  /// SPSRfiq.
  | SPSRfiq = 0x620
  /// Application Program Status Register.
  | APSR = 0x700
  /// Current Program Status Register.
  | CPSR = 0x701
  /// Saved Program Status Register.
  | SPSR = 0x702
  /// Secure Configuration Register.
  | SCR = 0x703
  /// System Control register
  | SCTLR = 0x704
  /// Non-Secure Access Control Register.
  | NSACR = 0x705
  /// FPSCR, Floating-point Status and Control Register, VMSA.
  | FPSCR = 0x800

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
    match str.ToLower () with
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
    | R.D26 | R.D27 | R.D28 | R.D29 | R.D30 | R.D31 -> 64<rt>
    | R.Q0 | R.Q1 | R.Q2 | R.Q3 | R.Q4 | R.Q5 | R.Q6 | R.Q7 | R.Q8 | R.Q9
    | R.Q10 | R.Q11 | R.Q12 | R.Q13 | R.Q14 | R.Q15 -> 128<rt>
    | _ -> Utils.impossible ()
