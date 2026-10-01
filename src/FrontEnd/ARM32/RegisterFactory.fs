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
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR
open type Register

/// Represents a factory for accessing various ARM32 register variables.
type RegisterFactory(isa: ISA) =
  let r0 = AST.var 32<rt> (Register.toRegID R0) "R0"
  let r1 = AST.var 32<rt> (Register.toRegID R1) "R1"
  let r2 = AST.var 32<rt> (Register.toRegID R2) "R2"
  let r3 = AST.var 32<rt> (Register.toRegID R3) "R3"
  let r4 = AST.var 32<rt> (Register.toRegID R4) "R4"
  let r5 = AST.var 32<rt> (Register.toRegID R5) "R5"
  let r6 = AST.var 32<rt> (Register.toRegID R6) "R6"
  let r7 = AST.var 32<rt> (Register.toRegID R7) "R7"
  let r8 = AST.var 32<rt> (Register.toRegID R8) "R8"
  let sb = AST.var 32<rt> (Register.toRegID SB) "SB"
  let sl = AST.var 32<rt> (Register.toRegID SL) "SL"
  let fp = AST.var 32<rt> (Register.toRegID FP) "FP"
  let ip = AST.var 32<rt> (Register.toRegID IP) "IP"
  let sp = AST.var 32<rt> (Register.toRegID SP) "SP"
  let lr = AST.var 32<rt> (Register.toRegID LR) "LR"
  let q0a = AST.var 64<rt> (Register.toRegID Q0A) "Q0A"
  let q0b = AST.var 64<rt> (Register.toRegID Q0B) "Q0B"
  let q1a = AST.var 64<rt> (Register.toRegID Q1A) "Q1A"
  let q1b = AST.var 64<rt> (Register.toRegID Q1B) "Q1B"
  let q2a = AST.var 64<rt> (Register.toRegID Q2A) "Q2A"
  let q2b = AST.var 64<rt> (Register.toRegID Q2B) "Q2B"
  let q3a = AST.var 64<rt> (Register.toRegID Q3A) "Q3A"
  let q3b = AST.var 64<rt> (Register.toRegID Q3B) "Q3B"
  let q4a = AST.var 64<rt> (Register.toRegID Q4A) "Q4A"
  let q4b = AST.var 64<rt> (Register.toRegID Q4B) "Q4B"
  let q5a = AST.var 64<rt> (Register.toRegID Q5A) "Q5A"
  let q5b = AST.var 64<rt> (Register.toRegID Q5B) "Q5B"
  let q6a = AST.var 64<rt> (Register.toRegID Q6A) "Q6A"
  let q6b = AST.var 64<rt> (Register.toRegID Q6B) "Q6B"
  let q7a = AST.var 64<rt> (Register.toRegID Q7A) "Q7A"
  let q7b = AST.var 64<rt> (Register.toRegID Q7B) "Q7B"
  let q8a = AST.var 64<rt> (Register.toRegID Q8A) "Q8A"
  let q8b = AST.var 64<rt> (Register.toRegID Q8B) "Q8B"
  let q9a = AST.var 64<rt> (Register.toRegID Q9A) "Q9A"
  let q9b = AST.var 64<rt> (Register.toRegID Q9B) "Q9B"
  let q10a = AST.var 64<rt> (Register.toRegID Q10A) "Q10A"
  let q10b = AST.var 64<rt> (Register.toRegID Q10B) "Q10B"
  let q11a = AST.var 64<rt> (Register.toRegID Q11A) "Q11A"
  let q11b = AST.var 64<rt> (Register.toRegID Q11B) "Q11B"
  let q12a = AST.var 64<rt> (Register.toRegID Q12A) "Q12A"
  let q12b = AST.var 64<rt> (Register.toRegID Q12B) "Q12B"
  let q13a = AST.var 64<rt> (Register.toRegID Q13A) "Q13A"
  let q13b = AST.var 64<rt> (Register.toRegID Q13B) "Q13B"
  let q14a = AST.var 64<rt> (Register.toRegID Q14A) "Q14A"
  let q14b = AST.var 64<rt> (Register.toRegID Q14B) "Q14B"
  let q15a = AST.var 64<rt> (Register.toRegID Q15A) "Q15A"
  let q15b = AST.var 64<rt> (Register.toRegID Q15B) "Q15B"
  let d0 = q0a
  let d1 = q0b
  let d2 = q1a
  let d3 = q1b
  let d4 = q2a
  let d5 = q2b
  let d6 = q3a
  let d7 = q3b
  let d8 = q4a
  let d9 = q4b
  let d10 = q5a
  let d11 = q5b
  let d12 = q6a
  let d13 = q6b
  let d14 = q7a
  let d15 = q7b
  let d16 = q8a
  let d17 = q8b
  let d18 = q9a
  let d19 = q9b
  let d20 = q10a
  let d21 = q10b
  let d22 = q11a
  let d23 = q11b
  let d24 = q12a
  let d25 = q12b
  let d26 = q13a
  let d27 = q13b
  let d28 = q14a
  let d29 = q14b
  let d30 = q15a
  let d31 = q15b
  let s0 = AST.xtlo 32<rt> d0
  let s1 = AST.xthi 32<rt> d0
  let s2 = AST.xtlo 32<rt> d1
  let s3 = AST.xthi 32<rt> d1
  let s4 = AST.xtlo 32<rt> d2
  let s5 = AST.xthi 32<rt> d2
  let s6 = AST.xtlo 32<rt> d3
  let s7 = AST.xthi 32<rt> d3
  let s8 = AST.xtlo 32<rt> d4
  let s9 = AST.xthi 32<rt> d4
  let s10 = AST.xtlo 32<rt> d5
  let s11 = AST.xthi 32<rt> d5
  let s12 = AST.xtlo 32<rt> d6
  let s13 = AST.xthi 32<rt> d6
  let s14 = AST.xtlo 32<rt> d7
  let s15 = AST.xthi 32<rt> d7
  let s16 = AST.xtlo 32<rt> d8
  let s17 = AST.xthi 32<rt> d8
  let s18 = AST.xtlo 32<rt> d9
  let s19 = AST.xthi 32<rt> d9
  let s20 = AST.xtlo 32<rt> d10
  let s21 = AST.xthi 32<rt> d10
  let s22 = AST.xtlo 32<rt> d11
  let s23 = AST.xthi 32<rt> d11
  let s24 = AST.xtlo 32<rt> d12
  let s25 = AST.xthi 32<rt> d12
  let s26 = AST.xtlo 32<rt> d13
  let s27 = AST.xthi 32<rt> d13
  let s28 = AST.xtlo 32<rt> d14
  let s29 = AST.xthi 32<rt> d14
  let s30 = AST.xtlo 32<rt> d15
  let s31 = AST.xthi 32<rt> d15

  (* Program counter *)
  let pc = AST.pcvar 32<rt> "PC"

  (* Program status registers *)
  let apsr = AST.var 32<rt> (Register.toRegID APSR) "APSR"
  let spsr = AST.var 32<rt> (Register.toRegID SPSR) "SPSR"
  let cpsr = AST.var 32<rt> (Register.toRegID CPSR) "CPSR"
  let fpscr = AST.var 32<rt> (Register.toRegID FPSCR) "FPSCR"

  (* System control register *)
  let sctlr = AST.var 32<rt> (Register.toRegID SCTLR) "SCTLR"

  (* Secure configuration register *)
  let scr = AST.var 32<rt> (Register.toRegID SCR) "SCR"

  (* Secure configuration register *)
  let nsacr = AST.var 32<rt> (Register.toRegID NSACR) "NSACR"

  (* SW thread ID register *)
  let tpidruro = AST.var 32<rt> (Register.toRegID TPIDRURO) "TPIDRURO"

  (* Extra pseudo registers for the value-based exclusive monitor. *)
  let exMonAddr = AST.var 32<rt> (Register.toRegID ExMonAddr) "ExMonAddr"
  let exMonVal = AST.var 32<rt> (Register.toRegID ExMonVal) "ExMonVal"

  (* Banked registers *)
  let r8usr = AST.var 32<rt> (Register.toRegID R8usr) "R8usr"
  let r9usr = AST.var 32<rt> (Register.toRegID R9usr) "R9usr"
  let r10usr = AST.var 32<rt> (Register.toRegID R10usr) "R10usr"
  let r11usr = AST.var 32<rt> (Register.toRegID R11usr) "R11usr"
  let r12usr = AST.var 32<rt> (Register.toRegID R12usr) "R12usr"
  let spusr = AST.var 32<rt> (Register.toRegID SPusr) "SPusr"
  let lrusr = AST.var 32<rt> (Register.toRegID LRusr) "LRusr"
  let sphyp = AST.var 32<rt> (Register.toRegID SPhyp) "SPhyp"
  let spsrhyp = AST.var 32<rt> (Register.toRegID SPSRhyp) "SPSRhyp"
  let elrhyp = AST.var 32<rt> (Register.toRegID ELRhyp) "ELRhyp"
  let spsvc = AST.var 32<rt> (Register.toRegID SPsvc) "SPsvc"
  let lrsvc = AST.var 32<rt> (Register.toRegID LRsvc) "LRsvc"
  let spsrsvc = AST.var 32<rt> (Register.toRegID SPSRsvc) "SPSRsvc"
  let spabt = AST.var 32<rt> (Register.toRegID SPabt) "SPabt"
  let lrabt = AST.var 32<rt> (Register.toRegID LRabt) "LRabt"
  let spsrabt = AST.var 32<rt> (Register.toRegID SPSRabt) "SPSRabt"
  let spund = AST.var 32<rt> (Register.toRegID SPund) "SPund"
  let lrund = AST.var 32<rt> (Register.toRegID LRund) "LRund"
  let spsrund = AST.var 32<rt> (Register.toRegID SPSRund) "SPSRund"
  let spmon = AST.var 32<rt> (Register.toRegID SPmon) "SPmon"
  let lrmon = AST.var 32<rt> (Register.toRegID LRmon) "LRmon"
  let spsrmon = AST.var 32<rt> (Register.toRegID SPSRmon) "SPSRmon"
  let spirq = AST.var 32<rt> (Register.toRegID SPirq) "SPirq"
  let lrirq = AST.var 32<rt> (Register.toRegID LRirq) "LRirq"
  let spsrirq = AST.var 32<rt> (Register.toRegID SPSRirq) "SPSRirq"
  let r8fiq = AST.var 32<rt> (Register.toRegID R8fiq) "R8fiq"
  let r9fiq = AST.var 32<rt> (Register.toRegID R9fiq) "R9fiq"
  let r10fiq = AST.var 32<rt> (Register.toRegID R10fiq) "R10fiq"
  let r11fiq = AST.var 32<rt> (Register.toRegID R11fiq) "R11fiq"
  let r12fiq = AST.var 32<rt> (Register.toRegID R12fiq) "R12fiq"
  let spfiq = AST.var 32<rt> (Register.toRegID SPfiq) "SPfiq"
  let lrfiq = AST.var 32<rt> (Register.toRegID LRfiq) "LRfiq"
  let spsrfiq = AST.var 32<rt> (Register.toRegID SPSRfiq) "SPSRfiq"

  (* Coprocessor 15 registers *)
  let midr = AST.var 32<rt> (Register.toRegID MIDR) "MIDR"
  let ctr = AST.var 32<rt> (Register.toRegID CTR) "CTR"
  let mpidr = AST.var 32<rt> (Register.toRegID MPIDR) "MPIDR"
  let idpfr0 = AST.var 32<rt> (Register.toRegID IDPFR0) "IDPFR0"
  let idpfr1 = AST.var 32<rt> (Register.toRegID IDPFR1) "IDPFR1"
  let iddfr0 = AST.var 32<rt> (Register.toRegID IDDFR0) "IDDFR0"
  let idafr0 = AST.var 32<rt> (Register.toRegID IDAFR0) "IDAFR0"
  let idmmfr0 = AST.var 32<rt> (Register.toRegID IDMMFR0) "IDMMFR0"
  let idmmfr1 = AST.var 32<rt> (Register.toRegID IDMMFR1) "IDMMFR1"
  let idmmfr2 = AST.var 32<rt> (Register.toRegID IDMMFR2) "IDMMFR2"
  let idmmfr3 = AST.var 32<rt> (Register.toRegID IDMMFR3) "IDMMFR3"
  let idisar0 = AST.var 32<rt> (Register.toRegID IDISAR0) "IDISAR0"
  let idisar1 = AST.var 32<rt> (Register.toRegID IDISAR1) "IDISAR1"
  let idisar2 = AST.var 32<rt> (Register.toRegID IDISAR2) "IDISAR2"
  let idisar3 = AST.var 32<rt> (Register.toRegID IDISAR3) "IDISAR3"
  let idisar4 = AST.var 32<rt> (Register.toRegID IDISAR4) "IDISAR4"
  let idisar5 = AST.var 32<rt> (Register.toRegID IDISAR5) "IDISAR5"
  let clidr = AST.var 32<rt> (Register.toRegID CLIDR) "CLIDR"
  let csselr = AST.var 32<rt> (Register.toRegID CSSELR) "CSSELR"
  let cpacr = AST.var 32<rt> (Register.toRegID CPACR) "CPACR"
  let ttbr0 = AST.var 32<rt> (Register.toRegID TTBR0) "TTBR0"
  let ttbr1 = AST.var 32<rt> (Register.toRegID TTBR1) "TTBR1"
  let ttbcr = AST.var 32<rt> (Register.toRegID TTBCR) "TTBCR"
  let dacr = AST.var 32<rt> (Register.toRegID DACR) "DACR"
  let dfsr = AST.var 32<rt> (Register.toRegID DFSR) "DFSR"
  let ifsr = AST.var 32<rt> (Register.toRegID IFSR) "IFSR"
  let dfar = AST.var 32<rt> (Register.toRegID DFAR) "DFAR"
  let ifar = AST.var 32<rt> (Register.toRegID IFAR) "IFAR"
  let par = AST.var 32<rt> (Register.toRegID PAR) "PAR"
  let prrr = AST.var 32<rt> (Register.toRegID PRRR) "PRRR"
  let nmrr = AST.var 32<rt> (Register.toRegID NMRR) "NMRR"
  let vbar = AST.var 32<rt> (Register.toRegID VBAR) "VBAR"
  let fcseidr = AST.var 32<rt> (Register.toRegID FCSEIDR) "FCSEIDR"
  let contextidr = AST.var 32<rt> (Register.toRegID CONTEXTIDR) "CONTEXTIDR"
  let tpidrurw = AST.var 32<rt> (Register.toRegID TPIDRURW) "TPIDRURW"
  let tpidrprw = AST.var 32<rt> (Register.toRegID TPIDRPRW) "TPIDRPRW"
  let cntfrq = AST.var 32<rt> (Register.toRegID CNTFRQ) "CNTFRQ"

  interface IRegisterFactory with
    member _.ISA = isa

    member _.ProgramCounter = PC |> Register.toRegID

    member _.StackPointer = SP |> Register.toRegID |> Some

    member _.FramePointer = FP |> Register.toRegID |> Some

    member _.GetRegVar name =
      match Register.ofRegID name with
      | R.R0 -> r0
      | R.R1 -> r1
      | R.R2 -> r2
      | R.R3 -> r3
      | R.R4 -> r4
      | R.R5 -> r5
      | R.R6 -> r6
      | R.R7 -> r7
      | R.R8 -> r8
      | R.SB -> sb
      | R.SL -> sl
      | R.FP -> fp
      | R.IP -> ip
      | R.SP -> sp
      | R.LR -> lr
      | R.PC -> pc
      | R.S0 -> s0
      | R.S1 -> s1
      | R.S2 -> s2
      | R.S3 -> s3
      | R.S4 -> s4
      | R.S5 -> s5
      | R.S6 -> s6
      | R.S7 -> s7
      | R.S8 -> s8
      | R.S9 -> s9
      | R.S10 -> s10
      | R.S11 -> s11
      | R.S12 -> s12
      | R.S13 -> s13
      | R.S14 -> s14
      | R.S15 -> s15
      | R.S16 -> s16
      | R.S17 -> s17
      | R.S18 -> s18
      | R.S19 -> s19
      | R.S20 -> s20
      | R.S21 -> s21
      | R.S22 -> s22
      | R.S23 -> s23
      | R.S24 -> s24
      | R.S25 -> s25
      | R.S26 -> s26
      | R.S27 -> s27
      | R.S28 -> s28
      | R.S29 -> s29
      | R.S30 -> s30
      | R.S31 -> s31
      | R.D0 -> d0
      | R.D1 -> d1
      | R.D2 -> d2
      | R.D3 -> d3
      | R.D4 -> d4
      | R.D5 -> d5
      | R.D6 -> d6
      | R.D7 -> d7
      | R.D8 -> d8
      | R.D9 -> d9
      | R.D10 -> d10
      | R.D11 -> d11
      | R.D12 -> d12
      | R.D13 -> d13
      | R.D14 -> d14
      | R.D15 -> d15
      | R.D16 -> d16
      | R.D17 -> d17
      | R.D18 -> d18
      | R.D19 -> d19
      | R.D20 -> d20
      | R.D21 -> d21
      | R.D22 -> d22
      | R.D23 -> d23
      | R.D24 -> d24
      | R.D25 -> d25
      | R.D26 -> d26
      | R.D27 -> d27
      | R.D28 -> d28
      | R.D29 -> d29
      | R.D30 -> d30
      | R.D31 -> d31
      | R.APSR -> apsr
      | R.SPSR -> spsr
      | R.CPSR -> cpsr
      | R.SCR -> scr
      | R.SCTLR -> sctlr
      | R.NSACR -> nsacr
      | R.FPSCR -> fpscr
      | R.TPIDRURO -> tpidruro
      | R.ExMonAddr -> exMonAddr
      | R.ExMonVal -> exMonVal
      | R.R8usr -> r8usr
      | R.R9usr -> r9usr
      | R.R10usr -> r10usr
      | R.R11usr -> r11usr
      | R.R12usr -> r12usr
      | R.SPusr -> spusr
      | R.LRusr -> lrusr
      | R.SPhyp -> sphyp
      | R.SPSRhyp -> spsrhyp
      | R.ELRhyp -> elrhyp
      | R.SPsvc -> spsvc
      | R.LRsvc -> lrsvc
      | R.SPSRsvc -> spsrsvc
      | R.SPabt -> spabt
      | R.LRabt -> lrabt
      | R.SPSRabt -> spsrabt
      | R.SPund -> spund
      | R.LRund -> lrund
      | R.SPSRund -> spsrund
      | R.SPmon -> spmon
      | R.LRmon -> lrmon
      | R.SPSRmon -> spsrmon
      | R.SPirq -> spirq
      | R.LRirq -> lrirq
      | R.SPSRirq -> spsrirq
      | R.R8fiq -> r8fiq
      | R.R9fiq -> r9fiq
      | R.R10fiq -> r10fiq
      | R.R11fiq -> r11fiq
      | R.R12fiq -> r12fiq
      | R.SPfiq -> spfiq
      | R.LRfiq -> lrfiq
      | R.SPSRfiq -> spsrfiq
      | R.MIDR -> midr
      | R.CTR -> ctr
      | R.MPIDR -> mpidr
      | R.IDPFR0 -> idpfr0
      | R.IDPFR1 -> idpfr1
      | R.IDDFR0 -> iddfr0
      | R.IDAFR0 -> idafr0
      | R.IDMMFR0 -> idmmfr0
      | R.IDMMFR1 -> idmmfr1
      | R.IDMMFR2 -> idmmfr2
      | R.IDMMFR3 -> idmmfr3
      | R.IDISAR0 -> idisar0
      | R.IDISAR1 -> idisar1
      | R.IDISAR2 -> idisar2
      | R.IDISAR3 -> idisar3
      | R.IDISAR4 -> idisar4
      | R.IDISAR5 -> idisar5
      | R.CLIDR -> clidr
      | R.CSSELR -> csselr
      | R.CPACR -> cpacr
      | R.TTBR0 -> ttbr0
      | R.TTBR1 -> ttbr1
      | R.TTBCR -> ttbcr
      | R.DACR -> dacr
      | R.DFSR -> dfsr
      | R.IFSR -> ifsr
      | R.DFAR -> dfar
      | R.IFAR -> ifar
      | R.PAR -> par
      | R.PRRR -> prrr
      | R.NMRR -> nmrr
      | R.VBAR -> vbar
      | R.FCSEIDR -> fcseidr
      | R.CONTEXTIDR -> contextidr
      | R.TPIDRURW -> tpidrurw
      | R.TPIDRPRW -> tpidrprw
      | R.CNTFRQ -> cntfrq
      | _ -> raise InvalidRegisterException

    member _.GetRegVar name =
      match name with
      | "R0" -> r0
      | "R1" -> r1
      | "R2" -> r2
      | "R3" -> r3
      | "R4" -> r4
      | "R5" -> r5
      | "R6" -> r6
      | "R7" -> r7
      | "R8" -> r8
      | "SB" -> sb
      | "SL" -> sl
      | "FP" -> fp
      | "IP" -> ip
      | "SP" -> sp
      | "LR" -> lr
      | "Q0A" -> q0a
      | "Q0B" -> q0b
      | "Q1A" -> q1a
      | "Q1B" -> q1b
      | "Q2A" -> q2a
      | "Q2B" -> q2b
      | "Q3A" -> q3a
      | "Q3B" -> q3b
      | "Q4A" -> q4a
      | "Q4B" -> q4b
      | "Q5A" -> q5a
      | "Q5B" -> q5b
      | "Q6A" -> q6a
      | "Q6B" -> q6b
      | "Q7A" -> q7a
      | "Q7B" -> q7b
      | "Q8A" -> q8a
      | "Q8B" -> q8b
      | "Q9A" -> q9a
      | "Q9B" -> q9b
      | "Q10A" -> q10a
      | "Q10B" -> q10b
      | "Q11A" -> q11a
      | "Q11B" -> q11b
      | "Q12A" -> q12a
      | "Q12B" -> q12b
      | "Q13A" -> q13a
      | "Q13B" -> q13b
      | "Q14A" -> q14a
      | "Q14B" -> q14b
      | "Q15A" -> q15a
      | "Q15B" -> q15b
      | "D0" -> d0
      | "D1" -> d1
      | "D2" -> d2
      | "D3" -> d3
      | "D4" -> d4
      | "D5" -> d5
      | "D6" -> d6
      | "D7" -> d7
      | "D8" -> d8
      | "D9" -> d9
      | "D10" -> d10
      | "D11" -> d11
      | "D12" -> d12
      | "D13" -> d13
      | "D14" -> d14
      | "D15" -> d15
      | "D16" -> d16
      | "D17" -> d17
      | "D18" -> d18
      | "D19" -> d19
      | "D20" -> d20
      | "D21" -> d21
      | "D22" -> d22
      | "D23" -> d23
      | "D24" -> d24
      | "D25" -> d25
      | "D26" -> d26
      | "D27" -> d27
      | "D28" -> d28
      | "D29" -> d29
      | "D30" -> d30
      | "D31" -> d31
      | "S0" -> s0
      | "S1" -> s1
      | "S2" -> s2
      | "S3" -> s3
      | "S4" -> s4
      | "S5" -> s5
      | "S6" -> s6
      | "S7" -> s7
      | "S8" -> s8
      | "S9" -> s9
      | "S10" -> s10
      | "S11" -> s11
      | "S12" -> s12
      | "S13" -> s13
      | "S14" -> s14
      | "S15" -> s15
      | "S16" -> s16
      | "S17" -> s17
      | "S18" -> s18
      | "S19" -> s19
      | "S20" -> s20
      | "S21" -> s21
      | "S22" -> s22
      | "S23" -> s23
      | "S24" -> s24
      | "S25" -> s25
      | "S26" -> s26
      | "S27" -> s27
      | "S28" -> s28
      | "S29" -> s29
      | "S30" -> s30
      | "S31" -> s31
      | "PC" -> pc
      | "APSR" -> apsr
      | "SPSR" -> spsr
      | "CPSR" -> cpsr
      | "FPSCR" -> fpscr
      | "SCTLR" -> sctlr
      | "SCR" -> scr
      | "NSACR" -> nsacr
      | "TPIDRURO" -> tpidruro
      | _ -> raise InvalidRegisterException

    member _.GetPseudoRegVar(rid, pos) =
      match Register.ofRegID rid, pos with
      | R.Q0, 1 -> q0a
      | R.Q0, 2 -> q0b
      | R.Q1, 1 -> q1a
      | R.Q1, 2 -> q1b
      | R.Q2, 1 -> q2a
      | R.Q2, 2 -> q2b
      | R.Q3, 1 -> q3a
      | R.Q3, 2 -> q3b
      | R.Q4, 1 -> q4a
      | R.Q4, 2 -> q4b
      | R.Q5, 1 -> q5a
      | R.Q5, 2 -> q5b
      | R.Q6, 1 -> q6a
      | R.Q6, 2 -> q6b
      | R.Q7, 1 -> q7a
      | R.Q7, 2 -> q7b
      | R.Q8, 1 -> q8a
      | R.Q8, 2 -> q8b
      | R.Q9, 1 -> q9a
      | R.Q9, 2 -> q9b
      | R.Q10, 1 -> q10a
      | R.Q10, 2 -> q10b
      | R.Q11, 1 -> q11a
      | R.Q11, 2 -> q11b
      | R.Q12, 1 -> q12a
      | R.Q12, 2 -> q12b
      | R.Q13, 1 -> q13a
      | R.Q13, 2 -> q13b
      | R.Q14, 1 -> q14a
      | R.Q14, 2 -> q14b
      | R.Q15, 1 -> q15a
      | R.Q15, 2 -> q15b
      | _ -> raise InvalidRegisterException

    member _.GetAllRegVars() =
      [| r0
         r1
         r2
         r3
         r4
         r5
         r6
         r7
         r8
         sb
         sl
         fp
         ip
         sp
         lr
         q0a
         q0b
         q1a
         q1b
         q2a
         q2b
         q3a
         q3b
         q4a
         q4b
         q5a
         q5b
         q6a
         q6b
         q7a
         q7b
         q8a
         q8b
         q9a
         q9b
         q10a
         q10b
         q11a
         q11b
         q12a
         q12b
         q13a
         q13b
         q14a
         q14b
         q15a
         q15b
         d0
         d1
         d2
         d3
         d4
         d5
         d6
         d7
         d8
         d9
         d10
         d11
         d12
         d13
         d14
         d15
         d16
         d17
         d18
         d19
         d20
         d21
         d22
         d23
         d24
         d25
         d26
         d27
         d28
         d29
         d30
         d31
         s0
         s1
         s2
         s3
         s4
         s5
         s6
         s7
         s8
         s9
         s10
         s11
         s12
         s13
         s14
         s15
         s16
         s17
         s18
         s19
         s20
         s21
         s22
         s23
         s24
         s25
         s26
         s27
         s28
         s29
         s30
         s31
         pc
         apsr
         spsr
         cpsr
         fpscr
         sctlr
         scr
         nsacr
         tpidruro
         r8usr
         r9usr
         r10usr
         r11usr
         r12usr
         spusr
         lrusr
         sphyp
         spsrhyp
         elrhyp
         spsvc
         lrsvc
         spsrsvc
         spabt
         lrabt
         spsrabt
         spund
         lrund
         spsrund
         spmon
         lrmon
         spsrmon
         spirq
         lrirq
         spsrirq
         r8fiq
         r9fiq
         r10fiq
         r11fiq
         r12fiq
         spfiq
         lrfiq
         spsrfiq
         midr
         ctr
         mpidr
         idpfr0
         idpfr1
         iddfr0
         idafr0
         idmmfr0
         idmmfr1
         idmmfr2
         idmmfr3
         idisar0
         idisar1
         idisar2
         idisar3
         idisar4
         idisar5
         clidr
         csselr
         cpacr
         ttbr0
         ttbr1
         ttbcr
         dacr
         dfsr
         ifsr
         dfar
         ifar
         par
         prrr
         nmrr
         vbar
         fcseidr
         contextidr
         tpidrurw
         tpidrprw
         cntfrq |]

    member _.GetGeneralRegVars() =
      [| r0
         r1
         r2
         r3
         r4
         r5
         r6
         r7
         r8
         sb
         sl
         fp
         ip
         sp
         lr
         pc
         apsr
         spsr
         cpsr |]

    member _.GetRegisterID expr =
      match expr with
      | Var(RegisterID = id) -> id
      | PCVar _ -> Register.toRegID PC
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name = Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases rid = [| rid |]

    member _.GetRegisterName rid = Register.ofRegID rid |> Register.toString

    member this.GetAllRegisterNames() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegisterName)

    member _.GetRegType rid = Register.ofRegID rid |> RegisterHelper.toRegType

    member _.IsProgramCounter regid =
      let pcid = PC |> Register.toRegID
      pcid = regid

    member _.IsStackPointer regid =
      let spid = SP |> Register.toRegID
      spid = regid

    member _.IsFramePointer regid =
      let fpid = FP |> Register.toRegID
      fpid = regid
