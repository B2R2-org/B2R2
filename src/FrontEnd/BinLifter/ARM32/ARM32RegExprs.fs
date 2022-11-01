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
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type internal RegExprs () =
  let var sz t name = AST.var sz t name (ARM32RegisterSet.singleton t)

  let q0a = var 64<rt> (Register.toRegID Register.Q0A) "Q0A"
  let q0b = var 64<rt> (Register.toRegID Register.Q0B) "Q0B"
  let q1a = var 64<rt> (Register.toRegID Register.Q1A) "Q1A"
  let q1b = var 64<rt> (Register.toRegID Register.Q1B) "Q1B"
  let q2a = var 64<rt> (Register.toRegID Register.Q2A) "Q2A"
  let q2b = var 64<rt> (Register.toRegID Register.Q2B) "Q2B"
  let q3a = var 64<rt> (Register.toRegID Register.Q3A) "Q3A"
  let q3b = var 64<rt> (Register.toRegID Register.Q3B) "Q3B"
  let q4a = var 64<rt> (Register.toRegID Register.Q4A) "Q4A"
  let q4b = var 64<rt> (Register.toRegID Register.Q4B) "Q4B"
  let q5a = var 64<rt> (Register.toRegID Register.Q5A) "Q5A"
  let q5b = var 64<rt> (Register.toRegID Register.Q5B) "Q5B"
  let q6a = var 64<rt> (Register.toRegID Register.Q6A) "Q6A"
  let q6b = var 64<rt> (Register.toRegID Register.Q6B) "Q6B"
  let q7a = var 64<rt> (Register.toRegID Register.Q7A) "Q7A"
  let q7b = var 64<rt> (Register.toRegID Register.Q7B) "Q7B"
  let q8a = var 64<rt> (Register.toRegID Register.Q8A) "Q8A"
  let q8b = var 64<rt> (Register.toRegID Register.Q8B) "Q8B"
  let q9a = var 64<rt> (Register.toRegID Register.Q9A) "Q9A"
  let q9b = var 64<rt> (Register.toRegID Register.Q9B) "Q9B"
  let q10a = var 64<rt> (Register.toRegID Register.Q10A) "Q10A"
  let q10b = var 64<rt> (Register.toRegID Register.Q10B) "Q10B"
  let q11a = var 64<rt> (Register.toRegID Register.Q11A) "Q11A"
  let q11b = var 64<rt> (Register.toRegID Register.Q11B) "Q11B"
  let q12a = var 64<rt> (Register.toRegID Register.Q12A) "Q12A"
  let q12b = var 64<rt> (Register.toRegID Register.Q12B) "Q12B"
  let q13a = var 64<rt> (Register.toRegID Register.Q13A) "Q13A"
  let q13b = var 64<rt> (Register.toRegID Register.Q13B) "Q13B"
  let q14a = var 64<rt> (Register.toRegID Register.Q14A) "Q14A"
  let q14b = var 64<rt> (Register.toRegID Register.Q14B) "Q14B"
  let q15a = var 64<rt> (Register.toRegID Register.Q15A) "Q15A"
  let q15b = var 64<rt> (Register.toRegID Register.Q15B) "Q15B"

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

  member val R0 = var 32<rt> (Register.toRegID Register.R0) "R0" with get
  member val R1 = var 32<rt> (Register.toRegID Register.R1) "R1" with get
  member val R2 = var 32<rt> (Register.toRegID Register.R2) "R2" with get
  member val R3 = var 32<rt> (Register.toRegID Register.R3) "R3" with get
  member val R4 = var 32<rt> (Register.toRegID Register.R4) "R4" with get
  member val R5 = var 32<rt> (Register.toRegID Register.R5) "R5" with get
  member val R6 = var 32<rt> (Register.toRegID Register.R6) "R6" with get
  member val R7 = var 32<rt> (Register.toRegID Register.R7) "R7" with get
  member val R8 = var 32<rt> (Register.toRegID Register.R8) "R8" with get
  member val SB = var 32<rt> (Register.toRegID Register.SB) "SB" with get
  member val SL = var 32<rt> (Register.toRegID Register.SL) "SL" with get
  member val FP = var 32<rt> (Register.toRegID Register.FP) "FP" with get
  member val IP = var 32<rt> (Register.toRegID Register.IP) "IP" with get
  member val SP = var 32<rt> (Register.toRegID Register.SP) "SP" with get
  member val LR = var 32<rt> (Register.toRegID Register.LR) "LR" with get

  member val Q0A = q0a with get
  member val Q0B = q0b with get
  member val Q1A = q1a with get
  member val Q1B = q1b with get
  member val Q2A = q2a with get
  member val Q2B = q2b with get
  member val Q3A = q3a with get
  member val Q3B = q3b with get
  member val Q4A = q4a with get
  member val Q4B = q4b with get
  member val Q5A = q5a with get
  member val Q5B = q5b with get
  member val Q6A = q6a with get
  member val Q6B = q6b with get
  member val Q7A = q7a with get
  member val Q7B = q7b with get
  member val Q8A = q8a with get
  member val Q8B = q8b with get
  member val Q9A = q9a with get
  member val Q9B = q9b with get
  member val Q10A = q10a with get
  member val Q10B = q10b with get
  member val Q11A = q11a with get
  member val Q11B = q11b with get
  member val Q12A = q12a with get
  member val Q12B = q12b with get
  member val Q13A = q13a with get
  member val Q13B = q13b with get
  member val Q14A = q14a with get
  member val Q14B = q14b with get
  member val Q15A = q15a with get
  member val Q15B = q15b with get

  member val D0 = d0 with get
  member val D1 = d1 with get
  member val D2 = d2 with get
  member val D3 = d3 with get
  member val D4 = d4 with get
  member val D5 = d5 with get
  member val D6 = d6 with get
  member val D7 = d7 with get
  member val D8 = d8 with get
  member val D9 = d9 with get
  member val D10 = d10 with get
  member val D11 = d11 with get
  member val D12 = d12 with get
  member val D13 = d13 with get
  member val D14 = d14 with get
  member val D15 = d15 with get
  member val D16 = d16 with get
  member val D17 = d17 with get
  member val D18 = d18 with get
  member val D19 = d19 with get
  member val D20 = d20 with get
  member val D21 = d21 with get
  member val D22 = d22 with get
  member val D23 = d23 with get
  member val D24 = d24 with get
  member val D25 = d25 with get
  member val D26 = d26 with get
  member val D27 = d27 with get
  member val D28 = d28 with get
  member val D29 = d29 with get
  member val D30 = d30 with get
  member val D31 = d31 with get

  member val S0 = s0 with get
  member val S1 = s1 with get
  member val S2 = s2 with get
  member val S3 = s3 with get
  member val S4 = s4 with get
  member val S5 = s5 with get
  member val S6 = s6 with get
  member val S7 = s7 with get
  member val S8 = s8 with get
  member val S9 = s9 with get
  member val S10 = s10 with get
  member val S11 = s11 with get
  member val S12 = s12 with get
  member val S13 = s13 with get
  member val S14 = s14 with get
  member val S15 = s15 with get
  member val S16 = s16 with get
  member val S17 = s17 with get
  member val S18 = s18 with get
  member val S19 = s19 with get
  member val S20 = s20 with get
  member val S21 = s21 with get
  member val S22 = s22 with get
  member val S23 = s23 with get
  member val S24 = s24 with get
  member val S25 = s25 with get
  member val S26 = s26 with get
  member val S27 = s27 with get
  member val S28 = s28 with get
  member val S29 = s29 with get
  member val S30 = s30 with get
  member val S31 = s31 with get

  (* Program counters *)
  member val PC = AST.pcvar 32<rt> "PC" with get

  (*Program Status Register*)
  member val APSR = var 32<rt> (Register.toRegID Register.APSR) "APSR" with get
  member val SPSR = var 32<rt> (Register.toRegID Register.SPSR) "SPSR" with get
  member val CPSR = var 32<rt> (Register.toRegID Register.CPSR) "CPSR" with get
  member val FPSCR =
    var 32<rt> (Register.toRegID Register.FPSCR) "FPSCR" with get

  (* System Control register *)
  member val SCTLR =
    var 32<rt> (Register.toRegID Register.SCTLR) "SCTLR" with get

  (* Secure Configuration register *)
  member val SCR = var 32<rt> (Register.toRegID Register.SCR) "SCR" with get

  (* Secure Configuration register *)
  member val NSACR =
    var 32<rt> (Register.toRegID Register.NSACR) "NSACR" with get

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
    | R.SB -> __.SB
    | R.SL -> __.SL
    | R.FP -> __.FP
    | R.IP -> __.IP
    | R.SP -> __.SP
    | R.LR -> __.LR
    | R.PC -> __.PC
    | R.S0 -> __.S0
    | R.S1 -> __.S1
    | R.S2 -> __.S2
    | R.S3 -> __.S3
    | R.S4 -> __.S4
    | R.S5 -> __.S5
    | R.S6 -> __.S6
    | R.S7 -> __.S7
    | R.S8 -> __.S8
    | R.S9 -> __.S9
    | R.S10 -> __.S10
    | R.S11 -> __.S11
    | R.S12 -> __.S12
    | R.S13 -> __.S13
    | R.S14 -> __.S14
    | R.S15 -> __.S15
    | R.S16 -> __.S16
    | R.S17 -> __.S17
    | R.S18 -> __.S18
    | R.S19 -> __.S19
    | R.S20 -> __.S20
    | R.S21 -> __.S21
    | R.S22 -> __.S22
    | R.S23 -> __.S23
    | R.S24 -> __.S24
    | R.S25 -> __.S25
    | R.S26 -> __.S26
    | R.S27 -> __.S27
    | R.S28 -> __.S28
    | R.S29 -> __.S29
    | R.S30 -> __.S30
    | R.S31 -> __.S31
    | R.D0 -> __.D0
    | R.D1 -> __.D1
    | R.D2 -> __.D2
    | R.D3 -> __.D3
    | R.D4 -> __.D4
    | R.D5 -> __.D5
    | R.D6 -> __.D6
    | R.D7 -> __.D7
    | R.D8 -> __.D8
    | R.D9 -> __.D9
    | R.D10 -> __.D10
    | R.D11 -> __.D11
    | R.D12 -> __.D12
    | R.D13 -> __.D13
    | R.D14 -> __.D14
    | R.D15 -> __.D15
    | R.D16 -> __.D16
    | R.D17 -> __.D17
    | R.D18 -> __.D18
    | R.D19 -> __.D19
    | R.D20 -> __.D20
    | R.D21 -> __.D21
    | R.D22 -> __.D22
    | R.D23 -> __.D23
    | R.D24 -> __.D24
    | R.D25 -> __.D25
    | R.D26 -> __.D26
    | R.D27 -> __.D27
    | R.D28 -> __.D28
    | R.D29 -> __.D29
    | R.D30 -> __.D30
    | R.D31 -> __.D31
    | R.APSR -> __.APSR
    | R.SPSR -> __.SPSR
    | R.CPSR -> __.CPSR
    | R.SCR -> __.SCR
    | R.SCTLR -> __.SCTLR
    | R.NSACR -> __.NSACR
    | R.FPSCR -> __.FPSCR
    | _ -> raise UnhandledRegExprException

  member __.GetPseudoRegVar name pos =
    match name, pos with
    | R.Q0, 1 -> __.Q0A
    | R.Q0, 2 -> __.Q0B
    | R.Q1, 1 -> __.Q1A
    | R.Q1, 2 -> __.Q1B
    | R.Q2, 1 -> __.Q2A
    | R.Q2, 2 -> __.Q2B
    | R.Q3, 1 -> __.Q3A
    | R.Q3, 2 -> __.Q3B
    | R.Q4, 1 -> __.Q4A
    | R.Q4, 2 -> __.Q4B
    | R.Q5, 1 -> __.Q5A
    | R.Q5, 2 -> __.Q5B
    | R.Q6, 1 -> __.Q6A
    | R.Q6, 2 -> __.Q6B
    | R.Q7, 1 -> __.Q7A
    | R.Q7, 2 -> __.Q7B
    | R.Q8, 1 -> __.Q8A
    | R.Q8, 2 -> __.Q8B
    | R.Q9, 1 -> __.Q9A
    | R.Q9, 2 -> __.Q9B
    | R.Q10, 1 -> __.Q10A
    | R.Q10, 2 -> __.Q10B
    | R.Q11, 1 -> __.Q11A
    | R.Q11, 2 -> __.Q11B
    | R.Q12, 1 -> __.Q12A
    | R.Q12, 2 -> __.Q12B
    | R.Q13, 1 -> __.Q13A
    | R.Q13, 2 -> __.Q13B
    | R.Q14, 1 -> __.Q14A
    | R.Q14, 2 -> __.Q14B
    | R.Q15, 1 -> __.Q15A
    | R.Q15, 2 -> __.Q15B
    | _ -> raise UnhandledRegExprException


// vim: set tw=80 sts=2 sw=2:
