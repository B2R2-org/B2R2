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
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST

type internal RegExprs () =
  let var sz t name = AST.var sz t name (ARM32RegisterSet.singleton t)

  let q0 = var 128<rt> (Register.toRegID Register.Q0) "Q0"
  let q1 = var 128<rt> (Register.toRegID Register.Q1) "Q1"
  let q2 = var 128<rt> (Register.toRegID Register.Q2) "Q2"
  let q3 = var 128<rt> (Register.toRegID Register.Q3) "Q3"
  let q4 = var 128<rt> (Register.toRegID Register.Q4) "Q4"
  let q5 = var 128<rt> (Register.toRegID Register.Q5) "Q5"
  let q6 = var 128<rt> (Register.toRegID Register.Q6) "Q6"
  let q7 = var 128<rt> (Register.toRegID Register.Q7) "Q7"
  let q8 = var 128<rt> (Register.toRegID Register.Q8) "Q8"
  let q9 = var 128<rt> (Register.toRegID Register.Q9) "Q9"
  let q10 = var 128<rt> (Register.toRegID Register.Q10) "Q10"
  let q11 = var 128<rt> (Register.toRegID Register.Q11) "Q11"
  let q12 = var 128<rt> (Register.toRegID Register.Q12) "Q12"
  let q13 = var 128<rt> (Register.toRegID Register.Q13) "Q13"
  let q14 = var 128<rt> (Register.toRegID Register.Q14) "Q14"
  let q15 = var 128<rt> (Register.toRegID Register.Q15) "Q15"

  let d0 = extractLow 64<rt> q0
  let d1 = extractHigh 64<rt> q0
  let d2 = extractLow 64<rt> q1
  let d3 = extractHigh 64<rt> q1
  let d4 = extractLow 64<rt> q2
  let d5 = extractHigh 64<rt> q2
  let d6 = extractLow 64<rt> q3
  let d7 = extractHigh 64<rt> q3
  let d8 = extractLow 64<rt> q4
  let d9 = extractHigh 64<rt> q4
  let d10 = extractLow 64<rt> q5
  let d11 = extractHigh 64<rt> q5
  let d12 = extractLow 64<rt> q6
  let d13 = extractHigh 64<rt> q6
  let d14 = extractLow 64<rt> q7
  let d15 = extractHigh 64<rt> q7
  let d16 = extractLow 64<rt> q8
  let d17 = extractHigh 64<rt> q8
  let d18 = extractLow 64<rt> q9
  let d19 = extractHigh 64<rt> q9
  let d20 = extractLow 64<rt> q10
  let d21 = extractHigh 64<rt> q10
  let d22 = extractLow 64<rt> q11
  let d23 = extractHigh 64<rt> q11
  let d24 = extractLow 64<rt> q12
  let d25 = extractHigh 64<rt> q12
  let d26 = extractLow 64<rt> q13
  let d27 = extractHigh 64<rt> q13
  let d28 = extractLow 64<rt> q14
  let d29 = extractHigh 64<rt> q14
  let d30 = extractLow 64<rt> q15
  let d31 = extractHigh 64<rt> q15

  let s0 = extractLow 32<rt> d0
  let s1 = extractHigh 32<rt> d0
  let s2 = extractLow 32<rt> d1
  let s3 = extractHigh 32<rt> d1
  let s4 = extractLow 32<rt> d2
  let s5 = extractHigh 32<rt> d2
  let s6 = extractLow 32<rt> d3
  let s7 = extractHigh 32<rt> d3
  let s8 = extractLow 32<rt> d4
  let s9 = extractHigh 32<rt> d4
  let s10 = extractLow 32<rt> d5
  let s11 = extractHigh 32<rt> d5
  let s12 = extractLow 32<rt> d6
  let s13 = extractHigh 32<rt> d6
  let s14 = extractLow 32<rt> d7
  let s15 = extractHigh 32<rt> d7
  let s16 = extractLow 32<rt> d8
  let s17 = extractHigh 32<rt> d8
  let s18 = extractLow 32<rt> d9
  let s19 = extractHigh 32<rt> d9
  let s20 = extractLow 32<rt> d10
  let s21 = extractHigh 32<rt> d10
  let s22 = extractLow 32<rt> d11
  let s23 = extractHigh 32<rt> d11
  let s24 = extractLow 32<rt> d12
  let s25 = extractHigh 32<rt> d12
  let s26 = extractLow 32<rt> d13
  let s27 = extractHigh 32<rt> d13
  let s28 = extractLow 32<rt> d14
  let s29 = extractHigh 32<rt> d14
  let s30 = extractLow 32<rt> d15
  let s31 = extractHigh 32<rt> d15

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

  member val Q0 = q0 with get
  member val Q1 = q1 with get
  member val Q2 = q2 with get
  member val Q3 = q3 with get
  member val Q4 = q4 with get
  member val Q5 = q5 with get
  member val Q6 = q6 with get
  member val Q7 = q7 with get
  member val Q8 = q8 with get
  member val Q9 = q9 with get
  member val Q10 = q10 with get
  member val Q11 = q11 with get
  member val Q12 = q12 with get
  member val Q13 = q13 with get
  member val Q14 = q14 with get
  member val Q15 = q15 with get

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
  member val PC = pcVar 32<rt> "PC" with get

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
    | R.S0  -> __.S0
    | R.S1  -> __.S1
    | R.S2  -> __.S2
    | R.S3  -> __.S3
    | R.S4  -> __.S4
    | R.S5  -> __.S5
    | R.S6  -> __.S6
    | R.S7  -> __.S7
    | R.S8  -> __.S8
    | R.S9  -> __.S9
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
    | R.Q0 -> __.Q0
    | R.Q1 -> __.Q1
    | R.Q2 -> __.Q2
    | R.Q3 -> __.Q3
    | R.Q4 -> __.Q4
    | R.Q5 -> __.Q5
    | R.Q6 -> __.Q6
    | R.Q7 -> __.Q7
    | R.Q8 -> __.Q8
    | R.Q9 -> __.Q9
    | R.Q10 -> __.Q10
    | R.Q11 -> __.Q11
    | R.Q12 -> __.Q12
    | R.Q13 -> __.Q13
    | R.Q14 -> __.Q14
    | R.Q15 -> __.Q15
    | R.APSR -> __.APSR
    | R.SPSR -> __.SPSR
    | R.CPSR -> __.CPSR
    | R.SCR -> __.SCR
    | R.SCTLR -> __.SCTLR
    | R.NSACR -> __.NSACR
    | R.FPSCR -> __.FPSCR
    | _ -> raise B2R2.FrontEnd.BinLifter.UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
