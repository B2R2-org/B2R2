(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Seung Il Jung <sijung@kaist.ac.kr>

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

namespace B2R2.FrontEnd.ARM64

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST

type internal RegExprs () =
  let var sz t name = AST.var sz t name (ARM64RegisterSet.singleton t)

  (* Registers *)
  let r0  = var 64<rt> (Register.toRegID Register.X0) "X0"
  let r1  = var 64<rt> (Register.toRegID Register.X1) "X1"
  let r2  = var 64<rt> (Register.toRegID Register.X2) "X2"
  let r3  = var 64<rt> (Register.toRegID Register.X3) "X3"
  let r4  = var 64<rt> (Register.toRegID Register.X4) "X4"
  let r5  = var 64<rt> (Register.toRegID Register.X5) "X5"
  let r6  = var 64<rt> (Register.toRegID Register.X6) "X6"
  let r7  = var 64<rt> (Register.toRegID Register.X7) "X7"
  let r8  = var 64<rt> (Register.toRegID Register.X8) "X8"
  let r9  = var 64<rt> (Register.toRegID Register.X9) "X9"
  let r10 = var 64<rt> (Register.toRegID Register.X10) "X10"
  let r11 = var 64<rt> (Register.toRegID Register.X11) "X11"
  let r12 = var 64<rt> (Register.toRegID Register.X12) "X12"
  let r13 = var 64<rt> (Register.toRegID Register.X13) "X13"
  let r14 = var 64<rt> (Register.toRegID Register.X14) "X14"
  let r15 = var 64<rt> (Register.toRegID Register.X15) "X15"
  let r16 = var 64<rt> (Register.toRegID Register.X16) "X16"
  let r17 = var 64<rt> (Register.toRegID Register.X17) "X17"
  let r18 = var 64<rt> (Register.toRegID Register.X18) "X18"
  let r19 = var 64<rt> (Register.toRegID Register.X19) "X19"
  let r20 = var 64<rt> (Register.toRegID Register.X20) "X20"
  let r21 = var 64<rt> (Register.toRegID Register.X21) "X21"
  let r22 = var 64<rt> (Register.toRegID Register.X22) "X22"
  let r23 = var 64<rt> (Register.toRegID Register.X23) "X23"
  let r24 = var 64<rt> (Register.toRegID Register.X24) "X24"
  let r25 = var 64<rt> (Register.toRegID Register.X25) "X25"
  let r26 = var 64<rt> (Register.toRegID Register.X26) "X26"
  let r27 = var 64<rt> (Register.toRegID Register.X27) "X27"
  let r28 = var 64<rt> (Register.toRegID Register.X28) "X28"
  let r29 = var 64<rt> (Register.toRegID Register.X29) "X29"
  let r30 = var 64<rt> (Register.toRegID Register.X30) "X30"
  let xzr = var 64<rt> (Register.toRegID Register.XZR) "XZR"
  let sp = var 64<rt> (Register.toRegID Register.SP) "SP"
  let pc = pcVar 64<rt> "PC"

  let w0  = extractLow 32<rt> r0
  let w1  = extractLow 32<rt> r1
  let w2  = extractLow 32<rt> r2
  let w3  = extractLow 32<rt> r3
  let w4  = extractLow 32<rt> r4
  let w5  = extractLow 32<rt> r5
  let w6  = extractLow 32<rt> r6
  let w7  = extractLow 32<rt> r7
  let w8  = extractLow 32<rt> r8
  let w9  = extractLow 32<rt> r9
  let w10 = extractLow 32<rt> r10
  let w11 = extractLow 32<rt> r11
  let w12 = extractLow 32<rt> r12
  let w13 = extractLow 32<rt> r13
  let w14 = extractLow 32<rt> r14
  let w15 = extractLow 32<rt> r15
  let w16 = extractLow 32<rt> r16
  let w17 = extractLow 32<rt> r17
  let w18 = extractLow 32<rt> r18
  let w19 = extractLow 32<rt> r19
  let w20 = extractLow 32<rt> r20
  let w21 = extractLow 32<rt> r21
  let w22 = extractLow 32<rt> r22
  let w23 = extractLow 32<rt> r23
  let w24 = extractLow 32<rt> r24
  let w25 = extractLow 32<rt> r25
  let w26 = extractLow 32<rt> r26
  let w27 = extractLow 32<rt> r27
  let w28 = extractLow 32<rt> r28
  let w29 = extractLow 32<rt> r29
  let w30 = extractLow 32<rt> r30
  let wzr = extractLow 32<rt> xzr
  let wsp = extractLow 32<rt> sp

  let v0  = var 128<rt> (Register.toRegID Register.V0) "V0"
  let v1  = var 128<rt> (Register.toRegID Register.V1) "V1"
  let v2  = var 128<rt> (Register.toRegID Register.V2) "V2"
  let v3  = var 128<rt> (Register.toRegID Register.V3) "V3"
  let v4  = var 128<rt> (Register.toRegID Register.V4) "V4"
  let v5  = var 128<rt> (Register.toRegID Register.V5) "V5"
  let v6  = var 128<rt> (Register.toRegID Register.V6) "V6"
  let v7  = var 128<rt> (Register.toRegID Register.V7) "V7"
  let v8  = var 128<rt> (Register.toRegID Register.V8) "V8"
  let v9  = var 128<rt> (Register.toRegID Register.V9) "V9"
  let v10 = var 128<rt> (Register.toRegID Register.V10) "V10"
  let v11 = var 128<rt> (Register.toRegID Register.V11) "V11"
  let v12 = var 128<rt> (Register.toRegID Register.V12) "V12"
  let v13 = var 128<rt> (Register.toRegID Register.V13) "V13"
  let v14 = var 128<rt> (Register.toRegID Register.V14) "V14"
  let v15 = var 128<rt> (Register.toRegID Register.V15) "V15"
  let v16 = var 128<rt> (Register.toRegID Register.V16) "V16"
  let v17 = var 128<rt> (Register.toRegID Register.V17) "V17"
  let v18 = var 128<rt> (Register.toRegID Register.V18) "V18"
  let v19 = var 128<rt> (Register.toRegID Register.V19) "V19"
  let v20 = var 128<rt> (Register.toRegID Register.V20) "V20"
  let v21 = var 128<rt> (Register.toRegID Register.V21) "V21"
  let v22 = var 128<rt> (Register.toRegID Register.V22) "V22"
  let v23 = var 128<rt> (Register.toRegID Register.V23) "V23"
  let v24 = var 128<rt> (Register.toRegID Register.V24) "V24"
  let v25 = var 128<rt> (Register.toRegID Register.V25) "V25"
  let v26 = var 128<rt> (Register.toRegID Register.V26) "V26"
  let v27 = var 128<rt> (Register.toRegID Register.V27) "V27"
  let v28 = var 128<rt> (Register.toRegID Register.V28) "V28"
  let v29 = var 128<rt> (Register.toRegID Register.V29) "V29"
  let v30 = var 128<rt> (Register.toRegID Register.V30) "V30"
  let v31 = var 128<rt> (Register.toRegID Register.V31) "V31"

  let d0  = extractLow 64<rt> v0
  let d1  = extractLow 64<rt> v1
  let d2  = extractLow 64<rt> v2
  let d3  = extractLow 64<rt> v3
  let d4  = extractLow 64<rt> v4
  let d5  = extractLow 64<rt> v5
  let d6  = extractLow 64<rt> v6
  let d7  = extractLow 64<rt> v7
  let d8  = extractLow 64<rt> v8
  let d9  = extractLow 64<rt> v9
  let d10 = extractLow 64<rt> v10
  let d11 = extractLow 64<rt> v11
  let d12 = extractLow 64<rt> v12
  let d13 = extractLow 64<rt> v13
  let d14 = extractLow 64<rt> v14
  let d15 = extractLow 64<rt> v15
  let d16 = extractLow 64<rt> v16
  let d17 = extractLow 64<rt> v17
  let d18 = extractLow 64<rt> v18
  let d19 = extractLow 64<rt> v19
  let d20 = extractLow 64<rt> v20
  let d21 = extractLow 64<rt> v21
  let d22 = extractLow 64<rt> v22
  let d23 = extractLow 64<rt> v23
  let d24 = extractLow 64<rt> v24
  let d25 = extractLow 64<rt> v25
  let d26 = extractLow 64<rt> v26
  let d27 = extractLow 64<rt> v27
  let d28 = extractLow 64<rt> v28
  let d29 = extractLow 64<rt> v29
  let d30 = extractLow 64<rt> v30
  let d31 = extractLow 64<rt> v31

  let s0  = extractLow 32<rt> v0
  let s1  = extractLow 32<rt> v1
  let s2  = extractLow 32<rt> v2
  let s3  = extractLow 32<rt> v3
  let s4  = extractLow 32<rt> v4
  let s5  = extractLow 32<rt> v5
  let s6  = extractLow 32<rt> v6
  let s7  = extractLow 32<rt> v7
  let s8  = extractLow 32<rt> v8
  let s9  = extractLow 32<rt> v9
  let s10 = extractLow 32<rt> v10
  let s11 = extractLow 32<rt> v11
  let s12 = extractLow 32<rt> v12
  let s13 = extractLow 32<rt> v13
  let s14 = extractLow 32<rt> v14
  let s15 = extractLow 32<rt> v15
  let s16 = extractLow 32<rt> v16
  let s17 = extractLow 32<rt> v17
  let s18 = extractLow 32<rt> v18
  let s19 = extractLow 32<rt> v19
  let s20 = extractLow 32<rt> v20
  let s21 = extractLow 32<rt> v21
  let s22 = extractLow 32<rt> v22
  let s23 = extractLow 32<rt> v23
  let s24 = extractLow 32<rt> v24
  let s25 = extractLow 32<rt> v25
  let s26 = extractLow 32<rt> v26
  let s27 = extractLow 32<rt> v27
  let s28 = extractLow 32<rt> v28
  let s29 = extractLow 32<rt> v29
  let s30 = extractLow 32<rt> v30
  let s31 = extractLow 32<rt> v31

  let h0  = extractLow 16<rt> v0
  let h1  = extractLow 16<rt> v1
  let h2  = extractLow 16<rt> v2
  let h3  = extractLow 16<rt> v3
  let h4  = extractLow 16<rt> v4
  let h5  = extractLow 16<rt> v5
  let h6  = extractLow 16<rt> v6
  let h7  = extractLow 16<rt> v7
  let h8  = extractLow 16<rt> v8
  let h9  = extractLow 16<rt> v9
  let h10 = extractLow 16<rt> v10
  let h11 = extractLow 16<rt> v11
  let h12 = extractLow 16<rt> v12
  let h13 = extractLow 16<rt> v13
  let h14 = extractLow 16<rt> v14
  let h15 = extractLow 16<rt> v15
  let h16 = extractLow 16<rt> v16
  let h17 = extractLow 16<rt> v17
  let h18 = extractLow 16<rt> v18
  let h19 = extractLow 16<rt> v19
  let h20 = extractLow 16<rt> v20
  let h21 = extractLow 16<rt> v21
  let h22 = extractLow 16<rt> v22
  let h23 = extractLow 16<rt> v23
  let h24 = extractLow 16<rt> v24
  let h25 = extractLow 16<rt> v25
  let h26 = extractLow 16<rt> v26
  let h27 = extractLow 16<rt> v27
  let h28 = extractLow 16<rt> v28
  let h29 = extractLow 16<rt> v29
  let h30 = extractLow 16<rt> v30
  let h31 = extractLow 16<rt> v31

  let b0  = extractLow 8<rt> v0
  let b1  = extractLow 8<rt> v1
  let b2  = extractLow 8<rt> v2
  let b3  = extractLow 8<rt> v3
  let b4  = extractLow 8<rt> v4
  let b5  = extractLow 8<rt> v5
  let b6  = extractLow 8<rt> v6
  let b7  = extractLow 8<rt> v7
  let b8  = extractLow 8<rt> v8
  let b9  = extractLow 8<rt> v9
  let b10 = extractLow 8<rt> v10
  let b11 = extractLow 8<rt> v11
  let b12 = extractLow 8<rt> v12
  let b13 = extractLow 8<rt> v13
  let b14 = extractLow 8<rt> v14
  let b15 = extractLow 8<rt> v15
  let b16 = extractLow 8<rt> v16
  let b17 = extractLow 8<rt> v17
  let b18 = extractLow 8<rt> v18
  let b19 = extractLow 8<rt> v19
  let b20 = extractLow 8<rt> v20
  let b21 = extractLow 8<rt> v21
  let b22 = extractLow 8<rt> v22
  let b23 = extractLow 8<rt> v23
  let b24 = extractLow 8<rt> v24
  let b25 = extractLow 8<rt> v25
  let b26 = extractLow 8<rt> v26
  let b27 = extractLow 8<rt> v27
  let b28 = extractLow 8<rt> v28
  let b29 = extractLow 8<rt> v29
  let b30 = extractLow 8<rt> v30
  let b31 = extractLow 8<rt> v31

  (* General-purpose registers *)
  member val X0  = r0 with get
  member val X1  = r1 with get
  member val X2  = r2 with get
  member val X3  = r3 with get
  member val X4  = r4 with get
  member val X5  = r5 with get
  member val X6  = r6 with get
  member val X7  = r7 with get
  member val X8  = r8 with get
  member val X9  = r9 with get
  member val X10 = r10 with get
  member val X11 = r11 with get
  member val X12 = r12 with get
  member val X13 = r13 with get
  member val X14 = r14 with get
  member val X15 = r15 with get
  member val X16 = r16 with get
  member val X17 = r17 with get
  member val X18 = r18 with get
  member val X19 = r19 with get
  member val X20 = r20 with get
  member val X21 = r21 with get
  member val X22 = r22 with get
  member val X23 = r23 with get
  member val X24 = r24 with get
  member val X25 = r25 with get
  member val X26 = r26 with get
  member val X27 = r27 with get
  member val X28 = r28 with get
  member val X29 = r29 with get
  member val X30 = r30 with get
  member val XZR = xzr with get
  member val W0  = w0 with get
  member val W1  = w1 with get
  member val W2  = w2 with get
  member val W3  = w3 with get
  member val W4  = w4 with get
  member val W5  = w5 with get
  member val W6  = w6 with get
  member val W7  = w7 with get
  member val W8  = w8 with get
  member val W9  = w9 with get
  member val W10 = w10 with get
  member val W11 = w11 with get
  member val W12 = w12 with get
  member val W13 = w13 with get
  member val W14 = w14 with get
  member val W15 = w15 with get
  member val W16 = w16 with get
  member val W17 = w17 with get
  member val W18 = w18 with get
  member val W19 = w19 with get
  member val W20 = w20 with get
  member val W21 = w21 with get
  member val W22 = w22 with get
  member val W23 = w23 with get
  member val W24 = w24 with get
  member val W25 = w25 with get
  member val W26 = w26 with get
  member val W27 = w27 with get
  member val W28 = w28 with get
  member val W29 = w29 with get
  member val W30 = w30 with get
  member val WZR = wzr with get

  (* Stack Pointer register *)
  member val SP  = sp with get
  member val WSP = wsp with get

  (* Program Couter *)
  member val PC  = pc with get

  (* 32 SIMD&FP registers *)
  (* 128-bit registers *)
  member val V0  = v0 with get
  member val V1  = v1 with get
  member val V2  = v2 with get
  member val V3  = v3 with get
  member val V4  = v4 with get
  member val V5  = v5 with get
  member val V6  = v6 with get
  member val V7  = v7 with get
  member val V8  = v8 with get
  member val V9  = v9 with get
  member val V10 = v10 with get
  member val V11 = v11 with get
  member val V12 = v12 with get
  member val V13 = v13 with get
  member val V14 = v14 with get
  member val V15 = v15 with get
  member val V16 = v16 with get
  member val V17 = v17 with get
  member val V18 = v18 with get
  member val V19 = v19 with get
  member val V20 = v20 with get
  member val V21 = v21 with get
  member val V22 = v22 with get
  member val V23 = v23 with get
  member val V24 = v24 with get
  member val V25 = v25 with get
  member val V26 = v26 with get
  member val V27 = v27 with get
  member val V28 = v28 with get
  member val V29 = v29 with get
  member val V30 = v30 with get
  member val V31 = v31 with get

  (* 128-bit registers *)
  member val Q0  = v0 with get
  member val Q1  = v1 with get
  member val Q2  = v2 with get
  member val Q3  = v3 with get
  member val Q4  = v4 with get
  member val Q5  = v5 with get
  member val Q6  = v6 with get
  member val Q7  = v7 with get
  member val Q8  = v8 with get
  member val Q9  = v9 with get
  member val Q10 = v10 with get
  member val Q11 = v11 with get
  member val Q12 = v12 with get
  member val Q13 = v13 with get
  member val Q14 = v14 with get
  member val Q15 = v15 with get
  member val Q16 = v16 with get
  member val Q17 = v17 with get
  member val Q18 = v18 with get
  member val Q19 = v19 with get
  member val Q20 = v20 with get
  member val Q21 = v21 with get
  member val Q22 = v22 with get
  member val Q23 = v23 with get
  member val Q24 = v24 with get
  member val Q25 = v25 with get
  member val Q26 = v26 with get
  member val Q27 = v27 with get
  member val Q28 = v28 with get
  member val Q29 = v29 with get
  member val Q30 = v30 with get
  member val Q31 = v31 with get

  (* 64-bit registers *)
  member val D0  = d0 with get
  member val D1  = d1 with get
  member val D2  = d2 with get
  member val D3  = d3 with get
  member val D4  = d4 with get
  member val D5  = d5 with get
  member val D6  = d6 with get
  member val D7  = d7 with get
  member val D8  = d8 with get
  member val D9  = d9 with get
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

  (* 32-bit registers *)
  member val S0  = s0 with get
  member val S1  = s1 with get
  member val S2  = s2 with get
  member val S3  = s3 with get
  member val S4  = s4 with get
  member val S5  = s5 with get
  member val S6  = s6 with get
  member val S7  = s7 with get
  member val S8  = s8 with get
  member val S9  = s9 with get
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

  (* 128-bit registers *)
  member val H0  = h0 with get
  member val H1  = h1 with get
  member val H2  = h2 with get
  member val H3  = h3 with get
  member val H4  = h4 with get
  member val H5  = h5 with get
  member val H6  = h6 with get
  member val H7  = h7 with get
  member val H8  = h8 with get
  member val H9  = h9 with get
  member val H10 = h10 with get
  member val H11 = h11 with get
  member val H12 = h12 with get
  member val H13 = h13 with get
  member val H14 = h14 with get
  member val H15 = h15 with get
  member val H16 = h16 with get
  member val H17 = h17 with get
  member val H18 = h18 with get
  member val H19 = h19 with get
  member val H20 = h20 with get
  member val H21 = h21 with get
  member val H22 = h22 with get
  member val H23 = h23 with get
  member val H24 = h24 with get
  member val H25 = h25 with get
  member val H26 = h26 with get
  member val H27 = h27 with get
  member val H28 = h28 with get
  member val H29 = h29 with get
  member val H30 = h30 with get
  member val H31 = h31 with get

  (* 8-bit registers *)
  member val B0  = b0 with get
  member val B1  = b1 with get
  member val B2  = b2 with get
  member val B3  = b3 with get
  member val B4  = b4 with get
  member val B5  = b5 with get
  member val B6  = b6 with get
  member val B7  = b7 with get
  member val B8  = b8 with get
  member val B9  = b9 with get
  member val B10 = b10 with get
  member val B11 = b11 with get
  member val B12 = b12 with get
  member val B13 = b13 with get
  member val B14 = b14 with get
  member val B15 = b15 with get
  member val B16 = b16 with get
  member val B17 = b17 with get
  member val B18 = b18 with get
  member val B19 = b19 with get
  member val B20 = b20 with get
  member val B21 = b21 with get
  member val B22 = b22 with get
  member val B23 = b23 with get
  member val B24 = b24 with get
  member val B25 = b25 with get
  member val B26 = b26 with get
  member val B27 = b27 with get
  member val B28 = b28 with get
  member val B29 = b29 with get
  member val B30 = b30 with get
  member val B31 = b31 with get

  (* Floating-point control and status registers *)
  member val FPCR = var 64<rt> (Register.toRegID Register.FPCR) "FPCR"
  member val FPSR = var 64<rt> (Register.toRegID Register.FPSR) "FPSR"

  (* Process state, PSTATE *)
  /// Negative condition flag
  member val N = var 1<rt> (Register.toRegID Register.N) "N"
  /// Zero condition flag
  member val Z = var 1<rt> (Register.toRegID Register.Z) "Z"
  /// Carry condition flag
  member val C = var 1<rt> (Register.toRegID Register.C) "C"
  /// Overflow condition flag
  member val V = var 1<rt> (Register.toRegID Register.V) "V"

  member __.GetRegVar (name) =
    match name with
    | R.X0  -> __.X0
    | R.X1  -> __.X1
    | R.X2  -> __.X2
    | R.X3  -> __.X3
    | R.X4  -> __.X4
    | R.X5  -> __.X5
    | R.X6  -> __.X6
    | R.X7  -> __.X7
    | R.X8  -> __.X8
    | R.X9  -> __.X9
    | R.X10 -> __.X10
    | R.X11 -> __.X11
    | R.X12 -> __.X12
    | R.X13 -> __.X13
    | R.X14 -> __.X14
    | R.X15 -> __.X15
    | R.X16 -> __.X16
    | R.X17 -> __.X17
    | R.X18 -> __.X18
    | R.X19 -> __.X19
    | R.X20 -> __.X20
    | R.X21 -> __.X21
    | R.X22 -> __.X22
    | R.X23 -> __.X23
    | R.X24 -> __.X24
    | R.X25 -> __.X25
    | R.X26 -> __.X26
    | R.X27 -> __.X27
    | R.X28 -> __.X28
    | R.X29 -> __.X29
    | R.X30 -> __.X30
    | R.XZR -> __.XZR
    | R.W0  -> __.W0
    | R.W1  -> __.W1
    | R.W2  -> __.W2
    | R.W3  -> __.W3
    | R.W4  -> __.W4
    | R.W5  -> __.W5
    | R.W6  -> __.W6
    | R.W7  -> __.W7
    | R.W8  -> __.W8
    | R.W9  -> __.W9
    | R.W10 -> __.W10
    | R.W11 -> __.W11
    | R.W12 -> __.W12
    | R.W13 -> __.W13
    | R.W14 -> __.W14
    | R.W15 -> __.W15
    | R.W16 -> __.W16
    | R.W17 -> __.W17
    | R.W18 -> __.W18
    | R.W19 -> __.W19
    | R.W20 -> __.W20
    | R.W21 -> __.W21
    | R.W22 -> __.W22
    | R.W23 -> __.W23
    | R.W24 -> __.W24
    | R.W25 -> __.W25
    | R.W26 -> __.W26
    | R.W27 -> __.W27
    | R.W28 -> __.W28
    | R.W29 -> __.W29
    | R.W30 -> __.W30
    | R.WZR -> __.WZR
    | R.SP  -> __.SP
    | R.WSP -> __.WSP
    | R.PC  -> __.PC
    | R.V0  -> __.V0
    | R.V1  -> __.V1
    | R.V2  -> __.V2
    | R.V3  -> __.V3
    | R.V4  -> __.V4
    | R.V5  -> __.V5
    | R.V6  -> __.V6
    | R.V7  -> __.V7
    | R.V8  -> __.V8
    | R.V9  -> __.V9
    | R.V10 -> __.V10
    | R.V11 -> __.V11
    | R.V12 -> __.V12
    | R.V13 -> __.V13
    | R.V14 -> __.V14
    | R.V15 -> __.V15
    | R.V16 -> __.V16
    | R.V17 -> __.V17
    | R.V18 -> __.V18
    | R.V19 -> __.V19
    | R.V20 -> __.V20
    | R.V21 -> __.V21
    | R.V22 -> __.V22
    | R.V23 -> __.V23
    | R.V24 -> __.V24
    | R.V25 -> __.V25
    | R.V26 -> __.V26
    | R.V27 -> __.V27
    | R.V28 -> __.V28
    | R.V29 -> __.V29
    | R.V30 -> __.V30
    | R.V31 -> __.V31
    | R.Q0  -> __.Q0
    | R.Q1  -> __.Q1
    | R.Q2  -> __.Q2
    | R.Q3  -> __.Q3
    | R.Q4  -> __.Q4
    | R.Q5  -> __.Q5
    | R.Q6  -> __.Q6
    | R.Q7  -> __.Q7
    | R.Q8  -> __.Q8
    | R.Q9  -> __.Q9
    | R.Q10 -> __.Q10
    | R.Q11 -> __.Q11
    | R.Q12 -> __.Q12
    | R.Q13 -> __.Q13
    | R.Q14 -> __.Q14
    | R.Q15 -> __.Q15
    | R.Q16 -> __.Q16
    | R.Q17 -> __.Q17
    | R.Q18 -> __.Q18
    | R.Q19 -> __.Q19
    | R.Q20 -> __.Q20
    | R.Q21 -> __.Q21
    | R.Q22 -> __.Q22
    | R.Q23 -> __.Q23
    | R.Q24 -> __.Q24
    | R.Q25 -> __.Q25
    | R.Q26 -> __.Q26
    | R.Q27 -> __.Q27
    | R.Q28 -> __.Q28
    | R.Q29 -> __.Q29
    | R.Q30 -> __.Q30
    | R.Q31 -> __.Q31
    | R.D0  -> __.D0
    | R.D1  -> __.D1
    | R.D2  -> __.D2
    | R.D3  -> __.D3
    | R.D4  -> __.D4
    | R.D5  -> __.D5
    | R.D6  -> __.D6
    | R.D7  -> __.D7
    | R.D8  -> __.D8
    | R.D9  -> __.D9
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
    | R.H0  -> __.H0
    | R.H1  -> __.H1
    | R.H2  -> __.H2
    | R.H3  -> __.H3
    | R.H4  -> __.H4
    | R.H5  -> __.H5
    | R.H6  -> __.H6
    | R.H7  -> __.H7
    | R.H8  -> __.H8
    | R.H9  -> __.H9
    | R.H10 -> __.H10
    | R.H11 -> __.H11
    | R.H12 -> __.H12
    | R.H13 -> __.H13
    | R.H14 -> __.H14
    | R.H15 -> __.H15
    | R.H16 -> __.H16
    | R.H17 -> __.H17
    | R.H18 -> __.H18
    | R.H19 -> __.H19
    | R.H20 -> __.H20
    | R.H21 -> __.H21
    | R.H22 -> __.H22
    | R.H23 -> __.H23
    | R.H24 -> __.H24
    | R.H25 -> __.H25
    | R.H26 -> __.H26
    | R.H27 -> __.H27
    | R.H28 -> __.H28
    | R.H29 -> __.H29
    | R.H30 -> __.H30
    | R.H31 -> __.H31
    | R.B0  -> __.B0
    | R.B1  -> __.B1
    | R.B2  -> __.B2
    | R.B3  -> __.B3
    | R.B4  -> __.B4
    | R.B5  -> __.B5
    | R.B6  -> __.B6
    | R.B7  -> __.B7
    | R.B8  -> __.B8
    | R.B9  -> __.B9
    | R.B10 -> __.B10
    | R.B11 -> __.B11
    | R.B12 -> __.B12
    | R.B13 -> __.B13
    | R.B14 -> __.B14
    | R.B15 -> __.B15
    | R.B16 -> __.B16
    | R.B17 -> __.B17
    | R.B18 -> __.B18
    | R.B19 -> __.B19
    | R.B20 -> __.B20
    | R.B21 -> __.B21
    | R.B22 -> __.B22
    | R.B23 -> __.B23
    | R.B24 -> __.B24
    | R.B25 -> __.B25
    | R.B26 -> __.B26
    | R.B27 -> __.B27
    | R.B28 -> __.B28
    | R.B29 -> __.B29
    | R.B30 -> __.B30
    | R.B31 -> __.B31
    | R.FPCR -> __.FPCR
    | R.FPSR -> __.FPSR
    | R.N -> __.N
    | R.Z -> __.Z
    | R.C -> __.C
    | R.V -> __.V
    | _ -> raise B2R2.FrontEnd.UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
