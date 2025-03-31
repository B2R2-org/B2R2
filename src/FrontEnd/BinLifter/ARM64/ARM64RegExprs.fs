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

namespace B2R2.FrontEnd.BinLifter.ARM64

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.Register
open B2R2.BinIR.LowUIR

type RegExprs () =
  let var sz t name = AST.var sz t name

  (* Registers *)
  let r0  = var 64<rt> (ARM64Register.ID ARM64.X0) "X0"
  let r1  = var 64<rt> (ARM64Register.ID ARM64.X1) "X1"
  let r2  = var 64<rt> (ARM64Register.ID ARM64.X2) "X2"
  let r3  = var 64<rt> (ARM64Register.ID ARM64.X3) "X3"
  let r4  = var 64<rt> (ARM64Register.ID ARM64.X4) "X4"
  let r5  = var 64<rt> (ARM64Register.ID ARM64.X5) "X5"
  let r6  = var 64<rt> (ARM64Register.ID ARM64.X6) "X6"
  let r7  = var 64<rt> (ARM64Register.ID ARM64.X7) "X7"
  let r8  = var 64<rt> (ARM64Register.ID ARM64.X8) "X8"
  let r9  = var 64<rt> (ARM64Register.ID ARM64.X9) "X9"
  let r10 = var 64<rt> (ARM64Register.ID ARM64.X10) "X10"
  let r11 = var 64<rt> (ARM64Register.ID ARM64.X11) "X11"
  let r12 = var 64<rt> (ARM64Register.ID ARM64.X12) "X12"
  let r13 = var 64<rt> (ARM64Register.ID ARM64.X13) "X13"
  let r14 = var 64<rt> (ARM64Register.ID ARM64.X14) "X14"
  let r15 = var 64<rt> (ARM64Register.ID ARM64.X15) "X15"
  let r16 = var 64<rt> (ARM64Register.ID ARM64.X16) "X16"
  let r17 = var 64<rt> (ARM64Register.ID ARM64.X17) "X17"
  let r18 = var 64<rt> (ARM64Register.ID ARM64.X18) "X18"
  let r19 = var 64<rt> (ARM64Register.ID ARM64.X19) "X19"
  let r20 = var 64<rt> (ARM64Register.ID ARM64.X20) "X20"
  let r21 = var 64<rt> (ARM64Register.ID ARM64.X21) "X21"
  let r22 = var 64<rt> (ARM64Register.ID ARM64.X22) "X22"
  let r23 = var 64<rt> (ARM64Register.ID ARM64.X23) "X23"
  let r24 = var 64<rt> (ARM64Register.ID ARM64.X24) "X24"
  let r25 = var 64<rt> (ARM64Register.ID ARM64.X25) "X25"
  let r26 = var 64<rt> (ARM64Register.ID ARM64.X26) "X26"
  let r27 = var 64<rt> (ARM64Register.ID ARM64.X27) "X27"
  let r28 = var 64<rt> (ARM64Register.ID ARM64.X28) "X28"
  let r29 = var 64<rt> (ARM64Register.ID ARM64.X29) "X29"
  let r30 = var 64<rt> (ARM64Register.ID ARM64.X30) "X30"
  let xzr = var 64<rt> (ARM64Register.ID ARM64.XZR) "XZR"
  let sp = var 64<rt> (ARM64Register.ID ARM64.SP) "SP"
  let pc = AST.pcvar 64<rt> "PC"

  let w0  = AST.xtlo 32<rt> r0
  let w1  = AST.xtlo 32<rt> r1
  let w2  = AST.xtlo 32<rt> r2
  let w3  = AST.xtlo 32<rt> r3
  let w4  = AST.xtlo 32<rt> r4
  let w5  = AST.xtlo 32<rt> r5
  let w6  = AST.xtlo 32<rt> r6
  let w7  = AST.xtlo 32<rt> r7
  let w8  = AST.xtlo 32<rt> r8
  let w9  = AST.xtlo 32<rt> r9
  let w10 = AST.xtlo 32<rt> r10
  let w11 = AST.xtlo 32<rt> r11
  let w12 = AST.xtlo 32<rt> r12
  let w13 = AST.xtlo 32<rt> r13
  let w14 = AST.xtlo 32<rt> r14
  let w15 = AST.xtlo 32<rt> r15
  let w16 = AST.xtlo 32<rt> r16
  let w17 = AST.xtlo 32<rt> r17
  let w18 = AST.xtlo 32<rt> r18
  let w19 = AST.xtlo 32<rt> r19
  let w20 = AST.xtlo 32<rt> r20
  let w21 = AST.xtlo 32<rt> r21
  let w22 = AST.xtlo 32<rt> r22
  let w23 = AST.xtlo 32<rt> r23
  let w24 = AST.xtlo 32<rt> r24
  let w25 = AST.xtlo 32<rt> r25
  let w26 = AST.xtlo 32<rt> r26
  let w27 = AST.xtlo 32<rt> r27
  let w28 = AST.xtlo 32<rt> r28
  let w29 = AST.xtlo 32<rt> r29
  let w30 = AST.xtlo 32<rt> r30
  let wzr = AST.xtlo 32<rt> xzr
  let wsp = AST.xtlo 32<rt> sp

  let v0a  = var 64<rt> (ARM64Register.ID ARM64.V0A) "V0A"
  let v0b  = var 64<rt> (ARM64Register.ID ARM64.V0B) "V0B"
  let v1a  = var 64<rt> (ARM64Register.ID ARM64.V1A) "V1A"
  let v1b  = var 64<rt> (ARM64Register.ID ARM64.V1B) "V1B"
  let v2a  = var 64<rt> (ARM64Register.ID ARM64.V2A) "V2A"
  let v2b  = var 64<rt> (ARM64Register.ID ARM64.V2B) "V2B"
  let v3a  = var 64<rt> (ARM64Register.ID ARM64.V3A) "V3A"
  let v3b  = var 64<rt> (ARM64Register.ID ARM64.V3B) "V3B"
  let v4a  = var 64<rt> (ARM64Register.ID ARM64.V4A) "V4A"
  let v4b  = var 64<rt> (ARM64Register.ID ARM64.V4B) "V4B"
  let v5a  = var 64<rt> (ARM64Register.ID ARM64.V5A) "V5A"
  let v5b  = var 64<rt> (ARM64Register.ID ARM64.V5B) "V5B"
  let v6a  = var 64<rt> (ARM64Register.ID ARM64.V6A) "V6A"
  let v6b  = var 64<rt> (ARM64Register.ID ARM64.V6B) "V6B"
  let v7a  = var 64<rt> (ARM64Register.ID ARM64.V7A) "V7A"
  let v7b  = var 64<rt> (ARM64Register.ID ARM64.V7B) "V7B"
  let v8a  = var 64<rt> (ARM64Register.ID ARM64.V8A) "V8A"
  let v8b  = var 64<rt> (ARM64Register.ID ARM64.V8B) "V8B"
  let v9a  = var 64<rt> (ARM64Register.ID ARM64.V9A) "V9A"
  let v9b  = var 64<rt> (ARM64Register.ID ARM64.V9B) "V9B"
  let v10a = var 64<rt> (ARM64Register.ID ARM64.V10A) "V10A"
  let v10b = var 64<rt> (ARM64Register.ID ARM64.V10B) "V10B"
  let v11a = var 64<rt> (ARM64Register.ID ARM64.V11A) "V11A"
  let v11b = var 64<rt> (ARM64Register.ID ARM64.V11B) "V11B"
  let v12a = var 64<rt> (ARM64Register.ID ARM64.V12A) "V12A"
  let v12b = var 64<rt> (ARM64Register.ID ARM64.V12B) "V12B"
  let v13a = var 64<rt> (ARM64Register.ID ARM64.V13A) "V13A"
  let v13b = var 64<rt> (ARM64Register.ID ARM64.V13B) "V13B"
  let v14a = var 64<rt> (ARM64Register.ID ARM64.V14A) "V14A"
  let v14b = var 64<rt> (ARM64Register.ID ARM64.V14B) "V14B"
  let v15a = var 64<rt> (ARM64Register.ID ARM64.V15A) "V15A"
  let v15b = var 64<rt> (ARM64Register.ID ARM64.V15B) "V15B"
  let v16a = var 64<rt> (ARM64Register.ID ARM64.V16A) "V16A"
  let v16b = var 64<rt> (ARM64Register.ID ARM64.V16B) "V16B"
  let v17a = var 64<rt> (ARM64Register.ID ARM64.V17A) "V17A"
  let v17b = var 64<rt> (ARM64Register.ID ARM64.V17B) "V17B"
  let v18a = var 64<rt> (ARM64Register.ID ARM64.V18A) "V18A"
  let v18b = var 64<rt> (ARM64Register.ID ARM64.V18B) "V18B"
  let v19a = var 64<rt> (ARM64Register.ID ARM64.V19A) "V19A"
  let v19b = var 64<rt> (ARM64Register.ID ARM64.V19B) "V19B"
  let v20a = var 64<rt> (ARM64Register.ID ARM64.V20A) "V20A"
  let v20b = var 64<rt> (ARM64Register.ID ARM64.V20B) "V20B"
  let v21a = var 64<rt> (ARM64Register.ID ARM64.V21A) "V21A"
  let v21b = var 64<rt> (ARM64Register.ID ARM64.V21B) "V21B"
  let v22a = var 64<rt> (ARM64Register.ID ARM64.V22A) "V22A"
  let v22b = var 64<rt> (ARM64Register.ID ARM64.V22B) "V22B"
  let v23a = var 64<rt> (ARM64Register.ID ARM64.V23A) "V23A"
  let v23b = var 64<rt> (ARM64Register.ID ARM64.V23B) "V23B"
  let v24a = var 64<rt> (ARM64Register.ID ARM64.V24A) "V24A"
  let v24b = var 64<rt> (ARM64Register.ID ARM64.V24B) "V24B"
  let v25a = var 64<rt> (ARM64Register.ID ARM64.V25A) "V25A"
  let v25b = var 64<rt> (ARM64Register.ID ARM64.V25B) "V25B"
  let v26a = var 64<rt> (ARM64Register.ID ARM64.V26A) "V26A"
  let v26b = var 64<rt> (ARM64Register.ID ARM64.V26B) "V26B"
  let v27a = var 64<rt> (ARM64Register.ID ARM64.V27A) "V27A"
  let v27b = var 64<rt> (ARM64Register.ID ARM64.V27B) "V27B"
  let v28a = var 64<rt> (ARM64Register.ID ARM64.V28A) "V28A"
  let v28b = var 64<rt> (ARM64Register.ID ARM64.V28B) "V28B"
  let v29a = var 64<rt> (ARM64Register.ID ARM64.V29A) "V29A"
  let v29b = var 64<rt> (ARM64Register.ID ARM64.V29B) "V29B"
  let v30a = var 64<rt> (ARM64Register.ID ARM64.V30A) "V30A"
  let v30b = var 64<rt> (ARM64Register.ID ARM64.V30B) "V30B"
  let v31a = var 64<rt> (ARM64Register.ID ARM64.V31A) "V31A"
  let v31b = var 64<rt> (ARM64Register.ID ARM64.V31B) "V31B"

  let d0  = v0a
  let d1  = v1a
  let d2  = v2a
  let d3  = v3a
  let d4  = v4a
  let d5  = v5a
  let d6  = v6a
  let d7  = v7a
  let d8  = v8a
  let d9  = v9a
  let d10 = v10a
  let d11 = v11a
  let d12 = v12a
  let d13 = v13a
  let d14 = v14a
  let d15 = v15a
  let d16 = v16a
  let d17 = v17a
  let d18 = v18a
  let d19 = v19a
  let d20 = v20a
  let d21 = v21a
  let d22 = v22a
  let d23 = v23a
  let d24 = v24a
  let d25 = v25a
  let d26 = v26a
  let d27 = v27a
  let d28 = v28a
  let d29 = v29a
  let d30 = v30a
  let d31 = v31a

  let s0  = AST.xtlo 32<rt> v0a
  let s1  = AST.xtlo 32<rt> v1a
  let s2  = AST.xtlo 32<rt> v2a
  let s3  = AST.xtlo 32<rt> v3a
  let s4  = AST.xtlo 32<rt> v4a
  let s5  = AST.xtlo 32<rt> v5a
  let s6  = AST.xtlo 32<rt> v6a
  let s7  = AST.xtlo 32<rt> v7a
  let s8  = AST.xtlo 32<rt> v8a
  let s9  = AST.xtlo 32<rt> v9a
  let s10 = AST.xtlo 32<rt> v10a
  let s11 = AST.xtlo 32<rt> v11a
  let s12 = AST.xtlo 32<rt> v12a
  let s13 = AST.xtlo 32<rt> v13a
  let s14 = AST.xtlo 32<rt> v14a
  let s15 = AST.xtlo 32<rt> v15a
  let s16 = AST.xtlo 32<rt> v16a
  let s17 = AST.xtlo 32<rt> v17a
  let s18 = AST.xtlo 32<rt> v18a
  let s19 = AST.xtlo 32<rt> v19a
  let s20 = AST.xtlo 32<rt> v20a
  let s21 = AST.xtlo 32<rt> v21a
  let s22 = AST.xtlo 32<rt> v22a
  let s23 = AST.xtlo 32<rt> v23a
  let s24 = AST.xtlo 32<rt> v24a
  let s25 = AST.xtlo 32<rt> v25a
  let s26 = AST.xtlo 32<rt> v26a
  let s27 = AST.xtlo 32<rt> v27a
  let s28 = AST.xtlo 32<rt> v28a
  let s29 = AST.xtlo 32<rt> v29a
  let s30 = AST.xtlo 32<rt> v30a
  let s31 = AST.xtlo 32<rt> v31a

  let h0  = AST.xtlo 16<rt> v0a
  let h1  = AST.xtlo 16<rt> v1a
  let h2  = AST.xtlo 16<rt> v2a
  let h3  = AST.xtlo 16<rt> v3a
  let h4  = AST.xtlo 16<rt> v4a
  let h5  = AST.xtlo 16<rt> v5a
  let h6  = AST.xtlo 16<rt> v6a
  let h7  = AST.xtlo 16<rt> v7a
  let h8  = AST.xtlo 16<rt> v8a
  let h9  = AST.xtlo 16<rt> v9a
  let h10 = AST.xtlo 16<rt> v10a
  let h11 = AST.xtlo 16<rt> v11a
  let h12 = AST.xtlo 16<rt> v12a
  let h13 = AST.xtlo 16<rt> v13a
  let h14 = AST.xtlo 16<rt> v14a
  let h15 = AST.xtlo 16<rt> v15a
  let h16 = AST.xtlo 16<rt> v16a
  let h17 = AST.xtlo 16<rt> v17a
  let h18 = AST.xtlo 16<rt> v18a
  let h19 = AST.xtlo 16<rt> v19a
  let h20 = AST.xtlo 16<rt> v20a
  let h21 = AST.xtlo 16<rt> v21a
  let h22 = AST.xtlo 16<rt> v22a
  let h23 = AST.xtlo 16<rt> v23a
  let h24 = AST.xtlo 16<rt> v24a
  let h25 = AST.xtlo 16<rt> v25a
  let h26 = AST.xtlo 16<rt> v26a
  let h27 = AST.xtlo 16<rt> v27a
  let h28 = AST.xtlo 16<rt> v28a
  let h29 = AST.xtlo 16<rt> v29a
  let h30 = AST.xtlo 16<rt> v30a
  let h31 = AST.xtlo 16<rt> v31a

  let b0  = AST.xtlo 8<rt> v0a
  let b1  = AST.xtlo 8<rt> v1a
  let b2  = AST.xtlo 8<rt> v2a
  let b3  = AST.xtlo 8<rt> v3a
  let b4  = AST.xtlo 8<rt> v4a
  let b5  = AST.xtlo 8<rt> v5a
  let b6  = AST.xtlo 8<rt> v6a
  let b7  = AST.xtlo 8<rt> v7a
  let b8  = AST.xtlo 8<rt> v8a
  let b9  = AST.xtlo 8<rt> v9a
  let b10 = AST.xtlo 8<rt> v10a
  let b11 = AST.xtlo 8<rt> v11a
  let b12 = AST.xtlo 8<rt> v12a
  let b13 = AST.xtlo 8<rt> v13a
  let b14 = AST.xtlo 8<rt> v14a
  let b15 = AST.xtlo 8<rt> v15a
  let b16 = AST.xtlo 8<rt> v16a
  let b17 = AST.xtlo 8<rt> v17a
  let b18 = AST.xtlo 8<rt> v18a
  let b19 = AST.xtlo 8<rt> v19a
  let b20 = AST.xtlo 8<rt> v20a
  let b21 = AST.xtlo 8<rt> v21a
  let b22 = AST.xtlo 8<rt> v22a
  let b23 = AST.xtlo 8<rt> v23a
  let b24 = AST.xtlo 8<rt> v24a
  let b25 = AST.xtlo 8<rt> v25a
  let b26 = AST.xtlo 8<rt> v26a
  let b27 = AST.xtlo 8<rt> v27a
  let b28 = AST.xtlo 8<rt> v28a
  let b29 = AST.xtlo 8<rt> v29a
  let b30 = AST.xtlo 8<rt> v30a
  let b31 = AST.xtlo 8<rt> v31a

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
  member val V0A  = v0a with get
  member val V0B  = v0b with get
  member val V1A  = v1a with get
  member val V1B  = v1b with get
  member val V2A  = v2a with get
  member val V2B  = v2b with get
  member val V3A  = v3a with get
  member val V3B  = v3b with get
  member val V4A  = v4a with get
  member val V4B  = v4b with get
  member val V5A  = v5a with get
  member val V5B  = v5b with get
  member val V6A  = v6a with get
  member val V6B  = v6b with get
  member val V7A  = v7a with get
  member val V7B  = v7b with get
  member val V8A  = v8a with get
  member val V8B  = v8b with get
  member val V9A  = v9a with get
  member val V9B  = v9b with get
  member val V10A = v10a with get
  member val V10B = v10b with get
  member val V11A = v11a with get
  member val V11B = v11b with get
  member val V12A = v12a with get
  member val V12B = v12b with get
  member val V13A = v13a with get
  member val V13B = v13b with get
  member val V14A = v14a with get
  member val V14B = v14b with get
  member val V15A = v15a with get
  member val V15B = v15b with get
  member val V16A = v16a with get
  member val V16B = v16b with get
  member val V17A = v17a with get
  member val V17B = v17b with get
  member val V18A = v18a with get
  member val V18B = v18b with get
  member val V19A = v19a with get
  member val V19B = v19b with get
  member val V20A = v20a with get
  member val V20B = v20b with get
  member val V21A = v21a with get
  member val V21B = v21b with get
  member val V22A = v22a with get
  member val V22B = v22b with get
  member val V23A = v23a with get
  member val V23B = v23b with get
  member val V24A = v24a with get
  member val V24B = v24b with get
  member val V25A = v25a with get
  member val V25B = v25b with get
  member val V26A = v26a with get
  member val V26B = v26b with get
  member val V27A = v27a with get
  member val V27B = v27b with get
  member val V28A = v28a with get
  member val V28B = v28b with get
  member val V29A = v29a with get
  member val V29B = v29b with get
  member val V30A = v30a with get
  member val V30B = v30b with get
  member val V31A = v31a with get
  member val V31B = v31b with get

  (* 128-bit registers *)
  member val Q0A = var 64<rt> (ARM64Register.ID ARM64.V0A) "Q0A" with get
  member val Q0B = var 64<rt> (ARM64Register.ID ARM64.V0B) "Q0B" with get
  member val Q1A = var 64<rt> (ARM64Register.ID ARM64.V1A) "Q1A" with get
  member val Q1B = var 64<rt> (ARM64Register.ID ARM64.V1B) "Q1B" with get
  member val Q2A = var 64<rt> (ARM64Register.ID ARM64.V2A) "Q2A" with get
  member val Q2B = var 64<rt> (ARM64Register.ID ARM64.V2B) "Q2B" with get
  member val Q3A = var 64<rt> (ARM64Register.ID ARM64.V3A) "Q3A" with get
  member val Q3B = var 64<rt> (ARM64Register.ID ARM64.V3B) "Q3B" with get
  member val Q4A = var 64<rt> (ARM64Register.ID ARM64.V4A) "Q4A" with get
  member val Q4B = var 64<rt> (ARM64Register.ID ARM64.V4B) "Q4B" with get
  member val Q5A = var 64<rt> (ARM64Register.ID ARM64.V5A) "Q5A" with get
  member val Q5B = var 64<rt> (ARM64Register.ID ARM64.V5B) "Q5B" with get
  member val Q6A = var 64<rt> (ARM64Register.ID ARM64.V6A) "Q6A" with get
  member val Q6B = var 64<rt> (ARM64Register.ID ARM64.V6B) "Q6B" with get
  member val Q7A = var 64<rt> (ARM64Register.ID ARM64.V7A) "Q7A" with get
  member val Q7B = var 64<rt> (ARM64Register.ID ARM64.V7B) "Q7B" with get
  member val Q8A = var 64<rt> (ARM64Register.ID ARM64.V8A) "Q8A" with get
  member val Q8B = var 64<rt> (ARM64Register.ID ARM64.V8B) "Q8B" with get
  member val Q9A = var 64<rt> (ARM64Register.ID ARM64.V9A) "Q9A" with get
  member val Q9B = var 64<rt> (ARM64Register.ID ARM64.V9B) "Q9B" with get
  member val Q10A = var 64<rt> (ARM64Register.ID ARM64.V10A) "Q10A" with get
  member val Q10B = var 64<rt> (ARM64Register.ID ARM64.V10B) "Q10B" with get
  member val Q11A = var 64<rt> (ARM64Register.ID ARM64.V11A) "Q11A" with get
  member val Q11B = var 64<rt> (ARM64Register.ID ARM64.V11B) "Q11B" with get
  member val Q12A = var 64<rt> (ARM64Register.ID ARM64.V12A) "Q12A" with get
  member val Q12B = var 64<rt> (ARM64Register.ID ARM64.V12B) "Q12B" with get
  member val Q13A = var 64<rt> (ARM64Register.ID ARM64.V13A) "Q13A" with get
  member val Q13B = var 64<rt> (ARM64Register.ID ARM64.V13B) "Q13B" with get
  member val Q14A = var 64<rt> (ARM64Register.ID ARM64.V14A) "Q14A" with get
  member val Q14B = var 64<rt> (ARM64Register.ID ARM64.V14B) "Q14B" with get
  member val Q15A = var 64<rt> (ARM64Register.ID ARM64.V15A) "Q15A" with get
  member val Q15B = var 64<rt> (ARM64Register.ID ARM64.V15B) "Q15B" with get
  member val Q16A = var 64<rt> (ARM64Register.ID ARM64.V16A) "Q16A" with get
  member val Q16B = var 64<rt> (ARM64Register.ID ARM64.V16B) "Q16B" with get
  member val Q17A = var 64<rt> (ARM64Register.ID ARM64.V17A) "Q17A" with get
  member val Q17B = var 64<rt> (ARM64Register.ID ARM64.V17B) "Q17B" with get
  member val Q18A = var 64<rt> (ARM64Register.ID ARM64.V18A) "Q18A" with get
  member val Q18B = var 64<rt> (ARM64Register.ID ARM64.V18B) "Q18B" with get
  member val Q19A = var 64<rt> (ARM64Register.ID ARM64.V19A) "Q19A" with get
  member val Q19B = var 64<rt> (ARM64Register.ID ARM64.V19B) "Q19B" with get
  member val Q20A = var 64<rt> (ARM64Register.ID ARM64.V20A) "Q20A" with get
  member val Q20B = var 64<rt> (ARM64Register.ID ARM64.V20B) "Q20B" with get
  member val Q21A = var 64<rt> (ARM64Register.ID ARM64.V21A) "Q21A" with get
  member val Q21B = var 64<rt> (ARM64Register.ID ARM64.V21B) "Q21B" with get
  member val Q22A = var 64<rt> (ARM64Register.ID ARM64.V22A) "Q22A" with get
  member val Q22B = var 64<rt> (ARM64Register.ID ARM64.V22B) "Q22B" with get
  member val Q23A = var 64<rt> (ARM64Register.ID ARM64.V23A) "Q23A" with get
  member val Q23B = var 64<rt> (ARM64Register.ID ARM64.V23B) "Q23B" with get
  member val Q24A = var 64<rt> (ARM64Register.ID ARM64.V24A) "Q24A" with get
  member val Q24B = var 64<rt> (ARM64Register.ID ARM64.V24B) "Q24B" with get
  member val Q25A = var 64<rt> (ARM64Register.ID ARM64.V25A) "Q25A" with get
  member val Q25B = var 64<rt> (ARM64Register.ID ARM64.V25B) "Q25B" with get
  member val Q26A = var 64<rt> (ARM64Register.ID ARM64.V26A) "Q26A" with get
  member val Q26B = var 64<rt> (ARM64Register.ID ARM64.V26B) "Q26B" with get
  member val Q27A = var 64<rt> (ARM64Register.ID ARM64.V27A) "Q27A" with get
  member val Q27B = var 64<rt> (ARM64Register.ID ARM64.V27B) "Q27B" with get
  member val Q28A = var 64<rt> (ARM64Register.ID ARM64.V28A) "Q28A" with get
  member val Q28B = var 64<rt> (ARM64Register.ID ARM64.V28B) "Q28B" with get
  member val Q29A = var 64<rt> (ARM64Register.ID ARM64.V29A) "Q29A" with get
  member val Q29B = var 64<rt> (ARM64Register.ID ARM64.V29B) "Q29B" with get
  member val Q30A = var 64<rt> (ARM64Register.ID ARM64.V30A) "Q30A" with get
  member val Q30B = var 64<rt> (ARM64Register.ID ARM64.V30B) "Q30B" with get
  member val Q31A = var 64<rt> (ARM64Register.ID ARM64.V31A) "Q31A" with get
  member val Q31B = var 64<rt> (ARM64Register.ID ARM64.V31B) "Q31B" with get

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
  member val FPCR = var 64<rt> (ARM64Register.ID ARM64.FPCR) "FPCR"
  member val FPSR = var 64<rt> (ARM64Register.ID ARM64.FPSR) "FPSR"

  (* Process state, PSTATE *)
  /// Negative condition flag.
  member val N = var 1<rt> (ARM64Register.ID ARM64.N) "N"
  /// Zero condition flag.
  member val Z = var 1<rt> (ARM64Register.ID ARM64.Z) "Z"
  /// Carry condition flag.
  member val C = var 1<rt> (ARM64Register.ID ARM64.C) "C"
  /// Overflow condition flag.
  member val V = var 1<rt> (ARM64Register.ID ARM64.V) "V"

  (* System registers *)
  /// Data Cache Zero ID register.
  member val DCZIDEL0 =
    var 64<rt> (ARM64Register.ID ARM64.DCZIDEL0) "DCZID_EL0"
  /// Main ID ARM64.
  member val MIDREL1 = var 64<rt> (ARM64Register.ID ARM64.MIDREL1) "MIDR_EL1"
  /// EL0 Read/Write Software Thread ID ARM64.
  member val TPIDREL0 =
    var 64<rt> (ARM64Register.ID ARM64.TPIDREL0) "TPIDR_EL0"
  /// S<op0>_<op1>_<Cn>_<Cm>_<op2>.
  member val S3_5_C3_C2_0 =
    var 64<rt> (ARM64Register.ID ARM64.S3_5_C3_C2_0) "S3_5_C3_C2_0"
  member val S3_7_C2_C2_7 =
    var 64<rt> (ARM64Register.ID ARM64.S3_7_C2_C2_7) "S3_7_C2_C2_7"
  member val S0_0_C2_C9_3 =
    var 64<rt> (ARM64Register.ID ARM64.S0_0_C2_C9_3) "S0_0_C2_C9_3"
  member val S2_7_C12_C7_6 =
    var 64<rt> (ARM64Register.ID ARM64.S2_7_C12_C7_6) "S2_7_C12_C7_6"

  (* Extra pseudo registers. *)
  /// Pseudo register for passing a return value from an external call.
  member val ERET = var 64<rt> (ARM64Register.ID ARM64.ERET) "ERET"

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
    | R.DCZIDEL0 -> __.DCZIDEL0
    | R.MIDREL1 -> __.MIDREL1
    | R.TPIDREL0 -> __.TPIDREL0
    | R.S3_5_C3_C2_0 -> __.S3_5_C3_C2_0
    | R.S3_7_C2_C2_7 -> __.S3_7_C2_C2_7
    | R.S0_0_C2_C9_3 -> __.S0_0_C2_C9_3
    | R.S2_7_C12_C7_6 -> __.S2_7_C12_C7_6
    | R.ERET -> __.ERET
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
    | R.Q16, 1 -> __.Q16A
    | R.Q16, 2 -> __.Q16B
    | R.Q17, 1 -> __.Q17A
    | R.Q17, 2 -> __.Q17B
    | R.Q18, 1 -> __.Q18A
    | R.Q18, 2 -> __.Q18B
    | R.Q19, 1 -> __.Q19A
    | R.Q19, 2 -> __.Q19B
    | R.Q20, 1 -> __.Q20A
    | R.Q20, 2 -> __.Q20B
    | R.Q21, 1 -> __.Q21A
    | R.Q21, 2 -> __.Q21B
    | R.Q22, 1 -> __.Q22A
    | R.Q22, 2 -> __.Q22B
    | R.Q23, 1 -> __.Q23A
    | R.Q23, 2 -> __.Q23B
    | R.Q24, 1 -> __.Q24A
    | R.Q24, 2 -> __.Q24B
    | R.Q25, 1 -> __.Q25A
    | R.Q25, 2 -> __.Q25B
    | R.Q26, 1 -> __.Q26A
    | R.Q26, 2 -> __.Q26B
    | R.Q27, 1 -> __.Q27A
    | R.Q27, 2 -> __.Q27B
    | R.Q28, 1 -> __.Q28A
    | R.Q28, 2 -> __.Q28B
    | R.Q29, 1 -> __.Q29A
    | R.Q29, 2 -> __.Q29B
    | R.Q30, 1 -> __.Q30A
    | R.Q30, 2 -> __.Q30B
    | R.Q31, 1 -> __.Q31A
    | R.Q31, 2 -> __.Q31B
    | R.V0, 1 -> __.V0A
    | R.V0, 2 -> __.V0B
    | R.V1, 1 -> __.V1A
    | R.V1, 2 -> __.V1B
    | R.V2, 1 -> __.V2A
    | R.V2, 2 -> __.V2B
    | R.V3, 1 -> __.V3A
    | R.V3, 2 -> __.V3B
    | R.V4, 1 -> __.V4A
    | R.V4, 2 -> __.V4B
    | R.V5, 1 -> __.V5A
    | R.V5, 2 -> __.V5B
    | R.V6, 1 -> __.V6A
    | R.V6, 2 -> __.V6B
    | R.V7, 1 -> __.V7A
    | R.V7, 2 -> __.V7B
    | R.V8, 1 -> __.V8A
    | R.V8, 2 -> __.V8B
    | R.V9, 1 -> __.V9A
    | R.V9, 2 -> __.V9B
    | R.V10, 1 -> __.V10A
    | R.V10, 2 -> __.V10B
    | R.V11, 1 -> __.V11A
    | R.V11, 2 -> __.V11B
    | R.V12, 1 -> __.V12A
    | R.V12, 2 -> __.V12B
    | R.V13, 1 -> __.V13A
    | R.V13, 2 -> __.V13B
    | R.V14, 1 -> __.V14A
    | R.V14, 2 -> __.V14B
    | R.V15, 1 -> __.V15A
    | R.V15, 2 -> __.V15B
    | R.V16, 1 -> __.V16A
    | R.V16, 2 -> __.V16B
    | R.V17, 1 -> __.V17A
    | R.V17, 2 -> __.V17B
    | R.V18, 1 -> __.V18A
    | R.V18, 2 -> __.V18B
    | R.V19, 1 -> __.V19A
    | R.V19, 2 -> __.V19B
    | R.V20, 1 -> __.V20A
    | R.V20, 2 -> __.V20B
    | R.V21, 1 -> __.V21A
    | R.V21, 2 -> __.V21B
    | R.V22, 1 -> __.V22A
    | R.V22, 2 -> __.V22B
    | R.V23, 1 -> __.V23A
    | R.V23, 2 -> __.V23B
    | R.V24, 1 -> __.V24A
    | R.V24, 2 -> __.V24B
    | R.V25, 1 -> __.V25A
    | R.V25, 2 -> __.V25B
    | R.V26, 1 -> __.V26A
    | R.V26, 2 -> __.V26B
    | R.V27, 1 -> __.V27A
    | R.V27, 2 -> __.V27B
    | R.V28, 1 -> __.V28A
    | R.V28, 2 -> __.V28B
    | R.V29, 1 -> __.V29A
    | R.V29, 2 -> __.V29B
    | R.V30, 1 -> __.V30A
    | R.V30, 2 -> __.V30B
    | R.V31, 1 -> __.V31A
    | R.V31, 2 -> __.V31B
    | _ -> raise UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
