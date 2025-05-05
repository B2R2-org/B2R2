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

namespace B2R2.FrontEnd.ARM64

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR
open type Register

type RegisterFactory () =
  (* Registers *)
  let x0  = AST.var 64<rt> (Register.toRegID X0) "X0"
  let x1  = AST.var 64<rt> (Register.toRegID X1) "X1"
  let x2  = AST.var 64<rt> (Register.toRegID X2) "X2"
  let x3  = AST.var 64<rt> (Register.toRegID X3) "X3"
  let x4  = AST.var 64<rt> (Register.toRegID X4) "X4"
  let x5  = AST.var 64<rt> (Register.toRegID X5) "X5"
  let x6  = AST.var 64<rt> (Register.toRegID X6) "X6"
  let x7  = AST.var 64<rt> (Register.toRegID X7) "X7"
  let x8  = AST.var 64<rt> (Register.toRegID X8) "X8"
  let x9  = AST.var 64<rt> (Register.toRegID X9) "X9"
  let x10 = AST.var 64<rt> (Register.toRegID X10) "X10"
  let x11 = AST.var 64<rt> (Register.toRegID X11) "X11"
  let x12 = AST.var 64<rt> (Register.toRegID X12) "X12"
  let x13 = AST.var 64<rt> (Register.toRegID X13) "X13"
  let x14 = AST.var 64<rt> (Register.toRegID X14) "X14"
  let x15 = AST.var 64<rt> (Register.toRegID X15) "X15"
  let x16 = AST.var 64<rt> (Register.toRegID X16) "X16"
  let x17 = AST.var 64<rt> (Register.toRegID X17) "X17"
  let x18 = AST.var 64<rt> (Register.toRegID X18) "X18"
  let x19 = AST.var 64<rt> (Register.toRegID X19) "X19"
  let x20 = AST.var 64<rt> (Register.toRegID X20) "X20"
  let x21 = AST.var 64<rt> (Register.toRegID X21) "X21"
  let x22 = AST.var 64<rt> (Register.toRegID X22) "X22"
  let x23 = AST.var 64<rt> (Register.toRegID X23) "X23"
  let x24 = AST.var 64<rt> (Register.toRegID X24) "X24"
  let x25 = AST.var 64<rt> (Register.toRegID X25) "X25"
  let x26 = AST.var 64<rt> (Register.toRegID X26) "X26"
  let x27 = AST.var 64<rt> (Register.toRegID X27) "X27"
  let x28 = AST.var 64<rt> (Register.toRegID X28) "X28"
  let x29 = AST.var 64<rt> (Register.toRegID X29) "X29"
  let x30 = AST.var 64<rt> (Register.toRegID X30) "X30"
  let xzr = AST.var 64<rt> (Register.toRegID XZR) "XZR"
  let sp = AST.var 64<rt> (Register.toRegID SP) "SP"
  let pc = AST.pcvar 64<rt> "PC"

  let w0  = AST.xtlo 32<rt> x0
  let w1  = AST.xtlo 32<rt> x1
  let w2  = AST.xtlo 32<rt> x2
  let w3  = AST.xtlo 32<rt> x3
  let w4  = AST.xtlo 32<rt> x4
  let w5  = AST.xtlo 32<rt> x5
  let w6  = AST.xtlo 32<rt> x6
  let w7  = AST.xtlo 32<rt> x7
  let w8  = AST.xtlo 32<rt> x8
  let w9  = AST.xtlo 32<rt> x9
  let w10 = AST.xtlo 32<rt> x10
  let w11 = AST.xtlo 32<rt> x11
  let w12 = AST.xtlo 32<rt> x12
  let w13 = AST.xtlo 32<rt> x13
  let w14 = AST.xtlo 32<rt> x14
  let w15 = AST.xtlo 32<rt> x15
  let w16 = AST.xtlo 32<rt> x16
  let w17 = AST.xtlo 32<rt> x17
  let w18 = AST.xtlo 32<rt> x18
  let w19 = AST.xtlo 32<rt> x19
  let w20 = AST.xtlo 32<rt> x20
  let w21 = AST.xtlo 32<rt> x21
  let w22 = AST.xtlo 32<rt> x22
  let w23 = AST.xtlo 32<rt> x23
  let w24 = AST.xtlo 32<rt> x24
  let w25 = AST.xtlo 32<rt> x25
  let w26 = AST.xtlo 32<rt> x26
  let w27 = AST.xtlo 32<rt> x27
  let w28 = AST.xtlo 32<rt> x28
  let w29 = AST.xtlo 32<rt> x29
  let w30 = AST.xtlo 32<rt> x30
  let wzr = AST.xtlo 32<rt> xzr
  let wsp = AST.xtlo 32<rt> sp

  let v0a  = AST.var 64<rt> (Register.toRegID V0A) "V0A"
  let v0b  = AST.var 64<rt> (Register.toRegID V0B) "V0B"
  let v1a  = AST.var 64<rt> (Register.toRegID V1A) "V1A"
  let v1b  = AST.var 64<rt> (Register.toRegID V1B) "V1B"
  let v2a  = AST.var 64<rt> (Register.toRegID V2A) "V2A"
  let v2b  = AST.var 64<rt> (Register.toRegID V2B) "V2B"
  let v3a  = AST.var 64<rt> (Register.toRegID V3A) "V3A"
  let v3b  = AST.var 64<rt> (Register.toRegID V3B) "V3B"
  let v4a  = AST.var 64<rt> (Register.toRegID V4A) "V4A"
  let v4b  = AST.var 64<rt> (Register.toRegID V4B) "V4B"
  let v5a  = AST.var 64<rt> (Register.toRegID V5A) "V5A"
  let v5b  = AST.var 64<rt> (Register.toRegID V5B) "V5B"
  let v6a  = AST.var 64<rt> (Register.toRegID V6A) "V6A"
  let v6b  = AST.var 64<rt> (Register.toRegID V6B) "V6B"
  let v7a  = AST.var 64<rt> (Register.toRegID V7A) "V7A"
  let v7b  = AST.var 64<rt> (Register.toRegID V7B) "V7B"
  let v8a  = AST.var 64<rt> (Register.toRegID V8A) "V8A"
  let v8b  = AST.var 64<rt> (Register.toRegID V8B) "V8B"
  let v9a  = AST.var 64<rt> (Register.toRegID V9A) "V9A"
  let v9b  = AST.var 64<rt> (Register.toRegID V9B) "V9B"
  let v10a = AST.var 64<rt> (Register.toRegID V10A) "V10A"
  let v10b = AST.var 64<rt> (Register.toRegID V10B) "V10B"
  let v11a = AST.var 64<rt> (Register.toRegID V11A) "V11A"
  let v11b = AST.var 64<rt> (Register.toRegID V11B) "V11B"
  let v12a = AST.var 64<rt> (Register.toRegID V12A) "V12A"
  let v12b = AST.var 64<rt> (Register.toRegID V12B) "V12B"
  let v13a = AST.var 64<rt> (Register.toRegID V13A) "V13A"
  let v13b = AST.var 64<rt> (Register.toRegID V13B) "V13B"
  let v14a = AST.var 64<rt> (Register.toRegID V14A) "V14A"
  let v14b = AST.var 64<rt> (Register.toRegID V14B) "V14B"
  let v15a = AST.var 64<rt> (Register.toRegID V15A) "V15A"
  let v15b = AST.var 64<rt> (Register.toRegID V15B) "V15B"
  let v16a = AST.var 64<rt> (Register.toRegID V16A) "V16A"
  let v16b = AST.var 64<rt> (Register.toRegID V16B) "V16B"
  let v17a = AST.var 64<rt> (Register.toRegID V17A) "V17A"
  let v17b = AST.var 64<rt> (Register.toRegID V17B) "V17B"
  let v18a = AST.var 64<rt> (Register.toRegID V18A) "V18A"
  let v18b = AST.var 64<rt> (Register.toRegID V18B) "V18B"
  let v19a = AST.var 64<rt> (Register.toRegID V19A) "V19A"
  let v19b = AST.var 64<rt> (Register.toRegID V19B) "V19B"
  let v20a = AST.var 64<rt> (Register.toRegID V20A) "V20A"
  let v20b = AST.var 64<rt> (Register.toRegID V20B) "V20B"
  let v21a = AST.var 64<rt> (Register.toRegID V21A) "V21A"
  let v21b = AST.var 64<rt> (Register.toRegID V21B) "V21B"
  let v22a = AST.var 64<rt> (Register.toRegID V22A) "V22A"
  let v22b = AST.var 64<rt> (Register.toRegID V22B) "V22B"
  let v23a = AST.var 64<rt> (Register.toRegID V23A) "V23A"
  let v23b = AST.var 64<rt> (Register.toRegID V23B) "V23B"
  let v24a = AST.var 64<rt> (Register.toRegID V24A) "V24A"
  let v24b = AST.var 64<rt> (Register.toRegID V24B) "V24B"
  let v25a = AST.var 64<rt> (Register.toRegID V25A) "V25A"
  let v25b = AST.var 64<rt> (Register.toRegID V25B) "V25B"
  let v26a = AST.var 64<rt> (Register.toRegID V26A) "V26A"
  let v26b = AST.var 64<rt> (Register.toRegID V26B) "V26B"
  let v27a = AST.var 64<rt> (Register.toRegID V27A) "V27A"
  let v27b = AST.var 64<rt> (Register.toRegID V27B) "V27B"
  let v28a = AST.var 64<rt> (Register.toRegID V28A) "V28A"
  let v28b = AST.var 64<rt> (Register.toRegID V28B) "V28B"
  let v29a = AST.var 64<rt> (Register.toRegID V29A) "V29A"
  let v29b = AST.var 64<rt> (Register.toRegID V29B) "V29B"
  let v30a = AST.var 64<rt> (Register.toRegID V30A) "V30A"
  let v30b = AST.var 64<rt> (Register.toRegID V30B) "V30B"
  let v31a = AST.var 64<rt> (Register.toRegID V31A) "V31A"
  let v31b = AST.var 64<rt> (Register.toRegID V31B) "V31B"

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

  (* 128-bit registers *)
  let q0a = AST.var 64<rt> (Register.toRegID V0A) "Q0A"
  let q0b = AST.var 64<rt> (Register.toRegID V0B) "Q0B"
  let q1a = AST.var 64<rt> (Register.toRegID V1A) "Q1A"
  let q1b = AST.var 64<rt> (Register.toRegID V1B) "Q1B"
  let q2a = AST.var 64<rt> (Register.toRegID V2A) "Q2A"
  let q2b = AST.var 64<rt> (Register.toRegID V2B) "Q2B"
  let q3a = AST.var 64<rt> (Register.toRegID V3A) "Q3A"
  let q3b = AST.var 64<rt> (Register.toRegID V3B) "Q3B"
  let q4a = AST.var 64<rt> (Register.toRegID V4A) "Q4A"
  let q4b = AST.var 64<rt> (Register.toRegID V4B) "Q4B"
  let q5a = AST.var 64<rt> (Register.toRegID V5A) "Q5A"
  let q5b = AST.var 64<rt> (Register.toRegID V5B) "Q5B"
  let q6a = AST.var 64<rt> (Register.toRegID V6A) "Q6A"
  let q6b = AST.var 64<rt> (Register.toRegID V6B) "Q6B"
  let q7a = AST.var 64<rt> (Register.toRegID V7A) "Q7A"
  let q7b = AST.var 64<rt> (Register.toRegID V7B) "Q7B"
  let q8a = AST.var 64<rt> (Register.toRegID V8A) "Q8A"
  let q8b = AST.var 64<rt> (Register.toRegID V8B) "Q8B"
  let q9a = AST.var 64<rt> (Register.toRegID V9A) "Q9A"
  let q9b = AST.var 64<rt> (Register.toRegID V9B) "Q9B"
  let q10a = AST.var 64<rt> (Register.toRegID V10A) "Q10A"
  let q10b = AST.var 64<rt> (Register.toRegID V10B) "Q10B"
  let q11a = AST.var 64<rt> (Register.toRegID V11A) "Q11A"
  let q11b = AST.var 64<rt> (Register.toRegID V11B) "Q11B"
  let q12a = AST.var 64<rt> (Register.toRegID V12A) "Q12A"
  let q12b = AST.var 64<rt> (Register.toRegID V12B) "Q12B"
  let q13a = AST.var 64<rt> (Register.toRegID V13A) "Q13A"
  let q13b = AST.var 64<rt> (Register.toRegID V13B) "Q13B"
  let q14a = AST.var 64<rt> (Register.toRegID V14A) "Q14A"
  let q14b = AST.var 64<rt> (Register.toRegID V14B) "Q14B"
  let q15a = AST.var 64<rt> (Register.toRegID V15A) "Q15A"
  let q15b = AST.var 64<rt> (Register.toRegID V15B) "Q15B"
  let q16a = AST.var 64<rt> (Register.toRegID V16A) "Q16A"
  let q16b = AST.var 64<rt> (Register.toRegID V16B) "Q16B"
  let q17a = AST.var 64<rt> (Register.toRegID V17A) "Q17A"
  let q17b = AST.var 64<rt> (Register.toRegID V17B) "Q17B"
  let q18a = AST.var 64<rt> (Register.toRegID V18A) "Q18A"
  let q18b = AST.var 64<rt> (Register.toRegID V18B) "Q18B"
  let q19a = AST.var 64<rt> (Register.toRegID V19A) "Q19A"
  let q19b = AST.var 64<rt> (Register.toRegID V19B) "Q19B"
  let q20a = AST.var 64<rt> (Register.toRegID V20A) "Q20A"
  let q20b = AST.var 64<rt> (Register.toRegID V20B) "Q20B"
  let q21a = AST.var 64<rt> (Register.toRegID V21A) "Q21A"
  let q21b = AST.var 64<rt> (Register.toRegID V21B) "Q21B"
  let q22a = AST.var 64<rt> (Register.toRegID V22A) "Q22A"
  let q22b = AST.var 64<rt> (Register.toRegID V22B) "Q22B"
  let q23a = AST.var 64<rt> (Register.toRegID V23A) "Q23A"
  let q23b = AST.var 64<rt> (Register.toRegID V23B) "Q23B"
  let q24a = AST.var 64<rt> (Register.toRegID V24A) "Q24A"
  let q24b = AST.var 64<rt> (Register.toRegID V24B) "Q24B"
  let q25a = AST.var 64<rt> (Register.toRegID V25A) "Q25A"
  let q25b = AST.var 64<rt> (Register.toRegID V25B) "Q25B"
  let q26a = AST.var 64<rt> (Register.toRegID V26A) "Q26A"
  let q26b = AST.var 64<rt> (Register.toRegID V26B) "Q26B"
  let q27a = AST.var 64<rt> (Register.toRegID V27A) "Q27A"
  let q27b = AST.var 64<rt> (Register.toRegID V27B) "Q27B"
  let q28a = AST.var 64<rt> (Register.toRegID V28A) "Q28A"
  let q28b = AST.var 64<rt> (Register.toRegID V28B) "Q28B"
  let q29a = AST.var 64<rt> (Register.toRegID V29A) "Q29A"
  let q29b = AST.var 64<rt> (Register.toRegID V29B) "Q29B"
  let q30a = AST.var 64<rt> (Register.toRegID V30A) "Q30A"
  let q30b = AST.var 64<rt> (Register.toRegID V30B) "Q30B"
  let q31a = AST.var 64<rt> (Register.toRegID V31A) "Q31A"
  let q31b = AST.var 64<rt> (Register.toRegID V31B) "Q31B"

  (* Floating-point control and status registers *)
  let fpcr = AST.var 64<rt> (Register.toRegID FPCR) "FPCR"
  let fpsr = AST.var 64<rt> (Register.toRegID FPSR) "FPSR"

  (* Process state, PSTATE *)
  /// Negative condition flag.
  let n = AST.var 1<rt> (Register.toRegID N) "N"
  /// Zero condition flag.
  let z = AST.var 1<rt> (Register.toRegID Z) "Z"
  /// Carry condition flag.
  let c = AST.var 1<rt> (Register.toRegID C) "C"
  /// Overflow condition flag.
  let v = AST.var 1<rt> (Register.toRegID V) "V"

  (* System registers *)
  /// Data Cache Zero ID register.
  let dczidel0 = AST.var 64<rt> (Register.toRegID DCZIDEL0) "DCZID_EL0"
  /// Main ID ARM64.
  let midrel1 = AST.var 64<rt> (Register.toRegID MIDREL1) "MIDR_EL1"
  /// EL0 Read/Write Software Thread ID ARM64.
  let tpidrel0 = AST.var 64<rt> (Register.toRegID TPIDREL0) "TPIDR_EL0"

  (* S<op0>_<op1>_<Cn>_<Cm>_<op2> *)
  let s35c3c20 =
    AST.var 64<rt> (Register.toRegID S3_5_C3_C2_0) "S3_5_C3_C2_0"
  let s37c2c27 =
    AST.var 64<rt> (Register.toRegID S3_7_C2_C2_7) "S3_7_C2_C2_7"
  let s00c2c93 =
    AST.var 64<rt> (Register.toRegID S0_0_C2_C9_3) "S0_0_C2_C9_3"
  let s27c12c76 =
    AST.var 64<rt> (Register.toRegID S2_7_C12_C7_6) "S2_7_C12_C7_6"

  (* Extra pseudo registers. *)
  /// Pseudo register for passing a return value from an external call.
  let eret = AST.var 64<rt> (Register.toRegID ERET) "ERET"

  interface IRegisterFactory with

    member _.GetRegVar rid =
      match Register.ofRegID rid with
      | R.X0  -> x0
      | R.X1  -> x1
      | R.X2  -> x2
      | R.X3  -> x3
      | R.X4  -> x4
      | R.X5  -> x5
      | R.X6  -> x6
      | R.X7  -> x7
      | R.X8  -> x8
      | R.X9  -> x9
      | R.X10 -> x10
      | R.X11 -> x11
      | R.X12 -> x12
      | R.X13 -> x13
      | R.X14 -> x14
      | R.X15 -> x15
      | R.X16 -> x16
      | R.X17 -> x17
      | R.X18 -> x18
      | R.X19 -> x19
      | R.X20 -> x20
      | R.X21 -> x21
      | R.X22 -> x22
      | R.X23 -> x23
      | R.X24 -> x24
      | R.X25 -> x25
      | R.X26 -> x26
      | R.X27 -> x27
      | R.X28 -> x28
      | R.X29 -> x29
      | R.X30 -> x30
      | R.XZR -> xzr
      | R.W0  -> w0
      | R.W1  -> w1
      | R.W2  -> w2
      | R.W3  -> w3
      | R.W4  -> w4
      | R.W5  -> w5
      | R.W6  -> w6
      | R.W7  -> w7
      | R.W8  -> w8
      | R.W9  -> w9
      | R.W10 -> w10
      | R.W11 -> w11
      | R.W12 -> w12
      | R.W13 -> w13
      | R.W14 -> w14
      | R.W15 -> w15
      | R.W16 -> w16
      | R.W17 -> w17
      | R.W18 -> w18
      | R.W19 -> w19
      | R.W20 -> w20
      | R.W21 -> w21
      | R.W22 -> w22
      | R.W23 -> w23
      | R.W24 -> w24
      | R.W25 -> w25
      | R.W26 -> w26
      | R.W27 -> w27
      | R.W28 -> w28
      | R.W29 -> w29
      | R.W30 -> w30
      | R.WZR -> wzr
      | R.SP  -> sp
      | R.WSP -> wsp
      | R.PC  -> pc
      | R.D0  -> d0
      | R.D1  -> d1
      | R.D2  -> d2
      | R.D3  -> d3
      | R.D4  -> d4
      | R.D5  -> d5
      | R.D6  -> d6
      | R.D7  -> d7
      | R.D8  -> d8
      | R.D9  -> d9
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
      | R.S0  -> s0
      | R.S1  -> s1
      | R.S2  -> s2
      | R.S3  -> s3
      | R.S4  -> s4
      | R.S5  -> s5
      | R.S6  -> s6
      | R.S7  -> s7
      | R.S8  -> s8
      | R.S9  -> s9
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
      | R.H0  -> h0
      | R.H1  -> h1
      | R.H2  -> h2
      | R.H3  -> h3
      | R.H4  -> h4
      | R.H5  -> h5
      | R.H6  -> h6
      | R.H7  -> h7
      | R.H8  -> h8
      | R.H9  -> h9
      | R.H10 -> h10
      | R.H11 -> h11
      | R.H12 -> h12
      | R.H13 -> h13
      | R.H14 -> h14
      | R.H15 -> h15
      | R.H16 -> h16
      | R.H17 -> h17
      | R.H18 -> h18
      | R.H19 -> h19
      | R.H20 -> h20
      | R.H21 -> h21
      | R.H22 -> h22
      | R.H23 -> h23
      | R.H24 -> h24
      | R.H25 -> h25
      | R.H26 -> h26
      | R.H27 -> h27
      | R.H28 -> h28
      | R.H29 -> h29
      | R.H30 -> h30
      | R.H31 -> h31
      | R.B0  -> b0
      | R.B1  -> b1
      | R.B2  -> b2
      | R.B3  -> b3
      | R.B4  -> b4
      | R.B5  -> b5
      | R.B6  -> b6
      | R.B7  -> b7
      | R.B8  -> b8
      | R.B9  -> b9
      | R.B10 -> b10
      | R.B11 -> b11
      | R.B12 -> b12
      | R.B13 -> b13
      | R.B14 -> b14
      | R.B15 -> b15
      | R.B16 -> b16
      | R.B17 -> b17
      | R.B18 -> b18
      | R.B19 -> b19
      | R.B20 -> b20
      | R.B21 -> b21
      | R.B22 -> b22
      | R.B23 -> b23
      | R.B24 -> b24
      | R.B25 -> b25
      | R.B26 -> b26
      | R.B27 -> b27
      | R.B28 -> b28
      | R.B29 -> b29
      | R.B30 -> b30
      | R.B31 -> b31
      | R.FPCR -> fpcr
      | R.FPSR -> fpsr
      | R.N -> n
      | R.Z -> z
      | R.C -> c
      | R.V -> v
      | R.DCZIDEL0 -> dczidel0
      | R.MIDREL1 -> midrel1
      | R.TPIDREL0 -> tpidrel0
      | R.S3_5_C3_C2_0 -> s35c3c20
      | R.S3_7_C2_C2_7 -> s37c2c27
      | R.S0_0_C2_C9_3 -> s00c2c93
      | R.S2_7_C12_C7_6 -> s27c12c76
      | R.ERET -> eret
      | _ -> raise UnhandledRegExprException

    member _.GetRegVar name =
      match name with
      | "X0" -> x0
      | "X1" -> x1
      | "X2" -> x2
      | "X3" -> x3
      | "X4" -> x4
      | "X5" -> x5
      | "X6" -> x6
      | "X7" -> x7
      | "X8" -> x8
      | "X9" -> x9
      | "X10" -> x10
      | "X11" -> x11
      | "X12" -> x12
      | "X13" -> x13
      | "X14" -> x14
      | "X15" -> x15
      | "X16" -> x16
      | "X17" -> x17
      | "X18" -> x18
      | "X19" -> x19
      | "X20" -> x20
      | "X21" -> x21
      | "X22" -> x22
      | "X23" -> x23
      | "X24" -> x24
      | "X25" -> x25
      | "X26" -> x26
      | "X27" -> x27
      | "X28" -> x28
      | "X29" -> x29
      | "X30" -> x30
      | "XZR" -> xzr
      | "W0" -> w0
      | "W1" -> w1
      | "W2" -> w2
      | "W3" -> w3
      | "W4" -> w4
      | "W5" -> w5
      | "W6" -> w6
      | "W7" -> w7
      | "W8" -> w8
      | "W9" -> w9
      | "W10" -> w10
      | "W11" -> w11
      | "W12" -> w12
      | "W13" -> w13
      | "W14" -> w14
      | "W15" -> w15
      | "W16" -> w16
      | "W17" -> w17
      | "W18" -> w18
      | "W19" -> w19
      | "W20" -> w20
      | "W21" -> w21
      | "W22" -> w22
      | "W23" -> w23
      | "W24" -> w24
      | "W25" -> w25
      | "W26" -> w26
      | "W27" -> w27
      | "W28" -> w28
      | "W29" -> w29
      | "W30" -> w30
      | "WZR" -> wzr
      | "SP" -> sp
      | "WSP" -> wsp
      | "PC" -> pc
      | "V0A" -> v0a
      | "V0B" -> v0b
      | "V1A" -> v1a
      | "V1B" -> v1b
      | "V2A" -> v2a
      | "V2B" -> v2b
      | "V3A" -> v3a
      | "V3B" -> v3b
      | "V4A" -> v4a
      | "V4B" -> v4b
      | "V5A" -> v5a
      | "V5B" -> v5b
      | "V6A" -> v6a
      | "V6B" -> v6b
      | "V7A" -> v7a
      | "V7B" -> v7b
      | "V8A" -> v8a
      | "V8B" -> v8b
      | "V9A" -> v9a
      | "V9B" -> v9b
      | "V10A" -> v10a
      | "V10B" -> v10b
      | "V11A" -> v11a
      | "V11B" -> v11b
      | "V12A" -> v12a
      | "V12B" -> v12b
      | "V13A" -> v13a
      | "V13B" -> v13b
      | "V14A" -> v14a
      | "V14B" -> v14b
      | "V15A" -> v15a
      | "V15B" -> v15b
      | "V16A" -> v16a
      | "V16B" -> v16b
      | "V17A" -> v17a
      | "V17B" -> v17b
      | "V18A" -> v18a
      | "V18B" -> v18b
      | "V19A" -> v19a
      | "V19B" -> v19b
      | "V20A" -> v20a
      | "V20B" -> v20b
      | "V21A" -> v21a
      | "V21B" -> v21b
      | "V22A" -> v22a
      | "V22B" -> v22b
      | "V23A" -> v23a
      | "V23B" -> v23b
      | "V24A" -> v24a
      | "V24B" -> v24b
      | "V25A" -> v25a
      | "V25B" -> v25b
      | "V26A" -> v26a
      | "V26B" -> v26b
      | "V27A" -> v27a
      | "V27B" -> v27b
      | "V28A" -> v28a
      | "V28B" -> v28b
      | "V29A" -> v29a
      | "V29B" -> v29b
      | "V30A" -> v30a
      | "V30B" -> v30b
      | "V31A" -> v31a
      | "V31B" -> v31b
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
      | "Q16A" -> q16a
      | "Q16B" -> q16b
      | "Q17A" -> q17a
      | "Q17B" -> q17b
      | "Q18A" -> q18a
      | "Q18B" -> q18b
      | "Q19A" -> q19a
      | "Q19B" -> q19b
      | "Q20A" -> q20a
      | "Q20B" -> q20b
      | "Q21A" -> q21a
      | "Q21B" -> q21b
      | "Q22A" -> q22a
      | "Q22B" -> q22b
      | "Q23A" -> q23a
      | "Q23B" -> q23b
      | "Q24A" -> q24a
      | "Q24B" -> q24b
      | "Q25A" -> q25a
      | "Q25B" -> q25b
      | "Q26A" -> q26a
      | "Q26B" -> q26b
      | "Q27A" -> q27a
      | "Q27B" -> q27b
      | "Q28A" -> q28a
      | "Q28B" -> q28b
      | "Q29A" -> q29a
      | "Q29B" -> q29b
      | "Q30A" -> q30a
      | "Q30B" -> q30b
      | "Q31A" -> q31a
      | "Q31B" -> q31b
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
      | "H0" -> h0
      | "H1" -> h1
      | "H2" -> h2
      | "H3" -> h3
      | "H4" -> h4
      | "H5" -> h5
      | "H6" -> h6
      | "H7" -> h7
      | "H8" -> h8
      | "H9" -> h9
      | "H10" -> h10
      | "H11" -> h11
      | "H12" -> h12
      | "H13" -> h13
      | "H14" -> h14
      | "H15" -> h15
      | "H16" -> h16
      | "H17" -> h17
      | "H18" -> h18
      | "H19" -> h19
      | "H20" -> h20
      | "H21" -> h21
      | "H22" -> h22
      | "H23" -> h23
      | "H24" -> h24
      | "H25" -> h25
      | "H26" -> h26
      | "H27" -> h27
      | "H28" -> h28
      | "H29" -> h29
      | "H30" -> h30
      | "H31" -> h31
      | "B0" -> b0
      | "B1" -> b1
      | "B2" -> b2
      | "B3" -> b3
      | "B4" -> b4
      | "B5" -> b5
      | "B6" -> b6
      | "B7" -> b7
      | "B8" -> b8
      | "B9" -> b9
      | "B10" -> b10
      | "B11" -> b11
      | "B12" -> b12
      | "B13" -> b13
      | "B14" -> b14
      | "B15" -> b15
      | "B16" -> b16
      | "B17" -> b17
      | "B18" -> b18
      | "B19" -> b19
      | "B20" -> b20
      | "B21" -> b21
      | "B22" -> b22
      | "B23" -> b23
      | "B24" -> b24
      | "B25" -> b25
      | "B26" -> b26
      | "B27" -> b27
      | "B28" -> b28
      | "B29" -> b29
      | "B30" -> b30
      | "B31" -> b31
      | "FPCR" -> fpcr
      | "FPSR" -> fpsr
      | "N" -> n
      | "Z" -> z
      | "C" -> c
      | "V" -> v
      | _ -> raise UnhandledRegExprException

    member _.GetPseudoRegVar rid pos =
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
      | R.Q16, 1 -> q16a
      | R.Q16, 2 -> q16b
      | R.Q17, 1 -> q17a
      | R.Q17, 2 -> q17b
      | R.Q18, 1 -> q18a
      | R.Q18, 2 -> q18b
      | R.Q19, 1 -> q19a
      | R.Q19, 2 -> q19b
      | R.Q20, 1 -> q20a
      | R.Q20, 2 -> q20b
      | R.Q21, 1 -> q21a
      | R.Q21, 2 -> q21b
      | R.Q22, 1 -> q22a
      | R.Q22, 2 -> q22b
      | R.Q23, 1 -> q23a
      | R.Q23, 2 -> q23b
      | R.Q24, 1 -> q24a
      | R.Q24, 2 -> q24b
      | R.Q25, 1 -> q25a
      | R.Q25, 2 -> q25b
      | R.Q26, 1 -> q26a
      | R.Q26, 2 -> q26b
      | R.Q27, 1 -> q27a
      | R.Q27, 2 -> q27b
      | R.Q28, 1 -> q28a
      | R.Q28, 2 -> q28b
      | R.Q29, 1 -> q29a
      | R.Q29, 2 -> q29b
      | R.Q30, 1 -> q30a
      | R.Q30, 2 -> q30b
      | R.Q31, 1 -> q31a
      | R.Q31, 2 -> q31b
      | R.V0, 1 -> v0a
      | R.V0, 2 -> v0b
      | R.V1, 1 -> v1a
      | R.V1, 2 -> v1b
      | R.V2, 1 -> v2a
      | R.V2, 2 -> v2b
      | R.V3, 1 -> v3a
      | R.V3, 2 -> v3b
      | R.V4, 1 -> v4a
      | R.V4, 2 -> v4b
      | R.V5, 1 -> v5a
      | R.V5, 2 -> v5b
      | R.V6, 1 -> v6a
      | R.V6, 2 -> v6b
      | R.V7, 1 -> v7a
      | R.V7, 2 -> v7b
      | R.V8, 1 -> v8a
      | R.V8, 2 -> v8b
      | R.V9, 1 -> v9a
      | R.V9, 2 -> v9b
      | R.V10, 1 -> v10a
      | R.V10, 2 -> v10b
      | R.V11, 1 -> v11a
      | R.V11, 2 -> v11b
      | R.V12, 1 -> v12a
      | R.V12, 2 -> v12b
      | R.V13, 1 -> v13a
      | R.V13, 2 -> v13b
      | R.V14, 1 -> v14a
      | R.V14, 2 -> v14b
      | R.V15, 1 -> v15a
      | R.V15, 2 -> v15b
      | R.V16, 1 -> v16a
      | R.V16, 2 -> v16b
      | R.V17, 1 -> v17a
      | R.V17, 2 -> v17b
      | R.V18, 1 -> v18a
      | R.V18, 2 -> v18b
      | R.V19, 1 -> v19a
      | R.V19, 2 -> v19b
      | R.V20, 1 -> v20a
      | R.V20, 2 -> v20b
      | R.V21, 1 -> v21a
      | R.V21, 2 -> v21b
      | R.V22, 1 -> v22a
      | R.V22, 2 -> v22b
      | R.V23, 1 -> v23a
      | R.V23, 2 -> v23b
      | R.V24, 1 -> v24a
      | R.V24, 2 -> v24b
      | R.V25, 1 -> v25a
      | R.V25, 2 -> v25b
      | R.V26, 1 -> v26a
      | R.V26, 2 -> v26b
      | R.V27, 1 -> v27a
      | R.V27, 2 -> v27b
      | R.V28, 1 -> v28a
      | R.V28, 2 -> v28b
      | R.V29, 1 -> v29a
      | R.V29, 2 -> v29b
      | R.V30, 1 -> v30a
      | R.V30, 2 -> v30b
      | R.V31, 1 -> v31a
      | R.V31, 2 -> v31b
      | _ -> raise UnhandledRegExprException

    member _.GetAllRegVars () =
      [| x0
         x1
         x2
         x3
         x4
         x5
         x6
         x7
         x8
         x9
         x10
         x11
         x12
         x13
         x14
         x15
         x16
         x17
         x18
         x19
         x20
         x21
         x22
         x23
         x24
         x25
         x26
         x27
         x28
         x29
         x30
         xzr
         w0
         w1
         w2
         w3
         w4
         w5
         w6
         w7
         w8
         w9
         w10
         w11
         w12
         w13
         w14
         w15
         w16
         w17
         w18
         w19
         w20
         w21
         w22
         w23
         w24
         w25
         w26
         w27
         w28
         w29
         w30
         wzr
         sp
         wsp
         pc
         v0a
         v0b
         v1a
         v1b
         v2a
         v2b
         v3a
         v3b
         v4a
         v4b
         v5a
         v5b
         v6a
         v6b
         v7a
         v7b
         v8a
         v8b
         v9a
         v9b
         v10a
         v10b
         v11a
         v11b
         v12a
         v12b
         v13a
         v13b
         v14a
         v14b
         v15a
         v15b
         v16a
         v16b
         v17a
         v17b
         v18a
         v18b
         v19a
         v19b
         v20a
         v20b
         v21a
         v21b
         v22a
         v22b
         v23a
         v23b
         v24a
         v24b
         v25a
         v25b
         v26a
         v26b
         v27a
         v27b
         v28a
         v28b
         v29a
         v29b
         v30a
         v30b
         v31a
         v31b
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
         q16a
         q16b
         q17a
         q17b
         q18a
         q18b
         q19a
         q19b
         q20a
         q20b
         q21a
         q21b
         q22a
         q22b
         q23a
         q23b
         q24a
         q24b
         q25a
         q25b
         q26a
         q26b
         q27a
         q27b
         q28a
         q28b
         q29a
         q29b
         q30a
         q30b
         q31a
         q31b
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
         h0
         h1
         h2
         h3
         h4
         h5
         h6
         h7
         h8
         h9
         h10
         h11
         h12
         h13
         h14
         h15
         h16
         h17
         h18
         h19
         h20
         h21
         h22
         h23
         h24
         h25
         h26
         h27
         h28
         h29
         h30
         h31
         b0
         b1
         b2
         b3
         b4
         b5
         b6
         b7
         b8
         b9
         b10
         b11
         b12
         b13
         b14
         b15
         b16
         b17
         b18
         b19
         b20
         b21
         b22
         b23
         b24
         b25
         b26
         b27
         b28
         b29
         b30
         b31
         fpcr
         fpsr
         n
         z
         c |]

    member _.GetGeneralRegVars () =
      [| x0
         x1
         x2
         x3
         x4
         x5
         x6
         x7
         x8
         x9
         x10
         x11
         x12
         x13
         x14
         x15
         x16
         x17
         x18
         x19
         x20
         x21
         x22
         x23
         x24
         x25
         x26
         x27
         x28
         x29
         x30
         xzr
         n
         z
         c |]

    member _.GetRegisterID expr =
      match expr with
      | Var (_, id, _, _) -> id
      | PCVar _ -> Register.toRegID PC
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name =
      Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases rid =
      Register.ofRegID rid
      |> Register.getAliases
      |> Array.map Register.toRegID

    member _.GetRegString rid =
      Register.ofRegID rid |> Register.toString

    member this.GetAllRegStrings () =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars ()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegString)

    member _.GetRegType rid =
      Register.ofRegID rid |> Register.toRegType

    member _.ProgramCounter =
      PC |> Register.toRegID

    member _.StackPointer =
      SP |> Register.toRegID |> Some

    member _.FramePointer =
      None

    member _.IsProgramCounter regid =
      let pcid = PC |> Register.toRegID
      pcid = regid

    member _.IsStackPointer regid =
      let spid = SP |> Register.toRegID
      spid = regid

    member _.IsFramePointer _ = false
