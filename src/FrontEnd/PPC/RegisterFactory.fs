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

namespace B2R2.FrontEnd.PPC

open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR
open type Register

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.PPC.Tests")>]
do ()

/// Represents a factory for accessing various PPC register variables.
type RegisterFactory(isa: ISA) =
  let rt = WordSize.toRegType isa.WordSize

  let r0 = AST.var rt (Register.toRegID R0) "R0"
  let r1 = AST.var rt (Register.toRegID R1) "R1"
  let r2 = AST.var rt (Register.toRegID R2) "R2"
  let r3 = AST.var rt (Register.toRegID R3) "R3"
  let r4 = AST.var rt (Register.toRegID R4) "R4"
  let r5 = AST.var rt (Register.toRegID R5) "R5"
  let r6 = AST.var rt (Register.toRegID R6) "R6"
  let r7 = AST.var rt (Register.toRegID R7) "R7"
  let r8 = AST.var rt (Register.toRegID R8) "R8"
  let r9 = AST.var rt (Register.toRegID R9) "R9"
  let r10 = AST.var rt (Register.toRegID R10) "R10"
  let r11 = AST.var rt (Register.toRegID R11) "R11"
  let r12 = AST.var rt (Register.toRegID R12) "R12"
  let r13 = AST.var rt (Register.toRegID R13) "R13"
  let r14 = AST.var rt (Register.toRegID R14) "R14"
  let r15 = AST.var rt (Register.toRegID R15) "R15"
  let r16 = AST.var rt (Register.toRegID R16) "R16"
  let r17 = AST.var rt (Register.toRegID R17) "R17"
  let r18 = AST.var rt (Register.toRegID R18) "R18"
  let r19 = AST.var rt (Register.toRegID R19) "R19"
  let r20 = AST.var rt (Register.toRegID R20) "R20"
  let r21 = AST.var rt (Register.toRegID R21) "R21"
  let r22 = AST.var rt (Register.toRegID R22) "R22"
  let r23 = AST.var rt (Register.toRegID R23) "R23"
  let r24 = AST.var rt (Register.toRegID R24) "R24"
  let r25 = AST.var rt (Register.toRegID R25) "R25"
  let r26 = AST.var rt (Register.toRegID R26) "R26"
  let r27 = AST.var rt (Register.toRegID R27) "R27"
  let r28 = AST.var rt (Register.toRegID R28) "R28"
  let r29 = AST.var rt (Register.toRegID R29) "R29"
  let r30 = AST.var rt (Register.toRegID R30) "R30"
  let r31 = AST.var rt (Register.toRegID R31) "R31"
  let f0 = AST.var 64<rt> (Register.toRegID F0) "F0"
  let f1 = AST.var 64<rt> (Register.toRegID F1) "F1"
  let f2 = AST.var 64<rt> (Register.toRegID F2) "F2"
  let f3 = AST.var 64<rt> (Register.toRegID F3) "F3"
  let f4 = AST.var 64<rt> (Register.toRegID F4) "F4"
  let f5 = AST.var 64<rt> (Register.toRegID F5) "F5"
  let f6 = AST.var 64<rt> (Register.toRegID F6) "F6"
  let f7 = AST.var 64<rt> (Register.toRegID F7) "F7"
  let f8 = AST.var 64<rt> (Register.toRegID F8) "F8"
  let f9 = AST.var 64<rt> (Register.toRegID F9) "F9"
  let f10 = AST.var 64<rt> (Register.toRegID F10) "F10"
  let f11 = AST.var 64<rt> (Register.toRegID F11) "F11"
  let f12 = AST.var 64<rt> (Register.toRegID F12) "F12"
  let f13 = AST.var 64<rt> (Register.toRegID F13) "F13"
  let f14 = AST.var 64<rt> (Register.toRegID F14) "F14"
  let f15 = AST.var 64<rt> (Register.toRegID F15) "F15"
  let f16 = AST.var 64<rt> (Register.toRegID F16) "F16"
  let f17 = AST.var 64<rt> (Register.toRegID F17) "F17"
  let f18 = AST.var 64<rt> (Register.toRegID F18) "F18"
  let f19 = AST.var 64<rt> (Register.toRegID F19) "F19"
  let f20 = AST.var 64<rt> (Register.toRegID F20) "F20"
  let f21 = AST.var 64<rt> (Register.toRegID F21) "F21"
  let f22 = AST.var 64<rt> (Register.toRegID F22) "F22"
  let f23 = AST.var 64<rt> (Register.toRegID F23) "F23"
  let f24 = AST.var 64<rt> (Register.toRegID F24) "F24"
  let f25 = AST.var 64<rt> (Register.toRegID F25) "F25"
  let f26 = AST.var 64<rt> (Register.toRegID F26) "F26"
  let f27 = AST.var 64<rt> (Register.toRegID F27) "F27"
  let f28 = AST.var 64<rt> (Register.toRegID F28) "F28"
  let f29 = AST.var 64<rt> (Register.toRegID F29) "F29"
  let f30 = AST.var 64<rt> (Register.toRegID F30) "F30"
  let f31 = AST.var 64<rt> (Register.toRegID F31) "F31"
  let cr00 = AST.var 1<rt> (Register.toRegID CR0_0) "CR0_0"
  let cr01 = AST.var 1<rt> (Register.toRegID CR0_1) "CR0_1"
  let cr02 = AST.var 1<rt> (Register.toRegID CR0_2) "CR0_2"
  let cr03 = AST.var 1<rt> (Register.toRegID CR0_3) "CR0_3"
  let cr10 = AST.var 1<rt> (Register.toRegID CR1_0) "CR1_0"
  let cr11 = AST.var 1<rt> (Register.toRegID CR1_1) "CR1_1"
  let cr12 = AST.var 1<rt> (Register.toRegID CR1_2) "CR1_2"
  let cr13 = AST.var 1<rt> (Register.toRegID CR1_3) "CR1_3"
  let cr20 = AST.var 1<rt> (Register.toRegID CR2_0) "CR2_0"
  let cr21 = AST.var 1<rt> (Register.toRegID CR2_1) "CR2_1"
  let cr22 = AST.var 1<rt> (Register.toRegID CR2_2) "CR2_2"
  let cr23 = AST.var 1<rt> (Register.toRegID CR2_3) "CR2_3"
  let cr30 = AST.var 1<rt> (Register.toRegID CR3_0) "CR3_0"
  let cr31 = AST.var 1<rt> (Register.toRegID CR3_1) "CR3_1"
  let cr32 = AST.var 1<rt> (Register.toRegID CR3_2) "CR3_2"
  let cr33 = AST.var 1<rt> (Register.toRegID CR3_3) "CR3_3"
  let cr40 = AST.var 1<rt> (Register.toRegID CR4_0) "CR4_0"
  let cr41 = AST.var 1<rt> (Register.toRegID CR4_1) "CR4_1"
  let cr42 = AST.var 1<rt> (Register.toRegID CR4_2) "CR4_2"
  let cr43 = AST.var 1<rt> (Register.toRegID CR4_3) "CR4_3"
  let cr50 = AST.var 1<rt> (Register.toRegID CR5_0) "CR5_0"
  let cr51 = AST.var 1<rt> (Register.toRegID CR5_1) "CR5_1"
  let cr52 = AST.var 1<rt> (Register.toRegID CR5_2) "CR5_2"
  let cr53 = AST.var 1<rt> (Register.toRegID CR5_3) "CR5_3"
  let cr60 = AST.var 1<rt> (Register.toRegID CR6_0) "CR6_0"
  let cr61 = AST.var 1<rt> (Register.toRegID CR6_1) "CR6_1"
  let cr62 = AST.var 1<rt> (Register.toRegID CR6_2) "CR6_2"
  let cr63 = AST.var 1<rt> (Register.toRegID CR6_3) "CR6_3"
  let cr70 = AST.var 1<rt> (Register.toRegID CR7_0) "CR7_0"
  let cr71 = AST.var 1<rt> (Register.toRegID CR7_1) "CR7_1"
  let cr72 = AST.var 1<rt> (Register.toRegID CR7_2) "CR7_2"
  let cr73 = AST.var 1<rt> (Register.toRegID CR7_3) "CR7_3"
  let fpscr = AST.var 32<rt> (Register.toRegID FPSCR) "FPSCR"
  let xer = AST.var 32<rt> (Register.toRegID XER) "XER"
  let lr = AST.var rt (Register.toRegID LR) "LR"
  let ctr = AST.var rt (Register.toRegID CTR) "CTR"
  let pvr = AST.var 32<rt> (Register.toRegID PVR) "PVR"
  let res = AST.var 1<rt> (Register.toRegID RES) "RES"
  let iar = AST.pcvar rt "IAR"
  let exMonAddr = AST.var rt (Register.toRegID ExMonAddr) "ExMonAddr"
  let exMonVal = AST.var rt (Register.toRegID ExMonVal) "ExMonVal"
  let vscr = AST.var 32<rt> (Register.toRegID VSCR) "VSCR"
  let vrsave = AST.var 32<rt> (Register.toRegID VRSAVE) "VRSAVE"
  let v0a = AST.var 64<rt> (Register.toRegID V0A) "V0A"
  let v0b = AST.var 64<rt> (Register.toRegID V0B) "V0B"
  let v1a = AST.var 64<rt> (Register.toRegID V1A) "V1A"
  let v1b = AST.var 64<rt> (Register.toRegID V1B) "V1B"
  let v2a = AST.var 64<rt> (Register.toRegID V2A) "V2A"
  let v2b = AST.var 64<rt> (Register.toRegID V2B) "V2B"
  let v3a = AST.var 64<rt> (Register.toRegID V3A) "V3A"
  let v3b = AST.var 64<rt> (Register.toRegID V3B) "V3B"
  let v4a = AST.var 64<rt> (Register.toRegID V4A) "V4A"
  let v4b = AST.var 64<rt> (Register.toRegID V4B) "V4B"
  let v5a = AST.var 64<rt> (Register.toRegID V5A) "V5A"
  let v5b = AST.var 64<rt> (Register.toRegID V5B) "V5B"
  let v6a = AST.var 64<rt> (Register.toRegID V6A) "V6A"
  let v6b = AST.var 64<rt> (Register.toRegID V6B) "V6B"
  let v7a = AST.var 64<rt> (Register.toRegID V7A) "V7A"
  let v7b = AST.var 64<rt> (Register.toRegID V7B) "V7B"
  let v8a = AST.var 64<rt> (Register.toRegID V8A) "V8A"
  let v8b = AST.var 64<rt> (Register.toRegID V8B) "V8B"
  let v9a = AST.var 64<rt> (Register.toRegID V9A) "V9A"
  let v9b = AST.var 64<rt> (Register.toRegID V9B) "V9B"
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
  let vsrl0 = AST.var 64<rt> (Register.toRegID VSRL0) "VSRL0"
  let vsrl1 = AST.var 64<rt> (Register.toRegID VSRL1) "VSRL1"
  let vsrl2 = AST.var 64<rt> (Register.toRegID VSRL2) "VSRL2"
  let vsrl3 = AST.var 64<rt> (Register.toRegID VSRL3) "VSRL3"
  let vsrl4 = AST.var 64<rt> (Register.toRegID VSRL4) "VSRL4"
  let vsrl5 = AST.var 64<rt> (Register.toRegID VSRL5) "VSRL5"
  let vsrl6 = AST.var 64<rt> (Register.toRegID VSRL6) "VSRL6"
  let vsrl7 = AST.var 64<rt> (Register.toRegID VSRL7) "VSRL7"
  let vsrl8 = AST.var 64<rt> (Register.toRegID VSRL8) "VSRL8"
  let vsrl9 = AST.var 64<rt> (Register.toRegID VSRL9) "VSRL9"
  let vsrl10 = AST.var 64<rt> (Register.toRegID VSRL10) "VSRL10"
  let vsrl11 = AST.var 64<rt> (Register.toRegID VSRL11) "VSRL11"
  let vsrl12 = AST.var 64<rt> (Register.toRegID VSRL12) "VSRL12"
  let vsrl13 = AST.var 64<rt> (Register.toRegID VSRL13) "VSRL13"
  let vsrl14 = AST.var 64<rt> (Register.toRegID VSRL14) "VSRL14"
  let vsrl15 = AST.var 64<rt> (Register.toRegID VSRL15) "VSRL15"
  let vsrl16 = AST.var 64<rt> (Register.toRegID VSRL16) "VSRL16"
  let vsrl17 = AST.var 64<rt> (Register.toRegID VSRL17) "VSRL17"
  let vsrl18 = AST.var 64<rt> (Register.toRegID VSRL18) "VSRL18"
  let vsrl19 = AST.var 64<rt> (Register.toRegID VSRL19) "VSRL19"
  let vsrl20 = AST.var 64<rt> (Register.toRegID VSRL20) "VSRL20"
  let vsrl21 = AST.var 64<rt> (Register.toRegID VSRL21) "VSRL21"
  let vsrl22 = AST.var 64<rt> (Register.toRegID VSRL22) "VSRL22"
  let vsrl23 = AST.var 64<rt> (Register.toRegID VSRL23) "VSRL23"
  let vsrl24 = AST.var 64<rt> (Register.toRegID VSRL24) "VSRL24"
  let vsrl25 = AST.var 64<rt> (Register.toRegID VSRL25) "VSRL25"
  let vsrl26 = AST.var 64<rt> (Register.toRegID VSRL26) "VSRL26"
  let vsrl27 = AST.var 64<rt> (Register.toRegID VSRL27) "VSRL27"
  let vsrl28 = AST.var 64<rt> (Register.toRegID VSRL28) "VSRL28"
  let vsrl29 = AST.var 64<rt> (Register.toRegID VSRL29) "VSRL29"
  let vsrl30 = AST.var 64<rt> (Register.toRegID VSRL30) "VSRL30"
  let vsrl31 = AST.var 64<rt> (Register.toRegID VSRL31) "VSRL31"

  interface IRegisterFactory with
    member _.ISA = isa

    member _.ProgramCounter = IAR |> Register.toRegID

    member _.StackPointer = R1 |> Register.toRegID |> Some

    member _.FramePointer = None

    member _.GetRegVar id =
      match Register.ofRegID id with
      | Register.R0 -> r0
      | Register.R1 -> r1
      | Register.R2 -> r2
      | Register.R3 -> r3
      | Register.R4 -> r4
      | Register.R5 -> r5
      | Register.R6 -> r6
      | Register.R7 -> r7
      | Register.R8 -> r8
      | Register.R9 -> r9
      | Register.R10 -> r10
      | Register.R11 -> r11
      | Register.R12 -> r12
      | Register.R13 -> r13
      | Register.R14 -> r14
      | Register.R15 -> r15
      | Register.R16 -> r16
      | Register.R17 -> r17
      | Register.R18 -> r18
      | Register.R19 -> r19
      | Register.R20 -> r20
      | Register.R21 -> r21
      | Register.R22 -> r22
      | Register.R23 -> r23
      | Register.R24 -> r24
      | Register.R25 -> r25
      | Register.R26 -> r26
      | Register.R27 -> r27
      | Register.R28 -> r28
      | Register.R29 -> r29
      | Register.R30 -> r30
      | Register.R31 -> r31
      | Register.F0 -> f0
      | Register.F1 -> f1
      | Register.F2 -> f2
      | Register.F3 -> f3
      | Register.F4 -> f4
      | Register.F5 -> f5
      | Register.F6 -> f6
      | Register.F7 -> f7
      | Register.F8 -> f8
      | Register.F9 -> f9
      | Register.F10 -> f10
      | Register.F11 -> f11
      | Register.F12 -> f12
      | Register.F13 -> f13
      | Register.F14 -> f14
      | Register.F15 -> f15
      | Register.F16 -> f16
      | Register.F17 -> f17
      | Register.F18 -> f18
      | Register.F19 -> f19
      | Register.F20 -> f20
      | Register.F21 -> f21
      | Register.F22 -> f22
      | Register.F23 -> f23
      | Register.F24 -> f24
      | Register.F25 -> f25
      | Register.F26 -> f26
      | Register.F27 -> f27
      | Register.F28 -> f28
      | Register.F29 -> f29
      | Register.F30 -> f30
      | Register.F31 -> f31
      | Register.CR0_0 -> cr00
      | Register.CR0_1 -> cr01
      | Register.CR0_2 -> cr02
      | Register.CR0_3 -> cr03
      | Register.CR1_0 -> cr10
      | Register.CR1_1 -> cr11
      | Register.CR1_2 -> cr12
      | Register.CR1_3 -> cr13
      | Register.CR2_0 -> cr20
      | Register.CR2_1 -> cr21
      | Register.CR2_2 -> cr22
      | Register.CR2_3 -> cr23
      | Register.CR3_0 -> cr30
      | Register.CR3_1 -> cr31
      | Register.CR3_2 -> cr32
      | Register.CR3_3 -> cr33
      | Register.CR4_0 -> cr40
      | Register.CR4_1 -> cr41
      | Register.CR4_2 -> cr42
      | Register.CR4_3 -> cr43
      | Register.CR5_0 -> cr50
      | Register.CR5_1 -> cr51
      | Register.CR5_2 -> cr52
      | Register.CR5_3 -> cr53
      | Register.CR6_0 -> cr60
      | Register.CR6_1 -> cr61
      | Register.CR6_2 -> cr62
      | Register.CR6_3 -> cr63
      | Register.CR7_0 -> cr70
      | Register.CR7_1 -> cr71
      | Register.CR7_2 -> cr72
      | Register.CR7_3 -> cr73
      | Register.FPSCR -> fpscr
      | Register.XER -> xer
      | Register.LR -> lr
      | Register.CTR -> ctr
      | Register.PVR -> pvr
      | Register.RES -> res
      | Register.IAR -> iar
      | Register.ExMonAddr -> exMonAddr
      | Register.ExMonVal -> exMonVal
      | Register.VSCR -> vscr
      | Register.VRSAVE -> vrsave
      | Register.V0A -> v0a
      | Register.V0B -> v0b
      | Register.V1A -> v1a
      | Register.V1B -> v1b
      | Register.V2A -> v2a
      | Register.V2B -> v2b
      | Register.V3A -> v3a
      | Register.V3B -> v3b
      | Register.V4A -> v4a
      | Register.V4B -> v4b
      | Register.V5A -> v5a
      | Register.V5B -> v5b
      | Register.V6A -> v6a
      | Register.V6B -> v6b
      | Register.V7A -> v7a
      | Register.V7B -> v7b
      | Register.V8A -> v8a
      | Register.V8B -> v8b
      | Register.V9A -> v9a
      | Register.V9B -> v9b
      | Register.V10A -> v10a
      | Register.V10B -> v10b
      | Register.V11A -> v11a
      | Register.V11B -> v11b
      | Register.V12A -> v12a
      | Register.V12B -> v12b
      | Register.V13A -> v13a
      | Register.V13B -> v13b
      | Register.V14A -> v14a
      | Register.V14B -> v14b
      | Register.V15A -> v15a
      | Register.V15B -> v15b
      | Register.V16A -> v16a
      | Register.V16B -> v16b
      | Register.V17A -> v17a
      | Register.V17B -> v17b
      | Register.V18A -> v18a
      | Register.V18B -> v18b
      | Register.V19A -> v19a
      | Register.V19B -> v19b
      | Register.V20A -> v20a
      | Register.V20B -> v20b
      | Register.V21A -> v21a
      | Register.V21B -> v21b
      | Register.V22A -> v22a
      | Register.V22B -> v22b
      | Register.V23A -> v23a
      | Register.V23B -> v23b
      | Register.V24A -> v24a
      | Register.V24B -> v24b
      | Register.V25A -> v25a
      | Register.V25B -> v25b
      | Register.V26A -> v26a
      | Register.V26B -> v26b
      | Register.V27A -> v27a
      | Register.V27B -> v27b
      | Register.V28A -> v28a
      | Register.V28B -> v28b
      | Register.V29A -> v29a
      | Register.V29B -> v29b
      | Register.V30A -> v30a
      | Register.V30B -> v30b
      | Register.V31A -> v31a
      | Register.V31B -> v31b
      | Register.VSRL0 -> vsrl0
      | Register.VSRL1 -> vsrl1
      | Register.VSRL2 -> vsrl2
      | Register.VSRL3 -> vsrl3
      | Register.VSRL4 -> vsrl4
      | Register.VSRL5 -> vsrl5
      | Register.VSRL6 -> vsrl6
      | Register.VSRL7 -> vsrl7
      | Register.VSRL8 -> vsrl8
      | Register.VSRL9 -> vsrl9
      | Register.VSRL10 -> vsrl10
      | Register.VSRL11 -> vsrl11
      | Register.VSRL12 -> vsrl12
      | Register.VSRL13 -> vsrl13
      | Register.VSRL14 -> vsrl14
      | Register.VSRL15 -> vsrl15
      | Register.VSRL16 -> vsrl16
      | Register.VSRL17 -> vsrl17
      | Register.VSRL18 -> vsrl18
      | Register.VSRL19 -> vsrl19
      | Register.VSRL20 -> vsrl20
      | Register.VSRL21 -> vsrl21
      | Register.VSRL22 -> vsrl22
      | Register.VSRL23 -> vsrl23
      | Register.VSRL24 -> vsrl24
      | Register.VSRL25 -> vsrl25
      | Register.VSRL26 -> vsrl26
      | Register.VSRL27 -> vsrl27
      | Register.VSRL28 -> vsrl28
      | Register.VSRL29 -> vsrl29
      | Register.VSRL30 -> vsrl30
      | Register.VSRL31 -> vsrl31
      | _ -> raise InvalidRegisterException

    member _.GetRegVar(name: string) =
      match name.ToLowerInvariant() with
      | "r0" -> r0
      | "r1" -> r1
      | "r2" -> r2
      | "r3" -> r3
      | "r4" -> r4
      | "r5" -> r5
      | "r6" -> r6
      | "r7" -> r7
      | "r8" -> r8
      | "r9" -> r9
      | "r10" -> r10
      | "r11" -> r11
      | "r12" -> r12
      | "r13" -> r13
      | "r14" -> r14
      | "r15" -> r15
      | "r16" -> r16
      | "r17" -> r17
      | "r18" -> r18
      | "r19" -> r19
      | "r20" -> r20
      | "r21" -> r21
      | "r22" -> r22
      | "r23" -> r23
      | "r24" -> r24
      | "r25" -> r25
      | "r26" -> r26
      | "r27" -> r27
      | "r28" -> r28
      | "r29" -> r29
      | "r30" -> r30
      | "r31" -> r31
      | "f0" -> f0
      | "f1" -> f1
      | "f2" -> f2
      | "f3" -> f3
      | "f4" -> f4
      | "f5" -> f5
      | "f6" -> f6
      | "f7" -> f7
      | "f8" -> f8
      | "f9" -> f9
      | "f10" -> f10
      | "f11" -> f11
      | "f12" -> f12
      | "f13" -> f13
      | "f14" -> f14
      | "f15" -> f15
      | "f16" -> f16
      | "f17" -> f17
      | "f18" -> f18
      | "f19" -> f19
      | "f20" -> f20
      | "f21" -> f21
      | "f22" -> f22
      | "f23" -> f23
      | "f24" -> f24
      | "f25" -> f25
      | "f26" -> f26
      | "f27" -> f27
      | "f28" -> f28
      | "f29" -> f29
      | "f30" -> f30
      | "f31" -> f31
      | "cr0_0" -> cr00
      | "cr0_1" -> cr01
      | "cr0_2" -> cr02
      | "cr0_3" -> cr03
      | "cr1_0" -> cr10
      | "cr1_1" -> cr11
      | "cr1_2" -> cr12
      | "cr1_3" -> cr13
      | "cr2_0" -> cr20
      | "cr2_1" -> cr21
      | "cr2_2" -> cr22
      | "cr2_3" -> cr23
      | "cr3_0" -> cr30
      | "cr3_1" -> cr31
      | "cr3_2" -> cr32
      | "cr3_3" -> cr33
      | "cr4_0" -> cr40
      | "cr4_1" -> cr41
      | "cr4_2" -> cr42
      | "cr4_3" -> cr43
      | "cr5_0" -> cr50
      | "cr5_1" -> cr51
      | "cr5_2" -> cr52
      | "cr5_3" -> cr53
      | "cr6_0" -> cr60
      | "cr6_1" -> cr61
      | "cr6_2" -> cr62
      | "cr6_3" -> cr63
      | "cr7_0" -> cr70
      | "cr7_1" -> cr71
      | "cr7_2" -> cr72
      | "cr7_3" -> cr73
      | "iar" -> iar
      | "exmonaddr" -> exMonAddr
      | "exmonval" -> exMonVal
      | "vscr" -> vscr
      | "vrsave" -> vrsave
      | "v0a" -> v0a
      | "v0b" -> v0b
      | "v1a" -> v1a
      | "v1b" -> v1b
      | "v2a" -> v2a
      | "v2b" -> v2b
      | "v3a" -> v3a
      | "v3b" -> v3b
      | "v4a" -> v4a
      | "v4b" -> v4b
      | "v5a" -> v5a
      | "v5b" -> v5b
      | "v6a" -> v6a
      | "v6b" -> v6b
      | "v7a" -> v7a
      | "v7b" -> v7b
      | "v8a" -> v8a
      | "v8b" -> v8b
      | "v9a" -> v9a
      | "v9b" -> v9b
      | "v10a" -> v10a
      | "v10b" -> v10b
      | "v11a" -> v11a
      | "v11b" -> v11b
      | "v12a" -> v12a
      | "v12b" -> v12b
      | "v13a" -> v13a
      | "v13b" -> v13b
      | "v14a" -> v14a
      | "v14b" -> v14b
      | "v15a" -> v15a
      | "v15b" -> v15b
      | "v16a" -> v16a
      | "v16b" -> v16b
      | "v17a" -> v17a
      | "v17b" -> v17b
      | "v18a" -> v18a
      | "v18b" -> v18b
      | "v19a" -> v19a
      | "v19b" -> v19b
      | "v20a" -> v20a
      | "v20b" -> v20b
      | "v21a" -> v21a
      | "v21b" -> v21b
      | "v22a" -> v22a
      | "v22b" -> v22b
      | "v23a" -> v23a
      | "v23b" -> v23b
      | "v24a" -> v24a
      | "v24b" -> v24b
      | "v25a" -> v25a
      | "v25b" -> v25b
      | "v26a" -> v26a
      | "v26b" -> v26b
      | "v27a" -> v27a
      | "v27b" -> v27b
      | "v28a" -> v28a
      | "v28b" -> v28b
      | "v29a" -> v29a
      | "v29b" -> v29b
      | "v30a" -> v30a
      | "v30b" -> v30b
      | "v31a" -> v31a
      | "v31b" -> v31b
      | "vsrl0" -> vsrl0
      | "vsrl1" -> vsrl1
      | "vsrl2" -> vsrl2
      | "vsrl3" -> vsrl3
      | "vsrl4" -> vsrl4
      | "vsrl5" -> vsrl5
      | "vsrl6" -> vsrl6
      | "vsrl7" -> vsrl7
      | "vsrl8" -> vsrl8
      | "vsrl9" -> vsrl9
      | "vsrl10" -> vsrl10
      | "vsrl11" -> vsrl11
      | "vsrl12" -> vsrl12
      | "vsrl13" -> vsrl13
      | "vsrl14" -> vsrl14
      | "vsrl15" -> vsrl15
      | "vsrl16" -> vsrl16
      | "vsrl17" -> vsrl17
      | "vsrl18" -> vsrl18
      | "vsrl19" -> vsrl19
      | "vsrl20" -> vsrl20
      | "vsrl21" -> vsrl21
      | "vsrl22" -> vsrl22
      | "vsrl23" -> vsrl23
      | "vsrl24" -> vsrl24
      | "vsrl25" -> vsrl25
      | "vsrl26" -> vsrl26
      | "vsrl27" -> vsrl27
      | "vsrl28" -> vsrl28
      | "vsrl29" -> vsrl29
      | "vsrl30" -> vsrl30
      | "vsrl31" -> vsrl31
      | _ -> raise InvalidRegisterException

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

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
         r9
         r10
         r11
         r12
         r13
         r14
         r15
         r16
         r17
         r18
         r19
         r20
         r21
         r22
         r23
         r24
         r25
         r26
         r27
         r28
         r29
         r30
         r31
         f0
         f1
         f2
         f3
         f4
         f5
         f6
         f7
         f8
         f9
         f10
         f11
         f12
         f13
         f14
         f15
         f16
         f17
         f18
         f19
         f20
         f21
         f22
         f23
         f24
         f25
         f26
         f27
         f28
         f29
         f30
         f31
         cr00
         cr01
         cr02
         cr03
         cr10
         cr11
         cr12
         cr13
         cr20
         cr21
         cr22
         cr23
         cr30
         cr32
         cr32
         cr33
         cr40
         cr41
         cr42
         cr43
         cr50
         cr51
         cr52
         cr53
         cr60
         cr61
         cr62
         cr63
         cr70
         cr71
         cr72
         cr73
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
         vscr
         vrsave
         vsrl0
         vsrl1
         vsrl2
         vsrl3
         vsrl4
         vsrl5
         vsrl6
         vsrl7
         vsrl8
         vsrl9
         vsrl10
         vsrl11
         vsrl12
         vsrl13
         vsrl14
         vsrl15
         vsrl16
         vsrl17
         vsrl18
         vsrl19
         vsrl20
         vsrl21
         vsrl22
         vsrl23
         vsrl24
         vsrl25
         vsrl26
         vsrl27
         vsrl28
         vsrl29
         vsrl30
         vsrl31 |]

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
         r9
         r10
         r11
         r12
         r13
         r14
         r15
         r16
         r17
         r18
         r19
         r20
         r21
         r22
         r23
         r24
         r25
         r26
         r27
         r28
         r29
         r30
         r31 |]

    member _.GetRegisterID expr =
      match expr with
      | Var(_, id, _, _) -> id
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name = Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases rid = [| rid |]

    member _.GetRegisterName rid = Register.ofRegID rid |> Register.toString

    member this.GetAllRegisterNames() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegisterName)

    member _.GetRegType rid =
      if rid < 0x40<RegisterID.T> then WordSize.toRegType isa.WordSize
      else 4<rt>

    member this.IsProgramCounter regid =
      (this :> IRegisterFactory).ProgramCounter = regid

    member _.IsStackPointer rid = Register.toRegID R1 = rid

    member _.IsFramePointer _ = false
