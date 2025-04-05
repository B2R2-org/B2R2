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

namespace B2R2.FrontEnd.PPC32

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR
open type Register

type RegExprs (wordSize) =
  let var sz t name = AST.var sz t name

  (* Registers *)
  let regType = WordSize.toRegType wordSize

  member val R0 = var regType (Register.toRegID R0) "R0" with get
  member val R1 = var regType (Register.toRegID R1) "R1" with get
  member val R2 = var regType (Register.toRegID R2) "R2" with get
  member val R3 = var regType (Register.toRegID R3) "R3" with get
  member val R4 = var regType (Register.toRegID R4) "R4" with get
  member val R5 = var regType (Register.toRegID R5) "R5" with get
  member val R6 = var regType (Register.toRegID R6) "R6" with get
  member val R7 = var regType (Register.toRegID R7) "R7" with get
  member val R8 = var regType (Register.toRegID R8) "R8" with get
  member val R9 = var regType (Register.toRegID R9) "R9" with get
  member val R10 = var regType (Register.toRegID R10) "R10" with get
  member val R11 = var regType (Register.toRegID R11) "R11" with get
  member val R12 = var regType (Register.toRegID R12) "R12" with get
  member val R13 = var regType (Register.toRegID R13) "R13" with get
  member val R14 = var regType (Register.toRegID R14) "R14" with get
  member val R15 = var regType (Register.toRegID R15) "R15" with get
  member val R16 = var regType (Register.toRegID R16) "R16" with get
  member val R17 = var regType (Register.toRegID R17) "R17" with get
  member val R18 = var regType (Register.toRegID R18) "R18" with get
  member val R19 = var regType (Register.toRegID R19) "R19" with get
  member val R20 = var regType (Register.toRegID R20) "R20" with get
  member val R21 = var regType (Register.toRegID R21) "R21" with get
  member val R22 = var regType (Register.toRegID R22) "R22" with get
  member val R23 = var regType (Register.toRegID R23) "R23" with get
  member val R24 = var regType (Register.toRegID R24) "R24" with get
  member val R25 = var regType (Register.toRegID R25) "R25" with get
  member val R26 = var regType (Register.toRegID R26) "R26" with get
  member val R27 = var regType (Register.toRegID R27) "R27" with get
  member val R28 = var regType (Register.toRegID R28) "R28" with get
  member val R29 = var regType (Register.toRegID R29) "R29" with get
  member val R30 = var regType (Register.toRegID R30) "R30" with get
  member val R31 = var regType (Register.toRegID R31) "R31" with get
  member val F0 =  var 64<rt> (Register.toRegID F0) "F0" with get
  member val F1 =  var 64<rt> (Register.toRegID F1) "F1" with get
  member val F2 =  var 64<rt> (Register.toRegID F2) "F2" with get
  member val F3 =  var 64<rt> (Register.toRegID F3) "F3" with get
  member val F4 =  var 64<rt> (Register.toRegID F4) "F4" with get
  member val F5 =  var 64<rt> (Register.toRegID F5) "F5" with get
  member val F6 =  var 64<rt> (Register.toRegID F6) "F6" with get
  member val F7 =  var 64<rt> (Register.toRegID F7) "F7" with get
  member val F8 =  var 64<rt> (Register.toRegID F8) "F8" with get
  member val F9 =  var 64<rt> (Register.toRegID F9) "F9" with get
  member val F10 =  var 64<rt> (Register.toRegID F10) "F10" with get
  member val F11 =  var 64<rt> (Register.toRegID F11) "F11" with get
  member val F12 =  var 64<rt> (Register.toRegID F12) "F12" with get
  member val F13 =  var 64<rt> (Register.toRegID F13) "F13" with get
  member val F14 =  var 64<rt> (Register.toRegID F14) "F14" with get
  member val F15 =  var 64<rt> (Register.toRegID F15) "F15" with get
  member val F16 =  var 64<rt> (Register.toRegID F16) "F16" with get
  member val F17 =  var 64<rt> (Register.toRegID F17) "F17" with get
  member val F18 =  var 64<rt> (Register.toRegID F18) "F18" with get
  member val F19 =  var 64<rt> (Register.toRegID F19) "F19" with get
  member val F20 =  var 64<rt> (Register.toRegID F20) "F20" with get
  member val F21 =  var 64<rt> (Register.toRegID F21) "F21" with get
  member val F22 =  var 64<rt> (Register.toRegID F22) "F22" with get
  member val F23 =  var 64<rt> (Register.toRegID F23) "F23" with get
  member val F24 =  var 64<rt> (Register.toRegID F24) "F24" with get
  member val F25 =  var 64<rt> (Register.toRegID F25) "F25" with get
  member val F26 =  var 64<rt> (Register.toRegID F26) "F26" with get
  member val F27 =  var 64<rt> (Register.toRegID F27) "F27" with get
  member val F28 =  var 64<rt> (Register.toRegID F28) "F28" with get
  member val F29 =  var 64<rt> (Register.toRegID F29) "F29" with get
  member val F30 =  var 64<rt> (Register.toRegID F30) "F30" with get
  member val F31 =  var 64<rt> (Register.toRegID F31) "F31" with get
  member val CR0_0 =
    var 1<rt> (Register.toRegID CR0_0) "CR0_0" with get
  member val CR0_1 =
    var 1<rt> (Register.toRegID CR0_1) "CR0_1" with get
  member val CR0_2 =
    var 1<rt> (Register.toRegID CR0_2) "CR0_2" with get
  member val CR0_3 =
    var 1<rt> (Register.toRegID CR0_3) "CR0_3" with get
  member val CR1_0 =
    var 1<rt> (Register.toRegID CR1_0) "CR1_0" with get
  member val CR1_1 =
    var 1<rt> (Register.toRegID CR1_1) "CR1_1" with get
  member val CR1_2 =
    var 1<rt> (Register.toRegID CR1_2) "CR1_2" with get
  member val CR1_3 =
    var 1<rt> (Register.toRegID CR1_3) "CR1_3" with get
  member val CR2_0 =
    var 1<rt> (Register.toRegID CR2_0) "CR2_0" with get
  member val CR2_1 =
    var 1<rt> (Register.toRegID CR2_1) "CR2_1" with get
  member val CR2_2 =
    var 1<rt> (Register.toRegID CR2_2) "CR2_2" with get
  member val CR2_3 =
    var 1<rt> (Register.toRegID CR2_3) "CR2_3" with get
  member val CR3_0 =
    var 1<rt> (Register.toRegID CR3_0) "CR3_0" with get
  member val CR3_1 =
    var 1<rt> (Register.toRegID CR3_1) "CR3_1" with get
  member val CR3_2 =
    var 1<rt> (Register.toRegID CR3_2) "CR3_2" with get
  member val CR3_3 =
    var 1<rt> (Register.toRegID CR3_3) "CR3_3" with get
  member val CR4_0 =
    var 1<rt> (Register.toRegID CR4_0) "CR4_0" with get
  member val CR4_1 =
    var 1<rt> (Register.toRegID CR4_1) "CR4_1" with get
  member val CR4_2 =
    var 1<rt> (Register.toRegID CR4_2) "CR4_2" with get
  member val CR4_3 =
    var 1<rt> (Register.toRegID CR4_3) "CR4_3" with get
  member val CR5_0 =
    var 1<rt> (Register.toRegID CR5_0) "CR5_0" with get
  member val CR5_1 =
    var 1<rt> (Register.toRegID CR5_1) "CR5_1" with get
  member val CR5_2 =
    var 1<rt> (Register.toRegID CR5_2) "CR5_2" with get
  member val CR5_3 =
    var 1<rt> (Register.toRegID CR5_3) "CR5_3" with get
  member val CR6_0 =
    var 1<rt> (Register.toRegID CR6_0) "CR6_0" with get
  member val CR6_1 =
    var 1<rt> (Register.toRegID CR6_1) "CR6_1" with get
  member val CR6_2 =
    var 1<rt> (Register.toRegID CR6_2) "CR6_2" with get
  member val CR6_3 =
    var 1<rt> (Register.toRegID CR6_3) "CR6_3" with get
  member val CR7_0 =
    var 1<rt> (Register.toRegID CR7_0) "CR7_0" with get
  member val CR7_1 =
    var 1<rt> (Register.toRegID CR7_1) "CR7_1" with get
  member val CR7_2 =
    var 1<rt> (Register.toRegID CR7_2) "CR7_2" with get
  member val CR7_3 =
    var 1<rt> (Register.toRegID CR7_3) "CR7_3" with get
  member val FPSCR =
    var 32<rt> (Register.toRegID FPSCR) "FPSCR" with get
  member val XER = var 32<rt> (Register.toRegID XER) "XER" with get
  member val LR = var regType (Register.toRegID LR) "LR" with get
  member val CTR = var regType (Register.toRegID CTR) "CTR" with get
  member val PVR = var 32<rt> (Register.toRegID PVR) "PVR" with get
  member val RES = var 1<rt> (Register.toRegID RES) "RES" with get

  member this.GetRegVar (name) =
    match name with
    | Register.R0 -> this.R0
    | Register.R1 -> this.R1
    | Register.R2 -> this.R2
    | Register.R3 -> this.R3
    | Register.R4 -> this.R4
    | Register.R5 -> this.R5
    | Register.R6 -> this.R6
    | Register.R7 -> this.R7
    | Register.R8 -> this.R8
    | Register.R9 -> this.R9
    | Register.R10 -> this.R10
    | Register.R11 -> this.R11
    | Register.R12 -> this.R12
    | Register.R13 -> this.R13
    | Register.R14 -> this.R14
    | Register.R15 -> this.R15
    | Register.R16 -> this.R16
    | Register.R17 -> this.R17
    | Register.R18 -> this.R18
    | Register.R19 -> this.R19
    | Register.R20 -> this.R20
    | Register.R21 -> this.R21
    | Register.R22 -> this.R22
    | Register.R23 -> this.R23
    | Register.R24 -> this.R24
    | Register.R25 -> this.R25
    | Register.R26 -> this.R26
    | Register.R27 -> this.R27
    | Register.R28 -> this.R28
    | Register.R29 -> this.R29
    | Register.R30 -> this.R30
    | Register.R31 -> this.R31
    | Register.F0 -> this.F0
    | Register.F1 -> this.F1
    | Register.F2 -> this.F2
    | Register.F3 -> this.F3
    | Register.F4 -> this.F4
    | Register.F5 -> this.F5
    | Register.F6 -> this.F6
    | Register.F7 -> this.F7
    | Register.F8 -> this.F8
    | Register.F9 -> this.F9
    | Register.F10 -> this.F10
    | Register.F11 -> this.F11
    | Register.F12 -> this.F12
    | Register.F13 -> this.F13
    | Register.F14 -> this.F14
    | Register.F15 -> this.F15
    | Register.F16 -> this.F16
    | Register.F17 -> this.F17
    | Register.F18 -> this.F18
    | Register.F19 -> this.F19
    | Register.F20 -> this.F20
    | Register.F21 -> this.F21
    | Register.F22 -> this.F22
    | Register.F23 -> this.F23
    | Register.F24 -> this.F24
    | Register.F25 -> this.F25
    | Register.F26 -> this.F26
    | Register.F27 -> this.F27
    | Register.F28 -> this.F28
    | Register.F29 -> this.F29
    | Register.F30 -> this.F30
    | Register.F31 -> this.F31
    | Register.CR0_0 -> this.CR0_0
    | Register.CR0_1 -> this.CR0_1
    | Register.CR0_2 -> this.CR0_2
    | Register.CR0_3 -> this.CR0_3
    | Register.CR1_0 -> this.CR1_0
    | Register.CR1_1 -> this.CR1_1
    | Register.CR1_2 -> this.CR1_2
    | Register.CR1_3 -> this.CR1_3
    | Register.CR2_0 -> this.CR2_0
    | Register.CR2_1 -> this.CR2_1
    | Register.CR2_2 -> this.CR2_2
    | Register.CR2_3 -> this.CR2_3
    | Register.CR3_0 -> this.CR3_0
    | Register.CR3_1 -> this.CR3_1
    | Register.CR3_2 -> this.CR3_2
    | Register.CR3_3 -> this.CR3_3
    | Register.CR4_0 -> this.CR4_0
    | Register.CR4_1 -> this.CR4_1
    | Register.CR4_2 -> this.CR4_2
    | Register.CR4_3 -> this.CR4_3
    | Register.CR5_0 -> this.CR5_0
    | Register.CR5_1 -> this.CR5_1
    | Register.CR5_2 -> this.CR5_2
    | Register.CR5_3 -> this.CR5_3
    | Register.CR6_0 -> this.CR6_0
    | Register.CR6_1 -> this.CR6_1
    | Register.CR6_2 -> this.CR6_2
    | Register.CR6_3 -> this.CR6_3
    | Register.CR7_0 -> this.CR7_0
    | Register.CR7_1 -> this.CR7_1
    | Register.CR7_2 -> this.CR7_2
    | Register.CR7_3 -> this.CR7_3
    | Register.FPSCR -> this.FPSCR
    | Register.XER -> this.XER
    | Register.LR -> this.LR
    | Register.CTR -> this.CTR
    | Register.PVR -> this.PVR
    | Register.RES -> this.RES
    | _ -> raise UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
