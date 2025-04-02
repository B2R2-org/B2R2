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

  member __.GetRegVar (name) =
    match name with
    | Register.R0 -> __.R0
    | Register.R1 -> __.R1
    | Register.R2 -> __.R2
    | Register.R3 -> __.R3
    | Register.R4 -> __.R4
    | Register.R5 -> __.R5
    | Register.R6 -> __.R6
    | Register.R7 -> __.R7
    | Register.R8 -> __.R8
    | Register.R9 -> __.R9
    | Register.R10 -> __.R10
    | Register.R11 -> __.R11
    | Register.R12 -> __.R12
    | Register.R13 -> __.R13
    | Register.R14 -> __.R14
    | Register.R15 -> __.R15
    | Register.R16 -> __.R16
    | Register.R17 -> __.R17
    | Register.R18 -> __.R18
    | Register.R19 -> __.R19
    | Register.R20 -> __.R20
    | Register.R21 -> __.R21
    | Register.R22 -> __.R22
    | Register.R23 -> __.R23
    | Register.R24 -> __.R24
    | Register.R25 -> __.R25
    | Register.R26 -> __.R26
    | Register.R27 -> __.R27
    | Register.R28 -> __.R28
    | Register.R29 -> __.R29
    | Register.R30 -> __.R30
    | Register.R31 -> __.R31
    | Register.F0 -> __.F0
    | Register.F1 -> __.F1
    | Register.F2 -> __.F2
    | Register.F3 -> __.F3
    | Register.F4 -> __.F4
    | Register.F5 -> __.F5
    | Register.F6 -> __.F6
    | Register.F7 -> __.F7
    | Register.F8 -> __.F8
    | Register.F9 -> __.F9
    | Register.F10 -> __.F10
    | Register.F11 -> __.F11
    | Register.F12 -> __.F12
    | Register.F13 -> __.F13
    | Register.F14 -> __.F14
    | Register.F15 -> __.F15
    | Register.F16 -> __.F16
    | Register.F17 -> __.F17
    | Register.F18 -> __.F18
    | Register.F19 -> __.F19
    | Register.F20 -> __.F20
    | Register.F21 -> __.F21
    | Register.F22 -> __.F22
    | Register.F23 -> __.F23
    | Register.F24 -> __.F24
    | Register.F25 -> __.F25
    | Register.F26 -> __.F26
    | Register.F27 -> __.F27
    | Register.F28 -> __.F28
    | Register.F29 -> __.F29
    | Register.F30 -> __.F30
    | Register.F31 -> __.F31
    | Register.CR0_0 -> __.CR0_0
    | Register.CR0_1 -> __.CR0_1
    | Register.CR0_2 -> __.CR0_2
    | Register.CR0_3 -> __.CR0_3
    | Register.CR1_0 -> __.CR1_0
    | Register.CR1_1 -> __.CR1_1
    | Register.CR1_2 -> __.CR1_2
    | Register.CR1_3 -> __.CR1_3
    | Register.CR2_0 -> __.CR2_0
    | Register.CR2_1 -> __.CR2_1
    | Register.CR2_2 -> __.CR2_2
    | Register.CR2_3 -> __.CR2_3
    | Register.CR3_0 -> __.CR3_0
    | Register.CR3_1 -> __.CR3_1
    | Register.CR3_2 -> __.CR3_2
    | Register.CR3_3 -> __.CR3_3
    | Register.CR4_0 -> __.CR4_0
    | Register.CR4_1 -> __.CR4_1
    | Register.CR4_2 -> __.CR4_2
    | Register.CR4_3 -> __.CR4_3
    | Register.CR5_0 -> __.CR5_0
    | Register.CR5_1 -> __.CR5_1
    | Register.CR5_2 -> __.CR5_2
    | Register.CR5_3 -> __.CR5_3
    | Register.CR6_0 -> __.CR6_0
    | Register.CR6_1 -> __.CR6_1
    | Register.CR6_2 -> __.CR6_2
    | Register.CR6_3 -> __.CR6_3
    | Register.CR7_0 -> __.CR7_0
    | Register.CR7_1 -> __.CR7_1
    | Register.CR7_2 -> __.CR7_2
    | Register.CR7_3 -> __.CR7_3
    | Register.FPSCR -> __.FPSCR
    | Register.XER -> __.XER
    | Register.LR -> __.LR
    | Register.CTR -> __.CTR
    | Register.PVR -> __.PVR
    | Register.RES -> __.RES
    | _ -> raise UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
