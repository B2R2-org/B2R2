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

namespace B2R2.FrontEnd.BinLifter.PPC32

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.Register
open B2R2.BinIR.LowUIR

type RegExprs (wordSize) =
  let var sz t name = AST.var sz t name

  (* Registers *)
  let regType = WordSize.toRegType wordSize

  member val R0 = var regType (PPC32Register.ID PPC32.R0) "R0" with get
  member val R1 = var regType (PPC32Register.ID PPC32.R1) "R1" with get
  member val R2 = var regType (PPC32Register.ID PPC32.R2) "R2" with get
  member val R3 = var regType (PPC32Register.ID PPC32.R3) "R3" with get
  member val R4 = var regType (PPC32Register.ID PPC32.R4) "R4" with get
  member val R5 = var regType (PPC32Register.ID PPC32.R5) "R5" with get
  member val R6 = var regType (PPC32Register.ID PPC32.R6) "R6" with get
  member val R7 = var regType (PPC32Register.ID PPC32.R7) "R7" with get
  member val R8 = var regType (PPC32Register.ID PPC32.R8) "R8" with get
  member val R9 = var regType (PPC32Register.ID PPC32.R9) "R9" with get
  member val R10 = var regType (PPC32Register.ID PPC32.R10) "R10" with get
  member val R11 = var regType (PPC32Register.ID PPC32.R11) "R11" with get
  member val R12 = var regType (PPC32Register.ID PPC32.R12) "R12" with get
  member val R13 = var regType (PPC32Register.ID PPC32.R13) "R13" with get
  member val R14 = var regType (PPC32Register.ID PPC32.R14) "R14" with get
  member val R15 = var regType (PPC32Register.ID PPC32.R15) "R15" with get
  member val R16 = var regType (PPC32Register.ID PPC32.R16) "R16" with get
  member val R17 = var regType (PPC32Register.ID PPC32.R17) "R17" with get
  member val R18 = var regType (PPC32Register.ID PPC32.R18) "R18" with get
  member val R19 = var regType (PPC32Register.ID PPC32.R19) "R19" with get
  member val R20 = var regType (PPC32Register.ID PPC32.R20) "R20" with get
  member val R21 = var regType (PPC32Register.ID PPC32.R21) "R21" with get
  member val R22 = var regType (PPC32Register.ID PPC32.R22) "R22" with get
  member val R23 = var regType (PPC32Register.ID PPC32.R23) "R23" with get
  member val R24 = var regType (PPC32Register.ID PPC32.R24) "R24" with get
  member val R25 = var regType (PPC32Register.ID PPC32.R25) "R25" with get
  member val R26 = var regType (PPC32Register.ID PPC32.R26) "R26" with get
  member val R27 = var regType (PPC32Register.ID PPC32.R27) "R27" with get
  member val R28 = var regType (PPC32Register.ID PPC32.R28) "R28" with get
  member val R29 = var regType (PPC32Register.ID PPC32.R29) "R29" with get
  member val R30 = var regType (PPC32Register.ID PPC32.R30) "R30" with get
  member val R31 = var regType (PPC32Register.ID PPC32.R31) "R31" with get
  member val F0 =  var 64<rt> (PPC32Register.ID PPC32.F0) "F0" with get
  member val F1 =  var 64<rt> (PPC32Register.ID PPC32.F1) "F1" with get
  member val F2 =  var 64<rt> (PPC32Register.ID PPC32.F2) "F2" with get
  member val F3 =  var 64<rt> (PPC32Register.ID PPC32.F3) "F3" with get
  member val F4 =  var 64<rt> (PPC32Register.ID PPC32.F4) "F4" with get
  member val F5 =  var 64<rt> (PPC32Register.ID PPC32.F5) "F5" with get
  member val F6 =  var 64<rt> (PPC32Register.ID PPC32.F6) "F6" with get
  member val F7 =  var 64<rt> (PPC32Register.ID PPC32.F7) "F7" with get
  member val F8 =  var 64<rt> (PPC32Register.ID PPC32.F8) "F8" with get
  member val F9 =  var 64<rt> (PPC32Register.ID PPC32.F9) "F9" with get
  member val F10 =  var 64<rt> (PPC32Register.ID PPC32.F10) "F10" with get
  member val F11 =  var 64<rt> (PPC32Register.ID PPC32.F11) "F11" with get
  member val F12 =  var 64<rt> (PPC32Register.ID PPC32.F12) "F12" with get
  member val F13 =  var 64<rt> (PPC32Register.ID PPC32.F13) "F13" with get
  member val F14 =  var 64<rt> (PPC32Register.ID PPC32.F14) "F14" with get
  member val F15 =  var 64<rt> (PPC32Register.ID PPC32.F15) "F15" with get
  member val F16 =  var 64<rt> (PPC32Register.ID PPC32.F16) "F16" with get
  member val F17 =  var 64<rt> (PPC32Register.ID PPC32.F17) "F17" with get
  member val F18 =  var 64<rt> (PPC32Register.ID PPC32.F18) "F18" with get
  member val F19 =  var 64<rt> (PPC32Register.ID PPC32.F19) "F19" with get
  member val F20 =  var 64<rt> (PPC32Register.ID PPC32.F20) "F20" with get
  member val F21 =  var 64<rt> (PPC32Register.ID PPC32.F21) "F21" with get
  member val F22 =  var 64<rt> (PPC32Register.ID PPC32.F22) "F22" with get
  member val F23 =  var 64<rt> (PPC32Register.ID PPC32.F23) "F23" with get
  member val F24 =  var 64<rt> (PPC32Register.ID PPC32.F24) "F24" with get
  member val F25 =  var 64<rt> (PPC32Register.ID PPC32.F25) "F25" with get
  member val F26 =  var 64<rt> (PPC32Register.ID PPC32.F26) "F26" with get
  member val F27 =  var 64<rt> (PPC32Register.ID PPC32.F27) "F27" with get
  member val F28 =  var 64<rt> (PPC32Register.ID PPC32.F28) "F28" with get
  member val F29 =  var 64<rt> (PPC32Register.ID PPC32.F29) "F29" with get
  member val F30 =  var 64<rt> (PPC32Register.ID PPC32.F30) "F30" with get
  member val F31 =  var 64<rt> (PPC32Register.ID PPC32.F31) "F31" with get
  member val CR0_0 =
    var 1<rt> (PPC32Register.ID PPC32.CR0_0) "CR0_0" with get
  member val CR0_1 =
    var 1<rt> (PPC32Register.ID PPC32.CR0_1) "CR0_1" with get
  member val CR0_2 =
    var 1<rt> (PPC32Register.ID PPC32.CR0_2) "CR0_2" with get
  member val CR0_3 =
    var 1<rt> (PPC32Register.ID PPC32.CR0_3) "CR0_3" with get
  member val CR1_0 =
    var 1<rt> (PPC32Register.ID PPC32.CR1_0) "CR1_0" with get
  member val CR1_1 =
    var 1<rt> (PPC32Register.ID PPC32.CR1_1) "CR1_1" with get
  member val CR1_2 =
    var 1<rt> (PPC32Register.ID PPC32.CR1_2) "CR1_2" with get
  member val CR1_3 =
    var 1<rt> (PPC32Register.ID PPC32.CR1_3) "CR1_3" with get
  member val CR2_0 =
    var 1<rt> (PPC32Register.ID PPC32.CR2_0) "CR2_0" with get
  member val CR2_1 =
    var 1<rt> (PPC32Register.ID PPC32.CR2_1) "CR2_1" with get
  member val CR2_2 =
    var 1<rt> (PPC32Register.ID PPC32.CR2_2) "CR2_2" with get
  member val CR2_3 =
    var 1<rt> (PPC32Register.ID PPC32.CR2_3) "CR2_3" with get
  member val CR3_0 =
    var 1<rt> (PPC32Register.ID PPC32.CR3_0) "CR3_0" with get
  member val CR3_1 =
    var 1<rt> (PPC32Register.ID PPC32.CR3_1) "CR3_1" with get
  member val CR3_2 =
    var 1<rt> (PPC32Register.ID PPC32.CR3_2) "CR3_2" with get
  member val CR3_3 =
    var 1<rt> (PPC32Register.ID PPC32.CR3_3) "CR3_3" with get
  member val CR4_0 =
    var 1<rt> (PPC32Register.ID PPC32.CR4_0) "CR4_0" with get
  member val CR4_1 =
    var 1<rt> (PPC32Register.ID PPC32.CR4_1) "CR4_1" with get
  member val CR4_2 =
    var 1<rt> (PPC32Register.ID PPC32.CR4_2) "CR4_2" with get
  member val CR4_3 =
    var 1<rt> (PPC32Register.ID PPC32.CR4_3) "CR4_3" with get
  member val CR5_0 =
    var 1<rt> (PPC32Register.ID PPC32.CR5_0) "CR5_0" with get
  member val CR5_1 =
    var 1<rt> (PPC32Register.ID PPC32.CR5_1) "CR5_1" with get
  member val CR5_2 =
    var 1<rt> (PPC32Register.ID PPC32.CR5_2) "CR5_2" with get
  member val CR5_3 =
    var 1<rt> (PPC32Register.ID PPC32.CR5_3) "CR5_3" with get
  member val CR6_0 =
    var 1<rt> (PPC32Register.ID PPC32.CR6_0) "CR6_0" with get
  member val CR6_1 =
    var 1<rt> (PPC32Register.ID PPC32.CR6_1) "CR6_1" with get
  member val CR6_2 =
    var 1<rt> (PPC32Register.ID PPC32.CR6_2) "CR6_2" with get
  member val CR6_3 =
    var 1<rt> (PPC32Register.ID PPC32.CR6_3) "CR6_3" with get
  member val CR7_0 =
    var 1<rt> (PPC32Register.ID PPC32.CR7_0) "CR7_0" with get
  member val CR7_1 =
    var 1<rt> (PPC32Register.ID PPC32.CR7_1) "CR7_1" with get
  member val CR7_2 =
    var 1<rt> (PPC32Register.ID PPC32.CR7_2) "CR7_2" with get
  member val CR7_3 =
    var 1<rt> (PPC32Register.ID PPC32.CR7_3) "CR7_3" with get
  member val FPSCR =
    var 32<rt> (PPC32Register.ID PPC32.FPSCR) "FPSCR" with get
  member val XER = var 32<rt> (PPC32Register.ID PPC32.XER) "XER" with get
  member val LR = var regType (PPC32Register.ID PPC32.LR) "LR" with get
  member val CTR = var regType (PPC32Register.ID PPC32.CTR) "CTR" with get
  member val PVR = var 32<rt> (PPC32Register.ID PPC32.PVR) "PVR" with get
  member val RES = var 1<rt> (PPC32Register.ID PPC32.RES) "RES" with get

  member __.GetRegVar (name) =
    match name with
    | PPC32.R0 -> __.R0
    | PPC32.R1 -> __.R1
    | PPC32.R2 -> __.R2
    | PPC32.R3 -> __.R3
    | PPC32.R4 -> __.R4
    | PPC32.R5 -> __.R5
    | PPC32.R6 -> __.R6
    | PPC32.R7 -> __.R7
    | PPC32.R8 -> __.R8
    | PPC32.R9 -> __.R9
    | PPC32.R10 -> __.R10
    | PPC32.R11 -> __.R11
    | PPC32.R12 -> __.R12
    | PPC32.R13 -> __.R13
    | PPC32.R14 -> __.R14
    | PPC32.R15 -> __.R15
    | PPC32.R16 -> __.R16
    | PPC32.R17 -> __.R17
    | PPC32.R18 -> __.R18
    | PPC32.R19 -> __.R19
    | PPC32.R20 -> __.R20
    | PPC32.R21 -> __.R21
    | PPC32.R22 -> __.R22
    | PPC32.R23 -> __.R23
    | PPC32.R24 -> __.R24
    | PPC32.R25 -> __.R25
    | PPC32.R26 -> __.R26
    | PPC32.R27 -> __.R27
    | PPC32.R28 -> __.R28
    | PPC32.R29 -> __.R29
    | PPC32.R30 -> __.R30
    | PPC32.R31 -> __.R31
    | PPC32.F0 -> __.F0
    | PPC32.F1 -> __.F1
    | PPC32.F2 -> __.F2
    | PPC32.F3 -> __.F3
    | PPC32.F4 -> __.F4
    | PPC32.F5 -> __.F5
    | PPC32.F6 -> __.F6
    | PPC32.F7 -> __.F7
    | PPC32.F8 -> __.F8
    | PPC32.F9 -> __.F9
    | PPC32.F10 -> __.F10
    | PPC32.F11 -> __.F11
    | PPC32.F12 -> __.F12
    | PPC32.F13 -> __.F13
    | PPC32.F14 -> __.F14
    | PPC32.F15 -> __.F15
    | PPC32.F16 -> __.F16
    | PPC32.F17 -> __.F17
    | PPC32.F18 -> __.F18
    | PPC32.F19 -> __.F19
    | PPC32.F20 -> __.F20
    | PPC32.F21 -> __.F21
    | PPC32.F22 -> __.F22
    | PPC32.F23 -> __.F23
    | PPC32.F24 -> __.F24
    | PPC32.F25 -> __.F25
    | PPC32.F26 -> __.F26
    | PPC32.F27 -> __.F27
    | PPC32.F28 -> __.F28
    | PPC32.F29 -> __.F29
    | PPC32.F30 -> __.F30
    | PPC32.F31 -> __.F31
    | PPC32.CR0_0 -> __.CR0_0
    | PPC32.CR0_1 -> __.CR0_1
    | PPC32.CR0_2 -> __.CR0_2
    | PPC32.CR0_3 -> __.CR0_3
    | PPC32.CR1_0 -> __.CR1_0
    | PPC32.CR1_1 -> __.CR1_1
    | PPC32.CR1_2 -> __.CR1_2
    | PPC32.CR1_3 -> __.CR1_3
    | PPC32.CR2_0 -> __.CR2_0
    | PPC32.CR2_1 -> __.CR2_1
    | PPC32.CR2_2 -> __.CR2_2
    | PPC32.CR2_3 -> __.CR2_3
    | PPC32.CR3_0 -> __.CR3_0
    | PPC32.CR3_1 -> __.CR3_1
    | PPC32.CR3_2 -> __.CR3_2
    | PPC32.CR3_3 -> __.CR3_3
    | PPC32.CR4_0 -> __.CR4_0
    | PPC32.CR4_1 -> __.CR4_1
    | PPC32.CR4_2 -> __.CR4_2
    | PPC32.CR4_3 -> __.CR4_3
    | PPC32.CR5_0 -> __.CR5_0
    | PPC32.CR5_1 -> __.CR5_1
    | PPC32.CR5_2 -> __.CR5_2
    | PPC32.CR5_3 -> __.CR5_3
    | PPC32.CR6_0 -> __.CR6_0
    | PPC32.CR6_1 -> __.CR6_1
    | PPC32.CR6_2 -> __.CR6_2
    | PPC32.CR6_3 -> __.CR6_3
    | PPC32.CR7_0 -> __.CR7_0
    | PPC32.CR7_1 -> __.CR7_1
    | PPC32.CR7_2 -> __.CR7_2
    | PPC32.CR7_3 -> __.CR7_3
    | PPC32.FPSCR -> __.FPSCR
    | PPC32.XER -> __.XER
    | PPC32.LR -> __.LR
    | PPC32.CTR -> __.CTR
    | PPC32.PVR -> __.PVR
    | PPC32.RES -> __.RES
    | _ -> raise UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
