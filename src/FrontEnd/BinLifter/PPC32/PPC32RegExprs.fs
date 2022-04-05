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
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type internal RegExprs (wordSize) =
  let var sz t name = AST.var sz t name (PPC32RegisterSet.singleton t)

  (* Registers *)
  let regType = WordSize.toRegType wordSize

  member val R0 = var regType (Register.toRegID Register.GPR0) "R0" with get
  member val R1 = var regType (Register.toRegID Register.GPR1) "R1" with get
  member val R2 = var regType (Register.toRegID Register.GPR2) "R2" with get
  member val R3 = var regType (Register.toRegID Register.GPR3) "R3" with get
  member val R4 = var regType (Register.toRegID Register.GPR4) "R4" with get
  member val R5 = var regType (Register.toRegID Register.GPR5) "R5" with get
  member val R6 = var regType (Register.toRegID Register.GPR6) "R6" with get
  member val R7 = var regType (Register.toRegID Register.GPR7) "R7" with get
  member val R8 = var regType (Register.toRegID Register.GPR8) "R8" with get
  member val R9 = var regType (Register.toRegID Register.GPR9) "R9" with get
  member val R10 = var regType (Register.toRegID Register.GPR10) "R10" with get
  member val R11 = var regType (Register.toRegID Register.GPR11) "R11" with get
  member val R12 = var regType (Register.toRegID Register.GPR12) "R12" with get
  member val R13 = var regType (Register.toRegID Register.GPR13) "R13" with get
  member val R14 = var regType (Register.toRegID Register.GPR14) "R14" with get
  member val R15 = var regType (Register.toRegID Register.GPR15) "R15" with get
  member val R16 = var regType (Register.toRegID Register.GPR16) "R16" with get
  member val R17 = var regType (Register.toRegID Register.GPR17) "R17" with get
  member val R18 = var regType (Register.toRegID Register.GPR18) "R18" with get
  member val R19 = var regType (Register.toRegID Register.GPR19) "R19" with get
  member val R20 = var regType (Register.toRegID Register.GPR20) "R20" with get
  member val R21 = var regType (Register.toRegID Register.GPR21) "R21" with get
  member val R22 = var regType (Register.toRegID Register.GPR22) "R22" with get
  member val R23 = var regType (Register.toRegID Register.GPR23) "R23" with get
  member val R24 = var regType (Register.toRegID Register.GPR24) "R24" with get
  member val R25 = var regType (Register.toRegID Register.GPR25) "R25" with get
  member val R26 = var regType (Register.toRegID Register.GPR26) "R26" with get
  member val R27 = var regType (Register.toRegID Register.GPR27) "R27" with get
  member val R28 = var regType (Register.toRegID Register.GPR28) "R28" with get
  member val R29 = var regType (Register.toRegID Register.GPR29) "R29" with get
  member val R30 = var regType (Register.toRegID Register.GPR30) "R30" with get
  member val R31 = var regType (Register.toRegID Register.GPR31) "R31" with get
  member val F0 =  var 64<rt> (Register.toRegID Register.FPR0) "F0" with get
  member val F1 =  var 64<rt> (Register.toRegID Register.FPR1) "F1" with get
  member val F2 =  var 64<rt> (Register.toRegID Register.FPR2) "F2" with get
  member val F3 =  var 64<rt> (Register.toRegID Register.FPR3) "F3" with get
  member val F4 =  var 64<rt> (Register.toRegID Register.FPR4) "F4" with get
  member val F5 =  var 64<rt> (Register.toRegID Register.FPR5) "F5" with get
  member val F6 =  var 64<rt> (Register.toRegID Register.FPR6) "F6" with get
  member val F7 =  var 64<rt> (Register.toRegID Register.FPR7) "F7" with get
  member val F8 =  var 64<rt> (Register.toRegID Register.FPR8) "F8" with get
  member val F9 =  var 64<rt> (Register.toRegID Register.FPR9) "F9" with get
  member val F10 =  var 64<rt> (Register.toRegID Register.FPR10) "F10" with get
  member val F11 =  var 64<rt> (Register.toRegID Register.FPR11) "F11" with get
  member val F12 =  var 64<rt> (Register.toRegID Register.FPR12) "F12" with get
  member val F13 =  var 64<rt> (Register.toRegID Register.FPR13) "F13" with get
  member val F14 =  var 64<rt> (Register.toRegID Register.FPR14) "F14" with get
  member val F15 =  var 64<rt> (Register.toRegID Register.FPR15) "F15" with get
  member val F16 =  var 64<rt> (Register.toRegID Register.FPR16) "F16" with get
  member val F17 =  var 64<rt> (Register.toRegID Register.FPR17) "F17" with get
  member val F18 =  var 64<rt> (Register.toRegID Register.FPR18) "F18" with get
  member val F19 =  var 64<rt> (Register.toRegID Register.FPR19) "F19" with get
  member val F20 =  var 64<rt> (Register.toRegID Register.FPR20) "F20" with get
  member val F21 =  var 64<rt> (Register.toRegID Register.FPR21) "F21" with get
  member val F22 =  var 64<rt> (Register.toRegID Register.FPR22) "F22" with get
  member val F23 =  var 64<rt> (Register.toRegID Register.FPR23) "F23" with get
  member val F24 =  var 64<rt> (Register.toRegID Register.FPR24) "F24" with get
  member val F25 =  var 64<rt> (Register.toRegID Register.FPR25) "F25" with get
  member val F26 =  var 64<rt> (Register.toRegID Register.FPR26) "F26" with get
  member val F27 =  var 64<rt> (Register.toRegID Register.FPR27) "F27" with get
  member val F28 =  var 64<rt> (Register.toRegID Register.FPR28) "F28" with get
  member val F29 =  var 64<rt> (Register.toRegID Register.FPR29) "F29" with get
  member val F30 =  var 64<rt> (Register.toRegID Register.FPR30) "F30" with get
  member val F31 =  var 64<rt> (Register.toRegID Register.FPR31) "F31" with get
  member val CR0 = var 4<rt> (Register.toRegID Register.CR0) "CR0" with get
  member val CR1 = var 4<rt> (Register.toRegID Register.CR1) "CR1" with get
  member val CR2 = var 4<rt> (Register.toRegID Register.CR2) "CR2" with get
  member val CR3 = var 4<rt> (Register.toRegID Register.CR3) "CR3" with get
  member val CR4 = var 4<rt> (Register.toRegID Register.CR4) "CR4" with get
  member val CR5 = var 4<rt> (Register.toRegID Register.CR5) "CR5" with get
  member val CR6 = var 4<rt> (Register.toRegID Register.CR6) "CR6" with get
  member val CR7 = var 4<rt> (Register.toRegID Register.CR7) "CR7" with get
  member val FPSCR =
    var 32<rt> (Register.toRegID Register.FPSCR) "FPSCR" with get
  member val XER = var 32<rt> (Register.toRegID Register.XER) "XER" with get
  member val LR = var regType (Register.toRegID Register.LR) "LR" with get
  member val CTR = var regType (Register.toRegID Register.CTR) "CTR" with get

  member __.GetRegVar (name) =
    match name with
    | R.GPR0 -> __.R0
    | R.GPR1 -> __.R1
    | R.GPR2 -> __.R2
    | R.GPR3 -> __.R3
    | R.GPR4 -> __.R4
    | R.GPR5 -> __.R5
    | R.GPR6 -> __.R6
    | R.GPR7 -> __.R7
    | R.GPR8 -> __.R8
    | R.GPR9 -> __.R9
    | R.GPR10 -> __.R10
    | R.GPR11 -> __.R11
    | R.GPR12 -> __.R12
    | R.GPR13 -> __.R13
    | R.GPR14 -> __.R14
    | R.GPR15 -> __.R15
    | R.GPR16 -> __.R16
    | R.GPR17 -> __.R17
    | R.GPR18 -> __.R18
    | R.GPR19 -> __.R19
    | R.GPR20 -> __.R20
    | R.GPR21 -> __.R21
    | R.GPR22 -> __.R22
    | R.GPR23 -> __.R23
    | R.GPR24 -> __.R24
    | R.GPR25 -> __.R25
    | R.GPR26 -> __.R26
    | R.GPR27 -> __.R27
    | R.GPR28 -> __.R28
    | R.GPR29 -> __.R29
    | R.GPR30 -> __.R30
    | R.GPR31 -> __.R31
    | R.FPR0 -> __.F0
    | R.FPR1 -> __.F1
    | R.FPR2 -> __.F2
    | R.FPR3 -> __.F3
    | R.FPR4 -> __.F4
    | R.FPR5 -> __.F5
    | R.FPR6 -> __.F6
    | R.FPR7 -> __.F7
    | R.FPR8 -> __.F8
    | R.FPR9 -> __.F9
    | R.FPR10 -> __.F10
    | R.FPR11 -> __.F11
    | R.FPR12 -> __.F12
    | R.FPR13 -> __.F13
    | R.FPR14 -> __.F14
    | R.FPR15 -> __.F15
    | R.FPR16 -> __.F16
    | R.FPR17 -> __.F17
    | R.FPR18 -> __.F18
    | R.FPR19 -> __.F19
    | R.FPR20 -> __.F20
    | R.FPR21 -> __.F21
    | R.FPR22 -> __.F22
    | R.FPR23 -> __.F23
    | R.FPR24 -> __.F24
    | R.FPR25 -> __.F25
    | R.FPR26 -> __.F26
    | R.FPR27 -> __.F27
    | R.FPR28 -> __.F28
    | R.FPR29 -> __.F29
    | R.FPR30 -> __.F30
    | R.FPR31 -> __.F31
    | R.CR0 -> __.CR0
    | R.CR1 -> __.CR1
    | R.CR2 -> __.CR2
    | R.CR3 -> __.CR3
    | R.CR4 -> __.CR4
    | R.CR5 -> __.CR5
    | R.CR6 -> __.CR6
    | R.CR7 -> __.CR7
    | R.FPSCR -> __.FPSCR
    | R.XER -> __.XER
    | R.LR -> __.LR
    | R.CTR -> __.CTR
    | _ -> raise UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
