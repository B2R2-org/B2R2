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

namespace B2R2.FrontEnd.BinLifter.AVR

open B2R2
open B2R2.BinIR.LowUIR

type internal RegExprs (wordSize) =
  let var sz t name = AST.var sz t name (AVRRegisterSet.singleton t)

  (* Registers *)
  let regType = WordSize.toRegType wordSize

  let reg16 reg1 reg2=
    AST.concat reg1 reg2

  let r26 = var regType (Register.toRegID Register.R26) "R26"
  let r27 = var regType (Register.toRegID Register.R27) "R27"
  let r28 = var regType (Register.toRegID Register.R28) "R28"
  let r29 = var regType (Register.toRegID Register.R29) "R29"
  let r30 = var regType (Register.toRegID Register.R30) "R30"
  let r31 = var regType (Register.toRegID Register.R31) "R31"


  member val R0= var regType (Register.toRegID Register.R0) "R0" with get
  member val R1 = var regType (Register.toRegID Register.R1) "R1" with get
  member val R2 = var regType (Register.toRegID Register.R2) "R2" with get
  member val R3 = var regType (Register.toRegID Register.R3) "R3" with get
  member val R4 = var regType (Register.toRegID Register.R4) "R4" with get
  member val R5 = var regType (Register.toRegID Register.R5) "R5" with get
  member val R6 = var regType (Register.toRegID Register.R6) "R6" with get
  member val R7 = var regType (Register.toRegID Register.R7) "R7" with get
  member val R8 = var regType (Register.toRegID Register.R8) "R8" with get
  member val R9 = var regType (Register.toRegID Register.R9) "R9" with get
  member val R10 = var regType (Register.toRegID Register.R10) "R10" with get
  member val R11 = var regType (Register.toRegID Register.R11) "R11" with get
  member val R12 = var regType (Register.toRegID Register.R12) "R12" with get
  member val R13 = var regType (Register.toRegID Register.R12) "R13" with get
  member val R14 = var regType (Register.toRegID Register.R13) "R14" with get
  member val R15 = var regType (Register.toRegID Register.R14) "R15" with get
  member val R16 = var regType (Register.toRegID Register.R15) "R16" with get
  member val R17 = var regType (Register.toRegID Register.R16) "R17" with get
  member val R18 = var regType (Register.toRegID Register.R17) "R18" with get
  member val R19 = var regType (Register.toRegID Register.R18) "R19" with get
  member val R20 = var regType (Register.toRegID Register.R19) "R20" with get
  member val R21 = var regType (Register.toRegID Register.R21) "R21" with get
  member val R22 = var regType (Register.toRegID Register.R22) "R22" with get
  member val R23 = var regType (Register.toRegID Register.R23) "R23" with get
  member val R24 = var regType (Register.toRegID Register.R24) "R24" with get
  member val R25 = var regType (Register.toRegID Register.R25) "R25" with get
  member val R26 = r26 with get
  member val R27 = r27 with get
  member val R28 = r28 with get
  member val R29 = r29 with get
  member val R30 = r30 with get
  member val R31 = r31 with get
  member val X = reg16 r27 r26 with get
  member val Y = reg16 r29 r28 with get
  member val Z = reg16 r31 r30 with get
  member val IF = var 1<rt> (Register.toRegID Register.IF) "IF" with get
  member val TF = var 1<rt> (Register.toRegID Register.TF) "TF" with get
  member val HF = var 1<rt> (Register.toRegID Register.HF) "HF" with get
  member val SF = var 1<rt> (Register.toRegID Register.SF) "SF" with get
  member val VF = var 1<rt> (Register.toRegID Register.VF) "VF" with get
  member val NF = var 1<rt> (Register.toRegID Register.NF) "NF" with get
  member val ZF = var 1<rt> (Register.toRegID Register.ZF) "ZF" with get
  member val CF = var 1<rt> (Register.toRegID Register.CF) "CF" with get
  member val PC = AST.pcvar 16<rt> "PC"
  member val SP = var 16<rt> (Register.toRegID Register.SP) "SP" with get

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
    | R.R9 -> __.R9
    | R.R10 -> __.R10
    | R.R11 -> __.R11
    | R.R12 -> __.R12
    | R.R13 -> __.R13
    | R.R14 -> __.R14
    | R.R15 -> __.R15
    | R.R16 -> __.R16
    | R.R17 -> __.R17
    | R.R18 -> __.R18
    | R.R19 -> __.R19
    | R.R20 -> __.R20
    | R.R21 -> __.R21
    | R.R22 -> __.R22
    | R.R23 -> __.R23
    | R.R24 -> __.R24
    | R.R25 -> __.R25
    | R.R26 -> __.R26
    | R.R27 -> __.R27
    | R.R28 -> __.R28
    | R.R29 -> __.R29
    | R.R30 -> __.R30
    | R.R31 -> __.R31
    | R.X -> __.X
    | R.Y -> __.Y
    | R.Z -> __.Z
    | R.IF -> __.IF
    | R.TF -> __.TF
    | R.HF -> __.HF
    | R.SF -> __.SF
    | R.VF -> __.VF
    | R.NF -> __.NF
    | R.ZF -> __.ZF
    | R.CF  -> __.CF
    | R.PC -> __.PC
    | R.SP -> __.SP
    | _ -> raise B2R2.FrontEnd.BinLifter.UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
