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
open B2R2.FrontEnd
open B2R2.FrontEnd.Register
open B2R2.BinIR.LowUIR

type RegExprs (wordSize) =
  let var sz t name = AST.var sz t name

  (* Registers *)
  let regType = WordSize.toRegType wordSize

  let reg16 reg1 reg2=
    AST.concat reg1 reg2

  let r26 = var regType (AVRRegister.ID AVR.R26) "R26"
  let r27 = var regType (AVRRegister.ID AVR.R27) "R27"
  let r28 = var regType (AVRRegister.ID AVR.R28) "R28"
  let r29 = var regType (AVRRegister.ID AVR.R29) "R29"
  let r30 = var regType (AVRRegister.ID AVR.R30) "R30"
  let r31 = var regType (AVRRegister.ID AVR.R31) "R31"


  member val R0= var regType (AVRRegister.ID AVR.R0) "R0" with get
  member val R1 = var regType (AVRRegister.ID AVR.R1) "R1" with get
  member val R2 = var regType (AVRRegister.ID AVR.R2) "R2" with get
  member val R3 = var regType (AVRRegister.ID AVR.R3) "R3" with get
  member val R4 = var regType (AVRRegister.ID AVR.R4) "R4" with get
  member val R5 = var regType (AVRRegister.ID AVR.R5) "R5" with get
  member val R6 = var regType (AVRRegister.ID AVR.R6) "R6" with get
  member val R7 = var regType (AVRRegister.ID AVR.R7) "R7" with get
  member val R8 = var regType (AVRRegister.ID AVR.R8) "R8" with get
  member val R9 = var regType (AVRRegister.ID AVR.R9) "R9" with get
  member val R10 = var regType (AVRRegister.ID AVR.R10) "R10" with get
  member val R11 = var regType (AVRRegister.ID AVR.R11) "R11" with get
  member val R12 = var regType (AVRRegister.ID AVR.R12) "R12" with get
  member val R13 = var regType (AVRRegister.ID AVR.R13) "R13" with get
  member val R14 = var regType (AVRRegister.ID AVR.R14) "R14" with get
  member val R15 = var regType (AVRRegister.ID AVR.R15) "R15" with get
  member val R16 = var regType (AVRRegister.ID AVR.R16) "R16" with get
  member val R17 = var regType (AVRRegister.ID AVR.R17) "R17" with get
  member val R18 = var regType (AVRRegister.ID AVR.R18) "R18" with get
  member val R19 = var regType (AVRRegister.ID AVR.R19) "R19" with get
  member val R20 = var regType (AVRRegister.ID AVR.R20) "R20" with get
  member val R21 = var regType (AVRRegister.ID AVR.R21) "R21" with get
  member val R22 = var regType (AVRRegister.ID AVR.R22) "R22" with get
  member val R23 = var regType (AVRRegister.ID AVR.R23) "R23" with get
  member val R24 = var regType (AVRRegister.ID AVR.R24) "R24" with get
  member val R25 = var regType (AVRRegister.ID AVR.R25) "R25" with get
  member val R26 = r26 with get
  member val R27 = r27 with get
  member val R28 = r28 with get
  member val R29 = r29 with get
  member val R30 = r30 with get
  member val R31 = r31 with get
  member val X = reg16 r27 r26 with get
  member val Y = reg16 r29 r28 with get
  member val Z = reg16 r31 r30 with get
  member val IF = var 1<rt> (AVRRegister.ID AVR.IF) "IF" with get
  member val TF = var 1<rt> (AVRRegister.ID AVR.TF) "TF" with get
  member val HF = var 1<rt> (AVRRegister.ID AVR.HF) "HF" with get
  member val SF = var 1<rt> (AVRRegister.ID AVR.SF) "SF" with get
  member val VF = var 1<rt> (AVRRegister.ID AVR.VF) "VF" with get
  member val NF = var 1<rt> (AVRRegister.ID AVR.NF) "NF" with get
  member val ZF = var 1<rt> (AVRRegister.ID AVR.ZF) "ZF" with get
  member val CF = var 1<rt> (AVRRegister.ID AVR.CF) "CF" with get
  member val PC = AST.pcvar 16<rt> "PC"
  member val SP = var 16<rt> (AVRRegister.ID AVR.SP) "SP" with get

  member __.GetRegVar (name) =
    match name with
    | AVR.R0 -> __.R0
    | AVR.R1 -> __.R1
    | AVR.R2 -> __.R2
    | AVR.R3 -> __.R3
    | AVR.R4 -> __.R4
    | AVR.R5 -> __.R5
    | AVR.R6 -> __.R6
    | AVR.R7 -> __.R7
    | AVR.R8 -> __.R8
    | AVR.R9 -> __.R9
    | AVR.R10 -> __.R10
    | AVR.R11 -> __.R11
    | AVR.R12 -> __.R12
    | AVR.R13 -> __.R13
    | AVR.R14 -> __.R14
    | AVR.R15 -> __.R15
    | AVR.R16 -> __.R16
    | AVR.R17 -> __.R17
    | AVR.R18 -> __.R18
    | AVR.R19 -> __.R19
    | AVR.R20 -> __.R20
    | AVR.R21 -> __.R21
    | AVR.R22 -> __.R22
    | AVR.R23 -> __.R23
    | AVR.R24 -> __.R24
    | AVR.R25 -> __.R25
    | AVR.R26 -> __.R26
    | AVR.R27 -> __.R27
    | AVR.R28 -> __.R28
    | AVR.R29 -> __.R29
    | AVR.R30 -> __.R30
    | AVR.R31 -> __.R31
    | AVR.X -> __.X
    | AVR.Y -> __.Y
    | AVR.Z -> __.Z
    | AVR.IF -> __.IF
    | AVR.TF -> __.TF
    | AVR.HF -> __.HF
    | AVR.SF -> __.SF
    | AVR.VF -> __.VF
    | AVR.NF -> __.NF
    | AVR.ZF -> __.ZF
    | AVR.CF  -> __.CF
    | AVR.PC -> __.PC
    | AVR.SP -> __.SP
    | _ -> raise UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
