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

namespace B2R2.FrontEnd.AVR

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR
open type Register

type RegExprs (wordSize) =
  let var sz t name = AST.var sz t name

  (* Registers *)
  let regType = WordSize.toRegType wordSize

  let reg16 reg1 reg2=
    AST.concat reg1 reg2

  let r26 = var regType (Register.toRegID R26) "R26"
  let r27 = var regType (Register.toRegID R27) "R27"
  let r28 = var regType (Register.toRegID R28) "R28"
  let r29 = var regType (Register.toRegID R29) "R29"
  let r30 = var regType (Register.toRegID R30) "R30"
  let r31 = var regType (Register.toRegID R31) "R31"


  member val R0= var regType (Register.toRegID R0) "R0" with get
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
  member val R26 = r26 with get
  member val R27 = r27 with get
  member val R28 = r28 with get
  member val R29 = r29 with get
  member val R30 = r30 with get
  member val R31 = r31 with get
  member val X = reg16 r27 r26 with get
  member val Y = reg16 r29 r28 with get
  member val Z = reg16 r31 r30 with get
  member val IF = var 1<rt> (Register.toRegID IF) "IF" with get
  member val TF = var 1<rt> (Register.toRegID TF) "TF" with get
  member val HF = var 1<rt> (Register.toRegID HF) "HF" with get
  member val SF = var 1<rt> (Register.toRegID SF) "SF" with get
  member val VF = var 1<rt> (Register.toRegID VF) "VF" with get
  member val NF = var 1<rt> (Register.toRegID NF) "NF" with get
  member val ZF = var 1<rt> (Register.toRegID ZF) "ZF" with get
  member val CF = var 1<rt> (Register.toRegID CF) "CF" with get
  member val PC = AST.pcvar 16<rt> "PC"
  member val SP = var 16<rt> (Register.toRegID SP) "SP" with get

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
    | Register.X -> this.X
    | Register.Y -> this.Y
    | Register.Z -> this.Z
    | Register.IF -> this.IF
    | Register.TF -> this.TF
    | Register.HF -> this.HF
    | Register.SF -> this.SF
    | Register.VF -> this.VF
    | Register.NF -> this.NF
    | Register.ZF -> this.ZF
    | Register.CF  -> this.CF
    | Register.PC -> this.PC
    | Register.SP -> this.SP
    | _ -> raise UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
