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

namespace B2R2.FrontEnd.MIPS

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
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

  member val F0 = var regType (Register.toRegID F0) "F0" with get
  member val F1 = var regType (Register.toRegID F1) "F1" with get
  member val F2 = var regType (Register.toRegID F2) "F2" with get
  member val F3 = var regType (Register.toRegID F3) "F3" with get
  member val F4 = var regType (Register.toRegID F4) "F4" with get
  member val F5 = var regType (Register.toRegID F5) "F5" with get
  member val F6 = var regType (Register.toRegID F6) "F6" with get
  member val F7 = var regType (Register.toRegID F7) "F7" with get
  member val F8 = var regType (Register.toRegID F8) "F8" with get
  member val F9 = var regType (Register.toRegID F9) "F9" with get
  member val F10 = var regType (Register.toRegID F10) "F10" with get
  member val F11 = var regType (Register.toRegID F11) "F11" with get
  member val F12 = var regType (Register.toRegID F12) "F12" with get
  member val F13 = var regType (Register.toRegID F13) "F13" with get
  member val F14 = var regType (Register.toRegID F14) "F14" with get
  member val F15 = var regType (Register.toRegID F15) "F15" with get
  member val F16 = var regType (Register.toRegID F16) "F16" with get
  member val F17 = var regType (Register.toRegID F17) "F17" with get
  member val F18 = var regType (Register.toRegID F18) "F18" with get
  member val F19 = var regType (Register.toRegID F19) "F19" with get
  member val F20 = var regType (Register.toRegID F20) "F20" with get
  member val F21 = var regType (Register.toRegID F21) "F21" with get
  member val F22 = var regType (Register.toRegID F22) "F22" with get
  member val F23 = var regType (Register.toRegID F23) "F23" with get
  member val F24 = var regType (Register.toRegID F24) "F24" with get
  member val F25 = var regType (Register.toRegID F25) "F25" with get
  member val F26 = var regType (Register.toRegID F26) "F26" with get
  member val F27 = var regType (Register.toRegID F27) "F27" with get
  member val F28 = var regType (Register.toRegID F28) "F28" with get
  member val F29 = var regType (Register.toRegID F29) "F29" with get
  member val F30 = var regType (Register.toRegID F30) "F30" with get
  member val F31 = var regType (Register.toRegID F31) "F31" with get

  member val HI = var regType (Register.toRegID HI) "HI" with get
  member val LO = var regType (Register.toRegID LO) "LO" with get
  member val PC = AST.pcvar regType "PC" with get
  member val NextPC = var regType (Register.toRegID NPC) "nPC" with get
  member val LLBit =
    var 1<rt> (Register.toRegID LLBit) "LLBit" with get
  member val FCSR = var 32<rt> (Register.toRegID FCSR) "FCSR" with get
  member val FIR = var 32<rt> (Register.toRegID FIR) "FIR" with get

  member this.GetRegVar (name) =
    match name with
    | R.HI  -> this.HI
    | R.LO  -> this.LO
    | R.PC  -> this.PC
    | R.NPC  -> this.NextPC
    | R.LLBit -> this.LLBit
    | R.R0  -> this.R0
    | R.R1  -> this.R1
    | R.R2  -> this.R2
    | R.R3  -> this.R3
    | R.R4  -> this.R4
    | R.R5  -> this.R5
    | R.R6  -> this.R6
    | R.R7  -> this.R7
    | R.R8  -> this.R8
    | R.R9  -> this.R9
    | R.R10 -> this.R10
    | R.R11 -> this.R11
    | R.R12 -> this.R12
    | R.R13 -> this.R13
    | R.R14 -> this.R14
    | R.R15 -> this.R15
    | R.R16 -> this.R16
    | R.R17 -> this.R17
    | R.R18 -> this.R18
    | R.R19 -> this.R19
    | R.R20 -> this.R20
    | R.R21 -> this.R21
    | R.R22 -> this.R22
    | R.R23 -> this.R23
    | R.R24 -> this.R24
    | R.R25 -> this.R25
    | R.R26 -> this.R26
    | R.R27 -> this.R27
    | R.R28 -> this.R28
    | R.R29 -> this.R29
    | R.R30 -> this.R30
    | R.R31 -> this.R31
    | R.F0  -> this.F0
    | R.F1  -> this.F1
    | R.F2  -> this.F2
    | R.F3  -> this.F3
    | R.F4  -> this.F4
    | R.F5  -> this.F5
    | R.F6  -> this.F6
    | R.F7  -> this.F7
    | R.F8  -> this.F8
    | R.F9  -> this.F9
    | R.F10 -> this.F10
    | R.F11 -> this.F11
    | R.F12 -> this.F12
    | R.F13 -> this.F13
    | R.F14 -> this.F14
    | R.F15 -> this.F15
    | R.F16 -> this.F16
    | R.F17 -> this.F17
    | R.F18 -> this.F18
    | R.F19 -> this.F19
    | R.F20 -> this.F20
    | R.F21 -> this.F21
    | R.F22 -> this.F22
    | R.F23 -> this.F23
    | R.F24 -> this.F24
    | R.F25 -> this.F25
    | R.F26 -> this.F26
    | R.F27 -> this.F27
    | R.F28 -> this.F28
    | R.F29 -> this.F29
    | R.F30 -> this.F30
    | R.F31 -> this.F31
    | R.FCSR -> this.FCSR
    | R.FIR -> this.FIR
    | _ -> raise UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
