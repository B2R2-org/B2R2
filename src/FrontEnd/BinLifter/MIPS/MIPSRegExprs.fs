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

namespace B2R2.FrontEnd.BinLifter.MIPS

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter

type internal RegExprs (wordSize) =
  let var sz t name = AST.var sz t name (MIPSRegisterSet.singleton t)

  (* Registers *)
  let regType = WordSize.toRegType wordSize

  member val R0 = var regType (Register.toRegID Register.R0) "R0" with get
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
  member val R13 = var regType (Register.toRegID Register.R13) "R13" with get
  member val R14 = var regType (Register.toRegID Register.R14) "R14" with get
  member val R15 = var regType (Register.toRegID Register.R15) "R15" with get
  member val R16 = var regType (Register.toRegID Register.R16) "R16" with get
  member val R17 = var regType (Register.toRegID Register.R17) "R17" with get
  member val R18 = var regType (Register.toRegID Register.R18) "R18" with get
  member val R19 = var regType (Register.toRegID Register.R19) "R19" with get
  member val R20 = var regType (Register.toRegID Register.R20) "R20" with get
  member val R21 = var regType (Register.toRegID Register.R21) "R21" with get
  member val R22 = var regType (Register.toRegID Register.R22) "R22" with get
  member val R23 = var regType (Register.toRegID Register.R23) "R23" with get
  member val R24 = var regType (Register.toRegID Register.R24) "R24" with get
  member val R25 = var regType (Register.toRegID Register.R25) "R25" with get
  member val R26 = var regType (Register.toRegID Register.R26) "R26" with get
  member val R27 = var regType (Register.toRegID Register.R27) "R27" with get
  member val R28 = var regType (Register.toRegID Register.R28) "R28" with get
  member val R29 = var regType (Register.toRegID Register.R29) "R29" with get
  member val R30 = var regType (Register.toRegID Register.R30) "R30" with get
  member val R31 = var regType (Register.toRegID Register.R31) "R31" with get

  member val F0 = var regType (Register.toRegID Register.F0) "F0" with get
  member val F1 = var regType (Register.toRegID Register.F1) "F1" with get
  member val F2 = var regType (Register.toRegID Register.F2) "F2" with get
  member val F3 = var regType (Register.toRegID Register.F3) "F3" with get
  member val F4 = var regType (Register.toRegID Register.F4) "F4" with get
  member val F5 = var regType (Register.toRegID Register.F5) "F5" with get
  member val F6 = var regType (Register.toRegID Register.F6) "F6" with get
  member val F7 = var regType (Register.toRegID Register.F7) "F7" with get
  member val F8 = var regType (Register.toRegID Register.F8) "F8" with get
  member val F9 = var regType (Register.toRegID Register.F9) "F9" with get
  member val F10 = var regType (Register.toRegID Register.F10) "F10" with get
  member val F11 = var regType (Register.toRegID Register.F11) "F11" with get
  member val F12 = var regType (Register.toRegID Register.F12) "F12" with get
  member val F13 = var regType (Register.toRegID Register.F13) "F13" with get
  member val F14 = var regType (Register.toRegID Register.F14) "F14" with get
  member val F15 = var regType (Register.toRegID Register.F15) "F15" with get
  member val F16 = var regType (Register.toRegID Register.F16) "F16" with get
  member val F17 = var regType (Register.toRegID Register.F17) "F17" with get
  member val F18 = var regType (Register.toRegID Register.F18) "F18" with get
  member val F19 = var regType (Register.toRegID Register.F19) "F19" with get
  member val F20 = var regType (Register.toRegID Register.F20) "F20" with get
  member val F21 = var regType (Register.toRegID Register.F21) "F21" with get
  member val F22 = var regType (Register.toRegID Register.F22) "F22" with get
  member val F23 = var regType (Register.toRegID Register.F23) "F23" with get
  member val F24 = var regType (Register.toRegID Register.F24) "F24" with get
  member val F25 = var regType (Register.toRegID Register.F25) "F25" with get
  member val F26 = var regType (Register.toRegID Register.F26) "F26" with get
  member val F27 = var regType (Register.toRegID Register.F27) "F27" with get
  member val F28 = var regType (Register.toRegID Register.F28) "F28" with get
  member val F29 = var regType (Register.toRegID Register.F29) "F29" with get
  member val F30 = var regType (Register.toRegID Register.F30) "F30" with get
  member val F31 = var regType (Register.toRegID Register.F31) "F31" with get

  member val HI = var regType (Register.toRegID Register.HI) "HI" with get
  member val LO = var regType (Register.toRegID Register.LO) "LO" with get
  member val PC = AST.pcvar regType "PC" with get
  member val NextPC = var regType (Register.toRegID Register.NPC) "nPC" with get

  member __.GetRegVar (name) =
    match name with
    | R.HI  -> __.HI
    | R.LO  -> __.LO
    | R.PC  -> __.PC
    | R.NPC  -> __.NextPC
    | R.R0  -> __.R0
    | R.R1  -> __.R1
    | R.R2  -> __.R2
    | R.R3  -> __.R3
    | R.R4  -> __.R4
    | R.R5  -> __.R5
    | R.R6  -> __.R6
    | R.R7  -> __.R7
    | R.R8  -> __.R8
    | R.R9  -> __.R9
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
    | R.F0  -> __.F0
    | R.F1  -> __.F1
    | R.F2  -> __.F2
    | R.F3  -> __.F3
    | R.F4  -> __.F4
    | R.F5  -> __.F5
    | R.F6  -> __.F6
    | R.F7  -> __.F7
    | R.F8  -> __.F8
    | R.F9  -> __.F9
    | R.F10 -> __.F10
    | R.F11 -> __.F11
    | R.F12 -> __.F12
    | R.F13 -> __.F13
    | R.F14 -> __.F14
    | R.F15 -> __.F15
    | R.F16 -> __.F16
    | R.F17 -> __.F17
    | R.F18 -> __.F18
    | R.F19 -> __.F19
    | R.F20 -> __.F20
    | R.F21 -> __.F21
    | R.F22 -> __.F22
    | R.F23 -> __.F23
    | R.F24 -> __.F24
    | R.F25 -> __.F25
    | R.F26 -> __.F26
    | R.F27 -> __.F27
    | R.F28 -> __.F28
    | R.F29 -> __.F29
    | R.F30 -> __.F30
    | R.F31 -> __.F31
    | _ -> raise UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
