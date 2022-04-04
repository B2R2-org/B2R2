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
    | _ -> raise B2R2.FrontEnd.BinLifter.UnhandledRegExprException

// vim: set tw=80 sts=2 sw=2:
