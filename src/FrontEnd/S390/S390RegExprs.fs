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

namespace B2R2.FrontEnd.S390

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type RegExprs (_wordSize) =
  let var sz t name = AST.var sz t name
  member val R0 = var 64<rt> (Register.toRegID Register.R0) "R0" with get
  member val R1 = var 64<rt> (Register.toRegID Register.R1) "R1" with get
  member val R2 = var 64<rt> (Register.toRegID Register.R2) "R2" with get
  member val R3 = var 64<rt> (Register.toRegID Register.R3) "R3" with get
  member val R4 = var 64<rt> (Register.toRegID Register.R4) "R4" with get
  member val R5 = var 64<rt> (Register.toRegID Register.R5) "R5" with get
  member val R6 = var 64<rt> (Register.toRegID Register.R6) "R6" with get
  member val R7 = var 64<rt> (Register.toRegID Register.R7) "R7" with get
  member val R8 = var 64<rt> (Register.toRegID Register.R8) "R8" with get
  member val R9 = var 64<rt> (Register.toRegID Register.R9) "R9" with get
  member val R10 = var 64<rt> (Register.toRegID Register.R10) "R10" with get
  member val R11 = var 64<rt> (Register.toRegID Register.R11) "R11" with get
  member val R12 = var 64<rt> (Register.toRegID Register.R12) "R12" with get
  member val R13 = var 64<rt> (Register.toRegID Register.R13) "R13" with get
  member val R14 = var 64<rt> (Register.toRegID Register.R14) "R14" with get
  member val R15 = var 64<rt> (Register.toRegID Register.R15) "R15" with get
  member val FPR0 = var 64<rt> (Register.toRegID Register.FPR0) "FPR0" with get
  member val FPR1 = var 64<rt> (Register.toRegID Register.FPR1) "FPR1" with get
  member val FPR2 = var 64<rt> (Register.toRegID Register.FPR2) "FPR2" with get
  member val FPR3 = var 64<rt> (Register.toRegID Register.FPR3) "FPR3" with get
  member val FPR4 = var 64<rt> (Register.toRegID Register.FPR4) "FPR4" with get
  member val FPR5 = var 64<rt> (Register.toRegID Register.FPR5) "FPR5" with get
  member val FPR6 = var 64<rt> (Register.toRegID Register.FPR6) "FPR6" with get
  member val FPR7 = var 64<rt> (Register.toRegID Register.FPR7) "FPR7" with get
  member val FPR8 = var 64<rt> (Register.toRegID Register.FPR8) "FPR8" with get
  member val FPR9 = var 64<rt> (Register.toRegID Register.FPR9) "FPR9" with get
  member val FPR10 =
    var 64<rt> (Register.toRegID Register.FPR10) "FPR10" with get
  member val FPR11 =
    var 64<rt> (Register.toRegID Register.FPR11) "FPR11" with get
  member val FPR12 =
    var 64<rt> (Register.toRegID Register.FPR12) "FPR12" with get
  member val FPR13 =
    var 64<rt> (Register.toRegID Register.FPR13) "FPR13" with get
  member val FPR14 =
    var 64<rt> (Register.toRegID Register.FPR14) "FPR14" with get
  member val FPR15 =
    var 64<rt> (Register.toRegID Register.FPR15) "FPR15" with get
  member val FPC = var 32<rt> (Register.toRegID Register.FPC) "FPC" with get
  member val VR0 = var 128<rt> (Register.toRegID Register.VR0) "VR0" with get
  member val VR1 = var 128<rt> (Register.toRegID Register.VR1) "VR1" with get
  member val VR2 = var 128<rt> (Register.toRegID Register.VR2) "VR2" with get
  member val VR3 = var 128<rt> (Register.toRegID Register.VR3) "VR3" with get
  member val VR4 = var 128<rt> (Register.toRegID Register.VR4) "VR4" with get
  member val VR5 = var 128<rt> (Register.toRegID Register.VR5) "VR5" with get
  member val VR6 = var 128<rt> (Register.toRegID Register.VR6) "VR6" with get
  member val VR7 = var 128<rt> (Register.toRegID Register.VR7) "VR7" with get
  member val VR8 = var 128<rt> (Register.toRegID Register.VR8) "VR8" with get
  member val VR9 = var 128<rt> (Register.toRegID Register.VR9) "VR9" with get
  member val VR10 = var 128<rt> (Register.toRegID Register.VR10) "VR10" with get
  member val VR11 = var 128<rt> (Register.toRegID Register.VR11) "VR11" with get
  member val VR12 = var 128<rt> (Register.toRegID Register.VR12) "VR12" with get
  member val VR13 = var 128<rt> (Register.toRegID Register.VR13) "VR13" with get
  member val VR14 = var 128<rt> (Register.toRegID Register.VR14) "VR14" with get
  member val VR15 = var 128<rt> (Register.toRegID Register.VR15) "VR15" with get
  member val VR16 = var 128<rt> (Register.toRegID Register.VR16) "VR16" with get
  member val VR17 = var 128<rt> (Register.toRegID Register.VR17) "VR17" with get
  member val VR18 = var 128<rt> (Register.toRegID Register.VR18) "VR18" with get
  member val VR19 = var 128<rt> (Register.toRegID Register.VR19) "VR19" with get
  member val VR20 = var 128<rt> (Register.toRegID Register.VR20) "VR20" with get
  member val VR21 = var 128<rt> (Register.toRegID Register.VR21) "VR21" with get
  member val VR22 = var 128<rt> (Register.toRegID Register.VR22) "VR22" with get
  member val VR23 = var 128<rt> (Register.toRegID Register.VR23) "VR23" with get
  member val VR24 = var 128<rt> (Register.toRegID Register.VR24) "VR24" with get
  member val VR25 = var 128<rt> (Register.toRegID Register.VR25) "VR25" with get
  member val VR26 = var 128<rt> (Register.toRegID Register.VR26) "VR26" with get
  member val VR27 = var 128<rt> (Register.toRegID Register.VR27) "VR27" with get
  member val VR28 = var 128<rt> (Register.toRegID Register.VR28) "VR28" with get
  member val VR29 = var 128<rt> (Register.toRegID Register.VR29) "VR29" with get
  member val VR30 = var 128<rt> (Register.toRegID Register.VR30) "VR30" with get
  member val VR31 = var 128<rt> (Register.toRegID Register.VR31) "VR31" with get
  member val CR0 = var 64<rt> (Register.toRegID Register.CR0) "CR0" with get
  member val CR1 = var 64<rt> (Register.toRegID Register.CR1) "CR1" with get
  member val CR2 = var 64<rt> (Register.toRegID Register.CR2) "CR2" with get
  member val CR3 = var 64<rt> (Register.toRegID Register.CR3) "CR3" with get
  member val CR4 = var 64<rt> (Register.toRegID Register.CR4) "CR4" with get
  member val CR5 = var 64<rt> (Register.toRegID Register.CR5) "CR5" with get
  member val CR6 = var 64<rt> (Register.toRegID Register.CR6) "CR6" with get
  member val CR7 = var 64<rt> (Register.toRegID Register.CR7) "CR7" with get
  member val CR8 = var 64<rt> (Register.toRegID Register.CR8) "CR8" with get
  member val CR9 = var 64<rt> (Register.toRegID Register.CR9) "CR9" with get
  member val CR10 = var 64<rt> (Register.toRegID Register.CR10) "CR10" with get
  member val CR11 = var 64<rt> (Register.toRegID Register.CR11) "CR11" with get
  member val CR12 = var 64<rt> (Register.toRegID Register.CR12) "CR12" with get
  member val CR13 = var 64<rt> (Register.toRegID Register.CR13) "CR13" with get
  member val CR14 = var 64<rt> (Register.toRegID Register.CR14) "CR14" with get
  member val CR15 = var 64<rt> (Register.toRegID Register.CR15) "CR15" with get
  member val AR0 = var 32<rt> (Register.toRegID Register.AR0) "AR0" with get
  member val AR1 = var 32<rt> (Register.toRegID Register.AR1) "AR1" with get
  member val AR2 = var 32<rt> (Register.toRegID Register.AR2) "AR2" with get
  member val AR3 = var 32<rt> (Register.toRegID Register.AR3) "AR3" with get
  member val AR4 = var 32<rt> (Register.toRegID Register.AR4) "AR4" with get
  member val AR5 = var 32<rt> (Register.toRegID Register.AR5) "AR5" with get
  member val AR6 = var 32<rt> (Register.toRegID Register.AR6) "AR6" with get
  member val AR7 = var 32<rt> (Register.toRegID Register.AR7) "AR7" with get
  member val AR8 = var 32<rt> (Register.toRegID Register.AR8) "AR8" with get
  member val AR9 = var 32<rt> (Register.toRegID Register.AR9) "AR9" with get
  member val AR10 = var 32<rt> (Register.toRegID Register.AR10) "AR10" with get
  member val AR11 = var 32<rt> (Register.toRegID Register.AR11) "AR11" with get
  member val AR12 = var 32<rt> (Register.toRegID Register.AR12) "AR12" with get
  member val AR13 = var 32<rt> (Register.toRegID Register.AR13) "AR13" with get
  member val AR14 = var 32<rt> (Register.toRegID Register.AR14) "AR14" with get
  member val AR15 = var 32<rt> (Register.toRegID Register.AR15) "AR15" with get
  member val BEAR = var 64<rt> (Register.toRegID Register.BEAR) "BEAR" with get
  member val PSW = var 128<rt> (Register.toRegID Register.PSW) "PSW" with get
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
    | R.FPR0 -> __.FPR0
    | R.FPR1 -> __.FPR1
    | R.FPR2 -> __.FPR2
    | R.FPR3 -> __.FPR3
    | R.FPR4 -> __.FPR4
    | R.FPR5 -> __.FPR5
    | R.FPR6 -> __.FPR6
    | R.FPR7 -> __.FPR7
    | R.FPR8 -> __.FPR8
    | R.FPR9 -> __.FPR9
    | R.FPR10 -> __.FPR10
    | R.FPR11 -> __.FPR11
    | R.FPR12 -> __.FPR12
    | R.FPR13 -> __.FPR13
    | R.FPR14 -> __.FPR14
    | R.FPR15 -> __.FPR15
    | R.FPC -> __.FPC
    | R.VR0 -> __.VR0
    | R.VR1 -> __.VR1
    | R.VR2 -> __.VR2
    | R.VR3 -> __.VR3
    | R.VR4 -> __.VR4
    | R.VR5 -> __.VR5
    | R.VR6 -> __.VR6
    | R.VR7 -> __.VR7
    | R.VR8 -> __.VR8
    | R.VR9 -> __.VR9
    | R.VR10 -> __.VR10
    | R.VR11 -> __.VR11
    | R.VR12 -> __.VR12
    | R.VR13 -> __.VR13
    | R.VR14 -> __.VR14
    | R.VR15 -> __.VR15
    | R.VR16 -> __.VR16
    | R.VR17 -> __.VR17
    | R.VR18 -> __.VR18
    | R.VR19 -> __.VR19
    | R.VR20 -> __.VR20
    | R.VR21 -> __.VR21
    | R.VR22 -> __.VR22
    | R.VR23 -> __.VR23
    | R.VR24 -> __.VR24
    | R.VR25 -> __.VR25
    | R.VR26 -> __.VR26
    | R.VR27 -> __.VR27
    | R.VR28 -> __.VR28
    | R.VR29 -> __.VR29
    | R.VR30 -> __.VR30
    | R.VR31 -> __.VR31
    | R.CR0 -> __.CR0
    | R.CR1 -> __.CR1
    | R.CR2 -> __.CR2
    | R.CR3 -> __.CR3
    | R.CR4 -> __.CR4
    | R.CR5 -> __.CR5
    | R.CR6 -> __.CR6
    | R.CR7 -> __.CR7
    | R.CR8 -> __.CR8
    | R.CR9 -> __.CR9
    | R.CR10 -> __.CR10
    | R.CR11 -> __.CR11
    | R.CR12 -> __.CR12
    | R.CR13 -> __.CR13
    | R.CR14 -> __.CR14
    | R.CR15 -> __.CR15
    | R.AR0 -> __.AR0
    | R.AR1 -> __.AR1
    | R.AR2 -> __.AR2
    | R.AR3 -> __.AR3
    | R.AR4 -> __.AR4
    | R.AR5 -> __.AR5
    | R.AR6 -> __.AR6
    | R.AR7 -> __.AR7
    | R.AR8 -> __.AR8
    | R.AR9 -> __.AR9
    | R.AR10 -> __.AR10
    | R.AR11 -> __.AR11
    | R.AR12 -> __.AR12
    | R.AR13 -> __.AR13
    | R.AR14 -> __.AR14
    | R.AR15 -> __.AR15
    | R.BEAR -> __.BEAR
    | R.PSW -> __.PSW
    | _ -> raise UnhandledRegExprException
