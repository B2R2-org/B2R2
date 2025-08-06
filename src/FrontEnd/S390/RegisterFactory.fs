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

/// Represents a factory for accessing various s390 register variables.
type RegisterFactory(wordSize) =
  let r0 = AST.var 64<rt> (Register.toRegID Register.R0) "R0"
  let r1 = AST.var 64<rt> (Register.toRegID Register.R1) "R1"
  let r2 = AST.var 64<rt> (Register.toRegID Register.R2) "R2"
  let r3 = AST.var 64<rt> (Register.toRegID Register.R3) "R3"
  let r4 = AST.var 64<rt> (Register.toRegID Register.R4) "R4"
  let r5 = AST.var 64<rt> (Register.toRegID Register.R5) "R5"
  let r6 = AST.var 64<rt> (Register.toRegID Register.R6) "R6"
  let r7 = AST.var 64<rt> (Register.toRegID Register.R7) "R7"
  let r8 = AST.var 64<rt> (Register.toRegID Register.R8) "R8"
  let r9 = AST.var 64<rt> (Register.toRegID Register.R9) "R9"
  let r10 = AST.var 64<rt> (Register.toRegID Register.R10) "R10"
  let r11 = AST.var 64<rt> (Register.toRegID Register.R11) "R11"
  let r12 = AST.var 64<rt> (Register.toRegID Register.R12) "R12"
  let r13 = AST.var 64<rt> (Register.toRegID Register.R13) "R13"
  let r14 = AST.var 64<rt> (Register.toRegID Register.R14) "R14"
  let r15 = AST.var 64<rt> (Register.toRegID Register.R15) "R15"
  let fpr0 = AST.var 64<rt> (Register.toRegID Register.FPR0) "FPR0"
  let fpr1 = AST.var 64<rt> (Register.toRegID Register.FPR1) "FPR1"
  let fpr2 = AST.var 64<rt> (Register.toRegID Register.FPR2) "FPR2"
  let fpr3 = AST.var 64<rt> (Register.toRegID Register.FPR3) "FPR3"
  let fpr4 = AST.var 64<rt> (Register.toRegID Register.FPR4) "FPR4"
  let fpr5 = AST.var 64<rt> (Register.toRegID Register.FPR5) "FPR5"
  let fpr6 = AST.var 64<rt> (Register.toRegID Register.FPR6) "FPR6"
  let fpr7 = AST.var 64<rt> (Register.toRegID Register.FPR7) "FPR7"
  let fpr8 = AST.var 64<rt> (Register.toRegID Register.FPR8) "FPR8"
  let fpr9 = AST.var 64<rt> (Register.toRegID Register.FPR9) "FPR9"
  let fpr10 = AST.var 64<rt> (Register.toRegID Register.FPR10) "FPR10"
  let fpr11 = AST.var 64<rt> (Register.toRegID Register.FPR11) "FPR11"
  let fpr12 = AST.var 64<rt> (Register.toRegID Register.FPR12) "FPR12"
  let fpr13 = AST.var 64<rt> (Register.toRegID Register.FPR13) "FPR13"
  let fpr14 = AST.var 64<rt> (Register.toRegID Register.FPR14) "FPR14"
  let fpr15 = AST.var 64<rt> (Register.toRegID Register.FPR15) "FPR15"
  let fpc = AST.var 32<rt> (Register.toRegID Register.FPC) "FPC"
  let vr0 = AST.var 128<rt> (Register.toRegID Register.VR0) "VR0"
  let vr1 = AST.var 128<rt> (Register.toRegID Register.VR1) "VR1"
  let vr2 = AST.var 128<rt> (Register.toRegID Register.VR2) "VR2"
  let vr3 = AST.var 128<rt> (Register.toRegID Register.VR3) "VR3"
  let vr4 = AST.var 128<rt> (Register.toRegID Register.VR4) "VR4"
  let vr5 = AST.var 128<rt> (Register.toRegID Register.VR5) "VR5"
  let vr6 = AST.var 128<rt> (Register.toRegID Register.VR6) "VR6"
  let vr7 = AST.var 128<rt> (Register.toRegID Register.VR7) "VR7"
  let vr8 = AST.var 128<rt> (Register.toRegID Register.VR8) "VR8"
  let vr9 = AST.var 128<rt> (Register.toRegID Register.VR9) "VR9"
  let vr10 = AST.var 128<rt> (Register.toRegID Register.VR10) "VR10"
  let vr11 = AST.var 128<rt> (Register.toRegID Register.VR11) "VR11"
  let vr12 = AST.var 128<rt> (Register.toRegID Register.VR12) "VR12"
  let vr13 = AST.var 128<rt> (Register.toRegID Register.VR13) "VR13"
  let vr14 = AST.var 128<rt> (Register.toRegID Register.VR14) "VR14"
  let vr15 = AST.var 128<rt> (Register.toRegID Register.VR15) "VR15"
  let vr16 = AST.var 128<rt> (Register.toRegID Register.VR16) "VR16"
  let vr17 = AST.var 128<rt> (Register.toRegID Register.VR17) "VR17"
  let vr18 = AST.var 128<rt> (Register.toRegID Register.VR18) "VR18"
  let vr19 = AST.var 128<rt> (Register.toRegID Register.VR19) "VR19"
  let vr20 = AST.var 128<rt> (Register.toRegID Register.VR20) "VR20"
  let vr21 = AST.var 128<rt> (Register.toRegID Register.VR21) "VR21"
  let vr22 = AST.var 128<rt> (Register.toRegID Register.VR22) "VR22"
  let vr23 = AST.var 128<rt> (Register.toRegID Register.VR23) "VR23"
  let vr24 = AST.var 128<rt> (Register.toRegID Register.VR24) "VR24"
  let vr25 = AST.var 128<rt> (Register.toRegID Register.VR25) "VR25"
  let vr26 = AST.var 128<rt> (Register.toRegID Register.VR26) "VR26"
  let vr27 = AST.var 128<rt> (Register.toRegID Register.VR27) "VR27"
  let vr28 = AST.var 128<rt> (Register.toRegID Register.VR28) "VR28"
  let vr29 = AST.var 128<rt> (Register.toRegID Register.VR29) "VR29"
  let vr30 = AST.var 128<rt> (Register.toRegID Register.VR30) "VR30"
  let vr31 = AST.var 128<rt> (Register.toRegID Register.VR31) "VR31"
  let cr0 = AST.var 64<rt> (Register.toRegID Register.CR0) "CR0"
  let cr1 = AST.var 64<rt> (Register.toRegID Register.CR1) "CR1"
  let cr2 = AST.var 64<rt> (Register.toRegID Register.CR2) "CR2"
  let cr3 = AST.var 64<rt> (Register.toRegID Register.CR3) "CR3"
  let cr4 = AST.var 64<rt> (Register.toRegID Register.CR4) "CR4"
  let cr5 = AST.var 64<rt> (Register.toRegID Register.CR5) "CR5"
  let cr6 = AST.var 64<rt> (Register.toRegID Register.CR6) "CR6"
  let cr7 = AST.var 64<rt> (Register.toRegID Register.CR7) "CR7"
  let cr8 = AST.var 64<rt> (Register.toRegID Register.CR8) "CR8"
  let cr9 = AST.var 64<rt> (Register.toRegID Register.CR9) "CR9"
  let cr10 = AST.var 64<rt> (Register.toRegID Register.CR10) "CR10"
  let cr11 = AST.var 64<rt> (Register.toRegID Register.CR11) "CR11"
  let cr12 = AST.var 64<rt> (Register.toRegID Register.CR12) "CR12"
  let cr13 = AST.var 64<rt> (Register.toRegID Register.CR13) "CR13"
  let cr14 = AST.var 64<rt> (Register.toRegID Register.CR14) "CR14"
  let cr15 = AST.var 64<rt> (Register.toRegID Register.CR15) "CR15"
  let ar0 = AST.var 32<rt> (Register.toRegID Register.AR0) "AR0"
  let ar1 = AST.var 32<rt> (Register.toRegID Register.AR1) "AR1"
  let ar2 = AST.var 32<rt> (Register.toRegID Register.AR2) "AR2"
  let ar3 = AST.var 32<rt> (Register.toRegID Register.AR3) "AR3"
  let ar4 = AST.var 32<rt> (Register.toRegID Register.AR4) "AR4"
  let ar5 = AST.var 32<rt> (Register.toRegID Register.AR5) "AR5"
  let ar6 = AST.var 32<rt> (Register.toRegID Register.AR6) "AR6"
  let ar7 = AST.var 32<rt> (Register.toRegID Register.AR7) "AR7"
  let ar8 = AST.var 32<rt> (Register.toRegID Register.AR8) "AR8"
  let ar9 = AST.var 32<rt> (Register.toRegID Register.AR9) "AR9"
  let ar10 = AST.var 32<rt> (Register.toRegID Register.AR10) "AR10"
  let ar11 = AST.var 32<rt> (Register.toRegID Register.AR11) "AR11"
  let ar12 = AST.var 32<rt> (Register.toRegID Register.AR12) "AR12"
  let ar13 = AST.var 32<rt> (Register.toRegID Register.AR13) "AR13"
  let ar14 = AST.var 32<rt> (Register.toRegID Register.AR14) "AR14"
  let ar15 = AST.var 32<rt> (Register.toRegID Register.AR15) "AR15"
  let bear = AST.var 64<rt> (Register.toRegID Register.BEAR) "BEAR"
  let psw = AST.var 128<rt> (Register.toRegID Register.PSW) "PSW"

  interface IRegisterFactory with
    member _.GetRegVar id =
      match Register.ofRegID id with
      | R.R0 -> r0
      | R.R1 -> r1
      | R.R2 -> r2
      | R.R3 -> r3
      | R.R4 -> r4
      | R.R5 -> r5
      | R.R6 -> r6
      | R.R7 -> r7
      | R.R8 -> r8
      | R.R9 -> r9
      | R.R10 -> r10
      | R.R11 -> r11
      | R.R12 -> r12
      | R.R13 -> r13
      | R.R14 -> r14
      | R.R15 -> r15
      | R.FPR0 -> fpr0
      | R.FPR1 -> fpr1
      | R.FPR2 -> fpr2
      | R.FPR3 -> fpr3
      | R.FPR4 -> fpr4
      | R.FPR5 -> fpr5
      | R.FPR6 -> fpr6
      | R.FPR7 -> fpr7
      | R.FPR8 -> fpr8
      | R.FPR9 -> fpr9
      | R.FPR10 -> fpr10
      | R.FPR11 -> fpr11
      | R.FPR12 -> fpr12
      | R.FPR13 -> fpr13
      | R.FPR14 -> fpr14
      | R.FPR15 -> fpr15
      | R.FPC -> fpc
      | R.VR0 -> vr0
      | R.VR1 -> vr1
      | R.VR2 -> vr2
      | R.VR3 -> vr3
      | R.VR4 -> vr4
      | R.VR5 -> vr5
      | R.VR6 -> vr6
      | R.VR7 -> vr7
      | R.VR8 -> vr8
      | R.VR9 -> vr9
      | R.VR10 -> vr10
      | R.VR11 -> vr11
      | R.VR12 -> vr12
      | R.VR13 -> vr13
      | R.VR14 -> vr14
      | R.VR15 -> vr15
      | R.VR16 -> vr16
      | R.VR17 -> vr17
      | R.VR18 -> vr18
      | R.VR19 -> vr19
      | R.VR20 -> vr20
      | R.VR21 -> vr21
      | R.VR22 -> vr22
      | R.VR23 -> vr23
      | R.VR24 -> vr24
      | R.VR25 -> vr25
      | R.VR26 -> vr26
      | R.VR27 -> vr27
      | R.VR28 -> vr28
      | R.VR29 -> vr29
      | R.VR30 -> vr30
      | R.VR31 -> vr31
      | R.CR0 -> cr0
      | R.CR1 -> cr1
      | R.CR2 -> cr2
      | R.CR3 -> cr3
      | R.CR4 -> cr4
      | R.CR5 -> cr5
      | R.CR6 -> cr6
      | R.CR7 -> cr7
      | R.CR8 -> cr8
      | R.CR9 -> cr9
      | R.CR10 -> cr10
      | R.CR11 -> cr11
      | R.CR12 -> cr12
      | R.CR13 -> cr13
      | R.CR14 -> cr14
      | R.CR15 -> cr15
      | R.AR0 -> ar0
      | R.AR1 -> ar1
      | R.AR2 -> ar2
      | R.AR3 -> ar3
      | R.AR4 -> ar4
      | R.AR5 -> ar5
      | R.AR6 -> ar6
      | R.AR7 -> ar7
      | R.AR8 -> ar8
      | R.AR9 -> ar9
      | R.AR10 -> ar10
      | R.AR11 -> ar11
      | R.AR12 -> ar12
      | R.AR13 -> ar13
      | R.AR14 -> ar14
      | R.AR15 -> ar15
      | R.BEAR -> bear
      | R.PSW -> psw
      | _ -> raise InvalidRegisterException

    member _.GetRegVar(name: string) =
      match name.ToUpperInvariant() with
      | "R0" -> r0
      | "R1" -> r1
      | "R2" -> r2
      | "R3" -> r3
      | "R4" -> r4
      | "R5" -> r5
      | "R6" -> r6
      | "R7" -> r7
      | "R8" -> r8
      | "R9" -> r9
      | "R10" -> r10
      | "R11" -> r11
      | "R12" -> r12
      | "R13" -> r13
      | "R14" -> r14
      | "R15" -> r15
      | "FPR0" -> fpr0
      | "FPR1" -> fpr1
      | "FPR2" -> fpr2
      | "FPR3" -> fpr3
      | "FPR4" -> fpr4
      | "FPR5" -> fpr5
      | "FPR6" -> fpr6
      | "FPR7" -> fpr7
      | "FPR8" -> fpr8
      | "FPR9" -> fpr9
      | "FPR10" -> fpr10
      | "FPR11" -> fpr11
      | "FPR12" -> fpr12
      | "FPR13" -> fpr13
      | "FPR14" -> fpr14
      | "FPR15" -> fpr15
      | "FPC" -> fpc
      | "VR0" -> vr0
      | "VR1" -> vr1
      | "VR2" -> vr2
      | "VR3" -> vr3
      | "VR4" -> vr4
      | "VR5" -> vr5
      | "VR6" -> vr6
      | "VR7" -> vr7
      | "VR8" -> vr8
      | "VR9" -> vr9
      | "VR10" -> vr10
      | "VR11" -> vr11
      | "VR12" -> vr12
      | "VR13" -> vr13
      | "VR14" -> vr14
      | "VR15" -> vr15
      | "VR16" -> vr16
      | "VR17" -> vr17
      | "VR18" -> vr18
      | "VR19" -> vr19
      | "VR20" -> vr20
      | "VR21" -> vr21
      | "VR22" -> vr22
      | "VR23" -> vr23
      | "VR24" -> vr24
      | "VR25" -> vr25
      | "VR26" -> vr26
      | "VR27" -> vr27
      | "VR28" -> vr28
      | "VR29" -> vr29
      | "VR30" -> vr30
      | "VR31" -> vr31
      | "CR0" -> cr0
      | "CR1" -> cr1
      | "CR2" -> cr2
      | "CR3" -> cr3
      | "CR4" -> cr4
      | "CR5" -> cr5
      | "CR6" -> cr6
      | "CR7" -> cr7
      | "CR8" -> cr8
      | "CR9" -> cr9
      | "CR10" -> cr10
      | "CR11" -> cr11
      | "CR12" -> cr12
      | "CR13" -> cr13
      | "CR14" -> cr14
      | "CR15" -> cr15
      | "AR0" -> ar0
      | "AR1" -> ar1
      | "AR2" -> ar2
      | "AR3" -> ar3
      | "AR4" -> ar4
      | "AR5" -> ar5
      | "AR6" -> ar6
      | "AR7" -> ar7
      | "AR8" -> ar8
      | "AR9" -> ar9
      | "AR10" -> ar10
      | "AR11" -> ar11
      | "AR12" -> ar12
      | "AR13" -> ar13
      | "AR14" -> ar14
      | "AR15" -> ar15
      | "BEAR" -> bear
      | "PSW" -> psw
      | _ -> raise InvalidRegisterException

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

    member _.GetAllRegVars() =
      [| r0
         r1
         r2
         r3
         r4
         r5
         r6
         r7
         r8
         r9
         r10
         r11
         r12
         r13
         r14
         r15
         fpr0
         fpr1
         fpr2
         fpr3
         fpr4
         fpr5
         fpr6
         fpr7
         fpr8
         fpr9
         fpr10
         fpr11
         fpr12
         fpr13
         fpr14
         fpr15
         fpc
         vr0
         vr1
         vr2
         vr3
         vr4
         vr5
         vr6
         vr7
         vr8
         vr9
         vr10
         vr11
         vr12
         vr13
         vr14
         vr15
         vr16
         vr17
         vr18
         vr19
         vr20
         vr21
         vr22
         vr23
         vr24
         vr25
         vr26
         vr27
         vr28
         vr29
         vr30
         vr31
         cr0
         cr1
         cr2
         cr3
         cr4
         cr5
         cr6
         cr7
         cr8
         cr9
         cr10
         cr11
         cr12
         cr13
         cr14
         cr15
         ar0
         ar1
         ar2
         ar3
         ar4
         ar5
         ar6
         ar7
         ar8
         ar9
         ar10
         ar11
         ar12
         ar13
         ar14
         ar15
         bear
         psw |]

    member _.GetGeneralRegVars() =
      [| r0
         r1
         r2
         r3
         r4
         r5
         r6
         r7
         r8
         r9
         r10
         r11
         r12
         r13
         r14
         r15 |]

    member _.GetRegisterID expr =
      match expr with
      | Var(_, id, _, _) -> id
      | PCVar _ -> Register.toRegID Register.PSW
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name =
      Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases _rid =
      Register.ofRegID _rid
      |> Register.getAliases
      |> Array.map Register.toRegID

    member _.GetRegString rid =
      Register.ofRegID rid |> Register.toString

    member this.GetAllRegStrings() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegString)

    member _.GetRegType rid =
      Register.ofRegID rid |> Register.toRegType wordSize

    member _.ProgramCounter =
      Register.PSW |> Register.toRegID

    member _.StackPointer =
      Register.R15
      |> Register.toRegID
      |> Some

    member _.FramePointer =
      None

    member _.IsProgramCounter rid =
      Register.toRegID Register.PSW = rid

    member _.IsStackPointer rid =
      Register.toRegID Register.R15 = rid

    member _.IsFramePointer _ = false
