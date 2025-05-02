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

namespace B2R2.FrontEnd.PPC32

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR
open type Register

type RegisterFactory (wordSize) =
  (* Registers *)
  let rt = WordSize.toRegType wordSize

  let r0 = AST.var rt (Register.toRegID R0) "R0"
  let r1 = AST.var rt (Register.toRegID R1) "R1"
  let r2 = AST.var rt (Register.toRegID R2) "R2"
  let r3 = AST.var rt (Register.toRegID R3) "R3"
  let r4 = AST.var rt (Register.toRegID R4) "R4"
  let r5 = AST.var rt (Register.toRegID R5) "R5"
  let r6 = AST.var rt (Register.toRegID R6) "R6"
  let r7 = AST.var rt (Register.toRegID R7) "R7"
  let r8 = AST.var rt (Register.toRegID R8) "R8"
  let r9 = AST.var rt (Register.toRegID R9) "R9"
  let r10 = AST.var rt (Register.toRegID R10) "R10"
  let r11 = AST.var rt (Register.toRegID R11) "R11"
  let r12 = AST.var rt (Register.toRegID R12) "R12"
  let r13 = AST.var rt (Register.toRegID R13) "R13"
  let r14 = AST.var rt (Register.toRegID R14) "R14"
  let r15 = AST.var rt (Register.toRegID R15) "R15"
  let r16 = AST.var rt (Register.toRegID R16) "R16"
  let r17 = AST.var rt (Register.toRegID R17) "R17"
  let r18 = AST.var rt (Register.toRegID R18) "R18"
  let r19 = AST.var rt (Register.toRegID R19) "R19"
  let r20 = AST.var rt (Register.toRegID R20) "R20"
  let r21 = AST.var rt (Register.toRegID R21) "R21"
  let r22 = AST.var rt (Register.toRegID R22) "R22"
  let r23 = AST.var rt (Register.toRegID R23) "R23"
  let r24 = AST.var rt (Register.toRegID R24) "R24"
  let r25 = AST.var rt (Register.toRegID R25) "R25"
  let r26 = AST.var rt (Register.toRegID R26) "R26"
  let r27 = AST.var rt (Register.toRegID R27) "R27"
  let r28 = AST.var rt (Register.toRegID R28) "R28"
  let r29 = AST.var rt (Register.toRegID R29) "R29"
  let r30 = AST.var rt (Register.toRegID R30) "R30"
  let r31 = AST.var rt (Register.toRegID R31) "R31"
  let f0 = AST.var 64<rt> (Register.toRegID F0) "F0"
  let f1 = AST.var 64<rt> (Register.toRegID F1) "F1"
  let f2 = AST.var 64<rt> (Register.toRegID F2) "F2"
  let f3 = AST.var 64<rt> (Register.toRegID F3) "F3"
  let f4 = AST.var 64<rt> (Register.toRegID F4) "F4"
  let f5 = AST.var 64<rt> (Register.toRegID F5) "F5"
  let f6 = AST.var 64<rt> (Register.toRegID F6) "F6"
  let f7 = AST.var 64<rt> (Register.toRegID F7) "F7"
  let f8 = AST.var 64<rt> (Register.toRegID F8) "F8"
  let f9 = AST.var 64<rt> (Register.toRegID F9) "F9"
  let f10 = AST.var 64<rt> (Register.toRegID F10) "F10"
  let f11 = AST.var 64<rt> (Register.toRegID F11) "F11"
  let f12 = AST.var 64<rt> (Register.toRegID F12) "F12"
  let f13 = AST.var 64<rt> (Register.toRegID F13) "F13"
  let f14 = AST.var 64<rt> (Register.toRegID F14) "F14"
  let f15 = AST.var 64<rt> (Register.toRegID F15) "F15"
  let f16 = AST.var 64<rt> (Register.toRegID F16) "F16"
  let f17 = AST.var 64<rt> (Register.toRegID F17) "F17"
  let f18 = AST.var 64<rt> (Register.toRegID F18) "F18"
  let f19 = AST.var 64<rt> (Register.toRegID F19) "F19"
  let f20 = AST.var 64<rt> (Register.toRegID F20) "F20"
  let f21 = AST.var 64<rt> (Register.toRegID F21) "F21"
  let f22 = AST.var 64<rt> (Register.toRegID F22) "F22"
  let f23 = AST.var 64<rt> (Register.toRegID F23) "F23"
  let f24 = AST.var 64<rt> (Register.toRegID F24) "F24"
  let f25 = AST.var 64<rt> (Register.toRegID F25) "F25"
  let f26 = AST.var 64<rt> (Register.toRegID F26) "F26"
  let f27 = AST.var 64<rt> (Register.toRegID F27) "F27"
  let f28 = AST.var 64<rt> (Register.toRegID F28) "F28"
  let f29 = AST.var 64<rt> (Register.toRegID F29) "F29"
  let f30 = AST.var 64<rt> (Register.toRegID F30) "F30"
  let f31 = AST.var 64<rt> (Register.toRegID F31) "F31"
  let cr00 = AST.var 1<rt> (Register.toRegID CR0_0) "CR0_0"
  let cr01 = AST.var 1<rt> (Register.toRegID CR0_1) "CR0_1"
  let cr02 = AST.var 1<rt> (Register.toRegID CR0_2) "CR0_2"
  let cr03 = AST.var 1<rt> (Register.toRegID CR0_3) "CR0_3"
  let cr10 = AST.var 1<rt> (Register.toRegID CR1_0) "CR1_0"
  let cr11 = AST.var 1<rt> (Register.toRegID CR1_1) "CR1_1"
  let cr12 = AST.var 1<rt> (Register.toRegID CR1_2) "CR1_2"
  let cr13 = AST.var 1<rt> (Register.toRegID CR1_3) "CR1_3"
  let cr20 = AST.var 1<rt> (Register.toRegID CR2_0) "CR2_0"
  let cr21 = AST.var 1<rt> (Register.toRegID CR2_1) "CR2_1"
  let cr22 = AST.var 1<rt> (Register.toRegID CR2_2) "CR2_2"
  let cr23 = AST.var 1<rt> (Register.toRegID CR2_3) "CR2_3"
  let cr30 = AST.var 1<rt> (Register.toRegID CR3_0) "CR3_0"
  let cr31 = AST.var 1<rt> (Register.toRegID CR3_1) "CR3_1"
  let cr32 = AST.var 1<rt> (Register.toRegID CR3_2) "CR3_2"
  let cr33 = AST.var 1<rt> (Register.toRegID CR3_3) "CR3_3"
  let cr40 = AST.var 1<rt> (Register.toRegID CR4_0) "CR4_0"
  let cr41 = AST.var 1<rt> (Register.toRegID CR4_1) "CR4_1"
  let cr42 = AST.var 1<rt> (Register.toRegID CR4_2) "CR4_2"
  let cr43 = AST.var 1<rt> (Register.toRegID CR4_3) "CR4_3"
  let cr50 = AST.var 1<rt> (Register.toRegID CR5_0) "CR5_0"
  let cr51 = AST.var 1<rt> (Register.toRegID CR5_1) "CR5_1"
  let cr52 = AST.var 1<rt> (Register.toRegID CR5_2) "CR5_2"
  let cr53 = AST.var 1<rt> (Register.toRegID CR5_3) "CR5_3"
  let cr60 = AST.var 1<rt> (Register.toRegID CR6_0) "CR6_0"
  let cr61 = AST.var 1<rt> (Register.toRegID CR6_1) "CR6_1"
  let cr62 = AST.var 1<rt> (Register.toRegID CR6_2) "CR6_2"
  let cr63 = AST.var 1<rt> (Register.toRegID CR6_3) "CR6_3"
  let cr70 = AST.var 1<rt> (Register.toRegID CR7_0) "CR7_0"
  let cr71 = AST.var 1<rt> (Register.toRegID CR7_1) "CR7_1"
  let cr72 = AST.var 1<rt> (Register.toRegID CR7_2) "CR7_2"
  let cr73 = AST.var 1<rt> (Register.toRegID CR7_3) "CR7_3"
  let fpscr = AST.var 32<rt> (Register.toRegID FPSCR) "FPSCR"
  let xer = AST.var 32<rt> (Register.toRegID XER) "XER"
  let lr = AST.var rt (Register.toRegID LR) "LR"
  let ctr = AST.var rt (Register.toRegID CTR) "CTR"
  let pvr = AST.var 32<rt> (Register.toRegID PVR) "PVR"
  let res = AST.var 1<rt> (Register.toRegID RES) "RES"

  interface IRegisterFactory with
    member _.GetRegVar id =
      match Register.ofRegID id with
      | Register.R0 -> r0
      | Register.R1 -> r1
      | Register.R2 -> r2
      | Register.R3 -> r3
      | Register.R4 -> r4
      | Register.R5 -> r5
      | Register.R6 -> r6
      | Register.R7 -> r7
      | Register.R8 -> r8
      | Register.R9 -> r9
      | Register.R10 -> r10
      | Register.R11 -> r11
      | Register.R12 -> r12
      | Register.R13 -> r13
      | Register.R14 -> r14
      | Register.R15 -> r15
      | Register.R16 -> r16
      | Register.R17 -> r17
      | Register.R18 -> r18
      | Register.R19 -> r19
      | Register.R20 -> r20
      | Register.R21 -> r21
      | Register.R22 -> r22
      | Register.R23 -> r23
      | Register.R24 -> r24
      | Register.R25 -> r25
      | Register.R26 -> r26
      | Register.R27 -> r27
      | Register.R28 -> r28
      | Register.R29 -> r29
      | Register.R30 -> r30
      | Register.R31 -> r31
      | Register.F0 -> f0
      | Register.F1 -> f1
      | Register.F2 -> f2
      | Register.F3 -> f3
      | Register.F4 -> f4
      | Register.F5 -> f5
      | Register.F6 -> f6
      | Register.F7 -> f7
      | Register.F8 -> f8
      | Register.F9 -> f9
      | Register.F10 -> f10
      | Register.F11 -> f11
      | Register.F12 -> f12
      | Register.F13 -> f13
      | Register.F14 -> f14
      | Register.F15 -> f15
      | Register.F16 -> f16
      | Register.F17 -> f17
      | Register.F18 -> f18
      | Register.F19 -> f19
      | Register.F20 -> f20
      | Register.F21 -> f21
      | Register.F22 -> f22
      | Register.F23 -> f23
      | Register.F24 -> f24
      | Register.F25 -> f25
      | Register.F26 -> f26
      | Register.F27 -> f27
      | Register.F28 -> f28
      | Register.F29 -> f29
      | Register.F30 -> f30
      | Register.F31 -> f31
      | Register.CR0_0 -> cr00
      | Register.CR0_1 -> cr01
      | Register.CR0_2 -> cr02
      | Register.CR0_3 -> cr03
      | Register.CR1_0 -> cr10
      | Register.CR1_1 -> cr11
      | Register.CR1_2 -> cr12
      | Register.CR1_3 -> cr13
      | Register.CR2_0 -> cr20
      | Register.CR2_1 -> cr21
      | Register.CR2_2 -> cr22
      | Register.CR2_3 -> cr23
      | Register.CR3_0 -> cr30
      | Register.CR3_1 -> cr31
      | Register.CR3_2 -> cr32
      | Register.CR3_3 -> cr33
      | Register.CR4_0 -> cr40
      | Register.CR4_1 -> cr41
      | Register.CR4_2 -> cr42
      | Register.CR4_3 -> cr43
      | Register.CR5_0 -> cr50
      | Register.CR5_1 -> cr51
      | Register.CR5_2 -> cr52
      | Register.CR5_3 -> cr53
      | Register.CR6_0 -> cr60
      | Register.CR6_1 -> cr61
      | Register.CR6_2 -> cr62
      | Register.CR6_3 -> cr63
      | Register.CR7_0 -> cr70
      | Register.CR7_1 -> cr71
      | Register.CR7_2 -> cr72
      | Register.CR7_3 -> cr73
      | Register.FPSCR -> fpscr
      | Register.XER -> xer
      | Register.LR -> lr
      | Register.CTR -> ctr
      | Register.PVR -> pvr
      | Register.RES -> res
      | _ -> raise UnhandledRegExprException

    member _.GetRegVar (name: string) =
      match name.ToLowerInvariant () with
      | "r0" -> r0
      | "r1" -> r1
      | "r2" -> r2
      | "r3" -> r3
      | "r4" -> r4
      | "r5" -> r5
      | "r6" -> r6
      | "r7" -> r7
      | "r8" -> r8
      | "r9" -> r9
      | "r10" -> r10
      | "r11" -> r11
      | "r12" -> r12
      | "r13" -> r13
      | "r14" -> r14
      | "r15" -> r15
      | "r16" -> r16
      | "r17" -> r17
      | "r18" -> r18
      | "r19" -> r19
      | "r20" -> r20
      | "r21" -> r21
      | "r22" -> r22
      | "r23" -> r23
      | "r24" -> r24
      | "r25" -> r25
      | "r26" -> r26
      | "r27" -> r27
      | "r28" -> r28
      | "r29" -> r29
      | "r30" -> r30
      | "r31" -> r31
      | "f0" -> f0
      | "f1" -> f1
      | "f2" -> f2
      | "f3" -> f3
      | "f4" -> f4
      | "f5" -> f5
      | "f6" -> f6
      | "f7" -> f7
      | "f8" -> f8
      | "f9" -> f9
      | "f10" -> f10
      | "f11" -> f11
      | "f12" -> f12
      | "f13" -> f13
      | "f14" -> f14
      | "f15" -> f15
      | "f16" -> f16
      | "f17" -> f17
      | "f18" -> f18
      | "f19" -> f19
      | "f20" -> f20
      | "f21" -> f21
      | "f22" -> f22
      | "f23" -> f23
      | "f24" -> f24
      | "f25" -> f25
      | "f26" -> f26
      | "f27" -> f27
      | "f28" -> f28
      | "f29" -> f29
      | "f30" -> f30
      | "f31" -> f31
      | "cr0_0" -> cr00
      | "cr0_1" -> cr01
      | "cr0_2" -> cr02
      | "cr0_3" -> cr03
      | "cr1_0" -> cr10
      | "cr1_1" -> cr11
      | "cr1_2" -> cr12
      | "cr1_3" -> cr13
      | "cr2_0" -> cr20
      | "cr2_1" -> cr21
      | "cr2_2" -> cr22
      | "cr2_3" -> cr23
      | "cr3_0" -> cr30
      | "cr3_1" -> cr31
      | "cr3_2" -> cr32
      | "cr3_3" -> cr33
      | "cr4_0" -> cr40
      | "cr4_1" -> cr41
      | "cr4_2" -> cr42
      | "cr4_3" -> cr43
      | "cr5_0" -> cr50
      | "cr5_1" -> cr51
      | "cr5_2" -> cr52
      | "cr5_3" -> cr53
      | "cr6_0" -> cr60
      | "cr6_1" -> cr61
      | "cr6_2" -> cr62
      | "cr6_3" -> cr63
      | "cr7_0" -> cr70
      | "cr7_1" -> cr71
      | "cr7_2" -> cr72
      | "cr7_3" -> cr73
      | _ -> raise UnhandledRegExprException

    member _.GetPseudoRegVar _id _idx = Terminator.impossible ()

    member _.GetAllRegVars () =
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
         r16
         r17
         r18
         r19
         r20
         r21
         r22
         r23
         r24
         r25
         r26
         r27
         r28
         r29
         r30
         r31
         f0
         f1
         f2
         f3
         f4
         f5
         f6
         f7
         f8
         f9
         f10
         f11
         f12
         f13
         f14
         f15
         f16
         f17
         f18
         f19
         f20
         f21
         f22
         f23
         f24
         f25
         f26
         f27
         f28
         f29
         f30
         f31
         cr00
         cr01
         cr02
         cr03
         cr10
         cr11
         cr12
         cr13
         cr20
         cr21
         cr22
         cr23
         cr30
         cr32
         cr32
         cr33
         cr40
         cr41
         cr42
         cr43
         cr50
         cr51
         cr52
         cr53
         cr60
         cr61
         cr62
         cr63
         cr70
         cr71
         cr72
         cr73 |]

    member _.GetGeneralRegVars () =
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
         r16
         r17
         r18
         r19
         r20
         r21
         r22
         r23
         r24
         r25
         r26
         r27
         r28
         r29
         r30
         r31 |]

    member _.GetRegisterID expr =
      match expr with
      | Var (_, id, _, _) -> id
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name =
      Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases rid =
      [| rid |]

    member _.GetRegString rid =
      Register.ofRegID rid |> Register.toString

    member this.GetAllRegStrings () =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars ()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegString)

    member _.GetRegType rid =
      if rid < 0x40<RegisterID.T> then WordSize.toRegType wordSize
      else 4<rt>

    member _.ProgramCounter = Terminator.futureFeature ()

    member _.StackPointer =
      R1 |> Register.toRegID |> Some

    member _.FramePointer = None

    member _.IsProgramCounter _ = false

    member _.IsStackPointer rid =
      Register.toRegID R1 = rid

    member _.IsFramePointer _ = false

// vim: set tw=80 sts=2 sw=2:
