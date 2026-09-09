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

namespace B2R2.FrontEnd.Alpha

open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.Alpha.Tests")>]
do ()

/// Represents a factory for accessing various Alpha register variables. Every
/// register is a quadword wide, the floating-point ones included, because what
/// a floating-point register holds is the sixty-four bits of a T_floating
/// number whatever format an instruction reads it in.
type RegisterFactory(isa: ISA) =
  let r0 = AST.var 64<rt> (Register.toRegID Register.R0) "r0"
  let r1 = AST.var 64<rt> (Register.toRegID Register.R1) "r1"
  let r2 = AST.var 64<rt> (Register.toRegID Register.R2) "r2"
  let r3 = AST.var 64<rt> (Register.toRegID Register.R3) "r3"
  let r4 = AST.var 64<rt> (Register.toRegID Register.R4) "r4"
  let r5 = AST.var 64<rt> (Register.toRegID Register.R5) "r5"
  let r6 = AST.var 64<rt> (Register.toRegID Register.R6) "r6"
  let r7 = AST.var 64<rt> (Register.toRegID Register.R7) "r7"
  let r8 = AST.var 64<rt> (Register.toRegID Register.R8) "r8"
  let r9 = AST.var 64<rt> (Register.toRegID Register.R9) "r9"
  let r10 = AST.var 64<rt> (Register.toRegID Register.R10) "r10"
  let r11 = AST.var 64<rt> (Register.toRegID Register.R11) "r11"
  let r12 = AST.var 64<rt> (Register.toRegID Register.R12) "r12"
  let r13 = AST.var 64<rt> (Register.toRegID Register.R13) "r13"
  let r14 = AST.var 64<rt> (Register.toRegID Register.R14) "r14"
  let r15 = AST.var 64<rt> (Register.toRegID Register.R15) "r15"
  let r16 = AST.var 64<rt> (Register.toRegID Register.R16) "r16"
  let r17 = AST.var 64<rt> (Register.toRegID Register.R17) "r17"
  let r18 = AST.var 64<rt> (Register.toRegID Register.R18) "r18"
  let r19 = AST.var 64<rt> (Register.toRegID Register.R19) "r19"
  let r20 = AST.var 64<rt> (Register.toRegID Register.R20) "r20"
  let r21 = AST.var 64<rt> (Register.toRegID Register.R21) "r21"
  let r22 = AST.var 64<rt> (Register.toRegID Register.R22) "r22"
  let r23 = AST.var 64<rt> (Register.toRegID Register.R23) "r23"
  let r24 = AST.var 64<rt> (Register.toRegID Register.R24) "r24"
  let r25 = AST.var 64<rt> (Register.toRegID Register.R25) "r25"
  let r26 = AST.var 64<rt> (Register.toRegID Register.R26) "r26"
  let r27 = AST.var 64<rt> (Register.toRegID Register.R27) "r27"
  let r28 = AST.var 64<rt> (Register.toRegID Register.R28) "r28"
  let r29 = AST.var 64<rt> (Register.toRegID Register.R29) "r29"
  let r30 = AST.var 64<rt> (Register.toRegID Register.R30) "r30"
  let r31 = AST.var 64<rt> (Register.toRegID Register.R31) "r31"
  let f0 = AST.var 64<rt> (Register.toRegID Register.F0) "f0"
  let f1 = AST.var 64<rt> (Register.toRegID Register.F1) "f1"
  let f2 = AST.var 64<rt> (Register.toRegID Register.F2) "f2"
  let f3 = AST.var 64<rt> (Register.toRegID Register.F3) "f3"
  let f4 = AST.var 64<rt> (Register.toRegID Register.F4) "f4"
  let f5 = AST.var 64<rt> (Register.toRegID Register.F5) "f5"
  let f6 = AST.var 64<rt> (Register.toRegID Register.F6) "f6"
  let f7 = AST.var 64<rt> (Register.toRegID Register.F7) "f7"
  let f8 = AST.var 64<rt> (Register.toRegID Register.F8) "f8"
  let f9 = AST.var 64<rt> (Register.toRegID Register.F9) "f9"
  let f10 = AST.var 64<rt> (Register.toRegID Register.F10) "f10"
  let f11 = AST.var 64<rt> (Register.toRegID Register.F11) "f11"
  let f12 = AST.var 64<rt> (Register.toRegID Register.F12) "f12"
  let f13 = AST.var 64<rt> (Register.toRegID Register.F13) "f13"
  let f14 = AST.var 64<rt> (Register.toRegID Register.F14) "f14"
  let f15 = AST.var 64<rt> (Register.toRegID Register.F15) "f15"
  let f16 = AST.var 64<rt> (Register.toRegID Register.F16) "f16"
  let f17 = AST.var 64<rt> (Register.toRegID Register.F17) "f17"
  let f18 = AST.var 64<rt> (Register.toRegID Register.F18) "f18"
  let f19 = AST.var 64<rt> (Register.toRegID Register.F19) "f19"
  let f20 = AST.var 64<rt> (Register.toRegID Register.F20) "f20"
  let f21 = AST.var 64<rt> (Register.toRegID Register.F21) "f21"
  let f22 = AST.var 64<rt> (Register.toRegID Register.F22) "f22"
  let f23 = AST.var 64<rt> (Register.toRegID Register.F23) "f23"
  let f24 = AST.var 64<rt> (Register.toRegID Register.F24) "f24"
  let f25 = AST.var 64<rt> (Register.toRegID Register.F25) "f25"
  let f26 = AST.var 64<rt> (Register.toRegID Register.F26) "f26"
  let f27 = AST.var 64<rt> (Register.toRegID Register.F27) "f27"
  let f28 = AST.var 64<rt> (Register.toRegID Register.F28) "f28"
  let f29 = AST.var 64<rt> (Register.toRegID Register.F29) "f29"
  let f30 = AST.var 64<rt> (Register.toRegID Register.F30) "f30"
  let f31 = AST.var 64<rt> (Register.toRegID Register.F31) "f31"
  let pc = AST.pcvar 64<rt> "pc"
  let fpcr = AST.var 64<rt> (Register.toRegID Register.FPCR) "fpcr"
  let uniq = AST.var 64<rt> (Register.toRegID Register.UNIQ) "uniq"
  let exMonAddr =
    AST.var 64<rt> (Register.toRegID Register.ExMonAddr) "exmonaddr"
  let exMonVal =
    AST.var 64<rt> (Register.toRegID Register.ExMonVal) "exmonval"

  interface IRegisterFactory with
    member _.ISA = isa

    member _.ProgramCounter = Register.PC |> Register.toRegID

    member _.StackPointer = Register.R30 |> Register.toRegID |> Some

    member _.FramePointer = Register.R15 |> Register.toRegID |> Some

    member _.GetRegVar rid =
      match Register.ofRegID rid with
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
      | Register.PC -> pc
      | Register.FPCR -> fpcr
      | Register.UNIQ -> uniq
      | Register.ExMonAddr -> exMonAddr
      | Register.ExMonVal -> exMonVal
      | _ -> raise InvalidRegisterException

    member _.GetRegVar(name: string) =
      match name.ToLowerInvariant() with
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
      | "pc" -> pc
      | "fpcr" -> fpcr
      | "uniq" -> uniq
      | "exmonaddr" -> exMonAddr
      | "exmonval" -> exMonVal
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
         pc
         fpcr
         uniq
         exMonAddr
         exMonVal |]

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
      | Var(_, id, _, _) -> id
      | PCVar _ -> Register.toRegID Register.PC
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name = Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases rid = [| rid |]

    member _.GetRegisterName rid = Register.ofRegID rid |> Register.toString

    member this.GetAllRegisterNames() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegisterName)

    member _.GetRegType _ = 64<rt>

    member _.IsProgramCounter rid = Register.toRegID Register.PC = rid

    member _.IsStackPointer rid = Register.toRegID Register.R30 = rid

    member _.IsFramePointer rid = Register.toRegID Register.R15 = rid

// vim: set tw=80 sts=2 sw=2:
