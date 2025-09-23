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

/// Represents a factory for accessing various MIPS register variables.
type RegisterFactory(wordSize) =
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

  let f0 = AST.var rt (Register.toRegID F0) "F0"
  let f1 = AST.var rt (Register.toRegID F1) "F1"
  let f2 = AST.var rt (Register.toRegID F2) "F2"
  let f3 = AST.var rt (Register.toRegID F3) "F3"
  let f4 = AST.var rt (Register.toRegID F4) "F4"
  let f5 = AST.var rt (Register.toRegID F5) "F5"
  let f6 = AST.var rt (Register.toRegID F6) "F6"
  let f7 = AST.var rt (Register.toRegID F7) "F7"
  let f8 = AST.var rt (Register.toRegID F8) "F8"
  let f9 = AST.var rt (Register.toRegID F9) "F9"
  let f10 = AST.var rt (Register.toRegID F10) "F10"
  let f11 = AST.var rt (Register.toRegID F11) "F11"
  let f12 = AST.var rt (Register.toRegID F12) "F12"
  let f13 = AST.var rt (Register.toRegID F13) "F13"
  let f14 = AST.var rt (Register.toRegID F14) "F14"
  let f15 = AST.var rt (Register.toRegID F15) "F15"
  let f16 = AST.var rt (Register.toRegID F16) "F16"
  let f17 = AST.var rt (Register.toRegID F17) "F17"
  let f18 = AST.var rt (Register.toRegID F18) "F18"
  let f19 = AST.var rt (Register.toRegID F19) "F19"
  let f20 = AST.var rt (Register.toRegID F20) "F20"
  let f21 = AST.var rt (Register.toRegID F21) "F21"
  let f22 = AST.var rt (Register.toRegID F22) "F22"
  let f23 = AST.var rt (Register.toRegID F23) "F23"
  let f24 = AST.var rt (Register.toRegID F24) "F24"
  let f25 = AST.var rt (Register.toRegID F25) "F25"
  let f26 = AST.var rt (Register.toRegID F26) "F26"
  let f27 = AST.var rt (Register.toRegID F27) "F27"
  let f28 = AST.var rt (Register.toRegID F28) "F28"
  let f29 = AST.var rt (Register.toRegID F29) "F29"
  let f30 = AST.var rt (Register.toRegID F30) "F30"
  let f31 = AST.var rt (Register.toRegID F31) "F31"

  let hi = AST.var rt (Register.toRegID HI) "HI"
  let lo = AST.var rt (Register.toRegID LO) "LO"
  let pc = AST.pcvar rt "PC"
  let nextPC = AST.var rt (Register.toRegID NPC) "nPC"
  let llbit = AST.var 1<rt> (Register.toRegID LLBit) "LLBit"
  let fcsr = AST.var 32<rt> (Register.toRegID FCSR) "FCSR"
  let fir = AST.var 32<rt> (Register.toRegID FIR) "FIR"

  interface IRegisterFactory with
    member _.GetRegVar id =
      match Register.ofRegID id with
      | R.HI  -> hi
      | R.LO  -> lo
      | R.PC  -> pc
      | R.NPC  -> nextPC
      | R.LLBit -> llbit
      | R.R0  -> r0
      | R.R1  -> r1
      | R.R2  -> r2
      | R.R3  -> r3
      | R.R4  -> r4
      | R.R5  -> r5
      | R.R6  -> r6
      | R.R7  -> r7
      | R.R8  -> r8
      | R.R9  -> r9
      | R.R10 -> r10
      | R.R11 -> r11
      | R.R12 -> r12
      | R.R13 -> r13
      | R.R14 -> r14
      | R.R15 -> r15
      | R.R16 -> r16
      | R.R17 -> r17
      | R.R18 -> r18
      | R.R19 -> r19
      | R.R20 -> r20
      | R.R21 -> r21
      | R.R22 -> r22
      | R.R23 -> r23
      | R.R24 -> r24
      | R.R25 -> r25
      | R.R26 -> r26
      | R.R27 -> r27
      | R.R28 -> r28
      | R.R29 -> r29
      | R.R30 -> r30
      | R.R31 -> r31
      | R.F0  -> f0
      | R.F1  -> f1
      | R.F2  -> f2
      | R.F3  -> f3
      | R.F4  -> f4
      | R.F5  -> f5
      | R.F6  -> f6
      | R.F7  -> f7
      | R.F8  -> f8
      | R.F9  -> f9
      | R.F10 -> f10
      | R.F11 -> f11
      | R.F12 -> f12
      | R.F13 -> f13
      | R.F14 -> f14
      | R.F15 -> f15
      | R.F16 -> f16
      | R.F17 -> f17
      | R.F18 -> f18
      | R.F19 -> f19
      | R.F20 -> f20
      | R.F21 -> f21
      | R.F22 -> f22
      | R.F23 -> f23
      | R.F24 -> f24
      | R.F25 -> f25
      | R.F26 -> f26
      | R.F27 -> f27
      | R.F28 -> f28
      | R.F29 -> f29
      | R.F30 -> f30
      | R.F31 -> f31
      | R.FCSR -> fcsr
      | R.FIR -> fir
      | _ -> raise InvalidRegisterException

    member this.GetRegVar name =
      Register.ofString name wordSize
      |> Register.toRegID
      |> (this :> IRegisterFactory).GetRegVar

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

    member _.GetAllRegVars() =
      [| hi
         lo
         pc
         r0
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
         f31 |]

    member _.GetGeneralRegVars() =
      [| hi
         lo
         pc
         r0
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
      | PCVar _ -> Register.toRegID PC
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name =
      Register.ofString name wordSize |> Register.toRegID

    member _.GetRegisterIDAliases rid =
      [| rid |]

    member _.GetRegisterName rid =
      Register.toString (Register.ofRegID rid) wordSize

    member this.GetAllRegisterNames() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegisterName)

    member _.GetRegType _rid =
      WordSize.toRegType wordSize

    member _.ProgramCounter =
      PC |> Register.toRegID

    member _.StackPointer =
      R29 |> Register.toRegID |> Some

    member _.FramePointer =
      R30 |> Register.toRegID |> Some

    member this.IsProgramCounter regid =
      (this :> IRegisterFactory).ProgramCounter = regid

    member _.IsStackPointer regid =
      Register.toRegID R29 = regid

    member _.IsFramePointer regid =
      Register.toRegID R30 = regid
