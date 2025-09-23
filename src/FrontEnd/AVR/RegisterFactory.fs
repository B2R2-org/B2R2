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

open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR
open type Register

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.AVR.Tests")>]
do ()

/// Represents a factory for accessing various AVR register variables.
type RegisterFactory(wordSize) =
  let regType = WordSize.toRegType wordSize

  let reg16 reg1 reg2 = AST.concat reg1 reg2

  let r0 = AST.var regType (Register.toRegID R0) "R0"
  let r1 = AST.var regType (Register.toRegID R1) "R1"
  let r2 = AST.var regType (Register.toRegID R2) "R2"
  let r3 = AST.var regType (Register.toRegID R3) "R3"
  let r4 = AST.var regType (Register.toRegID R4) "R4"
  let r5 = AST.var regType (Register.toRegID R5) "R5"
  let r6 = AST.var regType (Register.toRegID R6) "R6"
  let r7 = AST.var regType (Register.toRegID R7) "R7"
  let r8 = AST.var regType (Register.toRegID R8) "R8"
  let r9 = AST.var regType (Register.toRegID R9) "R9"
  let r10 = AST.var regType (Register.toRegID R10) "R10"
  let r11 = AST.var regType (Register.toRegID R11) "R11"
  let r12 = AST.var regType (Register.toRegID R12) "R12"
  let r13 = AST.var regType (Register.toRegID R13) "R13"
  let r14 = AST.var regType (Register.toRegID R14) "R14"
  let r15 = AST.var regType (Register.toRegID R15) "R15"
  let r16 = AST.var regType (Register.toRegID R16) "R16"
  let r17 = AST.var regType (Register.toRegID R17) "R17"
  let r18 = AST.var regType (Register.toRegID R18) "R18"
  let r19 = AST.var regType (Register.toRegID R19) "R19"
  let r20 = AST.var regType (Register.toRegID R20) "R20"
  let r21 = AST.var regType (Register.toRegID R21) "R21"
  let r22 = AST.var regType (Register.toRegID R22) "R22"
  let r23 = AST.var regType (Register.toRegID R23) "R23"
  let r24 = AST.var regType (Register.toRegID R24) "R24"
  let r25 = AST.var regType (Register.toRegID R25) "R25"
  let r26 = AST.var regType (Register.toRegID R26) "R26"
  let r27 = AST.var regType (Register.toRegID R27) "R27"
  let r28 = AST.var regType (Register.toRegID R28) "R28"
  let r29 = AST.var regType (Register.toRegID R29) "R29"
  let r30 = AST.var regType (Register.toRegID R30) "R30"
  let r31 = AST.var regType (Register.toRegID R31) "R31"

  let x = reg16 r27 r26
  let y = reg16 r29 r28
  let z = reg16 r31 r30
  let iF = AST.var 1<rt> (Register.toRegID IF) "IF"
  let tF = AST.var 1<rt> (Register.toRegID TF) "TF"
  let hF = AST.var 1<rt> (Register.toRegID HF) "HF"
  let sF = AST.var 1<rt> (Register.toRegID SF) "SF"
  let vF = AST.var 1<rt> (Register.toRegID VF) "VF"
  let nF = AST.var 1<rt> (Register.toRegID NF) "NF"
  let zF = AST.var 1<rt> (Register.toRegID ZF) "ZF"
  let cF = AST.var 1<rt> (Register.toRegID CF) "CF"
  let pc = AST.pcvar 16<rt> "PC"
  let sp = AST.var 16<rt> (Register.toRegID SP) "SP"

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
      | Register.X -> x
      | Register.Y -> y
      | Register.Z -> z
      | Register.IF -> iF
      | Register.TF -> tF
      | Register.HF -> hF
      | Register.SF -> sF
      | Register.VF -> vF
      | Register.NF -> nF
      | Register.ZF -> zF
      | Register.CF  -> cF
      | Register.PC -> pc
      | Register.SP -> sp
      | _ -> raise InvalidRegisterException

    member _.GetRegVar(_: string): Expr = Terminator.futureFeature ()

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

    member _.GetAllRegVars() = Terminator.futureFeature ()

    member _.GetGeneralRegVars() = Terminator.futureFeature ()

    member _.GetRegisterID expr =
      match expr with
      | Var(_, id, _, _) -> id (* TODO *)
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID(_: string): RegisterID = Terminator.futureFeature ()

    member _.GetRegisterIDAliases _ = Terminator.futureFeature ()

    member _.GetRegisterName _ = Terminator.futureFeature ()

    member _.GetAllRegisterNames() = Terminator.futureFeature ()

    member _.GetRegType _ = Terminator.futureFeature ()

    member _.ProgramCounter = Terminator.futureFeature ()

    member _.StackPointer = Terminator.futureFeature ()

    member _.FramePointer = Terminator.futureFeature ()

    member _.IsProgramCounter _ = Terminator.futureFeature ()

    member _.IsStackPointer _ = Terminator.futureFeature ()

    member _.IsFramePointer _ = Terminator.futureFeature ()
