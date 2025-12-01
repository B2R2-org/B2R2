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

namespace B2R2.FrontEnd.PPC

open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR
open type Register

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.PPC.Tests")>]
do ()

/// Represents a factory for accessing various PPC register variables.
type RegisterFactory(wordSize: WordSize) =
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
  let cr0 = AST.var 4<rt> (Register.toRegID CR0) "CR0"
  let cr1 = AST.var 4<rt> (Register.toRegID CR1) "CR1"
  let cr2 = AST.var 4<rt> (Register.toRegID CR2) "CR2"
  let cr3 = AST.var 4<rt> (Register.toRegID CR3) "CR3"
  let cr4 = AST.var 4<rt> (Register.toRegID CR4) "CR4"
  let cr5 = AST.var 4<rt> (Register.toRegID CR5) "CR5"
  let cr6 = AST.var 4<rt> (Register.toRegID CR6) "CR6"
  let cr7 = AST.var 4<rt> (Register.toRegID CR7) "CR7"
  let xer = AST.var 64<rt> (Register.toRegID XER) "XER"
  let lr = AST.var 64<rt> (Register.toRegID LR) "LR"
  let ctr = AST.var 64<rt> (Register.toRegID CTR) "CTR"
  let tar = AST.var 64<rt> (Register.toRegID TAR) "TAR"

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
      | Register.CR0 -> cr0
      | Register.CR1 -> cr1
      | Register.CR2 -> cr2
      | Register.CR3 -> cr3
      | Register.CR4 -> cr4
      | Register.CR5 -> cr5
      | Register.CR6 -> cr6
      | Register.CR7 -> cr7
      | Register.XER -> xer
      | Register.LR -> lr
      | Register.CTR -> ctr
      | Register.TAR -> tar
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
      | "cr0" -> cr0
      | "cr1" -> cr1
      | "cr2" -> cr2
      | "cr3" -> cr3
      | "cr4" -> cr4
      | "cr5" -> cr5
      | "cr6" -> cr6
      | "cr7" -> cr7
      | "xer" -> xer
      | "lr" -> lr
      | "ctr" -> ctr
      | "tar" -> tar
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
         cr0
         cr1
         cr2
         cr3
         cr4
         cr5
         cr6
         cr7
         xer 
         lr
         ctr 
         tar |]

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
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name =
      Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases rid =
      [| rid |]

    member _.GetRegisterName rid =
      Register.ofRegID rid |> Register.toString

    member this.GetAllRegisterNames() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegisterName)

    member _.GetRegType rid =
      if rid < 0x40<RegisterID.T> then WordSize.toRegType wordSize
      else 4<rt>

    member _.ProgramCounter = Terminator.futureFeature ()

    member _.StackPointer =
      R0 |> Register.toRegID |> Some

    member _.FramePointer = None

    member _.IsProgramCounter _ = false

    member _.IsStackPointer rid =
      Register.toRegID R1 = rid

    member _.IsFramePointer _ = false
