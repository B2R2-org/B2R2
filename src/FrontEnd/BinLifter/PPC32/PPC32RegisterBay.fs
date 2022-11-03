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

type PPC32RegisterBay internal (wordSize, r: RegExprs) =
  inherit RegisterBay ()

  override __.GetAllRegExprs () =
    [ r.R0; r.R1; r.R2; r.R3; r.R4; r.R5; r.R6; r.R7; r.R8; r.R9; r.R10; r.R11
      r.R12; r.R13; r.R14; r.R15; r.R16; r.R17; r.R18; r.R19; r.R20; r.R21
      r.R22; r.R23; r.R24; r.R25; r.R26; r.R27; r.R28; r.R29; r.R30; r.R31
      r.F0; r.F1; r.F2; r.F3; r.F4; r.F5; r.F6; r.F7; r.F8; r.F9; r.F10; r.F11
      r.F12; r.F13; r.F14; r.F15; r.F16; r.F17; r.F18; r.F19; r.F20; r.F21
      r.F22; r.F23; r.F24; r.F25; r.F26; r.F27; r.F28; r.F29; r.F30; r.F31
      r.CR0; r.CR1; r.CR2; r.CR3; r.CR4; r.CR5; r.CR6; r.CR7 ]

  override __.GetAllRegNames () =
    __.GetAllRegExprs ()
    |> List.map (__.RegIDFromRegExpr >> __.RegIDToString)

  override __.GetGeneralRegExprs () =
    [ r.R0; r.R1; r.R2; r.R3; r.R4; r.R5; r.R6; r.R7; r.R8; r.R9; r.R10; r.R11
      r.R12; r.R13; r.R14; r.R15; r.R16; r.R17; r.R18; r.R19; r.R20; r.R21
      r.R22; r.R23; r.R24; r.R25; r.R26; r.R27; r.R28; r.R29; r.R30; r.R31 ]

  override __.RegIDFromRegExpr (e) =
    match e.E with
    | Var (_, id, _ ,_) -> id
    | _ -> raise InvalidRegisterException

  override __.RegIDToRegExpr (id) =
    Register.ofRegID id |> r.GetRegVar

  override __.StrToRegExpr s =
    match s.ToLowerInvariant () with
    | "r0" -> r.R0
    | "r1" -> r.R1
    | "r2" -> r.R2
    | "r3" -> r.R3
    | "r4" -> r.R4
    | "r5" -> r.R5
    | "r6" -> r.R6
    | "r7" -> r.R7
    | "r8" -> r.R8
    | "r9" -> r.R9
    | "r10" -> r.R10
    | "r11" -> r.R11
    | "r12" -> r.R12
    | "r13" -> r.R13
    | "r14" -> r.R14
    | "r15" -> r.R15
    | "r16" -> r.R16
    | "r17" -> r.R17
    | "r18" -> r.R18
    | "r19" -> r.R19
    | "r20" -> r.R20
    | "r21" -> r.R21
    | "r22" -> r.R22
    | "r23" -> r.R23
    | "r24" -> r.R24
    | "r25" -> r.R25
    | "r26" -> r.R26
    | "r27" -> r.R27
    | "r28" -> r.R28
    | "r29" -> r.R29
    | "r30" -> r.R30
    | "r31" -> r.R31
    | "f0" -> r.F0
    | "f1" -> r.F1
    | "f2" -> r.F2
    | "f3" -> r.F3
    | "f4" -> r.F4
    | "f5" -> r.F5
    | "f6" -> r.F6
    | "f7" -> r.F7
    | "f8" -> r.F8
    | "f9" -> r.F9
    | "f10" -> r.F10
    | "f11" -> r.F11
    | "f12" -> r.F12
    | "f13" -> r.F13
    | "f14" -> r.F14
    | "f15" -> r.F15
    | "f16" -> r.F16
    | "f17" -> r.F17
    | "f18" -> r.F18
    | "f19" -> r.F19
    | "f20" -> r.F20
    | "f21" -> r.F21
    | "f22" -> r.F22
    | "f23" -> r.F23
    | "f24" -> r.F24
    | "f25" -> r.F25
    | "f26" -> r.F26
    | "f27" -> r.F27
    | "f28" -> r.F28
    | "f29" -> r.F29
    | "f30" -> r.F30
    | "f31" -> r.F31
    | "cr0" -> r.CR0
    | "cr1" -> r.CR1
    | "cr2" -> r.CR2
    | "cr3" -> r.CR3
    | "cr4" -> r.CR4
    | "cr5" -> r.CR5
    | "cr6" -> r.CR6
    | "cr7" -> r.CR7
    | _ -> raise UnhandledRegExprException

  override __.RegIDFromString str =
    Register.ofString str |> Register.toRegID

  override __.RegIDToString rid =
    Register.ofRegID rid |> Register.toString

  override __.RegIDToRegType rid =
    if rid < 0x40<RegisterID.T> then WordSize.toRegType wordSize
    else 4<rt>

  override __.GetRegisterAliases rid =
    [| rid |]

  override __.ProgramCounter = Utils.futureFeature ()

  override __.StackPointer =
    Register.R1 |> Register.toRegID |> Some

  override __.FramePointer = None

  override __.IsProgramCounter _ = false

  override __.IsStackPointer rid =
    (__.StackPointer |> Option.get) = rid

  override __.IsFramePointer _ = false
