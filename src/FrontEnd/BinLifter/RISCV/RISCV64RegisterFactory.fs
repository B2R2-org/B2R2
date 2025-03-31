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

namespace B2R2.FrontEnd.BinLifter.RISCV

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.Register
open B2R2.BinIR.LowUIR

type RISCV64RegisterFactory (wordSize, r: RegExprs) =
  inherit RegisterFactory ()

  override __.GetAllRegExprs () =
    [ r.X0; r.X1; r.X2; r.X3; r.X4; r.X5; r.X6; r.X7; r.X8; r.X9; r.X10; r.X11
      r.X12; r.X13; r.X14; r.X15; r.X16; r.X17; r.X18; r.X19; r.X20; r.X21
      r.X22; r.X23; r.X24; r.X25; r.X26; r.X27; r.X28; r.X29; r.X30; r.X31
      r.F0; r.F1; r.F2; r.F3; r.F4; r.F5; r.F6; r.F7; r.F8; r.F9; r.F10; r.F11
      r.F12; r.F13; r.F14; r.F15; r.F16; r.F17; r.F18; r.F19; r.F20; r.F21
      r.F22; r.F23; r.F24; r.F25; r.F26; r.F27; r.F28; r.F29; r.F30; r.F31
      r.PC; r.FCSR ]

  override __.GetAllRegNames () =
    __.GetAllRegExprs ()
    |> List.map (__.RegIDFromRegExpr >> __.RegIDToString)

  override __.GetGeneralRegExprs () =
    [ r.X0; r.X1; r.X2; r.X3; r.X4; r.X5; r.X6; r.X7; r.X8; r.X9; r.X10; r.X11
      r.X12; r.X13; r.X14; r.X15; r.X16; r.X17; r.X18; r.X19; r.X20; r.X21
      r.X22; r.X23; r.X24; r.X25; r.X26; r.X27; r.X28; r.X29; r.X30; r.X31 ]

  override __.RegIDFromRegExpr (e) =
    match e.E with
    | Var (_, id, _) -> id
    | PCVar (_) -> RISCV64Register.ID RISCV64.PC
    | _ -> raise InvalidRegisterException

  override __.RegIDToRegExpr (id) =
    RISCV64Register.Get id |> r.GetRegVar

  override __.StrToRegExpr s =
    match s.ToLowerInvariant () with
    | "x0" -> r.X0
    | "x1" -> r.X1
    | "x2" -> r.X2
    | "x3" -> r.X3
    | "x4" -> r.X4
    | "x5" -> r.X5
    | "x6" -> r.X6
    | "x7" -> r.X7
    | "x8" -> r.X8
    | "x9" -> r.X9
    | "x10" -> r.X10
    | "x11" -> r.X11
    | "x12" -> r.X12
    | "x13" -> r.X13
    | "x14" -> r.X14
    | "x15" -> r.X15
    | "x16" -> r.X16
    | "x17" -> r.X17
    | "x18" -> r.X18
    | "x19" -> r.X19
    | "x20" -> r.X20
    | "x21" -> r.X21
    | "x22" -> r.X22
    | "x23" -> r.X23
    | "x24" -> r.X24
    | "x25" -> r.X25
    | "x26" -> r.X26
    | "x27" -> r.X27
    | "x28" -> r.X28
    | "x29" -> r.X29
    | "x30" -> r.X30
    | "x31" -> r.X31
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
    | "pc" -> r.PC
    | "fcsr" -> r.FCSR
    | _ -> raise UnhandledRegExprException

  override __.RegIDFromString str =
    RISCV64Register.Get str |> RISCV64Register.ID

  override __.RegIDToString rid =
    RISCV64Register.Get rid |> RISCV64Register.String

  override __.RegIDToRegType rid =
    RISCV64Register.Get rid |> Register.toRegType wordSize

  override __.GetRegisterAliases _rid =
    Utils.futureFeature ()

  override __.ProgramCounter =
    RISCV64.PC |> RISCV64Register.ID

  override __.StackPointer =
    RISCV64.X30 |> RISCV64Register.ID |> Some

  override __.FramePointer =
    RISCV64.X29 |> RISCV64Register.ID |> Some

  override __.IsProgramCounter rid =
    __.ProgramCounter = rid

  override __.IsStackPointer rid =
    (__.StackPointer |> Option.get) = rid

  override __.IsFramePointer rid =
    (__.FramePointer |> Option.get) = rid
