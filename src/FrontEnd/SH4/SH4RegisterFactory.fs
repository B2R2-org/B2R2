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

namespace B2R2.FrontEnd.SH4

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type SH4RegisterFactory (r: RegExprs) =
  inherit RegisterFactory ()

  override _.GetAllRegExprs () =
    [ r.R0; r.R1; r.R2; r.R3; r.R4; r.R5; r.R6; r.R7; r.R8; r.R9; r.R10; r.R11
      r.R12; r.R13; r.R14; r.R15; r.PC ]

  override this.GetAllRegNames () =
    this.GetAllRegExprs ()
    |> List.map (this.RegIDFromRegExpr >> this.RegIDToString)

  override _.GetGeneralRegExprs () =
    [ r.R0; r.R1; r.R2; r.R3; r.R4; r.R5; r.R6; r.R7; r.R8; r.R9; r.R10; r.R11
      r.R12; r.R13; r.R14; r.R15 ]

  override _.RegIDFromRegExpr (e) =
    match e.E with
    | Var (_, id, _) -> id
    | PCVar (_) -> Register.toRegID Register.PC
    | _ -> raise InvalidRegisterException

  override _.RegIDToRegExpr id =
    Register.ofRegID id |> r.GetRegVar

  override _.StrToRegExpr s =
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
    | "pc" -> r.PC
    | _ -> raise UnhandledRegExprException

  override _.RegIDFromString str =
    Register.ofString str |> Register.toRegID

  override _.RegIDToString rid =
    Register.ofRegID rid |> Register.toString

  override _.RegIDToRegType rid =
    Register.ofRegID rid |> Register.toRegType

  override _.GetRegisterAliases _ =
    Terminator.futureFeature ()

  override _.ProgramCounter =
    Register.PC |> Register.toRegID

  override _.StackPointer =
    Register.R15 |> Register.toRegID |> Some

  override _.FramePointer =
    Register.R14 |> Register.toRegID |> Some

  override this.IsProgramCounter rid =
    this.ProgramCounter = rid

  override this.IsStackPointer rid =
    (this.StackPointer |> Option.get) = rid

  override this.IsFramePointer rid =
    (this.FramePointer |> Option.get) = rid
