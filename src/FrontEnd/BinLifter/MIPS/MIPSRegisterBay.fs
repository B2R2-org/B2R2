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

namespace B2R2.FrontEnd.BinLifter.MIPS

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type MIPSRegisterBay internal (wordSize, r: RegExprs) =
  inherit RegisterBay ()

  override __.GetAllRegExprs () =
    [ r.HI; r.LO; r.PC; r.R0; r.R1; r.R2; r.R3; r.R4; r.R5; r.R6; r.R7; r.R8;
      r.R9; r.R10; r.R11; r.R12; r.R13; r.R14; r.R15; r.R16; r.R17; r.R18;
      r.R19; r.R20; r.R21; r.R22; r.R23; r.R24; r.R25; r.R26; r.R27; r.R28;
      r.R29; r.R30; r.R31; r.F0; r.F1; r.F2; r.F3; r.F4; r.F5; r.F6; r.F7; r.F8;
      r.F9; r.F10; r.F11; r.F12; r.F13; r.F14; r.F15; r.F16; r.F17; r.F18;
      r.F19; r.F20; r.F21; r.F22; r.F23; r.F24; r.F25; r.F26; r.F27; r.F28;
      r.F29; r.F30; r.F31 ]

  override __.GetAllRegNames () =
    __.GetAllRegExprs ()
    |> List.map (__.RegIDFromRegExpr >> __.RegIDToString)

  override __.GetGeneralRegExprs () =
    [ r.HI; r.LO; r.PC; r.R0; r.R1; r.R2; r.R3; r.R4; r.R5; r.R6; r.R7; r.R8;
      r.R9; r.R10; r.R11; r.R12; r.R13; r.R14; r.R15; r.R16; r.R17; r.R18;
      r.R19; r.R20; r.R21; r.R22; r.R23; r.R24; r.R25; r.R26; r.R27; r.R28;
      r.R29; r.R30; r.R31 ]

  override __.RegIDFromRegExpr (e) =
    match e.E with
    | Var (_,id, _,_) -> id
    | PCVar _ -> Register.toRegID Register.PC
    | _ -> failwith "not a register expression"

  override __.RegIDToRegExpr (id) =
    Register.ofRegID id |> r.GetRegVar

  override __.StrToRegExpr s =
    match s with
    | "HI" -> r.HI
    | "LO" -> r.LO
    | "PC" -> r.PC
    | "R0" -> r.R0
    | "R1" -> r.R1
    | "R2" -> r.R2
    | "R3" -> r.R3
    | "R4" -> r.R4
    | "R5" -> r.R5
    | "R6" -> r.R6
    | "R7" -> r.R7
    | "R8" -> r.R8
    | "R9" -> r.R9
    | "R10" -> r.R10
    | "R11" -> r.R11
    | "R12" -> r.R12
    | "R13" -> r.R13
    | "R14" -> r.R14
    | "R15" -> r.R15
    | "R16" -> r.R16
    | "R17" -> r.R17
    | "R18" -> r.R18
    | "R19" -> r.R19
    | "R20" -> r.R20
    | "R21" -> r.R21
    | "R22" -> r.R22
    | "R23" -> r.R23
    | "R24" -> r.R24
    | "R25" -> r.R25
    | "R26" -> r.R26
    | "R27" -> r.R27
    | "R28" -> r.R28
    | "R29" -> r.R29
    | "R30" -> r.R30
    | "R31" -> r.R31
    | "F0" -> r.F0
    | "F1" -> r.F1
    | "F2" -> r.F2
    | "F3" -> r.F3
    | "F4" -> r.F4
    | "F5" -> r.F5
    | "F6" -> r.F6
    | "F7" -> r.F7
    | "F8" -> r.F8
    | "F9" -> r.F9
    | "F10" -> r.F10
    | "F11"-> r.F11
    | "F12" -> r.F12
    | "F13" -> r.F13
    | "F14" -> r.F14
    | "F15" -> r.F15
    | "F16" -> r.F16
    | "F17" -> r.F17
    | "F18" -> r.F18
    | "F19" -> r.F19
    | "F20" -> r.F20
    | "F21" -> r.F21
    | "F22" -> r.F22
    | "F23" -> r.F23
    | "F24" -> r.F24
    | "F25" -> r.F25
    | "F26" -> r.F26
    | "F27" -> r.F27
    | "F28" -> r.F28
    | "F29" -> r.F29
    | "F30" -> r.F30
    | "F31" -> r.F31
    | _ -> raise UnhandledRegExprException

  override __.RegIDFromString str =
    Register.ofString str |> Register.toRegID

  override __.RegIDToString rid =
    Register.ofRegID rid |> Register.toString

  override __.RegIDToRegType _rid =
    WordSize.toRegType wordSize

  override __.GetRegisterAliases rid =
    [| rid |]

  override __.ProgramCounter =
    Register.PC |> Register.toRegID

  override __.StackPointer =
    Register.R29 |> Register.toRegID |> Some

  override __.FramePointer =
    Register.R30 |> Register.toRegID |> Some

  override __.IsProgramCounter regid =
    __.ProgramCounter = regid

  override __.IsStackPointer regid =
    (__.StackPointer |> Option.get) = regid

  override __.IsFramePointer regid =
    (__.FramePointer |> Option.get) = regid
