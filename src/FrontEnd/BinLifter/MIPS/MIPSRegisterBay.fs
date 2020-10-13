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

type MIPSRegisterBay (wordSize) =
  inherit RegisterBay ()

  let R = RegExprs (wordSize)

  override __.GetAllRegExprs () =
    [ R.HI; R.LO; R.PC; R.R0; R.R1; R.R2; R.R3; R.R4; R.R5; R.R6; R.R7; R.R8;
      R.R9; R.R10; R.R11; R.R12; R.R13; R.R14; R.R15; R.R16; R.R17; R.R18;
      R.R19; R.R20; R.R21; R.R22; R.R23; R.R24; R.R25; R.R26; R.R27; R.R28;
      R.R29; R.R30; R.R31; R.F0; R.F1; R.F2; R.F3; R.F4; R.F5; R.F6; R.F7; R.F8;
      R.F9; R.F10; R.F11; R.F12; R.F13; R.F14; R.F15; R.F16; R.F17; R.F18;
      R.F19; R.F20; R.F21; R.F22; R.F23; R.F24; R.F25; R.F26; R.F27; R.F28;
      R.F29; R.F30; R.F31 ]

  override __.GetAllRegNames () =
    __.GetAllRegExprs ()
    |> List.map (__.RegIDFromRegExpr >> __.RegIDToString)

  override __.GetGeneralRegExprs () =
    [ R.HI; R.LO; R.PC; R.R0; R.R1; R.R2; R.R3; R.R4; R.R5; R.R6; R.R7; R.R8;
      R.R9; R.R10; R.R11; R.R12; R.R13; R.R14; R.R15; R.R16; R.R17; R.R18;
      R.R19; R.R20; R.R21; R.R22; R.R23; R.R24; R.R25; R.R26; R.R27; R.R28;
      R.R29; R.R30; R.R31 ]

  override __.RegIDFromRegExpr (e) =
    match e with
    | Var (_,id, _,_) -> id
    | PCVar (_, _) -> Register.toRegID Register.PC
    | _ -> failwith "not a register expression"

  override __.StrToRegExpr s =
    match s with
    | "HI" -> R.HI
    | "LO" -> R.LO
    | "PC" -> R.PC
    | "R0" -> R.R0
    | "R1" -> R.R1
    | "R2" -> R.R2
    | "R3" -> R.R3
    | "R4" -> R.R4
    | "R5" -> R.R5
    | "R6" -> R.R6
    | "R7" -> R.R7
    | "R8" -> R.R8
    | "R9" -> R.R9
    | "R10" -> R.R10
    | "R11" -> R.R11
    | "R12" -> R.R12
    | "R13" -> R.R13
    | "R14" -> R.R14
    | "R15" -> R.R15
    | "R16" -> R.R16
    | "R17" -> R.R17
    | "R18" -> R.R18
    | "R19" -> R.R19
    | "R20" -> R.R20
    | "R21" -> R.R21
    | "R22" -> R.R22
    | "R23" -> R.R23
    | "R24" -> R.R24
    | "R25" -> R.R25
    | "R26" -> R.R26
    | "R27" -> R.R27
    | "R28" -> R.R28
    | "R29" -> R.R29
    | "R30" -> R.R30
    | "R31" -> R.R31
    | "F0" -> R.F0
    | "F1" -> R.F1
    | "F2" -> R.F2
    | "F3" -> R.F3
    | "F4" -> R.F4
    | "F5" -> R.F5
    | "F6" -> R.F6
    | "F7" -> R.F7
    | "F8" -> R.F8
    | "F9" -> R.F9
    | "F10" -> R.F10
    | "F11"-> R.F11
    | "F12" -> R.F12
    | "F13" -> R.F13
    | "F14" -> R.F14
    | "F15" -> R.F15
    | "F16" -> R.F16
    | "F17" -> R.F17
    | "F18" -> R.F18
    | "F19" -> R.F19
    | "F20" -> R.F20
    | "F21" -> R.F21
    | "F22" -> R.F22
    | "F23" -> R.F23
    | "F24" -> R.F24
    | "F25" -> R.F25
    | "F26" -> R.F26
    | "F27" -> R.F27
    | "F28" -> R.F28
    | "F29" -> R.F29
    | "F30" -> R.F30
    | "F31" -> R.F31
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
