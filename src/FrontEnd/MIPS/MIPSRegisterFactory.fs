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
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type MIPSRegisterFactory (wordSize, r: RegExprs) =
  inherit RegisterFactory ()

  override _.GetAllRegExprs () =
    [ r.HI; r.LO; r.PC; r.R0; r.R1; r.R2; r.R3; r.R4; r.R5; r.R6; r.R7; r.R8;
      r.R9; r.R10; r.R11; r.R12; r.R13; r.R14; r.R15; r.R16; r.R17; r.R18;
      r.R19; r.R20; r.R21; r.R22; r.R23; r.R24; r.R25; r.R26; r.R27; r.R28;
      r.R29; r.R30; r.R31; r.F0; r.F1; r.F2; r.F3; r.F4; r.F5; r.F6; r.F7; r.F8;
      r.F9; r.F10; r.F11; r.F12; r.F13; r.F14; r.F15; r.F16; r.F17; r.F18;
      r.F19; r.F20; r.F21; r.F22; r.F23; r.F24; r.F25; r.F26; r.F27; r.F28;
      r.F29; r.F30; r.F31 ]

  override this.GetAllRegNames () =
    this.GetAllRegExprs ()
    |> List.map (this.RegIDFromRegExpr >> this.RegIDToString)

  override _.GetGeneralRegExprs () =
    [ r.HI; r.LO; r.PC; r.R0; r.R1; r.R2; r.R3; r.R4; r.R5; r.R6; r.R7; r.R8;
      r.R9; r.R10; r.R11; r.R12; r.R13; r.R14; r.R15; r.R16; r.R17; r.R18;
      r.R19; r.R20; r.R21; r.R22; r.R23; r.R24; r.R25; r.R26; r.R27; r.R28;
      r.R29; r.R30; r.R31 ]

  override _.RegIDFromRegExpr e =
    match e with
    | Var (_, id, _, _) -> id
    | PCVar _ -> Register.toRegID Register.PC
    | _ -> raise InvalidRegisterException

  override _.RegIDToRegExpr (id) =
    Register.ofRegID id |> r.GetRegVar

  override this.StrToRegExpr str =
    Register.ofString str wordSize |> Register.toRegID |> this.RegIDToRegExpr

  override _.RegIDFromString str =
    Register.ofString str wordSize |> Register.toRegID

  override _.RegIDToString rid =
    Register.toString (Register.ofRegID rid) wordSize

  override _.RegIDToRegType _rid =
    WordSize.toRegType wordSize

  override _.GetRegisterAliases rid =
    [| rid |]

  override _.ProgramCounter =
    Register.PC |> Register.toRegID

  override _.StackPointer =
    Register.R29 |> Register.toRegID |> Some

  override _.FramePointer =
    Register.R30 |> Register.toRegID |> Some

  override this.IsProgramCounter regid =
    this.ProgramCounter = regid

  override this.IsStackPointer regid =
    (this.StackPointer |> Option.get) = regid

  override this.IsFramePointer regid =
    (this.FramePointer |> Option.get) = regid
