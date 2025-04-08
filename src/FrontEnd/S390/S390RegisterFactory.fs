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

namespace B2R2.FrontEnd.S390

open B2R2.FrontEnd.S390
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type S39064RegisterFactory (wordSize, r: RegExprs) =
  inherit RegisterFactory ()

  override _.GetAllRegExprs () =
    [ r.R0; r.R1; r.R2; r.R3; r.R4; r.R5; r.R6; r.R7;
      r.R8; r.R9; r.R10; r.R11; r.R12; r.R13; r.R14; r.R15;
      r.FPR0; r.FPR1; r.FPR2; r.FPR3; r.FPR4; r.FPR5; r.FPR6; r.FPR7;
      r.FPR8; r.FPR9; r.FPR10; r.FPR11; r.FPR12; r.FPR13; r.FPR14; r.FPR15;
      r.FPC; r.VR0; r.VR1; r.VR2; r.VR3; r.VR4; r.VR5; r.VR6; r.VR7;
      r.VR8; r.VR9; r.VR10; r.VR11; r.VR12; r.VR13; r.VR14; r.VR15;
      r.VR16; r.VR17; r.VR18; r.VR19; r.VR20; r.VR21; r.VR22; r.VR23;
      r.VR24; r.VR25; r.VR26; r.VR27; r.VR28; r.VR29; r.VR30; r.VR31;
      r.CR0; r.CR1; r.CR2; r.CR3; r.CR4; r.CR5; r.CR6; r.CR7;
      r.CR8; r.CR9; r.CR10; r.CR11; r.CR12; r.CR13; r.CR14; r.CR15;
      r.AR0; r.AR1; r.AR2; r.AR3; r.AR4; r.AR5; r.AR6; r.AR7;
      r.AR8; r.AR9; r.AR10; r.AR11; r.AR12; r.AR13; r.AR14; r.AR15;
      r.BEAR; r.PSW ]

  override this.GetAllRegNames () =
    this.GetAllRegExprs ()
    |> List.map (this.RegIDFromRegExpr >> this.RegIDToString)

  override _.GetGeneralRegExprs () =
    [ r.R0; r.R1; r.R2; r.R3; r.R4; r.R5; r.R6; r.R7;
      r.R8; r.R9; r.R10; r.R11; r.R12; r.R13; r.R14; r.R15 ]

  override _.RegIDFromRegExpr e =
    match e.E with
    | Var (_, id, _) -> id
    | PCVar _ -> Register.toRegID Register.PSW
    | _ -> raise InvalidRegisterException

  override _.RegIDToRegExpr id =
    Register.ofRegID id |> r.GetRegVar

  override _.StrToRegExpr (s: string) =
    match s.ToUpper () with
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
    | "FPR0" -> r.FPR0
    | "FPR1" -> r.FPR1
    | "FPR2" -> r.FPR2
    | "FPR3" -> r.FPR3
    | "FPR4" -> r.FPR4
    | "FPR5" -> r.FPR5
    | "FPR6" -> r.FPR6
    | "FPR7" -> r.FPR7
    | "FPR8" -> r.FPR8
    | "FPR9" -> r.FPR9
    | "FPR10" -> r.FPR10
    | "FPR11" -> r.FPR11
    | "FPR12" -> r.FPR12
    | "FPR13" -> r.FPR13
    | "FPR14" -> r.FPR14
    | "FPR15" -> r.FPR15
    | "FPC" -> r.FPC
    | "VR0" -> r.VR0
    | "VR1" -> r.VR1
    | "VR2" -> r.VR2
    | "VR3" -> r.VR3
    | "VR4" -> r.VR4
    | "VR5" -> r.VR5
    | "VR6" -> r.VR6
    | "VR7" -> r.VR7
    | "VR8" -> r.VR8
    | "VR9" -> r.VR9
    | "VR10" -> r.VR10
    | "VR11" -> r.VR11
    | "VR12" -> r.VR12
    | "VR13" -> r.VR13
    | "VR14" -> r.VR14
    | "VR15" -> r.VR15
    | "VR16" -> r.VR16
    | "VR17" -> r.VR17
    | "VR18" -> r.VR18
    | "VR19" -> r.VR19
    | "VR20" -> r.VR20
    | "VR21" -> r.VR21
    | "VR22" -> r.VR22
    | "VR23" -> r.VR23
    | "VR24" -> r.VR24
    | "VR25" -> r.VR25
    | "VR26" -> r.VR26
    | "VR27" -> r.VR27
    | "VR28" -> r.VR28
    | "VR29" -> r.VR29
    | "VR30" -> r.VR30
    | "VR31" -> r.VR31
    | "CR0" -> r.CR0
    | "CR1" -> r.CR1
    | "CR2" -> r.CR2
    | "CR3" -> r.CR3
    | "CR4" -> r.CR4
    | "CR5" -> r.CR5
    | "CR6" -> r.CR6
    | "CR7" -> r.CR7
    | "CR8" -> r.CR8
    | "CR9" -> r.CR9
    | "CR10" -> r.CR10
    | "CR11" -> r.CR11
    | "CR12" -> r.CR12
    | "CR13" -> r.CR13
    | "CR14" -> r.CR14
    | "CR15" -> r.CR15
    | "AR0" -> r.AR0
    | "AR1" -> r.AR1
    | "AR2" -> r.AR2
    | "AR3" -> r.AR3
    | "AR4" -> r.AR4
    | "AR5" -> r.AR5
    | "AR6" -> r.AR6
    | "AR7" -> r.AR7
    | "AR8" -> r.AR8
    | "AR9" -> r.AR9
    | "AR10" -> r.AR10
    | "AR11" -> r.AR11
    | "AR12" -> r.AR12
    | "AR13" -> r.AR13
    | "AR14" -> r.AR14
    | "AR15" -> r.AR15
    | "BEAR" -> r.BEAR
    | "PSW" -> r.PSW
    | _ -> raise UnhandledRegExprException

  override _.RegIDFromString (str: string) =
    Register.ofString str |> Register.toRegID

  override _.RegIDToString rid =
    Register.ofRegID rid |> Register.toString

  override _.RegIDToRegType rid =
    Register.ofRegID rid |> Register.toRegType wordSize

  override _.GetRegisterAliases _rid =
    Register.ofRegID _rid
    |> Register.getAliases
    |> Array.map Register.toRegID

  override _.ProgramCounter =
    Register.PSW |> Register.toRegID

  override _.StackPointer =
    Register.R15
    |> Register.toRegID
    |> Some

  override _.FramePointer =
    None

  override this.IsProgramCounter rid =
    this.ProgramCounter = rid

  override this.IsStackPointer rid =
    this.StackPointer |> Option.get = rid

  override this.IsFramePointer rid =
    this.FramePointer |> Option.get = rid