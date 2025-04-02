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

namespace B2R2.FrontEnd.PARISC

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter

type PARISC64RegisterFactory (wordSize, r: RegExprs) =
  inherit RegisterFactory ()

  override __.GetAllRegExprs () =
    [ r.GR0; r.GR1; r.GR2; r.GR3; r.GR4; r.GR5; r.GR6; r.GR7; r.GR8; r.GR9
      r.GR10; r.GR11; r.GR12; r.GR13; r.GR14; r.GR15; r.GR16; r.GR17
      r.GR18;r.GR19; r.GR20; r.GR21; r.GR22; r.GR23; r.GR24; r.GR25; r.GR26
      r.GR27; r.GR28; r.GR29; r.GR30; r.GR31; r.SR0; r.SR1; r.SR2; r.SR3; r.SR4
      r.SR5; r.SR6; r.SR7; r.IAOQBACK; r.IAOQFRONT; r.IASQBACK; r.IASQFRONT
      r.CR0; r.CR1; r.CR2; r.CR3; r.CR4; r.CR5; r.CR6; r.CR7; r.CR8; r.CR9
      r.CR10; r.CR11; r.CR12; r.CR13; r.CR14; r.CR15; r.CR16; r.CR17; r.CR18
      r.CR19; r.CR20; r.CR21; r.CR22; r.CR23; r.CR24; r.CR25; r.CR26; r.CR27
      r.CR28; r.CR29; r.CR30; r.CR31; r.FPR0; r.FPR1; r.FPR2; r.FPR3; r.FPR4
      r.FPR5; r.FPR6; r.FPR7; r.FPR8; r.FPR9; r.FPR10; r.FPR11; r.FPR12; r.FPR13
      r.FPR14; r.FPR15; r.FPR16; r.FPR17; r.FPR18; r.FPR19; r.FPR20; r.FPR21
      r.FPR22; r.FPR23; r.FPR24; r.FPR25; r.FPR26; r.FPR27; r.FPR28; r.FPR29
      r.FPR30; r.FPR31 ]

  override __.GetAllRegNames () =
    __.GetAllRegExprs ()
    |> List.map (__.RegIDFromRegExpr >> __.RegIDToString)

  override __.GetGeneralRegExprs () =
    [ r.GR0; r.GR1; r.GR2; r.GR3; r.GR4; r.GR5; r.GR6; r.GR7; r.GR8; r.GR9
      r.GR10; r.GR11; r.GR12; r.GR13; r.GR14; r.GR15; r.GR16; r.GR17
      r.GR18;r.GR19; r.GR20; r.GR21; r.GR22; r.GR23; r.GR24; r.GR25; r.GR26
      r.GR27; r.GR28; r.GR29; r.GR30; r.GR31 ]

  override __.RegIDFromRegExpr (e) =
    match e.E with
    | Var (_, id, _) -> id
    | PCVar _ -> Register.toRegID Register.CR18
    | _ -> raise InvalidRegisterException

  override __.RegIDToRegExpr (id) =
    Register.ofRegID id |> r.GetRegVar

  override __.StrToRegExpr str =
    Register.ofString str |> Register.toRegID |> __.RegIDToRegExpr

  override __.RegIDFromString str =
    Register.ofString str |> Register.toRegID

  override __.RegIDToString rid =
    Register.toString (Register.ofRegID rid)

  override __.RegIDToRegType _rid =
    WordSize.toRegType wordSize

  override __.GetRegisterAliases rid =
    [| rid |]

  override __.ProgramCounter =
    Register.IAOQ_Front |> Register.toRegID

  override __.StackPointer =
    Register.GR30 |> Register.toRegID |> Some

  override __.FramePointer =
    Register.GR3 |> Register.toRegID |> Some

  override __.IsProgramCounter rid =
    __.ProgramCounter = rid

  override __.IsStackPointer rid =
    __.StackPointer |> Option.get = rid

  override __.IsFramePointer rid =
    __.FramePointer |> Option.get = rid
