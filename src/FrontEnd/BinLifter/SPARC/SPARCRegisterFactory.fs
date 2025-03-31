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

namespace B2R2.FrontEnd.BinLifter.SPARC

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.Register
open B2R2.BinIR.LowUIR

type SPARCRegisterFactory () =
  inherit RegisterFactory ()

  override __.GetAllRegExprs () = Utils.futureFeature ()

  override __.GetAllRegNames () = Utils.futureFeature ()

  override __.GetGeneralRegExprs () = Utils.futureFeature ()

  override __.RegIDFromRegExpr (e) =
    match e.E with
    | Var (_, id, _) -> id
    | PCVar _ -> SPARCRegister.ID SPARC.PC
    | _ -> raise InvalidRegisterException

  override __.RegIDToRegExpr (id) = Utils.futureFeature ()
  override __.StrToRegExpr _s = Utils.futureFeature ()
  override __.RegIDFromString _s = Utils.futureFeature ()
  override __.RegIDToString _ = Utils.futureFeature ()
  override __.RegIDToRegType _ = Utils.futureFeature ()
  override __.GetRegisterAliases _ = Utils.futureFeature ()
  override __.ProgramCounter = SPARC.PC |> SPARCRegister.ID
  override __.StackPointer = SPARC.O6 |> SPARCRegister.ID |> Some
  override __.FramePointer = SPARC.I6 |> SPARCRegister.ID |> Some
  override __.IsProgramCounter regid = __.ProgramCounter = regid
  override __.IsStackPointer _ = Utils.futureFeature ()
  override __.IsFramePointer _ = Utils.futureFeature ()
