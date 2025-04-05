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

namespace B2R2.FrontEnd.AVR

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type AVRRegisterFactory () =
  inherit RegisterFactory ()

  override _.GetAllRegExprs () = Terminator.futureFeature ()
  override _.GetAllRegNames () = Terminator.futureFeature ()
  override _.GetGeneralRegExprs () = Terminator.futureFeature ()

  override _.RegIDFromRegExpr (e) =
    match e.E with
    | Var (_, id, _) -> id (* TODO *)
    | _ -> raise InvalidRegisterException

  override _.RegIDToRegExpr (id) = Terminator.futureFeature ()
  override _.StrToRegExpr _s = Terminator.futureFeature ()
  override _.RegIDFromString _s = Terminator.futureFeature ()
  override _.RegIDToString _ = Terminator.futureFeature ()
  override _.RegIDToRegType _ = Terminator.futureFeature ()
  override _.GetRegisterAliases _ = Terminator.futureFeature ()
  override _.ProgramCounter = Terminator.futureFeature ()
  override _.StackPointer = Terminator.futureFeature ()
  override _.FramePointer = Terminator.futureFeature ()
  override _.IsProgramCounter _ = Terminator.futureFeature ()
  override _.IsStackPointer _ = Terminator.futureFeature ()
  override _.IsFramePointer _ = Terminator.futureFeature ()
