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

open B2R2
open B2R2.FrontEnd.BinLifter

type S39064RegisterFactory (wordSize, r: RegExprs) =
  inherit RegisterFactory ()

  override __.GetAllRegExprs () =
    Terminator.futureFeature ()

  override __.GetAllRegNames () =
    __.GetAllRegExprs ()
    |> List.map (__.RegIDFromRegExpr >> __.RegIDToString)

  override __.GetGeneralRegExprs () =
    Terminator.futureFeature ()

  override __.RegIDFromRegExpr (e) =
    Terminator.futureFeature ()

  override __.RegIDToRegExpr (id) =
    Terminator.futureFeature ()

  override __.StrToRegExpr s =
    Terminator.futureFeature ()

  override __.RegIDFromString str =
    Terminator.futureFeature ()

  override __.RegIDToString rid =
    Terminator.futureFeature ()

  override __.RegIDToRegType rid =
    Terminator.futureFeature ()

  override __.GetRegisterAliases _rid =
    Terminator.futureFeature ()

  override __.ProgramCounter =
    Terminator.futureFeature ()

  override __.StackPointer =
    Terminator.futureFeature ()

  override __.FramePointer =
    Terminator.futureFeature ()

  override __.IsProgramCounter rid =
    Terminator.futureFeature ()

  override __.IsStackPointer rid =
    Terminator.futureFeature ()

  override __.IsFramePointer rid =
    Terminator.futureFeature ()
