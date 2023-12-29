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

namespace B2R2.FrontEnd.BinLifter.S390

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type S39064RegisterFactory (wordSize, r: RegExprs) =
  inherit RegisterFactory ()

  override __.GetAllRegExprs () =
    Utils.futureFeature ()

  override __.GetAllRegNames () =
    __.GetAllRegExprs ()
    |> List.map (__.RegIDFromRegExpr >> __.RegIDToString)

  override __.GetGeneralRegExprs () =
    Utils.futureFeature ()

  override __.RegIDFromRegExpr (e) =
    Utils.futureFeature ()

  override __.RegIDToRegExpr (id) =
    Utils.futureFeature ()

  override __.StrToRegExpr s =
    Utils.futureFeature ()

  override __.RegIDFromString str =
    Utils.futureFeature ()

  override __.RegIDToString rid =
    Utils.futureFeature ()

  override __.RegIDToRegType rid =
    Utils.futureFeature ()

  override __.GetRegisterAliases _rid =
    Utils.futureFeature ()

  override __.ProgramCounter =
    Utils.futureFeature ()

  override __.StackPointer =
    Utils.futureFeature ()

  override __.FramePointer =
    Utils.futureFeature ()

  override __.IsProgramCounter rid =
    Utils.futureFeature ()

  override __.IsStackPointer rid =
    Utils.futureFeature ()

  override __.IsFramePointer rid =
    Utils.futureFeature ()
