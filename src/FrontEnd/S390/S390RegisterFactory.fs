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

  override _.GetAllRegExprs () =
    Terminator.futureFeature ()

  override this.GetAllRegNames () =
    this.GetAllRegExprs ()
    |> List.map (this.RegIDFromRegExpr >> this.RegIDToString)

  override _.GetGeneralRegExprs () =
    Terminator.futureFeature ()

  override _.RegIDFromRegExpr (e) =
    Terminator.futureFeature ()

  override _.RegIDToRegExpr (id) =
    Terminator.futureFeature ()

  override _.StrToRegExpr s =
    Terminator.futureFeature ()

  override _.RegIDFromString str =
    Terminator.futureFeature ()

  override _.RegIDToString rid =
    Terminator.futureFeature ()

  override _.RegIDToRegType rid =
    Terminator.futureFeature ()

  override _.GetRegisterAliases _rid =
    Terminator.futureFeature ()

  override _.ProgramCounter =
    Terminator.futureFeature ()

  override _.StackPointer =
    Terminator.futureFeature ()

  override _.FramePointer =
    Terminator.futureFeature ()

  override _.IsProgramCounter rid =
    Terminator.futureFeature ()

  override _.IsStackPointer rid =
    Terminator.futureFeature ()

  override _.IsFramePointer rid =
    Terminator.futureFeature ()
