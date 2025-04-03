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

namespace B2R2.FrontEnd.WASM

open B2R2
open B2R2.FrontEnd.BinLifter

type WASMRegisterFactory () =
  inherit RegisterFactory ()

  override __.GetAllRegExprs () = Terminator.futureFeature ()

  override __.GetAllRegNames () = []

  override __.GetGeneralRegExprs () = Terminator.futureFeature ()

  override __.RegIDFromRegExpr (_e) = Terminator.futureFeature ()

  override __.RegIDToRegExpr (_id) = Terminator.impossible ()

  override __.StrToRegExpr _s = Terminator.impossible ()

  override __.RegIDFromString str =
    Register.ofString str |> Register.toRegID

  override __.RegIDToString rid =
    Register.ofRegID rid |> Register.toString

  override __.RegIDToRegType rid =
    Register.ofRegID rid |> Register.toRegType

  override __.GetRegisterAliases _ = Terminator.futureFeature ()

  override __.ProgramCounter = Terminator.impossible()

  override __.StackPointer = Terminator.futureFeature ()

  override __.FramePointer = Terminator.impossible ()

  override __.IsProgramCounter regid = Terminator.futureFeature ()

  override __.IsStackPointer regid = Terminator.futureFeature ()

  override __.IsFramePointer _ = Terminator.impossible ()

// vim: set tw=80 sts=2 sw=2:
