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
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter

/// Represents a factory for accessing various WASM register variables.
type RegisterFactory () =
  interface IRegisterFactory with
    member _.GetRegVar rid: Expr =
      match Register.ofRegID rid with
      | _ -> raise InvalidRegisterException

    member _.GetRegVar (_: string): Expr = Terminator.futureFeature ()

    member _.GetPseudoRegVar _id _idx = Terminator.impossible ()

    member _.GetAllRegVars () = Terminator.futureFeature ()

    member _.GetGeneralRegVars () = Terminator.futureFeature ()

    member _.GetRegisterID (_: Expr): RegisterID = Terminator.futureFeature ()

    member _.GetRegisterID str =
      Register.ofString str |> Register.toRegID

    member _.GetRegisterIDAliases _ = Terminator.futureFeature ()

    member _.GetRegString rid =
      Register.ofRegID rid |> Register.toString

    member _.GetAllRegStrings () = [||]

    member _.GetRegType rid =
      Register.ofRegID rid |> Register.toRegType

    member _.ProgramCounter = Terminator.impossible()

    member _.StackPointer = Terminator.futureFeature ()

    member _.FramePointer = Terminator.impossible ()

    member _.IsProgramCounter _ = Terminator.futureFeature ()

    member _.IsStackPointer _ = Terminator.futureFeature ()

    member _.IsFramePointer _ = Terminator.impossible ()
