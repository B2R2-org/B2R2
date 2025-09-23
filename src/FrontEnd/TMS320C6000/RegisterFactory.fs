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

namespace B2R2.FrontEnd.TMS320C6000

open System.Runtime.CompilerServices
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.TMS320C6000.Tests")>]
do ()

/// Represents a factory for accessing various TMS320C6000 register variables.
type RegisterFactory(_wordSize) =
  interface IRegisterFactory with
    member _.GetRegVar(id: RegisterID): Expr =
      match Register.ofRegID id with
      | _ -> raise InvalidRegisterException

    member _.GetRegVar(_: string): Expr = Terminator.futureFeature ()

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

    member _.GetAllRegVars() = Terminator.futureFeature ()

    member _.GetGeneralRegVars() = Terminator.futureFeature ()

    member _.GetRegisterID e =
      match e with
      | Var(_, id, _, _) -> id
      | PCVar _ -> Register.toRegID Register.PCE1
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID(_: string): RegisterID = Terminator.futureFeature ()

    member _.GetRegisterIDAliases _ = Terminator.futureFeature ()

    member _.GetRegisterName _ = Terminator.futureFeature ()

    member _.GetAllRegisterNames() = Terminator.futureFeature ()

    member _.GetRegType _ = Terminator.futureFeature ()

    member _.ProgramCounter = Terminator.futureFeature ()

    member _.StackPointer = Terminator.futureFeature ()

    member _.FramePointer = Terminator.futureFeature ()

    member _.IsProgramCounter _ = Terminator.futureFeature ()

    member _.IsStackPointer _ = Terminator.futureFeature ()

    member _.IsFramePointer _ = Terminator.futureFeature ()
