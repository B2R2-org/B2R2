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

namespace B2R2.FrontEnd.PPC

open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR
open type Register

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.PPC.Tests")>]
do ()

/// Represents a factory for accessing various PPC register variables.
type RegisterFactory(wordSize) =
  let rt = WordSize.toRegType wordSize

  let r0 = AST.var rt (Register.toRegID R0) "R0"

  interface IRegisterFactory with
    member _.GetRegVar id =
      match Register.ofRegID id with
      | Register.R0 -> r0
      | _ -> raise InvalidRegisterException

    member _.GetRegVar(name: string) =
      match name.ToLowerInvariant() with
      | "r0" -> r0
      | _ -> raise InvalidRegisterException

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

    member _.GetAllRegVars() =
      [| r0 |]

    member _.GetGeneralRegVars() =
      [| r0 |]

    member _.GetRegisterID expr =
      match expr with
      | Var(_, id, _, _) -> id
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name =
      Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases rid =
      [| rid |]

    member _.GetRegString rid =
      Register.ofRegID rid |> Register.toString

    member this.GetAllRegStrings() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegString)

    member _.GetRegType rid =
      if rid < 0x40<RegisterID.T> then WordSize.toRegType wordSize
      else 4<rt>

    member _.ProgramCounter = Terminator.futureFeature ()

    member _.StackPointer =
      R0 |> Register.toRegID |> Some

    member _.FramePointer = None

    member _.IsProgramCounter _ = false

    member _.IsStackPointer rid =
      Register.toRegID R1 = rid

    member _.IsFramePointer _ = false
