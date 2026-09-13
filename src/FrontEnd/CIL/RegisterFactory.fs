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
namespace B2R2.FrontEnd.CIL

open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.CIL.Tests")>]
do ()

/// Represents a factory for accessing the CIL register variables. The machine
/// has no registers a program can name: the four here are the addresses that
/// locate the evaluation stack, the local variables and the arguments, and the
/// program counter, all of them a quadword wide.
type RegisterFactory(isa: ISA) =
  let pc = AST.pcvar 64<rt> "PC"
  let sp = AST.var 64<rt> (Register.toRegID Register.SP) "SP"
  let fp = AST.var 64<rt> (Register.toRegID Register.FP) "FP"
  let ap = AST.var 64<rt> (Register.toRegID Register.AP) "AP"

  interface IRegisterFactory with
    member _.ISA = isa

    member _.ProgramCounter = Register.PC |> Register.toRegID

    member _.StackPointer = Register.SP |> Register.toRegID |> Some

    member _.FramePointer = Register.FP |> Register.toRegID |> Some

    member _.GetRegVar id =
      match Register.ofRegID id with
      | Register.PC -> pc
      | Register.SP -> sp
      | Register.FP -> fp
      | Register.AP -> ap
      | _ -> raise InvalidRegisterException

    member _.GetRegVar(name: string) =
      match name.ToLowerInvariant() with
      | "pc" -> pc
      | "sp" -> sp
      | "fp" -> fp
      | "ap" -> ap
      | _ -> raise InvalidRegisterException

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

    member _.GetAllRegVars() = [| pc; sp; fp; ap |]

    member _.GetGeneralRegVars() = [| sp; fp; ap |]

    member _.GetRegisterID expr =
      match expr with
      | Var(_, id, _, _) -> id
      | PCVar _ -> Register.toRegID Register.PC
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID name = Register.ofString name |> Register.toRegID

    member _.GetRegisterIDAliases rid = [| rid |]

    member _.GetRegisterName rid = Register.ofRegID rid |> Register.toString

    member this.GetAllRegisterNames() =
      let regFactory = this :> IRegisterFactory
      regFactory.GetAllRegVars()
      |> Array.map (regFactory.GetRegisterID >> regFactory.GetRegisterName)

    member _.GetRegType rid = Register.ofRegID rid |> Register.toRegType

    member _.IsProgramCounter regid = Register.toRegID Register.PC = regid

    member _.IsStackPointer regid = Register.toRegID Register.SP = regid

    member _.IsFramePointer regid = Register.toRegID Register.FP = regid

// vim: set tw=80 sts=2 sw=2:
