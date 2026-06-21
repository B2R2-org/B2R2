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

namespace B2R2.FrontEnd.Python

open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.Python.Tests")>]
do ()

/// <namespacedoc>
///   <summary>
///   Contains types and functions for working with the Python bytecode
///   instructions.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents a factory for accessing various Python register variables.
/// </summary>
type RegisterFactory(isa: ISA) =
  let pcRID = Register.PC |> Register.toRegID
  let spRID = Register.SP |> Register.toRegID

  interface IRegisterFactory with
    member _.ISA = isa

    member _.ProgramCounter = pcRID

    member _.StackPointer = Some spRID

    member _.FramePointer = None

    member _.GetRegVar(rid: RegisterID): Expr =
      let r = Register.ofRegID rid
      AST.var OperationSize.regType rid (Register.toString r)

    member _.GetRegVar(_: string): Expr = Terminator.futureFeature ()

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

    member _.GetAllRegVars() = Terminator.futureFeature ()

    member _.GetGeneralRegVars() = Terminator.futureFeature ()

    member _.GetRegisterID(_: Expr): RegisterID = Terminator.futureFeature ()

    member _.GetRegisterID(_: string): RegisterID = Terminator.futureFeature ()

    member _.GetRegisterIDAliases _ = Terminator.futureFeature ()

    member _.GetRegisterName rid = rid |> Register.ofRegID |> Register.toString

    member _.GetAllRegisterNames() = [||]

    member _.GetRegType _ = OperationSize.regType

    member _.IsProgramCounter regid = regid = pcRID

    member _.IsStackPointer regid = regid = spRID

    member _.IsFramePointer _ = false
