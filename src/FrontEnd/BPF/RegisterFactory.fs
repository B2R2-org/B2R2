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

namespace B2R2.FrontEnd.BPF

open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.BPF.Tests")>]
do ()

/// Represents a factory for accessing various eBPF register variables. Every
/// register is a quadword wide, an instruction of the thirty-two bit class
/// reading the lower half of one and clearing the upper half when it writes.
type RegisterFactory(isa: ISA) =
  let r0 = AST.var 64<rt> (Register.toRegID Register.R0) "r0"
  let r1 = AST.var 64<rt> (Register.toRegID Register.R1) "r1"
  let r2 = AST.var 64<rt> (Register.toRegID Register.R2) "r2"
  let r3 = AST.var 64<rt> (Register.toRegID Register.R3) "r3"
  let r4 = AST.var 64<rt> (Register.toRegID Register.R4) "r4"
  let r5 = AST.var 64<rt> (Register.toRegID Register.R5) "r5"
  let r6 = AST.var 64<rt> (Register.toRegID Register.R6) "r6"
  let r7 = AST.var 64<rt> (Register.toRegID Register.R7) "r7"
  let r8 = AST.var 64<rt> (Register.toRegID Register.R8) "r8"
  let r9 = AST.var 64<rt> (Register.toRegID Register.R9) "r9"
  let r10 = AST.var 64<rt> (Register.toRegID Register.R10) "r10"
  let pc = AST.pcvar 64<rt> "pc"

  interface IRegisterFactory with
    member _.ISA = isa

    member _.ProgramCounter = Register.PC |> Register.toRegID

    (* Nothing here is a stack pointer: what a program reaches its own frame
       through is a register it may read and never write, so the frame pointer
       below is the whole of what this machine has. *)
    member _.StackPointer = None

    member _.FramePointer = Register.R10 |> Register.toRegID |> Some

    member _.GetRegVar rid =
      match Register.ofRegID rid with
      | Register.R0 -> r0
      | Register.R1 -> r1
      | Register.R2 -> r2
      | Register.R3 -> r3
      | Register.R4 -> r4
      | Register.R5 -> r5
      | Register.R6 -> r6
      | Register.R7 -> r7
      | Register.R8 -> r8
      | Register.R9 -> r9
      | Register.R10 -> r10
      | Register.PC -> pc
      | _ -> raise InvalidRegisterException

    member _.GetRegVar(name: string) =
      match name.ToLowerInvariant() with
      | "r0" -> r0
      | "r1" -> r1
      | "r2" -> r2
      | "r3" -> r3
      | "r4" -> r4
      | "r5" -> r5
      | "r6" -> r6
      | "r7" -> r7
      | "r8" -> r8
      | "r9" -> r9
      | "r10" | "fp" -> r10
      | "pc" -> pc
      | _ -> raise InvalidRegisterException

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

    member _.GetAllRegVars() =
      [| r0; r1; r2; r3; r4; r5; r6; r7; r8; r9; r10; pc |]

    member _.GetGeneralRegVars() =
      [| r0; r1; r2; r3; r4; r5; r6; r7; r8; r9; r10 |]

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

    member _.GetRegType _ = 64<rt>

    member _.IsProgramCounter rid = Register.toRegID Register.PC = rid

    member _.IsStackPointer _ = false

    member _.IsFramePointer rid = Register.toRegID Register.R10 = rid

// vim: set tw=80 sts=2 sw=2:
