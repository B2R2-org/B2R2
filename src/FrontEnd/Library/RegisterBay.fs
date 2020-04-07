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

module B2R2.FrontEnd.RegisterBay

open B2R2

[<CompiledName("RegisterIDFromString")>]
let registerIDFromString handler str =
  match handler.ISA.Arch with
  | Architecture.IntelX86 ->
    Intel.Register.ofString str
    |> Intel.Register.extendRegister32
    |> Intel.Register.toRegID
  | Architecture.IntelX64 ->
    Intel.Register.ofString str
    |> Intel.Register.extendRegister64
    |> Intel.Register.toRegID
  | Architecture.ARMv7
  | Architecture.AARCH32 ->
    ARM32.Register.ofString str |> ARM32.Register.toRegID
  | Architecture.AARCH64 ->
    ARM64.Register.ofString str |> ARM64.Register.toRegID
  | Architecture.MIPS1
  | Architecture.MIPS2
  | Architecture.MIPS3
  | Architecture.MIPS4
  | Architecture.MIPS5
  | Architecture.MIPS32
  | Architecture.MIPS32R2
  | Architecture.MIPS32R6
  | Architecture.MIPS64
  | Architecture.MIPS64R2
  | Architecture.MIPS64R6 ->
    MIPS.Register.ofString str |> MIPS.Register.toRegID
  | Architecture.EVM ->
    EVM.Register.ofString str |> EVM.Register.toRegID
  | Architecture.TMS320C5000
  | Architecture.TMS320C6000 ->
    TMS320C6000.Register.ofString str |> TMS320C6000.Register.toRegID
  | _ -> Utils.futureFeature ()

[<CompiledName("RegisterIDToString")>]
let registerIDToString handler rid =
  match handler.ISA.Arch with
  | Architecture.IntelX86
  | Architecture.IntelX64 ->
    Intel.Register.ofRegID rid |> Intel.Register.toString
  | Architecture.ARMv7
  | Architecture.AARCH32 ->
    ARM32.Register.ofRegID rid |> ARM32.Register.toString
  | Architecture.AARCH64 ->
    ARM64.Register.ofRegID rid |> ARM64.Register.toString
  | Architecture.MIPS1
  | Architecture.MIPS2
  | Architecture.MIPS3
  | Architecture.MIPS4
  | Architecture.MIPS5
  | Architecture.MIPS32
  | Architecture.MIPS32R2
  | Architecture.MIPS32R6
  | Architecture.MIPS64
  | Architecture.MIPS64R2
  | Architecture.MIPS64R6 ->
    MIPS.Register.ofRegID rid |> MIPS.Register.toString
  | Architecture.EVM ->
    EVM.Register.ofRegID rid |> EVM.Register.toString
  | Architecture.TMS320C5000
  | Architecture.TMS320C6000 ->
    TMS320C6000.Register.ofRegID rid |> TMS320C6000.Register.toString
  | _ -> Utils.futureFeature ()

[<CompiledName("GetRegisterAliases")>]
let getRegisterAliases handler rid =
  match handler.ISA.Arch with
  | Architecture.IntelX86
  | Architecture.IntelX64 ->
    Intel.Register.ofRegID rid
    |> Intel.Register.getAliases
    |> Array.map Intel.Register.toRegID
  | Architecture.ARMv7
  | Architecture.AARCH32
  | Architecture.AARCH64
  | Architecture.MIPS1
  | Architecture.MIPS2
  | Architecture.MIPS3
  | Architecture.MIPS4
  | Architecture.MIPS5
  | Architecture.MIPS32
  | Architecture.MIPS32R2
  | Architecture.MIPS32R6
  | Architecture.MIPS64
  | Architecture.MIPS64R2
  | Architecture.MIPS64R6
  | Architecture.EVM
  | Architecture.TMS320C5000
  | Architecture.TMS320C6000 -> [| rid |]
  | _ -> Utils.futureFeature ()

[<CompiledName("GetProgramCounter")>]
let getProgramCounter handler =
  match handler.ISA.Arch with
  | Architecture.IntelX86 -> Intel.Register.EIP |> Intel.Register.toRegID
  | Architecture.IntelX64 -> Intel.Register.RIP |> Intel.Register.toRegID
  | Architecture.ARMv7
  | Architecture.AARCH32 -> ARM32.Register.PC |> ARM32.Register.toRegID
  | Architecture.AARCH64 -> ARM64.Register.PC |> ARM64.Register.toRegID
  | Architecture.MIPS1
  | Architecture.MIPS2
  | Architecture.MIPS3
  | Architecture.MIPS4
  | Architecture.MIPS5
  | Architecture.MIPS32
  | Architecture.MIPS32R2
  | Architecture.MIPS32R6
  | Architecture.MIPS64
  | Architecture.MIPS64R2
  | Architecture.MIPS64R6 -> MIPS.Register.PC |> MIPS.Register.toRegID
  | Architecture.TMS320C5000
  | Architecture.TMS320C6000 ->
    TMS320C6000.Register.PCE1 |> TMS320C6000.Register.toRegID
  | Architecture.EVM -> EVM.Register.PC |> EVM.Register.toRegID
  | _ -> Utils.impossible ()

[<CompiledName("GetStackPointer")>]
let getStackPointer handler =
  match handler.ISA.Arch with
  | Architecture.IntelX86 ->
    Intel.Register.ESP |> Intel.Register.toRegID |> Some
  | Architecture.IntelX64 ->
    Intel.Register.RSP |> Intel.Register.toRegID |> Some
  | Architecture.ARMv7
  | Architecture.AARCH32 -> ARM32.Register.SP |> ARM32.Register.toRegID |> Some
  | Architecture.AARCH64 -> ARM64.Register.SP |> ARM64.Register.toRegID |> Some
  | Architecture.MIPS1
  | Architecture.MIPS2
  | Architecture.MIPS3
  | Architecture.MIPS4
  | Architecture.MIPS5
  | Architecture.MIPS32
  | Architecture.MIPS32R2
  | Architecture.MIPS32R6
  | Architecture.MIPS64
  | Architecture.MIPS64R2
  | Architecture.MIPS64R6 -> MIPS.Register.R29 |> MIPS.Register.toRegID |> Some
  | _ -> None

[<CompiledName("GetFramePointer")>]
let getFramePointer handler =
  match handler.ISA.Arch with
  | Architecture.IntelX86 ->
    Intel.Register.EBP |> Intel.Register.toRegID |> Some
  | Architecture.IntelX64 ->
    Intel.Register.RBP |> Intel.Register.toRegID |> Some
  | Architecture.ARMv7
  | Architecture.AARCH32 -> ARM32.Register.FP |> ARM32.Register.toRegID |> Some
  | Architecture.MIPS1
  | Architecture.MIPS2
  | Architecture.MIPS3
  | Architecture.MIPS4
  | Architecture.MIPS5
  | Architecture.MIPS32
  | Architecture.MIPS32R2
  | Architecture.MIPS32R6
  | Architecture.MIPS64
  | Architecture.MIPS64R2
  | Architecture.MIPS64R6 -> MIPS.Register.R30 |> MIPS.Register.toRegID |> Some
  | _ -> None
