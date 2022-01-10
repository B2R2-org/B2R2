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

[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinInterface.Basis

open B2R2
open B2R2.FrontEnd.BinLifter

/// Establish the basis for lifting. This function returns a pair of
/// TranslationContext and RegisterBay.
[<CompiledName ("Init")>]
let init isa =
  match isa.Arch with
  | Arch.IntelX64
  | Arch.IntelX86 -> Intel.Basis.init isa
  | Arch.ARMv7 -> ARM32.Basis.init isa
  | Arch.AARCH64 -> ARM64.Basis.init isa
  | Arch.MIPS1 | Arch.MIPS2 | Arch.MIPS3 | Arch.MIPS4 | Arch.MIPS5
  | Arch.MIPS32 | Arch.MIPS32R2 | Arch.MIPS32R6
  | Arch.MIPS64 | Arch.MIPS64R2 | Arch.MIPS64R6 -> MIPS.Basis.init isa
  | Arch.EVM -> EVM.Basis.init isa
  | Arch.TMS320C6000 -> TMS320C6000.Basis.init isa
  | Arch.CILOnly -> CIL.Basis.init isa
  | Arch.AVR -> AVR.Basis.init isa
  | Arch.SH4 -> SH4.Basis.init isa
  | Arch.PPC32 -> PPC32.Basis.init isa
  | _ -> Utils.futureFeature ()
