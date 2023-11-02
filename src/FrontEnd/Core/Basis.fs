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
module B2R2.FrontEnd.Basis

open B2R2
open B2R2.FrontEnd.BinLifter

/// Establish the basis for lifting. This function returns a pair of
/// TranslationContext and RegisterFactory.
[<CompiledName ("Init")>]
let init isa =
  match isa.Arch with
  | Architecture.IntelX64
  | Architecture.IntelX86 -> Intel.Basis.init isa
  | Architecture.ARMv7 | Architecture.AARCH32 -> ARM32.Basis.init isa
  | Architecture.AARCH64 -> ARM64.Basis.init isa
  | Architecture.MIPS32 | Architecture.MIPS64 -> MIPS.Basis.init isa
  | Architecture.EVM -> EVM.Basis.init isa
  | Architecture.TMS320C6000 -> TMS320C6000.Basis.init isa
  | Architecture.CILOnly -> CIL.Basis.init isa
  | Architecture.AVR -> AVR.Basis.init isa
  | Architecture.SH4 -> SH4.Basis.init isa
  | Architecture.PPC32 -> PPC32.Basis.init isa
  | Architecture.RISCV64 -> RISCV.Basis.init isa
  | Architecture.SPARC -> SPARC.Basis.init isa
  | _ -> Utils.futureFeature ()
