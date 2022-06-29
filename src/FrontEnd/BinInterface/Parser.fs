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
module B2R2.FrontEnd.BinInterface.Parser

open B2R2
open B2R2.FrontEnd.BinLifter

/// Initialize a `Parser` from a given ISA, ArchOperationMode, and (optional)
/// entrypoint address.
[<CompiledName ("Init")>]
let init (isa: ISA) mode (entryPoint: Addr option) =
  match isa.Arch with
  | Arch.IntelX64
  | Arch.IntelX86 -> Intel.IntelParser (isa.WordSize) :> Parser
  | Arch.ARMv7 | Arch.AARCH32 ->
    ARM32.ARM32Parser (isa, mode, entryPoint) :> Parser
  | Arch.AARCH64 -> ARM64.ARM64Parser (isa) :> Parser
  | Arch.MIPS1 | Arch.MIPS2 | Arch.MIPS3 | Arch.MIPS4 | Arch.MIPS5
  | Arch.MIPS32 | Arch.MIPS32R2 | Arch.MIPS32R6
  | Arch.MIPS64 | Arch.MIPS64R2 | Arch.MIPS64R6 ->
    MIPS.MIPSParser (isa) :> Parser
  | Arch.EVM -> EVM.EVMParser (isa) :> Parser
  | Arch.TMS320C6000 -> TMS320C6000.TMS320C6000Parser () :> Parser
  | Arch.CILOnly -> CIL.CILParser () :> Parser
  | Arch.AVR -> AVR.AVRParser () :> Parser
  | Arch.SH4 -> SH4.SH4Parser (isa) :> Parser
  | Arch.PPC32 -> PPC32.PPC32Parser (isa) :> Parser
  | Arch.RISCV64 -> RISCV.RISCV64Parser (isa) :> Parser
  | _ -> Utils.futureFeature ()
