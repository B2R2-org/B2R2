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
module B2R2.FrontEnd.Parser

open B2R2
open B2R2.FrontEnd.BinLifter

/// Initialize a `Parser` from a given ISA, ArchOperationMode, and (optional)
/// entrypoint address.
[<CompiledName ("Init")>]
let init (isa: ISA) mode (entryPoint: Addr option) =
  match isa.Arch with
  | Architecture.IntelX64
  | Architecture.IntelX86 ->
    Intel.IntelParser (isa.WordSize) :> IInstructionParsable
  | Architecture.ARMv7 | Architecture.AARCH32 ->
    ARM32.ARM32Parser (isa, mode, entryPoint) :> IInstructionParsable
  | Architecture.AARCH64 ->
    ARM64.ARM64Parser (isa) :> IInstructionParsable
  | Architecture.MIPS32 | Architecture.MIPS64 ->
    MIPS.MIPSParser (isa) :> IInstructionParsable
  | Architecture.EVM ->
    EVM.EVMParser (isa) :> IInstructionParsable
  | Architecture.TMS320C6000 ->
    TMS320C6000.TMS320C6000Parser () :> IInstructionParsable
  | Architecture.CILOnly ->
    CIL.CILParser () :> IInstructionParsable
  | Architecture.AVR ->
    AVR.AVRParser () :> IInstructionParsable
  | Architecture.SH4 ->
    SH4.SH4Parser (isa) :> IInstructionParsable
  | Architecture.PPC32 ->
    PPC32.PPC32Parser (isa) :> IInstructionParsable
  | Architecture.RISCV64 ->
    RISCV.RISCV64Parser (isa) :> IInstructionParsable
  | Architecture.SPARC ->
    SPARC.SPARCParser (isa) :> IInstructionParsable
  | _ ->
    Utils.futureFeature ()
