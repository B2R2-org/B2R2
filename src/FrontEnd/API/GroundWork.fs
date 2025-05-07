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

namespace B2R2.FrontEnd

open B2R2
open B2R2.FrontEnd.BinLifter

/// The groundwork for the front-end. This module provides a set of functions
/// to create fundamental components to use the front-end.
type GroundWork =
  static member CreateRegisterFactory (isa: ISA) =
    match isa.Arch with
    | Architecture.IntelX64
    | Architecture.IntelX86 ->
      Intel.RegisterFactory isa.WordSize :> IRegisterFactory
    | Architecture.ARMv7 | Architecture.AARCH32 ->
      ARM32.RegisterFactory () :> IRegisterFactory
    | Architecture.AARCH64 ->
      ARM64.RegisterFactory () :> IRegisterFactory
    | Architecture.MIPS32 | Architecture.MIPS64 ->
      MIPS.RegisterFactory isa.WordSize :> IRegisterFactory
    | Architecture.EVM ->
      EVM.RegisterFactory () :> IRegisterFactory
    | Architecture.TMS320C6000 ->
      TMS320C6000.RegisterFactory () :> IRegisterFactory
    | Architecture.AVR ->
      AVR.RegisterFactory isa.WordSize
    | Architecture.S390 | Architecture.S390X ->
      S390.RegisterFactory isa.WordSize :> IRegisterFactory
    | Architecture.SH4 ->
      SH4.RegisterFactory isa.WordSize :> IRegisterFactory
    | Architecture.PPC32 ->
      PPC32.RegisterFactory isa.WordSize :> IRegisterFactory
    | Architecture.RISCV64 ->
      RISCV64.RegisterFactory isa.WordSize :> IRegisterFactory
    | Architecture.SPARC ->
      SPARC.RegisterFactory isa.WordSize :> IRegisterFactory
    | Architecture.PARISC | Architecture.PARISC64 ->
      PARISC.RegisterFactory isa.WordSize :> IRegisterFactory
    | _ ->
      Terminator.futureFeature ()

  /// Create a new parser (IInstructionParsable) for the given architecture.
  static member CreateParser reader (isa: ISA) =
    match isa.Arch with
    | Architecture.IntelX64
    | Architecture.IntelX86 ->
      Intel.IntelParser (isa.WordSize, reader)
      :> IInstructionParsable
    | Architecture.ARMv7 | Architecture.AARCH32 ->
      ARM32.ARM32Parser (isa, false, reader)
      :> IInstructionParsable
    | Architecture.AARCH64 ->
      ARM64.ARM64Parser (reader) :> IInstructionParsable
    | Architecture.MIPS32 | Architecture.MIPS64 ->
      MIPS.MIPSParser (isa, reader) :> IInstructionParsable
    | Architecture.EVM ->
      EVM.EVMParser (isa) :> IInstructionParsable
    | Architecture.TMS320C6000 ->
      TMS320C6000.TMS320C6000Parser (reader) :> IInstructionParsable
    | Architecture.CILOnly ->
      CIL.CILParser () :> IInstructionParsable
    | Architecture.AVR ->
      AVR.AVRParser (reader) :> IInstructionParsable
    | Architecture.S390 | Architecture.S390X ->
      S390.S390Parser (isa, reader) :> IInstructionParsable
    | Architecture.SH4 ->
      SH4.SH4Parser (reader) :> IInstructionParsable
    | Architecture.PPC32 ->
      PPC32.PPC32Parser (reader) :> IInstructionParsable
    | Architecture.RISCV64 ->
      RISCV64.RISCV64Parser (isa, reader)
      :> IInstructionParsable
    | Architecture.SPARC ->
      SPARC.SPARCParser (reader) :> IInstructionParsable
    | Architecture.PARISC | Architecture.PARISC64 ->
      PARISC.PARISCParser (isa, reader) :> IInstructionParsable
    | _ ->
      Terminator.futureFeature ()

  /// Create a new LowUIR builder for the given architecture.
  static member CreateBuilder (isa: ISA) regFactory =
    let stream = LowUIRStream ()
    match isa.Arch with
    | Architecture.IntelX64
    | Architecture.IntelX86 ->
      Intel.LowUIRBuilder (isa, regFactory, stream) :> ILowUIRBuilder
    | Architecture.MIPS32 | Architecture.MIPS64 ->
      MIPS.LowUIRBuilder (isa, regFactory, stream) :> ILowUIRBuilder
    | _ ->
      ILowUIRBuilder.Default (isa, regFactory, stream)
