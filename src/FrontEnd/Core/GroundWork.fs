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
  /// Create a new translation context for the given architecture.
  static member CreateTranslationContext isa =
    match isa.Arch with
    | Architecture.IntelX64
    | Architecture.IntelX86 ->
      Intel.IntelTranslationContext isa :> TranslationContext
    | Architecture.ARMv7 | Architecture.AARCH32 ->
      ARM32.ARM32TranslationContext isa :> TranslationContext
    | Architecture.AARCH64 ->
      ARM64.ARM64TranslationContext isa :> TranslationContext
    | Architecture.AVR ->
      AVR.AVRTranslationContext isa :> TranslationContext
    | Architecture.EVM ->
      EVM.EVMTranslationContext isa :> TranslationContext
    | Architecture.TMS320C6000 ->
      TMS320C6000.TMS320C6000TranslationContext isa :> TranslationContext
    | Architecture.MIPS32 | Architecture.MIPS64 ->
      MIPS.MIPSTranslationContext isa :> TranslationContext
    | Architecture.PPC32 ->
      PPC32.PPC32TranslationContext isa :> TranslationContext
    | Architecture.RISCV64 ->
      RISCV.RISCV64TranslationContext isa :> TranslationContext
    | Architecture.SH4 ->
      SH4.SH4TranslationContext isa :> TranslationContext
    | Architecture.SPARC ->
      SPARC.SPARCTranslationContext isa :> TranslationContext
    | Architecture.PARISC | Architecture.PARISC64 ->
      PARISC.PARISCTranslationContext isa :> TranslationContext
    | _ -> Utils.futureFeature ()

  /// Create a new register factory for the given architecture.
  static member CreateRegisterFactory isa =
    match isa.Arch with
    | Architecture.IntelX64
    | Architecture.IntelX86 ->
      Intel.IntelRegisterFactory (isa.WordSize, Intel.RegExprs isa.WordSize)
      :> RegisterFactory
    | Architecture.ARMv7 | Architecture.AARCH32 ->
      ARM32.ARM32RegisterFactory (ARM32.RegExprs ()) :> RegisterFactory
    | Architecture.AARCH64 ->
      ARM64.ARM64RegisterFactory (ARM64.RegExprs ()) :> RegisterFactory
    | Architecture.AVR ->
      AVR.AVRRegisterFactory () :> RegisterFactory
    | Architecture.EVM ->
      EVM.EVMRegisterFactory () :> RegisterFactory
    | Architecture.TMS320C6000 ->
      TMS320C6000.TMS320C6000RegisterFactory () :> RegisterFactory
    | Architecture.MIPS32 | Architecture.MIPS64 ->
      MIPS.MIPSRegisterFactory (isa.WordSize, MIPS.RegExprs isa.WordSize)
      :> RegisterFactory
    | Architecture.PPC32 ->
      PPC32.PPC32RegisterFactory (isa.WordSize, PPC32.RegExprs isa.WordSize)
      :> RegisterFactory
    | Architecture.RISCV64 ->
      RISCV.RISCV64RegisterFactory (isa.WordSize, RISCV.RegExprs isa.WordSize)
      :> RegisterFactory
    | Architecture.SH4 ->
      SH4.SH4RegisterFactory (SH4.RegExprs isa.WordSize)
      :> RegisterFactory
    | Architecture.SPARC ->
      SPARC.SPARCRegisterFactory ()
      :> RegisterFactory
    | Architecture.PARISC | Architecture.PARISC64 ->
      PARISC.PARISC64RegisterFactory
        (isa.WordSize, PARISC.RegExprs isa.WordSize)
      :> RegisterFactory
    | _ -> Utils.futureFeature ()

  /// Create a new parser (IInstructionParsable) for the given architecture.
  static member CreateParser (isa: ISA) mode =
    match isa.Arch with
    | Architecture.IntelX64
    | Architecture.IntelX86 ->
      Intel.IntelParser (isa.WordSize) :> IInstructionParsable
    | Architecture.ARMv7 | Architecture.AARCH32 ->
      ARM32.ARM32Parser (isa, mode) :> IInstructionParsable
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
    | Architecture.PARISC | Architecture.PARISC64 ->
      PARISC.PARISC64Parser (isa) :> IInstructionParsable
    | _ ->
      Utils.futureFeature ()
