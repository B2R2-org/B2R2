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

/// Load a translation context for the given architecture.
[<CompiledName "LoadTranslationContext">]
let loadTranslationContext isa =
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
  | _ -> Utils.futureFeature ()

/// Load a register factory for the given architecture.
[<CompiledName "LoadRegisterFactory">]
let loadRegisterFactory isa =
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
  | _ -> Utils.futureFeature ()

/// Load both a translation context and a register factory for the given
/// architecture. This is a recommended way to load both data structures.
[<CompiledName "Load">]
let load isa =
  match isa.Arch with
  | Architecture.IntelX64
  | Architecture.IntelX86 ->
    let ctxt = Intel.IntelTranslationContext isa
    let factory = Intel.IntelRegisterFactory (isa.WordSize, ctxt.RegExprs)
    struct (ctxt :> TranslationContext, factory :> RegisterFactory)
  | Architecture.ARMv7 | Architecture.AARCH32 ->
    let ctxt = ARM32.ARM32TranslationContext isa
    let factory = ARM32.ARM32RegisterFactory (ctxt.RegExprs)
    struct (ctxt :> TranslationContext, factory :> RegisterFactory)
  | Architecture.AARCH64 ->
    let ctxt = ARM64.ARM64TranslationContext isa
    let factory = ARM64.ARM64RegisterFactory (ctxt.RegExprs)
    struct (ctxt :> TranslationContext, factory :> RegisterFactory)
  | Architecture.AVR ->
    let ctxt = AVR.AVRTranslationContext isa
    let factory = AVR.AVRRegisterFactory ()
    struct (ctxt :> TranslationContext, factory :> RegisterFactory)
  | Architecture.EVM ->
    let ctxt = EVM.EVMTranslationContext isa
    let factory = EVM.EVMRegisterFactory ()
    struct (ctxt :> TranslationContext, factory :> RegisterFactory)
  | Architecture.TMS320C6000 ->
    let ctxt = TMS320C6000.TMS320C6000TranslationContext isa
    let factory = TMS320C6000.TMS320C6000RegisterFactory ()
    struct (ctxt :> TranslationContext, factory :> RegisterFactory)
  | Architecture.MIPS32 | Architecture.MIPS64 ->
    let ctxt = MIPS.MIPSTranslationContext isa
    let factory = MIPS.MIPSRegisterFactory (isa.WordSize, ctxt.RegExprs)
    struct (ctxt :> TranslationContext, factory :> RegisterFactory)
  | Architecture.PPC32 ->
    let ctxt = PPC32.PPC32TranslationContext isa
    let factory = PPC32.PPC32RegisterFactory (isa.WordSize, ctxt.RegExprs)
    struct (ctxt :> TranslationContext, factory :> RegisterFactory)
  | Architecture.RISCV64 ->
    let ctxt = RISCV.RISCV64TranslationContext isa
    let factory = RISCV.RISCV64RegisterFactory (isa.WordSize, ctxt.RegExprs)
    struct (ctxt :> TranslationContext, factory :> RegisterFactory)
  | Architecture.SH4 ->
    let ctxt = SH4.SH4TranslationContext isa
    let factory = SH4.SH4RegisterFactory (ctxt.RegExprs)
    struct (ctxt :> TranslationContext, factory :> RegisterFactory)
  | Architecture.SPARC ->
    let ctxt = SPARC.SPARCTranslationContext isa
    let factory = SPARC.SPARCRegisterFactory ()
    struct (ctxt :> TranslationContext, factory :> RegisterFactory)
  | _ -> Utils.futureFeature ()
