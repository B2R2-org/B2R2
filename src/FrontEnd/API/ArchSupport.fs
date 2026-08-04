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
open B2R2.FrontEnd.BinFile

/// <namespacedoc>
///   <summary>
///   Contains the APIs for the B2R2 front-end, which is responsible for
///   parsing, disassembling, and lifting binaries.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Provides functions to create the architecture-specific components of the
/// B2R2 front-end, such as register factories, parsers, and IR builders. This
/// is used by <see cref='T:B2R2.FrontEnd.BinHandle'/> internally, and hence, it
/// is recommended to use <see cref='T:B2R2.FrontEnd.BinHandle'/> instead, in
/// most cases.
/// </summary>
[<RequireQualifiedAccess>]
module ArchSupport =
  /// Creates a new architecture-specific register factory for the given
  /// architecture.
  [<CompiledName "CreateRegisterFactory">]
  let createRegisterFactory isa =
    match isa with
    | Intel -> Intel.RegisterFactory isa :> IRegisterFactory
    | ARM32 -> ARM32.RegisterFactory isa :> IRegisterFactory
    | AArch64 -> ARM64.RegisterFactory isa :> IRegisterFactory
    | MIPS -> MIPS.RegisterFactory isa :> IRegisterFactory
    | TMS320C6000 -> TMS320C6000.RegisterFactory isa :> IRegisterFactory
    | AVR -> AVR.RegisterFactory isa :> IRegisterFactory
    | S390 -> S390.RegisterFactory isa :> IRegisterFactory
    | SH4 -> SH4.RegisterFactory isa :> IRegisterFactory
    | PPC -> PPC.RegisterFactory isa :> IRegisterFactory
    | RISCV64 -> RISCV64.RegisterFactory isa :> IRegisterFactory
    | SPARC -> SPARC.RegisterFactory isa :> IRegisterFactory
    | PARISC -> PARISC.RegisterFactory isa :> IRegisterFactory
    | M68K -> M68K.RegisterFactory isa :> IRegisterFactory
    | EVM -> EVM.RegisterFactory isa :> IRegisterFactory
    | Python -> Python.RegisterFactory isa :> IRegisterFactory
    | CIL -> CIL.RegisterFactory isa :> IRegisterFactory
    | WASM -> WASM.RegisterFactory() :> IRegisterFactory
    | _ -> Terminator.futureFeature ()

  /// Creates a new parser (IInstructionParsable) for the given architecture.
  [<CompiledName "CreateParser">]
  let createParser reader (isa: ISA) =
    match isa with
    | Intel ->
      Intel.IntelParser(isa.WordSize, reader) :> IInstructionParsable
    | ARM32 ->
      let isThumb = isa.ARM32Mode = ARM32Mode.Thumb
      ARM32.ARM32Parser(isa, isThumb, reader) :> IInstructionParsable
    | AArch64 ->
      ARM64.ARM64Parser(reader) :> IInstructionParsable
    | MIPS ->
      MIPS.MIPSParser(isa, reader) :> IInstructionParsable
    | EVM ->
      EVM.EVMParser(isa) :> IInstructionParsable
    | TMS320C6000 ->
      TMS320C6000.TMS320C6000Parser(reader) :> IInstructionParsable
    | AVR ->
      AVR.AVRParser(reader) :> IInstructionParsable
    | S390 ->
      S390.S390Parser(isa, reader) :> IInstructionParsable
    | SH4 ->
      SH4.SH4Parser(reader) :> IInstructionParsable
    | PPC ->
      PPC.PPCParser(isa.WordSize, reader) :> IInstructionParsable
    | RISCV64 ->
      RISCV64.RISCV64Parser(isa, reader) :> IInstructionParsable
    | SPARC ->
      SPARC.SPARCParser(reader) :> IInstructionParsable
    | PARISC ->
      PARISC.PARISCParser(isa, reader) :> IInstructionParsable
    | M68K ->
      M68K.M68KParser(isa, reader) :> IInstructionParsable
    | _ ->
      Terminator.futureFeature ()

  /// Creates a new parser (IInstructionParsable) for the given file.
  [<CompiledName "CreateParser">]
  let createParserForFile (binFile: IBinFile) =
    match binFile.ISA with
    | Python ->
      Python.PythonParser(binFile, binFile.Reader) :> IInstructionParsable
    | _ ->
      createParser binFile.Reader binFile.ISA

  /// Creates a new LowUIR builder for the given architecture.
  [<CompiledName "CreateBuilder">]
  let createBuilder isa regFactory =
    let stream = LowUIRStream()
    match isa with
    | Intel -> Intel.LowUIRBuilder(isa, regFactory, stream) :> ILowUIRBuilder
    | MIPS -> MIPS.LowUIRBuilder(isa, regFactory, stream) :> ILowUIRBuilder
    | SPARC -> SPARC.LowUIRBuilder(isa, regFactory, stream) :> ILowUIRBuilder
    | SH4 -> SH4.LowUIRBuilder(isa, regFactory, stream) :> ILowUIRBuilder
    | _ -> ILowUIRBuilder.Default(isa, regFactory, stream)
