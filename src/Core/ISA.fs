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

namespace B2R2

/// Represents the Instruction Set Architecture (ISA).
type ISA(arch, endian, wordSize, flags) =
  do assert (arch <> Architecture.UnknownISA)

  /// CPU Architecture.
  member _.Arch with get (): Architecture = arch

  /// Endianness.
  member _.Endian with get (): Endian = endian

  /// Word size.
  member _.WordSize with get (): WordSize = wordSize

  /// Architecture-specific flags. Not every architecture has this.
  member _.Flags with get (): int = flags

  /// True if this ISA is Intel x86.
  member _.IsX86 with get () =
    arch = Architecture.Intel && wordSize = WordSize.Bit32

  /// True if this ISA is Intel x86-64.
  member _.IsX64 with get () =
    arch = Architecture.Intel && wordSize = WordSize.Bit64

  /// Constructs an ISA object with the given architecture, endianness, and
  /// word size. The flags are set to 0.
  new (arch, endian, wordSize) = ISA(arch, endian, wordSize, 0)

  /// Constructs an ISA object with the given architecture. The endianness and
  /// word size are set to the default values for the given architecture.
  new (arch) =
    match arch with
    | Architecture.Intel -> ISA(arch, Endian.Little, WordSize.Bit64)
    | Architecture.ARMv7 -> ISA(arch, Endian.Little, WordSize.Bit32)
    | Architecture.ARMv8 -> ISA(arch, Endian.Little, WordSize.Bit64)
    | Architecture.MIPS -> ISA(arch, Endian.Big, WordSize.Bit32)
    | Architecture.PPC -> ISA(arch, Endian.Big, WordSize.Bit32)
    | Architecture.RISCV -> ISA(arch, Endian.Little, WordSize.Bit64)
    | Architecture.SPARC -> ISA(arch, Endian.Big, WordSize.Bit64)
    | Architecture.S390 -> ISA(arch, Endian.Big, WordSize.Bit32)
    | Architecture.SH4 -> ISA(arch, Endian.Little, WordSize.Bit32)
    | Architecture.PARISC -> ISA(arch, Endian.Big, WordSize.Bit32)
    | Architecture.AVR -> ISA(arch, Endian.Little, WordSize.Bit8)
    | Architecture.TMS320C6000 -> ISA(arch, Endian.Little, WordSize.Bit32)
    | Architecture.EVM -> ISA(arch, Endian.Big, WordSize.Bit256)
    | Architecture.Python ->
      ISA(arch, Endian.Little, WordSize.Bit32, int PythonVersion.Python312)
    | Architecture.WASM -> ISA(arch, Endian.Little, WordSize.Bit32)
    | Architecture.CIL -> ISA(arch, Endian.Little, WordSize.Bit64)
    | _ -> ISA(Architecture.UnknownISA, Endian.Little, WordSize.Bit64)

  /// Constructs an ISA object with the given architecture and endianness. The
  /// word size is set to the default value for the given architecture and
  /// endianness.
  new (arch, endian) =
    match arch with
    | Architecture.Intel when endian = Endian.Little ->
      ISA(arch, endian, WordSize.Bit64)
    | Architecture.ARMv7 -> ISA(arch, endian, WordSize.Bit32)
    | Architecture.ARMv8 -> ISA(arch, endian, WordSize.Bit64)
    | Architecture.MIPS -> ISA(arch, endian, WordSize.Bit32)
    | Architecture.PPC when endian = Endian.Little ->
      ISA(arch, endian, WordSize.Bit32)
    | Architecture.RISCV -> ISA(arch, endian, WordSize.Bit64)
    | Architecture.SPARC -> ISA(arch, endian, WordSize.Bit64)
    | Architecture.S390 -> ISA(arch, endian, WordSize.Bit32)
    | Architecture.SH4 -> ISA(arch, endian, WordSize.Bit32)
    | Architecture.PARISC when endian = Endian.Big ->
      ISA(arch, endian, WordSize.Bit32)
    | Architecture.AVR -> ISA(arch, endian, WordSize.Bit8)
    | Architecture.TMS320C6000 -> ISA(arch, endian, WordSize.Bit32)
    | Architecture.EVM -> ISA(arch, endian, WordSize.Bit256)
    | Architecture.Python -> ISA(arch, endian, WordSize.Bit32)
    | Architecture.WASM -> ISA(arch, endian, WordSize.Bit32)
    | Architecture.CIL -> ISA(arch, endian, WordSize.Bit64)
    | _ -> ISA(Architecture.UnknownISA, endian, WordSize.Bit64)

  /// Constructs an ISA object with the given architecture and word size. The
  /// endianness is set to the default value for the given architecture.
  new (arch, wordSize) =
    match arch with
    | Architecture.Intel when wordSize = WordSize.Bit32
                           || wordSize = WordSize.Bit64 ->
      ISA(arch, Endian.Little, wordSize)
    | Architecture.ARMv7 when wordSize = WordSize.Bit32 ->
      ISA(arch, Endian.Little, wordSize)
    | Architecture.ARMv8 when wordSize = WordSize.Bit32
                           || wordSize = WordSize.Bit64 ->
      ISA(arch, Endian.Little, wordSize)
    | Architecture.MIPS when wordSize = WordSize.Bit32
                          || wordSize = WordSize.Bit64 ->
      ISA(arch, Endian.Big, wordSize)
    | Architecture.PPC when wordSize = WordSize.Bit32
                         || wordSize = WordSize.Bit64 ->
      ISA(arch, Endian.Big, wordSize)
    | Architecture.RISCV when wordSize = WordSize.Bit32
                           || wordSize = WordSize.Bit64
                           || wordSize = WordSize.Bit128 ->
      ISA(arch, Endian.Little, wordSize)
    | Architecture.SPARC when wordSize = WordSize.Bit32
                           || wordSize = WordSize.Bit64 ->
      ISA(arch, Endian.Big, wordSize)
    | Architecture.S390 when wordSize = WordSize.Bit32
                          || wordSize = WordSize.Bit64 ->
      ISA(arch, Endian.Big, wordSize)
    | Architecture.SH4 when wordSize = WordSize.Bit32
                         || wordSize = WordSize.Bit64 ->
      ISA(arch, Endian.Little, wordSize)
    | Architecture.PARISC when wordSize = WordSize.Bit32
                            || wordSize = WordSize.Bit64 ->
      ISA(arch, Endian.Big, wordSize)
    | Architecture.AVR when wordSize = WordSize.Bit8 ->
      ISA(arch, Endian.Little, wordSize)
    | Architecture.TMS320C6000 when wordSize = WordSize.Bit32 ->
      ISA(arch, Endian.Little, wordSize)
    | Architecture.EVM when wordSize = WordSize.Bit256 ->
      ISA(arch, Endian.Big, wordSize)
    | Architecture.Python -> ISA(arch, Endian.Little, wordSize)
    | Architecture.WASM -> ISA(arch, Endian.Little, wordSize)
    | Architecture.CIL -> ISA(arch, Endian.Little, wordSize)
    | _ -> ISA(Architecture.UnknownISA, Endian.Little, wordSize)

  new (cilKind: CILKind) =
    let flag = int cilKind
    ISA(Architecture.CIL, Endian.Little, WordSize.Bit64, flag)

  new (pythonVer: PythonVersion) =
    let flag = int pythonVer
    ISA(Architecture.Python, Endian.Little, WordSize.Bit64, flag)

  static member OfString(s: string) =
    match s.ToLowerInvariant() with
    | "x86" | "i386" ->
      ISA(Architecture.Intel, WordSize.Bit32)
    | "x64" | "x86-64" | "amd64" ->
      ISA(Architecture.Intel, WordSize.Bit64)
    | "armv7" | "armv7le" | "armel" | "armhf" ->
      ISA Architecture.ARMv7
    | "armv7be" ->
      ISA(Architecture.ARMv7, Endian.Big)
    | "armv8a32" | "aarch32" ->
      ISA(Architecture.ARMv8, WordSize.Bit32)
    | "armv8a32be" | "aarch32be" ->
      ISA(Architecture.ARMv8, Endian.Big, WordSize.Bit32)
    | "armv8a64" | "aarch64"->
      ISA Architecture.ARMv8
    | "armv8a64be" | "aarch64be" ->
      ISA(Architecture.ARMv8, Endian.Big)
    | "mipsel" | "mips32" | "mips32le" ->
      ISA(Architecture.MIPS, Endian.Little, WordSize.Bit32)
    | "mips32" | "mips32be" ->
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    | "mips64el" | "mips64" | "mips64le" ->
      ISA(Architecture.MIPS, Endian.Little, WordSize.Bit64)
    | "mips64be" ->
      ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)
    | "ppc32le" ->
      ISA(Architecture.PPC, Endian.Little, WordSize.Bit32)
    | "ppc32" | "ppc32be" ->
      ISA(Architecture.PPC, Endian.Big, WordSize.Bit32)
    | "riscv64" ->
      ISA(Architecture.RISCV, Endian.Little, WordSize.Bit64)
    | "sparc" | "sparc64" ->
      ISA(Architecture.SPARC, Endian.Big)
    | "s390" ->
      ISA(Architecture.S390, WordSize.Bit32)
    | "s390x" ->
      ISA(Architecture.S390, WordSize.Bit64)
    | "sh4" ->
      ISA(Architecture.SH4, Endian.Little)
    | "sh4be" ->
      ISA(Architecture.SH4, Endian.Big)
    | "parisc" | "hppa" | "hppa32" ->
      ISA(Architecture.PARISC, WordSize.Bit32)
    | "parisc64" | "hppa64" ->
      ISA(Architecture.PARISC, WordSize.Bit64)
    | "avr" | "avr8" ->
      ISA Architecture.AVR
    | "tms320c6000" ->
      ISA Architecture.TMS320C6000
    | "evm" ->
      ISA Architecture.EVM
    | "cil" ->
      ISA CILKind.CILOnly
    | "cil-x86" ->
      ISA CILKind.CILx86
    | "cil-x64" ->
      ISA CILKind.CILx64
    | "python3.8" ->
      ISA PythonVersion.Python308
    | "python3.9" ->
      ISA PythonVersion.Python309
    | "python3.10" ->
      ISA PythonVersion.Python310
    | "python3.11" ->
      ISA PythonVersion.Python311
    | "python3.12" ->
      ISA PythonVersion.Python312
    | "python3.13" ->
      ISA PythonVersion.Python313
    | "python3.14" ->
      ISA PythonVersion.Python314
    | "python3.15" ->
      ISA PythonVersion.Python315
    | "wasm" ->
      ISA Architecture.WASM
    | _ -> raise InvalidISAException

  override _.ToString() =
    match arch, endian, wordSize with
    | Architecture.Intel, _, WordSize.Bit32 -> "x86"
    | Architecture.Intel, _, WordSize.Bit64 -> "x86-64"
    | Architecture.ARMv7, Endian.Little, _ -> "armv7"
    | Architecture.ARMv7, Endian.Big, _ -> "armv7be"
    | Architecture.ARMv8, Endian.Little, WordSize.Bit32 -> "aarch32"
    | Architecture.ARMv8, Endian.Big, WordSize.Bit32 -> "aarch32be"
    | Architecture.ARMv8, Endian.Little, WordSize.Bit64 -> "aarch64"
    | Architecture.ARMv8, Endian.Big, WordSize.Bit64 -> "aarch64be"
    | Architecture.MIPS, Endian.Little, WordSize.Bit32 -> "mips32le"
    | Architecture.MIPS, Endian.Big, WordSize.Bit32 -> "mips32"
    | Architecture.MIPS, Endian.Little, WordSize.Bit64 -> "mips64le"
    | Architecture.MIPS, Endian.Big, WordSize.Bit64 -> "mips64"
    | Architecture.PPC, Endian.Little, WordSize.Bit32 -> "ppc32le"
    | Architecture.PPC, Endian.Big, WordSize.Bit32 -> "ppc32"
    | Architecture.RISCV, Endian.Little, WordSize.Bit64 -> "riscv64"
    | Architecture.SPARC, Endian.Big, WordSize.Bit64 -> "sparc64"
    | Architecture.S390, Endian.Big, WordSize.Bit32 -> "s390"
    | Architecture.S390, Endian.Big, WordSize.Bit64 -> "s390x"
    | Architecture.SH4, Endian.Little, WordSize.Bit32 -> "sh4"
    | Architecture.SH4, Endian.Big, WordSize.Bit32 -> "sh4be"
    | Architecture.PARISC, Endian.Big, WordSize.Bit32 -> "parisc"
    | Architecture.PARISC, Endian.Big, WordSize.Bit64 -> "parisc64"
    | Architecture.AVR, _, _ -> "avr"
    | Architecture.TMS320C6000, _, _ -> "tms320c6000"
    | Architecture.EVM, _, _ -> "evm"
    | Architecture.Python, _, _ ->
      match LanguagePrimitives.EnumOfValue flags with
      | PythonVersion.Python308 -> "python3.8"
      | PythonVersion.Python309 -> "python3.9"
      | PythonVersion.Python310 -> "python3.10"
      | PythonVersion.Python311 -> "python3.11"
      | PythonVersion.Python312 -> "python3.12"
      | PythonVersion.Python313 -> "python3.13"
      | PythonVersion.Python314 -> "python3.14"
      | PythonVersion.Python315 -> "python3.15"
      | _ -> raise InvalidISAException
    | Architecture.WASM, _, _ -> "wasm"
    | Architecture.CIL, _, _ ->
      match LanguagePrimitives.EnumOfValue flags with
      | CILKind.CILOnly -> "cil"
      | CILKind.CILx86 -> "cil-x86"
      | CILKind.CILx64 -> "cil-x64"
      | _ -> raise InvalidISAException
    | _ -> raise InvalidISAException

/// Represents the kind of CIL code: only CIL, CIL for x86, or CIL for x64.
and CILKind =
  /// Only CIL code.
  | CILOnly = 0
  /// CIL code for x86.
  | CILx86 = 1
  /// CIL code for x86-64.
  | CILx64 = 2

/// Represents the Python version.
and PythonVersion =
  /// Python 3.8.
  | Python308 = 308
  /// Python 3.9.
  | Python309 = 309
  /// Python 3.10.
  | Python310 = 310
  /// Python 3.11.
  | Python311 = 311
  /// Python 3.12.
  | Python312 = 312
  /// Python 3.13.
  | Python313 = 313
  /// Python 3.14.
  | Python314 = 314
  /// Python 3.15.
  | Python315 = 315

/// Provides active patterns for matching against specific ISAs.
[<AutoOpen>]
module ISA =
  [<return: Struct>]
  let (|X86|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.Intel, WordSize.Bit32 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|X64|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.Intel, WordSize.Bit64 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|Intel|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.Intel -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|ARMv7|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.ARMv7 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|ARM32|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.ARMv7, _
    | Architecture.ARMv8, WordSize.Bit32 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|AArch64|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.ARMv8, WordSize.Bit64 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|MIPS|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.MIPS -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|MIPS32|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.MIPS, WordSize.Bit32 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|MIPS64|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.MIPS, WordSize.Bit32 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|PPC32|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.PPC, WordSize.Bit32 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|RISCV64|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.RISCV, WordSize.Bit64 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|SPARC|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.SPARC -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|S390|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.S390 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|SH4|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.SH4 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|PARISC|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.PARISC -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|AVR|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.AVR -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|TMS320C6000|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.TMS320C6000 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|EVM|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.EVM -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|WASM|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.WASM -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|Python|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.Python -> ValueSome()
    | _ -> ValueNone
