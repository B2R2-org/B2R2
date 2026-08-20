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

/// Raised when an invalid ISA is given as a parameter.
exception InvalidISAException

/// <summary>
/// Represents the Instruction Set Architecture (ISA).
/// </summary>
/// <param name="arch">CPU architecture. Raises <see
/// cref='T:B2R2.InvalidISAException'/> if <see
/// cref='F:B2R2.Architecture.UnknownISA'/> is given.</param>
/// <param name="endian">Endianness.</param>
/// <param name="wordSize">Word size in bits.</param>
/// <param name="flags">Architecture-specific flags (e.g., CIL kind, Python
/// version). Use 0 if not applicable.</param>
type ISA(arch, endian, wordSize, flags) =
  do
    if arch = Architecture.UnknownISA then raise InvalidISAException else ()

  /// Constructs an ISA object with the given architecture, endianness, and
  /// word size. The flags are set to 0.
  new(arch, endian, wordSize) = ISA(arch, endian, wordSize, 0)

  /// Constructs an ISA object with the given architecture. The endianness and
  /// word size are set to the default values for the given architecture. Raises
  /// <see cref='T:B2R2.InvalidISAException'/> if the architecture is not
  /// recognized.
  new(arch) =
    match arch with
    | Architecture.Intel ->
      ISA(arch, Endian.Little, WordSize.Bit64)
    | Architecture.ARMv7 ->
      ISA(arch, Endian.Little, WordSize.Bit32)
    | Architecture.ARMv8 ->
      ISA(arch, Endian.Little, WordSize.Bit64)
    | Architecture.MIPS ->
      ISA(arch, Endian.Big, WordSize.Bit32)
    | Architecture.PPC ->
      ISA(arch, Endian.Big, WordSize.Bit32)
    | Architecture.RISCV ->
      ISA(arch, Endian.Little, WordSize.Bit64)
    | Architecture.SPARC ->
      ISA(arch, Endian.Big, WordSize.Bit64)
    | Architecture.S390 ->
      ISA(arch, Endian.Big, WordSize.Bit64)
    | Architecture.SH4 ->
      ISA(arch, Endian.Little, WordSize.Bit32)
    | Architecture.PARISC ->
      ISA(arch, Endian.Big, WordSize.Bit32)
    | Architecture.M68K ->
      ISA(arch, Endian.Big, WordSize.Bit32, int M68KModel.M68020)
    | Architecture.AVR ->
      ISA(arch, Endian.Little, WordSize.Bit8)
    | Architecture.TMS320C6000 ->
      ISA(arch, Endian.Little, WordSize.Bit32)
    | Architecture.EVM ->
      ISA(arch, Endian.Big, WordSize.Bit256)
    | Architecture.Python ->
      ISA(arch, Endian.Little, WordSize.Bit64, int PythonVersion.Python312)
    | Architecture.WASM ->
      ISA(arch, Endian.Little, WordSize.Bit32)
    | Architecture.CIL ->
      ISA(arch, Endian.Little, WordSize.Bit64)
    | _ ->
      ISA(Architecture.UnknownISA, Endian.Little, WordSize.Bit64)

  /// Constructs an ISA object with the given architecture and endianness. The
  /// word size is set to the default value for the given architecture and
  /// endianness. Raises <see cref='T:B2R2.InvalidISAException'/> if the
  /// combination is not recognized.
  new(arch, endian) =
    match arch with
    | Architecture.Intel when endian = Endian.Little ->
      ISA(arch, endian, WordSize.Bit64)
    | Architecture.ARMv7 ->
      ISA(arch, endian, WordSize.Bit32)
    | Architecture.ARMv8 ->
      ISA(arch, endian, WordSize.Bit64)
    | Architecture.MIPS ->
      ISA(arch, endian, WordSize.Bit32)
    | Architecture.PPC when endian = Endian.Little ->
      ISA(arch, endian, WordSize.Bit32)
    | Architecture.RISCV ->
      ISA(arch, endian, WordSize.Bit64)
    | Architecture.SPARC ->
      ISA(arch, endian, WordSize.Bit64)
    | Architecture.S390 ->
      ISA(arch, endian, WordSize.Bit64)
    | Architecture.SH4 ->
      ISA(arch, endian, WordSize.Bit32)
    | Architecture.PARISC when endian = Endian.Big ->
      ISA(arch, endian, WordSize.Bit32)
    | Architecture.M68K when endian = Endian.Big ->
      ISA(arch, endian, WordSize.Bit32, int M68KModel.M68020)
    | Architecture.AVR ->
      ISA(arch, endian, WordSize.Bit8)
    | Architecture.TMS320C6000 ->
      ISA(arch, endian, WordSize.Bit32)
    | Architecture.EVM ->
      ISA(arch, endian, WordSize.Bit256)
    | Architecture.Python ->
      ISA(arch, endian, WordSize.Bit64)
    | Architecture.WASM ->
      ISA(arch, endian, WordSize.Bit32)
    | Architecture.CIL ->
      ISA(arch, endian, WordSize.Bit64)
    | _ ->
      ISA(Architecture.UnknownISA, endian, WordSize.Bit64)

  /// Constructs an ISA object with the given architecture and word size. The
  /// endianness is set to the default value for the given architecture. Raises
  /// <see cref='T:B2R2.InvalidISAException'/> if the combination is not
  /// recognized.
  new(arch, wordSize) =
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
    | Architecture.M68K when wordSize = WordSize.Bit32 ->
      ISA(arch, Endian.Big, wordSize, int M68KModel.M68020)
    | Architecture.AVR when wordSize = WordSize.Bit8 ->
      ISA(arch, Endian.Little, wordSize)
    | Architecture.TMS320C6000 when wordSize = WordSize.Bit32 ->
      ISA(arch, Endian.Little, wordSize)
    | Architecture.EVM when wordSize = WordSize.Bit256 ->
      ISA(arch, Endian.Big, wordSize)
    | Architecture.Python ->
      ISA(arch, Endian.Little, wordSize)
    | Architecture.WASM ->
      ISA(arch, Endian.Little, wordSize)
    | Architecture.CIL ->
      ISA(arch, Endian.Little, wordSize)
    | _ ->
      ISA(Architecture.UnknownISA, Endian.Little, wordSize)

  /// Constructs an ISA object for the given CIL kind.
  new(cilKind: CILKind) =
    let flag = int cilKind
    ISA(Architecture.CIL, Endian.Little, WordSize.Bit64, flag)

  /// Constructs an ISA object for the given Python version.
  new(pythonVer: PythonVersion) =
    let flag = int pythonVer
    ISA(Architecture.Python, Endian.Little, WordSize.Bit64, flag)

  /// Constructs an ISA object for the given member of the 68000 family.
  new(m68kModel: M68KModel) =
    let flag = int m68kModel
    ISA(Architecture.M68K, Endian.Big, WordSize.Bit32, flag)

  /// Constructs an ISA object for the given AVR core.
  new(avrCore: AVRCore) =
    let flag = int avrCore
    ISA(Architecture.AVR, Endian.Little, WordSize.Bit8, flag)

  /// Constructs an ISA object for the given AVR core and program memory size,
  /// which must be a power of two. Only a loader that has read the part out of
  /// an image knows the size; without it a relative branch cannot wrap.
  new(avrCore: AVRCore, programSize: uint64) =
    let mutable log2 = 0
    while programSize >>> (log2 + 1) <> 0UL do log2 <- log2 + 1
    let flag = int avrCore ||| (if programSize = 0UL then 0 else log2 <<< 8)
    ISA(Architecture.AVR, Endian.Little, WordSize.Bit8, flag)

  /// Constructs a 32-bit ARM ISA meaning the given instruction set, which is
  /// AArch32 if isAArch32 says so and ARMv7 otherwise. Only those two have the
  /// instruction sets a mode chooses between, so this names neither an
  /// architecture nor a word size that could be something else.
  new(endian, isAArch32: bool, mode: ARM32Mode) =
    let arch = if isAArch32 then Architecture.ARMv8 else Architecture.ARMv7
    ISA(arch, endian, WordSize.Bit32, int mode)

  /// Constructs an ISA object from a canonical ISA name string such as "x86",
  /// "x86-64", "aarch64", "mips32le", etc. Raises <see
  /// cref='T:B2R2.InvalidISAException'/> if the string is not recognized.
  new(isaName: string) =
    match isaName.ToLowerInvariant() with
    | "x86" | "i386" ->
      ISA(Architecture.Intel, WordSize.Bit32)
    | "x64" | "x86-64" | "amd64" ->
      ISA(Architecture.Intel, WordSize.Bit64)
    | "armv7" | "armv7le" | "armel" | "armhf" | "arm32" | "arm" ->
      ISA Architecture.ARMv7
    | "armv7be" ->
      ISA(Architecture.ARMv7, Endian.Big)
    | "thumb" | "t32" ->
      ISA(Endian.Little, false, ARM32Mode.Thumb)
    | "thumbbe" | "t32be" ->
      ISA(Endian.Big, false, ARM32Mode.Thumb)
    | "armv8a32" | "aarch32" ->
      ISA(Architecture.ARMv8, WordSize.Bit32)
    | "armv8a32be" | "aarch32be" ->
      ISA(Architecture.ARMv8, Endian.Big, WordSize.Bit32)
    | "aarch32t" ->
      ISA(Endian.Little, true, ARM32Mode.Thumb)
    | "aarch32tbe" ->
      ISA(Endian.Big, true, ARM32Mode.Thumb)
    | "armv8a64" | "aarch64" | "arm64" ->
      ISA Architecture.ARMv8
    | "armv8a64be" | "aarch64be" ->
      ISA(Architecture.ARMv8, Endian.Big)
    | "mipsel" | "mips32le" ->
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
    | "ppc64le" ->
      ISA(Architecture.PPC, Endian.Little, WordSize.Bit64)
    | "ppc64" | "ppc64be" ->
      ISA(Architecture.PPC, Endian.Big, WordSize.Bit64)
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
    | "m68k" | "68k" ->
      ISA M68KModel.M68020
    | "m68000" | "68000" ->
      ISA M68KModel.M68000
    | "m68010" | "68010" ->
      ISA M68KModel.M68010
    | "m68020" | "68020" ->
      ISA M68KModel.M68020
    | "m68030" | "68030" ->
      ISA M68KModel.M68030
    | "m68040" | "68040" ->
      ISA M68KModel.M68040
    | "m68060" | "68060" ->
      ISA M68KModel.M68060
    | "avr" | "avr8" ->
      ISA Architecture.AVR
    | "avr6" ->
      ISA AVRCore.Avr6
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
    (* The bare name takes the default version, the way "m68k" takes a default
       model, so that an input whose version is not the point does not have to
       name one. *)
    | "python" ->
      ISA Architecture.Python
    | "python3.0" ->
      ISA PythonVersion.Python300
    | "python3.1" ->
      ISA PythonVersion.Python301
    | "python3.2" ->
      ISA PythonVersion.Python302
    | "python3.3" ->
      ISA PythonVersion.Python303
    | "python3.4" ->
      ISA PythonVersion.Python304
    | "python3.5" ->
      ISA PythonVersion.Python305
    | "python3.6" ->
      ISA PythonVersion.Python306
    | "python3.7" ->
      ISA PythonVersion.Python307
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
    | _ ->
      ISA Architecture.UnknownISA

  /// CPU Architecture.
  member _.Arch with get(): Architecture = arch

  /// Endianness.
  member _.Endian with get(): Endian = endian

  /// Word size.
  member _.WordSize with get(): WordSize = wordSize

  /// Architecture-specific flags. Not every architecture has this.
  member _.Flags with get(): int = flags

  /// The instruction set a 32-bit ARM ISA means, which is A32 unless the flags
  /// say otherwise. Only 32-bit ARM has two of them, so this says nothing about
  /// any other architecture.
  member _.ARM32Mode with get(): ARM32Mode =
    LanguagePrimitives.EnumOfValue flags

  /// The member of the 68000 family an m68k ISA means, which is the 68020
  /// unless the flags say otherwise. The family shares one encoding space and a
  /// later model reads encodings an earlier one rejects, so nothing but this
  /// says what a halfword of m68k code belongs to.
  member _.M68KModel with get(): M68KModel =
    LanguagePrimitives.EnumOfValue flags

  /// How wide the program counter of an AVR ISA's core is, which is two bytes
  /// unless the flags say otherwise. Only AVR has cores that differ in this, so
  /// this says nothing about any other architecture.
  member _.AVRCore with get(): AVRCore =
    LanguagePrimitives.EnumOfValue(flags &&& 0xff)

  /// How many bytes of program memory an AVR part has, or zero when nothing
  /// said. A relative branch on AVR wraps around the end of program memory --
  /// which is how the reset vector reaches startup code sitting at the top of
  /// it -- so this is what the wrap is taken modulo of. It is always a power of
  /// two, and the flags hold its base-two logarithm.
  member _.AVRProgramSize with get() =
    match (flags >>> 8) &&& 0xff with
    | 0 -> 0UL
    | log2 -> 1UL <<< log2

  /// Returns true if this ISA is Intel x86.
  member _.IsX86 with get() =
    arch = Architecture.Intel && wordSize = WordSize.Bit32

  /// Returns true if this ISA is Intel x86-64.
  member _.IsX64 with get() =
    arch = Architecture.Intel && wordSize = WordSize.Bit64

  /// Returns true if this ISA is ARMv7 (any endianness).
  member _.IsARMv7 with get() = arch = Architecture.ARMv7

  /// Returns true if this ISA is 32-bit ARM (ARMv7 or AArch32).
  member _.IsARM32 with get() =
    arch = Architecture.ARMv7
    || (arch = Architecture.ARMv8 && wordSize = WordSize.Bit32)

  /// Returns true if this ISA is AArch64.
  member _.IsAArch64 with get() =
    arch = Architecture.ARMv8 && wordSize = WordSize.Bit64

  /// Returns true if this ISA is MIPS (any word size or endianness).
  member _.IsMIPS with get() = arch = Architecture.MIPS

  /// Returns true if this ISA is 32-bit MIPS.
  member _.IsMIPS32 with get() =
    arch = Architecture.MIPS && wordSize = WordSize.Bit32

  /// Returns true if this ISA is 64-bit MIPS.
  member _.IsMIPS64 with get() =
    arch = Architecture.MIPS && wordSize = WordSize.Bit64

  /// Returns true if this ISA is PowerPC (any word size or endianness).
  member _.IsPPC with get() = arch = Architecture.PPC

  /// Returns true if this ISA is 32-bit PowerPC.
  member _.IsPPC32 with get() =
    arch = Architecture.PPC && wordSize = WordSize.Bit32

  /// Returns true if this ISA is RISC-V 64-bit.
  member _.IsRISCV64 with get() =
    arch = Architecture.RISCV && wordSize = WordSize.Bit64

  /// Returns true if this ISA is SPARC (any word size).
  member _.IsSPARC with get() = arch = Architecture.SPARC

  /// Returns true if this ISA is IBM System/390 (any word size).
  member _.IsS390 with get() = arch = Architecture.S390

  /// Returns true if this ISA is SH4.
  member _.IsSH4 with get() = arch = Architecture.SH4

  /// Returns true if this ISA is PA-RISC (any word size).
  member _.IsPARISC with get() = arch = Architecture.PARISC

  /// Returns true if this ISA is Motorola 68000 series (any model).
  member _.IsM68K with get() = arch = Architecture.M68K

  /// Returns true if this ISA is AVR.
  member _.IsAVR with get() = arch = Architecture.AVR

  /// Returns true if this ISA is TMS320C6000.
  member _.IsTMS320C6000 with get() = arch = Architecture.TMS320C6000

  /// Returns true if this ISA is Ethereum Virtual Machine (EVM).
  member _.IsEVM with get() = arch = Architecture.EVM

  /// Returns true if this ISA is WebAssembly (WASM).
  member _.IsWASM with get() = arch = Architecture.WASM

  /// Returns true if this ISA is Python bytecode.
  member _.IsPython with get() = arch = Architecture.Python

  /// Returns true if this ISA is Common Intermediate Language (CIL).
  member _.IsCIL with get() = arch = Architecture.CIL

  override this.ToString() =
    let thumb = this.ARM32Mode = ARM32Mode.Thumb
    match arch, endian, wordSize with
    | Architecture.Intel, _, WordSize.Bit32 ->
      "x86"
    | Architecture.Intel, _, WordSize.Bit64 ->
      "x86-64"
    | Architecture.ARMv7, Endian.Little, _ ->
      if thumb then "thumb" else "armv7"
    | Architecture.ARMv7, Endian.Big, _ ->
      if thumb then "thumbbe" else "armv7be"
    | Architecture.ARMv8, Endian.Little, WordSize.Bit32 ->
      if thumb then "aarch32t" else "aarch32"
    | Architecture.ARMv8, Endian.Big, WordSize.Bit32 ->
      if thumb then "aarch32tbe" else "aarch32be"
    | Architecture.ARMv8, Endian.Little, WordSize.Bit64 ->
      "aarch64"
    | Architecture.ARMv8, Endian.Big, WordSize.Bit64 ->
      "aarch64be"
    | Architecture.MIPS, Endian.Little, WordSize.Bit32 ->
      "mips32le"
    | Architecture.MIPS, Endian.Big, WordSize.Bit32 ->
      "mips32"
    | Architecture.MIPS, Endian.Little, WordSize.Bit64 ->
      "mips64le"
    | Architecture.MIPS, Endian.Big, WordSize.Bit64 ->
      "mips64"
    | Architecture.PPC, Endian.Little, WordSize.Bit32 ->
      "ppc32le"
    | Architecture.PPC, Endian.Big, WordSize.Bit32 ->
      "ppc32"
    | Architecture.PPC, Endian.Little, WordSize.Bit64 ->
      "ppc64le"
    | Architecture.PPC, Endian.Big, WordSize.Bit64 ->
      "ppc64"
    | Architecture.RISCV, Endian.Little, WordSize.Bit64 ->
      "riscv64"
    | Architecture.SPARC, Endian.Big, WordSize.Bit64 ->
      "sparc64"
    | Architecture.S390, Endian.Big, WordSize.Bit32 ->
      "s390"
    | Architecture.S390, Endian.Big, WordSize.Bit64 ->
      "s390x"
    | Architecture.SH4, Endian.Little, WordSize.Bit32 ->
      "sh4"
    | Architecture.SH4, Endian.Big, WordSize.Bit32 ->
      "sh4be"
    | Architecture.PARISC, Endian.Big, WordSize.Bit32 ->
      "parisc"
    | Architecture.PARISC, Endian.Big, WordSize.Bit64 ->
      "parisc64"
    | Architecture.M68K, _, _ ->
      match LanguagePrimitives.EnumOfValue flags with
      | M68KModel.M68000 -> "m68000"
      | M68KModel.M68010 -> "m68010"
      | M68KModel.M68020 -> "m68020"
      | M68KModel.M68030 -> "m68030"
      | M68KModel.M68040 -> "m68040"
      | M68KModel.M68060 -> "m68060"
      | _ -> raise InvalidISAException
    | Architecture.AVR, _, _ ->
      "avr"
    | Architecture.TMS320C6000, _, _ ->
      "tms320c6000"
    | Architecture.EVM, _, _ ->
      "evm"
    | Architecture.Python, _, _ ->
      match LanguagePrimitives.EnumOfValue flags with
      | PythonVersion.Python300 -> "python3.0"
      | PythonVersion.Python301 -> "python3.1"
      | PythonVersion.Python302 -> "python3.2"
      | PythonVersion.Python303 -> "python3.3"
      | PythonVersion.Python304 -> "python3.4"
      | PythonVersion.Python305 -> "python3.5"
      | PythonVersion.Python306 -> "python3.6"
      | PythonVersion.Python307 -> "python3.7"
      | PythonVersion.Python308 -> "python3.8"
      | PythonVersion.Python309 -> "python3.9"
      | PythonVersion.Python310 -> "python3.10"
      | PythonVersion.Python311 -> "python3.11"
      | PythonVersion.Python312 -> "python3.12"
      | PythonVersion.Python313 -> "python3.13"
      | PythonVersion.Python314 -> "python3.14"
      | PythonVersion.Python315 -> "python3.15"
      | _ -> raise InvalidISAException
    | Architecture.WASM, _, _ ->
      "wasm"
    | Architecture.CIL, _, _ ->
      match LanguagePrimitives.EnumOfValue flags with
      | CILKind.CILOnly -> "cil"
      | CILKind.CILx86 -> "cil-x86"
      | CILKind.CILx64 -> "cil-x64"
      | _ -> raise InvalidISAException
    | _ ->
      raise InvalidISAException

/// Represents the kind of CIL code: only CIL, CIL for x86, or CIL for x64.
and CILKind =
  /// Only CIL code.
  | CILOnly = 0
  /// CIL code for x86.
  | CILx86 = 1
  /// CIL code for x86-64.
  | CILx64 = 2

/// Represents which of the two instruction sets a 32-bit ARM ISA means. A
/// 32-bit ARM processor runs both, and nothing but the mode it is in says
/// which one a word belongs to.
and ARM32Mode =
  /// The A32 instruction set, whose instructions are one word each.
  | ARM = 0
  /// The T32 instruction set, whose instructions are one or two halfwords.
  | Thumb = 1

/// Represents which member of the 68000 family an m68k ISA means. The family
/// shares one encoding space, and a later model reads encodings an earlier one
/// rejects -- including addressing modes that change how long an instruction is
/// -- so nothing but the model says what a halfword of code belongs to.
and M68KModel =
  /// MC68000, MC68008, MC68HC000, MC68HC001, and MC68EC000.
  | M68000 = 0
  /// MC68010.
  | M68010 = 1
  /// MC68020 and MC68EC020.
  | M68020 = 2
  /// MC68030 and MC68EC030.
  | M68030 = 3
  /// MC68040, MC68EC040, and MC68LC040.
  | M68040 = 4
  /// MC68060, MC68EC060, and MC68LC060.
  | M68060 = 5

/// Represents how wide an AVR core's program counter is, which is the one way
/// the AVR cores differ that an instruction's encoding does not already settle.
/// avr6 -- the cores reaching more than 128 KiB of program memory -- needs
/// three bytes of program counter, so a call there pushes three bytes of return
/// address where every earlier core pushes two, and a frame laid out for the
/// wrong one puts every saved register at the wrong offset. The finer core
/// levels (avr2, avr25, avr51, ...) differ only in which instructions they
/// have, which the decoder settles on its own, so nothing names them here.
and AVRCore =
  /// Every core up to avr51, whose program counter fits in two bytes. This is
  /// also what a raw image reports, having nothing to say which core it is for.
  | Classic = 0
  /// avr6, whose program counter needs three bytes.
  | Avr6 = 1

/// Represents the Python version.
and PythonVersion =
  /// Python 3.0.
  | Python300 = 300
  /// Python 3.1.
  | Python301 = 301
  /// Python 3.2.
  | Python302 = 302
  /// Python 3.3.
  | Python303 = 303
  /// Python 3.4.
  | Python304 = 304
  /// Python 3.5.
  | Python305 = 305
  /// Python 3.6
  | Python306 = 306
  /// Python 3.7
  | Python307 = 307
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

module PythonVersion =
  let minor (ver: PythonVersion) = int ver % 100

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
    | Architecture.MIPS, WordSize.Bit64 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|PPC|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.PPC -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|PPC32|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.PPC, WordSize.Bit32 -> ValueSome()
    | _ -> ValueNone

  [<return: Struct>]
  let (|PPC64|_|) (isa: ISA) =
    match isa.Arch, isa.WordSize with
    | Architecture.PPC, WordSize.Bit64 -> ValueSome()
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
  let (|M68K|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.M68K -> ValueSome()
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

  [<return: Struct>]
  let (|CIL|_|) (isa: ISA) =
    match isa.Arch with
    | Architecture.CIL -> ValueSome()
    | _ -> ValueNone
