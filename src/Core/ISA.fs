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

/// <summary>
/// Represents the Instruction Set Architecture (ISA).
/// </summary>
/// <param name="arch">CPU architecture. Raises <see
/// cref='T:B2R2.InvalidISAException'/> if <see
/// cref='F:B2R2.Architecture.UnknownISA'/> is given.</param>
/// <param name="endian">Endianness.</param>
/// <param name="wordSize">Word size in bits.</param>
/// <param name="flags">Architecture-specific flags (e.g., Python version,
/// m68k model). Use 0 if not applicable.</param>
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
    let arch, endian, wordSize, flags = ISADefaults.ofArch arch
    ISA(arch, endian, wordSize, flags)

  /// Constructs an ISA object with the given architecture and endianness. The
  /// word size is set to the default value for the given architecture and
  /// endianness. Raises <see cref='T:B2R2.InvalidISAException'/> if the
  /// combination is not recognized.
  new(arch, endian) =
    let arch, endian, wordSize, flags = ISADefaults.ofArchEndian arch endian
    ISA(arch, endian, wordSize, flags)

  /// Constructs an ISA object with the given architecture and word size. The
  /// endianness is set to the default value for the given architecture. Raises
  /// <see cref='T:B2R2.InvalidISAException'/> if the combination is not
  /// recognized.
  new(arch, wordSize) =
    let arch, endian, wordSize, flags =
      ISADefaults.ofArchWordSize arch wordSize
    ISA(arch, endian, wordSize, flags)

  /// Constructs an ISA object for the given Python version.
  new(pythonVer: PythonVersion) =
    let arch, endian, wordSize, flags = ISADefaults.ofPythonVersion pythonVer
    ISA(arch, endian, wordSize, flags)

  /// Constructs an ISA object for the given member of the 68000 family.
  new(m68kModel: M68KModel) =
    let arch, endian, wordSize, flags = ISADefaults.ofM68KModel m68kModel
    ISA(arch, endian, wordSize, flags)

  /// Constructs an ISA object for the given AVR core.
  new(avrCore: AVRCore) = ISA(avrCore, 0UL)

  /// Constructs an ISA object for the given AVR core and program memory size,
  /// which must be a power of two. Only a loader that has read the part out of
  /// an image knows the size; without it a relative branch cannot wrap.
  new(avrCore: AVRCore, programSize: uint64) =
    let arch, endian, wordSize, flags =
      ISADefaults.ofAVRCore avrCore programSize
    ISA(arch, endian, wordSize, flags)

  /// Constructs a 32-bit ARM ISA meaning the given instruction set, which is
  /// AArch32 if isAArch32 says so and ARMv7 otherwise. Only those two have the
  /// instruction sets a mode chooses between, so this names neither an
  /// architecture nor a word size that could be something else.
  new(endian, isAArch32: bool, mode: ARM32Mode) =
    let arch, endian, wordSize, flags =
      ISADefaults.ofARM32Mode endian isAArch32 mode
    ISA(arch, endian, wordSize, flags)

  /// Constructs an ISA object from a canonical ISA name string such as "x86",
  /// "x86-64", "aarch64", "mips32le", etc. Raises <see
  /// cref='T:B2R2.InvalidISAException'/> if the string is not recognized.
  new(isaName: string) =
    let arch, endian, wordSize, flags = ISAName.parse isaName
    ISA(arch, endian, wordSize, flags)

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
    ISAFlags.arm32Mode flags

  /// <summary>
  /// Which version of the ARM architecture an ARM ISA means, which is Any --
  /// every encoding the front end knows -- unless the flags say otherwise.
  /// It sits above the instruction set in the flags, so a Thumb ISA can name
  /// one as well.
  /// </summary>
  member _.ARMArchVersion with get(): ARMArchVersion =
    ISAFlags.armArchVersion flags

  /// The OPTIONAL features an AArch64 ISA names beyond what its version makes
  /// mandatory.
  member _.AArch64Extensions with get(): AArch64Extension =
    ISAFlags.aarch64Extensions flags

  /// The extensions an ARMv7 ISA names beyond what its version includes.
  member _.ARMv7Extensions with get(): ARMv7Extension =
    ISAFlags.armv7Extensions flags

  /// Which release of the MIPS architecture a MIPS ISA means, which is one
  /// of Release 1 to 5 unless the flags say otherwise. Release 6 is not a
  /// superset: it reassigned primary opcodes that earlier releases had given
  /// to ADDI and DADDI, and replaced the multiply and divide families with
  /// instructions that write a general register instead of HI and LO. So a
  /// word of MIPS code cannot be decoded without knowing which release it
  /// belongs to, and an ELF image says so in its processor-specific flags.
  member _.MIPSRelease with get(): MIPSRelease =
    ISAFlags.mipsRelease flags

  /// <summary>
  /// Which of the MIPS encodings a MIPS ISA begins in.
  ///
  /// Neither microMIPS nor MIPS16e is an extension: each is the same
  /// instruction set written another way, with its own opcode map and
  /// instructions one halfword or two where the older encoding always takes a
  /// word. Which one a processor reads is a bit of its own that code flips as
  /// it runs, so this says where decoding starts and no more. An ELF image
  /// says so in the part of its processor-specific flags that names the
  /// extensions it uses.
  /// </summary>
  member _.MIPSISAMode with get(): MIPSISAMode =
    ISAFlags.mipsISAMode flags

  /// The member of the 68000 family an m68k ISA means, which is the 68020
  /// unless the flags say otherwise. The family shares one encoding space and a
  /// later model reads encodings an earlier one rejects, so nothing but this
  /// says what a halfword of m68k code belongs to.
  member _.M68KModel with get(): M68KModel =
    ISAFlags.m68kModel flags

  /// How wide the program counter of an AVR ISA's core is, which is two bytes
  /// unless the flags say otherwise. Only AVR has cores that differ in this, so
  /// this says nothing about any other architecture.
  member _.AVRCore with get(): AVRCore =
    ISAFlags.avrCore flags

  /// How many bytes of program memory an AVR part has, or zero when nothing
  /// said. A relative branch on AVR wraps around the end of program memory --
  /// which is how the reset vector reaches startup code sitting at the top of
  /// it -- so this is what the wrap is taken modulo of. It is always a power of
  /// two, and the flags hold its base-two logarithm.
  member _.AVRProgramSize with get() =
    ISAFlags.avrProgramSize flags

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

  /// Returns true if this ISA is RISC-V (any word size).
  member _.IsRISCV with get() = arch = Architecture.RISCV

  /// Returns true if this ISA is RISC-V 32-bit.
  member _.IsRISCV32 with get() =
    arch = Architecture.RISCV && wordSize = WordSize.Bit32

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

  /// Returns true if this ISA is DEC Alpha.
  member _.IsAlpha with get() = arch = Architecture.Alpha

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

  /// Returns true if this ISA is eBPF (either byte order).
  member _.IsBPF with get() = arch = Architecture.BPF

  override _.ToString() = ISAName.print arch endian wordSize flags
