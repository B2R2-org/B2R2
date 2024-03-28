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

/// Architecture types.
type Architecture =
  /// x86 (i386).
  | IntelX86 = 1
  /// x86-64 (amd64).
  | IntelX64 = 2
  /// ARMv7.
  | ARMv7 = 3
  /// ARMv8 32-bit mode.
  | AARCH32 = 4
  /// ARMv8 64-bit mode.
  | AARCH64 = 5
  /// MIPS 32-bit mode.
  | MIPS32 = 6
  /// MIPS 64-bit mode.
  | MIPS64 = 7
  /// Ethereum Vritual Machine.
  | EVM = 17
  /// TMS320C54x, TMS320C55x, etc.
  | TMS320C5000 = 18
  /// TMS320C64x, TMS320C67x, etc.
  | TMS320C6000 = 19
  /// Common Intermediate Language (CIL), aka MSIL.
  | CILOnly = 20
  /// CIL + x86 (PE32).
  | CILIntel32 = 21
  /// CIL + x64 (PE32+).
  | CILIntel64 = 22
  /// Atmel AVR 8-bit microcontroller.
  | AVR = 23
  /// SuperH (SH-4).
  | SH4 = 24
  /// PA-RISC.
  | PARISC = 25
  /// PA-RISC 64-bit.
  | PARISC64 = 26
  /// PowerPC 32-bit.
  | PPC32 = 27
  /// Python bytecode.
  | Python = 28
  /// IBM System/390
  | S390 = 29
  /// IBM System/390 (64-bit)
  | S390X = 30
  /// Sparc 64-bit.
  | SPARC = 31
  /// RISCV 64-bit
  | RISCV64 = 32
  /// WASM
  | WASM = 40
  /// Unknown ISA.
  | UnknownISA = 42

/// Instruction Set Architecture (ISA).
type ISA = {
  Arch: Architecture
  Endian: Endian
  WordSize: WordSize
}
with
  static member DefaultISA =
    { Arch = Architecture.IntelX64
      Endian = Endian.Little
      WordSize = WordSize.Bit64 }

  static member Init arch endian =
    match arch with
    | Architecture.IntelX86 ->
      { Arch = arch; Endian = Endian.Little; WordSize = WordSize.Bit32 }
    | Architecture.IntelX64 -> ISA.DefaultISA
    | Architecture.ARMv7
    | Architecture.AARCH32
    | Architecture.MIPS32 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit32 }
    | Architecture.AARCH64
    | Architecture.MIPS64 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit64 }
    | Architecture.EVM ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit256 }
    | Architecture.TMS320C6000 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit32 }
    | Architecture.CILOnly ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit64 }
    | Architecture.AVR ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit8 }
    | Architecture.SH4 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit32 }
    | Architecture.PARISC ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit32 }
    | Architecture.PARISC64 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit64 }
    | Architecture.PPC32 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit32 }
    | Architecture.Python ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit32 }
    | Architecture.S390 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit32 }
    | Architecture.S390X ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit64 }
    | Architecture.SPARC ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit64 }
    | Architecture.RISCV64 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit64 }
    | Architecture.WASM ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit32 }
    | _ -> raise InvalidISAException

  static member OfString (s: string) =
    match s.ToLowerInvariant () with
    | "x86" | "i386" ->
      ISA.Init Architecture.IntelX86 Endian.Little
    | "x64" | "x86-64" | "amd64" ->
      ISA.DefaultISA
    | "armv7" | "armv7le" | "armel" | "armhf" ->
      ISA.Init Architecture.ARMv7 Endian.Little
    | "armv7be" ->
      ISA.Init Architecture.ARMv7 Endian.Big
    | "armv8a32" | "aarch32" ->
      ISA.Init Architecture.AARCH32 Endian.Little
    | "armv8a32be" | "aarch32be" ->
      ISA.Init Architecture.AARCH32 Endian.Big
    | "armv8a64" | "aarch64"->
      ISA.Init Architecture.AARCH64 Endian.Little
    | "armv8a64be" | "aarch64be" ->
      ISA.Init Architecture.AARCH64 Endian.Big
    | "mipsel" | "mips32" | "mips32le" ->
      ISA.Init Architecture.MIPS32 Endian.Little
    | "mips32be" ->
      ISA.Init Architecture.MIPS32 Endian.Big
    | "mips64el" | "mips64" | "mips64le" ->
      ISA.Init Architecture.MIPS64 Endian.Little
    | "mips64be" ->
      ISA.Init Architecture.MIPS64 Endian.Big
    | "evm" ->
      ISA.Init Architecture.EVM Endian.Big
    | "tms320c6000" ->
      ISA.Init Architecture.TMS320C6000 Endian.Little
    | "cil" ->
      ISA.Init Architecture.CILOnly Endian.Little
    | "avr" | "avr8" ->
      ISA.Init Architecture.AVR Endian.Little
    | "sh4" | "sh-4" ->
      ISA.Init Architecture.SH4 Endian.Little
    | "sh4be" | "sh-4be" ->
      ISA.Init Architecture.SH4 Endian.Big
    | "parisc" | "hppa" ->
      ISA.Init Architecture.PARISC Endian.Big
    | "parisc64" | "hppa64" ->
      ISA.Init Architecture.PARISC64 Endian.Big
    | "ppc32" | "ppc32le" ->
      ISA.Init Architecture.PPC32 Endian.Little
    | "ppc32be" ->
      ISA.Init Architecture.PPC32 Endian.Big
    | "python" ->
      ISA.Init Architecture.Python Endian.Little
    | "s390" ->
      ISA.Init Architecture.S390 Endian.Big
    | "s390x" ->
      ISA.Init Architecture.S390X Endian.Big
    | "sparc" | "sparc64" ->
      ISA.Init Architecture.SPARC Endian.Big
    | "riscv64" ->
      ISA.Init Architecture.RISCV64 Endian.Little
    | "wasm" ->
      ISA.Init Architecture.WASM Endian.Little
    | _ -> raise InvalidISAException

  static member ArchToString arch =
    match arch with
    | Architecture.IntelX86 -> "x86"
    | Architecture.IntelX64 -> "x86-64"
    | Architecture.ARMv7 -> "ARMv7"
    | Architecture.AARCH32 -> "AARCH32"
    | Architecture.AARCH64 -> "AARCH64"
    | Architecture.MIPS32 -> "MIPS32"
    | Architecture.MIPS64 -> "MIPS64"
    | Architecture.EVM -> "EVM"
    | Architecture.TMS320C6000 -> "TMS320C6000"
    | Architecture.CILOnly -> "CIL"
    | Architecture.AVR -> "AVR"
    | Architecture.SH4 -> "SH4"
    | Architecture.PARISC -> "PARISC"
    | Architecture.PARISC64 -> "PARISC64"
    | Architecture.PPC32 -> "PPC32"
    | Architecture.Python -> "Python"
    | Architecture.S390 -> "S390"
    | Architecture.S390X -> "S390X"
    | Architecture.SPARC -> "SPARC64"
    | Architecture.RISCV64 -> "RISCV64"
    | Architecture.WASM -> "WASM"
    | Architecture.UnknownISA -> "Unknown"
    | _ -> "Not supported ISA"
