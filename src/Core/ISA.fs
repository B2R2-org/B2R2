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

/// Raised when an invalid ArchOperationMode is given.
exception InvalidTargetArchModeException

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
  /// MIPS1 (32-bit mode).
  | MIPS1 = 6
  /// MIPS2 (32-bit mode).
  | MIPS2 = 7
  /// MIPS3 (64-bit mode).
  | MIPS3 = 8
  /// MIPS4 (64-bit mode).
  | MIPS4 = 9
  /// MIPS5 (64-bit mode).
  | MIPS5 = 10
  /// MIPS32 (32-bit mode).
  | MIPS32 = 11
  /// MIPS32 Release2 (32-bit mode).
  | MIPS32R2 = 12
  /// MIPS32 Release6 (32-bit mode).
  | MIPS32R6 = 13
  /// MIPS64 (64-bit mode).
  | MIPS64 = 14
  /// MIPS64R2 (64-bit mode).
  | MIPS64R2 = 15
  /// MIPS64R6 (64-bit mode).
  | MIPS64R6 = 16
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
  /// PowerPC 32-bit.
  | PPC32 = 25
  /// Sparc 64-bit.
  | Sparc64 = 26
  /// RISCV 64-bit
  | RISCV64 = 27
  /// WASM
  | WASM = 40
  /// Unknown ISA.
  | UnknownISA = 42

type Arch = Architecture

/// Some ISA, such as ARM, have their own operation mode, which can vary at
/// runtime. For example, ARM architecture can switch between Thumb and ARM
/// mode. ArchOperationMode decides which mode to consider at the time of
/// parsing/lifting machine instructions.
type ArchOperationMode =
  /// ARM mode.
  | ARMMode = 1
  /// Thumb mode.
  | ThumbMode = 2
  /// No mode. This is used for architectures that do not have any operation
  /// mode.
  | NoMode = 3

/// A helper module for ArchOperationMode.
[<RequireQualifiedAccess>]
module ArchOperationMode =
  let ofString (s: string) =
    match s.ToLowerInvariant () with
    | "arm" -> ArchOperationMode.ARMMode
    | "thumb" -> ArchOperationMode.ThumbMode
    | _ -> ArchOperationMode.NoMode

  let toString mode =
    match mode with
    | ArchOperationMode.ARMMode -> "arm"
    | ArchOperationMode.ThumbMode -> "thumb"
    | _ -> "nomode"

/// Instruction Set Architecture (ISA).
type ISA = {
  Arch: Architecture
  Endian: Endian
  WordSize: WordSize
}
with
  static member DefaultISA =
    { Arch = Arch.IntelX64; Endian = Endian.Little; WordSize = WordSize.Bit64 }

  static member Init arch endian =
    match arch with
    | Arch.IntelX86 ->
      { Arch = arch; Endian = Endian.Little; WordSize = WordSize.Bit32 }
    | Arch.IntelX64 -> ISA.DefaultISA
    | Arch.ARMv7
    | Arch.AARCH32
    | Arch.MIPS1
    | Arch.MIPS2
    | Arch.MIPS32
    | Arch.MIPS32R2
    | Arch.MIPS32R6 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit32 }
    | Arch.AARCH64
    | Arch.MIPS3
    | Arch.MIPS4
    | Arch.MIPS5
    | Arch.MIPS64
    | Arch.MIPS64R2
    | Arch.MIPS64R6 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit64 }
    | Arch.EVM ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit256 }
    | Arch.TMS320C6000 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit32 }
    | Arch.CILOnly ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit64 }
    | Arch.AVR ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit8 }
    | Arch.SH4 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit32 }
    | Arch.PPC32 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit32 }
    | Arch.Sparc64 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit64 }
    | Arch.RISCV64 ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit64 }
    | Arch.WASM ->
      { Arch = arch; Endian = endian; WordSize = WordSize.Bit32 }
    | _ -> raise InvalidISAException

  static member OfString (s: string) =
    match s.ToLowerInvariant () with
    | "x86" | "i386" -> ISA.Init Arch.IntelX86 Endian.Little
    | "x64" | "x86-64" | "amd64" -> ISA.DefaultISA
    | "armv7" | "armv7le"
    | "armel" | "armhf" -> ISA.Init Arch.ARMv7 Endian.Little
    | "armv7be" -> ISA.Init Arch.ARMv7 Endian.Big
    | "armv8a32" | "aarch32" -> ISA.Init Arch.AARCH32 Endian.Little
    | "armv8a32be" | "aarch32be" -> ISA.Init Arch.AARCH32 Endian.Big
    | "armv8a64" | "aarch64"-> ISA.Init Arch.AARCH64 Endian.Little
    | "armv8a64be" | "aarch64be" -> ISA.Init Arch.AARCH64 Endian.Big
    | "mips32r2" -> ISA.Init Arch.MIPS32R2 Endian.Little
    | "mips32r2be" -> ISA.Init Arch.MIPS32R2 Endian.Big
    | "mips32r6" -> ISA.Init Arch.MIPS32R6 Endian.Little
    | "mips32r6be" -> ISA.Init Arch.MIPS32R6 Endian.Big
    | "mips64r2" -> ISA.Init Arch.MIPS64R2 Endian.Little
    | "mips64r2be" -> ISA.Init Arch.MIPS64R2 Endian.Big
    | "mips64r6" -> ISA.Init Arch.MIPS64R6 Endian.Little
    | "mips64r6be" -> ISA.Init Arch.MIPS64R6 Endian.Big
    | "evm" -> ISA.Init Arch.EVM Endian.Big
    | "tms320c6000" -> ISA.Init Arch.TMS320C6000 Endian.Little
    | "cil" -> ISA.Init Arch.CILOnly Endian.Little
    | "avr" | "avr8" -> ISA.Init Arch.AVR Endian.Little
    | "sh4" | "sh-4" -> ISA.Init Arch.SH4 Endian.Little
    | "sh4be" | "sh-4be" -> ISA.Init Arch.SH4 Endian.Big
    | "ppc32" -> ISA.Init Arch.PPC32 Endian.Little
    | "sparc" | "sparc64" -> ISA.Init Arch.Sparc64 Endian.Big
    | "riscv64" -> ISA.Init Arch.RISCV64 Endian.Little
    | "wasm" -> ISA.Init Arch.WASM Endian.Little
    | _ -> raise InvalidISAException

  static member ArchToString arch =
    match arch with
    | Arch.IntelX86 -> "x86"
    | Arch.IntelX64 -> "x86-64"
    | Arch.ARMv7 -> "ARMv7"
    | Arch.AARCH32 -> "AARCH32"
    | Arch.AARCH64 -> "AARCH64"
    | Arch.MIPS32R2 -> "MIPS32 Release 2"
    | Arch.MIPS32R6 -> "MIPS32 Release 6"
    | Arch.MIPS64R2 -> "MIPS64 Release 2"
    | Arch.MIPS64R6 -> "MIPS64 Release 6"
    | Arch.EVM -> "EVM"
    | Arch.TMS320C6000 -> "TMS320C6000"
    | Arch.CILOnly -> "CIL"
    | Arch.AVR -> "AVR"
    | Arch.SH4 -> "SH4"
    | Arch.PPC32 -> "PPC32"
    | Arch.Sparc64 -> "SPARC64"
    | Arch.RISCV64 -> "RISCV64"
    | Arch.WASM -> "WASM"
    | Arch.UnknownISA -> "Unknown"
    | _ -> "Not supported ISA"
