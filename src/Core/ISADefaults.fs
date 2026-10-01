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

/// Says what an ISA that names only part of itself is: the endianness,
/// word size and flags that the rest of it takes by default.
module internal B2R2.ISADefaults

/// Returns what a bare architecture means: the endianness, word size and
/// flags an ISA that names nothing else takes. UnknownISA stands for an
/// architecture that has no default, which the ISA constructor refuses.
let ofArch arch =
  match arch with
  | Architecture.Intel ->
    arch, Endian.Little, WordSize.Bit64, 0
  | Architecture.ARMv7 ->
    arch, Endian.Little, WordSize.Bit32, 0
  | Architecture.ARMv8 ->
    arch, Endian.Little, WordSize.Bit64, 0
  | Architecture.MIPS ->
    arch, Endian.Big, WordSize.Bit32, 0
  | Architecture.PPC ->
    arch, Endian.Big, WordSize.Bit32, 0
  | Architecture.RISCV ->
    arch, Endian.Little, WordSize.Bit64, 0
  | Architecture.SPARC ->
    arch, Endian.Big, WordSize.Bit64, 0
  | Architecture.S390 ->
    arch, Endian.Big, WordSize.Bit64, 0
  | Architecture.SH4 ->
    arch, Endian.Little, WordSize.Bit32, 0
  | Architecture.PARISC ->
    arch, Endian.Big, WordSize.Bit32, 0
  | Architecture.M68K ->
    arch, Endian.Big, WordSize.Bit32, int M68KModel.M68020
  | Architecture.Alpha ->
    arch, Endian.Little, WordSize.Bit64, 0
  | Architecture.AVR ->
    arch, Endian.Little, WordSize.Bit8, 0
  | Architecture.TMS320C6000 ->
    arch, Endian.Little, WordSize.Bit32, 0
  | Architecture.EVM ->
    arch, Endian.Big, WordSize.Bit256, 0
  | Architecture.Python ->
    arch, Endian.Little, WordSize.Bit64, int PythonVersion.Python312
  | Architecture.WASM ->
    arch, Endian.Little, WordSize.Bit32, 0
  | Architecture.CIL ->
    arch, Endian.Little, WordSize.Bit64, 0
  | Architecture.BPF ->
    arch, Endian.Little, WordSize.Bit64, 0
  | _ ->
    Architecture.UnknownISA, Endian.Little, WordSize.Bit64, 0

/// Returns what an architecture and an endianness mean: the word size and
/// flags an ISA that names those two takes.
let ofArchEndian arch endian =
  match arch with
  | Architecture.Intel when endian = Endian.Little ->
    arch, endian, WordSize.Bit64, 0
  | Architecture.ARMv7 ->
    arch, endian, WordSize.Bit32, 0
  | Architecture.ARMv8 ->
    arch, endian, WordSize.Bit64, 0
  | Architecture.MIPS ->
    arch, endian, WordSize.Bit32, 0
  | Architecture.PPC when endian = Endian.Little ->
    arch, endian, WordSize.Bit32, 0
  | Architecture.RISCV ->
    arch, endian, WordSize.Bit64, 0
  | Architecture.SPARC ->
    arch, endian, WordSize.Bit64, 0
  | Architecture.S390 ->
    arch, endian, WordSize.Bit64, 0
  | Architecture.SH4 ->
    arch, endian, WordSize.Bit32, 0
  | Architecture.PARISC when endian = Endian.Big ->
    arch, endian, WordSize.Bit32, 0
  | Architecture.M68K when endian = Endian.Big ->
    arch, endian, WordSize.Bit32, int M68KModel.M68020
  | Architecture.Alpha when endian = Endian.Little ->
    arch, endian, WordSize.Bit64, 0
  | Architecture.AVR ->
    arch, endian, WordSize.Bit8, 0
  | Architecture.TMS320C6000 ->
    arch, endian, WordSize.Bit32, 0
  | Architecture.EVM ->
    arch, endian, WordSize.Bit256, 0
  | Architecture.Python ->
    arch, endian, WordSize.Bit64, int PythonVersion.Python312
  | Architecture.WASM ->
    arch, endian, WordSize.Bit32, 0
  | Architecture.CIL ->
    arch, endian, WordSize.Bit64, 0
  (* A program is stored in the order the machine running it stores a word,
     and both orders are built for, so this is the one thing about an eBPF
     image that is not settled in advance. *)
  | Architecture.BPF ->
    arch, endian, WordSize.Bit64, 0
  | _ ->
    Architecture.UnknownISA, endian, WordSize.Bit64, 0

/// Returns what an architecture and a word size mean: the endianness and
/// flags an ISA that names those two takes.
let ofArchWordSize arch wordSize =
  match arch with
  | Architecture.Intel when wordSize = WordSize.Bit32
                         || wordSize = WordSize.Bit64 ->
    arch, Endian.Little, wordSize, 0
  | Architecture.ARMv7 when wordSize = WordSize.Bit32 ->
    arch, Endian.Little, wordSize, 0
  | Architecture.ARMv8 when wordSize = WordSize.Bit32
                         || wordSize = WordSize.Bit64 ->
    arch, Endian.Little, wordSize, 0
  | Architecture.MIPS when wordSize = WordSize.Bit32
                        || wordSize = WordSize.Bit64 ->
    arch, Endian.Big, wordSize, 0
  | Architecture.PPC when wordSize = WordSize.Bit32
                       || wordSize = WordSize.Bit64 ->
    arch, Endian.Big, wordSize, 0
  | Architecture.RISCV when wordSize = WordSize.Bit32
                         || wordSize = WordSize.Bit64
                         || wordSize = WordSize.Bit128 ->
    arch, Endian.Little, wordSize, 0
  | Architecture.SPARC when wordSize = WordSize.Bit32
                         || wordSize = WordSize.Bit64 ->
    arch, Endian.Big, wordSize, 0
  | Architecture.S390 when wordSize = WordSize.Bit32
                        || wordSize = WordSize.Bit64 ->
    arch, Endian.Big, wordSize, 0
  | Architecture.SH4 when wordSize = WordSize.Bit32
                       || wordSize = WordSize.Bit64 ->
    arch, Endian.Little, wordSize, 0
  | Architecture.PARISC when wordSize = WordSize.Bit32
                          || wordSize = WordSize.Bit64 ->
    arch, Endian.Big, wordSize, 0
  | Architecture.M68K when wordSize = WordSize.Bit32 ->
    arch, Endian.Big, wordSize, int M68KModel.M68020
  | Architecture.Alpha when wordSize = WordSize.Bit64 ->
    arch, Endian.Little, wordSize, 0
  | Architecture.AVR when wordSize = WordSize.Bit8 ->
    arch, Endian.Little, wordSize, 0
  | Architecture.TMS320C6000 when wordSize = WordSize.Bit32 ->
    arch, Endian.Little, wordSize, 0
  | Architecture.EVM when wordSize = WordSize.Bit256 ->
    arch, Endian.Big, wordSize, 0
  | Architecture.Python ->
    arch, Endian.Little, wordSize, int PythonVersion.Python312
  | Architecture.WASM ->
    arch, Endian.Little, wordSize, 0
  | Architecture.CIL ->
    arch, Endian.Little, wordSize, 0
  | Architecture.BPF when wordSize = WordSize.Bit64 ->
    arch, Endian.Little, wordSize, 0
  | _ ->
    Architecture.UnknownISA, Endian.Little, wordSize, 0

/// Returns what a Python version means on its own.
let ofPythonVersion (ver: PythonVersion) =
  Architecture.Python, Endian.Little, WordSize.Bit64, int ver

/// Returns what a member of the 68000 family means on its own.
let ofM68KModel (model: M68KModel) =
  Architecture.M68K, Endian.Big, WordSize.Bit32, int model

/// Returns what an AVR core with the given program memory size means on its
/// own. The size must be a power of two, and zero stands for nothing said.
let ofAVRCore core programSize =
  let flags = ISAFlags.ofAVR core programSize
  Architecture.AVR, Endian.Little, WordSize.Bit8, flags

/// Returns what a 32-bit ARM instruction set means: AArch32 if isAArch32 says
/// so and ARMv7 otherwise, since only those two choose between sets.
let ofARM32Mode (endian: Endian) isAArch32 mode =
  let arch = if isAArch32 then Architecture.ARMv8 else Architecture.ARMv7
  arch, endian, WordSize.Bit32, ISAFlags.ofARM mode ARMArchVersion.Any 0
