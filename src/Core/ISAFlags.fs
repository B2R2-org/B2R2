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

/// <summary>
/// Reads and writes the architecture-specific flags of an ISA, which hold what
/// an architecture needs beyond its endianness and word size. Every
/// architecture has the whole word to itself, so the fields below overlap and
/// nothing but the architecture says which of them a flags word holds.
/// </summary>
module internal B2R2.ISAFlags

/// Reads the instruction set a 32-bit ARM ISA means, which sits in the
/// lowest bit.
let arm32Mode flags: ARM32Mode = LanguagePrimitives.EnumOfValue(flags &&& 1)

/// Reads the version an ARM ISA means, which sits above the instruction
/// set.
let armArchVersion flags: ARMArchVersion =
  LanguagePrimitives.EnumOfValue((flags >>> 4) &&& 0xf)

/// Reads the bits an ARM ISA keeps its extensions in, which begin at the
/// second byte so that the instruction set and the version sit below them.
let armExtensions flags = flags &&& ~~~0xff

/// Reads the OPTIONAL features an AArch64 ISA names.
let aarch64Extensions flags: AArch64Extension =
  LanguagePrimitives.EnumOfValue(armExtensions flags)

/// Reads the extensions an ARMv7 ISA names.
let armv7Extensions flags: ARMv7Extension =
  LanguagePrimitives.EnumOfValue(armExtensions flags)

/// Builds the flags of an ARM ISA that reads the given instruction set,
/// version and extensions.
let ofARM (mode: ARM32Mode) (version: ARMArchVersion) exts =
  int mode ||| (int version <<< 4) ||| exts

/// Reads the release a MIPS ISA means, which sits in the lowest bit.
let mipsRelease flags: MIPSRelease =
  LanguagePrimitives.EnumOfValue(flags &&& 1)

/// Reads the encoding a MIPS ISA begins in, which sits beside the release.
let mipsISAMode flags: MIPSISAMode =
  LanguagePrimitives.EnumOfValue(flags &&& 6)

/// Reads the member of the 68000 family an m68k ISA means, which has the
/// whole word to itself.
let m68kModel flags: M68KModel = LanguagePrimitives.EnumOfValue flags

/// Reads the core an AVR ISA means, which sits in the lowest byte.
let avrCore flags: AVRCore =
  LanguagePrimitives.EnumOfValue(flags &&& 0xff)

/// Returns how many bytes of program memory an AVR part has, or zero when
/// nothing said. The second byte holds the base-two logarithm of the size.
let avrProgramSize flags =
  match (flags >>> 8) &&& 0xff with
  | 0 -> 0UL
  | log2 -> 1UL <<< log2

/// Builds the flags of an AVR ISA on the given core with the given program
/// memory size, which must be a power of two. Zero stands for nothing said.
let ofAVR (core: AVRCore) programSize =
  let mutable log2 = 0
  while programSize >>> (log2 + 1) <> 0UL do log2 <- log2 + 1
  int core ||| (if programSize = 0UL then 0 else log2 <<< 8)

/// Reads the version a Python ISA means, which has the whole word to
/// itself.
let pythonVersion flags: PythonVersion = LanguagePrimitives.EnumOfValue flags
