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
/// Represents CPU architecture types that are supported by B2R2.
/// </summary>
type Architecture =
  /// Intel x86 or x86-64.
  | Intel = 0
  /// ARMv7.
  | ARMv7 = 1
  /// ARMv8 (aarch32 and aarch64)
  | ARMv8 = 2
  /// MIPS.
  | MIPS = 3
  /// PowerPC.
  | PPC = 4
  /// RISC-V.
  | RISCV = 5
  /// SPARC.
  | SPARC = 6
  ///// IBM System/390.
  | S390 = 7
  /// SuperH (SH-4).
  | SH4 = 8
  /// PA-RISC.
  | PARISC = 9
  /// Atmel AVR 8-bit microcontroller.
  | AVR = 20
  ///// TMS320C64x, TMS320C67x, etc.
  | TMS320C6000 = 21
  /// EVM.
  | EVM = 30
  /// Python bytecode.
  | Python = 31
  /// WASM
  | WASM = 32
  /// Common Intermediate Language (CIL), aka MSIL.
  | CIL = 33
  /// Unknown ISA.
  | UnknownISA = 42
