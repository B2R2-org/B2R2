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
/// Raised when an invalid ISA is given as a parameter.
/// </summary>
exception InvalidISAException

/// <summary>
/// Represents CPU architecture types that are supported by B2R2.
/// </summary>
type Architecture =
  /// <summary>
  /// Intel x86 or x86-64.
  /// </summary>
  | Intel = 0
  /// <summary>
  /// ARMv7.
  /// </summary>
  | ARMv7 = 1
  /// <summary>
  /// ARMv8 (aarch32 and aarch64)
  /// </summary>
  | ARMv8 = 2
  /// <summary>
  /// MIPS.
  /// </summary>
  | MIPS = 3
  /// <summary>
  /// PowerPC.
  /// </summary>
  | PPC = 4
  /// <summary>
  /// RISC-V.
  /// </summary>
  | RISCV = 5
  /// <summary>
  /// SPARC.
  /// </summary>
  | SPARC = 6
  ///// IBM System/390.
  | S390 = 7
  /// <summary>
  /// SuperH (SH-4).
  /// </summary>
  | SH4 = 8
  /// <summary>
  /// PA-RISC.
  /// </summary>
  | PARISC = 9
  /// <summary>
  /// Atmel AVR 8-bit microcontroller.
  /// </summary>
  | AVR = 20
  ///// TMS320C64x, TMS320C67x, etc.
  | TMS320C6000 = 21
  /// <summary>
  /// EVM.
  /// </summary>
  | EVM = 30
  /// <summary>
  /// Python bytecode.
  /// </summary>
  | Python = 31
  /// <summary>
  /// WASM
  /// </summary>
  | WASM = 32
  /// <summary>
  /// Common Intermediate Language (CIL), aka MSIL.
  /// </summary>
  | CIL = 33
  /// <summary>
  /// Unknown ISA.
  /// </summary>
  | UnknownISA = 42
