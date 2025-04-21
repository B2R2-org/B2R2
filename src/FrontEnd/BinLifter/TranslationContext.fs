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

namespace B2R2.FrontEnd.BinLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

#if EMULATION
/// Lazily remembered lastly used opcode.
type ConditionCodeOp =
  /// Indicator for the start of a trace.
  | TraceStart = 0x1
  /// Indicator for EFLAGS computation. This is set only when EFLAGS computation
  /// is complete.
  | EFlags = 0x2
  | SUBB = 0x3
  | SUBW = 0x4
  | SUBD = 0x5
  | SUBQ = 0x6
  | LOGICB = 0x7
  | LOGICW = 0x8
  | LOGICD = 0x9
  | LOGICQ = 0xA
  | ADDB = 0xB
  | ADDW = 0xC
  | ADDD = 0xD
  | ADDQ = 0xE
  | SHLB = 0xF
  | SHLW = 0x10
  | SHLD = 0x11
  | SHLQ = 0x12
  | SHRB = 0x13
  | SHRW = 0x14
  | SHRD = 0x15
  | SHRQ = 0x16
  | SARB = 0x17
  | SARW = 0x18
  | SARD = 0x19
  | SARQ = 0x1A
  | INCB = 0x1B
  | INCW = 0x1C
  | INCD = 0x1D
  | INCQ = 0x1E
  | DECB = 0x1F
  | DECW = 0x20
  | DECD = 0x21
  | DECQ = 0x22
  /// XOR of the same operands.
  | XORXX = 0x23
#endif

/// A high-level interface for the translation context, which stores several
/// states for translating/lifting instructions.
[<AbstractClass>]
type TranslationContext (isa) =
  let irb = IRBuilder (241)
  let mutable delayedJump = InterJmpKind.NotAJmp
#if EMULATION
  let mutable conditionCodeOp = ConditionCodeOp.TraceStart
#endif

  /// Word size.
  member _.WordSize with get() = isa.WordSize

  /// Word size in bits (RegType).
  member _.WordBitSize with get(): RegType = WordSize.toRegType isa.WordSize

  /// The endianness.
  member _.Endianness with get(): Endian = isa.Endian

  /// IRBuilder for lifting IRs.
  member _.IRBuilder with get() = irb

  /// Remember if a branch is delayed. If delayed, we store its InterJmpKind.
  /// Lifting results may vary depending on this variable.
  member _.DelayedBranch
    with get() = delayedJump and set(f) = delayedJump <- f

#if EMULATION
  /// Remember the lastly used opcode that updates EFLAGS. This is explicitly
  /// used for x86 emulation.
  member _.ConditionCodeOp
    with get() = conditionCodeOp and set(v) = conditionCodeOp <- v
#endif

  /// <summary>
  ///   Get register expression from a given register ID.
  /// </summary>
  /// <param name="id">Register ID.</param>
  /// <returns>
  ///   Returns an IR expression of a register.
  /// </returns>
  abstract GetRegVar: id: RegisterID -> Expr

  /// <summary>
  ///   Get pseudo register expression from a given register ID and an index.
  /// </summary>
  /// <param name="id">Register ID.</param>
  /// <param name="idx">Register index.</param>
  /// <returns>
  ///   Returns an IR expression of a pseudo-register.
  /// </returns>
  abstract GetPseudoRegVar: id: RegisterID -> idx: int -> Expr
