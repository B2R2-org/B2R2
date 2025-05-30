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

/// Represents a lastly used opcode, which can be lazily remembered by an
/// emulator to compute condition flags.
type ConditionCodeOp =
  /// Indicator for the start of a trace.
  | TraceStart = 0x1
  /// Indicator for EFLAGS computation. This is set only when EFLAGS computation
  /// is complete.
  | EFlags = 0x2
  /// Substraction of byte-size operands.
  | SUBB = 0x3
  /// Substraction of word-size operands.
  | SUBW = 0x4
  /// Substraction of doubleword-size operands.
  | SUBD = 0x5
  /// Substraction of quadword-size operands.
  | SUBQ = 0x6
  /// Logical operations of byte-size operands.
  | LOGICB = 0x7
  /// Logical operations of word-size operands.
  | LOGICW = 0x8
  /// Logical operations of doubleword-size operands.
  | LOGICD = 0x9
  /// Logical operations of quadword-size operands.
  | LOGICQ = 0xA
  /// Addition of byte-size operands.
  | ADDB = 0xB
  /// Addition of word-size operands.
  | ADDW = 0xC
  /// Addition of doubleword-size operands.
  | ADDD = 0xD
  /// Addition of quadword-size operands.
  | ADDQ = 0xE
  /// Shift operations of byte-size operands.
  | SHLB = 0xF
  /// Shift operations of word-size operands.
  | SHLW = 0x10
  /// Shift operations of doubleword-size operands.
  | SHLD = 0x11
  /// Shift operations of quadword-size operands.
  | SHLQ = 0x12
  /// Shift right operations of byte-size operands.
  | SHRB = 0x13
  /// Shift right operations of word-size operands.
  | SHRW = 0x14
  /// Shift right operations of doubleword-size operands.
  | SHRD = 0x15
  /// Shift right operations of quadword-size operands.
  | SHRQ = 0x16
  /// Shift arithmetic right operations of byte-size operands.
  | SARB = 0x17
  /// Shift arithmetic right operations of word-size operands.
  | SARW = 0x18
  /// Shift arithmetic right operations of doubleword-size operands.
  | SARD = 0x19
  /// Shift arithmetic right operations of quadword-size operands.
  | SARQ = 0x1A
  /// Increment of byte-size value.
  | INCB = 0x1B
  /// Increment of word-size value.
  | INCW = 0x1C
  /// Increment of doubleword-size value.
  | INCD = 0x1D
  /// Increment of quadword-size value.
  | INCQ = 0x1E
  /// Decrement of byte-size value.
  | DECB = 0x1F
  /// Decrement of word-size value.
  | DECW = 0x20
  /// Decrement of doubleword-size value.
  | DECD = 0x21
  /// Decrement of quadword-size value.
  | DECQ = 0x22
  /// XOR of the same operands.
  | XORXX = 0x23
