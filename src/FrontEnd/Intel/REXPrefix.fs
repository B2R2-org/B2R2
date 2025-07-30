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

namespace B2R2.FrontEnd.Intel

open LanguagePrimitives

/// Represents the REX prefix used in x86-64 instructions.
type REXPrefix =
  /// No REX: this is to represent the case where there is no REX
  | NOREX = 0b0000000
  /// Extension of the ModR/M reg, Opcode reg field (SPL, BPL, ...).
  | REX = 0b1000000
  /// Extension of the ModR/M rm, SIB base, Opcode reg field.
  | REXB = 0b1000001
  /// Extension of the SIB index field.
  | REXX = 0b1000010
  /// Extension of the ModR/M SIB index, base field.
  | REXXB = 0b1000011
  /// Extension of the ModR/M reg field.
  | REXR = 0b1000100
  /// Extension of the ModR/M reg, r/m field.
  | REXRB = 0b1000101
  /// Extension of the ModR/M reg, SIB index field.
  | REXRX = 0b1000110
  /// Extension of the ModR/M reg, SIB index, base.
  | REXRXB = 0b1000111
  /// Operand 64bit.
  | REXW = 0b1001000
  /// REX.B + Operand 64bit.
  | REXWB = 0b1001001
  /// REX.X + Operand 64bit.
  | REXWX = 0b1001010
  /// REX.XB + Operand 64bit.
  | REXWXB = 0b1001011
  /// REX.R + Operand 64bit.
  | REXWR = 0b1001100
  /// REX.RB + Operand 64bit.
  | REXWRB = 0b1001101
  /// REX.RX + Operand 64bit.
  | REXWRX = 0b1001110
  /// REX.RXB + Operand 64bit.
  | REXWRXB = 0b1001111

/// Provides a set of functions to manipulate REX prefixes.
[<RequireQualifiedAccess>]
module internal REXPrefix =
  let inline hasW rexPref = rexPref &&& REXPrefix.REXW = REXPrefix.REXW

  let inline hasR rexPref = rexPref &&& REXPrefix.REXR = REXPrefix.REXR

  let inline hasB rexPref = rexPref &&& REXPrefix.REXB = REXPrefix.REXB

  /// Filter out REXW (0x8).
  let [<Literal>] ClearREXWPrefMask: REXPrefix = EnumOfValue 0xFFF7
