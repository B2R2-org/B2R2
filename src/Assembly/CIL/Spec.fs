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

namespace B2R2.Assembly.CIL

/// <namespacedoc>
///   <summary>
///   Contains CIL-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents one instruction the assembler can write: the bytes that name it,
/// and how whatever a source writes beside the mnemonic turns into the bytes
/// that follow them.
/// </summary>
type Encoding =
  { /// The opcode bytes: one, or two behind the 0xfe prefix byte.
    Code: byte[]
    /// How the operand, if there is one, is laid out behind them.
    Shape: Shape }

/// <summary>
/// Represents how the operand of one instruction is laid out. An instruction
/// takes at most one, and every one but a switch table is of a width the
/// opcode settles.
/// </summary>
and Shape =
  /// No operand at all.
  | Bare
  /// One operand of the given kind, in the given number of bytes.
  | Fixed of kind: OperandKind * width: int
  /// The targets of a switch, counted, each four bytes wide.
  | Table

/// <summary>
/// Represents the kind of the one operand an instruction carries, which says
/// how a source writes it and what it has to fit. The kinds are the very cases
/// the decoder hands back, so that what an instruction takes can be read off a
/// decoded one.
/// </summary>
and OperandKind =
  /// An argument or a local variable, by an index that cannot be below zero.
  | VarKind
  /// A 32-bit integer constant, which a source may write below zero or as the
  /// bits it lands in.
  | I4Kind
  /// A 64-bit integer constant.
  | I8Kind
  /// A 32-bit float, which the encoding carries as the raw bits.
  | R4Kind
  /// A 64-bit float, which the encoding carries as the raw bits.
  | R8Kind
  /// The address a branch reaches, which is encoded as the distance from the
  /// instruction after the branch.
  | TargetKind
  /// A metadata token.
  | TokenKind
  /// The one byte a prefix carries.
  | ByteKind

// vim: set tw=80 sts=2 sw=2:
