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

namespace B2R2.FrontEnd.M68K

/// <summary>
/// Represents the size of the operation an m68k instruction performs, which its
/// mnemonic carries as a suffix. This is a field of its own rather than part of
/// the opcode because an m68k mnemonic names an operation and a size
/// independently, and how wide the operation is is what a lifter needs.
/// </summary>
type OperandSize =
  /// Byte operation.
  | Byte = 0
  /// Word operation.
  | Word = 1
  /// Long-word operation.
  | Long = 2
  /// Single-precision real operation.
  | Single = 3
  /// Double-precision real operation.
  | Double = 4
  /// Extended-precision real operation.
  | Extended = 5
  /// Packed-decimal real operation.
  | Packed = 6
  /// No size, which is what an instruction whose mnemonic takes no suffix
  /// carries.
  | NoSize = 7

type internal Sz = OperandSize
