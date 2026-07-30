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

/// <summary>
/// Provides an interface for parsing binary instructions.
/// <remarks>
/// Input that does not decode is reported as <see
/// cref='T:B2R2.FrontEnd.BinLifter.ParsingFailureException'/>, and that is the
/// only exception an implementation may raise about its input: a span too short
/// to hold the instruction it starts, an encoding the architecture reserves,
/// and one this parser has yet to cover all arrive as the same type. An
/// implementation converts at its <c>Parse</c> boundary, letting through only
/// what says nothing about the input, such as running out of memory.
/// </remarks>
/// </summary>
type IInstructionParsable =
  /// Return the maximum possible size of an instruction.
  abstract MaxInstructionSize: int

  /// The instruction alignment (in bytes) enforced by the CPU. For example, ARM
  /// requires instructions to be aligned to 4 bytes, while x86 does not have
  /// such a requirement (i.e., 1-byte alignment). This can depend on the
  /// parser's current state, as it does for ARM32, where Thumb instructions are
  /// aligned to 2 bytes and ARM instructions to 4.
  abstract InstructionAlignment: int

  /// <summary>
  /// Parse one instruction from the given byte array assuming that the address
  /// of the instruction is `addr`.
  /// </summary>
  /// <exception cref='T:B2R2.FrontEnd.BinLifter.ParsingFailureException'>
  /// Thrown when the bytes do not decode.
  /// </exception>
  abstract Parse: bs: byte[] * addr: Addr -> IInstruction

  /// <summary>
  /// Parse one instruction from the given byte span assuming that the address
  /// of the instruction is `addr`.
  /// </summary>
  /// <exception cref='T:B2R2.FrontEnd.BinLifter.ParsingFailureException'>
  /// Thrown when the bytes do not decode, which includes the span being too
  /// short to hold the instruction it starts.
  /// </exception>
  abstract Parse: span: ByteSpan * addr: Addr -> IInstruction
