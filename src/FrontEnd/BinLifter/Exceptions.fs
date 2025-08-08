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

/// <namespacedoc>
///   <summary>
///   Contains types and functions for working with parsing and lifting binary
///   code. Every parser and lifter in B2R2 should open this namespace at least
///   once.
///   </summary>
/// </namespacedoc>
///
/// <summary>
/// Raised when the IR is not implemented yet.
/// </summary>
exception NotImplementedIRException of string

/// Raised when an invalid operand has been encountered during parsing/lifting.
exception InvalidOperandException

/// Raised when an invalid operand type has been encountered during
/// parsing/lifting.
exception InvalidOperandSizeException

/// Raised when an invalid opcode has been encountered during parsing/lifting.
exception InvalidOpcodeException

/// Raised when an invalid register has been encountered during parsing/lifting.
exception InvalidRegisterException

/// Raised when parsing binary code failed. This exception indicates a
/// non-recoverable parsing failure.
exception ParsingFailureException
