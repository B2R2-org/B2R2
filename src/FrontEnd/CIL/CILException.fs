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

namespace B2R2.FrontEnd.CIL

/// <summary>
/// Represents an exception the machine raises of its own accord, which the
/// lifter names to the runtime through the external call "raise" with the
/// value as its one argument. A program's own throw carries an object instead
/// and goes through the external call "throw".
/// </summary>
type CILException =
  /// An integer division or remainder by zero.
  | DivideByZero = 1
  /// A checked arithmetic or conversion instruction whose result does not fit,
  /// or an integer division of the most negative value by minus one.
  | Overflow = 2
  /// An array instruction handed a null reference.
  | NullReference = 3
  /// An array instruction handed an index at or past the length.
  | IndexOutOfRange = 4
  /// A ckfinite handed a NaN or an infinity. ECMA-335 names
  /// ArithmeticException for it; the runtime throws that class's subclass
  /// OverflowException, which a runtime naming the exception has to know.
  | Arithmetic = 5

// vim: set tw=80 sts=2 sw=2:
