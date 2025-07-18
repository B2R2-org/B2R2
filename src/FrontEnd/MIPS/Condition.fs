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

namespace B2R2.FrontEnd.MIPS

/// Represents a condition code used in MIPS instructions.
type Condition =
  /// False [this predicate is always False].
  | F = 0
  /// Unordered.
  | UN = 1
  /// Equal.
  | EQ = 2
  /// Unordered or Equal.
  | UEQ = 3
  /// Ordered or Less Than.
  | OLT = 4
  /// Unordered or Less Than.
  | ULT = 5
  /// Ordered or Less Than or Equal.
  | OLE = 6
  /// Unordered or Less Than or Equal.
  | ULE = 7
  /// Signaling False [this predicate always False].
  | SF = 8
  /// Not Greater Than or Less Than or Equal.
  | NGLE = 9
  /// Signaling Equal.
  | SEQ = 10
  /// Not Greater Than or Less Than.
  | NGL = 11
  /// Less Than.
  | LT = 12
  /// Not Greater Than or Equal.
  | NGE = 13
  /// Less Than or Equal.
  | LE = 14
  /// Not Greater Than.
  | NGT = 15
