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

namespace B2R2.BinIR

/// Unary operator types.
type UnOpType =
  /// Make it negative (Two's complement)
  | NEG = 0
  /// Bitwise not (One's complement)
  | NOT = 1
  /// Square root
  | FSQRT = 2
  /// Cosine
  | FCOS = 5
  /// Sine
  | FSIN = 6
  /// Tangent
  | FTAN = 7
  /// Arc Tangent
  | FATAN = 8
  /// Floating negation.
  | FNEG = 9

module UnOpType =
  let toString = function
    | UnOpType.NEG -> "-"
    | UnOpType.NOT -> "~"
    | UnOpType.FSQRT -> "sqrt"
    | UnOpType.FCOS -> "cos"
    | UnOpType.FSIN -> "sin"
    | UnOpType.FTAN -> "tan"
    | UnOpType.FATAN -> "atan"
    | UnOpType.FNEG -> "fneg"
    | _ -> raise IllegalASTTypeException

  let ofString = function
    | "-" -> UnOpType.NEG
    | "~" -> UnOpType.NOT
    | "sqrt" -> UnOpType.FSQRT
    | "cos" -> UnOpType.FCOS
    | "sin" -> UnOpType.FSIN
    | "tan" -> UnOpType.FTAN
    | "atan" -> UnOpType.FATAN
    | "fneg" -> UnOpType.FNEG
    | _ -> raise IllegalASTTypeException

// vim: set tw=80 sts=2 sw=2:
