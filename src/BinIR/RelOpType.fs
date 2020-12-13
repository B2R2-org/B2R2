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

/// Relative operator types.
type RelOpType =
  /// Equal
  | EQ = 0
  /// Not equal
  | NEQ = 1
  /// Unsigned greater than
  | GT = 2
  /// Unsigned greater than or equal
  | GE = 3
  /// Signed greater than
  | SGT = 4
  /// Signed greater than or equal
  | SGE = 5
  /// Unsigned less than
  | LT = 6
  /// Unsigned less than or equal
  | LE = 7
  /// Signed less than
  | SLT = 8
  /// Signed less than or equal
  | SLE = 9
  /// Floating point greater than
  | FGT = 10
  /// Floating point greater than or equal
  | FGE = 11
  /// Floating point less than
  | FLT = 12
  /// Floating point less than or equal
  | FLE = 13

module RelOpType =
  let toString = function
    | RelOpType.EQ -> "="
    | RelOpType.NEQ -> "!="
    | RelOpType.GT -> ">"
    | RelOpType.GE -> ">="
    | RelOpType.SGT -> "?>"
    | RelOpType.SGE -> "?>="
    | RelOpType.LT -> "<"
    | RelOpType.LE -> "<="
    | RelOpType.SLT -> "?<"
    | RelOpType.SLE -> "?<="
    | RelOpType.FGT -> ">."
    | RelOpType.FGE -> ">=."
    | RelOpType.FLT -> "<."
    | RelOpType.FLE -> "<=."
    | _ -> raise IllegalASTTypeException

  let ofString = function
    | "=" -> RelOpType.EQ
    | "!=" -> RelOpType.NEQ
    | ">" -> RelOpType.GT
    | ">=" -> RelOpType.GE
    | "?>" -> RelOpType.SGT
    | "?>=" -> RelOpType.SGE
    | "<" -> RelOpType.LT
    | "<=" -> RelOpType.LE
    | "?<" -> RelOpType.SLT
    | "?<=" -> RelOpType.SLE
    | ">." -> RelOpType.FGT
    | ">=." -> RelOpType.FGE
    | "<." -> RelOpType.FLT
    | "<=." -> RelOpType.FLE
    | _ -> raise IllegalASTTypeException
