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

/// Casting kinds.
type CastKind =
  /// Sign-extending conversion
  | SignExt = 0
  /// Zero-extending conversion
  | ZeroExt = 1
  /// Integer to float conversion
  | IntToFloat = 2
  /// Float to Nearest Integer rounded conversion. Ties to even. When the given
  /// float is too large to be represented as an integer, the result is MIN_INT,
  /// i.e., 0x80000000 for 32-bit integers and 0x8000000000000000 for 64-bit
  /// integers.
  | FtoIRound = 3
  /// Float to Integer rounded up conversion (toward +inf). When the given float
  /// is too large to be represented as an integer, the result is MIN_INT, i.e.,
  /// 0x80000000 for 32-bit integers and 0x8000000000000000 for 64-bit integers.
  | FtoICeil = 4
  /// Float to Integer rounded down conversion (toward -inf). When the given
  /// float is too large to be represented as an integer, the result is MIN_INT,
  /// i.e., 0x80000000 for 32-bit integers and 0x8000000000000000 for 64-bit
  /// integers.
  | FtoIFloor = 5
  /// Float to Integer truncated conversion (closest to but no greater in
  /// absolute value than the infinitely precise result). When the given float
  /// is too large to be represented as an integer, the result is MIN_INT, i.e.,
  /// 0x80000000 for 32-bit integers and 0x8000000000000000 for 64-bit integers.
  | FtoITrunc = 6
  /// Float to Float conversion with different precisions
  | FloatCast = 7
  /// Float to Float conversion while rounding to nearest integer.. Ties to
  /// even.
  | FtoFRound = 8
  /// Float to Float conversion while rounding toward +inf. E.g., 23.2 -> 24.0,
  /// and -23.7 -> -23.
  | FtoFCeil = 9
  /// Float to Float conversion while rounding toward -inf. E.g., 23.7 -> 23.0,
  /// and -23.2 -> -24.
  | FtoFFloor = 10
  /// Float to Float conversion while rounding toward zero. E.g. 23.7 -> 23.0,
  /// and -23.7 -> -23.
  | FtoFTrunc = 11

module CastKind =
  let toString = function
    | CastKind.SignExt -> "sext"
    | CastKind.ZeroExt -> "zext"
    | CastKind.IntToFloat -> "float"
    | CastKind.FtoIRound -> "round"
    | CastKind.FtoICeil -> "ceil"
    | CastKind.FtoIFloor -> "floor"
    | CastKind.FtoITrunc -> "trunc"
    | CastKind.FloatCast -> "fext"
    | CastKind.FtoFRound -> "roundf"
    | CastKind.FtoFCeil -> "ceilf"
    | CastKind.FtoFFloor -> "floorf"
    | CastKind.FtoFTrunc -> "truncf"
    | _ -> raise IllegalASTTypeException

  let ofString = function
    | "sext" -> CastKind.SignExt
    | "zext" -> CastKind.ZeroExt
    | "float" -> CastKind.IntToFloat
    | "round" -> CastKind.FtoIRound
    | "ceil" -> CastKind.FtoICeil
    | "floor" -> CastKind.FtoIFloor
    | "trunc" -> CastKind.FtoITrunc
    | "fext" -> CastKind.FloatCast
    | "roundf" -> CastKind.FtoFRound
    | "ceilf" -> CastKind.FtoFCeil
    | "floorf" -> CastKind.FtoFFloor
    | "truncf" -> CastKind.FtoFTrunc
    | _ -> raise IllegalASTTypeException
