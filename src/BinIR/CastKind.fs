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

/// <summary>
/// Represents a cast kind, used in the <c>Cast</c> expression.
/// </summary>
type CastKind =
  /// Sign-extending conversion
  | SignExt = 0
  /// Zero-extending conversion
  | ZeroExt = 1
  /// Signed integer to float conversion
  | SIntToFloat = 2
  /// Unsigned integer to float conversion
  | UIntToFloat = 3
  /// <summary>
  /// Float to signed integer conversion, in whatever direction is in force:
  /// the one a <c>RoundCtrl</c> expression names, or, outside every
  /// RoundCtrl, the one the target's own control register holds. There is no
  /// unsigned form; a front end that needs one builds it on this. When the
  /// given float is too large to be represented as an integer, the result is
  /// MIN_INT, i.e., 0x80000000 for 32-bit integers and 0x8000000000000000 for
  /// 64-bit ones.
  /// </summary>
  | FloatToSInt = 4
  /// Float-to-float conversion between different precisions.
  | FloatCast = 5
  /// <summary>
  /// Float to an integral value of the same format, in whatever direction is
  /// in force: the one a <c>RoundCtrl</c> expression names, or, outside every
  /// RoundCtrl, the one the target's own control register holds. This is C's
  /// <c>rint</c>; <c>FloatCast</c> is the one that changes the format.
  /// </summary>
  | RoundToIntegral = 6

/// <summary>
/// Provides functions to access <see cref='T:B2R2.BinIR.CastKind'/>.
/// </summary>
[<RequireQualifiedAccess>]
module CastKind =
  /// <summary>
  /// Retrieves the string representation of the cast kind.
  /// </summary>
  [<CompiledName "ToString">]
  let toString = function
    | CastKind.SignExt -> "sext"
    | CastKind.ZeroExt -> "zext"
    | CastKind.SIntToFloat -> "sfloat"
    | CastKind.UIntToFloat -> "ufloat"
    | CastKind.FloatToSInt -> "fsint"
    | CastKind.FloatCast -> "fext"
    | CastKind.RoundToIntegral -> "rint"
    | _ -> raise IllegalASTTypeException

  /// <summary>
  /// Whether the result of the conversion depends on the rounding direction in
  /// force, which makes it unfoldable wherever that direction is unknown.
  /// </summary>
  /// <remarks>
  /// A float-to-float conversion that only widens is exact and could be folded
  /// whatever the direction, but the kind alone does not say which way it
  /// goes, and the fold is an optimisation rather than something anything
  /// depends on.
  /// </remarks>
  [<CompiledName "IsRoundingDependent">]
  let isRoundingDependent = function
    | CastKind.SignExt
    | CastKind.ZeroExt -> false
    | _ -> true

  /// <summary>
  /// Retrieves the cast kind from the string representation.
  /// </summary>
  [<CompiledName "OfString">]
  let ofString = function
    | "sext" -> CastKind.SignExt
    | "zext" -> CastKind.ZeroExt
    | "sfloat" -> CastKind.SIntToFloat
    | "ufloat" -> CastKind.UIntToFloat
    | "fsint" -> CastKind.FloatToSInt
    | "fext" -> CastKind.FloatCast
    | "rint" -> CastKind.RoundToIntegral
    | _ -> raise IllegalASTTypeException
