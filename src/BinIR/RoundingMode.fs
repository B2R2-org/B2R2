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

open B2R2

/// <summary>
/// Represents the direction a floating-point result takes when it does not fit
/// its format exactly, used as the mode of a <c>RoundCtrl</c> expression.
/// </summary>
/// <remarks>
/// The values are x86's MXCSR.RC encoding, which every other target is mapped
/// onto. A mode this enumeration does not name rounds to nearest; a target
/// that has to reject such a value -- RISC-V's reserved frm encodings, say --
/// does so with a check of its own, that being a question of instruction
/// validity rather than of rounding.
/// </remarks>
type RoundingMode =
  /// Round to the nearest representable value, ties to even. Every target
  /// starts here, and nearly all code stays.
  | ToNearestEven = 0
  /// Round toward negative infinity.
  | TowardNegative = 1
  /// Round toward positive infinity.
  | TowardPositive = 2
  /// Round toward zero, i.e., truncate the result.
  | TowardZero = 3
  /// Round to the nearest representable value, ties AWAY from zero. x86 has no
  /// such direction and MXCSR.RC cannot name it; RISC-V's frm can, as its mode
  /// 4, and this is why the enumeration runs one past the two bits MXCSR gives
  /// it. It differs from ToNearestEven only where the exact result falls
  /// precisely halfway between two representable values.
  | ToNearestAway = 4

/// <summary>
/// Provides functions to access <see cref='T:B2R2.BinIR.RoundingMode'/>.
/// </summary>
[<RequireQualifiedAccess>]
module RoundingMode =
  /// <summary>
  /// The width of a rounding mode expression, which every <c>RoundCtrl</c> mode
  /// has to be of.
  /// </summary>
  [<CompiledName "ModeType">]
  let modeType = 8<rt>

  /// <summary>
  /// Retrieves the string representation of the rounding mode.
  /// </summary>
  [<CompiledName "ToString">]
  let toString = function
    | RoundingMode.ToNearestEven -> "rne"
    | RoundingMode.TowardNegative -> "rdn"
    | RoundingMode.TowardPositive -> "rup"
    | RoundingMode.TowardZero -> "rtz"
    | RoundingMode.ToNearestAway -> "rmm"
    | _ -> raise IllegalASTTypeException

  /// <summary>
  /// Retrieves the rounding mode from the string representation.
  /// </summary>
  [<CompiledName "OfString">]
  let ofString = function
    | "rne" -> RoundingMode.ToNearestEven
    | "rdn" -> RoundingMode.TowardNegative
    | "rup" -> RoundingMode.TowardPositive
    | "rtz" -> RoundingMode.TowardZero
    | "rmm" -> RoundingMode.ToNearestAway
    | _ -> raise IllegalASTTypeException
