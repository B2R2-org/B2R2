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
  /// Float to Nearest Integer rounded conversion
  | FtoIRound = 3
  /// Float to Integer rounded up conversion
  | FtoICeil = 4
  /// Float to Integer rounded down conversion
  | FtoIFloor = 5
  /// Float to Integer truncated conversion
  | FtoITrunc = 6
  /// Float to Float conversion with different precisions
  | FloatExt = 7

module CastKind =
  let toString = function
    | CastKind.SignExt -> "sext"
    | CastKind.ZeroExt -> "zext"
    | CastKind.IntToFloat -> "float"
    | CastKind.FtoIRound -> "round"
    | CastKind.FtoICeil -> "ceil"
    | CastKind.FtoIFloor -> "floor"
    | CastKind.FtoITrunc -> "trunc"
    | CastKind.FloatExt -> "fext"
    | _ -> raise IllegalASTTypeException

  let ofString = function
    | "sext" -> CastKind.SignExt
    | "zext" -> CastKind.ZeroExt
    | "itof" -> CastKind.IntToFloat
    | "round" -> CastKind.FtoIRound
    | "ceil" -> CastKind.FtoICeil
    | "floor" -> CastKind.FtoIFloor
    | "trunc" -> CastKind.FtoITrunc
    | "fext" -> CastKind.FloatExt
    | _ -> raise IllegalASTTypeException
