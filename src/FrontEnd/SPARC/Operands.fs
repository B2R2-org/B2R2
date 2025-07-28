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

namespace B2R2.FrontEnd.SPARC

open B2R2

/// Represents a set of operands in an SPARC instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand
  | FiveOperands of Operand * Operand * Operand * Operand * Operand

/// Represents an operand used in an SPARC instruction.
and Operand =
  | OprReg of Register
  | OprImm of Const
  | OprAddr of Const
  | OprMemory of AddressingMode
  | OprCC of ConditionCode
  | OprPriReg of Register

/// Represents a constant value used in SPARC instructions.
and Const = int32

/// Represents addressing modes used in SPARC instructions.
and AddressingMode =
  | DispMode of Register * Const
  | PreIdxMode of Register
  | PostIdxMode of Register
  | UnchMode of Register

/// Represents a condition code used in SPARC instructions.
and ConditionCode =
  /// Floating-point condition code (FCC0-FCC3), used for floating-point
  /// comparisons.
  | Fcc0 = 0
  | Fcc1 = 1
  | Fcc2 = 2
  | Fcc3 = 3
  /// Integer condition code (ICC), based on 32-bit integer operation results.
  | Icc = 4
  /// Extended integer condition code (XCC), based on 64-bit integer operation
  /// results.
  | Xcc = 5
  /// Invalid Condition Code.
  | InvalidCC = 6

/// Provides functions related to condition codes in SPARC instructions.
[<RequireQualifiedAccess>]
module ConditionCode =
  let inline ofRegID (n: RegisterID): ConditionCode =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: ConditionCode) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "fcc0" -> ConditionCode.Fcc0
    | "fcc1" -> ConditionCode.Fcc1
    | "fcc2" -> ConditionCode.Fcc2
    | "fcc3" -> ConditionCode.Fcc3
    | "icc" -> ConditionCode.Icc
    | "xcc" -> ConditionCode.Xcc
    | _ -> Terminator.impossible ()

  let toString = function
    | ConditionCode.Fcc0 -> "%fcc0"
    | ConditionCode.Fcc1 -> "%fcc1"
    | ConditionCode.Fcc2 -> "%fcc2"
    | ConditionCode.Fcc3 -> "%fcc3"
    | ConditionCode.Icc -> "%icc"
    | ConditionCode.Xcc -> "%xcc"
    | _ -> Terminator.impossible ()
