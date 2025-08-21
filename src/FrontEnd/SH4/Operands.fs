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

namespace B2R2.FrontEnd.SH4

/// Represents a set of operands in an SH4 instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand

/// Represents an operand used in an SH4 instruction.
and Operand =
  | OpImm of Const
  | OpAddr of Const
  | OpReg of AddressingMode

/// Represents a constant value used in SH4 instructions.
and Const = int32

/// Represents addressing modes used in SH4 instructions.
and AddressingMode =
  /// Register direct
  | Regdir of Register
  /// Register indirect
  | RegIndir of Register
  /// Register indirect with post-increment
  | RegIndirPostInc of Register
  /// Register indirect with pre-decrement
  | RegIndirPreDec of Register
  /// Register indirect with displacement
  | RegIndirDisp of Const * Register
  /// Indexed register indirect
  | IdxRegIndir of Register * Register
  /// GBR indirect with displacement
  | GBRIndirDisp of Const * Register
  /// Indexed GBR indirect
  | IdxGBRIndir of Register * Register
  /// PC-relative with displacement
  | PCRelDisp of Const * Register
  /// PC-relative
  | PCRelative of Const
  /// Immediate
  | Imm of Const
