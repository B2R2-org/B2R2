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

namespace B2R2.FrontEnd.AVR

/// Represents a set of operands in an AVR instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand

/// Represents a single operand used in an AVR instruction.
and Operand =
  | OprReg of Register
  | OprImm of Const
  /// A distance from the address just past this instruction, which is how every
  /// relative branch says where it goes.
  | OprAddr of Const
  /// An address written out in full, which is how a long jump or call says
  /// where it goes and how a direct load or store says which byte it reaches.
  | OprAbsAddr of Const
  | OprMemory of AddressingMode

/// Represents an immediate constant value used in AVR instructions.
and Const = int32

/// Represents the addressing mode used in AVR memory access.
and AddressingMode =
  | DispMode of Register * Const
  | PreIdxMode of Register
  | PostIdxMode of Register
  | UnchMode of Register
