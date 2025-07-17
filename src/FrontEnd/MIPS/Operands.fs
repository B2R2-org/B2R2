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

open B2R2

/// Represents a set of operands in an MIPS instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand

/// Represents an operand in an MIPS instruction.
and Operand =
  | OpReg of Register
  | OpImm of Imm
  | OpMem of Base * Offset * AccessLength
  | OpAddr of JumpTarget
  | OpShiftAmount of Imm
  | GoToLabel of Label

/// Represents a immediate in MIPS instruction.
and Imm = uint64

/// Represents a base register in memory addressing.
and Base = Register

/// Represents an offset value in memory addressing.
and Offset =
  | Imm of int64
  | Reg of Register

/// Represents the memory access width in MIPS instructions.
and AccessLength = RegType

/// Represents a jump target as a relative offset.
and JumpTarget = Relative of int64

/// Represents a label in MIPS instructions.
and Label = string
