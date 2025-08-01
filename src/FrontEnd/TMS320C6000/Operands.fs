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

namespace B2R2.FrontEnd.TMS320C6000

/// Represents a set of operands in a TMS320C6000 instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand

/// Represents an operand used in a TMS320C6000 instruction.
and Operand =
  | OpReg of Register
  | RegisterPair of Register * Register
  | OprMem of Register * ModificationPerformed * Offset
  | Immediate of Imm

/// Represents an immediate value used in TMS320C6000 instructions.
and Imm = uint64

/// Represents the type of address modification performed during memory access.
and ModificationPerformed =
  | NegativeOffset
  | PositiveOffset
  | PreDecrement
  | PreIncrement
  | PostDecrement
  | PostIncrement

/// Represents an offset used in memory addressing.
and Offset =
  | OffsetR of Register
  | UCst5 of uint64
  | UCst15 of uint64
