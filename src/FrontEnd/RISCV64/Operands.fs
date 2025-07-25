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

namespace B2R2.FrontEnd.RISCV64

open B2R2

/// Represents a set of operands in a RISCV64 instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand
  | FiveOperands of Operand * Operand * Operand * Operand * Operand

/// Represents an operand used in a RISCV64 instruction.
and Operand =
  | OpReg of Register
  | OpImm of Imm
  | OpMem of Base * Offset option * AccessLength
  | OpAddr of JumpTarget
  | OpShiftAmount of Imm
  | OpFenceMask of FenceMask * FenceMask
  | OpAtomMemOper of Aq * Rl
  | OpRoundMode of RoundMode
  | OpCSR of uint16

/// Represents an immediate value in RISCV64 instructions.
and Imm = uint64

/// Represents a base register used in memory addressing.
and Base = Register

/// Represents an offset used in memory addressing.
and Offset = Imm of int64

/// Represents the memory access width in RISCV64 instructions.
and AccessLength = RegType

/// Represents a jump target in RISCV64 instructions.
and JumpTarget =
  | Relative of int64
  | RelativeBase of Base * Imm

/// Represents a memory fence mask in RISCV64 instructions.
and FenceMask = uint8

/// Represents the acquire flag in atomic memory operations.
and Aq = bool

/// Represents the release flag in atomic memory operations.
and Rl = bool

/// Represents a rounding mode used in RISCV64 floating-point instructions.
and RoundMode =
  // Round to Nearest, ties to Even
  | RNE = 0
  // Round towards Zero
  | RTZ = 1
  // Round Down
  | RDN = 2
  // Round Up
  | RUP = 3
  // Round to Nearest, ties to Max Magnitude
  | RMM = 4
  // In instruction's rm field selects dynamic mode;
  // In Rounding Mode register, Invalid
  | DYN = 7
