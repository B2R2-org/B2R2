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

namespace B2R2.FrontEnd.Intel

open B2R2

/// Represents a set of operands in an intel instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand

/// Represents four different types of intel operands:
/// register, memory, direct address, and immediate.
and Operand =
  /// A register operand.
  | OprReg of Register
  /// OprMem represents a memory operand. The OperandSize here means the memory
  /// access size of the operand, i.e., how many bytes do we read/write here.
  | OprMem of Register option
            * ScaledIndex option
            * Displacement option
            * OperandSize
  /// OprDirAddr is a direct branch target address.
  | OprDirAddr of JumpTarget
  /// OprImm represents an immediate operand. The OperandSize here means the
  /// size of the encoded immediate value.
  | OprImm of int64 * OperandSize
  /// Label is *not* encoded in the actual binary. This is only used when we
  /// assemble binaries.
  | Label of string * RegType

/// Represents a scaled index composed of a register and a scaling factor.
and ScaledIndex = Register * Scale

/// Represents the scaling factor used in index addressing.
and Scale =
  /// Times 1
  | X1 = 1
  /// Times 2
  | X2 = 2
  /// Times 4
  | X4 = 4
  /// Times 8
  | X8 = 8

/// Represents a displacement value used for memory offset calculations.
and Displacement = int64

/// Represents operand size.
and OperandSize = RegType

/// Represents the target of a jump instruction.
and JumpTarget =
  | Absolute of SegmentSelector * Addr * OperandSize
  | Relative of Offset

/// Represents a segment selector used in intel architecture.
and SegmentSelector = int16

/// Represents an offset value used for relative jump instructions.
and Offset = int64

/// Provides several accessor functions for operands.
[<RequireQualifiedAccess>]
module internal Operands =
  let inline getMod (byte: byte) = (int byte >>> 6) &&& 0b11

  let inline getReg (byte: byte) = (int byte >>> 3) &&& 0b111

  let inline getRM (byte: byte) = (int byte) &&& 0b111

  let inline getSTReg n = Register.streg n |> OprReg

  let inline modIsMemory b = (getMod b) <> 0b11

  let inline modIsReg b = (getMod b) = 0b11
