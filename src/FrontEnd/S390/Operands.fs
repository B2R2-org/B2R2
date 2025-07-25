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

namespace B2R2.FrontEnd.S390

open B2R2

/// Represents a set of operands in an S390 instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand
  | FiveOperands of Operand * Operand * Operand * Operand * Operand
  | SixOperands of Operand * Operand * Operand * Operand * Operand * Operand

/// Represents an operand used in an S390 instruction.
and Operand =
  | OpReg of Register
  | OpImm of ImmType
  | OpRImm of ImmType
  | OpMask of Mask
  | OpStore of Index * Base * Displacement
  | OpStoreLen of Length * Base * Displacement

/// Represents an immediate value used in S390 instructions.
and ImmType =
  | ImmU4 of BitVector
  | ImmU8 of uint8
  | ImmS8 of int8
  | ImmU12 of BitVector
  | ImmS12 of BitVector
  | ImmU16 of uint16
  | ImmS16 of int16
  | ImmS24 of BitVector
  | ImmU32 of uint32
  | ImmS32 of int32

/// Represents a mask field used in S390 instructions.
and Mask = uint16

/// Represents an optional index register used in address computation.
and Index = Register option

/// Represents a base register used in address computation.
and Base = Register

/// Represents a displacement value used in address computation.
and Displacement =
  | DispS of int32
  | DispU of uint32
  | DispS20 of BitVector
  | DispU12 of BitVector

/// Represents a length field used in storage-related instructions.
and Length = uint16
