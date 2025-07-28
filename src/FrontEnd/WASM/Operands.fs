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

namespace B2R2.FrontEnd.WASM

open B2R2

/// Represents a set of operands in an WASM instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | Operands of Operand list

/// Represents an operand used in an WASM instruction.
and Operand =
  | I32 of uint32
  | I64 of uint64
  | F32 of BitVector
  | F64 of BitVector
  | V128 of BitVector * BitVector * BitVector * BitVector
  | Type of int
  | RefType of int
  | Index of uint32
  | Alignment of uint32
  | Address of uint32
  | LaneIndex of uint8
  | ConsistencyModel of uint8
