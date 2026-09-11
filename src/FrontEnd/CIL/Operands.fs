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

namespace B2R2.FrontEnd.CIL

open B2R2

/// <summary>
/// Represents the operands of a CIL instruction, of which there is never more
/// than one. An instruction takes what it works on from the evaluation stack,
/// and the one operand it may carry says which method, field, variable,
/// constant or target it means.
/// </summary>
type Operands =
  | NoOperand
  | OneOperand of Operand

/// Represents an operand of a CIL instruction.
and Operand =
  /// An argument or a local variable, by its index.
  | OprVar of uint16
  /// A 32-bit integer constant. The short form carries one byte, which is
  /// sign-extended.
  | OprI4 of int32
  /// A 64-bit integer constant.
  | OprI8 of int64
  /// A 32-bit floating-point constant.
  | OprR4 of float32
  /// A 64-bit floating-point constant.
  | OprR8 of float
  /// The address a branch reaches, computed from the distance the encoding
  /// carries and the address of the instruction after the branch.
  | OprTarget of Addr
  /// The addresses a switch may reach, in the order its table has them.
  | OprTargets of Addr list
  /// A metadata token naming a method, field, type, signature or string.
  | OprToken of uint32
  /// The byte a prefix carries: the alignment an unaligned. promises, or the
  /// checks a no. turns off.
  | OprByte of uint8

// vim: set tw=80 sts=2 sw=2:
