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

namespace B2R2.FrontEnd.Alpha

/// Represents a set of operands in an Alpha instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand

/// Represents an operand used in an Alpha instruction.
and Operand =
  /// One of the general or floating-point registers.
  | OprReg of Register
  /// A number written where an encoding holds one: what an Operate instruction
  /// computes from in place of a second register, the hint a computed branch
  /// carries, or the function code a trap to PALcode names its routine by.
  | OprImm of uint64
  /// The memory an instruction reaches, written as a signed displacement
  /// counted from a register.
  | OprMem of Register * Disp
  /// The memory an instruction reaches, named by a register alone, which is
  /// what the instructions spending the displacement field on a function code
  /// reach.
  | OprBase of Register
  /// How far away the place a branch names is, counted in bytes from the
  /// instruction after the branch, which is where the machine counts from.
  | OprAddr of Disp

/// Represents a displacement in an Alpha instruction. The field holding one is
/// narrower than this, and what is kept here is the field widened to a signed
/// word, because that is what the machine adds.
and Disp = int32

// vim: set tw=80 sts=2 sw=2:
