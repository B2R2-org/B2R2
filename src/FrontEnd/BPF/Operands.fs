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

namespace B2R2.FrontEnd.BPF

/// Represents a set of operands in an eBPF instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand

/// Represents a single operand used in an eBPF instruction.
and Operand =
  | OprReg of Register
  | OprImm of Imm
  /// The memory an instruction reaches, written as the register holding where
  /// to start from and how far from there to reach.
  | OprMem of Register * Disp
  /// A distance from the address just past this instruction, which is how every
  /// jump says where it goes.
  | OprAddr of Rel

/// <summary>
/// Represents a number written in an instruction.
///
/// The field holding one is thirty-two bits wide but for the instruction
/// carrying a whole quadword, and what a narrower field holds is widened as
/// signed before it is used. What is kept here is the bits rather than what
/// they stand for, so that a number is written the same way whatever field it
/// came out of.
/// </summary>
and Imm = uint64

/// Represents how far from what a register holds a load or a store reaches,
/// which the encoding counts in bytes and holds in sixteen bits.
and Disp = int32

/// <summary>
/// Represents how far from the instruction after a jump the place it goes to
/// is.
///
/// The encoding counts this in instructions and it is kept here in the bytes an
/// address counts, which is eight times as many. The two jumps naming their
/// distance in the field a number would sit in reach far enough that eight
/// times it no longer fits in a word, so this is wider than the field any of
/// them holds.
/// </summary>
and Rel = int64

// vim: set tw=80 sts=2 sw=2:
