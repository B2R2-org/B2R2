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

/// Represents a jump target.
and JumpTarget =
  /// A signed offset from the address of the instruction in the delay slot,
  /// as the conditional branches use.
  | Relative of int64
  /// The instruction index of a PC-region jump, already shifted left two. It
  /// supplies only the low 28 bits of the target; the rest come from the
  /// current program counter, so this cannot be resolved without an address.
  | Region of uint64

/// Represents a label in MIPS instructions.
and Label = string

/// Resolving a jump target that the encoding leaves incomplete.
[<RequireQualifiedAccess>]
module JumpTarget =
  /// Completes a PC-region jump target. The architecture forms it by
  /// concatenating the upper bits of the program counter with the instruction
  /// index, so the index on its own is not an address.
  ///
  /// The upper bits come from the address of the instruction in the DELAY SLOT
  /// rather than from the jump itself -- the jump's address plus four. The two
  /// differ whenever a jump sits in the last word of a 256 MB region, and
  /// taking them from the jump would put the target one region low.
  ///
  /// How many upper bits there are depends on the word size: 63..28 on MIPS64
  /// and 31..28 on MIPS32.
  let regionTarget (addr: Addr) wordSize (index: uint64) =
    let widthMask =
      match wordSize with
      | WordSize.Bit32 -> 0xffffffffUL
      | _ -> System.UInt64.MaxValue
    ((addr + 4UL) &&& widthMask &&& ~~~0xfffffffUL) ||| index
