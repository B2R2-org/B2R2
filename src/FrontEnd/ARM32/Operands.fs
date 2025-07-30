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

namespace B2R2.FrontEnd.ARM32

open B2R2

/// Represents a set of operands in an ARM32 instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand
  | FiveOperands of Operand * Operand * Operand * Operand * Operand
  | SixOperands of Operand * Operand * Operand * Operand * Operand * Operand

/// Represents a single operand used in an ARM32 instruction.
and Operand =
  | OprReg of Register
  | OprSpecReg of Register * PSRFlag option
  | OprRegList of Register list
  | OprSIMD of SIMDOperand
  | OprImm of Const
  | OprFPImm of float
  | OprShift of Shift
  | OprRegShift of SRType * Register
  | OprMemory of AddressingMode
  | OprOption of BarrierOption
  | OprIflag of Iflag
  | OprEndian of Endian
  | OprCond of Condition
  | GoToLabel of string

/// Represents flag combinations used in ARM32 PSR (Program Status Register).
and PSRFlag =
  | PSRc
  | PSRx
  | PSRxc
  | PSRs
  | PSRsc
  | PSRsx
  | PSRsxc
  | PSRf
  | PSRfc
  | PSRfx
  | PSRfxc
  | PSRfs
  | PSRfsc
  | PSRfsx
  | PSRfsxc
  | PSRnzcv
  | PSRnzcvq
  | PSRg
  | PSRnzcvqg

/// Represents a SIMD operand made of one or more SIMD/FP registers.
and SIMDOperand =
  | SFReg of SIMDFPRegister
  | OneReg of SIMDFPRegister
  | TwoRegs of SIMDFPRegister * SIMDFPRegister
  | ThreeRegs of SIMDFPRegister * SIMDFPRegister * SIMDFPRegister
  | FourRegs of
    SIMDFPRegister * SIMDFPRegister * SIMDFPRegister * SIMDFPRegister

/// Represents a SIMD/FP register, either vector or scalar with optional element
/// index.
and SIMDFPRegister =
  | Vector of Register
  | Scalar of Register * Element option

/// Represents an index into a SIMD scalar register element.
and Element = uint8

/// Represents an immediate constant value in an instruction.
and Const = int64

/// Represents an immediate constant value in an instruction.
and Shift = SRType * Amount

/// Represents an immediate value used as a shift amount.
and Amount = Imm of uint32

/// Represents ARM32 shift operation types.
and SRType =
  | SRTypeLSL
  | SRTypeLSR
  | SRTypeASR
  | SRTypeROR
  | SRTypeRRX

/// Represents the addressing mode used in ARM32 memory access.
and AddressingMode =
  | OffsetMode of Offset
  | PreIdxMode of Offset
  | PostIdxMode of Offset
  | UnIdxMode of Register * Const (* [<Rn>], <option> *)
  | LiteralMode of Label

/// Represents a constant label used for PC-relative addressing.
and Label = Const

/// Represents ARM32 offset formats used in memory addressing.
and Offset =
  | ImmOffset of Register * Sign option * Const option
  | RegOffset of Register * Sign option * Register * Shift option
  | AlignOffset of Register * Align option * Register option (* Advanced SIMD *)

/// Represents the sign used in offset calculations.
and Sign =
  | Plus
  | Minus

/// Represents memory alignment value used in SIMD addressing.
and Align = Const

/// Represents memory barrier options used in ARM32 DMB and DSB instructions.
and BarrierOption =
  | OSHLD = 0b0001
  | OSHST = 0b0010
  | OSH = 0b0011
  | NSHLD = 0b0101
  | NSHST = 0b0110
  | NSH = 0b0111
  | ISHLD = 0b1001
  | ISHST = 0b1010
  | ISH = 0b1011
  | LD = 0b1101
  | ST = 0b1110
  | SY = 0b1111

/// Represents interrupt mask flags in ARM32 architecture.
and Iflag =
  | A
  | I
  | F
  | AI
  | AF
  | IF
  | AIF

/// <summary>
/// Represents the conditional execution behavior of ARM instructions.
/// Most ARM instructions, and most Thumb instructions from ARMv6T2 onwards,
/// can be executed conditionally, based on the values of the APSR condition
/// flags. Before ARMv6T2, the only conditional Thumb instruction was
/// the 16-bit conditional branch instruction.
/// </summary>
and Condition =
  /// Equal/Equal (Z == 1).
  | EQ = 0x01
  /// Not equal/Not equal, or unordered (Z == 0).
  | NE = 0x02
  /// Carry set/Greater than, equal, or unordered (C == 1).
  | CS = 0x03
  /// HS (unsigned higher or same) is a synonym for CS.
  | HS = 0x04
  /// Carry clear/Less than (C == 0).
  | CC = 0x05
  /// LO (unsigned lower) is a synonym for CC.
  | LO = 0x06
  /// Minus, negative/Less than (N == 1).
  | MI = 0x07
  /// Plus, positive or zero/Greater than, equal, or unordered (N == 0).
  | PL = 0x08
  /// Overflow/Unordered (V == 1).
  | VS = 0x09
  /// No overflow/Not unordered (V == 0).
  | VC = 0x0A
  /// Unsigned higher/Greater than, or unordered (C == 1 and Z == 0).
  | HI = 0x0B
  /// Unsigned lower or same/Less than or equal (C == 0 or Z == 1).
  | LS = 0x0C
  /// Signed greater than or equal/Greater than or equal (N == V).
  | GE = 0x0D
  /// Signed less than/Less than, or unordered (N != V).
  | LT = 0x0E
  /// Signed greater than/Greater than (Z == 0 and N == V).
  | GT = 0x0F
  /// Signed less than or equal/Less than, equal, or unordered
  /// (Z == 1 or N != V).
  | LE = 0x10
  /// Always (unconditional)/Always (unconditional) Any.
  | AL = 0x11
  /// The condition code NV exists only to provide a valid disassembly of
  /// the 0b1111 encoding, otherwise its behavior is identical to AL.
  | NV = 0x12
  /// Unconditional.
  | UN = 0x13
