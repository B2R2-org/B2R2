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

namespace B2R2.FrontEnd.ARM64

/// Represents a set of operands in an ARM64 instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand
  | FiveOperands of Operand * Operand * Operand * Operand * Operand

/// Represents a single operand used in an ARM64 instruction.
and Operand =
  | OprRegister of Register
  (* SIMD&FP register *)
  | OprSIMD of SIMDFPRegister
  (* SIMD vector register list or SIMD vector element list *)
  | OprSIMDList of SIMDFPRegister list
  | OprImm of Const
  | OprFPImm of float
  | OprNZCV of uint8
  | OprShift of Shift
  | OprExtReg of RegisterOffset option
  | OprMemory of AddressingMode
  | OprOption of OptionOpr
  | OprPstate of Pstate
  | OprPrfOp of PrefetchOperation
  | OprCond of Condition
  | OprFbits of uint8  (* fractional bits *)
  | OprLSB of uint8

/// Represents a SIMD/FP register used in ARM64 instructions, including scalar
/// and vector forms.
and SIMDFPRegister =
  | SIMDFPScalarReg of SIMDFPscalRegister
  | SIMDVecReg of SIMDVectorRegister
  | SIMDVecRegWithIdx of SIMDVectorRegisterWithIndex

/// Represents a scalar SIMD or FP register in ARM64.
and SIMDFPscalRegister = Register

/// Represents a SIMD vector register with a vector type.
and SIMDVectorRegister = Register * SIMDVector

/// Represents a SIMD vector register with an element index.
and SIMDVectorRegisterWithIndex = Register * SIMDVector * Index

/// Represents SIMD vector types.
and SIMDVector =
  | VecB
  | VecH
  | VecS
  | VecD
  | EightB
  | SixteenB
  | FourH
  | EightH
  | TwoS
  | FourS
  | OneD
  | TwoD
  | OneQ

/// Represents an element index in a SIMD vector register.
and Index = uint8

/// Represents an immediate constant value used in ARM64 instructions.
and Const = int64

/// Represents a shift operation with type and amount.
and Shift = SRType * Amount

/// Represents shift types used in ARM64.
and SRType =
  | SRTypeLSL
  | SRTypeLSR
  | SRTypeASR
  | SRTypeROR
  | SRTypeRRX
  | SRTypeMSL

/// Represents an immediate or register-based shift amount.
and Amount =
  | Imm of Const
  | Reg of Register

/// Represents register-based offset used in ARM64 memory addressing.
and RegisterOffset =
  | ShiftOffset of Shift (*  Register offset *)
  | ExtRegOffset of ExtendRegisterOffset (* Extended register offset *)

/// Represents a register extension with an optional offset.
and ExtendRegisterOffset = ExtendType * Const option

/// Represents value extension types used in ARM64 instructions.
and ExtendType =
  | ExtUXTB
  | ExtUXTH
  | ExtUXTW
  | ExtUXTX
  | ExtSXTB
  | ExtSXTH
  | ExtSXTW
  | ExtSXTX

/// Represents the addressing mode used in ARM64 memory access.
and AddressingMode =
  | BaseMode of Offset
  | PreIdxMode of Offset
  | PostIdxMode of Offset
  | LiteralMode of Offset

/// Represents offset values used in memory addressing.
and Offset =
  | ImmOffset of ImmOffset
  | RegOffset of Register * Register * RegisterOffset option

/// Represents an immediate offset or PC-relative label.
and ImmOffset =
  | BaseOffset of Register * Const option
  | Lbl of Label

/// Represents a constant label used in PC-relative instructions.
and Label = Const

/// Represents data barrier options used in ARM64 system instructions.
and OptionOpr =
  | SY
  | ST
  | LD
  | ISH
  | ISHST
  | ISHLD
  | NSH
  | NSHST
  | NSHLD
  | OSH
  | OSHST
  | OSHLD

/// Represents processor state specifiers for ARM64 system instructions.
and Pstate =
  | SPSEL
  | DAIFSET
  | DAIFCLR

/// Represents prefetch operations used for memory hint instructions.
and PrefetchOperation =
  | PLDL1KEEP
  | PLDL1STRM
  | PLDL2KEEP
  | PLDL2STRM
  | PLDL3KEEP
  | PLDL3STRM
  | PSTL1KEEP
  | PSTL1STRM
  | PSTL2KEEP
  | PSTL2STRM
  | PSTL3KEEP
  | PSTL3STRM
  | PLIL1KEEP
  | PLIL1STRM
  | PLIL2KEEP
  | PLIL2STRM
  | PLIL3KEEP
  | PLIL3STRM

/// <summary>
/// Represents a condition code used in the A64 ISA, which includes instructions
/// that either set condition flags, test condition codes, or both.
/// </summary>
and Condition =
  /// Equal/Equal (Z == 1).
  | EQ
  /// Not equal/Not equal or unordered (Z == 0).
  | NE
  /// Carry set/Greater than, equal, or unordered (C == 1).
  /// HS (unsigned higher or same) is a synonym for CS.
  | CS | HS
  /// Carry clear/Less than (C == 0).
  /// LO (unsigned lower) is a synonym for CC.
  | CC | LO
  /// Minus, negative/Less than (N == 1).
  | MI
  /// Plus, positive or zero/Greater than, equal, or unordered (N == 0).
  | PL
  /// Overflow/Unordered (V == 1).
  | VS
  /// No overflow/Ordered (V == 0).
  | VC
  /// Unsigned higher/Greater than, or unordered (C ==1 && Z == 0).
  | HI
  /// Unsigned lower or same/Less than or equal (!(C ==1 && Z ==0)).
  | LS
  /// Signed greater than or equal/Greater than or equal (N == V).
  | GE
  /// Signed less than/Less than, or unordered (N! = V).
  | LT
  /// Signed greater than Greater than (Z == 0 && N == V).
  | GT
  /// Signed less than or equal/Less than, equal, or unordered
  /// (!(Z == 0 && N == V)).
  | LE
  /// Always/Always (Any).
  | AL
  /// Always/Always (Any).
  /// The condition code NV exists only to provide a valid disassembly of
  /// the 0b1111 encoding, otherwise its behavior is identical to AL.
  | NV
