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

open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd.BinLifter

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.Intel.Tests")>]
[<assembly: InternalsVisibleTo("B2R2.Peripheral.Assembly.Intel")>]
do ()

/// Instruction prefixes.
[<System.FlagsAttribute>]
type Prefix =
  /// No prefix.
  | PrxNone = 0x0
  /// Lock prefix.
  | PrxLOCK = 0x1
  /// REPNE/REPNZ prefix is encoded using F2H.
  | PrxREPNZ = 0x2
  /// Bound prefix is encoded using F2H.
  | PrxBND = 0x4
  /// REP or REPE/REPZ is encoded using F3H.
  | PrxREPZ = 0x8
  /// CS segment prefix.
  | PrxCS = 0x10
  /// SS segment prefix.
  | PrxSS = 0x20
  /// DS segment prefix.
  | PrxDS = 0x40
  /// ES segment prefix.
  | PrxES = 0x80
  /// FS segment prefix.
  | PrxFS = 0x100
  /// GS segment prefix.
  | PrxGS = 0x200
  /// Operand-size override prefix is encoded using 66H.
  | PrxOPSIZE = 0x400
  /// 67H - Address-size override prefix.
  | PrxADDRSIZE = 0x800

/// REX prefixes.
type REXPrefix =
  /// No REX: this is to represent the case where there is no REX
  | NOREX = 0b0000000
  /// Extension of the ModR/M reg, Opcode reg field (SPL, BPL, ...).
  | REX = 0b1000000
  /// Extension of the ModR/M rm, SIB base, Opcode reg field.
  | REXB = 0b1000001
  /// Extension of the SIB index field.
  | REXX = 0b1000010
  /// Extension of the ModR/M SIB index, base field.
  | REXXB = 0b1000011
  /// Extension of the ModR/M reg field.
  | REXR = 0b1000100
  /// Extension of the ModR/M reg, r/m field.
  | REXRB = 0b1000101
  /// Extension of the ModR/M reg, SIB index field.
  | REXRX = 0b1000110
  /// Extension of the ModR/M reg, SIB index, base.
  | REXRXB = 0b1000111
  /// Operand 64bit.
  | REXW = 0b1001000
  /// REX.B + Operand 64bit.
  | REXWB = 0b1001001
  /// REX.X + Operand 64bit.
  | REXWX = 0b1001010
  /// REX.XB + Operand 64bit.
  | REXWXB = 0b1001011
  /// REX.R + Operand 64bit.
  | REXWR = 0b1001100
  /// REX.RB + Operand 64bit.
  | REXWRB = 0b1001101
  /// REX.RX + Operand 64bit.
  | REXWRX = 0b1001110
  /// REX.RXB + Operand 64bit.
  | REXWRXB = 0b1001111

/// We define 8 different RegGrp types. Intel instructions use an integer value
/// such as a REG field of a ModR/M value.
type RegGrp =
  /// AL/AX/EAX/...
  | RG0 = 0
  /// CL/CX/ECX/...
  | RG1 = 1
  /// DL/DX/EDX/...
  | RG2 = 2
  /// BL/BX/EBX/...
  | RG3 = 3
  /// AH/SP/ESP/...
  | RG4 = 4
  /// CH/BP/EBP/...
  | RG5 = 5
  /// DH/SI/ESI/...
  | RG6 = 6
  /// BH/DI/EDI/...
  | RG7 = 7

/// Opcode groups defined in manual Vol 2. Table A-6.
type OpGroup =
  | G1 = 0
  | G1Inv64 = 1
  | G1A = 2
  | G2 = 3
  | G3A = 4
  | G3B = 5
  | G4 = 6
  | G5 = 7
  | G6 = 8
  | G7 = 9
  | G8 = 10
  | G9 = 11
  | G10 = 12
  | G11A = 13
  | G11B = 14
  | G12 = 15
  | G13 = 16
  | G14 = 17
  | G15 = 18
  | G16 = 19
  | G17 = 20

/// The scale of Scaled Index.
type Scale =
  /// Times 1
  | X1 = 1
  /// Times 2
  | X2 = 2
  /// Times 4
  | X4 = 4
  /// Times 8
  | X8 = 8

/// Scaled index.
type ScaledIndex = Register * Scale

/// Jump target of a branch instruction.
type JumpTarget =
  | Absolute of Selector * Addr * OperandSize
  | Relative of Offset
and Selector = int16
and Offset = int64
and OperandSize = RegType

/// We define four different types of X86 operands:
/// register, memory, direct address, and immediate.
type Operand =
  /// A register operand.
  | OprReg of Register
  /// OprMem represents a memory operand. The OperandSize here means the memory
  /// access size of the operand, i.e., how many bytes do we read/write here.
  | OprMem of Register option
            * ScaledIndex option
            * Disp option
            * OperandSize
  /// OprDirAddr is a direct branch target address.
  | OprDirAddr of JumpTarget
  /// OprImm represents an immediate operand. The OperandSize here means the
  /// size of the encoded immediate value.
  | OprImm of int64 * OperandSize
  /// Label is *not* encoded in the actual binary. This is only used when we
  /// assemble binaries.
  | Label of string * RegType
/// Displacement.
and Disp = int64

/// A set of operands in an X86 instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand

/// Specific conditions for determining the size of operands.
/// (See Table A-1, Appendix A.2.5 of Vol. 2D).
type SzCond =
  /// (d64) When in 64-bit mode, instruction defaults to 64-bit operand size and
  /// cannot encode 32-bit operand size.
  | D64 = 0
  /// (f64) The operand size is forced to a 64-bit operand size when in 64-bit
  /// mode (prefixes that change operand size, e.g., 66 prefix, are ignored for
  /// this instruction in 64-bit mode).
  | F64 = 1
  /// Normal conditions. This includes all other size conditions in Table A-1.
  | Nor = 2

/// Types of VEX (Vector Extension).
[<System.FlagsAttribute>]
type VEXType =
  /// Original VEX that refers to two-byte opcode map.
  | VEXTwoByteOp = 0x1
  /// Original VEX that refers to three-byte opcode map #1.
  | VEXThreeByteOpOne = 0x2
  /// Original VEX that refers to three-byte opcode map #2.
  | VEXThreeByteOpTwo = 0x4
  /// EVEX Mask
  | EVEX = 0x10

/// Intel's memory operand is represented by two tables (ModR/M and SIB table).
/// Some memory operands do need SIB table lookups, whereas some memory operands
/// only need to look up the ModR/M table.
type internal MemLookupType =
  | SIB (* Need SIB lookup *)
  | NOSIB of RegGrp option (* No need *)

/// Vector destination merging/zeroing: P[23] encodes the destination result
/// behavior which either zeroes the masked elements or leave masked element
/// unchanged.
type ZeroingOrMerging =
  | Zeroing
  | Merging

/// Static Rounding Mode and SAE control can be enabled in the encoding of the
/// instruction by setting the EVEX.b bit to 1 in a register-register vector
/// instruction.
type StaticRoundingMode =
  | RN (* Round to nearest (even) + SAE *)
  | RD (* Round down (toward -inf) + SAE *)
  | RU (* Round up (toward +inf) + SAE *)
  | RZ (* Round toward zero (Truncate) + SAE *)

type EVEXPrefix = {
  /// Embedded opmask register specifier, P[18:16].
  AAA: uint8
  /// Zeroing/Merging, P[23].
  Z: ZeroingOrMerging
  /// Broadcast/RC/SAE Context, P[20].
  B: uint8
  /// Reg-reg, FP Instructions w/ rounding semantic or SAE, P2[6:5].
  RC: StaticRoundingMode
}

/// Information about Intel vector extension.
type VEXInfo = {
  VVVV: byte
  VectorLength: RegType
  VEXType: VEXType
  VPrefixes: Prefix
  EVEXPrx: EVEXPrefix option
}

/// Mandatory prefixes. The 66H, F2H, and F3H prefixes are mandatory for opcode
/// extensions.
type MPref =
  /// Indicates the use of 66/F2/F3 prefixes (beyond those already part of the
  /// instructions opcode) are not allowed with the instruction.
  | MPrxNP = 0
  /// 66 prefix.
  | MPrx66 = 1
  /// F3 prefix.
  | MPrxF3 = 2
  /// F2 prefix.
  | MPrxF2 = 3
  /// 66 & F2 prefix.
  | MPrx66F2 = 4

/// The tupletype will be referenced in the instruction operand encoding table
/// in the reference page of each instruction, providing the cross reference for
/// the scaling factor N to encoding memory addressing operand.
type TupleType =
  /// Compressed Displacement (DISP8*N) Affected by Embedded Broadcast.
  | Full = 0
  | Half = 1
  /// EVEX DISP8*N for Instructions Not Affected by Embedded Broadcast.
  | FullMem = 2
  | Tuple1Scalar = 3
  | Tuple1Fixed = 4
  | Tuple2 = 5
  | Tuple4 = 6
  | Tuple8 = 7
  | HalfMem = 8
  | QuarterMem = 9
  | EighthMem = 10
  | Mem128 = 11
  | MOVDDUP = 12
  | NA = 13 (* N/A *)
