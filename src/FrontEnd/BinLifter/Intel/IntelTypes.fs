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

namespace B2R2.FrontEnd.BinLifter.Intel

open B2R2

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

#if LCACHE
module Prefix =
  let computeHash (pref: Prefix) =
    let pref = int pref
    let grp1 =
      if pref &&& int Prefix.PrxLOCK <> 0 then 0x100000000000000UL
      elif pref &&& int Prefix.PrxREPNZ <> 0 then 0x200000000000000UL
      elif pref &&& int Prefix.PrxBND <> 0 then 0x300000000000000UL
      elif pref &&& int Prefix.PrxREPZ <> 0 then 0x400000000000000UL
      else 0UL
    let grp2 =
      if pref &&& int Prefix.PrxCS <> 0 then 0x800000000000000UL
      elif pref &&& int Prefix.PrxSS <> 0 then 0x1000000000000000UL
      elif pref &&& int Prefix.PrxDS <> 0 then 0x1800000000000000UL
      elif pref &&& int Prefix.PrxES <> 0 then 0x2000000000000000UL
      elif pref &&& int Prefix.PrxFS <> 0 then 0x2800000000000000UL
      elif pref &&& int Prefix.PrxGS <> 0 then 0x3000000000000000UL
      else 0UL
    let grp3 = (uint64 (pref &&& int Prefix.PrxOPSIZE)) <<< 52
    let grp4 = (uint64 (pref &&& int Prefix.PrxADDRSIZE)) <<< 52
    grp1 ||| grp2 ||| grp3 ||| grp4
#endif

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
  | OprMem of Register option * ScaledIndex option * Disp option * OperandSize
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

type EVEXPrefix = {
  /// Embedded opmask register specifier, P[18:16].
  AAA: uint8
  /// Zeroing/Merging, P[23].
  Z: ZeroingOrMerging
  /// Broadcast/RC/SAE Context, P[20].
  B: uint8
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

/// Basic information obtained by parsing an Intel instruction.
type InsInfo = {
  /// Prefixes.
  Prefixes: Prefix
  /// REX Prefix.
  REXPrefix: REXPrefix
  /// VEX information.
  VEXInfo: VEXInfo option
  /// Opcode.
  Opcode: Opcode
  /// Operands.
  Operands: Operands
  /// Size of the main operation performed by the instruction. This field is
  /// mainly used by our lifter, and we suggest not to use this field for
  /// analyzing binaries because there is some ambiguity in deciding the
  /// operation size when the instruction semantics are complex. We use this
  /// only for the purpose of optimizing the lifting process.
  MainOperationSize: RegType
  /// Size of the memory pointer in the instruction, i.e., how many bytes are
  /// required to represent a memory address. This field may hold a dummy value
  /// if there's no memory operand. This is mainly used for the lifting purpose
  /// along with the MainOperationSize.
  PointerSize: RegType
#if LCACHE
  /// Instruction hash.
  InsHash: uint64
#endif
}

// vim: set tw=80 sts=2 sw=2:
