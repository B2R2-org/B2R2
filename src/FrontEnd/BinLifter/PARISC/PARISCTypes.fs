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

namespace B2R2.FrontEnd.BinLifter.PARISC

open B2R2
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.BinLifter.Tests")>]
do ()

/// <summary>
///   PARISC opcodes. This type should be generated using
///   <c>scripts/genOpcode.fsx</c> from the `PARISC64SupportedOpcode.txt`
///   file.
/// </summary>
type Opcode =
  | ADD = 0
  | ADDL = 138
  | ADDC = 139
  | SHLADD = 1
  | SHLADDL = 140
  | SUB = 2
  | SUBB = 141
  | OR = 3
  | XOR = 4
  | AND = 5
  | ANDCM = 6
  | UADDCM = 7
  | UXOR = 8
  | DS = 9
  | CMPCLR = 10
  | DCOR = 11
  (* Immediate Arithmetic Instructions *)
  | ADDI = 12
  | SUBI = 13
  | CMPICLR = 14
  (* Shift Pair, Extract & Deposit Instructions *)
  | SHRPD = 15
  | SHRPW = 16
  | EXTRD = 17
  | EXTRW = 18
  | DEPD = 19
  | DEPDI = 20
  | DEPW = 21
  | DEPWI = 22
  (* Parallel Halfword Arithmetic Instructions *)
  | HADD = 23
  | HSUB = 24
  | HAVG = 25
  (* Parallel Halfword Shift Instructions *)
  | HSHLADD = 26
  | HSHRADD = 27
  | HSHL = 28
  | HSHR = 29
  (* Rearrangement Instructions *)
  | PERMH = 30
  | MIXH = 31
  | MIXW = 32
  (* Load/Store Instructions *)
  | LDB = 33
  | LDBS = 132
  | STB = 34
  | STBS = 133
  | LDH = 35
  | STH = 36
  | LDW = 37
  | LDWS = 130
  | STW = 38
  | STWS = 131
  | LDD = 39
  | STD = 40
  (* Load/Store Absolute Instructions *)
  | LDWA = 41
  | STWA = 42
  | LDDA = 43
  | STDA = 44
  (* Load and Clear Instructions *)
  | LDCW = 45
  | LDCD = 46
  (* Store Bytes/DoubleWord Bytes Instructions *)
  | STBY = 47
  | STDBY = 48
  (* Long Immediate Instructions *)
  | LDO = 49
  | LDIL = 50
  | ADDIL = 51
  (* Unconditional Local Branches *)
  | BL = 52
  | BLR = 53
  | BV = 54
  (* Unconditional External Branches *)
  | BE = 55
  | BVE = 56
  (* Conditional Local Branches *)
  | ADDB = 57
  | ADDIB = 58
  | BB = 59
  | CMPB = 60
  | CMPIB = 61
  | MOVB = 62
  | MOVIB = 63
  (* Special Register Move Instructions *)
  | LDSID = 64
  | MTSP = 65
  | MFSP = 66
  | MTCTL = 67
  | MFCTL = 68
  | MTSARCM = 69
  | MFIA = 70
  (* System Mask Control Instructions *)
  | SSM = 71
  | RSM = 72
  | MTSM = 73
  (* Return From Interrupt & Break Instructions *)
  | RFI = 74
  | BREAK = 75
  (* Memory Management Instructions *)
  | SYNC = 76
  | SYNCDMA = 77
  | PROBE = 78
  | PROBEI = 79
  | LPA = 80
  | LCI = 81
  | PDTLB = 82
  | PITLB = 83
  | PDTLBE = 84
  | PITLBE = 85
  | IDTLBT = 86
  | IITLBT = 87
  | PDC = 88
  | FDC = 89
  | FIC = 90
  | FDCE = 91
  | FICE = 92
  | PUSHBTS = 93
  | PUSHNOM = 94
  (* Implementation-Dependent Instruction *)
  | DIAG = 95
  (* Special Function Instructions *)
  | SPOP0 = 96
  | SPOP1 = 97
  | SPOP2 = 98
  | SPOP3 = 99
  (* Coprocessor Instructions *)
  | COPR = 100
  | CLDD = 101
  | CLDW = 102
  | CSTD = 103
  | CSTW = 104
  (* Floating-Point Load and Store Instructions *)
  | FLDW = 105
  | FLDD = 106
  | FSTW = 107
  | FSTD = 108
  (* Floating-Point Multiply/Add Instructions *)
  | FMPYADD = 109
  | FMPYSUB = 110
  (* Floating-Point Sub-op Multiply/Add Instructions *)
  | FMPYFADD = 111
  | FMPYNFADD = 112
  (* Floating-Point Conversion and Arithmetic Instructions *)
  | FID = 113
  | FCPYDBL = 114
  | FCPYSGL = 142
  | FABS = 115
  | FSQRT = 116
  | FRND = 117
  | FNEG = 118
  | FNEGABS = 119
  (* Floating-Point Conversion Instructions *)
  | FCNV = 120
  (* Floating-Point Compare and Test Instructions *)
  | FCMP = 121
  | FTEST = 122
  (* Floating-Point Arithmetic Instructions *)
  | FADD = 123
  | FSUB = 124
  | FMPY = 125
  | FDIV = 126
  (* Floating-Point interruptions and exceptions *)
  | PMENB = 127
  | PMDIS = 128
  | InvalOP = 129

type internal Op = Opcode

type RoundMode =
  // Round to Nearest
  | RN = 0
  // Round toward Zero
  | RZ = 1
  // Round toward +∞
  | RP = 2
  // Round toward −∞
  | RM = 3

type PARISCCondition =
  | NV = 0
  | EQ = 1
  | LT = 2
  | LTU = 3
  | LTE = 4
  | LTEU = 5
  | GT = 6
  | GTU = 7
  | GTE = 8
  | GTEU = 9
  | TR = 10
  | NEQ = 11

type SHIFTST =
  | SARSHFT = 0

type Operand =
  | OpReg of Register
  | OpImm of Imm
  | OpMem of Base * Offset option * AccessLength
  | OpAddr of JumpTarget
  | OpShiftAmount of Imm
  | OpSARSHIFT of SHIFTST
  | OpRoundMode of RoundMode
  | OpAtomMemOper of Aq * Rl
  | OpCSR of uint16
  | OpCond of PARISCCondition (* FIXME *)
and Aq = bool
and Rl = bool
and Imm = uint64
and JumpTarget =
  | Relative of int64
  | RelativeBase of Base * Imm
and Offset =
  | Imm of int64
  | Reg of Register
and AccessLength = RegType
and Base = Register

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand
  | FiveOperands of Operand * Operand * Operand * Operand * Operand

type internal Instruction = Opcode * Operands

/// Basic information obtained by parsing a PARISC instruction.
[<NoComparison; CustomEquality>]
type InsInfo = {
  /// Address.
  Address: Addr
  /// Instruction length.
  NumBytes: uint32
  /// Opcode.
  Opcode: Opcode
  /// Operands.
  Operands: Operands
  /// Operation Size.
  OperationSize: RegType
}
with
  override __.GetHashCode () =
    hash (__.Address,
          __.NumBytes,
          __.Opcode,
          __.Operands,
          __.OperationSize)
  override __.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = __.Address
      && i.NumBytes = __.NumBytes
      && i.Opcode = __.Opcode
      && i.Operands = __.Operands
      && i.OperationSize = __.OperationSize
    | _ -> false

// vim: set tw=80 sts=2 sw=2:
