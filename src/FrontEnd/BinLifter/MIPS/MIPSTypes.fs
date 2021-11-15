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

namespace B2R2.FrontEnd.BinLifter.MIPS

open B2R2
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.BinLifter.Tests")>]
do ()

exception internal InvalidConditionException
exception internal InvalidFmtException

/// MIPS Condition.
type Condition =
  /// False [this predicate is always False].
  | F = 0
  /// Unordered.
  | UN = 1
  /// Equal.
  | EQ = 2
  /// Unordered or Equal.
  | UEQ = 3
  /// Ordered or Less Than.
  | OLT = 4
  /// Unordered or Less Than.
  | ULT = 5
  /// Ordered or Less Than or Equal.
  | OLE = 6
  /// Unordered or Less Than or Equal.
  | ULE = 7
  /// Signaling False [this predicate always False].
  | SF = 8
  /// Not Greater Than or Less Than or Equal.
  | NGLE = 9
  /// Signaling Equal.
  | SEQ = 10
  /// Not Greater Than or Less Than.
  | NGL = 11
  /// Less Than.
  | LT = 12
  /// Not Greater Than or Equal.
  | NGE = 13
  /// Less Than or Equal.
  | LE = 14
  /// Not Greater Than.
  | NGT = 15

/// MIPS floating point format.
type Fmt =
  /// S.
  | S = 0
  /// D.
  | D = 1
  /// W.
  | W = 2
  /// L.
  | L = 3
  /// PS.
  | PS = 4
  /// OB.
  | OB = 5
  /// QH.
  | QH = 6
  /// UNINTERPRETED WORD.
  | UNINTERPRETED_WORD = 7
  /// UNINTERPRETED DOUBLEWORD.
  | UNINTERPRETED_DOUBLEWORD = 8

/// <summary>
///   MIPS opcodes. This type should be generated using
///   <c>scripts/genOpcode.fsx</c> from the `MIPSSupportedOpcode.txt` file.
/// </summary>
type Opcode =
  /// Floating Point Absolute Value.
  | ABS = 0
  /// Add Word.
  | ADD = 1
  /// Add Immediate Unsigned Word.
  | ADDIU = 2
  /// Add Unsigned Word.
  | ADDU = 3
  /// Concatenate two GPRs, and extract a contiguous subset at a byte position.
  | ALIGN = 4
  /// And.
  | AND = 5
  /// And immediate.
  | ANDI = 6
  /// Add Immediate to Upper Bits.
  | AUI = 7
  /// Unconditional Branch.
  | B = 8
  /// Branch and Link.
  | BAL = 9
  /// Branch on FP False.
  | BC1F = 10
  /// Branch on FP True.
  | BC1T = 11
  /// Branch on COP3 False.
  | BC3F = 12
  /// Branch on COP3 False Likely.
  | BC3FL = 13
  /// Branch on COP3 True.
  | BC3T = 14
  /// Branch on COP2 True Likely.
  | BC3TL = 15
  /// Branch on Equal.
  | BEQ = 16
  /// Branch on Greater Than or Equal to Zero.
  | BGEZ = 17
  /// Branch on Greater Than or Equal to Zero and Link.
  | BGEZAL = 18
  /// Branch on Greater Than Zero.
  | BGTZ = 19
  /// Swaps (reverses) bits in each byte.
  | BITSWAP = 20
  /// Branch on Less Than or Equal to Zero.
  | BLEZ = 21
  /// Branch on Less Than Zero.
  | BLTZ = 22
  /// Branch on Not Equal.
  | BNE = 23
  /// Floating Point Compare.
  | C = 24
  /// Move Control Word From Floating Point.
  | CFC1 = 25
  /// Count Leading Zeros in Word.
  | CLZ = 26
  /// Move Control Word to Floating Point.
  | CTC1 = 27
  /// Floating Point Convert to Double Floating Point.
  | CVTD = 28
  /// Floating Point Convert to Single Floating Point.
  | CVTS = 29
  /// Doubleword Add Immediate Unsigned.
  | DADDIU = 30
  /// Doubleword Add Unsigned.
  | DADDU = 31
  /// Concatenate two GPRs, and extract a contiguous subset at a byte position.
  | DALIGN = 32
  /// Swaps (reverses) bits in each byte.
  | DBITSWAP = 33
  /// Count Leading Zeros in Doubleword.
  | DCLZ = 34
  /// Doubleword Divide.
  | DDIV = 35
  /// Doubleword Divide Unsigned.
  | DDIVU = 36
  /// Doubleword Extract Bit Field.
  | DEXT = 37
  /// Doubleword Extract Bit Field Middle.
  | DEXTM = 38
  /// Doubleword Extract Bit Field Upper.
  | DEXTU = 39
  /// Doubleword Insert Bit Field.
  | DINS = 40
  /// Doubleword Insert Bit Field Middle.
  | DINSM = 41
  /// Doubleword Insert Bit Field Upper.
  | DINSU = 42
  /// Divide Word.
  | DIV = 43
  /// Divide Unsigned Word.
  | DIVU = 44
  /// Doubleword Move from Floating Point.
  | DMFC1 = 45
  /// Doubleword Move to Floating Point.
  | DMTC1 = 46
  /// Doubleword Multiply.
  | DMULT = 47
  /// Doubleword Multiply Unsigned.
  | DMULTU = 48
  /// Doubleword Rotate Right.
  | DROTR = 49
  /// Doubleword Rotate Right Plus 32.
  | DROTR32 = 50
  /// Doubleword Rotate Right Variable.
  | DROTRV = 51
  /// Doubleword Swap Bytes Within Halfwords.
  | DSBH = 52
  /// Doubleword Swap Halfwords Within Doublewords.
  | DSHD = 53
  /// Doubleword Shift Left Logical.
  | DSLL = 54
  /// Doubleword Shift Left Logical Plus 32.
  | DSLL32 = 55
  /// Doubleword Shift Left Logical Variable.
  | DSLLV = 56
  /// Doubleword Shift Right Arithmetic.
  | DSRA = 57
  /// Doubleword Shift Right Arithmetic Plus 32.
  | DSRA32 = 58
  /// Doubleword Shift Right Arithmetic Variable.
  | DSRAV = 59
  /// Doubleword Shift Right Logical.
  | DSRL = 60
  /// Doubleword Shift Right Logical Plus 32.
  | DSRL32 = 61
  /// Doubleword Shift Right Logical Variable.
  | DSRLV = 62
  /// Doubleword Subtract Unsigned.
  | DSUBU = 63
  /// Execution Hazard Barrier.
  | EHB = 64
  /// Extract Bit Field.
  | EXT = 65
  /// Insert Bit Field.
  | INS = 66
  /// Jump.
  | J = 67
  /// Jump and Link.
  | JAL = 68
  /// Jump and Link Register.
  | JALR = 69
  /// Jump and Link Register with Hazard Barrier.
  | JALRHB = 70
  /// Jump Register.
  | JR = 71
  /// Jump Register with Hazard Barrier.
  | JRHB = 72
  /// Load Byte.
  | LB = 73
  /// Load Byte Unsigned.
  | LBU = 74
  /// Load Doubleword.
  | LD = 75
  /// Load Doubleword to Floating Point.
  | LDC1 = 76
  /// Load Doubleword Left.
  | LDL = 77
  /// Load Doubleword Right.
  | LDR = 78
  /// Load Doubleword Indexed to Floating Point.
  | LDXC1 = 79
  /// Load Halfword.
  | LH = 80
  /// Load Halfword Unsigned.
  | LHU = 81
  /// Load Upper Immediate.
  | LUI = 82
  /// Load Word.
  | LW = 83
  /// Load Word to Floating Point.
  | LWC1 = 84
  /// Load Word Left.
  | LWL = 85
  /// Load Word Right.
  | LWR = 86
  /// Load Word Unsigned.
  | LWU = 87
  /// Load Word Indexed to Floating Point.
  | LWXC1 = 88
  /// Multiply and Add Word to Hi, Lo.
  | MADD = 89
  /// Multiply and Add Unsigned Word to Hi,Lo.
  | MADDU = 90
  /// Move Word From Floating Point.
  | MFC1 = 91
  /// Move Word From High Half of Floating Point Register.
  | MFHC1 = 92
  /// Move From HI Register.
  | MFHI = 93
  /// Move From LO Register.
  | MFLO = 94
  /// Floating Point Move.
  | MOV = 95
  /// Move Conditional on Floating Point False.
  | MOVF = 96
  /// Move Conditional on Not Zero.
  | MOVN = 97
  /// Move Conditional on Floating Point True.
  | MOVT = 98
  /// Move Conditional on Zero.
  | MOVZ = 99
  /// Multiply and Subtract Word to Hi,Lo.
  | MSUB = 100
  /// Move Word to Floating Point.
  | MTC1 = 101
  /// Move Word to High Half of Floating Point Register.
  | MTHC1 = 102
  /// Move to HI Register.
  | MTHI = 103
  /// Move to LO Register.
  | MTLO = 104
  /// Multiply Word to GPR.
  | MUL = 105
  /// Multiply Word.
  | MULT = 106
  /// Multiply Unsigned Word.
  | MULTU = 107
  /// Floating Point Negate.
  | NEG = 108
  /// No Operation.
  | NOP = 109
  /// Not Or.
  | NOR = 110
  /// Or.
  | OR = 111
  /// Or Immediate.
  | ORI = 112
  /// Wait for the LLBit to clear.
  | PAUSE = 113
  /// Rotate Word Right.
  | ROTR = 114
  /// Rotate Word Right Variable.
  | ROTRV = 115
  /// Store Byte.
  | SB = 116
  /// Store Doubleword.
  | SD = 117
  /// Store Doubleword from Floating Point.
  | SDC1 = 118
  /// Store Doubleword Left.
  | SDL = 119
  /// Store Doubleword Right.
  | SDR = 120
  /// Store Doubleword Indexed from Floating Point.
  | SDXC1 = 121
  /// Sign-Extend Byte.
  | SEB = 122
  /// Sign-Extend Halfword.
  | SEH = 123
  /// Store Halfword.
  | SH = 124
  /// Shift Word Left Logical.
  | SLL = 125
  /// Shift Word Left Logical Variable.
  | SLLV = 126
  /// Set on Less Than.
  | SLT = 127
  /// Set on Less Than Immediate.
  | SLTI = 128
  /// Set on Less Than Immediate Unsigned.
  | SLTIU = 129
  /// Set on Less Than Unsigned.
  | SLTU = 130
  /// Floating Point Square Root.
  | SQRT = 131
  /// Shift Word Right Arithmetic.
  | SRA = 132
  /// Shift Word Right Arithmetic Variable.
  | SRAV = 133
  /// Shift Word Right Logical.
  | SRL = 134
  /// Shift Word Right Logical Variable.
  | SRLV = 135
  /// Superscalar No Operation.
  | SSNOP = 136
  /// Subtract Word.
  | SUB = 137
  /// Subtract Unsigned Word.
  | SUBU = 138
  /// Store Word.
  | SW = 139
  /// Store Word from Floating Point.
  | SWC1 = 140
  /// Store Word Left.
  | SWL = 141
  /// Store Word Right.
  | SWR = 142
  /// Store Word Indexed from Floating Point.
  | SWXC1 = 143
  /// Synchronize Shared Memory.
  | SYNC = 144
  /// Trap if Equal.
  | TEQ = 145
  /// Floating Point Truncate to Long Fixed Point.
  | TRUNCL = 146
  /// Floating Point Truncate to Word Fixed Point.
  | TRUNCW = 147
  /// Word Swap Bytes Within Halfwords.
  | WSBH = 148
  /// Exclusive OR.
  | XOR = 149
  /// Exclusive OR Immediate.
  | XORI = 150
  /// Invalid Opcode.
  | InvalOP = 151

type internal Op = Opcode

type Operand =
  | OpReg of Register
  | OpImm of Imm
  | OpMem of Base * Offset * AccessLength
  | OpAddr of JumpTarget
  | OpShiftAmount of Imm
  | GoToLabel of Label

and Imm = uint64
and JumpTarget = Relative of int64
and Offset =
  | Imm of int64
  | Reg of Register
and Base = Register
and AccessLength = RegType
and Label = string

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand

type internal Instruction =
  Opcode * Condition option * Fmt option

/// Basic information obtained by parsing a MIPS instruction.
[<NoComparison; CustomEquality>]
type InsInfo = {
  /// Address.
  Address: Addr
  /// Instruction length.
  NumBytes: uint32
  /// Condition.
  Condition : Condition option
  /// Floating Point Format.
  Fmt : Fmt option
  /// Opcode.
  Opcode: Opcode
  /// Operands.
  Operands: Operands
  /// Operation Size.
  OperationSize: RegType
  /// Mips architecture.
  Arch: Arch
}
with
  override __.GetHashCode () =
    hash (__.Address,
          __.NumBytes,
          __.Condition,
          __.Fmt,
          __.Opcode,
          __.Operands,
          __.OperationSize,
          __.Arch)
  override __.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = __.Address
      && i.NumBytes = __.NumBytes
      && i.Condition = __.Condition
      && i.Fmt = __.Fmt
      && i.Opcode = __.Opcode
      && i.Operands = __.Operands
      && i.OperationSize = __.OperationSize
      && i.Arch = __.Arch
    | _ -> false

// vim: set tw=80 sts=2 sw=2:
