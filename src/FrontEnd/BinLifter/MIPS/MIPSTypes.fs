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
  /// Always False.
  | F = 0
  /// Unordered.
  | UN = 1
  /// Equal.
  | EQ = 2
  /// Greater Then.
  | GE = 3
  /// Less Then.
  | LT = 4
  /// Less Then or Equal.
  | LE = 5
  /// Not Equal.
  | NE = 6

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
  /// Add Word.
  | ADD = 0
  /// Add Immediate Unsigned Word.
  | ADDIU = 1
  /// Add Unsigned Word.
  | ADDU = 2
  /// Concatenate two GPRs, and extract a contiguous subset at a byte position.
  | ALIGN = 3
  /// And.
  | AND = 4
  /// And immediate.
  | ANDI = 5
  /// Add Immediate to Upper Bits.
  | AUI = 6
  /// Unconditional Branch.
  | B = 7
  /// Branch and Link.
  | BAL = 8
  /// Branch on FP False.
  | BC1F = 9
  /// Branch on FP True.
  | BC1T = 10
  /// Branch on Equal.
  | BEQ = 11
  /// Branch on Greater Than or Equal to Zero.
  | BGEZ = 12
  /// Branch on Greater Than or Equal to Zero and Link.
  | BGEZAL = 13
  /// Branch on Greater Than Zero.
  | BGTZ = 14
  /// Swaps (reverses) bits in each byte.
  | BITSWAP = 15
  /// Branch on Less Than or Equal to Zero.
  | BLEZ = 16
  /// Branch on Less Than Zero.
  | BLTZ = 17
  /// Branch on Not Equal.
  | BNE = 18
  /// Floating Point Compare.
  | C = 19
  /// Move Control Word From Floating Point.
  | CFC1 = 20
  /// Count Leading Zeros in Word.
  | CLZ = 21
  /// Move Control Word to Floating Point.
  | CTC1 = 22
  /// Floating Point Convert to Double Floating Point.
  | CVTD = 23
  /// Floating Point Convert to Single Floating Point.
  | CVTS = 24
  /// Doubleword Add Immediate Unsigned.
  | DADDIU = 25
  /// Doubleword Add Unsigned.
  | DADDU = 26
  /// Concatenate two GPRs, and extract a contiguous subset at a byte position.
  | DALIGN = 27
  /// Swaps (reverses) bits in each byte.
  | DBITSWAP = 28
  /// Count Leading Zeros in Doubleword.
  | DCLZ = 29
  /// Doubleword Divide Unsigned.
  | DDIVU = 30
  /// Doubleword Extract Bit Field.
  | DEXT = 31
  /// Doubleword Extract Bit Field Middle.
  | DEXTM = 32
  /// Doubleword Extract Bit Field Upper.
  | DEXTU = 33
  /// Doubleword Insert Bit Field.
  | DINS = 34
  /// Doubleword Insert Bit Field Middle.
  | DINSM = 35
  /// Doubleword Insert Bit Field Upper.
  | DINSU = 36
  /// Divide Word.
  | DIV = 37
  /// Divide Unsigned Word.
  | DIVU = 38
  /// Doubleword Move from Floating Point.
  | DMFC1 = 39
  /// Doubleword Move to Floating Point.
  | DMTC1 = 40
  /// Doubleword Multiply.
  | DMULT = 41
  /// Doubleword Multiply Unsigned.
  | DMULTU = 42
  /// Doubleword Rotate Right.
  | DROTR = 43
  /// Doubleword Shift Left Logical.
  | DSLL = 44
  /// Doubleword Shift Left Logical Plus 32.
  | DSLL32 = 45
  /// Doubleword Shift Left Logical Variable.
  | DSLLV = 46
  /// Doubleword Shift Right Arithmetic.
  | DSRA = 47
  /// Doubleword Shift Right Arithmetic Plus 32.
  | DSRA32 = 48
  /// Doubleword Shift Right Logical.
  | DSRL = 49
  /// Doubleword Shift Right Logical Plus 32.
  | DSRL32 = 50
  /// Doubleword Shift Right Logical Variable.
  | DSRLV = 51
  /// Doubleword Subtract Unsigned.
  | DSUBU = 52
  /// Execution Hazard Barrier.
  | EHB = 53
  /// Extract Bit Field.
  | EXT = 54
  /// Insert Bit Field.
  | INS = 55
  /// Jump and Link Register.
  | JALR = 56
  /// Jump and Link Register with Hazard Barrier.
  | JALRHB = 57
  /// Jump Register.
  | JR = 58
  /// Jump Register with Hazard Barrier.
  | JRHB = 59
  /// Load Byte.
  | LB = 60
  /// Load Byte Unsigned.
  | LBU = 61
  /// Load Doubleword.
  | LD = 62
  /// Load Doubleword to Floating Point.
  | LDC1 = 63
  /// Load Halfword.
  | LH = 64
  /// Load Halfword Unsigned.
  | LHU = 65
  /// Load Upper Immediate.
  | LUI = 66
  /// Load Word.
  | LW = 67
  /// Load Word to Floating Point.
  | LWC1 = 68
  /// Load Word Unsigned.
  | LWU = 69
  /// Multiply and Add Word to Hi, Lo.
  | MADD = 70
  /// Move Word From Floating Point.
  | MFC1 = 71
  /// Move From HI Register.
  | MFHI = 72
  /// Move From LO Register.
  | MFLO = 73
  /// Floating Point Move.
  | MOV = 74
  /// Move Conditional on Not Zero.
  | MOVN = 75
  /// Move Conditional on Zero.
  | MOVZ = 76
  /// Move Word to Floating Point.
  | MTC1 = 77
  /// Multiply Word to GPR.
  | MUL = 78
  /// Multiply Word.
  | MULT = 79
  /// Multiply Unsigned Word.
  | MULTU = 80
  /// No Operation.
  | NOP = 81
  /// Not Or.
  | NOR = 82
  /// Or.
  | OR = 83
  /// Or Immediate.
  | ORI = 84
  /// Wait for the LLBit to clear.
  | PAUSE = 85
  /// Rotate Word Right.
  | ROTR = 86
  /// Store Byte.
  | SB = 87
  /// Store Doubleword.
  | SD = 88
  /// Store Doubleword from Floating Point
  | SDC1 = 89
  /// Store Doubleword Left.
  | SDL = 90
  /// Store Doubleword Right.
  | SDR = 91
  /// Sign-Extend Byte.
  | SEB = 92
  /// Sign-Extend Halfword.
  | SEH = 93
  /// Store Halfword.
  | SH = 94
  /// Shift Word Left Logical.
  | SLL = 95
  /// Shift Word Left Logical Variable.
  | SLLV = 96
  /// Set on Less Than.
  | SLT = 97
  /// Set on Less Than Immediate.
  | SLTI = 98
  /// Set on Less Than Immediate Unsigned.
  | SLTIU = 99
  /// Set on Less Than Unsigned.
  | SLTU = 100
  /// Shift Word Right Arithmetic.
  | SRA = 101
  /// Shift Word Right Logical.
  | SRL = 102
  /// Shift Word Right Logical Variable.
  | SRLV = 103
  /// Superscalar No Operation.
  | SSNOP = 104
  /// Subtract Word.
  | SUB = 105
  /// Subtract Unsigned Word.
  | SUBU = 106
  /// Store Word.
  | SW = 107
  /// Store Word from Floating Point.
  | SWC1 = 108
  /// Store Word Left.
  | SWL = 109
  /// Store Word Right.
  | SWR = 110
  /// Trap if Equal.
  | TEQ = 111
  /// Floating Point Truncate to Long Fixed Point.
  | TRUNCL = 112
  /// Floating Point Truncate to Word Fixed Point.
  | TRUNCW = 113
  /// Word Swap Bytes Within Halfwords.
  | WSBH = 114
  /// Exclusive OR.
  | XOR = 115
  /// Exclusive OR Immediate.
  | XORI = 116
  /// Invalid Opcode.
  | InvalOP = 117

type internal Op = Opcode

type Operand =
  | OpReg of Register
  | OpImm of Imm
  | OpMem of Base * Offset * AccessLength
  | OpAddr of JumpTarget
  | OpShiftAmount of Imm
  | GoToLabel of Label

and Imm = uint64
and JumpTarget = Relative of Offset
and Offset = int64
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
