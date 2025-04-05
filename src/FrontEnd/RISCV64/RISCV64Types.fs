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

namespace B2R2.FrontEnd.RISCV64

open System.Runtime.CompilerServices
open B2R2

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.RISCV64.Tests")>]
do ()

/// <summary>
///   RISCV64 opcodes.
/// </summary>
type Opcode =
  | LUI = 0
  | AUIPC = 1
  | JAL = 2
  | JALR = 3
  | BEQ = 4
  | BNE = 5
  | BLT = 6
  | BGE = 7
  | BLTU = 8
  | BGEU = 9
  | LB = 10
  | LH = 11
  | LW = 12
  | LBU = 13
  | LHU = 14
  | SB = 15
  | SH = 16
  | SW = 17
  | ADDI = 18
  | SLTI = 19
  | SLTIU = 20
  | XORI = 21
  | ORI = 22
  | ANDI = 23
  | ADD = 24
  | SUB = 25
  | SLL = 26
  | SLT = 27
  | SLTU = 28
  | XOR = 29
  | SRL = 30
  | SRA = 31
  | OR = 32
  | AND = 33
  | FENCE = 34
  | FENCEdotI = 35
  | ECALL = 36
  | EBREAK = 37
  | CSRRW = 38
  | CSRRS = 39
  | CSRRC = 40
  | CSRRWI = 41
  | CSRRSI = 42
  | CSRRCI = 43
  (* RV64I Base Instruction Set *)
  | LWU = 44
  | LD = 45
  | SD = 46
  | SLLI = 47
  | SRLI = 48
  | SRAI = 49
  | ADDIW = 50
  | SLLIW = 51
  | SRLIW = 52
  | SRAIW = 53
  | ADDW = 54
  | SUBW = 55
  | SLLW = 56
  | SRLW = 57
  | SRAW = 58
  (* RV32M Standard Extension *)
  | MUL = 59
  | MULH = 60
  | MULHSU = 61
  | MULHU = 62
  | DIV = 63
  | DIVU = 64
  | REM = 65
  | REMU = 66
  (* RV64M Standard Extension *)
  | MULW = 67
  | DIVW = 68
  | DIVUW = 69
  | REMW = 70
  | REMUW = 71
  (* RV32A Standard Extension *)
  | LRdotW = 72
  | SCdotW = 73
  | AMOSWAPdotW = 74
  | AMOADDdotW = 75
  | AMOXORdotW = 76
  | AMOANDdotW = 77
  | AMOORdotW = 78
  | AMOMINdotW = 79
  | AMOMAXdotW = 80
  | AMOMINUdotW = 81
  | AMOMAXUdotW = 82
  (* RV64A Standard Extension *)
  | LRdotD = 83
  | SCdotD = 84
  | AMOSWAPdotD = 85
  | AMOADDdotD = 86
  | AMOXORdotD = 87
  | AMOANDdotD = 88
  | AMOORdotD = 89
  | AMOMINdotD = 90
  | AMOMAXdotD = 91
  | AMOMINUdotD = 92
  | AMOMAXUdotD = 93
  (* RV32F Standard Extension *)
  | FLW = 94
  | FSW = 95
  | FMADDdotS = 96
  | FMSUBdotS = 97
  | FNMSUBdotS = 98
  | FNMADDdotS = 99
  | FADDdotS = 100
  | FSUBdotS = 101
  | FMULdotS = 102
  | FDIVdotS = 103
  | FSQRTdotS = 104
  | FSGNJdotS = 105
  | FSGNJNdotS = 106
  | FSGNJXdotS = 107
  | FMINdotS = 108
  | FMAXdotS = 109
  | FCVTdotWdotS = 110
  | FCVTdotWUdotS = 111
  | FMVdotXdotW = 112
  | FEQdotS = 113
  | FLTdotS = 114
  | FLEdotS = 115
  | FCLASSdotS = 116
  | FCVTdotSdotW = 117
  | FCVTdotSdotWU = 118
  | FMVdotWdotX = 119
  (* RV64F Standard Extension *)
  | FCVTdotLdotS = 120
  | FCVTdotLUdotS = 121
  | FCVTdotSdotL = 122
  | FCVTdotSdotLU = 123
  (* RV32D Standard Extension *)
  | FLD = 124
  | FSD = 125
  | FMADDdotD = 126
  | FMSUBdotD = 127
  | FNMSUBdotD = 128
  | FNMADDdotD = 129
  | FADDdotD = 130
  | FSUBdotD = 131
  | FMULdotD = 132
  | FDIVdotD = 133
  | FSQRTdotD = 134
  | FSGNJdotD = 135
  | FSGNJNdotD = 136
  | FSGNJXdotD = 137
  | FMINdotD = 138
  | FMAXdotD = 139
  | FCVTdotSdotD = 140
  | FCVTdotDdotS = 141
  | FEQdotD = 142
  | FLTdotD = 143
  | FLEdotD = 144
  | FCLASSdotD = 145
  | FCVTdotWdotD = 146
  | FCVTdotWUdotD = 147
  | FCVTdotDdotW = 148
  | FCVTdotDdotWU = 149
  (* RV64D Standard Extension *)
  | FCVTdotLdotD = 150
  | FCVTdotLUdotD = 151
  | FMVdotXdotD = 152
  | FCVTdotDdotL = 153
  | FCVTdotDdotLU = 154
  | FMVdotDdotX = 155
  | FENCEdotTSO = 156
  (* RV64C Standard Extension *)
  | CdotADDI4SPN = 157
  | CdotFLD = 158
  | CdotLW = 159
  | CdotLD = 160
  | CdotFSD = 161
  | CdotSW = 162
  | CdotSD = 163
  | CdotNOP = 164
  | CdotADDI = 165
  | CdotADDIW = 166
  | CdotLI = 167
  | CdotADDI16SP = 168
  | CdotLUI = 169
  | CdotSRLI = 170
  | CdotSRAI = 171
  | CdotANDI = 172
  | CdotSUB = 173
  | CdotXOR = 174
  | CdotOR = 175
  | CdotAND = 176
  | CdotSUBW = 177
  | CdotADDW = 178
  | CdotJ = 179
  | CdotBEQZ = 180
  | CdotBNEZ = 181
  | CdotSLLI = 182
  | CdotFLDSP = 183
  | CdotLWSP = 184
  | CdotLDSP = 185
  | CdotJR = 186
  | CdotMV = 187
  | CdotEBREAK = 188
  | CdotJALR = 189
  | CdotADD = 190
  | CdotFSDSP = 191
  | CdotSWSP = 192
  | CdotSDSP = 193
  | InvalOP = 194

type internal Op = Opcode

type RoundMode =
  // Round to Nearest, ties to Even
  | RNE = 0
  // Round towards Zero
  | RTZ = 1
  // Round Down
  | RDN = 2
  // Round Up
  | RUP = 3
  // Round to Nearest, ties to Max Magnitude
  | RMM = 4
  // In instruction's rm field selects dynamic mode;
  // In Rounding Mode register, Invalid
  | DYN = 7

type Operand =
  | OpReg of Register
  | OpImm of Imm
  | OpMem of Base * Offset option * AccessLength
  | OpAddr of JumpTarget
  | OpShiftAmount of Imm
  | OpFenceMask of FenceMask * FenceMask
  | OpRoundMode of RoundMode
  | OpAtomMemOper of Aq * Rl
  | OpCSR of uint16
and Aq = bool
and Rl = bool
and Imm = uint64
and FenceMask = uint8
and JumpTarget =
  | Relative of int64
  | RelativeBase of Base * Imm
and Offset =
  | Imm of int64
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

/// Basic information obtained by parsing a RISCV64 instruction.
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
  override this.GetHashCode () =
    hash (this.Address,
          this.NumBytes,
          this.Opcode,
          this.Operands,
          this.OperationSize)

  override this.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = this.Address
      && i.NumBytes = this.NumBytes
      && i.Opcode = this.Opcode
      && i.Operands = this.Operands
      && i.OperationSize = this.OperationSize
    | _ -> false

// vim: set tw=80 sts=2 sw=2:
