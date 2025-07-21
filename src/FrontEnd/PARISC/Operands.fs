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

namespace B2R2.FrontEnd.PARISC

open B2R2

/// Represents a set of operands in a MIPS instruction.
type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand
  | FiveOperands of Operand * Operand * Operand * Operand * Operand

/// Represents an operand used in a PARISC instruction.
and Operand =
  | OpReg of Register
  | OpImm of Imm
  | OpMem of Base * Space option * Offset option * AccessLength
  | OpAddr of JumpTarget
  | OpShiftAmount of Imm
  | OpRoundMode of RoundMode
  | OpAtomMemOper of Aq * Rl
  | OpCSR of uint16
  | OpCond of Completer

/// Represents an immediate value in PARISC instructions.
and Imm = uint64

/// Represents a base register for memory access.
and Base = Register

/// Represents an optional memory space specifier.
and Space = Register

/// Represents an offset used in memory addressing.
and Offset =
  | Imm of int64
  | Reg of Register

/// Represents the memory access width in PARISC instructions.
and AccessLength = RegType

/// Represents a jump target for branch operations.
and JumpTarget =
  | Relative of int64
  | RelativeBase of Base * Imm

/// Represents a rounding mode for floating-point operations in PARISC.
and RoundMode =
  /// Round to Nearest
  | RN = 0
  /// Round toward Zero
  | RZ = 1
  /// Round toward +∞
  | RP = 2
  /// Round toward −∞
  | RM = 3

/// Represents the acquire flag in atomic memory operations.
and Aq = bool

/// Represents the release flag in atomic memory operations.
and Rl = bool

/// Represents a completer used in PARISC instructions.
and Completer =
  | B = 0
  | C = 1
  | GATE = 2
  | I = 3
  | L = 4
  | R = 5
  | S = 6
  | T = 7
  | U = 8
  | W = 9
  | Z = 10
  | M = 11
  | O = 12
  | E = 13
  | NEVER = 14
  | EQ = 15
  | LT = 16
  | LE = 17
  | LTU = 18
  | LEU = 19
  | SV = 20
  | OD = 21
  | TR = 22
  | NEQ = 23
  | GE = 24
  | GT = 25
  | GEU = 26
  | GTU = 27
  | NSV = 28
  | EV = 29
  | NUV = 30
  | ZNV = 31
  | UV = 32
  | VNZ = 33
  | NWC = 34
  | NWZ = 35
  | NHC = 36
  | NHZ = 37
  | NBC = 38
  | NBZ = 39
  | NDC = 40
  | SWC = 41
  | SWZ = 42
  | SHC = 43
  | SHZ = 44
  | SBC = 45
  | SBZ = 46
  | SDC = 47
  | DNEVER = 48
  | DEQ = 49
  | DLT = 50
  | DLE = 51
  | DLTU = 52
  | DLEU = 53
  | DSV = 54
  | DOD = 55
  | DTR = 56
  | DNEQ = 57
  | DGE = 58
  | DGT = 59
  | DGEU = 60
  | DGTU = 61
  | DNSV = 62
  | DEV = 63
  | DNUV = 64
  | DZNV = 65
  | DUV = 66
  | DVNZ = 67
  | DNWC = 68
  | DNWZ = 69
  | DNHC = 70
  | DNHZ = 71
  | DNBC = 72
  | DNBZ = 73
  | DNDC = 74
  | DSWC = 75
  | DSWZ = 76
  | DSHC = 77
  | DSHZ = 78
  | DSBC = 79
  | DSBZ = 80
  | DSDC = 81
  | DB = 82
  | DC = 83
  | TC = 84
  | TSV = 85
  | MA = 88
  | MB = 89
  | SM = 90
  | SGL = 97
  | DBL = 98
  | QUAD = 99
  | UW = 100
  | DW = 101
  | UDW = 102
  | QW = 103
  | UQW = 104
  | SS = 105
  | US = 106
  | LDISP = 107
  | SDISP = 108
  | N = 113
  | BC = 114
  | SL = 115
  | PUSH = 116
  | FALSEQ = 164
  | FALSE = 165
  | FQ = 166
  | FBGTLE = 167
  | FEQ = 168
  | FEQT = 169
  | FQEQ = 170
  | FBNEQ = 171
  | FBQGE = 172
  | FLT = 173
  | FQLT = 174
  | FBGE = 175
  | FBQGT = 176
  | FLE = 177
  | FQLE = 178
  | FBGT = 179
  | FBQLE = 180
  | FGT = 181
  | FQGT = 182
  | FBLE = 183
  | FBQLT = 184
  | FGE = 185
  | FQGE = 186
  | FBLT = 187
  | FBQEQ = 188
  | FNEQ = 189
  | FBEQ = 190
  | FBEQT = 191
  | FBQ = 192
  | FGTLE = 193
  | TRUEQ = 194
  | TRUE = 195
  | ACC = 196
  | ACC2 = 197
  | ACC4 = 198
  | ACC6 = 199
  | ACC8 = 200
  | REJ = 201
  | REJ8 = 202
  | CO = 203
