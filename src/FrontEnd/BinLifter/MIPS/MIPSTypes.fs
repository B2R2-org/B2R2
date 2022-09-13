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
  /// Add Immediate Word.
  | ADDI = 2
  /// Add Immediate Unsigned Word.
  | ADDIU = 3
  /// Add Immediate to PC.
  | ADDIUPC = 4
  /// Add Unsigned Word.
  | ADDU = 5
  /// Concatenate two GPRs, and extract a contiguous subset at a byte position.
  | ALIGN = 6
  /// Float Point Align Variable.
  | ALNVPS = 7
  /// Aligned Add Upper Immediate to PC.
  | ALUIPC = 8
  /// And.
  | AND = 9
  /// And immediate.
  | ANDI = 10
  /// Add Immediate to Upper Bits.
  | AUI = 11
  /// Add Upper Immediate to PC.
  | AUIPC = 12
  /// Unconditional Branch.
  | B = 13
  /// Branch and Link.
  | BAL = 14
  /// Branch and Link, Compact.
  | BALC = 15
  /// Branch, Compact.
  | BC = 16
  /// Branch if Coprocessor 1 (FPU) Register Bit 0 Equal to Zero.
  | BC1EQZ = 17
  /// Branch if Coprocessor 1 (FPU) Register Bit 0 Not Equal to Zero.
  | BC1NEZ = 18
  /// Branch on FP False.
  | BC1F = 19
  /// Branch on FP False Likely.
  | BC1FL = 20
  /// Branch on FP True.
  | BC1T = 21
  /// Branch on FP True Likely.
  | BC1TL = 22
  /// Branch if Coprocessor 2 Condition Register Equal to Zero.
  | BC2EQZ = 23
  /// Branch if Coprocessor 2 Condition Register Not Equal to Zero.
  | BC2NEZ = 24
  /// Branch on COP2 False.
  | BC2F = 25
  /// Branch on COP2 False Likely.
  | BC2FL = 26
  /// Branch on COP2 True.
  | BC2T = 27
  /// Branch on COP2 True Likely.
  | BC2TL = 28
  /// Branch on COP3 False.
  | BC3F = 29
  /// Branch on COP3 False Likely.
  | BC3FL = 30
  /// Branch on COP3 True.
  | BC3T = 31
  /// Branch on COP3 True Likely.
  | BC3TL = 32
  /// Branch on Equal.
  | BEQ = 33
  /// Branch on Equal Likely.
  | BEQL = 34
  /// Branch on Greater Than or Equal to Zero.
  | BGEZ = 35
  /// Branch on Greater Than or Equal to Zero and Link.
  | BGEZAL = 36
  /// Compact Zero-Compare and Branch-and-Link if less than or equal to zero.
  | BLEZALC = 37
  /// Compact Zero-Compare and Branch-and-Link if less than zero.
  | BLTZALC = 38
  /// Compact Zero-Compare and Branch-and-Link if greater than or equal to zero.
  | BGEZALC = 39
  /// Compact Zero-Compare and Branch-and-Link if greater than zero.
  | BGTZALC = 40
  /// Compact Zero-Compare and Branch-and-Link if equal to zero.
  | BEQZALC = 41
  /// Compact Zero-Compare and Branch-and-Link if not equal to zero.
  | BNEZALC = 42
  /// Branch on Greater Than or Equal to Zero and Link Likely.
  | BGEZALL = 43
  /// Compact Compare-and-Branch if less than or equal to zero.
  | BLEZC = 44
  /// Compact Compare-and-Branch if greater than or equal to zero.
  | BGEZC = 45
  /// Compact Compare-and-Branch if greater than or equal to.
  | BGEC = 46
  /// Compact Compare-and-Branch if greater than zero.
  | BGTZC = 47
  /// Compact Compare-and-Branch if less than zero.
  | BLTZC = 48
  /// Compact Compare-and-Branch if less than.
  | BLTC = 49
  /// Compact Compare-and-Branch if unsigned greater or equal to.
  | BGEUC = 50
  /// Compact Compare-and-Branch if unsigned less than.
  | BLTUC = 51
  /// Compact Compare-and-Branch if equal to.
  | BEQC = 52
  /// Compact Compare-and-Branch if not equal to.
  | BNEC = 53
  /// Compact Compare-and-Branch if equal to zero.
  | BEQZC = 54
  /// Compact Compare-and-Branch if not equal to zero.
  | BNEZC = 55
  /// Branch on Greater than or Equal to Zero Likely.
  | BGEZL = 56
  /// Branch on Greater Than Zero.
  | BGTZ = 57
  /// Branch on Greater Than Zero Likely.
  | BGTZL = 58
  /// Swaps (reverses) bits in each byte.
  | BITSWAP = 59
  /// Branch on Less Than or Equal to Zero.
  | BLEZ = 60
  /// Branch on Less Than or Equal to Zero Likely.
  | BLEZL = 61
  /// Branch on Less Than Zero.
  | BLTZ = 62
  /// Branch on Less Than Zero and Link.
  | BLTZAL = 63
  /// Branch on Less Than Zero and Link Likely.
  | BLTZALL = 64
  /// Branch on Less Than Zero Likely.
  | BLTZL = 65
  /// Branch on Not Equal.
  | BNE = 66
  /// Branch on Not Equal Likely.
  | BNEL = 67
  /// Branch on Overflow, Compact.
  | BOVC = 68
  /// Branch on No Overflow, Compact.
  | BNVC = 69
  /// Breakpoint.
  | BREAK = 70
  /// Floating Point Compare.
  | C = 71
  /// Perform Cache Operation.
  | CACHE = 72
  /// Perform Cache Operation EVA.
  | CACHEE = 73
  /// Fixed Point Ceiling Convert to Long Fixed Point.
  | CEILL = 74
  /// Fixed Point Ceiling Convert to Word Fixed Point.
  | CEILW = 75
  /// Move Control Word From Floating Point.
  | CFC1 = 76
  /// Move Control Word From Coprocessor 2.
  | CFC2 = 77
  /// Scalar Floating-Point Class Mask.
  | CLASS = 78
  /// Count Leading Ones in Word.
  | CLO = 79
  /// Count Leading Zeros in Word.
  | CLZ = 80
  /// Floating Point Compare Setting Mask.
  | CMP = 81
  /// Coprocessor Operation to Coprocessor 2.
  | COP2 = 82
  /// Generate CRC with reversed polynomial 0xEDB88320.
  | CRC32B = 83
  /// Generate CRC with reversed polynomial 0xEDB88320.
  | CRC32H = 84
  /// Generate CRC with reversed polynomial 0xEDB88320.
  | CRC32W = 85
  /// Generate CRC with reversed polynomial 0x82F63B78.
  | CRC32CB = 86
  /// Generate CRC with reversed polynomial 0x82F63B78.
  | CRC32CH = 87
  /// Generate CRC with reversed polynomial 0x82F63B78.
  | CRC32CW = 88
  /// Move Control Word to Floating Point.
  | CTC1 = 89
  /// Move Control Word to Coprocessor 2.
  | CTC2 = 90
  /// Floating Point Convert to Double Floating Point.
  | CVTD = 91
  /// Floating Point Convert to Long Fixed Point.
  | CVTL = 92
  /// Floating Point Convert Pair to Paired Single.
  | CVTPSS = 93
  /// Floating Point Convert to Single Floating Point.
  | CVTS = 94
  /// Floating Point Convert Pair Lower to Single Floating Point.
  | CVTSPL = 95
  /// Floating Point Convert Pair Upper to Single Floating Point.
  | CVTSPU = 96
  /// Floating Point Convert to Word Fixed Point.
  | CVTW = 97
  /// Doubleword Add Immediate Unsigned.
  | DADDIU = 98
  /// Doubleword Add Unsigned.
  | DADDU = 99
  /// Concatenate two GPRs, and extract a contiguous subset at a byte position.
  | DALIGN = 100
  /// Swaps (reverses) bits in each byte.
  | DBITSWAP = 101
  /// Count Leading Zeros in Doubleword.
  | DCLZ = 102
  /// Doubleword Divide.
  | DDIV = 103
  /// Doubleword Divide Unsigned.
  | DDIVU = 104
  /// Debug Exception Return.
  | DERET = 105
  /// Doubleword Extract Bit Field.
  | DEXT = 106
  /// Doubleword Extract Bit Field Middle.
  | DEXTM = 107
  /// Doubleword Extract Bit Field Upper.
  | DEXTU = 108
  /// Disable Interrupts.
  | DI = 109
  /// Doubleword Insert Bit Field.
  | DINS = 110
  /// Doubleword Insert Bit Field Middle.
  | DINSM = 111
  /// Doubleword Insert Bit Field Upper.
  | DINSU = 112
  /// Divide Word.
  | DIV = 113
  /// Modulo Words.
  | MOD = 114
  /// Divide Words Unsigned.
  | DIVU = 115
  /// Modulo Words Unsigned.
  | MODU = 116
  /// Disable Virtual Processor.
  | DVP = 117
  /// Doubleword Move from Floating Point.
  | DMFC1 = 118
  /// Doubleword Move to Floating Point.
  | DMTC1 = 119
  /// Doubleword Multiply.
  | DMULT = 120
  /// Doubleword Multiply Unsigned.
  | DMULTU = 121
  /// Doubleword Rotate Right.
  | DROTR = 122
  /// Doubleword Rotate Right Plus 32.
  | DROTR32 = 123
  /// Doubleword Rotate Right Variable.
  | DROTRV = 124
  /// Doubleword Swap Bytes Within Halfwords.
  | DSBH = 125
  /// Doubleword Swap Halfwords Within Doublewords.
  | DSHD = 126
  /// Doubleword Shift Left Logical.
  | DSLL = 127
  /// Doubleword Shift Left Logical Plus 32.
  | DSLL32 = 128
  /// Doubleword Shift Left Logical Variable.
  | DSLLV = 129
  /// Doubleword Shift Right Arithmetic.
  | DSRA = 130
  /// Doubleword Shift Right Arithmetic Plus 32.
  | DSRA32 = 131
  /// Doubleword Shift Right Arithmetic Variable.
  | DSRAV = 132
  /// Doubleword Shift Right Logical.
  | DSRL = 133
  /// Doubleword Shift Right Logical Plus 32.
  | DSRL32 = 134
  /// Doubleword Shift Right Logical Variable.
  | DSRLV = 135
  /// Doubleword Subtract Unsigned.
  | DSUBU = 136
  /// Execution Hazard Barrier.
  | EHB = 137
  /// Enable Interrupts.
  | EI = 138
  /// Exception Return.
  | ERET = 139
  /// Exception Return No Clear.
  | ERETNC = 140
  /// Enable Virtual Processor.
  | EVP = 141
  /// Extract Bit Field.
  | EXT = 142
  /// Floating Point Floor Convert to Long Fixed Point.
  | FLOORL = 143
  /// Floating Point Floor Convert to Word Fixed Point.
  | FLOORW = 144
  /// Global Invalidate Instruction Cache.
  | GINVI = 145
  /// Global Invalidate TLB.
  | GINVT = 146
  /// Insert Bit Field.
  | INS = 147
  /// Jump.
  | J = 148
  /// Jump and Link.
  | JAL = 149
  /// Jump and Link Register.
  | JALR = 150
  /// Jump and Link Register with Hazard Barrier.
  | JALRHB = 151
  /// Jump and Link Exchange.
  | JALX = 152
  /// Jump Indexed and Link, Compact.
  | JIALC = 153
  /// Jump Indexed, Compact.
  | JIC = 154
  /// Jump Register.
  | JR = 155
  /// Jump Register with Hazard Barrier.
  | JRHB = 156
  /// Load Byte.
  | LB = 157
  /// Load Byte EVA.
  | LBE = 158
  /// Load Byte Unsigned.
  | LBU = 159
  /// Load Byte Unsigned EVA.
  | LBUE = 160
  /// Load Doubleword.
  | LD = 161
  /// Load Doubleword to Floating Point.
  | LDC1 = 162
  /// Load Doubleword to Coprocessor 2.
  | LDC2 = 163
  /// Load Doubleword Left.
  | LDL = 164
  /// Load Doubleword Right.
  | LDR = 165
  /// Load Doubleword Indexed to Floating Point.
  | LDXC1 = 166
  /// Load Halfword.
  | LH = 167
  /// Load Halfword EVA.
  | LHE = 168
  /// Load Halfword Unsigned.
  | LHU = 169
  /// Load Halfword Unsigned EVA.
  | LHUE = 170
  /// Load Linked Word.
  | LL = 171
  /// Load Linked Doubleword.
  | LLD = 172
  /// Load Linked Word EVA.
  | LLE = 173
  /// Load Linked Word Paired.
  | LLWP = 174
  /// Load Linked Word Paired EVA.
  | LLWPE = 175
  /// Load Scaled Address.
  | LSA = 176
  /// Load Upper Immediate.
  | LUI = 177
  /// Load Doubleword Indexed Unaligned to Floating Point.
  | LUXC1 = 178
  /// Load Word.
  | LW = 179
  /// Load Word to Floating Point.
  | LWC1 = 180
  /// Load Word to Coprocessor 2.
  | LWC2 = 181
  /// Load Word EVA.
  | LWE = 182
  /// Load Word Left.
  | LWL = 183
  /// Load Word Left EVA.
  | LWLE = 184
  /// Load Word PC-relative.
  | LWPC = 185
  /// Load Word Right.
  | LWR = 186
  /// Load Word Right EVA.
  | LWRE = 187
  /// Load Word Unsigned.
  | LWU = 188
  /// Load Word Indexed to Floating Point.
  | LWXC1 = 189
  /// Multiply and Add Word to Hi, Lo.
  | MADD = 190
  /// Floating Point Fused Multiply Add.
  | MADDF = 191
  /// Floating Point Fused Multiply Sub.
  | MSUBF = 192
  /// Multiply and Add Unsigned Word to Hi,Lo.
  | MADDU = 193
  /// Scalar Floating-Point Max.
  | MAX = 194
  /// Scalar Floating-Point Min.
  | MIN = 195
  /// Scalar Floating-Point argument with Max Absolute Value.
  | MAXA = 196
  /// Scalar Floating-Point argument with Min Absolute Value.
  | MINA = 197
  /// Move from Coprocessor 0.
  | MFC0 = 198
  /// Move Word From Floating Point.
  | MFC1 = 199
  /// Move Word From Coprocessor 2.
  | MFC2 = 200
  /// Move from High Coprocessor 0.
  | MFHC0 = 201
  /// Move Word From High Half of Floating Point Register.
  | MFHC1 = 202
  /// Move Word From High Half of Coprocessor 2 Register.
  | MFHC2 = 203
  /// Move From HI Register.
  | MFHI = 204
  /// Move From LO Register
  | MFLO = 205
  /// Floating Point Move.
  | MOV = 206
  /// Move Conditional on Floating Point False.
  | MOVF = 207
  /// Move Conditional on Not Zero.
  | MOVN = 208
  /// Move Conditional on Floating Point True.
  | MOVT = 209
  /// Move Conditional on Zero.
  | MOVZ = 210
  /// Floating Point Multiply Subtract.
  | MSUB = 211
  /// Multiply and Subtract Word to Hi,Lo.
  | MSUBU = 212
  /// Move to Coprocessor 0.
  | MTC0 = 213
  /// IMove Word to Floating Point.
  | MTC1 = 214
  /// Move Word to Coprocessor 2.
  | MTC2 = 215
  /// Move to High Coprocessor 0.
  | MTHC0 = 216
  /// Move Word to High Half of Floating Point Register.
  | MTHC1 = 217
  /// Move Word to High Half of Coprocessor 2 Register.
  | MTHC2 = 218
  /// Move to HI Register.
  | MTHI = 219
  /// Move to LO Register
  | MTLO = 220
  /// Multiply Word to GPR.
  | MUL = 221
  /// Multiply Words Signed, High Word.
  | MUH = 222
  /// Multiply Words Unsigned, Low Word
  | MULU = 223
  /// Multiply Words Unsigned, High Word
  | MUHU = 224
  /// Multiply Word.
  | MULT = 225
  /// Multiply Unsigned Word.
  | MULTU = 226
  /// No-op and Link.
  | NAL = 227
  /// Floating Point Negate.
  | NEG = 228
  /// Floating Point Negative Multiply Add.
  | NMADD = 229
  /// Floating Point Negative Multiply Subtract.
  | NMSUB = 230
  /// No Operation.
  | NOP = 231
  /// Not Or.
  | NOR = 232
  /// Or.
  | OR = 233
  /// Or Immediate.
  | ORI = 234
  /// Wait for the LLBit to clear.
  | PAUSE = 235
  /// Pair Lower Lower.
  | PLLPS = 236
  /// Pair Lower Upper.
  | PLUPS = 237
  /// Prefetch.
  | PREF = 238
  /// Prefetch EVA.
  | PREFE = 239
  /// Prefetch Indexed.
  | PREFX = 240
  /// Pair Upper Lower.
  | PULPS = 241
  /// Pair Upper Upper.
  | PUUPS = 242
  /// Read Hardware Register.
  | RDHWR = 243
  /// Read GPR from Previous Shadow Set.
  | RDPGPR = 244
  /// Reciprocal Approximation.
  | RECIP = 245
  /// Floating-Point Round to Integral.
  | RINT = 246
  /// Rotate Word Right.
  | ROTR = 247
  /// Rotate Word Right Variable.
  | ROTRV = 248
  /// Floating Point Round to Long Fixed Point.
  | ROUNDL = 249
  /// Floating Point Round to Word Fixed Point.
  | ROUNDW = 250
  /// Reciprocal Square Root Approximation.
  | RSQRT = 251
  /// Store Byte.
  | SB = 252
  /// Store Byte EVA.
  | SBE = 253
  /// Store Conditional Word.
  | SC = 254
  /// Store Conditional Doubleword.
  | SCD = 255
  /// Store Conditional Word EVA.
  | SCE = 256
  /// Store Conditional Word Paired.
  | SCWP = 257
  /// Store Conditional Word Paired EVA.
  | SCWPE = 258
  /// Store Doubleword.
  | SD = 259
  /// Software Debug Breakpoint.
  | SDBBP = 260
  /// Store Doubleword from Floating Point.
  | SDC1 = 261
  /// Store Doubleword from Coprocessor 2.
  | SDC2 = 262
  /// Store Doubleword Left.
  | SDL = 263
  /// Store Doubleword Right.
  | SDR = 264
  /// Store Doubleword Indexed from Floating Point.
  | SDXC1 = 265
  /// Sign-Extend Byte.
  | SEB = 266
  /// Sign-Extend Halfword.
  | SEH = 267
  /// Select floating point values with FPR condition.
  | SEL = 268
  /// Select integer GPR value or zero.
  | SELEQZ = 269
  /// Select integer GPR value or zero.
  | SELNEZ = 270
  /// Select floating point value or zero with FPR condition.
  | SELNEQZ = 271
  /// Store Halfword.
  | SH = 272
  /// Store Halfword EVA.
  | SHE = 273
  /// Signal Reserved Instruction Exception.
  | SIGRIE = 274
  /// Shift Word Left Logical.
  | SLL = 275
  /// Shift Word Left Logical Variable.
  | SLLV = 276
  /// Set on Less Than.
  | SLT = 277
  /// Set on Less Than Immediate.
  | SLTI = 278
  /// Set on Less Than Immediate Unsigned.
  | SLTIU = 279
  /// Set on Less Than Unsigned.
  | SLTU = 280
  /// Floating Point Square Root.
  | SQRT = 281
  /// Shift Word Right Arithmetic.
  | SRA = 282
  /// Shift Word Right Arithmetic Variable.
  | SRAV = 283
  /// Shift Word Right Logical.
  | SRL = 284
  /// Shift Word Right Logical Variable.
  | SRLV = 285
  /// Superscalar No Operation.
  | SSNOP = 286
  /// Subtract Word.
  | SUB = 287
  /// Subtract Unsigned Word.
  | SUBU = 288
  /// Store Doubleword Indexed Unaligned from Floating Point.
  | SUXC1 = 289
  /// Store Word.
  | SW = 290
  /// Store Word from Floating Point.
  | SWC1 = 291
  /// Store Word from Coprocessor 2.
  | SWC2 = 292
  /// Store Word EVA.
  | SWE = 293
  /// Store Word Left.
  | SWL = 294
  /// Store Word Left EVA.
  | SWLE = 295
  /// Store Word Right.
  | SWR = 296
  /// Store Word Right EVA.
  | SWRE = 297
  /// Store Word Indexed from Floating Point.
  | SWXC1 = 298
  /// Synchronize Shared Memory.
  | SYNC = 299
  /// Synchronize Caches to Make Instruction Writes Effective
  | SYNCI = 300
  /// System Call.
  | SYSCALL = 301
  /// Trap if Equal.
  | TEQ = 302
  /// Trap if Equal Immediate.
  | TEQI = 303
  /// Trap if Greater or Equal.
  | TGE = 304
  /// Trap if Greater or Equal Immediate.
  | TGEI = 305
  /// Trap if Greater or Equal Immediate Unsigned.
  | TGEIU = 306
  /// Trap if Greater or Equal Unsigned.
  | TGEU = 307
  /// TLB Invalidate.
  | TLBINV = 308
  /// TLB Invalidate Flush.
  | TLBINVF = 309
  /// Probe TLB for Matching Entry.
  | TLBP = 310
  /// Read Indexed TLB Entry.
  | TLBR = 311
  /// Read Indexed TLB Entry.
  | TLBWI = 312
  /// Write Random TLB Entry.
  | TLBWR = 313
  /// Trap if Less Than.
  | TLT = 314
  /// Trap if Less Than Immediate.
  | TLTI = 315
  /// Trap if Less Than Immediate Unsigned.
  | TLTIU = 316
  /// Trap if Less Than Unsigned.
  | TLTU = 317
  /// Trap if Not Equal.
  | TNE = 318
  /// Trap if Not Equal Immediate.
  | TNEI = 319
  /// Floating Point Truncate to Long Fixed Point.
  | TRUNCL = 320
  /// Floating Point Truncate to Word Fixed Point.
  | TRUNCW = 321
  /// Enter Standby Mode.
  | WAIT = 322
  /// Write to GPR in Previous Shadow Set.
  | WRPGPR = 323
  /// Word Swap Bytes Within Halfwords.
  | WSBH = 324
  /// Exclusive OR.
  | XOR = 325
  /// Exclusive OR Immediate.
  | XORI = 326
  /// Invalid Opcode.
  | InvalOP = 327
  /// Add Dword.
  | DADD = 328

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
