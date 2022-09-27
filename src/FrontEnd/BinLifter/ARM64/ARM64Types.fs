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

namespace B2R2.FrontEnd.BinLifter.ARM64

open B2R2
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.BinLifter.Tests")>]
do ()

/// <summary>
///   Condition Code. The A64 ISA has some instructions that set condition flags
///   or test condition codes or both.
/// </summary>
type Condition =
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

/// <summary>
///   ARMv8 (AArch64) opcodes. This type should be generated using
///   <c>scripts/genOpcode.fsx</c> from the `ARM64SupportedOpcodes.txt` file.
/// </summary>
type Opcode =
   /// Absolute value (vector and scalar form).
  | ABS = 0
  /// Add with carry.
  | ADC = 1
  /// Add with carry and set flags.
  | ADCS = 2
  /// Add.
  | ADD = 3
  /// Add returning high, narrow (vector form).
  | ADDHN = 4
  /// Add returning high, narrow (vector form).
  | ADDHN2 = 5
  /// Add pairwise (vector and scalar form).
  | ADDP = 6
  /// Add and set flags.
  | ADDS = 7
  /// Add (across vector).
  | ADDV = 8
  /// Compute address of label at a PC-relative offset.
  | ADR = 9
  /// Compute address of 4KB page at a PC-relative offset.
  | ADRP = 10
  /// AES single round decryption.
  | AESD = 11
  /// AES single round encryption.
  | AESE = 12
  /// AES inverse mix columns.
  | AESIMC = 13
  /// AES mix columns.
  | AESMC = 14
  /// Bitwise AND.
  | AND = 15
  /// Bitwise AND and set flags.
  | ANDS = 16
  /// Arithmetic shift right.
  | ASR = 17
  /// Arithmetic shift right variable.
  | ASRV = 18
  /// Branch unconditionally.
  | B = 19
  /// Branch conditionally (AL).
  | BAL = 20
  /// Branch conditionally (CC).
  | BCC = 21
  /// Branch conditionally (CS).
  | BCS = 22
  /// Branch conditionally (EQ).
  | BEQ = 23
  /// Bitfield insert.
  | BFI = 24
  /// Bitfield move.
  | BFM = 25
  /// Bitfield extract and insert low.
  | BFXIL = 26
  /// Branch conditionally (GE).
  | BGE = 27
  /// Branch conditionally (GT).
  | BGT = 28
  /// Branch conditionally (HI).
  | BHI = 29
  /// Branch conditionally (HS).
  | BHS = 30
  /// Bitwise bit clear.
  | BIC = 31
  /// Bitwise bit clear and set flags.
  | BICS = 32
  /// Bitwise insert if false (vector form).
  | BIF = 33
  /// Bitwise insert if true (vector form).
  | BIT = 34
  /// Branch with link.
  | BL = 35
  /// Branch conditionally (LE).
  | BLE = 36
  /// Branch conditionally (LO).
  | BLO = 37
  /// Branch with link to register.
  | BLR = 38
  /// Branch conditionally (LS).
  | BLS = 39
  /// Branch conditionally (LT).
  | BLT = 40
  /// Branch conditionally (MI).
  | BMI = 41
  /// Branch conditionally (NE).
  | BNE = 42
  /// Branch conditionally (NV).
  | BNV = 43
  /// Branch conditionally (PL).
  | BPL = 44
  /// Branch to register.
  | BR = 45
  /// Breakpoint Instruction.
  | BRK = 46
  /// Bitwise select (vector form).
  | BSL = 47
  /// Branch conditionally (VC).
  | BVC = 48
  /// Branch conditionally (VS).
  | BVS = 49
  /// Compare and branch if nonzero.
  | CBNZ = 50
  /// Compare and branch if zero.
  | CBZ = 51
  /// Conditional compare negative (register or immediate).
  | CCMN = 52
  /// Conditional compare (register or immediate).
  | CCMP = 53
  /// Conditional increment.
  | CINC = 54
  /// Conditional invert.
  | CINV = 55
  /// Clear exclusive monitor.
  | CLREX = 56
  /// Count leading sign bits.
  | CLS = 57
  /// Count leading zero bits.
  | CLZ = 58
  /// Compare bitwise equal (vector and scalar form).
  | CMEQ = 59
  /// Compare signed greater than or equal (vector and scalar form).
  | CMGE = 60
  /// Compare signed greater than (vector and scalar form).
  | CMGT = 61
  /// Compare unsigned higher (vector and scalar form).
  | CMHI = 62
  /// Compare unsigned higher or same (vector and scalar form).
  | CMHS = 63
  /// Compare signed less than or equal to zero (vector and scalar form).
  | CMLE = 64
  /// Compare signed less than zero (vector and scalar form).
  | CMLT = 65
  /// Compare negative.
  | CMN = 66
  /// Compare negative.
  | CMP = 67
  /// Compare bitwise test bits nonzero (vector and scalar form).
  | CMTST = 68
  /// Conditional negate.
  | CNEG = 69
  /// Population count per byte (vector form).
  | CNT = 70
  /// CRC-32 sum from byte.
  | CRC32B = 71
  /// CRC-32C sum from byte.
  | CRC32CB = 72
  /// CRC-32C sum from halfword.
  | CRC32CH = 73
  /// CRC-32C sum from word.
  | CRC32CW = 74
  /// CRC-32C sum from doubleword.
  | CRC32CX = 75
  /// CRC-32 sum from halfword.
  | CRC32H = 76
  /// CRC-32 sum from word.
  | CRC32W = 77
  /// CRC-32 sum from doubleword.
  | CRC32X = 78
  /// Conditional select.
  | CSEL = 79
  /// Conditional set.
  | CSET = 80
  /// Conditional set mask.
  | CSETM = 81
  /// Conditional select increment.
  | CSINC = 82
  /// Conditional select inversion.
  | CSINV = 83
  /// Conditional select negation.
  | CSNEG = 84
  /// Clean of Data and Allocation Tags by Set/Way.
  | DCCGDSW = 85
  /// Clean of Data and Allocation Tags by VA to PoC.
  | DCCGDVAC = 86
  /// Clean of Data and Allocation Tags by VA to PoDP.
  | DCCGDVADP = 87
  /// Clean of Data and Allocation Tags by VA to PoP.
  | DCCGDVAP = 88
  /// Clean of Allocation Tags by Set/Way.
  | DCCGSW = 89
  /// Clean of Allocation Tags by VA to PoC.
  | DCCGVAC = 90
  /// Clean of Allocation Tags by VA to PoDP.
  | DCCGVADP = 91
  /// Clean of Allocation Tags by VA to PoP.
  | DCCGVAP = 92
  /// Clean and Invalidate of Data and Allocation Tags by Set/Way.
  | DCCIGDSW = 93
  /// Clean and Invalidate of Data and Allocation Tags by VA to PoC.
  | DCCIGDVAC = 94
  /// Clean and Invalidate of Allocation Tags by Set/Way.
  | DCCIGSW = 95
  /// Clean and Invalidate of Allocation Tags by VA to PoC.
  | DCCIGVAC = 96
  /// Data or unified Cache line Clean and Invalidate by Set/Way.
  | DCCISW = 97
  /// Data or unified Cache line Clean and Invalidate by VA to PoC.
  | DCCIVAC = 98
  /// Data or unified Cache line Clean by Set/Way.
  | DCCSW = 99
  /// Data or unified Cache line Clean by VA to PoC.
  | DCCVAC = 100
  /// Data or unified Cache line Clean by VA to PoDP.
  | DCCVADP = 101
  /// Data or unified Cache line Clean by VA to PoP.
  | DCCVAP = 102
  /// Data or unified Cache line Clean by VA to PoU.
  | DCCVAU = 103
  /// Data Cache set Allocation Tag by VA.
  | DCGVA = 104
  /// Data Cache set Allocation Tags and Zero by VA.
  | DCGZVA = 105
  /// Invalidate of Data and Allocation Tags by Set/Way.
  | DCIGDSW = 106
  /// Invalidate of Data and Allocation Tags by VA to PoC.
  | DCIGDVAC = 107
  /// Invalidate of Allocation Tags by Set/Way.
  | DCIGSW = 108
  /// Invalidate of Allocation Tags by VA to PoC.
  | DCIGVAC = 109
  /// Data or unified Cache line Invalidate by Set/Way.
  | DCISW = 110
  /// Data or unified Cache line Invalidate by VA to PoC.
  | DCIVAC = 111
  /// Debug switch to Exception level 1.
  | DCPS1 = 112
  /// Debug switch to Exception level 2.
  | DCPS2 = 113
  /// Debug switch to Exception level 3.
  | DCPS3 = 114
  /// Data Cache Zero by VA.
  | DCZVA = 115
  /// Data memory barrier.
  | DMB = 116
  /// Debug restore PE state.
  | DRPS = 117
  /// Data synchronization barrier.
  | DSB = 118
  /// Duplicate general-purpose register to vector.
  | DUP = 119
  /// Bitwise exclusive OR NOT.
  | EON = 120
  /// Bitwise exclusive OR.
  | EOR = 121
  /// Exception return using current ELR and SPSR.
  | ERET = 122
  /// Extract vector from a pair of vectors.
  | EXT = 123
  /// Extract register from pair.
  | EXTR = 124
  /// Floating-point absolute difference (vector and scalar form).
  | FABD = 125
  /// Floating-point absolute (vector form).
  | FABS = 126
  /// Floating-point absolute compare greater than or equal.
  | FACGE = 127
  /// Floating-point absolute compare greater than (vector and scalar form).
  | FACGT = 128
  /// Floating-point add (vector form).
  | FADD = 129
  /// Floating-point add pairwise (vector and scalar form).
  | FADDP = 130
  /// Floating-point conditional quiet compare.
  | FCCMP = 131
  /// Floating-point conditional signaling compare.
  | FCCMPE = 132
  /// Floating-point compare equal (vector and scalar form).
  | FCMEQ = 133
  /// Floating-point compare greater than or equal (vector and scalar form).
  | FCMGE = 134
  /// Floating-point compare greater than (vector and scalar form).
  | FCMGT = 135
  /// Floating-point compare less than or equal to zero (vector and scalar).
  | FCMLE = 136
  /// Floating-point compare less than zero (vector and scalar form).
  | FCMLT = 137
  /// Floating-point quiet compare.
  | FCMP = 138
  /// Floating-point signaling compare.
  | FCMPE = 139
  /// Floating-point scalar conditional select.
  | FCSEL = 140
  /// Floating-point convert precision (scalar).
  | FCVT = 141
  /// FP convert to signed integer, rounding to nearest with ties to away.
  | FCVTAS = 142
  /// FP convert to unsigned integer, rounding to nearest with ties to away.
  | FCVTAU = 143
  /// Floating-point convert to higher precision long (vector form).
  | FCVTL = 144
  /// Floating-point convert to higher precision long (vector form).
  | FCVTL2 = 145
  /// Floating-point convert to signed integer, rounding toward minus infinity.
  | FCVTMS = 146
  /// FP convert to unsigned integer, rounding toward minus infinity.
  | FCVTMU = 147
  /// Floating-point convert to lower precision narrow (vector form).
  | FCVTN = 148
  /// Floating-point convert to lower precision narrow (vector form).
  | FCVTN2 = 149
  /// FP convert to signed integer, rounding to nearest with ties to even.
  | FCVTNS = 150
  /// FP convert to unsigned integer, rounding to nearest with ties to even.
  | FCVTNU = 151
  /// FP convert to signed integer, rounding toward positive infinity.
  | FCVTPS = 152
  /// FP convert to unsigned integer, rounding toward positive infinity.
  | FCVTPU = 153
  /// FP convert to lower precision narrow, rounding to odd (vector and scalar).
  | FCVTXN = 154
  /// FP convert to lower precision narrow, rounding to odd (vector and scalar).
  | FCVTXN2 = 155
  /// FP convert to signed integer, rounding toward zero (vector and scalar).
  | FCVTZS = 156
  /// FP convert to unsigned integer, rounding toward zero (vector and scalar).
  | FCVTZU = 157
  /// Floating-point divide.
  | FDIV = 158
  /// Floating-point scalar fused multiply-add.
  | FMADD = 159
  /// Floating-point maximum.
  | FMAX = 160
  /// Floating-point maximum number.
  | FMAXNM = 161
  /// Floating-point maximum number pairwise (vector and scalar form).
  | FMAXNMP = 162
  /// Floating-point maximum number (across vector).
  | FMAXNMV = 163
  /// Floating-point maximum pairwise (vector and scalar form).
  | FMAXP = 164
  /// Floating-point maximum (across vector).
  | FMAXV = 165
  /// Floating-point minimum.
  | FMIN = 166
  /// Floating-point minimum number.
  | FMINNM = 167
  /// Floating-point minimum number pairwise (vector and scalar form).
  | FMINNMP = 168
  /// Floating-point minimum number (across vector).
  | FMINNMV = 169
  /// Floating-point minimum pairwise (vector and scalar form).
  | FMINP = 170
  /// Floating-point minimum (across vector).
  | FMINV = 171
  /// Floating-point fused multiply-add.
  | FMLA = 172
  /// Floating-point fused multiply-subtract.
  | FMLS = 173
  /// Floating-point move immediate.
  | FMOV = 174
  /// Floating-point scalar fused multiply-subtract.
  | FMSUB = 175
  /// Floating-point multiply.
  | FMUL = 176
  /// Floating-point multiply extended.
  | FMULX = 177
  /// Floating-point negate.
  | FNEG = 178
  /// Floating-point scalar negated fused multiply-add.
  | FNMADD = 179
  /// Floating-point scalar negated fused multiply-subtract.
  | FNMSUB = 180
  /// Floating-point scalar multiply-negate.
  | FNMUL = 181
  /// Floating-point reciprocal estimate (vector and scalar form).
  | FRECPE = 182
  /// Floating-point reciprocal step (vector and scalar form).
  | FRECPS = 183
  /// Floating-point reciprocal square root (scalar form).
  | FRECPX = 184
  /// Floating-point round to integral, to nearest with ties to away.
  | FRINTA = 185
  /// Floating-point round to integral, using current rounding mode.
  | FRINTI = 186
  /// Floating-point round to integral, toward minus infinity.
  | FRINTM = 187
  /// Floating-point round to integral, to nearest with ties to even.
  | FRINTN = 188
  /// Floating-point round to integral, toward positive infinity.
  | FRINTP = 189
  /// Floating-point round to integral exact, using current rounding mode.
  | FRINTX = 190
  /// Floating-point round to integral, toward zero.
  | FRINTZ = 191
  /// Floating-point reciprocal square root estimate.
  | FRSQRTE = 192
  /// Floating-point reciprocal square root step (vector and scalar form).
  | FRSQRTS = 193
  /// Floating-point square root,
  | FSQRT = 194
  /// Floating-point subtract.
  | FSUB = 195
  /// Unallocated hint.
  | HINT = 196
  /// Halt Instruction.
  | HLT = 197
  /// Generate exception targeting Exception level 2.
  | HVC = 198
  /// Insert vector element from general-purpose register.
  | INS = 199
  /// Instruction synchronization barrier.
  | ISB = 200
  /// Load single 1-element structure to one lane of one register.
  | LD1 = 201
  /// Load single 1-element structure and replicate to all lanes of one reg.
  | LD1R = 202
  /// Load multiple 2-element structures to two consecutive registers.
  | LD2 = 203
  /// Load single 2-element structure and replicate to all lanes of two regs.
  | LD2R = 204
  /// Load multiple 3-element structures to three consecutive registers.
  | LD3 = 205
  /// Load single 3-element structure and replicate to all lanes of three regs.
  | LD3R = 206
  /// Load multiple 4-element structures to four consecutive registers.
  | LD4 = 207
  /// Load single 4-element structure and replicate to all lanes of four regs.
  | LD4R = 208
  /// Load-Acquire register.
  | LDAR = 209
  /// Load-Acquire byte.
  | LDARB = 210
  /// Load-Acquire halfword.
  | LDARH = 211
  /// Load-Acquire Exclusive pair.
  | LDAXP = 212
  /// Load-Acquire Exclusive register.
  | LDAXR = 213
  /// Load-Acquire Exclusive byte.
  | LDAXRB = 214
  /// Load-Acquire Exclusive halfword.
  | LDAXRH = 215
  /// Load Non-temporal Pair.
  | LDNP = 216
  /// Load Pair.
  | LDP = 217
  /// Load Pair signed words.
  | LDPSW = 218
  /// Load register.
  | LDR = 219
  /// Load byte.
  | LDRB = 220
  /// Load halfword.
  | LDRH = 221
  /// Load signed byte.
  | LDRSB = 222
  /// Load signed halfword.
  | LDRSH = 223
  /// Load signed word.
  | LDRSW = 224
  /// Load unprivileged register.
  | LDTR = 225
  /// Load unprivileged byte.
  | LDTRB = 226
  /// Load unprivileged halfword.
  | LDTRH = 227
  /// Load unprivileged signed byte.
  | LDTRSB = 228
  /// Load unprivileged signed halfword.
  | LDTRSH = 229
  /// Load unprivileged signed word.
  | LDTRSW = 230
  /// Load register (unscaled offset).
  | LDUR = 231
  /// Load byte (unscaled offset).
  | LDURB = 232
  /// Load halfword (unscaled offset).
  | LDURH = 233
  /// Load signed byte (unscaled offset).
  | LDURSB = 234
  /// Load signed halfword (unscaled offset).
  | LDURSH = 235
  /// Load signed word (unscaled offset).
  | LDURSW = 236
  /// Load Exclusive pair.
  | LDXP = 237
  /// Load Exclusive register.
  | LDXR = 238
  /// Load Exclusive byte.
  | LDXRB = 239
  /// Load Exclusive halfword.
  | LDXRH = 240
  /// Logical shift left.
  | LSL = 241
  /// Logical shift left variable.
  | LSLV = 242
  /// Logical shift right.
  | LSR = 243
  /// Logical shift right variable.
  | LSRV = 244
  /// Multiply-add.
  | MADD = 245
  /// Multiply-add to accumulator.
  | MLA = 246
  /// Multiply-subtract from accumulator.
  | MLS = 247
  /// Multiply-negate.
  | MNEG = 248
  /// Move.
  | MOV = 249
  /// Move immediate.
  | MOVI = 250
  /// Move wide with keep.
  | MOVK = 251
  /// Move wide with NOT.
  | MOVN = 252
  /// Move wide with zero.
  | MOVZ = 253
  /// Move System register to general-purpose register.
  | MRS = 254
  /// Move general-purpose register to System register.
  | MSR = 255
  /// Multiply-subtract.
  | MSUB = 256
  /// Multiply.
  | MUL = 257
  /// Bitwise NOT.
  | MVN = 258
  /// Move inverted immediate.
  | MVNI = 259
  /// Negate.
  | NEG = 260
  /// Negate and set flags.
  | NEGS = 261
  /// Negate with carry.
  | NGC = 262
  /// Negate with carry and set flags.
  | NGCS = 263
  /// No operation.
  | NOP = 264
  /// Bitwise NOT.
  | NOT = 265
  /// Bitwise inclusive OR NOT.
  | ORN = 266
  /// Bitwise inclusive OR.
  | ORR = 267
  /// Polynomial multiply (vector form).
  | PMUL = 268
  /// Polynomial multiply long (vector form).
  | PMULL = 269
  /// Polynomial multiply long (vector form).
  | PMULL2 = 270
  /// Prefetch memory.
  | PRFM = 271
  /// Prefetch memory (unscaled offset).
  | PRFUM = 272
  /// Rounding add returning high, narrow (vector form).
  | RADDHN = 273
  /// Rounding add returning high, narrow (vector form).
  | RADDHN2 = 274
  /// Reverse bit order.
  | RBIT = 275
  /// Return from subroutine.
  | RET = 276
  /// Reverse bytes in register.
  | REV = 277
  /// Reverse bytes in halfwords.
  | REV16 = 278
  /// Reverses bytes in words.
  | REV32 = 279
  /// Reverse elements in 64-bit doublewords (vector form).
  | REV64 = 280
  /// Rotate right.
  | ROR = 281
  /// Rotate right variable.
  | RORV = 282
  /// Rounding shift right narrow immediate (vector form).
  | RSHRN = 283
  /// Rounding shift right narrow immediate (vector form).
  | RSHRN2 = 284
  /// Rounding subtract returning high, narrow (vector form).
  | RSUBHN = 285
  /// Rounding subtract returning high, narrow (vector form).
  | RSUBHN2 = 286
  /// Signed absolute difference and accumulate (vector form).
  | SABA = 287
  /// Signed absolute difference and accumulate long (vector form).
  | SABAL = 288
  /// Signed absolute difference and accumulate long (vector form).
  | SABAL2 = 289
  /// Signed absolute difference (vector form).
  | SABD = 290
  /// Signed absolute difference long (vector form).
  | SABDL = 291
  /// Signed absolute difference long (vector form).
  | SABDL2 = 292
  /// Signed add and accumulate long pairwise (vector form).
  | SADALP = 293
  /// Signed add long (vector form).
  | SADDL = 294
  /// Signed add long (vector form).
  | SADDL2 = 295
  /// Signed add long pairwise (vector form).
  | SADDLP = 296
  /// Signed add long (across vector).
  | SADDLV = 297
  /// Signed add wide (vector form).
  | SADDW = 298
  /// Signed add wide (vector form).
  | SADDW2 = 299
  /// Subtract with carry.
  | SBC = 300
  /// Subtract with carry and set flags.
  | SBCS = 301
  /// Signed bitfield insert in zero.
  | SBFIZ = 302
  /// Signed bitfield move.
  | SBFM = 303
  /// Signed bitfield extract.
  | SBFX = 304
  /// Signed integer scalar convert to FP, using the current rounding mode.
  | SCVTF = 305
  /// Signed divide.
  | SDIV = 306
  /// Send event.
  | SEV = 307
  /// Send event local.
  | SEVL = 308
  /// SHA1 hash update (choose).
  | SHA1C = 309
  /// SHA1 fixed rotate.
  | SHA1H = 310
  /// SHA1 hash update (majority).
  | SHA1M = 311
  /// SHA1 hash update (parity).
  | SHA1P = 312
  /// SHA1 schedule update 0.
  | SHA1SU0 = 313
  /// SHA1 schedule update 1.
  | SHA1SU1 = 314
  /// SHA256 hash update (part 1).
  | SHA256H = 315
  /// SHA256 hash update (part 2).
  | SHA256H2 = 316
  /// SHA256 schedule update 0.
  | SHA256SU0 = 317
  /// SHA256 schedule update 1.
  | SHA256SU1 = 318
  /// Signed halving add (vector form).
  | SHADD = 319
  /// Shift left immediate (vector and scalar form).
  | SHL = 320
  /// Shift left long (by element size) (vector form).
  | SHLL = 321
  /// Shift left long (by element size) (vector form).
  | SHLL2 = 322
  /// Shift right narrow immediate (vector form).
  | SHRN = 323
  /// Shift right narrow immediate (vector form).
  | SHRN2 = 324
  /// Signed halving subtract (vector form).
  | SHSUB = 325
  /// Shift left and insert immediate (vector and scalar form).
  | SLI = 326
  /// Signed multiply-add long.
  | SMADDL = 327
  /// Signed maximum (vector form).
  | SMAX = 328
  /// Signed maximum pairwise.
  | SMAXP = 329
  /// Signed maximum (across vector).
  | SMAXV = 330
  /// Generate exception targeting Exception level 3.
  | SMC = 331
  /// Signed minimum (vector form).
  | SMIN = 332
  /// Signed minimum pairwise.
  | SMINP = 333
  /// Signed minimum (across vector).
  | SMINV = 334
  /// Signed multiply-add long.
  | SMLAL = 335
  /// Signed multiply-add long.
  | SMLAL2 = 336
  /// Signed multiply-subtract long.
  | SMLSL = 337
  /// Signed multiply-subtract long.
  | SMLSL2 = 338
  /// Signed multiply-negate long.
  | SMNEGL = 339
  /// Signed move vector element to general-purpose register.
  | SMOV = 340
  /// Signed multiply-subtract long.
  | SMSUBL = 341
  /// Signed multiply high.
  | SMULH = 342
  /// Signed multiply long.
  | SMULL = 343
  /// Signed multiply long.
  | SMULL2 = 344
  /// Signed saturating absolute value.
  | SQABS = 345
  /// Signed saturating add.
  | SQADD = 346
  /// Signed saturating doubling multiply-add long.
  | SQDMLAL = 347
  /// Signed saturating doubling multiply-add long.
  | SQDMLAL2 = 348
  /// Signed saturating doubling multiply-subtract long.
  | SQDMLSL = 349
  /// Signed saturating doubling multiply-subtract long.
  | SQDMLSL2 = 350
  /// Signed saturating doubling multiply returning high half.
  | SQDMULH = 351
  /// Signed saturating doubling multiply long.
  | SQDMULL = 352
  /// Signed saturating doubling multiply long.
  | SQDMULL2 = 353
  /// Signed saturating negate.
  | SQNEG = 354
  /// Signed saturating rounding doubling multiply returning high half.
  | SQRDMULH = 355
  /// Signed saturating rounding shift left (register).
  | SQRSHL = 356
  /// Signed saturating rounded shift right narrow immediate.
  | SQRSHRN = 357
  /// Signed saturating rounded shift right narrow immediate.
  | SQRSHRN2 = 358
  /// Signed saturating shift right unsigned narrow immediate.
  | SQRSHRUN = 359
  /// Signed saturating shift right unsigned narrow immediate.
  | SQRSHRUN2 = 360
  /// Signed saturating shift left.
  | SQSHL = 361
  /// Signed saturating shift left unsigned immediate.
  | SQSHLU = 362
  /// Signed saturating shift right narrow immediate.
  | SQSHRN = 363
  /// Signed saturating shift right narrow immediate.
  | SQSHRN2 = 364
  /// Signed saturating shift right unsigned narrow immediate.
  | SQSHRUN = 365
  /// Signed saturating shift right unsigned narrow immediate.
  | SQSHRUN2 = 366
  /// Signed saturating subtract.
  | SQSUB = 367
  /// Signed saturating extract narrow.
  | SQXTN = 368
  /// Signed saturating extract narrow.
  | SQXTN2 = 369
  /// Signed saturating extract unsigned narrow.
  | SQXTUN = 370
  /// Signed saturating extract unsigned narrow.
  | SQXTUN2 = 371
  /// Signed rounding halving add.
  | SRHADD = 372
  /// Shift right and insert immediate.
  | SRI = 373
  /// Signed rounding shift left (register).
  | SRSHL = 374
  /// Signed rounding shift right immediate.
  | SRSHR = 375
  /// Signed rounding shift right and accumulate immediate.
  | SRSRA = 376
  /// Signed shift left (register).
  | SSHL = 377
  /// Signed shift left long immediate.
  | SSHLL = 378
  /// Signed shift left long immediate.
  | SSHLL2 = 379
  /// Signed shift right immediate.
  | SSHR = 380
  /// Signed integer shift right and accumulate immediate.
  | SSRA = 381
  /// Signed subtract long.
  | SSUBL = 382
  /// Signed subtract long.
  | SSUBL2 = 383
  /// Signed subtract wide.
  | SSUBW = 384
  /// Signed subtract wide.
  | SSUBW2 = 385
  /// Store single 1-element structure from one lane of one register.
  | ST1 = 386
  /// Store multiple 2-element structures from two consecutive registers.
  | ST2 = 387
  /// Store multiple 3-element structures from three consecutive registers.
  | ST3 = 388
  /// Store multiple 4-element structures from four consecutive registers.
  | ST4 = 389
  /// Store-Release register.
  | STLR = 390
  /// Store-Release byte.
  | STLRB = 391
  /// Store-Release halfword.
  | STLRH = 392
  /// Store-Release Exclusive pair.
  | STLXP = 393
  /// Store-Release Exclusive register.
  | STLXR = 394
  /// Store-Release Exclusive byte.
  | STLXRB = 395
  /// Store-Release Exclusive halfword.
  | STLXRH = 396
  /// Store Non-temporal Pair.
  | STNP = 397
  /// Store Pair.
  | STP = 398
  /// Store register.
  | STR = 399
  /// Store byte.
  | STRB = 400
  /// Store halfword.
  | STRH = 401
  /// Store unprivileged register.
  | STTR = 402
  /// Store unprivileged byte.
  | STTRB = 403
  /// Store unprivileged halfword.
  | STTRH = 404
  /// Store register (unscaled offset).
  | STUR = 405
  /// Store byte (unscaled offset).
  | STURB = 406
  /// Store halfword (unscaled offset).
  | STURH = 407
  /// Store Exclusive pair.
  | STXP = 408
  /// Store Exclusive register.
  | STXR = 409
  /// Store Exclusive byte.
  | STXRB = 410
  /// Store Exclusive halfword.
  | STXRH = 411
  /// Subtract.
  | SUB = 412
  /// Subtract returning high, narrow.
  | SUBHN = 413
  /// Subtract returning high, narrow.
  | SUBHN2 = 414
  /// Subtract and set flags.
  | SUBS = 415
  /// Signed saturating accumulate of unsigned value.
  | SUQADD = 416
  /// Generate exception targeting Exception level 1.
  | SVC = 417
  /// Sign-extend byte.
  | SXTB = 418
  /// Sign-extend halfword.
  | SXTH = 419
  /// Sign-extend word.
  | SXTW = 420
  /// System instruction.
  | SYS = 421
  /// System instruction with result.
  | SYSL = 422
  /// Table vector lookup.
  | TBL = 423
  /// Test bit and branch if nonzero.
  | TBNZ = 424
  /// Table vector lookup extension.
  | TBX = 425
  /// Test bit and branch if zero.
  | TBZ = 426
  /// Transpose vectors (primary).
  | TRN1 = 427
  /// Transpose vectors (secondary).
  | TRN2 = 428
  /// Test bits.
  | TST = 429
  /// Unsigned absolute difference and accumulate.
  | UABA = 430
  /// Unsigned absolute difference and accumulate long.
  | UABAL = 431
  /// Unsigned absolute difference and accumulate long.
  | UABAL2 = 432
  /// Unsigned absolute difference.
  | UABD = 433
  /// Unsigned absolute difference long.
  | UABDL = 434
  /// Unsigned absolute difference long.
  | UABDL2 = 435
  /// Unsigned add and accumulate long pairwise.
  | UADALP = 436
  /// Unsigned add long.
  | UADDL = 437
  /// Unsigned add long.
  | UADDL2 = 438
  /// Unsigned add long pairwise.
  | UADDLP = 439
  /// Unsigned add long (across vector).
  | UADDLV = 440
  /// Unsigned add wide.
  | UADDW = 441
  /// Unsigned add wide.
  | UADDW2 = 442
  /// Unsigned bitfield insert in zero.
  | UBFIZ = 443
  /// Unsigned bitfield move (32-bit).
  | UBFM = 444
  /// Unsigned bitfield extract.
  | UBFX = 445
  /// Unsigned integer scalar convert to FP, using the current rounding mode.
  | UCVTF = 446
  /// Unsigned divide.
  | UDIV = 447
  /// Unsigned halving add.
  | UHADD = 448
  /// Unsigned halving subtract.
  | UHSUB = 449
  /// Unsigned multiply-add long.
  | UMADDL = 450
  /// Unsigned maximum.
  | UMAX = 451
  /// Unsigned maximum pairwise.
  | UMAXP = 452
  /// Unsigned maximum (across vector).
  | UMAXV = 453
  /// Unsigned minimum.
  | UMIN = 454
  /// Unsigned minimum pairwise.
  | UMINP = 455
  /// Unsigned minimum (across vector).
  | UMINV = 456
  /// Unsigned multiply-add long.
  | UMLAL = 457
  /// Unsigned multiply-add long.
  | UMLAL2 = 458
  /// Unsigned multiply-subtract long.
  | UMLSL = 459
  /// Unsigned multiply-subtract long.
  | UMLSL2 = 460
  /// Unsigned multiply-negate long.
  | UMNEGL = 461
  /// Unsigned move vector element to general-purpose register.
  | UMOV = 462
  /// Unsigned multiply-subtract long.
  | UMSUBL = 463
  /// Unsigned multiply high.
  | UMULH = 464
  /// Unsigned multiply long.
  | UMULL = 465
  /// Unsigned multiply long.
  | UMULL2 = 466
  /// Unsigned saturating add.
  | UQADD = 467
  /// Unsigned saturating rounding shift left (register).
  | UQRSHL = 468
  /// Unsigned saturating rounded shift right narrow immediate.
  | UQRSHRN = 469
  /// Unsigned saturating rounded shift right narrow immediate.
  | UQRSHRN2 = 470
  /// Unsigned saturating shift left (register).
  | UQSHL = 471
  /// Unsigned saturating shift right narrow immediate.
  | UQSHRN = 472
  /// Unsigned saturating shift right narrow immediate.
  | UQSHRN2 = 473
  /// Unsigned saturating subtract.
  | UQSUB = 474
  /// Unsigned saturating extract narrow.
  | UQXTN = 475
  /// Unsigned saturating extract narrow.
  | UQXTN2 = 476
  /// Unsigned reciprocal estimate.
  | URECPE = 477
  /// Unsigned rounding halving add.
  | URHADD = 478
  /// Unsigned rounding shift left (register).
  | URSHL = 479
  /// Unsigned rounding shift right immediate.
  | URSHR = 480
  /// Unsigned reciprocal square root estimate.
  | URSQRTE = 481
  /// Unsigned integer rounding shift right and accumulate immediate.
  | URSRA = 482
  /// Unsigned shift left (register).
  | USHL = 483
  /// Unsigned shift left long immediate.
  | USHLL = 484
  /// Unsigned shift left long immediate.
  | USHLL2 = 485
  /// Unsigned shift right immediate.
  | USHR = 486
  /// Unsigned saturating accumulate of signed value.
  | USQADD = 487
  /// Unsigned shift right and accumulate immediate.
  | USRA = 488
  /// Unsigned subtract long.
  | USUBL = 489
  /// Unsigned subtract long.
  | USUBL2 = 490
  /// Unsigned subtract wide.
  | USUBW = 491
  /// Unsigned subtract wide.
  | USUBW2 = 492
  /// Unsigned extend byte.
  | UXTB = 493
  /// Unsigned extend halfword.
  | UXTH = 494
  /// Unzip vectors (primary).
  | UZP1 = 495
  /// Unzip vectors (secondary).
  | UZP2 = 496
  /// Wait for event.
  | WFE = 497
  /// Wait for interrupt.
  | WFI = 498
  /// Extract narrow.
  | XTN = 499
  /// Extract narrow.
  | XTN2 = 500
  /// Hint instruction.
  | YIELD = 501
  /// Zip vectors (primary).
  | ZIP1 = 502
  /// Zip vectors (secondary).
  | ZIP2 = 503

type PrefetchOperation =
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

type OptionOpr =
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

type SIMDVector =
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

 type SRType =
  | SRTypeLSL
  | SRTypeLSR
  | SRTypeASR
  | SRTypeROR
  | SRTypeRRX
  | SRTypeMSL

type Index = uint8

/// SIMD&FP Register
type SIMDFPscalRegister = Register
/// SIMD vector register
type SIMDVectorRegister = Register * SIMDVector
/// SIMD vector register with element index
type SIMDVectorRegisterWithIndex = Register * SIMDVector * Index

type SIMDFPRegister =
  | SIMDFPScalarReg of SIMDFPscalRegister
  | SIMDVecReg of SIMDVectorRegister
  | SIMDVecRegWithIdx of SIMDVectorRegisterWithIndex

type SIMDOperand =
  (* SIMD&FP register *)
  | SFReg of SIMDFPRegister
  (* SIMD vector register list or SIMD vector element list *)
  | OneReg of SIMDFPRegister
  | TwoRegs of SIMDFPRegister * SIMDFPRegister
  | ThreeRegs of SIMDFPRegister * SIMDFPRegister * SIMDFPRegister
  | FourRegs of SIMDFPRegister * SIMDFPRegister * SIMDFPRegister
                * SIMDFPRegister

type SystemOp =
  | SysAT
  | SysDC
  | SysIC
  | SysTLBI
  | SysSYS

type Const = int64

type Amount =
  | Imm of Const
  | Reg of Register

type Shift = SRType * Amount

type Label = Const

type ExtendType =
  | ExtUXTB
  | ExtUXTH
  | ExtUXTW
  | ExtUXTX
  | ExtSXTB
  | ExtSXTH
  | ExtSXTW
  | ExtSXTX

type ExtendRegisterOffset = ExtendType * Const option

type Pstate =
  | SPSEL
  | DAIFSET
  | DAIFCLR

type RegisterOffset =
  /// Register offset.
  | ShiftOffset of Shift
  /// Extended register offset.
  | ExtRegOffset of ExtendRegisterOffset

type ImmOffset =
  | BaseOffset of Register * Const option
  | Lbl of Label

type Offset =
  | ImmOffset of ImmOffset
  | RegOffset of Register * Register * RegisterOffset option

type AddressingMode =
  | BaseMode of Offset
  | PreIdxMode of Offset
  | PostIdxMode of Offset
  | LiteralMode of Offset

type Operand =
  | OprRegister of Register
  | SIMDOpr of SIMDOperand
  | Immediate of Const
  | FPImmediate of float
  | NZCV of uint8
  | Shift of Shift
  | ExtReg of RegisterOffset option
  | Memory of AddressingMode
  | Option of OptionOpr
  | Pstate of Pstate
  | PrfOp of PrefetchOperation
  | Cond of Condition
  | Fbits of uint8  (* fractional bits *)
  | LSB of uint8

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand
  | FiveOperands of Operand * Operand * Operand * Operand * Operand

/// Basic information for a single ARMv8 instruction obtained after parsing.
[<NoComparison; CustomEquality>]
type InsInfo = {
  /// Address.
  Address: Addr
  /// Instruction length.
  NumBytes: uint32
  /// Condition.
  Condition: Condition option
  /// Opcode.
  Opcode: Opcode
  /// Operands.
  Operands: Operands
  /// Operation size.
  OprSize: RegType
}
with
  override __.GetHashCode () =
    hash (__.Address,
          __.NumBytes,
          __.Condition,
          __.Opcode,
          __.Operands,
          __.OprSize)
  override __.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = __.Address
      && i.NumBytes = __.NumBytes
      && i.Condition = __.Condition
      && i.Opcode = __.Opcode
      && i.Operands = __.Operands
      && i.OprSize = __.OprSize
    | _ -> false

