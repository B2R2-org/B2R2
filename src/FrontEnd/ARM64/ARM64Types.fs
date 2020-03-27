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

open B2R2
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.Tests")>]
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
  // Bitfield move.
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
  /// Data cache maintenance
  | DC = 85
  /// Debug switch to Exception level 1.
  | DCPS1 = 86
  /// Debug switch to Exception level 2.
  | DCPS2 = 87
  /// Debug switch to Exception level 3.
  | DCPS3 = 88
  /// Data memory barrier.
  | DMB = 89
  /// Debug restore PE state.
  | DRPS = 90
  /// Data synchronization barrier.
  | DSB = 91
  /// Duplicate general-purpose register to vector.
  | DUP = 92
  /// Bitwise exclusive OR NOT.
  | EON = 93
  /// Bitwise exclusive OR.
  | EOR = 94
  /// Exception return using current ELR and SPSR.
  | ERET = 95
  /// Extract vector from a pair of vectors.
  | EXT = 96
  /// Extract register from pair.
  | EXTR = 97
  /// Floating-point absolute difference (vector and scalar form).
  | FABD = 98
  /// Floating-point absolute (vector form).
  | FABS = 99
  /// Floating-point absolute compare greater than or equal.
  | FACGE = 100
  /// Floating-point absolute compare greater than (vector and scalar form).
  | FACGT = 101
  /// Floating-point add (vector form).
  | FADD = 102
  /// Floating-point add pairwise (vector and scalar form).
  | FADDP = 103
  /// Floating-point conditional quiet compare.
  | FCCMP = 104
  /// Floating-point conditional signaling compare.
  | FCCMPE = 105
  /// Floating-point compare equal (vector and scalar form).
  | FCMEQ = 106
  /// Floating-point compare greater than or equal (vector and scalar form).
  | FCMGE = 107
  /// Floating-point compare greater than (vector and scalar form).
  | FCMGT = 108
  /// Floating-point compare less than or equal to zero (vector and scalar).
  | FCMLE = 109
  /// Floating-point compare less than zero (vector and scalar form).
  | FCMLT = 110
  /// Floating-point quiet compare.
  | FCMP = 111
  /// Floating-point signaling compare.
  | FCMPE = 112
  /// Floating-point scalar conditional select.
  | FCSEL = 113
  /// Floating-point convert precision (scalar).
  | FCVT = 114
  /// FP convert to signed integer, rounding to nearest with ties to away.
  | FCVTAS = 115
  /// FP convert to unsigned integer, rounding to nearest with ties to away.
  | FCVTAU = 116
  /// Floating-point convert to higher precision long (vector form).
  | FCVTL = 117
  /// Floating-point convert to higher precision long (vector form).
  | FCVTL2 = 118
  /// Floating-point convert to signed integer, rounding toward minus infinity.
  | FCVTMS = 119
  /// FP convert to unsigned integer, rounding toward minus infinity.
  | FCVTMU = 120
  /// Floating-point convert to lower precision narrow (vector form).
  | FCVTN = 121
  /// Floating-point convert to lower precision narrow (vector form).
  | FCVTN2 = 122
  /// FP convert to signed integer, rounding to nearest with ties to even.
  | FCVTNS = 123
  /// FP convert to unsigned integer, rounding to nearest with ties to even.
  | FCVTNU = 124
  /// FP convert to signed integer, rounding toward positive infinity.
  | FCVTPS = 125
  /// FP convert to unsigned integer, rounding toward positive infinity.
  | FCVTPU = 126
  /// FP convert to lower precision narrow, rounding to odd (vector and scalar).
  | FCVTXN = 127
  /// FP convert to lower precision narrow, rounding to odd (vector and scalar).
  | FCVTXN2 = 128
  /// FP convert to signed integer, rounding toward zero (vector and scalar).
  | FCVTZS = 129
  /// FP convert to unsigned integer, rounding toward zero (vector and scalar).
  | FCVTZU = 130
  /// Floating-point divide.
  | FDIV = 131
  /// Floating-point scalar fused multiply-add.
  | FMADD = 132
  /// Floating-point maximum.
  | FMAX = 133
  /// Floating-point maximum number.
  | FMAXNM = 134
  /// Floating-point maximum number pairwise (vector and scalar form).
  | FMAXNMP = 135
  /// Floating-point maximum number (across vector).
  | FMAXNMV = 136
  /// Floating-point maximum pairwise (vector and scalar form).
  | FMAXP = 137
  /// Floating-point maximum (across vector).
  | FMAXV = 138
  /// Floating-point minimum.
  | FMIN = 139
  /// Floating-point minimum number.
  | FMINNM = 140
  /// Floating-point minimum number pairwise (vector and scalar form).
  | FMINNMP = 141
  /// Floating-point minimum number (across vector).
  | FMINNMV = 142
  /// Floating-point minimum pairwise (vector and scalar form).
  | FMINP = 143
  /// Floating-point minimum (across vector).
  | FMINV = 144
  /// Floating-point fused multiply-add.
  | FMLA = 145
  /// Floating-point fused multiply-subtract.
  | FMLS = 146
  /// Floating-point move immediate.
  | FMOV = 147
  /// Floating-point scalar fused multiply-subtract.
  | FMSUB = 148
  /// Floating-point multiply.
  | FMUL = 149
  /// Floating-point multiply extended.
  | FMULX = 150
  /// Floating-point negate.
  | FNEG = 151
  /// Floating-point scalar negated fused multiply-add.
  | FNMADD = 152
  /// Floating-point scalar negated fused multiply-subtract.
  | FNMSUB = 153
  /// Floating-point scalar multiply-negate.
  | FNMUL = 154
  /// Floating-point reciprocal estimate (vector and scalar form).
  | FRECPE = 155
  /// Floating-point reciprocal step (vector and scalar form).
  | FRECPS = 156
  /// Floating-point reciprocal square root (scalar form).
  | FRECPX = 157
  /// Floating-point round to integral, to nearest with ties to away.
  | FRINTA = 158
  /// Floating-point round to integral, using current rounding mode.
  | FRINTI = 159
  /// Floating-point round to integral, toward minus infinity.
  | FRINTM = 160
  /// Floating-point round to integral, to nearest with ties to even.
  | FRINTN = 161
  /// Floating-point round to integral, toward positive infinity.
  | FRINTP = 162
  /// Floating-point round to integral exact, using current rounding mode.
  | FRINTX = 163
  /// Floating-point round to integral, toward zero.
  | FRINTZ = 164
  /// Floating-point reciprocal square root estimate.
  | FRSQRTE = 165
  /// Floating-point reciprocal square root step (vector and scalar form).
  | FRSQRTS = 166
  /// Floating-point square root,
  | FSQRT = 167
  /// Floating-point subtract.
  | FSUB = 168
  /// Unallocated hint.
  | HINT = 169
  /// Halt Instruction.
  | HLT = 170
  /// Generate exception targeting Exception level 2.
  | HVC = 171
  /// Insert vector element from general-purpose register.
  | INS = 172
  /// Instruction synchronization barrier.
  | ISB = 173
  /// Load single 1-element structure to one lane of one register.
  | LD1 = 174
  /// Load single 1-element structure and replicate to all lanes of one reg.
  | LD1R = 175
  /// Load multiple 2-element structures to two consecutive registers.
  | LD2 = 176
  /// Load single 2-element structure and replicate to all lanes of two regs.
  | LD2R = 177
  /// Load multiple 3-element structures to three consecutive registers.
  | LD3 = 178
  /// Load single 3-element structure and replicate to all lanes of three regs.
  | LD3R = 179
  /// Load multiple 4-element structures to four consecutive registers.
  | LD4 = 180
  /// Load single 4-element structure and replicate to all lanes of four regs.
  | LD4R = 181
  /// Load-Acquire register.
  | LDAR = 182
  /// Load-Acquire byte.
  | LDARB = 183
  /// Load-Acquire halfword.
  | LDARH = 184
  /// Load-Acquire Exclusive pair.
  | LDAXP = 185
  /// Load-Acquire Exclusive register.
  | LDAXR = 186
  /// Load-Acquire Exclusive byte.
  | LDAXRB = 187
  /// Load-Acquire Exclusive halfword.
  | LDAXRH = 188
  /// Load Non-temporal Pair.
  | LDNP = 189
  /// Load Pair.
  | LDP = 190
  /// Load Pair signed words.
  | LDPSW = 191
  /// Load register.
  | LDR = 192
  /// Load byte.
  | LDRB = 193
  /// Load halfword.
  | LDRH = 194
  /// Load signed byte.
  | LDRSB = 195
  /// Load signed halfword.
  | LDRSH = 196
  /// Load signed word.
  | LDRSW = 197
  /// Load unprivileged register.
  | LDTR = 198
  /// Load unprivileged byte.
  | LDTRB = 199
  /// Load unprivileged halfword.
  | LDTRH = 200
  /// Load unprivileged signed byte.
  | LDTRSB = 201
  /// Load unprivileged signed halfword.
  | LDTRSH = 202
  /// Load unprivileged signed word.
  | LDTRSW = 203
  /// Load register (unscaled offset).
  | LDUR = 204
  /// Load byte (unscaled offset).
  | LDURB = 205
  /// Load halfword (unscaled offset).
  | LDURH = 206
  /// Load signed byte (unscaled offset).
  | LDURSB = 207
  /// Load signed halfword (unscaled offset).
  | LDURSH = 208
  /// Load signed word (unscaled offset).
  | LDURSW = 209
  /// Load Exclusive pair.
  | LDXP = 210
  /// Load Exclusive register.
  | LDXR = 211
  /// Load Exclusive byte.
  | LDXRB = 212
  /// Load Exclusive halfword.
  | LDXRH = 213
  /// Logical shift left.
  | LSL = 214
  /// Logical shift left variable.
  | LSLV = 215
  /// Logical shift right.
  | LSR = 216
  /// Logical shift right variable.
  | LSRV = 217
  /// Multiply-add.
  | MADD = 218
  /// Multiply-add to accumulator.
  | MLA = 219
  /// Multiply-subtract from accumulator.
  | MLS = 220
  /// Multiply-negate.
  | MNEG = 221
  /// Move.
  | MOV = 222
  /// Move immediate.
  | MOVI = 223
  /// Move wide with keep.
  | MOVK = 224
  /// Move wide with NOT.
  | MOVN = 225
  /// Move wide with zero.
  | MOVZ = 226
  /// Move System register to general-purpose register.
  | MRS = 227
  /// Move general-purpose register to System register.
  | MSR = 228
  /// Multiply-subtract.
  | MSUB = 229
  /// Multiply.
  | MUL = 230
  /// Bitwise NOT.
  | MVN = 231
  /// Move inverted immediate.
  | MVNI = 232
  /// Negate.
  | NEG = 233
  /// Negate and set flags.
  | NEGS = 234
  /// Negate with carry.
  | NGC = 235
  /// Negate with carry and set flags.
  | NGCS = 236
  /// No operation.
  | NOP = 237
  /// Bitwise NOT.
  | NOT = 238
  /// Bitwise inclusive OR NOT.
  | ORN = 239
  /// Bitwise inclusive OR.
  | ORR = 240
  /// Polynomial multiply (vector form).
  | PMUL = 241
  /// Polynomial multiply long (vector form).
  | PMULL = 242
  /// Polynomial multiply long (vector form).
  | PMULL2 = 243
  /// Prefetch memory.
  | PRFM = 244
  /// Prefetch memory (unscaled offset).
  | PRFUM = 245
  /// Rounding add returning high, narrow (vector form).
  | RADDHN = 246
  /// Rounding add returning high, narrow (vector form).
  | RADDHN2 = 247
  /// Reverse bit order.
  | RBIT = 248
  /// Return from subroutine.
  | RET = 249
  /// Reverse bytes in register.
  | REV = 250
  /// Reverse bytes in halfwords.
  | REV16 = 251
  /// Reverses bytes in words.
  | REV32 = 252
  /// Reverse elements in 64-bit doublewords (vector form).
  | REV64 = 253
  /// Rotate right.
  | ROR = 254
  /// Rotate right variable.
  | RORV = 255
  /// Rounding shift right narrow immediate (vector form).
  | RSHRN = 256
  /// Rounding shift right narrow immediate (vector form).
  | RSHRN2 = 257
  /// Rounding subtract returning high, narrow (vector form).
  | RSUBHN = 258
  /// Rounding subtract returning high, narrow (vector form).
  | RSUBHN2 = 259
  /// Signed absolute difference and accumulate (vector form).
  | SABA = 260
  /// Signed absolute difference and accumulate long (vector form).
  | SABAL = 261
  /// Signed absolute difference and accumulate long (vector form).
  | SABAL2 = 262
  /// Signed absolute difference (vector form).
  | SABD = 263
  /// Signed absolute difference long (vector form).
  | SABDL = 264
  /// Signed absolute difference long (vector form).
  | SABDL2 = 265
  /// Signed add and accumulate long pairwise (vector form).
  | SADALP = 266
  /// Signed add long (vector form).
  | SADDL = 267
  /// Signed add long (vector form).
  | SADDL2 = 268
  /// Signed add long pairwise (vector form).
  | SADDLP = 269
  /// Signed add long (across vector).
  | SADDLV = 270
  /// Signed add wide (vector form).
  | SADDW = 271
  /// Signed add wide (vector form).
  | SADDW2 = 272
  /// Subtract with carry.
  | SBC = 273
  /// Subtract with carry and set flags.
  | SBCS = 274
  /// Signed bitfield insert in zero.
  | SBFIZ = 275
  /// Signed bitfield move.
  | SBFM = 276
  /// Signed bitfield extract.
  | SBFX = 277
  /// Signed integer scalar convert to FP, using the current rounding mode.
  | SCVTF = 278
  /// Signed divide.
  | SDIV = 279
  /// Send event.
  | SEV = 280
  /// Send event local.
  | SEVL = 281
  /// SHA1 hash update (choose).
  | SHA1C = 282
  /// SHA1 fixed rotate.
  | SHA1H = 283
  /// SHA1 hash update (majority).
  | SHA1M = 284
  /// SHA1 hash update (parity).
  | SHA1P = 285
  /// SHA1 schedule update 0.
  | SHA1SU0 = 286
  /// SHA1 schedule update 1.
  | SHA1SU1 = 287
  /// SHA256 hash update (part 1).
  | SHA256H = 288
  /// SHA256 hash update (part 2).
  | SHA256H2 = 289
  /// SHA256 schedule update 0.
  | SHA256SU0 = 290
  /// SHA256 schedule update 1.
  | SHA256SU1 = 291
  /// Signed halving add (vector form).
  | SHADD = 292
  /// Shift left immediate (vector and scalar form).
  | SHL = 293
  /// Shift left long (by element size) (vector form).
  | SHLL = 294
  /// Shift left long (by element size) (vector form).
  | SHLL2 = 295
  /// Shift right narrow immediate (vector form).
  | SHRN = 296
  /// Shift right narrow immediate (vector form).
  | SHRN2 = 297
  /// Signed halving subtract (vector form).
  | SHSUB = 298
  /// Shift left and insert immediate (vector and scalar form).
  | SLI = 299
  /// Signed multiply-add long.
  | SMADDL = 300
  /// Signed maximum (vector form).
  | SMAX = 301
  /// Signed maximum pairwise.
  | SMAXP = 302
  /// Signed maximum (across vector).
  | SMAXV = 303
  /// Generate exception targeting Exception level 3.
  | SMC = 304
  /// Signed minimum (vector form).
  | SMIN = 305
  /// Signed minimum pairwise.
  | SMINP = 306
  /// Signed minimum (across vector).
  | SMINV = 307
  /// Signed multiply-add long.
  | SMLAL = 308
  /// Signed multiply-add long.
  | SMLAL2 = 309
  /// Signed multiply-subtract long.
  | SMLSL = 310
  /// Signed multiply-subtract long.
  | SMLSL2 = 311
  /// Signed multiply-negate long.
  | SMNEGL = 312
  /// Signed move vector element to general-purpose register.
  | SMOV = 313
  /// Signed multiply-subtract long.
  | SMSUBL = 314
  /// Signed multiply high.
  | SMULH = 315
  /// Signed multiply long.
  | SMULL = 316
  /// Signed multiply long.
  | SMULL2 = 317
  /// Signed saturating absolute value.
  | SQABS = 318
  /// Signed saturating add.
  | SQADD = 319
  /// Signed saturating doubling multiply-add long.
  | SQDMLAL = 320
  /// Signed saturating doubling multiply-add long.
  | SQDMLAL2 = 321
  /// Signed saturating doubling multiply-subtract long.
  | SQDMLSL = 322
  /// Signed saturating doubling multiply-subtract long.
  | SQDMLSL2 = 323
  /// Signed saturating doubling multiply returning high half.
  | SQDMULH = 324
  /// Signed saturating doubling multiply long.
  | SQDMULL = 325
  /// Signed saturating doubling multiply long.
  | SQDMULL2 = 326
  /// Signed saturating negate.
  | SQNEG = 327
  /// Signed saturating rounding doubling multiply returning high half.
  | SQRDMULH = 328
  /// Signed saturating rounding shift left (register).
  | SQRSHL = 329
  /// Signed saturating rounded shift right narrow immediate.
  | SQRSHRN = 330
  /// Signed saturating rounded shift right narrow immediate.
  | SQRSHRN2 = 331
  /// Signed saturating shift right unsigned narrow immediate.
  | SQRSHRUN = 332
  /// Signed saturating shift right unsigned narrow immediate.
  | SQRSHRUN2 = 333
  /// Signed saturating shift left.
  | SQSHL = 334
  /// Signed saturating shift left unsigned immediate.
  | SQSHLU = 335
  /// Signed saturating shift right narrow immediate.
  | SQSHRN = 336
  /// Signed saturating shift right narrow immediate.
  | SQSHRN2 = 337
  /// Signed saturating shift right unsigned narrow immediate.
  | SQSHRUN = 338
  /// Signed saturating shift right unsigned narrow immediate.
  | SQSHRUN2 = 339
  /// Signed saturating subtract.
  | SQSUB = 340
  /// Signed saturating extract narrow.
  | SQXTN = 341
  /// Signed saturating extract narrow.
  | SQXTN2 = 342
  /// Signed saturating extract unsigned narrow.
  | SQXTUN = 343
  /// Signed saturating extract unsigned narrow.
  | SQXTUN2 = 344
  /// Signed rounding halving add.
  | SRHADD = 345
  /// Shift right and insert immediate.
  | SRI = 346
  /// Signed rounding shift left (register).
  | SRSHL = 347
  /// Signed rounding shift right immediate.
  | SRSHR = 348
  /// Signed rounding shift right and accumulate immediate.
  | SRSRA = 349
  /// Signed shift left (register).
  | SSHL = 350
  /// Signed shift left long immediate.
  | SSHLL = 351
  /// Signed shift left long immediate.
  | SSHLL2 = 352
  /// Signed shift right immediate.
  | SSHR = 353
  /// Signed integer shift right and accumulate immediate.
  | SSRA = 354
  /// Signed subtract long.
  | SSUBL = 355
  /// Signed subtract long.
  | SSUBL2 = 356
  /// Signed subtract wide.
  | SSUBW = 357
  /// Signed subtract wide.
  | SSUBW2 = 358
  /// Store single 1-element structure from one lane of one register.
  | ST1 = 359
  /// Store multiple 2-element structures from two consecutive registers.
  | ST2 = 360
  /// Store multiple 3-element structures from three consecutive registers.
  | ST3 = 361
  /// Store multiple 4-element structures from four consecutive registers.
  | ST4 = 362
  /// Store-Release register.
  | STLR = 363
  /// Store-Release byte.
  | STLRB = 364
  /// Store-Release halfword.
  | STLRH = 365
  /// Store-Release Exclusive pair.
  | STLXP = 366
  /// Store-Release Exclusive register.
  | STLXR = 367
  /// Store-Release Exclusive byte.
  | STLXRB = 368
  /// Store-Release Exclusive halfword.
  | STLXRH = 369
  /// Store Non-temporal Pair.
  | STNP = 370
  /// Store Pair.
  | STP = 371
  /// Store register.
  | STR = 372
  /// Store byte.
  | STRB = 373
  /// Store halfword.
  | STRH = 374
  /// Store unprivileged register.
  | STTR = 375
  /// Store unprivileged byte.
  | STTRB = 376
  /// Store unprivileged halfword.
  | STTRH = 377
  /// Store register (unscaled offset).
  | STUR = 378
  /// Store byte (unscaled offset).
  | STURB = 379
  /// Store halfword (unscaled offset).
  | STURH = 380
  /// Store Exclusive pair.
  | STXP = 381
  /// Store Exclusive register.
  | STXR = 382
  /// Store Exclusive byte.
  | STXRB = 383
  /// Store Exclusive halfword.
  | STXRH = 384
  /// Subtract.
  | SUB = 385
  /// Subtract returning high, narrow.
  | SUBHN = 386
  /// Subtract returning high, narrow.
  | SUBHN2 = 387
  /// Subtract and set flags.
  | SUBS = 388
  /// Signed saturating accumulate of unsigned value.
  | SUQADD = 389
  /// Generate exception targeting Exception level 1.
  | SVC = 390
  /// Sign-extend byte.
  | SXTB = 391
  /// Sign-extend halfword.
  | SXTH = 392
  /// Sign-extend word.
  | SXTW = 393
  /// System instruction.
  | SYS = 394
  /// System instruction with result.
  | SYSL = 395
  /// Table vector lookup.
  | TBL = 396
  /// Test bit and branch if nonzero.
  | TBNZ = 397
  /// Table vector lookup extension.
  | TBX = 398
  /// Test bit and branch if zero.
  | TBZ = 399
  /// Transpose vectors (primary).
  | TRN1 = 400
  /// Transpose vectors (secondary).
  | TRN2 = 401
  /// Test bits.
  | TST = 402
  /// Unsigned absolute difference and accumulate.
  | UABA = 403
  /// Unsigned absolute difference and accumulate long.
  | UABAL = 404
  /// Unsigned absolute difference and accumulate long.
  | UABAL2 = 405
  /// Unsigned absolute difference.
  | UABD = 406
  /// Unsigned absolute difference long.
  | UABDL = 407
  /// Unsigned absolute difference long.
  | UABDL2 = 408
  /// Unsigned add and accumulate long pairwise.
  | UADALP = 409
  /// Unsigned add long.
  | UADDL = 410
  /// Unsigned add long.
  | UADDL2 = 411
  /// Unsigned add long pairwise.
  | UADDLP = 412
  /// Unsigned add long (across vector).
  | UADDLV = 413
  /// Unsigned add wide.
  | UADDW = 414
  /// Unsigned add wide.
  | UADDW2 = 415
  /// Unsigned bitfield insert in zero.
  | UBFIZ = 416
  /// Unsigned bitfield move (32-bit).
  | UBFM = 417
  /// Unsigned bitfield extract.
  | UBFX = 418
  /// Unsigned integer scalar convert to FP, using the current rounding mode.
  | UCVTF = 419
  /// Unsigned divide.
  | UDIV = 420
  /// Unsigned halving add.
  | UHADD = 421
  /// Unsigned halving subtract.
  | UHSUB = 422
  /// Unsigned multiply-add long.
  | UMADDL = 423
  /// Unsigned maximum.
  | UMAX = 424
  /// Unsigned maximum pairwise.
  | UMAXP = 425
  /// Unsigned maximum (across vector).
  | UMAXV = 426
  /// Unsigned minimum.
  | UMIN = 427
  /// Unsigned minimum pairwise.
  | UMINP = 428
  /// Unsigned minimum (across vector).
  | UMINV = 429
  /// Unsigned multiply-add long.
  | UMLAL = 430
  /// Unsigned multiply-add long.
  | UMLAL2 = 431
  /// Unsigned multiply-subtract long.
  | UMLSL = 432
  /// Unsigned multiply-subtract long.
  | UMLSL2 = 433
  /// Unsigned multiply-negate long.
  | UMNEGL = 434
  /// Unsigned move vector element to general-purpose register.
  | UMOV = 435
  /// Unsigned multiply-subtract long.
  | UMSUBL = 436
  /// Unsigned multiply high.
  | UMULH = 437
  /// Unsigned multiply long.
  | UMULL = 438
  /// Unsigned multiply long.
  | UMULL2 = 439
  /// Unsigned saturating add.
  | UQADD = 440
  /// Unsigned saturating rounding shift left (register).
  | UQRSHL = 441
  /// Unsigned saturating rounded shift right narrow immediate.
  | UQRSHRN = 442
  /// Unsigned saturating rounded shift right narrow immediate.
  | UQRSHRN2 = 443
  /// Unsigned saturating shift left (register).
  | UQSHL = 444
  /// Unsigned saturating shift right narrow immediate.
  | UQSHRN = 445
  /// Unsigned saturating shift right narrow immediate.
  | UQSHRN2 = 446
  /// Unsigned saturating subtract.
  | UQSUB = 447
  /// Unsigned saturating extract narrow.
  | UQXTN = 448
  /// Unsigned saturating extract narrow.
  | UQXTN2 = 449
  /// Unsigned reciprocal estimate.
  | URECPE = 450
  /// Unsigned rounding halving add.
  | URHADD = 451
  /// Unsigned rounding shift left (register).
  | URSHL = 452
  /// Unsigned rounding shift right immediate.
  | URSHR = 453
  /// Unsigned reciprocal square root estimate.
  | URSQRTE = 454
  /// Unsigned integer rounding shift right and accumulate immediate.
  | URSRA = 455
  /// Unsigned shift left (register).
  | USHL = 456
  /// Unsigned shift left long immediate.
  | USHLL = 457
  /// Unsigned shift left long immediate.
  | USHLL2 = 458
  /// Unsigned shift right immediate.
  | USHR = 459
  /// Unsigned saturating accumulate of signed value.
  | USQADD = 460
  /// Unsigned shift right and accumulate immediate.
  | USRA = 461
  /// Unsigned subtract long.
  | USUBL = 462
  /// Unsigned subtract long.
  | USUBL2 = 463
  /// Unsigned subtract wide.
  | USUBW = 464
  /// Unsigned subtract wide.
  | USUBW2 = 465
  /// Unsigned extend byte.
  | UXTB = 466
  /// Unsigned extend halfword.
  | UXTH = 467
  /// Unzip vectors (primary).
  | UZP1 = 468
  /// Unzip vectors (secondary).
  | UZP2 = 469
  /// Wait for event.
  | WFE = 470
  /// Wait for interrupt.
  | WFI = 471
  /// Extract narrow.
  | XTN = 472
  /// Extract narrow.
  | XTN2 = 473
  | YIELD = 474
  /// Zip vectors (primary).
  | ZIP1 = 475
  /// Zip vectors (secondary).
  | ZIP2 = 476

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

type DCOpr =
  | IVAC
  | ISW
  | CSW
  | CISW
  | ZVA
  | CVAC
  | CVAU
  | CIVAC

type SysOperand =
  | DCOpr of DCOpr

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
  | Fbits of uint8  // fractional bits
  | LSB of uint8
  | SysOpr of SysOperand

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

