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

open System.Runtime.CompilerServices
open B2R2

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.ARM64.Tests")>]
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
///   ARMv8 (AArch64) opcodes.
/// </summary>
type Opcode =
  /// Absolute value.
  | ABS = 0
  /// Add with Carry.
  | ADC = 1
  /// Add with carry long (bottom).
  | ADCLB = 2
  /// Add with carry long (top).
  | ADCLT = 3
  /// Add with Carry, setting flags.
  | ADCS = 4
  /// Add multi-vector to ZA array vector accumulators.
  | ADD = 5
  /// Add with Tag.
  | ADDG = 6
  /// Add horizontally vector elements to ZA tile.
  | ADDHA = 7
  /// Add returning High Narrow.
  | ADDHN = 8
  /// Add returning High Narrow.
  | ADDHN2 = 9
  /// Add narrow high part (bottom).
  | ADDHNB = 10
  /// Add narrow high part (top).
  | ADDHNT = 11
  /// Add pairwise.
  | ADDP = 12
  /// Add multiple of predicate register size to scalar register.
  | ADDPL = 13
  /// Unsigned add reduction of quadword vector segments.
  | ADDQV = 14
  /// Add (extended register), setting flags.
  | ADDS = 15
  /// Add multiple of Streaming SVE predicate register size to scalar register.
  | ADDSPL = 16
  /// Add multiple of Streaming SVE vector register size to scalar register.
  | ADDSVL = 17
  /// Add across Vector.
  | ADDV = 18
  /// Add vertically vector elements to ZA tile.
  | ADDVA = 19
  /// Add multiple of vector register size to scalar register.
  | ADDVL = 20
  /// Form PC-relative address.
  | ADR = 21
  /// Form PC-relative address to 4KB page.
  | ADRP = 22
  /// AES single round decryption.
  | AESD = 23
  /// AES single round encryption.
  | AESE = 24
  /// AES inverse mix columns.
  | AESIMC = 25
  /// AES mix columns.
  | AESMC = 26
  /// Bitwise AND (immediate).
  | AND = 27
  /// Bitwise AND reduction of quadword vector segments.
  | ANDQV = 28
  /// Bitwise AND predicates, setting the condition flags.
  | ANDS = 29
  /// Bitwise AND reduction to scalar.
  | ANDV = 30
  /// Arithmetic Shift Right (immediate): an alias of SBFM.
  | ASR = 31
  /// Arithmetic shift right for divide by immediate (predicated).
  | ASRD = 32
  /// Reversed arithmetic shift right by vector (predicated).
  | ASRR = 33
  /// Arithmetic Shift Right Variable.
  | ASRV = 34
  /// Address Translate: an alias of SYS.
  | AT = 35
  /// Authenticate Data address, using key A.
  | AUTDA = 36
  /// Authenticate Data address, using key B.
  | AUTDB = 37
  /// Authenticate Data address, using key A.
  | AUTDZA = 38
  /// Authenticate Data address, using key B.
  | AUTDZB = 39
  /// Authenticate Instruction address, using key A.
  | AUTIA = 40
  /// Authenticate Instruction address, using key A.
  | AUTIA1716 = 41
  /// Authenticate Instruction address, using key A.
  | AUTIASP = 42
  /// Authenticate Instruction address, using key A.
  | AUTIAZ = 43
  /// Authenticate Instruction address, using key B.
  | AUTIB = 44
  /// Authenticate Instruction address, using key B.
  | AUTIB1716 = 45
  /// Authenticate Instruction address, using key B.
  | AUTIBSP = 46
  /// Authenticate Instruction address, using key B.
  | AUTIBZ = 47
  /// Authenticate Instruction address, using key A.
  | AUTIZA = 48
  /// Authenticate Instruction address, using key B.
  | AUTIZB = 49
  /// Convert FP condition flags from Arm to external format.
  | AXFLAG = 50
  /// Branch.
  | B = 51
  /// Branch conditionally (AL).
  | BAL = 52
  /// Branch Consistent conditionally.
  | BC = 53
  /// Bit Clear and XOR.
  | BCAX = 54
  /// Branch conditionally (CC).
  | BCC = 55
  /// Branch conditionally (CS).
  | BCS = 56
  /// Scatter lower bits into positions selected by bitmask.
  | BDEP = 57
  /// Branch conditionally (EQ).
  | BEQ = 58
  /// Gather lower bits from positions selected by bitmask.
  | BEXT = 59
  /// BFloat16 FP add multi-vector to ZA array vector accumulators.
  | BFADD = 60
  /// Bitfield Clear: an alias of BFM.
  | BFC = 61
  /// BFloat16 FP clamp to minimum/maximum number.
  | BFCLAMP = 62
  /// FP convert from single-precision to BFloat16 format (scalar).
  | BFCVT = 63
  /// FP convert from single-precision to BFloat16 format (vector).
  | BFCVTN = 64
  /// FP convert from single-precision to BFloat16 format (vector).
  | BFCVTN2 = 65
  /// FP down convert and narrow to BFloat16 (top, predicated).
  | BFCVTNT = 66
  /// BFloat16 FP dot product (vector, by element).
  | BFDOT = 67
  /// Bitfield Insert: an alias of BFM.
  | BFI = 68
  /// Bitfield Move.
  | BFM = 69
  /// BFloat16 FP maximum (predicated).
  | BFMAX = 70
  /// BFloat16 FP maximum number (predicated).
  | BFMAXNM = 71
  /// BFloat16 FP minimum (predicated).
  | BFMIN = 72
  /// BFloat16 FP minimum number (predicated).
  | BFMINNM = 73
  /// BFloat16 FP fused multiply-add vectors by indexed elements.
  | BFMLA = 74
  /// Multi-vector BFloat16 FP multiply-add long by indexed element.
  | BFMLAL = 75
  /// BFloat16 FP widening multiply-add long (by element).
  | BFMLALB = 76
  /// BFloat16 FP widening multiply-add long (by element).
  | BFMLALT = 77
  /// BFloat16 FP fused multiply-subtract vectors by indexed elements.
  | BFMLS = 78
  /// Multi-vector BFloat16 FP multiply-subtract long by indexed element.
  | BFMLSL = 79
  /// BFloat16 FP mul-subtract long from single-precision (bottom, indexed).
  | BFMLSLB = 80
  /// BFloat16 FP multiply-subtract long from single-precision (top, indexed).
  | BFMLSLT = 81
  /// BFloat16 FP matrix multiply-accumulate into 2x2 matrix.
  | BFMMLA = 82
  /// BFloat16 FP outer product and accumulate.
  | BFMOPA = 83
  /// BFloat16 FP outer product and subtract.
  | BFMOPS = 84
  /// BFloat16 FP multiply vectors by indexed elements.
  | BFMUL = 85
  /// BFloat16 FP subtract multi-vector from ZA array vector accumulators.
  | BFSUB = 86
  /// Multi-vector BFloat16 FP vertical dot-product by indexed element.
  | BFVDOT = 87
  /// Bitfield extract and insert at low end: an alias of BFM.
  | BFXIL = 88
  /// Branch conditionally (GE).
  | BGE = 89
  /// Group bits to right or left as selected by bitmask.
  | BGRP = 90
  /// Branch conditionally (GT).
  | BGT = 91
  /// Branch conditionally (HI).
  | BHI = 92
  /// Branch conditionally (HS).
  | BHS = 93
  /// Bitwise clear bits using immediate (unpredicated): an alias of AND (imm).
  | BIC = 94
  /// Bitwise clear predicates, setting the condition flags.
  | BICS = 95
  /// Bitwise Insert if False.
  | BIF = 96
  /// Bitwise Insert if True.
  | BIT = 97
  /// Branch with Link.
  | BL = 98
  /// Branch conditionally (LE).
  | BLE = 99
  /// Branch conditionally (LO).
  | BLO = 100
  /// Branch with Link to Register.
  | BLR = 101
  /// Branch with Link to Register, with pointer authentication.
  | BLRAA = 102
  /// Branch with Link to Register, with pointer authentication.
  | BLRAAZ = 103
  /// Branch with Link to Register, with pointer authentication.
  | BLRAB = 104
  /// Branch with Link to Register, with pointer authentication.
  | BLRABZ = 105
  /// Branch conditionally (LS).
  | BLS = 106
  /// Branch conditionally (LT).
  | BLT = 107
  /// Branch conditionally (MI).
  | BMI = 108
  /// Bitwise exclusive NOR population count outer product and accumulate.
  | BMOPA = 109
  /// Bitwise exclusive NOR population count outer product and subtract.
  | BMOPS = 110
  /// Branch conditionally (NE).
  | BNE = 111
  /// Branch conditionally (NV).
  | BNV = 112
  /// Branch conditionally (PL).
  | BPL = 113
  /// Branch to Register.
  | BR = 114
  /// Branch to Register, with pointer authentication.
  | BRAA = 115
  /// Branch to Register, with pointer authentication.
  | BRAAZ = 116
  /// Branch to Register, with pointer authentication.
  | BRAB = 117
  /// Branch to Register, with pointer authentication.
  | BRABZ = 118
  /// Branch Record Buffer: an alias of SYS.
  | BRB = 119
  /// Breakpoint instruction.
  | BRK = 120
  /// Break after first true condition.
  | BRKA = 121
  /// Break after first true condition, setting the condition flags.
  | BRKAS = 122
  /// Break before first true condition.
  | BRKB = 123
  /// Break before first true condition, setting the condition flags.
  | BRKBS = 124
  /// Propagate break to next partition.
  | BRKN = 125
  /// Propagate break to next partition, setting the condition flags.
  | BRKNS = 126
  /// Break after first true condition, propagating from previous partition.
  | BRKPA = 127
  /// Break after first true condition.
  | BRKPAS = 128
  /// Break before first true condition, propagating from previous partition.
  | BRKPB = 129
  /// Break before first true cond.
  | BRKPBS = 130
  /// Bitwise Select.
  | BSL = 131
  /// Bitwise select with first input inverted.
  | BSL1N = 132
  /// Bitwise select with second input inverted.
  | BSL2N = 133
  /// Branch Target Identification.
  | BTI = 134
  /// Branch conditionally (VC).
  | BVC = 135
  /// Branch conditionally (VS).
  | BVS = 136
  /// Complex integer add with rotate.
  | CADD = 137
  /// Compare and Swap word or doubleword in memory.
  | CAS = 138
  /// Compare and Swap word or doubleword in memory.
  | CASA = 139
  /// Compare and Swap byte in memory.
  | CASAB = 140
  /// Compare and Swap halfword in memory.
  | CASAH = 141
  /// Compare and Swap word or doubleword in memory.
  | CASAL = 142
  /// Compare and Swap byte in memory.
  | CASALB = 143
  /// Compare and Swap halfword in memory.
  | CASALH = 144
  /// Compare and Swap byte in memory.
  | CASB = 145
  /// Compare and Swap halfword in memory.
  | CASH = 146
  /// Compare and Swap word or doubleword in memory.
  | CASL = 147
  /// Compare and Swap byte in memory.
  | CASLB = 148
  /// Compare and Swap halfword in memory.
  | CASLH = 149
  /// Compare and Swap Pair of words or doublewords in memory.
  | CASP = 150
  /// Compare and Swap Pair of words or doublewords in memory.
  | CASPA = 151
  /// Compare and Swap Pair of words or doublewords in memory.
  | CASPAL = 152
  /// Compare and Swap Pair of words or doublewords in memory.
  | CASPL = 153
  /// Compare and Branch on Nonzero.
  | CBNZ = 154
  /// Compare and Branch on Zero.
  | CBZ = 155
  /// Conditional Compare Negative (immediate).
  | CCMN = 156
  /// Conditional Compare (immediate).
  | CCMP = 157
  /// Complex integer dot product (indexed).
  | CDOT = 158
  /// Invert Carry Flag.
  | CFINV = 159
  /// Control Flow Prediction Restriction by Context: an alias of SYS.
  | CFP = 160
  /// Conditional Increment: an alias of CSINC.
  | CINC = 161
  /// Conditional Invert: an alias of CSINV.
  | CINV = 162
  /// Conditionally extract element after last to general-purpose register.
  | CLASTA = 163
  /// Conditionally extract last element to general-purpose register.
  | CLASTB = 164
  /// Clear Branch History.
  | CLRBHB = 165
  /// Clear Exclusive.
  | CLREX = 166
  /// Count Leading Sign bits.
  | CLS = 167
  /// Count Leading Zeros.
  | CLZ = 168
  /// Compare bitwise Equal (vector).
  | CMEQ = 169
  /// Compare signed Greater than or Equal (vector).
  | CMGE = 170
  /// Compare signed Greater than (vector).
  | CMGT = 171
  /// Compare unsigned Higher (vector).
  | CMHI = 172
  /// Compare unsigned Higher or Same (vector).
  | CMHS = 173
  /// Complex integer multiply-add with rotate (indexed).
  | CMLA = 174
  /// Compare signed Less than or Equal to zero (vector).
  | CMLE = 175
  /// Compare signed Less than zero (vector).
  | CMLT = 176
  /// Compare Negative (extended reg): an alias of ADDS (extended register).
  | CMN = 177
  /// Compare (extended register): an alias of SUBS (extended register).
  | CMP = 178
  /// Compare signed less than or equal to vector, setting the condition flags.
  | CMPLE = 179
  /// Compare unsigned lower than vector, setting the condition flags.
  | CMPLO = 180
  /// Compare unsigned lower or same as vector, setting the condition flags.
  | CMPLS = 181
  /// Compare signed less than vector, setting the condition flags.
  | CMPLT = 182
  /// Compare with Tag: an alias of SUBPS.
  | CMPP = 183
  /// Compare bitwise Test bits nonzero (vector).
  | CMTST = 184
  /// Conditional Negate: an alias of CSNEG.
  | CNEG = 185
  /// Logically invert boolean condition in vector (predicated).
  | CNOT = 186
  /// Count bits.
  | CNT = 187
  /// Set scalar to multiple of predicate constraint element count.
  | CNTB = 188
  /// Set scalar to multiple of predicate constraint element count.
  | CNTD = 189
  /// Set scalar to multiple of predicate constraint element count.
  | CNTH = 190
  /// Set scalar to count from predicate-as-counter.
  | CNTP = 191
  /// Set scalar to multiple of predicate constraint element count.
  | CNTW = 192
  /// Shuffle active elements of vector to the right and fill with zero.
  | COMPACT = 193
  /// Clear Other Speculative Predictions by Context: an alias of SYS.
  | COSP = 194
  /// Cache Prefetch Prediction Restriction by Context: an alias of SYS.
  | CPP = 195
  /// Copy signed integer immediate to vector elements (merging).
  | CPY = 196
  /// Memory Copy.
  | CPYE = 197
  /// Memory Copy, reads and writes non-temporal.
  | CPYEN = 198
  /// Memory Copy, reads non-temporal.
  | CPYERN = 199
  /// Memory Copy, reads unprivileged.
  | CPYERT = 200
  /// Memory Copy, reads unprivileged, reads and writes non-temporal.
  | CPYERTN = 201
  /// Memory Copy, reads unprivileged and non-temporal.
  | CPYERTRN = 202
  /// Memory Copy, reads unprivileged, writes non-temporal.
  | CPYERTWN = 203
  /// Memory Copy, reads and writes unprivileged.
  | CPYET = 204
  /// Memory Copy, reads and writes unprivileged and non-temporal.
  | CPYETN = 205
  /// Memory Copy, reads and writes unprivileged, reads non-temporal.
  | CPYETRN = 206
  /// Memory Copy, reads and writes unprivileged, writes non-temporal.
  | CPYETWN = 207
  /// Memory Copy, writes non-temporal.
  | CPYEWN = 208
  /// Memory Copy, writes unprivileged.
  | CPYEWT = 209
  /// Memory Copy, writes unprivileged, reads and writes non-temporal.
  | CPYEWTN = 210
  /// Memory Copy, writes unprivileged, reads non-temporal.
  | CPYEWTRN = 211
  /// Memory Copy, writes unprivileged and non-temporal.
  | CPYEWTWN = 212
  /// Memory Copy Forward-only.
  | CPYFE = 213
  /// Memory Copy Forward-only, reads and writes non-temporal.
  | CPYFEN = 214
  /// Memory Copy Forward-only, reads non-temporal.
  | CPYFERN = 215
  /// Memory Copy Forward-only, reads unprivileged.
  | CPYFERT = 216
  /// Memory Copy Forward-only, reads unpriv, reads and writes non-temporal.
  | CPYFERTN = 217
  /// Memory Copy Forward-only, reads unprivileged and non-temporal.
  | CPYFERTRN = 218
  /// Memory Copy Forward-only, reads unprivileged, writes non-temporal.
  | CPYFERTWN = 219
  /// Memory Copy Forward-only, reads and writes unprivileged.
  | CPYFET = 220
  /// Memory Copy Forward-only, reads and writes unprivileged and non-temporal.
  | CPYFETN = 221
  /// Memory Copy Forward-only, reads and writes unpriv, reads non-temporal.
  | CPYFETRN = 222
  /// Memory Copy Forward-only, reads and writes unpriv, writes non-temporal.
  | CPYFETWN = 223
  /// Memory Copy Forward-only, writes non-temporal.
  | CPYFEWN = 224
  /// Memory Copy Forward-only, writes unprivileged.
  | CPYFEWT = 225
  /// Memory Copy Forward-only, writes unpriv, reads and writes non-temporal.
  | CPYFEWTN = 226
  /// Memory Copy Forward-only, writes unprivileged, reads non-temporal.
  | CPYFEWTRN = 227
  /// Memory Copy Forward-only, writes unprivileged and non-temporal.
  | CPYFEWTWN = 228
  /// Memory Copy Forward-only.
  | CPYFM = 229
  /// Memory Copy Forward-only, reads and writes non-temporal.
  | CPYFMN = 230
  /// Memory Copy Forward-only, reads non-temporal.
  | CPYFMRN = 231
  /// Memory Copy Forward-only, reads unprivileged.
  | CPYFMRT = 232
  /// Memory Copy Forward-only, reads unpriv, reads and writes non-temporal.
  | CPYFMRTN = 233
  /// Memory Copy Forward-only, reads unprivileged and non-temporal.
  | CPYFMRTRN = 234
  /// Memory Copy Forward-only, reads unprivileged, writes non-temporal.
  | CPYFMRTWN = 235
  /// Memory Copy Forward-only, reads and writes unprivileged.
  | CPYFMT = 236
  /// Memory Copy Forward-only, reads and writes unprivileged and non-temporal.
  | CPYFMTN = 237
  /// Memory Copy Forward-only, reads and writes unpriv, reads non-temporal.
  | CPYFMTRN = 238
  /// Memory Copy Forward-only, reads and writes unpriv, writes non-temporal.
  | CPYFMTWN = 239
  /// Memory Copy Forward-only, writes non-temporal.
  | CPYFMWN = 240
  /// Memory Copy Forward-only, writes unprivileged.
  | CPYFMWT = 241
  /// Memory Copy Forward-only, writes unpriv, reads and writes non-temporal.
  | CPYFMWTN = 242
  /// Memory Copy Forward-only, writes unprivileged, reads non-temporal.
  | CPYFMWTRN = 243
  /// Memory Copy Forward-only, writes unprivileged and non-temporal.
  | CPYFMWTWN = 244
  /// Memory Copy Forward-only.
  | CPYFP = 245
  /// Memory Copy Forward-only, reads and writes non-temporal.
  | CPYFPN = 246
  /// Memory Copy Forward-only, reads non-temporal.
  | CPYFPRN = 247
  /// Memory Copy Forward-only, reads unprivileged.
  | CPYFPRT = 248
  /// Memory Copy Forward-only, reads unpriv, reads and writes non-temporal.
  | CPYFPRTN = 249
  /// Memory Copy Forward-only, reads unprivileged and non-temporal.
  | CPYFPRTRN = 250
  /// Memory Copy Forward-only, reads unprivileged, writes non-temporal.
  | CPYFPRTWN = 251
  /// Memory Copy Forward-only, reads and writes unprivileged.
  | CPYFPT = 252
  /// Memory Copy Forward-only, reads and writes unprivileged and non-temporal.
  | CPYFPTN = 253
  /// Memory Copy Forward-only, reads and writes unpriv, reads non-temporal.
  | CPYFPTRN = 254
  /// Memory Copy Forward-only, reads and writes unpriv, writes non-temporal.
  | CPYFPTWN = 255
  /// Memory Copy Forward-only, writes non-temporal.
  | CPYFPWN = 256
  /// Memory Copy Forward-only, writes unprivileged.
  | CPYFPWT = 257
  /// Memory Copy Forward-only, writes unpriv, reads and writes non-temporal.
  | CPYFPWTN = 258
  /// Memory Copy Forward-only, writes unprivileged, reads non-temporal.
  | CPYFPWTRN = 259
  /// Memory Copy Forward-only, writes unprivileged and non-temporal.
  | CPYFPWTWN = 260
  /// Memory Copy.
  | CPYM = 261
  /// Memory Copy, reads and writes non-temporal.
  | CPYMN = 262
  /// Memory Copy, reads non-temporal.
  | CPYMRN = 263
  /// Memory Copy, reads unprivileged.
  | CPYMRT = 264
  /// Memory Copy, reads unprivileged, reads and writes non-temporal.
  | CPYMRTN = 265
  /// Memory Copy, reads unprivileged and non-temporal.
  | CPYMRTRN = 266
  /// Memory Copy, reads unprivileged, writes non-temporal.
  | CPYMRTWN = 267
  /// Memory Copy, reads and writes unprivileged.
  | CPYMT = 268
  /// Memory Copy, reads and writes unprivileged and non-temporal.
  | CPYMTN = 269
  /// Memory Copy, reads and writes unprivileged, reads non-temporal.
  | CPYMTRN = 270
  /// Memory Copy, reads and writes unprivileged, writes non-temporal.
  | CPYMTWN = 271
  /// Memory Copy, writes non-temporal.
  | CPYMWN = 272
  /// Memory Copy, writes unprivileged.
  | CPYMWT = 273
  /// Memory Copy, writes unprivileged, reads and writes non-temporal.
  | CPYMWTN = 274
  /// Memory Copy, writes unprivileged, reads non-temporal.
  | CPYMWTRN = 275
  /// Memory Copy, writes unprivileged and non-temporal.
  | CPYMWTWN = 276
  /// Memory Copy.
  | CPYP = 277
  /// Memory Copy, reads and writes non-temporal.
  | CPYPN = 278
  /// Memory Copy, reads non-temporal.
  | CPYPRN = 279
  /// Memory Copy, reads unprivileged.
  | CPYPRT = 280
  /// Memory Copy, reads unprivileged, reads and writes non-temporal.
  | CPYPRTN = 281
  /// Memory Copy, reads unprivileged and non-temporal.
  | CPYPRTRN = 282
  /// Memory Copy, reads unprivileged, writes non-temporal.
  | CPYPRTWN = 283
  /// Memory Copy, reads and writes unprivileged.
  | CPYPT = 284
  /// Memory Copy, reads and writes unprivileged and non-temporal.
  | CPYPTN = 285
  /// Memory Copy, reads and writes unprivileged, reads non-temporal.
  | CPYPTRN = 286
  /// Memory Copy, reads and writes unprivileged, writes non-temporal.
  | CPYPTWN = 287
  /// Memory Copy, writes non-temporal.
  | CPYPWN = 288
  /// Memory Copy, writes unprivileged.
  | CPYPWT = 289
  /// Memory Copy, writes unprivileged, reads and writes non-temporal.
  | CPYPWTN = 290
  /// Memory Copy, writes unprivileged, reads non-temporal.
  | CPYPWTRN = 291
  /// Memory Copy, writes unprivileged and non-temporal.
  | CPYPWTWN = 292
  /// CRC32 checksum.
  | CRC32B = 293
  /// CRC32C checksum.
  | CRC32CB = 294
  /// CRC32C checksum.
  | CRC32CH = 295
  /// CRC32C checksum.
  | CRC32CW = 296
  /// CRC32C checksum.
  | CRC32CX = 297
  /// CRC32 checksum.
  | CRC32H = 298
  /// CRC32 checksum.
  | CRC32W = 299
  /// CRC32 checksum.
  | CRC32X = 300
  /// Consumption of Speculative Data Barrier.
  | CSDB = 301
  /// Conditional Select.
  | CSEL = 302
  /// Conditional Set: an alias of CSINC.
  | CSET = 303
  /// Conditional Set Mask: an alias of CSINV.
  | CSETM = 304
  /// Conditional Select Increment.
  | CSINC = 305
  /// Conditional Select Invert.
  | CSINV = 306
  /// Conditional Select Negation.
  | CSNEG = 307
  /// Compare and terminate loop.
  | CTERMEQ = 308
  /// Compare and terminate loop.
  | CTERMNE = 309
  /// Count Trailing Zeros.
  | CTZ = 310
  /// Data Cache operation: an alias of SYS.
  | DC = 311
  /// Clean of Data and Allocation Tags by Set/Way.
  | DCCGDSW = 312
  /// Clean of Data and Allocation Tags by VA to PoC.
  | DCCGDVAC = 313
  /// Clean of Data and Allocation Tags by VA to PoDP.
  | DCCGDVADP = 314
  /// Clean of Data and Allocation Tags by VA to PoP.
  | DCCGDVAP = 315
  /// Clean of Allocation Tags by Set/Way.
  | DCCGSW = 316
  /// Clean of Allocation Tags by VA to PoC.
  | DCCGVAC = 317
  /// Clean of Allocation Tags by VA to PoDP.
  | DCCGVADP = 318
  /// Clean of Allocation Tags by VA to PoP.
  | DCCGVAP = 319
  /// Clean and Invalidate of Data and Allocation Tags by Set/Way.
  | DCCIGDSW = 320
  /// Clean and Invalidate of Data and Allocation Tags by VA to PoC.
  | DCCIGDVAC = 321
  /// Clean and Invalidate of Allocation Tags by Set/Way.
  | DCCIGSW = 322
  /// Clean and Invalidate of Allocation Tags by VA to PoC.
  | DCCIGVAC = 323
  /// Data or unified Cache line Clean and Invalidate by Set/Way.
  | DCCISW = 324
  /// Data or unified Cache line Clean and Invalidate by VA to PoC.
  | DCCIVAC = 325
  /// Data or unified Cache line Clean by Set/Way.
  | DCCSW = 326
  /// Data or unified Cache line Clean by VA to PoC.
  | DCCVAC = 327
  /// Data or unified Cache line Clean by VA to PoDP.
  | DCCVADP = 328
  /// Data or unified Cache line Clean by VA to PoP.
  | DCCVAP = 329
  /// Data or unified Cache line Clean by VA to PoU.
  | DCCVAU = 330
  /// Data Cache set Allocation Tag by VA.
  | DCGVA = 331
  /// Data Cache set Allocation Tags and Zero by VA.
  | DCGZVA = 332
  /// Invalidate of Data and Allocation Tags by Set/Way.
  | DCIGDSW = 333
  /// Invalidate of Data and Allocation Tags by VA to PoC.
  | DCIGDVAC = 334
  /// Invalidate of Allocation Tags by Set/Way.
  | DCIGSW = 335
  /// Invalidate of Allocation Tags by VA to PoC.
  | DCIGVAC = 336
  /// Data or unified Cache line Invalidate by Set/Way.
  | DCISW = 337
  /// Data or unified Cache line Invalidate by VA to PoC.
  | DCIVAC = 338
  /// Debug switch to Exception level 1.
  | DCPS1 = 339
  /// Debug switch to Exception level 2.
  | DCPS2 = 340
  /// Debug switch to Exception level 3.
  | DCPS3 = 341
  /// Data Cache Zero by VA.
  | DCZVA = 342
  /// Decrement scalar by multiple of predicate constraint element count.
  | DECB = 343
  /// Decrement scalar by multiple of predicate constraint element count.
  | DECD = 344
  /// Decrement scalar by multiple of predicate constraint element count.
  | DECH = 345
  /// Decrement scalar by count of true predicate elements.
  | DECP = 346
  /// Decrement scalar by multiple of predicate constraint element count.
  | DECW = 347
  /// Data Gathering Hint.
  | DGH = 348
  /// Data Memory Barrier.
  | DMB = 349
  /// Debug restore process state.
  | DRPS = 350
  /// Data Synchronization Barrier.
  | DSB = 351
  /// Duplicate vector element to vector or scalar.
  | DUP = 352
  /// Broadcast logical bitmask immediate to vector (unpredicated).
  | DUPM = 353
  /// Broadcast indexed element within each qword vector segment (unpred).
  | DUPQ = 354
  /// Data Value Prediction Restriction by Context: an alias of SYS.
  | DVP = 355
  /// Bitwise exclusive OR with inverted immediate (unpredicated).
  | EON = 356
  /// Bitwise Exclusive OR (immediate).
  | EOR = 357
  /// Three-way Exclusive OR.
  | EOR3 = 358
  /// Interleaving exclusive OR (bottom, top).
  | EORBT = 359
  /// Bitwise exclusive OR reduction of quadword vector segments.
  | EORQV = 360
  /// Bitwise exclusive OR predicates, setting the condition flags.
  | EORS = 361
  /// Interleaving exclusive OR (top, bottom).
  | EORTB = 362
  /// Bitwise exclusive OR reduction to scalar.
  | EORV = 363
  /// Exception Return.
  | ERET = 364
  /// Exception Return, with pointer authentication.
  | ERETAA = 365
  /// Exception Return, with pointer authentication.
  | ERETAB = 366
  /// Error Synchronization Barrier.
  | ESB = 367
  /// Extract vector from pair of vectors.
  | EXT = 368
  /// Extract vector segment from each pair of quadword vector segments.
  | EXTQ = 369
  /// Extract register.
  | EXTR = 370
  /// FP Absolute Difference (vector).
  | FABD = 371
  /// FP absolute value (predicated).
  | FABS = 372
  /// FP absolute compare vectors.
  | FAC = 373
  /// FP Absolute Compare Greater than or Equal (vector).
  | FACGE = 374
  /// FP Absolute Compare Greater than (vector).
  | FACGT = 375
  /// FP absolute compare less than or equal: an alias of FAC<cc>.
  | FACLE = 376
  /// FP absolute compare less than: an alias of FAC<cc>.
  | FACLT = 377
  /// FP add multi-vector to ZA array vector accumulators.
  | FADD = 378
  /// FP add strictly-ordered reduction, accumulating in scalar.
  | FADDA = 379
  /// FP add pairwise.
  | FADDP = 380
  /// FP add recursive reduction of quadword vector segments.
  | FADDQV = 381
  /// FP add recursive reduction to scalar.
  | FADDV = 382
  /// FP Complex Add.
  | FCADD = 383
  /// FP Conditional quiet Compare (scalar).
  | FCCMP = 384
  /// FP Conditional signaling Compare (scalar).
  | FCCMPE = 385
  /// FP clamp to minimum/maximum number.
  | FCLAMP = 386
  /// FP compare vectors.
  | FCM = 387
  /// FP Compare Equal (vector).
  | FCMEQ = 388
  /// FP Compare Greater than or Equal (vector).
  | FCMGE = 389
  /// FP Compare Greater than (vector).
  | FCMGT = 390
  /// FP Complex Multiply Accumulate.
  | FCMLA = 391
  /// FP compare less than or equal to vector: an alias of FCM<cc> (vectors).
  | FCMLE = 392
  /// FP compare less than vector: an alias of FCM<cc> (vectors).
  | FCMLT = 393
  /// FP quiet Compare (scalar).
  | FCMP = 394
  /// FP signaling Compare (scalar).
  | FCMPE = 395
  /// Copy 8-bit FP immediate to vector elements (predicated).
  | FCPY = 396
  /// FP Conditional Select (scalar).
  | FCSEL = 397
  /// FP Convert precision (scalar).
  | FCVT = 398
  /// FP Convert to Signed int, rounding to nearest with ties to Away (scalar).
  | FCVTAS = 399
  /// FP Conv to Unsigned int, rounding to nearest with ties to Away (scalar).
  | FCVTAU = 400
  /// FP Convert to higher precision Long (vector).
  | FCVTL = 401
  /// FP Convert to higher precision Long (vector).
  | FCVTL2 = 402
  /// FP up convert long (top, predicated).
  | FCVTLT = 403
  /// FP Convert to Signed integer, rounding toward Minus infinity (scalar).
  | FCVTMS = 404
  /// FP Convert to Unsigned integer, rounding toward Minus infinity (scalar).
  | FCVTMU = 405
  /// FP Convert to lower precision Narrow (vector).
  | FCVTN = 406
  /// FP Convert to lower precision Narrow (vector).
  | FCVTN2 = 407
  /// FP Convert to Signed int, rounding to nearest with ties to even (scalar).
  | FCVTNS = 408
  /// FP down convert and narrow (top, predicated).
  | FCVTNT = 409
  /// FP Conv to Unsigned int, rounding to nearest with ties to even (scalar).
  | FCVTNU = 410
  /// FP Convert to Signed integer, rounding toward Plus infinity (scalar).
  | FCVTPS = 411
  /// FP Convert to Unsigned integer, rounding toward Plus infinity (scalar).
  | FCVTPU = 412
  /// FP down convert, rounding to odd (predicated).
  | FCVTX = 413
  /// FP Convert to lower precision Narrow, rounding to odd (vector).
  | FCVTXN = 414
  /// FP Convert to lower precision Narrow, rounding to odd (vector).
  | FCVTXN2 = 415
  /// FP down convert, rounding to odd (top, predicated).
  | FCVTXNT = 416
  /// FP convert to signed integer, rounding toward zero (predicated).
  | FCVTZS = 417
  /// FP convert to unsigned integer, rounding toward zero (predicated).
  | FCVTZU = 418
  /// FP divide by vector (predicated).
  | FDIV = 419
  /// FP reversed divide by vector (predicated).
  | FDIVR = 420
  /// Half-precision FP indexed dot product.
  | FDOT = 421
  /// Broadcast 8-bit FP immediate to vector elements (unpredicated).
  | FDUP = 422
  /// FP exponential accelerator.
  | FEXPA = 423
  /// FP Javascript Convert to Signed fixed-point, rounding toward Zero.
  | FJCVTZS = 424
  /// FP base 2 logarithm as integer.
  | FLOGB = 425
  /// FP fused multiply-add vectors (predicated).
  | FMAD = 426
  /// FP fused Multiply-Add (scalar).
  | FMADD = 427
  /// FP maximum with immediate (predicated).
  | FMAX = 428
  /// FP maximum number with immediate (predicated).
  | FMAXNM = 429
  /// FP maximum number pairwise.
  | FMAXNMP = 430
  /// FP maximum number recursive reduction of quadword vector segments.
  | FMAXNMQV = 431
  /// FP Maximum Number across Vector.
  | FMAXNMV = 432
  /// FP maximum pairwise.
  | FMAXP = 433
  /// FP maximum reduction of quadword vector segments.
  | FMAXQV = 434
  /// FP Maximum across Vector.
  | FMAXV = 435
  /// FP minimum with immediate (predicated).
  | FMIN = 436
  /// FP minimum number with immediate (predicated).
  | FMINNM = 437
  /// FP minimum number pairwise.
  | FMINNMP = 438
  /// FP minimum number recursive reduction of quadword vector segments.
  | FMINNMQV = 439
  /// FP Minimum Number across Vector.
  | FMINNMV = 440
  /// FP minimum pairwise.
  | FMINP = 441
  /// FP minimum recursive reduction of quadword vector segments.
  | FMINQV = 442
  /// FP Minimum across Vector.
  | FMINV = 443
  /// FP fused Multiply-Add to accumulator (by element).
  | FMLA = 444
  /// FP fused Multiply-Add Long to accumulator (by element).
  | FMLAL = 445
  /// FP fused Multiply-Add Long to accumulator (by element).
  | FMLAL2 = 446
  /// Half-precision FP mul-add long to single-precision (bottom, indexed).
  | FMLALB = 447
  /// Half-precision FP multiply-add long to single-precision (top, indexed).
  | FMLALT = 448
  /// FP fused Multiply-Subtract from accumulator (by element).
  | FMLS = 449
  /// FP fused Multiply-Subtract Long from accumulator (by element).
  | FMLSL = 450
  /// FP fused Multiply-Subtract Long from accumulator (by element).
  | FMLSL2 = 451
  /// Half-precision FP mul-sub long from single-precision (bottom, indexed).
  | FMLSLB = 452
  /// Half-precision FP mul-sub long from single-precision (top, indexed).
  | FMLSLT = 453
  /// FP matrix multiply-accumulate.
  | FMMLA = 454
  /// FP outer product and accumulate.
  | FMOPA = 455
  /// FP outer product and subtract.
  | FMOPS = 456
  /// FP Move to or from general-purpose register without conversion.
  | FMOV = 457
  /// FP fused multiply-subtract vectors (predicated).
  | FMSB = 458
  /// FP Fused Multiply-Subtract (scalar).
  | FMSUB = 459
  /// FP Multiply (by element).
  | FMUL = 460
  /// FP Multiply extended.
  | FMULX = 461
  /// FP negate (predicated).
  | FNEG = 462
  /// FP negated fused multiply-add vectors (predicated).
  | FNMAD = 463
  /// FP Negated fused Multiply-Add (scalar).
  | FNMADD = 464
  /// FP negated fused multiply-add vectors (predicated).
  | FNMLA = 465
  /// FP negated fused multiply-subtract vectors (predicated).
  | FNMLS = 466
  /// FP negated fused multiply-subtract vectors (predicated).
  | FNMSB = 467
  /// FP Negated fused Multiply-Subtract (scalar).
  | FNMSUB = 468
  /// FP Multiply-Negate (scalar).
  | FNMUL = 469
  /// FP Reciprocal Estimate.
  | FRECPE = 470
  /// FP Reciprocal Step.
  | FRECPS = 471
  /// FP Reciprocal exponent (scalar).
  | FRECPX = 472
  /// FP round to integral value (predicated).
  | FRINT = 473
  /// FP Round to 32-bit Integer, using current rounding mode (scalar).
  | FRINT32X = 474
  /// FP Round to 32-bit Integer toward Zero (scalar).
  | FRINT32Z = 475
  /// FP Round to 64-bit Integer, using current rounding mode (scalar).
  | FRINT64X = 476
  /// FP Round to 64-bit Integer toward Zero (scalar).
  | FRINT64Z = 477
  /// Multi-vector FP round to int val, to nearest with ties away from zero.
  | FRINTA = 478
  /// FP Round to Integral, using current rounding mode (scalar).
  | FRINTI = 479
  /// Multi-vector FP round to integral value, toward minus Infinity.
  | FRINTM = 480
  /// Multi-vector FP round to integral value, to nearest with ties to even.
  | FRINTN = 481
  /// Multi-vector FP round to integral value, toward plus Infinity.
  | FRINTP = 482
  /// FP Round to Integral exact, using current rounding mode (scalar).
  | FRINTX = 483
  /// FP Round to Integral, toward Zero (scalar).
  | FRINTZ = 484
  /// FP Reciprocal Square Root Estimate.
  | FRSQRTE = 485
  /// FP Reciprocal Square Root Step.
  | FRSQRTS = 486
  /// FP adjust exponent by vector (predicated).
  | FSCALE = 487
  /// FP square root (predicated).
  | FSQRT = 488
  /// FP subtract multi-vector from ZA array vector accumulators.
  | FSUB = 489
  /// FP reversed subtract from immediate (predicated).
  | FSUBR = 490
  /// FP trigonometric multiply-add coefficient.
  | FTMAD = 491
  /// FP trigonometric starting value.
  | FTSMUL = 492
  /// FP trigonometric select coefficient.
  | FTSSEL = 493
  /// Multi-vector half-precision FP vertical dot-product by indexed element.
  | FVDOT = 494
  /// Tag Mask Insert.
  | GMI = 495
  /// Hint instruction.
  | HINT = 496
  /// Count matching elements in vector.
  | HISTCNT = 497
  /// Count matching elements in vector segments.
  | HISTSEG = 498
  /// Halt instruction.
  | HLT = 499
  /// Hypervisor Call.
  | HVC = 500
  /// Instruction Cache operation: an alias of SYS.
  | IC = 501
  /// Increment scalar by multiple of predicate constraint element count.
  | INCB = 502
  /// Increment scalar by multiple of predicate constraint element count.
  | INCD = 503
  /// Increment scalar by multiple of predicate constraint element count.
  | INCH = 504
  /// Increment scalar by count of true predicate elements.
  | INCP = 505
  /// Increment scalar by multiple of predicate constraint element count.
  | INCW = 506
  /// Create index starting from imm and incremented by general-purpose reg.
  | INDEX = 507
  /// Insert vector element from another vector element.
  | INS = 508
  /// Insert general-purpose register in shifted vector.
  | INSR = 509
  /// Insert Random Tag.
  | IRG = 510
  /// Instruction Synchronization Barrier.
  | ISB = 511
  /// Extract element after last to general-purpose register.
  | LASTA = 512
  /// Extract last element to general-purpose register.
  | LASTB = 513
  /// Load multiple single-element structures to one, two, three, or four regs.
  | LD1 = 514
  /// Contiguous load of bytes to mul consecutive vectors (immediate index).
  | LD1B = 515
  /// Contiguous load of dwords to mul consecutive vectors (immediate index).
  | LD1D = 516
  /// Contiguous load of hwords to mult consecutive vectors (immediate index).
  | LD1H = 517
  /// Gather load quadwords.
  | LD1Q = 518
  /// Load one single-element struct and Replicate to all lanes (of one reg).
  | LD1R = 519
  /// Load and broadcast unsigned byte to vector.
  | LD1RB = 520
  /// Load and broadcast doubleword to vector.
  | LD1RD = 521
  /// Load and broadcast unsigned halfword to vector.
  | LD1RH = 522
  /// Contiguous load and replicate thirty-two bytes (immediate index).
  | LD1ROB = 523
  /// Contiguous load and replicate four doublewords (immediate index).
  | LD1ROD = 524
  /// Contiguous load and replicate sixteen halfwords (immediate index).
  | LD1ROH = 525
  /// Contiguous load and replicate eight words (immediate index).
  | LD1ROW = 526
  /// Contiguous load and replicate sixteen bytes (immediate index).
  | LD1RQB = 527
  /// Contiguous load and replicate two doublewords (immediate index).
  | LD1RQD = 528
  /// Contiguous load and replicate eight halfwords (immediate index).
  | LD1RQH = 529
  /// Contiguous load and replicate four words (immediate index).
  | LD1RQW = 530
  /// Load and broadcast signed byte to vector.
  | LD1RSB = 531
  /// Load and broadcast signed halfword to vector.
  | LD1RSH = 532
  /// Load and broadcast signed word to vector.
  | LD1RSW = 533
  /// Load and broadcast unsigned word to vector.
  | LD1RW = 534
  /// Contiguous load signed bytes to vector (immediate index).
  | LD1SB = 535
  /// Contiguous load signed halfwords to vector (immediate index).
  | LD1SH = 536
  /// Contiguous load signed words to vector (immediate index).
  | LD1SW = 537
  /// Contiguous load of words to mul consecutive vectors (immediate index).
  | LD1W = 538
  /// Load multiple 2-element structures to two registers.
  | LD2 = 539
  /// Contiguous load two-byte structures to two vectors (immediate index).
  | LD2B = 540
  /// Contiguous load two-doubleword struct to two vectors (immediate index).
  | LD2D = 541
  /// Contiguous load two-halfword structures to two vectors (immediate index).
  | LD2H = 542
  /// Contiguous load two-quadword structures to two vectors (immediate index).
  | LD2Q = 543
  /// Load single 2-element struct and Replicate to all lanes of two registers.
  | LD2R = 544
  /// Contiguous load two-word structures to two vectors (immediate index).
  | LD2W = 545
  /// Load multiple 3-element structures to three registers.
  | LD3 = 546
  /// Contiguous load three-byte structures to three vectors (immediate index).
  | LD3B = 547
  /// Contiguous load three-dword structs to three vectors (immediate index).
  | LD3D = 548
  /// Contiguous load three-halfword structs to three vectors (immediate index).
  | LD3H = 549
  /// Contiguous load three-quadword structs to three vectors (immediate index).
  | LD3Q = 550
  /// Load single 3-element struct and Replicate to all lanes of three regs.
  | LD3R = 551
  /// Contiguous load three-word structures to three vectors (immediate index).
  | LD3W = 552
  /// Load multiple 4-element structures to four registers.
  | LD4 = 553
  /// Contiguous load four-byte structures to four vectors (immediate index).
  | LD4B = 554
  /// Contiguous load four-doubleword structs to four vectors (immediate index).
  | LD4D = 555
  /// Contiguous load four-halfword struct to four vectors (immediate index).
  | LD4H = 556
  /// Contiguous load four-quadword struct to four vectors (immediate index).
  | LD4Q = 557
  /// Load single 4-element struct and Replicate to all lanes of four regis.
  | LD4R = 558
  /// Contiguous load four-word structures to four vectors (immediate index).
  | LD4W = 559
  /// Single-copy Atomic 64-byte Load.
  | LD64B = 560
  /// Atomic add on word or doubleword in memory.
  | LDADD = 561
  /// Atomic add on word or doubleword in memory.
  | LDADDA = 562
  /// Atomic add on byte in memory.
  | LDADDAB = 563
  /// Atomic add on halfword in memory.
  | LDADDAH = 564
  /// Atomic add on word or doubleword in memory.
  | LDADDAL = 565
  /// Atomic add on byte in memory.
  | LDADDALB = 566
  /// Atomic add on halfword in memory.
  | LDADDALH = 567
  /// Atomic add on byte in memory.
  | LDADDB = 568
  /// Atomic add on halfword in memory.
  | LDADDH = 569
  /// Atomic add on word or doubleword in memory.
  | LDADDL = 570
  /// Atomic add on byte in memory.
  | LDADDLB = 571
  /// Atomic add on halfword in memory.
  | LDADDLH = 572
  /// Load-Acquire RCpc one single-element struct to one lane of one register.
  | LDAP1 = 573
  /// Load-Acquire RCpc Register.
  | LDAPR = 574
  /// Load-Acquire RCpc Register Byte.
  | LDAPRB = 575
  /// Load-Acquire RCpc Register Halfword.
  | LDAPRH = 576
  /// Load-Acquire RCpc Register (unscaled).
  | LDAPUR = 577
  /// Load-Acquire RCpc Register Byte (unscaled).
  | LDAPURB = 578
  /// Load-Acquire RCpc Register Halfword (unscaled).
  | LDAPURH = 579
  /// Load-Acquire RCpc Register Signed Byte (unscaled).
  | LDAPURSB = 580
  /// Load-Acquire RCpc Register Signed Halfword (unscaled).
  | LDAPURSH = 581
  /// Load-Acquire RCpc Register Signed Word (unscaled).
  | LDAPURSW = 582
  /// Load-Acquire Register.
  | LDAR = 583
  /// Load-Acquire Register Byte.
  | LDARB = 584
  /// Load-Acquire Register Halfword.
  | LDARH = 585
  /// Load-Acquire Exclusive Pair of Registers.
  | LDAXP = 586
  /// Load-Acquire Exclusive Register.
  | LDAXR = 587
  /// Load-Acquire Exclusive Register Byte.
  | LDAXRB = 588
  /// Load-Acquire Exclusive Register Halfword.
  | LDAXRH = 589
  /// Atomic bit clear on word or doubleword in memory.
  | LDCLR = 590
  /// Atomic bit clear on word or doubleword in memory.
  | LDCLRA = 591
  /// Atomic bit clear on byte in memory.
  | LDCLRAB = 592
  /// Atomic bit clear on halfword in memory.
  | LDCLRAH = 593
  /// Atomic bit clear on word or doubleword in memory.
  | LDCLRAL = 594
  /// Atomic bit clear on byte in memory.
  | LDCLRALB = 595
  /// Atomic bit clear on halfword in memory.
  | LDCLRALH = 596
  /// Atomic bit clear on byte in memory.
  | LDCLRB = 597
  /// Atomic bit clear on halfword in memory.
  | LDCLRH = 598
  /// Atomic bit clear on word or doubleword in memory.
  | LDCLRL = 599
  /// Atomic bit clear on byte in memory.
  | LDCLRLB = 600
  /// Atomic bit clear on halfword in memory.
  | LDCLRLH = 601
  /// Atomic bit clear on quadword in memory.
  | LDCLRP = 602
  /// Atomic bit clear on quadword in memory.
  | LDCLRPA = 603
  /// Atomic bit clear on quadword in memory.
  | LDCLRPAL = 604
  /// Atomic bit clear on quadword in memory.
  | LDCLRPL = 605
  /// Atomic exclusive OR on word or doubleword in memory.
  | LDEOR = 606
  /// Atomic exclusive OR on word or doubleword in memory.
  | LDEORA = 607
  /// Atomic exclusive OR on byte in memory.
  | LDEORAB = 608
  /// Atomic exclusive OR on halfword in memory.
  | LDEORAH = 609
  /// Atomic exclusive OR on word or doubleword in memory.
  | LDEORAL = 610
  /// Atomic exclusive OR on byte in memory.
  | LDEORALB = 611
  /// Atomic exclusive OR on halfword in memory.
  | LDEORALH = 612
  /// Atomic exclusive OR on byte in memory.
  | LDEORB = 613
  /// Atomic exclusive OR on halfword in memory.
  | LDEORH = 614
  /// Atomic exclusive OR on word or doubleword in memory.
  | LDEORL = 615
  /// Atomic exclusive OR on byte in memory.
  | LDEORLB = 616
  /// Atomic exclusive OR on halfword in memory.
  | LDEORLH = 617
  /// Contiguous load first-fault unsigned bytes to vector (scalar index).
  | LDFF1B = 618
  /// Contiguous load first-fault doublewords to vector (scalar index).
  | LDFF1D = 619
  /// Contiguous load first-fault unsigned halfwords to vector (scalar index).
  | LDFF1H = 620
  /// Contiguous load first-fault signed bytes to vector (scalar index).
  | LDFF1SB = 621
  /// Contiguous load first-fault signed halfwords to vector (scalar index).
  | LDFF1SH = 622
  /// Contiguous load first-fault signed words to vector (scalar index).
  | LDFF1SW = 623
  /// Contiguous load first-fault unsigned words to vector (scalar index).
  | LDFF1W = 624
  /// Load Allocation Tag.
  | LDG = 625
  /// Load Tag Multiple.
  | LDGM = 626
  /// Load-Acquire RCpc ordered Pair of registers.
  | LDIAPP = 627
  /// Load LOAcquire Register.
  | LDLAR = 628
  /// Load LOAcquire Register Byte.
  | LDLARB = 629
  /// Load LOAcquire Register Halfword.
  | LDLARH = 630
  /// Contiguous load non-fault unsigned bytes to vector.
  | LDNF1B = 631
  /// Contiguous load non-fault doublewords to vector.
  | LDNF1D = 632
  /// Contiguous load non-fault unsigned halfwords to vector.
  | LDNF1H = 633
  /// Contiguous load non-fault signed bytes to vector.
  | LDNF1SB = 634
  /// Contiguous load non-fault signed halfwords to vector.
  | LDNF1SH = 635
  /// Contiguous load non-fault signed words to vector.
  | LDNF1SW = 636
  /// Contiguous load non-fault unsigned words to vector.
  | LDNF1W = 637
  /// Load Pair of Registers, with non-temporal hint.
  | LDNP = 638
  /// Contiguous load non-temporal of bytes to multiple consecutive vectors.
  | LDNT1B = 639
  /// Contiguous load non-temporal of dwords to multiple consecutive vectors.
  | LDNT1D = 640
  /// Contiguous load non-temporal of hwords to multiple consecutive vectors.
  | LDNT1H = 641
  /// Gather load non-temporal signed bytes.
  | LDNT1SB = 642
  /// Gather load non-temporal signed halfwords.
  | LDNT1SH = 643
  /// Gather load non-temporal signed words.
  | LDNT1SW = 644
  /// Contiguous load non-temporal of words to multiple consecutive vectors.
  | LDNT1W = 645
  /// Load Pair of Registers.
  | LDP = 646
  /// Load Pair of Registers Signed Word.
  | LDPSW = 647
  /// Load Register (immediate).
  | LDR = 648
  /// Load Register, with pointer authentication.
  | LDRAA = 649
  /// Load Register, with pointer authentication.
  | LDRAB = 650
  /// Load Register Byte (immediate).
  | LDRB = 651
  /// Load Register Halfword (immediate).
  | LDRH = 652
  /// Load Register Signed Byte (immediate).
  | LDRSB = 653
  /// Load Register Signed Halfword (immediate).
  | LDRSH = 654
  /// Load Register Signed Word (immediate).
  | LDRSW = 655
  /// Atomic bit set on word or doubleword in memory.
  | LDSET = 656
  /// Atomic bit set on word or doubleword in memory.
  | LDSETA = 657
  /// Atomic bit set on byte in memory.
  | LDSETAB = 658
  /// Atomic bit set on halfword in memory.
  | LDSETAH = 659
  /// Atomic bit set on word or doubleword in memory.
  | LDSETAL = 660
  /// Atomic bit set on byte in memory.
  | LDSETALB = 661
  /// Atomic bit set on halfword in memory.
  | LDSETALH = 662
  /// Atomic bit set on byte in memory.
  | LDSETB = 663
  /// Atomic bit set on halfword in memory.
  | LDSETH = 664
  /// Atomic bit set on word or doubleword in memory.
  | LDSETL = 665
  /// Atomic bit set on byte in memory.
  | LDSETLB = 666
  /// Atomic bit set on halfword in memory.
  | LDSETLH = 667
  /// Atomic bit set on quadword in memory.
  | LDSETP = 668
  /// Atomic bit set on quadword in memory.
  | LDSETPA = 669
  /// Atomic bit set on quadword in memory.
  | LDSETPAL = 670
  /// Atomic bit set on quadword in memory.
  | LDSETPL = 671
  /// Atomic signed maximum on word or doubleword in memory.
  | LDSMAX = 672
  /// Atomic signed maximum on word or doubleword in memory.
  | LDSMAXA = 673
  /// Atomic signed maximum on byte in memory.
  | LDSMAXAB = 674
  /// Atomic signed maximum on halfword in memory.
  | LDSMAXAH = 675
  /// Atomic signed maximum on word or doubleword in memory.
  | LDSMAXAL = 676
  /// Atomic signed maximum on byte in memory.
  | LDSMAXALB = 677
  /// Atomic signed maximum on halfword in memory.
  | LDSMAXALH = 678
  /// Atomic signed maximum on byte in memory.
  | LDSMAXB = 679
  /// Atomic signed maximum on halfword in memory.
  | LDSMAXH = 680
  /// Atomic signed maximum on word or doubleword in memory.
  | LDSMAXL = 681
  /// Atomic signed maximum on byte in memory.
  | LDSMAXLB = 682
  /// Atomic signed maximum on halfword in memory.
  | LDSMAXLH = 683
  /// Atomic signed minimum on word or doubleword in memory.
  | LDSMIN = 684
  /// Atomic signed minimum on word or doubleword in memory.
  | LDSMINA = 685
  /// Atomic signed minimum on byte in memory.
  | LDSMINAB = 686
  /// Atomic signed minimum on halfword in memory.
  | LDSMINAH = 687
  /// Atomic signed minimum on word or doubleword in memory.
  | LDSMINAL = 688
  /// Atomic signed minimum on byte in memory.
  | LDSMINALB = 689
  /// Atomic signed minimum on halfword in memory.
  | LDSMINALH = 690
  /// Atomic signed minimum on byte in memory.
  | LDSMINB = 691
  /// Atomic signed minimum on halfword in memory.
  | LDSMINH = 692
  /// Atomic signed minimum on word or doubleword in memory.
  | LDSMINL = 693
  /// Atomic signed minimum on byte in memory.
  | LDSMINLB = 694
  /// Atomic signed minimum on halfword in memory.
  | LDSMINLH = 695
  /// Load Register (unprivileged).
  | LDTR = 696
  /// Load Register Byte (unprivileged).
  | LDTRB = 697
  /// Load Register Halfword (unprivileged).
  | LDTRH = 698
  /// Load Register Signed Byte (unprivileged).
  | LDTRSB = 699
  /// Load Register Signed Halfword (unprivileged).
  | LDTRSH = 700
  /// Load Register Signed Word (unprivileged).
  | LDTRSW = 701
  /// Atomic unsigned maximum on word or doubleword in memory.
  | LDUMAX = 702
  /// Atomic unsigned maximum on word or doubleword in memory.
  | LDUMAXA = 703
  /// Atomic unsigned maximum on byte in memory.
  | LDUMAXAB = 704
  /// Atomic unsigned maximum on halfword in memory.
  | LDUMAXAH = 705
  /// Atomic unsigned maximum on word or doubleword in memory.
  | LDUMAXAL = 706
  /// Atomic unsigned maximum on byte in memory.
  | LDUMAXALB = 707
  /// Atomic unsigned maximum on halfword in memory.
  | LDUMAXALH = 708
  /// Atomic unsigned maximum on byte in memory.
  | LDUMAXB = 709
  /// Atomic unsigned maximum on halfword in memory.
  | LDUMAXH = 710
  /// Atomic unsigned maximum on word or doubleword in memory.
  | LDUMAXL = 711
  /// Atomic unsigned maximum on byte in memory.
  | LDUMAXLB = 712
  /// Atomic unsigned maximum on halfword in memory.
  | LDUMAXLH = 713
  /// Atomic unsigned minimum on word or doubleword in memory.
  | LDUMIN = 714
  /// Atomic unsigned minimum on word or doubleword in memory.
  | LDUMINA = 715
  /// Atomic unsigned minimum on byte in memory.
  | LDUMINAB = 716
  /// Atomic unsigned minimum on halfword in memory.
  | LDUMINAH = 717
  /// Atomic unsigned minimum on word or doubleword in memory.
  | LDUMINAL = 718
  /// Atomic unsigned minimum on byte in memory.
  | LDUMINALB = 719
  /// Atomic unsigned minimum on halfword in memory.
  | LDUMINALH = 720
  /// Atomic unsigned minimum on byte in memory.
  | LDUMINB = 721
  /// Atomic unsigned minimum on halfword in memory.
  | LDUMINH = 722
  /// Atomic unsigned minimum on word or doubleword in memory.
  | LDUMINL = 723
  /// Atomic unsigned minimum on byte in memory.
  | LDUMINLB = 724
  /// Atomic unsigned minimum on halfword in memory.
  | LDUMINLH = 725
  /// Load Register (unscaled).
  | LDUR = 726
  /// Load Register Byte (unscaled).
  | LDURB = 727
  /// Load Register Halfword (unscaled).
  | LDURH = 728
  /// Load Register Signed Byte (unscaled).
  | LDURSB = 729
  /// Load Register Signed Halfword (unscaled).
  | LDURSH = 730
  /// Load Register Signed Word (unscaled).
  | LDURSW = 731
  /// Load Exclusive Pair of Registers.
  | LDXP = 732
  /// Load Exclusive Register.
  | LDXR = 733
  /// Load Exclusive Register Byte.
  | LDXRB = 734
  /// Load Exclusive Register Halfword.
  | LDXRH = 735
  /// Logical Shift Left (immediate): an alias of UBFM.
  | LSL = 736
  /// Reversed logical shift left by vector (predicated).
  | LSLR = 737
  /// Logical Shift Left Variable.
  | LSLV = 738
  /// Logical Shift Right (immediate): an alias of UBFM.
  | LSR = 739
  /// Reversed logical shift right by vector (predicated).
  | LSRR = 740
  /// Logical Shift Right Variable.
  | LSRV = 741
  /// Lookup table read with 2-bit indexes.
  | LUTI2 = 742
  /// Lookup table read with 4-bit indexes.
  | LUTI4 = 743
  /// Multiply-add vectors (predicated).
  | MAD = 744
  /// Multiply-Add.
  | MADD = 745
  /// Detect any matching elements, setting the condition flags.
  | MATCH = 746
  /// Multiply-Add to accumulator (vector, by element).
  | MLA = 747
  /// Multiply-Subtract from accumulator (vector, by element).
  | MLS = 748
  /// Multiply-Negate: an alias of MSUB.
  | MNEG = 749
  /// Move logical bitmask immediate to vector (unpredicated): an alias of DUPM.
  | MOV = 750
  /// Move four ZA single-vector groups to four vector registers.
  | MOVA = 751
  /// Move and zero four ZA single-vector groups to vector registers.
  | MOVAZ = 752
  /// Move Immediate (vector).
  | MOVI = 753
  /// Move wide with keep.
  | MOVK = 754
  /// Move wide with NOT.
  | MOVN = 755
  /// Move prefix (predicated).
  | MOVPRFX = 756
  /// Move predicates (zeroing), setting the condition flags: an alias of ANDS.
  | MOVS = 757
  /// Move 8 bytes from general-purpose register to ZT0.
  | MOVT = 758
  /// Move wide with zero.
  | MOVZ = 759
  /// Move System Register to two adjacent general-purpose registers.
  | MRRS = 760
  /// Move System Register to general-purpose register.
  | MRS = 761
  /// Multiply-subtract vectors (predicated).
  | MSB = 762
  /// Move immediate value to Special Register.
  | MSR = 763
  /// Move two adjacent general-purpose registers to System Register.
  | MSRR = 764
  /// Multiply-Subtract.
  | MSUB = 765
  /// Multiply: an alias of MADD.
  | MUL = 766
  /// Bitwise NOT: an alias of ORN (shifted register).
  | MVN = 767
  /// Move inverted Immediate (vector).
  | MVNI = 768
  /// Bitwise NAND predicates.
  | NAND = 769
  /// Bitwise NAND predicates, setting the condition flags.
  | NANDS = 770
  /// Bitwise inverted select.
  | NBSL = 771
  /// Negate (predicated).
  | NEG = 772
  /// Negate, setting flags: an alias of SUBS (shifted register).
  | NEGS = 773
  /// Negate with Carry: an alias of SBC.
  | NGC = 774
  /// Negate with Carry, setting flags: an alias of SBCS.
  | NGCS = 775
  /// Detect no matching elements, setting the condition flags.
  | NMATCH = 776
  /// No Operation.
  | NOP = 777
  /// Bitwise NOR predicates.
  | NOR = 778
  /// Bitwise NOR predicates, setting the condition flags.
  | NORS = 779
  /// Bitwise NOT (vector).
  | NOT = 780
  /// Bitwise invert predicate, setting the condition flags: an alias of EORS.
  | NOTS = 781
  /// Bitwise inclusive OR with inverted immediate (unpredicated).
  | ORN = 782
  /// Bitwise inclusive OR inverted predicate, setting the condition flags.
  | ORNS = 783
  /// Bitwise inclusive OR reduction of quadword vector segments.
  | ORQV = 784
  /// Bitwise OR (immediate).
  | ORR = 785
  /// Bitwise inclusive OR predicates, setting the condition flags.
  | ORRS = 786
  /// Bitwise inclusive OR reduction to scalar.
  | ORV = 787
  /// Pointer Authentication Code for Data address, using key A.
  | PACDA = 788
  /// Pointer Authentication Code for Data address, using key B.
  | PACDB = 789
  /// Pointer Authentication Code for Data address, using key A.
  | PACDZA = 790
  /// Pointer Authentication Code for Data address, using key B.
  | PACDZB = 791
  /// Pointer Authentication Code, using Generic key.
  | PACGA = 792
  /// Pointer Authentication Code for Instruction address, using key A.
  | PACIA = 793
  /// Pointer Authentication Code for Instruction address, using key A.
  | PACIA1716 = 794
  /// Pointer Authentication Code for Instruction address, using key A.
  | PACIASP = 795
  /// Pointer Authentication Code for Instruction address, using key A.
  | PACIAZ = 796
  /// Pointer Authentication Code for Instruction address, using key B.
  | PACIB = 797
  /// Pointer Authentication Code for Instruction address, using key B.
  | PACIB1716 = 798
  /// Pointer Authentication Code for Instruction address, using key B.
  | PACIBSP = 799
  /// Pointer Authentication Code for Instruction address, using key B.
  | PACIBZ = 800
  /// Pointer Authentication Code for Instruction address, using key A.
  | PACIZA = 801
  /// Pointer Authentication Code for Instruction address, using key B.
  | PACIZB = 802
  /// Set pair of predicates from predicate-as-counter.
  | PEXT = 803
  /// Set all predicate elements to false.
  | PFALSE = 804
  /// Set the first active predicate element to true.
  | PFIRST = 805
  /// Move predicate from vector.
  | PMOV = 806
  /// Polynomial Multiply.
  | PMUL = 807
  /// Polynomial Multiply Long.
  | PMULL = 808
  /// Polynomial Multiply Long.
  | PMULL2 = 809
  /// Polynomial multiply long (bottom).
  | PMULLB = 810
  /// Polynomial multiply long (top).
  | PMULLT = 811
  /// Find next active predicate.
  | PNEXT = 812
  /// Contiguous prefetch bytes (immediate index).
  | PRFB = 813
  /// Contiguous prefetch doublewords (immediate index).
  | PRFD = 814
  /// Contiguous prefetch halfwords (immediate index).
  | PRFH = 815
  /// Prefetch Memory (immediate).
  | PRFM = 816
  /// Prefetch Memory (unscaled offset).
  | PRFUM = 817
  /// Contiguous prefetch words (immediate index).
  | PRFW = 818
  /// Profiling Synchronization Barrier.
  | PSB = 819
  /// Predicate select between predicate register or all-false.
  | PSEL = 820
  /// Physical Speculative Store Bypass Barrier: an alias of DSB.
  | PSSBB = 821
  /// Set condition flags for predicate.
  | PTEST = 822
  /// Initialise predicate-as-counter to all active.
  | PTRUE = 823
  /// Initialise predicate from named constraint and set the condition flags.
  | PTRUES = 824
  /// Unpack and widen half of predicate.
  | PUNPKHI = 825
  /// Unpack and widen half of predicate.
  | PUNPKLO = 826
  /// Rounding Add returning High Narrow.
  | RADDHN = 827
  /// Rounding Add returning High Narrow.
  | RADDHN2 = 828
  /// Rounding add narrow high part (bottom).
  | RADDHNB = 829
  /// Rounding add narrow high part (top).
  | RADDHNT = 830
  /// Rotate and Exclusive OR.
  | RAX1 = 831
  /// Reverse Bits.
  | RBIT = 832
  /// Read Check Write Compare and Swap doubleword in memory.
  | RCWCAS = 833
  /// Read Check Write Compare and Swap doubleword in memory.
  | RCWCASA = 834
  /// Read Check Write Compare and Swap doubleword in memory.
  | RCWCASAL = 835
  /// Read Check Write Compare and Swap doubleword in memory.
  | RCWCASL = 836
  /// Read Check Write Compare and Swap quadword in memory.
  | RCWCASP = 837
  /// Read Check Write Compare and Swap quadword in memory.
  | RCWCASPA = 838
  /// Read Check Write Compare and Swap quadword in memory.
  | RCWCASPAL = 839
  /// Read Check Write Compare and Swap quadword in memory.
  | RCWCASPL = 840
  /// Read Check Write atomic bit Clear on doubleword in memory.
  | RCWCLR = 841
  /// Read Check Write atomic bit Clear on doubleword in memory.
  | RCWCLRA = 842
  /// Read Check Write atomic bit Clear on doubleword in memory.
  | RCWCLRAL = 843
  /// Read Check Write atomic bit Clear on doubleword in memory.
  | RCWCLRL = 844
  /// Read Check Write atomic bit Clear on quadword in memory.
  | RCWCLRP = 845
  /// Read Check Write atomic bit Clear on quadword in memory.
  | RCWCLRPA = 846
  /// Read Check Write atomic bit Clear on quadword in memory.
  | RCWCLRPAL = 847
  /// Read Check Write atomic bit Clear on quadword in memory.
  | RCWCLRPL = 848
  /// Read Check Write Software Compare and Swap doubleword in memory.
  | RCWSCAS = 849
  /// Read Check Write Software Compare and Swap doubleword in memory.
  | RCWSCASA = 850
  /// Read Check Write Software Compare and Swap doubleword in memory.
  | RCWSCASAL = 851
  /// Read Check Write Software Compare and Swap doubleword in memory.
  | RCWSCASL = 852
  /// Read Check Write Software Compare and Swap quadword in memory.
  | RCWSCASP = 853
  /// Read Check Write Software Compare and Swap quadword in memory.
  | RCWSCASPA = 854
  /// Read Check Write Software Compare and Swap quadword in memory.
  | RCWSCASPAL = 855
  /// Read Check Write Software Compare and Swap quadword in memory.
  | RCWSCASPL = 856
  /// Read Check Write Software atomic bit Clear on doubleword in memory.
  | RCWSCLR = 857
  /// Read Check Write Software atomic bit Clear on doubleword in memory.
  | RCWSCLRA = 858
  /// Read Check Write Software atomic bit Clear on doubleword in memory.
  | RCWSCLRAL = 859
  /// Read Check Write Software atomic bit Clear on doubleword in memory.
  | RCWSCLRL = 860
  /// Read Check Write Software atomic bit Clear on quadword in memory.
  | RCWSCLRP = 861
  /// Read Check Write Software atomic bit Clear on quadword in memory.
  | RCWSCLRPA = 862
  /// Read Check Write Software atomic bit Clear on quadword in memory.
  | RCWSCLRPAL = 863
  /// Read Check Write Software atomic bit Clear on quadword in memory.
  | RCWSCLRPL = 864
  /// Read Check Write atomic bit Set on doubleword in memory.
  | RCWSET = 865
  /// Read Check Write atomic bit Set on doubleword in memory.
  | RCWSETA = 866
  /// Read Check Write atomic bit Set on doubleword in memory.
  | RCWSETAL = 867
  /// Read Check Write atomic bit Set on doubleword in memory.
  | RCWSETL = 868
  /// Read Check Write atomic bit Set on quadword in memory.
  | RCWSETP = 869
  /// Read Check Write atomic bit Set on quadword in memory.
  | RCWSETPA = 870
  /// Read Check Write atomic bit Set on quadword in memory.
  | RCWSETPAL = 871
  /// Read Check Write atomic bit Set on quadword in memory.
  | RCWSETPL = 872
  /// Read Check Write Software atomic bit Set on doubleword in memory.
  | RCWSSET = 873
  /// Read Check Write Software atomic bit Set on doubleword in memory.
  | RCWSSETA = 874
  /// Read Check Write Software atomic bit Set on doubleword in memory.
  | RCWSSETAL = 875
  /// Read Check Write Software atomic bit Set on doubleword in memory.
  | RCWSSETL = 876
  /// Read Check Write Software atomic bit Set on quadword in memory.
  | RCWSSETP = 877
  /// Read Check Write Software atomic bit Set on quadword in memory.
  | RCWSSETPA = 878
  /// Read Check Write Software atomic bit Set on quadword in memory.
  | RCWSSETPAL = 879
  /// Read Check Write Software atomic bit Set on quadword in memory.
  | RCWSSETPL = 880
  /// Read Check Write Software Swap doubleword in memory.
  | RCWSSWP = 881
  /// Read Check Write Software Swap doubleword in memory.
  | RCWSSWPA = 882
  /// Read Check Write Software Swap doubleword in memory.
  | RCWSSWPAL = 883
  /// Read Check Write Software Swap doubleword in memory.
  | RCWSSWPL = 884
  /// Read Check Write Software Swap quadword in memory.
  | RCWSSWPP = 885
  /// Read Check Write Software Swap quadword in memory.
  | RCWSSWPPA = 886
  /// Read Check Write Software Swap quadword in memory.
  | RCWSSWPPAL = 887
  /// Read Check Write Software Swap quadword in memory.
  | RCWSSWPPL = 888
  /// Read Check Write Swap doubleword in memory.
  | RCWSWP = 889
  /// Read Check Write Swap doubleword in memory.
  | RCWSWPA = 890
  /// Read Check Write Swap doubleword in memory.
  | RCWSWPAL = 891
  /// Read Check Write Swap doubleword in memory.
  | RCWSWPL = 892
  /// Read Check Write Swap quadword in memory.
  | RCWSWPP = 893
  /// Read Check Write Swap quadword in memory.
  | RCWSWPPA = 894
  /// Read Check Write Swap quadword in memory.
  | RCWSWPPAL = 895
  /// Read Check Write Swap quadword in memory.
  | RCWSWPPL = 896
  /// Return predicate of succesfully loaded elements.
  | RDFFR = 897
  /// Return predicate of succesfully loaded elements, setting the cond flags.
  | RDFFRS = 898
  /// Read multiple of Streaming SVE vector register size to scalar register.
  | RDSVL = 899
  /// Read multiple of vector register size to scalar register.
  | RDVL = 900
  /// Return from subroutine.
  | RET = 901
  /// Return from subroutine, with pointer authentication.
  | RETAA = 902
  /// Return from subroutine, with pointer authentication.
  | RETAB = 903
  /// Reverse Bytes.
  | REV = 904
  /// Reverse bytes in 16-bit halfwords.
  | REV16 = 905
  /// Reverse bytes in 32-bit words.
  | REV32 = 906
  /// Reverse Bytes: an alias of REV.
  | REV64 = 907
  /// Reverse bytes / halfwords / words within elements (predicated).
  | REVB = 908
  /// Reverse 64-bit doublewords in elements (predicated).
  | REVD = 909
  /// Reverse bytes / halfwords / words within elements (predicated).
  | REVH = 910
  /// Reverse bytes / halfwords / words within elements (predicated).
  | REVW = 911
  /// Rotate, Mask Insert Flags.
  | RMIF = 912
  /// Rotate right (immediate): an alias of EXTR.
  | ROR = 913
  /// Rotate Right Variable.
  | RORV = 914
  /// Range Prefetch Memory.
  | RPRFM = 915
  /// Rounding Shift Right Narrow (immediate).
  | RSHRN = 916
  /// Rounding Shift Right Narrow (immediate).
  | RSHRN2 = 917
  /// Rounding shift right narrow by immediate (bottom).
  | RSHRNB = 918
  /// Rounding shift right narrow by immediate (top).
  | RSHRNT = 919
  /// Rounding Subtract returning High Narrow.
  | RSUBHN = 920
  /// Rounding Subtract returning High Narrow.
  | RSUBHN2 = 921
  /// Rounding subtract narrow high part (bottom).
  | RSUBHNB = 922
  /// Rounding subtract narrow high part (top).
  | RSUBHNT = 923
  /// Signed Absolute difference and Accumulate.
  | SABA = 924
  /// Signed Absolute difference and Accumulate Long.
  | SABAL = 925
  /// Signed Absolute difference and Accumulate Long.
  | SABAL2 = 926
  /// Signed absolute difference and accumulate long (bottom).
  | SABALB = 927
  /// Signed absolute difference and accumulate long (top).
  | SABALT = 928
  /// Signed Absolute Difference.
  | SABD = 929
  /// Signed Absolute Difference Long.
  | SABDL = 930
  /// Signed Absolute Difference Long.
  | SABDL2 = 931
  /// Signed absolute difference long (bottom).
  | SABDLB = 932
  /// Signed absolute difference long (top).
  | SABDLT = 933
  /// Signed Add and Accumulate Long Pairwise.
  | SADALP = 934
  /// Signed Add Long (vector).
  | SADDL = 935
  /// Signed Add Long (vector).
  | SADDL2 = 936
  /// Signed add long (bottom).
  | SADDLB = 937
  /// Signed add long (bottom + top).
  | SADDLBT = 938
  /// Signed Add Long Pairwise.
  | SADDLP = 939
  /// Signed add long (top).
  | SADDLT = 940
  /// Signed Add Long across Vector.
  | SADDLV = 941
  /// Signed add reduction to scalar.
  | SADDV = 942
  /// Signed Add Wide.
  | SADDW = 943
  /// Signed Add Wide.
  | SADDW2 = 944
  /// Signed add wide (bottom).
  | SADDWB = 945
  /// Signed add wide (top).
  | SADDWT = 946
  /// Speculation Barrier.
  | SB = 947
  /// Subtract with Carry.
  | SBC = 948
  /// Subtract with carry long (bottom).
  | SBCLB = 949
  /// Subtract with carry long (top).
  | SBCLT = 950
  /// Subtract with Carry, setting flags.
  | SBCS = 951
  /// Signed Bitfield Insert in Zero: an alias of SBFM.
  | SBFIZ = 952
  /// Signed Bitfield Move.
  | SBFM = 953
  /// Signed Bitfield Extract: an alias of SBFM.
  | SBFX = 954
  /// Signed clamp to minimum/maximum vector.
  | SCLAMP = 955
  /// Signed integer convert to FP (predicated).
  | SCVTF = 956
  /// Signed Divide.
  | SDIV = 957
  /// Signed reversed divide (predicated).
  | SDIVR = 958
  /// Signed integer indexed dot product.
  | SDOT = 959
  /// Multi-vector conditionally select elements from two vectors.
  | SEL = 960
  /// Memory Set.
  | SETE = 961
  /// Memory Set, non-temporal.
  | SETEN = 962
  /// Memory Set, unprivileged.
  | SETET = 963
  /// Memory Set, unprivileged and non-temporal.
  | SETETN = 964
  /// Evaluation of 8 or 16 bit flag values.
  | SETF16 = 965
  /// Evaluation of 8 or 16 bit flag values.
  | SETF8 = 966
  /// Initialise the first-fault register to all true.
  | SETFFR = 967
  /// Memory Set with tag setting.
  | SETGE = 968
  /// Memory Set with tag setting, non-temporal.
  | SETGEN = 969
  /// Memory Set with tag setting, unprivileged.
  | SETGET = 970
  /// Memory Set with tag setting, unprivileged and non-temporal.
  | SETGETN = 971
  /// Memory Set with tag setting.
  | SETGM = 972
  /// Memory Set with tag setting, non-temporal.
  | SETGMN = 973
  /// Memory Set with tag setting, unprivileged.
  | SETGMT = 974
  /// Memory Set with tag setting, unprivileged and non-temporal.
  | SETGMTN = 975
  /// Memory Set with tag setting.
  | SETGP = 976
  /// Memory Set with tag setting, non-temporal.
  | SETGPN = 977
  /// Memory Set with tag setting, unprivileged.
  | SETGPT = 978
  /// Memory Set with tag setting, unprivileged and non-temporal.
  | SETGPTN = 979
  /// Memory Set.
  | SETM = 980
  /// Memory Set, non-temporal.
  | SETMN = 981
  /// Memory Set, unprivileged.
  | SETMT = 982
  /// Memory Set, unprivileged and non-temporal.
  | SETMTN = 983
  /// Memory Set.
  | SETP = 984
  /// Memory Set, non-temporal.
  | SETPN = 985
  /// Memory Set, unprivileged.
  | SETPT = 986
  /// Memory Set, unprivileged and non-temporal.
  | SETPTN = 987
  /// Send Event.
  | SEV = 988
  /// Send Event Local.
  | SEVL = 989
  /// SHA1 hash update (choose).
  | SHA1C = 990
  /// SHA1 fixed rotate.
  | SHA1H = 991
  /// SHA1 hash update (majority).
  | SHA1M = 992
  /// SHA1 hash update (parity).
  | SHA1P = 993
  /// SHA1 schedule update 0.
  | SHA1SU0 = 994
  /// SHA1 schedule update 1.
  | SHA1SU1 = 995
  /// SHA256 hash update (part 1).
  | SHA256H = 996
  /// SHA256 hash update (part 2).
  | SHA256H2 = 997
  /// SHA256 schedule update 0.
  | SHA256SU0 = 998
  /// SHA256 schedule update 1.
  | SHA256SU1 = 999
  /// SHA512 Hash update part 1.
  | SHA512H = 1000
  /// SHA512 Hash update part 2.
  | SHA512H2 = 1001
  /// SHA512 Schedule Update 0.
  | SHA512SU0 = 1002
  /// SHA512 Schedule Update 1.
  | SHA512SU1 = 1003
  /// Signed Halving Add.
  | SHADD = 1004
  /// Shift Left (immediate).
  | SHL = 1005
  /// Shift Left Long (by element size).
  | SHLL = 1006
  /// Shift Left Long (by element size).
  | SHLL2 = 1007
  /// Shift Right Narrow (immediate).
  | SHRN = 1008
  /// Shift Right Narrow (immediate).
  | SHRN2 = 1009
  /// Shift right narrow by immediate (bottom).
  | SHRNB = 1010
  /// Shift right narrow by immediate (top).
  | SHRNT = 1011
  /// Signed Halving Subtract.
  | SHSUB = 1012
  /// Signed halving subtract reversed vectors.
  | SHSUBR = 1013
  /// Shift Left and Insert (immediate).
  | SLI = 1014
  /// SM3PARTW1.
  | SM3PARTW1 = 1015
  /// SM3PARTW2.
  | SM3PARTW2 = 1016
  /// SM3SS1.
  | SM3SS1 = 1017
  /// SM3TT1A.
  | SM3TT1A = 1018
  /// SM3TT1B.
  | SM3TT1B = 1019
  /// SM3TT2A.
  | SM3TT2A = 1020
  /// SM3TT2B.
  | SM3TT2B = 1021
  /// SM4 Encode.
  | SM4E = 1022
  /// SM4 Key.
  | SM4EKEY = 1023
  /// Signed Multiply-Add Long.
  | SMADDL = 1024
  /// Signed Maximum (vector).
  | SMAX = 1025
  /// Signed Maximum Pairwise.
  | SMAXP = 1026
  /// Signed maximum reduction of quadword vector segments.
  | SMAXQV = 1027
  /// Signed Maximum across Vector.
  | SMAXV = 1028
  /// Secure Monitor Call.
  | SMC = 1029
  /// Signed Minimum (vector).
  | SMIN = 1030
  /// Signed Minimum Pairwise.
  | SMINP = 1031
  /// Signed minimum reduction of quadword vector segments.
  | SMINQV = 1032
  /// Signed Minimum across Vector.
  | SMINV = 1033
  /// Signed Multiply-Add Long (vector, by element).
  | SMLAL = 1034
  /// Signed Multiply-Add Long (vector, by element).
  | SMLAL2 = 1035
  /// Signed multiply-add long to accumulator (bottom, indexed).
  | SMLALB = 1036
  /// Multi-vector signed integer multiply-add long long by indexed element.
  | SMLALL = 1037
  /// Signed multiply-add long to accumulator (top, indexed).
  | SMLALT = 1038
  /// Signed Multiply-Subtract Long (vector, by element).
  | SMLSL = 1039
  /// Signed Multiply-Subtract Long (vector, by element).
  | SMLSL2 = 1040
  /// Signed multiply-subtract long from accumulator (bottom, indexed).
  | SMLSLB = 1041
  /// Multi-vector signed integer multiply-subtract long long by indexed elem.
  | SMLSLL = 1042
  /// Signed multiply-subtract long from accumulator (top, indexed).
  | SMLSLT = 1043
  /// Signed integer matrix multiply-accumulate.
  | SMMLA = 1044
  /// Signed Multiply-Negate Long: an alias of SMSUBL.
  | SMNEGL = 1045
  /// Signed integer sum of outer products and accumulate.
  | SMOPA = 1046
  /// Signed integer sum of outer products and subtract.
  | SMOPS = 1047
  /// Signed Move vector element to general-purpose register.
  | SMOV = 1048
  /// Enables access to Streaming SVE mode and SME architectural state.
  | SMSTART = 1049
  /// Disables access to Streaming SVE mode and SME architectural state.
  | SMSTOP = 1050
  /// Signed Multiply-Subtract Long.
  | SMSUBL = 1051
  /// Signed Multiply High.
  | SMULH = 1052
  /// Signed Multiply Long: an alias of SMADDL.
  | SMULL = 1053
  /// Signed Multiply Long (vector, by element).
  | SMULL2 = 1054
  /// Signed multiply long (bottom, indexed).
  | SMULLB = 1055
  /// Signed multiply long (top, indexed).
  | SMULLT = 1056
  /// Splice two vectors under predicate control.
  | SPLICE = 1057
  /// Signed saturating Absolute value.
  | SQABS = 1058
  /// Signed saturating Add.
  | SQADD = 1059
  /// Saturating complex integer add with rotate.
  | SQCADD = 1060
  /// Multi-vector signed saturating extract narrow.
  | SQCVT = 1061
  /// Signed saturating extract narrow and interleave.
  | SQCVTN = 1062
  /// Multi-vector signed saturating unsigned extract narrow.
  | SQCVTU = 1063
  /// Signed saturating unsigned extract narrow and interleave.
  | SQCVTUN = 1064
  /// Signed saturating decr scalar by mul of 8-bit pred constraint elem count.
  | SQDECB = 1065
  /// Signed saturating decr scalar by mul of 64-bit pred constraint elem count.
  | SQDECD = 1066
  /// Signed saturating decr scalar by mul of 16-bit pred constraint elem count.
  | SQDECH = 1067
  /// Signed saturating decr scalar by count of true predicate elements.
  | SQDECP = 1068
  /// Signed saturating decr scalar by mul of 32-bit pred constraint elem count.
  | SQDECW = 1069
  /// Signed saturating Doubling Multiply-Add Long (by element).
  | SQDMLAL = 1070
  /// Signed saturating Doubling Multiply-Add Long (by element).
  | SQDMLAL2 = 1071
  /// Signed saturating doubling mul-add long to accumulator (bottom, indexed).
  | SQDMLALB = 1072
  /// Signed saturating doubling mul-add long to accumulator (bottom �� top).
  | SQDMLALBT = 1073
  /// Signed saturating doubling mul-add long to accumulator (top, indexed).
  | SQDMLALT = 1074
  /// Signed saturating Doubling Multiply-Subtract Long (by element).
  | SQDMLSL = 1075
  /// Signed saturating Doubling Multiply-Subtract Long (by element).
  | SQDMLSL2 = 1076
  /// Signed saturating doubling multiply-subtract long from accumulator.
  | SQDMLSLB = 1077
  /// Signed saturating doubling multiply-subtract long from accumulator.
  | SQDMLSLBT = 1078
  /// Signed saturating doubling multiply-subtract long from accumulator.
  | SQDMLSLT = 1079
  /// Signed saturating Doubling Multiply returning High half (by element).
  | SQDMULH = 1080
  /// Signed saturating Doubling Multiply Long (by element).
  | SQDMULL = 1081
  /// Signed saturating Doubling Multiply Long (by element).
  | SQDMULL2 = 1082
  /// Signed saturating doubling multiply long (bottom, indexed).
  | SQDMULLB = 1083
  /// Signed saturating doubling multiply long (top, indexed).
  | SQDMULLT = 1084
  /// Signed saturating incr scalar by mul of 8-bit pred constraint elem count.
  | SQINCB = 1085
  /// Signed saturating incr scalar by mul of 64-bit pred constraint elem count.
  | SQINCD = 1086
  /// Signed saturating incr scalar by mul of 16-bit pred constraint elem count.
  | SQINCH = 1087
  /// Signed saturating incr scalar by count of true predicate elements.
  | SQINCP = 1088
  /// Signed saturating incr scalar by mul of 32-bit pred constraint elem count.
  | SQINCW = 1089
  /// Signed saturating Negate.
  | SQNEG = 1090
  /// Saturating rounding doubling complex int multiply-add high with rotate.
  | SQRDCMLAH = 1091
  /// Signed Saturating Rounding Doubling Mul Accumulate returning High Half.
  | SQRDMLAH = 1092
  /// Signed Saturating Rounding Doubling Mul Subtract returning High Half.
  | SQRDMLSH = 1093
  /// Signed saturating Rounding Doubling Multiply returning High half.
  | SQRDMULH = 1094
  /// Signed saturating Rounding Shift Left (register).
  | SQRSHL = 1095
  /// Signed saturating rounding shift left reversed vectors (predicated).
  | SQRSHLR = 1096
  /// Multi-vector signed saturating rounding shift right narrow by immediate.
  | SQRSHR = 1097
  /// Signed saturating Rounded Shift Right Narrow (immediate).
  | SQRSHRN = 1098
  /// Signed saturating Rounded Shift Right Narrow (immediate).
  | SQRSHRN2 = 1099
  /// Signed saturating rounding shift right narrow by immediate (bottom).
  | SQRSHRNB = 1100
  /// Signed saturating rounding shift right narrow by immediate (top).
  | SQRSHRNT = 1101
  /// Multi-vector signed saturating rounding shf right unsigned narrow by imm.
  | SQRSHRU = 1102
  /// Signed saturating Rounded Shift Right Unsigned Narrow (immediate).
  | SQRSHRUN = 1103
  /// Signed saturating Rounded Shift Right Unsigned Narrow (immediate).
  | SQRSHRUN2 = 1104
  /// Signed saturating rounding shift right unsigned narrow by imm (bottom).
  | SQRSHRUNB = 1105
  /// Signed saturating rounding shift right unsigned narrow by immediate (top).
  | SQRSHRUNT = 1106
  /// Signed saturating Shift Left (immediate).
  | SQSHL = 1107
  /// Signed saturating shift left reversed vectors (predicated).
  | SQSHLR = 1108
  /// Signed saturating Shift Left Unsigned (immediate).
  | SQSHLU = 1109
  /// Signed saturating Shift Right Narrow (immediate).
  | SQSHRN = 1110
  /// Signed saturating Shift Right Narrow (immediate).
  | SQSHRN2 = 1111
  /// Signed saturating shift right narrow by immediate (bottom).
  | SQSHRNB = 1112
  /// Signed saturating shift right narrow by immediate (top).
  | SQSHRNT = 1113
  /// Signed saturating Shift Right Unsigned Narrow (immediate).
  | SQSHRUN = 1114
  /// Signed saturating Shift Right Unsigned Narrow (immediate).
  | SQSHRUN2 = 1115
  /// Signed saturating shift right unsigned narrow by immediate (bottom).
  | SQSHRUNB = 1116
  /// Signed saturating shift right unsigned narrow by immediate (top).
  | SQSHRUNT = 1117
  /// Signed saturating Subtract.
  | SQSUB = 1118
  /// Signed saturating subtraction reversed vectors (predicated).
  | SQSUBR = 1119
  /// Signed saturating extract Narrow.
  | SQXTN = 1120
  /// Signed saturating extract Narrow.
  | SQXTN2 = 1121
  /// Signed saturating extract narrow (bottom).
  | SQXTNB = 1122
  /// Signed saturating extract narrow (top).
  | SQXTNT = 1123
  /// Signed saturating extract Unsigned Narrow.
  | SQXTUN = 1124
  /// Signed saturating extract Unsigned Narrow.
  | SQXTUN2 = 1125
  /// Signed saturating unsigned extract narrow (bottom).
  | SQXTUNB = 1126
  /// Signed saturating unsigned extract narrow (top).
  | SQXTUNT = 1127
  /// Signed Rounding Halving Add.
  | SRHADD = 1128
  /// Shift Right and Insert (immediate).
  | SRI = 1129
  /// Signed Rounding Shift Left (register).
  | SRSHL = 1130
  /// Signed rounding shift left reversed vectors (predicated).
  | SRSHLR = 1131
  /// Signed Rounding Shift Right (immediate).
  | SRSHR = 1132
  /// Signed Rounding Shift Right and Accumulate (immediate).
  | SRSRA = 1133
  /// Speculative Store Bypass Barrier: an alias of DSB.
  | SSBB = 1134
  /// Signed Shift Left (register).
  | SSHL = 1135
  /// Signed Shift Left Long (immediate).
  | SSHLL = 1136
  /// Signed Shift Left Long (immediate).
  | SSHLL2 = 1137
  /// Signed shift left long by immediate (bottom).
  | SSHLLB = 1138
  /// Signed shift left long by immediate (top).
  | SSHLLT = 1139
  /// Signed Shift Right (immediate).
  | SSHR = 1140
  /// Signed Shift Right and Accumulate (immediate).
  | SSRA = 1141
  /// Signed Subtract Long.
  | SSUBL = 1142
  /// Signed Subtract Long.
  | SSUBL2 = 1143
  /// Signed subtract long (bottom).
  | SSUBLB = 1144
  /// Signed subtract long (bottom - top).
  | SSUBLBT = 1145
  /// Signed subtract long (top).
  | SSUBLT = 1146
  /// Signed subtract long (top - bottom).
  | SSUBLTB = 1147
  /// Signed Subtract Wide.
  | SSUBW = 1148
  /// Signed Subtract Wide.
  | SSUBW2 = 1149
  /// Signed subtract wide (bottom).
  | SSUBWB = 1150
  /// Signed subtract wide (top).
  | SSUBWT = 1151
  /// Store multiple single-element struct from one, two, three, or four regs.
  | ST1 = 1152
  /// Contiguous store of bytes from multiple consecutive vectors.
  | ST1B = 1153
  /// Contiguous store of doublewords from multiple consecutive vectors.
  | ST1D = 1154
  /// Contiguous store of halfwords from multiple consecutive vectors.
  | ST1H = 1155
  /// Scatter store quadwords.
  | ST1Q = 1156
  /// Contiguous store of words from multiple consecutive vectors.
  | ST1W = 1157
  /// Store multiple 2-element structures from two registers.
  | ST2 = 1158
  /// Contiguous store two-byte structures from two vectors.
  | ST2B = 1159
  /// Contiguous store two-doubleword structures from two vectors.
  | ST2D = 1160
  /// Store Allocation Tags.
  | ST2G = 1161
  /// Contiguous store two-halfword structures from two vectors.
  | ST2H = 1162
  /// Contiguous store two-quadword structures from two vectors.
  | ST2Q = 1163
  /// Contiguous store two-word structures from two vectors.
  | ST2W = 1164
  /// Store multiple 3-element structures from three registers.
  | ST3 = 1165
  /// Contiguous store three-byte structures from three vectors.
  | ST3B = 1166
  /// Contiguous store three-doubleword structures from three vectors.
  | ST3D = 1167
  /// Contiguous store three-halfword structures from three vectors.
  | ST3H = 1168
  /// Contiguous store three-quadword structures from three vectors.
  | ST3Q = 1169
  /// Contiguous store three-word structures from three vectors.
  | ST3W = 1170
  /// Store multiple 4-element structures from four registers.
  | ST4 = 1171
  /// Contiguous store four-byte structures from four vectors.
  | ST4B = 1172
  /// Contiguous store four-doubleword structures from four vectors.
  | ST4D = 1173
  /// Contiguous store four-halfword structures from four vectors.
  | ST4H = 1174
  /// Contiguous store four-quadword structures from four vectors.
  | ST4Q = 1175
  /// Contiguous store four-word structures from four vectors.
  | ST4W = 1176
  /// Single-copy Atomic 64-byte Store without Return.
  | ST64B = 1177
  /// Single-copy Atomic 64-byte Store with Return.
  | ST64BV = 1178
  /// Single-copy Atomic 64-byte EL0 Store with Return.
  | ST64BV0 = 1179
  /// Atomic add on word or doubleword in memory, without return.
  | STADD = 1180
  /// Atomic add on byte in memory, without return.
  | STADDB = 1181
  /// Atomic add on halfword in memory, without return.
  | STADDH = 1182
  /// Atomic add on word or doubleword in memory, without return.
  | STADDL = 1183
  /// Atomic add on byte in memory, without return.
  | STADDLB = 1184
  /// Atomic add on halfword in memory, without return.
  | STADDLH = 1185
  /// Atomic bit clear on word or doubleword in memory, without return.
  | STCLR = 1186
  /// Atomic bit clear on byte in memory, without return.
  | STCLRB = 1187
  /// Atomic bit clear on halfword in memory, without return.
  | STCLRH = 1188
  /// Atomic bit clear on word or doubleword in memory, without return.
  | STCLRL = 1189
  /// Atomic bit clear on byte in memory, without return.
  | STCLRLB = 1190
  /// Atomic bit clear on halfword in memory, without return.
  | STCLRLH = 1191
  /// Atomic exclusive OR on word or doubleword in memory, without return.
  | STEOR = 1192
  /// Atomic exclusive OR on byte in memory, without return.
  | STEORB = 1193
  /// Atomic exclusive OR on halfword in memory, without return.
  | STEORH = 1194
  /// Atomic exclusive OR on word or doubleword in memory, without return.
  | STEORL = 1195
  /// Atomic exclusive OR on byte in memory, without return.
  | STEORLB = 1196
  /// Atomic exclusive OR on halfword in memory, without return.
  | STEORLH = 1197
  /// Store Allocation Tag.
  | STG = 1198
  /// Store Tag Multiple.
  | STGM = 1199
  /// Store Allocation Tag and Pair of registers.
  | STGP = 1200
  /// Store-Release ordered Pair of registers.
  | STILP = 1201
  /// Store-Release a single-element structure from one lane of one register.
  | STL1 = 1202
  /// Store LORelease Register.
  | STLLR = 1203
  /// Store LORelease Register Byte.
  | STLLRB = 1204
  /// Store LORelease Register Halfword.
  | STLLRH = 1205
  /// Store-Release Register.
  | STLR = 1206
  /// Store-Release Register Byte.
  | STLRB = 1207
  /// Store-Release Register Halfword.
  | STLRH = 1208
  /// Store-Release Register (unscaled).
  | STLUR = 1209
  /// Store-Release Register Byte (unscaled).
  | STLURB = 1210
  /// Store-Release Register Halfword (unscaled).
  | STLURH = 1211
  /// Store-Release Exclusive Pair of registers.
  | STLXP = 1212
  /// Store-Release Exclusive Register.
  | STLXR = 1213
  /// Store-Release Exclusive Register Byte.
  | STLXRB = 1214
  /// Store-Release Exclusive Register Halfword.
  | STLXRH = 1215
  /// Store Pair of Registers, with non-temporal hint.
  | STNP = 1216
  /// Contiguous store non-temporal of bytes from multiple consecutive vectors.
  | STNT1B = 1217
  /// Contiguous store non-temporal of doublewords from mul consecutive vectors.
  | STNT1D = 1218
  /// Contiguous store non-temporal of halfwords from mul consecutive vectors.
  | STNT1H = 1219
  /// Contiguous store non-temporal of words from multiple consecutive vectors.
  | STNT1W = 1220
  /// Store Pair of Registers.
  | STP = 1221
  /// Store Register (immediate).
  | STR = 1222
  /// Store Register Byte (immediate).
  | STRB = 1223
  /// Store Register Halfword (immediate).
  | STRH = 1224
  /// Atomic bit set on word or doubleword in memory, without return.
  | STSET = 1225
  /// Atomic bit set on byte in memory, without return.
  | STSETB = 1226
  /// Atomic bit set on halfword in memory, without return.
  | STSETH = 1227
  /// Atomic bit set on word or doubleword in memory, without return.
  | STSETL = 1228
  /// Atomic bit set on byte in memory, without return.
  | STSETLB = 1229
  /// Atomic bit set on halfword in memory, without return.
  | STSETLH = 1230
  /// Atomic signed maximum on word or doubleword in memory, without return.
  | STSMAX = 1231
  /// Atomic signed maximum on byte in memory, without return.
  | STSMAXB = 1232
  /// Atomic signed maximum on halfword in memory, without return.
  | STSMAXH = 1233
  /// Atomic signed maximum on word or doubleword in memory, without return.
  | STSMAXL = 1234
  /// Atomic signed maximum on byte in memory, without return.
  | STSMAXLB = 1235
  /// Atomic signed maximum on halfword in memory, without return.
  | STSMAXLH = 1236
  /// Atomic signed minimum on word or doubleword in memory, without return.
  | STSMIN = 1237
  /// Atomic signed minimum on byte in memory, without return.
  | STSMINB = 1238
  /// Atomic signed minimum on halfword in memory, without return.
  | STSMINH = 1239
  /// Atomic signed minimum on word or doubleword in memory, without return.
  | STSMINL = 1240
  /// Atomic signed minimum on byte in memory, without return.
  | STSMINLB = 1241
  /// Atomic signed minimum on halfword in memory, without return.
  | STSMINLH = 1242
  /// Store Register (unprivileged).
  | STTR = 1243
  /// Store Register Byte (unprivileged).
  | STTRB = 1244
  /// Store Register Halfword (unprivileged).
  | STTRH = 1245
  /// Atomic unsigned maximum on word or doubleword in memory, without return.
  | STUMAX = 1246
  /// Atomic unsigned maximum on byte in memory, without return.
  | STUMAXB = 1247
  /// Atomic unsigned maximum on halfword in memory, without return.
  | STUMAXH = 1248
  /// Atomic unsigned maximum on word or doubleword in memory, without return.
  | STUMAXL = 1249
  /// Atomic unsigned maximum on byte in memory, without return.
  | STUMAXLB = 1250
  /// Atomic unsigned maximum on halfword in memory, without return.
  | STUMAXLH = 1251
  /// Atomic unsigned minimum on word or doubleword in memory, without return.
  | STUMIN = 1252
  /// Atomic unsigned minimum on byte in memory, without return.
  | STUMINB = 1253
  /// Atomic unsigned minimum on halfword in memory, without return.
  | STUMINH = 1254
  /// Atomic unsigned minimum on word or doubleword in memory, without return.
  | STUMINL = 1255
  /// Atomic unsigned minimum on byte in memory, without return.
  | STUMINLB = 1256
  /// Atomic unsigned minimum on halfword in memory, without return.
  | STUMINLH = 1257
  /// Store Register (unscaled).
  | STUR = 1258
  /// Store Register Byte (unscaled).
  | STURB = 1259
  /// Store Register Halfword (unscaled).
  | STURH = 1260
  /// Store Exclusive Pair of registers.
  | STXP = 1261
  /// Store Exclusive Register.
  | STXR = 1262
  /// Store Exclusive Register Byte.
  | STXRB = 1263
  /// Store Exclusive Register Halfword.
  | STXRH = 1264
  /// Store Allocation Tags, Zeroing.
  | STZ2G = 1265
  /// Store Allocation Tag, Zeroing.
  | STZG = 1266
  /// Store Tag and Zero Multiple.
  | STZGM = 1267
  /// Subtract multi-vector from ZA array vector accumulators.
  | SUB = 1268
  /// Subtract with Tag.
  | SUBG = 1269
  /// Subtract returning High Narrow.
  | SUBHN = 1270
  /// Subtract returning High Narrow.
  | SUBHN2 = 1271
  /// Subtract narrow high part (bottom).
  | SUBHNB = 1272
  /// Subtract narrow high part (top).
  | SUBHNT = 1273
  /// Subtract Pointer.
  | SUBP = 1274
  /// Subtract Pointer, setting Flags.
  | SUBPS = 1275
  /// Reversed subtract from immediate (unpredicated).
  | SUBR = 1276
  /// Subtract (extended register), setting flags.
  | SUBS = 1277
  /// Signed by unsigned integer indexed dot product.
  | SUDOT = 1278
  /// Multi-vector signed by unsigned int mul-add long long by indexed element.
  | SUMLALL = 1279
  /// Signed by unsigned integer sum of outer products and accumulate.
  | SUMOPA = 1280
  /// Signed by unsigned integer sum of outer products and subtract.
  | SUMOPS = 1281
  /// Unpack and sign-extend multi-vector elements.
  | SUNPK = 1282
  /// Signed unpack and extend half of vector.
  | SUNPKHI = 1283
  /// Signed unpack and extend half of vector.
  | SUNPKLO = 1284
  /// Signed saturating Accumulate of Unsigned value.
  | SUQADD = 1285
  /// Multi-vector signed by unsigned int vertical dot-product by indexed elem.
  | SUVDOT = 1286
  /// Supervisor Call.
  | SVC = 1287
  /// Multi-vector signed integer vertical dot-product by indexed element.
  | SVDOT = 1288
  /// Swap word or doubleword in memory.
  | SWP = 1289
  /// Swap word or doubleword in memory.
  | SWPA = 1290
  /// Swap byte in memory.
  | SWPAB = 1291
  /// Swap halfword in memory.
  | SWPAH = 1292
  /// Swap word or doubleword in memory.
  | SWPAL = 1293
  /// Swap byte in memory.
  | SWPALB = 1294
  /// Swap halfword in memory.
  | SWPALH = 1295
  /// Swap byte in memory.
  | SWPB = 1296
  /// Swap halfword in memory.
  | SWPH = 1297
  /// Swap word or doubleword in memory.
  | SWPL = 1298
  /// Swap byte in memory.
  | SWPLB = 1299
  /// Swap halfword in memory.
  | SWPLH = 1300
  /// Swap quadword in memory.
  | SWPP = 1301
  /// Swap quadword in memory.
  | SWPPA = 1302
  /// Swap quadword in memory.
  | SWPPAL = 1303
  /// Swap quadword in memory.
  | SWPPL = 1304
  /// Signed Extend Byte: an alias of SBFM.
  | SXTB = 1305
  /// Sign Extend Halfword: an alias of SBFM.
  | SXTH = 1306
  /// Signed extend Long: an alias of SSHLL, SSHLL2.
  | SXTL = 1307
  /// Signed extend Long: an alias of SSHLL, SSHLL2.
  | SXTL2 = 1308
  /// Sign Extend Word: an alias of SBFM.
  | SXTW = 1309
  /// System instruction.
  | SYS = 1310
  /// System instruction with result.
  | SYSL = 1311
  /// 128-bit System instruction.
  | SYSP = 1312
  /// Table vector Lookup.
  | TBL = 1313
  /// Programmable table lookup within each quadword vector segment (zeroing).
  | TBLQ = 1314
  /// Test bit and Branch if Nonzero.
  | TBNZ = 1315
  /// Table vector lookup extension.
  | TBX = 1316
  /// Programmable table lookup within each quadword vector segment (merging).
  | TBXQ = 1317
  /// Test bit and Branch if Zero.
  | TBZ = 1318
  /// Cancel current transaction.
  | TCANCEL = 1319
  /// Commit current transaction.
  | TCOMMIT = 1320
  /// TLB Invalidate operation: an alias of SYS.
  | TLBI = 1321
  /// TLB Invalidate Pair operation: an alias of SYSP.
  | TLBIP = 1322
  /// Trace Instrumentation: an alias of SYS.
  | TRCIT = 1323
  /// Transpose vectors (primary).
  | TRN1 = 1324
  /// Transpose vectors (secondary).
  | TRN2 = 1325
  /// Trace Synchronization Barrier.
  | TSB = 1326
  /// Test bits (immediate): an alias of ANDS (immediate).
  | TST = 1327
  /// Start transaction.
  | TSTART = 1328
  /// Test transaction state.
  | TTEST = 1329
  /// Unsigned Absolute difference and Accumulate.
  | UABA = 1330
  /// Unsigned Absolute difference and Accumulate Long.
  | UABAL = 1331
  /// Unsigned Absolute difference and Accumulate Long.
  | UABAL2 = 1332
  /// Unsigned absolute difference and accumulate long (bottom).
  | UABALB = 1333
  /// Unsigned absolute difference and accumulate long (top).
  | UABALT = 1334
  /// Unsigned Absolute Difference (vector).
  | UABD = 1335
  /// Unsigned Absolute Difference Long.
  | UABDL = 1336
  /// Unsigned Absolute Difference Long.
  | UABDL2 = 1337
  /// Unsigned absolute difference long (bottom).
  | UABDLB = 1338
  /// Unsigned absolute difference long (top).
  | UABDLT = 1339
  /// Unsigned Add and Accumulate Long Pairwise.
  | UADALP = 1340
  /// Unsigned Add Long (vector).
  | UADDL = 1341
  /// Unsigned Add Long (vector).
  | UADDL2 = 1342
  /// Unsigned add long (bottom).
  | UADDLB = 1343
  /// Unsigned Add Long Pairwise.
  | UADDLP = 1344
  /// Unsigned add long (top).
  | UADDLT = 1345
  /// Unsigned sum Long across Vector.
  | UADDLV = 1346
  /// Unsigned add reduction to scalar.
  | UADDV = 1347
  /// Unsigned Add Wide.
  | UADDW = 1348
  /// Unsigned Add Wide.
  | UADDW2 = 1349
  /// Unsigned add wide (bottom).
  | UADDWB = 1350
  /// Unsigned add wide (top).
  | UADDWT = 1351
  /// Unsigned Bitfield Insert in Zero: an alias of UBFM.
  | UBFIZ = 1352
  /// Unsigned Bitfield Move.
  | UBFM = 1353
  /// Unsigned Bitfield Extract: an alias of UBFM.
  | UBFX = 1354
  /// Unsigned clamp to minimum/maximum vector.
  | UCLAMP = 1355
  /// Unsigned integer convert to FP (predicated).
  | UCVTF = 1356
  /// Permanently Undefined.
  | UDF = 1357
  /// Unsigned Divide.
  | UDIV = 1358
  /// Unsigned reversed divide (predicated).
  | UDIVR = 1359
  /// Unsigned integer indexed dot product.
  | UDOT = 1360
  /// Unsigned Halving Add.
  | UHADD = 1361
  /// Unsigned Halving Subtract.
  | UHSUB = 1362
  /// Unsigned halving subtract reversed vectors.
  | UHSUBR = 1363
  /// Unsigned Multiply-Add Long.
  | UMADDL = 1364
  /// Unsigned Maximum (vector).
  | UMAX = 1365
  /// Unsigned Maximum Pairwise.
  | UMAXP = 1366
  /// Unsigned maximum reduction of quadword vector segments.
  | UMAXQV = 1367
  /// Unsigned Maximum across Vector.
  | UMAXV = 1368
  /// Unsigned Minimum (vector).
  | UMIN = 1369
  /// Unsigned Minimum Pairwise.
  | UMINP = 1370
  /// Unsigned minimum reduction of quadword vector segments.
  | UMINQV = 1371
  /// Unsigned Minimum across Vector.
  | UMINV = 1372
  /// Unsigned Multiply-Add Long (vector, by element).
  | UMLAL = 1373
  /// Unsigned Multiply-Add Long (vector, by element).
  | UMLAL2 = 1374
  /// Unsigned multiply-add long to accumulator (bottom, indexed).
  | UMLALB = 1375
  /// Multi-vector unsigned integer multiply-add long long by indexed element.
  | UMLALL = 1376
  /// Unsigned multiply-add long to accumulator (top, indexed).
  | UMLALT = 1377
  /// Unsigned Multiply-Subtract Long (vector, by element).
  | UMLSL = 1378
  /// Unsigned Multiply-Subtract Long (vector, by element).
  | UMLSL2 = 1379
  /// Unsigned multiply-subtract long from accumulator (bottom, indexed).
  | UMLSLB = 1380
  /// Multi-vector unsigned int multiply-subtract long long by indexed element.
  | UMLSLL = 1381
  /// Unsigned multiply-subtract long from accumulator (top, indexed).
  | UMLSLT = 1382
  /// Unsigned integer matrix multiply-accumulate.
  | UMMLA = 1383
  /// Unsigned Multiply-Negate Long: an alias of UMSUBL.
  | UMNEGL = 1384
  /// Unsigned integer sum of outer products and accumulate.
  | UMOPA = 1385
  /// Unsigned integer sum of outer products and subtract.
  | UMOPS = 1386
  /// Unsigned Move vector element to general-purpose register.
  | UMOV = 1387
  /// Unsigned Multiply-Subtract Long.
  | UMSUBL = 1388
  /// Unsigned Multiply High.
  | UMULH = 1389
  /// Unsigned Multiply Long: an alias of UMADDL.
  | UMULL = 1390
  /// Unsigned Multiply Long (vector, by element).
  | UMULL2 = 1391
  /// Unsigned multiply long (bottom, indexed).
  | UMULLB = 1392
  /// Unsigned multiply long (top, indexed).
  | UMULLT = 1393
  /// Unsigned saturating Add.
  | UQADD = 1394
  /// Multi-vector unsigned saturating extract narrow.
  | UQCVT = 1395
  /// Unsigned saturating extract narrow and interleave.
  | UQCVTN = 1396
  /// Unsigned saturating decr scalar by mul of 8-bit pred constraint elem cnt.
  | UQDECB = 1397
  /// Unsigned saturating decr scalar by mul of 64-bit pred constraint elem cnt.
  | UQDECD = 1398
  /// Unsigned saturating decr scalar by mul of 16-bit pred constraint elem cnt.
  | UQDECH = 1399
  /// Unsigned saturating decrement scalar by count of true predicate elements.
  | UQDECP = 1400
  /// Unsigned saturating decr scalar by mul of 32-bit pred constraint elem cnt.
  | UQDECW = 1401
  /// Unsigned saturating incr scalar by mul of 8-bit pred constraint elem cnt.
  | UQINCB = 1402
  /// Unsigned saturating incr scalar by mul of 64-bit pred constraint elem cnt.
  | UQINCD = 1403
  /// Unsigned saturating incr scalar by mul of 16-bit pred constraint elem cnt.
  | UQINCH = 1404
  /// Unsigned saturating increment scalar by count of true predicate elements.
  | UQINCP = 1405
  /// Unsigned saturating incr scalar by mul of 32-bit pred constraint elem cnt.
  | UQINCW = 1406
  /// Unsigned saturating Rounding Shift Left (register).
  | UQRSHL = 1407
  /// Unsigned saturating rounding shift left reversed vectors (predicated).
  | UQRSHLR = 1408
  /// Multi-vector unsigned saturating rounding shift right narrow by immediate.
  | UQRSHR = 1409
  /// Unsigned saturating Rounded Shift Right Narrow (immediate).
  | UQRSHRN = 1410
  /// Unsigned saturating Rounded Shift Right Narrow (immediate).
  | UQRSHRN2 = 1411
  /// Unsigned saturating rounding shift right narrow by immediate (bottom).
  | UQRSHRNB = 1412
  /// Unsigned saturating rounding shift right narrow by immediate (top).
  | UQRSHRNT = 1413
  /// Unsigned saturating Shift Left (immediate).
  | UQSHL = 1414
  /// Unsigned saturating shift left reversed vectors (predicated).
  | UQSHLR = 1415
  /// Unsigned saturating Shift Right Narrow (immediate).
  | UQSHRN = 1416
  /// Unsigned saturating Shift Right Narrow (immediate).
  | UQSHRN2 = 1417
  /// Unsigned saturating shift right narrow by immediate (bottom).
  | UQSHRNB = 1418
  /// Unsigned saturating shift right narrow by immediate (top).
  | UQSHRNT = 1419
  /// Unsigned saturating Subtract.
  | UQSUB = 1420
  /// Unsigned saturating subtraction reversed vectors (predicated).
  | UQSUBR = 1421
  /// Unsigned saturating extract Narrow.
  | UQXTN = 1422
  /// Unsigned saturating extract Narrow.
  | UQXTN2 = 1423
  /// Unsigned saturating extract narrow (bottom).
  | UQXTNB = 1424
  /// Unsigned saturating extract narrow (top).
  | UQXTNT = 1425
  /// Unsigned Reciprocal Estimate.
  | URECPE = 1426
  /// Unsigned Rounding Halving Add.
  | URHADD = 1427
  /// Unsigned Rounding Shift Left (register).
  | URSHL = 1428
  /// Unsigned rounding shift left reversed vectors (predicated).
  | URSHLR = 1429
  /// Unsigned Rounding Shift Right (immediate).
  | URSHR = 1430
  /// Unsigned Reciprocal Square Root Estimate.
  | URSQRTE = 1431
  /// Unsigned Rounding Shift Right and Accumulate (immediate).
  | URSRA = 1432
  /// Dot Product with unsigned and signed integers (vector, by element).
  | USDOT = 1433
  /// Unsigned Shift Left (register).
  | USHL = 1434
  /// Unsigned Shift Left Long (immediate).
  | USHLL = 1435
  /// Unsigned Shift Left Long (immediate).
  | USHLL2 = 1436
  /// Unsigned shift left long by immediate (bottom).
  | USHLLB = 1437
  /// Unsigned shift left long by immediate (top).
  | USHLLT = 1438
  /// Unsigned Shift Right (immediate).
  | USHR = 1439
  /// Multi-vector unsigned by signed int mul-add long long by indexed element.
  | USMLALL = 1440
  /// Unsigned by signed integer matrix multiply-accumulate.
  | USMMLA = 1441
  /// Unsigned by signed integer sum of outer products and accumulate.
  | USMOPA = 1442
  /// Unsigned by signed integer sum of outer products and subtract.
  | USMOPS = 1443
  /// Unsigned saturating Accumulate of Signed value.
  | USQADD = 1444
  /// Unsigned Shift Right and Accumulate (immediate).
  | USRA = 1445
  /// Unsigned Subtract Long.
  | USUBL = 1446
  /// Unsigned Subtract Long.
  | USUBL2 = 1447
  /// Unsigned subtract long (bottom).
  | USUBLB = 1448
  /// Unsigned subtract long (top).
  | USUBLT = 1449
  /// Unsigned Subtract Wide.
  | USUBW = 1450
  /// Unsigned Subtract Wide.
  | USUBW2 = 1451
  /// Unsigned subtract wide (bottom).
  | USUBWB = 1452
  /// Unsigned subtract wide (top).
  | USUBWT = 1453
  /// Multi-vector unsigned by signed int vertical dot-product by indexed elem.
  | USVDOT = 1454
  /// Unpack and zero-extend multi-vector elements.
  | UUNPK = 1455
  /// Unsigned unpack and extend half of vector.
  | UUNPKHI = 1456
  /// Unsigned unpack and extend half of vector.
  | UUNPKLO = 1457
  /// Multi-vector unsigned integer vertical dot-product by indexed element.
  | UVDOT = 1458
  /// Unsigned Extend Byte: an alias of UBFM.
  | UXTB = 1459
  /// Unsigned Extend Halfword: an alias of UBFM.
  | UXTH = 1460
  /// Unsigned extend Long: an alias of USHLL, USHLL2.
  | UXTL = 1461
  /// Unsigned extend Long: an alias of USHLL, USHLL2.
  | UXTL2 = 1462
  /// Unsigned byte / halfword / word extend (predicated).
  | UXTW = 1463
  /// Concatenate elements from four vectors.
  | UZP = 1464
  /// Unzip vectors (primary).
  | UZP1 = 1465
  /// Unzip vectors (secondary).
  | UZP2 = 1466
  /// Concatenate even elements within each pair of quadword vector segments.
  | UZPQ1 = 1467
  /// Concatenate odd elements within each pair of quadword vector segments.
  | UZPQ2 = 1468
  /// Wait For Event.
  | WFE = 1469
  /// Wait For Event with Timeout.
  | WFET = 1470
  /// Wait For Interrupt.
  | WFI = 1471
  /// Wait For Interrupt with Timeout.
  | WFIT = 1472
  /// While decrementing signed scalar greater than or equal to scalar.
  | WHILEGE = 1473
  /// While decrementing signed scalar greater than scalar.
  | WHILEGT = 1474
  /// While decrementing unsigned scalar higher than scalar.
  | WHILEHI = 1475
  /// While decrementing unsigned scalar higher or same as scalar.
  | WHILEHS = 1476
  /// While incrementing signed scalar less than or equal to scalar.
  | WHILELE = 1477
  /// While incrementing unsigned scalar lower than scalar.
  | WHILELO = 1478
  /// While incrementing unsigned scalar lower or same as scalar.
  | WHILELS = 1479
  /// While incrementing signed scalar less than scalar.
  | WHILELT = 1480
  /// While free of read-after-write conflicts.
  | WHILERW = 1481
  /// While free of write-after-read/write conflicts.
  | WHILEWR = 1482
  /// Write the first-fault register.
  | WRFFR = 1483
  /// Convert FP condition flags from external format to Arm format.
  | XAFLAG = 1484
  /// Exclusive OR and Rotate.
  | XAR = 1485
  /// Strip Pointer Authentication Code.
  | XPACD = 1486
  /// Strip Pointer Authentication Code.
  | XPACI = 1487
  /// Strip Pointer Authentication Code.
  | XPACLRI = 1488
  /// Extract Narrow.
  | XTN = 1489
  /// Extract Narrow.
  | XTN2 = 1490
  /// YIELD.
  | YIELD = 1491
  /// Zero ZA double-vector groups.
  | ZERO = 1492
  /// Interleave elements from four vectors.
  | ZIP = 1493
  /// Zip vectors (primary).
  | ZIP1 = 1494
  /// Zip vectors (secondary).
  | ZIP2 = 1495
  /// Interleave elements from low halves of each pair of qword vector segments.
  | ZIPQ1 = 1496
  /// Interleave elems from high halves of each pair of qword vector segments.
  | ZIPQ2 = 1497

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

type RoundMode =
  | FPRounding_TIEEVEN
  | FPRounding_TIEAWAY
  | FPRounding_Zero
  | FPRounding_POSINF
  | FPRounding_NEGINF

type Operand =
  | OprRegister of Register
  (* SIMD&FP register *)
  | OprSIMD of SIMDFPRegister
  (* SIMD vector register list or SIMD vector element list *)
  | OprSIMDList of SIMDFPRegister list
  | OprImm of Const
  | OprFPImm of float
  | OprNZCV of uint8
  | OprShift of Shift
  | OprExtReg of RegisterOffset option
  | OprMemory of AddressingMode
  | OprOption of OptionOpr
  | OprPstate of Pstate
  | OprPrfOp of PrefetchOperation
  | OprCond of Condition
  | OprFbits of uint8  (* fractional bits *)
  | OprLSB of uint8

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand
  | FiveOperands of Operand * Operand * Operand * Operand * Operand
