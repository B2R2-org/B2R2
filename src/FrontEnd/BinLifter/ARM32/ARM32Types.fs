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

namespace B2R2.FrontEnd.BinLifter.ARM32

open B2R2
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.BinLifter.Tests")>]
do ()

/// <sumary>
///   Most ARM instructions, and most Thumb instructions from ARMv6T2 onwards,
///   can be executed conditionally, based on the values of the APSR condition
///   flags. Before ARMv6T2, the only conditional Thumb instruction was
///   the 16-bit conditional branch instruction.
/// </sumary>
type Condition =
  /// Equal/Equal (Z == 1).
  | EQ = 0x01
  /// Not equal/Not equal, or unordered (Z == 0).
  | NE = 0x02
  /// Carry set/Greater than, equal, or unordered (C == 1).
  | CS = 0x03
  /// HS (unsigned higher or same) is a synonym for CS.
  | HS = 0x04
  /// Carry clear/Less than (C == 0).
  | CC = 0x05
  /// LO (unsigned lower) is a synonym for CC.
  | LO = 0x06
  /// Minus, negative/Less than (N == 1).
  | MI = 0x07
  /// Plus, positive or zero/Greater than, equal, or unordered (N == 0).
  | PL = 0x08
  /// Overflow/Unordered (V == 1).
  | VS = 0x09
  /// No overflow/Not unordered (V == 0).
  | VC = 0x0A
  /// Unsigned higher/Greater than, or unordered (C == 1 and Z == 0).
  | HI = 0x0B
  /// Unsigned lower or same/Less than or equal (C == 0 or Z == 1).
  | LS = 0x0C
  /// Signed greater than or equal/Greater than or equal (N == V).
  | GE = 0x0D
  /// Signed less than/Less than, or unordered (N != V).
  | LT = 0x0E
  /// Signed greater than/Greater than (Z == 0 and N == V).
  | GT = 0x0F
  /// Signed less than or equal/Less than, equal, or unordered
  /// (Z == 1 or N != V).
  | LE = 0x10
  /// Always (unconditional)/Always (unconditional) Any.
  | AL = 0x11
  /// The condition code NV exists only to provide a valid disassembly of
  /// the 0b1111 encoding, otherwise its behavior is identical to AL.
  | NV = 0x12
  /// Unconditional.
  | UN = 0x13

/// <summary>
///   ARM32 opcodes. This type should be generated using
///   <c>scripts/genOpcode.fsx</c> from the `ARM32SupportedOpcode.txt` file.
/// </summary>
type Opcode =
  /// Add with Carry.
  | ADC = 0
  /// Add with Carry and updates the flags.
  | ADCS = 1
  /// Add.
  | ADD = 2
  /// Add and updates the flags.
  | ADDS = 3
  /// Add Wide (12-bit).
  | ADDW = 4
  /// Form PC-relative Address.
  | ADR = 5
  /// AES single round decryption.
  | AESD = 6
  /// AES single round encryption.
  | AESE = 7
  /// AES inverse mix columns.
  | AESIMC = 8
  /// AES mix columns.
  | AESMC = 9
  /// Bitwise AND.
  | AND = 10
  /// Bitwise AND and updates the flags.
  | ANDS = 11
  /// Arithmetic Shift Right.
  | ASR = 12
  /// Arithmetic Shift Right and update the flags.
  | ASRS = 13
  /// Branch or Conditional branch.
  | B = 14
  /// Bit Field Clear.
  | BFC = 15
  /// Bit Field Insert.
  | BFI = 16
  /// Bitwise Bit Clear.
  | BIC = 17
  /// Bitwise Bit Clear and updates the flags.
  | BICS = 18
  /// Breakpoint.
  | BKPT = 19
  /// Branch with Link.
  | BL = 20
  /// Branch with Link and Exchange.
  | BLX = 21
  /// Branch and Exchange.
  | BX = 22
  /// Branch and Exchange Jazelle.
  | BXJ = 23
  /// Compare and Branch on Nonzero.
  | CBNZ = 24
  /// Compare and Branch on Zero.
  | CBZ = 25
  /// Coprocessor data operations.
  | CDP = 26
  /// Coprocessor data operations.
  | CDP2 = 27
  /// Clear-Exclusive.
  | CLREX = 28
  /// Count Leading Zeros.
  | CLZ = 29
  /// Compare Negative.
  | CMN = 30
  /// Compare.
  | CMP = 31
  /// Change Processor State.
  | CPS = 32
  /// Change Processor State, Interrupt Disasble.
  | CPSID = 33
  /// Change Processor State, Interrupt Enasble.
  | CPSIE = 34
  /// CRC-32 sum from byte.
  | CRC32B = 35
  /// CRC-32C sum from byte.
  | CRC32CB = 36
  /// CRC-32C sum from halfword.
  | CRC32CH = 37
  /// CRC-32C sum from word.
  | CRC32CW = 38
  /// CRC-32 sum from halfword.
  | CRC32H = 39
  /// CRC-32 sum from word.
  | CRC32W = 40
  /// Consumption of Speculative Data Barrier.
  | CSDB = 41
  /// Debug hint.
  | DBG = 42
  /// Data Memory Barrier.
  | DMB = 43
  /// Data Synchronization Barrier.
  | DSB = 44
  /// Enter ThumbEE state.
  | ENTERX = 45
  /// Bitwise Exclusive OR.
  | EOR = 46
  /// Bitwise Exclusive OR and update the flags.
  | EORS = 47
  /// Exception Return.
  | ERET = 48
  /// Error Synchronization Barrier.
  | ESB = 49
  /// Loads multiple SIMD&FP registers.
  | FLDMDBX = 50
  /// Loads multiple SIMD&FP registers.
  | FLDMIAX = 51
  /// Stores multiple SIMD&FP registers .
  | FSTMDBX = 52
  /// Stores multiple SIMD&FP registers .
  | FSTMIAX = 53
  /// Halt Instruction.
  | HLT = 54
  /// Hypervisor Call.
  | HVC = 55
  /// Instruction Synchronization Barrier.
  | ISB = 56
  /// If-Then.
  | IT = 57
  /// If-Then.
  | ITE = 58
  /// If-Then.
  | ITEE = 59
  /// If-Then.
  | ITEEE = 60
  /// If-Then.
  | ITEET = 61
  /// If-Then.
  | ITET = 62
  /// If-Then.
  | ITETE = 63
  /// If-Then.
  | ITETT = 64
  /// If-Then.
  | ITT = 65
  /// If-Then.
  | ITTE = 66
  /// If-Then.
  | ITTEE = 67
  /// If-Then.
  | ITTET = 68
  /// If-Then.
  | ITTT = 69
  /// If-Then.
  | ITTTE = 70
  /// If-Then.
  | ITTTT = 71
  /// Load-Acquire Word.
  | LDA = 72
  /// Load-Acquire Byte.
  | LDAB = 73
  /// Load-Acquire Exclusive Word.
  | LDAEX = 74
  /// Load-Acquire Exclusive Byte.
  | LDAEXB = 75
  /// Load-Acquire Exclusive Double.
  | LDAEXD = 76
  /// Load-Acquire Exclusive Halfword.
  | LDAEXH = 77
  /// Load-Acquire Halfword.
  | LDAH = 78
  /// Load Coprocessor.
  | LDC = 79
  /// Load Coprocessor.
  | LDC2 = 80
  /// Load Coprocessor.
  | LDC2L = 81
  /// Load Coprocessor.
  | LDCL = 82
  /// Load Multiple.
  | LDM = 83
  /// Load Multiple. Decrement After.
  | LDMDA = 84
  /// Load Multiple. Decrement Before.
  | LDMDB = 85
  /// Load Multiple. Increment After.
  | LDMIA = 86
  /// Load Multiple. Increment Before.
  | LDMIB = 87
  /// Load Register.
  | LDR = 88
  /// Load Register Byte.
  | LDRB = 89
  /// Load Register Byte Unprivileged.
  | LDRBT = 90
  /// Load Register Dual.
  | LDRD = 91
  /// Load Register Exclusive.
  | LDREX = 92
  /// Load Register Exclusive Byte.
  | LDREXB = 93
  /// Load Register Exclusive Doubleword.
  | LDREXD = 94
  /// Load Register Exclusive Halfword.
  | LDREXH = 95
  /// Load Register Halfword.
  | LDRH = 96
  /// Load Register Halfword Unprivileged.
  | LDRHT = 97
  /// Load Register Signed Byte.
  | LDRSB = 98
  /// Load Register Signed Byte Unprivileged.
  | LDRSBT = 99
  /// Load Register Signed Halfword.
  | LDRSH = 100
  /// Load Register Signed Halfword Unprivileged.
  | LDRSHT = 101
  /// Load Register Unprivileged.
  | LDRT = 102
  /// Exit ThumbEE state.
  | LEAVEX = 103
  /// Logical Shift Left.
  | LSL = 104
  /// Logical Shift Left and OutSide IT block.
  | LSLS = 105
  /// Logical Shift Right.
  | LSR = 106
  /// Logical Shift Right and OutSide IT block.
  | LSRS = 107
  /// Move to Coprocessor from ARM core register (T1/A1).
  | MCR = 108
  /// Move to Coprocessor from ARM core register (T2/A2).
  | MCR2 = 109
  /// Move to Coprocessor from two ARM core registers (T1/A1).
  | MCRR = 110
  /// Move to Coprocessor from two ARM core registers (T2/A2).
  | MCRR2 = 111
  /// Multiply Accumulate.
  | MLA = 112
  /// Multiply Accumulate and update the flags.
  | MLAS = 113
  /// Multiply and Subtract.
  | MLS = 114
  /// Move.
  | MOV = 115
  /// Move and update the flags.
  | MOVS = 116
  /// Move Top (16-bit).
  | MOVT = 117
  /// Move (Only encoding T3 or A2 permitted).
  | MOVW = 118
  /// Move to ARM core register from Coprocessor (T1/A1).
  | MRC = 119
  /// Move to ARM core register from Coprocessor (T2/A2).
  | MRC2 = 120
  /// Move to two ARM core registers from Coprocessor (T1/A1).
  | MRRC = 121
  /// Move to two ARM core registers from Coprocessor (T2/A2).
  | MRRC2 = 122
  /// Move from Banked or Special register.
  | MRS = 123
  /// Move to Special register, Application level.
  | MSR = 124
  /// Multiply.
  | MUL = 125
  /// Multiply and update the flags.
  | MULS = 126
  /// Bitwise NOT.
  | MVN = 127
  /// Bitwise NOT and update the flags.
  | MVNS = 128
  /// No Operation.
  | NOP = 129
  /// Bitwise OR NOT.
  | ORN = 130
  /// Bitwise OR NOT and update the flags.
  | ORNS = 131
  /// Bitwise OR.
  | ORR = 132
  /// Bitwise OR and update the flags.
  | ORRS = 133
  /// Pack Halfword (tbform == FALSE).
  | PKHBT = 134
  /// Pack Halfword (tbform == TRUE).
  | PKHTB = 135
  /// Preload Data.
  | PLD = 136
  /// Preload Data (W = 1 in Thumb or R = 0 in ARM).
  | PLDW = 137
  /// Preload Instruction.
  | PLI = 138
  /// Pop Multiple Registers.
  | POP = 139
  /// Physical Speculative Store Bypass Barrier.
  | PSSBB = 140
  /// Push Multiple Registers.
  | PUSH = 141
  /// Saturating Add.
  | QADD = 142
  /// Saturating Add 16-bit.
  | QADD16 = 143
  /// Saturating Add 8-bit.
  | QADD8 = 144
  /// Saturating Add and Subtract with Exchange, 16-bit.
  | QASX = 145
  /// Saturating Double and Add.
  | QDADD = 146
  /// Saturating Double and Subtract.
  | QDSUB = 147
  /// Saturating Subtract and Add with Exchange, 16-bit.
  | QSAX = 148
  /// Saturating Subtract.
  | QSUB = 149
  /// Saturating Subtract 16-bit.
  | QSUB16 = 150
  /// Saturating Add 8-bit.
  | QSUB8 = 151
  /// Reverse Bits.
  | RBIT = 152
  /// Byte-Reverse Word.
  | REV = 153
  /// Byte-Reverse Packed Halfword.
  | REV16 = 154
  /// Byte-Reverse Signed Halfword.
  | REVSH = 155
  /// Return From Exception.
  | RFE = 156
  /// Return From Exception. Decrement After.
  | RFEDA = 157
  /// Return From Exception. Decrement Before.
  | RFEDB = 158
  /// Return From Exception. Increment After.
  | RFEIA = 159
  /// Return From Exception. Increment Before.
  | RFEIB = 160
  /// Rotate Right.
  | ROR = 161
  /// Rotate Right and update the flags.
  | RORS = 162
  /// Rotate Right with Extend.
  | RRX = 163
  /// Rotate Right with Extend and update the flags.
  | RRXS = 164
  /// Reverse Subtract.
  | RSB = 165
  /// Reverse Subtract and update the flags.
  | RSBS = 166
  /// Reverse Subtract with Carry.
  | RSC = 167
  /// Reverse Subtract with Carry and update the flags.
  | RSCS = 168
  /// Add 16-bit.
  | SADD16 = 169
  /// Add 8-bit.
  | SADD8 = 170
  /// Add and Subtract with Exchange, 16-bit.
  | SASX = 171
  /// Speculation Barrier.
  | SB = 172
  /// Subtract with Carry.
  | SBC = 173
  /// Subtract with Carry and update the flags.
  | SBCS = 174
  /// Signed Bit Field Extract.
  | SBFX = 175
  /// Signed Divide.
  | SDIV = 176
  /// Select Bytes.
  | SEL = 177
  /// Set Endianness.
  | SETEND = 178
  /// Set Privileged Access Never.
  | SETPAN = 179
  /// Send Event.
  | SEV = 180
  /// Send Event Local is a hint instruction.
  | SEVL = 181
  /// SHA1 hash update (choose).
  | SHA1C = 182
  /// SHA1 fixed rotate.
  | SHA1H = 183
  /// SHA1 hash update (majority).
  | SHA1M = 184
  /// SHA1 hash update (parity).
  | SHA1P = 185
  /// SHA1 schedule update 0.
  | SHA1SU0 = 186
  /// SHA1 schedule update 1.
  | SHA1SU1 = 187
  /// SHA256 schedule update 0.
  | SHA256H = 188
  /// SHA256 hash update (part 2).
  | SHA256H2 = 189
  /// SHA256 schedule update 0.
  | SHA256SU0 = 190
  /// SHA256 schedule update 1.
  | SHA256SU1 = 191
  /// Halving Add 16-bit.
  | SHADD16 = 192
  /// Halving Add 8-bit.
  | SHADD8 = 193
  /// Halving Add and Subtract with Exchange, 16-bit.
  | SHASX = 194
  /// Halving Subtract and Add with Exchange, 16-bit.
  | SHSAX = 195
  /// Halving Subtract 16-bit.
  | SHSUB16 = 196
  /// Halving Subtract 8-bit.
  | SHSUB8 = 197
  /// Secure Monitor Call.
  | SMC = 198
  /// Signed Multiply Accumulate (Halfwords).
  | SMLABB = 199
  /// Signed Multiply Accumulate (Halfwords).
  | SMLABT = 200
  /// Signed Multiply Accumulate Dual.
  | SMLAD = 201
  /// Signed Multiply Accumulate Dual (M = 1).
  | SMLADX = 202
  /// Signed Multiply Accumulate Long.
  | SMLAL = 203
  /// Signed Multiply Accumulate Long (Halfwords).
  | SMLALBB = 204
  /// Signed Multiply Accumulate Long (Halfwords).
  | SMLALBT = 205
  /// Signed Multiply Accumulate Long Dual.
  | SMLALD = 206
  /// Signed Multiply Accumulate Long Dual (M = 1).
  | SMLALDX = 207
  /// Signed Multiply Accumulate Long and update the flags.
  | SMLALS = 208
  /// Signed Multiply Accumulate Long.
  | SMLALTB = 209
  /// Signed Multiply Accumulate Long (Halfwords).
  | SMLALTT = 210
  /// Signed Multiply Accumulate (Halfwords).
  | SMLATB = 211
  /// Signed Multiply Accumulate (Halfwords).
  | SMLATT = 212
  /// Signed Multiply Accumulate (Word by halfword).
  | SMLAWB = 213
  /// Signed Multiply Accumulate.
  | SMLAWT = 214
  /// Signed Multiply Subtract Dual.
  | SMLSD = 215
  /// Signed Multiply Subtract Dual (M = 1).
  | SMLSDX = 216
  /// Signed Multiply Subtract Long Dual.
  | SMLSLD = 217
  /// Signed Multiply Subtract Long Dual (M = 1).
  | SMLSLDX = 218
  /// Signed Most Significant Word Multiply Accumulate.
  | SMMLA = 219
  /// Signed Most Significant Word Multiply Accumulate (R = 1).
  | SMMLAR = 220
  /// Signed Most Significant Word Multiply Subtract.
  | SMMLS = 221
  /// Signed Most Significant Word Multiply Subtract (R = 1).
  | SMMLSR = 222
  /// Signed Most Significant Word Multiply.
  | SMMUL = 223
  /// Signed Most Significant Word Multiply (R = 1).
  | SMMULR = 224
  /// Signed Dual Multiply Add.
  | SMUAD = 225
  /// Signed Dual Multiply Add (M = 1).
  | SMUADX = 226
  /// Signed Multiply (Halfwords).
  | SMULBB = 227
  /// Signed Multiply (Halfwords).
  | SMULBT = 228
  /// Signed Multiply Long.
  | SMULL = 229
  /// Signed Multiply Long and update the flags.
  | SMULLS = 230
  /// Signed Multiply Long (Halfwords).
  | SMULTB = 231
  /// Signed Multiply Long (Halfwords).
  | SMULTT = 232
  /// Signed Multiply Accumulate (Word by halfword).
  | SMULWB = 233
  /// Signed Multiply Accumulate (Word by halfword).
  | SMULWT = 234
  /// Signed Dual Multiply Subtract.
  | SMUSD = 235
  /// Signed Dual Multiply Subtract (M = 1).
  | SMUSDX = 236
  /// Store Return State.
  | SRS = 237
  /// Store Return State. Decrement After.
  | SRSDA = 238
  /// Store Return State. Decrement Before.
  | SRSDB = 239
  /// Store Return State. Increment After.
  | SRSIA = 240
  /// Store Return State. Increment Before.
  | SRSIB = 241
  /// Signed Saturate.
  | SSAT = 242
  /// Signed Saturate, two 16-bit.
  | SSAT16 = 243
  /// Subtract and Add with Exchange, 16-bit.
  | SSAX = 244
  /// Speculative Store Bypass Barrier.
  | SSBB = 245
  /// Subtract 16-bit.
  | SSUB16 = 246
  /// Subtract 8-bit.
  | SSUB8 = 247
  /// Store Coprocessor (T1/A1).
  | STC = 248
  /// Store Coprocessor (T2/A2).
  | STC2 = 249
  /// Store Coprocessor (T2/A2) (D == 1).
  | STC2L = 250
  /// Store Coprocessor (T1/A1) (D == 1).
  | STCL = 251
  /// Store-Release Word.
  | STL = 252
  /// Store-Release Byte.
  | STLB = 253
  /// Store-Release Exclusive Word.
  | STLEX = 254
  /// Store-Release Exclusive Byte.
  | STLEXB = 255
  /// Store-Release Exclusive Doubleword.
  | STLEXD = 256
  /// Store-Release Exclusive Halfword.
  | STLEXH = 257
  /// Store-Release Halfword.
  | STLH = 258
  /// Store Multiple.
  | STM = 259
  /// Store Multiple. Decrement After.
  | STMDA = 260
  /// Store Multiple. Decrement Before.
  | STMDB = 261
  /// Store Multiple. Increment After.
  | STMEA = 262
  /// Store Multiple. Increment After.
  | STMIA = 263
  /// Store Multiple. Increment Before.
  | STMIB = 264
  /// Store Register.
  | STR = 265
  /// Store Register Byte.
  | STRB = 266
  /// Store Register Byte Unprivileged.
  | STRBT = 267
  /// Store Register Dual.
  | STRD = 268
  /// Store Register Exclusive.
  | STREX = 269
  /// Store Register Exclusive Byte.
  | STREXB = 270
  /// Store Register Exclusive Doubleword.
  | STREXD = 271
  /// Store Register Exclusive Halfword.
  | STREXH = 272
  /// Store Register Halfword.
  | STRH = 273
  /// Store Register Halfword Unprivileged.
  | STRHT = 274
  /// Store Register Unprivileged.
  | STRT = 275
  /// Subtract.
  | SUB = 276
  /// Subtract and update the flags.
  | SUBS = 277
  /// Subtract Wide.
  | SUBW = 278
  /// Supervisor Call.
  | SVC = 279
  /// Swap Word.
  | SWP = 280
  /// Swap Byte.
  | SWPB = 281
  /// Signed Extend and Add Byte.
  | SXTAB = 282
  /// Signed Extend and Add Byte 16.
  | SXTAB16 = 283
  /// Signed Extend and Add Halfword.
  | SXTAH = 284
  /// Signed Extend Byte.
  | SXTB = 285
  /// Signed Extend Byte 16.
  | SXTB16 = 286
  /// Signed Extend Halfword.
  | SXTH = 287
  /// Table Branch (byte offsets).
  | TBB = 288
  /// Table Branch (halfword offsets).
  | TBH = 289
  /// Test Equivalence.
  | TEQ = 290
  /// Trace Synchronization Barrier.
  | TSB = 291
  /// Test performs a bitwise AND operation.
  | TST = 292
  /// Add 16-bit.
  | UADD16 = 293
  /// Add 8-bit.
  | UADD8 = 294
  /// Add and Subtract with Exchange, 16-bit.
  | UASX = 295
  /// Unsigned Bit Field Extract.
  | UBFX = 296
  /// Permanently UNDEFINED.
  | UDF = 297
  /// Unsigned Divide.
  | UDIV = 298
  /// Halving Add 16-bit.
  | UHADD16 = 299
  /// Halving Add 8-bit.
  | UHADD8 = 300
  /// Halving Add and Subtract with Exchange, 16-bit.
  | UHASX = 301
  /// Halving Subtract and Add with Exchange, 16-bit.
  | UHSAX = 302
  /// Halving Subtract 16-bit.
  | UHSUB16 = 303
  /// Halving Add 8-bit.
  | UHSUB8 = 304
  /// Unsigned Multiply Accumulate Accumulate Long.
  | UMAAL = 305
  /// Unsigned Multiply Accumulate Long.
  | UMLAL = 306
  /// Unsigned Multiply Accumulate Long and update the flags.
  | UMLALS = 307
  /// Unsigned Multiply Long.
  | UMULL = 308
  /// Unsigned Multiply Long and update the flags.
  | UMULLS = 309
  /// Saturating Add 16-bit.
  | UQADD16 = 310
  /// Saturating Add 8-bit.
  | UQADD8 = 311
  /// Saturating Add and Subtract with Exchange, 16-bit.
  | UQASX = 312
  /// Saturating Subtract and Add with Exchange, 16-bit.
  | UQSAX = 313
  /// Saturating Subtract 16-bit.
  | UQSUB16 = 314
  /// Saturating Subtract 8-bit.
  | UQSUB8 = 315
  /// Unsigned Sum of Absolute Differences.
  | USAD8 = 316
  /// Unsigned Sum of Absolute Differences, Accumulate.
  | USADA8 = 317
  /// Unsigned Saturate.
  | USAT = 318
  /// Unsigned Saturate, two 16-bit.
  | USAT16 = 319
  /// Subtract and Add with Exchange, 16-bit.
  | USAX = 320
  /// Subtract 16-bit.
  | USUB16 = 321
  /// Subtract 8-bit.
  | USUB8 = 322
  /// Unsigned Extend and Add Byte.
  | UXTAB = 323
  /// Unsigned Extend and Add Byte 16.
  | UXTAB16 = 324
  /// Unsigned Extend and Add Halfword.
  | UXTAH = 325
  /// Unsigned Extend Byte.
  | UXTB = 326
  /// Unsigned Extend Byte 16.
  | UXTB16 = 327
  /// Unsigned Extend Halfword.
  | UXTH = 328
  /// Vector Absolute Difference and Accumulate.
  | VABA = 329
  /// Vector Absolute Difference and Accumulate (T2/A2).
  | VABAL = 330
  /// Vector Absolute Difference.
  | VABD = 331
  /// Vector Absolute Difference (T2/A2).
  | VABDL = 332
  /// Vector Absolute.
  | VABS = 333
  /// Vector Absolute Compare Greater or Less Than (or Equal).
  | VACGE = 334
  /// Vector Absolute Compare Greater or Less Than (or Equal).
  | VACGT = 335
  /// Vector Absolute Compare Greater or Less Than (or Equal).
  | VACLE = 336
  /// Vector Absolute Compare Greater or Less Than (or Equal).
  | VACLT = 337
  /// Vector Add.
  | VADD = 338
  /// Vector Add and Narrow, returning High Half.
  | VADDHN = 339
  /// Vector Add Long.
  | VADDL = 340
  /// Vector Add Wide.
  | VADDW = 341
  /// Vector Bitwise AND.
  | VAND = 342
  /// Vector Bitwise Bit Clear, AND complement.
  | VBIC = 343
  /// Vector Bitwise Select. Bitwise Insert if False, encoded as op = 0b11.
  | VBIF = 344
  /// Vector Bitwise Select. Bitwise Insert if True, encoded as op = 0b10.
  | VBIT = 345
  /// Vector Bitwise Select. Bitwise Select, encoded as op = 0b01.
  | VBSL = 346
  /// Vector Complex Add.
  | VCADD = 347
  /// Vector Compare Equal.
  | VCEQ = 348
  /// Vector Compare Greater Than or Equal.
  | VCGE = 349
  /// Vector Compare Greater Than.
  | VCGT = 350
  /// Vector Compare Less Than or Equal to Zero.
  | VCLE = 351
  /// Vector Count Leading Sign Bits.
  | VCLS = 352
  /// Vector Compare Less Than Zero.
  | VCLT = 353
  /// Vector Count Leading Zeros.
  | VCLZ = 354
  /// Vector Complex Multiply Accumulate.
  | VCMLA = 355
  /// Vector Compare. (Encoded as E = 0).
  | VCMP = 356
  /// Vector Compare. (Encoded as E = 1).
  | VCMPE = 357
  /// Vector Count.
  | VCNT = 358
  /// Vector Convert.
  | VCVT = 359
  /// Convert floating-point to integer with Round to Nearest with Ties to Away.
  | VCVTA = 360
  /// Convert between half-precision and single-precision.
  | VCVTB = 361
  /// Convert floating-point to integer with Round towards Minus Infinity.
  | VCVTM = 362
  /// Convert floating-point to integer with Round to Nearest.
  | VCVTN = 363
  /// Convert floating-point to integer with Round towards Plus Infinity.
  | VCVTP = 364
  /// Vector Convert floating-point to integer.
  | VCVTR = 365
  /// Convert between half-precision and single-precision.
  | VCVTT = 366
  /// Vector Divide.
  | VDIV = 367
  /// BFloat16 floating-point (BF16) dot product (vector).
  | VDOT = 368
  /// Vector Duplicate.
  | VDUP = 369
  /// Vector Bitwise Exclusive OR.
  | VEOR = 370
  /// Vector Extract.
  | VEXT = 371
  /// Vector Fused Multiply Accumulate.
  | VFMA = 372
  /// BFloat16 floating-point widening multiply-add.
  | VFMAB = 373
  /// Vector Floating-point Multiply-Add Long to accumulator.
  | VFMAL = 374
  /// BFloat16 floating-point widening multiply-add.
  | VFMAT = 375
  /// Vector Fused Multiply Subtract.
  | VFMS = 376
  /// Vector Floating-Point Multiply-Subtract Long.
  | VFMSL = 377
  /// Vector Fused Negate Multiply Accumulate.
  | VFNMA = 378
  /// Vector Fused Negate Multiply Subtract.
  | VFNMS = 379
  /// Vector Halving Add.
  | VHADD = 380
  /// Vector Halving Subtract.
  | VHSUB = 381
  /// Vector move Insertion.
  | VINS = 382
  /// FP Javascript convert to signed fixed-point, rounding toward zero.
  | VJCVT = 383
  /// Vector Load. (multiple single elements).
  | VLD1 = 384
  /// Vector Load. (multiple 2-element structures).
  | VLD2 = 385
  /// Vector Load. (multiple 3-element structures).
  | VLD3 = 386
  /// Vector Load. (multiple 4-element structures).
  | VLD4 = 387
  /// Vector Load Multiple.
  | VLDM = 388
  /// Vector Load Multiple. Decrement Before.
  | VLDMDB = 389
  /// Vector Load Multiple. Increment After.
  | VLDMIA = 390
  /// Vector Load Register.
  | VLDR = 391
  /// Vector Maximum.
  | VMAX = 392
  /// Floating-point Maximum Number.
  | VMAXNM = 393
  /// Vector Minimum.
  | VMIN = 394
  /// Floating-point Minimum Number.
  | VMINNM = 395
  /// Vector Multiply Accumulate.
  | VMLA = 396
  /// Vector Multiply Accumulate (T2/A2).
  | VMLAL = 397
  /// Vector Multiply Subtract.
  | VMLS = 398
  /// Vector Multiply Subtract (T2/A2).
  | VMLSL = 399
  /// BFloat16 floating-point matrix multiply-accumulate.
  | VMMLA = 400
  /// Vector Move.
  | VMOV = 401
  /// Vector Move Long.
  | VMOVL = 402
  /// Vector Move and Narrow.
  | VMOVN = 403
  /// Vector Move extraction.
  | VMOVX = 404
  /// Move to ARM core register from Floating-point Special register.
  | VMRS = 405
  /// Move to Floating-point Special register from ARM core register.
  | VMSR = 406
  /// Vector Multiply.
  | VMUL = 407
  /// Vector Multiply Long.
  | VMULL = 408
  /// Vector Bitwise NOT.
  | VMVN = 409
  /// Vector Negate.
  | VNEG = 410
  /// Vector Negate Multiply Accumulate or Subtract.
  | VNMLA = 411
  /// Vector Negate Multiply Accumulate or Subtract.
  | VNMLS = 412
  /// Vector Negate Multiply Accumulate or Subtract.
  | VNMUL = 413
  /// Vector Bitwise OR NOT.
  | VORN = 414
  /// Vector Bitwise OR, if source registers differ.
  | VORR = 415
  /// Vector Pairwise Add and Accumulate Long.
  | VPADAL = 416
  /// Vector Pairwise Add.
  | VPADD = 417
  /// Vector Pairwise Add Long.
  | VPADDL = 418
  /// Vector Pairwise Maximum.
  | VPMAX = 419
  /// Vector Pairwise Minimum.
  | VPMIN = 420
  /// Vector Pop Registers.
  | VPOP = 421
  /// Vector Push Registers.
  | VPUSH = 422
  /// Vector Saturating Absolute.
  | VQABS = 423
  /// Vector Saturating Add.
  | VQADD = 424
  /// Vector Saturating Doubling Multiply Accumulate Long.
  | VQDMLAL = 425
  /// Vector Saturating Doubling Multiply Subtract Long.
  | VQDMLSL = 426
  /// Vector Saturating Doubling Multiply returning High Half.
  | VQDMULH = 427
  /// Vector Saturating Doubling Multiply Long.
  | VQDMULL = 428
  /// Vector Saturating Move and Unsigned Narrow (op <> 0b01).
  | VQMOVN = 429
  /// Vector Saturating Move and Unsigned Narrow (op = 0b01).
  | VQMOVUN = 430
  /// Vector Saturating Negate.
  | VQNEG = 431
  /// Vector Saturating Rounding Doubling Mul Accumulate Returning High Half.
  | VQRDMLAH = 432
  /// Vector Saturating Rounding Doubling Multiply Subtract Returning High Half.
  | VQRDMLSH = 433
  /// Vector Saturating Rounding Doubling Multiply returning High Half.
  | VQRDMULH = 434
  /// Vector Saturating Rounding Shift Left.
  | VQRSHL = 435
  /// Vector Saturating Shift Right, Rounded Unsigned Narrow.
  | VQRSHRN = 436
  /// Vector Saturating Shift Right, Rounded Unsigned Narrow.
  | VQRSHRUN = 437
  /// Vector Saturating Shift Left.
  | VQSHL = 438
  /// Vector Saturating Shift Left.
  | VQSHLU = 439
  /// Vector Saturating Shift Right, Narrow.
  | VQSHRN = 440
  /// Vector Saturating Shift Right, Narrow.
  | VQSHRUN = 441
  /// Vector Saturating Subtract.
  | VQSUB = 442
  /// Vector Rounding Add and Narrow, returning High Half.
  | VRADDHN = 443
  /// Vector Reciprocal Estimate.
  | VRECPE = 444
  /// Vector Reciprocal Step.
  | VRECPS = 445
  /// Vector Reverse in halfwords.
  | VREV16 = 446
  /// Vector Reverse in words.
  | VREV32 = 447
  /// Vector Reverse in doublewords.
  | VREV64 = 448
  /// Vector Rounding Halving Add.
  | VRHADD = 449
  /// Vector Round floating-point to integer towards Nearest with Ties to Away.
  | VRINTA = 450
  /// Vector Round floating-point to integer towards Minus Infinity.
  | VRINTM = 451
  /// Vector Round floating-point to integer to Nearest.
  | VRINTN = 452
  /// Vector Round floating-point to integer towards Plus Infinity.
  | VRINTP = 453
  /// Vector Round floating-point to integer rounds.
  | VRINTR = 454
  /// Vector round floating-point to integer to nearest signaling inexactness.
  | VRINTX = 455
  /// Vector round floating-point to integer towards Zero.
  | VRINTZ = 456
  /// Vector Rounding Shift Left.
  | VRSHL = 457
  /// Vector Rounding Shift Right.
  | VRSHR = 458
  /// Vector Rounding Shift Right Narrow.
  | VRSHRN = 459
  /// Vector Reciprocal Square Root Estimate.
  | VRSQRTE = 460
  /// Vector Reciprocal Square Root Step.
  | VRSQRTS = 461
  /// Vector Rounding Shift Right and Accumulate.
  | VRSRA = 462
  /// Vector Rounding Subtract and Narrow, returning High Half.
  | VRSUBHN = 463
  /// Dot Product vector form with signed integers.
  | VSDOT = 464
  /// Floating-point conditional select.
  | VSELEQ = 465
  /// Floating-point conditional select.
  | VSELGE = 466
  /// Floating-point conditional select.
  | VSELGT = 467
  /// Floating-point conditional select.
  | VSELVS = 468
  /// Vector Shift Left.
  | VSHL = 469
  /// Vector Shift Left Long.
  | VSHLL = 470
  /// Vector Shift Right.
  | VSHR = 471
  /// Vector Shift Right Narrow.
  | VSHRN = 472
  /// Vector Shift Left and Insert.
  | VSLI = 473
  /// The widening integer matrix multiply-accumulate instruction.
  | VSMMLA = 474
  /// Vector Square Root.
  | VSQRT = 475
  /// Vector Shift Right and Accumulate.
  | VSRA = 476
  /// Vector Shift Right and Insert.
  | VSRI = 477
  /// Vector Store. (multiple single elements).
  | VST1 = 478
  /// Vector Store. (multiple 2-element structures).
  | VST2 = 479
  /// Vector Store. (multiple 3-element structures).
  | VST3 = 480
  /// Vector Store. (multiple 4-element structures).
  | VST4 = 481
  /// Vector Store Multiple.
  | VSTM = 482
  /// Vector Store Multiple. Decrement Before.
  | VSTMDB = 483
  /// Vector Store Multiple. Increment After.
  | VSTMIA = 484
  /// Vector Store Register.
  | VSTR = 485
  /// Vector Subtract.
  | VSUB = 486
  /// Vector Subtract and Narrow, returning High Half.
  | VSUBHN = 487
  /// Vector Subtract Long.
  | VSUBL = 488
  /// Vector Subtract Wide.
  | VSUBW = 489
  /// Dot Product index form with signed and unsigned integers.
  | VSUDOT = 490
  /// Vector Swap.
  | VSWP = 491
  /// Vector Table Lookup.
  | VTBL = 492
  /// Vector Table Extension.
  | VTBX = 493
  /// Vector Transpose.
  | VTRN = 494
  /// Vector Test Bits.
  | VTST = 495
  /// Dot Product index form with unsigned integers.
  | VUDOT = 496
  /// Widening 8-bit unsigned int matrix multiply-accumulate into 2x2 matrix.
  | VUMMLA = 497
  /// Dot Product index form with unsigned and signed integers.
  | VUSDOT = 498
  /// Widening 8-bit mixed sign int matrix multiply-accumulate into 2x2 matrix.
  | VUSMMLA = 499
  /// Vector Unzip.
  | VUZP = 500
  /// Vector Zip.
  | VZIP = 501
  /// Wait For Event hint.
  | WFE = 502
  /// Wait For Interrupt hint.
  | WFI = 503
  /// Yield hint.
  | YIELD = 504
  /// Invalid Opcode.
  | InvalidOP = 505

type internal Op = Opcode

type internal PSR =
  | PSR_Cond
  | PSR_N
  | PSR_Z
  | PSR_C
  | PSR_V
  | PSR_Q
  | PSR_IT10
  | PSR_J
  | PSR_GE
  | PSR_IT72
  | PSR_E
  | PSR_A
  | PSR_I
  | PSR_F
  | PSR_T
  | PSR_M

type internal SCTLR =
  | SCTLR_NMFI

type internal SCR =
  | SCR_AW
  | SCR_FW
  | SCR_NS

type internal NSACR =
  | NSACR_RFR

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

type Option =
  | OSHLD = 0b0001
  | OSHST = 0b0010
  | OSH = 0b0011
  | NSHLD = 0b0101
  | NSHST = 0b0110
  | NSH = 0b0111
  | ISHLD = 0b1001
  | ISHST = 0b1010
  | ISH = 0b1011
  | LD = 0b1101
  | ST = 0b1110
  | SY = 0b1111

type Iflag =
  | A
  | I
  | F
  | AI
  | AF
  | IF
  | AIF

type internal SIMDVFPRegisterSpacing =
  | Single
  | Double

type SRType =
  | SRTypeLSL
  | SRTypeLSR
  | SRTypeASR
  | SRTypeROR
  | SRTypeRRX

/// A8.2 Standard assembler syntax fields
type Qualifier =
  /// Wide.
  | W
  /// Narrow (defalut).
  | N

/// A2.6.3 Data types supported by the Advanced SIMD Extension
type SIMDDataType =
  | SIMDTyp8      (* Any element of <size> bits *)
  | SIMDTyp16
  | SIMDTyp32
  | SIMDTyp64
  | SIMDTypF16    (* Floating-point number of <size> bits *)
  | SIMDTypF32
  | SIMDTypF64
  | SIMDTypI8     (* Signed or unsigned integer of <size> bits *)
  | SIMDTypI16
  | SIMDTypI32
  | SIMDTypI64
  | SIMDTypP8     (* Polynomial over {0, 1} of degree less than <size> *)
  | SIMDTypS8     (* Signed integer of <size> bits *)
  | SIMDTypS16
  | SIMDTypS32
  | SIMDTypS64
  | SIMDTypU8     (* Unsigned integer of <size> bits *)
  | SIMDTypU16
  | SIMDTypU32
  | SIMDTypU64
  | BF16 // FIMXE

type SIMDDataTypes =
  | OneDT of SIMDDataType
  | TwoDT of SIMDDataType * SIMDDataType

/// V{<modifier>}<operation>{<shape>}{<c>}{<q>}{.<dt>} {<dest>,} <src1>, <src2>
type SIMDFPRegister =
  | Vector of Register
  | Scalar of Register * Element option
and Element = uint8

type SIMDOperand =
  | SFReg of SIMDFPRegister
  | OneReg of SIMDFPRegister
  | TwoRegs of SIMDFPRegister * SIMDFPRegister
  | ThreeRegs of SIMDFPRegister * SIMDFPRegister * SIMDFPRegister
  | FourRegs of
      SIMDFPRegister * SIMDFPRegister * SIMDFPRegister * SIMDFPRegister

type Amount = Imm of uint32

type Shift = SRType * Amount

type PSRFlag =
  | PSRc
  | PSRx
  | PSRxc
  | PSRs
  | PSRsc
  | PSRsx
  | PSRsxc
  | PSRf
  | PSRfc
  | PSRfx
  | PSRfxc
  | PSRfs
  | PSRfsc
  | PSRfsx
  | PSRfsxc
  | PSRnzcv
  | PSRnzcvq
  | PSRg
  | PSRnzcvqg

type Const = int64

type Label = Const

type Align = Const

type Sign =
  | Plus
  | Minus

type Offset =
  | ImmOffset of Register * Sign option * Const option
  | RegOffset of Register * Sign option * Register * Shift option
  | AlignOffset of Register * Align option * Register option (* Advanced SIMD *)

type AddressingMode =
  | OffsetMode of Offset
  | PreIdxMode of Offset
  | PostIdxMode of Offset
  | UnIdxMode of Register * Const (* [<Rn>], <option> *)
  | LiteralMode of Label

type Operand =
  | OprReg of Register
  | OprSpecReg of Register * PSRFlag option
  | OprRegList of Register list
  | OprSIMD of SIMDOperand
  | OprImm of Const
  | OprFPImm of float
  | OprShift of Shift
  | OprRegShift of SRType * Register
  | OprMemory of AddressingMode
  | OprOption of Option
  | OprIflag of Iflag
  | OprEndian of Endian
  | OprCond of Condition
  | GoToLabel of string

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand
  | FiveOperands of Operand * Operand * Operand * Operand * Operand
  | SixOperands of Operand * Operand * Operand * Operand * Operand * Operand

/// Basic information for a single ARMv7 instruction obtained after parsing.
[<NoComparison; CustomEquality>]
type InsInfo = {
  /// Address.
  Address: Addr
  /// Number of bytes.
  NumBytes: uint32
  /// Condition.
  Condition: Condition option
  /// Opcode.
  Opcode: Opcode
  /// Operands.
  Operands: Operands
  /// IT state for this instruction (used only for IT instructions).
  ITState: byte
  /// Write back.
  WriteBack: bool
  /// Qualifier.
  Qualifier: Qualifier
  /// SIMD data type.
  SIMDTyp: SIMDDataTypes option
  /// Target architecture mode.
  Mode: ArchOperationMode
  /// Carry Flag from decoding instruction
  Cflag: bool option
}
with
  override __.GetHashCode () =
    hash (__.Address,
          __.NumBytes,
          __.Condition,
          __.Opcode,
          __.Operands,
          __.Qualifier,
          __.SIMDTyp,
          __.Mode)
  override __.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = __.Address
      && i.NumBytes = __.NumBytes
      && i.Condition = __.Condition
      && i.Opcode = __.Opcode
      && i.Operands = __.Operands
      && i.Qualifier = __.Qualifier
      && i.SIMDTyp = __.SIMDTyp
      && i.Mode = __.Mode
      && i.Cflag = __.Cflag
    | _ -> false

// vim: set tw=80 sts=2 sw=2:
