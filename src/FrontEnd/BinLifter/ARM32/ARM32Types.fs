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
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
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
  /// Debug switch to Exception level 1.
  | DCPS1 = 43
  /// Debug switch to Exception level 2.
  | DCPS2 = 44
  /// Debug switch to Exception level 3.
  | DCPS3 = 45
  /// Data Memory Barrier.
  | DMB = 46
  /// Data Synchronization Barrier.
  | DSB = 47
  /// Enter ThumbEE state.
  | ENTERX = 48
  /// Bitwise Exclusive OR.
  | EOR = 49
  /// Bitwise Exclusive OR and update the flags.
  | EORS = 50
  /// Exception Return.
  | ERET = 51
  /// Error Synchronization Barrier.
  | ESB = 52
  /// Loads multiple SIMD&FP registers.
  | FLDMDBX = 53
  /// Loads multiple SIMD&FP registers.
  | FLDMIAX = 54
  /// Stores multiple SIMD&FP registers .
  | FSTMDBX = 55
  /// Stores multiple SIMD&FP registers .
  | FSTMIAX = 56
  /// Halt Instruction.
  | HLT = 57
  /// Hypervisor Call.
  | HVC = 58
  /// Instruction Synchronization Barrier.
  | ISB = 59
  /// If-Then.
  | IT = 60
  /// If-Then.
  | ITE = 61
  /// If-Then.
  | ITEE = 62
  /// If-Then.
  | ITEEE = 63
  /// If-Then.
  | ITEET = 64
  /// If-Then.
  | ITET = 65
  /// If-Then.
  | ITETE = 66
  /// If-Then.
  | ITETT = 67
  /// If-Then.
  | ITT = 68
  /// If-Then.
  | ITTE = 69
  /// If-Then.
  | ITTEE = 70
  /// If-Then.
  | ITTET = 71
  /// If-Then.
  | ITTT = 72
  /// If-Then.
  | ITTTE = 73
  /// If-Then.
  | ITTTT = 74
  /// Load-Acquire Word.
  | LDA = 75
  /// Load-Acquire Byte.
  | LDAB = 76
  /// Load-Acquire Exclusive Word.
  | LDAEX = 77
  /// Load-Acquire Exclusive Byte.
  | LDAEXB = 78
  /// Load-Acquire Exclusive Double.
  | LDAEXD = 79
  /// Load-Acquire Exclusive Halfword.
  | LDAEXH = 80
  /// Load-Acquire Halfword.
  | LDAH = 81
  /// Load Coprocessor.
  | LDC = 82
  /// Load Coprocessor.
  | LDC2 = 83
  /// Load Coprocessor.
  | LDC2L = 84
  /// Load Coprocessor.
  | LDCL = 85
  /// Load Multiple.
  | LDM = 86
  /// Load Multiple. Decrement After.
  | LDMDA = 87
  /// Load Multiple. Decrement Before.
  | LDMDB = 88
  /// Load Multiple. Increment After.
  | LDMIA = 89
  /// Load Multiple. Increment Before.
  | LDMIB = 90
  /// Load Register.
  | LDR = 91
  /// Load Register Byte.
  | LDRB = 92
  /// Load Register Byte Unprivileged.
  | LDRBT = 93
  /// Load Register Dual.
  | LDRD = 94
  /// Load Register Exclusive.
  | LDREX = 95
  /// Load Register Exclusive Byte.
  | LDREXB = 96
  /// Load Register Exclusive Doubleword.
  | LDREXD = 97
  /// Load Register Exclusive Halfword.
  | LDREXH = 98
  /// Load Register Halfword.
  | LDRH = 99
  /// Load Register Halfword Unprivileged.
  | LDRHT = 100
  /// Load Register Signed Byte.
  | LDRSB = 101
  /// Load Register Signed Byte Unprivileged.
  | LDRSBT = 102
  /// Load Register Signed Halfword.
  | LDRSH = 103
  /// Load Register Signed Halfword Unprivileged.
  | LDRSHT = 104
  /// Load Register Unprivileged.
  | LDRT = 105
  /// Exit ThumbEE state.
  | LEAVEX = 106
  /// Logical Shift Left.
  | LSL = 107
  /// Logical Shift Left and OutSide IT block.
  | LSLS = 108
  /// Logical Shift Right.
  | LSR = 109
  /// Logical Shift Right and OutSide IT block.
  | LSRS = 110
  /// Move to Coprocessor from ARM core register (T1/A1).
  | MCR = 111
  /// Move to Coprocessor from ARM core register (T2/A2).
  | MCR2 = 112
  /// Move to Coprocessor from two ARM core registers (T1/A1).
  | MCRR = 113
  /// Move to Coprocessor from two ARM core registers (T2/A2).
  | MCRR2 = 114
  /// Multiply Accumulate.
  | MLA = 115
  /// Multiply Accumulate and update the flags.
  | MLAS = 116
  /// Multiply and Subtract.
  | MLS = 117
  /// Move.
  | MOV = 118
  /// Move and update the flags.
  | MOVS = 119
  /// Move Top (16-bit).
  | MOVT = 120
  /// Move (Only encoding T3 or A2 permitted).
  | MOVW = 121
  /// Move to ARM core register from Coprocessor (T1/A1).
  | MRC = 122
  /// Move to ARM core register from Coprocessor (T2/A2).
  | MRC2 = 123
  /// Move to two ARM core registers from Coprocessor (T1/A1).
  | MRRC = 124
  /// Move to two ARM core registers from Coprocessor (T2/A2).
  | MRRC2 = 125
  /// Move from Banked or Special register.
  | MRS = 126
  /// Move to Special register, Application level.
  | MSR = 127
  /// Multiply.
  | MUL = 128
  /// Multiply and update the flags.
  | MULS = 129
  /// Bitwise NOT.
  | MVN = 130
  /// Bitwise NOT and update the flags.
  | MVNS = 131
  /// No Operation.
  | NOP = 132
  /// Bitwise OR NOT.
  | ORN = 133
  /// Bitwise OR NOT and update the flags.
  | ORNS = 134
  /// Bitwise OR.
  | ORR = 135
  /// Bitwise OR and update the flags.
  | ORRS = 136
  /// Pack Halfword (tbform == FALSE).
  | PKHBT = 137
  /// Pack Halfword (tbform == TRUE).
  | PKHTB = 138
  /// Preload Data.
  | PLD = 139
  /// Preload Data (W = 1 in Thumb or R = 0 in ARM).
  | PLDW = 140
  /// Preload Instruction.
  | PLI = 141
  /// Pop Multiple Registers.
  | POP = 142
  /// Physical Speculative Store Bypass Barrier.
  | PSSBB = 143
  /// Push Multiple Registers.
  | PUSH = 144
  /// Saturating Add.
  | QADD = 145
  /// Saturating Add 16-bit.
  | QADD16 = 146
  /// Saturating Add 8-bit.
  | QADD8 = 147
  /// Saturating Add and Subtract with Exchange, 16-bit.
  | QASX = 148
  /// Saturating Double and Add.
  | QDADD = 149
  /// Saturating Double and Subtract.
  | QDSUB = 150
  /// Saturating Subtract and Add with Exchange, 16-bit.
  | QSAX = 151
  /// Saturating Subtract.
  | QSUB = 152
  /// Saturating Subtract 16-bit.
  | QSUB16 = 153
  /// Saturating Add 8-bit.
  | QSUB8 = 154
  /// Reverse Bits.
  | RBIT = 155
  /// Byte-Reverse Word.
  | REV = 156
  /// Byte-Reverse Packed Halfword.
  | REV16 = 157
  /// Byte-Reverse Signed Halfword.
  | REVSH = 158
  /// Return From Exception.
  | RFE = 159
  /// Return From Exception. Decrement After.
  | RFEDA = 160
  /// Return From Exception. Decrement Before.
  | RFEDB = 161
  /// Return From Exception. Increment After.
  | RFEIA = 162
  /// Return From Exception. Increment Before.
  | RFEIB = 163
  /// Rotate Right.
  | ROR = 164
  /// Rotate Right and update the flags.
  | RORS = 165
  /// Rotate Right with Extend.
  | RRX = 166
  /// Rotate Right with Extend and update the flags.
  | RRXS = 167
  /// Reverse Subtract.
  | RSB = 168
  /// Reverse Subtract and update the flags.
  | RSBS = 169
  /// Reverse Subtract with Carry.
  | RSC = 170
  /// Reverse Subtract with Carry and update the flags.
  | RSCS = 171
  /// Add 16-bit.
  | SADD16 = 172
  /// Add 8-bit.
  | SADD8 = 173
  /// Add and Subtract with Exchange, 16-bit.
  | SASX = 174
  /// Speculation Barrier.
  | SB = 175
  /// Subtract with Carry.
  | SBC = 176
  /// Subtract with Carry and update the flags.
  | SBCS = 177
  /// Signed Bit Field Extract.
  | SBFX = 178
  /// Signed Divide.
  | SDIV = 179
  /// Select Bytes.
  | SEL = 180
  /// Set Endianness.
  | SETEND = 181
  /// Set Privileged Access Never.
  | SETPAN = 182
  /// Send Event.
  | SEV = 183
  /// Send Event Local is a hint instruction.
  | SEVL = 184
  /// SHA1 hash update (choose).
  | SHA1C = 185
  /// SHA1 fixed rotate.
  | SHA1H = 186
  /// SHA1 hash update (majority).
  | SHA1M = 187
  /// SHA1 hash update (parity).
  | SHA1P = 188
  /// SHA1 schedule update 0.
  | SHA1SU0 = 189
  /// SHA1 schedule update 1.
  | SHA1SU1 = 190
  /// SHA256 schedule update 0.
  | SHA256H = 191
  /// SHA256 hash update (part 2).
  | SHA256H2 = 192
  /// SHA256 schedule update 0.
  | SHA256SU0 = 193
  /// SHA256 schedule update 1.
  | SHA256SU1 = 194
  /// Halving Add 16-bit.
  | SHADD16 = 195
  /// Halving Add 8-bit.
  | SHADD8 = 196
  /// Halving Add and Subtract with Exchange, 16-bit.
  | SHASX = 197
  /// Halving Subtract and Add with Exchange, 16-bit.
  | SHSAX = 198
  /// Halving Subtract 16-bit.
  | SHSUB16 = 199
  /// Halving Subtract 8-bit.
  | SHSUB8 = 200
  /// Secure Monitor Call.
  | SMC = 201
  /// Signed Multiply Accumulate (Halfwords).
  | SMLABB = 202
  /// Signed Multiply Accumulate (Halfwords).
  | SMLABT = 203
  /// Signed Multiply Accumulate Dual.
  | SMLAD = 204
  /// Signed Multiply Accumulate Dual (M = 1).
  | SMLADX = 205
  /// Signed Multiply Accumulate Long.
  | SMLAL = 206
  /// Signed Multiply Accumulate Long (Halfwords).
  | SMLALBB = 207
  /// Signed Multiply Accumulate Long (Halfwords).
  | SMLALBT = 208
  /// Signed Multiply Accumulate Long Dual.
  | SMLALD = 209
  /// Signed Multiply Accumulate Long Dual (M = 1).
  | SMLALDX = 210
  /// Signed Multiply Accumulate Long and update the flags.
  | SMLALS = 211
  /// Signed Multiply Accumulate Long.
  | SMLALTB = 212
  /// Signed Multiply Accumulate Long (Halfwords).
  | SMLALTT = 213
  /// Signed Multiply Accumulate (Halfwords).
  | SMLATB = 214
  /// Signed Multiply Accumulate (Halfwords).
  | SMLATT = 215
  /// Signed Multiply Accumulate (Word by halfword).
  | SMLAWB = 216
  /// Signed Multiply Accumulate.
  | SMLAWT = 217
  /// Signed Multiply Subtract Dual.
  | SMLSD = 218
  /// Signed Multiply Subtract Dual (M = 1).
  | SMLSDX = 219
  /// Signed Multiply Subtract Long Dual.
  | SMLSLD = 220
  /// Signed Multiply Subtract Long Dual (M = 1).
  | SMLSLDX = 221
  /// Signed Most Significant Word Multiply Accumulate.
  | SMMLA = 222
  /// Signed Most Significant Word Multiply Accumulate (R = 1).
  | SMMLAR = 223
  /// Signed Most Significant Word Multiply Subtract.
  | SMMLS = 224
  /// Signed Most Significant Word Multiply Subtract (R = 1).
  | SMMLSR = 225
  /// Signed Most Significant Word Multiply.
  | SMMUL = 226
  /// Signed Most Significant Word Multiply (R = 1).
  | SMMULR = 227
  /// Signed Dual Multiply Add.
  | SMUAD = 228
  /// Signed Dual Multiply Add (M = 1).
  | SMUADX = 229
  /// Signed Multiply (Halfwords).
  | SMULBB = 230
  /// Signed Multiply (Halfwords).
  | SMULBT = 231
  /// Signed Multiply Long.
  | SMULL = 232
  /// Signed Multiply Long and update the flags.
  | SMULLS = 233
  /// Signed Multiply Long (Halfwords).
  | SMULTB = 234
  /// Signed Multiply Long (Halfwords).
  | SMULTT = 235
  /// Signed Multiply Accumulate (Word by halfword).
  | SMULWB = 236
  /// Signed Multiply Accumulate (Word by halfword).
  | SMULWT = 237
  /// Signed Dual Multiply Subtract.
  | SMUSD = 238
  /// Signed Dual Multiply Subtract (M = 1).
  | SMUSDX = 239
  /// Store Return State.
  | SRS = 240
  /// Store Return State. Decrement After.
  | SRSDA = 241
  /// Store Return State. Decrement Before.
  | SRSDB = 242
  /// Store Return State. Increment After.
  | SRSIA = 243
  /// Store Return State. Increment Before.
  | SRSIB = 244
  /// Signed Saturate.
  | SSAT = 245
  /// Signed Saturate, two 16-bit.
  | SSAT16 = 246
  /// Subtract and Add with Exchange, 16-bit.
  | SSAX = 247
  /// Speculative Store Bypass Barrier.
  | SSBB = 248
  /// Subtract 16-bit.
  | SSUB16 = 249
  /// Subtract 8-bit.
  | SSUB8 = 250
  /// Store Coprocessor (T1/A1).
  | STC = 251
  /// Store Coprocessor (T2/A2).
  | STC2 = 252
  /// Store Coprocessor (T2/A2) (D == 1).
  | STC2L = 253
  /// Store Coprocessor (T1/A1) (D == 1).
  | STCL = 254
  /// Store-Release Word.
  | STL = 255
  /// Store-Release Byte.
  | STLB = 256
  /// Store-Release Exclusive Word.
  | STLEX = 257
  /// Store-Release Exclusive Byte.
  | STLEXB = 258
  /// Store-Release Exclusive Doubleword.
  | STLEXD = 259
  /// Store-Release Exclusive Halfword.
  | STLEXH = 260
  /// Store-Release Halfword.
  | STLH = 261
  /// Store Multiple.
  | STM = 262
  /// Store Multiple. Decrement After.
  | STMDA = 263
  /// Store Multiple. Decrement Before.
  | STMDB = 264
  /// Store Multiple. Increment After.
  | STMEA = 265
  /// Store Multiple. Increment After.
  | STMIA = 266
  /// Store Multiple. Increment Before.
  | STMIB = 267
  /// Store Register.
  | STR = 268
  /// Store Register Byte.
  | STRB = 269
  /// Store Register Byte Unprivileged.
  | STRBT = 270
  /// Store Register Dual.
  | STRD = 271
  /// Store Register Exclusive.
  | STREX = 272
  /// Store Register Exclusive Byte.
  | STREXB = 273
  /// Store Register Exclusive Doubleword.
  | STREXD = 274
  /// Store Register Exclusive Halfword.
  | STREXH = 275
  /// Store Register Halfword.
  | STRH = 276
  /// Store Register Halfword Unprivileged.
  | STRHT = 277
  /// Store Register Unprivileged.
  | STRT = 278
  /// Subtract.
  | SUB = 279
  /// Subtract and update the flags.
  | SUBS = 280
  /// Subtract Wide.
  | SUBW = 281
  /// Supervisor Call.
  | SVC = 282
  /// Swap Word.
  | SWP = 283
  /// Swap Byte.
  | SWPB = 284
  /// Signed Extend and Add Byte.
  | SXTAB = 285
  /// Signed Extend and Add Byte 16.
  | SXTAB16 = 286
  /// Signed Extend and Add Halfword.
  | SXTAH = 287
  /// Signed Extend Byte.
  | SXTB = 288
  /// Signed Extend Byte 16.
  | SXTB16 = 289
  /// Signed Extend Halfword.
  | SXTH = 290
  /// Table Branch (byte offsets).
  | TBB = 291
  /// Table Branch (halfword offsets).
  | TBH = 292
  /// Test Equivalence.
  | TEQ = 293
  /// Trace Synchronization Barrier.
  | TSB = 294
  /// Test performs a bitwise AND operation.
  | TST = 295
  /// Add 16-bit.
  | UADD16 = 296
  /// Add 8-bit.
  | UADD8 = 297
  /// Add and Subtract with Exchange, 16-bit.
  | UASX = 298
  /// Unsigned Bit Field Extract.
  | UBFX = 299
  /// Permanently UNDEFINED.
  | UDF = 300
  /// Unsigned Divide.
  | UDIV = 301
  /// Halving Add 16-bit.
  | UHADD16 = 302
  /// Halving Add 8-bit.
  | UHADD8 = 303
  /// Halving Add and Subtract with Exchange, 16-bit.
  | UHASX = 304
  /// Halving Subtract and Add with Exchange, 16-bit.
  | UHSAX = 305
  /// Halving Subtract 16-bit.
  | UHSUB16 = 306
  /// Halving Add 8-bit.
  | UHSUB8 = 307
  /// Unsigned Multiply Accumulate Accumulate Long.
  | UMAAL = 308
  /// Unsigned Multiply Accumulate Long.
  | UMLAL = 309
  /// Unsigned Multiply Accumulate Long and update the flags.
  | UMLALS = 310
  /// Unsigned Multiply Long.
  | UMULL = 311
  /// Unsigned Multiply Long and update the flags.
  | UMULLS = 312
  /// Saturating Add 16-bit.
  | UQADD16 = 313
  /// Saturating Add 8-bit.
  | UQADD8 = 314
  /// Saturating Add and Subtract with Exchange, 16-bit.
  | UQASX = 315
  /// Saturating Subtract and Add with Exchange, 16-bit.
  | UQSAX = 316
  /// Saturating Subtract 16-bit.
  | UQSUB16 = 317
  /// Saturating Subtract 8-bit.
  | UQSUB8 = 318
  /// Unsigned Sum of Absolute Differences.
  | USAD8 = 319
  /// Unsigned Sum of Absolute Differences, Accumulate.
  | USADA8 = 320
  /// Unsigned Saturate.
  | USAT = 321
  /// Unsigned Saturate, two 16-bit.
  | USAT16 = 322
  /// Subtract and Add with Exchange, 16-bit.
  | USAX = 323
  /// Subtract 16-bit.
  | USUB16 = 324
  /// Subtract 8-bit.
  | USUB8 = 325
  /// Unsigned Extend and Add Byte.
  | UXTAB = 326
  /// Unsigned Extend and Add Byte 16.
  | UXTAB16 = 327
  /// Unsigned Extend and Add Halfword.
  | UXTAH = 328
  /// Unsigned Extend Byte.
  | UXTB = 329
  /// Unsigned Extend Byte 16.
  | UXTB16 = 330
  /// Unsigned Extend Halfword.
  | UXTH = 331
  /// Vector Absolute Difference and Accumulate.
  | VABA = 332
  /// Vector Absolute Difference and Accumulate (T2/A2).
  | VABAL = 333
  /// Vector Absolute Difference.
  | VABD = 334
  /// Vector Absolute Difference (T2/A2).
  | VABDL = 335
  /// Vector Absolute.
  | VABS = 336
  /// Vector Absolute Compare Greater or Less Than (or Equal).
  | VACGE = 337
  /// Vector Absolute Compare Greater or Less Than (or Equal).
  | VACGT = 338
  /// Vector Absolute Compare Greater or Less Than (or Equal).
  | VACLE = 339
  /// Vector Absolute Compare Greater or Less Than (or Equal).
  | VACLT = 340
  /// Vector Add.
  | VADD = 341
  /// Vector Add and Narrow, returning High Half.
  | VADDHN = 342
  /// Vector Add Long.
  | VADDL = 343
  /// Vector Add Wide.
  | VADDW = 344
  /// Vector Bitwise AND.
  | VAND = 345
  /// Vector Bitwise Bit Clear, AND complement.
  | VBIC = 346
  /// Vector Bitwise Select. Bitwise Insert if False, encoded as op = 0b11.
  | VBIF = 347
  /// Vector Bitwise Select. Bitwise Insert if True, encoded as op = 0b10.
  | VBIT = 348
  /// Vector Bitwise Select. Bitwise Select, encoded as op = 0b01.
  | VBSL = 349
  /// Vector Complex Add.
  | VCADD = 350
  /// Vector Compare Equal.
  | VCEQ = 351
  /// Vector Compare Greater Than or Equal.
  | VCGE = 352
  /// Vector Compare Greater Than.
  | VCGT = 353
  /// Vector Compare Less Than or Equal to Zero.
  | VCLE = 354
  /// Vector Count Leading Sign Bits.
  | VCLS = 355
  /// Vector Compare Less Than Zero.
  | VCLT = 356
  /// Vector Count Leading Zeros.
  | VCLZ = 357
  /// Vector Complex Multiply Accumulate.
  | VCMLA = 358
  /// Vector Compare. (Encoded as E = 0).
  | VCMP = 359
  /// Vector Compare. (Encoded as E = 1).
  | VCMPE = 360
  /// Vector Count.
  | VCNT = 361
  /// Vector Convert.
  | VCVT = 362
  /// Convert floating-point to integer with Round to Nearest with Ties to Away.
  | VCVTA = 363
  /// Convert between half-precision and single-precision.
  | VCVTB = 364
  /// Convert floating-point to integer with Round towards Minus Infinity.
  | VCVTM = 365
  /// Convert floating-point to integer with Round to Nearest.
  | VCVTN = 366
  /// Convert floating-point to integer with Round towards Plus Infinity.
  | VCVTP = 367
  /// Vector Convert floating-point to integer.
  | VCVTR = 368
  /// Convert between half-precision and single-precision.
  | VCVTT = 369
  /// Vector Divide.
  | VDIV = 370
  /// BFloat16 floating-point (BF16) dot product (vector).
  | VDOT = 371
  /// Vector Duplicate.
  | VDUP = 372
  /// Vector Bitwise Exclusive OR.
  | VEOR = 373
  /// Vector Extract.
  | VEXT = 374
  /// Vector Fused Multiply Accumulate.
  | VFMA = 375
  /// BFloat16 floating-point widening multiply-add.
  | VFMAB = 376
  /// Vector Floating-point Multiply-Add Long to accumulator.
  | VFMAL = 377
  /// BFloat16 floating-point widening multiply-add.
  | VFMAT = 378
  /// Vector Fused Multiply Subtract.
  | VFMS = 379
  /// Vector Floating-Point Multiply-Subtract Long.
  | VFMSL = 380
  /// Vector Fused Negate Multiply Accumulate.
  | VFNMA = 381
  /// Vector Fused Negate Multiply Subtract.
  | VFNMS = 382
  /// Vector Halving Add.
  | VHADD = 383
  /// Vector Halving Subtract.
  | VHSUB = 384
  /// Vector move Insertion.
  | VINS = 385
  /// FP Javascript convert to signed fixed-point, rounding toward zero.
  | VJCVT = 386
  /// Vector Load. (multiple single elements).
  | VLD1 = 387
  /// Vector Load. (multiple 2-element structures).
  | VLD2 = 388
  /// Vector Load. (multiple 3-element structures).
  | VLD3 = 389
  /// Vector Load. (multiple 4-element structures).
  | VLD4 = 390
  /// Vector Load Multiple.
  | VLDM = 391
  /// Vector Load Multiple. Decrement Before.
  | VLDMDB = 392
  /// Vector Load Multiple. Increment After.
  | VLDMIA = 393
  /// Vector Load Register.
  | VLDR = 394
  /// Vector Maximum.
  | VMAX = 395
  /// Floating-point Maximum Number.
  | VMAXNM = 396
  /// Vector Minimum.
  | VMIN = 397
  /// Floating-point Minimum Number.
  | VMINNM = 398
  /// Vector Multiply Accumulate.
  | VMLA = 399
  /// Vector Multiply Accumulate (T2/A2).
  | VMLAL = 400
  /// Vector Multiply Subtract.
  | VMLS = 401
  /// Vector Multiply Subtract (T2/A2).
  | VMLSL = 402
  /// BFloat16 floating-point matrix multiply-accumulate.
  | VMMLA = 403
  /// Vector Move.
  | VMOV = 404
  /// Vector Move Long.
  | VMOVL = 405
  /// Vector Move and Narrow.
  | VMOVN = 406
  /// Vector Move extraction.
  | VMOVX = 407
  /// Move to ARM core register from Floating-point Special register.
  | VMRS = 408
  /// Move to Floating-point Special register from ARM core register.
  | VMSR = 409
  /// Vector Multiply.
  | VMUL = 410
  /// Vector Multiply Long.
  | VMULL = 411
  /// Vector Bitwise NOT.
  | VMVN = 412
  /// Vector Negate.
  | VNEG = 413
  /// Vector Negate Multiply Accumulate or Subtract.
  | VNMLA = 414
  /// Vector Negate Multiply Accumulate or Subtract.
  | VNMLS = 415
  /// Vector Negate Multiply Accumulate or Subtract.
  | VNMUL = 416
  /// Vector Bitwise OR NOT.
  | VORN = 417
  /// Vector Bitwise OR, if source registers differ.
  | VORR = 418
  /// Vector Pairwise Add and Accumulate Long.
  | VPADAL = 419
  /// Vector Pairwise Add.
  | VPADD = 420
  /// Vector Pairwise Add Long.
  | VPADDL = 421
  /// Vector Pairwise Maximum.
  | VPMAX = 422
  /// Vector Pairwise Minimum.
  | VPMIN = 423
  /// Vector Pop Registers.
  | VPOP = 424
  /// Vector Push Registers.
  | VPUSH = 425
  /// Vector Saturating Absolute.
  | VQABS = 426
  /// Vector Saturating Add.
  | VQADD = 427
  /// Vector Saturating Doubling Multiply Accumulate Long.
  | VQDMLAL = 428
  /// Vector Saturating Doubling Multiply Subtract Long.
  | VQDMLSL = 429
  /// Vector Saturating Doubling Multiply returning High Half.
  | VQDMULH = 430
  /// Vector Saturating Doubling Multiply Long.
  | VQDMULL = 431
  /// Vector Saturating Move and Unsigned Narrow (op <> 0b01).
  | VQMOVN = 432
  /// Vector Saturating Move and Unsigned Narrow (op = 0b01).
  | VQMOVUN = 433
  /// Vector Saturating Negate.
  | VQNEG = 434
  /// Vector Saturating Rounding Doubling Mul Accumulate Returning High Half.
  | VQRDMLAH = 435
  /// Vector Saturating Rounding Doubling Multiply Subtract Returning High Half.
  | VQRDMLSH = 436
  /// Vector Saturating Rounding Doubling Multiply returning High Half.
  | VQRDMULH = 437
  /// Vector Saturating Rounding Shift Left.
  | VQRSHL = 438
  /// Vector Saturating Shift Right, Rounded Unsigned Narrow.
  | VQRSHRN = 439
  /// Vector Saturating Shift Right, Rounded Unsigned Narrow.
  | VQRSHRUN = 440
  /// Vector Saturating Shift Left.
  | VQSHL = 441
  /// Vector Saturating Shift Left.
  | VQSHLU = 442
  /// Vector Saturating Shift Right, Narrow.
  | VQSHRN = 443
  /// Vector Saturating Shift Right, Narrow.
  | VQSHRUN = 444
  /// Vector Saturating Subtract.
  | VQSUB = 445
  /// Vector Rounding Add and Narrow, returning High Half.
  | VRADDHN = 446
  /// Vector Reciprocal Estimate.
  | VRECPE = 447
  /// Vector Reciprocal Step.
  | VRECPS = 448
  /// Vector Reverse in halfwords.
  | VREV16 = 449
  /// Vector Reverse in words.
  | VREV32 = 450
  /// Vector Reverse in doublewords.
  | VREV64 = 451
  /// Vector Rounding Halving Add.
  | VRHADD = 452
  /// Vector Round floating-point to integer towards Nearest with Ties to Away.
  | VRINTA = 453
  /// Vector Round floating-point to integer towards Minus Infinity.
  | VRINTM = 454
  /// Vector Round floating-point to integer to Nearest.
  | VRINTN = 455
  /// Vector Round floating-point to integer towards Plus Infinity.
  | VRINTP = 456
  /// Vector Round floating-point to integer rounds.
  | VRINTR = 457
  /// Vector round floating-point to integer to nearest signaling inexactness.
  | VRINTX = 458
  /// Vector round floating-point to integer towards Zero.
  | VRINTZ = 459
  /// Vector Rounding Shift Left.
  | VRSHL = 460
  /// Vector Rounding Shift Right.
  | VRSHR = 461
  /// Vector Rounding Shift Right Narrow.
  | VRSHRN = 462
  /// Vector Reciprocal Square Root Estimate.
  | VRSQRTE = 463
  /// Vector Reciprocal Square Root Step.
  | VRSQRTS = 464
  /// Vector Rounding Shift Right and Accumulate.
  | VRSRA = 465
  /// Vector Rounding Subtract and Narrow, returning High Half.
  | VRSUBHN = 466
  /// Dot Product vector form with signed integers.
  | VSDOT = 467
  /// Floating-point conditional select.
  | VSELEQ = 468
  /// Floating-point conditional select.
  | VSELGE = 469
  /// Floating-point conditional select.
  | VSELGT = 470
  /// Floating-point conditional select.
  | VSELVS = 471
  /// Vector Shift Left.
  | VSHL = 472
  /// Vector Shift Left Long.
  | VSHLL = 473
  /// Vector Shift Right.
  | VSHR = 474
  /// Vector Shift Right Narrow.
  | VSHRN = 475
  /// Vector Shift Left and Insert.
  | VSLI = 476
  /// The widening integer matrix multiply-accumulate instruction.
  | VSMMLA = 477
  /// Vector Square Root.
  | VSQRT = 478
  /// Vector Shift Right and Accumulate.
  | VSRA = 479
  /// Vector Shift Right and Insert.
  | VSRI = 480
  /// Vector Store. (multiple single elements).
  | VST1 = 481
  /// Vector Store. (multiple 2-element structures).
  | VST2 = 482
  /// Vector Store. (multiple 3-element structures).
  | VST3 = 483
  /// Vector Store. (multiple 4-element structures).
  | VST4 = 484
  /// Vector Store Multiple.
  | VSTM = 485
  /// Vector Store Multiple. Decrement Before.
  | VSTMDB = 486
  /// Vector Store Multiple. Increment After.
  | VSTMIA = 487
  /// Vector Store Register.
  | VSTR = 488
  /// Vector Subtract.
  | VSUB = 489
  /// Vector Subtract and Narrow, returning High Half.
  | VSUBHN = 490
  /// Vector Subtract Long.
  | VSUBL = 491
  /// Vector Subtract Wide.
  | VSUBW = 492
  /// Dot Product index form with signed and unsigned integers.
  | VSUDOT = 493
  /// Vector Swap.
  | VSWP = 494
  /// Vector Table Lookup.
  | VTBL = 495
  /// Vector Table Extension.
  | VTBX = 496
  /// Vector Transpose.
  | VTRN = 497
  /// Vector Test Bits.
  | VTST = 498
  /// Dot Product index form with unsigned integers.
  | VUDOT = 499
  /// Widening 8-bit unsigned int matrix multiply-accumulate into 2x2 matrix.
  | VUMMLA = 500
  /// Dot Product index form with unsigned and signed integers.
  | VUSDOT = 501
  /// Widening 8-bit mixed sign int matrix multiply-accumulate into 2x2 matrix.
  | VUSMMLA = 502
  /// Vector Unzip.
  | VUZP = 503
  /// Vector Zip.
  | VZIP = 504
  /// Wait For Event hint.
  | WFE = 505
  /// Wait For Interrupt hint.
  | WFI = 506
  /// Yield hint.
  | YIELD = 507
  /// Invalid Opcode.
  | InvalidOP = 508

type internal Op = Opcode

type internal PSR =
  | Cond = 0
  | N = 1
  | Z = 2
  | C = 3
  | V = 4
  | Q = 5
  | IT10 = 6
  | J = 7
  | GE = 8
  | IT72 = 9
  | E = 10
  | A = 11
  | I = 12
  | F = 13
  | T = 14
  | M = 15

[<Struct>]
type internal SCTLR =
  | SCTLR_NMFI

[<Struct>]
type internal SCR =
  | SCR_AW
  | SCR_FW
  | SCR_NS

[<Struct>]
type internal NSACR =
  | NSACR_RFR

type BarrierOption =
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

[<Struct>]
type Iflag =
  | A
  | I
  | F
  | AI
  | AF
  | IF
  | AIF

[<Struct>]
type internal SIMDVFPRegisterSpacing =
  | Single
  | Double

[<Struct>]
type SRType =
  | SRTypeLSL
  | SRTypeLSR
  | SRTypeASR
  | SRTypeROR
  | SRTypeRRX

/// A8.2 Standard assembler syntax fields
[<Struct>]
type Qualifier =
  /// Wide.
  | W
  /// Narrow (defalut).
  | N

/// A2.6.3 Data types supported by the Advanced SIMD Extension
[<Struct>]
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
  | SIMDTypP64
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
  | Vector of Register.ARM32
  | Scalar of Register.ARM32 * Element option
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
  | ImmOffset of Register.ARM32 * Sign option * Const option
  | RegOffset of Register.ARM32 * Sign option * Register.ARM32 * Shift option
  | AlignOffset of Register.ARM32
                 * Align option
                 * Register.ARM32 option (* Advanced SIMD *)

type AddressingMode =
  | OffsetMode of Offset
  | PreIdxMode of Offset
  | PostIdxMode of Offset
  | UnIdxMode of Register.ARM32 * Const (* [<Rn>], <option> *)
  | LiteralMode of Label

type Operand =
  | OprReg of Register.ARM32
  | OprSpecReg of Register.ARM32 * PSRFlag option
  | OprRegList of Register.ARM32 list
  | OprSIMD of SIMDOperand
  | OprImm of Const
  | OprFPImm of float
  | OprShift of Shift
  | OprRegShift of SRType * Register.ARM32
  | OprMemory of AddressingMode
  | OprOption of BarrierOption
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
[<AbstractClass>]
type ARM32InternalInstruction
  (addr, nb, cond, op, opr, its, wb, q, s, m, cf, oSz, isAdd) =
  inherit Instruction (addr, nb, WordSize.Bit32)

  /// Condition.
  member __.Condition with get(): Condition = cond

  /// Opcode.
  member __.Opcode with get(): Opcode = op

  /// Operands.
  member __.Operands with get(): Operands = opr

  /// IT state for this instruction (used only for IT instructions).
  member __.ITState with get(): byte = its

  /// Write back.
  member __.WriteBack with get(): bool = wb

  /// Qualifier.
  member __.Qualifier with get(): Qualifier = q

  /// SIMD data type.
  member __.SIMDTyp with get(): SIMDDataTypes option = s

  /// Target architecture mode.
  member __.Mode with get(): ArchOperationMode = m

  /// Carry Flag from decoding instruction.
  member __.Cflag with get(): bool option = cf

  /// Operation size.
  member __.OprSize with get(): RegType = oSz

  /// Add or subtract offsets.
  member __.IsAdd with get(): bool = isAdd

  override __.ToString () =
    $"Condition: {cond}{System.Environment.NewLine}\
      Opcode: {op}{System.Environment.NewLine}\
      Operands: {opr}{System.Environment.NewLine}\
      ITState: {its}{System.Environment.NewLine}\
      WriteBack: {wb}{System.Environment.NewLine}\
      Qualifier: {q}{System.Environment.NewLine}\
      SIMD: {s}{System.Environment.NewLine}\
      Mode: {m}{System.Environment.NewLine}\
      Cflag: {cf}{System.Environment.NewLine}\"
      OprSize: {oSz}{System.Environment.NewLine}\"
      IsAdd: {isAdd}{System.Environment.NewLine}"

type internal InsInfo = ARM32InternalInstruction
