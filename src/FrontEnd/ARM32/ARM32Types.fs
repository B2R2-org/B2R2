(*
    B2R2 - the Next-Generation Reversing Platform

    Author: Seung Il Jung <sijung@kaist.ac.kr>
                    DongYeop Oh <oh51dy@kaist.ac.kr>

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

namespace B2R2.FrontEnd.ARM32

open B2R2
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.Tests")>]
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
    /// Debug hint.
    | DBG = 41
    /// Data Memory Barrier.
    | DMB = 42
    /// Data Synchronization Barrier.
    | DSB = 43
    /// Enter ThumbEE state.
    | ENTERX = 44
    /// Bitwise Exclusive OR.
    | EOR = 45
    /// Bitwise Exclusive OR and update the flags.
    | EORS = 46
    /// Exception Return.
    | ERET = 47
    /// Stores multiple SIMD&FP registers .
    | FSTMDBX = 48
    /// Stores multiple SIMD&FP registers .
    | FSTMIAX = 49
    /// Halt Instruction.
    | HLT = 50
    /// Hypervisor Call.
    | HVC = 51
    /// Instruction Synchronization Barrier.
    | ISB = 52
    // If-Then.
    | IT = 53
    // If-Then.
    | ITE = 54
    // If-Then.
    | ITEE = 55
    // If-Then.
    | ITEEE = 56
    // If-Then.
    | ITEET = 57
    // If-Then.
    | ITET = 58
    // If-Then.
    | ITETE = 59
    // If-Then.
    | ITETT = 60
    // If-Then.
    | ITT = 61
    // If-Then.
    | ITTE = 62
    // If-Then.
    | ITTEE = 63
    // If-Then.
    | ITTET = 64
    // If-Then.
    | ITTT = 65
    // If-Then.
    | ITTTE = 66
    // If-Then.
    | ITTTT = 67
    /// Load-Acquire Word.
    | LDA = 68
    /// Load-Acquire Byte.
    | LDAB = 69
    /// Load-Acquire Exclusive Word.
    | LDAEX = 70
    /// Load-Acquire Exclusive Byte.
    | LDAEXB = 71
    /// Load-Acquire Exclusive Double.
    | LDAEXD = 72
    /// Load-Acquire Exclusive Halfword.
    | LDAEXH = 73
    /// Load-Acquire Halfword.
    | LDAH = 74
    /// Load Coprocessor.
    | LDC = 75
    /// Load Coprocessor.
    | LDC2 = 76
    /// Load Coprocessor.
    | LDC2L = 77
    /// Load Coprocessor.
    | LDCL = 78
    /// Load Multiple.
    | LDM = 79
    /// Load Multiple. Decrement After.
    | LDMDA = 80
    /// Load Multiple. Decrement Before.
    | LDMDB = 81
    /// Load Multiple. Increment After.
    | LDMIA = 82
    /// Load Multiple. Increment Before.
    | LDMIB = 83
    /// Load Register.
    | LDR = 84
    /// Load Register Byte.
    | LDRB = 85
    /// Load Register Byte Unprivileged.
    | LDRBT = 86
    /// Load Register Dual.
    | LDRD = 87
    /// Load Register Exclusive.
    | LDREX = 88
    /// Load Register Exclusive Byte
    | LDREXB = 89
    /// Load Register Exclusive Doubleword.
    | LDREXD = 90
    /// Load Register Exclusive Halfword.
    | LDREXH = 91
    /// Load Register Halfword.
    | LDRH = 92
    /// Load Register Halfword Unprivileged.
    | LDRHT = 93
    /// Load Register Signed Byte.
    | LDRSB = 94
    /// Load Register Signed Byte Unprivileged.
    | LDRSBT = 95
    /// Load Register Signed Halfword.
    | LDRSH = 96
    /// Load Register Signed Halfword Unprivileged.
    | LDRSHT = 97
    /// Load Register Unprivileged.
    | LDRT = 98
    /// Exit ThumbEE state.
    | LEAVEX = 99
    /// Logical Shift Left.
    | LSL = 100
    /// Logical Shift Left and OutSide IT block.
    | LSLS = 101
    /// Logical Shift Right.
    | LSR = 102
    /// Logical Shift Right and OutSide IT block.
    | LSRS = 103
    /// Move to Coprocessor from ARM core register (T1/A1).
    | MCR = 104
    /// Move to Coprocessor from ARM core register (T2/A2).
    | MCR2 = 105
    /// Move to Coprocessor from two ARM core registers (T1/A1).
    | MCRR = 106
    /// Move to Coprocessor from two ARM core registers (T2/A2).
    | MCRR2 = 107
    /// Multiply Accumulate.
    | MLA = 108
    /// Multiply Accumulate and update the flags.
    | MLAS = 109
    /// Multiply and Subtract.
    | MLS = 110
    /// Move.
    | MOV = 111
    /// Move and update the flags.
    | MOVS = 112
    /// Move Top (16-bit).
    | MOVT = 113
    /// Move (Only encoding T3 or A2 permitted).
    | MOVW = 114
    /// Move to ARM core register from Coprocessor (T1/A1).
    | MRC = 115
    /// Move to ARM core register from Coprocessor (T2/A2).
    | MRC2 = 116
    /// Move to two ARM core registers from Coprocessor (T1/A1).
    | MRRC = 117
    /// Move to two ARM core registers from Coprocessor (T2/A2).
    | MRRC2 = 118
    /// Move from Banked or Special register.
    | MRS = 119
    /// Move to Special register, Application level.
    | MSR = 120
    /// Multiply.
    | MUL = 121
    /// Multiply and update the flags.
    | MULS = 122
    /// Bitwise NOT.
    | MVN = 123
    /// Bitwise NOT and update the flags.
    | MVNS = 124
    /// No Operation.
    | NOP = 125
    /// Bitwise OR NOT.
    | ORN = 126
    /// Bitwise OR NOT and update the flags.
    | ORNS = 127
    /// Bitwise OR.
    | ORR = 128
    /// Bitwise OR and update the flags.
    | ORRS = 129
    /// Pack Halfword (tbform == FALSE).
    | PKHBT = 130
    /// Pack Halfword (tbform == TRUE).
    | PKHTB = 131
    /// Preload Data.
    | PLD = 132
    /// Preload Data (W = 1 in Thumb or R = 0 in ARM).
    | PLDW = 133
    /// Preload Instruction.
    | PLI = 134
    /// Pop Multiple Registers.
    | POP = 135
    /// Push Multiple Registers.
    | PUSH = 136
    /// Saturating Add.
    | QADD = 137
    /// Saturating Add 16-bit.
    | QADD16 = 138
    /// Saturating Add 8-bit.
    | QADD8 = 139
    /// Saturating Add and Subtract with Exchange, 16-bit.
    | QASX = 140
    /// Saturating Double and Add.
    | QDADD = 141
    /// Saturating Double and Subtract.
    | QDSUB = 142
    /// Saturating Subtract and Add with Exchange, 16-bit.
    | QSAX = 143
    /// Saturating Subtract.
    | QSUB = 144
    /// Saturating Subtract 16-bit.
    | QSUB16 = 145
    /// Saturating Add 8-bit.
    | QSUB8 = 146
    /// Reverse Bits.
    | RBIT = 147
    /// Byte-Reverse Word.
    | REV = 148
    /// Byte-Reverse Packed Halfword.
    | REV16 = 149
    /// Byte-Reverse Signed Halfword.
    | REVSH = 150
    /// Return From Exception.
    | RFE = 151
    /// Return From Exception. Decrement After.
    | RFEDA = 152
    /// Return From Exception. Decrement Before.
    | RFEDB = 153
    /// Return From Exception. Increment After.
    | RFEIA = 154
    /// Return From Exception. Increment Before.
    | RFEIB = 155
    /// Rotate Right.
    | ROR = 156
    /// Rotate Right and update the flags.
    | RORS = 157
    /// Rotate Right with Extend.
    | RRX = 158
    /// Rotate Right with Extend and update the flags.
    | RRXS = 159
    /// Reverse Subtract.
    | RSB = 160
    /// Reverse Subtract and update the flags.
    | RSBS = 161
    /// Reverse Subtract with Carry.
    | RSC = 162
    /// Reverse Subtract with Carry and update the flags.
    | RSCS = 163
    /// Add 16-bit.
    | SADD16 = 164
    /// Add 8-bit.
    | SADD8 = 165
    /// Add and Subtract with Exchange, 16-bit.
    | SASX = 166
    /// Subtract with Carry.
    | SBC = 167
    /// Subtract with Carry and update the flags.
    | SBCS = 168
    /// Signed Bit Field Extract.
    | SBFX = 169
    /// Signed Divide.
    | SDIV = 170
    /// Select Bytes.
    | SEL = 171
    /// Set Endianness.
    | SETEND = 172
    /// Send Event.
    | SEV = 173
    /// Send Event Local is a hint instruction.
    | SEVL = 174
    /// SHA1 fixed rotate.
    | SHA1H = 175
    /// SHA1 schedule update 1.
    | SHA1SU1 = 176
    /// SHA256 schedule update 0.
    | SHA256SU0 = 177
    /// Halving Add 16-bit.
    | SHADD16 = 178
    /// Halving Add 8-bit.
    | SHADD8 = 179
    /// Halving Add and Subtract with Exchange, 16-bit.
    | SHASX = 180
    /// Halving Subtract and Add with Exchange, 16-bit.
    | SHSAX = 181
    /// Halving Subtract 16-bit.
    | SHSUB16 = 182
    /// Halving Subtract 8-bit.
    | SHSUB8 = 183
    /// Secure Monitor Call.
    | SMC = 184
    /// Signed Multiply Accumulate (Halfwords).
    | SMLABB = 185
    /// Signed Multiply Accumulate (Halfwords).
    | SMLABT = 186
    /// Signed Multiply Accumulate Dual.
    | SMLAD = 187
    /// Signed Multiply Accumulate Dual (M = 1).
    | SMLADX = 188
    /// Signed Multiply Accumulate Long.
    | SMLAL = 189
    /// Signed Multiply Accumulate Long (Halfwords).
    | SMLALBB = 190
    /// Signed Multiply Accumulate Long (Halfwords).
    | SMLALBT = 191
    /// Signed Multiply Accumulate Long Dual.
    | SMLALD = 192
    /// /// Signed Multiply Accumulate Long Dual (M = 1).
    | SMLALDX = 193
    /// Signed Multiply Accumulate Long and update the flags.
    | SMLALS = 194
    /// Signed Multiply Accumulate Long.
    | SMLALTB = 195
    /// Signed Multiply Accumulate Long (Halfwords).
    | SMLALTT = 196
    /// Signed Multiply Accumulate (Halfwords).
    | SMLATB = 197
    /// Signed Multiply Accumulate (Halfwords).
    | SMLATT = 198
    /// Signed Multiply Accumulate (Word by halfword).
    | SMLAWB = 199
    /// Signed Multiply Accumulate.
    | SMLAWT = 200
    /// Signed Multiply Subtract Dual.
    | SMLSD = 201
    /// Signed Multiply Subtract Dual (M = 1).
    | SMLSDX = 202
    /// Signed Multiply Subtract Long Dual.
    | SMLSLD = 203
    /// Signed Multiply Subtract Long Dual (M = 1).
    | SMLSLDX = 204
    /// Signed Most Significant Word Multiply Accumulate.
    | SMMLA = 205
    /// Signed Most Significant Word Multiply Accumulate (R = 1).
    | SMMLAR = 206
    /// Signed Most Significant Word Multiply Subtract.
    | SMMLS = 207
    /// Signed Most Significant Word Multiply Subtract (R = 1).
    | SMMLSR = 208
    /// Signed Most Significant Word Multiply.
    | SMMUL = 209
    /// Signed Most Significant Word Multiply (R = 1).
    | SMMULR = 210
    /// Signed Dual Multiply Add.
    | SMUAD = 211
    /// Signed Dual Multiply Add (M = 1).
    | SMUADX = 212
    /// Signed Multiply (Halfwords).
    | SMULBB = 213
    /// Signed Multiply (Halfwords).
    | SMULBT = 214
    /// Signed Multiply Long.
    | SMULL = 215
    /// Signed Multiply Long and update the flags.
    | SMULLS = 216
    /// Signed Multiply Long (Halfwords).
    | SMULTB = 217
    /// Signed Multiply Long (Halfwords).
    | SMULTT = 218
    /// Signed Multiply Accumulate (Word by halfword).
    | SMULWB = 219
    /// Signed Multiply Accumulate (Word by halfword).
    | SMULWT = 220
    /// Signed Dual Multiply Subtract.
    | SMUSD = 221
    /// Signed Dual Multiply Subtract (M = 1).
    | SMUSDX = 222
    /// Store Return State.
    | SRS = 223
    /// Store Return State. Decrement After.
    | SRSDA = 224
    /// Store Return State. Decrement Before.
    | SRSDB = 225
    /// Store Return State. Increment After.
    | SRSIA = 226
    /// Store Return State. Increment Before.
    | SRSIB = 227
    /// Signed Saturate.
    | SSAT = 228
    /// Signed Saturate, two 16-bit.
    | SSAT16 = 229
    /// Subtract and Add with Exchange, 16-bit
    | SSAX = 230
    /// Subtract 16-bit.
    | SSUB16 = 231
    /// Subtract 8-bit.
    | SSUB8 = 232
    /// Store Coprocessor (T1/A1).
    | STC = 233
    /// Store Coprocessor (T2/A2).
    | STC2 = 234
    /// Store Coprocessor (T2/A2) (D == 1).
    | STC2L = 235
    /// Store Coprocessor (T1/A1) (D == 1).
    | STCL = 236
    /// Store-Release Word.
    | STL = 237
    /// Store-Release Byte.
    | STLB = 238
    /// Store-Release Exclusive Word.
    | STLEX = 239
    /// Store-Release Exclusive Byte.
    | STLEXB = 240
    /// Store-Release Exclusive Doubleword.
    | STLEXD = 241
    /// Store-Release Exclusive Halfword.
    | STLEXH = 242
    /// Store-Release Halfword.
    | STLH = 243
    /// Store Multiple.
    | STM = 244
    /// Store Multiple. Decrement After.
    | STMDA = 245
    /// Store Multiple. Decrement Before.
    | STMDB = 246
    /// Store Multiple. Increment After.
    | STMEA = 247
    /// Store Multiple. Increment After.
    | STMIA = 248
    /// Store Multiple. Increment Before.
    | STMIB = 249
    /// Store Register.
    | STR = 250
    /// Store Register Byte.
    | STRB = 251
    /// Store Register Byte Unprivileged.
    | STRBT = 252
    /// Store Register Dual.
    | STRD = 253
    /// Store Register Exclusive.
    | STREX = 254
    /// Store Register Exclusive Byte.
    | STREXB = 255
    /// Store Register Exclusive Doubleword.
    | STREXD = 256
    /// Store Register Exclusive Halfword.
    | STREXH = 257
    /// Store Register Halfword.
    | STRH = 258
    /// Store Register Halfword Unprivileged.
    | STRHT = 259
    /// Store Register Unprivileged.
    | STRT = 260
    /// Subtract.
    | SUB = 261
    /// Subtract and update the flags.
    | SUBS = 262
    /// Subtract Wide.
    | SUBW = 263
    /// Supervisor Call.
    | SVC = 264
    /// Swap Word.
    | SWP = 265
    /// Swap Byte.
    | SWPB = 266
    /// Signed Extend and Add Byte.
    | SXTAB = 267
    /// Signed Extend and Add Byte 16.
    | SXTAB16 = 268
    /// Signed Extend and Add Halfword.
    | SXTAH = 269
    /// Signed Extend Byte.
    | SXTB = 270
    /// Signed Extend Byte 16.
    | SXTB16 = 271
    /// Signed Extend Halfword.
    | SXTH = 272
    /// Table Branch (byte offsets).
    | TBB = 273
    /// Table Branch (halfword offsets).
    | TBH = 274
    /// Test Equivalence.
    | TEQ = 275
    /// Test.
    | TST = 276
    /// Add 16-bit.
    | UADD16 = 277
    /// Add 8-bit.
    | UADD8 = 278
    /// Add and Subtract with Exchange, 16-bit.
    | UASX = 279
    /// Unsigned Bit Field Extract.
    | UBFX = 280
    /// Permanently UNDEFINED.
    | UDF = 281
    /// Unsigned Divide.
    | UDIV = 282
    /// Halving Add 16-bit.
    | UHADD16 = 283
    /// Halving Add 8-bit.
    | UHADD8 = 284
    /// Halving Add and Subtract with Exchange, 16-bit.
    | UHASX = 285
    /// Halving Subtract and Add with Exchange, 16-bit.
    | UHSAX = 286
    /// Halving Subtract 16-bit.
    | UHSUB16 = 287
    /// Halving Add 8-bit.
    | UHSUB8 = 288
    /// Unsigned Multiply Accumulate Accumulate Long.
    | UMAAL = 289
    /// Unsigned Multiply Accumulate Long.
    | UMLAL = 290
    /// Unsigned Multiply Accumulate Long and update the flags.
    | UMLALS = 291
    /// Unsigned Multiply Long.
    | UMULL = 292
    /// Unsigned Multiply Long and update the flags.
    | UMULLS = 293
    /// Saturating Add 16-bit.
    | UQADD16 = 294
    /// Saturating Add 8-bit.
    | UQADD8 = 295
    /// Saturating Add and Subtract with Exchange, 16-bit.
    | UQASX = 296
    /// Saturating Subtract and Add with Exchange, 16-bit.
    | UQSAX = 297
    /// Saturating Subtract 16-bit.
    | UQSUB16 = 298
    /// Saturating Subtract 8-bit.
    | UQSUB8 = 299
    /// Unsigned Sum of Absolute Differences.
    | USAD8 = 300
    /// Unsigned Sum of Absolute Differences, Accumulate.
    | USADA8 = 301
    /// Unsigned Saturate.
    | USAT = 302
    /// Unsigned Saturate, two 16-bit.
    | USAT16 = 303
    /// Subtract and Add with Exchange, 16-bit.
    | USAX = 304
    /// Subtract 16-bit.
    | USUB16 = 305
    /// Subtract 8-bit.
    | USUB8 = 306
    /// Unsigned Extend and Add Byte.
    | UXTAB = 307
    /// Unsigned Extend and Add Byte 16.
    | UXTAB16 = 308
    /// Unsigned Extend and Add Halfword.
    | UXTAH = 309
    /// Unsigned Extend Byte.
    | UXTB = 310
    /// Unsigned Extend Byte 16.
    | UXTB16 = 311
    /// Unsigned Extend Halfword.
    | UXTH = 312
    /// Vector Absolute Difference and Accumulate.
    | VABA = 313
    /// Vector Absolute Difference and Accumulate (T2/A2).
    | VABAL = 314
    /// Vector Absolute Difference.
    | VABD = 315
    /// Vector Absolute Difference (T2/A2).
    | VABDL = 316
    /// Vector Absolute.
    | VABS = 317
    /// Vector Absolute Compare Greater or Less Than (or Equal).
    | VACGE = 318
    /// Vector Absolute Compare Greater or Less Than (or Equal).
    | VACGT = 319
    /// Vector Absolute Compare Greater or Less Than (or Equal).
    | VACLE = 320
    /// Vector Absolute Compare Greater or Less Than (or Equal).
    | VACLT = 321
    /// Vector Add.
    | VADD = 322
    /// Vector Add and Narrow, returning High Half.
    | VADDHN = 323
    /// Vector Add Long.
    | VADDL = 324
    /// Vector Add Wide.
    | VADDW = 325
    /// Vector Bitwise AND.
    | VAND = 326
    /// Vector Bitwise Bit Clear, AND complement.
    | VBIC = 327
    /// Vector Bitwise Select. Bitwise Insert if False, encoded as op = 0b11.
    | VBIF = 328
    /// Vector Bitwise Select. Bitwise Insert if True, encoded as op = 0b10.
    | VBIT = 329
    /// Vector Bitwise Select. Bitwise Select, encoded as op = 0b01.
    | VBSL = 330
    /// Vector Compare Equal.
    | VCEQ = 331
    /// Vector Compare Greater Than or Equal.
    | VCGE = 332
    /// Vector Compare Greater Than.
    | VCGT = 333
    /// Vector Compare Less Than or Equal to Zero.
    | VCLE = 334
    /// Vector Count Leading Sign Bits.
    | VCLS = 335
    /// Vector Compare Less Than Zero.
    | VCLT = 336
    /// Vector Count Leading Zeros.
    | VCLZ = 337
    /// Vector Compare. (Encoded as E = 0)
    | VCMP = 338
    /// Vector Compare. (Encoded as E = 1).
    | VCMPE = 339
    /// Vector Count.
    | VCNT = 340
    /// Vector Convert.
    | VCVT = 341
    /// Convert floating-point to integer with Round to Nearest with Ties to Away.
    | VCVTA = 342
    /// Convert between half-precision and single-precision.
    | VCVTB = 343
    /// Convert floating-point to integer with Round towards Minus Infinity.
    | VCVTM = 344
    /// Convert floating-point to integer with Round to Nearest.
    | VCVTN = 345
    /// Convert floating-point to integer with Round towards Plus Infinity.
    | VCVTP = 346
    /// Vector Convert floating-point to integer.
    | VCVTR = 347
    /// Convert between half-precision and single-precision.
    | VCVTT = 348
    /// Vector Divide.
    | VDIV = 349
    /// Vector Duplicate.
    | VDUP = 350
    /// Vector Bitwise Exclusive OR
    | VEOR = 351
    /// Vector Extract.
    | VEXT = 352
    ///Vector Fused Multiply Accumulate.
    | VFMA = 353
    ///Vector Fused Multiply Subtract.
    | VFMS = 354
    /// Vector Fused Negate Multiply Accumulate.
    | VFNMA = 355
    /// Vector Fused Negate Multiply Subtract.
    | VFNMS = 356
    /// Vector Halving Add.
    | VHADD = 357
    /// Vector Halving Subtract.
    | VHSUB = 358
    /// Vector Load. (multiple single elements).
    | VLD1 = 359
    /// Vector Load. (multiple 2-element structures).
    | VLD2 = 360
    /// Vector Load. (multiple 3-element structures).
    | VLD3 = 361
    /// Vector Load. (multiple 4-element structures).
    | VLD4 = 362
    /// Vector Load Multiple.
    | VLDM = 363
    /// Vector Load Multiple. Decrement Before.
    | VLDMDB = 364
    /// Vector Load Multiple. Increment After.
    | VLDMIA = 365
    /// Vector Load Register.
    | VLDR = 366
    /// Vector Maximum.
    | VMAX = 367
    /// Vector Minimum.
    | VMIN = 368
    /// Vector Multiply Accumulate.
    | VMLA = 369
    /// Vector Multiply Accumulate (T2/A2).
    | VMLAL = 370
    /// Vector Multiply Subtract.
    | VMLS = 371
    /// Vector Multiply Subtract (T2/A2).
    | VMLSL = 372
    /// Vector Move.
    | VMOV = 373
    /// Vector Move Long.
    | VMOVL = 374
    /// Vector Move and Narrow.
    | VMOVN = 375
    /// Move to ARM core register from Floating-point Special register.
    | VMRS = 376
    /// Move to Floating-point Special register from ARM core register.
    | VMSR = 377
    /// Vector Multiply
    | VMUL = 378
    /// Vector Multiply Long.
    | VMULL = 379
    /// Vector Bitwise NOT.
    | VMVN = 380
    /// Vector Negate.
    | VNEG = 381
    /// Vector Negate Multiply Accumulate or Subtract.
    | VNMLA = 382
    /// Vector Negate Multiply Accumulate or Subtract.
    | VNMLS = 383
    /// Vector Negate Multiply Accumulate or Subtract.
    | VNMUL = 384
    /// Vector Bitwise OR NOT.
    | VORN = 385
    /// Vector Bitwise OR, if source registers differ.
    | VORR = 386
    /// Vector Pairwise Add and Accumulate Long.
    | VPADAL = 387
    /// Vector Pairwise Add.
    | VPADD = 388
    /// Vector Pairwise Add Long.
    | VPADDL = 389
    /// Vector Pairwise Maximum.
    | VPMAX = 390
    /// Vector Pairwise Minimum.
    | VPMIN = 391
    /// Vector Pop Registers.
    | VPOP = 392
    /// Vector Push Registers.
    | VPUSH = 393
    /// Vector Saturating Absolute.
    | VQABS = 394
    /// Vector Saturating Add.
    | VQADD = 395
    /// Vector Saturating Doubling Multiply Accumulate Long.
    | VQDMLAL = 396
    /// Vector Saturating Doubling Multiply Subtract Long.
    | VQDMLSL = 397
    /// Vector Saturating Doubling Multiply returning High Half.
    | VQDMULH = 398
    /// Vector Saturating Doubling Multiply Long.
    | VQDMULL = 399
    /// Vector Saturating Move and Unsigned Narrow (op <> 0b01).
    | VQMOVN = 400
    /// Vector Saturating Move and Unsigned Narrow (op = 0b01).
    | VQMOVUN = 401
    /// Vector Saturating Negate.
    | VQNEG = 402
    /// Vector Saturating Rounding Doubling Multiply returning High Half.
    | VQRDMULH = 403
    /// Vector Saturating Rounding Shift Left.
    | VQRSHL = 404
    /// Vector Saturating Shift Right, Rounded Unsigned Narrow.
    | VQRSHRN = 405
    /// Vector Saturating Shift Right, Rounded Unsigned Narrow.
    | VQRSHRUN = 406
    /// Vector Saturating Shift Left.
    | VQSHL = 407
    /// Vector Saturating Shift Left.
    | VQSHLU = 408
    /// Vector Saturating Shift Right, Narrow.
    | VQSHRN = 409
    /// Vector Saturating Shift Right, Narrow.
    | VQSHRUN = 410
    /// Vector Saturating Subtract.
    | VQSUB = 411
    /// Vector Rounding Add and Narrow, returning High Half.
    | VRADDHN = 412
    /// Vector Reciprocal Estimate.
    | VRECPE = 413
    /// Vector Reciprocal Step.
    | VRECPS = 414
    /// Vector Reverse in halfwords.
    | VREV16 = 415
    /// Vector Reverse in words.
    | VREV32 = 416
    /// Vector Reverse in doublewords.
    | VREV64 = 417
    /// Vector Rounding Halving Add
    | VRHADD = 418
    /// Vector Round floating-point to integer towards Nearest with Ties to Away.
    | VRINTA = 419
    /// Vector Round floating-point to integer towards Minus Infinity.
    | VRINTM = 420
    /// Vector Round floating-point to integer to Nearest.
    | VRINTN = 421
    /// Vector Round floating-point to integer towards Plus Infinity.
    | VRINTP = 422
    /// Vector round floating-point to integer to nearest signaling inexactness.
    | VRINTX = 423
    /// Vector round floating-point to integer towards Zero.
    | VRINTZ = 424
    /// Vector Rounding Shift Left.
    | VRSHL = 425
    /// Vector Rounding Shift Right.
    | VRSHR = 426
    /// Vector Rounding Shift Right Narrow.
    | VRSHRN = 427
    /// Vector Reciprocal Square Root Estimate.
    | VRSQRTE = 428
    /// Vector Reciprocal Square Root Step.
    | VRSQRTS = 429
    /// Vector Rounding Shift Right and Accumulate.
    | VRSRA = 430
    /// Vector Rounding Subtract and Narrow, returning High Half.
    | VRSUBHN = 431
    /// Vector Shift Left.
    | VSHL = 432
    /// Vector Shift Left Long.
    | VSHLL = 433
    /// Vector Shift Right.
    | VSHR = 434
    /// Vector Shift Right Narrow.
    | VSHRN = 435
    /// Vector Shift Left and Insert.
    | VSLI = 436
    /// Vector Square Root.
    | VSQRT = 437
    /// Vector Shift Right and Accumulate.
    | VSRA = 438
    /// Vector Shift Right and Insert.
    | VSRI = 439
    /// Vector Store. (multiple single elements).
    | VST1 = 440
    /// Vector Store. (multiple 2-element structures).
    | VST2 = 441
    /// Vector Store. (multiple 3-element structures).
    | VST3 = 442
    /// Vector Store. (multiple 4-element structures).
    | VST4 = 443
    /// Vector Store Multiple.
    | VSTM = 444
    /// Vector Store Multiple. Decrement Before.
    | VSTMDB = 445
    /// Vector Store Multiple. Increment After
    | VSTMIA = 446
    /// Vector Store Register.
    | VSTR = 447
    /// Vector Subtract.
    | VSUB = 448
    /// Vector Subtract and Narrow, returning High Half.
    | VSUBHN = 449
    /// Vector Subtract Long.
    | VSUBL = 450
    /// Vector Subtract Wide.
    | VSUBW = 451
    /// Vector Swap.
    | VSWP = 452
    /// Vector Table Lookup.
    | VTBL = 453
    /// Vector Table Extension.
    | VTBX = 454
    /// Vector Transpose.
    | VTRN = 455
    /// Vector Test Bits.
    | VTST = 456
    /// Vector Unzip.
    | VUZP = 457
    /// Vector Zip.
    | VZIP = 458
    /// Wait For Event hint.
    | WFE = 459
    /// Wait For Interrupt hint.
    | WFI = 460
    /// Yield hint
    | YIELD = 461
    /// Invalid Opcode.
    | InvalidOP = 462

type internal Op = Opcode

type Register =
    /// R0.
    | R0 = 0x0
    /// R1.
    | R1 = 0x1
    /// R2.
    | R2 = 0x2
    /// R3.
    | R3 = 0x3
    /// R4.
    | R4 = 0x4
    /// R5.
    | R5 = 0x5
    /// R6.
    | R6 = 0x6
    /// R7.
    | R7 = 0x7
    /// R8.
    | R8 = 0x8
    /// SB.
    | SB = 0x9
    /// SL.
    | SL = 0xA
    /// FP.
    | FP = 0xB
    /// IP.
    | IP = 0xC
    /// SP, the stack pointer.
    | SP = 0xD
    /// LR, the link register.
    | LR = 0xE
    /// PC, the program counter.
    | PC = 0xF
    /// S0.
    | S0 = 0x100
    /// S1.
    | S1 = 0x101
    /// S2.
    | S2 = 0x102
    /// S3.
    | S3 = 0x103
    /// S4.
    | S4 = 0x104
    /// S5.
    | S5 = 0x105
    /// S6.
    | S6 = 0x106
    /// S7.
    | S7 = 0x107
    /// S8.
    | S8 = 0x108
    /// S9.
    | S9 = 0x109
    /// S10.
    | S10 = 0x10A
    /// S11.
    | S11 = 0x10B
    /// S12.
    | S12 = 0x10C
    /// S13.
    | S13 = 0x10D
    /// S14.
    | S14 = 0x10E
    /// S15.
    | S15 = 0x10F
    /// S16.
    | S16 = 0x110
    /// S17.
    | S17 = 0x111
    /// S18.
    | S18 = 0x112
    /// S19.
    | S19 = 0x113
    /// S20.
    | S20 = 0x114
    /// S21.
    | S21 = 0x115
    /// S22.
    | S22 = 0x116
    /// S23.
    | S23 = 0x117
    /// S24.
    | S24 = 0x118
    /// S25.
    | S25 = 0x119
    /// S26.
    | S26 = 0x11A
    /// S27.
    | S27 = 0x11B
    /// S28.
    | S28 = 0x11C
    /// S29.
    | S29 = 0x11D
    /// S30.
    | S30 = 0x11E
    /// S31.
    | S31 = 0x11F
    /// D0.
    | D0 = 0x200
    /// D1.
    | D1 = 0x201
    /// D2.
    | D2 = 0x202
    /// D3.
    | D3 = 0x203
    /// D4.
    | D4 = 0x204
    /// D5.
    | D5 = 0x205
    /// D6.
    | D6 = 0x206
    /// D7.
    | D7 = 0x207
    /// D8.
    | D8 = 0x208
    /// D9.
    | D9 = 0x209
    /// D10.
    | D10 = 0x20A
    /// D11.
    | D11 = 0x20B
    /// D12.
    | D12 = 0x20C
    /// D13.
    | D13 = 0x20D
    /// D14.
    | D14 = 0x20E
    /// D15.
    | D15 = 0x20F
    /// D16.
    | D16 = 0x210
    /// D17.
    | D17 = 0x211
    /// D18.
    | D18 = 0x212
    /// D19.
    | D19 = 0x213
    /// D20.
    | D20 = 0x214
    /// D21.
    | D21 = 0x215
    /// D22.
    | D22 = 0x216
    /// D23.
    | D23 = 0x217
    /// D24.
    | D24 = 0x218
    /// D25.
    | D25 = 0x219
    /// D26.
    | D26 = 0x21A
    /// D27.
    | D27 = 0x21B
    /// D28.
    | D28 = 0x21C
    /// D29.
    | D29 = 0x21D
    /// D30.
    | D30 = 0x21E
    /// D31.
    | D31 = 0x21F
    /// FPINST2.
    | FPINST2 = 0x220
    /// MVFR0.
    | MVFR0 = 0x221
    /// MVFR1.
    | MVFR1 = 0x222
    /// Q0.
    | Q0 = 0x300
    /// Q1.
    | Q1 = 0x301
    /// Q2.
    | Q2 = 0x302
    /// Q3.
    | Q3 = 0x303
    /// Q4.
    | Q4 = 0x304
    /// Q5.
    | Q5 = 0x305
    /// Q6.
    | Q6 = 0x306
    /// Q7.
    | Q7 = 0x307
    /// Q8.
    | Q8 = 0x308
    /// Q9.
    | Q9 = 0x309
    /// Q10.
    | Q10 = 0x30A
    /// Q11.
    | Q11 = 0x30B
    /// Q12.
    | Q12 = 0x30C
    /// Q13.
    | Q13 = 0x30D
    /// Q14.
    | Q14 = 0x30E
    /// Q15.
    | Q15 = 0x30F
    /// C0.
    | C0 = 0x400
    /// C1.
    | C1 = 0x401
    /// C2.
    | C2 = 0x402
    /// C3.
    | C3 = 0x403
    /// C4.
    | C4 = 0x404
    /// C5.
    | C5 = 0x405
    /// C6.
    | C6 = 0x406
    /// C7.
    | C7 = 0x407
    /// C8.
    | C8 = 0x408
    /// C9.
    | C9 = 0x409
    /// C10.
    | C10 = 0x40A
    /// C11.
    | C11 = 0x40B
    /// C12.
    | C12 = 0x40C
    /// C13.
    | C13 = 0x40D
    /// C14.
    | C14 = 0x40E
    /// C15.
    | C15 = 0x40F
    /// P0.
    | P0 = 0x500
    /// P1.
    | P1 = 0x501
    /// P2.
    | P2 = 0x502
    /// P3.
    | P3 = 0x503
    /// P4.
    | P4 = 0x504
    /// P5.
    | P5 = 0x505
    /// P6.
    | P6 = 0x506
    /// P7.
    | P7 = 0x507
    /// P8.
    | P8 = 0x508
    /// P9.
    | P9 = 0x509
    /// P10.
    | P10 = 0x50A
    /// P11.
    | P11 = 0x50B
    /// P12.
    | P12 = 0x50C
    /// P13.
    | P13 = 0x50D
    /// P14.
    | P14 = 0x50E
    /// P15.
    | P15 = 0x50F
    /// R8usr.
    | R8usr = 0x600
    /// R9usr.
    | R9usr = 0x601
    /// R10usr.
    | R10usr = 0x602
    /// R11usr.
    | R11usr = 0x603
    /// R12usr.
    | R12usr = 0x604
    /// SPusr.
    | SPusr = 0x605
    /// LRusr.
    | LRusr = 0x606
    /// SPhyp.
    | SPhyp = 0x607
    /// SPSRhyp.
    | SPSRhyp = 0x608
    /// ELRhyp.
    | ELRhyp = 0x609
    /// SPsvc.
    | SPsvc = 0x60A
    /// LRsvc.
    | LRsvc = 0x60B
    /// SPSRsvc.
    | SPSRsvc = 0x60C
    /// SPabt.
    | SPabt = 0x60D
    /// LRabt.
    | LRabt = 0x60E
    /// SPSRabt.
    | SPSRabt = 0x60F
    /// SPund.
    | SPund = 0x610
    /// LRund.
    | LRund = 0x611
    /// SPSRund.
    | SPSRund = 0x612
    /// SPmon.
    | SPmon = 0x613
    /// LRmon.
    | LRmon = 0x614
    /// SPSRmon.
    | SPSRmon = 0x615
    /// SPirq.
    | SPirq = 0x616
    /// LRirq.
    | LRirq = 0x617
    /// SPSRirq.
    | SPSRirq = 0x618
    /// R8fiq.
    | R8fiq = 0x619
    /// R9fiq.
    | R9fiq = 0x61A
    /// R10fiq.
    | R10fiq = 0x61B
    /// R11fiq.
    | R11fiq = 0x61C
    /// R12fiq.
    | R12fiq = 0x61D
    /// SPfiq.
    | SPfiq = 0x61E
    /// LRfiq.
    | LRfiq = 0x61F
    /// SPSRfiq.
    | SPSRfiq = 0x620
    /// Application Program Status Register.
    | APSR = 0x700
    /// Current Program Status Register.
    | CPSR = 0x701
    /// Saved Program Status Register.
    | SPSR = 0x702
    /// Secure Configuration Register.
    | SCR = 0x703
    /// System Control register
    | SCTLR = 0x704
    /// Non-Secure Access Control Register.
    | NSACR = 0x705
    /// FPSCR, Floating-point Status and Control Register, VMSA.
    | FPSCR = 0x800
    /// RegisterWR0.
    | RegisterWR0 = 0x11000000
    /// RegisterWR1.
    | RegisterWR1 = 0x11000001
    /// RegisterWR2.
    | RegisterWR2 = 0x11000002
    /// RegisterWR3.
    | RegisterWR3 = 0x11000003
    /// RegisterWR4.
    | RegisterWR4 = 0x11000004
    /// RegisterWR5.
    | RegisterWR5 = 0x11000005
    /// RegisterWR6.
    | RegisterWR6 = 0x11000006
    /// RegisterWR7.
    | RegisterWR7 = 0x11000007
    /// RegisterWR8.
    | RegisterWR8 = 0x11000008
    /// RegisterWSB.
    | RegisterWSB = 0x11000009
    /// RegisterWSL.
    | RegisterWSL = 0x1100000A
    /// RegisterWFP.
    | RegisterWFP = 0x1100000B
    /// RegisterWIP.
    | RegisterWIP = 0x1100000C
    /// RegisterWSP.
    | RegisterWSP = 0x1100000D
    /// RegisterWLR.
    | RegisterWLR = 0x1100000E
    /// RegisterWPC.
    | RegisterWPC = 0x1100000F
    /// RegisterWS0.
    | RegisterWS0 = 0x11000100
    /// RegisterWS1.
    | RegisterWS1 = 0x11000101
    /// RegisterWS2.
    | RegisterWS2 = 0x11000102
    /// RegisterWS3.
    | RegisterWS3 = 0x11000103
    /// RegisterWS4.
    | RegisterWS4 = 0x11000104
    /// RegisterWS5.
    | RegisterWS5 = 0x11000105
    /// RegisterWS6.
    | RegisterWS6 = 0x11000106
    /// RegisterWS7.
    | RegisterWS7 = 0x11000107
    /// RegisterWS8.
    | RegisterWS8 = 0x11000108
    /// RegisterWS9.
    | RegisterWS9 = 0x11000109
    /// RegisterWS10.
    | RegisterWS10 = 0x1100010A
    /// RegisterWS11.
    | RegisterWS11 = 0x1100010B
    /// RegisterWS12.
    | RegisterWS12 = 0x1100010C
    /// RegisterWS13.
    | RegisterWS13 = 0x1100010D
    /// RegisterWS14.
    | RegisterWS14 = 0x1100010E
    /// RegisterWS15.
    | RegisterWS15 = 0x1100010F
    /// RegisterWS16.
    | RegisterWS16 = 0x11000110
    /// RegisterWS17.
    | RegisterWS17 = 0x11000111
    /// RegisterWS18.
    | RegisterWS18 = 0x11000112
    /// RegisterWS19.
    | RegisterWS19 = 0x11000113
    /// RegisterWS20.
    | RegisterWS20 = 0x11000114
    /// RegisterWS21.
    | RegisterWS21 = 0x11000115
    /// RegisterWS22.
    | RegisterWS22 = 0x11000116
    /// RegisterWS23.
    | RegisterWS23 = 0x11000117
    /// RegisterWS24.
    | RegisterWS24 = 0x11000118
    /// RegisterWS25.
    | RegisterWS25 = 0x11000119
    /// RegisterWS26.
    | RegisterWS26 = 0x1100011A
    /// RegisterWS27.
    | RegisterWS27 = 0x1100011B
    /// RegisterWS28.
    | RegisterWS28 = 0x1100011C
    /// RegisterWS29.
    | RegisterWS29 = 0x1100011D
    /// RegisterWS30.
    | RegisterWS30 = 0x1100011E
    /// RegisterWS31.
    | RegisterWS31 = 0x1100011F
    /// RegisterWD0.
    | RegisterWD0 = 0x11000200
    /// RegisterWD1.
    | RegisterWD1 = 0x11000201
    /// RegisterWD2.
    | RegisterWD2 = 0x11000202
    /// RegisterWD3.
    | RegisterWD3 = 0x11000203
    /// RegisterWD4.
    | RegisterWD4 = 0x11000204
    /// RegisterWD5.
    | RegisterWD5 = 0x11000205
    /// RegisterWD6.
    | RegisterWD6 = 0x11000206
    /// RegisterWD7.
    | RegisterWD7 = 0x11000207
    /// RegisterWD8.
    | RegisterWD8 = 0x11000208
    /// RegisterWD9.
    | RegisterWD9 = 0x11000209
    /// RegisterWD10.
    | RegisterWD10 = 0x1100020A
    /// RegisterWD11.
    | RegisterWD11 = 0x1100020B
    /// RegisterWD12.
    | RegisterWD12 = 0x1100020C
    /// RegisterWD13.
    | RegisterWD13 = 0x1100020D
    /// RegisterWD14.
    | RegisterWD14 = 0x1100020E
    /// RegisterWD15.
    | RegisterWD15 = 0x1100020F
    /// RegisterWD16.
    | RegisterWD16 = 0x11000210
    /// RegisterWD17.
    | RegisterWD17 = 0x11000211
    /// RegisterWD18.
    | RegisterWD18 = 0x11000212
    /// RegisterWD19.
    | RegisterWD19 = 0x11000213
    /// RegisterWD20.
    | RegisterWD20 = 0x11000214
    /// RegisterWD21.
    | RegisterWD21 = 0x11000215
    /// RegisterWD22.
    | RegisterWD22 = 0x11000216
    /// RegisterWD23.
    | RegisterWD23 = 0x11000217
    /// RegisterWD24.
    | RegisterWD24 = 0x11000218
    /// RegisterWD25.
    | RegisterWD25 = 0x11000219
    /// RegisterWD26.
    | RegisterWD26 = 0x1100021A
    /// RegisterWD27.
    | RegisterWD27 = 0x1100021B
    /// RegisterWD28.
    | RegisterWD28 = 0x1100021C
    /// RegisterWD29.
    | RegisterWD29 = 0x1100021D
    /// RegisterWD30.
    | RegisterWD30 = 0x1100021E
    /// RegisterWD31.
    | RegisterWD31 = 0x1100021F
    /// RegisterWFPINST2.
    | RegisterWFPINST2 = 0x11000220
    /// RegisterWMVFR0.
    | RegisterWMVFR0 = 0x11000221
    /// RegisterWMVFR1.
    | RegisterWMVFR1 = 0x11000222
    /// RegisterWQ0.
    | RegisterWQ0 = 0x11000300
    /// RegisterWQ1.
    | RegisterWQ1 = 0x11000301
    /// RegisterWQ2.
    | RegisterWQ2 = 0x11000302
    /// RegisterWQ3.
    | RegisterWQ3 = 0x11000303
    /// RegisterWQ4.
    | RegisterWQ4 = 0x11000304
    /// RegisterWQ5.
    | RegisterWQ5 = 0x11000305
    /// RegisterWQ6.
    | RegisterWQ6 = 0x11000306
    /// RegisterWQ7.
    | RegisterWQ7 = 0x11000307
    /// RegisterWQ8.
    | RegisterWQ8 = 0x11000308
    /// RegisterWQ9.
    | RegisterWQ9 = 0x11000309
    /// RegisterWQ10.
    | RegisterWQ10 = 0x1100030A
    /// RegisterWQ11.
    | RegisterWQ11 = 0x1100030B
    /// RegisterWQ12.
    | RegisterWQ12 = 0x1100030C
    /// RegisterWQ13.
    | RegisterWQ13 = 0x1100030D
    /// RegisterWQ14.
    | RegisterWQ14 = 0x1100030E
    /// RegisterWQ15.
    | RegisterWQ15 = 0x1100030F
    /// RegisterWC0.
    | RegisterWC0 = 0x11000400
    /// RegisterWC1.
    | RegisterWC1 = 0x11000401
    /// RegisterWC2.
    | RegisterWC2 = 0x11000402
    /// RegisterWC3.
    | RegisterWC3 = 0x11000403
    /// RegisterWC4.
    | RegisterWC4 = 0x11000404
    /// RegisterWC5.
    | RegisterWC5 = 0x11000405
    /// RegisterWC6.
    | RegisterWC6 = 0x11000406
    /// RegisterWC7.
    | RegisterWC7 = 0x11000407
    /// RegisterWC8.
    | RegisterWC8 = 0x11000408
    /// RegisterWC9.
    | RegisterWC9 = 0x11000409
    /// RegisterWC10.
    | RegisterWC10 = 0x1100040A
    /// RegisterWC11.
    | RegisterWC11 = 0x1100040B
    /// RegisterWC12.
    | RegisterWC12 = 0x1100040C
    /// RegisterWC13.
    | RegisterWC13 = 0x1100040D
    /// RegisterWC14.
    | RegisterWC14 = 0x1100040E
    /// RegisterWC15.
    | RegisterWC15 = 0x1100040F
    /// RegisterWP0.
    | RegisterWP0 = 0x11000500
    /// RegisterWP1.
    | RegisterWP1 = 0x11000501
    /// RegisterWP2.
    | RegisterWP2 = 0x11000502
    /// RegisterWP3.
    | RegisterWP3 = 0x11000503
    /// RegisterWP4.
    | RegisterWP4 = 0x11000504
    /// RegisterWP5.
    | RegisterWP5 = 0x11000505
    /// RegisterWP6.
    | RegisterWP6 = 0x11000506
    /// RegisterWP7.
    | RegisterWP7 = 0x11000507
    /// RegisterWP8.
    | RegisterWP8 = 0x11000508
    /// RegisterWP9.
    | RegisterWP9 = 0x11000509
    /// RegisterWP10.
    | RegisterWP10 = 0x1100050A
    /// RegisterWP11.
    | RegisterWP11 = 0x1100050B
    /// RegisterWP12.
    | RegisterWP12 = 0x1100050C
    /// RegisterWP13.
    | RegisterWP13 = 0x1100050D
    /// RegisterWP14.
    | RegisterWP14 = 0x1100050E
    /// RegisterWP15.
    | RegisterWP15 = 0x1100050F
    /// RegisterWP15.
    | RegisterWR8usr = 0x11000600
    /// RegisterWP15.
    | RegisterWR9usr = 0x11000601
    /// RegisterWP15.
    | RegisterWR10usr = 0x11000602
    /// RegisterWP15.
    | RegisterWR11usr = 0x11000603
    /// RegisterWP15.
    | RegisterWR12usr = 0x11000604
    /// RegisterWP15.
    | RegisterWSPusr = 0x11000605
    /// RegisterWP15.
    | RegisterWLRusr = 0x11000606
    /// RegisterWP15.
    | RegisterWSPhyp = 0x11000607
    /// RegisterWP15.
    | RegisterWSPSRhyp = 0x11000608
    /// RegisterWP15.
    | RegisterWELRhyp = 0x11000609
    /// RegisterWP15.
    | RegisterWSPsvc = 0x1100060A
    /// RegisterWP15.
    | RegisterWLRsvc = 0x1100060B
    /// RegisterWP15.
    | RegisterWSPSRsvc = 0x1100060C
    /// RegisterWP15.
    | RegisterWSPabt = 0x1100060D
    /// RegisterWP15.
    | RegisterWLRabt = 0x1100060E
    /// RegisterWP15.
    | RegisterWSPSRabt = 0x1100060F
    /// RegisterWP15.
    | RegisterWSPund = 0x11000610
    /// RegisterWP15.
    | RegisterWLRund = 0x11000611
    /// RegisterWP15.
    | RegisterWSPSRund = 0x11000612
    /// RegisterWP15.
    | RegisterWSPmon = 0x11000613
    /// RegisterWP15.
    | RegisterWLRmon = 0x11000614
    /// RegisterWP15.
    | RegisterWSPSRmon = 0x11000615
    /// RegisterWP15.
    | RegisterWSPirq = 0x11000616
    /// RegisterWP15.
    | RegisterWLRirq = 0x11000617
    /// RegisterWP15.
    | RegisterWSPSRirq = 0x11000618
    /// RegisterWP15.
    | RegisterWR8fiq = 0x11000619
    /// RegisterWP15.
    | RegisterWR9fiq = 0x1100061A
    /// RegisterWP15.
    | RegisterWR10fiq = 0x1100061B
    /// RegisterWP15.
    | RegisterWR11fiq = 0x1100061C
    /// RegisterWP15.
    | RegisterWR12fiq = 0x1100061D
    /// RegisterWP15.
    | RegisterWSPfiq = 0x1100061E
    /// RegisterWP15.
    | RegisterWLRfiq = 0x1100061F
    /// RegisterWP15.
    | RegisterWSPSRfiq = 0x11000620
    /// RegisterWP15.
    | RegisterWAPSR = 0x11000700
    /// RegisterWP15.
    | RegisterWCPSR = 0x11000701
    /// RegisterWP15.
    | RegisterWSPSR = 0x11000702
    /// RegisterWP15.
    | RegisterWSCR = 0x11000703
    /// RegisterWP15.
    | RegisterWSCTLR = 0x11000704
    /// RegisterWP15.
    | RegisterWNSACR = 0x11000705
    /// RegisterWP15.
    | RegisterWFPSCR = 0x11000800
    /// RegisterWR0F.
    | RegisterWR0F = 0x10000000
    /// RegisterWR1F.
    | RegisterWR1F = 0x10000001
    /// RegisterWR2F.
    | RegisterWR2F = 0x10000002
    /// RegisterWR3F.
    | RegisterWR3F = 0x10000003
    /// RegisterWR4F.
    | RegisterWR4F = 0x10000004
    /// RegisterWR5F.
    | RegisterWR5F = 0x10000005
    /// RegisterWR6F.
    | RegisterWR6F = 0x10000006
    /// RegisterWR7F.
    | RegisterWR7F = 0x10000007
    /// RegisterWR8F.
    | RegisterWR8F = 0x10000008
    /// RegisterWSBF.
    | RegisterWSBF = 0x10000009
    /// RegisterWSLF.
    | RegisterWSLF = 0x1000000A
    /// RegisterWFPF.
    | RegisterWFPF = 0x1000000B
    /// RegisterWIPF.
    | RegisterWIPF = 0x1000000C
    /// RegisterWSPF.
    | RegisterWSPF = 0x1000000D
    /// RegisterWLRF.
    | RegisterWLRF = 0x1000000E
    /// RegisterWPCF.
    | RegisterWPCF = 0x1000000F
    /// RegisterWS0F.
    | RegisterWS0F = 0x10000100
    /// RegisterWS1F.
    | RegisterWS1F = 0x10000101
    /// RegisterWS2F.
    | RegisterWS2F = 0x10000102
    /// RegisterWS3F.
    | RegisterWS3F = 0x10000103
    /// RegisterWS4F.
    | RegisterWS4F = 0x10000104
    /// RegisterWS5F.
    | RegisterWS5F = 0x10000105
    /// RegisterWS6F.
    | RegisterWS6F = 0x10000106
    /// RegisterWS7F.
    | RegisterWS7F = 0x10000107
    /// RegisterWS8F.
    | RegisterWS8F = 0x10000108
    /// RegisterWS9F.
    | RegisterWS9F = 0x10000109
    /// RegisterWS10F.
    | RegisterWS10F = 0x1000010A
    /// RegisterWS11F.
    | RegisterWS11F = 0x1000010B
    /// RegisterWS12F.
    | RegisterWS12F = 0x1000010C
    /// RegisterWS13F.
    | RegisterWS13F = 0x1000010D
    /// RegisterWS14F.
    | RegisterWS14F = 0x1000010E
    /// RegisterWS15F.
    | RegisterWS15F = 0x1000010F
    /// RegisterWS16F.
    | RegisterWS16F = 0x10000110
    /// RegisterWS17F.
    | RegisterWS17F = 0x10000111
    /// RegisterWS18F.
    | RegisterWS18F = 0x10000112
    /// RegisterWS19F.
    | RegisterWS19F = 0x10000113
    /// RegisterWS20F.
    | RegisterWS20F = 0x10000114
    /// RegisterWS21F.
    | RegisterWS21F = 0x10000115
    /// RegisterWS22F.
    | RegisterWS22F = 0x10000116
    /// RegisterWS23F.
    | RegisterWS23F = 0x10000117
    /// RegisterWS24F.
    | RegisterWS24F = 0x10000118
    /// RegisterWS25F.
    | RegisterWS25F = 0x10000119
    /// RegisterWS26F.
    | RegisterWS26F = 0x1000011A
    /// RegisterWS27F.
    | RegisterWS27F = 0x1000011B
    /// RegisterWS28F.
    | RegisterWS28F = 0x1000011C
    /// RegisterWS29F.
    | RegisterWS29F = 0x1000011D
    /// RegisterWS30F.
    | RegisterWS30F = 0x1000011E
    /// RegisterWS31F.
    | RegisterWS31F = 0x1000011F
    /// RegisterWD0F.
    | RegisterWD0F = 0x10000200
    /// RegisterWD1F.
    | RegisterWD1F = 0x10000201
    /// RegisterWD2F.
    | RegisterWD2F = 0x10000202
    /// RegisterWD3F.
    | RegisterWD3F = 0x10000203
    /// RegisterWD4F.
    | RegisterWD4F = 0x10000204
    /// RegisterWD5F.
    | RegisterWD5F = 0x10000205
    /// RegisterWD6F.
    | RegisterWD6F = 0x10000206
    /// RegisterWD7F.
    | RegisterWD7F = 0x10000207
    /// RegisterWD8F.
    | RegisterWD8F = 0x10000208
    /// RegisterWD9F.
    | RegisterWD9F = 0x10000209
    /// RegisterWD10F.
    | RegisterWD10F = 0x1000020A
    /// RegisterWD11F.
    | RegisterWD11F = 0x1000020B
    /// RegisterWD12F.
    | RegisterWD12F = 0x1000020C
    /// RegisterWD13F.
    | RegisterWD13F = 0x1000020D
    /// RegisterWD14F.
    | RegisterWD14F = 0x1000020E
    /// RegisterWD15F.
    | RegisterWD15F = 0x1000020F
    /// RegisterWD16F.
    | RegisterWD16F = 0x10000210
    /// RegisterWD17F.
    | RegisterWD17F = 0x10000211
    /// RegisterWD18F.
    | RegisterWD18F = 0x10000212
    /// RegisterWD19F.
    | RegisterWD19F = 0x10000213
    /// RegisterWD20F.
    | RegisterWD20F = 0x10000214
    /// RegisterWD21F.
    | RegisterWD21F = 0x10000215
    /// RegisterWD22F.
    | RegisterWD22F = 0x10000216
    /// RegisterWD23F.
    | RegisterWD23F = 0x10000217
    /// RegisterWD24F.
    | RegisterWD24F = 0x10000218
    /// RegisterWD25F.
    | RegisterWD25F = 0x10000219
    /// RegisterWD26F.
    | RegisterWD26F = 0x1000021A
    /// RegisterWD27F.
    | RegisterWD27F = 0x1000021B
    /// RegisterWD28F.
    | RegisterWD28F = 0x1000021C
    /// RegisterWD29F.
    | RegisterWD29F = 0x1000021D
    /// RegisterWD30F.
    | RegisterWD30F = 0x1000021E
    /// RegisterWD31F.
    | RegisterWD31F = 0x1000021F
    /// RegisterWFPINST2F.
    | RegisterWFPINST2F = 0x10000220
    /// RegisterWMVFR0F.
    | RegisterWMVFR0F = 0x10000221
    /// RegisterWMVFR1F.
    | RegisterWMVFR1F = 0x10000222
    /// RegisterWQ0F.
    | RegisterWQ0F= 0x10000300
    /// RegisterWQ1F.
    | RegisterWQ1F= 0x10000301
    /// RegisterWQ2F.
    | RegisterWQ2F= 0x10000302
    /// RegisterWQ3F.
    | RegisterWQ3F= 0x10000303
    /// RegisterWQ4F.
    | RegisterWQ4F= 0x10000304
    /// RegisterWQ5F.
    | RegisterWQ5F= 0x10000305
    /// RegisterWQ6F.
    | RegisterWQ6F= 0x10000306
    /// RegisterWQ7F.
    | RegisterWQ7F= 0x10000307
    /// RegisterWQ8F.
    | RegisterWQ8F= 0x10000308
    /// RegisterWQ9F.
    | RegisterWQ9F= 0x10000309
    /// RegisterWQ10F.
    | RegisterWQ10F = 0x1000030A
    /// RegisterWQ11F.
    | RegisterWQ11F = 0x1000030B
    /// RegisterWQ12F.
    | RegisterWQ12F = 0x1000030C
    /// RegisterWQ13F.
    | RegisterWQ13F = 0x1000030D
    /// RegisterWQ14F.
    | RegisterWQ14F = 0x1000030E
    /// RegisterWQ15F.
    | RegisterWQ15F = 0x1000030F
    /// RegisterWC0F.
    | RegisterWC0F = 0x10000400
    /// RegisterWC1F.
    | RegisterWC1F = 0x10000401
    /// RegisterWC2F.
    | RegisterWC2F = 0x10000402
    /// RegisterWC3F.
    | RegisterWC3F = 0x10000403
    /// RegisterWC4F.
    | RegisterWC4F = 0x10000404
    /// RegisterWC5F.
    | RegisterWC5F = 0x10000405
    /// RegisterWC6F.
    | RegisterWC6F = 0x10000406
    /// RegisterWC7F.
    | RegisterWC7F = 0x10000407
    /// RegisterWC8F.
    | RegisterWC8F = 0x10000408
    /// RegisterWC9F.
    | RegisterWC9F = 0x10000409
    /// RegisterWC10F.
    | RegisterWC10F = 0x1000040A
    /// RegisterWC11F.
    | RegisterWC11F = 0x1000040B
    /// RegisterWC12F.
    | RegisterWC12F = 0x1000040C
    /// RegisterWC13F.
    | RegisterWC13F = 0x1000040D
    /// RegisterWC14F.
    | RegisterWC14F = 0x1000040E
    /// RegisterWC15F.
    | RegisterWC15F = 0x1000040F
    /// RegisterWP0F.
    | RegisterWP0F = 0x10000500
    /// RegisterWP1F.
    | RegisterWP1F = 0x10000501
    /// RegisterWP2F.
    | RegisterWP2F = 0x10000502
    /// RegisterWP3F.
    | RegisterWP3F = 0x10000503
    /// RegisterWP4F.
    | RegisterWP4F = 0x10000504
    /// RegisterWP5F.
    | RegisterWP5F = 0x10000505
    /// RegisterWP6F.
    | RegisterWP6F = 0x10000506
    /// RegisterWP7F.
    | RegisterWP7F = 0x10000507
    /// RegisterWP8F.
    | RegisterWP8F = 0x10000508
    /// RegisterWP9F.
    | RegisterWP9F = 0x10000509
    /// RegisterWP10F.
    | RegisterWP10F = 0x1000050A
    /// RegisterWP11F.
    | RegisterWP11F = 0x1000050B
    /// RegisterWP12F.
    | RegisterWP12F = 0x1000050C
    /// RegisterWP13F.
    | RegisterWP13F = 0x1000050D
    /// RegisterWP14F.
    | RegisterWP14F = 0x1000050E
    /// RegisterWP15F.
    | RegisterWP15F = 0x1000050F
    /// RegisterWR8usrF.
    | RegisterWR8usrF = 0x10000600
    /// RegisterWR9usrF.
    | RegisterWR9usrF = 0x10000601
    /// RegisterWR10usrF.
    | RegisterWR10usrF = 0x10000602
    /// RegisterWR11usrF.
    | RegisterWR11usrF = 0x10000603
    /// RegisterWR12usrF.
    | RegisterWR12usrF = 0x10000604
    /// RegisterWSPusrF.
    | RegisterWSPusrF = 0x10000605
    /// RegisterWLRusrF.
    | RegisterWLRusrF = 0x10000606
    /// RegisterWSPhypF.
    | RegisterWSPhypF = 0x10000607
    /// RegisterWSPSRhypF.
    | RegisterWSPSRhypF = 0x10000608
    /// RegisterWELRhypF.
    | RegisterWELRhypF = 0x10000609
    /// RegisterWSPsvcF.
    | RegisterWSPsvcF = 0x1000060A
    /// RegisterWLRsvcF.
    | RegisterWLRsvcF = 0x1000060B
    /// RegisterWSPSRsvcF.
    | RegisterWSPSRsvcF = 0x1000060C
    /// RegisterWSPabtF.
    | RegisterWSPabtF = 0x1000060D
    /// RegisterWLRabtF.
    | RegisterWLRabtF = 0x1000060E
    /// RegisterWSPSRabtF.
    | RegisterWSPSRabtF = 0x1000060F
    /// RegisterWSPundF.
    | RegisterWSPundF = 0x10000610
    /// RegisterWLRundF.
    | RegisterWLRundF = 0x10000611
    /// RegisterWSPSRundF.
    | RegisterWSPSRundF = 0x10000612
    /// RegisterWSPmonF.
    | RegisterWSPmonF = 0x10000613
    /// RegisterWLRmonF.
    | RegisterWLRmonF = 0x10000614
    /// RegisterWSPSRmonF.
    | RegisterWSPSRmonF = 0x10000615
    /// RegisterWSPirqF.
    | RegisterWSPirqF = 0x10000616
    /// RegisterWLRirqF.
    | RegisterWLRirqF = 0x10000617
    /// RegisterWSPSRirqF.
    | RegisterWSPSRirqF = 0x10000618
    /// RegisterWR8fiqF.
    | RegisterWR8fiqF = 0x10000619
    /// RegisterWR9fiqF.
    | RegisterWR9fiqF = 0x1000061A
    /// RegisterWR10fiqF.
    | RegisterWR10fiqF = 0x1000061B
    /// RegisterWR11fiqF.
    | RegisterWR11fiqF = 0x1000061C
    /// RegisterWR12fiqF.
    | RegisterWR12fiqF = 0x1000061D
    /// RegisterWSPfiqF.
    | RegisterWSPfiqF = 0x1000061E
    /// RegisterWLRfiqF.
    | RegisterWLRfiqF = 0x1000061F
    /// RegisterWSPSRfiqF.
    | RegisterWSPSRfiqF = 0x10000620
    /// RegisterWAPSRF.
    | RegisterWAPSRF = 0x10000700
    /// RegisterWCPSRF.
    | RegisterWCPSRF = 0x10000701
    /// RegisterWSPSRF.
    | RegisterWSPSRF = 0x10000702
    /// RegisterWSCRF.
    | RegisterWSCRF = 0x10000703
    /// RegisterWSCTLRF.
    | RegisterWSCTLRF = 0x10000704
    /// RegisterWNSACRF.
    | RegisterWNSACRF = 0x10000705
    /// RegisterWFPSCRF.
    | RegisterWFPSCRF = 0x10000800

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle ARMv8 registers.
[<RequireQualifiedAccess>]
module Register =
    let inline ofRegID (n: RegisterID): Register =
        int n |> LanguagePrimitives.EnumOfValue

    let inline toRegID (reg: Register) =
        LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

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

type internal Option =
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

type internal Iflag =
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

type internal SRType =
    | SRTypeLSL
    | SRTypeLSR
    | SRTypeASR
    | SRTypeROR
    | SRTypeRRX

/// A8.2 Standard assembler syntax fields
type internal Qualifier =
    /// Wide.
    | W
    /// Narrow.
    | N

/// A2.6.3 Data types supported by the Advanced SIMD Extension
type internal SIMDDataType =
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

type internal SIMDDataTypes =
    | OneDT of SIMDDataType
    | TwoDT of SIMDDataType * SIMDDataType

/// V{<modifier>}<operation>{<shape>}{<c>}{<q>}{.<dt>} {<dest>,} <src1>, <src2>
type internal SIMDFPRegister =
    | Vector of Register
    | Scalar of Register * Element option
and Element = uint8

type internal SIMDOperand =
    | SFReg of SIMDFPRegister
    | OneReg of SIMDFPRegister
    | TwoRegs of SIMDFPRegister * SIMDFPRegister
    | ThreeRegs of SIMDFPRegister * SIMDFPRegister * SIMDFPRegister
    | FourRegs of
            SIMDFPRegister * SIMDFPRegister * SIMDFPRegister * SIMDFPRegister

type internal Amount = Imm of uint32

type internal Shift = SRType * Amount

type internal PSRFlag =
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

type internal Const = int64

type internal Label = Const

type internal Align = Const

type internal Sign =
    | Plus
    | Minus

type internal Offset =
    | ImmOffset of Register * Sign option * Const option
    | RegOffset of Register * Sign option * Register * Shift option
    | AlignOffset of Register * Align option * Register option (* Advanced SIMD *)

type internal AddressingMode =
    | OffsetMode of Offset
    | PreIdxMode of Offset
    | PostIdxMode of Offset
    | UnIdxMode of Register * Const (* [<Rn>], <option> *)
    | LiteralMode of Label

type internal Operand =
    | Register of Register
    | SpecReg of Register * PSRFlag option
    | RegList of Register list
    | SIMDOpr of SIMDOperand
    | Immediate of Const
    | FPImmediate of float
    | Shift of Shift
    | RegShift of SRType * Register
    | Memory of AddressingMode
    | Option of Option
    | Iflag of Iflag
    | Endian of Endian
    | Cond of Condition

type internal Operands =
    | NoOperand
    | OneOperand of Operand
    | TwoOperands of Operand * Operand
    | ThreeOperands of Operand * Operand * Operand
    | FourOperands of Operand * Operand * Operand * Operand
    | FiveOperands of Operand * Operand * Operand * Operand * Operand
    | SixOperands of Operand * Operand * Operand * Operand * Operand * Operand

/// Basic information for a single ARMv7 instruction obtained after parsing.
[<NoComparison; CustomEquality>]
type InsInfo = internal {
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
    /// Qualifier.
    Qualifier: Qualifier option
    /// SIMD data type.
    SIMDTyp: SIMDDataTypes option
    /// Target architecture mode.
    Mode: ArchOperationMode
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
        | _ -> false

