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

namespace B2R2.FrontEnd.M68K

/// <summary>
/// Represents an opcode of an m68k instruction. A conditional
/// instruction is spelled out one entry per condition, because
/// that is what its mnemonic is: a Bcc whose condition field reads
/// 0010 is not a Bcc carrying a condition but a BHI.
/// </summary>
type Opcode =
  /// Add Decimal with Extend
  | ABCD = 0
  /// Add
  | ADD = 1
  /// Add Address
  | ADDA = 2
  /// Add Immediate
  | ADDI = 3
  /// Add Quick
  | ADDQ = 4
  /// Add Extended
  | ADDX = 5
  /// AND Logical
  | AND = 6
  /// AND Immediate
  | ANDI = 7
  /// Arithmetic Shift Left
  | ASL = 8
  /// Arithmetic Shift Right
  | ASR = 9
  /// Branch Conditionally (CC)
  | BCC = 10
  /// Test a Bit and Change
  | BCHG = 11
  /// Test a Bit and Clear
  | BCLR = 12
  /// Branch Conditionally (CS)
  | BCS = 13
  /// Branch Conditionally (EQ)
  | BEQ = 14
  /// Test Bit Field and Change
  | BFCHG = 15
  /// Test Bit Field and Clear
  | BFCLR = 16
  /// Extract Bit Field Signed
  | BFEXTS = 17
  /// Extract Bit Field Unsigned
  | BFEXTU = 18
  /// Bit Field Find First One
  | BFFFO = 19
  /// Insert Bit Field
  | BFINS = 20
  /// Test Bit Field and Set
  | BFSET = 21
  /// Test Bit Field
  | BFTST = 22
  /// Branch Conditionally (GE)
  | BGE = 23
  /// Branch Conditionally (GT)
  | BGT = 24
  /// Branch Conditionally (HI)
  | BHI = 25
  /// Breakpoint
  | BKPT = 26
  /// Branch Conditionally (LE)
  | BLE = 27
  /// Branch Conditionally (LS)
  | BLS = 28
  /// Branch Conditionally (LT)
  | BLT = 29
  /// Branch Conditionally (MI)
  | BMI = 30
  /// Branch Conditionally (NE)
  | BNE = 31
  /// Branch Conditionally (PL)
  | BPL = 32
  /// Branch Always
  | BRA = 33
  /// Test a Bit and Set
  | BSET = 34
  /// Branch to Subroutine
  | BSR = 35
  /// Test a Bit
  | BTST = 36
  /// Branch Conditionally (VC)
  | BVC = 37
  /// Branch Conditionally (VS)
  | BVS = 38
  /// Call Module
  | CALLM = 39
  /// Compare and Swap with Operand
  | CAS = 40
  /// Compare and Swap with Operands
  | CAS2 = 41
  /// Check Register Against Bounds
  | CHK = 42
  /// Check Register Against Bounds
  | CHK2 = 43
  /// Invalidate All Cache Lines
  | CINVA = 44
  /// Invalidate Cache Line
  | CINVL = 45
  /// Invalidate Cache Page
  | CINVP = 46
  /// Clear an Operand
  | CLR = 47
  /// Compare
  | CMP = 48
  /// Compare Register Against Bounds
  | CMP2 = 49
  /// Compare Address
  | CMPA = 50
  /// Compare Immediate
  | CMPI = 51
  /// Compare Memory
  | CMPM = 52
  /// Push and Invalidate All Cache Lines
  | CPUSHA = 53
  /// Push and Invalidate Cache Line
  | CPUSHL = 54
  /// Push and Invalidate Cache Page
  | CPUSHP = 55
  /// Test Condition, Decrement, and Branch (CC)
  | DBCC = 56
  /// Test Condition, Decrement, and Branch (CS)
  | DBCS = 57
  /// Test Condition, Decrement, and Branch (EQ)
  | DBEQ = 58
  /// Test Condition, Decrement, and Branch (F)
  | DBF = 59
  /// Test Condition, Decrement, and Branch (GE)
  | DBGE = 60
  /// Test Condition, Decrement, and Branch (GT)
  | DBGT = 61
  /// Test Condition, Decrement, and Branch (HI)
  | DBHI = 62
  /// Test Condition, Decrement, and Branch (LE)
  | DBLE = 63
  /// Test Condition, Decrement, and Branch (LS)
  | DBLS = 64
  /// Test Condition, Decrement, and Branch (LT)
  | DBLT = 65
  /// Test Condition, Decrement, and Branch (MI)
  | DBMI = 66
  /// Test Condition, Decrement, and Branch (NE)
  | DBNE = 67
  /// Test Condition, Decrement, and Branch (PL)
  | DBPL = 68
  /// Test Condition, Decrement, and Branch (T)
  | DBT = 69
  /// Test Condition, Decrement, and Branch (VC)
  | DBVC = 70
  /// Test Condition, Decrement, and Branch (VS)
  | DBVS = 71
  /// Signed Divide
  | DIVS = 72
  /// Signed Divide Long
  | DIVSL = 73
  /// Unsigned Divide
  | DIVU = 74
  /// Unsigned Divide Long
  | DIVUL = 75
  /// Exclusive-OR Logical
  | EOR = 76
  /// Exclusive-OR Immediate
  | EORI = 77
  /// Exchange Registers
  | EXG = 78
  /// Sign Extend
  | EXT = 79
  /// Sign Extend Byte to Long
  | EXTB = 80
  /// Floating-Point Absolute Value
  | FABS = 81
  /// Floating-Point Arc Cosine
  | FACOS = 82
  /// Floating-Point Add
  | FADD = 83
  /// Floating-Point Arc Sine
  | FASIN = 84
  /// Floating-Point Arc Tangent
  | FATAN = 85
  /// Floating-Point Hyperbolic Arc Tangent
  | FATANH = 86
  /// Floating-Point Branch Conditionally (EQ)
  | FBEQ = 87
  /// Floating-Point Branch Conditionally (F)
  | FBF = 88
  /// Floating-Point Branch Conditionally (GE)
  | FBGE = 89
  /// Floating-Point Branch Conditionally (GL)
  | FBGL = 90
  /// Floating-Point Branch Conditionally (GLE)
  | FBGLE = 91
  /// Floating-Point Branch Conditionally (GT)
  | FBGT = 92
  /// Floating-Point Branch Conditionally (LE)
  | FBLE = 93
  /// Floating-Point Branch Conditionally (LT)
  | FBLT = 94
  /// Floating-Point Branch Conditionally (NE)
  | FBNE = 95
  /// Floating-Point Branch Conditionally (NGE)
  | FBNGE = 96
  /// Floating-Point Branch Conditionally (NGL)
  | FBNGL = 97
  /// Floating-Point Branch Conditionally (NGLE)
  | FBNGLE = 98
  /// Floating-Point Branch Conditionally (NGT)
  | FBNGT = 99
  /// Floating-Point Branch Conditionally (NLE)
  | FBNLE = 100
  /// Floating-Point Branch Conditionally (NLT)
  | FBNLT = 101
  /// Floating-Point Branch Conditionally (OGE)
  | FBOGE = 102
  /// Floating-Point Branch Conditionally (OGL)
  | FBOGL = 103
  /// Floating-Point Branch Conditionally (OGT)
  | FBOGT = 104
  /// Floating-Point Branch Conditionally (OLE)
  | FBOLE = 105
  /// Floating-Point Branch Conditionally (OLT)
  | FBOLT = 106
  /// Floating-Point Branch Conditionally (OR)
  | FBOR = 107
  /// Floating-Point Branch Conditionally (SEQ)
  | FBSEQ = 108
  /// Floating-Point Branch Conditionally (SF)
  | FBSF = 109
  /// Floating-Point Branch Conditionally (SNE)
  | FBSNE = 110
  /// Floating-Point Branch Conditionally (ST)
  | FBST = 111
  /// Floating-Point Branch Conditionally (T)
  | FBT = 112
  /// Floating-Point Branch Conditionally (UEQ)
  | FBUEQ = 113
  /// Floating-Point Branch Conditionally (UGE)
  | FBUGE = 114
  /// Floating-Point Branch Conditionally (UGT)
  | FBUGT = 115
  /// Floating-Point Branch Conditionally (ULE)
  | FBULE = 116
  /// Floating-Point Branch Conditionally (ULT)
  | FBULT = 117
  /// Floating-Point Branch Conditionally (UN)
  | FBUN = 118
  /// Floating-Point Compare
  | FCMP = 119
  /// Floating-Point Cosine
  | FCOS = 120
  /// Floating-Point Hyperbolic Cosine
  | FCOSH = 121
  /// Floating-Point Absolute Value, Rounded to Double Precision
  | FDABS = 122
  /// Floating-Point Add, Rounded to Double Precision
  | FDADD = 123
  /// Floating-Point Test, Decrement, Branch (EQ)
  | FDBEQ = 124
  /// Floating-Point Test, Decrement, Branch (F)
  | FDBF = 125
  /// Floating-Point Test, Decrement, Branch (GE)
  | FDBGE = 126
  /// Floating-Point Test, Decrement, Branch (GL)
  | FDBGL = 127
  /// Floating-Point Test, Decrement, Branch (GLE)
  | FDBGLE = 128
  /// Floating-Point Test, Decrement, Branch (GT)
  | FDBGT = 129
  /// Floating-Point Test, Decrement, Branch (LE)
  | FDBLE = 130
  /// Floating-Point Test, Decrement, Branch (LT)
  | FDBLT = 131
  /// Floating-Point Test, Decrement, Branch (NE)
  | FDBNE = 132
  /// Floating-Point Test, Decrement, Branch (NGE)
  | FDBNGE = 133
  /// Floating-Point Test, Decrement, Branch (NGL)
  | FDBNGL = 134
  /// Floating-Point Test, Decrement, Branch (NGLE)
  | FDBNGLE = 135
  /// Floating-Point Test, Decrement, Branch (NGT)
  | FDBNGT = 136
  /// Floating-Point Test, Decrement, Branch (NLE)
  | FDBNLE = 137
  /// Floating-Point Test, Decrement, Branch (NLT)
  | FDBNLT = 138
  /// Floating-Point Test, Decrement, Branch (OGE)
  | FDBOGE = 139
  /// Floating-Point Test, Decrement, Branch (OGL)
  | FDBOGL = 140
  /// Floating-Point Test, Decrement, Branch (OGT)
  | FDBOGT = 141
  /// Floating-Point Test, Decrement, Branch (OLE)
  | FDBOLE = 142
  /// Floating-Point Test, Decrement, Branch (OLT)
  | FDBOLT = 143
  /// Floating-Point Test, Decrement, Branch (OR)
  | FDBOR = 144
  /// Floating-Point Test, Decrement, Branch (SEQ)
  | FDBSEQ = 145
  /// Floating-Point Test, Decrement, Branch (SF)
  | FDBSF = 146
  /// Floating-Point Test, Decrement, Branch (SNE)
  | FDBSNE = 147
  /// Floating-Point Test, Decrement, Branch (ST)
  | FDBST = 148
  /// Floating-Point Test, Decrement, Branch (T)
  | FDBT = 149
  /// Floating-Point Test, Decrement, Branch (UEQ)
  | FDBUEQ = 150
  /// Floating-Point Test, Decrement, Branch (UGE)
  | FDBUGE = 151
  /// Floating-Point Test, Decrement, Branch (UGT)
  | FDBUGT = 152
  /// Floating-Point Test, Decrement, Branch (ULE)
  | FDBULE = 153
  /// Floating-Point Test, Decrement, Branch (ULT)
  | FDBULT = 154
  /// Floating-Point Test, Decrement, Branch (UN)
  | FDBUN = 155
  /// Floating-Point Divide, Rounded to Double Precision
  | FDDIV = 156
  /// Floating-Point Divide
  | FDIV = 157
  /// Move Floating-Point Data, Rounded to Double Precision
  | FDMOVE = 158
  /// Floating-Point Multiply, Rounded to Double Precision
  | FDMUL = 159
  /// Floating-Point Negate, Rounded to Double Precision
  | FDNEG = 160
  /// Floating-Point Square Root, Rounded to Double Precision
  | FDSQRT = 161
  /// Floating-Point Subtract, Rounded to Double Precision
  | FDSUB = 162
  /// Floating-Point e to the x Power
  | FETOX = 163
  /// Floating-Point e to the x Power Minus One
  | FETOXM1 = 164
  /// Floating-Point Get Exponent
  | FGETEXP = 165
  /// Floating-Point Get Mantissa
  | FGETMAN = 166
  /// Floating-Point Integer Part
  | FINT = 167
  /// Floating-Point Integer Part, Round to Zero
  | FINTRZ = 168
  /// Floating-Point Log Base 10
  | FLOG10 = 169
  /// Floating-Point Log Base 2
  | FLOG2 = 170
  /// Floating-Point Log Base e
  | FLOGN = 171
  /// Floating-Point Log Base e of x Plus One
  | FLOGNP1 = 172
  /// Floating-Point Modulo Remainder
  | FMOD = 173
  /// Move Floating-Point Data
  | FMOVE = 174
  /// Move Constant ROM
  | FMOVECR = 175
  /// Move Multiple Floating-Point Data Registers
  | FMOVEM = 176
  /// Floating-Point Multiply
  | FMUL = 177
  /// Floating-Point Negate
  | FNEG = 178
  /// Floating-Point No Operation
  | FNOP = 179
  /// Floating-Point IEEE Remainder
  | FREM = 180
  /// Restore Internal Floating-Point State
  | FRESTORE = 181
  /// Floating-Point Absolute Value, Rounded to Single Precision
  | FSABS = 182
  /// Floating-Point Add, Rounded to Single Precision
  | FSADD = 183
  /// Save Internal Floating-Point State
  | FSAVE = 184
  /// Floating-Point Scale Exponent
  | FSCALE = 185
  /// Floating-Point Divide, Rounded to Single Precision
  | FSDIV = 186
  /// Floating-Point Set According to Condition (EQ)
  | FSEQ = 187
  /// Floating-Point Set According to Condition (F)
  | FSF = 188
  /// Floating-Point Set According to Condition (GE)
  | FSGE = 189
  /// Floating-Point Set According to Condition (GL)
  | FSGL = 190
  /// Floating-Point Single-Precision Divide
  | FSGLDIV = 191
  /// Floating-Point Set According to Condition (GLE)
  | FSGLE = 192
  /// Floating-Point Single-Precision Multiply
  | FSGLMUL = 193
  /// Floating-Point Set According to Condition (GT)
  | FSGT = 194
  /// Floating-Point Sine
  | FSIN = 195
  /// Simultaneous Sine and Cosine
  | FSINCOS = 196
  /// Floating-Point Hyperbolic Sine
  | FSINH = 197
  /// Floating-Point Set According to Condition (LE)
  | FSLE = 198
  /// Floating-Point Set According to Condition (LT)
  | FSLT = 199
  /// Move Floating-Point Data, Rounded to Single Precision
  | FSMOVE = 200
  /// Floating-Point Multiply, Rounded to Single Precision
  | FSMUL = 201
  /// Floating-Point Set According to Condition (NE)
  | FSNE = 202
  /// Floating-Point Negate, Rounded to Single Precision
  | FSNEG = 203
  /// Floating-Point Set According to Condition (NGE)
  | FSNGE = 204
  /// Floating-Point Set According to Condition (NGL)
  | FSNGL = 205
  /// Floating-Point Set According to Condition (NGLE)
  | FSNGLE = 206
  /// Floating-Point Set According to Condition (NGT)
  | FSNGT = 207
  /// Floating-Point Set According to Condition (NLE)
  | FSNLE = 208
  /// Floating-Point Set According to Condition (NLT)
  | FSNLT = 209
  /// Floating-Point Set According to Condition (OGE)
  | FSOGE = 210
  /// Floating-Point Set According to Condition (OGL)
  | FSOGL = 211
  /// Floating-Point Set According to Condition (OGT)
  | FSOGT = 212
  /// Floating-Point Set According to Condition (OLE)
  | FSOLE = 213
  /// Floating-Point Set According to Condition (OLT)
  | FSOLT = 214
  /// Floating-Point Set According to Condition (OR)
  | FSOR = 215
  /// Floating-Point Square Root
  | FSQRT = 216
  /// Floating-Point Set According to Condition (SEQ)
  | FSSEQ = 217
  /// Floating-Point Set According to Condition (SF)
  | FSSF = 218
  /// Floating-Point Set According to Condition (SNE)
  | FSSNE = 219
  /// Floating-Point Square Root, Rounded to Single Precision
  | FSSQRT = 220
  /// Floating-Point Set According to Condition (ST)
  | FSST = 221
  /// Floating-Point Subtract, Rounded to Single Precision
  | FSSUB = 222
  /// Floating-Point Set According to Condition (T)
  | FST = 223
  /// Floating-Point Subtract
  | FSUB = 224
  /// Floating-Point Set According to Condition (UEQ)
  | FSUEQ = 225
  /// Floating-Point Set According to Condition (UGE)
  | FSUGE = 226
  /// Floating-Point Set According to Condition (UGT)
  | FSUGT = 227
  /// Floating-Point Set According to Condition (ULE)
  | FSULE = 228
  /// Floating-Point Set According to Condition (ULT)
  | FSULT = 229
  /// Floating-Point Set According to Condition (UN)
  | FSUN = 230
  /// Floating-Point Tangent
  | FTAN = 231
  /// Floating-Point Hyperbolic Tangent
  | FTANH = 232
  /// Floating-Point 10 to the x Power
  | FTENTOX = 233
  /// Floating-Point Trap on Condition (EQ)
  | FTRAPEQ = 234
  /// Floating-Point Trap on Condition (F)
  | FTRAPF = 235
  /// Floating-Point Trap on Condition (GE)
  | FTRAPGE = 236
  /// Floating-Point Trap on Condition (GL)
  | FTRAPGL = 237
  /// Floating-Point Trap on Condition (GLE)
  | FTRAPGLE = 238
  /// Floating-Point Trap on Condition (GT)
  | FTRAPGT = 239
  /// Floating-Point Trap on Condition (LE)
  | FTRAPLE = 240
  /// Floating-Point Trap on Condition (LT)
  | FTRAPLT = 241
  /// Floating-Point Trap on Condition (NE)
  | FTRAPNE = 242
  /// Floating-Point Trap on Condition (NGE)
  | FTRAPNGE = 243
  /// Floating-Point Trap on Condition (NGL)
  | FTRAPNGL = 244
  /// Floating-Point Trap on Condition (NGLE)
  | FTRAPNGLE = 245
  /// Floating-Point Trap on Condition (NGT)
  | FTRAPNGT = 246
  /// Floating-Point Trap on Condition (NLE)
  | FTRAPNLE = 247
  /// Floating-Point Trap on Condition (NLT)
  | FTRAPNLT = 248
  /// Floating-Point Trap on Condition (OGE)
  | FTRAPOGE = 249
  /// Floating-Point Trap on Condition (OGL)
  | FTRAPOGL = 250
  /// Floating-Point Trap on Condition (OGT)
  | FTRAPOGT = 251
  /// Floating-Point Trap on Condition (OLE)
  | FTRAPOLE = 252
  /// Floating-Point Trap on Condition (OLT)
  | FTRAPOLT = 253
  /// Floating-Point Trap on Condition (OR)
  | FTRAPOR = 254
  /// Floating-Point Trap on Condition (SEQ)
  | FTRAPSEQ = 255
  /// Floating-Point Trap on Condition (SF)
  | FTRAPSF = 256
  /// Floating-Point Trap on Condition (SNE)
  | FTRAPSNE = 257
  /// Floating-Point Trap on Condition (ST)
  | FTRAPST = 258
  /// Floating-Point Trap on Condition (T)
  | FTRAPT = 259
  /// Floating-Point Trap on Condition (UEQ)
  | FTRAPUEQ = 260
  /// Floating-Point Trap on Condition (UGE)
  | FTRAPUGE = 261
  /// Floating-Point Trap on Condition (UGT)
  | FTRAPUGT = 262
  /// Floating-Point Trap on Condition (ULE)
  | FTRAPULE = 263
  /// Floating-Point Trap on Condition (ULT)
  | FTRAPULT = 264
  /// Floating-Point Trap on Condition (UN)
  | FTRAPUN = 265
  /// Test Floating-Point Operand
  | FTST = 266
  /// Floating-Point 2 to the x Power
  | FTWOTOX = 267
  /// Take Illegal Instruction Trap
  | ILLEGAL = 268
  /// Jump
  | JMP = 269
  /// Jump to Subroutine
  | JSR = 270
  /// Load Effective Address
  | LEA = 271
  /// Link and Allocate
  | LINK = 272
  /// Logical Shift Left
  | LSL = 273
  /// Logical Shift Right
  | LSR = 274
  /// Move Data from Source to Destination
  | MOVE = 275
  /// Move 16-Byte Block
  | MOVE16 = 276
  /// Move Address
  | MOVEA = 277
  /// Move Control Register
  | MOVEC = 278
  /// Move Multiple Registers
  | MOVEM = 279
  /// Move Peripheral Data
  | MOVEP = 280
  /// Move Quick
  | MOVEQ = 281
  /// Move Address Space
  | MOVES = 282
  /// Signed Multiply
  | MULS = 283
  /// Unsigned Multiply
  | MULU = 284
  /// Negate Decimal with Extend
  | NBCD = 285
  /// Negate
  | NEG = 286
  /// Negate with Extend
  | NEGX = 287
  /// No Operation
  | NOP = 288
  /// Logical Complement
  | NOT = 289
  /// Inclusive-OR Logical
  | OR = 290
  /// Inclusive-OR Immediate
  | ORI = 291
  /// Pack BCD
  | PACK = 292
  /// Push Effective Address
  | PEA = 293
  /// Flush ATC Entry
  | PFLUSH = 294
  /// Flush All ATC Entries
  | PFLUSHA = 295
  /// Flush All ATC Entries Except Global
  | PFLUSHAN = 296
  /// Flush ATC Entry If Not Global
  | PFLUSHN = 297
  /// Test a Logical Address for Reading
  | PTESTR = 298
  /// Test a Logical Address for Writing
  | PTESTW = 299
  /// Reset External Devices
  | RESET = 300
  /// Rotate Left
  | ROL = 301
  /// Rotate Right
  | ROR = 302
  /// Rotate with Extend Left
  | ROXL = 303
  /// Rotate with Extend Right
  | ROXR = 304
  /// Return and Deallocate
  | RTD = 305
  /// Return from Exception
  | RTE = 306
  /// Return from Module
  | RTM = 307
  /// Return and Restore Codes
  | RTR = 308
  /// Return from Subroutine
  | RTS = 309
  /// Subtract Decimal with Extend
  | SBCD = 310
  /// Set According to Condition (CC)
  | SCC = 311
  /// Set According to Condition (CS)
  | SCS = 312
  /// Set According to Condition (EQ)
  | SEQ = 313
  /// Set According to Condition (F)
  | SF = 314
  /// Set According to Condition (GE)
  | SGE = 315
  /// Set According to Condition (GT)
  | SGT = 316
  /// Set According to Condition (HI)
  | SHI = 317
  /// Set According to Condition (LE)
  | SLE = 318
  /// Set According to Condition (LS)
  | SLS = 319
  /// Set According to Condition (LT)
  | SLT = 320
  /// Set According to Condition (MI)
  | SMI = 321
  /// Set According to Condition (NE)
  | SNE = 322
  /// Set According to Condition (PL)
  | SPL = 323
  /// Set According to Condition (T)
  | ST = 324
  /// Load Status Register and Stop
  | STOP = 325
  /// Subtract
  | SUB = 326
  /// Subtract Address
  | SUBA = 327
  /// Subtract Immediate
  | SUBI = 328
  /// Subtract Quick
  | SUBQ = 329
  /// Subtract with Extend
  | SUBX = 330
  /// Set According to Condition (VC)
  | SVC = 331
  /// Set According to Condition (VS)
  | SVS = 332
  /// Swap Register Halves
  | SWAP = 333
  /// Test and Set an Operand
  | TAS = 334
  /// Trap
  | TRAP = 335
  /// Trap on Condition (CC)
  | TRAPCC = 336
  /// Trap on Condition (CS)
  | TRAPCS = 337
  /// Trap on Condition (EQ)
  | TRAPEQ = 338
  /// Trap on Condition (F)
  | TRAPF = 339
  /// Trap on Condition (GE)
  | TRAPGE = 340
  /// Trap on Condition (GT)
  | TRAPGT = 341
  /// Trap on Condition (HI)
  | TRAPHI = 342
  /// Trap on Condition (LE)
  | TRAPLE = 343
  /// Trap on Condition (LS)
  | TRAPLS = 344
  /// Trap on Condition (LT)
  | TRAPLT = 345
  /// Trap on Condition (MI)
  | TRAPMI = 346
  /// Trap on Condition (NE)
  | TRAPNE = 347
  /// Trap on Condition (PL)
  | TRAPPL = 348
  /// Trap on Condition (T)
  | TRAPT = 349
  /// Trap on Overflow
  | TRAPV = 350
  /// Trap on Condition (VC)
  | TRAPVC = 351
  /// Trap on Condition (VS)
  | TRAPVS = 352
  /// Test an Operand
  | TST = 353
  /// Unlink
  | UNLK = 354
  /// Unpack BCD
  | UNPK = 355

type internal Op = Opcode
