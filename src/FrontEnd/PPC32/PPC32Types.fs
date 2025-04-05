﻿(*
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

namespace B2R2.FrontEnd.PPC32

open System.Runtime.CompilerServices
open B2R2

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.PPC32.Tests")>]
do ()

/// <summary>
///   PPC32 opcodes.
/// </summary>
type Opcode =
  | ADD = 0
  | ADDC = 1
  | ADDCdot = 2
  | ADDCO = 3
  | ADDCOdot = 4
  | ADDdot = 5
  | ADDE = 6
  | ADDEdot = 7
  | ADDEO = 8
  | ADDEOdot = 9
  | ADDI = 10
  | ADDIC = 11
  | ADDICdot = 12
  | ADDIS = 13
  | ADDME = 14
  | ADDMEdot = 15
  | ADDMEO = 16
  | ADDMEOdot = 17
  | ADDO = 18
  | ADDOdot = 19
  | ADDZE = 20
  | ADDZEdot = 21
  | ADDZEO = 22
  | ADDZEOdot = 23
  | AND = 24
  | ANDC = 25
  | ANDCdot = 26
  | ANDdot = 27
  | ANDIdot = 28
  | ANDISdot = 29
  | B = 30
  | BA = 31
  | BC = 32
  | BCA = 33
  | BCCTR = 34
  | BCCTRL = 35
  | BCL = 36
  | BCLA = 37
  | BCLR = 38
  | BCLRL = 39
  | BCTR = 40
  | BCTRL = 41
  | BDNZ = 42
  | BDNZA = 43
  | BDNZF = 44
  | BDNZFA = 45
  | BDNZFL = 46
  | BDNZFLA = 47
  | BDNZFLR = 48
  | BDNZFLRL = 49
  | BDNZL = 50
  | BDNZLA = 51
  | BDNZLR = 52
  | BDNZLRL = 53
  | BDNZT = 54
  | BDNZTA = 55
  | BDNZTL = 56
  | BDNZTLA = 57
  | BDNZTLR = 58
  | BDNZTLRL = 59
  | BDZ = 60
  | BDZA = 61
  | BDZF = 62
  | BDZFA = 63
  | BDZFL = 64
  | BDZFLA = 65
  | BDZFLR = 66
  | BDZFLRL = 67
  | BDZL = 68
  | BDZLA = 69
  | BDZLR = 70
  | BDZLRL = 71
  | BDZT = 72
  | BDZTA = 73
  | BDZTL = 74
  | BDZTLA = 75
  | BDZTLR = 76
  | BDZTLRL = 77
  | BEQ = 78
  | BEQA = 79
  | BEQCTR = 80
  | BEQCTRL = 81
  | BEQL = 82
  | BEQLA = 83
  | BEQLR = 84
  | BEQLRL = 85
  | BFLRL = 86
  | BGE = 87
  | BGEA = 88
  | BGECTR = 89
  | BGECTRL = 90
  | BGEL = 91
  | BGELA = 92
  | BGELR = 93
  | BGELRL = 94
  | BGT = 95
  | BGTA = 96
  | BGTCTR = 97
  | BGTCTRL = 98
  | BGTL = 99
  | BGTLA = 100
  | BGTLR = 101
  | BGTLRL = 102
  | BL = 103
  | BLA = 104
  | BLE = 105
  | BLEA = 106
  | BLECTR = 107
  | BLECTRL = 108
  | BLEL = 109
  | BLELA = 110
  | BLELR = 111
  | BLELRL = 112
  | BLR = 113
  | BLRL = 114
  | BLT = 115
  | BLTA = 116
  | BLTCTR = 117
  | BLTCTRL = 118
  | BLTL = 119
  | BLTLA = 120
  | BLTLR = 121
  | BLTLRL = 122
  | BNE = 123
  | BNEA = 124
  | BNECTR = 125
  | BNECTRL = 126
  | BNEL = 127
  | BNELA = 128
  | BNELR = 129
  | BNELRL = 130
  | BNS = 131
  | BNSA = 132
  | BNSCTR = 133
  | BNSCTRL = 134
  | BNSL = 135
  | BNSLA = 136
  | BNSLR = 137
  | BNSLRL = 138
  | BSO = 139
  | BSOA = 140
  | BSOCTR = 141
  | BSOCTRL = 142
  | BSOL = 143
  | BSOLA = 144
  | BSOLR = 145
  | BSOLRL = 146
  | BTCTRL = 147
  | BTLRL = 148
  | CLRLWI = 149
  | CLRRWI = 150
  | CMP = 151
  | CMPI = 152
  | CMPL = 153
  | CMPLI = 154
  | CMPLW = 155
  | CMPLWI = 156
  | CMPW = 157
  | CMPWI = 158
  | CNTLZW = 159
  | CNTLZWdot = 160
  | CRAND = 161
  | CRANDC = 162
  | CRCLR = 163
  | CREQV = 164
  | CRMOVE = 165
  | CRNAND = 166
  | CRNOR = 167
  | CRNOT = 168
  | CROR = 169
  | CRORC = 170
  | CRSET = 171
  | CRXOR = 172
  | DCBA = 173
  | DCBF = 174
  | DCBI = 175
  | DCBST = 176
  | DCBT = 177
  | DCBTST = 178
  | DCBZ = 179
  | DIVW = 180
  | DIVWdot = 181
  | DIVWO = 182
  | DIVWOdot = 183
  | DIVWU = 184
  | DIVWUdot = 185
  | DIVWUO = 186
  | DIVWUOdot = 187
  | ECIWX = 188
  | ECOWX = 189
  | EIEIO = 190
  | EQV = 191
  | EQVdot = 192
  | EXTSB = 193
  | EXTSBdot = 194
  | EXTSH = 195
  | EXTSHdot = 196
  | FABS = 197
  | FABSdot = 198
  | FADD = 199
  | FADDdot = 200
  | FADDS = 201
  | FADDSdot = 202
  | FCMPO = 203
  | FCMPU = 204
  | FCTIW = 205
  | FCTIWdot = 206
  | FCTIWZ = 207
  | FCTIWZdot = 208
  | FDIV = 209
  | FDIVdot = 210
  | FDIVS = 211
  | FDIVSdot = 212
  | FMADD = 213
  | FMADDdot = 214
  | FMADDS = 215
  | FMADDSdot = 216
  | FMR = 217
  | FMRdot = 218
  | FMSUB = 219
  | FMSUBdot = 220
  | FMSUBS = 221
  | FMSUBSdot = 222
  | FMUL = 223
  | FMULdot = 224
  | FMULS = 225
  | FMULSdot = 226
  | FNABS = 227
  | FNABSdot = 228
  | FNEG = 229
  | FNEGdot = 230
  | FNMADD = 231
  | FNMADDdot = 232
  | FNMADDS = 233
  | FNMADDSdot = 234
  | FNMSUB = 235
  | FNMSUBdot = 236
  | FNMSUBS = 237
  | FNMSUBSdot = 238
  | FRES = 239
  | FRESdot = 240
  | FRSP = 241
  | FRSPdot = 242
  | FRSQRTE = 243
  | FRSQRTEdot = 244
  | FSEL = 245
  | FSELdot = 246
  | FSQRT = 247
  | FSQRTdot = 248
  | FSQRTS = 249
  | FSQRTSdot = 250
  | FSUB = 251
  | FSUBdot = 252
  | FSUBS = 253
  | FSUBSdot = 254
  | ICBI = 255
  | InvalOP = 256
  | ISYNC = 257
  | LBZ = 258
  | LBZU = 259
  | LBZUX = 260
  | LBZX = 261
  | LFD = 262
  | LFDU = 263
  | LFDUX = 264
  | LFDX = 265
  | LFS = 266
  | LFSU = 267
  | LFSUX = 268
  | LFSX = 269
  | LHA = 270
  | LHAU = 271
  | LHAUX = 272
  | LHAX = 273
  | LHBRX = 274
  | LHZ = 275
  | LHZU = 276
  | LHZUX = 277
  | LHZX = 278
  | LI = 279
  | LIS = 280
  | LMW = 281
  | LSWI = 282
  | LSWX = 283
  | LWARX = 284
  | LWBRX = 285
  | LWSYNC = 286
  | LWZ = 287
  | LWZU = 288
  | LWZUX = 289
  | LWZX = 290
  | MCRF = 291
  | MCRFS = 292
  | MCRXR = 293
  | MFCR = 294
  | MFCTR = 295
  | MFFS = 296
  | MFFSdot = 297
  | MFLR = 298
  | MFMSR = 299
  | MFSPR = 300
  | MFSR = 301
  | MFSRIN = 302
  | MFTB = 303
  | MFTBU = 304
  | MFXER = 305
  | MR = 306
  | MTCRF = 307
  | MTCTR = 308
  | MTFSB0 = 309
  | MTFSB0dot = 310
  | MTFSB1 = 311
  | MTFSB1dot = 312
  | MTFSF = 313
  | MTFSFdot = 314
  | MTFSFI = 315
  | MTFSFIdot = 316
  | MTLR = 317
  | MTMSR = 318
  | MTSPR = 319
  | MTSR = 320
  | MTSRIN = 321
  | MTXER = 322
  | MULHW = 323
  | MULHWdot = 324
  | MULHWU = 325
  | MULHWUdot = 326
  | MULLI = 327
  | MULLW = 328
  | MULLWdot = 329
  | MULLWO = 330
  | MULLWOdot = 331
  | NAND = 332
  | NANDdot = 333
  | NEG = 334
  | NEGdot = 335
  | NEGO = 336
  | NEGOdot = 337
  | NOP = 338
  | NOR = 339
  | NORdot = 340
  | OR = 341
  | ORC = 342
  | ORCdot = 343
  | ORdot = 344
  | ORI = 345
  | ORIS = 346
  | RFI = 347
  | RLWIMI = 348
  | RLWIMIdot = 349
  | RLWINM = 350
  | RLWINMdot = 351
  | RLWNM = 352
  | RLWNMdot = 353
  | ROTLW = 354
  | ROTLWI = 355
  | SC = 356
  | SLW  = 357
  | SLWdot = 358
  | SLWI = 359
  | SRAW = 360
  | SRAWdot = 361
  | SRAWI = 362
  | SRAWIdot = 363
  | SRW = 364
  | SRWdot = 365
  | SRWI = 366
  | STB = 367
  | STBU = 368
  | STBUX = 369
  | STBX = 370
  | STFD = 371
  | STFDU = 372
  | STFDUX = 373
  | STFDX = 374
  | STFIWX = 375
  | STFS = 376
  | STFSU = 377
  | STFSUX = 378
  | STFSX = 379
  | STH = 380
  | STHBRX = 381
  | STHU = 382
  | STHUX = 383
  | STHX = 384
  | STMW = 385
  | STSWI = 386
  | STSWX = 387
  | STW = 388
  | STWBRX = 389
  | STWCXdot = 390
  | STWU = 391
  | STWUX = 392
  | STWX = 393
  | SUBF = 394
  | SUBFC = 395
  | SUBFCdot = 396
  | SUBFCO = 397
  | SUBFCOdot = 398
  | SUBFdot = 399
  | SUBFE = 400
  | SUBFEdot = 401
  | SUBFEO = 402
  | SUBFEOdot = 403
  | SUBFIC = 404
  | SUBFME = 405
  | SUBFMEdot = 406
  | SUBFMEO = 407
  | SUBFMEOdot = 408
  | SUBFO = 409
  | SUBFOdot = 410
  | SUBFZE = 411
  | SUBFZEdot = 412
  | SUBFZEO = 413
  | SUBFZEOdot = 414
  | SYNC = 415
  | TLBIA = 416
  | TLBIE = 417
  | TLBSYNC = 418
  | TRAP = 419
  | TW = 420
  | TWEQ = 421
  | TWEQI = 422
  | TWGE = 423
  | TWGEI = 424
  | TWGT = 425
  | TWGTI = 426
  | TWI = 427
  | TWLE = 428
  | TWLEI = 429
  | TWLGT = 430
  | TWLGTI = 431
  | TWLLE = 432
  | TWLLEI = 433
  | TWLLT = 434
  | TWLLTI = 435
  | TWLNL = 436
  | TWLNLI = 437
  | TWLT = 438
  | TWLTI = 439
  | TWNE = 440
  | TWNEI = 441
  | XOR = 442
  | XORdot = 443
  | XORI = 444
  | XORIS = 445

type internal Op = Opcode

type Condition =
  /// Less than [LT].
  | LT = 0x0
  /// Less than or equal (equivalent to ng) [GT].
  | LE = 0x1
  /// Equal [EQ].
  | EQ = 0x2
  /// Greater than or equal (equivalent to nl) [LT].
  | GE = 0x3
  /// Greater than [GT].
  | GT = 0x4
  /// Not less than (equivalent to ge) [LT].
  | NL = 0x5
  /// Not equal [EQ].
  | NE = 0x6
  /// Not greater than (equivalent to le) [GT].
  | NG = 0x7
  /// Summary overflow [SO].
  | SO = 0x8
  /// Not summary overflow [SO].
  | NS = 0x9
  /// Unordered (after floating-point comparison) [SO].
  | UN = 0xA
  /// Not unordered (after floating-point comparison) [SO].
  | NU = 0xB

type Operand =
  | OprReg of Register
  | OprMem of D * Register
  | OprImm of Imm
  | OprAddr of TargetAddr
  | OprBI of uint32
/// Immediate field specifying a 16-bit signed two's complement integer that is
/// sign-extended to 32 bits.
and D = int32
and Imm = uint64
/// Used to specify a CR bit to be used as the condition of a branch conditional
/// instruction.
and TargetAddr = uint64

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand
  | FiveOperands of Operand * Operand * Operand * Operand * Operand

type internal Instruction = Opcode * Operands

/// Basic information obtained by parsing a PPC32 instruction.
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
  /// Effective address.
  EffectiveAddress: Addr
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
