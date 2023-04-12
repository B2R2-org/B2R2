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

namespace B2R2.FrontEnd.BinLifter.PPC32

open B2R2
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.BinLifter.Tests")>]
do ()

/// <summary>
///   PPC32 opcodes. This type should be generated using
///   <c>scripts/genOpcode.fsx</c> from the `PPC32SupportedOpcode.txt`
///   file.
/// </summary>
type Opcode =
  | ADD = 0
  | ADDdot = 1
  | ADDO = 2
  | ADDOdot = 3
  | ADDC = 4
  | ADDCdot = 5
  | ADDCO = 6
  | ADDCOdot = 7
  | ADDE = 8
  | ADDEdot = 9
  | ADDEO = 10
  | ADDEOdot = 11
  | ADDME = 12
  | ADDMEdot = 13
  | ADDMEO = 14
  | ADDMEOdot = 15
  | ADDZE = 16
  | ADDZEdot = 17
  | ADDZEO = 18
  | ADDZEOdot = 19
  | DIVW = 20
  | DIVWdot = 21
  | DIVWO = 22
  | DIVWOdot = 23
  | DIVWU = 24
  | DIVWUdot = 25
  | DIVWUO = 26
  | DIVWUOdot = 27
  | MULLW = 28
  | MULLWdot = 29
  | MULLWO = 30
  | MULLWOdot = 31
  | NEG = 32
  | NEGdot = 33
  | NEGO = 34
  | NEGOdot = 35
  | SUBF = 36
  | SUBFdot = 37
  | SUBFO = 38
  | SUBFOdot = 39
  | SUBFC = 40
  | SUBFCdot = 41
  | SUBFCO = 42
  | SUBFCOdot = 43
  | SUBFE = 44
  | SUBFEdot = 45
  | SUBFEO = 46
  | SUBFEOdot = 47
  | SUBFME = 48
  | SUBFMEdot = 49
  | SUBFMEO = 50
  | SUBFMEOdot = 51
  | SUBFZE = 52
  | SUBFZEdot = 53
  | SUBFZEO = 54
  | SUBFZEOdot = 55
  | MULHW = 56
  | MULHWdot = 57
  | MULHWU = 58
  | MULHWUdot = 59
  | AND = 60
  | ANDdot = 61
  | ANDC = 62
  | ANDCdot = 63
  | CNTLZW = 64
  | CNTLZWdot = 65
  | DCBTST = 66
  | DCBA = 67
  | DCBF = 68
  | DCBI = 69
  | ICBI = 70
  | DCBST = 71
  | DCBT = 72
  | DCBZ = 73
  | ECIWX = 74
  | ECOWX = 75
  | EIEIO = 76
  | EQV = 77
  | EQVdot = 78
  | EXTSB = 79
  | EXTSBdot = 80
  | EXTSH = 81
  | EXTSHdot = 82
  | LBZUX = 83
  | LBZX = 84
  | LFDUX = 85
  | LFDX = 86
  | LFSUX = 87
  | LFSX = 88
  | LHAUX = 89
  | LHAX = 90
  | LHBRX = 91
  | LHZUX = 92
  | LHZX = 93
  | LSWI = 94
  | LSWX = 95
  | LWARX = 96
  | LWBRX = 97
  | LWZUX = 98
  | LWZX = 99
  | CMP = 100
  | CMPL = 101
  | MCRXR = 102
  | MFCR = 103
  | MFMSR = 104
  | MFSRIN = 105
  | MTMSR = 106
  | MTSRIN = 107
  | NAND = 108
  | NANDdot = 109
  | NOR = 110
  | NORdot = 111
  | OR = 112
  | ORdot = 113
  | ORC = 114
  | ORCdot = 115
  | SLW  = 116
  | SLWdot = 117
  | SRAW = 118
  | SRAWdot = 119
  | SRW = 120
  | SRWdot = 121
  | STBUX = 122
  | STBX = 123
  | STFDUX = 124
  | STFDX = 125
  | STFIWX = 126
  | STWUX = 127
  | STFSUX = 128
  | STWX = 129
  | STFSX = 130
  | STHBRX = 131
  | STHUX = 132
  | STHX = 133
  | STWBRX = 134
  | STWCXdot = 135
  | SYNC = 136
  | TLBIA = 137
  | TLBIE = 138
  | TLBSYNC = 139
  | XOR = 140
  | XORdot = 141
  | STSWX = 142
  | CMPW = 143
  | CMPLW = 144
  | TW = 145
  | TWEQ = 146
  | TRAP = 147
  | MTCRF = 148
  | MTSR = 149
  | MFSPR = 150
  | MFXER = 151
  | MFLR = 152
  | MFCTR = 153
  | MFTB = 154
  | MFTBU = 155
  | MTSPR = 156
  | MTXER = 157
  | MTLR = 158
  | MTCTR = 159
  | MFSR = 160
  | STSWI = 161
  | SRAWI = 162
  | SRAWIdot = 163
  | FCMPU = 164
  | FRSP = 165
  | FRSPdot = 166
  | FCTIW = 167
  | FCTIWdot = 168
  | FCTIWZ = 169
  | FCTIWZdot = 170
  | FDIV = 171
  | FDIVdot = 172
  | FSUB = 173
  | FSUBdot = 174
  | FADD = 175
  | FADDdot = 176
  | FSQRT = 177
  | FSQRTdot = 178
  | FSEL = 179
  | FSELdot = 180
  | FMUL =181
  | FMULdot = 182
  | FRSQRTE = 183
  | FRSQRTEdot = 184
  | FMSUB = 185
  | FMSUBdot = 186
  | FMADD = 187
  | FMADDdot = 188
  | FNMSUB = 189
  | FNMSUBdot = 190
  | FNMADD = 191
  | FNMADDdot = 192
  | FCMPO = 193
  | MTFSB1 = 194
  | MTFSB1dot = 195
  | FNEG = 196
  | FNEGdot = 197
  | MCRFS = 198
  | MTFSB0 = 199
  | MTFSB0dot = 200
  | FMR = 201
  | FMRdot = 202
  | MTFSFI = 203
  | MTFSFIdot = 204
  | FNABS = 205
  | FNABSdot = 206
  | FABS = 207
  | FABSdot = 208
  | MFFS = 209
  | MFFSdot = 210
  | MTFSF = 211
  | MTFSFdot = 212
  | FDIVS = 213
  | FDIVSdot = 214
  | FSUBS = 215
  | FSUBSdot = 216
  | FADDS = 217
  | FADDSdot = 218
  | FSQRTS = 219
  | FSQRTSdot = 220
  | FRES = 221
  | FRESdot = 222
  | FMULS = 223
  | FMULSdot = 224
  | FMSUBS = 225
  | FMSUBSdot = 226
  | FMADDS = 227
  | FMADDSdot = 228
  | FNMSUBS = 229
  | FNMSUBSdot = 230
  | FNMADDS = 231
  | FNMADDSdot = 232
  | TWLGT = 233
  | TWLLT = 234
  | TWLNL = 235
  | TWGT = 236
  | TWLT = 237
  | TWNE = 238
  | TWI = 239
  | TWLGTI = 240
  | TWLLTI = 241
  | TWEQI = 242
  | TWLNLI = 243
  | TWGTI = 244
  | TWLTI = 245
  | TWNEI = 246
  | MULLI = 247
  | SUBFIC = 248
  | CMPLI = 249
  | CMPLWI = 250
  | CMPI = 251
  | CMPWI = 252
  | ADDIC = 253
  | ADDICdot = 254
  | LI = 255
  | ADDI = 256
  | ADDIS = 257
  | LIS = 258
  | SC = 259
  | B = 260
  | BL = 261
  | BA = 262
  | BLA = 263
  | LWZ = 264
  | LWZU = 265
  | LBZ = 266
  | LBZU = 267
  | STW = 268
  | STWU = 269
  | STB = 270
  | STBU = 271
  | LHZ = 272
  | LHZU = 273
  | LHA = 274
  | LHAU = 275
  | STH = 276
  | STHU = 277
  | LMW = 278
  | STMW = 279
  | LFS = 280
  | LFSU = 281
  | LFD = 282
  | LFDU = 283
  | STFS = 284
  | STFSU = 285
  | STFD = 286
  | STFDU = 287
  | ORI = 288
  | NOP = 289
  | ORIS = 290
  | XORI = 291
  | XORIS = 292
  | ANDIdot = 293
  | ANDISdot = 294
  | RLWNM = 295
  | ROTLW = 296
  | RLWNMdot = 297
  | RLWIMI = 298
  | RLWIMIdot = 299
  | RLWINM = 300
  | RLWINMdot = 301
  | CLRLWI = 302
  | SLWI = 303
  | ROTLWI = 304
  | SRWI = 305
  | MCRF = 306
  | CRNOR = 307
  | CRNOT = 308
  | RFI = 309
  | CRANDC = 310
  | ISYNC = 311
  | CRXOR = 312
  | CRCLR = 313
  | CRAND = 314
  | CRNAND = 315
  | CREQV = 316
  | CRSET = 317
  | CRORC = 318
  | CROR = 319
  | CRMOVE = 320
  | BC = 321
  | BCA = 322
  | BCL = 323
  | BCLA = 324
  | BCLR = 325
  | BCLRL = 326
  | BCCTR = 327
  | BCCTRL = 328
  | BDNZF = 329
  | BDNZFA = 330
  | BDNZFL = 331
  | BDNZFLA = 332
  | BDZF = 333
  | BDZFA = 334
  | BDZFL = 335
  | BDZFLA = 336
  | BGE = 337
  | BLE = 338
  | BNE = 339
  | BNS = 340
  | BGEL = 341
  | BLEL = 342
  | BNEL = 343
  | BNSL = 344
  | BGEA = 345
  | BLEA = 346
  | BNEA = 347
  | BNSA = 348
  | BGELA = 349
  | BLELA = 350
  | BNELA = 351
  | BNSLA = 352
  | BDNZT = 353
  | BDNZTA = 354
  | BDNZTL = 355
  | BDNZTLA = 356
  | BDZT = 357
  | BDZTL = 358
  | BDZTA = 359
  | BDZTLA = 360
  | BLT = 361
  | BGT = 362
  | BEQ = 363
  | BSO = 364
  | BLTL = 365
  | BGTL = 366
  | BEQL = 367
  | BSOL = 368
  | BLTA = 369
  | BGTA = 370
  | BEQA = 371
  | BSOA = 372
  | BLTLA = 373
  | BGTLA = 374
  | BEQLA = 375
  | BSOLA = 376
  | BDNZ = 377
  | BDNZL = 378
  | BDNZA = 379
  | BDNZLA = 380
  | BDZ = 381
  | BDZL = 382
  | BDZA = 383
  | BDZLA = 384
  | BDNZFLR = 385
  | BDNZFLRL = 386
  | BDZFLR = 387
  | BDZFLRL = 388
  | BGELR = 389
  | BLELR = 390
  | BNELR = 391
  | BNSLR = 392
  | BGELRL = 393
  | BLELRL = 394
  | BNELRL = 395
  | BNSLRL = 396
  | BDNZTLR = 397
  | BDNZTLRL = 398
  | BDZTLR = 399
  | BDZTLRL = 400
  | BLTLR = 401
  | BGTLR = 402
  | BEQLR = 403
  | BSOLR = 404
  | BLTLRL = 405
  | BGTLRL = 406
  | BEQLRL = 407
  | BSOLRL = 408
  | BDNZLR = 409
  | BDNZLRL = 410
  | BDZLR = 411
  | BDZLRL = 412
  | BLR = 413
  | BLRL = 414
  | BGECTR = 415
  | BLECTR = 416
  | BNECTR = 417
  | BNSCTR = 418
  | BGECTRL = 419
  | BLECTRL = 420
  | BNECTRL = 421
  | BNSCTRL = 422
  | BLTCTR = 423
  | BGTCTR = 424
  | BEQCTR = 425
  | BSOCTR = 426
  | BLTCTRL = 427
  | BGTCTRL = 428
  | BEQCTRL = 429
  | BSOCTRL = 430
  | BCTR = 431
  | BCTRL = 432
  | MR = 433
  | InvalOP = 434
  | BTLRL = 435
  | BFLRL = 436
  | BTCTRL = 437
  | CLRRWI = 438
  | LWSYNC = 439

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
  override __.GetHashCode () =
    hash (__.Address,
          __.NumBytes,
          __.Opcode,
          __.Operands,
          __.OperationSize)
  override __.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = __.Address
      && i.NumBytes = __.NumBytes
      && i.Opcode = __.Opcode
      && i.Operands = __.Operands
      && i.OperationSize = __.OperationSize
    | _ -> false

// vim: set tw=80 sts=2 sw=2:
