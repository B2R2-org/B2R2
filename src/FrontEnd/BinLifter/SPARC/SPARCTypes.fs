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

namespace B2R2.FrontEnd.BinLifter.SPARC


open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.BinLifter.Tests")>]
do ()

/// <summary>
///   SPARC opcodes.
/// </summary>
type Opcode =
  /// Add
  | ADD = 0
  /// Add and modify cc's
  | ADDcc = 1
  /// Add with carry
  | ADDC = 2
  /// Add with Carry and modify cc's
  | ADDCcc = 3
  /// And
  | AND = 4
  /// And and modify cc's
  | ANDcc = 5
  /// And Not
  | ANDN = 6
  /// And Not and modify cc's
  | ANDNcc = 7
  /// Branch on Integer Condition Codes with Prediction (BPcc)
  /// Branch Always
  | BPA = 8
  /// Branch Never
  | BPN = 9
  /// Branch on Not Equal
  | BPNE = 10
  /// Branch on Equal
  | BPE = 11
  /// Branch on Greater
  | BPG = 12
  /// Branch on Less or Equal
  | BPLE = 13
  /// Branch on Greater or Equal
  | BPGE = 14
  /// Branch on Less
  | BPL = 15
  /// Branch on Greater Unsigned
  | BPGU = 16
  /// Branch on Less or Equal Unsigned
  | BPLEU = 17
  /// Branch on Carry Clear (Greater Than or Equal, Unsigned)
  | BPCC = 18
  /// Branch on Carry Set (Less than, Unsigned)
  | BPCS = 19
  /// Branch on Positive
  | BPPOS = 20
  /// Branch on Negative
  | BPNEG = 21
  /// Branch on Overflow Clear
  | BPVC = 22
  /// Branch on Overflow Set
  | BPVS = 23
  /// Branch on Integer Condition Codes (Bicc)
  /// Branch Always
  | BA = 24
  /// Branch Never
  | BN = 25
  /// Branch on Not Equal
  | BNE = 26
  /// Branch on Equal
  | BE = 27
  /// Branch on Greater
  | BG = 28
  /// Branch on Less or Equal
  | BLE = 29
  /// Branch on Greater or Equal
  | BGE = 30
  /// Branch on Less
  | BL = 31
  /// Branch on Greater Unsigned
  | BGU = 32
  /// Branch on Less or Equal Unsigned
  | BLEU = 33
  /// Branch on Carry Clear (Greater Than or Equal, Unsigned)
  | BCC = 34
  /// Branch on Carry Set (Less than, Unsigned)
  | BCS = 35
  /// Branch on Positive
  | BPOS = 36
  /// Branch on Negative
  | BNEG = 37
  /// Branch on Overflow Clear
  | BVC = 38
  /// Branch on Overflow Set
  | BVS = 39
  /// Branch on Integer Register with Prediction (BPr)
  /// Branch on Register Zero
  | BRZ = 40
  /// Branch on Register Less Than or Equal to Zero
  | BRLEZ = 41
  /// Branch on Register Less Than Zero
  | BRLZ = 42
  /// Branch on Register Not Zero
  | BRNZ = 43
  /// Branch on Register Greater Than Zero
  | BRGZ = 44
  /// Branch on Register Grater Than Equal to Zero
  | BRGEZ = 45
  /// Call and link
  | CALL = 46
  /// Compare and sawp word in alternate space
  | CASA = 47
  /// Compare and swap doubleword in alternate space
  | CASXA = 48
  /// Return from Trap (skip trapped instruction)
  | DONE = 49
  /// Floating-point absolute value
  /// Absolute Value Single
  | FABSs = 50
  /// Absolute Value Double
  | FABSd = 51
  /// Absolute Value Quad
  | FABSq = 52
  /// Floating-Point Add and Subtract
  /// Add Single
  | FADDs = 53
  /// Add Double
  | FADDd = 54
  /// Add Quad
  | FADDq = 55
  /// Branch on Floating-Point Condition Codes (FBFcc)
  /// Branch Always
  | FBA = 56
  /// Branch Never
  | FBN = 57
  /// Branch on Unordered
  | FBU = 58
  /// Branch on Greater
  | FBG = 59
  /// Branch on Unordered or Greater
  | FBUG = 60
  /// Branch on Less
  | FBL = 61
  /// Branch on Unordered or LEss
  | FBUL = 62
  /// Branch on Less or Greater
  | FBLG = 63
  /// Branch on Not Equal
  | FBNE = 64
  /// Branch on Equal
  | FBE = 65
  /// Branch on Unordered or Equal
  | FBUE = 66
  /// Branch on Greater or Euqal
  | FBGE = 67
  /// Branch on Unordered or Greater or Equal
  | FBUGE = 68
  /// Branch on Less or Equal
  | FBLE = 69
  /// Branch on Unordered or Less or Equal
  | FBULE = 70
  /// Branch on Ordered
  | FBO = 71
  /// Branch on Floating-Point Condition Codes with Prediction (FBPFcc)
  /// Branch Always
  | FBPA = 72
  /// Branch Never
  | FBPN = 73
  /// Branch on Unordered
  | FBPU = 74
  /// Branch on Greater
  | FBPG = 75
  /// Branch on Unordered or Greater
  | FBPUG = 76
  /// Branch on Less
  | FBPL = 77
  /// Branch on Unordered or LEss
  | FBPUL = 78
  /// Branch on Less or Greater
  | FBPLG = 79
  /// Branch on Not Equal
  | FBPNE = 80
  /// Branch on Equal
  | FBPE = 81
  /// Branch on Unordered or Equal
  | FBPUE = 82
  /// Branch on Greater or Euqal
  | FBPGE = 83
  /// Branch on Unordered or Greater or Equal
  | FBPUGE = 84
  /// Branch on Less or Equal
  | FBPLE = 85
  /// Branch on Unordered or Less or Equal
  | FBPULE = 86
  /// Branch on Ordered
  | FBPO = 87
  /// Floating-Point Compare
  /// Compare Single
  | FCMPs = 88
  /// Compare Double
  | FCMPd = 89
  /// Compare Quad
  | FCMPq = 90
  /// Compare Single and Exception if Unordered
  | FCMPEs = 91
  /// Compare Double and Exception if Unordered
  | FCMPEd = 92
  /// COmapre Quad and Exception if Unordered
  | FCMPEq = 93
  /// Floating-Point Multiply and Divide
  /// Divide Single
  | FDIVs = 94
  /// Divide Double
  | FDIVd = 95
  /// Divide Quad
  | FDIVq = 96
  /// Convert Integer to Floating-Point
  /// Convert 32-bit Integer to Single
  | FiTOs = 97
  /// Convert 32-bit Integer to Double
  | FiTOd = 98
  /// Convert 32-bit Integer to Quad
  | FiTOq = 99
  /// Flush Instruction Memory
  | FLUSH = 100
  /// Flush Register Windows
  | FLUSHW = 101
  /// Floating-Point Move
  /// Move Single
  | FMOVs = 102
  /// Move Double
  | FMOVd = 103
  /// Move Quad
  | FMOVq = 104
  /// Move Floating-Point Register on Condition (FMOVcc)
  /// Integer Condition Codes
  /// Move Always
  | FMOVA = 105
  /// Move Never
  | FMOVN = 106
  /// Move if Not Equal
  | FMOVNE = 107
  /// Move if Equal
  | FMOVE = 108
  /// Move if Greater
  | FMOVG = 109
  /// Move if Less or Equal
  | FMOVLE = 110
  /// Move if Greater or Equal
  | FMOVGE = 111
  /// Move if Less
  | FMOVL = 112
  /// Move if Greater Unsigned
  | FMOVGU = 113
  /// Move if Less or Equal Unsigned
  | FMOVLEU = 114
  /// Move if Carry Clear (Greater or Equal, Unsigned)
  | FMOVCC = 115
  /// Move if Carry Set (Less than, Unsigned)
  | FMOVCS = 116
  /// Move if Positive
  | FMOVPOS = 117
  /// Move if Negative
  | FMOVNEG = 118
  /// Move if Overflow Clear
  | FMOVVC = 119
  /// Move if Overflow Set
  | FMOVVS = 120
  /// Floating-Point Condition Codes
  /// More Always
  | FMOVFA = 121
  /// Move Never
  | FMOVFN = 122
  /// Move if Unordered
  | FMOVFU = 123
  /// Move if Greater
  | FMOVFG = 124
  /// Move if Unordered or Greater
  | FMOVFUG = 125
  /// Move if Less
  | FMOVFL = 126
  /// Move if Unordered or Less
  | FMOVFUL = 127
  /// Move if Less or Greater
  | FMOVFLG = 128
  /// Move if Not Equal
  | FMOVFNE = 129
  /// Move if Equal
  | FMOVFE = 130
  /// Move if Unordered or Equal
  | FMOVFUE = 131
  /// Move if Greater or Equal
  | FMOVFGE = 132
  /// Move if Unordered or Greater or Equal
  | FMOVFUGE = 133
  /// Move if Less or Equal
  | FMOVFLE = 134
  /// Move if Unordered or Less or Equal
  | FMOVFULE = 135
  /// Move if Ordered
  | FMOVFO = 136
  /// Move F-P Register on Integer Register Condition (FMOVr)
  /// Move if Register Zero
  | FMOVRZ = 137
  /// Move if Register Less Than or Equal to Zero
  | FMOVRLEZ = 138
  /// Move if Register Less Than Zero
  | FMOVRLZ = 139
  /// Move if Register Not Zero
  | FMOVRNZ = 140
  /// Move if Register Greater Than Zero
  | FMOVRGZ = 141
  /// Move if Register Greater Than or Equal to Zero
  | FMOVRGEZ = 142
  /// Floating-Point Multiply
  /// Multiply Single
  | FMULs = 143
  /// Multiply Double
  | FMULd = 144
  /// Multiply Quad
  | FMULq = 145
  /// Floating-Point Negate
  /// Negate Single
  | FNEGs = 146
  /// Negate Double
  | FNEGd = 147
  /// Negate Quad
  | FNEGq = 148
  /// Floating-Point Multiply Single to Double
  /// Multiply Single to Double
  | FsMULd = 149
  /// Multiyply Double to Quad
  | FdMULq = 150
  /// Floating-Point Square Root
  /// Square Root Single
  | FSQRTs = 151
  /// Square Root Double
  | FSQRTd = 152
  /// Square Root Quad
  | FSQRTq = 153
  /// Convert Floating Point to Integer
  /// Convert Single to 32-bit Integer
  | FsTOi = 154
  /// Convert Double to 32-bit Integer
  | FdTOi = 155
  /// Convert Quad to 32-bit Integer
  | FqTOi = 156
  /// Convert Between Floating-Point Formats
  /// Convert Single to Double
  | FsTOd = 157
  /// Convert Single to Quad
  | FsTOq = 158
  /// Convert Double to Single
  | FdTOs = 159
  /// Convert Double to Quad
  | FdTOq = 160
  /// Convert Quad to Single
  | FqTOs = 161
  /// Convert Quad To Double
  | FqTOd = 162
  /// Convert Floating Point 64-bit to Integer
  /// Convert Single to 64-bit to Integer
  | FsTOx = 163
  /// Convert Double to 64-bit to Integer
  | FdTOx = 164
  /// Convert Quad to 64-bit to integer
  | FqTOx = 165
  /// Floating-Point Subtract
  /// Subtract Single
  | FSUBs = 166
  /// Subtract Double
  | FSUBd = 167
  /// Subtract Quad
  | FSUBq = 168
  /// Convert 64-bit Integer to Floating-Point
  /// Convert 64-bit Integer to Single
  | FxTOs = 169
  /// Convert 64-bit Integer to Double
  | FxTOd = 170
  /// Convert 64-bit Integer to Quad
  | FxTOq = 171
  /// Illegal Instruction Trap
  | ILLTRAP = 172
  /// Implementation-Dependent Instructions 1
  | IMPDEP1 = 173
  /// Implementation-Dependent Instructions 2
  | IMPDEP2 = 174
  /// Jump and Link
  | JMPL = 175
  /// Load Doubleword
  | LDD = 176
  /// Load Doubleword from Alternate space
  | LDDA = 177
  /// Load Double Floating-Point Register
  | LDDF = 178
  /// Load Double Floating-Point Register from Alternate space
  | LDDFA = 179
  /// Load Floating-Point Register
  | LDF = 180
  /// Load Floating-Point Register from Alternate space
  | LDFA = 181
  /// Load Floating-Point State Register Lower
  | LDFSR = 182
  | LDQF = 183
  | LDQFA = 184
  | LDSB = 185
  | LDSBA = 186
  | LDSH = 187
  | LDSHA = 188
  | LDSTUB = 189
  | LDSTUBA = 190
  | LDSW = 191
  | LDSWA = 192
  | LDUB = 193
  | LDUBA = 194
  | LDUH = 195
  | LDUHA = 196
  | LDUW = 197
  | LDUWA = 198
  | LDX = 199
  | LDXA = 200
  | LDXFSR = 201
  | MEMBAR = 202
  /// Move Integer Register on Condition (MOVcc)
  /// Move Integer Register if Condition is Satisfied
  /// Move Always
  | MOVA = 203
  /// Move Never
  | MOVN = 204
  /// Move if Not Equal
  | MOVNE = 205
  /// Move if Equal
  | MOVE = 206
  /// Move if Greater
  | MOVG = 207
  /// Move if Less or Equal
  | MOVLE = 208
  /// Move if Greater or Equal
  | MOVGE = 209
  /// Move if Less
  | MOVL = 210
  /// Move if Greater Unsigned
  | MOVGU = 211
  /// Move if Less or Equal Unsigned
  | MOVLEU = 212
  /// Move if Carry Clear (Greater or Equal, Unsigned)
  | MOVCC = 213
  /// Move if Carry Set (Less than, Unsigned)
  | MOVCS = 214
  /// Move if Positive
  | MOVPOS = 215
  /// Move if Negative
  | MOVNEG = 216
  /// Move if Overflow Clear
  | MOVVC = 217
  /// Move if Overflow Set
  | MOVVS = 218
  /// Floating-Point Condition Codes
  /// More Always
  | MOVFA = 219
  /// Move Never
  | MOVFN = 220
  /// Move if Unordered
  | MOVFU = 221
  /// Move if Greater
  | MOVFG = 222
  /// Move if Unordered or Greater
  | MOVFUG = 223
  /// Move if Less
  | MOVFL = 224
  /// Move if Unordered or Less
  | MOVFUL = 225
  /// Move if Less or Greater
  | MOVFLG = 226
  /// Move if Not Equal
  | MOVFNE = 227
  /// Move if Equal
  | MOVFE = 228
  /// Move if Unordered or Equal
  | MOVFUE = 229
  /// Move if Greater or Equal
  | MOVFGE = 230
  /// Move if Unordered or Greater or Equal
  | MOVFUGE = 231
  /// Move if Less or Equal
  | MOVFLE = 232
  /// Move if Unordered or Less or Equal
  | MOVFULE = 233
  /// Move if Ordered
  | MOVFO = 234
  /// Move Integer Register on Register Condition (MOVR)
  /// Move if Register Zero
  | MOVRZ = 235
  /// Move if Register Less Than or Equal to Zero
  | MOVRLEZ = 236
  /// Move if Register Less Than Zero
  | MOVRLZ = 237
  /// Move if Register Not Zero
  | MOVRNZ = 238
  /// Move if Register Greater Than Zero
  | MOVRGZ = 239
  /// Move if Register Greater Than or Equal to Zero
  | MOVRGEZ = 240
  /// Multiply Step and modify cc's
  | MULScc = 241
  /// Multiply (signed or unsigned)
  | MULX = 242
  /// No Operation
  | NOP = 243
  /// Inclusive Or
  | OR = 244
  /// Inclusive Or and modify cc's
  | ORcc = 245
  /// Inclusive Or Not
  | ORN = 246
  /// Inclusive Or Not and modify cc's
  | ORNcc = 247
  /// Population Count
  | POPC = 248
  /// Prefetch Data
  | PREFETCH = 249
  /// Prefetch Data from Alternate Space
  | PREFETCHA = 250
  /// Read ASI Register
  | RDASI = 251
  /// Read Ancillary State Register
  | RDASR = 252
  /// Read Condition Codes Register
  | RDCCR = 253
  /// Read Floating-Point Register State Register
  | RDFPRS = 254
  /// Read Program Counter
  | RDPC = 255
  /// Read Privileged Register
  | RDPR = 256
  /// Read TICK Register
  | RDTICK = 257
  /// Read Y Register
  | RDY = 258
  | RESTORE = 259
  | RESTORED = 260
  | RETRY = 261
  | RETURN = 262
  | SAVE = 263
  | SAVED = 264
  /// Signed Integer Divide
  | SDIV = 265
  /// Signed Integer Divide and modify cc's
  | SDIVcc = 266
  /// Signed Divide
  | SDIVX = 267
  | SETHI = 268
  | SIR = 269
  | SLL = 270
  | SLLX = 271
  | SMUL = 272
  | SMULcc = 273
  | SRA = 274
  | SRAX = 275
  | SRL = 276
  | SRLX = 277
  | STB = 278
  | STBA = 279
  | STBAR = 280
  | STD = 281
  | STDA = 282
  | STDF = 283
  | STDFA = 284
  | STF = 285
  | STFA = 286
  | STFSR = 287
  | STH = 288
  | STHA = 289
  | STQF = 290
  | STQFA = 291
  | STW = 292
  | STWA = 293
  | STX = 294
  | STXA = 295
  | STXFSR = 296
  | SUB = 297
  | SUBcc = 298
  | SUBC = 299
  | SUBCcc = 300
  | SWAP = 301
  | SWAPA = 302
  | TADDcc = 303
  | TADDccTV = 304
  | Tcc = 305
  | TA = 306
  | TN = 307
  | TNE = 308
  | TE = 309
  | TG = 310
  | TLE = 311
  | TGE = 312
  | TL = 313
  | TGU = 314
  | TLEU = 315
  | TCC = 316
  | TCS = 317
  | TPOS = 318
  | TNEG = 319
  | TVC = 320
  | TVS = 321
  | TSUBcc = 322
  | TSUBccTV = 323
  | UDIV = 324
  | UDIVcc = 325
  | UDIVX = 326
  | UMUL = 327
  | UMULcc = 328
  | WRASI = 329
  | WRASR = 330
  | WRCCR = 331
  | WRFPRS = 332
  | WRPR = 333
  | WRY = 334
  | WNOR = 335
  | WNORcc = 336
  | XOR = 337
  | XORcc = 338
  | XNOR = 339
  | XNORcc = 340
  | FMOVsA = 341
  | FMOVdA = 342
  | FMOVqA = 343
  | FMOVsN = 344
  | FMOVdN = 345
  | FMOVqN = 346
  | FMOVsNE = 347
  | FMOVdNE = 348
  | FMOVqNE = 349
  | FMOVsE = 350
  | FMOVdE = 351
  | FMOVqE = 352
  | FMOVsG = 353
  | FMOVdG = 354
  | FMOVqG = 355
  | FMOVsLE = 357
  | FMOVdLE = 358
  | FMOVqLE = 359
  | FMOVsGE = 361
  | FMOVdGE = 362
  | FMOVqGE = 363
  | FMOVsL = 365
  | FMOVdL = 366
  | FMOVqL = 367
  | FMOVsGU = 369
  | FMOVdGU = 370
  | FMOVqGU = 371
  | FMOVsLEU = 373
  | FMOVdLEU = 374
  | FMOVqLEU = 375
  | FMOVsCC = 377
  | FMOVdCC = 378
  | FMOVqCC = 379
  | FMOVsCS = 382
  | FMOVdCS = 383
  | FMOVqCS = 384
  | FMOVsPOS = 386
  | FMOVdPOS = 387
  | FMOVqPOS = 388
  | FMOVsNEG = 390
  | FMOVdNEG = 391
  | FMOVqNEG = 392
  | FMOVsVC = 394
  | FMOVdVC = 395
  | FMOVqVC = 396
  | FMOVsVS = 398
  | FMOVdVS = 399
  | FMOVqVS = 400
  | FMOVFsA = 401
  | FMOVFdA = 402
  | FMOVFqA = 403
  | FMOVFsN = 404
  | FMOVFdN = 405
  | FMOVFqN = 406
  | FMOVFsU = 407
  | FMOVFdU = 408
  | FMOVFqU = 409
  | FMOVFsG = 410
  | FMOVFdG = 411
  | FMOVFqG = 412
  | FMOVFsUG = 413
  | FMOVFdUG = 414
  | FMOVFqUG = 415
  | FMOVFsL = 416
  | FMOVFdL = 417
  | FMOVFqL = 418
  | FMOVFsUL = 419
  | FMOVFdUL = 420
  | FMOVFqUL = 421
  | FMOVFsLG = 422
  | FMOVFdLG = 423
  | FMOVFqLG = 424
  | FMOVFsNE = 425
  | FMOVFdNE = 426
  | FMOVFqNE = 427
  | FMOVFsE = 428
  | FMOVFdE = 429
  | FMOVFqE = 430
  | FMOVFsUE = 431
  | FMOVFdUE = 432
  | FMOVFqUE = 433
  | FMOVFsGE = 434
  | FMOVFdGE = 435
  | FMOVFqGE = 436
  | FMOVFsUGE = 437
  | FMOVFdUGE = 438
  | FMOVFqUGE = 439
  | FMOVFsLE = 440
  | FMOVFdLE = 441
  | FMOVFqLE = 442
  | FMOVFsULE = 443
  | FMOVFdULE = 444
  | FMOVFqULE = 445
  | FMOVFsO = 446
  | FMOVFdO = 447
  | FMOVFqO = 448
  | FMOVRsZ = 449
  | FMOVRsLEZ = 450
  | FMOVRsLZ = 451
  | FMOVRsNZ = 452
  | FMOVRsGZ = 453
  | FMOVRsGEZ = 454
  | FMOVRdZ = 455
  | FMOVRdLEZ = 456
  | FMOVRdLZ = 457
  | FMOVRdNZ = 458
  | FMOVRdGZ = 459
  | FMOVRdGEZ = 460
  | FMOVRqZ = 461
  | FMOVRqLEZ = 462
  | FMOVRqLZ = 463
  | FMOVRqNZ = 464
  | FMOVRqGZ = 465
  | FMOVRqGEZ = 466
  | InvalidOp = 467

type ConditionCode =
  /// floating-point condition code
  | Fcc0 = 0
  | Fcc1 = 1
  | Fcc2 = 2
  | Fcc3 = 3
  /// integer condition codes
  /// based on either the 32-bit result of an operation
  | Icc = 4
  /// based on either the 64-bit result of an operation
  | Xcc = 5
  /// Invalid Condition Code
  | InvalidCC = 6

module ConditionCode =
  let inline ofRegID (n: RegisterID): ConditionCode =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: ConditionCode) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "fcc0" -> ConditionCode.Fcc0
    | "fcc1" -> ConditionCode.Fcc1
    | "fcc2" -> ConditionCode.Fcc2
    | "fcc3" -> ConditionCode.Fcc3
    | "icc" -> ConditionCode.Icc
    | "xcc" -> ConditionCode.Xcc
    | _ -> Utils.impossible ()

  let toString = function
    | ConditionCode.Fcc0 -> "%fcc0"
    | ConditionCode.Fcc1 -> "%fcc1"
    | ConditionCode.Fcc2 -> "%fcc2"
    | ConditionCode.Fcc3 -> "%fcc3"
    | ConditionCode.Icc -> "%icc"
    | ConditionCode.Xcc -> "%xcc"
    | _ -> Utils.impossible ()

type Const = int32

type AddressingMode =
  | DispMode of Register.SPARC * Const
  | PreIdxMode of Register.SPARC
  | PostIdxMode of Register.SPARC
  | UnchMode of Register.SPARC

type Operand =
  | OprReg of Register.SPARC
  | OprImm of Const
  | OprAddr of Const
  | OprMemory of AddressingMode
  | OprCC of ConditionCode
  | OprPriReg of Register.SPARC

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand
  | FourOperands of Operand * Operand * Operand * Operand
  | FiveOperands of Operand * Operand * Operand * Operand * Operand

/// Basic information obtained by parsing a SPARC instruction.
[<NoComparison; CustomEquality>]
type InsInfo = {
  /// Address.
  Address: Addr
  /// Instruction length.
  NumBytes: uint32
  /// Opcode.
  Opcode: Opcode
  /// Operands
  Operands: Operands
}
with
  override __.GetHashCode () =
    hash (__.Address,
          __.NumBytes,
          __.Opcode,
          __.Operands)

  override __.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = __.Address
      && i.NumBytes = __.NumBytes
      && i.Opcode = __.Opcode
      && i.Operands = __.Operands
    | _ -> false
