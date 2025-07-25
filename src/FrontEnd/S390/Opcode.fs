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

namespace B2R2.FrontEnd.S390

/// <summary>
/// Represents a S390 opcode.
/// </summary>
type Opcode =
  /// Invalid Opcode
  | InvalOp = 0
  /// Add Registers (32)
  | AR = 1
  /// Add Registers (64)
  | AGR = 2
  /// Add Registers (64 <- 32)
  | AGFR = 3
  /// Add (32)
  | ARK = 4
  /// Add (64)
  | AGRK = 5
  /// Add (32)
  | A = 6
  /// Add (32)
  | AY = 7
  /// Add (64)
  | AG = 8
  /// Add (64 <- 32)
  | AGF = 9
  /// Add Immediate (32)
  | AFI = 10
  /// Add Immediate to Register (64 <- 32)
  | AGFI = 11
  /// Add Immediate to Register (32 <- 16)
  | AHIK = 12
  /// Add Immediate to Register (64 <- 16)
  | AGHIK = 13
  /// Add Immediate to Register (32 <- 8)
  | ASI = 14
  /// Add Immediate to Register (64 <- 8)
  | AGSI = 15
  /// Add Halfword (32 <- 16)
  | AH = 16
  /// Add Halfword (32 <- 16)
  | AHY = 17
  /// Add Halfword (64 <- 16)
  | AGH = 18
  /// Add Halfword Immediate to Register (32)
  | AHI = 19
  /// Add Halfword Immediate to Register (64)
  | AGHI = 20
  /// Add High (32)
  | AHHHR = 21
  /// Add High (32)
  | AHHLR = 22
  /// Add Immediate High (32)
  | AIH = 23
  /// Add Logical Registers (32)
  | ALR = 24
  /// Add Logical Registers (64)
  | ALGR = 25
  /// Add Logical Registers (64 <- 32)
  | ALGFR = 26
  /// Add Logical (32)
  | ALRK = 27
  /// Add Logical (64)
  | ALGRK = 28
  /// Add Logical (32)
  | AL = 29
  /// Add Logical (32)
  | ALY = 30
  /// Add Logical (64)
  | ALG = 31
  /// Add Logical (64 <- 32)
  | ALGF = 32
  /// Add Logical Immediate to Register (32)
  | ALFI = 33
  /// Add Logical Immediate to Register (64 <- 32)
  | ALGFI = 34
  /// Add Logical High (32)
  | ALHHHR = 35
  /// Add Logical High (32)
  | ALHHLR = 36
  /// Add Logical Registers with Carry (32)
  | ALCR = 37
  /// Add Logical Registers with Carry (64)
  | ALCGR = 38
  /// Add Logical with Carry (32)
  | ALC = 39
  /// Add Logical with Carry (64)
  | ALCG = 40
  /// Add Logical with Signed Immediate (32 <- 8)
  | ALSI = 41
  /// Add Logical with Signed Immediate (64 <- 8)
  | ALGSI = 42
  /// Add Logical with Signed Immediate (32 <- 16)
  | ALHSIK = 43
  /// Add Logical with Signed Immediate (64 <- 16)
  | ALGHSIK = 44
  /// Add Logical with Signed Immediate High (32)
  | ALSIH = 45
  /// Add Logical with Signed Immediate High (32)
  | ALSIHN = 46
  /// AND Registers (32)
  | NR = 47
  /// AND Registers (64)
  | NGR = 48
  /// And Registers (32)
  | NRK = 49
  /// And Registers (64)
  | NGRK = 50
  /// AND (32)
  | N = 51
  /// AND (32)
  | NY = 52
  /// AND (64)
  | NG = 53
  /// AND Immediate
  | NI = 54
  /// AND Immediate
  | NIY = 55
  /// AND (Character)
  | NC = 56
  /// AND Register with Immediate (high, bit 0-31)
  | NIHF = 57
  /// AND Register with Immediate (high high, bit 0-15)
  | NIHH = 58
  /// AND Register with Immediate (high low, bit 16-31)
  | NIHL = 59
  /// AND Register with Immediate (low, bit 32-63)
  | NILF = 60
  /// AND Register with Immediate (low high, bit 32-47)
  | NILH = 61
  /// AND Register with Immediate (low low, bit 48-63)
  | NILL = 62
  /// Branch and Link
  | BALR = 63
  /// Branch and Link
  | BAL = 64
  /// Branch and Save
  | BASR = 65
  /// Branch and Save
  | BAS = 66
  /// Branch and Save and Set Mode
  | BASSM = 67
  /// Branch and Set Mode
  | BSM = 68
  /// Branch Indirect on Condition
  | BIC = 69
  /// Branch on Condition
  | BCR = 70
  /// Branch on Condition
  | BC = 71
  /// Branch on Count Register (32)
  | BCTR = 72
  /// Branch on Count Register (64)
  | BCTGR = 73
  /// Branch on Count (32)
  | BCT = 74
  /// Branch on Count (64)
  | BCTG = 75
  /// Branch on Index High (32)
  | BXH = 76
  /// Branch on Index High (64)
  | BXHG = 77
  /// Branch on Index Low or Equal (32)
  | BXLE = 78
  /// Branch on Index Low or Equal (64)
  | BXLEG = 79
  /// Branch Prediction Preload
  | BPP = 80
  /// Branch Prediction Relative Preload
  | BPRP = 81
  /// Branch Relative and Save
  | BRAS = 82
  /// Branch Relative and Save Long
  | BRASL = 83
  /// Branch Relative on Condition
  | BRC = 84
  /// Branch Relative on Condition Long
  | BRCL = 85
  /// Branch Relative on Count Register (32)
  | BRCT = 86
  /// Branch Relative on Count Register (64)
  | BRCTG = 87
  /// Branch Relative on Count High (32)
  | BRCTH = 88
  /// Branch Relative on Index High (32)
  | BRXH = 89
  /// Branch Relative on Index High (64)
  | BRXHG = 90
  /// Branch Relative on Index Low or Equal (32)
  | BRXLE = 91
  /// Branch Relative on Index Low or Equal (64)
  | BRXLG = 92
  /// Checksun
  | CKSM = 93
  /// Cipher Messasge
  | KM = 94
  /// Cipher Message with Chaining
  | KMC = 95
  /// Cipher Message with Authentication
  | KMA = 96
  /// Cipher Message with Cipher Feedback
  | KMF = 97
  /// Cipher Message with Counter
  | KMCTR = 98
  /// Cipher Message with Output Feedback
  | KMO = 99
  /// Compare Registers (32)
  | CR = 100
  /// Compare Registers (64)
  | CGR = 101
  /// Compare Registers (64 <- 32)
  | CGFR = 102
  /// Compare (32)
  | C = 103
  /// Compare (32)
  | CY = 104
  /// Compare (64)
  | CG = 105
  /// Compare (64 <- 32)
  | CGF = 106
  /// Compare Register with Immediate (32)
  | CFI = 107
  /// Compare Register with Immediate (64 <- 32)
  | CGFI = 108
  /// Compare Relative Long (32)
  | CRL = 109
  /// Compare Relative Long (64)
  | CGRL = 110
  /// Compare Relative Long (64 <- 32)
  | CGFRL = 111
  /// Compare and Branch (32)
  | CRB = 112
  /// Compare and Branch (64)
  | CGRB = 113
  /// Compare and Branch Relative (32)
  | CRJ = 114
  /// Compare and Branch Relative (64)
  | CGRJ = 115
  /// Compare Immediate and Branch (32 <- 8)
  | CIB = 116
  /// Compare Immediate And Branch (64 <- 8)
  | CGIB = 117
  /// Compare Immediate And Branch Relative (32 <- 8)
  | CIJ = 118
  /// Compare Immediate and Branch Relative (64 <- 8)
  | CGIJ = 119
  /// Compare and Form Codeword
  | CFC = 120
  /// Compare and Swap (32)
  | CS = 121
  /// Compare and Swap (32)
  | CSY = 122
  /// Compare and Swap (64)
  | CSG = 123
  /// Compare Double and Swap (32)
  | CDS = 124
  /// Compare Double and Swap (32)
  | CDSY = 125
  /// Compare Double and Swap (64)
  | CDSG = 126
  /// Compare and Swap and Store
  | CSST = 127
  /// Compare and Trap (32)
  | CRT = 128
  /// Compare and Trap (64)
  | CGRT = 129
  /// Compare Immediate and Trap (32 <- 16)
  | CIT = 130
  /// Compare Immediate and Trap (64 <- 16)
  | CGIT = 131
  /// Compare Halfword (32 <- 16)
  | CH = 132
  /// Compare Halfword (32 <- 16)
  | CHY = 133
  /// Compare Halfword (64 <- 16)
  | CGH = 134
  /// Compare Halfword Immediate (32 <- 16)
  | CHI = 135
  /// Compare Halfword Immediate (64 <- 16)
  | CGHI = 136
  /// Compare Halfword Immediate (16)
  | CHHSI = 137
  /// Compare Halfword Immediate (32 <- 16)
  | CHSI = 138
  /// Compare Halfword Immediate (64 <- 16)
  | CGHSI = 139
  /// Compare Halfword Relative Long (32 <- 16)
  | CHRL = 140
  /// Compare Halfword Relative Long (64 <- 16)
  | CGHRL = 141
  /// Compare High (32)
  | CHHR = 142
  /// Compare High (32)
  | CHLR = 143
  /// Compare High (32)
  | CHF = 144
  /// Compare Immediate High (32)
  | CIH = 145
  /// Compare Logical (32)
  | CLR = 146
  /// Compare Logical (64)
  | CLGR = 147
  /// Compare Logical (64 <- 32)
  | CLGFR = 148
  /// Compare Logical (32)
  | CL = 149
  /// Compare Logical (32)
  | CLY = 150
  /// Compare Logical (64)
  | CLG = 151
  /// Compare Logical (64 <- 32)
  | CLGF = 152
  /// Compare Logical (Character)
  | CLC = 153
  /// Compare Logical Immediate (32)
  | CLFI = 154
  /// Compare Logical Immediate (64 <- 32)
  | CLGFI = 155
  /// Compare Logical Immediate
  | CLI = 156
  /// Compare Logical Immediate
  | CLIY = 157
  /// Compare Logical Immediate (32 <- 16)
  | CLFHSI = 158
  /// Compare Logical Immediate (64 <- 16)
  | CLGHSI = 159
  /// Compare Logical Immediate (16)
  | CLHHSI = 160
  /// Compare Logical Relative Long (32)
  | CLRL = 161
  /// Compare Logical Relative Long (64)
  | CLGRL = 162
  /// Compare Logical Relative Long (64 <- 32)
  | CLGFRL = 163
  /// Compare Logical Relative Long (32 <- 16)
  | CLHRL = 164
  /// Compare Logical Relative Long (64 <- 16)
  | CLGHRL = 165
  /// Compare Logical and Branch (32)
  | CLRB = 166
  /// Compare Logical and Branch (64)
  | CLGRB = 167
  /// Compare Logical and Branch Relative (32)
  | CLRJ = 168
  /// Compare Logical and Branch Relative (64)
  | CLGRJ = 169
  /// Compare Logical Immediate and Branch (32 <- 8)
  | CLIB = 170
  /// Compare Logical Immediate and Branch (64 <- 8)
  | CLGIB = 171
  /// Compare Logical Immediate and Branch Relative (32 <- 8)
  | CLIJ = 172
  /// Compare Logical Immediate and Branch Relative (64 <- 8)
  | CLGIJ = 173
  /// Compare Logical and Trap (32)
  | CLRT = 174
  /// Compare Logical and Trap (64)
  | CLGRT = 175
  /// Compare Logical and Trap (32)
  | CLT = 176
  /// Compare Logical and Trap (64)
  | CLGT = 177
  /// Compare Logical Immediate and Trap (32 <- 16)
  | CLFIT = 178
  /// Compare Logical Immediate and Trap (64 <- 16)
  | CLGIT = 179
  /// Compare Logical Char under Mask (low)
  | CLM = 180
  /// Compare Logical Char under Mask (low)
  | CLMY = 181
  /// Compare Logical Char under Mask (high)
  | CLMH = 182
  /// Compare Logical High (32)
  | CLHHR = 183
  /// Compare Logical High (32)
  | CLHLR = 184
  /// Compare Logical High (32)
  | CLHF = 185
  /// Compare Logical Immediate High (32)
  | CLIH = 186
  /// Compare Logical Long
  | CLCL = 187
  /// Compare Logical Long Extended
  | CLCLE = 188
  /// Compare Logical Long Unicode
  | CLCLU = 189
  /// Compare Logical String
  | CLST = 190
  /// Compare Until Substring Equal
  | CUSE = 191
  /// Compression Call
  | CMPSC = 192
  /// Compute Intermediate Message Digest
  | KIMD = 193
  /// Compute Last Message Digest
  | KLMD = 194
  /// Compute Message Authentication Code
  | KMAC = 195
  /// Convert to Binary (32)
  | CVB = 196
  /// Convert to Binary (32)
  | CVBY = 197
  /// Convert to Binary (64)
  | CVBG = 198
  /// Convert to Decimal (32)
  | CVD = 199
  /// Convert to Decimal (32)
  | CVDY = 200
  /// Convert to Decimal (64)
  | CVDG = 201
  /// Convert UTF-16 to UTF-32
  | CU24 = 202
  /// Convert UTF-16 to UTF-8
  | CU21 = 203
  /// Convert Unicode to UTF-8
  | CUUTF = 204
  /// Convert UTF-32 to UTF-16
  | CU42 = 205
  /// Convert UTF-32 to UTF-8
  | CU41 = 206
  /// Convert UTF-8 to UTF-16
  | CU12 = 207
  /// Convert UTF-8 to Unicode
  | CUTFU = 208
  /// Convert UTF-8 to UTF-32
  | CU14 = 209
  /// Copy Access
  | CPYA = 210
  /// Divide (32 <- 64)
  | DR = 211
  /// Divide (32 <- 64)
  | D = 212
  /// Divide Logical (32 <- 64)
  | DLR = 213
  /// Divide Logical (64 <- 128)
  | DLGR = 214
  /// Divide Logical (32 <- 64)
  | DL = 215
  /// Divide Logical (64 <- 128)
  | DLG = 216
  /// Divide Single (64)
  | DSGR = 217
  /// Divide Single (64 <- 32)
  | DSGFR = 218
  /// Divide Single (64)
  | DSG = 219
  /// Divide Single (64 <- 32)
  | DSGF = 220
  /// Exclusive OR (32)
  | XR = 221
  /// Exclusive OR (64)
  | XGR = 222
  /// Exclusive OR (32)
  | XRK = 223
  /// Exclusive OR (64)
  | XGRK = 224
  /// Exclusive OR (32)
  | X = 225
  /// Exclusive OR (32)
  | XY = 226
  /// Exclusive OR (64)
  | XG = 227
  /// Exclusive OR (Immediate)
  | XI = 228
  /// Exclusive OR (Immediate)
  | XIY = 229
  /// Exclusive OR (Character)
  | XC = 230
  /// Exclusive OR Immediate (high)
  | XIHF = 231
  /// Exclusive OR Immediate (low)
  | XILF = 232
  /// Execute
  | EX = 233
  /// Execute Relative Long
  | EXRL = 234
  /// Extract Access Register
  | EAR = 235
  /// Extract Cache Attribute
  | ECAG = 236
  /// Extract CPU Time
  | ECTG = 237
  /// Extract PSW
  | EPSW = 238
  /// Extract Transaction Nesting Depth
  | ETND = 239
  /// Find Leftmost One
  | FLOGR = 240
  /// Insert Character
  | IC = 241
  /// Insert Character
  | ICY = 242
  /// Insert Characters under Mask (low)
  | ICM = 243
  /// Insert Characters under Mask (low)
  | ICMY = 244
  /// Insert Characters under Mask (high)
  | ICMH = 245
  /// Insert Immediate (high)
  | IIHF = 246
  /// Insert Immediate (high high)
  | IIHH = 247
  /// Insert Immediate (high low)
  | IIHL = 248
  /// Insert Immediate (low)
  | IILF = 249
  /// Insert Immediate (low high)
  | IILH = 250
  /// Insert Immediate (low low)
  | IILL = 251
  /// Insert Program Mask
  | IPM = 252
  /// Load (32)
  | LR = 253
  /// Load (64)
  | LGR = 254
  /// Load (64 <- 32)
  | LGFR = 255
  /// Load (32)
  | L = 256
  /// Load (32)
  | LY = 257
  /// Load (64)
  | LG = 258
  /// Load (64 <- 32)
  | LGF = 259
  /// Load Immediate (64 <- 32)
  | LGFI = 260
  /// Load Relative Long (32)
  | LRL = 261
  /// Load Relative Long (64)
  | LGRL = 262
  /// Load Relative Long (64 <- 32)
  | LGFRL = 263
  /// Load Access Multiple
  | LAM = 264
  /// Load Access Multiple
  | LAMY = 265
  /// Load Address
  | LA = 266
  /// Load Address
  | LAY = 267
  /// Load Address Extended
  | LAE = 268
  /// Load Address Extended
  | LAEY = 269
  /// Load Address Relative Long
  | LARL = 270
  /// Load and Add (32)
  | LAA = 271
  /// Load and Add (64)
  | LAAG = 272
  /// Load and Add Logical (32)
  | LAAL = 273
  /// Load and Add Logical (64)
  | LAALG = 274
  /// Load and AND (32)
  | LAN = 275
  /// Load and AND (64)
  | LANG = 276
  /// Load and Exclusive OR (32)
  | LAX = 277
  /// Load and Exclusive OR (64)
  | LAXG = 278
  /// Load and OR (32)
  | LAO = 279
  /// Load and OR (64)
  | LAOG = 280
  /// Load and Test (32)
  | LTR = 281
  /// Load and Test (64)
  | LTGR = 282
  /// Load and Test (64 <- 32)
  | LTGFR = 283
  /// Load and Test (32)
  | LT = 284
  /// Load and Test (64)
  | LTG = 285
  /// Load and Test (64 <- 32)
  | LTGF = 286
  /// Load and Trap (32L <- 32)
  | LAT = 287
  /// Load and Trap (64)
  | LGAT = 288
  /// Load and Zero Rightmost Byte (32)
  | LZRF = 289
  /// Load and Zero Rightmost Byte (64)
  | LZRG = 290
  /// Load Byte (32)
  | LBR = 291
  /// Load Byte (64)
  | LGBR = 292
  /// Load Byte (32)
  | LB = 293
  /// Load Byte (64)
  | LGB = 294
  /// Load Byte High (32 <- 8)
  | LBH = 295
  /// Load Complement (32)
  | LCR = 296
  /// Load Complement (64)
  | LCGR = 297
  /// Load Complement (64 <- 32)
  | LCGFR = 298
  /// Load Count to Block Boundary
  | LCBB = 299
  /// Load Guarded (64)
  | LGG = 300
  /// Load Logical and Shift Guarded (64 <- 32)
  | LLGFSG = 301
  /// Load Guarded Storage Controls
  | LGSC = 302
  /// Load Halfword (32)
  | LHR = 303
  /// Load Halfword (64)
  | LGHR = 304
  /// Load Halfword (32)
  | LH = 305
  /// Load Halfword (32)
  | LHY = 306
  /// Load Halfword (64)
  | LGH = 307
  /// Load Halfword Immediate (32)
  | LHI = 308
  /// Load Halfword Immediate (64)
  | LGHI = 309
  /// Load Halfword Relative Long (32 <- 16)
  | LHRL = 310
  /// Load Halfword Relative Long (64 <- 16)
  | LGHRL = 311
  /// Load Halfword High (32 <- 16)
  | LHH = 312
  /// Load Halfword Immediate on Condition (32 <- 16)
  | LOCHI = 313
  /// Load Halfword Immediate on Condition (64 <- 16)
  | LOCGHI = 314
  /// Load Halfword High Immediate on Condition (32 <- 16)
  | LOCHHI = 315
  /// Load High (32)
  | LFH = 316
  /// Load High and Trap (32)
  | LFHAT = 317
  /// Load Logical (64 <- 32)
  | LLGFR = 318
  /// Load Logical (64 <- 32)
  | LLGF = 319
  /// Load Logical Relative Long (64 <- 32)
  | LLGFRL = 320
  /// Load Logical and Trap (64 <- 32)
  | LLGFAT = 321
  /// Load Logical and Zero Rightmost Byte (64 <- 32)
  | LLZRGF = 322
  /// Load Logical Character (32)
  | LLCR = 323
  /// Load Logical Character (64)
  | LLGCR = 324
  /// Load Logical Character (32)
  | LLC = 325
  /// Load Logical Character (64)
  | LLGC = 326
  /// Load Logical Character High (32 <- 8)
  | LLCH = 327
  /// Load Logical Halfword (32)
  | LLHR = 328
  /// Load Logical Halfword (64)
  | LLGHR = 329
  /// Load Logical Halfword (32)
  | LLH = 330
  /// Load Logical Halfword (64)
  | LLGH = 331
  /// Load Logical Halfword Relative Long (32 <- 16)
  | LLHRL = 332
  /// Load Logical Halfword Relative Long (64 <- 16)
  | LLGHRL = 333
  /// Load Logical Halfword High (32 <- 16)
  | LLHH = 334
  /// Load Logical Immediate (high)
  | LLIHF = 335
  /// Load Logical Immediate (high high)
  | LLIHH = 336
  /// Load Logical Immediate (high low)
  | LLIHL = 337
  /// Load Logical Immediate (low)
  | LLILF = 338
  /// Load Logical Immediate (low high)
  | LLILH = 339
  /// Load Logical Immediate (low low)
  | LLILL = 340
  /// Load Logical Thirty One Bits
  | LLGTR = 341
  /// Load Logical Thirty One Bits
  | LLGT = 342
  /// Load Logical Thirty One Bits and Trap (64 <- 31)
  | LLGTAT = 343
  /// Load Multiple (32)
  | LM = 344
  /// Load Multiple (32)
  | LMY = 345
  /// Load Multiple (64)
  | LMG = 346
  /// Load Multiple Disjoint
  | LMD = 347
  /// Load Multiple High
  | LMH = 348
  /// Load Negative (32)
  | LNR = 349
  /// Load Negative (64)
  | LNGR = 350
  /// Load Negative (64 <- 32)
  | LNGFR = 351
  /// Load on Condition (32)
  | LOCR = 352
  /// Load on Condition (64)
  | LOCGR = 353
  /// Load on Condition (32)
  | LOC = 354
  /// Load on Condition (64)
  | LOCG = 355
  /// Load High on Condition (32)
  | LOCFHR = 356
  /// Load High on Condition (32)
  | LOCFH = 357
  /// Load Pair Disjoint (32)
  | LPD = 358
  /// Load Pair Disjoint (64)
  | LPDG = 359
  /// Load Pair from Quadword
  | LPQ = 360
  /// Load Positive (32)
  | LPR = 361
  /// Load Positive (64)
  | LPGR = 362
  /// Load Positive (64 <- 32)
  | LPGFR = 363
  /// Load Reserved (32)
  | LRVR = 364
  /// Load Reserved (64)
  | LRVGR = 365
  /// Load Reserved (16)
  | LRVH = 366
  /// Load Reserved (32)
  | LRV = 367
  /// Load Reserved (64)
  | LRVG = 368
  /// Monitor Call
  | MC = 369
  /// Move (Character)
  | MVC = 370
  /// Move (16 <- 16)
  | MVHHI = 371
  /// Move (32 <- 16)
  | MVHI = 372
  /// Move (64 <- 16)
  | MVGHI = 373
  /// Move (Immediate)
  | MVI = 374
  /// Move (Immediate)
  | MVIY = 375
  /// Move Inverse
  | MVCIN = 376
  /// Move Long
  | MVCL = 377
  /// Move Long Extended
  | MVCLE = 378
  /// Move Long Unicode
  | MVCLU = 379
  /// Move Numerics
  | MVN = 380
  /// Move String
  | MVST = 381
  /// Move with Offset
  | MVO = 382
  /// Move Zones
  | MVZ = 383
  /// Multiply (64 <- 32)
  | MR = 384
  /// Multiply (128 <- 64)
  | MGRK = 385
  /// Multiply (64 <- 32)
  | M = 386
  /// Multiply (64 <- 32)
  | MFY = 387
  /// Multiply (128 <- 64)
  | MG = 388
  /// Multiply Halfword (32)
  | MH = 389
  /// Multiply Halfword (32)
  | MHY = 390
  /// Multiply Halfword (64 <- 16)
  | MGH = 391
  /// Multiply Halfword Immediate (32)
  | MHI = 392
  /// Multiply Halfword Immediate (64)
  | MGHI = 393
  /// Multiply Logical (64 <- 32)
  | MLR = 394
  /// Multiply Logical (128 <- 64)
  | MLGR = 395
  /// Multiply Logical (64 <- 32)
  | ML = 396
  /// Multiply Logical (128 <- 64)
  | MLG = 397
  /// Multiply Single (32)
  | MSR = 398
  /// Multiply Single (32)
  | MSRKC = 399
  /// Multiply Single (64)
  | MSGR = 400
  /// Multiply Single (64)
  | MSGRKC = 401
  /// Multiply Single (64 <- 32)
  | MSGFR = 402
  /// Multiply Single (32)
  | MS = 403
  /// Multiply Single (32)
  | MSC = 404
  /// Multiply Single (32)
  | MSY = 405
  /// Multiply Single (64)
  | MSG = 406
  /// Multiply Single (64)
  | MSGC = 407
  /// Multiply Single (64 <- 32)
  | MSGF = 408
  /// Multiply Single Immediate (32)
  | MSFI = 409
  /// Multiply Single Immediate (64 <- 32)
  | MSGFI = 410
  /// Next Instruction Access Intent
  | NIAI = 411
  /// Nontransactional Store (64)
  | NTSTG = 412
  /// OR (32)
  | OR = 413
  /// OR (64)
  | OGR = 414
  /// OR (32)
  | ORK = 415
  /// OR (64)
  | OGRK = 416
  /// OR (32)
  | O = 417
  /// OR (32)
  | OY = 418
  /// OR (64)
  | OG = 419
  /// OR (Immediate)
  | OI = 420
  /// OR (Immediate)
  | OIY = 421
  /// OR (Character)
  | OC = 422
  /// OR Immediate (high)
  | OIHF = 423
  /// OR Immediate (high high)
  | OIHH = 424
  /// OR Immediate (high low)
  | OIHL = 425
  /// OR Immediate (low)
  | OILF = 426
  /// OR Immediate (low high)
  | OILH = 427
  /// OR Immediate (low low)
  | OILL = 428
  /// Pack
  | PACK = 429
  /// Pack ASCII
  | PKA = 430
  /// Pack Unicode
  | PKU = 431
  /// Perform Cryptographic Computation
  | PCC = 432
  /// Perform Locked Operation
  | PLO = 433
  /// Perform Processor Assist
  | PPA = 434
  /// Perform Random Number Operation
  | PRNO = 435
  /// Population Count
  | POPCNT = 436
  /// Prefetch Data
  | PFD = 437
  /// Prefetch Data Relative Long
  | PFDRL = 438
  /// Rotate Left Single Logical (32)
  | RLL = 439
  /// Rotate Left Single Logical (64)
  | RLLG = 440
  /// Rotate then AND Selected Bits
  | RNSBG = 441
  /// Rotate then Exclusive OR Selected Bits
  | RXSBG = 442
  /// Rotate then OR Selected Bits
  | ROSBG = 443
  /// Rotate then Insert Selected Bits
  | RISBG = 444
  /// Rotate then Insert Selected Bits (64)
  | RISBGN = 445
  /// Rotate then Insert Selected Bits High (32)
  | RISBHG = 446
  /// Rotate then Insert Selected Bits Low (32)
  | RISBLG = 447
  /// Search String
  | SRST = 448
  /// Search String Unicode
  | SRSTU = 449
  /// Set Access Register
  | SAR = 450
  /// Set Addressing Mode (24)
  | SAM24 = 451
  /// Set Addressing Mode (31)
  | SAM31 = 452
  /// Set Addressing Mode (64)
  | SAM64 = 453
  /// Set Program Mask
  | SPM = 454
  /// Shift Left Double
  | SLDA = 455
  /// Shift Left Double Logical
  | SLDL = 456
  /// Shift Left Single (32)
  | SLA = 457
  /// Shift Left Single (32)
  | SLAK = 458
  /// Shift Left Single (64)
  | SLAG = 459
  /// Shift Left Single Logical (32)
  | SLL = 460
  /// Shift Left Single Logical (32)
  | SLLK = 461
  /// Shift Left Single Logical (64)
  | SLLG = 462
  /// Shift Right Double
  | SRDA = 463
  /// Shift Right Double Logical
  | SRDL = 464
  /// Shift Right Single (32)
  | SRA = 465
  /// Shift Right Single (32)
  | SRAK = 466
  /// Shift Right Single (64)
  | SRAG = 467
  /// Shift Right Single Logical (32)
  | SRL = 468
  /// Shift Right Single Logical (32)
  | SRLK = 469
  /// Shift Right Single Logical (64)
  | SRLG = 470
  /// Store (32)
  | ST = 471
  /// Store (32)
  | STY = 472
  /// Store (64)
  | STG = 473
  /// Store Relative Long (32)
  | STRL = 474
  /// Store Relative Long (64)
  | STGRL = 475
  /// Store Access Multiple
  | STAM = 476
  /// Store Access Multiple
  | STAMY = 477
  /// Store Character
  | STC = 478
  /// Store Character
  | STCY = 479
  /// Store Character High (8)
  | STCH = 480
  /// Store Characters under Mask (low)
  | STCM = 481
  /// Store Characters under Mask (low)
  | STCMY = 482
  /// Store Characters under Mask (high)
  | STCMH = 483
  /// Store Clock
  | STCK = 484
  /// Store Clock Fast
  | STCKF = 485
  /// Store Clock Extended
  | STCKE = 486
  /// Store Facility List Extended
  | STFLE = 487
  /// Store Guarded Storage Controls
  | STGSC = 488
  /// Store Halfword
  | STH = 489
  /// Store Halfword
  | STHY = 490
  /// Store Halfword Relative Long
  | STHRL = 491
  /// Store Halfword High (16)
  | STHH = 492
  /// Store High (32)
  | STFH = 493
  /// Store Multiple (32)
  | STM = 494
  /// Store Multiple (32)
  | STMY = 495
  /// Store Multiple (64)
  | STMG = 496
  /// Store Multiple High
  | STMH = 497
  /// Store on Condition (32)
  | STOC = 498
  /// Store on Condition (64)
  | STOCG = 499
  /// Store High on Condition
  | STOCFH = 500
  /// Store Pair to Quadword
  | STPQ = 501
  /// Store Reversed (16)
  | STRVH = 502
  /// Store Reversed (32)
  | STRV = 503
  /// Store Reversed (46)
  | STRVG = 504
  /// Subtract (32)
  | SR = 505
  /// Subtract (64)
  | SGR = 506
  /// Subtract (64 <- 32)
  | SGFR = 507
  /// Subtract (32)
  | SRK = 508
  /// Subtract (64)
  | SGRK = 509
  /// Subtract (32)
  | S = 510
  /// Subtract (32)
  | SY = 511
  /// Subtract (64)
  | SG = 512
  /// Subtract (64 <- 32)
  | SGF = 513
  /// Subtract Halfword
  | SH = 514
  /// Subtract Halfword
  | SHY = 515
  /// Subtract Halfword (64 <- 16)
  | SGH = 516
  /// Subtract High (32)
  | SHHHR = 517
  /// Subtract High (32)
  | SHHLR = 518
  /// Subtract Logical (32)
  | SLR = 519
  /// Subtract Logical (64)
  | SLGR = 520
  /// Subtract Logical (64 <- 32)
  | SLGFR = 521
  /// Subtract Logical (32)
  | SLRK = 522
  /// Subtract Logical (64)
  | SLGRK = 523
  /// Subtract Logical (32)
  | SL = 524
  /// Subtract Logical (32)
  | SLY = 525
  /// Subtract Logical (64)
  | SLG = 526
  /// Subtract Logical (64 <- 32)
  | SLGF = 527
  /// Subtract Logical Immediate (32)
  | SLFI = 528
  /// Subtract Logical Immediate (64 <- 32)
  | SLGFI = 529
  /// Subtract Logical High (32)
  | SLHHHR = 530
  /// Subtract Logical High (32)
  | SLHHLR = 531
  /// Subtract Logical with Borrow (32)
  | SLBR = 532
  /// Subtract Logical with Borrow (64)
  | SLBGR = 533
  /// Subtract Logical with Borrow (32)
  | SLB = 534
  /// Subtract Logical with Borrow (64)
  | SLBG = 535
  /// Supervisor Call
  | SVC = 536
  /// Test Addressing Mode
  | TAM = 537
  /// Test and Set
  | TS = 538
  /// Test under Mask
  | TM = 539
  /// Test under Mask
  | TMY = 540
  /// Test under Mask (high high)
  | TMHH = 541
  /// Test under Mask (high low)
  | TMHL = 542
  /// Test under Mask (low high)
  | TMLH = 543
  /// Test under Mask (low low)
  | TMLL = 544
  /// Transaction Abort
  | TABORT = 545
  /// Transaction Begin (nonconstrained)
  | TBEGIN = 546
  /// Transaction Begin (constrained)
  | TBEGINC = 547
  /// Transaction End
  | TEND = 548
  /// Translate
  | TR = 549
  /// Translate and Test
  | TRT = 550
  /// Translate and Test Extended
  | TRTE = 551
  /// Translate and Test Reverse Extended
  | TRTRE = 552
  /// Translate and Test Reverse
  | TRTR = 553
  /// Translate Extended
  | TRE = 554
  /// Translate One to One
  | TROO = 555
  /// Translate One to Two
  | TROT = 556
  /// Translate Two to One
  | TRTO = 557
  /// Translate Two to Two
  | TRTT = 558
  /// Unpack
  | UNPK = 559
  /// Unpack ASCII
  | UNPKA = 560
  /// Unpack Unicode
  | UNPKU = 561
  /// Update Tree
  | UPT = 562
  /// Add Decimal
  | AP = 563
  /// Compare Decimal
  | CP = 564
  /// Divide Decimal
  | DP = 565
  /// Edit
  | ED = 566
  /// Edit and Mark
  | EDMK = 567
  /// Multiply Decimal
  | MP = 568
  /// Shift and Round Decimal
  | SRP = 569
  /// Subtract Decimal
  | SP = 570
  /// Test Decimal
  | TP = 571
  /// Zero and Add
  | ZAP = 572
  /// Convert BFP to HFP (short to long)
  | THDER = 573
  /// Convert BFP to HFP (long)
  | THDR = 574
  /// Convert HFP to BFP (short to long)
  | TBEDR = 575
  /// Convert HFP to BFP (long)
  | TBDR = 576
  /// Copy Sign (long)
  | CPSDR = 577
  /// Extract FPC
  | EFPC = 578
  /// Load (short)
  | LER = 579
  /// Load (long)
  | LDR = 580
  /// Load (extended)
  | LXR = 581
  /// Load (short)
  | LE = 582
  /// Load (long)
  | LD = 583
  /// Load (short)
  | LEY = 584
  /// Load (long)
  | LDY = 585
  /// Load Complement (long)
  | LCDFR = 586
  /// Load FPC
  | LFPC = 587
  /// Load FPC and Signal
  | LFAS = 588
  /// Load FPR from GR (long <- 64)
  | LDGR = 589
  /// Load GR from FPR (64 <- long)
  | LGDR = 590
  /// Load Negative (long)
  | LNDFR = 591
  /// Load Positive (long)
  | LPDFR = 592
  /// Load Zero (short)
  | LZER = 593
  /// Load Zero (long)
  | LZDR = 594
  /// Load Zero (extended)
  | LZXR = 595
  /// Perform Floating-Point Operation
  | PFPO = 596
  /// Set BFP Rounding Mode (2 bit)
  | SRNM = 597
  /// Set BFP Rounding Mode (3 bit)
  | SRNMB = 598
  /// Set DPF Rounding Mode
  | SRNMT = 599
  /// Set FPC
  | SFPC = 600
  /// Set FPC and Signal
  | SFASR = 601
  /// Store (short)
  | STE = 602
  /// Store (long)
  | STD = 603
  /// Store (short)
  | STEY = 604
  /// Store (long)
  | STDY = 605
  /// Store FPC
  | STFPC = 606
  /// Branch and Set Authority
  | BSA = 607
  /// Branch and Stack
  | BAKR = 608
  /// Branch in Subspace Group
  | BSG = 609
  /// Compare and Replace DAT Table Entry
  | CRDTE = 610
  /// Compare and Swap and Purge
  | CSP = 611
  /// Compare and Swap and Purge
  | CSPG = 612
  /// Diagnose
  | Diagnose = 613
  /// Extract and Set Extended Authority
  | ESEA = 614
  /// Extract Primary ASN
  | EPAR = 615
  /// Extract Primary ASN and Instance
  | EPAIR = 616
  /// Extract Secondary ASN
  | ESAR = 617
  /// Extract Secondary ASN and Instance
  | ESAIR = 618
  /// Extract Stacked Registers (32)
  | EREG = 619
  /// Extract Stacked Registers (64)
  | EREGG = 620
  /// Extract Stacked State
  | ESTA = 621
  /// Insert Address Space Control
  | IAC = 622
  /// Insert PSW Key
  | IPK = 623
  /// Insert Reference Bits Multiple
  | IRBM = 624
  /// Insert Storage Key Extended
  | ISKE = 625
  /// Insert Virtual Storage Key
  | IVSK = 626
  /// Invalidate DAT Table Entry
  | IDTE = 627
  /// Invalidate Page Table Entry
  | IPTE = 628
  /// Load Address Space Parameters
  | LASP = 629
  /// Load Control (32)
  | LCTL = 630
  /// Load Control (64)
  | LCTLG = 631
  /// Load Page Table Entry Address
  | LPTEA = 632
  /// Load PSW
  | LPSW = 633
  /// Load PSW Extended
  | LPSWE = 634
  /// Load Real Address (32)
  | LRA = 635
  /// Load Real Address (32)
  | LRAY = 636
  /// Load Real Address (64)
  | LRAG = 637
  /// Load Using Real Address (32)
  | LURA = 638
  /// Load Using Real Address (64)
  | LURAG = 639
  /// Modify Stacked State
  | MSTA = 640
  /// Move Page
  | MVPG = 641
  /// Move to Primary
  | MVCP = 642
  /// Move to Secondary
  | MVCS = 643
  /// Move with Destination Key
  | MVCDK = 644
  /// Move with Key
  | MVCK = 645
  /// Move with Optional Specifications
  | MVCOS = 646
  /// Move with Source Key
  | MVCSK = 647
  /// Page In
  | PGIN = 648
  /// Page Out
  | PGOUT = 649
  /// Perform Cryptography Key Management Operation
  | PCKMO = 650
  /// Perform Frame Management Function
  | PFMF = 651
  /// Perform Timing Facility Function
  | PTFF = 652
  /// Perform Topology Function
  | PTF = 653
  /// Program Call
  | PC = 654
  /// Program Return
  | PR = 655
  /// Program Transfer
  | PT = 656
  /// Program Transfer with Instance
  | PTI = 657
  /// Purge ALB
  | PALB = 658
  /// Purge TLB
  | PTLB = 659
  /// Reset Reference Bit Extended
  | RRBE = 660
  /// Reset Reference Bit Multiple
  | RRBM = 661
  /// Resume Program
  | RP = 662
  /// Set Address Space Control
  | SAC = 663
  /// Set Address Space Control Fast
  | SACF = 664
  /// Set Clock
  | SCK = 665
  /// Set Clock Comparator
  | SCKC = 666
  /// Set Clock Programmable Field
  | SCKPF = 667
  /// Set CPU Timer
  | SPT = 668
  /// Set Prefix
  | SPX = 669
  /// Set PSW Key from Address
  | SPKA = 670
  /// Set Secondary ASN
  | SSAR = 671
  /// Set Secondary ASN with Instance
  | SSAIR = 672
  /// Set Storage Key Extended
  | SSKE = 673
  /// Set System Mask
  | SSM = 674
  /// Signal Processor
  | SIGP = 675
  /// Store Clock Comparator
  | STCKC = 676
  /// Store Control (32)
  | STCTL = 677
  /// Store Control (64)
  | STCTG = 678
  /// Store CPU Address
  | STAP = 679
  /// Store CPU ID
  | STIDP = 680
  /// Store CPU Timer
  | STPT = 681
  /// Store Facility List
  | STFL = 682
  /// Store Prefix
  | STPX = 683
  /// Store Real Address
  | STRAG = 684
  /// Store System Information
  | STSI = 685
  /// Store then AND System Mask
  | STNSM = 686
  /// Store then OR System Mask
  | STOSM = 687
  /// Store Using Real Address (32)
  | STURA = 688
  /// Store Using Real Address (64)
  | STURG = 689
  /// Test Access
  | TAR = 690
  /// Test Block
  | TB = 691
  /// Test Pending External Interruption
  | TPEI = 692
  /// Test Protection
  | TPROT = 693
  /// Trace (32)
  | TRACE = 694
  /// Trace (64)
  | TRACG = 695
  /// Trap
  | TRAP2 = 696
  /// TRAP
  | TRAP4 = 697
  /// Cancel Subchannel
  | XSCH = 698
  /// Clear Subchannel
  | CSCH = 699
  /// Halt Subchannel
  | HSCH = 700
  /// Modify Subchannel
  | MSCH = 701
  /// Reset Channel Path
  | RCHP = 702
  /// Resume Subchannel
  | RSCH = 703
  /// Set Address Limit
  | SAL = 704
  /// Set Channel Monitor
  | SCHM = 705
  /// Start Subchannel
  | SSCH = 706
  /// Store Channel Path Status
  | STCPS = 707
  /// Store Channel Report Word
  | STCRW = 708
  /// Store Subchannel
  | STSCH = 709
  /// Test Pending Interruption
  | TPI = 710
  /// Test Subchannel
  | TSCH = 711
  /// Add Normalized (short HFP)
  | AER = 712
  /// Add Normalized (long HFP)
  | ADR = 713
  /// Add Normalized (extended HFP)
  | AXR = 714
  /// Add Normalized (short HFP)
  | AE = 715
  /// Add Normalized (long HFP)
  | AD = 716
  /// Add Unnormalized (short HFP)
  | AUR = 717
  /// Add Unnormalized (long HFP)
  | AWR = 718
  /// Add Unnormalized (short HFP)
  | AU = 719
  /// Add Unnormalized (long HFP)
  | AW = 720
  /// Compare (short HFP)
  | CER = 721
  /// Compare (long HFP)
  | CDR = 722
  /// Compare (extended HFP)
  | CXR = 723
  /// Compare (short HFP)
  | CE = 724
  /// Compare (long HFP)
  | CD = 725
  /// Convert from Fixed (short HFP <- 32)
  | CEFR = 726
  /// Convert from Fixed (long HFP <- 32)
  | CDFR = 727
  /// Convert from Fixed (extended HFP <- 32)
  | CXFR = 728
  /// Convert from Fixed (short HFP <- 64)
  | CEGR = 729
  /// Convert from Fixed (long HFP <- 64)
  | CDGR = 730
  /// Convert from Fixed (extended HFP <- 64)
  | CXGR = 731
  /// Convert to Fixed (32 <- short HFP)
  | CFER = 732
  /// Convert to Fixed (32 <- long HFP)
  | CFDR = 733
  /// Convert to Fixed (32 <- extended HFP)
  | CFXR = 734
  /// Convert to Fixed (64 <- short HFP)
  | CGER = 735
  /// Convert to Fixed (64 <- long HFP)
  | CGDR = 736
  /// Convert to Fixed (64 <- extended HFP)
  | CGXR = 737
  /// Divide (short HFP)
  | DER = 738
  /// Divide (long HFP)
  | DDR = 739
  /// Divide (extended HFP)
  | DXR = 740
  /// Divide (short HFP)
  | DE = 741
  /// Divide (long HFP)
  | DD = 742
  /// Halve (short HFP)
  | HER = 743
  /// Halve (long HFP)
  | HDR = 744
  /// Load and Test (short HFP)
  | LTER = 745
  /// Load and Test (long HFP)
  | LTDR = 746
  /// Load and Test (extended HFP)
  | LTXR = 747
  /// Load Complement (short HFP)
  | LCER = 748
  /// Load Complement (long HFP)
  | LCDR = 749
  /// Load Complement (extended HFP)
  | LCXR = 750
  /// Load FP Integer (short HFP)
  | FIER = 751
  /// Load FP Integer (long HFP)
  | FIDR = 752
  /// Load FP Integer (extended HFP)
  | FIXR = 753
  /// Load Lengthened (long HFP <- short)
  | LDER = 754
  /// Load Lengthened (extended HFP <- long)
  | LXDR = 755
  /// Load Lengthened (extended HFP <- short)
  | LXER = 756
  /// Load Lengthened (long HFP <- short)
  | LDE = 757
  /// Load Lengthened (extended HFP <- long)
  | LXD = 758
  /// Load Lengthened (extended HFP <- short)
  | LXE = 759
  /// Load Negative (short HFP)
  | LNER = 760
  /// Load Negative (long HFP)
  | LNDR = 761
  /// Load Negative (extended HFP)
  | LNXR = 762
  /// Load Positive (short HFP)
  | LPER = 763
  /// Load Positive (long HFP)
  | LPDR = 764
  /// Load Positive (extended HFP)
  | LPXR = 765
  /// Load Rounded (short HFP <- long)
  | LEDR = 766
  /// Load Rounded (long HFP <- extended)
  | LDXR = 767
  /// Load Rounded (short HFP <- extended)
  | LEXR = 768
  /// Multiply (short HFP)
  | MEER = 769
  /// Multiply (long HFP)
  | MDR = 770
  /// Multiply (extended HFP)
  | MXR = 771
  /// Multiply (long HFP <- short)
  | MDER = 772
  /// Multiply (extended HFP <- long)
  | MXDR = 773
  /// Multiply (short HFP)
  | MEE = 774
  /// Multiply (long HFP)
  | MD = 775
  /// Multiply (long HFP <- short)
  | MDE = 776
  /// Multiply (extended HFP <- long)
  | MXD = 777
  /// Multiply and Add (short HFP)
  | MAER = 778
  /// Multiply and Add (long HFP)
  | MADR = 779
  /// Multiply and Add (short HFP)
  | MAE = 780
  /// Multiply and Add (long HFP)
  | MAD = 781
  /// Multiply and Subtract (short HFP)
  | MSER = 782
  /// Multiply and Subtract (long HFP)
  | MSDR = 783
  /// Multiply and Subtract (short HFP)
  | MSE = 784
  /// Multiply and Subtract (long HFP)
  | MSD = 785
  /// Multiply and Add Unnormalized (long to ext. HFP)
  | MAYR = 786
  /// Multiply and Add Unnormalized (long to ext. high HFP)
  | MAYHR = 787
  /// Multiply and Add Unnormalized (long to ext. low HFP)
  | MAYLR = 788
  /// Multiply and Add Unnormalized (long to ext. HFP)
  | MAY = 789
  /// Multiply and Add Unnormalized (long to ext. high HFP)
  | MAYH = 790
  /// Multiply and Add Unnormalized (long to ext. low HFP)
  | MAYL = 791
  /// Multiply Unnormalized (long to ext. HFP)
  | MYR = 792
  /// Multiply Unnormalized (long to ext. high HFP)
  | MYHR = 793
  /// Multiply Unnormalized (long to ext. low HFP)
  | MYLR = 794
  /// Multiply Unnormalized (long to ext. HFP)
  | MY = 795
  /// Multiply Unnormalized (long to ext. high HFP)
  | MYH = 796
  /// Multiply Unnormalized (long to ext. low HFP)
  | MYL = 797
  /// Square Root (short HFP)
  | SQER = 798
  /// Square Root (long HFP)
  | SQDR = 799
  /// Square Root (extended HFP)
  | SQXR = 800
  /// Square Root (short HFP)
  | SQE = 801
  /// Square Root (long HFP)
  | SQD = 802
  /// Subtract Normalized (short HFP)
  | SER = 803
  /// Subtract Normalized (long HFP)
  | SDR = 804
  /// Subtract Normalized (extended HFP)
  | SXR = 805
  /// Subtract Normalized (short HFP)
  | SE = 806
  /// Subtract Normalized (long HFP)
  | SD = 807
  /// Subtract Unnormalized (short HFP)
  | SUR = 808
  /// Subtract Unnormalized (long HFP)
  | SWR = 809
  /// Subtract Unnormalized (short HFP)
  | SU = 810
  /// Subtract Unnormalized (long HFP)
  | SW = 811
  /// Add (short BFP)
  | AEBR = 812
  /// Add (long BFP)
  | ADBR = 813
  /// Add (extended BFP)
  | AXBR = 814
  /// Add (short BFP)
  | AEB = 815
  /// Add (long BFP)
  | ADB = 816
  /// Compare (short BFP)
  | CEBR = 817
  /// Compare (long BFP)
  | CDBR = 818
  /// Compare (extended BFP)
  | CXBR = 819
  /// Compare (short BFP)
  | CEB = 820
  /// Compare (long BFP)
  | CDB = 821
  /// Compare and Signal (short BFP)
  | KEBR = 822
  /// Compare and Signal (long BFP)
  | KDBR = 823
  /// Compare and Signal (extended BFP)
  | KXBR = 824
  /// Compare and Signal (short BFP)
  | KEB = 825
  /// Compare and Signal (long BFP)
  | KDB = 826
  /// Convert from Fixed (short BFP <- 32)
  | CEFBR = 827
  /// Convert from Fixed (long BFP <- 32)
  | CDFBR = 828
  /// Convert from Fixed (extended BFP <- 32)
  | CXFBR = 829
  /// Convert from Fixed (short BFP <- 64)
  | CEGBR = 830
  /// Convert from Fixed (long BFP <- 64)
  | CDGBR = 831
  /// Convert from Fixed (extended BFP <- 64)
  | CXGBR = 832
  /// Convert from Fixed (short BFP <- 32)
  | CEFBRA = 833
  /// Convert from Fixed (long BFP <- 64)
  | CDFBRA = 834
  /// Convert from Fixed (extended BFP <- 32)
  | CXFBRA = 835
  /// Convert from Fixed (short BFP <- 32)
  | CEGBRA = 836
  /// Convert from Fixed (long BFP <- 64)
  | CDGBRA = 837
  /// Convert from Fixed (extended BFP <- 64)
  | CXGBRA = 838
  /// Convert from Logical (short BFP <- 32)
  | CELFBR = 839
  /// Convert from Logical (long BFP <- 32)
  | CDLFBR = 840
  /// Convert from Logical (extended BFP <- 32)
  | CXLFBR = 841
  /// Convert from Logical (short BFP <- 64)
  | CELGBR = 842
  /// Convert from Logical (long BFP <- 64)
  | CDLGBR = 843
  /// Convert from Logical (extended BFP <- 64)
  | CXLGBR = 844
  /// Convert to Fixed (32 <- short BFP)
  | CFEBR = 845
  /// Convert to Fixed (32 <- long BFP)
  | CFDBR = 846
  /// Convert to Fixed (32 <- extended BFP)
  | CFXBR = 847
  /// Convert to Fixed (64 <- short BFP)
  | CGEBR = 848
  /// Convert to Fixed (64 <- long BFP)
  | CGDBR = 849
  /// Convert to Fixed (64 <- extended BFP)
  | CGXBR = 850
  /// Convert to Fixed (32 <- short BFP)
  | CFEBRA = 851
  /// Convert to Fixed (32 <- long BFP)
  | CFDBRA = 852
  /// Convert to Fixed (32 <- extended BFP)
  | CFXBRA = 853
  /// Convert to Fixed (64 <- short BFP)
  | CGEBRA = 854
  /// Convert to Fixed (64 <- long BFP)
  | CGDBRA = 855
  /// Convert to Fixed (64 <- extended BFP)
  | CGXBRA = 856
  /// Convert to Logical (32 <- short BFP)
  | CLFEBR = 857
  /// Convert to Logical (32 <- long BFP)
  | CLFDBR = 858
  /// Convert to Logical (32 <- extended BFP)
  | CLFXBR = 859
  /// Convert to Logical (64 <- short BFP)
  | CLGEBR = 860
  /// Convert to Logical (64 <- long BFP)
  | CLGDBR = 861
  /// Convert to Logical (64 <- extended BFP)
  | CLGXBR = 862
  /// Divide (short BFP)
  | DEBR = 863
  /// Divide (long BFP)
  | DDBR = 864
  /// Divide (extended BFP)
  | DXBR = 865
  /// Divide (short BFP)
  | DEB = 866
  /// Divide (long BFP)
  | DDB = 867
  /// Divide to Integer (short BFP)
  | DIEBR = 868
  /// Divide to Integer (long BFP)
  | DIDBR = 869
  /// Load and Test (short BFP)
  | LTEBR = 870
  /// Load and Test (long BFP)
  | LTDBR = 871
  /// Load and Test (extended BFP)
  | LTXBR = 872
  /// Load Complement (short BFP)
  | LCEBR = 873
  /// Load Complement (long BFP)
  | LCDBR = 874
  /// Load Complement (extended BFP)
  | LCXBR = 875
  /// Load FP Integer (short BFP)
  | FIEBR = 876
  /// Load FP Integer (long BFP)
  | FIDBR = 877
  /// Load FP Integer (extended BFP)
  | FIXBR = 878
  /// Load FP Integer (short BFP)
  | FIEBRA = 879
  /// Load FP Integer (long BFP)
  | FIDBRA = 880
  /// Load FP Integer (extended BFP)
  | FIXBRA = 881
  /// Load Lengthened (long BFP <- short)
  | LDEBR = 882
  /// Load Lengthened (extended BFP <- long)
  | LXDBR = 883
  /// Load Lengthened (extended BFP <- short)
  | LXEBR = 884
  /// Load Lengthened (long BFP <- short)
  | LDEB = 885
  /// Load Lengthened (extended BFP <- long)
  | LXDB = 886
  /// Load Lengthened (extended BFP <- short)
  | LXEB = 887
  /// Load Negative (short BFP)
  | LNEBR = 888
  /// Load Negative (long BFP)
  | LNDBR = 889
  /// Load Negative (extended BFP)
  | LNXBR = 890
  /// Load Positive (short BFP)
  | LPEBR = 891
  /// Load Positive (long BFP)
  | LPDBR = 892
  /// Load Positive (extended BFP)
  | LPXBR = 893
  /// Load Rounded (short BFP <- long)
  | LEDBR = 894
  /// Load Rounded (long BFP <- extended)
  | LDXBR = 895
  /// Load Rounded (short BFP <- extended)
  | LEXBR = 896
  /// Load Rounded (short BFP <- long)
  | LEDBRA = 897
  /// Load Rounded (long BFP <- extended)
  | LDXBRA = 898
  /// Load Rounded (short BFP <- extended)
  | LEXBRA = 899
  /// Multiply (short BFP)
  | MEEBR = 900
  /// Multiply (long BFP)
  | MDBR = 901
  /// Mulltiply (extended BFP)
  | MXBR = 902
  /// Multiply (long BFP <- short)
  | MDEBR = 903
  /// Multiply (extended BFP <- long)
  | MXDBR = 904
  /// Multiply (short BFP)
  | MEEB = 905
  /// Multiply (long BFP)
  | MDB = 906
  /// Multiply (long BFP <- short)
  | MDEB = 907
  /// Multiply (extended BFP <- long)
  | MXDB = 908
  /// Multiply and Add (short BFP)
  | MAEBR = 909
  /// Multiply and Add (long BFP)
  | MADBR = 910
  /// Multiply and Add (short BFP)
  | MAEB = 911
  /// Multiply and Add (long BFP)
  | MADB = 912
  /// Multiply and Subtract (short BFP)
  | MSEBR = 913
  /// Multiply and Subtract (long BFP)
  | MSDBR = 914
  /// Multiply and Subtract (short BFP)
  | MSEB = 915
  /// Multiply and Subtract (long BFP)
  | MSDB = 916
  /// Square Root (short BFP)
  | SQEBR = 917
  /// Square Root (long BFP)
  | SQDBR = 918
  /// Square Root (extended BFP)
  | SQXBR = 919
  /// Square Root (short BFP)
  | SQEB = 920
  /// Square Root (long BFP)
  | SQDB = 921
  /// Subtract (short BFP)
  | SEBR = 922
  /// Subtract (long BFP)
  | SDBR = 923
  /// Subtract (extended BFP)
  | SXBR = 924
  /// Subtract (short BFP)
  | SEB = 925
  /// Subtract (long BFP)
  | SDB = 926
  /// Test Data Class (short BFP)
  | TCEB = 927
  /// Test Data Class (long BFP)
  | TCDB = 928
  /// Test Data Class (extended BFP)
  | TCXB = 929
  /// Add (long DFP)
  | ADTR = 930
  /// Add (extended DFP)
  | AXTR = 931
  /// Add (extended DFP)
  | ADTRA = 932
  /// Add (extended DFP)
  | AXTRA = 933
  /// Compare (long DFP)
  | CDTR = 934
  /// Compare (extended DFP)
  | CXTR = 935
  /// Compare and Signal (long DFP)
  | KDTR = 936
  /// Compare and Signal (extended DFP)
  | KXTR = 937
  /// Compare Biased Exponent (long DFP)
  | CEDTR = 938
  /// Compare Biased Exponent (extended DFP)
  | CEXTR = 939
  /// Convert from Fixed (long DFP <- 64)
  | CDGTR = 940
  /// Convert from Fixed (extended DFP <- 64)
  | CXGTR = 941
  /// Convert from Fixed (long DFP <- 64)
  | CDGTRA = 942
  /// Convert from Fixed (extended DFP <- 64)
  | CXGTRA = 943
  /// Convert from Fixed (long DFP <- 32)
  | CDFTR = 944
  /// Convert from Fixed (extended DFP <- 32)
  | CXFTR = 945
  /// Convert from Logical (long DFP <- 64)
  | CDLGTR = 946
  /// Convert from Logical (extended DFP <- 64)
  | CXLGTR = 947
  /// Convert from Logical (long DFP <- 32)
  | CDLFTR = 948
  /// Convert from Logical (extended DFP <- 32)
  | CXLFTR = 949
  /// Convert from Packed (to long DFP)
  | CDPT = 950
  /// Convert from Packed (to extended DFP)
  | CXPT = 951
  /// Convert from Signed Packed (long DFP <- 64)
  | CDSTR = 952
  /// Convert from Signed Packed (extended DFP <- 128)
  | CXSTR = 953
  /// Convert from Unsigned Packed (long DFP <- 64)
  | CDUTR = 954
  /// Convert from Unsigned Packed (extended DFP <- 128)
  | CXUTR = 955
  /// Convert from Zoned (to long DFP)
  | CDZT = 956
  /// Convert from Zoned (to extended DFP)
  | CXZT = 957
  /// Convert to Fixed (64 <- long DFP)
  | CGDTR = 958
  /// Convert to Fixed (64 <- extended DFP)
  | CGXTR = 959
  /// Convert to Fixed (64 <- long DFP)
  | CGDTRA = 960
  /// Convert to Fixed (64 <- extended DFP)
  | CGXTRA = 961
  /// Convert to Fixed (32 <- long DFP)
  | CFDTR = 962
  /// Convert to Fixed (32 <- extended DFP)
  | CFXTR = 963
  /// Convert to Logical (64 <- long DFP)
  | CLGDTR = 964
  /// Convert to Logical (64 <- extended DFP)
  | CLGXTR = 965
  /// Convert to Logical (32 <- long DFP)
  | CLFDTR = 966
  /// Convert to Logical (32 <- extended DFP)
  | CLFXTR = 967
  /// Convert to Packed (from long DFP)
  | CPDT = 968
  /// Convert to Packed (from extended DFP)
  | CPXT = 969
  /// Convert to Signed Packed (64 <- long DFP)
  | CSDTR = 970
  /// Convert to Signed Packed (128 <- extended DFP)
  | CSXTR = 971
  /// Convert to Unsigned Packed (64 <- long DFP)
  | CUDTR = 972
  /// Convert to Unsigned Packed (64 <- long DFP)
  | CUXTR = 973
  /// Convert to Zoned (from long DFP)
  | CZDT = 974
  /// Convert to Zoned (from extended DFP)
  | CZXT = 975
  /// Divide (long DFP)
  | DDTR = 976
  /// Divide (extended DFP)
  | DXTR = 977
  /// Divide (long DFP)
  | DDTRA = 978
  /// Divide (extended DFP)
  | DXTRA = 979
  /// Extract Biased Exponent (64 <- long DFP)
  | EEDTR = 980
  /// Extract Biased Exponent (64 <- extended DFP)
  | EEXTR = 981
  /// Extract Significance (long DFP)
  | ESDTR = 982
  /// Extract Significance (long DFP)
  | ESXTR = 983
  /// Insert Biased Exponent (long DFP <- 64)
  | IEDTR = 984
  /// Insert Biased Exponent (long DFP <- 64)
  | IEXTR = 985
  /// Load and Test (long DFP)
  | LTDTR = 986
  /// Load and Test (extended DFP)
  | LTXTR = 987
  /// Load FP Integer (long DFP)
  | FIDTR = 988
  /// Load FP Integer (long DFP)
  | FIXTR = 989
  /// Load Lengthened (long DFP <- short)
  | LDETR = 990
  /// Load Lengthened (extended DFP <- long)
  | LXDTR = 991
  /// Load Rounded (short DFP <- long)
  | LEDTR = 992
  /// Load Rounded (long DFP <- extended)
  | LDXTR = 993
  /// Multiply (long DFP)
  | MDTR = 994
  /// Multiply (extended DFP)
  | MXTR = 995
  /// Multiply (long DFP)
  | MDTRA = 996
  /// Multiply (extended DFP)
  | MXTRA = 997
  /// Quantize (long DFP)
  | QADTR = 998
  /// Quantize (extended DFP)
  | QAXTR = 999
  /// Reround (long DFP)
  | RRDTR = 1000
  /// Reround (extended DFP)
  | RRXTR = 1001
  /// Shift Significand Left (long DFP)
  | SLDT = 1002
  /// Shift Significand Left (extended DFP)
  | SLXT = 1003
  /// Shift Significand Right (long DFP)
  | SRDT = 1004
  /// Shift Significand Right (extended DFP)
  | SRXT = 1005
  /// Subtract (long DFP)
  | SDTR = 1006
  /// Subtract (extended DFP)
  | SXTR = 1007
  /// Subtract (long DFP)
  | SDTRA = 1008
  /// Subtract (extended DFP)
  | SXTRA = 1009
  /// Test Data Class (short DFP)
  | TDCET = 1010
  /// Test Data Class (long DFP)
  | TDCDT = 1011
  /// Test Data Class (extended DFP)
  | TDCXT = 1012
  /// Test Data Group (short DFP)
  | TDGET = 1013
  /// Test Data Group (long DFP)
  | TDGDT = 1014
  /// Test Data Group (extended DFP)
  | TDGXT = 1015
  /// Vector Bit Permute
  | VBPERM = 1016
  /// Vector Gather Element (32)
  | VGEF = 1017
  /// Vector Gather Element (64)
  | VGEG = 1018
  /// Vector Generate Byte Mask
  | VGBM = 1019
  /// Vector Generate Mask
  | VGM = 1020
  /// Vector Load
  | VL = 1021
  /// Vector Load
  | VLR = 1022
  /// Vector Load and Replicate
  | VLREP = 1023
  /// Vector Load Element (8)
  | VLEB = 1024
  /// Vector Load Element (16)
  | VLEH = 1025
  /// Vector Load Element (32)
  | VLEF = 1026
  /// Vector Load Element (64)
  | VLEG = 1027
  /// Vector Load Element Immediate (8)
  | VLEIB = 1028
  /// Vector Load Element Immediate (16)
  | VLEIH = 1029
  /// Vector Load Element Immediate (32)
  | VLEIF = 1030
  /// Vector Load Element Immediate (64)
  | VLEIG = 1031
  /// Vector Load GR from VR Element
  | VLGV = 1032
  /// Vector Load Logical Element and Zero
  | VLLEZ = 1033
  /// Vector Load Multiple
  | VLM = 1034
  /// VEctor Load Rightmost with Length
  | VLRLR = 1035
  /// Vector Load Rightmost with Length
  | VLRL = 1036
  /// Vector Load to Block Boundary
  | VLBB = 1037
  /// Vector Load VR Element from GR
  | VLVG = 1038
  /// Vector Load VR from GRS Disjoint
  | VLVGP = 1039
  /// Vector Load with Length
  | VLL = 1040
  /// Vector Merge High
  | VMRH = 1041
  /// Vector Merge Low
  | VMRL = 1042
  /// Vector Pack
  | VPK = 1043
  /// Vector Pack Saturate
  | VPKS = 1044
  /// Vector Pack Logical Saturate
  | VPKLS = 1045
  /// Vector Permute
  | VPERM = 1046
  /// Vector Permute Doubleword Immediate
  | VPDI = 1047
  /// Vector Replicate
  | VREP = 1048
  /// Vector Replicate Immediate
  | VREPI = 1049
  /// Vector Scatter Element (32)
  | VSCEF = 1050
  /// Vector Scatter Element (64)
  | VSCEG = 1051
  /// Vector Select
  | VSEL = 1052
  /// Vector Sign Extend to Doubleword
  | VSEG = 1053
  /// Vector Store
  | VST = 1054
  /// Vector Store Element (8)
  | VSTEB = 1055
  /// Vector Store Element (16)
  | VSTEH = 1056
  /// Vector Store Element (32)
  | VSTEF = 1057
  /// Vector Store Element (64)
  | VSTEG = 1058
  /// Vector Store Multiple
  | VSTM = 1059
  /// Vector Store Rightmost with Length
  | VSTRLR = 1060
  /// Vector Store Rightmost with Length
  | VSTRL = 1061
  /// Vectore Store with Length
  | VSTL = 1062
  /// Vector Unpack High
  | VUPH = 1063
  /// Vector Unpack Logical High
  | VUPLH = 1064
  /// Vector Unpack Low
  | VUPL = 1065
  /// Vector Unpack Logical Low
  | VUPLL = 1066
  /// Vector Add
  | VA = 1067
  /// Vector Add Compute Carry
  | VACC = 1068
  /// Vector Add with Carry
  | VAC = 1069
  /// Vector Add with Carry Compute Carry
  | VACCC = 1070
  /// Vector AND
  | VN = 1071
  /// Vector AND with Complement
  | VNC = 1072
  /// Vector Average
  | VAVG = 1073
  /// Vector Average Logical
  | VAVGL = 1074
  /// Vector Checksum
  | VCKSM = 1075
  /// Vector Element Compare
  | VEC = 1076
  /// Vector Element Compare Logical
  | VECL = 1077
  /// Vector Compare Equal
  | VCEQ = 1078
  /// Vector Compare High
  | VCH = 1079
  /// Vector Compare High Logical
  | VCHL = 1080
  /// Vector Count Leading Zeros
  | VCLZ = 1081
  /// Vector Count Trailing Zeros
  | VCTZ = 1082
  /// Vector Exclusive OR
  | VX = 1083
  /// Vector Galois Field Multiply Sum
  | VGFM = 1084
  /// Vector Galois Field Multiply Sum and Accumulate
  | VGFMA = 1085
  /// Vector Load Complement
  | VLC = 1086
  /// Vector Load Positive
  | VLP = 1087
  /// Vector Maximum
  | VMX = 1088
  /// Vector Maximum Logical
  | VMXL = 1089
  /// Vector Minimum
  | VMN = 1090
  /// Vector Minimum Logical
  | VMNL = 1091
  /// Vector Multiply and Add Low
  | VMAL = 1092
  /// Vector Multiply and Add High
  | VMAH = 1093
  /// Vector Multiply and Add Logical High
  | VMALH = 1094
  /// Vector Multiply and Add Even
  | VMAE = 1095
  /// Vector Multiply and Add Logical Even
  | VMALE = 1096
  /// Vector Multiply and Add Odd
  | VMAO = 1097
  /// Vector Multiply and Add Logical Odd
  | VMALO = 1098
  /// Vector Multiply High
  | VMH = 1099
  /// Vector Multiply Logical High
  | VMLH = 1100
  /// Vector Multiply Low
  | VML = 1101
  /// Vector Multiply Even
  | VME = 1102
  /// Vector Multiply Logical Even
  | VMLE = 1103
  /// Vector Multiply Odd
  | VMO = 1104
  /// Vector Multiply Logial Odd
  | VMLO = 1105
  /// Vector Multiply Sum Logical
  | VMSL = 1106
  /// Vector NAND
  | VNN = 1107
  /// Vector NOR
  | VNO = 1108
  /// Vector NOT Exclusive OR
  | VNX = 1109
  /// Vector OR
  | VO = 1110
  /// Vector OR with Complement
  | VOC = 1111
  /// Vector Population Count
  | VPOPCT = 1112
  /// Vector Element Rotate Left Logical
  | VERLLV = 1113
  /// Vector Element Rotate Left Logical
  | VERLL = 1114
  /// Vector Element Rotate and Insert Under Mask
  | VERIM = 1115
  /// Vector Element Shift Left
  | VESLV = 1116
  /// Vector Element Shift Left
  | VESL = 1117
  /// Vector Element Shift Right Arithmentic
  | VESRAV = 1118
  /// Vector Element Shift Right Arithmetic
  | VESRA = 1119
  /// Vector Element Shift Right Logical
  | VESRLV = 1120
  /// Vector Element Shift Right Logical
  | VESRL = 1121
  /// Vector Shift Left
  | VSL = 1122
  /// Vector Shift Left by Byte
  | VSLB = 1123
  /// Vector Shift Left Double by Byte
  | VSLDB = 1124
  /// Vector Shift Right Arithmetic
  | VSRA = 1125
  /// Vector Shift Right Arithmetic by Byte
  | VSRAB = 1126
  /// Vector Shift Right Logical
  | VSRL = 1127
  /// Vector Shift Right Logical by Byte
  | VSRLB = 1128
  /// Vector Subtract
  | VS = 1129
  /// Vector Subtract Compute Borrow Indication
  | VSCBI = 1130
  /// Vector Subtract with Borrow Indication
  | VSBI = 1131
  /// Vector Subtract with Borrow Compute Borrow Indication
  | VSBCBI = 1132
  /// Vector Sum Across Doubleword
  | VSUMG = 1133
  /// Vector Sum Across Quadword
  | VSUMQ = 1134
  /// Vector Sum Across Word
  | VSUM = 1135
  /// Vector Test under Mask
  | VTM = 1136
  /// Vector Find Any Element Equal
  | VFAE = 1137
  /// Vector Find Element Equal
  | VFEE = 1138
  /// Vector Find Element Not Equal
  | VFENE = 1139
  /// Vector Isolate String
  | VISTR = 1140
  /// Vector String Range Compare
  | VSTRC = 1141
  /// Vector FP Add
  | VFA = 1142
  /// Vector FP Compare Scalar
  | WFC = 1143
  /// Vector FP Compare and Signal Scalar
  | WFK = 1144
  /// Vector FP Compare Equal
  | VFCE = 1145
  /// Vector fP Compare High
  | VFCH = 1146
  /// VEctor FP Compare High or Equal
  | VFCHE = 1147
  /// Vector FP Divide
  | VFD = 1148
  /// Vector Load FP Integer
  | VFI = 1149
  /// Vector FP Load Lengthened
  | VFLL = 1150
  /// Vector FP Load Rounded
  | VFLR = 1151
  /// Vector FP Maximum
  | VFMAX = 1152
  /// Vector FP Minimum
  | VFMIN = 1153
  /// Vector FP Multiply
  | VFM = 1154
  /// Vector FP Multiply and Add
  | VFMA = 1155
  /// Vector FP Multiply and Subtract
  | VFMS = 1156
  /// Vector FP Negative Multiply and Add
  | VFNMA = 1157
  /// Vector FP Negative Multiply and Subtract
  | VFNMS = 1158
  /// Vector FP Perform Sign Operation
  | VFPSO = 1159
  /// Vector FP Square Root
  | VFSQ = 1160
  /// Vector FP Subtract
  | VFS = 1161
  /// Vector FP Test Data Class Immediate
  | VFTCI = 1162
  /// Vector Add Decimal
  | VAP = 1163
  /// Vector Compare Decimal
  | VCP = 1164
  /// Vector Convert to Binary
  | VCVB = 1165
  /// Vector Convert to Binary
  | VCVBG = 1166
  /// Vector Convert to Decimal
  | VCVD = 1167
  /// Vector Convert to Decimal
  | VCVDG = 1168
  /// Vector Divide Decimal
  | VDP = 1169
  /// Vector Load Immediate Decimal
  | VLIP = 1170
  /// Vector Multiply Decimal
  | VMP = 1171
  /// Vector Multiply and Shift Decimal
  | VMSP = 1172
  /// Vector Pack Zoned
  | VPKZ = 1173
  /// Vector Perform Sign Operation Decimal
  | VPSOP = 1174
  /// Vector Remainder Decimal
  | VRP = 1175
  /// Vector Shift and Divide Decimal
  | VSDP = 1176
  /// Vector Shift and Round Decimal
  | VSRP = 1177
  /// Load BEAR
  | LBEAR = 1178
  /// Store BEAR
  | STBEAR = 1179
  /// Query Processor Activity Counter Information
  | QPACI = 1180
  /// Sort Lists
  | SORTL = 1181
  /// Deflate Conversion Call
  | DFLTCC = 1182
  /// Compute Digital Signature Authentication
  | KDSA = 1183
  /// Neural Networking Processing Assist
  | NNPA = 1184
  /// Load PSW Extended
  | LPSWEY = 1185
  /// Move Right to Left
  | MVCRL = 1186
  /// Vector Pack Zoned Register
  | VPKZR = 1187
  /// Vector Shift and Round Decimal Register
  | VSRPR = 1188
  /// Vector Subtract Decimal
  | VSP = 1189
  /// Vector Shift Left Double by Bit
  | VSLD = 1190
  /// Vector Shift Right Double by Bit
  | VSRD = 1191
  /// Vector Count Leading Zero Digits
  | VCLZDP = 1192
  /// Vector Unpack Zoned High
  | VUPKZH = 1193
  /// Vector FP Convert to NNP
  | VCNF = 1194
  /// Vector FP Convert and Lengthen from NNP High
  | VCLFNH = 1195
  /// Vector Unpack Zoned Low
  | VUPKZL = 1196
  /// Vector FP Convert from NNP
  | VCFN = 1197
  /// Vector FP Convert and Lengthen from NNP Low
  | VCLFNL = 1198
  /// Vector Test Decimal
  | VTP = 1199
  /// Decimal Scale and Convert to HFP
  | VSCHP = 1200
  /// Vector FP Convert and Round to NNP
  | VCRNF = 1201
  /// Decimal Scale and Convert and Split to HFP
  | VSCSHP = 1202
  /// Vector Convert HFP to Scaled Decimal
  | VCSPH = 1203
  /// Vector String Search
  | VSTRS = 1204
  /// Vector FP Convert to Logical
  | VCLFP = 1205
  /// Vector FP Convert from Logical
  | VCFPL = 1206
  /// Vector FP Convert to Fixed
  | VCSFP = 1207
  /// Vector FP Convert from Fixed
  | VCFPS = 1208
  /// Vectir Load Byte Reversed Element
  | VLEBRH = 1209
  /// Vector Load Byte Reversed Element
  | VLEBRG = 1210
  /// Vector Load Byte Reversed Element
  | VLEBRF = 1211
  /// Vector Load Byte Reversed Element and Zero
  | VLLEBRZ = 1212
  /// Vector Load Byte Reversed Element and Replicate
  | VLBRREP = 1213
  /// Vector Load Byte Reversed Elements
  | VLBR = 1214
  /// Vector Load Elements Reversed
  | VLER = 1215
  /// Vector Store Byte Reversed Elements
  | VSTEBRH = 1216
  /// Vector Store Byte Reversed Elements
  | VSTEBRF = 1217
  /// Vector Store Byte Reversed Elements
  | VSTEBRG = 1218
  /// Vector Store Byte Reversed Elements
  | VSTBR = 1219
  /// Vector Store Elements Reversed
  | VSTER = 1220
  /// Vector Unpack Zoned
  | VUPKZ = 1221

type internal Op = Opcode
