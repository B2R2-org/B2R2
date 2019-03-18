#!/usr/bin/env fsharpi
#load "../src/Core/TypeExtensions.fs"
#load "../src/Core/RegType.fs"
#load "../src/Core/RegisterID.fs"
#load "../src/FrontEnd/Intel/IntelRegister.fs"
(*
  B2R2 - the Next-Generation Reversing Platform

  Author: DongYeop Oh <oh51dy@kaist.ac.kr>
          Seung Il Jung <sijung@kaist.ac.kr>

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

type Opcode =
  | AAA = 0
  | AAD = 1
  | AAM = 2
  | AAS = 3
  | ADC = 4
  | ADD = 5
  | ADDPD = 6
  | ADDPS = 7
  | ADDSD = 8
  | ADDSS = 9
  | AND = 10
  | ANDNPD = 11
  | ANDNPS = 12
  | ANDPD = 13
  | ANDPS = 14
  | ARPL = 15
  | BNDMOV = 16
  | BOUND = 17
  | BSF = 18
  | BSR = 19
  | BSWAP = 20
  | BT = 21
  | BTC = 22
  | BTR = 23
  | BTS = 24
  | CALLFar = 25 (* Far call *)
  | CALLNear = 26 (* Near call *)
  | CBW = 27
  | CDQ = 28
  | CDQE = 29
  | CLAC = 30
  | CLC = 31
  | CLD = 32
  | CLFLUSH = 33
  | CLI = 34
  | CLTS = 35
  | CMC = 36
  | CMOVA = 37
  | CMOVAE = 38
  | CMOVB = 39
  | CMOVBE = 40
  | CMOVG = 41
  | CMOVL = 42
  | CMOVLE = 43
  | CMOVGE = 44
  | CMOVNO = 45
  | CMOVNP = 46
  | CMOVNS = 47
  | CMOVNZ = 48
  | CMOVO = 49
  | CMOVP = 50
  | CMOVS = 51
  | CMOVZ = 52
  | CMP = 53
  | CMPSB = 54
  | CMPSW = 55
  | CMPSD = 56
  | CMPSQ = 57
  | CMPXCH8B = 58
  | CMPXCHG = 59
  | CMPXCHG16B = 60
  | COMISD = 61
  | COMISS = 62
  | CPUID = 63
  | CQO = 64
  | CRC32 = 65
  | CVTDQ2PD = 66
  | CVTDQ2PS = 67
  | CVTPD2DQ = 68
  | CVTPD2PI = 69
  | CVTPD2PS = 70
  | CVTPI2PD = 71
  | CVTPI2PS = 72
  | CVTPS2DQ = 73
  | CVTPS2PD = 74
  | CVTPS2PI = 75
  | CVTSD2SI = 76
  | CVTSD2SS = 77
  | CVTSI2SD = 78
  | CVTSI2SS = 79
  | CVTSS2SD = 80
  | CVTSS2SI = 81
  | CVTTPD2DQ = 82
  | CVTTPD2PI = 83
  | CVTTPS2DQ = 84
  | CVTTPS2PI = 85
  | CVTTSD2SI = 86
  | CVTTSS2SI = 87
  | CWD = 88
  | CWDE = 89
  | DAA = 90
  | DAS = 91
  | DEC = 92
  | DIV = 93
  | DIVPD = 94
  | DIVPS = 95
  | DIVSD = 96
  | DIVSS = 97
  | ENTER = 98
  | F2XM1 = 99
  | FABS = 100
  | FADD = 101
  | FADDP = 102
  | FBLD = 103
  | FBSTP = 104
  | FCHS = 105
  | FCLEX = 106
  | FCMOVB = 107
  | FCMOVBE = 108
  | FCMOVE = 109
  | FCMOVNB = 110
  | FCMOVNBE = 111
  | FCMOVNE = 112
  | FCMOVNU = 113
  | FCMOVU = 114
  | FCOM = 115
  | FCOMI = 116
  | FCOMIP = 117
  | FCOMP = 118
  | FCOMPP = 119
  | FCOS = 120
  | FDECSTP = 121
  | FDIV = 122
  | FDIVP = 123
  | FDIVR = 124
  | FDIVRP = 125
  | FFREE = 126
  | FIADD = 127
  | FILD = 128
  | FIMUL = 129
  | FINCSTP = 130
  | FINIT = 131
  | FICOM = 132
  | FICOMP = 133
  | FIST = 134
  | FISTP = 135
  | FISTTP = 136
  | FISUB = 137
  | FISUBR = 138
  | FIDIV = 139
  | FIDIVR = 140
  | FLD = 141
  | FLD1 = 142
  | FLDCW = 143
  | FLDENV = 144
  | FLDL2T = 145
  | FLDL2E = 146
  | FLDPI = 147
  | FLDLG2 = 148
  | FLDLN2 = 149
  | FLDZ = 150
  | FNOP = 151
  | FMUL = 152
  | FMULP = 153
  | FPATAN = 154
  | FPREM = 155
  | FPREM1 = 156
  | FPTAN = 157
  | FRNDINT = 158
  | FRSTOR = 159
  | FSAVE = 160
  | FSCALE = 161
  | FSIN = 162
  | FSINCOS = 163
  | FSQRT = 164
  | FST = 165
  | FSTCW = 166
  | FSTENV = 167
  | FSTP = 168
  | FSTSW = 169
  | FSUB = 170
  | FSUBP = 171
  | FSUBR = 172
  | FSUBRP = 173
  | FTST = 174
  | FUCOM = 175
  | FUCOMI = 176
  | FUCOMIP = 177
  | FUCOMP = 178
  | FUCOMPP = 179
  | FXAM = 180
  | FXCH = 181
  | FXTRACT = 182
  | FYL2X = 183
  | FYL2XP1 = 184
  | FXRSTOR = 185
  | FXRSTOR64 = 186
  | FXSAVE = 187
  | FXSAVE64 = 188
  | GETSEC = 189
  | HLT = 190
  | IDIV = 191
  | IMUL = 192
  | IN = 193
  | INC = 194
  | INS = 195
  | INSB = 196
  | INSD = 197
  | INSW = 198
  | INT = 199
  | INT3 = 200
  | INTO = 201
  | INVD = 202
  | INVLPG = 203
  | IRETW = 204
  | IRETD = 205
  | IRETQ = 206
  | JA = 207
  | JB = 208
  | JBE = 209
  | JCXZ = 210
  | JECXZ = 211
  | JG = 212
  | JL = 213
  | JLE = 214
  | JMPFar = 215 (* Far jmp *)
  | JMPNear = 216 (* Near jmp *)
  | JNB = 217
  | JNL = 218
  | JNO = 219
  | JNP = 220
  | JNS = 221
  | JNZ = 222
  | JO = 223
  | JP = 224
  | JRCXZ = 225
  | JS = 226
  | JZ = 227
  | LAHF = 228
  | LAR = 229
  | LDDQU = 230
  | LDMXCSR = 231
  | LDS = 232
  | LEA = 233
  | LEAVE = 234
  | LES = 235
  | LFENCE = 236
  | LFS = 237
  | LGDT = 238
  | LGS = 239
  | LIDT = 240
  | LLDT = 241
  | LMSW = 242
  | LODSB = 243
  | LODSW = 244
  | LODSD = 245
  | LODSQ = 246
  | LOOP = 247
  | LOOPE = 248
  | LOOPNE = 249
  | LSL = 250
  | LSS = 251
  | LTR = 252
  | LZCNT = 253
  | MAXPS = 254
  | MAXPD = 255
  | MAXSD = 256
  | MAXSS = 257
  | MFENCE = 258
  | MINPD = 259
  | MINPS = 260
  | MINSD = 261
  | MINSS = 262
  | MONITOR = 263
  | MOV = 264
  | MOVAPD = 265
  | MOVAPS = 266
  | MOVBE = 267
  | MOVD = 268
  | MOVDDUP = 269
  | MOVDQ2Q = 270
  | MOVDQA = 271
  | MOVDQU = 272
  | MOVHLPS = 273
  | MOVHPD = 274
  | MOVHPS = 275
  | MOVLHPS = 276
  | MOVLPD = 277
  | MOVLPS = 278
  | MOVMSKPD = 279
  | MOVMSKPS = 280
  | MOVNTDQ = 281
  | MOVNTI = 282
  | MOVNTPD = 283
  | MOVNTPS = 284
  | MOVNTQ = 285
  | MOVQ = 286
  | MOVQ2DQ = 287
  | MOVSB = 288
  | MOVSD = 289
  | MOVSHDUP = 290
  | MOVSLDUP = 291
  | MOVSS = 292
  | MOVSW = 293
  | MOVSQ = 294
  | MOVSX = 295
  | MOVSXD = 296
  | MOVUPD = 297
  | MOVUPS = 298
  | MOVZX = 299
  | MUL = 300
  | MULPD = 301
  | MULPS = 302
  | MULSD = 303
  | MULSS = 304
  | MWAIT = 305
  | NEG = 306
  | NOP = 307
  | NOT = 308
  | OR = 309
  | ORPD = 310
  | ORPS = 311
  | OUT = 312
  | OUTS = 313
  | OUTSB = 314
  | OUTSD = 315
  | OUTSW = 316
  | PACKSSDW = 317
  | PACKSSWB = 318
  | PACKUSWB = 319
  | PADDB = 320
  | PADDD = 321
  | PADDQ = 322
  | PADDSB = 323
  | PADDSW = 324
  | PADDUSB = 325
  | PADDUSW = 326
  | PADDW = 327
  | PALIGNR = 328
  | PAND = 329
  | PANDN = 330
  | PAVGB = 331
  | PAVGW = 332
  | PAUSE = 333
  | PCMPEQB = 334
  | PCMPEQD = 335
  | PCMPEQQ = 336
  | PCMPESTRI = 337
  | PCMPESTRM = 338
  | PCMPGTB = 339
  | PCMPGTD = 340
  | PCMPGTW = 341
  | PCMPISTRI = 342
  | PCMPISTRM = 343
  | PEXTRW = 344
  | PINSRB = 345
  | PINSRW = 346
  | PMADDWD = 347
  | PMAXSW = 348
  | PMAXUB = 349
  | PMINSW = 350
  | PMINUB = 351
  | PMINUD = 352
  | PMINSB = 353
  | PMOVMSKB = 354
  | PMULHUW = 355
  | PMULHW = 356
  | PMULLW = 357
  | PMULUDQ = 358
  | POP = 359
  | POPA = 360
  | POPAD = 361
  | POPCNT = 362
  | POPF = 363
  | POPFD = 364
  | POPFQ = 365
  | POR = 366
  | PREFETCHNTA = 367
  | PREFETCHT0 = 368
  | PREFETCHT1 = 369
  | PREFETCHT2 = 370
  | PREFETCHW = 371
  | PREFETCHWT1 = 372
  | PSADBW = 373
  | PSHUFB = 374
  | PSHUFD = 375
  | PSHUFHW = 376
  | PSHUFLW = 377
  | PSHUFW = 378
  | PSLLD = 379
  | PSLLDQ = 380
  | PSLLQ = 381
  | PSLLW = 382
  | PSRAD = 383
  | PSRAW = 384
  | PSRLD = 385
  | PSRLDQ = 386
  | PSRLQ = 387
  | PSRLW = 388
  | PSUBB = 389
  | PSUBD = 390
  | PSUBQ = 391
  | PSUBSB = 392
  | PSUBSW = 393
  | PSUBUSB = 394
  | PSUBUSW = 395
  | PSUBW = 396
  | PTEST = 397
  | PUNPCKHBW = 398
  | PUNPCKHDQ = 399
  | PUNPCKHQDQ = 400
  | PUNPCKHWD = 401
  | PUNPCKLBW = 402
  | PUNPCKLDQ = 403
  | PUNPCKLQDQ = 404
  | PUNPCKLWD = 405
  | PUSH = 406
  | PUSHA = 407
  | PUSHAD = 408
  | PUSHF = 409
  | PUSHFD = 410
  | PUSHFQ = 411
  | PXOR = 412
  | RCL = 413
  | RCR = 414
  | RDFSBASE = 415
  | RDGSBASE = 416
  | RDMSR = 417
  | RDPKRU = 418
  | RDPMC = 419
  | RDRAND = 420
  | RDSEED = 421
  | RDTSC = 422
  | RDTSCP = 423
  | RETNear = 424 (* Near return *)
  | RETNearImm = 425 (* Near return w/ immediate *)
  | RETFar = 426 (* Far return *)
  | RETFarImm = 427 (* Far return w/ immediate *)
  | ROL = 428
  | ROR = 429
  | ROUNDSD = 430
  | RSM = 431
  | SAHF = 432
  | SAR = 433
  | SBB = 434
  | SCASB = 435
  | SCASW = 436
  | SCASD = 437
  | SCASQ = 438
  | SETA = 439
  | SETB = 440
  | SETBE = 441
  | SETG = 442
  | SETL = 443
  | SETLE = 444
  | SETNB = 445
  | SETNL = 446
  | SETNO = 447
  | SETNP = 448
  | SETNS = 449
  | SETNZ = 450
  | SETO = 451
  | SETP = 452
  | SETS = 453
  | SETZ = 454
  | SFENCE = 455
  | SGDT = 456
  | SHL = 457
  | SHLD = 458
  | SHR = 459
  | SHRD = 460
  | SHUFPD = 461
  | SHUFPS = 462
  | SIDT = 463
  | SLDT = 464
  | SMSW = 465
  | STAC = 466
  | STC = 467
  | STD = 468
  | STI = 469
  | STMXCSR = 470
  | STOSB = 471
  | STOSW = 472
  | STOSD = 473
  | STOSQ = 474
  | STR = 475
  | SUB = 476
  | SUBPD = 477
  | SUBPS = 478
  | SUBSD = 479
  | SUBSS = 480
  | SWAPGS = 481
  | SYSCALL = 482
  | SYSENTER = 483
  | SYSEXIT = 484
  | SYSRET = 485
  | TEST = 486
  | TZCNT = 487
  | UCOMISD = 488
  | UCOMISS = 489
  | UD2 = 490
  | UNPCKHPD = 491
  | UNPCKHPS = 492
  | UNPCKLPD = 493
  | UNPCKLPS = 494
  | VADDPD = 495
  | VADDPS = 496
  | VADDSD = 497
  | VADDSS = 498
  | VANDNPD = 499
  | VANDNPS = 500
  | VANDPD = 501
  | VANDPS = 502
  | VBROADCASTI128 = 503
  | VBROADCASTSS = 504
  | VCOMISD = 505
  | VCOMISS = 506
  | VCVTSD2SI = 507
  | VCVTSI2SD = 508
  | VCVTSI2SS = 509
  | VCVTSS2SI = 510
  | VCVTTSD2SI = 511
  | VCVTTSS2SI = 512
  | VDIVPD = 513
  | VDIVPS = 514
  | VDIVSD = 515
  | VDIVSS = 516
  | VERR = 517
  | VERW = 518
  | VINSERTI128 = 519
  | VLDDQU = 520
  | VMCALL = 521
  | VMCLEAR = 522
  | VMFUNC = 523
  | VMLAUNCH = 524
  | VMOVAPD = 525
  | VMOVAPS = 526
  | VMOVD = 527
  | VMOVDDUP = 528
  | VMOVDQA = 529
  | VMOVDQA32 = 530
  | VMOVDQA64 = 531
  | VMOVDQU = 532
  | VMOVDQU32 = 533
  | VMOVDQU64 = 534
  | VMOVHLPS = 535
  | VMOVHPD = 536
  | VMOVHPS = 537
  | VMOVLHPS = 538
  | VMOVLPD = 539
  | VMOVLPS = 540
  | VMOVMSKPD = 541
  | VMOVMSKPS = 542
  | VMOVNTDQ = 543
  | VMOVNTPD = 544
  | VMOVNTPS = 545
  | VMOVQ = 546
  | VMOVSD = 547
  | VMOVSHDUP = 548
  | VMOVSLDUP = 549
  | VMOVSS = 550
  | VMOVUPD = 551
  | VMOVUPS = 552
  | VMPTRLD = 553
  | VMPTRST = 554
  | VMRESUME = 555
  | VMULPD = 556
  | VMULPS = 557
  | VMULSD = 558
  | VMULSS = 559
  | VMXOFF = 560
  | VMXON = 561
  | VORPD = 562
  | VORPS = 563
  | VPACKSSDW = 564
  | VPACKSSWB = 565
  | VPACKUSWB = 566
  | VPADDB = 567
  | VPADDD = 568
  | VPADDQ = 569
  | VPADDSB = 570
  | VPADDSW = 571
  | VPADDUSB = 572
  | VPADDUSW = 573
  | VPADDW = 574
  | VPALIGNR = 575
  | VPAND = 576
  | VPANDN = 577
  | VPAVGB = 578
  | VPAVGW = 579
  | VPBROADCASTB = 580
  | VPCMPEQB = 581
  | VPCMPEQD = 582
  | VPCMPEQQ = 583
  | VPCMPESTRI = 584
  | VPCMPESTRM = 585
  | VPCMPGTB = 586
  | VPCMPGTD = 587
  | VPCMPGTW = 588
  | VPCMPISTRI = 589
  | VPCMPISTRM = 590
  | VPEXTRW = 591
  | VPINSRB = 592
  | VPINSRW = 593
  | VPMADDWD = 594
  | VPMAXSW = 595
  | VPMAXUB = 596
  | VPMINSW = 597
  | VPMINUB = 598
  | VPMINUD = 599
  | VPMOVMSKB = 600
  | VPMULHUW = 601
  | VPMULHW = 602
  | VPMULLW = 603
  | VPMULUDQ = 604
  | VPOR = 605
  | VPSADBW = 606
  | VPSHUFB = 607
  | VPSHUFD = 608
  | VPSHUFHW = 609
  | VPSHUFLW = 610
  | VPSLLD = 611
  | VPSLLDQ = 612
  | VPSLLQ = 613
  | VPSLLW = 614
  | VPSRAD = 615
  | VPSRAW = 616
  | VPSRLD = 617
  | VPSRLDQ = 618
  | VPSRLQ = 619
  | VPSRLW = 620
  | VPSUBB = 621
  | VPSUBD = 622
  | VPSUBQ = 623
  | VPSUBSB = 624
  | VPSUBSW = 625
  | VPSUBUSB = 626
  | VPSUBUSW = 627
  | VPSUBW = 628
  | VPTEST = 629
  | VPUNPCKHBW = 630
  | VPUNPCKHDQ = 631
  | VPUNPCKHQDQ = 632
  | VPUNPCKHWD = 633
  | VPUNPCKLBW = 634
  | VPUNPCKLDQ = 635
  | VPUNPCKLQDQ = 636
  | VPUNPCKLWD = 637
  | VPXOR = 638
  | VSHUFPD = 639
  | VSHUFPS = 640
  | VSUBPD = 641
  | VSUBPS = 642
  | VSUBSD = 643
  | VSUBSS = 644
  | VUCOMISD = 645
  | VUCOMISS = 646
  | VUNPCKHPD = 647
  | VUNPCKHPS = 648
  | VUNPCKLPD = 649
  | VUNPCKLPS = 650
  | VXORPD = 651
  | VXORPS = 652
  | VZEROUPPER = 653
  | WAIT = 654
  | WBINVD = 655
  | WRFSBASE = 656
  | WRGSBASE = 657
  | WRMSR = 658
  | WRPKRU = 659
  | XABORT = 660
  | XADD = 661
  | XBEGIN = 662
  | XCHG = 663
  | XEND = 664
  | XGETBV = 665
  | XLATB = 666
  | XOR = 667
  | XORPD = 668
  | XORPS = 669
  | XRSTOR = 670
  | XSAVE = 671
  | XSAVEOPT = 672
  | XSETBV = 673
  | XTEST = 674
  | InvalOP = 675

let opVEX =
  [
   ("opNor0F1A", [| Opcode.InvalOP; Opcode.BNDMOV;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F1B", [| Opcode.InvalOP; Opcode.BNDMOV;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F10", [| Opcode.MOVUPS; Opcode.MOVUPD;
                    Opcode.MOVSS; Opcode.MOVSD |])
   ("opVex0F10Mem", [| Opcode.VMOVUPS; Opcode.VMOVUPD;
                       Opcode.VMOVSS; Opcode.VMOVSD |])
   ("opVex0F10Reg", [| Opcode.VMOVUPS; Opcode.VMOVUPD;
                       Opcode.VMOVSS; Opcode.VMOVSD |])
   ("opNor0F11", [| Opcode.MOVUPS; Opcode.MOVUPD;
                    Opcode.MOVSS; Opcode.MOVSD |])
   ("opVex0F11Mem", [| Opcode.VMOVUPS; Opcode.VMOVUPD;
                       Opcode.VMOVSS; Opcode.VMOVSD |])
   ("opVex0F11Reg", [| Opcode.VMOVUPS; Opcode.VMOVUPD;
                       Opcode.VMOVSS; Opcode.VMOVSD |])
   ("opNor0F12Mem", [| Opcode.MOVLPS; Opcode.MOVLPD;
                       Opcode.MOVSLDUP; Opcode.MOVDDUP |])
   ("opNor0F12Reg", [| Opcode.MOVHLPS; Opcode.MOVLPD;
                       Opcode.MOVSLDUP; Opcode.MOVDDUP |])
   ("opVex0F12Mem", [| Opcode.VMOVLPS; Opcode.VMOVLPD;
                       Opcode.VMOVSLDUP; Opcode.VMOVDDUP |])
   ("opVex0F12Reg", [| Opcode.VMOVHLPS; Opcode.VMOVLPD;
                       Opcode.VMOVSLDUP; Opcode.VMOVDDUP |])
   ("opNor0F13", [| Opcode.MOVLPS; Opcode.MOVLPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F13", [| Opcode.VMOVLPS; Opcode.VMOVLPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F14", [| Opcode.UNPCKLPS; Opcode.UNPCKLPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F14", [| Opcode.VUNPCKLPS; Opcode.VUNPCKLPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F15", [| Opcode.UNPCKHPS; Opcode.UNPCKHPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F15", [| Opcode.VUNPCKHPS; Opcode.VUNPCKHPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F16Mem", [| Opcode.MOVHPS; Opcode.MOVHPD;
                       Opcode.MOVSHDUP; Opcode.InvalOP |])
   ("opNor0F16Reg", [| Opcode.MOVLHPS; Opcode.MOVHPD;
                       Opcode.MOVSHDUP; Opcode.InvalOP |])
   ("opVex0F16Mem", [| Opcode.VMOVHPS; Opcode.VMOVHPD;
                       Opcode.VMOVSHDUP; Opcode.InvalOP |])
   ("opVex0F16Reg", [| Opcode.VMOVLHPS; Opcode.VMOVHPD;
                       Opcode.VMOVSHDUP; Opcode.InvalOP |])
   ("opNor0F17", [| Opcode.MOVHPS; Opcode.MOVHPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F17", [| Opcode.VMOVHPS; Opcode.VMOVHPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F28", [| Opcode.MOVAPS; Opcode.MOVAPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F28", [| Opcode.VMOVAPS; Opcode.VMOVAPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F29", [| Opcode.MOVAPS; Opcode.MOVAPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F29", [| Opcode.VMOVAPS; Opcode.VMOVAPS;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F2A", [| Opcode.CVTPI2PS; Opcode.CVTPI2PD;
                    Opcode.CVTSI2SS; Opcode.CVTSI2SD |])
   ("opVex0F2A", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.VCVTSI2SS; Opcode.VCVTSI2SD |])
   ("opNor0F2B", [| Opcode.MOVNTPS; Opcode.MOVNTPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F2B", [| Opcode.VMOVNTPS; Opcode.VMOVNTPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F2C", [| Opcode.CVTTPS2PI; Opcode.CVTTPD2PI;
                    Opcode.CVTTSS2SI; Opcode.CVTTSD2SI |])
   ("opVex0F2C", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.VCVTTSS2SI; Opcode.VCVTTSD2SI |])
   ("opNor0F2D", [| Opcode.CVTPS2PI; Opcode.CVTPD2PI;
                    Opcode.CVTSS2SI; Opcode.CVTSD2SI |])
   ("opVex0F2D", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.VCVTSS2SI; Opcode.VCVTSD2SI |])
   ("opNor0F2E", [| Opcode.UCOMISS; Opcode.UCOMISD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F2E", [| Opcode.VUCOMISS; Opcode.VUCOMISD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F2F", [| Opcode.COMISS; Opcode.COMISD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F2F", [| Opcode.VCOMISS; Opcode.VCOMISD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F50", [| Opcode.MOVMSKPS; Opcode.MOVMSKPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F50", [| Opcode.VMOVMSKPS; Opcode.VMOVMSKPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F54", [| Opcode.ANDPS; Opcode.ANDPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F54", [| Opcode.VANDPS; Opcode.VANDPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F55", [| Opcode.ANDNPS; Opcode.ANDNPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F55", [| Opcode.VANDNPS; Opcode.VANDNPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F56", [| Opcode.ORPS; Opcode.ORPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F56", [| Opcode.VORPS; Opcode.VORPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F57", [| Opcode.XORPS; Opcode.XORPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F57", [| Opcode.VXORPS; Opcode.VXORPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F58", [| Opcode.ADDPS; Opcode.ADDPD;
                    Opcode.ADDSS; Opcode.ADDSD |])
   ("opVex0F58", [| Opcode.VADDPS; Opcode.VADDPD;
                    Opcode.VADDSS; Opcode.VADDSD |])
   ("opNor0F59", [| Opcode.MULPS; Opcode.MULPD;
                    Opcode.MULSS; Opcode.MULSD |])
   ("opVex0F59", [| Opcode.VMULPS; Opcode.VMULPD;
                    Opcode.VMULSS; Opcode.VMULSD |])
   ("opNor0F5A", [| Opcode.CVTPS2PD; Opcode.CVTPD2PS;
                    Opcode.CVTSS2SD; Opcode.CVTSD2SS |])
   ("opVex0F5A", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F5B", [| Opcode.CVTDQ2PS; Opcode.CVTPS2DQ;
                    Opcode.CVTTPS2DQ; Opcode.InvalOP |])
   ("opVex0F5B", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F5C", [| Opcode.SUBPS; Opcode.SUBPD;
                    Opcode.SUBSS; Opcode.SUBSD |])
   ("opVex0F5C", [| Opcode.VSUBPS; Opcode.VSUBPD;
                    Opcode.VSUBSS; Opcode.VSUBSD |])
   ("opNor0F5D", [| Opcode.MINPS; Opcode.MINPD;
                    Opcode.MINSS; Opcode.MINSD |])
   ("opVex0F5D", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F5E", [| Opcode.DIVPS; Opcode.DIVPD;
                    Opcode.DIVSS; Opcode.DIVSD |])
   ("opVex0F5E", [| Opcode.VDIVPS; Opcode.VDIVPD;
                    Opcode.VDIVSS; Opcode.VDIVSD |])
   ("opNor0F5F", [| Opcode.MAXPS; Opcode.MAXPD;
                    Opcode.MAXSS; Opcode.MAXSD |])
   ("opVex0F5F", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F60", [| Opcode.PUNPCKLBW; Opcode.PUNPCKLBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F60", [| Opcode.InvalOP; Opcode.VPUNPCKLBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F61", [| Opcode.PUNPCKLWD; Opcode.PUNPCKLWD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F61", [| Opcode.InvalOP; Opcode.VPUNPCKLWD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F62", [| Opcode.PUNPCKLDQ; Opcode.PUNPCKLDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F62", [| Opcode.InvalOP; Opcode.VPUNPCKLDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F63", [| Opcode.PACKSSWB; Opcode.PACKSSWB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F63", [| Opcode.InvalOP; Opcode.VPACKSSWB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F64", [| Opcode.PCMPGTB; Opcode.PCMPGTB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F64", [| Opcode.InvalOP; Opcode.VPCMPGTB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F65", [| Opcode.PCMPGTW; Opcode.PCMPGTW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F65", [| Opcode.InvalOP; Opcode.VPCMPGTW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F66", [| Opcode.PCMPGTD; Opcode.PCMPGTD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F66", [| Opcode.InvalOP; Opcode.VPCMPGTD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F67", [| Opcode.PACKUSWB; Opcode.PACKUSWB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F67", [| Opcode.InvalOP; Opcode.VPACKUSWB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F68", [| Opcode.PUNPCKHBW; Opcode.PUNPCKHBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F68", [| Opcode.InvalOP; Opcode.VPUNPCKHBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F69", [| Opcode.PUNPCKHWD; Opcode.PUNPCKHWD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F69", [| Opcode.InvalOP; Opcode.VPUNPCKHWD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6A", [| Opcode.PUNPCKHDQ; Opcode.PUNPCKHDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F6A", [| Opcode.InvalOP; Opcode.VPUNPCKHDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6B", [| Opcode.PACKSSDW; Opcode.PACKSSDW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F6B", [| Opcode.InvalOP; Opcode.VPACKSSDW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6C", [| Opcode.InvalOP; Opcode.PUNPCKLQDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F6C", [| Opcode.InvalOP; Opcode.VPUNPCKLQDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6D", [| Opcode.InvalOP; Opcode.PUNPCKHQDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F6D", [| Opcode.InvalOP; Opcode.VPUNPCKHQDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6EB64", [| Opcode.MOVQ; Opcode.MOVQ;
                       Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6EB32", [| Opcode.MOVD; Opcode.MOVD;
                       Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F6EB64", [| Opcode.InvalOP; Opcode.VMOVQ;
                       Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F6EB32", [| Opcode.InvalOP; Opcode.VMOVD;
                       Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F6F", [| Opcode.MOVQ; Opcode.MOVDQA;
                    Opcode.MOVDQU; Opcode.InvalOP |])
   ("opVex0F6F", [| Opcode.InvalOP; Opcode.VMOVDQA;
                    Opcode.VMOVDQU; Opcode.InvalOP |])
   ("opEVex0F6FB64", [| Opcode.InvalOP; Opcode.VMOVDQA64;
                        Opcode.VMOVDQU64; Opcode.InvalOP |])
   ("opEVex0F6FB32", [| Opcode.InvalOP; Opcode.VMOVDQA32;
                        Opcode.VMOVDQU32; Opcode.InvalOP |])
   ("opNor0F70", [| Opcode.PSHUFW; Opcode.PSHUFD;
                    Opcode.PSHUFHW; Opcode.PSHUFLW |])
   ("opVex0F70", [| Opcode.InvalOP; Opcode.VPSHUFD;
                    Opcode.VPSHUFHW; Opcode.VPSHUFLW |])
   ("opNor0F74", [| Opcode.PCMPEQB; Opcode.PCMPEQB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F74", [| Opcode.InvalOP; Opcode.VPCMPEQB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F76", [| Opcode.PCMPEQD; Opcode.PCMPEQD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F76", [| Opcode.InvalOP; Opcode.VPCMPEQD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F77", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F77", [| Opcode.VZEROUPPER; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F7EB64", [| Opcode.MOVQ; Opcode.MOVQ;
                       Opcode.MOVQ; Opcode.InvalOP |])
   ("opNor0F7EB32", [| Opcode.MOVD; Opcode.MOVD;
                       Opcode.MOVQ; Opcode.InvalOP |])
   ("opVex0F7EB64", [| Opcode.InvalOP; Opcode.VMOVQ;
                       Opcode.VMOVQ; Opcode.InvalOP |])
   ("opVex0F7EB32", [| Opcode.InvalOP; Opcode.VMOVD;
                       Opcode.VMOVQ; Opcode.InvalOP |])
   ("opNor0F7F", [| Opcode.MOVQ; Opcode.MOVDQA;
                    Opcode.MOVDQU; Opcode.InvalOP |])
   ("opVex0F7F", [| Opcode.InvalOP; Opcode.VMOVDQA;
                    Opcode.VMOVDQU; Opcode.InvalOP |])
   ("opEVex0F7FB64", [| Opcode.InvalOP; Opcode.VMOVDQA64;
                        Opcode.InvalOP; Opcode.InvalOP |])
   ("opEVex0F7FB32", [| Opcode.InvalOP; Opcode.VMOVDQA32;
                        Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FC4", [| Opcode.PINSRW; Opcode.PINSRW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FC4", [| Opcode.InvalOP; Opcode.VPINSRW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FC5", [| Opcode.PEXTRW; Opcode.PEXTRW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FC5", [| Opcode.InvalOP; Opcode.VPEXTRW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FC6", [| Opcode.SHUFPS; Opcode.SHUFPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FC6", [| Opcode.VSHUFPS; Opcode.VSHUFPD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD1", [| Opcode.PSRLW; Opcode.PSRLW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD1", [| Opcode.InvalOP; Opcode.VPSRLW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD2", [| Opcode.PSRLD; Opcode.PSRLD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD2", [| Opcode.InvalOP; Opcode.VPSRLD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD3", [| Opcode.PSRLQ; Opcode.PSRLQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD3", [| Opcode.InvalOP; Opcode.VPSRLQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD4", [| Opcode.PADDQ; Opcode.PADDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD4", [| Opcode.InvalOP; Opcode.VPADDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD5", [| Opcode.PMULLW; Opcode.PMULLW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD5", [| Opcode.InvalOP; Opcode.VPMULLW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD6", [| Opcode.InvalOP; Opcode.MOVQ;
                    Opcode.MOVQ2DQ; Opcode.MOVDQ2Q |])
   ("opVex0FD6", [| Opcode.InvalOP; Opcode.VMOVQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD7", [| Opcode.PMOVMSKB; Opcode.PMOVMSKB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD7", [| Opcode.InvalOP; Opcode.VPMOVMSKB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD8", [| Opcode.PSUBUSB; Opcode.PSUBUSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD8", [| Opcode.InvalOP; Opcode.VPSUBUSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FD9", [| Opcode.PSUBUSW; Opcode.PSUBUSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FD9", [| Opcode.InvalOP; Opcode.VPSUBUSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FDA", [| Opcode.PMINUB; Opcode.PMINUB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FDA", [| Opcode.InvalOP; Opcode.VPMINUB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FDB", [| Opcode.PAND; Opcode.PAND;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FDB", [| Opcode.InvalOP; Opcode.VPAND;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FDC", [| Opcode.PADDUSB; Opcode.PADDUSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FDC", [| Opcode.InvalOP; Opcode.VPADDUSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FDD", [| Opcode.PADDUSW; Opcode.PADDUSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FDD", [| Opcode.InvalOP; Opcode.VPADDUSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FDE", [| Opcode.PMAXUB; Opcode.PMAXUB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FDE", [| Opcode.InvalOP; Opcode.VPMAXUB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FDF", [| Opcode.PANDN; Opcode.PANDN;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FDF", [| Opcode.InvalOP; Opcode.VPANDN;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE0", [| Opcode.PAVGB; Opcode.PAVGB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE0", [| Opcode.InvalOP; Opcode.VPAVGB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE1", [| Opcode.PSRAW; Opcode.PSRAW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE1", [| Opcode.InvalOP; Opcode.VPSRAW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE2", [| Opcode.PSRAD; Opcode.PSRAD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE2", [| Opcode.InvalOP; Opcode.VPSRAD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE3", [| Opcode.PAVGW; Opcode.PAVGW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE3", [| Opcode.InvalOP; Opcode.VPAVGW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE4", [| Opcode.PMULHUW; Opcode.PMULHUW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE4", [| Opcode.InvalOP; Opcode.VPMULHUW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE5", [| Opcode.PMULHW; Opcode.PMULHW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE5", [| Opcode.InvalOP; Opcode.VPMULHW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE6", [| Opcode.InvalOP; Opcode.CVTTPD2DQ;
                    Opcode.CVTDQ2PD; Opcode.CVTPD2DQ |])
   ("opVex0FE6", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE7", [| Opcode.MOVNTQ; Opcode.MOVNTDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE7", [| Opcode.InvalOP; Opcode.VMOVNTDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opEVex0FE7B64", [| Opcode.InvalOP; Opcode.InvalOP;
                        Opcode.InvalOP; Opcode.InvalOP |])
   ("opEVex0FE7B32", [| Opcode.InvalOP; Opcode.VMOVNTDQ;
                        Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE8", [| Opcode.PSUBSB; Opcode.PSUBSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE8", [| Opcode.InvalOP; Opcode.VPSUBSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FE9", [| Opcode.PSUBSW; Opcode.PSUBSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FE9", [| Opcode.InvalOP; Opcode.VPSUBSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FEA", [| Opcode.PMINSW; Opcode.PMINSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FEA", [| Opcode.InvalOP; Opcode.VPMINSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FEB", [| Opcode.POR; Opcode.POR; Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FEB", [| Opcode.InvalOP; Opcode.VPOR;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FEC", [| Opcode.PADDSB; Opcode.PADDSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FEC", [| Opcode.InvalOP; Opcode.VPADDSB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FED", [| Opcode.PADDSW; Opcode.PADDSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FED", [| Opcode.InvalOP; Opcode.VPADDSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FEE", [| Opcode.PMAXSW; Opcode.PMAXSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FEE", [| Opcode.InvalOP; Opcode.VPMAXSW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FEF", [| Opcode.PXOR; Opcode.PXOR;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FEF", [| Opcode.InvalOP; Opcode.VPXOR;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF0", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.LDDQU |])
   ("opVex0FF0", [| Opcode.InvalOP; Opcode.InvalOP;
                    Opcode.InvalOP; Opcode.VLDDQU |])
   ("opNor0FF1", [| Opcode.PSLLW; Opcode.PSLLW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF1", [| Opcode.InvalOP; Opcode.VPSLLW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF2", [| Opcode.PSLLD; Opcode.PSLLD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF2", [| Opcode.InvalOP; Opcode.VPSLLD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF3", [| Opcode.PSLLQ; Opcode.PSLLQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF3", [| Opcode.InvalOP; Opcode.VPSLLQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF4", [| Opcode.PMULUDQ; Opcode.PMULUDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF4", [| Opcode.InvalOP; Opcode.VPMULUDQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF5", [| Opcode.PMADDWD; Opcode.PMADDWD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF5", [| Opcode.InvalOP; Opcode.VPMADDWD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF6", [| Opcode.PSADBW; Opcode.PSADBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF6", [| Opcode.InvalOP; Opcode.VPSADBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF8", [| Opcode.PSUBB; Opcode.PSUBB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF8", [| Opcode.InvalOP; Opcode.VPSUBB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FF9", [| Opcode.PSUBW; Opcode.PSUBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FF9", [| Opcode.InvalOP; Opcode.VPSUBW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FFA", [| Opcode.PSUBD; Opcode.PSUBD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FFA", [| Opcode.InvalOP; Opcode.VPSUBD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FFB", [| Opcode.PSUBQ; Opcode.PSUBQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FFB", [| Opcode.InvalOP; Opcode.VPSUBQ;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FFC", [| Opcode.PADDB; Opcode.PADDB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FFC", [| Opcode.InvalOP; Opcode.VPADDB;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FFD", [| Opcode.PADDW; Opcode.PADDW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FFD", [| Opcode.InvalOP; Opcode.VPADDW;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0FFE", [| Opcode.PADDD; Opcode.PADDD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0FFE", [| Opcode.InvalOP; Opcode.VPADDD;
                    Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3800", [| Opcode.PSHUFB; Opcode.PSHUFB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3800", [| Opcode.InvalOP; Opcode.VPSHUFB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3817", [| Opcode.InvalOP; Opcode.PTEST;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3817", [| Opcode.InvalOP; Opcode.VPTEST;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3818", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3818", [| Opcode.InvalOP; Opcode.VBROADCASTSS;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opEVex0F3818", [| Opcode.InvalOP; Opcode.VBROADCASTSS;
                       Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3829", [| Opcode.InvalOP; Opcode.PCMPEQQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3829", [| Opcode.InvalOP; Opcode.VPCMPEQQ;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3838", [| Opcode.InvalOP; Opcode.PMINSB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F383B", [| Opcode.InvalOP; Opcode.PMINUD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F383B", [| Opcode.InvalOP; Opcode.VPMINUD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F385A", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F385A", [| Opcode.InvalOP; Opcode.VBROADCASTI128;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3878", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3878", [| Opcode.InvalOP; Opcode.VPBROADCASTB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F38F0", [| Opcode.MOVBE; Opcode.MOVBE;
                      Opcode.InvalOP; Opcode.CRC32; Opcode.CRC32 |])
   ("opNor0F38F1", [| Opcode.MOVBE; Opcode.MOVBE;
                      Opcode.InvalOP; Opcode.CRC32; Opcode.CRC32 |])
   ("opNor0F3A0F", [| Opcode.PALIGNR; Opcode.PALIGNR;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A0F", [| Opcode.InvalOP; Opcode.VPALIGNR;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A20", [| Opcode.InvalOP; Opcode.PINSRB;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A20", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A38", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A38", [| Opcode.InvalOP; Opcode.VINSERTI128;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A60", [| Opcode.InvalOP; Opcode.PCMPESTRM;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A60", [| Opcode.InvalOP; Opcode.VPCMPESTRM;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A61", [| Opcode.InvalOP; Opcode.PCMPESTRI;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A61", [| Opcode.InvalOP; Opcode.VPCMPESTRI;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A62", [| Opcode.InvalOP; Opcode.PCMPISTRM;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A62", [| Opcode.InvalOP; Opcode.VPCMPISTRM;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A63", [| Opcode.InvalOP; Opcode.PCMPISTRI;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A63", [| Opcode.InvalOP; Opcode.VPCMPISTRI;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opNor0F3A0B", [| Opcode.InvalOP; Opcode.ROUNDSD;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opVex0F3A0B", [| Opcode.InvalOP; Opcode.InvalOP;
                      Opcode.InvalOP; Opcode.InvalOP |])
   ("opEmpty", [| Opcode.InvalOP; Opcode.InvalOP;
                  Opcode.InvalOP; Opcode.InvalOP |])
]


let toInt64 (opcode: Opcode) =
  LanguagePrimitives.EnumToValue opcode |> int64

let combineDescs descs =
  descs
  |> Array.mapi (fun idx desc -> desc <<< (48 - idx * 16))
  |> Array.fold (fun acc desc -> desc ||| acc) 0L

let main _args =
  opVEX
  |> List.iter (fun (var, desc) ->
       printfn "let [<Literal>] %s = 0x%xL"
               var (Array.map toInt64 desc |> combineDescs))

fsi.CommandLineArgs |> main
