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
namespace B2R2.FrontEnd.Intel

/// <summary>
/// Represents an Intel opcode.
/// </summary>
type Opcode =
  /// ASCII Adjust After Addition.
  | AAA = 0
  /// ASCII Adjust AX Before Division.
  | AAD = 1
  /// ASCII Adjust AX After Multiply.
  | AAM = 2
  /// ASCII Adjust AL After Subtraction.
  | AAS = 3
  /// Add With Carry.
  | ADC = 4
  /// Unsigned Integer Addition of Two Operands With Carry Flag.
  | ADCX = 5
  /// Add.
  | ADD = 6
  /// Add Packed Double Precision Floating-Point Values.
  | ADDPD = 7
  /// Add Packed Single Precision Floating-Point Values.
  | ADDPS = 8
  /// Add Scalar Double Precision Floating-Point Values.
  | ADDSD = 9
  /// Add Scalar Single Precision Floating-Point Values.
  | ADDSS = 10
  /// Packed Double Precision Floating-Point Add/Subtract.
  | ADDSUBPD = 11
  /// Packed Single Precision Floating-Point Add/Subtract.
  | ADDSUBPS = 12
  /// Unsigned Integer Addition of Two Operands With Overflow Flag.
  | ADOX = 13
  /// Perform One Round of an AES Decryption Flow.
  | AESDEC = 14
  /// Perform Ten Rounds of AES Decryption Flow With Key Locker Using 128-Bit
  /// Key.
  | AESDEC128KL = 15
  /// Perform 14 Rounds of AES Decryption Flow With Key Locker Using 256-Bit
  /// Key.
  | AESDEC256KL = 16
  /// Perform Last Round of an AES Decryption Flow.
  | AESDECLAST = 17
  /// Perform Ten Rounds of AES Decryption Flow With Key Locker on 8 Blocks
  /// Using 128-Bit Key.
  | AESDECWIDE128KL = 18
  /// Perform 14 Rounds of AES Decryption Flow With Key Locker on 8 Blocks Using
  /// 256-Bit Key.
  | AESDECWIDE256KL = 19
  /// Perform One Round of an AES Encryption Flow.
  | AESENC = 20
  /// Perform Ten Rounds of AES Encryption Flow With Key Locker Using 128-Bit
  /// Key.
  | AESENC128KL = 21
  /// Perform 14 Rounds of AES Encryption Flow With Key Locker Using 256-Bit
  /// Key.
  | AESENC256KL = 22
  /// Perform Last Round of an AES Encryption Flow.
  | AESENCLAST = 23
  /// Perform Ten Rounds of AES Encryption Flow With Key Locker on 8 Blocks
  /// Using 128-Bit Key.
  | AESENCWIDE128KL = 24
  /// Perform 14 Rounds of AES Encryption Flow With Key Locker on 8 Blocks Using
  /// 256-Bit Key.
  | AESENCWIDE256KL = 25
  /// Perform the AES InvMixColumn Transformation.
  | AESIMC = 26
  /// AES Round Key Generation Assist.
  | AESKEYGENASSIST = 27
  /// Logical AND.
  | AND = 28
  /// Logical AND NOT.
  | ANDN = 29
  /// Bitwise Logical AND NOT of Packed Double Precision Floating-Point Values.
  | ANDNPD = 30
  /// Bitwise Logical AND NOT of Packed Single Precision Floating-Point Values.
  | ANDNPS = 31
  /// Bitwise Logical AND of Packed Double Precision Floating-Point Values.
  | ANDPD = 32
  /// Bitwise Logical AND of Packed Single Precision Floating-Point Values.
  | ANDPS = 33
  /// Adjust RPL Field of Segment Selector.
  | ARPL = 34
  /// Bit Field Extract.
  | BEXTR = 35
  /// Blend Packed Double Precision Floating-Point Values.
  | BLENDPD = 36
  /// Blend Packed Single Precision Floating-Point Values.
  | BLENDPS = 37
  /// Variable Blend Packed Double Precision Floating-Point Values.
  | BLENDVPD = 38
  /// Variable Blend Packed Single Precision Floating-Point Values.
  | BLENDVPS = 39
  /// Extract Lowest Set Isolated Bit.
  | BLSI = 40
  /// Get Mask Up to Lowest Set Bit.
  | BLSMSK = 41
  /// Reset Lowest Set Bit.
  | BLSR = 42
  /// Check Lower Bound.
  | BNDCL = 43
  /// Check Upper Bound.
  | BNDCN = 44
  /// Check Upper Bound.
  | BNDCU = 45
  /// Load Extended Bounds Using Address Translation.
  | BNDLDX = 46
  /// Make Bounds.
  | BNDMK = 47
  /// Move Bounds.
  | BNDMOV = 48
  /// Store Extended Bounds Using Address Translation.
  | BNDSTX = 49
  /// Check Array Index Against Bounds.
  | BOUND = 50
  /// Bit Scan Forward.
  | BSF = 51
  /// Bit Scan Reverse.
  | BSR = 52
  /// Byte Swap.
  | BSWAP = 53
  /// Bit Test.
  | BT = 54
  /// Bit Test and Complement.
  | BTC = 55
  /// Bit Test and Reset.
  | BTR = 56
  /// Bit Test and Set.
  | BTS = 57
  /// Zero High Bits Starting with Specified Bit Position.
  | BZHI = 58
  /// Call Procedure.
  | CALL = 59
  /// Convert Byte to Word/Convert Word to Doubleword/Convert Doubleword to
  /// Quadword.
  | CBW = 60
  /// Chinese national cryptographic algorithms.
  | CCS_ENCRYPT = 61
  /// Chinese national cryptographic algorithms.
  | CCS_HASH = 62
  /// Convert Word to Doubleword/Convert Doubleword to Quadword.
  | CDQ = 63
  /// Convert Byte to Word/Convert Word to Doubleword/Convert Doubleword to
  /// Quadword.
  | CDQE = 64
  /// Clear AC Flag in EFLAGS Register.
  | CLAC = 65
  /// Clear Carry Flag.
  | CLC = 66
  /// Clear Direction Flag.
  | CLD = 67
  /// Cache Line Demote.
  | CLDEMOTE = 68
  /// Flush Cache Line.
  | CLFLUSH = 69
  /// Flush Cache Line Optimized.
  | CLFLUSHOPT = 70
  /// Clear Interrupt Flag.
  | CLI = 71
  /// Clear Busy Flag in a Supervisor Shadow Stack Token.
  | CLRSSBSY = 72
  /// Clear Task-Switched Flag in CR0.
  | CLTS = 73
  /// Clear User Interrupt Flag.
  | CLUI = 74
  /// Cache Line Write Back.
  | CLWB = 75
  /// Complement Carry Flag.
  | CMC = 76
  /// Conditional Move.
  | CMOVA = 77
  /// Conditional Move.
  | CMOVAE = 78
  /// Conditional Move.
  | CMOVB = 79
  /// Conditional Move.
  | CMOVBE = 80
  /// Conditional Move.
  | CMOVC = 81
  /// Conditional Move.
  | CMOVE = 82
  /// Conditional Move.
  | CMOVG = 83
  /// Conditional Move.
  | CMOVGE = 84
  /// Conditional Move.
  | CMOVL = 85
  /// Conditional Move.
  | CMOVLE = 86
  /// Conditional Move.
  | CMOVNA = 87
  /// Conditional Move.
  | CMOVNAE = 88
  /// Conditional Move.
  | CMOVNB = 89
  /// Conditional Move.
  | CMOVNBE = 90
  /// Conditional Move.
  | CMOVNC = 91
  /// Conditional Move.
  | CMOVNE = 92
  /// Conditional Move.
  | CMOVNG = 93
  /// Conditional Move.
  | CMOVNGE = 94
  /// Conditional Move.
  | CMOVNL = 95
  /// Conditional Move.
  | CMOVNLE = 96
  /// Conditional Move.
  | CMOVNO = 97
  /// Conditional Move.
  | CMOVNP = 98
  /// Conditional Move.
  | CMOVNS = 99
  /// Conditional Move.
  | CMOVNZ = 100
  /// Conditional Move.
  | CMOVO = 101
  /// Conditional Move.
  | CMOVP = 102
  /// Conditional Move.
  | CMOVPE = 103
  /// Conditional Move.
  | CMOVPO = 104
  /// Conditional Move.
  | CMOVS = 105
  /// Conditional Move.
  | CMOVZ = 106
  /// Compare Two Operands.
  | CMP = 107
  /// Compare and Add if Condition is Met.
  | CMPBEXADD = 108
  /// Compare and Add if Condition is Met.
  | CMPBXADD = 109
  /// Compare and Add if Condition is Met.
  | CMPLEXADD = 110
  /// Compare and Add if Condition is Met.
  | CMPLXADD = 111
  /// Compare and Add if Condition is Met.
  | CMPNBEXADD = 112
  /// Compare and Add if Condition is Met.
  | CMPNBXADD = 113
  /// Compare and Add if Condition is Met.
  | CMPNLEXADD = 114
  /// Compare and Add if Condition is Met.
  | CMPNLXADD = 115
  /// Compare and Add if Condition is Met.
  | CMPNOXADD = 116
  /// Compare and Add if Condition is Met.
  | CMPNPXADD = 117
  /// Compare and Add if Condition is Met.
  | CMPNSXADD = 118
  /// Compare and Add if Condition is Met.
  | CMPNZXADD = 119
  /// Compare and Add if Condition is Met.
  | CMPOXADD = 120
  /// Compare Packed Double Precision Floating-Point Values.
  | CMPPD = 121
  /// Compare Packed Single Precision Floating-Point Values.
  | CMPPS = 122
  /// Compare and Add if Condition is Met.
  | CMPPXADD = 123
  /// Compare String Operands.
  | CMPS = 124
  /// Compare String Operands.
  | CMPSB = 125
  /// Compare String Operands.
  /// Compare Scalar Double Precision Floating-Point Value.
  | CMPSD = 126
  /// Compare String Operands.
  | CMPSQ = 127
  /// Compare Scalar Single Precision Floating-Point Value.
  | CMPSS = 128
  /// Compare String Operands.
  | CMPSW = 129
  /// Compare and Add if Condition is Met.
  | CMPSXADD = 130
  /// Compare and Exchange.
  | CMPXCHG = 131
  /// Compare and Exchange Bytes.
  | CMPXCHG16B = 132
  /// Compare and Exchange Bytes.
  | CMPXCHG8B = 133
  /// Compare and Add if Condition is Met.
  | CMPZXADD = 134
  /// Compare Scalar Ordered Double Precision Floating-Point Values and Set
  /// EFLAGS.
  | COMISD = 135
  /// Compare Scalar Ordered Single Precision Floating-Point Values and Set
  /// EFLAGS.
  | COMISS = 136
  /// CPU Identification.
  | CPUID = 137
  /// Convert Word to Doubleword/Convert Doubleword to Quadword.
  | CQO = 138
  /// Accumulate CRC32 Value.
  | CRC32 = 139
  /// Convert Packed Doubleword Integers to Packed Double Precision
  /// Floating-Point Values.
  | CVTDQ2PD = 140
  /// Convert Packed Doubleword Integers to Packed Single Precision
  /// Floating-Point Values.
  | CVTDQ2PS = 141
  /// Convert Packed Double Precision Floating-Point Values to Packed Doubleword
  /// Integers.
  | CVTPD2DQ = 142
  /// Convert Packed Double Precision Floating-Point Values to Packed Dword
  /// Integers.
  | CVTPD2PI = 143
  /// Convert Packed Double Precision Floating-Point Values to Packed Single
  /// Precision Floating-Point Values.
  | CVTPD2PS = 144
  /// Convert Packed Dword Integers to Packed Double Precision Floating-Point
  /// Values.
  | CVTPI2PD = 145
  /// Convert Packed Dword Integers to Packed Single Precision Floating-Point
  /// Values.
  | CVTPI2PS = 146
  /// Convert Packed Single Precision Floating-Point Values to Packed Signed
  /// Doubleword Integer Values.
  | CVTPS2DQ = 147
  /// Convert Packed Single Precision Floating-Point Values to Packed Double
  /// Precision Floating-Point Values.
  | CVTPS2PD = 148
  /// Convert Packed Single Precision Floating-Point Values to Packed Dword
  /// Integers.
  | CVTPS2PI = 149
  /// Convert Scalar Double Precision Floating-Point Value to Signed Integer.
  | CVTSD2SI = 150
  /// Convert Scalar Double Precision Floating-Point Value to Scalar Single
  /// Precision Floating-Point Value.
  | CVTSD2SS = 151
  /// Convert Signed Integer to Scalar Double Precision Floating-Point Value.
  | CVTSI2SD = 152
  /// Convert Signed Integer to Scalar Single Precision Floating-Point Value.
  | CVTSI2SS = 153
  /// Convert Scalar Single Precision Floating-Point Value to Scalar Double
  /// Precision Floating-Point Value.
  | CVTSS2SD = 154
  /// Convert Scalar Single Precision Floating-Point Value to Signed Integer.
  | CVTSS2SI = 155
  /// Convert with Truncation Packed Double Precision Floating-Point Values to
  /// Packed Doubleword Integers.
  | CVTTPD2DQ = 156
  /// Convert With Truncation Packed Double Precision Floating-Point Values to
  /// Packed Dword Integers.
  | CVTTPD2PI = 157
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Signed Doubleword Integer Values.
  | CVTTPS2DQ = 158
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Dword Integers.
  | CVTTPS2PI = 159
  /// Convert With Truncation Scalar Double Precision Floating-Point Value to
  /// Signed Integer.
  | CVTTSD2SI = 160
  /// Convert With Truncation Scalar Single Precision Floating-Point Value to
  /// Signed Integer.
  | CVTTSS2SI = 161
  /// Convert Word to Doubleword/Convert Doubleword to Quadword.
  | CWD = 162
  /// Convert Byte to Word/Convert Word to Doubleword/Convert Doubleword to
  /// Quadword.
  | CWDE = 163
  /// Decimal Adjust AL After Addition.
  | DAA = 164
  /// Decimal Adjust AL After Subtraction.
  | DAS = 165
  /// Decrement by 1.
  | DEC = 166
  /// Unsigned Divide.
  | DIV = 167
  /// Divide Packed Double Precision Floating-Point Values.
  | DIVPD = 168
  /// Divide Packed Single Precision Floating-Point Values.
  | DIVPS = 169
  /// Divide Scalar Double Precision Floating-Point Value.
  | DIVSD = 170
  /// Divide Scalar Single Precision Floating-Point Values.
  | DIVSS = 171
  /// Dot Product of Packed Double Precision Floating-Point Values.
  | DPPD = 172
  /// Dot Product of Packed Single Precision Floating-Point Values.
  | DPPS = 173
  /// Empty MMX Technology State.
  | EMMS = 174
  /// Encode 128-Bit Key With Key Locker.
  | ENCODEKEY128 = 175
  /// Encode 256-Bit Key With Key Locker.
  | ENCODEKEY256 = 176
  /// Terminate an Indirect Branch in 32-bit and Compatibility Mode.
  | ENDBR32 = 177
  /// Terminate an Indirect Branch in 64-bit Mode.
  | ENDBR64 = 178
  /// Enqueue Command.
  | ENQCMD = 179
  /// Enqueue Command Supervisor.
  | ENQCMDS = 180
  /// Make Stack Frame for Procedure Parameters.
  | ENTER = 181
  /// Extract Packed Floating-Point Values.
  | EXTRACTPS = 182
  /// Extract Field from Register.
  | EXTRQ = 183
  /// Compute 2x-1.
  | F2XM1 = 184
  /// Absolute Value.
  | FABS = 185
  /// Add.
  | FADD = 186
  /// Add.
  | FADDP = 187
  /// Load Binary Coded Decimal.
  | FBLD = 188
  /// Store BCD Integer and Pop.
  | FBSTP = 189
  /// Change Sign.
  | FCHS = 190
  /// Clear Exceptions.
  | FCLEX = 191
  /// Floating-Point Conditional Move.
  | FCMOVB = 192
  /// Floating-Point Conditional Move.
  | FCMOVBE = 193
  /// Floating-Point Conditional Move.
  | FCMOVE = 194
  /// Floating-Point Conditional Move.
  | FCMOVNB = 195
  /// Floating-Point Conditional Move.
  | FCMOVNBE = 196
  /// Floating-Point Conditional Move.
  | FCMOVNE = 197
  /// Floating-Point Conditional Move.
  | FCMOVNU = 198
  /// Floating-Point Conditional Move.
  | FCMOVU = 199
  /// Compare Floating-Point Values.
  | FCOM = 200
  /// Compare Floating-Point Values and Set EFLAGS.
  | FCOMI = 201
  /// Compare Floating-Point Values and Set EFLAGS.
  | FCOMIP = 202
  /// Compare Floating-Point Values.
  | FCOMP = 203
  /// Compare Floating-Point Values.
  | FCOMPP = 204
  /// Cosine.
  | FCOS = 205
  /// Decrement Stack-Top Pointer.
  | FDECSTP = 206
  /// Divide.
  | FDIV = 207
  /// Divide.
  | FDIVP = 208
  /// Reverse Divide.
  | FDIVR = 209
  /// Reverse Divide.
  | FDIVRP = 210
  /// Free Floating-Point Register.
  | FFREE = 211
  /// Performs FFREE ST(i) and pop stack.
  | FFREEP = 212
  /// Add.
  | FIADD = 213
  /// Compare Integer.
  | FICOM = 214
  /// Compare Integer.
  | FICOMP = 215
  /// Divide.
  | FIDIV = 216
  /// Reverse Divide.
  | FIDIVR = 217
  /// Load Integer.
  | FILD = 218
  /// Multiply.
  | FIMUL = 219
  /// Increment Stack-Top Pointer.
  | FINCSTP = 220
  /// Initialize Floating-Point Unit.
  | FINIT = 221
  /// Store Integer.
  | FIST = 222
  /// Store Integer.
  | FISTP = 223
  /// Store Integer With Truncation.
  | FISTTP = 224
  /// Subtract.
  | FISUB = 225
  /// Reverse Subtract.
  | FISUBR = 226
  /// Load Floating-Point Value.
  | FLD = 227
  /// Load Constant.
  | FLD1 = 228
  /// Load x87 FPU Control Word.
  | FLDCW = 229
  /// Load x87 FPU Environment.
  | FLDENV = 230
  /// Load Constant.
  | FLDL2E = 231
  /// Load Constant.
  | FLDL2T = 232
  /// Load Constant.
  | FLDLG2 = 233
  /// Load Constant.
  | FLDLN2 = 234
  /// Load Constant.
  | FLDPI = 235
  /// Load Constant.
  | FLDZ = 236
  /// Multiply.
  | FMUL = 237
  /// Multiply.
  | FMULP = 238
  /// Clear Exceptions.
  | FNCLEX = 239
  /// Initialize Floating-Point Unit.
  | FNINIT = 240
  /// No Operation.
  | FNOP = 241
  /// Store x87 FPU State.
  | FNSAVE = 242
  /// Store x87 FPU Control Word.
  | FNSTCW = 243
  /// Store x87 FPU Environment.
  | FNSTENV = 244
  /// Store x87 FPU Status Word.
  | FNSTSW = 245
  /// Partial Arctangent.
  | FPATAN = 246
  /// Partial Remainder.
  | FPREM = 247
  /// Partial Remainder.
  | FPREM1 = 248
  /// Partial Tangent.
  | FPTAN = 249
  /// Round to Integer.
  | FRNDINT = 250
  /// Restore x87 FPU State.
  | FRSTOR = 251
  /// Store x87 FPU State.
  | FSAVE = 252
  /// Scale.
  | FSCALE = 253
  /// Sine.
  | FSIN = 254
  /// Sine and Cosine.
  | FSINCOS = 255
  /// Square Root.
  | FSQRT = 256
  /// Store Floating-Point Value.
  | FST = 257
  /// Store x87 FPU Control Word.
  | FSTCW = 258
  /// Store x87 FPU Environment.
  | FSTENV = 259
  /// Store Floating-Point Value.
  | FSTP = 260
  /// Store x87 FPU Status Word.
  | FSTSW = 261
  /// Subtract.
  | FSUB = 262
  /// Subtract.
  | FSUBP = 263
  /// Reverse Subtract.
  | FSUBR = 264
  /// Reverse Subtract.
  | FSUBRP = 265
  /// TEST.
  | FTST = 266
  /// Unordered Compare Floating-Point Values.
  | FUCOM = 267
  /// Compare Floating-Point Values and Set EFLAGS.
  | FUCOMI = 268
  /// Compare Floating-Point Values and Set EFLAGS.
  | FUCOMIP = 269
  /// Unordered Compare Floating-Point Values.
  | FUCOMP = 270
  /// Unordered Compare Floating-Point Values.
  | FUCOMPP = 271
  /// Wait.
  | FWAIT = 272
  /// Examine Floating-Point.
  | FXAM = 273
  /// Exchange Register Contents.
  | FXCH = 274
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR = 275
  /// Restore x87 FPU, MMX, XMM, and MXCSR State.
  | FXRSTOR64 = 276
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE = 277
  /// Save x87 FPU, MMX Technology, and SSE State.
  | FXSAVE64 = 278
  /// Extract Exponent and Significand.
  | FXTRACT = 279
  /// Compute y * log2x.
  | FYL2X = 280
  /// Compute y * log2(x +1).
  | FYL2XP1 = 281
  /// GETSEC[CAPABILITIES]: Report the SMX capabilities. The capabilities index
  /// is input in EBX with the result returned in EAX.
  /// GETSEC[ENTERACCS]: Enter authenticated code execution mode. EBX holds the
  /// authenticated code module physical base address. ECX holds the
  /// authenticated code module size (bytes).
  /// GETSEC[EXITAC]: Exit authenticated code execution mode. RBX holds the Near
  /// Absolute Indirect jump target and EDX hold the exit parameter flags.
  /// GETSEC[SENTER]: Launch a measured environment. EBX holds the SINIT
  /// authenticated code module physical base address. ECX holds the SINIT
  /// authenticated code module size (bytes). EDX controls the level of
  /// functionality supported by the measured environment launch.
  /// GETSEC[SEXIT]: Exit measured environment.
  /// GETSEC[PARAMETERS]: Report the SMX parameters. The parameters index is
  /// input in EBX with the result returned in EAX, EBX, and ECX.
  /// GETSEC[SMCTRL]: Perform specified SMX mode control as selected with the
  /// input EBX.
  /// GETSEC[WAKEUP]: Wake up the responding logical processors from the SENTER
  /// sleep state.
  | GETSEC = 282
  /// Galois Field Affine Transformation Inverse.
  | GF2P8AFFINEINVQB = 283
  /// Galois Field Affine Transformation.
  | GF2P8AFFINEQB = 284
  /// Galois Field Multiply Bytes.
  | GF2P8MULB = 285
  /// Packed Double Precision Floating-Point Horizontal Add.
  | HADDPD = 286
  /// Packed Single Precision Floating-Point Horizontal Add.
  | HADDPS = 287
  /// Halt.
  | HLT = 288
  /// History Reset.
  | HRESET = 289
  /// Packed Double Precision Floating-Point Horizontal Subtract.
  | HSUBPD = 290
  /// Packed Single Precision Floating-Point Horizontal Subtract.
  | HSUBPS = 291
  /// Signed Divide.
  | IDIV = 292
  /// Signed Multiply.
  | IMUL = 293
  /// Input From Port.
  | IN = 294
  /// Increment by 1.
  | INC = 295
  /// Increment Shadow Stack Pointer.
  | INCSSPD = 296
  /// Increment Shadow Stack Pointer.
  | INCSSPQ = 297
  /// Input from Port to String.
  | INS = 298
  /// Input from Port to String.
  | INSB = 299
  /// Input from Port to String.
  | INSD = 300
  /// Insert Scalar Single Precision Floating-Point Value.
  | INSERTPS = 301
  /// Inserts Field from a source Register to a destination Register.
  | INSERTQ = 302
  /// Input from Port to String.
  | INSW = 303
  /// Call to Interrupt Procedure.
  | INT = 304
  /// Call to Interrupt Procedure.
  | INT1 = 305
  /// Call to Interrupt Procedure.
  | INT3 = 306
  /// Call to Interrupt Procedure.
  | INTO = 307
  /// Invalidate Internal Caches.
  | INVD = 308
  /// Invalidate TLB Entries.
  | INVLPG = 309
  /// Invalidate Process-Context Identifier.
  | INVPCID = 310
  /// Interrupt Return.
  | IRET = 311
  /// Interrupt Return.
  | IRETD = 312
  /// Interrupt Return.
  | IRETQ = 313
  /// Interrupt return (16-bit operand size).
  | IRETW = 314
  /// Jump if Condition Is Met.
  | JA = 315
  | JNBE = 315
  /// Jump if Condition Is Met.
  | JNB = 316
  | JAE = 316
  | JNC = 316
  /// Jump if Condition Is Met.
  | JB = 317
  | JC = 317
  | JNAE = 317
  /// Jump if Condition Is Met.
  | JBE = 318
  | JNA = 318
  /// Jump if Condition Is Met.
  | JCXZ = 319
  /// Jump if Condition Is Met.
  | JZ = 320
  | JE = 320
  /// Jump if Condition Is Met.
  | JECXZ = 321
  /// Jump if Condition Is Met.
  | JG = 322
  | JNLE = 322
  /// Jump if Condition Is Met.
  | JNL = 323
  | JGE = 323
  /// Jump if Condition Is Met.
  | JL = 324
  | JNGE = 324
  /// Jump if Condition Is Met.
  | JLE = 325
  | JNG = 325
  /// Jump.
  | JMP = 326
  /// Jump if Condition Is Met.
  | JNZ = 327
  | JNE = 327
  /// Jump if Condition Is Met.
  | JNO = 328
  /// Jump if Condition Is Met.
  | JNP = 329
  | JPO = 329
  /// Jump if Condition Is Met.
  | JNS = 330
  /// Jump if Condition Is Met.
  | JO = 331
  /// Jump if Condition Is Met.
  | JP = 332
  | JPE = 332
  /// Jump if Condition Is Met.
  | JRCXZ = 333
  /// Jump if Condition Is Met.
  | JS = 334
  /// ADD Two Masks.
  | KADDB = 335
  /// ADD Two Masks.
  | KADDD = 336
  /// ADD Two Masks.
  | KADDQ = 337
  /// ADD Two Masks.
  | KADDW = 338
  /// Bitwise Logical AND Masks.
  | KANDB = 339
  /// Bitwise Logical AND Masks.
  | KANDD = 340
  /// Bitwise Logical AND NOT Masks.
  | KANDNB = 341
  /// Bitwise Logical AND NOT Masks.
  | KANDND = 342
  /// Bitwise Logical AND NOT Masks.
  | KANDNQ = 343
  /// Bitwise Logical AND NOT Masks.
  | KANDNW = 344
  /// Bitwise Logical AND Masks.
  | KANDQ = 345
  /// Bitwise Logical AND Masks.
  | KANDW = 346
  /// Move From and to Mask Registers.
  | KMOVB = 347
  /// Move From and to Mask Registers.
  | KMOVD = 348
  /// Move From and to Mask Registers.
  | KMOVQ = 349
  /// Move From and to Mask Registers.
  | KMOVW = 350
  /// NOT Mask Register.
  | KNOTB = 351
  /// NOT Mask Register.
  | KNOTD = 352
  /// NOT Mask Register.
  | KNOTQ = 353
  /// NOT Mask Register.
  | KNOTW = 354
  /// Bitwise Logical OR Masks.
  | KORB = 355
  /// Bitwise Logical OR Masks.
  | KORD = 356
  /// Bitwise Logical OR Masks.
  | KORQ = 357
  /// OR Masks and Set Flags.
  | KORTESTB = 358
  /// OR Masks and Set Flags.
  | KORTESTD = 359
  /// OR Masks and Set Flags.
  | KORTESTQ = 360
  /// OR Masks and Set Flags.
  | KORTESTW = 361
  /// Bitwise Logical OR Masks.
  | KORW = 362
  /// Shift Left Mask Registers.
  | KSHIFTLB = 363
  /// Shift Left Mask Registers.
  | KSHIFTLD = 364
  /// Shift Left Mask Registers.
  | KSHIFTLQ = 365
  /// Shift Left Mask Registers.
  | KSHIFTLW = 366
  /// Shift Right Mask Registers.
  | KSHIFTRB = 367
  /// Shift Right Mask Registers.
  | KSHIFTRD = 368
  /// Shift Right Mask Registers.
  | KSHIFTRQ = 369
  /// Shift Right Mask Registers.
  | KSHIFTRW = 370
  /// Packed Bit Test Masks and Set Flags.
  | KTESTB = 371
  /// Packed Bit Test Masks and Set Flags.
  | KTESTD = 372
  /// Packed Bit Test Masks and Set Flags.
  | KTESTQ = 373
  /// Packed Bit Test Masks and Set Flags.
  | KTESTW = 374
  /// Unpack for Mask Registers.
  | KUNPCKBW = 375
  /// Unpack for Mask Registers.
  | KUNPCKDQ = 376
  /// Unpack for Mask Registers.
  | KUNPCKWD = 377
  /// Bitwise Logical XNOR Masks.
  | KXNORB = 378
  /// Bitwise Logical XNOR Masks.
  | KXNORD = 379
  /// Bitwise Logical XNOR Masks.
  | KXNORQ = 380
  /// Bitwise Logical XNOR Masks.
  | KXNORW = 381
  /// Bitwise Logical XOR Masks.
  | KXORB = 382
  /// Bitwise Logical XOR Masks.
  | KXORD = 383
  /// Bitwise Logical XOR Masks.
  | KXORQ = 384
  /// Bitwise Logical XOR Masks.
  | KXORW = 385
  /// Load Status Flags Into AH Register.
  | LAHF = 386
  /// Load Access Rights.
  | LAR = 387
  /// Load Unaligned Integer 128 Bits.
  | LDDQU = 388
  /// Load MXCSR Register.
  | LDMXCSR = 389
  /// Load Far Pointer.
  | LDS = 390
  /// Load Tile Configuration.
  | LDTILECFG = 391
  /// Load Effective Address.
  | LEA = 392
  /// High Level Procedure Exit.
  | LEAVE = 393
  /// Load Far Pointer.
  | LES = 394
  /// Load Fence.
  | LFENCE = 395
  /// Load Far Pointer.
  | LFS = 396
  /// Load Global/Interrupt Descriptor Table Register.
  | LGDT = 397
  /// Load Far Pointer.
  | LGS = 398
  /// Load Global/Interrupt Descriptor Table Register.
  | LIDT = 399
  /// Load Local Descriptor Table Register.
  | LLDT = 400
  /// Load Machine Status Word.
  | LMSW = 401
  /// Load Internal Wrapping Key With Key Locker.
  | LOADIWKEY = 402
  /// Assert LOCK# Signal Prefix.
  | LOCK = 403
  /// Load String.
  | LODS = 404
  /// Load String.
  | LODSB = 405
  /// Load String.
  | LODSD = 406
  /// Load String.
  | LODSQ = 407
  /// Load String.
  | LODSW = 408
  /// Loop According to ECX Counter.
  | LOOP = 409
  /// Loop According to ECX Counter.
  | LOOPE = 410
  /// Loop According to ECX Counter.
  | LOOPNE = 411
  /// Load Segment Limit.
  | LSL = 412
  /// Load Far Pointer.
  | LSS = 413
  /// Load Task Register.
  | LTR = 414
  /// Count the Number of Leading Zero Bits.
  | LZCNT = 415
  /// Store Selected Bytes of Double Quadword.
  | MASKMOVDQU = 416
  /// Store Selected Bytes of Quadword.
  | MASKMOVQ = 417
  /// Maximum of Packed Double Precision Floating-Point Values.
  | MAXPD = 418
  /// Maximum of Packed Single Precision Floating-Point Values.
  | MAXPS = 419
  /// Return Maximum Scalar Double Precision Floating-Point Value.
  | MAXSD = 420
  /// Return Maximum Scalar Single Precision Floating-Point Value.
  | MAXSS = 421
  /// Memory Fence.
  | MFENCE = 422
  /// Minimum of Packed Double Precision Floating-Point Values.
  | MINPD = 423
  /// Minimum of Packed Single Precision Floating-Point Values.
  | MINPS = 424
  /// Return Minimum Scalar Double Precision Floating-Point Value.
  | MINSD = 425
  /// Return Minimum Scalar Single Precision Floating-Point Value.
  | MINSS = 426
  /// Set Up Monitor Address.
  | MONITOR = 427
  /// Montgomery multiplier (PMM).
  | MONTMUL = 428
  /// Montgomery multiplier (PMM).
  | MONTMUL2 = 429
  /// Move.
  | MOV = 430
  /// Move Aligned Packed Double Precision Floating-Point Values.
  | MOVAPD = 431
  /// Move Aligned Packed Single Precision Floating-Point Values.
  | MOVAPS = 432
  /// Move Data After Swapping Bytes.
  | MOVBE = 433
  /// Move Doubleword/Move Quadword.
  | MOVD = 434
  /// Replicate Double Precision Floating-Point Values.
  | MOVDDUP = 435
  /// Move 64 Bytes as Direct Store.
  | MOVDIR64B = 436
  /// Move Doubleword as Direct Store.
  | MOVDIRI = 437
  /// Move Quadword from XMM to MMX Technology Register.
  | MOVDQ2Q = 438
  /// Move Aligned Packed Integer Values.
  | MOVDQA = 439
  /// Move Unaligned Packed Integer Values.
  | MOVDQU = 440
  /// Move Packed Single Precision Floating-Point Values High to Low.
  | MOVHLPS = 441
  /// Move High Packed Double Precision Floating-Point Value.
  | MOVHPD = 442
  /// Move High Packed Single Precision Floating-Point Values.
  | MOVHPS = 443
  /// Move Packed Single Precision Floating-Point Values Low to High.
  | MOVLHPS = 444
  /// Move Low Packed Double Precision Floating-Point Value.
  | MOVLPD = 445
  /// Move Low Packed Single Precision Floating-Point Values.
  | MOVLPS = 446
  /// Extract Packed Double Precision Floating-Point Sign Mask.
  | MOVMSKPD = 447
  /// Extract Packed Single Precision Floating-Point Sign Mask.
  | MOVMSKPS = 448
  /// Store Packed Integers Using Non-Temporal Hint.
  | MOVNTDQ = 449
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | MOVNTDQA = 450
  /// Store Doubleword Using Non-Temporal Hint.
  | MOVNTI = 451
  /// Store Packed Double Precision Floating-Point Values Using Non-Temporal
  /// Hint.
  | MOVNTPD = 452
  /// Store Packed Single Precision Floating-Point Values Using Non-Temporal
  /// Hint.
  | MOVNTPS = 453
  /// Store of Quadword Using Non-Temporal Hint.
  | MOVNTQ = 454
  /// Move Doubleword/Move Quadword.
  /// Move Quadword.
  | MOVQ = 455
  /// Move Quadword from MMX Technology to XMM Register.
  | MOVQ2DQ = 456
  /// Move Data From String to String.
  | MOVS = 457
  /// Move Data From String to String.
  | MOVSB = 458
  /// Move Data From String to String.
  /// Move or Merge Scalar Double Precision Floating-Point Value.
  | MOVSD = 459
  /// Replicate Single Precision Floating-Point Values.
  | MOVSHDUP = 460
  /// Replicate Single Precision Floating-Point Values.
  | MOVSLDUP = 461
  /// Move Data From String to String.
  | MOVSQ = 462
  /// Move or Merge Scalar Single Precision Floating-Point Value.
  | MOVSS = 463
  /// Move Data From String to String.
  | MOVSW = 464
  /// Move With Sign-Extension.
  | MOVSX = 465
  /// Move With Sign-Extension.
  | MOVSXD = 466
  /// Move Unaligned Packed Double Precision Floating-Point Values.
  | MOVUPD = 467
  /// Move Unaligned Packed Single Precision Floating-Point Values.
  | MOVUPS = 468
  /// Move With Zero-Extend.
  | MOVZX = 469
  /// Compute Multiple Packed Sums of Absolute Difference.
  | MPSADBW = 470
  /// Unsigned Multiply.
  | MUL = 471
  /// Multiply Packed Double Precision Floating-Point Values.
  | MULPD = 472
  /// Multiply Packed Single Precision Floating-Point Values.
  | MULPS = 473
  /// Multiply Scalar Double Precision Floating-Point Value.
  | MULSD = 474
  /// Multiply Scalar Single Precision Floating-Point Values.
  | MULSS = 475
  /// Unsigned Multiply Without Affecting Flags.
  | MULX = 476
  /// Monitor Wait.
  | MWAIT = 477
  /// Two's Complement Negation.
  | NEG = 478
  /// No Operation.
  | NOP = 479
  /// One's Complement Negation.
  | NOT = 480
  /// Logical Inclusive OR.
  | OR = 481
  /// Bitwise Logical OR of Packed Double Precision Floating-Point Values.
  | ORPD = 482
  /// Bitwise Logical OR of Packed Single Precision Floating-Point Values.
  | ORPS = 483
  /// Output to Port.
  | OUT = 484
  /// Output String to Port.
  | OUTS = 485
  /// Output String to Port.
  | OUTSB = 486
  /// Output String to Port.
  | OUTSD = 487
  /// Output String to Port.
  | OUTSW = 488
  /// Packed Absolute Value.
  | PABSB = 489
  /// Packed Absolute Value.
  | PABSD = 490
  /// Packed Absolute Value.
  | PABSW = 491
  /// Pack With Signed Saturation.
  | PACKSSDW = 492
  /// Pack With Signed Saturation.
  | PACKSSWB = 493
  /// Pack With Unsigned Saturation.
  | PACKUSDW = 494
  /// Pack With Unsigned Saturation.
  | PACKUSWB = 495
  /// Add Packed Integers.
  | PADDB = 496
  /// Add Packed Integers.
  | PADDD = 497
  /// Add Packed Integers.
  | PADDQ = 498
  /// Add Packed Signed Integers with Signed Saturation.
  | PADDSB = 499
  /// Add Packed Signed Integers with Signed Saturation.
  | PADDSW = 500
  /// Add Packed Unsigned Integers With Unsigned Saturation.
  | PADDUSB = 501
  /// Add Packed Unsigned Integers With Unsigned Saturation.
  | PADDUSW = 502
  /// Add Packed Integers.
  | PADDW = 503
  /// Packed Align Right.
  | PALIGNR = 504
  /// Logical AND.
  | PAND = 505
  /// Logical AND NOT.
  | PANDN = 506
  /// Spin Loop Hint.
  | PAUSE = 507
  /// Average Packed Integers.
  | PAVGB = 508
  /// Average Packed Integers.
  | PAVGW = 509
  /// Variable Blend Packed Bytes.
  | PBLENDVB = 510
  /// Blend Packed Words.
  | PBLENDW = 511
  /// Carry-Less Multiplication Quadword.
  | PCLMULQDQ = 512
  /// Compare Packed Data for Equal.
  | PCMPEQB = 513
  /// Compare Packed Data for Equal.
  | PCMPEQD = 514
  /// Compare Packed Qword Data for Equal.
  | PCMPEQQ = 515
  /// Compare Packed Data for Equal.
  | PCMPEQW = 516
  /// Packed Compare Explicit Length Strings, Return Index.
  | PCMPESTRI = 517
  /// Packed Compare Explicit Length Strings, Return Mask.
  | PCMPESTRM = 518
  /// Compare Packed Signed Integers for Greater Than.
  | PCMPGTB = 519
  /// Compare Packed Signed Integers for Greater Than.
  | PCMPGTD = 520
  /// Compare Packed Data for Greater Than.
  | PCMPGTQ = 521
  /// Compare Packed Signed Integers for Greater Than.
  | PCMPGTW = 522
  /// Packed Compare Implicit Length Strings, Return Index.
  | PCMPISTRI = 523
  /// Packed Compare Implicit Length Strings, Return Mask.
  | PCMPISTRM = 524
  /// Platform Configuration.
  | PCONFIG = 525
  /// Parallel Bits Deposit.
  | PDEP = 526
  /// Parallel Bits Extract.
  | PEXT = 527
  /// Extract Byte/Dword/Qword.
  | PEXTRB = 528
  /// Extract Byte/Dword/Qword.
  | PEXTRD = 529
  /// Extract Byte/Dword/Qword.
  | PEXTRQ = 530
  /// Extract Word.
  | PEXTRW = 531
  /// Packed Horizontal Add.
  | PHADDD = 532
  /// Packed Horizontal Add and Saturate.
  | PHADDSW = 533
  /// Packed Horizontal Add.
  | PHADDW = 534
  /// Packed Horizontal Word Minimum.
  | PHMINPOSUW = 535
  /// Packed Horizontal Subtract.
  | PHSUBD = 536
  /// Packed Horizontal Subtract and Saturate.
  | PHSUBSW = 537
  /// Packed Horizontal Subtract.
  | PHSUBW = 538
  /// Insert Byte/Dword/Qword.
  | PINSRB = 539
  /// Insert Byte/Dword/Qword.
  | PINSRD = 540
  /// Insert Byte/Dword/Qword.
  | PINSRQ = 541
  /// Insert Word.
  | PINSRW = 542
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | PMADDUBSW = 543
  /// Multiply and Add Packed Integers.
  | PMADDWD = 544
  /// Maximum of Packed Signed Integers.
  | PMAXSB = 545
  /// Maximum of Packed Signed Integers.
  | PMAXSD = 546
  /// Maximum of Packed Signed Integers.
  | PMAXSW = 547
  /// Maximum of Packed Unsigned Integers.
  | PMAXUB = 548
  /// Maximum of Packed Unsigned Integers.
  | PMAXUD = 549
  /// Maximum of Packed Unsigned Integers.
  | PMAXUW = 550
  /// Minimum of Packed Signed Integers.
  | PMINSB = 551
  /// Minimum of Packed Signed Integers.
  | PMINSD = 552
  /// Minimum of Packed Signed Integers.
  | PMINSW = 553
  /// Minimum of Packed Unsigned Integers.
  | PMINUB = 554
  /// Minimum of Packed Unsigned Integers.
  | PMINUD = 555
  /// Minimum of Packed Unsigned Integers.
  | PMINUW = 556
  /// Move Byte Mask.
  | PMOVMSKB = 557
  /// Packed Move With Sign Extend.
  | PMOVSXBD = 558
  /// Packed Move With Sign Extend.
  | PMOVSXBQ = 559
  /// Packed Move With Sign Extend.
  | PMOVSXBW = 560
  /// Packed Move With Sign Extend.
  | PMOVSXDQ = 561
  /// Packed Move With Sign Extend.
  | PMOVSXWD = 562
  /// Packed Move With Sign Extend.
  | PMOVSXWQ = 563
  /// Packed Move With Zero Extend.
  | PMOVZXBD = 564
  /// Packed Move With Zero Extend.
  | PMOVZXBQ = 565
  /// Packed Move With Zero Extend.
  | PMOVZXBW = 566
  /// Packed Move With Zero Extend.
  | PMOVZXDQ = 567
  /// Packed Move With Zero Extend.
  | PMOVZXWD = 568
  /// Packed Move With Zero Extend.
  | PMOVZXWQ = 569
  /// Multiply Packed Doubleword Integers.
  | PMULDQ = 570
  /// Packed Multiply High With Round and Scale.
  | PMULHRSW = 571
  /// Multiply Packed Unsigned Integers and Store High Result.
  | PMULHUW = 572
  /// Multiply Packed Signed Integers and Store High Result.
  | PMULHW = 573
  /// Multiply Packed Integers and Store Low Result.
  | PMULLD = 574
  /// Multiply Packed Signed Integers and Store Low Result.
  | PMULLW = 575
  /// Multiply Packed Unsigned Doubleword Integers.
  | PMULUDQ = 576
  /// Pop a Value From the Stack.
  | POP = 577
  /// Pop All General-Purpose Registers.
  | POPA = 578
  /// Pop All General-Purpose Registers.
  | POPAD = 579
  /// Return the Count of Number of Bits Set to 1.
  | POPCNT = 580
  /// Pop Stack Into EFLAGS Register.
  | POPF = 581
  /// Pop Stack Into EFLAGS Register.
  | POPFD = 582
  /// Pop Stack Into EFLAGS Register.
  | POPFQ = 583
  /// Bitwise Logical OR.
  | POR = 584
  /// Prefetch Data Into Caches.
  | PREFETCHIT0 = 585
  /// Prefetch Data Into Caches.
  | PREFETCHIT1 = 586
  /// Prefetch Data Into Caches.
  | PREFETCHNTA = 587
  /// Prefetch Data Into Caches.
  | PREFETCHT0 = 588
  /// Prefetch Data Into Caches.
  | PREFETCHT1 = 589
  /// Prefetch Data Into Caches.
  | PREFETCHT2 = 590
  /// Prefetch Data Into Caches in Anticipation of a Write.
  | PREFETCHW = 591
  /// Prefetch Vector Data Into Caches With Intent to Write and T1 Hint.
  | PREFETCHWT1 = 592
  /// Compute Sum of Absolute Differences.
  | PSADBW = 593
  /// Packed Shuffle Bytes.
  | PSHUFB = 594
  /// Shuffle Packed Doublewords.
  | PSHUFD = 595
  /// Shuffle Packed High Words.
  | PSHUFHW = 596
  /// Shuffle Packed Low Words.
  | PSHUFLW = 597
  /// Shuffle Packed Words.
  | PSHUFW = 598
  /// Packed SIGN.
  | PSIGNB = 599
  /// Packed SIGN.
  | PSIGND = 600
  /// Packed SIGN.
  | PSIGNW = 601
  /// Shift Packed Data Left Logical.
  | PSLLD = 602
  /// Shift Double Quadword Left Logical.
  | PSLLDQ = 603
  /// Shift Packed Data Left Logical.
  | PSLLQ = 604
  /// Shift Packed Data Left Logical.
  | PSLLW = 605
  /// Shift Packed Data Right Arithmetic.
  | PSRAD = 606
  /// Shift Packed Data Right Arithmetic.
  | PSRAW = 607
  /// Shift Packed Data Right Logical.
  | PSRLD = 608
  /// Shift Double Quadword Right Logical.
  | PSRLDQ = 609
  /// Shift Packed Data Right Logical.
  | PSRLQ = 610
  /// Shift Packed Data Right Logical.
  | PSRLW = 611
  /// Subtract Packed Integers.
  | PSUBB = 612
  /// Subtract Packed Integers.
  | PSUBD = 613
  /// Subtract Packed Quadword Integers.
  | PSUBQ = 614
  /// Subtract Packed Signed Integers With Signed Saturation.
  | PSUBSB = 615
  /// Subtract Packed Signed Integers With Signed Saturation.
  | PSUBSW = 616
  /// Subtract Packed Unsigned Integers With Unsigned Saturation.
  | PSUBUSB = 617
  /// Subtract Packed Unsigned Integers With Unsigned Saturation.
  | PSUBUSW = 618
  /// Subtract Packed Integers.
  | PSUBW = 619
  /// Logical Compare.
  | PTEST = 620
  /// Write Data to a Processor Trace Packet.
  | PTWRITE = 621
  /// Unpack High Data.
  | PUNPCKHBW = 622
  /// Unpack High Data.
  | PUNPCKHDQ = 623
  /// Unpack High Data.
  | PUNPCKHQDQ = 624
  /// Unpack High Data.
  | PUNPCKHWD = 625
  /// Unpack Low Data.
  | PUNPCKLBW = 626
  /// Unpack Low Data.
  | PUNPCKLDQ = 627
  /// Unpack Low Data.
  | PUNPCKLQDQ = 628
  /// Unpack Low Data.
  | PUNPCKLWD = 629
  /// Push Word, Doubleword, or Quadword Onto the Stack.
  | PUSH = 630
  /// Push All General-Purpose Registers.
  | PUSHA = 631
  /// Push All General-Purpose Registers.
  | PUSHAD = 632
  /// Push EFLAGS Register Onto the Stack.
  | PUSHF = 633
  /// Push EFLAGS Register Onto the Stack.
  | PUSHFD = 634
  /// Push EFLAGS Register Onto the Stack.
  | PUSHFQ = 635
  /// Logical Exclusive OR.
  | PXOR = 636
  /// Rotate.
  | RCL = 637
  /// Compute Reciprocals of Packed Single Precision Floating-Point Values.
  | RCPPS = 638
  /// Compute Reciprocal of Scalar Single Precision Floating-Point Values.
  | RCPSS = 639
  /// Rotate.
  | RCR = 640
  /// Read FS/GS Segment Base.
  | RDFSBASE = 641
  /// Read FS/GS Segment Base.
  | RDGSBASE = 642
  /// Read From Model Specific Register.
  | RDMSR = 643
  /// Read List of Model Specific Registers.
  | RDMSRLIST = 644
  /// Read Processor ID.
  | RDPID = 645
  /// Read Protection Key Rights for User Pages.
  | RDPKRU = 646
  /// Read Performance-Monitoring Counters.
  | RDPMC = 647
  /// Read Random Number.
  | RDRAND = 648
  /// Read Random SEED.
  | RDSEED = 649
  /// Read Shadow Stack Pointer.
  | RDSSPD = 650
  /// Read Shadow Stack Pointer.
  | RDSSPQ = 651
  /// Read Time-Stamp Counter.
  | RDTSC = 652
  /// Read Time-Stamp Counter and Processor ID.
  | RDTSCP = 653
  /// Return From Procedure.
  | RET = 654
  /// Rotate.
  | ROL = 655
  /// Rotate.
  | ROR = 656
  /// Rotate Right Logical Without Affecting Flags.
  | RORX = 657
  /// Round Packed Double Precision Floating-Point Values.
  | ROUNDPD = 658
  /// Round Packed Single Precision Floating-Point Values.
  | ROUNDPS = 659
  /// Round Scalar Double Precision Floating-Point Values.
  | ROUNDSD = 660
  /// Round Scalar Single Precision Floating-Point Values.
  | ROUNDSS = 661
  /// Resume From System Management Mode.
  | RSM = 662
  /// Compute Reciprocals of Square Roots of Packed Single Precision
  /// Floating-Point Values.
  | RSQRTPS = 663
  /// Compute Reciprocal of Square Root of Scalar Single Precision
  /// Floating-Point Value.
  | RSQRTSS = 664
  /// Restore Saved Shadow Stack Pointer.
  | RSTORSSP = 665
  /// Store AH Into Flags.
  | SAHF = 666
  /// Shift.
  | SHL = 667
  | SAL = 667
  /// Shift.
  | SAR = 668
  /// Shift Without Affecting Flags.
  | SARX = 669
  /// Save Previous Shadow Stack Pointer.
  | SAVEPREVSSP = 670
  /// Integer Subtraction With Borrow.
  | SBB = 671
  /// Scan String.
  | SCAS = 672
  /// Scan String.
  | SCASB = 673
  /// Scan String.
  | SCASD = 674
  /// Scan String.
  | SCASQ = 675
  /// Scan String.
  | SCASW = 676
  /// Send User Interprocessor Interrupt.
  | SENDUIPI = 677
  /// Serialize Instruction Execution.
  | SERIALIZE = 678
  /// Set Byte on Condition.
  | SETA = 679
  /// Set Byte on Condition.
  | SETAE = 680
  /// Set Byte on Condition.
  | SETB = 681
  /// Set Byte on Condition.
  | SETBE = 682
  /// Set Byte on Condition.
  | SETC = 683
  /// Set Byte on Condition.
  | SETE = 684
  /// Set Byte on Condition.
  | SETG = 685
  /// Set Byte on Condition.
  | SETGE = 686
  /// Set Byte on Condition.
  | SETL = 687
  /// Set Byte on Condition.
  | SETLE = 688
  /// Set Byte on Condition.
  | SETNA = 689
  /// Set Byte on Condition.
  | SETNAE = 690
  /// Set Byte on Condition.
  | SETNB = 691
  /// Set Byte on Condition.
  | SETNBE = 692
  /// Set Byte on Condition.
  | SETNC = 693
  /// Set Byte on Condition.
  | SETNE = 694
  /// Set Byte on Condition.
  | SETNG = 695
  /// Set Byte on Condition.
  | SETNGE = 696
  /// Set Byte on Condition.
  | SETNL = 697
  /// Set Byte on Condition.
  | SETNLE = 698
  /// Set Byte on Condition.
  | SETNO = 699
  /// Set Byte on Condition.
  | SETNP = 700
  /// Set Byte on Condition.
  | SETNS = 701
  /// Set Byte on Condition.
  | SETNZ = 702
  /// Set Byte on Condition.
  | SETO = 703
  /// Set Byte on Condition.
  | SETP = 704
  /// Set Byte on Condition.
  | SETPE = 705
  /// Set Byte on Condition.
  | SETPO = 706
  /// Set Byte on Condition.
  | SETS = 707
  /// Mark Shadow Stack Busy.
  | SETSSBSY = 708
  /// Set Byte on Condition.
  | SETZ = 709
  /// Store Fence.
  | SFENCE = 710
  /// Store Global Descriptor Table Register.
  | SGDT = 711
  /// Perform an Intermediate Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG1 = 712
  /// Perform a Final Calculation for the Next Four SHA1 Message Dwords.
  | SHA1MSG2 = 713
  /// Calculate SHA1 State Variable E After Four Rounds.
  | SHA1NEXTE = 714
  /// Perform Four Rounds of SHA1 Operation.
  | SHA1RNDS4 = 715
  /// Perform an Intermediate Calculation for the Next Four SHA256 Message
  /// Dwords.
  | SHA256MSG1 = 716
  /// Perform a Final Calculation for the Next Four SHA256 Message Dwords.
  | SHA256MSG2 = 717
  /// Perform Two Rounds of SHA256 Operation.
  | SHA256RNDS2 = 718
  /// Double Precision Shift Left.
  | SHLD = 719
  /// Shift Without Affecting Flags.
  | SHLX = 720
  /// Shift.
  | SHR = 721
  /// Double Precision Shift Right.
  | SHRD = 722
  /// Shift Without Affecting Flags.
  | SHRX = 723
  /// Packed Interleave Shuffle of Pairs of Double Precision Floating-Point
  /// Values.
  | SHUFPD = 724
  /// Packed Interleave Shuffle of Quadruplets of Single Precision
  /// Floating-Point Values.
  | SHUFPS = 725
  /// Store Interrupt Descriptor Table Register.
  | SIDT = 726
  /// Store Local Descriptor Table Register.
  | SLDT = 727
  /// Chinese national cryptographic algorithms.
  | SM2 = 728
  /// Store Machine Status Word.
  | SMSW = 729
  /// Square Root of Double Precision Floating-Point Values.
  | SQRTPD = 730
  /// Square Root of Single Precision Floating-Point Values.
  | SQRTPS = 731
  /// Compute Square Root of Scalar Double Precision Floating-Point Value.
  | SQRTSD = 732
  /// Compute Square Root of Scalar Single Precision Value.
  | SQRTSS = 733
  /// Set AC Flag in EFLAGS Register.
  | STAC = 734
  /// Set Carry Flag.
  | STC = 735
  /// Set Direction Flag.
  | STD = 736
  /// Set Interrupt Flag.
  | STI = 737
  /// Store MXCSR Register State.
  | STMXCSR = 738
  /// Store String.
  | STOS = 739
  /// Store String.
  | STOSB = 740
  /// Store String.
  | STOSD = 741
  /// Store String.
  | STOSQ = 742
  /// Store String.
  | STOSW = 743
  /// Store Task Register.
  | STR = 744
  /// Store Tile Configuration.
  | STTILECFG = 745
  /// Set User Interrupt Flag.
  | STUI = 746
  /// Subtract.
  | SUB = 747
  /// Subtract Packed Double Precision Floating-Point Values.
  | SUBPD = 748
  /// Subtract Packed Single Precision Floating-Point Values.
  | SUBPS = 749
  /// Subtract Scalar Double Precision Floating-Point Value.
  | SUBSD = 750
  /// Subtract Scalar Single Precision Floating-Point Value.
  | SUBSS = 751
  /// Swap GS Base Register.
  | SWAPGS = 752
  /// Fast System Call.
  | SYSCALL = 753
  /// Fast System Call.
  | SYSENTER = 754
  /// Fast Return from Fast System Call.
  | SYSEXIT = 755
  /// Return From Fast System Call.
  | SYSRET = 756
  /// Dot Product of BF16 Tiles Accumulated into Packed Single Precision Tile.
  | TDPBF16PS = 757
  /// Dot Product of Signed/Unsigned Bytes with Dword Accumulation.
  | TDPBSSD = 758
  /// Dot Product of Signed/Unsigned Bytes with Dword Accumulation.
  | TDPBSUD = 759
  /// Dot Product of Signed/Unsigned Bytes with Dword Accumulation.
  | TDPBUSD = 760
  /// Dot Product of Signed/Unsigned Bytes with Dword Accumulation.
  | TDPBUUD = 761
  /// Dot Product of FP16 Tiles Accumulated into Packed Single Precision Tile.
  | TDPFP16PS = 762
  /// Logical Compare.
  | TEST = 763
  /// Determine User Interrupt Flag.
  | TESTUI = 764
  /// Load Tile.
  | TILELOADD = 765
  /// Load Tile.
  | TILELOADDT1 = 766
  /// Release Tile.
  | TILERELEASE = 767
  /// Store Tile.
  | TILESTORED = 768
  /// Zero Tile.
  | TILEZERO = 769
  /// Timed PAUSE.
  | TPAUSE = 770
  /// Count the Number of Trailing Zero Bits.
  | TZCNT = 771
  /// Unordered Compare Scalar Double Precision Floating-Point Values and Set
  /// EFLAGS.
  | UCOMISD = 772
  /// Unordered Compare Scalar Single Precision Floating-Point Values and Set
  /// EFLAGS.
  | UCOMISS = 773
  /// Undefined Instruction.
  | UD0 = 774
  /// Undefined Instruction.
  | UD1 = 775
  /// Undefined Instruction.
  | UD2 = 776
  /// Undefined Instruction.
  | UDB = 777
  /// User-Interrupt Return.
  | UIRET = 778
  /// User Level Set Up Monitor Address.
  | UMONITOR = 779
  /// User Level Monitor Wait.
  | UMWAIT = 780
  /// Unpack and Interleave High Packed Double Precision Floating-Point Values.
  | UNPCKHPD = 781
  /// Unpack and Interleave High Packed Single Precision Floating-Point Values.
  | UNPCKHPS = 782
  /// Unpack and Interleave Low Packed Double Precision Floating-Point Values.
  | UNPCKLPD = 783
  /// Unpack and Interleave Low Packed Single Precision Floating-Point Values.
  | UNPCKLPS = 784
  /// Packed Single Precision Floating-Point Fused Multiply-Add (4-Iterations).
  | V4FMADDPS = 785
  /// Scalar Single Precision Floating-Point Fused Multiply-Add (4-Iterations).
  | V4FMADDSS = 786
  /// Packed Single Precision Floating-Point Fused Multiply-Add (4-Iterations).
  | V4FNMADDPS = 787
  /// Scalar Single Precision Floating-Point Fused Multiply-Add (4-Iterations).
  | V4FNMADDSS = 788
  /// Add Packed Double Precision Floating-Point Values.
  | VADDPD = 789
  /// Add Packed FP16 Values.
  | VADDPH = 790
  /// Add Packed Single Precision Floating-Point Values.
  | VADDPS = 791
  /// Add Scalar Double Precision Floating-Point Values.
  | VADDSD = 792
  /// Add Scalar FP16 Values.
  | VADDSH = 793
  /// Add Scalar Single Precision Floating-Point Values.
  | VADDSS = 794
  /// Packed Double Precision Floating-Point Add/Subtract.
  | VADDSUBPD = 795
  /// Packed Single Precision Floating-Point Add/Subtract.
  | VADDSUBPS = 796
  /// Perform One Round of an AES Decryption Flow.
  | VAESDEC = 797
  /// Perform Last Round of an AES Decryption Flow.
  | VAESDECLAST = 798
  /// Perform One Round of an AES Encryption Flow.
  | VAESENC = 799
  /// Perform Last Round of an AES Encryption Flow.
  | VAESENCLAST = 800
  /// Perform the AES InvMixColumn Transformation.
  | VAESIMC = 801
  /// AES Round Key Generation Assist.
  | VAESKEYGENASSIST = 802
  /// Align Doubleword/Quadword Vectors.
  | VALIGND = 803
  /// Align Doubleword/Quadword Vectors.
  | VALIGNQ = 804
  /// Bitwise Logical AND NOT of Packed Double Precision Floating-Point Values.
  | VANDNPD = 805
  /// Bitwise Logical AND NOT of Packed Single Precision Floating-Point Values.
  | VANDNPS = 806
  /// Bitwise Logical AND of Packed Double Precision Floating-Point Values.
  | VANDPD = 807
  /// Bitwise Logical AND of Packed Single Precision Floating-Point Values.
  | VANDPS = 808
  /// Load BF16 Element and Convert to FP32 Element With Broadcast.
  | VBCSTNEBF162PS = 809
  /// Load FP16 Element and Convert to FP32 Element with Broadcast.
  | VBCSTNESH2PS = 810
  /// Blend Float64/Float32 Vectors Using an OpMask Control.
  | VBLENDMPD = 811
  /// Blend Float64/Float32 Vectors Using an OpMask Control.
  | VBLENDMPS = 812
  /// Blend Packed Double Precision Floating-Point Values.
  | VBLENDPD = 813
  /// Blend Packed Single Precision Floating-Point Values.
  | VBLENDPS = 814
  /// Variable Blend Packed Double Precision Floating-Point Values.
  | VBLENDVPD = 815
  /// Variable Blend Packed Single Precision Floating-Point Values.
  | VBLENDVPS = 816
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF128 = 817
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF32X2 = 818
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF32X4 = 819
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF32X8 = 820
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF64X2 = 821
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTF64X4 = 822
  /// Load Integer and Broadcast.
  | VBROADCASTI128 = 823
  /// Load Integer and Broadcast.
  | VBROADCASTI32X2 = 824
  /// Load Integer and Broadcast.
  | VBROADCASTI32X4 = 825
  /// Load Integer and Broadcast.
  | VBROADCASTI32X8 = 826
  /// Load Integer and Broadcast.
  | VBROADCASTI64X2 = 827
  /// Load Integer and Broadcast.
  | VBROADCASTI64X4 = 828
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTSD = 829
  /// Load with Broadcast Floating-Point Data.
  | VBROADCASTSS = 830
  /// Compare Packed Double Precision Floating-Point Values.
  | VCMPPD = 831
  /// Compare Packed FP16 Values.
  | VCMPPH = 832
  /// Compare Packed Single Precision Floating-Point Values.
  | VCMPPS = 833
  /// Compare Scalar Double Precision Floating-Point Value.
  | VCMPSD = 834
  /// Compare Scalar FP16 Values.
  | VCMPSH = 835
  /// Compare Scalar Single Precision Floating-Point Value.
  | VCMPSS = 836
  /// Compare Scalar Ordered Double Precision Floating-Point Values and Set
  /// EFLAGS.
  | VCOMISD = 837
  /// Compare Scalar Ordered FP16 Values and Set EFLAGS.
  | VCOMISH = 838
  /// Compare Scalar Ordered Single Precision Floating-Point Values and Set
  /// EFLAGS.
  | VCOMISS = 839
  /// Store Sparse Packed Double Precision Floating-Point Values Into Dense
  /// Memory.
  | VCOMPRESSPD = 840
  /// Store Sparse Packed Single Precision Floating-Point Values Into Dense
  /// Memory.
  | VCOMPRESSPS = 841
  /// Convert Packed Doubleword Integers to Packed Double Precision
  /// Floating-Point Values.
  | VCVTDQ2PD = 842
  /// Convert Packed Signed Doubleword Integers to Packed FP16 Values.
  | VCVTDQ2PH = 843
  /// Convert Packed Doubleword Integers to Packed Single Precision
  /// Floating-Point Values.
  | VCVTDQ2PS = 844
  /// Convert Two Packed Single Data to One Packed BF16 Data.
  | VCVTNE2PS2BF16 = 845
  /// Convert Even Elements of Packed BF16 Values to FP32 Values.
  | VCVTNEEBF162PS = 846
  /// Convert Even Elements of Packed FP16 Values to FP32 Values.
  | VCVTNEEPH2PS = 847
  /// Convert Odd Elements of Packed BF16 Values to FP32 Values.
  | VCVTNEOBF162PS = 848
  /// Convert Odd Elements of Packed FP16 Values to FP32 Values.
  | VCVTNEOPH2PS = 849
  /// Convert Packed Single Data to Packed BF16 Data.
  | VCVTNEPS2BF16 = 850
  /// Convert Packed Double Precision Floating-Point Values to Packed Doubleword
  /// Integers.
  | VCVTPD2DQ = 851
  /// Convert Packed Double Precision FP Values to Packed FP16 Values.
  | VCVTPD2PH = 852
  /// Convert Packed Double Precision Floating-Point Values to Packed Single
  /// Precision Floating-Point Values.
  | VCVTPD2PS = 853
  /// Convert Packed Double Precision Floating-Point Values to Packed Quadword
  /// Integers.
  | VCVTPD2QQ = 854
  /// Convert Packed Double Precision Floating-Point Values to Packed Unsigned
  /// Doubleword Integers.
  | VCVTPD2UDQ = 855
  /// Convert Packed Double Precision Floating-Point Values to Packed Unsigned
  /// Quadword Integers.
  | VCVTPD2UQQ = 856
  /// Convert Packed FP16 Values to Signed Doubleword Integers.
  | VCVTPH2DQ = 857
  /// Convert Packed FP16 Values to FP64 Values.
  | VCVTPH2PD = 858
  /// Convert Packed FP16 Values to Single Precision Floating-Point Values.
  | VCVTPH2PS = 859
  /// Convert Packed FP16 Values to Single Precision Floating-Point Values.
  | VCVTPH2PSX = 860
  /// Convert Packed FP16 Values to Signed Quadword Integer Values.
  | VCVTPH2QQ = 861
  /// Convert Packed FP16 Values to Unsigned Doubleword Integers.
  | VCVTPH2UDQ = 862
  /// Convert Packed FP16 Values to Unsigned Quadword Integers.
  | VCVTPH2UQQ = 863
  /// Convert Packed FP16 Values to Unsigned Word Integers.
  | VCVTPH2UW = 864
  /// Convert Packed FP16 Values to Signed Word Integers.
  | VCVTPH2W = 865
  /// Convert Packed Single Precision Floating-Point Values to Packed Signed
  /// Doubleword Integer Values.
  | VCVTPS2DQ = 866
  /// Convert Packed Single Precision Floating-Point Values to Packed Double
  /// Precision Floating-Point Values.
  | VCVTPS2PD = 867
  /// Convert Single Precision FP Value to 16-bit FP Value.
  | VCVTPS2PH = 868
  /// Convert Packed Single Precision Floating-Point Values to Packed FP16
  /// Values.
  | VCVTPS2PHX = 869
  /// Convert Packed Single Precision Floating-Point Values to Packed Signed
  /// Quadword Integer Values.
  | VCVTPS2QQ = 870
  /// Convert Packed Single Precision Floating-Point Values to Packed Unsigned
  /// Doubleword Integer Values.
  | VCVTPS2UDQ = 871
  /// Convert Packed Single Precision Floating-Point Values to Packed Unsigned
  /// Quadword Integer Values.
  | VCVTPS2UQQ = 872
  /// Convert Packed Quadword Integers to Packed Double Precision Floating-Point
  /// Values.
  | VCVTQQ2PD = 873
  /// Convert Packed Signed Quadword Integers to Packed FP16 Values.
  | VCVTQQ2PH = 874
  /// Convert Packed Quadword Integers to Packed Single Precision Floating-Point
  /// Values.
  | VCVTQQ2PS = 875
  /// Convert Low FP64 Value to an FP16 Value.
  | VCVTSD2SH = 876
  /// Convert Scalar Double Precision Floating-Point Value to Signed Integer.
  | VCVTSD2SI = 877
  /// Convert Scalar Double Precision Floating-Point Value to Scalar Single
  /// Precision Floating-Point Value.
  | VCVTSD2SS = 878
  /// Convert Scalar Double Precision Floating-Point Value to Unsigned Integer.
  | VCVTSD2USI = 879
  /// Convert Low FP16 Value to an FP64 Value.
  | VCVTSH2SD = 880
  /// Convert Low FP16 Value to Signed Integer.
  | VCVTSH2SI = 881
  /// Convert Low FP16 Value to FP32 Value.
  | VCVTSH2SS = 882
  /// Convert Low FP16 Value to Unsigned Integer.
  | VCVTSH2USI = 883
  /// Convert Signed Integer to Scalar Double Precision Floating-Point Value.
  | VCVTSI2SD = 884
  /// Convert a Signed Doubleword/Quadword Integer to an FP16 Value.
  | VCVTSI2SH = 885
  /// Convert Signed Integer to Scalar Single Precision Floating-Point Value.
  | VCVTSI2SS = 886
  /// Convert Scalar Single Precision Floating-Point Value to Scalar Double
  /// Precision Floating-Point Value.
  | VCVTSS2SD = 887
  /// Convert Low FP32 Value to an FP16 Value.
  | VCVTSS2SH = 888
  /// Convert Scalar Single Precision Floating-Point Value to Signed Integer.
  | VCVTSS2SI = 889
  /// Convert Scalar Single Precision Floating-Point Value to Unsigned
  /// Doubleword Integer.
  | VCVTSS2USI = 890
  /// Convert with Truncation Packed Double Precision Floating-Point Values to
  /// Packed Doubleword Integers.
  | VCVTTPD2DQ = 891
  /// Convert With Truncation Packed Double Precision Floating-Point Values to
  /// Packed Quadword Integers.
  | VCVTTPD2QQ = 892
  /// Convert With Truncation Packed Double Precision Floating-Point Values to
  /// Packed Unsigned Doubleword Integers.
  | VCVTTPD2UDQ = 893
  /// Convert With Truncation Packed Double Precision Floating-Point Values to
  /// Packed Unsigned Quadword Integers.
  | VCVTTPD2UQQ = 894
  /// Convert with Truncation Packed FP16 Values to Signed Doubleword Integers.
  | VCVTTPH2DQ = 895
  /// Convert with Truncation Packed FP16 Values to Signed Quadword Integers.
  | VCVTTPH2QQ = 896
  /// Convert with Truncation Packed FP16 Values to Unsigned Doubleword
  /// Integers.
  | VCVTTPH2UDQ = 897
  /// Convert with Truncation Packed FP16 Values to Unsigned Quadword Integers.
  | VCVTTPH2UQQ = 898
  /// Convert Packed FP16 Values to Unsigned Word Integers.
  | VCVTTPH2UW = 899
  /// Convert Packed FP16 Values to Signed Word Integers.
  | VCVTTPH2W = 900
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Signed Doubleword Integer Values.
  | VCVTTPS2DQ = 901
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Signed Quadword Integer Values.
  | VCVTTPS2QQ = 902
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Unsigned Doubleword Integer Values.
  | VCVTTPS2UDQ = 903
  /// Convert With Truncation Packed Single Precision Floating-Point Values to
  /// Packed Unsigned Quadword Integer Values.
  | VCVTTPS2UQQ = 904
  /// Convert With Truncation Scalar Double Precision Floating-Point Value to
  /// Signed Integer.
  | VCVTTSD2SI = 905
  /// Convert With Truncation Scalar Double Precision Floating-Point Value to
  /// Unsigned Integer.
  | VCVTTSD2USI = 906
  /// Convert with Truncation Low FP16 Value to a Signed Integer.
  | VCVTTSH2SI = 907
  /// Convert with Truncation Low FP16 Value to an Unsigned Integer.
  | VCVTTSH2USI = 908
  /// Convert With Truncation Scalar Single Precision Floating-Point Value to
  /// Signed Integer.
  | VCVTTSS2SI = 909
  /// Convert With Truncation Scalar Single Precision Floating-Point Value to
  /// Unsigned Integer.
  | VCVTTSS2USI = 910
  /// Convert Packed Unsigned Doubleword Integers to Packed Double Precision
  /// Floating-Point Values.
  | VCVTUDQ2PD = 911
  /// Convert Packed Unsigned Doubleword Integers to Packed FP16 Values.
  | VCVTUDQ2PH = 912
  /// Convert Packed Unsigned Doubleword Integers to Packed Single Precision
  /// Floating-Point Values.
  | VCVTUDQ2PS = 913
  /// Convert Packed Unsigned Quadword Integers to Packed Double Precision
  /// Floating-Point Values.
  | VCVTUQQ2PD = 914
  /// Convert Packed Unsigned Quadword Integers to Packed FP16 Values.
  | VCVTUQQ2PH = 915
  /// Convert Packed Unsigned Quadword Integers to Packed Single Precision
  /// Floating-Point Values.
  | VCVTUQQ2PS = 916
  /// Convert Unsigned Integer to Scalar Double Precision Floating-Point Value.
  | VCVTUSI2SD = 917
  /// Convert Unsigned Doubleword Integer to an FP16 Value.
  | VCVTUSI2SH = 918
  /// Convert Unsigned Integer to Scalar Single Precision Floating-Point Value.
  | VCVTUSI2SS = 919
  /// Convert Packed Unsigned Word Integers to FP16 Values.
  | VCVTUW2PH = 920
  /// Convert Packed Signed Word Integers to FP16 Values.
  | VCVTW2PH = 921
  /// Double Block Packed Sum-Absolute-Differences (SAD) on Unsigned Bytes.
  | VDBPSADBW = 922
  /// Divide Packed Double Precision Floating-Point Values.
  | VDIVPD = 923
  /// Divide Packed FP16 Values.
  | VDIVPH = 924
  /// Divide Packed Single Precision Floating-Point Values.
  | VDIVPS = 925
  /// Divide Scalar Double Precision Floating-Point Value.
  | VDIVSD = 926
  /// Divide Scalar FP16 Values.
  | VDIVSH = 927
  /// Divide Scalar Single Precision Floating-Point Values.
  | VDIVSS = 928
  /// Dot Product of BF16 Pairs Accumulated Into Packed Single Precision.
  | VDPBF16PS = 929
  /// Dot Product of Packed Double Precision Floating-Point Values.
  | VDPPD = 930
  /// Dot Product of Packed Single Precision Floating-Point Values.
  | VDPPS = 931
  /// Verify a Segment for Reading or Writing.
  | VERR = 932
  /// Verify a Segment for Reading or Writing.
  | VERW = 933
  /// Approximation to the Exponential 2^x of Packed Double Precision
  /// Floating-Point Values With Less Than 2^-23 Relative Error.
  | VEXP2PD = 934
  /// Approximation to the Exponential 2^x of Packed Single Precision
  /// Floating-Point Values With Less Than 2^-23 Relative Error.
  | VEXP2PS = 935
  /// Load Sparse Packed Double Precision Floating-Point Values From Dense
  /// Memory.
  | VEXPANDPD = 936
  /// Load Sparse Packed Single Precision Floating-Point Values From Dense
  /// Memory.
  | VEXPANDPS = 937
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF128 = 938
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF32X4 = 939
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF32X8 = 940
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF64X2 = 941
  /// Extract Packed Floating-Point Values.
  | VEXTRACTF64X4 = 942
  /// Extract Packed Integer Values.
  | VEXTRACTI128 = 943
  /// Extract Packed Integer Values.
  | VEXTRACTI32X4 = 944
  /// Extract Packed Integer Values.
  | VEXTRACTI32X8 = 945
  /// Extract Packed Integer Values.
  | VEXTRACTI64X2 = 946
  /// Extract Packed Integer Values.
  | VEXTRACTI64X4 = 947
  /// Extract Packed Floating-Point Values.
  | VEXTRACTPS = 948
  /// Complex Multiply and Accumulate FP16 Values.
  | VFCMADDCPH = 949
  /// Complex Multiply and Accumulate Scalar FP16 Values.
  | VFCMADDCSH = 950
  /// Complex Multiply FP16 Values.
  | VFCMULCPH = 951
  /// Complex Multiply Scalar FP16 Values.
  | VFCMULCSH = 952
  /// Fix Up Special Packed Float64 Values.
  | VFIXUPIMMPD = 953
  /// Fix Up Special Packed Float32 Values.
  | VFIXUPIMMPS = 954
  /// Fix Up Special Scalar Float64 Value.
  | VFIXUPIMMSD = 955
  /// Fix Up Special Scalar Float32 Value.
  | VFIXUPIMMSS = 956
  /// Fused Multiply-Add of Packed Double Precision Floating-Point Values.
  | VFMADD132PD = 957
  /// Fused Multiply-Add of Packed FP16 Values.
  | VFMADD132PH = 958
  /// Fused Multiply-Add of Packed Single Precision Floating-Point Values.
  | VFMADD132PS = 959
  /// Fused Multiply-Add of Scalar Double Precision Floating-Point Values.
  | VFMADD132SD = 960
  /// Fused Multiply-Add of Scalar FP16 Values.
  | VFMADD132SH = 961
  /// Fused Multiply-Add of Scalar Single Precision Floating-Point Values.
  | VFMADD132SS = 962
  /// Fused Multiply-Add of Packed Double Precision Floating-Point Values.
  | VFMADD213PD = 963
  /// Fused Multiply-Add of Packed FP16 Values.
  | VFMADD213PH = 964
  /// Fused Multiply-Add of Packed Single Precision Floating-Point Values.
  | VFMADD213PS = 965
  /// Fused Multiply-Add of Scalar Double Precision Floating-Point Values.
  | VFMADD213SD = 966
  /// Fused Multiply-Add of Scalar FP16 Values.
  | VFMADD213SH = 967
  /// Fused Multiply-Add of Scalar Single Precision Floating-Point Values.
  | VFMADD213SS = 968
  /// Fused Multiply-Add of Packed Double Precision Floating-Point Values.
  | VFMADD231PD = 969
  /// Fused Multiply-Add of Packed FP16 Values.
  | VFMADD231PH = 970
  /// Fused Multiply-Add of Packed Single Precision Floating-Point Values.
  | VFMADD231PS = 971
  /// Fused Multiply-Add of Scalar Double Precision Floating-Point Values.
  | VFMADD231SD = 972
  /// Fused Multiply-Add of Scalar FP16 Values.
  | VFMADD231SH = 973
  /// Fused Multiply-Add of Scalar Single Precision Floating-Point Values.
  | VFMADD231SS = 974
  /// Complex Multiply and Accumulate FP16 Values.
  | VFMADDCPH = 975
  /// Complex Multiply and Accumulate Scalar FP16 Values.
  | VFMADDCSH = 976
  /// Multiply and Add Packed Double-Precision Floating-Point(Only AMD).
  | VFMADDPD = 977
  /// Multiply and Add Packed Single-Precision Floating-Point(Only AMD).
  | VFMADDPS = 978
  /// Multiply and Add Scalar Double-Precision Floating-Point(Only AMD).
  | VFMADDSD = 979
  /// Multiply and Add Scalar Single-Precision Floating-Point(Only AMD).
  | VFMADDSS = 980
  /// Fused Multiply-Alternating Add/Subtract of Packed Double Precision
  /// Floating-Point Values.
  | VFMADDSUB132PD = 981
  /// Fused Multiply-Alternating Add/Subtract of Packed FP16 Values.
  | VFMADDSUB132PH = 982
  /// Fused Multiply-Alternating Add/Subtract of Packed Single Precision
  /// Floating-Point Values.
  | VFMADDSUB132PS = 983
  /// Fused Multiply-Alternating Add/Subtract of Packed Double Precision
  /// Floating-Point Values.
  | VFMADDSUB213PD = 984
  /// Fused Multiply-Alternating Add/Subtract of Packed FP16 Values.
  | VFMADDSUB213PH = 985
  /// Fused Multiply-Alternating Add/Subtract of Packed Single Precision
  /// Floating-Point Values.
  | VFMADDSUB213PS = 986
  /// Fused Multiply-Alternating Add/Subtract of Packed Double Precision
  /// Floating-Point Values.
  | VFMADDSUB231PD = 987
  /// Fused Multiply-Alternating Add/Subtract of Packed FP16 Values.
  | VFMADDSUB231PH = 988
  /// Fused Multiply-Alternating Add/Subtract of Packed Single Precision
  /// Floating-Point Values.
  | VFMADDSUB231PS = 989
  /// Fused Multiply-Subtract of Packed Double Precision Floating-Point Values.
  | VFMSUB132PD = 990
  /// Fused Multiply-Subtract of Packed FP16 Values.
  | VFMSUB132PH = 991
  /// Fused Multiply-Subtract of Packed Single Precision Floating-Point Values.
  | VFMSUB132PS = 992
  /// Fused Multiply-Subtract of Scalar Double Precision Floating-Point Values.
  | VFMSUB132SD = 993
  /// Fused Multiply-Subtract of Scalar FP16 Values.
  | VFMSUB132SH = 994
  /// Fused Multiply-Subtract of Scalar Single Precision Floating-Point Values.
  | VFMSUB132SS = 995
  /// Fused Multiply-Subtract of Packed Double Precision Floating-Point Values.
  | VFMSUB213PD = 996
  /// Fused Multiply-Subtract of Packed FP16 Values.
  | VFMSUB213PH = 997
  /// Fused Multiply-Subtract of Packed Single Precision Floating-Point Values.
  | VFMSUB213PS = 998
  /// Fused Multiply-Subtract of Scalar Double Precision Floating-Point Values.
  | VFMSUB213SD = 999
  /// Fused Multiply-Subtract of Scalar FP16 Values.
  | VFMSUB213SH = 1000
  /// Fused Multiply-Subtract of Scalar Single Precision Floating-Point Values.
  | VFMSUB213SS = 1001
  /// Fused Multiply-Subtract of Packed Double Precision Floating-Point Values.
  | VFMSUB231PD = 1002
  /// Fused Multiply-Subtract of Packed FP16 Values.
  | VFMSUB231PH = 1003
  /// Fused Multiply-Subtract of Packed Single Precision Floating-Point Values.
  | VFMSUB231PS = 1004
  /// Fused Multiply-Subtract of Scalar Double Precision Floating-Point Values.
  | VFMSUB231SD = 1005
  /// Fused Multiply-Subtract of Scalar FP16 Values.
  | VFMSUB231SH = 1006
  /// Fused Multiply-Subtract of Scalar Single Precision Floating-Point Values.
  | VFMSUB231SS = 1007
  /// Fused Multiply-Alternating Subtract/Add of Packed Double Precision
  /// Floating-Point Values.
  | VFMSUBADD132PD = 1008
  /// Fused Multiply-Alternating Subtract/Add of Packed FP16 Values.
  | VFMSUBADD132PH = 1009
  /// Fused Multiply-Alternating Subtract/Add of Packed Single Precision
  /// Floating-Point Values.
  | VFMSUBADD132PS = 1010
  /// Fused Multiply-Alternating Subtract/Add of Packed Double Precision
  /// Floating-Point Values.
  | VFMSUBADD213PD = 1011
  /// Fused Multiply-Alternating Subtract/Add of Packed FP16 Values.
  | VFMSUBADD213PH = 1012
  /// Fused Multiply-Alternating Subtract/Add of Packed Single Precision
  /// Floating-Point Values.
  | VFMSUBADD213PS = 1013
  /// Fused Multiply-Alternating Subtract/Add of Packed Double Precision
  /// Floating-Point Values.
  | VFMSUBADD231PD = 1014
  /// Fused Multiply-Alternating Subtract/Add of Packed FP16 Values.
  | VFMSUBADD231PH = 1015
  /// Fused Multiply-Alternating Subtract/Add of Packed Single Precision
  /// Floating-Point Values.
  | VFMSUBADD231PS = 1016
  /// Complex Multiply FP16 Values.
  | VFMULCPH = 1017
  /// Complex Multiply Scalar FP16 Values.
  | VFMULCSH = 1018
  /// Fused Negative Multiply-Add of Packed Double Precision Floating-Point
  /// Values.
  | VFNMADD132PD = 1019
  /// Fused Multiply-Add of Packed FP16 Values.
  | VFNMADD132PH = 1020
  /// Fused Negative Multiply-Add of Packed Single Precision Floating-Point
  /// Values.
  | VFNMADD132PS = 1021
  /// Fused Negative Multiply-Add of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMADD132SD = 1022
  /// Fused Multiply-Add of Scalar FP16 Values.
  | VFNMADD132SH = 1023
  /// Fused Negative Multiply-Add of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMADD132SS = 1024
  /// Fused Negative Multiply-Add of Packed Double Precision Floating-Point
  /// Values.
  | VFNMADD213PD = 1025
  /// Fused Multiply-Add of Packed FP16 Values.
  | VFNMADD213PH = 1026
  /// Fused Negative Multiply-Add of Packed Single Precision Floating-Point
  /// Values.
  | VFNMADD213PS = 1027
  /// Fused Negative Multiply-Add of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMADD213SD = 1028
  /// Fused Multiply-Add of Scalar FP16 Values.
  | VFNMADD213SH = 1029
  /// Fused Negative Multiply-Add of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMADD213SS = 1030
  /// Fused Negative Multiply-Add of Packed Double Precision Floating-Point
  /// Values.
  | VFNMADD231PD = 1031
  /// Fused Multiply-Add of Packed FP16 Values.
  | VFNMADD231PH = 1032
  /// Fused Negative Multiply-Add of Packed Single Precision Floating-Point
  /// Values.
  | VFNMADD231PS = 1033
  /// Fused Negative Multiply-Add of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMADD231SD = 1034
  /// Fused Multiply-Add of Scalar FP16 Values.
  | VFNMADD231SH = 1035
  /// Fused Negative Multiply-Add of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMADD231SS = 1036
  /// Fused Negative Multiply-Subtract of Packed Double Precision Floating-Point
  /// Values.
  | VFNMSUB132PD = 1037
  /// Fused Multiply-Subtract of Packed FP16 Values.
  | VFNMSUB132PH = 1038
  /// Fused Negative Multiply-Subtract of Packed Single Precision Floating-Point
  /// Values.
  | VFNMSUB132PS = 1039
  /// Fused Negative Multiply-Subtract of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMSUB132SD = 1040
  /// Fused Multiply-Subtract of Scalar FP16 Values.
  | VFNMSUB132SH = 1041
  /// Fused Negative Multiply-Subtract of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMSUB132SS = 1042
  /// Fused Negative Multiply-Subtract of Packed Double Precision Floating-Point
  /// Values.
  | VFNMSUB213PD = 1043
  /// Fused Multiply-Subtract of Packed FP16 Values.
  | VFNMSUB213PH = 1044
  /// Fused Negative Multiply-Subtract of Packed Single Precision Floating-Point
  /// Values.
  | VFNMSUB213PS = 1045
  /// Fused Negative Multiply-Subtract of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMSUB213SD = 1046
  /// Fused Multiply-Subtract of Scalar FP16 Values.
  | VFNMSUB213SH = 1047
  /// Fused Negative Multiply-Subtract of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMSUB213SS = 1048
  /// Fused Negative Multiply-Subtract of Packed Double Precision Floating-Point
  /// Values.
  | VFNMSUB231PD = 1049
  /// Fused Multiply-Subtract of Packed FP16 Values.
  | VFNMSUB231PH = 1050
  /// Fused Negative Multiply-Subtract of Packed Single Precision Floating-Point
  /// Values.
  | VFNMSUB231PS = 1051
  /// Fused Negative Multiply-Subtract of Scalar Double Precision Floating-Point
  /// Values.
  | VFNMSUB231SD = 1052
  /// Fused Multiply-Subtract of Scalar FP16 Values.
  | VFNMSUB231SH = 1053
  /// Fused Negative Multiply-Subtract of Scalar Single Precision Floating-Point
  /// Values.
  | VFNMSUB231SS = 1054
  /// Tests Types of Packed Float64 Values.
  | VFPCLASSPD = 1055
  /// Test Types of Packed FP16 Values.
  | VFPCLASSPH = 1056
  /// Tests Types of Packed Float32 Values.
  | VFPCLASSPS = 1057
  /// Tests Type of a Scalar Float64 Value.
  | VFPCLASSSD = 1058
  /// Test Types of Scalar FP16 Values.
  | VFPCLASSSH = 1059
  /// Tests Type of a Scalar Float32 Value.
  | VFPCLASSSS = 1060
  /// Gather Packed Double Precision Floating-Point Values Using Signed
  /// Dword/Qword Indices.
  /// Gather Packed Single, Packed Double with Signed Dword Indices.
  | VGATHERDPD = 1061
  /// Gather Packed Single, Packed Double with Signed Dword Indices.
  /// Gather Packed Single Precision Floating-Point Values Using Signed
  /// Dword/Qword Indices.
  | VGATHERDPS = 1062
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T0 Hint.
  | VGATHERPF0DPD = 1063
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T0 Hint.
  | VGATHERPF0DPS = 1064
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T0 Hint.
  | VGATHERPF0QPD = 1065
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T0 Hint.
  | VGATHERPF0QPS = 1066
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint.
  | VGATHERPF1DPD = 1067
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint.
  | VGATHERPF1DPS = 1068
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint.
  | VGATHERPF1QPD = 1069
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint.
  | VGATHERPF1QPS = 1070
  /// Gather Packed Double Precision Floating-Point Values Using Signed
  /// Dword/Qword Indices.
  /// Gather Packed Single, Packed Double with Signed Qword Indices.
  | VGATHERQPD = 1071
  /// Gather Packed Single Precision Floating-Point Values Using Signed
  /// Dword/Qword Indices.
  /// Gather Packed Single, Packed Double with Signed Qword Indices.
  | VGATHERQPS = 1072
  /// Convert Exponents of Packed Double Precision Floating-Point Values to
  /// Double Precision Floating-Point Values.
  | VGETEXPPD = 1073
  /// Convert Exponents of Packed FP16 Values to FP16 Values.
  | VGETEXPPH = 1074
  /// Convert Exponents of Packed Single Precision Floating-Point Values to
  /// Single Precision Floating-Point Values.
  | VGETEXPPS = 1075
  /// Convert Exponents of Scalar Double Precision Floating-Point Value to
  /// Double Precision Floating-Point Value.
  | VGETEXPSD = 1076
  /// Convert Exponents of Scalar FP16 Values to FP16 Values.
  | VGETEXPSH = 1077
  /// Convert Exponents of Scalar Single Precision Floating-Point Value to
  /// Single Precision Floating-Point Value.
  | VGETEXPSS = 1078
  /// Extract Float64 Vector of Normalized Mantissas From Float64 Vector.
  | VGETMANTPD = 1079
  /// Extract FP16 Vector of Normalized Mantissas from FP16 Vector.
  | VGETMANTPH = 1080
  /// Extract Float32 Vector of Normalized Mantissas From Float32 Vector.
  | VGETMANTPS = 1081
  /// Extract Float64 of Normalized Mantissa From Float64 Scalar.
  | VGETMANTSD = 1082
  /// Extract FP16 of Normalized Mantissa from FP16 Scalar.
  | VGETMANTSH = 1083
  /// Extract Float32 Vector of Normalized Mantissa From Float32 Scalar.
  | VGETMANTSS = 1084
  /// Galois Field Affine Transformation Inverse.
  | VGF2P8AFFINEINVQB = 1085
  /// Galois Field Affine Transformation.
  | VGF2P8AFFINEQB = 1086
  /// Galois Field Multiply Bytes.
  | VGF2P8MULB = 1087
  /// Packed Double Precision Floating-Point Horizontal Add.
  | VHADDPD = 1088
  /// Packed Single Precision Floating-Point Horizontal Add.
  | VHADDPS = 1089
  /// Packed Double Precision Floating-Point Horizontal Subtract.
  | VHSUBPD = 1090
  /// Packed Single Precision Floating-Point Horizontal Subtract.
  | VHSUBPS = 1091
  /// Insert Packed Floating-Point Values.
  | VINSERTF128 = 1092
  /// Insert Packed Floating-Point Values.
  | VINSERTF32X4 = 1093
  /// Insert Packed Floating-Point Values.
  | VINSERTF32X8 = 1094
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X2 = 1095
  /// Insert Packed Floating-Point Values.
  | VINSERTF64X4 = 1096
  /// Insert Packed Integer Values.
  | VINSERTI128 = 1097
  /// Insert Packed Integer Values.
  | VINSERTI32X4 = 1098
  /// Insert Packed Integer Values.
  | VINSERTI32X8 = 1099
  /// Insert Packed Integer Values.
  | VINSERTI64X2 = 1100
  /// Insert Packed Integer Values.
  | VINSERTI64X4 = 1101
  /// Insert Scalar Single Precision Floating-Point Value.
  | VINSERTPS = 1102
  /// Load Unaligned Integer 128 Bits.
  | VLDDQU = 1103
  /// Load MXCSR Register.
  | VLDMXCSR = 1104
  /// Store Selected Bytes of Double Quadword.
  | VMASKMOVDQU = 1105
  /// Conditional SIMD Packed Loads and Stores.
  | VMASKMOVPD = 1106
  /// Conditional SIMD Packed Loads and Stores.
  | VMASKMOVPS = 1107
  /// Maximum of Packed Double Precision Floating-Point Values.
  | VMAXPD = 1108
  /// Return Maximum of Packed FP16 Values.
  | VMAXPH = 1109
  /// Maximum of Packed Single Precision Floating-Point Values.
  | VMAXPS = 1110
  /// Return Maximum Scalar Double Precision Floating-Point Value.
  | VMAXSD = 1111
  /// Return Maximum of Scalar FP16 Values.
  | VMAXSH = 1112
  /// Return Maximum Scalar Single Precision Floating-Point Value.
  | VMAXSS = 1113
  /// Call to VM Monitor.
  | VMCALL = 1114
  /// Clear Virtual-Machine Control Structure.
  | VMCLEAR = 1115
  /// Invoke VM function.
  | VMFUNC = 1116
  /// Minimum of Packed Double Precision Floating-Point Values.
  | VMINPD = 1117
  /// Return Minimum of Packed FP16 Values.
  | VMINPH = 1118
  /// Minimum of Packed Single Precision Floating-Point Values.
  | VMINPS = 1119
  /// Return Minimum Scalar Double Precision Floating-Point Value.
  | VMINSD = 1120
  /// Return Minimum Scalar FP16 Value.
  | VMINSH = 1121
  /// Return Minimum Scalar Single Precision Floating-Point Value.
  | VMINSS = 1122
  /// Launch Virtual Machine.
  | VMLAUNCH = 1123
  /// Move Aligned Packed Double Precision Floating-Point Values.
  | VMOVAPD = 1124
  /// Move Aligned Packed Single Precision Floating-Point Values.
  | VMOVAPS = 1125
  /// Move Doubleword/Move Quadword.
  | VMOVD = 1126
  /// Replicate Double Precision Floating-Point Values.
  | VMOVDDUP = 1127
  /// Move Aligned Packed Integer Values.
  | VMOVDQA = 1128
  /// Move Aligned Packed Integer Values.
  | VMOVDQA32 = 1129
  /// Move Aligned Packed Integer Values.
  | VMOVDQA64 = 1130
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU = 1131
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU16 = 1132
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU32 = 1133
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU64 = 1134
  /// Move Unaligned Packed Integer Values.
  | VMOVDQU8 = 1135
  /// Move Packed Single Precision Floating-Point Values High to Low.
  | VMOVHLPS = 1136
  /// Move High Packed Double Precision Floating-Point Value.
  | VMOVHPD = 1137
  /// Move High Packed Single Precision Floating-Point Values.
  | VMOVHPS = 1138
  /// Move Packed Single Precision Floating-Point Values Low to High.
  | VMOVLHPS = 1139
  /// Move Low Packed Double Precision Floating-Point Value.
  | VMOVLPD = 1140
  /// Move Low Packed Single Precision Floating-Point Values.
  | VMOVLPS = 1141
  /// Extract Packed Double Precision Floating-Point Sign Mask.
  | VMOVMSKPD = 1142
  /// Extract Packed Single Precision Floating-Point Sign Mask.
  | VMOVMSKPS = 1143
  /// Store Packed Integers Using Non-Temporal Hint.
  | VMOVNTDQ = 1144
  /// Load Double Quadword Non-Temporal Aligned Hint.
  | VMOVNTDQA = 1145
  /// Store Packed Double Precision Floating-Point Values Using Non-Temporal
  /// Hint.
  | VMOVNTPD = 1146
  /// Store Packed Single Precision Floating-Point Values Using Non-Temporal
  /// Hint.
  | VMOVNTPS = 1147
  /// Move Doubleword/Move Quadword.
  /// Move Quadword.
  | VMOVQ = 1148
  /// Move or Merge Scalar Double Precision Floating-Point Value.
  | VMOVSD = 1149
  /// Move Scalar FP16 Value.
  | VMOVSH = 1150
  /// Replicate Single Precision Floating-Point Values.
  | VMOVSHDUP = 1151
  /// Replicate Single Precision Floating-Point Values.
  | VMOVSLDUP = 1152
  /// Move or Merge Scalar Single Precision Floating-Point Value.
  | VMOVSS = 1153
  /// Move Unaligned Packed Double Precision Floating-Point Values.
  | VMOVUPD = 1154
  /// Move Unaligned Packed Single Precision Floating-Point Values.
  | VMOVUPS = 1155
  /// Move Word.
  | VMOVW = 1156
  /// Compute Multiple Packed Sums of Absolute Difference.
  | VMPSADBW = 1157
  /// Load Pointer to Virtual-Machine Control Structure.
  | VMPTRLD = 1158
  /// Store Pointer to Virtual-Machine Control Structure.
  | VMPTRST = 1159
  /// Reads a component from the VMCS and stores it into a destination operand.
  | VMREAD = 1160
  /// Resume Virtual Machine.
  | VMRESUME = 1161
  /// Multiply Packed Double Precision Floating-Point Values.
  | VMULPD = 1162
  /// Multiply Packed FP16 Values.
  | VMULPH = 1163
  /// Multiply Packed Single Precision Floating-Point Values.
  | VMULPS = 1164
  /// Multiply Scalar Double Precision Floating-Point Value.
  | VMULSD = 1165
  /// Multiply Scalar FP16 Values.
  | VMULSH = 1166
  /// Multiply Scalar Single Precision Floating-Point Values.
  | VMULSS = 1167
  /// Leave VMX Operation.
  | VMXOFF = 1168
  /// Enter VMX Operation.
  | VMXON = 1169
  /// Bitwise Logical OR of Packed Double Precision Floating-Point Values.
  | VORPD = 1170
  /// Bitwise Logical OR of Packed Single Precision Floating-Point Values.
  | VORPS = 1171
  /// Compute Intersection Between DWORDS/QUADWORDS to a Pair of Mask Registers.
  | VP2INTERSECTD = 1172
  /// Compute Intersection Between DWORDS/QUADWORDS to a Pair of Mask Registers.
  | VP2INTERSECTQ = 1173
  /// Dot Product of Signed Words With Dword Accumulation (4-Iterations).
  | VP4DPWSSD = 1174
  /// Dot Product of Signed Words With Dword Accumulation and Saturation
  /// (4-Iterations).
  | VP4DPWSSDS = 1175
  /// Packed Absolute Value.
  | VPABSB = 1176
  /// Packed Absolute Value.
  | VPABSD = 1177
  /// Packed Absolute Value.
  | VPABSQ = 1178
  /// Packed Absolute Value.
  | VPABSW = 1179
  /// Pack With Signed Saturation.
  | VPACKSSDW = 1180
  /// Pack With Signed Saturation.
  | VPACKSSWB = 1181
  /// Pack With Unsigned Saturation.
  | VPACKUSDW = 1182
  /// Pack With Unsigned Saturation.
  | VPACKUSWB = 1183
  /// Add Packed Integers.
  | VPADDB = 1184
  /// Add Packed Integers.
  | VPADDD = 1185
  /// Add Packed Integers.
  | VPADDQ = 1186
  /// Add Packed Signed Integers with Signed Saturation.
  | VPADDSB = 1187
  /// Add Packed Signed Integers with Signed Saturation.
  | VPADDSW = 1188
  /// Add Packed Unsigned Integers With Unsigned Saturation.
  | VPADDUSB = 1189
  /// Add Packed Unsigned Integers With Unsigned Saturation.
  | VPADDUSW = 1190
  /// Add Packed Integers.
  | VPADDW = 1191
  /// Packed Align Right.
  | VPALIGNR = 1192
  /// Logical AND.
  | VPAND = 1193
  /// Logical AND.
  | VPANDD = 1194
  /// Logical AND NOT.
  | VPANDN = 1195
  /// Logical AND NOT.
  | VPANDND = 1196
  /// Logical AND NOT.
  | VPANDNQ = 1197
  /// Logical AND.
  | VPANDQ = 1198
  /// Average Packed Integers.
  | VPAVGB = 1199
  /// Average Packed Integers.
  | VPAVGW = 1200
  /// Blend Packed Dwords.
  | VPBLENDD = 1201
  /// Blend Byte/Word Vectors Using an Opmask Control.
  | VPBLENDMB = 1202
  /// Blend Int32/Int64 Vectors Using an OpMask Control.
  | VPBLENDMD = 1203
  /// Blend Int32/Int64 Vectors Using an OpMask Control.
  | VPBLENDMQ = 1204
  /// Blend Byte/Word Vectors Using an Opmask Control.
  | VPBLENDMW = 1205
  /// Variable Blend Packed Bytes.
  | VPBLENDVB = 1206
  /// Blend Packed Words.
  | VPBLENDW = 1207
  /// Load Integer and Broadcast.
  /// Load With Broadcast Integer Data From General Purpose Register.
  | VPBROADCASTB = 1208
  /// Load Integer and Broadcast.
  /// Load With Broadcast Integer Data From General Purpose Register.
  | VPBROADCASTD = 1209
  /// Broadcast Mask to Vector Register.
  | VPBROADCASTMB2Q = 1210
  /// Broadcast Mask to Vector Register.
  | VPBROADCASTMW2D = 1211
  /// Load Integer and Broadcast.
  /// Load With Broadcast Integer Data From General Purpose Register.
  | VPBROADCASTQ = 1212
  /// Load Integer and Broadcast.
  /// Load With Broadcast Integer Data From General Purpose Register.
  | VPBROADCASTW = 1213
  /// Carry-Less Multiplication Quadword.
  | VPCLMULQDQ = 1214
  /// Compare Packed Byte Values Into Mask.
  | VPCMPB = 1215
  /// Compare Packed Integer Values Into Mask.
  | VPCMPD = 1216
  /// Compare Packed Data for Equal.
  | VPCMPEQB = 1217
  /// Compare Packed Data for Equal.
  | VPCMPEQD = 1218
  /// Compare Packed Qword Data for Equal.
  | VPCMPEQQ = 1219
  /// Compare Packed Data for Equal.
  | VPCMPEQW = 1220
  /// Packed Compare Explicit Length Strings, Return Index.
  | VPCMPESTRI = 1221
  /// Packed Compare Explicit Length Strings, Return Mask.
  | VPCMPESTRM = 1222
  /// Compare Packed Signed Integers for Greater Than.
  | VPCMPGTB = 1223
  /// Compare Packed Signed Integers for Greater Than.
  | VPCMPGTD = 1224
  /// Compare Packed Data for Greater Than.
  | VPCMPGTQ = 1225
  /// Compare Packed Signed Integers for Greater Than.
  | VPCMPGTW = 1226
  /// Packed Compare Implicit Length Strings, Return Index.
  | VPCMPISTRI = 1227
  /// Packed Compare Implicit Length Strings, Return Mask.
  | VPCMPISTRM = 1228
  /// Compare Packed Integer Values Into Mask.
  | VPCMPQ = 1229
  /// Compare Packed Byte Values Into Mask.
  | VPCMPUB = 1230
  /// Compare Packed Integer Values Into Mask.
  | VPCMPUD = 1231
  /// Compare Packed Integer Values Into Mask.
  | VPCMPUQ = 1232
  /// Compare Packed Word Values Into Mask.
  | VPCMPUW = 1233
  /// Compare Packed Word Values Into Mask.
  | VPCMPW = 1234
  /// Store Sparse Packed Byte/Word Integer Values Into Dense Memory/Register.
  | VPCOMPRESSB = 1235
  /// Store Sparse Packed Doubleword Integer Values Into Dense Memory/Register.
  | VPCOMPRESSD = 1236
  /// Store Sparse Packed Quadword Integer Values Into Dense Memory/Register.
  | VPCOMPRESSQ = 1237
  /// Store Sparse Packed Byte/Word Integer Values Into Dense Memory/Register.
  | VPCOMPRESSW = 1238
  /// Detect Conflicts Within a Vector of Packed Dword/Qword Values Into Dense
  /// Memory/ Register.
  | VPCONFLICTD = 1239
  /// Detect Conflicts Within a Vector of Packed Dword/Qword Values Into Dense
  /// Memory/ Register.
  | VPCONFLICTQ = 1240
  /// Multiply and Add Unsigned and Signed Bytes With and Without Saturation.
  | VPDPBSSD = 1241
  /// Multiply and Add Unsigned and Signed Bytes With and Without Saturation.
  | VPDPBSSDS = 1242
  /// Multiply and Add Unsigned and Signed Bytes With and Without Saturation.
  | VPDPBSUD = 1243
  /// Multiply and Add Unsigned and Signed Bytes With and Without Saturation.
  | VPDPBSUDS = 1244
  /// Multiply and Add Unsigned and Signed Bytes.
  | VPDPBUSD = 1245
  /// Multiply and Add Unsigned and Signed Bytes With Saturation.
  | VPDPBUSDS = 1246
  /// Multiply and Add Unsigned and Signed Bytes With and Without Saturation.
  | VPDPBUUD = 1247
  /// Multiply and Add Unsigned and Signed Bytes With and Without Saturation.
  | VPDPBUUDS = 1248
  /// Multiply and Add Signed Word Integers.
  | VPDPWSSD = 1249
  /// Multiply and Add Signed Word Integers With Saturation.
  | VPDPWSSDS = 1250
  /// Multiply and Add Unsigned and Signed Words With and Without Saturation.
  | VPDPWSUD = 1251
  /// Multiply and Add Unsigned and Signed Words With and Without Saturation.
  | VPDPWSUDS = 1252
  /// Multiply and Add Unsigned and Signed Words With and Without Saturation.
  | VPDPWUSD = 1253
  /// Multiply and Add Unsigned and Signed Words With and Without Saturation.
  | VPDPWUSDS = 1254
  /// Multiply and Add Unsigned and Signed Words With and Without Saturation.
  | VPDPWUUD = 1255
  /// Multiply and Add Unsigned and Signed Words With and Without Saturation.
  | VPDPWUUDS = 1256
  /// Permute Floating-Point Values.
  | VPERM2F128 = 1257
  /// Permute Integer Values.
  | VPERM2I128 = 1258
  /// Permute Packed Bytes Elements.
  | VPERMB = 1259
  /// Permute Packed Doubleword/Word Elements.
  | VPERMD = 1260
  /// Full Permute of Bytes From Two Tables Overwriting the Index.
  | VPERMI2B = 1261
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2D = 1262
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2PD = 1263
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2PS = 1264
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2Q = 1265
  /// Full Permute From Two Tables Overwriting the Index.
  | VPERMI2W = 1266
  /// Permute In-Lane of Pairs of Double Precision Floating-Point Values.
  | VPERMILPD = 1267
  /// Permute In-Lane of Quadruples of Single Precision Floating-Point Values.
  | VPERMILPS = 1268
  /// Permute Double Precision Floating-Point Elements.
  | VPERMPD = 1269
  /// Permute Single Precision Floating-Point Elements.
  | VPERMPS = 1270
  /// Qwords Element Permutation.
  | VPERMQ = 1271
  /// Full Permute of Bytes From Two Tables Overwriting a Table.
  | VPERMT2B = 1272
  /// Full Permute From Two Tables Overwriting One Table.
  | VPERMT2D = 1273
  /// Full Permute From Two Tables Overwriting One Table.
  | VPERMT2PD = 1274
  /// Full Permute From Two Tables Overwriting One Table.
  | VPERMT2PS = 1275
  /// Full Permute From Two Tables Overwriting One Table.
  | VPERMT2Q = 1276
  /// Full Permute From Two Tables Overwriting One Table.
  | VPERMT2W = 1277
  /// Permute Packed Doubleword/Word Elements.
  | VPERMW = 1278
  /// Expand Byte/Word Values.
  | VPEXPANDB = 1279
  /// Load Sparse Packed Doubleword Integer Values From Dense Memory/Register.
  | VPEXPANDD = 1280
  /// Load Sparse Packed Quadword Integer Values From Dense Memory/Register.
  | VPEXPANDQ = 1281
  /// Expand Byte/Word Values.
  | VPEXPANDW = 1282
  /// Extract Byte/Dword/Qword.
  | VPEXTRB = 1283
  /// Extract Byte/Dword/Qword.
  | VPEXTRD = 1284
  /// Extract Byte/Dword/Qword.
  | VPEXTRQ = 1285
  /// Extract Word.
  | VPEXTRW = 1286
  /// Gather Packed Dword, Packed Qword With Signed Dword Indices.
  /// Gather Packed Dword Values Using Signed Dword/Qword Indices.
  | VPGATHERDD = 1287
  /// Gather Packed Dword, Packed Qword With Signed Dword Indices.
  /// Gather Packed Qword Values Using Signed Dword/Qword Indices.
  | VPGATHERDQ = 1288
  /// Gather Packed Dword Values Using Signed Dword/Qword Indices.
  /// Gather Packed Dword, Packed Qword with Signed Qword Indices.
  | VPGATHERQD = 1289
  /// Gather Packed Qword Values Using Signed Dword/Qword Indices.
  /// Gather Packed Dword, Packed Qword with Signed Qword Indices.
  | VPGATHERQQ = 1290
  /// Packed Horizontal Add.
  | VPHADDD = 1291
  /// Packed Horizontal Add and Saturate.
  | VPHADDSW = 1292
  /// Packed Horizontal Add.
  | VPHADDW = 1293
  /// Packed Horizontal Word Minimum.
  | VPHMINPOSUW = 1294
  /// Packed Horizontal Subtract.
  | VPHSUBD = 1295
  /// Packed Horizontal Subtract and Saturate.
  | VPHSUBSW = 1296
  /// Packed Horizontal Subtract.
  | VPHSUBW = 1297
  /// Insert Byte/Dword/Qword.
  | VPINSRB = 1298
  /// Insert Byte/Dword/Qword.
  | VPINSRD = 1299
  /// Insert Byte/Dword/Qword.
  | VPINSRQ = 1300
  /// Insert Word.
  | VPINSRW = 1301
  /// Count the Number of Leading Zero Bits for Packed Dword, Packed Qword
  /// Values.
  | VPLZCNTD = 1302
  /// Count the Number of Leading Zero Bits for Packed Dword, Packed Qword
  /// Values.
  | VPLZCNTQ = 1303
  /// Packed Multiply of Unsigned 52-Bit Unsigned Integers and Add High 52-Bit
  /// Products to 64-Bit Accumulators.
  | VPMADD52HUQ = 1304
  /// Packed Multiply of Unsigned 52-Bit Integers and Add the Low 52-Bit
  /// Products to Qword Accumulators.
  | VPMADD52LUQ = 1305
  /// Multiply and Add Packed Signed and Unsigned Bytes.
  | VPMADDUBSW = 1306
  /// Multiply and Add Packed Integers.
  | VPMADDWD = 1307
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVD = 1308
  /// Conditional SIMD Integer Packed Loads and Stores.
  | VPMASKMOVQ = 1309
  /// Maximum of Packed Signed Integers.
  | VPMAXSB = 1310
  /// Maximum of Packed Signed Integers.
  | VPMAXSD = 1311
  /// Maximum of Packed Signed Integers.
  | VPMAXSQ = 1312
  /// Maximum of Packed Signed Integers.
  | VPMAXSW = 1313
  /// Maximum of Packed Unsigned Integers.
  | VPMAXUB = 1314
  /// Maximum of Packed Unsigned Integers.
  | VPMAXUD = 1315
  /// Maximum of Packed Unsigned Integers.
  | VPMAXUQ = 1316
  /// Maximum of Packed Unsigned Integers.
  | VPMAXUW = 1317
  /// Minimum of Packed Signed Integers.
  | VPMINSB = 1318
  /// Minimum of Packed Signed Integers.
  | VPMINSD = 1319
  /// Minimum of Packed Signed Integers.
  | VPMINSQ = 1320
  /// Minimum of Packed Signed Integers.
  | VPMINSW = 1321
  /// Minimum of Packed Unsigned Integers.
  | VPMINUB = 1322
  /// Minimum of Packed Unsigned Integers.
  | VPMINUD = 1323
  /// Minimum of Packed Unsigned Integers.
  | VPMINUQ = 1324
  /// Minimum of Packed Unsigned Integers.
  | VPMINUW = 1325
  /// Convert a Vector Register to a Mask.
  | VPMOVB2M = 1326
  /// Convert a Vector Register to a Mask.
  | VPMOVD2M = 1327
  /// Down Convert DWord to Byte.
  | VPMOVDB = 1328
  /// Down Convert DWord to Word.
  | VPMOVDW = 1329
  /// Convert a Mask Register to a Vector Register.
  | VPMOVM2B = 1330
  /// Convert a Mask Register to a Vector Register.
  | VPMOVM2D = 1331
  /// Convert a Mask Register to a Vector Register.
  | VPMOVM2Q = 1332
  /// Convert a Mask Register to a Vector Register.
  | VPMOVM2W = 1333
  /// Move Byte Mask.
  | VPMOVMSKB = 1334
  /// Convert a Vector Register to a Mask.
  | VPMOVQ2M = 1335
  /// Down Convert QWord to Byte.
  | VPMOVQB = 1336
  /// Down Convert QWord to DWord.
  | VPMOVQD = 1337
  /// Down Convert QWord to Word.
  | VPMOVQW = 1338
  /// Down Convert DWord to Byte.
  | VPMOVSDB = 1339
  /// Down Convert DWord to Word.
  | VPMOVSDW = 1340
  /// Down Convert QWord to Byte.
  | VPMOVSQB = 1341
  /// Down Convert QWord to DWord.
  | VPMOVSQD = 1342
  /// Down Convert QWord to Word.
  | VPMOVSQW = 1343
  /// Down Convert Word to Byte.
  | VPMOVSWB = 1344
  /// Packed Move With Sign Extend.
  | VPMOVSXBD = 1345
  /// Packed Move With Sign Extend.
  | VPMOVSXBQ = 1346
  /// Packed Move With Sign Extend.
  | VPMOVSXBW = 1347
  /// Packed Move With Sign Extend.
  | VPMOVSXDQ = 1348
  /// Packed Move With Sign Extend.
  | VPMOVSXWD = 1349
  /// Packed Move With Sign Extend.
  | VPMOVSXWQ = 1350
  /// Down Convert DWord to Byte.
  | VPMOVUSDB = 1351
  /// Down Convert DWord to Word.
  | VPMOVUSDW = 1352
  /// Down Convert QWord to Byte.
  | VPMOVUSQB = 1353
  /// Down Convert QWord to DWord.
  | VPMOVUSQD = 1354
  /// Down Convert QWord to Word.
  | VPMOVUSQW = 1355
  /// Down Convert Word to Byte.
  | VPMOVUSWB = 1356
  /// Convert a Vector Register to a Mask.
  | VPMOVW2M = 1357
  /// Down Convert Word to Byte.
  | VPMOVWB = 1358
  /// Packed Move With Zero Extend.
  | VPMOVZXBD = 1359
  /// Packed Move With Zero Extend.
  | VPMOVZXBQ = 1360
  /// Packed Move With Zero Extend.
  | VPMOVZXBW = 1361
  /// Packed Move With Zero Extend.
  | VPMOVZXDQ = 1362
  /// Packed Move With Zero Extend.
  | VPMOVZXWD = 1363
  /// Packed Move With Zero Extend.
  | VPMOVZXWQ = 1364
  /// Multiply Packed Doubleword Integers.
  | VPMULDQ = 1365
  /// Packed Multiply High With Round and Scale.
  | VPMULHRSW = 1366
  /// Multiply Packed Unsigned Integers and Store High Result.
  | VPMULHUW = 1367
  /// Multiply Packed Signed Integers and Store High Result.
  | VPMULHW = 1368
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLD = 1369
  /// Multiply Packed Integers and Store Low Result.
  | VPMULLQ = 1370
  /// Multiply Packed Signed Integers and Store Low Result.
  | VPMULLW = 1371
  /// Select Packed Unaligned Bytes From Quadword Sources.
  | VPMULTISHIFTQB = 1372
  /// Multiply Packed Unsigned Doubleword Integers.
  | VPMULUDQ = 1373
  /// Return the Count of Number of Bits Set to 1 in BYTE/WORD/DWORD/QWORD.
  | VPOPCNTB = 1374
  /// Return the Count of Number of Bits Set to 1 in BYTE/WORD/DWORD/QWORD.
  | VPOPCNTD = 1375
  /// Return the Count of Number of Bits Set to 1 in BYTE/WORD/DWORD/QWORD.
  | VPOPCNTQ = 1376
  /// Return the Count of Number of Bits Set to 1 in BYTE/WORD/DWORD/QWORD.
  | VPOPCNTW = 1377
  /// Bitwise Logical OR.
  | VPOR = 1378
  /// Bitwise Logical OR.
  | VPORD = 1379
  /// Bitwise Logical OR.
  | VPORQ = 1380
  /// Bit Rotate Left.
  | VPROLD = 1381
  /// Bit Rotate Left.
  | VPROLQ = 1382
  /// Bit Rotate Left.
  | VPROLVD = 1383
  /// Bit Rotate Left.
  | VPROLVQ = 1384
  /// Bit Rotate Right.
  | VPRORD = 1385
  /// Bit Rotate Right.
  | VPRORQ = 1386
  /// Bit Rotate Right.
  | VPRORVD = 1387
  /// Bit Rotate Right.
  | VPRORVQ = 1388
  /// Compute Sum of Absolute Differences.
  | VPSADBW = 1389
  /// Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword
  /// Indices.
  | VPSCATTERDD = 1390
  /// Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword
  /// Indices.
  | VPSCATTERDQ = 1391
  /// Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword
  /// Indices.
  | VPSCATTERQD = 1392
  /// Scatter Packed Dword, Packed Qword with Signed Dword, Signed Qword
  /// Indices.
  | VPSCATTERQQ = 1393
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDD = 1394
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDQ = 1395
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVD = 1396
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVQ = 1397
  /// Concatenate and Variable Shift Packed Data Left Logical.
  | VPSHLDVW = 1398
  /// Concatenate and Shift Packed Data Left Logical.
  | VPSHLDW = 1399
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDD = 1400
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDQ = 1401
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVD = 1402
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVQ = 1403
  /// Concatenate and Variable Shift Packed Data Right Logical.
  | VPSHRDVW = 1404
  /// Concatenate and Shift Packed Data Right Logical.
  | VPSHRDW = 1405
  /// Packed Shuffle Bytes.
  | VPSHUFB = 1406
  /// Shuffle Bits From Quadword Elements Using Byte Indexes Into Mask.
  | VPSHUFBITQMB = 1407
  /// Shuffle Packed Doublewords.
  | VPSHUFD = 1408
  /// Shuffle Packed High Words.
  | VPSHUFHW = 1409
  /// Shuffle Packed Low Words.
  | VPSHUFLW = 1410
  /// Packed SIGN.
  | VPSIGNB = 1411
  /// Packed SIGN.
  | VPSIGND = 1412
  /// Packed SIGN.
  | VPSIGNW = 1413
  /// Shift Packed Data Left Logical.
  | VPSLLD = 1414
  /// Shift Double Quadword Left Logical.
  | VPSLLDQ = 1415
  /// Shift Packed Data Left Logical.
  | VPSLLQ = 1416
  /// Variable Bit Shift Left Logical.
  | VPSLLVD = 1417
  /// Variable Bit Shift Left Logical.
  | VPSLLVQ = 1418
  /// Variable Bit Shift Left Logical.
  | VPSLLVW = 1419
  /// Shift Packed Data Left Logical.
  | VPSLLW = 1420
  /// Shift Packed Data Right Arithmetic.
  | VPSRAD = 1421
  /// Shift Packed Data Right Arithmetic.
  | VPSRAQ = 1422
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVD = 1423
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVQ = 1424
  /// Variable Bit Shift Right Arithmetic.
  | VPSRAVW = 1425
  /// Shift Packed Data Right Arithmetic.
  | VPSRAW = 1426
  /// Shift Packed Data Right Logical.
  | VPSRLD = 1427
  /// Shift Double Quadword Right Logical.
  | VPSRLDQ = 1428
  /// Shift Packed Data Right Logical.
  | VPSRLQ = 1429
  /// Variable Bit Shift Right Logical.
  | VPSRLVD = 1430
  /// Variable Bit Shift Right Logical.
  | VPSRLVQ = 1431
  /// Variable Bit Shift Right Logical.
  | VPSRLVW = 1432
  /// Shift Packed Data Right Logical.
  | VPSRLW = 1433
  /// Subtract Packed Integers.
  | VPSUBB = 1434
  /// Subtract Packed Integers.
  | VPSUBD = 1435
  /// Subtract Packed Quadword Integers.
  | VPSUBQ = 1436
  /// Subtract Packed Signed Integers With Signed Saturation.
  | VPSUBSB = 1437
  /// Subtract Packed Signed Integers With Signed Saturation.
  | VPSUBSW = 1438
  /// Subtract Packed Unsigned Integers With Unsigned Saturation.
  | VPSUBUSB = 1439
  /// Subtract Packed Unsigned Integers With Unsigned Saturation.
  | VPSUBUSW = 1440
  /// Subtract Packed Integers.
  | VPSUBW = 1441
  /// Bitwise Ternary Logic.
  | VPTERNLOGD = 1442
  /// Bitwise Ternary Logic.
  | VPTERNLOGQ = 1443
  /// Logical Compare.
  | VPTEST = 1444
  /// Logical AND and Set Mask.
  | VPTESTMB = 1445
  /// Logical AND and Set Mask.
  | VPTESTMD = 1446
  /// Logical AND and Set Mask.
  | VPTESTMQ = 1447
  /// Logical AND and Set Mask.
  | VPTESTMW = 1448
  /// Logical NAND and Set.
  | VPTESTNMB = 1449
  /// Logical NAND and Set.
  | VPTESTNMD = 1450
  /// Logical NAND and Set.
  | VPTESTNMQ = 1451
  /// Logical NAND and Set.
  | VPTESTNMW = 1452
  /// Unpack High Data.
  | VPUNPCKHBW = 1453
  /// Unpack High Data.
  | VPUNPCKHDQ = 1454
  /// Unpack High Data.
  | VPUNPCKHQDQ = 1455
  /// Unpack High Data.
  | VPUNPCKHWD = 1456
  /// Unpack Low Data.
  | VPUNPCKLBW = 1457
  /// Unpack Low Data.
  | VPUNPCKLDQ = 1458
  /// Unpack Low Data.
  | VPUNPCKLQDQ = 1459
  /// Unpack Low Data.
  | VPUNPCKLWD = 1460
  /// Logical Exclusive OR.
  | VPXOR = 1461
  /// Logical Exclusive OR.
  | VPXORD = 1462
  /// Logical Exclusive OR.
  | VPXORQ = 1463
  /// Range Restriction Calculation for Packed Pairs of Float64 Values.
  | VRANGEPD = 1464
  /// Range Restriction Calculation for Packed Pairs of Float32 Values.
  | VRANGEPS = 1465
  /// Range Restriction Calculation From a Pair of Scalar Float64 Values.
  | VRANGESD = 1466
  /// Range Restriction Calculation From a Pair of Scalar Float32 Values.
  | VRANGESS = 1467
  /// Compute Approximate Reciprocals of Packed Float64 Values.
  | VRCP14PD = 1468
  /// Compute Approximate Reciprocals of Packed Float32 Values.
  | VRCP14PS = 1469
  /// Compute Approximate Reciprocal of Scalar Float64 Value.
  | VRCP14SD = 1470
  /// Compute Approximate Reciprocal of Scalar Float32 Value.
  | VRCP14SS = 1471
  /// Approximation to the Reciprocal of Packed Double Precision Floating-Point
  /// Values With Less Than 2^-28 Relative Error.
  | VRCP28PD = 1472
  /// Approximation to the Reciprocal of Packed Single Precision Floating-Point
  /// Values With Less Than 2^-28 Relative Error.
  | VRCP28PS = 1473
  /// Approximation to the Reciprocal of Scalar Double Precision Floating-Point
  /// Value With Less Than 2^-28 Relative Error.
  | VRCP28SD = 1474
  /// Approximation to the Reciprocal of Scalar Single Precision Floating-Point
  /// Value With Less Than 2^-28 Relative Error.
  | VRCP28SS = 1475
  /// Compute Reciprocals of Packed FP16 Values.
  | VRCPPH = 1476
  /// Compute Reciprocals of Packed Single Precision Floating-Point Values.
  | VRCPPS = 1477
  /// Compute Reciprocal of Scalar FP16 Value.
  | VRCPSH = 1478
  /// Compute Reciprocal of Scalar Single Precision Floating-Point Values.
  | VRCPSS = 1479
  /// Perform Reduction Transformation on Packed Float64 Values.
  | VREDUCEPD = 1480
  /// Perform Reduction Transformation on Packed FP16 Values.
  | VREDUCEPH = 1481
  /// Perform Reduction Transformation on Packed Float32 Values.
  | VREDUCEPS = 1482
  /// Perform a Reduction Transformation on a Scalar Float64 Value.
  | VREDUCESD = 1483
  /// Perform Reduction Transformation on Scalar FP16 Value.
  | VREDUCESH = 1484
  /// Perform a Reduction Transformation on a Scalar Float32 Value.
  | VREDUCESS = 1485
  /// Round Packed Float64 Values to Include a Given Number of Fraction Bits.
  | VRNDSCALEPD = 1486
  /// Round Packed FP16 Values to Include a Given Number of Fraction Bits.
  | VRNDSCALEPH = 1487
  /// Round Packed Float32 Values to Include a Given Number of Fraction Bits.
  | VRNDSCALEPS = 1488
  /// Round Scalar Float64 Value to Include a Given Number of Fraction Bits.
  | VRNDSCALESD = 1489
  /// Round Scalar FP16 Value to Include a Given Number of Fraction Bits.
  | VRNDSCALESH = 1490
  /// Round Scalar Float32 Value to Include a Given Number of Fraction Bits.
  | VRNDSCALESS = 1491
  /// Round Packed Double Precision Floating-Point Values.
  | VROUNDPD = 1492
  /// Round Packed Single Precision Floating-Point Values.
  | VROUNDPS = 1493
  /// Round Scalar Double Precision Floating-Point Values.
  | VROUNDSD = 1494
  /// Round Scalar Single Precision Floating-Point Values.
  | VROUNDSS = 1495
  /// Compute Approximate Reciprocals of Square Roots of Packed Float64 Values.
  | VRSQRT14PD = 1496
  /// Compute Approximate Reciprocals of Square Roots of Packed Float32 Values.
  | VRSQRT14PS = 1497
  /// Compute Approximate Reciprocal of Square Root of Scalar Float64 Value.
  | VRSQRT14SD = 1498
  /// Compute Approximate Reciprocal of Square Root of Scalar Float32 Value.
  | VRSQRT14SS = 1499
  /// Approximation to the Reciprocal Square Root of Packed Double Precision
  /// Floating-Point Values With Less Than 2^-28 Relative Error.
  | VRSQRT28PD = 1500
  /// Approximation to the Reciprocal Square Root of Packed Single Precision
  /// Floating-Point Values With Less Than 2^-28 Relative Error.
  | VRSQRT28PS = 1501
  /// Approximation to the Reciprocal Square Root of Scalar Double Precision
  /// Floating-Point Value With Less Than 2^-28 Relative Error.
  | VRSQRT28SD = 1502
  /// Approximation to the Reciprocal Square Root of Scalar Single Precision
  /// Floating-Point Value With Less Than 2^-28 Relative Error.
  | VRSQRT28SS = 1503
  /// Compute Reciprocals of Square Roots of Packed FP16 Values.
  | VRSQRTPH = 1504
  /// Compute Reciprocals of Square Roots of Packed Single Precision
  /// Floating-Point Values.
  | VRSQRTPS = 1505
  /// Compute Approximate Reciprocal of Square Root of Scalar FP16 Value.
  | VRSQRTSH = 1506
  /// Compute Reciprocal of Square Root of Scalar Single Precision
  /// Floating-Point Value.
  | VRSQRTSS = 1507
  /// Scale Packed Float64 Values With Float64 Values.
  | VSCALEFPD = 1508
  /// Scale Packed FP16 Values with FP16 Values.
  | VSCALEFPH = 1509
  /// Scale Packed Float32 Values With Float32 Values.
  | VSCALEFPS = 1510
  /// Scale Scalar Float64 Values With Float64 Values.
  | VSCALEFSD = 1511
  /// Scale Scalar FP16 Values with FP16 Values.
  | VSCALEFSH = 1512
  /// Scale Scalar Float32 Value With Float32 Value.
  | VSCALEFSS = 1513
  /// Scatter Packed Single Precision, Packed Double Precision Floating-Point
  /// Values with Signed Dword and Qword Indices.
  | VSCATTERDPD = 1514
  /// Scatter Packed Single Precision, Packed Double Precision Floating-Point
  /// Values with Signed Dword and Qword Indices.
  | VSCATTERDPS = 1515
  /// Sparse Prefetch Packed SP/DP Data Values with Signed Dword, Signed Qword
  /// Indices Using T0 Hint With Intent to Write.
  | VSCATTERPF0DPD = 1516
  /// Sparse Prefetch Packed SP/DP Data Values with Signed Dword, Signed Qword
  /// Indices Using T0 Hint With Intent to Write.
  | VSCATTERPF0DPS = 1517
  /// Sparse Prefetch Packed SP/DP Data Values with Signed Dword, Signed Qword
  /// Indices Using T0 Hint With Intent to Write.
  | VSCATTERPF0QPD = 1518
  /// Sparse Prefetch Packed SP/DP Data Values with Signed Dword, Signed Qword
  /// Indices Using T0 Hint With Intent to Write.
  | VSCATTERPF0QPS = 1519
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint With Intent to Write.
  | VSCATTERPF1DPD = 1520
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint With Intent to Write.
  | VSCATTERPF1DPS = 1521
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint With Intent to Write.
  | VSCATTERPF1QPD = 1522
  /// Sparse Prefetch Packed SP/DP Data Values With Signed Dword, Signed Qword
  /// Indices Using T1 Hint With Intent to Write.
  | VSCATTERPF1QPS = 1523
  /// Scatter Packed Single Precision, Packed Double Precision Floating-Point
  /// Values with Signed Dword and Qword Indices.
  | VSCATTERQPD = 1524
  /// Scatter Packed Single Precision, Packed Double Precision Floating-Point
  /// Values with Signed Dword and Qword Indices.
  | VSCATTERQPS = 1525
  /// Perform an Intermediate Calculation for the Next Four SHA512 Message
  /// Qwords.
  | VSHA512MSG1 = 1526
  /// Perform a Final Calculation for the Next Four SHA512 Message Qwords.
  | VSHA512MSG2 = 1527
  /// Perform Two Rounds of SHA512 Operation.
  | VSHA512RNDS2 = 1528
  /// Shuffle Packed Values at 128-Bit Granularity.
  | VSHUFF32X4 = 1529
  /// Shuffle Packed Values at 128-Bit Granularity.
  | VSHUFF64X2 = 1530
  /// Shuffle Packed Values at 128-Bit Granularity.
  | VSHUFI32X4 = 1531
  /// Shuffle Packed Values at 128-Bit Granularity.
  | VSHUFI64X2 = 1532
  /// Packed Interleave Shuffle of Pairs of Double Precision Floating-Point
  /// Values.
  | VSHUFPD = 1533
  /// Packed Interleave Shuffle of Quadruplets of Single Precision
  /// Floating-Point Values.
  | VSHUFPS = 1534
  /// Perform Initial Calculation for the Next Four SM3 Message Words.
  | VSM3MSG1 = 1535
  /// Perform Final Calculation for the Next Four SM3 Message Words.
  | VSM3MSG2 = 1536
  /// Perform Two Rounds of SM3 Operation.
  | VSM3RNDS2 = 1537
  /// Perform Four Rounds of SM4 Key Expansion.
  | VSM4KEY4 = 1538
  /// Performs Four Rounds of SM4 Encryption.
  | VSM4RNDS4 = 1539
  /// Square Root of Double Precision Floating-Point Values.
  | VSQRTPD = 1540
  /// Compute Square Root of Packed FP16 Values.
  | VSQRTPH = 1541
  /// Square Root of Single Precision Floating-Point Values.
  | VSQRTPS = 1542
  /// Compute Square Root of Scalar Double Precision Floating-Point Value.
  | VSQRTSD = 1543
  /// Compute Square Root of Scalar FP16 Value.
  | VSQRTSH = 1544
  /// Compute Square Root of Scalar Single Precision Value.
  | VSQRTSS = 1545
  /// Store MXCSR Register State.
  | VSTMXCSR = 1546
  /// Subtract Packed Double Precision Floating-Point Values.
  | VSUBPD = 1547
  /// Subtract Packed FP16 Values.
  | VSUBPH = 1548
  /// Subtract Packed Single Precision Floating-Point Values.
  | VSUBPS = 1549
  /// Subtract Scalar Double Precision Floating-Point Value.
  | VSUBSD = 1550
  /// Subtract Scalar FP16 Value.
  | VSUBSH = 1551
  /// Subtract Scalar Single Precision Floating-Point Value.
  | VSUBSS = 1552
  /// Packed Bit Test.
  | VTESTPD = 1553
  /// Packed Bit Test.
  | VTESTPS = 1554
  /// Unordered Compare Scalar Double Precision Floating-Point Values and Set
  /// EFLAGS.
  | VUCOMISD = 1555
  /// Unordered Compare Scalar FP16 Values and Set EFLAGS.
  | VUCOMISH = 1556
  /// Unordered Compare Scalar Single Precision Floating-Point Values and Set
  /// EFLAGS.
  | VUCOMISS = 1557
  /// Unpack and Interleave High Packed Double Precision Floating-Point Values.
  | VUNPCKHPD = 1558
  /// Unpack and Interleave High Packed Single Precision Floating-Point Values.
  | VUNPCKHPS = 1559
  /// Unpack and Interleave Low Packed Double Precision Floating-Point Values.
  | VUNPCKLPD = 1560
  /// Unpack and Interleave Low Packed Single Precision Floating-Point Values.
  | VUNPCKLPS = 1561
  /// Bitwise Logical XOR of Packed Double Precision Floating-Point Values.
  | VXORPD = 1562
  /// Bitwise Logical XOR of Packed Single Precision Floating-Point Values.
  | VXORPS = 1563
  /// Zero XMM, YMM, and ZMM Registers.
  | VZEROALL = 1564
  /// Zero Upper Bits of YMM and ZMM Registers.
  | VZEROUPPER = 1565
  /// Wait.
  | WAIT = 1566
  /// Write Back and Invalidate Cache.
  | WBINVD = 1567
  /// Write Back and Do Not Invalidate Cache.
  | WBNOINVD = 1568
  /// Write FS/GS Segment Base.
  | WRFSBASE = 1569
  /// Write FS/GS Segment Base.
  | WRGSBASE = 1570
  /// Write to Model Specific Register.
  | WRMSR = 1571
  /// Write List of Model Specific Registers.
  | WRMSRLIST = 1572
  /// Non-Serializing Write to Model Specific Register.
  | WRMSRNS = 1573
  /// Write Data to User Page Key Register.
  | WRPKRU = 1574
  /// Write to Shadow Stack.
  | WRSSD = 1575
  /// Write to Shadow Stack.
  | WRSSQ = 1576
  /// Write to User Shadow Stack.
  | WRUSSD = 1577
  /// Write to User Shadow Stack.
  | WRUSSQ = 1578
  /// Transactional Abort.
  | XABORT = 1579
  /// Hardware Lock Elision Prefix Hints.
  | XACQUIRE = 1580
  /// Exchange and Add.
  | XADD = 1581
  /// Transactional Begin.
  | XBEGIN = 1582
  /// Exchange Register/Memory With Register.
  | XCHG = 1583
  /// Cipher Block Chaining.
  | XCRYPTCBC = 1584
  /// Cipher Feedback Mode.
  | XCRYPTCFB = 1585
  /// Counter Mode (ACE2).
  | XCRYPTCTR = 1586
  /// Electronic code book.
  | XCRYPTECB = 1587
  /// Output Feedback Mode.
  | XCRYPTOFB = 1588
  /// Transactional End.
  | XEND = 1589
  /// Get Value of Extended Control Register.
  | XGETBV = 1590
  /// Table Look-up Translation.
  | XLAT = 1591
  /// Table Look-up Translation.
  | XLATB = 1592
  /// Modular Multiplication.
  | XMODEXP = 1593
  /// Logical Exclusive OR.
  | XOR = 1594
  /// Bitwise Logical XOR of Packed Double Precision Floating-Point Values.
  | XORPD = 1595
  /// Bitwise Logical XOR of Packed Single Precision Floating-Point Values.
  | XORPS = 1596
  /// Hardware Lock Elision Prefix Hints.
  | XRELEASE = 1597
  /// Resume Tracking Load Addresses.
  | XRESLDTRK = 1598
  /// Random Number Generation.
  | XRNG2 = 1599
  /// Restore Processor Extended States.
  | XRSTOR = 1600
  /// Restore Processor Extended States.
  | XRSTOR64 = 1601
  /// Restore Processor Extended States Supervisor.
  | XRSTORS = 1602
  /// Restore Processor Extended States Supervisor.
  | XRSTORS64 = 1603
  /// Save Processor Extended States.
  | XSAVE = 1604
  /// Save Processor Extended States.
  | XSAVE64 = 1605
  /// Save Processor Extended States With Compaction.
  | XSAVEC = 1606
  /// Save Processor Extended States With Compaction.
  | XSAVEC64 = 1607
  /// Save Processor Extended States Optimized.
  | XSAVEOPT = 1608
  /// Save Processor Extended States Optimized.
  | XSAVEOPT64 = 1609
  /// Save Processor Extended States Supervisor.
  | XSAVES = 1610
  /// Save Processor Extended States Supervisor.
  | XSAVES64 = 1611
  /// Set Extended Control Register.
  | XSETBV = 1612
  /// Hash Function SHA-1.
  | XSHA1 = 1613
  /// Hash Function SHA-256.
  | XSHA256 = 1614
  /// Hash Function SHA-384.
  | XSHA384 = 1615
  /// Hash Function SHA-512.
  | XSHA512 = 1616
  /// Store Available Random Bytes.
  | XSTORERNG = 1617
  /// Suspend Tracking Load Addresses.
  | XSUSLDTRK = 1618
  /// Test if in Transactional Execution.
  | XTEST = 1619
  /// Invalid Opcode.
  | InvalOP = 1620

/// Provides functions to check properties of opcodes.
[<RequireQualifiedAccess>]
module internal Opcode =
  let isBranch = function
    | Opcode.CALL | Opcode.JMP | Opcode.RET
    | Opcode.JA | Opcode.JB | Opcode.JBE | Opcode.JCXZ | Opcode.JECXZ
    | Opcode.JG | Opcode.JL | Opcode.JLE | Opcode.JNB | Opcode.JNL
    | Opcode.JNO | Opcode.JNP | Opcode.JNS | Opcode.JNZ | Opcode.JO
    | Opcode.JP | Opcode.JRCXZ | Opcode.JS | Opcode.JZ | Opcode.LOOP
    | Opcode.LOOPE | Opcode.LOOPNE -> true
    | _ -> false

  let isCETInstr = function
    | Opcode.INCSSPD | Opcode.INCSSPQ | Opcode.RDSSPD | Opcode.RDSSPQ
    | Opcode.SAVEPREVSSP | Opcode.RSTORSSP | Opcode.WRSSD | Opcode.WRSSQ
    | Opcode.WRUSSD | Opcode.WRUSSQ | Opcode.SETSSBSY | Opcode.CLRSSBSY ->
      true
    | _ -> false

  let toString = function
    | Opcode.AAA -> "aaa"
    | Opcode.AAD -> "aad"
    | Opcode.AAM -> "aam"
    | Opcode.AAS -> "aas"
    | Opcode.ADC -> "adc"
    | Opcode.ADCX -> "adcx"
    | Opcode.ADD -> "add"
    | Opcode.ADDPD -> "addpd"
    | Opcode.ADDPS -> "addps"
    | Opcode.ADDSD -> "addsd"
    | Opcode.ADDSS -> "addss"
    | Opcode.ADDSUBPD -> "addsubpd"
    | Opcode.ADDSUBPS -> "addsubps"
    | Opcode.ADOX -> "adox"
    | Opcode.AESDEC -> "aesdec"
    | Opcode.AESDEC128KL -> "aesdec128kl"
    | Opcode.AESDEC256KL -> "aesdec256kl"
    | Opcode.AESDECLAST -> "aesdeclast"
    | Opcode.AESDECWIDE128KL -> "aesdecwide128kl"
    | Opcode.AESDECWIDE256KL -> "aesdecwide256kl"
    | Opcode.AESENC -> "aesenc"
    | Opcode.AESENC128KL -> "aesenc128kl"
    | Opcode.AESENC256KL -> "aesenc256kl"
    | Opcode.AESENCLAST -> "aesenclast"
    | Opcode.AESENCWIDE128KL -> "aesencwide128kl"
    | Opcode.AESENCWIDE256KL -> "aesencwide256kl"
    | Opcode.AESIMC -> "aesimc"
    | Opcode.AESKEYGENASSIST -> "aeskeygenassist"
    | Opcode.AND -> "and"
    | Opcode.ANDN -> "andn"
    | Opcode.ANDNPD -> "andnpd"
    | Opcode.ANDNPS -> "andnps"
    | Opcode.ANDPD -> "andpd"
    | Opcode.ANDPS -> "andps"
    | Opcode.ARPL -> "arpl"
    | Opcode.BEXTR -> "bextr"
    | Opcode.BLENDPD -> "blendpd"
    | Opcode.BLENDPS -> "blendps"
    | Opcode.BLENDVPD -> "blendvpd"
    | Opcode.BLENDVPS -> "blendvps"
    | Opcode.BLSI -> "blsi"
    | Opcode.BLSMSK -> "blsmsk"
    | Opcode.BLSR -> "blsr"
    | Opcode.BNDCL -> "bndcl"
    | Opcode.BNDCN -> "bndcn"
    | Opcode.BNDCU -> "bndcu"
    | Opcode.BNDLDX -> "bndldx"
    | Opcode.BNDMK -> "bndmk"
    | Opcode.BNDMOV -> "bndmov"
    | Opcode.BNDSTX -> "bndstx"
    | Opcode.BOUND -> "bound"
    | Opcode.BSF -> "bsf"
    | Opcode.BSR -> "bsr"
    | Opcode.BSWAP -> "bswap"
    | Opcode.BT -> "bt"
    | Opcode.BTC -> "btc"
    | Opcode.BTR -> "btr"
    | Opcode.BTS -> "bts"
    | Opcode.BZHI -> "bzhi"
    | Opcode.CALL -> "call"
    | Opcode.CBW -> "cbw"
    | Opcode.CCS_ENCRYPT -> "ccs_encrypt"
    | Opcode.CCS_HASH -> "ccs_hash"
    | Opcode.CDQ -> "cdq"
    | Opcode.CDQE -> "cdqe"
    | Opcode.CLAC -> "clac"
    | Opcode.CLC -> "clc"
    | Opcode.CLD -> "cld"
    | Opcode.CLDEMOTE -> "cldemote"
    | Opcode.CLFLUSH -> "clflush"
    | Opcode.CLFLUSHOPT -> "clflushopt"
    | Opcode.CLI -> "cli"
    | Opcode.CLRSSBSY -> "clrssbsy"
    | Opcode.CLTS -> "clts"
    | Opcode.CLUI -> "clui"
    | Opcode.CLWB -> "clwb"
    | Opcode.CMC -> "cmc"
    | Opcode.CMOVA -> "cmova"
    | Opcode.CMOVAE -> "cmovae"
    | Opcode.CMOVB -> "cmovb"
    | Opcode.CMOVBE -> "cmovbe"
    | Opcode.CMOVC -> "cmovc"
    | Opcode.CMOVE -> "cmove"
    | Opcode.CMOVG -> "cmovg"
    | Opcode.CMOVGE -> "cmovge"
    | Opcode.CMOVL -> "cmovl"
    | Opcode.CMOVLE -> "cmovle"
    | Opcode.CMOVNA -> "cmovna"
    | Opcode.CMOVNAE -> "cmovnae"
    | Opcode.CMOVNB -> "cmovnb"
    | Opcode.CMOVNBE -> "cmovnbe"
    | Opcode.CMOVNC -> "cmovnc"
    | Opcode.CMOVNE -> "cmovne"
    | Opcode.CMOVNG -> "cmovng"
    | Opcode.CMOVNGE -> "cmovnge"
    | Opcode.CMOVNL -> "cmovnl"
    | Opcode.CMOVNLE -> "cmovnle"
    | Opcode.CMOVNO -> "cmovno"
    | Opcode.CMOVNP -> "cmovnp"
    | Opcode.CMOVNS -> "cmovns"
    | Opcode.CMOVNZ -> "cmovnz"
    | Opcode.CMOVO -> "cmovo"
    | Opcode.CMOVP -> "cmovp"
    | Opcode.CMOVPE -> "cmovpe"
    | Opcode.CMOVPO -> "cmovpo"
    | Opcode.CMOVS -> "cmovs"
    | Opcode.CMOVZ -> "cmovz"
    | Opcode.CMP -> "cmp"
    | Opcode.CMPBEXADD -> "cmpbexadd"
    | Opcode.CMPBXADD -> "cmpbxadd"
    | Opcode.CMPLEXADD -> "cmplexadd"
    | Opcode.CMPLXADD -> "cmplxadd"
    | Opcode.CMPNBEXADD -> "cmpnbexadd"
    | Opcode.CMPNBXADD -> "cmpnbxadd"
    | Opcode.CMPNLEXADD -> "cmpnlexadd"
    | Opcode.CMPNLXADD -> "cmpnlxadd"
    | Opcode.CMPNOXADD -> "cmpnoxadd"
    | Opcode.CMPNPXADD -> "cmpnpxadd"
    | Opcode.CMPNSXADD -> "cmpnsxadd"
    | Opcode.CMPNZXADD -> "cmpnzxadd"
    | Opcode.CMPOXADD -> "cmpoxadd"
    | Opcode.CMPPD -> "cmppd"
    | Opcode.CMPPS -> "cmpps"
    | Opcode.CMPPXADD -> "cmppxadd"
    | Opcode.CMPS -> "cmps"
    | Opcode.CMPSB -> "cmpsb"
    | Opcode.CMPSD -> "cmpsd"
    | Opcode.CMPSQ -> "cmpsq"
    | Opcode.CMPSS -> "cmpss"
    | Opcode.CMPSW -> "cmpsw"
    | Opcode.CMPSXADD -> "cmpsxadd"
    | Opcode.CMPXCHG -> "cmpxchg"
    | Opcode.CMPXCHG16B -> "cmpxchg16b"
    | Opcode.CMPXCHG8B -> "cmpxchg8b"
    | Opcode.CMPZXADD -> "cmpzxadd"
    | Opcode.COMISD -> "comisd"
    | Opcode.COMISS -> "comiss"
    | Opcode.CPUID -> "cpuid"
    | Opcode.CQO -> "cqo"
    | Opcode.CRC32 -> "crc32"
    | Opcode.CVTDQ2PD -> "cvtdq2pd"
    | Opcode.CVTDQ2PS -> "cvtdq2ps"
    | Opcode.CVTPD2DQ -> "cvtpd2dq"
    | Opcode.CVTPD2PI -> "cvtpd2pi"
    | Opcode.CVTPD2PS -> "cvtpd2ps"
    | Opcode.CVTPI2PD -> "cvtpi2pd"
    | Opcode.CVTPI2PS -> "cvtpi2ps"
    | Opcode.CVTPS2DQ -> "cvtps2dq"
    | Opcode.CVTPS2PD -> "cvtps2pd"
    | Opcode.CVTPS2PI -> "cvtps2pi"
    | Opcode.CVTSD2SI -> "cvtsd2si"
    | Opcode.CVTSD2SS -> "cvtsd2ss"
    | Opcode.CVTSI2SD -> "cvtsi2sd"
    | Opcode.CVTSI2SS -> "cvtsi2ss"
    | Opcode.CVTSS2SD -> "cvtss2sd"
    | Opcode.CVTSS2SI -> "cvtss2si"
    | Opcode.CVTTPD2DQ -> "cvttpd2dq"
    | Opcode.CVTTPD2PI -> "cvttpd2pi"
    | Opcode.CVTTPS2DQ -> "cvttps2dq"
    | Opcode.CVTTPS2PI -> "cvttps2pi"
    | Opcode.CVTTSD2SI -> "cvttsd2si"
    | Opcode.CVTTSS2SI -> "cvttss2si"
    | Opcode.CWD -> "cwd"
    | Opcode.CWDE -> "cwde"
    | Opcode.DAA -> "daa"
    | Opcode.DAS -> "das"
    | Opcode.DEC -> "dec"
    | Opcode.DIV -> "div"
    | Opcode.DIVPD -> "divpd"
    | Opcode.DIVPS -> "divps"
    | Opcode.DIVSD -> "divsd"
    | Opcode.DIVSS -> "divss"
    | Opcode.DPPD -> "dppd"
    | Opcode.DPPS -> "dpps"
    | Opcode.EMMS -> "emms"
    | Opcode.ENCODEKEY128 -> "encodekey128"
    | Opcode.ENCODEKEY256 -> "encodekey256"
    | Opcode.ENDBR32 -> "endbr32"
    | Opcode.ENDBR64 -> "endbr64"
    | Opcode.ENQCMD -> "enqcmd"
    | Opcode.ENQCMDS -> "enqcmds"
    | Opcode.ENTER -> "enter"
    | Opcode.EXTRACTPS -> "extractps"
    | Opcode.EXTRQ -> "extrq"
    | Opcode.F2XM1 -> "f2xm1"
    | Opcode.FABS -> "fabs"
    | Opcode.FADD -> "fadd"
    | Opcode.FADDP -> "faddp"
    | Opcode.FBLD -> "fbld"
    | Opcode.FBSTP -> "fbstp"
    | Opcode.FCHS -> "fchs"
    | Opcode.FCLEX -> "fclex"
    | Opcode.FCMOVB -> "fcmovb"
    | Opcode.FCMOVBE -> "fcmovbe"
    | Opcode.FCMOVE -> "fcmove"
    | Opcode.FCMOVNB -> "fcmovnb"
    | Opcode.FCMOVNBE -> "fcmovnbe"
    | Opcode.FCMOVNE -> "fcmovne"
    | Opcode.FCMOVNU -> "fcmovnu"
    | Opcode.FCMOVU -> "fcmovu"
    | Opcode.FCOM -> "fcom"
    | Opcode.FCOMI -> "fcomi"
    | Opcode.FCOMIP -> "fcomip"
    | Opcode.FCOMP -> "fcomp"
    | Opcode.FCOMPP -> "fcompp"
    | Opcode.FCOS -> "fcos"
    | Opcode.FDECSTP -> "fdecstp"
    | Opcode.FDIV -> "fdiv"
    | Opcode.FDIVP -> "fdivp"
    | Opcode.FDIVR -> "fdivr"
    | Opcode.FDIVRP -> "fdivrp"
    | Opcode.FFREE -> "ffree"
    | Opcode.FFREEP -> "ffreep"
    | Opcode.FIADD -> "fiadd"
    | Opcode.FICOM -> "ficom"
    | Opcode.FICOMP -> "ficomp"
    | Opcode.FIDIV -> "fidiv"
    | Opcode.FIDIVR -> "fidivr"
    | Opcode.FILD -> "fild"
    | Opcode.FIMUL -> "fimul"
    | Opcode.FINCSTP -> "fincstp"
    | Opcode.FINIT -> "finit"
    | Opcode.FIST -> "fist"
    | Opcode.FISTP -> "fistp"
    | Opcode.FISTTP -> "fisttp"
    | Opcode.FISUB -> "fisub"
    | Opcode.FISUBR -> "fisubr"
    | Opcode.FLD -> "fld"
    | Opcode.FLD1 -> "fld1"
    | Opcode.FLDCW -> "fldcw"
    | Opcode.FLDENV -> "fldenv"
    | Opcode.FLDL2E -> "fldl2e"
    | Opcode.FLDL2T -> "fldl2t"
    | Opcode.FLDLG2 -> "fldlg2"
    | Opcode.FLDLN2 -> "fldln2"
    | Opcode.FLDPI -> "fldpi"
    | Opcode.FLDZ -> "fldz"
    | Opcode.FMUL -> "fmul"
    | Opcode.FMULP -> "fmulp"
    | Opcode.FNCLEX -> "fnclex"
    | Opcode.FNINIT -> "fninit"
    | Opcode.FNOP -> "fnop"
    | Opcode.FNSAVE -> "fnsave"
    | Opcode.FNSTCW -> "fnstcw"
    | Opcode.FNSTENV -> "fnstenv"
    | Opcode.FNSTSW -> "fnstsw"
    | Opcode.FPATAN -> "fpatan"
    | Opcode.FPREM -> "fprem"
    | Opcode.FPREM1 -> "fprem1"
    | Opcode.FPTAN -> "fptan"
    | Opcode.FRNDINT -> "frndint"
    | Opcode.FRSTOR -> "frstor"
    | Opcode.FSAVE -> "fsave"
    | Opcode.FSCALE -> "fscale"
    | Opcode.FSIN -> "fsin"
    | Opcode.FSINCOS -> "fsincos"
    | Opcode.FSQRT -> "fsqrt"
    | Opcode.FST -> "fst"
    | Opcode.FSTCW -> "fstcw"
    | Opcode.FSTENV -> "fstenv"
    | Opcode.FSTP -> "fstp"
    | Opcode.FSTSW -> "fstsw"
    | Opcode.FSUB -> "fsub"
    | Opcode.FSUBP -> "fsubp"
    | Opcode.FSUBR -> "fsubr"
    | Opcode.FSUBRP -> "fsubrp"
    | Opcode.FTST -> "ftst"
    | Opcode.FUCOM -> "fucom"
    | Opcode.FUCOMI -> "fucomi"
    | Opcode.FUCOMIP -> "fucomip"
    | Opcode.FUCOMP -> "fucomp"
    | Opcode.FUCOMPP -> "fucompp"
    | Opcode.FWAIT -> "fwait"
    | Opcode.FXAM -> "fxam"
    | Opcode.FXCH -> "fxch"
    | Opcode.FXRSTOR -> "fxrstor"
    | Opcode.FXRSTOR64 -> "fxrstor64"
    | Opcode.FXSAVE -> "fxsave"
    | Opcode.FXSAVE64 -> "fxsave64"
    | Opcode.FXTRACT -> "fxtract"
    | Opcode.FYL2X -> "fyl2x"
    | Opcode.FYL2XP1 -> "fyl2xp1"
    | Opcode.GETSEC -> "getsec"
    | Opcode.GF2P8AFFINEINVQB -> "gf2p8affineinvqb"
    | Opcode.GF2P8AFFINEQB -> "gf2p8affineqb"
    | Opcode.GF2P8MULB -> "gf2p8mulb"
    | Opcode.HADDPD -> "haddpd"
    | Opcode.HADDPS -> "haddps"
    | Opcode.HLT -> "hlt"
    | Opcode.HRESET -> "hreset"
    | Opcode.HSUBPD -> "hsubpd"
    | Opcode.HSUBPS -> "hsubps"
    | Opcode.IDIV -> "idiv"
    | Opcode.IMUL -> "imul"
    | Opcode.IN -> "in"
    | Opcode.INC -> "inc"
    | Opcode.INCSSPD -> "incsspd"
    | Opcode.INCSSPQ -> "incsspq"
    | Opcode.INS -> "ins"
    | Opcode.INSB -> "insb"
    | Opcode.INSD -> "insd"
    | Opcode.INSERTPS -> "insertps"
    | Opcode.INSERTQ -> "insertq"
    | Opcode.INSW -> "insw"
    | Opcode.INT -> "int"
    | Opcode.INT1 -> "int1"
    | Opcode.INT3 -> "int3"
    | Opcode.INTO -> "into"
    | Opcode.INVD -> "invd"
    | Opcode.INVLPG -> "invlpg"
    | Opcode.INVPCID -> "invpcid"
    | Opcode.IRET -> "iret"
    | Opcode.IRETD -> "iretd"
    | Opcode.IRETQ -> "iretq"
    | Opcode.IRETW -> "iretw"
    | Opcode.JA -> "ja"
    | Opcode.JB -> "jb"
    | Opcode.JBE -> "jbe"
    | Opcode.JCXZ -> "jcxz"
    | Opcode.JECXZ -> "jecxz"
    | Opcode.JG -> "jg"
    | Opcode.JL -> "jl"
    | Opcode.JLE -> "jle"
    | Opcode.JMP -> "jmp"
    | Opcode.JNB -> "jnb"
    | Opcode.JNL -> "jnl"
    | Opcode.JNO -> "jno"
    | Opcode.JNP -> "jnp"
    | Opcode.JNS -> "jns"
    | Opcode.JNZ -> "jnz"
    | Opcode.JO -> "jo"
    | Opcode.JP -> "jp"
    | Opcode.JRCXZ -> "jrcxz"
    | Opcode.JS -> "js"
    | Opcode.JZ -> "jz"
    | Opcode.KADDB -> "kaddb"
    | Opcode.KADDD -> "kaddd"
    | Opcode.KADDQ -> "kaddq"
    | Opcode.KADDW -> "kaddw"
    | Opcode.KANDB -> "kandb"
    | Opcode.KANDD -> "kandd"
    | Opcode.KANDNB -> "kandnb"
    | Opcode.KANDND -> "kandnd"
    | Opcode.KANDNQ -> "kandnq"
    | Opcode.KANDNW -> "kandnw"
    | Opcode.KANDQ -> "kandq"
    | Opcode.KANDW -> "kandw"
    | Opcode.KMOVB -> "kmovb"
    | Opcode.KMOVD -> "kmovd"
    | Opcode.KMOVQ -> "kmovq"
    | Opcode.KMOVW -> "kmovw"
    | Opcode.KNOTB -> "knotb"
    | Opcode.KNOTD -> "knotd"
    | Opcode.KNOTQ -> "knotq"
    | Opcode.KNOTW -> "knotw"
    | Opcode.KORB -> "korb"
    | Opcode.KORD -> "kord"
    | Opcode.KORQ -> "korq"
    | Opcode.KORTESTB -> "kortestb"
    | Opcode.KORTESTD -> "kortestd"
    | Opcode.KORTESTQ -> "kortestq"
    | Opcode.KORTESTW -> "kortestw"
    | Opcode.KORW -> "korw"
    | Opcode.KSHIFTLB -> "kshiftlb"
    | Opcode.KSHIFTLD -> "kshiftld"
    | Opcode.KSHIFTLQ -> "kshiftlq"
    | Opcode.KSHIFTLW -> "kshiftlw"
    | Opcode.KSHIFTRB -> "kshiftrb"
    | Opcode.KSHIFTRD -> "kshiftrd"
    | Opcode.KSHIFTRQ -> "kshiftrq"
    | Opcode.KSHIFTRW -> "kshiftrw"
    | Opcode.KTESTB -> "ktestb"
    | Opcode.KTESTD -> "ktestd"
    | Opcode.KTESTQ -> "ktestq"
    | Opcode.KTESTW -> "ktestw"
    | Opcode.KUNPCKBW -> "kunpckbw"
    | Opcode.KUNPCKDQ -> "kunpckdq"
    | Opcode.KUNPCKWD -> "kunpckwd"
    | Opcode.KXNORB -> "kxnorb"
    | Opcode.KXNORD -> "kxnord"
    | Opcode.KXNORQ -> "kxnorq"
    | Opcode.KXNORW -> "kxnorw"
    | Opcode.KXORB -> "kxorb"
    | Opcode.KXORD -> "kxord"
    | Opcode.KXORQ -> "kxorq"
    | Opcode.KXORW -> "kxorw"
    | Opcode.LAHF -> "lahf"
    | Opcode.LAR -> "lar"
    | Opcode.LDDQU -> "lddqu"
    | Opcode.LDMXCSR -> "ldmxcsr"
    | Opcode.LDS -> "lds"
    | Opcode.LDTILECFG -> "ldtilecfg"
    | Opcode.LEA -> "lea"
    | Opcode.LEAVE -> "leave"
    | Opcode.LES -> "les"
    | Opcode.LFENCE -> "lfence"
    | Opcode.LFS -> "lfs"
    | Opcode.LGDT -> "lgdt"
    | Opcode.LGS -> "lgs"
    | Opcode.LIDT -> "lidt"
    | Opcode.LLDT -> "lldt"
    | Opcode.LMSW -> "lmsw"
    | Opcode.LOADIWKEY -> "loadiwkey"
    | Opcode.LOCK -> "lock"
    | Opcode.LODS -> "lods"
    | Opcode.LODSB -> "lodsb"
    | Opcode.LODSD -> "lodsd"
    | Opcode.LODSQ -> "lodsq"
    | Opcode.LODSW -> "lodsw"
    | Opcode.LOOP -> "loop"
    | Opcode.LOOPE -> "loope"
    | Opcode.LOOPNE -> "loopne"
    | Opcode.LSL -> "lsl"
    | Opcode.LSS -> "lss"
    | Opcode.LTR -> "ltr"
    | Opcode.LZCNT -> "lzcnt"
    | Opcode.MASKMOVDQU -> "maskmovdqu"
    | Opcode.MASKMOVQ -> "maskmovq"
    | Opcode.MAXPD -> "maxpd"
    | Opcode.MAXPS -> "maxps"
    | Opcode.MAXSD -> "maxsd"
    | Opcode.MAXSS -> "maxss"
    | Opcode.MFENCE -> "mfence"
    | Opcode.MINPD -> "minpd"
    | Opcode.MINPS -> "minps"
    | Opcode.MINSD -> "minsd"
    | Opcode.MINSS -> "minss"
    | Opcode.MONITOR -> "monitor"
    | Opcode.MONTMUL -> "montmul"
    | Opcode.MONTMUL2 -> "montmul2"
    | Opcode.MOV -> "mov"
    | Opcode.MOVAPD -> "movapd"
    | Opcode.MOVAPS -> "movaps"
    | Opcode.MOVBE -> "movbe"
    | Opcode.MOVD -> "movd"
    | Opcode.MOVDDUP -> "movddup"
    | Opcode.MOVDIR64B -> "movdir64b"
    | Opcode.MOVDIRI -> "movdiri"
    | Opcode.MOVDQ2Q -> "movdq2q"
    | Opcode.MOVDQA -> "movdqa"
    | Opcode.MOVDQU -> "movdqu"
    | Opcode.MOVHLPS -> "movhlps"
    | Opcode.MOVHPD -> "movhpd"
    | Opcode.MOVHPS -> "movhps"
    | Opcode.MOVLHPS -> "movlhps"
    | Opcode.MOVLPD -> "movlpd"
    | Opcode.MOVLPS -> "movlps"
    | Opcode.MOVMSKPD -> "movmskpd"
    | Opcode.MOVMSKPS -> "movmskps"
    | Opcode.MOVNTDQ -> "movntdq"
    | Opcode.MOVNTDQA -> "movntdqa"
    | Opcode.MOVNTI -> "movnti"
    | Opcode.MOVNTPD -> "movntpd"
    | Opcode.MOVNTPS -> "movntps"
    | Opcode.MOVNTQ -> "movntq"
    | Opcode.MOVQ -> "movq"
    | Opcode.MOVQ2DQ -> "movq2dq"
    | Opcode.MOVS -> "movs"
    | Opcode.MOVSB -> "movsb"
    | Opcode.MOVSD -> "movsd"
    | Opcode.MOVSHDUP -> "movshdup"
    | Opcode.MOVSLDUP -> "movsldup"
    | Opcode.MOVSQ -> "movsq"
    | Opcode.MOVSS -> "movss"
    | Opcode.MOVSW -> "movsw"
    | Opcode.MOVSX -> "movsx"
    | Opcode.MOVSXD -> "movsxd"
    | Opcode.MOVUPD -> "movupd"
    | Opcode.MOVUPS -> "movups"
    | Opcode.MOVZX -> "movzx"
    | Opcode.MPSADBW -> "mpsadbw"
    | Opcode.MUL -> "mul"
    | Opcode.MULPD -> "mulpd"
    | Opcode.MULPS -> "mulps"
    | Opcode.MULSD -> "mulsd"
    | Opcode.MULSS -> "mulss"
    | Opcode.MULX -> "mulx"
    | Opcode.MWAIT -> "mwait"
    | Opcode.NEG -> "neg"
    | Opcode.NOP -> "nop"
    | Opcode.NOT -> "not"
    | Opcode.OR -> "or"
    | Opcode.ORPD -> "orpd"
    | Opcode.ORPS -> "orps"
    | Opcode.OUT -> "out"
    | Opcode.OUTS -> "outs"
    | Opcode.OUTSB -> "outsb"
    | Opcode.OUTSD -> "outsd"
    | Opcode.OUTSW -> "outsw"
    | Opcode.PABSB -> "pabsb"
    | Opcode.PABSD -> "pabsd"
    | Opcode.PABSW -> "pabsw"
    | Opcode.PACKSSDW -> "packssdw"
    | Opcode.PACKSSWB -> "packsswb"
    | Opcode.PACKUSDW -> "packusdw"
    | Opcode.PACKUSWB -> "packuswb"
    | Opcode.PADDB -> "paddb"
    | Opcode.PADDD -> "paddd"
    | Opcode.PADDQ -> "paddq"
    | Opcode.PADDSB -> "paddsb"
    | Opcode.PADDSW -> "paddsw"
    | Opcode.PADDUSB -> "paddusb"
    | Opcode.PADDUSW -> "paddusw"
    | Opcode.PADDW -> "paddw"
    | Opcode.PALIGNR -> "palignr"
    | Opcode.PAND -> "pand"
    | Opcode.PANDN -> "pandn"
    | Opcode.PAUSE -> "pause"
    | Opcode.PAVGB -> "pavgb"
    | Opcode.PAVGW -> "pavgw"
    | Opcode.PBLENDVB -> "pblendvb"
    | Opcode.PBLENDW -> "pblendw"
    | Opcode.PCLMULQDQ -> "pclmulqdq"
    | Opcode.PCMPEQB -> "pcmpeqb"
    | Opcode.PCMPEQD -> "pcmpeqd"
    | Opcode.PCMPEQQ -> "pcmpeqq"
    | Opcode.PCMPEQW -> "pcmpeqw"
    | Opcode.PCMPESTRI -> "pcmpestri"
    | Opcode.PCMPESTRM -> "pcmpestrm"
    | Opcode.PCMPGTB -> "pcmpgtb"
    | Opcode.PCMPGTD -> "pcmpgtd"
    | Opcode.PCMPGTQ -> "pcmpgtq"
    | Opcode.PCMPGTW -> "pcmpgtw"
    | Opcode.PCMPISTRI -> "pcmpistri"
    | Opcode.PCMPISTRM -> "pcmpistrm"
    | Opcode.PCONFIG -> "pconfig"
    | Opcode.PDEP -> "pdep"
    | Opcode.PEXT -> "pext"
    | Opcode.PEXTRB -> "pextrb"
    | Opcode.PEXTRD -> "pextrd"
    | Opcode.PEXTRQ -> "pextrq"
    | Opcode.PEXTRW -> "pextrw"
    | Opcode.PHADDD -> "phaddd"
    | Opcode.PHADDSW -> "phaddsw"
    | Opcode.PHADDW -> "phaddw"
    | Opcode.PHMINPOSUW -> "phminposuw"
    | Opcode.PHSUBD -> "phsubd"
    | Opcode.PHSUBSW -> "phsubsw"
    | Opcode.PHSUBW -> "phsubw"
    | Opcode.PINSRB -> "pinsrb"
    | Opcode.PINSRD -> "pinsrd"
    | Opcode.PINSRQ -> "pinsrq"
    | Opcode.PINSRW -> "pinsrw"
    | Opcode.PMADDUBSW -> "pmaddubsw"
    | Opcode.PMADDWD -> "pmaddwd"
    | Opcode.PMAXSB -> "pmaxsb"
    | Opcode.PMAXSD -> "pmaxsd"
    | Opcode.PMAXSW -> "pmaxsw"
    | Opcode.PMAXUB -> "pmaxub"
    | Opcode.PMAXUD -> "pmaxud"
    | Opcode.PMAXUW -> "pmaxuw"
    | Opcode.PMINSB -> "pminsb"
    | Opcode.PMINSD -> "pminsd"
    | Opcode.PMINSW -> "pminsw"
    | Opcode.PMINUB -> "pminub"
    | Opcode.PMINUD -> "pminud"
    | Opcode.PMINUW -> "pminuw"
    | Opcode.PMOVMSKB -> "pmovmskb"
    | Opcode.PMOVSXBD -> "pmovsxbd"
    | Opcode.PMOVSXBQ -> "pmovsxbq"
    | Opcode.PMOVSXBW -> "pmovsxbw"
    | Opcode.PMOVSXDQ -> "pmovsxdq"
    | Opcode.PMOVSXWD -> "pmovsxwd"
    | Opcode.PMOVSXWQ -> "pmovsxwq"
    | Opcode.PMOVZXBD -> "pmovzxbd"
    | Opcode.PMOVZXBQ -> "pmovzxbq"
    | Opcode.PMOVZXBW -> "pmovzxbw"
    | Opcode.PMOVZXDQ -> "pmovzxdq"
    | Opcode.PMOVZXWD -> "pmovzxwd"
    | Opcode.PMOVZXWQ -> "pmovzxwq"
    | Opcode.PMULDQ -> "pmuldq"
    | Opcode.PMULHRSW -> "pmulhrsw"
    | Opcode.PMULHUW -> "pmulhuw"
    | Opcode.PMULHW -> "pmulhw"
    | Opcode.PMULLD -> "pmulld"
    | Opcode.PMULLW -> "pmullw"
    | Opcode.PMULUDQ -> "pmuludq"
    | Opcode.POP -> "pop"
    | Opcode.POPA -> "popa"
    | Opcode.POPAD -> "popad"
    | Opcode.POPCNT -> "popcnt"
    | Opcode.POPF -> "popf"
    | Opcode.POPFD -> "popfd"
    | Opcode.POPFQ -> "popfq"
    | Opcode.POR -> "por"
    | Opcode.PREFETCHIT0 -> "prefetchit0"
    | Opcode.PREFETCHIT1 -> "prefetchit1"
    | Opcode.PREFETCHNTA -> "prefetchnta"
    | Opcode.PREFETCHT0 -> "prefetcht0"
    | Opcode.PREFETCHT1 -> "prefetcht1"
    | Opcode.PREFETCHT2 -> "prefetcht2"
    | Opcode.PREFETCHW -> "prefetchw"
    | Opcode.PREFETCHWT1 -> "prefetchwt1"
    | Opcode.PSADBW -> "psadbw"
    | Opcode.PSHUFB -> "pshufb"
    | Opcode.PSHUFD -> "pshufd"
    | Opcode.PSHUFHW -> "pshufhw"
    | Opcode.PSHUFLW -> "pshuflw"
    | Opcode.PSHUFW -> "pshufw"
    | Opcode.PSIGNB -> "psignb"
    | Opcode.PSIGND -> "psignd"
    | Opcode.PSIGNW -> "psignw"
    | Opcode.PSLLD -> "pslld"
    | Opcode.PSLLDQ -> "pslldq"
    | Opcode.PSLLQ -> "psllq"
    | Opcode.PSLLW -> "psllw"
    | Opcode.PSRAD -> "psrad"
    | Opcode.PSRAW -> "psraw"
    | Opcode.PSRLD -> "psrld"
    | Opcode.PSRLDQ -> "psrldq"
    | Opcode.PSRLQ -> "psrlq"
    | Opcode.PSRLW -> "psrlw"
    | Opcode.PSUBB -> "psubb"
    | Opcode.PSUBD -> "psubd"
    | Opcode.PSUBQ -> "psubq"
    | Opcode.PSUBSB -> "psubsb"
    | Opcode.PSUBSW -> "psubsw"
    | Opcode.PSUBUSB -> "psubusb"
    | Opcode.PSUBUSW -> "psubusw"
    | Opcode.PSUBW -> "psubw"
    | Opcode.PTEST -> "ptest"
    | Opcode.PTWRITE -> "ptwrite"
    | Opcode.PUNPCKHBW -> "punpckhbw"
    | Opcode.PUNPCKHDQ -> "punpckhdq"
    | Opcode.PUNPCKHQDQ -> "punpckhqdq"
    | Opcode.PUNPCKHWD -> "punpckhwd"
    | Opcode.PUNPCKLBW -> "punpcklbw"
    | Opcode.PUNPCKLDQ -> "punpckldq"
    | Opcode.PUNPCKLQDQ -> "punpcklqdq"
    | Opcode.PUNPCKLWD -> "punpcklwd"
    | Opcode.PUSH -> "push"
    | Opcode.PUSHA -> "pusha"
    | Opcode.PUSHAD -> "pushad"
    | Opcode.PUSHF -> "pushf"
    | Opcode.PUSHFD -> "pushfd"
    | Opcode.PUSHFQ -> "pushfq"
    | Opcode.PXOR -> "pxor"
    | Opcode.RCL -> "rcl"
    | Opcode.RCPPS -> "rcpps"
    | Opcode.RCPSS -> "rcpss"
    | Opcode.RCR -> "rcr"
    | Opcode.RDFSBASE -> "rdfsbase"
    | Opcode.RDGSBASE -> "rdgsbase"
    | Opcode.RDMSR -> "rdmsr"
    | Opcode.RDMSRLIST -> "rdmsrlist"
    | Opcode.RDPID -> "rdpid"
    | Opcode.RDPKRU -> "rdpkru"
    | Opcode.RDPMC -> "rdpmc"
    | Opcode.RDRAND -> "rdrand"
    | Opcode.RDSEED -> "rdseed"
    | Opcode.RDSSPD -> "rdsspd"
    | Opcode.RDSSPQ -> "rdsspq"
    | Opcode.RDTSC -> "rdtsc"
    | Opcode.RDTSCP -> "rdtscp"
    | Opcode.RET -> "ret"
    | Opcode.ROL -> "rol"
    | Opcode.ROR -> "ror"
    | Opcode.RORX -> "rorx"
    | Opcode.ROUNDPD -> "roundpd"
    | Opcode.ROUNDPS -> "roundps"
    | Opcode.ROUNDSD -> "roundsd"
    | Opcode.ROUNDSS -> "roundss"
    | Opcode.RSM -> "rsm"
    | Opcode.RSQRTPS -> "rsqrtps"
    | Opcode.RSQRTSS -> "rsqrtss"
    | Opcode.RSTORSSP -> "rstorssp"
    | Opcode.SAHF -> "sahf"
    | Opcode.SAR -> "sar"
    | Opcode.SARX -> "sarx"
    | Opcode.SAVEPREVSSP -> "saveprevssp"
    | Opcode.SBB -> "sbb"
    | Opcode.SCAS -> "scas"
    | Opcode.SCASB -> "scasb"
    | Opcode.SCASD -> "scasd"
    | Opcode.SCASQ -> "scasq"
    | Opcode.SCASW -> "scasw"
    | Opcode.SENDUIPI -> "senduipi"
    | Opcode.SERIALIZE -> "serialize"
    | Opcode.SETA -> "seta"
    | Opcode.SETAE -> "setae"
    | Opcode.SETB -> "setb"
    | Opcode.SETBE -> "setbe"
    | Opcode.SETC -> "setc"
    | Opcode.SETE -> "sete"
    | Opcode.SETG -> "setg"
    | Opcode.SETGE -> "setge"
    | Opcode.SETL -> "setl"
    | Opcode.SETLE -> "setle"
    | Opcode.SETNA -> "setna"
    | Opcode.SETNAE -> "setnae"
    | Opcode.SETNB -> "setnb"
    | Opcode.SETNBE -> "setnbe"
    | Opcode.SETNC -> "setnc"
    | Opcode.SETNE -> "setne"
    | Opcode.SETNG -> "setng"
    | Opcode.SETNGE -> "setnge"
    | Opcode.SETNL -> "setnl"
    | Opcode.SETNLE -> "setnle"
    | Opcode.SETNO -> "setno"
    | Opcode.SETNP -> "setnp"
    | Opcode.SETNS -> "setns"
    | Opcode.SETNZ -> "setnz"
    | Opcode.SETO -> "seto"
    | Opcode.SETP -> "setp"
    | Opcode.SETPE -> "setpe"
    | Opcode.SETPO -> "setpo"
    | Opcode.SETS -> "sets"
    | Opcode.SETSSBSY -> "setssbsy"
    | Opcode.SETZ -> "setz"
    | Opcode.SFENCE -> "sfence"
    | Opcode.SGDT -> "sgdt"
    | Opcode.SHA1MSG1 -> "sha1msg1"
    | Opcode.SHA1MSG2 -> "sha1msg2"
    | Opcode.SHA1NEXTE -> "sha1nexte"
    | Opcode.SHA1RNDS4 -> "sha1rnds4"
    | Opcode.SHA256MSG1 -> "sha256msg1"
    | Opcode.SHA256MSG2 -> "sha256msg2"
    | Opcode.SHA256RNDS2 -> "sha256rnds2"
    | Opcode.SHL -> "shl"
    | Opcode.SHLD -> "shld"
    | Opcode.SHLX -> "shlx"
    | Opcode.SHR -> "shr"
    | Opcode.SHRD -> "shrd"
    | Opcode.SHRX -> "shrx"
    | Opcode.SHUFPD -> "shufpd"
    | Opcode.SHUFPS -> "shufps"
    | Opcode.SIDT -> "sidt"
    | Opcode.SLDT -> "sldt"
    | Opcode.SM2 -> "sm2"
    | Opcode.SMSW -> "smsw"
    | Opcode.SQRTPD -> "sqrtpd"
    | Opcode.SQRTPS -> "sqrtps"
    | Opcode.SQRTSD -> "sqrtsd"
    | Opcode.SQRTSS -> "sqrtss"
    | Opcode.STAC -> "stac"
    | Opcode.STC -> "stc"
    | Opcode.STD -> "std"
    | Opcode.STI -> "sti"
    | Opcode.STMXCSR -> "stmxcsr"
    | Opcode.STOS -> "stos"
    | Opcode.STOSB -> "stosb"
    | Opcode.STOSD -> "stosd"
    | Opcode.STOSQ -> "stosq"
    | Opcode.STOSW -> "stosw"
    | Opcode.STR -> "str"
    | Opcode.STTILECFG -> "sttilecfg"
    | Opcode.STUI -> "stui"
    | Opcode.SUB -> "sub"
    | Opcode.SUBPD -> "subpd"
    | Opcode.SUBPS -> "subps"
    | Opcode.SUBSD -> "subsd"
    | Opcode.SUBSS -> "subss"
    | Opcode.SWAPGS -> "swapgs"
    | Opcode.SYSCALL -> "syscall"
    | Opcode.SYSENTER -> "sysenter"
    | Opcode.SYSEXIT -> "sysexit"
    | Opcode.SYSRET -> "sysret"
    | Opcode.TDPBF16PS -> "tdpbf16ps"
    | Opcode.TDPBSSD -> "tdpbssd"
    | Opcode.TDPBSUD -> "tdpbsud"
    | Opcode.TDPBUSD -> "tdpbusd"
    | Opcode.TDPBUUD -> "tdpbuud"
    | Opcode.TDPFP16PS -> "tdpfp16ps"
    | Opcode.TEST -> "test"
    | Opcode.TESTUI -> "testui"
    | Opcode.TILELOADD -> "tileloadd"
    | Opcode.TILELOADDT1 -> "tileloaddt1"
    | Opcode.TILERELEASE -> "tilerelease"
    | Opcode.TILESTORED -> "tilestored"
    | Opcode.TILEZERO -> "tilezero"
    | Opcode.TPAUSE -> "tpause"
    | Opcode.TZCNT -> "tzcnt"
    | Opcode.UCOMISD -> "ucomisd"
    | Opcode.UCOMISS -> "ucomiss"
    | Opcode.UD0 -> "ud0"
    | Opcode.UD1 -> "ud1"
    | Opcode.UD2 -> "ud2"
    | Opcode.UDB -> "udb"
    | Opcode.UIRET -> "uiret"
    | Opcode.UMONITOR -> "umonitor"
    | Opcode.UMWAIT -> "umwait"
    | Opcode.UNPCKHPD -> "unpckhpd"
    | Opcode.UNPCKHPS -> "unpckhps"
    | Opcode.UNPCKLPD -> "unpcklpd"
    | Opcode.UNPCKLPS -> "unpcklps"
    | Opcode.V4FMADDPS -> "v4fmaddps"
    | Opcode.V4FMADDSS -> "v4fmaddss"
    | Opcode.V4FNMADDPS -> "v4fnmaddps"
    | Opcode.V4FNMADDSS -> "v4fnmaddss"
    | Opcode.VADDPD -> "vaddpd"
    | Opcode.VADDPH -> "vaddph"
    | Opcode.VADDPS -> "vaddps"
    | Opcode.VADDSD -> "vaddsd"
    | Opcode.VADDSH -> "vaddsh"
    | Opcode.VADDSS -> "vaddss"
    | Opcode.VADDSUBPD -> "vaddsubpd"
    | Opcode.VADDSUBPS -> "vaddsubps"
    | Opcode.VAESDEC -> "vaesdec"
    | Opcode.VAESDECLAST -> "vaesdeclast"
    | Opcode.VAESENC -> "vaesenc"
    | Opcode.VAESENCLAST -> "vaesenclast"
    | Opcode.VAESIMC -> "vaesimc"
    | Opcode.VAESKEYGENASSIST -> "vaeskeygenassist"
    | Opcode.VALIGND -> "valignd"
    | Opcode.VALIGNQ -> "valignq"
    | Opcode.VANDNPD -> "vandnpd"
    | Opcode.VANDNPS -> "vandnps"
    | Opcode.VANDPD -> "vandpd"
    | Opcode.VANDPS -> "vandps"
    | Opcode.VBCSTNEBF162PS -> "vbcstnebf162ps"
    | Opcode.VBCSTNESH2PS -> "vbcstnesh2ps"
    | Opcode.VBLENDMPD -> "vblendmpd"
    | Opcode.VBLENDMPS -> "vblendmps"
    | Opcode.VBLENDPD -> "vblendpd"
    | Opcode.VBLENDPS -> "vblendps"
    | Opcode.VBLENDVPD -> "vblendvpd"
    | Opcode.VBLENDVPS -> "vblendvps"
    | Opcode.VBROADCASTF128 -> "vbroadcastf128"
    | Opcode.VBROADCASTF32X2 -> "vbroadcastf32x2"
    | Opcode.VBROADCASTF32X4 -> "vbroadcastf32x4"
    | Opcode.VBROADCASTF32X8 -> "vbroadcastf32x8"
    | Opcode.VBROADCASTF64X2 -> "vbroadcastf64x2"
    | Opcode.VBROADCASTF64X4 -> "vbroadcastf64x4"
    | Opcode.VBROADCASTI128 -> "vbroadcasti128"
    | Opcode.VBROADCASTI32X2 -> "vbroadcasti32x2"
    | Opcode.VBROADCASTI32X4 -> "vbroadcasti32x4"
    | Opcode.VBROADCASTI32X8 -> "vbroadcasti32x8"
    | Opcode.VBROADCASTI64X2 -> "vbroadcasti64x2"
    | Opcode.VBROADCASTI64X4 -> "vbroadcasti64x4"
    | Opcode.VBROADCASTSD -> "vbroadcastsd"
    | Opcode.VBROADCASTSS -> "vbroadcastss"
    | Opcode.VCMPPD -> "vcmppd"
    | Opcode.VCMPPH -> "vcmpph"
    | Opcode.VCMPPS -> "vcmpps"
    | Opcode.VCMPSD -> "vcmpsd"
    | Opcode.VCMPSH -> "vcmpsh"
    | Opcode.VCMPSS -> "vcmpss"
    | Opcode.VCOMISD -> "vcomisd"
    | Opcode.VCOMISH -> "vcomish"
    | Opcode.VCOMISS -> "vcomiss"
    | Opcode.VCOMPRESSPD -> "vcompresspd"
    | Opcode.VCOMPRESSPS -> "vcompressps"
    | Opcode.VCVTDQ2PD -> "vcvtdq2pd"
    | Opcode.VCVTDQ2PH -> "vcvtdq2ph"
    | Opcode.VCVTDQ2PS -> "vcvtdq2ps"
    | Opcode.VCVTNE2PS2BF16 -> "vcvtne2ps2bf16"
    | Opcode.VCVTNEEBF162PS -> "vcvtneebf162ps"
    | Opcode.VCVTNEEPH2PS -> "vcvtneeph2ps"
    | Opcode.VCVTNEOBF162PS -> "vcvtneobf162ps"
    | Opcode.VCVTNEOPH2PS -> "vcvtneoph2ps"
    | Opcode.VCVTNEPS2BF16 -> "vcvtneps2bf16"
    | Opcode.VCVTPD2DQ -> "vcvtpd2dq"
    | Opcode.VCVTPD2PH -> "vcvtpd2ph"
    | Opcode.VCVTPD2PS -> "vcvtpd2ps"
    | Opcode.VCVTPD2QQ -> "vcvtpd2qq"
    | Opcode.VCVTPD2UDQ -> "vcvtpd2udq"
    | Opcode.VCVTPD2UQQ -> "vcvtpd2uqq"
    | Opcode.VCVTPH2DQ -> "vcvtph2dq"
    | Opcode.VCVTPH2PD -> "vcvtph2pd"
    | Opcode.VCVTPH2PS -> "vcvtph2ps"
    | Opcode.VCVTPH2PSX -> "vcvtph2psx"
    | Opcode.VCVTPH2QQ -> "vcvtph2qq"
    | Opcode.VCVTPH2UDQ -> "vcvtph2udq"
    | Opcode.VCVTPH2UQQ -> "vcvtph2uqq"
    | Opcode.VCVTPH2UW -> "vcvtph2uw"
    | Opcode.VCVTPH2W -> "vcvtph2w"
    | Opcode.VCVTPS2DQ -> "vcvtps2dq"
    | Opcode.VCVTPS2PD -> "vcvtps2pd"
    | Opcode.VCVTPS2PH -> "vcvtps2ph"
    | Opcode.VCVTPS2PHX -> "vcvtps2phx"
    | Opcode.VCVTPS2QQ -> "vcvtps2qq"
    | Opcode.VCVTPS2UDQ -> "vcvtps2udq"
    | Opcode.VCVTPS2UQQ -> "vcvtps2uqq"
    | Opcode.VCVTQQ2PD -> "vcvtqq2pd"
    | Opcode.VCVTQQ2PH -> "vcvtqq2ph"
    | Opcode.VCVTQQ2PS -> "vcvtqq2ps"
    | Opcode.VCVTSD2SH -> "vcvtsd2sh"
    | Opcode.VCVTSD2SI -> "vcvtsd2si"
    | Opcode.VCVTSD2SS -> "vcvtsd2ss"
    | Opcode.VCVTSD2USI -> "vcvtsd2usi"
    | Opcode.VCVTSH2SD -> "vcvtsh2sd"
    | Opcode.VCVTSH2SI -> "vcvtsh2si"
    | Opcode.VCVTSH2SS -> "vcvtsh2ss"
    | Opcode.VCVTSH2USI -> "vcvtsh2usi"
    | Opcode.VCVTSI2SD -> "vcvtsi2sd"
    | Opcode.VCVTSI2SH -> "vcvtsi2sh"
    | Opcode.VCVTSI2SS -> "vcvtsi2ss"
    | Opcode.VCVTSS2SD -> "vcvtss2sd"
    | Opcode.VCVTSS2SH -> "vcvtss2sh"
    | Opcode.VCVTSS2SI -> "vcvtss2si"
    | Opcode.VCVTSS2USI -> "vcvtss2usi"
    | Opcode.VCVTTPD2DQ -> "vcvttpd2dq"
    | Opcode.VCVTTPD2QQ -> "vcvttpd2qq"
    | Opcode.VCVTTPD2UDQ -> "vcvttpd2udq"
    | Opcode.VCVTTPD2UQQ -> "vcvttpd2uqq"
    | Opcode.VCVTTPH2DQ -> "vcvttph2dq"
    | Opcode.VCVTTPH2QQ -> "vcvttph2qq"
    | Opcode.VCVTTPH2UDQ -> "vcvttph2udq"
    | Opcode.VCVTTPH2UQQ -> "vcvttph2uqq"
    | Opcode.VCVTTPH2UW -> "vcvttph2uw"
    | Opcode.VCVTTPH2W -> "vcvttph2w"
    | Opcode.VCVTTPS2DQ -> "vcvttps2dq"
    | Opcode.VCVTTPS2QQ -> "vcvttps2qq"
    | Opcode.VCVTTPS2UDQ -> "vcvttps2udq"
    | Opcode.VCVTTPS2UQQ -> "vcvttps2uqq"
    | Opcode.VCVTTSD2SI -> "vcvttsd2si"
    | Opcode.VCVTTSD2USI -> "vcvttsd2usi"
    | Opcode.VCVTTSH2SI -> "vcvttsh2si"
    | Opcode.VCVTTSH2USI -> "vcvttsh2usi"
    | Opcode.VCVTTSS2SI -> "vcvttss2si"
    | Opcode.VCVTTSS2USI -> "vcvttss2usi"
    | Opcode.VCVTUDQ2PD -> "vcvtudq2pd"
    | Opcode.VCVTUDQ2PH -> "vcvtudq2ph"
    | Opcode.VCVTUDQ2PS -> "vcvtudq2ps"
    | Opcode.VCVTUQQ2PD -> "vcvtuqq2pd"
    | Opcode.VCVTUQQ2PH -> "vcvtuqq2ph"
    | Opcode.VCVTUQQ2PS -> "vcvtuqq2ps"
    | Opcode.VCVTUSI2SD -> "vcvtusi2sd"
    | Opcode.VCVTUSI2SH -> "vcvtusi2sh"
    | Opcode.VCVTUSI2SS -> "vcvtusi2ss"
    | Opcode.VCVTUW2PH -> "vcvtuw2ph"
    | Opcode.VCVTW2PH -> "vcvtw2ph"
    | Opcode.VDBPSADBW -> "vdbpsadbw"
    | Opcode.VDIVPD -> "vdivpd"
    | Opcode.VDIVPH -> "vdivph"
    | Opcode.VDIVPS -> "vdivps"
    | Opcode.VDIVSD -> "vdivsd"
    | Opcode.VDIVSH -> "vdivsh"
    | Opcode.VDIVSS -> "vdivss"
    | Opcode.VDPBF16PS -> "vdpbf16ps"
    | Opcode.VDPPD -> "vdppd"
    | Opcode.VDPPS -> "vdpps"
    | Opcode.VERR -> "verr"
    | Opcode.VERW -> "verw"
    | Opcode.VEXP2PD -> "vexp2pd"
    | Opcode.VEXP2PS -> "vexp2ps"
    | Opcode.VEXPANDPD -> "vexpandpd"
    | Opcode.VEXPANDPS -> "vexpandps"
    | Opcode.VEXTRACTF128 -> "vextractf128"
    | Opcode.VEXTRACTF32X4 -> "vextractf32x4"
    | Opcode.VEXTRACTF32X8 -> "vextractf32x8"
    | Opcode.VEXTRACTF64X2 -> "vextractf64x2"
    | Opcode.VEXTRACTF64X4 -> "vextractf64x4"
    | Opcode.VEXTRACTI128 -> "vextracti128"
    | Opcode.VEXTRACTI32X4 -> "vextracti32x4"
    | Opcode.VEXTRACTI32X8 -> "vextracti32x8"
    | Opcode.VEXTRACTI64X2 -> "vextracti64x2"
    | Opcode.VEXTRACTI64X4 -> "vextracti64x4"
    | Opcode.VEXTRACTPS -> "vextractps"
    | Opcode.VFCMADDCPH -> "vfcmaddcph"
    | Opcode.VFCMADDCSH -> "vfcmaddcsh"
    | Opcode.VFCMULCPH -> "vfcmulcph"
    | Opcode.VFCMULCSH -> "vfcmulcsh"
    | Opcode.VFIXUPIMMPD -> "vfixupimmpd"
    | Opcode.VFIXUPIMMPS -> "vfixupimmps"
    | Opcode.VFIXUPIMMSD -> "vfixupimmsd"
    | Opcode.VFIXUPIMMSS -> "vfixupimmss"
    | Opcode.VFMADD132PD -> "vfmadd132pd"
    | Opcode.VFMADD132PH -> "vfmadd132ph"
    | Opcode.VFMADD132PS -> "vfmadd132ps"
    | Opcode.VFMADD132SD -> "vfmadd132sd"
    | Opcode.VFMADD132SH -> "vfmadd132sh"
    | Opcode.VFMADD132SS -> "vfmadd132ss"
    | Opcode.VFMADD213PD -> "vfmadd213pd"
    | Opcode.VFMADD213PH -> "vfmadd213ph"
    | Opcode.VFMADD213PS -> "vfmadd213ps"
    | Opcode.VFMADD213SD -> "vfmadd213sd"
    | Opcode.VFMADD213SH -> "vfmadd213sh"
    | Opcode.VFMADD213SS -> "vfmadd213ss"
    | Opcode.VFMADD231PD -> "vfmadd231pd"
    | Opcode.VFMADD231PH -> "vfmadd231ph"
    | Opcode.VFMADD231PS -> "vfmadd231ps"
    | Opcode.VFMADD231SD -> "vfmadd231sd"
    | Opcode.VFMADD231SH -> "vfmadd231sh"
    | Opcode.VFMADD231SS -> "vfmadd231ss"
    | Opcode.VFMADDCPH -> "vfmaddcph"
    | Opcode.VFMADDCSH -> "vfmaddcsh"
    | Opcode.VFMADDPD -> "vfmaddpd"
    | Opcode.VFMADDPS -> "vfmaddps"
    | Opcode.VFMADDSD -> "vfmaddsd"
    | Opcode.VFMADDSS -> "vfmaddss"
    | Opcode.VFMADDSUB132PD -> "vfmaddsub132pd"
    | Opcode.VFMADDSUB132PH -> "vfmaddsub132ph"
    | Opcode.VFMADDSUB132PS -> "vfmaddsub132ps"
    | Opcode.VFMADDSUB213PD -> "vfmaddsub213pd"
    | Opcode.VFMADDSUB213PH -> "vfmaddsub213ph"
    | Opcode.VFMADDSUB213PS -> "vfmaddsub213ps"
    | Opcode.VFMADDSUB231PD -> "vfmaddsub231pd"
    | Opcode.VFMADDSUB231PH -> "vfmaddsub231ph"
    | Opcode.VFMADDSUB231PS -> "vfmaddsub231ps"
    | Opcode.VFMSUB132PD -> "vfmsub132pd"
    | Opcode.VFMSUB132PH -> "vfmsub132ph"
    | Opcode.VFMSUB132PS -> "vfmsub132ps"
    | Opcode.VFMSUB132SD -> "vfmsub132sd"
    | Opcode.VFMSUB132SH -> "vfmsub132sh"
    | Opcode.VFMSUB132SS -> "vfmsub132ss"
    | Opcode.VFMSUB213PD -> "vfmsub213pd"
    | Opcode.VFMSUB213PH -> "vfmsub213ph"
    | Opcode.VFMSUB213PS -> "vfmsub213ps"
    | Opcode.VFMSUB213SD -> "vfmsub213sd"
    | Opcode.VFMSUB213SH -> "vfmsub213sh"
    | Opcode.VFMSUB213SS -> "vfmsub213ss"
    | Opcode.VFMSUB231PD -> "vfmsub231pd"
    | Opcode.VFMSUB231PH -> "vfmsub231ph"
    | Opcode.VFMSUB231PS -> "vfmsub231ps"
    | Opcode.VFMSUB231SD -> "vfmsub231sd"
    | Opcode.VFMSUB231SH -> "vfmsub231sh"
    | Opcode.VFMSUB231SS -> "vfmsub231ss"
    | Opcode.VFMSUBADD132PD -> "vfmsubadd132pd"
    | Opcode.VFMSUBADD132PH -> "vfmsubadd132ph"
    | Opcode.VFMSUBADD132PS -> "vfmsubadd132ps"
    | Opcode.VFMSUBADD213PD -> "vfmsubadd213pd"
    | Opcode.VFMSUBADD213PH -> "vfmsubadd213ph"
    | Opcode.VFMSUBADD213PS -> "vfmsubadd213ps"
    | Opcode.VFMSUBADD231PD -> "vfmsubadd231pd"
    | Opcode.VFMSUBADD231PH -> "vfmsubadd231ph"
    | Opcode.VFMSUBADD231PS -> "vfmsubadd231ps"
    | Opcode.VFMULCPH -> "vfmulcph"
    | Opcode.VFMULCSH -> "vfmulcsh"
    | Opcode.VFNMADD132PD -> "vfnmadd132pd"
    | Opcode.VFNMADD132PH -> "vfnmadd132ph"
    | Opcode.VFNMADD132PS -> "vfnmadd132ps"
    | Opcode.VFNMADD132SD -> "vfnmadd132sd"
    | Opcode.VFNMADD132SH -> "vfnmadd132sh"
    | Opcode.VFNMADD132SS -> "vfnmadd132ss"
    | Opcode.VFNMADD213PD -> "vfnmadd213pd"
    | Opcode.VFNMADD213PH -> "vfnmadd213ph"
    | Opcode.VFNMADD213PS -> "vfnmadd213ps"
    | Opcode.VFNMADD213SD -> "vfnmadd213sd"
    | Opcode.VFNMADD213SH -> "vfnmadd213sh"
    | Opcode.VFNMADD213SS -> "vfnmadd213ss"
    | Opcode.VFNMADD231PD -> "vfnmadd231pd"
    | Opcode.VFNMADD231PH -> "vfnmadd231ph"
    | Opcode.VFNMADD231PS -> "vfnmadd231ps"
    | Opcode.VFNMADD231SD -> "vfnmadd231sd"
    | Opcode.VFNMADD231SH -> "vfnmadd231sh"
    | Opcode.VFNMADD231SS -> "vfnmadd231ss"
    | Opcode.VFNMSUB132PD -> "vfnmsub132pd"
    | Opcode.VFNMSUB132PH -> "vfnmsub132ph"
    | Opcode.VFNMSUB132PS -> "vfnmsub132ps"
    | Opcode.VFNMSUB132SD -> "vfnmsub132sd"
    | Opcode.VFNMSUB132SH -> "vfnmsub132sh"
    | Opcode.VFNMSUB132SS -> "vfnmsub132ss"
    | Opcode.VFNMSUB213PD -> "vfnmsub213pd"
    | Opcode.VFNMSUB213PH -> "vfnmsub213ph"
    | Opcode.VFNMSUB213PS -> "vfnmsub213ps"
    | Opcode.VFNMSUB213SD -> "vfnmsub213sd"
    | Opcode.VFNMSUB213SH -> "vfnmsub213sh"
    | Opcode.VFNMSUB213SS -> "vfnmsub213ss"
    | Opcode.VFNMSUB231PD -> "vfnmsub231pd"
    | Opcode.VFNMSUB231PH -> "vfnmsub231ph"
    | Opcode.VFNMSUB231PS -> "vfnmsub231ps"
    | Opcode.VFNMSUB231SD -> "vfnmsub231sd"
    | Opcode.VFNMSUB231SH -> "vfnmsub231sh"
    | Opcode.VFNMSUB231SS -> "vfnmsub231ss"
    | Opcode.VFPCLASSPD -> "vfpclasspd"
    | Opcode.VFPCLASSPH -> "vfpclassph"
    | Opcode.VFPCLASSPS -> "vfpclassps"
    | Opcode.VFPCLASSSD -> "vfpclasssd"
    | Opcode.VFPCLASSSH -> "vfpclasssh"
    | Opcode.VFPCLASSSS -> "vfpclassss"
    | Opcode.VGATHERDPD -> "vgatherdpd"
    | Opcode.VGATHERDPS -> "vgatherdps"
    | Opcode.VGATHERPF0DPD -> "vgatherpf0dpd"
    | Opcode.VGATHERPF0DPS -> "vgatherpf0dps"
    | Opcode.VGATHERPF0QPD -> "vgatherpf0qpd"
    | Opcode.VGATHERPF0QPS -> "vgatherpf0qps"
    | Opcode.VGATHERPF1DPD -> "vgatherpf1dpd"
    | Opcode.VGATHERPF1DPS -> "vgatherpf1dps"
    | Opcode.VGATHERPF1QPD -> "vgatherpf1qpd"
    | Opcode.VGATHERPF1QPS -> "vgatherpf1qps"
    | Opcode.VGATHERQPD -> "vgatherqpd"
    | Opcode.VGATHERQPS -> "vgatherqps"
    | Opcode.VGETEXPPD -> "vgetexppd"
    | Opcode.VGETEXPPH -> "vgetexpph"
    | Opcode.VGETEXPPS -> "vgetexpps"
    | Opcode.VGETEXPSD -> "vgetexpsd"
    | Opcode.VGETEXPSH -> "vgetexpsh"
    | Opcode.VGETEXPSS -> "vgetexpss"
    | Opcode.VGETMANTPD -> "vgetmantpd"
    | Opcode.VGETMANTPH -> "vgetmantph"
    | Opcode.VGETMANTPS -> "vgetmantps"
    | Opcode.VGETMANTSD -> "vgetmantsd"
    | Opcode.VGETMANTSH -> "vgetmantsh"
    | Opcode.VGETMANTSS -> "vgetmantss"
    | Opcode.VGF2P8AFFINEINVQB -> "vgf2p8affineinvqb"
    | Opcode.VGF2P8AFFINEQB -> "vgf2p8affineqb"
    | Opcode.VGF2P8MULB -> "vgf2p8mulb"
    | Opcode.VHADDPD -> "vhaddpd"
    | Opcode.VHADDPS -> "vhaddps"
    | Opcode.VHSUBPD -> "vhsubpd"
    | Opcode.VHSUBPS -> "vhsubps"
    | Opcode.VINSERTF128 -> "vinsertf128"
    | Opcode.VINSERTF32X4 -> "vinsertf32x4"
    | Opcode.VINSERTF32X8 -> "vinsertf32x8"
    | Opcode.VINSERTF64X2 -> "vinsertf64x2"
    | Opcode.VINSERTF64X4 -> "vinsertf64x4"
    | Opcode.VINSERTI128 -> "vinserti128"
    | Opcode.VINSERTI32X4 -> "vinserti32x4"
    | Opcode.VINSERTI32X8 -> "vinserti32x8"
    | Opcode.VINSERTI64X2 -> "vinserti64x2"
    | Opcode.VINSERTI64X4 -> "vinserti64x4"
    | Opcode.VINSERTPS -> "vinsertps"
    | Opcode.VLDDQU -> "vlddqu"
    | Opcode.VLDMXCSR -> "vldmxcsr"
    | Opcode.VMASKMOVDQU -> "vmaskmovdqu"
    | Opcode.VMASKMOVPD -> "vmaskmovpd"
    | Opcode.VMASKMOVPS -> "vmaskmovps"
    | Opcode.VMAXPD -> "vmaxpd"
    | Opcode.VMAXPH -> "vmaxph"
    | Opcode.VMAXPS -> "vmaxps"
    | Opcode.VMAXSD -> "vmaxsd"
    | Opcode.VMAXSH -> "vmaxsh"
    | Opcode.VMAXSS -> "vmaxss"
    | Opcode.VMCALL -> "vmcall"
    | Opcode.VMCLEAR -> "vmclear"
    | Opcode.VMFUNC -> "vmfunc"
    | Opcode.VMINPD -> "vminpd"
    | Opcode.VMINPH -> "vminph"
    | Opcode.VMINPS -> "vminps"
    | Opcode.VMINSD -> "vminsd"
    | Opcode.VMINSH -> "vminsh"
    | Opcode.VMINSS -> "vminss"
    | Opcode.VMLAUNCH -> "vmlaunch"
    | Opcode.VMOVAPD -> "vmovapd"
    | Opcode.VMOVAPS -> "vmovaps"
    | Opcode.VMOVD -> "vmovd"
    | Opcode.VMOVDDUP -> "vmovddup"
    | Opcode.VMOVDQA -> "vmovdqa"
    | Opcode.VMOVDQA32 -> "vmovdqa32"
    | Opcode.VMOVDQA64 -> "vmovdqa64"
    | Opcode.VMOVDQU -> "vmovdqu"
    | Opcode.VMOVDQU16 -> "vmovdqu16"
    | Opcode.VMOVDQU32 -> "vmovdqu32"
    | Opcode.VMOVDQU64 -> "vmovdqu64"
    | Opcode.VMOVDQU8 -> "vmovdqu8"
    | Opcode.VMOVHLPS -> "vmovhlps"
    | Opcode.VMOVHPD -> "vmovhpd"
    | Opcode.VMOVHPS -> "vmovhps"
    | Opcode.VMOVLHPS -> "vmovlhps"
    | Opcode.VMOVLPD -> "vmovlpd"
    | Opcode.VMOVLPS -> "vmovlps"
    | Opcode.VMOVMSKPD -> "vmovmskpd"
    | Opcode.VMOVMSKPS -> "vmovmskps"
    | Opcode.VMOVNTDQ -> "vmovntdq"
    | Opcode.VMOVNTDQA -> "vmovntdqa"
    | Opcode.VMOVNTPD -> "vmovntpd"
    | Opcode.VMOVNTPS -> "vmovntps"
    | Opcode.VMOVQ -> "vmovq"
    | Opcode.VMOVSD -> "vmovsd"
    | Opcode.VMOVSH -> "vmovsh"
    | Opcode.VMOVSHDUP -> "vmovshdup"
    | Opcode.VMOVSLDUP -> "vmovsldup"
    | Opcode.VMOVSS -> "vmovss"
    | Opcode.VMOVUPD -> "vmovupd"
    | Opcode.VMOVUPS -> "vmovups"
    | Opcode.VMOVW -> "vmovw"
    | Opcode.VMPSADBW -> "vmpsadbw"
    | Opcode.VMPTRLD -> "vmptrld"
    | Opcode.VMPTRST -> "vmptrst"
    | Opcode.VMREAD -> "vmread"
    | Opcode.VMRESUME -> "vmresume"
    | Opcode.VMULPD -> "vmulpd"
    | Opcode.VMULPH -> "vmulph"
    | Opcode.VMULPS -> "vmulps"
    | Opcode.VMULSD -> "vmulsd"
    | Opcode.VMULSH -> "vmulsh"
    | Opcode.VMULSS -> "vmulss"
    | Opcode.VMXOFF -> "vmxoff"
    | Opcode.VMXON -> "vmxon"
    | Opcode.VORPD -> "vorpd"
    | Opcode.VORPS -> "vorps"
    | Opcode.VP2INTERSECTD -> "vp2intersectd"
    | Opcode.VP2INTERSECTQ -> "vp2intersectq"
    | Opcode.VP4DPWSSD -> "vp4dpwssd"
    | Opcode.VP4DPWSSDS -> "vp4dpwssds"
    | Opcode.VPABSB -> "vpabsb"
    | Opcode.VPABSD -> "vpabsd"
    | Opcode.VPABSQ -> "vpabsq"
    | Opcode.VPABSW -> "vpabsw"
    | Opcode.VPACKSSDW -> "vpackssdw"
    | Opcode.VPACKSSWB -> "vpacksswb"
    | Opcode.VPACKUSDW -> "vpackusdw"
    | Opcode.VPACKUSWB -> "vpackuswb"
    | Opcode.VPADDB -> "vpaddb"
    | Opcode.VPADDD -> "vpaddd"
    | Opcode.VPADDQ -> "vpaddq"
    | Opcode.VPADDSB -> "vpaddsb"
    | Opcode.VPADDSW -> "vpaddsw"
    | Opcode.VPADDUSB -> "vpaddusb"
    | Opcode.VPADDUSW -> "vpaddusw"
    | Opcode.VPADDW -> "vpaddw"
    | Opcode.VPALIGNR -> "vpalignr"
    | Opcode.VPAND -> "vpand"
    | Opcode.VPANDD -> "vpandd"
    | Opcode.VPANDN -> "vpandn"
    | Opcode.VPANDND -> "vpandnd"
    | Opcode.VPANDNQ -> "vpandnq"
    | Opcode.VPANDQ -> "vpandq"
    | Opcode.VPAVGB -> "vpavgb"
    | Opcode.VPAVGW -> "vpavgw"
    | Opcode.VPBLENDD -> "vpblendd"
    | Opcode.VPBLENDMB -> "vpblendmb"
    | Opcode.VPBLENDMD -> "vpblendmd"
    | Opcode.VPBLENDMQ -> "vpblendmq"
    | Opcode.VPBLENDMW -> "vpblendmw"
    | Opcode.VPBLENDVB -> "vpblendvb"
    | Opcode.VPBLENDW -> "vpblendw"
    | Opcode.VPBROADCASTB -> "vpbroadcastb"
    | Opcode.VPBROADCASTD -> "vpbroadcastd"
    | Opcode.VPBROADCASTMB2Q -> "vpbroadcastmb2q"
    | Opcode.VPBROADCASTMW2D -> "vpbroadcastmw2d"
    | Opcode.VPBROADCASTQ -> "vpbroadcastq"
    | Opcode.VPBROADCASTW -> "vpbroadcastw"
    | Opcode.VPCLMULQDQ -> "vpclmulqdq"
    | Opcode.VPCMPB -> "vpcmpb"
    | Opcode.VPCMPD -> "vpcmpd"
    | Opcode.VPCMPEQB -> "vpcmpeqb"
    | Opcode.VPCMPEQD -> "vpcmpeqd"
    | Opcode.VPCMPEQQ -> "vpcmpeqq"
    | Opcode.VPCMPEQW -> "vpcmpeqw"
    | Opcode.VPCMPESTRI -> "vpcmpestri"
    | Opcode.VPCMPESTRM -> "vpcmpestrm"
    | Opcode.VPCMPGTB -> "vpcmpgtb"
    | Opcode.VPCMPGTD -> "vpcmpgtd"
    | Opcode.VPCMPGTQ -> "vpcmpgtq"
    | Opcode.VPCMPGTW -> "vpcmpgtw"
    | Opcode.VPCMPISTRI -> "vpcmpistri"
    | Opcode.VPCMPISTRM -> "vpcmpistrm"
    | Opcode.VPCMPQ -> "vpcmpq"
    | Opcode.VPCMPUB -> "vpcmpub"
    | Opcode.VPCMPUD -> "vpcmpud"
    | Opcode.VPCMPUQ -> "vpcmpuq"
    | Opcode.VPCMPUW -> "vpcmpuw"
    | Opcode.VPCMPW -> "vpcmpw"
    | Opcode.VPCOMPRESSB -> "vpcompressb"
    | Opcode.VPCOMPRESSD -> "vpcompressd"
    | Opcode.VPCOMPRESSQ -> "vpcompressq"
    | Opcode.VPCOMPRESSW -> "vpcompressw"
    | Opcode.VPCONFLICTD -> "vpconflictd"
    | Opcode.VPCONFLICTQ -> "vpconflictq"
    | Opcode.VPDPBSSD -> "vpdpbssd"
    | Opcode.VPDPBSSDS -> "vpdpbssds"
    | Opcode.VPDPBSUD -> "vpdpbsud"
    | Opcode.VPDPBSUDS -> "vpdpbsuds"
    | Opcode.VPDPBUSD -> "vpdpbusd"
    | Opcode.VPDPBUSDS -> "vpdpbusds"
    | Opcode.VPDPBUUD -> "vpdpbuud"
    | Opcode.VPDPBUUDS -> "vpdpbuuds"
    | Opcode.VPDPWSSD -> "vpdpwssd"
    | Opcode.VPDPWSSDS -> "vpdpwssds"
    | Opcode.VPDPWSUD -> "vpdpwsud"
    | Opcode.VPDPWSUDS -> "vpdpwsuds"
    | Opcode.VPDPWUSD -> "vpdpwusd"
    | Opcode.VPDPWUSDS -> "vpdpwusds"
    | Opcode.VPDPWUUD -> "vpdpwuud"
    | Opcode.VPDPWUUDS -> "vpdpwuuds"
    | Opcode.VPERM2F128 -> "vperm2f128"
    | Opcode.VPERM2I128 -> "vperm2i128"
    | Opcode.VPERMB -> "vpermb"
    | Opcode.VPERMD -> "vpermd"
    | Opcode.VPERMI2B -> "vpermi2b"
    | Opcode.VPERMI2D -> "vpermi2d"
    | Opcode.VPERMI2PD -> "vpermi2pd"
    | Opcode.VPERMI2PS -> "vpermi2ps"
    | Opcode.VPERMI2Q -> "vpermi2q"
    | Opcode.VPERMI2W -> "vpermi2w"
    | Opcode.VPERMILPD -> "vpermilpd"
    | Opcode.VPERMILPS -> "vpermilps"
    | Opcode.VPERMPD -> "vpermpd"
    | Opcode.VPERMPS -> "vpermps"
    | Opcode.VPERMQ -> "vpermq"
    | Opcode.VPERMT2B -> "vpermt2b"
    | Opcode.VPERMT2D -> "vpermt2d"
    | Opcode.VPERMT2PD -> "vpermt2pd"
    | Opcode.VPERMT2PS -> "vpermt2ps"
    | Opcode.VPERMT2Q -> "vpermt2q"
    | Opcode.VPERMT2W -> "vpermt2w"
    | Opcode.VPERMW -> "vpermw"
    | Opcode.VPEXPANDB -> "vpexpandb"
    | Opcode.VPEXPANDD -> "vpexpandd"
    | Opcode.VPEXPANDQ -> "vpexpandq"
    | Opcode.VPEXPANDW -> "vpexpandw"
    | Opcode.VPEXTRB -> "vpextrb"
    | Opcode.VPEXTRD -> "vpextrd"
    | Opcode.VPEXTRQ -> "vpextrq"
    | Opcode.VPEXTRW -> "vpextrw"
    | Opcode.VPGATHERDD -> "vpgatherdd"
    | Opcode.VPGATHERDQ -> "vpgatherdq"
    | Opcode.VPGATHERQD -> "vpgatherqd"
    | Opcode.VPGATHERQQ -> "vpgatherqq"
    | Opcode.VPHADDD -> "vphaddd"
    | Opcode.VPHADDSW -> "vphaddsw"
    | Opcode.VPHADDW -> "vphaddw"
    | Opcode.VPHMINPOSUW -> "vphminposuw"
    | Opcode.VPHSUBD -> "vphsubd"
    | Opcode.VPHSUBSW -> "vphsubsw"
    | Opcode.VPHSUBW -> "vphsubw"
    | Opcode.VPINSRB -> "vpinsrb"
    | Opcode.VPINSRD -> "vpinsrd"
    | Opcode.VPINSRQ -> "vpinsrq"
    | Opcode.VPINSRW -> "vpinsrw"
    | Opcode.VPLZCNTD -> "vplzcntd"
    | Opcode.VPLZCNTQ -> "vplzcntq"
    | Opcode.VPMADD52HUQ -> "vpmadd52huq"
    | Opcode.VPMADD52LUQ -> "vpmadd52luq"
    | Opcode.VPMADDUBSW -> "vpmaddubsw"
    | Opcode.VPMADDWD -> "vpmaddwd"
    | Opcode.VPMASKMOVD -> "vpmaskmovd"
    | Opcode.VPMASKMOVQ -> "vpmaskmovq"
    | Opcode.VPMAXSB -> "vpmaxsb"
    | Opcode.VPMAXSD -> "vpmaxsd"
    | Opcode.VPMAXSQ -> "vpmaxsq"
    | Opcode.VPMAXSW -> "vpmaxsw"
    | Opcode.VPMAXUB -> "vpmaxub"
    | Opcode.VPMAXUD -> "vpmaxud"
    | Opcode.VPMAXUQ -> "vpmaxuq"
    | Opcode.VPMAXUW -> "vpmaxuw"
    | Opcode.VPMINSB -> "vpminsb"
    | Opcode.VPMINSD -> "vpminsd"
    | Opcode.VPMINSQ -> "vpminsq"
    | Opcode.VPMINSW -> "vpminsw"
    | Opcode.VPMINUB -> "vpminub"
    | Opcode.VPMINUD -> "vpminud"
    | Opcode.VPMINUQ -> "vpminuq"
    | Opcode.VPMINUW -> "vpminuw"
    | Opcode.VPMOVB2M -> "vpmovb2m"
    | Opcode.VPMOVD2M -> "vpmovd2m"
    | Opcode.VPMOVDB -> "vpmovdb"
    | Opcode.VPMOVDW -> "vpmovdw"
    | Opcode.VPMOVM2B -> "vpmovm2b"
    | Opcode.VPMOVM2D -> "vpmovm2d"
    | Opcode.VPMOVM2Q -> "vpmovm2q"
    | Opcode.VPMOVM2W -> "vpmovm2w"
    | Opcode.VPMOVMSKB -> "vpmovmskb"
    | Opcode.VPMOVQ2M -> "vpmovq2m"
    | Opcode.VPMOVQB -> "vpmovqb"
    | Opcode.VPMOVQD -> "vpmovqd"
    | Opcode.VPMOVQW -> "vpmovqw"
    | Opcode.VPMOVSDB -> "vpmovsdb"
    | Opcode.VPMOVSDW -> "vpmovsdw"
    | Opcode.VPMOVSQB -> "vpmovsqb"
    | Opcode.VPMOVSQD -> "vpmovsqd"
    | Opcode.VPMOVSQW -> "vpmovsqw"
    | Opcode.VPMOVSWB -> "vpmovswb"
    | Opcode.VPMOVSXBD -> "vpmovsxbd"
    | Opcode.VPMOVSXBQ -> "vpmovsxbq"
    | Opcode.VPMOVSXBW -> "vpmovsxbw"
    | Opcode.VPMOVSXDQ -> "vpmovsxdq"
    | Opcode.VPMOVSXWD -> "vpmovsxwd"
    | Opcode.VPMOVSXWQ -> "vpmovsxwq"
    | Opcode.VPMOVUSDB -> "vpmovusdb"
    | Opcode.VPMOVUSDW -> "vpmovusdw"
    | Opcode.VPMOVUSQB -> "vpmovusqb"
    | Opcode.VPMOVUSQD -> "vpmovusqd"
    | Opcode.VPMOVUSQW -> "vpmovusqw"
    | Opcode.VPMOVUSWB -> "vpmovuswb"
    | Opcode.VPMOVW2M -> "vpmovw2m"
    | Opcode.VPMOVWB -> "vpmovwb"
    | Opcode.VPMOVZXBD -> "vpmovzxbd"
    | Opcode.VPMOVZXBQ -> "vpmovzxbq"
    | Opcode.VPMOVZXBW -> "vpmovzxbw"
    | Opcode.VPMOVZXDQ -> "vpmovzxdq"
    | Opcode.VPMOVZXWD -> "vpmovzxwd"
    | Opcode.VPMOVZXWQ -> "vpmovzxwq"
    | Opcode.VPMULDQ -> "vpmuldq"
    | Opcode.VPMULHRSW -> "vpmulhrsw"
    | Opcode.VPMULHUW -> "vpmulhuw"
    | Opcode.VPMULHW -> "vpmulhw"
    | Opcode.VPMULLD -> "vpmulld"
    | Opcode.VPMULLQ -> "vpmullq"
    | Opcode.VPMULLW -> "vpmullw"
    | Opcode.VPMULTISHIFTQB -> "vpmultishiftqb"
    | Opcode.VPMULUDQ -> "vpmuludq"
    | Opcode.VPOPCNTB -> "vpopcntb"
    | Opcode.VPOPCNTD -> "vpopcntd"
    | Opcode.VPOPCNTQ -> "vpopcntq"
    | Opcode.VPOPCNTW -> "vpopcntw"
    | Opcode.VPOR -> "vpor"
    | Opcode.VPORD -> "vpord"
    | Opcode.VPORQ -> "vporq"
    | Opcode.VPROLD -> "vprold"
    | Opcode.VPROLQ -> "vprolq"
    | Opcode.VPROLVD -> "vprolvd"
    | Opcode.VPROLVQ -> "vprolvq"
    | Opcode.VPRORD -> "vprord"
    | Opcode.VPRORQ -> "vprorq"
    | Opcode.VPRORVD -> "vprorvd"
    | Opcode.VPRORVQ -> "vprorvq"
    | Opcode.VPSADBW -> "vpsadbw"
    | Opcode.VPSCATTERDD -> "vpscatterdd"
    | Opcode.VPSCATTERDQ -> "vpscatterdq"
    | Opcode.VPSCATTERQD -> "vpscatterqd"
    | Opcode.VPSCATTERQQ -> "vpscatterqq"
    | Opcode.VPSHLDD -> "vpshldd"
    | Opcode.VPSHLDQ -> "vpshldq"
    | Opcode.VPSHLDVD -> "vpshldvd"
    | Opcode.VPSHLDVQ -> "vpshldvq"
    | Opcode.VPSHLDVW -> "vpshldvw"
    | Opcode.VPSHLDW -> "vpshldw"
    | Opcode.VPSHRDD -> "vpshrdd"
    | Opcode.VPSHRDQ -> "vpshrdq"
    | Opcode.VPSHRDVD -> "vpshrdvd"
    | Opcode.VPSHRDVQ -> "vpshrdvq"
    | Opcode.VPSHRDVW -> "vpshrdvw"
    | Opcode.VPSHRDW -> "vpshrdw"
    | Opcode.VPSHUFB -> "vpshufb"
    | Opcode.VPSHUFBITQMB -> "vpshufbitqmb"
    | Opcode.VPSHUFD -> "vpshufd"
    | Opcode.VPSHUFHW -> "vpshufhw"
    | Opcode.VPSHUFLW -> "vpshuflw"
    | Opcode.VPSIGNB -> "vpsignb"
    | Opcode.VPSIGND -> "vpsignd"
    | Opcode.VPSIGNW -> "vpsignw"
    | Opcode.VPSLLD -> "vpslld"
    | Opcode.VPSLLDQ -> "vpslldq"
    | Opcode.VPSLLQ -> "vpsllq"
    | Opcode.VPSLLVD -> "vpsllvd"
    | Opcode.VPSLLVQ -> "vpsllvq"
    | Opcode.VPSLLVW -> "vpsllvw"
    | Opcode.VPSLLW -> "vpsllw"
    | Opcode.VPSRAD -> "vpsrad"
    | Opcode.VPSRAQ -> "vpsraq"
    | Opcode.VPSRAVD -> "vpsravd"
    | Opcode.VPSRAVQ -> "vpsravq"
    | Opcode.VPSRAVW -> "vpsravw"
    | Opcode.VPSRAW -> "vpsraw"
    | Opcode.VPSRLD -> "vpsrld"
    | Opcode.VPSRLDQ -> "vpsrldq"
    | Opcode.VPSRLQ -> "vpsrlq"
    | Opcode.VPSRLVD -> "vpsrlvd"
    | Opcode.VPSRLVQ -> "vpsrlvq"
    | Opcode.VPSRLVW -> "vpsrlvw"
    | Opcode.VPSRLW -> "vpsrlw"
    | Opcode.VPSUBB -> "vpsubb"
    | Opcode.VPSUBD -> "vpsubd"
    | Opcode.VPSUBQ -> "vpsubq"
    | Opcode.VPSUBSB -> "vpsubsb"
    | Opcode.VPSUBSW -> "vpsubsw"
    | Opcode.VPSUBUSB -> "vpsubusb"
    | Opcode.VPSUBUSW -> "vpsubusw"
    | Opcode.VPSUBW -> "vpsubw"
    | Opcode.VPTERNLOGD -> "vpternlogd"
    | Opcode.VPTERNLOGQ -> "vpternlogq"
    | Opcode.VPTEST -> "vptest"
    | Opcode.VPTESTMB -> "vptestmb"
    | Opcode.VPTESTMD -> "vptestmd"
    | Opcode.VPTESTMQ -> "vptestmq"
    | Opcode.VPTESTMW -> "vptestmw"
    | Opcode.VPTESTNMB -> "vptestnmb"
    | Opcode.VPTESTNMD -> "vptestnmd"
    | Opcode.VPTESTNMQ -> "vptestnmq"
    | Opcode.VPTESTNMW -> "vptestnmw"
    | Opcode.VPUNPCKHBW -> "vpunpckhbw"
    | Opcode.VPUNPCKHDQ -> "vpunpckhdq"
    | Opcode.VPUNPCKHQDQ -> "vpunpckhqdq"
    | Opcode.VPUNPCKHWD -> "vpunpckhwd"
    | Opcode.VPUNPCKLBW -> "vpunpcklbw"
    | Opcode.VPUNPCKLDQ -> "vpunpckldq"
    | Opcode.VPUNPCKLQDQ -> "vpunpcklqdq"
    | Opcode.VPUNPCKLWD -> "vpunpcklwd"
    | Opcode.VPXOR -> "vpxor"
    | Opcode.VPXORD -> "vpxord"
    | Opcode.VPXORQ -> "vpxorq"
    | Opcode.VRANGEPD -> "vrangepd"
    | Opcode.VRANGEPS -> "vrangeps"
    | Opcode.VRANGESD -> "vrangesd"
    | Opcode.VRANGESS -> "vrangess"
    | Opcode.VRCP14PD -> "vrcp14pd"
    | Opcode.VRCP14PS -> "vrcp14ps"
    | Opcode.VRCP14SD -> "vrcp14sd"
    | Opcode.VRCP14SS -> "vrcp14ss"
    | Opcode.VRCP28PD -> "vrcp28pd"
    | Opcode.VRCP28PS -> "vrcp28ps"
    | Opcode.VRCP28SD -> "vrcp28sd"
    | Opcode.VRCP28SS -> "vrcp28ss"
    | Opcode.VRCPPH -> "vrcpph"
    | Opcode.VRCPPS -> "vrcpps"
    | Opcode.VRCPSH -> "vrcpsh"
    | Opcode.VRCPSS -> "vrcpss"
    | Opcode.VREDUCEPD -> "vreducepd"
    | Opcode.VREDUCEPH -> "vreduceph"
    | Opcode.VREDUCEPS -> "vreduceps"
    | Opcode.VREDUCESD -> "vreducesd"
    | Opcode.VREDUCESH -> "vreducesh"
    | Opcode.VREDUCESS -> "vreducess"
    | Opcode.VRNDSCALEPD -> "vrndscalepd"
    | Opcode.VRNDSCALEPH -> "vrndscaleph"
    | Opcode.VRNDSCALEPS -> "vrndscaleps"
    | Opcode.VRNDSCALESD -> "vrndscalesd"
    | Opcode.VRNDSCALESH -> "vrndscalesh"
    | Opcode.VRNDSCALESS -> "vrndscaless"
    | Opcode.VROUNDPD -> "vroundpd"
    | Opcode.VROUNDPS -> "vroundps"
    | Opcode.VROUNDSD -> "vroundsd"
    | Opcode.VROUNDSS -> "vroundss"
    | Opcode.VRSQRT14PD -> "vrsqrt14pd"
    | Opcode.VRSQRT14PS -> "vrsqrt14ps"
    | Opcode.VRSQRT14SD -> "vrsqrt14sd"
    | Opcode.VRSQRT14SS -> "vrsqrt14ss"
    | Opcode.VRSQRT28PD -> "vrsqrt28pd"
    | Opcode.VRSQRT28PS -> "vrsqrt28ps"
    | Opcode.VRSQRT28SD -> "vrsqrt28sd"
    | Opcode.VRSQRT28SS -> "vrsqrt28ss"
    | Opcode.VRSQRTPH -> "vrsqrtph"
    | Opcode.VRSQRTPS -> "vrsqrtps"
    | Opcode.VRSQRTSH -> "vrsqrtsh"
    | Opcode.VRSQRTSS -> "vrsqrtss"
    | Opcode.VSCALEFPD -> "vscalefpd"
    | Opcode.VSCALEFPH -> "vscalefph"
    | Opcode.VSCALEFPS -> "vscalefps"
    | Opcode.VSCALEFSD -> "vscalefsd"
    | Opcode.VSCALEFSH -> "vscalefsh"
    | Opcode.VSCALEFSS -> "vscalefss"
    | Opcode.VSCATTERDPD -> "vscatterdpd"
    | Opcode.VSCATTERDPS -> "vscatterdps"
    | Opcode.VSCATTERPF0DPD -> "vscatterpf0dpd"
    | Opcode.VSCATTERPF0DPS -> "vscatterpf0dps"
    | Opcode.VSCATTERPF0QPD -> "vscatterpf0qpd"
    | Opcode.VSCATTERPF0QPS -> "vscatterpf0qps"
    | Opcode.VSCATTERPF1DPD -> "vscatterpf1dpd"
    | Opcode.VSCATTERPF1DPS -> "vscatterpf1dps"
    | Opcode.VSCATTERPF1QPD -> "vscatterpf1qpd"
    | Opcode.VSCATTERPF1QPS -> "vscatterpf1qps"
    | Opcode.VSCATTERQPD -> "vscatterqpd"
    | Opcode.VSCATTERQPS -> "vscatterqps"
    | Opcode.VSHA512MSG1 -> "vsha512msg1"
    | Opcode.VSHA512MSG2 -> "vsha512msg2"
    | Opcode.VSHA512RNDS2 -> "vsha512rnds2"
    | Opcode.VSHUFF32X4 -> "vshuff32x4"
    | Opcode.VSHUFF64X2 -> "vshuff64x2"
    | Opcode.VSHUFI32X4 -> "vshufi32x4"
    | Opcode.VSHUFI64X2 -> "vshufi64x2"
    | Opcode.VSHUFPD -> "vshufpd"
    | Opcode.VSHUFPS -> "vshufps"
    | Opcode.VSM3MSG1 -> "vsm3msg1"
    | Opcode.VSM3MSG2 -> "vsm3msg2"
    | Opcode.VSM3RNDS2 -> "vsm3rnds2"
    | Opcode.VSM4KEY4 -> "vsm4key4"
    | Opcode.VSM4RNDS4 -> "vsm4rnds4"
    | Opcode.VSQRTPD -> "vsqrtpd"
    | Opcode.VSQRTPH -> "vsqrtph"
    | Opcode.VSQRTPS -> "vsqrtps"
    | Opcode.VSQRTSD -> "vsqrtsd"
    | Opcode.VSQRTSH -> "vsqrtsh"
    | Opcode.VSQRTSS -> "vsqrtss"
    | Opcode.VSTMXCSR -> "vstmxcsr"
    | Opcode.VSUBPD -> "vsubpd"
    | Opcode.VSUBPH -> "vsubph"
    | Opcode.VSUBPS -> "vsubps"
    | Opcode.VSUBSD -> "vsubsd"
    | Opcode.VSUBSH -> "vsubsh"
    | Opcode.VSUBSS -> "vsubss"
    | Opcode.VTESTPD -> "vtestpd"
    | Opcode.VTESTPS -> "vtestps"
    | Opcode.VUCOMISD -> "vucomisd"
    | Opcode.VUCOMISH -> "vucomish"
    | Opcode.VUCOMISS -> "vucomiss"
    | Opcode.VUNPCKHPD -> "vunpckhpd"
    | Opcode.VUNPCKHPS -> "vunpckhps"
    | Opcode.VUNPCKLPD -> "vunpcklpd"
    | Opcode.VUNPCKLPS -> "vunpcklps"
    | Opcode.VXORPD -> "vxorpd"
    | Opcode.VXORPS -> "vxorps"
    | Opcode.VZEROALL -> "vzeroall"
    | Opcode.VZEROUPPER -> "vzeroupper"
    | Opcode.WAIT -> "wait"
    | Opcode.WBINVD -> "wbinvd"
    | Opcode.WBNOINVD -> "wbnoinvd"
    | Opcode.WRFSBASE -> "wrfsbase"
    | Opcode.WRGSBASE -> "wrgsbase"
    | Opcode.WRMSR -> "wrmsr"
    | Opcode.WRMSRLIST -> "wrmsrlist"
    | Opcode.WRMSRNS -> "wrmsrns"
    | Opcode.WRPKRU -> "wrpkru"
    | Opcode.WRSSD -> "wrssd"
    | Opcode.WRSSQ -> "wrssq"
    | Opcode.WRUSSD -> "wrussd"
    | Opcode.WRUSSQ -> "wrussq"
    | Opcode.XABORT -> "xabort"
    | Opcode.XACQUIRE -> "xacquire"
    | Opcode.XADD -> "xadd"
    | Opcode.XBEGIN -> "xbegin"
    | Opcode.XCHG -> "xchg"
    | Opcode.XCRYPTCBC -> "xcryptcbc"
    | Opcode.XCRYPTCFB -> "xcryptcfb"
    | Opcode.XCRYPTCTR -> "xcryptctr"
    | Opcode.XCRYPTECB -> "xcryptecb"
    | Opcode.XCRYPTOFB -> "xcryptofb"
    | Opcode.XEND -> "xend"
    | Opcode.XGETBV -> "xgetbv"
    | Opcode.XLAT -> "xlat"
    | Opcode.XLATB -> "xlatb"
    | Opcode.XMODEXP -> "xmodexp"
    | Opcode.XOR -> "xor"
    | Opcode.XORPD -> "xorpd"
    | Opcode.XORPS -> "xorps"
    | Opcode.XRELEASE -> "xrelease"
    | Opcode.XRESLDTRK -> "xresldtrk"
    | Opcode.XRNG2 -> "xrng2"
    | Opcode.XRSTOR -> "xrstor"
    | Opcode.XRSTOR64 -> "xrstor64"
    | Opcode.XRSTORS -> "xrstors"
    | Opcode.XRSTORS64 -> "xrstors64"
    | Opcode.XSAVE -> "xsave"
    | Opcode.XSAVE64 -> "xsave64"
    | Opcode.XSAVEC -> "xsavec"
    | Opcode.XSAVEC64 -> "xsavec64"
    | Opcode.XSAVEOPT -> "xsaveopt"
    | Opcode.XSAVEOPT64 -> "xsaveopt64"
    | Opcode.XSAVES -> "xsaves"
    | Opcode.XSAVES64 -> "xsaves64"
    | Opcode.XSETBV -> "xsetbv"
    | Opcode.XSHA1 -> "xsha1"
    | Opcode.XSHA256 -> "xsha256"
    | Opcode.XSHA384 -> "xsha384"
    | Opcode.XSHA512 -> "xsha512"
    | Opcode.XSTORERNG -> "xstorerng"
    | Opcode.XSUSLDTRK -> "xsusldtrk"
    | Opcode.XTEST -> "xtest"
    | Opcode.InvalOP -> "(InvalOp)"
    | s -> printfn "%A" s; failwith "InvalidOpcodeException"
